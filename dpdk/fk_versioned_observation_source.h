#ifndef FK_VERSIONED_OBSERVATION_SOURCE_H
#define FK_VERSIONED_OBSERVATION_SOURCE_H
#include "fk_native_coverage_source.h"
#include "fk_prefix_version_store.h"
#include "fk_selected_evidence_observer.h"
#include <list>
#include "fk_natural_history_audit.h"
#ifndef FK_VERSIONED_CONTROL_LIST
#define FK_VERSIONED_CONTROL_LIST 1
#endif
#if FK_VERSIONED_CONTROL_LIST != 0 && FK_VERSIONED_CONTROL_LIST != 1
#error FK_VERSIONED_CONTROL_LIST must be 0 or 1
#endif

#ifndef FK_DEFER_SELECTED_FINALIZATION
#define FK_DEFER_SELECTED_FINALIZATION 1
#endif
namespace flowkeep {
// Controls travel through the existing ordered SHM. Evidence stays immutable
// in the version pool. Only selected observations enter the scoring/ledger
// pipeline. Independent event clocks may interleave; each event remains causal.
class VersionedObservationSource final : public NativeFusionRequestSource {
    using Key=std::array<uint8_t,sizeof(fk_flow_key)>;
    struct Hash {size_t operator()(const Key &k) const {size_t h=0;for(auto b:k)h=h*131+b;return h;}};
    struct Control {fk_detector_request_v1 request{};uint64_t raw=0;};
    // A run-lifetime identity usually has an empty control FIFO. A lazy linked
    // FIFO avoids retaining an empty large-record deque block per identity.
    // FIFO order and value copies at Emit remain unchanged. The legacy layout
    // is retained as a consistently compiled ablation, not a runtime union.
#if FK_VERSIONED_CONTROL_LIST
    using ControlQueue=std::list<Control>;
#else
    using ControlQueue=std::deque<Control>;
#endif
    struct Entry {
        PrefixVersionStore::Identity id{};
        PrefixVersionStore::ReadHandle versions;
        AdaptiveTerminalRegistry::Snapshot feedback{};
        bool waiting_feedback=false;
        uint32_t first_next=0;
        uint64_t event=0,issued=0,final_sequence=0,physical_close_ns=0;
        uint32_t packet=0,index=0,generation=0;
        uint32_t predecessor_entry=UINT32_MAX,successor_entry=UINT32_MAX;
        bool open=false,physical_closed=false,finished=false,terminal=false,released=false,queued=false;
        bool release_queued=false;
        ControlQueue controls;
    };
    struct Issued {uint64_t raw=0;uint32_t entry=0;bool terminal=false;};
    std::unique_ptr<NativeFusionRequestSource> source_;
    NativeFusionEventRouter *router_;
    std::shared_ptr<PrefixVersionStore> versions_;
    std::shared_ptr<AdaptiveTerminalRegistry> registry_;
    std::shared_ptr<SelectedEvidenceObserver> selected_evidence_;
    size_t capacity_;
    std::vector<Entry> entries_;
    std::vector<uint32_t> slot_to_entry_;
    std::unordered_map<Key,uint32_t,Hash> current_;
    std::unordered_set<uint64_t> events_;
    std::deque<uint32_t> ready_;
    std::deque<uint32_t> release_ready_;
    uint64_t release_enqueued_=0,release_completed_=0,release_deferrals_=0,release_peak_=0;
    uint64_t release_work_ns_=0;
    std::vector<Issued> issued_;
    std::vector<uint64_t> raw_emitted_{0};
    uint64_t raw_read_=0,raw_ack_=0,durable_=0,ack_=0,watermark_=0,eof_ns_=0;
    uint64_t terminal_count_=0,terminal_ack_=0,current_finals_=0,selected_count_=0;
    uint64_t finished_entries_=0,controls_emitted_=0;
public:
    static constexpr bool UsesCompactControlQueue(){return FK_VERSIONED_CONTROL_LIST!=0;}
    struct ReadyStats {
        uint64_t peek_calls=0,ready_checks=0,prefix_notifications=0,feedback_notifications=0;
        uint64_t notification_scratch_calls=0;
        uint64_t prefix_parks=0,feedback_parks=0,unresolved_retries=0,empty_peeks=0;
    };
private:
    ReadyStats ready_stats_;
    std::unique_ptr<AdaptiveTerminalRegistry::Notification[]> notification_scratch_;
    bool maintenance_progress_enabled_=true,last_peek_maintenance_progress_=false;
    bool eof_=false,fault_=false,closed_=false;
    CoverageEscrow::Stats stats_{};
    static Key key(const fk_flow_key &k){Key v{};std::memcpy(v.data(),&k,v.size());return v;}
    static uint64_t now(){timespec t{};clock_gettime(CLOCK_MONOTONIC,&t);return uint64_t(t.tv_sec)*1000000000ull+t.tv_nsec;}
    NativeFusionSourceResult Fail(std::string *error,const char *why) {
        fault_=true;++stats_.rejected;if(error)*error=why;return NativeFusionSourceResult::Fault;
    }
    void Queue(uint32_t index){auto &e=entries_[index];if(!e.queued){e.queued=true;ready_.push_back(index);}}
    bool Done() const{return eof_ && finished_entries_==entries_.size() && controls_emitted_==raw_read_
#if FK_DEFER_SELECTED_FINALIZATION
        && release_completed_==entries_.size()
#endif
        ;}
    void Notifications() {
        if(notification_scratch_) {
            ++ready_stats_.notification_scratch_calls;
            ConsumeNotifications(notification_scratch_.get());
        }else {
            AdaptiveTerminalRegistry::Notification updates[256];ConsumeNotifications(updates);
        }
    }
    void ConsumeNotifications(AdaptiveTerminalRegistry::Notification *updates) {
        const size_t count=registry_->TakeNotifications(updates,256);
        for(size_t i=0;i<count;++i) {
            const auto &update=updates[i];if(update.token>=entries_.size())continue;
            auto &entry=entries_[update.token];entry.feedback=update.snapshot;
            ++ready_stats_.feedback_notifications;
            if(!entry.finished || !entry.controls.empty())Queue(update.token);
        }
        uint32_t slot=0;
        for(unsigned n=0;n<256 && versions_->TakeNotification(&slot);++n) {
            ++ready_stats_.prefix_notifications;
            const uint32_t index=slot_to_entry_[slot];
            if(index!=UINT32_MAX && !entries_[index].waiting_feedback &&
               (!entries_[index].finished || !entries_[index].controls.empty()))Queue(index);
        }
    }
    bool Finish(Entry &e,std::string *error) {
        if(e.finished)return true;
        versions_->Stop(e.versions);
        e.finished=true;e.final_sequence=e.issued;++current_finals_;++stats_.superseded;++finished_entries_;
        if(e.successor_entry!=UINT32_MAX)Queue(e.successor_entry);
        return Release(e,error);
    }
    bool Release(Entry &e,std::string *error) {
        if(e.finished && !e.released && e.final_sequence && ack_>=e.final_sequence){
#if FK_DEFER_SELECTED_FINALIZATION
            (void)error;
            if(!e.release_queued) {
                release_ready_.push_back(static_cast<uint32_t>(&e-entries_.data()));
                e.release_queued=true;++release_enqueued_;
                release_peak_=std::max<uint64_t>(release_peak_,release_ready_.size());
            }
            return true;
#endif
            if(selected_evidence_ && !selected_evidence_->Finalize(e.id.key,e.id.first,
                    e.id.logical,e.final_sequence,error)) {
                fault_=true;++stats_.rejected;return false;
            }
            e.released=true;++stats_.released;--stats_.live;
        }
        return true;
    }
    bool DrainReleases(std::string *error) {
#if FK_DEFER_SELECTED_FINALIZATION
        // Already-durable final identities retain their own selected snapshot
        // and historical payload while parked. No new request is authorized.
        // Bound work per turn so disk backpressure cannot monopolize ingress.
        if(selected_evidence_ && selected_evidence_->SupportsFinalizeBatch() && !release_ready_.empty()) {
            const size_t count=selected_evidence_->FinalizeBatchAdmission(std::min<size_t>(16,release_ready_.size()));
            if(!count){++release_deferrals_;return true;}
            SelectedFinalizationRequest requests[16];
            for(size_t i=0;i<count;++i) {
                const auto &e=entries_[release_ready_[i]];
                if(!e.finished || e.released || !e.release_queued || !e.final_sequence || ack_<e.final_sequence)
                    return Fail(error,"batched selected release invariant"),false;
                requests[i]={e.id.key,e.id.first,e.id.logical,e.final_sequence};
                if(selected_evidence_->UsesBoundFinalizationRequests())requests[i].binding=e.versions;
            }
            const uint64_t begin=now();
            if(!selected_evidence_->FinalizeBatch(requests,count,error)){fault_=true;++stats_.rejected;return false;}
            release_work_ns_+=now()-begin;
            for(size_t i=0;i<count;++i) {
                auto &e=entries_[release_ready_.front()];e.released=true;++stats_.released;--stats_.live;
                release_ready_.pop_front();++release_completed_;
            }
            return true;
        }
        for(unsigned n=0;n<16 && !release_ready_.empty();++n) {
            if(selected_evidence_ && !selected_evidence_->FinalizeAdmissionReady()) {
                ++release_deferrals_;break;
            }
            auto &e=entries_[release_ready_.front()];
            if(!e.finished || e.released || !e.release_queued || !e.final_sequence || ack_<e.final_sequence)
                return Fail(error,"deferred selected release invariant"),false;
            const uint64_t begin=now();
            if(selected_evidence_ && !selected_evidence_->Finalize(e.id.key,e.id.first,
                    e.id.logical,e.final_sequence,error)) {
                fault_=true;++stats_.rejected;return false;
            }
            release_work_ns_+=now()-begin;
            e.released=true;++stats_.released;--stats_.live;
            release_ready_.pop_front();++release_completed_;
        }
#else
        (void)error;
#endif
        return true;
    }
    bool Emit(uint32_t index,uint64_t raw,fk_detector_request_v1 *r,uint64_t *seq,std::string *error) {
        if(issued_.size()>=capacity_*6 || !fk_detector_request_v1_valid(r)){
            Fail(error,"versioned source output capacity/ABI invalid");return false;
        }
        *seq=issued_.size()+1;r->event_routing_token=*seq;
        const bool terminal=r->flags==FK_DETECTOR_REQUEST_FLAG_COVERAGE_TERMINAL;
        if(selected_evidence_ && (r->flags==0 || terminal)) {
            const auto &entry=entries_[index];
            const bool accepted=selected_evidence_->UsesBoundIssueRequests()
                ? selected_evidence_->IssuedBound(*r,*seq,entry.event,entry.versions,error)
                : selected_evidence_->Issued(*r,*seq,entry.event,error);
            if(!accepted){fault_=true;++stats_.rejected;return false;}
        }
        issued_.push_back({raw,index,terminal});if(raw){raw_emitted_[raw]=*seq;++controls_emitted_;}
        if(!raw && !terminal)++selected_count_;
        auto &e=entries_[index];
        if(r->flags==0 || terminal){e.issued=*seq;e.packet=r->checkpoint_packet;e.waiting_feedback=!terminal;}
        if(terminal){e.terminal=true;e.finished=true;e.final_sequence=*seq;++terminal_count_;++stats_.coverage_leases;++finished_entries_;
            if(e.successor_entry!=UINT32_MAX)Queue(e.successor_entry);}
        return true;
    }
public:
    VersionedObservationSource(std::unique_ptr<NativeFusionRequestSource> source,
        NativeFusionEventRouter *router,std::shared_ptr<PrefixVersionStore> versions,
        std::shared_ptr<AdaptiveTerminalRegistry> registry,size_t capacity,
        std::shared_ptr<SelectedEvidenceObserver> selected_evidence=nullptr)
        :source_(std::move(source)),router_(router),versions_(std::move(versions)),
         registry_(std::move(registry)),selected_evidence_(std::move(selected_evidence)),capacity_(capacity) {
        if(!source_ || !router_ || !versions_ || !registry_ || !capacity_ || capacity_>UINT32_MAX/6)
            throw std::invalid_argument("versioned source configuration invalid");
        if(const char *mode=std::getenv("FK_SOURCE_MAINTENANCE_PROGRESS")) {
            if(std::strcmp(mode,"0") && std::strcmp(mode,"1"))throw std::invalid_argument("invalid maintenance-progress flag");
            maintenance_progress_enabled_=std::strcmp(mode,"0")!=0;
        }
        if(const char *mode=std::getenv("FK_NOTIFICATION_SCRATCH")) {
            if(std::strcmp(mode,"0") && std::strcmp(mode,"1"))throw std::invalid_argument("invalid notification scratch flag");
            if(std::strcmp(mode,"1")==0)notification_scratch_=std::make_unique<AdaptiveTerminalRegistry::Notification[]>(256);
        }
        entries_.reserve(capacity_);current_.max_load_factor(2.0f);events_.max_load_factor(2.0f);current_.reserve(capacity_);events_.reserve(capacity_);
        issued_.reserve(capacity_*6);raw_emitted_.reserve(capacity_*2);
        slot_to_entry_.resize(PrefixVersionStore::EntryCapacity(),UINT32_MAX);
    }
    bool DeliversValidatedItems() const noexcept override{return true;}
    bool IndependentEventClocks() const noexcept override{return true;}
    bool InputFenceReached() const noexcept override{return eof_ && !fault_;}
    bool LastPeekMadeMaintenanceProgress() const noexcept override{return maintenance_progress_enabled_ && last_peek_maintenance_progress_;}
    NativeFusionSourceResult Peek(fk_detector_request_v1 *r,uint64_t *seq,std::string *error) noexcept override {
        try {
            if(!r || !seq || fault_ || closed_ || versions_->Faulted())return Fail(error,"version store/source faulted");
            ++ready_stats_.peek_calls;
            last_peek_maintenance_progress_=false;
            const uint64_t completed_before=release_completed_;
            if(!DrainReleases(error))return NativeFusionSourceResult::Fault;
            last_peek_maintenance_progress_=release_completed_!=completed_before;
            Notifications();
            // Bound each control ingestion slice; do not starve ready scores.
            for(unsigned n=0;n<32 && !eof_;++n) {
                fk_detector_request_v1 control{};uint64_t raw=0;
                const auto result=source_->Peek(&control,&raw,error);
                if(result==NativeFusionSourceResult::Empty)break;
                if(result==NativeFusionSourceResult::Fault)return Fail(error,"versioned control transport fault");
                if(result==NativeFusionSourceResult::ProducerDone){
                    NativeFusionSourceSnapshot s{};
                    if(!source_->Snapshot(&s,error) || !s.producer_done || s.published!=raw_read_ ||
                       s.write_sequence!=raw_read_ || s.records_peeked!=raw_read_ || !s.producer_stop_monotonic_ns ||
                       s.producer_drops || s.producer_overruns || s.producer_fail_closed || s.producer_validation_failures ||
                       s.producer_integrity_failures || s.sequence_gaps || s.consumer_validation_failures || s.consumer_fault)
                        return Fail(error,"versioned EOF lacks clean producer fence");
                    eof_=true;eof_ns_=s.producer_stop_monotonic_ns;
                    watermark_=std::max(watermark_,versions_->MaximumSemantic());
                    for(uint32_t i=0;i<entries_.size();++i)
                        if((!entries_[i].finished && !entries_[i].waiting_feedback) || !entries_[i].controls.empty())Queue(i);
                    break;
                }
                if(raw_read_>=capacity_*2 || !fk_detector_request_v1_valid(&control) || raw!=raw_read_+1 ||
                   control.event_routing_token!=raw || control.semantic_timestamp_ns<watermark_)
                    return Fail(error,"versioned physical control order invalid");
                watermark_=control.semantic_timestamp_ns;raw_read_=raw;raw_emitted_.push_back(0);
                const auto k=key(control.canonical_key);uint32_t index=0;
                if(control.flags==FK_DETECTOR_REQUEST_FLAG_COVERAGE_OPEN){
                    NativeFusionEventRouter::Route route{};
                    if(entries_.size()>=capacity_ || !router_->Resolve(control,&route,error) || !route.event_token)
                        return Fail(error,"versioned mode requires one semantic flow per frozen event");
                    const auto previous=current_.find(k);
                    uint32_t predecessor=UINT32_MAX;
                    if(previous!=current_.end()) {
                        auto &prior=entries_[previous->second];
                        if(prior.event!=route.event_token)
                            return Fail(error,"versioned tuple reuse changed frozen event route");
                        // TCP SYN starts a new physical epoch, but DAPT's
                        // frozen event is the canonical bidirectional tuple.
                        // Close the predecessor at its last real prefix and
                        // keep both generations routed to the same event.
                        predecessor=previous->second;
                        prior.physical_closed=true;
                        prior.physical_close_ns=control.semantic_timestamp_ns;
                        Queue(predecessor);
                    } else if(!events_.insert(route.event_token).second) {
                        return Fail(error,"versioned event route aliases distinct flow keys");
                    }
                    index=entries_.size();Entry e{};
                    e.id={control.canonical_key,control.flow_first_timestamp_ns,control.logical_connection_id};
                    e.predecessor_entry=predecessor;
                    e.event=route.event_token;entries_.push_back(std::move(e));current_[k]=index;
                    if(predecessor!=UINT32_MAX)entries_[predecessor].successor_entry=index;
                    registry_->Watch(control.canonical_key,control.flow_first_timestamp_ns,control.logical_connection_id,index);
                    ++stats_.reserved;++stats_.live;stats_.peak_live=std::max(stats_.peak_live,stats_.live);
                }else if(control.flags==FK_DETECTOR_REQUEST_FLAG_FLOW_CONTINUE){
                    const auto found=current_.find(k);
                    if(found==current_.end())return Fail(error,"versioned continuation lacks OPEN");
                    index=found->second;
                    if(control.flow_first_timestamp_ns!=entries_[index].id.first ||
                       control.logical_connection_id!=entries_[index].id.logical)
                        return Fail(error,"versioned continuation identity differs");
                }else return Fail(error,"versioned transport must contain only OPEN/CONTINUE controls");
                entries_[index].controls.push_back({control,raw});Queue(index);
            }
            const size_t attempts=std::min<size_t>(ready_.size(),256);
            for(size_t n=0;n<attempts;++n){
                const uint32_t index=ready_.front();ready_.pop_front();auto &e=entries_[index];e.queued=false;
                ++ready_stats_.ready_checks;
                if(e.finished && e.controls.empty())continue;
                if(e.predecessor_entry!=UINT32_MAX &&
                   !entries_[e.predecessor_entry].finished)continue;
                if(!e.versions.Bound() && versions_->Resolve(e.id,&e.versions))slot_to_entry_[e.versions.Slot()]=index;
                const auto &state=e.feedback;
                const bool observed=e.issued && state.latest_candidate_sequence>=e.issued;
                if(observed)e.waiting_feedback=false;
                if(observed && state.stopped && !Finish(e,error))return NativeFusionSourceResult::Fault;
                if(!e.issued && !e.first_next)e.first_next=versions_->FirstNext(e.versions);
                uint32_t next=e.issued?(observed?state.pending_packet:0):e.first_next;
                const bool input_closed=eof_ || e.physical_closed;
                if(input_closed && !e.issued && !next)return Fail(error,"versioned flow is missing its first packet/plan");
                PrefixVersionStore::Prefix prefix{};
                const auto natural_lookup_before=versions_->Latest(e.versions);
                bool available=!e.finished && next && versions_->Lookup(e.versions,next,&prefix);
                const auto natural_lookup_after=versions_->Latest(e.versions);
                bool terminal=false;
                if(!e.finished && input_closed && next && !available){
                    const uint32_t latest=versions_->Latest(e.versions);
                    if(!latest || latest>=next || !versions_->Lookup(e.versions,latest,&prefix))
                        return Fail(error,"versioned EOF missing exact pending/terminal evidence");
                    if(observed && state.last_observation_packet==latest) {
                        if(!Finish(e,error))return NativeFusionSourceResult::Fault;
                    }
                    else {available=true;terminal=true;}
                }
                // NEXT may lie beyond the current last packet. Once an
                // immutable prefix proves we have entered a successor
                // generation, no future observation at NEXT can belong to
                // the predecessor. Admit its CONTINUE now, not at EOF.
                bool advance_without_observation=false;
                if(!available && !e.finished && next && !e.controls.empty()) {
                    const uint32_t latest=versions_->Latest(e.versions);
                    PrefixVersionStore::Prefix last{};
                    advance_without_observation=latest && latest<next && versions_->Lookup(e.versions,latest,&last) &&
                        (last.evidence.flow_index!=e.index || last.evidence.generation!=e.generation);
                }
                if(!e.controls.empty() && (!e.open || e.finished ||
                    advance_without_observation ||
                    (available && (prefix.evidence.flow_index!=e.index || prefix.evidence.generation!=e.generation)))){
                    Control c=std::move(e.controls.front());e.controls.pop_front();*r=c.request;
                    if(e.open){
                        const auto p=r->predecessor_checkpoint_packet;
                        if(r->predecessor_flow_index!=e.index || r->predecessor_flow_generation!=e.generation ||
                           !(p==0 || p==4 || p==8 || p==12 || p==20))
                            return Fail(error,"versioned continuation predecessor differs");
                        r->predecessor_checkpoint_packet=e.packet;
                    }
                    e.open=true;e.index=r->flow_index;e.generation=r->flow_generation;
                    r->event_routing_token=issued_.size()+1;Queue(index);
                    return Emit(index,c.raw,r,seq,error)?NativeFusionSourceResult::Item:NativeFusionSourceResult::Fault;
                }
                if(available && e.open){
                    if(prefix.evidence.flow_index!=e.index || prefix.evidence.generation!=e.generation){Queue(index);continue;}
                    fk_detector_request_v1_prepare(r);r->canonical_key=e.id.key;
                    r->flow_first_timestamp_ns=e.id.first;r->logical_connection_id=e.id.logical;
                    r->flow_index=e.index;r->flow_generation=e.generation;r->checkpoint_packet=prefix.evidence.packet;
                    r->source_mask=prefix.evidence.mask;r->semantic_timestamp_ns=prefix.evidence.observation_ns;
                    r->physical_timestamp_ns=prefix.physical_ns;r->event_routing_token=issued_.size()+1;
                    std::copy(prefix.evidence.features.begin(),prefix.evidence.features.end(),std::begin(r->features));
                    if(terminal){r->flags=FK_DETECTOR_REQUEST_FLAG_COVERAGE_TERMINAL;
                        const uint64_t boundary=e.physical_closed?e.physical_close_ns:watermark_;
                        r->semantic_timestamp_ns=std::max(boundary,prefix.evidence.observation_ns);
                        r->physical_timestamp_ns=now();fk_detector_coverage_set_evidence_ns(r,prefix.evidence.observation_ns);}
                    const auto authorization_latest=e.issued?state.natural_authorization_latest:1u;
                    const auto authorization_sequence=e.issued?state.latest_candidate_sequence:0u;
                    const auto lookup_latest=versions_->Latest(e.versions);
                    const bool emitted=Emit(index,0,r,seq,error);
                    if(emitted)NaturalHistoryAudit::Get().Bind(*r,*seq,authorization_sequence,
                        authorization_latest,lookup_latest,terminal,natural_lookup_before,natural_lookup_after);
                    if(terminal && !e.controls.empty())Queue(index);
                    return emitted?NativeFusionSourceResult::Item:NativeFusionSourceResult::Fault;
                }
                if(!e.finished || !e.controls.empty()) {
                    if(!e.versions.Bound()){++ready_stats_.unresolved_retries;Queue(index);}
                    else if(e.waiting_feedback)++ready_stats_.feedback_parks;
                    else ++ready_stats_.prefix_parks;
                }
            }
            if(Done())return NativeFusionSourceResult::ProducerDone;
            ++ready_stats_.empty_peeks;return NativeFusionSourceResult::Empty;
        }catch(const std::exception &e){return Fail(error,e.what());}
        catch(...){return Fail(error,"versioned source nonstandard exception");}
    }
    bool ObserveDurableDecision(const NativeFusionDecision &d,std::string *error) noexcept override {
        if(d.sequence!=durable_+1 || d.sequence>issued_.size())return Fail(error,"versioned durable sequence gap"),false;
        const auto &item=issued_[d.sequence-1];auto &e=entries_[item.entry];
        if(d.event_token!=e.event || d.coverage_terminal!=item.terminal)return Fail(error,"versioned durable identity mismatch"),false;
        if(selected_evidence_ && !selected_evidence_->Durable(d,error)) {
            fault_=true;++stats_.rejected;return false;
        }
        if(item.terminal)++stats_.coverage_committed;
        durable_=d.sequence;return true;
    }
    bool Ack(uint64_t sequence,std::string *error) noexcept override {
        if(fault_ || sequence<=ack_ || sequence>durable_)return Fail(error,"versioned ACK lacks durable prefix"),false;
        const uint64_t previous_ack=ack_;
        for(uint64_t i=ack_;i<sequence;++i){const auto &item=issued_[i];if(item.terminal)++terminal_ack_;}
        ack_=sequence;
        uint64_t raw=raw_ack_;
        while(raw<raw_read_ && raw_emitted_[raw+1] && raw_emitted_[raw+1]<=ack_)++raw;
        if(raw>raw_ack_ && !source_->Ack(raw,error))return false;
        raw_ack_=raw;
        // Only entries covered by this newly durable interval can become
        // releasable here. Finish() already handles a STOP observed after ACK.
        // Avoid scanning every live flow on each bounded commit completion.
        for(uint64_t i=previous_ack;i<sequence;++i)
            if(!Release(entries_[issued_[i].entry],error))return false;
        return true;
    }
    bool Snapshot(NativeFusionSourceSnapshot *s,std::string *error) const noexcept override {
        if(!source_->Snapshot(s,error))return false;
        s->write_sequence=s->published=s->records_peeked=issued_.size();
        s->read_sequence=s->records_acked=ack_;s->producer_done=Done();
        if(fault_)s->consumer_fault=1;
        if(closed_ && ack_!=issued_.size())s->unacked_on_close=issued_.size()-ack_;
        return true;
    }
    bool Close(std::string *error) noexcept override {
        if(closed_) {
            if(fault_ && error && error->empty())*error="versioned source already closed with failure";
            return !fault_;
        }
        // Keep the real SHM claim until every additional evidence write has
        // completed. RX total-pipeline timing must not stop at queue admission.
        const bool evidence_ok=!selected_evidence_ || selected_evidence_->Finish(error);
        closed_=true;
        std::string transport_error;
        const bool transport_ok=source_->Close(&transport_error);
        if(!evidence_ok){fault_=true;++stats_.rejected;}
        if(!transport_ok) {
            fault_=true;
            if(error && error->empty())*error=transport_error;
        }
        return evidence_ok && transport_ok;
    }
    uint64_t release_enqueued() const{return release_enqueued_;}
    uint64_t release_completed() const{return release_completed_;}
    uint64_t release_deferrals() const{return release_deferrals_;}
    uint64_t release_peak() const{return release_peak_;}
    uint64_t release_work_ns() const{return release_work_ns_;}
    uint64_t physical_records() const{return raw_read_;}
    uint64_t selected_records() const{return selected_count_;}
    uint64_t physical_acked() const{return raw_ack_;}
    uint64_t terminal_records() const{return terminal_count_;}
    uint64_t terminal_acked() const{return terminal_ack_;}
    uint64_t current_score_finalizations() const{return current_finals_;}
    uint64_t sparse_terminal_snapshots() const{return terminal_count_;}
    uint64_t eof_monotonic_ns() const{return eof_ns_;}
    uint64_t request_watermark_ns() const{return watermark_;}
    uint64_t payload_bytes() const{return PrefixVersionStore::Bytes();}
    uint64_t metadata_vector_bytes() const{return entries_.capacity()*sizeof(Entry)+issued_.capacity()*sizeof(Issued);}
    const CoverageEscrow::Stats &stats() const{return stats_;}
    const ReadyStats &ready_stats() const{return ready_stats_;}
};
}
#endif
