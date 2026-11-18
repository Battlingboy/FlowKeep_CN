#include "fk_final_scored_evidence_selector.h"
#include "fk_native_fusion_service.h"
#include "fk_natural_history_audit.h"
#include <algorithm>
#include <cmath>
#include <cstring>
#include <cstdlib>
#include <jansson.h>
#include <pthread.h>
#include <sched.h>
#include <chrono>
#include "fk_thread_phase_clock.h"

namespace flowkeep {
FinalScoredEvidenceSelector::FinalScoredEvidenceSelector(
        std::shared_ptr<PrefixVersionStore> versions,
        std::shared_ptr<EvidenceGainChannel> gains,
        std::shared_ptr<SelectedEvidenceStore> store,size_t flows,size_t pending)
    :versions_(std::move(versions)),gains_(std::move(gains)),store_(std::move(store)),
     flow_capacity_(flows),pending_capacity_(pending) {
    if(!versions_ || !store_ || !flows || !pending)
        throw std::invalid_argument("selected evidence selector configuration invalid");
    if(const char *mode=std::getenv("FK_SELECTOR_BOUND_HANDOFF")) {
        if(std::strcmp(mode,"0") && std::strcmp(mode,"1"))
            throw std::invalid_argument("FK_SELECTOR_BOUND_HANDOFF must be 0 or 1");
        bound_handoff_=std::strcmp(mode,"0")!=0;
    }
    const auto toggle=[](const char *name){const char *v=std::getenv(name);
        if(v && std::strcmp(v,"0") && std::strcmp(v,"1"))throw std::invalid_argument(std::string(name)+" must be 0 or 1");
        return v && std::strcmp(v,"1")==0;};
    batch_finalization_=toggle("FK_BATCH_FINALIZATION") && store_->SupportsBoundSubmission();
    final_owner_handoff_=toggle("FK_FINAL_OWNER_HANDOFF");
    final_version_handoff_=toggle("FK_FINAL_VERSION_HANDOFF") && versions_->RecyclingEnabled() && store_->SupportsBoundSubmission();
    pending_.reserve(std::min<size_t>(pending,4096));
    if(!final_owner_handoff_) {
        flows_.reserve(std::min<size_t>(flows,4096));finalized_.reserve(std::min<size_t>(flows,4096));
    }
    expected_.reserve(std::min<size_t>(flows,4096));
    if(versions_->RecyclingEnabled()) {
        std::string error;
        if(!store_->BindVersionRetirement(versions_,&error))throw std::runtime_error(error);
    }
    split_selection_=toggle("FK_SPLIT_FINAL_SELECTION");
    async_selection_=toggle("FK_ASYNC_FINAL_SELECTION");
    final_queue_binding_=toggle("FK_FINAL_QUEUE_BINDING");
    bound_issue_=toggle("FK_BOUND_ISSUE_HANDOFF");pending_inplace_=toggle("FK_PENDING_INPLACE");
    if(bound_issue_ && !final_owner_handoff_)throw std::invalid_argument("bound issue requires directory ownership");
    if(final_queue_binding_ && (!async_selection_ || !final_owner_handoff_))
        throw std::invalid_argument("final queue binding requires async directory ownership");
    if(split_selection_ && !async_selection_)throw std::invalid_argument("split final selection requires asynchronous ownership");
    if(async_selection_) {
        if(!final_owner_handoff_ || !batch_finalization_ || !store_->CapacityRecords())
            throw std::invalid_argument("asynchronous final selection requires directory ownership and bounded batches");
        selection_requested_cpu_=int(store_->WriterCpu());
        if(const char *v=std::getenv("FK_FINAL_SELECTION_CPU")) {
            char *end=nullptr;const long cpu=std::strtol(v,&end,10);
            if(!*v || *end || cpu<0 || cpu>=CPU_SETSIZE)throw std::invalid_argument("invalid final selection CPU");
            selection_requested_cpu_=int(cpu);
        }
        selection_thread_=std::thread(&FinalScoredEvidenceSelector::SelectionLoop,this);
        std::unique_lock<std::mutex> lock(mutex_);selection_ready_cv_.wait(lock,[&]{return selection_ready_;});
        if(failed_){const auto error=failure_;lock.unlock();JoinSelection();throw std::runtime_error(error);}
    }
}
FinalScoredEvidenceSelector::~FinalScoredEvidenceSelector(){JoinSelection();}
void FinalScoredEvidenceSelector::JoinSelection() noexcept {
    std::lock_guard<std::mutex> lifecycle(selection_finish_mutex_);
    {std::lock_guard<std::mutex> lock(mutex_);selection_stopping_=true;}
    selection_ready_cv_.notify_all();selection_space_cv_.notify_all();
    if(selection_thread_.joinable())selection_thread_.join();
}
bool FinalScoredEvidenceSelector::FinalizeAdmissionReady() const noexcept {
    return FinalizeBatchAdmission(1)!=0;
}
size_t FinalScoredEvidenceSelector::FinalizeBatchAdmission(size_t maximum) const noexcept {
    maximum=std::min<size_t>(maximum,16);
    if(!async_selection_)return batch_finalization_?store_->AdmissionAvailable(maximum):
        (store_->AdmissionReady()?std::min<size_t>(maximum,1):0);
    std::lock_guard<std::mutex> lock(mutex_);
    if(failed_ || selection_stopping_)return maximum; // Let the caller observe the fault.
    return std::min(maximum,store_->CapacityRecords()-selection_outstanding_);
}
bool FinalScoredEvidenceSelector::EnqueueFinal(const SelectedFinalizationRequest *requests,
        size_t count,std::string *error) noexcept {
    std::unique_lock<std::mutex> lock(mutex_);
    try {
        if(!requests || !count || count>16 || count>store_->CapacityRecords())
            return Fail(error,"invalid asynchronous finalization batch");
        const bool available=selection_space_cv_.wait_for(lock,std::chrono::milliseconds(store_->FullWaitMs()),
            [&]{return failed_ || selection_stopping_ || store_->CapacityRecords()-selection_outstanding_>=count;});
        if(!available || failed_ || finished_ || selection_stopping_)
            return Fail(error,"asynchronous final selection admission failed");
        std::array<Flow*,16> owners{};
        std::array<PrefixVersionStore::ReadHandle,16> bindings;
        for(size_t i=0;i<count;++i) {
            const auto &r=requests[i];PrefixVersionStore::ReadHandle binding;
            if(final_queue_binding_ && r.binding.Bound()) {
                if(!versions_->Matches(r.binding,{r.key,r.first,r.logical}))
                    return Fail(error,"queued final binding identity/mapping mismatch");
                binding=r.binding;++final_queue_source_bindings_;
            }else {
                if(!versions_->Resolve({r.key,r.first,r.logical},&binding))
                    return Fail(error,"queued final identity missing from directory");
                if(final_queue_binding_)++final_queue_fallback_resolves_;
            }
            bindings[i]=binding;
            const auto slot=binding.Slot();
            if(slot>=directory_flows_.size() || directory_finalized_[slot] || !directory_flows_[slot])
                return Fail(error,"queued final identity already finalized or absent");
            auto *flow=directory_flows_[slot].get();
            if(flow->pending || flow->finalizing || flow->finalization_queued || flow->last_candidate!=r.last_candidate)
                return Fail(error,"queued finalization lacks exact settled durable candidate");
            for(size_t j=0;j<i;++j)if(owners[j]==flow)
                return Fail(error,"duplicate identity in queued finalization batch");
            owners[i]=flow;
        }
        // All admission checks precede publication. A failed allocation is
        // fail-closed; no worker proceeds after failed_ becomes visible.
        for(size_t i=0;i<count;++i) {
            auto task=requests[i];if(final_queue_binding_)task.binding=bindings[i];
            selection_queue_.push_back(std::move(task));
        }
        for(size_t i=0;i<count;++i)owners[i]->finalization_queued=true;
        selection_outstanding_+=count;selection_enqueued_+=count;
        selection_peak_=std::max(selection_peak_,selection_outstanding_);
        selection_ready_cv_.notify_one();return true;
    }catch(const std::exception&e){return Fail(error,e.what());}
    catch(...){return Fail(error,"asynchronous finalization admission failure");}
}
bool FinalScoredEvidenceSelector::Finalize(const fk_flow_key &key,uint64_t first,uint64_t logical,
        uint64_t candidate,std::string *error) noexcept {
    if(!async_selection_)return FinalizeNow(key,first,logical,candidate,false,error);
    const SelectedFinalizationRequest request{key,first,logical,candidate};
    return EnqueueFinal(&request,1,error);
}
bool FinalScoredEvidenceSelector::FinalizeBatch(const SelectedFinalizationRequest *requests,
        size_t count,std::string *error) noexcept {
    return async_selection_?EnqueueFinal(requests,count,error):FinalizeBatchNow(requests,count,false,error);
}
void FinalScoredEvidenceSelector::SelectionLoop() noexcept {
    try {
        cpu_set_t wanted,observed;CPU_ZERO(&wanted);CPU_SET(selection_requested_cpu_,&wanted);
        const bool pinned=pthread_setaffinity_np(pthread_self(),sizeof(wanted),&wanted)==0 &&
            pthread_getaffinity_np(pthread_self(),sizeof(observed),&observed)==0 && CPU_EQUAL(&wanted,&observed);
        {std::lock_guard<std::mutex> lock(mutex_);selection_cpu_=sched_getcpu();selection_ready_=true;
            if(!pinned)Fail(nullptr,"final selection affinity mismatch");}
        selection_ready_cv_.notify_all();
        for(;;) {
            std::array<SelectedFinalizationRequest,16> tasks;size_t count=0;
            {
                std::unique_lock<std::mutex> lock(mutex_);
                selection_ready_cv_.wait(lock,[&]{return failed_ || selection_stopping_ || !selection_queue_.empty();});
                if(failed_ || (selection_stopping_ && selection_queue_.empty()))break;
                count=std::min<size_t>(16,selection_queue_.size());
                for(size_t i=0;i<count;++i){tasks[i]=selection_queue_.front();selection_queue_.pop_front();}
            }
            const auto before=ReadThreadPhaseStamp();std::string error;
            const bool ok=FinalizeBatchNow(tasks.data(),count,true,&error);
            const auto timing=ThreadPhaseBetween(before,ReadThreadPhaseStamp());
            {
                std::lock_guard<std::mutex> lock(mutex_);
                selection_work_cpu_ns_+=timing.cpu_ns;
                selection_work_wall_ns_+=timing.finished_ns-timing.started_ns;
                if(selection_outstanding_<count){Fail(nullptr,"selection ownership underflow");break;}
                selection_outstanding_-=count;
                if(ok)selection_completed_+=count;else Fail(nullptr,error);
            }
            selection_space_cv_.notify_all();if(!ok)break;
        }
    }catch(const std::exception&e){std::lock_guard<std::mutex> lock(mutex_);selection_ready_=true;Fail(nullptr,e.what());}
    catch(...){std::lock_guard<std::mutex> lock(mutex_);selection_ready_=true;Fail(nullptr,"selection worker failure");}
    selection_ready_cv_.notify_all();selection_space_cv_.notify_all();
}

bool FinalScoredEvidenceSelector::Fail(std::string *error,const std::string &why) noexcept {
    failed_=true;selection_ready_cv_.notify_all();selection_space_cv_.notify_all();
    try {if(failure_.empty())failure_=why;if(error)*error=failure_;}catch(...){}
    return false;
}
std::string FinalScoredEvidenceSelector::Identity(const fk_flow_key &key,uint64_t first,uint64_t logical) {
    SelectedEvidenceRecord record{};record.request.canonical_key=key;
    record.request.flow_first_timestamp_ns=first;record.request.logical_connection_id=logical;
    return SelectedEvidenceStore::IdentityKey(record);
}
bool FinalScoredEvidenceSelector::Issued(const fk_detector_request_v1 &r,uint64_t seq,
        uint64_t event,std::string *error) noexcept {return IssuedImpl(r,seq,event,nullptr,error);}
bool FinalScoredEvidenceSelector::IssuedBound(const fk_detector_request_v1 &r,uint64_t seq,
        uint64_t event,const PrefixVersionStore::ReadHandle &binding,std::string *error) noexcept {
    return IssuedImpl(r,seq,event,bound_issue_?&binding:nullptr,error);
}
bool FinalScoredEvidenceSelector::IssuedImpl(const fk_detector_request_v1 &r,uint64_t seq,
        uint64_t event,const PrefixVersionStore::ReadHandle *source_binding,std::string *error) noexcept {
    std::lock_guard<std::mutex> lock(mutex_);
    try {
        if(failed_ || finished_ || !seq || !event || r.event_routing_token!=seq ||
           (r.flags!=0 && r.flags!=FK_DETECTOR_REQUEST_FLAG_COVERAGE_TERMINAL) ||
           !fk_detector_request_v1_valid(&r) || pending_.size()>=pending_capacity_)
            return Fail(error,"selected evidence invalid/over-capacity issued request");
        Flow *owner=nullptr;
        if(final_owner_handoff_) {
            PrefixVersionStore::ReadHandle binding;
            const PrefixVersionStore::Identity id{r.canonical_key,r.flow_first_timestamp_ns,r.logical_connection_id};
            if(source_binding) {
                if(!versions_->Matches(*source_binding,id))return Fail(error,"issued binding identity/mapping mismatch");
                binding=*source_binding;++source_issue_bindings_;
            }else {
                if(!versions_->Resolve(id,&binding))return Fail(error,"selected evidence bound identity has no exact version directory entry");
                ++issue_directory_resolves_;
            }
            const uint32_t slot=binding.Slot();
            if(directory_flows_.size()<=slot){directory_flows_.resize(slot+1);directory_finalized_.resize(slot+1,0);}
            if(directory_finalized_[slot] || (!directory_flows_[slot] && directory_active_+finalized_count_>=flow_capacity_))
                return Fail(error,"selected evidence flow finalized or identity capacity exhausted");
            if(!directory_flows_[slot]){directory_flows_[slot]=std::make_unique<Flow>();directory_flows_[slot]->version_handle=binding;++directory_active_;}
            owner=directory_flows_[slot].get();++directory_owner_joins_;
        }else {
            const auto key=Identity(r.canonical_key,r.flow_first_timestamp_ns,r.logical_connection_id);
            if(finalized_.count(key) || (flows_.count(key)==0 && flows_.size()+finalized_.size()>=flow_capacity_))
                return Fail(error,"selected evidence flow finalized or identity capacity exhausted");
            owner=&flows_[key];
            if((bound_handoff_ || final_version_handoff_) && !owner->version_handle.Bound() &&
               !versions_->Resolve({r.canonical_key,r.flow_first_timestamp_ns,r.logical_connection_id},&owner->version_handle))
                return Fail(error,"selected evidence bound identity has no exact version directory entry");
        }
        auto &flow=*owner;
        if(flow.finalizing || flow.finalization_queued || seq<=flow.last_candidate)return Fail(error,"selected evidence candidate sequence is stale or finalized");
        const auto fill=[&](Pending &item) {
            item.owner=(bound_handoff_ || final_owner_handoff_)?&flow:nullptr;
            item.record.request=r;item.record.decision_sequence=seq;item.record.event_token=event;
            item.record.evidence_timestamp_ns=r.flags==FK_DETECTOR_REQUEST_FLAG_COVERAGE_TERMINAL?
                fk_detector_coverage_evidence_ns(&r):r.semantic_timestamp_ns;
        };
        if(pending_inplace_) {
            auto inserted=pending_.try_emplace(seq);
            if(!inserted.second)return Fail(error,"selected evidence duplicate issued sequence");
            fill(inserted.first->second);++pending_inplace_records_;
        }else {
            Pending item{};fill(item);
            if(!pending_.emplace(seq,std::move(item)).second)return Fail(error,"selected evidence duplicate issued sequence");
        }
        ++flow.pending;
        ++issued_;peak_pending_=std::max(peak_pending_,pending_.size());peak_flows_=std::max(peak_flows_,final_owner_handoff_?directory_active_:flows_.size());
        return true;
    }catch(const std::exception &e){return Fail(error,e.what());}
    catch(...){return Fail(error,"selected evidence issue failed");}
}
bool FinalScoredEvidenceSelector::Scored(uint64_t seq,bool actual,double score,std::string *error) noexcept {
    std::lock_guard<std::mutex> lock(mutex_);
    try {
        auto found=pending_.find(seq);
        if(failed_ || finished_ || found==pending_.end() || found->second.attested || !std::isfinite(score))
            return Fail(error,"selected evidence missing/duplicate actual-score attestation");
        found->second.attested=true;found->second.actual=actual;found->second.score=score;
        ++attested_;if(actual)++actual_;else ++synthetic_;
        NaturalHistoryAudit::Get().Score(seq,actual,score);
        return true;
    }catch(const std::exception &e){return Fail(error,e.what());}
    catch(...){return Fail(error,"selected evidence score attestation failed");}
}
bool FinalScoredEvidenceSelector::Durable(const NativeFusionDecision &d,std::string *error) noexcept {
    if(d.kind!=NativeFusionDecisionKind::Checkpoint)return true;
    std::lock_guard<std::mutex> lock(mutex_);
    try {
        const auto found=pending_.find(d.sequence);
        if(failed_ || finished_ || found==pending_.end() || !found->second.attested || !d.score_present)
            return Fail(error,"selected evidence durable decision lacks scored input attestation");
        auto &item=found->second;const auto &r=item.record.request;
        const bool terminal=r.flags==FK_DETECTOR_REQUEST_FLAG_COVERAGE_TERMINAL;
        if(d.event_token!=item.record.event_token || std::memcmp(&d.canonical_key,&r.canonical_key,sizeof(r.canonical_key)) ||
           d.flow_first_timestamp_ns!=r.flow_first_timestamp_ns || d.logical_connection_id!=r.logical_connection_id ||
           d.checkpoint_packet!=r.checkpoint_packet || d.flow_index!=r.flow_index || d.flow_generation!=r.flow_generation ||
           d.source_mask!=r.source_mask || d.coverage_terminal!=terminal || d.semantic_timestamp_ns!=r.semantic_timestamp_ns ||
           d.physical_enqueue_monotonic_ns!=r.physical_timestamp_ns ||
           std::memcmp(&d.score,&item.score,sizeof(d.score)) ||
           (terminal && (d.coverage_evidence_timestamp_ns!=item.record.evidence_timestamp_ns || !d.coverage_prefix ||
               std::memcmp(d.coverage_prefix->data(),r.features,sizeof(r.features)))))
            return Fail(error,"selected evidence durable decision and issued request differ");
        Flow *flow=item.owner;
        if(bound_handoff_ || final_owner_handoff_) {
            ++bound_owner_joins_;
        } else {
            const auto key=Identity(r.canonical_key,r.flow_first_timestamp_ns,r.logical_connection_id);
            auto found_flow=flows_.find(key);
            flow=found_flow==flows_.end()?nullptr:&found_flow->second;
            ++independent_owner_lookups_;
        }
        if(!flow || !flow->pending || d.sequence<=flow->last_candidate)
            return Fail(error,"selected evidence durable sequence/identity mismatch");
        flow->last_candidate=d.sequence;
        if(item.actual) {
            item.record.score=d.score;item.record.threshold_met=d.threshold_met;item.record.alert_latched=d.alert_latched;
            if(flow->has_actual && r.checkpoint_packet<=flow->last_actual.request.checkpoint_packet)
                return Fail(error,"selected evidence actual prefix failed to advance");
            flow->last_actual=item.record;flow->has_actual=true;
        }
        --flow->pending;pending_.erase(found);++durable_;return true;
    }catch(const std::exception &e){return Fail(error,e.what());}
    catch(...){return Fail(error,"selected evidence durable join failed");}
}
bool FinalScoredEvidenceSelector::PrepareFinalLocked(const SelectedFinalizationRequest &request,
        PreparedFinal &prepared,bool from_queue,std::string *error) {
    const auto &key=request.key;const auto first=request.first,logical=request.logical,last_candidate=request.last_candidate;
    auto &identity=prepared.identity;
    auto &final_binding=prepared.binding;auto &directory_slot=prepared.directory_slot;Flow *selected_flow=nullptr;
    if(final_owner_handoff_) {
        if(final_queue_binding_ && from_queue) {
            if(!versions_->Matches(request.binding,{key,first,logical}))
                return Fail(error,"selected evidence queued binding identity/mapping mismatch");
            final_binding=request.binding;++final_queue_worker_bindings_;
        }else if(!versions_->Resolve({key,first,logical},&final_binding))
            return Fail(error,"selected evidence final identity missing from directory");
        directory_slot=final_binding.Slot();
        if(directory_slot>=directory_flows_.size() || directory_finalized_[directory_slot])
            return Fail(error,"selected evidence finalization lacks exact durable candidate");
        selected_flow=directory_flows_[directory_slot].get();
    }else {
        identity=Identity(key,first,logical);auto found=flows_.find(identity);
        if(finalized_.count(identity))return Fail(error,"selected evidence finalization lacks exact durable candidate");
        selected_flow=found==flows_.end()?nullptr:&found->second;
    }
    if(failed_ || finished_ || !selected_flow || selected_flow->finalizing || selected_flow->pending || selected_flow->last_candidate!=last_candidate || selected_flow->finalization_queued!=from_queue)
        return Fail(error,"selected evidence finalization lacks exact durable candidate");
    auto &flow=*selected_flow;final_binding=flow.version_handle;
    if(!flow.has_actual) {
        const PrefixVersionStore::Identity id{key,first,logical};
        if(!(final_version_handoff_?versions_->SealFinalized(id,final_binding):versions_->SealFinalized(id)) ||
           !(final_version_handoff_?versions_->RetireFinalized(id,final_binding):versions_->RetireFinalized(id)))
            return Fail(error,"synthetic-only version retirement failed");
        if(final_owner_handoff_){directory_finalized_[directory_slot]=1;directory_flows_[directory_slot].reset();--directory_active_;++directory_finalizations_;}
        else {finalized_.insert(identity);flows_.erase(identity);}++zero_actual_;++finalized_count_;return true;
    }
    // The queued identity has no pending requests. Claim it under the same
    // mutex used by Issued/Durable; its heap Flow remains stable across vector
    // growth until this worker completes it. No other thread may mutate it.
    prepared.owner=&flow;flow.finalizing=true;prepared.has_actual=true;
    prepared.payload_deferred=split_selection_ && from_queue;
    if(prepared.payload_deferred)return true;
    return PrepareFinalPayload(prepared,true,error);
}
bool FinalScoredEvidenceSelector::PrepareFinalPayload(PreparedFinal &prepared,bool locked,std::string *error) {
    auto fail=[&](const std::string &message) {
        if(locked)return Fail(error,message);
        std::lock_guard<std::mutex> guard(mutex_);return Fail(error,message);
    };
    auto &flow=*prepared.owner;auto &expected=prepared.expected;auto &actual=prepared.actual;
    auto &final_binding=prepared.binding;
    expected=flow.last_actual;actual=expected;
    const auto &key=expected.request.canonical_key;
    const auto first=expected.request.flow_first_timestamp_ns,logical=expected.request.logical_connection_id;
    const PrefixVersionStore::Identity id{key,first,logical};
    PrefixVersionStore::Prefix prefix{};
    const bool historical_found=bound_handoff_?
        versions_->Lookup(flow.version_handle,expected.request.checkpoint_packet,&prefix):
        versions_->Lookup(id,expected.request.checkpoint_packet,&prefix);

    if(!historical_found)
        return fail("selected evidence exact historical version is unavailable; latest fallback forbidden");
    auto &r=actual.request;const auto &p=prefix.evidence;
    r.flow_index=p.flow_index;r.flow_generation=p.generation;r.checkpoint_packet=p.packet;r.source_mask=p.mask;
    std::copy(p.features.begin(),p.features.end(),std::begin(r.features));
    actual.evidence_timestamp_ns=p.observation_ns;
    if(r.flags==FK_DETECTOR_REQUEST_FLAG_COVERAGE_TERMINAL)
        fk_detector_coverage_set_evidence_ns(&r,p.observation_ns);
    else {r.semantic_timestamp_ns=p.observation_ns;r.physical_timestamp_ns=prefix.physical_ns;}
    if(!SelectedEvidenceStore::SameEncodedPayload(actual,expected))
        return fail("selected evidence historical payload/identity differs from actual scoring input");

    NaturalHistoryAudit::Get().Finalize(expected.decision_sequence,
        expected.request.checkpoint_packet,bound_handoff_?versions_->Latest(flow.version_handle):versions_->Latest(id));
    // The exact selected bytes remain live through synchronous WAL.
    // Retirement is event-gated, not a fabricated wall-clock deadline.
    actual.recoverability_deadline_ns=0;
    actual.semantic_watermark_ns=versions_->MaximumSemantic();
    EvidenceGainFeedback feedback{};
    if(gains_ && gains_->Lookup(key,first,logical,r.checkpoint_packet,&feedback) &&
       feedback.sequence==actual.decision_sequence && feedback.evidence_packet==r.checkpoint_packet &&
       feedback.required_mask==r.source_mask) {
        actual.gain_known=true;actual.marginal_gain=feedback.gain;
    }
    if(!(final_version_handoff_?versions_->SealFinalized(id,final_binding):versions_->SealFinalized(id)))return fail("selected identity seal failed");
    const auto account=[&] {
        if(bound_handoff_)++cached_version_lookups_;
        ++history_exact_;
        if(actual.gain_known)++feedback_exact_;else ++feedback_unknown_;
    };
    if(locked)account();else {std::lock_guard<std::mutex> guard(mutex_);account();}
    prepared.payload_deferred=false;return true;
}
bool FinalScoredEvidenceSelector::CompleteFinalLocked(PreparedFinal &prepared,std::string *error) {
    (void)error;auto &expected=prepared.expected;auto &identity=prepared.identity;
    const auto directory_slot=prepared.directory_slot;
    expected_.push_back(std::move(expected));
    if(final_owner_handoff_){directory_finalized_[directory_slot]=1;directory_flows_[directory_slot].reset();--directory_active_;++directory_finalizations_;}
    else {finalized_.insert(identity);flows_.erase(identity);}++finalized_count_;
    return true;
}
bool FinalScoredEvidenceSelector::FinalizeNow(const fk_flow_key &key,uint64_t first,uint64_t logical,
        uint64_t last_candidate,bool from_queue,std::string *error) noexcept {
    PreparedFinal prepared;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        try {if(!PrepareFinalLocked({key,first,logical,last_candidate},prepared,from_queue,error))return false;}
        catch(const std::exception &e){return Fail(error,e.what());}
        catch(...){return Fail(error,"selected evidence finalization failed");}
    }
    if(!prepared.has_actual)return true;
    try {if(prepared.payload_deferred && !PrepareFinalPayload(prepared,false,error))return false;}
    catch(const std::exception &e){std::lock_guard<std::mutex> lock(mutex_);return Fail(error,e.what());}
    catch(...){std::lock_guard<std::mutex> lock(mutex_);return Fail(error,"deferred final payload check failed");}
    std::string store_error;
    if(!(final_version_handoff_?store_->SubmitBound(prepared.actual,prepared.binding,&store_error):
            store_->Submit(prepared.actual,&store_error))) {
        std::lock_guard<std::mutex> lock(mutex_);return Fail(error,store_error);
    }
    std::lock_guard<std::mutex> lock(mutex_);
    try {return CompleteFinalLocked(prepared,error);}
    catch(const std::exception &e){return Fail(error,e.what());}
    catch(...){return Fail(error,"selected evidence oracle retention failed");}
}
bool FinalScoredEvidenceSelector::FinalizeBatchNow(const SelectedFinalizationRequest *requests,size_t count,
        bool from_queue,std::string *error) noexcept {
    if(!batch_finalization_)return SelectedEvidenceObserver::FinalizeBatch(requests,count,error);
    if(!requests || !count || count>16) {
        std::lock_guard<std::mutex> lock(mutex_);return Fail(error,"finalization batch size invalid");
    }
    if(count==1 && !final_queue_binding_)return FinalizeNow(requests[0].key,requests[0].first,requests[0].logical,requests[0].last_candidate,from_queue,error);
    try {
        std::array<PreparedFinal,16> prepared;
        std::array<const SelectedEvidenceRecord*,16> records{};
        std::array<PrefixVersionStore::ReadHandle,16> bindings;
        size_t actual_count=0;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            for(size_t i=0;i<count;++i) {
                if(!PrepareFinalLocked(requests[i],prepared[i],from_queue,error))return false;
                if(prepared[i].has_actual) {
                    records[actual_count]=&prepared[i].actual;bindings[actual_count]=prepared[i].binding;++actual_count;
                }
            }
        }
        for(size_t i=0;i<count;++i)
            if(prepared[i].payload_deferred && !PrepareFinalPayload(prepared[i],false,error))return false;
        // Capacity was only a hint. A concurrent submitter cannot make this
        // wait hold mutex_ or allow an early durable/retirement acknowledgement.
        std::string storage_error;
        if(actual_count && !store_->SubmitBatch(records.data(),actual_count,
                final_version_handoff_?bindings.data():nullptr,&storage_error)) {
            std::lock_guard<std::mutex> lock(mutex_);return Fail(error,storage_error);
        }
        std::lock_guard<std::mutex> lock(mutex_);
        for(size_t i=0;i<count;++i)if(prepared[i].has_actual && !CompleteFinalLocked(prepared[i],error))return false;
        ++finalize_batch_calls_;finalize_batch_rows_+=count;finalize_batch_max_=std::max<uint64_t>(finalize_batch_max_,count);
        return true;
    }catch(const std::exception &e){std::lock_guard<std::mutex> lock(mutex_);return Fail(error,e.what());}
    catch(...){std::lock_guard<std::mutex> lock(mutex_);return Fail(error,"selected evidence batch finalization failed");}
}
bool FinalScoredEvidenceSelector::Finish(std::string *error) noexcept {
    JoinSelection();
    std::string store_error;
    bool storage_ok=false;
    try {storage_ok=store_->Finish(&store_error);}catch(...){store_error="selected evidence store drain raised";}
    std::lock_guard<std::mutex> lock(mutex_);
    if(!storage_ok)return Fail(error,store_error);
    if(failed_)return Fail(error,failure_);
    if(selection_outstanding_ || !selection_queue_.empty() || selection_enqueued_!=selection_completed_ ||
       !pending_.empty() || !flows_.empty() || directory_active_ || issued_!=attested_ || issued_!=durable_ ||
       finalized_count_!=expected_.size()+zero_actual_ || history_exact_!=expected_.size())
        return Fail(error,"selected evidence drain has unfinished scoring/selection targets");
    finished_=true;return true;
}
bool FinalScoredEvidenceSelector::Verify(std::string *error) noexcept {
    std::lock_guard<std::mutex> lock(mutex_);
    try {
        if(failed_ || !finished_)return Fail(error,"selected evidence verification before complete drain");
        if(!store_->Verify(expected_,error))return Fail(error,error?*error:"selected evidence readback failed");
        verified_=true;return true;
    }catch(const std::exception &e){return Fail(error,e.what());}
    catch(...){return Fail(error,"selected evidence verification raised");}
}
std::string FinalScoredEvidenceSelector::ReceiptJson() const {
    std::lock_guard<std::mutex> lock(mutex_);json_error_t error{};
    json_t *root=json_loads(store_->ReceiptJson().c_str(),JSON_REJECT_DUPLICATES,&error);
    if(!root || !json_is_object(root)){if(root)json_decref(root);throw std::runtime_error("selected store receipt invalid");}
    const auto number=[&](const char *key,uint64_t value){json_object_set_new(root,key,json_integer(value));};
    json_object_set_new(root,"bound_owner_handoff_enabled",json_boolean(bound_handoff_));
    json_object_set_new(root,"final_owner_handoff_enabled",json_boolean(final_owner_handoff_));
    json_object_set_new(root,"final_version_handoff_enabled",json_boolean(final_version_handoff_));
    json_object_set_new(root,"batch_finalization_enabled",json_boolean(batch_finalization_));
    json_object_set_new(root,"async_final_selection",json_boolean(async_selection_));
    json_object_set_new(root,"split_final_selection",json_boolean(split_selection_));
    json_object_set_new(root,"final_queue_binding",json_boolean(final_queue_binding_));
    json_object_set_new(root,"bound_issue_handoff",json_boolean(bound_issue_));
    json_object_set_new(root,"pending_inplace",json_boolean(pending_inplace_));
    number("source_issue_bindings",source_issue_bindings_);number("issue_directory_resolves",issue_directory_resolves_);
    number("pending_inplace_records",pending_inplace_records_);
    number("final_queue_source_bindings",final_queue_source_bindings_);
    number("final_queue_fallback_resolves",final_queue_fallback_resolves_);
    number("final_queue_worker_bindings",final_queue_worker_bindings_);
    number("actual_final_selection_cpu",selection_cpu_);number("final_selection_requested_cpu",selection_requested_cpu_);
    number("final_selection_enqueued",selection_enqueued_);number("final_selection_completed",selection_completed_);
    number("final_selection_peak_outstanding",selection_peak_);
    number("final_selection_capacity",async_selection_?store_->CapacityRecords():0);
    number("final_selection_work_cpu_ns",selection_work_cpu_ns_);number("final_selection_work_wall_ns",selection_work_wall_ns_);

    number("finalize_batch_calls",finalize_batch_calls_);number("finalize_batch_rows",finalize_batch_rows_);
    number("finalize_batch_max",finalize_batch_max_);
    number("directory_owner_joins",directory_owner_joins_);number("directory_finalizations",directory_finalizations_);
    number("directory_active_owners",directory_active_);
    number("directory_selection_index_bytes",directory_flows_.capacity()*sizeof(std::unique_ptr<Flow>)+directory_finalized_.capacity());
    number("bound_owner_joins",bound_owner_joins_);number("independent_owner_lookups",independent_owner_lookups_);
    number("cached_version_lookups",cached_version_lookups_);
    number("expected_records",expected_.size());number("candidate_requests_issued",issued_);
    number("score_attestations",attested_);number("actual_model_calls_attested",actual_);
    number("synthetic_rows_attested",synthetic_);number("durable_candidates_joined",durable_);
    number("semantic_flows_finalized",finalized_count_);number("zero_actual_score_flows",zero_actual_);
    number("exact_historical_payload_matches",history_exact_);number("exact_gain_feedback_hits",feedback_exact_);
    number("unknown_gain_feedback",feedback_unknown_);number("selector_peak_pending_requests",peak_pending_);
    number("selector_peak_active_flows",peak_flows_);number("selector_pending_capacity",pending_capacity_);
    number("selector_flow_capacity",flow_capacity_);number("oracle_record_size_bytes",sizeof(SelectedEvidenceRecord));
    number("oracle_vector_capacity_bytes",expected_.capacity()*sizeof(SelectedEvidenceRecord));
    json_object_set_new(root,"selector_failed",json_boolean(failed_));
    json_object_set_new(root,"selector_finished",json_boolean(finished_));
    json_object_set_new(root,"independent_scoring_input_readback_verified",json_boolean(verified_));
    json_object_set_new(root,"selector_error",json_string(failure_.c_str()));
    json_object_set_new(root,"selection_unit",json_string("canonical_key+first_timestamp+logical_id; last actual model call; synthetic-only identities have no target"));
    json_object_set_new(root,"deadline_source",json_string(versions_->RecyclingEnabled()?
        "unknown: version retirement follows finalized selected synchronous WAL; no fabricated expiry":
        "unknown: immutable version pool retained through run; no fabricated expiry"));
    char *raw=json_dumps(root,JSON_COMPACT|JSON_SORT_KEYS);json_decref(root);
    if(!raw)throw std::bad_alloc();
    std::string out(raw);std::free(raw);return out;
}
}
