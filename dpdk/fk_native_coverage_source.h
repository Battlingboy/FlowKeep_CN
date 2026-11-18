#ifndef FK_NATIVE_COVERAGE_SOURCE_H
#define FK_NATIVE_COVERAGE_SOURCE_H

#include "fk_native_fusion_service.h"
#include "fk_adaptive_terminal_registry.h"
#include "fk_coverage_escrow.h"
#include <algorithm>
#include <array>
#include <cstring>
#include <deque>
#include <stdexcept>
#include <unordered_map>
#include <unordered_set>
#include <time.h>

namespace flowkeep {

// Live finite-input adapter, not an offline rescorer. It owns no labels/model.
// The SHM prefix and locally appended EOF suffix have separate ACK domains.
// Physical EOF is required before suffix admission. Inference may overlap
// earlier commits; the combined sequence enforces durable-before-ACK ordering.
// A frozen route remains one tuple / event.  Multiple transport epochs of that
// tuple are retained as distinct physical prefixes and merge only through the
// already frozen event token.
class NativeCoverageSource final : public NativeFusionRequestSource {
    using Key = std::array<uint8_t, sizeof(fk_flow_key)>;
    struct Hash {
        size_t operator()(const Key &k) const {
            size_t h=1469598103934665603ull;
            for (auto b:k) h=(h^b)*1099511628211ull;
            return h;
        }
    };
    struct Entry {
        fk_flow_key key{};
        CoverageEscrow::Identity id{};
        CoverageEscrow::Handle handle{};
        std::array<float, FK_DETECTOR_REQUEST_FEATURE_COUNT> last_features{};
        uint64_t last_observation_ns=0;
        uint32_t last_checkpoint=0;
        uint32_t last_evidence_packet=1;
        uint8_t last_source_mask=0;
        uint64_t open_sequence=0, terminal_sequence=0;
        bool last_prefix_present=false, escrow_owner=false, released=false;
    };
    struct EventState {
        uint32_t owner_entry=0;
        uint32_t latest_entry=0;
        bool primary=false;
    };
    std::unique_ptr<NativeFusionRequestSource> source_;
    NativeFusionEventRouter *router_;
    const size_t route_capacity_;
    const size_t physical_capacity_;
    CoverageEscrow escrow_;
    std::unordered_map<Key,uint32_t,Hash> indices_;
    std::unordered_map<uint64_t,EventState> event_states_;
    std::vector<Entry> entries_;
    std::vector<uint32_t> pending_;
    std::vector<uint32_t> terminal_entries_;
    std::deque<std::pair<uint64_t,uint32_t>> release_queue_;
    uint64_t physical_read_=0, physical_ack_=0, combined_ack_=0;
    uint64_t durable_seen_=0, watermark_=0, terminal_count_=0;
    uint64_t eof_monotonic_ns_=0, terminal_acked_=0;
    uint64_t current_score_finalizations_=0;
    size_t next_terminal_=0;
    bool eof_=false, closed_=false, fault_=false;
    bool adaptive_detector_=false;
    std::shared_ptr<AdaptiveTerminalRegistry> terminal_registry_;
    std::shared_ptr<SparsePrefixChannel> sparse_prefixes_;
    uint64_t sparse_terminal_snapshots_=0;
    static Key key(const fk_flow_key &k) {
        Key out{};std::memcpy(out.data(),&k,out.size());return out;
    }
    static uint64_t now() {
        timespec t{};
        return clock_gettime(CLOCK_MONOTONIC,&t)==0 ?
            uint64_t(t.tv_sec)*1000000000ull+uint64_t(t.tv_nsec):0;
    }
    bool fail(std::string *error, const char *message) noexcept {
        fault_=true;if(error)*error=message;return false;
    }
    static bool clean(const NativeFusionSourceSnapshot &s) {
        return !s.producer_drops && !s.producer_overruns && !s.producer_fail_closed &&
            !s.producer_validation_failures && !s.producer_integrity_failures &&
            !s.sequence_gaps && !s.consumer_validation_failures && !s.ack_rejections &&
            !s.consumer_fault && !s.unacked_on_close;
    }
    bool track(fk_detector_request_v1 &r,uint64_t sequence,std::string *error) {
        if ((!source_->DeliversValidatedItems() && !fk_detector_request_v1_valid(&r)) || sequence!=physical_read_+1 ||
            r.event_routing_token!=sequence || r.semantic_timestamp_ns<watermark_ ||
            r.flags==FK_DETECTOR_REQUEST_FLAG_COVERAGE_TERMINAL)
            return fail(error,"coverage physical record/sequence invalid");
        const auto k=key(r.canonical_key);
        auto found=indices_.find(k);
        if (r.flags==FK_DETECTOR_REQUEST_FLAG_COVERAGE_OPEN) {
            if(entries_.size()>=physical_capacity_)
                return fail(error,"coverage physical epoch capacity exceeded");
            NativeFusionEventRouter::Route route{};
            if(!router_->Resolve(r,&route,error) || !route.event_token || !route.event_id ||
                route.event_id->empty())
                return fail(error,"coverage requires frozen one-to-one tuple/event routing");
            auto event=event_states_.find(route.event_token);
            if(found==indices_.end()) {
                if(event!=event_states_.end())
                    return fail(error,"coverage event token belongs to another tuple");
            } else if(entries_[found->second].id.event_token!=route.event_token) {
                return fail(error,"coverage tuple epoch changed frozen event route");
            }
            Entry entry{};entry.key=r.canonical_key;entry.open_sequence=sequence;
            entry.id={route.event_token,r.logical_connection_id,r.flow_first_timestamp_ns,
                r.flow_index,r.flow_generation};
            std::copy(std::begin(r.features),std::end(r.features),
                entry.last_features.begin());
            entry.last_observation_ns=r.semantic_timestamp_ns;
            entry.last_source_mask=0u;
            entry.last_prefix_present=true;
            fk_native_fusion_request prefix{};prefix.sequence=sequence;
            prefix.event_token=route.event_token;prefix.source_mask=0;
            std::copy(std::begin(r.features),std::end(r.features),std::begin(prefix.features));
            const uint32_t index=static_cast<uint32_t>(entries_.size());
            if(event==event_states_.end()) {
                if(event_states_.size()>=route_capacity_)
                    return fail(error,"coverage frozen route capacity exceeded");
                entry.escrow_owner=true;
                const uint32_t slot=static_cast<uint32_t>(event_states_.size());
                if(!escrow_.reserve(slot,entry.id,r.flow_first_timestamp_ns,
                        prefix,&entry.handle))
                    return fail(error,"coverage prefix reserve failed");
                const auto inserted=event_states_.emplace(
                    route.event_token,EventState{index,index,false});
                if(!inserted.second)
                    return fail(error,"coverage event state insertion raced");
            } else {
                event->second.latest_entry=index;
            }
            entries_.push_back(entry);
            if(found==indices_.end())indices_.emplace(k,index);
            else found->second=index;
        } else {
            if(found==indices_.end())return fail(error,"coverage record lacks actual prefix deposit");
            auto &entry=entries_[found->second];
            if(r.flow_first_timestamp_ns!=entry.id.first_semantic_ns ||
                r.logical_connection_id!=entry.id.logical_connection_id)
                return fail(error,"coverage semantic identity changed");
            if(r.flags==FK_DETECTOR_REQUEST_FLAG_FLOW_CONTINUE) {
                // A retention checkpoint can occur between two adaptive
                // snapshots (e.g. detector 7, retention 8, next detector 10).
                // It may also open a successor before that packet's detector
                // snapshot is published. Validate the frozen retention
                // domain, then translate to the exact detector cursor already
                // observed for this generation.  An adaptive detector cursor
                // may legitimately remain below several retention points.
                const uint32_t predecessor=r.predecessor_checkpoint_packet;
                const bool retention_cursor_valid=
                    (predecessor==0u || predecessor==4u || predecessor==8u ||
                     predecessor==12u || predecessor==20u);
                if(r.predecessor_flow_index!=entry.id.flow_index ||
                    r.predecessor_flow_generation!=entry.id.flow_generation ||
                    (!adaptive_detector_ &&
                     r.predecessor_checkpoint_packet!=entry.last_checkpoint) ||
                    (adaptive_detector_ && !retention_cursor_valid))
                    return fail(error,("coverage continuation predecessor differs: received="+
                        std::to_string(r.predecessor_flow_index)+":"+
                        std::to_string(r.predecessor_flow_generation)+":"+
                        std::to_string(predecessor)+" expected_generation="+
                        std::to_string(entry.id.flow_index)+":"+
                        std::to_string(entry.id.flow_generation)+
                        " detector_cursor="+std::to_string(entry.last_checkpoint)+
                        " retention_cursor="+std::to_string(predecessor)).c_str());
                /* The compact continuation directory intentionally stores the
                 * last R16 retention checkpoint.  Adaptive detector-only
                 * snapshots do not mutate that retention cursor.  Once this
                 * adapter has validated the exact predecessor generation and
                 * observed the detector snapshot, normalize the copied
                 * request to the detector cursor consumed downstream. */
                if(adaptive_detector_)
                    r.predecessor_checkpoint_packet=entry.last_checkpoint;
                auto successor=entry.id;successor.flow_index=r.flow_index;
                successor.flow_generation=r.flow_generation;
                if(entry.escrow_owner &&
                   !event_states_.at(entry.id.event_token).primary &&
                   !escrow_.continue_generation(entry.handle,successor))
                    return fail(error,"coverage continuation inheritance failed");
                entry.id=successor;
                if(entry.escrow_owner &&
                   !event_states_.at(entry.id.event_token).primary &&
                   !escrow_.observe(entry.handle,r.semantic_timestamp_ns))
                    return fail(error,"coverage continuation time regressed");
            } else if(r.flags==0) {
                if(r.flow_index!=entry.id.flow_index || r.flow_generation!=entry.id.flow_generation ||
                    r.checkpoint_packet<=entry.last_checkpoint)
                    return fail(error,"coverage checkpoint generation/cursor differs");
                entry.last_checkpoint=r.checkpoint_packet;
                entry.last_evidence_packet=r.checkpoint_packet;
                std::copy(std::begin(r.features),std::end(r.features),
                    entry.last_features.begin());
                entry.last_observation_ns=r.semantic_timestamp_ns;
                entry.last_source_mask=r.source_mask;
                entry.last_prefix_present=true;
                auto &event=event_states_.at(entry.id.event_token);
                event.latest_entry=found->second;
                auto &owner=entries_[event.owner_entry];
                if(adaptive_detector_ && !event.primary &&
                   !escrow_.observe(owner.handle,r.semantic_timestamp_ns))
                    return fail(error,"coverage adaptive evidence time regressed");
                if(!adaptive_detector_ && !event.primary) {
                    if(!escrow_.primary_admitted(owner.handle,sequence))
                        return fail(error,"coverage primary admission failed");
                    event.primary=true;
                    release_queue_.emplace_back(sequence,event.owner_entry);
                }
            } else return fail(error,"coverage mode requires deposit OPEN, not plain OPEN");
        }
        physical_read_=sequence;watermark_=r.semantic_timestamp_ns;return true;
    }
public:
    NativeCoverageSource(std::unique_ptr<NativeFusionRequestSource> source,
        NativeFusionEventRouter *router,size_t routes,size_t events,
        bool adaptive_detector=false,size_t physical_capacity=0u,
        std::shared_ptr<AdaptiveTerminalRegistry> terminal_registry=nullptr,
        std::shared_ptr<SparsePrefixChannel> sparse_prefixes=nullptr)
        :source_(std::move(source)),router_(router),
         route_capacity_(routes),
         physical_capacity_(physical_capacity==0u?routes:physical_capacity),
         escrow_(routes,routes*CoverageEscrow::bytes_per_slot()),
         adaptive_detector_(adaptive_detector),
         terminal_registry_(std::move(terminal_registry)),
         sparse_prefixes_(std::move(sparse_prefixes)) {
        if(!source_ || !router_ || routes!=events || !routes ||
           physical_capacity_<routes)
            throw std::invalid_argument("coverage requires bounded one-to-one event assets");
        entries_.reserve(physical_capacity_);pending_.reserve(route_capacity_);
        terminal_entries_.reserve(route_capacity_);
        indices_.reserve(routes);event_states_.reserve(routes);
    }
    bool DeliversValidatedItems() const noexcept override { return true; }
    NativeFusionSourceResult Peek(fk_detector_request_v1 *r,uint64_t *sequence,
        std::string *error) noexcept override {
        try {
            if(!r || !sequence || fault_ || closed_) {
                fail(error,"coverage source is closed/faulted");return NativeFusionSourceResult::Fault;
            }
            if(!eof_) {
                const auto result=source_->Peek(r,sequence,error);
                if(result==NativeFusionSourceResult::Item) {
                    return track(*r,*sequence,error)?result:NativeFusionSourceResult::Fault;
                }
                if(result!=NativeFusionSourceResult::ProducerDone)return result;
                NativeFusionSourceSnapshot s{};
                if(!source_->Snapshot(&s,error) || !clean(s) || !s.producer_done ||
                    s.write_sequence!=physical_read_ || s.published!=physical_read_ ||
                    s.records_peeked!=physical_read_ || !s.producer_stop_monotonic_ns) {
                    fail(error,"coverage EOF lacks clean fully consumed producer frontier");
                    return NativeFusionSourceResult::Fault;
                }
                eof_=true;eof_monotonic_ns_=s.producer_stop_monotonic_ns;
                // ProducerDone fences every RX owner and deposit. These
                // snapshots are terminal evidence, NOT scored checkpoints.
                // Keep last_checkpoint unchanged: only that delivered cursor
                // must wait for the per-flow scorer, never the omitted prefix.
                if(sparse_prefixes_)for(auto &entry:entries_) {
                    AdaptiveTerminalRegistry::Snapshot state{};
                    if(terminal_registry_ && terminal_registry_->Lookup(entry.key,
                        entry.id.first_semantic_ns,entry.id.logical_connection_id,&state) && state.stopped)
                        continue;
                    SparsePrefixChannel::Prefix prefix{};
                    if(!sparse_prefixes_->Lookup({entry.key,entry.id.first_semantic_ns,
                            entry.id.logical_connection_id},&prefix) ||
                       prefix.packet<=entry.last_evidence_packet)continue;
                    if(prefix.flow_index!=entry.id.flow_index ||
                       prefix.generation!=entry.id.flow_generation ||
                       prefix.observation_ns<entry.last_observation_ns) {
                        fail(error,"sparse terminal snapshot identity/time mismatch");
                        return NativeFusionSourceResult::Fault;
                    }
                    entry.last_evidence_packet=prefix.packet;
                    entry.last_features=prefix.features;
                    entry.last_source_mask=prefix.mask;
                    entry.last_observation_ns=prefix.observation_ns;
                    watermark_=std::max(watermark_,prefix.observation_ns);
                    ++sparse_terminal_snapshots_;
                }
                for(const auto &event:event_states_) {
                    if(adaptive_detector_ && terminal_registry_) {
                        pending_.push_back(event.second.latest_entry);
                        continue;
                    }
                    if(adaptive_detector_ || !event.second.primary)
                        pending_.push_back(adaptive_detector_
                            ? event.second.latest_entry
                            : event.second.owner_entry);
                }
                std::sort(pending_.begin(),pending_.end(),[&](uint32_t a,uint32_t b){
                    const auto ka=key(entries_[a].key),kb=key(entries_[b].key);
                    return ka==kb?entries_[a].id.first_semantic_ns<entries_[b].id.first_semantic_ns:ka<kb;
                });
            }
            // All physical observations have been admitted, so absence of a
            // primary is final. No cross-event inference dependency requires
            // waiting for their ACK: the existing ordered ledger/ACK prefix
            // still persists each deposit before its terminal decision.
            uint32_t terminal_entry=0u;
            if(adaptive_detector_ && terminal_registry_) {
                bool selected=false;
                while(next_terminal_<pending_.size()) {
                    const uint32_t index=pending_[next_terminal_];
                    auto &candidate=entries_[index];
                    AdaptiveTerminalRegistry::Snapshot state{};
                    const bool observed=terminal_registry_->Lookup(
                        candidate.key,candidate.id.first_semantic_ns,
                        candidate.id.logical_connection_id,&state);
                    if(observed && state.stopped) {
                        ++next_terminal_;
                        continue;
                    }
                    if(candidate.last_checkpoint!=0u &&
                       (!observed || state.latest_candidate_packet<
                            candidate.last_checkpoint))
                        return NativeFusionSourceResult::Empty;
                    ++next_terminal_;
                    const uint32_t terminal_packet=
                        candidate.last_evidence_packet;
                    if(observed && (state.pending_packet==0u ||
                       terminal_packet>=state.pending_packet)) {
                        fail(error,
                            "marginal EOF found an unconsumed reached checkpoint");
                        return NativeFusionSourceResult::Fault;
                    }
                    terminal_entry=index;selected=true;break;
                }
                if(!selected)
                    return NativeFusionSourceResult::ProducerDone;
            } else {
                if(next_terminal_==pending_.size())
                    return NativeFusionSourceResult::ProducerDone;
                terminal_entry=pending_[next_terminal_++];
            }
            auto &entry=entries_[terminal_entry];
            auto &event=event_states_.at(entry.id.event_token);
            auto &owner=entries_[event.owner_entry];
            CoverageEscrow::TerminalProof proof{};
            proof.kind=CoverageEscrow::TerminalKind::InputEof;
            proof.semantic_frontier_ns=watermark_; // last request watermark, NOT last packet time
            proof.physical_enqueue_ns=now();
            proof.sequence=physical_read_+terminal_count_+1;
            proof.input_frontier_closed=true;
            proof.event_has_no_primary=!event.primary;
            CoverageEscrow::Work work{};
            if(!entry.last_prefix_present ||
                !escrow_.prepare_terminal(owner.handle,proof,&work) ||
                !fk_detector_request_v1_prepare(r)) {
                fail(error,"coverage terminal lease failed");return NativeFusionSourceResult::Fault;
            }
            r->canonical_key=entry.key;r->flow_index=entry.id.flow_index;
            r->flow_generation=entry.id.flow_generation;r->flow_first_timestamp_ns=entry.id.first_semantic_ns;
            r->logical_connection_id=entry.id.logical_connection_id;
            r->flags=FK_DETECTOR_REQUEST_FLAG_COVERAGE_TERMINAL;
            r->checkpoint_packet=entry.last_evidence_packet;
            r->source_mask=entry.last_source_mask;
            r->semantic_timestamp_ns=work.trigger_semantic_ns;
            r->physical_timestamp_ns=work.physical_enqueue_ns;r->event_routing_token=work.request.sequence;
            fk_detector_coverage_set_evidence_ns(r,entry.last_observation_ns);
            std::copy(entry.last_features.begin(),entry.last_features.end(),
                std::begin(r->features));
            if(!fk_detector_request_v1_valid(r)) {
                fail(error,"coverage terminal ABI invalid");return NativeFusionSourceResult::Fault;
            }
            *sequence=work.request.sequence;entry.terminal_sequence=*sequence;
            release_queue_.emplace_back(*sequence,event.owner_entry);
            terminal_entries_.push_back(terminal_entry);
            ++terminal_count_;return NativeFusionSourceResult::Item;
        } catch(const std::exception &e) {
            fail(error,e.what());return NativeFusionSourceResult::Fault;
        } catch(...) {
            fail(error,"coverage source exception");return NativeFusionSourceResult::Fault;
        }
    }
    bool ObserveDurableDecision(const NativeFusionDecision &d,std::string *error) noexcept override {
        if(d.sequence!=durable_seen_+1)return fail(error,"coverage durable decision prefix has gap");
        if(adaptive_detector_ && terminal_registry_ &&
           !d.coverage_terminal &&
           d.kind==NativeFusionDecisionKind::Checkpoint) {
            AdaptiveTerminalRegistry::Snapshot state{};
            if(terminal_registry_->Lookup(d.canonical_key,
                    d.flow_first_timestamp_ns,d.logical_connection_id,&state) &&
               state.stopped && state.latest_candidate_sequence==d.sequence) {
                const auto event_position=event_states_.find(d.event_token);
                if(event_position==event_states_.end() ||
                   event_position->second.owner_entry>=entries_.size())
                    return fail(error,"marginal STOP route disappeared");
                auto &event=event_position->second;
                auto &owner=entries_[event.owner_entry];
                if(!event.primary) {
                    if(!escrow_.primary_admitted(owner.handle,d.sequence))
                        return fail(error,"marginal STOP escrow admission failed");
                    event.primary=true;
                    ++current_score_finalizations_;
                    release_queue_.emplace_back(d.sequence,event.owner_entry);
                }
            }
        }
        if(d.coverage_terminal) {
            if(d.sequence<=physical_read_ ||
                d.sequence-physical_read_>terminal_entries_.size())
                return fail(error,"coverage durable result lacks prefix");
            auto &entry=entries_[terminal_entries_[static_cast<size_t>(
                d.sequence-physical_read_-1u)]];
            fk_native_fusion_result actual{};actual.sequence=d.sequence;actual.event_token=d.event_token;
            actual.score=d.score;actual.threshold_met=d.threshold_met;
            actual.first_alert=d.first_alert;actual.alert_latched=d.alert_latched;
            const auto event_position=event_states_.find(entry.id.event_token);
            if(event_position==event_states_.end())
                return fail(error,"coverage durable terminal route disappeared");
            auto &event=event_position->second;
            if(event.owner_entry>=entries_.size())
                return fail(error,"coverage durable terminal owner is invalid");
            auto &owner=entries_[event.owner_entry];
            if(event.primary ||
                d.sequence!=entry.terminal_sequence ||
                !escrow_.decision_persisted(owner.handle,actual))
                return fail(error,"coverage durable native result identity invalid");
        }
        durable_seen_=d.sequence;return true;
    }
    bool Ack(uint64_t sequence,std::string *error) noexcept override {
        if(fault_ || sequence<=combined_ack_ || sequence>durable_seen_ ||
            sequence>physical_read_+terminal_count_)return fail(error,"coverage ACK lacks durable prefix");
        const uint64_t physical=std::min(sequence,physical_read_);
        if(physical>physical_ack_ && !source_->Ack(physical,error))return false;
        physical_ack_=physical;combined_ack_=sequence;
        while(!release_queue_.empty() && release_queue_.front().first<=sequence) {
            auto &entry=entries_[release_queue_.front().second];
            if(!escrow_.release_after_durable_ack(entry.handle,sequence))
                return fail(error,"coverage evidence release before ACK");
            entry.released=true;release_queue_.pop_front();
        }
        terminal_acked_=sequence>physical_read_?sequence-physical_read_:0;
        return true;
    }
    bool Snapshot(NativeFusionSourceSnapshot *s,std::string *error) const noexcept override {
        if(!s || !source_->Snapshot(s,error))return false;
        s->write_sequence+=terminal_count_;s->published+=terminal_count_;
        // SHM read_sequence is the durable prefix, NOT the speculative Peek cursor.
        s->read_sequence+=terminal_acked_;s->records_peeked+=terminal_count_;
        s->records_acked+=terminal_acked_;
        s->producer_done=(eof_ && next_terminal_==pending_.size())?1:0;
        if(fault_)s->consumer_fault=1;
        if(closed_ && combined_ack_!=physical_read_+terminal_count_)
            s->unacked_on_close=physical_read_+terminal_count_-combined_ack_;
        return true;
    }
    bool Close(std::string *error) noexcept override {
        closed_=true;return source_->Close(error);
    }
    uint64_t physical_records() const {return physical_read_;}
    uint64_t physical_acked() const {return physical_ack_;}
    uint64_t terminal_records() const {return terminal_count_;}
    uint64_t terminal_acked() const {return terminal_acked_;}
    uint64_t current_score_finalizations() const {
        return current_score_finalizations_;
    }
    uint64_t sparse_terminal_snapshots() const {return sparse_terminal_snapshots_;}
    uint64_t eof_monotonic_ns() const {return eof_monotonic_ns_;}
    uint64_t request_watermark_ns() const {return watermark_;}
    uint64_t payload_bytes() const {return escrow_.allocated_payload_bytes();}
    uint64_t metadata_vector_bytes() const {return entries_.capacity()*sizeof(Entry)+(pending_.capacity()+terminal_entries_.capacity())*sizeof(uint32_t);}
    const CoverageEscrow::Stats &stats() const {return escrow_.stats();}
};
} // namespace flowkeep
#endif
