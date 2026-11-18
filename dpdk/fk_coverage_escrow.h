#ifndef FK_COVERAGE_ESCROW_H
#define FK_COVERAGE_ESCROW_H

// Preallocated lifecycle state for first-prefix coverage inference.
// Keep a real first-prefix snapshot without invoking any model/history update.
// A normal admitted checkpoint supersedes it; otherwise only a proven terminal
// frontier may lease it for coverage inference. No release before durable ACK.
// Caller must use its existing unique event/semantic-epoch registry to assign
// one pool slot per epoch and prevent duplicate reserve across slots. It must
// validate routing, native feature schema and terminal frontier independently.
// Prefix memory is explicitly preallocated/charged, not free/unbounded memory.
#include "fk_native_seven_state_fusion.h"
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <stdexcept>
#include <vector>

namespace flowkeep {

class CoverageEscrow {
public:
    struct Identity {
        uint64_t event_token=0, logical_connection_id=0, first_semantic_ns=0;
        uint32_t flow_index=0, flow_generation=0;
    };
    struct Handle { uint32_t index=0; uint64_t lease=0; };
    enum class TerminalKind { None, InputEof, ValidatedIdleExpiry, ValidatedProtocolEnd };
    struct TerminalProof {
        TerminalKind kind=TerminalKind::None;
        uint64_t semantic_frontier_ns=0;
        uint64_t physical_enqueue_ns=0;
        uint64_t sequence=0;
        // Must mean all relevant owner-visible inputs / prior primary work are
        // accounted for. Empty RX dequeue, capacity demote and queue emptiness
        // do not establish this fact and are NOT terminal kinds.
        bool input_frontier_closed=false;
        bool event_has_no_primary=false;
    };
    struct Work {
        fk_native_fusion_request request{};
        Identity identity{};
        uint64_t evidence_semantic_ns=0;
        uint64_t trigger_semantic_ns=0;
        uint64_t physical_enqueue_ns=0;
        TerminalKind trigger=TerminalKind::None;
    };
    struct Stats {
        uint64_t reserved=0, superseded=0, coverage_leases=0, coverage_committed=0;
        uint64_t released=0, rejected=0, aborted=0, live=0, peak_live=0;
    };
private:
    enum class State { Empty, Pending, PrimaryAwaitAck, CoverageInFlight, CoverageAwaitAck };
    struct Slot {
        State state=State::Empty;
        uint64_t lease=0, evidence_ns=0, last_observed_ns=0, required_ack=0;
        Identity identity{};
        fk_native_fusion_request prefix{};
    };
    std::vector<Slot> slots_;
    Stats stats_{};
    uint64_t last_ack_prefix_=0;

    bool reject() { ++stats_.rejected; return false; }
    Slot *get(Handle h) {
        if(h.index>=slots_.size())return nullptr;
        Slot &s=slots_[h.index];
        return s.state!=State::Empty && s.lease==h.lease?&s:nullptr;
    }
public:
    static size_t bytes_per_slot() { return sizeof(Slot); }
    CoverageEscrow(size_t capacity, size_t charged_byte_limit) {
        if(capacity==0 || capacity>UINT32_MAX || capacity>charged_byte_limit/sizeof(Slot))
            throw std::invalid_argument("coverage escrow exceeds explicit payload budget");
        slots_.resize(capacity); // the sole payload allocation; no runtime resize
        if(slots_.capacity()>charged_byte_limit/sizeof(Slot))
            throw std::invalid_argument("coverage allocator capacity exceeds payload budget");
    }
    size_t allocated_payload_bytes() const { return slots_.capacity()*sizeof(Slot); }
    const Stats &stats() const { return stats_; }
    bool reserve(uint32_t index, const Identity &id, uint64_t evidence_ns,
                 const fk_native_fusion_request &actual_first_prefix, Handle *out) {
        if(!out || index>=slots_.size() || slots_[index].state!=State::Empty ||
           !id.event_token || !id.flow_generation ||
           evidence_ns!=id.first_semantic_ns ||
           actual_first_prefix.event_token!=id.event_token || !actual_first_prefix.sequence ||
           actual_first_prefix.source_mask!=0)return reject();
        for(float v:actual_first_prefix.features)if(!std::isfinite(v))return reject();
        for(uint8_t v:actual_first_prefix.reserved)if(v!=0)return reject();
        Slot &s=slots_[index];
        if(s.lease==UINT64_MAX)return reject();
        ++s.lease; s.state=State::Pending; s.identity=id;
        s.evidence_ns=s.last_observed_ns=evidence_ns; s.required_ack=0;
        s.prefix=actual_first_prefix; *out={index,s.lease};
        ++stats_.reserved; ++stats_.live;
        if(stats_.live>stats_.peak_live)stats_.peak_live=stats_.live;
        return true;
    }
    bool observe(Handle h, uint64_t actual_semantic_ns) {
        Slot *s=get(h);
        if(!s || s->state!=State::Pending || actual_semantic_ns<s->last_observed_ns)return reject();
        s->last_observed_ns=actual_semantic_ns;return true;
    }
    bool continue_generation(Handle h, const Identity &successor) {
        Slot *s=get(h);
        if(!s || s->state!=State::Pending || successor.event_token!=s->identity.event_token ||
           successor.logical_connection_id!=s->identity.logical_connection_id ||
           successor.first_semantic_ns!=s->identity.first_semantic_ns || !successor.flow_generation ||
           (successor.flow_generation==s->identity.flow_generation && successor.flow_index==s->identity.flow_index))
            return reject();
        s->identity=successor;return true; // preserve evidence; CONTINUE is not terminal
    }
    bool primary_admitted(Handle h, uint64_t sequence) {
        Slot *s=get(h);
        if(!s || s->state!=State::Pending || sequence<=s->prefix.sequence || sequence<=last_ack_prefix_)
            return reject();
        s->state=State::PrimaryAwaitAck;s->required_ack=sequence;++stats_.superseded;
        return true; // zero fallback model calls, retain snapshot until ACK
    }
    bool prepare_terminal(Handle h, const TerminalProof &proof, Work *out) {
        Slot *s=get(h);
        const bool supported=proof.kind==TerminalKind::InputEof ||
            proof.kind==TerminalKind::ValidatedIdleExpiry || proof.kind==TerminalKind::ValidatedProtocolEnd;
        if(!s || !out || s->state!=State::Pending || !supported ||
           !proof.input_frontier_closed || !proof.event_has_no_primary ||
           proof.semantic_frontier_ns<s->last_observed_ns || !proof.physical_enqueue_ns ||
           proof.sequence<=s->prefix.sequence || proof.sequence<=last_ack_prefix_)return reject();
        Work work{};work.request=s->prefix;work.request.sequence=proof.sequence;
        work.identity=s->identity;work.evidence_semantic_ns=s->evidence_ns;
        work.trigger_semantic_ns=proof.semantic_frontier_ns;
        work.physical_enqueue_ns=proof.physical_enqueue_ns;work.trigger=proof.kind;
        s->required_ack=proof.sequence;s->state=State::CoverageInFlight;
        ++stats_.coverage_leases;*out=work;return true;
    }
    bool abort_terminal(Handle h, uint64_t sequence) {
        Slot *s=get(h);
        if(!s || s->state!=State::CoverageInFlight || s->required_ack!=sequence)return reject();
        s->state=State::Pending;s->required_ack=0;++stats_.aborted;return true;
    }
    bool decision_persisted(Handle h, const fk_native_fusion_result &result) {
        Slot *s=get(h);
        if(!s || s->state!=State::CoverageInFlight || result.sequence!=s->required_ack ||
           result.event_token!=s->identity.event_token || !std::isfinite(result.score) ||
           result.score<0 || result.score>1 || result.alert_latched>1 || result.threshold_met>1 ||
           result.first_alert>1 || (result.threshold_met && !result.alert_latched) ||
           (result.first_alert && !result.threshold_met))return reject();
        for(uint8_t v:result.reserved)if(v!=0)return reject();
        // This call must follow successful native history + result persistence;
        // it is not itself an I/O operation or a durability proof.
        s->state=State::CoverageAwaitAck;++stats_.coverage_committed;return true;
    }
    bool release_after_durable_ack(Handle h, uint64_t durable_ack_prefix) {
        Slot *s=get(h);
        if(!s || (s->state!=State::PrimaryAwaitAck && s->state!=State::CoverageAwaitAck) ||
           durable_ack_prefix<s->required_ack || durable_ack_prefix<last_ack_prefix_)return reject();
        last_ack_prefix_=durable_ack_prefix;
        const uint64_t old_lease=s->lease;*s=Slot{};s->lease=old_lease;
        --stats_.live;++stats_.released;return true;
    }
};
} // namespace flowkeep
#endif
