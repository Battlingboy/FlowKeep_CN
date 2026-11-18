#ifndef FK_OWNER_TAIL_EPOCH_H
#define FK_OWNER_TAIL_EPOCH_H

namespace fk_owner_tail_epoch {
enum class Boundary { PhysicalIdle, SemanticBoundary, Shutdown };

// Finishing classifier checkpoints is not finishing a connection. A pump
// cache cannot observe ordered Core reclamation, expiry or continuation
// state. Until an ordered owner-acknowledged metadata handoff exists, every
// packet must reach its sole lifecycle owner. The owner's bounded tail batch
// still skips feature extraction while preserving counters, clocks and TCP.
constexpr bool AllowsPumpZeroMessageBypass() { return false; }

// A zero-packet owner poll can mean that a globally ordered stream is
// waiting for its exclusive ingress watermark, rather than a real traffic
// idle.  Keep a bounded final-tail batch across those transient polls and
// flush it before the owner sleeps (or when input closes).  This preserves
// packet order and lifecycle ownership while avoiding schedule-dependent
// tiny batches on a hot flow.
constexpr bool FlushBufferedTailOnEmptyPoll(
        bool handoff_empty,
        bool owner_will_sleep,
        bool input_closed) {
    return input_closed || (handoff_empty && owner_will_sleep);
}

// Owner-visible key boundaries also depend on terminal-pump cache hits.
// Closing a batching epoch may disarm the cache, but MUST NOT retire a Core.
// Actual retirement belongs to the runtime's idle/tuple/capacity contracts.
// All retained Core/lease allocation stays charged to the hard budget.
template <typename Flush, typename Close>
bool Quiesce(Boundary boundary, Flush flush, Close close) {
    if (!flush())
        return false;
    return boundary == Boundary::PhysicalIdle ? true : close();
}
}  // namespace fk_owner_tail_epoch
#endif
