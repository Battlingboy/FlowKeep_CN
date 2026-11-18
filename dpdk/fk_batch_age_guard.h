#ifndef FLOWKEEP_BATCH_AGE_GUARD_H
#define FLOWKEEP_BATCH_AGE_GUARD_H
#include <algorithm>
#include <cstdint>

namespace flowkeep {
// Physical batching clock only: a queued item must not receive a fresh full
// coalescing interval after the preceding synchronous inference/WAL batch.
// Saturating subtraction avoids overflow near UINT64_MAX. Clock failures
// surrender optional waiting; the caller's timestamp validation still fails
// invalid requests closed. This never changes FIFO order or the decision SLA.
inline uint64_t BatchAgeRemainingNs(uint64_t received_ns, uint64_t now_ns,
                                    uint64_t maximum_wait_ns) noexcept {
    if (!received_ns || !now_ns || now_ns < received_ns)
        return 0;
    const uint64_t age = now_ns - received_ns;
    return age >= maximum_wait_ns ? 0 : maximum_wait_ns - age;
}

// Once the physical deadline has already been missed, flushing each newly
// routed item cannot rescue it. Coalesce for at most 1 ms from the supplied
// fixed batch-activation anchor, not from every wake-up. Never extend a live deadline;
// miss accounting continues to use the unchanged physical enqueue timestamp.
inline uint64_t OverdueBatchRecoveryNs(uint64_t physical_ns,
        uint64_t batch_started_ns, uint64_t now_ns, uint64_t deadline_ns,
        uint64_t maximum_wait_ns) noexcept {
    if (!physical_ns || !now_ns || now_ns < physical_ns ||
        now_ns - physical_ns < deadline_ns)
        return 0;
    return BatchAgeRemainingNs(batch_started_ns, now_ns,
        std::min<uint64_t>(maximum_wait_ns, UINT64_C(1000000)));
}
}
#endif
