#ifndef FK_ORDERED_HANDOFF_BATCH_H
#define FK_ORDERED_HANDOFF_BATCH_H

#include <algorithm>
#include <array>
#include <cstdint>

namespace fk_ordered_handoff {

constexpr uint16_t kMaximumOwners = 64u;
constexpr uint32_t kMaximumBatch = 1024u;

/* The multi-producer publication generation is only a wake-up hint.  Exact
 * readiness is always revalidated against the ordered head slot. */
inline bool publication_generation_advanced(
        uint64_t observed_generation,
        uint64_t generation_at_last_gap) {
    return observed_generation != generation_at_last_gap;
}

inline bool should_probe_ordered_head(
        uint64_t observed_generation,
        uint64_t generation_at_last_gap,
        bool force_head_probe) {
    return force_head_probe || publication_generation_advanced(
        observed_generation, generation_at_last_gap);
}

enum class ExactReadyCreditStatus : uint8_t {
    kDispatch,
    kWait,
    kComplete,
    kInvalid,
};

struct ExactReadyCreditPlan {
    ExactReadyCreditStatus status = ExactReadyCreditStatus::kInvalid;
    uint32_t maximum_dispatch = 0u;
    uint64_t execution_ahead = 0u;
    uint64_t available_credit = 0u;
};

/*
 * Bound owner execution by the globally exact-ready packet prefix.  The
 * subtraction form deliberately avoids ready_prefix + window, so the plan is
 * well-defined even at the uint64 sequence tail.  Invalid relationships fail
 * closed instead of silently granting credit.
 */
inline ExactReadyCreditPlan plan_exact_ready_credit(
        uint64_t next_sequence,
        uint64_t ready_prefix,
        uint64_t expected_packets,
        uint64_t window,
        uint32_t requested_maximum,
        uint32_t minimum_dispatch = 1u) {
    ExactReadyCreditPlan plan{};
    if (window == 0u || requested_maximum == 0u || minimum_dispatch == 0u ||
        minimum_dispatch > requested_maximum || minimum_dispatch > window ||
        next_sequence > expected_packets || ready_prefix > next_sequence) {
        return plan;
    }
    plan.execution_ahead = next_sequence - ready_prefix;
    if (plan.execution_ahead > window)
        return plan;
    if (next_sequence == expected_packets) {
        plan.status = ExactReadyCreditStatus::kComplete;
        return plan;
    }
    if (plan.execution_ahead == window) {
        plan.status = ExactReadyCreditStatus::kWait;
        return plan;
    }

    const uint64_t available = window - plan.execution_ahead;
    plan.available_credit = available;
    const uint64_t remaining = expected_packets - next_sequence;
    const uint64_t required = std::min<uint64_t>(minimum_dispatch, remaining);
    /* Replenishing one packet of credit at a time turns the ordered handoff
     * into millions of tiny owner-ring reservations.  Accumulate a bounded
     * dispatch quantum while input remains, but always release the exact EOF
     * remainder.  This changes neither the execution-ahead window nor global
     * sequence order. */
    if (available < required) {
        plan.status = ExactReadyCreditStatus::kWait;
        return plan;
    }
    plan.maximum_dispatch = static_cast<uint32_t>(std::min<uint64_t>(
        requested_maximum, std::min<uint64_t>(available, remaining)));
    if (plan.maximum_dispatch == 0u)
        return plan;
    plan.status = ExactReadyCreditStatus::kDispatch;
    return plan;
}

/*
 * A plan contains one contiguous global sequence prefix, stably partitioned
 * by owner.  Stable partitioning is important: workers may run independently,
 * but packets routed to one owner must retain their original sequence order.
 *
 * Payload is deliberately generic so the planner can be tested without DPDK.
 */
template <typename Payload>
struct BatchPlan {
    uint32_t prefix_count;
    std::array<uint32_t, kMaximumOwners> owner_counts;
    std::array<uint32_t, kMaximumOwners + 1u> owner_offsets;
    /* Compact list of owners that hold at least one packet in this batch.
     * The drain loops over this list instead of all 64 owners on every
     * (often two-packet) batch. */
    uint16_t active_owner_count = 0u;
    std::array<uint16_t, kMaximumOwners> active_owners{};
    /* Preserve the exact prefix order as well as the grouped view.  The
     * formal RX dispatcher uses this view when publishing to owner rings so
     * an optimization that groups owners can never change visibility order. */
    std::array<uint16_t, kMaximumBatch> sequence_owners{};
    std::array<Payload, kMaximumBatch> sequence_payloads{};
    std::array<Payload, kMaximumBatch> grouped_payloads;
};

/*
 * Reader(sequence, owner, payload) returns true only when the exact sequence
 * is ready.  A gap terminates the prefix; no sequence after the gap is read.
 * At most kMaximumBatch entries are scanned per call.
 */
template <typename Payload, typename Reader>
uint32_t build_batch_plan(
        uint64_t next_sequence,
        uint64_t expected_packets,
        uint16_t worker_count,
        uint32_t requested_maximum,
        Reader &&reader,
        BatchPlan<Payload> &plan) {
    plan.prefix_count = 0u;
    plan.owner_counts.fill(0u);
    plan.owner_offsets.fill(0u);
    plan.active_owner_count = 0u;
    /* Do not clear the 1,024-entry prefix scratch arrays here.  Live RSS
     * interleaving commonly exposes only a handful of exact-ready packets
     * per call, and build_batch_plan overwrites every entry below
     * prefix_count before either array is read.  Clearing their unused tail
     * made the sole ordered consumer write roughly 10 KiB for an average
     * seven-packet DoH batch, directly limiting the 9.8 Gb/s drain. */
    if (worker_count == 0u || worker_count > kMaximumOwners ||
        requested_maximum == 0u || next_sequence >= expected_packets) {
        return 0u;
    }

    const uint64_t remaining = expected_packets - next_sequence;
    const uint32_t scan_limit = static_cast<uint32_t>(std::min<uint64_t>(
        std::min<uint32_t>(requested_maximum, kMaximumBatch), remaining));
    while (plan.prefix_count < scan_limit) {
        uint16_t owner = 0u;
        Payload payload{};
        const uint64_t sequence = next_sequence + plan.prefix_count;
        if (!reader(sequence, owner, payload) || owner >= worker_count)
            break;
        plan.sequence_owners[plan.prefix_count] = owner;
        plan.sequence_payloads[plan.prefix_count] = payload;
        if (plan.owner_counts[owner] == 0u) {
            plan.active_owners[plan.active_owner_count++] = owner;
        }
        ++plan.owner_counts[owner];
        ++plan.prefix_count;
    }
    if (plan.prefix_count == 0u)
        return 0u;

    uint32_t offset = 0u;
    for (uint16_t owner = 0u; owner < worker_count; ++owner) {
        plan.owner_offsets[owner] = offset;
        offset += plan.owner_counts[owner];
    }
    plan.owner_offsets[worker_count] = offset;

    std::array<uint32_t, kMaximumOwners> cursors;
    for (uint16_t owner = 0u; owner < worker_count; ++owner)
        cursors[owner] = plan.owner_offsets[owner];
    for (uint32_t index = 0u; index < plan.prefix_count; ++index) {
        const uint16_t owner = plan.sequence_owners[index];
        plan.grouped_payloads[cursors[owner]++] =
            plan.sequence_payloads[index];
    }
    return plan.prefix_count;
}

/*
 * Call this before publishing any owner batch.  With a single producer and
 * dequeue-only consumers, a successful snapshot cannot become smaller, so
 * the subsequent owner bulk enqueues are an all-or-none prefix commit.
 */
template <typename Payload, typename Available>
bool capacity_available(
        const BatchPlan<Payload> &plan,
        uint16_t worker_count,
        Available &&available) {
    if (worker_count == 0u || worker_count > kMaximumOwners ||
        plan.prefix_count == 0u)
        return false;
    for (uint16_t index = 0u; index < plan.active_owner_count; ++index) {
        const uint16_t owner = plan.active_owners[index];
        if (available(owner) < plan.owner_counts[owner])
            return false;
    }
    return true;
}

}  // namespace fk_ordered_handoff

#endif
