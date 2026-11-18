#include "fk_exact_identity_rx_worker_pump.h"

#include "fk_owner_pipeline_abort_coordinator.h"

#include <atomic>
#include <cstddef>
#include <cstdio>
#include <cstring>
#include <limits>
#include <new>

namespace {

constexpr uint64_t kMagic = UINT64_C(0x464b455852585031);  // "FKEXRXP1"

enum class ClearKind : uint8_t {
    None = 0u,
    Skip = 1u,
    Reject = 2u,
};

enum class ReclaimKind : uint8_t {
    None = 0u,
    Skip = 1u,
    Reject = 2u,
    AbortDrain = 3u,
};

struct PumpState {
    uint64_t magic = 0u;
    fk_exact_identity_rx_worker_pump_config config{};
    size_t reserved_bytes = 0u;
    uint64_t pump_instance_token = 0u;
    std::atomic<uint64_t> identity_thread_token{0u};
    std::atomic<uint64_t> identity_claim_attempts{0u};
    std::atomic<uint64_t> identity_claim_successes{0u};
    std::atomic<uint64_t> identity_claim_rejections{0u};
    std::atomic<uint64_t> wrong_thread_calls{0u};
    std::atomic<uint8_t> shared_counter_overflow{0u};
    fk_exact_identity_rx_worker_pump_stats counters{};
    fk_exact_identity_packet current{};
    fk_exact_identity_packet router_abort_descriptor{};
    fk_exact_identity_rx_worker_abort_receipt_v1 abort_receipt{};
    fk_owner_abort_identity_prepared_receipt_v1 prepared_receipt{};
    fk_exact_identity_router_detach_receipt_v1 router_detach_receipt{};
    fk_exact_identity_rx_worker_terminal_reason terminal_reason =
        FK_EXACT_IDENTITY_RX_WORKER_TERMINAL_NONE;
    ClearKind clear_kind = ClearKind::None;
    ReclaimKind reclaim_kind = ReclaimKind::None;
    uint16_t owner_count = 0u;
    uint8_t initialized = 0u;
    uint8_t current_packet = 0u;
    uint8_t source_claimed = 0u;
    uint8_t reclaim_pending = 0u;
    uint8_t router_abort_candidate = 0u;
    uint8_t sequencer_abort_started = 0u;
    uint8_t sequencer_complete_observed = 0u;
    uint8_t reservations_stopped = 0u;
    uint8_t aborting = 0u;
    uint8_t abort_prepared = 0u;
    uint8_t needs_global_abort = 0u;
    uint8_t stopped_normal = 0u;
    uint8_t stopped_abort = 0u;
    uint8_t counter_overflow = 0u;
    uint8_t ownership_indeterminate = 0u;
    uint8_t abort_unrecoverable = 0u;
    uint8_t reserved[1]{};
};

static_assert(alignof(PumpState) <= alignof(max_align_t),
    "exact RX worker pump placement alignment changed");

std::atomic<uint64_t> g_next_identity_thread_token{1u};
std::atomic<uint64_t> g_next_pump_instance_token{1u};

PumpState *implementation(fk_exact_identity_rx_worker_pump *pump) {
    return reinterpret_cast<PumpState *>(pump);
}

const PumpState *implementation(
        const fk_exact_identity_rx_worker_pump *pump) {
    return reinterpret_cast<const PumpState *>(pump);
}

void set_error(char *error, size_t capacity, const char *message) {
    if (error == nullptr || capacity == 0u)
        return;
    std::snprintf(error, capacity, "%s", message == nullptr ? "" : message);
}

bool all_zero(const uint8_t *bytes, size_t count) {
    if (bytes == nullptr)
        return false;
    uint8_t combined = 0u;
    for (size_t index = 0u; index < count; ++index)
        combined = static_cast<uint8_t>(combined | bytes[index]);
    return combined == 0u;
}

bool config_shape_valid(
        const fk_exact_identity_rx_worker_pump_config *config) {
    return config != nullptr &&
        config->abi_version ==
            FK_EXACT_IDENTITY_RX_WORKER_PUMP_ABI_VERSION &&
        config->producer_count != 0u &&
        config->producer_count <=
            FK_EXACT_IDENTITY_SEQUENCER_MAX_PRODUCERS &&
        all_zero(config->reserved0, sizeof(config->reserved0)) &&
        all_zero(config->reserved, sizeof(config->reserved)) &&
        config->sequencer != nullptr && config->source != nullptr &&
        config->router != nullptr && config->completion_bridge != nullptr &&
        config->reclaim != nullptr;
}

uint64_t allocate_monotonic_token(std::atomic<uint64_t> &next) {
    uint64_t candidate =
        next.load(std::memory_order_relaxed);
    while (candidate != 0u) {
        const uint64_t successor =
            candidate == std::numeric_limits<uint64_t>::max()
                ? 0u : candidate + 1u;
        if (next.compare_exchange_weak(
                candidate,
                successor,
                std::memory_order_relaxed,
                std::memory_order_relaxed)) {
            return candidate;
        }
    }
    return 0u;
}

uint64_t allocate_identity_thread_token() {
    return allocate_monotonic_token(g_next_identity_thread_token);
}

uint64_t current_thread_token() {
    static thread_local const uint64_t token =
        allocate_identity_thread_token();
    return token;
}

bool owner_thread(const PumpState &state) {
    const uint64_t current = current_thread_token();
    const uint64_t owner =
        state.identity_thread_token.load(std::memory_order_acquire);
    return current != 0u && owner != 0u && current == owner;
}

bool check_owner_or_reject(PumpState &state) {
    if (owner_thread(state))
        return true;
    uint64_t observed =
        state.wrong_thread_calls.load(std::memory_order_relaxed);
    for (;;) {
        if (observed == std::numeric_limits<uint64_t>::max()) {
            state.shared_counter_overflow.store(
                1u, std::memory_order_release);
            break;
        }
        if (state.wrong_thread_calls.compare_exchange_weak(
                observed,
                observed + 1u,
                std::memory_order_relaxed,
                std::memory_order_relaxed)) {
            break;
        }
    }
    return false;
}

bool increment_atomic_checked(
        PumpState &state,
        std::atomic<uint64_t> &counter) {
    uint64_t observed = counter.load(std::memory_order_relaxed);
    for (;;) {
        if (observed == std::numeric_limits<uint64_t>::max()) {
            state.shared_counter_overflow.store(
                1u, std::memory_order_release);
            return false;
        }
        if (counter.compare_exchange_weak(
                observed,
                observed + 1u,
                std::memory_order_relaxed,
                std::memory_order_relaxed)) {
            return true;
        }
    }
}

void mark_terminal(
        PumpState &state,
        fk_exact_identity_rx_worker_terminal_reason reason) {
    if (state.terminal_reason ==
            FK_EXACT_IDENTITY_RX_WORKER_TERMINAL_NONE) {
        state.terminal_reason = reason;
    }
}

bool increment(PumpState &state, uint64_t &counter, uint64_t value = 1u) {
    if (value > std::numeric_limits<uint64_t>::max() - counter) {
        state.counter_overflow = 1u;
        state.abort_unrecoverable = 1u;
        mark_terminal(
            state,
            FK_EXACT_IDENTITY_RX_WORKER_TERMINAL_COUNTER_OVERFLOW);
        return false;
    }
    counter += value;
    return true;
}

bool checked_sum_equals(
        uint64_t expected,
        const uint64_t *values,
        size_t count) {
    uint64_t sum = 0u;
    for (size_t index = 0u; index < count; ++index) {
        if (values[index] > std::numeric_limits<uint64_t>::max() - sum)
            return false;
        sum += values[index];
    }
    return sum == expected;
}

void update_pending_peak(PumpState &state) {
    const uint64_t pending = state.current_packet != 0u ? 1u : 0u;
    if (pending > state.counters.peak_pending_owned_packets)
        state.counters.peak_pending_owned_packets = pending;
}

bool set_current(
        PumpState &state,
        const fk_exact_identity_packet &packet) {
    if (state.current_packet != 0u || packet.packet_handle == 0u)
        return false;
    state.current = packet;
    state.current_packet = 1u;
    state.source_claimed = 0u;
    state.reclaim_pending = 0u;
    state.clear_kind = ClearKind::None;
    state.reclaim_kind = ReclaimKind::None;
    if (!increment(state, state.counters.submitted_packets))
        return false;
    update_pending_peak(state);
    return true;
}

void clear_current(PumpState &state) {
    state.current = {};
    state.current_packet = 0u;
    state.source_claimed = 0u;
    state.reclaim_pending = 0u;
    state.clear_kind = ClearKind::None;
    state.reclaim_kind = ReclaimKind::None;
}

void record_abort_receipt_once(PumpState &state) {
    if (state.abort_receipt.abi_version != 0u)
        return;
    fk_exact_identity_rx_worker_abort_receipt_v1 receipt{};
    receipt.abi_version = FK_EXACT_IDENTITY_RX_WORKER_PUMP_ABI_VERSION;
    receipt.first_reason = state.terminal_reason;
    receipt.receipt_ordinal = 1u;
    if (state.current_packet != 0u) {
        receipt.descriptor = state.current;
        receipt.descriptor_present = 1u;
        fk_owner_reserved_abort_receipt_v1 bridge_receipt{};
        if (fk_owner_output_sequence_bridge_get_abort_receipt(
                state.config.completion_bridge, &bridge_receipt) &&
            bridge_receipt.packet_sequence ==
                state.current.packet_sequence) {
            receipt.bridge_receipt = bridge_receipt;
            receipt.bridge_receipt_present = 1u;
        }
    }
    state.abort_receipt = receipt;
}

bool stop_reservations(PumpState &state) {
    if (state.reservations_stopped != 0u)
        return true;
    (void)increment(
        state, state.counters.bridge_stop_reservation_attempts);
    if (!fk_owner_output_sequence_bridge_stop_reservations(
            state.config.completion_bridge)) {
        (void)increment(
            state, state.counters.bridge_stop_reservation_failures);
        state.abort_unrecoverable = 1u;
        mark_terminal(
            state,
            FK_EXACT_IDENTITY_RX_WORKER_TERMINAL_RESERVATION_STOP);
        return false;
    }
    state.reservations_stopped = 1u;
    (void)increment(
        state, state.counters.bridge_stop_reservation_successes);
    return true;
}

void begin_abort_prepare(
        PumpState &state,
        fk_exact_identity_rx_worker_terminal_reason reason) {
    mark_terminal(state, reason);
    record_abort_receipt_once(state);
    state.aborting = 1u;
    state.needs_global_abort = 1u;
    if (state.sequencer_abort_started == 0u) {
        state.sequencer_abort_started = 1u;
        (void)increment(state, state.counters.sequencer_abort_attempts);
        const bool first = fk_exact_identity_sequencer_abort(
            state.config.sequencer);
        fk_exact_identity_sequencer_stats stats{};
        if (first ||
            (fk_exact_identity_sequencer_get_stats(
                 state.config.sequencer, &stats) &&
             stats.terminal_reason != FK_EXACT_IDENTITY_TERMINAL_NONE)) {
            (void)increment(
                state, state.counters.sequencer_abort_acknowledged);
        } else {
            (void)increment(
                state, state.counters.sequencer_abort_failures);
            state.abort_unrecoverable = 1u;
        }
    }
    (void)stop_reservations(state);
}

bool attempt_source_clear(PumpState &state) {
    if (state.source_claimed == 0u)
        return true;
    fk_dpdk_exact_identity_mbuf_clear_result result =
        FK_DPDK_EXACT_IDENTITY_MBUF_CLEAR_INVALID;
    if (state.clear_kind == ClearKind::Skip) {
        (void)increment(state, state.counters.source_skip_clear_attempts);
        result = fk_dpdk_exact_identity_mbuf_source_clear_skip_for_reclaim(
            state.config.source, &state.current);
        if (result == FK_DPDK_EXACT_IDENTITY_MBUF_CLEARED)
            (void)increment(state, state.counters.source_skip_clears);
        else
            (void)increment(
                state, state.counters.source_skip_clear_failures);
    } else {
        state.clear_kind = ClearKind::Reject;
        (void)increment(state, state.counters.source_reject_clear_attempts);
        result = fk_dpdk_exact_identity_mbuf_source_clear_reject_for_reclaim(
            state.config.source, &state.current);
        if (result == FK_DPDK_EXACT_IDENTITY_MBUF_CLEARED)
            (void)increment(state, state.counters.source_reject_clears);
        else
            (void)increment(
                state, state.counters.source_reject_clear_failures);
    }
    if (result != FK_DPDK_EXACT_IDENTITY_MBUF_CLEARED)
        return false;
    state.source_claimed = 0u;
    state.clear_kind = ClearKind::None;
    state.reclaim_pending = 1u;
    return true;
}

bool attempt_reclaim(PumpState &state) {
    if (state.current_packet == 0u || state.reclaim_pending == 0u ||
        state.source_claimed != 0u ||
        state.reclaim_kind == ReclaimKind::None) {
        if (state.current_packet != 0u &&
            state.reclaim_pending != 0u &&
            state.source_claimed == 0u &&
            state.reclaim_kind == ReclaimKind::None) {
            state.abort_unrecoverable = 1u;
        }
        return false;
    }
    (void)increment(state, state.counters.reclaim_attempts);
    if (!state.config.reclaim(
            state.config.reclaim_context,
            state.current.packet_handle)) {
        (void)increment(state, state.counters.reclaim_failures);
        return false;
    }
    (void)increment(state, state.counters.reclaim_successes);
    (void)increment(state, state.counters.reclaimed_packets);
    switch (state.reclaim_kind) {
    case ReclaimKind::Skip:
        (void)increment(state, state.counters.reclaimed_skip_packets);
        break;
    case ReclaimKind::Reject:
        (void)increment(state, state.counters.reclaimed_reject_packets);
        break;
    case ReclaimKind::AbortDrain:
        (void)increment(
            state, state.counters.reclaimed_abort_drain_packets);
        break;
    case ReclaimKind::None:
        /* Rejected before invoking the ownership-consuming callback. */
        return false;
    }
    clear_current(state);
    return true;
}

bool attempt_router_detach(PumpState &state) {
    if (state.router_abort_candidate == 0u)
        return true;
    (void)increment(state, state.counters.router_detach_attempts);
    fk_exact_identity_router_detach_receipt_v1 receipt{};
    const fk_exact_identity_router_detach_pending_result detached =
        fk_exact_identity_router_detach_pending_for_global_abort(
            state.config.router,
            &state.router_abort_descriptor,
            &receipt);
    if (detached ==
            FK_EXACT_IDENTITY_ROUTER_DETACH_PENDING_DETACHED) {
        state.router_detach_receipt = receipt;
        state.router_abort_candidate = 0u;
        (void)increment(state, state.counters.router_detach_successes);
        return true;
    }
    if (detached ==
            FK_EXACT_IDENTITY_ROUTER_DETACH_PENDING_ALREADY_DETACHED) {
        state.router_detach_receipt = receipt;
        state.router_abort_candidate = 0u;
        (void)increment(
            state, state.counters.router_detach_already_detached);
        return true;
    }
    if (detached == FK_EXACT_IDENTITY_ROUTER_DETACH_PENDING_NONE) {
        /* Completion-window pressure can occur before the router owns a
         * reservation/prepared publisher transaction. There is then no
         * router-local candidate for global cleanup. */
        state.router_abort_descriptor = {};
        state.router_abort_candidate = 0u;
        (void)increment(state, state.counters.router_detach_none);
        return true;
    }
    (void)increment(state, state.counters.router_detach_failures);
    state.abort_unrecoverable = 1u;
    return false;
}

void record_prepared_receipt_once(PumpState &state) {
    if (state.prepared_receipt.abi_version != 0u)
        return;
    fk_owner_abort_identity_prepared_receipt_v1 receipt;
    std::memset(&receipt, 0, sizeof(receipt));
    receipt.abi_version = FK_OWNER_ABORT_PROTOCOL_ABI_VERSION;
    receipt.producer_count = state.config.producer_count;
    receipt.receipt_ordinal = 1u;
    receipt.pump_instance_token = state.pump_instance_token;
    receipt.submitted_packets = state.counters.submitted_packets;
    receipt.data_transfers = state.counters.data_transfers;
    receipt.reclaimed_packets = state.counters.reclaimed_packets;
    receipt.first_reason = static_cast<uint32_t>(state.terminal_reason);
    if (state.router_detach_receipt.abi_version ==
            FK_EXACT_IDENTITY_ROUTER_DETACH_RECEIPT_ABI_VERSION) {
        receipt.candidate = state.router_detach_receipt.descriptor;
        receipt.candidate_present = 1u;
        receipt.router_candidate_present = 1u;
    } else if (state.abort_receipt.descriptor_present != 0u) {
        receipt.candidate = state.abort_receipt.descriptor;
        receipt.candidate_present = 1u;
    }
    std::memcpy(
        &state.prepared_receipt, &receipt, sizeof(state.prepared_receipt));
}

fk_exact_identity_rx_worker_step_result finish_step(
        PumpState &state,
        fk_exact_identity_rx_worker_step_result result) {
    uint64_t *counter = nullptr;
    switch (result) {
    case FK_EXACT_IDENTITY_RX_WORKER_STEP_IDLE:
        counter = &state.counters.step_idle;
        break;
    case FK_EXACT_IDENTITY_RX_WORKER_STEP_DATA_TRANSFERRED:
        counter = &state.counters.step_data_transferred;
        break;
    case FK_EXACT_IDENTITY_RX_WORKER_STEP_PACKET_RECLAIMED:
        counter = &state.counters.step_packet_reclaimed;
        break;
    case FK_EXACT_IDENTITY_RX_WORKER_STEP_BACKPRESSURE_RETAINED:
        counter = &state.counters.step_backpressure_retained;
        break;
    case FK_EXACT_IDENTITY_RX_WORKER_STEP_RECLAIM_RETRY:
        counter = &state.counters.step_reclaim_retry;
        break;
    case FK_EXACT_IDENTITY_RX_WORKER_STEP_COMPLETE:
        counter = &state.counters.step_complete;
        break;
    case FK_EXACT_IDENTITY_RX_WORKER_STEP_TERMINAL:
        counter = &state.counters.step_terminal;
        break;
    case FK_EXACT_IDENTITY_RX_WORKER_STEP_STOPPED:
        counter = &state.counters.step_stopped;
        break;
    case FK_EXACT_IDENTITY_RX_WORKER_STEP_INVALID:
    case FK_EXACT_IDENTITY_RX_WORKER_STEP_WRONG_THREAD:
        break;
    }
    if (counter != nullptr)
        (void)increment(state, *counter);
    return result;
}

fk_exact_identity_rx_worker_step_result route_current(PumpState &state) {
    (void)increment(state, state.counters.router_calls);
    fk_exact_identity_router_result result{};
    const fk_exact_identity_router_outcome outcome =
        fk_exact_identity_router_process(
            state.config.router, &state.current, &result);
    if (outcome ==
            FK_EXACT_IDENTITY_ROUTER_DATA_COMMITTED_TRANSFER) {
        (void)increment(state, state.counters.router_data_committed);
        state.router_abort_candidate = 0u;
        (void)increment(
            state, state.counters.source_transfer_clear_attempts);
        const fk_dpdk_exact_identity_mbuf_clear_result cleared =
            fk_dpdk_exact_identity_mbuf_source_transfer_data_committed(
                state.config.source, &state.current);
        /* Dispatch commit is the ownership linearization point, regardless
         * of whether the local post-commit bookkeeping clear succeeds. */
        (void)increment(state, state.counters.data_transfers);
        if (cleared != FK_DPDK_EXACT_IDENTITY_MBUF_CLEARED) {
            (void)increment(
                state, state.counters.source_transfer_clear_failures);
            begin_abort_prepare(
                state,
                FK_EXACT_IDENTITY_RX_WORKER_TERMINAL_OWNERSHIP_INDETERMINATE);
            state.ownership_indeterminate = 1u;
            state.abort_unrecoverable = 1u;
            /* Never free: the fixed owner already owns the mbuf. */
            clear_current(state);
            return FK_EXACT_IDENTITY_RX_WORKER_STEP_TERMINAL;
        }
        (void)increment(state, state.counters.source_transfer_clears);
        clear_current(state);
        return FK_EXACT_IDENTITY_RX_WORKER_STEP_DATA_TRANSFERRED;
    }
    if (outcome == FK_EXACT_IDENTITY_ROUTER_SKIP_COMMITTED_RECLAIM) {
        (void)increment(state, state.counters.router_skip_committed);
        state.router_abort_candidate = 0u;
        state.clear_kind = ClearKind::Skip;
        state.reclaim_kind = ReclaimKind::Skip;
        if (!attempt_source_clear(state)) {
            begin_abort_prepare(
                state,
                FK_EXACT_IDENTITY_RX_WORKER_TERMINAL_SOURCE_TRANSITION);
            return FK_EXACT_IDENTITY_RX_WORKER_STEP_TERMINAL;
        }
        if (!attempt_reclaim(state))
            return FK_EXACT_IDENTITY_RX_WORKER_STEP_RECLAIM_RETRY;
        return FK_EXACT_IDENTITY_RX_WORKER_STEP_PACKET_RECLAIMED;
    }
    if (outcome == FK_EXACT_IDENTITY_ROUTER_BACKPRESSURE_RETAIN) {
        (void)increment(state, state.counters.router_backpressure);
        state.router_abort_descriptor = state.current;
        state.router_abort_candidate = 1u;
        (void)increment(state, state.counters.source_retain_attempts);
        const fk_dpdk_exact_identity_mbuf_retain_result retained =
            fk_dpdk_exact_identity_mbuf_source_retain_backpressure(
                state.config.source, &state.current);
        if (retained == FK_DPDK_EXACT_IDENTITY_MBUF_RETAINED) {
            (void)increment(state, state.counters.source_retain_successes);
            return
                FK_EXACT_IDENTITY_RX_WORKER_STEP_BACKPRESSURE_RETAINED;
        }
        (void)increment(state, state.counters.source_retain_failures);
        state.clear_kind = ClearKind::Reject;
        state.reclaim_kind = ReclaimKind::Reject;
        begin_abort_prepare(
            state,
            FK_EXACT_IDENTITY_RX_WORKER_TERMINAL_SOURCE_TRANSITION);
        (void)attempt_source_clear(state);
        if (state.reclaim_pending != 0u)
            (void)attempt_reclaim(state);
        return FK_EXACT_IDENTITY_RX_WORKER_STEP_TERMINAL;
    }

    if (outcome ==
            FK_EXACT_IDENTITY_ROUTER_TERMINAL_PENDING_GLOBAL_ABORT) {
        (void)increment(
            state, state.counters.router_terminal_or_invalid);
        state.router_abort_descriptor = state.current;
        state.router_abort_candidate = 1u;
        state.clear_kind = ClearKind::Reject;
        state.reclaim_kind = ReclaimKind::Reject;
        begin_abort_prepare(
            state, FK_EXACT_IDENTITY_RX_WORKER_TERMINAL_ROUTER);
        (void)attempt_source_clear(state);
        if (state.reclaim_pending != 0u)
            (void)attempt_reclaim(state);
        return FK_EXACT_IDENTITY_RX_WORKER_STEP_TERMINAL;
    }

    (void)increment(state, state.counters.router_terminal_or_invalid);
    state.router_abort_candidate = 0u;
    state.clear_kind = ClearKind::Reject;
    state.reclaim_kind = ReclaimKind::Reject;
    begin_abort_prepare(
        state, FK_EXACT_IDENTITY_RX_WORKER_TERMINAL_ROUTER);
    (void)attempt_source_clear(state);
    if (state.reclaim_pending != 0u)
        (void)attempt_reclaim(state);
    return FK_EXACT_IDENTITY_RX_WORKER_STEP_TERMINAL;
}

bool accounting_conserved(const PumpState &state) {
    const auto &s = state.counters;
    const uint64_t pending = state.current_packet != 0u ? 1u : 0u;
    const uint64_t submitted_partition[]{
        s.data_transfers,
        s.reclaimed_packets,
        pending,
    };
    const uint64_t handoff_partition[]{
        s.sequencer_poll_released,
        s.sequencer_drain_handoffs,
    };
    const uint64_t poll_partition[]{
        s.sequencer_poll_released,
        s.sequencer_poll_idle,
        s.sequencer_poll_complete,
        s.sequencer_poll_terminal,
        s.sequencer_poll_invalid,
    };
    const uint64_t source_claim_partition[]{
        s.source_claim_successes,
        s.source_claim_failures,
    };
    const uint64_t router_partition[]{
        s.router_data_committed,
        s.router_skip_committed,
        s.router_backpressure,
        s.router_terminal_or_invalid,
    };
    const uint64_t retain_partition[]{
        s.source_retain_successes,
        s.source_retain_failures,
    };
    const uint64_t transfer_partition[]{
        s.source_transfer_clears,
        s.source_transfer_clear_failures,
    };
    const uint64_t skip_partition[]{
        s.source_skip_clears,
        s.source_skip_clear_failures,
    };
    const uint64_t reject_partition[]{
        s.source_reject_clears,
        s.source_reject_clear_failures,
    };
    const uint64_t reclaim_partition[]{
        s.reclaim_successes,
        s.reclaim_failures,
    };
    const uint64_t reclaimed_kind_partition[]{
        s.reclaimed_skip_packets,
        s.reclaimed_reject_packets,
        s.reclaimed_abort_drain_packets,
    };
    const uint64_t step_partition[]{
        s.step_idle,
        s.step_data_transferred,
        s.step_packet_reclaimed,
        s.step_backpressure_retained,
        s.step_reclaim_retry,
        s.step_complete,
        s.step_terminal,
        s.step_stopped,
    };
    const uint64_t detach_partition[]{
        s.router_detach_successes,
        s.router_detach_already_detached,
        s.router_detach_none,
        s.router_detach_failures,
    };
    const uint64_t claim_attempts =
        state.identity_claim_attempts.load(std::memory_order_acquire);
    const uint64_t claim_partition[]{
        state.identity_claim_successes.load(std::memory_order_acquire),
        state.identity_claim_rejections.load(std::memory_order_acquire),
    };
    return state.initialized == 1u && state.current_packet <= 1u &&
        state.source_claimed <= 1u && state.reclaim_pending <= 1u &&
        state.shared_counter_overflow.load(std::memory_order_acquire) == 0u &&
        state.counters.peak_pending_owned_packets >= pending &&
        checked_sum_equals(
            claim_attempts,
            claim_partition,
            sizeof(claim_partition) / sizeof(claim_partition[0])) &&
        checked_sum_equals(
            s.submitted_packets,
            submitted_partition,
            sizeof(submitted_partition) / sizeof(submitted_partition[0])) &&
        checked_sum_equals(
            s.submitted_packets,
            handoff_partition,
            sizeof(handoff_partition) / sizeof(handoff_partition[0])) &&
        checked_sum_equals(
            s.sequencer_poll_calls,
            poll_partition,
            sizeof(poll_partition) / sizeof(poll_partition[0])) &&
        checked_sum_equals(
            s.source_claim_attempts,
            source_claim_partition,
            sizeof(source_claim_partition) /
                sizeof(source_claim_partition[0])) &&
        s.source_claim_attempts == s.sequencer_poll_released &&
        checked_sum_equals(
            s.router_calls,
            router_partition,
            sizeof(router_partition) / sizeof(router_partition[0])) &&
        checked_sum_equals(
            s.source_retain_attempts,
            retain_partition,
            sizeof(retain_partition) / sizeof(retain_partition[0])) &&
        checked_sum_equals(
            s.source_transfer_clear_attempts,
            transfer_partition,
            sizeof(transfer_partition) / sizeof(transfer_partition[0])) &&
        checked_sum_equals(
            s.source_skip_clear_attempts,
            skip_partition,
            sizeof(skip_partition) / sizeof(skip_partition[0])) &&
        checked_sum_equals(
            s.source_reject_clear_attempts,
            reject_partition,
            sizeof(reject_partition) / sizeof(reject_partition[0])) &&
        checked_sum_equals(
            s.reclaim_attempts,
            reclaim_partition,
            sizeof(reclaim_partition) / sizeof(reclaim_partition[0])) &&
        s.reclaim_successes == s.reclaimed_packets &&
        checked_sum_equals(
            s.reclaimed_packets,
            reclaimed_kind_partition,
            sizeof(reclaimed_kind_partition) /
                sizeof(reclaimed_kind_partition[0])) &&
        s.data_transfers == s.router_data_committed &&
        checked_sum_equals(
            s.step_calls,
            step_partition,
            sizeof(step_partition) / sizeof(step_partition[0])) &&
        checked_sum_equals(
            s.router_detach_attempts,
            detach_partition,
            sizeof(detach_partition) / sizeof(detach_partition[0])) &&
        s.reserved_bytes == state.reserved_bytes &&
        s.service_memory_bytes == state.reserved_bytes;
}

}  // namespace

extern "C" {

void fk_exact_identity_rx_worker_pump_default_config_init(
        fk_exact_identity_rx_worker_pump_config *config) {
    if (config == nullptr)
        return;
    *config = {};
    config->abi_version =
        FK_EXACT_IDENTITY_RX_WORKER_PUMP_ABI_VERSION;
    config->producer_count = 1u;
}

bool fk_exact_identity_rx_worker_pump_config_valid(
        const fk_exact_identity_rx_worker_pump_config *config) {
    return config_shape_valid(config);
}

size_t fk_exact_identity_rx_worker_pump_storage_bytes(
        const fk_exact_identity_rx_worker_pump_config *config) {
    return config_shape_valid(config) ? sizeof(PumpState) : 0u;
}

fk_exact_identity_rx_worker_pump *
fk_exact_identity_rx_worker_pump_initialize(
        void *storage,
        size_t storage_bytes,
        const fk_exact_identity_rx_worker_pump_config *config,
        char *error,
        size_t error_capacity) {
    set_error(error, error_capacity, "");
    if (storage == nullptr || storage_bytes < sizeof(PumpState) ||
        reinterpret_cast<uintptr_t>(storage) % alignof(max_align_t) != 0u ||
        !config_shape_valid(config)) {
        set_error(error, error_capacity,
            "invalid exact RX worker pump placement/configuration");
        return nullptr;
    }
    fk_exact_identity_sequencer_stats sequencer_stats{};
    fk_dpdk_exact_identity_mbuf_source_stats source_stats{};
    fk_exact_identity_router_stats router_stats{};
    fk_owner_output_sequence_bridge_stats bridge_stats{};
    if (!fk_exact_identity_sequencer_get_stats(
            config->sequencer, &sequencer_stats) ||
        !fk_dpdk_exact_identity_mbuf_source_get_stats(
            config->source, &source_stats) ||
        !fk_exact_identity_router_get_stats(
            config->router, &router_stats) ||
        !fk_owner_output_sequence_bridge_get_stats(
            config->completion_bridge, &bridge_stats) ||
        sequencer_stats.producer_count != config->producer_count ||
        source_stats.producer_count != config->producer_count ||
        source_stats.identity_thread_claimed != 0u ||
        source_stats.active_claim != 0u ||
        router_stats.identity_thread_claimed != 0u ||
        router_stats.sticky_failure != 0u ||
        router_stats.prepared_transaction != 0u ||
        router_stats.owner_count != bridge_stats.owner_count ||
        ((bridge_stats.readiness_mode ==
              FK_OWNER_OUTPUT_SEQUENCE_BRIDGE_READINESS_FINITE_BARRIER &&
          sequencer_stats.expected_packets != bridge_stats.expected_packets) ||
         (bridge_stats.readiness_mode ==
              FK_OWNER_OUTPUT_SEQUENCE_BRIDGE_READINESS_STREAMING_STRICT_PREFIX &&
          (bridge_stats.sequence_base != 0u ||
           sequencer_stats.expected_packets >
               bridge_stats.configured_packet_capacity))) ||
        bridge_stats.reservations_stopped || bridge_stats.terminal_failure) {
        set_error(error, error_capacity,
            "exact RX worker pump dependency topology is not pristine");
        return nullptr;
    }
    auto *state = new (storage) PumpState{};
    const uint64_t instance_token =
        allocate_monotonic_token(g_next_pump_instance_token);
    if (instance_token == 0u) {
        state->~PumpState();
        set_error(error, error_capacity,
            "exact RX worker pump instance-token space exhausted");
        return nullptr;
    }
    state->magic = kMagic;
    state->config = *config;
    state->reserved_bytes = sizeof(PumpState);
    state->pump_instance_token = instance_token;
    state->owner_count = bridge_stats.owner_count;
    state->counters.abi_version =
        FK_EXACT_IDENTITY_RX_WORKER_PUMP_ABI_VERSION;
    state->counters.producer_count = config->producer_count;
    state->counters.reserved_bytes = sizeof(PumpState);
    state->counters.service_memory_bytes = sizeof(PumpState);
    state->initialized = 1u;
    return reinterpret_cast<fk_exact_identity_rx_worker_pump *>(state);
}

bool fk_exact_identity_rx_worker_pump_claim_identity_thread(
        fk_exact_identity_rx_worker_pump *pump) {
    if (pump == nullptr)
        return false;
    PumpState &state = *implementation(pump);
    if (state.magic != kMagic || state.initialized == 0u)
        return false;
    if (!increment_atomic_checked(
            state, state.identity_claim_attempts)) {
        return false;
    }
    const uint64_t token = current_thread_token();
    uint64_t expected = 0u;
    if (token == 0u || !state.identity_thread_token.compare_exchange_strong(
            expected,
            token,
            std::memory_order_acq_rel,
            std::memory_order_acquire)) {
        (void)increment_atomic_checked(
            state, state.identity_claim_rejections);
        return false;
    }
    if (!fk_dpdk_exact_identity_mbuf_source_claim_identity_thread(
            state.config.source) ||
        !fk_exact_identity_router_claim_identity_thread(
            state.config.router)) {
        (void)increment_atomic_checked(
            state, state.identity_claim_rejections);
        mark_terminal(
            state, FK_EXACT_IDENTITY_RX_WORKER_TERMINAL_IDENTITY_CLAIM);
        state.abort_unrecoverable = 1u;
        record_abort_receipt_once(state);
        return false;
    }
    if (!increment_atomic_checked(
            state, state.identity_claim_successes)) {
        mark_terminal(
            state, FK_EXACT_IDENTITY_RX_WORKER_TERMINAL_COUNTER_OVERFLOW);
        state.abort_unrecoverable = 1u;
        return false;
    }
    return true;
}

fk_exact_identity_rx_worker_step_result
fk_exact_identity_rx_worker_pump_step(
        fk_exact_identity_rx_worker_pump *pump) {
    if (pump == nullptr)
        return FK_EXACT_IDENTITY_RX_WORKER_STEP_INVALID;
    PumpState &state = *implementation(pump);
    if (state.magic != kMagic || state.initialized == 0u)
        return FK_EXACT_IDENTITY_RX_WORKER_STEP_INVALID;
    if (!check_owner_or_reject(state))
        return FK_EXACT_IDENTITY_RX_WORKER_STEP_WRONG_THREAD;
    (void)increment(state, state.counters.step_calls);
    if (state.stopped_normal != 0u || state.stopped_abort != 0u)
        return finish_step(state, FK_EXACT_IDENTITY_RX_WORKER_STEP_STOPPED);
    if (state.aborting != 0u || state.terminal_reason !=
            FK_EXACT_IDENTITY_RX_WORKER_TERMINAL_NONE) {
        return finish_step(state, FK_EXACT_IDENTITY_RX_WORKER_STEP_TERMINAL);
    }
    if (state.reclaim_pending != 0u) {
        return finish_step(
            state,
            attempt_reclaim(state)
                ? FK_EXACT_IDENTITY_RX_WORKER_STEP_PACKET_RECLAIMED
                : FK_EXACT_IDENTITY_RX_WORKER_STEP_RECLAIM_RETRY);
    }
    if (state.current_packet != 0u) {
        return finish_step(state, route_current(state));
    }
    if (state.sequencer_complete_observed != 0u) {
        return finish_step(state, FK_EXACT_IDENTITY_RX_WORKER_STEP_COMPLETE);
    }

    (void)increment(state, state.counters.sequencer_poll_calls);
    fk_exact_identity_packet packet{};
    const fk_exact_identity_poll_result polled =
        fk_exact_identity_sequencer_poll(state.config.sequencer, &packet);
    if (polled == FK_EXACT_IDENTITY_POLL_IDLE) {
        (void)increment(state, state.counters.sequencer_poll_idle);
        return finish_step(state, FK_EXACT_IDENTITY_RX_WORKER_STEP_IDLE);
    }
    if (polled == FK_EXACT_IDENTITY_POLL_COMPLETE) {
        (void)increment(state, state.counters.sequencer_poll_complete);
        state.sequencer_complete_observed = 1u;
        return finish_step(state, FK_EXACT_IDENTITY_RX_WORKER_STEP_COMPLETE);
    }
    if (polled == FK_EXACT_IDENTITY_POLL_TERMINAL) {
        (void)increment(state, state.counters.sequencer_poll_terminal);
        begin_abort_prepare(
            state, FK_EXACT_IDENTITY_RX_WORKER_TERMINAL_SEQUENCER);
        return finish_step(state, FK_EXACT_IDENTITY_RX_WORKER_STEP_TERMINAL);
    }
    if (polled != FK_EXACT_IDENTITY_POLL_RELEASED) {
        (void)increment(state, state.counters.sequencer_poll_invalid);
        begin_abort_prepare(
            state, FK_EXACT_IDENTITY_RX_WORKER_TERMINAL_SEQUENCER);
        return finish_step(state, FK_EXACT_IDENTITY_RX_WORKER_STEP_TERMINAL);
    }

    (void)increment(state, state.counters.sequencer_poll_released);
    if (!set_current(state, packet)) {
        begin_abort_prepare(
            state, FK_EXACT_IDENTITY_RX_WORKER_TERMINAL_CONFIGURATION);
        return finish_step(state, FK_EXACT_IDENTITY_RX_WORKER_STEP_TERMINAL);
    }
    (void)increment(state, state.counters.source_claim_attempts);
    const fk_dpdk_exact_identity_mbuf_claim_result claimed =
        fk_dpdk_exact_identity_mbuf_source_claim_released(
            state.config.source, &state.current);
    if (claimed != FK_DPDK_EXACT_IDENTITY_MBUF_CLAIMED) {
        (void)increment(state, state.counters.source_claim_failures);
        state.reclaim_pending = 1u;
        state.reclaim_kind = ReclaimKind::Reject;
        begin_abort_prepare(
            state, FK_EXACT_IDENTITY_RX_WORKER_TERMINAL_SOURCE_CLAIM);
        (void)attempt_reclaim(state);
        return finish_step(state, FK_EXACT_IDENTITY_RX_WORKER_STEP_TERMINAL);
    }
    (void)increment(state, state.counters.source_claim_successes);
    state.source_claimed = 1u;
    return finish_step(state, route_current(state));
}

fk_exact_identity_rx_worker_stop_result
fk_exact_identity_rx_worker_pump_stop_normal(
        fk_exact_identity_rx_worker_pump *pump) {
    if (pump == nullptr)
        return FK_EXACT_IDENTITY_RX_WORKER_STOP_INVALID;
    PumpState &state = *implementation(pump);
    if (state.magic != kMagic || state.initialized == 0u)
        return FK_EXACT_IDENTITY_RX_WORKER_STOP_INVALID;
    if (!check_owner_or_reject(state))
        return FK_EXACT_IDENTITY_RX_WORKER_STOP_WRONG_THREAD;
    (void)increment(state, state.counters.normal_stop_attempts);
    if (state.stopped_normal != 0u || state.stopped_abort != 0u)
        return FK_EXACT_IDENTITY_RX_WORKER_STOP_ALREADY_STOPPED;
    if (state.terminal_reason !=
            FK_EXACT_IDENTITY_RX_WORKER_TERMINAL_NONE ||
        state.aborting != 0u) {
        (void)increment(state, state.counters.normal_stop_rejections);
        return FK_EXACT_IDENTITY_RX_WORKER_STOP_TERMINAL;
    }
    fk_dpdk_exact_identity_mbuf_source_stats source_stats{};
    fk_exact_identity_router_stats router_stats{};
    if (state.sequencer_complete_observed == 0u ||
        state.current_packet != 0u || state.source_claimed != 0u ||
        state.reclaim_pending != 0u ||
        !fk_exact_identity_sequencer_formal_complete(
            state.config.sequencer) ||
        !fk_dpdk_exact_identity_mbuf_source_get_stats(
            state.config.source, &source_stats) ||
        source_stats.active_claim != 0u ||
        source_stats.accounting_conserved == 0u ||
        !fk_exact_identity_router_get_stats(
            state.config.router, &router_stats) ||
        router_stats.prepared_transaction != 0u ||
        router_stats.sticky_failure != 0u ||
        router_stats.accounting_conserved == 0u) {
        (void)increment(state, state.counters.normal_stop_rejections);
        return FK_EXACT_IDENTITY_RX_WORKER_STOP_NOT_READY;
    }
    if (!stop_reservations(state)) {
        (void)increment(state, state.counters.normal_stop_rejections);
        begin_abort_prepare(
            state,
            FK_EXACT_IDENTITY_RX_WORKER_TERMINAL_RESERVATION_STOP);
        return FK_EXACT_IDENTITY_RX_WORKER_STOP_TERMINAL;
    }
    fk_owner_output_sequence_bridge_stats bridge_stats{};
    if (!fk_owner_output_sequence_bridge_get_stats(
            state.config.completion_bridge, &bridge_stats) ||
        !bridge_stats.reservations_stopped ||
        bridge_stats.completions_stopped || bridge_stats.terminal_failure) {
        (void)increment(state, state.counters.normal_stop_rejections);
        begin_abort_prepare(
            state,
            FK_EXACT_IDENTITY_RX_WORKER_TERMINAL_RESERVATION_STOP);
        return FK_EXACT_IDENTITY_RX_WORKER_STOP_TERMINAL;
    }
    state.stopped_normal = 1u;
    (void)increment(state, state.counters.normal_stop_successes);
    return FK_EXACT_IDENTITY_RX_WORKER_STOPPED_NORMAL;
}

fk_exact_identity_rx_worker_abort_prepare_result
fk_exact_identity_rx_worker_pump_abort_prepare(
        fk_exact_identity_rx_worker_pump *pump) {
    if (pump == nullptr)
        return FK_EXACT_IDENTITY_RX_WORKER_ABORT_PREPARE_INVALID;
    PumpState &state = *implementation(pump);
    if (state.magic != kMagic || state.initialized == 0u)
        return FK_EXACT_IDENTITY_RX_WORKER_ABORT_PREPARE_INVALID;
    if (!check_owner_or_reject(state))
        return FK_EXACT_IDENTITY_RX_WORKER_ABORT_PREPARE_WRONG_THREAD;
    (void)increment(state, state.counters.abort_prepare_calls);
    if (state.stopped_normal != 0u || state.stopped_abort != 0u ||
        state.abort_prepared != 0u) {
        return FK_EXACT_IDENTITY_RX_WORKER_ABORT_PREPARE_ALREADY_PREPARED;
    }
    if (state.aborting == 0u) {
        begin_abort_prepare(
            state, FK_EXACT_IDENTITY_RX_WORKER_TERMINAL_EXPLICIT_ABORT);
    }

    /* Detach any router-local publisher/terminal transaction before the mbuf
     * is reclaimed.  This leaves its exact bridge reservation active and
     * nonterminal for the global coordinator. */
    (void)attempt_router_detach(state);

    if (state.current_packet != 0u) {
        if (state.source_claimed != 0u) {
            if (state.clear_kind == ClearKind::None)
                state.clear_kind = ClearKind::Reject;
            if (state.reclaim_kind == ReclaimKind::None)
                state.reclaim_kind = ReclaimKind::Reject;
            if (!attempt_source_clear(state)) {
                (void)increment(
                    state, state.counters.abort_prepare_retries);
                return
                    FK_EXACT_IDENTITY_RX_WORKER_ABORT_PREPARE_RETRY_REQUIRED;
            }
        }
        if (state.reclaim_pending == 0u) {
            state.reclaim_pending = 1u;
            if (state.reclaim_kind == ReclaimKind::None)
                state.reclaim_kind = ReclaimKind::Reject;
        }
        if (!attempt_reclaim(state)) {
            (void)increment(state, state.counters.abort_prepare_retries);
            return FK_EXACT_IDENTITY_RX_WORKER_ABORT_PREPARE_RETRY_REQUIRED;
        }
    }

    (void)increment(state, state.counters.sequencer_drain_attempts);
    fk_exact_identity_packet drained{};
    if (fk_exact_identity_sequencer_drain_next(
            state.config.sequencer, &drained)) {
        (void)increment(state, state.counters.sequencer_drain_handoffs);
        if (!set_current(state, drained)) {
            state.abort_unrecoverable = 1u;
            (void)increment(
                state, state.counters.abort_prepare_unrecoverable);
            return FK_EXACT_IDENTITY_RX_WORKER_ABORT_PREPARE_UNRECOVERABLE;
        }
        state.reclaim_pending = 1u;
        state.reclaim_kind = ReclaimKind::AbortDrain;
        if (!attempt_reclaim(state)) {
            (void)increment(state, state.counters.abort_prepare_retries);
            return FK_EXACT_IDENTITY_RX_WORKER_ABORT_PREPARE_RETRY_REQUIRED;
        }
    } else {
        (void)increment(state, state.counters.sequencer_drain_empty);
    }

    if (!fk_exact_identity_sequencer_drain_complete(
            state.config.sequencer)) {
        (void)increment(state, state.counters.abort_prepare_retries);
        return FK_EXACT_IDENTITY_RX_WORKER_ABORT_PREPARE_RETRY_REQUIRED;
    }
    if (state.abort_unrecoverable != 0u ||
        state.ownership_indeterminate != 0u) {
        (void)increment(
            state, state.counters.abort_prepare_unrecoverable);
        return FK_EXACT_IDENTITY_RX_WORKER_ABORT_PREPARE_UNRECOVERABLE;
    }
    record_prepared_receipt_once(state);
    state.abort_prepared = 1u;
    (void)increment(state, state.counters.abort_prepare_successes);
    return FK_EXACT_IDENTITY_RX_WORKER_ABORT_PREPARED_NEEDS_GLOBAL;
}

fk_exact_identity_rx_worker_abort_finalize_result
fk_exact_identity_rx_worker_pump_abort_finalize(
        fk_exact_identity_rx_worker_pump *pump,
        fk_owner_pipeline_abort_coordinator *coordinator,
        const fk_owner_pipeline_abort_receipt_v1 *global_receipt) {
    if (pump == nullptr || coordinator == nullptr ||
        global_receipt == nullptr) {
        return FK_EXACT_IDENTITY_RX_WORKER_ABORT_FINALIZE_INVALID;
    }
    PumpState &state = *implementation(pump);
    if (state.magic != kMagic || state.initialized == 0u)
        return FK_EXACT_IDENTITY_RX_WORKER_ABORT_FINALIZE_INVALID;
    if (!check_owner_or_reject(state))
        return FK_EXACT_IDENTITY_RX_WORKER_ABORT_FINALIZE_WRONG_THREAD;
    (void)increment(state, state.counters.abort_finalize_calls);
    if (state.stopped_abort != 0u || state.stopped_normal != 0u)
        return FK_EXACT_IDENTITY_RX_WORKER_ABORT_FINALIZE_ALREADY_STOPPED;
    if (state.abort_prepared == 0u) {
        (void)increment(state, state.counters.abort_finalize_not_ready);
        return FK_EXACT_IDENTITY_RX_WORKER_ABORT_FINALIZE_NOT_READY;
    }
    if (state.abort_unrecoverable != 0u ||
        state.ownership_indeterminate != 0u) {
        (void)increment(state, state.counters.abort_finalize_unrecoverable);
        return FK_EXACT_IDENTITY_RX_WORKER_ABORT_FINALIZE_UNRECOVERABLE;
    }

    (void)increment(state, state.counters.coordinator_validate_attempts);
    if (!fk_owner_pipeline_abort_coordinator_validate_receipt(
            coordinator, global_receipt)) {
        (void)increment(
            state, state.counters.coordinator_validate_rejections);
        (void)increment(state, state.counters.abort_finalize_not_ready);
        return FK_EXACT_IDENTITY_RX_WORKER_ABORT_FINALIZE_NOT_READY;
    }
    (void)increment(
        state, state.counters.coordinator_validate_successes);
    (void)increment(state, state.counters.coordinator_authorize_attempts);
    const fk_owner_pipeline_abort_authorize_result authorized =
        fk_owner_pipeline_abort_coordinator_authorize_finalize(
            coordinator,
            global_receipt,
            FK_OWNER_PIPELINE_ABORT_PARTICIPANT_IDENTITY_RX,
            FK_OWNER_ABORT_IDENTITY_RX_PARTICIPANT_ID);
    if (authorized == FK_OWNER_PIPELINE_ABORT_ALREADY_AUTHORIZED) {
        (void)increment(
            state, state.counters.coordinator_authorize_already);
        (void)increment(state, state.counters.abort_finalize_not_ready);
        return FK_EXACT_IDENTITY_RX_WORKER_ABORT_FINALIZE_NOT_READY;
    }
    if (authorized != FK_OWNER_PIPELINE_ABORT_AUTHORIZED) {
        (void)increment(
            state, state.counters.coordinator_authorize_rejections);
        (void)increment(state, state.counters.abort_finalize_unrecoverable);
        return FK_EXACT_IDENTITY_RX_WORKER_ABORT_FINALIZE_UNRECOVERABLE;
    }
    (void)increment(
        state, state.counters.coordinator_authorize_successes);
    state.needs_global_abort = 0u;
    state.stopped_abort = 1u;
    (void)increment(state, state.counters.abort_finalize_successes);
    return FK_EXACT_IDENTITY_RX_WORKER_ABORT_FINALIZED;
}

bool fk_exact_identity_rx_worker_pump_get_abort_receipt(
        const fk_exact_identity_rx_worker_pump *pump,
        fk_exact_identity_rx_worker_abort_receipt_v1 *receipt) {
    if (receipt != nullptr)
        *receipt = {};
    if (pump == nullptr || receipt == nullptr)
        return false;
    const PumpState &state = *implementation(pump);
    if (state.magic != kMagic || state.initialized == 0u ||
        state.abort_receipt.abi_version !=
            FK_EXACT_IDENTITY_RX_WORKER_PUMP_ABI_VERSION) {
        return false;
    }
    *receipt = state.abort_receipt;
    return true;
}

bool fk_exact_identity_rx_worker_pump_get_abort_prepared_receipt(
        const fk_exact_identity_rx_worker_pump *pump,
        fk_owner_abort_identity_prepared_receipt_v1 *receipt) {
    if (receipt != nullptr)
        std::memset(receipt, 0, sizeof(*receipt));
    if (pump == nullptr || receipt == nullptr)
        return false;
    const PumpState &state = *implementation(pump);
    if (state.magic != kMagic || state.initialized == 0u ||
        state.abort_prepared == 0u ||
        state.prepared_receipt.abi_version !=
            FK_OWNER_ABORT_PROTOCOL_ABI_VERSION) {
        return false;
    }
    std::memcpy(receipt, &state.prepared_receipt, sizeof(*receipt));
    return true;
}

bool fk_exact_identity_rx_worker_pump_verify_abort_prepared_receipt(
        const fk_exact_identity_rx_worker_pump *pump,
        const fk_owner_abort_identity_prepared_receipt_v1 *receipt,
        fk_owner_abort_identity_live_summary_v1 *summary) {
    if (summary != nullptr)
        std::memset(summary, 0, sizeof(*summary));
    if (pump == nullptr || receipt == nullptr || summary == nullptr)
        return false;
    const PumpState &state = *implementation(pump);
    if (state.magic != kMagic || state.initialized == 0u ||
        state.abort_prepared == 0u || state.needs_global_abort == 0u ||
        state.stopped_normal != 0u || state.stopped_abort != 0u ||
        state.abort_unrecoverable != 0u ||
        state.ownership_indeterminate != 0u ||
        state.prepared_receipt.abi_version !=
            FK_OWNER_ABORT_PROTOCOL_ABI_VERSION ||
        std::memcmp(
            receipt,
            &state.prepared_receipt,
            sizeof(*receipt)) != 0) {
        return false;
    }

    fk_exact_identity_sequencer_stats sequencer_stats{};
    fk_dpdk_exact_identity_mbuf_source_stats source_stats{};
    fk_exact_identity_router_stats router_stats{};
    fk_owner_output_sequence_bridge_stats bridge_stats{};
    if (!fk_exact_identity_sequencer_get_stats(
            state.config.sequencer, &sequencer_stats) ||
        !fk_dpdk_exact_identity_mbuf_source_get_stats(
            state.config.source, &source_stats) ||
        !fk_exact_identity_router_get_stats(
            state.config.router, &router_stats) ||
        !fk_owner_output_sequence_bridge_get_stats(
            state.config.completion_bridge, &bridge_stats)) {
        return false;
    }

    const uint64_t exact_owned_mbufs =
        state.current_packet != 0u || source_stats.active_claim != 0u
        ? 1u : 0u;
    const bool inputs_stopped = sequencer_stats.aborted &&
        sequencer_stats.all_producers_closed &&
        sequencer_stats.drain_complete &&
        sequencer_stats.owned_packets == 0u;
    const bool admissions_stopped = state.reservations_stopped != 0u &&
        bridge_stats.reservations_stopped;
    const bool router_candidate_consistent =
        receipt->router_candidate_present == 0u
        ? (state.router_detach_receipt.abi_version == 0u)
        : (state.router_detach_receipt.abi_version ==
               FK_EXACT_IDENTITY_ROUTER_DETACH_RECEIPT_ABI_VERSION &&
           router_stats.detached_global_abort != 0u &&
           std::memcmp(
               &receipt->candidate,
               &state.router_detach_receipt.descriptor,
               sizeof(receipt->candidate)) == 0);
    const bool rx_handoffs_resolved = exact_owned_mbufs == 0u &&
        sequencer_stats.owned_packets == 0u &&
        state.router_abort_candidate == 0u &&
        router_stats.prepared_transaction == 0u &&
        router_stats.terminal_pending_global_abort == 0u &&
        router_candidate_consistent;
    const bool conserved = accounting_conserved(state) &&
        source_stats.accounting_conserved != 0u &&
        router_stats.accounting_conserved != 0u &&
        receipt->submitted_packets == state.counters.submitted_packets &&
        receipt->data_transfers == state.counters.data_transfers &&
        receipt->reclaimed_packets == state.counters.reclaimed_packets;

    summary->abi_version = FK_OWNER_ABORT_PROTOCOL_ABI_VERSION;
    summary->producer_count = state.config.producer_count;
    summary->exact_owned_mbufs = exact_owned_mbufs;
    summary->sequencer_owned_packets = sequencer_stats.owned_packets;
    summary->submitted_packets = state.counters.submitted_packets;
    summary->data_transfers = state.counters.data_transfers;
    summary->reclaimed_packets = state.counters.reclaimed_packets;
    summary->inputs_stopped = inputs_stopped ? 1u : 0u;
    summary->admissions_stopped = admissions_stopped ? 1u : 0u;
    summary->rx_handoffs_resolved = rx_handoffs_resolved ? 1u : 0u;
    summary->router_candidate_declared =
        receipt->router_candidate_present;
    summary->accounting_conserved = conserved ? 1u : 0u;
    return inputs_stopped && admissions_stopped &&
        rx_handoffs_resolved && conserved;
}

bool fk_exact_identity_rx_worker_pump_abort_prepared_verify_callback(
        const void *context,
        const fk_owner_abort_identity_prepared_receipt_v1 *receipt,
        fk_owner_abort_identity_live_summary_v1 *summary) {
    return fk_exact_identity_rx_worker_pump_verify_abort_prepared_receipt(
        static_cast<const fk_exact_identity_rx_worker_pump *>(context),
        receipt,
        summary);
}

bool fk_exact_identity_rx_worker_pump_get_stats(
        const fk_exact_identity_rx_worker_pump *pump,
        fk_exact_identity_rx_worker_pump_stats *stats) {
    if (stats != nullptr)
        *stats = {};
    if (pump == nullptr || stats == nullptr)
        return false;
    const PumpState &state = *implementation(pump);
    if (state.magic != kMagic || state.initialized == 0u ||
        ((state.stopped_normal == 0u && state.stopped_abort == 0u) &&
         !owner_thread(state))) {
        return false;
    }
    *stats = state.counters;
    stats->identity_claim_attempts =
        state.identity_claim_attempts.load(std::memory_order_acquire);
    stats->identity_claim_successes =
        state.identity_claim_successes.load(std::memory_order_acquire);
    stats->identity_claim_rejections =
        state.identity_claim_rejections.load(std::memory_order_acquire);
    stats->wrong_thread_calls =
        state.wrong_thread_calls.load(std::memory_order_acquire);
    stats->pending_owned_packets = state.current_packet != 0u ? 1u : 0u;
    stats->pending_packet_handle = state.current.packet_handle;
    stats->pending_packet_sequence = state.current.packet_sequence;
    stats->terminal_reason = state.terminal_reason;
    stats->initialized = state.initialized;
    stats->identity_thread_claimed =
        state.identity_thread_token.load(std::memory_order_acquire) != 0u
        ? 1u : 0u;
    stats->current_packet = state.current_packet;
    stats->source_claimed = state.source_claimed;
    stats->reclaim_pending = state.reclaim_pending;
    stats->sequencer_complete_observed =
        state.sequencer_complete_observed;
    stats->reservations_stopped = state.reservations_stopped;
    stats->abort_receipt_present =
        state.abort_receipt.abi_version != 0u ? 1u : 0u;
    stats->abort_prepared = state.abort_prepared;
    stats->needs_global_abort = state.needs_global_abort;
    stats->stopped_normal = state.stopped_normal;
    stats->stopped_abort = state.stopped_abort;
    stats->counter_overflow =
        state.counter_overflow != 0u ||
        state.shared_counter_overflow.load(std::memory_order_acquire) != 0u
        ? 1u : 0u;
    stats->ownership_indeterminate = state.ownership_indeterminate;
    stats->accounting_conserved = accounting_conserved(state) ? 1u : 0u;
    return true;
}

bool fk_exact_identity_rx_worker_pump_accounting_conserved(
        const fk_exact_identity_rx_worker_pump *pump) {
    return pump != nullptr &&
        implementation(pump)->magic == kMagic &&
        accounting_conserved(*implementation(pump));
}

bool fk_exact_identity_rx_worker_pump_formal_ready(
        const fk_exact_identity_rx_worker_pump *pump) {
    if (pump == nullptr)
        return false;
    const PumpState &state = *implementation(pump);
    if (state.magic != kMagic || state.initialized == 0u ||
        state.stopped_normal == 0u || state.stopped_abort != 0u ||
        state.terminal_reason !=
            FK_EXACT_IDENTITY_RX_WORKER_TERMINAL_NONE ||
        state.current_packet != 0u || state.counter_overflow != 0u ||
        state.shared_counter_overflow.load(std::memory_order_acquire) != 0u ||
        state.ownership_indeterminate != 0u ||
        !accounting_conserved(state)) {
        return false;
    }
    return fk_exact_identity_sequencer_formal_complete(
            state.config.sequencer) &&
        fk_dpdk_exact_identity_mbuf_source_accounting_conserved(
            state.config.source) &&
        fk_exact_identity_router_accounting_conserved(
            state.config.router);
}

bool fk_exact_identity_rx_worker_pump_destroy_checked(
        fk_exact_identity_rx_worker_pump *pump) {
    if (pump == nullptr)
        return false;
    PumpState &state = *implementation(pump);
    if (state.magic != kMagic || state.initialized == 0u ||
        (state.stopped_normal == 0u && state.stopped_abort == 0u) ||
        state.current_packet != 0u || state.source_claimed != 0u ||
        state.reclaim_pending != 0u ||
        state.ownership_indeterminate != 0u)
        return false;
    state.initialized = 0u;
    state.magic = 0u;
    state.~PumpState();
    return true;
}

const char *fk_exact_identity_rx_worker_step_result_name(
        fk_exact_identity_rx_worker_step_result result) {
    switch (result) {
    case FK_EXACT_IDENTITY_RX_WORKER_STEP_INVALID: return "invalid";
    case FK_EXACT_IDENTITY_RX_WORKER_STEP_IDLE: return "idle";
    case FK_EXACT_IDENTITY_RX_WORKER_STEP_DATA_TRANSFERRED:
        return "data_transferred";
    case FK_EXACT_IDENTITY_RX_WORKER_STEP_PACKET_RECLAIMED:
        return "packet_reclaimed";
    case FK_EXACT_IDENTITY_RX_WORKER_STEP_BACKPRESSURE_RETAINED:
        return "backpressure_retained";
    case FK_EXACT_IDENTITY_RX_WORKER_STEP_RECLAIM_RETRY:
        return "reclaim_retry";
    case FK_EXACT_IDENTITY_RX_WORKER_STEP_COMPLETE: return "complete";
    case FK_EXACT_IDENTITY_RX_WORKER_STEP_TERMINAL: return "terminal";
    case FK_EXACT_IDENTITY_RX_WORKER_STEP_STOPPED: return "stopped";
    case FK_EXACT_IDENTITY_RX_WORKER_STEP_WRONG_THREAD:
        return "wrong_thread";
    }
    return "unknown";
}

}  // extern "C"
