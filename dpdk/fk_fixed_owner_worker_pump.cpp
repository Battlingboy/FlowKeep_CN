#include "fk_fixed_owner_worker_pump.h"

#include "fk_owner_pipeline_abort_coordinator.h"

#include <atomic>
#include <cstddef>
#include <cstring>
#include <initializer_list>
#include <limits>
#include <new>

namespace {

constexpr uint64_t kMagic = UINT64_C(0x464b4f574e505531);  // "FKOWNPU1"

struct PumpState {
    fk_fixed_owner_worker_pump_config config{};
    std::atomic<uint64_t> owner_thread_token{0u};
    std::atomic<uint64_t> owner_claim_attempts{0u};
    std::atomic<uint64_t> owner_claim_successes{0u};
    std::atomic<uint64_t> owner_claim_rejections{0u};
    std::atomic<uint64_t> owner_thread_rejections{0u};
    std::atomic<uint64_t> foreign_step_calls{0u};
    fk_fixed_owner_worker_pump_stats counters{};
    fk_owner_envelope current{};
    fk_owner_packet_completion_v1 completion{};
    fk_fixed_owner_abort_prepared_receipt_v1 abort_prepared_receipt{};
    fk_owner_runtime_outbox_abort_receipt_v1 abort_outbox_receipt{};
    uintptr_t reclaim_handle = 0u;
    uint64_t abort_packet_sequence = 0u;
    uint64_t pump_instance_token = 0u;
    uint64_t abort_reclaim_successes_baseline = 0u;
    uint64_t abort_retire_discards_baseline = 0u;
    uint64_t abort_completion_discards_baseline = 0u;
    uint64_t magic = 0u;
    uint8_t data_pending = 0u;
    uint8_t source_claimed = 0u;
    uint8_t reclaim_pending = 0u;
    uint8_t retire_pending = 0u;
    uint8_t completion_pending = 0u;
    uint8_t completion_waits_for_output_ack = 0u;
    uint8_t completion_is_dequeued_data = 0u;
    uint8_t abort_sequence_pending = 0u;
    uint8_t aborted = 0u;
    std::atomic<uint8_t> abort_prepared{0u};
    uint8_t stopped_normal = 0u;
    uint8_t stopped_abort = 0u;
    uint8_t initialized = 0u;
    uint8_t owner_claimed = 0u;
    uint8_t sequence_initialized = 0u;
    uint8_t reserved[2]{};
};

static_assert(
    alignof(PumpState) <= alignof(std::max_align_t),
    "fixed-owner pump exceeds max_align_t placement alignment");

std::atomic<uint64_t> g_next_thread_token{1u};
std::atomic<uint64_t> g_next_pump_instance_token{1u};

PumpState *implementation(fk_fixed_owner_worker_pump *pump) {
    return reinterpret_cast<PumpState *>(pump);
}

const PumpState *implementation(const fk_fixed_owner_worker_pump *pump) {
    return reinterpret_cast<const PumpState *>(pump);
}

bool reserved_zero(const fk_fixed_owner_worker_pump_config &config) {
    for (const uint8_t value : config.reserved) {
        if (value != 0u)
            return false;
    }
    return true;
}

bool basic_config_valid(
        const fk_fixed_owner_worker_pump_config *config) {
    return config != nullptr &&
        config->abi_version == FK_FIXED_OWNER_WORKER_PUMP_ABI_VERSION &&
        config->owner_count != 0u &&
        config->fixed_owner < config->owner_count &&
        config->dispatch != nullptr && config->mbuf_source != nullptr &&
        config->adapter != nullptr && config->output_ring != nullptr &&
        config->output_bridge != nullptr && config->reclaim != nullptr &&
        reserved_zero(*config);
}

bool packet_source_equal(
        const fk_owner_packet_bytes_source &left,
        const fk_owner_packet_bytes_source &right) {
    return left.abi_version == right.abi_version &&
        left.exact_handle_binding == right.exact_handle_binding &&
        left.immutable_while_owned == right.immutable_while_owned &&
        left.contiguous_frame == right.contiguous_frame &&
        left.reserved0 == right.reserved0 &&
        left.context == right.context && left.resolve == right.resolve;
}

bool bound_components_pristine(
        const fk_fixed_owner_worker_pump_config &config) {
    fk_owner_packet_bytes_source expected_source{};
    fk_dpdk_owner_mbuf_bytes_source_stats source_stats{};
    fk_owner_output_batch_ring_stats ring_stats{};
    fk_owner_dispatch_stats dispatch_stats{};
    const fk_owner_runtime_adapter &adapter = *config.adapter;
    return fk_dpdk_owner_mbuf_bytes_source_get_adapter_source(
            config.mbuf_source, &expected_source) &&
        fk_dpdk_owner_mbuf_bytes_source_get_stats(
            config.mbuf_source, &source_stats) &&
        source_stats.initialized == 1u && source_stats.owner_claimed == 0u &&
        source_stats.active_claim == 0u &&
        source_stats.fixed_owner == config.fixed_owner &&
        source_stats.owner_count == config.owner_count &&
        source_stats.accounting_conserved == 1u &&
        fk_owner_output_batch_ring_get_stats(
            config.output_ring, &ring_stats) &&
        ring_stats.fixed_owner == config.fixed_owner &&
        ring_stats.lifecycle == FK_OWNER_OUTPUT_BATCH_RING_ACCEPTING &&
        ring_stats.accepted_batches == 0u && ring_stats.depth == 0u &&
        ring_stats.pending_commit_ordinal == 0u &&
        fk_owner_dispatch_get_stats(config.dispatch, &dispatch_stats) &&
        dispatch_stats.worker_count == config.owner_count &&
        dispatch_stats.lifecycle == FK_OWNER_DISPATCH_ACCEPTING &&
        adapter.initialized == 1u && adapter.receipt_sealed == 0u &&
        adapter.fixed_owner == config.fixed_owner &&
        adapter.owner_count == config.owner_count &&
        adapter.dispatch == config.dispatch &&
        adapter.output_ring == config.output_ring &&
        adapter.output.state == FK_OWNER_RUNTIME_OUTPUT_EMPTY &&
        packet_source_equal(adapter.packet_bytes_source, expected_source);
}

uint64_t allocate_thread_token() {
    uint64_t candidate = g_next_thread_token.load(std::memory_order_relaxed);
    while (candidate != 0u) {
        const uint64_t successor =
            candidate == std::numeric_limits<uint64_t>::max()
                ? 0u : candidate + 1u;
        if (g_next_thread_token.compare_exchange_weak(
                candidate,
                successor,
                std::memory_order_relaxed,
                std::memory_order_relaxed)) {
            return candidate;
        }
    }
    return 0u;
}

uint64_t allocate_pump_instance_token() {
    uint64_t candidate =
        g_next_pump_instance_token.load(std::memory_order_relaxed);
    while (candidate != 0u) {
        const uint64_t successor =
            candidate == std::numeric_limits<uint64_t>::max()
                ? 0u : candidate + 1u;
        if (g_next_pump_instance_token.compare_exchange_weak(
                candidate,
                successor,
                std::memory_order_relaxed,
                std::memory_order_relaxed)) {
            return candidate;
        }
    }
    return 0u;
}

uint64_t current_thread_token() {
    static thread_local const uint64_t token = allocate_thread_token();
    return token;
}

void saturating_atomic_increment(std::atomic<uint64_t> &counter) {
    uint64_t observed = counter.load(std::memory_order_relaxed);
    while (observed != std::numeric_limits<uint64_t>::max() &&
           !counter.compare_exchange_weak(
               observed,
               observed + 1u,
               std::memory_order_relaxed,
               std::memory_order_relaxed)) {
    }
}

bool owner_thread(const PumpState &state) {
    const uint64_t current = current_thread_token();
    const uint64_t claimed =
        state.owner_thread_token.load(std::memory_order_acquire);
    return current != 0u && claimed != 0u && current == claimed;
}

void mark_terminal(
        PumpState &state,
        fk_fixed_owner_worker_pump_terminal_reason reason) {
    if (state.counters.terminal_reason !=
            FK_FIXED_OWNER_WORKER_PUMP_TERMINAL_NONE)
        return;
    state.counters.terminal_reason = reason;
    if (state.counters.terminal_transitions !=
            std::numeric_limits<uint64_t>::max()) {
        ++state.counters.terminal_transitions;
    } else {
        state.counters.counter_overflow = 1u;
    }
}

void mark_counter_overflow(PumpState &state) {
    state.counters.counter_overflow = 1u;
    mark_terminal(
        state, FK_FIXED_OWNER_WORKER_PUMP_TERMINAL_COUNTER_OVERFLOW);
}

bool increment(PumpState &state, uint64_t &counter) {
    if (counter == std::numeric_limits<uint64_t>::max()) {
        mark_counter_overflow(state);
        return false;
    }
    ++counter;
    return true;
}

bool checked_add(uint64_t &value, uint64_t addend) {
    if (addend > std::numeric_limits<uint64_t>::max() - value)
        return false;
    value += addend;
    return true;
}

bool sum_equals(
        uint64_t expected,
        std::initializer_list<uint64_t> parts) {
    uint64_t sum = 0u;
    for (const uint64_t part : parts) {
        if (!checked_add(sum, part))
            return false;
    }
    return sum == expected;
}

bool no_pending(const PumpState &state) {
    return state.data_pending == 0u && state.source_claimed == 0u &&
        state.reclaim_pending == 0u && state.retire_pending == 0u &&
        state.completion_pending == 0u &&
        state.completion_waits_for_output_ack == 0u &&
        state.abort_sequence_pending == 0u &&
        state.config.adapter->output.state == FK_OWNER_RUNTIME_OUTPUT_EMPTY;
}

bool accounting_conserved(const PumpState &state) {
    const fk_fixed_owner_worker_pump_stats &s = state.counters;
    const uint64_t owned_data = state.reclaim_pending != 0u ? 1u : 0u;
    const uint64_t pending_retire = state.retire_pending != 0u ? 1u : 0u;
    const uint64_t owner_claim_attempts =
        state.owner_claim_attempts.load(std::memory_order_relaxed);
    const uint64_t owner_claim_successes =
        state.owner_claim_successes.load(std::memory_order_relaxed);
    const uint64_t owner_claim_rejections =
        state.owner_claim_rejections.load(std::memory_order_relaxed);
    return state.initialized == 1u &&
        s.service_memory_bytes == sizeof(PumpState) &&
        s.service_memory_exact == 1u &&
        state.data_pending <= 1u && state.source_claimed <= 1u &&
        state.reclaim_pending <= 1u && state.retire_pending <= 1u &&
        state.completion_pending <= 1u &&
        (!state.source_claimed || state.reclaim_pending) &&
        (!state.data_pending || state.reclaim_pending) &&
        owner_claim_successes <= 1u &&
        sum_equals(owner_claim_attempts,
            {owner_claim_successes, owner_claim_rejections}) &&
        sum_equals(s.step_calls,
            {s.step_idle, s.step_progressed, s.step_output_ring_full,
             s.step_data_retry, s.step_retire_retry, s.step_terminal,
             s.step_stopped, s.step_wrong_thread}) &&
        sum_equals(s.dequeue_attempts,
            {s.data_dequeued, s.retire_dequeued, s.dequeue_empty,
             s.invalid_envelopes}) &&
        s.packet_sequence_rejections <= s.data_dequeued &&
        sum_equals(s.packet_sequence_checks,
            {s.data_dequeued - s.packet_sequence_rejections,
             s.packet_sequence_rejections}) &&
        sum_equals(s.mbuf_claim_attempts,
            {s.mbuf_claim_successes, s.mbuf_claim_failures}) &&
        sum_equals(s.data_process_calls,
            {s.data_ordinary, s.data_quic, s.data_ignored,
             s.data_admission_rejected, s.data_output_backpressure,
             s.data_semantic_drain_required,
             s.data_terminal_results}) &&
        sum_equals(s.source_release_attempts,
            {s.source_release_successes, s.source_release_failures}) &&
        sum_equals(s.reclaim_attempts,
            {s.reclaim_successes, s.reclaim_failures}) &&
        sum_equals(s.data_dequeued, {s.reclaim_successes, owned_data}) &&
        sum_equals(s.retire_process_calls,
            {s.retire_acked, s.retire_retry_required,
             s.retire_output_backpressure,
             s.retire_semantic_drain_required,
             s.retire_terminal_results}) &&
        sum_equals(s.retire_dequeued,
            {s.retire_acked, s.retire_controls_aborted, pending_retire}) &&
        sum_equals(s.output_publish_attempts,
            {s.output_batches_published_and_acked, s.output_ring_full,
             s.output_publish_failures}) &&
        sum_equals(s.completion_publish_attempts,
            {s.completions_published, s.completion_publish_failures}) &&
        sum_equals(s.completions_published,
            {s.completions_with_batch, s.completions_without_batch}) &&
        sum_equals(s.normal_stop_attempts,
            {s.normal_stop_successes, s.normal_stop_rejections,
             s.normal_stop_already_stopped}) &&
        sum_equals(s.abort_calls,
            {s.abort_retries, s.abort_successes, s.abort_unrecoverable,
             s.abort_already_stopped, s.abort_needs_coordinator}) &&
        sum_equals(s.abort_receipt_attempts,
            {s.abort_receipts_recorded, s.abort_receipt_failures}) &&
        sum_equals(s.abort_prepare_calls,
            {s.abort_prepare_retries, s.abort_prepare_successes,
             s.abort_prepare_already_prepared,
             s.abort_prepare_unrecoverable}) &&
        sum_equals(s.abort_finalize_calls,
            {s.abort_finalize_not_ready, s.abort_finalize_successes,
             s.abort_finalize_already_stopped,
             s.abort_finalize_unrecoverable}) &&
        s.abort_committed_outboxes_discarded <=
            s.abort_prepare_successes &&
        s.abort_completion_values_discarded <= 1u &&
        s.data_packets_completed <= s.data_dequeued &&
        s.data_packets_completed <= s.completions_published;
}

void observe_foreign_thread_violation(PumpState &state) {
    if (state.owner_thread_rejections.load(std::memory_order_acquire) != 0u)
        mark_terminal(
            state, FK_FIXED_OWNER_WORKER_PUMP_TERMINAL_OWNER_THREAD);
}

bool check_owner_or_reject(PumpState &state) {
    if (state.owner_claimed != 0u && owner_thread(state))
        return true;
    saturating_atomic_increment(state.owner_thread_rejections);
    return false;
}

fk_fixed_owner_worker_pump_step_result finish_step(
        PumpState &state,
        fk_fixed_owner_worker_pump_step_result result) {
    switch (result) {
    case FK_FIXED_OWNER_WORKER_PUMP_STEP_IDLE:
        (void)increment(state, state.counters.step_idle);
        break;
    case FK_FIXED_OWNER_WORKER_PUMP_STEP_PROGRESSED:
        (void)increment(state, state.counters.step_progressed);
        break;
    case FK_FIXED_OWNER_WORKER_PUMP_STEP_OUTPUT_RING_FULL:
        (void)increment(state, state.counters.step_output_ring_full);
        break;
    case FK_FIXED_OWNER_WORKER_PUMP_STEP_DATA_RETRY:
        (void)increment(state, state.counters.step_data_retry);
        break;
    case FK_FIXED_OWNER_WORKER_PUMP_STEP_RETIRE_RETRY:
        (void)increment(state, state.counters.step_retire_retry);
        break;
    case FK_FIXED_OWNER_WORKER_PUMP_STEP_TERMINAL:
        (void)increment(state, state.counters.step_terminal);
        break;
    case FK_FIXED_OWNER_WORKER_PUMP_STEP_STOPPED:
        (void)increment(state, state.counters.step_stopped);
        break;
    case FK_FIXED_OWNER_WORKER_PUMP_STEP_WRONG_THREAD:
        (void)increment(state, state.counters.step_wrong_thread);
        break;
    case FK_FIXED_OWNER_WORKER_PUMP_STEP_INVALID:
        break;
    }
    return result;
}

bool output_batch_shape_valid(
        const PumpState &state,
        uint64_t expected_packet_sequence,
        bool exact_sequence) {
    const fk_owner_runtime_output_batch_v2 &batch =
        state.config.adapter->output;
    return batch.state == FK_OWNER_RUNTIME_OUTPUT_IDENTITY_COMMITTED &&
        batch.abi_version == FK_OWNER_RUNTIME_OUTPUT_ABI_VERSION &&
        batch.transaction_epoch != 0u &&
        batch.transaction_epoch != std::numeric_limits<uint64_t>::max() &&
        batch.packet_sequence != std::numeric_limits<uint64_t>::max() &&
        (!exact_sequence ||
         batch.packet_sequence == expected_packet_sequence) &&
        batch.has_flow_open <= 1u && batch.has_detection <= 1u &&
        batch.has_action <= 1u &&
        (batch.has_flow_open | batch.has_detection |
         batch.has_action) != 0u;
}

bool capture_output_completion(
        PumpState &state,
        uint64_t expected_packet_sequence,
        bool exact_sequence,
        bool dequeued_data) {
    if (state.completion_pending != 0u ||
        !output_batch_shape_valid(
            state, expected_packet_sequence, exact_sequence)) {
        mark_terminal(
            state, FK_FIXED_OWNER_WORKER_PUMP_TERMINAL_OUTPUT_BATCH);
        return false;
    }
    const fk_owner_runtime_output_batch_v2 &batch =
        state.config.adapter->output;
    state.completion = {};
    state.completion.packet_sequence = batch.packet_sequence;
    state.completion.fixed_owner = state.config.fixed_owner;
    state.completion.completion_kind =
        FK_OWNER_PACKET_COMPLETION_OUTPUT_COMMIT_ACKED;
    if (batch.has_flow_open != 0u)
        state.completion.expected_association_mask |=
            FK_TRACE_MESSAGE_FLOW_OPEN;
    if (batch.has_detection != 0u)
        state.completion.expected_association_mask |=
            FK_TRACE_MESSAGE_CHECKPOINT;
    state.completion_pending = 1u;
    state.completion_waits_for_output_ack = 1u;
    state.completion_is_dequeued_data = dequeued_data ? 1u : 0u;
    return true;
}

bool capture_no_output_completion(PumpState &state, uint64_t sequence) {
    if (state.completion_pending != 0u) {
        mark_terminal(
            state, FK_FIXED_OWNER_WORKER_PUMP_TERMINAL_OUTPUT_BATCH);
        return false;
    }
    state.completion = {};
    state.completion.packet_sequence = sequence;
    state.completion.fixed_owner = state.config.fixed_owner;
    state.completion.completion_kind =
        FK_OWNER_PACKET_COMPLETION_OWNER_NO_OUTPUT;
    state.completion_pending = 1u;
    state.completion_waits_for_output_ack = 0u;
    state.completion_is_dequeued_data = 1u;
    return true;
}

bool capture_orphan_outbox(PumpState &state) {
    if (state.config.adapter->output.state ==
            FK_OWNER_RUNTIME_OUTPUT_EMPTY ||
        state.completion_pending != 0u)
        return state.completion_pending != 0u;
    const uint64_t sequence = state.config.adapter->output.packet_sequence;
    bool ordered_before_current = true;
    if (state.data_pending != 0u) {
        ordered_before_current = sequence <
            state.current.payload.data.packet_sequence;
    } else {
        ordered_before_current = state.sequence_initialized != 0u &&
            sequence <= state.counters.last_packet_sequence;
    }
    if (!ordered_before_current ||
        !capture_output_completion(state, sequence, true, false))
        return false;
    (void)increment(state, state.counters.orphan_outbox_recoveries);
    return true;
}

bool release_source_claim(PumpState &state) {
    if (state.source_claimed == 0u)
        return true;
    (void)increment(state, state.counters.source_release_attempts);
    const fk_dpdk_owner_mbuf_release_result result =
        fk_dpdk_owner_mbuf_bytes_source_release_consumed(
            state.config.mbuf_source, state.reclaim_handle);
    if (result != FK_DPDK_OWNER_MBUF_RELEASED) {
        (void)increment(state, state.counters.source_release_failures);
        mark_terminal(
            state, FK_FIXED_OWNER_WORKER_PUMP_TERMINAL_SOURCE_RELEASE);
        return false;
    }
    state.source_claimed = 0u;
    (void)increment(state, state.counters.source_release_successes);
    return true;
}

bool reclaim_owned_mbuf(PumpState &state) {
    if (state.reclaim_pending == 0u)
        return true;
    if (!release_source_claim(state))
        return false;
    (void)increment(state, state.counters.reclaim_attempts);
    if (!state.config.reclaim(
            state.config.reclaim_context, state.reclaim_handle)) {
        (void)increment(state, state.counters.reclaim_failures);
        mark_terminal(state, FK_FIXED_OWNER_WORKER_PUMP_TERMINAL_RECLAIM);
        return false;
    }
    state.reclaim_pending = 0u;
    state.reclaim_handle = 0u;
    (void)increment(state, state.counters.reclaim_successes);
    return true;
}

enum class PublishProgress : uint8_t {
    Nothing,
    Completed,
    Full,
    Failed,
};

PublishProgress publish_normal_output_and_completion(PumpState &state) {
    if (state.config.adapter->output.state !=
            FK_OWNER_RUNTIME_OUTPUT_EMPTY) {
        if (state.completion_pending == 0u &&
            !capture_orphan_outbox(state))
            return PublishProgress::Failed;
        if (state.completion_waits_for_output_ack == 0u) {
            mark_terminal(
                state, FK_FIXED_OWNER_WORKER_PUMP_TERMINAL_OUTPUT_BATCH);
            return PublishProgress::Failed;
        }
        (void)increment(state, state.counters.output_publish_attempts);
        const fk_owner_runtime_output_publish_result result =
            fk_owner_runtime_adapter_publish_output_batch_v2(
                state.config.adapter);
        if (result == FK_OWNER_RUNTIME_OUTPUT_RING_FULL) {
            (void)increment(state, state.counters.output_ring_full);
            return PublishProgress::Full;
        }
        if (result != FK_OWNER_RUNTIME_OUTPUT_PUBLISHED) {
            (void)increment(state, state.counters.output_publish_failures);
            mark_terminal(
                state, FK_FIXED_OWNER_WORKER_PUMP_TERMINAL_OUTPUT_PUBLISH);
            return PublishProgress::Failed;
        }
        (void)increment(
            state, state.counters.output_batches_published_and_acked);
        state.completion_waits_for_output_ack = 0u;
    } else if (state.completion_waits_for_output_ack != 0u) {
        mark_terminal(
            state, FK_FIXED_OWNER_WORKER_PUMP_TERMINAL_OUTPUT_BATCH);
        return PublishProgress::Failed;
    }

    if (state.completion_pending == 0u)
        return PublishProgress::Nothing;
    (void)increment(state, state.counters.completion_publish_attempts);
    const fk_owner_packet_completion_publish_result result =
        fk_owner_output_sequence_bridge_publish_completion_after_commit_ack(
            state.config.output_bridge, &state.completion);
    if (result != FK_OWNER_PACKET_COMPLETION_PUBLISHED) {
        (void)increment(state, state.counters.completion_publish_failures);
        mark_terminal(state,
            FK_FIXED_OWNER_WORKER_PUMP_TERMINAL_COMPLETION_PUBLISH);
        return PublishProgress::Failed;
    }
    (void)increment(state, state.counters.completions_published);
    if (state.completion.completion_kind ==
            FK_OWNER_PACKET_COMPLETION_OUTPUT_COMMIT_ACKED) {
        (void)increment(state, state.counters.completions_with_batch);
    } else {
        (void)increment(state, state.counters.completions_without_batch);
    }
    if (state.completion_is_dequeued_data != 0u)
        (void)increment(state, state.counters.data_packets_completed);
    state.completion = {};
    state.completion_pending = 0u;
    state.completion_is_dequeued_data = 0u;
    return PublishProgress::Completed;
}

void remember_abort_sequence(PumpState &state, uint64_t sequence) {
    if (state.abort_sequence_pending == 0u) {
        state.abort_packet_sequence = sequence;
        state.abort_sequence_pending = 1u;
    }
}

bool data_result_consumes(fk_owner_runtime_adapter_result result) {
    return result != FK_OWNER_RUNTIME_ADAPTER_OUTPUT_BACKPRESSURE &&
        result != FK_OWNER_RUNTIME_ADAPTER_SEMANTIC_DRAIN_REQUIRED &&
        result != FK_OWNER_RUNTIME_ADAPTER_OWNER_THREAD_REJECTED &&
        result != FK_OWNER_RUNTIME_ADAPTER_RUNTIME_CLAIM_REJECTED &&
        result != FK_OWNER_RUNTIME_ADAPTER_SEALED;
}

bool data_result_success(fk_owner_runtime_adapter_result result) {
    return result == FK_OWNER_RUNTIME_ADAPTER_ORDINARY_OBSERVED ||
        result == FK_OWNER_RUNTIME_ADAPTER_QUIC_OBSERVED ||
        result == FK_OWNER_RUNTIME_ADAPTER_RUNTIME_IGNORED;
}

fk_fixed_owner_worker_pump_step_result process_pending_data(
        PumpState &state) {
    const uint64_t sequence = state.current.payload.data.packet_sequence;
    (void)increment(state, state.counters.data_process_calls);
    const fk_owner_runtime_adapter_result result =
        fk_owner_runtime_adapter_process_data(
            state.config.adapter, &state.current.payload.data);
    switch (result) {
    case FK_OWNER_RUNTIME_ADAPTER_ORDINARY_OBSERVED:
        (void)increment(state, state.counters.data_ordinary);
        break;
    case FK_OWNER_RUNTIME_ADAPTER_QUIC_OBSERVED:
        (void)increment(state, state.counters.data_quic);
        break;
    case FK_OWNER_RUNTIME_ADAPTER_RUNTIME_IGNORED:
        (void)increment(state, state.counters.data_ignored);
        break;
    case FK_OWNER_RUNTIME_ADAPTER_ADMISSION_REJECTED:
        (void)increment(state, state.counters.data_admission_rejected);
        break;
    case FK_OWNER_RUNTIME_ADAPTER_OUTPUT_BACKPRESSURE:
        (void)increment(state, state.counters.data_output_backpressure);
        if (state.config.adapter->output.state !=
                FK_OWNER_RUNTIME_OUTPUT_EMPTY &&
            !capture_orphan_outbox(state)) {
            return FK_FIXED_OWNER_WORKER_PUMP_STEP_TERMINAL;
        }
        return FK_FIXED_OWNER_WORKER_PUMP_STEP_DATA_RETRY;
    case FK_OWNER_RUNTIME_ADAPTER_SEMANTIC_DRAIN_REQUIRED:
        (void)increment(
            state, state.counters.data_semantic_drain_required);
        return FK_FIXED_OWNER_WORKER_PUMP_STEP_DATA_RETRY;
    default:
        (void)increment(state, state.counters.data_terminal_results);
        break;
    }

    if (!data_result_consumes(result)) {
        remember_abort_sequence(state, sequence);
        mark_terminal(
            state, FK_FIXED_OWNER_WORKER_PUMP_TERMINAL_DATA_ADAPTER);
        return FK_FIXED_OWNER_WORKER_PUMP_STEP_TERMINAL;
    }

    const bool successful = data_result_success(result);
    if (successful) {
        if (state.config.adapter->output.state !=
                FK_OWNER_RUNTIME_OUTPUT_EMPTY) {
            if (!capture_output_completion(state, sequence, true, true))
                remember_abort_sequence(state, sequence);
        } else if (!capture_no_output_completion(state, sequence)) {
            remember_abort_sequence(state, sequence);
        }
    } else {
        remember_abort_sequence(state, sequence);
        mark_terminal(
            state, FK_FIXED_OWNER_WORKER_PUMP_TERMINAL_DATA_ADAPTER);
    }

    state.data_pending = 0u;
    if (!reclaim_owned_mbuf(state))
        return FK_FIXED_OWNER_WORKER_PUMP_STEP_TERMINAL;
    if (!successful || state.counters.terminal_reason !=
            FK_FIXED_OWNER_WORKER_PUMP_TERMINAL_NONE)
        return FK_FIXED_OWNER_WORKER_PUMP_STEP_TERMINAL;

    const PublishProgress publish =
        publish_normal_output_and_completion(state);
    if (publish == PublishProgress::Full)
        return FK_FIXED_OWNER_WORKER_PUMP_STEP_OUTPUT_RING_FULL;
    if (publish == PublishProgress::Failed)
        return FK_FIXED_OWNER_WORKER_PUMP_STEP_TERMINAL;
    return FK_FIXED_OWNER_WORKER_PUMP_STEP_PROGRESSED;
}

fk_fixed_owner_worker_pump_step_result process_pending_retire(
        PumpState &state) {
    (void)increment(state, state.counters.retire_process_calls);
    const fk_owner_runtime_adapter_result result =
        fk_owner_runtime_adapter_process_retire(
            state.config.adapter, &state.current.payload.quic_retire);
    if (result == FK_OWNER_RUNTIME_ADAPTER_RETIRE_ACKED) {
        (void)increment(state, state.counters.retire_acked);
        state.retire_pending = 0u;
        state.current = {};
        return FK_FIXED_OWNER_WORKER_PUMP_STEP_PROGRESSED;
    }
    if (result == FK_OWNER_RUNTIME_ADAPTER_RETIRE_RETRY_REQUIRED) {
        (void)increment(state, state.counters.retire_retry_required);
        return FK_FIXED_OWNER_WORKER_PUMP_STEP_RETIRE_RETRY;
    }
    if (result == FK_OWNER_RUNTIME_ADAPTER_OUTPUT_BACKPRESSURE) {
        (void)increment(state, state.counters.retire_output_backpressure);
        if (state.config.adapter->output.state !=
                FK_OWNER_RUNTIME_OUTPUT_EMPTY &&
            !capture_orphan_outbox(state)) {
            return FK_FIXED_OWNER_WORKER_PUMP_STEP_TERMINAL;
        }
        return FK_FIXED_OWNER_WORKER_PUMP_STEP_RETIRE_RETRY;
    }
    if (result == FK_OWNER_RUNTIME_ADAPTER_SEMANTIC_DRAIN_REQUIRED) {
        (void)increment(
            state, state.counters.retire_semantic_drain_required);
        return FK_FIXED_OWNER_WORKER_PUMP_STEP_RETIRE_RETRY;
    }
    (void)increment(state, state.counters.retire_terminal_results);
    mark_terminal(
        state, FK_FIXED_OWNER_WORKER_PUMP_TERMINAL_RETIRE_ADAPTER);
    return FK_FIXED_OWNER_WORKER_PUMP_STEP_TERMINAL;
}

fk_fixed_owner_worker_pump_step_result dequeue_and_process(
        PumpState &state) {
    (void)increment(state, state.counters.dequeue_attempts);
    fk_owner_envelope envelope{};
    if (!fk_owner_dispatch_dequeue_envelope(
            state.config.dispatch, state.config.fixed_owner, &envelope)) {
        (void)increment(state, state.counters.dequeue_empty);
        return FK_FIXED_OWNER_WORKER_PUMP_STEP_IDLE;
    }
    state.current = envelope;
    if (envelope.kind == FK_OWNER_ENVELOPE_DATA) {
        (void)increment(state, state.counters.data_dequeued);
        state.data_pending = 1u;
        state.reclaim_pending = 1u;
        state.reclaim_handle = envelope.payload.data.packet_handle;
        (void)increment(state, state.counters.packet_sequence_checks);
        const uint64_t sequence = envelope.payload.data.packet_sequence;
        if (envelope.payload.data.packet_handle == 0u ||
            envelope.payload.data.owner_worker != state.config.fixed_owner ||
            sequence == std::numeric_limits<uint64_t>::max() ||
            (state.sequence_initialized != 0u &&
             sequence <= state.counters.last_packet_sequence)) {
            (void)increment(state, state.counters.packet_sequence_rejections);
            remember_abort_sequence(state, sequence);
            mark_terminal(
                state, FK_FIXED_OWNER_WORKER_PUMP_TERMINAL_PACKET_SEQUENCE);
            return FK_FIXED_OWNER_WORKER_PUMP_STEP_TERMINAL;
        }
        state.counters.last_packet_sequence = sequence;
        state.sequence_initialized = 1u;
        (void)increment(state, state.counters.mbuf_claim_attempts);
        const fk_dpdk_owner_mbuf_claim_result claim =
            fk_dpdk_owner_mbuf_bytes_source_claim_dequeued(
                state.config.mbuf_source, &envelope.payload.data);
        if (claim != FK_DPDK_OWNER_MBUF_CLAIMED) {
            (void)increment(state, state.counters.mbuf_claim_failures);
            remember_abort_sequence(state, sequence);
            mark_terminal(
                state, FK_FIXED_OWNER_WORKER_PUMP_TERMINAL_MBUF_CLAIM);
            return FK_FIXED_OWNER_WORKER_PUMP_STEP_TERMINAL;
        }
        state.source_claimed = 1u;
        (void)increment(state, state.counters.mbuf_claim_successes);
        return process_pending_data(state);
    }
    if (envelope.kind == FK_OWNER_ENVELOPE_QUIC_RETIRE) {
        (void)increment(state, state.counters.retire_dequeued);
        state.retire_pending = 1u;
        return process_pending_retire(state);
    }
    state.current = {};
    (void)increment(state, state.counters.invalid_envelopes);
    mark_terminal(state, FK_FIXED_OWNER_WORKER_PUMP_TERMINAL_ENVELOPE);
    return FK_FIXED_OWNER_WORKER_PUMP_STEP_TERMINAL;
}

bool formal_ready(const PumpState &state) {
    const fk_fixed_owner_worker_pump_stats &s = state.counters;
    fk_owner_runtime_adapter_stats adapter{};
    return state.stopped_normal != 0u && state.stopped_abort == 0u &&
        state.aborted == 0u && no_pending(state) &&
        s.terminal_reason == FK_FIXED_OWNER_WORKER_PUMP_TERMINAL_NONE &&
        s.counter_overflow == 0u && accounting_conserved(state) &&
        state.owner_claim_successes.load(std::memory_order_relaxed) == 1u &&
        state.owner_claim_rejections.load(std::memory_order_relaxed) == 0u &&
        state.owner_thread_rejections.load(std::memory_order_relaxed) == 0u &&
        s.packet_sequence_rejections == 0u &&
        s.mbuf_claim_failures == 0u && s.source_release_failures == 0u &&
        s.reclaim_failures == 0u &&
        s.data_output_backpressure == 0u &&
        s.data_terminal_results == 0u && s.data_ignored == 0u &&
        s.data_admission_rejected == 0u &&
        s.retire_retry_required == 0u &&
        s.retire_output_backpressure == 0u &&
        s.retire_terminal_results == 0u &&
        s.retire_controls_aborted == 0u &&
        s.orphan_outbox_recoveries == 0u &&
        s.output_publish_failures == 0u &&
        s.completion_publish_failures == 0u &&
        s.invalid_envelopes == 0u &&
        s.data_packets_completed == s.data_dequeued &&
        s.completions_published == s.data_dequeued &&
        s.reclaim_successes == s.data_dequeued &&
        s.normal_stop_attempts == 1u &&
        s.normal_stop_successes == 1u &&
        s.normal_stop_rejections == 0u &&
        s.normal_stop_already_stopped == 0u &&
        s.abort_calls == 0u &&
        fk_dpdk_owner_mbuf_bytes_source_accounting_conserved(
            state.config.mbuf_source) &&
        fk_owner_runtime_adapter_get_stats(
            state.config.adapter, &adapter) &&
        adapter.abi_version == FK_OWNER_RUNTIME_ADAPTER_ABI_VERSION &&
        adapter.data_calls == s.data_dequeued &&
        adapter.retire_calls == s.retire_dequeued &&
        adapter.semantic_data_step_calls == s.data_process_calls &&
        adapter.semantic_retire_step_calls == s.retire_process_calls &&
        adapter.semantic_data_step_completions == adapter.data_calls &&
        adapter.semantic_retire_step_completions == adapter.retire_calls &&
        adapter.semantic_data_drain_required ==
            s.data_semantic_drain_required &&
        adapter.semantic_retire_drain_required ==
            s.retire_semantic_drain_required &&
        fk_owner_runtime_adapter_formal_ready(state.config.adapter);
}

void snapshot(PumpState &state, fk_fixed_owner_worker_pump_stats &stats) {
    stats = state.counters;
    const uint64_t foreign_steps =
        state.foreign_step_calls.load(std::memory_order_relaxed);
    if (foreign_steps <=
            std::numeric_limits<uint64_t>::max() - stats.step_calls) {
        stats.step_calls += foreign_steps;
        stats.step_wrong_thread = foreign_steps;
    } else {
        stats.step_calls = std::numeric_limits<uint64_t>::max();
        stats.step_wrong_thread = foreign_steps;
        stats.counter_overflow = 1u;
    }
    stats.owner_claim_attempts =
        state.owner_claim_attempts.load(std::memory_order_relaxed);
    stats.owner_claim_successes =
        state.owner_claim_successes.load(std::memory_order_relaxed);
    stats.owner_claim_rejections =
        state.owner_claim_rejections.load(std::memory_order_relaxed);
    stats.owner_thread_rejections =
        state.owner_thread_rejections.load(std::memory_order_relaxed);
    stats.initialized = state.initialized;
    stats.owner_claimed = state.owner_claimed;
    stats.packet_sequence_initialized = state.sequence_initialized;
    stats.pending_data = state.data_pending;
    stats.active_mbuf_claim = state.source_claimed;
    stats.pending_reclaim = state.reclaim_pending;
    stats.pending_retire = state.retire_pending;
    stats.pending_outbox = state.config.adapter->output.state !=
        FK_OWNER_RUNTIME_OUTPUT_EMPTY ? 1u : 0u;
    stats.pending_completion = state.completion_pending;
    stats.stopped_normal = state.stopped_normal;
    stats.stopped_abort = state.stopped_abort;
    stats.abort_prepared =
        state.abort_prepared.load(std::memory_order_acquire);
    stats.pending_reclaim_handle = state.reclaim_handle;
    if (state.data_pending != 0u) {
        stats.pending_packet_sequence =
            state.current.payload.data.packet_sequence;
    } else if (state.completion_pending != 0u) {
        stats.pending_packet_sequence = state.completion.packet_sequence;
    } else if (state.abort_sequence_pending != 0u) {
        stats.pending_packet_sequence = state.abort_packet_sequence;
    } else {
        stats.pending_packet_sequence = 0u;
    }
    stats.accounting_conserved = accounting_conserved(state) ? 1u : 0u;
    stats.formal_ready = formal_ready(state) ? 1u : 0u;
    stats.service_memory_exact =
        stats.service_memory_bytes == sizeof(PumpState) ? 1u : 0u;
}

}  // namespace

extern "C" {

void fk_fixed_owner_worker_pump_default_config_init(
        fk_fixed_owner_worker_pump_config *config) {
    if (config == nullptr)
        return;
    *config = {};
    config->abi_version = FK_FIXED_OWNER_WORKER_PUMP_ABI_VERSION;
    config->owner_count = 1u;
}

bool fk_fixed_owner_worker_pump_config_valid(
        const fk_fixed_owner_worker_pump_config *config) {
    return basic_config_valid(config);
}

size_t fk_fixed_owner_worker_pump_storage_bytes(
        const fk_fixed_owner_worker_pump_config *config) {
    return basic_config_valid(config) ? sizeof(PumpState) : 0u;
}

fk_fixed_owner_worker_pump *fk_fixed_owner_worker_pump_initialize(
        void *storage,
        size_t storage_bytes,
        const fk_fixed_owner_worker_pump_config *config) {
    if (storage == nullptr || !basic_config_valid(config) ||
        storage_bytes < sizeof(PumpState) ||
        reinterpret_cast<uintptr_t>(storage) % alignof(std::max_align_t) !=
            0u ||
        !bound_components_pristine(*config)) {
        return nullptr;
    }
    auto *state = new (storage) PumpState{};
    state->pump_instance_token = allocate_pump_instance_token();
    if (state->pump_instance_token == 0u) {
        state->~PumpState();
        return nullptr;
    }
    state->config = *config;
    state->magic = kMagic;
    state->initialized = 1u;
    state->counters.abi_version = FK_FIXED_OWNER_WORKER_PUMP_ABI_VERSION;
    state->counters.fixed_owner = config->fixed_owner;
    state->counters.owner_count = config->owner_count;
    state->counters.initialized = 1u;
    state->counters.service_memory_bytes = sizeof(PumpState);
    state->counters.service_memory_exact = 1u;
    return reinterpret_cast<fk_fixed_owner_worker_pump *>(state);
}

bool fk_fixed_owner_worker_pump_claim_owner(
        fk_fixed_owner_worker_pump *pump) {
    if (pump == nullptr)
        return false;
    PumpState &state = *implementation(pump);
    if (state.magic != kMagic || state.initialized == 0u)
        return false;
    saturating_atomic_increment(state.owner_claim_attempts);
    fk_owner_runtime_adapter_stats adapter_stats{};
    if (!fk_owner_runtime_adapter_get_stats(
            state.config.adapter, &adapter_stats) ||
        adapter_stats.fixed_owner != state.config.fixed_owner ||
        adapter_stats.initialized != 1u) {
        saturating_atomic_increment(state.owner_claim_rejections);
        saturating_atomic_increment(state.owner_thread_rejections);
        return false;
    }
    const uint64_t token = current_thread_token();
    uint64_t expected = 0u;
    if (token == 0u ||
        !state.owner_thread_token.compare_exchange_strong(
            expected,
            token,
            std::memory_order_acq_rel,
            std::memory_order_acquire)) {
        saturating_atomic_increment(state.owner_claim_rejections);
        saturating_atomic_increment(state.owner_thread_rejections);
        return false;
    }
    if (!fk_dpdk_owner_mbuf_bytes_source_claim_owner(
            state.config.mbuf_source)) {
        saturating_atomic_increment(state.owner_claim_rejections);
        mark_terminal(
            state, FK_FIXED_OWNER_WORKER_PUMP_TERMINAL_CONFIGURATION);
        return false;
    }
    state.owner_claimed = 1u;
    state.counters.owner_claimed = 1u;
    saturating_atomic_increment(state.owner_claim_successes);
    return true;
}

fk_fixed_owner_worker_pump_step_result fk_fixed_owner_worker_pump_step(
        fk_fixed_owner_worker_pump *pump) {
    if (pump == nullptr)
        return FK_FIXED_OWNER_WORKER_PUMP_STEP_INVALID;
    PumpState &state = *implementation(pump);
    if (state.magic != kMagic || state.initialized == 0u)
        return FK_FIXED_OWNER_WORKER_PUMP_STEP_INVALID;
    if (!check_owner_or_reject(state)) {
        saturating_atomic_increment(state.foreign_step_calls);
        return FK_FIXED_OWNER_WORKER_PUMP_STEP_WRONG_THREAD;
    }
    (void)increment(state, state.counters.step_calls);
    observe_foreign_thread_violation(state);
    if (state.stopped_normal != 0u || state.stopped_abort != 0u)
        return finish_step(
            state, FK_FIXED_OWNER_WORKER_PUMP_STEP_STOPPED);
    if (state.counters.terminal_reason !=
            FK_FIXED_OWNER_WORKER_PUMP_TERMINAL_NONE ||
        state.aborted != 0u) {
        return finish_step(
            state, FK_FIXED_OWNER_WORKER_PUMP_STEP_TERMINAL);
    }
    if (state.reclaim_pending != 0u && state.data_pending == 0u) {
        /* Normal execution reaches this only if reclamation failed, which is
         * sticky terminal.  It is retried solely by the explicit abort API. */
        mark_terminal(state, FK_FIXED_OWNER_WORKER_PUMP_TERMINAL_RECLAIM);
        return finish_step(
            state, FK_FIXED_OWNER_WORKER_PUMP_STEP_TERMINAL);
    }
    if (state.config.adapter->output.state !=
            FK_OWNER_RUNTIME_OUTPUT_EMPTY ||
        state.completion_pending != 0u) {
        const PublishProgress publish =
            publish_normal_output_and_completion(state);
        if (publish == PublishProgress::Full) {
            return finish_step(state,
                FK_FIXED_OWNER_WORKER_PUMP_STEP_OUTPUT_RING_FULL);
        }
        if (publish == PublishProgress::Failed) {
            return finish_step(
                state, FK_FIXED_OWNER_WORKER_PUMP_STEP_TERMINAL);
        }
        if (publish == PublishProgress::Completed) {
            return finish_step(
                state, FK_FIXED_OWNER_WORKER_PUMP_STEP_PROGRESSED);
        }
    }
    fk_fixed_owner_worker_pump_step_result result =
        FK_FIXED_OWNER_WORKER_PUMP_STEP_INVALID;
    if (state.data_pending != 0u) {
        result = process_pending_data(state);
    } else if (state.retire_pending != 0u) {
        result = process_pending_retire(state);
    } else {
        result = dequeue_and_process(state);
    }
    return finish_step(state, result);
}

fk_fixed_owner_worker_pump_stop_result
fk_fixed_owner_worker_pump_stop_normal(
        fk_fixed_owner_worker_pump *pump) {
    if (pump == nullptr)
        return FK_FIXED_OWNER_WORKER_PUMP_STOP_INVALID;
    PumpState &state = *implementation(pump);
    if (state.magic != kMagic || state.initialized == 0u)
        return FK_FIXED_OWNER_WORKER_PUMP_STOP_INVALID;
    if (!check_owner_or_reject(state))
        return FK_FIXED_OWNER_WORKER_PUMP_STOP_WRONG_THREAD;
    (void)increment(state, state.counters.normal_stop_attempts);
    observe_foreign_thread_violation(state);
    if (state.stopped_normal != 0u || state.stopped_abort != 0u) {
        (void)increment(
            state, state.counters.normal_stop_already_stopped);
        return FK_FIXED_OWNER_WORKER_PUMP_STOP_ALREADY_STOPPED;
    }
    if (state.counters.terminal_reason !=
            FK_FIXED_OWNER_WORKER_PUMP_TERMINAL_NONE ||
        state.aborted != 0u) {
        (void)increment(state, state.counters.normal_stop_rejections);
        return FK_FIXED_OWNER_WORKER_PUMP_STOP_TERMINAL;
    }
    fk_owner_dispatch_stats dispatch_stats{};
    fk_owner_dispatch_owner_stats owner_stats{};
    fk_dpdk_owner_mbuf_bytes_source_stats source_stats{};
    if (!no_pending(state) ||
        !fk_owner_dispatch_get_stats(
            state.config.dispatch, &dispatch_stats) ||
        !fk_owner_dispatch_get_owner_stats(
            state.config.dispatch, state.config.fixed_owner, &owner_stats) ||
        dispatch_stats.lifecycle != FK_OWNER_DISPATCH_STOPPED_NORMAL ||
        owner_stats.depth != 0u || owner_stats.retire_control_depth != 0u ||
        !fk_dpdk_owner_mbuf_bytes_source_get_stats(
            state.config.mbuf_source, &source_stats) ||
        source_stats.active_claim != 0u ||
        source_stats.accounting_conserved == 0u) {
        (void)increment(state, state.counters.normal_stop_rejections);
        return FK_FIXED_OWNER_WORKER_PUMP_STOP_NOT_READY;
    }
    if (!fk_owner_runtime_adapter_seal_receipt(state.config.adapter) ||
        !fk_owner_output_batch_ring_stop(state.config.output_ring)) {
        (void)increment(state, state.counters.normal_stop_rejections);
        mark_terminal(
            state, FK_FIXED_OWNER_WORKER_PUMP_TERMINAL_CONFIGURATION);
        return FK_FIXED_OWNER_WORKER_PUMP_STOP_TERMINAL;
    }
    state.stopped_normal = 1u;
    state.counters.stopped_normal = 1u;
    (void)increment(state, state.counters.normal_stop_successes);
    return FK_FIXED_OWNER_WORKER_PUMP_STOPPED_NORMAL;
}

fk_fixed_owner_worker_pump_abort_result
fk_fixed_owner_worker_pump_abort_reclaim_and_stop(
        fk_fixed_owner_worker_pump *pump) {
    if (pump == nullptr)
        return FK_FIXED_OWNER_WORKER_PUMP_ABORT_INVALID;
    PumpState &state = *implementation(pump);
    if (state.magic != kMagic || state.initialized == 0u)
        return FK_FIXED_OWNER_WORKER_PUMP_ABORT_INVALID;
    if (!check_owner_or_reject(state))
        return FK_FIXED_OWNER_WORKER_PUMP_ABORT_WRONG_THREAD;
    (void)increment(state, state.counters.abort_calls);
    if (state.stopped_abort != 0u || state.stopped_normal != 0u) {
        (void)increment(state, state.counters.abort_already_stopped);
        return FK_FIXED_OWNER_WORKER_PUMP_ABORT_ALREADY_STOPPED;
    }
    fk_fixed_owner_abort_prepared_receipt_v1 receipt{};
    const fk_fixed_owner_worker_pump_abort_prepare_result prepared =
        fk_fixed_owner_worker_pump_abort_prepare(pump, &receipt);
    if (prepared ==
            FK_FIXED_OWNER_WORKER_PUMP_ABORT_PREPARE_RETRY_REQUIRED) {
        (void)increment(state, state.counters.abort_retries);
        return FK_FIXED_OWNER_WORKER_PUMP_ABORT_RETRY_REQUIRED;
    }
    if (prepared ==
            FK_FIXED_OWNER_WORKER_PUMP_ABORT_PREPARE_WRONG_THREAD) {
        return FK_FIXED_OWNER_WORKER_PUMP_ABORT_WRONG_THREAD;
    }
    if (prepared == FK_FIXED_OWNER_WORKER_PUMP_ABORT_PREPARE_INVALID ||
        prepared ==
            FK_FIXED_OWNER_WORKER_PUMP_ABORT_PREPARE_UNRECOVERABLE) {
        (void)increment(state, state.counters.abort_unrecoverable);
        return FK_FIXED_OWNER_WORKER_PUMP_ABORT_UNRECOVERABLE;
    }
    (void)increment(state, state.counters.abort_needs_coordinator);
    return FK_FIXED_OWNER_WORKER_PUMP_ABORT_NEEDS_COORDINATOR;
}

fk_fixed_owner_worker_pump_abort_prepare_result
fk_fixed_owner_worker_pump_abort_prepare(
        fk_fixed_owner_worker_pump *pump,
        fk_fixed_owner_abort_prepared_receipt_v1 *receipt) {
    if (receipt != nullptr)
        *receipt = {};
    if (pump == nullptr || receipt == nullptr)
        return FK_FIXED_OWNER_WORKER_PUMP_ABORT_PREPARE_INVALID;
    PumpState &state = *implementation(pump);
    if (state.magic != kMagic || state.initialized == 0u)
        return FK_FIXED_OWNER_WORKER_PUMP_ABORT_PREPARE_INVALID;
    if (!check_owner_or_reject(state))
        return FK_FIXED_OWNER_WORKER_PUMP_ABORT_PREPARE_WRONG_THREAD;
    (void)increment(state, state.counters.abort_prepare_calls);
    if (state.stopped_normal != 0u || state.stopped_abort != 0u) {
        (void)increment(
            state, state.counters.abort_prepare_already_prepared);
        return FK_FIXED_OWNER_WORKER_PUMP_ABORT_PREPARE_ALREADY_PREPARED;
    }
    if (state.abort_prepared.load(std::memory_order_acquire) != 0u) {
        *receipt = state.abort_prepared_receipt;
        (void)increment(
            state, state.counters.abort_prepare_already_prepared);
        return FK_FIXED_OWNER_WORKER_PUMP_ABORT_PREPARE_ALREADY_PREPARED;
    }
    if (state.aborted == 0u) {
        state.aborted = 1u;
        state.abort_reclaim_successes_baseline =
            state.counters.reclaim_successes;
        state.abort_retire_discards_baseline =
            state.counters.retire_controls_aborted;
        state.abort_completion_discards_baseline =
            state.counters.abort_completion_values_discarded;
    }

    if (state.data_pending != 0u) {
        remember_abort_sequence(
            state, state.current.payload.data.packet_sequence);
        state.data_pending = 0u;
    }
    if (!reclaim_owned_mbuf(state)) {
        (void)increment(state, state.counters.abort_prepare_retries);
        return FK_FIXED_OWNER_WORKER_PUMP_ABORT_PREPARE_RETRY_REQUIRED;
    }
    if (state.retire_pending != 0u) {
        state.retire_pending = 0u;
        state.current = {};
        (void)increment(state, state.counters.retire_controls_aborted);
    }

    if (state.config.adapter->output.state !=
            FK_OWNER_RUNTIME_OUTPUT_EMPTY) {
        remember_abort_sequence(
            state, state.config.adapter->output.packet_sequence);
        const fk_owner_runtime_outbox_abort_result discarded =
            fk_owner_runtime_adapter_abort_committed_outbox(
                state.config.adapter, &state.abort_outbox_receipt);
        if (discarded != FK_OWNER_RUNTIME_OUTBOX_ABORT_DISCARDED) {
            (void)increment(
                state, state.counters.abort_prepare_unrecoverable);
            return FK_FIXED_OWNER_WORKER_PUMP_ABORT_PREPARE_UNRECOVERABLE;
        }
        (void)increment(
            state, state.counters.abort_committed_outboxes_discarded);
    }
    if (state.completion_pending != 0u) {
        remember_abort_sequence(state, state.completion.packet_sequence);
        state.completion = {};
        state.completion_pending = 0u;
        state.completion_waits_for_output_ack = 0u;
        state.completion_is_dequeued_data = 0u;
        (void)increment(
            state, state.counters.abort_completion_values_discarded);
    }
    state.current = {};

    if (!fk_owner_runtime_adapter_accounting_conserved(
            state.config.adapter) ||
        !fk_owner_output_batch_ring_stop(state.config.output_ring)) {
        (void)increment(state, state.counters.abort_prepare_unrecoverable);
        return FK_FIXED_OWNER_WORKER_PUMP_ABORT_PREPARE_UNRECOVERABLE;
    }
    fk_dpdk_owner_mbuf_bytes_source_stats source_stats{};
    fk_owner_output_batch_ring_stats ring_stats{};
    if (state.data_pending != 0u || state.source_claimed != 0u ||
        state.reclaim_pending != 0u || state.retire_pending != 0u ||
        state.completion_pending != 0u ||
        state.completion_waits_for_output_ack != 0u ||
        state.config.adapter->output.state !=
            FK_OWNER_RUNTIME_OUTPUT_EMPTY ||
        !fk_dpdk_owner_mbuf_bytes_source_get_stats(
            state.config.mbuf_source, &source_stats) ||
        source_stats.active_claim != 0u ||
        source_stats.accounting_conserved == 0u ||
        !fk_owner_output_batch_ring_get_stats(
            state.config.output_ring, &ring_stats) ||
        ring_stats.lifecycle != FK_OWNER_OUTPUT_BATCH_RING_STOPPED ||
        ring_stats.pending_commit_ordinal != 0u) {
        (void)increment(state, state.counters.abort_prepare_unrecoverable);
        return FK_FIXED_OWNER_WORKER_PUMP_ABORT_PREPARE_UNRECOVERABLE;
    }

    fk_fixed_owner_abort_prepared_receipt_v1 candidate{};
    candidate.abi_version = FK_OWNER_ABORT_PROTOCOL_ABI_VERSION;
    candidate.fixed_owner = state.config.fixed_owner;
    candidate.owner_count = state.config.owner_count;
    candidate.receipt_ordinal = 1u;
    candidate.pump_instance_token = state.pump_instance_token;
    if (state.abort_sequence_pending != 0u) {
        candidate.first_sequence_candidate = state.abort_packet_sequence;
        candidate.first_sequence_candidate_present = 1u;
    }
    if (state.abort_outbox_receipt.abi_version ==
            FK_OWNER_RUNTIME_OUTBOX_ABORT_RECEIPT_ABI_VERSION) {
        candidate.committed_outbox_transaction_epoch =
            state.abort_outbox_receipt.transaction_epoch;
        candidate.committed_outbox_discarded = 1u;
    }
    candidate.exact_mbufs_reclaimed =
        state.counters.reclaim_successes -
        state.abort_reclaim_successes_baseline;
    candidate.retire_controls_discarded =
        state.counters.retire_controls_aborted -
        state.abort_retire_discards_baseline;
    candidate.completion_values_discarded =
        state.counters.abort_completion_values_discarded -
        state.abort_completion_discards_baseline;
    candidate.outbox_resolved = 1u;
    candidate.output_ring_stopped = 1u;
    candidate.no_local_ownership = 1u;

    state.abort_prepared_receipt = candidate;
    state.abort_sequence_pending = 0u;
    state.abort_packet_sequence = 0u;
    state.abort_prepared.store(1u, std::memory_order_release);
    (void)increment(state, state.counters.abort_prepare_successes);
    *receipt = candidate;
    return FK_FIXED_OWNER_WORKER_PUMP_ABORT_PREPARED_NEEDS_COORDINATOR;
}

bool fk_fixed_owner_worker_pump_get_abort_prepared_receipt(
        const fk_fixed_owner_worker_pump *pump,
        fk_fixed_owner_abort_prepared_receipt_v1 *receipt) {
    if (receipt != nullptr)
        *receipt = {};
    if (pump == nullptr || receipt == nullptr)
        return false;
    const PumpState &state = *implementation(pump);
    if (state.magic != kMagic || state.initialized == 0u ||
        state.abort_prepared.load(std::memory_order_acquire) == 0u) {
        return false;
    }
    *receipt = state.abort_prepared_receipt;
    return true;
}

bool fk_fixed_owner_worker_pump_validate_abort_prepared_receipt(
        const fk_fixed_owner_worker_pump *pump,
        const fk_fixed_owner_abort_prepared_receipt_v1 *receipt) {
    if (pump == nullptr || receipt == nullptr)
        return false;
    const PumpState &state = *implementation(pump);
    if (state.magic != kMagic || state.initialized == 0u ||
        state.abort_prepared.load(std::memory_order_acquire) == 0u ||
        std::memcmp(
            receipt,
            &state.abort_prepared_receipt,
            sizeof(*receipt)) != 0 ||
        receipt->abi_version != FK_OWNER_ABORT_PROTOCOL_ABI_VERSION ||
        receipt->fixed_owner != state.config.fixed_owner ||
        receipt->owner_count != state.config.owner_count ||
        receipt->receipt_ordinal != 1u ||
        receipt->pump_instance_token != state.pump_instance_token ||
        receipt->first_sequence_candidate_present > 1u ||
        receipt->committed_outbox_discarded > 1u ||
        receipt->outbox_resolved != 1u ||
        receipt->output_ring_stopped != 1u ||
        receipt->no_local_ownership != 1u ||
        (receipt->committed_outbox_discarded == 0u &&
         receipt->committed_outbox_transaction_epoch != 0u) ||
        state.data_pending != 0u || state.source_claimed != 0u ||
        state.reclaim_pending != 0u || state.retire_pending != 0u ||
        state.completion_pending != 0u ||
        state.completion_waits_for_output_ack != 0u ||
        state.config.adapter->output.state !=
            FK_OWNER_RUNTIME_OUTPUT_EMPTY) {
        return false;
    }
    for (const uint8_t value : receipt->reserved) {
        if (value != 0u)
            return false;
    }
    fk_dpdk_owner_mbuf_bytes_source_stats source_stats{};
    fk_owner_output_batch_ring_stats ring_stats{};
    return fk_dpdk_owner_mbuf_bytes_source_get_stats(
            state.config.mbuf_source, &source_stats) &&
        source_stats.active_claim == 0u &&
        source_stats.accounting_conserved != 0u &&
        fk_owner_output_batch_ring_get_stats(
            state.config.output_ring, &ring_stats) &&
        ring_stats.fixed_owner == state.config.fixed_owner &&
        ring_stats.lifecycle == FK_OWNER_OUTPUT_BATCH_RING_STOPPED &&
        ring_stats.pending_commit_ordinal == 0u &&
        ring_stats.ownership_conserved;
}

fk_fixed_owner_worker_pump_abort_finalize_result
fk_fixed_owner_worker_pump_abort_finalize(
        fk_fixed_owner_worker_pump *pump,
        fk_owner_pipeline_abort_coordinator *coordinator,
        const fk_owner_pipeline_abort_receipt_v1 *receipt) {
    if (pump == nullptr || coordinator == nullptr || receipt == nullptr)
        return FK_FIXED_OWNER_WORKER_PUMP_ABORT_FINALIZE_INVALID;
    PumpState &state = *implementation(pump);
    if (state.magic != kMagic || state.initialized == 0u)
        return FK_FIXED_OWNER_WORKER_PUMP_ABORT_FINALIZE_INVALID;
    if (!check_owner_or_reject(state))
        return FK_FIXED_OWNER_WORKER_PUMP_ABORT_FINALIZE_WRONG_THREAD;
    (void)increment(state, state.counters.abort_finalize_calls);
    if (state.stopped_normal != 0u || state.stopped_abort != 0u) {
        (void)increment(
            state, state.counters.abort_finalize_already_stopped);
        return FK_FIXED_OWNER_WORKER_PUMP_ABORT_FINALIZE_ALREADY_STOPPED;
    }
    if (state.abort_prepared.load(std::memory_order_acquire) == 0u ||
        !fk_owner_pipeline_abort_coordinator_validate_receipt(
            coordinator, receipt)) {
        (void)increment(state, state.counters.abort_finalize_not_ready);
        return FK_FIXED_OWNER_WORKER_PUMP_ABORT_FINALIZE_NOT_READY;
    }
    const fk_owner_pipeline_abort_authorize_result authorization =
        fk_owner_pipeline_abort_coordinator_authorize_finalize(
            coordinator,
            receipt,
            FK_OWNER_PIPELINE_ABORT_PARTICIPANT_FIXED_OWNER,
            state.config.fixed_owner);
    if (authorization == FK_OWNER_PIPELINE_ABORT_AUTHORIZE_INVALID) {
        (void)increment(state, state.counters.abort_finalize_not_ready);
        return FK_FIXED_OWNER_WORKER_PUMP_ABORT_FINALIZE_NOT_READY;
    }
    fk_owner_output_sequence_bridge_stats bridge_stats{};
    fk_owner_output_batch_ring_stats ring_stats{};
    if (!fk_owner_output_sequence_bridge_get_stats(
            state.config.output_bridge, &bridge_stats) ||
        !bridge_stats.reservations_stopped ||
        !bridge_stats.completions_stopped ||
        !bridge_stats.abort_cleanup_done ||
        (!bridge_stats.abort_receipt_present &&
         !bridge_stats.abort_no_active) ||
        bridge_stats.active_reservations != 0u ||
        bridge_stats.payloads_in_use != 0u ||
        !fk_owner_output_batch_ring_get_stats(
            state.config.output_ring, &ring_stats) ||
        ring_stats.lifecycle != FK_OWNER_OUTPUT_BATCH_RING_STOPPED ||
        ring_stats.depth != 0u || ring_stats.owned_batches != 0u ||
        ring_stats.pending_commit_ordinal != 0u ||
        !fk_fixed_owner_worker_pump_validate_abort_prepared_receipt(
            pump, &state.abort_prepared_receipt)) {
        (void)increment(
            state, state.counters.abort_finalize_unrecoverable);
        return FK_FIXED_OWNER_WORKER_PUMP_ABORT_FINALIZE_UNRECOVERABLE;
    }
    state.stopped_abort = 1u;
    state.counters.stopped_abort = 1u;
    (void)increment(state, state.counters.abort_finalize_successes);
    return FK_FIXED_OWNER_WORKER_PUMP_ABORT_FINALIZED;
}

bool fk_fixed_owner_worker_pump_get_stats(
        const fk_fixed_owner_worker_pump *pump,
        fk_fixed_owner_worker_pump_stats *stats) {
    if (stats != nullptr)
        *stats = {};
    if (pump == nullptr || stats == nullptr)
        return false;
    PumpState &state = *const_cast<PumpState *>(implementation(pump));
    if (state.magic != kMagic || state.initialized == 0u ||
        (state.stopped_normal == 0u && state.stopped_abort == 0u &&
         !owner_thread(state))) {
        return false;
    }
    snapshot(state, *stats);
    return true;
}

bool fk_fixed_owner_worker_pump_accounting_conserved(
        const fk_fixed_owner_worker_pump *pump) {
    if (pump == nullptr)
        return false;
    const PumpState &state = *implementation(pump);
    if (state.magic != kMagic || state.initialized == 0u ||
        (state.stopped_normal == 0u && state.stopped_abort == 0u &&
         !owner_thread(state))) {
        return false;
    }
    return accounting_conserved(state) &&
        fk_dpdk_owner_mbuf_bytes_source_accounting_conserved(
            state.config.mbuf_source);
}

bool fk_fixed_owner_worker_pump_formal_ready(
        const fk_fixed_owner_worker_pump *pump) {
    if (pump == nullptr)
        return false;
    const PumpState &state = *implementation(pump);
    if (state.magic != kMagic || state.initialized == 0u ||
        (state.stopped_normal == 0u && !owner_thread(state)))
        return false;
    return formal_ready(state);
}

bool fk_fixed_owner_worker_pump_destroy_checked(
        fk_fixed_owner_worker_pump *pump) {
    if (pump == nullptr)
        return false;
    PumpState &state = *implementation(pump);
    if (state.magic != kMagic || state.initialized == 0u ||
        (state.stopped_normal == 0u && state.stopped_abort == 0u) ||
        !no_pending(state)) {
        return false;
    }
    state.magic = 0u;
    state.initialized = 0u;
    state.~PumpState();
    return true;
}

const char *fk_fixed_owner_worker_pump_step_result_name(
        fk_fixed_owner_worker_pump_step_result result) {
    switch (result) {
    case FK_FIXED_OWNER_WORKER_PUMP_STEP_INVALID: return "invalid";
    case FK_FIXED_OWNER_WORKER_PUMP_STEP_IDLE: return "idle";
    case FK_FIXED_OWNER_WORKER_PUMP_STEP_PROGRESSED: return "progressed";
    case FK_FIXED_OWNER_WORKER_PUMP_STEP_OUTPUT_RING_FULL:
        return "output_ring_full";
    case FK_FIXED_OWNER_WORKER_PUMP_STEP_DATA_RETRY: return "data_retry";
    case FK_FIXED_OWNER_WORKER_PUMP_STEP_RETIRE_RETRY:
        return "retire_retry";
    case FK_FIXED_OWNER_WORKER_PUMP_STEP_TERMINAL: return "terminal";
    case FK_FIXED_OWNER_WORKER_PUMP_STEP_STOPPED: return "stopped";
    case FK_FIXED_OWNER_WORKER_PUMP_STEP_WRONG_THREAD:
        return "wrong_thread";
    }
    return "unknown";
}

const char *fk_fixed_owner_worker_pump_terminal_reason_name(
        fk_fixed_owner_worker_pump_terminal_reason reason) {
    switch (reason) {
    case FK_FIXED_OWNER_WORKER_PUMP_TERMINAL_NONE: return "none";
    case FK_FIXED_OWNER_WORKER_PUMP_TERMINAL_CONFIGURATION:
        return "configuration";
    case FK_FIXED_OWNER_WORKER_PUMP_TERMINAL_OWNER_THREAD:
        return "owner_thread";
    case FK_FIXED_OWNER_WORKER_PUMP_TERMINAL_COUNTER_OVERFLOW:
        return "counter_overflow";
    case FK_FIXED_OWNER_WORKER_PUMP_TERMINAL_ENVELOPE: return "envelope";
    case FK_FIXED_OWNER_WORKER_PUMP_TERMINAL_PACKET_SEQUENCE:
        return "packet_sequence";
    case FK_FIXED_OWNER_WORKER_PUMP_TERMINAL_MBUF_CLAIM:
        return "mbuf_claim";
    case FK_FIXED_OWNER_WORKER_PUMP_TERMINAL_SOURCE_RELEASE:
        return "source_release";
    case FK_FIXED_OWNER_WORKER_PUMP_TERMINAL_RECLAIM: return "reclaim";
    case FK_FIXED_OWNER_WORKER_PUMP_TERMINAL_DATA_ADAPTER:
        return "data_adapter";
    case FK_FIXED_OWNER_WORKER_PUMP_TERMINAL_RETIRE_ADAPTER:
        return "retire_adapter";
    case FK_FIXED_OWNER_WORKER_PUMP_TERMINAL_OUTPUT_BATCH:
        return "output_batch";
    case FK_FIXED_OWNER_WORKER_PUMP_TERMINAL_OUTPUT_PUBLISH:
        return "output_publish";
    case FK_FIXED_OWNER_WORKER_PUMP_TERMINAL_COMPLETION_PUBLISH:
        return "completion_publish";
    case FK_FIXED_OWNER_WORKER_PUMP_TERMINAL_ABORT_RECEIPT:
        return "abort_receipt";
    }
    return "unknown";
}

}  // extern "C"
