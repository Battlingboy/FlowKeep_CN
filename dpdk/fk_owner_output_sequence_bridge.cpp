#include "fk_owner_output_sequence_bridge.h"

#include <atomic>
#include <cstddef>
#include <cstdio>
#include <cstring>
#include <limits>
#include <new>

#include "fk_actor_session.h"
#include "fk_compact_exact_trace.h"

namespace {

constexpr uint64_t kMagic = UINT64_C(0x464b4f5554534231);  // "FKOUTSB1"
constexpr uint64_t kStoppedBit = UINT64_C(1) << 63u;
constexpr uint64_t kPublisherMask = kStoppedBit - UINT64_C(1);
constexpr uint32_t kCompletionPublishedBit = UINT32_C(1) << 31u;
constexpr uint32_t kCompletionBoundBit = UINT32_C(1) << 30u;
constexpr uint32_t kCompletionFree = 0u;
constexpr uint32_t kCompletionReserved = 1u;
constexpr uint32_t kNoPayload = UINT32_MAX;
constexpr uint32_t kNoFreePayload = UINT32_MAX;
constexpr uint8_t kEndpointOpen = 0u;
constexpr uint8_t kEndpointFreezing = 1u;
constexpr uint8_t kEndpointFrozen = 2u;

struct PayloadCell {
    fk_owner_checkpoint_payload_v1 payload;
    uint32_t next_free;
    uint8_t active;
    uint8_t reserved[3];
};

struct CompletionSlot {
    std::atomic<uint64_t> packet_sequence;
    std::atomic<uint32_t> state;
};

struct State {
    uint64_t magic;
    fk_owner_output_sequence_bridge_config config;
    fk_owner_output_batch_ring **owner_rings;
    CompletionSlot *completions;
    PayloadCell *payloads;
    fk_trace_message_barrier *barrier;
    fk_checkpoint_reorder *reorder;
    uint64_t reserved_bytes;
    uint64_t metadata_bytes;
    uint64_t completion_bytes;
    uint64_t payload_bytes;

    std::atomic<uint64_t> lifecycle_and_publishers;
    std::atomic<uint64_t> lifecycle_and_reservers;
    std::atomic<uint64_t> reservation_thread_token;
    std::atomic<uint64_t> consumer_thread_token;
    std::atomic<uint64_t> consumer_thread_claims;
    std::atomic<uint64_t> consumer_thread_rejections;
    std::atomic<uint64_t> next_reservation_sequence;
    std::atomic<uint64_t> consumer_prefix;
    std::atomic<uint64_t> reservation_attempts;
    std::atomic<uint64_t> reservations;
    std::atomic<uint64_t> idempotent_reservations;
    std::atomic<uint64_t> reservation_full_backpressure;
    std::atomic<uint64_t> out_of_order_reservations;
    std::atomic<uint64_t> out_of_range_reservations;
    std::atomic<uint64_t> stopped_reservations;
    std::atomic<uint64_t> terminal_reservations;
    std::atomic<uint64_t> reservation_thread_claims;
    std::atomic<uint64_t> reservation_thread_rejections;
    std::atomic<uint64_t> reservation_internal_failures;
    std::atomic<uint64_t> reservation_stop_attempts;
    std::atomic<uint64_t> reservation_stop_transitions;
    std::atomic<uint64_t> epoch_close_attempts;
    std::atomic<uint64_t> epoch_close_transitions;
    std::atomic<uint64_t> epoch_close_prefix_mismatches;
    std::atomic<uint64_t> epoch_close_unbound_routes;
    std::atomic<uint64_t> epoch_close_empty_rejections;
    std::atomic<uint64_t> formal_packet_sequence_exclusive;
    std::atomic<uint8_t> epoch_endpoint_frozen;
    std::atomic<uint64_t> peak_active_reservations;
    std::atomic<uint64_t> active_reservations;
    std::atomic<uint64_t> route_bind_attempts;
    std::atomic<uint64_t> routes_bound;
    std::atomic<uint64_t> idempotent_route_bindings;
    std::atomic<uint64_t> unreserved_route_bindings;
    std::atomic<uint64_t> mismatched_route_bindings;
    std::atomic<uint64_t> terminal_route_bindings;
    std::atomic<uint64_t> terminal_publications;
    std::atomic<uint64_t> abort_attempts;
    std::atomic<uint64_t> abort_receipts;
    std::atomic<uint8_t> abort_receipt_ready;
    std::atomic<uint64_t> publication_attempts;
    std::atomic<uint64_t> published_completions;
    std::atomic<uint64_t> published_owner_no_output;
    std::atomic<uint64_t> published_output_batches;
    std::atomic<uint64_t> published_ordered_skips;
    std::atomic<uint64_t> invalid_publications;
    std::atomic<uint64_t> duplicate_publications;
    std::atomic<uint64_t> out_of_range_publications;
    std::atomic<uint64_t> stopped_publications;
    std::atomic<uint64_t> unreserved_publications;
    std::atomic<uint64_t> completion_stop_attempts;
    std::atomic<uint64_t> completion_stop_transitions;
    std::atomic<uint64_t> expected_flow_open_messages;
    std::atomic<uint64_t> expected_checkpoint_messages;
    mutable std::atomic<uint64_t> ready_boundary_reads;
    mutable std::atomic<uint8_t> ready_boundary_counter_overflow;

    fk_owner_output_sequence_bridge_stats counters;
    fk_owner_runtime_output_batch_v2 pending_batch;
    uint64_t next_packet_sequence;
    uint64_t ready_prefix_packets;
    uint64_t reorder_batch_attempts_at_init;
    uint64_t reorder_batch_failures_at_init;
    uint32_t payload_free_head;
    uint32_t pending_payload_slot;
    uint16_t pending_owner;
    uint8_t pending_association_mask;
    uint8_t has_pending_batch;
    std::atomic<uint8_t> terminal_failure;
    uint8_t sealed;
    uint8_t abort_cleanup_done;
    uint8_t abort_no_active;
    fk_owner_reserved_abort_receipt_v1 abort_receipt;
};

static_assert(
    alignof(State) <= alignof(std::max_align_t),
    "bridge metadata exceeds placement alignment");
static_assert(
    alignof(PayloadCell) <= alignof(std::max_align_t),
    "bridge payload exceeds placement alignment");
static_assert(
    alignof(CompletionSlot) <= alignof(std::max_align_t),
    "bridge completion slot exceeds placement alignment");

State *implementation(fk_owner_output_sequence_bridge *bridge) {
    return reinterpret_cast<State *>(bridge);
}

const State *implementation(
        const fk_owner_output_sequence_bridge *bridge) {
    return reinterpret_cast<const State *>(bridge);
}

void set_error(char *error, size_t capacity, const char *message) {
    if (error != nullptr && capacity != 0u)
        std::snprintf(error, capacity, "%s", message);
}

bool checked_add(size_t &value, size_t increment) {
    if (increment > std::numeric_limits<size_t>::max() - value)
        return false;
    value += increment;
    return true;
}

bool checked_multiply(size_t left, size_t right, size_t &result) {
    if (left != 0u &&
        right > std::numeric_limits<size_t>::max() / left)
        return false;
    result = left * right;
    return true;
}

bool align_size(size_t &value, size_t alignment) {
    const size_t remainder = value % alignment;
    return remainder == 0u || checked_add(value, alignment - remainder);
}

uintptr_t align_pointer(uintptr_t value, size_t alignment) {
    const uintptr_t remainder = value % alignment;
    return remainder == 0u ? value : value + alignment - remainder;
}

template <typename T>
T *take(uintptr_t &cursor, uintptr_t end, size_t count) {
    cursor = align_pointer(cursor, alignof(T));
    size_t bytes = 0u;
    if (!checked_multiply(count, sizeof(T), bytes) ||
        cursor > end || bytes > end - cursor)
        return nullptr;
    T *result = reinterpret_cast<T *>(cursor);
    cursor += bytes;
    return result;
}

bool all_zero(const uint8_t *bytes, size_t length) {
    uint8_t combined = 0u;
    for (size_t index = 0u; index < length; ++index)
        combined = static_cast<uint8_t>(combined | bytes[index]);
    return combined == 0u;
}

bool valid_config(const fk_owner_output_sequence_bridge_config *config) {
    return config != nullptr && config->expected_packets != 0u &&
        config->sequence_base < FK_COMPACT_EXACT_TRACE_MAX_PACKETS &&
        config->expected_packets <=
            FK_COMPACT_EXACT_TRACE_MAX_PACKETS - config->sequence_base &&
        config->checkpoint_payload_capacity != 0u &&
        config->completion_window_capacity != 0u &&
        config->completion_window_capacity <= config->expected_packets &&
        config->owner_count != 0u &&
        config->owner_count <= FK_ACTOR_FLOW_IDENTITY_MAX_SHARDS &&
        config->reserved0 == 0u &&
        config->readiness_mode <=
            FK_OWNER_OUTPUT_SEQUENCE_BRIDGE_READINESS_STREAMING_STRICT_PREFIX &&
        all_zero(config->reserved1, sizeof(config->reserved1));
}

uint64_t configured_sequence_exclusive(const State &state) {
    return state.config.sequence_base + state.config.expected_packets;
}

uint64_t formal_sequence_exclusive(const State &state) {
    return state.formal_packet_sequence_exclusive.load(
        std::memory_order_acquire);
}

uint64_t formal_packet_count(const State &state) {
    const uint64_t end = formal_sequence_exclusive(state);
    return end >= state.config.sequence_base
        ? end - state.config.sequence_base : UINT64_MAX;
}

bool sequence_in_configured_epoch(const State &state, uint64_t sequence) {
    return sequence >= state.config.sequence_base &&
        sequence < configured_sequence_exclusive(state);
}

uint32_t completion_slot_index(const State &state, uint64_t sequence) {
    return static_cast<uint32_t>(
        (sequence - state.config.sequence_base) %
            state.config.completion_window_capacity);
}

bool streaming_readiness(const State &state) {
    return state.config.readiness_mode ==
        FK_OWNER_OUTPUT_SEQUENCE_BRIDGE_READINESS_STREAMING_STRICT_PREFIX;
}

size_t required_bytes(
        const fk_owner_output_sequence_bridge_config *config,
        size_t *metadata_bytes,
        size_t *completion_bytes,
        size_t *payload_bytes) {
    if (!valid_config(config))
        return 0u;
    size_t bytes = alignof(std::max_align_t) - 1u;
    size_t region = 0u;
    if (!align_size(bytes, alignof(State)) ||
        !checked_add(bytes, sizeof(State)) ||
        !align_size(bytes, alignof(fk_owner_output_batch_ring *)) ||
        !checked_multiply(
            config->owner_count,
            sizeof(fk_owner_output_batch_ring *), region) ||
        !checked_add(bytes, region) ||
        !align_size(bytes, alignof(CompletionSlot)))
        return 0u;
    const size_t metadata = bytes;
    size_t completions = 0u;
    if (!checked_multiply(
            config->completion_window_capacity,
            sizeof(CompletionSlot), completions) ||
        !checked_add(bytes, completions) ||
        !align_size(bytes, alignof(PayloadCell)))
        return 0u;
    const size_t aligned_payload_start = bytes;
    size_t payloads = 0u;
    if (!checked_multiply(
            config->checkpoint_payload_capacity,
            sizeof(PayloadCell), payloads) ||
        !checked_add(bytes, payloads))
        return 0u;
    if (metadata_bytes != nullptr) {
        *metadata_bytes = metadata +
            (aligned_payload_start - metadata - completions);
    }
    if (completion_bytes != nullptr)
        *completion_bytes = completions;
    if (payload_bytes != nullptr)
        *payload_bytes = payloads;
    return bytes;
}

bool completions_stopped(const State &state) {
    return (state.lifecycle_and_publishers.load(std::memory_order_acquire) &
        kStoppedBit) != 0u;
}

bool reservations_stopped(const State &state) {
    return (state.lifecycle_and_reservers.load(std::memory_order_acquire) &
        kStoppedBit) != 0u;
}

uint64_t allocate_thread_token() {
    static std::atomic<uint64_t> next{1u};
    uint64_t candidate = next.load(std::memory_order_relaxed);
    while (candidate != 0u && candidate != UINT64_MAX) {
        if (next.compare_exchange_weak(
                candidate, candidate + 1u,
                std::memory_order_relaxed,
                std::memory_order_relaxed))
            return candidate;
    }
    return 0u;
}

uint64_t current_thread_token() {
    static thread_local const uint64_t token = allocate_thread_token();
    return token;
}

bool claim_or_validate_reservation_thread(State &state) {
    const uint64_t token = current_thread_token();
    uint64_t observed = state.reservation_thread_token.load(
        std::memory_order_acquire);
    if (token == 0u) {
        state.reservation_thread_rejections.fetch_add(
            1u, std::memory_order_relaxed);
        return false;
    }
    if (observed == 0u &&
        state.reservation_thread_token.compare_exchange_strong(
            observed, token,
            std::memory_order_acq_rel,
            std::memory_order_acquire)) {
        state.reservation_thread_claims.fetch_add(
            1u, std::memory_order_relaxed);
        return true;
    }
    if (observed == token)
        return true;
    state.reservation_thread_rejections.fetch_add(
        1u, std::memory_order_relaxed);
    return false;
}

bool claim_or_validate_consumer_thread(State &state) {
    const uint64_t token = current_thread_token();
    uint64_t observed = state.consumer_thread_token.load(
        std::memory_order_acquire);
    if (token == 0u) {
        state.consumer_thread_rejections.fetch_add(
            1u, std::memory_order_relaxed);
        return false;
    }
    if (observed == 0u &&
        state.consumer_thread_token.compare_exchange_strong(
            observed,
            token,
            std::memory_order_acq_rel,
            std::memory_order_acquire)) {
        state.consumer_thread_claims.fetch_add(
            1u, std::memory_order_relaxed);
        return true;
    }
    if (observed == token)
        return true;
    state.consumer_thread_rejections.fetch_add(
        1u, std::memory_order_relaxed);
    return false;
}

enum class ReserveResult : uint8_t { Reserved, Stopped, Failed };

ReserveResult reserve_publisher(State &state) {
    uint64_t observed = state.lifecycle_and_publishers.load(
        std::memory_order_acquire);
    for (;;) {
        if ((observed & kStoppedBit) != 0u)
            return ReserveResult::Stopped;
        if ((observed & kPublisherMask) == kPublisherMask)
            return ReserveResult::Failed;
        if (state.lifecycle_and_publishers.compare_exchange_weak(
                observed,
                observed + 1u,
                std::memory_order_acq_rel,
                std::memory_order_acquire))
            return ReserveResult::Reserved;
    }
}

ReserveResult reserve_reserver(State &state) {
    uint64_t observed = state.lifecycle_and_reservers.load(
        std::memory_order_acquire);
    for (;;) {
        if ((observed & kStoppedBit) != 0u)
            return ReserveResult::Stopped;
        if ((observed & kPublisherMask) == kPublisherMask)
            return ReserveResult::Failed;
        if (state.lifecycle_and_reservers.compare_exchange_weak(
                observed,
                observed + 1u,
                std::memory_order_acq_rel,
                std::memory_order_acquire))
            return ReserveResult::Reserved;
    }
}

struct PublisherReservation {
    explicit PublisherReservation(State &input) : state(input) {}
    ~PublisherReservation() {
        state.lifecycle_and_publishers.fetch_sub(
            1u, std::memory_order_release);
    }
    State &state;
};

struct ReserverReservation {
    explicit ReserverReservation(State &input) : state(input) {}
    ~ReserverReservation() {
        state.lifecycle_and_reservers.fetch_sub(
            1u, std::memory_order_release);
    }
    State &state;
};

uint32_t encode_completion(const fk_owner_packet_completion_v1 &completion) {
    return kCompletionPublishedBit |
        static_cast<uint32_t>(completion.fixed_owner) |
        (static_cast<uint32_t>(completion.completion_kind) << 16u) |
        (static_cast<uint32_t>(completion.expected_association_mask) << 18u);
}

uint32_t encode_route(const fk_owner_reserved_route_v1 &route) {
    return kCompletionBoundBit |
        static_cast<uint32_t>(route.expected_owner) |
        (static_cast<uint32_t>(route.route_kind) << 16u);
}

void decode_route(uint32_t encoded, uint16_t &owner, uint8_t &kind) {
    owner = static_cast<uint16_t>(encoded & UINT32_C(0xffff));
    kind = static_cast<uint8_t>((encoded >> 16u) & UINT32_C(0x3));
}

void decode_completion(
        uint32_t encoded,
        uint16_t &owner,
        uint8_t &kind,
        uint8_t &mask) {
    owner = static_cast<uint16_t>(encoded & UINT32_C(0xffff));
    kind = static_cast<uint8_t>((encoded >> 16u) & UINT32_C(0x3));
    mask = static_cast<uint8_t>((encoded >> 18u) & UINT32_C(0x3));
}

bool completion_valid(
        const State &state,
        const fk_owner_packet_completion_v1 &completion) {
    if (!all_zero(completion.reserved, sizeof(completion.reserved)) ||
        (completion.expected_association_mask &
            ~FK_TRACE_MESSAGE_VALID_MASK) != 0u)
        return false;
    switch (completion.completion_kind) {
    case FK_OWNER_PACKET_COMPLETION_OWNER_NO_OUTPUT:
        return completion.fixed_owner < state.config.owner_count &&
            completion.expected_association_mask == 0u;
    case FK_OWNER_PACKET_COMPLETION_OUTPUT_COMMIT_ACKED:
        return completion.fixed_owner < state.config.owner_count;
    case FK_OWNER_PACKET_COMPLETION_ORDERED_SKIP:
        return completion.fixed_owner ==
                FK_OWNER_OUTPUT_SEQUENCE_BRIDGE_SKIP_OWNER &&
            completion.expected_association_mask == 0u;
    default:
        return false;
    }
}

bool batch_valid(const fk_owner_runtime_output_batch_v2 &batch) {
    if (batch.transaction_epoch == 0u ||
        batch.transaction_epoch == UINT64_MAX ||
        batch.abi_version != FK_OWNER_RUNTIME_OUTPUT_ABI_VERSION ||
        batch.packet_sequence == UINT64_MAX ||
        batch.physical_ingress_timestamp_ns == 0u ||
        batch.handle.generation == 0u ||
        batch.state != FK_OWNER_RUNTIME_OUTPUT_IDENTITY_COMMITTED ||
        batch.has_flow_open > 1u || batch.has_detection > 1u ||
        batch.has_action > 1u ||
        (batch.has_flow_open | batch.has_detection | batch.has_action) == 0u ||
        !all_zero(batch.reserved, sizeof(batch.reserved)))
        return false;
    if (batch.has_flow_open != 0u &&
        (batch.flow_open.logical_connection_id !=
             batch.logical_connection_id ||
         (batch.flow_open.presentation.control_kind !=
              FK_COMPACT_FLOW_CONTROL_OPEN &&
          batch.flow_open.presentation.control_kind !=
              FK_COMPACT_FLOW_CONTROL_CONTINUE) ||
         !all_zero(batch.flow_open.presentation.reserved,
             sizeof(batch.flow_open.presentation.reserved)) ||
         batch.flow_open.presentation.observation_timestamp_ns !=
             batch.semantic_timestamp_ns ||
         batch.flow_open.presentation.flow_index != batch.handle.index ||
         batch.flow_open.presentation.flow_generation !=
             batch.handle.generation ||
         (batch.flow_open.presentation.control_kind ==
              FK_COMPACT_FLOW_CONTROL_OPEN &&
          (batch.flow_open.presentation.predecessor_flow_index != 0u ||
           batch.flow_open.presentation.predecessor_flow_generation != 0u ||
           batch.flow_open.presentation.predecessor_checkpoint_packet != 0u)) ||
         (batch.flow_open.presentation.control_kind ==
              FK_COMPACT_FLOW_CONTROL_CONTINUE &&
          (batch.flow_open.logical_connection_id != 0u ||
           batch.flow_open.presentation.predecessor_flow_generation == 0u ||
           (batch.flow_open.presentation.predecessor_flow_index ==
                batch.handle.index &&
            batch.flow_open.presentation.predecessor_flow_generation ==
                batch.handle.generation)))))
        return false;
    if (batch.has_detection != 0u &&
        (batch.detection.logical_connection_id !=
             batch.logical_connection_id ||
         batch.detection.presentation.observation_timestamp_ns !=
             batch.semantic_timestamp_ns ||
         batch.detection.presentation.flow_index != batch.handle.index ||
         batch.detection.presentation.flow_generation !=
             batch.handle.generation))
        return false;
    return batch.has_action == 0u ||
        batch.action.observation_timestamp_ns == batch.semantic_timestamp_ns;
}

uint8_t batch_association_mask(
        const fk_owner_runtime_output_batch_v2 &batch) {
    return static_cast<uint8_t>(
        (batch.has_flow_open != 0u ? FK_TRACE_MESSAGE_FLOW_OPEN : 0u) |
        (batch.has_detection != 0u ? FK_TRACE_MESSAGE_CHECKPOINT : 0u));
}

bool terminal(State &state) {
    state.terminal_failure.store(1u, std::memory_order_release);
    return false;
}

bool terminal_failed(const State &state) {
    return state.terminal_failure.load(std::memory_order_acquire) != 0u;
}

bool counter_can_add(uint64_t value, uint64_t addend) {
    return addend <= std::numeric_limits<uint64_t>::max() - value;
}

bool abort_counter_overflow(State &state) {
    if (state.counters.abort_cleanup_counter_overflows != UINT64_MAX)
        ++state.counters.abort_cleanup_counter_overflows;
    return terminal(state);
}

bool abort_release_payload(
        State &state,
        uint32_t payload_slot,
        uint64_t &reason_counter) {
    if (payload_slot >= state.config.checkpoint_payload_capacity ||
        state.payloads[payload_slot].active == 0u ||
        state.counters.payloads_in_use == 0u ||
        !counter_can_add(state.counters.payload_releases, 1u) ||
        !counter_can_add(reason_counter, 1u)) {
        return false;
    }
    PayloadCell &cell = state.payloads[payload_slot];
    cell.payload = {};
    cell.active = 0u;
    cell.next_free = state.payload_free_head;
    state.payload_free_head = payload_slot;
    ++state.counters.payload_releases;
    --state.counters.payloads_in_use;
    ++reason_counter;
    if (state.pending_payload_slot == payload_slot)
        state.pending_payload_slot = kNoPayload;
    return true;
}

bool allocate_payload(State &state) {
    if (state.pending_payload_slot != kNoPayload)
        return true;
    if (state.payload_free_head == kNoFreePayload) {
        state.counters.payload_exhaustions++;
        return false;
    }
    const uint32_t slot = state.payload_free_head;
    if (slot >= state.config.checkpoint_payload_capacity ||
        state.payloads[slot].active != 0u)
        return terminal(state);
    PayloadCell &cell = state.payloads[slot];
    state.payload_free_head = cell.next_free;
    cell.payload = {};
    cell.payload.detection = state.pending_batch.detection;
    cell.payload.has_action = state.pending_batch.has_action;
    if (cell.payload.has_action != 0u)
        cell.payload.action = state.pending_batch.action;
    cell.active = 1u;
    cell.next_free = kNoFreePayload;
    state.pending_payload_slot = slot;
    state.counters.payload_allocations++;
    state.counters.payloads_in_use++;
    if (state.counters.payloads_in_use >
            state.counters.peak_payloads_in_use)
        state.counters.peak_payloads_in_use =
            state.counters.payloads_in_use;
    return true;
}

bool make_envelope(
        State &state,
        uint8_t message_kind,
        uint64_t physical_now_ns,
        fk_checkpoint_envelope_v3 &result) {
    result = {};
    fk_checkpoint_envelope &out = result.presentation;
    uint64_t input_sequence = 0u;
    uint8_t ignored_mask = 0u;
    if (!fk_compact_exact_trace_message_fields(
            state.next_packet_sequence,
            message_kind,
            &input_sequence,
            &ignored_mask))
        return terminal(state);
    uint32_t flow_index = 0u;
    uint32_t generation = 0u;
    uint64_t first_timestamp_ns = 0u;
    if (message_kind == FK_CHECKPOINT_MESSAGE_FLOW_OPEN) {
        const fk_compact_flow_open_observation &source =
            state.pending_batch.flow_open.presentation;
        out.key = source.key;
        flow_index = source.flow_index;
        generation = source.flow_generation;
        first_timestamp_ns = source.flow_first_timestamp_ns;
        result.control_kind = source.control_kind ==
                FK_COMPACT_FLOW_CONTROL_OPEN
            ? FK_CHECKPOINT_FLOW_CONTROL_OPEN
            : FK_CHECKPOINT_FLOW_CONTROL_CONTINUE;
        result.predecessor_flow_index = source.predecessor_flow_index;
        result.predecessor_flow_generation =
            source.predecessor_flow_generation;
        result.predecessor_last_checkpoint_packet =
            source.predecessor_checkpoint_packet;
        result.coverage_prefix_present = source.coverage_prefix_present;
        std::memcpy(result.coverage_prefix,source.coverage_prefix,sizeof(result.coverage_prefix));
        out.checkpoint_payload_slot = kNoPayload;
    } else {
        const fk_compact_detection_request &source =
            state.pending_batch.detection.presentation;
        out.key = source.key;
        flow_index = source.flow_index;
        generation = source.flow_generation;
        first_timestamp_ns = source.flow_first_timestamp_ns;
        out.checkpoint_payload_slot = state.pending_payload_slot;
    }
    fk_actor_flow_identity_v2 exact_identity{};
    if (!fk_actor_flow_identity_init(
            &out.flow_identity,
            state.pending_owner,
            flow_index,
            generation,
            first_timestamp_ns) ||
        !fk_actor_flow_identity_v2_init(
            &exact_identity,
            &out.flow_identity,
            state.pending_batch.logical_connection_id)) {
        state.counters.flow_identity_failures++;
        return terminal(state);
    }
    out.observation_timestamp_ns =
        state.pending_batch.semantic_timestamp_ns;
    out.physical_ingress_timestamp_ns =
        state.pending_batch.physical_ingress_timestamp_ns;
    out.association_enqueue_timestamp_ns = physical_now_ns;
    out.input_sequence = input_sequence;
    out.shard = state.pending_owner;
    out.message_kind = message_kind;
    result.logical_connection_id = exact_identity.logical_connection_id;
    return true;
}

bool release_completion_credit(State &state) {
    const uint64_t sequence = state.next_packet_sequence;
    CompletionSlot &slot = state.completions[
        completion_slot_index(state, sequence)];
    const uint64_t observed_sequence = slot.packet_sequence.load(
        std::memory_order_acquire);
    const uint32_t observed_state = slot.state.load(
        std::memory_order_acquire);
    if (observed_sequence != sequence ||
        (observed_state & kCompletionPublishedBit) == 0u)
        return terminal(state);
    /* Free the exact generation before publishing the returned credit. */
    slot.state.store(kCompletionFree, std::memory_order_release);
    const uint64_t active = state.active_reservations.load(
        std::memory_order_relaxed);
    if (active == 0u)
        return terminal(state);
    state.active_reservations.fetch_sub(1u, std::memory_order_relaxed);
    state.next_packet_sequence++;
    state.consumer_prefix.store(
        state.next_packet_sequence, std::memory_order_release);
    return true;
}

bool ingest_readiness_message(
        State &state, uint8_t message_mask) {
    if (streaming_readiness(state))
        return true;
    if (fk_trace_message_barrier_ingest_message(
            state.barrier,
            state.next_packet_sequence,
            message_mask))
        return true;
    state.counters.barrier_ingest_failures++;
    return terminal(state);
}

bool complete_readiness_packet(State &state, uint8_t expected_mask) {
    if (streaming_readiness(state))
        return true;
    if (!fk_trace_message_barrier_complete_packet(
            state.barrier,
            state.next_packet_sequence,
            expected_mask)) {
        state.counters.barrier_completion_failures++;
        return terminal(state);
    }
    if (!fk_trace_message_barrier_advance_ready(
            state.barrier, &state.ready_prefix_packets))
        return terminal(state);
    if (state.counters.finite_barrier_packets_completed >=
            state.config.expected_packets)
        return terminal(state);
    state.counters.finite_barrier_packets_completed++;
    return true;
}

bool release_credit_and_advance(State &state) {
    if (!release_completion_credit(state))
        return false;
    if (streaming_readiness(state)) {
        if (state.counters.streaming_prefix_packets_advanced >=
                state.config.expected_packets)
            return terminal(state);
        state.ready_prefix_packets = state.next_packet_sequence;
        state.counters.streaming_prefix_packets_advanced++;
    }
    return true;
}

bool complete_without_batch(State &state) {
    if (!complete_readiness_packet(state, 0u))
        return false;
    state.counters.completions_consumed++;
    state.counters.completions_without_batch++;
    return release_credit_and_advance(state);
}

bool process_pending_batch(State &state, uint64_t physical_now_ns,
        bool &backpressured) {
    backpressured = false;
    const uint8_t association_count = static_cast<uint8_t>(
        (state.pending_association_mask & FK_TRACE_MESSAGE_FLOW_OPEN ? 1u : 0u) +
        (state.pending_association_mask & FK_TRACE_MESSAGE_CHECKPOINT ? 1u : 0u));
    const uint32_t depth = fk_checkpoint_reorder_count(state.reorder);
    fk_checkpoint_reorder_stats reorder_stats{};
    if (!fk_checkpoint_reorder_get_stats(state.reorder, &reorder_stats) ||
        depth > reorder_stats.capacity)
        return terminal(state);
    if (association_count > reorder_stats.capacity - depth) {
        state.counters.reorder_capacity_backpressure++;
        backpressured = true;
        return false;
    }
    if (state.pending_batch.has_detection != 0u &&
        !allocate_payload(state)) {
        if (terminal_failed(state))
            return false;
        backpressured = true;
        return false;
    }

    fk_checkpoint_envelope_v3 messages[2]{};
    uint8_t message_masks[2]{};
    uint8_t count = 0u;
    if (state.pending_batch.has_flow_open != 0u) {
        if (!make_envelope(
                state, FK_CHECKPOINT_MESSAGE_FLOW_OPEN,
                physical_now_ns, messages[count]))
            return false;
        message_masks[count++] = FK_TRACE_MESSAGE_FLOW_OPEN;
    }
    if (state.pending_batch.has_detection != 0u) {
        if (!make_envelope(
                state, FK_CHECKPOINT_MESSAGE_DETECTION_CHECKPOINT,
                physical_now_ns, messages[count]))
            return false;
        message_masks[count++] = FK_TRACE_MESSAGE_CHECKPOINT;
    }
    if (count != 0u) {
        state.counters.atomic_reorder_push_attempts++;
        if (!fk_checkpoint_reorder_push_batch_v3(
                state.reorder, messages, count)) {
            state.counters.atomic_reorder_push_failures++;
            return terminal(state);
        }
        state.counters.atomic_reorder_pushes++;
        for (uint8_t index = 0u; index < count; ++index) {
            if (!ingest_readiness_message(state, message_masks[index]))
                return false;
            if (message_masks[index] == FK_TRACE_MESSAGE_FLOW_OPEN)
                state.counters.flow_open_messages_pushed++;
            else
                state.counters.checkpoint_messages_pushed++;
        }
    }
    if (state.pending_batch.has_action != 0u)
        state.counters.action_records_consumed++;
    if (!complete_readiness_packet(
            state, state.pending_association_mask))
        return false;
    state.counters.batches_completed++;
    state.counters.completions_consumed++;
    state.has_pending_batch = 0u;
    state.pending_batch = {};
    state.pending_owner = UINT16_MAX;
    state.pending_association_mask = 0u;
    state.pending_payload_slot = kNoPayload;
    return release_credit_and_advance(state);
}

bool snapshot_accounting(
        fk_owner_output_sequence_bridge_stats &stats) {
    const uint64_t publication_rejections =
        stats.invalid_publications + stats.duplicate_publications +
        stats.out_of_range_publications + stats.stopped_publications +
        stats.unreserved_publications + stats.terminal_publications;
    stats.publication_accounting_conserved =
        stats.publication_attempts ==
            stats.published_completions + publication_rejections &&
        stats.published_completions ==
            stats.published_owner_no_output +
            stats.published_output_batches +
            stats.published_ordered_skips;
    const uint64_t reservation_rejections =
        stats.idempotent_reservations +
        stats.reservation_full_backpressure +
        stats.out_of_order_reservations +
        stats.out_of_range_reservations +
        stats.stopped_reservations +
        stats.terminal_reservations +
        stats.reservation_thread_rejections +
        stats.reservation_internal_failures;
    stats.reservation_accounting_conserved =
        stats.reservation_attempts ==
            stats.reservations + reservation_rejections &&
        stats.next_reservation_sequence >= stats.sequence_base &&
        stats.reservations ==
            stats.next_reservation_sequence - stats.sequence_base;
    stats.completion_accounting_conserved =
        stats.completions_consumed ==
            stats.completions_without_batch + stats.batches_completed &&
        stats.batches_dequeued == stats.batches_completed +
            (stats.pending_batch ? 1u : 0u) +
            stats.aborted_pending_batches_cleaned;
    stats.payload_accounting_conserved =
        stats.payload_allocations ==
            stats.payload_releases + stats.payloads_in_use;
    stats.readiness_accounting_conserved =
        (stats.readiness_mode ==
             FK_OWNER_OUTPUT_SEQUENCE_BRIDGE_READINESS_FINITE_BARRIER &&
         stats.finite_barrier_packets_completed ==
             stats.completions_consumed &&
         stats.streaming_prefix_packets_advanced == 0u) ||
        (stats.readiness_mode ==
             FK_OWNER_OUTPUT_SEQUENCE_BRIDGE_READINESS_STREAMING_STRICT_PREFIX &&
         stats.streaming_prefix_packets_advanced ==
             stats.completions_consumed &&
         stats.finite_barrier_packets_completed == 0u &&
         stats.ready_prefix_packets == stats.next_packet_sequence);
    return stats.publication_accounting_conserved &&
        stats.reservation_accounting_conserved &&
        stats.completion_accounting_conserved &&
        stats.payload_accounting_conserved &&
        stats.readiness_accounting_conserved;
}

bool stop_reservation_admission(State &state) {
    uint64_t observed = state.lifecycle_and_reservers.load(
        std::memory_order_acquire);
    for (;;) {
        if ((observed & kStoppedBit) != 0u)
            break;
        if (state.lifecycle_and_reservers.compare_exchange_weak(
                observed,
                observed | kStoppedBit,
                std::memory_order_acq_rel,
                std::memory_order_acquire)) {
            state.reservation_stop_transitions.fetch_add(
                1u, std::memory_order_relaxed);
            break;
        }
    }
    while ((state.lifecycle_and_reservers.load(std::memory_order_acquire) &
            kPublisherMask) != 0u)
        std::atomic_signal_fence(std::memory_order_seq_cst);
    return true;
}

bool freeze_endpoint(State &state, uint64_t endpoint) {
    uint8_t expected = kEndpointOpen;
    if (state.epoch_endpoint_frozen.compare_exchange_strong(
            expected,
            kEndpointFreezing,
            std::memory_order_acq_rel,
            std::memory_order_acquire)) {
        state.formal_packet_sequence_exclusive.store(
            endpoint, std::memory_order_release);
        state.epoch_endpoint_frozen.store(
            kEndpointFrozen, std::memory_order_release);
        return true;
    }
    while (expected == kEndpointFreezing) {
        expected = state.epoch_endpoint_frozen.load(
            std::memory_order_acquire);
        std::atomic_signal_fence(std::memory_order_seq_cst);
    }
    return expected == kEndpointFrozen &&
        formal_sequence_exclusive(state) == endpoint;
}

}  // namespace

extern "C" {

size_t fk_owner_output_sequence_bridge_storage_bytes(
        const fk_owner_output_sequence_bridge_config *config) {
    return required_bytes(config, nullptr, nullptr, nullptr);
}

fk_owner_output_sequence_bridge *fk_owner_output_sequence_bridge_init(
        void *storage,
        size_t storage_bytes,
        const fk_owner_output_sequence_bridge_config *config,
        fk_owner_output_batch_ring *const *owner_rings,
        fk_trace_message_barrier *barrier,
        fk_checkpoint_reorder *reorder,
        char *error,
        size_t error_capacity) {
    set_error(error, error_capacity, "");
    size_t metadata_bytes = 0u;
    size_t completion_bytes = 0u;
    size_t payload_bytes = 0u;
    const size_t required = required_bytes(
        config, &metadata_bytes, &completion_bytes, &payload_bytes);
    if (storage == nullptr || storage_bytes < required || required == 0u ||
        owner_rings == nullptr || reorder == nullptr) {
        set_error(error, error_capacity, "invalid output sequence bridge input");
        return nullptr;
    }
    fk_checkpoint_reorder_stats reorder_stats{};
    if (!fk_checkpoint_reorder_get_stats(reorder, &reorder_stats) ||
        reorder_stats.capacity < 2u || reorder_stats.inserted != 0u ||
        reorder_stats.released != 0u ||
        reorder_stats.sequence_index_active != 0u ||
        reorder_stats.batch_accounting_conserved == 0u) {
        set_error(error, error_capacity,
            "reorder is not a pristine exact-trace dependency");
        return nullptr;
    }
    if (config->readiness_mode ==
            FK_OWNER_OUTPUT_SEQUENCE_BRIDGE_READINESS_FINITE_BARRIER) {
        fk_trace_message_barrier_stats barrier_stats{};
        if (config->sequence_base != 0u || barrier == nullptr ||
            !fk_trace_message_barrier_get_stats(barrier, &barrier_stats) ||
            barrier_stats.expected_packets != config->expected_packets ||
            barrier_stats.completed_packets != 0u ||
            barrier_stats.ingested_unique_messages != 0u ||
            reorder_stats.sequence_index_enabled != 1u ||
            reorder_stats.maximum_input_sequence_exclusive <
                config->expected_packets * UINT64_C(2) ||
            reorder_stats.admission_mode ==
                FK_CHECKPOINT_REORDER_ADMISSION_STREAMING_MONOTONIC_V2) {
            set_error(error, error_capacity,
                "finite readiness dependencies are not exact and pristine");
            return nullptr;
        }
    } else if (barrier != nullptr ||
        reorder_stats.admission_mode !=
            FK_CHECKPOINT_REORDER_ADMISSION_STREAMING_MONOTONIC_V2 ||
        reorder_stats.sequence_index_enabled != 0u ||
        reorder_stats.maximum_input_sequence_exclusive != 0u ||
        reorder_stats.streaming_accounting_conserved == 0u) {
        set_error(error, error_capacity,
            "streaming readiness requires null barrier and monotonic reorder");
        return nullptr;
    }
    for (uint16_t owner = 0u; owner < config->owner_count; ++owner) {
        fk_owner_output_batch_ring_stats ring_stats{};
        if (owner_rings[owner] == nullptr ||
            !fk_owner_output_batch_ring_get_stats(
                owner_rings[owner], &ring_stats) ||
            ring_stats.fixed_owner != owner ||
            ring_stats.lifecycle != FK_OWNER_OUTPUT_BATCH_RING_ACCEPTING ||
            ring_stats.accepted_batches != 0u || ring_stats.depth != 0u ||
            ring_stats.pending_commit_ordinal != 0u) {
            set_error(error, error_capacity,
                "owner ring topology is not pristine or exact");
            return nullptr;
        }
    }
    const uintptr_t start = reinterpret_cast<uintptr_t>(storage);
    if (storage_bytes > std::numeric_limits<uintptr_t>::max() - start) {
        set_error(error, error_capacity, "bridge storage overflows");
        return nullptr;
    }
    uintptr_t cursor = start;
    const uintptr_t end = start + storage_bytes;
    State *state = take<State>(cursor, end, 1u);
    fk_owner_output_batch_ring **rings =
        take<fk_owner_output_batch_ring *>(
            cursor, end, config->owner_count);
    CompletionSlot *completions = take<CompletionSlot>(
        cursor, end, config->completion_window_capacity);
    PayloadCell *payloads = take<PayloadCell>(
        cursor, end, config->checkpoint_payload_capacity);
    if (state == nullptr || rings == nullptr || completions == nullptr ||
        payloads == nullptr) {
        set_error(error, error_capacity, "bridge placement layout failed");
        return nullptr;
    }
    state = new (state) State{};
    for (uint32_t slot = 0u;
         slot < config->completion_window_capacity; ++slot) {
        new (&completions[slot]) CompletionSlot{};
        completions[slot].packet_sequence.store(
            UINT64_MAX, std::memory_order_relaxed);
        completions[slot].state.store(
            kCompletionFree, std::memory_order_relaxed);
    }
    if (!completions[0].packet_sequence.is_lock_free() ||
        !completions[0].state.is_lock_free()) {
        set_error(error, error_capacity,
            "bridge requires lock-free completion atomics");
        return nullptr;
    }
    for (uint32_t slot = 0u; slot < config->checkpoint_payload_capacity;
         ++slot) {
        new (&payloads[slot]) PayloadCell{};
        payloads[slot].next_free =
            slot + 1u < config->checkpoint_payload_capacity
                ? slot + 1u : kNoFreePayload;
    }
    for (uint16_t owner = 0u; owner < config->owner_count; ++owner)
        rings[owner] = owner_rings[owner];
    state->config = *config;
    state->owner_rings = rings;
    state->completions = completions;
    state->payloads = payloads;
    state->barrier = barrier;
    state->reorder = reorder;
    state->reserved_bytes = required;
    state->metadata_bytes = metadata_bytes;
    state->completion_bytes = completion_bytes;
    state->payload_bytes = payload_bytes;
    state->payload_free_head = 0u;
    state->pending_payload_slot = kNoPayload;
    state->pending_owner = UINT16_MAX;
    state->next_reservation_sequence.store(
        config->sequence_base, std::memory_order_relaxed);
    state->consumer_prefix.store(
        config->sequence_base, std::memory_order_relaxed);
    state->formal_packet_sequence_exclusive.store(
        config->sequence_base + config->expected_packets,
        std::memory_order_relaxed);
    state->next_packet_sequence = config->sequence_base;
    state->ready_prefix_packets = config->sequence_base;
    state->reorder_batch_attempts_at_init =
        reorder_stats.batch_push_attempts;
    state->reorder_batch_failures_at_init =
        reorder_stats.batch_push_attempts - reorder_stats.batch_pushes;
    state->magic = kMagic;
    return reinterpret_cast<fk_owner_output_sequence_bridge *>(state);
}

enum fk_owner_packet_reservation_result
fk_owner_output_sequence_bridge_reserve_next(
        fk_owner_output_sequence_bridge *bridge,
        uint64_t packet_sequence) {
    if (bridge == nullptr)
        return FK_OWNER_PACKET_RESERVATION_INVALID;
    State &state = *implementation(bridge);
    if (state.magic != kMagic)
        return FK_OWNER_PACKET_RESERVATION_INVALID;
    state.reservation_attempts.fetch_add(1u, std::memory_order_relaxed);
    if (terminal_failed(state)) {
        state.terminal_reservations.fetch_add(1u, std::memory_order_relaxed);
        return FK_OWNER_PACKET_RESERVATION_TERMINAL;
    }
    if (!sequence_in_configured_epoch(state, packet_sequence)) {
        state.out_of_range_reservations.fetch_add(
            1u, std::memory_order_relaxed);
        return FK_OWNER_PACKET_RESERVATION_OUT_OF_RANGE;
    }
    if (!claim_or_validate_reservation_thread(state))
        return FK_OWNER_PACKET_RESERVATION_INVALID;
    const ReserveResult reserved = reserve_reserver(state);
    if (reserved == ReserveResult::Stopped) {
        state.stopped_reservations.fetch_add(1u, std::memory_order_relaxed);
        return FK_OWNER_PACKET_RESERVATION_STOPPED;
    }
    if (reserved == ReserveResult::Failed) {
        state.reservation_internal_failures.fetch_add(
            1u, std::memory_order_relaxed);
        return FK_OWNER_PACKET_RESERVATION_INTERNAL_FAILURE;
    }
    ReserverReservation reservation(state);
    const uint64_t next = state.next_reservation_sequence.load(
        std::memory_order_acquire);
    CompletionSlot &slot = state.completions[
        completion_slot_index(state, packet_sequence)];
    const uint64_t slot_sequence = slot.packet_sequence.load(
        std::memory_order_acquire);
    const uint32_t slot_state = slot.state.load(std::memory_order_acquire);
    if (packet_sequence < next) {
        if ((slot_sequence == packet_sequence &&
             slot_state != kCompletionFree) ||
            packet_sequence < state.consumer_prefix.load(
                std::memory_order_acquire)) {
            state.idempotent_reservations.fetch_add(
                1u, std::memory_order_relaxed);
            return FK_OWNER_PACKET_ALREADY_RESERVED;
        }
        state.out_of_order_reservations.fetch_add(
            1u, std::memory_order_relaxed);
        return FK_OWNER_PACKET_RESERVATION_OUT_OF_ORDER;
    }
    if (packet_sequence != next) {
        state.out_of_order_reservations.fetch_add(
            1u, std::memory_order_relaxed);
        return FK_OWNER_PACKET_RESERVATION_OUT_OF_ORDER;
    }
    const uint64_t consumed = state.consumer_prefix.load(
        std::memory_order_acquire);
    if (packet_sequence < consumed ||
        packet_sequence - consumed >=
            state.config.completion_window_capacity) {
        state.reservation_full_backpressure.fetch_add(
            1u, std::memory_order_relaxed);
        return FK_OWNER_PACKET_RESERVATION_FULL;
    }
    if (slot_state != kCompletionFree) {
        state.reservation_internal_failures.fetch_add(
            1u, std::memory_order_relaxed);
        return FK_OWNER_PACKET_RESERVATION_INTERNAL_FAILURE;
    }
    slot.packet_sequence.store(packet_sequence, std::memory_order_relaxed);
    slot.state.store(kCompletionReserved, std::memory_order_release);
    state.next_reservation_sequence.store(
        packet_sequence + 1u, std::memory_order_release);
    state.reservations.fetch_add(1u, std::memory_order_relaxed);
    const uint64_t active = state.active_reservations.fetch_add(
        1u, std::memory_order_relaxed) + 1u;
    uint64_t peak = state.peak_active_reservations.load(
        std::memory_order_relaxed);
    while (active > peak &&
        !state.peak_active_reservations.compare_exchange_weak(
            peak, active,
            std::memory_order_relaxed,
            std::memory_order_relaxed)) {
    }
    return FK_OWNER_PACKET_RESERVED;
}

enum fk_owner_reserved_route_bind_result
fk_owner_output_sequence_bridge_bind_reserved_route(
        fk_owner_output_sequence_bridge *bridge,
        const fk_owner_reserved_route_v1 *route) {
    if (bridge == nullptr || route == nullptr)
        return FK_OWNER_RESERVED_ROUTE_BIND_INVALID;
    State &state = *implementation(bridge);
    if (state.magic != kMagic)
        return FK_OWNER_RESERVED_ROUTE_BIND_INVALID;
    state.route_bind_attempts.fetch_add(1u, std::memory_order_relaxed);
    if (terminal_failed(state)) {
        state.terminal_route_bindings.fetch_add(1u, std::memory_order_relaxed);
        return FK_OWNER_RESERVED_ROUTE_TERMINAL;
    }
    const bool route_valid =
        all_zero(route->reserved, sizeof(route->reserved)) &&
        sequence_in_configured_epoch(state, route->packet_sequence) &&
        ((route->route_kind == FK_OWNER_RESERVED_ROUTE_DATA &&
          route->expected_owner < state.config.owner_count) ||
         (route->route_kind == FK_OWNER_RESERVED_ROUTE_SKIP &&
          route->expected_owner ==
              FK_OWNER_OUTPUT_SEQUENCE_BRIDGE_SKIP_OWNER));
    if (!route_valid || current_thread_token() == 0u ||
        state.reservation_thread_token.load(std::memory_order_acquire) !=
            current_thread_token()) {
        state.terminal_route_bindings.fetch_add(1u, std::memory_order_relaxed);
        terminal(state);
        return FK_OWNER_RESERVED_ROUTE_BIND_INVALID;
    }
    const ReserveResult lifecycle = reserve_reserver(state);
    if (lifecycle == ReserveResult::Stopped) {
        state.terminal_route_bindings.fetch_add(1u, std::memory_order_relaxed);
        terminal(state);
        return FK_OWNER_RESERVED_ROUTE_STOPPED;
    }
    if (lifecycle == ReserveResult::Failed) {
        state.terminal_route_bindings.fetch_add(1u, std::memory_order_relaxed);
        terminal(state);
        return FK_OWNER_RESERVED_ROUTE_TERMINAL;
    }
    ReserverReservation reservation(state);
    CompletionSlot &slot = state.completions[
        completion_slot_index(state, route->packet_sequence)];
    if (slot.packet_sequence.load(std::memory_order_acquire) !=
            route->packet_sequence) {
        state.unreserved_route_bindings.fetch_add(
            1u, std::memory_order_relaxed);
        return FK_OWNER_RESERVED_ROUTE_UNRESERVED;
    }
    uint32_t observed = slot.state.load(std::memory_order_acquire);
    const uint32_t desired = encode_route(*route);
    if (observed == desired) {
        state.idempotent_route_bindings.fetch_add(
            1u, std::memory_order_relaxed);
        return FK_OWNER_RESERVED_ROUTE_ALREADY_BOUND;
    }
    if (observed != kCompletionReserved) {
        state.mismatched_route_bindings.fetch_add(
            1u, std::memory_order_relaxed);
        terminal(state);
        return FK_OWNER_RESERVED_ROUTE_MISMATCH_TERMINAL;
    }
    if (!slot.state.compare_exchange_strong(
            observed,
            desired,
            std::memory_order_release,
            std::memory_order_acquire)) {
        if (observed == desired) {
            state.idempotent_route_bindings.fetch_add(
                1u, std::memory_order_relaxed);
            return FK_OWNER_RESERVED_ROUTE_ALREADY_BOUND;
        }
        state.mismatched_route_bindings.fetch_add(
            1u, std::memory_order_relaxed);
        terminal(state);
        return FK_OWNER_RESERVED_ROUTE_MISMATCH_TERMINAL;
    }
    state.routes_bound.fetch_add(1u, std::memory_order_relaxed);
    return FK_OWNER_RESERVED_ROUTE_BOUND;
}

enum fk_owner_reserved_abort_result
fk_owner_output_sequence_bridge_abort_reserved(
        fk_owner_output_sequence_bridge *bridge,
        uint64_t packet_sequence,
        uint8_t abort_reason) {
    if (bridge == nullptr)
        return FK_OWNER_RESERVED_ABORT_INVALID;
    State &state = *implementation(bridge);
    if (state.magic != kMagic)
        return FK_OWNER_RESERVED_ABORT_INVALID;
    state.abort_attempts.fetch_add(1u, std::memory_order_relaxed);
    if (abort_reason < FK_OWNER_RESERVED_ABORT_ROUTER_TERMINAL ||
        abort_reason > FK_OWNER_RESERVED_ABORT_SHUTDOWN_TERMINAL ||
        !sequence_in_configured_epoch(state, packet_sequence))
        return FK_OWNER_RESERVED_ABORT_INVALID;
    if (state.abort_receipt_ready.load(std::memory_order_acquire) != 0u) {
        return state.abort_receipt.packet_sequence == packet_sequence &&
                state.abort_receipt.abort_reason == abort_reason
            ? FK_OWNER_RESERVED_ABORT_ALREADY_RECORDED
            : FK_OWNER_RESERVED_ABORT_INVALID;
    }
    CompletionSlot &slot = state.completions[
        completion_slot_index(state, packet_sequence)];
    const uint64_t observed_sequence = slot.packet_sequence.load(
        std::memory_order_acquire);
    const uint32_t observed_state = slot.state.load(std::memory_order_acquire);
    if (observed_sequence != packet_sequence ||
        observed_state == kCompletionFree)
        return FK_OWNER_RESERVED_ABORT_UNRESERVED;

    fk_owner_reserved_abort_receipt_v1 receipt{};
    receipt.packet_sequence = packet_sequence;
    receipt.receipt_ordinal = 1u;
    receipt.expected_owner =
        FK_OWNER_OUTPUT_SEQUENCE_BRIDGE_SKIP_OWNER;
    receipt.abort_reason = abort_reason;
    if ((observed_state & kCompletionBoundBit) != 0u) {
        decode_route(
            observed_state, receipt.expected_owner, receipt.route_kind);
        receipt.slot_was_bound = 1u;
    } else if ((observed_state & kCompletionPublishedBit) != 0u) {
        uint8_t completion_kind = 0u;
        uint8_t ignored_mask = 0u;
        decode_completion(
            observed_state,
            receipt.expected_owner,
            completion_kind,
            ignored_mask);
        receipt.route_kind = completion_kind ==
                FK_OWNER_PACKET_COMPLETION_ORDERED_SKIP
            ? FK_OWNER_RESERVED_ROUTE_SKIP
            : FK_OWNER_RESERVED_ROUTE_DATA;
        receipt.slot_was_bound = 1u;
    }
    state.abort_receipt = receipt;
    terminal(state);
    state.abort_receipts.fetch_add(1u, std::memory_order_relaxed);
    state.abort_receipt_ready.store(1u, std::memory_order_release);
    return FK_OWNER_RESERVED_ABORT_RECORDED;
}

bool fk_owner_output_sequence_bridge_claim_abort_consumer_thread(
        fk_owner_output_sequence_bridge *bridge) {
    if (bridge == nullptr)
        return false;
    State &state = *implementation(bridge);
    return state.magic == kMagic &&
        claim_or_validate_consumer_thread(state);
}

fk_owner_active_reservation_state
fk_owner_output_sequence_bridge_query_active_reservation(
        const fk_owner_output_sequence_bridge *bridge,
        uint64_t packet_sequence,
        fk_owner_active_reservation_v1 *reservation) {
    if (reservation != nullptr)
        *reservation = {};
    if (bridge == nullptr || reservation == nullptr)
        return FK_OWNER_ACTIVE_RESERVATION_INVALID;
    const State &state = *implementation(bridge);
    if (state.magic != kMagic || !reservations_stopped(state) ||
        !sequence_in_configured_epoch(state, packet_sequence)) {
        return FK_OWNER_ACTIVE_RESERVATION_INVALID;
    }
    reservation->packet_sequence = packet_sequence;
    reservation->expected_owner =
        FK_OWNER_OUTPUT_SEQUENCE_BRIDGE_SKIP_OWNER;
    const CompletionSlot &slot = state.completions[
        completion_slot_index(state, packet_sequence)];
    const uint64_t observed_sequence_before = slot.packet_sequence.load(
        std::memory_order_acquire);
    const uint32_t observed_state = slot.state.load(
        std::memory_order_acquire);
    const uint64_t observed_sequence_after = slot.packet_sequence.load(
        std::memory_order_acquire);
    if (observed_sequence_before != observed_sequence_after)
        return FK_OWNER_ACTIVE_RESERVATION_INTEGRITY_FAILURE;
    if (observed_state == kCompletionFree ||
        observed_sequence_before != packet_sequence) {
        reservation->state = FK_OWNER_ACTIVE_RESERVATION_INACTIVE;
        return FK_OWNER_ACTIVE_RESERVATION_INACTIVE;
    }
    if (observed_state == kCompletionReserved) {
        reservation->state = FK_OWNER_ACTIVE_RESERVATION_UNBOUND;
        return FK_OWNER_ACTIVE_RESERVATION_UNBOUND;
    }
    if ((observed_state & kCompletionBoundBit) != 0u &&
        (observed_state & kCompletionPublishedBit) == 0u) {
        decode_route(
            observed_state,
            reservation->expected_owner,
            reservation->route_kind);
        reservation->state = FK_OWNER_ACTIVE_RESERVATION_BOUND;
        return FK_OWNER_ACTIVE_RESERVATION_BOUND;
    }
    if ((observed_state & kCompletionPublishedBit) != 0u &&
        (observed_state & kCompletionBoundBit) == 0u) {
        uint8_t completion_kind = 0u;
        uint8_t ignored_mask = 0u;
        decode_completion(
            observed_state,
            reservation->expected_owner,
            completion_kind,
            ignored_mask);
        reservation->route_kind = completion_kind ==
                FK_OWNER_PACKET_COMPLETION_ORDERED_SKIP
            ? FK_OWNER_RESERVED_ROUTE_SKIP
            : FK_OWNER_RESERVED_ROUTE_DATA;
        reservation->state =
            FK_OWNER_ACTIVE_RESERVATION_COMPLETION_PUBLISHED;
        return FK_OWNER_ACTIVE_RESERVATION_COMPLETION_PUBLISHED;
    }
    reservation->state = FK_OWNER_ACTIVE_RESERVATION_INTEGRITY_FAILURE;
    return FK_OWNER_ACTIVE_RESERVATION_INTEGRITY_FAILURE;
}

fk_owner_abort_first_active_result
fk_owner_output_sequence_bridge_abort_first_active(
        fk_owner_output_sequence_bridge *bridge,
        uint8_t abort_reason) {
    if (bridge == nullptr)
        return FK_OWNER_ABORT_FIRST_ACTIVE_INVALID;
    State &state = *implementation(bridge);
    if (state.magic != kMagic ||
        abort_reason < FK_OWNER_RESERVED_ABORT_ROUTER_TERMINAL ||
        abort_reason > FK_OWNER_RESERVED_ABORT_SHUTDOWN_TERMINAL) {
        return FK_OWNER_ABORT_FIRST_ACTIVE_INVALID;
    }
    if (!counter_can_add(state.counters.abort_first_active_attempts, 1u)) {
        terminal(state);
        return FK_OWNER_ABORT_FIRST_ACTIVE_INTEGRITY_FAILURE;
    }
    ++state.counters.abort_first_active_attempts;
    if (!claim_or_validate_consumer_thread(state))
        return FK_OWNER_ABORT_FIRST_ACTIVE_WRONG_CONSUMER;
    if (!reservations_stopped(state) || !completions_stopped(state))
        return FK_OWNER_ABORT_FIRST_ACTIVE_NOT_STOPPED;
    if (state.abort_receipt_ready.load(std::memory_order_acquire) != 0u)
        return FK_OWNER_ABORT_FIRST_ACTIVE_ALREADY_RECORDED;
    if (state.abort_no_active != 0u)
        return FK_OWNER_ABORT_FIRST_ACTIVE_NO_ACTIVE;
    if (!counter_can_add(
            state.counters.abort_first_active_scanned_slots,
            state.config.completion_window_capacity)) {
        terminal(state);
        return FK_OWNER_ABORT_FIRST_ACTIVE_INTEGRITY_FAILURE;
    }
    state.counters.abort_first_active_scanned_slots +=
        state.config.completion_window_capacity;

    uint64_t minimum = UINT64_MAX;
    uint64_t observed_active = 0u;
    for (uint32_t index = 0u;
         index < state.config.completion_window_capacity; ++index) {
        const uint32_t slot_state = state.completions[index].state.load(
            std::memory_order_acquire);
        if (slot_state == kCompletionFree)
            continue;
        const uint64_t sequence =
            state.completions[index].packet_sequence.load(
                std::memory_order_acquire);
        if (!sequence_in_configured_epoch(state, sequence) ||
            completion_slot_index(state, sequence) != index ||
            observed_active == UINT64_MAX) {
            if (state.counters.abort_first_active_integrity_failures !=
                    UINT64_MAX) {
                ++state.counters.abort_first_active_integrity_failures;
            }
            terminal(state);
            return FK_OWNER_ABORT_FIRST_ACTIVE_INTEGRITY_FAILURE;
        }
        ++observed_active;
        if (sequence < minimum)
            minimum = sequence;
    }
    if (observed_active != state.active_reservations.load(
            std::memory_order_acquire)) {
        if (state.counters.abort_first_active_integrity_failures !=
                UINT64_MAX) {
            ++state.counters.abort_first_active_integrity_failures;
        }
        terminal(state);
        return FK_OWNER_ABORT_FIRST_ACTIVE_INTEGRITY_FAILURE;
    }
    if (observed_active == 0u) {
        if (!counter_can_add(
                state.counters.abort_first_active_no_active, 1u)) {
            terminal(state);
            return FK_OWNER_ABORT_FIRST_ACTIVE_INTEGRITY_FAILURE;
        }
        ++state.counters.abort_first_active_no_active;
        state.abort_no_active = 1u;
        return FK_OWNER_ABORT_FIRST_ACTIVE_NO_ACTIVE;
    }
    const fk_owner_reserved_abort_result result =
        fk_owner_output_sequence_bridge_abort_reserved(
            bridge, minimum, abort_reason);
    if (result == FK_OWNER_RESERVED_ABORT_RECORDED)
        return FK_OWNER_ABORT_FIRST_ACTIVE_RECORDED;
    if (result == FK_OWNER_RESERVED_ABORT_ALREADY_RECORDED)
        return FK_OWNER_ABORT_FIRST_ACTIVE_ALREADY_RECORDED;
    if (state.counters.abort_first_active_integrity_failures != UINT64_MAX)
        ++state.counters.abort_first_active_integrity_failures;
    terminal(state);
    return FK_OWNER_ABORT_FIRST_ACTIVE_INTEGRITY_FAILURE;
}

bool fk_owner_output_sequence_bridge_get_abort_receipt(
        const fk_owner_output_sequence_bridge *bridge,
        fk_owner_reserved_abort_receipt_v1 *receipt) {
    if (bridge == nullptr || receipt == nullptr)
        return false;
    const State &state = *implementation(bridge);
    if (state.magic != kMagic ||
        state.abort_receipt_ready.load(std::memory_order_acquire) == 0u)
        return false;
    *receipt = state.abort_receipt;
    return true;
}

bool fk_owner_output_sequence_bridge_cleanup_aborted(
        fk_owner_output_sequence_bridge *bridge) {
    if (bridge == nullptr)
        return false;
    State &state = *implementation(bridge);
    if (state.magic != kMagic)
        return false;
    if (!claim_or_validate_consumer_thread(state))
        return false;
    if (!counter_can_add(state.counters.abort_cleanup_attempts, 1u))
        return abort_counter_overflow(state);
    ++state.counters.abort_cleanup_attempts;
    if (state.abort_cleanup_done != 0u)
        return true;
    if ((!terminal_failed(state) && state.abort_no_active == 0u) ||
        (state.abort_receipt_ready.load(std::memory_order_acquire) == 0u &&
         state.abort_no_active == 0u) ||
        !reservations_stopped(state) || !completions_stopped(state)) {
        return false;
    }

    uint64_t ring_batches = 0u;
    for (uint16_t owner = 0u; owner < state.config.owner_count; ++owner) {
        fk_owner_output_batch_ring_stats ring_stats{};
        if (!fk_owner_output_batch_ring_get_stats(
                state.owner_rings[owner], &ring_stats) ||
            ring_stats.lifecycle != FK_OWNER_OUTPUT_BATCH_RING_STOPPED ||
            ring_stats.pending_commit_ordinal != 0u ||
            ring_stats.depth != ring_stats.owned_batches ||
            !ring_stats.ownership_conserved ||
            !counter_can_add(ring_batches, ring_stats.depth)) {
            return false;
        }
        ring_batches += ring_stats.depth;
    }

    const uint64_t reorder_envelopes =
        fk_checkpoint_reorder_count(state.reorder);
    uint64_t payload_cells = 0u;
    uint64_t completion_slots = 0u;
    for (uint32_t index = 0u;
         index < state.config.checkpoint_payload_capacity; ++index) {
        if (state.payloads[index].active != 0u) {
            if (payload_cells == UINT64_MAX)
                return abort_counter_overflow(state);
            ++payload_cells;
        }
    }
    for (uint32_t index = 0u;
         index < state.config.completion_window_capacity; ++index) {
        if (state.completions[index].state.load(
                std::memory_order_acquire) != kCompletionFree) {
            if (completion_slots == UINT64_MAX)
                return abort_counter_overflow(state);
            ++completion_slots;
        }
    }
    if (payload_cells != state.counters.payloads_in_use ||
        completion_slots != state.active_reservations.load(
            std::memory_order_acquire)) {
        return false;
    }

    const uint64_t pending_batch = state.has_pending_batch != 0u ? 1u : 0u;
    if (!counter_can_add(
            state.counters.aborted_ring_batches_drained, ring_batches) ||
        !counter_can_add(
            state.counters.aborted_reorder_envelopes_drained,
            reorder_envelopes) ||
        !counter_can_add(
            state.counters.aborted_reorder_checkpoint_payloads_released,
            reorder_envelopes) ||
        !counter_can_add(
            state.counters.aborted_pending_payloads_released,
            payload_cells) ||
        !counter_can_add(
            state.counters.aborted_orphan_payloads_released,
            payload_cells) ||
        !counter_can_add(state.counters.payload_releases, payload_cells) ||
        !counter_can_add(
            state.counters.aborted_pending_batches_cleaned,
            pending_batch) ||
        !counter_can_add(
            state.counters.aborted_reservations_cleaned,
            completion_slots) ||
        !counter_can_add(state.counters.abort_cleanup_successes, 1u)) {
        return abort_counter_overflow(state);
    }

    while (fk_checkpoint_reorder_count(state.reorder) != 0u) {
        fk_checkpoint_envelope_v3 envelope{};
        fk_checkpoint_release_reason reason = FK_CHECKPOINT_RELEASE_NONE;
        if (!fk_checkpoint_reorder_force_pop_v3(
                state.reorder, &envelope, &reason) ||
            reason != FK_CHECKPOINT_RELEASE_CAPACITY) {
            return false;
        }
        ++state.counters.aborted_reorder_envelopes_drained;
        const fk_checkpoint_envelope &value = envelope.presentation;
        if (value.message_kind ==
                FK_CHECKPOINT_MESSAGE_DETECTION_CHECKPOINT) {
            if (value.checkpoint_payload_slot == kNoPayload ||
                !abort_release_payload(
                    state,
                    value.checkpoint_payload_slot,
                    state.counters
                        .aborted_reorder_checkpoint_payloads_released)) {
                return false;
            }
        } else if (value.message_kind != FK_CHECKPOINT_MESSAGE_FLOW_OPEN ||
                   value.checkpoint_payload_slot != kNoPayload) {
            return false;
        }
    }

    if (state.pending_payload_slot != kNoPayload &&
        !abort_release_payload(
            state,
            state.pending_payload_slot,
            state.counters.aborted_pending_payloads_released)) {
        return false;
    }
    for (uint32_t slot = 0u;
         slot < state.config.checkpoint_payload_capacity; ++slot) {
        if (state.payloads[slot].active != 0u &&
            !abort_release_payload(
                state, slot,
                state.counters.aborted_orphan_payloads_released)) {
            return false;
        }
    }
    if (state.counters.payloads_in_use != 0u)
        return false;

    if (state.has_pending_batch != 0u) {
        state.has_pending_batch = 0u;
        state.pending_batch = {};
        state.pending_owner = UINT16_MAX;
        state.pending_association_mask = 0u;
        ++state.counters.aborted_pending_batches_cleaned;
    }
    for (uint16_t owner = 0u; owner < state.config.owner_count; ++owner) {
        for (;;) {
            fk_owner_runtime_output_batch_v2 discarded{};
            const fk_owner_output_batch_take_result result =
                fk_owner_output_batch_ring_drain(
                    state.owner_rings[owner], &discarded);
            if (result == FK_OWNER_OUTPUT_BATCH_DRAINED) {
                ++state.counters.aborted_ring_batches_drained;
                continue;
            }
            if (result != FK_OWNER_OUTPUT_BATCH_STOPPED_EMPTY)
                return false;
            break;
        }
    }
    for (uint32_t index = 0u;
         index < state.config.completion_window_capacity; ++index) {
        state.completions[index].state.store(
            kCompletionFree, std::memory_order_release);
        state.completions[index].packet_sequence.store(
            UINT64_MAX, std::memory_order_relaxed);
    }
    state.active_reservations.store(0u, std::memory_order_release);
    state.counters.aborted_reservations_cleaned += completion_slots;
    state.abort_cleanup_done = 1u;
    ++state.counters.abort_cleanup_successes;
    return true;
}

bool fk_owner_output_sequence_bridge_stop_reservations(
        fk_owner_output_sequence_bridge *bridge) {
    if (bridge == nullptr)
        return false;
    State &state = *implementation(bridge);
    if (state.magic != kMagic)
        return false;
    state.reservation_stop_attempts.fetch_add(1u, std::memory_order_relaxed);
    const uint8_t endpoint_state = state.epoch_endpoint_frozen.load(
        std::memory_order_acquire);
    if (endpoint_state != kEndpointFrozen &&
        !freeze_endpoint(state, configured_sequence_exclusive(state)))
        return false;
    return stop_reservation_admission(state);
}

fk_owner_output_sequence_bridge_close_result
fk_owner_output_sequence_bridge_close_epoch(
        fk_owner_output_sequence_bridge *bridge,
        uint64_t packet_sequence_exclusive) {
    if (bridge == nullptr)
        return FK_OWNER_OUTPUT_SEQUENCE_BRIDGE_CLOSE_INVALID;
    State &state = *implementation(bridge);
    if (state.magic != kMagic)
        return FK_OWNER_OUTPUT_SEQUENCE_BRIDGE_CLOSE_INVALID;
    state.epoch_close_attempts.fetch_add(1u, std::memory_order_relaxed);
    if (terminal_failed(state))
        return FK_OWNER_OUTPUT_SEQUENCE_BRIDGE_CLOSE_TERMINAL;
    if (packet_sequence_exclusive < state.config.sequence_base ||
        packet_sequence_exclusive > configured_sequence_exclusive(state)) {
        state.epoch_close_prefix_mismatches.fetch_add(
            1u, std::memory_order_relaxed);
        return FK_OWNER_OUTPUT_SEQUENCE_BRIDGE_CLOSE_PREFIX_MISMATCH;
    }
    if (packet_sequence_exclusive == state.config.sequence_base) {
        state.epoch_close_empty_rejections.fetch_add(
            1u, std::memory_order_relaxed);
        return FK_OWNER_OUTPUT_SEQUENCE_BRIDGE_CLOSE_EMPTY_EPOCH;
    }
    if (!streaming_readiness(state) &&
        packet_sequence_exclusive != configured_sequence_exclusive(state))
        return FK_OWNER_OUTPUT_SEQUENCE_BRIDGE_CLOSE_INVALID;
    const uint8_t endpoint_state = state.epoch_endpoint_frozen.load(
        std::memory_order_acquire);
    if (endpoint_state == kEndpointFrozen) {
        return formal_sequence_exclusive(state) == packet_sequence_exclusive
            ? FK_OWNER_OUTPUT_SEQUENCE_BRIDGE_ALREADY_CLOSED
            : FK_OWNER_OUTPUT_SEQUENCE_BRIDGE_CLOSE_PREFIX_MISMATCH;
    }
    if (!claim_or_validate_reservation_thread(state))
        return FK_OWNER_OUTPUT_SEQUENCE_BRIDGE_CLOSE_INVALID;
    const uint64_t prefix = state.next_reservation_sequence.load(
        std::memory_order_acquire);
    if (prefix != packet_sequence_exclusive) {
        state.epoch_close_prefix_mismatches.fetch_add(
            1u, std::memory_order_relaxed);
        return FK_OWNER_OUTPUT_SEQUENCE_BRIDGE_CLOSE_PREFIX_MISMATCH;
    }
    if (state.routes_bound.load(std::memory_order_acquire) !=
            state.reservations.load(std::memory_order_acquire)) {
        state.epoch_close_unbound_routes.fetch_add(
            1u, std::memory_order_relaxed);
        return FK_OWNER_OUTPUT_SEQUENCE_BRIDGE_CLOSE_UNBOUND_ROUTE;
    }
    state.reservation_stop_attempts.fetch_add(1u, std::memory_order_relaxed);
    if (!stop_reservation_admission(state))
        return FK_OWNER_OUTPUT_SEQUENCE_BRIDGE_CLOSE_INVALID;
    if (state.next_reservation_sequence.load(std::memory_order_acquire) !=
            packet_sequence_exclusive ||
        state.routes_bound.load(std::memory_order_acquire) !=
            state.reservations.load(std::memory_order_acquire) ||
        !freeze_endpoint(state, packet_sequence_exclusive)) {
        terminal(state);
        return FK_OWNER_OUTPUT_SEQUENCE_BRIDGE_CLOSE_TERMINAL;
    }
    state.epoch_close_transitions.fetch_add(1u, std::memory_order_relaxed);
    return FK_OWNER_OUTPUT_SEQUENCE_BRIDGE_CLOSED;
}

enum fk_owner_packet_completion_publish_result
fk_owner_output_sequence_bridge_publish_completion_after_commit_ack(
        fk_owner_output_sequence_bridge *bridge,
        const fk_owner_packet_completion_v1 *completion) {
    if (bridge == nullptr || completion == nullptr)
        return FK_OWNER_PACKET_COMPLETION_PUBLISH_INVALID;
    State &state = *implementation(bridge);
    if (state.magic != kMagic)
        return FK_OWNER_PACKET_COMPLETION_PUBLISH_INVALID;
    state.publication_attempts.fetch_add(1u, std::memory_order_relaxed);
    if (terminal_failed(state)) {
        state.terminal_publications.fetch_add(1u, std::memory_order_relaxed);
        return FK_OWNER_PACKET_COMPLETION_TERMINAL;
    }
    if (!completion_valid(state, *completion)) {
        state.invalid_publications.fetch_add(1u, std::memory_order_relaxed);
        return FK_OWNER_PACKET_COMPLETION_PUBLISH_INVALID;
    }
    if (!sequence_in_configured_epoch(
            state, completion->packet_sequence)) {
        state.out_of_range_publications.fetch_add(
            1u, std::memory_order_relaxed);
        return FK_OWNER_PACKET_COMPLETION_OUT_OF_RANGE;
    }
    const ReserveResult reserved = reserve_publisher(state);
    if (reserved == ReserveResult::Stopped) {
        state.stopped_publications.fetch_add(1u, std::memory_order_relaxed);
        return FK_OWNER_PACKET_COMPLETION_STOPPED;
    }
    if (reserved == ReserveResult::Failed) {
        state.invalid_publications.fetch_add(1u, std::memory_order_relaxed);
        return FK_OWNER_PACKET_COMPLETION_INTERNAL_FAILURE;
    }
    PublisherReservation reservation(state);
    CompletionSlot &slot = state.completions[
        completion_slot_index(state, completion->packet_sequence)];
    const uint64_t slot_sequence = slot.packet_sequence.load(
        std::memory_order_acquire);
    uint32_t expected = slot.state.load(std::memory_order_acquire);
    if (completion->packet_sequence < state.consumer_prefix.load(
            std::memory_order_acquire) ||
        (slot_sequence == completion->packet_sequence &&
         ((expected & kCompletionPublishedBit) != 0u ||
          expected == kCompletionFree))) {
        state.duplicate_publications.fetch_add(1u, std::memory_order_relaxed);
        return FK_OWNER_PACKET_COMPLETION_DUPLICATE;
    }
    if (slot_sequence != completion->packet_sequence ||
        (expected & kCompletionBoundBit) == 0u) {
        state.unreserved_publications.fetch_add(1u, std::memory_order_relaxed);
        terminal(state);
        return FK_OWNER_PACKET_COMPLETION_UNRESERVED;
    }
    uint16_t expected_owner = 0u;
    uint8_t expected_route_kind = 0u;
    decode_route(expected, expected_owner, expected_route_kind);
    const bool route_matches =
        (expected_route_kind == FK_OWNER_RESERVED_ROUTE_DATA &&
         completion->fixed_owner == expected_owner &&
         completion->completion_kind !=
             FK_OWNER_PACKET_COMPLETION_ORDERED_SKIP) ||
        (expected_route_kind == FK_OWNER_RESERVED_ROUTE_SKIP &&
         completion->fixed_owner ==
             FK_OWNER_OUTPUT_SEQUENCE_BRIDGE_SKIP_OWNER &&
         completion->completion_kind ==
             FK_OWNER_PACKET_COMPLETION_ORDERED_SKIP);
    if (!route_matches) {
        state.terminal_publications.fetch_add(1u, std::memory_order_relaxed);
        terminal(state);
        return FK_OWNER_PACKET_COMPLETION_TERMINAL;
    }
    const uint32_t encoded = encode_completion(*completion);
    if (!slot.state.compare_exchange_strong(
                expected,
                encoded,
                std::memory_order_release,
                std::memory_order_relaxed)) {
        state.duplicate_publications.fetch_add(1u, std::memory_order_relaxed);
        return FK_OWNER_PACKET_COMPLETION_DUPLICATE;
    }
    state.published_completions.fetch_add(1u, std::memory_order_relaxed);
    if (completion->completion_kind ==
            FK_OWNER_PACKET_COMPLETION_OWNER_NO_OUTPUT) {
        state.published_owner_no_output.fetch_add(
            1u, std::memory_order_relaxed);
    } else if (completion->completion_kind ==
            FK_OWNER_PACKET_COMPLETION_ORDERED_SKIP) {
        state.published_ordered_skips.fetch_add(
            1u, std::memory_order_relaxed);
    } else {
        state.published_output_batches.fetch_add(
            1u, std::memory_order_relaxed);
        if ((completion->expected_association_mask &
                FK_TRACE_MESSAGE_FLOW_OPEN) != 0u) {
            state.expected_flow_open_messages.fetch_add(
                1u, std::memory_order_relaxed);
        }
        if ((completion->expected_association_mask &
                FK_TRACE_MESSAGE_CHECKPOINT) != 0u) {
            state.expected_checkpoint_messages.fetch_add(
                1u, std::memory_order_relaxed);
        }
    }
    return FK_OWNER_PACKET_COMPLETION_PUBLISHED;
}

bool fk_owner_output_sequence_bridge_stop_completions(
        fk_owner_output_sequence_bridge *bridge) {
    if (bridge == nullptr)
        return false;
    State &state = *implementation(bridge);
    if (state.magic != kMagic)
        return false;
    state.completion_stop_attempts.fetch_add(1u, std::memory_order_relaxed);
    uint64_t observed = state.lifecycle_and_publishers.load(
        std::memory_order_acquire);
    for (;;) {
        if ((observed & kStoppedBit) != 0u)
            break;
        if (state.lifecycle_and_publishers.compare_exchange_weak(
                observed,
                observed | kStoppedBit,
                std::memory_order_acq_rel,
                std::memory_order_acquire)) {
            state.completion_stop_transitions.fetch_add(
                1u, std::memory_order_relaxed);
            break;
        }
    }
    while ((state.lifecycle_and_publishers.load(std::memory_order_acquire) &
            kPublisherMask) != 0u)
        std::atomic_signal_fence(std::memory_order_seq_cst);
    return true;
}

enum fk_owner_output_sequence_bridge_poll_result
fk_owner_output_sequence_bridge_poll(
        fk_owner_output_sequence_bridge *bridge,
        uint64_t physical_now_ns) {
    if (bridge == nullptr)
        return FK_OWNER_OUTPUT_SEQUENCE_BRIDGE_POLL_INVALID;
    State &state = *implementation(bridge);
    if (state.magic != kMagic)
        return FK_OWNER_OUTPUT_SEQUENCE_BRIDGE_POLL_INVALID;
    state.counters.poll_calls++;
    if (!claim_or_validate_consumer_thread(state)) {
        state.counters.invalid_poll_calls++;
        return FK_OWNER_OUTPUT_SEQUENCE_BRIDGE_POLL_INVALID;
    }
    if (state.sealed != 0u)
        return FK_OWNER_OUTPUT_SEQUENCE_BRIDGE_POLL_SEALED;
    if (terminal_failed(state))
        return FK_OWNER_OUTPUT_SEQUENCE_BRIDGE_POLL_TERMINAL;
    if (physical_now_ns == 0u) {
        state.counters.invalid_poll_calls++;
        terminal(state);
        return FK_OWNER_OUTPUT_SEQUENCE_BRIDGE_POLL_INVALID;
    }
    if (state.has_pending_batch != 0u) {
        bool backpressured = false;
        if (process_pending_batch(state, physical_now_ns, backpressured))
            return FK_OWNER_OUTPUT_SEQUENCE_BRIDGE_POLL_PROGRESSED;
        if (backpressured) {
            state.counters.backpressured_polls++;
            return FK_OWNER_OUTPUT_SEQUENCE_BRIDGE_POLL_BACKPRESSURED;
        }
        return FK_OWNER_OUTPUT_SEQUENCE_BRIDGE_POLL_TERMINAL;
    }
    const uint64_t endpoint = formal_sequence_exclusive(state);
    if (state.next_packet_sequence == endpoint &&
        state.epoch_endpoint_frozen.load(std::memory_order_acquire) ==
            kEndpointFrozen) {
        if (completions_stopped(state) && reservations_stopped(state))
            return FK_OWNER_OUTPUT_SEQUENCE_BRIDGE_POLL_DRAINED;
        state.counters.idle_polls++;
        return FK_OWNER_OUTPUT_SEQUENCE_BRIDGE_POLL_IDLE;
    }
    const uint64_t reserved_prefix =
        state.next_reservation_sequence.load(std::memory_order_acquire);
    if (state.next_packet_sequence >= reserved_prefix) {
        if (reservations_stopped(state)) {
            /* close_epoch first stops admission, waits for any in-flight
             * reserver, and then publishes the exact endpoint.  That short
             * transition is not a missing completion. */
            if (state.epoch_endpoint_frozen.load(
                    std::memory_order_acquire) != kEndpointFrozen) {
                state.counters.idle_polls++;
                return FK_OWNER_OUTPUT_SEQUENCE_BRIDGE_POLL_IDLE;
            }
            if (state.next_packet_sequence ==
                    formal_sequence_exclusive(state)) {
                if (completions_stopped(state))
                    return FK_OWNER_OUTPUT_SEQUENCE_BRIDGE_POLL_DRAINED;
                state.counters.idle_polls++;
                return FK_OWNER_OUTPUT_SEQUENCE_BRIDGE_POLL_IDLE;
            }
            state.counters.missing_completions_after_stop++;
            terminal(state);
            return FK_OWNER_OUTPUT_SEQUENCE_BRIDGE_POLL_TERMINAL;
        }
        state.counters.idle_polls++;
        return FK_OWNER_OUTPUT_SEQUENCE_BRIDGE_POLL_IDLE;
    }
    CompletionSlot &completion_slot = state.completions[
        completion_slot_index(state, state.next_packet_sequence)];
    const uint64_t slot_sequence = completion_slot.packet_sequence.load(
        std::memory_order_acquire);
    const uint32_t encoded = completion_slot.state.load(
        std::memory_order_acquire);
    if (slot_sequence != state.next_packet_sequence) {
        state.counters.packet_sequence_mismatches++;
        terminal(state);
        return FK_OWNER_OUTPUT_SEQUENCE_BRIDGE_POLL_TERMINAL;
    }
    if ((encoded & kCompletionPublishedBit) == 0u) {
        if (encoded != kCompletionReserved &&
            (encoded & kCompletionBoundBit) == 0u) {
            state.counters.missing_completions_after_stop++;
            terminal(state);
            return FK_OWNER_OUTPUT_SEQUENCE_BRIDGE_POLL_TERMINAL;
        }
        if (completions_stopped(state)) {
            state.counters.missing_completions_after_stop++;
            terminal(state);
            return FK_OWNER_OUTPUT_SEQUENCE_BRIDGE_POLL_TERMINAL;
        }
        state.counters.idle_polls++;
        return FK_OWNER_OUTPUT_SEQUENCE_BRIDGE_POLL_IDLE;
    }
    uint16_t owner = 0u;
    uint8_t kind = 0u;
    uint8_t mask = 0u;
    decode_completion(encoded, owner, kind, mask);
    if (kind != FK_OWNER_PACKET_COMPLETION_OUTPUT_COMMIT_ACKED) {
        if ((kind != FK_OWNER_PACKET_COMPLETION_OWNER_NO_OUTPUT &&
             kind != FK_OWNER_PACKET_COMPLETION_ORDERED_SKIP) || mask != 0u ||
            (kind == FK_OWNER_PACKET_COMPLETION_ORDERED_SKIP
                 ? owner != FK_OWNER_OUTPUT_SEQUENCE_BRIDGE_SKIP_OWNER
                 : owner >= state.config.owner_count)) {
            terminal(state);
            return FK_OWNER_OUTPUT_SEQUENCE_BRIDGE_POLL_TERMINAL;
        }
        if (!complete_without_batch(state))
            return FK_OWNER_OUTPUT_SEQUENCE_BRIDGE_POLL_TERMINAL;
        return FK_OWNER_OUTPUT_SEQUENCE_BRIDGE_POLL_PROGRESSED;
    }
    if (owner >= state.config.owner_count) {
        state.counters.owner_mismatches++;
        terminal(state);
        return FK_OWNER_OUTPUT_SEQUENCE_BRIDGE_POLL_TERMINAL;
    }
    fk_owner_runtime_output_batch_v2 batch{};
    const fk_owner_output_batch_take_result taken =
        fk_owner_output_batch_ring_dequeue(state.owner_rings[owner], &batch);
    if (taken == FK_OWNER_OUTPUT_BATCH_EMPTY) {
        state.counters.ring_empty_after_completion++;
        state.counters.backpressured_polls++;
        return FK_OWNER_OUTPUT_SEQUENCE_BRIDGE_POLL_BACKPRESSURED;
    }
    if (taken != FK_OWNER_OUTPUT_BATCH_DEQUEUED) {
        state.counters.ring_take_failures++;
        terminal(state);
        return FK_OWNER_OUTPUT_SEQUENCE_BRIDGE_POLL_TERMINAL;
    }
    state.pending_batch = batch;
    state.pending_owner = owner;
    state.pending_association_mask = mask;
    state.pending_payload_slot = kNoPayload;
    state.has_pending_batch = 1u;
    state.counters.batches_dequeued++;
    if (!batch_valid(batch)) {
        state.counters.invalid_output_batches++;
        terminal(state);
        return FK_OWNER_OUTPUT_SEQUENCE_BRIDGE_POLL_TERMINAL;
    }
    if (batch.packet_sequence != state.next_packet_sequence) {
        state.counters.packet_sequence_mismatches++;
        terminal(state);
        return FK_OWNER_OUTPUT_SEQUENCE_BRIDGE_POLL_TERMINAL;
    }
    if (batch_association_mask(batch) != mask) {
        state.counters.association_mask_mismatches++;
        terminal(state);
        return FK_OWNER_OUTPUT_SEQUENCE_BRIDGE_POLL_TERMINAL;
    }
    bool backpressured = false;
    if (process_pending_batch(state, physical_now_ns, backpressured))
        return FK_OWNER_OUTPUT_SEQUENCE_BRIDGE_POLL_PROGRESSED;
    if (backpressured) {
        state.counters.backpressured_polls++;
        return FK_OWNER_OUTPUT_SEQUENCE_BRIDGE_POLL_BACKPRESSURED;
    }
    return FK_OWNER_OUTPUT_SEQUENCE_BRIDGE_POLL_TERMINAL;
}

bool fk_owner_output_sequence_bridge_ready_boundary(
        const fk_owner_output_sequence_bridge *bridge,
        uint64_t *ready_prefix_packets,
        uint64_t *input_sequence_exclusive) {
    if (bridge == nullptr || ready_prefix_packets == nullptr ||
        input_sequence_exclusive == nullptr)
        return false;
    const State &state = *implementation(bridge);
    if (state.magic != kMagic ||
        state.ready_prefix_packets < state.config.sequence_base ||
        state.ready_prefix_packets > configured_sequence_exclusive(state) ||
        !fk_compact_exact_trace_ready_boundary(
            state.ready_prefix_packets, input_sequence_exclusive))
        return false;
    uint64_t reads = state.ready_boundary_reads.load(
        std::memory_order_relaxed);
    for (;;) {
        if (reads == UINT64_MAX) {
            state.ready_boundary_counter_overflow.store(
                1u, std::memory_order_relaxed);
            return false;
        }
        if (state.ready_boundary_reads.compare_exchange_weak(
                reads, reads + 1u,
                std::memory_order_relaxed,
                std::memory_order_relaxed))
            break;
    }
    *ready_prefix_packets = state.ready_prefix_packets;
    return true;
}

bool fk_owner_output_sequence_bridge_take_checkpoint_payload_v1(
        fk_owner_output_sequence_bridge *bridge,
        uint32_t payload_slot,
        fk_owner_checkpoint_payload_v1 *payload) {
    if (bridge == nullptr || payload == nullptr)
        return false;
    State &state = *implementation(bridge);
    if (state.magic != kMagic ||
        !claim_or_validate_consumer_thread(state) ||
        payload_slot >= state.config.checkpoint_payload_capacity ||
        state.payloads[payload_slot].active == 0u) {
        if (state.magic == kMagic)
            state.counters.payload_invalid_releases++;
        return false;
    }
    PayloadCell &cell = state.payloads[payload_slot];
    *payload = cell.payload;
    cell.payload = {};
    cell.active = 0u;
    cell.next_free = state.payload_free_head;
    state.payload_free_head = payload_slot;
    state.counters.payload_releases++;
    if (state.counters.payloads_in_use == 0u) {
        terminal(state);
        return false;
    }
    state.counters.payloads_in_use--;
    return true;
}

bool fk_owner_output_sequence_bridge_take_checkpoint_payload(
        fk_owner_output_sequence_bridge *bridge,
        uint32_t payload_slot,
        fk_compact_detection_request_v2 *request) {
    if (request == nullptr)
        return false;
    fk_owner_checkpoint_payload_v1 payload{};
    if (!fk_owner_output_sequence_bridge_take_checkpoint_payload_v1(
            bridge, payload_slot, &payload)) {
        return false;
    }
    *request = payload.detection;
    return true;
}

bool fk_owner_output_sequence_bridge_get_stats(
        const fk_owner_output_sequence_bridge *bridge,
        fk_owner_output_sequence_bridge_stats *stats) {
    if (bridge == nullptr || stats == nullptr)
        return false;
    const State &state = *implementation(bridge);
    if (state.magic != kMagic)
        return false;
    *stats = state.counters;
    stats->configured_packet_capacity = state.config.expected_packets;
    stats->sequence_base = state.config.sequence_base;
    stats->packet_sequence_exclusive = formal_sequence_exclusive(state);
    stats->expected_packets = formal_packet_count(state);
    stats->next_packet_sequence = state.next_packet_sequence;
    stats->next_reservation_sequence =
        state.next_reservation_sequence.load(std::memory_order_acquire);
    stats->ready_prefix_packets = state.ready_prefix_packets;
    stats->ready_boundary_reads =
        state.ready_boundary_reads.load(std::memory_order_acquire);
    stats->ready_boundary_counter_overflows =
        state.ready_boundary_counter_overflow.load(
            std::memory_order_acquire);
    stats->reservation_attempts =
        state.reservation_attempts.load(std::memory_order_acquire);
    stats->reservations =
        state.reservations.load(std::memory_order_acquire);
    stats->idempotent_reservations =
        state.idempotent_reservations.load(std::memory_order_acquire);
    stats->reservation_full_backpressure =
        state.reservation_full_backpressure.load(std::memory_order_acquire);
    stats->out_of_order_reservations =
        state.out_of_order_reservations.load(std::memory_order_acquire);
    stats->out_of_range_reservations =
        state.out_of_range_reservations.load(std::memory_order_acquire);
    stats->stopped_reservations =
        state.stopped_reservations.load(std::memory_order_acquire);
    stats->terminal_reservations =
        state.terminal_reservations.load(std::memory_order_acquire);
    stats->reservation_thread_claims =
        state.reservation_thread_claims.load(std::memory_order_acquire);
    stats->reservation_thread_rejections =
        state.reservation_thread_rejections.load(std::memory_order_acquire);
    stats->consumer_thread_claims =
        state.consumer_thread_claims.load(std::memory_order_acquire);
    stats->consumer_thread_rejections =
        state.consumer_thread_rejections.load(std::memory_order_acquire);
    stats->reservation_internal_failures =
        state.reservation_internal_failures.load(std::memory_order_acquire);
    stats->reservation_stop_attempts =
        state.reservation_stop_attempts.load(std::memory_order_acquire);
    stats->reservation_stop_transitions =
        state.reservation_stop_transitions.load(std::memory_order_acquire);
    stats->epoch_close_attempts =
        state.epoch_close_attempts.load(std::memory_order_acquire);
    stats->epoch_close_transitions =
        state.epoch_close_transitions.load(std::memory_order_acquire);
    stats->epoch_close_prefix_mismatches =
        state.epoch_close_prefix_mismatches.load(std::memory_order_acquire);
    stats->epoch_close_unbound_routes =
        state.epoch_close_unbound_routes.load(std::memory_order_acquire);
    stats->epoch_close_empty_rejections =
        state.epoch_close_empty_rejections.load(std::memory_order_acquire);
    stats->active_reservations =
        state.active_reservations.load(std::memory_order_acquire);
    stats->peak_active_reservations =
        state.peak_active_reservations.load(std::memory_order_acquire);
    stats->route_bind_attempts =
        state.route_bind_attempts.load(std::memory_order_acquire);
    stats->routes_bound =
        state.routes_bound.load(std::memory_order_acquire);
    stats->idempotent_route_bindings =
        state.idempotent_route_bindings.load(std::memory_order_acquire);
    stats->unreserved_route_bindings =
        state.unreserved_route_bindings.load(std::memory_order_acquire);
    stats->mismatched_route_bindings =
        state.mismatched_route_bindings.load(std::memory_order_acquire);
    stats->terminal_route_bindings =
        state.terminal_route_bindings.load(std::memory_order_acquire);
    stats->terminal_publications =
        state.terminal_publications.load(std::memory_order_acquire);
    stats->abort_attempts =
        state.abort_attempts.load(std::memory_order_acquire);
    stats->abort_receipts =
        state.abort_receipts.load(std::memory_order_acquire);
    stats->publication_attempts =
        state.publication_attempts.load(std::memory_order_acquire);
    stats->published_completions =
        state.published_completions.load(std::memory_order_acquire);
    stats->published_owner_no_output =
        state.published_owner_no_output.load(std::memory_order_acquire);
    stats->published_output_batches =
        state.published_output_batches.load(std::memory_order_acquire);
    stats->published_ordered_skips =
        state.published_ordered_skips.load(std::memory_order_acquire);
    stats->invalid_publications =
        state.invalid_publications.load(std::memory_order_acquire);
    stats->duplicate_publications =
        state.duplicate_publications.load(std::memory_order_acquire);
    stats->out_of_range_publications =
        state.out_of_range_publications.load(std::memory_order_acquire);
    stats->stopped_publications =
        state.stopped_publications.load(std::memory_order_acquire);
    stats->unreserved_publications =
        state.unreserved_publications.load(std::memory_order_acquire);
    stats->completion_stop_attempts =
        state.completion_stop_attempts.load(std::memory_order_acquire);
    stats->completion_stop_transitions =
        state.completion_stop_transitions.load(std::memory_order_acquire);
    stats->expected_flow_open_messages =
        state.expected_flow_open_messages.load(std::memory_order_acquire);
    stats->expected_checkpoint_messages =
        state.expected_checkpoint_messages.load(std::memory_order_acquire);
    stats->reorder_envelopes_remaining =
        fk_checkpoint_reorder_count(state.reorder);
    stats->owner_ring_batches_remaining = 0u;
    for (uint16_t owner = 0u; owner < state.config.owner_count; ++owner) {
        fk_owner_output_batch_ring_stats ring_stats{};
        if (!fk_owner_output_batch_ring_get_stats(
                state.owner_rings[owner], &ring_stats) ||
            !counter_can_add(
                stats->owner_ring_batches_remaining,
                ring_stats.depth)) {
            return false;
        }
        stats->owner_ring_batches_remaining += ring_stats.depth;
    }
    stats->service_memory_bytes = state.reserved_bytes;
    stats->service_metadata_bytes = state.metadata_bytes;
    stats->service_completion_bytes = state.completion_bytes;
    stats->service_payload_bytes = state.payload_bytes;
    stats->checkpoint_payload_capacity =
        state.config.checkpoint_payload_capacity;
    stats->completion_window_capacity =
        state.config.completion_window_capacity;
    stats->owner_count = state.config.owner_count;
    stats->abi_version = FK_OWNER_OUTPUT_SEQUENCE_BRIDGE_ABI_VERSION;
    stats->readiness_mode = state.config.readiness_mode;
    stats->completions_stopped = completions_stopped(state);
    stats->reservations_stopped = reservations_stopped(state);
    stats->epoch_endpoint_frozen =
        state.epoch_endpoint_frozen.load(std::memory_order_acquire) ==
            kEndpointFrozen;
    stats->partial_epoch = stats->epoch_endpoint_frozen &&
        stats->expected_packets < stats->configured_packet_capacity;
    stats->pending_batch = state.has_pending_batch != 0u;
    stats->terminal_failure = terminal_failed(state);
    stats->abort_receipt_present =
        state.abort_receipt_ready.load(std::memory_order_acquire) != 0u;
    stats->abort_no_active = state.abort_no_active != 0u;
    stats->abort_cleanup_done = state.abort_cleanup_done != 0u;
    stats->sealed = state.sealed != 0u;
    snapshot_accounting(*stats);
    stats->formal_ready = state.sealed != 0u &&
        !terminal_failed(state) &&
        stats->publication_accounting_conserved &&
        stats->reservation_accounting_conserved &&
        stats->completion_accounting_conserved &&
        stats->payload_accounting_conserved &&
        stats->readiness_accounting_conserved;
    return true;
}

bool fk_owner_output_sequence_bridge_seal(
        fk_owner_output_sequence_bridge *bridge) {
    if (bridge == nullptr)
        return false;
    State &state = *implementation(bridge);
    if (state.magic != kMagic)
        return false;
    state.counters.seal_attempts++;
    if (state.sealed != 0u)
        return true;
    const uint64_t endpoint = formal_sequence_exclusive(state);
    const uint64_t packet_count = formal_packet_count(state);
    bool valid = !terminal_failed(state) &&
        completions_stopped(state) && reservations_stopped(state) &&
        state.epoch_endpoint_frozen.load(std::memory_order_acquire) ==
            kEndpointFrozen &&
        state.has_pending_batch == 0u &&
        state.next_packet_sequence == endpoint &&
        state.next_reservation_sequence.load(std::memory_order_acquire) ==
            endpoint &&
        state.active_reservations.load(std::memory_order_acquire) == 0u &&
        state.counters.payloads_in_use == 0u &&
        fk_checkpoint_reorder_count(state.reorder) == 0u;
    for (uint16_t owner = 0u; valid && owner < state.config.owner_count;
         ++owner)
        valid = fk_owner_output_batch_ring_formal_ready(
            state.owner_rings[owner]);
    uint64_t ready = state.ready_prefix_packets;
    fk_checkpoint_reorder_stats reorder_stats{};
    if (streaming_readiness(state)) {
        valid = valid && state.barrier == nullptr &&
            ready == endpoint &&
            state.counters.streaming_prefix_packets_advanced ==
                packet_count &&
            state.counters.finite_barrier_packets_completed == 0u;
    } else {
        fk_trace_message_barrier_stats barrier_stats{};
        valid = valid && fk_trace_message_barrier_advance_ready(
            state.barrier, &ready);
        valid = valid && ready == endpoint &&
            fk_trace_message_barrier_get_stats(
                state.barrier, &barrier_stats) &&
            barrier_stats.integrity_passed &&
            state.counters.finite_barrier_packets_completed ==
                packet_count &&
            state.counters.streaming_prefix_packets_advanced == 0u;
    }
    valid = valid && fk_checkpoint_reorder_get_stats(
        state.reorder, &reorder_stats) &&
        reorder_stats.batch_accounting_conserved != 0u &&
        reorder_stats.sequence_index_active == 0u &&
        reorder_stats.sequence_index_integrity_failures == 0u &&
        reorder_stats.batch_push_attempts ==
            state.reorder_batch_attempts_at_init +
                state.counters.atomic_reorder_push_attempts &&
        reorder_stats.batch_push_attempts - reorder_stats.batch_pushes ==
            state.reorder_batch_failures_at_init &&
        state.counters.atomic_reorder_push_failures == 0u &&
        reorder_stats.inserted ==
            state.counters.flow_open_messages_pushed +
                state.counters.checkpoint_messages_pushed &&
        reorder_stats.released == reorder_stats.inserted &&
        reorder_stats.exact_sequence_releases == reorder_stats.released &&
        reorder_stats.input_sequence_order_violations == 0u &&
        (!streaming_readiness(state) ||
         (reorder_stats.admission_mode ==
              FK_CHECKPOINT_REORDER_ADMISSION_STREAMING_MONOTONIC_V2 &&
          reorder_stats.streaming_accounting_conserved != 0u &&
          reorder_stats.streaming_order_rejections == 0u &&
          reorder_stats.streaming_api_rejections == 0u));
    fk_owner_output_sequence_bridge_stats snapshot{};
    valid = valid && fk_owner_output_sequence_bridge_get_stats(
        bridge, &snapshot) && snapshot.publication_accounting_conserved &&
        snapshot.reservation_accounting_conserved &&
        snapshot.completion_accounting_conserved &&
        snapshot.payload_accounting_conserved &&
        snapshot.readiness_accounting_conserved &&
        snapshot.ready_boundary_counter_overflows == 0u &&
        snapshot.published_completions == packet_count &&
        snapshot.completions_consumed == packet_count &&
        snapshot.expected_flow_open_messages ==
            snapshot.flow_open_messages_pushed &&
        snapshot.expected_checkpoint_messages ==
            snapshot.checkpoint_messages_pushed &&
        snapshot.invalid_publications == 0u &&
        snapshot.duplicate_publications == 0u &&
        snapshot.out_of_range_publications == 0u &&
        snapshot.stopped_publications == 0u &&
        snapshot.unreserved_publications == 0u &&
        snapshot.terminal_publications == 0u &&
        snapshot.routes_bound == snapshot.reservations &&
        snapshot.route_bind_attempts ==
            snapshot.routes_bound + snapshot.idempotent_route_bindings &&
        snapshot.unreserved_route_bindings == 0u &&
        snapshot.mismatched_route_bindings == 0u &&
        snapshot.terminal_route_bindings == 0u &&
        snapshot.out_of_order_reservations == 0u &&
        snapshot.out_of_range_reservations == 0u &&
        snapshot.stopped_reservations == 0u &&
        snapshot.terminal_reservations == 0u &&
        snapshot.reservation_thread_rejections == 0u &&
        snapshot.consumer_thread_rejections == 0u &&
        snapshot.reservation_internal_failures == 0u &&
        snapshot.epoch_close_prefix_mismatches == 0u &&
        snapshot.epoch_close_unbound_routes == 0u &&
        snapshot.epoch_close_empty_rejections == 0u &&
        snapshot.abort_receipts == 0u &&
        snapshot.invalid_poll_calls == 0u &&
        snapshot.ring_empty_after_completion == 0u &&
        snapshot.ring_take_failures == 0u &&
        snapshot.missing_completions_after_stop == 0u &&
        snapshot.owner_mismatches == 0u &&
        snapshot.packet_sequence_mismatches == 0u &&
        snapshot.association_mask_mismatches == 0u &&
        snapshot.invalid_output_batches == 0u &&
        snapshot.flow_identity_failures == 0u &&
        snapshot.barrier_ingest_failures == 0u &&
        snapshot.barrier_completion_failures == 0u &&
        snapshot.payload_invalid_releases == 0u;
    if (!valid) {
        state.counters.seal_rejections++;
        return false;
    }
    state.ready_prefix_packets = ready;
    state.sealed = 1u;
    state.counters.seal_successes++;
    return true;
}

bool fk_owner_output_sequence_bridge_destroy_checked(
        fk_owner_output_sequence_bridge *bridge) {
    if (bridge == nullptr)
        return false;
    State &state = *implementation(bridge);
    if (state.magic != kMagic)
        return false;
    const uint64_t reservers = state.lifecycle_and_reservers.load(
        std::memory_order_acquire);
    const uint64_t publishers = state.lifecycle_and_publishers.load(
        std::memory_order_acquire);
    const bool lifecycle_clean =
        reservers == kStoppedBit && publishers == kStoppedBit;
    const bool terminal_cleanup = state.abort_cleanup_done != 0u &&
        ((terminal_failed(state) &&
          state.abort_receipt_ready.load(std::memory_order_acquire) != 0u) ||
         state.abort_no_active != 0u);
    bool valid = lifecycle_clean &&
        (state.sealed != 0u || terminal_cleanup) &&
        state.active_reservations.load(std::memory_order_acquire) == 0u &&
        state.counters.payloads_in_use == 0u &&
        state.has_pending_batch == 0u &&
        state.pending_payload_slot == kNoPayload &&
        fk_checkpoint_reorder_count(state.reorder) == 0u;
    for (uint16_t owner = 0u; valid && owner < state.config.owner_count;
         ++owner) {
        fk_owner_output_batch_ring_stats ring_stats{};
        valid = fk_owner_output_batch_ring_get_stats(
                    state.owner_rings[owner], &ring_stats) &&
            ring_stats.lifecycle == FK_OWNER_OUTPUT_BATCH_RING_STOPPED &&
            ring_stats.depth == 0u && ring_stats.owned_batches == 0u &&
            ring_stats.pending_commit_ordinal == 0u &&
            (!state.sealed || ring_stats.formal_ready);
    }
    if (!valid)
        return false;
    state.magic = 0u;
    for (uint32_t index = 0u;
         index < state.config.completion_window_capacity; ++index)
        state.completions[index].~CompletionSlot();
    for (uint32_t index = 0u;
         index < state.config.checkpoint_payload_capacity; ++index)
        state.payloads[index].~PayloadCell();
    state.~State();
    return true;
}

}  // extern "C"
