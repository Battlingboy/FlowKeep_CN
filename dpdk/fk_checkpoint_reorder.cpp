#include "fk_checkpoint_reorder.h"

#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <cmath>
#include <limits>
#include <new>

namespace {

constexpr uint64_t kMagic = 0x464b52454f524431ull;  // "FKREORD1"
constexpr uint32_t kNone = UINT32_MAX;

struct Entry {
    fk_checkpoint_envelope_v3 checkpoint;
    uint32_t trace_position;
    uint32_t wait_position;
    uint32_t sequence_position;
    uint32_t next_free;
    uint8_t active;
};

struct State {
    uint64_t magic;
    fk_checkpoint_reorder_config config;
    fk_checkpoint_reorder_stats stats;
    Entry *entries;
    uint32_t *trace_heap;
    uint32_t *wait_heap;
    uint32_t *sequence_heap;
    uint64_t *sequence_occupancy;
    uint64_t sequence_occupancy_word_count;
    uint32_t free_head;
    uint32_t count;
    uint8_t has_maximum_trace;
    uint8_t has_last_released;
    uint8_t has_last_released_sequence;
    uint8_t identity_abi_mode;
};

constexpr uint8_t kIdentityAbiV1 = FK_CHECKPOINT_IDENTITY_ABI_MODE_V1;
constexpr uint8_t kIdentityAbiV2 = FK_CHECKPOINT_IDENTITY_ABI_MODE_V2;
constexpr uint8_t kIdentityAbiV3 = FK_CHECKPOINT_IDENTITY_ABI_MODE_V3;

enum class HeapOrder : uint8_t {
    kTrace,
    kWait,
    kSequence,
};

static State *implementation(fk_checkpoint_reorder *reorder) {
    return reinterpret_cast<State *>(reorder);
}

static const State *implementation(
        const fk_checkpoint_reorder *reorder) {
    return reinterpret_cast<const State *>(reorder);
}

static void set_error(
        char *error, size_t capacity, const char *message) {
    if (error != nullptr && capacity != 0u)
        std::snprintf(error, capacity, "%s", message);
}

static bool checked_add(size_t &value, size_t increment) {
    if (increment > std::numeric_limits<size_t>::max() - value)
        return false;
    value += increment;
    return true;
}

static bool checked_multiply(
        size_t left, size_t right, size_t &result) {
    if (left != 0u &&
        right > std::numeric_limits<size_t>::max() / left)
        return false;
    result = left * right;
    return true;
}

static bool checked_counter_add(uint64_t value, uint64_t increment) {
    return increment <= std::numeric_limits<uint64_t>::max() - value;
}

static bool count_checked(State &state, uint64_t &counter,
        uint64_t increment = 1u) {
    if (!checked_counter_add(counter, increment)) {
        if (state.stats.batch_counter_overflows != UINT64_MAX)
            state.stats.batch_counter_overflows++;
        return false;
    }
    counter += increment;
    return true;
}

static bool align_offset(size_t &value, size_t alignment) {
    const size_t remainder = value % alignment;
    return remainder == 0u ||
        checked_add(value, alignment - remainder);
}

static bool all_zero(const uint8_t *bytes, size_t length) {
    uint8_t combined = 0u;
    for (size_t index = 0u; index < length; ++index)
        combined = static_cast<uint8_t>(combined | bytes[index]);
    return combined == 0u;
}

static bool legacy_envelope_valid(
        const fk_checkpoint_envelope &presentation) {
    return presentation.reserved == 0u &&
        (presentation.message_kind == FK_CHECKPOINT_MESSAGE_FLOW_OPEN ||
         presentation.message_kind ==
             FK_CHECKPOINT_MESSAGE_DETECTION_CHECKPOINT);
}

static bool legacy_to_v3(
        const fk_checkpoint_envelope_v2 &source,
        fk_checkpoint_envelope_v3 &result) {
    if (!legacy_envelope_valid(source.presentation))
        return false;
    result = {};
    result.presentation = source.presentation;
    result.logical_connection_id = source.logical_connection_id;
    result.control_kind = source.presentation.message_kind ==
            FK_CHECKPOINT_MESSAGE_FLOW_OPEN
        ? FK_CHECKPOINT_FLOW_CONTROL_OPEN
        : FK_CHECKPOINT_FLOW_CONTROL_NONE;
    return true;
}

static bool v3_envelope_valid(
        const fk_checkpoint_envelope_v3 &checkpoint) {
    if (checkpoint.coverage_prefix_present > 1u) return false;
    if (checkpoint.coverage_prefix_present) {
        if (checkpoint.control_kind != FK_CHECKPOINT_FLOW_CONTROL_OPEN ||
            checkpoint.presentation.message_kind != FK_CHECKPOINT_MESSAGE_FLOW_OPEN) return false;
        for (float value : checkpoint.coverage_prefix) if (!std::isfinite(value)) return false;
    } else {
        static const float empty[159]{};
        if (std::memcmp(checkpoint.coverage_prefix,empty,sizeof(empty)) != 0) return false;
    }
    if (!legacy_envelope_valid(checkpoint.presentation) ||
        !all_zero(checkpoint.reserved0, sizeof(checkpoint.reserved0)) ||
        (checkpoint.logical_connection_id != 0u &&
         checkpoint.presentation.key.protocol != 17u)) {
        return false;
    }
    if (checkpoint.presentation.message_kind ==
            FK_CHECKPOINT_MESSAGE_DETECTION_CHECKPOINT) {
        return checkpoint.control_kind == FK_CHECKPOINT_FLOW_CONTROL_NONE &&
            checkpoint.predecessor_flow_index == 0u &&
            checkpoint.predecessor_flow_generation == 0u &&
            checkpoint.predecessor_last_checkpoint_packet == 0u;
    }
    if (checkpoint.control_kind == FK_CHECKPOINT_FLOW_CONTROL_OPEN) {
        return checkpoint.predecessor_flow_index == 0u &&
            checkpoint.predecessor_flow_generation == 0u &&
            checkpoint.predecessor_last_checkpoint_packet == 0u;
    }
    const uint32_t successor_index =
        checkpoint.presentation.flow_identity.packed_location &
        UINT32_C(0x00ffffff);
    return checkpoint.control_kind == FK_CHECKPOINT_FLOW_CONTROL_CONTINUE &&
        checkpoint.logical_connection_id == 0u &&
        checkpoint.predecessor_flow_generation != 0u &&
        (checkpoint.predecessor_flow_index != successor_index ||
         checkpoint.predecessor_flow_generation !=
             checkpoint.presentation.flow_identity.generation);
}

static void v3_to_legacy(
        const fk_checkpoint_envelope_v3 &source,
        fk_checkpoint_envelope_v2 &result) {
    result = {};
    result.presentation = source.presentation;
    result.logical_connection_id = source.logical_connection_id;
}

static bool valid_admission_config(
        const fk_checkpoint_reorder_config &config) {
    if (!all_zero(config.reserved0, sizeof(config.reserved0)) ||
        config.admission_mode >
            FK_CHECKPOINT_REORDER_ADMISSION_STREAMING_MONOTONIC_V2)
        return false;
    if (config.admission_mode ==
            FK_CHECKPOINT_REORDER_ADMISSION_FINITE_INDEXED)
        return config.maximum_input_sequence_exclusive != 0u;
    if (config.admission_mode ==
            FK_CHECKPOINT_REORDER_ADMISSION_STREAMING_MONOTONIC_V2)
        return config.maximum_input_sequence_exclusive == 0u;
    return true;
}

static uintptr_t align_pointer(uintptr_t value, size_t alignment) {
    const uintptr_t remainder = value % alignment;
    return remainder == 0u
        ? value : value + alignment - remainder;
}

template <typename T>
static T *take(
        uintptr_t &cursor, uintptr_t end, size_t count) {
    cursor = align_pointer(cursor, alignof(T));
    size_t bytes = 0u;
    if (!checked_multiply(count, sizeof(T), bytes) ||
        cursor > end || bytes > end - cursor)
        return nullptr;
    T *result = reinterpret_cast<T *>(cursor);
    cursor += bytes;
    return result;
}

static bool trace_less(
        const State &state, uint32_t left_slot, uint32_t right_slot) {
    const fk_checkpoint_envelope &left =
        state.entries[left_slot].checkpoint.presentation;
    const fk_checkpoint_envelope &right =
        state.entries[right_slot].checkpoint.presentation;
    if (left.observation_timestamp_ns !=
        right.observation_timestamp_ns)
        return left.observation_timestamp_ns <
            right.observation_timestamp_ns;
    return left.input_sequence < right.input_sequence;
}

static bool wait_less(
        const State &state, uint32_t left_slot, uint32_t right_slot) {
    const fk_checkpoint_envelope &left =
        state.entries[left_slot].checkpoint.presentation;
    const fk_checkpoint_envelope &right =
        state.entries[right_slot].checkpoint.presentation;
    if (left.association_enqueue_timestamp_ns !=
        right.association_enqueue_timestamp_ns)
        return left.association_enqueue_timestamp_ns <
            right.association_enqueue_timestamp_ns;
    return left.input_sequence < right.input_sequence;
}

static bool sequence_less(
        const State &state, uint32_t left_slot, uint32_t right_slot) {
    const fk_checkpoint_envelope &left =
        state.entries[left_slot].checkpoint.presentation;
    const fk_checkpoint_envelope &right =
        state.entries[right_slot].checkpoint.presentation;
    if (left.input_sequence != right.input_sequence)
        return left.input_sequence < right.input_sequence;
    if (left.observation_timestamp_ns !=
        right.observation_timestamp_ns)
        return left.observation_timestamp_ns <
            right.observation_timestamp_ns;
    return left.message_kind < right.message_kind;
}

static uint32_t &position(
        Entry &entry, HeapOrder order) {
    switch (order) {
    case HeapOrder::kTrace:
        return entry.trace_position;
    case HeapOrder::kWait:
        return entry.wait_position;
    case HeapOrder::kSequence:
        return entry.sequence_position;
    }
    return entry.trace_position;
}

static bool heap_less(
        const State &state,
        HeapOrder order,
        uint32_t left_slot,
        uint32_t right_slot) {
    switch (order) {
    case HeapOrder::kTrace:
        return trace_less(state, left_slot, right_slot);
    case HeapOrder::kWait:
        return wait_less(state, left_slot, right_slot);
    case HeapOrder::kSequence:
        return sequence_less(state, left_slot, right_slot);
    }
    return false;
}

static void heap_swap(
        State &state,
        uint32_t *heap,
        HeapOrder order,
        uint32_t left,
        uint32_t right) {
    const uint32_t temporary = heap[left];
    heap[left] = heap[right];
    heap[right] = temporary;
    position(state.entries[heap[left]], order) = left;
    position(state.entries[heap[right]], order) = right;
}

static void heap_up(
        State &state,
        uint32_t *heap,
        HeapOrder order,
        uint32_t index) {
    while (index != 0u) {
        const uint32_t parent = (index - 1u) / 2u;
        if (!heap_less(
                state, order, heap[index], heap[parent]))
            break;
        heap_swap(state, heap, order, index, parent);
        index = parent;
    }
}

static void heap_down(
        State &state,
        uint32_t *heap,
        HeapOrder order,
        uint32_t index,
        uint32_t count) {
    for (;;) {
        const uint32_t left = index * 2u + 1u;
        if (left >= count)
            return;
        const uint32_t right = left + 1u;
        uint32_t smallest = left;
        if (right < count &&
            heap_less(
                state, order, heap[right], heap[left]))
            smallest = right;
        if (!heap_less(
                state, order, heap[smallest], heap[index]))
            return;
        heap_swap(state, heap, order, index, smallest);
        index = smallest;
    }
}

static void heap_insert(
        State &state,
        uint32_t *heap,
        HeapOrder order,
        uint32_t slot) {
    const uint32_t index = state.count;
    heap[index] = slot;
    position(state.entries[slot], order) = index;
    heap_up(state, heap, order, index);
}

static void heap_remove(
        State &state,
        uint32_t *heap,
        HeapOrder order,
        uint32_t index,
        uint32_t old_count) {
    const uint32_t new_count = old_count - 1u;
    if (index == new_count)
        return;
    heap[index] = heap[new_count];
    position(state.entries[heap[index]], order) = index;
    if (index != 0u &&
        heap_less(
            state,
            order,
            heap[index],
            heap[(index - 1u) / 2u]))
        heap_up(state, heap, order, index);
    else
        heap_down(state, heap, order, index, new_count);
}

static bool release_slot(
        State &state,
        uint32_t slot,
        fk_checkpoint_envelope_v3 &checkpoint,
        fk_checkpoint_release_reason release_reason) {
    if (state.count == 0u)
        return false;
    Entry &entry = state.entries[slot];
    if (state.sequence_occupancy != nullptr) {
        const uint64_t sequence =
            entry.checkpoint.presentation.input_sequence;
        if (sequence >=
                state.config.maximum_input_sequence_exclusive) {
            state.stats.sequence_index_integrity_failures++;
            return false;
        }
        const uint64_t word = sequence / UINT64_C(64);
        const uint64_t bit = UINT64_C(1) << (sequence % UINT64_C(64));
        if ((state.sequence_occupancy[word] & bit) == 0u ||
            state.stats.sequence_index_active == 0u) {
            state.stats.sequence_index_integrity_failures++;
            return false;
        }
        state.sequence_occupancy[word] &= ~bit;
        state.stats.sequence_index_active--;
    }
    checkpoint = entry.checkpoint;
    const uint32_t old_count = state.count;
    heap_remove(
        state,
        state.trace_heap,
        HeapOrder::kTrace,
        entry.trace_position,
        old_count);
    heap_remove(
        state,
        state.wait_heap,
        HeapOrder::kWait,
        entry.wait_position,
        old_count);
    heap_remove(
        state,
        state.sequence_heap,
        HeapOrder::kSequence,
        entry.sequence_position,
        old_count);
    state.count--;
    entry.active = 0u;
    entry.next_free = state.free_head;
    state.free_head = slot;
    state.stats.released++;
    state.stats.current_depth = state.count;
    switch (release_reason) {
    case FK_CHECKPOINT_RELEASE_WATERMARK:
        state.stats.watermark_releases++;
        break;
    case FK_CHECKPOINT_RELEASE_MAXIMUM_WAIT:
        state.stats.maximum_wait_releases++;
        break;
    case FK_CHECKPOINT_RELEASE_INPUT_CLOSED:
        state.stats.input_closed_releases++;
        break;
    case FK_CHECKPOINT_RELEASE_CAPACITY:
        state.stats.capacity_releases++;
        break;
    case FK_CHECKPOINT_RELEASE_EXACT_SEQUENCE:
        state.stats.exact_sequence_releases++;
        break;
    default:
        break;
    }
    const uint64_t observation_ns =
        checkpoint.presentation.observation_timestamp_ns;
    if (state.has_last_released != 0u &&
        observation_ns <
            state.stats.last_released_observation_ns)
        state.stats.release_order_violations++;
    state.has_last_released = 1u;
    state.stats.last_released_observation_ns = observation_ns;
    if (state.has_last_released_sequence != 0u &&
        checkpoint.presentation.input_sequence <
            state.stats.last_released_input_sequence)
        state.stats.input_sequence_order_violations++;
    state.has_last_released_sequence = 1u;
    state.stats.last_released_input_sequence =
        checkpoint.presentation.input_sequence;
    return true;
}

static bool release_trace_minimum(
        State &state,
        fk_checkpoint_envelope_v3 &checkpoint,
        fk_checkpoint_release_reason release_reason) {
    return state.count != 0u &&
        release_slot(
            state,
            state.trace_heap[0],
            checkpoint,
            release_reason);
}

static bool release_sequence_minimum(
        State &state,
        fk_checkpoint_envelope_v3 &checkpoint,
        fk_checkpoint_release_reason release_reason) {
    return state.count != 0u &&
        release_slot(
            state,
            state.sequence_heap[0],
            checkpoint,
            release_reason);
}

static bool identity_mode_matches(State &state, uint8_t requested) {
    if (state.identity_abi_mode == 0u ||
        state.identity_abi_mode == requested)
        return true;
    state.stats.identity_mode_rejections++;
    return false;
}

static void commit_identity_mode(State &state, uint8_t requested) {
    if (state.identity_abi_mode == 0u) {
        state.identity_abi_mode = requested;
        state.stats.identity_abi_mode = requested;
    }
}

static void insert_checkpoint(
        State &state,
        const fk_checkpoint_envelope_v3 &checkpoint,
        uint8_t requested_mode) {
    const fk_checkpoint_envelope &presentation =
        checkpoint.presentation;
    if (state.sequence_occupancy != nullptr) {
        const uint64_t sequence = presentation.input_sequence;
        const uint64_t word = sequence / UINT64_C(64);
        const uint64_t bit = UINT64_C(1) << (sequence % UINT64_C(64));
        state.sequence_occupancy[word] |= bit;
        state.stats.sequence_index_active++;
        if (state.stats.sequence_index_active >
                state.stats.sequence_index_peak_active) {
            state.stats.sequence_index_peak_active =
                state.stats.sequence_index_active;
        }
    }
    const uint64_t observation_ns =
        presentation.observation_timestamp_ns;
    if (state.has_last_released != 0u &&
        observation_ns <
            state.stats.last_released_observation_ns)
        state.stats.late_inputs++;
    if (state.has_maximum_trace == 0u ||
        observation_ns >
            state.stats.maximum_trace_observation_ns) {
        state.has_maximum_trace = 1u;
        state.stats.maximum_trace_observation_ns = observation_ns;
    }
    const uint32_t slot = state.free_head;
    Entry &entry = state.entries[slot];
    state.free_head = entry.next_free;
    entry.checkpoint = checkpoint;
    entry.active = 1u;
    heap_insert(
        state, state.trace_heap, HeapOrder::kTrace, slot);
    heap_insert(
        state, state.wait_heap, HeapOrder::kWait, slot);
    heap_insert(
        state, state.sequence_heap, HeapOrder::kSequence, slot);
    state.count++;
    state.stats.inserted++;
    state.stats.current_depth = state.count;
    if (state.count > state.stats.peak_depth)
        state.stats.peak_depth = state.count;
    commit_identity_mode(state, requested_mode);
}

static bool push_checkpoint(
        State &state,
        const fk_checkpoint_envelope_v3 &checkpoint,
        uint8_t requested_mode) {
    if (state.config.admission_mode ==
            FK_CHECKPOINT_REORDER_ADMISSION_STREAMING_MONOTONIC_V2) {
        count_checked(state, state.stats.streaming_api_rejections);
        return false;
    }
    if (!identity_mode_matches(state, requested_mode))
        return false;
    if (state.count >= state.config.capacity ||
        state.free_head == kNone) {
        state.stats.full_rejections++;
        return false;
    }
    if (state.sequence_occupancy != nullptr) {
        const uint64_t sequence =
            checkpoint.presentation.input_sequence;
        if (sequence >=
                state.config.maximum_input_sequence_exclusive) {
            state.stats.input_sequence_domain_rejections++;
            return false;
        }
        state.stats.sequence_index_probes++;
        if (state.stats.sequence_index_peak_probes_per_lookup < 1u)
            state.stats.sequence_index_peak_probes_per_lookup = 1u;
        const uint64_t word = sequence / UINT64_C(64);
        const uint64_t bit = UINT64_C(1) << (sequence % UINT64_C(64));
        if ((state.sequence_occupancy[word] & bit) != 0u) {
            state.stats.duplicate_input_sequence_rejections++;
            return false;
        }
    }
    insert_checkpoint(state, checkpoint, requested_mode);
    return true;
}

static bool free_slots_available(const State &state, uint8_t count) {
    uint32_t slot = state.free_head;
    for (uint8_t index = 0u; index < count; ++index) {
        if (slot == kNone || slot >= state.config.capacity)
            return false;
        slot = state.entries[slot].next_free;
    }
    return true;
}

static bool pop_ready_checkpoint(
        State &state,
        uint8_t requested_mode,
        uint64_t physical_now_ns,
        bool input_closed,
        fk_checkpoint_envelope_v3 &checkpoint,
        fk_checkpoint_release_reason &reason) {
    if (!identity_mode_matches(state, requested_mode) ||
        state.count == 0u)
        return false;
    fk_checkpoint_release_reason selected =
        FK_CHECKPOINT_RELEASE_NONE;
    if (input_closed) {
        selected = FK_CHECKPOINT_RELEASE_INPUT_CLOSED;
    } else {
        const Entry &trace_min =
            state.entries[state.trace_heap[0]];
        const uint64_t trace_ns =
            trace_min.checkpoint.presentation.observation_timestamp_ns;
        const uint64_t maximum_ns =
            state.stats.maximum_trace_observation_ns;
        if (maximum_ns >= trace_ns &&
            maximum_ns - trace_ns >=
                state.config.trace_horizon_ns) {
            selected = FK_CHECKPOINT_RELEASE_WATERMARK;
        } else {
            const Entry &wait_min =
                state.entries[state.wait_heap[0]];
            const uint64_t enqueue_ns = wait_min.checkpoint.presentation
                .association_enqueue_timestamp_ns;
            if (physical_now_ns >= enqueue_ns &&
                physical_now_ns - enqueue_ns >=
                    state.config.maximum_wait_ns)
                selected = FK_CHECKPOINT_RELEASE_MAXIMUM_WAIT;
        }
    }
    if (selected == FK_CHECKPOINT_RELEASE_NONE)
        return false;
    reason = selected;
    return release_trace_minimum(state, checkpoint, selected);
}

static bool force_pop_checkpoint(
        State &state,
        uint8_t requested_mode,
        fk_checkpoint_envelope_v3 &checkpoint,
        fk_checkpoint_release_reason &reason) {
    if (!identity_mode_matches(state, requested_mode) ||
        state.count == 0u)
        return false;
    reason = FK_CHECKPOINT_RELEASE_CAPACITY;
    return release_trace_minimum(
        state, checkpoint, FK_CHECKPOINT_RELEASE_CAPACITY);
}

static bool pop_sequence_checkpoint(
        State &state,
        uint8_t requested_mode,
        uint64_t input_sequence_exclusive,
        fk_checkpoint_envelope_v3 &checkpoint,
        fk_checkpoint_release_reason &reason) {
    if (!identity_mode_matches(state, requested_mode) ||
        state.count == 0u)
        return false;
    const Entry &minimum = state.entries[state.sequence_heap[0]];
    if (minimum.checkpoint.presentation.input_sequence >=
        input_sequence_exclusive)
        return false;
    reason = FK_CHECKPOINT_RELEASE_EXACT_SEQUENCE;
    return release_sequence_minimum(
        state, checkpoint, FK_CHECKPOINT_RELEASE_EXACT_SEQUENCE);
}

static bool push_batch_checkpoint(
        State &state,
        const fk_checkpoint_envelope_v3 *checkpoints,
        uint8_t count,
        uint8_t requested_mode) {
    if (!count_checked(state, state.stats.batch_push_attempts))
        return false;
    if (checkpoints == nullptr || count == 0u || count > 2u) {
        count_checked(state, state.stats.batch_invalid_rejections);
        return false;
    }
    for (uint8_t index = 0u; index < count; ++index) {
        if (!v3_envelope_valid(checkpoints[index])) {
            count_checked(state, state.stats.batch_invalid_rejections);
            return false;
        }
    }
    if (state.identity_abi_mode != 0u &&
        state.identity_abi_mode != requested_mode) {
        state.stats.identity_mode_rejections++;
        count_checked(state, state.stats.batch_identity_rejections);
        return false;
    }
    const bool streaming = state.config.admission_mode ==
        FK_CHECKPOINT_REORDER_ADMISSION_STREAMING_MONOTONIC_V2;
    if (!streaming && state.sequence_occupancy == nullptr) {
        count_checked(state, state.stats.batch_sequence_domain_rejections);
        return false;
    }
    if (state.count > state.config.capacity ||
        static_cast<uint32_t>(count) >
            state.config.capacity - state.count ||
        !free_slots_available(state, count)) {
        state.stats.full_rejections++;
        count_checked(state, state.stats.batch_capacity_rejections);
        return false;
    }
    for (uint8_t index = 0u; index < count; ++index) {
        const uint64_t sequence =
            checkpoints[index].presentation.input_sequence;
        if (streaming) {
            if ((index == 0u &&
                 state.stats.streaming_has_last_admitted != 0u &&
                 sequence <=
                    state.stats.streaming_last_admitted_input_sequence) ||
                (index != 0u && sequence <= checkpoints[index - 1u]
                    .presentation.input_sequence)) {
                count_checked(
                    state, state.stats.streaming_order_rejections);
                count_checked(
                    state, state.stats.batch_streaming_order_rejections);
                return false;
            }
            continue;
        }
        if (sequence >= state.config.maximum_input_sequence_exclusive) {
            state.stats.input_sequence_domain_rejections++;
            count_checked(
                state, state.stats.batch_sequence_domain_rejections);
            return false;
        }
        for (uint8_t prior = 0u; prior < index; ++prior) {
            if (checkpoints[prior].presentation.input_sequence == sequence) {
                state.stats.duplicate_input_sequence_rejections++;
                count_checked(
                    state, state.stats.batch_duplicate_rejections);
                return false;
            }
        }
        if (!count_checked(state, state.stats.sequence_index_probes)) {
            count_checked(state, state.stats.batch_internal_rejections);
            return false;
        }
        if (state.stats.sequence_index_peak_probes_per_lookup < 1u)
            state.stats.sequence_index_peak_probes_per_lookup = 1u;
        const uint64_t word = sequence / UINT64_C(64);
        const uint64_t bit = UINT64_C(1) << (sequence % UINT64_C(64));
        if ((state.sequence_occupancy[word] & bit) != 0u) {
            state.stats.duplicate_input_sequence_rejections++;
            count_checked(state, state.stats.batch_duplicate_rejections);
            return false;
        }
    }

    const uint64_t &commits = count == 1u
        ? state.stats.batch_single_commits
        : state.stats.batch_double_commits;
    if (!checked_counter_add(state.stats.batch_pushes, 1u) ||
        !checked_counter_add(state.stats.batch_items_inserted, count) ||
        !checked_counter_add(commits, 1u) ||
        !checked_counter_add(state.stats.inserted, count) ||
        !checked_counter_add(state.stats.sequence_index_active, count) ||
        (streaming &&
         (!checked_counter_add(state.stats.streaming_batch_commits, 1u) ||
          !checked_counter_add(state.stats.streaming_items_admitted, count)))) {
        if (state.stats.batch_counter_overflows != UINT64_MAX)
            state.stats.batch_counter_overflows++;
        count_checked(state, state.stats.batch_internal_rejections);
        return false;
    }
    for (uint8_t index = 0u; index < count; ++index)
        insert_checkpoint(state, checkpoints[index], requested_mode);
    state.stats.batch_pushes++;
    state.stats.batch_items_inserted += count;
    if (count == 1u)
        state.stats.batch_single_commits++;
    else
        state.stats.batch_double_commits++;
    if (streaming) {
        state.stats.streaming_batch_commits++;
        state.stats.streaming_items_admitted += count;
        state.stats.streaming_last_admitted_input_sequence =
            checkpoints[count - 1u].presentation.input_sequence;
        state.stats.streaming_has_last_admitted = 1u;
    }
    return true;
}

}  // namespace

extern "C" {

size_t fk_checkpoint_reorder_storage_bytes(
        const fk_checkpoint_reorder_config *config) {
    if (config == nullptr || config->capacity == 0u ||
        config->maximum_wait_ns == 0u ||
        !valid_admission_config(*config))
        return 0u;
    size_t bytes = alignof(std::max_align_t) - 1u;
    size_t region = 0u;
    if (!align_offset(bytes, alignof(State)) ||
        !checked_add(bytes, sizeof(State)) ||
        !align_offset(bytes, alignof(Entry)) ||
        !checked_multiply(config->capacity, sizeof(Entry), region) ||
        !checked_add(bytes, region) ||
        !align_offset(bytes, alignof(uint32_t)) ||
        !checked_multiply(config->capacity, sizeof(uint32_t), region) ||
        !checked_add(bytes, region) ||
        !align_offset(bytes, alignof(uint32_t)) ||
        !checked_add(bytes, region) ||
        !align_offset(bytes, alignof(uint32_t)) ||
        !checked_add(bytes, region))
        return 0u;
    if (config->maximum_input_sequence_exclusive != 0u) {
        if (config->maximum_input_sequence_exclusive >
                UINT64_MAX - UINT64_C(63))
            return 0u;
        const uint64_t words64 =
            (config->maximum_input_sequence_exclusive + UINT64_C(63)) /
            UINT64_C(64);
        if (words64 > static_cast<uint64_t>(
                std::numeric_limits<size_t>::max()))
            return 0u;
        if (!align_offset(bytes, alignof(uint64_t)) ||
            !checked_multiply(
                static_cast<size_t>(words64), sizeof(uint64_t), region) ||
            !checked_add(bytes, region))
            return 0u;
    }
    return bytes;
}

fk_checkpoint_reorder *fk_checkpoint_reorder_init(
        void *storage,
        size_t storage_bytes,
        const fk_checkpoint_reorder_config *config,
        char *error,
        size_t error_capacity) {
    set_error(error, error_capacity, "");
    const size_t required =
        fk_checkpoint_reorder_storage_bytes(config);
    if (storage == nullptr || required == 0u ||
        storage_bytes < required) {
        set_error(error, error_capacity, "invalid checkpoint reorder storage");
        return nullptr;
    }
    const uintptr_t start = reinterpret_cast<uintptr_t>(storage);
    if (storage_bytes >
        std::numeric_limits<uintptr_t>::max() - start) {
        set_error(error, error_capacity, "checkpoint reorder storage overflows");
        return nullptr;
    }
    uintptr_t cursor = start;
    const uintptr_t end = start + storage_bytes;
    State *state = take<State>(cursor, end, 1u);
    Entry *entries = take<Entry>(cursor, end, config->capacity);
    uint32_t *trace_heap =
        take<uint32_t>(cursor, end, config->capacity);
    uint32_t *wait_heap =
        take<uint32_t>(cursor, end, config->capacity);
    uint32_t *sequence_heap =
        take<uint32_t>(cursor, end, config->capacity);
    uint64_t sequence_occupancy_word_count = 0u;
    if (config->maximum_input_sequence_exclusive != 0u) {
        sequence_occupancy_word_count =
            (config->maximum_input_sequence_exclusive + UINT64_C(63)) /
            UINT64_C(64);
    }
    uint64_t *sequence_occupancy = sequence_occupancy_word_count == 0u
        ? nullptr
        : take<uint64_t>(
            cursor, end,
            static_cast<size_t>(sequence_occupancy_word_count));
    if (state == nullptr || entries == nullptr ||
        trace_heap == nullptr || wait_heap == nullptr ||
        sequence_heap == nullptr ||
        (sequence_occupancy_word_count != 0u &&
         sequence_occupancy == nullptr)) {
        set_error(error, error_capacity, "checkpoint reorder layout failed");
        return nullptr;
    }
    state = new (state) State{};
    for (uint32_t index = 0u; index < config->capacity; ++index)
        new (&entries[index]) Entry{};
    state->magic = kMagic;
    state->config = *config;
    state->entries = entries;
    state->trace_heap = trace_heap;
    state->wait_heap = wait_heap;
    state->sequence_heap = sequence_heap;
    state->sequence_occupancy = sequence_occupancy;
    state->sequence_occupancy_word_count =
        sequence_occupancy_word_count;
    state->free_head = 0u;
    state->stats.reserved_bytes = required;
    state->stats.capacity = config->capacity;
    state->stats.entry_bytes = sizeof(Entry);
    state->stats.maximum_input_sequence_exclusive =
        config->maximum_input_sequence_exclusive;
    state->stats.admission_mode = config->admission_mode;
    state->stats.sequence_index_enabled =
        sequence_occupancy != nullptr ? 1u : 0u;
    state->stats.sequence_index_bytes =
        sequence_occupancy_word_count * sizeof(uint64_t);
    state->stats.batch_accounting_conserved = 1u;
    if (sequence_occupancy != nullptr) {
        std::memset(
            sequence_occupancy,
            0,
            static_cast<size_t>(state->stats.sequence_index_bytes));
    }
    for (uint32_t index = 0u; index < config->capacity; ++index)
        entries[index].next_free =
            index + 1u < config->capacity ? index + 1u : kNone;
    return reinterpret_cast<fk_checkpoint_reorder *>(state);
}

bool fk_checkpoint_reorder_push(
        fk_checkpoint_reorder *reorder,
        const fk_checkpoint_envelope *checkpoint) {
    if (reorder == nullptr || checkpoint == nullptr)
        return false;
    State &state = *implementation(reorder);
    if (state.magic != kMagic)
        return false;
    fk_checkpoint_envelope_v2 legacy{};
    legacy.presentation = *checkpoint;
    fk_checkpoint_envelope_v3 value{};
    return legacy_to_v3(legacy, value) &&
        push_checkpoint(state, value, kIdentityAbiV1);
}

bool fk_checkpoint_reorder_push_v2(
        fk_checkpoint_reorder *reorder,
        const fk_checkpoint_envelope_v2 *checkpoint) {
    if (reorder == nullptr || checkpoint == nullptr)
        return false;
    State &state = *implementation(reorder);
    fk_checkpoint_envelope_v3 value{};
    return state.magic == kMagic && legacy_to_v3(*checkpoint, value) &&
        push_checkpoint(state, value, kIdentityAbiV2);
}

bool fk_checkpoint_reorder_push_v3(
        fk_checkpoint_reorder *reorder,
        const fk_checkpoint_envelope_v3 *checkpoint) {
    if (reorder == nullptr || checkpoint == nullptr)
        return false;
    State &state = *implementation(reorder);
    return state.magic == kMagic && v3_envelope_valid(*checkpoint) &&
        push_checkpoint(state, *checkpoint, kIdentityAbiV3);
}

bool fk_checkpoint_reorder_push_batch_v2(
        fk_checkpoint_reorder *reorder,
        const fk_checkpoint_envelope_v2 *checkpoints,
        uint8_t count) {
    if (reorder == nullptr)
        return false;
    State &state = *implementation(reorder);
    if (state.magic != kMagic)
        return false;
    if (!count_checked(state, state.stats.batch_push_attempts))
        return false;
    if (checkpoints == nullptr || count == 0u || count > 2u) {
        count_checked(state, state.stats.batch_invalid_rejections);
        return false;
    }
    fk_checkpoint_envelope_v3 converted[2]{};
    for (uint8_t index = 0u; index < count; ++index) {
        if (!legacy_to_v3(checkpoints[index], converted[index])) {
            count_checked(state, state.stats.batch_invalid_rejections);
            return false;
        }
    }
    if (state.identity_abi_mode != 0u &&
        state.identity_abi_mode != kIdentityAbiV2) {
        state.stats.identity_mode_rejections++;
        count_checked(state, state.stats.batch_identity_rejections);
        return false;
    }
    const bool streaming = state.config.admission_mode ==
        FK_CHECKPOINT_REORDER_ADMISSION_STREAMING_MONOTONIC_V2;
    if (!streaming && state.sequence_occupancy == nullptr) {
        count_checked(state, state.stats.batch_sequence_domain_rejections);
        return false;
    }
    if (state.count > state.config.capacity ||
        static_cast<uint32_t>(count) >
            state.config.capacity - state.count ||
        !free_slots_available(state, count)) {
        state.stats.full_rejections++;
        count_checked(state, state.stats.batch_capacity_rejections);
        return false;
    }
    for (uint8_t index = 0u; index < count; ++index) {
        const uint64_t sequence =
            checkpoints[index].presentation.input_sequence;
        if (streaming) {
            if ((index == 0u &&
                 state.stats.streaming_has_last_admitted != 0u &&
                 sequence <=
                    state.stats.streaming_last_admitted_input_sequence) ||
                (index != 0u && sequence <= checkpoints[index - 1u]
                    .presentation.input_sequence)) {
                count_checked(
                    state, state.stats.streaming_order_rejections);
                count_checked(
                    state, state.stats.batch_streaming_order_rejections);
                return false;
            }
            continue;
        }
        if (sequence >=
                state.config.maximum_input_sequence_exclusive) {
            state.stats.input_sequence_domain_rejections++;
            count_checked(
                state, state.stats.batch_sequence_domain_rejections);
            return false;
        }
        for (uint8_t prior = 0u; prior < index; ++prior) {
            if (checkpoints[prior].presentation.input_sequence == sequence) {
                state.stats.duplicate_input_sequence_rejections++;
                count_checked(
                    state, state.stats.batch_duplicate_rejections);
                return false;
            }
        }
        if (!count_checked(state, state.stats.sequence_index_probes)) {
            count_checked(state, state.stats.batch_internal_rejections);
            return false;
        }
        if (state.stats.sequence_index_peak_probes_per_lookup < 1u)
            state.stats.sequence_index_peak_probes_per_lookup = 1u;
        const uint64_t word = sequence / UINT64_C(64);
        const uint64_t bit = UINT64_C(1) << (sequence % UINT64_C(64));
        if ((state.sequence_occupancy[word] & bit) != 0u) {
            state.stats.duplicate_input_sequence_rejections++;
            count_checked(state, state.stats.batch_duplicate_rejections);
            return false;
        }
    }

    /* Every subsequent operation is a no-fail placement commit.  Prove all
     * externally audited counters can advance before touching queue state. */
    const uint64_t &commits = count == 1u
        ? state.stats.batch_single_commits
        : state.stats.batch_double_commits;
    if (!checked_counter_add(state.stats.batch_pushes, 1u) ||
        !checked_counter_add(state.stats.batch_items_inserted, count) ||
        !checked_counter_add(commits, 1u) ||
        !checked_counter_add(state.stats.inserted, count) ||
        !checked_counter_add(state.stats.sequence_index_active, count) ||
        (streaming &&
         (!checked_counter_add(state.stats.streaming_batch_commits, 1u) ||
          !checked_counter_add(state.stats.streaming_items_admitted, count)))) {
        if (state.stats.batch_counter_overflows != UINT64_MAX)
            state.stats.batch_counter_overflows++;
        count_checked(state, state.stats.batch_internal_rejections);
        return false;
    }
    for (uint8_t index = 0u; index < count; ++index)
        insert_checkpoint(state, converted[index], kIdentityAbiV2);
    state.stats.batch_pushes++;
    state.stats.batch_items_inserted += count;
    if (count == 1u)
        state.stats.batch_single_commits++;
    else
        state.stats.batch_double_commits++;
    if (streaming) {
        state.stats.streaming_batch_commits++;
        state.stats.streaming_items_admitted += count;
        state.stats.streaming_last_admitted_input_sequence =
            checkpoints[count - 1u].presentation.input_sequence;
        state.stats.streaming_has_last_admitted = 1u;
    }
    return true;
}

bool fk_checkpoint_reorder_push_batch_v3(
        fk_checkpoint_reorder *reorder,
        const fk_checkpoint_envelope_v3 *checkpoints,
        uint8_t count) {
    if (reorder == nullptr)
        return false;
    State &state = *implementation(reorder);
    return state.magic == kMagic && push_batch_checkpoint(
        state, checkpoints, count, kIdentityAbiV3);
}

bool fk_checkpoint_reorder_pop_ready(
        fk_checkpoint_reorder *reorder,
        uint64_t physical_now_ns,
        bool input_closed,
        fk_checkpoint_envelope *checkpoint,
        fk_checkpoint_release_reason *reason) {
    if (reason != nullptr)
        *reason = FK_CHECKPOINT_RELEASE_NONE;
    if (reorder == nullptr || checkpoint == nullptr ||
        reason == nullptr)
        return false;
    State &state = *implementation(reorder);
    if (state.magic != kMagic)
        return false;
    fk_checkpoint_envelope_v3 value{};
    if (!pop_ready_checkpoint(
            state, kIdentityAbiV1, physical_now_ns, input_closed,
            value, *reason))
        return false;
    *checkpoint = value.presentation;
    return true;
}

bool fk_checkpoint_reorder_pop_ready_v2(
        fk_checkpoint_reorder *reorder,
        uint64_t physical_now_ns,
        bool input_closed,
        fk_checkpoint_envelope_v2 *checkpoint,
        fk_checkpoint_release_reason *reason) {
    if (reason != nullptr)
        *reason = FK_CHECKPOINT_RELEASE_NONE;
    if (reorder == nullptr || checkpoint == nullptr || reason == nullptr)
        return false;
    State &state = *implementation(reorder);
    fk_checkpoint_envelope_v3 value{};
    if (state.magic != kMagic || !pop_ready_checkpoint(
            state, kIdentityAbiV2, physical_now_ns, input_closed,
            value, *reason))
        return false;
    v3_to_legacy(value, *checkpoint);
    return true;
}

bool fk_checkpoint_reorder_pop_ready_v3(
        fk_checkpoint_reorder *reorder,
        uint64_t physical_now_ns,
        bool input_closed,
        fk_checkpoint_envelope_v3 *checkpoint,
        fk_checkpoint_release_reason *reason) {
    if (reason != nullptr)
        *reason = FK_CHECKPOINT_RELEASE_NONE;
    if (reorder == nullptr || checkpoint == nullptr || reason == nullptr)
        return false;
    State &state = *implementation(reorder);
    return state.magic == kMagic && pop_ready_checkpoint(
        state, kIdentityAbiV3, physical_now_ns, input_closed,
        *checkpoint, *reason);
}

bool fk_checkpoint_reorder_force_pop(
        fk_checkpoint_reorder *reorder,
        fk_checkpoint_envelope *checkpoint,
        fk_checkpoint_release_reason *reason) {
    if (reason != nullptr)
        *reason = FK_CHECKPOINT_RELEASE_NONE;
    if (reorder == nullptr || checkpoint == nullptr ||
        reason == nullptr)
        return false;
    State &state = *implementation(reorder);
    if (state.magic != kMagic)
        return false;
    fk_checkpoint_envelope_v3 value{};
    if (!force_pop_checkpoint(
            state, kIdentityAbiV1, value, *reason))
        return false;
    *checkpoint = value.presentation;
    return true;
}

bool fk_checkpoint_reorder_force_pop_v2(
        fk_checkpoint_reorder *reorder,
        fk_checkpoint_envelope_v2 *checkpoint,
        fk_checkpoint_release_reason *reason) {
    if (reason != nullptr)
        *reason = FK_CHECKPOINT_RELEASE_NONE;
    if (reorder == nullptr || checkpoint == nullptr || reason == nullptr)
        return false;
    State &state = *implementation(reorder);
    fk_checkpoint_envelope_v3 value{};
    if (state.magic != kMagic || !force_pop_checkpoint(
            state, kIdentityAbiV2, value, *reason))
        return false;
    v3_to_legacy(value, *checkpoint);
    return true;
}

bool fk_checkpoint_reorder_force_pop_v3(
        fk_checkpoint_reorder *reorder,
        fk_checkpoint_envelope_v3 *checkpoint,
        fk_checkpoint_release_reason *reason) {
    if (reason != nullptr)
        *reason = FK_CHECKPOINT_RELEASE_NONE;
    if (reorder == nullptr || checkpoint == nullptr || reason == nullptr)
        return false;
    State &state = *implementation(reorder);
    return state.magic == kMagic && force_pop_checkpoint(
        state, kIdentityAbiV3, *checkpoint, *reason);
}

bool fk_checkpoint_reorder_pop_sequence_ready(
        fk_checkpoint_reorder *reorder,
        uint64_t input_sequence_exclusive,
        fk_checkpoint_envelope *checkpoint,
        fk_checkpoint_release_reason *reason) {
    if (reason != nullptr)
        *reason = FK_CHECKPOINT_RELEASE_NONE;
    if (reorder == nullptr || checkpoint == nullptr ||
        reason == nullptr)
        return false;
    State &state = *implementation(reorder);
    if (state.magic != kMagic)
        return false;
    fk_checkpoint_envelope_v3 value{};
    if (!pop_sequence_checkpoint(
            state, kIdentityAbiV1, input_sequence_exclusive,
            value, *reason))
        return false;
    *checkpoint = value.presentation;
    return true;
}

bool fk_checkpoint_reorder_pop_sequence_ready_v2(
        fk_checkpoint_reorder *reorder,
        uint64_t input_sequence_exclusive,
        fk_checkpoint_envelope_v2 *checkpoint,
        fk_checkpoint_release_reason *reason) {
    if (reason != nullptr)
        *reason = FK_CHECKPOINT_RELEASE_NONE;
    if (reorder == nullptr || checkpoint == nullptr || reason == nullptr)
        return false;
    State &state = *implementation(reorder);
    fk_checkpoint_envelope_v3 value{};
    if (state.magic != kMagic || !pop_sequence_checkpoint(
            state, kIdentityAbiV2, input_sequence_exclusive,
            value, *reason))
        return false;
    v3_to_legacy(value, *checkpoint);
    return true;
}

bool fk_checkpoint_reorder_pop_sequence_ready_v3(
        fk_checkpoint_reorder *reorder,
        uint64_t input_sequence_exclusive,
        fk_checkpoint_envelope_v3 *checkpoint,
        fk_checkpoint_release_reason *reason) {
    if (reason != nullptr)
        *reason = FK_CHECKPOINT_RELEASE_NONE;
    if (reorder == nullptr || checkpoint == nullptr || reason == nullptr)
        return false;
    State &state = *implementation(reorder);
    return state.magic == kMagic && pop_sequence_checkpoint(
        state, kIdentityAbiV3, input_sequence_exclusive,
        *checkpoint, *reason);
}

uint32_t fk_checkpoint_reorder_count(
        const fk_checkpoint_reorder *reorder) {
    if (reorder == nullptr)
        return 0u;
    const State &state = *implementation(reorder);
    return state.magic == kMagic ? state.count : 0u;
}

bool fk_checkpoint_reorder_get_stats(
        const fk_checkpoint_reorder *reorder,
        fk_checkpoint_reorder_stats *stats) {
    if (reorder == nullptr || stats == nullptr)
        return false;
    const State &state = *implementation(reorder);
    if (state.magic != kMagic)
        return false;
    *stats = state.stats;
    uint64_t rejection_total = 0u;
    uint64_t commit_total = 0u;
    uint64_t item_total = 0u;
    const bool rejection_ok =
        checked_counter_add(rejection_total,
            stats->batch_invalid_rejections) &&
        (rejection_total += stats->batch_invalid_rejections, true) &&
        checked_counter_add(rejection_total,
            stats->batch_identity_rejections) &&
        (rejection_total += stats->batch_identity_rejections, true) &&
        checked_counter_add(rejection_total,
            stats->batch_capacity_rejections) &&
        (rejection_total += stats->batch_capacity_rejections, true) &&
        checked_counter_add(rejection_total,
            stats->batch_duplicate_rejections) &&
        (rejection_total += stats->batch_duplicate_rejections, true) &&
        checked_counter_add(rejection_total,
            stats->batch_sequence_domain_rejections) &&
        (rejection_total += stats->batch_sequence_domain_rejections, true) &&
        checked_counter_add(rejection_total,
            stats->batch_streaming_order_rejections) &&
        (rejection_total += stats->batch_streaming_order_rejections, true) &&
        checked_counter_add(rejection_total,
            stats->batch_internal_rejections) &&
        (rejection_total += stats->batch_internal_rejections, true);
    const bool commit_ok =
        checked_counter_add(
            stats->batch_single_commits,
            stats->batch_double_commits) &&
        (commit_total = stats->batch_single_commits +
            stats->batch_double_commits, true);
    const bool item_ok =
        stats->batch_double_commits <= UINT64_MAX / UINT64_C(2) &&
        (item_total = stats->batch_double_commits * UINT64_C(2), true) &&
        checked_counter_add(item_total, stats->batch_single_commits) &&
        (item_total += stats->batch_single_commits, true);
    stats->batch_accounting_conserved =
        rejection_ok && commit_ok && item_ok &&
        stats->batch_counter_overflows == 0u &&
        checked_counter_add(stats->batch_pushes, rejection_total) &&
        stats->batch_push_attempts ==
            stats->batch_pushes + rejection_total &&
        stats->batch_pushes == commit_total &&
        stats->batch_items_inserted == item_total ? 1u : 0u;
    stats->streaming_accounting_conserved =
        stats->admission_mode !=
            FK_CHECKPOINT_REORDER_ADMISSION_STREAMING_MONOTONIC_V2 ||
        (stats->sequence_index_enabled == 0u &&
         stats->maximum_input_sequence_exclusive == 0u &&
         stats->streaming_batch_commits == stats->batch_pushes &&
         stats->streaming_items_admitted == stats->batch_items_inserted &&
         (stats->streaming_has_last_admitted != 0u) ==
            (stats->streaming_items_admitted != 0u)) ? 1u : 0u;
    return true;
}

bool fk_checkpoint_reorder_destroy_checked(
        fk_checkpoint_reorder *reorder) {
    if (reorder == nullptr)
        return false;
    State &state = *implementation(reorder);
    if (state.magic != kMagic || state.count != 0u)
        return false;
    fk_checkpoint_reorder_stats stats{};
    if (!fk_checkpoint_reorder_get_stats(reorder, &stats) ||
        stats.sequence_index_active != 0u ||
        stats.batch_accounting_conserved == 0u ||
        stats.inserted != stats.released)
        return false;
    state.magic = 0u;
    for (uint32_t index = 0u; index < state.config.capacity; ++index)
        state.entries[index].~Entry();
    state.~State();
    return true;
}

}  // extern "C"
