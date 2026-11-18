#include "fk_exact_identity_sequencer.h"

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <limits>
#include <new>
#include <type_traits>

namespace {

constexpr uint64_t kMagic = UINT64_C(0x464b455853455131);  // "FKEXSEQ1"

static_assert(
    std::is_trivially_copyable<fk_exact_identity_packet>::value,
    "the exact identity ingress envelope must remain a value type");

struct QueueCell {
    fk_exact_identity_packet packet;
};

struct ProducerQueue {
    std::atomic<uint64_t> head;
    std::atomic<uint64_t> tail;
    std::atomic<bool> closed;
    QueueCell *cells;
    uint32_t mask;
};

struct ReorderSlot {
    fk_exact_identity_packet packet;
    uint8_t occupied;
};

struct State {
    uint64_t magic;
    fk_exact_identity_sequencer_config config;
    ProducerQueue *queues;
    ReorderSlot *reorder;
    size_t reserved_bytes;

    std::atomic<uint64_t> submit_attempts;
    std::atomic<uint64_t> accepted_packets;
    std::atomic<uint64_t> ordered_released_packets;
    std::atomic<uint64_t> abort_drained_packets;
    std::atomic<uint64_t> invalid_submissions;
    std::atomic<uint64_t> out_of_range_submissions;
    std::atomic<uint64_t> queue_full_rejections;
    std::atomic<uint64_t> closed_producer_rejections;
    std::atomic<uint64_t> aborted_rejections;
    std::atomic<uint64_t> invalid_close_attempts;
    std::atomic<uint64_t> duplicate_sequences;
    std::atomic<uint64_t> window_overflows;
    std::atomic<uint64_t> slot_conflicts;
    std::atomic<uint64_t> semantic_time_regressions;
    std::atomic<uint64_t> terminal_gaps;
    std::atomic<uint64_t> abort_calls;
    std::atomic<uint64_t> ingress_depth;
    std::atomic<uint64_t> peak_ingress_depth;
    std::atomic<uint64_t> reorder_depth;
    std::atomic<uint64_t> peak_reorder_depth;
    std::atomic<uint16_t> closed_producers;
    std::atomic<uint8_t> terminal_reason;
    std::atomic<bool> aborted;

    std::atomic<uint64_t> next_sequence;
    std::atomic<uint64_t> last_released_semantic_timestamp_ns;
    std::atomic<bool> semantic_time_initialized;
    uint32_t drain_reorder_cursor;
    uint16_t drain_queue_cursor;
};

static State *implementation(fk_exact_identity_sequencer *sequencer) {
    return reinterpret_cast<State *>(sequencer);
}

static const State *implementation(
        const fk_exact_identity_sequencer *sequencer) {
    return reinterpret_cast<const State *>(sequencer);
}

static bool power_of_two(uint32_t value) {
    return value >= 2u && (value & (value - 1u)) == 0u;
}

static bool valid_config(
        const fk_exact_identity_sequencer_config *config) {
    return config != nullptr && config->producer_count != 0u &&
        config->producer_count <=
            FK_EXACT_IDENTITY_SEQUENCER_MAX_PRODUCERS &&
        power_of_two(config->ingress_capacity_per_producer) &&
        power_of_two(config->reorder_capacity) &&
        config->expected_packets != 0u &&
        config->expected_packets <
            FK_EXACT_IDENTITY_SEQUENCER_MAX_PACKETS;
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

static bool align_offset(size_t &offset, size_t alignment) {
    const size_t remainder = offset % alignment;
    return remainder == 0u ||
        checked_add(offset, alignment - remainder);
}

static bool add_region(
        size_t &offset,
        size_t count,
        size_t element_size,
        size_t alignment) {
    size_t bytes = 0u;
    return align_offset(offset, alignment) &&
        checked_multiply(count, element_size, bytes) &&
        checked_add(offset, bytes);
}

template <typename T>
static T *take_region(
        uintptr_t &cursor, uintptr_t end, size_t count) {
    const uintptr_t remainder = cursor % alignof(T);
    const uintptr_t adjustment = remainder == 0u
        ? 0u : alignof(T) - remainder;
    if (cursor > end || adjustment > end - cursor)
        return nullptr;
    cursor += adjustment;
    size_t bytes = 0u;
    if (!checked_multiply(count, sizeof(T), bytes) ||
        cursor > end || bytes > end - cursor)
        return nullptr;
    T *result = reinterpret_cast<T *>(cursor);
    cursor += bytes;
    return result;
}

static size_t required_bytes(
        const fk_exact_identity_sequencer_config *config) {
    if (!valid_config(config))
        return 0u;
    size_t bytes = alignof(std::max_align_t) - 1u;
    size_t cell_count = 0u;
    if (!checked_multiply(
            config->producer_count,
            config->ingress_capacity_per_producer,
            cell_count) ||
        !add_region(bytes, 1u, sizeof(State), alignof(State)) ||
        !add_region(
            bytes,
            config->producer_count,
            sizeof(ProducerQueue),
            alignof(ProducerQueue)) ||
        !add_region(
            bytes,
            cell_count,
            sizeof(QueueCell),
            alignof(QueueCell)) ||
        !add_region(
            bytes,
            config->reorder_capacity,
            sizeof(ReorderSlot),
            alignof(ReorderSlot)))
        return 0u;
    return bytes;
}

static void set_error(
        char *error, size_t capacity, const char *message) {
    if (error != nullptr && capacity != 0u)
        std::snprintf(error, capacity, "%s", message);
}

static void update_peak(
        std::atomic<uint64_t> &peak, uint64_t candidate) {
    uint64_t observed = peak.load(std::memory_order_relaxed);
    while (candidate > observed &&
           !peak.compare_exchange_weak(
               observed,
               candidate,
               std::memory_order_relaxed,
               std::memory_order_relaxed)) {
    }
}

static bool packet_shape_valid(
        const fk_exact_identity_packet &packet,
        uint16_t producer_index) {
    return packet.packet_handle != 0u &&
        packet.physical_ingress_timestamp_ns != 0u &&
        packet.captured_length != 0u &&
        packet.wire_length >= packet.captured_length &&
        packet.ingress_worker == producer_index &&
        packet.reserved == 0u;
}

static bool queue_peek(
        const ProducerQueue &queue,
        fk_exact_identity_packet &packet) {
    const uint64_t head = queue.head.load(std::memory_order_relaxed);
    const uint64_t tail = queue.tail.load(std::memory_order_acquire);
    if (head == tail)
        return false;
    packet = queue.cells[head & queue.mask].packet;
    return true;
}

static bool queue_pop(
        ProducerQueue &queue,
        fk_exact_identity_packet &packet) {
    const uint64_t head = queue.head.load(std::memory_order_relaxed);
    const uint64_t tail = queue.tail.load(std::memory_order_acquire);
    if (head == tail)
        return false;
    packet = queue.cells[head & queue.mask].packet;
    queue.head.store(head + 1u, std::memory_order_release);
    return true;
}

static bool all_producers_closed(const State &state) {
    return state.closed_producers.load(std::memory_order_acquire) ==
        state.config.producer_count;
}

static bool all_ingress_empty(const State &state) {
    return state.ingress_depth.load(std::memory_order_acquire) == 0u;
}

static bool set_terminal(
        State &state, fk_exact_identity_terminal_reason reason) {
    uint8_t expected = FK_EXACT_IDENTITY_TERMINAL_NONE;
    return state.terminal_reason.compare_exchange_strong(
        expected,
        static_cast<uint8_t>(reason),
        std::memory_order_acq_rel,
        std::memory_order_acquire);
}

static fk_exact_identity_poll_result release_ready(
        State &state,
        fk_exact_identity_packet *packet) {
    const uint64_t next = state.next_sequence.load(
        std::memory_order_relaxed);
    ReorderSlot &slot = state.reorder[
        static_cast<uint32_t>(next) &
        (state.config.reorder_capacity - 1u)];
    if (slot.occupied == 0u ||
        slot.packet.packet_sequence != next)
        return FK_EXACT_IDENTITY_POLL_IDLE;
    const bool initialized = state.semantic_time_initialized.load(
        std::memory_order_relaxed);
    const uint64_t previous =
        state.last_released_semantic_timestamp_ns.load(
            std::memory_order_relaxed);
    if (initialized && slot.packet.semantic_timestamp_ns < previous) {
        state.semantic_time_regressions.fetch_add(
            1u, std::memory_order_relaxed);
        (void)set_terminal(
            state, FK_EXACT_IDENTITY_TERMINAL_TIME_REGRESSION);
        return FK_EXACT_IDENTITY_POLL_TERMINAL;
    }
    *packet = slot.packet;
    slot.occupied = 0u;
    state.reorder_depth.fetch_sub(1u, std::memory_order_relaxed);
    state.last_released_semantic_timestamp_ns.store(
        packet->semantic_timestamp_ns, std::memory_order_relaxed);
    state.semantic_time_initialized.store(
        true, std::memory_order_relaxed);
    state.next_sequence.store(next + 1u, std::memory_order_release);
    state.ordered_released_packets.fetch_add(
        1u, std::memory_order_relaxed);
    return FK_EXACT_IDENTITY_POLL_RELEASED;
}

static uint64_t failure_count(const State &state) {
    return
        state.invalid_submissions.load(std::memory_order_relaxed) +
        state.out_of_range_submissions.load(std::memory_order_relaxed) +
        state.queue_full_rejections.load(std::memory_order_relaxed) +
        state.closed_producer_rejections.load(std::memory_order_relaxed) +
        state.aborted_rejections.load(std::memory_order_relaxed) +
        state.invalid_close_attempts.load(std::memory_order_relaxed) +
        state.duplicate_sequences.load(std::memory_order_relaxed) +
        state.window_overflows.load(std::memory_order_relaxed) +
        state.slot_conflicts.load(std::memory_order_relaxed) +
        state.semantic_time_regressions.load(std::memory_order_relaxed) +
        state.terminal_gaps.load(std::memory_order_relaxed) +
        state.abort_calls.load(std::memory_order_relaxed);
}

static uint64_t owned_packets(const State &state) {
    const uint64_t accepted = state.accepted_packets.load(
        std::memory_order_acquire);
    const uint64_t released = state.ordered_released_packets.load(
        std::memory_order_acquire);
    const uint64_t drained = state.abort_drained_packets.load(
        std::memory_order_acquire);
    if (released > accepted || drained > accepted - released)
        return UINT64_MAX;
    return accepted - released - drained;
}

}  // namespace

extern "C" {

size_t fk_exact_identity_sequencer_storage_bytes(
        const fk_exact_identity_sequencer_config *config) {
    return required_bytes(config);
}

fk_exact_identity_sequencer *
fk_exact_identity_sequencer_initialize(
        void *storage,
        size_t storage_bytes,
        const fk_exact_identity_sequencer_config *config,
        char *error,
        size_t error_capacity) {
    set_error(error, error_capacity, "");
    const size_t required = required_bytes(config);
    if (storage == nullptr || required == 0u ||
        storage_bytes < required) {
        set_error(
            error, error_capacity,
            "invalid exact identity sequencer storage or configuration");
        return nullptr;
    }
    const uintptr_t start = reinterpret_cast<uintptr_t>(storage);
    if (storage_bytes >
        std::numeric_limits<uintptr_t>::max() - start) {
        set_error(
            error, error_capacity,
            "exact identity sequencer storage overflows address space");
        return nullptr;
    }
    const uintptr_t end = start + storage_bytes;
    uintptr_t cursor = start;
    State *state = take_region<State>(cursor, end, 1u);
    ProducerQueue *queues = take_region<ProducerQueue>(
        cursor, end, config->producer_count);
    size_t cell_count = 0u;
    (void)checked_multiply(
        config->producer_count,
        config->ingress_capacity_per_producer,
        cell_count);
    QueueCell *cells = take_region<QueueCell>(
        cursor, end, cell_count);
    ReorderSlot *reorder = take_region<ReorderSlot>(
        cursor, end, config->reorder_capacity);
    if (state == nullptr || queues == nullptr || cells == nullptr ||
        reorder == nullptr) {
        set_error(
            error, error_capacity,
            "exact identity sequencer placement regions do not fit");
        return nullptr;
    }
    state = new (state) State{};
    state->config = *config;
    state->queues = queues;
    state->reorder = reorder;
    state->reserved_bytes = required;
    for (uint16_t producer = 0u;
         producer < config->producer_count; ++producer) {
        ProducerQueue *queue = new (&queues[producer]) ProducerQueue{};
        queue->cells = cells +
            static_cast<size_t>(producer) *
                config->ingress_capacity_per_producer;
        queue->mask = config->ingress_capacity_per_producer - 1u;
        for (uint32_t index = 0u;
             index < config->ingress_capacity_per_producer; ++index)
            new (&queue->cells[index]) QueueCell{};
    }
    for (uint32_t index = 0u;
         index < config->reorder_capacity; ++index)
        new (&reorder[index]) ReorderSlot{};
    if (!state->queues[0].head.is_lock_free() ||
        !state->queues[0].closed.is_lock_free() ||
        !state->closed_producers.is_lock_free() ||
        !state->terminal_reason.is_lock_free() ||
        !state->accepted_packets.is_lock_free()) {
        for (uint32_t index = 0u;
             index < config->reorder_capacity; ++index)
            reorder[index].~ReorderSlot();
        for (uint16_t producer = 0u;
             producer < config->producer_count; ++producer) {
            ProducerQueue &queue = queues[producer];
            for (uint32_t index = 0u;
                 index < config->ingress_capacity_per_producer; ++index)
                queue.cells[index].~QueueCell();
            queue.~ProducerQueue();
        }
        state->~State();
        set_error(
            error, error_capacity,
            "exact identity sequencer requires lock-free atomics");
        return nullptr;
    }
    state->magic = kMagic;
    return reinterpret_cast<fk_exact_identity_sequencer *>(state);
}

bool fk_exact_identity_sequencer_destroy(
        fk_exact_identity_sequencer *sequencer) {
    if (sequencer == nullptr)
        return true;
    State &state = *implementation(sequencer);
    if (state.magic != kMagic || !all_producers_closed(state) ||
        owned_packets(state) != 0u)
        return false;
    state.magic = 0u;
    for (uint16_t producer = 0u;
         producer < state.config.producer_count; ++producer) {
        ProducerQueue &queue = state.queues[producer];
        for (uint32_t index = 0u;
             index < state.config.ingress_capacity_per_producer; ++index)
            queue.cells[index].~QueueCell();
        queue.~ProducerQueue();
    }
    for (uint32_t index = 0u;
         index < state.config.reorder_capacity; ++index)
        state.reorder[index].~ReorderSlot();
    state.~State();
    return true;
}

fk_exact_identity_submit_result fk_exact_identity_sequencer_submit(
        fk_exact_identity_sequencer *sequencer,
        uint16_t producer_index,
        const fk_exact_identity_packet *packet) {
    if (sequencer == nullptr)
        return FK_EXACT_IDENTITY_SUBMIT_INVALID;
    State &state = *implementation(sequencer);
    if (state.magic != kMagic)
        return FK_EXACT_IDENTITY_SUBMIT_INVALID;
    state.submit_attempts.fetch_add(1u, std::memory_order_relaxed);
    if (packet == nullptr || producer_index >= state.config.producer_count ||
        !packet_shape_valid(*packet, producer_index)) {
        state.invalid_submissions.fetch_add(
            1u, std::memory_order_relaxed);
        return FK_EXACT_IDENTITY_SUBMIT_INVALID;
    }
    if (packet->packet_sequence >= state.config.expected_packets) {
        state.out_of_range_submissions.fetch_add(
            1u, std::memory_order_relaxed);
        return FK_EXACT_IDENTITY_SUBMIT_OUT_OF_RANGE;
    }
    ProducerQueue &queue = state.queues[producer_index];
    if (queue.closed.load(std::memory_order_acquire)) {
        state.closed_producer_rejections.fetch_add(
            1u, std::memory_order_relaxed);
        return FK_EXACT_IDENTITY_SUBMIT_PRODUCER_CLOSED;
    }
    if (state.aborted.load(std::memory_order_acquire) ||
        state.terminal_reason.load(std::memory_order_acquire) !=
            FK_EXACT_IDENTITY_TERMINAL_NONE) {
        state.aborted_rejections.fetch_add(
            1u, std::memory_order_relaxed);
        return FK_EXACT_IDENTITY_SUBMIT_ABORTED;
    }
    const uint64_t tail = queue.tail.load(std::memory_order_relaxed);
    const uint64_t head = queue.head.load(std::memory_order_acquire);
    if (tail - head >= state.config.ingress_capacity_per_producer) {
        state.queue_full_rejections.fetch_add(
            1u, std::memory_order_relaxed);
        return FK_EXACT_IDENTITY_SUBMIT_QUEUE_FULL;
    }
    queue.cells[tail & queue.mask].packet = *packet;
    state.accepted_packets.fetch_add(1u, std::memory_order_relaxed);
    const uint64_t depth = state.ingress_depth.fetch_add(
        1u, std::memory_order_relaxed) + 1u;
    update_peak(state.peak_ingress_depth, depth);
    queue.tail.store(tail + 1u, std::memory_order_release);
    return FK_EXACT_IDENTITY_SUBMIT_ACCEPTED;
}

bool fk_exact_identity_sequencer_close_producer(
        fk_exact_identity_sequencer *sequencer,
        uint16_t producer_index) {
    if (sequencer == nullptr)
        return false;
    State &state = *implementation(sequencer);
    if (state.magic != kMagic)
        return false;
    if (producer_index >= state.config.producer_count) {
        state.invalid_close_attempts.fetch_add(
            1u, std::memory_order_relaxed);
        return false;
    }
    ProducerQueue &queue = state.queues[producer_index];
    bool expected = false;
    if (!queue.closed.compare_exchange_strong(
            expected,
            true,
            std::memory_order_release,
            std::memory_order_relaxed)) {
        state.invalid_close_attempts.fetch_add(
            1u, std::memory_order_relaxed);
        return false;
    }
    state.closed_producers.fetch_add(1u, std::memory_order_release);
    return true;
}

fk_exact_identity_poll_result fk_exact_identity_sequencer_poll(
        fk_exact_identity_sequencer *sequencer,
        fk_exact_identity_packet *packet) {
    if (sequencer == nullptr || packet == nullptr)
        return FK_EXACT_IDENTITY_POLL_INVALID;
    State &state = *implementation(sequencer);
    if (state.magic != kMagic)
        return FK_EXACT_IDENTITY_POLL_INVALID;
    if (state.terminal_reason.load(std::memory_order_acquire) !=
        FK_EXACT_IDENTITY_TERMINAL_NONE)
        return FK_EXACT_IDENTITY_POLL_TERMINAL;

    const fk_exact_identity_poll_result ready = release_ready(
        state, packet);
    if (ready != FK_EXACT_IDENTITY_POLL_IDLE)
        return ready;

    bool found = false;
    uint16_t selected = 0u;
    fk_exact_identity_packet selected_packet{};
    for (uint16_t producer = 0u;
         producer < state.config.producer_count; ++producer) {
        fk_exact_identity_packet candidate{};
        if (!queue_peek(state.queues[producer], candidate))
            continue;
        if (!found ||
            candidate.packet_sequence < selected_packet.packet_sequence ||
            (candidate.packet_sequence == selected_packet.packet_sequence &&
             producer < selected)) {
            found = true;
            selected = producer;
            selected_packet = candidate;
        }
    }

    const uint64_t next = state.next_sequence.load(
        std::memory_order_relaxed);
    if (!found) {
        if (all_producers_closed(state) && all_ingress_empty(state)) {
            if (next == state.config.expected_packets &&
                state.reorder_depth.load(std::memory_order_relaxed) == 0u)
                return FK_EXACT_IDENTITY_POLL_COMPLETE;
            state.terminal_gaps.fetch_add(
                1u, std::memory_order_relaxed);
            (void)set_terminal(
                state, FK_EXACT_IDENTITY_TERMINAL_GAP);
            return FK_EXACT_IDENTITY_POLL_TERMINAL;
        }
        return FK_EXACT_IDENTITY_POLL_IDLE;
    }

    if (selected_packet.packet_sequence < next) {
        state.duplicate_sequences.fetch_add(
            1u, std::memory_order_relaxed);
        (void)set_terminal(
            state, FK_EXACT_IDENTITY_TERMINAL_DUPLICATE);
        return FK_EXACT_IDENTITY_POLL_TERMINAL;
    }
    const uint64_t distance = selected_packet.packet_sequence - next;
    if (distance >= state.config.reorder_capacity) {
        if (!all_producers_closed(state))
            return FK_EXACT_IDENTITY_POLL_IDLE;
        state.window_overflows.fetch_add(
            1u, std::memory_order_relaxed);
        (void)set_terminal(
            state, FK_EXACT_IDENTITY_TERMINAL_WINDOW_OVERFLOW);
        return FK_EXACT_IDENTITY_POLL_TERMINAL;
    }
    ReorderSlot &slot = state.reorder[
        static_cast<uint32_t>(selected_packet.packet_sequence) &
        (state.config.reorder_capacity - 1u)];
    if (slot.occupied != 0u) {
        if (slot.packet.packet_sequence ==
            selected_packet.packet_sequence) {
            state.duplicate_sequences.fetch_add(
                1u, std::memory_order_relaxed);
            (void)set_terminal(
                state, FK_EXACT_IDENTITY_TERMINAL_DUPLICATE);
        } else {
            state.slot_conflicts.fetch_add(
                1u, std::memory_order_relaxed);
            (void)set_terminal(
                state, FK_EXACT_IDENTITY_TERMINAL_SLOT_CONFLICT);
        }
        return FK_EXACT_IDENTITY_POLL_TERMINAL;
    }
    fk_exact_identity_packet dequeued{};
    if (!queue_pop(state.queues[selected], dequeued) ||
        dequeued.packet_handle != selected_packet.packet_handle ||
        dequeued.packet_sequence != selected_packet.packet_sequence) {
        state.slot_conflicts.fetch_add(
            1u, std::memory_order_relaxed);
        (void)set_terminal(
            state, FK_EXACT_IDENTITY_TERMINAL_SLOT_CONFLICT);
        return FK_EXACT_IDENTITY_POLL_TERMINAL;
    }
    state.ingress_depth.fetch_sub(1u, std::memory_order_relaxed);
    slot.packet = dequeued;
    slot.occupied = 1u;
    const uint64_t reorder_depth = state.reorder_depth.fetch_add(
        1u, std::memory_order_relaxed) + 1u;
    update_peak(state.peak_reorder_depth, reorder_depth);
    return release_ready(state, packet);
}

bool fk_exact_identity_sequencer_abort(
        fk_exact_identity_sequencer *sequencer) {
    if (sequencer == nullptr)
        return false;
    State &state = *implementation(sequencer);
    if (state.magic != kMagic)
        return false;
    const bool first = !state.aborted.exchange(
        true, std::memory_order_acq_rel);
    if (first) {
        state.abort_calls.fetch_add(1u, std::memory_order_relaxed);
        (void)set_terminal(
            state, FK_EXACT_IDENTITY_TERMINAL_ABORTED);
    }
    return first;
}

bool fk_exact_identity_sequencer_drain_next(
        fk_exact_identity_sequencer *sequencer,
        fk_exact_identity_packet *packet) {
    if (sequencer == nullptr || packet == nullptr)
        return false;
    State &state = *implementation(sequencer);
    if (state.magic != kMagic ||
        state.terminal_reason.load(std::memory_order_acquire) ==
            FK_EXACT_IDENTITY_TERMINAL_NONE)
        return false;
    for (uint32_t scanned = 0u;
         scanned < state.config.reorder_capacity; ++scanned) {
        const uint32_t index = state.drain_reorder_cursor++ &
            (state.config.reorder_capacity - 1u);
        ReorderSlot &slot = state.reorder[index];
        if (slot.occupied == 0u)
            continue;
        *packet = slot.packet;
        slot.occupied = 0u;
        state.reorder_depth.fetch_sub(1u, std::memory_order_relaxed);
        state.abort_drained_packets.fetch_add(
            1u, std::memory_order_relaxed);
        return true;
    }
    for (uint16_t scanned = 0u;
         scanned < state.config.producer_count; ++scanned) {
        const uint16_t producer = static_cast<uint16_t>(
            state.drain_queue_cursor++ % state.config.producer_count);
        if (!queue_pop(state.queues[producer], *packet))
            continue;
        state.ingress_depth.fetch_sub(1u, std::memory_order_relaxed);
        state.abort_drained_packets.fetch_add(
            1u, std::memory_order_relaxed);
        return true;
    }
    return false;
}

bool fk_exact_identity_sequencer_drain_complete(
        const fk_exact_identity_sequencer *sequencer) {
    if (sequencer == nullptr)
        return false;
    const State &state = *implementation(sequencer);
    return state.magic == kMagic &&
        state.terminal_reason.load(std::memory_order_acquire) !=
            FK_EXACT_IDENTITY_TERMINAL_NONE &&
        all_producers_closed(state) &&
        state.ingress_depth.load(std::memory_order_acquire) == 0u &&
        state.reorder_depth.load(std::memory_order_acquire) == 0u &&
        owned_packets(state) == 0u;
}

bool fk_exact_identity_sequencer_get_stats(
        const fk_exact_identity_sequencer *sequencer,
        fk_exact_identity_sequencer_stats *stats) {
    if (sequencer == nullptr || stats == nullptr)
        return false;
    const State &state = *implementation(sequencer);
    if (state.magic != kMagic)
        return false;
    *stats = {};
    stats->expected_packets = state.config.expected_packets;
    stats->submit_attempts = state.submit_attempts.load(
        std::memory_order_relaxed);
    stats->accepted_packets = state.accepted_packets.load(
        std::memory_order_acquire);
    stats->ordered_released_packets =
        state.ordered_released_packets.load(std::memory_order_acquire);
    stats->abort_drained_packets = state.abort_drained_packets.load(
        std::memory_order_acquire);
    stats->invalid_submissions = state.invalid_submissions.load(
        std::memory_order_relaxed);
    stats->out_of_range_submissions =
        state.out_of_range_submissions.load(std::memory_order_relaxed);
    stats->queue_full_rejections = state.queue_full_rejections.load(
        std::memory_order_relaxed);
    stats->closed_producer_rejections =
        state.closed_producer_rejections.load(std::memory_order_relaxed);
    stats->aborted_rejections = state.aborted_rejections.load(
        std::memory_order_relaxed);
    stats->invalid_close_attempts = state.invalid_close_attempts.load(
        std::memory_order_relaxed);
    stats->duplicate_sequences = state.duplicate_sequences.load(
        std::memory_order_relaxed);
    stats->window_overflows = state.window_overflows.load(
        std::memory_order_relaxed);
    stats->slot_conflicts = state.slot_conflicts.load(
        std::memory_order_relaxed);
    stats->semantic_time_regressions =
        state.semantic_time_regressions.load(std::memory_order_relaxed);
    stats->terminal_gaps = state.terminal_gaps.load(
        std::memory_order_relaxed);
    stats->abort_calls = state.abort_calls.load(
        std::memory_order_relaxed);
    stats->next_sequence = state.next_sequence.load(
        std::memory_order_acquire);
    stats->last_released_semantic_timestamp_ns =
        state.last_released_semantic_timestamp_ns.load(
            std::memory_order_relaxed);
    stats->ingress_depth = state.ingress_depth.load(
        std::memory_order_acquire);
    stats->peak_ingress_depth = state.peak_ingress_depth.load(
        std::memory_order_relaxed);
    stats->reorder_depth = state.reorder_depth.load(
        std::memory_order_acquire);
    stats->peak_reorder_depth = state.peak_reorder_depth.load(
        std::memory_order_relaxed);
    stats->owned_packets = owned_packets(state);
    stats->reserved_bytes = state.reserved_bytes;
    stats->producer_count = state.config.producer_count;
    stats->closed_producers = state.closed_producers.load(
        std::memory_order_acquire);
    stats->ingress_capacity_per_producer =
        state.config.ingress_capacity_per_producer;
    stats->reorder_capacity = state.config.reorder_capacity;
    stats->terminal_reason =
        static_cast<fk_exact_identity_terminal_reason>(
            state.terminal_reason.load(std::memory_order_acquire));
    stats->semantic_time_initialized =
        state.semantic_time_initialized.load(std::memory_order_relaxed);
    stats->all_producers_closed = all_producers_closed(state);
    stats->sequence_complete =
        stats->next_sequence == stats->expected_packets;
    stats->timestamp_complete = stats->sequence_complete &&
        stats->semantic_time_initialized &&
        stats->ordered_released_packets == stats->expected_packets &&
        stats->semantic_time_regressions == 0u;
    stats->aborted = state.aborted.load(std::memory_order_acquire);
    stats->drain_complete =
        fk_exact_identity_sequencer_drain_complete(sequencer);
    stats->formal_complete =
        stats->all_producers_closed && stats->sequence_complete &&
        stats->timestamp_complete && !stats->aborted &&
        stats->terminal_reason == FK_EXACT_IDENTITY_TERMINAL_NONE &&
        stats->accepted_packets == stats->expected_packets &&
        stats->ordered_released_packets == stats->expected_packets &&
        stats->abort_drained_packets == 0u &&
        stats->ingress_depth == 0u && stats->reorder_depth == 0u &&
        stats->owned_packets == 0u && failure_count(state) == 0u;
    return true;
}

bool fk_exact_identity_sequencer_formal_complete(
        const fk_exact_identity_sequencer *sequencer) {
    fk_exact_identity_sequencer_stats stats{};
    return fk_exact_identity_sequencer_get_stats(
        sequencer, &stats) && stats.formal_complete;
}

}  // extern "C"
