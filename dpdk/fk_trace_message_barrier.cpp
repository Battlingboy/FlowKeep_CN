#include "fk_trace_message_barrier.h"

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <limits>
#include <new>

namespace {

constexpr uint64_t kMagic = UINT64_C(0x464b4d5347425231);  // "FKMSGBR1"
constexpr uint64_t kMaximumPackets = UINT64_C(1) << 40u;
constexpr uint64_t kPacketsPerCompletionWord = 16u;
constexpr uint64_t kPacketsPerIngestedWord = 32u;
constexpr uint8_t kCompletionMarker = UINT8_C(4);
constexpr uint8_t kLossMarker = UINT8_C(8);

struct State {
    uint64_t magic;
    uint64_t expected_packets;
    uint64_t completion_word_count;
    uint64_t ingested_word_count;
    uint64_t completion_bitmap_bytes;
    uint64_t ingested_bitmap_bytes;
    uint64_t reserved_bytes;
    std::atomic<uint64_t> completed_packets;
    std::atomic<uint64_t> duplicate_packet_completions;
    std::atomic<uint64_t> out_of_range_packet_completions;
    std::atomic<uint64_t> invalid_expected_masks;
    uint64_t ready_prefix_packets;
    uint64_t duplicate_ingested_messages;
    uint64_t out_of_range_ingested_messages;
    uint64_t invalid_ingested_masks;
    std::atomic<uint64_t> *completion_words;
    uint64_t *ingested_words;
};

static State *implementation(
        fk_trace_message_barrier *barrier) {
    return reinterpret_cast<State *>(barrier);
}

static const State *implementation(
        const fk_trace_message_barrier *barrier) {
    return reinterpret_cast<const State *>(barrier);
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

static bool align_offset(size_t &value, size_t alignment) {
    const size_t remainder = value % alignment;
    return remainder == 0u ||
        checked_add(value, alignment - remainder);
}

static uintptr_t align_pointer(uintptr_t value, size_t alignment) {
    const uintptr_t remainder = value % alignment;
    return remainder == 0u
        ? value : value + alignment - remainder;
}

static void set_error(
        char *error, size_t capacity, const char *message) {
    if (error != nullptr && capacity != 0u)
        std::snprintf(error, capacity, "%s", message);
}

static uint8_t completion_value(
        const State &state, uint64_t sequence) {
    const uint64_t word =
        state.completion_words[
            sequence / kPacketsPerCompletionWord].load(
                std::memory_order_acquire);
    const uint32_t shift = static_cast<uint32_t>(
        (sequence % kPacketsPerCompletionWord) * 4u);
    return static_cast<uint8_t>((word >> shift) & UINT64_C(0xf));
}

static uint8_t ingested_mask(
        const State &state, uint64_t sequence) {
    const uint64_t word =
        state.ingested_words[
            sequence / kPacketsPerIngestedWord];
    const uint32_t shift = static_cast<uint32_t>(
        (sequence % kPacketsPerIngestedWord) * 2u);
    return static_cast<uint8_t>((word >> shift) & UINT64_C(0x3));
}

static uint32_t popcount2(uint8_t value) {
    return static_cast<uint32_t>(
        (value & UINT8_C(1)) +
        ((value >> 1u) & UINT8_C(1)));
}

}  // namespace

extern "C" {

size_t fk_trace_message_barrier_storage_bytes(
        uint64_t expected_packets) {
    if (expected_packets == 0u ||
        expected_packets >= kMaximumPackets ||
        expected_packets > UINT64_MAX - 31u)
        return 0u;
    const uint64_t completion_words64 =
        (expected_packets + 15u) / 16u;
    const uint64_t ingested_words64 =
        (expected_packets + 31u) / 32u;
    if (completion_words64 >
            static_cast<uint64_t>(
                std::numeric_limits<size_t>::max()) ||
        ingested_words64 >
            static_cast<uint64_t>(
                std::numeric_limits<size_t>::max()))
        return 0u;
    size_t bytes = alignof(std::max_align_t) - 1u;
    size_t completion_bytes = 0u;
    size_t ingested_bytes = 0u;
    if (!align_offset(bytes, alignof(State)) ||
        !checked_add(bytes, sizeof(State)) ||
        !align_offset(bytes, alignof(std::atomic<uint64_t>)) ||
        !checked_multiply(
            static_cast<size_t>(completion_words64),
            sizeof(std::atomic<uint64_t>),
            completion_bytes) ||
        !checked_add(bytes, completion_bytes) ||
        !align_offset(bytes, alignof(uint64_t)) ||
        !checked_multiply(
            static_cast<size_t>(ingested_words64),
            sizeof(uint64_t),
            ingested_bytes) ||
        !checked_add(bytes, ingested_bytes))
        return 0u;
    return bytes;
}

fk_trace_message_barrier *fk_trace_message_barrier_init(
        void *storage,
        size_t storage_bytes,
        uint64_t expected_packets,
        char *error,
        size_t error_capacity) {
    set_error(error, error_capacity, "");
    const size_t required =
        fk_trace_message_barrier_storage_bytes(expected_packets);
    if (storage == nullptr || required == 0u ||
        storage_bytes < required) {
        set_error(
            error,
            error_capacity,
            "invalid trace-message barrier storage or capacity");
        return nullptr;
    }
    const uintptr_t start = reinterpret_cast<uintptr_t>(storage);
    if (storage_bytes >
        std::numeric_limits<uintptr_t>::max() - start) {
        set_error(
            error, error_capacity,
            "trace-message barrier storage overflows");
        return nullptr;
    }
    const uintptr_t end = start + storage_bytes;
    const uintptr_t state_address =
        align_pointer(start, alignof(State));
    if (state_address > end ||
        sizeof(State) > end - state_address) {
        set_error(
            error, error_capacity,
            "trace-message barrier state does not fit");
        return nullptr;
    }
    State *state =
        new (reinterpret_cast<void *>(state_address)) State{};
    uintptr_t cursor = state_address + sizeof(State);
    cursor = align_pointer(
        cursor, alignof(std::atomic<uint64_t>));
    const uint64_t completion_word_count =
        (expected_packets + 15u) / 16u;
    const size_t completion_bytes =
        static_cast<size_t>(completion_word_count) *
        sizeof(std::atomic<uint64_t>);
    if (cursor > end || completion_bytes > end - cursor) {
        set_error(
            error, error_capacity,
            "trace-message completion bitmap does not fit");
        return nullptr;
    }
    state->completion_words =
        reinterpret_cast<std::atomic<uint64_t> *>(cursor);
    cursor += completion_bytes;
    cursor = align_pointer(cursor, alignof(uint64_t));
    const uint64_t ingested_word_count =
        (expected_packets + 31u) / 32u;
    const size_t ingested_bytes =
        static_cast<size_t>(ingested_word_count) *
        sizeof(uint64_t);
    if (cursor > end || ingested_bytes > end - cursor) {
        set_error(
            error, error_capacity,
            "trace-message ingested bitmap does not fit");
        return nullptr;
    }
    state->ingested_words =
        reinterpret_cast<uint64_t *>(cursor);
    for (uint64_t index = 0u;
         index < completion_word_count; ++index)
        new (&state->completion_words[index])
            std::atomic<uint64_t>(0u);
    if (!state->completion_words[0].is_lock_free()) {
        set_error(
            error, error_capacity,
            "trace-message barrier requires lock-free uint64 atomics");
        return nullptr;
    }
    std::memset(
        state->ingested_words, 0, ingested_bytes);
    state->expected_packets = expected_packets;
    state->completion_word_count = completion_word_count;
    state->ingested_word_count = ingested_word_count;
    state->completion_bitmap_bytes = completion_bytes;
    state->ingested_bitmap_bytes = ingested_bytes;
    state->reserved_bytes = required;
    state->completed_packets.store(
        0u, std::memory_order_relaxed);
    state->duplicate_packet_completions.store(
        0u, std::memory_order_relaxed);
    state->out_of_range_packet_completions.store(
        0u, std::memory_order_relaxed);
    state->invalid_expected_masks.store(
        0u, std::memory_order_relaxed);
    state->ready_prefix_packets = 0u;
    state->duplicate_ingested_messages = 0u;
    state->out_of_range_ingested_messages = 0u;
    state->invalid_ingested_masks = 0u;
    state->magic = kMagic;
    return reinterpret_cast<fk_trace_message_barrier *>(state);
}

bool fk_trace_message_barrier_drop_packet(
        fk_trace_message_barrier *barrier, uint64_t packet_sequence) {
    if (barrier == nullptr)
        return false;
    State &state = *implementation(barrier);
    if (state.magic != kMagic || packet_sequence >= state.expected_packets)
        return false;
    const uint64_t index = packet_sequence / kPacketsPerCompletionWord;
    const uint32_t shift = (packet_sequence % kPacketsPerCompletionWord) * 4u;
    const uint64_t previous = state.completion_words[index].fetch_or(
        static_cast<uint64_t>(kLossMarker) << shift, std::memory_order_release);
    if ((previous & (UINT64_C(0xf) << shift)) != 0u) {
        state.duplicate_packet_completions.fetch_add(1u, std::memory_order_relaxed);
        return false;
    }
    return true;
}

bool fk_trace_message_barrier_complete_packet(
        fk_trace_message_barrier *barrier,
        uint64_t packet_sequence,
        uint8_t expected_mask) {
    if (barrier == nullptr)
        return false;
    State &state = *implementation(barrier);
    if (state.magic != kMagic)
        return false;
    if ((expected_mask & ~FK_TRACE_MESSAGE_VALID_MASK) != 0u) {
        state.invalid_expected_masks.fetch_add(
            1u, std::memory_order_relaxed);
        return false;
    }
    if (packet_sequence >= state.expected_packets) {
        state.out_of_range_packet_completions.fetch_add(
            1u, std::memory_order_relaxed);
        return false;
    }
    const uint64_t word_index =
        packet_sequence / kPacketsPerCompletionWord;
    const uint32_t shift = static_cast<uint32_t>(
        (packet_sequence % kPacketsPerCompletionWord) * 4u);
    const uint64_t field_mask = UINT64_C(0xf) << shift;
    const uint64_t encoded = static_cast<uint64_t>(
        kCompletionMarker | expected_mask) << shift;
    /* Each packet owns one initially-zero nibble.  A single atomic OR both
     * publishes that immutable field and returns the prior field for the
     * duplicate check.  This avoids a contended load/CAS retry loop.  The
     * bitmap remains authoritative; get_stats() counts its completion
     * markers after closure instead of serializing all workers through one
     * global completed_packets counter. */
    const uint64_t observed =
        state.completion_words[word_index].fetch_or(
            encoded, std::memory_order_release);
    if ((observed & field_mask) != 0u) {
        state.duplicate_packet_completions.fetch_add(
            1u, std::memory_order_relaxed);
        return false;
    }
    return true;
}

bool fk_trace_message_barrier_complete_zero_mask_batch(
        fk_trace_message_barrier *barrier,
        const uint64_t *packet_sequences,
        uint32_t count) {
    if (barrier == nullptr || packet_sequences == nullptr || count == 0u)
        return false;
    State &state = *implementation(barrier);
    if (state.magic != kMagic)
        return false;
    for (uint32_t index = 0u; index < count; ++index) {
        if (packet_sequences[index] >= state.expected_packets) {
            state.out_of_range_packet_completions.fetch_add(
                1u, std::memory_order_relaxed);
            return false;
        }
        if (index != 0u &&
            packet_sequences[index] <= packet_sequences[index - 1u]) {
            if (packet_sequences[index] == packet_sequences[index - 1u]) {
                state.duplicate_packet_completions.fetch_add(
                    1u, std::memory_order_relaxed);
            }
            return false;
        }
    }
    bool valid = true;
    uint32_t cursor = 0u;
    while (cursor < count) {
        const uint64_t word_index =
            packet_sequences[cursor] / kPacketsPerCompletionWord;
        uint64_t encoded = 0u;
        do {
            const uint32_t shift = static_cast<uint32_t>(
                (packet_sequences[cursor] % kPacketsPerCompletionWord) *
                4u);
            encoded |= static_cast<uint64_t>(kCompletionMarker) << shift;
            ++cursor;
        } while (cursor < count &&
                 packet_sequences[cursor] / kPacketsPerCompletionWord ==
                     word_index);
        const uint64_t previous =
            state.completion_words[word_index].fetch_or(
                encoded, std::memory_order_release);
        uint64_t duplicate_fields = previous & encoded;
        if (duplicate_fields != 0u) {
            uint64_t duplicate_count = 0u;
            while (duplicate_fields != 0u) {
                duplicate_count +=
                    (duplicate_fields & UINT64_C(0xf)) != 0u ? 1u : 0u;
                duplicate_fields >>= 4u;
            }
            state.duplicate_packet_completions.fetch_add(
                duplicate_count, std::memory_order_relaxed);
            valid = false;
        }
    }
    return valid;
}

bool fk_trace_message_barrier_ingest_message(
        fk_trace_message_barrier *barrier,
        uint64_t packet_sequence,
        uint8_t message_mask) {
    if (barrier == nullptr)
        return false;
    State &state = *implementation(barrier);
    if (state.magic != kMagic)
        return false;
    if (message_mask != FK_TRACE_MESSAGE_FLOW_OPEN &&
        message_mask != FK_TRACE_MESSAGE_CHECKPOINT) {
        state.invalid_ingested_masks++;
        return false;
    }
    if (packet_sequence >= state.expected_packets) {
        state.out_of_range_ingested_messages++;
        return false;
    }
    const uint64_t word_index =
        packet_sequence / kPacketsPerIngestedWord;
    const uint32_t shift = static_cast<uint32_t>(
        (packet_sequence % kPacketsPerIngestedWord) * 2u);
    const uint64_t encoded =
        static_cast<uint64_t>(message_mask) << shift;
    if ((state.ingested_words[word_index] & encoded) != 0u) {
        state.duplicate_ingested_messages++;
        return false;
    }
    state.ingested_words[word_index] |= encoded;
    return true;
}

bool fk_trace_message_barrier_advance_ready(
        fk_trace_message_barrier *barrier,
        uint64_t *ready_prefix_packets) {
    if (barrier == nullptr || ready_prefix_packets == nullptr)
        return false;
    State &state = *implementation(barrier);
    if (state.magic != kMagic)
        return false;
    uint64_t cursor = state.ready_prefix_packets;
    while (cursor < state.expected_packets) {
        const uint8_t completion =
            completion_value(state, cursor);
        if ((completion & kLossMarker) != 0u) {
            if (completion != kLossMarker || ingested_mask(state, cursor) != 0u)
                return false;
            ++cursor;
            continue;
        }
        if ((completion & kCompletionMarker) == 0u)
            break;
        const uint8_t expected =
            completion & FK_TRACE_MESSAGE_VALID_MASK;
        if (ingested_mask(state, cursor) != expected)
            break;
        cursor++;
    }
    state.ready_prefix_packets = cursor;
    *ready_prefix_packets = cursor;
    return true;
}

bool fk_trace_message_barrier_get_stats(
        const fk_trace_message_barrier *barrier,
        fk_trace_message_barrier_stats *stats) {
    if (barrier == nullptr || stats == nullptr)
        return false;
    const State &state = *implementation(barrier);
    if (state.magic != kMagic)
        return false;
    std::memset(stats, 0, sizeof(*stats));
    stats->expected_packets = state.expected_packets;
    constexpr uint64_t kCompletionMarkerBits =
        UINT64_C(0x4444444444444444);
    uint64_t completed_packets = 0u;
    for (uint64_t word_index = 0u;
         word_index < state.completion_word_count; ++word_index) {
        const uint64_t word = state.completion_words[word_index].load(
            std::memory_order_acquire);
        completed_packets += static_cast<uint64_t>(
            __builtin_popcountll(word & kCompletionMarkerBits));
        stats->explicitly_dropped_packets += static_cast<uint64_t>(
            __builtin_popcountll(word & UINT64_C(0x8888888888888888)));
    }
    stats->completed_packets = completed_packets;
    stats->ready_prefix_packets =
        state.ready_prefix_packets;
    stats->duplicate_packet_completions =
        state.duplicate_packet_completions.load(
            std::memory_order_relaxed);
    stats->out_of_range_packet_completions =
        state.out_of_range_packet_completions.load(
            std::memory_order_relaxed);
    stats->invalid_expected_masks =
        state.invalid_expected_masks.load(
            std::memory_order_relaxed);
    stats->duplicate_ingested_messages =
        state.duplicate_ingested_messages;
    stats->out_of_range_ingested_messages =
        state.out_of_range_ingested_messages;
    stats->invalid_ingested_masks =
        state.invalid_ingested_masks;
    stats->completion_bitmap_bytes =
        state.completion_bitmap_bytes;
    stats->ingested_bitmap_bytes =
        state.ingested_bitmap_bytes;
    stats->reserved_bytes = state.reserved_bytes;
    for (uint64_t sequence = 0u;
         sequence < state.expected_packets; ++sequence) {
        const uint8_t completion =
            completion_value(state, sequence);
        const uint8_t observed =
            ingested_mask(state, sequence);
        if ((completion & kCompletionMarker) == 0u) {
            if (observed != 0u)
                stats->packets_with_unexpected_messages++;
            stats->ingested_unique_messages +=
                popcount2(observed);
            continue;
        }
        const uint8_t expected =
            completion & FK_TRACE_MESSAGE_VALID_MASK;
        stats->expected_unique_messages +=
            popcount2(expected);
        stats->ingested_unique_messages +=
            popcount2(observed);
        if ((expected & ~observed) != 0u)
            stats->packets_with_missing_messages++;
        if ((observed & ~expected) != 0u)
            stats->packets_with_unexpected_messages++;
    }
    stats->packets_complete =
        stats->completed_packets == stats->expected_packets;
    stats->messages_complete =
        stats->packets_with_missing_messages == 0u &&
        stats->packets_with_unexpected_messages == 0u &&
        stats->expected_unique_messages ==
            stats->ingested_unique_messages;
    stats->integrity_passed =
        stats->packets_complete &&
        stats->messages_complete &&
        stats->ready_prefix_packets ==
            stats->expected_packets &&
        stats->duplicate_packet_completions == 0u &&
        stats->out_of_range_packet_completions == 0u &&
        stats->invalid_expected_masks == 0u &&
        stats->duplicate_ingested_messages == 0u &&
        stats->out_of_range_ingested_messages == 0u &&
        stats->invalid_ingested_masks == 0u;
    return true;
}

}  // extern "C"
