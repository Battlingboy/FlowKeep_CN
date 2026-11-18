#include "fk_trace_sequence_audit.h"

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <limits>
#include <new>

namespace {

constexpr uint64_t kMagic = UINT64_C(0x464b534551415531);  // "FKSEQAU1"
constexpr uint64_t kMaximumSequences = UINT64_C(1) << 40u;

struct State {
    uint64_t magic;
    uint64_t expected_sequences;
    uint64_t word_count;
    uint64_t bitmap_bytes;
    uint64_t reserved_bytes;
    std::atomic<uint64_t> unique_sequences;
    std::atomic<uint64_t> duplicate_sequences;
    std::atomic<uint64_t> out_of_range_sequences;
    std::atomic<uint64_t> contiguous_prefix_sequences;
    std::atomic<uint64_t> lowest_sequence;
    std::atomic<uint64_t> highest_sequence;
    std::atomic<uint64_t> *words;
};

static State *implementation(fk_trace_sequence_audit *audit) {
    return reinterpret_cast<State *>(audit);
}

static const State *implementation(
        const fk_trace_sequence_audit *audit) {
    return reinterpret_cast<const State *>(audit);
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

}  // namespace

extern "C" {

size_t fk_trace_sequence_audit_storage_bytes(
        uint64_t expected_sequences) {
    if (expected_sequences == 0u ||
        expected_sequences >= kMaximumSequences ||
        expected_sequences > UINT64_MAX - 63u)
        return 0u;
    const uint64_t word_count64 =
        (expected_sequences + 63u) / 64u;
    if (word_count64 >
        static_cast<uint64_t>(
            std::numeric_limits<size_t>::max()))
        return 0u;
    size_t bytes = alignof(std::max_align_t) - 1u;
    size_t bitmap_bytes = 0u;
    if (!align_offset(bytes, alignof(State)) ||
        !checked_add(bytes, sizeof(State)) ||
        !align_offset(bytes, alignof(std::atomic<uint64_t>)) ||
        !checked_multiply(
            static_cast<size_t>(word_count64),
            sizeof(std::atomic<uint64_t>),
            bitmap_bytes) ||
        !checked_add(bytes, bitmap_bytes))
        return 0u;
    return bytes;
}

fk_trace_sequence_audit *fk_trace_sequence_audit_init(
        void *storage,
        size_t storage_bytes,
        uint64_t expected_sequences,
        char *error,
        size_t error_capacity) {
    set_error(error, error_capacity, "");
    const size_t required =
        fk_trace_sequence_audit_storage_bytes(expected_sequences);
    if (storage == nullptr || required == 0u ||
        storage_bytes < required) {
        set_error(
            error,
            error_capacity,
            "invalid trace-sequence audit storage or capacity");
        return nullptr;
    }
    const uintptr_t start = reinterpret_cast<uintptr_t>(storage);
    if (storage_bytes >
        std::numeric_limits<uintptr_t>::max() - start) {
        set_error(
            error, error_capacity,
            "trace-sequence audit storage overflows");
        return nullptr;
    }
    const uintptr_t end = start + storage_bytes;
    const uintptr_t state_address =
        align_pointer(start, alignof(State));
    if (state_address > end ||
        sizeof(State) > end - state_address) {
        set_error(
            error, error_capacity,
            "trace-sequence audit state does not fit");
        return nullptr;
    }
    State *state =
        new (reinterpret_cast<void *>(state_address)) State{};
    uintptr_t cursor = state_address + sizeof(State);
    cursor = align_pointer(
        cursor, alignof(std::atomic<uint64_t>));
    const uint64_t word_count =
        (expected_sequences + 63u) / 64u;
    const size_t bitmap_bytes =
        static_cast<size_t>(word_count) *
        sizeof(std::atomic<uint64_t>);
    if (cursor > end || bitmap_bytes > end - cursor) {
        set_error(
            error, error_capacity,
            "trace-sequence audit bitmap does not fit");
        return nullptr;
    }
    state->expected_sequences = expected_sequences;
    state->word_count = word_count;
    state->bitmap_bytes = bitmap_bytes;
    state->reserved_bytes = required;
    state->unique_sequences.store(0u, std::memory_order_relaxed);
    state->duplicate_sequences.store(0u, std::memory_order_relaxed);
    state->out_of_range_sequences.store(0u, std::memory_order_relaxed);
    state->contiguous_prefix_sequences.store(
        0u, std::memory_order_relaxed);
    state->lowest_sequence.store(
        UINT64_MAX, std::memory_order_relaxed);
    state->highest_sequence.store(0u, std::memory_order_relaxed);
    state->words =
        reinterpret_cast<std::atomic<uint64_t> *>(cursor);
    for (uint64_t index = 0u; index < word_count; ++index)
        new (&state->words[index])
            std::atomic<uint64_t>(0u);
    if (!state->words[0].is_lock_free()) {
        set_error(
            error, error_capacity,
            "trace-sequence audit requires lock-free uint64 atomics");
        return nullptr;
    }
    state->magic = kMagic;
    return reinterpret_cast<fk_trace_sequence_audit *>(state);
}

bool fk_trace_sequence_audit_observe(
        fk_trace_sequence_audit *audit,
        uint64_t sequence) {
    if (audit == nullptr)
        return false;
    State &state = *implementation(audit);
    if (state.magic != kMagic)
        return false;
    if (sequence >= state.expected_sequences) {
        state.out_of_range_sequences.fetch_add(
            1u, std::memory_order_relaxed);
        return false;
    }
    const uint64_t word = sequence >> 6u;
    const uint64_t bit = UINT64_C(1) << (sequence & 63u);
    const uint64_t previous = state.words[word].fetch_or(
        bit, std::memory_order_release);
    if ((previous & bit) != 0u) {
        state.duplicate_sequences.fetch_add(
            1u, std::memory_order_relaxed);
        return false;
    }
    /* The bitmap is the authoritative uniqueness evidence.  Do not also
     * bounce three global scalar cache lines (count/minimum/maximum) between
     * every RX or state worker for every packet.  get_stats() derives those
     * terminal receipts exactly from the lossless bitmap after the workers
     * have closed. */
    return true;
}

bool fk_trace_sequence_audit_observe_batch(
        fk_trace_sequence_audit *audit,
        const uint64_t *sequences,
        uint32_t count) {
    if (audit == nullptr || sequences == nullptr || count == 0u)
        return false;
    State &state = *implementation(audit);
    if (state.magic != kMagic)
        return false;
    for (uint32_t index = 0u; index < count; ++index) {
        if (sequences[index] >= state.expected_sequences) {
            state.out_of_range_sequences.fetch_add(
                1u, std::memory_order_relaxed);
            return false;
        }
        if (index != 0u && sequences[index] <= sequences[index - 1u]) {
            if (sequences[index] == sequences[index - 1u]) {
                state.duplicate_sequences.fetch_add(
                    1u, std::memory_order_relaxed);
            }
            return false;
        }
    }
    bool valid = true;
    uint32_t cursor = 0u;
    while (cursor < count) {
        const uint64_t word_index = sequences[cursor] >> 6u;
        uint64_t bits = 0u;
        do {
            bits |= UINT64_C(1) << (sequences[cursor] & 63u);
            ++cursor;
        } while (cursor < count &&
                 (sequences[cursor] >> 6u) == word_index);
        const uint64_t previous = state.words[word_index].fetch_or(
            bits, std::memory_order_release);
        const uint64_t duplicates = previous & bits;
        if (duplicates != 0u) {
            state.duplicate_sequences.fetch_add(
                static_cast<uint64_t>(__builtin_popcountll(duplicates)),
                std::memory_order_relaxed);
            valid = false;
        }
    }
    return valid;
}

bool fk_trace_sequence_audit_advance_contiguous(
        fk_trace_sequence_audit *audit,
        uint64_t *contiguous_prefix_sequences) {
    if (audit == nullptr || contiguous_prefix_sequences == nullptr)
        return false;
    State &state = *implementation(audit);
    if (state.magic != kMagic)
        return false;
    uint64_t cursor = state.contiguous_prefix_sequences.load(
        std::memory_order_relaxed);
    while (cursor < state.expected_sequences) {
        const uint64_t word_index = cursor >> 6u;
        const uint32_t bit_offset =
            static_cast<uint32_t>(cursor & 63u);
        uint64_t word = state.words[word_index].load(
            std::memory_order_acquire);
        if (bit_offset != 0u)
            word |= (UINT64_C(1) << bit_offset) - 1u;
        if (word == UINT64_MAX) {
            const uint64_t next = (word_index + 1u) << 6u;
            cursor = next < state.expected_sequences
                ? next : state.expected_sequences;
            continue;
        }
        const uint32_t first_missing =
            static_cast<uint32_t>(__builtin_ctzll(~word));
        const uint64_t missing_sequence =
            (word_index << 6u) + first_missing;
        cursor = missing_sequence < state.expected_sequences
            ? missing_sequence : state.expected_sequences;
        break;
    }
    state.contiguous_prefix_sequences.store(
        cursor, std::memory_order_release);
    *contiguous_prefix_sequences = cursor;
    return true;
}

bool fk_trace_sequence_audit_load_word(
        const fk_trace_sequence_audit *audit,
        uint64_t word_index, uint64_t *word) {
    if (audit == nullptr || word == nullptr)
        return false;
    const State &state = *implementation(audit);
    if (state.magic != kMagic || word_index >= state.word_count)
        return false;
    *word = state.words[word_index].load(std::memory_order_acquire);
    return true;
}

bool fk_trace_sequence_audit_advance_resolved(
        const fk_trace_sequence_audit *audit,
        const fk_trace_sequence_audit *losses,
        uint64_t *resolved_prefix) {
    if (audit == nullptr || losses == nullptr || resolved_prefix == nullptr)
        return false;
    const State &state = *implementation(audit);
    const State &lost = *implementation(losses);
    if (state.magic != kMagic || lost.magic != kMagic ||
        state.expected_sequences != lost.expected_sequences ||
        *resolved_prefix > state.expected_sequences)
        return false;
    uint64_t cursor = *resolved_prefix;
    while (cursor < state.expected_sequences) {
        const uint64_t index = cursor >> 6u;
        uint64_t word = state.words[index].load(std::memory_order_acquire) |
            lost.words[index].load(std::memory_order_acquire);
        const uint32_t offset = cursor & 63u;
        if (offset != 0u)
            word |= (UINT64_C(1) << offset) - 1u;
        if (word != UINT64_MAX) {
            cursor = (index << 6u) + __builtin_ctzll(~word);
            break;
        }
        cursor = (index + 1u) << 6u;
    }
    *resolved_prefix = cursor < state.expected_sequences
        ? cursor : state.expected_sequences;
    return true;
}

bool fk_trace_sequence_audit_get_stats(
        const fk_trace_sequence_audit *audit,
        fk_trace_sequence_audit_stats *stats) {
    if (audit == nullptr || stats == nullptr)
        return false;
    const State &state = *implementation(audit);
    if (state.magic != kMagic)
        return false;
    std::memset(stats, 0, sizeof(*stats));
    stats->expected_sequences = state.expected_sequences;
    uint64_t unique_sequences = 0u;
    uint64_t lowest_sequence = UINT64_MAX;
    uint64_t highest_sequence = 0u;
    for (uint64_t word_index = 0u;
         word_index < state.word_count; ++word_index) {
        const uint64_t word = state.words[word_index].load(
            std::memory_order_acquire);
        if (word == 0u)
            continue;
        unique_sequences += static_cast<uint64_t>(
            __builtin_popcountll(word));
        const uint64_t word_lowest =
            (word_index << 6u) +
            static_cast<uint64_t>(__builtin_ctzll(word));
        const uint64_t word_highest =
            (word_index << 6u) + 63u -
            static_cast<uint64_t>(__builtin_clzll(word));
        if (word_lowest < lowest_sequence)
            lowest_sequence = word_lowest;
        if (word_highest > highest_sequence)
            highest_sequence = word_highest;
    }
    stats->unique_sequences = unique_sequences;
    stats->duplicate_sequences =
        state.duplicate_sequences.load(std::memory_order_relaxed);
    stats->out_of_range_sequences =
        state.out_of_range_sequences.load(std::memory_order_relaxed);
    stats->contiguous_prefix_sequences =
        state.contiguous_prefix_sequences.load(
            std::memory_order_acquire);
    stats->bitmap_bytes = state.bitmap_bytes;
    stats->reserved_bytes = state.reserved_bytes;
    stats->has_observation = stats->unique_sequences != 0u;
    if (stats->has_observation) {
        stats->lowest_sequence = lowest_sequence;
        stats->highest_sequence = highest_sequence;
        const uint64_t observed_span =
            stats->highest_sequence + 1u;
        stats->internal_gaps_through_highest =
            observed_span >= stats->unique_sequences
            ? observed_span - stats->unique_sequences : 0u;
    }
    stats->total_missing_sequences =
        state.expected_sequences >= stats->unique_sequences
        ? state.expected_sequences - stats->unique_sequences : 0u;
    stats->complete =
        stats->unique_sequences == state.expected_sequences;
    stats->integrity_passed =
        stats->complete &&
        stats->duplicate_sequences == 0u &&
        stats->out_of_range_sequences == 0u;
    return true;
}

}  // extern "C"
