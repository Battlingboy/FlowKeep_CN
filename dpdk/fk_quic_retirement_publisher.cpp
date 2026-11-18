#include "fk_quic_retirement_publisher.h"

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <limits>
#include <new>

namespace {

constexpr uint64_t kMagic = UINT64_C(0x464b515250554231);  // "FKQRPUB1"

struct PublisherState {
    std::atomic<uint8_t> active{0u};
    std::atomic<uint64_t> concurrent_rejections{0u};
    uint64_t magic = 0u;
    fk_quic_retirement_publisher_config config{};
    fk_quic_retirement_publisher_stats stats{};
    fk_quic_cid_map *cid_map = nullptr;
    fk_owner_dispatch *dispatch = nullptr;
    fk_quic_cid_retirement_token *tokens = nullptr;
    fk_owner_quic_retire_control *controls = nullptr;
    uint32_t marked_count = 0u;
    size_t reserved_bytes = 0u;
    uint64_t baseline_cid_publication_marks = 0u;
    uint64_t baseline_cid_publication_rollbacks = 0u;
    uint64_t baseline_dispatch_controls_enqueued = 0u;
};

class ActiveGuard {
  public:
    explicit ActiveGuard(PublisherState &state) : state_(state) {}
    ~ActiveGuard() {
        state_.active.store(0u, std::memory_order_release);
    }
    ActiveGuard(const ActiveGuard &) = delete;
    ActiveGuard &operator=(const ActiveGuard &) = delete;

  private:
    PublisherState &state_;
};

enum class CollectionResult {
    Complete,
    PrefixReady,
    ScratchOverflow,
    PeekFailed,
    MarkFailed,
};

enum class SubmissionKind {
    Data,
    Skipped,
    Terminal,
};

static PublisherState *implementation(
        fk_quic_retirement_publisher *publisher) {
    return reinterpret_cast<PublisherState *>(publisher);
}

static const PublisherState *implementation(
        const fk_quic_retirement_publisher *publisher) {
    return reinterpret_cast<const PublisherState *>(publisher);
}

static void set_error(
        char *error, size_t error_capacity, const char *message) {
    if (error != nullptr && error_capacity != 0u)
        std::snprintf(error, error_capacity, "%s", message);
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

static bool checked_add_u64(uint64_t &value, uint64_t increment) {
    if (increment > std::numeric_limits<uint64_t>::max() - value)
        return false;
    value += increment;
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

static bool layout(
        const fk_quic_retirement_publisher_config &config,
        size_t &bytes) {
    size_t offset = alignof(std::max_align_t) - 1u;
    if (!add_region(
            offset, 1u, sizeof(PublisherState),
            alignof(PublisherState)) ||
        !add_region(
            offset, config.maximum_controls_per_batch,
            sizeof(fk_quic_cid_retirement_token),
            alignof(fk_quic_cid_retirement_token)) ||
        !add_region(
            offset, config.maximum_controls_per_batch,
            sizeof(fk_owner_quic_retire_control),
            alignof(fk_owner_quic_retire_control)))
        return false;
    bytes = offset;
    return true;
}

static uintptr_t align_pointer(uintptr_t value, size_t alignment) {
    const uintptr_t remainder = value % alignment;
    return remainder == 0u ? value : value + alignment - remainder;
}

template <typename T>
static T *take_region(uintptr_t &cursor, uintptr_t end, size_t count) {
    cursor = align_pointer(cursor, alignof(T));
    size_t bytes = 0u;
    if (!checked_multiply(count, sizeof(T), bytes) ||
        cursor > end || bytes > end - cursor)
        return nullptr;
    T *result = reinterpret_cast<T *>(cursor);
    cursor += bytes;
    return result;
}

static bool claim(PublisherState &state, bool count_rejection) {
    uint8_t expected = 0u;
    if (state.active.compare_exchange_strong(
            expected, 1u,
            std::memory_order_acq_rel,
            std::memory_order_acquire))
        return true;
    if (count_rejection) {
        state.concurrent_rejections.fetch_add(
            1u, std::memory_order_relaxed);
    }
    return false;
}

static bool valid_skip_reason(fk_owner_observation_skip_reason reason) {
    return reason >= FK_OWNER_OBSERVATION_SKIP_FILTERED &&
        reason < FK_OWNER_OBSERVATION_SKIP_REASON_COUNT;
}

static bool all_zero(const uint8_t *bytes, size_t byte_count) {
    for (size_t index = 0u; index < byte_count; ++index) {
        if (bytes[index] != 0u)
            return false;
    }
    return true;
}

static void refresh_current_marks(PublisherState &state) {
    state.stats.current_marked_controls = state.marked_count;
    if (state.marked_count > state.stats.peak_marked_controls)
        state.stats.peak_marked_controls = state.marked_count;
}

static void make_token_and_control(
        const fk_quic_cid_retirement &retirement,
        fk_quic_cid_retirement_token &token,
        fk_owner_quic_retire_control &control) {
    token = {};
    token.logical_connection_id = retirement.logical_connection_id;
    token.retirement_ordinal = retirement.retirement_ordinal;
    token.fixed_owner = retirement.fixed_owner;
    control = {};
    control.logical_connection_id = retirement.logical_connection_id;
    control.retirement_ordinal = retirement.retirement_ordinal;
    control.fixed_owner = retirement.fixed_owner;
    control.binding_expected_at_enqueue = retirement.binding_expected;
}

static bool token_empty(const fk_quic_cid_retirement_token &token) {
    return token.logical_connection_id == 0u &&
        token.retirement_ordinal == 0u && token.fixed_owner == 0u &&
        token.reserved0 == 0u && token.reserved1 == 0u;
}

static bool control_empty(const fk_owner_quic_retire_control &control) {
    if (control.logical_connection_id != 0u ||
        control.retirement_ordinal != 0u || control.fixed_owner != 0u ||
        control.binding_expected_at_enqueue != 0u)
        return false;
    for (const uint8_t value : control.reserved) {
        if (value != 0u)
            return false;
    }
    return true;
}

static bool scratch_conserved(const PublisherState &state) {
    uint16_t prior_owner = 0u;
    uint64_t prior_ordinal = 0u;
    bool initialized = false;
    for (uint32_t index = 0u;
         index < state.config.maximum_controls_per_batch; ++index) {
        const fk_quic_cid_retirement_token &token = state.tokens[index];
        const fk_owner_quic_retire_control &control =
            state.controls[index];
        if (index >= state.marked_count) {
            if (!token_empty(token) || !control_empty(control))
                return false;
            continue;
        }
        if (token.logical_connection_id == 0u ||
            token.retirement_ordinal == 0u ||
            token.fixed_owner >= state.config.owner_count ||
            token.reserved0 != 0u || token.reserved1 != 0u ||
            control.logical_connection_id !=
                token.logical_connection_id ||
            control.retirement_ordinal != token.retirement_ordinal ||
            control.fixed_owner != token.fixed_owner ||
            control.binding_expected_at_enqueue > 1u)
            return false;
        for (const uint8_t value : control.reserved) {
            if (value != 0u)
                return false;
        }
        if (initialized &&
            (token.fixed_owner < prior_owner ||
             (token.fixed_owner == prior_owner &&
              token.retirement_ordinal <= prior_ordinal)))
            return false;
        prior_owner = token.fixed_owner;
        prior_ordinal = token.retirement_ordinal;
        initialized = true;
    }
    return true;
}

static CollectionResult collect_prefix(PublisherState &state) {
    state.stats.collection_attempts++;
    for (uint16_t owner = 0u;
         owner < state.config.owner_count; ++owner) {
        state.stats.owner_scans++;
        for (;;) {
            /* Scratch bounds only this prefix. The caller commits it as a
             * controls-only observation prefix and immediately resumes the
             * same exact observation before DATA/SKIP can be submitted. */
            if (state.marked_count ==
                    state.config.maximum_controls_per_batch) {
                state.stats.collection_successes++;
                return CollectionResult::PrefixReady;
            }
            fk_quic_cid_retirement retirement{};
            state.stats.cid_peek_calls++;
            const fk_quic_cid_retirement_peek_result peek =
                fk_quic_cid_map_peek_next_undispatched_retirement(
                    state.cid_map, owner, &retirement);
            if (peek == FK_QUIC_CID_RETIREMENT_PEEK_EMPTY) {
                state.stats.cid_peek_empty++;
                break;
            }
            if (peek != FK_QUIC_CID_RETIREMENT_PEEK_READY) {
                state.stats.cid_peek_invalid++;
                return CollectionResult::PeekFailed;
            }
            state.stats.cid_peek_ready++;
            if (state.marked_count >=
                    state.config.maximum_controls_per_batch) {
                state.stats.scratch_overflows++;
                return CollectionResult::ScratchOverflow;
            }
            fk_quic_cid_retirement_token &token =
                state.tokens[state.marked_count];
            fk_owner_quic_retire_control &control =
                state.controls[state.marked_count];
            make_token_and_control(retirement, token, control);
            state.stats.cid_mark_attempts++;
            if (fk_quic_cid_map_mark_retirement_dispatched(
                    state.cid_map, &token) !=
                    FK_QUIC_CID_RETIREMENT_PUBLICATION_MARKED) {
                state.stats.cid_mark_failures++;
                token = {};
                control = {};
                return CollectionResult::MarkFailed;
            }
            state.marked_count++;
            state.stats.cid_marks++;
            refresh_current_marks(state);
        }
    }
    state.stats.collection_successes++;
    return CollectionResult::Complete;
}

static bool rollback_all(PublisherState &state) {
    while (state.marked_count != 0u) {
        const uint32_t index = state.marked_count - 1u;
        state.stats.rollback_attempts++;
        const fk_quic_cid_retirement_publication_result result =
            fk_quic_cid_map_rollback_retirement_dispatched(
                state.cid_map, &state.tokens[index]);
        if (result !=
                FK_QUIC_CID_RETIREMENT_PUBLICATION_ROLLED_BACK) {
            state.stats.rollback_failures++;
            state.stats.sticky_failure = true;
            state.stats.sticky_rollback_failure = true;
            refresh_current_marks(state);
            return false;
        }
        state.tokens[index] = {};
        state.controls[index] = {};
        state.marked_count--;
        state.stats.controls_rolled_back++;
        refresh_current_marks(state);
    }
    return true;
}

static fk_quic_retirement_publisher_result fail_after_collection(
        PublisherState &state,
        fk_quic_retirement_publisher_result original) {
    return rollback_all(state)
        ? original : FK_QUIC_RETIREMENT_PUBLISHER_ROLLBACK_FAILED;
}

static fk_quic_retirement_publisher_result collection_failure_result(
        PublisherState &state, CollectionResult result) {
    switch (result) {
    case CollectionResult::ScratchOverflow:
        return fail_after_collection(
            state, FK_QUIC_RETIREMENT_PUBLISHER_SCRATCH_OVERFLOW);
    case CollectionResult::PeekFailed:
        return fail_after_collection(
            state, FK_QUIC_RETIREMENT_PUBLISHER_CID_PEEK_FAILED);
    case CollectionResult::MarkFailed:
        return fail_after_collection(
            state, FK_QUIC_RETIREMENT_PUBLISHER_CID_MARK_FAILED);
    case CollectionResult::Complete:
    case CollectionResult::PrefixReady:
        break;
    }
    return FK_QUIC_RETIREMENT_PUBLISHER_INVALID;
}

static void commit_marks(PublisherState &state) {
    state.stats.controls_committed += state.marked_count;
    for (uint32_t index = 0u; index < state.marked_count; ++index) {
        state.tokens[index] = {};
        state.controls[index] = {};
    }
    state.marked_count = 0u;
    refresh_current_marks(state);
}

static fk_quic_retirement_publisher_result dispatch_failure_result(
        fk_owner_dispatch_result result) {
    switch (result) {
    case FK_OWNER_DISPATCH_QUEUE_FULL:
        return FK_QUIC_RETIREMENT_PUBLISHER_DISPATCH_QUEUE_FULL;
    case FK_OWNER_DISPATCH_INVALID:
        return FK_QUIC_RETIREMENT_PUBLISHER_DISPATCH_INVALID;
    case FK_OWNER_DISPATCH_STOPPED:
        return FK_QUIC_RETIREMENT_PUBLISHER_DISPATCH_STOPPED;
    case FK_OWNER_DISPATCH_OBSERVATIONS_SEALED:
        return FK_QUIC_RETIREMENT_PUBLISHER_DISPATCH_OBSERVATIONS_SEALED;
    case FK_OWNER_DISPATCH_LOCAL:
    case FK_OWNER_DISPATCH_FORWARDED:
    case FK_OWNER_DISPATCH_SKIPPED:
        break;
    }
    return FK_QUIC_RETIREMENT_PUBLISHER_DISPATCH_UNEXPECTED_NOT_COMMITTED;
}

static void record_noncommitted_dispatch_result(
        PublisherState &state, fk_owner_dispatch_result result) {
    switch (result) {
    case FK_OWNER_DISPATCH_QUEUE_FULL:
        state.stats.dispatch_queue_full++;
        break;
    case FK_OWNER_DISPATCH_INVALID:
        state.stats.dispatch_invalid++;
        break;
    case FK_OWNER_DISPATCH_STOPPED:
        state.stats.dispatch_stopped++;
        break;
    case FK_OWNER_DISPATCH_OBSERVATIONS_SEALED:
        state.stats.dispatch_observations_sealed++;
        break;
    case FK_OWNER_DISPATCH_LOCAL:
    case FK_OWNER_DISPATCH_FORWARDED:
    case FK_OWNER_DISPATCH_SKIPPED:
        state.stats.dispatch_unexpected++;
        break;
    }
}

static fk_quic_retirement_publisher_result finish_dispatch(
        PublisherState &state,
        SubmissionKind kind,
        fk_owner_dispatch_result result) {
    state.stats.dispatch_attempts++;
    const bool committed =
        result == FK_OWNER_DISPATCH_FORWARDED ||
        result == FK_OWNER_DISPATCH_SKIPPED;
    const bool expected =
        (kind == SubmissionKind::Data &&
         result == FK_OWNER_DISPATCH_FORWARDED) ||
        (kind == SubmissionKind::Skipped &&
         result == FK_OWNER_DISPATCH_SKIPPED) ||
        (kind == SubmissionKind::Terminal &&
         result == FK_OWNER_DISPATCH_FORWARDED);
    if (committed) {
        state.stats.dispatch_committed_batches++;
        commit_marks(state);
        if (!expected) {
            state.stats.dispatch_unexpected++;
            state.stats.unexpected_committed_batches++;
            state.stats.sticky_failure = true;
            if (kind == SubmissionKind::Data &&
                result == FK_OWNER_DISPATCH_SKIPPED) {
                return FK_QUIC_RETIREMENT_PUBLISHER_DISPATCH_UNEXPECTED_COMMITTED_PACKET_RETAINED;
            }
            return
                FK_QUIC_RETIREMENT_PUBLISHER_DISPATCH_UNEXPECTED_COMMITTED;
        }
        switch (kind) {
        case SubmissionKind::Data:
            state.stats.data_batches_committed++;
            return FK_QUIC_RETIREMENT_PUBLISHER_DATA_COMMITTED;
        case SubmissionKind::Skipped:
            state.stats.skipped_batches_committed++;
            return FK_QUIC_RETIREMENT_PUBLISHER_SKIP_COMMITTED;
        case SubmissionKind::Terminal:
            state.stats.terminal_batches_committed++;
            return FK_QUIC_RETIREMENT_PUBLISHER_TERMINAL_COMMITTED;
        }
    }
    record_noncommitted_dispatch_result(state, result);
    return fail_after_collection(
        state, dispatch_failure_result(result));
}

static bool finish_observation_prefix_dispatch(
        PublisherState &state,
        fk_owner_dispatch_result result,
        fk_quic_retirement_publisher_result &failure) {
    state.stats.dispatch_attempts++;
    state.stats.observation_prefix_dispatch_attempts++;
    if (result == FK_OWNER_DISPATCH_FORWARDED) {
        state.stats.dispatch_committed_batches++;
        state.stats.observation_prefix_batches_committed++;
        commit_marks(state);
        return true;
    }
    if (result == FK_OWNER_DISPATCH_SKIPPED) {
        /* This controls-only API can never advance an observation. Treat any
         * future ABI violation as a committed sticky failure so controls of
         * ambiguous fate are never republished. */
        state.stats.dispatch_committed_batches++;
        state.stats.unexpected_committed_batches++;
        state.stats.dispatch_unexpected++;
        state.stats.sticky_failure = true;
        commit_marks(state);
        failure =
            FK_QUIC_RETIREMENT_PUBLISHER_DISPATCH_UNEXPECTED_COMMITTED;
        return false;
    }
    record_noncommitted_dispatch_result(state, result);
    failure = fail_after_collection(
        state, dispatch_failure_result(result));
    return false;
}

static bool drain_observation_retirement_suffix(
        PublisherState &state,
        uint64_t packet_sequence,
        fk_quic_retirement_publisher_result &failure) {
    for (;;) {
        const CollectionResult collected = collect_prefix(state);
        if (collected != CollectionResult::Complete &&
            collected != CollectionResult::PrefixReady) {
            failure = collection_failure_result(state, collected);
            return false;
        }
        if (state.marked_count == 0u)
            return true;
        const fk_owner_dispatch_result dispatched =
            fk_owner_dispatch_submit_observation_retire_prefix(
                state.dispatch,
                packet_sequence,
                state.controls,
                state.marked_count);
        if (!finish_observation_prefix_dispatch(
                state, dispatched, failure)) {
            return false;
        }
        /* Even a short final prefix is committed controls-only. Re-collecting
         * proves the suffix empty before the unique DATA/SKIP below. */
    }
}

static bool counters_conserved(const PublisherState &state) {
    const fk_quic_retirement_publisher_stats &stats = state.stats;
    if (!scratch_conserved(state) || stats.reserved0 != 0u ||
        !all_zero(stats.reserved1, sizeof(stats.reserved1)) ||
        stats.current_marked_controls != state.marked_count ||
        stats.current_marked_controls >
            state.config.maximum_controls_per_batch ||
        stats.peak_marked_controls < stats.current_marked_controls ||
        stats.owner_count != state.config.owner_count ||
        stats.maximum_controls_per_batch !=
            state.config.maximum_controls_per_batch ||
        stats.reserved_bytes != state.reserved_bytes ||
        stats.dispatch_unexpected <
            stats.unexpected_committed_batches ||
        stats.observation_prefix_dispatch_attempts <
            stats.observation_prefix_batches_committed ||
        stats.rollback_recovery_calls < stats.rollback_recoveries ||
        (stats.sticky_rollback_failure && !stats.sticky_failure))
        return false;
    uint64_t peek_partition = stats.cid_peek_ready;
    uint64_t mark_partition = stats.cid_marks;
    uint64_t rollback_partition = stats.controls_rolled_back;
    uint64_t collection_partition = stats.collection_successes;
    uint64_t collection_success_partition = stats.dispatch_attempts;
    uint64_t committed_partition = stats.data_batches_committed;
    uint64_t dispatch_partition = stats.dispatch_committed_batches;
    uint64_t mark_conservation = stats.controls_committed;
    return checked_add_u64(peek_partition, stats.cid_peek_empty) &&
        checked_add_u64(peek_partition, stats.cid_peek_invalid) &&
        peek_partition == stats.cid_peek_calls &&
        checked_add_u64(mark_partition, stats.cid_mark_failures) &&
        mark_partition == stats.cid_mark_attempts &&
        checked_add_u64(
            rollback_partition, stats.rollback_failures) &&
        rollback_partition == stats.rollback_attempts &&
        checked_add_u64(
            collection_partition, stats.scratch_overflows) &&
        checked_add_u64(
            collection_partition, stats.cid_peek_invalid) &&
        checked_add_u64(
            collection_partition, stats.cid_mark_failures) &&
        collection_partition == stats.collection_attempts &&
        checked_add_u64(
            collection_success_partition, stats.terminal_empty) &&
        collection_success_partition == stats.collection_successes &&
        checked_add_u64(
            committed_partition,
            stats.observation_prefix_batches_committed) &&
        checked_add_u64(
            committed_partition, stats.skipped_batches_committed) &&
        checked_add_u64(
            committed_partition, stats.terminal_batches_committed) &&
        checked_add_u64(
            committed_partition, stats.unexpected_committed_batches) &&
        committed_partition == stats.dispatch_committed_batches &&
        checked_add_u64(
            dispatch_partition, stats.dispatch_queue_full) &&
        checked_add_u64(dispatch_partition, stats.dispatch_invalid) &&
        checked_add_u64(dispatch_partition, stats.dispatch_stopped) &&
        checked_add_u64(
            dispatch_partition, stats.dispatch_observations_sealed) &&
        checked_add_u64(
            dispatch_partition,
            stats.dispatch_unexpected -
                stats.unexpected_committed_batches) &&
        dispatch_partition == stats.dispatch_attempts &&
        checked_add_u64(
            mark_conservation, stats.controls_rolled_back) &&
        checked_add_u64(mark_conservation, state.marked_count) &&
        mark_conservation == stats.cid_marks;
}

static bool accounting_locked(const PublisherState &state) {
    if (!counters_conserved(state) || state.cid_map == nullptr ||
        state.dispatch == nullptr ||
        !fk_quic_cid_map_accounting_conserved(state.cid_map))
        return false;
    fk_quic_cid_map_stats cid_stats{};
    fk_owner_dispatch_stats dispatch_stats{};
    if (!fk_quic_cid_map_get_stats(state.cid_map, &cid_stats) ||
        !fk_owner_dispatch_get_stats(state.dispatch, &dispatch_stats) ||
        cid_stats.retirement_publication_marks <
            state.baseline_cid_publication_marks ||
        cid_stats.retirement_publication_rollbacks <
            state.baseline_cid_publication_rollbacks ||
        dispatch_stats.retire_controls_enqueued <
            state.baseline_dispatch_controls_enqueued)
        return false;
    return cid_stats.retirement_publication_marks -
            state.baseline_cid_publication_marks ==
            state.stats.cid_marks &&
        cid_stats.retirement_publication_rollbacks -
            state.baseline_cid_publication_rollbacks ==
            state.stats.controls_rolled_back &&
        dispatch_stats.retire_controls_enqueued -
            state.baseline_dispatch_controls_enqueued ==
            state.stats.controls_committed;
}

static bool formal_locked(const PublisherState &state) {
    const fk_quic_retirement_publisher_stats &stats = state.stats;
    return accounting_locked(state) && state.marked_count == 0u &&
        !stats.sticky_failure && !stats.sticky_rollback_failure &&
        stats.invalid_calls == 0u &&
        state.concurrent_rejections.load(std::memory_order_acquire) == 0u &&
        stats.sticky_rejections == 0u && stats.scratch_overflows == 0u &&
        stats.cid_peek_invalid == 0u && stats.cid_mark_failures == 0u &&
        stats.rollback_failures == 0u &&
        stats.observation_prefix_dispatch_attempts ==
            stats.observation_prefix_batches_committed &&
        stats.dispatch_queue_full == 0u && stats.dispatch_invalid == 0u &&
        stats.dispatch_stopped == 0u &&
        stats.dispatch_observations_sealed == 0u &&
        stats.dispatch_unexpected == 0u;
}

}  // namespace

extern "C" {

bool fk_quic_retirement_publisher_config_valid(
        const fk_quic_retirement_publisher_config *config) {
    return config != nullptr && config->owner_count != 0u &&
        config->owner_count <= 64u &&
        config->maximum_controls_per_batch != 0u &&
        config->reserved0 == 0u && config->reserved1[0] == 0u &&
        config->reserved1[1] == 0u;
}

size_t fk_quic_retirement_publisher_storage_bytes(
        const fk_quic_retirement_publisher_config *config) {
    if (!fk_quic_retirement_publisher_config_valid(config))
        return 0u;
    size_t bytes = 0u;
    return layout(*config, bytes) ? bytes : 0u;
}

fk_quic_retirement_publisher *
fk_quic_retirement_publisher_initialize(
        void *storage,
        size_t storage_bytes,
        const fk_quic_retirement_publisher_config *config,
        fk_quic_cid_map *cid_map,
        fk_owner_dispatch *dispatch,
        char *error,
        size_t error_capacity) {
    set_error(error, error_capacity, "");
    const size_t required =
        fk_quic_retirement_publisher_storage_bytes(config);
    if (storage == nullptr || required == 0u || storage_bytes < required ||
        cid_map == nullptr || dispatch == nullptr) {
        set_error(error, error_capacity, "invalid publisher storage plan");
        return nullptr;
    }
    fk_owner_dispatch_stats dispatch_stats{};
    fk_quic_cid_map_stats cid_stats{};
    if (!fk_owner_dispatch_get_stats(dispatch, &dispatch_stats) ||
        dispatch_stats.worker_count != config->owner_count) {
        set_error(error, error_capacity, "dispatch owner count mismatch");
        return nullptr;
    }
    fk_quic_cid_fixed_owner_lifecycle lifecycle{};
    for (uint16_t owner = 0u; owner < config->owner_count; ++owner) {
        if (!fk_quic_cid_map_get_fixed_owner_lifecycle(
                cid_map, owner, &lifecycle)) {
            set_error(error, error_capacity, "CID owner count mismatch");
            return nullptr;
        }
    }
    if (fk_quic_cid_map_get_fixed_owner_lifecycle(
            cid_map, config->owner_count, &lifecycle) ||
        !fk_quic_cid_map_accounting_conserved(cid_map) ||
        !fk_quic_cid_map_get_stats(cid_map, &cid_stats)) {
        set_error(error, error_capacity, "CID lifecycle is not conserved");
        return nullptr;
    }

    uintptr_t cursor = reinterpret_cast<uintptr_t>(storage);
    const uintptr_t end = cursor + storage_bytes;
    if (end < cursor) {
        set_error(error, error_capacity, "publisher storage overflow");
        return nullptr;
    }
    cursor = align_pointer(cursor, alignof(PublisherState));
    PublisherState *state =
        take_region<PublisherState>(cursor, end, 1u);
    if (state == nullptr) {
        set_error(error, error_capacity, "publisher state does not fit");
        return nullptr;
    }
    state = new (state) PublisherState{};
    state->tokens = take_region<fk_quic_cid_retirement_token>(
        cursor, end, config->maximum_controls_per_batch);
    state->controls = take_region<fk_owner_quic_retire_control>(
        cursor, end, config->maximum_controls_per_batch);
    if (state->tokens == nullptr || state->controls == nullptr) {
        state->~PublisherState();
        set_error(error, error_capacity, "publisher scratch does not fit");
        return nullptr;
    }
    state->magic = kMagic;
    state->config = *config;
    state->cid_map = cid_map;
    state->dispatch = dispatch;
    state->reserved_bytes = required;
    state->baseline_cid_publication_marks =
        cid_stats.retirement_publication_marks;
    state->baseline_cid_publication_rollbacks =
        cid_stats.retirement_publication_rollbacks;
    state->baseline_dispatch_controls_enqueued =
        dispatch_stats.retire_controls_enqueued;
    state->stats.reserved_bytes = required;
    state->stats.owner_count = config->owner_count;
    state->stats.maximum_controls_per_batch =
        config->maximum_controls_per_batch;
    for (uint32_t index = 0u;
         index < config->maximum_controls_per_batch; ++index) {
        state->tokens[index] = {};
        state->controls[index] = {};
    }
    return reinterpret_cast<fk_quic_retirement_publisher *>(state);
}

bool fk_quic_retirement_publisher_destroy_checked(
        fk_quic_retirement_publisher *publisher) {
    if (publisher == nullptr)
        return false;
    PublisherState &state = *implementation(publisher);
    if (state.magic != kMagic || !claim(state, false))
        return false;
    if (state.marked_count != 0u) {
        state.active.store(0u, std::memory_order_release);
        return false;
    }
    state.magic = 0u;
    state.~PublisherState();
    return true;
}

fk_quic_retirement_publisher_result
fk_quic_retirement_publisher_submit_data_observation(
        fk_quic_retirement_publisher *publisher,
        uint16_t ingress_worker,
        uint16_t owner_worker,
        const fk_owner_packet *packet) {
    if (publisher == nullptr)
        return FK_QUIC_RETIREMENT_PUBLISHER_INVALID;
    PublisherState &state = *implementation(publisher);
    if (state.magic != kMagic)
        return FK_QUIC_RETIREMENT_PUBLISHER_INVALID;
    if (!claim(state, true))
        return FK_QUIC_RETIREMENT_PUBLISHER_REENTRANT;
    const ActiveGuard guard(state);
    state.stats.data_calls++;
    if (state.stats.sticky_failure || state.marked_count != 0u) {
        state.stats.sticky_rejections++;
        return FK_QUIC_RETIREMENT_PUBLISHER_STICKY_FAILURE;
    }
    if (packet == nullptr || ingress_worker >= state.config.owner_count ||
        owner_worker >= state.config.owner_count) {
        state.stats.invalid_calls++;
        return FK_QUIC_RETIREMENT_PUBLISHER_INVALID;
    }
    fk_quic_retirement_publisher_result failure =
        FK_QUIC_RETIREMENT_PUBLISHER_INVALID;
    if (!drain_observation_retirement_suffix(
            state, packet->packet_sequence, failure)) {
        return failure;
    }
    const fk_owner_dispatch_result dispatched =
        fk_owner_dispatch_submit_observation_batch(
            state.dispatch,
            ingress_worker,
            owner_worker,
            packet,
            nullptr,
            0u);
    return finish_dispatch(state, SubmissionKind::Data, dispatched);
}

fk_quic_retirement_publisher_result
fk_quic_retirement_publisher_submit_skipped_observation(
        fk_quic_retirement_publisher *publisher,
        uint64_t packet_sequence,
        fk_owner_observation_skip_reason reason) {
    if (publisher == nullptr)
        return FK_QUIC_RETIREMENT_PUBLISHER_INVALID;
    PublisherState &state = *implementation(publisher);
    if (state.magic != kMagic)
        return FK_QUIC_RETIREMENT_PUBLISHER_INVALID;
    if (!claim(state, true))
        return FK_QUIC_RETIREMENT_PUBLISHER_REENTRANT;
    const ActiveGuard guard(state);
    state.stats.skipped_calls++;
    if (state.stats.sticky_failure || state.marked_count != 0u) {
        state.stats.sticky_rejections++;
        return FK_QUIC_RETIREMENT_PUBLISHER_STICKY_FAILURE;
    }
    if (!valid_skip_reason(reason)) {
        state.stats.invalid_calls++;
        return FK_QUIC_RETIREMENT_PUBLISHER_INVALID;
    }
    fk_quic_retirement_publisher_result failure =
        FK_QUIC_RETIREMENT_PUBLISHER_INVALID;
    if (!drain_observation_retirement_suffix(
            state, packet_sequence, failure)) {
        return failure;
    }
    const fk_owner_dispatch_result dispatched =
        fk_owner_dispatch_submit_skipped_observation_batch(
            state.dispatch,
            packet_sequence,
            reason,
            nullptr,
            0u);
    return finish_dispatch(state, SubmissionKind::Skipped, dispatched);
}

fk_quic_retirement_publisher_result
fk_quic_retirement_publisher_submit_terminal_batch(
        fk_quic_retirement_publisher *publisher,
        uint64_t terminal_ordinal) {
    if (publisher == nullptr)
        return FK_QUIC_RETIREMENT_PUBLISHER_INVALID;
    PublisherState &state = *implementation(publisher);
    if (state.magic != kMagic)
        return FK_QUIC_RETIREMENT_PUBLISHER_INVALID;
    if (!claim(state, true))
        return FK_QUIC_RETIREMENT_PUBLISHER_REENTRANT;
    const ActiveGuard guard(state);
    state.stats.terminal_calls++;
    if (state.stats.sticky_failure || state.marked_count != 0u) {
        state.stats.sticky_rejections++;
        return FK_QUIC_RETIREMENT_PUBLISHER_STICKY_FAILURE;
    }
    const CollectionResult collected = collect_prefix(state);
    if (collected != CollectionResult::Complete &&
        collected != CollectionResult::PrefixReady)
        return collection_failure_result(state, collected);
    if (state.marked_count == 0u) {
        state.stats.terminal_empty++;
        return FK_QUIC_RETIREMENT_PUBLISHER_TERMINAL_EMPTY;
    }
    const fk_owner_dispatch_result dispatched =
        fk_owner_dispatch_submit_terminal_retire_batch(
            state.dispatch,
            terminal_ordinal,
            state.controls,
            state.marked_count);
    return finish_dispatch(state, SubmissionKind::Terminal, dispatched);
}

fk_quic_retirement_publisher_result
fk_quic_retirement_publisher_retry_pending_rollback(
        fk_quic_retirement_publisher *publisher) {
    if (publisher == nullptr)
        return FK_QUIC_RETIREMENT_PUBLISHER_INVALID;
    PublisherState &state = *implementation(publisher);
    if (state.magic != kMagic)
        return FK_QUIC_RETIREMENT_PUBLISHER_INVALID;
    if (!claim(state, true))
        return FK_QUIC_RETIREMENT_PUBLISHER_REENTRANT;
    const ActiveGuard guard(state);
    state.stats.rollback_recovery_calls++;
    if (!state.stats.sticky_rollback_failure ||
        state.marked_count == 0u) {
        state.stats.invalid_calls++;
        return FK_QUIC_RETIREMENT_PUBLISHER_INVALID;
    }
    if (!rollback_all(state))
        return FK_QUIC_RETIREMENT_PUBLISHER_ROLLBACK_FAILED;
    state.stats.rollback_recoveries++;
    return FK_QUIC_RETIREMENT_PUBLISHER_ROLLBACK_RECOVERED;
}

bool fk_quic_retirement_publisher_get_stats(
        const fk_quic_retirement_publisher *publisher,
        fk_quic_retirement_publisher_stats *stats) {
    if (publisher == nullptr || stats == nullptr)
        return false;
    PublisherState &state =
        *const_cast<PublisherState *>(implementation(publisher));
    if (state.magic != kMagic || !claim(state, false))
        return false;
    const ActiveGuard guard(state);
    *stats = state.stats;
    stats->reentrant_rejections =
        state.concurrent_rejections.load(std::memory_order_acquire);
    return true;
}

bool fk_quic_retirement_publisher_accounting_conserved(
        const fk_quic_retirement_publisher *publisher) {
    if (publisher == nullptr)
        return false;
    PublisherState &state =
        *const_cast<PublisherState *>(implementation(publisher));
    if (state.magic != kMagic || !claim(state, false))
        return false;
    const ActiveGuard guard(state);
    return accounting_locked(state);
}

bool fk_quic_retirement_publisher_formal_complete(
        const fk_quic_retirement_publisher *publisher) {
    if (publisher == nullptr)
        return false;
    PublisherState &state =
        *const_cast<PublisherState *>(implementation(publisher));
    if (state.magic != kMagic || !claim(state, false))
        return false;
    const ActiveGuard guard(state);
    return formal_locked(state);
}

const char *fk_quic_retirement_publisher_result_name(
        fk_quic_retirement_publisher_result result) {
    switch (result) {
    case FK_QUIC_RETIREMENT_PUBLISHER_INVALID:
        return "invalid";
    case FK_QUIC_RETIREMENT_PUBLISHER_DATA_COMMITTED:
        return "data_committed";
    case FK_QUIC_RETIREMENT_PUBLISHER_SKIP_COMMITTED:
        return "skip_committed";
    case FK_QUIC_RETIREMENT_PUBLISHER_TERMINAL_COMMITTED:
        return "terminal_committed";
    case FK_QUIC_RETIREMENT_PUBLISHER_TERMINAL_EMPTY:
        return "terminal_empty";
    case FK_QUIC_RETIREMENT_PUBLISHER_SCRATCH_OVERFLOW:
        return "scratch_overflow";
    case FK_QUIC_RETIREMENT_PUBLISHER_CID_PEEK_FAILED:
        return "cid_peek_failed";
    case FK_QUIC_RETIREMENT_PUBLISHER_CID_MARK_FAILED:
        return "cid_mark_failed";
    case FK_QUIC_RETIREMENT_PUBLISHER_DISPATCH_QUEUE_FULL:
        return "dispatch_queue_full";
    case FK_QUIC_RETIREMENT_PUBLISHER_DISPATCH_INVALID:
        return "dispatch_invalid";
    case FK_QUIC_RETIREMENT_PUBLISHER_DISPATCH_STOPPED:
        return "dispatch_stopped";
    case FK_QUIC_RETIREMENT_PUBLISHER_DISPATCH_OBSERVATIONS_SEALED:
        return "dispatch_observations_sealed";
    case FK_QUIC_RETIREMENT_PUBLISHER_DISPATCH_UNEXPECTED_COMMITTED:
        return "dispatch_unexpected_committed";
    case FK_QUIC_RETIREMENT_PUBLISHER_DISPATCH_UNEXPECTED_NOT_COMMITTED:
        return "dispatch_unexpected_not_committed";
    case FK_QUIC_RETIREMENT_PUBLISHER_ROLLBACK_FAILED:
        return "rollback_failed";
    case FK_QUIC_RETIREMENT_PUBLISHER_ROLLBACK_RECOVERED:
        return "rollback_recovered";
    case FK_QUIC_RETIREMENT_PUBLISHER_STICKY_FAILURE:
        return "sticky_failure";
    case FK_QUIC_RETIREMENT_PUBLISHER_REENTRANT:
        return "reentrant";
    case FK_QUIC_RETIREMENT_PUBLISHER_DISPATCH_UNEXPECTED_COMMITTED_PACKET_RETAINED:
        return "dispatch_unexpected_committed_packet_retained";
    }
    return "unknown";
}

}  // extern "C"
