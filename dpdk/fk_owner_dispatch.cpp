#include "fk_owner_dispatch.h"

#include <atomic>
#include <cstddef>
#include <cstring>
#include <limits>
#include <new>

namespace {

struct QueueCell {
    std::atomic<uint64_t> sequence;
    fk_owner_envelope envelope;
};

struct OwnerQueue {
    std::atomic<uint64_t> enqueue_position;
    std::atomic<uint64_t> dequeue_position;
    std::atomic<uint64_t> enqueued;
    std::atomic<uint64_t> dequeued;
    std::atomic<uint64_t> local_enqueued;
    std::atomic<uint64_t> local_dequeued;
    std::atomic<uint64_t> remote_enqueued;
    std::atomic<uint64_t> remote_dequeued;
    std::atomic<uint64_t> depth;
    std::atomic<uint64_t> peak_depth;
    std::atomic<uint64_t> normal_dequeued;
    std::atomic<uint64_t> drained;
    std::atomic<uint64_t> retire_controls_enqueued;
    std::atomic<uint64_t> retire_controls_dequeued;
    std::atomic<uint64_t> retire_controls_normal_dequeued;
    std::atomic<uint64_t> retire_controls_drained;
    std::atomic<uint64_t> retire_control_depth;
    std::atomic<uint64_t> last_retirement_ordinal;
    std::atomic<uint8_t> retirement_ordinal_initialized;
    QueueCell *cells;
    uint32_t mask;
};

struct DispatchImpl {
    fk_owner_dispatch_config config;
    OwnerQueue *queues;
    std::atomic<uint64_t> submit_attempts;
    std::atomic<uint64_t> local_packets;
    std::atomic<uint64_t> local_enqueued;
    std::atomic<uint64_t> local_dequeued;
    std::atomic<uint64_t> remote_enqueued;
    std::atomic<uint64_t> remote_dequeued;
    std::atomic<uint64_t> queued_enqueued;
    std::atomic<uint64_t> queued_dequeued;
    std::atomic<uint64_t> ordered_accepted_packets;
    std::atomic<uint64_t> ordered_skipped_observations;
    std::atomic<uint64_t> ordered_skipped_filtered;
    std::atomic<uint64_t> ordered_skipped_parse_rejected;
    std::atomic<uint64_t> ordered_skipped_unresolved_identity;
    std::atomic<uint64_t> ordered_skipped_capture_truncated;
    std::atomic<uint64_t> ordered_skipped_unsupported_packet;
    std::atomic<uint64_t> next_ordered_sequence;
    std::atomic<uint64_t> ordered_sequence_failures;
    std::atomic<uint64_t> retire_controls_enqueued;
    std::atomic<uint64_t> retire_controls_dequeued;
    std::atomic<uint64_t> retire_controls_normal_dequeued;
    std::atomic<uint64_t> retire_controls_drained;
    std::atomic<uint64_t> retire_control_depth;
    std::atomic<uint64_t> peak_retire_control_depth;
    std::atomic<uint64_t> total_envelope_depth;
    std::atomic<uint64_t> peak_envelope_depth;
    std::atomic<uint64_t> maximum_retirement_ordinal_observed;
    std::atomic<uint64_t> retirement_ordinal_failures;
    std::atomic<uint64_t> observation_retire_prefix_attempts;
    std::atomic<uint64_t> observation_retire_prefixes_accepted;
    std::atomic<uint64_t> terminal_batch_attempts;
    std::atomic<uint64_t> terminal_batches_accepted;
    std::atomic<uint64_t> next_terminal_ordinal;
    std::atomic<uint64_t> terminal_ordinal_failures;
    std::atomic<uint64_t> observation_seal_attempts;
    std::atomic<uint64_t> observation_seal_transitions;
    std::atomic<uint64_t> observation_seal_failures;
    std::atomic<uint64_t> submit_rejected_observations_sealed;
    std::atomic<uint64_t> atomic_batch_preflight_failures;
    std::atomic<uint8_t> observations_sealed;
    std::atomic<uint64_t> queue_full;
    std::atomic<uint64_t> invalid_routes;
    std::atomic<uint64_t> total_depth;
    std::atomic<uint64_t> peak_total_depth;
    /* Top two bits are lifecycle, lower 62 bits are active submitters. */
    std::atomic<uint64_t> lifecycle_and_submitters;
    /* Serializes every producer and atomic multi-owner batch commit. */
    std::atomic_flag producer_commit_lock = ATOMIC_FLAG_INIT;
    std::atomic<uint64_t> normal_dequeued;
    std::atomic<uint64_t> drained;
    std::atomic<uint64_t> stop_attempts;
    std::atomic<uint64_t> stop_transitions;
    std::atomic<uint64_t> abort_attempts;
    std::atomic<uint64_t> abort_transitions;
    std::atomic<uint64_t> submit_rejected_stopped;
    std::atomic<uint64_t> submit_rejected_aborted;
    std::atomic<uint64_t> destroy_rejected_live_ownership;
    uint64_t reserved_bytes;
};

constexpr uint64_t kLifecycleShift = 62u;
constexpr uint64_t kSubmitterMask =
    (UINT64_C(1) << kLifecycleShift) - UINT64_C(1);
constexpr uint64_t kLifecycleMask = ~kSubmitterMask;
constexpr uint64_t kStoppedBits = UINT64_C(1) << kLifecycleShift;
constexpr uint64_t kAbortedBits = UINT64_C(2) << kLifecycleShift;

static_assert(
    alignof(DispatchImpl) <= alignof(max_align_t),
    "DispatchImpl exceeds caller storage alignment");
static_assert(
    alignof(OwnerQueue) <= alignof(max_align_t),
    "OwnerQueue exceeds caller storage alignment");
static_assert(
    alignof(QueueCell) <= alignof(max_align_t),
    "QueueCell exceeds caller storage alignment");
static_assert(sizeof(fk_owner_packet) == 88u, "owner packet ABI changed");
static_assert(sizeof(fk_owner_envelope) == 96u, "owner envelope ABI changed");

bool power_of_two(uint32_t value) {
    return value >= 2u && (value & (value - 1u)) == 0u;
}

bool valid_config(const fk_owner_dispatch_config *config) {
    return config != nullptr &&
        config->worker_count != 0u &&
        config->worker_count <= 64u &&
        power_of_two(config->queue_capacity_per_owner);
}

bool checked_add(size_t &value, size_t addend) {
    if (addend > std::numeric_limits<size_t>::max() - value)
        return false;
    value += addend;
    return true;
}

bool checked_multiply(size_t left, size_t right, size_t &result) {
    if (left != 0u && right > std::numeric_limits<size_t>::max() / left)
        return false;
    result = left * right;
    return true;
}

bool align_size(size_t &value, size_t alignment) {
    const size_t remainder = value % alignment;
    return remainder == 0u || checked_add(value, alignment - remainder);
}

size_t required_bytes(const fk_owner_dispatch_config *config) {
    if (!valid_config(config))
        return 0u;
    size_t bytes = sizeof(DispatchImpl);
    if (!align_size(bytes, alignof(OwnerQueue)))
        return 0u;
    size_t queue_bytes = 0u;
    if (!checked_multiply(
            config->worker_count, sizeof(OwnerQueue), queue_bytes) ||
        !checked_add(bytes, queue_bytes) ||
        !align_size(bytes, alignof(QueueCell)))
        return 0u;
    size_t cell_count = 0u;
    size_t cell_bytes = 0u;
    if (!checked_multiply(
            config->worker_count,
            config->queue_capacity_per_owner,
            cell_count) ||
        !checked_multiply(cell_count, sizeof(QueueCell), cell_bytes) ||
        !checked_add(bytes, cell_bytes))
        return 0u;
    return bytes;
}

uint64_t rotate_left(uint64_t value, unsigned shift) {
    return (value << shift) | (value >> (64u - shift));
}

uint64_t load_u64_le(const uint8_t *bytes) {
    uint64_t result = 0u;
    for (uint32_t index = 0u; index < 8u; ++index)
        result |= static_cast<uint64_t>(bytes[index]) << (index * 8u);
    return result;
}

void sip_round(uint64_t &v0, uint64_t &v1, uint64_t &v2, uint64_t &v3) {
    v0 += v1;
    v1 = rotate_left(v1, 13u);
    v1 ^= v0;
    v0 = rotate_left(v0, 32u);
    v2 += v3;
    v3 = rotate_left(v3, 16u);
    v3 ^= v2;
    v0 += v3;
    v3 = rotate_left(v3, 21u);
    v3 ^= v0;
    v2 += v1;
    v1 = rotate_left(v1, 17u);
    v1 ^= v2;
    v2 = rotate_left(v2, 32u);
}

uint64_t siphash24(
        const uint8_t key[FK_OWNER_DISPATCH_KEY_BYTES],
        const uint8_t *message,
        size_t length) {
    const uint64_t k0 = load_u64_le(key);
    const uint64_t k1 = load_u64_le(key + 8u);
    uint64_t v0 = UINT64_C(0x736f6d6570736575) ^ k0;
    uint64_t v1 = UINT64_C(0x646f72616e646f6d) ^ k1;
    uint64_t v2 = UINT64_C(0x6c7967656e657261) ^ k0;
    uint64_t v3 = UINT64_C(0x7465646279746573) ^ k1;
    const size_t blocks = length / 8u;
    for (size_t index = 0u; index < blocks; ++index) {
        const uint64_t word = load_u64_le(message + index * 8u);
        v3 ^= word;
        sip_round(v0, v1, v2, v3);
        sip_round(v0, v1, v2, v3);
        v0 ^= word;
    }
    uint64_t tail = static_cast<uint64_t>(length) << 56u;
    const size_t offset = blocks * 8u;
    for (size_t index = 0u; index < length - offset; ++index)
        tail |= static_cast<uint64_t>(message[offset + index]) << (index * 8u);
    v3 ^= tail;
    sip_round(v0, v1, v2, v3);
    sip_round(v0, v1, v2, v3);
    v0 ^= tail;
    v2 ^= 0xffu;
    for (uint32_t index = 0u; index < 4u; ++index)
        sip_round(v0, v1, v2, v3);
    return v0 ^ v1 ^ v2 ^ v3;
}

DispatchImpl *implementation(fk_owner_dispatch *dispatch) {
    return reinterpret_cast<DispatchImpl *>(dispatch);
}

const DispatchImpl *implementation(const fk_owner_dispatch *dispatch) {
    return reinterpret_cast<const DispatchImpl *>(dispatch);
}

void update_peak(std::atomic<uint64_t> &peak, uint64_t candidate) {
    uint64_t observed = peak.load(std::memory_order_relaxed);
    while (candidate > observed &&
           !peak.compare_exchange_weak(
               observed,
               candidate,
               std::memory_order_relaxed,
               std::memory_order_relaxed)) {
    }
}

fk_owner_dispatch_lifecycle lifecycle_from_word(uint64_t word) {
    switch (word & kLifecycleMask) {
    case 0u:
        return FK_OWNER_DISPATCH_ACCEPTING;
    case kStoppedBits:
        return FK_OWNER_DISPATCH_STOPPED_NORMAL;
    case kAbortedBits:
        return FK_OWNER_DISPATCH_ABORTED;
    default:
        return FK_OWNER_DISPATCH_ABORTED;
    }
}

void wait_for_submitters(DispatchImpl &state) {
    while ((state.lifecycle_and_submitters.load(std::memory_order_acquire) &
            kSubmitterMask) != 0u)
        std::atomic_signal_fence(std::memory_order_seq_cst);
}

enum class SubmitReservation {
    Reserved,
    Stopped,
    Invalid,
};

SubmitReservation reserve_submitter(DispatchImpl &state) {
    uint64_t observed = state.lifecycle_and_submitters.load(
        std::memory_order_acquire);
    for (;;) {
        const fk_owner_dispatch_lifecycle lifecycle =
            lifecycle_from_word(observed);
        if (lifecycle != FK_OWNER_DISPATCH_ACCEPTING) {
            if (lifecycle == FK_OWNER_DISPATCH_ABORTED) {
                state.submit_rejected_aborted.fetch_add(
                    1u, std::memory_order_relaxed);
            } else {
                state.submit_rejected_stopped.fetch_add(
                    1u, std::memory_order_relaxed);
            }
            return SubmitReservation::Stopped;
        }
        if ((observed & kSubmitterMask) == kSubmitterMask) {
            state.invalid_routes.fetch_add(1u, std::memory_order_relaxed);
            return SubmitReservation::Invalid;
        }
        if (state.lifecycle_and_submitters.compare_exchange_weak(
                observed,
                observed + 1u,
                std::memory_order_acq_rel,
                std::memory_order_acquire))
            return SubmitReservation::Reserved;
    }
}

void release_submitter(DispatchImpl &state) {
    state.lifecycle_and_submitters.fetch_sub(1u, std::memory_order_release);
}

struct SubmitterGuard {
    explicit SubmitterGuard(DispatchImpl &dispatch) : state(dispatch) {}
    ~SubmitterGuard() { release_submitter(state); }
    SubmitterGuard(const SubmitterGuard &) = delete;
    SubmitterGuard &operator=(const SubmitterGuard &) = delete;
    DispatchImpl &state;
};

struct ProducerCommitGuard {
    explicit ProducerCommitGuard(DispatchImpl &dispatch) : state(dispatch) {
        while (state.producer_commit_lock.test_and_set(
                   std::memory_order_acquire))
            std::atomic_signal_fence(std::memory_order_seq_cst);
    }
    ~ProducerCommitGuard() {
        state.producer_commit_lock.clear(std::memory_order_release);
    }
    ProducerCommitGuard(const ProducerCommitGuard &) = delete;
    ProducerCommitGuard &operator=(const ProducerCommitGuard &) = delete;
    DispatchImpl &state;
};

bool ownership_conserved_values(
        uint64_t accepted,
        uint64_t normal_dequeued,
        uint64_t drained,
        uint64_t owned) {
    return normal_dequeued <= accepted &&
        drained <= accepted - normal_dequeued &&
        owned == accepted - normal_dequeued - drained;
}

bool retire_controls_conserved_values(
        uint64_t enqueued,
        uint64_t normal_dequeued,
        uint64_t drained,
        uint64_t depth) {
    return normal_dequeued <= enqueued &&
        drained <= enqueued - normal_dequeued &&
        depth == enqueued - normal_dequeued - drained;
}

bool valid_skip_reason(fk_owner_observation_skip_reason reason) {
    switch (reason) {
    case FK_OWNER_OBSERVATION_SKIP_FILTERED:
    case FK_OWNER_OBSERVATION_SKIP_PARSE_REJECTED:
    case FK_OWNER_OBSERVATION_SKIP_UNRESOLVED_IDENTITY:
    case FK_OWNER_OBSERVATION_SKIP_CAPTURE_TRUNCATED:
    case FK_OWNER_OBSERVATION_SKIP_UNSUPPORTED_PACKET:
        return true;
    default:
        return false;
    }
}

void record_skip_reason(
        DispatchImpl &state,
        fk_owner_observation_skip_reason reason) {
    switch (reason) {
    case FK_OWNER_OBSERVATION_SKIP_FILTERED:
        state.ordered_skipped_filtered.fetch_add(
            1u, std::memory_order_relaxed);
        return;
    case FK_OWNER_OBSERVATION_SKIP_PARSE_REJECTED:
        state.ordered_skipped_parse_rejected.fetch_add(
            1u, std::memory_order_relaxed);
        return;
    case FK_OWNER_OBSERVATION_SKIP_UNRESOLVED_IDENTITY:
        state.ordered_skipped_unresolved_identity.fetch_add(
            1u, std::memory_order_relaxed);
        return;
    case FK_OWNER_OBSERVATION_SKIP_CAPTURE_TRUNCATED:
        state.ordered_skipped_capture_truncated.fetch_add(
            1u, std::memory_order_relaxed);
        return;
    case FK_OWNER_OBSERVATION_SKIP_UNSUPPORTED_PACKET:
        state.ordered_skipped_unsupported_packet.fetch_add(
            1u, std::memory_order_relaxed);
        return;
    default:
        return;
    }
}

bool checked_sum(uint64_t left, uint64_t right, uint64_t &sum) {
    if (right > UINT64_MAX - left)
        return false;
    sum = left + right;
    return true;
}

bool valid_retire_control(
        const DispatchImpl &state,
        const fk_owner_quic_retire_control &control) {
    if (control.logical_connection_id == 0u ||
        control.retirement_ordinal == 0u ||
        control.fixed_owner >= state.config.worker_count ||
        control.binding_expected_at_enqueue > 1u)
        return false;
    for (uint8_t byte : control.reserved) {
        if (byte != 0u)
            return false;
    }
    return true;
}

enum class BatchPreflight {
    Ready,
    Capacity,
    Integrity,
};

BatchPreflight preflight_batch(
        DispatchImpl &state,
        const uint64_t needed[64]) {
    const uint64_t capacity = state.config.queue_capacity_per_owner;
    for (uint16_t owner = 0u; owner < state.config.worker_count; ++owner) {
        if (needed[owner] == 0u)
            continue;
        OwnerQueue &queue = state.queues[owner];
        const uint64_t depth = queue.depth.load(std::memory_order_acquire);
        if (depth > capacity)
            return BatchPreflight::Integrity;
        if (needed[owner] > capacity - depth)
            return BatchPreflight::Capacity;
        const uint64_t position = queue.enqueue_position.load(
            std::memory_order_relaxed);
        /* Stop before either the producer position or later consumer slot
         * release arithmetic could wrap. */
        if (position > UINT64_MAX - capacity ||
            needed[owner] > UINT64_MAX - capacity - position)
            return BatchPreflight::Integrity;
        for (uint64_t offset = 0u; offset < needed[owner]; ++offset) {
            const uint64_t expected = position + offset;
            const QueueCell &cell = queue.cells[expected & queue.mask];
            if (cell.sequence.load(std::memory_order_acquire) != expected)
                return BatchPreflight::Integrity;
        }
    }
    return BatchPreflight::Ready;
}

void commit_envelope(
        DispatchImpl &state,
        uint16_t owner,
        const fk_owner_envelope &envelope,
        bool local_route) {
    OwnerQueue &queue = state.queues[owner];
    const uint64_t position = queue.enqueue_position.load(
        std::memory_order_relaxed);
    QueueCell &cell = queue.cells[position & queue.mask];
    queue.enqueue_position.store(position + 1u, std::memory_order_relaxed);
    cell.envelope = envelope;
    if (envelope.kind == FK_OWNER_ENVELOPE_DATA) {
        state.queued_enqueued.fetch_add(1u, std::memory_order_relaxed);
        queue.enqueued.fetch_add(1u, std::memory_order_relaxed);
        if (local_route) {
            state.local_enqueued.fetch_add(1u, std::memory_order_relaxed);
            queue.local_enqueued.fetch_add(1u, std::memory_order_relaxed);
        } else {
            state.remote_enqueued.fetch_add(1u, std::memory_order_relaxed);
            queue.remote_enqueued.fetch_add(1u, std::memory_order_relaxed);
        }
        const uint64_t data_depth = state.total_depth.fetch_add(
            1u, std::memory_order_relaxed) + 1u;
        update_peak(state.peak_total_depth, data_depth);
    } else {
        state.retire_controls_enqueued.fetch_add(
            1u, std::memory_order_relaxed);
        queue.retire_controls_enqueued.fetch_add(
            1u, std::memory_order_relaxed);
        const uint64_t control_depth = state.retire_control_depth.fetch_add(
            1u, std::memory_order_relaxed) + 1u;
        update_peak(state.peak_retire_control_depth, control_depth);
        queue.retire_control_depth.fetch_add(1u, std::memory_order_relaxed);
    }
    const uint64_t envelope_depth = state.total_envelope_depth.fetch_add(
        1u, std::memory_order_relaxed) + 1u;
    update_peak(state.peak_envelope_depth, envelope_depth);
    const uint64_t owner_depth = queue.depth.fetch_add(
        1u, std::memory_order_relaxed) + 1u;
    update_peak(queue.peak_depth, owner_depth);
    cell.sequence.store(position + 1u, std::memory_order_release);
}

bool dequeue_envelope(OwnerQueue &queue, fk_owner_envelope &envelope) {
    uint64_t position = queue.dequeue_position.load(std::memory_order_relaxed);
    QueueCell &cell = queue.cells[position & queue.mask];
    const uint64_t sequence = cell.sequence.load(std::memory_order_acquire);
    const int64_t difference =
        static_cast<int64_t>(sequence - (position + 1u));
    if (difference != 0)
        return false;
    envelope = cell.envelope;
    queue.dequeue_position.store(position + 1u, std::memory_order_relaxed);
    cell.sequence.store(
        position + static_cast<uint64_t>(queue.mask) + 1u,
        std::memory_order_release);
    return true;
}

bool front_kind(OwnerQueue &queue, fk_owner_envelope_kind &kind) {
    const uint64_t position = queue.dequeue_position.load(
        std::memory_order_relaxed);
    QueueCell &cell = queue.cells[position & queue.mask];
    if (cell.sequence.load(std::memory_order_acquire) != position + 1u)
        return false;
    kind = cell.envelope.kind;
    return true;
}

}  // namespace

extern "C" {

size_t fk_owner_dispatch_storage_bytes(
        const fk_owner_dispatch_config *config) {
    return required_bytes(config);
}

bool fk_owner_dispatch_initialize(
        void *storage,
        size_t storage_bytes,
        const fk_owner_dispatch_config *config,
        fk_owner_dispatch **dispatch) {
    if (dispatch != nullptr)
        *dispatch = nullptr;
    const size_t required = required_bytes(config);
    if (storage == nullptr || dispatch == nullptr || required == 0u ||
        storage_bytes < required ||
        reinterpret_cast<uintptr_t>(storage) % alignof(max_align_t) != 0u)
        return false;
    auto *base = static_cast<uint8_t *>(storage);
    auto *state = new (base) DispatchImpl{};
    state->producer_commit_lock.clear(std::memory_order_relaxed);
    state->maximum_retirement_ordinal_observed.store(
        0u, std::memory_order_relaxed);
    state->config = *config;
    state->reserved_bytes = required;
    size_t offset = sizeof(DispatchImpl);
    (void)align_size(offset, alignof(OwnerQueue));
    state->queues = reinterpret_cast<OwnerQueue *>(base + offset);
    offset += static_cast<size_t>(config->worker_count) * sizeof(OwnerQueue);
    (void)align_size(offset, alignof(QueueCell));
    auto *cells = reinterpret_cast<QueueCell *>(base + offset);
    for (uint16_t owner = 0u; owner < config->worker_count; ++owner) {
        OwnerQueue *queue = new (&state->queues[owner]) OwnerQueue{};
        queue->last_retirement_ordinal.store(0u, std::memory_order_relaxed);
        queue->retirement_ordinal_initialized.store(
            0u, std::memory_order_relaxed);
        queue->mask = config->queue_capacity_per_owner - 1u;
        queue->cells = cells +
            static_cast<size_t>(owner) * config->queue_capacity_per_owner;
        for (uint32_t index = 0u;
             index < config->queue_capacity_per_owner; ++index) {
            QueueCell *cell = new (&queue->cells[index]) QueueCell{};
            cell->sequence.store(index, std::memory_order_relaxed);
        }
    }
    *dispatch = reinterpret_cast<fk_owner_dispatch *>(state);
    return true;
}

static void destroy_unchecked(DispatchImpl *state) {
    for (uint16_t owner = 0u; owner < state->config.worker_count; ++owner) {
        OwnerQueue &queue = state->queues[owner];
        for (uint32_t index = 0u;
             index < state->config.queue_capacity_per_owner; ++index)
            queue.cells[index].~QueueCell();
        queue.~OwnerQueue();
    }
    state->~DispatchImpl();
}

bool fk_owner_dispatch_stop_accepting(fk_owner_dispatch *dispatch) {
    if (dispatch == nullptr)
        return false;
    DispatchImpl &state = *implementation(dispatch);
    state.stop_attempts.fetch_add(1u, std::memory_order_relaxed);
    uint64_t observed = state.lifecycle_and_submitters.load(
        std::memory_order_acquire);
    for (;;) {
        const fk_owner_dispatch_lifecycle lifecycle =
            lifecycle_from_word(observed);
        if (lifecycle == FK_OWNER_DISPATCH_ABORTED) {
            wait_for_submitters(state);
            return false;
        }
        if (lifecycle == FK_OWNER_DISPATCH_STOPPED_NORMAL)
            break;
        const uint64_t desired = (observed & kSubmitterMask) | kStoppedBits;
        if (state.lifecycle_and_submitters.compare_exchange_weak(
                observed,
                desired,
                std::memory_order_acq_rel,
                std::memory_order_acquire)) {
            state.stop_transitions.fetch_add(1u, std::memory_order_relaxed);
            break;
        }
    }
    wait_for_submitters(state);
    return lifecycle_from_word(state.lifecycle_and_submitters.load(
        std::memory_order_acquire)) == FK_OWNER_DISPATCH_STOPPED_NORMAL;
}

bool fk_owner_dispatch_abort(fk_owner_dispatch *dispatch) {
    if (dispatch == nullptr)
        return false;
    DispatchImpl &state = *implementation(dispatch);
    state.abort_attempts.fetch_add(1u, std::memory_order_relaxed);
    uint64_t observed = state.lifecycle_and_submitters.load(
        std::memory_order_acquire);
    for (;;) {
        if (lifecycle_from_word(observed) == FK_OWNER_DISPATCH_ABORTED)
            break;
        const uint64_t desired = (observed & kSubmitterMask) | kAbortedBits;
        if (state.lifecycle_and_submitters.compare_exchange_weak(
                observed,
                desired,
                std::memory_order_acq_rel,
                std::memory_order_acquire)) {
            state.abort_transitions.fetch_add(1u, std::memory_order_relaxed);
            break;
        }
    }
    wait_for_submitters(state);
    return true;
}

bool fk_owner_dispatch_destroy_checked(fk_owner_dispatch *dispatch) {
    if (dispatch == nullptr)
        return true;
    DispatchImpl *state = implementation(dispatch);
    const fk_owner_dispatch_lifecycle lifecycle = lifecycle_from_word(
        state->lifecycle_and_submitters.load(std::memory_order_acquire));
    if (lifecycle == FK_OWNER_DISPATCH_ACCEPTING)
        (void)fk_owner_dispatch_stop_accepting(dispatch);
    else
        wait_for_submitters(*state);
    if (!fk_owner_dispatch_drain_complete(dispatch)) {
        state->destroy_rejected_live_ownership.fetch_add(
            1u, std::memory_order_relaxed);
        return false;
    }
    destroy_unchecked(state);
    return true;
}

void fk_owner_dispatch_destroy(fk_owner_dispatch *dispatch) {
    (void)fk_owner_dispatch_destroy_checked(dispatch);
}

bool fk_owner_identity_from_flow_key(
        const fk_flow_key *key,
        fk_owner_identity *identity) {
    if (identity != nullptr)
        std::memset(identity, 0, sizeof(*identity));
    if (key == nullptr || identity == nullptr ||
        (key->ip_version != 4u && key->ip_version != 6u) ||
        (key->protocol != 6u && key->protocol != 17u))
        return false;
    const size_t address_bytes = key->ip_version == 4u ? 4u : 16u;
    if (key->ip_version == 4u) {
        for (size_t index = address_bytes; index < 16u; ++index) {
            if (key->low_addr[index] != 0u || key->high_addr[index] != 0u)
                return false;
        }
    }
    const int address_order = std::memcmp(
        key->low_addr, key->high_addr, address_bytes);
    if (address_order > 0 ||
        (address_order == 0 && key->low_port > key->high_port))
        return false;
    identity->kind = FK_OWNER_IDENTITY_FLOW_KEY;
    identity->length = FK_OWNER_FLOW_KEY_IDENTITY_BYTES;
    identity->bytes[0] = key->ip_version;
    identity->bytes[1] = key->protocol;
    std::memcpy(identity->bytes + 2u, key->low_addr, 16u);
    std::memcpy(identity->bytes + 18u, key->high_addr, 16u);
    identity->bytes[34] = static_cast<uint8_t>(key->low_port >> 8u);
    identity->bytes[35] = static_cast<uint8_t>(key->low_port);
    identity->bytes[36] = static_cast<uint8_t>(key->high_port >> 8u);
    identity->bytes[37] = static_cast<uint8_t>(key->high_port);
    return true;
}

bool fk_owner_dispatch_select_owner(
        const fk_owner_dispatch *dispatch,
        const fk_owner_identity *identity,
        uint16_t *owner,
        bool *formal_owner) {
    if (owner != nullptr)
        *owner = UINT16_MAX;
    if (formal_owner != nullptr)
        *formal_owner = false;
    if (dispatch == nullptr || identity == nullptr || owner == nullptr ||
        formal_owner == nullptr)
        return false;
    if (identity->kind == FK_OWNER_IDENTITY_FLOW_KEY) {
        if (identity->length != FK_OWNER_FLOW_KEY_IDENTITY_BYTES)
            return false;
        const uint8_t ip_version = identity->bytes[0];
        const uint8_t protocol = identity->bytes[1];
        if ((ip_version != 4u && ip_version != 6u) ||
            (protocol != 6u && protocol != 17u))
            return false;
        const size_t address_bytes = ip_version == 4u ? 4u : 16u;
        if (ip_version == 4u) {
            for (size_t index = address_bytes; index < 16u; ++index) {
                if (identity->bytes[2u + index] != 0u ||
                    identity->bytes[18u + index] != 0u)
                    return false;
            }
        }
        const int address_order = std::memcmp(
            identity->bytes + 2u,
            identity->bytes + 18u,
            address_bytes);
        const uint16_t low_port = static_cast<uint16_t>(
            (static_cast<uint16_t>(identity->bytes[34]) << 8u) |
            identity->bytes[35]);
        const uint16_t high_port = static_cast<uint16_t>(
            (static_cast<uint16_t>(identity->bytes[36]) << 8u) |
            identity->bytes[37]);
        if (address_order > 0 ||
            (address_order == 0 && low_port > high_port))
            return false;
    } else if (identity->kind == FK_OWNER_IDENTITY_QUIC_INITIAL_CID) {
        if (identity->length == 0u || identity->length > 20u)
            return false;
    } else {
        /* QUIC_LOGICAL is routed from the CID directory's stored fixed owner;
         * it is never re-hashed here. */
        return false;
    }
    const DispatchImpl &state = *implementation(dispatch);
    uint8_t message[2u + FK_OWNER_IDENTITY_MAX_BYTES]{};
    message[0] = identity->kind;
    message[1] = identity->length;
    std::memcpy(message + 2u, identity->bytes, identity->length);
    const uint64_t hash = siphash24(
        state.config.owner_hash_key,
        message,
        static_cast<size_t>(identity->length) + 2u);
    *owner = static_cast<uint16_t>(hash % state.config.worker_count);
    *formal_owner = state.config.owner_hash_key_precommitted;
    return true;
}

static bool packet_valid(
        const fk_owner_packet *packet,
        uint16_t ingress_worker,
        uint16_t owner_worker) {
    const bool identity_valid = packet != nullptr &&
        ((packet->identity_kind == FK_OWNER_IDENTITY_FLOW_KEY &&
          packet->logical_connection_id == 0u &&
          packet->feature_direction == 0u &&
          packet->feature_direction_known == 0u &&
          fk_quic_route_receipt_is_zero(&packet->route_receipt)) ||
         (packet->identity_kind == FK_OWNER_IDENTITY_QUIC_LOGICAL &&
          packet->logical_connection_id != 0u &&
          packet->feature_direction <= 1u &&
          packet->feature_direction_known <= 1u &&
          (packet->feature_direction_known != 0u ||
           packet->feature_direction == 0u) &&
          packet->ingress_worker == ingress_worker &&
          packet->owner_worker == owner_worker &&
          fk_quic_route_receipt_shape_valid(&packet->route_receipt)));
    return identity_valid && packet->packet_handle != 0u &&
        packet->physical_ingress_timestamp_ns != 0u &&
        packet->captured_length != 0u &&
        packet->wire_length >= packet->captured_length &&
        packet->reserved[0] == 0u && packet->reserved[1] == 0u &&
        packet->reserved[2] == 0u && packet->reserved[3] == 0u &&
        packet->reserved[4] == 0u;
}

static fk_owner_envelope data_envelope(
        const fk_owner_packet &packet,
        uint16_t ingress_worker,
        uint16_t owner_worker) {
    fk_owner_envelope envelope{};
    envelope.kind = FK_OWNER_ENVELOPE_DATA;
    envelope.payload.data = packet;
    envelope.payload.data.ingress_worker = ingress_worker;
    envelope.payload.data.owner_worker = owner_worker;
    return envelope;
}

static fk_owner_envelope retire_envelope(
        const fk_owner_quic_retire_control &control) {
    fk_owner_envelope envelope{};
    envelope.kind = FK_OWNER_ENVELOPE_QUIC_RETIRE;
    envelope.payload.quic_retire = control;
    return envelope;
}

static fk_owner_dispatch_result preflight_result(
        DispatchImpl &state,
        const uint64_t needed[64]) {
    const BatchPreflight result = preflight_batch(state, needed);
    if (result == BatchPreflight::Ready)
        return FK_OWNER_DISPATCH_FORWARDED;
    state.atomic_batch_preflight_failures.fetch_add(
        1u, std::memory_order_relaxed);
    if (result == BatchPreflight::Capacity) {
        state.queue_full.fetch_add(1u, std::memory_order_relaxed);
        return FK_OWNER_DISPATCH_QUEUE_FULL;
    }
    state.invalid_routes.fetch_add(1u, std::memory_order_relaxed);
    return FK_OWNER_DISPATCH_INVALID;
}

static bool controls_valid_and_counted(
        const DispatchImpl &state,
        const fk_owner_quic_retire_control *controls,
        size_t control_count,
        bool with_data,
        uint16_t data_owner,
        uint64_t needed[64],
        bool *capacity_impossible) {
    *capacity_impossible = false;
    if ((control_count != 0u && controls == nullptr) ||
        (with_data && data_owner >= state.config.worker_count))
        return false;
    const uint64_t total_capacity =
        static_cast<uint64_t>(state.config.worker_count) *
        state.config.queue_capacity_per_owner;
    if (control_count > total_capacity ||
        (with_data && control_count == total_capacity)) {
        *capacity_impossible = true;
        return true;
    }
    for (size_t index = 0u; index < control_count; ++index) {
        if (!valid_retire_control(state, controls[index]))
            return false;
        const uint16_t owner = controls[index].fixed_owner;
        if (needed[owner] == UINT64_MAX)
            return false;
        needed[owner]++;
    }
    if (with_data) {
        if (needed[data_owner] == UINT64_MAX)
            return false;
        needed[data_owner]++;
    }
    return true;
}

static bool retirement_stream_after(
        DispatchImpl &state,
        const fk_owner_quic_retire_control *controls,
        size_t control_count,
        uint64_t last_after[64],
        uint8_t touched[64]) {
    for (size_t index = 0u; index < control_count; ++index) {
        const uint16_t owner = controls[index].fixed_owner;
        const OwnerQueue &queue = state.queues[owner];
        const bool already_touched = touched[owner] != 0u;
        const bool initialized = already_touched ||
            queue.retirement_ordinal_initialized.load(
                std::memory_order_relaxed) != 0u;
        const uint64_t previous = already_touched ? last_after[owner] :
            queue.last_retirement_ordinal.load(std::memory_order_relaxed);
        if ((!initialized && previous != 0u) ||
            (initialized && previous == 0u) ||
            (initialized &&
             controls[index].retirement_ordinal <= previous)) {
            state.retirement_ordinal_failures.fetch_add(
                1u, std::memory_order_relaxed);
            return false;
        }
        last_after[owner] = controls[index].retirement_ordinal;
        touched[owner] = 1u;
    }
    return true;
}

static void commit_retirement_metadata(
        DispatchImpl &state,
        const uint64_t last_after[64],
        const uint8_t touched[64]) {
    uint64_t maximum = state.maximum_retirement_ordinal_observed.load(
        std::memory_order_relaxed);
    for (uint16_t owner = 0u; owner < state.config.worker_count; ++owner) {
        if (touched[owner] == 0u)
            continue;
        state.queues[owner].last_retirement_ordinal.store(
            last_after[owner], std::memory_order_relaxed);
        state.queues[owner].retirement_ordinal_initialized.store(
            1u, std::memory_order_relaxed);
        if (last_after[owner] > maximum)
            maximum = last_after[owner];
    }
    state.maximum_retirement_ordinal_observed.store(
        maximum, std::memory_order_relaxed);
}

static fk_owner_dispatch_result submit_legacy_impl(
        fk_owner_dispatch *dispatch,
        uint16_t ingress_worker,
        uint16_t owner_worker,
        const fk_owner_packet *packet) {
    if (dispatch == nullptr)
        return FK_OWNER_DISPATCH_INVALID;
    DispatchImpl &state = *implementation(dispatch);
    state.submit_attempts.fetch_add(1u, std::memory_order_relaxed);
    const SubmitReservation reservation = reserve_submitter(state);
    if (reservation == SubmitReservation::Stopped)
        return FK_OWNER_DISPATCH_STOPPED;
    if (reservation != SubmitReservation::Reserved)
        return FK_OWNER_DISPATCH_INVALID;
    const SubmitterGuard submitter_guard(state);
    if (!packet_valid(packet, ingress_worker, owner_worker) ||
        ingress_worker >= state.config.worker_count ||
        owner_worker >= state.config.worker_count) {
        state.invalid_routes.fetch_add(1u, std::memory_order_relaxed);
        return FK_OWNER_DISPATCH_INVALID;
    }
    const ProducerCommitGuard commit_guard(state);
    if (state.observations_sealed.load(std::memory_order_relaxed) != 0u) {
        state.submit_rejected_observations_sealed.fetch_add(
            1u, std::memory_order_relaxed);
        return FK_OWNER_DISPATCH_OBSERVATIONS_SEALED;
    }
    if (ingress_worker == owner_worker) {
        state.local_packets.fetch_add(1u, std::memory_order_relaxed);
        return FK_OWNER_DISPATCH_LOCAL;
    }
    uint64_t needed[64]{};
    needed[owner_worker] = 1u;
    const fk_owner_dispatch_result ready = preflight_result(state, needed);
    if (ready != FK_OWNER_DISPATCH_FORWARDED)
        return ready;
    commit_envelope(
        state,
        owner_worker,
        data_envelope(*packet, ingress_worker, owner_worker),
        false);
    return FK_OWNER_DISPATCH_FORWARDED;
}

fk_owner_dispatch_result fk_owner_dispatch_submit(
        fk_owner_dispatch *dispatch,
        uint16_t ingress_worker,
        uint16_t owner_worker,
        const fk_owner_packet *packet) {
    return submit_legacy_impl(
        dispatch, ingress_worker, owner_worker, packet);
}

fk_owner_dispatch_result fk_owner_dispatch_submit_observation_batch(
        fk_owner_dispatch *dispatch,
        uint16_t ingress_worker,
        uint16_t owner_worker,
        const fk_owner_packet *packet,
        const fk_owner_quic_retire_control *controls,
        size_t control_count) {
    if (dispatch == nullptr)
        return FK_OWNER_DISPATCH_INVALID;
    DispatchImpl &state = *implementation(dispatch);
    state.submit_attempts.fetch_add(1u, std::memory_order_relaxed);
    const SubmitReservation reservation = reserve_submitter(state);
    if (reservation == SubmitReservation::Stopped)
        return FK_OWNER_DISPATCH_STOPPED;
    if (reservation != SubmitReservation::Reserved)
        return FK_OWNER_DISPATCH_INVALID;
    const SubmitterGuard submitter_guard(state);
    if (!packet_valid(packet, ingress_worker, owner_worker) ||
        ingress_worker >= state.config.worker_count ||
        owner_worker >= state.config.worker_count) {
        state.invalid_routes.fetch_add(1u, std::memory_order_relaxed);
        return FK_OWNER_DISPATCH_INVALID;
    }
    uint64_t needed[64]{};
    bool capacity_impossible = false;
    if (!controls_valid_and_counted(
            state, controls, control_count, true, owner_worker,
            needed, &capacity_impossible)) {
        state.invalid_routes.fetch_add(1u, std::memory_order_relaxed);
        return FK_OWNER_DISPATCH_INVALID;
    }
    const ProducerCommitGuard commit_guard(state);
    if (state.observations_sealed.load(std::memory_order_relaxed) != 0u) {
        state.submit_rejected_observations_sealed.fetch_add(
            1u, std::memory_order_relaxed);
        return FK_OWNER_DISPATCH_OBSERVATIONS_SEALED;
    }
    const uint64_t expected = state.next_ordered_sequence.load(
        std::memory_order_relaxed);
    if (expected == UINT64_MAX || packet->packet_sequence != expected) {
        state.ordered_sequence_failures.fetch_add(
            1u, std::memory_order_relaxed);
        state.invalid_routes.fetch_add(1u, std::memory_order_relaxed);
        return FK_OWNER_DISPATCH_INVALID;
    }
    if (capacity_impossible) {
        state.atomic_batch_preflight_failures.fetch_add(
            1u, std::memory_order_relaxed);
        state.queue_full.fetch_add(1u, std::memory_order_relaxed);
        return FK_OWNER_DISPATCH_QUEUE_FULL;
    }
    uint64_t retirement_after[64]{};
    uint8_t retirement_touched[64]{};
    if (!retirement_stream_after(
            state, controls, control_count,
            retirement_after, retirement_touched)) {
        state.invalid_routes.fetch_add(1u, std::memory_order_relaxed);
        return FK_OWNER_DISPATCH_INVALID;
    }
    const fk_owner_dispatch_result ready = preflight_result(state, needed);
    if (ready != FK_OWNER_DISPATCH_FORWARDED)
        return ready;
    for (size_t index = 0u; index < control_count; ++index) {
        commit_envelope(
            state,
            controls[index].fixed_owner,
            retire_envelope(controls[index]),
            false);
    }
    commit_envelope(
        state,
        owner_worker,
        data_envelope(*packet, ingress_worker, owner_worker),
        ingress_worker == owner_worker);
    state.ordered_accepted_packets.fetch_add(
        1u, std::memory_order_relaxed);
    state.next_ordered_sequence.store(
        expected + 1u, std::memory_order_relaxed);
    commit_retirement_metadata(
        state, retirement_after, retirement_touched);
    return FK_OWNER_DISPATCH_FORWARDED;
}

fk_owner_dispatch_result fk_owner_dispatch_submit_ordered(
        fk_owner_dispatch *dispatch,
        uint16_t ingress_worker,
        uint16_t owner_worker,
        const fk_owner_packet *packet) {
    return fk_owner_dispatch_submit_observation_batch(
        dispatch, ingress_worker, owner_worker, packet, nullptr, 0u);
}

fk_owner_dispatch_result
fk_owner_dispatch_submit_skipped_observation_batch(
        fk_owner_dispatch *dispatch,
        uint64_t packet_sequence,
        fk_owner_observation_skip_reason reason,
        const fk_owner_quic_retire_control *controls,
        size_t control_count) {
    if (dispatch == nullptr)
        return FK_OWNER_DISPATCH_INVALID;
    DispatchImpl &state = *implementation(dispatch);
    state.submit_attempts.fetch_add(1u, std::memory_order_relaxed);
    const SubmitReservation reservation = reserve_submitter(state);
    if (reservation == SubmitReservation::Stopped)
        return FK_OWNER_DISPATCH_STOPPED;
    if (reservation != SubmitReservation::Reserved)
        return FK_OWNER_DISPATCH_INVALID;
    const SubmitterGuard submitter_guard(state);
    if (!valid_skip_reason(reason)) {
        state.invalid_routes.fetch_add(1u, std::memory_order_relaxed);
        return FK_OWNER_DISPATCH_INVALID;
    }
    uint64_t needed[64]{};
    bool capacity_impossible = false;
    if (!controls_valid_and_counted(
            state, controls, control_count, false, 0u,
            needed, &capacity_impossible)) {
        state.invalid_routes.fetch_add(1u, std::memory_order_relaxed);
        return FK_OWNER_DISPATCH_INVALID;
    }
    const ProducerCommitGuard commit_guard(state);
    if (state.observations_sealed.load(std::memory_order_relaxed) != 0u) {
        state.submit_rejected_observations_sealed.fetch_add(
            1u, std::memory_order_relaxed);
        return FK_OWNER_DISPATCH_OBSERVATIONS_SEALED;
    }
    const uint64_t expected = state.next_ordered_sequence.load(
        std::memory_order_relaxed);
    if (expected == UINT64_MAX || packet_sequence != expected) {
        state.ordered_sequence_failures.fetch_add(
            1u, std::memory_order_relaxed);
        state.invalid_routes.fetch_add(1u, std::memory_order_relaxed);
        return FK_OWNER_DISPATCH_INVALID;
    }
    if (capacity_impossible) {
        state.atomic_batch_preflight_failures.fetch_add(
            1u, std::memory_order_relaxed);
        state.queue_full.fetch_add(1u, std::memory_order_relaxed);
        return FK_OWNER_DISPATCH_QUEUE_FULL;
    }
    uint64_t retirement_after[64]{};
    uint8_t retirement_touched[64]{};
    if (!retirement_stream_after(
            state, controls, control_count,
            retirement_after, retirement_touched)) {
        state.invalid_routes.fetch_add(1u, std::memory_order_relaxed);
        return FK_OWNER_DISPATCH_INVALID;
    }
    const fk_owner_dispatch_result ready = preflight_result(state, needed);
    if (ready != FK_OWNER_DISPATCH_FORWARDED)
        return ready;
    for (size_t index = 0u; index < control_count; ++index) {
        commit_envelope(
            state,
            controls[index].fixed_owner,
            retire_envelope(controls[index]),
            false);
    }
    commit_retirement_metadata(
        state, retirement_after, retirement_touched);
    record_skip_reason(state, reason);
    state.ordered_skipped_observations.fetch_add(
        1u, std::memory_order_relaxed);
    state.next_ordered_sequence.store(
        expected + 1u, std::memory_order_relaxed);
    return FK_OWNER_DISPATCH_SKIPPED;
}

fk_owner_dispatch_result fk_owner_dispatch_skip_ordered_observation(
        fk_owner_dispatch *dispatch,
        uint64_t packet_sequence,
        fk_owner_observation_skip_reason reason) {
    return fk_owner_dispatch_submit_skipped_observation_batch(
        dispatch, packet_sequence, reason, nullptr, 0u);
}

fk_owner_dispatch_result
fk_owner_dispatch_submit_observation_retire_prefix(
        fk_owner_dispatch *dispatch,
        uint64_t packet_sequence,
        const fk_owner_quic_retire_control *controls,
        size_t control_count) {
    if (dispatch == nullptr)
        return FK_OWNER_DISPATCH_INVALID;
    DispatchImpl &state = *implementation(dispatch);
    state.submit_attempts.fetch_add(1u, std::memory_order_relaxed);
    state.observation_retire_prefix_attempts.fetch_add(
        1u, std::memory_order_relaxed);
    const SubmitReservation reservation = reserve_submitter(state);
    if (reservation == SubmitReservation::Stopped)
        return FK_OWNER_DISPATCH_STOPPED;
    if (reservation != SubmitReservation::Reserved)
        return FK_OWNER_DISPATCH_INVALID;
    const SubmitterGuard submitter_guard(state);
    uint64_t needed[64]{};
    bool capacity_impossible = false;
    if (control_count == 0u || !controls_valid_and_counted(
            state, controls, control_count, false, 0u,
            needed, &capacity_impossible)) {
        state.invalid_routes.fetch_add(1u, std::memory_order_relaxed);
        return FK_OWNER_DISPATCH_INVALID;
    }
    const ProducerCommitGuard commit_guard(state);
    if (state.observations_sealed.load(std::memory_order_relaxed) != 0u) {
        state.submit_rejected_observations_sealed.fetch_add(
            1u, std::memory_order_relaxed);
        return FK_OWNER_DISPATCH_OBSERVATIONS_SEALED;
    }
    const uint64_t expected = state.next_ordered_sequence.load(
        std::memory_order_relaxed);
    if (expected == UINT64_MAX || packet_sequence != expected) {
        state.ordered_sequence_failures.fetch_add(
            1u, std::memory_order_relaxed);
        state.invalid_routes.fetch_add(1u, std::memory_order_relaxed);
        return FK_OWNER_DISPATCH_INVALID;
    }
    if (capacity_impossible) {
        state.atomic_batch_preflight_failures.fetch_add(
            1u, std::memory_order_relaxed);
        state.queue_full.fetch_add(1u, std::memory_order_relaxed);
        return FK_OWNER_DISPATCH_QUEUE_FULL;
    }
    uint64_t retirement_after[64]{};
    uint8_t retirement_touched[64]{};
    if (!retirement_stream_after(
            state, controls, control_count,
            retirement_after, retirement_touched)) {
        state.invalid_routes.fetch_add(1u, std::memory_order_relaxed);
        return FK_OWNER_DISPATCH_INVALID;
    }
    const fk_owner_dispatch_result ready = preflight_result(state, needed);
    if (ready != FK_OWNER_DISPATCH_FORWARDED)
        return ready;
    for (size_t index = 0u; index < control_count; ++index) {
        commit_envelope(
            state,
            controls[index].fixed_owner,
            retire_envelope(controls[index]),
            false);
    }
    commit_retirement_metadata(
        state, retirement_after, retirement_touched);
    state.observation_retire_prefixes_accepted.fetch_add(
        1u, std::memory_order_relaxed);
    return FK_OWNER_DISPATCH_FORWARDED;
}

static bool reserve_seal_operation(DispatchImpl &state) {
    uint64_t observed = state.lifecycle_and_submitters.load(
        std::memory_order_acquire);
    for (;;) {
        if (lifecycle_from_word(observed) != FK_OWNER_DISPATCH_ACCEPTING ||
            (observed & kSubmitterMask) == kSubmitterMask)
            return false;
        if (state.lifecycle_and_submitters.compare_exchange_weak(
                observed,
                observed + 1u,
                std::memory_order_acq_rel,
                std::memory_order_acquire))
            return true;
    }
}

bool fk_owner_dispatch_seal_observations(
        fk_owner_dispatch *dispatch,
        uint64_t expected_next_packet_sequence) {
    if (dispatch == nullptr)
        return false;
    DispatchImpl &state = *implementation(dispatch);
    state.observation_seal_attempts.fetch_add(
        1u, std::memory_order_relaxed);
    if (!reserve_seal_operation(state)) {
        state.observation_seal_failures.fetch_add(
            1u, std::memory_order_relaxed);
        return false;
    }
    const SubmitterGuard submitter_guard(state);
    const ProducerCommitGuard commit_guard(state);
    if (state.observations_sealed.load(std::memory_order_relaxed) != 0u ||
        state.next_ordered_sequence.load(std::memory_order_relaxed) !=
            expected_next_packet_sequence) {
        state.observation_seal_failures.fetch_add(
            1u, std::memory_order_relaxed);
        return false;
    }
    state.observations_sealed.store(1u, std::memory_order_relaxed);
    state.observation_seal_transitions.fetch_add(
        1u, std::memory_order_relaxed);
    return true;
}

fk_owner_dispatch_result fk_owner_dispatch_submit_terminal_retire_batch(
        fk_owner_dispatch *dispatch,
        uint64_t terminal_ordinal,
        const fk_owner_quic_retire_control *controls,
        size_t control_count) {
    if (dispatch == nullptr)
        return FK_OWNER_DISPATCH_INVALID;
    DispatchImpl &state = *implementation(dispatch);
    state.submit_attempts.fetch_add(1u, std::memory_order_relaxed);
    state.terminal_batch_attempts.fetch_add(1u, std::memory_order_relaxed);
    const SubmitReservation reservation = reserve_submitter(state);
    if (reservation == SubmitReservation::Stopped)
        return FK_OWNER_DISPATCH_STOPPED;
    if (reservation != SubmitReservation::Reserved)
        return FK_OWNER_DISPATCH_INVALID;
    const SubmitterGuard submitter_guard(state);
    uint64_t needed[64]{};
    bool capacity_impossible = false;
    if (control_count == 0u || !controls_valid_and_counted(
            state, controls, control_count, false, 0u,
            needed, &capacity_impossible)) {
        state.invalid_routes.fetch_add(1u, std::memory_order_relaxed);
        return FK_OWNER_DISPATCH_INVALID;
    }
    const ProducerCommitGuard commit_guard(state);
    if (state.observations_sealed.load(std::memory_order_relaxed) == 0u) {
        state.terminal_ordinal_failures.fetch_add(
            1u, std::memory_order_relaxed);
        state.invalid_routes.fetch_add(1u, std::memory_order_relaxed);
        return FK_OWNER_DISPATCH_INVALID;
    }
    const uint64_t expected_terminal = state.next_terminal_ordinal.load(
        std::memory_order_relaxed);
    if (expected_terminal == UINT64_MAX ||
        terminal_ordinal != expected_terminal) {
        state.terminal_ordinal_failures.fetch_add(
            1u, std::memory_order_relaxed);
        state.invalid_routes.fetch_add(1u, std::memory_order_relaxed);
        return FK_OWNER_DISPATCH_INVALID;
    }
    if (capacity_impossible) {
        state.atomic_batch_preflight_failures.fetch_add(
            1u, std::memory_order_relaxed);
        state.queue_full.fetch_add(1u, std::memory_order_relaxed);
        return FK_OWNER_DISPATCH_QUEUE_FULL;
    }
    uint64_t retirement_after[64]{};
    uint8_t retirement_touched[64]{};
    if (!retirement_stream_after(
            state, controls, control_count,
            retirement_after, retirement_touched)) {
        state.invalid_routes.fetch_add(1u, std::memory_order_relaxed);
        return FK_OWNER_DISPATCH_INVALID;
    }
    const fk_owner_dispatch_result ready = preflight_result(state, needed);
    if (ready != FK_OWNER_DISPATCH_FORWARDED)
        return ready;
    for (size_t index = 0u; index < control_count; ++index) {
        commit_envelope(
            state,
            controls[index].fixed_owner,
            retire_envelope(controls[index]),
            false);
    }
    commit_retirement_metadata(
        state, retirement_after, retirement_touched);
    state.terminal_batches_accepted.fetch_add(
        1u, std::memory_order_relaxed);
    state.next_terminal_ordinal.store(
        expected_terminal + 1u, std::memory_order_relaxed);
    return FK_OWNER_DISPATCH_FORWARDED;
}

static bool remove_envelope(
        fk_owner_dispatch *dispatch,
        uint16_t owner_worker,
        fk_owner_envelope *envelope,
        bool draining) {
    if (dispatch == nullptr || envelope == nullptr)
        return false;
    DispatchImpl &state = *implementation(dispatch);
    if (owner_worker >= state.config.worker_count) {
        state.invalid_routes.fetch_add(1u, std::memory_order_relaxed);
        return false;
    }
    const uint64_t lifecycle_word = state.lifecycle_and_submitters.load(
        std::memory_order_acquire);
    const fk_owner_dispatch_lifecycle lifecycle =
        lifecycle_from_word(lifecycle_word);
    if (draining) {
        /* Drain starts only after admission and every reserved submit ended. */
        if (lifecycle == FK_OWNER_DISPATCH_ACCEPTING ||
            (lifecycle_word & kSubmitterMask) != 0u)
            return false;
    } else if (lifecycle == FK_OWNER_DISPATCH_ABORTED) {
        return false;
    }
    if (!dequeue_envelope(state.queues[owner_worker], *envelope))
        return false;
    OwnerQueue &queue = state.queues[owner_worker];
    if (envelope->kind == FK_OWNER_ENVELOPE_DATA) {
        const fk_owner_packet &packet = envelope->payload.data;
        if (packet.owner_worker != owner_worker)
            state.invalid_routes.fetch_add(1u, std::memory_order_relaxed);
        const bool local_route = packet.ingress_worker == owner_worker;
        state.queued_dequeued.fetch_add(1u, std::memory_order_relaxed);
        queue.dequeued.fetch_add(1u, std::memory_order_relaxed);
        if (local_route) {
            state.local_dequeued.fetch_add(1u, std::memory_order_relaxed);
            queue.local_dequeued.fetch_add(1u, std::memory_order_relaxed);
        } else {
            state.remote_dequeued.fetch_add(1u, std::memory_order_relaxed);
            queue.remote_dequeued.fetch_add(1u, std::memory_order_relaxed);
        }
        if (draining) {
            state.drained.fetch_add(1u, std::memory_order_relaxed);
            queue.drained.fetch_add(1u, std::memory_order_relaxed);
        } else {
            state.normal_dequeued.fetch_add(1u, std::memory_order_relaxed);
            queue.normal_dequeued.fetch_add(1u, std::memory_order_relaxed);
        }
        state.total_depth.fetch_sub(1u, std::memory_order_relaxed);
    } else if (envelope->kind == FK_OWNER_ENVELOPE_QUIC_RETIRE) {
        const fk_owner_quic_retire_control &control =
            envelope->payload.quic_retire;
        if (!valid_retire_control(state, control) ||
            control.fixed_owner != owner_worker)
            state.invalid_routes.fetch_add(1u, std::memory_order_relaxed);
        state.retire_controls_dequeued.fetch_add(
            1u, std::memory_order_relaxed);
        queue.retire_controls_dequeued.fetch_add(
            1u, std::memory_order_relaxed);
        if (draining) {
            state.retire_controls_drained.fetch_add(
                1u, std::memory_order_relaxed);
            queue.retire_controls_drained.fetch_add(
                1u, std::memory_order_relaxed);
        } else {
            state.retire_controls_normal_dequeued.fetch_add(
                1u, std::memory_order_relaxed);
            queue.retire_controls_normal_dequeued.fetch_add(
                1u, std::memory_order_relaxed);
        }
        state.retire_control_depth.fetch_sub(
            1u, std::memory_order_relaxed);
        queue.retire_control_depth.fetch_sub(
            1u, std::memory_order_relaxed);
    } else {
        state.invalid_routes.fetch_add(1u, std::memory_order_relaxed);
    }
    queue.depth.fetch_sub(
        1u, std::memory_order_relaxed);
    /* Last dispatcher access: reaching zero proves every envelope has left its
     * ring and all kind-specific removal accounting is globally visible. */
    state.total_envelope_depth.fetch_sub(1u, std::memory_order_release);
    return true;
}

bool fk_owner_dispatch_dequeue_envelope(
        fk_owner_dispatch *dispatch,
        uint16_t owner_worker,
        fk_owner_envelope *envelope) {
    return remove_envelope(dispatch, owner_worker, envelope, false);
}

bool fk_owner_dispatch_dequeue(
        fk_owner_dispatch *dispatch,
        uint16_t owner_worker,
        fk_owner_packet *packet) {
    if (dispatch == nullptr || packet == nullptr)
        return false;
    DispatchImpl &state = *implementation(dispatch);
    if (owner_worker >= state.config.worker_count) {
        state.invalid_routes.fetch_add(1u, std::memory_order_relaxed);
        return false;
    }
    fk_owner_envelope_kind kind = FK_OWNER_ENVELOPE_DATA;
    if (!front_kind(state.queues[owner_worker], kind) ||
        kind != FK_OWNER_ENVELOPE_DATA)
        return false;
    fk_owner_envelope envelope{};
    if (!remove_envelope(dispatch, owner_worker, &envelope, false))
        return false;
    *packet = envelope.payload.data;
    return true;
}

bool fk_owner_dispatch_drain_next(
        fk_owner_dispatch *dispatch,
        uint16_t owner_worker,
        fk_owner_packet *packet) {
    if (dispatch == nullptr || packet == nullptr)
        return false;
    DispatchImpl &state = *implementation(dispatch);
    if (owner_worker >= state.config.worker_count) {
        state.invalid_routes.fetch_add(1u, std::memory_order_relaxed);
        return false;
    }
    fk_owner_envelope_kind kind = FK_OWNER_ENVELOPE_DATA;
    if (!front_kind(state.queues[owner_worker], kind) ||
        kind != FK_OWNER_ENVELOPE_DATA)
        return false;
    fk_owner_envelope envelope{};
    if (!remove_envelope(dispatch, owner_worker, &envelope, true))
        return false;
    *packet = envelope.payload.data;
    return true;
}

bool fk_owner_dispatch_drain_next_envelope(
        fk_owner_dispatch *dispatch,
        uint16_t owner_worker,
        fk_owner_envelope *envelope) {
    return remove_envelope(dispatch, owner_worker, envelope, true);
}

bool fk_owner_dispatch_owned_packets(
        const fk_owner_dispatch *dispatch,
        uint64_t *owned_packets) {
    if (owned_packets != nullptr)
        *owned_packets = 0u;
    if (dispatch == nullptr || owned_packets == nullptr)
        return false;
    *owned_packets = implementation(dispatch)->total_depth.load(
        std::memory_order_acquire);
    return true;
}

bool fk_owner_dispatch_drain_complete(
        const fk_owner_dispatch *dispatch) {
    if (dispatch == nullptr)
        return false;
    const DispatchImpl &state = *implementation(dispatch);
    const uint64_t word = state.lifecycle_and_submitters.load(
        std::memory_order_acquire);
    if (lifecycle_from_word(word) == FK_OWNER_DISPATCH_ACCEPTING ||
        (word & kSubmitterMask) != 0u)
        return false;
    const uint64_t accepted = state.queued_enqueued.load(
        std::memory_order_acquire);
    const uint64_t dequeued = state.queued_dequeued.load(
        std::memory_order_acquire);
    const uint64_t normal_dequeued = state.normal_dequeued.load(
        std::memory_order_acquire);
    const uint64_t drained = state.drained.load(std::memory_order_acquire);
    const uint64_t owned = state.total_depth.load(std::memory_order_acquire);
    const uint64_t controls_enqueued = state.retire_controls_enqueued.load(
        std::memory_order_acquire);
    const uint64_t controls_dequeued = state.retire_controls_dequeued.load(
        std::memory_order_acquire);
    const uint64_t controls_normal =
        state.retire_controls_normal_dequeued.load(std::memory_order_acquire);
    const uint64_t controls_drained = state.retire_controls_drained.load(
        std::memory_order_acquire);
    const uint64_t control_depth = state.retire_control_depth.load(
        std::memory_order_acquire);
    if (owned != 0u || control_depth != 0u || accepted != dequeued ||
        controls_enqueued != controls_dequeued ||
        state.total_envelope_depth.load(std::memory_order_acquire) != 0u ||
        !ownership_conserved_values(
            accepted, normal_dequeued, drained, owned) ||
        !retire_controls_conserved_values(
            controls_enqueued, controls_normal, controls_drained,
            control_depth))
        return false;
    for (uint16_t owner = 0u; owner < state.config.worker_count; ++owner) {
        const OwnerQueue &queue = state.queues[owner];
        const uint64_t enqueued = queue.enqueued.load(
            std::memory_order_acquire);
        const uint64_t dequeued = queue.dequeued.load(
            std::memory_order_acquire);
        const uint64_t normal = queue.normal_dequeued.load(
            std::memory_order_acquire);
        const uint64_t owner_drained = queue.drained.load(
            std::memory_order_acquire);
        const uint64_t controls = queue.retire_controls_enqueued.load(
            std::memory_order_acquire);
        const uint64_t controls_dequeued =
            queue.retire_controls_dequeued.load(std::memory_order_acquire);
        const uint64_t controls_normal =
            queue.retire_controls_normal_dequeued.load(
                std::memory_order_acquire);
        const uint64_t controls_drained =
            queue.retire_controls_drained.load(std::memory_order_acquire);
        const uint64_t controls_depth = queue.retire_control_depth.load(
            std::memory_order_acquire);
        if (queue.depth.load(std::memory_order_acquire) != 0u ||
            enqueued != dequeued || normal > dequeued ||
            owner_drained != dequeued - normal ||
            controls != controls_dequeued ||
            !retire_controls_conserved_values(
                controls, controls_normal, controls_drained, controls_depth))
            return false;
    }
    return true;
}

bool fk_owner_dispatch_get_stats(
        const fk_owner_dispatch *dispatch,
        fk_owner_dispatch_stats *stats) {
    if (dispatch == nullptr || stats == nullptr)
        return false;
    const DispatchImpl &state = *implementation(dispatch);
    stats->submit_attempts =
        state.submit_attempts.load(std::memory_order_acquire);
    stats->local_packets =
        state.local_packets.load(std::memory_order_acquire);
    stats->local_enqueued =
        state.local_enqueued.load(std::memory_order_acquire);
    stats->local_dequeued =
        state.local_dequeued.load(std::memory_order_acquire);
    stats->remote_enqueued =
        state.remote_enqueued.load(std::memory_order_acquire);
    stats->remote_dequeued =
        state.remote_dequeued.load(std::memory_order_acquire);
    stats->queued_enqueued =
        state.queued_enqueued.load(std::memory_order_acquire);
    stats->queued_dequeued =
        state.queued_dequeued.load(std::memory_order_acquire);
    stats->ordered_accepted_packets =
        state.ordered_accepted_packets.load(std::memory_order_acquire);
    stats->ordered_skipped_observations =
        state.ordered_skipped_observations.load(std::memory_order_acquire);
    stats->ordered_skipped_filtered =
        state.ordered_skipped_filtered.load(std::memory_order_acquire);
    stats->ordered_skipped_parse_rejected =
        state.ordered_skipped_parse_rejected.load(
            std::memory_order_acquire);
    stats->ordered_skipped_unresolved_identity =
        state.ordered_skipped_unresolved_identity.load(
            std::memory_order_acquire);
    stats->ordered_skipped_capture_truncated =
        state.ordered_skipped_capture_truncated.load(
            std::memory_order_acquire);
    stats->ordered_skipped_unsupported_packet =
        state.ordered_skipped_unsupported_packet.load(
            std::memory_order_acquire);
    stats->next_ordered_sequence =
        state.next_ordered_sequence.load(std::memory_order_acquire);
    stats->ordered_sequence_failures =
        state.ordered_sequence_failures.load(std::memory_order_acquire);
    stats->retire_controls_enqueued =
        state.retire_controls_enqueued.load(std::memory_order_acquire);
    stats->retire_controls_dequeued =
        state.retire_controls_dequeued.load(std::memory_order_acquire);
    stats->retire_controls_normal_dequeued =
        state.retire_controls_normal_dequeued.load(
            std::memory_order_acquire);
    stats->retire_controls_drained =
        state.retire_controls_drained.load(std::memory_order_acquire);
    stats->retire_control_depth =
        state.retire_control_depth.load(std::memory_order_acquire);
    stats->peak_retire_control_depth =
        state.peak_retire_control_depth.load(std::memory_order_acquire);
    stats->envelope_depth =
        state.total_envelope_depth.load(std::memory_order_acquire);
    stats->peak_envelope_depth =
        state.peak_envelope_depth.load(std::memory_order_acquire);
    stats->maximum_retirement_ordinal_observed =
        state.maximum_retirement_ordinal_observed.load(
            std::memory_order_acquire);
    stats->retirement_ordinal_failures =
        state.retirement_ordinal_failures.load(std::memory_order_acquire);
    stats->observation_retire_prefix_attempts =
        state.observation_retire_prefix_attempts.load(
            std::memory_order_acquire);
    stats->observation_retire_prefixes_accepted =
        state.observation_retire_prefixes_accepted.load(
            std::memory_order_acquire);
    stats->terminal_batch_attempts =
        state.terminal_batch_attempts.load(std::memory_order_acquire);
    stats->terminal_batches_accepted =
        state.terminal_batches_accepted.load(std::memory_order_acquire);
    stats->next_terminal_ordinal =
        state.next_terminal_ordinal.load(std::memory_order_acquire);
    stats->terminal_ordinal_failures =
        state.terminal_ordinal_failures.load(std::memory_order_acquire);
    stats->observation_seal_attempts =
        state.observation_seal_attempts.load(std::memory_order_acquire);
    stats->observation_seal_transitions =
        state.observation_seal_transitions.load(std::memory_order_acquire);
    stats->observation_seal_failures =
        state.observation_seal_failures.load(std::memory_order_acquire);
    stats->submit_rejected_observations_sealed =
        state.submit_rejected_observations_sealed.load(
            std::memory_order_acquire);
    stats->atomic_batch_preflight_failures =
        state.atomic_batch_preflight_failures.load(
            std::memory_order_acquire);
    stats->queue_full = state.queue_full.load(std::memory_order_acquire);
    stats->invalid_routes =
        state.invalid_routes.load(std::memory_order_acquire);
    stats->total_depth =
        state.total_depth.load(std::memory_order_acquire);
    stats->peak_total_depth =
        state.peak_total_depth.load(std::memory_order_acquire);
    stats->reserved_bytes = state.reserved_bytes;
    stats->worker_count = state.config.worker_count;
    stats->queue_capacity_per_owner =
        state.config.queue_capacity_per_owner;
    stats->accepted_packets = stats->queued_enqueued;
    stats->dequeued_packets = state.normal_dequeued.load(
        std::memory_order_acquire);
    stats->drained_packets = state.drained.load(
        std::memory_order_acquire);
    stats->owned_packets = stats->total_depth;
    const uint64_t lifecycle_word = state.lifecycle_and_submitters.load(
        std::memory_order_acquire);
    stats->in_flight_submitters = lifecycle_word & kSubmitterMask;
    stats->stop_attempts = state.stop_attempts.load(
        std::memory_order_acquire);
    stats->stop_transitions = state.stop_transitions.load(
        std::memory_order_acquire);
    stats->abort_attempts = state.abort_attempts.load(
        std::memory_order_acquire);
    stats->abort_transitions = state.abort_transitions.load(
        std::memory_order_acquire);
    stats->submit_rejected_stopped =
        state.submit_rejected_stopped.load(std::memory_order_acquire);
    stats->submit_rejected_aborted =
        state.submit_rejected_aborted.load(std::memory_order_acquire);
    stats->destroy_rejected_live_ownership =
        state.destroy_rejected_live_ownership.load(
            std::memory_order_acquire);
    stats->lifecycle = lifecycle_from_word(lifecycle_word);
    stats->ownership_conserved = ownership_conserved_values(
        stats->accepted_packets,
        stats->dequeued_packets,
        stats->drained_packets,
        stats->owned_packets);
    stats->retire_controls_conserved = retire_controls_conserved_values(
        stats->retire_controls_enqueued,
        stats->retire_controls_normal_dequeued,
        stats->retire_controls_drained,
        stats->retire_control_depth);
    uint64_t skip_reason_sum = 0u;
    stats->ordered_skip_reasons_conserved =
        checked_sum(skip_reason_sum, stats->ordered_skipped_filtered,
            skip_reason_sum) &&
        checked_sum(skip_reason_sum, stats->ordered_skipped_parse_rejected,
            skip_reason_sum) &&
        checked_sum(skip_reason_sum,
            stats->ordered_skipped_unresolved_identity,
            skip_reason_sum) &&
        checked_sum(skip_reason_sum,
            stats->ordered_skipped_capture_truncated,
            skip_reason_sum) &&
        checked_sum(skip_reason_sum,
            stats->ordered_skipped_unsupported_packet,
            skip_reason_sum) &&
        skip_reason_sum == stats->ordered_skipped_observations;
    uint64_t accounted_observations = 0u;
    stats->ordered_observation_accounting_conserved =
        checked_sum(
            stats->ordered_accepted_packets,
            stats->ordered_skipped_observations,
            accounted_observations) &&
        accounted_observations == stats->next_ordered_sequence;
    stats->observations_sealed =
        state.observations_sealed.load(std::memory_order_acquire) != 0u;
    return true;
}

bool fk_owner_dispatch_get_owner_stats(
        const fk_owner_dispatch *dispatch,
        uint16_t owner_worker,
        fk_owner_dispatch_owner_stats *stats) {
    if (dispatch == nullptr || stats == nullptr)
        return false;
    const DispatchImpl &state = *implementation(dispatch);
    if (owner_worker >= state.config.worker_count)
        return false;
    const OwnerQueue &queue = state.queues[owner_worker];
    stats->local_enqueued =
        queue.local_enqueued.load(std::memory_order_acquire);
    stats->local_dequeued =
        queue.local_dequeued.load(std::memory_order_acquire);
    stats->remote_enqueued =
        queue.remote_enqueued.load(std::memory_order_acquire);
    stats->remote_dequeued =
        queue.remote_dequeued.load(std::memory_order_acquire);
    stats->queued_enqueued =
        queue.enqueued.load(std::memory_order_acquire);
    stats->queued_dequeued =
        queue.dequeued.load(std::memory_order_acquire);
    stats->depth = queue.depth.load(std::memory_order_acquire);
    stats->peak_depth = queue.peak_depth.load(std::memory_order_acquire);
    stats->owner_worker = owner_worker;
    stats->queue_capacity = state.config.queue_capacity_per_owner;
    stats->dequeued_packets = queue.normal_dequeued.load(
        std::memory_order_acquire);
    stats->drained_packets = queue.drained.load(
        std::memory_order_acquire);
    stats->retire_controls_enqueued =
        queue.retire_controls_enqueued.load(std::memory_order_acquire);
    stats->retire_controls_dequeued =
        queue.retire_controls_dequeued.load(std::memory_order_acquire);
    stats->retire_controls_normal_dequeued =
        queue.retire_controls_normal_dequeued.load(
            std::memory_order_acquire);
    stats->retire_controls_drained =
        queue.retire_controls_drained.load(std::memory_order_acquire);
    stats->retire_control_depth =
        queue.retire_control_depth.load(std::memory_order_acquire);
    stats->last_retirement_ordinal =
        queue.last_retirement_ordinal.load(std::memory_order_acquire);
    stats->retirement_ordinal_initialized =
        queue.retirement_ordinal_initialized.load(
            std::memory_order_acquire) != 0u;
    return true;
}

bool fk_owner_dispatch_formal_complete(
        const fk_owner_dispatch *dispatch) {
    fk_owner_dispatch_stats stats{};
    if (!fk_owner_dispatch_get_stats(dispatch, &stats) ||
        stats.lifecycle != FK_OWNER_DISPATCH_STOPPED_NORMAL ||
        stats.in_flight_submitters != 0u ||
        stats.stop_transitions != 1u || stats.abort_transitions != 0u ||
        stats.submit_rejected_stopped != 0u ||
        stats.submit_rejected_aborted != 0u ||
        stats.submit_rejected_observations_sealed != 0u ||
        stats.ordered_sequence_failures != 0u ||
        stats.retirement_ordinal_failures != 0u ||
        stats.observation_retire_prefix_attempts !=
            stats.observation_retire_prefixes_accepted ||
        stats.terminal_ordinal_failures != 0u ||
        stats.atomic_batch_preflight_failures != 0u ||
        stats.destroy_rejected_live_ownership != 0u ||
        !stats.observations_sealed ||
        stats.observation_seal_attempts != 1u ||
        stats.observation_seal_transitions != 1u ||
        stats.observation_seal_failures != 0u ||
        stats.ordered_skipped_observations != 0u ||
        !stats.ordered_skip_reasons_conserved ||
        !stats.ordered_observation_accounting_conserved ||
        /* Exact identity mode forbids the legacy local bypass. */
        stats.local_packets != 0u ||
        stats.queue_full != 0u || stats.invalid_routes != 0u ||
        stats.total_depth != 0u || stats.retire_control_depth != 0u ||
        stats.envelope_depth != 0u ||
        !stats.ownership_conserved || stats.drained_packets != 0u ||
        !stats.retire_controls_conserved ||
        stats.retire_controls_drained != 0u ||
        stats.accepted_packets != stats.dequeued_packets ||
        stats.ordered_accepted_packets != stats.accepted_packets ||
        stats.next_ordered_sequence != stats.ordered_accepted_packets ||
        stats.queued_enqueued != stats.queued_dequeued ||
        stats.retire_controls_enqueued !=
            stats.retire_controls_dequeued ||
        stats.retire_controls_enqueued !=
            stats.retire_controls_normal_dequeued ||
        stats.remote_enqueued != stats.remote_dequeued ||
        stats.local_enqueued != stats.local_dequeued ||
        stats.terminal_batch_attempts !=
            stats.terminal_batches_accepted ||
        stats.next_terminal_ordinal !=
            stats.terminal_batches_accepted ||
        (stats.retire_controls_enqueued == 0u &&
         stats.maximum_retirement_ordinal_observed != 0u) ||
        (stats.retire_controls_enqueued != 0u &&
         stats.maximum_retirement_ordinal_observed == 0u) ||
        stats.remote_enqueued >
            UINT64_MAX - stats.local_enqueued ||
        stats.remote_enqueued + stats.local_enqueued !=
            stats.queued_enqueued)
        return false;
    uint64_t accounted_attempts = 0u;
    const uint64_t attempt_categories[] = {
        stats.local_packets,
        stats.queued_enqueued,
        stats.ordered_skipped_observations,
        stats.observation_retire_prefixes_accepted,
        stats.terminal_batches_accepted,
        stats.queue_full,
        stats.invalid_routes,
        stats.submit_rejected_observations_sealed,
        stats.submit_rejected_stopped,
        stats.submit_rejected_aborted,
    };
    for (const uint64_t category : attempt_categories) {
        if (category > UINT64_MAX - accounted_attempts)
            return false;
        accounted_attempts += category;
    }
    if (stats.submit_attempts != accounted_attempts)
        return false;
    uint64_t owner_queued_enqueued = 0u;
    uint64_t owner_queued_dequeued = 0u;
    uint64_t owner_local_enqueued = 0u;
    uint64_t owner_local_dequeued = 0u;
    uint64_t owner_remote_enqueued = 0u;
    uint64_t owner_remote_dequeued = 0u;
    uint64_t owner_depth = 0u;
    uint64_t owner_normal_dequeued = 0u;
    uint64_t owner_drained = 0u;
    uint64_t owner_retire_enqueued = 0u;
    uint64_t owner_retire_dequeued = 0u;
    uint64_t owner_retire_normal = 0u;
    uint64_t owner_retire_drained = 0u;
    uint64_t owner_retire_depth = 0u;
    uint64_t owner_maximum_retirement_ordinal = 0u;
    for (uint16_t owner = 0u; owner < stats.worker_count; ++owner) {
        fk_owner_dispatch_owner_stats per_owner{};
        if (!fk_owner_dispatch_get_owner_stats(
                dispatch, owner, &per_owner) ||
            per_owner.queued_enqueued >
                UINT64_MAX - owner_queued_enqueued ||
            per_owner.queued_dequeued >
                UINT64_MAX - owner_queued_dequeued ||
            per_owner.local_enqueued >
                UINT64_MAX - owner_local_enqueued ||
            per_owner.local_dequeued >
                UINT64_MAX - owner_local_dequeued ||
            per_owner.remote_enqueued >
                UINT64_MAX - owner_remote_enqueued ||
            per_owner.remote_dequeued >
                UINT64_MAX - owner_remote_dequeued ||
            per_owner.depth > UINT64_MAX - owner_depth ||
            per_owner.dequeued_packets >
                UINT64_MAX - owner_normal_dequeued ||
            per_owner.drained_packets > UINT64_MAX - owner_drained ||
            per_owner.retire_controls_enqueued >
                UINT64_MAX - owner_retire_enqueued ||
            per_owner.retire_controls_dequeued >
                UINT64_MAX - owner_retire_dequeued ||
            per_owner.retire_controls_normal_dequeued >
                UINT64_MAX - owner_retire_normal ||
            per_owner.retire_controls_drained >
                UINT64_MAX - owner_retire_drained ||
            per_owner.retire_control_depth >
                UINT64_MAX - owner_retire_depth ||
            (per_owner.retire_controls_enqueued == 0u &&
             (per_owner.retirement_ordinal_initialized ||
              per_owner.last_retirement_ordinal != 0u)) ||
            (per_owner.retire_controls_enqueued != 0u &&
             (!per_owner.retirement_ordinal_initialized ||
              per_owner.last_retirement_ordinal == 0u)))
            return false;
        owner_queued_enqueued += per_owner.queued_enqueued;
        owner_queued_dequeued += per_owner.queued_dequeued;
        owner_local_enqueued += per_owner.local_enqueued;
        owner_local_dequeued += per_owner.local_dequeued;
        owner_remote_enqueued += per_owner.remote_enqueued;
        owner_remote_dequeued += per_owner.remote_dequeued;
        owner_depth += per_owner.depth;
        owner_normal_dequeued += per_owner.dequeued_packets;
        owner_drained += per_owner.drained_packets;
        owner_retire_enqueued += per_owner.retire_controls_enqueued;
        owner_retire_dequeued += per_owner.retire_controls_dequeued;
        owner_retire_normal +=
            per_owner.retire_controls_normal_dequeued;
        owner_retire_drained += per_owner.retire_controls_drained;
        owner_retire_depth += per_owner.retire_control_depth;
        if (per_owner.last_retirement_ordinal >
                owner_maximum_retirement_ordinal) {
            owner_maximum_retirement_ordinal =
                per_owner.last_retirement_ordinal;
        }
    }
    return owner_queued_enqueued == stats.queued_enqueued &&
        owner_queued_dequeued == stats.queued_dequeued &&
        owner_local_enqueued == stats.local_enqueued &&
        owner_local_dequeued == stats.local_dequeued &&
        owner_remote_enqueued == stats.remote_enqueued &&
        owner_remote_dequeued == stats.remote_dequeued &&
        owner_depth == stats.envelope_depth &&
        owner_normal_dequeued == stats.dequeued_packets &&
        owner_drained == stats.drained_packets &&
        owner_retire_enqueued == stats.retire_controls_enqueued &&
        owner_retire_dequeued == stats.retire_controls_dequeued &&
        owner_retire_normal == stats.retire_controls_normal_dequeued &&
        owner_retire_drained == stats.retire_controls_drained &&
        owner_retire_depth == stats.retire_control_depth &&
        owner_maximum_retirement_ordinal ==
            stats.maximum_retirement_ordinal_observed;
}

fk_owner_consistency_gate_result fk_owner_consistency_gate_evaluate(
        const fk_owner_consistency_gate_input *input) {
    fk_owner_consistency_gate_result result{};
    result.blocker = FK_OWNER_CONSISTENCY_BLOCKER_INVALID_TOPOLOGY;
    if (input == nullptr || input->worker_count == 0u)
        return result;
    if (input->worker_count == 1u) {
        result.passed = true;
        result.blocker = FK_OWNER_CONSISTENCY_BLOCKER_NONE;
        return result;
    }
    if (!input->software_dispatch_connected) {
        if (input->quic_migration_in_scope) {
            result.blocker =
                FK_OWNER_CONSISTENCY_BLOCKER_MIGRATION_REQUIRES_DISPATCH;
            return result;
        }
        if (!input->symmetric_rss_verified) {
            result.blocker =
                FK_OWNER_CONSISTENCY_BLOCKER_NO_VERIFIED_MECHANISM;
            return result;
        }
        result.passed = true;
        result.blocker = FK_OWNER_CONSISTENCY_BLOCKER_NONE;
        return result;
    }
    if (!input->stable_logical_identity_connected ||
        input->unresolved_quic_packets != 0u) {
        result.blocker = FK_OWNER_CONSISTENCY_BLOCKER_STABLE_IDENTITY;
        return result;
    }
    if (!input->owner_hash_key_precommitted) {
        result.blocker =
            FK_OWNER_CONSISTENCY_BLOCKER_HASH_KEY_NOT_PRECOMMITTED;
        return result;
    }
    if (!input->dispatch_reserved_inside_bounded_service_ceiling) {
        result.blocker =
            FK_OWNER_CONSISTENCY_BLOCKER_DISPATCH_NOT_IN_SERVICE_CEILING;
        return result;
    }
    if (input->queue_full != 0u || input->invalid_routes != 0u) {
        result.blocker = FK_OWNER_CONSISTENCY_BLOCKER_DISPATCH_LOSS;
        return result;
    }
    if (input->remote_enqueued != input->remote_dequeued ||
        input->local_enqueued != input->local_dequeued ||
        input->dispatch_depth_end != 0u) {
        result.blocker = FK_OWNER_CONSISTENCY_BLOCKER_DISPATCH_NOT_DRAINED;
        return result;
    }
    if (input->remote_dequeued >
            UINT64_MAX - input->local_dequeued ||
        input->dequeued_state_processed !=
            input->remote_dequeued + input->local_dequeued) {
        result.blocker =
            FK_OWNER_CONSISTENCY_BLOCKER_STATE_PROCESSING_INCOMPLETE;
        return result;
    }
    if (input->owner_violations != 0u) {
        result.blocker = FK_OWNER_CONSISTENCY_BLOCKER_OWNER_VIOLATION;
        return result;
    }
    result.passed = true;
    result.blocker = FK_OWNER_CONSISTENCY_BLOCKER_NONE;
    return result;
}

const char *fk_owner_consistency_blocker_name(
        fk_owner_consistency_blocker blocker) {
    switch (blocker) {
    case FK_OWNER_CONSISTENCY_BLOCKER_NONE:
        return "none";
    case FK_OWNER_CONSISTENCY_BLOCKER_INVALID_TOPOLOGY:
        return "owner_topology_invalid";
    case FK_OWNER_CONSISTENCY_BLOCKER_MIGRATION_REQUIRES_DISPATCH:
        return "QUIC_migration_requires_software_owner_dispatch";
    case FK_OWNER_CONSISTENCY_BLOCKER_NO_VERIFIED_MECHANISM:
        return "no_verified_owner_consistency_mechanism";
    case FK_OWNER_CONSISTENCY_BLOCKER_STABLE_IDENTITY:
        return "stable_QUIC_logical_identity_incomplete";
    case FK_OWNER_CONSISTENCY_BLOCKER_HASH_KEY_NOT_PRECOMMITTED:
        return "owner_hash_key_not_precommitted";
    case FK_OWNER_CONSISTENCY_BLOCKER_DISPATCH_NOT_IN_SERVICE_CEILING:
        return "owner_dispatch_not_in_bounded_service_ceiling";
    case FK_OWNER_CONSISTENCY_BLOCKER_DISPATCH_LOSS:
        return "owner_dispatch_loss_or_invalid_route";
    case FK_OWNER_CONSISTENCY_BLOCKER_DISPATCH_NOT_DRAINED:
        return "owner_dispatch_not_drained";
    case FK_OWNER_CONSISTENCY_BLOCKER_STATE_PROCESSING_INCOMPLETE:
        return "owner_dequeued_packet_not_state_processed";
    case FK_OWNER_CONSISTENCY_BLOCKER_OWNER_VIOLATION:
        return "logical_connection_owner_violation";
    }
    return "unknown_owner_consistency_blocker";
}

}  // extern "C"
