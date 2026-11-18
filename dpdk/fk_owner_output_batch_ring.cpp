#include "fk_owner_output_batch_ring.h"

#include <atomic>
#include <cstddef>
#include <cstring>
#include <limits>
#include <new>

namespace {

struct RingState {
    fk_owner_output_batch_ring_config config;
    fk_owner_runtime_output_batch_v2 *cells;
    size_t reserved_bytes;
    size_t metadata_bytes;
    size_t batch_storage_bytes;

    std::atomic<uint64_t> head;
    std::atomic<uint64_t> tail;
    /* High bit seals admission; low 63 bits count in-flight enqueues. */
    std::atomic<uint64_t> lifecycle_and_producers;
    std::atomic<uint64_t> producer_thread_token;

    std::atomic<uint64_t> pending_commit_ordinal;
    std::atomic<uint64_t> pending_transaction_epoch;
    std::atomic<uint64_t> last_transaction_epoch;
    std::atomic<uint64_t> next_commit_ordinal;

    std::atomic<uint64_t> enqueue_attempts;
    std::atomic<uint64_t> accepted_batches;
    std::atomic<uint64_t> full_rejections;
    std::atomic<uint64_t> stopped_rejections;
    std::atomic<uint64_t> invalid_enqueue_rejections;
    std::atomic<uint64_t> transaction_replay_rejections;
    std::atomic<uint64_t> commit_ack_required_rejections;
    std::atomic<uint64_t> producer_thread_claims;
    std::atomic<uint64_t> producer_thread_rejections;

    std::atomic<uint64_t> commit_ack_attempts;
    std::atomic<uint64_t> commit_acks;
    std::atomic<uint64_t> commit_ack_no_pending_rejections;
    std::atomic<uint64_t> commit_receipt_rejections;

    std::atomic<uint64_t> dequeue_attempts;
    std::atomic<uint64_t> dequeued_batches;
    std::atomic<uint64_t> drain_attempts;
    std::atomic<uint64_t> drained_batches;
    std::atomic<uint64_t> drain_before_stop_rejections;
    std::atomic<uint64_t> empty_observations;

    std::atomic<uint64_t> stop_attempts;
    std::atomic<uint64_t> stop_transitions;
    std::atomic<uint64_t> internal_integrity_failures;
    std::atomic<uint64_t> destroy_rejected_live_ownership;
    std::atomic<uint64_t> peak_depth;
};

constexpr uint64_t kStoppedBit = UINT64_C(1) << 63u;
constexpr uint64_t kProducerMask = kStoppedBit - UINT64_C(1);

static_assert(
    alignof(RingState) <= alignof(max_align_t),
    "output ring metadata exceeds caller placement alignment");
static_assert(
    alignof(fk_owner_runtime_output_batch_v2) <= alignof(max_align_t),
    "output batch exceeds caller placement alignment");
static_assert(
    sizeof(fk_owner_output_batch_commit_receipt) == 48u,
    "output batch receipt ABI changed");

bool checked_add(size_t &value, size_t addend) {
    if (addend > std::numeric_limits<size_t>::max() - value)
        return false;
    value += addend;
    return true;
}

bool checked_counter_add(uint64_t &value, uint64_t addend) {
    if (addend > std::numeric_limits<uint64_t>::max() - value)
        return false;
    value += addend;
    return true;
}

bool checked_multiply(size_t left, size_t right, size_t &result) {
    if (left != 0u && right >
            std::numeric_limits<size_t>::max() / left)
        return false;
    result = left * right;
    return true;
}

bool align_size(size_t &value, size_t alignment) {
    const size_t remainder = value % alignment;
    return remainder == 0u || checked_add(value, alignment - remainder);
}

bool all_zero(const uint8_t *bytes, size_t length) {
    uint8_t combined = 0u;
    for (size_t index = 0u; index < length; ++index)
        combined = static_cast<uint8_t>(combined | bytes[index]);
    return combined == 0u;
}

bool independent_nonzero_keys(
        const fk_owner_output_batch_ring_config &config) {
    uint8_t key0 = 0u;
    uint8_t key1 = 0u;
    uint8_t difference = 0u;
    for (size_t index = 0u; index < FK_OWNER_OUTPUT_BATCH_RING_KEY_BYTES;
         ++index) {
        key0 = static_cast<uint8_t>(
            key0 | config.authentication_key_0[index]);
        key1 = static_cast<uint8_t>(
            key1 | config.authentication_key_1[index]);
        difference = static_cast<uint8_t>(difference |
            (config.authentication_key_0[index] ^
             config.authentication_key_1[index]));
    }
    return key0 != 0u && key1 != 0u && difference != 0u;
}

bool valid_config(const fk_owner_output_batch_ring_config *config) {
    return config != nullptr && config->ring_epoch != 0u &&
        config->capacity != 0u &&
        config->fixed_owner != UINT16_MAX &&
        config->reserved0 == 0u && config->keys_precommitted == 1u &&
        all_zero(config->reserved, sizeof(config->reserved)) &&
        independent_nonzero_keys(*config);
}

size_t required_bytes(
        const fk_owner_output_batch_ring_config *config,
        size_t *metadata_bytes,
        size_t *batch_storage_bytes) {
    if (!valid_config(config))
        return 0u;
    size_t bytes = sizeof(RingState);
    if (!align_size(bytes, alignof(fk_owner_runtime_output_batch_v2)))
        return 0u;
    const size_t metadata = bytes;
    size_t batches = 0u;
    if (!checked_multiply(
            config->capacity,
            sizeof(fk_owner_runtime_output_batch_v2),
            batches) ||
        !checked_add(bytes, batches)) {
        return 0u;
    }
    if (metadata_bytes != nullptr)
        *metadata_bytes = metadata;
    if (batch_storage_bytes != nullptr)
        *batch_storage_bytes = batches;
    return bytes;
}

RingState *implementation(fk_owner_output_batch_ring *ring) {
    return reinterpret_cast<RingState *>(ring);
}

const RingState *implementation(const fk_owner_output_batch_ring *ring) {
    return reinterpret_cast<const RingState *>(ring);
}

uint64_t allocate_thread_token() {
    static std::atomic<uint64_t> next{1u};
    uint64_t candidate = next.load(std::memory_order_relaxed);
    while (candidate != 0u &&
           candidate != std::numeric_limits<uint64_t>::max()) {
        if (next.compare_exchange_weak(
                candidate, candidate + 1u,
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

bool claim_or_validate_producer(RingState &state) {
    const uint64_t token = current_thread_token();
    uint64_t claimed = state.producer_thread_token.load(
        std::memory_order_acquire);
    if (token == 0u) {
        state.producer_thread_rejections.fetch_add(
            1u, std::memory_order_relaxed);
        return false;
    }
    if (claimed == 0u) {
        if (state.producer_thread_token.compare_exchange_strong(
                claimed,
                token,
                std::memory_order_acq_rel,
                std::memory_order_acquire)) {
            state.producer_thread_claims.fetch_add(
                1u, std::memory_order_relaxed);
            return true;
        }
    }
    if (claimed == token)
        return true;
    state.producer_thread_rejections.fetch_add(
        1u, std::memory_order_relaxed);
    return false;
}

bool batch_valid(const fk_owner_runtime_output_batch_v2 *batch) {
    if (batch == nullptr || batch->transaction_epoch == 0u ||
        batch->transaction_epoch == UINT64_MAX ||
        batch->abi_version != FK_OWNER_RUNTIME_OUTPUT_ABI_VERSION ||
        batch->packet_sequence == UINT64_MAX ||
        batch->physical_ingress_timestamp_ns == 0u ||
        batch->handle.generation == 0u ||
        batch->state != FK_OWNER_RUNTIME_OUTPUT_IDENTITY_COMMITTED ||
        batch->has_flow_open > 1u || batch->has_detection > 1u ||
        batch->has_action > 1u ||
        (batch->has_flow_open | batch->has_detection |
         batch->has_action) == 0u ||
        !all_zero(batch->reserved, sizeof(batch->reserved))) {
        return false;
    }
    if (batch->has_flow_open != 0u &&
        (batch->flow_open.logical_connection_id !=
             batch->logical_connection_id ||
         (batch->flow_open.presentation.control_kind !=
              FK_COMPACT_FLOW_CONTROL_OPEN &&
          batch->flow_open.presentation.control_kind !=
              FK_COMPACT_FLOW_CONTROL_CONTINUE) ||
         !all_zero(batch->flow_open.presentation.reserved,
             sizeof(batch->flow_open.presentation.reserved)) ||
         batch->flow_open.presentation.observation_timestamp_ns !=
             batch->semantic_timestamp_ns ||
         batch->flow_open.presentation.flow_index != batch->handle.index ||
         batch->flow_open.presentation.flow_generation !=
             batch->handle.generation)) {
        return false;
    }
    if (batch->has_detection != 0u &&
        (batch->detection.logical_connection_id !=
             batch->logical_connection_id ||
         batch->detection.presentation.observation_timestamp_ns !=
             batch->semantic_timestamp_ns ||
         batch->detection.presentation.flow_index != batch->handle.index ||
         batch->detection.presentation.flow_generation !=
             batch->handle.generation)) {
        return false;
    }
    if (batch->has_action != 0u &&
        batch->action.observation_timestamp_ns !=
            batch->semantic_timestamp_ns) {
        return false;
    }
    return true;
}

enum class ReserveResult {
    Reserved,
    Stopped,
    Failed,
};

ReserveResult reserve_producer(RingState &state) {
    uint64_t observed = state.lifecycle_and_producers.load(
        std::memory_order_acquire);
    for (;;) {
        if ((observed & kStoppedBit) != 0u) {
            state.stopped_rejections.fetch_add(
                1u, std::memory_order_relaxed);
            return ReserveResult::Stopped;
        }
        if ((observed & kProducerMask) == kProducerMask) {
            state.internal_integrity_failures.fetch_add(
                1u, std::memory_order_relaxed);
            return ReserveResult::Failed;
        }
        if (state.lifecycle_and_producers.compare_exchange_weak(
                observed,
                observed + 1u,
                std::memory_order_acq_rel,
                std::memory_order_acquire)) {
            return ReserveResult::Reserved;
        }
    }
}

void release_producer(RingState &state) {
    state.lifecycle_and_producers.fetch_sub(
        1u, std::memory_order_release);
}

struct ProducerReservation {
    explicit ProducerReservation(RingState &input) : state(input) {}
    ~ProducerReservation() { release_producer(state); }
    ProducerReservation(const ProducerReservation &) = delete;
    ProducerReservation &operator=(const ProducerReservation &) = delete;
    RingState &state;
};

uint64_t rotate_left(uint64_t value, unsigned shift) {
    return (value << shift) | (value >> (64u - shift));
}

uint64_t load_u64_le(const uint8_t *bytes) {
    uint64_t result = 0u;
    for (unsigned index = 0u; index < 8u; ++index)
        result |= static_cast<uint64_t>(bytes[index]) << (index * 8u);
    return result;
}

void store_u64_le(uint64_t value, uint8_t *bytes) {
    for (unsigned index = 0u; index < 8u; ++index)
        bytes[index] = static_cast<uint8_t>(value >> (index * 8u));
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
        const uint8_t key[FK_OWNER_OUTPUT_BATCH_RING_KEY_BYTES],
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
    for (size_t index = 0u; index < length - offset; ++index) {
        tail |= static_cast<uint64_t>(message[offset + index]) <<
            (index * 8u);
    }
    v3 ^= tail;
    sip_round(v0, v1, v2, v3);
    sip_round(v0, v1, v2, v3);
    v0 ^= tail;
    v2 ^= 0xffu;
    for (unsigned index = 0u; index < 4u; ++index)
        sip_round(v0, v1, v2, v3);
    return v0 ^ v1 ^ v2 ^ v3;
}

void append_u16_le(uint16_t value, uint8_t *bytes, size_t &offset) {
    bytes[offset++] = static_cast<uint8_t>(value);
    bytes[offset++] = static_cast<uint8_t>(value >> 8u);
}

void append_u64_le(uint64_t value, uint8_t *bytes, size_t &offset) {
    for (unsigned shift = 0u; shift < 64u; shift += 8u)
        bytes[offset++] = static_cast<uint8_t>(value >> shift);
}

void receipt_tag(
        const RingState &state,
        uint64_t transaction_epoch,
        uint64_t commit_ordinal,
        uint8_t tag[FK_OWNER_OUTPUT_BATCH_RING_TAG_BYTES]) {
    uint8_t material[40]{};
    size_t offset = 0u;
    const uint8_t domain[8] = {
        'F', 'K', 'O', 'U', 'T', 'B', '1', 0u,
    };
    std::memcpy(material + offset, domain, sizeof(domain));
    offset += sizeof(domain);
    append_u16_le(
        static_cast<uint16_t>(FK_OWNER_OUTPUT_BATCH_RING_ABI_VERSION),
        material,
        offset);
    append_u16_le(state.config.fixed_owner, material, offset);
    append_u64_le(state.config.ring_epoch, material, offset);
    append_u64_le(transaction_epoch, material, offset);
    append_u64_le(commit_ordinal, material, offset);
    /* Two zero domain-reserved words are committed by the fixed 40B length. */
    while (offset < sizeof(material))
        material[offset++] = 0u;
    store_u64_le(
        siphash24(
            state.config.authentication_key_0,
            material,
            sizeof(material)),
        tag);
    store_u64_le(
        siphash24(
            state.config.authentication_key_1,
            material,
            sizeof(material)),
        tag + 8u);
}

bool tags_equal(
        const uint8_t left[FK_OWNER_OUTPUT_BATCH_RING_TAG_BYTES],
        const uint8_t right[FK_OWNER_OUTPUT_BATCH_RING_TAG_BYTES]) {
    uint8_t difference = 0u;
    for (size_t index = 0u; index < FK_OWNER_OUTPUT_BATCH_RING_TAG_BYTES;
         ++index) {
        difference = static_cast<uint8_t>(difference |
            (left[index] ^ right[index]));
    }
    return difference == 0u;
}

void make_receipt(
        const RingState &state,
        uint64_t transaction_epoch,
        uint64_t commit_ordinal,
        fk_owner_output_batch_commit_receipt &receipt) {
    receipt = {};
    receipt.ring_epoch = state.config.ring_epoch;
    receipt.batch_transaction_epoch = transaction_epoch;
    receipt.commit_ordinal = commit_ordinal;
    receipt.fixed_owner = state.config.fixed_owner;
    receipt.abi_version = FK_OWNER_OUTPUT_BATCH_RING_ABI_VERSION;
    receipt_tag(state, transaction_epoch, commit_ordinal, receipt.tag);
}

bool receipt_matches(
        const RingState &state,
        const fk_owner_output_batch_commit_receipt &receipt,
        uint64_t pending_ordinal,
        uint64_t pending_transaction_epoch) {
    if (receipt.ring_epoch != state.config.ring_epoch ||
        receipt.batch_transaction_epoch != pending_transaction_epoch ||
        receipt.commit_ordinal != pending_ordinal ||
        receipt.fixed_owner != state.config.fixed_owner ||
        receipt.abi_version != FK_OWNER_OUTPUT_BATCH_RING_ABI_VERSION ||
        receipt.reserved0 != 0u) {
        return false;
    }
    uint8_t expected[FK_OWNER_OUTPUT_BATCH_RING_TAG_BYTES];
    receipt_tag(
        state, pending_transaction_epoch, pending_ordinal, expected);
    return tags_equal(receipt.tag, expected);
}

void update_peak(std::atomic<uint64_t> &peak, uint64_t value) {
    uint64_t observed = peak.load(std::memory_order_relaxed);
    while (value > observed && !peak.compare_exchange_weak(
            observed,
            value,
            std::memory_order_relaxed,
            std::memory_order_relaxed)) {
    }
}

bool lifecycle_stopped(const RingState &state) {
    return (state.lifecycle_and_producers.load(std::memory_order_acquire) &
        kStoppedBit) != 0u;
}

bool accounting_values_conserved(
        const RingState &state,
        uint64_t *owned_result,
        bool *commit_result) {
    const uint64_t accepted = state.accepted_batches.load(
        std::memory_order_acquire);
    const uint64_t dequeued = state.dequeued_batches.load(
        std::memory_order_acquire);
    const uint64_t drained = state.drained_batches.load(
        std::memory_order_acquire);
    const uint64_t head = state.head.load(std::memory_order_acquire);
    const uint64_t tail = state.tail.load(std::memory_order_acquire);
    if (tail < head || tail - head > state.config.capacity ||
        dequeued > accepted || drained > accepted - dequeued) {
        return false;
    }
    uint64_t consumed = dequeued;
    if (!checked_counter_add(consumed, drained))
        return false;
    const uint64_t owned = tail - head;
    const bool ownership = accepted - consumed == owned &&
        tail == accepted && head == consumed;
    const uint64_t acked = state.commit_acks.load(std::memory_order_acquire);
    const uint64_t pending = state.pending_commit_ordinal.load(
        std::memory_order_acquire);
    const bool commits = acked <= accepted && accepted - acked <= 1u &&
        ((accepted == acked) == (pending == 0u));
    if (owned_result != nullptr)
        *owned_result = owned;
    if (commit_result != nullptr)
        *commit_result = commits;
    return ownership;
}

bool formal_ready_impl(const RingState &state) {
    uint64_t owned = 0u;
    bool commits = false;
    if (!accounting_values_conserved(state, &owned, &commits) || !commits ||
        !lifecycle_stopped(state) || owned != 0u ||
        state.pending_commit_ordinal.load(std::memory_order_acquire) != 0u ||
        state.drained_batches.load(std::memory_order_acquire) != 0u) {
        return false;
    }
    return state.stopped_rejections.load(std::memory_order_relaxed) == 0u &&
        state.invalid_enqueue_rejections.load(
            std::memory_order_relaxed) == 0u &&
        state.transaction_replay_rejections.load(
            std::memory_order_relaxed) == 0u &&
        state.commit_ack_required_rejections.load(
            std::memory_order_relaxed) == 0u &&
        state.producer_thread_rejections.load(
            std::memory_order_relaxed) == 0u &&
        state.commit_ack_no_pending_rejections.load(
            std::memory_order_relaxed) == 0u &&
        state.commit_receipt_rejections.load(
            std::memory_order_relaxed) == 0u &&
        state.drain_before_stop_rejections.load(
            std::memory_order_relaxed) == 0u &&
        state.internal_integrity_failures.load(
            std::memory_order_relaxed) == 0u &&
        state.destroy_rejected_live_ownership.load(
            std::memory_order_relaxed) == 0u;
}

enum fk_owner_output_batch_take_result take_one(
        RingState &state,
        fk_owner_runtime_output_batch_v2 *batch,
        bool draining) {
    if (batch == nullptr)
        return FK_OWNER_OUTPUT_BATCH_TAKE_INVALID;
    *batch = {};
    if (draining) {
        state.drain_attempts.fetch_add(1u, std::memory_order_relaxed);
        if (!lifecycle_stopped(state)) {
            state.drain_before_stop_rejections.fetch_add(
                1u, std::memory_order_relaxed);
            return FK_OWNER_OUTPUT_BATCH_DRAIN_REQUIRES_STOP;
        }
    } else {
        state.dequeue_attempts.fetch_add(1u, std::memory_order_relaxed);
    }
    const uint64_t head = state.head.load(std::memory_order_relaxed);
    const uint64_t tail = state.tail.load(std::memory_order_acquire);
    if (head == tail) {
        state.empty_observations.fetch_add(1u, std::memory_order_relaxed);
        return lifecycle_stopped(state) ?
            FK_OWNER_OUTPUT_BATCH_STOPPED_EMPTY :
            FK_OWNER_OUTPUT_BATCH_EMPTY;
    }
    if (tail < head || tail - head > state.config.capacity) {
        state.internal_integrity_failures.fetch_add(
            1u, std::memory_order_relaxed);
        return FK_OWNER_OUTPUT_BATCH_TAKE_INVALID;
    }
    const size_t index = static_cast<size_t>(head % state.config.capacity);
    *batch = state.cells[index];
    state.cells[index] = {};
    state.head.store(head + 1u, std::memory_order_release);
    if (draining) {
        state.drained_batches.fetch_add(1u, std::memory_order_relaxed);
        return FK_OWNER_OUTPUT_BATCH_DRAINED;
    }
    state.dequeued_batches.fetch_add(1u, std::memory_order_relaxed);
    return FK_OWNER_OUTPUT_BATCH_DEQUEUED;
}

}  // namespace

extern "C" {

size_t fk_owner_output_batch_ring_storage_bytes(
        const fk_owner_output_batch_ring_config *config) {
    return required_bytes(config, nullptr, nullptr);
}

bool fk_owner_output_batch_ring_initialize(
        void *storage,
        size_t storage_bytes,
        const fk_owner_output_batch_ring_config *config,
        fk_owner_output_batch_ring **ring) {
    if (ring != nullptr)
        *ring = nullptr;
    size_t metadata_bytes = 0u;
    size_t batch_storage_bytes = 0u;
    const size_t needed = required_bytes(
        config, &metadata_bytes, &batch_storage_bytes);
    if (storage == nullptr || ring == nullptr || needed == 0u ||
        storage_bytes < needed ||
        reinterpret_cast<uintptr_t>(storage) % alignof(max_align_t) != 0u) {
        return false;
    }
    auto *state = new (storage) RingState{};
    state->config = *config;
    state->cells = reinterpret_cast<fk_owner_runtime_output_batch_v2 *>(
        static_cast<uint8_t *>(storage) + metadata_bytes);
    state->reserved_bytes = needed;
    state->metadata_bytes = metadata_bytes;
    state->batch_storage_bytes = batch_storage_bytes;
    std::memset(state->cells, 0, batch_storage_bytes);
    state->next_commit_ordinal.store(1u, std::memory_order_relaxed);
    *ring = reinterpret_cast<fk_owner_output_batch_ring *>(state);
    return true;
}

enum fk_owner_output_batch_enqueue_result
fk_owner_output_batch_ring_enqueue(
        fk_owner_output_batch_ring *ring,
        const fk_owner_runtime_output_batch_v2 *batch,
        fk_owner_output_batch_commit_receipt *receipt) {
    if (receipt != nullptr)
        *receipt = {};
    if (ring == nullptr || receipt == nullptr)
        return FK_OWNER_OUTPUT_BATCH_ENQUEUE_INVALID;
    RingState &state = *implementation(ring);
    state.enqueue_attempts.fetch_add(1u, std::memory_order_relaxed);
    if (!batch_valid(batch)) {
        state.invalid_enqueue_rejections.fetch_add(
            1u, std::memory_order_relaxed);
        return FK_OWNER_OUTPUT_BATCH_ENQUEUE_INVALID;
    }
    if (!claim_or_validate_producer(state))
        return FK_OWNER_OUTPUT_BATCH_ENQUEUE_WRONG_PRODUCER;
    const ReserveResult reserve = reserve_producer(state);
    if (reserve == ReserveResult::Stopped)
        return FK_OWNER_OUTPUT_BATCH_ENQUEUE_STOPPED;
    if (reserve == ReserveResult::Failed)
        return FK_OWNER_OUTPUT_BATCH_ENQUEUE_INTERNAL_FAILURE;
    ProducerReservation reservation(state);

    if (state.pending_commit_ordinal.load(std::memory_order_acquire) != 0u) {
        state.commit_ack_required_rejections.fetch_add(
            1u, std::memory_order_relaxed);
        return FK_OWNER_OUTPUT_BATCH_ENQUEUE_COMMIT_ACK_REQUIRED;
    }
    const uint64_t last_transaction = state.last_transaction_epoch.load(
        std::memory_order_relaxed);
    if (batch->transaction_epoch <= last_transaction) {
        state.transaction_replay_rejections.fetch_add(
            1u, std::memory_order_relaxed);
        return FK_OWNER_OUTPUT_BATCH_ENQUEUE_INVALID;
    }
    const uint64_t head = state.head.load(std::memory_order_acquire);
    const uint64_t tail = state.tail.load(std::memory_order_relaxed);
    if (tail < head || tail - head > state.config.capacity) {
        state.internal_integrity_failures.fetch_add(
            1u, std::memory_order_relaxed);
        return FK_OWNER_OUTPUT_BATCH_ENQUEUE_INTERNAL_FAILURE;
    }
    if (tail - head == state.config.capacity) {
        state.full_rejections.fetch_add(1u, std::memory_order_relaxed);
        return FK_OWNER_OUTPUT_BATCH_ENQUEUE_FULL;
    }
    const uint64_t ordinal = state.next_commit_ordinal.load(
        std::memory_order_relaxed);
    if (tail == UINT64_MAX || ordinal == 0u || ordinal == UINT64_MAX) {
        state.internal_integrity_failures.fetch_add(
            1u, std::memory_order_relaxed);
        return FK_OWNER_OUTPUT_BATCH_ENQUEUE_INTERNAL_FAILURE;
    }

    const size_t index = static_cast<size_t>(tail % state.config.capacity);
    state.cells[index] = *batch;
    fk_owner_output_batch_commit_receipt committed{};
    make_receipt(state, batch->transaction_epoch, ordinal, committed);
    state.pending_transaction_epoch.store(
        batch->transaction_epoch, std::memory_order_relaxed);
    state.pending_commit_ordinal.store(ordinal, std::memory_order_release);
    state.last_transaction_epoch.store(
        batch->transaction_epoch, std::memory_order_relaxed);
    state.next_commit_ordinal.store(ordinal + 1u, std::memory_order_relaxed);
    state.accepted_batches.fetch_add(1u, std::memory_order_relaxed);
    state.tail.store(tail + 1u, std::memory_order_release);
    update_peak(state.peak_depth, tail + 1u - head);
    *receipt = committed;
    return FK_OWNER_OUTPUT_BATCH_ENQUEUE_COMMITTED;
}

enum fk_owner_output_batch_commit_ack_result
fk_owner_output_batch_ring_ack_commit(
        fk_owner_output_batch_ring *ring,
        const fk_owner_output_batch_commit_receipt *receipt) {
    if (ring == nullptr || receipt == nullptr)
        return FK_OWNER_OUTPUT_BATCH_COMMIT_ACK_INVALID;
    RingState &state = *implementation(ring);
    state.commit_ack_attempts.fetch_add(1u, std::memory_order_relaxed);
    const uint64_t claimed = state.producer_thread_token.load(
        std::memory_order_acquire);
    if (claimed == 0u || claimed != current_thread_token()) {
        state.producer_thread_rejections.fetch_add(
            1u, std::memory_order_relaxed);
        return FK_OWNER_OUTPUT_BATCH_COMMIT_ACK_WRONG_PRODUCER;
    }
    const uint64_t pending = state.pending_commit_ordinal.load(
        std::memory_order_acquire);
    const uint64_t pending_transaction =
        state.pending_transaction_epoch.load(std::memory_order_relaxed);
    if (pending == 0u) {
        state.commit_ack_no_pending_rejections.fetch_add(
            1u, std::memory_order_relaxed);
        return FK_OWNER_OUTPUT_BATCH_COMMIT_ACK_NO_PENDING;
    }
    if (!receipt_matches(state, *receipt, pending, pending_transaction)) {
        state.commit_receipt_rejections.fetch_add(
            1u, std::memory_order_relaxed);
        return FK_OWNER_OUTPUT_BATCH_COMMIT_ACK_RECEIPT_REJECTED;
    }
    state.pending_transaction_epoch.store(0u, std::memory_order_relaxed);
    state.pending_commit_ordinal.store(0u, std::memory_order_release);
    state.commit_acks.fetch_add(1u, std::memory_order_relaxed);
    return FK_OWNER_OUTPUT_BATCH_COMMIT_ACKED;
}

enum fk_owner_output_batch_take_result
fk_owner_output_batch_ring_dequeue(
        fk_owner_output_batch_ring *ring,
        fk_owner_runtime_output_batch_v2 *batch) {
    if (ring == nullptr || batch == nullptr)
        return FK_OWNER_OUTPUT_BATCH_TAKE_INVALID;
    return take_one(*implementation(ring), batch, false);
}

enum fk_owner_output_batch_take_result
fk_owner_output_batch_ring_drain(
        fk_owner_output_batch_ring *ring,
        fk_owner_runtime_output_batch_v2 *batch) {
    if (ring == nullptr || batch == nullptr)
        return FK_OWNER_OUTPUT_BATCH_TAKE_INVALID;
    return take_one(*implementation(ring), batch, true);
}

bool fk_owner_output_batch_ring_stop(fk_owner_output_batch_ring *ring) {
    if (ring == nullptr)
        return false;
    RingState &state = *implementation(ring);
    state.stop_attempts.fetch_add(1u, std::memory_order_relaxed);
    uint64_t observed = state.lifecycle_and_producers.load(
        std::memory_order_acquire);
    for (;;) {
        if ((observed & kStoppedBit) != 0u)
            break;
        if (state.lifecycle_and_producers.compare_exchange_weak(
                observed,
                observed | kStoppedBit,
                std::memory_order_acq_rel,
                std::memory_order_acquire)) {
            state.stop_transitions.fetch_add(1u, std::memory_order_relaxed);
            observed |= kStoppedBit;
            break;
        }
    }
    while ((state.lifecycle_and_producers.load(std::memory_order_acquire) &
            kProducerMask) != 0u) {
        std::atomic_signal_fence(std::memory_order_seq_cst);
    }
    return true;
}

bool fk_owner_output_batch_ring_get_stats(
        const fk_owner_output_batch_ring *ring,
        fk_owner_output_batch_ring_stats *stats) {
    if (ring == nullptr || stats == nullptr)
        return false;
    const RingState &state = *implementation(ring);
    *stats = {};
#define FK_LOAD_COUNTER(name) \
    stats->name = state.name.load(std::memory_order_acquire)
    FK_LOAD_COUNTER(enqueue_attempts);
    FK_LOAD_COUNTER(accepted_batches);
    FK_LOAD_COUNTER(full_rejections);
    FK_LOAD_COUNTER(stopped_rejections);
    FK_LOAD_COUNTER(invalid_enqueue_rejections);
    FK_LOAD_COUNTER(transaction_replay_rejections);
    FK_LOAD_COUNTER(commit_ack_required_rejections);
    FK_LOAD_COUNTER(producer_thread_claims);
    FK_LOAD_COUNTER(producer_thread_rejections);
    FK_LOAD_COUNTER(commit_ack_attempts);
    FK_LOAD_COUNTER(commit_acks);
    FK_LOAD_COUNTER(commit_ack_no_pending_rejections);
    FK_LOAD_COUNTER(commit_receipt_rejections);
    FK_LOAD_COUNTER(dequeue_attempts);
    FK_LOAD_COUNTER(dequeued_batches);
    FK_LOAD_COUNTER(drain_attempts);
    FK_LOAD_COUNTER(drained_batches);
    FK_LOAD_COUNTER(drain_before_stop_rejections);
    FK_LOAD_COUNTER(empty_observations);
    FK_LOAD_COUNTER(stop_attempts);
    FK_LOAD_COUNTER(stop_transitions);
    FK_LOAD_COUNTER(internal_integrity_failures);
    FK_LOAD_COUNTER(destroy_rejected_live_ownership);
    FK_LOAD_COUNTER(peak_depth);
#undef FK_LOAD_COUNTER
    stats->pending_commit_ordinal = state.pending_commit_ordinal.load(
        std::memory_order_acquire);
    stats->last_batch_transaction_epoch =
        state.last_transaction_epoch.load(std::memory_order_acquire);
    stats->next_commit_ordinal = state.next_commit_ordinal.load(
        std::memory_order_acquire);
    stats->service_memory_bytes = state.reserved_bytes;
    stats->service_metadata_bytes = state.metadata_bytes;
    stats->service_batch_storage_bytes = state.batch_storage_bytes;
    stats->capacity = state.config.capacity;
    stats->batch_element_bytes = sizeof(fk_owner_runtime_output_batch_v2);
    stats->ring_epoch = state.config.ring_epoch;
    stats->fixed_owner = state.config.fixed_owner;
    stats->abi_version = FK_OWNER_OUTPUT_BATCH_RING_ABI_VERSION;
    stats->lifecycle = lifecycle_stopped(state) ?
        FK_OWNER_OUTPUT_BATCH_RING_STOPPED :
        FK_OWNER_OUTPUT_BATCH_RING_ACCEPTING;
    bool commits = false;
    stats->ownership_conserved = accounting_values_conserved(
        state, &stats->owned_batches, &commits);
    stats->depth = stats->owned_batches;
    stats->commit_receipts_conserved = commits;
    stats->service_memory_exact =
        state.reserved_bytes ==
            state.metadata_bytes + state.batch_storage_bytes &&
        state.batch_storage_bytes ==
            static_cast<uint64_t>(state.config.capacity) *
                sizeof(fk_owner_runtime_output_batch_v2);
    stats->formal_ready = formal_ready_impl(state);
    return true;
}

bool fk_owner_output_batch_ring_accounting_conserved(
        const fk_owner_output_batch_ring *ring) {
    if (ring == nullptr)
        return false;
    bool commits = false;
    const bool ownership = accounting_values_conserved(
        *implementation(ring), nullptr, &commits);
    return ownership && commits;
}

bool fk_owner_output_batch_ring_formal_ready(
        const fk_owner_output_batch_ring *ring) {
    return ring != nullptr && formal_ready_impl(*implementation(ring));
}

bool fk_owner_output_batch_ring_destroy_checked(
        fk_owner_output_batch_ring *ring) {
    if (ring == nullptr)
        return false;
    RingState &state = *implementation(ring);
    uint64_t owned = 0u;
    bool commits = false;
    if (!lifecycle_stopped(state) ||
        !accounting_values_conserved(state, &owned, &commits) ||
        !commits || owned != 0u ||
        state.pending_commit_ordinal.load(std::memory_order_acquire) != 0u) {
        state.destroy_rejected_live_ownership.fetch_add(
            1u, std::memory_order_relaxed);
        return false;
    }
    state.~RingState();
    return true;
}

}  // extern "C"
