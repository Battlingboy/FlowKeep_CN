#include "fk_detector_request_ring.h"
#include "fk_feature_validation.h"

#include <atomic>
#include <cmath>
#include <cstddef>
#include <cstring>
#include <limits>
#include <new>
#include <type_traits>

#if !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "fk_detector_request_ring ABI requires a little-endian target"
#endif

namespace {

struct alignas(FK_DETECTOR_REQUEST_RING_STORAGE_ALIGNMENT) RingState {
    uint64_t magic;
    fk_detector_request_ring_config config;
    fk_detector_request_v1 *cells;
    size_t storage_bytes;
    size_t metadata_bytes;
    size_t request_storage_bytes;
    uint8_t reserved_header[16];

    /* Producer-owned position; published to the consumer with release. */
    alignas(FK_DETECTOR_REQUEST_RING_STORAGE_ALIGNMENT)
        std::atomic<uint64_t> head;
    /* Consumer-owned position; published to the producer with release. */
    alignas(FK_DETECTOR_REQUEST_RING_STORAGE_ALIGNMENT)
        std::atomic<uint64_t> tail;

    std::atomic<uint64_t> producer_thread_token;
    std::atomic<uint64_t> consumer_thread_token;
    std::atomic<uint64_t> producer_closed;
    std::atomic<uint64_t> fail_closed;

    std::atomic<uint64_t> enqueue_attempts;
    std::atomic<uint64_t> enqueued;
    std::atomic<uint64_t> request_validation_failures;
    std::atomic<uint64_t> overflow_failures;
    std::atomic<uint64_t> closed_rejections;
    std::atomic<uint64_t> faulted_enqueue_rejections;
    std::atomic<uint64_t> producer_thread_claims;
    std::atomic<uint64_t> producer_thread_rejections;

    std::atomic<uint64_t> dequeue_attempts;
    std::atomic<uint64_t> dequeued;
    std::atomic<uint64_t> empty_observations;
    std::atomic<uint64_t> faulted_empty_observations;
    std::atomic<uint64_t> consumer_thread_claims;
    std::atomic<uint64_t> consumer_thread_rejections;

    std::atomic<uint64_t> close_attempts;
    std::atomic<uint64_t> close_transitions;
    std::atomic<uint64_t> internal_integrity_failures;
    std::atomic<uint64_t> destroy_rejections;
    std::atomic<uint64_t> peak_depth;
};

constexpr uint64_t kDestroyedMagic = UINT64_C(0x4441454451524446);
constexpr size_t kStorageAlignment =
    FK_DETECTOR_REQUEST_RING_STORAGE_ALIGNMENT;

static_assert(sizeof(float) == 4u, "detector ABI requires binary32 floats");
static_assert(
    std::numeric_limits<float>::is_iec559,
    "detector ABI requires IEEE-754 floats");
static_assert(
    (std::is_same<uint64_t, unsigned int>::value &&
        ATOMIC_INT_LOCK_FREE == 2) ||
    (std::is_same<uint64_t, unsigned long>::value &&
        ATOMIC_LONG_LOCK_FREE == 2) ||
    (std::is_same<uint64_t, unsigned long long>::value &&
        ATOMIC_LLONG_LOCK_FREE == 2),
    "detector SPSC ring requires lock-free 64-bit atomics");
static_assert(sizeof(fk_flow_key) == 38u, "canonical key ABI changed");
static_assert(sizeof(fk_detector_request_v1) ==
    FK_DETECTOR_REQUEST_RECORD_BYTES, "detector request ABI changed");
static_assert(offsetof(fk_detector_request_v1, canonical_key) == 16u,
    "detector request canonical-key offset changed");
static_assert(offsetof(fk_detector_request_v1, flow_index) == 56u,
    "detector request flow offset changed");
static_assert(offsetof(fk_detector_request_v1, semantic_timestamp_ns) == 72u,
    "detector request semantic-time offset changed");
static_assert(offsetof(fk_detector_request_v1, event_routing_token) == 88u,
    "detector request route-token offset changed");
static_assert(offsetof(fk_detector_request_v1,
    flow_first_timestamp_ns) == 104u,
    "detector request first-time offset changed");
static_assert(offsetof(fk_detector_request_v1,
    predecessor_flow_index) == 112u,
    "detector request predecessor-index offset changed");
static_assert(offsetof(fk_detector_request_v1,
    predecessor_checkpoint_packet) == 120u,
    "detector request predecessor-cursor offset changed");
static_assert(offsetof(fk_detector_request_v1, reserved_header) == 124u,
    "detector request reserved-header offset changed");
static_assert(offsetof(fk_detector_request_v1, features) ==
    FK_DETECTOR_REQUEST_HEADER_BYTES, "detector feature offset changed");
static_assert(sizeof(fk_detector_request_ring_config) ==
    FK_DETECTOR_REQUEST_RING_CONFIG_BYTES, "ring config ABI changed");
static_assert(sizeof(fk_detector_request_ring_stats) == 224u,
    "ring statistics ABI changed");
static_assert(alignof(RingState) == kStorageAlignment,
    "ring placement alignment changed");
static_assert(sizeof(RingState) % kStorageAlignment == 0u,
    "ring metadata must end on a cache-line boundary");
static_assert(sizeof(fk_detector_request_v1) % kStorageAlignment == 0u,
    "request cells must preserve cache-line alignment");

bool checked_add(size_t &value, size_t addend) {
    if (addend > std::numeric_limits<size_t>::max() - value)
        return false;
    value += addend;
    return true;
}

bool checked_multiply(size_t left, size_t right, size_t &result) {
    if (left != 0u && right >
            std::numeric_limits<size_t>::max() / left) {
        return false;
    }
    result = left * right;
    return true;
}

bool bytes_zero(const void *memory, size_t bytes) {
    if (memory == nullptr)
        return false;
    const auto *values = static_cast<const uint8_t *>(memory);
    uint8_t combined = 0u;
    for (size_t index = 0u; index < bytes; ++index)
        combined = static_cast<uint8_t>(combined | values[index]);
    return combined == 0u;
}

bool power_of_two(uint32_t value) {
    return value != 0u && (value & (value - 1u)) == 0u;
}

bool valid_capacity(uint32_t capacity) {
    return capacity >= FK_DETECTOR_REQUEST_RING_MIN_CAPACITY &&
        capacity <= FK_DETECTOR_REQUEST_RING_MAX_CAPACITY &&
        power_of_two(capacity);
}

bool valid_config(const fk_detector_request_ring_config *config) {
    return config != nullptr &&
        config->magic == FK_DETECTOR_REQUEST_RING_MAGIC &&
        config->abi_version == FK_DETECTOR_REQUEST_RING_ABI_VERSION &&
        config->config_bytes == FK_DETECTOR_REQUEST_RING_CONFIG_BYTES &&
        config->request_bytes == FK_DETECTOR_REQUEST_RECORD_BYTES &&
        config->reserved0 == 0u && valid_capacity(config->capacity) &&
        config->fail_closed_on_overflow == 1u &&
        bytes_zero(config->reserved, sizeof(config->reserved));
}

bool canonical_key_valid(const fk_flow_key &key) {
    if ((key.ip_version != 4u && key.ip_version != 6u) ||
        (key.protocol != 6u && key.protocol != 17u)) {
        return false;
    }
    const size_t address_bytes = key.ip_version == 4u ? 4u : 16u;
    if (key.ip_version == 4u &&
        (!bytes_zero(key.low_addr + address_bytes,
             sizeof(key.low_addr) - address_bytes) ||
         !bytes_zero(key.high_addr + address_bytes,
             sizeof(key.high_addr) - address_bytes))) {
        return false;
    }
    const int address_order = std::memcmp(
        key.low_addr, key.high_addr, address_bytes);
    return address_order < 0 ||
        (address_order == 0 && key.low_port <= key.high_port);
}

bool request_valid(const fk_detector_request_v1 *request) {
    if (request == nullptr ||
        request->magic != FK_DETECTOR_REQUEST_MAGIC ||
        request->abi_version != FK_DETECTOR_REQUEST_ABI_VERSION ||
        request->header_bytes != FK_DETECTOR_REQUEST_HEADER_BYTES ||
        request->record_bytes != FK_DETECTOR_REQUEST_RECORD_BYTES ||
        request->feature_count != FK_DETECTOR_REQUEST_FEATURE_COUNT ||
        !canonical_key_valid(request->canonical_key) ||
        request->reserved_key_alignment != 0u ||
        request->flow_index == UINT32_MAX ||
        request->flow_generation == 0u ||
        (request->source_mask &
            static_cast<uint8_t>(~FK_DETECTOR_REQUEST_SOURCE_MASK_ALL)) !=
            0u ||
        (request->flags &
            static_cast<uint8_t>(~FK_DETECTOR_REQUEST_FLAGS_ALL)) != 0u ||
        !bytes_zero(request->reserved0, sizeof(request->reserved0)) ||
        request->flow_first_timestamp_ns == 0u ||
        request->flow_first_timestamp_ns >
            request->semantic_timestamp_ns ||
        request->physical_timestamp_ns == 0u ||
        request->event_routing_token == 0u ||
        (request->logical_connection_id != 0u &&
         request->canonical_key.protocol != 17u) ||
        !bytes_zero(
            request->reserved_header, sizeof(request->reserved_header)) ||
        !bytes_zero(request->reserved_tail, sizeof(request->reserved_tail))) {
        return false;
    }
    const bool flow_open =
        request->flags == FK_DETECTOR_REQUEST_FLAG_FLOW_OPEN ||
        request->flags == FK_DETECTOR_REQUEST_FLAG_COVERAGE_OPEN;
    const bool coverage_open=request->flags==FK_DETECTOR_REQUEST_FLAG_COVERAGE_OPEN;
    const bool terminal=request->flags==FK_DETECTOR_REQUEST_FLAG_COVERAGE_TERMINAL;
    const bool flow_continue =
        request->flags == FK_DETECTOR_REQUEST_FLAG_FLOW_CONTINUE;
    const bool control = flow_open || flow_continue;
    if ((!control &&
         ((!terminal && request->flags != 0u) || request->checkpoint_packet == 0u)) ||
        (control &&
         (request->checkpoint_packet != 0u || request->source_mask != 0u)) ||
        (flow_continue && request->logical_connection_id != 0u) ||
        (flow_continue &&
         (request->predecessor_flow_index == UINT32_MAX ||
          request->predecessor_flow_generation == 0u ||
          (request->predecessor_flow_index == request->flow_index &&
           request->predecessor_flow_generation ==
               request->flow_generation))) ||
        (!flow_continue && !terminal &&
         (request->predecessor_flow_index != 0u ||
          request->predecessor_flow_generation != 0u ||
          request->predecessor_checkpoint_packet != 0u)) ||
        (flow_open && request->flow_first_timestamp_ns !=
            request->semantic_timestamp_ns) ||
        (terminal && (request->checkpoint_packet == 0u ||
            request->predecessor_checkpoint_packet != 0u ||
            fk_detector_coverage_evidence_ns(request) <
                request->flow_first_timestamp_ns ||
            fk_detector_coverage_evidence_ns(request) >
                request->semantic_timestamp_ns))) {
        return false;
    }
    return flowkeep::FeatureValuesValid(request->features,
        FK_DETECTOR_REQUEST_FEATURE_COUNT, control && !coverage_open);
}

size_t required_bytes(
        const fk_detector_request_ring_config *config,
        size_t *request_storage_bytes) {
    if (!valid_config(config))
        return 0u;
    size_t requests = 0u;
    if (!checked_multiply(
            config->capacity, sizeof(fk_detector_request_v1), requests)) {
        return 0u;
    }
    size_t bytes = kStorageAlignment - 1u;
    if (!checked_add(bytes, sizeof(RingState)) ||
        !checked_add(bytes, requests)) {
        return 0u;
    }
    if (request_storage_bytes != nullptr)
        *request_storage_bytes = requests;
    return bytes;
}

RingState *implementation(fk_detector_request_ring *ring) {
    return reinterpret_cast<RingState *>(ring);
}

const RingState *implementation(const fk_detector_request_ring *ring) {
    return reinterpret_cast<const RingState *>(ring);
}

bool state_header_valid(const RingState &state) {
    return state.magic == FK_DETECTOR_REQUEST_RING_MAGIC &&
        valid_config(&state.config) && state.cells != nullptr &&
        state.request_storage_bytes ==
            static_cast<size_t>(state.config.capacity) *
                sizeof(fk_detector_request_v1) &&
        state.metadata_bytes >= sizeof(RingState) &&
        state.storage_bytes ==
            state.metadata_bytes + state.request_storage_bytes &&
        bytes_zero(state.reserved_header, sizeof(state.reserved_header));
}

void fail_closed(RingState &state) {
    state.fail_closed.store(1u, std::memory_order_release);
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

bool claim_or_validate_thread(
        RingState &state,
        std::atomic<uint64_t> &claimed_token,
        std::atomic<uint64_t> &claim_counter,
        std::atomic<uint64_t> &rejection_counter) {
    const uint64_t token = current_thread_token();
    uint64_t claimed = claimed_token.load(std::memory_order_acquire);
    if (token == 0u) {
        rejection_counter.fetch_add(1u, std::memory_order_relaxed);
        fail_closed(state);
        return false;
    }
    if (claimed == 0u && claimed_token.compare_exchange_strong(
            claimed,
            token,
            std::memory_order_acq_rel,
            std::memory_order_acquire)) {
        claim_counter.fetch_add(1u, std::memory_order_relaxed);
        return true;
    }
    if (claimed == token)
        return true;
    rejection_counter.fetch_add(1u, std::memory_order_relaxed);
    fail_closed(state);
    return false;
}

bool claim_producer(RingState &state) {
    return claim_or_validate_thread(
        state,
        state.producer_thread_token,
        state.producer_thread_claims,
        state.producer_thread_rejections);
}

bool claim_consumer(RingState &state) {
    return claim_or_validate_thread(
        state,
        state.consumer_thread_token,
        state.consumer_thread_claims,
        state.consumer_thread_rejections);
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

bool positions_valid(
        const RingState &state,
        uint64_t head,
        uint64_t tail,
        uint64_t *depth) {
    if (head < tail || head - tail > state.config.capacity)
        return false;
    if (depth != nullptr)
        *depth = head - tail;
    return true;
}

bool accounting_conserved(
        const RingState &state,
        uint64_t head,
        uint64_t tail,
        uint64_t depth) {
    const uint64_t enqueued = state.enqueued.load(std::memory_order_acquire);
    const uint64_t dequeued = state.dequeued.load(std::memory_order_acquire);
    return head == enqueued && tail == dequeued && enqueued >= dequeued &&
        enqueued - dequeued == depth;
}

bool formal_ready_impl(const RingState &state) {
    const uint64_t head = state.head.load(std::memory_order_acquire);
    const uint64_t tail = state.tail.load(std::memory_order_acquire);
    uint64_t depth = 0u;
    if (!positions_valid(state, head, tail, &depth) ||
        !accounting_conserved(state, head, tail, depth) || depth != 0u ||
        state.producer_closed.load(std::memory_order_acquire) == 0u ||
        state.fail_closed.load(std::memory_order_acquire) != 0u) {
        return false;
    }
    return state.request_validation_failures.load(
               std::memory_order_relaxed) == 0u &&
        state.overflow_failures.load(std::memory_order_relaxed) == 0u &&
        state.closed_rejections.load(std::memory_order_relaxed) == 0u &&
        state.faulted_enqueue_rejections.load(
            std::memory_order_relaxed) == 0u &&
        state.producer_thread_rejections.load(
            std::memory_order_relaxed) == 0u &&
        state.consumer_thread_rejections.load(
            std::memory_order_relaxed) == 0u &&
        state.faulted_empty_observations.load(
            std::memory_order_relaxed) == 0u &&
        state.internal_integrity_failures.load(
            std::memory_order_relaxed) == 0u &&
        state.destroy_rejections.load(std::memory_order_relaxed) == 0u;
}

}  // namespace

extern "C" {

bool fk_detector_request_v1_prepare(fk_detector_request_v1 *request) {
    if (request == nullptr)
        return false;
    std::memset(request, 0, sizeof(*request));
    request->magic = FK_DETECTOR_REQUEST_MAGIC;
    request->abi_version = FK_DETECTOR_REQUEST_ABI_VERSION;
    request->header_bytes = FK_DETECTOR_REQUEST_HEADER_BYTES;
    request->record_bytes = FK_DETECTOR_REQUEST_RECORD_BYTES;
    request->feature_count = FK_DETECTOR_REQUEST_FEATURE_COUNT;
    return true;
}

bool fk_detector_request_v1_valid(const fk_detector_request_v1 *request) {
    return request_valid(request);
}

bool fk_detector_request_v1_is_flow_open(
        const fk_detector_request_v1 *request) {
    return request_valid(request) &&
        (request->flags == FK_DETECTOR_REQUEST_FLAG_FLOW_OPEN ||
         request->flags == FK_DETECTOR_REQUEST_FLAG_COVERAGE_OPEN);
}

bool fk_detector_request_v1_is_flow_continue(
        const fk_detector_request_v1 *request) {
    return request_valid(request) &&
        request->flags == FK_DETECTOR_REQUEST_FLAG_FLOW_CONTINUE;
}

bool fk_detector_request_ring_config_prepare(
        fk_detector_request_ring_config *config,
        uint32_t capacity) {
    if (config == nullptr || !valid_capacity(capacity))
        return false;
    std::memset(config, 0, sizeof(*config));
    config->magic = FK_DETECTOR_REQUEST_RING_MAGIC;
    config->abi_version = FK_DETECTOR_REQUEST_RING_ABI_VERSION;
    config->config_bytes = FK_DETECTOR_REQUEST_RING_CONFIG_BYTES;
    config->request_bytes = FK_DETECTOR_REQUEST_RECORD_BYTES;
    config->capacity = capacity;
    config->fail_closed_on_overflow = 1u;
    return true;
}

size_t fk_detector_request_ring_storage_bytes(
        const fk_detector_request_ring_config *config) {
    return required_bytes(config, nullptr);
}

bool fk_detector_request_ring_initialize(
        void *storage,
        size_t storage_bytes,
        const fk_detector_request_ring_config *config,
        fk_detector_request_ring **ring) {
    if (ring != nullptr)
        *ring = nullptr;
    size_t request_storage_bytes = 0u;
    const size_t worst_case = required_bytes(
        config, &request_storage_bytes);
    if (storage == nullptr || ring == nullptr || worst_case == 0u ||
        storage_bytes < worst_case) {
        return false;
    }
    const uintptr_t raw = reinterpret_cast<uintptr_t>(storage);
    if (raw > std::numeric_limits<uintptr_t>::max() -
            (kStorageAlignment - 1u)) {
        return false;
    }
    const uintptr_t aligned = (raw + kStorageAlignment - 1u) &
        ~(static_cast<uintptr_t>(kStorageAlignment) - 1u);
    const size_t prefix = static_cast<size_t>(aligned - raw);
    size_t actual_bytes = prefix;
    if (!checked_add(actual_bytes, sizeof(RingState)) ||
        !checked_add(actual_bytes, request_storage_bytes) ||
        actual_bytes > storage_bytes) {
        return false;
    }

    auto *state = new (reinterpret_cast<void *>(aligned)) RingState{};
/* std::atomic's C++17 default constructor need not initialize its value. */
#define FK_ATOMIC_INIT_ZERO(name) \
    std::atomic_init(&state->name, UINT64_C(0))
    FK_ATOMIC_INIT_ZERO(head);
    FK_ATOMIC_INIT_ZERO(tail);
    FK_ATOMIC_INIT_ZERO(producer_thread_token);
    FK_ATOMIC_INIT_ZERO(consumer_thread_token);
    FK_ATOMIC_INIT_ZERO(producer_closed);
    FK_ATOMIC_INIT_ZERO(fail_closed);
    FK_ATOMIC_INIT_ZERO(enqueue_attempts);
    FK_ATOMIC_INIT_ZERO(enqueued);
    FK_ATOMIC_INIT_ZERO(request_validation_failures);
    FK_ATOMIC_INIT_ZERO(overflow_failures);
    FK_ATOMIC_INIT_ZERO(closed_rejections);
    FK_ATOMIC_INIT_ZERO(faulted_enqueue_rejections);
    FK_ATOMIC_INIT_ZERO(producer_thread_claims);
    FK_ATOMIC_INIT_ZERO(producer_thread_rejections);
    FK_ATOMIC_INIT_ZERO(dequeue_attempts);
    FK_ATOMIC_INIT_ZERO(dequeued);
    FK_ATOMIC_INIT_ZERO(empty_observations);
    FK_ATOMIC_INIT_ZERO(faulted_empty_observations);
    FK_ATOMIC_INIT_ZERO(consumer_thread_claims);
    FK_ATOMIC_INIT_ZERO(consumer_thread_rejections);
    FK_ATOMIC_INIT_ZERO(close_attempts);
    FK_ATOMIC_INIT_ZERO(close_transitions);
    FK_ATOMIC_INIT_ZERO(internal_integrity_failures);
    FK_ATOMIC_INIT_ZERO(destroy_rejections);
    FK_ATOMIC_INIT_ZERO(peak_depth);
#undef FK_ATOMIC_INIT_ZERO
    state->magic = FK_DETECTOR_REQUEST_RING_MAGIC;
    state->config = *config;
    state->metadata_bytes = prefix + sizeof(RingState);
    state->request_storage_bytes = request_storage_bytes;
    state->storage_bytes = actual_bytes;
    state->cells = reinterpret_cast<fk_detector_request_v1 *>(
        static_cast<uint8_t *>(storage) + state->metadata_bytes);
    if (reinterpret_cast<uintptr_t>(state->cells) % kStorageAlignment != 0u) {
        state->~RingState();
        return false;
    }
    std::memset(state->cells, 0, request_storage_bytes);
    *ring = reinterpret_cast<fk_detector_request_ring *>(state);
    return true;
}

enum fk_detector_request_ring_enqueue_result
fk_detector_request_ring_enqueue(
        fk_detector_request_ring *ring,
        const fk_detector_request_v1 *request) {
    if (ring == nullptr || request == nullptr)
        return FK_DETECTOR_REQUEST_RING_ENQUEUE_INVALID_ARGUMENT;
    RingState &state = *implementation(ring);
    if (!state_header_valid(state))
        return FK_DETECTOR_REQUEST_RING_ENQUEUE_INTERNAL_FAILURE;
    state.enqueue_attempts.fetch_add(1u, std::memory_order_relaxed);
    if (!claim_producer(state))
        return FK_DETECTOR_REQUEST_RING_ENQUEUE_WRONG_PRODUCER;
    if (state.fail_closed.load(std::memory_order_acquire) != 0u) {
        state.faulted_enqueue_rejections.fetch_add(
            1u, std::memory_order_relaxed);
        return FK_DETECTOR_REQUEST_RING_ENQUEUE_FAULTED;
    }
    if (state.producer_closed.load(std::memory_order_acquire) != 0u) {
        state.closed_rejections.fetch_add(1u, std::memory_order_relaxed);
        fail_closed(state);
        return FK_DETECTOR_REQUEST_RING_ENQUEUE_CLOSED;
    }
    if (!request_valid(request)) {
        state.request_validation_failures.fetch_add(
            1u, std::memory_order_relaxed);
        fail_closed(state);
        return FK_DETECTOR_REQUEST_RING_ENQUEUE_REQUEST_REJECTED;
    }

    const uint64_t head = state.head.load(std::memory_order_relaxed);
    const uint64_t tail = state.tail.load(std::memory_order_acquire);
    uint64_t depth = 0u;
    if (!positions_valid(state, head, tail, &depth) || head == UINT64_MAX) {
        state.internal_integrity_failures.fetch_add(
            1u, std::memory_order_relaxed);
        fail_closed(state);
        return FK_DETECTOR_REQUEST_RING_ENQUEUE_INTERNAL_FAILURE;
    }
    if (depth == state.config.capacity) {
        state.overflow_failures.fetch_add(1u, std::memory_order_relaxed);
        fail_closed(state);
        return FK_DETECTOR_REQUEST_RING_ENQUEUE_OVERFLOW_FAIL_CLOSED;
    }

    const size_t index = static_cast<size_t>(
        head & (static_cast<uint64_t>(state.config.capacity) - 1u));
    state.cells[index] = *request;
    state.enqueued.fetch_add(1u, std::memory_order_relaxed);
    state.head.store(head + 1u, std::memory_order_release);
    update_peak(state.peak_depth, depth + 1u);
    return FK_DETECTOR_REQUEST_RING_ENQUEUE_COMMITTED;
}

enum fk_detector_request_ring_dequeue_result
fk_detector_request_ring_dequeue(
        fk_detector_request_ring *ring,
        fk_detector_request_v1 *request) {
    if (request != nullptr)
        std::memset(request, 0, sizeof(*request));
    if (ring == nullptr || request == nullptr)
        return FK_DETECTOR_REQUEST_RING_DEQUEUE_INVALID_ARGUMENT;
    RingState &state = *implementation(ring);
    if (!state_header_valid(state))
        return FK_DETECTOR_REQUEST_RING_DEQUEUE_CORRUPT;
    state.dequeue_attempts.fetch_add(1u, std::memory_order_relaxed);
    if (!claim_consumer(state))
        return FK_DETECTOR_REQUEST_RING_DEQUEUE_WRONG_CONSUMER;

    const uint64_t tail = state.tail.load(std::memory_order_relaxed);
    const uint64_t head = state.head.load(std::memory_order_acquire);
    uint64_t depth = 0u;
    if (!positions_valid(state, head, tail, &depth)) {
        state.internal_integrity_failures.fetch_add(
            1u, std::memory_order_relaxed);
        fail_closed(state);
        return FK_DETECTOR_REQUEST_RING_DEQUEUE_CORRUPT;
    }
    if (depth == 0u) {
        state.empty_observations.fetch_add(1u, std::memory_order_relaxed);
        if (state.fail_closed.load(std::memory_order_acquire) != 0u) {
            state.faulted_empty_observations.fetch_add(
                1u, std::memory_order_relaxed);
            return FK_DETECTOR_REQUEST_RING_DEQUEUE_FAULTED_EMPTY;
        }
        return state.producer_closed.load(std::memory_order_acquire) != 0u ?
            FK_DETECTOR_REQUEST_RING_DEQUEUE_CLOSED_EMPTY :
            FK_DETECTOR_REQUEST_RING_DEQUEUE_EMPTY;
    }

    const size_t index = static_cast<size_t>(
        tail & (static_cast<uint64_t>(state.config.capacity) - 1u));
    const fk_detector_request_v1 candidate = state.cells[index];
    if (!request_valid(&candidate) || tail == UINT64_MAX) {
        state.request_validation_failures.fetch_add(
            1u, std::memory_order_relaxed);
        state.internal_integrity_failures.fetch_add(
            1u, std::memory_order_relaxed);
        fail_closed(state);
        return FK_DETECTOR_REQUEST_RING_DEQUEUE_CORRUPT;
    }
    *request = candidate;
    std::memset(&state.cells[index], 0, sizeof(state.cells[index]));
    state.dequeued.fetch_add(1u, std::memory_order_relaxed);
    state.tail.store(tail + 1u, std::memory_order_release);
    return FK_DETECTOR_REQUEST_RING_DEQUEUE_ITEM;
}

bool fk_detector_request_ring_close_producer(
        fk_detector_request_ring *ring) {
    if (ring == nullptr)
        return false;
    RingState &state = *implementation(ring);
    if (!state_header_valid(state))
        return false;
    state.close_attempts.fetch_add(1u, std::memory_order_relaxed);
    if (!claim_producer(state))
        return false;
    if (state.producer_closed.exchange(
            1u, std::memory_order_acq_rel) == 0u) {
        state.close_transitions.fetch_add(1u, std::memory_order_relaxed);
    }
    return true;
}

bool fk_detector_request_ring_get_stats(
        const fk_detector_request_ring *ring,
        fk_detector_request_ring_stats *stats) {
    if (ring == nullptr || stats == nullptr)
        return false;
    const RingState &state = *implementation(ring);
    if (!state_header_valid(state))
        return false;
    *stats = {};
#define FK_LOAD_COUNTER(name) \
    stats->name = state.name.load(std::memory_order_acquire)
    FK_LOAD_COUNTER(enqueue_attempts);
    FK_LOAD_COUNTER(enqueued);
    FK_LOAD_COUNTER(request_validation_failures);
    FK_LOAD_COUNTER(overflow_failures);
    FK_LOAD_COUNTER(closed_rejections);
    FK_LOAD_COUNTER(faulted_enqueue_rejections);
    FK_LOAD_COUNTER(producer_thread_claims);
    FK_LOAD_COUNTER(producer_thread_rejections);
    FK_LOAD_COUNTER(dequeue_attempts);
    FK_LOAD_COUNTER(dequeued);
    FK_LOAD_COUNTER(empty_observations);
    FK_LOAD_COUNTER(faulted_empty_observations);
    FK_LOAD_COUNTER(consumer_thread_claims);
    FK_LOAD_COUNTER(consumer_thread_rejections);
    FK_LOAD_COUNTER(close_attempts);
    FK_LOAD_COUNTER(close_transitions);
    FK_LOAD_COUNTER(internal_integrity_failures);
    FK_LOAD_COUNTER(destroy_rejections);
    FK_LOAD_COUNTER(peak_depth);
#undef FK_LOAD_COUNTER
    stats->head = state.head.load(std::memory_order_acquire);
    stats->tail = state.tail.load(std::memory_order_acquire);
    uint64_t depth = 0u;
    const bool positions = positions_valid(
        state, stats->head, stats->tail, &depth);
    stats->depth = positions ? depth : UINT64_MAX;
    stats->storage_bytes = state.storage_bytes;
    stats->metadata_bytes = state.metadata_bytes;
    stats->request_storage_bytes = state.request_storage_bytes;
    stats->ring_magic = state.magic;
    stats->capacity = state.config.capacity;
    stats->request_bytes = sizeof(fk_detector_request_v1);
    stats->abi_version = FK_DETECTOR_REQUEST_RING_ABI_VERSION;
    stats->lifecycle =
        state.producer_closed.load(std::memory_order_acquire) != 0u ?
        FK_DETECTOR_REQUEST_RING_PRODUCER_CLOSED :
        FK_DETECTOR_REQUEST_RING_ACCEPTING;
    stats->fail_closed = static_cast<uint8_t>(
        state.fail_closed.load(std::memory_order_acquire) != 0u);
    stats->accounting_conserved = static_cast<uint8_t>(
        positions && accounting_conserved(
            state, stats->head, stats->tail, depth));
    stats->formal_ready = static_cast<uint8_t>(formal_ready_impl(state));
    return true;
}

bool fk_detector_request_ring_formal_ready(
        const fk_detector_request_ring *ring) {
    if (ring == nullptr)
        return false;
    const RingState &state = *implementation(ring);
    return state_header_valid(state) && formal_ready_impl(state);
}

bool fk_detector_request_ring_destroy_checked(
        fk_detector_request_ring *ring) {
    if (ring == nullptr)
        return false;
    RingState &state = *implementation(ring);
    if (!state_header_valid(state))
        return false;
    const uint64_t head = state.head.load(std::memory_order_acquire);
    const uint64_t tail = state.tail.load(std::memory_order_acquire);
    if (state.producer_closed.load(std::memory_order_acquire) == 0u ||
        head != tail) {
        state.destroy_rejections.fetch_add(1u, std::memory_order_relaxed);
        return false;
    }
    state.magic = kDestroyedMagic;
    state.~RingState();
    return true;
}

}  // extern "C"
