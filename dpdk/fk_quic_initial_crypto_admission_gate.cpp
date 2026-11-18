#include "fk_quic_initial_crypto_admission_gate.h"

#include <atomic>
#include <cstddef>
#include <cstring>
#include <initializer_list>
#include <limits>
#include <new>
#include <type_traits>

namespace {

constexpr uint64_t kMagic = UINT64_C(0x464b514943414731);  // "FKQICAG1"
constexpr uint32_t kNoPrefixSlot = UINT32_MAX;

struct PrefixKey {
    uint8_t ip_version = 0u;
    uint8_t prefix_bits = 0u;
    uint8_t address[16]{};
};

struct PrefixEntry {
    PrefixKey key{};
    uint64_t hash = 0u;
    uint64_t credits = 0u;
    uint64_t last_refill_ns = 0u;
    uint64_t last_seen_ns = 0u;
    uint64_t generation = 0u;
    uint8_t occupied = 0u;
    uint8_t reserved[7]{};
};

struct CanonicalDescriptor {
    uint64_t packet_sequence = 0u;
    uintptr_t packet_handle = 0u;
    uint64_t physical_ingress_timestamp_ns = 0u;
    uint32_t crypto_input_bytes = 0u;
    uint8_t ip_version = 0u;
    uint8_t source_address[16]{};
    uint8_t reserved[7]{};
};

struct GateState {
    fk_quic_initial_crypto_admission_gate_config config{};
    std::atomic<uint64_t> owner_thread_token{0u};
    std::atomic<uint64_t> owner_claim_attempts{0u};
    std::atomic<uint64_t> owner_claim_successes{0u};
    std::atomic<uint64_t> owner_claim_rejections{0u};
    std::atomic<uint64_t> owner_thread_rejections{0u};
    fk_quic_initial_crypto_admission_gate_stats counters{};
    PrefixEntry *prefix_entries = nullptr;
    CanonicalDescriptor active_descriptor{};
    CanonicalDescriptor last_descriptor{};
    CanonicalDescriptor last_rejected_descriptor{};
    fk_quic_initial_crypto_admission_receipt_v1 active_receipt{};
    fk_quic_initial_crypto_admission_receipt_v1 last_completed_receipt{};
    uint64_t observed_owner_thread_rejections = 0u;
    uint64_t global_tokens = 0u;
    uint64_t global_last_refill_ns = 0u;
    uint64_t last_physical_now_ns = 0u;
    uint64_t next_receipt_ordinal = 1u;
    uint64_t service_memory_bytes = 0u;
    uint64_t service_metadata_bytes = 0u;
    uint64_t service_prefix_table_bytes = 0u;
    uint64_t magic = 0u;
    uint8_t prefix_hash_key_commitment[16]{};
    uint8_t receipt_key_0_commitment[16]{};
    uint8_t receipt_key_1_commitment[16]{};
    fk_quic_initial_crypto_completion_outcome last_completion_outcome =
        FK_QUIC_INITIAL_CRYPTO_COMPLETION_AUTHENTICATED;
    fk_quic_initial_crypto_gate_lifecycle lifecycle =
        FK_QUIC_INITIAL_CRYPTO_GATE_ACCEPTING;
    fk_quic_initial_crypto_terminal_reason terminal_reason =
        FK_QUIC_INITIAL_CRYPTO_TERMINAL_NONE;
    uint8_t initialized = 0u;
    uint8_t owner_claimed = 0u;
    uint8_t active = 0u;
    uint8_t has_last_descriptor = 0u;
    uint8_t has_last_completed_receipt = 0u;
    uint8_t has_last_rejected_descriptor = 0u;
    uint8_t pressure_active = 0u;
    uint8_t formal_fault = 0u;
    fk_quic_initial_crypto_admission_reason last_rejected_reason =
        FK_QUIC_INITIAL_CRYPTO_REASON_NONE;
};

static_assert(
    alignof(GateState) <= alignof(std::max_align_t),
    "gate placement alignment exceeds max_align_t");
static_assert(
    std::is_trivially_copyable<CanonicalDescriptor>::value,
    "descriptor must remain trivially copyable");
static_assert(sizeof(uintptr_t) == sizeof(uint64_t), "64-bit runtime required");
static_assert(
    sizeof(fk_quic_initial_crypto_admission_gate_config) ==
        FK_QUIC_INITIAL_CRYPTO_ADMISSION_CONFIG_BYTES,
    "gate config C ABI changed");
static_assert(
    sizeof(fk_quic_initial_crypto_admission_request_v1) ==
        FK_QUIC_INITIAL_CRYPTO_ADMISSION_REQUEST_V1_BYTES,
    "gate request C ABI changed");
static_assert(
    sizeof(fk_quic_initial_crypto_admission_receipt_v1) ==
        FK_QUIC_INITIAL_CRYPTO_ADMISSION_RECEIPT_V1_BYTES,
    "gate receipt C ABI changed");
static_assert(
    sizeof(fk_quic_initial_crypto_admission_begin_result_v1) ==
        FK_QUIC_INITIAL_CRYPTO_ADMISSION_BEGIN_RESULT_V1_BYTES,
    "gate begin-result C ABI changed");
static_assert(
    sizeof(fk_quic_initial_crypto_admission_gate_stats) ==
        FK_QUIC_INITIAL_CRYPTO_ADMISSION_STATS_BYTES,
    "gate stats C ABI changed");

std::atomic<uint64_t> g_next_thread_token{1u};

GateState *implementation(fk_quic_initial_crypto_admission_gate *gate) {
    return reinterpret_cast<GateState *>(gate);
}

const GateState *implementation(
        const fk_quic_initial_crypto_admission_gate *gate) {
    return reinterpret_cast<const GateState *>(gate);
}

bool bytes_zero(const uint8_t *bytes, size_t count) {
    if (bytes == nullptr)
        return false;
    for (size_t index = 0u; index < count; ++index) {
        if (bytes[index] != 0u)
            return false;
    }
    return true;
}

bool key_nonzero(const uint8_t *key) {
    uint8_t aggregate = 0u;
    for (size_t index = 0u;
         index < FK_QUIC_INITIAL_CRYPTO_ADMISSION_KEY_BYTES; ++index) {
        aggregate = static_cast<uint8_t>(aggregate | key[index]);
    }
    return aggregate != 0u;
}

bool keys_distinct(const uint8_t *left, const uint8_t *right) {
    uint8_t difference = 0u;
    for (size_t index = 0u;
         index < FK_QUIC_INITIAL_CRYPTO_ADMISSION_KEY_BYTES; ++index) {
        difference = static_cast<uint8_t>(difference | (left[index] ^ right[index]));
    }
    return difference != 0u;
}

bool power_of_two(uint32_t value) {
    return value != 0u && (value & (value - 1u)) == 0u;
}

bool multiply_fits_size(size_t left, size_t right, size_t *product) {
    if (product == nullptr ||
        (left != 0u && right > std::numeric_limits<size_t>::max() / left)) {
        return false;
    }
    *product = left * right;
    return true;
}

bool add_fits_size(size_t left, size_t right, size_t *sum) {
    if (sum == nullptr || right > std::numeric_limits<size_t>::max() - left)
        return false;
    *sum = left + right;
    return true;
}

bool align_up(size_t value, size_t alignment, size_t *aligned) {
    if (aligned == nullptr || alignment == 0u)
        return false;
    const size_t remainder = value % alignment;
    if (remainder == 0u) {
        *aligned = value;
        return true;
    }
    return add_fits_size(value, alignment - remainder, aligned);
}

uint64_t rotate_left(uint64_t value, unsigned shift) {
    return (value << shift) | (value >> (64u - shift));
}

uint64_t load_u64_le(const uint8_t *bytes) {
    uint64_t value = 0u;
    for (unsigned index = 0u; index < 8u; ++index)
        value |= static_cast<uint64_t>(bytes[index]) << (8u * index);
    return value;
}

void store_u64_le(uint8_t *bytes, uint64_t value) {
    for (unsigned index = 0u; index < 8u; ++index)
        bytes[index] = static_cast<uint8_t>(value >> (8u * index));
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
        const uint8_t key[FK_QUIC_INITIAL_CRYPTO_ADMISSION_KEY_BYTES],
        const uint8_t *bytes,
        size_t length) {
    const uint64_t k0 = load_u64_le(key);
    const uint64_t k1 = load_u64_le(key + 8u);
    uint64_t v0 = UINT64_C(0x736f6d6570736575) ^ k0;
    uint64_t v1 = UINT64_C(0x646f72616e646f6d) ^ k1;
    uint64_t v2 = UINT64_C(0x6c7967656e657261) ^ k0;
    uint64_t v3 = UINT64_C(0x7465646279746573) ^ k1;
    size_t offset = 0u;
    while (length - offset >= 8u) {
        const uint64_t message = load_u64_le(bytes + offset);
        v3 ^= message;
        sip_round(v0, v1, v2, v3);
        sip_round(v0, v1, v2, v3);
        v0 ^= message;
        offset += 8u;
    }
    uint64_t tail = static_cast<uint64_t>(length) << 56u;
    for (size_t index = 0u; index < length - offset; ++index)
        tail |= static_cast<uint64_t>(bytes[offset + index]) << (8u * index);
    v3 ^= tail;
    sip_round(v0, v1, v2, v3);
    sip_round(v0, v1, v2, v3);
    v0 ^= tail;
    v2 ^= UINT64_C(0xff);
    for (unsigned round = 0u; round < 4u; ++round)
        sip_round(v0, v1, v2, v3);
    return v0 ^ v1 ^ v2 ^ v3;
}

void key_commitment(
        const uint8_t key[FK_QUIC_INITIAL_CRYPTO_ADMISSION_KEY_BYTES],
        uint8_t label,
        uint8_t commitment[16]) {
    uint8_t message[24]{
        'F', 'L', 'O', 'W', 'K', 'E', 'E', 'P',
        '-', 'Q', 'U', 'I', 'C', '-', 'G', 'A',
        'T', 'E', '-', 'K', 'E', 'Y', 0u, 0u,
    };
    message[22] = label;
    message[23] = 0u;
    const uint64_t first = siphash24(key, message, sizeof(message));
    message[23] = 1u;
    const uint64_t second = siphash24(key, message, sizeof(message));
    store_u64_le(commitment, first);
    store_u64_le(commitment + 8u, second);
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

bool valid_state(const GateState *state) {
    return state != nullptr && state->magic == kMagic &&
        state->initialized == 1u && state->prefix_entries != nullptr;
}

bool owner_thread(const GateState &state) {
    const uint64_t current = current_thread_token();
    const uint64_t owner =
        state.owner_thread_token.load(std::memory_order_acquire);
    return current != 0u && owner != 0u && current == owner;
}

void mark_terminal(
        GateState &state,
        fk_quic_initial_crypto_terminal_reason reason) {
    state.formal_fault = 1u;
    if (state.terminal_reason != FK_QUIC_INITIAL_CRYPTO_TERMINAL_NONE)
        return;
    state.terminal_reason = reason;
    if (state.counters.terminal_transitions !=
            std::numeric_limits<uint64_t>::max()) {
        ++state.counters.terminal_transitions;
    } else if (state.counters.counter_overflows !=
            std::numeric_limits<uint64_t>::max()) {
        ++state.counters.counter_overflows;
    }
}

void mark_counter_overflow(GateState &state) {
    state.formal_fault = 1u;
    if (state.counters.counter_overflows !=
            std::numeric_limits<uint64_t>::max()) {
        ++state.counters.counter_overflows;
    }
    mark_terminal(state, FK_QUIC_INITIAL_CRYPTO_TERMINAL_COUNTER_OVERFLOW);
}

void mark_arithmetic_overflow(GateState &state) {
    state.formal_fault = 1u;
    if (state.counters.arithmetic_overflows !=
            std::numeric_limits<uint64_t>::max()) {
        ++state.counters.arithmetic_overflows;
    }
    mark_terminal(state, FK_QUIC_INITIAL_CRYPTO_TERMINAL_ARITHMETIC_OVERFLOW);
}

bool increment_all(
        GateState &state,
        std::initializer_list<uint64_t *> counters) {
    for (uint64_t *counter : counters) {
        if (counter == nullptr ||
            *counter == std::numeric_limits<uint64_t>::max()) {
            mark_counter_overflow(state);
            return false;
        }
    }
    for (uint64_t *counter : counters)
        ++(*counter);
    return true;
}

bool observe_foreign_access(GateState &state) {
    const uint64_t observed =
        state.owner_thread_rejections.load(std::memory_order_acquire);
    if (observed == state.observed_owner_thread_rejections)
        return true;
    state.observed_owner_thread_rejections = observed;
    mark_terminal(state, FK_QUIC_INITIAL_CRYPTO_TERMINAL_OWNER_THREAD);
    return false;
}

bool valid_request(
        const fk_quic_initial_crypto_admission_request_v1 &request) {
    if (request.abi_version !=
            FK_QUIC_INITIAL_CRYPTO_ADMISSION_GATE_ABI_VERSION ||
        (request.ip_version != 4u && request.ip_version != 6u) ||
        !bytes_zero(request.reserved0, sizeof(request.reserved0)) ||
        !bytes_zero(request.reserved1, sizeof(request.reserved1)) ||
        request.packet_sequence == std::numeric_limits<uint64_t>::max() ||
        request.packet_handle == 0u ||
        request.crypto_input_bytes <
            FK_QUIC_INITIAL_CRYPTO_ADMISSION_MIN_INPUT_BYTES ||
        request.physical_ingress_timestamp_ns == 0u ||
        request.physical_now_ns == 0u ||
        request.physical_now_ns < request.physical_ingress_timestamp_ns) {
        return false;
    }
    return request.ip_version != 4u ||
        bytes_zero(request.source_address + 4u, 12u);
}

CanonicalDescriptor canonical_descriptor(
        const fk_quic_initial_crypto_admission_request_v1 &request) {
    CanonicalDescriptor descriptor{};
    descriptor.packet_sequence = request.packet_sequence;
    descriptor.packet_handle = request.packet_handle;
    descriptor.physical_ingress_timestamp_ns =
        request.physical_ingress_timestamp_ns;
    descriptor.crypto_input_bytes = request.crypto_input_bytes;
    descriptor.ip_version = request.ip_version;
    std::memcpy(
        descriptor.source_address,
        request.source_address,
        sizeof(descriptor.source_address));
    return descriptor;
}

bool descriptors_equal(
        const CanonicalDescriptor &left,
        const CanonicalDescriptor &right) {
    return left.packet_sequence == right.packet_sequence &&
        left.packet_handle == right.packet_handle &&
        left.physical_ingress_timestamp_ns ==
            right.physical_ingress_timestamp_ns &&
        left.crypto_input_bytes == right.crypto_input_bytes &&
        left.ip_version == right.ip_version &&
        std::memcmp(
            left.source_address,
            right.source_address,
            sizeof(left.source_address)) == 0;
}

size_t serialize_descriptor(
        const CanonicalDescriptor &descriptor,
        uint8_t *output,
        uint8_t domain) {
    size_t offset = 0u;
    output[offset++] = domain;
    store_u64_le(output + offset, descriptor.packet_sequence);
    offset += 8u;
    store_u64_le(
        output + offset,
        static_cast<uint64_t>(descriptor.packet_handle));
    offset += 8u;
    store_u64_le(output + offset, descriptor.physical_ingress_timestamp_ns);
    offset += 8u;
    store_u64_le(output + offset, descriptor.crypto_input_bytes);
    offset += 8u;
    output[offset++] = descriptor.ip_version;
    std::memcpy(output + offset, descriptor.source_address, 16u);
    offset += 16u;
    return offset;
}

uint64_t descriptor_hash(
        const GateState &state,
        const CanonicalDescriptor &descriptor,
        uint8_t domain) {
    uint8_t bytes[51]{};
    const size_t length = serialize_descriptor(descriptor, bytes, domain);
    const uint8_t *key = domain == 0x31u
        ? state.config.receipt_key_0 : state.config.receipt_key_1;
    return siphash24(key, bytes, length);
}

PrefixKey canonical_prefix(
        const GateState &state,
        const fk_quic_initial_crypto_admission_request_v1 &request) {
    PrefixKey key{};
    key.ip_version = request.ip_version;
    key.prefix_bits = request.ip_version == 4u
        ? state.config.ipv4_prefix_bits : state.config.ipv6_prefix_bits;
    std::memcpy(key.address, request.source_address, sizeof(key.address));
    const uint8_t address_bits = request.ip_version == 4u ? 32u : 128u;
    const uint8_t complete_bytes = key.prefix_bits / 8u;
    const uint8_t remaining_bits = key.prefix_bits % 8u;
    if (remaining_bits != 0u) {
        key.address[complete_bytes] &=
            static_cast<uint8_t>(0xffu << (8u - remaining_bits));
    }
    uint8_t clear_from = complete_bytes;
    if (remaining_bits != 0u)
        ++clear_from;
    const uint8_t address_bytes = address_bits / 8u;
    for (uint8_t index = clear_from; index < address_bytes; ++index)
        key.address[index] = 0u;
    for (uint8_t index = address_bytes; index < 16u; ++index)
        key.address[index] = 0u;
    return key;
}

bool prefix_equal(const PrefixKey &left, const PrefixKey &right) {
    return left.ip_version == right.ip_version &&
        left.prefix_bits == right.prefix_bits &&
        std::memcmp(left.address, right.address, sizeof(left.address)) == 0;
}

uint64_t prefix_hash(const GateState &state, const PrefixKey &key) {
    uint8_t bytes[19]{};
    bytes[0] = UINT8_C(0xa5);
    bytes[1] = key.ip_version;
    bytes[2] = key.prefix_bits;
    std::memcpy(bytes + 3u, key.address, sizeof(key.address));
    return siphash24(state.config.prefix_hash_key, bytes, sizeof(bytes));
}

bool entry_expired(
        const GateState &state,
        const PrefixEntry &entry,
        uint64_t now_ns) {
    return entry.occupied == 1u && now_ns >= entry.last_seen_ns &&
        now_ns - entry.last_seen_ns >= state.config.prefix_idle_timeout_ns;
}

bool active_uses_slot(const GateState &state, uint32_t slot) {
    return state.active == 1u && state.active_receipt.prefix_slot == slot;
}

struct RefillResult {
    uint64_t tokens = 0u;
    uint64_t anchor_ns = 0u;
    uint64_t added = 0u;
};

bool calculate_refill(
        uint64_t current,
        uint64_t capacity,
        uint64_t refill,
        uint64_t interval_ns,
        uint64_t last_refill_ns,
        uint64_t now_ns,
        RefillResult *result) {
    if (result == nullptr || current > capacity || refill == 0u ||
        interval_ns == 0u || now_ns < last_refill_ns) {
        return false;
    }
    result->tokens = current;
    result->anchor_ns = last_refill_ns;
    result->added = 0u;
    const uint64_t elapsed = now_ns - last_refill_ns;
    const uint64_t periods = elapsed / interval_ns;
    if (periods == 0u)
        return true;
    result->anchor_ns = now_ns - (elapsed % interval_ns);
    const uint64_t missing = capacity - current;
    if (missing == 0u)
        return true;
    const uint64_t periods_needed =
        missing / refill + (missing % refill == 0u ? 0u : 1u);
    if (periods >= periods_needed) {
        result->added = missing;
        result->tokens = capacity;
        return true;
    }
    if (periods > std::numeric_limits<uint64_t>::max() / refill)
        return false;
    result->added = periods * refill;
    if (result->added > missing)
        return false;
    result->tokens = current + result->added;
    return true;
}

bool refill_global(GateState &state, uint64_t now_ns) {
    if (state.global_last_refill_ns == 0u) {
        state.global_last_refill_ns = now_ns;
        return true;
    }
    RefillResult refill{};
    if (!calculate_refill(
            state.global_tokens,
            state.config.global_burst_tokens,
            state.config.global_refill_tokens_per_interval,
            state.config.refill_interval_ns,
            state.global_last_refill_ns,
            now_ns,
            &refill)) {
        mark_arithmetic_overflow(state);
        return false;
    }
    if (refill.added != 0u) {
        if (state.counters.global_refill_events ==
                std::numeric_limits<uint64_t>::max() ||
            refill.added > std::numeric_limits<uint64_t>::max() -
                state.counters.global_tokens_refilled) {
            mark_counter_overflow(state);
            return false;
        }
        ++state.counters.global_refill_events;
        state.counters.global_tokens_refilled += refill.added;
    }
    state.global_tokens = refill.tokens;
    state.global_last_refill_ns = refill.anchor_ns;
    return true;
}

bool refill_prefix(GateState &state, PrefixEntry &entry, uint64_t now_ns) {
    RefillResult refill{};
    if (!calculate_refill(
            entry.credits,
            state.config.prefix_burst_credits,
            state.config.prefix_refill_credits_per_interval,
            state.config.refill_interval_ns,
            entry.last_refill_ns,
            now_ns,
            &refill)) {
        mark_arithmetic_overflow(state);
        return false;
    }
    if (refill.added != 0u) {
        if (state.counters.prefix_refill_events ==
                std::numeric_limits<uint64_t>::max() ||
            refill.added > std::numeric_limits<uint64_t>::max() -
                state.counters.prefix_credits_refilled) {
            mark_counter_overflow(state);
            return false;
        }
        ++state.counters.prefix_refill_events;
        state.counters.prefix_credits_refilled += refill.added;
    }
    entry.credits = refill.tokens;
    entry.last_refill_ns = refill.anchor_ns;
    return true;
}

enum class PrefixLookupResult {
    Found,
    Inserted,
    Pressure,
    Failure,
};

PrefixLookupResult find_or_insert_prefix(
        GateState &state,
        const PrefixKey &key,
        uint64_t now_ns,
        uint32_t *slot_out) {
    if (!increment_all(state, {&state.counters.prefix_lookups}))
        return PrefixLookupResult::Failure;
    const uint64_t hash = prefix_hash(state, key);
    const uint32_t mask = state.config.prefix_table_capacity - 1u;
    const uint32_t start = static_cast<uint32_t>(hash) & mask;
    uint32_t reusable = kNoPrefixSlot;
    bool reusable_is_eviction = false;
    for (uint32_t probe = 0u;
         probe < state.config.maximum_probe_length;
         ++probe) {
        const uint32_t slot = (start + probe) & mask;
        PrefixEntry &entry = state.prefix_entries[slot];
        if (entry.occupied == 0u) {
            if (reusable == kNoPrefixSlot) {
                reusable = slot;
                reusable_is_eviction = false;
            }
            break;
        }
        if (entry.hash == hash && prefix_equal(entry.key, key)) {
            if (!increment_all(state, {&state.counters.prefix_hits}) ||
                !refill_prefix(state, entry, now_ns)) {
                return PrefixLookupResult::Failure;
            }
            entry.last_seen_ns = now_ns;
            *slot_out = slot;
            return PrefixLookupResult::Found;
        }
        if (!increment_all(state, {&state.counters.prefix_collision_steps}))
            return PrefixLookupResult::Failure;
        if (reusable == kNoPrefixSlot && !active_uses_slot(state, slot) &&
            entry_expired(state, entry, now_ns)) {
            reusable = slot;
            reusable_is_eviction = true;
        }
    }
    if (reusable == kNoPrefixSlot) {
        if (!increment_all(state, {&state.counters.prefix_probe_exhaustions}))
            return PrefixLookupResult::Failure;
        return PrefixLookupResult::Pressure;
    }
    PrefixEntry &entry = state.prefix_entries[reusable];
    uint64_t generation = 1u;
    if (reusable_is_eviction) {
        if (entry.generation == std::numeric_limits<uint64_t>::max()) {
            mark_arithmetic_overflow(state);
            return PrefixLookupResult::Failure;
        }
        generation = entry.generation + 1u;
        if (!increment_all(
                state,
                {&state.counters.prefix_insertions,
                 &state.counters.prefix_evictions}))
            return PrefixLookupResult::Failure;
    } else {
        if (!increment_all(
                state,
                {&state.counters.prefix_insertions,
                 &state.counters.active_prefix_entries})) {
            return PrefixLookupResult::Failure;
        }
        if (state.counters.active_prefix_entries >
                state.counters.peak_prefix_entries) {
            state.counters.peak_prefix_entries =
                state.counters.active_prefix_entries;
        }
    }
    entry = {};
    entry.key = key;
    entry.hash = hash;
    entry.credits = state.config.prefix_burst_credits;
    entry.last_refill_ns = now_ns;
    entry.last_seen_ns = now_ns;
    entry.generation = generation;
    entry.occupied = 1u;
    *slot_out = reusable;
    return PrefixLookupResult::Inserted;
}

void enter_pressure(GateState &state) {
    if (state.counters.pressure_observations !=
            std::numeric_limits<uint64_t>::max()) {
        ++state.counters.pressure_observations;
    } else {
        mark_counter_overflow(state);
        return;
    }
    if (state.pressure_active == 0u) {
        if (state.counters.pressure_entries ==
                std::numeric_limits<uint64_t>::max()) {
            mark_counter_overflow(state);
            return;
        }
        ++state.counters.pressure_entries;
        state.pressure_active = 1u;
    }
}

bool recover_pressure(GateState &state) {
    if (state.pressure_active == 0u)
        return true;
    if (!increment_all(state, {&state.counters.pressure_recoveries}))
        return false;
    state.pressure_active = 0u;
    return true;
}

size_t serialize_receipt(
        const fk_quic_initial_crypto_admission_receipt_v1 &receipt,
        uint8_t domain,
        uint8_t *output) {
    size_t offset = 0u;
    output[offset++] = domain;
    store_u64_le(output + offset, receipt.abi_version);
    offset += 8u;
    store_u64_le(output + offset, receipt.prefix_slot);
    offset += 8u;
    store_u64_le(output + offset, receipt.receipt_ordinal);
    offset += 8u;
    store_u64_le(output + offset, receipt.packet_sequence);
    offset += 8u;
    store_u64_le(output + offset, static_cast<uint64_t>(receipt.packet_handle));
    offset += 8u;
    store_u64_le(output + offset, receipt.physical_ingress_timestamp_ns);
    offset += 8u;
    store_u64_le(output + offset, receipt.begin_physical_now_ns);
    offset += 8u;
    store_u64_le(output + offset, receipt.prefix_generation);
    offset += 8u;
    store_u64_le(output + offset, receipt.cost_units);
    offset += 8u;
    store_u64_le(output + offset, receipt.descriptor_hash_0);
    offset += 8u;
    store_u64_le(output + offset, receipt.descriptor_hash_1);
    offset += 8u;
    store_u64_le(output + offset, receipt.crypto_input_bytes);
    offset += 8u;
    store_u64_le(output + offset, receipt.cost_quantum_bytes);
    offset += 8u;
    output[offset++] = receipt.ip_version;
    output[offset++] = receipt.prefix_bits;
    std::memcpy(output + offset, receipt.reserved, sizeof(receipt.reserved));
    offset += sizeof(receipt.reserved);
    return offset;
}

void authenticate_receipt(
        const GateState &state,
        fk_quic_initial_crypto_admission_receipt_v1 &receipt) {
    uint8_t bytes[128]{};
    const size_t first_length = serialize_receipt(receipt, UINT8_C(0xc1), bytes);
    const uint64_t first =
        siphash24(state.config.receipt_key_0, bytes, first_length);
    const size_t second_length = serialize_receipt(receipt, UINT8_C(0xc2), bytes);
    const uint64_t second =
        siphash24(state.config.receipt_key_1, bytes, second_length);
    store_u64_le(receipt.tag, first);
    store_u64_le(receipt.tag + 8u, second);
}

bool receipt_authenticated(
        const GateState &state,
        const fk_quic_initial_crypto_admission_receipt_v1 &receipt) {
    fk_quic_initial_crypto_admission_receipt_v1 expected = receipt;
    std::memset(expected.tag, 0, sizeof(expected.tag));
    authenticate_receipt(state, expected);
    uint8_t difference = 0u;
    for (size_t index = 0u; index < sizeof(receipt.tag); ++index)
        difference = static_cast<uint8_t>(
            difference | (expected.tag[index] ^ receipt.tag[index]));
    return difference == 0u;
}

bool receipts_equal(
        const fk_quic_initial_crypto_admission_receipt_v1 &left,
        const fk_quic_initial_crypto_admission_receipt_v1 &right) {
    return std::memcmp(&left, &right, sizeof(left)) == 0;
}

bool issue_receipt(
        GateState &state,
        const CanonicalDescriptor &descriptor,
        const fk_quic_initial_crypto_admission_request_v1 &request,
        uint32_t prefix_slot,
        uint64_t prefix_generation,
        uint8_t prefix_bits,
        uint64_t cost_units,
        fk_quic_initial_crypto_admission_receipt_v1 *receipt) {
    if (receipt == nullptr || state.next_receipt_ordinal == 0u ||
        state.next_receipt_ordinal == std::numeric_limits<uint64_t>::max()) {
        mark_arithmetic_overflow(state);
        return false;
    }
    *receipt = {};
    receipt->abi_version =
        FK_QUIC_INITIAL_CRYPTO_ADMISSION_GATE_ABI_VERSION;
    receipt->prefix_slot = prefix_slot;
    receipt->receipt_ordinal = state.next_receipt_ordinal;
    receipt->packet_sequence = descriptor.packet_sequence;
    receipt->packet_handle = descriptor.packet_handle;
    receipt->physical_ingress_timestamp_ns =
        descriptor.physical_ingress_timestamp_ns;
    receipt->begin_physical_now_ns = request.physical_now_ns;
    receipt->prefix_generation = prefix_generation;
    receipt->cost_units = cost_units;
    receipt->descriptor_hash_0 = descriptor_hash(state, descriptor, 0x31u);
    receipt->descriptor_hash_1 = descriptor_hash(state, descriptor, 0x32u);
    receipt->crypto_input_bytes = descriptor.crypto_input_bytes;
    receipt->cost_quantum_bytes = state.config.cost_quantum_bytes;
    receipt->ip_version = descriptor.ip_version;
    receipt->prefix_bits = prefix_bits;
    authenticate_receipt(state, *receipt);
    ++state.next_receipt_ordinal;
    state.active_descriptor = descriptor;
    state.last_descriptor = descriptor;
    state.active_receipt = *receipt;
    state.active = 1u;
    state.has_last_descriptor = 1u;
    state.has_last_rejected_descriptor = 0u;
    state.last_rejected_descriptor = {};
    state.last_rejected_reason = FK_QUIC_INITIAL_CRYPTO_REASON_NONE;
    return true;
}

void initialize_result(
        fk_quic_initial_crypto_admission_begin_result_v1 *result) {
    if (result == nullptr)
        return;
    std::memset(result, 0, sizeof(*result));
    result->abi_version =
        FK_QUIC_INITIAL_CRYPTO_ADMISSION_GATE_ABI_VERSION;
    result->decision = FK_QUIC_INITIAL_CRYPTO_ADMISSION_REJECT;
    result->reason = FK_QUIC_INITIAL_CRYPTO_REASON_INTERNAL_FAILURE;
}

fk_quic_initial_crypto_admission_decision reject_begin(
        GateState &state,
        fk_quic_initial_crypto_admission_begin_result_v1 &result,
        fk_quic_initial_crypto_admission_reason reason,
        uint64_t *specific_counter,
        bool pressure,
        const CanonicalDescriptor *freeze_descriptor = nullptr) {
    if (pressure) {
        if (!increment_all(
                state,
                {&state.counters.begin_rejected,
                 &state.counters.pressure_rejects,
                 specific_counter})) {
            result.reason = FK_QUIC_INITIAL_CRYPTO_REASON_COUNTER_OVERFLOW;
            return result.decision;
        }
        enter_pressure(state);
    } else if (!increment_all(
                   state,
                   {&state.counters.begin_rejected, specific_counter})) {
        result.reason = FK_QUIC_INITIAL_CRYPTO_REASON_COUNTER_OVERFLOW;
        return result.decision;
    }
    if (freeze_descriptor != nullptr) {
        state.last_rejected_descriptor = *freeze_descriptor;
        state.last_rejected_reason = reason;
        state.has_last_rejected_descriptor = 1u;
    }
    result.reason = reason;
    return result.decision;
}

bool pressure_reason(fk_quic_initial_crypto_admission_reason reason) {
    return reason == FK_QUIC_INITIAL_CRYPTO_REASON_GLOBAL_TOKENS_EXHAUSTED ||
        reason == FK_QUIC_INITIAL_CRYPTO_REASON_PREFIX_CREDITS_EXHAUSTED ||
        reason == FK_QUIC_INITIAL_CRYPTO_REASON_PREFIX_TABLE_PRESSURE;
}

uint64_t *rejection_reason_counter(
        GateState &state,
        fk_quic_initial_crypto_admission_reason reason) {
    switch (reason) {
    case FK_QUIC_INITIAL_CRYPTO_REASON_GLOBAL_TOKENS_EXHAUSTED:
        return &state.counters.global_token_rejects;
    case FK_QUIC_INITIAL_CRYPTO_REASON_PREFIX_CREDITS_EXHAUSTED:
        return &state.counters.prefix_credit_rejects;
    case FK_QUIC_INITIAL_CRYPTO_REASON_PREFIX_TABLE_PRESSURE:
        return &state.counters.prefix_table_rejects;
    case FK_QUIC_INITIAL_CRYPTO_REASON_CRYPTO_INPUT_TOO_LARGE:
        return &state.counters.oversized_crypto_input_rejects;
    default:
        return nullptr;
    }
}

fk_quic_initial_crypto_admission_decision replay_frozen_rejection(
        GateState &state,
        fk_quic_initial_crypto_admission_begin_result_v1 &result) {
    uint64_t *specific =
        rejection_reason_counter(state, state.last_rejected_reason);
    if (specific == nullptr) {
        mark_terminal(state, FK_QUIC_INITIAL_CRYPTO_TERMINAL_INTERNAL);
        return reject_begin(
            state,
            result,
            FK_QUIC_INITIAL_CRYPTO_REASON_INTERNAL_FAILURE,
            &state.counters.internal_rejects,
            false);
    }
    if (pressure_reason(state.last_rejected_reason)) {
        if (!increment_all(
                state,
                {&state.counters.begin_rejected,
                 &state.counters.pressure_rejects,
                 specific,
                 &state.counters.idempotent_reject_retries})) {
            result.reason = FK_QUIC_INITIAL_CRYPTO_REASON_COUNTER_OVERFLOW;
            return result.decision;
        }
    } else if (!increment_all(
                   state,
                   {&state.counters.begin_rejected,
                    specific,
                    &state.counters.idempotent_reject_retries})) {
        result.reason = FK_QUIC_INITIAL_CRYPTO_REASON_COUNTER_OVERFLOW;
        return result.decision;
    }
    result.reason = state.last_rejected_reason;
    return result.decision;
}

bool counter_can_add(GateState &state, uint64_t counter, uint64_t addend) {
    if (addend > std::numeric_limits<uint64_t>::max() - counter) {
        mark_counter_overflow(state);
        return false;
    }
    return true;
}

bool valid_completion_outcome(
        fk_quic_initial_crypto_completion_outcome outcome) {
    return outcome == FK_QUIC_INITIAL_CRYPTO_COMPLETION_AUTHENTICATED ||
        outcome == FK_QUIC_INITIAL_CRYPTO_COMPLETION_INVALID_AUTH ||
        outcome == FK_QUIC_INITIAL_CRYPTO_COMPLETION_CRYPTO_FAILURE ||
        outcome == FK_QUIC_INITIAL_CRYPTO_COMPLETION_DOWNSTREAM_ABORTED;
}

uint64_t *completion_outcome_counter(
        GateState &state,
        fk_quic_initial_crypto_completion_outcome outcome) {
    switch (outcome) {
    case FK_QUIC_INITIAL_CRYPTO_COMPLETION_AUTHENTICATED:
        return &state.counters.authenticated_completions;
    case FK_QUIC_INITIAL_CRYPTO_COMPLETION_INVALID_AUTH:
        return &state.counters.invalid_auth_completions;
    case FK_QUIC_INITIAL_CRYPTO_COMPLETION_CRYPTO_FAILURE:
        return &state.counters.crypto_failure_completions;
    case FK_QUIC_INITIAL_CRYPTO_COMPLETION_DOWNSTREAM_ABORTED:
        return &state.counters.downstream_abort_completions;
    }
    return nullptr;
}

bool sum_equals(
        uint64_t expected,
        std::initializer_list<uint64_t> components) {
    uint64_t sum = 0u;
    for (const uint64_t component : components) {
        if (component > std::numeric_limits<uint64_t>::max() - sum)
            return false;
        sum += component;
    }
    return sum == expected;
}

bool frozen_reject_reason(
        fk_quic_initial_crypto_admission_reason reason) {
    return pressure_reason(reason) ||
        reason == FK_QUIC_INITIAL_CRYPTO_REASON_CRYPTO_INPUT_TOO_LARGE;
}

bool accounting_conserved_impl(
        const GateState &state,
        bool ignore_open_normal_seal_attempt = false) {
    if (!valid_state(&state) ||
        !fk_quic_initial_crypto_admission_gate_config_valid(&state.config) ||
        !key_nonzero(state.prefix_hash_key_commitment) ||
        !key_nonzero(state.receipt_key_0_commitment) ||
        !key_nonzero(state.receipt_key_1_commitment) ||
        !keys_distinct(
            state.prefix_hash_key_commitment,
            state.receipt_key_0_commitment) ||
        !keys_distinct(
            state.prefix_hash_key_commitment,
            state.receipt_key_1_commitment) ||
        !keys_distinct(
            state.receipt_key_0_commitment,
            state.receipt_key_1_commitment) ||
        state.observed_owner_thread_rejections !=
            state.owner_thread_rejections.load(std::memory_order_acquire) ||
        state.counters.counter_overflows != 0u ||
        state.counters.arithmetic_overflows != 0u ||
        state.counters.begin_deferred != 0u ||
        state.counters.token_refunds != 0u ||
        state.owner_claim_successes.load(std::memory_order_acquire) !=
            static_cast<uint64_t>(state.owner_claimed) ||
        state.owner_claimed != 1u ||
        state.global_tokens > state.config.global_burst_tokens ||
        state.counters.active_prefix_entries >
            state.config.prefix_table_capacity ||
        state.counters.peak_prefix_entries >
            state.config.prefix_table_capacity ||
        state.next_receipt_ordinal == 0u ||
        state.counters.receipts_issued ==
            std::numeric_limits<uint64_t>::max() ||
        state.next_receipt_ordinal != state.counters.receipts_issued + 1u ||
        (state.has_last_rejected_descriptor != 0u &&
         (!frozen_reject_reason(state.last_rejected_reason) ||
          state.active != 0u ||
          (state.has_last_descriptor != 0u &&
           state.last_rejected_descriptor.packet_sequence <=
               state.last_descriptor.packet_sequence))) ||
        (state.lifecycle != FK_QUIC_INITIAL_CRYPTO_GATE_ACCEPTING &&
         state.active != 0u)) {
        return false;
    }
    if (state.active != 0u) {
        const auto &receipt = state.active_receipt;
        if (!receipt_authenticated(state, receipt) ||
            receipt.packet_sequence != state.active_descriptor.packet_sequence ||
            receipt.packet_handle != state.active_descriptor.packet_handle ||
            receipt.physical_ingress_timestamp_ns !=
                state.active_descriptor.physical_ingress_timestamp_ns ||
            receipt.crypto_input_bytes !=
                state.active_descriptor.crypto_input_bytes ||
            receipt.cost_quantum_bytes != state.config.cost_quantum_bytes ||
            receipt.ip_version != state.active_descriptor.ip_version) {
            return false;
        }
        const uint64_t expected_cost =
            receipt.crypto_input_bytes / state.config.cost_quantum_bytes +
            (receipt.crypto_input_bytes % state.config.cost_quantum_bytes == 0u
                 ? 0u : 1u);
        if (receipt.cost_units == 0u || receipt.cost_units != expected_cost ||
            receipt.prefix_slot >= state.config.prefix_table_capacity ||
            state.prefix_entries[receipt.prefix_slot].occupied != 1u ||
            state.prefix_entries[receipt.prefix_slot].generation !=
                receipt.prefix_generation) {
            return false;
        }
    }
    if (!sum_equals(
            state.owner_claim_attempts.load(std::memory_order_acquire),
            {state.owner_claim_successes.load(std::memory_order_acquire),
             state.owner_claim_rejections.load(std::memory_order_acquire)}) ||
        !sum_equals(
            state.counters.begin_attempts,
            {state.counters.begin_allowed,
             state.counters.begin_deferred,
             state.counters.begin_rejected}) ||
        !sum_equals(
            state.counters.begin_allowed,
            {state.counters.charged_crypto_allows,
             state.counters.idempotent_active_allows}) ||
        !sum_equals(
            state.counters.pressure_rejects,
            {state.counters.global_token_rejects,
             state.counters.prefix_credit_rejects,
             state.counters.prefix_table_rejects}) ||
        !sum_equals(
            state.counters.begin_rejected,
            {state.counters.pressure_rejects,
             state.counters.oversized_crypto_input_rejects,
             state.counters.invalid_request_rejects,
             state.counters.active_mismatch_rejects,
             state.counters.sequence_replay_rejects,
             state.counters.completed_replay_rejects,
             state.counters.clock_regression_rejects,
             state.counters.stopped_rejects,
             state.counters.terminal_rejects,
             state.counters.internal_rejects}) ||
        state.counters.global_tokens_charged !=
            state.counters.prefix_credits_charged ||
        state.counters.global_tokens_charged !=
            state.counters.charged_work_units ||
        state.counters.charged_crypto_input_bytes >
            state.counters.charged_crypto_byte_upper_bound ||
        state.counters.charged_work_units >
            std::numeric_limits<uint64_t>::max() /
                state.config.cost_quantum_bytes ||
        state.counters.charged_crypto_byte_upper_bound !=
            state.counters.charged_work_units *
                state.config.cost_quantum_bytes ||
        !sum_equals(
            state.counters.receipts_issued,
            {state.counters.charged_crypto_allows}) ||
        !sum_equals(
            state.counters.completion_attempts,
            {state.counters.completions,
             state.counters.idempotent_completions,
             state.counters.completion_rejections}) ||
        !sum_equals(
            state.counters.completions,
            {state.counters.authenticated_completions,
             state.counters.invalid_auth_completions,
             state.counters.crypto_failure_completions,
             state.counters.downstream_abort_completions}) ||
        !sum_equals(
            state.counters.receipts_issued,
            {state.counters.completions,
             static_cast<uint64_t>(state.active),
             state.counters.active_receipts_abandoned}) ||
        (!ignore_open_normal_seal_attempt &&
         !sum_equals(
             state.counters.normal_seal_attempts,
             {state.counters.normal_seal_successes,
              state.counters.normal_seal_rejections}))) {
        return false;
    }
    uint64_t occupied = 0u;
    for (uint32_t slot = 0u; slot < state.config.prefix_table_capacity;
         ++slot) {
        const PrefixEntry &entry = state.prefix_entries[slot];
        if (entry.occupied == 0u)
            continue;
        if (entry.occupied != 1u ||
            entry.credits > state.config.prefix_burst_credits ||
            entry.generation == 0u) {
            return false;
        }
        ++occupied;
    }
    return occupied == state.counters.active_prefix_entries &&
        state.service_metadata_bytes + state.service_prefix_table_bytes ==
            state.service_memory_bytes &&
        state.service_memory_bytes ==
            fk_quic_initial_crypto_admission_gate_storage_bytes(
                &state.config);
}

bool formal_ready_impl(const GateState &state) {
    return state.lifecycle == FK_QUIC_INITIAL_CRYPTO_GATE_SEALED_NORMAL &&
        state.terminal_reason == FK_QUIC_INITIAL_CRYPTO_TERMINAL_NONE &&
        state.formal_fault == 0u && state.active == 0u &&
        accounting_conserved_impl(state);
}

}  // namespace

void fk_quic_initial_crypto_admission_gate_default_config_init(
        fk_quic_initial_crypto_admission_gate_config *config) {
    if (config == nullptr)
        return;
    *config = {};
    config->abi_version =
        FK_QUIC_INITIAL_CRYPTO_ADMISSION_GATE_ABI_VERSION;
    config->prefix_table_capacity = 1024u;
    config->maximum_probe_length = 16u;
    config->fair_share_divisor = 64u;
    config->cost_quantum_bytes = 1200u;
    config->max_admissible_crypto_input_bytes = 16384u;
    config->global_burst_tokens = 1024u;
    config->prefix_burst_credits = 16u;
    config->global_refill_tokens_per_interval = 1024u;
    config->prefix_refill_credits_per_interval = 16u;
    config->refill_interval_ns = UINT64_C(1000000000);
    config->prefix_idle_timeout_ns = UINT64_C(60000000000);
    config->ipv4_prefix_bits = 24u;
    config->ipv6_prefix_bits = 56u;
    /* Deliberately no public default keys.  The run controller must inject
     * three independent secrets and freeze their commitments before init. */
    config->keys_precommitted = 0u;
}

bool fk_quic_initial_crypto_admission_gate_config_valid(
        const fk_quic_initial_crypto_admission_gate_config *config) {
    if (config == nullptr ||
        config->abi_version !=
            FK_QUIC_INITIAL_CRYPTO_ADMISSION_GATE_ABI_VERSION ||
        !power_of_two(config->prefix_table_capacity) ||
        config->prefix_table_capacity >
            FK_QUIC_INITIAL_CRYPTO_ADMISSION_MAX_PREFIX_SLOTS ||
        config->maximum_probe_length == 0u ||
        config->maximum_probe_length > config->prefix_table_capacity ||
        config->fair_share_divisor == 0u ||
        config->cost_quantum_bytes == 0u ||
        config->max_admissible_crypto_input_bytes <
            FK_QUIC_INITIAL_CRYPTO_ADMISSION_MIN_INPUT_BYTES ||
        config->global_burst_tokens == 0u ||
        config->prefix_burst_credits == 0u ||
        config->global_refill_tokens_per_interval == 0u ||
        config->prefix_refill_credits_per_interval == 0u ||
        config->refill_interval_ns == 0u ||
        config->prefix_idle_timeout_ns == 0u ||
        config->ipv4_prefix_bits == 0u || config->ipv4_prefix_bits > 32u ||
        config->ipv6_prefix_bits == 0u || config->ipv6_prefix_bits > 128u ||
        config->keys_precommitted != 1u ||
        !bytes_zero(config->reserved0, sizeof(config->reserved0)) ||
        !bytes_zero(config->reserved1, sizeof(config->reserved1)) ||
        !key_nonzero(config->prefix_hash_key) ||
        !key_nonzero(config->receipt_key_0) ||
        !key_nonzero(config->receipt_key_1) ||
        !keys_distinct(config->prefix_hash_key, config->receipt_key_0) ||
        !keys_distinct(config->prefix_hash_key, config->receipt_key_1) ||
        !keys_distinct(config->receipt_key_0, config->receipt_key_1)) {
        return false;
    }
    const uint64_t maximum_cost_units =
        config->max_admissible_crypto_input_bytes /
            config->cost_quantum_bytes +
        (config->max_admissible_crypto_input_bytes %
                 config->cost_quantum_bytes == 0u
             ? 0u : 1u);
    if (maximum_cost_units == 0u ||
        config->global_burst_tokens < maximum_cost_units ||
        config->prefix_burst_credits < maximum_cost_units) {
        return false;
    }
    /* N is independent of table capacity.  These division-form checks are
     * exactly N*share <= global without a multiplication overflow.  One
     * prefix therefore cannot consume the shares reserved for the other
     * N-1 prefixes.  Spoofing several prefixes can consume several shares,
     * but never exceeds the global hard cap or the bounded prefix table. */
    return config->prefix_burst_credits <=
            config->global_burst_tokens / config->fair_share_divisor &&
        config->prefix_refill_credits_per_interval <=
            config->global_refill_tokens_per_interval /
                config->fair_share_divisor;
}

size_t fk_quic_initial_crypto_admission_gate_storage_bytes(
        const fk_quic_initial_crypto_admission_gate_config *config) {
    if (!fk_quic_initial_crypto_admission_gate_config_valid(config))
        return 0u;
    size_t metadata = 0u;
    size_t table = 0u;
    size_t total = 0u;
    if (!align_up(sizeof(GateState), alignof(PrefixEntry), &metadata) ||
        !multiply_fits_size(
            static_cast<size_t>(config->prefix_table_capacity),
            sizeof(PrefixEntry),
            &table) ||
        !add_fits_size(metadata, table, &total)) {
        return 0u;
    }
    return total;
}

fk_quic_initial_crypto_admission_gate *
fk_quic_initial_crypto_admission_gate_initialize(
        void *storage,
        size_t storage_bytes,
        const fk_quic_initial_crypto_admission_gate_config *config) {
    const size_t required =
        fk_quic_initial_crypto_admission_gate_storage_bytes(config);
    size_t metadata = 0u;
    if (storage == nullptr || required == 0u || storage_bytes < required ||
        reinterpret_cast<uintptr_t>(storage) % alignof(GateState) != 0u ||
        !align_up(sizeof(GateState), alignof(PrefixEntry), &metadata)) {
        return nullptr;
    }
    std::memset(storage, 0, required);
    auto *state = new (storage) GateState{};
    state->config = *config;
    state->prefix_entries = reinterpret_cast<PrefixEntry *>(
        static_cast<uint8_t *>(storage) + metadata);
    for (uint32_t slot = 0u; slot < config->prefix_table_capacity; ++slot)
        new (&state->prefix_entries[slot]) PrefixEntry{};
    state->global_tokens = config->global_burst_tokens;
    state->next_receipt_ordinal = 1u;
    state->service_memory_bytes = required;
    state->service_metadata_bytes = metadata;
    state->service_prefix_table_bytes = required - metadata;
    key_commitment(
        config->prefix_hash_key,
        1u,
        state->prefix_hash_key_commitment);
    key_commitment(
        config->receipt_key_0,
        2u,
        state->receipt_key_0_commitment);
    key_commitment(
        config->receipt_key_1,
        3u,
        state->receipt_key_1_commitment);
    state->counters.abi_version =
        FK_QUIC_INITIAL_CRYPTO_ADMISSION_GATE_ABI_VERSION;
    state->lifecycle = FK_QUIC_INITIAL_CRYPTO_GATE_ACCEPTING;
    state->terminal_reason = FK_QUIC_INITIAL_CRYPTO_TERMINAL_NONE;
    state->initialized = 1u;
    state->magic = kMagic;
    return reinterpret_cast<fk_quic_initial_crypto_admission_gate *>(state);
}

bool fk_quic_initial_crypto_admission_gate_claim_owner(
        fk_quic_initial_crypto_admission_gate *gate) {
    GateState *state = implementation(gate);
    if (!valid_state(state))
        return false;
    saturating_atomic_increment(state->owner_claim_attempts);
    const uint64_t current = current_thread_token();
    uint64_t expected = 0u;
    if (current != 0u && state->owner_thread_token.compare_exchange_strong(
            expected,
            current,
            std::memory_order_acq_rel,
            std::memory_order_acquire)) {
        state->owner_claimed = 1u;
        saturating_atomic_increment(state->owner_claim_successes);
        return true;
    }
    saturating_atomic_increment(state->owner_claim_rejections);
    return false;
}

fk_quic_initial_crypto_admission_decision
fk_quic_initial_crypto_admission_gate_begin(
        fk_quic_initial_crypto_admission_gate *gate,
        const fk_quic_initial_crypto_admission_request_v1 *request,
        fk_quic_initial_crypto_admission_begin_result_v1 *result) {
    initialize_result(result);
    GateState *state = implementation(gate);
    if (!valid_state(state) || result == nullptr)
        return FK_QUIC_INITIAL_CRYPTO_ADMISSION_REJECT;
    if (!owner_thread(*state)) {
        saturating_atomic_increment(state->owner_thread_rejections);
        result->reason = FK_QUIC_INITIAL_CRYPTO_REASON_TERMINAL;
        return result->decision;
    }
    observe_foreign_access(*state);
    if (!increment_all(*state, {&state->counters.begin_attempts})) {
        result->reason = FK_QUIC_INITIAL_CRYPTO_REASON_COUNTER_OVERFLOW;
        return result->decision;
    }
    if (state->lifecycle != FK_QUIC_INITIAL_CRYPTO_GATE_ACCEPTING) {
        return reject_begin(
            *state,
            *result,
            FK_QUIC_INITIAL_CRYPTO_REASON_STOPPED,
            &state->counters.stopped_rejects,
            false);
    }
    if (state->terminal_reason != FK_QUIC_INITIAL_CRYPTO_TERMINAL_NONE) {
        return reject_begin(
            *state,
            *result,
            FK_QUIC_INITIAL_CRYPTO_REASON_TERMINAL,
            &state->counters.terminal_rejects,
            false);
    }
    if (request == nullptr || !valid_request(*request)) {
        state->formal_fault = 1u;
        return reject_begin(
            *state,
            *result,
            FK_QUIC_INITIAL_CRYPTO_REASON_INVALID_REQUEST,
            &state->counters.invalid_request_rejects,
            false);
    }
    const CanonicalDescriptor descriptor = canonical_descriptor(*request);
    /* Retry identity is resolved before consulting physical time or mutable
     * buckets.  Thus a delayed publisher retry cannot refill the gate or turn
     * an already-published ordered skip into an ALLOW. */
    if (state->active != 0u) {
        if (descriptors_equal(descriptor, state->active_descriptor)) {
            if (!increment_all(
                    *state,
                    {&state->counters.begin_allowed,
                     &state->counters.idempotent_active_allows})) {
                result->reason =
                    FK_QUIC_INITIAL_CRYPTO_REASON_COUNTER_OVERFLOW;
                return result->decision;
            }
            result->decision = FK_QUIC_INITIAL_CRYPTO_ADMISSION_ALLOW;
            result->reason =
                FK_QUIC_INITIAL_CRYPTO_REASON_IDEMPOTENT_ACTIVE_RETRY;
            result->receipt = state->active_receipt;
            return result->decision;
        }
        mark_terminal(
            *state, FK_QUIC_INITIAL_CRYPTO_TERMINAL_DESCRIPTOR_MISMATCH);
        return reject_begin(
            *state,
            *result,
            FK_QUIC_INITIAL_CRYPTO_REASON_ACTIVE_DESCRIPTOR_MISMATCH,
            &state->counters.active_mismatch_rejects,
            false);
    }
    if (state->has_last_rejected_descriptor != 0u &&
        descriptor.packet_sequence <=
            state->last_rejected_descriptor.packet_sequence) {
        if (descriptor.packet_sequence ==
                state->last_rejected_descriptor.packet_sequence &&
            descriptors_equal(
                descriptor, state->last_rejected_descriptor)) {
            return replay_frozen_rejection(*state, *result);
        }
        mark_terminal(
            *state,
            descriptor.packet_sequence ==
                    state->last_rejected_descriptor.packet_sequence
                ? FK_QUIC_INITIAL_CRYPTO_TERMINAL_DESCRIPTOR_MISMATCH
                : FK_QUIC_INITIAL_CRYPTO_TERMINAL_SEQUENCE_REPLAY);
        return reject_begin(
            *state,
            *result,
            FK_QUIC_INITIAL_CRYPTO_REASON_SEQUENCE_REPLAY,
            &state->counters.sequence_replay_rejects,
            false);
    }
    if (state->has_last_descriptor != 0u &&
        descriptor.packet_sequence <= state->last_descriptor.packet_sequence) {
        if (descriptor.packet_sequence ==
                state->last_descriptor.packet_sequence &&
            descriptors_equal(descriptor, state->last_descriptor)) {
            return reject_begin(
                *state,
                *result,
                FK_QUIC_INITIAL_CRYPTO_REASON_COMPLETED_DESCRIPTOR_REPLAY,
                &state->counters.completed_replay_rejects,
                false);
        }
        mark_terminal(
            *state, FK_QUIC_INITIAL_CRYPTO_TERMINAL_SEQUENCE_REPLAY);
        return reject_begin(
            *state,
            *result,
            FK_QUIC_INITIAL_CRYPTO_REASON_SEQUENCE_REPLAY,
            &state->counters.sequence_replay_rejects,
            false);
    }

    if (request->crypto_input_bytes >
            state->config.max_admissible_crypto_input_bytes) {
        return reject_begin(
            *state,
            *result,
            FK_QUIC_INITIAL_CRYPTO_REASON_CRYPTO_INPUT_TOO_LARGE,
            &state->counters.oversized_crypto_input_rejects,
            false,
            &descriptor);
    }
    if (state->last_physical_now_ns != 0u &&
        request->physical_now_ns < state->last_physical_now_ns) {
        if (!increment_all(
                *state,
                {&state->counters.begin_rejected,
                 &state->counters.clock_regression_rejects,
                 &state->counters.clock_regressions})) {
            result->reason = FK_QUIC_INITIAL_CRYPTO_REASON_COUNTER_OVERFLOW;
            return result->decision;
        }
        mark_terminal(
            *state, FK_QUIC_INITIAL_CRYPTO_TERMINAL_CLOCK_REGRESSION);
        result->reason = FK_QUIC_INITIAL_CRYPTO_REASON_CLOCK_REGRESSION;
        return result->decision;
    }
    state->last_physical_now_ns = request->physical_now_ns;
    if (!refill_global(*state, request->physical_now_ns)) {
        return reject_begin(
            *state,
            *result,
            FK_QUIC_INITIAL_CRYPTO_REASON_INTERNAL_FAILURE,
            &state->counters.internal_rejects,
            false);
    }
    const uint64_t cost_units =
        request->crypto_input_bytes / state->config.cost_quantum_bytes +
        (request->crypto_input_bytes % state->config.cost_quantum_bytes == 0u
             ? 0u : 1u);
    if (cost_units == 0u) {
        mark_arithmetic_overflow(*state);
        return reject_begin(
            *state,
            *result,
            FK_QUIC_INITIAL_CRYPTO_REASON_INTERNAL_FAILURE,
            &state->counters.internal_rejects,
            false);
    }

    if (state->next_receipt_ordinal == 0u ||
        state->next_receipt_ordinal == std::numeric_limits<uint64_t>::max() ||
        state->counters.begin_allowed ==
            std::numeric_limits<uint64_t>::max() ||
        state->counters.receipts_issued ==
            std::numeric_limits<uint64_t>::max()) {
        mark_counter_overflow(*state);
        result->reason = FK_QUIC_INITIAL_CRYPTO_REASON_COUNTER_OVERFLOW;
        return result->decision;
    }

    if (state->global_tokens < cost_units) {
        return reject_begin(
            *state,
            *result,
            FK_QUIC_INITIAL_CRYPTO_REASON_GLOBAL_TOKENS_EXHAUSTED,
            &state->counters.global_token_rejects,
            true,
            &descriptor);
    }
    const PrefixKey prefix = canonical_prefix(*state, *request);
    uint32_t prefix_slot = kNoPrefixSlot;
    const PrefixLookupResult lookup = find_or_insert_prefix(
        *state, prefix, request->physical_now_ns, &prefix_slot);
    if (lookup == PrefixLookupResult::Pressure) {
        return reject_begin(
            *state,
            *result,
            FK_QUIC_INITIAL_CRYPTO_REASON_PREFIX_TABLE_PRESSURE,
            &state->counters.prefix_table_rejects,
            true,
            &descriptor);
    }
    if (lookup == PrefixLookupResult::Failure ||
        prefix_slot >= state->config.prefix_table_capacity) {
        mark_terminal(*state, FK_QUIC_INITIAL_CRYPTO_TERMINAL_INTERNAL);
        return reject_begin(
            *state,
            *result,
            FK_QUIC_INITIAL_CRYPTO_REASON_INTERNAL_FAILURE,
            &state->counters.internal_rejects,
            false);
    }
    PrefixEntry &entry = state->prefix_entries[prefix_slot];
    if (entry.credits < cost_units) {
        return reject_begin(
            *state,
            *result,
            FK_QUIC_INITIAL_CRYPTO_REASON_PREFIX_CREDITS_EXHAUSTED,
            &state->counters.prefix_credit_rejects,
            true,
            &descriptor);
    }
    if (cost_units > std::numeric_limits<uint64_t>::max() /
            state->config.cost_quantum_bytes) {
        mark_arithmetic_overflow(*state);
        return reject_begin(
            *state,
            *result,
            FK_QUIC_INITIAL_CRYPTO_REASON_INTERNAL_FAILURE,
            &state->counters.internal_rejects,
            false);
    }
    const uint64_t crypto_byte_upper_bound =
        cost_units * state->config.cost_quantum_bytes;
    if (state->counters.charged_crypto_allows ==
            std::numeric_limits<uint64_t>::max() ||
        !counter_can_add(
            *state, state->counters.global_tokens_charged, cost_units) ||
        !counter_can_add(
            *state, state->counters.prefix_credits_charged, cost_units) ||
        !counter_can_add(
            *state, state->counters.charged_work_units, cost_units) ||
        !counter_can_add(
            *state,
            state->counters.charged_crypto_input_bytes,
            request->crypto_input_bytes) ||
        !counter_can_add(
            *state,
            state->counters.charged_crypto_byte_upper_bound,
            crypto_byte_upper_bound)) {
        if (state->terminal_reason ==
                FK_QUIC_INITIAL_CRYPTO_TERMINAL_NONE) {
            mark_counter_overflow(*state);
        }
        result->reason = FK_QUIC_INITIAL_CRYPTO_REASON_COUNTER_OVERFLOW;
        return result->decision;
    }
    fk_quic_initial_crypto_admission_receipt_v1 receipt{};
    if (!issue_receipt(
            *state,
            descriptor,
            *request,
            prefix_slot,
            entry.generation,
            prefix.prefix_bits,
            cost_units,
            &receipt)) {
        return reject_begin(
            *state,
            *result,
            FK_QUIC_INITIAL_CRYPTO_REASON_INTERNAL_FAILURE,
            &state->counters.internal_rejects,
            false);
    }
    state->global_tokens -= cost_units;
    entry.credits -= cost_units;
    ++state->counters.begin_allowed;
    ++state->counters.charged_crypto_allows;
    state->counters.global_tokens_charged += cost_units;
    state->counters.prefix_credits_charged += cost_units;
    state->counters.charged_work_units += cost_units;
    state->counters.charged_crypto_input_bytes +=
        request->crypto_input_bytes;
    state->counters.charged_crypto_byte_upper_bound +=
        crypto_byte_upper_bound;
    ++state->counters.receipts_issued;
    if (!recover_pressure(*state)) {
        result->reason = FK_QUIC_INITIAL_CRYPTO_REASON_COUNTER_OVERFLOW;
        return result->decision;
    }
    result->decision = FK_QUIC_INITIAL_CRYPTO_ADMISSION_ALLOW;
    result->reason = FK_QUIC_INITIAL_CRYPTO_REASON_CHARGED_PREFIX_CRYPTO;
    result->receipt = receipt;
    return result->decision;
}

fk_quic_initial_crypto_completion_result
fk_quic_initial_crypto_admission_gate_complete(
        fk_quic_initial_crypto_admission_gate *gate,
        const fk_quic_initial_crypto_admission_receipt_v1 *receipt,
        fk_quic_initial_crypto_completion_outcome outcome) {
    GateState *state = implementation(gate);
    if (!valid_state(state))
        return FK_QUIC_INITIAL_CRYPTO_COMPLETE_INVALID;
    if (!owner_thread(*state)) {
        saturating_atomic_increment(state->owner_thread_rejections);
        return FK_QUIC_INITIAL_CRYPTO_COMPLETE_WRONG_THREAD;
    }
    observe_foreign_access(*state);
    if (!increment_all(*state, {&state->counters.completion_attempts}))
        return FK_QUIC_INITIAL_CRYPTO_COMPLETE_TERMINAL;
    if (state->lifecycle != FK_QUIC_INITIAL_CRYPTO_GATE_ACCEPTING) {
        increment_all(*state, {&state->counters.completion_rejections});
        return FK_QUIC_INITIAL_CRYPTO_COMPLETE_STOPPED;
    }
    if (state->terminal_reason != FK_QUIC_INITIAL_CRYPTO_TERMINAL_NONE) {
        increment_all(*state, {&state->counters.completion_rejections});
        return FK_QUIC_INITIAL_CRYPTO_COMPLETE_TERMINAL;
    }
    if (receipt == nullptr || !valid_completion_outcome(outcome) ||
        receipt->abi_version !=
            FK_QUIC_INITIAL_CRYPTO_ADMISSION_GATE_ABI_VERSION) {
        increment_all(*state, {&state->counters.completion_rejections});
        mark_terminal(
            *state, FK_QUIC_INITIAL_CRYPTO_TERMINAL_RECEIPT_MISMATCH);
        return FK_QUIC_INITIAL_CRYPTO_COMPLETE_INVALID;
    }
    if (state->active != 0u) {
        if (!receipts_equal(*receipt, state->active_receipt) ||
            !receipt_authenticated(*state, *receipt)) {
            increment_all(*state, {&state->counters.completion_rejections});
            mark_terminal(
                *state, FK_QUIC_INITIAL_CRYPTO_TERMINAL_RECEIPT_MISMATCH);
            return FK_QUIC_INITIAL_CRYPTO_COMPLETE_INVALID;
        }
        uint64_t *outcome_counter = completion_outcome_counter(*state, outcome);
        if (outcome_counter == nullptr ||
            !increment_all(
                *state,
                {&state->counters.completions, outcome_counter})) {
            return FK_QUIC_INITIAL_CRYPTO_COMPLETE_TERMINAL;
        }
        state->last_completed_receipt = state->active_receipt;
        state->last_completion_outcome = outcome;
        state->has_last_completed_receipt = 1u;
        state->active = 0u;
        state->active_receipt = {};
        state->active_descriptor = {};
        return FK_QUIC_INITIAL_CRYPTO_COMPLETED;
    }
    if (state->has_last_completed_receipt != 0u &&
        receipts_equal(*receipt, state->last_completed_receipt) &&
        receipt_authenticated(*state, *receipt) &&
        outcome == state->last_completion_outcome) {
        if (!increment_all(*state, {&state->counters.idempotent_completions}))
            return FK_QUIC_INITIAL_CRYPTO_COMPLETE_TERMINAL;
        return FK_QUIC_INITIAL_CRYPTO_COMPLETE_ALREADY_COMPLETED;
    }
    increment_all(*state, {&state->counters.completion_rejections});
    mark_terminal(*state, FK_QUIC_INITIAL_CRYPTO_TERMINAL_RECEIPT_MISMATCH);
    return FK_QUIC_INITIAL_CRYPTO_COMPLETE_INVALID;
}

bool fk_quic_initial_crypto_admission_gate_seal_normal(
        fk_quic_initial_crypto_admission_gate *gate) {
    GateState *state = implementation(gate);
    if (!valid_state(state))
        return false;
    if (!owner_thread(*state)) {
        saturating_atomic_increment(state->owner_thread_rejections);
        return false;
    }
    observe_foreign_access(*state);
    if (!increment_all(*state, {&state->counters.normal_seal_attempts}))
        return false;
    if (state->lifecycle != FK_QUIC_INITIAL_CRYPTO_GATE_ACCEPTING ||
        state->active != 0u ||
        state->terminal_reason != FK_QUIC_INITIAL_CRYPTO_TERMINAL_NONE ||
        state->formal_fault != 0u ||
        !accounting_conserved_impl(*state, true)) {
        increment_all(*state, {&state->counters.normal_seal_rejections});
        return false;
    }
    if (!increment_all(*state, {&state->counters.normal_seal_successes}))
        return false;
    state->lifecycle = FK_QUIC_INITIAL_CRYPTO_GATE_SEALED_NORMAL;
    return true;
}

bool fk_quic_initial_crypto_admission_gate_seal_abort(
        fk_quic_initial_crypto_admission_gate *gate) {
    GateState *state = implementation(gate);
    if (!valid_state(state))
        return false;
    if (!owner_thread(*state)) {
        saturating_atomic_increment(state->owner_thread_rejections);
        return false;
    }
    observe_foreign_access(*state);
    if (!increment_all(*state, {&state->counters.abort_seal_attempts}))
        return false;
    if (state->lifecycle == FK_QUIC_INITIAL_CRYPTO_GATE_SEALED_ABORT) {
        return increment_all(*state, {&state->counters.abort_seal_already});
    }
    if (state->lifecycle == FK_QUIC_INITIAL_CRYPTO_GATE_SEALED_NORMAL)
        return false;
    if (state->active != 0u) {
        if (!increment_all(
                *state, {&state->counters.active_receipts_abandoned})) {
            return false;
        }
        state->active = 0u;
        state->active_receipt = {};
        state->active_descriptor = {};
    }
    if (!increment_all(*state, {&state->counters.abort_seal_successes}))
        return false;
    state->formal_fault = 1u;
    state->lifecycle = FK_QUIC_INITIAL_CRYPTO_GATE_SEALED_ABORT;
    return true;
}

bool fk_quic_initial_crypto_admission_gate_get_stats(
        const fk_quic_initial_crypto_admission_gate *gate,
        fk_quic_initial_crypto_admission_gate_stats *stats) {
    const GateState *state = implementation(gate);
    if (!valid_state(state) || stats == nullptr)
        return false;
    if (state->lifecycle == FK_QUIC_INITIAL_CRYPTO_GATE_ACCEPTING &&
        !owner_thread(*state)) {
        GateState *mutable_state = const_cast<GateState *>(state);
        saturating_atomic_increment(mutable_state->owner_thread_rejections);
        return false;
    }
    *stats = state->counters;
    stats->owner_claim_attempts =
        state->owner_claim_attempts.load(std::memory_order_acquire);
    stats->owner_claim_successes =
        state->owner_claim_successes.load(std::memory_order_acquire);
    stats->owner_claim_rejections =
        state->owner_claim_rejections.load(std::memory_order_acquire);
    stats->owner_thread_rejections =
        state->owner_thread_rejections.load(std::memory_order_acquire);
    stats->global_tokens_available = state->global_tokens;
    stats->last_physical_now_ns = state->last_physical_now_ns;
    stats->next_receipt_ordinal = state->next_receipt_ordinal;
    stats->service_memory_bytes = state->service_memory_bytes;
    stats->service_metadata_bytes = state->service_metadata_bytes;
    stats->service_prefix_table_bytes = state->service_prefix_table_bytes;
    stats->prefix_table_capacity = state->config.prefix_table_capacity;
    stats->maximum_probe_length = state->config.maximum_probe_length;
    stats->fair_share_divisor = state->config.fair_share_divisor;
    stats->cost_quantum_bytes = state->config.cost_quantum_bytes;
    stats->max_admissible_crypto_input_bytes =
        state->config.max_admissible_crypto_input_bytes;
    stats->abi_version =
        FK_QUIC_INITIAL_CRYPTO_ADMISSION_GATE_ABI_VERSION;
    stats->lifecycle = state->lifecycle;
    stats->terminal_reason = state->terminal_reason;
    stats->initialized = state->initialized;
    stats->owner_claimed = state->owner_claimed;
    stats->active_receipt = state->active;
    stats->pressure_active = state->pressure_active;
    stats->accounting_conserved = accounting_conserved_impl(*state) ? 1u : 0u;
    stats->service_memory_exact =
        state->service_metadata_bytes + state->service_prefix_table_bytes ==
                state->service_memory_bytes
            ? 1u : 0u;
    stats->formal_ready = formal_ready_impl(*state) ? 1u : 0u;
    stats->keys_injected = state->config.keys_precommitted;
    std::memcpy(
        stats->prefix_hash_key_commitment,
        state->prefix_hash_key_commitment,
        sizeof(stats->prefix_hash_key_commitment));
    std::memcpy(
        stats->receipt_key_0_commitment,
        state->receipt_key_0_commitment,
        sizeof(stats->receipt_key_0_commitment));
    std::memcpy(
        stats->receipt_key_1_commitment,
        state->receipt_key_1_commitment,
        sizeof(stats->receipt_key_1_commitment));
    return true;
}

bool fk_quic_initial_crypto_admission_gate_accounting_conserved(
        const fk_quic_initial_crypto_admission_gate *gate) {
    const GateState *state = implementation(gate);
    if (!valid_state(state))
        return false;
    if (state->lifecycle == FK_QUIC_INITIAL_CRYPTO_GATE_ACCEPTING &&
        !owner_thread(*state)) {
        GateState *mutable_state = const_cast<GateState *>(state);
        saturating_atomic_increment(mutable_state->owner_thread_rejections);
        return false;
    }
    return accounting_conserved_impl(*state);
}

bool fk_quic_initial_crypto_admission_gate_formal_ready(
        const fk_quic_initial_crypto_admission_gate *gate) {
    const GateState *state = implementation(gate);
    if (!valid_state(state))
        return false;
    if (state->lifecycle == FK_QUIC_INITIAL_CRYPTO_GATE_ACCEPTING &&
        !owner_thread(*state)) {
        GateState *mutable_state = const_cast<GateState *>(state);
        saturating_atomic_increment(mutable_state->owner_thread_rejections);
        return false;
    }
    return formal_ready_impl(*state);
}

bool fk_quic_initial_crypto_admission_gate_destroy_checked(
        fk_quic_initial_crypto_admission_gate *gate) {
    GateState *state = implementation(gate);
    if (!valid_state(state) ||
        state->lifecycle == FK_QUIC_INITIAL_CRYPTO_GATE_ACCEPTING ||
        state->active != 0u) {
        return false;
    }
    const size_t bytes = static_cast<size_t>(state->service_memory_bytes);
    const uint32_t prefix_count = state->config.prefix_table_capacity;
    PrefixEntry *prefix_entries = state->prefix_entries;
    for (uint32_t slot = 0u; slot < prefix_count; ++slot)
        prefix_entries[slot].~PrefixEntry();
    state->~GateState();
    volatile uint8_t *wipe = reinterpret_cast<volatile uint8_t *>(gate);
    for (size_t index = 0u; index < bytes; ++index)
        wipe[index] = 0u;
    return true;
}

const char *fk_quic_initial_crypto_admission_reason_name(
        fk_quic_initial_crypto_admission_reason reason) {
    switch (reason) {
    case FK_QUIC_INITIAL_CRYPTO_REASON_NONE:
        return "none";
    case FK_QUIC_INITIAL_CRYPTO_REASON_CHARGED_PREFIX_CRYPTO:
        return "charged_prefix_crypto";
    case FK_QUIC_INITIAL_CRYPTO_REASON_IDEMPOTENT_ACTIVE_RETRY:
        return "idempotent_active_retry";
    case FK_QUIC_INITIAL_CRYPTO_REASON_GLOBAL_TOKENS_EXHAUSTED:
        return "global_tokens_exhausted";
    case FK_QUIC_INITIAL_CRYPTO_REASON_PREFIX_CREDITS_EXHAUSTED:
        return "prefix_credits_exhausted";
    case FK_QUIC_INITIAL_CRYPTO_REASON_PREFIX_TABLE_PRESSURE:
        return "prefix_table_pressure";
    case FK_QUIC_INITIAL_CRYPTO_REASON_CRYPTO_INPUT_TOO_LARGE:
        return "crypto_input_too_large";
    case FK_QUIC_INITIAL_CRYPTO_REASON_INVALID_REQUEST:
        return "invalid_request";
    case FK_QUIC_INITIAL_CRYPTO_REASON_ACTIVE_DESCRIPTOR_MISMATCH:
        return "active_descriptor_mismatch";
    case FK_QUIC_INITIAL_CRYPTO_REASON_SEQUENCE_REPLAY:
        return "sequence_replay";
    case FK_QUIC_INITIAL_CRYPTO_REASON_COMPLETED_DESCRIPTOR_REPLAY:
        return "completed_descriptor_replay";
    case FK_QUIC_INITIAL_CRYPTO_REASON_CLOCK_REGRESSION:
        return "clock_regression";
    case FK_QUIC_INITIAL_CRYPTO_REASON_STOPPED:
        return "stopped";
    case FK_QUIC_INITIAL_CRYPTO_REASON_TERMINAL:
        return "terminal";
    case FK_QUIC_INITIAL_CRYPTO_REASON_COUNTER_OVERFLOW:
        return "counter_overflow";
    case FK_QUIC_INITIAL_CRYPTO_REASON_INTERNAL_FAILURE:
        return "internal_failure";
    case FK_QUIC_INITIAL_CRYPTO_REASON_COUNT:
        return "count";
    }
    return "unknown";
}

#ifdef FK_QUIC_INITIAL_CRYPTO_ADMISSION_GATE_TEST_HOOKS
bool fk_quic_initial_crypto_admission_gate_test_force_begin_attempts(
        fk_quic_initial_crypto_admission_gate *gate,
        uint64_t value) {
    GateState *state = implementation(gate);
    if (!valid_state(state) || !owner_thread(*state) ||
        state->lifecycle != FK_QUIC_INITIAL_CRYPTO_GATE_ACCEPTING)
        return false;
    state->counters.begin_attempts = value;
    return true;
}
#endif
