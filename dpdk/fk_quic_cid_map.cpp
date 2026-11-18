#include "fk_quic_cid_map.h"

#include "fk_quic_logical_id.h"

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <limits>
#include <new>
#include <type_traits>

namespace {

static_assert(
    sizeof(fk_quic_cid_initial_admission_proof) ==
        FK_QUIC_CID_INITIAL_ADMISSION_PROOF_BYTES,
    "QUIC Initial admission-proof ABI changed");
static_assert(offsetof(fk_quic_cid_initial_admission_proof, abi_version) == 0u,
    "QUIC Initial proof abi_version offset changed");
static_assert(offsetof(
    fk_quic_cid_initial_admission_proof, authentication_method) == 4u,
    "QUIC Initial proof authentication offset changed");
static_assert(offsetof(fk_quic_cid_initial_admission_proof, version) == 8u,
    "QUIC Initial proof version offset changed");
static_assert(offsetof(fk_quic_cid_initial_admission_proof, fixed_bit) == 12u,
    "QUIC Initial proof fixed-bit offset changed");
static_assert(offsetof(
    fk_quic_cid_initial_admission_proof, destination_cid) == 16u,
    "QUIC Initial proof DCID offset changed");
static_assert(offsetof(
    fk_quic_cid_initial_admission_proof, source_cid) == 36u,
    "QUIC Initial proof SCID offset changed");
static_assert(offsetof(fk_quic_cid_initial_admission_proof, reserved) == 56u,
    "QUIC Initial proof reserved offset changed");
static_assert(sizeof(fk_quic_cid_resolution) == 40u,
    "CID resolution value ABI changed");
static_assert(offsetof(
    fk_quic_cid_resolution, resolved_destination_cid_length) == 26u,
    "CID resolution destination-CID length offset changed");
static_assert(offsetof(fk_quic_cid_resolution, reserved0) == 27u,
    "CID resolution reserved byte offset changed");
static_assert(offsetof(fk_quic_cid_resolution, code) == 28u &&
        offsetof(fk_quic_cid_resolution, reason) == 32u,
    "CID resolution enum offsets changed");
static_assert(offsetof(
    fk_quic_cid_map_stats, route_prevalidation_internal_integrity) ==
    offsetof(fk_quic_cid_map_stats, route_prevalidation_calls) +
        7u * sizeof(uint64_t),
    "route-prevalidation diagnostics must remain contiguous");
static_assert(offsetof(
    fk_quic_cid_map_stats, route_prevalidation_internal_integrity) +
        sizeof(uint64_t) == sizeof(fk_quic_cid_map_stats),
    "route-prevalidation diagnostics must remain append-only tail fields");
static_assert(sizeof(fk_quic_cid_map_topology_receipt) == 32u &&
        offsetof(fk_quic_cid_map_topology_receipt,
            receipt_abi_version) == 0u &&
        offsetof(fk_quic_cid_map_topology_receipt,
            logical_id_abi_version) == 4u &&
        offsetof(fk_quic_cid_map_topology_receipt,
            fixed_owner_count) == 12u &&
        offsetof(fk_quic_cid_map_topology_receipt,
            maximum_connection_slots) == 16u &&
        offsetof(fk_quic_cid_map_topology_receipt,
            topology_config_hash) == 24u,
    "CID topology receipt ABI changed");

template <typename Enum>
typename std::underlying_type<Enum>::type enum_object_representation(
        const Enum &value) {
    using Underlying = typename std::underlying_type<Enum>::type;
    static_assert(sizeof(Underlying) == sizeof(Enum),
        "enum representation size changed");
    Underlying raw{};
    /* The parser observation is an external C ABI record. Read its object
     * representation before validation so a deliberately malformed enum does
     * not itself trigger C++ undefined behaviour under UBSan. */
    std::memcpy(&raw, &value, sizeof(raw));
    return raw;
}

constexpr uint32_t kNone = std::numeric_limits<uint32_t>::max();
constexpr uint64_t kMagic = 0x464b514349444d31ull;  // "FKQCIDM1"
constexpr uint32_t kQuicV1 = 0x00000001u;
constexpr uint32_t kQuicV2 = 0x6b3343cfu;
constexpr uint16_t kConnectionActive = 1u << 0u;
constexpr uint16_t kConnectionPendingHandshake = 1u << 1u;
constexpr uint16_t kConnectionGreaseQuicBitNegotiated = 1u << 2u;
constexpr uint16_t kConnectionPublished = 1u << 3u;
constexpr uint16_t kConnectionRetiredPendingOwnerAck = 1u << 4u;
constexpr uint16_t kConnectionRetirementSequenceKnown = 1u << 5u;
constexpr uint16_t kConnectionBindingEstablished = 1u << 6u;
constexpr uint16_t kConnectionGenerationExhausted = 1u << 7u;
constexpr uint16_t kConnectionRetiredExpired = 1u << 8u;
constexpr uint16_t kConnectionRetirementTimestampKnown = 1u << 9u;
constexpr uint16_t kConnectionRetirementTimestampFormal = 1u << 10u;
constexpr uint16_t kConnectionRetirementDispatched = 1u << 11u;
constexpr uint8_t kCidActive = 1u << 0u;
constexpr uint8_t kCidAmbiguous = 1u << 1u;
constexpr uint8_t kCidDestinationDirectionKnown = 1u << 2u;
constexpr uint8_t kCidDestinationDirection = 1u << 3u;

struct ConnectionEntry {
    uint64_t created_ns;
    uint64_t last_seen_ns;
    uint64_t expiry_ns;
    uint32_t first_cid;
    uint32_t next_free;
    uint32_t generation;
    uint16_t owner;
    uint16_t cid_count;
    uint16_t flags;
};

struct CidEntry {
    uint64_t last_seen_ns;
    uint64_t expiry_ns;
    uint32_t connection_slot;
    uint32_t next_bucket;
    uint32_t next_connection;
    uint32_t next_free;
    uint8_t bytes[FK_QUIC_CID_MAX_BYTES];
    uint8_t length;
    uint8_t flags;
};

struct State {
    std::atomic_flag lock = ATOMIC_FLAG_INIT;
    uint64_t magic;
    fk_quic_cid_map_config config;
    fk_quic_cid_map_stats stats;
    ConnectionEntry *connections;
    CidEntry *cids;
    uint32_t *cid_buckets;
    uint32_t *active_connections_by_fixed_owner;
    uint32_t *binding_credits_by_fixed_owner;
    /* The former per-owner retired-count region was redundant because
     * binding_credits-active_connections is the exact retired count.  Reuse
     * that already reserved region for the first-undispatched cursor so the
     * new O(1) publication index allocates no per-owner bytes. */
    uint32_t *first_undispatched_by_fixed_owner;
    uint32_t *retired_head_by_fixed_owner;
    uint32_t *retired_tail_by_fixed_owner;
    uint32_t cid_bucket_count;
    uint32_t cid_bucket_mask;
    uint32_t connection_free_head;
    uint32_t cid_free_head;
    uint32_t connection_scan_cursor;
    uint32_t cid_scan_cursor;
    uint32_t active_cid_length_counts[FK_QUIC_CID_MAX_BYTES];
    uint32_t active_cid_length_mask;
    uint64_t last_timestamp_ns;
    uint64_t retirement_ordinal;
    size_t reserved_bytes;
    size_t fixed_used_bytes;
    uint32_t free_connection_slots;
    uint32_t quarantined_connection_slots;
    uint8_t time_initialized;
    uint8_t expiration_scan_phase;
};

struct LockGuard {
    explicit LockGuard(State &state) : state_(state) {
        while (state_.lock.test_and_set(std::memory_order_acquire)) {
        }
    }
    ~LockGuard() {
        state_.lock.clear(std::memory_order_release);
    }
    State &state_;
};

static State *implementation(fk_quic_cid_map *map) {
    return reinterpret_cast<State *>(map);
}

static const State *implementation(const fk_quic_cid_map *map) {
    return reinterpret_cast<const State *>(map);
}

static void set_error(char *error, size_t capacity, const char *message) {
    if (error != nullptr && capacity != 0u)
        std::snprintf(error, capacity, "%s", message);
}

constexpr uint64_t kTopologyFnvOffset = UINT64_C(14695981039346656037);
constexpr uint64_t kTopologyFnvPrime = UINT64_C(1099511628211);

static void topology_hash_byte(uint64_t &hash, uint8_t value) {
    hash ^= value;
    hash *= kTopologyFnvPrime;
}

static void topology_hash_u16(uint64_t &hash, uint16_t value) {
    topology_hash_byte(hash, static_cast<uint8_t>(value));
    topology_hash_byte(hash, static_cast<uint8_t>(value >> 8u));
}

static void topology_hash_u32(uint64_t &hash, uint32_t value) {
    topology_hash_u16(hash, static_cast<uint16_t>(value));
    topology_hash_u16(hash, static_cast<uint16_t>(value >> 16u));
}

static uint64_t topology_config_hash(
        uint16_t fixed_owner_count,
        uint32_t maximum_connection_slots) {
    static constexpr char kDomain[] = "FLOWKEEP_OWNER_TOPOLOGY_V1";
    uint64_t hash = kTopologyFnvOffset;
    for (size_t index = 0u; index + 1u < sizeof(kDomain); ++index)
        topology_hash_byte(hash, static_cast<uint8_t>(kDomain[index]));
    topology_hash_u32(
        hash, FK_QUIC_CID_MAP_TOPOLOGY_RECEIPT_ABI_VERSION);
    topology_hash_u16(hash, FK_QUIC_LOGICAL_ID_ABI_VERSION);
    topology_hash_byte(hash, FK_QUIC_LOGICAL_ID_FULL_WIDTH_BITS);
    topology_hash_byte(hash, FK_QUIC_LOGICAL_ID_GENERATION_BITS);
    topology_hash_byte(hash, FK_QUIC_LOGICAL_ID_ENCODED_SLOT_BITS);
    topology_hash_byte(hash, 1u);  // full-width logical id required
    topology_hash_byte(hash, 1u);  // retire acknowledgement required
    topology_hash_u16(hash, fixed_owner_count);
    topology_hash_u32(hash, maximum_connection_slots);
    return hash;
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

static bool next_power_of_two(uint64_t value, uint32_t &result) {
    if (value == 0u || value > (1ull << 31u))
        return false;
    uint64_t power = 1u;
    while (power < value)
        power <<= 1u;
    result = static_cast<uint32_t>(power);
    return true;
}

static bool layout(
        const fk_quic_cid_map_config &config,
        size_t &bytes,
        uint32_t &bucket_count) {
    if (!next_power_of_two(
            static_cast<uint64_t>(config.maximum_cids) * 2u,
            bucket_count))
        return false;
    size_t offset = alignof(std::max_align_t) - 1u;
    if (!add_region(offset, 1u, sizeof(State), alignof(State)) ||
        !add_region(
            offset,
            config.maximum_connections,
            sizeof(ConnectionEntry),
            alignof(ConnectionEntry)) ||
        !add_region(
            offset,
            config.maximum_cids,
            sizeof(CidEntry),
            alignof(CidEntry)) ||
        !add_region(
            offset,
            bucket_count,
            sizeof(uint32_t),
            alignof(uint32_t)) ||
        !add_region(
            offset,
            config.fixed_owner_count,
            sizeof(uint32_t),
            alignof(uint32_t)) ||
        !add_region(
            offset,
            config.fixed_owner_count,
            sizeof(uint32_t),
            alignof(uint32_t)) ||
        !add_region(
            offset,
            config.fixed_owner_count,
            sizeof(uint32_t),
            alignof(uint32_t)) ||
        !add_region(
            offset,
            config.fixed_owner_count,
            sizeof(uint32_t),
            alignof(uint32_t)) ||
        !add_region(
            offset,
            config.fixed_owner_count,
            sizeof(uint32_t),
            alignof(uint32_t)))
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

static uint64_t saturating_add(uint64_t left, uint64_t right) {
    return right > std::numeric_limits<uint64_t>::max() - left
        ? std::numeric_limits<uint64_t>::max() : left + right;
}

static uint64_t rotate_left(uint64_t value, uint32_t bits) {
    return (value << bits) | (value >> (64u - bits));
}

static uint64_t load_little_endian_u64(const uint8_t *bytes) {
    uint64_t value = 0u;
    for (uint32_t index = 0u; index < 8u; ++index)
        value |= static_cast<uint64_t>(bytes[index]) << (8u * index);
    return value;
}

static void sip_round(
        uint64_t &v0, uint64_t &v1, uint64_t &v2, uint64_t &v3) {
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

static uint64_t siphash24(
        const uint8_t key[16], const uint8_t *data, size_t length) {
    const uint64_t key0 = load_little_endian_u64(key);
    const uint64_t key1 = load_little_endian_u64(key + 8u);
    uint64_t v0 = 0x736f6d6570736575ull ^ key0;
    uint64_t v1 = 0x646f72616e646f6dull ^ key1;
    uint64_t v2 = 0x6c7967656e657261ull ^ key0;
    uint64_t v3 = 0x7465646279746573ull ^ key1;
    size_t offset = 0u;
    while (length - offset >= 8u) {
        const uint64_t message = load_little_endian_u64(data + offset);
        v3 ^= message;
        sip_round(v0, v1, v2, v3);
        sip_round(v0, v1, v2, v3);
        v0 ^= message;
        offset += 8u;
    }
    uint64_t tail = static_cast<uint64_t>(length) << 56u;
    for (size_t index = 0u; index < length - offset; ++index)
        tail |= static_cast<uint64_t>(data[offset + index]) <<
            (8u * index);
    v3 ^= tail;
    sip_round(v0, v1, v2, v3);
    sip_round(v0, v1, v2, v3);
    v0 ^= tail;
    v2 ^= 0xffu;
    sip_round(v0, v1, v2, v3);
    sip_round(v0, v1, v2, v3);
    sip_round(v0, v1, v2, v3);
    sip_round(v0, v1, v2, v3);
    return v0 ^ v1 ^ v2 ^ v3;
}

static uint64_t cid_hash(
        const State &state, const uint8_t *cid, uint8_t length) {
    uint8_t domain_separated[1u + FK_QUIC_CID_MAX_BYTES]{};
    domain_separated[0] = length;
    std::memcpy(domain_separated + 1u, cid, length);
    return siphash24(
        state.config.siphash_key,
        domain_separated,
        static_cast<size_t>(length) + 1u);
}

static bool valid_cid(const uint8_t *cid, uint8_t length) {
    return cid != nullptr && length != 0u &&
        length <= FK_QUIC_CID_MAX_BYTES;
}

enum LongHeaderValidation {
    LONG_HEADER_NOT_QUIC,
    LONG_HEADER_UNSUPPORTED,
    LONG_HEADER_INVALID,
    LONG_HEADER_VALID,
};

static bool expected_long_packet_type(
        uint32_t version,
        uint8_t type_bits,
        fk_quic_long_packet_type &expected) {
    if (type_bits > 3u)
        return false;
    if (version == kQuicV1) {
        static const fk_quic_long_packet_type types[4]{
            FK_QUIC_LONG_PACKET_INITIAL,
            FK_QUIC_LONG_PACKET_ZERO_RTT,
            FK_QUIC_LONG_PACKET_HANDSHAKE,
            FK_QUIC_LONG_PACKET_RETRY,
        };
        expected = types[type_bits];
        return true;
    }
    if (version == kQuicV2) {
        static const fk_quic_long_packet_type types[4]{
            FK_QUIC_LONG_PACKET_RETRY,
            FK_QUIC_LONG_PACKET_INITIAL,
            FK_QUIC_LONG_PACKET_ZERO_RTT,
            FK_QUIC_LONG_PACKET_HANDSHAKE,
        };
        expected = types[type_bits];
        return true;
    }
    return false;
}

static LongHeaderValidation validate_long_header_observation(
        const fk_quic_header_observation *observation,
        fk_quic_long_packet_type &packet_type) {
    if (observation == nullptr)
        return LONG_HEADER_INVALID;
    using InspectionRaw =
        typename std::underlying_type<fk_quic_inspection>::type;
    using CompletenessRaw =
        typename std::underlying_type<fk_protocol_completeness>::type;
    using PacketTypeRaw =
        typename std::underlying_type<fk_quic_long_packet_type>::type;
    const InspectionRaw status =
        enum_object_representation(observation->status);
    const CompletenessRaw completeness =
        enum_object_representation(observation->completeness);
    const PacketTypeRaw observed_packet_type =
        enum_object_representation(observation->long_packet_type);
    if (status == static_cast<InspectionRaw>(FK_QUIC_NOT_DETECTED))
        return LONG_HEADER_NOT_QUIC;
    if (status == static_cast<InspectionRaw>(
            FK_QUIC_VERSION_NEGOTIATION_PARTIAL) ||
        (observation->version != kQuicV1 &&
         observation->version != kQuicV2))
        return LONG_HEADER_UNSUPPORTED;
    if (status != static_cast<InspectionRaw>(
            FK_QUIC_LONG_HEADER_PARTIAL) ||
        completeness != static_cast<CompletenessRaw>(
            FK_COMPLETENESS_PARTIAL) ||
        observation->destination_cid_length > FK_QUIC_CID_MAX_BYTES ||
        observation->source_cid_length > FK_QUIC_CID_MAX_BYTES ||
        !expected_long_packet_type(
            observation->version,
            observation->long_packet_type_bits,
            packet_type) ||
        observed_packet_type != static_cast<PacketTypeRaw>(packet_type))
        return LONG_HEADER_INVALID;
    return LONG_HEADER_VALID;
}

static fk_quic_cid_reject_reason validate_initial_admission_proof(
        const fk_quic_header_observation &observation,
        fk_quic_long_packet_type packet_type,
        const fk_quic_cid_initial_admission_proof *proof) {
    if (packet_type != FK_QUIC_LONG_PACKET_INITIAL)
        return FK_QUIC_CID_REJECT_NON_INITIAL_MUTATION;
    if (proof == nullptr ||
        proof->authentication_method == FK_QUIC_CID_INITIAL_AUTH_NONE)
        return FK_QUIC_CID_REJECT_INITIAL_AUTH_REQUIRED;
    if (proof->fixed_bit == 0u)
        return FK_QUIC_CID_REJECT_FIXED_BIT_ZERO;
    static const uint8_t zero_reserved[4]{};
    if (proof->abi_version !=
            FK_QUIC_CID_INITIAL_ADMISSION_PROOF_ABI_VERSION ||
        proof->authentication_method !=
            FK_QUIC_CID_INITIAL_AUTH_AEAD_VERIFIED ||
        proof->fixed_bit != 1u ||
        proof->version != observation.version ||
        proof->long_packet_type_bits !=
            observation.long_packet_type_bits ||
        proof->destination_cid_length !=
            observation.destination_cid_length ||
        proof->source_cid_length != observation.source_cid_length ||
        std::memcmp(
            proof->reserved,
            zero_reserved,
            sizeof(proof->reserved)) != 0 ||
        std::memcmp(
            proof->destination_cid,
            observation.destination_cid,
            observation.destination_cid_length) != 0 ||
        std::memcmp(
            proof->source_cid,
            observation.source_cid,
            observation.source_cid_length) != 0)
        return FK_QUIC_CID_REJECT_INITIAL_PROOF_MISMATCH;
    for (uint8_t index = observation.destination_cid_length;
         index < FK_QUIC_CID_MAX_BYTES; ++index) {
        if (proof->destination_cid[index] != 0u)
            return FK_QUIC_CID_REJECT_INITIAL_PROOF_MISMATCH;
    }
    for (uint8_t index = observation.source_cid_length;
         index < FK_QUIC_CID_MAX_BYTES; ++index) {
        if (proof->source_cid[index] != 0u)
            return FK_QUIC_CID_REJECT_INITIAL_PROOF_MISMATCH;
    }
    return FK_QUIC_CID_REJECT_NONE;
}

static bool connection_flag(
        const ConnectionEntry &entry, uint16_t flag) {
    return (entry.flags & flag) != 0u;
}

static void set_connection_flag(
        ConnectionEntry &entry, uint16_t flag, bool enabled) {
    if (enabled)
        entry.flags |= flag;
    else
        entry.flags &= static_cast<uint16_t>(~flag);
}

static bool cid_flag(const CidEntry &entry, uint8_t flag) {
    return (entry.flags & flag) != 0u;
}

static void set_cid_flag(CidEntry &entry, uint8_t flag, bool enabled) {
    if (enabled)
        entry.flags |= flag;
    else
        entry.flags &= static_cast<uint8_t>(~flag);
}

static uint64_t logical_id(
        const ConnectionEntry &entry, uint32_t slot) {
    uint64_t id = 0u;
    return fk_quic_logical_id_encode(slot, entry.generation, &id)
        ? id : 0u;
}

static ConnectionEntry *connection_by_id(
        State &state, uint64_t id, uint32_t *slot_out = nullptr) {
    uint32_t slot = kNone;
    uint32_t generation = 0u;
    if (!fk_quic_logical_id_decode(
            id,
            state.config.maximum_connections,
            &slot,
            &generation))
        return nullptr;
    ConnectionEntry &entry = state.connections[slot];
    if (!connection_flag(entry, kConnectionActive) ||
        !connection_flag(entry, kConnectionPublished) ||
        entry.generation != generation)
        return nullptr;
    if (slot_out != nullptr)
        *slot_out = slot;
    return &entry;
}

enum FindCode {
    FIND_NOT_FOUND,
    FIND_FOUND,
    FIND_CHAIN_LIMIT,
    FIND_INTERNAL,
};

struct FindResult {
    FindCode code;
    uint32_t slot;
    uint32_t previous;
    uint32_t traversed;
};

static FindResult find_cid(
        State &state, const uint8_t *cid, uint8_t length) {
    const uint32_t bucket =
        static_cast<uint32_t>(cid_hash(state, cid, length)) &
        state.cid_bucket_mask;
    uint32_t prior = kNone;
    uint32_t slot = state.cid_buckets[bucket];
    uint32_t traversed = 0u;
    while (slot != kNone &&
           traversed < state.config.maximum_hash_chain) {
        if (slot >= state.config.maximum_cids) {
            state.stats.hash_chain_internal_rejects++;
            state.stats.hard_integrity_failures++;
            return {FIND_INTERNAL, kNone, prior, traversed};
        }
        traversed++;
        const CidEntry &entry = state.cids[slot];
        if (cid_flag(entry, kCidActive) && entry.length == length &&
            std::memcmp(entry.bytes, cid, length) == 0) {
            if (traversed > state.stats.peak_hash_chain_traversed)
                state.stats.peak_hash_chain_traversed = traversed;
            return {FIND_FOUND, slot, prior, traversed};
        }
        prior = slot;
        slot = entry.next_bucket;
    }
    if (traversed > state.stats.peak_hash_chain_traversed)
        state.stats.peak_hash_chain_traversed = traversed;
    return {
        traversed >= state.config.maximum_hash_chain
            ? FIND_CHAIN_LIMIT : FIND_NOT_FOUND,
        kNone,
        prior,
        traversed,
    };
}

static void record_hash_chain_reject(
        State &state, bool registration, bool internal) {
    state.stats.hash_chain_limit_rejects++;
    if (internal) {
        state.stats.hash_chain_internal_rejects++;
        state.stats.hard_integrity_failures++;
    } else if (registration)
        state.stats.hash_chain_registration_rejects++;
    else
        state.stats.hash_chain_lookup_rejects++;
}

static void record_short_header_probes(
        State &state, uint32_t probes) {
    state.stats.short_header_hash_probes += probes;
    if (probes > state.stats.peak_short_header_hash_probes)
        state.stats.peak_short_header_hash_probes = probes;
}

static void refresh_used(State &state) {
    const uint64_t used = static_cast<uint64_t>(state.fixed_used_bytes) +
        static_cast<uint64_t>(state.stats.binding_credits_in_use) *
            sizeof(ConnectionEntry) +
        static_cast<uint64_t>(state.stats.active_cids) * sizeof(CidEntry);
    state.stats.used_bytes = used;
    if (used > state.stats.peak_used_bytes)
        state.stats.peak_used_bytes = used;
    if (used > state.reserved_bytes)
        state.stats.hard_budget_violations++;
}

static bool unlink_cid_from_connection(
        State &state, uint32_t cid_slot, uint32_t connection_slot) {
    if (connection_slot >= state.config.maximum_connections)
        return false;
    ConnectionEntry &connection = state.connections[connection_slot];
    uint32_t previous = kNone;
    uint32_t current = connection.first_cid;
    uint16_t traversed = 0u;
    while (current != kNone &&
           traversed < state.config.maximum_cids_per_connection) {
        if (current >= state.config.maximum_cids)
            return false;
        traversed++;
        CidEntry &entry = state.cids[current];
        if (current == cid_slot) {
            if (connection.cid_count == 0u)
                return false;
            if (previous == kNone)
                connection.first_cid = entry.next_connection;
            else
                state.cids[previous].next_connection =
                    entry.next_connection;
            connection.cid_count--;
            entry.next_connection = kNone;
            return true;
        }
        previous = current;
        current = entry.next_connection;
    }
    return false;
}

static bool remove_cid(State &state, uint32_t slot, bool expired) {
    if (slot >= state.config.maximum_cids) {
        state.stats.hard_integrity_failures++;
        return false;
    }
    CidEntry &entry = state.cids[slot];
    if (!cid_flag(entry, kCidActive))
        return true;
    if (entry.length == 0u || entry.length > FK_QUIC_CID_MAX_BYTES) {
        state.stats.hard_integrity_failures++;
        return false;
    }
    const uint32_t bucket =
        static_cast<uint32_t>(
            cid_hash(state, entry.bytes, entry.length)) &
        state.cid_bucket_mask;
    uint32_t previous = kNone;
    uint32_t current = state.cid_buckets[bucket];
    uint32_t traversed = 0u;
    while (current != kNone && current != slot &&
           traversed < state.config.maximum_hash_chain) {
        if (current >= state.config.maximum_cids) {
            record_hash_chain_reject(state, false, true);
            return false;
        }
        traversed++;
        previous = current;
        current = state.cids[current].next_bucket;
    }
    if (current != slot) {
        record_hash_chain_reject(state, false, true);
        return false;
    }
    const uint8_t old_length = entry.length;
    if (state.stats.active_cids == 0u ||
        state.active_cid_length_counts[old_length - 1u] == 0u) {
        state.stats.hard_integrity_failures++;
        return false;
    }
    if (!cid_flag(entry, kCidAmbiguous) &&
        !unlink_cid_from_connection(
            state, slot, entry.connection_slot)) {
        state.stats.hard_integrity_failures++;
        return false;
    }
    if (current == slot) {
        if (previous == kNone)
            state.cid_buckets[bucket] = entry.next_bucket;
        else
            state.cids[previous].next_bucket = entry.next_bucket;
    }
    entry = {};
    entry.connection_slot = kNone;
    entry.next_bucket = kNone;
    entry.next_connection = kNone;
    entry.next_free = state.cid_free_head;
    state.cid_free_head = slot;
    state.stats.active_cids--;
    uint32_t &count = state.active_cid_length_counts[old_length - 1u];
    count--;
    if (count == 0u)
        state.active_cid_length_mask &= ~(1u << (old_length - 1u));
    if (expired)
        state.stats.cids_expired++;
    return true;
}

static void record_allocator_integrity_failure(State &state) {
    state.stats.allocator_integrity_failures++;
    state.stats.hard_integrity_failures++;
}

static void reclaim_unpublished_or_acknowledged_slot(
        State &state, uint32_t slot) {
    ConnectionEntry &entry = state.connections[slot];
    const uint32_t generation = entry.generation;
    entry = {};
    entry.generation = generation;
    entry.first_cid = kNone;
    entry.next_free = kNone;
    if (generation == std::numeric_limits<uint32_t>::max()) {
        set_connection_flag(
            entry, kConnectionGenerationExhausted, true);
        state.quarantined_connection_slots++;
        state.stats.quarantined_connection_slots =
            state.quarantined_connection_slots;
        state.stats.generation_exhaustions++;
        return;
    }
    entry.next_free = state.connection_free_head;
    state.connection_free_head = slot;
    state.free_connection_slots++;
    state.stats.free_connection_slots = state.free_connection_slots;
}

static bool rollback_unpublished_connection(
        State &state, uint32_t slot) {
    if (slot >= state.config.maximum_connections) {
        state.stats.rollback_cleanup_failures++;
        state.stats.hard_integrity_failures++;
        return false;
    }
    ConnectionEntry &entry = state.connections[slot];
    if (!connection_flag(entry, kConnectionActive) ||
        connection_flag(entry, kConnectionPublished) ||
        entry.owner >= state.config.fixed_owner_count ||
        state.active_connections_by_fixed_owner[entry.owner] == 0u ||
        state.binding_credits_by_fixed_owner[entry.owner] == 0u ||
        state.stats.active_connections == 0u ||
        state.stats.binding_credits_in_use == 0u) {
        state.stats.rollback_cleanup_failures++;
        state.stats.hard_integrity_failures++;
        return false;
    }
    while (entry.first_cid != kNone) {
        if (!remove_cid(state, entry.first_cid, false)) {
            state.stats.rollback_cleanup_failures++;
            return false;
        }
    }
    if (connection_flag(entry, kConnectionPendingHandshake)) {
        if (state.stats.pending_handshakes == 0u) {
            state.stats.rollback_cleanup_failures++;
            state.stats.hard_integrity_failures++;
            return false;
        }
        state.stats.pending_handshakes--;
    }
    state.active_connections_by_fixed_owner[entry.owner]--;
    state.binding_credits_by_fixed_owner[entry.owner]--;
    state.stats.active_connections--;
    state.stats.binding_credits_in_use--;
    state.stats.connection_allocation_rollbacks++;
    reclaim_unpublished_or_acknowledged_slot(state, slot);
    refresh_used(state);
    return true;
}

static bool retired_fifo_valid_for_append(
        State &state, uint16_t owner) {
    const uint32_t head = state.retired_head_by_fixed_owner[owner];
    const uint32_t tail = state.retired_tail_by_fixed_owner[owner];
    const uint32_t undispatched =
        state.first_undispatched_by_fixed_owner[owner];
    if ((head == kNone) != (tail == kNone))
        return false;
    if (tail == kNone)
        return undispatched == kNone;
    if (head >= state.config.maximum_connections ||
        tail >= state.config.maximum_connections ||
        (undispatched != kNone &&
         undispatched >= state.config.maximum_connections))
        return false;
    const ConnectionEntry &tail_entry = state.connections[tail];
    if (!connection_flag(
            tail_entry, kConnectionRetiredPendingOwnerAck) ||
        tail_entry.owner != owner || tail_entry.next_free != kNone)
        return false;
    if (undispatched == kNone)
        return connection_flag(
            tail_entry, kConnectionRetirementDispatched);
    if (connection_flag(
            tail_entry, kConnectionRetirementDispatched))
        return false;
    const ConnectionEntry &undispatched_entry =
        state.connections[undispatched];
    return connection_flag(
            undispatched_entry, kConnectionRetiredPendingOwnerAck) &&
        !connection_flag(
            undispatched_entry, kConnectionRetirementDispatched) &&
        undispatched_entry.owner == owner;
}

static bool retire_published_connection(
        State &state,
        uint32_t slot,
        bool expired,
        bool packet_sequence_known,
        uint64_t packet_sequence,
        uint64_t retirement_timestamp_ns,
        bool retirement_timestamp_known,
        bool retirement_timestamp_formal) {
    if (slot >= state.config.maximum_connections) {
        state.stats.hard_integrity_failures++;
        return false;
    }
    ConnectionEntry &entry = state.connections[slot];
    if (!connection_flag(entry, kConnectionActive) ||
        !connection_flag(entry, kConnectionPublished) ||
        entry.owner >= state.config.fixed_owner_count ||
        state.active_connections_by_fixed_owner[entry.owner] == 0u ||
        state.binding_credits_by_fixed_owner[entry.owner] == 0u ||
        state.stats.active_connections == 0u ||
        state.stats.binding_credits_in_use == 0u ||
        !retired_fifo_valid_for_append(state, entry.owner) ||
        (retirement_timestamp_formal &&
         !retirement_timestamp_known) ||
        (retirement_timestamp_known &&
         (retirement_timestamp_ns < entry.created_ns ||
          retirement_timestamp_ns < entry.last_seen_ns)) ||
        (expired &&
         (!retirement_timestamp_known ||
          !retirement_timestamp_formal))) {
        state.stats.hard_integrity_failures++;
        return false;
    }
    if (state.retirement_ordinal ==
            std::numeric_limits<uint64_t>::max()) {
        state.stats.retirement_ordinal_exhaustions++;
        state.stats.hard_integrity_failures++;
        return false;
    }
    while (entry.first_cid != kNone) {
        if (!remove_cid(state, entry.first_cid, expired))
            return false;
    }
    if (connection_flag(entry, kConnectionPendingHandshake)) {
        if (state.stats.pending_handshakes == 0u) {
            state.stats.hard_integrity_failures++;
            return false;
        }
        state.stats.pending_handshakes--;
    }

    const uint16_t owner = entry.owner;
    const bool binding_established = connection_flag(
        entry, kConnectionBindingEstablished);
    const uint32_t prior_tail =
        state.retired_tail_by_fixed_owner[owner];
    const uint64_t ordinal = ++state.retirement_ordinal;
    const uint32_t generation = entry.generation;
    entry = {};
    entry.created_ns = ordinal;
    entry.last_seen_ns = packet_sequence_known ? packet_sequence : 0u;
    entry.expiry_ns = retirement_timestamp_known
        ? retirement_timestamp_ns : 0u;
    entry.first_cid = kNone;
    entry.next_free = kNone;
    entry.generation = generation;
    entry.owner = owner;
    set_connection_flag(
        entry, kConnectionRetiredPendingOwnerAck, true);
    set_connection_flag(
        entry,
        kConnectionRetirementSequenceKnown,
        packet_sequence_known);
    set_connection_flag(
        entry, kConnectionBindingEstablished, binding_established);
    set_connection_flag(entry, kConnectionRetiredExpired, expired);
    set_connection_flag(
        entry,
        kConnectionRetirementTimestampKnown,
        retirement_timestamp_known);
    set_connection_flag(
        entry,
        kConnectionRetirementTimestampFormal,
        retirement_timestamp_formal);
    if (prior_tail == kNone) {
        state.retired_head_by_fixed_owner[owner] = slot;
    } else {
        state.connections[prior_tail].next_free = slot;
    }
    state.retired_tail_by_fixed_owner[owner] = slot;
    if (state.first_undispatched_by_fixed_owner[owner] == kNone)
        state.first_undispatched_by_fixed_owner[owner] = slot;

    state.active_connections_by_fixed_owner[owner]--;
    state.stats.active_connections--;
    state.stats.retired_pending_owner_ack++;
    state.stats.connections_retired_pending_owner_ack++;
    if (state.stats.retired_pending_owner_ack >
            state.stats.peak_retired_pending_owner_ack) {
        state.stats.peak_retired_pending_owner_ack =
            state.stats.retired_pending_owner_ack;
    }
    if (expired)
        state.stats.connections_expired++;
    refresh_used(state);
    return true;
}

static bool publish_connection(State &state, uint32_t slot) {
    if (slot >= state.config.maximum_connections) {
        state.stats.hard_integrity_failures++;
        return false;
    }
    ConnectionEntry &entry = state.connections[slot];
    if (!connection_flag(entry, kConnectionActive) ||
        connection_flag(entry, kConnectionPublished) ||
        entry.owner >= state.config.fixed_owner_count) {
        state.stats.hard_integrity_failures++;
        return false;
    }
    set_connection_flag(entry, kConnectionPublished, true);
    state.stats.connections_created++;
    if (state.stats.active_connections >
            state.stats.peak_active_connections) {
        state.stats.peak_active_connections =
            state.stats.active_connections;
    }
    if (state.stats.pending_handshakes >
            state.stats.peak_pending_handshakes) {
        state.stats.peak_pending_handshakes =
            state.stats.pending_handshakes;
    }
    if (state.stats.binding_credits_in_use >
            state.stats.peak_binding_credits_in_use) {
        state.stats.peak_binding_credits_in_use =
            state.stats.binding_credits_in_use;
    }
    const uint32_t owner_active =
        state.active_connections_by_fixed_owner[entry.owner];
    if (owner_active >
            state.stats.peak_active_connections_per_fixed_owner) {
        state.stats.peak_active_connections_per_fixed_owner = owner_active;
    }
    const uint32_t owner_credits =
        state.binding_credits_by_fixed_owner[entry.owner];
    if (owner_credits >
            state.stats.peak_binding_credits_per_fixed_owner) {
        state.stats.peak_binding_credits_per_fixed_owner = owner_credits;
    }
    return true;
}

static bool expire_bounded(State &state, uint64_t now_ns) {
    uint32_t remaining = state.config.expiration_scan_per_observation;
    while (remaining-- != 0u) {
        const bool scan_connection =
            state.expiration_scan_phase == 0u;
        state.expiration_scan_phase = static_cast<uint8_t>(
            state.expiration_scan_phase ^ 1u);
        if (scan_connection) {
            const uint32_t slot = state.connection_scan_cursor++ %
                state.config.maximum_connections;
            ConnectionEntry &entry = state.connections[slot];
            if (connection_flag(entry, kConnectionActive) &&
                entry.expiry_ns <= now_ns &&
                !retire_published_connection(
                    state,
                    slot,
                    true,
                    false,
                    0u,
                    now_ns,
                    true,
                    true)) {
                refresh_used(state);
                return false;
            }
        } else {
            const uint32_t slot = state.cid_scan_cursor++ %
                state.config.maximum_cids;
            CidEntry &entry = state.cids[slot];
            if (cid_flag(entry, kCidActive) &&
                entry.expiry_ns <= now_ns &&
                !remove_cid(state, slot, true)) {
                refresh_used(state);
                return false;
            }
        }
    }
    refresh_used(state);
    return true;
}

enum AdvanceTimeResult {
    ADVANCE_TIME_OK,
    ADVANCE_TIME_REGRESSION,
    ADVANCE_TIME_INTERNAL_FAILURE,
};

static AdvanceTimeResult advance_time(
        State &state, uint64_t timestamp_ns) {
    if (state.time_initialized != 0u &&
        timestamp_ns < state.last_timestamp_ns) {
        state.stats.clock_regressions++;
        return ADVANCE_TIME_REGRESSION;
    }
    state.last_timestamp_ns = timestamp_ns;
    state.time_initialized = 1u;
    return expire_bounded(state, timestamp_ns)
        ? ADVANCE_TIME_OK : ADVANCE_TIME_INTERNAL_FAILURE;
}

static uint32_t allocate_connection(
        State &state, uint64_t now_ns, uint16_t owner) {
    if (owner >= state.config.fixed_owner_count ||
        state.binding_credits_by_fixed_owner[owner] >=
            state.config.maximum_connections_per_fixed_owner ||
        state.connection_free_head == kNone ||
        state.free_connection_slots == 0u)
        return kNone;
    const uint32_t slot = state.connection_free_head;
    if (slot >= state.config.maximum_connections)
        return kNone;
    ConnectionEntry &entry = state.connections[slot];
    if (connection_flag(entry, kConnectionActive) ||
        connection_flag(entry, kConnectionRetiredPendingOwnerAck) ||
        connection_flag(entry, kConnectionGenerationExhausted) ||
        entry.generation == std::numeric_limits<uint32_t>::max())
        return kNone;
    state.connection_free_head = entry.next_free;
    state.free_connection_slots--;
    state.stats.free_connection_slots = state.free_connection_slots;
    uint32_t generation = entry.generation + 1u;
    entry = {};
    entry.created_ns = now_ns;
    entry.last_seen_ns = now_ns;
    entry.expiry_ns = saturating_add(
        now_ns, state.config.connection_ttl_ns);
    entry.first_cid = kNone;
    entry.next_free = kNone;
    entry.generation = generation;
    entry.owner = owner;
    set_connection_flag(entry, kConnectionActive, true);
    set_connection_flag(entry, kConnectionPendingHandshake, true);
    state.stats.active_connections++;
    state.active_connections_by_fixed_owner[owner]++;
    state.stats.binding_credits_in_use++;
    state.binding_credits_by_fixed_owner[owner]++;
    state.stats.pending_handshakes++;
    return slot;
}

enum RegisterResult {
    REGISTERED,
    DUPLICATE,
    COLLISION,
    GLOBAL_FULL,
    PER_CONNECTION_FULL,
    HASH_CHAIN_FULL,
    DIRECTION_CONFLICT,
    EXPIRED_ASSOCIATION,
    INTERNAL_FAILURE,
};

static RegisterResult register_cid(
        State &state,
        uint32_t connection_slot,
        const uint8_t *cid,
        uint8_t length,
        bool destination_direction_known,
        uint8_t destination_direction,
        uint64_t now_ns) {
    if (connection_slot >= state.config.maximum_connections) {
        state.stats.hard_integrity_failures++;
        return INTERNAL_FAILURE;
    }
    ConnectionEntry &connection = state.connections[connection_slot];
    const FindResult found = find_cid(state, cid, length);
    if (found.code == FIND_INTERNAL)
        return INTERNAL_FAILURE;
    if (found.code == FIND_FOUND) {
        CidEntry &entry = state.cids[found.slot];
        if (entry.expiry_ns <= now_ns) {
            if (!remove_cid(state, found.slot, true)) {
                refresh_used(state);
                return INTERNAL_FAILURE;
            }
            refresh_used(state);
            return EXPIRED_ASSOCIATION;
        }
        if (!cid_flag(entry, kCidAmbiguous) &&
            entry.connection_slot == connection_slot) {
            if (destination_direction_known) {
                if (cid_flag(
                        entry, kCidDestinationDirectionKnown) &&
                    cid_flag(entry, kCidDestinationDirection) !=
                        (destination_direction != 0u)) {
                    state.stats.direction_conflicts++;
                    return DIRECTION_CONFLICT;
                }
                set_cid_flag(
                    entry, kCidDestinationDirectionKnown, true);
                set_cid_flag(
                    entry,
                    kCidDestinationDirection,
                    destination_direction != 0u);
            }
            entry.last_seen_ns = now_ns;
            entry.expiry_ns = saturating_add(
                now_ns, state.config.cid_ttl_ns);
            state.stats.duplicate_cids++;
            return DUPLICATE;
        }
        if (!cid_flag(entry, kCidAmbiguous)) {
            if (!unlink_cid_from_connection(
                    state, found.slot, entry.connection_slot)) {
                state.stats.hard_integrity_failures++;
                return INTERNAL_FAILURE;
            }
            entry.connection_slot = kNone;
            set_cid_flag(entry, kCidAmbiguous, true);
            set_cid_flag(entry, kCidDestinationDirectionKnown, false);
            set_cid_flag(entry, kCidDestinationDirection, false);
            state.stats.cid_collisions++;
        }
        entry.last_seen_ns = now_ns;
        entry.expiry_ns = saturating_add(
            now_ns, state.config.cid_ttl_ns);
        return COLLISION;
    }
    if (found.code == FIND_CHAIN_LIMIT) {
        record_hash_chain_reject(state, true, false);
        return HASH_CHAIN_FULL;
    }
    if (connection.cid_count >=
            state.config.maximum_cids_per_connection) {
        state.stats.per_connection_cid_capacity_rejects++;
        return PER_CONNECTION_FULL;
    }
    if (state.cid_free_head == kNone) {
        state.stats.cid_capacity_rejects++;
        return GLOBAL_FULL;
    }
    const uint32_t slot = state.cid_free_head;
    if (slot >= state.config.maximum_cids) {
        record_allocator_integrity_failure(state);
        return INTERNAL_FAILURE;
    }
    CidEntry &entry = state.cids[slot];
    if (entry.flags != 0u || entry.connection_slot != kNone ||
        entry.next_bucket != kNone || entry.next_connection != kNone ||
        entry.length != 0u) {
        record_allocator_integrity_failure(state);
        return INTERNAL_FAILURE;
    }
    state.cid_free_head = entry.next_free;
    entry = {};
    entry.last_seen_ns = now_ns;
    entry.expiry_ns = saturating_add(now_ns, state.config.cid_ttl_ns);
    entry.connection_slot = connection_slot;
    entry.next_connection = connection.first_cid;
    entry.next_free = kNone;
    entry.length = length;
    set_cid_flag(entry, kCidActive, true);
    set_cid_flag(
        entry,
        kCidDestinationDirectionKnown,
        destination_direction_known);
    set_cid_flag(
        entry,
        kCidDestinationDirection,
        destination_direction_known && destination_direction != 0u);
    std::memcpy(entry.bytes, cid, length);
    const uint32_t bucket =
        static_cast<uint32_t>(cid_hash(state, cid, length)) &
        state.cid_bucket_mask;
    entry.next_bucket = state.cid_buckets[bucket];
    state.cid_buckets[bucket] = slot;
    connection.first_cid = slot;
    connection.cid_count++;
    state.stats.active_cids++;
    state.active_cid_length_counts[length - 1u]++;
    state.active_cid_length_mask |= 1u << (length - 1u);
    if (state.stats.active_cids > state.stats.peak_active_cids)
        state.stats.peak_active_cids = state.stats.active_cids;
    state.stats.cids_registered++;
    return REGISTERED;
}

enum CidAssociationStatus {
    CID_ASSOCIATION_LIVE,
    CID_ASSOCIATION_EXPIRED,
    CID_ASSOCIATION_INTERNAL_FAILURE,
};

static CidAssociationStatus cid_association_status(
        State &state, uint32_t cid_slot, uint64_t now_ns) {
    if (cid_slot >= state.config.maximum_cids) {
        state.stats.hard_integrity_failures++;
        return CID_ASSOCIATION_INTERNAL_FAILURE;
    }
    CidEntry &association = state.cids[cid_slot];
    if (!cid_flag(association, kCidActive)) {
        state.stats.hard_integrity_failures++;
        return CID_ASSOCIATION_INTERNAL_FAILURE;
    }
    if (association.expiry_ns <= now_ns) {
        const bool removed = remove_cid(state, cid_slot, true);
        refresh_used(state);
        return removed
            ? CID_ASSOCIATION_EXPIRED
            : CID_ASSOCIATION_INTERNAL_FAILURE;
    }
    if (cid_flag(association, kCidAmbiguous))
        return CID_ASSOCIATION_LIVE;
    if (association.connection_slot >=
            state.config.maximum_connections) {
        state.stats.hard_integrity_failures++;
        return CID_ASSOCIATION_INTERNAL_FAILURE;
    }
    ConnectionEntry &connection =
        state.connections[association.connection_slot];
    if (!connection_flag(connection, kConnectionActive)) {
        state.stats.hard_integrity_failures++;
        return CID_ASSOCIATION_INTERNAL_FAILURE;
    }
    if (connection.expiry_ns <= now_ns) {
        const bool released = retire_published_connection(
            state,
            association.connection_slot,
            true,
            false,
            0u,
            now_ns,
            true,
            true);
        refresh_used(state);
        return released
            ? CID_ASSOCIATION_EXPIRED
            : CID_ASSOCIATION_INTERNAL_FAILURE;
    }
    return CID_ASSOCIATION_LIVE;
}

static bool connection_live_by_id(
        State &state,
        uint64_t logical_connection_id,
        uint64_t now_ns,
        uint32_t *slot,
        ConnectionEntry **connection) {
    uint32_t resolved_slot = kNone;
    ConnectionEntry *resolved = connection_by_id(
        state, logical_connection_id, &resolved_slot);
    if (resolved == nullptr)
        return false;
    if (resolved->expiry_ns <= now_ns) {
        const bool retired = retire_published_connection(
            state,
            resolved_slot,
            true,
            false,
            0u,
            now_ns,
            true,
            true);
        refresh_used(state);
        if (!retired)
            return false;
        return false;
    }
    if (slot != nullptr)
        *slot = resolved_slot;
    if (connection != nullptr)
        *connection = resolved;
    return true;
}

static void clear_result(
        const State &state,
        uint16_t ingress_owner,
        fk_quic_cid_resolution *result) {
    if (result == nullptr)
        return;
    *result = {};
    result->ingress_owner = ingress_owner;
    result->reserved_bytes = state.reserved_bytes;
    result->code = FK_QUIC_CID_INVALID;
    result->reason = FK_QUIC_CID_REJECT_INVALID_INPUT;
}

/* Preserve fail-closed output semantics even when no map exists from which to
 * copy reserved_bytes.  Public resolution entry points call this before their
 * null-map check and clear_result() replaces it once state is available. */
static void clear_unbound_result(
        uint16_t ingress_owner,
        fk_quic_cid_resolution *result) {
    if (result == nullptr)
        return;
    *result = {};
    result->ingress_owner = ingress_owner;
    result->code = FK_QUIC_CID_INVALID;
    result->reason = FK_QUIC_CID_REJECT_INVALID_INPUT;
}

static void resolved_result(
        State &state,
        uint32_t slot,
        uint16_t ingress_owner,
        fk_quic_cid_result_code code,
        uint8_t visible_cids,
        bool feature_direction_known,
        uint8_t feature_direction,
        uint8_t resolved_destination_cid_length,
        fk_quic_cid_resolution *result) {
    const ConnectionEntry &entry = state.connections[slot];
    if (!feature_direction_known)
        state.stats.direction_unknown_resolutions++;
    if (result == nullptr)
        return;
    result->logical_connection_id = logical_id(entry, slot);
    result->fixed_owner = entry.owner;
    result->ingress_owner = ingress_owner;
    result->visible_cid_count = visible_cids;
    result->created = code == FK_QUIC_CID_CREATED ? 1u : 0u;
    result->cross_owner = entry.owner != ingress_owner ? 1u : 0u;
    result->pending_handshake = connection_flag(
        entry, kConnectionPendingHandshake) ? 1u : 0u;
    result->feature_direction = feature_direction_known
        ? static_cast<uint8_t>(feature_direction != 0u) : 0u;
    result->feature_direction_known = feature_direction_known ? 1u : 0u;
    result->resolved_destination_cid_length =
        resolved_destination_cid_length;
    result->reserved_bytes = state.reserved_bytes;
    result->code = code;
    result->reason = FK_QUIC_CID_REJECT_NONE;
}

static void rejection(
        fk_quic_cid_result_code code,
        fk_quic_cid_reject_reason reason,
        fk_quic_cid_resolution *result) {
    if (result != nullptr) {
        result->code = code;
        result->reason = reason;
    }
}

/* A failed unpublished rollback is never allowed to masquerade as the
 * original soft admission failure.  The partially allocated connection is
 * then an allocator/accounting integrity failure and must fail closed. */
static bool rollback_created_or_reject_internal(
        State &state,
        bool created,
        uint32_t connection_slot,
        fk_quic_cid_resolution *result) {
    if (!created)
        return true;
    if (rollback_unpublished_connection(state, connection_slot))
        return true;
    refresh_used(state);
    state.stats.unresolved_observations++;
    rejection(
        FK_QUIC_CID_REJECTED,
        FK_QUIC_CID_REJECT_INTERNAL_INTEGRITY,
        result);
    return false;
}

static bool register_authenticated_locked(
        State &state,
        uint64_t logical_connection_id,
        const uint8_t *cid,
        uint8_t cid_length,
        bool destination_direction_known,
        uint8_t destination_direction,
        uint64_t timestamp_ns) {
    if (state.magic != kMagic ||
        advance_time(state, timestamp_ns) != ADVANCE_TIME_OK)
        return false;
    uint32_t slot = kNone;
    ConnectionEntry *connection = nullptr;
    if (!connection_live_by_id(
            state,
            logical_connection_id,
            timestamp_ns,
            &slot,
            &connection))
        return false;
    (void)connection;
    const RegisterResult registered = register_cid(
        state,
        slot,
        cid,
        cid_length,
        destination_direction_known,
        destination_direction,
        timestamp_ns);
    refresh_used(state);
    return registered == REGISTERED || registered == DUPLICATE;
}

static bool checked_counter_add(uint64_t &value, uint64_t increment) {
    if (increment > std::numeric_limits<uint64_t>::max() - value)
        return false;
    value += increment;
    return true;
}

static bool checked_counter_multiply(
        uint64_t left,
        uint64_t right,
        uint64_t &result) {
    if (left != 0u &&
        right > std::numeric_limits<uint64_t>::max() / left)
        return false;
    result = left * right;
    return true;
}

static bool retirement_snapshot(
        const State &state,
        uint32_t slot,
        uint16_t fixed_owner,
        fk_quic_cid_retirement &retirement) {
    retirement = {};
    if (slot >= state.config.maximum_connections ||
        fixed_owner >= state.config.fixed_owner_count)
        return false;
    const ConnectionEntry &entry = state.connections[slot];
    if (!connection_flag(entry, kConnectionRetiredPendingOwnerAck) ||
        entry.owner != fixed_owner || entry.created_ns == 0u)
        return false;
    const uint64_t id = logical_id(entry, slot);
    if (id == 0u)
        return false;
    retirement.logical_connection_id = id;
    retirement.retirement_ordinal = entry.created_ns;
    retirement.packet_sequence = entry.last_seen_ns;
    retirement.retirement_timestamp_ns = entry.expiry_ns;
    retirement.fixed_owner = fixed_owner;
    retirement.packet_sequence_known = connection_flag(
        entry, kConnectionRetirementSequenceKnown) ? 1u : 0u;
    retirement.expired = connection_flag(
        entry, kConnectionRetiredExpired) ? 1u : 0u;
    retirement.binding_expected = connection_flag(
        entry, kConnectionBindingEstablished) ? 1u : 0u;
    retirement.retirement_timestamp_known = connection_flag(
        entry, kConnectionRetirementTimestampKnown) ? 1u : 0u;
    retirement.retirement_timestamp_formal = connection_flag(
        entry, kConnectionRetirementTimestampFormal) ? 1u : 0u;
    return true;
}

static bool retirement_token_shape_valid(
        const State &state,
        const fk_quic_cid_retirement_token &token,
        uint32_t &slot,
        uint32_t &generation) {
    return token.fixed_owner < state.config.fixed_owner_count &&
        token.retirement_ordinal != 0u && token.reserved0 == 0u &&
        token.reserved1 == 0u && fk_quic_logical_id_decode(
            token.logical_connection_id,
            state.config.maximum_connections,
            &slot,
            &generation);
}

static bool retirement_token_matches_entry(
        const ConnectionEntry &entry,
        uint32_t generation,
        const fk_quic_cid_retirement_token &token) {
    return connection_flag(
            entry, kConnectionRetiredPendingOwnerAck) &&
        entry.generation == generation &&
        entry.owner == token.fixed_owner &&
        entry.created_ns == token.retirement_ordinal;
}

static bool accounting_conserved_locked(const State &state) {
    if (state.magic != kMagic || state.config.fixed_owner_count > 64u ||
        state.stats.reserved0 != 0u || state.stats.reserved1 != 0u)
        return false;

    uint32_t scanned_active_by_owner[64]{};
    uint32_t scanned_retired_by_owner[64]{};
    uint32_t scanned_credits_by_owner[64]{};
    uint64_t scanned_active = 0u;
    uint64_t scanned_retired = 0u;
    uint64_t scanned_dispatched = 0u;
    uint64_t scanned_undispatched = 0u;
    uint64_t scanned_free_state = 0u;
    uint64_t scanned_quarantined = 0u;
    uint64_t scanned_pending = 0u;
    uint64_t connection_linked_cids = 0u;
    uint32_t maximum_active_owner = 0u;
    uint32_t maximum_credit_owner = 0u;

    for (uint32_t slot = 0u;
         slot < state.config.maximum_connections; ++slot) {
        const ConnectionEntry &entry = state.connections[slot];
        const bool active = connection_flag(entry, kConnectionActive);
        const bool published = connection_flag(entry, kConnectionPublished);
        const bool retired = connection_flag(
            entry, kConnectionRetiredPendingOwnerAck);
        const bool exhausted = connection_flag(
            entry, kConnectionGenerationExhausted);
        if (active) {
            constexpr uint16_t kActiveFlags =
                kConnectionActive |
                kConnectionPendingHandshake |
                kConnectionGreaseQuicBitNegotiated |
                kConnectionPublished |
                kConnectionBindingEstablished;
            if (!published || retired || exhausted || entry.generation == 0u ||
                entry.owner >= state.config.fixed_owner_count ||
                entry.next_free != kNone ||
                (entry.flags & static_cast<uint16_t>(~kActiveFlags)) != 0u)
                return false;
            scanned_active++;
            scanned_active_by_owner[entry.owner]++;
            scanned_credits_by_owner[entry.owner]++;
            if (connection_flag(entry, kConnectionPendingHandshake))
                scanned_pending++;
            uint32_t cid_cursor = entry.first_cid;
            uint32_t cid_traversed = 0u;
            while (cid_cursor != kNone) {
                if (cid_cursor >= state.config.maximum_cids ||
                    cid_traversed >=
                        state.config.maximum_cids_per_connection)
                    return false;
                const CidEntry &cid = state.cids[cid_cursor];
                if (!cid_flag(cid, kCidActive) ||
                    cid_flag(cid, kCidAmbiguous) ||
                    cid.connection_slot != slot)
                    return false;
                cid_cursor = cid.next_connection;
                cid_traversed++;
            }
            if (cid_traversed != entry.cid_count ||
                !checked_counter_add(
                    connection_linked_cids, cid_traversed))
                return false;
            continue;
        }
        if (retired) {
            constexpr uint16_t kRetiredFlags =
                kConnectionRetiredPendingOwnerAck |
                kConnectionRetirementSequenceKnown |
                kConnectionBindingEstablished |
                kConnectionRetiredExpired |
                kConnectionRetirementTimestampKnown |
                kConnectionRetirementTimestampFormal |
                kConnectionRetirementDispatched;
            const bool timestamp_known = connection_flag(
                entry, kConnectionRetirementTimestampKnown);
            const bool timestamp_formal = connection_flag(
                entry, kConnectionRetirementTimestampFormal);
            const bool expired = connection_flag(
                entry, kConnectionRetiredExpired);
            if (published || exhausted ||
                (entry.flags & static_cast<uint16_t>(~kRetiredFlags)) != 0u ||
                entry.generation == 0u ||
                entry.owner >= state.config.fixed_owner_count ||
                entry.first_cid != kNone || entry.cid_count != 0u ||
                entry.created_ns == 0u ||
                entry.created_ns > state.retirement_ordinal ||
                (timestamp_formal && !timestamp_known) ||
                (expired && (!timestamp_known || !timestamp_formal)) ||
                (!timestamp_known && entry.expiry_ns != 0u))
                return false;
            scanned_retired++;
            if (connection_flag(
                    entry, kConnectionRetirementDispatched))
                scanned_dispatched++;
            else
                scanned_undispatched++;
            scanned_retired_by_owner[entry.owner]++;
            scanned_credits_by_owner[entry.owner]++;
            continue;
        }
        if (exhausted) {
            if (entry.flags != kConnectionGenerationExhausted ||
                entry.generation !=
                    std::numeric_limits<uint32_t>::max() ||
                entry.first_cid != kNone || entry.next_free != kNone ||
                entry.cid_count != 0u)
                return false;
            scanned_quarantined++;
            continue;
        }
        if (entry.flags != 0u || entry.first_cid != kNone ||
            entry.cid_count != 0u || entry.generation ==
                std::numeric_limits<uint32_t>::max())
            return false;
        scanned_free_state++;
    }

    uint64_t owner_active_sum = 0u;
    uint64_t owner_retired_sum = 0u;
    uint64_t owner_credit_sum = 0u;
    uint64_t fifo_retired_sum = 0u;
    uint64_t fifo_undispatched_sum = 0u;
    for (uint16_t owner = 0u;
         owner < state.config.fixed_owner_count; ++owner) {
        const uint32_t active =
            state.active_connections_by_fixed_owner[owner];
        const uint32_t credits =
            state.binding_credits_by_fixed_owner[owner];
        if (credits < active)
            return false;
        const uint32_t retired = credits - active;
        uint64_t owner_partition = active;
        if (!checked_counter_add(owner_partition, retired))
            return false;
        if (active != scanned_active_by_owner[owner] ||
            retired != scanned_retired_by_owner[owner] ||
            credits != scanned_credits_by_owner[owner] ||
            credits != owner_partition ||
            credits > state.config.maximum_connections_per_fixed_owner ||
            !checked_counter_add(owner_active_sum, active) ||
            !checked_counter_add(owner_retired_sum, retired) ||
            !checked_counter_add(owner_credit_sum, credits))
            return false;
        if (active > maximum_active_owner)
            maximum_active_owner = active;
        if (credits > maximum_credit_owner)
            maximum_credit_owner = credits;

        const uint32_t head = state.retired_head_by_fixed_owner[owner];
        const uint32_t tail = state.retired_tail_by_fixed_owner[owner];
        const uint32_t first_undispatched =
            state.first_undispatched_by_fixed_owner[owner];
        if ((head == kNone) != (tail == kNone))
            return false;
        uint32_t cursor = head;
        uint32_t last = kNone;
        uint32_t traversed = 0u;
        uint32_t undispatched_traversed = 0u;
        uint64_t prior_ordinal = 0u;
        bool reached_first_undispatched = false;
        while (cursor != kNone) {
            if (cursor >= state.config.maximum_connections ||
                traversed >= state.config.maximum_connections)
                return false;
            const ConnectionEntry &entry = state.connections[cursor];
            if (!connection_flag(
                    entry, kConnectionRetiredPendingOwnerAck) ||
                entry.owner != owner || entry.created_ns <= prior_ordinal)
                return false;
            const bool dispatched = connection_flag(
                entry, kConnectionRetirementDispatched);
            if (cursor == first_undispatched) {
                if (dispatched || reached_first_undispatched)
                    return false;
                reached_first_undispatched = true;
            }
            if (first_undispatched == kNone) {
                if (!dispatched)
                    return false;
            } else if (reached_first_undispatched) {
                if (dispatched)
                    return false;
                undispatched_traversed++;
            } else if (!dispatched) {
                return false;
            }
            prior_ordinal = entry.created_ns;
            last = cursor;
            cursor = entry.next_free;
            traversed++;
        }
        if ((traversed == 0u && tail != kNone) ||
            (traversed != 0u && last != tail) || traversed != retired ||
            (first_undispatched != kNone &&
             !reached_first_undispatched) ||
            (first_undispatched == kNone &&
             undispatched_traversed != 0u) ||
            !checked_counter_add(
                fifo_undispatched_sum, undispatched_traversed) ||
            !checked_counter_add(fifo_retired_sum, traversed))
            return false;
    }

    uint64_t free_list_count = 0u;
    uint32_t free_cursor = state.connection_free_head;
    while (free_cursor != kNone) {
        if (free_cursor >= state.config.maximum_connections ||
            free_list_count >= state.config.maximum_connections)
            return false;
        const ConnectionEntry &entry = state.connections[free_cursor];
        if (entry.flags != 0u || entry.first_cid != kNone ||
            entry.cid_count != 0u || entry.generation ==
                std::numeric_limits<uint32_t>::max())
            return false;
        free_cursor = entry.next_free;
        free_list_count++;
    }

    uint64_t scanned_active_cids = 0u;
    uint64_t scanned_nonambiguous_cids = 0u;
    uint64_t scanned_inactive_cids = 0u;
    uint32_t length_counts[FK_QUIC_CID_MAX_BYTES]{};
    uint32_t length_mask = 0u;
    for (uint32_t slot = 0u; slot < state.config.maximum_cids; ++slot) {
        const CidEntry &cid = state.cids[slot];
        if (!cid_flag(cid, kCidActive)) {
            if (cid.flags != 0u || cid.connection_slot != kNone ||
                cid.next_bucket != kNone || cid.next_connection != kNone ||
                cid.length != 0u)
                return false;
            scanned_inactive_cids++;
            continue;
        }
        if (cid.length == 0u || cid.length > FK_QUIC_CID_MAX_BYTES)
            return false;
        if (cid.next_free != kNone)
            return false;
        scanned_active_cids++;
        length_counts[cid.length - 1u]++;
        length_mask |= 1u << (cid.length - 1u);
        if (cid_flag(cid, kCidAmbiguous)) {
            if (cid.connection_slot != kNone ||
                cid.next_connection != kNone)
                return false;
            continue;
        }
        if (cid.connection_slot >= state.config.maximum_connections ||
            !connection_flag(
                state.connections[cid.connection_slot], kConnectionActive) ||
            !connection_flag(
                state.connections[cid.connection_slot],
                kConnectionPublished))
            return false;
        scanned_nonambiguous_cids++;
    }
    for (uint32_t index = 0u; index < FK_QUIC_CID_MAX_BYTES; ++index) {
        if (length_counts[index] != state.active_cid_length_counts[index])
            return false;
    }

    uint64_t cid_free_list_count = 0u;
    uint32_t cid_free_cursor = state.cid_free_head;
    while (cid_free_cursor != kNone) {
        if (cid_free_cursor >= state.config.maximum_cids ||
            cid_free_list_count >= state.config.maximum_cids)
            return false;
        const CidEntry &cid = state.cids[cid_free_cursor];
        if (cid.flags != 0u || cid.connection_slot != kNone ||
            cid.next_bucket != kNone || cid.next_connection != kNone ||
            cid.length != 0u)
            return false;
        cid_free_cursor = cid.next_free;
        cid_free_list_count++;
    }

    uint64_t bucket_member_count = 0u;
    for (uint32_t bucket = 0u; bucket < state.cid_bucket_count; ++bucket) {
        uint32_t cid_cursor = state.cid_buckets[bucket];
        uint32_t traversed = 0u;
        while (cid_cursor != kNone) {
            if (cid_cursor >= state.config.maximum_cids ||
                traversed >= state.config.maximum_hash_chain)
                return false;
            const CidEntry &cid = state.cids[cid_cursor];
            if (!cid_flag(cid, kCidActive) || cid.length == 0u ||
                cid.length > FK_QUIC_CID_MAX_BYTES ||
                (static_cast<uint32_t>(
                    cid_hash(state, cid.bytes, cid.length)) &
                    state.cid_bucket_mask) != bucket)
                return false;
            cid_cursor = cid.next_bucket;
            traversed++;
            if (!checked_counter_add(bucket_member_count, 1u))
                return false;
        }
    }

    uint64_t occupied = owner_credit_sum;
    if (!checked_counter_add(occupied, scanned_quarantined) ||
        !checked_counter_add(occupied, free_list_count) ||
        occupied != state.config.maximum_connections)
        return false;
    uint64_t published_partition = state.stats.active_connections;
    if (!checked_counter_add(
            published_partition,
            state.stats.connections_retired_pending_owner_ack) ||
        published_partition != state.stats.connections_created)
        return false;
    uint64_t retired_partition = state.stats.retired_pending_owner_ack;
    if (!checked_counter_add(
            retired_partition, state.stats.retirement_acks) ||
        retired_partition !=
            state.stats.connections_retired_pending_owner_ack)
        return false;
    uint64_t peek_partition = state.stats.retirement_peek_ready;
    uint64_t ack_partition = state.stats.retirement_acks;
    uint64_t mark_partition = state.stats.binding_established_marks;
    uint64_t publication_peek_partition =
        state.stats.retirement_publication_peek_ready;
    uint64_t publication_mark_partition =
        state.stats.retirement_publication_marks;
    uint64_t publication_rollback_partition =
        state.stats.retirement_publication_rollbacks;
    if (!checked_counter_add(
            peek_partition, state.stats.retirement_peek_empty) ||
        !checked_counter_add(
            peek_partition, state.stats.retirement_peek_invalid) ||
        peek_partition != state.stats.retirement_peek_calls ||
        !checked_counter_add(
            ack_partition, state.stats.retirement_ack_empty) ||
        !checked_counter_add(
            ack_partition, state.stats.retirement_ack_mismatches) ||
        !checked_counter_add(
            ack_partition, state.stats.retirement_ack_invalid) ||
        !checked_counter_add(
            ack_partition,
            state.stats.retirement_ack_cleanup_failures) ||
        !checked_counter_add(
            ack_partition,
            state.stats.retirement_ack_not_dispatched) ||
        ack_partition != state.stats.retirement_ack_calls ||
        !checked_counter_add(
            mark_partition,
            state.stats.binding_established_mark_idempotent) ||
        !checked_counter_add(
            mark_partition,
            state.stats.binding_established_mark_rejects) ||
        mark_partition != state.stats.binding_established_mark_calls ||
        !checked_counter_add(
            publication_peek_partition,
            state.stats.retirement_publication_peek_empty) ||
        !checked_counter_add(
            publication_peek_partition,
            state.stats.retirement_publication_peek_invalid) ||
        publication_peek_partition !=
            state.stats.retirement_publication_peek_calls ||
        !checked_counter_add(
            publication_mark_partition,
            state.stats.retirement_publication_mark_empty) ||
        !checked_counter_add(
            publication_mark_partition,
            state.stats.retirement_publication_mark_mismatches) ||
        !checked_counter_add(
            publication_mark_partition,
            state.stats.retirement_publication_mark_invalid) ||
        publication_mark_partition !=
            state.stats.retirement_publication_mark_calls ||
        !checked_counter_add(
            publication_rollback_partition,
            state.stats.retirement_publication_rollback_mismatches) ||
        !checked_counter_add(
            publication_rollback_partition,
            state.stats.retirement_publication_rollback_invalid) ||
        publication_rollback_partition !=
            state.stats.retirement_publication_rollback_calls)
        return false;

    uint64_t retired_plus_rollbacks =
        state.stats.connections_retired_pending_owner_ack;
    uint64_t marks_plus_undispatched =
        state.stats.retirement_publication_marks;
    uint64_t rollbacks_acks_dispatched =
        state.stats.retirement_publication_rollbacks;
    if (!checked_counter_add(
            retired_plus_rollbacks,
            state.stats.retirement_publication_rollbacks) ||
        !checked_counter_add(
            marks_plus_undispatched, scanned_undispatched) ||
        retired_plus_rollbacks != marks_plus_undispatched ||
        !checked_counter_add(
            rollbacks_acks_dispatched,
            state.stats.retirement_acks) ||
        !checked_counter_add(
            rollbacks_acks_dispatched, scanned_dispatched) ||
        rollbacks_acks_dispatched !=
            state.stats.retirement_publication_marks)
        return false;

    uint64_t connection_partition = scanned_active;
    uint64_t dispatch_partition = scanned_dispatched;
    uint64_t cid_partition = scanned_active_cids;
    uint64_t connection_bytes = 0u;
    uint64_t cid_bytes = 0u;
    uint64_t expected_used = static_cast<uint64_t>(state.fixed_used_bytes);
    if (!checked_counter_add(connection_partition, scanned_retired) ||
        !checked_counter_add(dispatch_partition, scanned_undispatched) ||
        !checked_counter_add(cid_partition, cid_free_list_count) ||
        !checked_counter_multiply(
            owner_credit_sum, sizeof(ConnectionEntry), connection_bytes) ||
        !checked_counter_multiply(
            scanned_active_cids, sizeof(CidEntry), cid_bytes) ||
        !checked_counter_add(expected_used, connection_bytes) ||
        !checked_counter_add(expected_used, cid_bytes))
        return false;
    return owner_active_sum == scanned_active &&
        owner_retired_sum == scanned_retired &&
        owner_credit_sum == connection_partition &&
        fifo_retired_sum == scanned_retired &&
        fifo_undispatched_sum == scanned_undispatched &&
        dispatch_partition == scanned_retired &&
        free_list_count == scanned_free_state &&
        free_list_count == state.free_connection_slots &&
        free_list_count == state.stats.free_connection_slots &&
        scanned_quarantined == state.quarantined_connection_slots &&
        scanned_quarantined == state.stats.quarantined_connection_slots &&
        state.stats.generation_exhaustions == scanned_quarantined &&
        scanned_active == state.stats.active_connections &&
        scanned_retired == state.stats.retired_pending_owner_ack &&
        owner_credit_sum == state.stats.binding_credits_in_use &&
        scanned_pending == state.stats.pending_handshakes &&
        scanned_active_cids == state.stats.active_cids &&
        cid_free_list_count == scanned_inactive_cids &&
        cid_partition == state.config.maximum_cids &&
        bucket_member_count == scanned_active_cids &&
        scanned_nonambiguous_cids == connection_linked_cids &&
        length_mask == state.active_cid_length_mask &&
        state.retirement_ordinal ==
            state.stats.connections_retired_pending_owner_ack &&
        state.stats.connections_expired <=
            state.stats.connections_retired_pending_owner_ack &&
        state.stats.peak_active_connections >= scanned_active &&
        state.stats.peak_binding_credits_in_use >= owner_credit_sum &&
        state.stats.peak_retired_pending_owner_ack >= scanned_retired &&
        state.stats.peak_active_connections_per_fixed_owner >=
            maximum_active_owner &&
        state.stats.peak_binding_credits_per_fixed_owner >=
            maximum_credit_owner &&
        expected_used == state.stats.used_bytes &&
        expected_used <= state.stats.reserved_bytes;
}

}  // namespace

extern "C" {

uint64_t fk_quic_cid_map_siphash24(
        const uint8_t key[16],
        const uint8_t *data,
        size_t length) {
    if (key == nullptr || (data == nullptr && length != 0u))
        return 0u;
    return siphash24(key, data, length);
}

bool fk_quic_cid_map_visit_config_hash_v4_fields(
        const fk_quic_cid_map_config *config,
        fk_quic_cid_config_hash_field_callback callback,
        void *callback_user) {
    if (config == nullptr || callback == nullptr)
        return false;
    const uint8_t maximum_hash_chain[4]{
        static_cast<uint8_t>(config->maximum_hash_chain),
        static_cast<uint8_t>(config->maximum_hash_chain >> 8u),
        static_cast<uint8_t>(config->maximum_hash_chain >> 16u),
        static_cast<uint8_t>(config->maximum_hash_chain >> 24u),
    };
    return callback(
            callback_user, 80u, maximum_hash_chain,
            sizeof(maximum_hash_chain)) &&
        callback(
            callback_user, 81u, config->siphash_key,
            sizeof(config->siphash_key)) &&
        callback(
            callback_user, 82u, &config->siphash_key_precommitted,
            sizeof(config->siphash_key_precommitted));
}

void fk_quic_cid_map_q2_config_init(
        fk_quic_cid_map_config *config) {
    if (config == nullptr)
        return;
    *config = {};
    config->maximum_connections = 4096u;
    config->maximum_cids = 16384u;
    config->maximum_cids_per_connection = 8u;
    config->maximum_pending_handshakes = 1024u;
    config->expiration_scan_per_observation = 64u;
    config->connection_ttl_ns = 600ull * 1000u * 1000u * 1000u;
    config->cid_ttl_ns = 300ull * 1000u * 1000u * 1000u;
    config->maximum_hash_chain = 8u;
    /* Public deterministic Validation/test key; it is not a live secret. */
    for (uint8_t index = 0u; index < 16u; ++index)
        config->siphash_key[index] = index;
    config->siphash_key_precommitted = 1u;
    config->fixed_owner_count = 8u;
    config->maximum_connections_per_fixed_owner = 1024u;
}

bool fk_quic_cid_map_config_valid(
        const fk_quic_cid_map_config *config) {
    return config != nullptr &&
        config->maximum_connections != 0u &&
        config->maximum_cids != 0u &&
        config->maximum_cids_per_connection != 0u &&
        config->maximum_cids_per_connection <=
            config->maximum_cids &&
        config->maximum_pending_handshakes != 0u &&
        config->maximum_pending_handshakes <=
            config->maximum_connections &&
        config->expiration_scan_per_observation != 0u &&
        config->connection_ttl_ns != 0u &&
        config->cid_ttl_ns != 0u &&
        config->maximum_pending_initial_bytes == 0u &&
        config->maximum_pending_initial_bytes_per_connection == 0u &&
        config->maximum_hash_chain != 0u &&
        config->maximum_hash_chain <= config->maximum_cids &&
        config->siphash_key_precommitted == 1u &&
        config->reserved[0] == 0u &&
        config->reserved[1] == 0u &&
        config->reserved[2] == 0u &&
        config->fixed_owner_count != 0u &&
        config->fixed_owner_count <= 64u &&
        config->maximum_connections_per_fixed_owner != 0u &&
        static_cast<uint64_t>(config->fixed_owner_count) *
                config->maximum_connections_per_fixed_owner >=
            config->maximum_connections;
}

size_t fk_quic_cid_map_storage_bytes(
        const fk_quic_cid_map_config *config) {
    if (!fk_quic_cid_map_config_valid(config))
        return 0u;
    size_t bytes = 0u;
    uint32_t buckets = 0u;
    return layout(*config, bytes, buckets) ? bytes : 0u;
}

fk_quic_cid_map *fk_quic_cid_map_init(
        void *storage,
        size_t storage_bytes,
        const fk_quic_cid_map_config *config,
        char *error,
        size_t error_capacity) {
    set_error(error, error_capacity, "");
    const size_t required = fk_quic_cid_map_storage_bytes(config);
    if (storage == nullptr || required == 0u ||
        storage_bytes < required) {
        set_error(error, error_capacity, "invalid QUIC CID storage plan");
        return nullptr;
    }
    uint32_t bucket_count = 0u;
    size_t ignored = 0u;
    if (!layout(*config, ignored, bucket_count)) {
        set_error(error, error_capacity, "QUIC CID layout overflow");
        return nullptr;
    }
    uintptr_t cursor = reinterpret_cast<uintptr_t>(storage);
    const uintptr_t end = cursor + storage_bytes;
    if (end < cursor) {
        set_error(error, error_capacity, "QUIC CID storage overflow");
        return nullptr;
    }
    cursor = align_pointer(cursor, alignof(State));
    State *state = take_region<State>(cursor, end, 1u);
    if (state == nullptr) {
        set_error(error, error_capacity, "QUIC CID state does not fit");
        return nullptr;
    }
    state = new (state) State{};
    state->connections = take_region<ConnectionEntry>(
        cursor, end, config->maximum_connections);
    state->cids = take_region<CidEntry>(
        cursor, end, config->maximum_cids);
    state->cid_buckets = take_region<uint32_t>(
        cursor, end, bucket_count);
    state->active_connections_by_fixed_owner = take_region<uint32_t>(
        cursor, end, config->fixed_owner_count);
    state->binding_credits_by_fixed_owner = take_region<uint32_t>(
        cursor, end, config->fixed_owner_count);
    state->first_undispatched_by_fixed_owner = take_region<uint32_t>(
        cursor, end, config->fixed_owner_count);
    state->retired_head_by_fixed_owner = take_region<uint32_t>(
        cursor, end, config->fixed_owner_count);
    state->retired_tail_by_fixed_owner = take_region<uint32_t>(
        cursor, end, config->fixed_owner_count);
    if (state->connections == nullptr || state->cids == nullptr ||
        state->cid_buckets == nullptr ||
        state->active_connections_by_fixed_owner == nullptr ||
        state->binding_credits_by_fixed_owner == nullptr ||
        state->first_undispatched_by_fixed_owner == nullptr ||
        state->retired_head_by_fixed_owner == nullptr ||
        state->retired_tail_by_fixed_owner == nullptr) {
        set_error(error, error_capacity, "QUIC CID regions do not fit");
        return nullptr;
    }
    state->magic = kMagic;
    state->config = *config;
    state->cid_bucket_count = bucket_count;
    state->cid_bucket_mask = bucket_count - 1u;
    state->reserved_bytes = required;
    state->stats.reserved_bytes = required;
    state->connection_free_head = 0u;
    state->cid_free_head = 0u;
    state->free_connection_slots = config->maximum_connections;
    state->stats.free_connection_slots = config->maximum_connections;
    for (uint32_t slot = 0u;
         slot < config->maximum_connections; ++slot) {
        state->connections[slot] = {};
        state->connections[slot].first_cid = kNone;
        state->connections[slot].next_free =
            slot + 1u < config->maximum_connections ? slot + 1u : kNone;
    }
    for (uint32_t slot = 0u; slot < config->maximum_cids; ++slot) {
        state->cids[slot] = {};
        state->cids[slot].connection_slot = kNone;
        state->cids[slot].next_bucket = kNone;
        state->cids[slot].next_connection = kNone;
        state->cids[slot].next_free =
            slot + 1u < config->maximum_cids ? slot + 1u : kNone;
    }
    for (uint32_t bucket = 0u; bucket < bucket_count; ++bucket)
        state->cid_buckets[bucket] = kNone;
    for (uint16_t owner = 0u;
         owner < config->fixed_owner_count; ++owner) {
        state->active_connections_by_fixed_owner[owner] = 0u;
        state->binding_credits_by_fixed_owner[owner] = 0u;
        state->first_undispatched_by_fixed_owner[owner] = kNone;
        state->retired_head_by_fixed_owner[owner] = kNone;
        state->retired_tail_by_fixed_owner[owner] = kNone;
    }
    state->fixed_used_bytes =
        static_cast<size_t>(cursor - reinterpret_cast<uintptr_t>(storage)) -
        static_cast<size_t>(config->maximum_connections) *
            sizeof(ConnectionEntry) -
        static_cast<size_t>(config->maximum_cids) * sizeof(CidEntry);
    refresh_used(*state);
    return reinterpret_cast<fk_quic_cid_map *>(state);
}

void fk_quic_cid_map_destroy(fk_quic_cid_map *map) {
    if (map == nullptr)
        return;
    State *state = implementation(map);
    if (state->magic != kMagic)
        return;
    state->magic = 0u;
    state->~State();
}

bool fk_quic_cid_map_get_topology_receipt(
        const fk_quic_cid_map *map,
        fk_quic_cid_map_topology_receipt *receipt) {
    if (receipt != nullptr)
        *receipt = {};
    if (map == nullptr || receipt == nullptr)
        return false;
    const State &state = *implementation(map);
    if (state.magic != kMagic)
        return false;
    receipt->receipt_abi_version =
        FK_QUIC_CID_MAP_TOPOLOGY_RECEIPT_ABI_VERSION;
    receipt->logical_id_abi_version = FK_QUIC_LOGICAL_ID_ABI_VERSION;
    receipt->logical_id_bits = FK_QUIC_LOGICAL_ID_FULL_WIDTH_BITS;
    receipt->logical_id_full_width = 1u;
    receipt->logical_id_generation_bits =
        FK_QUIC_LOGICAL_ID_GENERATION_BITS;
    receipt->logical_id_encoded_slot_bits =
        FK_QUIC_LOGICAL_ID_ENCODED_SLOT_BITS;
    receipt->retire_ack_required = 1u;
    receipt->fixed_owner_count = state.config.fixed_owner_count;
    receipt->maximum_connection_slots =
        state.config.maximum_connections;
    receipt->topology_config_hash = topology_config_hash(
        receipt->fixed_owner_count,
        receipt->maximum_connection_slots);
    return true;
}

fk_quic_cid_result_code fk_quic_cid_map_lookup(
        fk_quic_cid_map *map,
        const uint8_t *cid,
        uint8_t cid_length,
        uint64_t timestamp_ns,
        uint16_t ingress_owner,
        fk_quic_cid_resolution *result) {
    clear_unbound_result(ingress_owner, result);
    if (map == nullptr)
        return FK_QUIC_CID_INVALID;
    State &state = *implementation(map);
    LockGuard guard(state);
    clear_result(state, ingress_owner, result);
    state.stats.observations++;
    if (state.magic != kMagic || !valid_cid(cid, cid_length)) {
        state.stats.unresolved_observations++;
        return FK_QUIC_CID_INVALID;
    }
    if (ingress_owner >= state.config.fixed_owner_count) {
        state.stats.unresolved_observations++;
        rejection(
            FK_QUIC_CID_REJECTED,
            FK_QUIC_CID_REJECT_INVALID_INPUT,
            result);
        return FK_QUIC_CID_REJECTED;
    }
    const AdvanceTimeResult advance = advance_time(state, timestamp_ns);
    if (advance != ADVANCE_TIME_OK) {
        state.stats.unresolved_observations++;
        rejection(
            FK_QUIC_CID_REJECTED,
            advance == ADVANCE_TIME_REGRESSION
                ? FK_QUIC_CID_REJECT_TIME_REGRESSION
                : FK_QUIC_CID_REJECT_INTERNAL_INTEGRITY,
            result);
        return FK_QUIC_CID_REJECTED;
    }
    const FindResult found = find_cid(state, cid, cid_length);
    if (found.code == FIND_INTERNAL) {
        state.stats.unresolved_observations++;
        rejection(
            FK_QUIC_CID_REJECTED,
            FK_QUIC_CID_REJECT_INTERNAL_INTEGRITY,
            result);
        return FK_QUIC_CID_REJECTED;
    }
    if (found.code == FIND_CHAIN_LIMIT) {
        record_hash_chain_reject(state, false, false);
        state.stats.unresolved_observations++;
        rejection(
            FK_QUIC_CID_REJECTED,
            FK_QUIC_CID_REJECT_HASH_CHAIN_CAPACITY,
            result);
        return FK_QUIC_CID_REJECTED;
    }
    if (found.code == FIND_NOT_FOUND) {
        state.stats.unresolved_observations++;
        rejection(
            FK_QUIC_CID_UNRESOLVED,
            FK_QUIC_CID_REJECT_NONE,
            result);
        return FK_QUIC_CID_UNRESOLVED;
    }
    const CidAssociationStatus association_status =
        cid_association_status(state, found.slot, timestamp_ns);
    if (association_status != CID_ASSOCIATION_LIVE) {
        state.stats.unresolved_observations++;
        rejection(
            association_status == CID_ASSOCIATION_INTERNAL_FAILURE
                ? FK_QUIC_CID_REJECTED
                : FK_QUIC_CID_UNRESOLVED,
            association_status == CID_ASSOCIATION_INTERNAL_FAILURE
                ? FK_QUIC_CID_REJECT_INTERNAL_INTEGRITY
                : FK_QUIC_CID_REJECT_NONE,
            result);
        return association_status == CID_ASSOCIATION_INTERNAL_FAILURE
            ? FK_QUIC_CID_REJECTED
            : FK_QUIC_CID_UNRESOLVED;
    }
    CidEntry &association = state.cids[found.slot];
    association.last_seen_ns = timestamp_ns;
    association.expiry_ns = saturating_add(
        timestamp_ns, state.config.cid_ttl_ns);
    if (cid_flag(association, kCidAmbiguous)) {
        state.stats.ambiguous_cid_hits++;
        state.stats.unresolved_observations++;
        rejection(
            FK_QUIC_CID_AMBIGUOUS,
            FK_QUIC_CID_REJECT_COLLISION,
            result);
        return FK_QUIC_CID_AMBIGUOUS;
    }
    ConnectionEntry &connection =
        state.connections[association.connection_slot];
    if (!connection_flag(connection, kConnectionActive)) {
        state.stats.unresolved_observations++;
        rejection(
            FK_QUIC_CID_REJECTED,
            FK_QUIC_CID_REJECT_INVALID_INPUT,
            result);
        return FK_QUIC_CID_REJECTED;
    }
    connection.last_seen_ns = timestamp_ns;
    connection.expiry_ns = saturating_add(
        timestamp_ns, state.config.connection_ttl_ns);
    state.stats.resolved_observations++;
    const bool direction_known = cid_flag(
        association, kCidDestinationDirectionKnown);
    const uint8_t direction = cid_flag(
        association, kCidDestinationDirection) ? 1u : 0u;
    resolved_result(
        state,
        association.connection_slot,
        ingress_owner,
        FK_QUIC_CID_RESOLVED,
        1u,
        direction_known,
        direction,
        cid_length,
        result);
    return FK_QUIC_CID_RESOLVED;
}

fk_quic_cid_result_code
fk_quic_cid_map_resolve_known_short_header(
        fk_quic_cid_map *map,
        const uint8_t *udp_payload,
        size_t udp_payload_length,
        uint64_t timestamp_ns,
        uint16_t ingress_owner,
        fk_quic_cid_resolution *result) {
    clear_unbound_result(ingress_owner, result);
    if (map == nullptr)
        return FK_QUIC_CID_INVALID;
    State &state = *implementation(map);
    LockGuard guard(state);
    clear_result(state, ingress_owner, result);
    if (state.magic != kMagic || udp_payload == nullptr ||
        udp_payload_length == 0u)
        return FK_QUIC_CID_INVALID;

    if (ingress_owner >= state.config.fixed_owner_count) {
        state.stats.observations++;
        state.stats.short_header_attempts++;
        state.stats.unresolved_observations++;
        state.stats.short_header_unresolved++;
        rejection(
            FK_QUIC_CID_REJECTED,
            FK_QUIC_CID_REJECT_INVALID_INPUT,
            result);
        return FK_QUIC_CID_REJECTED;
    }

    /* Header Form is never greased: a short header must keep it at zero. */
    if ((udp_payload[0] & 0x80u) != 0u) {
        rejection(
            FK_QUIC_CID_NOT_QUIC,
            FK_QUIC_CID_REJECT_NONE,
            result);
        return FK_QUIC_CID_NOT_QUIC;
    }

    const bool fixed_bit_zero = (udp_payload[0] & 0x40u) == 0u;
    state.stats.observations++;
    state.stats.short_header_attempts++;
    if (fixed_bit_zero)
        state.stats.short_header_fixed_zero_candidates++;
    const AdvanceTimeResult advance = advance_time(state, timestamp_ns);
    if (advance != ADVANCE_TIME_OK) {
        state.stats.unresolved_observations++;
        state.stats.short_header_unresolved++;
        rejection(
            FK_QUIC_CID_REJECTED,
            advance == ADVANCE_TIME_REGRESSION
                ? FK_QUIC_CID_REJECT_TIME_REGRESSION
                : FK_QUIC_CID_REJECT_INTERNAL_INTEGRITY,
            result);
        return FK_QUIC_CID_REJECTED;
    }

    const size_t available = udp_payload_length - 1u;
    const uint8_t maximum_length = static_cast<uint8_t>(
        available < FK_QUIC_CID_MAX_BYTES
            ? available : FK_QUIC_CID_MAX_BYTES);
    uint32_t matched_cid_slot = kNone;
    uint32_t matched_connection_slot = kNone;
    uint8_t match_count = 0u;
    uint32_t hash_probes = 0u;
    bool ambiguous_tombstone = false;
    bool cross_connection_prefixes = false;
    bool invalid_association = false;
    bool matched_direction_known = false;
    uint8_t matched_direction = 0u;

    /* Probe only currently active lengths; the hard worst case remains 20. */
    for (uint8_t length = 1u; length <= maximum_length; ++length) {
        if ((state.active_cid_length_mask &
                (1u << (length - 1u))) == 0u)
            continue;
        hash_probes++;
        const FindResult found = find_cid(
            state, udp_payload + 1u, length);
        if (found.code == FIND_INTERNAL) {
            record_short_header_probes(state, hash_probes);
            state.stats.unresolved_observations++;
            state.stats.short_header_unresolved++;
            rejection(
                FK_QUIC_CID_REJECTED,
                FK_QUIC_CID_REJECT_INTERNAL_INTEGRITY,
                result);
            return FK_QUIC_CID_REJECTED;
        }
        if (found.code == FIND_CHAIN_LIMIT) {
            record_short_header_probes(state, hash_probes);
            record_hash_chain_reject(state, false, false);
            state.stats.unresolved_observations++;
            state.stats.short_header_unresolved++;
            rejection(
                FK_QUIC_CID_REJECTED,
                FK_QUIC_CID_REJECT_HASH_CHAIN_CAPACITY,
                result);
            return FK_QUIC_CID_REJECTED;
        }
        if (found.code == FIND_NOT_FOUND)
            continue;
        const CidAssociationStatus association_status =
            cid_association_status(state, found.slot, timestamp_ns);
        if (association_status == CID_ASSOCIATION_EXPIRED)
            continue;
        if (association_status == CID_ASSOCIATION_INTERNAL_FAILURE) {
            record_short_header_probes(state, hash_probes);
            state.stats.unresolved_observations++;
            state.stats.short_header_unresolved++;
            rejection(
                FK_QUIC_CID_REJECTED,
                FK_QUIC_CID_REJECT_INTERNAL_INTEGRITY,
                result);
            return FK_QUIC_CID_REJECTED;
        }
        match_count++;
        const CidEntry &association = state.cids[found.slot];
        if (cid_flag(association, kCidAmbiguous)) {
            ambiguous_tombstone = true;
            continue;
        }
        if (association.connection_slot >=
                state.config.maximum_connections ||
            !connection_flag(
                state.connections[association.connection_slot],
                kConnectionActive)) {
            invalid_association = true;
            continue;
        }
        if (matched_connection_slot == kNone) {
            matched_connection_slot = association.connection_slot;
            matched_cid_slot = found.slot;
            matched_direction_known = cid_flag(
                association, kCidDestinationDirectionKnown);
            matched_direction = cid_flag(
                association, kCidDestinationDirection) ? 1u : 0u;
        } else if (matched_connection_slot !=
                association.connection_slot) {
            cross_connection_prefixes = true;
        }
    }
    record_short_header_probes(state, hash_probes);

    if (match_count == 0u) {
        state.stats.unresolved_observations++;
        state.stats.short_header_unresolved++;
        rejection(
            FK_QUIC_CID_UNRESOLVED,
            FK_QUIC_CID_REJECT_NONE,
            result);
        return FK_QUIC_CID_UNRESOLVED;
    }
    if (ambiguous_tombstone || match_count > 1u) {
        state.stats.unresolved_observations++;
        state.stats.short_header_ambiguous++;
        if (ambiguous_tombstone)
            state.stats.ambiguous_cid_hits++;
        else if (cross_connection_prefixes)
            state.stats.short_header_cross_connection_prefix_ambiguities++;
        else
            state.stats.short_header_same_connection_prefix_ambiguities++;
        rejection(
            FK_QUIC_CID_AMBIGUOUS,
            ambiguous_tombstone
                ? FK_QUIC_CID_REJECT_COLLISION
                : FK_QUIC_CID_REJECT_SHORT_HEADER_PREFIX_AMBIGUITY,
            result);
        return FK_QUIC_CID_AMBIGUOUS;
    }
    if (invalid_association || matched_cid_slot == kNone ||
        matched_connection_slot == kNone) {
        state.stats.unresolved_observations++;
        state.stats.short_header_unresolved++;
        rejection(
            FK_QUIC_CID_REJECTED,
            FK_QUIC_CID_REJECT_INVALID_INPUT,
            result);
        return FK_QUIC_CID_REJECTED;
    }

    CidEntry &association = state.cids[matched_cid_slot];
    ConnectionEntry &connection =
        state.connections[matched_connection_slot];
    if (fixed_bit_zero && !connection_flag(
            connection, kConnectionGreaseQuicBitNegotiated)) {
        state.stats.unresolved_observations++;
        state.stats.short_header_unresolved++;
        state.stats.short_header_fixed_zero_unnegotiated_rejects++;
        rejection(
            FK_QUIC_CID_REJECTED,
            FK_QUIC_CID_REJECT_FIXED_BIT_ZERO_UNNEGOTIATED,
            result);
        return FK_QUIC_CID_REJECTED;
    }
    association.last_seen_ns = timestamp_ns;
    association.expiry_ns = saturating_add(
        timestamp_ns, state.config.cid_ttl_ns);
    connection.last_seen_ns = timestamp_ns;
    connection.expiry_ns = saturating_add(
        timestamp_ns, state.config.connection_ttl_ns);
    state.stats.resolved_observations++;
    state.stats.short_header_resolved++;
    if (fixed_bit_zero)
        state.stats.short_header_fixed_zero_resolved++;
    resolved_result(
        state,
        matched_connection_slot,
        ingress_owner,
        FK_QUIC_CID_RESOLVED,
        1u,
        matched_direction_known,
        matched_direction,
        association.length,
        result);
    return FK_QUIC_CID_RESOLVED;
}

fk_quic_cid_result_code fk_quic_cid_map_observe_long_header(
        fk_quic_cid_map *map,
        const fk_quic_header_observation *observation,
        uint64_t timestamp_ns,
        uint16_t ingress_owner,
        uint16_t proposed_fixed_owner,
        fk_quic_cid_resolution *result) {
    clear_unbound_result(ingress_owner, result);
    if (map == nullptr)
        return FK_QUIC_CID_INVALID;
    State &state = *implementation(map);
    LockGuard guard(state);
    clear_result(state, ingress_owner, result);
    state.stats.observations++;
    if (state.magic != kMagic || observation == nullptr) {
        state.stats.unresolved_observations++;
        return FK_QUIC_CID_INVALID;
    }
    if (ingress_owner >= state.config.fixed_owner_count ||
        proposed_fixed_owner >= state.config.fixed_owner_count) {
        state.stats.unresolved_observations++;
        rejection(
            FK_QUIC_CID_REJECTED,
            FK_QUIC_CID_REJECT_INVALID_INPUT,
            result);
        return FK_QUIC_CID_REJECTED;
    }

    fk_quic_long_packet_type packet_type = FK_QUIC_LONG_PACKET_UNKNOWN;
    const LongHeaderValidation validation =
        validate_long_header_observation(observation, packet_type);
    if (validation == LONG_HEADER_NOT_QUIC) {
        rejection(
            FK_QUIC_CID_NOT_QUIC,
            FK_QUIC_CID_REJECT_NONE,
            result);
        return FK_QUIC_CID_NOT_QUIC;
    }
    if (validation == LONG_HEADER_UNSUPPORTED) {
        state.stats.unresolved_observations++;
        rejection(
            FK_QUIC_CID_UNRESOLVED,
            FK_QUIC_CID_REJECT_UNSUPPORTED_HEADER,
            result);
        return FK_QUIC_CID_UNRESOLVED;
    }
    if (validation != LONG_HEADER_VALID) {
        state.stats.unresolved_observations++;
        rejection(
            FK_QUIC_CID_REJECTED,
            FK_QUIC_CID_REJECT_INVALID_INPUT,
            result);
        return FK_QUIC_CID_REJECTED;
    }
    const AdvanceTimeResult advance = advance_time(state, timestamp_ns);
    if (advance != ADVANCE_TIME_OK) {
        state.stats.unresolved_observations++;
        rejection(
            FK_QUIC_CID_REJECTED,
            advance == ADVANCE_TIME_REGRESSION
                ? FK_QUIC_CID_REJECT_TIME_REGRESSION
                : FK_QUIC_CID_REJECT_INTERNAL_INTEGRITY,
            result);
        return FK_QUIC_CID_REJECTED;
    }

    /* A clear long header may route only through a previously authenticated
     * destination CID.  The visible SCID is never trusted for association or
     * registration, and this path deliberately does not refresh TTLs. */
    if (observation->destination_cid_length == 0u) {
        state.stats.unresolved_observations++;
        rejection(
            packet_type == FK_QUIC_LONG_PACKET_INITIAL
                ? FK_QUIC_CID_REJECTED : FK_QUIC_CID_UNRESOLVED,
            packet_type == FK_QUIC_LONG_PACKET_INITIAL
                ? FK_QUIC_CID_REJECT_INITIAL_AUTH_REQUIRED
                : FK_QUIC_CID_REJECT_NONE,
            result);
        return packet_type == FK_QUIC_LONG_PACKET_INITIAL
            ? FK_QUIC_CID_REJECTED : FK_QUIC_CID_UNRESOLVED;
    }
    const FindResult found = find_cid(
        state,
        observation->destination_cid,
        observation->destination_cid_length);
    if (found.code == FIND_INTERNAL) {
        state.stats.unresolved_observations++;
        rejection(
            FK_QUIC_CID_REJECTED,
            FK_QUIC_CID_REJECT_INTERNAL_INTEGRITY,
            result);
        return FK_QUIC_CID_REJECTED;
    }
    if (found.code == FIND_CHAIN_LIMIT) {
        record_hash_chain_reject(state, false, false);
        state.stats.unresolved_observations++;
        rejection(
            FK_QUIC_CID_REJECTED,
            FK_QUIC_CID_REJECT_HASH_CHAIN_CAPACITY,
            result);
        return FK_QUIC_CID_REJECTED;
    }
    if (found.code == FIND_NOT_FOUND) {
        state.stats.unresolved_observations++;
        rejection(
            packet_type == FK_QUIC_LONG_PACKET_INITIAL
                ? FK_QUIC_CID_REJECTED : FK_QUIC_CID_UNRESOLVED,
            packet_type == FK_QUIC_LONG_PACKET_INITIAL
                ? FK_QUIC_CID_REJECT_INITIAL_AUTH_REQUIRED
                : FK_QUIC_CID_REJECT_NONE,
            result);
        return packet_type == FK_QUIC_LONG_PACKET_INITIAL
            ? FK_QUIC_CID_REJECTED : FK_QUIC_CID_UNRESOLVED;
    }
    const CidAssociationStatus association_status =
        cid_association_status(state, found.slot, timestamp_ns);
    if (association_status != CID_ASSOCIATION_LIVE) {
        state.stats.unresolved_observations++;
        rejection(
            association_status == CID_ASSOCIATION_INTERNAL_FAILURE
                ? FK_QUIC_CID_REJECTED : FK_QUIC_CID_UNRESOLVED,
            association_status == CID_ASSOCIATION_INTERNAL_FAILURE
                ? FK_QUIC_CID_REJECT_INTERNAL_INTEGRITY
                : FK_QUIC_CID_REJECT_NONE,
            result);
        return association_status == CID_ASSOCIATION_INTERNAL_FAILURE
            ? FK_QUIC_CID_REJECTED : FK_QUIC_CID_UNRESOLVED;
    }
    const CidEntry &association = state.cids[found.slot];
    if (cid_flag(association, kCidAmbiguous)) {
        state.stats.ambiguous_cid_hits++;
        state.stats.unresolved_observations++;
        rejection(
            FK_QUIC_CID_AMBIGUOUS,
            FK_QUIC_CID_REJECT_COLLISION,
            result);
        return FK_QUIC_CID_AMBIGUOUS;
    }
    if (association.connection_slot >=
            state.config.maximum_connections) {
        state.stats.hard_integrity_failures++;
        state.stats.unresolved_observations++;
        rejection(
            FK_QUIC_CID_REJECTED,
            FK_QUIC_CID_REJECT_INTERNAL_INTEGRITY,
            result);
        return FK_QUIC_CID_REJECTED;
    }
    const ConnectionEntry &connection =
        state.connections[association.connection_slot];
    if (!connection_flag(connection, kConnectionActive) ||
        !connection_flag(connection, kConnectionPublished)) {
        state.stats.hard_integrity_failures++;
        state.stats.unresolved_observations++;
        rejection(
            FK_QUIC_CID_REJECTED,
            FK_QUIC_CID_REJECT_INTERNAL_INTEGRITY,
            result);
        return FK_QUIC_CID_REJECTED;
    }
    state.stats.resolved_observations++;
    const bool direction_known = cid_flag(
        association, kCidDestinationDirectionKnown);
    const uint8_t direction = cid_flag(
        association, kCidDestinationDirection) ? 1u : 0u;
    resolved_result(
        state,
        association.connection_slot,
        ingress_owner,
        FK_QUIC_CID_RESOLVED,
        1u,
        direction_known,
        direction,
        observation->destination_cid_length,
        result);
    return FK_QUIC_CID_RESOLVED;
}

fk_quic_cid_result_code fk_quic_cid_map_observe_authenticated_initial(
        fk_quic_cid_map *map,
        const fk_quic_header_observation *observation,
        const fk_quic_cid_initial_admission_proof *proof,
        uint64_t timestamp_ns,
        uint16_t ingress_owner,
        uint16_t proposed_fixed_owner,
        fk_quic_cid_resolution *result) {
    clear_unbound_result(ingress_owner, result);
    if (map == nullptr)
        return FK_QUIC_CID_INVALID;
    State &state = *implementation(map);
    LockGuard guard(state);
    clear_result(state, ingress_owner, result);
    state.stats.observations++;
    if (state.magic != kMagic || observation == nullptr) {
        state.stats.unresolved_observations++;
        return FK_QUIC_CID_INVALID;
    }
    if (ingress_owner >= state.config.fixed_owner_count ||
        proposed_fixed_owner >= state.config.fixed_owner_count) {
        state.stats.unresolved_observations++;
        rejection(
            FK_QUIC_CID_REJECTED,
            FK_QUIC_CID_REJECT_INVALID_INPUT,
            result);
        return FK_QUIC_CID_REJECTED;
    }
    fk_quic_long_packet_type packet_type = FK_QUIC_LONG_PACKET_UNKNOWN;
    const LongHeaderValidation validation =
        validate_long_header_observation(observation, packet_type);
    if (validation == LONG_HEADER_NOT_QUIC) {
        rejection(
            FK_QUIC_CID_NOT_QUIC,
            FK_QUIC_CID_REJECT_NONE,
            result);
        return FK_QUIC_CID_NOT_QUIC;
    }
    if (validation == LONG_HEADER_UNSUPPORTED) {
        state.stats.unresolved_observations++;
        rejection(
            FK_QUIC_CID_UNRESOLVED,
            FK_QUIC_CID_REJECT_UNSUPPORTED_HEADER,
            result);
        return FK_QUIC_CID_UNRESOLVED;
    }
    if (validation != LONG_HEADER_VALID) {
        state.stats.unresolved_observations++;
        rejection(
            FK_QUIC_CID_REJECTED,
            FK_QUIC_CID_REJECT_INVALID_INPUT,
            result);
        return FK_QUIC_CID_REJECTED;
    }
    const fk_quic_cid_reject_reason proof_rejection =
        validate_initial_admission_proof(
            *observation, packet_type, proof);
    if (proof_rejection != FK_QUIC_CID_REJECT_NONE) {
        state.stats.unresolved_observations++;
        rejection(
            FK_QUIC_CID_REJECTED,
            proof_rejection,
            result);
        return FK_QUIC_CID_REJECTED;
    }
    const AdvanceTimeResult advance = advance_time(state, timestamp_ns);
    if (advance != ADVANCE_TIME_OK) {
        state.stats.unresolved_observations++;
        rejection(
            FK_QUIC_CID_REJECTED,
            advance == ADVANCE_TIME_REGRESSION
                ? FK_QUIC_CID_REJECT_TIME_REGRESSION
                : FK_QUIC_CID_REJECT_INTERNAL_INTEGRITY,
            result);
        return FK_QUIC_CID_REJECTED;
    }
    const uint8_t *visible[2]{
        observation->destination_cid,
        observation->source_cid,
    };
    const uint8_t lengths[2]{
        observation->destination_cid_length,
        observation->source_cid_length,
    };
    if (lengths[0] != 0u && lengths[0] == lengths[1] &&
        std::memcmp(visible[0], visible[1], lengths[0]) == 0) {
        state.stats.same_cid_dual_role_rejects++;
        state.stats.direction_conflicts++;
        state.stats.unresolved_observations++;
        rejection(
            FK_QUIC_CID_AMBIGUOUS,
            FK_QUIC_CID_REJECT_DIRECTION_CONFLICT,
            result);
        return FK_QUIC_CID_AMBIGUOUS;
    }
    uint8_t visible_count = 0u;
    uint8_t unknown_count = 0u;
    uint32_t connection_slot = kNone;
    bool feature_direction_known = false;
    uint8_t feature_direction = 0u;
    for (uint32_t index = 0u; index < 2u; ++index) {
        if (lengths[index] == 0u)
            continue;
        visible_count++;
        const FindResult found =
            find_cid(state, visible[index], lengths[index]);
        if (found.code == FIND_INTERNAL) {
            state.stats.unresolved_observations++;
            rejection(
                FK_QUIC_CID_REJECTED,
                FK_QUIC_CID_REJECT_INTERNAL_INTEGRITY,
                result);
            return FK_QUIC_CID_REJECTED;
        }
        if (found.code == FIND_CHAIN_LIMIT) {
            record_hash_chain_reject(state, false, false);
            state.stats.unresolved_observations++;
            rejection(
                FK_QUIC_CID_REJECTED,
                FK_QUIC_CID_REJECT_HASH_CHAIN_CAPACITY,
                result);
            return FK_QUIC_CID_REJECTED;
        }
        if (found.code == FIND_NOT_FOUND) {
            unknown_count++;
            continue;
        }
        const CidAssociationStatus association_status =
            cid_association_status(state, found.slot, timestamp_ns);
        if (association_status == CID_ASSOCIATION_EXPIRED) {
            unknown_count++;
            continue;
        }
        if (association_status == CID_ASSOCIATION_INTERNAL_FAILURE) {
            state.stats.unresolved_observations++;
            rejection(
                FK_QUIC_CID_REJECTED,
                FK_QUIC_CID_REJECT_INTERNAL_INTEGRITY,
                result);
            return FK_QUIC_CID_REJECTED;
        }
        const CidEntry &entry = state.cids[found.slot];
        if (cid_flag(entry, kCidAmbiguous)) {
            state.stats.ambiguous_cid_hits++;
            state.stats.unresolved_observations++;
            rejection(
                FK_QUIC_CID_AMBIGUOUS,
                FK_QUIC_CID_REJECT_COLLISION,
                result);
            return FK_QUIC_CID_AMBIGUOUS;
        }
        if (connection_slot != kNone &&
            connection_slot != entry.connection_slot) {
            state.stats.cid_collisions++;
            state.stats.unresolved_observations++;
            rejection(
                FK_QUIC_CID_AMBIGUOUS,
                FK_QUIC_CID_REJECT_COLLISION,
                result);
            return FK_QUIC_CID_AMBIGUOUS;
        }
        connection_slot = entry.connection_slot;
        if (cid_flag(entry, kCidDestinationDirectionKnown)) {
            const uint8_t derived_direction = static_cast<uint8_t>(
                (cid_flag(entry, kCidDestinationDirection) ? 1u : 0u) ^
                (index == 1u ? 1u : 0u));
            if (feature_direction_known &&
                feature_direction != derived_direction) {
                state.stats.direction_conflicts++;
                state.stats.unresolved_observations++;
                rejection(
                    FK_QUIC_CID_AMBIGUOUS,
                    FK_QUIC_CID_REJECT_DIRECTION_CONFLICT,
                    result);
                return FK_QUIC_CID_AMBIGUOUS;
            }
            feature_direction_known = true;
            feature_direction = derived_direction;
        }
    }
    if (visible_count == 0u) {
        state.stats.unresolved_observations++;
        rejection(
            FK_QUIC_CID_UNRESOLVED,
            FK_QUIC_CID_REJECT_UNSUPPORTED_HEADER,
            result);
        return FK_QUIC_CID_UNRESOLVED;
    }
    const uint32_t existing_cids = connection_slot == kNone
        ? 0u : state.connections[connection_slot].cid_count;
    if (static_cast<uint32_t>(unknown_count) >
            state.config.maximum_cids - state.stats.active_cids) {
        state.stats.cid_capacity_rejects++;
        state.stats.unresolved_observations++;
        rejection(
            FK_QUIC_CID_REJECTED,
            FK_QUIC_CID_REJECT_CID_CAPACITY,
            result);
        return FK_QUIC_CID_REJECTED;
    }
    if (static_cast<uint32_t>(unknown_count) >
            state.config.maximum_cids_per_connection - existing_cids) {
        state.stats.per_connection_cid_capacity_rejects++;
        state.stats.unresolved_observations++;
        rejection(
            FK_QUIC_CID_REJECTED,
            FK_QUIC_CID_REJECT_PER_CONNECTION_CID_CAPACITY,
            result);
        return FK_QUIC_CID_REJECTED;
    }
    bool created = false;
    if (connection_slot == kNone) {
        if (state.binding_credits_by_fixed_owner[
                proposed_fixed_owner] >=
                state.config.maximum_connections_per_fixed_owner) {
            state.stats.fixed_owner_capacity_rejects++;
            state.stats.unresolved_observations++;
            rejection(
                FK_QUIC_CID_REJECTED,
                FK_QUIC_CID_REJECT_FIXED_OWNER_CAPACITY,
                result);
            return FK_QUIC_CID_REJECTED;
        }
        if (state.free_connection_slots == 0u) {
            state.stats.connection_capacity_rejects++;
            state.stats.unresolved_observations++;
            rejection(
                FK_QUIC_CID_REJECTED,
                FK_QUIC_CID_REJECT_CONNECTION_CAPACITY,
                result);
            return FK_QUIC_CID_REJECTED;
        }
        if (state.stats.pending_handshakes >=
                state.config.maximum_pending_handshakes) {
            state.stats.pending_handshake_capacity_rejects++;
            state.stats.unresolved_observations++;
            rejection(
                FK_QUIC_CID_REJECTED,
                FK_QUIC_CID_REJECT_PENDING_HANDSHAKE_CAPACITY,
                result);
            return FK_QUIC_CID_REJECTED;
        }
        connection_slot = allocate_connection(
            state, timestamp_ns, proposed_fixed_owner);
        if (connection_slot == kNone) {
            record_allocator_integrity_failure(state);
            state.stats.unresolved_observations++;
            rejection(
                FK_QUIC_CID_REJECTED,
                FK_QUIC_CID_REJECT_INTERNAL_INTEGRITY,
                result);
            return FK_QUIC_CID_REJECTED;
        }
        created = true;
        /* The first accepted long-header packet defines logical direction 0. */
        feature_direction_known = true;
        feature_direction = 0u;
    }
    for (uint32_t index = 0u; index < 2u; ++index) {
        if (lengths[index] == 0u)
            continue;
        const RegisterResult registered = register_cid(
            state,
            connection_slot,
            visible[index],
            lengths[index],
            feature_direction_known,
            static_cast<uint8_t>(
                feature_direction ^ (index == 1u ? 1u : 0u)),
            timestamp_ns);
        if (registered == COLLISION) {
            if (!rollback_created_or_reject_internal(
                    state, created, connection_slot, result))
                return FK_QUIC_CID_REJECTED;
            refresh_used(state);
            state.stats.unresolved_observations++;
            rejection(
                FK_QUIC_CID_AMBIGUOUS,
                FK_QUIC_CID_REJECT_COLLISION,
                result);
            return FK_QUIC_CID_AMBIGUOUS;
        }
        if (registered == DIRECTION_CONFLICT) {
            if (!rollback_created_or_reject_internal(
                    state, created, connection_slot, result))
                return FK_QUIC_CID_REJECTED;
            refresh_used(state);
            state.stats.unresolved_observations++;
            rejection(
                FK_QUIC_CID_AMBIGUOUS,
                FK_QUIC_CID_REJECT_DIRECTION_CONFLICT,
                result);
            return FK_QUIC_CID_AMBIGUOUS;
        }
        if (registered == HASH_CHAIN_FULL) {
            if (!rollback_created_or_reject_internal(
                    state, created, connection_slot, result))
                return FK_QUIC_CID_REJECTED;
            refresh_used(state);
            state.stats.unresolved_observations++;
            rejection(
                FK_QUIC_CID_REJECTED,
                FK_QUIC_CID_REJECT_HASH_CHAIN_CAPACITY,
                result);
            return FK_QUIC_CID_REJECTED;
        }
        if (registered == EXPIRED_ASSOCIATION) {
            if (!rollback_created_or_reject_internal(
                    state, created, connection_slot, result))
                return FK_QUIC_CID_REJECTED;
            refresh_used(state);
            state.stats.unresolved_observations++;
            rejection(
                FK_QUIC_CID_UNRESOLVED,
                FK_QUIC_CID_REJECT_NONE,
                result);
            return FK_QUIC_CID_UNRESOLVED;
        }
        if (registered == INTERNAL_FAILURE) {
            if (!rollback_created_or_reject_internal(
                    state, created, connection_slot, result))
                return FK_QUIC_CID_REJECTED;
            refresh_used(state);
            state.stats.unresolved_observations++;
            rejection(
                FK_QUIC_CID_REJECTED,
                FK_QUIC_CID_REJECT_INTERNAL_INTEGRITY,
                result);
            return FK_QUIC_CID_REJECTED;
        }
        if (registered == GLOBAL_FULL ||
            registered == PER_CONNECTION_FULL) {
            if (!rollback_created_or_reject_internal(
                    state, created, connection_slot, result))
                return FK_QUIC_CID_REJECTED;
            refresh_used(state);
            state.stats.unresolved_observations++;
            rejection(
                FK_QUIC_CID_REJECTED,
                registered == GLOBAL_FULL
                    ? FK_QUIC_CID_REJECT_CID_CAPACITY
                    : FK_QUIC_CID_REJECT_PER_CONNECTION_CID_CAPACITY,
                result);
            return FK_QUIC_CID_REJECTED;
        }
    }
    ConnectionEntry &connection = state.connections[connection_slot];
    connection.last_seen_ns = timestamp_ns;
    connection.expiry_ns = saturating_add(
        timestamp_ns, state.config.connection_ttl_ns);
    if (created && !publish_connection(state, connection_slot)) {
        const bool rolled_back = rollback_unpublished_connection(
            state, connection_slot);
        refresh_used(state);
        state.stats.unresolved_observations++;
        rejection(
            FK_QUIC_CID_REJECTED,
            FK_QUIC_CID_REJECT_INTERNAL_INTEGRITY,
            result);
        if (!rolled_back)
            record_allocator_integrity_failure(state);
        return FK_QUIC_CID_REJECTED;
    }
    refresh_used(state);
    state.stats.resolved_observations++;
    resolved_result(
        state,
        connection_slot,
        ingress_owner,
        created ? FK_QUIC_CID_CREATED : FK_QUIC_CID_RESOLVED,
        visible_count,
        feature_direction_known,
        feature_direction,
        observation->destination_cid_length,
        result);
    return created ? FK_QUIC_CID_CREATED : FK_QUIC_CID_RESOLVED;
}

bool fk_quic_cid_map_register_authenticated_cid(
        fk_quic_cid_map *map,
        uint64_t logical_connection_id,
        const uint8_t *cid,
        uint8_t cid_length,
        uint64_t timestamp_ns) {
    if (map == nullptr || !valid_cid(cid, cid_length))
        return false;
    State &state = *implementation(map);
    LockGuard guard(state);
    return register_authenticated_locked(
        state,
        logical_connection_id,
        cid,
        cid_length,
        false,
        0u,
        timestamp_ns);
}

bool fk_quic_cid_map_register_authenticated_cid_with_direction(
        fk_quic_cid_map *map,
        uint64_t logical_connection_id,
        const uint8_t *cid,
        uint8_t cid_length,
        uint8_t destination_feature_direction,
        uint64_t timestamp_ns) {
    if (map == nullptr || !valid_cid(cid, cid_length) ||
        destination_feature_direction > 1u)
        return false;
    State &state = *implementation(map);
    LockGuard guard(state);
    return register_authenticated_locked(
        state,
        logical_connection_id,
        cid,
        cid_length,
        true,
        destination_feature_direction,
        timestamp_ns);
}

bool fk_quic_cid_map_mark_grease_quic_bit_negotiated(
        fk_quic_cid_map *map,
        uint64_t logical_connection_id,
        uint64_t timestamp_ns) {
    if (map == nullptr)
        return false;
    State &state = *implementation(map);
    LockGuard guard(state);
    if (state.magic != kMagic ||
        advance_time(state, timestamp_ns) != ADVANCE_TIME_OK)
        return false;
    ConnectionEntry *connection = nullptr;
    if (!connection_live_by_id(
            state,
            logical_connection_id,
            timestamp_ns,
            nullptr,
            &connection))
        return false;
    set_connection_flag(
        *connection, kConnectionGreaseQuicBitNegotiated, true);
    return true;
}

bool fk_quic_cid_map_mark_handshake_complete(
        fk_quic_cid_map *map,
        uint64_t logical_connection_id,
        uint64_t timestamp_ns) {
    if (map == nullptr)
        return false;
    State &state = *implementation(map);
    LockGuard guard(state);
    if (state.magic != kMagic ||
        advance_time(state, timestamp_ns) != ADVANCE_TIME_OK)
        return false;
    ConnectionEntry *connection = nullptr;
    if (!connection_live_by_id(
            state,
            logical_connection_id,
            timestamp_ns,
            nullptr,
            &connection))
        return false;
    connection->last_seen_ns = timestamp_ns;
    connection->expiry_ns = saturating_add(
        timestamp_ns, state.config.connection_ttl_ns);
    if (connection_flag(*connection, kConnectionPendingHandshake)) {
        set_connection_flag(
            *connection, kConnectionPendingHandshake, false);
        state.stats.pending_handshakes--;
    }
    return true;
}

bool fk_quic_cid_map_release(
        fk_quic_cid_map *map,
        uint64_t logical_connection_id) {
    if (map == nullptr)
        return false;
    State &state = *implementation(map);
    LockGuard guard(state);
    if (state.magic != kMagic)
        return false;
    uint32_t slot = kNone;
    if (connection_by_id(state, logical_connection_id, &slot) == nullptr)
        return false;
    const bool timestamp_known = state.time_initialized != 0u;
    const bool released = retire_published_connection(
        state,
        slot,
        false,
        false,
        0u,
        timestamp_known ? state.last_timestamp_ns : 0u,
        timestamp_known,
        false);
    refresh_used(state);
    return released;
}

bool fk_quic_cid_map_release_ordered(
        fk_quic_cid_map *map,
        uint64_t logical_connection_id,
        uint64_t packet_sequence,
        uint64_t semantic_timestamp_ns) {
    if (map == nullptr)
        return false;
    State &state = *implementation(map);
    LockGuard guard(state);
    if (state.magic != kMagic)
        return false;
    uint32_t slot = kNone;
    ConnectionEntry *connection = connection_by_id(
        state, logical_connection_id, &slot);
    if (connection == nullptr || state.time_initialized == 0u ||
        semantic_timestamp_ns < connection->created_ns ||
        semantic_timestamp_ns < connection->last_seen_ns ||
        semantic_timestamp_ns > state.last_timestamp_ns)
        return false;
    const bool released = retire_published_connection(
        state,
        slot,
        false,
        true,
        packet_sequence,
        semantic_timestamp_ns,
        true,
        true);
    refresh_used(state);
    return released;
}

bool fk_quic_cid_map_drain_finite_epoch(
        fk_quic_cid_map *map,
        uint64_t terminal_semantic_timestamp_ns,
        fk_quic_cid_finite_epoch_drain_receipt_v1 *receipt) {
    if (receipt != nullptr)
        *receipt = {};
    if (map == nullptr || receipt == nullptr ||
        terminal_semantic_timestamp_ns == 0u) {
        return false;
    }
    State &state = *implementation(map);
    LockGuard guard(state);
    receipt->abi_version =
        FK_QUIC_CID_FINITE_EPOCH_DRAIN_RECEIPT_ABI_VERSION;
    receipt->terminal_semantic_timestamp_ns =
        terminal_semantic_timestamp_ns;
    if (state.magic != kMagic ||
        (state.time_initialized != 0u &&
         terminal_semantic_timestamp_ns < state.last_timestamp_ns)) {
        return false;
    }

    receipt->active_connections_before = state.stats.active_connections;
    /* Preflight the whole live set before advancing time.  In particular, a
     * caller that has not reached the frozen idle boundary cannot partially
     * retire a directory and then claim a failed drain. */
    for (uint32_t slot = 0u;
         slot < state.config.maximum_connections; ++slot) {
        const ConnectionEntry &entry = state.connections[slot];
        if (!connection_flag(entry, kConnectionActive))
            continue;
        if (!connection_flag(entry, kConnectionPublished) ||
            entry.owner >= state.config.fixed_owner_count ||
            entry.expiry_ns > terminal_semantic_timestamp_ns) {
            return false;
        }
    }

    const uint64_t expired_before = state.stats.connections_expired;
    if (advance_time(state, terminal_semantic_timestamp_ns) !=
            ADVANCE_TIME_OK) {
        return false;
    }
    for (uint32_t slot = 0u;
         slot < state.config.maximum_connections; ++slot) {
        if (!connection_flag(
                state.connections[slot], kConnectionActive)) {
            continue;
        }
        if (!retire_published_connection(
                state,
                slot,
                true,
                false,
                0u,
                terminal_semantic_timestamp_ns,
                true,
                true)) {
            refresh_used(state);
            return false;
        }
    }
    refresh_used(state);
    receipt->active_connections_after = state.stats.active_connections;
    const uint64_t expired_after = state.stats.connections_expired;
    if (expired_after < expired_before ||
        expired_after - expired_before > UINT32_MAX) {
        return false;
    }
    receipt->connections_drained =
        static_cast<uint32_t>(expired_after - expired_before);
    receipt->complete =
        receipt->active_connections_after == 0u &&
                receipt->connections_drained ==
                    receipt->active_connections_before
            ? 1u : 0u;
    if (receipt->complete != 0u) {
        receipt->reason =
            FK_QUIC_CID_FINITE_EPOCH_DRAIN_IDLE_TIMEOUT_AFTER_EOF;
    }
    return receipt->complete != 0u;
}

bool fk_quic_cid_map_mark_binding_established(
        fk_quic_cid_map *map,
        uint64_t logical_connection_id,
        uint16_t fixed_owner) {
    if (map == nullptr)
        return false;
    State &state = *implementation(map);
    LockGuard guard(state);
    if (state.magic != kMagic)
        return false;
    state.stats.binding_established_mark_calls++;
    uint32_t slot = kNone;
    uint32_t generation = 0u;
    if (fixed_owner >= state.config.fixed_owner_count ||
        !fk_quic_logical_id_decode(
            logical_connection_id,
            state.config.maximum_connections,
            &slot,
            &generation)) {
        state.stats.binding_established_mark_rejects++;
        return false;
    }
    ConnectionEntry &entry = state.connections[slot];
    const bool published_active =
        connection_flag(entry, kConnectionActive) &&
        connection_flag(entry, kConnectionPublished);
    const bool retired = connection_flag(
        entry, kConnectionRetiredPendingOwnerAck);
    if ((!published_active && !retired) || entry.generation != generation ||
        entry.owner != fixed_owner) {
        state.stats.binding_established_mark_rejects++;
        return false;
    }
    if (connection_flag(entry, kConnectionBindingEstablished)) {
        state.stats.binding_established_mark_idempotent++;
        return true;
    }
    set_connection_flag(entry, kConnectionBindingEstablished, true);
    state.stats.binding_established_marks++;
    return true;
}

fk_quic_cid_route_prevalidation_result
fk_quic_cid_map_prevalidate_logical_route_v2(
        const fk_quic_cid_map *map,
        uint64_t logical_connection_id,
        uint16_t expected_fixed_owner,
        fk_quic_cid_route_guard_v2 *route_guard) {
    if (route_guard != nullptr)
        *route_guard = {};
    if (map == nullptr || route_guard == nullptr)
        return FK_QUIC_CID_ROUTE_PREVALIDATION_INVALID;
    State &state = *const_cast<State *>(implementation(map));
    LockGuard guard(state);
    if (state.magic != kMagic)
        return FK_QUIC_CID_ROUTE_PREVALIDATION_INVALID;
    state.stats.route_prevalidation_calls++;
    uint32_t slot = kNone;
    uint32_t generation = 0u;
    if (expected_fixed_owner >= state.config.fixed_owner_count ||
        !fk_quic_logical_id_decode(
            logical_connection_id,
            state.config.maximum_connections,
            &slot,
            &generation)) {
        state.stats.route_prevalidation_invalid++;
        return FK_QUIC_CID_ROUTE_PREVALIDATION_INVALID;
    }
    const ConnectionEntry &entry = state.connections[slot];
    if (entry.generation != generation) {
        state.stats.route_prevalidation_stale_generations++;
        return FK_QUIC_CID_ROUTE_PREVALIDATION_STALE_GENERATION;
    }
    const bool active =
        connection_flag(entry, kConnectionActive) &&
        connection_flag(entry, kConnectionPublished);
    const bool retired = connection_flag(
        entry, kConnectionRetiredPendingOwnerAck);
    const bool partial_active =
        connection_flag(entry, kConnectionActive) !=
        connection_flag(entry, kConnectionPublished);
    if ((active && retired) || partial_active ||
        ((active || retired) &&
         entry.owner >= state.config.fixed_owner_count)) {
        state.stats.route_prevalidation_internal_integrity++;
        state.stats.hard_integrity_failures++;
        return FK_QUIC_CID_ROUTE_PREVALIDATION_INTERNAL_INTEGRITY;
    }
    if (!active && !retired) {
        state.stats.route_prevalidation_not_found++;
        return FK_QUIC_CID_ROUTE_PREVALIDATION_NOT_FOUND;
    }
    route_guard->logical_connection_id = logical_connection_id;
    route_guard->immutable_fixed_owner = entry.owner;
    route_guard->lifecycle = active
        ? FK_QUIC_CID_ROUTE_GUARD_ACTIVE
        : FK_QUIC_CID_ROUTE_GUARD_RETIRED_PENDING_OWNER_ACK;
    if (retired) {
        route_guard->packet_sequence_known = connection_flag(
            entry, kConnectionRetirementSequenceKnown) ? 1u : 0u;
        route_guard->retirement_packet_sequence =
            route_guard->packet_sequence_known != 0u
                ? entry.last_seen_ns : 0u;
        route_guard->retirement_timestamp_known = connection_flag(
            entry, kConnectionRetirementTimestampKnown) ? 1u : 0u;
        route_guard->retirement_timestamp_formal = connection_flag(
            entry, kConnectionRetirementTimestampFormal) ? 1u : 0u;
        route_guard->retirement_timestamp_ns =
            route_guard->retirement_timestamp_known != 0u
                ? entry.expiry_ns : 0u;
    }
    if (entry.owner != expected_fixed_owner) {
        state.stats.route_prevalidation_owner_mismatches++;
        return FK_QUIC_CID_ROUTE_PREVALIDATION_OWNER_MISMATCH;
    }
    if (retired) {
        state.stats.route_prevalidation_retired_pending_owner_ack++;
        return
            FK_QUIC_CID_ROUTE_PREVALIDATION_RETIRED_PENDING_OWNER_ACK;
    }
    state.stats.route_prevalidation_active++;
    return FK_QUIC_CID_ROUTE_PREVALIDATION_ACTIVE;
}

fk_quic_cid_route_prevalidation_result
fk_quic_cid_map_prevalidate_logical_route(
        const fk_quic_cid_map *map,
        uint64_t logical_connection_id,
        uint16_t expected_fixed_owner,
        uint16_t *immutable_fixed_owner) {
    if (immutable_fixed_owner != nullptr)
        *immutable_fixed_owner = UINT16_MAX;
    if (immutable_fixed_owner == nullptr)
        return FK_QUIC_CID_ROUTE_PREVALIDATION_INVALID;
    fk_quic_cid_route_guard_v2 guard{};
    const fk_quic_cid_route_prevalidation_result result =
        fk_quic_cid_map_prevalidate_logical_route_v2(
            map, logical_connection_id, expected_fixed_owner, &guard);
    if (result == FK_QUIC_CID_ROUTE_PREVALIDATION_ACTIVE ||
        result ==
            FK_QUIC_CID_ROUTE_PREVALIDATION_RETIRED_PENDING_OWNER_ACK ||
        result == FK_QUIC_CID_ROUTE_PREVALIDATION_OWNER_MISMATCH) {
        *immutable_fixed_owner = guard.immutable_fixed_owner;
    }
    return result;
}

fk_quic_cid_retirement_peek_result fk_quic_cid_map_peek_retired(
        fk_quic_cid_map *map,
        uint16_t fixed_owner,
        fk_quic_cid_retirement *retirement) {
    if (retirement != nullptr)
        *retirement = {};
    if (map == nullptr || retirement == nullptr)
        return FK_QUIC_CID_RETIREMENT_PEEK_INVALID;
    State &state = *implementation(map);
    LockGuard guard(state);
    if (state.magic != kMagic)
        return FK_QUIC_CID_RETIREMENT_PEEK_INVALID;
    state.stats.retirement_peek_calls++;
    if (fixed_owner >= state.config.fixed_owner_count) {
        state.stats.retirement_peek_invalid++;
        return FK_QUIC_CID_RETIREMENT_PEEK_INVALID;
    }
    const uint32_t slot = state.retired_head_by_fixed_owner[fixed_owner];
    if (slot == kNone) {
        state.stats.retirement_peek_empty++;
        return FK_QUIC_CID_RETIREMENT_PEEK_EMPTY;
    }
    if (slot >= state.config.maximum_connections) {
        state.stats.hard_integrity_failures++;
        state.stats.retirement_peek_invalid++;
        return FK_QUIC_CID_RETIREMENT_PEEK_INVALID;
    }
    const ConnectionEntry &entry = state.connections[slot];
    if (!connection_flag(entry, kConnectionRetiredPendingOwnerAck) ||
        entry.owner != fixed_owner || entry.created_ns == 0u) {
        state.stats.hard_integrity_failures++;
        state.stats.retirement_peek_invalid++;
        return FK_QUIC_CID_RETIREMENT_PEEK_INVALID;
    }
    if (!retirement_snapshot(
            state, slot, fixed_owner, *retirement)) {
        state.stats.hard_integrity_failures++;
        state.stats.retirement_peek_invalid++;
        return FK_QUIC_CID_RETIREMENT_PEEK_INVALID;
    }
    state.stats.retirement_peek_ready++;
    return FK_QUIC_CID_RETIREMENT_PEEK_READY;
}

fk_quic_cid_retirement_peek_result
fk_quic_cid_map_peek_next_undispatched_retirement(
        fk_quic_cid_map *map,
        uint16_t fixed_owner,
        fk_quic_cid_retirement *retirement) {
    if (retirement != nullptr)
        *retirement = {};
    if (map == nullptr || retirement == nullptr)
        return FK_QUIC_CID_RETIREMENT_PEEK_INVALID;
    State &state = *implementation(map);
    LockGuard guard(state);
    if (state.magic != kMagic)
        return FK_QUIC_CID_RETIREMENT_PEEK_INVALID;
    state.stats.retirement_publication_peek_calls++;
    if (fixed_owner >= state.config.fixed_owner_count) {
        state.stats.retirement_publication_peek_invalid++;
        return FK_QUIC_CID_RETIREMENT_PEEK_INVALID;
    }
    const uint32_t slot =
        state.first_undispatched_by_fixed_owner[fixed_owner];
    if (slot == kNone) {
        state.stats.retirement_publication_peek_empty++;
        return FK_QUIC_CID_RETIREMENT_PEEK_EMPTY;
    }
    if (slot >= state.config.maximum_connections ||
        connection_flag(
            state.connections[slot],
            kConnectionRetirementDispatched) ||
        !retirement_snapshot(
            state, slot, fixed_owner, *retirement)) {
        state.stats.hard_integrity_failures++;
        state.stats.retirement_publication_peek_invalid++;
        return FK_QUIC_CID_RETIREMENT_PEEK_INVALID;
    }
    state.stats.retirement_publication_peek_ready++;
    return FK_QUIC_CID_RETIREMENT_PEEK_READY;
}

fk_quic_cid_retirement_publication_result
fk_quic_cid_map_mark_retirement_dispatched(
        fk_quic_cid_map *map,
        const fk_quic_cid_retirement_token *token) {
    if (map == nullptr || token == nullptr)
        return FK_QUIC_CID_RETIREMENT_PUBLICATION_INVALID;
    State &state = *implementation(map);
    LockGuard guard(state);
    if (state.magic != kMagic)
        return FK_QUIC_CID_RETIREMENT_PUBLICATION_INVALID;
    state.stats.retirement_publication_mark_calls++;
    uint32_t slot = kNone;
    uint32_t generation = 0u;
    if (!retirement_token_shape_valid(
            state, *token, slot, generation)) {
        state.stats.retirement_publication_mark_invalid++;
        return FK_QUIC_CID_RETIREMENT_PUBLICATION_INVALID;
    }
    const uint32_t current =
        state.first_undispatched_by_fixed_owner[token->fixed_owner];
    if (current == kNone) {
        state.stats.retirement_publication_mark_empty++;
        return FK_QUIC_CID_RETIREMENT_PUBLICATION_EMPTY;
    }
    if (current != slot ||
        !retirement_token_matches_entry(
            state.connections[current], generation, *token)) {
        state.stats.retirement_publication_mark_mismatches++;
        return FK_QUIC_CID_RETIREMENT_PUBLICATION_MISMATCH;
    }
    ConnectionEntry &entry = state.connections[current];
    if (connection_flag(entry, kConnectionRetirementDispatched)) {
        state.stats.hard_integrity_failures++;
        state.stats.retirement_publication_mark_invalid++;
        return FK_QUIC_CID_RETIREMENT_PUBLICATION_INVALID;
    }
    const uint32_t next = entry.next_free;
    if (next != kNone) {
        if (next >= state.config.maximum_connections) {
            state.stats.hard_integrity_failures++;
            state.stats.retirement_publication_mark_invalid++;
            return FK_QUIC_CID_RETIREMENT_PUBLICATION_INVALID;
        }
        const ConnectionEntry &next_entry = state.connections[next];
        if (!connection_flag(
                next_entry, kConnectionRetiredPendingOwnerAck) ||
            connection_flag(
                next_entry, kConnectionRetirementDispatched) ||
            next_entry.owner != token->fixed_owner ||
            next_entry.created_ns <= entry.created_ns) {
            state.stats.hard_integrity_failures++;
            state.stats.retirement_publication_mark_invalid++;
            return FK_QUIC_CID_RETIREMENT_PUBLICATION_INVALID;
        }
    } else if (state.retired_tail_by_fixed_owner[token->fixed_owner] !=
            current) {
        state.stats.hard_integrity_failures++;
        state.stats.retirement_publication_mark_invalid++;
        return FK_QUIC_CID_RETIREMENT_PUBLICATION_INVALID;
    }
    set_connection_flag(entry, kConnectionRetirementDispatched, true);
    state.first_undispatched_by_fixed_owner[token->fixed_owner] = next;
    state.stats.retirement_publication_marks++;
    return FK_QUIC_CID_RETIREMENT_PUBLICATION_MARKED;
}

fk_quic_cid_retirement_publication_result
fk_quic_cid_map_rollback_retirement_dispatched(
        fk_quic_cid_map *map,
        const fk_quic_cid_retirement_token *token) {
    if (map == nullptr || token == nullptr)
        return FK_QUIC_CID_RETIREMENT_PUBLICATION_INVALID;
    State &state = *implementation(map);
    LockGuard guard(state);
    if (state.magic != kMagic)
        return FK_QUIC_CID_RETIREMENT_PUBLICATION_INVALID;
    state.stats.retirement_publication_rollback_calls++;
    uint32_t slot = kNone;
    uint32_t generation = 0u;
    if (!retirement_token_shape_valid(
            state, *token, slot, generation)) {
        state.stats.retirement_publication_rollback_invalid++;
        return FK_QUIC_CID_RETIREMENT_PUBLICATION_INVALID;
    }
    ConnectionEntry &entry = state.connections[slot];
    if (!retirement_token_matches_entry(entry, generation, *token) ||
        !connection_flag(entry, kConnectionRetirementDispatched)) {
        state.stats.retirement_publication_rollback_mismatches++;
        return FK_QUIC_CID_RETIREMENT_PUBLICATION_MISMATCH;
    }
    const uint16_t owner = token->fixed_owner;
    const uint32_t current =
        state.first_undispatched_by_fixed_owner[owner];
    if (entry.next_free != current) {
        state.stats.retirement_publication_rollback_mismatches++;
        return FK_QUIC_CID_RETIREMENT_PUBLICATION_MISMATCH;
    }
    if (current != kNone) {
        if (current >= state.config.maximum_connections) {
            state.stats.hard_integrity_failures++;
            state.stats.retirement_publication_rollback_invalid++;
            return FK_QUIC_CID_RETIREMENT_PUBLICATION_INVALID;
        }
        const ConnectionEntry &current_entry = state.connections[current];
        if (!connection_flag(
                current_entry, kConnectionRetiredPendingOwnerAck) ||
            connection_flag(
                current_entry, kConnectionRetirementDispatched) ||
            current_entry.owner != owner ||
            current_entry.created_ns <= entry.created_ns) {
            state.stats.hard_integrity_failures++;
            state.stats.retirement_publication_rollback_invalid++;
            return FK_QUIC_CID_RETIREMENT_PUBLICATION_INVALID;
        }
    } else if (state.retired_tail_by_fixed_owner[owner] != slot) {
        state.stats.hard_integrity_failures++;
        state.stats.retirement_publication_rollback_invalid++;
        return FK_QUIC_CID_RETIREMENT_PUBLICATION_INVALID;
    }
    set_connection_flag(entry, kConnectionRetirementDispatched, false);
    state.first_undispatched_by_fixed_owner[owner] = slot;
    state.stats.retirement_publication_rollbacks++;
    return FK_QUIC_CID_RETIREMENT_PUBLICATION_ROLLED_BACK;
}

fk_quic_cid_retirement_ack_result
fk_quic_cid_map_ack_retired_with_cleanup(
        fk_quic_cid_map *map,
        const fk_quic_cid_retirement_token *token,
        fk_quic_cid_owner_cleanup_callback cleanup,
        void *cleanup_user) {
    if (map == nullptr || token == nullptr || cleanup == nullptr)
        return FK_QUIC_CID_RETIREMENT_ACK_INVALID;
    State &state = *implementation(map);
    LockGuard guard(state);
    if (state.magic != kMagic)
        return FK_QUIC_CID_RETIREMENT_ACK_INVALID;
    state.stats.retirement_ack_calls++;
    uint32_t slot = kNone;
    uint32_t generation = 0u;
    if (!retirement_token_shape_valid(
            state, *token, slot, generation)) {
        state.stats.retirement_ack_invalid++;
        return FK_QUIC_CID_RETIREMENT_ACK_INVALID;
    }
    ConnectionEntry &entry = state.connections[slot];
    if (connection_flag(entry, kConnectionRetiredPendingOwnerAck) &&
        entry.generation == generation &&
        entry.owner != token->fixed_owner) {
        state.stats.retirement_ack_mismatches++;
        return FK_QUIC_CID_RETIREMENT_ACK_MISMATCH;
    }
    const uint16_t owner = token->fixed_owner;
    const uint32_t head = state.retired_head_by_fixed_owner[owner];
    if (head == kNone) {
        state.stats.retirement_ack_empty++;
        return FK_QUIC_CID_RETIREMENT_ACK_EMPTY;
    }
    if (head >= state.config.maximum_connections) {
        state.stats.hard_integrity_failures++;
        state.stats.retirement_ack_invalid++;
        return FK_QUIC_CID_RETIREMENT_ACK_INVALID;
    }
    ConnectionEntry &head_entry = state.connections[head];
    const bool snapshot_matches = head == slot &&
        connection_flag(
            head_entry, kConnectionRetiredPendingOwnerAck) &&
        head_entry.generation == generation && head_entry.owner == owner &&
        head_entry.created_ns == token->retirement_ordinal;
    if (!snapshot_matches) {
        state.stats.retirement_ack_mismatches++;
        return FK_QUIC_CID_RETIREMENT_ACK_MISMATCH;
    }
    const uint32_t owner_active =
        state.active_connections_by_fixed_owner[owner];
    const uint32_t owner_credits =
        state.binding_credits_by_fixed_owner[owner];
    if (owner_credits <= owner_active ||
        state.stats.retired_pending_owner_ack == 0u ||
        state.stats.binding_credits_in_use == 0u) {
        state.stats.hard_integrity_failures++;
        state.stats.retirement_ack_invalid++;
        return FK_QUIC_CID_RETIREMENT_ACK_INVALID;
    }
    const uint32_t next = head_entry.next_free;
    const uint32_t tail = state.retired_tail_by_fixed_owner[owner];
    if ((next == kNone && tail != head) ||
        (next != kNone &&
         (tail == head || next >= state.config.maximum_connections))) {
        state.stats.hard_integrity_failures++;
        state.stats.retirement_ack_invalid++;
        return FK_QUIC_CID_RETIREMENT_ACK_INVALID;
    }
    if (next != kNone) {
        const ConnectionEntry &next_entry = state.connections[next];
        if (!connection_flag(
                next_entry, kConnectionRetiredPendingOwnerAck) ||
            next_entry.owner != owner ||
            next_entry.created_ns <= head_entry.created_ns) {
            state.stats.hard_integrity_failures++;
            state.stats.retirement_ack_invalid++;
            return FK_QUIC_CID_RETIREMENT_ACK_INVALID;
        }
    }

    const bool head_dispatched = connection_flag(
        head_entry, kConnectionRetirementDispatched);
    const uint32_t first_undispatched =
        state.first_undispatched_by_fixed_owner[owner];
    if ((!head_dispatched && first_undispatched != head) ||
        (head_dispatched && first_undispatched == head) ||
        (head_dispatched && next == kNone &&
         first_undispatched != kNone)) {
        state.stats.hard_integrity_failures++;
        state.stats.retirement_ack_invalid++;
        return FK_QUIC_CID_RETIREMENT_ACK_INVALID;
    }

    /* Publication is an explicit producer-side transaction.  Cleanup cannot
     * run for a FIFO head that was never atomically submitted to owner
     * dispatch, even when its token is otherwise exact. */
    if (!head_dispatched) {
        state.stats.retirement_ack_not_dispatched++;
        return FK_QUIC_CID_RETIREMENT_ACK_NOT_DISPATCHED;
    }

    fk_quic_cid_retirement current{};
    if (!retirement_snapshot(state, head, owner, current)) {
        state.stats.hard_integrity_failures++;
        state.stats.retirement_ack_invalid++;
        return FK_QUIC_CID_RETIREMENT_ACK_INVALID;
    }
    if (!cleanup(cleanup_user, &current)) {
        state.stats.retirement_ack_cleanup_failures++;
        return FK_QUIC_CID_RETIREMENT_ACK_CLEANUP_FAILED;
    }

    /* Every fallible validation and external action is complete.  The
     * remaining local pop/counter/reclaim sequence cannot fail. */
    state.retired_head_by_fixed_owner[owner] = next;
    if (next == kNone)
        state.retired_tail_by_fixed_owner[owner] = kNone;
    state.binding_credits_by_fixed_owner[owner]--;
    state.stats.retired_pending_owner_ack--;
    state.stats.binding_credits_in_use--;
    state.stats.retirement_acks++;
    reclaim_unpublished_or_acknowledged_slot(state, head);
    refresh_used(state);
    return FK_QUIC_CID_RETIREMENT_ACKED;
}

bool fk_quic_cid_map_get_stats(
        const fk_quic_cid_map *map,
        fk_quic_cid_map_stats *stats) {
    if (map == nullptr || stats == nullptr)
        return false;
    State &state = *const_cast<State *>(implementation(map));
    LockGuard guard(state);
    if (state.magic != kMagic)
        return false;
    *stats = state.stats;
    return true;
}

bool fk_quic_cid_map_get_fixed_owner_active_connections(
        const fk_quic_cid_map *map,
        uint16_t fixed_owner,
        uint32_t *active_connections) {
    if (map == nullptr || active_connections == nullptr)
        return false;
    State &state = *const_cast<State *>(implementation(map));
    LockGuard guard(state);
    if (state.magic != kMagic ||
        fixed_owner >= state.config.fixed_owner_count)
        return false;
    *active_connections =
        state.active_connections_by_fixed_owner[fixed_owner];
    return true;
}

bool fk_quic_cid_map_get_fixed_owner_lifecycle(
        const fk_quic_cid_map *map,
        uint16_t fixed_owner,
        fk_quic_cid_fixed_owner_lifecycle *lifecycle) {
    if (lifecycle != nullptr)
        *lifecycle = {};
    if (map == nullptr || lifecycle == nullptr)
        return false;
    State &state = *const_cast<State *>(implementation(map));
    LockGuard guard(state);
    if (state.magic != kMagic ||
        fixed_owner >= state.config.fixed_owner_count)
        return false;
    lifecycle->active_connections =
        state.active_connections_by_fixed_owner[fixed_owner];
    lifecycle->binding_credits_in_use =
        state.binding_credits_by_fixed_owner[fixed_owner];
    if (lifecycle->binding_credits_in_use <
            lifecycle->active_connections)
        return false;
    lifecycle->retired_pending_owner_ack =
        lifecycle->binding_credits_in_use -
        lifecycle->active_connections;
    return true;
}

bool fk_quic_cid_map_accounting_conserved(
        const fk_quic_cid_map *map) {
    if (map == nullptr)
        return false;
    State &state = *const_cast<State *>(implementation(map));
    LockGuard guard(state);
    return accounting_conserved_locked(state);
}

const char *fk_quic_cid_retirement_peek_result_name(
        fk_quic_cid_retirement_peek_result result) {
    switch (result) {
    case FK_QUIC_CID_RETIREMENT_PEEK_INVALID:
        return "invalid";
    case FK_QUIC_CID_RETIREMENT_PEEK_EMPTY:
        return "empty";
    case FK_QUIC_CID_RETIREMENT_PEEK_READY:
        return "ready";
    }
    return "unknown";
}

const char *fk_quic_cid_retirement_ack_result_name(
        fk_quic_cid_retirement_ack_result result) {
    switch (result) {
    case FK_QUIC_CID_RETIREMENT_ACK_INVALID:
        return "invalid";
    case FK_QUIC_CID_RETIREMENT_ACK_EMPTY:
        return "empty";
    case FK_QUIC_CID_RETIREMENT_ACK_MISMATCH:
        return "mismatch";
    case FK_QUIC_CID_RETIREMENT_ACKED:
        return "acked";
    case FK_QUIC_CID_RETIREMENT_ACK_CLEANUP_FAILED:
        return "cleanup_failed";
    case FK_QUIC_CID_RETIREMENT_ACK_NOT_DISPATCHED:
        return "not_dispatched";
    }
    return "unknown";
}

const char *fk_quic_cid_route_prevalidation_result_name(
        fk_quic_cid_route_prevalidation_result result) {
    switch (result) {
    case FK_QUIC_CID_ROUTE_PREVALIDATION_INVALID:
        return "invalid";
    case FK_QUIC_CID_ROUTE_PREVALIDATION_ACTIVE:
        return "active";
    case FK_QUIC_CID_ROUTE_PREVALIDATION_RETIRED_PENDING_OWNER_ACK:
        return "retired_pending_owner_ack";
    case FK_QUIC_CID_ROUTE_PREVALIDATION_OWNER_MISMATCH:
        return "owner_mismatch";
    case FK_QUIC_CID_ROUTE_PREVALIDATION_STALE_GENERATION:
        return "stale_generation";
    case FK_QUIC_CID_ROUTE_PREVALIDATION_NOT_FOUND:
        return "not_found";
    case FK_QUIC_CID_ROUTE_PREVALIDATION_INTERNAL_INTEGRITY:
        return "internal_integrity";
    }
    return "unknown";
}

const char *fk_quic_cid_retirement_publication_result_name(
        fk_quic_cid_retirement_publication_result result) {
    switch (result) {
    case FK_QUIC_CID_RETIREMENT_PUBLICATION_INVALID:
        return "invalid";
    case FK_QUIC_CID_RETIREMENT_PUBLICATION_EMPTY:
        return "empty";
    case FK_QUIC_CID_RETIREMENT_PUBLICATION_MISMATCH:
        return "mismatch";
    case FK_QUIC_CID_RETIREMENT_PUBLICATION_MARKED:
        return "marked";
    case FK_QUIC_CID_RETIREMENT_PUBLICATION_ROLLED_BACK:
        return "rolled_back";
    }
    return "unknown";
}

const char *fk_quic_cid_reject_reason_name(
        fk_quic_cid_reject_reason reason) {
    switch (reason) {
    case FK_QUIC_CID_REJECT_NONE:
        return "none";
    case FK_QUIC_CID_REJECT_INVALID_INPUT:
        return "invalid_input";
    case FK_QUIC_CID_REJECT_TIME_REGRESSION:
        return "semantic_time_regression";
    case FK_QUIC_CID_REJECT_CONNECTION_CAPACITY:
        return "connection_capacity";
    case FK_QUIC_CID_REJECT_CID_CAPACITY:
        return "cid_capacity";
    case FK_QUIC_CID_REJECT_PER_CONNECTION_CID_CAPACITY:
        return "per_connection_cid_capacity";
    case FK_QUIC_CID_REJECT_PENDING_HANDSHAKE_CAPACITY:
        return "pending_handshake_capacity";
    case FK_QUIC_CID_REJECT_COLLISION:
        return "cid_collision";
    case FK_QUIC_CID_REJECT_UNSUPPORTED_HEADER:
        return "unsupported_header";
    case FK_QUIC_CID_REJECT_SHORT_HEADER_PREFIX_AMBIGUITY:
        return "short_header_prefix_ambiguity";
    case FK_QUIC_CID_REJECT_HASH_CHAIN_CAPACITY:
        return "hash_chain_capacity";
    case FK_QUIC_CID_REJECT_DIRECTION_CONFLICT:
        return "direction_conflict";
    case FK_QUIC_CID_REJECT_INTERNAL_INTEGRITY:
        return "internal_integrity";
    case FK_QUIC_CID_REJECT_FIXED_BIT_ZERO_UNNEGOTIATED:
        return "fixed_bit_zero_unnegotiated";
    case FK_QUIC_CID_REJECT_FIXED_OWNER_CAPACITY:
        return "fixed_owner_capacity";
    case FK_QUIC_CID_REJECT_INITIAL_AUTH_REQUIRED:
        return "initial_auth_required";
    case FK_QUIC_CID_REJECT_INITIAL_PROOF_MISMATCH:
        return "initial_proof_mismatch";
    case FK_QUIC_CID_REJECT_NON_INITIAL_MUTATION:
        return "non_initial_mutation";
    case FK_QUIC_CID_REJECT_FIXED_BIT_ZERO:
        return "fixed_bit_zero";
    }
    return "unknown";
}

#ifdef FK_QUIC_CID_MAP_TEST_HOOKS
bool fk_quic_cid_map_test_override_hash_chain_limit(
        fk_quic_cid_map *map, uint32_t maximum_hash_chain) {
    if (map == nullptr)
        return false;
    State &state = *implementation(map);
    LockGuard guard(state);
    if (state.magic != kMagic ||
        maximum_hash_chain > state.config.maximum_cids)
        return false;
    state.config.maximum_hash_chain = maximum_hash_chain;
    return true;
}

bool fk_quic_cid_map_test_set_free_head_generation(
        fk_quic_cid_map *map, uint32_t generation) {
    if (map == nullptr)
        return false;
    State &state = *implementation(map);
    LockGuard guard(state);
    if (state.magic != kMagic || state.connection_free_head == kNone ||
        state.connection_free_head >= state.config.maximum_connections)
        return false;
    ConnectionEntry &entry =
        state.connections[state.connection_free_head];
    if (entry.flags != 0u || entry.first_cid != kNone ||
        entry.cid_count != 0u)
        return false;
    entry.generation = generation;
    return true;
}

bool fk_quic_cid_map_test_override_bucket_head(
        fk_quic_cid_map *map,
        const uint8_t *cid,
        uint8_t cid_length,
        uint32_t replacement_head,
        uint32_t *prior_head) {
    if (map == nullptr || prior_head == nullptr ||
        !valid_cid(cid, cid_length))
        return false;
    State &state = *implementation(map);
    LockGuard guard(state);
    if (state.magic != kMagic ||
        (replacement_head != kNone &&
         replacement_head > state.config.maximum_cids))
        return false;
    const uint32_t bucket =
        static_cast<uint32_t>(cid_hash(state, cid, cid_length)) &
        state.cid_bucket_mask;
    *prior_head = state.cid_buckets[bucket];
    state.cid_buckets[bucket] = replacement_head;
    return true;
}
#endif

}  // extern "C"
