#include "fk_quic_presentation_path_directory.h"

#include <cstddef>
#include <cstdio>
#include <cstring>
#include <limits>
#include <new>

namespace {

constexpr uint32_t kInvalidIndex = UINT32_MAX;
constexpr uint8_t kUdpProtocol = 17u;
constexpr size_t kCanonicalKeyBytes = 38u;

struct ConnectionEntry {
    uint64_t logical_connection_id = 0u;
    uint32_t path_head = kInvalidIndex;
    uint16_t path_count = 0u;
    uint16_t reserved = 0u;
};

struct PathEntry {
    fk_flow_key key{};
    uint64_t logical_connection_id = 0u;
    uint64_t last_authenticated_timestamp_ns = 0u;
    uint64_t key_hash = 0u;
    uint32_t bucket_next = kInvalidIndex;
    uint32_t bucket_previous = kInvalidIndex;
    uint32_t connection_next = kInvalidIndex;
    uint32_t connection_previous = kInvalidIndex;
    uint32_t free_next = kInvalidIndex;
    uint8_t active = 0u;
    uint8_t reserved[3]{};
};

struct DirectoryImpl {
    fk_quic_presentation_path_directory_config config{};
    fk_quic_presentation_path_directory_stats stats{};
    uint32_t *buckets = nullptr;
    ConnectionEntry *connections = nullptr;
    PathEntry *paths = nullptr;
    uint32_t free_path_head = kInvalidIndex;
    uint32_t expiration_cursor = 0u;
};

struct Layout {
    size_t total_bytes = 0u;
    size_t bucket_offset = 0u;
    size_t connection_offset = 0u;
    size_t path_offset = 0u;
    uint32_t bucket_count = 0u;
};

struct DecodedLogicalId {
    uint32_t slot = 0u;
    uint32_t generation = 0u;
};

enum class RemovalCause {
    Expired,
    Released,
};

struct BucketScan {
    bool valid = true;
    uint32_t matching = 0u;
    uint32_t exact_logical_index = kInvalidIndex;
    uint32_t chain_length = 0u;
};

static_assert(sizeof(fk_flow_key) == 38u,
    "canonical flow-key ABI drifted");
static_assert(sizeof(ConnectionEntry) ==
        FK_QUIC_PRESENTATION_PATH_CONNECTION_ENTRY_BYTES,
    "presentation-path connection entry must remain exactly 16 bytes");
static_assert(sizeof(PathEntry) == FK_QUIC_PRESENTATION_PATH_ENTRY_BYTES,
    "presentation-path entry must remain exactly 88 bytes");
static_assert(sizeof(fk_quic_presentation_path_directory_config) == 56u,
    "presentation-path config ABI v1 layout drifted");
static_assert(sizeof(fk_quic_presentation_path_classification) == 16u,
    "classification ABI must remain value-only and contain no logical id");
static_assert(alignof(DirectoryImpl) <= alignof(max_align_t) &&
        alignof(ConnectionEntry) <= alignof(max_align_t) &&
        alignof(PathEntry) <= alignof(max_align_t),
    "all placement objects must fit max_align_t storage");

bool checked_add_size(size_t &value, size_t addend) {
    if (addend > std::numeric_limits<size_t>::max() - value)
        return false;
    value += addend;
    return true;
}

bool checked_multiply_size(size_t left, size_t right, size_t &result) {
    if (left != 0u && right > std::numeric_limits<size_t>::max() / left)
        return false;
    result = left * right;
    return true;
}

bool align_size(size_t &value, size_t alignment) {
    const size_t remainder = value % alignment;
    return remainder == 0u || checked_add_size(value, alignment - remainder);
}

bool reserved_zero(
        const fk_quic_presentation_path_directory_config &config) {
    if (config.reserved0 != 0u || config.reserved1 != 0u)
        return false;
    for (uint8_t byte : config.reserved) {
        if (byte != 0u)
            return false;
    }
    return true;
}

bool valid_config(
        const fk_quic_presentation_path_directory_config *config) {
    return config != nullptr &&
        config->maximum_logical_connections != 0u &&
        config->maximum_logical_connections < UINT32_MAX &&
        config->maximum_paths != 0u &&
        config->maximum_paths <= (UINT32_C(1) << 30u) &&
        config->maximum_paths_per_connection != 0u &&
        config->maximum_paths_per_connection <= config->maximum_paths &&
        config->maximum_hash_chain != 0u &&
        config->maximum_hash_chain <= config->maximum_paths &&
        config->expiration_scan_per_operation != 0u &&
        config->expiration_scan_per_operation <= config->maximum_paths &&
        config->path_ttl_ns != 0u &&
        config->siphash_key_precommitted == 1u && reserved_zero(*config);
}

bool next_power_of_two(uint32_t value, uint32_t &result) {
    uint64_t candidate = 1u;
    while (candidate < value)
        candidate <<= 1u;
    if (candidate > UINT32_MAX)
        return false;
    result = static_cast<uint32_t>(candidate);
    return true;
}

bool compute_layout(
        const fk_quic_presentation_path_directory_config *config,
        Layout &layout) {
    layout = {};
    if (!valid_config(config) ||
        !next_power_of_two(config->maximum_paths, layout.bucket_count))
        return false;

    size_t cursor = sizeof(DirectoryImpl);
    if (!align_size(cursor, alignof(uint32_t)))
        return false;
    layout.bucket_offset = cursor;
    size_t bytes = 0u;
    if (!checked_multiply_size(
            layout.bucket_count, sizeof(uint32_t), bytes) ||
        !checked_add_size(cursor, bytes) ||
        !align_size(cursor, alignof(ConnectionEntry)))
        return false;
    layout.connection_offset = cursor;
    if (!checked_multiply_size(
            config->maximum_logical_connections,
            sizeof(ConnectionEntry), bytes) ||
        !checked_add_size(cursor, bytes) ||
        !align_size(cursor, alignof(PathEntry)))
        return false;
    layout.path_offset = cursor;
    if (!checked_multiply_size(
            config->maximum_paths, sizeof(PathEntry), bytes) ||
        !checked_add_size(cursor, bytes))
        return false;
    layout.total_bytes = cursor;
    return true;
}

void set_error(char *error, size_t capacity, const char *message) {
    if (error == nullptr || capacity == 0u)
        return;
    std::snprintf(error, capacity, "%s", message == nullptr ? "" : message);
}

DirectoryImpl *implementation(
        fk_quic_presentation_path_directory *directory) {
    return reinterpret_cast<DirectoryImpl *>(directory);
}

const DirectoryImpl *implementation(
        const fk_quic_presentation_path_directory *directory) {
    return reinterpret_cast<const DirectoryImpl *>(directory);
}

uint64_t rotate_left(uint64_t value, uint32_t bits) {
    return (value << bits) | (value >> (64u - bits));
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
        const uint8_t key[16],
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
        tail |= static_cast<uint64_t>(message[offset + index]) <<
            (index * 8u);
    v3 ^= tail;
    sip_round(v0, v1, v2, v3);
    sip_round(v0, v1, v2, v3);
    v0 ^= tail;
    v2 ^= 0xffu;
    for (uint32_t index = 0u; index < 4u; ++index)
        sip_round(v0, v1, v2, v3);
    return v0 ^ v1 ^ v2 ^ v3;
}

int endpoint_compare(
        const uint8_t *left_address,
        uint16_t left_port,
        const uint8_t *right_address,
        uint16_t right_port,
        size_t address_bytes) {
    const int address_order = std::memcmp(
        left_address, right_address, address_bytes);
    if (address_order != 0)
        return address_order;
    if (left_port < right_port)
        return -1;
    if (left_port > right_port)
        return 1;
    return 0;
}

bool canonical_udp_key(
        const fk_flow_key *input,
        fk_flow_key &canonical) {
    if (input == nullptr ||
        (input->ip_version != 4u && input->ip_version != 6u) ||
        input->protocol != kUdpProtocol)
        return false;
    canonical = {};
    canonical.ip_version = input->ip_version;
    canonical.protocol = input->protocol;
    const size_t address_bytes = input->ip_version == 4u ? 4u : 16u;
    std::memcpy(canonical.low_addr, input->low_addr, address_bytes);
    std::memcpy(canonical.high_addr, input->high_addr, address_bytes);
    canonical.low_port = input->low_port;
    canonical.high_port = input->high_port;
    if (endpoint_compare(
            canonical.low_addr,
            canonical.low_port,
            canonical.high_addr,
            canonical.high_port,
            address_bytes) > 0)
        return false;
    /* Also rejects nonzero IPv4 tail bytes. */
    return std::memcmp(input, &canonical, sizeof(canonical)) == 0;
}

void serialize_key(
        const fk_flow_key &key,
        uint8_t bytes[kCanonicalKeyBytes]) {
    bytes[0] = key.ip_version;
    bytes[1] = key.protocol;
    std::memcpy(bytes + 2u, key.low_addr, sizeof(key.low_addr));
    std::memcpy(bytes + 18u, key.high_addr, sizeof(key.high_addr));
    bytes[34] = static_cast<uint8_t>(key.low_port >> 8u);
    bytes[35] = static_cast<uint8_t>(key.low_port);
    bytes[36] = static_cast<uint8_t>(key.high_port >> 8u);
    bytes[37] = static_cast<uint8_t>(key.high_port);
}

uint64_t key_hash(const DirectoryImpl &state, const fk_flow_key &key) {
    uint8_t bytes[kCanonicalKeyBytes]{};
    serialize_key(key, bytes);
    return siphash24(state.config.siphash_key, bytes, sizeof(bytes));
}

bool decode_logical_id(
        const DirectoryImpl &state,
        uint64_t logical_connection_id,
        DecodedLogicalId &decoded) {
    return fk_quic_logical_id_decode(
        logical_connection_id,
        state.config.maximum_logical_connections,
        &decoded.slot,
        &decoded.generation);
}

void reset_classification(
        fk_quic_presentation_path_classification *classification) {
    if (classification != nullptr)
        *classification = {};
}

void update_used_bytes(DirectoryImpl &state) {
    state.stats.used_bytes = state.stats.fixed_bytes +
        static_cast<uint64_t>(state.stats.active_logical_connections) *
            sizeof(ConnectionEntry) +
        static_cast<uint64_t>(state.stats.active_paths) * sizeof(PathEntry);
    if (state.stats.used_bytes > state.stats.peak_used_bytes)
        state.stats.peak_used_bytes = state.stats.used_bytes;
}

void multiply_u64(
        uint64_t left,
        uint64_t right,
        uint64_t &high,
        uint64_t &low) {
    const uint64_t left_low = static_cast<uint32_t>(left);
    const uint64_t left_high = left >> 32u;
    const uint64_t right_low = static_cast<uint32_t>(right);
    const uint64_t right_high = right >> 32u;
    const uint64_t first = left_low * right_low;
    const uint64_t middle_first =
        left_high * right_low + (first >> 32u);
    uint64_t middle = static_cast<uint32_t>(middle_first);
    const uint64_t upper = middle_first >> 32u;
    middle += left_low * right_high;
    high = left_high * right_high + upper + (middle >> 32u);
    low = (middle << 32u) | static_cast<uint32_t>(first);
}

bool accumulate_byte_time(
        DirectoryImpl &state,
        uint64_t elapsed_ns) {
    uint64_t product_high = 0u;
    uint64_t product_low = 0u;
    multiply_u64(
        state.stats.used_bytes, elapsed_ns, product_high, product_low);
    const uint64_t old_low = state.stats.state_byte_nanoseconds_low;
    const uint64_t new_low = old_low + product_low;
    const uint64_t carry = new_low < old_low ? 1u : 0u;
    if (product_high > UINT64_MAX -
            state.stats.state_byte_nanoseconds_high ||
        carry > UINT64_MAX -
            state.stats.state_byte_nanoseconds_high - product_high)
        return false;
    state.stats.state_byte_nanoseconds_low = new_low;
    state.stats.state_byte_nanoseconds_high += product_high + carry;
    return true;
}

bool advance_semantic_time(
        DirectoryImpl &state,
        uint64_t timestamp_ns,
        fk_quic_presentation_path_reject_reason &reason) {
    if (state.stats.semantic_timestamp_set == 0u) {
        state.stats.semantic_timestamp_set = 1u;
        state.stats.last_semantic_timestamp_ns = timestamp_ns;
        return true;
    }
    if (timestamp_ns < state.stats.last_semantic_timestamp_ns) {
        reason = FK_QUIC_PRESENTATION_PATH_REJECT_TIME_REGRESSION;
        return false;
    }
    const uint64_t elapsed =
        timestamp_ns - state.stats.last_semantic_timestamp_ns;
    if (elapsed != 0u && !accumulate_byte_time(state, elapsed)) {
        reason = FK_QUIC_PRESENTATION_PATH_REJECT_BYTE_TIME_OVERFLOW;
        return false;
    }
    state.stats.last_semantic_timestamp_ns = timestamp_ns;
    return true;
}

bool path_expired(
        const DirectoryImpl &state,
        const PathEntry &path,
        uint64_t timestamp_ns) {
    return timestamp_ns >= path.last_authenticated_timestamp_ns &&
        timestamp_ns - path.last_authenticated_timestamp_ns >=
            state.config.path_ttl_ns;
}

void count_reject(
        DirectoryImpl &state,
        fk_quic_presentation_path_reject_reason reason) {
    state.stats.rejected_operations++;
    switch (reason) {
    case FK_QUIC_PRESENTATION_PATH_REJECT_INVALID_INPUT:
        state.stats.invalid_input_rejects++;
        break;
    case FK_QUIC_PRESENTATION_PATH_REJECT_TIME_REGRESSION:
        state.stats.time_regression_rejects++;
        break;
    case FK_QUIC_PRESENTATION_PATH_REJECT_GLOBAL_CAPACITY:
        state.stats.global_capacity_rejects++;
        break;
    case FK_QUIC_PRESENTATION_PATH_REJECT_PER_CONNECTION_CAPACITY:
        state.stats.per_connection_capacity_rejects++;
        break;
    case FK_QUIC_PRESENTATION_PATH_REJECT_HASH_CHAIN_CAPACITY:
        state.stats.hash_chain_capacity_rejects++;
        break;
    case FK_QUIC_PRESENTATION_PATH_REJECT_LOGICAL_GENERATION_CONFLICT:
        state.stats.logical_generation_conflict_rejects++;
        break;
    case FK_QUIC_PRESENTATION_PATH_REJECT_BYTE_TIME_OVERFLOW:
        state.stats.byte_time_overflow_rejects++;
        break;
    case FK_QUIC_PRESENTATION_PATH_REJECT_INTERNAL_INTEGRITY:
        state.stats.internal_integrity_rejects++;
        break;
    case FK_QUIC_PRESENTATION_PATH_REJECT_NONE:
        break;
    }
}

fk_quic_presentation_path_code finish_classification(
        DirectoryImpl &state,
        fk_quic_presentation_path_classification &classification,
        fk_quic_presentation_path_code code,
        fk_quic_presentation_path_reject_reason reason,
        uint32_t matching,
        bool created,
        bool refreshed) {
    classification = {};
    classification.code = code;
    classification.reason = reason;
    classification.matching_logical_connections = matching;
    classification.registration_created = created ? 1u : 0u;
    classification.registration_refreshed = refreshed ? 1u : 0u;
    switch (code) {
    case FK_QUIC_PRESENTATION_PATH_NOT_KNOWN:
        state.stats.not_known_classifications++;
        break;
    case FK_QUIC_PRESENTATION_PATH_KNOWN_QUIC_PATH:
        state.stats.known_classifications++;
        break;
    case FK_QUIC_PRESENTATION_PATH_AMBIGUOUS:
        state.stats.ambiguous_classifications++;
        break;
    case FK_QUIC_PRESENTATION_PATH_REJECTED:
        count_reject(state, reason);
        break;
    }
    return code;
}

fk_quic_presentation_path_code reject_classification(
        DirectoryImpl &state,
        fk_quic_presentation_path_classification &classification,
        fk_quic_presentation_path_reject_reason reason) {
    return finish_classification(
        state,
        classification,
        FK_QUIC_PRESENTATION_PATH_REJECTED,
        reason,
        0u,
        false,
        false);
}

bool unlink_path(
        DirectoryImpl &state,
        uint32_t index,
        RemovalCause cause) {
    if (index >= state.config.maximum_paths)
        return false;
    PathEntry &path = state.paths[index];
    if (path.active != 1u)
        return false;
    DecodedLogicalId decoded{};
    if (!decode_logical_id(state, path.logical_connection_id, decoded))
        return false;
    ConnectionEntry &connection = state.connections[decoded.slot];
    if (connection.logical_connection_id != path.logical_connection_id ||
        connection.path_count == 0u)
        return false;
    const uint32_t bucket =
        static_cast<uint32_t>(path.key_hash) &
        (state.stats.hash_bucket_count - 1u);
    if (path.bucket_previous == kInvalidIndex) {
        if (state.buckets[bucket] != index)
            return false;
    } else if (path.bucket_previous >= state.config.maximum_paths ||
            state.paths[path.bucket_previous].active != 1u ||
            state.paths[path.bucket_previous].bucket_next != index) {
        return false;
    }
    if (path.bucket_next != kInvalidIndex &&
        (path.bucket_next >= state.config.maximum_paths ||
         state.paths[path.bucket_next].active != 1u ||
         state.paths[path.bucket_next].bucket_previous != index))
        return false;
    if (path.connection_previous == kInvalidIndex) {
        if (connection.path_head != index)
            return false;
    } else if (path.connection_previous >= state.config.maximum_paths ||
            state.paths[path.connection_previous].active != 1u ||
            state.paths[path.connection_previous].connection_next != index) {
        return false;
    }
    if (path.connection_next != kInvalidIndex &&
        (path.connection_next >= state.config.maximum_paths ||
         state.paths[path.connection_next].active != 1u ||
         state.paths[path.connection_next].connection_previous != index))
        return false;

    if (path.bucket_previous == kInvalidIndex)
        state.buckets[bucket] = path.bucket_next;
    else
        state.paths[path.bucket_previous].bucket_next = path.bucket_next;
    if (path.bucket_next != kInvalidIndex)
        state.paths[path.bucket_next].bucket_previous = path.bucket_previous;
    if (path.connection_previous == kInvalidIndex)
        connection.path_head = path.connection_next;
    else
        state.paths[path.connection_previous].connection_next =
            path.connection_next;
    if (path.connection_next != kInvalidIndex)
        state.paths[path.connection_next].connection_previous =
            path.connection_previous;

    connection.path_count--;
    if (connection.path_count == 0u) {
        connection = {};
        connection.path_head = kInvalidIndex;
        if (state.stats.active_logical_connections == 0u)
            return false;
        state.stats.active_logical_connections--;
    }
    PathEntry empty{};
    empty.bucket_next = kInvalidIndex;
    empty.bucket_previous = kInvalidIndex;
    empty.connection_next = kInvalidIndex;
    empty.connection_previous = kInvalidIndex;
    empty.free_next = state.free_path_head;
    path = empty;
    state.free_path_head = index;
    if (state.stats.active_paths == 0u)
        return false;
    state.stats.active_paths--;
    if (cause == RemovalCause::Expired)
        state.stats.paths_expired++;
    else
        state.stats.paths_released++;
    update_used_bytes(state);
    return true;
}

bool run_expiration_scan(DirectoryImpl &state, uint64_t timestamp_ns) {
    state.stats.expiration_scan_calls++;
    for (uint32_t count = 0u;
         count < state.config.expiration_scan_per_operation;
         ++count) {
        const uint32_t index = state.expiration_cursor;
        state.expiration_cursor++;
        if (state.expiration_cursor == state.config.maximum_paths)
            state.expiration_cursor = 0u;
        state.stats.expiration_slots_scanned++;
        if (state.paths[index].active == 1u &&
            path_expired(state, state.paths[index], timestamp_ns) &&
            !unlink_path(state, index, RemovalCause::Expired))
            return false;
    }
    return true;
}

bool purge_expired_connection_paths(
        DirectoryImpl &state,
        uint32_t slot,
        uint64_t timestamp_ns) {
    uint32_t index = state.connections[slot].path_head;
    uint32_t traversed = 0u;
    while (index != kInvalidIndex) {
        if (index >= state.config.maximum_paths ||
            ++traversed > state.config.maximum_paths)
            return false;
        const uint32_t next = state.paths[index].connection_next;
        if (path_expired(state, state.paths[index], timestamp_ns) &&
            !unlink_path(state, index, RemovalCause::Expired))
            return false;
        index = next;
    }
    return true;
}

BucketScan scan_bucket(
        DirectoryImpl &state,
        const fk_flow_key &key,
        uint64_t hash,
        uint64_t timestamp_ns,
        uint64_t exact_logical_id) {
    BucketScan result{};
    const uint32_t bucket = static_cast<uint32_t>(hash) &
        (state.stats.hash_bucket_count - 1u);
    uint32_t index = state.buckets[bucket];
    uint32_t traversed = 0u;
    while (index != kInvalidIndex) {
        if (index >= state.config.maximum_paths ||
            ++traversed > state.config.maximum_paths) {
            result.valid = false;
            return result;
        }
        result.chain_length++;
        const uint32_t next = state.paths[index].bucket_next;
        if (state.paths[index].active != 1u) {
            result.valid = false;
            return result;
        }
        if (path_expired(state, state.paths[index], timestamp_ns)) {
            if (!unlink_path(state, index, RemovalCause::Expired)) {
                result.valid = false;
                return result;
            }
            result.chain_length--;
        } else if (state.paths[index].key_hash == hash &&
                fk_flow_key_equal(&state.paths[index].key, &key)) {
            result.matching++;
            if (exact_logical_id != 0u &&
                state.paths[index].logical_connection_id ==
                    exact_logical_id) {
                if (result.exact_logical_index != kInvalidIndex) {
                    result.valid = false;
                    return result;
                }
                result.exact_logical_index = index;
            }
        }
        index = next;
    }
    if (result.chain_length > state.config.maximum_hash_chain)
        result.valid = false;
    return result;
}

fk_quic_presentation_path_code classification_for_count(uint32_t count) {
    if (count == 0u)
        return FK_QUIC_PRESENTATION_PATH_NOT_KNOWN;
    if (count == 1u)
        return FK_QUIC_PRESENTATION_PATH_KNOWN_QUIC_PATH;
    return FK_QUIC_PRESENTATION_PATH_AMBIGUOUS;
}

bool create_path(
        DirectoryImpl &state,
        uint32_t connection_slot,
        uint64_t logical_connection_id,
        const fk_flow_key &key,
        uint64_t hash,
        uint64_t timestamp_ns) {
    if (state.free_path_head == kInvalidIndex ||
        state.free_path_head >= state.config.maximum_paths)
        return false;
    ConnectionEntry &connection = state.connections[connection_slot];
    const bool new_connection = connection.logical_connection_id == 0u;
    if (new_connection) {
        connection.logical_connection_id = logical_connection_id;
        connection.path_head = kInvalidIndex;
        connection.path_count = 0u;
        state.stats.active_logical_connections++;
        if (state.stats.active_logical_connections >
            state.stats.peak_active_logical_connections) {
            state.stats.peak_active_logical_connections =
                state.stats.active_logical_connections;
        }
    }
    const uint32_t index = state.free_path_head;
    PathEntry &path = state.paths[index];
    state.free_path_head = path.free_next;
    path = {};
    path.key = key;
    path.logical_connection_id = logical_connection_id;
    path.last_authenticated_timestamp_ns = timestamp_ns;
    path.key_hash = hash;
    const uint32_t bucket = static_cast<uint32_t>(hash) &
        (state.stats.hash_bucket_count - 1u);
    path.bucket_next = state.buckets[bucket];
    path.bucket_previous = kInvalidIndex;
    path.connection_next = connection.path_head;
    path.connection_previous = kInvalidIndex;
    path.free_next = kInvalidIndex;
    path.active = 1u;
    if (path.bucket_next != kInvalidIndex)
        state.paths[path.bucket_next].bucket_previous = index;
    if (path.connection_next != kInvalidIndex)
        state.paths[path.connection_next].connection_previous = index;
    state.buckets[bucket] = index;
    connection.path_head = index;
    connection.path_count++;
    state.stats.active_paths++;
    state.stats.paths_registered++;
    if (state.stats.active_paths > state.stats.peak_active_paths)
        state.stats.peak_active_paths = state.stats.active_paths;
    update_used_bytes(state);
    return true;
}

bool internal_accounting_conserved(const DirectoryImpl &state) {
    Layout layout{};
    if (!compute_layout(&state.config, layout))
        return false;
    const uint64_t variable_bytes =
        static_cast<uint64_t>(state.config.maximum_logical_connections) *
            sizeof(ConnectionEntry) +
        static_cast<uint64_t>(state.config.maximum_paths) * sizeof(PathEntry);
    if (state.stats.reserved_bytes != layout.total_bytes ||
        state.stats.fixed_bytes != state.stats.reserved_bytes -
            variable_bytes ||
        state.stats.used_bytes > state.stats.reserved_bytes ||
        state.stats.peak_used_bytes < state.stats.used_bytes ||
        state.stats.peak_used_bytes > state.stats.reserved_bytes ||
        state.stats.active_logical_connections >
            state.config.maximum_logical_connections ||
        state.stats.peak_active_logical_connections >
            state.config.maximum_logical_connections ||
        state.stats.active_paths > state.config.maximum_paths ||
        state.stats.peak_active_paths > state.config.maximum_paths ||
        state.stats.maximum_logical_connections !=
            state.config.maximum_logical_connections ||
        state.stats.maximum_paths != state.config.maximum_paths ||
        state.stats.maximum_paths_per_connection !=
            state.config.maximum_paths_per_connection ||
        state.stats.path_entry_bytes != sizeof(PathEntry) ||
        state.stats.connection_entry_bytes != sizeof(ConnectionEntry) ||
        state.stats.siphash_key_precommitted != 1u ||
        state.stats.hash_bucket_count != layout.bucket_count ||
        (state.stats.hash_bucket_count &
            (state.stats.hash_bucket_count - 1u)) != 0u ||
        state.expiration_cursor >= state.config.maximum_paths ||
        state.stats.semantic_timestamp_set > 1u ||
        (state.stats.semantic_timestamp_set == 0u &&
         (state.stats.last_semantic_timestamp_ns != 0u ||
          state.stats.state_byte_nanoseconds_low != 0u ||
          state.stats.state_byte_nanoseconds_high != 0u)))
        return false;

    uint32_t active_connections = 0u;
    uint32_t connection_paths = 0u;
    for (uint32_t slot = 0u;
         slot < state.config.maximum_logical_connections;
         ++slot) {
        const ConnectionEntry &connection = state.connections[slot];
        if (connection.logical_connection_id == 0u) {
            if (connection.path_head != kInvalidIndex ||
                connection.path_count != 0u || connection.reserved != 0u)
                return false;
            continue;
        }
        DecodedLogicalId decoded{};
        if (!decode_logical_id(
                state, connection.logical_connection_id, decoded) ||
            decoded.slot != slot || connection.path_count == 0u ||
            connection.path_count >
                state.config.maximum_paths_per_connection ||
            connection.reserved != 0u)
            return false;
        active_connections++;
        uint32_t index = connection.path_head;
        uint32_t previous = kInvalidIndex;
        uint32_t traversed = 0u;
        while (index != kInvalidIndex) {
            if (index >= state.config.maximum_paths ||
                ++traversed > state.config.maximum_paths)
                return false;
            const PathEntry &path = state.paths[index];
            if (path.active != 1u ||
                path.logical_connection_id !=
                    connection.logical_connection_id ||
                path.connection_previous != previous)
                return false;
            previous = index;
            index = path.connection_next;
        }
        if (traversed != connection.path_count ||
            connection_paths > UINT32_MAX - traversed)
            return false;
        connection_paths += traversed;
    }

    uint32_t bucket_paths = 0u;
    for (uint32_t bucket = 0u;
         bucket < state.stats.hash_bucket_count;
         ++bucket) {
        uint32_t index = state.buckets[bucket];
        uint32_t previous = kInvalidIndex;
        uint32_t traversed = 0u;
        while (index != kInvalidIndex) {
            if (index >= state.config.maximum_paths ||
                ++traversed > state.config.maximum_hash_chain)
                return false;
            const PathEntry &path = state.paths[index];
            fk_flow_key canonical{};
            DecodedLogicalId decoded{};
            if (path.active != 1u || path.bucket_previous != previous ||
                (static_cast<uint32_t>(path.key_hash) &
                    (state.stats.hash_bucket_count - 1u)) != bucket ||
                !canonical_udp_key(&path.key, canonical) ||
                path.key_hash != key_hash(state, path.key) ||
                !decode_logical_id(
                    state, path.logical_connection_id, decoded) ||
                state.connections[decoded.slot].logical_connection_id !=
                    path.logical_connection_id ||
                path.free_next != kInvalidIndex ||
                path.reserved[0] != 0u || path.reserved[1] != 0u ||
                path.reserved[2] != 0u ||
                (state.stats.semantic_timestamp_set != 0u &&
                 path.last_authenticated_timestamp_ns >
                    state.stats.last_semantic_timestamp_ns))
                return false;
            previous = index;
            index = path.bucket_next;
        }
        if (bucket_paths > UINT32_MAX - traversed)
            return false;
        bucket_paths += traversed;
    }

    uint32_t free_paths = 0u;
    uint32_t free_index = state.free_path_head;
    while (free_index != kInvalidIndex) {
        if (free_index >= state.config.maximum_paths ||
            ++free_paths > state.config.maximum_paths ||
            state.paths[free_index].active != 0u)
            return false;
        free_index = state.paths[free_index].free_next;
    }
    const uint64_t expected_used = state.stats.fixed_bytes +
        static_cast<uint64_t>(active_connections) *
            sizeof(ConnectionEntry) +
        static_cast<uint64_t>(bucket_paths) * sizeof(PathEntry);
    return active_connections == state.stats.active_logical_connections &&
        connection_paths == bucket_paths &&
        bucket_paths == state.stats.active_paths &&
        static_cast<uint64_t>(bucket_paths) + free_paths ==
            state.config.maximum_paths &&
        expected_used == state.stats.used_bytes &&
        state.stats.peak_active_logical_connections >= active_connections &&
        state.stats.peak_active_paths >= bucket_paths;
}

}  // namespace

extern "C" {

void fk_quic_presentation_path_directory_default_config_init(
        fk_quic_presentation_path_directory_config *config) {
    if (config == nullptr)
        return;
    *config = {};
    config->maximum_logical_connections = 4096u;
    config->maximum_paths = 16384u;
    config->maximum_paths_per_connection = 8u;
    config->maximum_hash_chain = 64u;
    config->expiration_scan_per_operation = 64u;
    config->path_ttl_ns = UINT64_C(300) * 1000u * 1000u * 1000u;
    /* Public deterministic Validation/test key, never a live generated key. */
    for (uint8_t index = 0u; index < 16u; ++index)
        config->siphash_key[index] = index;
    config->siphash_key_precommitted = 1u;
}

bool fk_quic_presentation_path_directory_config_valid(
        const fk_quic_presentation_path_directory_config *config) {
    return valid_config(config);
}

size_t fk_quic_presentation_path_directory_storage_bytes(
        const fk_quic_presentation_path_directory_config *config) {
    Layout layout{};
    return compute_layout(config, layout) ? layout.total_bytes : 0u;
}

fk_quic_presentation_path_directory *
fk_quic_presentation_path_directory_initialize(
        void *storage,
        size_t storage_bytes,
        const fk_quic_presentation_path_directory_config *config,
        char *error,
        size_t error_capacity) {
    set_error(error, error_capacity, "");
    Layout layout{};
    if (storage == nullptr || !compute_layout(config, layout) ||
        storage_bytes < layout.total_bytes) {
        set_error(error, error_capacity,
            "invalid presentation-path placement plan");
        return nullptr;
    }
    if (reinterpret_cast<uintptr_t>(storage) % alignof(max_align_t) != 0u) {
        set_error(error, error_capacity,
            "presentation-path storage is not max_align_t aligned");
        return nullptr;
    }
    std::memset(storage, 0, layout.total_bytes);
    auto *state = new (storage) DirectoryImpl{};
    state->config = *config;
    uint8_t *base = static_cast<uint8_t *>(storage);
    state->buckets = reinterpret_cast<uint32_t *>(
        base + layout.bucket_offset);
    state->connections = reinterpret_cast<ConnectionEntry *>(
        base + layout.connection_offset);
    state->paths = reinterpret_cast<PathEntry *>(base + layout.path_offset);
    for (uint32_t index = 0u; index < layout.bucket_count; ++index)
        new (&state->buckets[index]) uint32_t(kInvalidIndex);
    for (uint32_t index = 0u;
         index < config->maximum_logical_connections;
         ++index) {
        new (&state->connections[index]) ConnectionEntry{};
        state->connections[index].path_head = kInvalidIndex;
    }
    for (uint32_t index = 0u; index < config->maximum_paths; ++index) {
        new (&state->paths[index]) PathEntry{};
        state->paths[index].bucket_next = kInvalidIndex;
        state->paths[index].bucket_previous = kInvalidIndex;
        state->paths[index].connection_next = kInvalidIndex;
        state->paths[index].connection_previous = kInvalidIndex;
        state->paths[index].free_next =
            index + 1u < config->maximum_paths ? index + 1u : kInvalidIndex;
    }
    state->free_path_head = 0u;
    state->stats.reserved_bytes = layout.total_bytes;
    const uint64_t variable_bytes =
        static_cast<uint64_t>(config->maximum_logical_connections) *
            sizeof(ConnectionEntry) +
        static_cast<uint64_t>(config->maximum_paths) * sizeof(PathEntry);
    state->stats.fixed_bytes = state->stats.reserved_bytes - variable_bytes;
    state->stats.maximum_logical_connections =
        config->maximum_logical_connections;
    state->stats.maximum_paths = config->maximum_paths;
    state->stats.hash_bucket_count = layout.bucket_count;
    state->stats.maximum_paths_per_connection =
        config->maximum_paths_per_connection;
    state->stats.path_entry_bytes = sizeof(PathEntry);
    state->stats.connection_entry_bytes = sizeof(ConnectionEntry);
    state->stats.siphash_key_precommitted =
        config->siphash_key_precommitted;
    update_used_bytes(*state);
    if (!internal_accounting_conserved(*state)) {
        fk_quic_presentation_path_directory_destroy(
            reinterpret_cast<fk_quic_presentation_path_directory *>(state));
        set_error(error, error_capacity,
            "presentation-path initial accounting failure");
        return nullptr;
    }
    return reinterpret_cast<fk_quic_presentation_path_directory *>(state);
}

void fk_quic_presentation_path_directory_destroy(
        fk_quic_presentation_path_directory *directory) {
    DirectoryImpl *state = implementation(directory);
    if (state == nullptr)
        return;
    for (uint32_t index = 0u; index < state->config.maximum_paths; ++index)
        state->paths[index].~PathEntry();
    for (uint32_t index = 0u;
         index < state->config.maximum_logical_connections;
         ++index)
        state->connections[index].~ConnectionEntry();
    state->~DirectoryImpl();
}

fk_quic_presentation_path_code
fk_quic_presentation_path_directory_classify(
        fk_quic_presentation_path_directory *directory,
        const fk_flow_key *canonical_udp_key_value,
        uint64_t semantic_timestamp_ns,
        fk_quic_presentation_path_classification *classification) {
    reset_classification(classification);
    DirectoryImpl *state = implementation(directory);
    if (state == nullptr || classification == nullptr)
        return FK_QUIC_PRESENTATION_PATH_REJECTED;
    state->stats.classify_calls++;
    fk_flow_key key{};
    if (!canonical_udp_key(canonical_udp_key_value, key))
        return reject_classification(
            *state,
            *classification,
            FK_QUIC_PRESENTATION_PATH_REJECT_INVALID_INPUT);
    fk_quic_presentation_path_reject_reason reason =
        FK_QUIC_PRESENTATION_PATH_REJECT_NONE;
    if (!advance_semantic_time(*state, semantic_timestamp_ns, reason))
        return reject_classification(*state, *classification, reason);
    if (!run_expiration_scan(*state, semantic_timestamp_ns))
        return reject_classification(
            *state,
            *classification,
            FK_QUIC_PRESENTATION_PATH_REJECT_INTERNAL_INTEGRITY);
    const uint64_t hash = key_hash(*state, key);
    const BucketScan scan = scan_bucket(
        *state, key, hash, semantic_timestamp_ns, 0u);
    if (!scan.valid)
        return reject_classification(
            *state,
            *classification,
            FK_QUIC_PRESENTATION_PATH_REJECT_INTERNAL_INTEGRITY);
    const fk_quic_presentation_path_code code =
        classification_for_count(scan.matching);
    return finish_classification(
        *state,
        *classification,
        code,
        FK_QUIC_PRESENTATION_PATH_REJECT_NONE,
        scan.matching,
        false,
        false);
}

fk_quic_presentation_path_code
fk_quic_presentation_path_directory_register_authenticated(
        fk_quic_presentation_path_directory *directory,
        uint64_t logical_connection_id,
        const fk_flow_key *canonical_udp_key_value,
        uint64_t semantic_timestamp_ns,
        fk_quic_presentation_path_classification *classification) {
    reset_classification(classification);
    DirectoryImpl *state = implementation(directory);
    if (state == nullptr || classification == nullptr)
        return FK_QUIC_PRESENTATION_PATH_REJECTED;
    state->stats.authenticated_register_calls++;
    fk_flow_key key{};
    DecodedLogicalId decoded{};
    if (!canonical_udp_key(canonical_udp_key_value, key) ||
        !decode_logical_id(*state, logical_connection_id, decoded))
        return reject_classification(
            *state,
            *classification,
            FK_QUIC_PRESENTATION_PATH_REJECT_INVALID_INPUT);
    fk_quic_presentation_path_reject_reason reason =
        FK_QUIC_PRESENTATION_PATH_REJECT_NONE;
    if (!advance_semantic_time(*state, semantic_timestamp_ns, reason))
        return reject_classification(*state, *classification, reason);
    if (!run_expiration_scan(*state, semantic_timestamp_ns))
        return reject_classification(
            *state,
            *classification,
            FK_QUIC_PRESENTATION_PATH_REJECT_INTERNAL_INTEGRITY);

    ConnectionEntry &connection = state->connections[decoded.slot];
    if (connection.logical_connection_id != 0u &&
        connection.logical_connection_id != logical_connection_id) {
        if (!purge_expired_connection_paths(
                *state, decoded.slot, semantic_timestamp_ns))
            return reject_classification(
                *state,
                *classification,
                FK_QUIC_PRESENTATION_PATH_REJECT_INTERNAL_INTEGRITY);
        if (state->connections[decoded.slot].logical_connection_id != 0u)
            return reject_classification(
                *state,
                *classification,
                FK_QUIC_PRESENTATION_PATH_REJECT_LOGICAL_GENERATION_CONFLICT);
    }

    const uint64_t hash = key_hash(*state, key);
    const BucketScan scan = scan_bucket(
        *state,
        key,
        hash,
        semantic_timestamp_ns,
        logical_connection_id);
    if (!scan.valid)
        return reject_classification(
            *state,
            *classification,
            FK_QUIC_PRESENTATION_PATH_REJECT_INTERNAL_INTEGRITY);
    if (scan.exact_logical_index != kInvalidIndex) {
        state->paths[scan.exact_logical_index].
            last_authenticated_timestamp_ns = semantic_timestamp_ns;
        state->stats.paths_refreshed++;
        return finish_classification(
            *state,
            *classification,
            classification_for_count(scan.matching),
            FK_QUIC_PRESENTATION_PATH_REJECT_NONE,
            scan.matching,
            false,
            true);
    }

    ConnectionEntry &current_connection = state->connections[decoded.slot];
    if (current_connection.path_count >=
        state->config.maximum_paths_per_connection)
        return reject_classification(
            *state,
            *classification,
            FK_QUIC_PRESENTATION_PATH_REJECT_PER_CONNECTION_CAPACITY);
    if (state->stats.active_paths >= state->config.maximum_paths ||
        state->free_path_head == kInvalidIndex)
        return reject_classification(
            *state,
            *classification,
            FK_QUIC_PRESENTATION_PATH_REJECT_GLOBAL_CAPACITY);
    if (scan.chain_length >= state->config.maximum_hash_chain)
        return reject_classification(
            *state,
            *classification,
            FK_QUIC_PRESENTATION_PATH_REJECT_HASH_CHAIN_CAPACITY);
    if (!create_path(
            *state,
            decoded.slot,
            logical_connection_id,
            key,
            hash,
            semantic_timestamp_ns))
        return reject_classification(
            *state,
            *classification,
            FK_QUIC_PRESENTATION_PATH_REJECT_INTERNAL_INTEGRITY);
    return finish_classification(
        *state,
        *classification,
        classification_for_count(scan.matching + 1u),
        FK_QUIC_PRESENTATION_PATH_REJECT_NONE,
        scan.matching + 1u,
        true,
        false);
}

fk_quic_presentation_path_release_result
fk_quic_presentation_path_directory_release_logical_connection(
        fk_quic_presentation_path_directory *directory,
        uint64_t logical_connection_id,
        uint64_t semantic_timestamp_ns,
        uint32_t *released_paths) {
    if (released_paths != nullptr)
        *released_paths = 0u;
    DirectoryImpl *state = implementation(directory);
    if (state == nullptr)
        return FK_QUIC_PRESENTATION_PATH_RELEASE_INVALID;
    state->stats.release_calls++;
    DecodedLogicalId decoded{};
    if (!decode_logical_id(*state, logical_connection_id, decoded)) {
        count_reject(
            *state, FK_QUIC_PRESENTATION_PATH_REJECT_INVALID_INPUT);
        return FK_QUIC_PRESENTATION_PATH_RELEASE_INVALID;
    }
    fk_quic_presentation_path_reject_reason reason =
        FK_QUIC_PRESENTATION_PATH_REJECT_NONE;
    if (!advance_semantic_time(*state, semantic_timestamp_ns, reason)) {
        count_reject(*state, reason);
        return FK_QUIC_PRESENTATION_PATH_RELEASE_REJECTED;
    }
    if (!run_expiration_scan(*state, semantic_timestamp_ns)) {
        count_reject(
            *state, FK_QUIC_PRESENTATION_PATH_REJECT_INTERNAL_INTEGRITY);
        return FK_QUIC_PRESENTATION_PATH_RELEASE_REJECTED;
    }
    ConnectionEntry &connection = state->connections[decoded.slot];
    if (connection.logical_connection_id == 0u)
        return FK_QUIC_PRESENTATION_PATH_RELEASE_NOT_FOUND;
    if (connection.logical_connection_id != logical_connection_id) {
        count_reject(
            *state,
            FK_QUIC_PRESENTATION_PATH_REJECT_LOGICAL_GENERATION_CONFLICT);
        return FK_QUIC_PRESENTATION_PATH_RELEASE_REJECTED;
    }
    uint32_t removed = 0u;
    while (state->connections[decoded.slot].path_head != kInvalidIndex) {
        const uint32_t index = state->connections[decoded.slot].path_head;
        if (!unlink_path(*state, index, RemovalCause::Released)) {
            count_reject(
                *state,
                FK_QUIC_PRESENTATION_PATH_REJECT_INTERNAL_INTEGRITY);
            return FK_QUIC_PRESENTATION_PATH_RELEASE_REJECTED;
        }
        removed++;
    }
    state->stats.logical_connections_released++;
    if (released_paths != nullptr)
        *released_paths = removed;
    return FK_QUIC_PRESENTATION_PATH_RELEASED;
}

bool fk_quic_presentation_path_directory_drain_finite_epoch(
        fk_quic_presentation_path_directory *directory,
        uint64_t terminal_semantic_timestamp_ns,
        fk_quic_presentation_path_finite_epoch_drain_receipt_v1 *receipt) {
    if (receipt != nullptr)
        *receipt = {};
    DirectoryImpl *state = implementation(directory);
    if (state == nullptr || receipt == nullptr ||
        terminal_semantic_timestamp_ns == 0u) {
        return false;
    }
    receipt->abi_version =
        FK_QUIC_PRESENTATION_PATH_FINITE_EPOCH_DRAIN_RECEIPT_ABI_VERSION;
    receipt->terminal_semantic_timestamp_ns =
        terminal_semantic_timestamp_ns;
    receipt->active_logical_connections_before =
        state->stats.active_logical_connections;
    receipt->active_paths_before = state->stats.active_paths;
    if (!internal_accounting_conserved(*state) ||
        (state->stats.semantic_timestamp_set != 0u &&
         terminal_semantic_timestamp_ns <
             state->stats.last_semantic_timestamp_ns)) {
        return false;
    }

    /* Preflight every live path before semantic time or lifecycle state is
     * changed.  A premature terminal watermark therefore cannot partially
     * drain the directory. */
    for (uint32_t index = 0u;
         index < state->config.maximum_paths; ++index) {
        const PathEntry &path = state->paths[index];
        if (path.active == 1u &&
            !path_expired(
                *state, path, terminal_semantic_timestamp_ns)) {
            return false;
        }
    }

    fk_quic_presentation_path_reject_reason reason =
        FK_QUIC_PRESENTATION_PATH_REJECT_NONE;
    if (!advance_semantic_time(
            *state, terminal_semantic_timestamp_ns, reason)) {
        return false;
    }
    const uint64_t expired_before = state->stats.paths_expired;
    for (uint32_t index = 0u;
         index < state->config.maximum_paths; ++index) {
        if (state->paths[index].active == 1u &&
            !unlink_path(*state, index, RemovalCause::Expired)) {
            return false;
        }
    }
    const uint64_t expired_after = state->stats.paths_expired;
    if (expired_after < expired_before ||
        expired_after - expired_before > UINT32_MAX ||
        !internal_accounting_conserved(*state)) {
        return false;
    }
    receipt->paths_drained =
        static_cast<uint32_t>(expired_after - expired_before);
    receipt->active_logical_connections_after =
        state->stats.active_logical_connections;
    receipt->active_paths_after = state->stats.active_paths;
    receipt->complete =
        receipt->active_logical_connections_after == 0u &&
                receipt->active_paths_after == 0u &&
                receipt->paths_drained == receipt->active_paths_before
            ? 1u : 0u;
    if (receipt->complete != 0u) {
        receipt->reason =
            FK_QUIC_PRESENTATION_PATH_FINITE_EPOCH_DRAIN_IDLE_TIMEOUT_AFTER_EOF;
    }
    return receipt->complete != 0u;
}

bool fk_quic_presentation_path_directory_get_stats(
        const fk_quic_presentation_path_directory *directory,
        fk_quic_presentation_path_directory_stats *stats) {
    const DirectoryImpl *state = implementation(directory);
    if (state == nullptr || stats == nullptr)
        return false;
    *stats = state->stats;
    return true;
}

bool fk_quic_presentation_path_directory_accounting_conserved(
        fk_quic_presentation_path_directory *directory) {
    DirectoryImpl *state = implementation(directory);
    if (state == nullptr)
        return false;
    if (internal_accounting_conserved(*state))
        return true;
    state->stats.accounting_failures++;
    return false;
}

}  // extern "C"
