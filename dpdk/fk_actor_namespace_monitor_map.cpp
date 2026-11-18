#include "fk_actor_namespace_monitor_map.h"

#include <cstdio>
#include <cstring>
#include <limits>

namespace {

constexpr uint8_t kMagic[8] = {
    'F', 'K', 'A', 'N', 'M', '0', '1', 0u,
};

static void set_error(
        char *error,
        size_t capacity,
        const char *message) {
    if (error == nullptr || capacity == 0u)
        return;
    std::snprintf(error, capacity, "%s", message);
}

static uint16_t read_u16(const uint8_t *bytes) {
    return static_cast<uint16_t>(bytes[0]) |
        static_cast<uint16_t>(bytes[1]) << 8u;
}

static uint32_t read_u32(const uint8_t *bytes) {
    return static_cast<uint32_t>(bytes[0]) |
        static_cast<uint32_t>(bytes[1]) << 8u |
        static_cast<uint32_t>(bytes[2]) << 16u |
        static_cast<uint32_t>(bytes[3]) << 24u;
}

static uint32_t ipv4_u32(const uint8_t address[4]) {
    return static_cast<uint32_t>(address[0]) << 24u |
        static_cast<uint32_t>(address[1]) << 16u |
        static_cast<uint32_t>(address[2]) << 8u |
        static_cast<uint32_t>(address[3]);
}

static bool all_zero(const uint8_t *bytes, size_t count) {
    uint8_t aggregate = 0u;
    for (size_t index = 0u; index < count; ++index)
        aggregate = static_cast<uint8_t>(aggregate | bytes[index]);
    return aggregate == 0u;
}

}  // namespace

extern "C" {

bool fk_actor_namespace_monitor_map_decode(
        const uint8_t *bytes,
        size_t byte_count,
        fk_actor_namespace_monitor_map_metadata *metadata,
        uint32_t *entries,
        uint32_t entry_capacity,
        char *error,
        size_t error_capacity) {
    if (metadata != nullptr)
        std::memset(metadata, 0, sizeof(*metadata));
    if (entries != nullptr && entry_capacity != 0u) {
        std::memset(
            entries,
            0,
            static_cast<size_t>(entry_capacity) * sizeof(*entries));
    }
    set_error(error, error_capacity, "");
    if (bytes == nullptr || metadata == nullptr ||
        ((entries == nullptr) != (entry_capacity == 0u))) {
        set_error(error, error_capacity, "invalid map decode arguments");
        return false;
    }
    if (byte_count < FK_ACTOR_NAMESPACE_MONITOR_MAP_HEADER_BYTES ||
        byte_count > FK_ACTOR_NAMESPACE_MONITOR_MAP_MAX_FILE_BYTES) {
        set_error(error, error_capacity, "map byte count is outside bounds");
        return false;
    }
    if (std::memcmp(bytes, kMagic, sizeof(kMagic)) != 0 ||
        read_u16(bytes + 8u) != FK_ACTOR_NAMESPACE_MONITOR_MAP_VERSION ||
        read_u16(bytes + 10u) !=
            FK_ACTOR_NAMESPACE_MONITOR_MAP_HEADER_BYTES ||
        read_u16(bytes + 12u) !=
            FK_ACTOR_NAMESPACE_MONITOR_MAP_ENTRY_BYTES ||
        read_u16(bytes + 14u) != 0u) {
        set_error(error, error_capacity, "map fixed header is invalid");
        return false;
    }
    if (!all_zero(bytes + 21u, 3u) || !all_zero(bytes + 36u, 4u) ||
        !all_zero(bytes + 72u, 8u)) {
        set_error(error, error_capacity, "map reserved bytes are nonzero");
        return false;
    }
    const uint8_t prefix = bytes[20u];
    const uint32_t slots = read_u32(bytes + 24u);
    const uint32_t namespaces = read_u32(bytes + 28u);
    const uint32_t entry_count = read_u32(bytes + 32u);
    if (prefix > 32u || slots == 0u || namespaces == 0u ||
        namespaces > FK_ACTOR_NAMESPACE_MONITOR_MAP_MAX_NAMESPACES ||
        entry_count != namespaces ||
        all_zero(
            bytes + 40u,
            FK_ACTOR_NAMESPACE_MONITOR_MAP_SOURCE_SHA256_BYTES)) {
        set_error(error, error_capacity, "map semantic header is invalid");
        return false;
    }
    const uint64_t pool_size = UINT64_C(1) << (32u - prefix);
    const uint64_t base = ipv4_u32(bytes + 16u);
    const uint64_t assigned =
        static_cast<uint64_t>(slots) * namespaces;
    if ((base & (pool_size - 1u)) != 0u || assigned == 0u ||
        assigned > pool_size - 1u) {
        set_error(error, error_capacity, "map namespace pool is invalid");
        return false;
    }
    const uint64_t expected_bytes =
        FK_ACTOR_NAMESPACE_MONITOR_MAP_HEADER_BYTES +
        static_cast<uint64_t>(namespaces) *
            FK_ACTOR_NAMESPACE_MONITOR_MAP_ENTRY_BYTES;
    if (expected_bytes != byte_count ||
        (entries != nullptr && entry_capacity < namespaces)) {
        set_error(error, error_capacity, "map exact size/capacity mismatch");
        return false;
    }
    for (uint32_t index = 0u; index < namespaces; ++index) {
        const uint32_t identity = read_u32(
            bytes + FK_ACTOR_NAMESPACE_MONITOR_MAP_HEADER_BYTES +
            static_cast<size_t>(index) *
                FK_ACTOR_NAMESPACE_MONITOR_MAP_ENTRY_BYTES);
        if (identity == 0u || identity > slots) {
            set_error(error, error_capacity, "map identity index is invalid");
            if (entries != nullptr) {
                std::memset(
                    entries,
                    0,
                    static_cast<size_t>(entry_capacity) * sizeof(*entries));
            }
            return false;
        }
        if (entries != nullptr)
            entries[index] = identity;
    }
    std::memcpy(metadata->pool_base, bytes + 16u, 4u);
    metadata->pool_prefix_length = prefix;
    metadata->slots_per_namespace = slots;
    metadata->namespace_count = namespaces;
    std::memcpy(
        metadata->source_mapping_sha256,
        bytes + 40u,
        FK_ACTOR_NAMESPACE_MONITOR_MAP_SOURCE_SHA256_BYTES);
    return true;
}

}  // extern "C"
