#include "fk_actor_session.h"
#include "fk_quic_logical_id.h"

#include <arpa/inet.h>

#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <limits>
#include <new>

namespace {

constexpr uint32_t kNone = std::numeric_limits<uint32_t>::max();
constexpr uint64_t kMagic = 0x464b4143544f5231ull;  // "FKACTOR1"
constexpr uint32_t kLogicalIdentityTag = uint32_t{1u} << 31u;
constexpr uint32_t kEventSlotMask = kLogicalIdentityTag - 1u;

static_assert(
    FK_ACTOR_SESSION_MAX_EVENTS <= kEventSlotMask,
    "the internal logical-flow tag must not overlap an event slot");

using AssociationKey = fk_actor_event_identity;

static_assert(
    sizeof(AssociationKey) == 36u,
    "actor event identity ABI must remain exactly 36 bytes");
static_assert(
    offsetof(AssociationKey, key_kind) == 0u &&
    offsetof(AssociationKey, ip_version) == 1u &&
    offsetof(AssociationKey, reserved) == 2u &&
    offsetof(AssociationKey, low) == 4u &&
    offsetof(AssociationKey, high) == 20u,
    "actor event identity must remain byte-isomorphic to AssociationKey");
static_assert(
    sizeof(fk_actor_session_result) == 32u &&
    offsetof(fk_actor_session_result, event_id) == 0u &&
    offsetof(fk_actor_session_result, event_slot) == 8u &&
    offsetof(fk_actor_session_result, event_generation) == 12u &&
    offsetof(fk_actor_session_result, key_kind) == 16u &&
    offsetof(fk_actor_session_result, reason) == 20u &&
    offsetof(fk_actor_session_result, created) == 24u,
    "actor event handle/result ABI must remain unchanged");

struct EventEntry {
    AssociationKey key;
    uint64_t event_id;
    uint64_t start_ns;
    uint64_t last_ns;
    uint64_t expiry_ns;
    uint32_t generation;
    uint32_t flow_count;
    uint32_t flow_head;
    uint32_t next_key;
    uint32_t next_free;
    uint32_t heap_position;
    uint8_t active;
};

union FlowIdentityKey {
    fk_actor_flow_identity presentation;
    struct {
        uint64_t logical_connection_id;
        uint64_t reserved;
    } logical;
    uint8_t bytes[16];
};

struct FlowEntry {
    FlowIdentityKey identity;
    /* Bit 31 tags the identity union's logical-ID arm.  Public event handles
     * always receive the untagged low bits.  kNone remains the free marker. */
    uint32_t tagged_event_slot;
    uint32_t next_bucket;
    uint32_t next_event;
    uint32_t next_free;
};

static_assert(
    sizeof(fk_actor_flow_identity) == 16u,
    "actor flow identity ABI must remain exactly 16 bytes");
static_assert(
    sizeof(fk_actor_flow_identity_v2) == 24u,
    "actor v2 flow identity ABI must remain exactly 24 bytes");
static_assert(
    offsetof(fk_actor_flow_identity_v2, presentation) == 0u &&
    offsetof(fk_actor_flow_identity_v2, logical_connection_id) == 16u,
    "actor v2 flow identity must preserve the v1 prefix");
static_assert(
    sizeof(FlowIdentityKey) == 16u,
    "internal sticky-flow identity must remain exactly 16 bytes");
static_assert(
    sizeof(FlowEntry) == 32u,
    "v2 must not expand the legacy sticky actor flow entry");

struct State {
    uint64_t magic;
    fk_actor_session_config config;
    fk_actor_session_stats stats;
    EventEntry *events;
    FlowEntry *flows;
    uint32_t *event_buckets;
    uint32_t event_bucket_count;
    uint32_t event_bucket_mask;
    uint32_t *flow_buckets;
    uint32_t flow_bucket_count;
    uint32_t flow_bucket_mask;
    uint32_t *expiry_heap;
    uint32_t heap_count;
    uint32_t event_free_head;
    uint32_t flow_free_head;
    uint32_t total_flow_capacity;
    size_t reserved_bytes;
    size_t fixed_bytes;
    uint64_t next_event_id;
    uint64_t last_observation_ns;
    uint8_t has_observation;
};

static State *implementation(fk_actor_session *sessions) {
    return reinterpret_cast<State *>(sessions);
}

static const State *implementation(const fk_actor_session *sessions) {
    return reinterpret_cast<const State *>(sessions);
}

static void set_error(
        char *error,
        size_t capacity,
        const char *message) {
    if (error == nullptr || capacity == 0u)
        return;
    std::snprintf(error, capacity, "%s", message);
}

static bool valid_ip_version(uint8_t version) {
    return version == 4u || version == 6u;
}

static uint32_t address_bytes(uint8_t version) {
    return version == 4u ? 4u : 16u;
}

static bool valid_cidr(const fk_actor_session_cidr &cidr) {
    return valid_ip_version(cidr.ip_version) &&
        cidr.prefix_length <= (cidr.ip_version == 4u ? 32u : 128u);
}

static void clear_host_bits(fk_actor_session_cidr &cidr) {
    const uint32_t bytes = address_bytes(cidr.ip_version);
    const uint32_t whole_bytes = cidr.prefix_length / 8u;
    const uint32_t remaining_bits = cidr.prefix_length % 8u;
    uint32_t first_host_byte = whole_bytes;
    if (remaining_bits != 0u && whole_bytes < bytes) {
        cidr.address[whole_bytes] &= static_cast<uint8_t>(
            0xffu << (8u - remaining_bits));
        first_host_byte++;
    }
    for (uint32_t index = first_host_byte; index < bytes; ++index)
        cidr.address[index] = 0u;
}

static uint32_t ipv4_u32(const uint8_t address[4]) {
    return (static_cast<uint32_t>(address[0]) << 24u) |
        (static_cast<uint32_t>(address[1]) << 16u) |
        (static_cast<uint32_t>(address[2]) << 8u) |
        static_cast<uint32_t>(address[3]);
}

static bool prefix_matches(
    const uint8_t *address,
    const fk_actor_session_cidr &cidr);

static bool compact_ipv4_monitor_disabled_clean(
        const fk_actor_session_compact_ipv4_monitor &contract) {
    return contract.enabled == 0u &&
        contract.pool_prefix_length == 0u &&
        contract.pool_base[0] == 0u &&
        contract.pool_base[1] == 0u &&
        contract.pool_base[2] == 0u &&
        contract.pool_base[3] == 0u &&
        contract.reserved == 0u &&
        contract.slots_per_namespace == 0u &&
        contract.namespace_count == 0u &&
        contract.monitored_identity_index == 0u &&
        contract.monitored_identity_indices == nullptr &&
        contract.monitored_identity_index_count == 0u &&
        contract.reserved_v2 == 0u;
}

static bool compact_ipv4_monitor_valid(
        const fk_actor_session_compact_ipv4_monitor &contract) {
    if (contract.enabled != 1u || contract.pool_prefix_length > 32u ||
        contract.reserved != 0u || contract.slots_per_namespace == 0u ||
        contract.namespace_count == 0u || contract.reserved_v2 != 0u) {
        return false;
    }
    const bool fixed_mode =
        contract.monitored_identity_index != 0u &&
        contract.monitored_identity_indices == nullptr &&
        contract.monitored_identity_index_count == 0u;
    const bool map_mode =
        contract.monitored_identity_index == 0u &&
        contract.monitored_identity_indices != nullptr &&
        contract.monitored_identity_index_count == contract.namespace_count;
    if (fixed_mode == map_mode)
        return false;
    if (fixed_mode &&
        contract.monitored_identity_index > contract.slots_per_namespace) {
        return false;
    }
    if (map_mode) {
        for (uint32_t index = 0u;
             index < contract.monitored_identity_index_count; ++index) {
            const uint32_t identity =
                contract.monitored_identity_indices[index];
            if (identity == 0u ||
                identity > contract.slots_per_namespace) {
                return false;
            }
        }
    }
    const uint64_t pool_size = UINT64_C(1) <<
        (32u - contract.pool_prefix_length);
    const uint64_t base = ipv4_u32(contract.pool_base);
    if ((base & (pool_size - 1u)) != 0u)
        return false;
    const uint64_t assigned =
        static_cast<uint64_t>(contract.namespace_count) *
        contract.slots_per_namespace;
    /* Offset zero is deliberately unused by the compact replay formula. */
    return assigned != 0u && assigned <= pool_size - 1u;
}

static bool compact_ipv4_monitor_overlaps_cidr(
        const fk_actor_session_compact_ipv4_monitor &contract,
        const fk_actor_session_cidr &cidr) {
    if (cidr.ip_version != 4u)
        return false;
    fk_actor_session_cidr pool{};
    pool.ip_version = 4u;
    pool.prefix_length = contract.pool_prefix_length;
    std::memcpy(pool.address, contract.pool_base, 4u);
    return prefix_matches(contract.pool_base, cidr) ||
        prefix_matches(cidr.address, pool);
}

static bool valid_flow_key(const fk_flow_key &key) {
    if (!valid_ip_version(key.ip_version))
        return false;
    if (key.ip_version == 4u) {
        for (uint32_t index = 4u; index < 16u; ++index) {
            if (key.low_addr[index] != 0u ||
                key.high_addr[index] != 0u)
                return false;
        }
    }
    return true;
}

static uint64_t saturating_add(uint64_t left, uint64_t right) {
    return left > std::numeric_limits<uint64_t>::max() - right
        ? std::numeric_limits<uint64_t>::max()
        : left + right;
}

static bool next_event_generation(
        uint32_t current_generation,
        uint32_t &next_generation) {
    next_generation = 0u;
    if (current_generation == std::numeric_limits<uint32_t>::max())
        return false;
    next_generation = current_generation + 1u;
    return next_generation != 0u;
}

static bool checked_add(size_t &value, size_t increment) {
    if (value > std::numeric_limits<size_t>::max() - increment)
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
        size_t element_bytes,
        size_t alignment) {
    size_t bytes = 0u;
    return align_offset(offset, alignment) &&
        checked_multiply(count, element_bytes, bytes) &&
        checked_add(offset, bytes);
}

static bool next_power_of_two(uint64_t value, uint32_t &result) {
    if (value == 0u ||
        value > static_cast<uint64_t>(
            std::numeric_limits<uint32_t>::max()))
        return false;
    uint64_t power = 1u;
    while (power < value)
        power <<= 1u;
    if (power > static_cast<uint64_t>(
            std::numeric_limits<uint32_t>::max()))
        return false;
    result = static_cast<uint32_t>(power);
    return true;
}

static bool storage_layout(
        const fk_actor_session_config &config,
        size_t &bytes,
        uint32_t &flow_capacity,
        uint32_t &flow_bucket_count,
        uint32_t &event_bucket_count) {
    const uint64_t flow_capacity64 = config.maximum_total_flows;
    if (flow_capacity64 == 0u ||
        flow_capacity64 > std::numeric_limits<uint32_t>::max() ||
        !next_power_of_two(flow_capacity64 * 2u, flow_bucket_count) ||
        !next_power_of_two(
            static_cast<uint64_t>(config.maximum_events) * 2u,
            event_bucket_count))
        return false;
    flow_capacity = static_cast<uint32_t>(flow_capacity64);
    size_t offset = alignof(std::max_align_t) - 1u;
    if (!add_region(offset, 1u, sizeof(State), alignof(State)) ||
        !add_region(
            offset,
            config.maximum_events,
            sizeof(EventEntry),
            alignof(EventEntry)) ||
        !add_region(
            offset,
            flow_capacity,
            sizeof(FlowEntry),
            alignof(FlowEntry)) ||
        !add_region(
            offset,
            event_bucket_count,
            sizeof(uint32_t),
            alignof(uint32_t)) ||
        !add_region(
            offset,
            flow_bucket_count,
            sizeof(uint32_t),
            alignof(uint32_t)) ||
        !add_region(
            offset,
            config.maximum_events,
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
static T *take_region(
        uintptr_t &cursor,
        uintptr_t end,
        size_t count) {
    cursor = align_pointer(cursor, alignof(T));
    size_t bytes = 0u;
    if (!checked_multiply(count, sizeof(T), bytes) ||
        cursor > end ||
        bytes > end - cursor)
        return nullptr;
    T *result = reinterpret_cast<T *>(cursor);
    cursor += bytes;
    return result;
}

static uint64_t hash_bytes(
        const uint8_t *data, size_t bytes, uint64_t hash) {
    for (size_t index = 0u; index < bytes; ++index) {
        hash ^= data[index];
        hash *= 1099511628211ull;
    }
    return hash;
}

static uint64_t association_hash(const AssociationKey &key) {
    return hash_bytes(
        reinterpret_cast<const uint8_t *>(&key),
        sizeof(key),
        1469598103934665603ull);
}

static bool association_equal(
        const AssociationKey &left,
        const AssociationKey &right) {
    return std::memcmp(&left, &right, sizeof(left)) == 0;
}

static uint64_t presentation_identity_hash(
        const fk_actor_flow_identity &identity) {
    constexpr uint64_t kOffset = 1469598103934665603ull;
    /* Preserve the complete v1 hash domain byte-for-byte. */
    return hash_bytes(
        reinterpret_cast<const uint8_t *>(&identity),
        sizeof(identity),
        kOffset);
}

static uint64_t logical_identity_hash(uint64_t logical_connection_id) {
    constexpr uint64_t kOffset = 1469598103934665603ull;
    /* Domain-separated, endian-explicit QUIC logical identity. */
    const uint8_t domain = static_cast<uint8_t>('Q');
    uint64_t hash = hash_bytes(&domain, 1u, kOffset);
    uint8_t encoded[sizeof(logical_connection_id)]{};
    for (uint32_t index = 0u; index < sizeof(encoded); ++index) {
        encoded[index] = static_cast<uint8_t>(
            logical_connection_id >> (index * 8u));
    }
    return hash_bytes(encoded, sizeof(encoded), hash);
}

static uint64_t flow_identity_hash(
        const fk_actor_flow_identity_v2 &identity) {
    return identity.logical_connection_id == 0u
        ? presentation_identity_hash(identity.presentation)
        : logical_identity_hash(identity.logical_connection_id);
}

static bool flow_has_logical_identity(const FlowEntry &entry) {
    return entry.tagged_event_slot != kNone &&
        (entry.tagged_event_slot & kLogicalIdentityTag) != 0u;
}

static uint32_t flow_event_slot(const FlowEntry &entry) {
    return entry.tagged_event_slot == kNone
        ? kNone
        : entry.tagged_event_slot & kEventSlotMask;
}

static uint64_t stored_flow_identity_hash(const FlowEntry &entry) {
    return flow_has_logical_identity(entry)
        ? logical_identity_hash(
            entry.identity.logical.logical_connection_id)
        : presentation_identity_hash(entry.identity.presentation);
}

static bool flow_identity_equal(
        const FlowEntry &entry,
        const fk_actor_flow_identity_v2 &identity) {
    if (entry.tagged_event_slot == kNone)
        return false;
    const bool input_is_logical =
        identity.logical_connection_id != 0u;
    if (flow_has_logical_identity(entry) != input_is_logical)
        return false;
    if (input_is_logical) {
        return entry.identity.logical.logical_connection_id ==
            identity.logical_connection_id;
    }
    return entry.identity.presentation.first_timestamp_ns ==
            identity.presentation.first_timestamp_ns &&
        entry.identity.presentation.generation ==
            identity.presentation.generation &&
        entry.identity.presentation.packed_location ==
            identity.presentation.packed_location;
}

static bool valid_flow_identity(
        const State &state,
        const fk_actor_flow_identity_v2 &identity,
        const uint64_t *observation_timestamp_ns) {
    if (identity.presentation.generation == 0u ||
        (observation_timestamp_ns != nullptr &&
         *observation_timestamp_ns <
            identity.presentation.first_timestamp_ns)) {
        return false;
    }
    if (identity.logical_connection_id == 0u)
        return true;
    /* Only CID-authenticated QUIC/UDP observations may select the logical
     * identity domain.  This prevents a mislabeled TCP/TLS flow from gaining
     * cross-five-tuple stickiness. */
    if (state.config.maximum_logical_connection_slots == 0u)
        return false;
    uint32_t connection_slot = 0u;
    uint32_t connection_generation = 0u;
    return fk_quic_logical_id_decode(
            identity.logical_connection_id,
            state.config.maximum_logical_connection_slots,
            &connection_slot,
            &connection_generation);
}

static bool prefix_matches(
        const uint8_t *address,
        const fk_actor_session_cidr &cidr) {
    const uint32_t whole_bytes = cidr.prefix_length / 8u;
    const uint32_t remaining_bits = cidr.prefix_length % 8u;
    if (whole_bytes != 0u &&
        std::memcmp(address, cidr.address, whole_bytes) != 0)
        return false;
    if (remaining_bits == 0u)
        return true;
    const uint8_t mask = static_cast<uint8_t>(
        0xffu << (8u - remaining_bits));
    return
        (address[whole_bytes] & mask) ==
        (cidr.address[whole_bytes] & mask);
}

static bool monitored(
        const State &state,
        uint8_t ip_version,
        const uint8_t *address) {
    const fk_actor_session_compact_ipv4_monitor &compact =
        state.config.compact_ipv4_monitor;
    if (compact.enabled != 0u && ip_version == 4u) {
        const uint64_t value = ipv4_u32(address);
        const uint64_t base = ipv4_u32(compact.pool_base);
        const uint64_t pool_size = UINT64_C(1) <<
            (32u - compact.pool_prefix_length);
        if (value >= base && value - base < pool_size) {
            const uint64_t relative = value - base;
            const uint64_t assigned =
                static_cast<uint64_t>(compact.namespace_count) *
                compact.slots_per_namespace;
            if (relative == 0u || relative > assigned)
                return false;
            const uint32_t namespace_index = static_cast<uint32_t>(
                (relative - 1u) / compact.slots_per_namespace);
            const uint32_t identity_index = static_cast<uint32_t>(
                (relative - 1u) % compact.slots_per_namespace + 1u);
            const uint32_t monitored_identity_index =
                compact.monitored_identity_indices == nullptr
                ? compact.monitored_identity_index
                : compact.monitored_identity_indices[namespace_index];
            return identity_index == monitored_identity_index;
        }
    }
    for (uint32_t index = 0u;
         index < state.config.cidr_count; ++index) {
        const fk_actor_session_cidr &cidr =
            state.config.cidrs[index];
        if (cidr.ip_version == ip_version &&
            prefix_matches(address, cidr))
            return true;
    }
    return false;
}

static fk_actor_session_reason resolve_association(
        const State &state,
        const fk_flow_key &flow,
        AssociationKey &key) {
    std::memset(&key, 0, sizeof(key));
    key.ip_version = flow.ip_version;
    const uint32_t bytes = address_bytes(flow.ip_version);
    const bool low_monitored =
        monitored(state, flow.ip_version, flow.low_addr);
    const bool high_monitored =
        monitored(state, flow.ip_version, flow.high_addr);
    const bool same_address =
        std::memcmp(flow.low_addr, flow.high_addr, bytes) == 0;
    if ((low_monitored != high_monitored) ||
        (low_monitored && high_monitored && same_address)) {
        key.key_kind = FK_ACTOR_SESSION_MONITORED_ACTOR;
        std::memcpy(
            key.low,
            low_monitored ? flow.low_addr : flow.high_addr,
            bytes);
        return FK_ACTOR_REASON_NEW_MONITORED_ACTOR;
    }
    key.key_kind = FK_ACTOR_SESSION_ENDPOINT_PAIR;
    std::memcpy(key.low, flow.low_addr, bytes);
    std::memcpy(key.high, flow.high_addr, bytes);
    return low_monitored && high_monitored
        ? FK_ACTOR_REASON_NEW_PAIR_AMBIGUOUS_MONITORED_ACTOR
        : FK_ACTOR_REASON_NEW_PAIR_NO_MONITORED_ACTOR;
}

static uint64_t event_expiry(
        const State &state, const EventEntry &event) {
    const uint64_t idle =
        saturating_add(event.last_ns, state.config.idle_timeout_ns);
    const uint64_t lifetime =
        saturating_add(
            event.start_ns, state.config.maximum_lifetime_ns);
    return idle < lifetime ? idle : lifetime;
}

static bool heap_less(
        const State &state, uint32_t left_slot, uint32_t right_slot) {
    const EventEntry &left = state.events[left_slot];
    const EventEntry &right = state.events[right_slot];
    return left.expiry_ns < right.expiry_ns ||
        (left.expiry_ns == right.expiry_ns &&
         left.event_id < right.event_id);
}

static void heap_swap(State &state, uint32_t left, uint32_t right) {
    const uint32_t temporary = state.expiry_heap[left];
    state.expiry_heap[left] = state.expiry_heap[right];
    state.expiry_heap[right] = temporary;
    state.events[state.expiry_heap[left]].heap_position = left;
    state.events[state.expiry_heap[right]].heap_position = right;
}

static void heap_sift_up(State &state, uint32_t position) {
    while (position != 0u) {
        const uint32_t parent = (position - 1u) / 2u;
        if (!heap_less(
                state,
                state.expiry_heap[position],
                state.expiry_heap[parent]))
            break;
        heap_swap(state, position, parent);
        position = parent;
    }
}

static void heap_sift_down(State &state, uint32_t position) {
    for (;;) {
        const uint32_t left = position * 2u + 1u;
        if (left >= state.heap_count)
            break;
        const uint32_t right = left + 1u;
        uint32_t smallest = left;
        if (right < state.heap_count &&
            heap_less(
                state,
                state.expiry_heap[right],
                state.expiry_heap[left]))
            smallest = right;
        if (!heap_less(
                state,
                state.expiry_heap[smallest],
                state.expiry_heap[position]))
            break;
        heap_swap(state, position, smallest);
        position = smallest;
    }
}

static void heap_insert(State &state, uint32_t event_slot) {
    const uint32_t position = state.heap_count++;
    state.expiry_heap[position] = event_slot;
    state.events[event_slot].heap_position = position;
    heap_sift_up(state, position);
}

static void heap_update(State &state, uint32_t event_slot) {
    EventEntry &event = state.events[event_slot];
    const uint64_t previous = event.expiry_ns;
    event.expiry_ns = event_expiry(state, event);
    const uint32_t position = event.heap_position;
    if (event.expiry_ns < previous)
        heap_sift_up(state, position);
    else
        heap_sift_down(state, position);
}

static void heap_remove(State &state, uint32_t event_slot) {
    EventEntry &event = state.events[event_slot];
    const uint32_t position = event.heap_position;
    const uint32_t last = --state.heap_count;
    if (position != last) {
        const uint32_t moved_slot = state.expiry_heap[last];
        state.expiry_heap[position] = moved_slot;
        state.events[moved_slot].heap_position = position;
        heap_sift_up(state, position);
        heap_sift_down(
            state,
            state.events[moved_slot].heap_position);
    }
    event.heap_position = kNone;
}

static void remove_event_bucket(State &state, uint32_t event_slot) {
    const uint32_t bucket = static_cast<uint32_t>(
        association_hash(state.events[event_slot].key)) &
        state.event_bucket_mask;
    uint32_t current = state.event_buckets[bucket];
    uint32_t previous = kNone;
    while (current != kNone) {
        if (current == event_slot) {
            if (previous == kNone)
                state.event_buckets[bucket] =
                    state.events[current].next_key;
            else
                state.events[previous].next_key =
                    state.events[current].next_key;
            return;
        }
        previous = current;
        current = state.events[current].next_key;
    }
}

static void remove_flow_bucket(State &state, uint32_t flow_slot) {
    const FlowEntry &flow = state.flows[flow_slot];
    const uint32_t bucket = static_cast<uint32_t>(
        stored_flow_identity_hash(flow)) &
        state.flow_bucket_mask;
    uint32_t current = state.flow_buckets[bucket];
    uint32_t previous = kNone;
    while (current != kNone) {
        if (current == flow_slot) {
            if (previous == kNone)
                state.flow_buckets[bucket] =
                    state.flows[current].next_bucket;
            else
                state.flows[previous].next_bucket =
                    state.flows[current].next_bucket;
            return;
        }
        previous = current;
        current = state.flows[current].next_bucket;
    }
}

enum class RetirementReason {
    Idle,
    Lifetime,
    EventCapacity,
    TotalFlowCapacity,
};

static void update_memory_usage(State &state) {
    const uint64_t event_bytes =
        static_cast<uint64_t>(state.stats.active_events) *
        (sizeof(EventEntry) + sizeof(uint32_t));
    const uint64_t flow_bytes =
        static_cast<uint64_t>(state.stats.active_flows) *
        sizeof(FlowEntry);
    state.stats.used_bytes =
        static_cast<uint64_t>(state.fixed_bytes) +
        event_bytes +
        flow_bytes;
    if (state.stats.used_bytes > state.stats.peak_used_bytes)
        state.stats.peak_used_bytes = state.stats.used_bytes;
}

static void quarantine_event_slot(State &state, uint32_t event_slot) {
    EventEntry &event = state.events[event_slot];
    event.active = 0u;
    event.flow_count = 0u;
    event.flow_head = kNone;
    event.next_key = kNone;
    event.next_free = kNone;
    event.heap_position = kNone;
    state.stats.event_generation_exhaustions++;
    state.stats.quarantined_event_slots++;
}

static void retire_event(
        State &state,
        uint32_t event_slot,
        RetirementReason reason) {
    EventEntry &event = state.events[event_slot];
    if (event.active == 0u)
        return;
    heap_remove(state, event_slot);
    remove_event_bucket(state, event_slot);
    uint32_t flow_slot = event.flow_head;
    while (flow_slot != kNone) {
        FlowEntry &flow = state.flows[flow_slot];
        const uint32_t next = flow.next_event;
        remove_flow_bucket(state, flow_slot);
        std::memset(&flow, 0, sizeof(flow));
        flow.tagged_event_slot = kNone;
        flow.next_free = state.flow_free_head;
        state.flow_free_head = flow_slot;
        state.stats.active_flows--;
        flow_slot = next;
    }
    event.active = 0u;
    event.flow_count = 0u;
    event.flow_head = kNone;
    event.next_key = kNone;
    if (event.generation == std::numeric_limits<uint32_t>::max()) {
        quarantine_event_slot(state, event_slot);
    } else {
        event.next_free = state.event_free_head;
        state.event_free_head = event_slot;
    }
    state.stats.active_events--;
    if (reason == RetirementReason::Idle)
        state.stats.idle_expirations++;
    else if (reason == RetirementReason::Lifetime)
        state.stats.lifetime_expirations++;
    else if (reason == RetirementReason::EventCapacity)
        state.stats.event_capacity_evictions++;
    else
        state.stats.total_flow_capacity_evictions++;
    update_memory_usage(state);
}

static void expire_before(State &state, uint64_t observation_ns) {
    while (state.heap_count != 0u) {
        const uint32_t event_slot = state.expiry_heap[0];
        const EventEntry &event = state.events[event_slot];
        if (event.expiry_ns >= observation_ns)
            break;
        const uint64_t idle =
            saturating_add(
                event.last_ns, state.config.idle_timeout_ns);
        const uint64_t lifetime =
            saturating_add(
                event.start_ns,
                state.config.maximum_lifetime_ns);
        retire_event(
            state,
            event_slot,
            lifetime <= idle
                ? RetirementReason::Lifetime
                : RetirementReason::Idle);
    }
}

static uint32_t find_flow(
        const State &state,
        const fk_actor_flow_identity_v2 &identity) {
    const uint32_t bucket = static_cast<uint32_t>(
        flow_identity_hash(identity)) &
        state.flow_bucket_mask;
    uint32_t current = state.flow_buckets[bucket];
    while (current != kNone) {
        if (flow_identity_equal(state.flows[current], identity))
            return current;
        current = state.flows[current].next_bucket;
    }
    return kNone;
}

static uint32_t find_accepting_event(
        const State &state,
        const AssociationKey &key,
        bool &full_match) {
    full_match = false;
    const uint32_t bucket = static_cast<uint32_t>(
        association_hash(key)) & state.event_bucket_mask;
    uint32_t current = state.event_buckets[bucket];
    while (current != kNone) {
        const EventEntry &event = state.events[current];
        if (event.active != 0u &&
            association_equal(event.key, key)) {
            if (event.flow_count <
                state.config.maximum_flows_per_event)
                return current;
            full_match = true;
        }
        current = event.next_key;
    }
    return kNone;
}

static uint32_t oldest_event_slot(const State &state) {
    uint32_t oldest_slot = kNone;
    for (uint32_t slot = 0u;
         slot < state.config.maximum_events; ++slot) {
        const EventEntry &candidate = state.events[slot];
        if (candidate.active == 0u)
            continue;
        if (oldest_slot == kNone) {
            oldest_slot = slot;
            continue;
        }
        const EventEntry &oldest = state.events[oldest_slot];
        if (candidate.last_ns < oldest.last_ns ||
            (candidate.last_ns == oldest.last_ns &&
             (candidate.start_ns < oldest.start_ns ||
              (candidate.start_ns == oldest.start_ns &&
               candidate.event_id < oldest.event_id))))
            oldest_slot = slot;
    }
    return oldest_slot;
}

static uint32_t oldest_reusable_event_slot(const State &state) {
    uint32_t oldest_slot = kNone;
    for (uint32_t slot = 0u;
         slot < state.config.maximum_events; ++slot) {
        const EventEntry &candidate = state.events[slot];
        if (candidate.active == 0u ||
            candidate.generation ==
                std::numeric_limits<uint32_t>::max())
            continue;
        if (oldest_slot == kNone) {
            oldest_slot = slot;
            continue;
        }
        const EventEntry &oldest = state.events[oldest_slot];
        if (candidate.last_ns < oldest.last_ns ||
            (candidate.last_ns == oldest.last_ns &&
             (candidate.start_ns < oldest.start_ns ||
              (candidate.start_ns == oldest.start_ns &&
               candidate.event_id < oldest.event_id))))
            oldest_slot = slot;
    }
    return oldest_slot;
}

static uint32_t take_reusable_event_slot(State &state) {
    while (state.event_free_head != kNone) {
        const uint32_t event_slot = state.event_free_head;
        EventEntry &event = state.events[event_slot];
        state.event_free_head = event.next_free;
        event.next_free = kNone;
        if (event.generation ==
                std::numeric_limits<uint32_t>::max()) {
            quarantine_event_slot(state, event_slot);
            continue;
        }
        return event_slot;
    }
    return kNone;
}

static uint32_t create_event(
        State &state,
        const AssociationKey &key,
        uint64_t observation_ns) {
    uint32_t event_slot = take_reusable_event_slot(state);
    while (event_slot == kNone) {
        const uint32_t oldest_slot = oldest_reusable_event_slot(state);
        if (oldest_slot == kNone)
            return kNone;
        retire_event(
            state,
            oldest_slot,
            RetirementReason::EventCapacity);
        event_slot = take_reusable_event_slot(state);
    }
    EventEntry &event = state.events[event_slot];
    uint32_t generation = 0u;
    if (!next_event_generation(event.generation, generation)) {
        quarantine_event_slot(state, event_slot);
        return kNone;
    }
    std::memset(&event, 0, sizeof(event));
    event.key = key;
    event.event_id = state.next_event_id++;
    if (state.next_event_id == 0u)
        state.next_event_id = 1u;
    event.start_ns = observation_ns;
    event.last_ns = observation_ns;
    event.generation = generation;
    event.flow_head = kNone;
    event.next_key = kNone;
    event.next_free = kNone;
    event.heap_position = kNone;
    event.active = 1u;
    event.expiry_ns = event_expiry(state, event);
    const uint32_t bucket = static_cast<uint32_t>(
        association_hash(key)) & state.event_bucket_mask;
    event.next_key = state.event_buckets[bucket];
    state.event_buckets[bucket] = event_slot;
    heap_insert(state, event_slot);
    state.stats.events_created++;
    state.stats.active_events++;
    if (state.stats.active_events > state.stats.peak_active_events)
        state.stats.peak_active_events = state.stats.active_events;
    update_memory_usage(state);
    return event_slot;
}

static bool bind_flow(
        State &state,
        uint32_t event_slot,
        const fk_actor_flow_identity_v2 &identity) {
    if (state.flow_free_head == kNone)
        return false;
    const uint32_t flow_slot = state.flow_free_head;
    FlowEntry &flow = state.flows[flow_slot];
    state.flow_free_head = flow.next_free;
    std::memset(&flow, 0, sizeof(flow));
    const bool logical = identity.logical_connection_id != 0u;
    if (logical) {
        flow.identity.logical.logical_connection_id =
            identity.logical_connection_id;
        flow.identity.logical.reserved = 0u;
    } else {
        flow.identity.presentation = identity.presentation;
    }
    flow.tagged_event_slot = event_slot |
        (logical ? kLogicalIdentityTag : 0u);
    const uint32_t bucket = static_cast<uint32_t>(
        flow_identity_hash(identity)) &
        state.flow_bucket_mask;
    flow.next_bucket = state.flow_buckets[bucket];
    state.flow_buckets[bucket] = flow_slot;
    EventEntry &event = state.events[event_slot];
    flow.next_event = event.flow_head;
    event.flow_head = flow_slot;
    event.flow_count++;
    state.stats.active_flows++;
    if (state.stats.active_flows > state.stats.peak_active_flows)
        state.stats.peak_active_flows = state.stats.active_flows;
    update_memory_usage(state);
    return true;
}

static void update_event(
        State &state,
        uint32_t event_slot,
        uint64_t observation_ns) {
    EventEntry &event = state.events[event_slot];
    event.last_ns = observation_ns;
    heap_update(state, event_slot);
}

static void record_reason(
        State &state, fk_actor_session_reason reason) {
    if (reason >= 0 && reason < FK_ACTOR_REASON_COUNT)
        state.stats.reason_counts[reason]++;
}

static void fill_result(
        const State &state,
        uint32_t event_slot,
        fk_actor_session_key_kind key_kind,
        fk_actor_session_reason reason,
        bool created,
        fk_actor_session_result &result) {
    const EventEntry &event = state.events[event_slot];
    result.event_id = event.event_id;
    result.event_slot = event_slot;
    result.event_generation = event.generation;
    result.key_kind = key_kind;
    result.reason = reason;
    result.created = created;
}

}  // namespace

extern "C" {

bool fk_actor_flow_identity_init(
        fk_actor_flow_identity *identity,
        uint32_t shard,
        uint32_t flow_index,
        uint32_t generation,
        uint64_t first_timestamp_ns) {
    if (identity == nullptr ||
        shard >= FK_ACTOR_FLOW_IDENTITY_MAX_SHARDS ||
        flow_index > FK_ACTOR_FLOW_IDENTITY_MAX_INDEX ||
        generation == 0u)
        return false;
    identity->first_timestamp_ns = first_timestamp_ns;
    identity->generation = generation;
    identity->packed_location =
        (shard << 24u) | flow_index;
    return true;
}

bool fk_actor_flow_identity_v2_init(
        fk_actor_flow_identity_v2 *identity,
        const fk_actor_flow_identity *presentation,
        uint64_t logical_connection_id) {
    if (identity == nullptr || presentation == nullptr ||
        presentation->generation == 0u)
        return false;
    identity->presentation = *presentation;
    identity->logical_connection_id = logical_connection_id;
    return true;
}

bool fk_actor_event_generation_next(
        uint32_t current_generation,
        uint32_t *next_generation) {
    if (next_generation == nullptr)
        return false;
    return next_event_generation(current_generation, *next_generation);
}

bool fk_actor_session_test_seed_event_generation(
        fk_actor_session *sessions,
        uint32_t event_slot,
        uint32_t current_generation) {
    if (sessions == nullptr)
        return false;
    State &state = *implementation(sessions);
    if (state.magic != kMagic || state.has_observation != 0u ||
        state.stats.observations != 0u ||
        state.stats.active_events != 0u ||
        event_slot >= state.config.maximum_events ||
        state.events[event_slot].active != 0u)
        return false;
    uint32_t current = state.event_free_head;
    uint32_t visited = 0u;
    while (current != kNone &&
           visited < state.config.maximum_events) {
        if (current == event_slot) {
            state.events[event_slot].generation = current_generation;
            return true;
        }
        current = state.events[current].next_free;
        visited++;
    }
    return false;
}

void fk_actor_session_config_init(fk_actor_session_config *config) {
    if (config == nullptr)
        return;
    std::memset(config, 0, sizeof(*config));
    config->idle_timeout_ns = FK_ACTOR_SESSION_DEFAULT_IDLE_NS;
    config->maximum_lifetime_ns =
        FK_ACTOR_SESSION_DEFAULT_MAX_LIFETIME_NS;
    config->maximum_events = FK_ACTOR_SESSION_DEFAULT_MAX_EVENTS;
    config->maximum_flows_per_event =
        FK_ACTOR_SESSION_MAX_FLOWS_PER_EVENT;
    config->maximum_total_flows =
        FK_ACTOR_SESSION_DEFAULT_TOTAL_FLOWS;
}

bool fk_actor_session_config_add_cidr(
        fk_actor_session_config *config,
        uint8_t ip_version,
        const uint8_t *address,
        uint8_t prefix_length) {
    if (config == nullptr || address == nullptr ||
        !valid_ip_version(ip_version) ||
        prefix_length > (ip_version == 4u ? 32u : 128u) ||
        config->cidr_count >= FK_ACTOR_SESSION_MAX_CIDRS)
        return false;
    fk_actor_session_cidr &cidr =
        config->cidrs[config->cidr_count++];
    std::memset(&cidr, 0, sizeof(cidr));
    cidr.ip_version = ip_version;
    cidr.prefix_length = prefix_length;
    std::memcpy(cidr.address, address, address_bytes(ip_version));
    clear_host_bits(cidr);
    return true;
}

bool fk_actor_session_config_add_cidr_text(
        fk_actor_session_config *config,
        const char *cidr_text) {
    if (config == nullptr || cidr_text == nullptr ||
        *cidr_text == '\0')
        return false;
    const char *slash = std::strchr(cidr_text, '/');
    if (slash == nullptr || slash == cidr_text ||
        slash[1] == '\0' ||
        slash[1] < '0' || slash[1] > '9' ||
        std::strchr(slash + 1, '/') != nullptr)
        return false;
    const size_t address_length =
        static_cast<size_t>(slash - cidr_text);
    if (address_length >= INET6_ADDRSTRLEN)
        return false;
    char address_text[INET6_ADDRSTRLEN]{};
    std::memcpy(address_text, cidr_text, address_length);
    errno = 0;
    char *prefix_end = nullptr;
    const unsigned long prefix = std::strtoul(
        slash + 1, &prefix_end, 10);
    if (errno != 0 || prefix_end == slash + 1 ||
        *prefix_end != '\0')
        return false;
    const uint8_t ip_version =
        std::strchr(address_text, ':') == nullptr ? 4u : 6u;
    const unsigned long maximum_prefix =
        ip_version == 4u ? 32u : 128u;
    if (prefix > maximum_prefix)
        return false;
    uint8_t address[16]{};
    const int family = ip_version == 4u ? AF_INET : AF_INET6;
    if (inet_pton(family, address_text, address) != 1)
        return false;
    return fk_actor_session_config_add_cidr(
        config,
        ip_version,
        address,
        static_cast<uint8_t>(prefix));
}

bool fk_actor_session_config_set_compact_ipv4_monitor(
        fk_actor_session_config *config,
        const uint8_t pool_base[4],
        uint8_t pool_prefix_length,
        uint32_t slots_per_namespace,
        uint32_t namespace_count,
        uint32_t monitored_identity_index) {
    if (config == nullptr || pool_base == nullptr)
        return false;
    fk_actor_session_compact_ipv4_monitor candidate{};
    candidate.enabled = 1u;
    candidate.pool_prefix_length = pool_prefix_length;
    std::memcpy(candidate.pool_base, pool_base, 4u);
    candidate.slots_per_namespace = slots_per_namespace;
    candidate.namespace_count = namespace_count;
    candidate.monitored_identity_index = monitored_identity_index;
    if (!compact_ipv4_monitor_valid(candidate))
        return false;
    for (uint32_t index = 0u; index < config->cidr_count; ++index) {
        if (compact_ipv4_monitor_overlaps_cidr(
                candidate, config->cidrs[index])) {
            return false;
        }
    }
    config->compact_ipv4_monitor = candidate;
    return true;
}

bool fk_actor_session_config_set_compact_ipv4_monitor_text(
        fk_actor_session_config *config,
        const char *pool_cidr,
        uint32_t slots_per_namespace,
        uint32_t namespace_count,
        uint32_t monitored_identity_index) {
    if (config == nullptr || pool_cidr == nullptr || *pool_cidr == '\0')
        return false;
    const char *slash = std::strchr(pool_cidr, '/');
    if (slash == nullptr || slash == pool_cidr || slash[1] == '\0' ||
        slash[1] < '0' || slash[1] > '9' ||
        std::strchr(slash + 1, '/') != nullptr) {
        return false;
    }
    const size_t address_length = static_cast<size_t>(slash - pool_cidr);
    if (address_length >= INET_ADDRSTRLEN)
        return false;
    char address_text[INET_ADDRSTRLEN]{};
    std::memcpy(address_text, pool_cidr, address_length);
    errno = 0;
    char *prefix_end = nullptr;
    const unsigned long prefix = std::strtoul(
        slash + 1, &prefix_end, 10);
    if (errno != 0 || prefix_end == slash + 1 || *prefix_end != '\0' ||
        prefix > 32u) {
        return false;
    }
    uint8_t address[4]{};
    if (inet_pton(AF_INET, address_text, address) != 1)
        return false;
    return fk_actor_session_config_set_compact_ipv4_monitor(
        config, address, static_cast<uint8_t>(prefix),
        slots_per_namespace, namespace_count, monitored_identity_index);
}

bool fk_actor_session_config_set_compact_ipv4_monitor_map(
        fk_actor_session_config *config,
        const uint8_t pool_base[4],
        uint8_t pool_prefix_length,
        uint32_t slots_per_namespace,
        uint32_t namespace_count,
        const uint32_t *monitored_identity_indices,
        uint32_t monitored_identity_index_count) {
    if (config == nullptr || pool_base == nullptr ||
        monitored_identity_indices == nullptr)
        return false;
    fk_actor_session_compact_ipv4_monitor candidate{};
    candidate.enabled = 1u;
    candidate.pool_prefix_length = pool_prefix_length;
    std::memcpy(candidate.pool_base, pool_base, 4u);
    candidate.slots_per_namespace = slots_per_namespace;
    candidate.namespace_count = namespace_count;
    candidate.monitored_identity_indices = monitored_identity_indices;
    candidate.monitored_identity_index_count =
        monitored_identity_index_count;
    if (!compact_ipv4_monitor_valid(candidate))
        return false;
    for (uint32_t index = 0u; index < config->cidr_count; ++index) {
        if (compact_ipv4_monitor_overlaps_cidr(
                candidate, config->cidrs[index])) {
            return false;
        }
    }
    config->compact_ipv4_monitor = candidate;
    return true;
}

bool fk_actor_session_config_set_compact_ipv4_monitor_map_text(
        fk_actor_session_config *config,
        const char *pool_cidr,
        uint32_t slots_per_namespace,
        uint32_t namespace_count,
        const uint32_t *monitored_identity_indices,
        uint32_t monitored_identity_index_count) {
    if (config == nullptr || pool_cidr == nullptr || *pool_cidr == '\0' ||
        monitored_identity_indices == nullptr) {
        return false;
    }
    const char *slash = std::strchr(pool_cidr, '/');
    if (slash == nullptr || slash == pool_cidr || slash[1] == '\0' ||
        slash[1] < '0' || slash[1] > '9' ||
        std::strchr(slash + 1, '/') != nullptr) {
        return false;
    }
    const size_t address_length = static_cast<size_t>(slash - pool_cidr);
    if (address_length >= INET_ADDRSTRLEN)
        return false;
    char address_text[INET_ADDRSTRLEN]{};
    std::memcpy(address_text, pool_cidr, address_length);
    errno = 0;
    char *prefix_end = nullptr;
    const unsigned long prefix = std::strtoul(
        slash + 1, &prefix_end, 10);
    if (errno != 0 || prefix_end == slash + 1 || *prefix_end != '\0' ||
        prefix > 32u) {
        return false;
    }
    uint8_t address[4]{};
    if (inet_pton(AF_INET, address_text, address) != 1)
        return false;
    return fk_actor_session_config_set_compact_ipv4_monitor_map(
        config,
        address,
        static_cast<uint8_t>(prefix),
        slots_per_namespace,
        namespace_count,
        monitored_identity_indices,
        monitored_identity_index_count);
}

bool fk_actor_session_config_valid(
        const fk_actor_session_config *config) {
    if (config == nullptr ||
        config->idle_timeout_ns == 0u ||
        config->maximum_lifetime_ns == 0u ||
        config->maximum_events == 0u ||
        config->maximum_events > FK_ACTOR_SESSION_MAX_EVENTS ||
        config->maximum_flows_per_event == 0u ||
        config->maximum_flows_per_event >
            FK_ACTOR_SESSION_MAX_FLOWS_PER_EVENT ||
        config->maximum_total_flows == 0u ||
        static_cast<uint64_t>(config->maximum_total_flows) >
            static_cast<uint64_t>(config->maximum_events) *
            config->maximum_flows_per_event ||
        config->reserved_v2 != 0u ||
        config->cidr_count == 0u ||
        config->cidr_count > FK_ACTOR_SESSION_MAX_CIDRS)
        return false;
    for (uint32_t index = 0u; index < config->cidr_count; ++index) {
        if (!valid_cidr(config->cidrs[index]))
            return false;
    }
    const fk_actor_session_compact_ipv4_monitor &compact =
        config->compact_ipv4_monitor;
    if (compact.enabled == 0u) {
        if (!compact_ipv4_monitor_disabled_clean(compact))
            return false;
    } else {
        if (!compact_ipv4_monitor_valid(compact))
            return false;
        for (uint32_t index = 0u; index < config->cidr_count; ++index) {
            if (compact_ipv4_monitor_overlaps_cidr(
                    compact, config->cidrs[index])) {
                return false;
            }
        }
    }
    return true;
}

bool fk_actor_session_config_is_datacon(
        const fk_actor_session_config *config) {
    if (!fk_actor_session_config_valid(config) ||
        config->cidr_count != 1u)
        return false;
    const fk_actor_session_cidr &cidr = config->cidrs[0];
    if (cidr.ip_version != 4u || cidr.prefix_length != 16u ||
        cidr.address[0] != 192u || cidr.address[1] != 168u)
        return false;
    for (uint32_t index = 2u; index < 16u; ++index) {
        if (cidr.address[index] != 0u)
            return false;
    }
    return true;
}

size_t fk_actor_session_storage_bytes(
        const fk_actor_session_config *config) {
    if (!fk_actor_session_config_valid(config))
        return 0u;
    size_t bytes = 0u;
    uint32_t flow_capacity = 0u;
    uint32_t flow_buckets = 0u;
    uint32_t event_buckets = 0u;
    return storage_layout(
        *config,
        bytes,
        flow_capacity,
        flow_buckets,
        event_buckets) ? bytes : 0u;
}

fk_actor_session *fk_actor_session_init(
        void *storage,
        size_t storage_bytes,
        const fk_actor_session_config *config,
        char *error,
        size_t error_capacity) {
    set_error(error, error_capacity, "");
    if (storage == nullptr || !fk_actor_session_config_valid(config)) {
        set_error(error, error_capacity, "invalid actor-session config");
        return nullptr;
    }
    size_t required = 0u;
    uint32_t flow_capacity = 0u;
    uint32_t flow_bucket_count = 0u;
    uint32_t event_bucket_count = 0u;
    if (!storage_layout(
            *config,
            required,
            flow_capacity,
            flow_bucket_count,
            event_bucket_count) ||
        storage_bytes < required) {
        set_error(error, error_capacity, "actor-session storage is too small");
        return nullptr;
    }
    const uintptr_t start = reinterpret_cast<uintptr_t>(storage);
    if (storage_bytes >
        std::numeric_limits<uintptr_t>::max() - start) {
        set_error(error, error_capacity, "actor-session storage overflows");
        return nullptr;
    }
    uintptr_t cursor = start;
    const uintptr_t end = start + storage_bytes;
    State *state = take_region<State>(cursor, end, 1u);
    EventEntry *events = take_region<EventEntry>(
        cursor, end, config->maximum_events);
    FlowEntry *flows = take_region<FlowEntry>(
        cursor, end, flow_capacity);
    uint32_t *event_buckets = take_region<uint32_t>(
        cursor, end, event_bucket_count);
    uint32_t *flow_buckets = take_region<uint32_t>(
        cursor, end, flow_bucket_count);
    uint32_t *heap = take_region<uint32_t>(
        cursor, end, config->maximum_events);
    if (state == nullptr || events == nullptr || flows == nullptr ||
        event_buckets == nullptr || flow_buckets == nullptr ||
        heap == nullptr) {
        set_error(error, error_capacity, "actor-session storage layout failed");
        return nullptr;
    }
    state = new (state) State{};
    for (uint32_t index = 0u;
         index < config->maximum_events; ++index)
        new (&events[index]) EventEntry{};
    for (uint32_t index = 0u; index < flow_capacity; ++index)
        new (&flows[index]) FlowEntry{};
    state->magic = kMagic;
    state->config = *config;
    state->events = events;
    state->flows = flows;
    state->event_buckets = event_buckets;
    state->event_bucket_count = event_bucket_count;
    state->event_bucket_mask = event_bucket_count - 1u;
    state->flow_buckets = flow_buckets;
    state->flow_bucket_count = flow_bucket_count;
    state->flow_bucket_mask = flow_bucket_count - 1u;
    state->expiry_heap = heap;
    state->event_free_head = 0u;
    state->flow_free_head = 0u;
    state->total_flow_capacity = flow_capacity;
    state->reserved_bytes = required;
    state->fixed_bytes =
        required -
        static_cast<size_t>(config->maximum_events) *
            (sizeof(EventEntry) + sizeof(uint32_t)) -
        static_cast<size_t>(flow_capacity) * sizeof(FlowEntry);
    state->next_event_id = 1u;
    state->stats.maximum_events = config->maximum_events;
    state->stats.maximum_flows_per_event =
        config->maximum_flows_per_event;
    state->stats.maximum_total_flows = flow_capacity;
    state->stats.maximum_logical_connection_slots =
        config->maximum_logical_connection_slots;
    state->stats.flow_identity_v2_abi_version =
        FK_ACTOR_FLOW_IDENTITY_V2_ABI_VERSION;
    state->stats.reserved_bytes = required;
    state->stats.used_bytes = state->fixed_bytes;
    state->stats.peak_used_bytes = state->fixed_bytes;
    for (uint32_t index = 0u;
         index < event_bucket_count; ++index)
        event_buckets[index] = kNone;
    for (uint32_t index = 0u;
         index < flow_bucket_count; ++index)
        flow_buckets[index] = kNone;
    for (uint32_t index = 0u;
         index < config->maximum_events; ++index) {
        events[index].flow_head = kNone;
        events[index].next_key = kNone;
        events[index].heap_position = kNone;
        events[index].next_free =
            index + 1u < config->maximum_events
            ? index + 1u : kNone;
    }
    for (uint32_t index = 0u; index < flow_capacity; ++index) {
        flows[index].tagged_event_slot = kNone;
        flows[index].next_free =
            index + 1u < flow_capacity ? index + 1u : kNone;
    }
    return reinterpret_cast<fk_actor_session *>(state);
}

bool fk_actor_session_observe_v2(
        fk_actor_session *sessions,
        const fk_flow_key *key,
        const fk_actor_flow_identity_v2 *flow_identity,
        uint64_t observation_timestamp_ns,
        fk_actor_session_result *result) {
    if (result != nullptr)
        std::memset(result, 0, sizeof(*result));
    if (sessions == nullptr)
        return false;
    State &state = *implementation(sessions);
    if (state.magic != kMagic)
        return false;
    if (key == nullptr || flow_identity == nullptr ||
        (flow_identity != nullptr &&
         !valid_flow_identity(
            state, *flow_identity, &observation_timestamp_ns)) ||
        (key != nullptr && flow_identity != nullptr &&
         flow_identity->logical_connection_id != 0u &&
         key->protocol != 17u) ||
        result == nullptr || !valid_flow_key(*key)) {
        state.stats.invalid_inputs++;
        if (flow_identity != nullptr &&
            flow_identity->logical_connection_id != 0u)
            state.stats.logical_input_validation_rejects++;
        record_reason(state, FK_ACTOR_REASON_INVALID_INPUT);
        if (result != nullptr)
            result->reason = FK_ACTOR_REASON_INVALID_INPUT;
        return false;
    }
    if (state.has_observation != 0u &&
        observation_timestamp_ns < state.last_observation_ns) {
        state.stats.out_of_order_observations++;
        record_reason(state, FK_ACTOR_REASON_OUT_OF_ORDER);
        result->reason = FK_ACTOR_REASON_OUT_OF_ORDER;
        return false;
    }
    state.has_observation = 1u;
    state.last_observation_ns = observation_timestamp_ns;
    state.stats.observations++;
    if (flow_identity->logical_connection_id != 0u)
        state.stats.logical_observations++;
    expire_before(state, observation_timestamp_ns);

    const uint32_t flow_slot =
        find_flow(state, *flow_identity);
    if (flow_slot != kNone) {
        const uint32_t event_slot =
            flow_event_slot(state.flows[flow_slot]);
        if (event_slot >= state.config.maximum_events ||
            state.events[event_slot].active == 0u) {
            state.stats.invalid_inputs++;
            record_reason(state, FK_ACTOR_REASON_INVALID_INPUT);
            result->reason = FK_ACTOR_REASON_INVALID_INPUT;
            return false;
        }
        update_event(state, event_slot, observation_timestamp_ns);
        const fk_actor_session_reason reason =
            FK_ACTOR_REASON_EXISTING_FLOW_STICKY;
        record_reason(state, reason);
        if (flow_identity->logical_connection_id != 0u)
            state.stats.logical_sticky_hits++;
        fill_result(
            state,
            event_slot,
            static_cast<fk_actor_session_key_kind>(
                state.events[event_slot].key.key_kind),
            reason,
            false,
            *result);
        return true;
    }

    if (state.flow_free_head == kNone) {
        const uint32_t oldest_slot = oldest_event_slot(state);
        if (oldest_slot == kNone) {
            state.stats.invalid_inputs++;
            record_reason(state, FK_ACTOR_REASON_INVALID_INPUT);
            result->reason = FK_ACTOR_REASON_INVALID_INPUT;
            return false;
        }
        retire_event(
            state,
            oldest_slot,
            RetirementReason::TotalFlowCapacity);
    }

    AssociationKey association{};
    const fk_actor_session_reason creation_reason =
        resolve_association(state, *key, association);
    bool full_match = false;
    uint32_t event_slot = find_accepting_event(
        state, association, full_match);
    bool created = false;
    fk_actor_session_reason reason;
    if (event_slot == kNone) {
        if (full_match) {
            state.stats.flow_capacity_rollovers++;
            reason = FK_ACTOR_REASON_FLOW_CAPACITY_ROLLOVER;
        } else {
            reason = creation_reason;
        }
        event_slot = create_event(
            state, association, observation_timestamp_ns);
        if (event_slot == kNone) {
            state.stats.invalid_inputs++;
            record_reason(state, FK_ACTOR_REASON_INVALID_INPUT);
            result->reason = FK_ACTOR_REASON_INVALID_INPUT;
            return false;
        }
        created = true;
    } else {
        reason = association.key_kind ==
                FK_ACTOR_SESSION_MONITORED_ACTOR
            ? FK_ACTOR_REASON_EXISTING_ACTOR_SESSION
            : FK_ACTOR_REASON_EXISTING_PAIR_SESSION;
        update_event(state, event_slot, observation_timestamp_ns);
    }
    if (!bind_flow(
            state,
            event_slot,
            *flow_identity)) {
        if (created)
            retire_event(
                state, event_slot, RetirementReason::EventCapacity);
        state.stats.invalid_inputs++;
        record_reason(state, FK_ACTOR_REASON_INVALID_INPUT);
        result->reason = FK_ACTOR_REASON_INVALID_INPUT;
        return false;
    }
    if (flow_identity->logical_connection_id != 0u)
        state.stats.logical_flows_created++;
    record_reason(state, reason);
    fill_result(
        state,
        event_slot,
        static_cast<fk_actor_session_key_kind>(association.key_kind),
        reason,
        created,
        *result);
    return true;
}

bool fk_actor_session_observe(
        fk_actor_session *sessions,
        const fk_flow_key *key,
        const fk_actor_flow_identity *flow_identity,
        uint64_t observation_timestamp_ns,
        fk_actor_session_result *result) {
    if (flow_identity == nullptr) {
        return fk_actor_session_observe_v2(
            sessions, key, nullptr, observation_timestamp_ns, result);
    }
    const fk_actor_flow_identity_v2 identity{
        *flow_identity,
        0u,
    };
    return fk_actor_session_observe_v2(
        sessions, key, &identity, observation_timestamp_ns, result);
}

bool fk_actor_session_lookup_flow_v2(
        const fk_actor_session *sessions,
        const fk_actor_flow_identity_v2 *flow_identity,
        fk_actor_session_result *result) {
    if (result != nullptr)
        std::memset(result, 0, sizeof(*result));
    if (sessions == nullptr || flow_identity == nullptr || result == nullptr)
        return false;
    const State &state = *implementation(sessions);
    if (state.magic != kMagic ||
        !valid_flow_identity(state, *flow_identity, nullptr))
        return false;
    const uint32_t flow_slot = find_flow(state, *flow_identity);
    if (flow_slot == kNone)
        return false;
    const uint32_t event_slot = flow_event_slot(state.flows[flow_slot]);
    if (event_slot >= state.config.maximum_events ||
        state.events[event_slot].active == 0u)
        return false;
    fill_result(
        state,
        event_slot,
        static_cast<fk_actor_session_key_kind>(
            state.events[event_slot].key.key_kind),
        FK_ACTOR_REASON_EXISTING_FLOW_STICKY,
        false,
        *result);
    return true;
}

bool fk_actor_session_lookup_flow(
        const fk_actor_session *sessions,
        const fk_actor_flow_identity *flow_identity,
        fk_actor_session_result *result) {
    if (flow_identity == nullptr) {
        return fk_actor_session_lookup_flow_v2(
            sessions, nullptr, result);
    }
    const fk_actor_flow_identity_v2 identity{
        *flow_identity,
        0u,
    };
    return fk_actor_session_lookup_flow_v2(
        sessions, &identity, result);
}

bool fk_actor_session_get_stats(
        const fk_actor_session *sessions,
        fk_actor_session_stats *stats) {
    if (sessions == nullptr || stats == nullptr)
        return false;
    const State &state = *implementation(sessions);
    if (state.magic != kMagic)
        return false;
    *stats = state.stats;
    return true;
}

bool fk_actor_session_event_handle_active(
        const fk_actor_session *sessions,
        uint32_t event_slot,
        uint32_t event_generation,
        uint64_t event_id) {
    if (sessions == nullptr)
        return false;
    const State &state = *implementation(sessions);
    if (state.magic != kMagic ||
        event_slot >= state.config.maximum_events)
        return false;
    const EventEntry &event = state.events[event_slot];
    return event.active != 0u &&
        event.generation == event_generation &&
        event.event_id == event_id;
}

bool fk_actor_session_get_event_identity(
        const fk_actor_session *sessions,
        uint32_t event_slot,
        uint32_t event_generation,
        uint64_t event_id,
        fk_actor_event_identity *identity) {
    if (identity != nullptr)
        std::memset(identity, 0, sizeof(*identity));
    if (sessions == nullptr || identity == nullptr)
        return false;
    const State &state = *implementation(sessions);
    if (state.magic != kMagic ||
        event_slot >= state.config.maximum_events)
        return false;
    const EventEntry &event = state.events[event_slot];
    if (event.active == 0u ||
        event.generation != event_generation ||
        event.event_id != event_id ||
        (event.key.key_kind != FK_ACTOR_SESSION_MONITORED_ACTOR &&
         event.key.key_kind != FK_ACTOR_SESSION_ENDPOINT_PAIR) ||
        !valid_ip_version(event.key.ip_version))
        return false;
    *identity = event.key;
    return true;
}

}  // extern "C"
