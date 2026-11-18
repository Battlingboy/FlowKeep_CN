#include "fk_owner_flow_bindings.h"

#include <atomic>
#include <cstddef>
#include <cstring>
#include <limits>
#include <new>

namespace {

constexpr uint64_t kCidGenerationMask = UINT64_C(0xffffffff);
constexpr uint32_t kFixedOwnerShift = 32u;
constexpr uint64_t kFixedOwnerMask = UINT64_C(0xffff);
constexpr uint32_t kStateShift = 48u;
constexpr uint64_t kStateMask = UINT64_C(0x3);
constexpr uint32_t kUnpublishedShift = 50u;
constexpr uint64_t kUnpublishedMask = UINT64_C(1) << kUnpublishedShift;
constexpr uint64_t kIdentityReservedMask = UINT64_C(0xfff8000000000000);

constexpr uint64_t kFlowIndexMask = FK_OWNER_FLOW_BINDINGS_MAX_FLOW_INDEX;
constexpr uint32_t kDirectionAxisShift = 24u;
constexpr uint64_t kHandleReservedMask = UINT64_C(0x00000000fe000000);
constexpr uint32_t kFlowGenerationShift = 32u;

enum EntryState : uint8_t {
    ENTRY_FREE = 0,
    ENTRY_UNBOUND = 1,
    ENTRY_BOUND = 2,
    ENTRY_RETIRED_PENDING_CID_ACK = 3,
};

struct BindingEntry {
    /* generation:u32 | fixed_owner:u16 | state:u2 | reserved:u14 */
    std::atomic<uint64_t> identity_word{0u};
    /* flow_index:u24 | axis:u1 | reserved:u7 | flow_generation:u32 */
    std::atomic<uint64_t> handle_axis_word{0u};
};

static_assert(sizeof(BindingEntry) == FK_OWNER_FLOW_BINDING_ENTRY_BYTES,
    "the direct-slot controlled-state entry must remain exactly 16 bytes");
static_assert(__atomic_always_lock_free(sizeof(uint64_t), nullptr),
    "both direct-slot publication words must be lock-free");
static_assert(sizeof(fk_owner_flow_bindings_config) == 16u &&
        offsetof(fk_owner_flow_bindings_config, owner_count) == 0u &&
        offsetof(fk_owner_flow_bindings_config,
            logical_id_abi_version) == 2u &&
        offsetof(fk_owner_flow_bindings_config,
            maximum_connection_slots) == 4u &&
        offsetof(fk_owner_flow_bindings_config,
            retire_ack_required) == 8u,
    "owner-flow binding ABI v4 config layout drifted");
static_assert(sizeof(fk_owner_flow_handle) == 8u,
    "the module-local FlowTable generation handle must remain 8 bytes");
static_assert(sizeof(fk_owner_flow_binding) == 24u &&
        offsetof(fk_owner_flow_binding, logical_connection_id) == 0u &&
        offsetof(fk_owner_flow_binding, handle) == 8u &&
        offsetof(fk_owner_flow_binding,
            logical_feature_to_presentation_direction_xor) == 16u,
    "owner-flow binding ABI v4 exported binding layout drifted");
static_assert(sizeof(fk_owner_flow_binding_creation_receipt) == 48u &&
        alignof(fk_owner_flow_binding_creation_receipt) == alignof(uint64_t),
    "owner-flow creation receipt ABI changed");
static_assert(sizeof(fk_owner_flow_bindings_topology_receipt) == 32u &&
        offsetof(fk_owner_flow_bindings_topology_receipt,
            receipt_abi_version) == 0u &&
        offsetof(fk_owner_flow_bindings_topology_receipt,
            logical_id_abi_version) == 4u &&
        offsetof(fk_owner_flow_bindings_topology_receipt,
            fixed_owner_count) == 12u &&
        offsetof(fk_owner_flow_bindings_topology_receipt,
            maximum_connection_slots) == 16u &&
        offsetof(fk_owner_flow_bindings_topology_receipt,
            topology_config_hash) == 24u,
    "owner-flow topology receipt ABI changed");
static_assert(alignof(BindingEntry) <= alignof(max_align_t),
    "binding entries must fit caller-provided max_align_t storage");

#define FK_BINDING_COUNTER_FIELDS(X)            \
    X(lookup_attempts)                          \
    X(lookup_found)                             \
    X(lookup_not_found)                         \
    X(bind_attempts)                            \
    X(bindings_created)                         \
    X(bind_idempotent)                          \
    X(bind_conflicts)                           \
    X(rebind_attempts)                          \
    X(rebind_success)                           \
    X(rebind_idempotent)                        \
    X(release_attempts)                         \
    X(releases)                                 \
    X(retire_prepare_attempts)                  \
    X(retire_prepared_bound)                    \
    X(retire_prepared_unbound)                  \
    X(retire_prepared_absent)                   \
    X(retire_prepare_idempotent)                \
    X(retire_finalize_attempts)                 \
    X(retire_finalize_success)                  \
    X(scan_calls)                               \
    X(scan_slots)                               \
    X(scan_active)                              \
    X(scan_passes_completed)                    \
    X(missing_binding_rejects)                  \
    X(stale_generation_rejects)                 \
    X(handle_mismatch_rejects)                  \
    X(direction_mismatch_rejects)               \
    X(cid_generation_mismatch_rejects)          \
    X(fixed_owner_mismatch_rejects)             \
    X(slot_reuse_before_retire_ack_rejects)     \
    X(retire_expectation_mismatch_rejects)      \
    X(slot_out_of_range_rejects)                \
    X(invalid_requests)                         \
    X(state_integrity_failures)                 \
    X(owner_thread_claims)                      \
    X(owner_thread_violations)

struct AtomicCounters {
#define DECLARE_ATOMIC(name) std::atomic<uint64_t> name{0u};
    FK_BINDING_COUNTER_FIELDS(DECLARE_ATOMIC)
#undef DECLARE_ATOMIC
};

struct OwnerState {
    std::atomic<uint64_t> owner_thread_token{0u};
    std::atomic<uint64_t> active_bindings{0u};
    std::atomic<uint64_t> peak_active_bindings{0u};
    std::atomic<uint64_t> unbound_slots{0u};
    std::atomic<uint64_t> peak_unbound_slots{0u};
    std::atomic<uint64_t> retired_pending_cid_ack_slots{0u};
    std::atomic<uint64_t> peak_retired_pending_cid_ack_slots{0u};
    /* V2 creation is owner-serialized.  The monotonically increasing epoch
     * is never reused; active_creation_epoch==0 means there is no outstanding
     * unpublished transaction for this owner. */
    std::atomic<uint64_t> last_creation_epoch{0u};
    std::atomic<uint64_t> active_creation_epoch{0u};
    AtomicCounters counters;
};

struct BindingsImpl {
    fk_owner_flow_bindings_config config{};
    OwnerState *owners = nullptr;
    BindingEntry *entries = nullptr;
    uint64_t reserved_bytes = 0u;
    uint64_t directory_lifetime_nonce = 0u;
};

static_assert(alignof(OwnerState) <= alignof(max_align_t),
    "owner metadata must fit caller-provided max_align_t storage");
static_assert(alignof(BindingsImpl) <= alignof(max_align_t),
    "binding metadata must fit caller-provided max_align_t storage");

struct DecodedLogicalId {
    uint32_t slot;
    uint32_t generation;
};

struct EntrySnapshot {
    uint64_t identity;
    uint64_t handle_axis;
};

constexpr uint8_t kLogicalIdFullWidthBits = 64u;
constexpr uint8_t kLogicalIdGenerationBits = 32u;
constexpr uint8_t kLogicalIdEncodedSlotBits = 32u;
constexpr uint64_t kTopologyFnvOffset = UINT64_C(14695981039346656037);
constexpr uint64_t kTopologyFnvPrime = UINT64_C(1099511628211);
constexpr uint16_t kCreationReceiptDomain = UINT16_C(0xf1c5);
constexpr uint32_t kCreationReceiptOwnerShift = 16u;
constexpr uint32_t kCreationReceiptPriorUnboundShift = 32u;
constexpr uint32_t kCreationReceiptDomainShift = 48u;

void topology_hash_byte(uint64_t &hash, uint8_t value) {
    hash ^= value;
    hash *= kTopologyFnvPrime;
}

void topology_hash_u16(uint64_t &hash, uint16_t value) {
    topology_hash_byte(hash, static_cast<uint8_t>(value));
    topology_hash_byte(hash, static_cast<uint8_t>(value >> 8u));
}

void topology_hash_u32(uint64_t &hash, uint32_t value) {
    topology_hash_u16(hash, static_cast<uint16_t>(value));
    topology_hash_u16(hash, static_cast<uint16_t>(value >> 16u));
}

uint64_t topology_config_hash(
        uint16_t fixed_owner_count,
        uint32_t maximum_connection_slots) {
    static constexpr char kDomain[] = "FLOWKEEP_OWNER_TOPOLOGY_V1";
    uint64_t hash = kTopologyFnvOffset;
    for (size_t index = 0u; index + 1u < sizeof(kDomain); ++index)
        topology_hash_byte(hash, static_cast<uint8_t>(kDomain[index]));
    topology_hash_u32(
        hash, FK_OWNER_FLOW_BINDINGS_TOPOLOGY_RECEIPT_ABI_VERSION);
    topology_hash_u16(hash, FK_QUIC_LOGICAL_ID_ABI_VERSION);
    topology_hash_byte(hash, kLogicalIdFullWidthBits);
    topology_hash_byte(hash, kLogicalIdGenerationBits);
    topology_hash_byte(hash, kLogicalIdEncodedSlotBits);
    topology_hash_byte(hash, 1u);  // full-width logical id required
    topology_hash_byte(hash, 1u);  // retire acknowledgement required
    topology_hash_u16(hash, fixed_owner_count);
    topology_hash_u32(hash, maximum_connection_slots);
    return hash;
}

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

bool reserved_zero(const fk_owner_flow_bindings_config &config) {
    for (uint8_t byte : config.reserved) {
        if (byte != 0u)
            return false;
    }
    return true;
}

bool valid_config(const fk_owner_flow_bindings_config *config) {
    return config != nullptr &&
        config->owner_count != 0u && config->owner_count <= 64u &&
        config->logical_id_abi_version == FK_QUIC_LOGICAL_ID_ABI_VERSION &&
        config->maximum_connection_slots != 0u &&
        config->retire_ack_required == 1u && reserved_zero(*config);
}

size_t required_bytes(const fk_owner_flow_bindings_config *config) {
    if (!valid_config(config))
        return 0u;
    size_t bytes = sizeof(BindingsImpl);
    if (!align_size(bytes, alignof(OwnerState)))
        return 0u;
    size_t owner_bytes = 0u;
    if (!checked_multiply_size(
            config->owner_count, sizeof(OwnerState), owner_bytes) ||
        !checked_add_size(bytes, owner_bytes) ||
        !align_size(bytes, alignof(BindingEntry)))
        return 0u;
    size_t entry_bytes = 0u;
    if (!checked_multiply_size(
            config->maximum_connection_slots,
            sizeof(BindingEntry), entry_bytes) ||
        !checked_add_size(bytes, entry_bytes))
        return 0u;
    return bytes;
}

BindingsImpl *implementation(fk_owner_flow_bindings *bindings) {
    return reinterpret_cast<BindingsImpl *>(bindings);
}

const BindingsImpl *implementation(const fk_owner_flow_bindings *bindings) {
    return reinterpret_cast<const BindingsImpl *>(bindings);
}

/* Zero is permanently reserved for "unassigned/exhausted".  Saturation at
 * zero is deliberate: allowing unsigned wrap would eventually reuse a token
 * and revive an exited thread's immutable owner claim. */
std::atomic<uint64_t> g_next_thread_token{1u};
std::atomic<uint64_t> g_next_directory_lifetime_nonce{1u};

uint64_t allocate_nonreused_nonce(std::atomic<uint64_t> &source) {
    uint64_t candidate = source.load(std::memory_order_relaxed);
    while (candidate != 0u) {
        const uint64_t successor =
            candidate == std::numeric_limits<uint64_t>::max()
                ? 0u : candidate + 1u;
        if (source.compare_exchange_weak(
                candidate,
                successor,
                std::memory_order_relaxed,
                std::memory_order_relaxed)) {
            return candidate;
        }
    }
    return 0u;
}

uint64_t allocate_thread_token() {
    return allocate_nonreused_nonce(g_next_thread_token);
}

uint64_t current_thread_token() {
    /* Allocation occurs only on this thread's first bindings entry.  All
     * packet-path checks after claim are one TLS load plus one atomic load. */
    static thread_local const uint64_t token = allocate_thread_token();
    return token;
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

bool checked_add_u64(uint64_t &target, uint64_t increment) {
    if (increment > std::numeric_limits<uint64_t>::max() - target)
        return false;
    target += increment;
    return true;
}

bool add_counters(
        fk_owner_flow_binding_counters &target,
        const fk_owner_flow_binding_counters &source) {
#define ADD_COUNTER(name) \
    if (!checked_add_u64(target.name, source.name)) return false;
    FK_BINDING_COUNTER_FIELDS(ADD_COUNTER)
#undef ADD_COUNTER
    return true;
}

void load_counters(
        const AtomicCounters &source,
        fk_owner_flow_binding_counters &destination) {
#define LOAD_COUNTER(name) \
    destination.name = source.name.load(std::memory_order_relaxed);
    FK_BINDING_COUNTER_FIELDS(LOAD_COUNTER)
#undef LOAD_COUNTER
}

OwnerState *owner_for_operation(
        BindingsImpl *state,
        uint16_t owner_index,
        fk_owner_flow_binding_result &error) {
    if (state == nullptr || owner_index >= state->config.owner_count) {
        error = FK_OWNER_FLOW_BINDING_INVALID;
        return nullptr;
    }
    OwnerState &owner = state->owners[owner_index];
    const uint64_t claimed =
        owner.owner_thread_token.load(std::memory_order_acquire);
    const uint64_t current = current_thread_token();
    if (current == 0u) {
        owner.counters.state_integrity_failures.fetch_add(
            1u, std::memory_order_relaxed);
        owner.counters.owner_thread_violations.fetch_add(
            1u, std::memory_order_relaxed);
        error = FK_OWNER_FLOW_BINDING_NOT_OWNER;
        return nullptr;
    }
    if (claimed == 0u || claimed != current) {
        owner.counters.owner_thread_violations.fetch_add(
            1u, std::memory_order_relaxed);
        error = FK_OWNER_FLOW_BINDING_NOT_OWNER;
        return nullptr;
    }
    return &owner;
}

bool decode_logical_id(
        const BindingsImpl &state,
        OwnerState &owner,
        uint64_t logical_connection_id,
        DecodedLogicalId &decoded) {
    if (fk_quic_logical_id_decode(
            logical_connection_id,
            state.config.maximum_connection_slots,
            &decoded.slot,
            &decoded.generation))
        return true;
    const uint32_t encoded_slot =
        static_cast<uint32_t>(logical_connection_id);
    const uint32_t generation =
        static_cast<uint32_t>(logical_connection_id >> 32u);
    if (encoded_slot != 0u && generation != 0u &&
        encoded_slot - 1u >= state.config.maximum_connection_slots) {
        owner.counters.slot_out_of_range_rejects.fetch_add(
            1u, std::memory_order_relaxed);
    }
    owner.counters.invalid_requests.fetch_add(1u, std::memory_order_relaxed);
    return false;
}

bool valid_handle(fk_owner_flow_handle handle) {
    return handle.index <= FK_OWNER_FLOW_BINDINGS_MAX_FLOW_INDEX &&
        handle.generation != 0u;
}

bool handles_equal(
        fk_owner_flow_handle left,
        fk_owner_flow_handle right) {
    return left.index == right.index && left.generation == right.generation;
}

uint8_t direction_axis(
        uint8_t admitted_identity_first_canonical_direction,
        uint8_t current_logical_feature_direction) {
    return admitted_identity_first_canonical_direction ^
        current_logical_feature_direction;
}

uint64_t pack_identity(
        uint32_t cid_generation,
        uint16_t fixed_owner,
        EntryState state,
        bool unpublished = false) {
    return static_cast<uint64_t>(cid_generation) |
        (static_cast<uint64_t>(fixed_owner) << kFixedOwnerShift) |
        (static_cast<uint64_t>(state) << kStateShift) |
        (unpublished ? kUnpublishedMask : 0u);
}

uint32_t identity_generation(uint64_t identity) {
    return static_cast<uint32_t>(identity & kCidGenerationMask);
}

uint16_t identity_owner(uint64_t identity) {
    return static_cast<uint16_t>(
        (identity >> kFixedOwnerShift) & kFixedOwnerMask);
}

EntryState identity_state(uint64_t identity) {
    return static_cast<EntryState>((identity >> kStateShift) & kStateMask);
}

bool identity_unpublished(uint64_t identity) {
    return (identity & kUnpublishedMask) != 0u;
}

bool identity_word_valid(
        uint64_t identity,
        uint16_t owner_count) {
    if (identity == 0u)
        return true;
    return (identity & kIdentityReservedMask) == 0u &&
        identity_generation(identity) != 0u &&
        identity_owner(identity) < owner_count &&
        (!identity_unpublished(identity) ||
         identity_state(identity) == ENTRY_BOUND);
}

uint64_t pack_handle_axis(fk_owner_flow_handle handle, uint8_t axis) {
    return static_cast<uint64_t>(handle.index) |
        (static_cast<uint64_t>(axis) << kDirectionAxisShift) |
        (static_cast<uint64_t>(handle.generation) << kFlowGenerationShift);
}

fk_owner_flow_handle unpack_handle(uint64_t packed) {
    return {
        static_cast<uint32_t>(packed & kFlowIndexMask),
        static_cast<uint32_t>(packed >> kFlowGenerationShift),
    };
}

uint8_t unpack_direction_axis(uint64_t packed) {
    return static_cast<uint8_t>(
        (packed >> kDirectionAxisShift) & 1u);
}

bool handle_axis_word_valid(uint64_t packed);

uint64_t mix64(uint64_t value) {
    value ^= value >> 30u;
    value *= UINT64_C(0xbf58476d1ce4e5b9);
    value ^= value >> 27u;
    value *= UINT64_C(0x94d049bb133111eb);
    return value ^ (value >> 31u);
}

uint64_t creation_receipt_header(uint16_t owner, bool prior_unbound) {
    return static_cast<uint64_t>(
               FK_OWNER_FLOW_BINDING_CREATION_RECEIPT_ABI_VERSION) |
        (static_cast<uint64_t>(owner) << kCreationReceiptOwnerShift) |
        (static_cast<uint64_t>(prior_unbound ? 1u : 0u)
            << kCreationReceiptPriorUnboundShift) |
        (static_cast<uint64_t>(kCreationReceiptDomain)
            << kCreationReceiptDomainShift);
}

uint64_t creation_receipt_tag(
        const BindingsImpl &state,
        const fk_owner_flow_binding_creation_receipt &receipt) {
    /* The receipt is a same-process capability rather than a remote security
     * boundary.  Its tag detects mutation, while lifetime_nonce plus the
     * owner-local non-reused epoch provide the ABA guarantee. */
    uint64_t accumulator = mix64(
        state.directory_lifetime_nonce ^ UINT64_C(0x464b435245415431));
    for (size_t index = 0u;
         index + 1u < FK_OWNER_FLOW_BINDING_CREATION_RECEIPT_WORDS;
         ++index) {
        accumulator = mix64(
            accumulator ^ receipt.opaque[index] ^
            (UINT64_C(0x9e3779b97f4a7c15) * (index + 1u)));
    }
    return accumulator;
}

void issue_creation_receipt(
        const BindingsImpl &state,
        uint16_t owner,
        bool prior_unbound,
        uint64_t creation_epoch,
        uint64_t logical_connection_id,
        uint64_t handle_axis,
        fk_owner_flow_binding_creation_receipt &receipt) {
    receipt = {};
    receipt.opaque[0] = creation_receipt_header(owner, prior_unbound);
    receipt.opaque[1] = state.directory_lifetime_nonce;
    receipt.opaque[2] = creation_epoch;
    receipt.opaque[3] = logical_connection_id;
    receipt.opaque[4] = handle_axis;
    receipt.opaque[5] = creation_receipt_tag(state, receipt);
}

bool creation_receipt_matches(
        const BindingsImpl &state,
        const OwnerState &owner_state,
        uint16_t owner,
        uint64_t logical_connection_id,
        fk_owner_flow_handle expected,
        const fk_owner_flow_binding_creation_receipt *receipt,
        bool &prior_unbound,
        uint64_t &handle_axis) {
    prior_unbound = false;
    handle_axis = 0u;
    if (receipt == nullptr || !valid_handle(expected))
        return false;
    const uint64_t header = receipt->opaque[0];
    const uint64_t prior_unbound_mask =
        UINT64_C(1) << kCreationReceiptPriorUnboundShift;
    if ((header & ~prior_unbound_mask) !=
            creation_receipt_header(owner, false) ||
        receipt->opaque[1] != state.directory_lifetime_nonce ||
        receipt->opaque[2] == 0u ||
        receipt->opaque[2] != owner_state.active_creation_epoch.load(
            std::memory_order_acquire) ||
        receipt->opaque[3] != logical_connection_id ||
        receipt->opaque[5] != creation_receipt_tag(state, *receipt)) {
        return false;
    }
    handle_axis = receipt->opaque[4];
    if (!handle_axis_word_valid(handle_axis) ||
        !handles_equal(unpack_handle(handle_axis), expected)) {
        return false;
    }
    prior_unbound = ((header >> kCreationReceiptPriorUnboundShift) & 1u) != 0u;
    return true;
}

bool handle_axis_word_valid(uint64_t packed) {
    return packed != 0u && (packed & kHandleReservedMask) == 0u &&
        valid_handle(unpack_handle(packed));
}

EntrySnapshot snapshot(const BindingEntry &entry) {
    /* Two identity reads prevent a collector from combining two lifetimes. */
    for (uint32_t attempt = 0u; attempt < 4u; ++attempt) {
        const uint64_t before =
            entry.identity_word.load(std::memory_order_acquire);
        const uint64_t handle =
            entry.handle_axis_word.load(std::memory_order_acquire);
        const uint64_t after =
            entry.identity_word.load(std::memory_order_acquire);
        if (before == after)
            return {after, handle};
    }
    return {
        entry.identity_word.load(std::memory_order_acquire),
        entry.handle_axis_word.load(std::memory_order_acquire),
    };
}

void clear_binding(fk_owner_flow_binding *binding) {
    if (binding != nullptr)
        std::memset(binding, 0, sizeof(*binding));
}

bool export_binding(
        uint32_t slot,
        const EntrySnapshot &entry,
        fk_owner_flow_binding *binding) {
    if (binding == nullptr ||
        !identity_word_valid(entry.identity, UINT16_MAX))
        return false;
    const EntryState state = identity_state(entry.identity);
    if (state != ENTRY_BOUND && state != ENTRY_UNBOUND &&
        state != ENTRY_RETIRED_PENDING_CID_ACK)
        return false;
    uint64_t logical_connection_id = 0u;
    if (!fk_quic_logical_id_encode(
            slot,
            identity_generation(entry.identity),
            &logical_connection_id))
        return false;
    std::memset(binding, 0, sizeof(*binding));
    binding->logical_connection_id = logical_connection_id;
    if (state == ENTRY_BOUND ||
        (state == ENTRY_RETIRED_PENDING_CID_ACK &&
         entry.handle_axis != 0u)) {
        if (!handle_axis_word_valid(entry.handle_axis))
            return false;
        binding->handle = unpack_handle(entry.handle_axis);
        binding->logical_feature_to_presentation_direction_xor =
            unpack_direction_axis(entry.handle_axis);
    } else if (entry.handle_axis != 0u) {
        return false;
    }
    return true;
}

enum EntryMatch {
    MATCH_FREE,
    MATCH_BOUND,
    MATCH_UNPUBLISHED_BOUND,
    MATCH_UNBOUND,
    MATCH_RETIRED,
    MATCH_CID_GENERATION,
    MATCH_FIXED_OWNER,
    MATCH_TRANSIENT_OR_CORRUPT,
};

EntryMatch match_entry(
        const BindingsImpl &state,
        const EntrySnapshot &entry,
        uint16_t owner,
        uint32_t generation) {
    if (entry.identity == 0u)
        return entry.handle_axis == 0u
            ? MATCH_FREE : MATCH_TRANSIENT_OR_CORRUPT;
    if (!identity_word_valid(entry.identity, state.config.owner_count))
        return MATCH_TRANSIENT_OR_CORRUPT;
    if (identity_generation(entry.identity) != generation)
        return MATCH_CID_GENERATION;
    if (identity_owner(entry.identity) != owner)
        return MATCH_FIXED_OWNER;
    switch (identity_state(entry.identity)) {
    case ENTRY_BOUND:
        if (!handle_axis_word_valid(entry.handle_axis))
            return MATCH_TRANSIENT_OR_CORRUPT;
        return identity_unpublished(entry.identity)
            ? MATCH_UNPUBLISHED_BOUND : MATCH_BOUND;
    case ENTRY_UNBOUND:
        return entry.handle_axis == 0u
            ? MATCH_UNBOUND : MATCH_TRANSIENT_OR_CORRUPT;
    case ENTRY_RETIRED_PENDING_CID_ACK:
        return entry.handle_axis == 0u ||
                handle_axis_word_valid(entry.handle_axis)
            ? MATCH_RETIRED : MATCH_TRANSIENT_OR_CORRUPT;
    case ENTRY_FREE:
        return MATCH_TRANSIENT_OR_CORRUPT;
    }
    return MATCH_TRANSIENT_OR_CORRUPT;
}

fk_owner_flow_binding_result match_failure(
        OwnerState &owner,
        EntryMatch match,
        bool binding_creation) {
    if (match == MATCH_RETIRED)
        return FK_OWNER_FLOW_BINDING_RETIRE_PENDING_CID_ACK;
    if (match == MATCH_CID_GENERATION) {
        owner.counters.cid_generation_mismatch_rejects.fetch_add(
            1u, std::memory_order_relaxed);
        if (binding_creation) {
            owner.counters.slot_reuse_before_retire_ack_rejects.fetch_add(
                1u, std::memory_order_relaxed);
            return FK_OWNER_FLOW_BINDING_SLOT_REUSE_BEFORE_RETIRE_ACK;
        }
        return FK_OWNER_FLOW_BINDING_CID_GENERATION_MISMATCH;
    }
    if (match == MATCH_FIXED_OWNER) {
        owner.counters.fixed_owner_mismatch_rejects.fetch_add(
            1u, std::memory_order_relaxed);
        if (binding_creation) {
            owner.counters.slot_reuse_before_retire_ack_rejects.fetch_add(
                1u, std::memory_order_relaxed);
        }
        return FK_OWNER_FLOW_BINDING_FIXED_OWNER_MISMATCH;
    }
    owner.counters.state_integrity_failures.fetch_add(
        1u, std::memory_order_relaxed);
    return FK_OWNER_FLOW_BINDING_STATE_INTEGRITY_FAILURE;
}

void increment_bound(OwnerState &owner) {
    const uint64_t value = owner.active_bindings.fetch_add(
        1u, std::memory_order_relaxed) + 1u;
    update_peak(owner.peak_active_bindings, value);
}

void increment_unbound(OwnerState &owner) {
    const uint64_t value = owner.unbound_slots.fetch_add(
        1u, std::memory_order_relaxed) + 1u;
    update_peak(owner.peak_unbound_slots, value);
}

void increment_retired_pending(OwnerState &owner) {
    const uint64_t value = owner.retired_pending_cid_ack_slots.fetch_add(
        1u, std::memory_order_relaxed) + 1u;
    update_peak(owner.peak_retired_pending_cid_ack_slots, value);
}

}  // namespace

extern "C" {

void fk_owner_flow_bindings_default_config_init(
        fk_owner_flow_bindings_config *config) {
    if (config == nullptr)
        return;
    *config = {};
    config->owner_count = FK_OWNER_FLOW_BINDINGS_DEFAULT_OWNERS;
    config->logical_id_abi_version = FK_QUIC_LOGICAL_ID_ABI_VERSION;
    config->maximum_connection_slots =
        FK_OWNER_FLOW_BINDINGS_DEFAULT_CONNECTION_SLOTS;
    config->retire_ack_required = 1u;
}

bool fk_owner_flow_bindings_config_valid(
        const fk_owner_flow_bindings_config *config) {
    return valid_config(config);
}

size_t fk_owner_flow_bindings_storage_bytes(
        const fk_owner_flow_bindings_config *config) {
    return required_bytes(config);
}

fk_owner_flow_bindings *fk_owner_flow_bindings_initialize(
        void *storage,
        size_t storage_bytes,
        const fk_owner_flow_bindings_config *config) {
    const size_t required = required_bytes(config);
    if (storage == nullptr || required == 0u || storage_bytes < required ||
        reinterpret_cast<uintptr_t>(storage) % alignof(max_align_t) != 0u)
        return nullptr;
    const uint64_t lifetime_nonce =
        allocate_nonreused_nonce(g_next_directory_lifetime_nonce);
    if (lifetime_nonce == 0u)
        return nullptr;
    auto *base = static_cast<uint8_t *>(storage);
    auto *state = new (base) BindingsImpl{};
    state->config = *config;
    state->reserved_bytes = required;
    state->directory_lifetime_nonce = lifetime_nonce;
    size_t offset = sizeof(BindingsImpl);
    (void)align_size(offset, alignof(OwnerState));
    state->owners = reinterpret_cast<OwnerState *>(base + offset);
    offset += static_cast<size_t>(config->owner_count) * sizeof(OwnerState);
    (void)align_size(offset, alignof(BindingEntry));
    state->entries = reinterpret_cast<BindingEntry *>(base + offset);
    for (uint16_t owner = 0u; owner < config->owner_count; ++owner)
        new (&state->owners[owner]) OwnerState{};
    for (uint32_t slot = 0u;
         slot < config->maximum_connection_slots; ++slot)
        new (&state->entries[slot]) BindingEntry{};
    return reinterpret_cast<fk_owner_flow_bindings *>(state);
}

void fk_owner_flow_bindings_destroy(fk_owner_flow_bindings *bindings) {
    if (bindings == nullptr)
        return;
    BindingsImpl *state = implementation(bindings);
    for (uint32_t slot = 0u;
         slot < state->config.maximum_connection_slots; ++slot)
        state->entries[slot].~BindingEntry();
    for (uint16_t owner = 0u; owner < state->config.owner_count; ++owner)
        state->owners[owner].~OwnerState();
    state->~BindingsImpl();
}

bool fk_owner_flow_bindings_get_topology_receipt(
        const fk_owner_flow_bindings *bindings,
        fk_owner_flow_bindings_topology_receipt *receipt) {
    if (receipt != nullptr)
        *receipt = {};
    if (bindings == nullptr || receipt == nullptr)
        return false;
    const BindingsImpl &state = *implementation(bindings);
    receipt->receipt_abi_version =
        FK_OWNER_FLOW_BINDINGS_TOPOLOGY_RECEIPT_ABI_VERSION;
    receipt->logical_id_abi_version = state.config.logical_id_abi_version;
    receipt->logical_id_bits = kLogicalIdFullWidthBits;
    receipt->logical_id_full_width = 1u;
    receipt->logical_id_generation_bits = kLogicalIdGenerationBits;
    receipt->logical_id_encoded_slot_bits = kLogicalIdEncodedSlotBits;
    receipt->retire_ack_required = state.config.retire_ack_required;
    receipt->fixed_owner_count = state.config.owner_count;
    receipt->maximum_connection_slots =
        state.config.maximum_connection_slots;
    receipt->topology_config_hash = topology_config_hash(
        receipt->fixed_owner_count,
        receipt->maximum_connection_slots);
    return true;
}

bool fk_owner_flow_bindings_claim_owner(
        fk_owner_flow_bindings *bindings,
        uint16_t owner_index) {
    if (bindings == nullptr)
        return false;
    BindingsImpl &state = *implementation(bindings);
    if (owner_index >= state.config.owner_count)
        return false;
    OwnerState &owner = state.owners[owner_index];
    const uint64_t token = current_thread_token();
    if (token == 0u) {
        owner.counters.state_integrity_failures.fetch_add(
            1u, std::memory_order_relaxed);
        owner.counters.owner_thread_violations.fetch_add(
            1u, std::memory_order_relaxed);
        return false;
    }
    uint64_t expected = 0u;
    if (owner.owner_thread_token.compare_exchange_strong(
            expected,
            token,
            std::memory_order_acq_rel,
            std::memory_order_acquire)) {
        owner.counters.owner_thread_claims.fetch_add(
            1u, std::memory_order_relaxed);
        return true;
    }
    /* A claim is a one-shot ownership transfer, not an idempotent thread
     * check.  Returning true here would let a second adapter on the same
     * thread attach a different runtime/outbox to the same CID owner. */
    owner.counters.owner_thread_violations.fetch_add(
        1u, std::memory_order_relaxed);
    return false;
}

bool fk_owner_flow_bindings_is_owner_thread(
        const fk_owner_flow_bindings *bindings,
        uint16_t owner_index) {
    if (bindings == nullptr)
        return false;
    const BindingsImpl &state = *implementation(bindings);
    if (owner_index >= state.config.owner_count)
        return false;
    const uint64_t current = current_thread_token();
    return current != 0u &&
        state.owners[owner_index].owner_thread_token.load(
            std::memory_order_acquire) == current;
}

bool fk_owner_flow_bindings_validate_owner_thread_and_account(
        fk_owner_flow_bindings *bindings,
        uint16_t owner_index) {
    fk_owner_flow_binding_result error = FK_OWNER_FLOW_BINDING_INVALID;
    BindingsImpl *state = bindings == nullptr
        ? nullptr : implementation(bindings);
    return owner_for_operation(state, owner_index, error) != nullptr;
}

fk_owner_flow_binding_result fk_owner_flow_bindings_lookup(
        fk_owner_flow_bindings *bindings,
        uint16_t owner_index,
        uint64_t logical_connection_id,
        fk_owner_flow_binding *binding) {
    clear_binding(binding);
    fk_owner_flow_binding_result error = FK_OWNER_FLOW_BINDING_INVALID;
    BindingsImpl *state = bindings == nullptr
        ? nullptr : implementation(bindings);
    OwnerState *owner = owner_for_operation(state, owner_index, error);
    if (owner == nullptr)
        return error;
    owner->counters.lookup_attempts.fetch_add(1u, std::memory_order_relaxed);
    DecodedLogicalId decoded{};
    if (binding == nullptr ||
        !decode_logical_id(*state, *owner, logical_connection_id, decoded)) {
        if (binding == nullptr)
            owner->counters.invalid_requests.fetch_add(
                1u, std::memory_order_relaxed);
        return FK_OWNER_FLOW_BINDING_INVALID;
    }
    const EntrySnapshot entry = snapshot(state->entries[decoded.slot]);
    const EntryMatch match = match_entry(
        *state, entry, owner_index, decoded.generation);
    if (match == MATCH_BOUND) {
        if (!export_binding(decoded.slot, entry, binding))
            return match_failure(*owner, MATCH_TRANSIENT_OR_CORRUPT, false);
        owner->counters.lookup_found.fetch_add(1u, std::memory_order_relaxed);
        return FK_OWNER_FLOW_BINDING_FOUND;
    }
    if (match == MATCH_FREE || match == MATCH_UNBOUND) {
        owner->counters.lookup_not_found.fetch_add(
            1u, std::memory_order_relaxed);
        return FK_OWNER_FLOW_BINDING_NOT_FOUND;
    }
    if (match == MATCH_RETIRED) {
        if (!export_binding(decoded.slot, entry, binding))
            return match_failure(*owner, MATCH_TRANSIENT_OR_CORRUPT, false);
        return FK_OWNER_FLOW_BINDING_RETIRE_PENDING_CID_ACK;
    }
    return match_failure(*owner, match, false);
}

static fk_owner_flow_binding_result bind_from_admission_impl(
        fk_owner_flow_bindings *bindings,
        uint16_t owner_index,
        uint64_t logical_connection_id,
        fk_owner_flow_handle handle,
        uint8_t admitted_identity_first_canonical_direction,
        uint8_t current_logical_feature_direction,
        fk_owner_flow_binding *binding,
        bool transactional_v2,
        fk_owner_flow_binding_creation_receipt *creation_receipt) {
    clear_binding(binding);
    if (creation_receipt != nullptr)
        *creation_receipt = {};
    fk_owner_flow_binding_result error = FK_OWNER_FLOW_BINDING_INVALID;
    BindingsImpl *state = bindings == nullptr
        ? nullptr : implementation(bindings);
    OwnerState *owner = owner_for_operation(state, owner_index, error);
    if (owner == nullptr)
        return error;
    owner->counters.bind_attempts.fetch_add(1u, std::memory_order_relaxed);
    DecodedLogicalId decoded{};
    if ((transactional_v2 && creation_receipt == nullptr) ||
        (!transactional_v2 && creation_receipt != nullptr) ||
        !valid_handle(handle) ||
        admitted_identity_first_canonical_direction > 1u ||
        current_logical_feature_direction > 1u || binding == nullptr ||
        !decode_logical_id(*state, *owner, logical_connection_id, decoded)) {
        if ((transactional_v2 && creation_receipt == nullptr) ||
            (!transactional_v2 && creation_receipt != nullptr) ||
            !valid_handle(handle) ||
            admitted_identity_first_canonical_direction > 1u ||
            current_logical_feature_direction > 1u || binding == nullptr) {
            owner->counters.invalid_requests.fetch_add(
                1u, std::memory_order_relaxed);
        }
        return FK_OWNER_FLOW_BINDING_INVALID;
    }
    if (transactional_v2 &&
        owner->active_creation_epoch.load(std::memory_order_acquire) != 0u) {
        owner->counters.bind_conflicts.fetch_add(
            1u, std::memory_order_relaxed);
        return FK_OWNER_FLOW_BINDING_CONFLICT;
    }
    const uint8_t axis = direction_axis(
        admitted_identity_first_canonical_direction,
        current_logical_feature_direction);
    const uint64_t desired_handle = pack_handle_axis(handle, axis);
    BindingEntry &slot = state->entries[decoded.slot];
    uint64_t creation_epoch = 0u;

    for (uint32_t attempt = 0u; attempt < 2u; ++attempt) {
        const EntrySnapshot entry = snapshot(slot);
        const EntryMatch match = match_entry(
            *state, entry, owner_index, decoded.generation);
        if (match == MATCH_FREE) {
            if (transactional_v2 && creation_epoch == 0u) {
                const uint64_t previous = owner->last_creation_epoch.load(
                    std::memory_order_relaxed);
                if (previous == std::numeric_limits<uint64_t>::max()) {
                    owner->counters.state_integrity_failures.fetch_add(
                        1u, std::memory_order_relaxed);
                    return FK_OWNER_FLOW_BINDING_STATE_INTEGRITY_FAILURE;
                }
                creation_epoch = previous + 1u;
                owner->last_creation_epoch.store(
                    creation_epoch, std::memory_order_relaxed);
            }
            uint64_t expected_free = 0u;
            const uint64_t claimed = pack_identity(
                decoded.generation,
                owner_index,
                ENTRY_RETIRED_PENDING_CID_ACK);
            if (!slot.identity_word.compare_exchange_strong(
                    expected_free,
                    claimed,
                    std::memory_order_acq_rel,
                    std::memory_order_acquire))
                continue;
            slot.handle_axis_word.store(
                desired_handle, std::memory_order_relaxed);
            slot.identity_word.store(
                pack_identity(
                    decoded.generation,
                    owner_index,
                    ENTRY_BOUND,
                    transactional_v2),
                std::memory_order_release);
            increment_bound(*owner);
            owner->counters.bindings_created.fetch_add(
                1u, std::memory_order_relaxed);
            const EntrySnapshot created = snapshot(slot);
            if (!export_binding(decoded.slot, created, binding))
                return match_failure(
                    *owner, MATCH_TRANSIENT_OR_CORRUPT, false);
            if (transactional_v2) {
                owner->active_creation_epoch.store(
                    creation_epoch, std::memory_order_release);
                issue_creation_receipt(
                    *state,
                    owner_index,
                    false,
                    creation_epoch,
                    logical_connection_id,
                    desired_handle,
                    *creation_receipt);
            }
            return FK_OWNER_FLOW_BINDING_CREATED;
        }
        if (match == MATCH_UNBOUND) {
            if (transactional_v2 && creation_epoch == 0u) {
                const uint64_t previous = owner->last_creation_epoch.load(
                    std::memory_order_relaxed);
                if (previous == std::numeric_limits<uint64_t>::max()) {
                    owner->counters.state_integrity_failures.fetch_add(
                        1u, std::memory_order_relaxed);
                    return FK_OWNER_FLOW_BINDING_STATE_INTEGRITY_FAILURE;
                }
                creation_epoch = previous + 1u;
                owner->last_creation_epoch.store(
                    creation_epoch, std::memory_order_relaxed);
            }
            slot.identity_word.store(
                pack_identity(
                    decoded.generation,
                    owner_index,
                    ENTRY_RETIRED_PENDING_CID_ACK),
                std::memory_order_release);
            slot.handle_axis_word.store(
                desired_handle, std::memory_order_relaxed);
            slot.identity_word.store(
                pack_identity(
                    decoded.generation,
                    owner_index,
                    ENTRY_BOUND,
                    transactional_v2),
                std::memory_order_release);
            owner->unbound_slots.fetch_sub(1u, std::memory_order_relaxed);
            increment_bound(*owner);
            owner->counters.bindings_created.fetch_add(
                1u, std::memory_order_relaxed);
            const EntrySnapshot rebound = snapshot(slot);
            if (!export_binding(decoded.slot, rebound, binding))
                return match_failure(
                    *owner, MATCH_TRANSIENT_OR_CORRUPT, false);
            if (transactional_v2) {
                owner->active_creation_epoch.store(
                    creation_epoch, std::memory_order_release);
                issue_creation_receipt(
                    *state,
                    owner_index,
                    true,
                    creation_epoch,
                    logical_connection_id,
                    desired_handle,
                    *creation_receipt);
            }
            return FK_OWNER_FLOW_BINDING_CREATED;
        }
        if (match == MATCH_BOUND) {
            if (!export_binding(decoded.slot, entry, binding))
                return match_failure(
                    *owner, MATCH_TRANSIENT_OR_CORRUPT, false);
            if (unpack_direction_axis(entry.handle_axis) != axis) {
                owner->counters.bind_conflicts.fetch_add(
                    1u, std::memory_order_relaxed);
                owner->counters.direction_mismatch_rejects.fetch_add(
                    1u, std::memory_order_relaxed);
                return FK_OWNER_FLOW_BINDING_DIRECTION_MISMATCH;
            }
            if (!handles_equal(unpack_handle(entry.handle_axis), handle)) {
                owner->counters.bind_conflicts.fetch_add(
                    1u, std::memory_order_relaxed);
                owner->counters.handle_mismatch_rejects.fetch_add(
                    1u, std::memory_order_relaxed);
                return FK_OWNER_FLOW_BINDING_CONFLICT;
            }
            owner->counters.bind_idempotent.fetch_add(
                1u, std::memory_order_relaxed);
            return FK_OWNER_FLOW_BINDING_IDEMPOTENT;
        }
        return match_failure(*owner, match, true);
    }
    return match_failure(*owner, MATCH_TRANSIENT_OR_CORRUPT, true);
}

fk_owner_flow_binding_result fk_owner_flow_bindings_bind_from_admission(
        fk_owner_flow_bindings *bindings,
        uint16_t owner_index,
        uint64_t logical_connection_id,
        fk_owner_flow_handle handle,
        uint8_t admitted_identity_first_canonical_direction,
        uint8_t current_logical_feature_direction,
        fk_owner_flow_binding *binding) {
    return bind_from_admission_impl(
        bindings,
        owner_index,
        logical_connection_id,
        handle,
        admitted_identity_first_canonical_direction,
        current_logical_feature_direction,
        binding,
        false,
        nullptr);
}

fk_owner_flow_binding_result fk_owner_flow_bindings_bind_from_admission_v2(
        fk_owner_flow_bindings *bindings,
        uint16_t owner_index,
        uint64_t logical_connection_id,
        fk_owner_flow_handle handle,
        uint8_t admitted_identity_first_canonical_direction,
        uint8_t current_logical_feature_direction,
        fk_owner_flow_binding *binding,
        fk_owner_flow_binding_creation_receipt *creation_receipt) {
    return bind_from_admission_impl(
        bindings,
        owner_index,
        logical_connection_id,
        handle,
        admitted_identity_first_canonical_direction,
        current_logical_feature_direction,
        binding,
        true,
        creation_receipt);
}

fk_owner_flow_binding_result fk_owner_flow_bindings_bind_once(
        fk_owner_flow_bindings *bindings,
        uint16_t owner_index,
        uint64_t logical_connection_id,
        fk_owner_flow_handle handle,
        uint8_t first_canonical_direction,
        fk_owner_flow_binding *binding) {
    return fk_owner_flow_bindings_bind_from_admission(
        bindings,
        owner_index,
        logical_connection_id,
        handle,
        first_canonical_direction,
        0u,
        binding);
}

fk_owner_flow_binding_result
fk_owner_flow_bindings_compare_exchange_rebind_from_admission(
        fk_owner_flow_bindings *bindings,
        uint16_t owner_index,
        uint64_t logical_connection_id,
        fk_owner_flow_handle expected,
        fk_owner_flow_handle desired,
        uint8_t admitted_identity_first_canonical_direction,
        uint8_t current_logical_feature_direction,
        fk_owner_flow_binding *binding) {
    clear_binding(binding);
    fk_owner_flow_binding_result error = FK_OWNER_FLOW_BINDING_INVALID;
    BindingsImpl *state = bindings == nullptr
        ? nullptr : implementation(bindings);
    OwnerState *owner = owner_for_operation(state, owner_index, error);
    if (owner == nullptr)
        return error;
    owner->counters.rebind_attempts.fetch_add(1u, std::memory_order_relaxed);
    DecodedLogicalId decoded{};
    if (!valid_handle(expected) || !valid_handle(desired) ||
        admitted_identity_first_canonical_direction > 1u ||
        current_logical_feature_direction > 1u || binding == nullptr ||
        !decode_logical_id(*state, *owner, logical_connection_id, decoded)) {
        if (!valid_handle(expected) || !valid_handle(desired) ||
            admitted_identity_first_canonical_direction > 1u ||
            current_logical_feature_direction > 1u || binding == nullptr) {
            owner->counters.invalid_requests.fetch_add(
                1u, std::memory_order_relaxed);
        }
        return FK_OWNER_FLOW_BINDING_INVALID;
    }
    BindingEntry &slot = state->entries[decoded.slot];
    const EntrySnapshot entry = snapshot(slot);
    const EntryMatch match = match_entry(
        *state, entry, owner_index, decoded.generation);
    if (match == MATCH_FREE || match == MATCH_UNBOUND) {
        owner->counters.missing_binding_rejects.fetch_add(
            1u, std::memory_order_relaxed);
        return FK_OWNER_FLOW_BINDING_NOT_FOUND;
    }
    if (match != MATCH_BOUND)
        return match_failure(*owner, match, false);
    if (!export_binding(decoded.slot, entry, binding))
        return match_failure(*owner, MATCH_TRANSIENT_OR_CORRUPT, false);
    const fk_owner_flow_handle current = unpack_handle(entry.handle_axis);
    if (current.generation != expected.generation) {
        owner->counters.stale_generation_rejects.fetch_add(
            1u, std::memory_order_relaxed);
        return FK_OWNER_FLOW_BINDING_STALE_GENERATION;
    }
    if (current.index != expected.index) {
        owner->counters.handle_mismatch_rejects.fetch_add(
            1u, std::memory_order_relaxed);
        return FK_OWNER_FLOW_BINDING_HANDLE_MISMATCH;
    }
    const uint8_t axis = direction_axis(
        admitted_identity_first_canonical_direction,
        current_logical_feature_direction);
    const uint64_t desired_word = pack_handle_axis(desired, axis);
    if (entry.handle_axis == desired_word) {
        owner->counters.rebind_idempotent.fetch_add(
            1u, std::memory_order_relaxed);
        return FK_OWNER_FLOW_BINDING_IDEMPOTENT;
    }
    slot.handle_axis_word.store(desired_word, std::memory_order_release);
    const EntrySnapshot rebound = snapshot(slot);
    if (!export_binding(decoded.slot, rebound, binding))
        return match_failure(*owner, MATCH_TRANSIENT_OR_CORRUPT, false);
    owner->counters.rebind_success.fetch_add(1u, std::memory_order_relaxed);
    return FK_OWNER_FLOW_BINDING_REBOUND;
}

bool fk_owner_flow_binding_resolve_presentation_direction(
        const fk_owner_flow_binding *binding,
        uint8_t current_logical_feature_direction,
        uint8_t *presentation_canonical_direction) {
    if (binding == nullptr || presentation_canonical_direction == nullptr ||
        static_cast<uint32_t>(binding->logical_connection_id) == 0u ||
        static_cast<uint32_t>(binding->logical_connection_id >> 32u) == 0u ||
        !valid_handle(binding->handle) ||
        binding->logical_feature_to_presentation_direction_xor > 1u ||
        current_logical_feature_direction > 1u)
        return false;
    *presentation_canonical_direction =
        binding->logical_feature_to_presentation_direction_xor ^
        current_logical_feature_direction;
    return true;
}

fk_owner_flow_binding_result fk_owner_flow_bindings_release(
        fk_owner_flow_bindings *bindings,
        uint16_t owner_index,
        uint64_t logical_connection_id,
        fk_owner_flow_handle expected) {
    fk_owner_flow_binding_result error = FK_OWNER_FLOW_BINDING_INVALID;
    BindingsImpl *state = bindings == nullptr
        ? nullptr : implementation(bindings);
    OwnerState *owner = owner_for_operation(state, owner_index, error);
    if (owner == nullptr)
        return error;
    owner->counters.release_attempts.fetch_add(1u, std::memory_order_relaxed);
    DecodedLogicalId decoded{};
    if (!valid_handle(expected) ||
        !decode_logical_id(*state, *owner, logical_connection_id, decoded)) {
        if (!valid_handle(expected))
            owner->counters.invalid_requests.fetch_add(
                1u, std::memory_order_relaxed);
        return FK_OWNER_FLOW_BINDING_INVALID;
    }
    BindingEntry &slot = state->entries[decoded.slot];
    const EntrySnapshot entry = snapshot(slot);
    const EntryMatch match = match_entry(
        *state, entry, owner_index, decoded.generation);
    if (match == MATCH_FREE || match == MATCH_UNBOUND) {
        owner->counters.missing_binding_rejects.fetch_add(
            1u, std::memory_order_relaxed);
        return FK_OWNER_FLOW_BINDING_NOT_FOUND;
    }
    if (match != MATCH_BOUND)
        return match_failure(*owner, match, false);
    const fk_owner_flow_handle current = unpack_handle(entry.handle_axis);
    if (current.generation != expected.generation) {
        owner->counters.stale_generation_rejects.fetch_add(
            1u, std::memory_order_relaxed);
        return FK_OWNER_FLOW_BINDING_STALE_GENERATION;
    }
    if (current.index != expected.index) {
        owner->counters.handle_mismatch_rejects.fetch_add(
            1u, std::memory_order_relaxed);
        return FK_OWNER_FLOW_BINDING_HANDLE_MISMATCH;
    }
    slot.identity_word.store(
        pack_identity(
            decoded.generation,
            owner_index,
            ENTRY_RETIRED_PENDING_CID_ACK),
        std::memory_order_release);
    slot.handle_axis_word.store(0u, std::memory_order_relaxed);
    slot.identity_word.store(
        pack_identity(decoded.generation, owner_index, ENTRY_UNBOUND),
        std::memory_order_release);
    owner->active_bindings.fetch_sub(1u, std::memory_order_relaxed);
    increment_unbound(*owner);
    owner->counters.releases.fetch_add(1u, std::memory_order_relaxed);
    return FK_OWNER_FLOW_BINDING_RELEASED;
}

bool fk_owner_flow_bindings_commit_creation_v2(
        fk_owner_flow_bindings *bindings,
        uint16_t owner_index,
        uint64_t logical_connection_id,
        fk_owner_flow_handle expected,
        const fk_owner_flow_binding_creation_receipt *creation_receipt) {
    fk_owner_flow_binding_result error = FK_OWNER_FLOW_BINDING_INVALID;
    BindingsImpl *state = bindings == nullptr
        ? nullptr : implementation(bindings);
    OwnerState *owner = owner_for_operation(state, owner_index, error);
    if (owner == nullptr)
        return false;
    DecodedLogicalId decoded{};
    bool prior_unbound = false;
    uint64_t receipt_handle_axis = 0u;
    if (!decode_logical_id(
            *state, *owner, logical_connection_id, decoded) ||
        !creation_receipt_matches(
            *state,
            *owner,
            owner_index,
            logical_connection_id,
            expected,
            creation_receipt,
            prior_unbound,
            receipt_handle_axis)) {
        owner->counters.invalid_requests.fetch_add(
            1u, std::memory_order_relaxed);
        return false;
    }
    (void)prior_unbound;
    BindingEntry &slot = state->entries[decoded.slot];
    const EntrySnapshot entry = snapshot(slot);
    const uint64_t unpublished_identity = pack_identity(
        decoded.generation, owner_index, ENTRY_BOUND, true);
    if (entry.identity != unpublished_identity ||
        entry.handle_axis != receipt_handle_axis ||
        owner->active_bindings.load(std::memory_order_relaxed) == 0u) {
        owner->counters.state_integrity_failures.fetch_add(
            1u, std::memory_order_relaxed);
        return false;
    }
    uint64_t expected_identity = unpublished_identity;
    if (!slot.identity_word.compare_exchange_strong(
            expected_identity,
            pack_identity(decoded.generation, owner_index, ENTRY_BOUND),
            std::memory_order_release,
            std::memory_order_acquire)) {
        owner->counters.state_integrity_failures.fetch_add(
            1u, std::memory_order_relaxed);
        return false;
    }
    owner->active_creation_epoch.store(0u, std::memory_order_release);
    return true;
}

bool fk_owner_flow_bindings_abort_unpublished_creation_v2(
        fk_owner_flow_bindings *bindings,
        uint16_t owner_index,
        uint64_t logical_connection_id,
        fk_owner_flow_handle expected,
        const fk_owner_flow_binding_creation_receipt *creation_receipt) {
    fk_owner_flow_binding_result error = FK_OWNER_FLOW_BINDING_INVALID;
    BindingsImpl *state = bindings == nullptr
        ? nullptr : implementation(bindings);
    OwnerState *owner = owner_for_operation(state, owner_index, error);
    if (owner == nullptr)
        return false;
    DecodedLogicalId decoded{};
    bool prior_unbound = false;
    uint64_t receipt_handle_axis = 0u;
    if (!decode_logical_id(
            *state, *owner, logical_connection_id, decoded) ||
        !creation_receipt_matches(
            *state,
            *owner,
            owner_index,
            logical_connection_id,
            expected,
            creation_receipt,
            prior_unbound,
            receipt_handle_axis)) {
        owner->counters.invalid_requests.fetch_add(
            1u, std::memory_order_relaxed);
        return false;
    }
    BindingEntry &slot = state->entries[decoded.slot];
    const EntrySnapshot entry = snapshot(slot);
    const uint64_t unpublished_identity = pack_identity(
        decoded.generation, owner_index, ENTRY_BOUND, true);
    if (entry.identity != unpublished_identity ||
        entry.handle_axis != receipt_handle_axis ||
        owner->active_bindings.load(std::memory_order_relaxed) == 0u) {
        owner->counters.state_integrity_failures.fetch_add(
            1u, std::memory_order_relaxed);
        return false;
    }
    /* RETIRED is a transient publication barrier: no reader can combine a
     * restored FREE/UNBOUND identity with the unpublished nonzero handle. */
    uint64_t expected_identity = unpublished_identity;
    if (!slot.identity_word.compare_exchange_strong(
            expected_identity,
            pack_identity(
                decoded.generation,
                owner_index,
                ENTRY_RETIRED_PENDING_CID_ACK),
            std::memory_order_acq_rel,
            std::memory_order_acquire)) {
        owner->counters.state_integrity_failures.fetch_add(
            1u, std::memory_order_relaxed);
        return false;
    }
    slot.handle_axis_word.store(0u, std::memory_order_relaxed);
    if (prior_unbound) {
        slot.identity_word.store(
            pack_identity(decoded.generation, owner_index, ENTRY_UNBOUND),
            std::memory_order_release);
    } else {
        slot.identity_word.store(0u, std::memory_order_release);
    }
    owner->active_bindings.fetch_sub(1u, std::memory_order_relaxed);
    if (prior_unbound)
        increment_unbound(*owner);
    owner->active_creation_epoch.store(0u, std::memory_order_release);
    return true;
}

bool fk_owner_flow_bindings_abort_unpublished_creation(
        fk_owner_flow_bindings *bindings,
        uint16_t owner_index,
        uint64_t logical_connection_id,
        fk_owner_flow_handle expected) {
    fk_owner_flow_binding_result error = FK_OWNER_FLOW_BINDING_INVALID;
    BindingsImpl *state = bindings == nullptr
        ? nullptr : implementation(bindings);
    OwnerState *owner = owner_for_operation(state, owner_index, error);
    if (owner == nullptr)
        return false;
    (void)logical_connection_id;
    (void)expected;
    /* The old API has no creation capability and therefore cannot
     * distinguish an unpublished transaction from an established binding. */
    owner->counters.invalid_requests.fetch_add(1u, std::memory_order_relaxed);
    return false;
}

fk_owner_flow_binding_result fk_owner_flow_bindings_retire_connection(
        fk_owner_flow_bindings *bindings,
        uint16_t owner_index,
        uint64_t logical_connection_id,
        bool binding_expected,
        fk_owner_flow_binding *retired_binding) {
    clear_binding(retired_binding);
    fk_owner_flow_binding_result error = FK_OWNER_FLOW_BINDING_INVALID;
    BindingsImpl *state = bindings == nullptr
        ? nullptr : implementation(bindings);
    OwnerState *owner = owner_for_operation(state, owner_index, error);
    if (owner == nullptr)
        return error;
    owner->counters.retire_prepare_attempts.fetch_add(
        1u, std::memory_order_relaxed);
    DecodedLogicalId decoded{};
    if (!decode_logical_id(
            *state, *owner, logical_connection_id, decoded))
        return FK_OWNER_FLOW_BINDING_INVALID;
    BindingEntry &slot = state->entries[decoded.slot];
    for (uint32_t attempt = 0u; attempt < 2u; ++attempt) {
        const EntrySnapshot entry = snapshot(slot);
        const EntryMatch match = match_entry(
            *state, entry, owner_index, decoded.generation);
        if (match == MATCH_RETIRED) {
            if (retired_binding != nullptr &&
                !export_binding(decoded.slot, entry, retired_binding))
                return match_failure(
                    *owner, MATCH_TRANSIENT_OR_CORRUPT, false);
            owner->counters.retire_prepare_idempotent.fetch_add(
                1u, std::memory_order_relaxed);
            return FK_OWNER_FLOW_BINDING_RETIRE_PREPARE_IDEMPOTENT;
        }
        if (match == MATCH_FREE) {
            if (binding_expected) {
                owner->counters.retire_expectation_mismatch_rejects.fetch_add(
                    1u, std::memory_order_relaxed);
                return FK_OWNER_FLOW_BINDING_RETIRE_EXPECTATION_MISMATCH;
            }
            uint64_t expected_free = 0u;
            const uint64_t retired = pack_identity(
                decoded.generation,
                owner_index,
                ENTRY_RETIRED_PENDING_CID_ACK);
            if (!slot.identity_word.compare_exchange_strong(
                    expected_free,
                    retired,
                    std::memory_order_acq_rel,
                    std::memory_order_acquire))
                continue;
            increment_retired_pending(*owner);
            owner->counters.retire_prepared_absent.fetch_add(
                1u, std::memory_order_relaxed);
            if (retired_binding != nullptr)
                retired_binding->logical_connection_id = logical_connection_id;
            return FK_OWNER_FLOW_BINDING_RETIRE_PREPARED;
        }
        if (match != MATCH_BOUND && match != MATCH_UNBOUND)
            return match_failure(*owner, match, false);
        if (!binding_expected) {
            owner->counters.retire_expectation_mismatch_rejects.fetch_add(
                1u, std::memory_order_relaxed);
            return FK_OWNER_FLOW_BINDING_RETIRE_EXPECTATION_MISMATCH;
        }
        if (retired_binding != nullptr &&
            !export_binding(decoded.slot, entry, retired_binding))
            return match_failure(*owner, MATCH_TRANSIENT_OR_CORRUPT, false);
        slot.identity_word.store(
            pack_identity(
                decoded.generation,
                owner_index,
                ENTRY_RETIRED_PENDING_CID_ACK),
            std::memory_order_release);
        if (match == MATCH_BOUND) {
            owner->active_bindings.fetch_sub(1u, std::memory_order_relaxed);
            owner->counters.retire_prepared_bound.fetch_add(
                1u, std::memory_order_relaxed);
        } else {
            owner->unbound_slots.fetch_sub(1u, std::memory_order_relaxed);
            owner->counters.retire_prepared_unbound.fetch_add(
                1u, std::memory_order_relaxed);
        }
        increment_retired_pending(*owner);
        return FK_OWNER_FLOW_BINDING_RETIRE_PREPARED;
    }
    return match_failure(*owner, MATCH_TRANSIENT_OR_CORRUPT, false);
}

fk_owner_flow_binding_result
fk_owner_flow_bindings_finalize_retire_exact(
        fk_owner_flow_bindings *bindings,
        uint16_t owner_index,
        uint64_t logical_connection_id) {
    fk_owner_flow_binding_result error = FK_OWNER_FLOW_BINDING_INVALID;
    BindingsImpl *state = bindings == nullptr
        ? nullptr : implementation(bindings);
    OwnerState *owner = owner_for_operation(state, owner_index, error);
    if (owner == nullptr)
        return error;
    owner->counters.retire_finalize_attempts.fetch_add(
        1u, std::memory_order_relaxed);
    DecodedLogicalId decoded{};
    if (!decode_logical_id(
            *state, *owner, logical_connection_id, decoded))
        return FK_OWNER_FLOW_BINDING_INVALID;
    BindingEntry &slot = state->entries[decoded.slot];
    const EntrySnapshot entry = snapshot(slot);
    const EntryMatch match = match_entry(
        *state, entry, owner_index, decoded.generation);
    if (match == MATCH_FREE || match == MATCH_BOUND ||
        match == MATCH_UNBOUND) {
        owner->counters.retire_expectation_mismatch_rejects.fetch_add(
            1u, std::memory_order_relaxed);
        return FK_OWNER_FLOW_BINDING_RETIRE_EXPECTATION_MISMATCH;
    }
    if (match != MATCH_RETIRED)
        return match_failure(*owner, match, false);
    /*
     * The fixed owner is the sole writer for this slot and the CID callback
     * still holds the CID-directory lock.  Once the exact retired marker has
     * been validated there must be no fallible half-finalized path: clear the
     * retained (possibly already stale) FlowTable handle first, then publish
     * FREE.  A retry after FlowTable cleanup may find the handle already
     * absent at the FlowTable, but the binding marker remains durable until
     * this publication.
     */
    slot.handle_axis_word.store(0u, std::memory_order_release);
    slot.identity_word.store(0u, std::memory_order_release);
    owner->retired_pending_cid_ack_slots.fetch_sub(
        1u, std::memory_order_relaxed);
    owner->counters.retire_finalize_success.fetch_add(
        1u, std::memory_order_relaxed);
    return FK_OWNER_FLOW_BINDING_RETIRE_FINALIZED;
}

fk_owner_flow_binding_scan_result
fk_owner_flow_bindings_inspect_next_active(
        fk_owner_flow_bindings *bindings,
        uint16_t owner_index,
        uint32_t *cursor,
        uint32_t maximum_slots_to_scan,
        fk_owner_flow_binding *binding,
        uint32_t *slots_scanned) {
    clear_binding(binding);
    if (slots_scanned != nullptr)
        *slots_scanned = 0u;
    fk_owner_flow_binding_result ownership_error =
        FK_OWNER_FLOW_BINDING_INVALID;
    BindingsImpl *state = bindings == nullptr
        ? nullptr : implementation(bindings);
    OwnerState *owner =
        owner_for_operation(state, owner_index, ownership_error);
    if (owner == nullptr) {
        return ownership_error == FK_OWNER_FLOW_BINDING_NOT_OWNER
            ? FK_OWNER_FLOW_BINDING_SCAN_NOT_OWNER
            : FK_OWNER_FLOW_BINDING_SCAN_INVALID;
    }
    owner->counters.scan_calls.fetch_add(1u, std::memory_order_relaxed);
    const uint32_t capacity = state->config.maximum_connection_slots;
    if (cursor == nullptr || binding == nullptr || slots_scanned == nullptr ||
        maximum_slots_to_scan == 0u || *cursor > capacity) {
        owner->counters.invalid_requests.fetch_add(
            1u, std::memory_order_relaxed);
        return FK_OWNER_FLOW_BINDING_SCAN_INVALID;
    }
    const uint32_t start = *cursor;
    const uint32_t remaining = capacity - start;
    const uint32_t limit = maximum_slots_to_scan < remaining
        ? maximum_slots_to_scan : remaining;
    for (uint32_t offset = 0u; offset < limit; ++offset) {
        const uint32_t slot_index = start + offset;
        const EntrySnapshot entry = snapshot(state->entries[slot_index]);
        *cursor = slot_index + 1u;
        *slots_scanned = offset + 1u;
        if (identity_word_valid(
                entry.identity, state->config.owner_count) &&
            identity_state(entry.identity) == ENTRY_BOUND &&
            !identity_unpublished(entry.identity) &&
            identity_owner(entry.identity) == owner_index) {
            owner->counters.scan_slots.fetch_add(
                *slots_scanned, std::memory_order_relaxed);
            if (!export_binding(slot_index, entry, binding)) {
                owner->counters.state_integrity_failures.fetch_add(
                    1u, std::memory_order_relaxed);
                return FK_OWNER_FLOW_BINDING_SCAN_INVALID;
            }
            owner->counters.scan_active.fetch_add(
                1u, std::memory_order_relaxed);
            if (*cursor == capacity && start < capacity) {
                owner->counters.scan_passes_completed.fetch_add(
                    1u, std::memory_order_relaxed);
            }
            return FK_OWNER_FLOW_BINDING_SCAN_ACTIVE;
        }
    }
    owner->counters.scan_slots.fetch_add(
        *slots_scanned, std::memory_order_relaxed);
    if (*cursor == capacity) {
        if (start < capacity) {
            owner->counters.scan_passes_completed.fetch_add(
                1u, std::memory_order_relaxed);
        }
        return FK_OWNER_FLOW_BINDING_SCAN_END;
    }
    return FK_OWNER_FLOW_BINDING_SCAN_MORE;
}

bool fk_owner_flow_bindings_get_owner_stats(
        const fk_owner_flow_bindings *bindings,
        uint16_t owner_index,
        fk_owner_flow_bindings_owner_stats *stats) {
    if (stats != nullptr)
        std::memset(stats, 0, sizeof(*stats));
    if (bindings == nullptr || stats == nullptr)
        return false;
    const BindingsImpl &state = *implementation(bindings);
    if (owner_index >= state.config.owner_count)
        return false;
    const OwnerState &owner = state.owners[owner_index];
    load_counters(owner.counters, stats->counters);
    stats->active_bindings =
        owner.active_bindings.load(std::memory_order_relaxed);
    stats->peak_active_bindings =
        owner.peak_active_bindings.load(std::memory_order_relaxed);
    stats->unbound_slots =
        owner.unbound_slots.load(std::memory_order_relaxed);
    stats->peak_unbound_slots =
        owner.peak_unbound_slots.load(std::memory_order_relaxed);
    stats->retired_pending_cid_ack_slots =
        owner.retired_pending_cid_ack_slots.load(std::memory_order_relaxed);
    stats->peak_retired_pending_cid_ack_slots =
        owner.peak_retired_pending_cid_ack_slots.load(
            std::memory_order_relaxed);
    stats->owner = owner_index;
    stats->owner_thread_claimed = static_cast<uint16_t>(
        owner.owner_thread_token.load(std::memory_order_acquire) != 0u);
    stats->maximum_connection_slots =
        state.config.maximum_connection_slots;
    return true;
}

bool fk_owner_flow_bindings_get_stats(
        const fk_owner_flow_bindings *bindings,
        fk_owner_flow_bindings_stats *stats) {
    if (stats != nullptr)
        std::memset(stats, 0, sizeof(*stats));
    if (bindings == nullptr || stats == nullptr)
        return false;
    const BindingsImpl &state = *implementation(bindings);
    stats->reserved_bytes = state.reserved_bytes;
    stats->owner_count = state.config.owner_count;
    stats->logical_id_abi_version = state.config.logical_id_abi_version;
    stats->maximum_connection_slots =
        state.config.maximum_connection_slots;
    stats->entry_bytes = FK_OWNER_FLOW_BINDING_ENTRY_BYTES;
    stats->retire_ack_required = state.config.retire_ack_required;
    stats->total_capacity = state.config.maximum_connection_slots;
    for (uint16_t owner_index = 0u;
         owner_index < state.config.owner_count; ++owner_index) {
        fk_owner_flow_bindings_owner_stats owner{};
        if (!fk_owner_flow_bindings_get_owner_stats(
                bindings, owner_index, &owner) ||
            !add_counters(stats->counters, owner.counters) ||
            !checked_add_u64(stats->active_bindings, owner.active_bindings) ||
            !checked_add_u64(
                stats->peak_active_bindings_sum,
                owner.peak_active_bindings) ||
            !checked_add_u64(stats->unbound_slots, owner.unbound_slots) ||
            !checked_add_u64(
                stats->peak_unbound_slots_sum,
                owner.peak_unbound_slots) ||
            !checked_add_u64(
                stats->retired_pending_cid_ack_slots,
                owner.retired_pending_cid_ack_slots) ||
            !checked_add_u64(
                stats->peak_retired_pending_cid_ack_slots_sum,
                owner.peak_retired_pending_cid_ack_slots))
            return false;
    }
    if (stats->active_bindings > stats->total_capacity ||
        stats->unbound_slots >
            stats->total_capacity - stats->active_bindings ||
        stats->retired_pending_cid_ack_slots >
            stats->total_capacity - stats->active_bindings -
                stats->unbound_slots)
        return false;
    stats->empty_slots = stats->total_capacity -
        stats->active_bindings - stats->unbound_slots -
        stats->retired_pending_cid_ack_slots;
    return true;
}

bool fk_owner_flow_bindings_accounting_conserved(
        const fk_owner_flow_bindings *bindings) {
    if (bindings == nullptr)
        return false;
    const BindingsImpl &state = *implementation(bindings);
    uint64_t observed_bound[64]{};
    uint64_t observed_unpublished[64]{};
    uint64_t observed_unbound[64]{};
    uint64_t observed_retired[64]{};
    uint64_t observed_empty = 0u;
    for (uint32_t slot = 0u;
         slot < state.config.maximum_connection_slots; ++slot) {
        const EntrySnapshot entry = snapshot(state.entries[slot]);
        if (entry.identity == 0u) {
            if (entry.handle_axis != 0u)
                return false;
            observed_empty++;
            continue;
        }
        if (!identity_word_valid(entry.identity, state.config.owner_count))
            return false;
        const uint16_t owner = identity_owner(entry.identity);
        if (identity_state(entry.identity) == ENTRY_BOUND) {
            if (!handle_axis_word_valid(entry.handle_axis))
                return false;
            observed_bound[owner]++;
            if (identity_unpublished(entry.identity))
                observed_unpublished[owner]++;
        } else if (identity_state(entry.identity) == ENTRY_UNBOUND) {
            if (entry.handle_axis != 0u)
                return false;
            observed_unbound[owner]++;
        } else if (identity_state(entry.identity) ==
                ENTRY_RETIRED_PENDING_CID_ACK) {
            if (entry.handle_axis != 0u &&
                !handle_axis_word_valid(entry.handle_axis))
                return false;
            observed_retired[owner]++;
        } else {
            return false;
        }
    }

    uint64_t summed_bound = 0u;
    uint64_t summed_unbound = 0u;
    uint64_t summed_retired = 0u;
    fk_owner_flow_binding_counters summed_counters{};
    for (uint16_t owner_index = 0u;
         owner_index < state.config.owner_count; ++owner_index) {
        fk_owner_flow_bindings_owner_stats owner{};
        const uint64_t active_creation_epoch =
            state.owners[owner_index].active_creation_epoch.load(
                std::memory_order_acquire);
        const uint64_t last_creation_epoch =
            state.owners[owner_index].last_creation_epoch.load(
                std::memory_order_acquire);
        if (!fk_owner_flow_bindings_get_owner_stats(
                bindings, owner_index, &owner) ||
            observed_unpublished[owner_index] > 1u ||
            ((active_creation_epoch != 0u) !=
                (observed_unpublished[owner_index] == 1u)) ||
            active_creation_epoch > last_creation_epoch ||
            owner.active_bindings != observed_bound[owner_index] ||
            owner.unbound_slots != observed_unbound[owner_index] ||
            owner.retired_pending_cid_ack_slots !=
                observed_retired[owner_index] ||
            !checked_add_u64(summed_bound, owner.active_bindings) ||
            !checked_add_u64(summed_unbound, owner.unbound_slots) ||
            !checked_add_u64(
                summed_retired,
                owner.retired_pending_cid_ack_slots) ||
            !add_counters(summed_counters, owner.counters))
            return false;
    }
    fk_owner_flow_bindings_stats global{};
    uint64_t observed_total = observed_empty;
    if (!checked_add_u64(observed_total, summed_bound) ||
        !checked_add_u64(observed_total, summed_unbound) ||
        !checked_add_u64(observed_total, summed_retired))
        return false;
    if (!fk_owner_flow_bindings_get_stats(bindings, &global) ||
        summed_bound != global.active_bindings ||
        summed_unbound != global.unbound_slots ||
        summed_retired != global.retired_pending_cid_ack_slots ||
        observed_empty != global.empty_slots ||
        observed_total != global.total_capacity ||
        global.reserved_bytes != state.reserved_bytes)
        return false;
#define CHECK_COUNTER_EQUAL(name) \
    if (summed_counters.name != global.counters.name) return false;
    FK_BINDING_COUNTER_FIELDS(CHECK_COUNTER_EQUAL)
#undef CHECK_COUNTER_EQUAL
    return true;
}

#ifdef FK_OWNER_FLOW_BINDINGS_TEST_HOOKS
bool fk_owner_flow_bindings_test_reserve_final_thread_token(void) {
    uint64_t observed =
        g_next_thread_token.load(std::memory_order_relaxed);
    while (observed != 0u) {
        if (g_next_thread_token.compare_exchange_weak(
                observed,
                std::numeric_limits<uint64_t>::max(),
                std::memory_order_relaxed,
                std::memory_order_relaxed)) {
            return true;
        }
    }
    return false;
}

uint64_t fk_owner_flow_bindings_test_current_thread_token(void) {
    return current_thread_token();
}
#endif

const char *fk_owner_flow_binding_result_name(
        fk_owner_flow_binding_result result) {
    switch (result) {
    case FK_OWNER_FLOW_BINDING_INVALID: return "invalid";
    case FK_OWNER_FLOW_BINDING_NOT_OWNER: return "not_owner";
    case FK_OWNER_FLOW_BINDING_NOT_FOUND: return "not_found";
    case FK_OWNER_FLOW_BINDING_FOUND: return "found";
    case FK_OWNER_FLOW_BINDING_CREATED: return "created";
    case FK_OWNER_FLOW_BINDING_IDEMPOTENT: return "idempotent";
    case FK_OWNER_FLOW_BINDING_REBOUND: return "rebound";
    case FK_OWNER_FLOW_BINDING_RELEASED: return "released_to_unbound";
    case FK_OWNER_FLOW_BINDING_CONFLICT: return "flow_handle_conflict";
    case FK_OWNER_FLOW_BINDING_STALE_GENERATION:
        return "stale_flow_generation";
    case FK_OWNER_FLOW_BINDING_HANDLE_MISMATCH:
        return "flow_handle_mismatch";
    case FK_OWNER_FLOW_BINDING_DIRECTION_MISMATCH:
        return "direction_mismatch";
    case FK_OWNER_FLOW_BINDING_CID_GENERATION_MISMATCH:
        return "cid_generation_mismatch";
    case FK_OWNER_FLOW_BINDING_FIXED_OWNER_MISMATCH:
        return "fixed_owner_mismatch";
    case FK_OWNER_FLOW_BINDING_SLOT_REUSE_BEFORE_RETIRE_ACK:
        return "slot_reuse_before_retire_ack";
    case FK_OWNER_FLOW_BINDING_RETIRE_EXPECTATION_MISMATCH:
        return "retire_expectation_mismatch";
    case FK_OWNER_FLOW_BINDING_RETIRE_PREPARED:
        return "retire_prepared";
    case FK_OWNER_FLOW_BINDING_RETIRE_PREPARE_IDEMPOTENT:
        return "retire_prepare_idempotent";
    case FK_OWNER_FLOW_BINDING_RETIRE_FINALIZED:
        return "retire_finalized";
    case FK_OWNER_FLOW_BINDING_RETIRE_PENDING_CID_ACK:
        return "retire_pending_cid_ack";
    case FK_OWNER_FLOW_BINDING_STATE_INTEGRITY_FAILURE:
        return "state_integrity_failure";
    }
    return "unknown";
}

const char *fk_owner_flow_binding_scan_result_name(
        fk_owner_flow_binding_scan_result result) {
    switch (result) {
    case FK_OWNER_FLOW_BINDING_SCAN_INVALID: return "invalid";
    case FK_OWNER_FLOW_BINDING_SCAN_NOT_OWNER: return "not_owner";
    case FK_OWNER_FLOW_BINDING_SCAN_ACTIVE: return "active";
    case FK_OWNER_FLOW_BINDING_SCAN_MORE: return "more";
    case FK_OWNER_FLOW_BINDING_SCAN_END: return "end";
    }
    return "unknown";
}

}  // extern "C"
