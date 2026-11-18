#include "fk_compact_flow_table.h"
#include "fk_evidence_archive.h"
#include "fk_slab_pool.h"
#include "fk_m1_watch.h"

#include <algorithm>
#include <array>
#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <limits>
#include <memory>
#include <new>
#include <vector>

namespace {

constexpr uint32_t kNoIndex = std::numeric_limits<uint32_t>::max();
constexpr uint8_t kSlotEmpty = 0u;
constexpr uint8_t kSlotOccupied = 1u;
constexpr uint8_t kSlotTombstone = 2u;
constexpr uint8_t kJa4ModePending = 0u;
constexpr uint8_t kJa4ModeSummary = 1u;
constexpr uint8_t kJa4ModeProvisional = 2u;
constexpr uint8_t kValueHeapStat = 0u;
constexpr uint8_t kValueHeapSeq = 1u;
constexpr uint8_t kValueHeapJa4Pending = 2u;
constexpr uint8_t kValueHeapJa4Summary = 3u;
constexpr uint8_t kValueHeapCount = 4u;
constexpr uint32_t kAtomicMaximumVictimFlows = 64u;
constexpr uint32_t kAtomicMaximumVictimComponents =
    kAtomicMaximumVictimFlows * 3u;
/* The Real X710 trace reached one eight-candidate collision at only 48.1%
 * per-shard peak load (13,989 live continuation entries, 14,437 stores).
 * Sixty-four double-hash candidates retain a fixed admission bound while
 * providing headroom for the denser portion of the frozen trace.  Tiny
 * fixtures inspect every distinct slot once. */
constexpr uint32_t kContinuationProbeLimit =
    FK_COMPACT_CAPACITY_CONTINUATION_PROBE_LIMIT;
constexpr uint32_t kContinuationExpirationSweepSteps =
    FK_COMPACT_CAPACITY_CONTINUATION_EXPIRATION_SWEEP_STEPS;
constexpr uint32_t kContinuationMinimumCapacity = 4u;
/* Four retained generations per resident flow is the frozen capacity safety
 * envelope.  A smaller compile-time multiplier is available only for isolated
 * Development A/B builds; it must not enter a promoted receiver unless the
 * five-dataset quality gate proves non-regression. */
#ifndef FK_CONTROLLED_CONTINUATION_ENTRIES_PER_FLOW
#define FK_CONTROLLED_CONTINUATION_ENTRIES_PER_FLOW 4u
#endif
constexpr uint32_t kControlledContinuationEntriesPerFlow =
    FK_CONTROLLED_CONTINUATION_ENTRIES_PER_FLOW;
constexpr uint32_t kFullContinuationEntriesPerFlow = 4u;
static_assert(kControlledContinuationEntriesPerFlow >= 1u &&
              kControlledContinuationEntriesPerFlow <=
                  kFullContinuationEntriesPerFlow,
              "controlled continuation multiplier must stay bounded");
constexpr uint8_t kTcpLifecycleSynSeen = 1u << 0u;
constexpr uint8_t kTcpLifecycleEstablished = 1u << 1u;
constexpr uint8_t kTcpLifecycleFinDirection0 = 1u << 2u;
constexpr uint8_t kTcpLifecycleFinDirection1 = 1u << 3u;
constexpr uint8_t kTcpLifecycleRstSeen = 1u << 4u;

enum class AtomicReplacementMode : uint8_t {
    None = 0u,
    Value = 1u,
    Lru = 2u,
    Lfu = 3u,
    Fifo = 4u,
    SeededRandom = 5u,
    Clock = 6u,
    TwoQ = 7u,
    Arc = 8u,
    Gdsf = 9u,
};

constexpr uint8_t kFixedTtlDeadlineFlag = 1u << 0u;
constexpr uint8_t kClockReferenceFlag = 1u << 1u;
constexpr uint8_t kTwoQFrequentFlag = 1u << 2u;
constexpr uint8_t kArcClassShift = 3u;
constexpr uint8_t kArcClassMask = 3u << kArcClassShift;
constexpr uint8_t kArcT1 = 0u << kArcClassShift;
constexpr uint8_t kArcT2 = 1u << kArcClassShift;
constexpr uint8_t kArcB1 = 2u << kArcClassShift;
constexpr uint8_t kArcB2 = 3u << kArcClassShift;

enum class AtomicFaultPoint : uint8_t {
    None = 0u,
    AfterFlowPlan = 1u,
    AfterVictimPlan = 2u,
    BeforeStoragePrepare = 3u,
    AfterStoragePrepare = 4u,
    BeforeBudgetCommit = 5u,
};

struct HashSlot {
    uint32_t core_index;
    uint16_t fingerprint;
    uint8_t state;
    uint8_t reserved;
};

/* The five Test corpora are overwhelmingly IPv4, but the former mandatory
 * core stored two 16-byte addresses for every flow.  Keep the common IPv4
 * identity inline and allocate the two IPv6 addresses only for an IPv6
 * generation.  Ports/protocol/version remain inline, so the side allocation
 * is exactly the 32 address bytes and no identity information is compressed
 * or hashed away. */
struct CompactFlowKey {
    union AddressStorage {
        uint32_t ipv4[2];
        uint8_t *ipv6;

        constexpr AddressStorage() : ipv4{0u, 0u} {}
    } addresses;
    uint16_t low_port;
    uint16_t high_port;
    uint8_t ip_version;
    uint8_t protocol;
    uint16_t reserved;
};

static_assert(sizeof(CompactFlowKey) == 16u,
              "IPv4 inline key must occupy two 64-bit words");

struct CoreEntry {
    uint64_t first_timestamp_ns;
    uint64_t last_timestamp_ns;
    uint64_t logical_connection_id;
    uint64_t packets;
    uint64_t bytes;
    uint16_t stat_index;
    uint16_t seq_index;
    uint16_t ja4_index;
    fk_component_flow component;
    CompactFlowKey key;
    fk_compact_bootstrap_state bootstrap;
    uint32_t hash_slot;
    uint32_t next_free;
    uint32_t generation;
    uint16_t value_heap_position[3];
    uint16_t direction_packets[2];
    uint16_t maximum_wire_size;
    uint8_t first_direction;
    uint8_t evidence_mask;
    uint8_t ja4_is_summary;
    uint8_t ja4_value_heap;
    uint8_t fixed_ttl_deadline;
    uint8_t used;
    uint8_t terminal_observed;
    uint8_t lifecycle_reserved;
    uint32_t optional_deadline_heap_position;
};

static uint8_t resident_component_mask(const CoreEntry &entry);

static uint8_t replacement_planning_mask(const CoreEntry &entry) {
    return entry.component.replacement_values_physical != 0u
        ? resident_component_mask(entry) : entry.component.mask;
}

static_assert(sizeof(CoreEntry) == 192u,
              "timer indexes must not enlarge the frozen core layout");

/* A stable flow handle names a logical slot, not a permanently committed
 * Core object.  Keep slots stable while committing 64 Core objects at a
 * time.  Empty pages can then be physically returned after terminal
 * demotion without changing hash indexes or generation semantics. */
constexpr uint32_t kCorePageEntries = 64u;

struct CorePage {
    std::unique_ptr<CoreEntry[]> entries;
    uint32_t active_entries = 0u;
};

struct CoreSlotMetadata {
    uint32_t next_free = kNoIndex;
    uint32_t generation = 0u;
};

static_assert(sizeof(CoreSlotMetadata) == 8u,
              "dynamic Core slot metadata must remain compact");

struct CoreStore {
    std::unique_ptr<CorePage[]> pages;
    uint32_t page_count = 0u;

    CoreEntry &operator[](uint32_t index) {
        return pages[index / kCorePageEntries]
            .entries[index % kCorePageEntries];
    }

    const CoreEntry &operator[](uint32_t index) const {
        return pages[index / kCorePageEntries]
            .entries[index % kCorePageEntries];
    }
};

static uint32_t core_page_count(uint32_t maximum_flows) {
    return maximum_flows == 0u ? 0u :
        (maximum_flows + kCorePageEntries - 1u) / kCorePageEntries;
}

static uint64_t dynamic_core_index_bytes(uint32_t maximum_flows) {
    return static_cast<uint64_t>(core_page_count(maximum_flows)) *
            sizeof(CorePage) +
        static_cast<uint64_t>(maximum_flows) * sizeof(CoreSlotMetadata);
}

/* A displaced generation has already lost every optional slab.  Retaining
 * the full fk_component_flow here used to duplicate owned-byte fields and
 * eight float action values that can never select resident evidence again.
 * Keep only the checkpoint/missing/deadline prefix that is read after a
 * continuation restore; later causal checkpoints may publish a fresh value
 * vector into the new live CoreEntry. */
struct CapacityContinuationComponent {
    uint8_t decision_started;
    uint8_t checkpoint_index;
    uint8_t observation_complete;
    uint8_t missing_reason[3];
    uint8_t next_checkpoint_packet;
    uint8_t component_start_packet[3];
    uint8_t released_mask;
};

static_assert(sizeof(CapacityContinuationComponent) == 11u,
              "continuation component prefix is part of the hard budget");

/* A compact copy of the mandatory prefix needed to continue checkpoint
 * numbering after admission-time displacement.  Slab indexes, owned bytes,
 * and stale replacement values are deliberately absent. */
struct CapacityContinuationEntry {
    uint64_t first_timestamp_ns;
    uint64_t last_timestamp_ns;
    uint64_t packets;
    uint64_t bytes;
    CapacityContinuationComponent component;
    fk_flow_key key;
    fk_compact_bootstrap_state bootstrap;
    uint16_t direction_packets[2];
    uint16_t maximum_wire_size;
    uint32_t initial_syn_sequence;
    uint32_t predecessor_flow_index;
    uint32_t predecessor_flow_generation;
    uint8_t first_direction;
    uint8_t fixed_ttl_deadline;
    uint8_t tcp_lifecycle;
    uint8_t valid;
};

static_assert(sizeof(CapacityContinuationEntry) == 136u,
              "continuation records are part of the frozen hard budget");

struct ContinuationPage {
    std::unique_ptr<CapacityContinuationEntry[]> entries;
    uint32_t active_entries;
};

/* Preserve the exact directory capacity and double-hash probe sequence, but
 * commit continuation payload in small independently zeroed pages.  An
 * absent page is semantically identical to eight empty records and therefore
 * does not change lookup, expiry, or replacement decisions. */
constexpr uint32_t kContinuationPageEntries = 8u;

static uint32_t continuation_page_count(uint32_t capacity) {
    return capacity == 0u ? 0u :
        (capacity + kContinuationPageEntries - 1u) /
            kContinuationPageEntries;
}

static uint64_t continuation_directory_index_bytes(uint32_t capacity) {
    return static_cast<uint64_t>(continuation_page_count(capacity)) *
        sizeof(ContinuationPage);
}

static uint64_t continuation_payload_bytes(uint32_t capacity) {
    return static_cast<uint64_t>(capacity) *
        sizeof(CapacityContinuationEntry);
}

/* Preserve the optional-pool envelope that predates the complete Core-Mini
 * layout.  The protected mandatory accounting envelope is 224 bytes per
 * flow: attempt33's 216-byte resident core plus the eight bytes per flow
 * that its separate value/deadline indexing still charged before those
 * indexes were folded into the compact layout.  Crediting only the resident
 * 216 bytes silently reinvested that second structural saving and enlarged
 * the typed pools (67/91/10/178 became 71/95/11/187 at the 32 MiB DataCon
 * point), which changed automatic pressure and detector inputs. */
constexpr uint64_t kProtectedCoreAndIndexEnvelopeBytes = 224u;
constexpr uint64_t kProtectedContinuationEntryBytes = 136u;

static uint64_t structural_compaction_credit(
        uint32_t maximum_flows,
        uint32_t continuation_capacity) {
    const uint64_t gross_credit = static_cast<uint64_t>(maximum_flows) *
            (kProtectedCoreAndIndexEnvelopeBytes - sizeof(CoreEntry)) +
        static_cast<uint64_t>(continuation_capacity) *
            (kProtectedContinuationEntryBytes -
             sizeof(CapacityContinuationEntry));
    const uint64_t dynamic_index_bytes =
        continuation_directory_index_bytes(continuation_capacity) +
        dynamic_core_index_bytes(maximum_flows);
    return gross_credit > dynamic_index_bytes
        ? gross_credit - dynamic_index_bytes : 0u;
}

struct CompactFlowTable {
    const fk_compact_lifecycle_guard *lifecycle_guard = nullptr;
    const fk_compact_idle_retirement_guard *idle_retirement_guard = nullptr;
    uint32_t pending_idle_retirements = 0u;
    bool idle_retirement_failed = false;
    uint32_t maximum_flows = 0u;
    uint32_t hash_capacity = 0u;
    uint32_t free_head = kNoIndex;
    uint32_t expiration_cursor = 0u;
    uint32_t timer_cursor = 0u;
    uint32_t continuation_expiration_cursor = 0u;
    uint32_t clock_replacement_hand = 0u;
    uint32_t arc_target_t1_entries = 0u;
    float gdsf_aging_priority = 0.0f;
    fk_compact_retention_metadata_mode retention_metadata_mode =
        FK_COMPACT_RETENTION_METADATA_NONE;
    uint64_t expiration_cycle_min_last_timestamp_ns = UINT64_MAX;
    uint64_t expiration_scan_not_before_ns = 0u;
    fk_component_policy_config policy{};
    fk_state_budget *budget = nullptr;
    fk_slab_pool *stat_pool = nullptr;
    fk_slab_pool *seq_pool = nullptr;
    fk_slab_pool *ja4_pending_pool = nullptr;
    fk_slab_pool *ja4_summary_pool = nullptr;
    std::unique_ptr<HashSlot[]> slots;
    CoreStore cores;
    std::unique_ptr<CoreSlotMetadata[]> core_slots;
    std::unique_ptr<ContinuationPage[]> continuation_pages;
    uint32_t continuation_capacity = 0u;
    uint32_t continuation_entries = 0u;
    uint64_t continuation_maximum_gap_ns = 0u;
    std::unique_ptr<uint32_t[]> value_heaps[kValueHeapCount];
    uint32_t value_heap_size[kValueHeapCount]{};
    uint32_t value_heap_capacity[kValueHeapCount]{};
    std::array<fk_compact_evidence_transition,
               FK_COMPACT_TRANSITION_CAPACITY> transitions{};
    uint32_t transition_head = 0u;
    uint32_t transition_count = 0u;
    uint64_t next_transition_sequence = 0u;
    /* Wide-only storage reuses the frozen cached-deadline footprint.  At
     * <=65536 flows deadline indexes occupy the upper halves of value words. */
    std::unique_ptr<uint32_t[]> optional_deadline_heap;
    mutable uint64_t timer_deadline_queries = 0u;
    mutable uint64_t timer_deadline_rebuilds = 0u;
    mutable uint64_t timer_deadline_probes = 0u;
    uint32_t optional_deadline_heap_size = 0u;
#ifdef FK_COMPACT_FLOW_TABLE_TEST_HOOKS
    AtomicFaultPoint atomic_fault_point = AtomicFaultPoint::None;
#endif
    fk_compact_value_eviction_config value_eviction{
        FK_VALUE_EVICTION_DEFAULT_ETA,
        FK_VALUE_EVICTION_DEFAULT_EPSILON,
        FK_VALUE_EVICTION_DEFAULT_MAX_VICTIMS,
    };
    fk_compact_flow_table_stats stats{};
};

#ifndef FK_COMPACT_FLOW_TABLE_TEST_HOOKS
static_assert(sizeof(CompactFlowTable) == 140360u,
              "production FlowTable layout is part of the frozen budget");
#endif

static CompactFlowTable *implementation(fk_compact_flow_table *table) {
    return reinterpret_cast<CompactFlowTable *>(table);
}

static const CompactFlowTable *implementation(
        const fk_compact_flow_table *table) {
    return reinterpret_cast<const CompactFlowTable *>(table);
}

/* Cache baselines share the frozen Core allocation.  Their compact metadata
 * occupies otherwise policy-specific flag/value fields, so it is included
 * in the same byte budget and does not create an uncharged side table. */
static void note_retention_access(
        CompactFlowTable &table, CoreEntry &entry) {
    if (table.retention_metadata_mode ==
            FK_COMPACT_RETENTION_METADATA_NONE ||
        table.retention_metadata_mode ==
            FK_COMPACT_RETENTION_METADATA_GDSF)
        return;
    if (table.retention_metadata_mode ==
            FK_COMPACT_RETENTION_METADATA_CLOCK) {
        entry.fixed_ttl_deadline |= kClockReferenceFlag;
        return;
    }
    if (table.retention_metadata_mode ==
            FK_COMPACT_RETENTION_METADATA_TWO_Q) {
        if (entry.packets >= 2u)
            entry.fixed_ttl_deadline |= kTwoQFrequentFlag;
        return;
    }
    const uint8_t arc_class = static_cast<uint8_t>(
        entry.fixed_ttl_deadline & kArcClassMask);
    if (arc_class == kArcB1) {
        if (table.arc_target_t1_entries < table.maximum_flows)
            ++table.arc_target_t1_entries;
        entry.fixed_ttl_deadline = static_cast<uint8_t>(
            (entry.fixed_ttl_deadline & ~kArcClassMask) | kArcT2);
    } else if (arc_class == kArcB2) {
        if (table.arc_target_t1_entries != 0u)
            --table.arc_target_t1_entries;
        entry.fixed_ttl_deadline = static_cast<uint8_t>(
            (entry.fixed_ttl_deadline & ~kArcClassMask) | kArcT2);
    } else if (arc_class == kArcT1 && entry.packets >= 2u) {
        entry.fixed_ttl_deadline = static_cast<uint8_t>(
            (entry.fixed_ttl_deadline & ~kArcClassMask) | kArcT2);
    }
}

static bool compact_key_materialize(
        const CompactFlowKey &compact,
        fk_flow_key &key) {
    key = {};
    key.ip_version = compact.ip_version;
    key.protocol = compact.protocol;
    key.low_port = compact.low_port;
    key.high_port = compact.high_port;
    if (compact.ip_version == 4u) {
        std::memcpy(key.low_addr, &compact.addresses.ipv4[0], 4u);
        std::memcpy(key.high_addr, &compact.addresses.ipv4[1], 4u);
        return true;
    }
    if (compact.ip_version != 6u || compact.addresses.ipv6 == nullptr)
        return false;
    std::memcpy(key.low_addr, compact.addresses.ipv6, 16u);
    std::memcpy(key.high_addr, compact.addresses.ipv6 + 16u, 16u);
    return true;
}

static bool compact_key_equal(
        const CompactFlowKey &compact,
        const fk_flow_key &key) {
    if (compact.ip_version != key.ip_version ||
        compact.protocol != key.protocol ||
        compact.low_port != key.low_port ||
        compact.high_port != key.high_port)
        return false;
    if (compact.ip_version == 4u) {
        return std::memcmp(
                   &compact.addresses.ipv4[0], key.low_addr, 4u) == 0 &&
            std::memcmp(
                   &compact.addresses.ipv4[1], key.high_addr, 4u) == 0;
    }
    return compact.ip_version == 6u && compact.addresses.ipv6 != nullptr &&
        std::memcmp(compact.addresses.ipv6, key.low_addr, 16u) == 0 &&
        std::memcmp(compact.addresses.ipv6 + 16u, key.high_addr, 16u) == 0;
}

static bool compact_key_assign(
        CompactFlowTable &table,
        CompactFlowKey &compact,
        const fk_flow_key &key) {
    if (key.ip_version != 4u && key.ip_version != 6u)
        return false;
    compact = {};
    compact.ip_version = key.ip_version;
    compact.protocol = key.protocol;
    compact.low_port = key.low_port;
    compact.high_port = key.high_port;
    if (key.ip_version == 4u) {
        std::memcpy(&compact.addresses.ipv4[0], key.low_addr, 4u);
        std::memcpy(&compact.addresses.ipv4[1], key.high_addr, 4u);
        return true;
    }
    constexpr uint64_t kIpv6SideBytes = 32u;
    if (!fk_state_budget_try_reserve(
            table.budget, FK_MEMORY_CORE, kIpv6SideBytes))
        return false;
    compact.addresses.ipv6 =
        new (std::nothrow) uint8_t[kIpv6SideBytes];
    if (compact.addresses.ipv6 == nullptr) {
        (void)fk_state_budget_release(
            table.budget, FK_MEMORY_CORE, kIpv6SideBytes);
        compact = {};
        return false;
    }
    std::memcpy(compact.addresses.ipv6, key.low_addr, 16u);
    std::memcpy(compact.addresses.ipv6 + 16u, key.high_addr, 16u);
    return true;
}

static void compact_key_release(
        CompactFlowTable &table,
        CompactFlowKey &compact) {
    if (compact.ip_version == 6u && compact.addresses.ipv6 != nullptr) {
        delete[] compact.addresses.ipv6;
        if (!fk_state_budget_release(table.budget, FK_MEMORY_CORE, 32u))
            table.stats.allocator_integrity_failures++;
    }
    compact = {};
}

#ifdef FK_COMPACT_FLOW_TABLE_TEST_HOOKS
static bool consume_atomic_fault(
        CompactFlowTable &table,
        AtomicFaultPoint point) {
    if (table.atomic_fault_point != point)
        return false;
    table.atomic_fault_point = AtomicFaultPoint::None;
    return true;
}
#else
static bool consume_atomic_fault(CompactFlowTable &, AtomicFaultPoint) {
    return false;
}
#endif

static void set_error(char *error, size_t capacity, const char *message) {
    if (error != nullptr && capacity != 0u)
        std::snprintf(error, capacity, "%s", message);
}

static uint32_t hash_capacity(uint32_t maximum_flows) {
    const uint64_t target =
        static_cast<uint64_t>(maximum_flows) * 8u / 7u + 1u;
    uint32_t capacity = 2u;
    while (capacity < target && capacity <= (1u << 30u))
        capacity <<= 1u;
    return capacity;
}

static bool compact_index_is_narrow(uint32_t maximum_flows) {
    return maximum_flows <=
        static_cast<uint32_t>(std::numeric_limits<uint16_t>::max()) + 1u;
}

static uint32_t value_index_get(
        const std::unique_ptr<uint32_t[]> &storage,
        uint32_t position,
        uint32_t maximum_flows) {
    return compact_index_is_narrow(maximum_flows)
        ? storage[position] & 0xffffu : storage[position];
}

static void value_index_set(
        std::unique_ptr<uint32_t[]> &storage,
        uint32_t position,
        uint32_t core_index,
        uint32_t maximum_flows) {
    if (compact_index_is_narrow(maximum_flows)) {
        storage[position] = (storage[position] & 0xffff0000u) |
            (core_index & 0xffffu);
        return;
    }
    storage[position] = core_index;
}

static bool mandatory_allocation_plan(
        uint32_t maximum_flows,
        uint32_t continuation_capacity,
        uint64_t &table_bytes,
        uint64_t &core_bytes,
        uint64_t &lease_bytes,
        uint64_t &mandatory_bytes) {
    if (maximum_flows == 0u || maximum_flows > 1048576u)
        return false;
    const uint32_t capacity = hash_capacity(maximum_flows);
    table_bytes =
        sizeof(CompactFlowTable) +
        fk_state_budget_overhead_bytes() +
        static_cast<uint64_t>(capacity) * sizeof(HashSlot) +
        continuation_directory_index_bytes(continuation_capacity) +
        dynamic_core_index_bytes(maximum_flows);
    lease_bytes =
        static_cast<uint64_t>(maximum_flows) *
        sizeof(fk_component_flow);
    core_bytes =
        static_cast<uint64_t>(maximum_flows) *
        (sizeof(CoreEntry) - sizeof(fk_component_flow));
    if (table_bytes >
            std::numeric_limits<uint64_t>::max() - core_bytes ||
        table_bytes + core_bytes >
            std::numeric_limits<uint64_t>::max() - lease_bytes)
        return false;
    mandatory_bytes = table_bytes + core_bytes + lease_bytes;
    return true;
}

static uint16_t fingerprint(uint64_t hash) {
    uint16_t value = static_cast<uint16_t>(hash >> 48u);
    return value == 0u ? 1u : value;
}

static void initialize_value_heap_positions(CoreEntry &entry);

static uint32_t core_page_entry_count(
        const CompactFlowTable &table,
        uint32_t page_index) {
    const uint32_t first = page_index * kCorePageEntries;
    return std::min(
        kCorePageEntries, table.maximum_flows - first);
}

static CoreEntry *core_entry_if_allocated(
        CompactFlowTable &table,
        uint32_t index) {
    if (index >= table.maximum_flows || table.cores.pages == nullptr)
        return nullptr;
    CorePage &page = table.cores.pages[index / kCorePageEntries];
    return page.entries == nullptr ? nullptr :
        &page.entries[index % kCorePageEntries];
}

static const CoreEntry *core_entry_if_allocated(
        const CompactFlowTable &table,
        uint32_t index) {
    if (index >= table.maximum_flows || table.cores.pages == nullptr)
        return nullptr;
    const CorePage &page = table.cores.pages[index / kCorePageEntries];
    return page.entries == nullptr ? nullptr :
        &page.entries[index % kCorePageEntries];
}

static bool ensure_core_page(
        CompactFlowTable &table,
        uint32_t index) {
    if (index >= table.maximum_flows || table.cores.pages == nullptr)
        return false;
    CorePage &page = table.cores.pages[index / kCorePageEntries];
    if (page.entries != nullptr)
        return true;
    const uint32_t entries = core_page_entry_count(
        table, index / kCorePageEntries);
    const uint64_t core_bytes = static_cast<uint64_t>(entries) *
        (sizeof(CoreEntry) - sizeof(fk_component_flow));
    const uint64_t lease_bytes = static_cast<uint64_t>(entries) *
        sizeof(fk_component_flow);
    const uint64_t total_bytes = core_bytes + lease_bytes;
    if (table.stats.pool_unassigned_bytes < total_bytes)
        return false;
    uint64_t releases[FK_MEMORY_COMPONENT_COUNT]{};
    uint64_t reserves[FK_MEMORY_COMPONENT_COUNT]{};
    reserves[FK_MEMORY_CORE] = core_bytes;
    reserves[FK_MEMORY_LEASE] = lease_bytes;
    if (!fk_state_budget_apply_transaction(
            table.budget, releases, reserves)) {
        return false;
    }
    std::unique_ptr<CoreEntry[]> allocated(
        new (std::nothrow) CoreEntry[entries]());
    if (allocated == nullptr) {
        std::swap(releases, reserves);
        (void)fk_state_budget_apply_transaction(
            table.budget, releases, reserves);
        return false;
    }
    for (uint32_t offset = 0u; offset < entries; ++offset)
        initialize_value_heap_positions(allocated[offset]);
    page.entries = std::move(allocated);
    page.active_entries = 0u;
    table.stats.core_allocation_bytes += core_bytes;
    table.stats.lease_allocation_bytes += lease_bytes;
    table.stats.mandatory_allocation_bytes += total_bytes;
    table.stats.pool_unassigned_bytes -= total_bytes;
    return true;
}

static bool release_empty_core_page(
        CompactFlowTable &table,
        uint32_t index) {
    if (index >= table.maximum_flows || table.cores.pages == nullptr)
        return false;
    CorePage &page = table.cores.pages[index / kCorePageEntries];
    if (page.entries == nullptr || page.active_entries != 0u)
        return page.entries != nullptr;
    const uint32_t entries = core_page_entry_count(
        table, index / kCorePageEntries);
    const uint64_t core_bytes = static_cast<uint64_t>(entries) *
        (sizeof(CoreEntry) - sizeof(fk_component_flow));
    const uint64_t lease_bytes = static_cast<uint64_t>(entries) *
        sizeof(fk_component_flow);
    uint64_t releases[FK_MEMORY_COMPONENT_COUNT]{};
    uint64_t reserves[FK_MEMORY_COMPONENT_COUNT]{};
    releases[FK_MEMORY_CORE] = core_bytes;
    releases[FK_MEMORY_LEASE] = lease_bytes;
    if (!fk_state_budget_apply_transaction(
            table.budget, releases, reserves)) {
        return false;
    }
    page.entries.reset();
    table.stats.core_allocation_bytes -= core_bytes;
    table.stats.lease_allocation_bytes -= lease_bytes;
    table.stats.mandatory_allocation_bytes -= core_bytes + lease_bytes;
    table.stats.pool_unassigned_bytes += core_bytes + lease_bytes;
    return true;
}

static bool allocated_handle(
        const CompactFlowTable &table,
        fk_compact_flow_handle handle) {
    const CoreEntry *entry = core_entry_if_allocated(table, handle.index);
    return entry != nullptr && entry->used != 0u &&
        entry->generation == handle.generation;
}
static bool valid_handle(
        const CompactFlowTable &table,fk_compact_flow_handle handle) {
    return !table.idle_retirement_failed && allocated_handle(table,handle) &&
        table.cores[handle.index].used == 1u;
}

static uint32_t continuation_page_entry_count(
        const CompactFlowTable &table,
        uint32_t page_index) {
    const uint32_t first = page_index * kContinuationPageEntries;
    return std::min(
        kContinuationPageEntries,
        table.continuation_capacity - first);
}

static CapacityContinuationEntry *continuation_entry(
        CompactFlowTable &table,
        uint32_t index,
        bool allocate) {
    if (index >= table.continuation_capacity ||
        table.continuation_pages == nullptr) {
        return nullptr;
    }
    const uint32_t page_index = index / kContinuationPageEntries;
    const uint32_t page_offset = index % kContinuationPageEntries;
    ContinuationPage &page =
        table.continuation_pages[page_index];
    if (page.entries == nullptr) {
        if (!allocate)
            return nullptr;
        const uint64_t allocation_bytes =
            static_cast<uint64_t>(
                continuation_page_entry_count(table, page_index)) *
            sizeof(CapacityContinuationEntry);
        if (table.stats.pool_unassigned_bytes < allocation_bytes ||
            !fk_state_budget_try_reserve(
                table.budget,
                FK_MEMORY_FLOW_TABLE,
                allocation_bytes)) {
            return nullptr;
        }
        std::unique_ptr<CapacityContinuationEntry[]> allocated(
            new (std::nothrow)
                CapacityContinuationEntry[
                    continuation_page_entry_count(table, page_index)]());
        if (allocated == nullptr) {
            (void)fk_state_budget_release(
                table.budget,
                FK_MEMORY_FLOW_TABLE,
                allocation_bytes);
            return nullptr;
        }
        page.entries = std::move(allocated);
        page.active_entries = 0u;
        table.stats.flow_table_allocation_bytes += allocation_bytes;
        table.stats.mandatory_allocation_bytes += allocation_bytes;
        table.stats.pool_unassigned_bytes -= allocation_bytes;
    }
    return &page.entries[page_offset];
}

struct ContinuationProbeSequence {
    uint32_t base;
    uint32_t stride;
    uint32_t capacity;
};

static uint32_t continuation_greatest_common_divisor(
        uint32_t left,
        uint32_t right) {
    while (right != 0u) {
        const uint32_t remainder = left % right;
        left = right;
        right = remainder;
    }
    return left;
}

static ContinuationProbeSequence continuation_probe_sequence(
        const CompactFlowTable &table,
        const fk_flow_key &key) {
    uint64_t hash = fk_flow_key_hash(&key);
    /* Finalize the public canonical-key hash before deriving an independent
     * stride.  A stride coprime with the exact directory capacity visits
     * every slot once before wrapping, including for budget-fit capacities
     * that are not powers of two. */
    hash ^= hash >> 33u;
    hash *= UINT64_C(0xff51afd7ed558ccd);
    hash ^= hash >> 33u;
    hash *= UINT64_C(0xc4ceb9fe1a85ec53);
    hash ^= hash >> 33u;
    uint32_t stride =
        static_cast<uint32_t>(hash >> 32u) % table.continuation_capacity;
    if (stride == 0u)
        stride = 1u;
    while (continuation_greatest_common_divisor(
               stride, table.continuation_capacity) != 1u) {
        ++stride;
        if (stride == table.continuation_capacity)
            stride = 1u;
    }
    return {
        static_cast<uint32_t>(hash) % table.continuation_capacity,
        stride,
        table.continuation_capacity,
    };
}

static uint32_t continuation_probe_index(
        const ContinuationProbeSequence &sequence,
        uint32_t probe) {
    return static_cast<uint32_t>(
        (static_cast<uint64_t>(sequence.base) +
         static_cast<uint64_t>(probe) * sequence.stride) %
        sequence.capacity);
}

static uint32_t continuation_probe_limit(const CompactFlowTable &table) {
    return std::min(kContinuationProbeLimit, table.continuation_capacity);
}

static void continuation_remove(
        CompactFlowTable &table,
        uint32_t entry_index,
        CapacityContinuationEntry &entry) {
    if (entry.valid == 0u)
        return;
    entry = {};
    if (table.continuation_entries == 0u) {
        table.stats.allocator_integrity_failures++;
    } else {
        table.continuation_entries--;
    }
    table.stats.continuation_directory_entries =
        table.continuation_entries;
    const uint32_t page_index = entry_index / kContinuationPageEntries;
    if (entry_index >= table.continuation_capacity ||
        table.continuation_pages == nullptr ||
        table.continuation_pages[page_index].entries == nullptr ||
        table.continuation_pages[page_index].active_entries == 0u) {
        table.stats.allocator_integrity_failures++;
        return;
    }
    ContinuationPage &page = table.continuation_pages[page_index];
    page.active_entries--;
    if (page.active_entries != 0u)
        return;
    const uint64_t allocation_bytes =
        static_cast<uint64_t>(
            continuation_page_entry_count(table, page_index)) *
        sizeof(CapacityContinuationEntry);
    if (!fk_state_budget_release(
            table.budget, FK_MEMORY_FLOW_TABLE, allocation_bytes)) {
        table.stats.allocator_integrity_failures++;
        return;
    }
    page.entries.reset();
    table.stats.flow_table_allocation_bytes -= allocation_bytes;
    table.stats.mandatory_allocation_bytes -= allocation_bytes;
    table.stats.pool_unassigned_bytes += allocation_bytes;
}

/* Incremental global reclamation prevents an inactive key from occupying a
 * slot forever merely because no later key shares its double-hash path.  The
 * work per capacity displacement is fixed, charged in the receipt, and uses
 * the same idle-gap semantics as an exact-key lookup. */
static void continuation_expiration_sweep(
        CompactFlowTable &table,
        uint64_t timestamp_ns) {
    if (table.continuation_capacity == 0u)
        return;
    const uint32_t steps = std::min(
        kContinuationExpirationSweepSteps,
        table.continuation_capacity);
    table.stats.continuation_expiration_sweep_calls++;
    table.stats.continuation_expiration_sweep_steps += steps;
    for (uint32_t step = 0u; step < steps; ++step) {
        const uint32_t candidate_index =
            table.continuation_expiration_cursor;
        CapacityContinuationEntry *candidate = continuation_entry(
            table, candidate_index, false);
        ++table.continuation_expiration_cursor;
        if (table.continuation_expiration_cursor ==
                table.continuation_capacity) {
            table.continuation_expiration_cursor = 0u;
        }
        if (candidate == nullptr || candidate->valid == 0u ||
            table.continuation_maximum_gap_ns == 0u ||
            timestamp_ns < candidate->last_timestamp_ns ||
            timestamp_ns - candidate->last_timestamp_ns <=
                table.continuation_maximum_gap_ns) {
            continue;
        }
        continuation_remove(table, candidate_index, *candidate);
        table.stats.continuation_expirations++;
        table.stats.continuation_expiration_sweep_expirations++;
    }
}

static CapacityContinuationEntry make_capacity_continuation(
        uint32_t flow_index,
        const CoreEntry &entry) {
    CapacityContinuationEntry continuation{};
    continuation.first_timestamp_ns = entry.first_timestamp_ns;
    continuation.last_timestamp_ns = entry.last_timestamp_ns;
    continuation.packets = entry.packets;
    continuation.bytes = entry.bytes;
    continuation.component.decision_started =
        entry.component.decision_started;
    continuation.component.checkpoint_index =
        entry.component.checkpoint_index;
    continuation.component.observation_complete =
        entry.component.observation_complete;
    std::copy_n(entry.component.missing_reason, 3u,
                continuation.component.missing_reason);
    continuation.component.next_checkpoint_packet =
        entry.component.next_checkpoint_packet;
    std::copy_n(entry.component.component_start_packet, 3u,
                continuation.component.component_start_packet);
    if (!compact_key_materialize(entry.key, continuation.key))
        return {};
    continuation.bootstrap = entry.bootstrap;
    continuation.direction_packets[0] = entry.direction_packets[0];
    continuation.direction_packets[1] = entry.direction_packets[1];
    continuation.maximum_wire_size = entry.maximum_wire_size;
    continuation.initial_syn_sequence = entry.next_free;
    continuation.predecessor_flow_index = flow_index;
    continuation.predecessor_flow_generation = entry.generation;
    continuation.first_direction = entry.first_direction;
    continuation.fixed_ttl_deadline = entry.fixed_ttl_deadline;
    continuation.tcp_lifecycle = entry.lifecycle_reserved;

    /* Capacity displacement destroys every optional slab.  Preserve the
     * latest checkpoint values and checkpoint cursor, but make physical loss
     * explicit so no later controller can pretend the old evidence survived. */
    const uint8_t lost_mask = static_cast<uint8_t>(
        entry.evidence_mask | entry.component.mask);
    continuation.component.released_mask = static_cast<uint8_t>(
        entry.component.released_mask | lost_mask);
    for (uint8_t index = 0u; index < 3u; ++index) {
        if ((lost_mask & (1u << index)) != 0u)
            continuation.component.missing_reason[index] =
                FK_MISSING_LOST_OR_FAILED;
    }
    if (lost_mask != FK_COMPONENT_NONE)
        continuation.component.observation_complete = 0u;
    continuation.valid = 1u;
    return continuation;
}

struct ContinuationTarget {
    CapacityContinuationEntry *entry;
    uint32_t index;
};

static ContinuationTarget continuation_store_target(
        CompactFlowTable &table,
        const CapacityContinuationEntry &incoming,
        uint64_t timestamp_ns) {
    if (incoming.valid == 0u || table.continuation_capacity == 0u)
        return {nullptr, kNoIndex};
    table.stats.continuation_store_attempts++;
    continuation_expiration_sweep(table, timestamp_ns);
    uint32_t first_empty = kNoIndex;
    CapacityContinuationEntry *oldest = nullptr;
    uint32_t oldest_index = kNoIndex;
    const uint32_t probe_limit = continuation_probe_limit(table);
    const ContinuationProbeSequence sequence =
        continuation_probe_sequence(table, incoming.key);
    for (uint32_t probe = 0u;
         probe < probe_limit; ++probe) {
        const uint64_t probe_count = static_cast<uint64_t>(probe) + 1u;
        const uint32_t candidate_index =
            continuation_probe_index(sequence, probe);
        CapacityContinuationEntry *candidate = continuation_entry(
            table, candidate_index, false);
        if (candidate != nullptr && candidate->valid != 0u &&
            table.continuation_maximum_gap_ns != 0u &&
            timestamp_ns >= candidate->last_timestamp_ns &&
            timestamp_ns - candidate->last_timestamp_ns >
                table.continuation_maximum_gap_ns) {
            continuation_remove(table, candidate_index, *candidate);
            table.stats.continuation_expirations++;
            candidate = nullptr;
        }
        if (candidate != nullptr && candidate->valid != 0u &&
            fk_flow_key_equal(&candidate->key, &incoming.key)) {
            table.stats.continuation_store_probe_steps += probe_count;
            table.stats.continuation_peak_probe_count = std::max(
                table.stats.continuation_peak_probe_count, probe_count);
            return {candidate, candidate_index};
        }
        if ((candidate == nullptr || candidate->valid == 0u) &&
            first_empty == kNoIndex) {
            first_empty = candidate_index;
        }
        if (candidate != nullptr && candidate->valid != 0u &&
            (oldest == nullptr ||
            candidate->last_timestamp_ns < oldest->last_timestamp_ns)) {
            oldest = candidate;
            oldest_index = candidate_index;
        }
    }
    table.stats.continuation_store_probe_steps +=
        probe_limit;
    table.stats.continuation_peak_probe_count = std::max(
        table.stats.continuation_peak_probe_count,
        static_cast<uint64_t>(probe_limit));
    if (first_empty != kNoIndex) {
        CapacityContinuationEntry *target = continuation_entry(
            table, first_empty, true);
        if (target == nullptr)
            table.stats.continuation_probe_exhaustions++;
        return {target, target == nullptr ? kNoIndex : first_empty};
    }

    /* A continuation is best-effort state kept only after its live core has
     * already been selected for admission-time displacement.  Exhausting the
     * fixed 64-candidate window must therefore replace bounded old history,
     * not reject the arriving live flow and stop the entire RX pipeline.
     * The oldest candidate is deterministic for a frozen trace and keeps the
     * admission path O(kContinuationProbeLimit) without spending more of the
     * controlled state budget.  continuation_store_at() records this as a
     * replacement, preserving exact directory accounting. */
    return {oldest, oldest == nullptr ? kNoIndex : oldest_index};
}

static void continuation_store_at(
        CompactFlowTable &table,
        uint32_t target_index,
        CapacityContinuationEntry &target,
        const CapacityContinuationEntry &incoming) {
    const bool insertion = target.valid == 0u;
    if (!insertion)
        table.stats.continuation_store_replacements++;
    target = incoming;
    if (insertion) {
        const uint32_t page_index =
            target_index / kContinuationPageEntries;
        if (target_index >= table.continuation_capacity ||
            table.continuation_pages == nullptr ||
            table.continuation_pages[page_index].entries == nullptr) {
            table.stats.allocator_integrity_failures++;
            return;
        }
        table.continuation_pages[page_index].active_entries++;
        table.continuation_entries++;
        table.stats.continuation_directory_entries =
            table.continuation_entries;
        table.stats.continuation_directory_peak_entries = std::max(
            table.stats.continuation_directory_peak_entries,
            table.continuation_entries);
    }
    table.stats.continuation_stores++;
}

static constexpr uint32_t kJa4SummaryBytes =
    offsetof(fk_compact_ja4_state, tls);

static uint64_t owned_evidence_bytes(const fk_component_flow &flow) {
    return static_cast<uint64_t>(flow.owned.stat_bytes) +
        flow.owned.seq_bytes + flow.owned.ja4_bytes;
}

static void initialize_value_heap_positions(CoreEntry &entry) {
    for (uint8_t component = 0u; component < 3u; ++component)
        entry.value_heap_position[component] =
            std::numeric_limits<uint16_t>::max();
    entry.ja4_value_heap = kValueHeapJa4Pending;
    entry.optional_deadline_heap_position = kNoIndex;
}

static uint8_t heap_position_slot(uint8_t heap) {
    return heap == kValueHeapStat ? 0u :
        heap == kValueHeapSeq ? 1u : 2u;
}

static bool entry_belongs_to_heap(
        const CoreEntry &entry,
        uint8_t heap) {
    if (heap < kValueHeapJa4Pending)
        return true;
    return entry.ja4_value_heap == heap;
}

static uint8_t heap_component(uint8_t heap) {
    if (heap == kValueHeapStat)
        return FK_COMPONENT_STAT;
    if (heap == kValueHeapSeq)
        return FK_COMPONENT_SEQ;
    return FK_COMPONENT_JA4;
}

static uint8_t entry_heap_for_component(
        const CoreEntry &entry,
        uint8_t component) {
    if (component == FK_COMPONENT_STAT)
        return kValueHeapStat;
    if (component == FK_COMPONENT_SEQ)
        return kValueHeapSeq;
    return entry.ja4_is_summary == kJa4ModeSummary
        ? kValueHeapJa4Summary : kValueHeapJa4Pending;
}

static uint64_t component_owned_bytes(
        const CoreEntry &entry,
        uint8_t component) {
    if (component == FK_COMPONENT_STAT)
        return entry.component.owned.stat_bytes;
    if (component == FK_COMPONENT_SEQ)
        return entry.component.owned.seq_bytes;
    return entry.component.owned.ja4_bytes;
}

static uint8_t component_array_index(uint8_t component) {
    return component == FK_COMPONENT_STAT ? 0u :
        component == FK_COMPONENT_SEQ ? 1u : 2u;
}

static fk_memory_component component_memory_kind(uint8_t component) {
    return component == FK_COMPONENT_STAT ? FK_MEMORY_STAT :
        component == FK_COMPONENT_SEQ ? FK_MEMORY_SEQ : FK_MEMORY_JA4;
}

static uint16_t component_slab_index(
        const CoreEntry &entry,
        uint8_t component) {
    return component == FK_COMPONENT_STAT ? entry.stat_index :
        component == FK_COMPONENT_SEQ ? entry.seq_index : entry.ja4_index;
}

static void set_component_slab_index(
        CoreEntry &entry,
        uint8_t component,
        uint16_t index) {
    if (component == FK_COMPONENT_STAT)
        entry.stat_index = index;
    else if (component == FK_COMPONENT_SEQ)
        entry.seq_index = index;
    else
        entry.ja4_index = index;
}

static fk_slab_pool *component_pool(
        CompactFlowTable &table,
        const CoreEntry &entry,
        uint8_t component) {
    if (component == FK_COMPONENT_STAT)
        return table.stat_pool;
    if (component == FK_COMPONENT_SEQ)
        return table.seq_pool;
    return entry.ja4_is_summary == kJa4ModeSummary
        ? table.ja4_summary_pool : table.ja4_pending_pool;
}

static fk_slab_pool *heap_pool(
        CompactFlowTable &table,
        uint8_t heap) {
    if (heap == kValueHeapStat)
        return table.stat_pool;
    if (heap == kValueHeapSeq)
        return table.seq_pool;
    return heap == kValueHeapJa4Summary
        ? table.ja4_summary_pool : table.ja4_pending_pool;
}

static void set_component_owned_bytes(
        fk_component_flow &flow,
        uint8_t component,
        uint32_t bytes) {
    if (component == FK_COMPONENT_STAT)
        flow.owned.stat_bytes = bytes;
    else if (component == FK_COMPONENT_SEQ)
        flow.owned.seq_bytes = bytes;
    else
        flow.owned.ja4_bytes = bytes;
}

static float removal_loss_for_mask(
        const CoreEntry &entry,
        uint8_t planning_mask,
        uint8_t component) {
    if ((planning_mask & component) == 0u)
        return 0.0f;
    float loss = 0.0f;
    if (!fk_component_flow_removal_loss(
            &entry.component, planning_mask, component, &loss))
        return std::numeric_limits<float>::infinity();
    return loss;
}

static float resident_value_density(
        const CoreEntry &entry,
        uint8_t planning_mask,
        uint8_t component) {
    const uint64_t bytes = component_owned_bytes(entry, component);
    if (bytes == 0u)
        return std::numeric_limits<float>::infinity();
    return removal_loss_for_mask(entry, planning_mask, component) /
        static_cast<float>(bytes);
}

static bool value_key_less(
        const CompactFlowTable &table,
        uint8_t heap,
        uint32_t left_index,
        uint32_t right_index) {
    const CoreEntry &left = table.cores[left_index];
    const CoreEntry &right = table.cores[right_index];
    const uint8_t component = heap_component(heap);
    const float left_density = resident_value_density(
        left, replacement_planning_mask(left), component);
    const float right_density = resident_value_density(
        right, replacement_planning_mask(right), component);
    if (left_density != right_density)
        return left_density < right_density;
    if (left.component.absolute_deadline_ns !=
            right.component.absolute_deadline_ns)
        return left.component.absolute_deadline_ns <
            right.component.absolute_deadline_ns;
    if (left_index != right_index)
        return left_index < right_index;
    return component < heap_component(heap);
}

static void value_heap_swap(
        CompactFlowTable &table,
        uint8_t heap,
        uint32_t left,
        uint32_t right) {
    const uint32_t left_index = value_index_get(
        table.value_heaps[heap], left, table.maximum_flows);
    const uint32_t right_index = value_index_get(
        table.value_heaps[heap], right, table.maximum_flows);
    value_index_set(
        table.value_heaps[heap], left, right_index, table.maximum_flows);
    value_index_set(
        table.value_heaps[heap], right, left_index, table.maximum_flows);
    table.cores[right_index].value_heap_position[
        heap_position_slot(heap)] = static_cast<uint16_t>(left);
    table.cores[left_index].value_heap_position[
        heap_position_slot(heap)] = static_cast<uint16_t>(right);
}

static void value_heap_sift_up(
        CompactFlowTable &table,
        uint8_t heap,
        uint32_t position) {
    while (position != 0u) {
        const uint32_t parent = (position - 1u) / 2u;
        if (!value_key_less(
                table,
                heap,
                value_index_get(
                    table.value_heaps[heap], position,
                    table.maximum_flows),
                value_index_get(
                    table.value_heaps[heap], parent,
                    table.maximum_flows)))
            break;
        value_heap_swap(table, heap, position, parent);
        position = parent;
    }
}

static void value_heap_sift_down(
        CompactFlowTable &table,
        uint8_t heap,
        uint32_t position) {
    for (;;) {
        const uint32_t size = table.value_heap_size[heap];
        const uint32_t left = position * 2u + 1u;
        if (left >= size)
            return;
        const uint32_t right = left + 1u;
        uint32_t best = left;
        if (right < size && value_key_less(
                table,
                heap,
                value_index_get(
                    table.value_heaps[heap], right,
                    table.maximum_flows),
                value_index_get(
                    table.value_heaps[heap], left,
                    table.maximum_flows)))
            best = right;
        if (!value_key_less(
                table,
                heap,
                value_index_get(
                    table.value_heaps[heap], best,
                    table.maximum_flows),
                value_index_get(
                    table.value_heaps[heap], position,
                    table.maximum_flows)))
            return;
        value_heap_swap(table, heap, position, best);
        position = best;
    }
}

static bool value_heap_insert(
        CompactFlowTable &table,
        uint8_t heap,
        uint32_t core_index) {
    if (heap >= kValueHeapCount || core_index >= table.maximum_flows ||
        table.value_heap_size[heap] >= table.value_heap_capacity[heap] ||
        table.value_heap_capacity[heap] >
            std::numeric_limits<uint16_t>::max() ||
        (entry_belongs_to_heap(table.cores[core_index], heap) &&
         table.cores[core_index].value_heap_position[
             heap_position_slot(heap)] !=
             std::numeric_limits<uint16_t>::max()))
        return false;
    const uint32_t position = table.value_heap_size[heap]++;
    value_index_set(
        table.value_heaps[heap], position, core_index,
        table.maximum_flows);
    table.cores[core_index].value_heap_position[
        heap_position_slot(heap)] = static_cast<uint16_t>(position);
    if (heap >= kValueHeapJa4Pending)
        table.cores[core_index].ja4_value_heap = heap;
    value_heap_sift_up(table, heap, position);
    return true;
}

static bool value_heap_remove(
        CompactFlowTable &table,
        uint8_t heap,
        uint32_t core_index) {
    if (heap >= kValueHeapCount || core_index >= table.maximum_flows)
        return false;
    CoreEntry &entry = table.cores[core_index];
    if (!entry_belongs_to_heap(entry, heap))
        return true;
    const uint8_t position_slot = heap_position_slot(heap);
    const uint32_t position = entry.value_heap_position[position_slot];
    if (position == std::numeric_limits<uint16_t>::max())
        return true;
    const uint32_t size = table.value_heap_size[heap];
    if (position >= size || value_index_get(
            table.value_heaps[heap], position,
            table.maximum_flows) != core_index)
        return false;
    const uint32_t last_position = size - 1u;
    const uint32_t last_index = value_index_get(
        table.value_heaps[heap], last_position,
        table.maximum_flows);
    table.value_heap_size[heap] = last_position;
    entry.value_heap_position[position_slot] =
        std::numeric_limits<uint16_t>::max();
    if (position == last_position)
        return true;
    value_index_set(
        table.value_heaps[heap], position, last_index,
        table.maximum_flows);
    table.cores[last_index].value_heap_position[
        heap_position_slot(heap)] = static_cast<uint16_t>(position);
    if (position != 0u) {
        const uint32_t parent = (position - 1u) / 2u;
        if (value_key_less(
                table, heap, last_index,
                value_index_get(
                    table.value_heaps[heap], parent,
                    table.maximum_flows))) {
            value_heap_sift_up(table, heap, position);
            return true;
        }
    }
    value_heap_sift_down(table, heap, position);
    return true;
}

static bool detach_entry_value_heaps(
        CompactFlowTable &table,
        uint32_t core_index) {
    bool ok = true;
    for (uint8_t heap = 0u; heap < kValueHeapCount; ++heap)
        ok = value_heap_remove(table, heap, core_index) && ok;
    return ok;
}

static bool refresh_entry_value_heaps(
        CompactFlowTable &table,
        uint32_t core_index) {
    if (core_index >= table.maximum_flows)
        return false;
    CoreEntry &entry = table.cores[core_index];
    if (!detach_entry_value_heaps(table, core_index))
        return false;
    /* A provisional component has no causal-checkpoint value yet.
     * Treating its absent logical-mask bit as zero removal loss lets another
     * flow evict the very evidence needed to construct that value later.  It
     * therefore cannot enter the value-replacement victim index until the
     * first decision has published all eight action values. */
    if (entry.used == 0u ||
        entry.component.initial_action_values_valid == 0u)
        return true;
    if ((entry.evidence_mask & FK_COMPONENT_STAT) != 0u &&
        !value_heap_insert(table, kValueHeapStat, core_index))
        return false;
    if ((entry.evidence_mask & FK_COMPONENT_SEQ) != 0u &&
        !value_heap_insert(table, kValueHeapSeq, core_index))
        return false;
    const bool resident_ja4 =
        (entry.evidence_mask & FK_COMPONENT_JA4) != 0u ||
        entry.ja4_is_summary == kJa4ModeProvisional;
    if (resident_ja4 && !value_heap_insert(
            table,
            entry_heap_for_component(entry, FK_COMPONENT_JA4),
            core_index))
        return false;
    return true;
}

/* Action-value refresh changes heap keys but not residency or heap
 * membership.  Repair the indexed node in place instead of removing and
 * reinserting it in every component heap.  This preserves the exact
 * comparator and tie-break order while avoiding two structural mutations
 * and their position rewrites per resident component. */
static bool fix_value_heap_key(
        CompactFlowTable &table,
        uint8_t heap,
        uint32_t core_index) {
    if (heap >= kValueHeapCount || core_index >= table.maximum_flows)
        return false;
    CoreEntry &entry = table.cores[core_index];
    if (!entry_belongs_to_heap(entry, heap))
        return true;
    const uint8_t slot = heap_position_slot(heap);
    const uint32_t position = entry.value_heap_position[slot];
    if (position == std::numeric_limits<uint16_t>::max())
        return true;
    if (position >= table.value_heap_size[heap] || value_index_get(
            table.value_heaps[heap], position,
            table.maximum_flows) != core_index)
        return false;
    if (position != 0u) {
        const uint32_t parent = (position - 1u) / 2u;
        if (value_key_less(
                table, heap, core_index,
                value_index_get(
                    table.value_heaps[heap], parent,
                    table.maximum_flows))) {
            value_heap_sift_up(table, heap, position);
            return true;
        }
    }
    value_heap_sift_down(table, heap, position);
    return true;
}

static bool fix_entry_value_heap_keys(
        CompactFlowTable &table,
        uint32_t core_index) {
    bool ok = true;
    for (uint8_t heap = 0u; heap < kValueHeapCount; ++heap)
        ok = fix_value_heap_key(table, heap, core_index) && ok;
    return ok;
}

static void *evidence_component(
        CompactFlowTable &table,
        CoreEntry &entry,
        uint8_t component) {
    if ((entry.evidence_mask & component) == 0u)
        return nullptr;
    if (component == FK_COMPONENT_STAT)
        return fk_slab_pool_get_index(table.stat_pool, entry.stat_index);
    if (component == FK_COMPONENT_SEQ)
        return fk_slab_pool_get_index(table.seq_pool, entry.seq_index);
    if (component == FK_COMPONENT_JA4) {
        return fk_slab_pool_get_index(
            entry.ja4_is_summary == kJa4ModeSummary
                ? table.ja4_summary_pool : table.ja4_pending_pool,
            entry.ja4_index);
    }
    return nullptr;
}

static bool has_optional_resident(const CoreEntry &entry) {
    return entry.evidence_mask != FK_COMPONENT_NONE ||
        (entry.ja4_is_summary == kJa4ModeProvisional &&
         entry.component.owned.ja4_bytes != 0u);
}

static uint32_t optional_heap_position(const CoreEntry &entry) {
    return entry.optional_deadline_heap_position;
}

static void set_optional_heap_position(
        CoreEntry &entry,
        uint32_t position) {
    entry.optional_deadline_heap_position = position;
}

static uint32_t indexed_heap_position(
        CoreEntry &entry,
        bool optional_deadline) {
    return optional_deadline ? optional_heap_position(entry) : kNoIndex;
}

static void set_indexed_heap_position(
        CoreEntry &entry,
        bool optional_deadline,
        uint32_t position) {
    if (optional_deadline)
        set_optional_heap_position(entry, position);
}

static uint32_t optional_deadline_heap_capacity(
        const CompactFlowTable &table) {
    uint64_t resident_capacity = 0u;
    for (uint8_t heap = 0u; heap < kValueHeapCount; ++heap)
        resident_capacity += table.value_heap_capacity[heap];
    return static_cast<uint32_t>(std::min<uint64_t>(
        table.maximum_flows, resident_capacity));
}

static uint32_t optional_deadline_index_get(
        const CompactFlowTable &table,
        uint32_t position) {
    if (!compact_index_is_narrow(table.maximum_flows))
        return table.optional_deadline_heap[position];
    for (uint8_t heap = 0u; heap < kValueHeapCount; ++heap) {
        const uint32_t capacity = table.value_heap_capacity[heap];
        if (position < capacity)
            return table.value_heaps[heap][position] >> 16u;
        position -= capacity;
    }
    return kNoIndex;
}

static bool optional_deadline_index_set(
        CompactFlowTable &table,
        uint32_t position,
        uint32_t core_index) {
    if (!compact_index_is_narrow(table.maximum_flows)) {
        table.optional_deadline_heap[position] = core_index;
        return true;
    }
    if (core_index > std::numeric_limits<uint16_t>::max())
        return false;
    for (uint8_t heap = 0u; heap < kValueHeapCount; ++heap) {
        const uint32_t capacity = table.value_heap_capacity[heap];
        if (position < capacity) {
            uint32_t &word = table.value_heaps[heap][position];
            word = (word & 0x0000ffffu) | (core_index << 16u);
            return true;
        }
        position -= capacity;
    }
    return false;
}

static uint32_t &indexed_heap_size(
        CompactFlowTable &table,
        bool optional_deadline) {
    return optional_deadline
        ? table.optional_deadline_heap_size :
          table.optional_deadline_heap_size;
}

static bool indexed_heap_key_less(
        const CompactFlowTable &table,
        bool optional_deadline,
        uint32_t left_index,
        uint32_t right_index) {
    (void)optional_deadline;
    const CoreEntry &left = table.cores[left_index];
    const CoreEntry &right = table.cores[right_index];
    const uint64_t left_key = left.component.absolute_deadline_ns;
    const uint64_t right_key = right.component.absolute_deadline_ns;
    if (left_key != right_key)
        return left_key < right_key;
    if (left_index != right_index)
        return left_index < right_index;
    return left.generation < right.generation;
}

static void indexed_heap_swap(
        CompactFlowTable &table,
        bool optional_deadline,
        uint32_t left,
        uint32_t right) {
    const uint32_t left_index = optional_deadline_index_get(table, left);
    const uint32_t right_index = optional_deadline_index_get(table, right);
    (void)optional_deadline_index_set(table, left, right_index);
    (void)optional_deadline_index_set(table, right, left_index);
    set_indexed_heap_position(
        table.cores[right_index], optional_deadline, left);
    set_indexed_heap_position(
        table.cores[left_index], optional_deadline, right);
}

static void indexed_heap_sift_up(
        CompactFlowTable &table,
        bool optional_deadline,
        uint32_t position) {
    while (position != 0u) {
        const uint32_t parent = (position - 1u) / 2u;
        if (!indexed_heap_key_less(
                table,
                optional_deadline,
                optional_deadline_index_get(table, position),
                optional_deadline_index_get(table, parent)))
            break;
        indexed_heap_swap(table, optional_deadline, position, parent);
        position = parent;
    }
}

static void indexed_heap_sift_down(
        CompactFlowTable &table,
        bool optional_deadline,
        uint32_t position) {
    for (;;) {
        const uint32_t size = indexed_heap_size(
            table, optional_deadline);
        const uint32_t left = position * 2u + 1u;
        if (left >= size)
            return;
        const uint32_t right = left + 1u;
        uint32_t best = left;
        if (right < size && indexed_heap_key_less(
                table,
                optional_deadline,
                optional_deadline_index_get(table, right),
                optional_deadline_index_get(table, left)))
            best = right;
        if (!indexed_heap_key_less(
                table,
                optional_deadline,
                optional_deadline_index_get(table, best),
                optional_deadline_index_get(table, position)))
            return;
        indexed_heap_swap(table, optional_deadline, position, best);
        position = best;
    }
}

static bool indexed_heap_insert(
        CompactFlowTable &table,
        bool optional_deadline,
        uint32_t core_index) {
    uint32_t &size = indexed_heap_size(table, optional_deadline);
    CoreEntry &entry = table.cores[core_index];
    if (entry.used == 0u ||
        size >= optional_deadline_heap_capacity(table) ||
        indexed_heap_position(entry, optional_deadline) != kNoIndex)
        return false;
    const uint32_t position = size++;
    if (!optional_deadline_index_set(table, position, core_index)) {
        size--;
        return false;
    }
    set_indexed_heap_position(entry, optional_deadline, position);
    indexed_heap_sift_up(table, optional_deadline, position);
    return true;
}

static bool indexed_heap_remove(
        CompactFlowTable &table,
        bool optional_deadline,
        uint32_t core_index) {
    CoreEntry &entry = table.cores[core_index];
    const uint32_t position = indexed_heap_position(
        entry, optional_deadline);
    if (position == kNoIndex)
        return true;
    uint32_t &size = indexed_heap_size(table, optional_deadline);
    if (position >= size ||
        optional_deadline_index_get(table, position) != core_index)
        return false;
    const uint32_t last_position = --size;
    const uint32_t last_index = optional_deadline_index_get(
        table, last_position);
    set_indexed_heap_position(entry, optional_deadline, kNoIndex);
    if (position == last_position)
        return true;
    if (!optional_deadline_index_set(table, position, last_index))
        return false;
    set_indexed_heap_position(
        table.cores[last_index], optional_deadline, position);
    if (position != 0u) {
        const uint32_t parent = (position - 1u) / 2u;
        if (indexed_heap_key_less(
                table,
                optional_deadline,
                last_index,
                optional_deadline_index_get(table, parent))) {
            indexed_heap_sift_up(table, optional_deadline, position);
            return true;
        }
    }
    indexed_heap_sift_down(table, optional_deadline, position);
    return true;
}

static bool indexed_heap_refresh(
        CompactFlowTable &table,
        bool optional_deadline,
        uint32_t core_index,
        bool resident) {
    CoreEntry &entry = table.cores[core_index];
    const uint32_t position = indexed_heap_position(
        entry, optional_deadline);
    if (!resident)
        return indexed_heap_remove(table, optional_deadline, core_index);
    if (position == kNoIndex) {
        if (!indexed_heap_insert(
                table, optional_deadline, core_index))
            return false;
        return true;
    }
    if (position >= indexed_heap_size(table, optional_deadline) ||
        optional_deadline_index_get(table, position) != core_index)
        return false;
    if (position != 0u) {
        const uint32_t parent = (position - 1u) / 2u;
        if (indexed_heap_key_less(
                table,
                optional_deadline,
                core_index,
                optional_deadline_index_get(table, parent))) {
            indexed_heap_sift_up(table, optional_deadline, position);
            return true;
        }
    }
    indexed_heap_sift_down(table, optional_deadline, position);
    return true;
}

static bool indexed_heaps_valid(const CompactFlowTable &table) {
    if (table.optional_deadline_heap_size >
            optional_deadline_heap_capacity(table))
        return false;
    for (uint32_t position = 0u;
         position < table.optional_deadline_heap_size;
         ++position) {
        const uint32_t core_index = optional_deadline_index_get(
            table, position);
        if (core_index >= table.maximum_flows)
            return false;
        const CoreEntry &entry = table.cores[core_index];
        if (entry.used == 0u || entry.generation == 0u ||
            !has_optional_resident(entry) ||
            optional_heap_position(entry) != position)
            return false;
        if (position != 0u) {
            const uint32_t parent_index = optional_deadline_index_get(
                table, (position - 1u) / 2u);
            if (indexed_heap_key_less(
                    table, true, core_index, parent_index))
                return false;
        }
    }
    uint32_t used_count = 0u;
    for (uint32_t core_index = 0u;
         core_index < table.maximum_flows;
         ++core_index) {
        const CoreEntry *entry = core_entry_if_allocated(
            table, core_index);
        if (entry == nullptr || entry->used == 0u) {
            if (entry != nullptr &&
                optional_heap_position(*entry) != kNoIndex)
                return false;
            continue;
        }
        used_count++;
        const bool optional = has_optional_resident(*entry);
        if (optional !=
                (optional_heap_position(*entry) != kNoIndex))
            return false;
        if (optional &&
            (optional_heap_position(*entry) >=
                 table.optional_deadline_heap_size ||
             optional_deadline_index_get(
                 table, optional_heap_position(*entry)) != core_index))
            return false;
    }
    return used_count == table.stats.active_flows;
}

static void note_optional_deadline(
        CompactFlowTable &table,
        uint32_t core_index) {
    const CoreEntry &entry = table.cores[core_index];
    if (entry.used == 0u || !has_optional_resident(entry))
        return;
    if (!indexed_heap_refresh(table, true, core_index, true))
        table.stats.allocator_integrity_failures++;
}

static void invalidate_removed_optional_deadline(
        CompactFlowTable &table,
        uint32_t core_index) {
    CoreEntry &entry = table.cores[core_index];
    if (!indexed_heap_refresh(
            table, true, core_index, has_optional_resident(entry)))
        table.stats.allocator_integrity_failures++;
}

static bool persist_lifecycle(CompactFlowTable &table,uint32_t index,
        fk_compact_persist_reason reason) {
    if(!table.lifecycle_guard)return true;
    if(index>=table.maximum_flows)return false;
    const auto &entry=table.cores[index];
    if(!entry.used)return false;
    bool persisted=false;
    try {persisted=table.lifecycle_guard->persist(table.lifecycle_guard->context,
        reinterpret_cast<fk_compact_flow_table*>(&table),{index,entry.generation},
        resident_component_mask(entry),reason);}catch(...){}
    if(!persisted && table.idle_retirement_guard)table.idle_retirement_failed=true;
    return persisted;
}

static void free_evidence(
        CompactFlowTable &table,
        uint32_t core_index) {
    CoreEntry &entry = table.cores[core_index];
    if(auto *evidence=flowkeep::EvidenceFor(reinterpret_cast<fk_compact_flow_table*>(&table)))
        flowkeep::EvidenceCapture(evidence,
            reinterpret_cast<fk_compact_flow_table*>(&table),
            {core_index,entry.generation},7,flowkeep::EvidenceBeforeDestroy);
    (void)detach_entry_value_heaps(table, core_index);
    const bool has_ja4 =
        (entry.evidence_mask & FK_COMPONENT_JA4) != 0u ||
        entry.ja4_is_summary == kJa4ModeProvisional;
    const bool had_optional = has_optional_resident(entry);
    const uint64_t bytes =
        ((entry.evidence_mask & FK_COMPONENT_STAT) != 0u
            ? sizeof(fk_compact_stat_state) : 0u) +
        ((entry.evidence_mask & FK_COMPONENT_SEQ) != 0u
            ? sizeof(fk_compact_seq_state) : 0u) +
        (has_ja4
            ? (entry.ja4_is_summary == kJa4ModeSummary
                ? kJa4SummaryBytes : sizeof(fk_compact_ja4_state))
            : 0u);
    if ((entry.evidence_mask & FK_COMPONENT_STAT) != 0u)
        (void)fk_slab_pool_release_index(
            table.stat_pool, entry.stat_index);
    if ((entry.evidence_mask & FK_COMPONENT_SEQ) != 0u)
        (void)fk_slab_pool_release_index(
            table.seq_pool, entry.seq_index);
    if (has_ja4)
        (void)fk_slab_pool_release_index(
            entry.ja4_is_summary == kJa4ModeSummary
                ? table.ja4_summary_pool : table.ja4_pending_pool,
            entry.ja4_index);
    entry.stat_index = 0u;
    entry.seq_index = 0u;
    entry.ja4_index = 0u;
    entry.evidence_mask = FK_COMPONENT_NONE;
    entry.ja4_is_summary = kJa4ModePending;
    table.stats.evidence_storage_bytes -= bytes;
    if (had_optional)
        invalidate_removed_optional_deadline(table, core_index);
}

static bool compact_ja4_if_terminal(
        CompactFlowTable &table,
        uint32_t core_index) {
    CoreEntry &entry = table.cores[core_index];
    if ((entry.evidence_mask & FK_COMPONENT_JA4) == 0u ||
        entry.component.owned.ja4_bytes <= kJa4SummaryBytes)
        return true;
    auto *ja4 = static_cast<fk_compact_ja4_state *>(
        evidence_component(table, entry, FK_COMPONENT_JA4));
    if (ja4 == nullptr)
        return false;
    const bool fingerprint_present =
        ja4->client.present != 0u || ja4->server.present != 0u;
    const bool both_present =
        ja4->client.present != 0u && ja4->server.present != 0u;
    const bool terminal_record =
        ja4->tls.direction[0].tls.application_data_seen != 0u ||
        ja4->tls.direction[1].tls.application_data_seen != 0u ||
        ja4->tls.direction[0].closed != 0u ||
        ja4->tls.direction[1].closed != 0u;
    if (!fingerprint_present || (!both_present && !terminal_record))
        return true;
    if(!persist_lifecycle(table,core_index,FK_COMPACT_PERSIST_TLS_COMPACTION))return false;
    uint16_t summary_index = 0u;
    void *summary_memory = nullptr;
    if (!fk_slab_pool_acquire_index(
            table.ja4_summary_pool,
            &summary_index,
            &summary_memory)) {
        table.stats.ja4_compaction_rejects++;
        return true;
    }
    if(auto *evidence=flowkeep::EvidenceFor(reinterpret_cast<fk_compact_flow_table*>(&table)))
        flowkeep::EvidenceCapture(evidence,
            reinterpret_cast<fk_compact_flow_table*>(&table),
            {core_index,entry.generation},4,flowkeep::EvidenceBeforeCompaction);
    std::memcpy(summary_memory, ja4, kJa4SummaryBytes);
    const uint32_t old_ja4_bytes =
        entry.component.owned.ja4_bytes;
    const uint32_t reclaimed = old_ja4_bytes - kJa4SummaryBytes;
    if (!fk_component_flow_shrink_owned(
            table.budget,
            &entry.component,
            FK_COMPONENT_JA4,
            kJa4SummaryBytes)) {
        (void)fk_slab_pool_release_index(
            table.ja4_summary_pool, summary_index);
        fk_component_flow_mark_loss(
            &entry.component, FK_COMPONENT_JA4);
        return false;
    }
    (void)fk_slab_pool_release_index(
        table.ja4_pending_pool, entry.ja4_index);
    entry.ja4_index = summary_index;
    entry.ja4_is_summary = kJa4ModeSummary;
    table.stats.evidence_storage_bytes -= reclaimed;
    table.stats.ja4_compactions++;
    table.stats.ja4_parser_bytes_reclaimed += reclaimed;
    return refresh_entry_value_heaps(table, core_index);
}

static bool reserve_mandatory(
        CompactFlowTable &table,
        uint64_t table_bytes,
        uint64_t core_bytes,
        uint64_t lease_bytes) {
    if (!fk_state_budget_try_reserve(
            table.budget, FK_MEMORY_FLOW_TABLE, table_bytes))
        return false;
    if (!fk_state_budget_try_reserve(
            table.budget, FK_MEMORY_CORE, core_bytes)) {
        (void)fk_state_budget_release(
            table.budget, FK_MEMORY_FLOW_TABLE, table_bytes);
        return false;
    }
    if (!fk_state_budget_try_reserve(
            table.budget, FK_MEMORY_LEASE, lease_bytes)) {
        (void)fk_state_budget_release(
            table.budget, FK_MEMORY_CORE, core_bytes);
        (void)fk_state_budget_release(
            table.budget, FK_MEMORY_FLOW_TABLE, table_bytes);
        return false;
    }
    return true;
}

static void release_mandatory(CompactFlowTable &table) {
    if(table.idle_retirement_guard) {
        (void)fk_state_budget_release(table.budget,FK_MEMORY_LEDGER,
            table.idle_retirement_guard->metadata_bytes);
        table.stats.mandatory_allocation_bytes-=table.idle_retirement_guard->metadata_bytes;
        table.stats.pool_unassigned_bytes+=table.idle_retirement_guard->metadata_bytes;
        table.idle_retirement_guard=nullptr;
    }
    if (table.stats.value_index_allocation_bytes != 0u) {
        (void)fk_state_budget_release(
            table.budget,
            FK_MEMORY_LEDGER,
            table.stats.value_index_allocation_bytes);
        table.stats.mandatory_allocation_bytes -=
            table.stats.value_index_allocation_bytes;
        table.stats.value_index_allocation_bytes = 0u;
    }
    (void)fk_state_budget_release(
        table.budget,
        FK_MEMORY_LEASE,
        table.stats.lease_allocation_bytes);
    (void)fk_state_budget_release(
        table.budget,
        FK_MEMORY_CORE,
        table.stats.core_allocation_bytes);
    (void)fk_state_budget_release(
        table.budget,
        FK_MEMORY_FLOW_TABLE,
        table.stats.flow_table_allocation_bytes);
}

struct PoolPlan {
    uint32_t block_size;
    uint32_t weight;
    uint32_t capacity;
    uint64_t unit_bytes;
    uint64_t overhead_bytes;
};

static constexpr uint64_t kValueIndexBytesPerResident =
    sizeof(uint32_t);

static uint64_t optional_indexes_bytes_per_resident(
        uint32_t maximum_flows) {
    return compact_index_is_narrow(maximum_flows)
        ? kValueIndexBytesPerResident
        : kValueIndexBytesPerResident * 2u;
}

/* The frozen <=65536-flow layout reserves one uint32_t word per typed-pool
 * resident.  Its low half stores the value index and its high half stores a
 * segment of the shared deadline heap, so D=min(maximum_flows,S)<=S and no
 * extra storage is needed.  Wide indexes are charged at exact 4*S + 4*D. */
static bool optional_index_reservation_bytes(
        const uint32_t capacities[kValueHeapCount],
        uint32_t maximum_flows,
        uint64_t &reserved_bytes,
        uint32_t &deadline_capacity) {
    uint64_t resident_capacity = 0u;
    for (uint8_t heap = 0u; heap < kValueHeapCount; ++heap) {
        resident_capacity += capacities[heap];
    }
    deadline_capacity = static_cast<uint32_t>(std::min<uint64_t>(
        maximum_flows, resident_capacity));
    if (resident_capacity >
            std::numeric_limits<uint64_t>::max() /
                kValueIndexBytesPerResident)
        return false;
    reserved_bytes = resident_capacity *
        kValueIndexBytesPerResident;
    if (!compact_index_is_narrow(maximum_flows)) {
        const uint64_t deadline_bytes =
            static_cast<uint64_t>(deadline_capacity) * sizeof(uint32_t);
        if (reserved_bytes >
                std::numeric_limits<uint64_t>::max() - deadline_bytes)
            return false;
        reserved_bytes += deadline_bytes;
    }
    return true;
}

static bool create_value_indexes(
        CompactFlowTable &table,
        const uint32_t capacities[kValueHeapCount],
        char *error,
        size_t error_capacity) {
    uint64_t bytes = 0u;
    uint32_t deadline_capacity = 0u;
    if (!optional_index_reservation_bytes(
            capacities, table.maximum_flows,
            bytes, deadline_capacity))
        return false;
    for (uint8_t heap = 0u; heap < kValueHeapCount; ++heap) {
        if (capacities[heap] == 0u)
            return false;
    }
    if (!fk_state_budget_try_reserve(
            table.budget, FK_MEMORY_LEDGER, bytes)) {
        set_error(error, error_capacity,
                  "value-index ledger exceeds controlled budget");
        return false;
    }
    for (uint8_t heap = 0u; heap < kValueHeapCount; ++heap) {
        table.value_heaps[heap].reset(
            new (std::nothrow) uint32_t[capacities[heap]]());
        if (table.value_heaps[heap] == nullptr) {
            for (uint8_t rollback = 0u;
                 rollback < kValueHeapCount;
                 ++rollback) {
                table.value_heaps[rollback].reset();
                table.value_heap_capacity[rollback] = 0u;
            }
            (void)fk_state_budget_release(
                table.budget, FK_MEMORY_LEDGER, bytes);
            set_error(error, error_capacity,
                      "value-index allocation failed");
            return false;
        }
        table.value_heap_capacity[heap] = capacities[heap];
    }
    if (!compact_index_is_narrow(table.maximum_flows))
        table.optional_deadline_heap.reset(
            new (std::nothrow) uint32_t[deadline_capacity]);
    if (!compact_index_is_narrow(table.maximum_flows) &&
        table.optional_deadline_heap == nullptr) {
        for (uint8_t rollback = 0u;
             rollback < kValueHeapCount;
             ++rollback) {
            table.value_heaps[rollback].reset();
            table.value_heap_capacity[rollback] = 0u;
        }
        (void)fk_state_budget_release(
            table.budget, FK_MEMORY_LEDGER, bytes);
        set_error(error, error_capacity,
                  "deadline-index allocation failed");
        return false;
    }
    table.stats.value_index_allocation_bytes = bytes;
    table.stats.mandatory_allocation_bytes += bytes;
    return true;
}

static bool valid_pool_weights(
        const fk_component_pool_weights &weights) {
    return weights.stat_percent != 0u &&
        weights.seq_percent != 0u &&
        weights.ja4_pending_percent != 0u &&
        weights.ja4_summary_percent != 0u &&
        static_cast<uint32_t>(weights.stat_percent) +
            weights.seq_percent +
            weights.ja4_pending_percent +
            weights.ja4_summary_percent == 100u;
}

static bool minimum_optional_pool_bytes(
        uint32_t maximum_flows,
        const fk_component_pool_weights &weights,
        uint64_t &minimum_bytes) {
    if (maximum_flows == 0u ||
        !valid_pool_weights(weights))
        return false;
    const uint32_t block_sizes[4]{
        sizeof(fk_compact_stat_state),
        sizeof(fk_compact_seq_state),
        sizeof(fk_compact_ja4_state),
        kJa4SummaryBytes,
    };
    uint64_t required = 0u;
    uint32_t capacities[kValueHeapCount]{1u, 1u, 1u, 1u};
    for (uint32_t block_size : block_sizes) {
        const uint64_t one = fk_slab_pool_allocation_bytes(
            block_size, 1u);
        if (one == 0u || required >
                std::numeric_limits<uint64_t>::max() - one)
            return false;
        required += one;
    }
    uint64_t index_bytes = 0u;
    uint32_t deadline_capacity = 0u;
    if (!optional_index_reservation_bytes(
            capacities, maximum_flows,
            index_bytes, deadline_capacity) ||
        required > std::numeric_limits<uint64_t>::max() - index_bytes)
        return false;
    minimum_bytes = required + index_bytes;
    return true;
}

static bool optional_plan_reserved_bytes(
        const PoolPlan plans[4],
        uint64_t fixed_overhead,
        uint32_t maximum_flows,
        uint64_t &reserved) {
    reserved = fixed_overhead;
    uint32_t capacities[kValueHeapCount]{};
    for (uint8_t index = 0u; index < 4u; ++index) {
        const uint64_t bytes =
            static_cast<uint64_t>(plans[index].capacity) *
                plans[index].unit_bytes;
        if (reserved > std::numeric_limits<uint64_t>::max() - bytes)
            return false;
        reserved += bytes;
        capacities[index] = plans[index].capacity;
    }
    uint64_t index_bytes = 0u;
    uint32_t deadline_capacity = 0u;
    if (!optional_index_reservation_bytes(
            capacities, maximum_flows,
            index_bytes, deadline_capacity) ||
        reserved > std::numeric_limits<uint64_t>::max() - index_bytes)
        return false;
    reserved += index_bytes;
    return true;
}

static bool create_optional_pools(
        CompactFlowTable &table,
        uint64_t optional_budget_bytes,
        const fk_component_pool_weights &weights,
        char *error,
        size_t error_capacity) {
    uint64_t minimum_optional_bytes = 0u;
    if (minimum_optional_pool_bytes(
            table.maximum_flows,
            weights,
            minimum_optional_bytes) &&
        optional_budget_bytes < minimum_optional_bytes)
        return false;
    PoolPlan plans[4]{
        {sizeof(fk_compact_stat_state),
         weights.stat_percent, 1u, 0u, 0u},
        {sizeof(fk_compact_seq_state),
         weights.seq_percent, 1u, 0u, 0u},
        {sizeof(fk_compact_ja4_state),
         weights.ja4_pending_percent, 1u, 0u, 0u},
        {kJa4SummaryBytes,
         weights.ja4_summary_percent, 1u, 0u, 0u},
    };
    const uint32_t maximum_capacity =
        std::min(table.maximum_flows, 65535u);
    uint64_t fixed_overhead = 0u;
    for (PoolPlan &plan : plans) {
        const uint64_t one =
            fk_slab_pool_allocation_bytes(plan.block_size, 1u);
        const uint64_t two =
            fk_slab_pool_allocation_bytes(plan.block_size, 2u);
        if (one == 0u || two <= one)
            return false;
        plan.unit_bytes = two - one;
        plan.overhead_bytes = one - plan.unit_bytes;
        fixed_overhead += plan.overhead_bytes;
    }
    if (optional_budget_bytes <= fixed_overhead)
        return false;
    const uint64_t distributable =
        optional_budget_bytes - fixed_overhead;
    uint64_t reserved = 0u;
    for (PoolPlan &plan : plans) {
        const uint64_t share =
            distributable * plan.weight / 100u;
        plan.capacity = static_cast<uint32_t>(std::max<uint64_t>(
            1u,
            std::min<uint64_t>(
                maximum_capacity,
                share /
                    (plan.unit_bytes +
                     optional_indexes_bytes_per_resident(
                         table.maximum_flows)))));
    }
    if (!optional_plan_reserved_bytes(
            plans, fixed_overhead, table.maximum_flows, reserved))
        return false;
    while (reserved > optional_budget_bytes) {
        int selected = -1;
        for (int index = 0; index < 4; ++index) {
            if (plans[index].capacity <= 1u)
                continue;
            const uint64_t unit = plans[index].unit_bytes +
                optional_indexes_bytes_per_resident(
                    table.maximum_flows);
            if (selected < 0 ||
                static_cast<uint64_t>(plans[index].capacity) * unit *
                        plans[selected].weight >
                    static_cast<uint64_t>(plans[selected].capacity) *
                        (plans[selected].unit_bytes +
                         optional_indexes_bytes_per_resident(
                             table.maximum_flows)) *
                        plans[index].weight)
                selected = index;
        }
        if (selected < 0)
            return false;
        plans[selected].capacity--;
        if (!optional_plan_reserved_bytes(
                plans, fixed_overhead, table.maximum_flows, reserved))
            return false;
    }
    for (;;) {
        int selected = -1;
        for (int index = 0; index < 4; ++index) {
            PoolPlan &candidate = plans[index];
            if (candidate.capacity >= maximum_capacity)
                continue;
            candidate.capacity++;
            uint64_t candidate_reserved = 0u;
            const bool fits = optional_plan_reserved_bytes(
                plans,
                fixed_overhead,
                table.maximum_flows,
                candidate_reserved) &&
                candidate_reserved <= optional_budget_bytes;
            candidate.capacity--;
            if (!fits)
                continue;
            if (selected < 0 ||
                static_cast<uint64_t>(candidate.capacity) *
                        (candidate.unit_bytes +
                         optional_indexes_bytes_per_resident(
                             table.maximum_flows)) *
                        plans[selected].weight <
                    static_cast<uint64_t>(plans[selected].capacity) *
                        (plans[selected].unit_bytes +
                         optional_indexes_bytes_per_resident(
                             table.maximum_flows)) *
                        candidate.weight)
                selected = index;
        }
        if (selected < 0)
            break;
        plans[selected].capacity++;
        if (!optional_plan_reserved_bytes(
                plans, fixed_overhead, table.maximum_flows, reserved))
            return false;
    }

    table.stat_pool = fk_slab_pool_create(
        plans[0].block_size, plans[0].capacity,
        error, error_capacity);
    table.seq_pool = fk_slab_pool_create(
        plans[1].block_size, plans[1].capacity,
        error, error_capacity);
    table.ja4_pending_pool = fk_slab_pool_create(
        plans[2].block_size, plans[2].capacity,
        error, error_capacity);
    table.ja4_summary_pool = fk_slab_pool_create(
        plans[3].block_size, plans[3].capacity,
        error, error_capacity);
    if (table.stat_pool == nullptr || table.seq_pool == nullptr ||
        table.ja4_pending_pool == nullptr ||
        table.ja4_summary_pool == nullptr)
        return false;
    const uint32_t index_capacities[kValueHeapCount]{
        plans[0].capacity,
        plans[1].capacity,
        plans[2].capacity,
        plans[3].capacity,
    };
    if (!create_value_indexes(
            table, index_capacities, error, error_capacity))
        return false;
    table.stats.stat_pool_capacity = plans[0].capacity;
    table.stats.seq_pool_capacity = plans[1].capacity;
    table.stats.ja4_pending_pool_capacity = plans[2].capacity;
    table.stats.ja4_summary_pool_capacity = plans[3].capacity;
    uint64_t slab_reserved = fixed_overhead;
    for (const PoolPlan &plan : plans)
        slab_reserved +=
            static_cast<uint64_t>(plan.capacity) * plan.unit_bytes;
    table.stats.pool_reserved_bytes = slab_reserved;
    table.stats.pool_unassigned_bytes =
        optional_budget_bytes - reserved;
    return true;
}

static uint64_t full_optional_index_bytes(uint32_t maximum_flows) {
    const uint32_t capacity = std::min(maximum_flows, 65535u);
    const uint32_t capacities[kValueHeapCount]{
        capacity, capacity, capacity, capacity};
    uint64_t bytes = 0u;
    uint32_t deadline_capacity = 0u;
    return optional_index_reservation_bytes(
        capacities, maximum_flows, bytes, deadline_capacity)
        ? bytes : 0u;
}

static uint64_t full_optional_pool_bytes(uint32_t maximum_flows) {
    const uint32_t capacity = std::min(maximum_flows, 65535u);
    const uint32_t block_sizes[4]{
        sizeof(fk_compact_stat_state),
        sizeof(fk_compact_seq_state),
        sizeof(fk_compact_ja4_state),
        kJa4SummaryBytes,
    };
    uint64_t bytes = 0u;
    for (uint32_t block_size : block_sizes) {
        const uint64_t allocation =
            fk_slab_pool_allocation_bytes(block_size, capacity);
        if (allocation == 0u ||
            bytes > std::numeric_limits<uint64_t>::max() - allocation)
            return 0u;
        bytes += allocation;
    }
    const uint64_t index_bytes = full_optional_index_bytes(maximum_flows);
    if (bytes > std::numeric_limits<uint64_t>::max() - index_bytes)
        return 0u;
    bytes += index_bytes;
    return bytes;
}

static bool create_full_optional_pools(
        CompactFlowTable &table,
        char *error,
        size_t error_capacity) {
    const uint32_t capacity =
        std::min(table.maximum_flows, 65535u);
    table.stat_pool = fk_slab_pool_create(
        sizeof(fk_compact_stat_state), capacity,
        error, error_capacity);
    table.seq_pool = fk_slab_pool_create(
        sizeof(fk_compact_seq_state), capacity,
        error, error_capacity);
    table.ja4_pending_pool = fk_slab_pool_create(
        sizeof(fk_compact_ja4_state), capacity,
        error, error_capacity);
    table.ja4_summary_pool = fk_slab_pool_create(
        kJa4SummaryBytes, capacity,
        error, error_capacity);
    if (table.stat_pool == nullptr || table.seq_pool == nullptr ||
        table.ja4_pending_pool == nullptr ||
        table.ja4_summary_pool == nullptr)
        return false;
    const uint32_t index_capacities[kValueHeapCount]{
        capacity, capacity, capacity, capacity};
    if (!create_value_indexes(
            table, index_capacities, error, error_capacity))
        return false;
    table.stats.stat_pool_capacity = capacity;
    table.stats.seq_pool_capacity = capacity;
    table.stats.ja4_pending_pool_capacity = capacity;
    table.stats.ja4_summary_pool_capacity = capacity;
    table.stats.pool_reserved_bytes =
        full_optional_pool_bytes(table.maximum_flows) -
        table.stats.value_index_allocation_bytes;
    table.stats.pool_unassigned_bytes = 0u;
    return table.stats.pool_reserved_bytes != 0u;
}

static void destroy_optional_pools(CompactFlowTable &table) {
    fk_slab_pool_destroy(table.stat_pool);
    fk_slab_pool_destroy(table.seq_pool);
    fk_slab_pool_destroy(table.ja4_pending_pool);
    fk_slab_pool_destroy(table.ja4_summary_pool);
    table.stat_pool = nullptr;
    table.seq_pool = nullptr;
    table.ja4_pending_pool = nullptr;
    table.ja4_summary_pool = nullptr;
    for (uint8_t heap = 0u; heap < kValueHeapCount; ++heap) {
        table.value_heaps[heap].reset();
        table.value_heap_size[heap] = 0u;
        table.value_heap_capacity[heap] = 0u;
    }
    table.optional_deadline_heap.reset();
    table.optional_deadline_heap_size = 0u;
}

static void fill_snapshot(
        const CoreEntry &entry,
        fk_compact_flow_snapshot *snapshot) {
    if (snapshot == nullptr)
        return;
    std::memset(snapshot, 0, sizeof(*snapshot));
    if (!compact_key_materialize(entry.key, snapshot->key))
        return;
    snapshot->first_timestamp_ns = entry.first_timestamp_ns;
    snapshot->last_timestamp_ns = entry.last_timestamp_ns;
    snapshot->packets = entry.packets;
    snapshot->bytes = entry.bytes;
    snapshot->first_direction = entry.first_direction;
    snapshot->component_mask = entry.component.mask;
    snapshot->observation_complete =
        entry.component.observation_complete;
    snapshot->next_checkpoint_packet =
        entry.component.next_checkpoint_packet;
}

static uint32_t saturating_delta_us(
        uint64_t previous_ns,
        uint64_t timestamp_ns) {
    if (timestamp_ns <= previous_ns)
        return 0u;
    const uint64_t delta = (timestamp_ns - previous_ns) / 1000u;
    return delta > std::numeric_limits<uint32_t>::max()
        ? std::numeric_limits<uint32_t>::max()
        : static_cast<uint32_t>(delta);
}

static uint16_t saturating_u16(uint32_t value) {
    return value > std::numeric_limits<uint16_t>::max()
        ? std::numeric_limits<uint16_t>::max()
        : static_cast<uint16_t>(value);
}

static bool is_grease(uint16_t value) {
    return (value & 0x0f0fu) == 0x0a0au;
}

static uint64_t fnv1a_u16_set(
        const uint16_t *values,
        uint16_t count) {
    uint16_t normalized[FK_TLS_CIPHER_CAP]{};
    uint16_t retained = 0u;
    const uint16_t capacity = static_cast<uint16_t>(
        sizeof(normalized) / sizeof(normalized[0]));
    for (uint16_t index = 0u;
         index < count && retained < capacity; ++index) {
        if (!is_grease(values[index]))
            normalized[retained++] = values[index];
    }
    std::sort(normalized, normalized + retained);
    uint64_t hash = 1469598103934665603ull;
    for (uint16_t index = 0u; index < retained; ++index) {
        hash ^= static_cast<uint8_t>(normalized[index] >> 8u);
        hash *= 1099511628211ull;
        hash ^= static_cast<uint8_t>(normalized[index]);
        hash *= 1099511628211ull;
    }
    return hash;
}

static uint64_t fnv1a_text(const char *text, size_t capacity) {
    /*
     * Zero is the explicit "field absent" sentinel consumed by the compact
     * detector feature builder.  Returning the FNV offset basis for an empty
     * SNI/ALPN made an absent string look present because the feature builder
     * tests hash != 0.
     */
    if (text == nullptr || capacity == 0u || text[0] == '\0')
        return 0u;
    uint64_t hash = 1469598103934665603ull;
    for (size_t index = 0u;
         index < capacity && text[index] != '\0'; ++index) {
        hash ^= static_cast<uint8_t>(text[index]);
        hash *= 1099511628211ull;
    }
    return hash;
}

struct FingerprintCapture {
    fk_compact_ja4_state *state;
    fk_component_flow *component;
    fk_tls_hello_callback callback;
    void *callback_user;
};

static void capture_fingerprint(const fk_tls_hello *hello, void *user) {
    auto *capture = static_cast<FingerprintCapture *>(user);
    fk_compact_fingerprint_observation *observation =
        hello->kind == FK_TLS_CLIENT_HELLO
        ? &capture->state->client : &capture->state->server;
    *observation = {};
    observation->cipher_set_hash =
        fnv1a_u16_set(hello->ciphers, hello->cipher_count);
    observation->extension_set_hash =
        fnv1a_u16_set(hello->extensions, hello->extension_count);
    observation->signature_set_hash = fnv1a_u16_set(
        hello->signature_algorithms,
        hello->signature_algorithm_count);
    observation->server_name_hash =
        fnv1a_text(hello->server_name, FK_TLS_SNI_CAP);
    observation->alpn_hash =
        fnv1a_text(hello->alpn, FK_TLS_ALPN_CAP);
    observation->legacy_version = hello->legacy_version;
    observation->selected_cipher = hello->selected_cipher;
    observation->cipher_count = hello->cipher_count;
    observation->extension_count = hello->extension_count;
    observation->signature_algorithm_count =
        hello->signature_algorithm_count;
    observation->present = 1u;
    observation->hello_retry_request =
        hello->hello_retry_request ? 1u : 0u;
    observation->completeness = static_cast<uint8_t>(hello->completeness);
    observation->framing = static_cast<uint8_t>(hello->framing);
    if (capture->component != nullptr &&
        capture->component->missing_reason[2] !=
            FK_MISSING_LOST_OR_FAILED)
        capture->component->missing_reason[2] = FK_MISSING_PRESENT;
    if (capture->callback != nullptr)
        capture->callback(hello, capture->callback_user);
}

static bool tls_candidate(const fk_packet_view &view) {
    if (view.l4_protocol != 6u)
        return false;
    const uint16_t ports[2]{view.src_port, view.dst_port};
    for (uint16_t port : ports) {
        switch (port) {
        case 443u:
        case 465u:
        case 636u:
        case 853u:
        case 989u:
        case 990u:
        case 993u:
        case 995u:
        case 5061u:
        case 8443u:
        case 9443u:
            return true;
        default:
            break;
        }
    }
    return false;
}

static void ensure_provisional_tls(
        CompactFlowTable &table,
        uint32_t core_index,
        const fk_packet_view &view,
        uint64_t timestamp_ns) {
    CoreEntry &entry = table.cores[core_index];
    if (entry.component.decision_started != 0u ||
        (entry.evidence_mask & FK_COMPONENT_JA4) != 0u ||
        entry.ja4_is_summary == kJa4ModeProvisional ||
        timestamp_ns >= entry.component.absolute_deadline_ns ||
        (entry.component.released_mask & FK_COMPONENT_JA4) != 0u ||
        entry.component.missing_reason[2] == FK_MISSING_LOST_OR_FAILED ||
        !tls_candidate(view))
        return;
    const uint32_t bytes = sizeof(fk_compact_ja4_state);
    if (!fk_state_budget_try_reserve(
            table.budget, FK_MEMORY_JA4, bytes)) {
        table.stats.bootstrap_tls_budget_rejects++;
        fk_component_flow_mark_loss(
            &entry.component, FK_COMPONENT_JA4);
        return;
    }
    uint16_t index = 0u;
    void *memory = nullptr;
    if (!fk_slab_pool_acquire_index(
            table.ja4_pending_pool, &index, &memory)) {
        (void)fk_state_budget_release(
            table.budget, FK_MEMORY_JA4, bytes);
        table.stats.bootstrap_tls_pool_rejects++;
        fk_component_flow_mark_loss(
            &entry.component, FK_COMPONENT_JA4);
        return;
    }
    entry.ja4_index = index;
    entry.ja4_is_summary = kJa4ModeProvisional;
    entry.component.owned.ja4_bytes = bytes;
    note_optional_deadline(table, core_index);
    table.stats.bootstrap_tls_admissions++;
    table.stats.evidence_storage_bytes += bytes;
    if (table.stats.evidence_storage_bytes >
        table.stats.peak_evidence_storage_bytes) {
        table.stats.peak_evidence_storage_bytes =
            table.stats.evidence_storage_bytes;
    }
    if (!refresh_entry_value_heaps(table, core_index))
        fk_component_flow_mark_loss(
            &entry.component, FK_COMPONENT_JA4);
}

static uint32_t transition_capacity_available(
        const CompactFlowTable &table) {
    return FK_COMPACT_TRANSITION_CAPACITY - table.transition_count;
}

static bool transition_owner_valid(
        const CompactFlowTable &table,
        fk_compact_flow_handle handle) {
    if (!valid_handle(table, handle))
        return false;
    const CoreEntry &owner = table.cores[handle.index];
    return (owner.key.ip_version == 4u || owner.key.ip_version == 6u) &&
        (owner.key.protocol == 6u || owner.key.protocol == 17u) &&
        (owner.key.protocol != 6u || owner.logical_connection_id == 0u);
}

static bool append_transition(
        CompactFlowTable &table,
        fk_compact_evidence_transition transition) {
    if (table.transition_count >= FK_COMPACT_TRANSITION_CAPACITY) {
        table.stats.transition_queue_full_rejects++;
        return false;
    }
    if (!transition_owner_valid(table, transition.victim_handle)) {
        table.stats.allocator_integrity_failures++;
        return false;
    }
    const CoreEntry &victim =
        table.cores[transition.victim_handle.index];
    if (!compact_key_materialize(victim.key, transition.victim_key)) {
        table.stats.allocator_integrity_failures++;
        return false;
    }
    transition.victim_flow_first_timestamp_ns = victim.first_timestamp_ns;
    transition.victim_logical_connection_id = victim.logical_connection_id;
    const uint32_t tail =
        (table.transition_head + table.transition_count) %
        FK_COMPACT_TRANSITION_CAPACITY;
    transition.sequence = table.next_transition_sequence++;
    table.transitions[tail] = transition;
    table.transition_count++;
    table.stats.transition_records_emitted++;
    return true;
}

static bool component_resident(
        const CoreEntry &entry,
        uint8_t component) {
    if ((entry.evidence_mask & component) != 0u)
        return true;
    return component == FK_COMPONENT_JA4 &&
        entry.ja4_is_summary == kJa4ModeProvisional &&
        entry.component.owned.ja4_bytes != 0u;
}

static uint8_t resident_component_mask(const CoreEntry &entry) {
    uint8_t mask = entry.evidence_mask;
    if (entry.ja4_is_summary == kJa4ModeProvisional)
        mask |= FK_COMPONENT_JA4;
    return mask;
}

static bool commit_component_release_after_budget(
        CompactFlowTable &table,
        uint32_t core_index,
        uint8_t component,
        fk_compact_transition_reason reason,
        fk_compact_flow_handle causing_handle,
        uint32_t causing_packet_count,
        uint64_t timestamp_ns,
        float victim_loss,
        float incoming_gain,
        float victim_total_loss,
        float eta,
        bool release_slab) {
    if (core_index >= table.maximum_flows ||
        transition_capacity_available(table) == 0u)
        return false;
    CoreEntry &entry = table.cores[core_index];
    if (entry.used == 0u || !component_resident(entry, component))
        return false;
    const fk_compact_flow_handle victim_handle{
        core_index, entry.generation};
    if (!transition_owner_valid(table, victim_handle))
        return false;
    const uint64_t bytes = component_owned_bytes(entry, component);
    if (bytes == 0u)
        return false;
    /* Evidence-transition masks describe physical residency, not only the
     * policy-selected logical mask.  In particular, a pre-decision JA4 slab
     * is physically resident while its logical component bit is still zero.
     * Keeping both ends physical gives every release one invariant shape:
     * final_mask == previous_mask & ~component. */
    const uint8_t previous_mask = resident_component_mask(entry);
    if(auto *evidence=flowkeep::EvidenceFor(reinterpret_cast<fk_compact_flow_table*>(&table)))
        flowkeep::EvidenceCapture(evidence,
            reinterpret_cast<fk_compact_flow_table*>(&table),victim_handle,
            component,flowkeep::EvidenceBeforeRelease,static_cast<uint32_t>(reason));
    if (release_slab && !fk_slab_pool_release_index(
            component_pool(table, entry, component),
            component_slab_index(entry, component)))
        return false;
    set_component_owned_bytes(entry.component, component, 0u);
    entry.component.mask = static_cast<uint8_t>(
        entry.component.mask & ~component);
    entry.component.released_mask |= component;
    entry.component.missing_reason[component_array_index(component)] =
        FK_MISSING_NOT_SELECTED;
    entry.evidence_mask = static_cast<uint8_t>(
        entry.evidence_mask & ~component);
    set_component_slab_index(entry, component, 0u);
    if (component == FK_COMPONENT_JA4) {
        if (entry.ja4_is_summary == kJa4ModeProvisional)
            table.stats.bootstrap_tls_releases++;
        entry.ja4_is_summary = kJa4ModePending;
    }
    if (!has_optional_resident(entry))
        invalidate_removed_optional_deadline(table, core_index);
    if (bytes > table.stats.evidence_storage_bytes) {
        table.stats.allocator_integrity_failures++;
        return false;
    }
    table.stats.evidence_storage_bytes -= bytes;
    fk_compact_evidence_transition transition{};
    transition.timestamp_ns = timestamp_ns;
    transition.victim_handle = {core_index, entry.generation};
    transition.causing_handle = causing_handle;
    transition.causing_packet_count = causing_packet_count;
    transition.previous_mask = previous_mask;
    transition.final_mask = resident_component_mask(entry);
    transition.released_mask = entry.component.released_mask;
    transition.component = component;
    transition.reason = reason;
    transition.bytes_released = bytes;
    transition.victim_loss = victim_loss;
    transition.victim_value_per_byte =
        victim_loss / static_cast<float>(bytes);
    transition.incoming_bundle_gain = incoming_gain;
    transition.victim_total_loss = victim_total_loss;
    transition.hysteresis_eta = eta;
    if (!append_transition(table, transition))
        return false;
    return true;
}

static bool release_component_and_trace(
        CompactFlowTable &table,
        uint32_t core_index,
        uint8_t component,
        fk_compact_transition_reason reason,
        fk_compact_flow_handle causing_handle,
        uint32_t causing_packet_count,
        uint64_t timestamp_ns,
        float victim_loss,
        float incoming_gain,
        float victim_total_loss,
        float eta,
        bool refresh_heap) {
    if (core_index >= table.maximum_flows ||
        transition_capacity_available(table) == 0u)
        return false;
    CoreEntry &entry = table.cores[core_index];
    if (entry.used == 0u || !component_resident(entry, component))
        return false;
    const fk_compact_flow_handle victim_handle{
        core_index, entry.generation};
    if (!transition_owner_valid(table, victim_handle))
        return false;
    const uint64_t bytes = component_owned_bytes(entry, component);
    fk_slab_pool *pool = component_pool(table, entry, component);
    if (bytes == 0u || fk_slab_pool_get_index(
            pool, component_slab_index(entry, component)) == nullptr ||
        bytes > table.stats.evidence_storage_bytes)
        return false;
    if(!persist_lifecycle(table,core_index,FK_COMPACT_PERSIST_COMPONENT_RELEASE))return false;
    if (!detach_entry_value_heaps(table, core_index))
        return false;
    uint64_t releases[FK_MEMORY_COMPONENT_COUNT]{};
    uint64_t reserves[FK_MEMORY_COMPONENT_COUNT]{};
    releases[component_memory_kind(component)] = bytes;
    if (!fk_state_budget_apply_transaction(
            table.budget, releases, reserves)) {
        (void)refresh_entry_value_heaps(table, core_index);
        return false;
    }
    if (!commit_component_release_after_budget(
            table,
            core_index,
            component,
            reason,
            causing_handle,
            causing_packet_count,
            timestamp_ns,
            victim_loss,
            incoming_gain,
            victim_total_loss,
            eta,
            true)) {
        table.stats.allocator_integrity_failures++;
        return false;
    }
    return !refresh_heap || refresh_entry_value_heaps(table, core_index);
}

static bool checked_add_u64(uint64_t &target, uint64_t value);

static bool release_all_optional_for_reason(
        CompactFlowTable &table,
        uint32_t core_index,
        fk_compact_transition_reason reason,
        fk_compact_flow_handle causing_handle,
        uint32_t causing_packet_count,
        uint64_t timestamp_ns) {
    if (core_index >= table.maximum_flows)
        return false;
    CoreEntry &entry = table.cores[core_index];
    const fk_compact_flow_handle victim_handle{
        core_index, entry.generation};
    if (!transition_owner_valid(table, victim_handle))
        return false;
    const uint8_t resident = resident_component_mask(entry);
    uint32_t count = 0u;
    for (uint8_t component : {
             static_cast<uint8_t>(FK_COMPONENT_STAT),
             static_cast<uint8_t>(FK_COMPONENT_SEQ),
             static_cast<uint8_t>(FK_COMPONENT_JA4)})
        count += (resident & component) != 0u ? 1u : 0u;
    if (count > transition_capacity_available(table)) {
        table.stats.transition_queue_full_rejects++;
        return false;
    }
    uint64_t releases[FK_MEMORY_COMPONENT_COUNT]{};
    uint64_t reserves[FK_MEMORY_COMPONENT_COUNT]{};
    uint64_t total_bytes = 0u;
    for (uint8_t component : {
             static_cast<uint8_t>(FK_COMPONENT_STAT),
             static_cast<uint8_t>(FK_COMPONENT_SEQ),
             static_cast<uint8_t>(FK_COMPONENT_JA4)}) {
        if ((resident & component) == 0u)
            continue;
        const uint64_t bytes = component_owned_bytes(entry, component);
        const bool slab_valid = fk_slab_pool_get_index(
            component_pool(table, entry, component),
            component_slab_index(entry, component)) != nullptr;
        if (bytes == 0u ||
            !checked_add_u64(total_bytes, bytes) ||
            !checked_add_u64(
                releases[component_memory_kind(component)], bytes) ||
            !slab_valid)
            return false;
    }
    if (total_bytes > table.stats.evidence_storage_bytes)
        return false;
    // A metadata-only expiry does not free evidence. Persist the complete
    // Core at retirement/shutdown instead of syncing an empty release here.
    // total_bytes includes physically resident provisional TLS even while
    // the logical component mask is NONE, so real slab releases stay guarded.
    if(total_bytes != 0u &&
        !persist_lifecycle(table,core_index,FK_COMPACT_PERSIST_COMPONENT_RELEASE))return false;
    if (!detach_entry_value_heaps(table, core_index))
        return false;
    if (!fk_state_budget_apply_transaction(
            table.budget, releases, reserves)) {
        (void)refresh_entry_value_heaps(table, core_index);
        return false;
    }
    for (uint8_t component : {
             static_cast<uint8_t>(FK_COMPONENT_STAT),
             static_cast<uint8_t>(FK_COMPONENT_SEQ),
             static_cast<uint8_t>(FK_COMPONENT_JA4)}) {
        if ((resident & component) == 0u)
            continue;
        const float loss = removal_loss_for_mask(
            entry, replacement_planning_mask(entry), component);
        if (!commit_component_release_after_budget(
                table,
                core_index,
                component,
                reason,
                causing_handle,
                causing_packet_count,
                timestamp_ns,
                std::isfinite(loss) ? loss : 0.0f,
                0.0f,
                0.0f,
                0.0f,
                true)) {
            table.stats.allocator_integrity_failures++;
            return false;
        }
    }
    entry.component.released_mask |= FK_COMPONENT_FULL;
    return refresh_entry_value_heaps(table, core_index);
}

struct PlannedValueVictim {
    uint32_t core_index;
    uint32_t generation;
    uint8_t component;
    uint8_t previous_mask;
    uint8_t final_mask;
    uint8_t donates_storage;
    uint64_t bytes;
    float loss;
};

struct TouchedValueVictim {
    uint32_t core_index;
    uint32_t generation;
    uint8_t planning_mask;
    uint8_t resident_mask;
};

struct ValueVictimCandidate {
    bool valid;
    bool from_heap;
    uint8_t heap;
    uint8_t component;
    uint32_t core_index;
    uint32_t touched_index;
    uint64_t bytes;
    uint64_t deadline_ns;
    float loss;
    float density;
};

static bool victim_candidate_less(
        const ValueVictimCandidate &left,
        const ValueVictimCandidate &right) {
    if (!right.valid)
        return left.valid;
    if (!left.valid)
        return false;
    if (left.density != right.density)
        return left.density < right.density;
    if (left.deadline_ns != right.deadline_ns)
        return left.deadline_ns < right.deadline_ns;
    if (left.core_index != right.core_index)
        return left.core_index < right.core_index;
    return left.component < right.component;
}

static bool heap_needed_for_typed_pool(
        uint8_t heap,
        const bool pool_needed[kValueHeapCount]) {
    return heap < kValueHeapCount && pool_needed[heap];
}

static uint8_t component_heap_for_new_state(uint8_t component) {
    return component == FK_COMPONENT_STAT ? kValueHeapStat :
        component == FK_COMPONENT_SEQ ? kValueHeapSeq :
        kValueHeapJa4Pending;
}

static uint32_t mask_component_count(uint8_t mask) {
    uint32_t count = 0u;
    while (mask != 0u) {
        count += mask & 1u;
        mask >>= 1u;
    }
    return count;
}

static bool checked_add_u64(uint64_t &target, uint64_t value) {
    if (value > std::numeric_limits<uint64_t>::max() - target)
        return false;
    target += value;
    return true;
}

static uint64_t seeded_random_mix(uint64_t value) {
    value += UINT64_C(0x9e3779b97f4a7c15);
    value = (value ^ (value >> 30u)) * UINT64_C(0xbf58476d1ce4e5b9);
    value = (value ^ (value >> 27u)) * UINT64_C(0x94d049bb133111eb);
    return value ^ (value >> 31u);
}

static uint64_t seeded_random_victim_rank(
        uint64_t seed,
        fk_compact_flow_handle incoming,
        uint32_t causing_packet_count,
        uint64_t timestamp_ns,
        uint32_t victim_ordinal,
        uint32_t candidate_index,
        uint32_t candidate_generation) {
    uint64_t rank = seeded_random_mix(seed);
    rank = seeded_random_mix(
        rank ^ (static_cast<uint64_t>(incoming.index) << 32u) ^
        incoming.generation);
    rank = seeded_random_mix(
        rank ^ (static_cast<uint64_t>(causing_packet_count) << 32u) ^
        victim_ordinal);
    rank = seeded_random_mix(rank ^ timestamp_ns);
    return seeded_random_mix(
        rank ^ (static_cast<uint64_t>(candidate_index) << 32u) ^
        candidate_generation);
}

static void restore_detached_value_heaps(
        CompactFlowTable &table,
        const std::array<TouchedValueVictim,
                         kAtomicMaximumVictimFlows> &touched,
        uint32_t touched_count,
        uint32_t incoming_index) {
    for (uint32_t index = 0u; index < touched_count; ++index)
        (void)refresh_entry_value_heaps(
            table, touched[index].core_index);
    (void)refresh_entry_value_heaps(table, incoming_index);
}

static fk_compact_value_replacement_status
commit_value_replacement_internal(
        CompactFlowTable &table,
        fk_compact_flow_handle incoming_handle,
        uint8_t desired_mask,
        bool ja4_applicable,
        AtomicReplacementMode replacement_mode,
        uint32_t maximum_lru_victim_flows,
        uint32_t causing_packet_count,
        uint64_t timestamp_ns,
        const fk_component_policy_config &config,
        fk_transition_result &transition_result,
        fk_compact_value_replacement_outcome &outcome,
        uint64_t seeded_random_seed = 0u,
        const fk_compact_release_guard *release_guard = nullptr) {
    outcome = {};
    transition_result = FK_TRANSITION_ILLEGAL_MASK;
    outcome.status = FK_COMPACT_VALUE_REPLACEMENT_INVALID;
    const float eta = table.value_eviction.hysteresis_eta;
    const float epsilon = table.value_eviction.hysteresis_epsilon;
    const uint32_t maximum_victims =
        table.value_eviction.maximum_victim_components;
    outcome.hysteresis_eta = eta;
    outcome.hysteresis_epsilon = epsilon;
    if (!valid_handle(table, incoming_handle) ||
        (desired_mask & ~FK_COMPONENT_FULL) != 0u ||
        maximum_victims == 0u ||
        ((replacement_mode == AtomicReplacementMode::Lru ||
          replacement_mode == AtomicReplacementMode::Lfu ||
          replacement_mode == AtomicReplacementMode::Fifo ||
          replacement_mode == AtomicReplacementMode::SeededRandom ||
          replacement_mode == AtomicReplacementMode::Clock ||
          replacement_mode == AtomicReplacementMode::TwoQ ||
          replacement_mode == AtomicReplacementMode::Arc ||
          replacement_mode == AtomicReplacementMode::Gdsf) &&
         (maximum_lru_victim_flows == 0u ||
          maximum_lru_victim_flows > kAtomicMaximumVictimFlows)))
        return outcome.status;
    CoreEntry &incoming = table.cores[incoming_handle.index];
    fk_component_bytes component_bytes{};
    component_bytes.stat_bytes = sizeof(fk_compact_stat_state);
    component_bytes.seq_bytes = sizeof(fk_compact_seq_state);
    component_bytes.ja4_bytes = sizeof(fk_compact_ja4_state);
    fk_component_flow planned_incoming{};
    uint64_t incoming_release[3]{};
    uint64_t incoming_reserve[3]{};
    if (!fk_component_flow_plan_transition(
            &incoming.component,
            desired_mask,
            &component_bytes,
            ja4_applicable,
            causing_packet_count,
            timestamp_ns,
            &config,
            &planned_incoming,
            incoming_release,
            incoming_reserve,
            &transition_result))
        return outcome.status;
    if (transition_result != FK_TRANSITION_APPLIED &&
        transition_result != FK_TRANSITION_NO_CHANGE)
        return outcome.status;
    if (consume_atomic_fault(
            table, AtomicFaultPoint::AfterFlowPlan)) {
        transition_result = FK_TRANSITION_ILLEGAL_MASK;
        return outcome.status;
    }
    if (transition_result == FK_TRANSITION_NO_CHANGE) {
        incoming.component = planned_incoming;
        outcome.status = FK_COMPACT_VALUE_REPLACEMENT_NOT_NEEDED;
        return outcome.status;
    }

    const uint8_t resident_before = resident_component_mask(incoming);
    const uint8_t added_physical = static_cast<uint8_t>(
        desired_mask & ~resident_before);
    const uint8_t local_release_mask = static_cast<uint8_t>(
        resident_before & ~desired_mask);
    fk_slab_pool_stats pool_stats[kValueHeapCount]{};
    if (!fk_slab_pool_get_stats(table.stat_pool, &pool_stats[0]) ||
        !fk_slab_pool_get_stats(table.seq_pool, &pool_stats[1]) ||
        !fk_slab_pool_get_stats(
            table.ja4_pending_pool, &pool_stats[2]) ||
        !fk_slab_pool_get_stats(
            table.ja4_summary_pool, &pool_stats[3]))
        return outcome.status;
    bool pool_needed[kValueHeapCount]{};
    pool_needed[kValueHeapStat] =
        (added_physical & FK_COMPONENT_STAT) != 0u &&
        pool_stats[kValueHeapStat].in_use >=
            pool_stats[kValueHeapStat].capacity;
    pool_needed[kValueHeapSeq] =
        (added_physical & FK_COMPONENT_SEQ) != 0u &&
        pool_stats[kValueHeapSeq].in_use >=
            pool_stats[kValueHeapSeq].capacity;
    pool_needed[kValueHeapJa4Pending] =
        (added_physical & FK_COMPONENT_JA4) != 0u &&
        pool_stats[kValueHeapJa4Pending].in_use >=
            pool_stats[kValueHeapJa4Pending].capacity;
    bool typed_required_initial[kValueHeapCount]{};
    std::copy_n(pool_needed, kValueHeapCount, typed_required_initial);

    fk_budget_snapshot budget{};
    fk_state_budget_snapshot(table.budget, &budget);
    uint64_t incoming_release_total = 0u;
    uint64_t incoming_reserve_total = 0u;
    for (uint8_t index = 0u; index < 3u; ++index) {
        if (!checked_add_u64(
                incoming_release_total, incoming_release[index]) ||
            !checked_add_u64(
                incoming_reserve_total, incoming_reserve[index]))
            return outcome.status;
    }
    const uint64_t available_budget =
        budget.used_bytes < budget.budget_bytes
        ? budget.budget_bytes - budget.used_bytes : 0u;
    const uint64_t financed_without_victims =
        available_budget >
                std::numeric_limits<uint64_t>::max() -
                    incoming_release_total
            ? std::numeric_limits<uint64_t>::max()
            : available_budget + incoming_release_total;
    const uint64_t budget_deficit =
        incoming_reserve_total > financed_without_victims
        ? incoming_reserve_total - financed_without_victims : 0u;
    bool typed_needed = pool_needed[kValueHeapStat] ||
        pool_needed[kValueHeapSeq] ||
        pool_needed[kValueHeapJa4Pending];
    const bool replacement_needed = typed_needed || budget_deficit != 0u;
    if (replacement_needed &&
        replacement_mode == AtomicReplacementMode::None) {
        outcome.status = FK_COMPACT_VALUE_REPLACEMENT_NO_PLAN;
        return outcome.status;
    }
    float incoming_gain = 0.0f;
    if (replacement_needed &&
        replacement_mode == AtomicReplacementMode::Value) {
        if (incoming.component.initial_action_values_valid == 0u)
            return outcome.status;
        table.stats.value_replacement_attempts++;
        incoming_gain = std::max(
            0.0f,
            incoming.component.initial_action_values[desired_mask] -
            incoming.component.initial_action_values[
                incoming.component.mask]);
    }
    outcome.incoming_bundle_gain = incoming_gain;

    std::array<PlannedValueVictim,
               kAtomicMaximumVictimComponents> plan{};
    std::array<TouchedValueVictim,
               kAtomicMaximumVictimFlows> touched{};
    uint32_t plan_count = 0u;
    uint32_t touched_count = 0u;
    uint64_t released_bytes = 0u;
    float total_loss = 0.0f;
    float gdsf_planned_aging = table.gdsf_aging_priority;
    bool incoming_detached = false;
    if (replacement_needed) {
        if (!detach_entry_value_heaps(table, incoming_handle.index))
            return outcome.status;
        incoming_detached = true;
    }

    if (replacement_mode == AtomicReplacementMode::Value) {
    while (typed_needed || released_bytes < budget_deficit) {
        if (plan_count >= maximum_victims) {
            restore_detached_value_heaps(
                table, touched, touched_count, incoming_handle.index);
            outcome.status = FK_COMPACT_VALUE_REPLACEMENT_NO_PLAN;
            table.stats.value_replacement_rejects++;
            table.stats.value_victim_probes += outcome.victim_probes;
            return outcome.status;
        }
        ValueVictimCandidate best{};
        for (uint8_t heap = 0u; heap < kValueHeapCount; ++heap) {
            if (typed_needed &&
                !heap_needed_for_typed_pool(heap, pool_needed))
                continue;
            if (table.value_heap_size[heap] == 0u)
                continue;
            const uint32_t core_index = value_index_get(
                table.value_heaps[heap], 0u, table.maximum_flows);
            const CoreEntry &entry = table.cores[core_index];
            if (entry.component.initial_action_values_valid == 0u)
                continue;
            const uint8_t component = heap_component(heap);
            ValueVictimCandidate candidate{};
            candidate.valid = true;
            candidate.from_heap = true;
            candidate.heap = heap;
            candidate.component = component;
            candidate.core_index = core_index;
            candidate.bytes = component_owned_bytes(entry, component);
            candidate.deadline_ns = entry.component.absolute_deadline_ns;
            candidate.loss = removal_loss_for_mask(
                entry, replacement_planning_mask(entry), component);
            candidate.density = candidate.loss /
                static_cast<float>(candidate.bytes);
            outcome.victim_probes++;
            if (victim_candidate_less(candidate, best))
                best = candidate;
        }
        for (uint32_t touched_index = 0u;
             touched_index < touched_count;
             ++touched_index) {
            const TouchedValueVictim &virtual_entry =
                touched[touched_index];
            const CoreEntry &entry =
                table.cores[virtual_entry.core_index];
            if (entry.component.initial_action_values_valid == 0u)
                continue;
            for (uint8_t component : {
                     static_cast<uint8_t>(FK_COMPONENT_STAT),
                     static_cast<uint8_t>(FK_COMPONENT_SEQ),
                     static_cast<uint8_t>(FK_COMPONENT_JA4)}) {
                if ((virtual_entry.resident_mask & component) == 0u)
                    continue;
                const uint8_t heap = entry_heap_for_component(
                    entry, component);
                if (typed_needed &&
                    !heap_needed_for_typed_pool(heap, pool_needed))
                    continue;
                ValueVictimCandidate candidate{};
                candidate.valid = true;
                candidate.from_heap = false;
                candidate.heap = heap;
                candidate.component = component;
                candidate.core_index = virtual_entry.core_index;
                candidate.touched_index = touched_index;
                candidate.bytes = component_owned_bytes(entry, component);
                candidate.deadline_ns =
                    entry.component.absolute_deadline_ns;
                candidate.loss = removal_loss_for_mask(
                    entry, virtual_entry.planning_mask, component);
                candidate.density = candidate.loss /
                    static_cast<float>(candidate.bytes);
                outcome.victim_probes++;
                if (victim_candidate_less(candidate, best))
                    best = candidate;
            }
        }
        if (!best.valid || best.bytes == 0u ||
            !std::isfinite(best.density)) {
            restore_detached_value_heaps(
                table, touched, touched_count, incoming_handle.index);
            outcome.status = FK_COMPACT_VALUE_REPLACEMENT_NO_PLAN;
            table.stats.value_replacement_rejects++;
            table.stats.value_victim_probes += outcome.victim_probes;
            return outcome.status;
        }

        uint32_t touched_index = best.touched_index;
        if (best.from_heap) {
            if (touched_count >= touched.size() ||
                !detach_entry_value_heaps(table, best.core_index)) {
                restore_detached_value_heaps(
                    table, touched, touched_count, incoming_handle.index);
                outcome.status = FK_COMPACT_VALUE_REPLACEMENT_INVALID;
                table.stats.value_victim_probes += outcome.victim_probes;
                return outcome.status;
            }
            touched_index = touched_count++;
            const CoreEntry &entry = table.cores[best.core_index];
            touched[touched_index] = TouchedValueVictim{
                best.core_index,
                entry.generation,
                replacement_planning_mask(entry),
                resident_component_mask(entry),
            };
        }
        TouchedValueVictim &virtual_entry = touched[touched_index];
        const CoreEntry &entry = table.cores[virtual_entry.core_index];
        const uint8_t previous_mask = virtual_entry.planning_mask;
        best.loss = removal_loss_for_mask(
            entry, previous_mask, best.component);
        best.density = best.loss / static_cast<float>(best.bytes);
        virtual_entry.planning_mask = static_cast<uint8_t>(
            virtual_entry.planning_mask & ~best.component);
        virtual_entry.resident_mask = static_cast<uint8_t>(
            virtual_entry.resident_mask & ~best.component);
        plan[plan_count++] = PlannedValueVictim{
            best.core_index,
            entry.generation,
            best.component,
            previous_mask,
            virtual_entry.planning_mask,
            0u,
            best.bytes,
            best.loss,
        };
        released_bytes += best.bytes;
        total_loss += best.loss;
        if (best.heap < kValueHeapCount)
            pool_needed[best.heap] = false;
        typed_needed = pool_needed[kValueHeapStat] ||
            pool_needed[kValueHeapSeq] ||
            pool_needed[kValueHeapJa4Pending];
    }
    } else if (replacement_mode == AtomicReplacementMode::Lru ||
               replacement_mode == AtomicReplacementMode::Lfu ||
               replacement_mode == AtomicReplacementMode::Fifo ||
               replacement_mode == AtomicReplacementMode::SeededRandom ||
               replacement_mode == AtomicReplacementMode::Clock ||
               replacement_mode == AtomicReplacementMode::TwoQ ||
               replacement_mode == AtomicReplacementMode::Arc ||
               replacement_mode == AtomicReplacementMode::Gdsf) {
        uint32_t victim_flows = 0u;
        while (typed_needed || released_bytes < budget_deficit) {
            if (victim_flows >= maximum_lru_victim_flows ||
                touched_count >= touched.size()) {
                restore_detached_value_heaps(
                    table, touched, touched_count, incoming_handle.index);
                outcome.status = FK_COMPACT_VALUE_REPLACEMENT_NO_PLAN;
                return outcome.status;
            }
            uint32_t victim_index = kNoIndex;
            uint64_t least_primary = std::numeric_limits<uint64_t>::max();
            uint64_t least_secondary =
                std::numeric_limits<uint64_t>::max();
            long double least_gdsf_score =
                std::numeric_limits<long double>::infinity();
            uint32_t arc_t1_resident = 0u;
            uint32_t arc_t2_resident = 0u;
            if (replacement_mode == AtomicReplacementMode::Arc) {
                for (uint32_t core_index = 0u;
                     core_index < table.maximum_flows; ++core_index) {
                    const CoreEntry *entry = core_entry_if_allocated(
                        table, core_index);
                    if (entry == nullptr || entry->used == 0u ||
                        core_index == incoming_handle.index ||
                        resident_component_mask(*entry) == FK_COMPONENT_NONE)
                        continue;
                    const uint8_t arc_class = static_cast<uint8_t>(
                        entry->fixed_ttl_deadline & kArcClassMask);
                    if (arc_class == kArcT1)
                        ++arc_t1_resident;
                    else if (arc_class == kArcT2)
                        ++arc_t2_resident;
                }
            }
            const bool arc_choose_t1 =
                replacement_mode == AtomicReplacementMode::Arc &&
                (arc_t2_resident == 0u ||
                 arc_t1_resident > table.arc_target_t1_entries);
            const uint64_t scan_limit =
                replacement_mode == AtomicReplacementMode::Clock
                ? static_cast<uint64_t>(table.maximum_flows) * 2u
                : table.maximum_flows;
            for (uint64_t scan = 0u; scan < scan_limit; ++scan) {
                const uint32_t core_index =
                    replacement_mode == AtomicReplacementMode::Clock
                    ? static_cast<uint32_t>(
                        (static_cast<uint64_t>(
                             table.clock_replacement_hand) + scan) %
                        table.maximum_flows)
                    : static_cast<uint32_t>(scan);
                CoreEntry *entry = core_entry_if_allocated(
                    table, core_index);
                if (entry == nullptr || entry->used == 0u ||
                    core_index == incoming_handle.index)
                    continue;
                bool already_planned = false;
                for (uint32_t touched_index = 0u;
                     touched_index < touched_count; ++touched_index) {
                    if (touched[touched_index].core_index == core_index) {
                        already_planned = true;
                        break;
                    }
                }
                if (already_planned)
                    continue;
                const uint8_t resident = resident_component_mask(*entry);
                if (resident == FK_COMPONENT_NONE)
                    continue;
                bool helps_typed = !typed_needed;
                if (typed_needed) {
                    for (uint8_t component : {
                             static_cast<uint8_t>(FK_COMPONENT_STAT),
                             static_cast<uint8_t>(FK_COMPONENT_SEQ),
                             static_cast<uint8_t>(FK_COMPONENT_JA4)}) {
                        if ((resident & component) == 0u)
                            continue;
                        const uint8_t heap = entry_heap_for_component(
                            *entry, component);
                        helps_typed = helps_typed ||
                            (heap < kValueHeapCount && pool_needed[heap]);
                    }
                }
                if (!helps_typed)
                    continue;
                if (replacement_mode == AtomicReplacementMode::Clock &&
                    (entry->fixed_ttl_deadline & kClockReferenceFlag) != 0u) {
                    entry->fixed_ttl_deadline = static_cast<uint8_t>(
                        entry->fixed_ttl_deadline & ~kClockReferenceFlag);
                    continue;
                }
                if (replacement_mode == AtomicReplacementMode::Arc) {
                    const uint8_t arc_class = static_cast<uint8_t>(
                        entry->fixed_ttl_deadline & kArcClassMask);
                    if ((arc_choose_t1 && arc_class != kArcT1) ||
                        (!arc_choose_t1 && arc_class != kArcT2))
                        continue;
                }
                uint64_t primary =
                    replacement_mode == AtomicReplacementMode::SeededRandom
                    ? seeded_random_victim_rank(
                        seeded_random_seed, incoming_handle,
                        causing_packet_count, timestamp_ns, victim_flows,
                        core_index, entry->generation)
                    : (replacement_mode == AtomicReplacementMode::Lru
                        ? entry->last_timestamp_ns
                        : (replacement_mode == AtomicReplacementMode::Fifo
                            ? entry->first_timestamp_ns : entry->packets));
                uint64_t secondary =
                    replacement_mode == AtomicReplacementMode::Lfu
                    ? entry->first_timestamp_ns : 0u;
                if (replacement_mode == AtomicReplacementMode::Clock ||
                    replacement_mode == AtomicReplacementMode::Arc) {
                    primary = entry->last_timestamp_ns;
                } else if (replacement_mode == AtomicReplacementMode::TwoQ) {
                    const bool frequent =
                        (entry->fixed_ttl_deadline &
                         kTwoQFrequentFlag) != 0u;
                    primary = (frequent ? (UINT64_C(1) << 63u) : 0u) |
                        (frequent ? entry->last_timestamp_ns :
                                    entry->first_timestamp_ns);
                } else if (replacement_mode == AtomicReplacementMode::Gdsf) {
                    uint64_t resident_bytes = 0u;
                    for (uint8_t component : {
                             static_cast<uint8_t>(FK_COMPONENT_STAT),
                             static_cast<uint8_t>(FK_COMPONENT_SEQ),
                             static_cast<uint8_t>(FK_COMPONENT_JA4)}) {
                        if ((resident & component) != 0u)
                            resident_bytes +=
                                component_owned_bytes(*entry, component);
                    }
                    if (resident_bytes == 0u)
                        continue;
                    float &base_priority =
                        entry->component.initial_action_values[0];
                    if (entry->component.initial_action_values[7] != -1.0f ||
                        !std::isfinite(base_priority) ||
                        base_priority < 0.0f) {
                        base_priority = table.gdsf_aging_priority;
                        entry->component.initial_action_values[7] = -1.0f;
                    }
                    const long double score =
                        static_cast<long double>(base_priority) +
                        static_cast<long double>(entry->packets) /
                            static_cast<long double>(resident_bytes);
                    if (victim_index == kNoIndex ||
                        score < least_gdsf_score ||
                        (score == least_gdsf_score &&
                         core_index < victim_index)) {
                        victim_index = core_index;
                        least_gdsf_score = score;
                    }
                    continue;
                }
                if (victim_index == kNoIndex ||
                    primary < least_primary ||
                    (primary == least_primary &&
                     secondary < least_secondary) ||
                    (primary == least_primary &&
                     secondary == least_secondary &&
                     core_index < victim_index)) {
                    victim_index = core_index;
                    least_primary = primary;
                    least_secondary = secondary;
                }
                if (replacement_mode == AtomicReplacementMode::Clock &&
                    victim_index != kNoIndex)
                    break;
            }
            if (replacement_mode == AtomicReplacementMode::Clock &&
                victim_index != kNoIndex) {
                table.clock_replacement_hand =
                    victim_index + 1u == table.maximum_flows
                    ? 0u : victim_index + 1u;
            }
            if (replacement_mode == AtomicReplacementMode::Gdsf &&
                victim_index != kNoIndex &&
                std::isfinite(least_gdsf_score)) {
                gdsf_planned_aging = static_cast<float>(least_gdsf_score);
            }
            if (victim_index == kNoIndex ||
                !detach_entry_value_heaps(table, victim_index)) {
                restore_detached_value_heaps(
                    table, touched, touched_count, incoming_handle.index);
                outcome.status = FK_COMPACT_VALUE_REPLACEMENT_NO_PLAN;
                return outcome.status;
            }
            CoreEntry &victim_entry = table.cores[victim_index];
            const uint8_t resident = resident_component_mask(victim_entry);
            TouchedValueVictim &virtual_entry = touched[touched_count++];
            virtual_entry = TouchedValueVictim{
                victim_index,
                victim_entry.generation,
                replacement_planning_mask(victim_entry),
                resident,
            };
            victim_flows++;
            for (uint8_t component : {
                     static_cast<uint8_t>(FK_COMPONENT_STAT),
                     static_cast<uint8_t>(FK_COMPONENT_SEQ),
                     static_cast<uint8_t>(FK_COMPONENT_JA4)}) {
                if ((resident & component) == 0u)
                    continue;
                if (plan_count >= plan.size()) {
                    restore_detached_value_heaps(
                        table, touched, touched_count,
                        incoming_handle.index);
                    outcome.status = FK_COMPACT_VALUE_REPLACEMENT_NO_PLAN;
                    return outcome.status;
                }
                const uint8_t previous_mask = virtual_entry.planning_mask;
                float loss = removal_loss_for_mask(
                    victim_entry, previous_mask, component);
                if (!std::isfinite(loss))
                    loss = 0.0f;
                virtual_entry.planning_mask = static_cast<uint8_t>(
                    virtual_entry.planning_mask & ~component);
                virtual_entry.resident_mask = static_cast<uint8_t>(
                    virtual_entry.resident_mask & ~component);
                plan[plan_count++] = PlannedValueVictim{
                    victim_index,
                    victim_entry.generation,
                    component,
                    previous_mask,
                    virtual_entry.planning_mask,
                    0u,
                    component_owned_bytes(victim_entry, component),
                    loss,
                };
                released_bytes += component_owned_bytes(
                    victim_entry, component);
                total_loss += loss;
                const uint8_t heap = entry_heap_for_component(
                    victim_entry, component);
                if (heap < kValueHeapCount)
                    pool_needed[heap] = false;
            }
            typed_needed = pool_needed[kValueHeapStat] ||
                pool_needed[kValueHeapSeq] ||
                pool_needed[kValueHeapJa4Pending];
        }
        outcome.victim_flows = victim_flows;
    }

    if (consume_atomic_fault(
            table, AtomicFaultPoint::AfterVictimPlan)) {
        restore_detached_value_heaps(
            table, touched, touched_count, incoming_handle.index);
        transition_result = FK_TRANSITION_ILLEGAL_MASK;
        return outcome.status;
    }

    outcome.victim_components = plan_count;
    outcome.bytes_released = released_bytes;
    outcome.victim_total_loss = total_loss;
    if (replacement_mode == AtomicReplacementMode::Value)
        table.stats.value_victim_probes += outcome.victim_probes;
    if (replacement_needed &&
        replacement_mode == AtomicReplacementMode::Value &&
        !(incoming_gain >
            (1.0f + eta) * total_loss + epsilon)) {
        restore_detached_value_heaps(
            table, touched, touched_count, incoming_handle.index);
        outcome.status = FK_COMPACT_VALUE_REPLACEMENT_VALUE_REJECTED;
        table.stats.value_replacement_rejects++;
        return outcome.status;
    }
    const uint32_t transition_count = plan_count +
        mask_component_count(local_release_mask);
    if (transition_count > transition_capacity_available(table)) {
        restore_detached_value_heaps(
            table, touched, touched_count, incoming_handle.index);
        outcome.status = FK_COMPACT_VALUE_REPLACEMENT_TRACE_FULL;
        table.stats.transition_queue_full_rejects++;
        if (replacement_mode == AtomicReplacementMode::Value)
            table.stats.value_replacement_rejects++;
        return outcome.status;
    }
    if (local_release_mask != FK_COMPONENT_NONE &&
        !transition_owner_valid(table, incoming_handle)) {
        restore_detached_value_heaps(
            table, touched, touched_count, incoming_handle.index);
        return outcome.status;
    }

    uint64_t ledger_release[FK_MEMORY_COMPONENT_COUNT]{};
    uint64_t ledger_reserve[FK_MEMORY_COMPONENT_COUNT]{};
    for (uint8_t index = 0u; index < 3u; ++index) {
        const fk_memory_component kind = index == 0u ? FK_MEMORY_STAT :
            index == 1u ? FK_MEMORY_SEQ : FK_MEMORY_JA4;
        ledger_release[kind] = incoming_release[index];
        ledger_reserve[kind] = incoming_reserve[index];
    }
    for (uint32_t index = 0u; index < plan_count; ++index) {
        PlannedValueVictim &victim = plan[index];
        if (victim.core_index >= table.maximum_flows) {
            restore_detached_value_heaps(
                table, touched, touched_count, incoming_handle.index);
            return outcome.status;
        }
        const CoreEntry &entry = table.cores[victim.core_index];
        if (entry.used == 0u || entry.generation != victim.generation ||
            !transition_owner_valid(
                table, {victim.core_index, victim.generation}) ||
            !component_resident(entry, victim.component) ||
            component_owned_bytes(entry, victim.component) != victim.bytes ||
            fk_slab_pool_get_index(
                component_pool(table,
                               const_cast<CoreEntry &>(entry),
                               victim.component),
                component_slab_index(entry, victim.component)) == nullptr) {
            restore_detached_value_heaps(
                table, touched, touched_count, incoming_handle.index);
            return outcome.status;
        }
        if (!checked_add_u64(
                ledger_release[component_memory_kind(victim.component)],
                victim.bytes)) {
            restore_detached_value_heaps(
                table, touched, touched_count, incoming_handle.index);
            return outcome.status;
        }
    }
    fk_state_budget_snapshot(table.budget, &budget);
    uint64_t total_release = 0u;
    uint64_t total_reserve = 0u;
    bool ledger_valid = true;
    for (uint8_t component = 0u;
         component < FK_MEMORY_COMPONENT_COUNT; ++component) {
        ledger_valid = ledger_valid &&
            budget.used_by_component[component] >=
                ledger_release[component] &&
            checked_add_u64(total_release, ledger_release[component]) &&
            checked_add_u64(total_reserve, ledger_reserve[component]);
    }
    const uint64_t after_release = ledger_valid &&
            budget.used_bytes >= total_release
        ? budget.used_bytes - total_release : 0u;
    ledger_valid = ledger_valid && budget.used_bytes >= total_release &&
        after_release <= budget.budget_bytes &&
        total_reserve <= budget.budget_bytes - after_release;
    const uint64_t evidence_after_release =
        ledger_valid &&
            table.stats.evidence_storage_bytes >= total_release
        ? table.stats.evidence_storage_bytes - total_release : 0u;
    ledger_valid = ledger_valid &&
        table.stats.evidence_storage_bytes >= total_release &&
        total_reserve <=
            std::numeric_limits<uint64_t>::max() - evidence_after_release;
    if (!ledger_valid) {
        restore_detached_value_heaps(
            table, touched, touched_count, incoming_handle.index);
        return outcome.status;
    }

    for (uint8_t component : {
             static_cast<uint8_t>(FK_COMPONENT_STAT),
             static_cast<uint8_t>(FK_COMPONENT_SEQ),
             static_cast<uint8_t>(FK_COMPONENT_JA4)}) {
        if ((local_release_mask & component) == 0u)
            continue;
        if (fk_slab_pool_get_index(
                component_pool(table, incoming, component),
                component_slab_index(incoming, component)) == nullptr) {
            restore_detached_value_heaps(
                table, touched, touched_count, incoming_handle.index);
            return outcome.status;
        }
    }

    if(table.lifecycle_guard && !release_guard && (local_release_mask || plan_count)) {
        restore_detached_value_heaps(table,touched,touched_count,incoming_handle.index);
        return outcome.status; // Reject unguarded atomic bypass in persistent mode.
    }
    if (release_guard && (local_release_mask || plan_count)) {
        std::array<fk_compact_release_request,kAtomicMaximumVictimFlows+1u> requests{};
        size_t count=0;
        if(local_release_mask)requests[count++]={incoming_handle,local_release_mask};
        for(uint32_t i=0;i<plan_count;++i) {
            const auto &victim=plan[i];size_t j=0;
            for(;j<count;++j)if(requests[j].handle.index==victim.core_index &&
                requests[j].handle.generation==victim.generation)break;
            if(j==count) {
                if(count==requests.size()) {
                    restore_detached_value_heaps(table,touched,touched_count,incoming_handle.index);
                    return outcome.status;
                }
                requests[count++]={{victim.core_index,victim.generation},0};
            }
            requests[j].mask=static_cast<uint8_t>(requests[j].mask|victim.component);
        }
        bool authorized=false;
        try {authorized=release_guard->authorize(release_guard->context,requests.data(),count);}
        catch(...) {authorized=false;}
        if(!authorized) {
            restore_detached_value_heaps(table,touched,touched_count,incoming_handle.index);
            outcome.status=FK_COMPACT_VALUE_REPLACEMENT_PERSISTENCE_PENDING;
            transition_result=FK_TRANSITION_STORAGE_FAILED;
            return outcome.status;
        }
    }

    uint16_t prepared_index[3]{};
    uint8_t prepared_kind[3]{};  /* 1=acquired, 2=victim transfer. */
    const auto rollback_prepared_storage = [&]() {
        for (uint8_t rollback = 0u; rollback < 3u; ++rollback) {
            if (prepared_kind[rollback] != 1u)
                continue;
            (void)fk_slab_pool_release_index(
                heap_pool(table,
                    component_heap_for_new_state(
                        static_cast<uint8_t>(1u << rollback))),
                prepared_index[rollback]);
            prepared_kind[rollback] = 0u;
        }
    };
    if (consume_atomic_fault(
            table, AtomicFaultPoint::BeforeStoragePrepare)) {
        restore_detached_value_heaps(
            table, touched, touched_count, incoming_handle.index);
        transition_result = FK_TRANSITION_ILLEGAL_MASK;
        return outcome.status;
    }
    for (uint8_t component : {
             static_cast<uint8_t>(FK_COMPONENT_STAT),
             static_cast<uint8_t>(FK_COMPONENT_SEQ),
             static_cast<uint8_t>(FK_COMPONENT_JA4)}) {
        if ((added_physical & component) == 0u)
            continue;
        const uint8_t component_index = component_array_index(component);
        const uint8_t heap = component_heap_for_new_state(component);
        if (typed_required_initial[heap]) {
            bool donor_found = false;
            for (uint32_t plan_index = 0u;
                 plan_index < plan_count; ++plan_index) {
                PlannedValueVictim &victim = plan[plan_index];
                CoreEntry &victim_entry = table.cores[victim.core_index];
                if (victim.component != component ||
                    entry_heap_for_component(
                        victim_entry, victim.component) != heap)
                    continue;
                victim.donates_storage = 1u;
                prepared_index[component_index] =
                    component_slab_index(victim_entry, victim.component);
                prepared_kind[component_index] = 2u;
                donor_found = true;
                break;
            }
            if (!donor_found) {
                restore_detached_value_heaps(
                    table, touched, touched_count, incoming_handle.index);
                return outcome.status;
            }
        }
    }

    if (!incoming_detached &&
        !detach_entry_value_heaps(table, incoming_handle.index))
        return outcome.status;
    incoming_detached = true;
    for (uint8_t component : {
             static_cast<uint8_t>(FK_COMPONENT_STAT),
             static_cast<uint8_t>(FK_COMPONENT_SEQ),
             static_cast<uint8_t>(FK_COMPONENT_JA4)}) {
        if ((added_physical & component) == 0u)
            continue;
        const uint8_t component_index = component_array_index(component);
        if (prepared_kind[component_index] != 0u)
            continue;
        void *memory = nullptr;
        const uint8_t heap = component_heap_for_new_state(component);
        if (!fk_slab_pool_acquire_index(
                heap_pool(table, heap),
                &prepared_index[component_index],
                &memory)) {
            rollback_prepared_storage();
            restore_detached_value_heaps(
                table, touched, touched_count, incoming_handle.index);
            outcome.status = FK_COMPACT_VALUE_REPLACEMENT_NO_PLAN;
            if (replacement_mode == AtomicReplacementMode::Value &&
                replacement_needed)
                table.stats.value_replacement_rejects++;
            return outcome.status;
        }
        prepared_kind[component_index] = 1u;
    }

    if (consume_atomic_fault(
            table, AtomicFaultPoint::AfterStoragePrepare) ||
        consume_atomic_fault(
            table, AtomicFaultPoint::BeforeBudgetCommit)) {
        rollback_prepared_storage();
        restore_detached_value_heaps(
            table, touched, touched_count, incoming_handle.index);
        transition_result = FK_TRANSITION_ILLEGAL_MASK;
        return outcome.status;
    }

    if (!fk_state_budget_apply_transaction(
            table.budget, ledger_release, ledger_reserve)) {
        rollback_prepared_storage();
        restore_detached_value_heaps(
            table, touched, touched_count, incoming_handle.index);
        outcome.status = FK_COMPACT_VALUE_REPLACEMENT_NO_PLAN;
        if (replacement_mode == AtomicReplacementMode::Value &&
            replacement_needed)
            table.stats.value_replacement_rejects++;
        return outcome.status;
    }

    /* From here every capacity, ledger balance, slab handle and trace slot
     * has been validated.  The single owner performs one non-failing commit. */
    const fk_compact_transition_reason victim_reason =
        replacement_mode == AtomicReplacementMode::Lru
        ? FK_COMPACT_TRANSITION_LRU_EVICTED
        : (replacement_mode == AtomicReplacementMode::Lfu
            ? FK_COMPACT_TRANSITION_LFU_EVICTED
            : (replacement_mode == AtomicReplacementMode::Fifo
                ? FK_COMPACT_TRANSITION_FIFO_EVICTED
                : (replacement_mode == AtomicReplacementMode::SeededRandom
                    ? FK_COMPACT_TRANSITION_SEEDED_RANDOM_EVICTED
                    : (replacement_mode == AtomicReplacementMode::Clock
                        ? FK_COMPACT_TRANSITION_CLOCK_EVICTED
                        : (replacement_mode == AtomicReplacementMode::TwoQ
                            ? FK_COMPACT_TRANSITION_TWO_Q_EVICTED
                            : (replacement_mode == AtomicReplacementMode::Arc
                                ? FK_COMPACT_TRANSITION_ARC_EVICTED
                                : (replacement_mode ==
                                           AtomicReplacementMode::Gdsf
                                    ? FK_COMPACT_TRANSITION_GDSF_EVICTED
                                    : FK_COMPACT_TRANSITION_VALUE_REPLACED)))))));
    for (uint32_t index = 0u; index < plan_count; ++index) {
        const PlannedValueVictim &victim = plan[index];
        CoreEntry &entry = table.cores[victim.core_index];
        if (replacement_planning_mask(entry) != victim.previous_mask ||
            !commit_component_release_after_budget(
                table,
                victim.core_index,
                victim.component,
                victim_reason,
                incoming_handle,
                causing_packet_count,
                timestamp_ns,
                victim.loss,
                incoming_gain,
                total_loss,
                eta,
                victim.donates_storage == 0u)) {
            table.stats.allocator_integrity_failures++;
            outcome.status = FK_COMPACT_VALUE_REPLACEMENT_INVALID;
            return outcome.status;
        }
    }
    if (replacement_mode == AtomicReplacementMode::Arc) {
        for (uint32_t index = 0u; index < touched_count; ++index) {
            CoreEntry &entry = table.cores[touched[index].core_index];
            if (resident_component_mask(entry) != FK_COMPONENT_NONE)
                continue;
            const uint8_t arc_class = static_cast<uint8_t>(
                entry.fixed_ttl_deadline & kArcClassMask);
            const uint8_t ghost = arc_class == kArcT1 ? kArcB1 : kArcB2;
            entry.fixed_ttl_deadline = static_cast<uint8_t>(
                (entry.fixed_ttl_deadline & ~kArcClassMask) | ghost);
        }
    } else if (replacement_mode == AtomicReplacementMode::Gdsf &&
               plan_count != 0u && std::isfinite(gdsf_planned_aging)) {
        table.gdsf_aging_priority = gdsf_planned_aging;
    }

    const fk_compact_transition_reason local_reason =
        incoming.component.decision_started == 0u
        ? FK_COMPACT_TRANSITION_FIRST_DECISION_RELEASED
        : FK_COMPACT_TRANSITION_POLICY_RELEASED;
    for (uint8_t component : {
             static_cast<uint8_t>(FK_COMPONENT_STAT),
             static_cast<uint8_t>(FK_COMPONENT_SEQ),
             static_cast<uint8_t>(FK_COMPONENT_JA4)}) {
        if ((local_release_mask & component) == 0u)
            continue;
        const float loss = removal_loss_for_mask(
            incoming, replacement_planning_mask(incoming), component);
        if (!commit_component_release_after_budget(
                table,
                incoming_handle.index,
                component,
                local_reason,
                incoming_handle,
                causing_packet_count,
                timestamp_ns,
                std::isfinite(loss) ? loss : 0.0f,
                0.0f,
                0.0f,
                0.0f,
                true)) {
            table.stats.allocator_integrity_failures++;
            outcome.status = FK_COMPACT_VALUE_REPLACEMENT_INVALID;
            return outcome.status;
        }
    }

    for (uint8_t component : {
             static_cast<uint8_t>(FK_COMPONENT_STAT),
             static_cast<uint8_t>(FK_COMPONENT_SEQ),
             static_cast<uint8_t>(FK_COMPONENT_JA4)}) {
        if ((added_physical & component) == 0u)
            continue;
        const uint8_t component_index = component_array_index(component);
        set_component_slab_index(
            incoming, component, prepared_index[component_index]);
        if (prepared_kind[component_index] == 2u) {
            fk_slab_pool *pool = heap_pool(
                table, component_heap_for_new_state(component));
            void *memory = fk_slab_pool_get_index(
                pool, prepared_index[component_index]);
            if (memory == nullptr) {
                table.stats.allocator_integrity_failures++;
                outcome.status = FK_COMPACT_VALUE_REPLACEMENT_INVALID;
                return outcome.status;
            }
            std::memset(
                memory,
                0,
                component == FK_COMPONENT_STAT
                    ? sizeof(fk_compact_stat_state) :
                component == FK_COMPONENT_SEQ
                    ? sizeof(fk_compact_seq_state) :
                    sizeof(fk_compact_ja4_state));
        }
        if (component == FK_COMPONENT_JA4)
            incoming.ja4_is_summary = kJa4ModePending;
    }
    if ((desired_mask & FK_COMPONENT_JA4) != 0u &&
        incoming.ja4_is_summary == kJa4ModeProvisional)
        incoming.ja4_is_summary = kJa4ModePending;
    incoming.component = planned_incoming;
    incoming.evidence_mask = desired_mask;
    note_optional_deadline(table, incoming_handle.index);
    if (!checked_add_u64(
            table.stats.evidence_storage_bytes,
            incoming_reserve_total)) {
        table.stats.allocator_integrity_failures++;
        outcome.status = FK_COMPACT_VALUE_REPLACEMENT_INVALID;
        return outcome.status;
    }
    table.stats.peak_evidence_storage_bytes = std::max(
        table.stats.peak_evidence_storage_bytes,
        table.stats.evidence_storage_bytes);
    restore_detached_value_heaps(
        table, touched, touched_count, incoming_handle.index);
    outcome.status = plan_count != 0u
        ? FK_COMPACT_VALUE_REPLACEMENT_COMMITTED
        : FK_COMPACT_VALUE_REPLACEMENT_NOT_NEEDED;
    if (plan_count != 0u &&
        replacement_mode == AtomicReplacementMode::Value) {
        table.stats.value_replacement_commits++;
        table.stats.value_components_evicted += plan_count;
    }
    return outcome.status;
}

static bool release_due_before_observation(
        CompactFlowTable &table,
        uint32_t core_index,
        uint64_t timestamp_ns,
        uint32_t causing_packet_count) {
    CoreEntry &entry = table.cores[core_index];
    fk_compact_transition_reason reason{};
    bool due = false;
    if (timestamp_ns >= entry.component.absolute_deadline_ns) {
        reason = (entry.fixed_ttl_deadline & kFixedTtlDeadlineFlag) != 0u
            ? FK_COMPACT_TRANSITION_FIXED_TTL_EXPIRED
            : FK_COMPACT_TRANSITION_LEASE_EXPIRED;
        due = true;
    }
    if (!due || entry.component.released_mask == FK_COMPONENT_FULL)
        return true;
    const fk_compact_flow_handle causing{core_index, entry.generation};
    if (!release_all_optional_for_reason(
            table,
            core_index,
            reason,
            causing,
            causing_packet_count,
            entry.component.absolute_deadline_ns))
        return false;
    if (reason == FK_COMPACT_TRANSITION_FIXED_TTL_EXPIRED)
        table.stats.fixed_ttl_expirations++;
    else
        table.stats.lease_expirations++;
    return true;
}

static uint32_t power_of_two_floor(uint64_t value) {
    if (value == 0u)
        return 0u;
    uint32_t result = 1u;
    while (result <= (UINT32_MAX >> 1u) &&
           static_cast<uint64_t>(result << 1u) <= value) {
        result <<= 1u;
    }
    return result;
}

/* Spend at most two fifths of a bounded shard budget on continuation state,
 * while retaining enough room for every typed optional pool.  Budgeted mode
 * consumes the exact number of entries that fit instead of rounding it down
 * to a power of two.  At the frozen 64 MiB / 32-shard operating point this
 * provides at least as many entries as the former 200-byte/one-half plan,
 * while returning 10% of the shard ceiling to optional evidence or a lower
 * matched-quality ceiling.  The frozen 64 MiB / 32-shard fixture grows from
 * 4862 to more than 5100 entries despite using fewer directory bytes.
 * Full-capacity reference fixtures retain their power-of-two directory.
 * Four entries are the correctness floor: a one-slot table can displace A for
 * B and must not overwrite A while B itself is displaced to resume A. */
static bool continuation_capacity_plan(
        uint32_t maximum_flows,
        uint64_t controlled_budget_bytes,
        bool full_capacity,
        const fk_component_pool_weights *pool_weights,
        uint32_t &capacity) {
    constexpr uint32_t kMinimumCapacity = kContinuationMinimumCapacity;
    if (maximum_flows == 0u)
        return false;
    const uint64_t entries_per_flow = full_capacity
        ? kFullContinuationEntriesPerFlow
        : kControlledContinuationEntriesPerFlow;
    const uint64_t maximum_entries = std::max<uint64_t>(
        kMinimumCapacity,
        static_cast<uint64_t>(maximum_flows) * entries_per_flow);
    if (full_capacity) {
        capacity = power_of_two_floor(maximum_entries);
        return capacity >= kMinimumCapacity;
    }
    if (pool_weights == nullptr)
        return false;
    uint64_t base_table_bytes = 0u;
    uint64_t core_bytes = 0u;
    uint64_t lease_bytes = 0u;
    uint64_t base_mandatory_bytes = 0u;
    uint64_t minimum_optional_bytes = 0u;
    if (!mandatory_allocation_plan(
            maximum_flows,
            0u,
            base_table_bytes,
            core_bytes,
            lease_bytes,
            base_mandatory_bytes) ||
        !minimum_optional_pool_bytes(
            maximum_flows, *pool_weights, minimum_optional_bytes) ||
        controlled_budget_bytes < base_mandatory_bytes ||
        controlled_budget_bytes - base_mandatory_bytes <
            minimum_optional_bytes) {
        return false;
    }
    const uint64_t available_bytes =
        controlled_budget_bytes - base_mandatory_bytes -
        minimum_optional_bytes;
    const uint64_t minimum_directory_bytes =
        static_cast<uint64_t>(kMinimumCapacity) *
        sizeof(CapacityContinuationEntry);
    if (available_bytes < minimum_directory_bytes)
        return false;
    /* Near the mandatory floor, optional evidence is already the scarce
     * experimental resource.  Keep only the four-entry correctness floor;
     * scaling the directory there would silently erase the intended typed-
     * pool pressure regime (notably the 16 MiB protocol point). */
    if (base_mandatory_bytes > UINT64_MAX / 2u ||
        controlled_budget_bytes < base_mandatory_bytes * 2u) {
        capacity = kMinimumCapacity;
        return true;
    }
    const uint64_t target_bytes = std::min(
        available_bytes, (controlled_budget_bytes / 5u) * 2u);
    const uint64_t target_entries = std::min(
        maximum_entries,
        target_bytes / sizeof(CapacityContinuationEntry));
    if (target_entries > UINT32_MAX)
        return false;
    capacity = static_cast<uint32_t>(target_entries);
    return capacity >= kMinimumCapacity;
}

}  // namespace

extern "C" {

bool fk_compact_flow_table_minimum_controlled_budget_bytes(
        uint32_t maximum_flows,
        const fk_component_pool_weights *pool_weights,
        uint64_t *minimum_bytes) {
    if (pool_weights == nullptr || minimum_bytes == nullptr)
        return false;
    uint64_t table_bytes = 0u;
    uint64_t core_bytes = 0u;
    uint64_t lease_bytes = 0u;
    uint64_t mandatory_bytes = 0u;
    uint64_t optional_bytes = 0u;
    if (!mandatory_allocation_plan(
            maximum_flows,
            kContinuationMinimumCapacity,
            table_bytes,
            core_bytes,
            lease_bytes,
            mandatory_bytes) ||
        !minimum_optional_pool_bytes(
            maximum_flows, *pool_weights, optional_bytes) ||
        mandatory_bytes >
            std::numeric_limits<uint64_t>::max() - optional_bytes)
        return false;
    const uint64_t compaction_credit = structural_compaction_credit(
        maximum_flows, kContinuationMinimumCapacity);
    const uint64_t continuation_headroom =
        continuation_payload_bytes(kContinuationMinimumCapacity);
    if (mandatory_bytes + optional_bytes >
            std::numeric_limits<uint64_t>::max() - continuation_headroom ||
        mandatory_bytes + optional_bytes + continuation_headroom >
            std::numeric_limits<uint64_t>::max() - compaction_credit)
        return false;
    *minimum_bytes = mandatory_bytes + optional_bytes +
        continuation_headroom + compaction_credit;
    return true;
}

fk_compact_flow_table *fk_compact_flow_table_create(
        uint32_t maximum_flows,
        uint64_t controlled_budget_bytes,
        const fk_component_policy_config *policy,
        char *error,
        size_t error_capacity) {
    const fk_component_pool_weights weights{10u, 15u, 60u, 15u};
    return fk_compact_flow_table_create_with_pool_weights(
        maximum_flows,
        controlled_budget_bytes,
        policy,
        &weights,
        error,
        error_capacity);
}

fk_compact_flow_table *fk_compact_flow_table_create_with_pool_weights(
        uint32_t maximum_flows,
        uint64_t controlled_budget_bytes,
        const fk_component_policy_config *policy,
        const fk_component_pool_weights *pool_weights,
        char *error,
        size_t error_capacity) {
    set_error(error, error_capacity, "");
    const bool full_capacity =
        controlled_budget_bytes == 0u && pool_weights == nullptr;
    const uint32_t weight_total = pool_weights == nullptr ? 0u :
        static_cast<uint32_t>(pool_weights->stat_percent) +
        pool_weights->seq_percent +
        pool_weights->ja4_pending_percent +
        pool_weights->ja4_summary_percent;
    if (maximum_flows == 0u || maximum_flows > 1048576u ||
        !fk_component_policy_config_valid(policy) ||
        (!full_capacity &&
         (controlled_budget_bytes == 0u ||
          pool_weights == nullptr ||
          pool_weights->stat_percent == 0u ||
          pool_weights->seq_percent == 0u ||
          pool_weights->ja4_pending_percent == 0u ||
          pool_weights->ja4_summary_percent == 0u ||
          weight_total != 100u))) {
        set_error(error, error_capacity, "invalid compact table config");
        return nullptr;
    }
    CompactFlowTable *table = new (std::nothrow) CompactFlowTable();
    if (table == nullptr) {
        set_error(error, error_capacity, "table allocation failed");
        return nullptr;
    }
    table->maximum_flows = maximum_flows;
    table->hash_capacity = hash_capacity(maximum_flows);
    table->policy = *policy;

    uint32_t continuation_capacity = 0u;
    if (!continuation_capacity_plan(
            maximum_flows,
            controlled_budget_bytes,
            full_capacity,
            pool_weights,
            continuation_capacity)) {
        delete table;
        set_error(error, error_capacity,
                  "controlled budget cannot fit continuation directory");
        return nullptr;
    }
    table->continuation_capacity = continuation_capacity;

    uint64_t table_bytes = 0u;
    uint64_t core_bytes = 0u;
    uint64_t lease_bytes = 0u;
    uint64_t mandatory_bytes = 0u;
    if (!mandatory_allocation_plan(
            maximum_flows,
            continuation_capacity,
            table_bytes,
            core_bytes,
            lease_bytes,
            mandatory_bytes)) {
        delete table;
        set_error(error, error_capacity, "mandatory allocation size overflow");
        return nullptr;
    }
    table->stats.flow_table_allocation_bytes = table_bytes;
    table->stats.core_allocation_bytes = 0u;
    table->stats.lease_allocation_bytes = 0u;
    table->stats.mandatory_allocation_bytes = table_bytes;
    table->stats.maximum_flows = maximum_flows;
    table->stats.hash_capacity = table->hash_capacity;
    table->stats.free_flow_slots = maximum_flows;
    table->stats.continuation_directory_capacity =
        continuation_capacity;
    table->stats.continuation_directory_reserved_bytes =
        continuation_payload_bytes(continuation_capacity);
    const uint64_t continuation_headroom =
        continuation_payload_bytes(continuation_capacity);
    if (full_capacity) {
        const uint64_t optional_bytes =
            full_optional_pool_bytes(maximum_flows);
        const uint64_t ipv6_side_capacity_bytes =
            static_cast<uint64_t>(maximum_flows) * 32u;
        if (optional_bytes == 0u ||
            mandatory_bytes >
                std::numeric_limits<uint64_t>::max() - optional_bytes ||
            mandatory_bytes + optional_bytes >
                std::numeric_limits<uint64_t>::max() -
                    continuation_headroom ||
            mandatory_bytes + optional_bytes +
                    continuation_headroom >
                std::numeric_limits<uint64_t>::max() -
                    ipv6_side_capacity_bytes) {
            delete table;
            set_error(error, error_capacity, "full-capacity size overflow");
            return nullptr;
        }
        controlled_budget_bytes =
            mandatory_bytes + optional_bytes +
            continuation_headroom + ipv6_side_capacity_bytes;
    }
    table->budget = fk_state_budget_create(controlled_budget_bytes);
    if (table->budget == nullptr) {
        delete table;
        set_error(error, error_capacity, "budget allocation failed");
        return nullptr;
    }
    if (!reserve_mandatory(
            *table, table_bytes, 0u, 0u)) {
        fk_state_budget_destroy(table->budget);
        delete table;
        set_error(
            error,
            error_capacity,
            "mandatory FlowTable+CORE+lease exceeds controlled budget");
        return nullptr;
    }

    table->slots.reset(new (std::nothrow) HashSlot[table->hash_capacity]());
    table->cores.page_count = core_page_count(maximum_flows);
    table->cores.pages.reset(
        new (std::nothrow) CorePage[table->cores.page_count]());
    table->core_slots.reset(
        new (std::nothrow) CoreSlotMetadata[maximum_flows]());
    table->continuation_pages.reset(
        new (std::nothrow)
            ContinuationPage[
                continuation_page_count(continuation_capacity)]());
    if (!table->slots || !table->cores.pages || !table->core_slots ||
        !table->continuation_pages) {
        release_mandatory(*table);
        fk_state_budget_destroy(table->budget);
        delete table;
        set_error(error, error_capacity,
                  "compact array/index allocation failed");
        return nullptr;
    }
    uint64_t optional_budget_bytes =
        controlled_budget_bytes - mandatory_bytes;
    const uint64_t compaction_credit = full_capacity
        ? static_cast<uint64_t>(maximum_flows) * 32u
        : structural_compaction_credit(
              maximum_flows, continuation_capacity);
    if (optional_budget_bytes < continuation_headroom ||
        optional_budget_bytes - continuation_headroom <
            compaction_credit) {
        release_mandatory(*table);
        fk_state_budget_destroy(table->budget);
        delete table;
        set_error(error, error_capacity,
                  "dynamic structural headroom exceeds optional budget");
        return nullptr;
    }
    /* Do not silently reinvest mandatory-layout savings into larger optional
     * pools.  Using the legacy optional-pool envelope preserves the exact
     * evidence capacity/quality contract, while the unassigned credit is
     * available to IPv6 side keys and remains a real saving for IPv4. */
    optional_budget_bytes -= continuation_headroom;
    optional_budget_bytes -= compaction_credit;
    const bool pools_created = full_capacity
        ? create_full_optional_pools(*table, error, error_capacity)
        : create_optional_pools(
            *table, optional_budget_bytes, *pool_weights,
            error, error_capacity);
    if (!pools_created) {
        destroy_optional_pools(*table);
        release_mandatory(*table);
        fk_state_budget_destroy(table->budget);
        delete table;
        set_error(
            error,
            error_capacity,
            "optional slab pools do not fit the controlled budget");
        return nullptr;
    }
    table->stats.pool_unassigned_bytes +=
        core_bytes + lease_bytes + continuation_headroom +
        compaction_credit;
    for (uint32_t index = 0u; index < maximum_flows; ++index) {
        table->core_slots[index].next_free =
            index + 1u < maximum_flows ? index + 1u : kNoIndex;
    }
    table->free_head = 0u;
    try {
        (void)flowkeep::EvidenceAttach(
            reinterpret_cast<fk_compact_flow_table*>(table),maximum_flows);
    } catch(const std::exception &e) {
        set_error(error,error_capacity,e.what());
        fk_compact_flow_table_destroy(reinterpret_cast<fk_compact_flow_table*>(table));
        return nullptr;
    }
    return reinterpret_cast<fk_compact_flow_table *>(table);
}

fk_compact_flow_table *fk_compact_flow_table_create_full_capacity(
        uint32_t maximum_flows,
        const fk_component_policy_config *policy,
        char *error,
        size_t error_capacity) {
    return fk_compact_flow_table_create_with_pool_weights(
        maximum_flows, 0u, policy, nullptr, error, error_capacity);
}

bool fk_compact_flow_table_attach_lifecycle_guard(
        fk_compact_flow_table *table,const fk_compact_lifecycle_guard *guard) {
    if(!table || !guard || !guard->persist)return false;
    auto &state=*implementation(table);
    if(state.lifecycle_guard || state.stats.active_flows)return false;
    state.lifecycle_guard=guard;return true;
}
bool fk_compact_flow_table_attach_idle_retirement_guard(
        fk_compact_flow_table *table,const fk_compact_idle_retirement_guard *guard) {
    if(!table || !guard || !guard->defer || !guard->poll ||
        !guard->metadata_bytes || guard->metadata_bytes>(1u<<20))return false;
    auto &state=*implementation(table);
    if(!state.lifecycle_guard || state.idle_retirement_guard || state.stats.active_flows ||
        state.stats.pool_unassigned_bytes<guard->metadata_bytes ||
        state.stats.mandatory_allocation_bytes>UINT64_MAX-guard->metadata_bytes ||
        !fk_state_budget_try_reserve(state.budget,FK_MEMORY_LEDGER,guard->metadata_bytes))return false;
    state.idle_retirement_guard=guard;
    state.stats.mandatory_allocation_bytes+=guard->metadata_bytes;
    state.stats.pool_unassigned_bytes-=guard->metadata_bytes;return true;
}
bool fk_compact_flow_table_poll_idle_retirements(fk_compact_flow_table *table,bool drain_all) {
    if(!table)return false;
    auto &state=*implementation(table);
    if(state.idle_retirement_failed)return false;
    if(!state.idle_retirement_guard || !state.pending_idle_retirements)return true;
    try {
        if(state.idle_retirement_guard->poll(state.idle_retirement_guard->context,table,drain_all) &&
            (!drain_all || !state.pending_idle_retirements))return true;
    }catch(...){}
    state.idle_retirement_failed=true;return false;
}
bool fk_compact_flow_table_prepare_due_optional(fk_compact_flow_table *table,uint64_t target_ns) {
    if(!table)return false;
    auto &state=*implementation(table);
    if(state.idle_retirement_failed)return false;
    const auto *guard=state.idle_retirement_guard;
    if(!guard || !guard->prepare_optional)return true;
    // Most packet timestamps do not cross any optional-state deadline.
    if(!state.optional_deadline_heap_size)return true;
    const uint32_t root=optional_deadline_index_get(state,0u);
    const auto *entry=core_entry_if_allocated(state,root);
    if(!entry || entry->used!=1u || !has_optional_resident(*entry) ||
        optional_heap_position(*entry)!=0u) {
        state.idle_retirement_failed=true;return false;
    }
    if(entry->component.absolute_deadline_ns>target_ns)return true;
    try {
        if(guard->prepare_optional(guard->context,table,target_ns))return true;
    }catch(...){}
    state.idle_retirement_failed=true;return false;
}
uint32_t fk_compact_flow_table_pending_idle_retirements(const fk_compact_flow_table *table) {
    return table?implementation(table)->pending_idle_retirements:0u;
}
bool fk_compact_flow_table_prepare_shutdown(fk_compact_flow_table *table) {
    if(!table)return false;
    auto &state=*implementation(table);
    if(!fk_compact_flow_table_poll_idle_retirements(table,true))return false;
    if(!state.lifecycle_guard)return true;
    for(uint32_t index=0;index<state.maximum_flows;++index) {
        auto *entry=core_entry_if_allocated(state,index);
        if(entry && entry->used && !persist_lifecycle(state,index,FK_COMPACT_PERSIST_SHUTDOWN))return false;
    }
    return true;
}

void fk_compact_flow_table_destroy(fk_compact_flow_table *table) {
    if (table == nullptr)
        return;
    CompactFlowTable *state = implementation(table);
    // Fail closed: void legacy destructor cannot attest a failed persistence
    // operation. Explicit prepare_shutdown lets the owner handle the failure.
    if(!fk_compact_flow_table_prepare_shutdown(table))return;
    for (uint32_t index = 0u; index < state->maximum_flows; ++index) {
        CoreEntry *entry = core_entry_if_allocated(*state, index);
        if (entry != nullptr && entry->used != 0u) {
            free_evidence(*state, index);
            fk_component_flow_release_all(
                state->budget, &entry->component);
            compact_key_release(*state, entry->key);
        }
    }
    destroy_optional_pools(*state);
    release_mandatory(*state);
    fk_state_budget_destroy(state->budget);
    flowkeep::EvidenceDetach(flowkeep::EvidenceFor(table));
    delete state;
}

static bool evict_one_scored_flow(
        CompactFlowTable &state,
        uint64_t timestamp_ns,
        bool allow_unscored_fallback);

static bool lookup_or_admit_impl(
        fk_compact_flow_table *table,
        const fk_flow_key *key,
        uint8_t first_direction,
        uint64_t timestamp_ns,
        fk_compact_flow_handle *handle,
        bool *created,
        bool allow_unscored_fallback) {
    if (table == nullptr || key == nullptr || handle == nullptr ||
        created == nullptr || first_direction > 1u)
        return false;
    CompactFlowTable &state = *implementation(table);
    if(state.idle_retirement_failed)return false;
    state.stats.lookups++;
    const uint64_t hash = fk_flow_key_hash(key);
    const uint16_t tag = fingerprint(hash);
    const uint32_t mask = state.hash_capacity - 1u;
    const uint32_t start = static_cast<uint32_t>(hash) & mask;
    uint32_t available = kNoIndex;
    for (uint32_t probe = 0u; probe < state.hash_capacity; ++probe) {
        const uint32_t slot_index = (start + probe) & mask;
        HashSlot &slot = state.slots[slot_index];
        if (slot.state == kSlotOccupied) {
            CoreEntry &entry = state.cores[slot.core_index];
            if (slot.fingerprint == tag &&
                compact_key_equal(entry.key, *key)) {
                if(entry.used==2u) {
                    const fk_compact_flow_handle retiring{slot.core_index,entry.generation};
                    if(!fk_compact_flow_table_release(table,retiring))return false;
                    return lookup_or_admit_impl(table,key,first_direction,timestamp_ns,
                        handle,created,allow_unscored_fallback);
                }
                state.stats.lookup_hits++;
                *handle = {slot.core_index, entry.generation};
                *created = false;
                return true;
            }
            continue;
        }
        if (available == kNoIndex)
            available = slot_index;
        if (slot.state == kSlotEmpty)
            break;
    }
    // Pending idle epochs are already semantically expired, even when they
    // never reached a scoring checkpoint. Drain them before the scored-only
    // capacity policy considers evicting an unrelated live generation.
    if(state.stats.free_flow_slots==0u && state.pending_idle_retirements) {
        if(!fk_compact_flow_table_poll_idle_retirements(table,true))return false;
        return lookup_or_admit_impl(table,key,first_direction,timestamp_ns,
            handle,created,allow_unscored_fallback);
    }
    if (available == kNoIndex || state.free_head == kNoIndex ||
        state.stats.free_flow_slots == 0u) {
        if (state.stats.free_flow_slots == 0u) {
            /* Table saturated: evict one already-scored flow so the new flow
             * is admitted instead of silently rejected. */
            if (!evict_one_scored_flow(
                    state,
                    timestamp_ns,
                    allow_unscored_fallback)) {
                state.stats.admission_rejects++;
                return false;
            }
            if (state.free_head == kNoIndex ||
                state.stats.free_flow_slots == 0u) {
                state.stats.allocator_integrity_failures++;
                state.stats.admission_rejects++;
                return false;
            }
            if (available == kNoIndex) {
                for (uint32_t probe = 0u;
                     probe < state.hash_capacity; ++probe) {
                    const uint32_t slot_index = (start + probe) & mask;
                    if (state.slots[slot_index].state != kSlotOccupied) {
                        available = slot_index;
                        break;
                    }
                }
            }
        }
    }
    if (available == kNoIndex || state.free_head == kNoIndex ||
        state.stats.free_flow_slots == 0u) {
        if ((state.free_head == kNoIndex) !=
                (state.stats.free_flow_slots == 0u))
            state.stats.allocator_integrity_failures++;
        state.stats.admission_rejects++;
        return false;
    }
    const uint32_t core_index = state.free_head;
    if (core_index >= state.maximum_flows) {
        state.stats.allocator_integrity_failures++;
        state.stats.admission_rejects++;
        return false;
    }
    CoreSlotMetadata &slot_metadata = state.core_slots[core_index];
    if (slot_metadata.generation ==
            std::numeric_limits<uint32_t>::max() ||
        !ensure_core_page(state, core_index)) {
        state.stats.allocator_integrity_failures++;
        state.stats.admission_rejects++;
        return false;
    }
    CoreEntry &entry = state.cores[core_index];
    if (entry.used != 0u) {
        state.stats.allocator_integrity_failures++;
        state.stats.admission_rejects++;
        return false;
    }
    state.free_head = slot_metadata.next_free;
    state.stats.free_flow_slots--;
    CompactFlowKey compact_key{};
    if (!compact_key_assign(state, compact_key, *key)) {
        slot_metadata.next_free = state.free_head;
        state.free_head = core_index;
        state.stats.free_flow_slots++;
        state.stats.admission_rejects++;
        (void)release_empty_core_page(state, core_index);
        return false;
    }
    const uint32_t generation = slot_metadata.generation + 1u;
    slot_metadata.generation = generation;
    entry = {};
    initialize_value_heap_positions(entry);
    entry.key = compact_key;
    entry.first_timestamp_ns = timestamp_ns;
    entry.last_timestamp_ns = timestamp_ns;
    entry.hash_slot = available;
    entry.generation = generation;
    entry.next_free = kNoIndex;
    entry.first_direction = first_direction;
    entry.used = 1u;
    state.cores.pages[core_index / kCorePageEntries].active_entries++;
    /* A completed empty-table scan may have armed an unbounded idle-scan
     * gate.  Admission is the only operation that can introduce an earlier
     * idle deadline, so force the next packet to rebuild the lower bound. */
    state.expiration_scan_not_before_ns = 0u;
    fk_component_flow_init(
        &entry.component, timestamp_ns, &state.policy);
    HashSlot &slot = state.slots[available];
    slot.core_index = core_index;
    slot.fingerprint = tag;
    slot.state = kSlotOccupied;
    state.stats.flows_created++;
    state.stats.active_flows++;
    if (state.stats.active_flows > state.stats.peak_active_flows)
        state.stats.peak_active_flows = state.stats.active_flows;
    *handle = {core_index, generation};
    *created = true;
    return true;
}

bool fk_compact_flow_table_lookup_or_admit(
        fk_compact_flow_table *table,
        const fk_flow_key *key,
        uint8_t first_direction,
        uint64_t timestamp_ns,
        fk_compact_flow_handle *handle,
        bool *created) {
    return lookup_or_admit_impl(
        table, key, first_direction, timestamp_ns,
        handle, created, true);
}

bool fk_compact_flow_table_lookup_or_admit_scored_only(
        fk_compact_flow_table *table,
        const fk_flow_key *key,
        uint8_t first_direction,
        uint64_t timestamp_ns,
        fk_compact_flow_handle *handle,
        bool *created) {
    return lookup_or_admit_impl(
        table, key, first_direction, timestamp_ns,
        handle, created, false);
}

/* Admission-time supersession: when the fixed flow table is saturated, prefer
 * evicting a flow whose first model decision has already started so a
 * never-scored flow can be admitted.  Reuses the normal release path (value
 * heaps detached, evidence released, hash slot tombstoned).  A bounded scan
 * keeps the line-rate admission cost low; the scan start is derived from the
 * packet timestamp to avoid repeatedly probing the same hot slots. */
static bool evict_one_scored_flow(
        CompactFlowTable &state,
        uint64_t timestamp_ns,
        bool allow_unscored_fallback) {
    const uint32_t mask = state.hash_capacity - 1u;
    const uint32_t start = static_cast<uint32_t>(timestamp_ns) & mask;
    uint32_t best = kNoIndex;
    uint64_t best_last = UINT64_MAX;
    /* Fallback: if no already-scored victim exists (saturation burst before
     * any flow reaches its first checkpoint), recycle the least-recently
     * active flow so the arriving flow is admitted instead of rejected. */
    uint32_t fallback = kNoIndex;
    uint64_t fallback_last = UINT64_MAX;
    const uint32_t limit = state.hash_capacity < 512u
        ? state.hash_capacity : 512u;
    for (uint32_t probe = 0u; probe < limit; ++probe) {
        const uint32_t slot_index = (start + probe) & mask;
        const HashSlot &slot = state.slots[slot_index];
        if (slot.state != kSlotOccupied)
            continue;
        const CoreEntry &entry = state.cores[slot.core_index];
        if (entry.used == 0u)
            continue;
        if (entry.component.decision_started != 0u) {
            if (entry.last_timestamp_ns < best_last) {
                best_last = entry.last_timestamp_ns;
                best = slot.core_index;
            }
            if (probe >= 64u && best != kNoIndex)
                break;
        } else if (entry.last_timestamp_ns < fallback_last) {
            fallback_last = entry.last_timestamp_ns;
            fallback = slot.core_index;
        }
    }
    if (best == kNoIndex &&
        (!allow_unscored_fallback || fallback == kNoIndex))
        return false;
    const uint32_t victim = best != kNoIndex ? best : fallback;
    const CoreEntry &victim_entry = state.cores[victim];
    const uint32_t generation = victim_entry.generation;
    fk_flow_key watched_victim{};
    if (compact_key_materialize(victim_entry.key, watched_victim) &&
        fk_m1_watched(watched_victim))
        fk_m1_watch("capacity_victim", UINT64_MAX, timestamp_ns,
            victim_entry.last_timestamp_ns, victim_entry.packets,
            victim, generation, victim_entry.used);
    // An already expired epoch must never create a capacity continuation.
    if(victim_entry.used==2u)return fk_compact_flow_table_release(
        reinterpret_cast<fk_compact_flow_table*>(&state),{victim,generation});
    const bool retain_continuation =
        victim_entry.logical_connection_id == 0u &&
        victim_entry.terminal_observed == 0u;
    const CapacityContinuationEntry continuation =
        retain_continuation
        ? make_capacity_continuation(victim, victim_entry)
        : CapacityContinuationEntry{};
    ContinuationTarget continuation_target{nullptr, kNoIndex};
    if (retain_continuation) {
        continuation_target = continuation_store_target(
            state,
            continuation,
            timestamp_ns);
        if (continuation_target.entry == nullptr) {
            state.stats.continuation_store_rejects++;
            return false;
        }
    }
    const fk_compact_flow_handle victim_handle{victim, generation};
    if (resident_component_mask(victim_entry) != FK_COMPONENT_NONE &&
        !release_all_optional_for_reason(
            state,
            victim,
            FK_COMPACT_TRANSITION_LRU_EVICTED,
            victim_handle,
            static_cast<uint32_t>(std::min<uint64_t>(
                victim_entry.packets,
                std::numeric_limits<uint32_t>::max())),
            timestamp_ns)) {
        return false;
    }
    if (!fk_compact_flow_table_release(
        reinterpret_cast<fk_compact_flow_table *>(&state),
        victim_handle)) {
        return false;
    }
    if (retain_continuation)
        continuation_store_at(
            state,
            continuation_target.index,
            *continuation_target.entry,
            continuation);
    return true;
}

bool fk_compact_flow_table_admit_distinct(
        fk_compact_flow_table *table,
        const fk_flow_key *presentation_key,
        uint8_t first_direction,
        uint64_t timestamp_ns,
        fk_compact_flow_handle *handle) {
    if (table == nullptr || presentation_key == nullptr ||
        handle == nullptr || first_direction > 1u)
        return false;
    CompactFlowTable &state = *implementation(table);
    if(state.idle_retirement_failed)return false;
    state.stats.distinct_admission_attempts++;
    // No Core is borrowed at this entry point. Expired unscored generations
    // must finish durable retirement before the scored-only capacity policy.
    if(state.stats.free_flow_slots==0u && state.pending_idle_retirements &&
        !fk_compact_flow_table_poll_idle_retirements(table,true))return false;
    if (state.free_head == kNoIndex ||
        state.stats.free_flow_slots == 0u) {
        if (state.stats.free_flow_slots != 0u ||
            !evict_one_scored_flow(state, timestamp_ns, false)) {
            if ((state.free_head == kNoIndex) !=
                    (state.stats.free_flow_slots == 0u))
                state.stats.allocator_integrity_failures++;
            state.stats.admission_rejects++;
            state.stats.distinct_admission_rejects++;
            return false;
        }
        if (state.free_head == kNoIndex ||
            state.stats.free_flow_slots == 0u) {
            state.stats.allocator_integrity_failures++;
            state.stats.admission_rejects++;
            state.stats.distinct_admission_rejects++;
            return false;
        }
    }
    const uint32_t core_index = state.free_head;
    if (core_index >= state.maximum_flows) {
        state.stats.allocator_integrity_failures++;
        state.stats.admission_rejects++;
        state.stats.distinct_admission_rejects++;
        return false;
    }
    CoreSlotMetadata &slot_metadata = state.core_slots[core_index];
    if (slot_metadata.generation ==
            std::numeric_limits<uint32_t>::max() ||
        !ensure_core_page(state, core_index)) {
        state.stats.allocator_integrity_failures++;
        state.stats.admission_rejects++;
        state.stats.distinct_admission_rejects++;
        return false;
    }
    CoreEntry &entry = state.cores[core_index];
    if (entry.used != 0u) {
        state.stats.allocator_integrity_failures++;
        state.stats.admission_rejects++;
        state.stats.distinct_admission_rejects++;
        return false;
    }
    state.free_head = slot_metadata.next_free;
    state.stats.free_flow_slots--;
    CompactFlowKey compact_key{};
    if (!compact_key_assign(state, compact_key, *presentation_key)) {
        slot_metadata.next_free = state.free_head;
        state.free_head = core_index;
        state.stats.free_flow_slots++;
        state.stats.admission_rejects++;
        state.stats.distinct_admission_rejects++;
        (void)release_empty_core_page(state, core_index);
        return false;
    }
    const uint32_t generation = slot_metadata.generation + 1u;
    slot_metadata.generation = generation;
    entry = {};
    initialize_value_heap_positions(entry);
    entry.key = compact_key;
    entry.first_timestamp_ns = timestamp_ns;
    entry.last_timestamp_ns = timestamp_ns;
    entry.hash_slot = kNoIndex;
    entry.generation = generation;
    entry.next_free = kNoIndex;
    entry.first_direction = first_direction;
    entry.used = 1u;
    state.cores.pages[core_index / kCorePageEntries].active_entries++;
    state.expiration_scan_not_before_ns = 0u;
    fk_component_flow_init(
        &entry.component, timestamp_ns, &state.policy);
    state.stats.flows_created++;
    state.stats.distinct_flows_created++;
    state.stats.active_flows++;
    state.stats.active_distinct_flows++;
    if (state.stats.active_flows > state.stats.peak_active_flows)
        state.stats.peak_active_flows = state.stats.active_flows;
    if (state.stats.active_distinct_flows >
            state.stats.peak_active_distinct_flows) {
        state.stats.peak_active_distinct_flows =
            state.stats.active_distinct_flows;
    }
    *handle = {core_index, generation};
    return true;
}

bool fk_compact_flow_table_bind_logical_connection_id(
        fk_compact_flow_table *table,
        fk_compact_flow_handle handle,
        uint64_t logical_connection_id) {
    if (table == nullptr)
        return false;
    CompactFlowTable &state = *implementation(table);
    if (!valid_handle(state, handle)) {
        state.stats.stale_handle_rejects++;
        return false;
    }
    CoreEntry &entry = state.cores[handle.index];
    if (entry.logical_connection_id == logical_connection_id)
        return true;
    if (entry.logical_connection_id != 0u ||
        logical_connection_id == 0u || entry.packets != 0u ||
        entry.hash_slot != kNoIndex || entry.key.protocol != 17u)
        return false;
    entry.logical_connection_id = logical_connection_id;
    return true;
}

bool fk_compact_flow_table_handle_valid(
        const fk_compact_flow_table *table,
        fk_compact_flow_handle handle) {
    return table != nullptr &&
        valid_handle(*implementation(table), handle);
}

bool fk_compact_flow_table_set_capacity_continuation_gap(
        fk_compact_flow_table *table,
        uint64_t maximum_gap_ns) {
    if (table == nullptr || maximum_gap_ns == 0u)
        return false;
    CompactFlowTable &state = *implementation(table);
    if (state.continuation_maximum_gap_ns != 0u &&
        state.continuation_maximum_gap_ns != maximum_gap_ns)
        return false;
    state.continuation_maximum_gap_ns = maximum_gap_ns;
    return true;
}

bool fk_compact_flow_table_demote_terminal_core(
        fk_compact_flow_table *table,
        fk_compact_flow_handle handle,
        uint64_t timestamp_ns,
        bool *demoted) {
    if (demoted != nullptr)
        *demoted = false;
    if (table == nullptr || demoted == nullptr)
        return false;
    CompactFlowTable &state = *implementation(table);
    if (!valid_handle(state, handle)) {
        state.stats.stale_handle_rejects++;
        return false;
    }
    const CoreEntry &entry = state.cores[handle.index];
    const bool ordinary_indexed_flow =
        entry.logical_connection_id == 0u &&
        entry.hash_slot != kNoIndex;
    const bool final_checkpoint_complete =
        entry.component.decision_started != 0u &&
        entry.component.checkpoint_index == state.policy.checkpoint_count &&
        entry.component.next_checkpoint_packet == 0u;
    const bool optional_state_absent =
        entry.evidence_mask == FK_COMPONENT_NONE &&
        entry.component.mask == FK_COMPONENT_NONE &&
        owned_evidence_bytes(entry.component) == 0u &&
        !has_optional_resident(entry);
    if (!ordinary_indexed_flow || !final_checkpoint_complete ||
        !optional_state_absent || entry.terminal_observed != 0u ||
        state.continuation_maximum_gap_ns == 0u ||
        timestamp_ns < entry.last_timestamp_ns) {
        return true;
    }

    /* A continuation is a physical-memory optimization, not merely a
     * logical live-flow optimization.  Releasing one Core from a page that
     * still contains another live Core cannot return any Core/lease bytes to
     * the controlled arena, while it does allocate a continuation payload
     * and later pays a second admission/restore transaction.  In that case
     * retaining the already compact Core is strictly cheaper in both
     * byte-seconds and work.  Demote only the last live Core in its page, for
     * which release_empty_core_page() can immediately return the full page.
     */
    const CorePage &core_page =
        state.cores.pages[handle.index / kCorePageEntries];
    if (core_page.active_entries != 1u)
        return true;

    const CapacityContinuationEntry continuation =
        make_capacity_continuation(handle.index, entry);
    ContinuationTarget target = continuation_store_target(
        state, continuation, timestamp_ns);
    if (target.entry == nullptr) {
        state.stats.continuation_store_rejects++;
        return true;
    }
    if (!fk_compact_flow_table_release(table, handle)) {
        return false;
    }
    continuation_store_at(
        state, target.index, *target.entry, continuation);
    *demoted = true;
    return true;
}

bool fk_compact_flow_table_retire_reused_tcp_tuple(
        fk_compact_flow_table *table,
        const fk_flow_key *key,
        const fk_compact_flow_handle *bound_handle,
        uint8_t tcp_flags,
        uint32_t tcp_sequence,
        uint64_t timestamp_ns,
        bool *retired) {
    if (retired != nullptr)
        *retired = false;
    if (table == nullptr || key == nullptr || retired == nullptr)
        return false;
    if (key->protocol != 6u ||
        (tcp_flags & FK_TCP_FLAG_SYN) == 0u ||
        (tcp_flags & FK_TCP_FLAG_ACK) != 0u) {
        return true;
    }
    CompactFlowTable &state = *implementation(table);
    uint32_t core_index = kNoIndex;
    if (bound_handle != nullptr) {
        if (!valid_handle(state, *bound_handle))
            return true;
        const CoreEntry &bound = state.cores[bound_handle->index];
        if (!compact_key_equal(bound.key, *key))
            return false;
        core_index = bound_handle->index;
    } else {
        const uint64_t hash = fk_flow_key_hash(key);
        const uint16_t tag = fingerprint(hash);
        const uint32_t mask = state.hash_capacity - 1u;
        const uint32_t start = static_cast<uint32_t>(hash) & mask;
        for (uint32_t probe = 0u; probe < state.hash_capacity; ++probe) {
            const HashSlot &slot = state.slots[(start + probe) & mask];
            if (slot.state == kSlotEmpty)
                break;
            if (slot.state != kSlotOccupied || slot.fingerprint != tag)
                continue;
            const CoreEntry &candidate = state.cores[slot.core_index];
            if (candidate.used != 0u &&
                compact_key_equal(candidate.key, *key)) {
                core_index = slot.core_index;
                break;
            }
        }
    }
    if (core_index == kNoIndex)
        return true;
    CoreEntry &entry = state.cores[core_index];
    if (entry.packets == 0u)
        return true;
    const bool syn_seen =
        (entry.lifecycle_reserved & kTcpLifecycleSynSeen) != 0u;
    const bool established =
        (entry.lifecycle_reserved & kTcpLifecycleEstablished) != 0u;
    const bool exact_syn_retransmission =
        syn_seen && !established &&
        entry.next_free == tcp_sequence;
    /* Before a handshake is established, repeated bare SYN attempts belong
     * to one causal connection-attempt event even if the client rotates its
     * ISN. This keeps the pre-response history associated and prevents a
     * delayed SYN|ACK for an earlier attempt from being counted as packet 4
     * of a fabricated new generation. After terminal evidence, only an exact
     * SYN retransmission is allowed to remain in the old generation. */
    const bool unestablished_attempt_continuation =
        syn_seen && !established && entry.terminal_observed == 0u;
    if (exact_syn_retransmission || unestablished_attempt_continuation)
        return true;

    const fk_compact_flow_handle victim{core_index, entry.generation};
    if (resident_component_mask(entry) != FK_COMPONENT_NONE &&
        !release_all_optional_for_reason(
            state,
            core_index,
            FK_COMPACT_TRANSITION_POLICY_RELEASED,
            victim,
            static_cast<uint32_t>(std::min<uint64_t>(
                entry.packets,
                std::numeric_limits<uint32_t>::max())),
            timestamp_ns)) {
        return false;
    }
    if (!fk_compact_flow_table_release(table, victim))
        return false;

    const uint32_t probe_limit = continuation_probe_limit(state);
    const ContinuationProbeSequence sequence =
        continuation_probe_sequence(state, *key);
    for (uint32_t probe = 0u;
         probe < probe_limit; ++probe) {
        CapacityContinuationEntry *candidate = continuation_entry(
            state, continuation_probe_index(sequence, probe), false);
        if (candidate != nullptr && candidate->valid != 0u &&
            fk_flow_key_equal(&candidate->key, key)) {
            continuation_remove(
                state,
                continuation_probe_index(sequence, probe),
                *candidate);
            state.stats.continuation_new_epoch_invalidations++;
            break;
        }
    }
    state.stats.tcp_new_epoch_retirements++;
    *retired = true;
    return true;
}

bool fk_compact_flow_table_resume_capacity_continuation(
        fk_compact_flow_table *table,
        fk_compact_flow_handle handle,
        uint8_t tcp_flags,
        uint32_t tcp_sequence,
        uint8_t canonical_direction,
        uint64_t timestamp_ns,
        uint64_t maximum_gap_ns,
        bool *resumed,
        fk_compact_capacity_continuation_predecessor *predecessor) {
    if (resumed != nullptr)
        *resumed = false;
    if (predecessor != nullptr)
        *predecessor = {};
    if (table == nullptr || resumed == nullptr || predecessor == nullptr ||
        maximum_gap_ns == 0u ||
        canonical_direction > 1u)
        return false;
    CompactFlowTable &state = *implementation(table);
    if (state.continuation_maximum_gap_ns == 0u ||
        state.continuation_maximum_gap_ns != maximum_gap_ns)
        return false;
    if (!valid_handle(state, handle)) {
        state.stats.stale_handle_rejects++;
        return false;
    }
    CoreEntry &entry = state.cores[handle.index];
    /* This API is an admission transaction step, never a late mutation of a
     * generation that already owns packets or optional evidence. */
    if (entry.packets != 0u || entry.evidence_mask != FK_COMPONENT_NONE ||
        entry.component.decision_started != 0u ||
        entry.logical_connection_id != 0u) {
        return false;
    }
    state.stats.continuation_lookups++;
    CapacityContinuationEntry *match = nullptr;
    uint32_t match_index = kNoIndex;
    const uint32_t probe_limit = continuation_probe_limit(state);
    fk_flow_key materialized_key{};
    if (!compact_key_materialize(entry.key, materialized_key)) {
        state.stats.allocator_integrity_failures++;
        return false;
    }
    const ContinuationProbeSequence sequence =
        continuation_probe_sequence(state, materialized_key);
    for (uint32_t probe = 0u;
         probe < probe_limit; ++probe) {
        CapacityContinuationEntry *candidate = continuation_entry(
            state, continuation_probe_index(sequence, probe), false);
        if (candidate != nullptr && candidate->valid != 0u &&
            fk_flow_key_equal(&candidate->key, &materialized_key)) {
            match = candidate;
            match_index = continuation_probe_index(sequence, probe);
            const uint64_t probe_count =
                static_cast<uint64_t>(probe) + 1u;
            state.stats.continuation_lookup_probe_steps += probe_count;
            state.stats.continuation_peak_probe_count = std::max(
                state.stats.continuation_peak_probe_count, probe_count);
            break;
        }
    }
    if (match == nullptr) {
        state.stats.continuation_lookup_probe_steps +=
            probe_limit;
        state.stats.continuation_peak_probe_count = std::max(
            state.stats.continuation_peak_probe_count,
            static_cast<uint64_t>(probe_limit));
        state.stats.continuation_misses++;
        return true;
    }
    const bool time_regression = timestamp_ns < match->last_timestamp_ns;
    const bool gap_expired = !time_regression &&
        timestamp_ns - match->last_timestamp_ns > maximum_gap_ns;
    const bool bare_syn = entry.key.protocol == 6u &&
        (tcp_flags & FK_TCP_FLAG_SYN) != 0u &&
        (tcp_flags & FK_TCP_FLAG_ACK) == 0u;
    const bool syn_retransmission = bare_syn &&
        (match->tcp_lifecycle & kTcpLifecycleSynSeen) != 0u &&
        (match->tcp_lifecycle & kTcpLifecycleEstablished) == 0u &&
        match->initial_syn_sequence == tcp_sequence;
    /* A bare SYN resumes only an exact pre-establishment retransmission.
     * Every other bare SYN starts a fresh transport epoch, independently of
     * whether the discarded prefix had reached a model checkpoint. */
    const bool new_epoch = bare_syn && !syn_retransmission;
    if (time_regression || gap_expired || new_epoch) {
        /* Counters are mutually exclusive removal reasons so the directory
         * conservation receipt never counts one erased slot twice.  Gap or
         * clock invalidity takes precedence over transport-epoch evidence. */
        if (gap_expired || time_regression) {
            state.stats.continuation_expirations++;
        } else if (new_epoch) {
            state.stats.continuation_new_epoch_invalidations++;
        }
        continuation_remove(state, match_index, *match);
        state.stats.continuation_misses++;
        return true;
    }

    predecessor->flow_index = match->predecessor_flow_index;
    predecessor->flow_generation = match->predecessor_flow_generation;
    predecessor->last_checkpoint_packet =
        match->component.checkpoint_index != 0u &&
                match->component.checkpoint_index <=
                    state.policy.checkpoint_count
        ? state.policy.checkpoints[
              match->component.checkpoint_index - 1u]
        : 0u;
    if (predecessor->flow_generation == 0u ||
        (predecessor->flow_index == handle.index &&
         predecessor->flow_generation == handle.generation)) {
        state.stats.allocator_integrity_failures++;
        *predecessor = {};
        return false;
    }

    entry.first_timestamp_ns = match->first_timestamp_ns;
    entry.last_timestamp_ns = match->last_timestamp_ns;
    entry.packets = match->packets;
    entry.bytes = match->bytes;
    entry.component = {};
    entry.component.decision_started =
        match->component.decision_started;
    entry.component.checkpoint_index =
        match->component.checkpoint_index;
    entry.component.observation_complete =
        match->component.observation_complete;
    std::copy_n(match->component.missing_reason, 3u,
                entry.component.missing_reason);
    entry.component.next_checkpoint_packet =
        match->component.next_checkpoint_packet;
    std::copy_n(match->component.component_start_packet, 3u,
                entry.component.component_start_packet);
    entry.component.released_mask =
        match->component.released_mask;
    entry.component.absolute_deadline_ns =
        match->first_timestamp_ns >
                std::numeric_limits<uint64_t>::max() -
                    state.policy.maximum_lifetime_ns
        ? std::numeric_limits<uint64_t>::max()
        : match->first_timestamp_ns +
              state.policy.maximum_lifetime_ns;
    entry.bootstrap = match->bootstrap;
    entry.direction_packets[0] = match->direction_packets[0];
    entry.direction_packets[1] = match->direction_packets[1];
    entry.maximum_wire_size = match->maximum_wire_size;
    entry.next_free = match->initial_syn_sequence;
    entry.first_direction = match->first_direction;
    entry.fixed_ttl_deadline = match->fixed_ttl_deadline;
    entry.lifecycle_reserved = match->tcp_lifecycle;
    continuation_remove(state, match_index, *match);
    state.stats.continuation_hits++;
    state.stats.continuation_restores++;
    *resumed = true;
    return true;
}

bool fk_compact_flow_table_snapshot(
        const fk_compact_flow_table *table,
        fk_compact_flow_handle handle,
        fk_compact_flow_snapshot *snapshot) {
    if (snapshot != nullptr)
        *snapshot = {};
    if (table == nullptr || snapshot == nullptr)
        return false;
    const CompactFlowTable &state = *implementation(table);
    if (!allocated_handle(state, handle))
        return false;
    fill_snapshot(state.cores[handle.index], snapshot);
    return true;
}

bool fk_compact_flow_table_update(
        fk_compact_flow_table *table,
        fk_compact_flow_handle handle,
        uint8_t direction,
        uint32_t wire_size,
        uint64_t timestamp_ns,
        fk_compact_flow_snapshot *snapshot) {
    if (table == nullptr || direction > 1u)
        return false;
    CompactFlowTable &state = *implementation(table);
    if (!valid_handle(state, handle)) {
        state.stats.stale_handle_rejects++;
        return false;
    }
    CoreEntry &entry = state.cores[handle.index];
    if (!release_due_before_observation(
            state,
            handle.index,
            timestamp_ns,
            static_cast<uint32_t>(
                std::min<uint64_t>(
                    entry.packets + 1u,
                    std::numeric_limits<uint32_t>::max()))))
        return false;
    entry.packets++;
    note_retention_access(state, entry);
    entry.bytes += wire_size;
    if (entry.direction_packets[direction] !=
        std::numeric_limits<uint16_t>::max())
        entry.direction_packets[direction]++;
    if (wire_size > entry.maximum_wire_size)
        entry.maximum_wire_size = saturating_u16(wire_size);
    if (timestamp_ns >= entry.last_timestamp_ns)
        entry.last_timestamp_ns = timestamp_ns;
    fill_snapshot(entry, snapshot);
    return true;
}

bool fk_compact_flow_table_observe_packet_with_flags(
        fk_compact_flow_table *table,
        fk_compact_flow_handle handle,
        uint8_t canonical_direction,
        const fk_packet_view *view,
        uint64_t timestamp_ns,
        uint32_t observation_flags,
        fk_tls_hello_callback callback,
        void *callback_user,
        fk_compact_flow_snapshot *snapshot) {
    if (table == nullptr || view == nullptr ||
        canonical_direction > 1u ||
        (observation_flags & ~static_cast<uint32_t>(
            FK_COMPACT_OBSERVE_PROVISIONAL_TLS |
            FK_COMPACT_OBSERVE_ELIDE_OPTIONAL_AFTER_FINAL_CHECKPOINT)) != 0u)
        return false;
    CompactFlowTable &state = *implementation(table);
    if (!valid_handle(state, handle)) {
        state.stats.stale_handle_rejects++;
        return false;
    }
    CoreEntry &entry = state.cores[handle.index];
    const bool elide_optional_after_final_checkpoint =
        (observation_flags &
            FK_COMPACT_OBSERVE_ELIDE_OPTIONAL_AFTER_FINAL_CHECKPOINT) != 0u;
    if (elide_optional_after_final_checkpoint &&
        entry.component.next_checkpoint_packet != 0u) {
        return false;
    }
    if (!release_due_before_observation(
            state,
            handle.index,
            timestamp_ns,
            static_cast<uint32_t>(
                std::min<uint64_t>(
                    entry.packets + 1u,
                    std::numeric_limits<uint32_t>::max()))))
        return false;
    if (entry.evidence_mask != entry.component.mask) {
        fk_component_flow_mark_loss(
            &entry.component,
            entry.evidence_mask ^ entry.component.mask);
        return false;
    }
    if (!elide_optional_after_final_checkpoint &&
        (observation_flags & FK_COMPACT_OBSERVE_PROVISIONAL_TLS) != 0u)
        ensure_provisional_tls(state, handle.index, *view, timestamp_ns);
    const uint8_t direction =
        canonical_direction == entry.first_direction ? 0u : 1u;
    const uint64_t previous_timestamp_ns = entry.last_timestamp_ns;
    const uint32_t delta_us =
        saturating_delta_us(previous_timestamp_ns, timestamp_ns);
    entry.packets++;
    note_retention_access(state, entry);
    entry.bytes += view->wire_size;
    if (view->l4_protocol == 6u) {
        const bool syn = (view->tcp_flags & FK_TCP_FLAG_SYN) != 0u;
        const bool ack = (view->tcp_flags & FK_TCP_FLAG_ACK) != 0u;
        const bool rst = (view->tcp_flags & FK_TCP_FLAG_RST) != 0u;
        if (syn && !ack &&
            (entry.lifecycle_reserved & kTcpLifecycleSynSeen) == 0u) {
            entry.next_free = view->tcp_sequence;
            entry.lifecycle_reserved |= kTcpLifecycleSynSeen;
        }
        /* A rejected SYN commonly receives RST|ACK before the client retries
         * the exact SYN sequence.  RST|ACK is terminal evidence, not proof
         * that the transport epoch was established; marking it established
         * would split that retry into a fabricated new generation. */
        if (!rst && ((ack && !syn) || (syn && ack)))
            entry.lifecycle_reserved |= kTcpLifecycleEstablished;
        if ((view->tcp_flags & FK_TCP_FLAG_FIN) != 0u) {
            entry.lifecycle_reserved |= direction == 0u
                ? kTcpLifecycleFinDirection0
                : kTcpLifecycleFinDirection1;
        }
        if (rst) {
            entry.lifecycle_reserved |= kTcpLifecycleRstSeen;
            entry.terminal_observed = 1u;
        }
        const uint8_t both_fin = static_cast<uint8_t>(
            kTcpLifecycleFinDirection0 | kTcpLifecycleFinDirection1);
        if ((entry.lifecycle_reserved & both_fin) == both_fin)
            entry.terminal_observed = 1u;
    }
    if (entry.direction_packets[direction] !=
        std::numeric_limits<uint16_t>::max())
        entry.direction_packets[direction]++;
    if (view->wire_size > entry.maximum_wire_size)
        entry.maximum_wire_size = saturating_u16(view->wire_size);
    if (timestamp_ns >= entry.last_timestamp_ns)
        entry.last_timestamp_ns = timestamp_ns;
    if (entry.bootstrap.count < FK_COMPACT_BOOTSTRAP_PACKETS) {
        const uint8_t index = entry.bootstrap.count;
        entry.bootstrap.wire_size[index] =
            saturating_u16(view->wire_size);
        entry.bootstrap.payload_size[index] =
            saturating_u16(view->payload_size);
        entry.bootstrap.tcp_flags[index] = view->tcp_flags;
        if (direction != 0u)
            entry.bootstrap.direction_bits |=
                static_cast<uint8_t>(1u << index);
        if (index != 0u)
            entry.bootstrap.delta_time_us[index - 1u] =
                saturating_u16(delta_us);
        entry.bootstrap.count++;
    }

    /* No configured detector or value decision can observe optional state
     * after next_checkpoint_packet becomes zero.  Keep CORE counters,
     * direction, liveness, and TCP epoch/terminal state exact above, while
     * avoiding writes to cold optional slabs on an arbitrarily long tail. */
    if (elide_optional_after_final_checkpoint) {
        fill_snapshot(entry, snapshot);
        return true;
    }

    auto *stat = static_cast<fk_compact_stat_state *>(
        evidence_component(state, entry, FK_COMPONENT_STAT));
    if (stat != nullptr) {
        stat->direction_packets[direction]++;
        stat->direction_bytes[direction] += view->wire_size;
        stat->payload_bytes[direction] += view->payload_size;
        const uint64_t delta_ns =
            timestamp_ns >= previous_timestamp_ns
            ? timestamp_ns - previous_timestamp_ns : 0u;
        stat->interarrival_sum_ns[direction] += delta_ns;
        const uint64_t squared =
            delta_ns != 0u &&
                delta_ns > std::numeric_limits<uint64_t>::max() / delta_ns
            ? std::numeric_limits<uint64_t>::max()
            : delta_ns * delta_ns;
        if (std::numeric_limits<uint64_t>::max() -
                stat->interarrival_squared_sum_ns[direction] < squared) {
            stat->interarrival_squared_sum_ns[direction] =
                std::numeric_limits<uint64_t>::max();
        } else {
            stat->interarrival_squared_sum_ns[direction] += squared;
        }
        if (stat->direction_packets[0] + stat->direction_packets[1] == 1u ||
            view->wire_size < stat->minimum_wire_size)
            stat->minimum_wire_size = view->wire_size;
        if (view->wire_size > stat->maximum_wire_size)
            stat->maximum_wire_size = view->wire_size;
        for (uint8_t bit = 0u; bit < 8u; ++bit) {
            if ((view->tcp_flags & (1u << bit)) != 0u)
                stat->tcp_flag_counts[bit]++;
        }
    }

    auto *seq = static_cast<fk_compact_seq_state *>(
        evidence_component(state, entry, FK_COMPONENT_SEQ));
    if (seq != nullptr) {
        fk_compact_packet_metadata &packet =
            seq->packets[seq->next];
        packet.delta_time_us = delta_us;
        packet.wire_size = saturating_u16(view->wire_size);
        packet.direction = direction;
        seq->next = (seq->next + 1u) % FK_COMPACT_SEQ_PACKETS;
        if (seq->count < FK_COMPACT_SEQ_PACKETS)
            seq->count++;
    }

    auto *ja4 = static_cast<fk_compact_ja4_state *>(
        evidence_component(state, entry, FK_COMPONENT_JA4));
    const bool provisional_ja4 =
        ja4 == nullptr &&
        entry.ja4_is_summary == kJa4ModeProvisional;
    if (provisional_ja4) {
        ja4 = static_cast<fk_compact_ja4_state *>(
            fk_slab_pool_get_index(
                state.ja4_pending_pool, entry.ja4_index));
    }
    /*
     * A compacted JA4 summary slab is only the 112-byte fingerprint
     * artifact; it has no TLS stream and must never be fed again.  Only the
     * full provisional (or resident pending) TLS state can be advanced by
     * subsequent records.  Feeding the summary slab as a full
     * fk_compact_ja4_state writes past its allocation.
     */
    const bool ja4_is_summary =
        entry.ja4_is_summary == kJa4ModeSummary;
    if (ja4 != nullptr && !ja4_is_summary &&
        view->l4_protocol == 6u) {
        FingerprintCapture capture{
            ja4, &entry.component, callback, callback_user};
        const fk_protocol_completeness completeness =
            fk_compact_tls_flow_feed(
                &ja4->tls,
                canonical_direction,
                view->tcp_sequence,
                view->tcp_flags,
                view->payload,
                view->payload_size,
                capture_fingerprint,
                &capture);
        if (completeness == FK_COMPLETENESS_MALFORMED ||
            completeness == FK_COMPLETENESS_CAP_EXCEEDED) {
            fk_component_flow_mark_loss(
                &entry.component, FK_COMPONENT_JA4);
        } else if (
            ja4->tls.direction[canonical_direction].desynchronized != 0u) {
            fk_component_flow_mark_loss(
                &entry.component, FK_COMPONENT_JA4);
        }
        if(auto *evidence=flowkeep::EvidenceFor(table))
            flowkeep::EvidenceObserve(evidence,table,handle,4);
        if (!provisional_ja4 &&
            !compact_ja4_if_terminal(state, handle.index))
            return false;
    }
    if(auto *evidence=flowkeep::EvidenceFor(table))
        flowkeep::EvidenceObserve(evidence,table,handle,
            static_cast<uint8_t>((stat?1:0)|(seq?2:0)));
    fill_snapshot(entry, snapshot);
    return true;
}

bool fk_compact_flow_table_observe_prepared_final_tail_packet(
        fk_compact_flow_table *table,
        fk_compact_flow_handle handle,
        uint8_t canonical_direction,
        const fk_packet_view *view,
        uint64_t timestamp_ns,
        uint8_t *first_canonical_direction) {
    if (first_canonical_direction != nullptr)
        *first_canonical_direction = 0u;
    if (table == nullptr || view == nullptr ||
        canonical_direction > 1u || first_canonical_direction == nullptr)
        return false;
    CompactFlowTable &state = *implementation(table);
    if (!valid_handle(state, handle)) {
        state.stats.stale_handle_rejects++;
        return false;
    }
    CoreEntry &entry = state.cores[handle.index];
    /* The prepared runtime call is the proof that a due optional deadline
     * cannot remain at this timestamp.  Keep the other invariants local so
     * misuse fails closed without partially updating CORE. */
    if (entry.component.next_checkpoint_packet != 0u ||
        entry.evidence_mask != entry.component.mask ||
        (entry.component.released_mask != FK_COMPONENT_FULL &&
         timestamp_ns >= entry.component.absolute_deadline_ns)) {
        return false;
    }

    const uint8_t direction =
        canonical_direction == entry.first_direction ? 0u : 1u;
    const uint64_t previous_timestamp_ns = entry.last_timestamp_ns;
    const uint32_t delta_us =
        saturating_delta_us(previous_timestamp_ns, timestamp_ns);
    entry.packets++;
    note_retention_access(state, entry);
    entry.bytes += view->wire_size;
    if (view->l4_protocol == 6u) {
        const bool syn = (view->tcp_flags & FK_TCP_FLAG_SYN) != 0u;
        const bool ack = (view->tcp_flags & FK_TCP_FLAG_ACK) != 0u;
        const bool rst = (view->tcp_flags & FK_TCP_FLAG_RST) != 0u;
        if (syn && !ack &&
            (entry.lifecycle_reserved & kTcpLifecycleSynSeen) == 0u) {
            entry.next_free = view->tcp_sequence;
            entry.lifecycle_reserved |= kTcpLifecycleSynSeen;
        }
        if (!rst && ((ack && !syn) || (syn && ack)))
            entry.lifecycle_reserved |= kTcpLifecycleEstablished;
        if ((view->tcp_flags & FK_TCP_FLAG_FIN) != 0u) {
            entry.lifecycle_reserved |= direction == 0u
                ? kTcpLifecycleFinDirection0
                : kTcpLifecycleFinDirection1;
        }
        if (rst) {
            entry.lifecycle_reserved |= kTcpLifecycleRstSeen;
            entry.terminal_observed = 1u;
        }
        const uint8_t both_fin = static_cast<uint8_t>(
            kTcpLifecycleFinDirection0 | kTcpLifecycleFinDirection1);
        if ((entry.lifecycle_reserved & both_fin) == both_fin)
            entry.terminal_observed = 1u;
    }
    if (entry.direction_packets[direction] !=
        std::numeric_limits<uint16_t>::max()) {
        entry.direction_packets[direction]++;
    }
    if (view->wire_size > entry.maximum_wire_size)
        entry.maximum_wire_size = saturating_u16(view->wire_size);
    if (timestamp_ns >= entry.last_timestamp_ns)
        entry.last_timestamp_ns = timestamp_ns;
    if (entry.bootstrap.count < FK_COMPACT_BOOTSTRAP_PACKETS) {
        const uint8_t index = entry.bootstrap.count;
        entry.bootstrap.wire_size[index] =
            saturating_u16(view->wire_size);
        entry.bootstrap.payload_size[index] =
            saturating_u16(view->payload_size);
        entry.bootstrap.tcp_flags[index] = view->tcp_flags;
        if (direction != 0u) {
            entry.bootstrap.direction_bits |=
                static_cast<uint8_t>(1u << index);
        }
        if (index != 0u) {
            entry.bootstrap.delta_time_us[index - 1u] =
                saturating_u16(delta_us);
        }
        entry.bootstrap.count++;
    }
    *first_canonical_direction = entry.first_direction;
    return true;
}

bool fk_compact_flow_table_observe_prepared_final_tail_batch(
        fk_compact_flow_table *table,
        fk_compact_flow_handle handle,
        const fk_compact_final_tail_observation *observations,
        uint32_t count,
        uint8_t *first_canonical_direction) {
    if (first_canonical_direction != nullptr)
        *first_canonical_direction = 0u;
    if (table == nullptr || observations == nullptr || count == 0u ||
        count > FK_COMPACT_FINAL_TAIL_BATCH_MAX ||
        first_canonical_direction == nullptr)
        return false;
    CompactFlowTable &state = *implementation(table);
    if (!valid_handle(state, handle)) {
        state.stats.stale_handle_rejects++;
        return false;
    }
    CoreEntry &entry = state.cores[handle.index];
    if (entry.component.next_checkpoint_packet != 0u ||
        entry.evidence_mask != entry.component.mask)
        return false;

    uint64_t previous_timestamp_ns = entry.last_timestamp_ns;
    uint64_t bytes = 0u;
    uint32_t direction_packets[2]{};
    uint32_t maximum_wire_size = entry.maximum_wire_size;
    uint8_t lifecycle = entry.lifecycle_reserved;
    uint8_t terminal_observed = entry.terminal_observed;
    fk_compact_bootstrap_state bootstrap = entry.bootstrap;
    for (uint32_t index = 0u; index < count; ++index) {
        const fk_compact_final_tail_observation &observation =
            observations[index];
        if (observation.canonical_direction > 1u ||
            observation.timestamp_ns < previous_timestamp_ns ||
            (observation.l4_protocol == 6u &&
             (observation.tcp_flags & FK_TCP_FLAG_SYN) != 0u &&
             (observation.tcp_flags & FK_TCP_FLAG_ACK) == 0u) ||
            (entry.component.released_mask != FK_COMPONENT_FULL &&
             observation.timestamp_ns >=
                 entry.component.absolute_deadline_ns)) {
            return false;
        }
        const uint8_t direction = observation.canonical_direction ==
            entry.first_direction ? 0u : 1u;
        bytes += observation.wire_size;
        direction_packets[direction]++;
        maximum_wire_size = std::max<uint32_t>(
            maximum_wire_size, observation.wire_size);
        if (observation.l4_protocol == 6u) {
            const bool syn =
                (observation.tcp_flags & FK_TCP_FLAG_SYN) != 0u;
            const bool ack =
                (observation.tcp_flags & FK_TCP_FLAG_ACK) != 0u;
            const bool rst =
                (observation.tcp_flags & FK_TCP_FLAG_RST) != 0u;
            if (!rst && ((ack && !syn) || (syn && ack)))
                lifecycle |= kTcpLifecycleEstablished;
            if ((observation.tcp_flags & FK_TCP_FLAG_FIN) != 0u) {
                lifecycle |= direction == 0u
                    ? kTcpLifecycleFinDirection0
                    : kTcpLifecycleFinDirection1;
            }
            if (rst) {
                lifecycle |= kTcpLifecycleRstSeen;
                terminal_observed = 1u;
            }
            const uint8_t both_fin = static_cast<uint8_t>(
                kTcpLifecycleFinDirection0 |
                kTcpLifecycleFinDirection1);
            if ((lifecycle & both_fin) == both_fin)
                terminal_observed = 1u;
        }
        if (bootstrap.count < FK_COMPACT_BOOTSTRAP_PACKETS) {
            const uint8_t bootstrap_index = bootstrap.count;
            bootstrap.wire_size[bootstrap_index] =
                saturating_u16(observation.wire_size);
            bootstrap.payload_size[bootstrap_index] =
                saturating_u16(observation.payload_size);
            bootstrap.tcp_flags[bootstrap_index] = observation.tcp_flags;
            if (direction != 0u) {
                bootstrap.direction_bits |=
                    static_cast<uint8_t>(1u << bootstrap_index);
            }
            if (bootstrap_index != 0u) {
                bootstrap.delta_time_us[bootstrap_index - 1u] =
                    saturating_u16(saturating_delta_us(
                        previous_timestamp_ns,
                        observation.timestamp_ns));
            }
            bootstrap.count++;
        }
        previous_timestamp_ns = observation.timestamp_ns;
    }

    entry.packets += count;
    note_retention_access(state, entry);
    entry.bytes += bytes;
    for (uint8_t direction = 0u; direction < 2u; ++direction) {
        const uint32_t total = static_cast<uint32_t>(
            entry.direction_packets[direction]) +
            direction_packets[direction];
        entry.direction_packets[direction] = static_cast<uint16_t>(
            std::min<uint32_t>(
                total, std::numeric_limits<uint16_t>::max()));
    }
    entry.maximum_wire_size = saturating_u16(maximum_wire_size);
    entry.last_timestamp_ns = previous_timestamp_ns;
    entry.lifecycle_reserved = lifecycle;
    entry.terminal_observed = terminal_observed;
    entry.bootstrap = bootstrap;
    *first_canonical_direction = entry.first_direction;
    return true;
}

bool fk_compact_flow_table_apply_prepared_final_tail_delta(
        fk_compact_flow_table *table,
        fk_compact_flow_handle handle,
        const fk_compact_final_tail_delta *delta,
        uint8_t *first_canonical_direction) {
    if (first_canonical_direction != nullptr)
        *first_canonical_direction = 0u;
    if (table == nullptr || delta == nullptr ||
        first_canonical_direction == nullptr || delta->packet_count == 0u ||
        delta->first_timestamp_ns > delta->last_timestamp_ns ||
        delta->canonical_direction_packets[0] > delta->packet_count ||
        delta->canonical_direction_packets[1] > delta->packet_count ||
        static_cast<uint64_t>(delta->canonical_direction_packets[0]) +
                delta->canonical_direction_packets[1] !=
            delta->packet_count ||
        (delta->tcp_fin_canonical_mask & ~UINT8_C(3)) != 0u ||
        delta->reserved[0] != 0u || delta->reserved[1] != 0u ||
        delta->reserved[2] != 0u || delta->reserved[3] != 0u)
        return false;
    CompactFlowTable &state = *implementation(table);
    if (!valid_handle(state, handle)) {
        state.stats.stale_handle_rejects++;
        return false;
    }
    CoreEntry &entry = state.cores[handle.index];
    if (entry.component.next_checkpoint_packet != 0u ||
        entry.evidence_mask != entry.component.mask ||
        entry.bootstrap.count < FK_COMPACT_BOOTSTRAP_PACKETS ||
        delta->l4_protocol != entry.key.protocol ||
        (delta->l4_protocol != 6u && delta->l4_protocol != 17u) ||
        delta->first_timestamp_ns < entry.last_timestamp_ns ||
        (entry.component.released_mask != FK_COMPONENT_FULL &&
         delta->last_timestamp_ns >= entry.component.absolute_deadline_ns) ||
        delta->packet_count > UINT64_MAX - entry.packets ||
        delta->wire_bytes > UINT64_MAX - entry.bytes ||
        (delta->l4_protocol != 6u &&
         (delta->tcp_ack_observed != 0u ||
          delta->tcp_fin_canonical_mask != 0u ||
          delta->tcp_rst_observed != 0u))) {
        return false;
    }
    entry.packets += delta->packet_count;
    note_retention_access(state, entry);
    entry.bytes += delta->wire_bytes;
    for (uint8_t canonical_direction = 0u;
         canonical_direction < 2u; ++canonical_direction) {
        const uint8_t direction = canonical_direction ==
                entry.first_direction
            ? 0u : 1u;
        const uint32_t total = static_cast<uint32_t>(
            entry.direction_packets[direction]) +
            delta->canonical_direction_packets[canonical_direction];
        entry.direction_packets[direction] = static_cast<uint16_t>(
            std::min<uint32_t>(
                total, std::numeric_limits<uint16_t>::max()));
        if ((delta->tcp_fin_canonical_mask &
                static_cast<uint8_t>(1u << canonical_direction)) != 0u) {
            entry.lifecycle_reserved |= direction == 0u
                ? kTcpLifecycleFinDirection0
                : kTcpLifecycleFinDirection1;
        }
    }
    entry.maximum_wire_size = std::max<uint16_t>(
        entry.maximum_wire_size, delta->maximum_wire_size);
    if (delta->tcp_ack_observed != 0u)
        entry.lifecycle_reserved |= kTcpLifecycleEstablished;
    if (delta->tcp_rst_observed != 0u) {
        entry.lifecycle_reserved |= kTcpLifecycleRstSeen;
        entry.terminal_observed = 1u;
    }
    const uint8_t both_fin = static_cast<uint8_t>(
        kTcpLifecycleFinDirection0 | kTcpLifecycleFinDirection1);
    if ((entry.lifecycle_reserved & both_fin) == both_fin)
        entry.terminal_observed = 1u;
    entry.last_timestamp_ns = delta->last_timestamp_ns;
    *first_canonical_direction = entry.first_direction;
    return true;
}

bool fk_compact_flow_table_idle_scan_gated_through(
        const fk_compact_flow_table *table,
        uint64_t timestamp_ns) {
    if (table == nullptr)
        return false;
    const CompactFlowTable &state = *implementation(table);
    return timestamp_ns < state.expiration_scan_not_before_ns;
}

bool fk_compact_flow_table_idle_scan_not_before(
        const fk_compact_flow_table *table,
        uint64_t *timestamp_ns) {
    if (table == nullptr || timestamp_ns == nullptr)
        return false;
    *timestamp_ns = implementation(table)->expiration_scan_not_before_ns;
    return true;
}

bool fk_compact_flow_table_observe_packet(
        fk_compact_flow_table *table,
        fk_compact_flow_handle handle,
        uint8_t canonical_direction,
        const fk_packet_view *view,
        uint64_t timestamp_ns,
        fk_tls_hello_callback callback,
        void *callback_user,
        fk_compact_flow_snapshot *snapshot) {
    return fk_compact_flow_table_observe_packet_with_flags(
        table,
        handle,
        canonical_direction,
        view,
        timestamp_ns,
        FK_COMPACT_OBSERVE_PROVISIONAL_TLS,
        callback,
        callback_user,
        snapshot);
}

fk_component_flow *fk_compact_flow_table_component_flow(
        fk_compact_flow_table *table,
        fk_compact_flow_handle handle) {
    if (table == nullptr)
        return nullptr;
    CompactFlowTable &state = *implementation(table);
    if (!valid_handle(state, handle)) {
        state.stats.stale_handle_rejects++;
        return nullptr;
    }
    return &state.cores[handle.index].component;
}

bool fk_compact_flow_table_resident_component_mask(
        const fk_compact_flow_table *table,
        fk_compact_flow_handle handle,
        uint8_t *resident_mask) {
    if (table == nullptr || resident_mask == nullptr)
        return false;
    const CompactFlowTable &state = *implementation(table);
    if (!valid_handle(state, handle))
        return false;
    *resident_mask = resident_component_mask(state.cores[handle.index]);
    return true;
}

bool fk_compact_flow_table_logical_connection_id(
        const fk_compact_flow_table *table,
        fk_compact_flow_handle handle,
        uint64_t *logical_connection_id) {
    if (table == nullptr || logical_connection_id == nullptr)
        return false;
    const CompactFlowTable &state = *implementation(table);
    if (!valid_handle(state, handle))
        return false;
    *logical_connection_id = state.cores[handle.index].logical_connection_id;
    return true;
}

bool fk_compact_flow_table_refresh_action_values(
        fk_compact_flow_table *table,
        fk_compact_flow_handle handle,
        const float action_values[8]) {
    if (table == nullptr || action_values == nullptr)
        return false;
    CompactFlowTable &state = *implementation(table);
    if (!valid_handle(state, handle)) {
        state.stats.stale_handle_rejects++;
        return false;
    }
    /* Validate before updating so an invalid inference cannot perturb the
     * victim index.  The update itself cannot fail after this finite check. */
    for (uint8_t mask = 0u; mask < 8u; ++mask) {
        if (!std::isfinite(action_values[mask]))
            return false;
    }
    CoreEntry &entry = state.cores[handle.index];
    const bool already_indexed =
        entry.component.initial_action_values_valid != 0u;
    if (!fk_component_flow_update_action_values(
            &entry.component, action_values))
        return false;
    return already_indexed
        ? fix_entry_value_heap_keys(state, handle.index)
        : refresh_entry_value_heaps(state, handle.index);
}

bool fk_compact_flow_table_refresh_transition_values(
        fk_compact_flow_table *table,
        fk_compact_flow_handle handle,
        const float transition_potentials[8]) {
    if (table == nullptr || transition_potentials == nullptr)
        return false;
    CompactFlowTable &state = *implementation(table);
    if (!valid_handle(state, handle)) {
        state.stats.stale_handle_rejects++;
        return false;
    }
    for (uint8_t mask = 0u; mask < 8u; ++mask) {
        if (!std::isfinite(transition_potentials[mask]))
            return false;
    }
    CoreEntry &entry = state.cores[handle.index];
    const bool already_indexed =
        entry.component.initial_action_values_valid != 0u;
    if (!fk_component_flow_update_transition_values(
            &entry.component, transition_potentials))
        return false;
    return already_indexed
        ? fix_entry_value_heap_keys(state, handle.index)
        : refresh_entry_value_heaps(state, handle.index);
}

bool fk_compact_flow_table_bootstrap(
        const fk_compact_flow_table *table,
        fk_compact_flow_handle handle,
        fk_compact_bootstrap_state *bootstrap) {
    if (table == nullptr || bootstrap == nullptr)
        return false;
    const CompactFlowTable &state = *implementation(table);
    if (!valid_handle(state, handle))
        return false;
    *bootstrap = state.cores[handle.index].bootstrap;
    return true;
}

bool fk_compact_flow_table_action_features(
        const fk_compact_flow_table *table,
        fk_compact_flow_handle handle,
        const fk_packet_view *current_packet,
        fk_pressure_mode pressure,
        float features[FK_COMPACT_ACTION_FEATURES]) {
    if (table == nullptr || current_packet == nullptr ||
        features == nullptr || pressure < FK_PRESSURE_NORMAL ||
        pressure > FK_PRESSURE_OVERLOAD)
        return false;
    const CompactFlowTable &state = *implementation(table);
    if (!valid_handle(state, handle))
        return false;
    const CoreEntry &entry = state.cores[handle.index];
    std::memset(features, 0, sizeof(float) * FK_COMPACT_ACTION_FEATURES);
    const double packets =
        entry.packets == 0u ? 1.0 : static_cast<double>(entry.packets);
    const double direction_total =
        static_cast<double>(entry.direction_packets[0]) +
        static_cast<double>(entry.direction_packets[1]);
    const double imbalance = direction_total == 0.0 ? 0.0 :
        std::fabs(
            static_cast<double>(entry.direction_packets[0]) -
            static_cast<double>(entry.direction_packets[1])) /
        direction_total;
    const double age_ms =
        entry.last_timestamp_ns >= entry.first_timestamp_ns
        ? static_cast<double>(
            entry.last_timestamp_ns - entry.first_timestamp_ns) /
            1000000.0
        : 0.0;
    features[0] = static_cast<float>(std::log1p(entry.packets));
    features[1] = static_cast<float>(std::log1p(entry.bytes));
    features[2] = static_cast<float>(
        static_cast<double>(entry.bytes) / packets / 1514.0);
    features[3] =
        static_cast<float>(entry.maximum_wire_size) / 1514.0f;
    features[4] = static_cast<float>(imbalance);
    features[5] = current_packet->l4_protocol == 6u ? 1.0f : 0.0f;
    features[6] = current_packet->l4_protocol == 17u ? 1.0f : 0.0f;
    features[7] = tls_candidate(*current_packet) ? 1.0f : 0.0f;
    features[8] = pressure == FK_PRESSURE_PRESSURE ? 1.0f : 0.0f;
    features[9] = pressure == FK_PRESSURE_OVERLOAD ? 1.0f : 0.0f;
    features[10] = static_cast<float>(std::log1p(age_ms));
    features[11] = current_packet->wire_size == 0u ? 0.0f :
        static_cast<float>(current_packet->payload_size) /
        static_cast<float>(current_packet->wire_size);
    for (uint8_t index = 0u;
         index < FK_COMPACT_BOOTSTRAP_PACKETS; ++index) {
        const float normalized =
            static_cast<float>(entry.bootstrap.wire_size[index]) /
            1514.0f;
        features[12u + index] =
            (entry.bootstrap.direction_bits & (1u << index)) == 0u
            ? normalized : -normalized;
        const uint16_t wire = entry.bootstrap.wire_size[index];
        features[19u + index] = wire == 0u ? 0.0f :
            static_cast<float>(entry.bootstrap.payload_size[index]) /
            static_cast<float>(wire);
    }
    for (uint8_t index = 0u;
         index < FK_COMPACT_BOOTSTRAP_PACKETS - 1u; ++index) {
        features[16u + index] = static_cast<float>(
            std::log1p(
                static_cast<double>(
                    entry.bootstrap.delta_time_us[index]) / 1000.0));
    }
    const double port_scale = std::log(65536.0);
    features[23] = static_cast<float>(
        std::log1p(static_cast<double>(entry.key.low_port)) / port_scale);
    features[24] = static_cast<float>(
        std::log1p(static_cast<double>(entry.key.high_port)) / port_scale);
    features[25] =
        (current_packet->tcp_flags & FK_TCP_FLAG_SYN) != 0u ? 1.0f : 0.0f;
    features[26] =
        (current_packet->tcp_flags & FK_TCP_FLAG_ACK) != 0u ? 1.0f : 0.0f;
    features[27] =
        (current_packet->tcp_flags & FK_TCP_FLAG_FIN) != 0u ? 1.0f : 0.0f;
    features[28] =
        (current_packet->tcp_flags & FK_TCP_FLAG_RST) != 0u ? 1.0f : 0.0f;
    features[29] =
        (current_packet->tcp_flags & FK_TCP_FLAG_PSH) != 0u ? 1.0f : 0.0f;
    return true;
}

void fk_compact_flow_table_component_bytes(fk_component_bytes *bytes) {
    if (bytes == nullptr)
        return;
    bytes->stat_bytes = sizeof(fk_compact_stat_state);
    bytes->seq_bytes = sizeof(fk_compact_seq_state);
    bytes->ja4_bytes = sizeof(fk_compact_ja4_state);
}

bool fk_compact_flow_table_materializable_mask(
        const fk_compact_flow_table *table,
        fk_compact_flow_handle handle,
        uint8_t *mask) {
    if (table == nullptr || mask == nullptr)
        return false;
    const CompactFlowTable &state = *implementation(table);
    if (!valid_handle(state, handle))
        return false;
    const CoreEntry &entry = state.cores[handle.index];
    uint8_t available = entry.evidence_mask;
    fk_slab_pool_stats stat{};
    fk_slab_pool_stats seq{};
    fk_slab_pool_stats ja4{};
    if (!fk_slab_pool_get_stats(state.stat_pool, &stat) ||
        !fk_slab_pool_get_stats(state.seq_pool, &seq) ||
        !fk_slab_pool_get_stats(state.ja4_pending_pool, &ja4))
        return false;
    if (stat.in_use < stat.capacity)
        available |= FK_COMPONENT_STAT;
    if (seq.in_use < seq.capacity)
        available |= FK_COMPONENT_SEQ;
    if (entry.ja4_is_summary == kJa4ModeProvisional ||
        ja4.in_use < ja4.capacity)
        available |= FK_COMPONENT_JA4;
    *mask = available;
    return true;
}

bool fk_compact_flow_table_sync_components(
        fk_compact_flow_table *table,
        fk_compact_flow_handle handle) {
    if (table == nullptr)
        return false;
    CompactFlowTable &state = *implementation(table);
    if (!valid_handle(state, handle))
        return fk_compact_flow_table_sync_components_at(
            table, handle, 0u, 0u);
    const CoreEntry &entry = state.cores[handle.index];
    return fk_compact_flow_table_sync_components_at(
        table,
        handle,
        static_cast<uint32_t>(std::min<uint64_t>(
            entry.packets, std::numeric_limits<uint32_t>::max())),
        entry.last_timestamp_ns);
}

bool fk_compact_flow_table_sync_components_at(
        fk_compact_flow_table *table,
        fk_compact_flow_handle handle,
        uint32_t causing_packet_count,
        uint64_t timestamp_ns) {
    if (table == nullptr)
        return false;
    CompactFlowTable &state = *implementation(table);
    if (!valid_handle(state, handle)) {
        state.stats.stale_handle_rejects++;
        return false;
    }
    CoreEntry &entry = state.cores[handle.index];
    const uint8_t desired_mask = entry.component.mask;
    const bool has_provisional_ja4 =
        entry.ja4_is_summary == kJa4ModeProvisional &&
        (entry.evidence_mask & FK_COMPONENT_JA4) == 0u;
    if (desired_mask == entry.evidence_mask &&
        !has_provisional_ja4)
        return true;
    const uint8_t previous_mask = entry.evidence_mask;
    const uint8_t added = desired_mask & ~previous_mask;
    const uint8_t removed = previous_mask & ~desired_mask;
    const uint8_t physical_before = static_cast<uint8_t>(
        previous_mask |
        (has_provisional_ja4 ? FK_COMPONENT_JA4 : FK_COMPONENT_NONE));
    /* This compatibility API follows a caller-side logical budget
     * transition.  Reserve enough trace slots for the worst-case allocation
     * failure before touching any typed slab, so every physical release is
     * nevertheless observable.  Formal controller paths use the atomic API
     * above and never enter this split compatibility path. */
    if (mask_component_count(physical_before) >
            transition_capacity_available(state)) {
        state.stats.transition_queue_full_rejects++;
        return false;
    }
    if (physical_before != FK_COMPONENT_NONE &&
        !transition_owner_valid(state, handle))
        return false;
    if(physical_before && !persist_lifecycle(state,handle.index,FK_COMPACT_PERSIST_COMPATIBILITY))return false;
    if(physical_before)
        if(auto *evidence=flowkeep::EvidenceFor(table))
            flowkeep::EvidenceCapture(evidence,table,handle,
                physical_before,flowkeep::EvidenceCompatibility);
    uint8_t sync_trace_mask = physical_before;
    const fk_compact_flow_handle self{handle.index, entry.generation};
    const auto physical_bytes = [&](uint8_t component) -> uint64_t {
        if (component == FK_COMPONENT_STAT)
            return sizeof(fk_compact_stat_state);
        if (component == FK_COMPONENT_SEQ)
            return sizeof(fk_compact_seq_state);
        return entry.ja4_is_summary == kJa4ModeSummary
            ? kJa4SummaryBytes : sizeof(fk_compact_ja4_state);
    };
    const auto emit_sync_release = [&](
            uint8_t component,
            fk_compact_transition_reason reason) -> bool {
        const uint8_t final_mask = static_cast<uint8_t>(
            sync_trace_mask & ~component);
        const uint64_t bytes = physical_bytes(component);
        fk_compact_evidence_transition transition{};
        transition.timestamp_ns = timestamp_ns;
        transition.victim_handle = self;
        transition.causing_handle = self;
        transition.causing_packet_count = causing_packet_count;
        transition.previous_mask = sync_trace_mask;
        transition.final_mask = final_mask;
        transition.released_mask = static_cast<uint8_t>(
            entry.component.released_mask | component);
        transition.component = component;
        transition.reason = reason;
        transition.bytes_released = bytes;
        sync_trace_mask = final_mask;
        return append_transition(state, transition);
    };
    uint16_t acquired_stat = 0u;
    uint16_t acquired_seq = 0u;
    uint16_t acquired_ja4 = 0u;
    void *memory = nullptr;
    bool stat_acquired = false;
    bool seq_acquired = false;
    bool ja4_acquired = false;
    if ((added & FK_COMPONENT_STAT) != 0u) {
        stat_acquired = fk_slab_pool_acquire_index(
            state.stat_pool, &acquired_stat, &memory);
    }
    if ((added & FK_COMPONENT_SEQ) != 0u) {
        seq_acquired = fk_slab_pool_acquire_index(
            state.seq_pool, &acquired_seq, &memory);
    }
    if ((added & FK_COMPONENT_JA4) != 0u &&
        has_provisional_ja4) {
        acquired_ja4 = entry.ja4_index;
        ja4_acquired = true;
    } else if ((added & FK_COMPONENT_JA4) != 0u) {
        ja4_acquired = fk_slab_pool_acquire_index(
            state.ja4_pending_pool, &acquired_ja4, &memory);
    }
    const bool allocation_failed =
        ((added & FK_COMPONENT_STAT) != 0u && !stat_acquired) ||
        ((added & FK_COMPONENT_SEQ) != 0u && !seq_acquired) ||
        ((added & FK_COMPONENT_JA4) != 0u && !ja4_acquired);
    if (allocation_failed) {
        if (stat_acquired)
            (void)fk_slab_pool_release_index(
                state.stat_pool, acquired_stat);
        if (seq_acquired)
            (void)fk_slab_pool_release_index(
                state.seq_pool, acquired_seq);
        if (ja4_acquired && !has_provisional_ja4)
            (void)fk_slab_pool_release_index(
                state.ja4_pending_pool, acquired_ja4);
        state.stats.evidence_allocation_failures++;
        for (uint8_t component : {
                 static_cast<uint8_t>(FK_COMPONENT_STAT),
                 static_cast<uint8_t>(FK_COMPONENT_SEQ),
                 static_cast<uint8_t>(FK_COMPONENT_JA4)}) {
            if ((physical_before & component) != 0u &&
                !emit_sync_release(
                    component, FK_COMPACT_TRANSITION_STORAGE_FAILED)) {
                state.stats.allocator_integrity_failures++;
                return false;
            }
        }
        free_evidence(state, handle.index);
        fk_component_flow_release_all(
            state.budget, &entry.component);
        fk_component_flow_mark_loss(
            &entry.component, desired_mask);
        return false;
    }
    const uint64_t previous_bytes =
        ((previous_mask & FK_COMPONENT_STAT) != 0u
            ? sizeof(fk_compact_stat_state) : 0u) +
        ((previous_mask & FK_COMPONENT_SEQ) != 0u
            ? sizeof(fk_compact_seq_state) : 0u) +
        ((previous_mask & FK_COMPONENT_JA4) != 0u
            ? (entry.ja4_is_summary == kJa4ModeSummary
                ? kJa4SummaryBytes : sizeof(fk_compact_ja4_state))
            : (has_provisional_ja4
                ? sizeof(fk_compact_ja4_state) : 0u));
    if ((removed & FK_COMPONENT_STAT) != 0u) {
        (void)fk_slab_pool_release_index(
            state.stat_pool, entry.stat_index);
        if (!emit_sync_release(
                FK_COMPONENT_STAT,
                FK_COMPACT_TRANSITION_POLICY_RELEASED))
            return false;
    }
    if ((removed & FK_COMPONENT_SEQ) != 0u) {
        (void)fk_slab_pool_release_index(
            state.seq_pool, entry.seq_index);
        if (!emit_sync_release(
                FK_COMPONENT_SEQ,
                FK_COMPACT_TRANSITION_POLICY_RELEASED))
            return false;
    }
    if ((removed & FK_COMPONENT_JA4) != 0u) {
        (void)fk_slab_pool_release_index(
            entry.ja4_is_summary == kJa4ModeSummary
                ? state.ja4_summary_pool : state.ja4_pending_pool,
            entry.ja4_index);
        if (!emit_sync_release(
                FK_COMPONENT_JA4,
                FK_COMPACT_TRANSITION_POLICY_RELEASED))
            return false;
        entry.ja4_is_summary = kJa4ModePending;
    }
    if (stat_acquired)
        entry.stat_index = acquired_stat;
    if (seq_acquired)
        entry.seq_index = acquired_seq;
    if (ja4_acquired) {
        entry.ja4_index = acquired_ja4;
        entry.ja4_is_summary = kJa4ModePending;
    } else if (has_provisional_ja4 &&
               (desired_mask & FK_COMPONENT_JA4) == 0u) {
        (void)fk_slab_pool_release_index(
            state.ja4_pending_pool, entry.ja4_index);
        if (!emit_sync_release(
                FK_COMPONENT_JA4,
                FK_COMPACT_TRANSITION_FIRST_DECISION_RELEASED))
            return false;
        if (!fk_component_flow_release_provisional(
                state.budget,
                &entry.component,
                FK_COMPONENT_JA4)) {
            fk_component_flow_mark_loss(
                &entry.component, FK_COMPONENT_JA4);
            return false;
        }
        entry.ja4_index = 0u;
        entry.ja4_is_summary = kJa4ModePending;
        state.stats.bootstrap_tls_releases++;
    }
    entry.evidence_mask = desired_mask;
    if (has_optional_resident(entry))
        note_optional_deadline(state, handle.index);
    else if (previous_mask != FK_COMPONENT_NONE || has_provisional_ja4)
        invalidate_removed_optional_deadline(state, handle.index);
    const uint64_t desired_bytes =
        owned_evidence_bytes(entry.component);
    state.stats.evidence_storage_bytes =
        state.stats.evidence_storage_bytes - previous_bytes +
        desired_bytes;
    if (state.stats.evidence_storage_bytes >
        state.stats.peak_evidence_storage_bytes) {
        state.stats.peak_evidence_storage_bytes =
            state.stats.evidence_storage_bytes;
    }
    return refresh_entry_value_heaps(state, handle.index);
}

bool fk_compact_flow_table_release_lru_optional(
        fk_compact_flow_table *table,
        fk_compact_flow_handle protected_handle,
        uint8_t required_mask,
        fk_compact_flow_handle *released_handle,
        uint8_t *released_mask) {
    if (table == nullptr || released_handle == nullptr ||
        released_mask == nullptr ||
        (required_mask & ~FK_COMPONENT_FULL) != 0u ||
        required_mask == FK_COMPONENT_NONE ||
        !valid_handle(*implementation(table), protected_handle))
        return false;
    CompactFlowTable &state = *implementation(table);
    uint32_t victim = kNoIndex;
    uint64_t oldest = std::numeric_limits<uint64_t>::max();
    for (uint32_t index = 0u; index < state.maximum_flows; ++index) {
        const CoreEntry *entry = core_entry_if_allocated(state, index);
        if (entry == nullptr || entry->used == 0u ||
            index == protected_handle.index ||
            (resident_component_mask(*entry) & required_mask) == 0u)
            continue;
        if (victim == kNoIndex || entry->last_timestamp_ns < oldest) {
            victim = index;
            oldest = entry->last_timestamp_ns;
        }
    }
    if (victim == kNoIndex)
        return false;
    CoreEntry &entry = state.cores[victim];
    *released_mask = resident_component_mask(entry);
    released_handle->index = victim;
    released_handle->generation = entry.generation;
    const CoreEntry &cause = state.cores[protected_handle.index];
    return release_all_optional_for_reason(
        state,
        victim,
        FK_COMPACT_TRANSITION_LRU_EVICTED,
        protected_handle,
        static_cast<uint32_t>(std::min<uint64_t>(
            cause.packets, std::numeric_limits<uint32_t>::max())),
        cause.last_timestamp_ns);
}

fk_compact_value_replacement_status
fk_compact_flow_table_commit_value_replacement(
        fk_compact_flow_table *table,
        fk_compact_flow_handle incoming_handle,
        uint8_t desired_mask,
        uint32_t causing_packet_count,
        uint64_t timestamp_ns,
        fk_compact_value_replacement_outcome *outcome) {
    if (outcome != nullptr)
        *outcome = {};
    if (table == nullptr || outcome == nullptr) {
        if (outcome != nullptr)
            outcome->status = FK_COMPACT_VALUE_REPLACEMENT_INVALID;
        return FK_COMPACT_VALUE_REPLACEMENT_INVALID;
    }
    CompactFlowTable &state = *implementation(table);
    fk_transition_result transition = FK_TRANSITION_ILLEGAL_MASK;
    return commit_value_replacement_internal(
        state,
        incoming_handle,
        desired_mask,
        true,
        AtomicReplacementMode::Value,
        0u,
        causing_packet_count,
        timestamp_ns,
        state.policy,
        transition,
        *outcome);
}

fk_compact_value_replacement_status
fk_compact_flow_table_commit_atomic_transition(
        fk_compact_flow_table *table,
        fk_compact_flow_handle incoming_handle,
        uint8_t desired_mask,
        bool ja4_applicable,
        bool allow_value_replacement,
        uint32_t causing_packet_count,
        uint64_t timestamp_ns,
        const fk_component_policy_config *config,
        fk_compact_value_replacement_outcome *outcome,
        fk_transition_result *transition_result) {
    if (outcome != nullptr)
        *outcome = {};
    if (transition_result != nullptr)
        *transition_result = FK_TRANSITION_ILLEGAL_MASK;
    if (table == nullptr || config == nullptr || outcome == nullptr ||
        transition_result == nullptr ||
        !fk_component_policy_config_valid(config)) {
        if (outcome != nullptr)
            outcome->status = FK_COMPACT_VALUE_REPLACEMENT_INVALID;
        return FK_COMPACT_VALUE_REPLACEMENT_INVALID;
    }
    return commit_value_replacement_internal(
        *implementation(table),
        incoming_handle,
        desired_mask,
        ja4_applicable,
        allow_value_replacement
            ? AtomicReplacementMode::Value
            : AtomicReplacementMode::None,
        0u,
        causing_packet_count,
        timestamp_ns,
        *config,
        *transition_result,
        *outcome);
}

fk_compact_value_replacement_status
fk_compact_flow_table_commit_persistent_transition(
        fk_compact_flow_table *table,fk_compact_flow_handle incoming,
        uint8_t desired_mask,bool ja4_applicable,fk_compact_persistent_policy policy,
        uint32_t maximum_victim_flows,uint32_t packet_count,uint64_t timestamp_ns,
        const fk_component_policy_config *config,const fk_compact_release_guard *guard,
        fk_compact_value_replacement_outcome *outcome,fk_transition_result *transition_result) {
    if(outcome){*outcome={};outcome->status=FK_COMPACT_VALUE_REPLACEMENT_INVALID;}
    if(transition_result)*transition_result=FK_TRANSITION_ILLEGAL_MASK;
    if(!table || !config || !guard || !guard->authorize || !outcome || !transition_result ||
        !fk_component_policy_config_valid(config) || policy<FK_COMPACT_PERSISTENT_FLOWKEEP ||
        policy>FK_COMPACT_PERSISTENT_NO_REPLACEMENT || !maximum_victim_flows || maximum_victim_flows>64)
        return FK_COMPACT_VALUE_REPLACEMENT_INVALID;
    auto &state=*implementation(table);
    const auto expected_metadata=policy==FK_COMPACT_PERSISTENT_CLOCK ? FK_COMPACT_RETENTION_METADATA_CLOCK :
        (policy==FK_COMPACT_PERSISTENT_TWO_Q ? FK_COMPACT_RETENTION_METADATA_TWO_Q : FK_COMPACT_RETENTION_METADATA_NONE);
    if(state.retention_metadata_mode!=expected_metadata)return FK_COMPACT_VALUE_REPLACEMENT_INVALID;
    const AtomicReplacementMode modes[]={AtomicReplacementMode::Value,AtomicReplacementMode::Lru,
        AtomicReplacementMode::Clock,AtomicReplacementMode::TwoQ,
        AtomicReplacementMode::Fifo,AtomicReplacementMode::None};
    // CLOCK mutates reference bits while planning. A deferred persistence
    // attempt must not consume its second chances. This temporary journal is
    // only used by the new opt-in API; account it separately from frozen state.
    std::vector<uint8_t> clock_refs;
    const uint32_t original_hand=state.clock_replacement_hand;
    try {
        if(policy==FK_COMPACT_PERSISTENT_CLOCK) {
            clock_refs.resize(state.maximum_flows);
            for(uint32_t i=0;i<state.maximum_flows;++i) {
                const auto *entry=core_entry_if_allocated(state,i);
                if(entry)clock_refs[i]=static_cast<uint8_t>(entry->fixed_ttl_deadline&kClockReferenceFlag);
            }
        }
    }catch(...) {return FK_COMPACT_VALUE_REPLACEMENT_INVALID;}
    const auto status=commit_value_replacement_internal(state,incoming,desired_mask,ja4_applicable,
        modes[policy],maximum_victim_flows,packet_count,timestamp_ns,*config,*transition_result,*outcome,0,guard);
    if(policy==FK_COMPACT_PERSISTENT_CLOCK) {
        ++outcome->planner_dynamic_allocations;
        if(status!=FK_COMPACT_VALUE_REPLACEMENT_COMMITTED && status!=FK_COMPACT_VALUE_REPLACEMENT_NOT_NEEDED) {
            state.clock_replacement_hand=original_hand;
            for(uint32_t i=0;i<state.maximum_flows;++i) {
                auto *entry=core_entry_if_allocated(state,i);
                if(entry)entry->fixed_ttl_deadline=(entry->fixed_ttl_deadline&~uint64_t(kClockReferenceFlag))|clock_refs[i];
            }
        }
    }
    return status;
}

fk_compact_value_replacement_status
fk_compact_flow_table_commit_atomic_lru_transition(
        fk_compact_flow_table *table,
        fk_compact_flow_handle incoming_handle,
        uint8_t desired_mask,
        bool ja4_applicable,
        uint32_t maximum_victim_flows,
        uint32_t causing_packet_count,
        uint64_t timestamp_ns,
        const fk_component_policy_config *config,
        fk_compact_value_replacement_outcome *outcome,
        fk_transition_result *transition_result) {
    if (outcome != nullptr)
        *outcome = {};
    if (transition_result != nullptr)
        *transition_result = FK_TRANSITION_ILLEGAL_MASK;
    if (table == nullptr || config == nullptr || outcome == nullptr ||
        transition_result == nullptr || maximum_victim_flows == 0u ||
        !fk_component_policy_config_valid(config)) {
        if (outcome != nullptr)
            outcome->status = FK_COMPACT_VALUE_REPLACEMENT_INVALID;
        return FK_COMPACT_VALUE_REPLACEMENT_INVALID;
    }
    return commit_value_replacement_internal(
        *implementation(table),
        incoming_handle,
        desired_mask,
        ja4_applicable,
        AtomicReplacementMode::Lru,
        maximum_victim_flows,
        causing_packet_count,
        timestamp_ns,
        *config,
        *transition_result,
        *outcome);
}

static fk_compact_value_replacement_status
commit_atomic_ordered_transition(
        fk_compact_flow_table *table,
        fk_compact_flow_handle incoming_handle,
        uint8_t desired_mask,
        bool ja4_applicable,
        uint32_t maximum_victim_flows,
        uint32_t causing_packet_count,
        uint64_t timestamp_ns,
        const fk_component_policy_config *config,
        fk_compact_value_replacement_outcome *outcome,
        fk_transition_result *transition_result,
        AtomicReplacementMode mode) {
    if (outcome != nullptr)
        *outcome = {};
    if (transition_result != nullptr)
        *transition_result = FK_TRANSITION_ILLEGAL_MASK;
    if (table == nullptr || config == nullptr || outcome == nullptr ||
        transition_result == nullptr || maximum_victim_flows == 0u ||
        (mode != AtomicReplacementMode::Lfu &&
         mode != AtomicReplacementMode::Fifo &&
         mode != AtomicReplacementMode::Clock &&
         mode != AtomicReplacementMode::TwoQ &&
         mode != AtomicReplacementMode::Arc &&
         mode != AtomicReplacementMode::Gdsf) ||
        !fk_component_policy_config_valid(config)) {
        if (outcome != nullptr)
            outcome->status = FK_COMPACT_VALUE_REPLACEMENT_INVALID;
        return FK_COMPACT_VALUE_REPLACEMENT_INVALID;
    }
    return commit_value_replacement_internal(
        *implementation(table), incoming_handle, desired_mask,
        ja4_applicable, mode, maximum_victim_flows,
        causing_packet_count, timestamp_ns, *config,
        *transition_result, *outcome);
}

fk_compact_value_replacement_status
fk_compact_flow_table_commit_atomic_lfu_transition(
        fk_compact_flow_table *table,
        fk_compact_flow_handle incoming_handle,
        uint8_t desired_mask,
        bool ja4_applicable,
        uint32_t maximum_victim_flows,
        uint32_t causing_packet_count,
        uint64_t timestamp_ns,
        const fk_component_policy_config *config,
        fk_compact_value_replacement_outcome *outcome,
        fk_transition_result *transition_result) {
    return commit_atomic_ordered_transition(
        table, incoming_handle, desired_mask, ja4_applicable,
        maximum_victim_flows, causing_packet_count, timestamp_ns,
        config, outcome, transition_result, AtomicReplacementMode::Lfu);
}

fk_compact_value_replacement_status
fk_compact_flow_table_commit_atomic_fifo_transition(
        fk_compact_flow_table *table,
        fk_compact_flow_handle incoming_handle,
        uint8_t desired_mask,
        bool ja4_applicable,
        uint32_t maximum_victim_flows,
        uint32_t causing_packet_count,
        uint64_t timestamp_ns,
        const fk_component_policy_config *config,
        fk_compact_value_replacement_outcome *outcome,
        fk_transition_result *transition_result) {
    return commit_atomic_ordered_transition(
        table, incoming_handle, desired_mask, ja4_applicable,
        maximum_victim_flows, causing_packet_count, timestamp_ns,
        config, outcome, transition_result, AtomicReplacementMode::Fifo);
}

fk_compact_value_replacement_status
fk_compact_flow_table_commit_atomic_clock_transition(
        fk_compact_flow_table *table,
        fk_compact_flow_handle incoming_handle,
        uint8_t desired_mask,
        bool ja4_applicable,
        uint32_t maximum_victim_flows,
        uint32_t causing_packet_count,
        uint64_t timestamp_ns,
        const fk_component_policy_config *config,
        fk_compact_value_replacement_outcome *outcome,
        fk_transition_result *transition_result) {
    return commit_atomic_ordered_transition(
        table, incoming_handle, desired_mask, ja4_applicable,
        maximum_victim_flows, causing_packet_count, timestamp_ns,
        config, outcome, transition_result, AtomicReplacementMode::Clock);
}

fk_compact_value_replacement_status
fk_compact_flow_table_commit_atomic_two_q_transition(
        fk_compact_flow_table *table,
        fk_compact_flow_handle incoming_handle,
        uint8_t desired_mask,
        bool ja4_applicable,
        uint32_t maximum_victim_flows,
        uint32_t causing_packet_count,
        uint64_t timestamp_ns,
        const fk_component_policy_config *config,
        fk_compact_value_replacement_outcome *outcome,
        fk_transition_result *transition_result) {
    return commit_atomic_ordered_transition(
        table, incoming_handle, desired_mask, ja4_applicable,
        maximum_victim_flows, causing_packet_count, timestamp_ns,
        config, outcome, transition_result, AtomicReplacementMode::TwoQ);
}

fk_compact_value_replacement_status
fk_compact_flow_table_commit_atomic_arc_transition(
        fk_compact_flow_table *table,
        fk_compact_flow_handle incoming_handle,
        uint8_t desired_mask,
        bool ja4_applicable,
        uint32_t maximum_victim_flows,
        uint32_t causing_packet_count,
        uint64_t timestamp_ns,
        const fk_component_policy_config *config,
        fk_compact_value_replacement_outcome *outcome,
        fk_transition_result *transition_result) {
    return commit_atomic_ordered_transition(
        table, incoming_handle, desired_mask, ja4_applicable,
        maximum_victim_flows, causing_packet_count, timestamp_ns,
        config, outcome, transition_result, AtomicReplacementMode::Arc);
}

fk_compact_value_replacement_status
fk_compact_flow_table_commit_atomic_gdsf_transition(
        fk_compact_flow_table *table,
        fk_compact_flow_handle incoming_handle,
        uint8_t desired_mask,
        bool ja4_applicable,
        uint32_t maximum_victim_flows,
        uint32_t causing_packet_count,
        uint64_t timestamp_ns,
        const fk_component_policy_config *config,
        fk_compact_value_replacement_outcome *outcome,
        fk_transition_result *transition_result) {
    return commit_atomic_ordered_transition(
        table, incoming_handle, desired_mask, ja4_applicable,
        maximum_victim_flows, causing_packet_count, timestamp_ns,
        config, outcome, transition_result, AtomicReplacementMode::Gdsf);
}

fk_compact_value_replacement_status
fk_compact_flow_table_commit_atomic_seeded_random_transition(
        fk_compact_flow_table *table,
        fk_compact_flow_handle incoming_handle,
        uint8_t desired_mask,
        bool ja4_applicable,
        uint32_t maximum_victim_flows,
        uint64_t deterministic_seed,
        uint32_t causing_packet_count,
        uint64_t timestamp_ns,
        const fk_component_policy_config *config,
        fk_compact_value_replacement_outcome *outcome,
        fk_transition_result *transition_result) {
    if (outcome != nullptr)
        *outcome = {};
    if (transition_result != nullptr)
        *transition_result = FK_TRANSITION_ILLEGAL_MASK;
    if (table == nullptr || config == nullptr || outcome == nullptr ||
        transition_result == nullptr || maximum_victim_flows == 0u ||
        !fk_component_policy_config_valid(config)) {
        if (outcome != nullptr)
            outcome->status = FK_COMPACT_VALUE_REPLACEMENT_INVALID;
        return FK_COMPACT_VALUE_REPLACEMENT_INVALID;
    }
    return commit_value_replacement_internal(
        *implementation(table), incoming_handle, desired_mask,
        ja4_applicable, AtomicReplacementMode::SeededRandom,
        maximum_victim_flows, causing_packet_count, timestamp_ns,
        *config, *transition_result, *outcome, deterministic_seed);
}

bool fk_compact_flow_table_set_value_eviction_config(
        fk_compact_flow_table *table,
        const fk_compact_value_eviction_config *config) {
    if (table == nullptr || config == nullptr ||
        !std::isfinite(config->hysteresis_eta) ||
        !std::isfinite(config->hysteresis_epsilon) ||
        config->hysteresis_eta < 0.0f ||
        config->hysteresis_epsilon < 0.0f ||
        config->maximum_victim_components == 0u ||
        config->maximum_victim_components >
            FK_VALUE_EVICTION_DEFAULT_MAX_VICTIMS)
        return false;
    CompactFlowTable &state = *implementation(table);
    if (state.stats.active_flows != 0u)
        return false;
    state.value_eviction = *config;
    return true;
}

bool fk_compact_flow_table_set_retention_metadata_mode(
        fk_compact_flow_table *table,
        fk_compact_retention_metadata_mode mode) {
    if (table == nullptr || mode > FK_COMPACT_RETENTION_METADATA_GDSF)
        return false;
    CompactFlowTable &state = *implementation(table);
    if (state.stats.active_flows != 0u)
        return false;
    state.retention_metadata_mode = mode;
    return true;
}

bool fk_compact_flow_table_set_fixed_ttl(
        fk_compact_flow_table *table,
        fk_compact_flow_handle handle,
        uint64_t fixed_ttl_ns) {
    if (table == nullptr || fixed_ttl_ns == 0u)
        return false;
    CompactFlowTable &state = *implementation(table);
    if (!valid_handle(state, handle))
        return false;
    CoreEntry &entry = state.cores[handle.index];
    const uint64_t expiry = entry.first_timestamp_ns >
            std::numeric_limits<uint64_t>::max() - fixed_ttl_ns
        ? std::numeric_limits<uint64_t>::max()
        : entry.first_timestamp_ns + fixed_ttl_ns;
    if (expiry <= entry.component.absolute_deadline_ns) {
        entry.component.absolute_deadline_ns = expiry;
        entry.fixed_ttl_deadline |= kFixedTtlDeadlineFlag;
        note_optional_deadline(state, handle.index);
    }
    return true;
}

bool fk_compact_flow_table_apply_due_timer(
        fk_compact_flow_table *table,
        fk_compact_flow_handle handle,
        uint64_t timestamp_ns,
        uint32_t causing_packet_count,
        bool *expired) {
    if (expired != nullptr)
        *expired = false;
    if (table == nullptr || expired == nullptr)
        return false;
    CompactFlowTable &state = *implementation(table);
    if (!valid_handle(state, handle))
        return false;
    CoreEntry &entry = state.cores[handle.index];
    const bool due =
        timestamp_ns >= entry.component.absolute_deadline_ns;
    if (!due) {
        *expired = false;
        return true;
    }
    *expired = true;
    return release_due_before_observation(
        state, handle.index, timestamp_ns, causing_packet_count);
}

bool fk_compact_flow_table_due_optional_batch(
        const fk_compact_flow_table *table,uint64_t target_ns,
        fk_compact_flow_handle *handles,uint32_t capacity,uint32_t *count) {
    if(count)*count=0u;
    if(!table || !handles || !count || capacity==0u || capacity>64u)return false;
    const auto &state=*implementation(table);
    if(state.idle_retirement_failed)return false;
    if(!state.optional_deadline_heap_size)return true;
    // A 64-node traversal has at most 65 frontier positions. This stack
    // scratch contains indices only, never evidence or retained metadata.
    std::array<uint32_t,65> frontier{};uint32_t size=1u;
    auto entry_at=[&](uint32_t position)->const CoreEntry* {
        if(position>=state.optional_deadline_heap_size)return nullptr;
        const uint32_t index=optional_deadline_index_get(state,position);
        const auto *entry=core_entry_if_allocated(state,index);
        return entry && entry->used==1u && has_optional_resident(*entry) &&
            optional_heap_position(*entry)==position ? entry : nullptr;
    };
    auto later=[&](uint32_t left,uint32_t right) {
        return indexed_heap_key_less(state,true,
            optional_deadline_index_get(state,right),optional_deadline_index_get(state,left));
    };
    if(!entry_at(0u))return false;
    while(size && *count<capacity) {
        std::pop_heap(frontier.begin(),frontier.begin()+size,later);
        const uint32_t position=frontier[--size];
        const auto *entry=entry_at(position);
        if(!entry)return false;
        if(entry->component.absolute_deadline_ns>target_ns)break;
        handles[(*count)++]={optional_deadline_index_get(state,position),entry->generation};
        for(uint32_t child:{position*2u+1u,position*2u+2u})
            if(child<state.optional_deadline_heap_size) {
                if(size==frontier.size() || !entry_at(child))return false;
                frontier[size++]=child;
                std::push_heap(frontier.begin(),frontier.begin()+size,later);
            }
    }
    return true;
}

bool fk_compact_flow_table_next_optional_timer_deadline(
        const fk_compact_flow_table *table,
        uint64_t after_ns,
        uint64_t target_ns,
        uint64_t *deadline_ns) {
    if (table == nullptr || deadline_ns == nullptr ||
        target_ns < after_ns)
        return false;
    const CompactFlowTable &state = *implementation(table);
    state.timer_deadline_queries++;
    if (state.optional_deadline_heap_size == 0u)
        return false;
    const uint32_t core_index = optional_deadline_index_get(state, 0u);
    if (core_index >= state.maximum_flows) {
        state.timer_deadline_rebuilds++;
        state.timer_deadline_probes++;
        return false;
    }
    const CoreEntry *entry = core_entry_if_allocated(state, core_index);
    if (entry == nullptr || entry->used == 0u ||
        !has_optional_resident(*entry) ||
        optional_heap_position(*entry) != 0u) {
        state.timer_deadline_rebuilds++;
        state.timer_deadline_probes++;
        return false;
    }
    const uint64_t earliest = entry->component.absolute_deadline_ns;
    if (earliest < after_ns || earliest > target_ns)
        return false;
    *deadline_ns = earliest;
    return true;
}

uint32_t fk_compact_flow_table_scan_optional_timers(
        fk_compact_flow_table *table,
        uint64_t timestamp_ns,
        fk_pressure_mode pressure,
        const fk_compact_timer_config *config,
        fk_compact_flow_handle causing_handle,
        uint32_t causing_packet_count,
        uint32_t scan_limit) {
    if (table == nullptr || config == nullptr || scan_limit == 0u ||
        pressure < FK_PRESSURE_NORMAL || pressure > FK_PRESSURE_OVERLOAD)
        return 0u;
    CompactFlowTable &state = *implementation(table);
    const uint32_t release_limit =
        config->maximum_component_releases != 0u
        ? config->maximum_component_releases
        : FK_VALUE_EVICTION_DEFAULT_MAX_VICTIMS;
    uint32_t releases = 0u;
    /* Exact optional-deadline expiry (lease path; fixed-TTL disables the
     * fast path because it opportunistically re-arms deadlines while
     * walking).  The deadline heap root is the smallest absolute deadline,
     * so every due entry is released with O(log n) heap work instead of a
     * rotating cursor walk over up to maximum_flows slots per victim.  The
     * previous walk turned sparse lease clusters at the trace tail into
     * tens of millions of empty/non-due table probes and multi-hundred-ms
     * single-owner stalls, which backpressured the exact-ready barrier and
     * produced 300 ms deadline misses. */
    if (config->fixed_ttl_ns == 0u) {
        while (releases < release_limit &&
               state.optional_deadline_heap_size != 0u) {
            const uint32_t core_index =
                optional_deadline_index_get(state, 0u);
            if (core_index >= state.maximum_flows) {
                state.timer_deadline_rebuilds++;
                break;
            }
            CoreEntry *entry = core_entry_if_allocated(state, core_index);
            if (entry == nullptr || entry->used == 0u ||
                !has_optional_resident(*entry) ||
                optional_heap_position(*entry) != 0u) {
                state.timer_deadline_rebuilds++;
                break;
            }
            if (entry->component.absolute_deadline_ns > timestamp_ns)
                break;
            fk_compact_transition_reason reason =
                (entry->fixed_ttl_deadline & kFixedTtlDeadlineFlag) != 0u
                ? FK_COMPACT_TRANSITION_FIXED_TTL_EXPIRED
                : FK_COMPACT_TRANSITION_LEASE_EXPIRED;
            const uint8_t resident = resident_component_mask(*entry);
            if (resident == FK_COMPONENT_NONE) {
                state.timer_deadline_rebuilds++;
                break;
            }
            uint32_t component_count = 0u;
            for (uint8_t component : {
                     static_cast<uint8_t>(FK_COMPONENT_STAT),
                     static_cast<uint8_t>(FK_COMPONENT_SEQ),
                     static_cast<uint8_t>(FK_COMPONENT_JA4)})
                component_count +=
                    (resident & component) != 0u ? 1u : 0u;
            if (component_count > release_limit - releases)
                break;
            if (!release_all_optional_for_reason(
                    state,
                    core_index,
                    reason,
                    causing_handle,
                    causing_packet_count,
                    entry->component.absolute_deadline_ns))
                break;
            releases += component_count;
            if (reason == FK_COMPACT_TRANSITION_FIXED_TTL_EXPIRED)
                state.stats.fixed_ttl_expirations++;
            else
                state.stats.lease_expirations++;
        }
        if (releases >= release_limit)
            return releases;
    }
    const uint32_t scans = std::min(scan_limit, state.maximum_flows);
    for (uint32_t scanned = 0u;
         scanned < scans && releases < release_limit;
         ++scanned) {
        const uint32_t core_index = state.timer_cursor;
        state.timer_cursor =
            (state.timer_cursor + 1u) % state.maximum_flows;
        CoreEntry *entry = core_entry_if_allocated(state, core_index);
        if (entry == nullptr || entry->used == 0u)
            continue;
        if (config->fixed_ttl_ns != 0u) {
            const fk_compact_flow_handle handle{
                core_index, entry->generation};
            (void)fk_compact_flow_table_set_fixed_ttl(
                table, handle, config->fixed_ttl_ns);
        }
        fk_compact_transition_reason reason{};
        bool expire_all = false;
        if (timestamp_ns >= entry->component.absolute_deadline_ns) {
            reason =
                (entry->fixed_ttl_deadline & kFixedTtlDeadlineFlag) != 0u
                ? FK_COMPACT_TRANSITION_FIXED_TTL_EXPIRED
                : FK_COMPACT_TRANSITION_LEASE_EXPIRED;
            expire_all = true;
        }
        const uint8_t resident = resident_component_mask(*entry);
        if (resident == FK_COMPONENT_NONE) {
            if (expire_all)
                entry->component.released_mask |= FK_COMPONENT_FULL;
            continue;
        }
        if (expire_all) {
            uint32_t component_count = 0u;
            for (uint8_t component : {
                     static_cast<uint8_t>(FK_COMPONENT_STAT),
                     static_cast<uint8_t>(FK_COMPONENT_SEQ),
                     static_cast<uint8_t>(FK_COMPONENT_JA4)})
                component_count +=
                    (resident & component) != 0u ? 1u : 0u;
            if (component_count > release_limit - releases)
                break;
            if (!release_all_optional_for_reason(
                    state,
                    core_index,
                    reason,
                    causing_handle,
                    causing_packet_count,
                    entry->component.absolute_deadline_ns))
                break;
            releases += component_count;
            if (reason == FK_COMPACT_TRANSITION_FIXED_TTL_EXPIRED)
                state.stats.fixed_ttl_expirations++;
            else
                state.stats.lease_expirations++;
            continue;
        }
        const uint64_t idle_limit = pressure == FK_PRESSURE_PRESSURE
            ? config->pressure_idle_ns :
            pressure == FK_PRESSURE_OVERLOAD
            ? config->overload_idle_ns : 0u;
        if (idle_limit == 0u ||
            timestamp_ns < entry->last_timestamp_ns ||
            timestamp_ns - entry->last_timestamp_ns < idle_limit)
            continue;
        uint8_t best_component = FK_COMPONENT_NONE;
        float best_density = std::numeric_limits<float>::infinity();
        for (uint8_t component : {
                 static_cast<uint8_t>(FK_COMPONENT_STAT),
                 static_cast<uint8_t>(FK_COMPONENT_SEQ),
                 static_cast<uint8_t>(FK_COMPONENT_JA4)}) {
            if ((resident & component) == 0u)
                continue;
            const float density = resident_value_density(
                *entry, replacement_planning_mask(*entry), component);
            if (density < best_density ||
                (density == best_density && component < best_component)) {
                best_density = density;
                best_component = component;
            }
        }
        if (best_component == FK_COMPONENT_NONE ||
            !std::isfinite(best_density))
            continue;
        const float loss = removal_loss_for_mask(
            *entry, replacement_planning_mask(*entry), best_component);
        const uint64_t pressure_due = entry->last_timestamp_ns >
                std::numeric_limits<uint64_t>::max() - idle_limit
            ? std::numeric_limits<uint64_t>::max()
            : entry->last_timestamp_ns + idle_limit;
        if (!release_component_and_trace(
                state,
                core_index,
                best_component,
                FK_COMPACT_TRANSITION_PRESSURE_EVICTED,
                causing_handle,
                causing_packet_count,
                pressure_due,
                loss,
                0.0f,
                loss,
                0.0f,
                true))
            break;
        releases++;
        state.stats.pressure_evictions++;
    }
    return releases;
}

size_t fk_compact_flow_table_drain_evidence_transitions(
        fk_compact_flow_table *table,
        fk_compact_evidence_transition *transitions,
        size_t capacity) {
    if (table == nullptr || transitions == nullptr || capacity == 0u)
        return 0u;
    CompactFlowTable &state = *implementation(table);
    const size_t count = std::min<size_t>(
        capacity, state.transition_count);
    for (size_t index = 0u; index < count; ++index) {
        transitions[index] = state.transitions[
            (state.transition_head + static_cast<uint32_t>(index)) %
            FK_COMPACT_TRANSITION_CAPACITY];
    }
    state.transition_head =
        (state.transition_head + static_cast<uint32_t>(count)) %
        FK_COMPACT_TRANSITION_CAPACITY;
    state.transition_count -= static_cast<uint32_t>(count);
    return count;
}

fk_compact_stat_state *fk_compact_flow_table_stat(
        fk_compact_flow_table *table,
        fk_compact_flow_handle handle) {
    if (table == nullptr)
        return nullptr;
    CompactFlowTable &state = *implementation(table);
    if (!valid_handle(state, handle))
        return nullptr;
    return static_cast<fk_compact_stat_state *>(
        evidence_component(
            state, state.cores[handle.index], FK_COMPONENT_STAT));
}

fk_compact_seq_state *fk_compact_flow_table_seq(
        fk_compact_flow_table *table,
        fk_compact_flow_handle handle) {
    if (table == nullptr)
        return nullptr;
    CompactFlowTable &state = *implementation(table);
    if (!valid_handle(state, handle))
        return nullptr;
    return static_cast<fk_compact_seq_state *>(
        evidence_component(
            state, state.cores[handle.index], FK_COMPONENT_SEQ));
}

fk_compact_tls_flow *fk_compact_flow_table_tls(
        fk_compact_flow_table *table,
        fk_compact_flow_handle handle) {
    if (table == nullptr)
        return nullptr;
    CompactFlowTable &state = *implementation(table);
    if (!valid_handle(state, handle))
        return nullptr;
    auto *ja4 = static_cast<fk_compact_ja4_state *>(
        evidence_component(
            state, state.cores[handle.index], FK_COMPONENT_JA4));
    if (ja4 == nullptr ||
        state.cores[handle.index].component.owned.ja4_bytes <=
            kJa4SummaryBytes)
        return nullptr;
    return &ja4->tls;
}

fk_compact_ja4_state *fk_compact_flow_table_ja4(
        fk_compact_flow_table *table,
        fk_compact_flow_handle handle) {
    if (table == nullptr)
        return nullptr;
    CompactFlowTable &state = *implementation(table);
    if (!valid_handle(state, handle))
        return nullptr;
    return static_cast<fk_compact_ja4_state *>(
        evidence_component(
            state, state.cores[handle.index], FK_COMPONENT_JA4));
}

bool fk_compact_flow_table_restore_cold(
        fk_compact_flow_table *table,const fk_compact_flow_snapshot *snapshot,
        const fk_compact_core_state *core,const fk_compact_stat_state *stat,
        const fk_compact_seq_state *seq,const fk_compact_ja4_state *ja4,bool full_tls,
        fk_compact_flow_handle *restored_handle) {
    if(!table || !snapshot || !core || !restored_handle ||
       snapshot->first_timestamp_ns>snapshot->last_timestamp_ns ||
       core->first_direction>1 || snapshot->first_direction!=core->first_direction ||
       snapshot->component_mask!=core->component.mask ||
       snapshot->observation_complete!=core->component.observation_complete ||
       snapshot->next_checkpoint_packet!=core->component.next_checkpoint_packet ||
       core->component.mask>FK_COMPONENT_FULL || core->component.released_mask>FK_COMPONENT_FULL ||
       (core->component.mask&core->component.released_mask) ||
       (core->logical_connection_id && snapshot->key.protocol!=17) ||
       (full_tls && !ja4))return false;
    auto &state=*implementation(table);
    if(state.idle_retirement_failed || !state.stats.free_flow_slots)return false;
    const uint8_t resident=(stat?FK_COMPONENT_STAT:0)|(seq?FK_COMPONENT_SEQ:0)|(ja4?FK_COMPONENT_JA4:0);
    if((core->component.mask&~resident) ||
       (resident&~core->component.mask&~FK_COMPONENT_JA4))return false;
    const bool provisional=ja4 && !(core->component.mask&FK_COMPONENT_JA4);
    if(provisional && (!full_tls || core->component.decision_started))return false;
    const uint64_t sizes[3]={stat?sizeof(*stat):0,seq?sizeof(*seq):0,
        ja4?(full_tls?sizeof(*ja4):kJa4SummaryBytes):0};
    if(core->component.owned.stat_bytes!=sizes[0] || core->component.owned.seq_bytes!=sizes[1] ||
       core->component.owned.ja4_bytes!=sizes[2])return false;
    fk_compact_flow_handle handle{};bool created=false;
    if(core->logical_connection_id) {
        // A nonzero identity must not be duplicated among existing distinct cores.
        for(uint32_t i=0;i<state.maximum_flows;++i) {
            auto *e=core_entry_if_allocated(state,i);
            if(e && e->used && e->logical_connection_id==core->logical_connection_id)return false;
        }
        if(!fk_compact_flow_table_admit_distinct(table,&snapshot->key,core->first_direction,
            snapshot->first_timestamp_ns,&handle))return false;
        created=true;
    }else if(!fk_compact_flow_table_lookup_or_admit(table,&snapshot->key,core->first_direction,
                snapshot->first_timestamp_ns,&handle,&created) || !created)return false;
    auto rollback_core=[&]() {
        const auto *guard=state.lifecycle_guard;state.lifecycle_guard=nullptr;
        const bool ok=fk_compact_flow_table_release(table,handle);state.lifecycle_guard=guard;return ok;
    };
    fk_slab_pool *pools[3]={state.stat_pool,state.seq_pool,full_tls?state.ja4_pending_pool:state.ja4_summary_pool};
    uint16_t indexes[3]{};void *memory[3]{};bool acquired[3]{};
    for(unsigned i=0;i<3;++i)if(sizes[i]) {
        acquired[i]=fk_slab_pool_acquire_index(pools[i],&indexes[i],&memory[i]);
        if(!acquired[i]) {
            for(unsigned j=0;j<i;++j)if(acquired[j])fk_slab_pool_release_index(pools[j],indexes[j]);
            rollback_core();return false;
        }
    }
    uint64_t releases[FK_MEMORY_COMPONENT_COUNT]{},reserves[FK_MEMORY_COMPONENT_COUNT]{};
    reserves[FK_MEMORY_STAT]=sizes[0];reserves[FK_MEMORY_SEQ]=sizes[1];reserves[FK_MEMORY_JA4]=sizes[2];
    if(!fk_state_budget_apply_transaction(state.budget,releases,reserves)) {
        for(unsigned i=0;i<3;++i)if(acquired[i])fk_slab_pool_release_index(pools[i],indexes[i]);
        rollback_core();return false;
    }
    auto &entry=state.cores[handle.index];
    entry.first_timestamp_ns=snapshot->first_timestamp_ns;entry.last_timestamp_ns=snapshot->last_timestamp_ns;
    entry.logical_connection_id=core->logical_connection_id;entry.packets=snapshot->packets;entry.bytes=snapshot->bytes;
    entry.component=core->component;entry.bootstrap=core->bootstrap;
    entry.direction_packets[0]=core->direction_packets[0];entry.direction_packets[1]=core->direction_packets[1];
    entry.maximum_wire_size=core->maximum_wire_size;entry.first_direction=core->first_direction;
    entry.fixed_ttl_deadline=core->fixed_ttl_deadline;entry.terminal_observed=core->terminal_observed;
    entry.lifecycle_reserved=core->lifecycle_reserved;
    entry.evidence_mask=core->component.mask;
    entry.ja4_is_summary=provisional?kJa4ModeProvisional:(ja4 && !full_tls?kJa4ModeSummary:kJa4ModePending);
    entry.stat_index=indexes[0];entry.seq_index=indexes[1];entry.ja4_index=indexes[2];
    if(stat)std::memcpy(memory[0],stat,sizes[0]);
    if(seq)std::memcpy(memory[1],seq,sizes[1]);
    if(ja4)std::memcpy(memory[2],ja4,sizes[2]);
    state.stats.evidence_storage_bytes+=sizes[0]+sizes[1]+sizes[2];
    state.stats.peak_evidence_storage_bytes=std::max(state.stats.peak_evidence_storage_bytes,state.stats.evidence_storage_bytes);
    if(has_optional_resident(entry))note_optional_deadline(state,handle.index);
    if(!refresh_entry_value_heaps(state,handle.index)){rollback_core();return false;}
    *restored_handle=handle;return true;
}

bool fk_compact_flow_table_capture_core(
        fk_compact_flow_table *table, fk_compact_flow_handle handle,
        fk_compact_core_state *output) {
    if(!table || !output)return false;
    auto &state=*implementation(table);
    if(!allocated_handle(state,handle))return false;
    const auto &entry=state.cores[handle.index];
    *output={};output->logical_connection_id=entry.logical_connection_id;
    output->component=entry.component;output->bootstrap=entry.bootstrap;
    output->direction_packets[0]=entry.direction_packets[0];
    output->direction_packets[1]=entry.direction_packets[1];
    output->maximum_wire_size=entry.maximum_wire_size;
    output->first_direction=entry.first_direction;
    output->fixed_ttl_deadline=entry.fixed_ttl_deadline;
    output->terminal_observed=entry.terminal_observed;
    output->lifecycle_reserved=entry.lifecycle_reserved;
    return true;
}

const fk_compact_ja4_state *fk_compact_flow_table_resident_ja4(
        fk_compact_flow_table *table, fk_compact_flow_handle handle, bool *full_tls) {
    if(full_tls)*full_tls=false;
    if(!table || !full_tls)return nullptr;
    auto &state=*implementation(table);
    if(!valid_handle(state,handle))return nullptr;
    const auto &entry=state.cores[handle.index];
    if(!component_resident(entry,FK_COMPONENT_JA4))return nullptr;
    const auto *record=static_cast<const fk_compact_ja4_state*>(fk_slab_pool_get_index(
        component_pool(state,entry,FK_COMPONENT_JA4),entry.ja4_index));
    if(record)*full_tls=entry.ja4_is_summary!=kJa4ModeSummary;
    return record;
}

bool fk_compact_flow_table_release(
        fk_compact_flow_table *table,
        fk_compact_flow_handle handle) {
    if (table == nullptr)
        return false;
    CompactFlowTable &state = *implementation(table);
    if (!allocated_handle(state, handle)) {
        state.stats.stale_handle_rejects++;
        return false;
    }
    CoreEntry &entry = state.cores[handle.index];
    const bool distinct = entry.hash_slot == kNoIndex;
    if (!distinct &&
        (entry.hash_slot >= state.hash_capacity ||
         state.slots[entry.hash_slot].state != kSlotOccupied ||
         state.slots[entry.hash_slot].core_index != handle.index)) {
        state.stats.allocator_integrity_failures++;
        return false;
    }
    const bool idle_pending=entry.used==2u;
    if(!persist_lifecycle(state,handle.index,FK_COMPACT_PERSIST_CORE_RETIRE)) {
        if(idle_pending)state.idle_retirement_failed=true;
        return false;
    }
    free_evidence(state, handle.index);
    fk_component_flow_release_all(state.budget, &entry.component);
    fk_flow_key watched_retired{};
    if (compact_key_materialize(entry.key, watched_retired) &&
        fk_m1_watched(watched_retired))
        fk_m1_watch("core_retire", UINT64_MAX, UINT64_MAX,
            entry.last_timestamp_ns, entry.packets,
            handle.index, handle.generation, entry.used);
    compact_key_release(state, entry.key);
    if (!distinct)
        state.slots[entry.hash_slot].state = kSlotTombstone;
    const uint32_t generation = entry.generation;
    entry = {};
    initialize_value_heap_positions(entry);
    CoreSlotMetadata &slot_metadata = state.core_slots[handle.index];
    slot_metadata.generation = generation;
    if (generation == std::numeric_limits<uint32_t>::max()) {
        slot_metadata.next_free = kNoIndex;
        state.stats.generation_exhaustions++;
        state.stats.quarantined_flow_slots++;
    } else {
        slot_metadata.next_free = state.free_head;
        state.free_head = handle.index;
        state.stats.free_flow_slots++;
    }
    CorePage &page =
        state.cores.pages[handle.index / kCorePageEntries];
    if (page.active_entries == 0u) {
        state.stats.allocator_integrity_failures++;
    } else {
        page.active_entries--;
    }
    state.stats.flows_released++;
    state.stats.active_flows--;
    if(idle_pending) {
        if(!state.pending_idle_retirements)state.stats.allocator_integrity_failures++;
        else --state.pending_idle_retirements;
        state.stats.idle_expirations++;
    }
    if (distinct) {
        state.stats.distinct_flows_released++;
        state.stats.active_distinct_flows--;
    }
    if (page.active_entries == 0u &&
        !release_empty_core_page(state, handle.index)) {
        state.stats.allocator_integrity_failures++;
    }
    return true;
}

uint32_t fk_compact_flow_table_expire_idle(
        fk_compact_flow_table *table,
        uint64_t timestamp_ns,
        uint64_t idle_timeout_ns,
        uint32_t scan_limit) {
    if (table == nullptr || scan_limit == 0u)
        return 0u;
    CompactFlowTable &state = *implementation(table);
    state.stats.idle_scan_calls++;
    const uint64_t completed_before=state.stats.idle_expirations;
    if(state.idle_retirement_failed)return 0u;
    if(state.pending_idle_retirements && (state.stats.idle_scan_calls&63u)==0u &&
        !fk_compact_flow_table_poll_idle_retirements(table,false))return 0u;
    uint32_t completed=static_cast<uint32_t>(state.stats.idle_expirations-completed_before);
    /* Optional evidence has its own exact deadline heap and is advanced by
     * the runtime before this idle pass.  Direct FlowTable users retain the
     * legacy release behavior: a due optional root disables this gate. */
    bool optional_deadline_due = false;
    if (state.optional_deadline_heap_size != 0u) {
        const uint32_t root = optional_deadline_index_get(state, 0u);
        const CoreEntry *root_entry = core_entry_if_allocated(state, root);
        optional_deadline_due = root >= state.maximum_flows ||
            root_entry == nullptr || root_entry->used == 0u ||
            root_entry->component.absolute_deadline_ns <= timestamp_ns;
    }
    if (!optional_deadline_due &&
        timestamp_ns < state.expiration_scan_not_before_ns) {
        state.stats.idle_scan_gated_calls++;
        return completed;
    }
    uint32_t expired = 0u;
    const uint32_t scans =
        std::min(scan_limit, state.maximum_flows);
    for (uint32_t scanned = 0u; scanned < scans; ++scanned) {
        const uint32_t index = state.expiration_cursor;
        state.expiration_cursor =
            (state.expiration_cursor + 1u) % state.maximum_flows;
        if(state.pending_idle_retirements>=128u) {
            // Apply bounded backpressure per full batch, rather than falling
            // back to one synchronous WAL write for every subsequent Core in
            // a large semantic-time jump. No borrowed entry survives this poll.
            const uint64_t prior=state.stats.idle_expirations;
            const bool ready=fk_compact_flow_table_poll_idle_retirements(table,true);
            completed+=static_cast<uint32_t>(state.stats.idle_expirations-prior);
            if(!ready)return expired+completed;
        }
        CoreEntry *entry = core_entry_if_allocated(state, index);
        state.stats.idle_scan_probes++;
        const bool entry_was_live = entry != nullptr && entry->used == 1u;
        const uint64_t entry_last_timestamp_ns = entry_was_live
            ? entry->last_timestamp_ns : UINT64_MAX;
        bool entry_left_live_set = false;
        if (entry != nullptr && entry->used == 1u &&
            timestamp_ns >= entry->last_timestamp_ns) {
            const bool deadline_due =
                timestamp_ns >= entry->component.absolute_deadline_ns;
            const bool fixed_ttl_due = deadline_due &&
                (entry->fixed_ttl_deadline & kFixedTtlDeadlineFlag) != 0u;
            const bool lease_due = deadline_due && !fixed_ttl_due;
            if ((fixed_ttl_due || lease_due) &&
                entry->component.released_mask != FK_COMPONENT_FULL) {
                const fk_compact_flow_handle causing{
                    index, entry->generation};
                if (release_all_optional_for_reason(
                        state,
                        index,
                        fixed_ttl_due
                            ? FK_COMPACT_TRANSITION_FIXED_TTL_EXPIRED
                            : FK_COMPACT_TRANSITION_LEASE_EXPIRED,
                        causing,
                        static_cast<uint32_t>(
                            std::min<uint64_t>(
                                entry->packets,
                                std::numeric_limits<uint32_t>::max())),
                        entry->component.absolute_deadline_ns)) {
                    if (fixed_ttl_due)
                        state.stats.fixed_ttl_expirations++;
                    else
                        state.stats.lease_expirations++;
                }
            }
            if (idle_timeout_ns != 0u &&
                timestamp_ns - entry->last_timestamp_ns >
                    idle_timeout_ns) {
                const fk_compact_flow_handle handle{
                    index, entry->generation};
                bool deferred=false;
                if(state.idle_retirement_guard && state.pending_idle_retirements<128u &&
                    entry->logical_connection_id==0u && entry->hash_slot!=kNoIndex &&
                    resident_component_mask(*entry)==FK_COMPONENT_NONE &&
                    entry->component.mask==FK_COMPONENT_NONE && owned_evidence_bytes(entry->component)==0u &&
                    entry->component.released_mask==FK_COMPONENT_FULL) {
                    fk_compact_idle_retirement_result result=FK_COMPACT_IDLE_RETIRE_FAILED;
                    try {result=state.idle_retirement_guard->defer(
                        state.idle_retirement_guard->context,table,handle);}catch(...){}
                    if(result==FK_COMPACT_IDLE_RETIRE_DEFERRED) {
                        entry->used=2u;++state.pending_idle_retirements;deferred=true;
                        entry_left_live_set=true;
                    }else if(result!=FK_COMPACT_IDLE_RETIRE_RETRY) {
                        state.idle_retirement_failed=true;return expired+completed;
                    }
                }
                if (!deferred) {
                    if(fk_compact_flow_table_release(table, handle)) {
                        expired++;state.stats.idle_expirations++;
                        entry_left_live_set=true;
                    }else if(state.idle_retirement_guard) {
                        // A full-queue fallback is still an expiry decision.
                        // Never let a failed write leave its old epoch writable
                        // for the packet about to enter the ordinary lookup.
                        state.idle_retirement_failed=true;return expired+completed;
                    }
                }
            }
        }
        /* The completed-cycle watermark is a proof about entries that remain
         * writable after this scan.  Including an entry that this same pass
         * retired forced one unnecessary full-table pass before a terminal
         * tail batch could resume.  Capture last_timestamp before release
         * (release may free its page), then include it only when it survived. */
        if (entry_was_live && !entry_left_live_set) {
            state.expiration_cycle_min_last_timestamp_ns = std::min(
                state.expiration_cycle_min_last_timestamp_ns,
                entry_last_timestamp_ns);
        }
        if (state.expiration_cursor == 0u) {
            const uint64_t minimum_last =
                state.expiration_cycle_min_last_timestamp_ns;
            state.expiration_scan_not_before_ns =
                idle_timeout_ns == 0u || minimum_last == UINT64_MAX ||
                    minimum_last > UINT64_MAX - idle_timeout_ns
                ? UINT64_MAX : minimum_last + idle_timeout_ns;
            state.expiration_cycle_min_last_timestamp_ns = UINT64_MAX;
            state.stats.idle_scan_completed_cycles++;
        }
    }
    return expired+completed;
}

fk_state_budget *fk_compact_flow_table_budget(
        fk_compact_flow_table *table) {
    return table == nullptr ? nullptr : implementation(table)->budget;
}

bool fk_compact_flow_table_get_stats(
        const fk_compact_flow_table *table,
        fk_compact_flow_table_stats *stats) {
    if (table == nullptr || stats == nullptr)
        return false;
    const CompactFlowTable &state = *implementation(table);
    fk_slab_pool_stats stat{};
    fk_slab_pool_stats seq{};
    fk_slab_pool_stats ja4_pending{};
    fk_slab_pool_stats ja4_summary{};
    if (!fk_slab_pool_get_stats(state.stat_pool, &stat) ||
        !fk_slab_pool_get_stats(state.seq_pool, &seq) ||
        !fk_slab_pool_get_stats(state.ja4_pending_pool, &ja4_pending) ||
        !fk_slab_pool_get_stats(state.ja4_summary_pool, &ja4_summary)) {
        return false;
    }
    *stats = state.stats;
    stats->transition_queue_pending = state.transition_count;
    stats->timer_deadline_queries = state.timer_deadline_queries;
    stats->timer_deadline_rebuilds = state.timer_deadline_rebuilds;
    stats->timer_deadline_probes = state.timer_deadline_probes;
    stats->stat_pool_in_use = stat.in_use;
    stats->stat_pool_peak_in_use = stat.peak_in_use;
    stats->seq_pool_in_use = seq.in_use;
    stats->seq_pool_peak_in_use = seq.peak_in_use;
    stats->ja4_pending_pool_in_use = ja4_pending.in_use;
    stats->ja4_pending_pool_peak_in_use = ja4_pending.peak_in_use;
    stats->ja4_summary_pool_in_use = ja4_summary.in_use;
    stats->ja4_summary_pool_peak_in_use = ja4_summary.peak_in_use;
    stats->stat_pool_block_bytes = stat.block_size;
    stats->seq_pool_block_bytes = seq.block_size;
    stats->ja4_pending_pool_block_bytes = ja4_pending.block_size;
    stats->ja4_summary_pool_block_bytes = ja4_summary.block_size;
    stats->stat_pool_allocations = stat.allocations;
    stats->stat_pool_allocation_rejects = stat.allocation_rejects;
    stats->seq_pool_allocations = seq.allocations;
    stats->seq_pool_allocation_rejects = seq.allocation_rejects;
    stats->ja4_pending_pool_allocations = ja4_pending.allocations;
    stats->ja4_pending_pool_allocation_rejects =
        ja4_pending.allocation_rejects;
    stats->ja4_summary_pool_allocations = ja4_summary.allocations;
    stats->ja4_summary_pool_allocation_rejects =
        ja4_summary.allocation_rejects;
    return true;
}

bool fk_compact_flow_table_slot_accounting_conserved(
        const fk_compact_flow_table *table) {
    if (table == nullptr)
        return false;
    const CompactFlowTable &state = *implementation(table);
    const fk_compact_flow_table_stats &stats = state.stats;
    const uint64_t continuation_limit =
        continuation_probe_limit(state);
    const uint64_t continuation_sweep_steps = std::min(
        kContinuationExpirationSweepSteps,
        state.continuation_capacity);
    const bool continuation_store_outcomes_valid =
        stats.continuation_stores <=
            UINT64_MAX - stats.continuation_store_rejects;
    const uint64_t continuation_store_outcomes =
        continuation_store_outcomes_valid
        ? stats.continuation_stores + stats.continuation_store_rejects
        : 0u;
    const bool continuation_insertions_valid =
        stats.continuation_store_replacements <=
            stats.continuation_stores;
    const uint64_t continuation_insertions =
        continuation_insertions_valid
        ? stats.continuation_stores -
            stats.continuation_store_replacements
        : 0u;
    uint64_t continuation_removals = 0u;
    const bool continuation_removals_valid =
        checked_add_u64(
            continuation_removals,
            stats.continuation_restores) &&
        checked_add_u64(
            continuation_removals,
            stats.continuation_expirations) &&
        checked_add_u64(
            continuation_removals,
            stats.continuation_new_epoch_invalidations) &&
        continuation_removals <= continuation_insertions;
    return indexed_heaps_valid(state) &&
        stats.flows_created >= stats.flows_released &&
        stats.flows_created - stats.flows_released ==
            stats.active_flows &&
        stats.distinct_flows_created >=
            stats.distinct_flows_released &&
        stats.distinct_flows_created -
            stats.distinct_flows_released ==
            stats.active_distinct_flows &&
        stats.distinct_admission_attempts >=
            stats.distinct_flows_created &&
        stats.distinct_admission_attempts -
            stats.distinct_flows_created ==
            stats.distinct_admission_rejects &&
        stats.active_distinct_flows <= stats.active_flows &&
        stats.peak_active_distinct_flows <= stats.peak_active_flows &&
        stats.active_flows <= stats.maximum_flows &&
        stats.free_flow_slots <= stats.maximum_flows - stats.active_flows &&
        stats.quarantined_flow_slots == stats.generation_exhaustions &&
        stats.quarantined_flow_slots ==
            stats.maximum_flows - stats.active_flows -
                stats.free_flow_slots &&
        stats.continuation_directory_entries <=
            stats.continuation_directory_capacity &&
        stats.continuation_directory_entries <=
            stats.continuation_directory_peak_entries &&
        stats.continuation_directory_peak_entries <=
            stats.continuation_directory_capacity &&
        continuation_insertions_valid &&
        continuation_removals_valid &&
        stats.continuation_directory_entries ==
            continuation_insertions - continuation_removals &&
        stats.continuation_store_rejects ==
            stats.continuation_probe_exhaustions &&
        stats.continuation_hits <= stats.continuation_lookups &&
        stats.continuation_misses ==
            stats.continuation_lookups - stats.continuation_hits &&
        stats.continuation_peak_probe_count <= continuation_limit &&
        stats.continuation_expiration_sweep_calls ==
            stats.continuation_store_attempts &&
        stats.continuation_expiration_sweep_calls <=
            UINT64_MAX / continuation_sweep_steps &&
        stats.continuation_expiration_sweep_steps ==
            stats.continuation_expiration_sweep_calls *
                continuation_sweep_steps &&
        stats.continuation_expiration_sweep_expirations <=
            stats.continuation_expirations &&
        continuation_store_outcomes_valid &&
        continuation_store_outcomes <=
            stats.continuation_store_attempts &&
        (stats.continuation_store_attempts == 0u ||
         (stats.continuation_store_probe_steps >=
              stats.continuation_store_attempts &&
          stats.continuation_store_attempts <=
              UINT64_MAX / continuation_limit &&
          stats.continuation_store_probe_steps <=
              stats.continuation_store_attempts * continuation_limit)) &&
        (stats.continuation_lookups == 0u ||
         (stats.continuation_lookup_probe_steps >=
              stats.continuation_lookups &&
          stats.continuation_lookups <=
              UINT64_MAX / continuation_limit &&
          stats.continuation_lookup_probe_steps <=
              stats.continuation_lookups * continuation_limit));
}

#ifdef FK_COMPACT_FLOW_TABLE_TEST_HOOKS
bool fk_compact_flow_table_test_set_free_head_generation(
        fk_compact_flow_table *table,
        uint32_t generation) {
    if (table == nullptr)
        return false;
    CompactFlowTable &state = *implementation(table);
    if (state.free_head == kNoIndex ||
        state.free_head >= state.maximum_flows)
        return false;
    const CoreEntry *entry = core_entry_if_allocated(
        state, state.free_head);
    if (entry != nullptr && entry->used != 0u)
        return false;
    state.core_slots[state.free_head].generation = generation;
    return true;
}

bool fk_compact_flow_table_test_set_atomic_fault_point(
        fk_compact_flow_table *table,
        fk_compact_atomic_fault_point point) {
    if (table == nullptr ||
        point > FK_COMPACT_ATOMIC_FAULT_BEFORE_BUDGET_COMMIT)
        return false;
    implementation(table)->atomic_fault_point =
        static_cast<AtomicFaultPoint>(point);
    return true;
}

bool fk_compact_flow_table_test_full_optional_index_bytes(
        uint32_t maximum_flows,
        uint64_t *bytes) {
    if (maximum_flows == 0u || maximum_flows > 1048576u ||
        bytes == nullptr)
        return false;
    *bytes = full_optional_index_bytes(maximum_flows);
    return *bytes != 0u;
}

bool fk_compact_flow_table_test_narrow_deadline_slot_round_trip(
        fk_compact_flow_table *table,
        uint32_t logical_position,
        uint32_t core_index) {
    if (table == nullptr)
        return false;
    CompactFlowTable &state = *implementation(table);
    if (!compact_index_is_narrow(state.maximum_flows) ||
        core_index >= state.maximum_flows ||
        logical_position >= optional_deadline_heap_capacity(state))
        return false;
    uint32_t remaining = logical_position;
    for (uint8_t heap = 0u; heap < kValueHeapCount; ++heap) {
        const uint32_t capacity = state.value_heap_capacity[heap];
        if (remaining >= capacity) {
            remaining -= capacity;
            continue;
        }
        uint32_t &word = state.value_heaps[heap][remaining];
        const uint32_t saved = word;
        const uint32_t value_seed =
            (core_index + 1u) % state.maximum_flows;
        value_index_set(
            state.value_heaps[heap], remaining,
            value_seed, state.maximum_flows);
        const bool set = optional_deadline_index_set(
            state, logical_position, core_index);
        const bool valid = set &&
            value_index_get(
                state.value_heaps[heap], remaining,
                state.maximum_flows) == value_seed &&
            optional_deadline_index_get(
                state, logical_position) == core_index;
        word = saved;
        return valid;
    }
    return false;
}
#endif

void fk_compact_flow_table_budget_snapshot(
        const fk_compact_flow_table *table,
        fk_budget_snapshot *snapshot) {
    if (table == nullptr || snapshot == nullptr)
        return;
    fk_state_budget_snapshot(implementation(table)->budget, snapshot);
}

}  // extern "C"
