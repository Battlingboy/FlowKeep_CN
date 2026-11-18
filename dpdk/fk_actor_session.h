#ifndef FLOWKEEP_FK_ACTOR_SESSION_H
#define FLOWKEEP_FK_ACTOR_SESSION_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "fk_native_parser.h"

#ifdef __cplusplus
extern "C" {
#endif

#define FK_ACTOR_SESSION_MAX_CIDRS 16u
#define FK_ACTOR_SESSION_DEFAULT_MAX_EVENTS 4096u
#define FK_ACTOR_SESSION_MAX_EVENTS 65536u
#define FK_ACTOR_SESSION_MAX_FLOWS_PER_EVENT 256u
#define FK_ACTOR_SESSION_DEFAULT_TOTAL_FLOWS 65536u

#define FK_ACTOR_SESSION_DEFAULT_IDLE_NS 120000000000ull
#define FK_ACTOR_SESSION_DEFAULT_MAX_LIFETIME_NS 300000000000ull

#define FK_ACTOR_FLOW_IDENTITY_MAX_SHARDS 256u
#define FK_ACTOR_FLOW_IDENTITY_MAX_INDEX 16777215u
#define FK_ACTOR_FLOW_IDENTITY_V2_ABI_VERSION 2u

/*
 * Exact, collision-free identity for one FlowTable incarnation.
 *
 * packed_location stores shard in the high eight bits and the FlowTable slot
 * index in the low 24 bits.  first_timestamp_ns disambiguates an incarnation
 * even if the 32-bit slot generation eventually wraps.  The actor table uses
 * the full 16-byte tuple for hashing and equality; it never substitutes a
 * lossy hash for identity.
 */
struct fk_actor_flow_identity {
    uint64_t first_timestamp_ns;
    uint32_t generation;
    uint32_t packed_location;
};

/*
 * Backward-compatible logical-flow identity.
 *
 * logical_connection_id == 0 preserves the complete v1 presentation
 * identity above.  A non-zero value is the complete QUIC logical connection
 * id (generation in the high word, slot+1 in the low word); in that mode the
 * presentation identity is diagnostic only and may change after migration,
 * NAT rebinding, or a generation-safe FlowTable readmission.
 *
 * Hash tables may use a hash for bucket selection, but equality for a QUIC
 * identity must compare the complete 64-bit logical_connection_id.  A slot
 * index or either 32-bit word alone is never an identity.
 */
struct fk_actor_flow_identity_v2 {
    struct fk_actor_flow_identity presentation;
    uint64_t logical_connection_id;
};

struct fk_actor_session;

bool fk_actor_flow_identity_init(
    struct fk_actor_flow_identity *identity,
    uint32_t shard,
    uint32_t flow_index,
    uint32_t generation,
    uint64_t first_timestamp_ns);

bool fk_actor_flow_identity_v2_init(
    struct fk_actor_flow_identity_v2 *identity,
    const struct fk_actor_flow_identity *presentation,
    uint64_t logical_connection_id);

/* Pure generation arithmetic shared with the allocator and fault tests.
 * UINT32_MAX is a usable final generation, but it has no successor. */
bool fk_actor_event_generation_next(
    uint32_t current_generation,
    uint32_t *next_generation);

/* No-NIC fault-injection hook.  It succeeds only before the first
 * observation and only for an inactive slot that is still on the free list.
 * Production startup must never call this function. */
bool fk_actor_session_test_seed_event_generation(
    struct fk_actor_session *sessions,
    uint32_t event_slot,
    uint32_t current_generation);

enum fk_actor_session_key_kind {
    FK_ACTOR_SESSION_MONITORED_ACTOR = 1,
    FK_ACTOR_SESSION_ENDPOINT_PAIR = 2,
};

enum fk_actor_session_reason {
    FK_ACTOR_REASON_INVALID_INPUT = 0,
    FK_ACTOR_REASON_OUT_OF_ORDER = 1,
    FK_ACTOR_REASON_EXISTING_FLOW_STICKY = 2,
    FK_ACTOR_REASON_EXISTING_ACTOR_SESSION = 3,
    FK_ACTOR_REASON_EXISTING_PAIR_SESSION = 4,
    FK_ACTOR_REASON_NEW_MONITORED_ACTOR = 5,
    FK_ACTOR_REASON_NEW_PAIR_NO_MONITORED_ACTOR = 6,
    FK_ACTOR_REASON_NEW_PAIR_AMBIGUOUS_MONITORED_ACTOR = 7,
    FK_ACTOR_REASON_FLOW_CAPACITY_ROLLOVER = 8,
    FK_ACTOR_REASON_COUNT = 9,
};

struct fk_actor_session_cidr {
    uint8_t ip_version;
    uint8_t prefix_length;
    uint8_t address[16];
};

/*
 * Optional contract for a collision-free compact IPv4 replay namespace.
 *
 * A rewritten address has the form
 *
 *   pool_base + (namespace_id - 1) * slots_per_namespace + identity_index
 *
 * where both namespace_id and identity_index are one based.  The monitored
 * identity is either one fixed index for every namespace or an immutable
 * namespace_count-entry vector indexed by namespace_id-1.  Exactly one mode
 * is configured.  This is intentionally narrower than treating the synthetic
 * replay pool (for example 10.0.0.0/8) as a monitored CIDR.
 */
struct fk_actor_session_compact_ipv4_monitor {
    uint8_t enabled;
    uint8_t pool_prefix_length;
    uint8_t pool_base[4];
    uint16_t reserved;
    uint32_t slots_per_namespace;
    uint32_t namespace_count;
    uint32_t monitored_identity_index;
    const uint32_t *monitored_identity_indices;
    uint32_t monitored_identity_index_count;
    uint32_t reserved_v2;
};

struct fk_actor_session_config {
    uint64_t idle_timeout_ns;
    uint64_t maximum_lifetime_ns;
    uint32_t maximum_events;
    uint32_t maximum_flows_per_event;
    uint32_t maximum_total_flows;
    uint32_t cidr_count;
    struct fk_actor_session_cidr cidrs[FK_ACTOR_SESSION_MAX_CIDRS];
    /* Zero disables non-zero logical_connection_id observations.  A v2
     * deployment must set this to the CID directory's exact connection-slot
     * bound so fk_quic_logical_id_decode can reject out-of-range ids. */
    uint32_t maximum_logical_connection_slots;
    uint32_t reserved_v2;
    struct fk_actor_session_compact_ipv4_monitor compact_ipv4_monitor;
};

struct fk_actor_session_result {
    uint64_t event_id;
    uint32_t event_slot;
    uint32_t event_generation;
    enum fk_actor_session_key_kind key_kind;
    enum fk_actor_session_reason reason;
    bool created;
};

/*
 * Stable, truth-free identity for an active event handle.
 *
 * This is deliberately byte-isomorphic to the AssociationKey stored by the
 * actor/session table.  key_kind contains one of
 * fk_actor_session_key_kind; uint8_t keeps the public C ABI identical to the
 * allocation-free internal key.  IPv4 addresses occupy bytes [0, 4) and the
 * remaining bytes are zero.  For a monitored-actor key, low is the canonical
 * monitored address and high is all zero.  For an endpoint-pair key, low and
 * high are the canonical addresses from fk_flow_key.
 */
struct fk_actor_event_identity {
    uint8_t key_kind;
    uint8_t ip_version;
    uint8_t reserved[2];
    uint8_t low[16];
    uint8_t high[16];
};

struct fk_actor_session_stats {
    uint64_t observations;
    uint64_t invalid_inputs;
    uint64_t out_of_order_observations;
    uint64_t events_created;
    uint64_t idle_expirations;
    uint64_t lifetime_expirations;
    uint64_t event_capacity_evictions;
    uint64_t total_flow_capacity_evictions;
    uint64_t flow_capacity_rollovers;
    uint64_t reason_counts[FK_ACTOR_REASON_COUNT];
    uint32_t active_events;
    uint32_t peak_active_events;
    uint32_t active_flows;
    uint32_t peak_active_flows;
    uint32_t maximum_events;
    uint32_t maximum_flows_per_event;
    uint32_t maximum_total_flows;
    uint64_t reserved_bytes;
    uint64_t used_bytes;
    uint64_t peak_used_bytes;
    uint64_t event_generation_exhaustions;
    uint64_t logical_observations;
    uint64_t logical_sticky_hits;
    uint64_t logical_flows_created;
    /* Rejections caused by malformed/out-of-range logical identity input or
     * by attempting to use the logical domain for a non-UDP flow. */
    uint64_t logical_input_validation_rejects;
    uint32_t quarantined_event_slots;
    uint32_t maximum_logical_connection_slots;
    uint16_t flow_identity_v2_abi_version;
    uint16_t reserved_v2;
};

/*
 * Initialize the frozen production defaults.  The caller must then add at
 * least one monitored CIDR explicitly; no dataset or endpoint heuristic is
 * used to infer the monitored side.
 */
void fk_actor_session_config_init(struct fk_actor_session_config *config);

/*
 * Add an IPv4 or IPv6 prefix.  address points to four bytes for IPv4 and
 * sixteen bytes for IPv6.  Host bits are ignored during prefix matching.
 */
bool fk_actor_session_config_add_cidr(
    struct fk_actor_session_config *config,
    uint8_t ip_version,
    const uint8_t *address,
    uint8_t prefix_length);

/*
 * Parse one allocation-free CLI token such as 192.168.0.0/16 or
 * 2001:db8::/32. The stored address is canonicalized by clearing host bits.
 */
bool fk_actor_session_config_add_cidr_text(
    struct fk_actor_session_config *config,
    const char *cidr_text);

/* Configure the optional compact rewritten-IPv4 monitored identity. */
bool fk_actor_session_config_set_compact_ipv4_monitor(
    struct fk_actor_session_config *config,
    const uint8_t pool_base[4],
    uint8_t pool_prefix_length,
    uint32_t slots_per_namespace,
    uint32_t namespace_count,
    uint32_t monitored_identity_index);

/* Allocation-free IPv4 CIDR parser for the compact monitor contract. */
bool fk_actor_session_config_set_compact_ipv4_monitor_text(
    struct fk_actor_session_config *config,
    const char *pool_cidr,
    uint32_t slots_per_namespace,
    uint32_t namespace_count,
    uint32_t monitored_identity_index);

/*
 * Configure a per-namespace monitored identity vector.  The vector must have
 * exactly namespace_count one-based entries in [1, slots_per_namespace] and
 * must remain immutable and alive for every actor-session object initialized
 * from this config.  The implementation never takes ownership and never
 * writes through this pointer.
 */
bool fk_actor_session_config_set_compact_ipv4_monitor_map(
    struct fk_actor_session_config *config,
    const uint8_t pool_base[4],
    uint8_t pool_prefix_length,
    uint32_t slots_per_namespace,
    uint32_t namespace_count,
    const uint32_t *monitored_identity_indices,
    uint32_t monitored_identity_index_count);

bool fk_actor_session_config_set_compact_ipv4_monitor_map_text(
    struct fk_actor_session_config *config,
    const char *pool_cidr,
    uint32_t slots_per_namespace,
    uint32_t namespace_count,
    const uint32_t *monitored_identity_indices,
    uint32_t monitored_identity_index_count);

bool fk_actor_session_config_valid(
    const struct fk_actor_session_config *config);

/* Strict Datacon attestation: exactly the canonical 192.168.0.0/16 prefix. */
bool fk_actor_session_config_is_datacon(
    const struct fk_actor_session_config *config);

/*
 * The implementation performs no dynamic allocation or deallocation.
 * Objects are placement-constructed once inside caller-owned storage;
 * storage_bytes includes enough leading padding for arbitrary alignment.
 */
size_t fk_actor_session_storage_bytes(
    const struct fk_actor_session_config *config);

struct fk_actor_session *fk_actor_session_init(
    void *storage,
    size_t storage_bytes,
    const struct fk_actor_session_config *config,
    char *error,
    size_t error_capacity);

/*
 * Observe one immutable checkpoint in non-decreasing observation-time order;
 * observation time must also be at or after identity.first_timestamp_ns.
 * One DPDK shard/worker owns each instance; this API intentionally performs
 * no internal locking.
 * Flow identity is the exact runtime tuple:
 *
 *   (flow_first_timestamp_ns, flow_generation, shard, FlowTable slot)
 *
 * The canonical flow key is used only when a new identity must be mapped to
 * an actor/pair.  It is deliberately not duplicated in the sticky-flow table.
 *
 * A successful result contains a monotonic event_id and a slot generation;
 * callers must use both slot and generation if retaining a direct slot handle.
 */
bool fk_actor_session_observe(
    struct fk_actor_session *sessions,
    const struct fk_flow_key *key,
    const struct fk_actor_flow_identity *flow_identity,
    uint64_t observation_timestamp_ns,
    struct fk_actor_session_result *result);

/* v2 observation.  The v1 entry point above is exactly this operation with
 * logical_connection_id == 0. */
bool fk_actor_session_observe_v2(
    struct fk_actor_session *sessions,
    const struct fk_flow_key *key,
    const struct fk_actor_flow_identity_v2 *flow_identity,
    uint64_t observation_timestamp_ns,
    struct fk_actor_session_result *result);

/* Read-only sticky-flow lookup.  It performs no expiry, timestamp update, or
 * statistics mutation.  The returned event handle remains subject to the
 * normal event_handle_active validation before delayed use. */
bool fk_actor_session_lookup_flow(
    const struct fk_actor_session *sessions,
    const struct fk_actor_flow_identity *flow_identity,
    struct fk_actor_session_result *result);

bool fk_actor_session_lookup_flow_v2(
    const struct fk_actor_session *sessions,
    const struct fk_actor_flow_identity_v2 *flow_identity,
    struct fk_actor_session_result *result);

bool fk_actor_session_get_stats(
    const struct fk_actor_session *sessions,
    struct fk_actor_session_stats *stats);

/* Validate a delayed detector result against slot reuse and event expiry. */
bool fk_actor_session_event_handle_active(
    const struct fk_actor_session *sessions,
    uint32_t event_slot,
    uint32_t event_generation,
    uint64_t event_id);

/*
 * Resolve the immutable actor/pair identity for one complete active handle.
 * The exact (event_slot, event_generation, event_id) tuple must match.  The
 * operation performs no allocation, expiry, or statistics mutation.  On any
 * failure, identity is zeroed when non-null so stale caller data cannot be
 * mistaken for a successful EVENT_BIND identity.
 */
bool fk_actor_session_get_event_identity(
    const struct fk_actor_session *sessions,
    uint32_t event_slot,
    uint32_t event_generation,
    uint64_t event_id,
    struct fk_actor_event_identity *identity);

#ifdef __cplusplus
}
#endif

#endif
