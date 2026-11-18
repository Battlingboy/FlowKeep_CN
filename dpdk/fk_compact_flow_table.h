#ifndef FLOWKEEP_FK_COMPACT_FLOW_TABLE_H
#define FLOWKEEP_FK_COMPACT_FLOW_TABLE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "fk_component_state.h"
#include "fk_compact_tls.h"
#include "fk_native_parser.h"

#ifdef __cplusplus
extern "C" {
#endif

struct fk_compact_flow_handle {
    uint32_t index;
    uint32_t generation;
};

/* Producer-observed identity of the resident generation displaced into the
 * bounded continuation directory.  It is returned exactly once with a
 * successful restore and becomes the attested FLOW_CONTINUE edge. */
struct fk_compact_capacity_continuation_predecessor {
    uint32_t flow_index;
    uint32_t flow_generation;
    uint32_t last_checkpoint_packet;
};

struct fk_compact_flow_snapshot {
    struct fk_flow_key key;
    uint64_t first_timestamp_ns;
    uint64_t last_timestamp_ns;
    uint64_t packets;
    uint64_t bytes;
    uint8_t first_direction;
    uint8_t component_mask;
    uint8_t observation_complete;
    uint8_t reserved;
    uint32_t next_checkpoint_packet;
};

#define FK_COMPACT_SEQ_PACKETS 20u
#define FK_COMPACT_BOOTSTRAP_PACKETS 4u
#define FK_COMPACT_ACTION_FEATURES 30u
/* Pending transition records can span multiple packets until the external
 * consumer drains them.  Keep the audited 1,024-record cross-transaction
 * burst capacity; the 195-record single-transaction bound is not sufficient
 * for high-churn policies such as LRU. */
#define FK_COMPACT_TRANSITION_CAPACITY 1024u
#define FK_COMPACT_CAPACITY_CONTINUATION_PROBE_LIMIT 64u
#define FK_COMPACT_CAPACITY_CONTINUATION_EXPIRATION_SWEEP_STEPS 64u

struct fk_compact_packet_metadata {
    uint32_t delta_time_us;
    /* Compact detector schema V4 consumes only wire size, delta time, and
     * direction from SEQ.  The receiver's validated maximum frame is at most
     * 16,384 bytes, so uint16_t is lossless for every admitted packet. */
    uint16_t wire_size;
    uint8_t direction;
    uint8_t reserved;
};

#ifdef __cplusplus
static_assert(sizeof(fk_compact_packet_metadata) == 8u,
              "compact SEQ record must remain one 64-bit word");
#endif

struct fk_compact_bootstrap_state {
    uint16_t wire_size[FK_COMPACT_BOOTSTRAP_PACKETS];
    uint16_t payload_size[FK_COMPACT_BOOTSTRAP_PACKETS];
    uint16_t delta_time_us[FK_COMPACT_BOOTSTRAP_PACKETS - 1u];
    uint8_t tcp_flags[FK_COMPACT_BOOTSTRAP_PACKETS];
    uint8_t direction_bits;
    uint8_t count;
};

struct fk_compact_flow_table;
/* Portable logical Core payload; deliberately excludes allocator pointers,
 * hash/slab indexes and replacement heap positions. */
struct fk_compact_core_state {
    uint64_t logical_connection_id;
    struct fk_component_flow component;
    struct fk_compact_bootstrap_state bootstrap;
    uint16_t direction_packets[2];
    uint16_t maximum_wire_size;
    uint8_t first_direction;
    uint8_t fixed_ttl_deadline;
    uint8_t terminal_observed;
    uint8_t lifecycle_reserved;
};
bool fk_compact_flow_table_capture_core(
    struct fk_compact_flow_table *table, struct fk_compact_flow_handle handle,
    struct fk_compact_core_state *output);

struct fk_compact_stat_state {
    uint64_t direction_packets[2];
    uint64_t direction_bytes[2];
    uint64_t payload_bytes[2];
    uint64_t interarrival_sum_ns[2];
    uint64_t interarrival_squared_sum_ns[2];
    uint32_t minimum_wire_size;
    uint32_t maximum_wire_size;
    uint32_t tcp_flag_counts[8];
};

struct fk_compact_seq_state {
    struct fk_compact_packet_metadata packets[FK_COMPACT_SEQ_PACKETS];
    uint32_t count;
    uint32_t next;
};

struct fk_compact_fingerprint_observation {
    uint64_t cipher_set_hash;
    uint64_t extension_set_hash;
    uint64_t signature_set_hash;
    uint64_t server_name_hash;
    uint64_t alpn_hash;
    uint16_t legacy_version;
    uint16_t selected_cipher;
    uint16_t cipher_count;
    uint16_t extension_count;
    uint16_t signature_algorithm_count;
    uint8_t present;
    uint8_t hello_retry_request;
    uint8_t completeness;
    uint8_t framing;
};

struct fk_compact_ja4_state {
    struct fk_compact_fingerprint_observation client;
    struct fk_compact_fingerprint_observation server;
    struct fk_compact_tls_flow tls;
};

struct fk_compact_flow_table_stats {
    uint64_t lookups;
    uint64_t lookup_hits;
    uint64_t flows_created;
    uint64_t flows_released;
    uint64_t idle_expirations;
    uint64_t lease_expirations;
    uint64_t admission_rejects;
    uint64_t stale_handle_rejects;
    uint64_t active_flows;
    uint64_t peak_active_flows;
    uint32_t maximum_flows;
    uint32_t hash_capacity;
    uint64_t flow_table_allocation_bytes;
    uint64_t core_allocation_bytes;
    uint64_t lease_allocation_bytes;
    uint64_t mandatory_allocation_bytes;
    uint64_t evidence_allocation_failures;
    uint64_t evidence_storage_bytes;
    uint64_t peak_evidence_storage_bytes;
    uint64_t ja4_compactions;
    uint64_t ja4_compaction_rejects;
    uint64_t ja4_parser_bytes_reclaimed;
    uint64_t bootstrap_tls_admissions;
    uint64_t bootstrap_tls_budget_rejects;
    uint64_t bootstrap_tls_pool_rejects;
    uint64_t bootstrap_tls_releases;
    uint64_t pool_reserved_bytes;
    uint64_t pool_unassigned_bytes;
    uint64_t value_index_allocation_bytes;
    uint32_t stat_pool_capacity;
    uint32_t seq_pool_capacity;
    uint32_t ja4_pending_pool_capacity;
    uint32_t ja4_summary_pool_capacity;
    /* Quiescent optional-pool receipts.  Capacity alone cannot establish
     * that a Validation pressure trace exercised retention competition, so
     * expose the allocator occupancy and rejection counters as well. */
    uint32_t stat_pool_in_use;
    uint32_t stat_pool_peak_in_use;
    uint32_t seq_pool_in_use;
    uint32_t seq_pool_peak_in_use;
    uint32_t ja4_pending_pool_in_use;
    uint32_t ja4_pending_pool_peak_in_use;
    uint32_t ja4_summary_pool_in_use;
    uint32_t ja4_summary_pool_peak_in_use;
    uint32_t stat_pool_block_bytes;
    uint32_t seq_pool_block_bytes;
    uint32_t ja4_pending_pool_block_bytes;
    uint32_t ja4_summary_pool_block_bytes;
    uint64_t stat_pool_allocations;
    uint64_t stat_pool_allocation_rejects;
    uint64_t seq_pool_allocations;
    uint64_t seq_pool_allocation_rejects;
    uint64_t ja4_pending_pool_allocations;
    uint64_t ja4_pending_pool_allocation_rejects;
    uint64_t ja4_summary_pool_allocations;
    uint64_t ja4_summary_pool_allocation_rejects;
    /* Append-only allocator integrity accounting.  A slot whose 32-bit
     * generation reaches UINT32_MAX is permanently quarantined on release;
     * wrapping it to one would make a sufficiently old handle valid again. */
    uint64_t generation_exhaustions;
    uint64_t allocator_integrity_failures;
    uint32_t free_flow_slots;
    uint32_t quarantined_flow_slots;
    /* QUIC logical connections can share one UDP five tuple.  These counters
     * cover deliberately unindexed core entries reached thereafter only by
     * an exact owner-binding generation handle. */
    uint64_t distinct_admission_attempts;
    uint64_t distinct_admission_rejects;
    uint64_t distinct_flows_created;
    uint64_t distinct_flows_released;
    uint64_t active_distinct_flows;
    uint64_t peak_active_distinct_flows;
    uint64_t value_replacement_attempts;
    uint64_t value_replacement_commits;
    uint64_t value_replacement_rejects;
    uint64_t value_components_evicted;
    uint64_t value_victim_probes;
    uint64_t value_planner_dynamic_allocations;
    uint64_t fixed_ttl_expirations;
    uint64_t pressure_evictions;
    uint64_t transition_records_emitted;
    uint64_t transition_queue_full_rejects;
    /* Exact-deadline index audit.  Queries read the per-shard heap root in
     * O(1).  The legacy rebuild/probe ABI counters remain zero in normal
     * operation and increment only if root integrity validation fails. */
    uint64_t timer_deadline_queries;
    uint64_t timer_deadline_rebuilds;
    uint64_t timer_deadline_probes;
    /* Records awaiting owner/composition consumption.  A formal run is
     * complete only after this reaches zero: otherwise a causal evidence
     * release was not attached to the decision audit trail. */
    uint32_t transition_queue_pending;
    /* Fixed-capacity, controlled-budget continuation directory.  Only
     * ordinary tuple-owned flows displaced by saturated-table admission are
     * entered.  Lookups and replacement inspect at most the frozen bounded
     * double-hash probe limit (or all distinct slots in a smaller directory). */
    uint32_t continuation_directory_capacity;
    uint32_t continuation_directory_entries;
    /* Temporal high-water mark, updated on every successful insertion. */
    uint32_t continuation_directory_peak_entries;
    uint64_t continuation_directory_reserved_bytes;
    uint64_t continuation_lookups;
    uint64_t continuation_hits;
    uint64_t continuation_misses;
    uint64_t continuation_store_attempts;
    uint64_t continuation_stores;
    uint64_t continuation_store_replacements;
    uint64_t continuation_store_rejects;
    uint64_t continuation_store_probe_steps;
    uint64_t continuation_lookup_probe_steps;
    uint64_t continuation_peak_probe_count;
    uint64_t continuation_probe_exhaustions;
    uint64_t continuation_expirations;
    uint64_t continuation_expiration_sweep_calls;
    uint64_t continuation_expiration_sweep_steps;
    uint64_t continuation_expiration_sweep_expirations;
    uint64_t continuation_new_epoch_invalidations;
    uint64_t continuation_restores;
    uint64_t tcp_new_epoch_retirements;
    /* Idle expiry remains a bounded rotating scan, but a completed pass
     * proves a lower bound on the next possible idle deadline.  These
     * counters make the hot-path gate externally auditable. */
    uint64_t idle_scan_calls;
    uint64_t idle_scan_probes;
    uint64_t idle_scan_gated_calls;
    uint64_t idle_scan_completed_cycles;
};

enum fk_compact_transition_reason {
    FK_COMPACT_TRANSITION_VALUE_REPLACED = 1,
    FK_COMPACT_TRANSITION_FIXED_TTL_EXPIRED = 2,
    FK_COMPACT_TRANSITION_LEASE_EXPIRED = 3,
    FK_COMPACT_TRANSITION_PRESSURE_EVICTED = 4,
    FK_COMPACT_TRANSITION_POLICY_RELEASED = 5,
    FK_COMPACT_TRANSITION_LRU_EVICTED = 6,
    FK_COMPACT_TRANSITION_FIRST_DECISION_RELEASED = 7,
    FK_COMPACT_TRANSITION_STORAGE_FAILED = 8,
    FK_COMPACT_TRANSITION_LFU_EVICTED = 9,
    FK_COMPACT_TRANSITION_FIFO_EVICTED = 10,
    FK_COMPACT_TRANSITION_SEEDED_RANDOM_EVICTED = 11,
    FK_COMPACT_TRANSITION_CLOCK_EVICTED = 12,
    FK_COMPACT_TRANSITION_TWO_Q_EVICTED = 13,
    FK_COMPACT_TRANSITION_ARC_EVICTED = 14,
    FK_COMPACT_TRANSITION_GDSF_EVICTED = 15,
};

struct fk_compact_evidence_transition {
    uint64_t sequence;
    uint64_t timestamp_ns;
    struct fk_compact_flow_handle victim_handle;
    /* Immutable owner evidence is captured while victim_handle is still a
     * live generation.  Consumers must never reconstruct it from a slot after
     * timer/idle/terminal reclamation. */
    struct fk_flow_key victim_key;
    uint64_t victim_flow_first_timestamp_ns;
    uint64_t victim_logical_connection_id;
    struct fk_compact_flow_handle causing_handle;
    uint32_t causing_packet_count;
    uint8_t previous_mask;
    uint8_t final_mask;
    uint8_t released_mask;
    uint8_t component;
    enum fk_compact_transition_reason reason;
    uint64_t bytes_released;
    float victim_loss;
    float victim_value_per_byte;
    float incoming_bundle_gain;
    float victim_total_loss;
    float hysteresis_eta;
};

enum fk_compact_value_replacement_status {
    FK_COMPACT_VALUE_REPLACEMENT_NOT_NEEDED = 0,
    FK_COMPACT_VALUE_REPLACEMENT_COMMITTED = 1,
    FK_COMPACT_VALUE_REPLACEMENT_VALUE_REJECTED = 2,
    FK_COMPACT_VALUE_REPLACEMENT_NO_PLAN = 3,
    FK_COMPACT_VALUE_REPLACEMENT_TRACE_FULL = 4,
    FK_COMPACT_VALUE_REPLACEMENT_INVALID = 5,
    FK_COMPACT_VALUE_REPLACEMENT_PERSISTENCE_PENDING = 6,
};

struct fk_compact_value_replacement_outcome {
    enum fk_compact_value_replacement_status status;
    uint32_t victim_components;
    uint32_t victim_flows;
    uint32_t victim_probes;
    uint32_t planner_dynamic_allocations;
    uint64_t bytes_released;
    float incoming_bundle_gain;
    float victim_total_loss;
    float hysteresis_eta;
    float hysteresis_epsilon;
};

struct fk_compact_value_eviction_config {
    float hysteresis_eta;
    float hysteresis_epsilon;
    uint32_t maximum_victim_components;
};

struct fk_compact_timer_config {
    /* Zero disables a timer.  Expiry uses now >= first/last + interval. */
    uint64_t fixed_ttl_ns;
    uint64_t pressure_idle_ns;
    uint64_t overload_idle_ns;
    uint32_t maximum_component_releases;
};

struct fk_compact_flow_table;

enum fk_compact_retention_metadata_mode {
    FK_COMPACT_RETENTION_METADATA_NONE = 0,
    FK_COMPACT_RETENTION_METADATA_CLOCK = 1,
    FK_COMPACT_RETENTION_METADATA_TWO_Q = 2,
    FK_COMPACT_RETENTION_METADATA_ARC = 3,
    FK_COMPACT_RETENTION_METADATA_GDSF = 4,
};

struct fk_component_pool_weights {
    uint8_t stat_percent;
    uint8_t seq_percent;
    uint8_t ja4_pending_percent;
    uint8_t ja4_summary_percent;
};

/*
 * Exact ABI-specific lower bound for a usable table: mandatory
 * FlowTable/BOOTSTRAP/lease arrays plus at least one block in every optional
 * evidence pool under the supplied weights. No allocation is performed.
 */
bool fk_compact_flow_table_minimum_controlled_budget_bytes(
    uint32_t maximum_flows,
    const struct fk_component_pool_weights *pool_weights,
    uint64_t *minimum_bytes);

struct fk_compact_flow_table *fk_compact_flow_table_create(
    uint32_t maximum_flows,
    uint64_t controlled_budget_bytes,
    const struct fk_component_policy_config *policy,
    char *error,
    size_t error_capacity);

struct fk_compact_flow_table *fk_compact_flow_table_create_with_pool_weights(
    uint32_t maximum_flows,
    uint64_t controlled_budget_bytes,
    const struct fk_component_policy_config *policy,
    const struct fk_component_pool_weights *pool_weights,
    char *error,
    size_t error_capacity);

/*
 * Full-State reference mode: preallocate every optional state pool to the
 * maximum representable flow capacity. This has no 16/32/64 MiB hard limit,
 * but remains bounded by maximum_flows and never allocates on the hot path.
 */
struct fk_compact_flow_table *fk_compact_flow_table_create_full_capacity(
    uint32_t maximum_flows,
    const struct fk_component_policy_config *policy,
    char *error,
    size_t error_capacity);

void fk_compact_flow_table_destroy(struct fk_compact_flow_table *table);

bool fk_compact_flow_table_lookup_or_admit(
    struct fk_compact_flow_table *table,
    const struct fk_flow_key *key,
    uint8_t first_direction,
    uint64_t timestamp_ns,
    struct fk_compact_flow_handle *handle,
    bool *created);

/* Stale owner-handle recovery may replace an already-scored generation but
 * must not destroy a never-scored resident merely because the supplied
 * handle was invalid.  Ordinary unbound admission uses lookup_or_admit(). */
bool fk_compact_flow_table_lookup_or_admit_scored_only(
    struct fk_compact_flow_table *table,
    const struct fk_flow_key *key,
    uint8_t first_direction,
    uint64_t timestamp_ns,
    struct fk_compact_flow_handle *handle,
    bool *created);

/*
 * Allocate a new core entry without inserting the presentation five tuple
 * into the tuple hash.  This is the initial/readmission path for a resolved
 * QUIC logical connection: multiple connections may concurrently share the
 * same UDP tuple, and all later observations must arrive through the exact
 * generation handle held by the owner-binding directory.  The immutable
 * logical ID is bound immediately after admission so a later evidence-release
 * audit record remains attributable after the core generation is reclaimed;
 * it is never a detector feature.
 */
bool fk_compact_flow_table_admit_distinct(
    struct fk_compact_flow_table *table,
    const struct fk_flow_key *presentation_key,
    uint8_t first_direction,
    uint64_t timestamp_ns,
    struct fk_compact_flow_handle *handle);

/* Bind/validate the immutable routing identity before the first observation.
 * Zero identifies ordinary tuple-owned flows.  A nonzero identity is accepted
 * only for an unindexed UDP generation and can never be changed afterward. */
bool fk_compact_flow_table_bind_logical_connection_id(
    struct fk_compact_flow_table *table,
    struct fk_compact_flow_handle handle,
    uint64_t logical_connection_id);

/* Non-mutating generation check for an identity directory that retains a
 * bound flow handle.  A false result requires explicit rebind/re-admission;
 * callers must never reuse only the slot index. */
bool fk_compact_flow_table_handle_valid(
    const struct fk_compact_flow_table *table,
    struct fk_compact_flow_handle handle);

/* Configure the maximum inactive gap for fixed-directory continuation
 * records.  Runtime creation installs its frozen idle timeout exactly once;
 * a direct FlowTable user may leave this unset, in which case a full
 * directory applies lossless admission backpressure instead of guessing an
 * expiry boundary. */
bool fk_compact_flow_table_set_capacity_continuation_gap(
    struct fk_compact_flow_table *table,
    uint64_t maximum_gap_ns);

/* Apply the TCP five-tuple epoch rule before lookup/admission.  A bare SYN is
 * a retransmission only while the live generation is still pre-established
 * and its sequence equals the original ISN.  Every other bare SYN retires the
 * exact old generation, after first tracing any resident optional evidence,
 * so the caller can admit a fresh FLOW_OPEN generation for the same tuple.
 * `bound_handle` may be NULL for ordinary tuple lookup. */
bool fk_compact_flow_table_retire_reused_tcp_tuple(
    struct fk_compact_flow_table *table,
    const struct fk_flow_key *key,
    const struct fk_compact_flow_handle *bound_handle,
    uint8_t tcp_flags,
    uint32_t tcp_sequence,
    uint64_t timestamp_ns,
    bool *retired);

/* Restore the mandatory CORE/checkpoint prefix of an ordinary flow that was
 * displaced solely to admit another tuple at full capacity.  The call is
 * valid only for a just-created, still-empty generation.  Optional evidence
 * is never resurrected: any previously resident component is marked lost.
 *
 * A matching entry is consumed exactly once.  Entries older than
 * maximum_gap_ns, timestamp regressions, and a bare SYN after an already
 * scored prefix start a new epoch instead.  The directory is allocated as
 * part of FlowTable mandatory state and never grows after creation. */
bool fk_compact_flow_table_resume_capacity_continuation(
    struct fk_compact_flow_table *table,
    struct fk_compact_flow_handle handle,
    uint8_t tcp_flags,
    uint32_t tcp_sequence,
    uint8_t canonical_direction,
    uint64_t timestamp_ns,
    uint64_t maximum_gap_ns,
    bool *resumed,
    struct fk_compact_capacity_continuation_predecessor *predecessor);

/* Replace one ordinary live CORE generation with an exact sparse
 * continuation after its final checkpoint is complete.  The operation is
 * atomic with respect to visible identity: an ineligible flow remains live,
 * and a directory failure never releases it.  Optional evidence must already
 * be absent; callers must first publish/drain any policy-release transition.
 * A later non-SYN collision fallback resumes as FLOW_CONTINUE, while a new
 * bare SYN invalidates the continuation and starts a fresh epoch. */
bool fk_compact_flow_table_demote_terminal_core(
    struct fk_compact_flow_table *table,
    struct fk_compact_flow_handle handle,
    uint64_t timestamp_ns,
    bool *demoted);

/* Copy the immutable presentation owner identity and current counters for one
 * exact live generation. This owner-scoped audit read never performs a
 * five-tuple lookup or admits state, and it never accepts a stale slot index
 * without the matching generation. */
bool fk_compact_flow_table_snapshot(
    const struct fk_compact_flow_table *table,
    struct fk_compact_flow_handle handle,
    struct fk_compact_flow_snapshot *snapshot);

bool fk_compact_flow_table_update(
    struct fk_compact_flow_table *table,
    struct fk_compact_flow_handle handle,
    uint8_t direction,
    uint32_t wire_size,
    uint64_t timestamp_ns,
    struct fk_compact_flow_snapshot *snapshot);

/* Per-observation evidence bootstrap controls.  Zero is intentionally the
 * strict CORE-only mode: it updates only the mandatory FlowTable entry and
 * BOOTSTRAP prefix.  Existing callers retain the historical behavior through
 * fk_compact_flow_table_observe_packet(), which enables provisional TLS. */
enum fk_compact_observation_flags {
    FK_COMPACT_OBSERVE_PROVISIONAL_TLS = 1u << 0,
    /* Valid only after the flow has consumed its final configured causal
     * checkpoint.  Mandatory CORE/lifecycle state is still updated exactly;
     * optional evidence that no future request can read is left unchanged. */
    FK_COMPACT_OBSERVE_ELIDE_OPTIONAL_AFTER_FINAL_CHECKPOINT = 1u << 1,
};

bool fk_compact_flow_table_observe_packet_with_flags(
    struct fk_compact_flow_table *table,
    struct fk_compact_flow_handle handle,
    uint8_t canonical_direction,
    const struct fk_packet_view *view,
    uint64_t timestamp_ns,
    uint32_t observation_flags,
    fk_tls_hello_callback callback,
    void *callback_user,
    struct fk_compact_flow_snapshot *snapshot);

/* Hot-path equivalent of an ELIDE_OPTIONAL observation after the owning
 * runtime has already advanced every optional deadline through timestamp_ns.
 * It is accepted only for a live generation whose final checkpoint has
 * completed.  Mandatory CORE counters, direction, timestamp, bootstrap and
 * TCP epoch/terminal state remain exact; no optional slab or snapshot key is
 * touched. */
bool fk_compact_flow_table_observe_prepared_final_tail_packet(
    struct fk_compact_flow_table *table,
    struct fk_compact_flow_handle handle,
    uint8_t canonical_direction,
    const struct fk_packet_view *view,
    uint64_t timestamp_ns,
    uint8_t *first_canonical_direction);

#define FK_COMPACT_FINAL_TAIL_BATCH_MAX 128u

struct fk_compact_final_tail_observation {
    uint64_t timestamp_ns;
    uint32_t wire_size;
    uint32_t payload_size;
    uint32_t tcp_sequence;
    uint8_t canonical_direction;
    uint8_t l4_protocol;
    uint8_t tcp_flags;
    uint8_t payload_truncated;
};

/* Associative summary of post-final-checkpoint CORE-only observations.  It
 * is intentionally independent of transport packet storage so RX pumps can
 * coalesce an elephant flow before the owner handoff. */
struct fk_compact_final_tail_delta {
    uint64_t first_timestamp_ns;
    uint64_t last_timestamp_ns;
    uint64_t wire_bytes;
    uint64_t payload_truncated_frames;
    uint32_t packet_count;
    uint32_t canonical_direction_packets[2];
    uint16_t maximum_wire_size;
    uint8_t l4_protocol;
    uint8_t tcp_ack_observed;
    uint8_t tcp_fin_canonical_mask;
    uint8_t tcp_rst_observed;
    uint8_t reserved[4];
};

/* Apply a bounded run of already parsed observations to one exact live
 * post-final generation.  The caller must first prove that semantic time can
 * advance through the last timestamp without an optional deadline or idle
 * scan.  The implementation validates the complete batch before its single
 * CORE commit, so rejection never partially updates the generation. */
bool fk_compact_flow_table_observe_prepared_final_tail_batch(
    struct fk_compact_flow_table *table,
    struct fk_compact_flow_handle handle,
    const struct fk_compact_final_tail_observation *observations,
    uint32_t count,
    uint8_t *first_canonical_direction);

bool fk_compact_flow_table_apply_prepared_final_tail_delta(
    struct fk_compact_flow_table *table,
    struct fk_compact_flow_handle handle,
    const struct fk_compact_final_tail_delta *delta,
    uint8_t *first_canonical_direction);

/* Exact negative gate used by the runtime batch proof.  A true result means
 * fk_compact_flow_table_expire_idle() would return at its no-scan gate for
 * every nondecreasing timestamp through timestamp_ns. */
bool fk_compact_flow_table_idle_scan_gated_through(
    const struct fk_compact_flow_table *table,
    uint64_t timestamp_ns);

bool fk_compact_flow_table_idle_scan_not_before(
    const struct fk_compact_flow_table *table,
    uint64_t *timestamp_ns);

bool fk_compact_flow_table_observe_packet(
    struct fk_compact_flow_table *table,
    struct fk_compact_flow_handle handle,
    uint8_t canonical_direction,
    const struct fk_packet_view *view,
    uint64_t timestamp_ns,
    fk_tls_hello_callback callback,
    void *callback_user,
    struct fk_compact_flow_snapshot *snapshot);

struct fk_component_flow *fk_compact_flow_table_component_flow(
    struct fk_compact_flow_table *table,
    struct fk_compact_flow_handle handle);

bool fk_compact_flow_table_resident_component_mask(
    const struct fk_compact_flow_table *table,
    struct fk_compact_flow_handle handle,
    uint8_t *resident_mask);

/* Read the immutable semantic routing identity of an exact live generation.
 * This is audit metadata only and is never exposed as a detector feature. */
bool fk_compact_flow_table_logical_connection_id(
    const struct fk_compact_flow_table *table,
    struct fk_compact_flow_handle handle,
    uint64_t *logical_connection_id);

/* Atomically publish the latest causal-checkpoint value vector and rebuild
 * every value-replacement heap key derived from it. */
bool fk_compact_flow_table_refresh_action_values(
    struct fk_compact_flow_table *table,
    struct fk_compact_flow_handle handle,
    const float action_values[8]);

/* Atomically publish physical-residency causal transition potentials. */
bool fk_compact_flow_table_refresh_transition_values(
    struct fk_compact_flow_table *table,
    struct fk_compact_flow_handle handle,
    const float transition_potentials[8]);

bool fk_compact_flow_table_bootstrap(
    const struct fk_compact_flow_table *table,
    struct fk_compact_flow_handle handle,
    struct fk_compact_bootstrap_state *bootstrap);

bool fk_compact_flow_table_action_features(
    const struct fk_compact_flow_table *table,
    struct fk_compact_flow_handle handle,
    const struct fk_packet_view *current_packet,
    enum fk_pressure_mode pressure,
    float features[FK_COMPACT_ACTION_FEATURES]);

void fk_compact_flow_table_component_bytes(
    struct fk_component_bytes *bytes);

/*
 * Return the optional components that can be materialized without a slab
 * allocation failure at this instant. Components already owned by the flow
 * are always included. Each shard has one owner, so this result remains valid
 * through the immediately following checkpoint transition.
 */
bool fk_compact_flow_table_materializable_mask(
    const struct fk_compact_flow_table *table,
    struct fk_compact_flow_handle handle,
    uint8_t *mask);

/*
 * Materialize the payload storage represented by component_flow->mask.
 * Call this immediately after a successful controller transition. Existing
 * evidence common to the old and new masks is retained across downgrades.
 */
bool fk_compact_flow_table_sync_components(
    struct fk_compact_flow_table *table,
    struct fk_compact_flow_handle handle);

/* Timestamped compatibility form used by tests/offline migration tools.
 * Production controllers use commit_atomic_transition().  Any physical
 * release performed here is still emitted at the caller's exact causal
 * packet/time instead of being an untracked split sync. */
bool fk_compact_flow_table_sync_components_at(
    struct fk_compact_flow_table *table,
    struct fk_compact_flow_handle handle,
    uint32_t causing_packet_count,
    uint64_t timestamp_ns);

/* Release all optional evidence owned by the least-recently-used live flow
 * that can satisfy at least one bit in required_mask. The protected flow is
 * never selected. Ties are resolved by slot index, making replay exact. */
bool fk_compact_flow_table_release_lru_optional(
    struct fk_compact_flow_table *table,
    struct fk_compact_flow_handle protected_handle,
    uint8_t required_mask,
    struct fk_compact_flow_handle *released_handle,
    uint8_t *released_mask);

/* Construct a complete fixed-capacity victim plan, validate typed-pool and
 * total-budget feasibility plus hysteresis, then commit all victim releases.
 * No resident is changed on VALUE_REJECTED/NO_PLAN/TRACE_FULL. */
enum fk_compact_value_replacement_status
fk_compact_flow_table_commit_value_replacement(
    struct fk_compact_flow_table *table,
    struct fk_compact_flow_handle incoming_handle,
    uint8_t desired_mask,
    uint32_t causing_packet_count,
    uint64_t timestamp_ns,
    struct fk_compact_value_replacement_outcome *outcome);

/* End-to-end atomic logical+typed-storage bind.  On every rejection the
 * incoming flow, all residents, budget ledger, and transition queue remain
 * unchanged.  A successful NOT_NEEDED or COMMITTED result has already
 * installed desired_mask; callers must not invoke a second transition/sync. */
enum fk_compact_value_replacement_status
fk_compact_flow_table_commit_atomic_transition(
    struct fk_compact_flow_table *table,
    struct fk_compact_flow_handle incoming_handle,
    uint8_t desired_mask,
    bool ja4_applicable,
    bool allow_value_replacement,
    uint32_t causing_packet_count,
    uint64_t timestamp_ns,
    const struct fk_component_policy_config *config,
    struct fk_compact_value_replacement_outcome *outcome,
    enum fk_transition_result *transition_result);

/* LRU baseline variant of the same atomic bind.  It plans whole-flow LRU
 * releases but does not expose any victim mutation unless the incoming state
 * can be bound in the same commit. */
enum fk_compact_value_replacement_status
fk_compact_flow_table_commit_atomic_lru_transition(
    struct fk_compact_flow_table *table,
    struct fk_compact_flow_handle incoming_handle,
    uint8_t desired_mask,
    bool ja4_applicable,
    uint32_t maximum_victim_flows,
    uint32_t causing_packet_count,
    uint64_t timestamp_ns,
    const struct fk_component_policy_config *config,
    struct fk_compact_value_replacement_outcome *outcome,
    enum fk_transition_result *transition_result);

/* LFU/FIFO whole-flow baselines use the identical atomic byte-budget and
 * typed-pool transaction as LRU; only the deterministic victim order differs.
 * LFU orders by observed packet count, then admission time and slot. FIFO
 * orders by admission time, then slot. */
enum fk_compact_value_replacement_status
fk_compact_flow_table_commit_atomic_lfu_transition(
    struct fk_compact_flow_table *table,
    struct fk_compact_flow_handle incoming_handle,
    uint8_t desired_mask,
    bool ja4_applicable,
    uint32_t maximum_victim_flows,
    uint32_t causing_packet_count,
    uint64_t timestamp_ns,
    const struct fk_component_policy_config *config,
    struct fk_compact_value_replacement_outcome *outcome,
    enum fk_transition_result *transition_result);

enum fk_compact_value_replacement_status
fk_compact_flow_table_commit_atomic_fifo_transition(
    struct fk_compact_flow_table *table,
    struct fk_compact_flow_handle incoming_handle,
    uint8_t desired_mask,
    bool ja4_applicable,
    uint32_t maximum_victim_flows,
    uint32_t causing_packet_count,
    uint64_t timestamp_ns,
    const struct fk_component_policy_config *config,
    struct fk_compact_value_replacement_outcome *outcome,
    enum fk_transition_result *transition_result);

/* Seeded-random whole-flow baseline.  Candidate eligibility, typed-pool
 * financing, byte-budget accounting, and commit atomicity are identical to
 * LRU/LFU/FIFO.  Only the victim ordering is a stateless hash of the frozen
 * seed and causal conflict context. */
enum fk_compact_value_replacement_status
fk_compact_flow_table_commit_atomic_seeded_random_transition(
    struct fk_compact_flow_table *table,
    struct fk_compact_flow_handle incoming_handle,
    uint8_t desired_mask,
    bool ja4_applicable,
    uint32_t maximum_victim_flows,
    uint64_t deterministic_seed,
    uint32_t causing_packet_count,
    uint64_t timestamp_ns,
    const struct fk_component_policy_config *config,
    struct fk_compact_value_replacement_outcome *outcome,
    enum fk_transition_result *transition_result);

/* Native retention-policy baselines over the same irreversible optional
 * evidence bundles. CLOCK uses a persistent second-chance hand; 2Q uses a
 * scan-resistant A1/Am split; ARC maintains T1/T2 plus B1/B2 ghost feedback;
 * GDSF uses frequency/retained-byte priority with global aging. */
enum fk_compact_value_replacement_status
fk_compact_flow_table_commit_atomic_clock_transition(
    struct fk_compact_flow_table *table,
    struct fk_compact_flow_handle incoming_handle,
    uint8_t desired_mask,
    bool ja4_applicable,
    uint32_t maximum_victim_flows,
    uint32_t causing_packet_count,
    uint64_t timestamp_ns,
    const struct fk_component_policy_config *config,
    struct fk_compact_value_replacement_outcome *outcome,
    enum fk_transition_result *transition_result);

enum fk_compact_value_replacement_status
fk_compact_flow_table_commit_atomic_two_q_transition(
    struct fk_compact_flow_table *table,
    struct fk_compact_flow_handle incoming_handle,
    uint8_t desired_mask,
    bool ja4_applicable,
    uint32_t maximum_victim_flows,
    uint32_t causing_packet_count,
    uint64_t timestamp_ns,
    const struct fk_component_policy_config *config,
    struct fk_compact_value_replacement_outcome *outcome,
    enum fk_transition_result *transition_result);

enum fk_compact_value_replacement_status
fk_compact_flow_table_commit_atomic_arc_transition(
    struct fk_compact_flow_table *table,
    struct fk_compact_flow_handle incoming_handle,
    uint8_t desired_mask,
    bool ja4_applicable,
    uint32_t maximum_victim_flows,
    uint32_t causing_packet_count,
    uint64_t timestamp_ns,
    const struct fk_component_policy_config *config,
    struct fk_compact_value_replacement_outcome *outcome,
    enum fk_transition_result *transition_result);

enum fk_compact_value_replacement_status
fk_compact_flow_table_commit_atomic_gdsf_transition(
    struct fk_compact_flow_table *table,
    struct fk_compact_flow_handle incoming_handle,
    uint8_t desired_mask,
    bool ja4_applicable,
    uint32_t maximum_victim_flows,
    uint32_t causing_packet_count,
    uint64_t timestamp_ns,
    const struct fk_component_policy_config *config,
    struct fk_compact_value_replacement_outcome *outcome,
    enum fk_transition_result *transition_result);

/* Quiescent configuration hook.  Tables start with the frozen formal
 * defaults eta=.05, epsilon=1e-6, max_victims=64. */
bool fk_compact_flow_table_set_value_eviction_config(
    struct fk_compact_flow_table *table,
    const struct fk_compact_value_eviction_config *config);

/* Bind optional cache-policy metadata before the first flow is admitted. */
bool fk_compact_flow_table_set_retention_metadata_mode(
    struct fk_compact_flow_table *table,
    enum fk_compact_retention_metadata_mode mode);

/* Install the Fixed-TTL semantic expiry from the flow's first timestamp.
 * Once installed it may only move earlier, never later. */
bool fk_compact_flow_table_set_fixed_ttl(
    struct fk_compact_flow_table *table,
    struct fk_compact_flow_handle handle,
    uint64_t fixed_ttl_ns);

bool fk_compact_flow_table_apply_due_timer(
    struct fk_compact_flow_table *table,
    struct fk_compact_flow_handle handle,
    uint64_t timestamp_ns,
    uint32_t causing_packet_count,
    bool *expired);

/* Exact semantic boundary discovery.  Returns the earliest live
 * optional-state deadline in [after_ns, target_ns] from the per-shard
 * incremental heap.  Query is O(1); admission/deadline/release maintenance
 * is O(log resident_optional_flows), with no table rebuild.  The caller can
 * account residency to that boundary, release there, drain traces, then
 * continue. */
bool fk_compact_flow_table_next_optional_timer_deadline(
    const struct fk_compact_flow_table *table,
    uint64_t after_ns,
    uint64_t target_ns,
    uint64_t *deadline_ns);

/* Bounded periodic maintenance for flows that receive no new checkpoint.
 * Lease/FixedTTL expiry releases all optional evidence; pressure releases
 * the lowest-density component of an idle resident. */
uint32_t fk_compact_flow_table_scan_optional_timers(
    struct fk_compact_flow_table *table,
    uint64_t timestamp_ns,
    enum fk_pressure_mode pressure,
    const struct fk_compact_timer_config *config,
    struct fk_compact_flow_handle causing_handle,
    uint32_t causing_packet_count,
    uint32_t scan_limit);

/* Single-owner bounded transition queue.  The controller/trace composition
 * path should drain after each decision/timer tick; commits fail closed when
 * the queue cannot hold a complete atomic plan. */
size_t fk_compact_flow_table_drain_evidence_transitions(
    struct fk_compact_flow_table *table,
    struct fk_compact_evidence_transition *transitions,
    size_t capacity);

struct fk_compact_stat_state *fk_compact_flow_table_stat(
    struct fk_compact_flow_table *table,
    struct fk_compact_flow_handle handle);

struct fk_compact_seq_state *fk_compact_flow_table_seq(
    struct fk_compact_flow_table *table,
    struct fk_compact_flow_handle handle);

struct fk_compact_tls_flow *fk_compact_flow_table_tls(
    struct fk_compact_flow_table *table,
    struct fk_compact_flow_handle handle);

struct fk_compact_ja4_state *fk_compact_flow_table_ja4(
    struct fk_compact_flow_table *table,
    struct fk_compact_flow_handle handle);

bool fk_compact_flow_table_release(
    struct fk_compact_flow_table *table,
    struct fk_compact_flow_handle handle);

uint32_t fk_compact_flow_table_expire_idle(
    struct fk_compact_flow_table *table,
    uint64_t timestamp_ns,
    uint64_t idle_timeout_ns,
    uint32_t scan_limit);

struct fk_state_budget *fk_compact_flow_table_budget(
    struct fk_compact_flow_table *table);

bool fk_compact_flow_table_get_stats(
    const struct fk_compact_flow_table *table,
    struct fk_compact_flow_table_stats *stats);

/* Cold/quiescent counter conservation.  It does not walk the free list. */
bool fk_compact_flow_table_slot_accounting_conserved(
    const struct fk_compact_flow_table *table);

#ifdef FK_COMPACT_FLOW_TABLE_TEST_HOOKS
/* Unit-test fault injection; absent from production builds. */
enum fk_compact_atomic_fault_point {
    FK_COMPACT_ATOMIC_FAULT_NONE = 0,
    FK_COMPACT_ATOMIC_FAULT_AFTER_FLOW_PLAN = 1,
    FK_COMPACT_ATOMIC_FAULT_AFTER_VICTIM_PLAN = 2,
    FK_COMPACT_ATOMIC_FAULT_BEFORE_STORAGE_PREPARE = 3,
    FK_COMPACT_ATOMIC_FAULT_AFTER_STORAGE_PREPARE = 4,
    FK_COMPACT_ATOMIC_FAULT_BEFORE_BUDGET_COMMIT = 5,
};

bool fk_compact_flow_table_test_set_free_head_generation(
    struct fk_compact_flow_table *table,
    uint32_t generation);

bool fk_compact_flow_table_test_set_atomic_fault_point(
    struct fk_compact_flow_table *table,
    enum fk_compact_atomic_fault_point point);

bool fk_compact_flow_table_test_full_optional_index_bytes(
    uint32_t maximum_flows,
    uint64_t *bytes);

/* Exercises one packed narrow deadline slot while proving the colocated
 * value-index half-word is unchanged; restores the original word. */
bool fk_compact_flow_table_test_narrow_deadline_slot_round_trip(
    struct fk_compact_flow_table *table,
    uint32_t logical_position,
    uint32_t core_index);
#endif

void fk_compact_flow_table_budget_snapshot(
    const struct fk_compact_flow_table *table,
    struct fk_budget_snapshot *snapshot);


/* Restore into a NEW handle, without evicting a live flow or exceeding its
 * existing controlled budget. Caller rebinds identity only after success. */
bool fk_compact_flow_table_restore_cold(
    struct fk_compact_flow_table *table,
    const struct fk_compact_flow_snapshot *snapshot,
    const struct fk_compact_core_state *core,
    const struct fk_compact_stat_state *stat,
    const struct fk_compact_seq_state *seq,
    const struct fk_compact_ja4_state *ja4, bool full_tls,
    struct fk_compact_flow_handle *restored_handle);

enum fk_compact_persist_reason {
    FK_COMPACT_PERSIST_COMPONENT_RELEASE=1,
    FK_COMPACT_PERSIST_CORE_RETIRE=2,
    FK_COMPACT_PERSIST_TLS_COMPACTION=3,
    FK_COMPACT_PERSIST_SHUTDOWN=4,
    FK_COMPACT_PERSIST_COMPATIBILITY=5,
};
struct fk_compact_lifecycle_guard {
    void *context;
    bool (*persist)(void *context, struct fk_compact_flow_table *table,
        struct fk_compact_flow_handle handle, uint8_t resident_mask,
        enum fk_compact_persist_reason reason);
};
enum fk_compact_idle_retirement_result {
    FK_COMPACT_IDLE_RETIRE_DEFERRED = 1,
    FK_COMPACT_IDLE_RETIRE_RETRY = 2,
    FK_COMPACT_IDLE_RETIRE_FAILED = 3,
};
/* Optional non-owning idle writer. Accepted deferral keeps the original Core
 * and all budget charges until the normal release guard confirms durability.
 * Only ordinary, physically Core-only, fully released epochs are eligible.
 * Callbacks run on the exclusive owner and must outlive the table. */
struct fk_compact_idle_retirement_guard {
    void *context;
    uint64_t metadata_bytes;
    enum fk_compact_idle_retirement_result (*defer)(void *context,
        struct fk_compact_flow_table *table,struct fk_compact_flow_handle handle);
    bool (*poll)(void *context,struct fk_compact_flow_table *table,bool drain_all);
    /* Optional lookahead within an already known target timestamp. It may
     * queue immutable snapshots but cannot release or mutate table state. */
    bool (*prepare_optional)(void *context,struct fk_compact_flow_table *table,
        uint64_t target_ns);
};
/* Read-only earliest due optional handles, at most 64. No heap mutation. */
bool fk_compact_flow_table_due_optional_batch(
    const struct fk_compact_flow_table *table,uint64_t target_ns,
    struct fk_compact_flow_handle *handles,uint32_t capacity,uint32_t *count);
bool fk_compact_flow_table_prepare_due_optional(
    struct fk_compact_flow_table *table,uint64_t target_ns);
bool fk_compact_flow_table_attach_idle_retirement_guard(
    struct fk_compact_flow_table *table,
    const struct fk_compact_idle_retirement_guard *guard);
bool fk_compact_flow_table_poll_idle_retirements(
    struct fk_compact_flow_table *table,bool drain_all);
uint32_t fk_compact_flow_table_pending_idle_retirements(
    const struct fk_compact_flow_table *table);
/* Attach before admission. Non-owning callback remains live until destroy.
 * Callback may read/export but never mutate or re-enter this table. */
bool fk_compact_flow_table_attach_lifecycle_guard(
    struct fk_compact_flow_table *table,
    const struct fk_compact_lifecycle_guard *guard);
/* Persist every active Core/evidence record before destructive cleanup.
 * False retains the live table; caller must not report successful shutdown. */
bool fk_compact_flow_table_prepare_shutdown(struct fk_compact_flow_table *table);

/* Opt-in guarded atomic entry. Existing APIs and frozen table layout remain
 * unchanged. Guard sees the entire release plan before any slab or budget
 * transfer. It must not throw or mutate this flow table. False defers the
 * transaction; it may enqueue immutable snapshots in an external queue.
 * A true answer must be repeatable if a later allocation/fault aborts the
 * operation: retain durable content IDs until the caller observes commit. */
enum fk_compact_persistent_policy {
    FK_COMPACT_PERSISTENT_FLOWKEEP=0, FK_COMPACT_PERSISTENT_LRU=1,
    FK_COMPACT_PERSISTENT_CLOCK=2, FK_COMPACT_PERSISTENT_TWO_Q=3,
    FK_COMPACT_PERSISTENT_FIFO=4, FK_COMPACT_PERSISTENT_NO_REPLACEMENT=5
};
/* Physical JA4 view for persistence, including provisional pre-decision TLS.
 * Unlike detector accessors this must not be used to claim available features. */
const struct fk_compact_ja4_state *fk_compact_flow_table_resident_ja4(
    struct fk_compact_flow_table *table, struct fk_compact_flow_handle handle,
    bool *full_tls);

struct fk_compact_release_request {
    struct fk_compact_flow_handle handle;
    uint8_t mask;
};
struct fk_compact_release_guard {
    void *context;
    bool (*authorize)(void *, const struct fk_compact_release_request *, size_t);
};
enum fk_compact_value_replacement_status
fk_compact_flow_table_commit_persistent_transition(
    struct fk_compact_flow_table *table, struct fk_compact_flow_handle incoming,
    uint8_t desired_mask, bool ja4_applicable,
    enum fk_compact_persistent_policy policy, uint32_t maximum_victim_flows,
    uint32_t packet_count, uint64_t timestamp_ns,
    const struct fk_component_policy_config *config,
    const struct fk_compact_release_guard *guard,
    struct fk_compact_value_replacement_outcome *outcome,
    enum fk_transition_result *transition_result);

#ifdef __cplusplus
}
#endif

#endif
