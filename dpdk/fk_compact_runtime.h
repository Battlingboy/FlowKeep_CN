#ifndef FLOWKEEP_FK_COMPACT_RUNTIME_H
#define FLOWKEEP_FK_COMPACT_RUNTIME_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "fk_compact_controller.h"
#include "fk_ja4_identity_features.h"

#ifdef __cplusplus
extern "C" {
#endif

struct fk_compact_runtime;
/* Opt-in candidate: one real Core-prefix detection at packet 1, independently
 * of the unmodified 4/8/12/20 retention schedule. No optional evidence is
 * acquired, no label is inferred from FLOW_OPEN, and no timer is invented.
 * Enable before ownership/ingress. Production promotion requires measuring
 * the extra inference cost and changed alert history with the frozen model. */
bool fk_compact_runtime_enable_first_packet_coverage(
    struct fk_compact_runtime *runtime);
bool fk_compact_runtime_enable_eof_coverage_deposit(struct fk_compact_runtime *runtime);
/* Detector-only candidate snapshots. Component checkpoints and their LRU /
 * release actions remain unchanged. */
bool fk_compact_runtime_enable_adaptive_detection_candidates(
    struct fk_compact_runtime *runtime, uint32_t first_packet,
    uint32_t near_gap, uint32_t far_gap, uint32_t horizon_packet);
/* Marginal scheduler transport: publish each causal prefix up to the horizon
 * so the service can execute only its predicted NEXT positions.  No fixed
 * first point or near/far lattice is embedded in this mode. */
bool fk_compact_runtime_enable_marginal_detection_candidates(
    struct fk_compact_runtime *runtime, uint32_t horizon_packet);
uint64_t fk_compact_runtime_first_packet_coverage_requests(
    const struct fk_compact_runtime *runtime);
/* Opt-in online checkpoint guard. Attach before the first packet. Callback
 * runs on the exclusive owner, must finish durability before returning true,
 * and must not re-enter the runtime. False aborts the packet checkpoint.
 * This hook alone does not cover expiration/retirement/shutdown release. */
bool fk_compact_runtime_attach_checkpoint_release_guard(
    struct fk_compact_runtime *runtime,
    const struct fk_compact_release_guard *guard);

#define FK_COMPACT_RUNTIME_IDENTITY_ABI_VERSION 2u

enum fk_compact_action_value_model_kind {
    FK_COMPACT_ACTION_VALUE_LEGACY_30D =
        FK_CPU_PIPELINE_ACTION_LEGACY_30D,
    FK_COMPACT_ACTION_VALUE_V3_64D =
        FK_CPU_PIPELINE_ACTION_VALUE_V3_64D,
    FK_COMPACT_ACTION_VALUE_NONE =
        FK_CPU_PIPELINE_ACTION_NONE,
};

enum fk_compact_runtime_api_mode {
    FK_COMPACT_RUNTIME_API_MODE_UNSET = 0,
    FK_COMPACT_RUNTIME_API_MODE_V1_ZERO_ID = 1,
    FK_COMPACT_RUNTIME_API_MODE_V2_EXPLICIT_ID = 2,
};

enum fk_compact_runtime_result {
    FK_COMPACT_RUNTIME_OBSERVED = 0,
    FK_COMPACT_RUNTIME_IGNORED = 1,
    FK_COMPACT_RUNTIME_ADMISSION_REJECTED = 2,
    FK_COMPACT_RUNTIME_STATE_FAILED = 3,
    FK_COMPACT_RUNTIME_STALE_BOUND_HANDLE = 4,
};

enum fk_compact_runtime_flow_release_result {
    FK_COMPACT_RUNTIME_FLOW_RELEASE_INVALID = 0,
    FK_COMPACT_RUNTIME_FLOW_RELEASE_RELEASED = 1,
    FK_COMPACT_RUNTIME_FLOW_RELEASE_ALREADY_ABSENT = 2,
    FK_COMPACT_RUNTIME_FLOW_RELEASE_TIME_REGRESSION = 3,
    FK_COMPACT_RUNTIME_FLOW_RELEASE_FAILED = 4,
};

#define FK_COMPACT_DETECTOR_FEATURES_MAX \
    FK_COMPACT_DETECTOR_FEATURES_V4
#define FK_COMPACT_DETECTOR_COMPONENT_START_BASE 116u

/*
 * Opaque ingress routing metadata.  Zero is the ordinary TCP/TLS identity;
 * non-zero values are allocated and validated by the QUIC CID directory.
 * The compact runtime never derives this value from a presentation 5-tuple.
 */
struct fk_compact_runtime_ingress_identity_v2 {
    uint64_t logical_connection_id;
};

struct fk_compact_detection_request {
    struct fk_flow_key key;
    uint64_t flow_first_timestamp_ns;
    uint64_t observation_timestamp_ns;
    uint64_t packet_count;
    uint32_t feature_count;
    uint32_t flow_index;
    uint32_t flow_generation;
    uint8_t component_mask;
    uint8_t observation_complete;
    uint8_t checkpoint_packet;
    uint8_t reserved;
    float features[FK_COMPACT_DETECTOR_FEATURES_MAX];
};

typedef bool (*fk_compact_prefix_callback)(
    void *context, const struct fk_compact_detection_request *request,
    bool terminal_observed, bool standard_checkpoint);
bool fk_compact_runtime_attach_prefix_callback(
    struct fk_compact_runtime *runtime,
    fk_compact_prefix_callback callback, void *context);
/* Offline/development trajectory collector. The legacy attachment above is
 * intentionally fixed at packet 20. This explicit variant permits a larger
 * observation horizon without changing runtimes that do not opt in. */
bool fk_compact_runtime_attach_prefix_callback_until(
    struct fk_compact_runtime *runtime,
    fk_compact_prefix_callback callback, void *context,
    uint32_t maximum_packet);

/* ABI-v2 routing envelope.  logical_connection_id is not a model feature. */
struct fk_compact_detection_request_v2 {
    struct fk_compact_detection_request presentation;
    uint64_t logical_connection_id;
};

enum fk_compact_flow_control_kind {
    /* First presentation generation of a new semantic flow instance. */
    FK_COMPACT_FLOW_CONTROL_OPEN = 1,
    /* New resident presentation generation after bounded capacity eviction;
     * the original first timestamp and checkpoint cursor are preserved. */
    FK_COMPACT_FLOW_CONTROL_CONTINUE = 2,
};

/*
 * Immutable one-shot control for a newly admitted presentation generation.
 * OPEN is emitted after the semantic flow's first packet. CONTINUE is emitted
 * after the first packet processed by a replacement resident generation. No
 * detector features are copied into either control record.
 */
struct fk_compact_flow_open_observation {
    struct fk_flow_key key;
    uint64_t flow_first_timestamp_ns;
    uint64_t observation_timestamp_ns;
    uint32_t flow_index;
    uint32_t flow_generation;
    uint32_t predecessor_flow_index;
    uint32_t predecessor_flow_generation;
    uint32_t predecessor_checkpoint_packet;
    uint8_t control_kind;
    uint8_t reserved[3];
    uint32_t coverage_prefix_present;
    float coverage_prefix[159];
};

struct fk_compact_flow_open_observation_v2 {
    struct fk_compact_flow_open_observation presentation;
    uint64_t logical_connection_id;
};

/*
 * Identity returned synchronously to a fixed-owner ingress transaction.
 * handle_available becomes one immediately after an admission or supplied
 * bound handle has been proven live.  If created is also one, that exact
 * generation was allocated by this call and remains a cleanup obligation
 * even when the call later returns STATE_FAILED.  valid becomes one only
 * when the complete runtime call returns OBSERVED; therefore a failure may
 * legitimately return handle_available=1, created=1, valid=0.  This is
 * deliberately separate from FLOW_OPEN and never treats cleanup identity as
 * a successful packet observation.
 */
struct fk_compact_runtime_flow_identity {
    struct fk_flow_key presentation_key;
    struct fk_compact_flow_handle handle;
    uint8_t first_canonical_direction;
    uint8_t created;
    uint8_t valid;
    uint8_t handle_available;
};

struct fk_compact_runtime_flow_identity_v2 {
    struct fk_compact_runtime_flow_identity presentation;
    uint64_t logical_connection_id;
};

/*
 * Audit result for the packet-once bound path.  The three terminal path
 * flags are mutually exclusive when identity.valid is one:
 *
 *   used_bound_handle  the supplied generation was live;
 *   rebound_existing   it was stale and the current five-tuple found an
 *                      already-live presentation flow;
 *   readmitted         it was stale and the current five-tuple admitted a
 *                      new presentation-flow generation.
 *
 * stale_bound_handle records that recovery was attempted even when lookup or
 * admission fails.  In that case identity remains all-zero/invalid.
 */
struct fk_compact_runtime_packet_once_outcome {
    struct fk_compact_runtime_flow_identity identity;
    uint8_t used_bound_handle;
    uint8_t stale_bound_handle;
    uint8_t rebound_existing;
    uint8_t readmitted;
    /* Exact negative receipts for the owner hot path.  These are set only
     * when the runtime proves that polling the corresponding output queues
     * would be empty after this packet. */
    uint8_t no_pending_outputs;
    uint8_t no_pending_evidence_transitions;
    uint8_t reserved[2];
};

struct fk_compact_runtime_packet_once_outcome_v2 {
    struct fk_compact_runtime_flow_identity_v2 identity;
    uint8_t used_bound_handle;
    uint8_t stale_bound_handle;
    uint8_t rebound_existing;
    uint8_t readmitted;
    uint8_t no_pending_outputs;
    uint8_t no_pending_evidence_transitions;
    uint8_t reserved[2];
};

struct fk_compact_action_record {
    struct fk_flow_key key;
    uint64_t observation_timestamp_ns;
    uint64_t packet_count;
    uint64_t controlled_bytes_before;
    uint64_t controlled_bytes_after;
    float selected_utility;
    uint8_t pressure;
    uint8_t previous_mask;
    /* The value policy's requested logical action inside the trained protocol
     * domain. Typed-pool capacity, budget feasibility, or an irreversible
     * release can make final_mask a strict subset of this request. */
    uint8_t selected_mask;
    uint8_t protocol_applicable_mask;
    /* The physically retained component mask after the transition. */
    uint8_t final_mask;
    uint8_t released_mask_before;
    uint8_t released_mask_after;
    uint8_t materializable_mask;
    uint8_t pool_unavailable_mask;
    uint8_t observation_complete;
    uint8_t missing_reason[3];
    uint8_t candidates_considered;
    uint8_t budget_rejections;
    uint8_t transition_result;
};

#define FK_COMPACT_CHECKPOINT_INTERVENTION_ABI_VERSION 1u
#define FK_COMPACT_CHECKPOINT_INTERVENTION_MAX_VICTIMS 64u

enum fk_compact_checkpoint_intervention_mode_v1 {
    FK_COMPACT_CHECKPOINT_INTERVENTION_DISABLED = 0,
    /* Reject only the candidate's pressure action by keeping its exact
     * pre-decision resident mask.  No released component may be restored and
     * no alternate victim may be selected. */
    FK_COMPACT_CHECKPOINT_INTERVENTION_KEEP_EXISTING = 1,
};

struct fk_compact_checkpoint_intervention_victim_v1 {
    struct fk_flow_key key;
    uint64_t logical_connection_id;
    uint64_t flow_first_timestamp_ns;
    uint32_t flow_index;
    uint32_t flow_generation;
    uint8_t expected_previous_mask;
    /* What the unmodified keep-candidate branch physically released to. */
    uint8_t expected_behavior_final_mask;
    /* The one-step keep-victim branch must retain the pre-action mask. */
    uint8_t expected_intervention_final_mask;
    uint8_t reserved[5];
};

/* One immutable Development-only intervention anchor.  source_packet_sequence
 * binds the upstream mixed-replay/FKPLV1 position; the compact runtime binds
 * the independent semantic identity below.  The enclosing no-NIC composition
 * must prove that both refer to the same emitted checkpoint record. */
struct fk_compact_checkpoint_intervention_v1 {
    uint32_t abi_version;
    uint32_t record_bytes;
    uint64_t source_packet_sequence;
    struct fk_flow_key candidate_key;
    uint64_t logical_connection_id;
    uint64_t flow_first_timestamp_ns;
    uint64_t observation_timestamp_ns;
    uint32_t flow_index;
    uint32_t flow_generation;
    uint32_t checkpoint_packet;
    uint32_t victim_count;
    uint8_t expected_previous_mask;
    uint8_t expected_behavior_requested_mask;
    uint8_t expected_behavior_final_mask;
    uint8_t forced_requested_mask;
    uint8_t mode;
    uint8_t enabled;
    uint8_t reserved0[2];
    uint8_t reserved[8];
    struct fk_compact_checkpoint_intervention_victim_v1
        victims[FK_COMPACT_CHECKPOINT_INTERVENTION_MAX_VICTIMS];
};

struct fk_compact_checkpoint_intervention_receipt_v1 {
    uint32_t abi_version;
    uint32_t record_bytes;
    uint64_t source_packet_sequence;
    uint64_t semantic_candidate_matches;
    uint64_t applications;
    uint64_t controller_failures;
    uint64_t identity_mismatches;
    uint64_t target_missed_before_later_timestamp;
    uint64_t trace_checkpoint_matches;
    uint64_t trace_binding_mismatches;
    uint64_t victim_identity_checks;
    uint64_t victim_identity_mismatches;
    uint64_t alternative_victim_releases;
    uint64_t candidate_evidence_allocations;
    uint64_t candidate_evidence_allocation_rejections;
    /* Successful ordinary-policy checkpoint decisions after the one-shot
     * intervention has been consumed.  Zero is valid when the replay ends
     * before another checkpoint; one_shot_disarmed is the immediate state
     * invariant in that case. */
    uint64_t post_intervention_original_policy_decisions;
    uint64_t applied_controlled_bytes_before;
    uint64_t applied_controlled_bytes_after;
    uint32_t flow_index;
    uint32_t flow_generation;
    uint32_t checkpoint_packet;
    uint32_t victim_count;
    uint8_t expected_previous_mask;
    uint8_t expected_behavior_requested_mask;
    uint8_t expected_behavior_final_mask;
    uint8_t forced_requested_mask;
    uint8_t applied_previous_mask;
    uint8_t applied_requested_mask;
    uint8_t applied_final_mask;
    uint8_t mode;
    uint8_t enabled;
    uint8_t complete;
    uint8_t trace_binding_complete;
    uint8_t one_shot_disarmed;
    uint8_t reserved[8];
};

struct fk_compact_runtime_config {
    uint32_t maximum_flows;
    uint64_t controlled_budget_bytes;
    bool full_capacity_state;
    uint64_t idle_timeout_ns;
    uint32_t expiration_scan_per_packet;
    const char *action_value_model_path;
    const char *detector_model_path;
    const char *detector_state_model_paths[8];
    const char *action_schema_sha256;
    const char *detector_schema_sha256;
    struct fk_component_policy_config policy;
    struct fk_compact_baseline_policy_config baseline_policy;
    struct fk_component_pool_weights pool_weights;
    struct fk_resource_costs resource_costs;
    uint8_t automatic_pressure_enabled;
    uint8_t pressure_enter_percent;
    uint8_t overload_enter_percent;
    uint8_t pressure_exit_percent;
    uint8_t overload_exit_percent;
    /* Append-only action-model contract.  Zero preserves the legacy 30D
     * FKMODEL path.  ABI64 requires an exact FKVM3 role (1..4), schema, and
     * artifact SHA-256; no format or role is inferred from the filename. */
    uint8_t action_value_model_kind;
    uint8_t action_value_model_v3_expected_role;
    uint8_t action_value_model_reserved[6];
    const char *action_value_model_sha256;
    /* Optional causal cross-flow replacement head.  All three bindings must
     * be supplied together; it is valid only with the ABI64 learned selector. */
    const char *transition_value_model_path;
    const char *transition_value_schema_sha256;
    const char *transition_value_model_sha256;
    /* Disabled (all-zero) in production and frozen paper measurements.
     * Enabled only by the Development paired-suffix executor. */
    struct fk_compact_checkpoint_intervention_v1 checkpoint_intervention;
    uint8_t cache_initial_value_v3;
};

/* Stable description of the byte denominator used by automatic state
 * pressure.  This is deliberately distinct from the hard total budget:
 * mandatory FlowTable/CORE/lease state is a non-reclaimable floor and does
 * not represent competition between optional evidence choices. */
enum fk_compact_pressure_denominator {
    FK_COMPACT_PRESSURE_DENOMINATOR_NONE = 0,
    FK_COMPACT_PRESSURE_DENOMINATOR_OPTIONAL_EVIDENCE_CAPACITY_BYTES = 1,
    FK_COMPACT_PRESSURE_DENOMINATOR_MAX_OPTIONAL_TYPED_POOL_UTILIZATION = 2,
};

struct fk_compact_runtime_stats {
    uint64_t frames;
    uint64_t parse_ignored;
    uint64_t payload_truncated_frames;
    uint64_t flow_admission_rejects;
    uint64_t state_update_failures;
    uint64_t bound_handle_calls;
    uint64_t bound_handle_successes;
    uint64_t stale_bound_handle_rejects;
    uint64_t bound_handle_other_failures;
    uint64_t packet_once_calls;
    uint64_t packet_once_used_bound_handles;
    uint64_t packet_once_stale_bound_handles;
    uint64_t packet_once_rebound_existing;
    uint64_t packet_once_readmissions;
    uint64_t packet_once_recovery_failures;
    uint64_t post_final_checkpoint_tail_packets;
    uint64_t bound_final_tail_fast_path_packets;
    uint64_t final_tail_batch_calls;
    uint64_t final_tail_batch_packets;
    /* All presentation-generation controls; CONTINUE is the exact subset
     * generated by a successful capacity-continuation restore. */
    uint64_t flow_open_observations_ready;
    uint64_t flow_continue_observations_ready;
    uint64_t flow_open_observations_overwritten;
    uint64_t checkpoint_decisions;
    uint64_t checkpoint_failures;
    uint64_t component_sync_failures;
    uint64_t action_records_ready;
    uint64_t action_records_overwritten;
    uint64_t detection_windows_ready;
    uint64_t detection_windows_overwritten;
    uint64_t detector_calls;
    uint64_t detector_failures;
    uint64_t value_model_calls;
    uint64_t value_model_failures;
    uint64_t value_inference_failures;
    uint64_t value_transition_failures;
    uint64_t value_inference_ns;
    uint64_t detector_inference_ns;
    uint64_t idle_expirations;
    uint64_t optional_timer_scan_calls;
    uint64_t optional_timer_component_releases;
    uint64_t optional_timer_exact_boundaries;
    uint64_t optional_timer_boundary_stalls;
    uint64_t optional_timer_deadline_queries;
    uint64_t optional_timer_deadline_rebuilds;
    uint64_t optional_timer_deadline_probes;
    uint64_t idle_scan_calls;
    uint64_t idle_scan_probes;
    uint64_t idle_scan_gated_calls;
    uint64_t idle_scan_completed_cycles;
    uint64_t fixed_ttl_creation_installs;
    uint64_t fixed_ttl_creation_install_failures;
    uint64_t evidence_transition_drain_calls;
    uint64_t evidence_transition_records_drained;
    uint64_t semantic_time_regressions;
    uint64_t semantic_first_timestamp_ns;
    uint64_t semantic_last_timestamp_ns;
    double controlled_state_byte_seconds;
    double state_byte_seconds_by_component[FK_MEMORY_COMPONENT_COUNT];
    /* Every published checkpoint decision contributes exactly once.  These
     * counters distinguish real optional-state competition from a small
     * configured ceiling that the trace never actually exercises. */
    uint64_t action_selected_mask_counts[8];
    uint64_t action_pool_unavailable_records;
    uint64_t action_pool_unavailable_component_counts[3];
    uint64_t action_budget_rejections;
    uint64_t baseline_lru_victims_released;
    uint64_t baseline_lfu_victims_released;
    uint64_t baseline_fifo_victims_released;
    uint64_t baseline_seeded_random_victims_released;
    uint64_t baseline_clock_victims_released;
    uint64_t baseline_two_q_victims_released;
    uint64_t baseline_arc_victims_released;
    uint64_t baseline_gdsf_victims_released;
    uint64_t automatic_pressure_transitions;
    uint64_t automatic_overload_transitions;
    uint64_t automatic_recovery_transitions;
    uint64_t action_transition_failure_counts[7];
    bool semantic_time_initialized;
    bool semantic_time_complete;
    /* Append-only owner-retirement control accounting. */
    uint64_t bound_flow_release_calls;
    uint64_t bound_flow_releases;
    uint64_t bound_flow_release_already_absent;
    uint64_t bound_flow_release_proven_absent;
    uint64_t bound_flow_release_time_regressions;
    uint64_t bound_flow_release_failures;
    /* Append-only ABI-v2 identity/completeness receipt.  A formal v2 run
     * requires mode V2 and every rejection counter below to remain zero. */
    uint64_t api_mode_rejections;
    uint64_t v2_unproven_existing_rejections;
    uint64_t v2_invalid_logical_protocol_rejections;
    uint32_t identity_abi_version;
    uint8_t identity_api_mode;
    uint8_t identity_receipt_reserved[3];
    /* Explicit ordinary TCP/UDP canonical-key proof accounting.  Calls are
     * conserved exactly as validations + rejections for a mode-valid runtime
     * invocation; a validation says only that the caller-supplied canonical
     * key and zero-id routing domain matched the packet, not that subsequent
     * admission/state processing succeeded. */
    uint64_t v2_canonical_key_proof_calls;
    uint64_t v2_canonical_key_proof_validations;
    uint64_t v2_canonical_key_proof_rejections;
    /* Append-only owner-adapter exclusivity receipt.  It is service metadata,
     * not retained per-flow controlled state. */
    uint64_t owner_adapter_claim_attempts;
    uint64_t owner_adapter_claim_successes;
    uint64_t owner_adapter_claim_rejections;
    uint64_t owner_adapter_validation_calls;
    uint64_t owner_adapter_validation_successes;
    uint64_t owner_adapter_validation_rejections;
    uint16_t owner_adapter_fixed_owner;
    uint8_t owner_adapter_claimed;
    uint8_t owner_adapter_reserved[5];
    /* Append-only owner capability-scope receipt.  Once a runtime is
     * claimed, every public state-changing/process/drain API is closed
     * unless the exact claimed adapter has opened one bounded owner scope.
     * The atomic counters are service metadata, not controlled flow state. */
    uint64_t owner_adapter_scope_begin_calls;
    uint64_t owner_adapter_scope_begin_successes;
    uint64_t owner_adapter_scope_begin_rejections;
    uint64_t owner_adapter_scope_end_calls;
    uint64_t owner_adapter_scope_end_successes;
    uint64_t owner_adapter_scope_end_rejections;
    uint64_t owner_adapter_unscoped_mutation_rejections;
    uint64_t owner_adapter_foreign_scope_mutation_rejections;
    uint8_t owner_adapter_scope_active;
    uint8_t owner_adapter_scope_thread_bound;
    uint8_t owner_adapter_scope_reserved[6];
    /* Append-only ABI64 value-serving receipt.  Context construction occurs
     * once at the packet-4 prefix; later checkpoints reuse the pre-existing
     * per-flow eight-float frozen action vector. */
    uint64_t value_v3_contexts_built;
    uint64_t value_v3_context_failures;
    uint64_t value_v3_inferences;
    uint64_t value_v3_inference_failures;
    uint64_t value_v3_core_zero_violations;
    uint64_t value_v3_protocol_domain_violations;
    /* ABI64 packet-4 action values are immutable per flow.  Later causal
     * checkpoints reuse that vector when no cross-flow transition head is
     * attached, avoiding repeated hot-path model evaluation without adding
     * per-flow state. */
    uint64_t value_v3_cache_hits;
    uint64_t value_v3_cache_misses;
    uint64_t value_v3_inferences_avoided;
    uint64_t transition_value_calls;
    uint64_t transition_value_failures;
    uint64_t transition_value_inference_ns;
    uint64_t transition_value_fallback_attempts;
    uint64_t transition_value_fallback_successes;
    /* Append-only pressure-contract receipt.  The four optional-evidence
     * byte values use the exact slab payload denominator, excluding pool
     * metadata and the mandatory controlled-state floor. */
    uint64_t mandatory_floor_bytes;
    uint64_t optional_evidence_capacity_bytes;
    uint64_t optional_evidence_current_bytes;
    uint64_t optional_evidence_peak_bytes;
    uint8_t automatic_pressure_enabled;
    uint8_t pressure_enter_percent;
    uint8_t pressure_exit_percent;
    uint8_t overload_enter_percent;
    uint8_t overload_exit_percent;
    uint8_t pressure_denominator;
    uint8_t pressure_contract_reserved[2];
    /* Frozen policy values after role-specific configuration resolution.
     * Index order is FK_PRESSURE_NORMAL, FK_PRESSURE_PRESSURE, then
     * FK_PRESSURE_OVERLOAD. */
    uint8_t resolved_policy_maximum_components[3];
    uint8_t resolved_policy_preserve_full_state_in_normal;
    float resolved_policy_minimum_utility[3];
    uint64_t pressure_accounting_failures;
    /* Effective pressure is max(automatic optional-pool pressure, external
     * service/backlog pressure).  These modes make composition auditable. */
    uint8_t current_pressure_mode;
    uint8_t automatic_pressure_mode;
    uint8_t external_pressure_mode;
    uint8_t pressure_composition_reserved[5];
    /* Append-only checkpoint failure partition.  These four counters are the
     * only sites that increment checkpoint_failures, so their sum must equal
     * the legacy aggregate without guessing from downstream symptoms. */
    uint64_t checkpoint_action_feature_failures;
    uint64_t checkpoint_value_context_failures;
    uint64_t checkpoint_controller_failures;
    uint64_t checkpoint_ja4_identity_failures;
    /* Development-only, exact one-shot causal intervention receipt. */
    struct fk_compact_checkpoint_intervention_receipt_v1
        checkpoint_intervention;
};

struct fk_compact_runtime;

/* Pure, non-mutating pressure-accounting validator used by runtime receipts
 * and offline gates.  It rejects nulls, zero capacity, invalid occupancy, zero
 * block sizes, and any per-pool or aggregate uint64 overflow.  Output values
 * are written only on success. */
bool fk_compact_runtime_optional_evidence_utilization_from_stats(
    const struct fk_compact_flow_table_stats *stats,
    uint64_t *current_bytes,
    uint64_t *capacity_bytes);

/* Return the occupancy ratio of the most constrained typed optional-state
 * pool as an exact numerator/denominator pair.  Pressure decisions use this
 * ratio rather than the byte-weighted aggregate: a full STAT or SEQ pool is
 * real allocation pressure even when a large JA4 pool remains mostly empty. */
bool fk_compact_runtime_max_optional_pool_utilization_from_stats(
    const struct fk_compact_flow_table_stats *stats,
    uint64_t *current_slots,
    uint64_t *capacity_slots);

/* Validate the mask/reason shape of one drained evidence record.  Transition
 * masks describe physical evidence residency, including a provisional JA4
 * slab before the first policy decision, so every valid release removes its
 * component from previous_mask exactly once. */
bool fk_compact_runtime_evidence_transition_shape_valid(
    const struct fk_compact_evidence_transition *transition);

struct fk_compact_runtime *fk_compact_runtime_create(
    const struct fk_compact_runtime_config *config,
    char *error,
    size_t error_capacity);

void fk_compact_runtime_destroy(struct fk_compact_runtime *runtime);

/* One-shot runtime ownership claim.  A runtime can belong to exactly one
 * adapter object and fixed owner for its entire lifetime; even the same token
 * cannot reinitialize and erase the run epoch. */
bool fk_compact_runtime_claim_owner_adapter(
    struct fk_compact_runtime *runtime,
    uintptr_t adapter_token,
    uint16_t fixed_owner);

/* Atomic validation used before an adapter touches owner-local runtime state.
 * Rejections are recorded in the runtime receipt without writing adapter
 * memory from the wrong object/thread. */
bool fk_compact_runtime_validate_owner_adapter_and_account(
    struct fk_compact_runtime *runtime,
    uintptr_t adapter_token,
    uint16_t fixed_owner);

/*
 * Open/close the sole bounded mutation scope for the claimed adapter.  The
 * adapter token is a capability: it must be the exact non-zero token used by
 * claim_owner_adapter(), and fixed_owner must match the immutable claim.
 * Scopes cannot nest.  A successful begin must have exactly one successful
 * end on every control path.  While no scope is active, all public packet,
 * drain, release, semantic-time, pressure, and mutable FlowTable APIs fail
 * closed after a claim; an unclaimed standalone runtime remains compatible.
 */
bool fk_compact_runtime_owner_adapter_scope_begin(
    struct fk_compact_runtime *runtime,
    uintptr_t adapter_token,
    uint16_t fixed_owner);

bool fk_compact_runtime_owner_adapter_scope_end(
    struct fk_compact_runtime *runtime,
    uintptr_t adapter_token,
    uint16_t fixed_owner);

/* Immutable receipt gate.  This does not increment validation counters. */
bool fk_compact_runtime_owner_adapter_formal_ready(
    const struct fk_compact_runtime *runtime,
    uintptr_t adapter_token,
    uint16_t fixed_owner);

enum fk_compact_runtime_result fk_compact_runtime_process_frame(
    struct fk_compact_runtime *runtime,
    const uint8_t *frame,
    size_t captured_length,
    uint32_t wire_length,
    uint64_t timestamp_ns);

/*
 * ABI-v2 packet entry points require an explicit ingress identity.  Runtime
 * instances are mode-locked by their first packet API call: v1 (implicit
 * zero) and v2 can never be mixed.  Non-zero existing-generation calls must
 * use a live bound handle returned with the same logical id by the owner
 * binding directory; the pair is the caller proof.  Non-zero ids are valid
 * only on UDP.  Every unbound/stale-recovery lookup hit fails closed: neither
 * an explicit zero id nor a presentation five-tuple is an implicit proof.
 * Ordinary TCP/UDP packets whose fixed owner has already proved the canonical
 * flow key use process_canonical_packet_v2 below.  Alternatively, packet one
 * may use parsed_packet_v2 and retain its returned handle for bound_view_v2.
 * Non-zero initial/stale admissions allocate an unindexed distinct FlowTable
 * generation, so multiple QUIC connections may share one UDP five tuple.
 * Logical identity remains in the already-budgeted owner binding rather than
 * adding an unbudgeted per-FlowTable-slot sidecar.
 */
enum fk_compact_runtime_result fk_compact_runtime_process_frame_v2(
    struct fk_compact_runtime *runtime,
    const uint8_t *frame,
    size_t captured_length,
    uint32_t wire_length,
    uint64_t timestamp_ns,
    const struct fk_compact_runtime_ingress_identity_v2 *ingress_identity);

enum fk_compact_runtime_result fk_compact_runtime_process_view(
    struct fk_compact_runtime *runtime,
    const struct fk_packet_view *view,
    uint64_t timestamp_ns);

enum fk_compact_runtime_result fk_compact_runtime_process_view_v2(
    struct fk_compact_runtime *runtime,
    const struct fk_packet_view *view,
    uint64_t timestamp_ns,
    const struct fk_compact_runtime_ingress_identity_v2 *ingress_identity);

/*
 * Process one ingress packet that was already parsed by the CID/owner stage.
 * Unlike process_view(), this is a packet-bearing entry point: it increments
 * runtime.frames exactly once and advances residency exactly once.  On a
 * successful state observation, identity.valid is one and the returned
 * generation handle refers to the sticky presentation_key in the owning
 * FlowTable shard.  No second lookup or admission is required.
 */
enum fk_compact_runtime_result fk_compact_runtime_process_parsed_packet(
    struct fk_compact_runtime *runtime,
    const struct fk_packet_view *view,
    uint64_t timestamp_ns,
    struct fk_compact_runtime_flow_identity *identity);

/*
 * One-entry owner-local flow cache.  The runtime derives the canonical key
 * exactly once from `view`.  If it equals `cached_key`, the supplied handle
 * is used with packet-once stale-generation recovery; otherwise the packet
 * follows the ordinary lookup/admit path.  In both cases one packet/frame
 * and one semantic-time update are recorded, and `outcome.identity` returns
 * the generation suitable for the caller's next packet.  A null cached_key
 * is an explicit cold miss.  This API changes only lookup work: observation,
 * checkpoints, timers, transitions, and detector outputs remain identical.
 */
enum fk_compact_runtime_result fk_compact_runtime_process_cached_packet(
    struct fk_compact_runtime *runtime,
    const struct fk_packet_view *view,
    const struct fk_flow_key *cached_key,
    struct fk_compact_flow_handle cached_handle,
    uint64_t timestamp_ns,
    struct fk_compact_runtime_packet_once_outcome *outcome,
    bool *cache_hit);

/* Same one-entry cache operation after the owning thread has successfully
 * advanced semantic time to timestamp_ns with
 * fk_compact_runtime_prepare_semantic_time_step().  This avoids a redundant
 * second deadline-index query and permits an exact negative transition
 * receipt on the post-final-checkpoint tail. */
enum fk_compact_runtime_result
fk_compact_runtime_process_prepared_cached_packet(
    struct fk_compact_runtime *runtime,
    const struct fk_packet_view *view,
    const struct fk_flow_key *cached_key,
    struct fk_compact_flow_handle cached_handle,
    uint64_t timestamp_ns,
    struct fk_compact_runtime_packet_once_outcome *outcome,
    bool *cache_hit);

/* Return the first semantic timestamp that cannot be included in a
 * no-timer/no-idle exact final-tail batch for this cached generation. */
enum fk_compact_tail_limit_reason {
    FK_TAIL_LIMIT_READY = 0,
    FK_TAIL_LIMIT_INVALID_REQUEST,
    FK_TAIL_LIMIT_RUNTIME_MODE,
    FK_TAIL_LIMIT_OCCUPANCY_CHANGED,
    FK_TAIL_LIMIT_HANDLE,
    FK_TAIL_LIMIT_CHECKPOINT,
    FK_TAIL_LIMIT_KEY,
    FK_TAIL_LIMIT_IDLE_SCAN,
    FK_TAIL_LIMIT_OPTIONAL_TIMER,
    FK_TAIL_LIMIT_REASON_COUNT
};
/* Same admission predicate, with an optional diagnostic rejection reason. */
bool fk_compact_runtime_final_tail_batch_limit_diagnostic(
    struct fk_compact_runtime *runtime,
    const struct fk_flow_key *cached_key,
    struct fk_compact_flow_handle cached_handle,
    uint64_t *exclusive_timestamp_ns,
    enum fk_compact_tail_limit_reason *reason);

bool fk_compact_runtime_final_tail_batch_limit(
    struct fk_compact_runtime *runtime,
    const struct fk_flow_key *cached_key,
    struct fk_compact_flow_handle cached_handle,
    uint64_t *exclusive_timestamp_ns);

/* Replace one fully scored, CORE-only ordinary FlowKeep generation with its
 * sparse continuation.  This is an owner-quiescent operation: every pending
 * FLOW_OPEN/checkpoint/action/evidence-transition output must already have
 * been consumed.  Ineligible generations are a successful no-op; `demoted`
 * distinguishes them from an actual release.  The operation does not advance
 * semantic time and is deliberately unavailable to comparison policies. */
bool fk_compact_runtime_demote_terminal_core(
    struct fk_compact_runtime *runtime,
    const struct fk_flow_key *cached_key,
    struct fk_compact_flow_handle cached_handle,
    bool *demoted);

/* Commit 1..128 already parsed packets from the same exact cached generation.
 * Every observation timestamp must be below the previously returned limit.
 * On success the receipt proves no FLOW_OPEN/checkpoint/action/transition
 * output, while runtime frame and packet-once counters remain per-packet. */
enum fk_compact_runtime_result
fk_compact_runtime_process_final_tail_batch(
    struct fk_compact_runtime *runtime,
    const struct fk_flow_key *cached_key,
    struct fk_compact_flow_handle cached_handle,
    const struct fk_compact_final_tail_observation *observations,
    uint32_t count,
    struct fk_compact_runtime_packet_once_outcome *outcome);

/* Commit an already coalesced post-final CORE delta.  This has the same
 * no-output receipt and per-packet runtime accounting as the observation
 * batch API, but no longer requires retaining every packet or observation. */
enum fk_compact_runtime_result
fk_compact_runtime_process_final_tail_delta(
    struct fk_compact_runtime *runtime,
    const struct fk_flow_key *cached_key,
    struct fk_compact_flow_handle cached_handle,
    const struct fk_compact_final_tail_delta *delta,
    struct fk_compact_runtime_packet_once_outcome *outcome);

enum fk_compact_runtime_result fk_compact_runtime_process_parsed_packet_v2(
    struct fk_compact_runtime *runtime,
    const struct fk_packet_view *view,
    uint64_t timestamp_ns,
    const struct fk_compact_runtime_ingress_identity_v2 *ingress_identity,
    struct fk_compact_runtime_flow_identity_v2 *identity);

/*
 * Explicit proof boundary for ordinary (non-logical) TCP/UDP traffic in a
 * v2-only runtime.  The fixed-owner caller must supply the exact canonical
 * flow key produced by fk_native_flow_key() for this packet and an explicit
 * zero logical_connection_id.  Runtime derives the key again and requires a
 * byte-exact match before lookup or admission.  A validated proof permits an
 * existing generation to be entered by canonical-key lookup, so the caller
 * need not retain one handle per ordinary flow.  It does not permit a
 * non-zero logical id, a non-TCP/UDP packet, a mismatched key, or any access
 * through the generic unbound v2 APIs above.  Each pointer-valid call is one
 * packet and increments runtime.frames exactly once; malformed API calls are
 * proof rejections but are not fabricated as ingress frames.
 */
enum fk_compact_runtime_result
fk_compact_runtime_process_canonical_packet_v2(
    struct fk_compact_runtime *runtime,
    const struct fk_packet_view *view,
    uint64_t timestamp_ns,
    const struct fk_compact_runtime_ingress_identity_v2 *ingress_identity,
    const struct fk_flow_key *canonical_flow_key_proof,
    struct fk_compact_runtime_flow_identity_v2 *identity);

/*
 * Process a packet already associated with a live logical-connection handle.
 * The first normally admitted five-tuple stored in the FlowTable remains the
 * sticky presentation identity for FLOW_OPEN/action/detection records.  The
 * supplied direction is the packet's canonical direction in the original
 * presentation five-tuple coordinate system.  It is not an already-normalized
 * feature direction: if the first packet's native canonical direction was 1,
 * a later same-direction packet must pass 1 and a reverse packet must pass 0.
 * A stale generation returns STALE_BOUND_HANDLE so the identity
 * directory can explicitly rebind or re-admit; slot-index reuse is forbidden.
 * Each call represents one ingress packet and increments runtime.frames once;
 * CID pre-parsing must therefore not call process_frame for the same packet.
 * The v1 function preserves its API and uses logical id zero.  Production
 * owner/CID ingress must use the v2 API for every packet, including TCP/TLS
 * packets whose explicit logical id is zero.
 */
enum fk_compact_runtime_result fk_compact_runtime_process_bound_view(
    struct fk_compact_runtime *runtime,
    const struct fk_packet_view *view,
    struct fk_compact_flow_handle handle,
    uint8_t canonical_direction_in_presentation_axis,
    uint64_t timestamp_ns);

enum fk_compact_runtime_result fk_compact_runtime_process_bound_view_v2(
    struct fk_compact_runtime *runtime,
    const struct fk_packet_view *view,
    struct fk_compact_flow_handle handle,
    uint8_t canonical_direction_in_presentation_axis,
    uint64_t timestamp_ns,
    const struct fk_compact_runtime_ingress_identity_v2 *caller_identity_proof);

/*
 * Packet-once replacement for a two-call "bound then re-admit" sequence.
 * The call increments frames and advances semantic residency exactly once.
 * A live handle is observed with canonical_direction_in_presentation_axis.
 * A stale handle is counted and recovered inside this same call by deriving
 * the current view's canonical key/direction and performing lookup-or-admit.
 * Consequently this API never returns STALE_BOUND_HANDLE.  On successful
 * packet incorporation, outcome.identity is suitable for an owner-local
 * compare-and-swap rebind.  A failed lookup/admission/state observation never
 * fabricates a valid identity.
 */
enum fk_compact_runtime_result fk_compact_runtime_process_packet_once(
    struct fk_compact_runtime *runtime,
    const struct fk_packet_view *view,
    struct fk_compact_flow_handle bound_handle,
    uint8_t canonical_direction_in_presentation_axis,
    uint64_t timestamp_ns,
    struct fk_compact_runtime_packet_once_outcome *outcome);

enum fk_compact_runtime_result fk_compact_runtime_process_packet_once_v2(
    struct fk_compact_runtime *runtime,
    const struct fk_packet_view *view,
    struct fk_compact_flow_handle bound_handle,
    uint8_t canonical_direction_in_presentation_axis,
    uint64_t timestamp_ns,
    const struct fk_compact_runtime_ingress_identity_v2 *caller_identity_proof,
    struct fk_compact_runtime_packet_once_outcome_v2 *outcome);

/*
 * Release one exact owner-bound FlowTable generation at the QUIC retirement
 * semantic timestamp.  Residency is advanced before state is released, so
 * byte-seconds include the state through the retirement instant.  A zero
 * generation is the binding directory's proof that this logical connection
 * has no FlowTable generation; it still advances semantic residency and
 * returns ALREADY_ABSENT.  Repeating an already completed cleanup is
 * generation-safe and returns ALREADY_ABSENT; it never releases a newer flow
 * that reused the same slot index.
 */
enum fk_compact_runtime_flow_release_result
fk_compact_runtime_release_bound_flow(
    struct fk_compact_runtime *runtime,
    struct fk_compact_flow_handle handle,
    uint64_t retirement_timestamp_ns);

/*
 * Advance actual controlled-state residency accounting and run a complete
 * lease/idle scan at an explicit semantic-time watermark. Formal replay calls
 * this once per shard at the exact final PCAP timestamp.
 */
bool fk_compact_runtime_advance_semantic_time(
    struct fk_compact_runtime *runtime,
    uint64_t timestamp_ns);

/*
 * Advance optional-state deadlines toward one packet/control timestamp, but
 * do not run the final idle-flow scan.  One successful call stops after at
 * most one non-empty timer pass.  `complete=false` requires the fixed owner
 * to drain every evidence transition before retrying the exact same input.
 * Once `complete=true`, the normal packet/retirement API may run at the same
 * timestamp; its legacy advance then has no optional deadline left to cross.
 *
 * This split is what keeps a large timestamp gap from filling the bounded
 * transition ring before the owner has an opportunity to persist it.  False
 * is a fail-closed semantic-time/timer error, never a retry indication.
 */
bool fk_compact_runtime_prepare_semantic_time_step(
    struct fk_compact_runtime *runtime,
    uint64_t timestamp_ns,
    bool *complete);

/*
 * Advance toward one semantic watermark without allowing timer-generated
 * evidence transitions to outrun the bounded audit queue.  One successful
 * call stops after at most one non-empty optional-timer scan.  `complete` is
 * true only after residency has reached timestamp_ns and the final idle scan
 * has run.  A caller that receives complete=false must drain every evidence
 * transition before calling this function again for the same timestamp.
 *
 * This is the production terminal-watermark API.  It preserves exact
 * byte-seconds at each lease/TTL boundary while giving the owner a bounded
 * opportunity to persist a gap-free transition sequence.  Returning false
 * is a fail-closed semantic-time or timer no-progress error.
 */
bool fk_compact_runtime_advance_semantic_time_step(
    struct fk_compact_runtime *runtime,
    uint64_t timestamp_ns,
    bool *complete);

/* Continue bounded optional-state timer maintenance at an already reached
 * semantic timestamp.  The terminal composition alternates this call with
 * drain_evidence_transitions() until zero releases are returned, preventing
 * a trace queue from being mistaken for retained state. */
bool fk_compact_runtime_scan_optional_timers(
    struct fk_compact_runtime *runtime,
    uint64_t timestamp_ns,
    uint32_t scan_limit,
    uint32_t *component_releases);

/* Move append-only evidence-release records out of the owning FlowTable.
 * A production composition drains after every packet/checkpoint timer pass
 * and proves a zero-pending, gap-free terminal sequence. */
size_t fk_compact_runtime_drain_evidence_transitions(
    struct fk_compact_runtime *runtime,
    struct fk_compact_evidence_transition *transitions,
    size_t capacity);

/* Resolve the immutable presentation owner of an exact live FlowTable
 * generation while the fixed-owner adapter scope is held. This exists for
 * evidence-transition provenance export; it does not mutate retention state
 * or perform a five-tuple lookup/admission. */
bool fk_compact_runtime_flow_snapshot(
    struct fk_compact_runtime *runtime,
    struct fk_compact_flow_handle handle,
    struct fk_compact_flow_snapshot *snapshot);

/*
 * Move the pending first-packet flow-open observation out of the runtime.
 * The caller must drain this after every processed packet, before draining a
 * checkpoint request, so a packet-one checkpoint cannot overtake FLOW_OPEN.
 * Repeated packets for the same flow generation never republish this record.
 * The v1 drain accepts only id-zero records; use the v2 drain for non-zero
 * logical connections so routing identity cannot be discarded silently.
 */
bool fk_compact_runtime_take_flow_open_observation(
    struct fk_compact_runtime *runtime,
    struct fk_compact_flow_open_observation *observation);

bool fk_compact_runtime_take_flow_open_observation_v2(
    struct fk_compact_runtime *runtime,
    struct fk_compact_flow_open_observation_v2 *observation);

/*
 * Move the most recent immutable checkpoint snapshot out of the RX runtime.
 * The caller should invoke this after every processed packet and enqueue the
 * returned value into a bounded detector queue.  The v1 drain accepts only
 * id-zero records; all QUIC logical connections must use the v2 drain.
 */
bool fk_compact_runtime_take_detection_request(
    struct fk_compact_runtime *runtime,
    struct fk_compact_detection_request *request);

bool fk_compact_runtime_take_detection_request_v2(
    struct fk_compact_runtime *runtime,
    struct fk_compact_detection_request_v2 *request);

/*
 * Move the latest checkpoint action audit record out of the RX runtime.
 * Callers must drain this after every processed packet, just like detection
 * requests, and enqueue it to a bounded audit writer.
 */
bool fk_compact_runtime_take_action_record(
    struct fk_compact_runtime *runtime,
    struct fk_compact_action_record *record);

/* Thread-safe read-only model execution over an immutable request snapshot. */
bool fk_compact_runtime_detect(
    struct fk_compact_runtime *runtime,
    const struct fk_compact_detection_request *request,
    float *score);

/* Executes exactly the v1 159D presentation; routing metadata is ignored. */
bool fk_compact_runtime_detect_v2(
    struct fk_compact_runtime *runtime,
    const struct fk_compact_detection_request_v2 *request,
    float *score);

void fk_compact_runtime_set_pressure(
    struct fk_compact_runtime *runtime,
    enum fk_pressure_mode pressure);

bool fk_compact_runtime_get_stats(
    const struct fk_compact_runtime *runtime,
    struct fk_compact_runtime_stats *stats);

bool fk_compact_runtime_detector_feature_count(
    const struct fk_compact_runtime *runtime,
    uint32_t *feature_count);

bool fk_compact_runtime_get_action_model_metadata(
    const struct fk_compact_runtime *runtime,
    struct fk_cpu_pipeline_action_model_metadata *metadata);

struct fk_compact_flow_table *fk_compact_runtime_flow_table(
    struct fk_compact_runtime *runtime);

#ifdef __cplusplus
}
#endif

#endif
