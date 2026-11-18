#ifndef FLOWKEEP_FK_NO_NIC_FULL_COMPOSITION_H
#define FLOWKEEP_FK_NO_NIC_FULL_COMPOSITION_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "fk_actor_session.h"
#include "fk_compact_runtime.h"
#include "fk_dpdk_exact_rx_producer_pump.h"
#include "fk_event_student.h"
#include "fk_identity_pipeline_contract.h"
#include "fk_compact_controller.h"
#include "fk_ja4_identity_features.h"
#include "fk_native_parser.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Production-topology composition for bounded no-NIC conservation/order
 * smoke runs.  It is never, by itself, a detector-accuracy or throughput
 * result. */
enum fk_no_nic_full_composition_budget_mode {
    FK_NO_NIC_FULL_COMPOSITION_BUDGET_16_MIB = 1,
    FK_NO_NIC_FULL_COMPOSITION_BUDGET_UNLIMITED_FULL_STATE = 2,
    FK_NO_NIC_FULL_COMPOSITION_BUDGET_32_MIB = 3,
    FK_NO_NIC_FULL_COMPOSITION_BUDGET_64_MIB = 4,
    FK_NO_NIC_FULL_COMPOSITION_BUDGET_128_MIB = 5,
};

#define FK_NO_NIC_FROZEN_CAUSAL_TEXT_BYTES 64u
#define FK_NO_NIC_FROZEN_CAUSAL_SHA256_CHARS 64u
#define FK_NO_NIC_FROZEN_CAUSAL_AGGREGATION_RECEIPT_ABI_VERSION 3u

#define FK_NO_NIC_VALUE_MODEL_V3_RECEIPT_ABI_VERSION 2u
#define FK_NO_NIC_DETECTION_SERVICE_CAPACITY_RECEIPT_ABI_VERSION 1u
#define FK_NO_NIC_OWNER_HASH_KEY_BYTES 16u

/* Optional formal 64D state-value route.  All pointer fields are an atomic
 * provenance group: either every field is null (legacy/disabled) or every
 * field is present and hash-bound. */
struct fk_no_nic_value_model_v3_config_v1 {
    const char *artifact_path;
    const char *artifact_sha256;
    const char *training_receipt_sha256;
    const char *online_context_schema_sha256;
    const char *requested_action_domain_sha256;
    const char *online_deadline_contract_sha256;
    enum fk_value_model_v3_role expected_role;
};

struct fk_no_nic_value_model_v3_receipt_v1 {
    uint32_t abi_version;
    uint32_t format_version;
    enum fk_value_model_v3_family family;
    enum fk_value_model_v3_role role;
    uint32_t context_features;
    uint32_t query_features;
    uint32_t model_features;
    uint32_t learned_actions;
    uint32_t outputs;
    float conditional_equivalence_tolerance;
    uint32_t training_target_uses_detector_threshold;
    uint32_t formal_event_student_counterfactual_semantics_aligned;
    uint32_t detector_threshold_bits;
    uint64_t artifact_file_bytes;
    uint64_t model_reserved_bytes;
    uint64_t frozen_context_reserved_bytes;
    uint64_t load_attempts;
    uint64_t load_successes;
    uint64_t load_failures;
    uint64_t contexts_built;
    uint64_t context_failures;
    uint64_t inference_calls;
    uint64_t inference_failures;
    uint64_t core_zero_violations;
    uint64_t protocol_domain_violations;
    char artifact_sha256[FK_VALUE_MODEL_V3_SCHEMA_SHA256_CHARS + 1u];
    char training_receipt_sha256[
        FK_VALUE_MODEL_V3_SCHEMA_SHA256_CHARS + 1u];
    char online_context_schema_sha256[
        FK_VALUE_MODEL_V3_SCHEMA_SHA256_CHARS + 1u];
    char requested_action_domain_sha256[
        FK_VALUE_MODEL_V3_SCHEMA_SHA256_CHARS + 1u];
    char online_deadline_contract_sha256[
        FK_VALUE_MODEL_V3_SCHEMA_SHA256_CHARS + 1u];
    char detector_threshold_binding_sha256[
        FK_VALUE_MODEL_V3_SCHEMA_SHA256_CHARS + 1u];
    char detector_threshold_selection_receipt_sha256[
        FK_VALUE_MODEL_V3_SCHEMA_SHA256_CHARS + 1u];
    char detector_operating_point_receipt_sha256[
        FK_VALUE_MODEL_V3_SCHEMA_SHA256_CHARS + 1u];
    uint8_t enabled;
    uint8_t loaded;
    uint8_t used;
    uint8_t complete;
    uint8_t reserved[4];
};

/* Production replacement for the historical deterministic FKESV1 smoke
 * shard.  The only formal online rule is a causal maximum over record scores
 * within one stable (event_id,event_generation), with threshold crossing
 * latched for that event generation. */
enum fk_no_nic_event_aggregation_mode_v1 {
    FK_NO_NIC_EVENT_AGGREGATION_EVENT_STUDENT = 0,
    FK_NO_NIC_EVENT_AGGREGATION_FROZEN_CPP_CAUSAL = 1,
};

struct fk_no_nic_frozen_causal_aggregation_config_v1 {
    enum fk_no_nic_event_aggregation_mode_v1 mode;
    float threshold;
    const char *threshold_profile;
    const char *aggregation_contract_sha256;
    const char *development_oof_receipt_sha256;
    const char *causal_event_calibrator_artifact_path;
    const char *causal_event_calibrator_artifact_sha256;
    const char *causal_event_calibrator_source_npz_sha256;
    const char *causal_event_feature_contract_sha256;
    const char *causal_event_real_prefix_receipt_sha256;
};

struct fk_no_nic_frozen_causal_aggregation_receipt_v1 {
    uint32_t abi_version;
    float threshold;
    uint64_t checkpoint_updates;
    uint64_t periodic_updates;
    uint64_t total_feature_updates;
    uint64_t initialized_event_generations;
    uint64_t feature_state_resets;
    uint64_t inference_calls;
    uint64_t inference_failures;
    uint64_t model_load_successes;
    uint64_t model_load_failures;
    uint64_t mixed_mask_triggers;
    uint64_t causal_records_presented;
    uint64_t requested_effective_mask_divergences;
    uint64_t protocol_action_domain_checks;
    uint64_t protocol_action_domain_violations;
    uint64_t physical_feature_mask_checks;
    uint64_t physical_feature_mask_mismatches;
    uint64_t scheduled_periodic_ticks;
    uint64_t empty_periodic_ticks;
    uint64_t same_timestamp_periodic_coalesces;
    uint64_t threshold_crossings;
    uint64_t latched_alert_outputs;
    uint64_t stale_handle_rejections;
    uint64_t reserved_bytes;
    char aggregation_rule[FK_NO_NIC_FROZEN_CAUSAL_TEXT_BYTES];
    char threshold_profile[FK_NO_NIC_FROZEN_CAUSAL_TEXT_BYTES];
    char aggregation_contract_sha256[
        FK_NO_NIC_FROZEN_CAUSAL_SHA256_CHARS + 1u];
    char development_oof_receipt_sha256[
        FK_NO_NIC_FROZEN_CAUSAL_SHA256_CHARS + 1u];
    char causal_event_calibrator_artifact_sha256[
        FK_NO_NIC_FROZEN_CAUSAL_SHA256_CHARS + 1u];
    char causal_event_calibrator_source_npz_sha256[
        FK_NO_NIC_FROZEN_CAUSAL_SHA256_CHARS + 1u];
    char causal_event_feature_contract_sha256[
        FK_NO_NIC_FROZEN_CAUSAL_SHA256_CHARS + 1u];
    char causal_event_real_prefix_receipt_sha256[
        FK_NO_NIC_FROZEN_CAUSAL_SHA256_CHARS + 1u];
    uint8_t enabled;
    uint8_t calibrator_enabled;
    uint8_t model_loaded;
    uint8_t model_used;
    uint8_t requested_mask_or;
    uint8_t physical_final_mask_or;
    uint8_t complete;
    uint8_t deterministic_smoke_model;
    uint8_t reserved[7];
};

struct fk_no_nic_full_composition_io_stats_v1 {
    uint64_t acquired_packets;
    uint64_t acquired_wire_bytes;
    uint64_t reclaim_attempts;
    uint64_t reclaim_successes;
    uint64_t duplicate_reclaims;
    uint64_t live_mbufs;
    uint64_t forced_failure_reclaims;
    /* Fixed source-side ownership/tracking window.  PCAP bytes, DPDK mbuf
     * pools and NIC descriptors are infrastructure memory and are not folded
     * into this receipt. */
    uint64_t bounded_source_reserved_bytes;
    uint64_t bounded_source_peak_bytes;
    uint32_t bounded_source_capacity;
    uint8_t source_exhausted;
    uint8_t source_failed;
    uint8_t accounting_conserved;
    uint8_t ownership_recovered;
    uint8_t bounded_source_memory_exact;
    uint8_t bounded_source_trace_independent;
    uint8_t reserved[2];
};

typedef bool (*fk_no_nic_full_composition_io_stats_callback)(
    void *context,
    struct fk_no_nic_full_composition_io_stats_v1 *stats);

#define FK_NO_NIC_DECISION_TRACE_ABI_VERSION 3u
#define FK_NO_NIC_DECISION_TRACE_HISTOGRAM_BINS 64u
#define FK_NO_NIC_DECISION_TRACE_DETECTOR_FEATURES \
    FK_COMPACT_DETECTOR_FEATURES_V4

enum fk_no_nic_decision_trace_kind_v1 {
    FK_NO_NIC_DECISION_TRACE_CHECKPOINT = 1,
    FK_NO_NIC_DECISION_TRACE_PERIODIC = 2,
    FK_NO_NIC_DECISION_TRACE_EVIDENCE_TRANSITION = 3,
};

/* Truth-free, append-only decision record.  CHECKPOINT records bind the exact
 * packet/flow/action transaction to its event-level Student decision.  PERIODIC
 * records carry event identity and decision time but deliberately have no
 * packet/action association. */
struct fk_no_nic_decision_trace_record_v1 {
    uint32_t abi_version;
    uint32_t record_bytes;
    uint64_t record_sequence;
    uint64_t input_sequence;
    uint64_t packet_sequence;
    struct fk_flow_key flow_key;
    uint64_t logical_connection_id;
    uint64_t flow_first_timestamp_ns;
    uint64_t observation_timestamp_ns;
    uint64_t physical_ingress_timestamp_ns;
    uint64_t association_enqueue_timestamp_ns;
    uint64_t detector_start_monotonic_ns;
    uint64_t decision_monotonic_ns;
    uint64_t detection_latency_ns;
    uint64_t packet_to_decision_latency_ns;
    uint64_t flow_detector_latency_ns;
    uint64_t event_id;
    uint64_t event_start_ns;
    uint64_t event_anchor_ns;
    uint64_t trigger_ordinal;
    uint64_t packet_count;
    uint64_t controlled_bytes_before;
    uint64_t controlled_bytes_after;
    uint32_t flow_index;
    uint32_t flow_generation;
    uint32_t event_slot;
    uint32_t event_generation;
    uint32_t retained_flow_snapshots;
    float event_detector_score;
    float flow_detector_score;
    float selected_utility;
    uint8_t trace_kind;
    uint8_t trigger_protocol;
    uint8_t trigger_kind;
    uint8_t checkpoint_packet;
    uint8_t flow_association_available;
    uint8_t action_available;
    uint8_t flow_detector_score_available;
    uint8_t packet_latency_available;
    uint8_t previous_mask;
    /* Protocol-legal policy request before pool/budget/released feasibility. */
    uint8_t selected_mask;
    /* Protocol-legal action domain; independent from pool availability. */
    uint8_t protocol_applicable_mask;
    /* Physically retained action after applicability and transitions. */
    uint8_t final_mask;
    uint8_t released_mask_before;
    uint8_t released_mask_after;
    uint8_t materializable_mask;
    uint8_t pool_unavailable_mask;
    uint8_t observation_complete;
    uint8_t pressure;
    uint8_t missing_reason[3];
    uint8_t candidates_considered;
    uint8_t budget_rejections;
    uint8_t action_reason;
    uint8_t threshold_crossed;
    uint8_t alert_latched;
    uint8_t first_alert;
    uint8_t behavior_stage;
    uint8_t alert_state;
    uint8_t alert_state_changed;
    uint8_t correction_emitted;
    uint8_t reopen_emitted;
    uint8_t transition_component;
    uint8_t transition_reason;
    uint8_t reserved[6];
    uint64_t evidence_transition_sequence;
    uint64_t evidence_transition_timestamp_ns;
    uint64_t evidence_transition_bytes_released;
    uint32_t transition_victim_index;
    uint32_t transition_victim_generation;
    uint32_t transition_causing_index;
    uint32_t transition_causing_generation;
    uint32_t transition_causing_packet_count;
    uint32_t reserved2;
    float transition_victim_loss;
    float transition_victim_value_per_byte;
    float transition_incoming_bundle_gain;
    float transition_victim_total_loss;
    float transition_hysteresis_eta;
};

typedef bool (*fk_no_nic_decision_trace_sink_v1)(
    void *context,
    const struct fk_no_nic_decision_trace_record_v1 *record);

#define FK_NO_NIC_DETECTOR_REQUEST_TRACE_ABI_VERSION 1u

/* Independent, opt-in exact checkpoint detector request.  Keeping this out of
 * fk_no_nic_decision_trace_record_v1 preserves the ABI-3 main trace layout and
 * avoids touching 159 floats on the default performance path. */
struct fk_no_nic_detector_request_trace_record_v1 {
    uint32_t abi_version;
    uint32_t record_bytes;
    uint64_t trace_record_sequence;
    struct fk_flow_key flow_key;
    uint64_t logical_connection_id;
    uint64_t flow_first_timestamp_ns;
    uint64_t observation_timestamp_ns;
    uint32_t flow_index;
    uint32_t flow_generation;
    uint8_t checkpoint_packet;
    uint8_t reserved[3];
    uint32_t feature_count;
    float features[FK_NO_NIC_DECISION_TRACE_DETECTOR_FEATURES];
};

typedef bool (*fk_no_nic_detector_request_trace_sink_v1)(
    void *context,
    const struct fk_no_nic_detector_request_trace_record_v1 *record);

struct fk_no_nic_full_composition_config {
    enum fk_no_nic_full_composition_budget_mode budget_mode;
    uint32_t packet_count;
    /* Finite epoch endpoint only.  It is never a storage dimension. */
    uint32_t bridge_epoch_packet_limit;
    uint32_t completion_window_capacity;
    uint32_t sequencer_ingress_capacity;
    uint32_t rx_burst_capacity;
    uint32_t abort_after_identity_transfers;

    /* Optional bounded external source mode.  The callback contracts are
     * exactly those of fk_dpdk_exact_rx_producer_pump.  expected packet count
     * is packet_count and must be obtained without retaining the trace. */
    uint32_t maximum_flows;
    /* Precommitted owner-sharding key.  No-NIC and actual-NIC parity requires
     * the same key because hard state budgets are enforced per owner shard. */
    uint8_t owner_hash_key[FK_NO_NIC_OWNER_HASH_KEY_BYTES];
    uint8_t owner_hash_key_precommitted;
    uint8_t reserved_owner_hash_key[7];
    /* Independent hard capacity for the QUIC CID directory, presentation
     * path directory, and owner-flow binding directory.  It is deliberately
     * not inferred from maximum_flows: TCP-only workloads must not reserve a
     * QUIC identity slot for every possible FlowTable entry.  The complete
     * reservation for all three directories remains controlled state. */
    uint32_t maximum_quic_connections;
    /* Optional typed-pool split. All zeros select the runtime default.
     * Formal comparisons must freeze one common split for every policy. */
    struct fk_component_pool_weights pool_weights;
    struct fk_compact_baseline_policy_config baseline_policy;
    /* Optional FLOWKEEP resource shadow prices applied to every action
     * utility before candidate ranking.  They are part of the frozen
     * Development calibration and default to zero: raw predicted causal
     * impact with exact-state-byte density ranking once the optional pool
     * enters PRESSURE/OVERLOAD.  A non-zero memory price makes the per-byte
     * trade-off explicit at every pressure level, not only under pressure. */
    float lambda_memory_per_byte;
    float retention_discount;
    float lambda_queue;
    float lambda_deadline;
    uint64_t idle_timeout_ns;
    uint64_t terminal_semantic_timestamp_ns;
    /* Zero uses the bounded deterministic smoke limit.  A live finite source
     * may select a larger bound and must use io_stats.source_failed to end an
     * idle/error wait without pretending the expected input was exhausted. */
    uint64_t maximum_run_iterations;
    const char *action_value_model_path;
    const char *detector_model_path;
    const char *detector_state_model_paths[8];
    const char *action_schema_sha256;
    const char *detector_schema_sha256;
    struct fk_no_nic_value_model_v3_config_v1 value_model_v3;
    /* Development-only one-shot source-record intervention.  A formal
     * accuracy/throughput run must leave this all-zero. */
    struct fk_compact_checkpoint_intervention_v1 checkpoint_intervention;
    const char *transition_value_model_path;
    const char *transition_value_schema_sha256;
    const char *transition_value_model_sha256;
    struct fk_no_nic_frozen_causal_aggregation_config_v1
        frozen_causal_aggregation;
    /* Optional strict FKESV1 deployment.  In EVENT_STUDENT mode a null
     * artifact selects the deterministic topology-smoke model and is never
     * paper evidence.  In FROZEN_CPP_CAUSAL mode this must be null and no
     * Student shard is created.  Supplying an FKESV1 artifact requires every
     * expected hash/dimension below. */
    const char *event_student_artifact_path;
    struct fk_event_student_load_config event_student_load_config;
    /* Frozen, truth-free actor/session association contract shared by the
     * no-NIC and finite-live paths. CIDRs are never inferred from a capture.
     * By default its capacities are clamped to maximum_flows for compact
     * tests. A finite formal replay may explicitly preserve larger bounded
     * detection-service capacities; those bytes are reported separately and
     * never charged to the controlled FlowKeep state budget. */
    struct fk_actor_session_config actor_session;
    uint16_t event_student_worker_count;
    uint16_t reserved_event_student16;
    uint32_t event_student_command_queue_capacity;
    uint32_t event_student_result_queue_capacity;
    void *burst_context;
    fk_dpdk_exact_rx_burst_callback burst;
    void *clock_context;
    fk_dpdk_exact_rx_clock_callback clock;
    void *decode_context;
    fk_dpdk_exact_rx_identity_decode_callback decode;
    void *reclaim_context;
    fk_dpdk_exact_rx_reclaim_callback reclaim;
    void *monotonic_clock_context;
    fk_dpdk_exact_rx_clock_callback monotonic_now_ns;
    void *io_stats_context;
    fk_no_nic_full_composition_io_stats_callback io_stats;
    void *decision_trace_context;
    fk_no_nic_decision_trace_sink_v1 decision_trace_sink;
    uint8_t external_io;
    uint8_t preserve_actor_session_capacities;
    uint8_t reserved[6];
    /* Optional scope-bound assertion for legitimate per-event segmentation.
     * Formal replay runners set this from an independently frozen flow-map
     * receipt; it is not part of capacity_clean and is checked separately. */
    uint8_t enforce_flow_rollover_contract;
    uint8_t reserved_rollover_contract[7];
    uint64_t expected_flow_capacity_rollovers;
    /* Optional independent sink for exact 159D checkpoint requests.  It is
     * valid only together with decision_trace_sink so trace_record_sequence is
     * a stable one-to-one join key. */
    void *decision_trace_features_context;
    fk_no_nic_detector_request_trace_sink_v1 decision_trace_features_sink;
};

struct fk_no_nic_optional_pool_result_v1 {
    uint32_t block_bytes;
    uint32_t capacity;
    uint32_t current_in_use;
    uint32_t peak_in_use;
    uint64_t allocations;
    uint64_t allocation_rejects;
};

struct fk_no_nic_decision_observability_v1 {
    uint32_t abi_version;
    uint32_t histogram_bins;
    uint64_t decision_records;
    uint64_t checkpoint_records;
    uint64_t periodic_records;
    uint64_t evidence_transition_records;
    uint64_t trace_sink_records;
    uint64_t trace_sink_rejections;
    uint64_t trace_rolling_hash64;
    uint64_t timestamp_failures;
    uint64_t order_failures;
    uint64_t detection_latency_samples;
    uint64_t detection_latency_p50_ns;
    uint64_t detection_latency_p95_ns;
    uint64_t detection_latency_p99_ns;
    uint64_t packet_to_decision_samples;
    uint64_t packet_to_decision_p50_ns;
    uint64_t packet_to_decision_p95_ns;
    uint64_t packet_to_decision_p99_ns;
    uint64_t flow_detector_latency_samples;
    uint64_t flow_detector_latency_p50_ns;
    uint64_t flow_detector_latency_p95_ns;
    uint64_t flow_detector_latency_p99_ns;
    uint64_t queue_samples;
    uint64_t queue_peak_entries;
    uint64_t sequencer_ingress_peak;
    uint64_t sequencer_reorder_peak;
    uint64_t dispatch_peak;
    uint64_t owner_output_peak;
    uint64_t checkpoint_reorder_peak;
    uint64_t student_command_peak;
    uint64_t student_result_peak;
    double queue_ols_slope_entries_per_second;
    double queue_peak_positive_slope_entries_per_second;
    uint64_t recovery_start_monotonic_ns;
    uint64_t recovery_complete_monotonic_ns;
    uint64_t recovery_time_ns;
    uint64_t fatal_packet_drops;
    uint64_t fatal_decision_drops;
    uint64_t fatal_integrity_events;
    uint64_t policy_flow_rejects;
    uint64_t policy_state_action_rejects;
    uint64_t policy_evidence_rejects;
    uint64_t transient_backpressure_events;
    uint8_t trace_sink_enabled;
    uint8_t trace_export_complete;
    uint8_t timing_complete;
    uint8_t recovery_complete;
    uint8_t drop_accounting_complete;
    uint8_t reserved[3];
};

#define FK_NO_NIC_EVIDENCE_TRANSITION_RECEIPT_ABI_VERSION 1u

struct fk_no_nic_evidence_transition_receipt_v1 {
    uint32_t abi_version;
    uint32_t terminal_pending;
    uint64_t table_records_emitted;
    uint64_t runtime_records_drained;
    uint64_t trace_records_emitted;
    uint64_t drain_calls;
    uint64_t terminal_timer_scan_passes;
    uint64_t terminal_timer_component_releases;
    uint64_t last_transition_sequence;
    uint64_t sequence_failures;
    uint64_t queue_full_rejects;
    uint8_t sequence_contiguous;
    uint8_t terminal_queue_empty;
    uint8_t complete;
    uint8_t reserved[5];
};

#define FK_NO_NIC_TRIGGER_RECEIPT_V2_ABI_VERSION 3u

/* Terminal checkpoint+periodic receipt for the real bounded Student route.
 * It binds the V2 protocol, checkpoint packet distribution, 0-based ordinal
 * summary, same-timestamp periodic coalescing, and exact final watermark. */
struct fk_no_nic_trigger_receipt_v2 {
    uint32_t abi_version;
    uint16_t worker_count;
    uint8_t trigger_protocol;
    uint8_t ordinal_base;
    uint64_t checkpoint_trigger_messages;
    uint64_t scheduled_periodic_ticks;
    uint64_t empty_periodic_ticks;
    uint64_t same_timestamp_unchanged_periodic_coalesces;
    uint64_t checkpoint_trigger_results;
    uint64_t periodic_trigger_results;
    uint64_t output_results;
    uint64_t trigger_ordinal_sum;
    uint64_t trigger_ordinal_xor;
    uint64_t trigger_ordinal_max;
    uint64_t checkpoint_packet_4_results;
    uint64_t checkpoint_packet_8_results;
    uint64_t checkpoint_packet_12_results;
    uint64_t checkpoint_packet_20_results;
    uint64_t invalid_checkpoint_packet_rejections;
    uint64_t trigger_protocol_rejections;
    uint64_t final_watermark_ns;
    uint64_t event_path_reserved_bytes;
    uint64_t student_shards_reserved_bytes;
    uint32_t student_continuous_features;
    uint32_t student_input_features;
    uint32_t student_hidden;
    uint32_t student_identity_embedding;
    uint32_t student_event_hidden;
    uint32_t student_parameter_floats;
    float student_decision_threshold;
    char student_artifact_sha256[FK_EVENT_STUDENT_SHA256_CHARS + 1u];
    char student_feature_schema_sha256[FK_EVENT_STUDENT_SHA256_CHARS + 1u];
    char student_architecture_sha256[FK_EVENT_STUDENT_SHA256_CHARS + 1u];
    char student_source_state_sha256[FK_EVENT_STUDENT_SHA256_CHARS + 1u];
    char student_payload_sha256[FK_EVENT_STUDENT_SHA256_CHARS + 1u];
    uint8_t final_flush_complete;
    uint8_t command_queues_empty;
    uint8_t result_queues_empty;
    uint8_t worker_failure;
    uint8_t conservation_valid;
    uint8_t deterministic_smoke_model;
    uint8_t reserved[2];
};

#define FK_NO_NIC_SERVICE_MEMORY_RECEIPT_ABI_VERSION 1u
#define FK_NO_NIC_SERVICE_MEMORY_RECEIPT_SHA256_BYTES 32u
#define FK_NO_NIC_SERVICE_MEMORY_AUXILIARY_COMPONENT_COUNT 7u

enum fk_no_nic_service_memory_disposition_v1 {
    FK_NO_NIC_SERVICE_MEMORY_DISABLED = 0,
    FK_NO_NIC_SERVICE_MEMORY_ACTIVE_BOUNDED = 1,
    FK_NO_NIC_SERVICE_MEMORY_INLINE_NO_TRANSPORT = 2,
    FK_NO_NIC_SERVICE_MEMORY_TEST_ONLY_TRACE_SIZED = 3,
};

enum fk_no_nic_service_memory_auxiliary_component_v1 {
    FK_NO_NIC_SERVICE_AUX_RX_PRODUCER_PUMP = 0,
    FK_NO_NIC_SERVICE_AUX_IDENTITY_WORKER_PUMP,
    FK_NO_NIC_SERVICE_AUX_IDENTITY_ROUTER,
    FK_NO_NIC_SERVICE_AUX_QUIC_ADMISSION_GATE,
    FK_NO_NIC_SERVICE_AUX_OWNER_WORKER_PUMP,
    FK_NO_NIC_SERVICE_AUX_ABORT_COORDINATOR,
    FK_NO_NIC_SERVICE_AUX_EXTERNAL_SOURCE_WINDOW,
};

struct fk_no_nic_service_memory_component_receipt_v1 {
    uint64_t configured_reserved_bytes;
    uint64_t observed_reserved_bytes;
    uint64_t peak_bytes;
    uint8_t disposition;
    uint8_t reservation_exact;
    uint8_t trace_independent;
    uint8_t bounded_window;
    uint8_t hash_bound;
    uint8_t reserved[3];
};

/* Post-run, tamper-evident service-memory receipt.  It deliberately does not
 * claim the formal 14-component topology: this composition uses strict-prefix
 * streaming without a trace barrier and calls detector/aggregation inline.
 * The inactive formal slots and every auxiliary placement object remain
 * visible instead of being hidden in a miscellaneous allowance. */
struct fk_no_nic_service_memory_receipt_v1 {
    uint32_t abi_version;
    uint32_t component_count;
    uint32_t auxiliary_component_count;
    uint32_t active_component_mask;
    uint32_t inline_component_mask;
    uint32_t disabled_component_mask;
    uint32_t formal_non_active_component_mask;
    uint32_t auxiliary_active_mask;

    uint64_t trace_packet_count;
    uint64_t bridge_epoch_packet_limit;
    uint32_t completion_window_capacity;
    uint32_t checkpoint_payload_capacity;
    uint32_t sequencer_ingress_capacity;
    uint32_t sequencer_reorder_capacity;
    uint32_t rx_burst_capacity;
    uint32_t owner_dispatch_capacity;
    uint32_t owner_output_ring_capacity;
    uint32_t checkpoint_reorder_capacity;
    uint16_t producer_count;
    uint16_t owner_count;

    uint64_t component_configured_reserved_bytes;
    uint64_t component_observed_reserved_bytes;
    uint64_t component_peak_bytes;
    uint64_t auxiliary_configured_reserved_bytes;
    uint64_t auxiliary_observed_reserved_bytes;
    uint64_t auxiliary_peak_bytes;
    uint64_t total_configured_reserved_bytes;
    uint64_t total_observed_reserved_bytes;
    uint64_t total_peak_bytes;
    uint64_t trace_sized_active_reserved_bytes;

    uint8_t service_memory_separate_from_controlled_state;
    uint8_t component_accounting_exact;
    uint8_t auxiliary_accounting_exact;
    uint8_t active_reservations_trace_independent;
    uint8_t completion_transport_window_bounded;
    uint8_t external_source_window_bounded;
    uint8_t finite_epoch_handoff_required;
    uint8_t formal_14_component_complete;
    uint8_t post_run_hash_bound;
    uint8_t reserved[7];
    uint8_t receipt_sha256[FK_NO_NIC_SERVICE_MEMORY_RECEIPT_SHA256_BYTES];

    struct fk_no_nic_service_memory_component_receipt_v1
        components[FK_IDENTITY_SERVICE_COMPONENT_COUNT];
    struct fk_no_nic_service_memory_component_receipt_v1
        auxiliary_components[
            FK_NO_NIC_SERVICE_MEMORY_AUXILIARY_COMPONENT_COUNT];
};

/* Detection-service state is preallocated and reported separately from the
 * controlled FlowKeep state budget.  A formal replay is capacity-clean only
 * when the actor table never evicted an event/flow epoch and the downstream
 * window scheduler never observed an active-slot generation replacement. */
struct fk_no_nic_detection_service_capacity_receipt_v1 {
    uint32_t abi_version;
    uint32_t actor_maximum_events;
    uint32_t actor_maximum_total_flows;
    uint32_t window_maximum_events;
    uint32_t window_maximum_total_flows;
    uint32_t actor_active_events;
    uint32_t actor_peak_active_events;
    uint32_t actor_active_flows;
    uint32_t actor_peak_active_flows;
    uint64_t actor_event_capacity_evictions;
    uint64_t actor_total_flow_capacity_evictions;
    uint64_t window_live_slot_reuse_conflicts;
    uint64_t window_event_slots_reused;
    uint8_t capacity_clean;
    uint8_t reserved[7];
    /* Append-only: a per-event rollover is declared segmentation, not an
     * event-table/total-flow eviction.  Formal runs bind its exact count. */
    uint64_t actor_flow_capacity_rollovers;
    uint32_t actor_maximum_flows_per_event;
    uint32_t reserved2;
    uint64_t expected_flow_capacity_rollovers;
    uint8_t flow_rollover_contract_enforced;
    uint8_t flow_rollover_contract_valid;
    uint8_t reserved3[6];
};

#define FK_NO_NIC_QUIC_IDENTITY_OBSERVABILITY_ABI_VERSION 2u

/* Append-only terminal audit of every controlled QUIC identity directory.
 * It deliberately reports both individual reject counters and conservative
 * aggregates; a TCP-only replay can therefore prove that no QUIC identity
 * state or admission path was exercised. */
struct fk_no_nic_quic_identity_observability_v1 {
    uint32_t abi_version;
    uint32_t maximum_connections;
    uint32_t cid_map_maximum_connections;
    uint32_t path_maximum_connections;
    uint32_t binding_maximum_connections;

    uint32_t cid_active_connections_at_end;
    uint32_t cid_peak_active_connections;
    uint32_t cid_active_cids_at_end;
    uint32_t cid_peak_active_cids;
    uint32_t cid_pending_handshakes_at_end;
    uint32_t cid_peak_pending_handshakes;
    uint32_t cid_retired_pending_owner_ack_at_end;
    uint32_t cid_binding_credits_in_use_at_end;
    uint32_t path_active_connections_at_end;
    uint32_t path_peak_active_connections;
    uint32_t path_active_paths_at_end;
    uint32_t path_peak_active_paths;
    uint64_t binding_active_at_end;
    uint64_t binding_peak_active_sum;
    uint64_t binding_unbound_at_end;
    uint64_t binding_retired_pending_at_end;

    uint64_t router_quic_initial_packets;
    uint64_t router_quic_long_packets;
    uint64_t router_quic_short_packets;
    uint64_t cid_observations;
    uint64_t cid_connections_created;
    uint64_t cid_connection_capacity_rejects;
    uint64_t cid_fixed_owner_capacity_rejects;
    uint64_t cid_capacity_rejects;
    uint64_t cid_per_connection_capacity_rejects;
    uint64_t cid_pending_handshake_capacity_rejects;
    uint64_t cid_hash_chain_lookup_rejects;
    uint64_t cid_hash_chain_registration_rejects;
    uint64_t cid_hash_chain_internal_rejects;
    uint64_t cid_direction_conflicts;
    uint64_t cid_same_cid_dual_role_rejects;
    uint64_t cid_hard_integrity_failures;
    uint64_t cid_allocator_integrity_failures;

    uint64_t path_classify_calls;
    uint64_t path_register_calls;
    uint64_t path_rejected_operations;
    uint64_t path_global_capacity_rejects;
    uint64_t path_per_connection_capacity_rejects;
    uint64_t path_hash_chain_capacity_rejects;
    uint64_t path_invalid_input_rejects;
    uint64_t path_generation_conflict_rejects;
    uint64_t path_internal_integrity_rejects;

    uint64_t binding_bind_attempts;
    uint64_t binding_created;
    uint64_t binding_idempotent;
    uint64_t binding_conflicts;
    uint64_t binding_missing_rejects;
    uint64_t binding_stale_generation_rejects;
    uint64_t binding_handle_mismatch_rejects;
    uint64_t binding_direction_mismatch_rejects;
    uint64_t binding_cid_generation_mismatch_rejects;
    uint64_t binding_fixed_owner_mismatch_rejects;
    uint64_t binding_slot_reuse_rejects;
    uint64_t binding_retire_expectation_rejects;
    uint64_t binding_slot_out_of_range_rejects;
    uint64_t binding_invalid_requests;
    uint64_t binding_state_integrity_failures;

    uint64_t crypto_gate_begin_attempts;
    uint64_t crypto_gate_begin_allowed;
    uint64_t crypto_gate_begin_deferred;
    uint64_t crypto_gate_begin_rejected;
    uint64_t crypto_gate_pressure_rejects;
    uint64_t crypto_gate_global_token_rejects;
    uint64_t crypto_gate_prefix_credit_rejects;
    uint64_t crypto_gate_prefix_table_rejects;
    uint64_t crypto_gate_oversized_rejects;
    uint64_t crypto_gate_invalid_request_rejects;
    uint64_t crypto_gate_internal_rejects;

    uint64_t cid_map_admission_rejections;
    uint64_t path_admission_rejections;
    uint64_t binding_admission_rejections;
    uint64_t admission_rejections;
    uint8_t capacity_conserved;
    uint8_t terminal_active_zero;
    uint8_t admission_rejections_zero;
    uint8_t tcp_only_no_quic_activity;
    uint8_t reserved[4];
    /* Append-only proof that external finite replay drained QUIC state only
     * after producer/identity EOF at the frozen terminal watermark. */
    uint64_t finite_epoch_drain_timestamp_ns;
    uint32_t finite_epoch_active_before;
    uint32_t finite_epoch_connections_drained;
    uint32_t finite_epoch_active_after;
    uint8_t finite_epoch_drain_reason;
    uint8_t finite_epoch_drain_requested;
    uint8_t finite_epoch_drain_after_input_eof;
    uint8_t finite_epoch_drain_complete;
    uint8_t reserved2[4];
    uint32_t finite_epoch_path_active_connections_before;
    uint32_t finite_epoch_paths_before;
    uint32_t finite_epoch_paths_drained;
    uint32_t finite_epoch_path_active_connections_after;
    uint32_t finite_epoch_paths_after;
    uint8_t finite_epoch_path_drain_reason;
    uint8_t finite_epoch_path_drain_complete;
    uint8_t reserved3[2];

    /* Append-only V2 retirement-delivery proof.  Expiring a CID-directory
     * entry is only the producer half of shutdown: every resulting control
     * must be published, consumed by its immutable owner, and ACKed back to
     * the CID map before a finite replay can claim terminal identity
     * closure.  Retry calls may exceed successful controls, so conservation
     * is expressed using committed/dequeued/ACKed successes and failures are
     * reported separately. */
    uint64_t router_quic_data_committed_transfers;
    uint64_t router_quic_skip_committed_reclaims;
    uint64_t publisher_controls_committed;
    uint64_t publisher_terminal_batches_committed;
    uint64_t publisher_terminal_empty;
    uint64_t dispatch_retire_controls_enqueued;
    uint64_t dispatch_retire_controls_normal_dequeued;
    uint64_t dispatch_retire_control_depth_at_end;
    uint64_t owner_retire_controls_dequeued;
    uint64_t owner_retire_controls_acked;
    uint64_t adapter_retire_calls;
    uint64_t adapter_retire_acked;
    uint64_t cid_retirement_ack_calls;
    uint64_t cid_retirement_acks;
    uint64_t cid_connections_retired_pending_owner_ack_total;
    uint64_t cid_retirement_publication_marks;
    uint64_t retirement_ack_failures;
    uint32_t publisher_marked_controls_at_end;
    uint8_t publisher_accounting_conserved;
    uint8_t publisher_formal_complete;
    uint8_t retirement_delivery_conserved;
    uint8_t owner_ack_complete;
    uint8_t finite_epoch_drain_before_publisher_terminal;
    uint8_t dispatch_observations_sealed;
    uint8_t router_quic_disposition_conserved;
    uint8_t reserved4[1];
};

struct fk_no_nic_full_composition_result {
    uint64_t packets_created;
    uint64_t rx_received;
    uint64_t sequencer_transferred;
    uint64_t identity_data_transfers;
    uint64_t owner_packets_completed;
    uint64_t mbufs_reclaimed;
    /* True first-generation OPEN controls only. */
    uint64_t flow_open_messages;
    /* Capacity-generation rebinding controls, never counted as OPEN. */
    uint64_t flow_continue_messages;
    uint64_t detection_requests;
    uint64_t detector_executions;
    uint64_t reorder_messages;
    uint64_t last_reorder_input_sequence;
    uint64_t controlled_allocation_bytes;
    uint64_t peak_evidence_storage_bytes;
    uint64_t bridge_service_memory_bytes;
    uint64_t reorder_service_memory_bytes;
    struct fk_no_nic_service_memory_receipt_v1 service_memory;
    struct fk_no_nic_trigger_receipt_v2 trigger_receipt;
    struct fk_no_nic_frozen_causal_aggregation_receipt_v1
        frozen_causal_aggregation;
    struct fk_no_nic_value_model_v3_receipt_v1 value_model_v3;
    struct fk_compact_checkpoint_intervention_receipt_v1
        checkpoint_intervention;
    struct fk_no_nic_decision_observability_v1 observability;
    struct fk_no_nic_evidence_transition_receipt_v1 evidence_transitions;
    uint64_t positive_detection_decisions;
    double detection_score_sum;
    double detection_score_min;
    double detection_score_max;

    uint64_t rx_callback_retries;
    uint64_t rx_shape_rejections;
    uint64_t sequencer_queue_full_rejections;
    uint64_t sequencer_integrity_rejections;
    uint64_t identity_skip_reclaims;
    uint64_t identity_reject_reclaims;
    uint64_t identity_backpressure;
    uint64_t router_resolver_rejections;
    uint64_t router_parser_rejections;
    uint64_t router_identity_rejections;
    uint64_t router_completion_backpressure;
    uint64_t router_completion_rejections;
    uint64_t dispatch_ordered_skips;
    uint64_t dispatch_queue_full;
    uint64_t dispatch_invalid_routes;
    uint64_t owner_ignored;
    uint64_t owner_admission_rejected;
    uint64_t owner_output_backpressure;
    uint64_t owner_terminal_results;
    uint64_t owner_reclaim_failures;
    uint64_t owner_data_semantic_drain_retries;
    uint64_t owner_retire_semantic_drain_retries;
    uint64_t adapter_semantic_data_step_calls;
    uint64_t adapter_semantic_data_step_completions;
    uint64_t adapter_semantic_data_drain_required;
    uint64_t adapter_semantic_data_step_failures;
    uint64_t adapter_semantic_retire_step_calls;
    uint64_t adapter_semantic_retire_step_completions;
    uint64_t adapter_semantic_retire_drain_required;
    uint64_t adapter_semantic_retire_step_failures;
    uint64_t bridge_reservation_backpressure;
    uint64_t bridge_reorder_backpressure;
    uint64_t bridge_publication_rejections;
    uint64_t bridge_integrity_rejections;
    uint64_t runtime_parse_ignored;
    uint64_t runtime_frames;
    uint64_t runtime_post_final_checkpoint_tail_packets;
    uint64_t runtime_bound_final_tail_fast_path_packets;
    uint64_t runtime_flow_admission_rejects;
    uint64_t runtime_state_update_failures;
    uint64_t runtime_checkpoint_failures;
    uint64_t runtime_optional_timer_exact_boundaries;
    uint64_t runtime_optional_timer_boundary_stalls;
    uint64_t runtime_timer_deadline_queries;
    uint64_t runtime_timer_deadline_rebuilds;
    uint64_t runtime_timer_deadline_probes;
    uint64_t runtime_idle_scan_calls;
    uint64_t runtime_idle_scan_probes;
    uint64_t runtime_idle_scan_gated_calls;
    uint64_t runtime_idle_scan_completed_cycles;
    uint64_t table_admission_rejects;
    uint64_t table_evidence_allocation_failures;
    uint64_t controlled_state_ceiling_bytes;
    uint64_t controlled_state_unassigned_bytes;
    uint64_t flow_table_reserved_bytes;
    uint64_t flow_table_current_bytes;
    uint64_t flow_table_peak_bytes;
    uint64_t quic_cid_reserved_bytes;
    uint64_t quic_cid_current_bytes;
    uint64_t quic_cid_peak_bytes;
    uint64_t quic_path_reserved_bytes;
    uint64_t quic_path_current_bytes;
    uint64_t quic_path_peak_bytes;
    uint64_t owner_binding_reserved_bytes;
    uint64_t owner_binding_current_bytes;
    uint64_t owner_binding_peak_bytes;
    /* Configured capacity and independently observed component topologies.
     * A successful terminal receipt requires all three actual capacities to
     * equal maximum_quic_connections_configured. */
    uint32_t maximum_quic_connections_configured;
    uint32_t quic_cid_connection_capacity;
    uint32_t quic_path_connection_capacity;
    uint32_t owner_binding_connection_capacity;
    uint64_t controlled_state_current_bytes;
    uint64_t controlled_state_peak_bytes;
    uint64_t controlled_state_hard_budget_violations;
    double controlled_state_byte_seconds;
    double state_byte_seconds_by_component[FK_MEMORY_COMPONENT_COUNT];
    uint8_t state_byte_seconds_complete;
    uint64_t flows_created;
    uint64_t flows_released;
    uint64_t active_flows;
    uint64_t peak_active_flows;
    struct fk_no_nic_optional_pool_result_v1 stat_pool;
    struct fk_no_nic_optional_pool_result_v1 seq_pool;
    struct fk_no_nic_optional_pool_result_v1 ja4_pending_pool;
    struct fk_no_nic_optional_pool_result_v1 ja4_summary_pool;
    uint64_t checkpoint_decisions;
    uint64_t value_model_calls;
    uint64_t value_model_failures;
    uint64_t value_inference_failures;
    uint64_t value_transition_failures;
    uint64_t value_inference_ns;
    uint64_t detector_inference_ns;
    uint64_t value_v3_cache_hits;
    uint64_t value_v3_cache_misses;
    uint64_t value_v3_inferences_avoided;
    uint64_t transition_value_calls;
    uint64_t transition_value_failures;
    uint64_t transition_value_inference_ns;
    uint64_t transition_value_fallback_attempts;
    uint64_t transition_value_fallback_successes;
    uint64_t action_selected_mask_counts[8];
    uint64_t action_pool_unavailable_records;
    uint64_t action_pool_unavailable_component_counts[3];
    uint64_t action_budget_rejections;
    uint64_t baseline_lru_victims_released;
    uint64_t baseline_lfu_victims_released;
    uint64_t baseline_fifo_victims_released;
    uint64_t baseline_seeded_random_victims_released;
    uint64_t automatic_pressure_transitions;
    uint64_t automatic_overload_transitions;
    uint64_t automatic_recovery_transitions;
    uint64_t action_transition_failure_counts[7];
    /* Append-only automatic-pressure contract receipt.  The denominator
     * counts only reclaimable optional evidence payload bytes. */
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
    /* Resolved at runtime configuration; index order is normal, pressure,
     * overload.  This receipt makes role-specific policy changes auditable. */
    uint8_t resolved_policy_maximum_components[3];
    uint8_t resolved_policy_preserve_full_state_in_normal;
    float resolved_policy_minimum_utility[3];
    uint64_t pressure_accounting_failures;
    uint64_t io_duplicate_reclaims;
    uint64_t io_live_mbufs;
    uint64_t io_forced_failure_reclaims;
    uint8_t partial_epoch_closed;
    uint8_t normal_complete;
    uint8_t abort_complete;
    uint8_t mbuf_ownership_conserved;
    uint8_t global_order_conserved;
    uint8_t topology_smoke_only;
    uint8_t source_exhausted;
    uint8_t source_failed;
    uint8_t bridge_sealed;
    uint8_t reorder_drained;
    uint8_t controlled_state_accounting_valid;
    uint8_t reserved[5];
    /* Append-only result ABI extension. */
    struct fk_no_nic_detection_service_capacity_receipt_v1
        detection_service_capacity;
    /* Append-only formal parser/disposition and QUIC identity audits. */
    uint64_t router_parser_successes;
    uint64_t router_parser_rejections_by_code[
        FK_PARSE_CAP_EXCEEDED + 1u];
    uint64_t owner_ordinary;
    uint64_t owner_quic;
    uint8_t router_parser_reason_conserved;
    uint8_t packet_disposition_conserved;
    uint8_t reserved_formal_audit[6];
    struct fk_no_nic_quic_identity_observability_v1 quic_identity;
};

void fk_no_nic_full_composition_default_config_init(
    struct fk_no_nic_full_composition_config *config);

bool fk_no_nic_full_composition_run(
    const struct fk_no_nic_full_composition_config *config,
    struct fk_no_nic_full_composition_result *result,
    char *error,
    size_t error_capacity);

/* Recomputes both semantic accounting and the canonical SHA-256. */
bool fk_no_nic_service_memory_receipt_verify_v1(
    const struct fk_no_nic_service_memory_receipt_v1 *receipt);

const char *fk_no_nic_service_memory_disposition_name_v1(uint8_t value);
const char *fk_no_nic_service_memory_auxiliary_component_name_v1(
    uint32_t value);

#ifdef __cplusplus
}
#endif

#endif
