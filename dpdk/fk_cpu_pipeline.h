#ifndef FLOWKEEP_FK_CPU_PIPELINE_H
#define FLOWKEEP_FK_CPU_PIPELINE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "fk_component_state.h"
#include "fk_value_model_v3.h"

#ifdef __cplusplus
extern "C" {
#endif

struct fk_cpu_pipeline_stats {
    uint64_t value_calls;
    uint64_t value_failures;
    uint64_t value_inference_failures;
    uint64_t value_transition_failures;
    uint64_t detector_calls;
    uint64_t detector_failures;
    uint64_t value_inference_ns;
    uint64_t detector_inference_ns;
    uint64_t value_v3_inferences;
    uint64_t value_v3_inference_failures;
    uint64_t value_v3_core_zero_violations;
    uint64_t transition_value_calls;
    uint64_t transition_value_failures;
    uint64_t transition_value_inference_ns;
};

enum fk_cpu_pipeline_action_model_kind {
    FK_CPU_PIPELINE_ACTION_LEGACY_30D = 0,
    FK_CPU_PIPELINE_ACTION_VALUE_V3_64D = 1,
    FK_CPU_PIPELINE_ACTION_NONE = 2,
};

struct fk_cpu_pipeline_action_model_metadata {
    enum fk_cpu_pipeline_action_model_kind kind;
    enum fk_value_model_v3_family v3_family;
    enum fk_value_model_v3_role v3_role;
    uint32_t format_version;
    uint32_t context_feature_count;
    uint32_t query_feature_count;
    uint32_t model_feature_count;
    uint32_t learned_action_count;
    uint32_t output_count;
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
    char artifact_sha256[FK_VALUE_MODEL_V3_SCHEMA_SHA256_CHARS + 1u];
};

struct fk_resource_costs {
    float completion_probability[8];
    float queue_cost[8];
    float deadline_cost[8];
    float lambda_memory_per_byte;
    float lambda_queue;
    float lambda_deadline;
    /* Uniform per-action retention discount applied after value recovery.
     * A positive value raises the retention bar without changing the
     * relative ranking of non-empty actions (same discount for all). */
    float retention_discount;
    /* Model-level conformal radii are shared by all flows. Keeping them here
     * avoids adding any per-flow bytes to the hard controlled-state budget. */
    float action_uncertainty[8];
    /* 0 uses the conservative one-sided lower bound; 1 recovers the frozen
     * packet-4 conditional mean. Intermediate values are selected online
     * from current hard-budget slack, never from labels or suffix traffic. */
    float uncertainty_recovery;
};

struct fk_cpu_pipeline;

bool fk_cpu_pipeline_get_action_uncertainty(
    const struct fk_cpu_pipeline *pipeline,
    float uncertainty[8]);

struct fk_cpu_pipeline *fk_cpu_pipeline_create(
    const char *action_value_model_path,
    const char *detector_model_path,
    char *error,
    size_t error_capacity);

struct fk_cpu_pipeline *fk_cpu_pipeline_create_verified(
    const char *action_value_model_path,
    const char *detector_model_path,
    const char *expected_action_schema_sha256,
    const char *expected_detector_schema_sha256,
    char *error,
    size_t error_capacity);

/* detector_model_paths[1..7] are required; index 0 is unused. */
struct fk_cpu_pipeline *fk_cpu_pipeline_create_seven_state_verified(
    const char *action_value_model_path,
    const char *const detector_model_paths[8],
    const char *expected_action_schema_sha256,
    const char *expected_detector_schema_sha256,
    char *error,
    size_t error_capacity);

/* Dedicated ABI64 constructors.  expected_role must be one of the four
 * frozen FKVM3 roles and is matched exactly; there is no file-format or role
 * autodetection. expected_artifact_sha256 is mandatory. */
struct fk_cpu_pipeline *fk_cpu_pipeline_create_value_v3_verified(
    const char *action_value_model_path,
    const char *detector_model_path,
    enum fk_value_model_v3_role expected_role,
    const char *expected_action_schema_sha256,
    const char *expected_action_artifact_sha256,
    const char *expected_detector_schema_sha256,
    char *error,
    size_t error_capacity);

struct fk_cpu_pipeline *fk_cpu_pipeline_create_seven_state_value_v3_verified(
    const char *action_value_model_path,
    const char *const detector_model_paths[8],
    enum fk_value_model_v3_role expected_role,
    const char *expected_action_schema_sha256,
    const char *expected_action_artifact_sha256,
    const char *expected_detector_schema_sha256,
    char *error,
    size_t error_capacity);

/* Deterministic retention baselines still share the exact detector path but
 * have no value selector artifact, load, reserved bytes, or calls. */
struct fk_cpu_pipeline *fk_cpu_pipeline_create_detector_only_verified(
    const char *detector_model_path,
    const char *expected_detector_schema_sha256,
    char *error,
    size_t error_capacity);

struct fk_cpu_pipeline *fk_cpu_pipeline_create_seven_state_detector_only_verified(
    const char *const detector_model_paths[8],
    const char *expected_detector_schema_sha256,
    char *error,
    size_t error_capacity);

void fk_cpu_pipeline_destroy(struct fk_cpu_pipeline *pipeline);

/* Attach the independently selected replacement-value head.  The head is
 * optional and never changes within-flow action selection. */
bool fk_cpu_pipeline_attach_transition_value_verified(
    struct fk_cpu_pipeline *pipeline,
    const char *transition_model_path,
    const char *expected_transition_schema_sha256,
    const char *expected_transition_artifact_sha256,
    char *error,
    size_t error_capacity);

bool fk_cpu_pipeline_has_transition_value(
    const struct fk_cpu_pipeline *pipeline);

bool fk_cpu_pipeline_predict_transition_value(
    struct fk_cpu_pipeline *pipeline,
    const float *context_features,
    size_t context_feature_count,
    uint8_t kept_mask,
    uint8_t released_mask,
    float *transition_value);

/* Construct one bounded potential vector around base_mask.  Subset values
 * receive a monotone loss closure so sequential component releases telescope
 * to a nonnegative total causal loss. */
bool fk_cpu_pipeline_build_transition_potentials(
    struct fk_cpu_pipeline *pipeline,
    const float *context_features,
    size_t context_feature_count,
    uint8_t base_mask,
    float potentials[8]);

/* Predict the current causal-prefix V_t(mask) vector without mutating flow
 * state.  The compact controller publishes it together with refreshed
 * cross-flow replacement indexes before planning a transition. */
bool fk_cpu_pipeline_predict_action_values(
    struct fk_cpu_pipeline *pipeline,
    struct fk_component_flow *flow,
    const float *features,
    size_t feature_count,
    float action_values[8]);

/* Apply the common completion/queue/deadline/resource costs to a frozen
 * action-value vector.  Non-materializable masks are returned as NaN. */
bool fk_cpu_pipeline_compute_action_utilities(
    const struct fk_component_flow *flow,
    const float action_values[8],
    const struct fk_component_bytes *component_bytes,
    const struct fk_resource_costs *resource_costs,
    uint8_t available_mask,
    float utilities[8]);

bool fk_cpu_pipeline_choose_state(
    struct fk_cpu_pipeline *pipeline,
    struct fk_state_budget *budget,
    struct fk_component_flow *flow,
    const float *features,
    size_t feature_count,
    const struct fk_component_bytes *component_bytes,
    const struct fk_resource_costs *resource_costs,
    bool ja4_applicable,
    enum fk_pressure_mode pressure,
    uint32_t packet_count,
    uint64_t timestamp_ns,
    const struct fk_component_policy_config *config,
    struct fk_component_decision *decision);

/*
 * Pool-aware variant. available_mask is the subset of STAT/SEQ/JA4 that the
 * owning state shard can materialize atomically at this checkpoint.
 */
bool fk_cpu_pipeline_choose_state_available(
    struct fk_cpu_pipeline *pipeline,
    struct fk_state_budget *budget,
    struct fk_component_flow *flow,
    const float *features,
    size_t feature_count,
    const struct fk_component_bytes *component_bytes,
    const struct fk_resource_costs *resource_costs,
    uint8_t available_mask,
    bool ja4_applicable,
    enum fk_pressure_mode pressure,
    uint32_t packet_count,
    uint64_t timestamp_ns,
    const struct fk_component_policy_config *config,
    struct fk_component_decision *decision);

/*
 * Offline-oracle/diagnostic entry points.  The supplied eight action values
 * bypass only value-model inference; they still traverse the exact common
 * completion, memory, queue and deadline costs, protocol legality,
 * irreversible-release rules, hard budget, and component-state controller.
 * They must not be exposed as a live deployable oracle policy.
 */
bool fk_cpu_pipeline_choose_state_from_values(
    struct fk_state_budget *budget,
    struct fk_component_flow *flow,
    const float *action_values,
    size_t action_value_count,
    const struct fk_component_bytes *component_bytes,
    const struct fk_resource_costs *resource_costs,
    bool ja4_applicable,
    enum fk_pressure_mode pressure,
    uint32_t packet_count,
    uint64_t timestamp_ns,
    const struct fk_component_policy_config *config,
    struct fk_component_decision *decision);

bool fk_cpu_pipeline_choose_state_from_values_available(
    struct fk_state_budget *budget,
    struct fk_component_flow *flow,
    const float *action_values,
    size_t action_value_count,
    const struct fk_component_bytes *component_bytes,
    const struct fk_resource_costs *resource_costs,
    uint8_t available_mask,
    bool ja4_applicable,
    enum fk_pressure_mode pressure,
    uint32_t packet_count,
    uint64_t timestamp_ns,
    const struct fk_component_policy_config *config,
    struct fk_component_decision *decision);

bool fk_cpu_pipeline_detect(
    struct fk_cpu_pipeline *pipeline,
    const float *features,
    size_t feature_count,
    float *score);

bool fk_cpu_pipeline_detect_state(
    struct fk_cpu_pipeline *pipeline,
    uint8_t state_mask,
    const float *features,
    size_t feature_count,
    float *score);

bool fk_cpu_pipeline_get_stats(
    const struct fk_cpu_pipeline *pipeline,
    struct fk_cpu_pipeline_stats *stats);

bool fk_cpu_pipeline_feature_counts(
    const struct fk_cpu_pipeline *pipeline,
    uint32_t *action_feature_count,
    uint32_t *detector_feature_count);

bool fk_cpu_pipeline_get_action_model_metadata(
    const struct fk_cpu_pipeline *pipeline,
    struct fk_cpu_pipeline_action_model_metadata *metadata);

#ifdef __cplusplus
}
#endif

#endif
