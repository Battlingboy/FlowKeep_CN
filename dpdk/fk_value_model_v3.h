#ifndef FLOWKEEP_FK_VALUE_MODEL_V3_H
#define FLOWKEEP_FK_VALUE_MODEL_V3_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define FK_VALUE_MODEL_V3_CONTEXT_FEATURES 64u
#define FK_VALUE_MODEL_V3_QUERY_FEATURES 3u
#define FK_VALUE_MODEL_V3_MODEL_FEATURES 67u
#define FK_VALUE_MODEL_V3_ACTIONS 7u
#define FK_VALUE_MODEL_V3_OUTPUTS 14u
#define FK_VALUE_MODEL_V3_SCHEMA_SHA256_CHARS 64u
#define FK_VALUE_MODEL_V3_REQUESTED_ACTION_DOMAIN_SHA256 \
    "e09eca8eca55f9ef049f78415f7b74303476cd094b41840c2ff70cb0fd01e13d"
#define FK_VALUE_MODEL_V3_ONLINE_DEADLINE_CONTRACT_SHA256 \
    "8ae8ad1b3fa037a69b452647ac793b4324ea1c9e822d4c199a0f0794fabd8d8d"

enum fk_value_model_v3_family {
    FK_VALUE_MODEL_V3_RIDGE = 1,
    FK_VALUE_MODEL_V3_BOUNDED_TREE = 2,
    FK_VALUE_MODEL_V3_LIGHT_MLP = 3,
    /* Seven fixed 64D context heads selected by action mask.  The external
     * request contract remains ABI64 + query3 (67 model features / 14 outputs);
     * query bits select a head and are not learned as shared coefficients. */
    FK_VALUE_MODEL_V3_ACTION_RIDGE = 4,
    /* A 64D action-ridge gate fixes the cross-flow value scale; a bounded
     * per-action forest supplies only conditional action ordering.  The
     * fixed combiner preserves gate value density while avoiding incoherent
     * independent action selection. */
    FK_VALUE_MODEL_V3_HYBRID_GATE_FOREST = 5,
};

enum fk_value_model_v3_role {
    FK_VALUE_MODEL_V3_FLOWKEEP = 1,
    FK_VALUE_MODEL_V3_IMMEDIATE_RISK = 2,
    FK_VALUE_MODEL_V3_FUTURE_RISK = 3,
    FK_VALUE_MODEL_V3_DETECTION_LOSS = 4,
};

struct fk_value_model_v3_metadata {
    uint32_t format_version;
    enum fk_value_model_v3_family family;
    enum fk_value_model_v3_role role;
    uint32_t context_feature_count;
    uint32_t query_feature_count;
    uint32_t model_feature_count;
    uint32_t learned_action_count;
    uint32_t output_count;
    uint32_t node_count;
    uint32_t hidden_units;
    float conditional_equivalence_tolerance;
    uint32_t training_target_uses_detector_threshold;
    uint32_t formal_event_student_counterfactual_semantics_aligned;
    uint32_t detector_threshold_bits;
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
    uint64_t artifact_file_bytes;
    /* Exact C++ object plus vector-capacity payload requested by the loaded
     * model.  Allocator bookkeeping and the on-disk artifact are excluded. */
    uint64_t model_reserved_bytes;
};

struct fk_value_model_v3;

struct fk_value_model_v3 *fk_value_model_v3_load(
    const char *path,
    char *error,
    size_t error_capacity);

/* Hashes and parses the same open regular-file description, then verifies
 * that its inode/size/timestamps did not change. expected_artifact_sha256 is
 * required and must be lower-case hexadecimal. */
struct fk_value_model_v3 *fk_value_model_v3_load_verified(
    const char *path,
    const char *expected_artifact_sha256,
    char *error,
    size_t error_capacity);

void fk_value_model_v3_destroy(struct fk_value_model_v3 *model);

bool fk_value_model_v3_get_metadata(
    const struct fk_value_model_v3 *model,
    struct fk_value_model_v3_metadata *metadata);

/* action_mask is exactly 1..7. CORE is a fixed controller fallback and is
 * deliberately not a learned action/head. */
bool fk_value_model_v3_predict_action(
    const struct fk_value_model_v3 *model,
    const float context[FK_VALUE_MODEL_V3_CONTEXT_FEATURES],
    uint8_t action_mask,
    float *mean,
    float *uncertainty);

/* Output order is means for masks 1..7 followed by uncertainties 1..7. */
bool fk_value_model_v3_predict_all(
    const struct fk_value_model_v3 *model,
    const float context[FK_VALUE_MODEL_V3_CONTEXT_FEATURES],
    float outputs[FK_VALUE_MODEL_V3_OUTPUTS]);

#ifdef __cplusplus
}
#endif

#endif
