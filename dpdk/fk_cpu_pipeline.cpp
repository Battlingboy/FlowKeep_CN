#include "fk_cpu_pipeline.h"

#include "fk_cpu_model.h"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cmath>
#include <cstdio>
#include <cstring>
#include <limits>
#include <new>

namespace {

struct CpuPipeline {
    fk_cpu_model *action_value = nullptr;
    fk_value_model_v3 *action_value_v3 = nullptr;
    fk_cpu_model *transition_value = nullptr;
    fk_cpu_model *detectors[8]{};
    bool seven_state_detectors = false;
    fk_cpu_pipeline_action_model_metadata action_metadata{};
    uint32_t action_feature_count = 0u;
    uint32_t detector_feature_count = 0u;
    float action_uncertainty[8]{};
    std::atomic<uint64_t> value_calls{0u};
    std::atomic<uint64_t> value_failures{0u};
    std::atomic<uint64_t> value_inference_failures{0u};
    std::atomic<uint64_t> value_transition_failures{0u};
    std::atomic<uint64_t> detector_calls{0u};
    std::atomic<uint64_t> detector_failures{0u};
    std::atomic<uint64_t> value_inference_ns{0u};
    std::atomic<uint64_t> detector_inference_ns{0u};
    std::atomic<uint64_t> value_v3_inferences{0u};
    std::atomic<uint64_t> value_v3_inference_failures{0u};
    std::atomic<uint64_t> value_v3_core_zero_violations{0u};
    std::atomic<uint64_t> transition_value_calls{0u};
    std::atomic<uint64_t> transition_value_failures{0u};
    std::atomic<uint64_t> transition_value_inference_ns{0u};
};

constexpr uint32_t kTransitionContextFeatures = 64u;
constexpr uint32_t kTransitionQueryFeatures = 6u;
constexpr uint32_t kTransitionModelFeatures =
    kTransitionContextFeatures + kTransitionQueryFeatures;

static CpuPipeline *implementation(fk_cpu_pipeline *pipeline) {
    return reinterpret_cast<CpuPipeline *>(pipeline);
}

static const CpuPipeline *implementation(const fk_cpu_pipeline *pipeline) {
    return reinterpret_cast<const CpuPipeline *>(pipeline);
}

static void set_error(char *error, size_t capacity, const char *message) {
    if (error != nullptr && capacity != 0u)
        std::snprintf(error, capacity, "%s", message);
}

static bool valid_v3_role(fk_value_model_v3_role role) {
    return role >= FK_VALUE_MODEL_V3_FLOWKEEP &&
        role <= FK_VALUE_MODEL_V3_DETECTION_LOSS;
}

static bool load_value_v3(
        CpuPipeline &pipeline,
        const char *path,
        fk_value_model_v3_role expected_role,
        const char *expected_schema,
        const char *expected_artifact_sha256,
        char *error,
        size_t error_capacity) {
    pipeline.action_metadata = {};
    pipeline.action_metadata.kind = FK_CPU_PIPELINE_ACTION_VALUE_V3_64D;
    pipeline.action_metadata.load_attempts = 1u;
    if (!valid_v3_role(expected_role) || expected_schema == nullptr ||
        expected_artifact_sha256 == nullptr) {
        pipeline.action_metadata.load_failures = 1u;
        set_error(error, error_capacity, "invalid value-v3 expectation");
        return false;
    }
    pipeline.action_value_v3 = fk_value_model_v3_load_verified(
        path, expected_artifact_sha256, error, error_capacity);
    fk_value_model_v3_metadata metadata{};
    if (pipeline.action_value_v3 == nullptr ||
        !fk_value_model_v3_get_metadata(
            pipeline.action_value_v3, &metadata) ||
        metadata.role != expected_role ||
        std::strcmp(
            metadata.online_context_schema_sha256,
            expected_schema) != 0) {
        fk_value_model_v3_destroy(pipeline.action_value_v3);
        pipeline.action_value_v3 = nullptr;
        pipeline.action_metadata.load_failures = 1u;
        set_error(error, error_capacity, "value-v3 role/schema/hash mismatch");
        return false;
    }
    pipeline.action_metadata.kind = FK_CPU_PIPELINE_ACTION_VALUE_V3_64D;
    pipeline.action_metadata.v3_family = metadata.family;
    pipeline.action_metadata.v3_role = metadata.role;
    pipeline.action_metadata.format_version = metadata.format_version;
    pipeline.action_metadata.context_feature_count =
        metadata.context_feature_count;
    pipeline.action_metadata.query_feature_count = metadata.query_feature_count;
    pipeline.action_metadata.model_feature_count = metadata.model_feature_count;
    pipeline.action_metadata.learned_action_count =
        metadata.learned_action_count;
    pipeline.action_metadata.output_count = metadata.output_count;
    pipeline.action_metadata.conditional_equivalence_tolerance =
        metadata.conditional_equivalence_tolerance;
    pipeline.action_metadata.training_target_uses_detector_threshold =
        metadata.training_target_uses_detector_threshold;
    pipeline.action_metadata.formal_event_student_counterfactual_semantics_aligned =
        metadata.formal_event_student_counterfactual_semantics_aligned;
    pipeline.action_metadata.detector_threshold_bits =
        metadata.detector_threshold_bits;
    pipeline.action_metadata.artifact_file_bytes = metadata.artifact_file_bytes;
    pipeline.action_metadata.model_reserved_bytes = metadata.model_reserved_bytes;
    /* ABI64 context is a checkpoint-local stack array.  Per-flow serving
     * reuses the pre-existing eight-float frozen action vector. */
    pipeline.action_metadata.frozen_context_reserved_bytes = 0u;
    pipeline.action_metadata.load_successes = 1u;
    std::memcpy(
        pipeline.action_metadata.online_context_schema_sha256,
        metadata.online_context_schema_sha256,
        sizeof(metadata.online_context_schema_sha256));
    std::memcpy(
        pipeline.action_metadata.requested_action_domain_sha256,
        metadata.requested_action_domain_sha256,
        sizeof(metadata.requested_action_domain_sha256));
    std::memcpy(
        pipeline.action_metadata.online_deadline_contract_sha256,
        metadata.online_deadline_contract_sha256,
        sizeof(metadata.online_deadline_contract_sha256));
    std::memcpy(
        pipeline.action_metadata.detector_threshold_binding_sha256,
        metadata.detector_threshold_binding_sha256,
        sizeof(metadata.detector_threshold_binding_sha256));
    std::memcpy(
        pipeline.action_metadata.detector_threshold_selection_receipt_sha256,
        metadata.detector_threshold_selection_receipt_sha256,
        sizeof(metadata.detector_threshold_selection_receipt_sha256));
    std::memcpy(
        pipeline.action_metadata.detector_operating_point_receipt_sha256,
        metadata.detector_operating_point_receipt_sha256,
        sizeof(metadata.detector_operating_point_receipt_sha256));
    std::memcpy(
        pipeline.action_metadata.artifact_sha256,
        metadata.artifact_sha256,
        sizeof(metadata.artifact_sha256));
    pipeline.action_feature_count = metadata.context_feature_count;
    float zero_context[FK_VALUE_MODEL_V3_CONTEXT_FEATURES]{};
    float zero_outputs[FK_VALUE_MODEL_V3_OUTPUTS]{};
    if (!fk_value_model_v3_predict_all(
            pipeline.action_value_v3, zero_context, zero_outputs)) {
        fk_value_model_v3_destroy(pipeline.action_value_v3);
        pipeline.action_value_v3 = nullptr;
        pipeline.action_metadata.load_successes = 0u;
        pipeline.action_metadata.load_failures = 1u;
        set_error(error, error_capacity, "value-v3 uncertainty unavailable");
        return false;
    }
    pipeline.action_uncertainty[0] = 0.0f;
    for (uint8_t action = 1u; action <= FK_VALUE_MODEL_V3_ACTIONS; ++action) {
        pipeline.action_uncertainty[action] =
            zero_outputs[FK_VALUE_MODEL_V3_ACTIONS + action - 1u];
        if (!std::isfinite(pipeline.action_uncertainty[action]) ||
            pipeline.action_uncertainty[action] < 0.0f) {
            fk_value_model_v3_destroy(pipeline.action_value_v3);
            pipeline.action_value_v3 = nullptr;
            pipeline.action_metadata.load_successes = 0u;
            pipeline.action_metadata.load_failures = 1u;
            set_error(error, error_capacity, "invalid value-v3 uncertainty");
            return false;
        }
    }
    return true;
}

static bool load_one_detector(
        CpuPipeline &pipeline,
        uint8_t index,
        const char *path,
        const char *expected_schema,
        fk_cpu_model_metadata *metadata,
        char *error,
        size_t error_capacity) {
    pipeline.detectors[index] = fk_cpu_model_load(path, error, error_capacity);
    return pipeline.detectors[index] != nullptr &&
        fk_cpu_model_get_metadata(pipeline.detectors[index], metadata) &&
        metadata->role == FK_CPU_MODEL_DETECTOR &&
        metadata->output_count == 1u &&
        (expected_schema == nullptr ||
         std::strcmp(metadata->feature_schema_sha256, expected_schema) == 0);
}

static uint64_t state_bytes(
        uint8_t mask,
        const fk_component_bytes &bytes,
        const fk_component_flow &flow) {
    uint64_t total = 0u;
    if ((mask & FK_COMPONENT_STAT) != 0u) {
        total += flow.decision_started != 0u &&
                (flow.mask & FK_COMPONENT_STAT) != 0u
            ? flow.owned.stat_bytes : bytes.stat_bytes;
    }
    if ((mask & FK_COMPONENT_SEQ) != 0u) {
        total += flow.decision_started != 0u &&
                (flow.mask & FK_COMPONENT_SEQ) != 0u
            ? flow.owned.seq_bytes : bytes.seq_bytes;
    }
    if ((mask & FK_COMPONENT_JA4) != 0u) {
        total += flow.decision_started != 0u &&
                (flow.mask & FK_COMPONENT_JA4) != 0u
            ? flow.owned.ja4_bytes : bytes.ja4_bytes;
    }
    return total;
}

static bool valid_resource_costs(const fk_resource_costs &costs) {
    if (!std::isfinite(costs.lambda_memory_per_byte) ||
        !std::isfinite(costs.lambda_queue) ||
        !std::isfinite(costs.lambda_deadline) ||
        !std::isfinite(costs.retention_discount) ||
        !std::isfinite(costs.uncertainty_recovery) ||
        costs.lambda_memory_per_byte < 0.0f ||
        costs.lambda_queue < 0.0f ||
        costs.lambda_deadline < 0.0f ||
        costs.retention_discount < 0.0f ||
        costs.uncertainty_recovery < 0.0f ||
        costs.uncertainty_recovery > 1.0f)
        return false;
    for (std::size_t mask = 0u; mask < 8u; ++mask) {
        if (!std::isfinite(costs.completion_probability[mask]) ||
            !std::isfinite(costs.queue_cost[mask]) ||
            !std::isfinite(costs.deadline_cost[mask]) ||
            costs.completion_probability[mask] < 0.0f ||
            costs.completion_probability[mask] > 1.0f ||
            costs.queue_cost[mask] < 0.0f ||
            costs.deadline_cost[mask] < 0.0f)
            return false;
    }
    return true;
}

static bool choose_state_from_values_available(
        fk_state_budget *budget,
        fk_component_flow *flow,
        const float *action_values,
        size_t action_value_count,
        const fk_component_bytes *component_bytes,
        const fk_resource_costs *resource_costs,
        uint8_t available_mask,
        bool ja4_applicable,
        fk_pressure_mode pressure,
        uint32_t packet_count,
        uint64_t timestamp_ns,
        const fk_component_policy_config *config,
        fk_component_decision *decision) {
    if (budget == nullptr || flow == nullptr || action_values == nullptr ||
        action_value_count != 8u || component_bytes == nullptr ||
        resource_costs == nullptr || config == nullptr ||
        decision == nullptr)
        return false;
    float utilities[8]{};
    if (!fk_cpu_pipeline_compute_action_utilities(
            flow,
            action_values,
            component_bytes,
            resource_costs,
            available_mask,
            utilities))
        return false;
    return fk_component_choose_and_transition(
        budget,
        flow,
        utilities,
        component_bytes,
        ja4_applicable,
        pressure,
        packet_count,
        timestamp_ns,
        config,
        decision);
}

}  // namespace

extern "C" {

bool fk_cpu_pipeline_get_action_uncertainty(
        const fk_cpu_pipeline *pipeline,
        float uncertainty[8]) {
    if (pipeline == nullptr || uncertainty == nullptr)
        return false;
    const CpuPipeline &state = *implementation(pipeline);
    if (state.action_metadata.kind !=
            FK_CPU_PIPELINE_ACTION_VALUE_V3_64D)
        return false;
    std::copy_n(state.action_uncertainty, 8u, uncertainty);
    return true;
}

fk_cpu_pipeline *fk_cpu_pipeline_create(
        const char *action_value_model_path,
        const char *detector_model_path,
        char *error,
        size_t error_capacity) {
    return fk_cpu_pipeline_create_verified(
        action_value_model_path,
        detector_model_path,
        nullptr,
        nullptr,
        error,
        error_capacity);
}

fk_cpu_pipeline *fk_cpu_pipeline_create_verified(
        const char *action_value_model_path,
        const char *detector_model_path,
        const char *expected_action_schema_sha256,
        const char *expected_detector_schema_sha256,
        char *error,
        size_t error_capacity) {
    set_error(error, error_capacity, "");
    CpuPipeline *pipeline = new (std::nothrow) CpuPipeline();
    if (pipeline == nullptr) {
        set_error(error, error_capacity, "pipeline allocation failed");
        return nullptr;
    }
    pipeline->action_value = fk_cpu_model_load(
        action_value_model_path, error, error_capacity);
    if (pipeline->action_value == nullptr) {
        delete pipeline;
        return nullptr;
    }
    pipeline->detectors[0] = fk_cpu_model_load(
        detector_model_path, error, error_capacity);
    if (pipeline->detectors[0] == nullptr) {
        fk_cpu_model_destroy(pipeline->action_value);
        delete pipeline;
        return nullptr;
    }
    fk_cpu_model_metadata action_metadata{};
    fk_cpu_model_metadata detector_metadata{};
    if (!fk_cpu_model_get_metadata(
            pipeline->action_value, &action_metadata) ||
        !fk_cpu_model_get_metadata(
            pipeline->detectors[0], &detector_metadata) ||
        action_metadata.role != FK_CPU_MODEL_ACTION_VALUE ||
        action_metadata.output_count != 8u ||
        detector_metadata.role != FK_CPU_MODEL_DETECTOR ||
        detector_metadata.output_count != 1u ||
        (expected_action_schema_sha256 != nullptr &&
         std::strcmp(
             action_metadata.feature_schema_sha256,
             expected_action_schema_sha256) != 0) ||
        (expected_detector_schema_sha256 != nullptr &&
         std::strcmp(
             detector_metadata.feature_schema_sha256,
             expected_detector_schema_sha256) != 0)) {
        fk_cpu_model_destroy(pipeline->action_value);
        fk_cpu_model_destroy(pipeline->detectors[0]);
        delete pipeline;
        set_error(
            error,
            error_capacity,
            "model role/output/feature-schema mismatch");
        return nullptr;
    }
    pipeline->action_feature_count = action_metadata.feature_count;
    pipeline->detector_feature_count = detector_metadata.feature_count;
    pipeline->action_metadata.kind = FK_CPU_PIPELINE_ACTION_LEGACY_30D;
    pipeline->action_metadata.format_version = action_metadata.format_version;
    pipeline->action_metadata.context_feature_count =
        action_metadata.feature_count;
    pipeline->action_metadata.learned_action_count =
        action_metadata.output_count;
    pipeline->action_metadata.output_count = action_metadata.output_count;
    pipeline->action_metadata.load_attempts = 1u;
    pipeline->action_metadata.load_successes = 1u;
    std::memcpy(
        pipeline->action_metadata.online_context_schema_sha256,
        action_metadata.feature_schema_sha256,
        sizeof(action_metadata.feature_schema_sha256));
    return reinterpret_cast<fk_cpu_pipeline *>(pipeline);
}

fk_cpu_pipeline *fk_cpu_pipeline_create_seven_state_verified(
        const char *action_value_model_path,
        const char *const detector_model_paths[8],
        const char *expected_action_schema_sha256,
        const char *expected_detector_schema_sha256,
        char *error,
        size_t error_capacity) {
    set_error(error, error_capacity, "");
    if (detector_model_paths == nullptr) {
        set_error(error, error_capacity, "seven-state detector paths are absent");
        return nullptr;
    }
    CpuPipeline *pipeline = new (std::nothrow) CpuPipeline();
    if (pipeline == nullptr) {
        set_error(error, error_capacity, "pipeline allocation failed");
        return nullptr;
    }
    pipeline->action_value = fk_cpu_model_load(
        action_value_model_path, error, error_capacity);
    fk_cpu_model_metadata action_metadata{};
    if (pipeline->action_value == nullptr ||
        !fk_cpu_model_get_metadata(pipeline->action_value, &action_metadata) ||
        action_metadata.role != FK_CPU_MODEL_ACTION_VALUE ||
        action_metadata.output_count != 8u ||
        (expected_action_schema_sha256 != nullptr &&
         std::strcmp(action_metadata.feature_schema_sha256,
                     expected_action_schema_sha256) != 0)) {
        fk_cpu_model_destroy(pipeline->action_value);
        delete pipeline;
        set_error(error, error_capacity, "action model role/schema mismatch");
        return nullptr;
    }
    fk_cpu_model_metadata first{};
    bool valid = true;
    for (uint8_t mask = 0u; valid && mask < 8u; ++mask) {
        pipeline->detectors[mask] = fk_cpu_model_load(
            detector_model_paths[mask], error, error_capacity);
        fk_cpu_model_metadata metadata{};
        valid = pipeline->detectors[mask] != nullptr &&
            fk_cpu_model_get_metadata(pipeline->detectors[mask], &metadata) &&
            metadata.role == FK_CPU_MODEL_DETECTOR &&
            metadata.output_count == 1u &&
            (expected_detector_schema_sha256 == nullptr ||
             std::strcmp(metadata.feature_schema_sha256,
                         expected_detector_schema_sha256) == 0);
        if (valid && mask == 0u)
            first = metadata;
        else if (valid)
            valid = metadata.feature_count == first.feature_count &&
                std::strcmp(metadata.feature_schema_sha256,
                            first.feature_schema_sha256) == 0;
    }
    if (!valid) {
        fk_cpu_model_destroy(pipeline->action_value);
        for (uint8_t mask = 0u; mask < 8u; ++mask)
            fk_cpu_model_destroy(pipeline->detectors[mask]);
        delete pipeline;
        set_error(error, error_capacity, "seven-state detector role/schema mismatch");
        return nullptr;
    }
    pipeline->seven_state_detectors = true;
    pipeline->action_feature_count = action_metadata.feature_count;
    pipeline->detector_feature_count = first.feature_count;
    pipeline->action_metadata.kind = FK_CPU_PIPELINE_ACTION_LEGACY_30D;
    pipeline->action_metadata.format_version = action_metadata.format_version;
    pipeline->action_metadata.context_feature_count =
        action_metadata.feature_count;
    pipeline->action_metadata.learned_action_count =
        action_metadata.output_count;
    pipeline->action_metadata.output_count = action_metadata.output_count;
    pipeline->action_metadata.load_attempts = 1u;
    pipeline->action_metadata.load_successes = 1u;
    std::memcpy(
        pipeline->action_metadata.online_context_schema_sha256,
        action_metadata.feature_schema_sha256,
        sizeof(action_metadata.feature_schema_sha256));
    return reinterpret_cast<fk_cpu_pipeline *>(pipeline);
}

fk_cpu_pipeline *fk_cpu_pipeline_create_value_v3_verified(
        const char *action_value_model_path,
        const char *detector_model_path,
        fk_value_model_v3_role expected_role,
        const char *expected_action_schema_sha256,
        const char *expected_action_artifact_sha256,
        const char *expected_detector_schema_sha256,
        char *error,
        size_t error_capacity) {
    set_error(error, error_capacity, "");
    CpuPipeline *pipeline = new (std::nothrow) CpuPipeline();
    if (pipeline == nullptr) {
        set_error(error, error_capacity, "pipeline allocation failed");
        return nullptr;
    }
    fk_cpu_model_metadata detector_metadata{};
    if (!load_value_v3(
            *pipeline,
            action_value_model_path,
            expected_role,
            expected_action_schema_sha256,
            expected_action_artifact_sha256,
            error,
            error_capacity) ||
        !load_one_detector(
            *pipeline,
            0u,
            detector_model_path,
            expected_detector_schema_sha256,
            &detector_metadata,
            error,
            error_capacity)) {
        fk_value_model_v3_destroy(pipeline->action_value_v3);
        fk_cpu_model_destroy(pipeline->detectors[0]);
        delete pipeline;
        if (error != nullptr && error_capacity != 0u && error[0] == '\0')
            set_error(error, error_capacity, "value-v3 pipeline load failed");
        return nullptr;
    }
    pipeline->detector_feature_count = detector_metadata.feature_count;
    return reinterpret_cast<fk_cpu_pipeline *>(pipeline);
}

fk_cpu_pipeline *fk_cpu_pipeline_create_seven_state_value_v3_verified(
        const char *action_value_model_path,
        const char *const detector_model_paths[8],
        fk_value_model_v3_role expected_role,
        const char *expected_action_schema_sha256,
        const char *expected_action_artifact_sha256,
        const char *expected_detector_schema_sha256,
        char *error,
        size_t error_capacity) {
    set_error(error, error_capacity, "");
    if (detector_model_paths == nullptr) {
        set_error(error, error_capacity, "seven-state detector paths are absent");
        return nullptr;
    }
    CpuPipeline *pipeline = new (std::nothrow) CpuPipeline();
    if (pipeline == nullptr) {
        set_error(error, error_capacity, "pipeline allocation failed");
        return nullptr;
    }
    bool valid = load_value_v3(
        *pipeline,
        action_value_model_path,
        expected_role,
        expected_action_schema_sha256,
        expected_action_artifact_sha256,
        error,
        error_capacity);
    fk_cpu_model_metadata first{};
    for (uint8_t mask = 0u; valid && mask < 8u; ++mask) {
        fk_cpu_model_metadata metadata{};
        valid = load_one_detector(
            *pipeline,
            mask,
            detector_model_paths[mask],
            expected_detector_schema_sha256,
            &metadata,
            error,
            error_capacity);
        if (valid && mask == 0u)
            first = metadata;
        else if (valid)
            valid = metadata.feature_count == first.feature_count &&
                std::strcmp(metadata.feature_schema_sha256,
                            first.feature_schema_sha256) == 0;
    }
    if (!valid) {
        fk_value_model_v3_destroy(pipeline->action_value_v3);
        for (uint8_t mask = 0u; mask < 8u; ++mask)
            fk_cpu_model_destroy(pipeline->detectors[mask]);
        delete pipeline;
        if (error != nullptr && error_capacity != 0u && error[0] == '\0')
            set_error(error, error_capacity,
                      "seven-state value-v3 pipeline load failed");
        return nullptr;
    }
    pipeline->seven_state_detectors = true;
    pipeline->detector_feature_count = first.feature_count;
    return reinterpret_cast<fk_cpu_pipeline *>(pipeline);
}

fk_cpu_pipeline *fk_cpu_pipeline_create_detector_only_verified(
        const char *detector_model_path,
        const char *expected_detector_schema_sha256,
        char *error,
        size_t error_capacity) {
    set_error(error, error_capacity, "");
    CpuPipeline *pipeline = new (std::nothrow) CpuPipeline();
    if (pipeline == nullptr) {
        set_error(error, error_capacity, "pipeline allocation failed");
        return nullptr;
    }
    fk_cpu_model_metadata metadata{};
    if (!load_one_detector(
            *pipeline,
            0u,
            detector_model_path,
            expected_detector_schema_sha256,
            &metadata,
            error,
            error_capacity)) {
        fk_cpu_model_destroy(pipeline->detectors[0]);
        delete pipeline;
        if (error != nullptr && error_capacity != 0u && error[0] == '\0')
            set_error(error, error_capacity, "detector-only pipeline load failed");
        return nullptr;
    }
    pipeline->action_metadata.kind = FK_CPU_PIPELINE_ACTION_NONE;
    pipeline->detector_feature_count = metadata.feature_count;
    return reinterpret_cast<fk_cpu_pipeline *>(pipeline);
}

fk_cpu_pipeline *fk_cpu_pipeline_create_seven_state_detector_only_verified(
        const char *const detector_model_paths[8],
        const char *expected_detector_schema_sha256,
        char *error,
        size_t error_capacity) {
    set_error(error, error_capacity, "");
    if (detector_model_paths == nullptr) {
        set_error(error, error_capacity, "seven-state detector paths are absent");
        return nullptr;
    }
    CpuPipeline *pipeline = new (std::nothrow) CpuPipeline();
    if (pipeline == nullptr) {
        set_error(error, error_capacity, "pipeline allocation failed");
        return nullptr;
    }
    fk_cpu_model_metadata first{};
    bool valid = true;
    for (uint8_t mask = 0u; valid && mask < 8u; ++mask) {
        fk_cpu_model_metadata metadata{};
        valid = load_one_detector(
            *pipeline,
            mask,
            detector_model_paths[mask],
            expected_detector_schema_sha256,
            &metadata,
            error,
            error_capacity);
        if (valid && mask == 0u)
            first = metadata;
        else if (valid)
            valid = metadata.feature_count == first.feature_count &&
                std::strcmp(metadata.feature_schema_sha256,
                            first.feature_schema_sha256) == 0;
    }
    if (!valid) {
        for (uint8_t mask = 0u; mask < 8u; ++mask)
            fk_cpu_model_destroy(pipeline->detectors[mask]);
        delete pipeline;
        if (error != nullptr && error_capacity != 0u && error[0] == '\0')
            set_error(error, error_capacity,
                      "seven-state detector-only pipeline load failed");
        return nullptr;
    }
    pipeline->action_metadata.kind = FK_CPU_PIPELINE_ACTION_NONE;
    pipeline->seven_state_detectors = true;
    pipeline->detector_feature_count = first.feature_count;
    return reinterpret_cast<fk_cpu_pipeline *>(pipeline);
}

void fk_cpu_pipeline_destroy(fk_cpu_pipeline *pipeline) {
    if (pipeline == nullptr)
        return;
    CpuPipeline *state = implementation(pipeline);
    fk_cpu_model_destroy(state->action_value);
    fk_value_model_v3_destroy(state->action_value_v3);
    fk_cpu_model_destroy(state->transition_value);
    for (uint8_t mask = 0u; mask < 8u; ++mask)
        fk_cpu_model_destroy(state->detectors[mask]);
    delete state;
}

bool fk_cpu_pipeline_attach_transition_value_verified(
        fk_cpu_pipeline *pipeline,
        const char *transition_model_path,
        const char *expected_transition_schema_sha256,
        const char *expected_transition_artifact_sha256,
        char *error,
        size_t error_capacity) {
    set_error(error, error_capacity, "");
    if (pipeline == nullptr || transition_model_path == nullptr ||
        expected_transition_schema_sha256 == nullptr ||
        expected_transition_artifact_sha256 == nullptr) {
        set_error(error, error_capacity, "invalid transition model binding");
        return false;
    }
    CpuPipeline &state = *implementation(pipeline);
    if (state.action_metadata.kind !=
            FK_CPU_PIPELINE_ACTION_VALUE_V3_64D ||
        state.transition_value != nullptr) {
        set_error(error, error_capacity,
                  "transition head requires one ABI64 value pipeline");
        return false;
    }
    fk_cpu_model *model = fk_cpu_model_load_verified(
        transition_model_path,
        expected_transition_artifact_sha256,
        error,
        error_capacity);
    fk_cpu_model_metadata metadata{};
    const bool valid = model != nullptr &&
        fk_cpu_model_get_metadata(model, &metadata) &&
        metadata.role == FK_CPU_MODEL_TRANSITION_VALUE &&
        metadata.link == FK_CPU_MODEL_IDENTITY &&
        metadata.feature_count == kTransitionModelFeatures &&
        metadata.output_count == 1u &&
        std::strcmp(metadata.feature_schema_sha256,
                    expected_transition_schema_sha256) == 0;
    if (!valid) {
        fk_cpu_model_destroy(model);
        if (error != nullptr && error_capacity != 0u && error[0] == '\0')
            set_error(error, error_capacity,
                      "transition role/link/schema/shape mismatch");
        return false;
    }
    state.transition_value = model;
    return true;
}

bool fk_cpu_pipeline_has_transition_value(
        const fk_cpu_pipeline *pipeline) {
    return pipeline != nullptr &&
        implementation(pipeline)->transition_value != nullptr;
}

bool fk_cpu_pipeline_predict_transition_value(
        fk_cpu_pipeline *pipeline,
        const float *context_features,
        size_t context_feature_count,
        uint8_t kept_mask,
        uint8_t released_mask,
        float *transition_value) {
    if (pipeline == nullptr || context_features == nullptr ||
        transition_value == nullptr ||
        context_feature_count != kTransitionContextFeatures ||
        kept_mask > FK_COMPONENT_FULL || released_mask > FK_COMPONENT_FULL ||
        (released_mask & ~kept_mask) != 0u)
        return false;
    CpuPipeline &state = *implementation(pipeline);
    if (state.transition_value == nullptr)
        return false;
    state.transition_value_calls.fetch_add(1u, std::memory_order_relaxed);
    const auto started = std::chrono::steady_clock::now();
    float features[kTransitionModelFeatures]{};
    std::copy_n(context_features, kTransitionContextFeatures, features);
    for (uint8_t index = 0u; index < 3u; ++index) {
        const uint8_t bit = static_cast<uint8_t>(1u << index);
        features[kTransitionContextFeatures + index] =
            (kept_mask & bit) != 0u ? 1.0f : 0.0f;
        features[kTransitionContextFeatures + 3u + index] =
            (released_mask & bit) != 0u ? 1.0f : 0.0f;
    }
    float raw = 0.0f;
    const bool valid = fk_cpu_model_predict(
        state.transition_value,
        features,
        kTransitionModelFeatures,
        &raw,
        1u) && std::isfinite(raw);
    state.transition_value_inference_ns.fetch_add(
        static_cast<uint64_t>(
            std::chrono::duration_cast<std::chrono::nanoseconds>(
                std::chrono::steady_clock::now() - started).count()),
        std::memory_order_relaxed);
    if (!valid) {
        state.transition_value_failures.fetch_add(
            1u, std::memory_order_relaxed);
        return false;
    }
    *transition_value = std::min(1.0f, std::max(0.0f, raw));
    return true;
}

bool fk_cpu_pipeline_build_transition_potentials(
        fk_cpu_pipeline *pipeline,
        const float *context_features,
        size_t context_feature_count,
        uint8_t base_mask,
        float potentials[8]) {
    if (pipeline == nullptr || context_features == nullptr ||
        potentials == nullptr || base_mask > FK_COMPONENT_FULL ||
        context_feature_count != kTransitionContextFeatures ||
        !fk_cpu_pipeline_has_transition_value(pipeline))
        return false;
    float subset_loss[8]{};
    for (uint8_t mask = 0u; mask < 8u; ++mask) {
        if (mask == base_mask)
            continue;
        if ((mask & ~base_mask) == 0u) {
            if (!fk_cpu_pipeline_predict_transition_value(
                    pipeline, context_features, context_feature_count,
                    base_mask, mask, &subset_loss[mask]))
                return false;
        }
    }
    /* A farther release cannot cost less than an immediate superset. */
    for (int retained = 2; retained >= 0; --retained) {
        for (uint8_t mask = 0u; mask < 8u; ++mask) {
            if ((mask & ~base_mask) != 0u ||
                __builtin_popcount(static_cast<unsigned int>(mask)) != retained)
                continue;
            for (uint8_t index = 0u; index < 3u; ++index) {
                const uint8_t bit = static_cast<uint8_t>(1u << index);
                const uint8_t parent = static_cast<uint8_t>(mask | bit);
                if ((base_mask & bit) != 0u)
                    subset_loss[mask] = std::max(
                        subset_loss[mask], subset_loss[parent]);
            }
        }
    }
    for (uint8_t mask = 0u; mask < 8u; ++mask) {
        if (mask == base_mask) {
            potentials[mask] = 0.0f;
        } else if ((mask & ~base_mask) == 0u) {
            potentials[mask] = -subset_loss[mask];
        } else if ((base_mask & ~mask) == 0u) {
            if (!fk_cpu_pipeline_predict_transition_value(
                    pipeline, context_features, context_feature_count,
                    mask, base_mask, &potentials[mask]))
                return false;
        } else {
            const uint8_t common = static_cast<uint8_t>(mask & base_mask);
            float gained = 0.0f;
            if (!fk_cpu_pipeline_predict_transition_value(
                    pipeline, context_features, context_feature_count,
                    mask, common, &gained))
                return false;
            potentials[mask] = gained - subset_loss[common];
        }
        if (!std::isfinite(potentials[mask]))
            return false;
    }
    return true;
}

bool fk_cpu_pipeline_predict_action_values(
        fk_cpu_pipeline *pipeline,
        fk_component_flow *flow,
        const float *features,
        size_t feature_count,
        float action_values[8]) {
    if (pipeline == nullptr || flow == nullptr || features == nullptr ||
        action_values == nullptr)
        return false;
    CpuPipeline &state = *implementation(pipeline);
    if (state.action_metadata.kind == FK_CPU_PIPELINE_ACTION_NONE)
        return false;
    state.value_calls.fetch_add(1u, std::memory_order_relaxed);
    const auto inference_start = std::chrono::steady_clock::now();
    bool predicted = feature_count == state.action_feature_count;
    if (state.action_metadata.kind ==
            FK_CPU_PIPELINE_ACTION_VALUE_V3_64D) {
        state.value_v3_inferences.fetch_add(1u, std::memory_order_relaxed);
        float outputs[FK_VALUE_MODEL_V3_OUTPUTS]{};
        predicted = predicted && fk_value_model_v3_predict_all(
            state.action_value_v3, features, outputs);
        if (predicted) {
            action_values[0] = 0.0f;
            for (uint8_t action = 1u;
                 action <= FK_VALUE_MODEL_V3_ACTIONS; ++action) {
                action_values[action] =
                    outputs[action - 1u] -
                    outputs[FK_VALUE_MODEL_V3_ACTIONS + action - 1u];
                predicted = predicted &&
                    std::isfinite(action_values[action]) &&
                    std::isfinite(
                        outputs[FK_VALUE_MODEL_V3_ACTIONS + action - 1u]) &&
                    outputs[FK_VALUE_MODEL_V3_ACTIONS + action - 1u] >= 0.0f;
            }
            if (action_values[0] != 0.0f) {
                state.value_v3_core_zero_violations.fetch_add(
                    1u, std::memory_order_relaxed);
                predicted = false;
            }
        }
        if (!predicted)
            state.value_v3_inference_failures.fetch_add(
                1u, std::memory_order_relaxed);
    } else if (predicted) {
        predicted = fk_cpu_model_predict(
            state.action_value,
            features,
            feature_count,
            action_values,
            8u);
    }
    if (!predicted) {
        state.value_inference_ns.fetch_add(
            static_cast<uint64_t>(
                std::chrono::duration_cast<std::chrono::nanoseconds>(
                    std::chrono::steady_clock::now() -
                    inference_start).count()),
            std::memory_order_relaxed);
        state.value_failures.fetch_add(1u, std::memory_order_relaxed);
        state.value_inference_failures.fetch_add(
            1u, std::memory_order_relaxed);
        return false;
    }
    state.value_inference_ns.fetch_add(
        static_cast<uint64_t>(
            std::chrono::duration_cast<std::chrono::nanoseconds>(
                std::chrono::steady_clock::now() -
                inference_start).count()),
        std::memory_order_relaxed);
    return true;
}

bool fk_cpu_pipeline_compute_action_utilities(
        const fk_component_flow *flow,
        const float action_values[8],
        const fk_component_bytes *component_bytes,
        const fk_resource_costs *resource_costs,
        uint8_t available_mask,
        float utilities[8]) {
    if (flow == nullptr || action_values == nullptr ||
        component_bytes == nullptr || resource_costs == nullptr ||
        utilities == nullptr ||
        (available_mask & ~FK_COMPONENT_FULL) != 0u ||
        !valid_resource_costs(*resource_costs))
        return false;
    for (uint8_t mask = 0u; mask < 8u; ++mask) {
        if (!std::isfinite(action_values[mask]))
            return false;
        if ((mask & ~available_mask) != 0u) {
            utilities[mask] =
                std::numeric_limits<float>::quiet_NaN();
            continue;
        }
        if (!std::isfinite(resource_costs->action_uncertainty[mask]) ||
            resource_costs->action_uncertainty[mask] < 0.0f)
            return false;
        const float recovered_value =
            action_values[mask] +
            resource_costs->uncertainty_recovery *
                resource_costs->action_uncertainty[mask];
        utilities[mask] =
            resource_costs->completion_probability[mask] *
                recovered_value -
            resource_costs->lambda_memory_per_byte *
                static_cast<float>(
                    state_bytes(mask, *component_bytes, *flow)) -
            resource_costs->lambda_queue *
                resource_costs->queue_cost[mask] -
            resource_costs->lambda_deadline *
                resource_costs->deadline_cost[mask];
        if (mask != 0u)
            utilities[mask] -= resource_costs->retention_discount;
    }
    return true;
}

bool fk_cpu_pipeline_choose_state(
        fk_cpu_pipeline *pipeline,
        fk_state_budget *budget,
        fk_component_flow *flow,
        const float *features,
        size_t feature_count,
        const fk_component_bytes *component_bytes,
        const fk_resource_costs *resource_costs,
        bool ja4_applicable,
        fk_pressure_mode pressure,
        uint32_t packet_count,
        uint64_t timestamp_ns,
        const fk_component_policy_config *config,
        fk_component_decision *decision) {
    return fk_cpu_pipeline_choose_state_available(
        pipeline,
        budget,
        flow,
        features,
        feature_count,
        component_bytes,
        resource_costs,
        FK_COMPONENT_FULL,
        ja4_applicable,
        pressure,
        packet_count,
        timestamp_ns,
        config,
        decision);
}

bool fk_cpu_pipeline_choose_state_available(
        fk_cpu_pipeline *pipeline,
        fk_state_budget *budget,
        fk_component_flow *flow,
        const float *features,
        size_t feature_count,
        const fk_component_bytes *component_bytes,
        const fk_resource_costs *resource_costs,
        uint8_t available_mask,
        bool ja4_applicable,
        fk_pressure_mode pressure,
        uint32_t packet_count,
        uint64_t timestamp_ns,
        const fk_component_policy_config *config,
        fk_component_decision *decision) {
    if (pipeline == nullptr || budget == nullptr || flow == nullptr ||
        component_bytes == nullptr || resource_costs == nullptr ||
        config == nullptr || decision == nullptr ||
        (available_mask & ~FK_COMPONENT_FULL) != 0u ||
        !valid_resource_costs(*resource_costs))
        return false;
    CpuPipeline &state = *implementation(pipeline);
    float values[8]{};
    if (!fk_cpu_pipeline_predict_action_values(
            pipeline, flow, features, feature_count, values))
        return false;
    if (!choose_state_from_values_available(
            budget,
            flow,
            values,
            8u,
            component_bytes,
            resource_costs,
            available_mask,
            ja4_applicable,
            pressure,
            packet_count,
            timestamp_ns,
            config,
            decision)) {
        state.value_failures.fetch_add(1u, std::memory_order_relaxed);
        state.value_transition_failures.fetch_add(
            1u, std::memory_order_relaxed);
        return false;
    }
    return true;
}

bool fk_cpu_pipeline_choose_state_from_values(
        fk_state_budget *budget,
        fk_component_flow *flow,
        const float *action_values,
        size_t action_value_count,
        const fk_component_bytes *component_bytes,
        const fk_resource_costs *resource_costs,
        bool ja4_applicable,
        fk_pressure_mode pressure,
        uint32_t packet_count,
        uint64_t timestamp_ns,
        const fk_component_policy_config *config,
        fk_component_decision *decision) {
    return fk_cpu_pipeline_choose_state_from_values_available(
        budget,
        flow,
        action_values,
        action_value_count,
        component_bytes,
        resource_costs,
        FK_COMPONENT_FULL,
        ja4_applicable,
        pressure,
        packet_count,
        timestamp_ns,
        config,
        decision);
}

bool fk_cpu_pipeline_choose_state_from_values_available(
        fk_state_budget *budget,
        fk_component_flow *flow,
        const float *action_values,
        size_t action_value_count,
        const fk_component_bytes *component_bytes,
        const fk_resource_costs *resource_costs,
        uint8_t available_mask,
        bool ja4_applicable,
        fk_pressure_mode pressure,
        uint32_t packet_count,
        uint64_t timestamp_ns,
        const fk_component_policy_config *config,
        fk_component_decision *decision) {
    return choose_state_from_values_available(
        budget,
        flow,
        action_values,
        action_value_count,
        component_bytes,
        resource_costs,
        available_mask,
        ja4_applicable,
        pressure,
        packet_count,
        timestamp_ns,
        config,
        decision);
}

bool fk_cpu_pipeline_detect(
        fk_cpu_pipeline *pipeline,
        const float *features,
        size_t feature_count,
        float *score) {
    if (pipeline == nullptr)
        return false;
    const CpuPipeline &read_only = *implementation(pipeline);
    if (read_only.seven_state_detectors)
        return false;
    return fk_cpu_pipeline_detect_state(
        pipeline, 0u, features, feature_count, score);
}

bool fk_cpu_pipeline_detect_state(
        fk_cpu_pipeline *pipeline,
        uint8_t state_mask,
        const float *features,
        size_t feature_count,
        float *score) {
    if (pipeline == nullptr || state_mask > 7u)
        return false;
    CpuPipeline &state = *implementation(pipeline);
    if (!state.seven_state_detectors && state_mask != 0u)
        return false;
    fk_cpu_model *detector = state.detectors[state_mask];
    state.detector_calls.fetch_add(1u, std::memory_order_relaxed);
    const auto inference_start = std::chrono::steady_clock::now();
    if (feature_count != state.detector_feature_count ||
        !fk_cpu_model_predict(
            detector, features, feature_count, score, 1u)) {
        state.detector_inference_ns.fetch_add(
            static_cast<uint64_t>(
                std::chrono::duration_cast<std::chrono::nanoseconds>(
                    std::chrono::steady_clock::now() -
                    inference_start).count()),
            std::memory_order_relaxed);
        state.detector_failures.fetch_add(1u, std::memory_order_relaxed);
        return false;
    }
    state.detector_inference_ns.fetch_add(
        static_cast<uint64_t>(
            std::chrono::duration_cast<std::chrono::nanoseconds>(
                std::chrono::steady_clock::now() -
                inference_start).count()),
        std::memory_order_relaxed);
    return true;
}

bool fk_cpu_pipeline_get_stats(
        const fk_cpu_pipeline *pipeline,
        struct fk_cpu_pipeline_stats *stats) {
    if (pipeline == nullptr || stats == nullptr)
        return false;
    const CpuPipeline &state = *implementation(pipeline);
    stats->value_calls =
        state.value_calls.load(std::memory_order_relaxed);
    stats->value_failures =
        state.value_failures.load(std::memory_order_relaxed);
    stats->value_inference_failures =
        state.value_inference_failures.load(std::memory_order_relaxed);
    stats->value_transition_failures =
        state.value_transition_failures.load(std::memory_order_relaxed);
    stats->detector_calls =
        state.detector_calls.load(std::memory_order_relaxed);
    stats->detector_failures =
        state.detector_failures.load(std::memory_order_relaxed);
    stats->value_inference_ns =
        state.value_inference_ns.load(std::memory_order_relaxed);
    stats->detector_inference_ns =
        state.detector_inference_ns.load(std::memory_order_relaxed);
    stats->value_v3_inferences =
        state.value_v3_inferences.load(std::memory_order_relaxed);
    stats->value_v3_inference_failures =
        state.value_v3_inference_failures.load(std::memory_order_relaxed);
    stats->value_v3_core_zero_violations =
        state.value_v3_core_zero_violations.load(std::memory_order_relaxed);
    stats->transition_value_calls =
        state.transition_value_calls.load(std::memory_order_relaxed);
    stats->transition_value_failures =
        state.transition_value_failures.load(std::memory_order_relaxed);
    stats->transition_value_inference_ns =
        state.transition_value_inference_ns.load(std::memory_order_relaxed);
    return true;
}

bool fk_cpu_pipeline_feature_counts(
        const fk_cpu_pipeline *pipeline,
        uint32_t *action_feature_count,
        uint32_t *detector_feature_count) {
    if (pipeline == nullptr || action_feature_count == nullptr ||
        detector_feature_count == nullptr)
        return false;
    const CpuPipeline &state = *implementation(pipeline);
    *action_feature_count = state.action_feature_count;
    *detector_feature_count = state.detector_feature_count;
    return true;
}

bool fk_cpu_pipeline_get_action_model_metadata(
        const fk_cpu_pipeline *pipeline,
        fk_cpu_pipeline_action_model_metadata *metadata) {
    if (pipeline == nullptr || metadata == nullptr)
        return false;
    *metadata = implementation(pipeline)->action_metadata;
    return true;
}

}  // extern "C"
