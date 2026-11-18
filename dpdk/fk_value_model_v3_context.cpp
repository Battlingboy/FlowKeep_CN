#include "fk_value_model_v3_context.h"

#include <cmath>
#include <cstring>

namespace {

constexpr uint8_t kFullMask = 7u;
constexpr uint8_t kComponents[3]{1u, 2u, 4u};
constexpr uint8_t kCheckpoints[4]{4u, 8u, 12u, 20u};

static bool checkpoint_permitted(uint8_t packet) {
    for (const uint8_t checkpoint : kCheckpoints) {
        if (packet == checkpoint)
            return true;
    }
    return false;
}

}  // namespace

extern "C" bool fk_value_model_v3_build_context(
        const fk_value_model_v3_context_input *input,
        float context[FK_VALUE_MODEL_V3_CONTEXT_FEATURES]) {
    if (input == nullptr || context == nullptr ||
        input->current_mask > kFullMask ||
        input->released_mask > kFullMask ||
        input->materialized_mask == 0u ||
        input->materialized_mask > kFullMask ||
        (input->current_mask & input->released_mask) != 0u ||
        (input->current_mask & ~input->materialized_mask) != 0u)
        return false;
    for (const float value : input->base_30) {
        if (!std::isfinite(value))
            return false;
    }
    for (const uint8_t reason : input->missing_reason) {
        if (reason >= FK_VALUE_MODEL_V3_MISSING_REASONS)
            return false;
    }
    if ((input->trigger_kind == FK_VALUE_MODEL_V3_TRIGGER_CHECKPOINT &&
         !checkpoint_permitted(input->checkpoint_packet)) ||
        (input->trigger_kind == FK_VALUE_MODEL_V3_TRIGGER_PERIODIC &&
         input->checkpoint_packet != 0u) ||
        (input->trigger_kind != FK_VALUE_MODEL_V3_TRIGGER_CHECKPOINT &&
         input->trigger_kind != FK_VALUE_MODEL_V3_TRIGGER_PERIODIC))
        return false;

    std::memset(
        context, 0, sizeof(float) * FK_VALUE_MODEL_V3_CONTEXT_FEATURES);
    std::memcpy(
        context, input->base_30,
        sizeof(float) * FK_VALUE_MODEL_V3_BASE_FEATURES);
    /* The value estimator is intentionally blind to legacy pressure and
     * overload shortcuts even though the causal base-30 producer carries
     * those fields for the controller. */
    context[8] = 0.0f;
    context[9] = 0.0f;

    size_t output = FK_VALUE_MODEL_V3_BASE_FEATURES;
    const uint8_t masks[3]{
        input->current_mask,
        input->released_mask,
        input->materialized_mask,
    };
    for (const uint8_t mask : masks) {
        for (const uint8_t component : kComponents)
            context[output++] = (mask & component) != 0u ? 1.0f : 0.0f;
    }
    for (const uint8_t reason : input->missing_reason) {
        for (uint8_t value = 0u;
             value < FK_VALUE_MODEL_V3_MISSING_REASONS; ++value)
            context[output++] = reason == value ? 1.0f : 0.0f;
    }
    context[output++] = static_cast<float>(
        std::log1p(FK_VALUE_MODEL_V3_FROZEN_HORIZON_MS));
    context[output++] = input->trigger_kind ==
        FK_VALUE_MODEL_V3_TRIGGER_CHECKPOINT ? 1.0f : 0.0f;
    context[output++] = input->trigger_kind ==
        FK_VALUE_MODEL_V3_TRIGGER_PERIODIC ? 1.0f : 0.0f;
    for (const uint8_t checkpoint : kCheckpoints)
        context[output++] = input->checkpoint_packet == checkpoint
            ? 1.0f : 0.0f;
    context[output++] = input->checkpoint_packet == 0u ? 1.0f : 0.0f;
    context[output++] = 0.0f;
    context[output++] = 0.0f;
    return output == FK_VALUE_MODEL_V3_CONTEXT_FEATURES &&
        context[8] == 0.0f && context[9] == 0.0f &&
        context[62] == 0.0f && context[63] == 0.0f;
}
