#ifndef FLOWKEEP_FK_VALUE_MODEL_V3_CONTEXT_H
#define FLOWKEEP_FK_VALUE_MODEL_V3_CONTEXT_H

#include <stdbool.h>
#include <stdint.h>

#include "fk_value_model_v3.h"

#ifdef __cplusplus
extern "C" {
#endif

#define FK_VALUE_MODEL_V3_BASE_FEATURES 30u
#define FK_VALUE_MODEL_V3_MISSING_REASONS 5u
#define FK_VALUE_MODEL_V3_FROZEN_HORIZON_MS 30000.0
#define FK_VALUE_MODEL_V3_ONLINE_CONTEXT_SCHEMA_SHA256 \
    "7a0f609e7cbe399b967ad9c7ab2c543ec2d08c91613f49c398adae7ce3161bd4"

enum fk_value_model_v3_trigger_kind {
    FK_VALUE_MODEL_V3_TRIGGER_CHECKPOINT = 1,
    FK_VALUE_MODEL_V3_TRIGGER_PERIODIC = 2,
};

/*
 * Frozen ABI64 builder input.  materialized_mask is the causally observed
 * protocol-applicable action domain (STAT|SEQ, plus JA4 for TLS/QUIC), never
 * a typed-pool availability or controlled-budget feasibility mask.
 *
 * decision_deadline_ns is deliberately absent.  Every causal checkpoint uses
 * the preregistered 30-second horizon, so feature 54 is the constant
 * log1p(30000 ms).  A trace's later terminal time cannot change this prefix.
 */
struct fk_value_model_v3_context_input {
    float base_30[FK_VALUE_MODEL_V3_BASE_FEATURES];
    uint8_t current_mask;
    uint8_t released_mask;
    uint8_t materialized_mask;
    uint8_t missing_reason[3];
    enum fk_value_model_v3_trigger_kind trigger_kind;
    uint8_t checkpoint_packet;
};

bool fk_value_model_v3_build_context(
    const struct fk_value_model_v3_context_input *input,
    float context[FK_VALUE_MODEL_V3_CONTEXT_FEATURES]);

#ifdef __cplusplus
}
#endif

#endif
