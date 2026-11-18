#ifndef FLOWKEEP_FK_CAUSAL_EVENT_FEATURES_H
#define FLOWKEEP_FK_CAUSAL_EVENT_FEATURES_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "fk_causal_event_calibrator.h"

#ifdef __cplusplus
extern "C" {
#endif

#define FK_CAUSAL_EVENT_MASKED_STATE_COLUMNS 7u

/*
 * Fixed-size causal prefix state.  One instance belongs to exactly one
 * (event_id,event_generation) and is reset before ordinal 1.
 * It contains no record payload and performs no allocation.
 */
struct fk_causal_event_feature_state_v1 {
    uint64_t trigger_count;
    double trigger_mean;
    double trigger_m2;
    double trajectory_top3[3];
    uint64_t score_gt_0p5;
    uint64_t score_gt_0p75;
    uint64_t score_gt_0p9;
    uint64_t score_gt_0p95;
    double first_score;
    double prior_score;
    double ema_0p5;
    uint8_t initialized;
};

struct fk_causal_event_trigger_input_v1 {
    uint8_t trigger_kind;
    uint8_t reserved0[3];
    uint32_t checkpoint_packet;
    uint64_t event_start_ns;
    uint64_t anchor_ns;
    size_t record_count;
    const double *record_scores;
    /* Original action mask for every member record (each value is 0..7). */
    const uint8_t *record_action_masks;
    /* Row-major record_count x 7: masked source columns 30 through 36. */
    const float *masked_state_columns;
};

void fk_causal_event_feature_state_reset(
    struct fk_causal_event_feature_state_v1 *state);

/*
 * Appends one causal trigger prefix and emits the exact ordered 32D feature
 * vector specified by config/causal_event_feature_formulas_v1.json.  Failure
 * is atomic: state and output are unchanged.
 */
bool fk_causal_event_features_update(
    struct fk_causal_event_feature_state_v1 *state,
    const struct fk_causal_event_trigger_input_v1 *input,
    float output[FK_CAUSAL_EVENT_CALIBRATOR_FEATURES]);

#ifdef __cplusplus
}
#endif

#endif
