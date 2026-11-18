#ifndef FLOWKEEP_FK_MARGINAL_CHECKPOINT_SCHEDULER_H
#define FLOWKEEP_FK_MARGINAL_CHECKPOINT_SCHEDULER_H

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define FK_MARGINAL_SCHEDULER_STAGES 7u
#define FK_MARGINAL_SCHEDULER_SCORE_BINS 8u
#define FK_MARGINAL_SCHEDULER_HORIZON 20u

enum fk_marginal_checkpoint_action_kind {
    FK_MARGINAL_ACTION_INVALID = 0,
    FK_MARGINAL_ACTION_NEXT = 1,
    FK_MARGINAL_ACTION_STOP = 2,
    FK_MARGINAL_ACTION_CHECK_EOF = 3,
};

struct fk_marginal_checkpoint_config {
    uint8_t horizon_packet;
    uint8_t maximum_checks;
    uint8_t stage_end[FK_MARGINAL_SCHEDULER_STAGES];
    double alert_threshold;
    double observation_cost;
    double wait_cost_per_packet;
    /* Frozen prior gain-rate envelope; not by itself a STOP certificate. */
    double gain_upper[FK_MARGINAL_SCHEDULER_STAGES]
                     [FK_MARGINAL_SCHEDULER_SCORE_BINS];
    /* V2: the admission risk is ONLY a conditioning bin. Entries predict
     * positive original-detector score gain over the packet-1 prefix. */
    uint8_t detector_score_prior;
    uint8_t source_model_sha256[32];
    double first_gain[FK_MARGINAL_SCHEDULER_SCORE_BINS]
                      [FK_MARGINAL_SCHEDULER_HORIZON];
};

struct fk_marginal_checkpoint_state {
    uint8_t admission_risk_bin;
    uint8_t calls;
    uint8_t last_observation_packet;
    uint8_t pending_packet;
    uint8_t stopped;
    double last_score;
    double observed_gain_per_packet;
    double predicted_evidence_gain;
    double predicted_net_utility;
    uint8_t stop_reason; // 1 alert, 2 horizon, 3 certified low gain, 4 budget
};

struct fk_marginal_checkpoint_action {
    enum fk_marginal_checkpoint_action_kind kind;
    uint8_t packet;
    double predicted_evidence_gain;
    double predicted_net_utility;
};

bool fk_marginal_checkpoint_config_valid(
    const struct fk_marginal_checkpoint_config *config);

bool fk_marginal_checkpoint_load(const char *path,
    struct fk_marginal_checkpoint_config *config);

/* Select the first observation from a cheap causal risk estimate available at
 * flow admission. No fixed first packet is embedded in this contract. */
bool fk_marginal_checkpoint_plan_first(
    const struct fk_marginal_checkpoint_config *config,
    struct fk_marginal_checkpoint_state *state,
    double initial_risk,
    double future_detection_benefit_upper,
    bool stop_certified,
    struct fk_marginal_checkpoint_action *action);

/* Select NEXT(packet) or STOP after a real observation. Low estimated gain
 * alone is not a STOP certificate. Reserve the final observation for the
 * horizon, and use the actual score trajectory to update the gain forecast. */
bool fk_marginal_checkpoint_observe(
    const struct fk_marginal_checkpoint_config *config,
    struct fk_marginal_checkpoint_state *state,
    uint8_t packet,
    double score,
    double future_detection_benefit_upper,
    bool stop_certified,
    struct fk_marginal_checkpoint_action *action);

/* A flow ending before its pending first/successor observation is scored once
 * at the real terminal cumulative state.  An explicit STOP suppresses EOF. */
bool fk_marginal_checkpoint_eof(
    struct fk_marginal_checkpoint_state *state,
    uint8_t terminal_packet,
    struct fk_marginal_checkpoint_action *action);

#ifdef __cplusplus
}
#endif

#endif
