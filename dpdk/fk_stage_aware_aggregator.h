#ifndef FLOWKEEP_FK_STAGE_AWARE_AGGREGATOR_H
#define FLOWKEEP_FK_STAGE_AWARE_AGGREGATOR_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define FK_STAGE_AWARE_STAGE_COUNT 6u
#define FK_STAGE_AWARE_RISK_THRESHOLD_COUNT 4u
#define FK_STAGE_AWARE_EVIDENCE_FULL 7u

enum fk_event_behavior_stage {
    FK_EVENT_STAGE_BOOTSTRAP = 0,
    FK_EVENT_STAGE_HANDSHAKE = 1,
    FK_EVENT_STAGE_ESTABLISHED = 2,
    FK_EVENT_STAGE_TRANSFER = 3,
    FK_EVENT_STAGE_RETRY_OR_MIGRATION = 4,
    FK_EVENT_STAGE_REOPENED = 5,
};

enum fk_event_alert_state {
    FK_EVENT_ALERT_UNKNOWN = 0,
    FK_EVENT_ALERT_PROVISIONAL = 1,
    FK_EVENT_ALERT_CONFIRMED = 2,
    FK_EVENT_ALERT_RETRACTED = 3,
    FK_EVENT_ALERT_REOPENED = 4,
};

struct fk_stage_aware_policy {
    float provisional_threshold;
    float confirm_threshold;
    float retract_threshold;
    uint16_t persistent_support;
    uint16_t contradictory_support;
    uint8_t distinct_stages_to_confirm;
    uint8_t reserved8[3];
};

struct fk_stage_aware_event_state {
    uint64_t count;
    uint64_t last_anchor_ns;
    uint64_t event_first_ns;
    uint64_t threshold_first_ns[FK_STAGE_AWARE_RISK_THRESHOLD_COUNT];
    uint64_t maximum_score_ns;
    uint64_t stage_first_ns[FK_STAGE_AWARE_STAGE_COUNT];
    uint64_t stage_last_ns[FK_STAGE_AWARE_STAGE_COUNT];
    double stage_mean[FK_STAGE_AWARE_STAGE_COUNT];
    double stage_m2[FK_STAGE_AWARE_STAGE_COUNT];
    uint16_t stage_count[FK_STAGE_AWARE_STAGE_COUNT];
    uint16_t threshold_count[FK_STAGE_AWARE_RISK_THRESHOLD_COUNT];
    uint8_t transition_count[FK_STAGE_AWARE_STAGE_COUNT]
                              [FK_STAGE_AWARE_STAGE_COUNT];
    float stage_first[FK_STAGE_AWARE_STAGE_COUNT];
    float stage_last[FK_STAGE_AWARE_STAGE_COUNT];
    float stage_max[FK_STAGE_AWARE_STAGE_COUNT];
    float stage_ewma[FK_STAGE_AWARE_STAGE_COUNT];
    uint32_t provisional_count;
    uint32_t confirmation_count;
    uint32_t retraction_count;
    uint32_t reopen_count;
    float maximum_score;
    float top_scores[3];
    float first5_sum;
    uint16_t score_histogram[8];
    uint16_t first5_count;
    uint16_t high_run;
    uint16_t low_run;
    uint16_t high80_run;
    uint16_t high80_run_max;
    uint8_t stage_evidence_mask[FK_STAGE_AWARE_STAGE_COUNT];
    uint8_t current_stage;
    uint8_t visited_stage_mask;
    uint8_t alert_state;
    uint8_t reserved8;
};

struct fk_stage_aware_transition {
    uint8_t previous_alert_state;
    uint8_t current_alert_state;
    bool changed;
    bool correction_emitted;
    bool reopen_emitted;
};

void fk_stage_aware_default_policy(struct fk_stage_aware_policy *policy);
bool fk_stage_aware_policy_valid(const struct fk_stage_aware_policy *policy);
void fk_stage_aware_event_reset(struct fk_stage_aware_event_state *state);

bool fk_stage_aware_infer_stage(
    uint8_t checkpoint_packet,
    bool tls_or_quic_candidate,
    bool handshake_complete,
    bool application_data_observed,
    bool retry_or_migration,
    bool reopened,
    uint8_t *stage);

bool fk_stage_aware_event_update(
    struct fk_stage_aware_event_state *state,
    const struct fk_stage_aware_policy *policy,
    uint8_t stage,
    float risk_score,
    uint64_t anchor_ns,
    uint8_t evidence_mask,
    struct fk_stage_aware_transition *transition);

size_t fk_stage_aware_event_state_bytes(void);

#ifdef __cplusplus
}
#endif

#endif
