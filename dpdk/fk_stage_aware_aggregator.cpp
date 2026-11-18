#include "fk_stage_aware_aggregator.h"

#include <algorithm>
#include <cmath>
#include <cstring>
#include <limits>

namespace {

bool valid_checkpoint(uint8_t value) {
    return value == 0u || value == 4u || value == 8u || value == 12u ||
           value == 20u;
}

uint8_t stage_bits(uint8_t value) {
    uint8_t count = 0u;
    while (value != 0u) {
        count = static_cast<uint8_t>(count + (value & 1u));
        value = static_cast<uint8_t>(value >> 1u);
    }
    return count;
}

void saturating_increment(uint16_t &value) {
    if (value != std::numeric_limits<uint16_t>::max())
        ++value;
}

void saturating_increment(uint8_t &value) {
    if (value != std::numeric_limits<uint8_t>::max())
        ++value;
}

void saturating_increment(uint32_t &value) {
    if (value != std::numeric_limits<uint32_t>::max())
        ++value;
}

}  // namespace

void fk_stage_aware_default_policy(fk_stage_aware_policy *policy) {
    if (policy == nullptr)
        return;
    *policy = {};
    policy->provisional_threshold = 0.50f;
    policy->confirm_threshold = 0.90f;
    policy->retract_threshold = 0.30f;
    policy->persistent_support = 3u;
    policy->contradictory_support = 3u;
    policy->distinct_stages_to_confirm = 2u;
}

bool fk_stage_aware_policy_valid(const fk_stage_aware_policy *policy) {
    return policy != nullptr && std::isfinite(policy->provisional_threshold) &&
           std::isfinite(policy->confirm_threshold) &&
           std::isfinite(policy->retract_threshold) &&
           policy->retract_threshold >= 0.0f &&
           policy->retract_threshold < policy->provisional_threshold &&
           policy->provisional_threshold < policy->confirm_threshold &&
           policy->confirm_threshold <= 1.0f &&
           policy->persistent_support != 0u &&
           policy->contradictory_support != 0u &&
           policy->distinct_stages_to_confirm != 0u &&
           policy->distinct_stages_to_confirm <= FK_STAGE_AWARE_STAGE_COUNT;
}

void fk_stage_aware_event_reset(fk_stage_aware_event_state *state) {
    if (state != nullptr)
        std::memset(state, 0, sizeof(*state));
}

bool fk_stage_aware_infer_stage(
        uint8_t checkpoint_packet,
        bool tls_or_quic_candidate,
        bool handshake_complete,
        bool application_data_observed,
        bool retry_or_migration,
        bool reopened,
        uint8_t *stage) {
    if (stage == nullptr || !valid_checkpoint(checkpoint_packet))
        return false;
    if (reopened)
        *stage = FK_EVENT_STAGE_REOPENED;
    else if (retry_or_migration)
        *stage = FK_EVENT_STAGE_RETRY_OR_MIGRATION;
    else if (application_data_observed)
        *stage = FK_EVENT_STAGE_TRANSFER;
    else if (handshake_complete)
        *stage = FK_EVENT_STAGE_ESTABLISHED;
    else if (tls_or_quic_candidate)
        *stage = FK_EVENT_STAGE_HANDSHAKE;
    else
        *stage = FK_EVENT_STAGE_BOOTSTRAP;
    return true;
}

bool fk_stage_aware_event_update(
        fk_stage_aware_event_state *state,
        const fk_stage_aware_policy *policy,
        uint8_t stage,
        float risk_score,
        uint64_t anchor_ns,
        uint8_t evidence_mask,
        fk_stage_aware_transition *transition) {
    if (state == nullptr || transition == nullptr ||
        !fk_stage_aware_policy_valid(policy) ||
        stage >= FK_STAGE_AWARE_STAGE_COUNT || !std::isfinite(risk_score) ||
        risk_score < 0.0f || risk_score > 1.0f || evidence_mask > 7u ||
        (state->count != 0u && anchor_ns < state->last_anchor_ns))
        return false;
    *transition = {};
    transition->previous_alert_state = state->alert_state;
    static constexpr float risk_thresholds[
        FK_STAGE_AWARE_RISK_THRESHOLD_COUNT] = {0.30f, 0.50f, 0.70f, 0.80f};
    if (state->count == 0u) {
        state->event_first_ns = anchor_ns;
        state->maximum_score = risk_score;
        state->maximum_score_ns = anchor_ns;
    } else if (risk_score > state->maximum_score) {
        state->maximum_score = risk_score;
        state->maximum_score_ns = anchor_ns;
    }
    for (uint8_t index = 0u;
         index < FK_STAGE_AWARE_RISK_THRESHOLD_COUNT; ++index) {
        if (risk_score >= risk_thresholds[index]) {
            if (state->threshold_count[index] == 0u)
                state->threshold_first_ns[index] = anchor_ns;
            saturating_increment(state->threshold_count[index]);
        }
    }
    state->high80_run = risk_score >= 0.80f
        ? static_cast<uint16_t>(std::min<uint32_t>(
              static_cast<uint32_t>(state->high80_run) + 1u,
              std::numeric_limits<uint16_t>::max()))
        : 0u;
    state->high80_run_max = std::max(
        state->high80_run_max, state->high80_run);
    const uint8_t histogram_bin = static_cast<uint8_t>(std::min(
        7, static_cast<int>(risk_score * 8.0f)));
    saturating_increment(state->score_histogram[histogram_bin]);
    for (uint8_t index = 0u; index < 3u; ++index) {
        if (risk_score > state->top_scores[index]) {
            for (uint8_t move = 2u; move > index; --move)
                state->top_scores[move] = state->top_scores[move - 1u];
            state->top_scores[index] = risk_score;
            break;
        }
    }
    if (state->first5_count < 5u) {
        state->first5_sum += risk_score;
        ++state->first5_count;
    }
    if (state->count != 0u) {
        saturating_increment(
            state->transition_count[state->current_stage][stage]);
    }
    state->current_stage = stage;
    state->visited_stage_mask = static_cast<uint8_t>(
        state->visited_stage_mask | (1u << stage));
    const uint16_t previous_count = state->stage_count[stage];
    if (previous_count != std::numeric_limits<uint16_t>::max())
        ++state->stage_count[stage];
    const double denominator = static_cast<double>(previous_count) + 1.0;
    if (previous_count == 0u) {
        state->stage_first[stage] = risk_score;
        state->stage_mean[stage] = risk_score;
        state->stage_max[stage] = risk_score;
        state->stage_ewma[stage] = risk_score;
        state->stage_first_ns[stage] = anchor_ns;
    } else {
        const double delta = risk_score - state->stage_mean[stage];
        state->stage_mean[stage] += delta / denominator;
        state->stage_m2[stage] +=
            delta * (risk_score - state->stage_mean[stage]);
        state->stage_max[stage] =
            std::max(state->stage_max[stage], risk_score);
        state->stage_ewma[stage] +=
            0.25f * (risk_score - state->stage_ewma[stage]);
    }
    state->stage_last[stage] = risk_score;
    state->stage_last_ns[stage] = anchor_ns;
    state->stage_evidence_mask[stage] = static_cast<uint8_t>(
        state->stage_evidence_mask[stage] | evidence_mask);
    if (state->count != std::numeric_limits<uint64_t>::max())
        ++state->count;
    state->last_anchor_ns = anchor_ns;
    state->high_run = risk_score >= policy->provisional_threshold
        ? static_cast<uint16_t>(std::min<uint32_t>(
              static_cast<uint32_t>(state->high_run) + 1u,
              std::numeric_limits<uint16_t>::max()))
        : 0u;
    state->low_run = risk_score <= policy->retract_threshold
        ? static_cast<uint16_t>(std::min<uint32_t>(
              static_cast<uint32_t>(state->low_run) + 1u,
              std::numeric_limits<uint16_t>::max()))
        : 0u;
    if (state->alert_state == FK_EVENT_ALERT_UNKNOWN ||
        state->alert_state == FK_EVENT_ALERT_RETRACTED) {
        if (stage == FK_EVENT_STAGE_REOPENED &&
            state->alert_state == FK_EVENT_ALERT_RETRACTED) {
            state->alert_state = FK_EVENT_ALERT_REOPENED;
            saturating_increment(state->reopen_count);
            transition->reopen_emitted = true;
        } else if (risk_score >= policy->provisional_threshold) {
            state->alert_state = FK_EVENT_ALERT_PROVISIONAL;
            saturating_increment(state->provisional_count);
        }
    }
    if (state->alert_state == FK_EVENT_ALERT_PROVISIONAL ||
        state->alert_state == FK_EVENT_ALERT_REOPENED) {
        if (risk_score >= policy->confirm_threshold ||
            (state->high_run >= policy->persistent_support &&
             stage_bits(state->visited_stage_mask) >=
                 policy->distinct_stages_to_confirm)) {
            state->alert_state = FK_EVENT_ALERT_CONFIRMED;
            saturating_increment(state->confirmation_count);
        } else if (state->low_run >= policy->contradictory_support) {
            state->alert_state = FK_EVENT_ALERT_RETRACTED;
            saturating_increment(state->retraction_count);
            transition->correction_emitted = true;
        }
    } else if (state->alert_state == FK_EVENT_ALERT_CONFIRMED &&
               state->low_run >= policy->contradictory_support) {
        state->alert_state = FK_EVENT_ALERT_RETRACTED;
        saturating_increment(state->retraction_count);
        transition->correction_emitted = true;
    }
    transition->current_alert_state = state->alert_state;
    transition->changed = transition->previous_alert_state !=
                          transition->current_alert_state;
    return true;
}

size_t fk_stage_aware_event_state_bytes(void) {
    return sizeof(fk_stage_aware_event_state);
}
