#include "fk_marginal_checkpoint_scheduler.h"

#include <algorithm>
#include <cmath>
#include <cstdio>
#include <cstring>
#include <limits>

namespace {

uint32_t stage_for(const fk_marginal_checkpoint_config &config,
                   uint8_t packet) {
    for (uint32_t stage = 0; stage < FK_MARGINAL_SCHEDULER_STAGES; ++stage)
        if (packet < config.stage_end[stage])
            return stage;
    return FK_MARGINAL_SCHEDULER_STAGES - 1u;
}

uint32_t bin_for(double score) {
    const double bounded = std::max(0.0, std::min(1.0, score));
    return std::min<uint32_t>(
        FK_MARGINAL_SCHEDULER_SCORE_BINS - 1u,
        static_cast<uint32_t>(bounded * FK_MARGINAL_SCHEDULER_SCORE_BINS));
}

// Integrate future stages rather than extrapolating the current stage across
// the entire remaining horizon. The on-flow slope can increase the forecast;
// a flat recent prefix cannot erase a later evidence-bearing stage.
double forecast(const fk_marginal_checkpoint_config &config,
                uint8_t packet, uint8_t next, double score,
                double observed_rate) {
    double gain = 0.0;
    for (uint32_t p = packet; p < next; ++p) {
        const double rate = std::max(observed_rate,
            config.gain_upper[stage_for(config, static_cast<uint8_t>(p))]
                             [bin_for(std::min(1.0, score + gain))]);
        gain += rate;
    }
    return std::min(std::max(0.0, config.alert_threshold - score), gain);
}

}  // namespace

extern "C" bool fk_marginal_checkpoint_config_valid(
        const fk_marginal_checkpoint_config *config) {
    if (config == nullptr || config->horizon_packet == 0u ||
        config->horizon_packet > FK_MARGINAL_SCHEDULER_HORIZON ||
        config->detector_score_prior > 1u ||
        config->maximum_checks == 0u ||
        !std::isfinite(config->alert_threshold) ||
        config->alert_threshold < 0.0 || config->alert_threshold > 1.0 ||
        !std::isfinite(config->observation_cost) ||
        config->observation_cost < 0.0 ||
        !std::isfinite(config->wait_cost_per_packet) ||
        config->wait_cost_per_packet < 0.0)
        return false;
    uint8_t previous = 0u;
    for (uint32_t stage = 0; stage < FK_MARGINAL_SCHEDULER_STAGES; ++stage) {
        if (config->stage_end[stage] <= previous)
            return false;
        previous = config->stage_end[stage];
        for (double gain : config->gain_upper[stage])
            if (!std::isfinite(gain) || gain < 0.0)
                return false;
    }
    if (config->detector_score_prior)
        for (const auto &bin : config->first_gain)
            for (double score : bin)
                if (!std::isfinite(score) || score < 0.0 || score > 1.0)
                    return false;
    return previous > config->horizon_packet;
}

extern "C" bool fk_marginal_checkpoint_load(const char *path,
        fk_marginal_checkpoint_config *config) {
    if (!path || !config) return false;
    FILE *file = std::fopen(path, "rb");
    if (!file) return false;
    fk_marginal_checkpoint_config value{};
    char magic[8]{};
    bool ok = std::fread(magic, 1, 8, file) == 8;
    const bool v2 = ok && std::memcmp(magic, "FKMGN2\0\0", 8) == 0;
    ok = ok && (v2 || std::memcmp(magic, "FKMGN1\0\0", 8) == 0) &&
        std::fread(&value.horizon_packet, 1, 1, file) == 1 &&
        std::fread(&value.maximum_checks, 1, 1, file) == 1 &&
        std::fread(value.stage_end, 1, 7, file) == 7 &&
        std::fread(&value.alert_threshold, sizeof(double), 1, file) == 1 &&
        std::fread(&value.observation_cost, sizeof(double), 1, file) == 1 &&
        std::fread(&value.wait_cost_per_packet, sizeof(double), 1, file) == 1 &&
        std::fread(value.gain_upper, sizeof(double), 56, file) == 56;
    if (v2) {
        value.detector_score_prior = 1;
        ok = ok && std::fread(value.source_model_sha256, 1, 32, file) == 32 &&
            std::fread(value.first_gain, sizeof(double), 160, file) == 160;
    }
    ok = ok && std::fgetc(file) == EOF && fk_marginal_checkpoint_config_valid(&value);
    std::fclose(file);
    if (ok) *config = value;
    return ok;
}

extern "C" bool fk_marginal_checkpoint_plan_first(
        const fk_marginal_checkpoint_config *config,
        fk_marginal_checkpoint_state *state,
        double initial_risk,
        double future_detection_benefit_upper,
        bool stop_certified,
        fk_marginal_checkpoint_action *action) {
    if (!fk_marginal_checkpoint_config_valid(config) || state == nullptr ||
        action == nullptr || state->calls != 0u ||
        state->last_observation_packet != 0u ||
        state->pending_packet != 0u || state->stopped != 0u ||
        !std::isfinite(initial_risk) || initial_risk < 0.0 ||
        initial_risk > 1.0 ||
        !std::isfinite(future_detection_benefit_upper) ||
        future_detection_benefit_upper < 0.0 ||
        future_detection_benefit_upper > 1.0)
        return false;
    *action = {};
    const double rate = config->gain_upper[0][bin_for(initial_risk)];
    const double evidence_needed = std::max(
        0.0, config->alert_threshold - initial_risk);
    double best = -std::numeric_limits<double>::infinity();
    uint8_t best_packet = 0u;
    double best_gain = 0.0;
    for (uint32_t next = 1u; next <= config->horizon_packet; ++next) {
        const double gain = config->detector_score_prior ?
            std::min(config->alert_threshold,
                config->first_gain[bin_for(initial_risk)][next - 1u]) :
            std::min(evidence_needed, rate * static_cast<double>(next));
        const double utility = future_detection_benefit_upper * gain -
            config->observation_cost -
            config->wait_cost_per_packet * static_cast<double>(next);
        if (utility > best) {
            best = utility;
            best_packet = static_cast<uint8_t>(next);
            best_gain = gain;
        }
    }
    if (stop_certified && best <= 0.0) {
        state->stopped = 1u;
        action->kind = FK_MARGINAL_ACTION_STOP;
        action->predicted_net_utility = best;
        return true;
    }
    /* Every flow still needs one real seven-head observation.  When no
     * future point has positive marginal utility, keep the earliest
     * utility-maximising point (normally packet 1); postponing that mandatory
     * observation to the hard horizon turns short flows into a large dirty
     * EOF burst. */
    if (best_packet == 0u)
        return false;
    state->pending_packet = best_packet;
    state->predicted_evidence_gain = best_gain;
    state->predicted_net_utility = best;
    action->kind = FK_MARGINAL_ACTION_NEXT;
    action->packet = best_packet;
    action->predicted_evidence_gain = best_gain;
    action->predicted_net_utility = best;
    return true;
}

extern "C" bool fk_marginal_checkpoint_observe(
        const fk_marginal_checkpoint_config *config,
        fk_marginal_checkpoint_state *state,
        uint8_t packet,
        double score,
        double future_detection_benefit_upper,
        bool stop_certified,
        fk_marginal_checkpoint_action *action) {
    if (!fk_marginal_checkpoint_config_valid(config) || state == nullptr ||
        action == nullptr || state->stopped != 0u || packet == 0u ||
        packet <= state->last_observation_packet ||
        packet > config->horizon_packet || !std::isfinite(score) ||
        score < 0.0 || score > 1.0 ||
        !std::isfinite(future_detection_benefit_upper) ||
        future_detection_benefit_upper < 0.0 ||
        future_detection_benefit_upper > 1.0)
        return false;

    *action = {};
    if (state->calls != 0u) {
        const double slope = std::max(0.0, score - state->last_score) /
            static_cast<double>(packet - state->last_observation_packet);
        state->observed_gain_per_packet = state->calls == 1u ? slope :
            0.5 * (state->observed_gain_per_packet + slope);
    }
    state->last_score = score;
    ++state->calls;
    state->last_observation_packet = packet;
    state->pending_packet = 0u;
    if (score >= config->alert_threshold ||
        state->calls >= config->maximum_checks ||
        packet >= config->horizon_packet) {
        state->stopped = 1u;
        state->stop_reason = score >= config->alert_threshold ? 1u :
            (packet >= config->horizon_packet ? 2u : 4u);
        state->predicted_evidence_gain = 0.0;
        state->predicted_net_utility = 0.0;
        action->kind = FK_MARGINAL_ACTION_STOP;
        action->packet = packet;
        return true;
    }

    double best = -std::numeric_limits<double>::infinity();
    uint8_t best_packet = 0u;
    double best_gain = 0.0;
    // Never spend all four observations on early prefixes and silently lose
    // the later evidence. This is a budget boundary, not a fixed point grid.
    const uint32_t first_candidate = state->calls + 1u >= config->maximum_checks
        ? config->horizon_packet : static_cast<uint32_t>(packet) + 1u;
    for (uint32_t next = first_candidate;
         next <= config->horizon_packet; ++next) {
        const double gap = static_cast<double>(next - packet);
        const double gain = forecast(*config, packet, static_cast<uint8_t>(next),
                                    score, state->observed_gain_per_packet);
        const double utility =
            future_detection_benefit_upper * gain -
            config->observation_cost - config->wait_cost_per_packet * gap;
        if (utility > best) {
            best = utility;
            best_packet = static_cast<uint8_t>(next);
            best_gain = gain;
        }
    }

    if (best <= 0.0 && stop_certified) {
        state->stopped = 1u;
        state->stop_reason = 3u;
        state->predicted_evidence_gain = 0.0;
        state->predicted_net_utility = best;
        action->kind = FK_MARGINAL_ACTION_STOP;
        action->packet = packet;
        action->predicted_net_utility = best;
        return true;
    }
    if (best_packet == 0u || best <= 0.0) {
        best_packet = config->horizon_packet;
        best_gain = forecast(*config, packet, best_packet, score,
                             state->observed_gain_per_packet);
        best = future_detection_benefit_upper * best_gain -
            config->observation_cost -
            config->wait_cost_per_packet * (best_packet - packet);
    }
    state->pending_packet = best_packet;
    state->predicted_evidence_gain = best_gain;
    state->predicted_net_utility = best;
    action->kind = FK_MARGINAL_ACTION_NEXT;
    action->packet = best_packet;
    action->predicted_evidence_gain = best_gain;
    action->predicted_net_utility = best;
    return true;
}

extern "C" bool fk_marginal_checkpoint_eof(
        fk_marginal_checkpoint_state *state,
        uint8_t terminal_packet,
        fk_marginal_checkpoint_action *action) {
    if (state == nullptr || action == nullptr || terminal_packet == 0u)
        return false;
    *action = {};
    action->packet = terminal_packet;
    if (state->stopped != 0u) {
        action->kind = FK_MARGINAL_ACTION_STOP;
        return true;
    }
    /* No duplicate: an EOF following an already-terminal observation is not
     * a second model call. */
    if (state->last_observation_packet == terminal_packet) {
        state->pending_packet = 0u;
        state->stopped = 1u;
        action->kind = FK_MARGINAL_ACTION_STOP;
        return true;
    }
    state->pending_packet = 0u;
    state->last_observation_packet = terminal_packet;
    state->stopped = 1u;
    action->kind = FK_MARGINAL_ACTION_CHECK_EOF;
    return true;
}
