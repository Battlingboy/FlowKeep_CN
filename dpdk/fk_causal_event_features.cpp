#include "fk_causal_event_features.h"

#include <algorithm>
#include <cmath>
#include <cstring>
#include <limits>

namespace {

constexpr size_t kTop = 3u;

bool finite_columns(const float *row) {
    for (size_t index = 0u;
         index < FK_CAUSAL_EVENT_MASKED_STATE_COLUMNS; ++index) {
        if (!std::isfinite(row[index]))
            return false;
    }
    return true;
}

void insert_top3(double value, double top[kTop]) {
    for (size_t index = 0u; index < kTop; ++index) {
        if (value > top[index]) {
            for (size_t move = kTop - 1u; move > index; --move)
                top[move] = top[move - 1u];
            top[index] = value;
            return;
        }
    }
}

double mean_top(const double top[kTop], uint64_t count, size_t wanted) {
    const size_t used = std::min<size_t>(
        wanted, static_cast<size_t>(std::min<uint64_t>(count, kTop)));
    double sum = 0.0;
    for (size_t index = 0u; index < used; ++index)
        sum += top[index];
    return sum / static_cast<double>(used);
}

bool output_finite(const float output[FK_CAUSAL_EVENT_CALIBRATOR_FEATURES]) {
    for (size_t index = 0u;
         index < FK_CAUSAL_EVENT_CALIBRATOR_FEATURES; ++index) {
        if (!std::isfinite(output[index]))
            return false;
    }
    return true;
}

}  // namespace

extern "C" {

void fk_causal_event_feature_state_reset(
        fk_causal_event_feature_state_v1 *state) {
    if (state == nullptr)
        return;
    std::memset(state, 0, sizeof(*state));
}

bool fk_causal_event_features_update(
        fk_causal_event_feature_state_v1 *state,
        const fk_causal_event_trigger_input_v1 *input,
        float output[FK_CAUSAL_EVENT_CALIBRATOR_FEATURES]) {
    if (state == nullptr || input == nullptr || output == nullptr ||
        (input->trigger_kind != 1u && input->trigger_kind != 2u) ||
        input->record_count == 0u || input->record_scores == nullptr ||
        input->record_action_masks == nullptr ||
        input->masked_state_columns == nullptr ||
        state->trigger_count == std::numeric_limits<uint64_t>::max()) {
        return false;
    }
    fk_causal_event_feature_state_v1 next = *state;
    double local_sum = 0.0;
    double local_top[kTop]{
        -std::numeric_limits<double>::infinity(),
        -std::numeric_limits<double>::infinity(),
        -std::numeric_limits<double>::infinity(),
    };
    double retained_sum[3]{};
    uint64_t missing_count[3]{};
    uint64_t complete_count = 0u;
    uint8_t requested_mask = 0u;
    for (size_t record = 0u; record < input->record_count; ++record) {
        const double score = input->record_scores[record];
        const float *columns = input->masked_state_columns +
            record * FK_CAUSAL_EVENT_MASKED_STATE_COLUMNS;
        if (!std::isfinite(score) || score < 0.0 || score > 1.0 ||
            input->record_action_masks[record] > 7u ||
            !finite_columns(columns)) {
            return false;
        }
        local_sum += score;
        insert_top3(score, local_top);
        for (size_t component = 0u; component < 3u; ++component) {
            retained_sum[component] +=
                static_cast<double>(columns[component]);
            missing_count[component] += columns[component + 3u] != 0.0f;
        }
        complete_count += columns[6] > 0.5f;
        requested_mask = static_cast<uint8_t>(
            requested_mask | input->record_action_masks[record]);
    }
    const double raw = local_top[0];
    const uint64_t ordinal = next.trigger_count + 1u;
    if (ordinal == 1u) {
        next.first_score = raw;
        next.prior_score = raw;
        next.ema_0p5 = raw;
        next.trajectory_top3[0] =
            next.trajectory_top3[1] =
            next.trajectory_top3[2] =
                -std::numeric_limits<double>::infinity();
    } else {
        next.ema_0p5 = 0.5 * raw + 0.5 * next.ema_0p5;
    }
    insert_top3(raw, next.trajectory_top3);
    next.trigger_count = ordinal;
    const double mean_delta = raw - next.trigger_mean;
    next.trigger_mean += mean_delta / static_cast<double>(ordinal);
    next.trigger_m2 += mean_delta * (raw - next.trigger_mean);
    next.score_gt_0p5 += raw > 0.5;
    next.score_gt_0p75 += raw > 0.75;
    next.score_gt_0p9 += raw > 0.9;
    next.score_gt_0p95 += raw > 0.95;

    const double denominator = static_cast<double>(ordinal);
    const double mean = next.trigger_mean;
    double variance = next.trigger_m2 / denominator;
    if (variance < 0.0 && variance > -1.0e-18)
        variance = 0.0;
    if (variance < 0.0)
        return false;
    const double duration_seconds = input->anchor_ns >= input->event_start_ns
        ? static_cast<double>(input->anchor_ns - input->event_start_ns) / 1.0e9
        : 0.0;
    const double records = static_cast<double>(input->record_count);
    const double periodic = input->trigger_kind == 1u ? 1.0 : 0.0;
    float candidate[FK_CAUSAL_EVENT_CALIBRATOR_FEATURES]{
        static_cast<float>(raw),
        static_cast<float>(local_sum / records),
        static_cast<float>(mean_top(local_top, input->record_count, 3u)),
        static_cast<float>(next.trajectory_top3[0]),
        static_cast<float>(raw),
        static_cast<float>(next.ema_0p5),
        static_cast<float>(mean),
        static_cast<float>(std::sqrt(variance)),
        static_cast<float>(mean_top(next.trajectory_top3, ordinal, 2u)),
        static_cast<float>(mean_top(next.trajectory_top3, ordinal, 3u)),
        static_cast<float>(static_cast<double>(next.score_gt_0p5) / denominator),
        static_cast<float>(static_cast<double>(next.score_gt_0p75) / denominator),
        static_cast<float>(static_cast<double>(next.score_gt_0p9) / denominator),
        static_cast<float>(static_cast<double>(next.score_gt_0p95) / denominator),
        static_cast<float>(std::log1p(denominator)),
        static_cast<float>(std::log1p(duration_seconds)),
        static_cast<float>(std::log1p(records)),
        static_cast<float>(static_cast<double>(input->checkpoint_packet) / 20.0),
        static_cast<float>(periodic),
        static_cast<float>(1.0 - periodic),
        static_cast<float>(retained_sum[0] / records),
        static_cast<float>(retained_sum[1] / records),
        static_cast<float>(retained_sum[2] / records),
        static_cast<float>(static_cast<double>(missing_count[0]) / records),
        static_cast<float>(static_cast<double>(missing_count[1]) / records),
        static_cast<float>(static_cast<double>(missing_count[2]) / records),
        static_cast<float>(static_cast<double>(complete_count) / records),
        static_cast<float>((requested_mask >> 0u) & 1u),
        static_cast<float>((requested_mask >> 1u) & 1u),
        static_cast<float>((requested_mask >> 2u) & 1u),
        static_cast<float>(ordinal > 1u ? raw - next.prior_score : 0.0),
        static_cast<float>((raw - next.first_score) /
            static_cast<double>(std::max<uint64_t>(ordinal - 1u, 1u))),
    };
    if (!output_finite(candidate))
        return false;
    next.prior_score = raw;
    next.initialized = 1u;
    *state = next;
    std::memcpy(output, candidate, sizeof(candidate));
    return true;
}

}  // extern "C"
