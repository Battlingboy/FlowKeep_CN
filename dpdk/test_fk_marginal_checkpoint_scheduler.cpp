#include "fk_marginal_checkpoint_scheduler.h"

#include <cassert>
#include <cstdio>

static fk_marginal_checkpoint_config configuration() {
    fk_marginal_checkpoint_config config{};
    config.horizon_packet = 20u;
    config.maximum_checks = 4u;
    const uint8_t stages[FK_MARGINAL_SCHEDULER_STAGES] =
        {8u, 12u, 16u, 20u, 32u, 48u, 65u};
    for (uint32_t stage = 0; stage < FK_MARGINAL_SCHEDULER_STAGES; ++stage) {
        config.stage_end[stage] = stages[stage];
        for (double &gain : config.gain_upper[stage])
            gain = 0.10;
    }
    config.alert_threshold = 0.60;
    config.observation_cost = 0.01;
    config.wait_cost_per_packet = 0.001;
    return config;
}

int main() {
    auto config = configuration();
    assert(fk_marginal_checkpoint_config_valid(&config));

    fk_marginal_checkpoint_state state{};
    fk_marginal_checkpoint_action action{};
    assert(fk_marginal_checkpoint_plan_first(
        &config, &state, 0.20, 1.0, false, &action));
    assert(action.kind == FK_MARGINAL_ACTION_NEXT);
    assert(action.packet == 4u);  // Predicted, not a configured fixed point.
    state = {};
    assert(fk_marginal_checkpoint_plan_first(
        &config, &state, 0.70, 1.0, false, &action));
    assert(action.kind == FK_MARGINAL_ACTION_NEXT);
    assert(action.packet == 1u);  // Mandatory first score is never delayed to 20.
    // V2 admission risk is a covariate, not a fusion score. Even risk above
    // the alert threshold must not force a packet-1 observation.
    auto aligned = config;
    aligned.detector_score_prior = 1;
    for (auto &bin : aligned.first_gain)
        for (uint32_t p = 0; p < 20; ++p)
            bin[p] = p < 4 ? .1 : .5;
    state = {};
    assert(fk_marginal_checkpoint_plan_first(
        &aligned, &state, .99, 1., false, &action));
    assert(action.packet == 5);
    aligned.first_gain[7][6] = .6;
    state = {};
    assert(fk_marginal_checkpoint_plan_first(
        &aligned, &state, .99, 1., false, &action));
    assert(action.packet == 7); // Off-grid predicted evidence, not 4/8/12/20.
    assert(fk_marginal_checkpoint_eof(&state, 3, &action));
    assert(action.kind == FK_MARGINAL_ACTION_CHECK_EOF && action.packet == 3);
    aligned.horizon_packet = 21;
    assert(!fk_marginal_checkpoint_config_valid(&aligned));
    state = {};
    assert(fk_marginal_checkpoint_observe(
        &config, &state, 4u, 0.20, 1.0, false, &action));
    assert(action.kind == FK_MARGINAL_ACTION_NEXT);
    assert(action.packet == 8u);  // Earliest point reaching the evidence need.
    assert(state.pending_packet == 8u);

    assert(fk_marginal_checkpoint_eof(&state, 6u, &action));
    assert(action.kind == FK_MARGINAL_ACTION_CHECK_EOF);
    assert(action.packet == 6u);

    // Terminal may be any prefix, not a special hard-coded 6->8 case.
    for (uint8_t terminal = 1u; terminal < 20u; ++terminal) {
        state = {};
        state.pending_packet = terminal + 1u;
        assert(fk_marginal_checkpoint_eof(&state, terminal, &action));
        assert(action.kind == FK_MARGINAL_ACTION_CHECK_EOF);
        assert(action.packet == terminal);
        assert(fk_marginal_checkpoint_eof(&state, terminal, &action));
        assert(action.kind == FK_MARGINAL_ACTION_STOP);
        state = {};
        state.last_observation_packet = terminal;
        state.pending_packet = terminal + 1u;
        assert(fk_marginal_checkpoint_eof(&state, terminal, &action));
        assert(action.kind == FK_MARGINAL_ACTION_STOP);
    }

    state = {};
    config.gain_upper[0][0] = 0.0;
    assert(fk_marginal_checkpoint_observe(
        &config, &state, 4u, 0.01, 0.0, true, &action));
    assert(action.kind == FK_MARGINAL_ACTION_STOP);
    assert(fk_marginal_checkpoint_eof(&state, 7u, &action));
    assert(action.kind == FK_MARGINAL_ACTION_STOP);

    state = {};
    assert(fk_marginal_checkpoint_eof(&state, 2u, &action));
    assert(action.kind == FK_MARGINAL_ACTION_CHECK_EOF);
    assert(action.packet == 2u);  // EOF before the first observation.

    state = {};
    config.gain_upper[0][0] = 0.0;
    assert(fk_marginal_checkpoint_observe(
        &config, &state, 4u, 0.01, 0.0, false, &action));
    assert(action.kind == FK_MARGINAL_ACTION_NEXT);
    assert(action.packet == 20u); // Uncertified low gain waits, not false STOP.

    // A flat current stage cannot hide later-stage evidence.
    auto future = configuration();
    for(double &rate:future.gain_upper[0])rate=0.0;
    state={};
    assert(fk_marginal_checkpoint_observe(&future,&state,4,.2,1.,false,&action));
    assert(action.kind==FK_MARGINAL_ACTION_NEXT && action.packet>8);
    // Reserve the last regular call at the horizon, not an arbitrary early
    // fourth point. An early EOF will instead score its actual last prefix.
    state={};state.calls=2;state.last_observation_packet=2;state.last_score=.1;
    assert(fk_marginal_checkpoint_observe(&future,&state,3,.2,1.,false,&action));
    assert(action.kind==FK_MARGINAL_ACTION_NEXT && action.packet==20);
    assert(state.observed_gain_per_packet>0.0);
    assert(fk_marginal_checkpoint_eof(&state,7,&action));
    assert(action.kind==FK_MARGINAL_ACTION_CHECK_EOF && action.packet==7);
    state={};state.calls=1;state.last_observation_packet=5;
    assert(!fk_marginal_checkpoint_observe(&future,&state,4,.2,1.,false,&action));

    state = {};
    config.gain_upper[0][0] = 0.10;
    assert(fk_marginal_checkpoint_observe(
        &config, &state, 20u, 0.01, 1.0, false, &action));
    assert(action.kind == FK_MARGINAL_ACTION_STOP);
    assert(action.packet == 20u);  // Hard horizon, never NEXT(>20).

    std::puts("marginal_checkpoint_scheduler: NEXT/STOP/dirty-EOF PASS");
    return 0;
}
