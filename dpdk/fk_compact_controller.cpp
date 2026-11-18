#include "fk_compact_controller.h"

#include <cstring>

namespace {

static uint8_t component_count(uint8_t mask) {
    return static_cast<uint8_t>(
        ((mask & FK_COMPONENT_STAT) != 0u ? 1u : 0u) +
        ((mask & FK_COMPONENT_SEQ) != 0u ? 1u : 0u) +
        ((mask & FK_COMPONENT_JA4) != 0u ? 1u : 0u));
}

static void refresh_ja4_missing_reason(
        fk_compact_flow_table *table,
        fk_compact_flow_handle handle,
        fk_component_flow *flow,
        bool ja4_applicable) {
    if (flow == nullptr)
        return;
    if (!ja4_applicable) {
        flow->missing_reason[2] = FK_MISSING_NOT_APPLICABLE;
        return;
    }
    if ((flow->mask & FK_COMPONENT_JA4) == 0u) {
        if (flow->missing_reason[2] != FK_MISSING_LOST_OR_FAILED)
            flow->missing_reason[2] = FK_MISSING_NOT_SELECTED;
        return;
    }
    if (flow->missing_reason[2] == FK_MISSING_LOST_OR_FAILED)
        return;
    const fk_compact_ja4_state *ja4 =
        fk_compact_flow_table_ja4(table, handle);
    flow->missing_reason[2] =
        ja4 != nullptr &&
            (ja4->client.present != 0u || ja4->server.present != 0u)
        ? FK_MISSING_PRESENT : FK_MISSING_NOT_YET_AVAILABLE;
}

static bool checkpoint_common(
        fk_cpu_pipeline *pipeline,
        fk_compact_flow_table *table,
        fk_compact_flow_handle handle,
        const float *features,
        size_t feature_count,
        const float *action_values,
        size_t action_value_count,
        bool injected_values,
        bool requested_action_override,
        uint8_t requested_mask_override,
        bool enable_value_replacement,
        fk_compact_retention_policy_kind whole_flow_replacement_policy,
        uint32_t maximum_lru_victim_flows,
        const fk_resource_costs *resource_costs,
        bool ja4_applicable,
        fk_pressure_mode pressure,
        uint32_t packet_count,
        uint64_t timestamp_ns,
        const fk_component_policy_config *config,
        fk_compact_controller_result *result,
        uint64_t whole_flow_replacement_seed = 0u,
        const fk_compact_release_guard *release_guard = nullptr,
        bool *persistence_pending = nullptr) {
    if(persistence_pending)*persistence_pending=false;
    if(release_guard && (!release_guard->authorize || !persistence_pending))return false;
    if (table == nullptr || resource_costs == nullptr || config == nullptr ||
        result == nullptr ||
        requested_mask_override > FK_COMPONENT_FULL ||
        (injected_values
            ? action_values == nullptr || action_value_count != 8u
            : pipeline == nullptr || features == nullptr))
        return false;
    *result = {};
    fk_component_flow *flow =
        fk_compact_flow_table_component_flow(table, handle);
    if (flow == nullptr)
        return false;
    fk_budget_snapshot budget_snapshot{};
    fk_state_budget_snapshot(
        fk_compact_flow_table_budget(table), &budget_snapshot);
    result->controlled_bytes_before = budget_snapshot.used_bytes;
    result->controlled_bytes_after = budget_snapshot.used_bytes;
    result->previous_mask = flow->mask;
    result->final_mask = flow->mask;
    result->released_mask_before = flow->released_mask;
    result->released_mask_after = flow->released_mask;
    result->observation_complete = flow->observation_complete;
    result->protocol_applicable_mask = static_cast<uint8_t>(
        FK_COMPONENT_STAT | FK_COMPONENT_SEQ |
        (ja4_applicable ? FK_COMPONENT_JA4 : FK_COMPONENT_NONE));
    for (size_t index = 0u; index < 3u; ++index)
        result->missing_reason[index] = flow->missing_reason[index];
    result->decision_due = fk_component_flow_decision_due(
        flow, packet_count, timestamp_ns);
    if (!result->decision_due)
        return true;
    fk_component_bytes component_bytes{};
    fk_compact_flow_table_component_bytes(&component_bytes);
    uint8_t materializable_mask = FK_COMPONENT_NONE;
    if (!fk_compact_flow_table_materializable_mask(
            table, handle, &materializable_mask))
        return false;
    result->materializable_mask = materializable_mask;
    result->pool_unavailable_mask =
        static_cast<uint8_t>(
            FK_COMPONENT_FULL & ~materializable_mask);
    bool selected = false;
    float decision_values[8]{};
    if (injected_values) {
        if (action_value_count != 8u)
            return false;
        for (size_t mask = 0u; mask < 8u; ++mask)
            decision_values[mask] = action_values[mask];
    } else if (!fk_cpu_pipeline_predict_action_values(
                   pipeline,
                   flow,
                   features,
                   feature_count,
                   decision_values)) {
        return false;
    }
    float utilities[8]{};
    if (!fk_cpu_pipeline_compute_action_utilities(
            flow,
            decision_values,
            &component_bytes,
            resource_costs,
            FK_COMPONENT_FULL,
            utilities))
        return false;
    /* Action values are the cheap default victim valuation.  The causal
     * transition head is deliberately not evaluated speculatively: it is a
     * conflict resolver and is invoked below only after the ordinary atomic
     * replacement path proves that the requested state cannot be admitted. */
    const bool transition_fallback_available = enable_value_replacement &&
        !injected_values && pipeline != nullptr && features != nullptr &&
        fk_cpu_pipeline_has_transition_value(pipeline);
    if (enable_value_replacement &&
        !fk_compact_flow_table_refresh_action_values(
            table, handle, decision_values)) {
        return false;
    }
    uint8_t provisional_floor = FK_COMPONENT_NONE;
    bool provisional_active = false;
    const bool preserve_full_state =
        !requested_action_override &&
        config->preserve_full_state_in_normal != 0u &&
        pressure == FK_PRESSURE_NORMAL;
    if (requested_action_override) {
        result->requested_mask = requested_mask_override;
        result->requested_utility = utilities[requested_mask_override];
    } else if (preserve_full_state) {
        result->requested_mask = static_cast<uint8_t>(
            result->protocol_applicable_mask & ~flow->released_mask);
        result->requested_utility = utilities[result->requested_mask];
    } else {
        /* Freeze the policy's logical request under the same protocol,
         * pressure, cost, chain, and deterministic tie-break contract as the
         * physical path, but before irreversible-release, pool, or budget
         * feasibility can turn it into a fallback. */
        fk_component_flow request_flow = *flow;
        request_flow.released_mask = FK_COMPONENT_NONE;
        fk_component_candidate request_candidates[8]{};
        const size_t request_count = fk_component_rank_candidates(
            &request_flow,
            utilities,
            &component_bytes,
            FK_COMPONENT_FULL,
            ja4_applicable,
            pressure,
            config,
            request_candidates);
        if (request_count == 0u)
            return false;
        const uint8_t model_request = request_candidates[0].mask;
        result->requested_mask = model_request;
        result->requested_utility = request_candidates[0].utility;
        if (config->provisional_minimum_mask != FK_COMPONENT_NONE &&
            packet_count < config->provisional_until_packet) {
            provisional_floor = static_cast<uint8_t>(
                config->provisional_minimum_mask &
                result->protocol_applicable_mask & ~flow->released_mask);
            const uint8_t maximum = config->maximum_components[
                static_cast<size_t>(pressure)];
            /* Preserve temporal continuity when pressure permits only one
             * optional component.  This gives the common safety envelope the
             * nested CORE -> SEQ -> STAT+SEQ stack property instead of
             * dropping the whole floor and letting a weak Teacher jump to an
             * unrelated singleton such as JA4. */
            if (maximum == 1u && component_count(provisional_floor) > 1u) {
                provisional_floor =
                    (provisional_floor & FK_COMPONENT_SEQ) != 0u
                    ? FK_COMPONENT_SEQ
                    : ((provisional_floor & FK_COMPONENT_STAT) != 0u
                        ? FK_COMPONENT_STAT : FK_COMPONENT_JA4);
            }
            if (provisional_floor != FK_COMPONENT_NONE &&
                component_count(provisional_floor) <= maximum) {
                uint8_t protected_request = static_cast<uint8_t>(
                    (model_request | provisional_floor) &
                    result->protocol_applicable_mask & ~flow->released_mask);
                if (component_count(protected_request) > maximum)
                    protected_request = provisional_floor;
                result->requested_mask = protected_request;
                result->requested_utility = utilities[protected_request];
                provisional_active = true;
            }
        }
    }
    if ((result->requested_mask & ~result->protocol_applicable_mask) != 0u)
        return false;
    fk_component_candidate ranked_candidates[8]{};
    const size_t ranked_candidate_count = fk_component_rank_candidates(
        flow,
        utilities,
        &component_bytes,
        FK_COMPONENT_FULL,
        ja4_applicable,
        pressure,
        config,
        ranked_candidates);
    fk_component_candidate candidates[8]{};
    size_t candidate_count = 0u;
    const auto append_candidate = [&](uint8_t mask) {
        if (mask > FK_COMPONENT_FULL)
            return;
        for (size_t index = 0u; index < candidate_count; ++index) {
            if (candidates[index].mask == mask)
                return;
        }
        if (candidate_count < 8u) {
            candidates[candidate_count].mask = mask;
            candidates[candidate_count].utility = utilities[mask];
            candidates[candidate_count].rank_value = utilities[mask];
            candidate_count++;
        }
    };
    /* The short-prefix insurance is an ordering constraint, not a resource
     * exemption.  The ordinary learned list remains intact as the fallback
     * when either protected request cannot be installed atomically. */
    if (requested_action_override) {
        /* A causal keep-existing intervention is a one-action transaction,
         * not a hint to the ordinary ranked fallback list.  Admitting any
         * second candidate here could release the anchored victim set and
         * silently change the estimand. */
        append_candidate(result->requested_mask);
    } else if (preserve_full_state) {
        append_candidate(result->requested_mask);
    } else if (provisional_active) {
        append_candidate(provisional_floor);
        append_candidate(result->requested_mask);
    }
    if (!requested_action_override) {
        for (size_t index = 0u; index < ranked_candidate_count; ++index)
            append_candidate(ranked_candidates[index].mask);
    }
    for (size_t index = 0u; index < candidate_count; ++index) {
        result->decision.candidates_considered++;
        fk_compact_value_replacement_outcome replacement{};
        fk_transition_result transition = FK_TRANSITION_ILLEGAL_MASK;
        const auto commit_candidate = [&]() {
            if(release_guard) {
                fk_compact_persistent_policy policy=FK_COMPACT_PERSISTENT_FLOWKEEP;
                if(whole_flow_replacement_policy==FK_COMPACT_POLICY_LRU)policy=FK_COMPACT_PERSISTENT_LRU;
                else if(whole_flow_replacement_policy==FK_COMPACT_POLICY_CLOCK)policy=FK_COMPACT_PERSISTENT_CLOCK;
                else if(whole_flow_replacement_policy==FK_COMPACT_POLICY_TWO_Q)policy=FK_COMPACT_PERSISTENT_TWO_Q;
                else if(whole_flow_replacement_policy==FK_COMPACT_POLICY_FIFO)policy=FK_COMPACT_PERSISTENT_FIFO;
                else if(whole_flow_replacement_policy==FK_COMPACT_POLICY_SUMMARY_HISTORY ||
                        whole_flow_replacement_policy==FK_COMPACT_POLICY_FULL_STATE ||
                        whole_flow_replacement_policy==FK_COMPACT_POLICY_CORE_ONLY)
                    policy=FK_COMPACT_PERSISTENT_NO_REPLACEMENT;
                else if(whole_flow_replacement_policy!=FK_COMPACT_POLICY_FLOWKEEP)return FK_COMPACT_VALUE_REPLACEMENT_INVALID;
                return fk_compact_flow_table_commit_persistent_transition(table,handle,candidates[index].mask,
                    ja4_applicable,policy,maximum_lru_victim_flows ? maximum_lru_victim_flows : 64u,
                    packet_count,timestamp_ns,config,release_guard,&replacement,&transition);
            }
            if (whole_flow_replacement_policy == FK_COMPACT_POLICY_LRU) {
                return fk_compact_flow_table_commit_atomic_lru_transition(
                    table,
                    handle,
                    candidates[index].mask,
                    ja4_applicable,
                    maximum_lru_victim_flows,
                    packet_count,
                    timestamp_ns,
                    config,
                    &replacement,
                    &transition);
            }
            if (whole_flow_replacement_policy == FK_COMPACT_POLICY_LFU) {
                return fk_compact_flow_table_commit_atomic_lfu_transition(
                    table, handle, candidates[index].mask, ja4_applicable,
                    maximum_lru_victim_flows, packet_count, timestamp_ns,
                    config, &replacement, &transition);
            }
            if (whole_flow_replacement_policy == FK_COMPACT_POLICY_FIFO) {
                return fk_compact_flow_table_commit_atomic_fifo_transition(
                    table, handle, candidates[index].mask, ja4_applicable,
                    maximum_lru_victim_flows, packet_count, timestamp_ns,
                    config, &replacement, &transition);
            }
            if (whole_flow_replacement_policy ==
                    FK_COMPACT_POLICY_SEEDED_RANDOM_RETENTION) {
                return
                    fk_compact_flow_table_commit_atomic_seeded_random_transition(
                        table, handle, candidates[index].mask,
                        ja4_applicable, maximum_lru_victim_flows,
                        whole_flow_replacement_seed, packet_count,
                        timestamp_ns, config, &replacement, &transition);
            }
            if (whole_flow_replacement_policy == FK_COMPACT_POLICY_CLOCK) {
                return fk_compact_flow_table_commit_atomic_clock_transition(
                    table, handle, candidates[index].mask, ja4_applicable,
                    maximum_lru_victim_flows, packet_count, timestamp_ns,
                    config, &replacement, &transition);
            }
            if (whole_flow_replacement_policy == FK_COMPACT_POLICY_TWO_Q) {
                return fk_compact_flow_table_commit_atomic_two_q_transition(
                    table, handle, candidates[index].mask, ja4_applicable,
                    maximum_lru_victim_flows, packet_count, timestamp_ns,
                    config, &replacement, &transition);
            }
            if (whole_flow_replacement_policy == FK_COMPACT_POLICY_ARC) {
                return fk_compact_flow_table_commit_atomic_arc_transition(
                    table, handle, candidates[index].mask, ja4_applicable,
                    maximum_lru_victim_flows, packet_count, timestamp_ns,
                    config, &replacement, &transition);
            }
            if (whole_flow_replacement_policy == FK_COMPACT_POLICY_GDSF) {
                return fk_compact_flow_table_commit_atomic_gdsf_transition(
                    table, handle, candidates[index].mask, ja4_applicable,
                    maximum_lru_victim_flows, packet_count, timestamp_ns,
                    config, &replacement, &transition);
            }
            return fk_compact_flow_table_commit_atomic_transition(
                    table,
                    handle,
                    candidates[index].mask,
                    ja4_applicable,
                    enable_value_replacement,
                    packet_count,
                    timestamp_ns,
                    config,
                    &replacement,
                    &transition);
        };
        fk_compact_value_replacement_status status = commit_candidate();
        result->value_victim_probes += replacement.victim_probes;
        bool transition_fallback_active = false;
        const uint8_t transition_base_mask = flow->mask;
        if (index == 0u && transition_fallback_available &&
            (status == FK_COMPACT_VALUE_REPLACEMENT_VALUE_REJECTED ||
             status == FK_COMPACT_VALUE_REPLACEMENT_NO_PLAN)) {
            result->transition_value_fallback_attempted = 1u;
            float incoming_replacement_values[8]{};
            if (!fk_cpu_pipeline_build_transition_potentials(
                    pipeline,
                    features,
                    feature_count,
                    transition_base_mask,
                    incoming_replacement_values) ||
                !fk_compact_flow_table_refresh_transition_values(
                    table, handle, incoming_replacement_values))
                return false;
            transition_fallback_active = true;
            replacement = {};
            transition = FK_TRANSITION_ILLEGAL_MASK;
            status = commit_candidate();
            result->value_victim_probes += replacement.victim_probes;
            if (status == FK_COMPACT_VALUE_REPLACEMENT_COMMITTED ||
                status == FK_COMPACT_VALUE_REPLACEMENT_NOT_NEEDED) {
                result->transition_value_fallback_succeeded = 1u;
            } else if (!fk_compact_flow_table_refresh_action_values(
                           table, handle, decision_values)) {
                return false;
            }
        }
        if(status==FK_COMPACT_VALUE_REPLACEMENT_PERSISTENCE_PENDING) {
            if(!persistence_pending)return false;
            *persistence_pending=true;
            // Keep the same checkpoint pending. Never fall back to a cheaper
            // candidate merely because this candidate awaits durable evidence.
            result->applied=false;
            result->final_mask=flow->mask;
            result->released_mask_after=flow->released_mask;
            result->observation_complete=flow->observation_complete;
            result->decision.selected_mask=flow->mask;
            result->decision.selected_utility=utilities[flow->mask];
            result->decision.result=FK_TRANSITION_STORAGE_FAILED;
            for(size_t i=0;i<3;++i)result->missing_reason[i]=flow->missing_reason[i];
            fk_state_budget_snapshot(fk_compact_flow_table_budget(table),&budget_snapshot);
            result->controlled_bytes_after=budget_snapshot.used_bytes;
            return true;
        }
        if (enable_value_replacement &&
            status != FK_COMPACT_VALUE_REPLACEMENT_NOT_NEEDED) {
            result->value_replacement_attempted = 1u;
            result->incoming_bundle_gain =
                replacement.incoming_bundle_gain;
            result->victim_total_loss = replacement.victim_total_loss;
            result->value_eviction_hysteresis_eta =
                replacement.hysteresis_eta;
        }
        if (status == FK_COMPACT_VALUE_REPLACEMENT_VALUE_REJECTED ||
            status == FK_COMPACT_VALUE_REPLACEMENT_NO_PLAN ||
            status == FK_COMPACT_VALUE_REPLACEMENT_TRACE_FULL) {
            result->decision.budget_rejections++;
            continue;
        }
        if (status == FK_COMPACT_VALUE_REPLACEMENT_INVALID)
            return false;
        if (status == FK_COMPACT_VALUE_REPLACEMENT_COMMITTED) {
            if (enable_value_replacement) {
                result->value_replacement_committed = 1u;
                result->value_victims_released +=
                    replacement.victim_components;
            }
            if (whole_flow_replacement_policy == FK_COMPACT_POLICY_LRU)
                result->lru_victims_released +=
                    replacement.victim_flows;
            else if (whole_flow_replacement_policy == FK_COMPACT_POLICY_LFU)
                result->lfu_victims_released +=
                    replacement.victim_flows;
            else if (whole_flow_replacement_policy == FK_COMPACT_POLICY_FIFO)
                result->fifo_victims_released +=
                    replacement.victim_flows;
            else if (whole_flow_replacement_policy ==
                     FK_COMPACT_POLICY_SEEDED_RANDOM_RETENTION)
                result->seeded_random_victims_released +=
                    replacement.victim_flows;
            else if (whole_flow_replacement_policy == FK_COMPACT_POLICY_CLOCK)
                result->clock_victims_released += replacement.victim_flows;
            else if (whole_flow_replacement_policy == FK_COMPACT_POLICY_TWO_Q)
                result->two_q_victims_released += replacement.victim_flows;
            else if (whole_flow_replacement_policy == FK_COMPACT_POLICY_ARC)
                result->arc_victims_released += replacement.victim_flows;
            else if (whole_flow_replacement_policy == FK_COMPACT_POLICY_GDSF)
                result->gdsf_victims_released += replacement.victim_flows;
        }
        result->decision.selected_mask = candidates[index].mask;
        result->decision.selected_utility = candidates[index].utility;
        result->decision.result = transition;
        selected = transition == FK_TRANSITION_APPLIED ||
            transition == FK_TRANSITION_NO_CHANGE;
        if (!selected)
            return false;
        if (transition_fallback_active &&
            result->transition_value_fallback_succeeded != 0u) {
            /* Persist victim potentials only when the successful conflict
             * resolution changed the physical anchor.  Otherwise the vector
             * already describes the resident state used by the branch. */
            uint8_t resident_mask = FK_COMPONENT_NONE;
            if (!fk_compact_flow_table_resident_component_mask(
                    table, handle, &resident_mask))
                return false;
            if (resident_mask != transition_base_mask) {
                float resident_replacement_values[8]{};
                if (!fk_cpu_pipeline_build_transition_potentials(
                        pipeline,
                        features,
                        feature_count,
                        resident_mask,
                        resident_replacement_values) ||
                    !fk_compact_flow_table_refresh_transition_values(
                        table, handle, resident_replacement_values))
                    return false;
            }
        }
        break;
    }
    if (!selected)
        return false;
    refresh_ja4_missing_reason(
        table, handle, flow, ja4_applicable);
    if (!fk_compact_flow_table_materializable_mask(
            table, handle, &materializable_mask))
        return false;
    result->materializable_mask = materializable_mask;
    result->pool_unavailable_mask = static_cast<uint8_t>(
        FK_COMPONENT_FULL & ~materializable_mask);
    result->applied = true;
    result->final_mask = flow->mask;
    result->released_mask_after = flow->released_mask;
    result->observation_complete = flow->observation_complete;
    for (size_t index = 0u; index < 3u; ++index)
        result->missing_reason[index] = flow->missing_reason[index];
    fk_state_budget_snapshot(
        fk_compact_flow_table_budget(table), &budget_snapshot);
    result->controlled_bytes_after = budget_snapshot.used_bytes;
    return true;
}

}  // namespace

extern "C" {

bool fk_compact_retention_policy_parse(
        const char *name,
        fk_compact_retention_policy_kind *kind) {
    if (name == nullptr || kind == nullptr)
        return false;
    struct policy_name {
        const char *name;
        fk_compact_retention_policy_kind kind;
    };
    static constexpr policy_name policies[]{
        {"flowkeep", FK_COMPACT_POLICY_FLOWKEEP},
        {"lru", FK_COMPACT_POLICY_LRU},
        {"fixed_ttl", FK_COMPACT_POLICY_FIXED_TTL},
        {"protocol_aware", FK_COMPACT_POLICY_PROTOCOL_AWARE},
        {"protocol_deadline", FK_COMPACT_POLICY_PROTOCOL_DEADLINE},
        {"handshake_only", FK_COMPACT_POLICY_HANDSHAKE_ONLY},
        {"full_state", FK_COMPACT_POLICY_FULL_STATE},
        {"summary_only", FK_COMPACT_POLICY_SUMMARY_ONLY},
        {"history_only", FK_COMPACT_POLICY_HISTORY_ONLY},
        {"summary_history", FK_COMPACT_POLICY_SUMMARY_HISTORY},
        {"summary_handshake", FK_COMPACT_POLICY_SUMMARY_HANDSHAKE},
        {"history_handshake", FK_COMPACT_POLICY_HISTORY_HANDSHAKE},
        {"core_only", FK_COMPACT_POLICY_CORE_ONLY},
        {"lfu", FK_COMPACT_POLICY_LFU},
        {"fifo", FK_COMPACT_POLICY_FIFO},
        {"seeded_random_retention",
         FK_COMPACT_POLICY_SEEDED_RANDOM_RETENTION},
        {"clock", FK_COMPACT_POLICY_CLOCK},
        {"two_q", FK_COMPACT_POLICY_TWO_Q},
        {"arc", FK_COMPACT_POLICY_ARC},
        {"gdsf", FK_COMPACT_POLICY_GDSF},
        {"learned_detection_loss_per_byte",
         FK_COMPACT_POLICY_LEARNED_DETECTION_LOSS_PER_BYTE},
    };
    for (const policy_name &policy : policies) {
        if (std::strcmp(name, policy.name) == 0) {
            *kind = policy.kind;
            return true;
        }
    }
    return false;
}

bool fk_compact_retention_policy_uses_learned_selector(
        fk_compact_retention_policy_kind kind) {
    return kind == FK_COMPACT_POLICY_FLOWKEEP ||
        kind == FK_COMPACT_POLICY_LEARNED_DETECTION_LOSS_PER_BYTE;
}

static bool checkpoint_baseline_common(
        fk_compact_flow_table *table,
        fk_compact_flow_handle handle,
        const fk_resource_costs *resource_costs,
        bool ja4_applicable,
        fk_pressure_mode pressure,
        uint32_t packet_count,
        uint64_t timestamp_ns,
        uint64_t flow_age_ns,
        const fk_component_policy_config *component_config,
        const fk_compact_baseline_policy_config *baseline_config,
        fk_compact_controller_result *result,
        const fk_compact_release_guard *release_guard, bool *persistence_pending) {
    if (baseline_config == nullptr || result == nullptr ||
        baseline_config->fixed_state_lru_replacement > 1u ||
        (baseline_config->fixed_state_lru_replacement != 0u &&
         baseline_config->kind != FK_COMPACT_POLICY_SUMMARY_HISTORY) ||
        fk_compact_retention_policy_uses_learned_selector(
            baseline_config->kind) ||
        baseline_config->kind < FK_COMPACT_POLICY_LRU ||
        baseline_config->kind > FK_COMPACT_POLICY_GDSF ||
        (baseline_config->kind ==
             FK_COMPACT_POLICY_SEEDED_RANDOM_RETENTION
            ? baseline_config->seeded_random_seed_precommitted != 1u
            : (baseline_config->seeded_random_seed_precommitted != 0u ||
               baseline_config->seeded_random_seed != 0u)))
        return false;
    fk_component_flow *baseline_flow =
        fk_compact_flow_table_component_flow(table, handle);
    if (baseline_flow == nullptr)
        return false;
    if (baseline_config->kind == FK_COMPACT_POLICY_FIXED_TTL) {
        if (baseline_config->fixed_ttl_ns == 0u ||
            !fk_compact_flow_table_set_fixed_ttl(
                table, handle, baseline_config->fixed_ttl_ns))
            return false;
        fk_component_flow *flow_before =
            fk_compact_flow_table_component_flow(table, handle);
        if (flow_before == nullptr)
            return false;
        const uint8_t mask_before = flow_before->mask;
        const uint8_t released_before = flow_before->released_mask;
        fk_budget_snapshot budget_before{};
        fk_compact_flow_table_budget_snapshot(table, &budget_before);
        bool expired = false;
        if (!fk_compact_flow_table_apply_due_timer(
                table,
                handle,
                timestamp_ns,
                packet_count,
                &expired))
            return false;
        if (expired) {
            *result = {};
            fk_component_flow *flow =
                fk_compact_flow_table_component_flow(table, handle);
            if (flow == nullptr)
                return false;
            result->decision_due = true;
            result->applied = true;
            result->previous_mask = mask_before;
            result->final_mask = flow->mask;
            result->released_mask_before = released_before;
            result->released_mask_after = flow->released_mask;
            result->observation_complete = flow->observation_complete;
            result->protocol_applicable_mask = static_cast<uint8_t>(
                FK_COMPONENT_STAT | FK_COMPONENT_SEQ |
                (ja4_applicable ? FK_COMPONENT_JA4 : FK_COMPONENT_NONE));
            result->decision.selected_mask = flow->mask;
            result->requested_mask = FK_COMPONENT_NONE;
            result->requested_utility = 0.0f;
            result->decision.result = FK_TRANSITION_EXPIRED;
            fk_budget_snapshot snapshot{};
            fk_compact_flow_table_budget_snapshot(table, &snapshot);
            result->controlled_bytes_before = budget_before.used_bytes;
            result->controlled_bytes_after = snapshot.used_bytes;
            for (size_t index = 0u; index < 3u; ++index)
                result->missing_reason[index] =
                    flow->missing_reason[index];
            return true;
        }
    }
    uint8_t desired = FK_COMPONENT_NONE;
    uint8_t requested = FK_COMPONENT_NONE;
    switch (baseline_config->kind) {
    case FK_COMPACT_POLICY_LRU:
    case FK_COMPACT_POLICY_LFU:
    case FK_COMPACT_POLICY_FIFO:
    case FK_COMPACT_POLICY_SEEDED_RANDOM_RETENTION:
    case FK_COMPACT_POLICY_CLOCK:
    case FK_COMPACT_POLICY_TWO_Q:
    case FK_COMPACT_POLICY_ARC:
    case FK_COMPACT_POLICY_GDSF:
    case FK_COMPACT_POLICY_FULL_STATE:
        desired = ja4_applicable ? static_cast<uint8_t>(FK_COMPONENT_FULL) :
            static_cast<uint8_t>(FK_COMPONENT_STAT | FK_COMPONENT_SEQ);
        requested = desired;
        break;
    case FK_COMPACT_POLICY_FIXED_TTL:
        desired = flow_age_ns >= baseline_config->fixed_ttl_ns
            ? static_cast<uint8_t>(FK_COMPONENT_NONE)
            : (ja4_applicable ? static_cast<uint8_t>(FK_COMPONENT_FULL) :
               static_cast<uint8_t>(FK_COMPONENT_STAT | FK_COMPONENT_SEQ));
        requested = desired;
        break;
    case FK_COMPACT_POLICY_PROTOCOL_AWARE:
        desired = ja4_applicable
            ? static_cast<uint8_t>(FK_COMPONENT_STAT | FK_COMPONENT_JA4)
            : static_cast<uint8_t>(FK_COMPONENT_STAT | FK_COMPONENT_SEQ);
        requested = desired;
        break;
    case FK_COMPACT_POLICY_PROTOCOL_DEADLINE:
        desired = pressure == FK_PRESSURE_NORMAL
            ? (ja4_applicable
                ? static_cast<uint8_t>(FK_COMPONENT_STAT | FK_COMPONENT_JA4)
                : static_cast<uint8_t>(FK_COMPONENT_STAT | FK_COMPONENT_SEQ))
            : static_cast<uint8_t>(FK_COMPONENT_STAT);
        requested = desired;
        break;
    case FK_COMPACT_POLICY_HANDSHAKE_ONLY:
        desired = ja4_applicable ? FK_COMPONENT_JA4 : FK_COMPONENT_NONE;
        requested = desired;
        break;
    case FK_COMPACT_POLICY_SUMMARY_ONLY:
        requested = FK_COMPONENT_STAT;
        desired = FK_COMPONENT_STAT;
        break;
    case FK_COMPACT_POLICY_HISTORY_ONLY:
        requested = FK_COMPONENT_SEQ;
        desired = FK_COMPONENT_SEQ;
        break;
    case FK_COMPACT_POLICY_SUMMARY_HISTORY:
        requested = static_cast<uint8_t>(
            FK_COMPONENT_STAT | FK_COMPONENT_SEQ);
        desired = static_cast<uint8_t>(FK_COMPONENT_STAT | FK_COMPONENT_SEQ);
        break;
    case FK_COMPACT_POLICY_SUMMARY_HANDSHAKE:
        desired = ja4_applicable
            ? static_cast<uint8_t>(FK_COMPONENT_STAT | FK_COMPONENT_JA4)
            : static_cast<uint8_t>(FK_COMPONENT_STAT);
        requested = desired;
        break;
    case FK_COMPACT_POLICY_HISTORY_HANDSHAKE:
        desired = ja4_applicable
            ? static_cast<uint8_t>(FK_COMPONENT_SEQ | FK_COMPONENT_JA4)
            : static_cast<uint8_t>(FK_COMPONENT_SEQ);
        requested = desired;
        break;
    case FK_COMPACT_POLICY_CORE_ONLY:
        /* CORE is the mandatory FlowTable entry and has no optional-component
         * bit.  Requesting NONE therefore releases/avoids STAT, SEQ and JA4
         * while preserving the flow itself. */
        desired = FK_COMPONENT_NONE;
        requested = FK_COMPONENT_NONE;
        break;
    case FK_COMPACT_POLICY_FLOWKEEP:
    case FK_COMPACT_POLICY_LEARNED_DETECTION_LOSS_PER_BYTE:
    default:
        return false;
    }

    /* Bootstrap or an earlier capacity decision may have already made an
     * optional component irreversibly unavailable.  Ordered baselines still
     * prefer their canonical mask, but must operate on the remaining legal
     * mask instead of submitting an impossible reacquisition and terminating
     * the Test run.  This is a feasibility constraint shared by every policy,
     * not a baseline-specific quality concession. */
    const uint8_t protocol_applicable = static_cast<uint8_t>(
        FK_COMPONENT_STAT | FK_COMPONENT_SEQ |
        (ja4_applicable ? FK_COMPONENT_JA4 : FK_COMPONENT_NONE));
    uint8_t irrecoverable = baseline_flow->released_mask;
    const uint8_t evidence_bits[3]{
        FK_COMPONENT_STAT, FK_COMPONENT_SEQ, FK_COMPONENT_JA4};
    for (size_t index = 0u; index < 3u; ++index) {
        if (baseline_flow->missing_reason[index] ==
                FK_MISSING_LOST_OR_FAILED) {
            irrecoverable = static_cast<uint8_t>(
                irrecoverable | evidence_bits[index]);
        }
    }
    const uint8_t legal = static_cast<uint8_t>(
        protocol_applicable & ~irrecoverable);
    desired = static_cast<uint8_t>(desired & legal);
    requested = static_cast<uint8_t>(requested & legal);

    float values[8]{};
    fk_component_bytes component_bytes{};
    fk_compact_flow_table_component_bytes(&component_bytes);
    for (uint8_t mask = 0u; mask < 8u; ++mask) {
        const uint8_t overlap = static_cast<uint8_t>(mask & desired);
        const float desired_density = mask == desired ? 2.0f :
            static_cast<float>(overlap != 0u ? 0.5f : 0.0f);
        uint64_t bytes = 1u;
        if (mask != FK_COMPONENT_NONE) {
            bytes =
                ((mask & FK_COMPONENT_STAT) != 0u
                    ? component_bytes.stat_bytes : 0u) +
                ((mask & FK_COMPONENT_SEQ) != 0u
                    ? component_bytes.seq_bytes : 0u) +
                ((mask & FK_COMPONENT_JA4) != 0u
                    ? component_bytes.ja4_bytes : 0u);
        }
        values[mask] =
            component_config->rank_by_marginal_value_per_byte != 0u
            ? desired_density * static_cast<float>(bytes)
            : desired_density;
    }
    const bool ok = checkpoint_common(
        nullptr, table, handle, nullptr, 0u, values, 8u, true, true,
        requested, false,
        baseline_config->fixed_state_lru_replacement != 0u
            ? FK_COMPACT_POLICY_LRU : baseline_config->kind,
        baseline_config->maximum_lru_victims_per_decision,
        resource_costs, ja4_applicable, pressure, packet_count,
        timestamp_ns, component_config, result,
        baseline_config->seeded_random_seed,release_guard,persistence_pending);
    return ok;
}

bool fk_compact_controller_checkpoint_baseline(
        fk_compact_flow_table *table,
        fk_compact_flow_handle handle,
        const fk_resource_costs *resource_costs,
        bool ja4_applicable,
        fk_pressure_mode pressure,
        uint32_t packet_count,
        uint64_t timestamp_ns,
        uint64_t flow_age_ns,
        const fk_component_policy_config *component_config,
        const fk_compact_baseline_policy_config *baseline_config,
        fk_compact_controller_result *result) {
    return checkpoint_baseline_common(table,handle,resource_costs,ja4_applicable,pressure,packet_count,
        timestamp_ns,flow_age_ns,component_config,baseline_config,result,nullptr,nullptr);
}

bool fk_compact_controller_checkpoint_baseline_persistent(
        fk_compact_flow_table *table,
        fk_compact_flow_handle handle,
        const fk_resource_costs *resource_costs,
        bool ja4_applicable,
        fk_pressure_mode pressure,
        uint32_t packet_count,
        uint64_t timestamp_ns,
        uint64_t flow_age_ns,
        const fk_component_policy_config *component_config,
        const fk_compact_baseline_policy_config *baseline_config,
        fk_compact_controller_result *result,
        const fk_compact_release_guard *release_guard, bool *persistence_pending) {
    if(persistence_pending)*persistence_pending=false;
    if(!release_guard || !release_guard->authorize || !persistence_pending || !component_config || !resource_costs || !baseline_config ||
        (baseline_config->kind!=FK_COMPACT_POLICY_LRU && baseline_config->kind!=FK_COMPACT_POLICY_CLOCK &&
         baseline_config->kind!=FK_COMPACT_POLICY_TWO_Q && baseline_config->kind!=FK_COMPACT_POLICY_FIFO &&
         baseline_config->kind!=FK_COMPACT_POLICY_SUMMARY_HISTORY && baseline_config->kind!=FK_COMPACT_POLICY_FULL_STATE &&
         baseline_config->kind!=FK_COMPACT_POLICY_CORE_ONLY))return false;
    return checkpoint_baseline_common(table,handle,resource_costs,ja4_applicable,pressure,packet_count,
        timestamp_ns,flow_age_ns,component_config,baseline_config,result,release_guard,persistence_pending);
}

bool fk_compact_controller_checkpoint(
        fk_cpu_pipeline *pipeline,
        fk_compact_flow_table *table,
        fk_compact_flow_handle handle,
        const float *features,
        size_t feature_count,
        const fk_resource_costs *resource_costs,
        bool ja4_applicable,
        fk_pressure_mode pressure,
        uint32_t packet_count,
        uint64_t timestamp_ns,
        const fk_component_policy_config *config,
        fk_compact_controller_result *result) {
    return checkpoint_common(
        pipeline,
        table,
        handle,
        features,
        feature_count,
        nullptr,
        0u,
        false,
        false,
        FK_COMPONENT_NONE,
        true,
        FK_COMPACT_POLICY_FLOWKEEP,
        0u,
        resource_costs,
        ja4_applicable,
        pressure,
        packet_count,
        timestamp_ns,
        config,
        result);
}

bool fk_compact_controller_checkpoint_from_values(
        fk_compact_flow_table *table,
        fk_compact_flow_handle handle,
        const float *action_values,
        size_t action_value_count,
        const fk_resource_costs *resource_costs,
        bool ja4_applicable,
        fk_pressure_mode pressure,
        uint32_t packet_count,
        uint64_t timestamp_ns,
        const fk_component_policy_config *config,
        fk_compact_controller_result *result) {
    return checkpoint_common(
        nullptr,
        table,
        handle,
        nullptr,
        0u,
        action_values,
        action_value_count,
        true,
        false,
        FK_COMPONENT_NONE,
        true,
        FK_COMPACT_POLICY_FLOWKEEP,
        0u,
        resource_costs,
        ja4_applicable,
        pressure,
        packet_count,
        timestamp_ns,
        config,
        result);
}

bool fk_compact_controller_checkpoint_keep_existing_intervention(
        fk_compact_flow_table *table,
        fk_compact_flow_handle handle,
        const fk_resource_costs *resource_costs,
        bool ja4_applicable,
        fk_pressure_mode pressure,
        uint32_t packet_count,
        uint64_t timestamp_ns,
        const fk_component_policy_config *config,
        fk_compact_controller_result *result) {
    if (table == nullptr || result == nullptr)
        return false;
    const fk_component_flow *flow =
        fk_compact_flow_table_component_flow(table, handle);
    if (flow == nullptr || flow->mask > FK_COMPONENT_FULL ||
        (flow->mask & flow->released_mask) != 0u)
        return false;
    const uint8_t existing_mask = flow->mask;
    const float neutral_values[8]{};
    const bool ok = checkpoint_common(
        nullptr,
        table,
        handle,
        nullptr,
        0u,
        neutral_values,
        8u,
        true,
        true,
        existing_mask,
        false,
        FK_COMPACT_POLICY_FLOWKEEP,
        0u,
        resource_costs,
        ja4_applicable,
        pressure,
        packet_count,
        timestamp_ns,
        config,
        result);
    return ok && result->decision_due && result->applied &&
        result->previous_mask == existing_mask &&
        result->requested_mask == existing_mask &&
        result->final_mask == existing_mask &&
        result->controlled_bytes_after <= result->controlled_bytes_before &&
        result->value_replacement_attempted == 0u &&
        result->value_replacement_committed == 0u &&
        result->value_victims_released == 0u &&
        result->lru_victims_released == 0u &&
        result->lfu_victims_released == 0u &&
        result->fifo_victims_released == 0u &&
        result->seeded_random_victims_released == 0u;
}

bool fk_compact_controller_checkpoint_persistent(
        fk_cpu_pipeline *pipeline,
        fk_compact_flow_table *table,
        fk_compact_flow_handle handle,
        const float *features,
        size_t feature_count,
        const fk_resource_costs *resource_costs,
        bool ja4_applicable,
        fk_pressure_mode pressure,
        uint32_t packet_count,
        uint64_t timestamp_ns,
        const fk_component_policy_config *config,
        fk_compact_controller_result *result,
        const fk_compact_release_guard *release_guard, bool *persistence_pending) {
    if(persistence_pending)*persistence_pending=false;
    if(!release_guard || !release_guard->authorize || !persistence_pending)return false;

    return checkpoint_common(
        pipeline,
        table,
        handle,
        features,
        feature_count,
        nullptr,
        0u,
        false,
        false,
        FK_COMPONENT_NONE,
        true,
        FK_COMPACT_POLICY_FLOWKEEP,
        0u,
        resource_costs,
        ja4_applicable,
        pressure,
        packet_count,
        timestamp_ns,
        config,
        result,0,release_guard,persistence_pending);
}

bool fk_compact_controller_checkpoint_from_values_persistent(
        fk_compact_flow_table *table,
        fk_compact_flow_handle handle,
        const float *action_values,
        size_t action_value_count,
        const fk_resource_costs *resource_costs,
        bool ja4_applicable,
        fk_pressure_mode pressure,
        uint32_t packet_count,
        uint64_t timestamp_ns,
        const fk_component_policy_config *config,
        fk_compact_controller_result *result,
        const fk_compact_release_guard *release_guard, bool *persistence_pending) {
    if(persistence_pending)*persistence_pending=false;
    if(!release_guard || !release_guard->authorize || !persistence_pending)return false;

    return checkpoint_common(
        nullptr,
        table,
        handle,
        nullptr,
        0u,
        action_values,
        action_value_count,
        true,
        false,
        FK_COMPONENT_NONE,
        true,
        FK_COMPACT_POLICY_FLOWKEEP,
        0u,
        resource_costs,
        ja4_applicable,
        pressure,
        packet_count,
        timestamp_ns,
        config,
        result,0,release_guard,persistence_pending);
}

}  // extern "C"
