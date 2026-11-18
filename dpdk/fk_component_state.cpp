#include "fk_component_state.h"

#include <algorithm>
#include <array>
#include <atomic>
#include <cmath>
#include <limits>
#include <new>

namespace {

static_assert(sizeof(fk_component_flow) == 64u,
              "per-flow component state must stay cache compact");

constexpr std::size_t kComponentCount = FK_MEMORY_COMPONENT_COUNT;
constexpr std::array<uint8_t, 3> kEvidenceBits{
    FK_COMPONENT_STAT,
    FK_COMPONENT_SEQ,
    FK_COMPONENT_JA4,
};
constexpr std::array<fk_memory_component, 3> kMemoryComponents{
    FK_MEMORY_STAT,
    FK_MEMORY_SEQ,
    FK_MEMORY_JA4,
};

struct StateBudget {
    explicit StateBudget(uint64_t limit) : budget_bytes(limit) {
        for (auto &value : used_by_component)
            value.store(0u, std::memory_order_relaxed);
        for (auto &value : peak_by_component)
            value.store(0u, std::memory_order_relaxed);
    }

    const uint64_t budget_bytes;
    std::atomic<uint64_t> used_bytes{0u};
    std::atomic<uint64_t> peak_bytes{0u};
    std::array<std::atomic<uint64_t>, kComponentCount> used_by_component;
    std::array<std::atomic<uint64_t>, kComponentCount> peak_by_component;
    std::atomic<uint64_t> reserve_checks{0u};
    std::atomic<uint64_t> reserve_rejects{0u};
    std::atomic<uint64_t> release_errors{0u};
    std::atomic<uint64_t> hard_budget_violations{0u};
    mutable std::atomic_flag transaction_lock = ATOMIC_FLAG_INIT;
};

static StateBudget *implementation(fk_state_budget *budget) {
    return reinterpret_cast<StateBudget *>(budget);
}

static const StateBudget *implementation(const fk_state_budget *budget) {
    return reinterpret_cast<const StateBudget *>(budget);
}

static bool valid_component(fk_memory_component component) {
    return component >= FK_MEMORY_FLOW_TABLE &&
        component < FK_MEMORY_COMPONENT_COUNT;
}

static void update_peak(std::atomic<uint64_t> &peak, uint64_t value) {
    uint64_t observed = peak.load(std::memory_order_relaxed);
    while (observed < value &&
           !peak.compare_exchange_weak(
               observed,
               value,
               std::memory_order_relaxed,
               std::memory_order_relaxed)) {
    }
}

static uint64_t bytes_for_index(
        const fk_component_bytes &bytes,
        std::size_t index) {
    switch (index) {
    case 0u:
        return bytes.stat_bytes;
    case 1u:
        return bytes.seq_bytes;
    case 2u:
        return bytes.ja4_bytes;
    default:
        return 0u;
    }
}

static uint64_t owned_for_index(
        const fk_component_flow &flow,
        std::size_t index) {
    switch (index) {
    case 0u:
        return flow.owned.stat_bytes;
    case 1u:
        return flow.owned.seq_bytes;
    case 2u:
        return flow.owned.ja4_bytes;
    default:
        return 0u;
    }
}

static uint64_t bytes_for_mask(
        uint8_t mask,
        const fk_component_bytes &bytes,
        const fk_component_flow &flow) {
    uint64_t total = 0u;
    for (std::size_t index = 0u; index < kEvidenceBits.size(); ++index) {
        if ((mask & kEvidenceBits[index]) == 0u)
            continue;
        const uint64_t owned = owned_for_index(flow, index);
        total += owned != 0u ? owned : bytes_for_index(bytes, index);
    }
    return total;
}

static void set_owned_for_index(
        fk_component_flow &flow,
        std::size_t index,
        uint64_t bytes) {
    const uint32_t compact = static_cast<uint32_t>(bytes);
    switch (index) {
    case 0u:
        flow.owned.stat_bytes = compact;
        break;
    case 1u:
        flow.owned.seq_bytes = compact;
        break;
    case 2u:
        flow.owned.ja4_bytes = compact;
        break;
    default:
        break;
    }
}

static void lock_budget(const StateBudget &budget) {
    while (budget.transaction_lock.test_and_set(
               std::memory_order_acquire)) {
    }
}

static void unlock_budget(const StateBudget &budget) {
    budget.transaction_lock.clear(std::memory_order_release);
}

static bool apply_budget_transaction(
        StateBudget &budget,
        const uint64_t release_by_component[kComponentCount],
        const uint64_t reserve_by_component[kComponentCount]) {
    lock_budget(budget);
    uint64_t total_release = 0u;
    uint64_t total_reserve = 0u;
    bool release_invalid = false;
    bool arithmetic_invalid = false;
    for (std::size_t component = 0u;
         component < kComponentCount; ++component) {
        const uint64_t owned = budget.used_by_component[component].load(
            std::memory_order_relaxed);
        release_invalid = release_invalid ||
            release_by_component[component] > owned;
        arithmetic_invalid = arithmetic_invalid ||
            release_by_component[component] >
                std::numeric_limits<uint64_t>::max() - total_release ||
            reserve_by_component[component] >
                std::numeric_limits<uint64_t>::max() - total_reserve;
        if (!arithmetic_invalid) {
            total_release += release_by_component[component];
            total_reserve += reserve_by_component[component];
        }
    }
    const uint64_t current = budget.used_bytes.load(
        std::memory_order_relaxed);
    release_invalid = release_invalid || total_release > current;
    if (release_invalid || arithmetic_invalid) {
        budget.release_errors.fetch_add(1u, std::memory_order_relaxed);
        unlock_budget(budget);
        return false;
    }
    if (total_reserve != 0u)
        budget.reserve_checks.fetch_add(1u, std::memory_order_relaxed);
    const uint64_t after_release = current - total_release;
    if (after_release > budget.budget_bytes ||
        total_reserve > budget.budget_bytes - after_release) {
        budget.reserve_rejects.fetch_add(1u, std::memory_order_relaxed);
        unlock_budget(budget);
        return false;
    }
    const uint64_t final_total = after_release + total_reserve;
    for (std::size_t component = 0u;
         component < kComponentCount; ++component) {
        const uint64_t owned = budget.used_by_component[component].load(
            std::memory_order_relaxed);
        const uint64_t final_owned =
            owned - release_by_component[component] +
            reserve_by_component[component];
        budget.used_by_component[component].store(
            final_owned, std::memory_order_relaxed);
        update_peak(budget.peak_by_component[component], final_owned);
    }
    budget.used_bytes.store(final_total, std::memory_order_release);
    update_peak(budget.peak_bytes, final_total);
    unlock_budget(budget);
    return true;
}

static void advance_checkpoint(
        fk_component_flow &flow,
        uint32_t packet_count,
        const fk_component_policy_config &config) {
    while (flow.checkpoint_index < config.checkpoint_count &&
           packet_count >= config.checkpoints[flow.checkpoint_index])
        flow.checkpoint_index++;
    flow.next_checkpoint_packet =
        flow.checkpoint_index < config.checkpoint_count
        ? config.checkpoints[flow.checkpoint_index] : 0u;
}

static uint8_t component_count(uint8_t mask) {
    uint8_t count = 0u;
    while (mask != 0u) {
        count += mask & 1u;
        mask >>= 1u;
    }
    return count;
}

}  // namespace

extern "C" {

fk_state_budget *fk_state_budget_create(uint64_t budget_bytes) {
    if (budget_bytes == 0u)
        return nullptr;
    StateBudget *budget = new (std::nothrow) StateBudget(budget_bytes);
    return reinterpret_cast<fk_state_budget *>(budget);
}

void fk_state_budget_destroy(fk_state_budget *budget) {
    delete implementation(budget);
}

uint64_t fk_state_budget_overhead_bytes(void) {
    return sizeof(StateBudget);
}

bool fk_state_budget_try_reserve(
        fk_state_budget *budget,
        fk_memory_component component,
        uint64_t bytes) {
    if (budget == nullptr || !valid_component(component))
        return false;
    uint64_t releases[kComponentCount]{};
    uint64_t reserves[kComponentCount]{};
    reserves[component] = bytes;
    return apply_budget_transaction(
        *implementation(budget), releases, reserves);
}

bool fk_state_budget_release(
        fk_state_budget *budget,
        fk_memory_component component,
        uint64_t bytes) {
    if (budget == nullptr || !valid_component(component))
        return false;
    uint64_t releases[kComponentCount]{};
    uint64_t reserves[kComponentCount]{};
    releases[component] = bytes;
    return apply_budget_transaction(
        *implementation(budget), releases, reserves);
}

bool fk_state_budget_apply_transaction(
        fk_state_budget *budget,
        const uint64_t release_by_component[FK_MEMORY_COMPONENT_COUNT],
        const uint64_t reserve_by_component[FK_MEMORY_COMPONENT_COUNT]) {
    if (budget == nullptr || release_by_component == nullptr ||
        reserve_by_component == nullptr)
        return false;
    return apply_budget_transaction(
        *implementation(budget),
        release_by_component,
        reserve_by_component);
}

void fk_state_budget_snapshot(
        const fk_state_budget *budget,
        fk_budget_snapshot *snapshot) {
    if (budget == nullptr || snapshot == nullptr)
        return;
    const StateBudget &state = *implementation(budget);
    lock_budget(state);
    snapshot->budget_bytes = state.budget_bytes;
    snapshot->used_bytes =
        state.used_bytes.load(std::memory_order_relaxed);
    snapshot->peak_bytes =
        state.peak_bytes.load(std::memory_order_relaxed);
    for (std::size_t index = 0u; index < kComponentCount; ++index) {
        snapshot->used_by_component[index] =
            state.used_by_component[index].load(std::memory_order_relaxed);
        snapshot->peak_by_component[index] =
            state.peak_by_component[index].load(std::memory_order_relaxed);
    }
    snapshot->reserve_checks =
        state.reserve_checks.load(std::memory_order_relaxed);
    snapshot->reserve_rejects =
        state.reserve_rejects.load(std::memory_order_relaxed);
    snapshot->release_errors =
        state.release_errors.load(std::memory_order_relaxed);
    snapshot->hard_budget_violations =
        state.hard_budget_violations.load(std::memory_order_relaxed);
    unlock_budget(state);
}

void fk_budget_calibrate(
        uint64_t mandatory_bytes,
        uint64_t full_state_bytes,
        uint64_t low_budget_bytes,
        fk_budget_calibration *calibration) {
    if (calibration == nullptr)
        return;
    calibration->mandatory_bytes = mandatory_bytes;
    calibration->full_state_bytes = full_state_bytes;
    calibration->low_budget_bytes = low_budget_bytes;
    calibration->mandatory_fits = mandatory_bytes <=
        low_budget_bytes - low_budget_bytes / 4u;
    calibration->optional_competition_exists =
        full_state_bytes > low_budget_bytes;
    calibration->suitable_for_retention_q2 =
        calibration->mandatory_fits &&
        calibration->optional_competition_exists;
}

bool fk_component_policy_config_valid(
        const fk_component_policy_config *config) {
    if (config == nullptr || config->maximum_lifetime_ns == 0u ||
        config->checkpoint_count == 0u ||
        config->checkpoint_count > FK_COMPONENT_CHECKPOINT_CAP ||
        config->allow_prospective_late_start > 1u ||
        config->enforce_budget_monotone_chain > 1u ||
        config->preserve_full_state_in_normal > 1u ||
        config->rank_by_marginal_value_per_byte >
            FK_COMPONENT_RANK_BUDGET_ADAPTIVE ||
        (config->provisional_minimum_mask & ~FK_COMPONENT_FULL) != 0u ||
        ((config->provisional_minimum_mask == FK_COMPONENT_NONE) !=
         (config->provisional_until_packet == 0u)))
        return false;
    uint32_t previous = 0u;
    for (uint8_t index = 0u;
         index < config->checkpoint_count;
         ++index) {
        const uint32_t checkpoint = config->checkpoints[index];
        if (checkpoint == 0u || checkpoint > 255u ||
            checkpoint <= previous)
            return false;
        previous = checkpoint;
    }
    if (config->provisional_minimum_mask != FK_COMPONENT_NONE &&
        (config->provisional_until_packet <= config->checkpoints[0] ||
         config->provisional_until_packet > previous))
        return false;
    for (std::size_t index = 0u; index < 3u; ++index) {
        if (config->maximum_components[index] > 3u ||
            !std::isfinite(config->minimum_utility[index]))
            return false;
    }
    return true;
}

void fk_component_flow_init(
        fk_component_flow *flow,
        uint64_t first_timestamp_ns,
        const fk_component_policy_config *config) {
    if (flow == nullptr || !fk_component_policy_config_valid(config))
        return;
    *flow = {};
    flow->observation_complete = 1u;
    for (uint8_t &reason : flow->missing_reason)
        reason = FK_MISSING_NOT_YET_AVAILABLE;
    flow->absolute_deadline_ns =
        first_timestamp_ns >
                std::numeric_limits<uint64_t>::max() -
                    config->maximum_lifetime_ns
        ? std::numeric_limits<uint64_t>::max()
        : first_timestamp_ns + config->maximum_lifetime_ns;
    flow->next_checkpoint_packet = config->checkpoints[0];
}

bool fk_component_flow_decision_due(
        const fk_component_flow *flow,
        uint32_t packet_count,
        uint64_t timestamp_ns) {
    if (flow == nullptr)
        return false;
    if (timestamp_ns >= flow->absolute_deadline_ns)
        return false;
    return flow->next_checkpoint_packet != 0u &&
        packet_count >= flow->next_checkpoint_packet;
}

bool fk_component_flow_expired(
        const fk_component_flow *flow,
        uint64_t timestamp_ns) {
    return flow != nullptr &&
        timestamp_ns >= flow->absolute_deadline_ns;
}

bool fk_component_flow_plan_transition(
        const fk_component_flow *flow,
        uint8_t desired_mask,
        const fk_component_bytes *component_bytes,
        bool ja4_applicable,
        uint32_t packet_count,
        uint64_t timestamp_ns,
        const fk_component_policy_config *config,
        fk_component_flow *planned,
        uint64_t release_bytes[3],
        uint64_t reserve_bytes[3],
        fk_transition_result *result) {
    if (flow == nullptr || component_bytes == nullptr || planned == nullptr ||
        release_bytes == nullptr || reserve_bytes == nullptr ||
        result == nullptr || !fk_component_policy_config_valid(config) ||
        (desired_mask & ~FK_COMPONENT_FULL) != 0u)
        return false;
    *planned = *flow;
    std::fill_n(release_bytes, 3u, 0u);
    std::fill_n(reserve_bytes, 3u, 0u);
    *result = FK_TRANSITION_ILLEGAL_MASK;
    if (!ja4_applicable && (desired_mask & FK_COMPONENT_JA4) != 0u)
        return true;
    if (timestamp_ns >= flow->absolute_deadline_ns) {
        *result = FK_TRANSITION_EXPIRED;
        return true;
    }
    if ((desired_mask & flow->released_mask) != 0u) {
        *result = FK_TRANSITION_NON_MONOTONE;
        return true;
    }
    if (flow->decision_started != 0u && desired_mask == flow->mask) {
        advance_checkpoint(*planned, packet_count, *config);
        *result = FK_TRANSITION_NO_CHANGE;
        return true;
    }

    const uint8_t added = static_cast<uint8_t>(
        desired_mask & ~flow->mask);
    if (flow->decision_started != 0u && added != 0u &&
        config->allow_prospective_late_start == 0u) {
        *result = FK_TRANSITION_NON_MONOTONE;
        return true;
    }
    const uint8_t removed = static_cast<uint8_t>(
        flow->mask & ~desired_mask);
    planned->released_mask |= removed;
    for (std::size_t index = 0u; index < kEvidenceBits.size(); ++index) {
        const uint8_t component = kEvidenceBits[index];
        const uint64_t already_owned = owned_for_index(*flow, index);
        const bool keep = (desired_mask & component) != 0u;
        if (keep) {
            uint64_t target = already_owned;
            if ((added & component) != 0u) {
                target = bytes_for_index(*component_bytes, index);
                if (already_owned > target ||
                    target > std::numeric_limits<uint32_t>::max()) {
                    *result = FK_TRANSITION_ILLEGAL_MASK;
                    return true;
                }
                reserve_bytes[index] = target - already_owned;
                planned->component_start_packet[index] =
                    static_cast<uint8_t>(packet_count);
            } else if (already_owned == 0u) {
                *result = FK_TRANSITION_STORAGE_FAILED;
                return true;
            }
            set_owned_for_index(*planned, index, target);
            if (planned->missing_reason[index] !=
                    FK_MISSING_LOST_OR_FAILED)
                planned->missing_reason[index] = FK_MISSING_PRESENT;
        } else {
            release_bytes[index] = already_owned;
            set_owned_for_index(*planned, index, 0u);
            if (planned->missing_reason[index] !=
                    FK_MISSING_LOST_OR_FAILED)
                planned->missing_reason[index] =
                    FK_MISSING_NOT_SELECTED;
        }
    }
    planned->mask = desired_mask;
    if (flow->decision_started == 0u &&
        config->allow_prospective_late_start == 0u) {
        planned->released_mask |= static_cast<uint8_t>(
            FK_COMPONENT_FULL & ~desired_mask);
    }
    planned->decision_started = 1u;
    if (!ja4_applicable)
        planned->missing_reason[2] = FK_MISSING_NOT_APPLICABLE;
    advance_checkpoint(*planned, packet_count, *config);
    *result = FK_TRANSITION_APPLIED;
    return true;
}

fk_transition_result fk_component_flow_transition(
        fk_state_budget *budget,
        fk_component_flow *flow,
        uint8_t desired_mask,
        const fk_component_bytes *component_bytes,
        bool ja4_applicable,
        uint32_t packet_count,
        uint64_t timestamp_ns,
        const fk_component_policy_config *config) {
    if (budget == nullptr || flow == nullptr)
        return FK_TRANSITION_ILLEGAL_MASK;
    fk_component_flow planned{};
    uint64_t release_evidence[3]{};
    uint64_t reserve_evidence[3]{};
    fk_transition_result result = FK_TRANSITION_ILLEGAL_MASK;
    if (!fk_component_flow_plan_transition(
            flow,
            desired_mask,
            component_bytes,
            ja4_applicable,
            packet_count,
            timestamp_ns,
            config,
            &planned,
            release_evidence,
            reserve_evidence,
            &result))
        return FK_TRANSITION_ILLEGAL_MASK;
    if (result != FK_TRANSITION_APPLIED &&
        result != FK_TRANSITION_NO_CHANGE)
        return result;
    uint64_t releases[kComponentCount]{};
    uint64_t reserves[kComponentCount]{};
    for (std::size_t index = 0u; index < 3u; ++index) {
        releases[kMemoryComponents[index]] = release_evidence[index];
        reserves[kMemoryComponents[index]] = reserve_evidence[index];
    }
    if (!fk_state_budget_apply_transaction(
            budget, releases, reserves))
        return FK_TRANSITION_BUDGET_REJECTED;
    *flow = planned;
    return result;
}

size_t fk_component_rank_candidates(
        const fk_component_flow *flow,
        const float utilities[8],
        const fk_component_bytes *component_bytes,
        uint8_t available_mask,
        bool ja4_applicable,
        fk_pressure_mode pressure,
        const fk_component_policy_config *config,
        fk_component_candidate output[8]) {
    if (flow == nullptr || utilities == nullptr ||
        component_bytes == nullptr || output == nullptr ||
        !fk_component_policy_config_valid(config) ||
        (available_mask & ~FK_COMPONENT_FULL) != 0u ||
        pressure < FK_PRESSURE_NORMAL ||
        pressure > FK_PRESSURE_OVERLOAD)
        return 0u;

    std::array<fk_component_candidate, 8> candidates{};
    std::size_t count = 0u;
    const uint8_t maximum =
        config->maximum_components[static_cast<std::size_t>(pressure)];
    const float minimum =
        config->minimum_utility[static_cast<std::size_t>(pressure)];
    for (uint8_t mask = 0u; mask <= FK_COMPONENT_FULL; ++mask) {
        if (!std::isfinite(utilities[mask]) ||
            (mask & ~available_mask) != 0u ||
            component_count(mask) > maximum ||
            (!ja4_applicable && (mask & FK_COMPONENT_JA4) != 0u) ||
            (mask & flow->released_mask) != 0u)
            continue;
        /*
         * CORE-only is always a legal fail-safe. Optional evidence must have
         * positive-enough event value after resource costs.
         */
        if (mask != FK_COMPONENT_NONE && utilities[mask] < minimum)
            continue;
        const uint64_t candidate_bytes =
            mask == FK_COMPONENT_NONE ? 1u :
            bytes_for_mask(mask, *component_bytes, *flow);
        if (candidate_bytes == 0u)
            return 0u;
        const bool rank_by_density =
            config->rank_by_marginal_value_per_byte ==
                FK_COMPONENT_RANK_VALUE_PER_BYTE ||
            (config->rank_by_marginal_value_per_byte ==
                 FK_COMPONENT_RANK_BUDGET_ADAPTIVE &&
             pressure != FK_PRESSURE_NORMAL);
        const float rank_value =
            rank_by_density && mask != FK_COMPONENT_NONE
                ? utilities[mask] / static_cast<float>(candidate_bytes)
                : utilities[mask];
        candidates[count++] = fk_component_candidate{
            mask, {0u, 0u, 0u}, utilities[mask], rank_value};
    }
    const auto rank_before = [](
            const fk_component_candidate &left,
            const fk_component_candidate &right) {
        if (left.rank_value != right.rank_value)
            return left.rank_value > right.rank_value;
        if (left.utility != right.utility)
            return left.utility > right.utility;
        return component_count(left.mask) < component_count(right.mask);
    };
    /* Fixed eight-element stable insertion sort: unlike std::stable_sort it
     * cannot request a temporary heap buffer on the packet hot path. */
    for (std::size_t index = 1u; index < count; ++index) {
        const fk_component_candidate candidate = candidates[index];
        std::size_t position = index;
        while (position != 0u &&
               rank_before(candidate, candidates[position - 1u])) {
            candidates[position] = candidates[position - 1u];
            --position;
        }
        candidates[position] = candidate;
    }

    if (config->enforce_budget_monotone_chain != 0u && count > 1u) {
        /* Every three-bit state belongs to at least one of these maximal
         * lattice chains.  First preserve the unconstrained best action;
         * among chains containing it, retain the lexicographically best
         * sequence of fallbacks under the exact C++ candidate ordering.
         * Thus the flag changes only budget fallbacks, never the best
         * feasible action when it fits. */
        static constexpr uint8_t chains[6][4]{
            {0u, 1u, 3u, 7u}, {0u, 1u, 5u, 7u},
            {0u, 2u, 3u, 7u}, {0u, 2u, 6u, 7u},
            {0u, 4u, 5u, 7u}, {0u, 4u, 6u, 7u},
        };
        const uint8_t best_mask = candidates[0].mask;
        std::size_t best_chain = 0u;
        std::array<std::size_t, 4> best_ranks{
            count, count, count, count};
        bool found_chain = false;
        for (std::size_t chain = 0u; chain < 6u; ++chain) {
            bool contains_best = false;
            for (uint8_t mask : chains[chain])
                contains_best = contains_best || mask == best_mask;
            if (!contains_best)
                continue;
            std::array<std::size_t, 4> ranks{count, count, count, count};
            std::size_t ranks_count = 0u;
            for (std::size_t rank = 0u; rank < count; ++rank) {
                bool in_chain = false;
                for (uint8_t mask : chains[chain])
                    in_chain = in_chain || mask == candidates[rank].mask;
                if (in_chain && ranks_count < ranks.size())
                    ranks[ranks_count++] = rank;
            }
            if (!found_chain || ranks < best_ranks) {
                found_chain = true;
                best_chain = chain;
                best_ranks = ranks;
            }
        }
        if (!found_chain)
            return 0u;
        std::array<fk_component_candidate, 8> filtered{};
        std::size_t filtered_count = 0u;
        for (std::size_t rank = 0u; rank < count; ++rank) {
            bool in_chain = false;
            for (uint8_t mask : chains[best_chain])
                in_chain = in_chain || mask == candidates[rank].mask;
            if (in_chain)
                filtered[filtered_count++] = candidates[rank];
        }
        candidates = filtered;
        count = filtered_count;
    }

    std::copy_n(candidates.begin(), count, output);
    return count;
}

bool fk_component_choose_and_transition(
        fk_state_budget *budget,
        fk_component_flow *flow,
        const float utilities[8],
        const fk_component_bytes *component_bytes,
        bool ja4_applicable,
        fk_pressure_mode pressure,
        uint32_t packet_count,
        uint64_t timestamp_ns,
        const fk_component_policy_config *config,
        fk_component_decision *decision) {
    if (decision != nullptr)
        *decision = {};
    if (budget == nullptr || flow == nullptr || utilities == nullptr ||
        component_bytes == nullptr || decision == nullptr)
        return false;
    std::array<fk_component_candidate, 8> candidates{};
    const std::size_t count = fk_component_rank_candidates(
        flow,
        utilities,
        component_bytes,
        FK_COMPONENT_FULL,
        ja4_applicable,
        pressure,
        config,
        candidates.data());
    if (count == 0u)
        return false;

    for (std::size_t index = 0u; index < count; ++index) {
        decision->candidates_considered++;
        const fk_transition_result result = fk_component_flow_transition(
            budget,
            flow,
            candidates[index].mask,
            component_bytes,
            ja4_applicable,
            packet_count,
            timestamp_ns,
            config);
        if (result == FK_TRANSITION_BUDGET_REJECTED) {
            decision->budget_rejections++;
            continue;
        }
        decision->selected_mask = candidates[index].mask;
        decision->selected_utility = candidates[index].utility;
        decision->result = result;
        return result == FK_TRANSITION_APPLIED ||
            result == FK_TRANSITION_NO_CHANGE;
    }
    decision->selected_mask = flow->mask;
    decision->selected_utility = 0.0f;
    decision->result = timestamp_ns >= flow->absolute_deadline_ns
        ? FK_TRANSITION_EXPIRED : FK_TRANSITION_BUDGET_REJECTED;
    return false;
}

bool fk_component_flow_freeze_initial_values(
        fk_component_flow *flow,
        const float action_values[8]) {
    if (flow == nullptr || action_values == nullptr)
        return false;
    for (std::size_t mask = 0u; mask < 8u; ++mask) {
        if (!std::isfinite(action_values[mask]))
            return false;
    }
    if (flow->initial_action_values_valid != 0u) {
        for (std::size_t mask = 0u; mask < 8u; ++mask) {
            const float existing = flow->initial_action_values[mask];
            const float incoming = action_values[mask];
            const float tolerance = 1.0e-6f *
                std::max(1.0f, std::max(std::fabs(existing),
                                        std::fabs(incoming)));
            if (std::fabs(existing - incoming) > tolerance)
                return false;
        }
        return true;
    }
    std::copy_n(action_values, 8u, flow->initial_action_values);
    flow->initial_action_values_valid = 1u;
    flow->replacement_values_physical = 0u;
    return true;
}

bool fk_component_flow_update_action_values(
        fk_component_flow *flow,
        const float action_values[8]) {
    if (flow == nullptr || action_values == nullptr)
        return false;
    for (std::size_t mask = 0u; mask < 8u; ++mask) {
        if (!std::isfinite(action_values[mask]))
            return false;
    }
    std::copy_n(action_values, 8u, flow->initial_action_values);
    flow->initial_action_values_valid = 1u;
    flow->replacement_values_physical = 0u;
    return true;
}

bool fk_component_flow_update_transition_values(
        fk_component_flow *flow,
        const float transition_potentials[8]) {
    if (flow == nullptr || transition_potentials == nullptr)
        return false;
    for (std::size_t mask = 0u; mask < 8u; ++mask) {
        if (!std::isfinite(transition_potentials[mask]))
            return false;
    }
    std::copy_n(
        transition_potentials, 8u, flow->initial_action_values);
    flow->initial_action_values_valid = 1u;
    flow->replacement_values_physical = 1u;
    return true;
}

bool fk_component_flow_removal_loss(
        const fk_component_flow *flow,
        uint8_t mask,
        uint8_t component,
        float *loss) {
    if (flow == nullptr || loss == nullptr ||
        flow->initial_action_values_valid == 0u ||
        (mask & ~FK_COMPONENT_FULL) != 0u ||
        (component != FK_COMPONENT_STAT &&
         component != FK_COMPONENT_SEQ &&
         component != FK_COMPONENT_JA4) ||
        (mask & component) == 0u)
        return false;
    const uint8_t without = static_cast<uint8_t>(mask & ~component);
    const float difference =
        flow->initial_action_values[mask] -
        flow->initial_action_values[without];
    *loss = std::max(0.0f, difference);
    return std::isfinite(*loss);
}

void fk_component_flow_mark_loss(
        fk_component_flow *flow,
        uint8_t affected_mask) {
    if (flow == nullptr)
        return;
    flow->observation_complete = 0u;
    for (std::size_t index = 0u; index < kEvidenceBits.size(); ++index) {
        if ((affected_mask & kEvidenceBits[index]) != 0u)
            flow->missing_reason[index] = FK_MISSING_LOST_OR_FAILED;
    }
}

bool fk_component_flow_shrink_owned(
        fk_state_budget *budget,
        fk_component_flow *flow,
        uint8_t component,
        uint32_t new_bytes) {
    if (budget == nullptr || flow == nullptr ||
        (component != FK_COMPONENT_STAT &&
         component != FK_COMPONENT_SEQ &&
         component != FK_COMPONENT_JA4) ||
        (flow->mask & component) == 0u)
        return false;
    std::size_t index = component == FK_COMPONENT_STAT ? 0u :
        component == FK_COMPONENT_SEQ ? 1u : 2u;
    const uint64_t old_bytes = owned_for_index(*flow, index);
    if (new_bytes > old_bytes)
        return false;
    const uint64_t released = old_bytes - new_bytes;
    if (released != 0u &&
        !fk_state_budget_release(
            budget, kMemoryComponents[index], released))
        return false;
    set_owned_for_index(*flow, index, new_bytes);
    return true;
}

bool fk_component_flow_release_provisional(
        fk_state_budget *budget,
        fk_component_flow *flow,
        uint8_t component) {
    if (budget == nullptr || flow == nullptr ||
        (flow->mask & component) != 0u ||
        (component != FK_COMPONENT_STAT &&
         component != FK_COMPONENT_SEQ &&
         component != FK_COMPONENT_JA4))
        return false;
    const std::size_t index = component == FK_COMPONENT_STAT ? 0u :
        component == FK_COMPONENT_SEQ ? 1u : 2u;
    const uint64_t bytes = owned_for_index(*flow, index);
    if (bytes != 0u &&
        !fk_state_budget_release(
            budget, kMemoryComponents[index], bytes))
        return false;
    set_owned_for_index(*flow, index, 0u);
    return true;
}

bool fk_component_flow_release_irreversible(
        fk_state_budget *budget,
        fk_component_flow *flow,
        uint8_t component) {
    if (budget == nullptr || flow == nullptr ||
        (component != FK_COMPONENT_STAT &&
         component != FK_COMPONENT_SEQ &&
         component != FK_COMPONENT_JA4))
        return false;
    const std::size_t index = component == FK_COMPONENT_STAT ? 0u :
        component == FK_COMPONENT_SEQ ? 1u : 2u;
    if ((flow->mask & component) == 0u &&
        owned_for_index(*flow, index) == 0u)
        return false;
    const uint64_t bytes = owned_for_index(*flow, index);
    if (bytes != 0u &&
        !fk_state_budget_release(
            budget, kMemoryComponents[index], bytes))
        return false;
    set_owned_for_index(*flow, index, 0u);
    flow->mask = static_cast<uint8_t>(flow->mask & ~component);
    flow->released_mask |= component;
    flow->missing_reason[index] = FK_MISSING_NOT_SELECTED;
    return true;
}

void fk_component_flow_release_all(
        fk_state_budget *budget,
        fk_component_flow *flow) {
    if (budget == nullptr || flow == nullptr)
        return;
    flow->released_mask |= flow->mask;
    for (std::size_t index = 0u; index < kEvidenceBits.size(); ++index) {
        const uint64_t bytes = owned_for_index(*flow, index);
        if (bytes != 0u)
            (void)fk_state_budget_release(
                budget, kMemoryComponents[index], bytes);
        set_owned_for_index(*flow, index, 0u);
        flow->missing_reason[index] = FK_MISSING_NOT_SELECTED;
    }
    flow->mask = FK_COMPONENT_NONE;
}

const char *fk_component_mask_name(uint8_t mask) {
    switch (mask) {
    case FK_COMPONENT_NONE:
        return "core";
    case FK_COMPONENT_STAT:
        return "core+stat";
    case FK_COMPONENT_SEQ:
        return "core+seq";
    case FK_COMPONENT_JA4:
        return "core+ja4";
    case FK_COMPONENT_STAT | FK_COMPONENT_SEQ:
        return "core+stat+seq";
    case FK_COMPONENT_STAT | FK_COMPONENT_JA4:
        return "core+stat+ja4";
    case FK_COMPONENT_SEQ | FK_COMPONENT_JA4:
        return "core+seq+ja4";
    case FK_COMPONENT_FULL:
        return "full";
    default:
        return "invalid";
    }
}

}  // extern "C"
