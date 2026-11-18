#ifndef FK_SEEDED_RANDOM_RETENTION_CONTRACT_H
#define FK_SEEDED_RANDOM_RETENTION_CONTRACT_H

#include "fk_compact_controller.h"

#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <limits>

/*
 * Actual-NIC CLI-to-runtime binding for the formal seeded-random baseline.
 * The seed is immutable run configuration, not mutable PRNG state.  Keeping
 * parsing, iff validation, runtime binding and terminal-receipt semantics in
 * this small header lets them be compiled and tested without linking or
 * replacing the frozen DPDK receiver binary.
 */
struct fk_seeded_random_retention_binding {
    uint64_t seed = 0u;
    uint8_t seed_precommitted = 0u;
};

inline bool fk_seeded_random_retention_parse_seed_once(
        const char *text,
        fk_seeded_random_retention_binding *binding) {
    if (text == nullptr || binding == nullptr ||
        binding->seed_precommitted != 0u || text[0] == '\0') {
        return false;
    }

    const char *cursor = text;
    uint32_t base = 10u;
    if (cursor[0] == '0' && (cursor[1] == 'x' || cursor[1] == 'X')) {
        base = 16u;
        cursor += 2;
        if (cursor[0] == '\0')
            return false;
    }
    uint64_t value = 0u;
    for (; cursor[0] != '\0'; ++cursor) {
        uint32_t digit = 0u;
        if (cursor[0] >= '0' && cursor[0] <= '9') {
            digit = static_cast<uint32_t>(cursor[0] - '0');
        } else if (base == 16u && cursor[0] >= 'a' && cursor[0] <= 'f') {
            digit = 10u + static_cast<uint32_t>(cursor[0] - 'a');
        } else if (base == 16u && cursor[0] >= 'A' && cursor[0] <= 'F') {
            digit = 10u + static_cast<uint32_t>(cursor[0] - 'A');
        } else {
            return false;
        }
        if (digit >= base ||
            value > (std::numeric_limits<uint64_t>::max() - digit) / base) {
            return false;
        }
        value = value * base + digit;
    }

    binding->seed = value;
    binding->seed_precommitted = 1u;
    return true;
}

inline bool fk_seeded_random_retention_binding_valid(
        fk_compact_retention_policy_kind policy,
        const fk_seeded_random_retention_binding *binding) {
    if (binding == nullptr || binding->seed_precommitted > 1u)
        return false;
    return policy == FK_COMPACT_POLICY_SEEDED_RANDOM_RETENTION
        ? binding->seed_precommitted == 1u
        : (binding->seed_precommitted == 0u && binding->seed == 0u);
}

inline bool fk_seeded_random_retention_bind_baseline(
        fk_compact_retention_policy_kind policy,
        const fk_seeded_random_retention_binding *binding,
        fk_compact_baseline_policy_config *baseline) {
    if (baseline == nullptr || baseline->kind != policy ||
        !fk_seeded_random_retention_binding_valid(policy, binding)) {
        return false;
    }
    baseline->seeded_random_seed = binding->seed;
    baseline->seeded_random_seed_precommitted =
        binding->seed_precommitted;
    return true;
}

inline bool fk_seeded_random_retention_receipt_valid(
        fk_compact_retention_policy_kind policy,
        const fk_seeded_random_retention_binding *binding,
        uint64_t victim_flows_released,
        uint64_t transition_component_releases) {
    if (!fk_seeded_random_retention_binding_valid(policy, binding))
        return false;
    if (policy != FK_COMPACT_POLICY_SEEDED_RANDOM_RETENTION) {
        return victim_flows_released == 0u &&
            transition_component_releases == 0u;
    }
    return transition_component_releases >= victim_flows_released &&
        ((victim_flows_released == 0u) ==
         (transition_component_releases == 0u));
}

inline bool fk_seeded_random_retention_format_receipt_json(
        char *output,
        size_t capacity,
        fk_compact_retention_policy_kind policy,
        const fk_seeded_random_retention_binding *binding,
        uint64_t victim_flows_released,
        uint64_t transition_component_releases) {
    if (output == nullptr || capacity == 0u || binding == nullptr)
        return false;
    output[0] = '\0';
    const bool selected =
        policy == FK_COMPACT_POLICY_SEEDED_RANDOM_RETENTION;
    const bool valid = fk_seeded_random_retention_receipt_valid(
        policy, binding, victim_flows_released,
        transition_component_releases);
    const int written = std::snprintf(
        output,
        capacity,
        "{\"selected\":%s,\"seed\":%llu,"
        "\"seed_precommitted\":%s,"
        "\"victim_flows_released\":%llu,"
        "\"transition_component_releases\":%llu,"
        "\"receipt_valid\":%s}",
        selected ? "true" : "false",
        static_cast<unsigned long long>(binding->seed),
        binding->seed_precommitted == 1u ? "true" : "false",
        static_cast<unsigned long long>(victim_flows_released),
        static_cast<unsigned long long>(transition_component_releases),
        valid ? "true" : "false");
    return written >= 0 && static_cast<size_t>(written) < capacity;
}

#endif  // FK_SEEDED_RANDOM_RETENTION_CONTRACT_H
