#ifndef FK_FIXED_TTL_RETENTION_CONTRACT_H
#define FK_FIXED_TTL_RETENTION_CONTRACT_H

#include "fk_compact_controller.h"

#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <limits>

/*
 * Shared CLI-to-runtime contract for the frozen fixed-TTL baseline.
 *
 * The Development-only selector freezes an integer nanosecond value under the
 * name selected_ttl_ns.  The runtime binding uses the same bits under the
 * name fixed_ttl_ns.  No unit conversion, implicit default, floating-point
 * parsing, or policy-dependent fallback is allowed on the execution path.
 */
struct fk_fixed_ttl_retention_binding {
    uint64_t fixed_ttl_ns = 0u;
    uint8_t selected_ttl_precommitted = 0u;
};

constexpr const char FK_FIXED_TTL_SELECTION_PROTOCOL[] =
    "flowkeep-fixed-ttl-development-selection-v2";

inline bool fk_fixed_ttl_retention_parse_ns_once(
        const char *text,
        fk_fixed_ttl_retention_binding *binding) {
    if (text == nullptr || binding == nullptr || text[0] == '\0' ||
        binding->selected_ttl_precommitted != 0u) {
        return false;
    }

    uint64_t value = 0u;
    for (const char *cursor = text; cursor[0] != '\0'; ++cursor) {
        if (cursor[0] < '0' || cursor[0] > '9')
            return false;
        const uint64_t digit = static_cast<uint64_t>(cursor[0] - '0');
        if (value >
            (std::numeric_limits<uint64_t>::max() - digit) / 10u) {
            return false;
        }
        value = value * 10u + digit;
    }
    if (value == 0u)
        return false;

    binding->fixed_ttl_ns = value;
    binding->selected_ttl_precommitted = 1u;
    return true;
}

inline bool fk_fixed_ttl_retention_binding_valid(
        fk_compact_retention_policy_kind policy,
        const fk_fixed_ttl_retention_binding *binding) {
    if (binding == nullptr || binding->selected_ttl_precommitted > 1u)
        return false;
    return policy == FK_COMPACT_POLICY_FIXED_TTL
        ? (binding->selected_ttl_precommitted == 1u &&
           binding->fixed_ttl_ns != 0u)
        : (binding->selected_ttl_precommitted == 0u &&
           binding->fixed_ttl_ns == 0u);
}

inline bool fk_fixed_ttl_retention_bind_baseline(
        fk_compact_retention_policy_kind policy,
        const fk_fixed_ttl_retention_binding *binding,
        fk_compact_baseline_policy_config *baseline) {
    if (baseline == nullptr || baseline->kind != policy ||
        !fk_fixed_ttl_retention_binding_valid(policy, binding)) {
        return false;
    }
    baseline->fixed_ttl_ns = binding->fixed_ttl_ns;
    return true;
}

/*
 * A flow's generic component lease is installed before its Fixed-TTL
 * deadline, and the table deliberately permits a later operation to move a
 * deadline only earlier.  Therefore a stale 30-second component lifetime
 * would silently cap any selected TTL above 30 seconds.  Align the generic
 * lifetime for Fixed-TTL only; other policies retain their independently
 * frozen component lifetime.
 */
inline bool fk_fixed_ttl_retention_align_component_lifetime(
        const fk_compact_baseline_policy_config *baseline,
        fk_component_policy_config *component_policy) {
    if (baseline == nullptr || component_policy == nullptr)
        return false;
    if (baseline->kind != FK_COMPACT_POLICY_FIXED_TTL)
        return true;
    if (baseline->fixed_ttl_ns == 0u)
        return false;
    component_policy->maximum_lifetime_ns = baseline->fixed_ttl_ns;
    return true;
}

inline bool fk_fixed_ttl_retention_receipt_valid(
        fk_compact_retention_policy_kind policy,
        const fk_fixed_ttl_retention_binding *binding) {
    return fk_fixed_ttl_retention_binding_valid(policy, binding);
}

inline bool fk_fixed_ttl_retention_format_receipt_json(
        char *output,
        size_t capacity,
        fk_compact_retention_policy_kind policy,
        const fk_fixed_ttl_retention_binding *binding) {
    if (output == nullptr || capacity == 0u || binding == nullptr)
        return false;
    output[0] = '\0';
    const bool selected = policy == FK_COMPACT_POLICY_FIXED_TTL;
    const bool valid =
        fk_fixed_ttl_retention_receipt_valid(policy, binding);
    int written = 0;
    if (selected) {
        written = std::snprintf(
            output,
            capacity,
            "{\"selected\":true,\"selection_protocol\":\"%s\","
            "\"ttl_unit\":\"nanoseconds\"," 
            "\"fixed_ttl_ns\":%llu,\"selected_ttl_ns\":%llu,"
            "\"selected_ttl_precommitted\":%s,\"receipt_valid\":%s}",
            FK_FIXED_TTL_SELECTION_PROTOCOL,
            static_cast<unsigned long long>(binding->fixed_ttl_ns),
            static_cast<unsigned long long>(binding->fixed_ttl_ns),
            binding->selected_ttl_precommitted == 1u ? "true" : "false",
            valid ? "true" : "false");
    } else {
        written = std::snprintf(
            output,
            capacity,
            "{\"selected\":false,\"selection_protocol\":\"%s\","
            "\"ttl_unit\":\"nanoseconds\"," 
            "\"fixed_ttl_ns\":null,\"selected_ttl_ns\":null,"
            "\"selected_ttl_precommitted\":false,"
            "\"receipt_valid\":%s}",
            FK_FIXED_TTL_SELECTION_PROTOCOL,
            valid ? "true" : "false");
    }
    return written >= 0 && static_cast<size_t>(written) < capacity;
}

#endif  // FK_FIXED_TTL_RETENTION_CONTRACT_H
