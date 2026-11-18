#include "fk_controlled_budget_plan.h"

#include <limits>

namespace {

static bool checked_add(uint64_t left, uint64_t right, uint64_t &sum) {
    if (right > std::numeric_limits<uint64_t>::max() - left)
        return false;
    sum = left + right;
    return true;
}

static bool checked_multiply(
        uint64_t left, uint64_t right, uint64_t &product) {
    if (left != 0u &&
        right > std::numeric_limits<uint64_t>::max() / left)
        return false;
    product = left * right;
    return true;
}

}  // namespace

extern "C" {

bool fk_controlled_budget_plan_make(
        const fk_controlled_budget_plan_input *input,
        fk_controlled_budget_plan *plan) {
    if (plan != nullptr)
        *plan = {};
    if (input == nullptr || plan == nullptr ||
        input->shard_count == 0u ||
        input->actor_session_reserved_bytes == 0u ||
        input->quic_cid_map_reserved_bytes == 0u ||
        input->quic_presentation_path_reserved_bytes == 0u ||
        input->owner_flow_bindings_reserved_bytes == 0u ||
        input->minimum_flow_table_bytes_per_shard == 0u ||
        (input->unlimited &&
         input->unlimited_flow_table_bytes_per_shard == 0u) ||
        (!input->unlimited && input->requested_ceiling_bytes == 0u))
        return false;

    plan->actor_session_reserved_bytes =
        input->actor_session_reserved_bytes;
    plan->quic_cid_map_reserved_bytes =
        input->quic_cid_map_reserved_bytes;
    plan->quic_presentation_path_reserved_bytes =
        input->quic_presentation_path_reserved_bytes;
    plan->owner_flow_bindings_reserved_bytes =
        input->owner_flow_bindings_reserved_bytes;
    plan->terminal_tail_accelerator_reserved_bytes =
        input->terminal_tail_accelerator_reserved_bytes;
    uint64_t actor_and_cid = 0u;
    uint64_t identity_before_bindings = 0u;
    uint64_t identity_with_bindings = 0u;
    if (!checked_add(
            input->actor_session_reserved_bytes,
            input->quic_cid_map_reserved_bytes,
            actor_and_cid) ||
        !checked_add(
            actor_and_cid,
            input->quic_presentation_path_reserved_bytes,
            identity_before_bindings) ||
        !checked_add(
            identity_before_bindings,
            input->owner_flow_bindings_reserved_bytes,
            identity_with_bindings) ||
        !checked_add(
            identity_with_bindings,
            input->terminal_tail_accelerator_reserved_bytes,
            plan->identity_reserved_bytes) ||
        !checked_multiply(
            input->minimum_flow_table_bytes_per_shard,
            input->shard_count,
            plan->minimum_flow_table_bytes_total) ||
        !checked_add(
            plan->identity_reserved_bytes,
            plan->minimum_flow_table_bytes_total,
            plan->minimum_feasible_total_bytes))
        return false;

    if (input->unlimited) {
        plan->flow_table_budget_bytes_per_shard =
            input->unlimited_flow_table_bytes_per_shard;
        if (!checked_multiply(
                plan->flow_table_budget_bytes_per_shard,
                input->shard_count,
                plan->flow_table_budget_bytes_total) ||
            !checked_add(
                plan->identity_reserved_bytes,
                plan->flow_table_budget_bytes_total,
                plan->controlled_ceiling_bytes))
            return false;
    } else {
        plan->controlled_ceiling_bytes =
            input->requested_ceiling_bytes;
        if (plan->identity_reserved_bytes >=
                plan->controlled_ceiling_bytes)
            return true;
        const uint64_t remainder =
            plan->controlled_ceiling_bytes -
            plan->identity_reserved_bytes;
        plan->flow_table_budget_bytes_per_shard =
            remainder / input->shard_count;
        if (!checked_multiply(
                plan->flow_table_budget_bytes_per_shard,
                input->shard_count,
                plan->flow_table_budget_bytes_total))
            return false;
        plan->partition_unassigned_bytes =
            remainder - plan->flow_table_budget_bytes_total;
    }

    plan->feasible =
        plan->flow_table_budget_bytes_per_shard >=
            input->minimum_flow_table_bytes_per_shard;
    if (plan->feasible) {
        plan->flow_table_headroom_above_minimum_bytes_total =
            plan->flow_table_budget_bytes_total -
            plan->minimum_flow_table_bytes_total;
    }
    uint64_t accounted = 0u;
    plan->exact_accounting =
        checked_add(
            plan->identity_reserved_bytes,
            plan->flow_table_budget_bytes_total,
            accounted) &&
        checked_add(
            accounted,
            plan->partition_unassigned_bytes,
            accounted) &&
        accounted == plan->controlled_ceiling_bytes;
    return true;
}

}  // extern "C"
