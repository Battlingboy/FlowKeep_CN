#ifndef FLOWKEEP_FK_CONTROLLED_BUDGET_PLAN_H
#define FLOWKEEP_FK_CONTROLLED_BUDGET_PLAN_H

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

struct fk_controlled_budget_plan_input {
    bool unlimited;
    uint32_t shard_count;
    uint64_t requested_ceiling_bytes;
    uint64_t actor_session_reserved_bytes;
    uint64_t quic_cid_map_reserved_bytes;
    uint64_t quic_presentation_path_reserved_bytes;
    uint64_t owner_flow_bindings_reserved_bytes;
    uint64_t terminal_tail_accelerator_reserved_bytes;
    uint64_t minimum_flow_table_bytes_per_shard;
    uint64_t unlimited_flow_table_bytes_per_shard;
};

struct fk_controlled_budget_plan {
    uint64_t controlled_ceiling_bytes;
    uint64_t actor_session_reserved_bytes;
    uint64_t quic_cid_map_reserved_bytes;
    uint64_t quic_presentation_path_reserved_bytes;
    uint64_t owner_flow_bindings_reserved_bytes;
    uint64_t terminal_tail_accelerator_reserved_bytes;
    uint64_t identity_reserved_bytes;
    uint64_t minimum_flow_table_bytes_total;
    uint64_t minimum_feasible_total_bytes;
    uint64_t flow_table_budget_bytes_per_shard;
    uint64_t flow_table_budget_bytes_total;
    uint64_t partition_unassigned_bytes;
    uint64_t flow_table_headroom_above_minimum_bytes_total;
    bool feasible;
    bool exact_accounting;
};

/* Pure, overflow-checked process-wide partitioning used by CLI and receiver. */
bool fk_controlled_budget_plan_make(
    const struct fk_controlled_budget_plan_input *input,
    struct fk_controlled_budget_plan *plan);

#ifdef __cplusplus
}
#endif

#endif
