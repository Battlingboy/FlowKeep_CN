#ifndef FLOWKEEP_FK_NO_NIC_CONTROLLED_STATE_SIZING_H
#define FLOWKEEP_FK_NO_NIC_CONTROLLED_STATE_SIZING_H

#include <stdbool.h>
#include <stdint.h>

#include "fk_owner_flow_bindings.h"
#include "fk_quic_cid_map.h"
#include "fk_quic_presentation_path_directory.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * The exact bounded QUIC identity configuration used by the external-input
 * no-NIC runtime.  Keeping the component configs in this pure sizing plan
 * prevents a receipt generator from silently using different CID, path, or
 * binding dimensions from the runtime it is meant to describe.
 */
struct fk_no_nic_controlled_identity_plan_v1 {
    struct fk_quic_cid_map_config cid_config;
    struct fk_quic_presentation_path_directory_config path_config;
    struct fk_owner_flow_bindings_config binding_config;
    uint64_t quic_cid_reserved_bytes;
    uint64_t quic_presentation_path_reserved_bytes;
    uint64_t owner_flow_bindings_reserved_bytes;
    uint64_t identity_reserved_bytes;
    uint32_t maximum_quic_connections;
    uint16_t fixed_owner_count;
    uint8_t external_input;
    uint8_t exact_accounting;
};

/* No allocation is performed.  All byte counts come from the production
 * components' storage_bytes() functions. */
bool fk_no_nic_controlled_identity_plan_make_v1(
    uint32_t maximum_quic_connections,
    uint16_t fixed_owner_count,
    bool external_input,
    struct fk_no_nic_controlled_identity_plan_v1 *plan);

/* Exact one-FlowTable partition used by the external-input no-NIC runtime:
 * total = CID + path + bindings + FlowTable. */
bool fk_no_nic_controlled_flow_table_partition_v1(
    uint64_t controlled_state_ceiling_bytes,
    uint64_t identity_reserved_bytes,
    uint64_t *flow_table_budget_bytes);

#ifdef __cplusplus
}
#endif

#endif
