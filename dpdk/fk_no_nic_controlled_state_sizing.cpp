#include "fk_no_nic_controlled_state_sizing.h"

#include <algorithm>
#include <limits>

namespace {

bool checked_add(uint64_t left, uint64_t right, uint64_t &sum) {
    if (right > std::numeric_limits<uint64_t>::max() - left)
        return false;
    sum = left + right;
    return true;
}

}  // namespace

extern "C" {

bool fk_no_nic_controlled_identity_plan_make_v1(
        uint32_t maximum_quic_connections,
        uint16_t fixed_owner_count,
        bool external_input,
        fk_no_nic_controlled_identity_plan_v1 *plan) {
    if (plan != nullptr)
        *plan = {};
    if (plan == nullptr || maximum_quic_connections == 0u ||
        maximum_quic_connections > UINT16_MAX || fixed_owner_count == 0u)
        return false;

    plan->maximum_quic_connections = maximum_quic_connections;
    plan->fixed_owner_count = fixed_owner_count;
    plan->external_input = external_input ? 1u : 0u;

    fk_quic_cid_map_q2_config_init(&plan->cid_config);
    plan->cid_config.maximum_connections = maximum_quic_connections;
    plan->cid_config.maximum_cids = maximum_quic_connections * 4u;
    plan->cid_config.maximum_cids_per_connection =
        static_cast<uint8_t>(
            std::min<uint32_t>(8u, maximum_quic_connections));
    plan->cid_config.maximum_pending_handshakes =
        static_cast<uint16_t>(
            std::min<uint32_t>(1024u, maximum_quic_connections));
    plan->cid_config.expiration_scan_per_observation =
        external_input ? 64u : 32u;
    plan->cid_config.connection_ttl_ns = UINT64_C(60000000000);
    plan->cid_config.cid_ttl_ns = UINT64_C(30000000000);
    plan->cid_config.maximum_hash_chain = 8u;
    plan->cid_config.fixed_owner_count = fixed_owner_count;
    const uint32_t connections_per_owner =
        (maximum_quic_connections + fixed_owner_count - 1u) /
        fixed_owner_count;
    if (connections_per_owner == 0u || connections_per_owner > UINT16_MAX)
        return false;
    plan->cid_config.maximum_connections_per_fixed_owner =
        static_cast<uint16_t>(connections_per_owner);
    plan->quic_cid_reserved_bytes =
        fk_quic_cid_map_storage_bytes(&plan->cid_config);

    fk_quic_presentation_path_directory_default_config_init(
        &plan->path_config);
    plan->path_config.maximum_logical_connections =
        maximum_quic_connections;
    plan->path_config.maximum_paths = maximum_quic_connections;
    plan->path_config.maximum_paths_per_connection =
        static_cast<uint16_t>(
            std::min<uint32_t>(8u, maximum_quic_connections));
    plan->path_config.maximum_hash_chain =
        std::min<uint32_t>(64u, maximum_quic_connections);
    plan->path_config.expiration_scan_per_operation =
        std::min<uint32_t>(64u, maximum_quic_connections);
    plan->path_config.path_ttl_ns = UINT64_C(30000000000);
    plan->quic_presentation_path_reserved_bytes =
        fk_quic_presentation_path_directory_storage_bytes(
            &plan->path_config);

    fk_owner_flow_bindings_default_config_init(&plan->binding_config);
    plan->binding_config.owner_count = fixed_owner_count;
    plan->binding_config.maximum_connection_slots =
        maximum_quic_connections;
    plan->owner_flow_bindings_reserved_bytes =
        fk_owner_flow_bindings_storage_bytes(&plan->binding_config);

    uint64_t cid_and_path = 0u;
    if (plan->quic_cid_reserved_bytes == 0u ||
        plan->quic_presentation_path_reserved_bytes == 0u ||
        plan->owner_flow_bindings_reserved_bytes == 0u ||
        !checked_add(
            plan->quic_cid_reserved_bytes,
            plan->quic_presentation_path_reserved_bytes,
            cid_and_path) ||
        !checked_add(
            cid_and_path,
            plan->owner_flow_bindings_reserved_bytes,
            plan->identity_reserved_bytes)) {
        *plan = {};
        return false;
    }
    plan->exact_accounting = 1u;
    return true;
}

bool fk_no_nic_controlled_flow_table_partition_v1(
        uint64_t controlled_state_ceiling_bytes,
        uint64_t identity_reserved_bytes,
        uint64_t *flow_table_budget_bytes) {
    if (flow_table_budget_bytes != nullptr)
        *flow_table_budget_bytes = 0u;
    if (flow_table_budget_bytes == nullptr ||
        controlled_state_ceiling_bytes == 0u ||
        identity_reserved_bytes == 0u ||
        identity_reserved_bytes >= controlled_state_ceiling_bytes)
        return false;
    *flow_table_budget_bytes =
        controlled_state_ceiling_bytes - identity_reserved_bytes;
    return true;
}

}  // extern "C"
