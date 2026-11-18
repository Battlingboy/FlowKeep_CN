#include "fk_formal_gate.h"

#include <limits.h>

namespace {

bool checked_add_u64(uint64_t left, uint64_t right, uint64_t *sum) {
    if (sum == nullptr || right > UINT64_MAX - left)
        return false;
    *sum = left + right;
    return true;
}

}  // namespace

extern "C" {

fk_formal_budget_gate_result fk_formal_budget_gate_evaluate(
        const fk_formal_budget_gate_input *input) {
    fk_formal_budget_gate_result result{};
    result.blocker = FK_FORMAL_BUDGET_BLOCKER_BASE_ACCOUNTING;
    if (input == nullptr || !input->base_accounting_valid)
        return result;
    if (!input->quic_cid_map_connected) {
        result.blocker = FK_FORMAL_BUDGET_BLOCKER_QUIC_CID_NOT_CONNECTED;
        return result;
    }
    if (!input->quic_identity_parser_complete) {
        result.blocker =
            FK_FORMAL_BUDGET_BLOCKER_QUIC_IDENTITY_PARSER_INCOMPLETE;
        return result;
    }
    if (!input->quic_identity_semantic_ordering_connected) {
        result.blocker =
            FK_FORMAL_BUDGET_BLOCKER_QUIC_IDENTITY_SEMANTIC_ORDERING_NOT_CONNECTED;
        return result;
    }
    if (!input->quic_cid_map_in_controlled_ceiling ||
        input->quic_cid_map_reserved_bytes == 0u) {
        result.blocker = FK_FORMAL_BUDGET_BLOCKER_QUIC_CID_NOT_BUDGETED;
        return result;
    }
    if (!input->owner_flow_bindings_connected) {
        result.blocker =
            FK_FORMAL_BUDGET_BLOCKER_OWNER_FLOW_BINDINGS_NOT_CONNECTED;
        return result;
    }
    if (!input->owner_flow_bindings_in_controlled_ceiling ||
        input->owner_flow_bindings_reserved_bytes == 0u) {
        result.blocker =
            FK_FORMAL_BUDGET_BLOCKER_OWNER_FLOW_BINDINGS_NOT_BUDGETED;
        return result;
    }
    if (!input->identity_loss_accounting_complete) {
        result.blocker =
            FK_FORMAL_BUDGET_BLOCKER_IDENTITY_LOSS_ACCOUNTING_INCOMPLETE;
        return result;
    }
    if (input->identity_integrity_failures != 0u) {
        result.blocker =
            FK_FORMAL_BUDGET_BLOCKER_IDENTITY_INTEGRITY_FAILURE;
        return result;
    }
    if (input->hard_budget_violations != 0u) {
        result.blocker = FK_FORMAL_BUDGET_BLOCKER_HARD_BUDGET_VIOLATION;
        return result;
    }
    result.passed = true;
    result.blocker = FK_FORMAL_BUDGET_BLOCKER_NONE;
    return result;
}

bool fk_controlled_budget_accounting_valid(
        const fk_controlled_budget_accounting_input *input) {
    if (input == nullptr ||
        input->configured_actor_reserved_bytes !=
            input->observed_actor_reserved_bytes ||
        input->configured_quic_cid_reserved_bytes !=
            input->observed_quic_cid_reserved_bytes ||
        input->configured_quic_presentation_path_reserved_bytes !=
            input->observed_quic_presentation_path_reserved_bytes ||
        input->configured_owner_flow_bindings_reserved_bytes !=
            input->observed_owner_flow_bindings_reserved_bytes ||
        input->configured_terminal_tail_accelerator_reserved_bytes !=
            input->observed_terminal_tail_accelerator_reserved_bytes ||
        input->flow_peak_bytes > input->flow_budget_bytes) {
        return false;
    }

    uint64_t flow_accounted = 0u;
    if (!checked_add_u64(
            input->mandatory_bytes,
            input->pool_reserved_bytes,
            &flow_accounted) ||
        !checked_add_u64(
            flow_accounted,
            input->pool_unassigned_bytes,
            &flow_accounted) ||
        flow_accounted != input->flow_budget_bytes) {
        return false;
    }

    uint64_t controlled_preallocated = 0u;
    if (!checked_add_u64(
            input->configured_actor_reserved_bytes,
            input->mandatory_bytes,
            &controlled_preallocated) ||
        !checked_add_u64(
            controlled_preallocated,
            input->configured_quic_cid_reserved_bytes,
            &controlled_preallocated) ||
        !checked_add_u64(
            controlled_preallocated,
            input->configured_quic_presentation_path_reserved_bytes,
            &controlled_preallocated) ||
        !checked_add_u64(
            controlled_preallocated,
            input->configured_owner_flow_bindings_reserved_bytes,
            &controlled_preallocated) ||
        !checked_add_u64(
            controlled_preallocated,
            input->configured_terminal_tail_accelerator_reserved_bytes,
            &controlled_preallocated) ||
        !checked_add_u64(
            controlled_preallocated,
            input->pool_reserved_bytes,
            &controlled_preallocated) ||
        controlled_preallocated > input->controlled_ceiling_bytes) {
        return false;
    }

    uint64_t controlled_accounted = controlled_preallocated;
    if (!checked_add_u64(
            controlled_accounted,
            input->configured_partition_unassigned_bytes,
            &controlled_accounted) ||
        !checked_add_u64(
            controlled_accounted,
            input->pool_unassigned_bytes,
            &controlled_accounted)) {
        return false;
    }
    return controlled_accounted == input->controlled_ceiling_bytes;
}

bool fk_pipeline_readiness_gate_valid(
        const fk_pipeline_readiness_gate_input *input) {
    return input != nullptr &&
        input->expected_rx_workers != 0u &&
        input->expected_detection_workers != 0u &&
        input->observed_rx_workers == input->expected_rx_workers &&
        input->observed_detection_workers ==
            input->expected_detection_workers &&
        input->aggregator_ready && input->barrier_passed &&
        input->run_released;
}

bool fk_nic_packet_conservation_gate_valid(
        const fk_nic_packet_conservation_gate_input *input) {
    if (input == nullptr || !input->port_stop_succeeded ||
        !input->baseline_valid || !input->end_valid ||
        !input->counters_monotonic ||
        input->received_packets != input->processed_packets ||
        input->missed_packets != 0u || input->input_errors != 0u ||
        input->rx_nombuf != 0u) {
        return false;
    }
    return !input->formal_mode ||
        (input->drop_xstat_resolved &&
         input->drop_xstat_baseline_valid &&
         input->drop_xstat_end_valid &&
         input->drop_xstat_monotonic &&
         input->drop_xstat_delta == 0u);
}

bool fk_nic_scoped_packet_conservation_gate_valid(
        const fk_nic_scoped_packet_conservation_gate_input *input) {
    if (input == nullptr)
        return false;
    const uint64_t boundary_packets =
        input->received_packets >= input->scoped_processed_packets
        ? input->received_packets - input->scoped_processed_packets
        : input->scoped_processed_packets - input->received_packets;
    if (!input->baseline_after_all_workers_ready_pre_release ||
        !input->exact_expected_eof_observed ||
        !input->all_rx_pumps_joined ||
        input->port_stop_call_count != 1u ||
        !input->capture_end_after_port_stop ||
        input->baseline_monotonic_ns == 0u ||
        input->exact_expected_eof_monotonic_ns <
            input->baseline_monotonic_ns ||
        input->rx_pumps_joined_monotonic_ns <
            input->exact_expected_eof_monotonic_ns ||
        input->capture_end_monotonic_ns <
            input->rx_pumps_joined_monotonic_ns ||
        !input->port_stop_succeeded ||
        !input->baseline_valid || !input->end_valid ||
        !input->counters_monotonic ||
        boundary_packets > input->maximum_scope_boundary_packets ||
        input->missed_packets != 0u || input->input_errors != 0u ||
        input->rx_nombuf != 0u) {
        return false;
    }
    return !input->formal_mode ||
        (input->drop_xstat_resolved &&
         input->drop_xstat_baseline_valid &&
         input->drop_xstat_end_valid &&
         input->drop_xstat_monotonic &&
         input->drop_xstat_delta == 0u);
}

const char *fk_formal_budget_blocker_name(
        fk_formal_budget_blocker blocker) {
    switch (blocker) {
    case FK_FORMAL_BUDGET_BLOCKER_NONE:
        return "none";
    case FK_FORMAL_BUDGET_BLOCKER_BASE_ACCOUNTING:
        return "controlled_state_accounting_failed";
    case FK_FORMAL_BUDGET_BLOCKER_QUIC_CID_NOT_CONNECTED:
        return "QUIC_CID_map_not_connected";
    case FK_FORMAL_BUDGET_BLOCKER_QUIC_IDENTITY_PARSER_INCOMPLETE:
        return "QUIC_identity_parser_incomplete";
    case FK_FORMAL_BUDGET_BLOCKER_QUIC_IDENTITY_SEMANTIC_ORDERING_NOT_CONNECTED:
        return "QUIC_identity_semantic_ordering_not_connected";
    case FK_FORMAL_BUDGET_BLOCKER_QUIC_CID_NOT_BUDGETED:
        return "QUIC_CID_map_not_budgeted_inside_controlled_ceiling";
    case FK_FORMAL_BUDGET_BLOCKER_OWNER_FLOW_BINDINGS_NOT_CONNECTED:
        return "owner_flow_bindings_not_connected";
    case FK_FORMAL_BUDGET_BLOCKER_OWNER_FLOW_BINDINGS_NOT_BUDGETED:
        return "owner_flow_bindings_not_budgeted_inside_controlled_ceiling";
    case FK_FORMAL_BUDGET_BLOCKER_IDENTITY_LOSS_ACCOUNTING_INCOMPLETE:
        return "identity_loss_accounting_incomplete";
    case FK_FORMAL_BUDGET_BLOCKER_IDENTITY_INTEGRITY_FAILURE:
        return "identity_integrity_failure";
    case FK_FORMAL_BUDGET_BLOCKER_HARD_BUDGET_VIOLATION:
        return "controlled_state_hard_budget_violation";
    }
    return "unknown_formal_budget_blocker";
}

bool fk_formal_budget_allows_commit(
        bool formal_mode,
        const fk_formal_budget_gate_result *result) {
    return !formal_mode || (result != nullptr && result->passed);
}

fk_formal_rss_owner_gate_result fk_formal_rss_owner_gate_evaluate(
        const fk_formal_rss_owner_gate_input *input) {
    fk_formal_rss_owner_gate_result result{};
    result.blocker = FK_FORMAL_RSS_OWNER_BLOCKER_READBACK_FAILED;
    if (input == nullptr)
        return result;
    if (input->worker_count == 0u) {
        result.blocker = FK_FORMAL_RSS_OWNER_BLOCKER_INVALID_TOPOLOGY;
        return result;
    }
    if (input->worker_count == 1u) {
        result.passed = true;
        result.blocker = FK_FORMAL_RSS_OWNER_BLOCKER_NONE;
        return result;
    }
    if (!input->requested_algorithm_supported) {
        result.blocker = FK_FORMAL_RSS_OWNER_BLOCKER_ALGORITHM_UNSUPPORTED;
        return result;
    }
    if (!input->runtime_query_succeeded)
        return result;
    if (input->observed_algorithm != input->requested_algorithm) {
        result.blocker = FK_FORMAL_RSS_OWNER_BLOCKER_ALGORITHM_MISMATCH;
        return result;
    }
    if (input->requested_hash_fields == 0u ||
        (input->observed_hash_fields & input->requested_hash_fields) !=
        input->requested_hash_fields) {
        result.blocker = FK_FORMAL_RSS_OWNER_BLOCKER_HASH_FIELDS_MISMATCH;
        return result;
    }
    if (input->requested_hash_key_length == 0u ||
        input->observed_hash_key_length !=
            input->requested_hash_key_length ||
        !input->observed_hash_key_digest_valid) {
        result.blocker = FK_FORMAL_RSS_OWNER_BLOCKER_HASH_KEY_BINDING;
        return result;
    }
    result.passed = true;
    result.blocker = FK_FORMAL_RSS_OWNER_BLOCKER_NONE;
    return result;
}

const char *fk_formal_rss_owner_blocker_name(
        fk_formal_rss_owner_blocker blocker) {
    switch (blocker) {
    case FK_FORMAL_RSS_OWNER_BLOCKER_NONE:
        return "none";
    case FK_FORMAL_RSS_OWNER_BLOCKER_INVALID_TOPOLOGY:
        return "RSS_owner_topology_invalid";
    case FK_FORMAL_RSS_OWNER_BLOCKER_ALGORITHM_UNSUPPORTED:
        return "symmetric_RSS_algorithm_not_advertised";
    case FK_FORMAL_RSS_OWNER_BLOCKER_READBACK_FAILED:
        return "RSS_runtime_readback_failed";
    case FK_FORMAL_RSS_OWNER_BLOCKER_ALGORITHM_MISMATCH:
        return "RSS_runtime_algorithm_mismatch";
    case FK_FORMAL_RSS_OWNER_BLOCKER_HASH_FIELDS_MISMATCH:
        return "RSS_runtime_hash_fields_mismatch";
    case FK_FORMAL_RSS_OWNER_BLOCKER_HASH_KEY_BINDING:
        return "RSS_runtime_hash_key_binding_failed";
    }
    return "unknown_formal_RSS_owner_blocker";
}

}  // extern "C"
