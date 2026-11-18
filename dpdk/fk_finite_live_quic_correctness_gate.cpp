#include "fk_finite_live_quic_correctness_gate.h"

#include <limits.h>

namespace {

constexpr uint64_t bit(fk_finite_live_quic_correctness_blocker value) {
    return static_cast<uint64_t>(value);
}

bool exact_packet_conservation(
        const fk_finite_live_quic_correctness_gate_input &input) {
    if (input.expected_packets == 0u)
        return false;
    const uint64_t expected = input.expected_packets;
    if (input.nic_non_trace_packets_filtered > UINT64_MAX - expected ||
        input.identity_skip_reclaims >
            UINT64_MAX - input.identity_data_transfers)
        return false;
    const uint64_t nic_accounted =
        expected + input.nic_non_trace_packets_filtered;
    uint64_t identity_accounted =
        input.identity_data_transfers + input.identity_skip_reclaims;
    if (input.identity_reject_reclaims > UINT64_MAX - identity_accounted)
        return false;
    identity_accounted += input.identity_reject_reclaims;
    return input.nic_received_packets == nic_accounted &&
        input.pipeline_rx_packets == expected &&
        input.sequencer_transferred_packets == expected &&
        identity_accounted == expected &&
        input.owner_packets_completed == input.identity_data_transfers &&
        input.mbufs_reclaimed == expected &&
        input.live_mbufs_at_end == 0u &&
        input.duplicate_reclaims == 0u &&
        input.forced_failure_reclaims == 0u;
}

bool drain_conserved(uint64_t before, uint64_t drained, uint64_t after) {
    return drained <= UINT64_MAX - after && before == drained + after;
}

bool path_directory_shape_conserved(
        uint64_t active_connections,
        uint64_t active_paths) {
    /* Every live path belongs to exactly one live logical connection, and a
     * live logical connection represented by this directory owns at least
     * one path.  Keep this necessary relation independent of the directory's
     * self-reported complete bit. */
    return active_connections <= active_paths &&
        ((active_connections == 0u) == (active_paths == 0u));
}

bool quic_disposition_conserved(
        const fk_finite_live_quic_correctness_gate_input &input) {
    return input.quic_identity_disposition_conserved &&
        input.quic_identity_packets_skipped <=
            UINT64_MAX - input.quic_identity_packets_routed &&
        input.quic_identity_packets_routed +
                input.quic_identity_packets_skipped ==
            input.quic_packets_observed &&
        input.quic_owner_packets_processed ==
            input.quic_identity_packets_routed;
}

bool identity_capacity_valid(
        const fk_finite_live_quic_correctness_gate_input &input) {
    const uint32_t capacity = input.configured_quic_connection_capacity;
    return input.quic_identity_parser_complete &&
        input.quic_identity_semantic_ordering_connected &&
        input.quic_cid_map_connected &&
        input.quic_presentation_path_connected &&
        input.owner_flow_bindings_connected &&
        input.identity_capacity_accounting_valid && capacity != 0u &&
        input.quic_cid_connection_capacity == capacity &&
        input.quic_path_connection_capacity == capacity &&
        input.owner_binding_connection_capacity == capacity &&
        input.peak_active_quic_connections <= capacity;
}

bool retirement_conserved(
        const fk_finite_live_quic_correctness_gate_input &input) {
    const uint64_t controls = input.retirement_controls_committed;
    return controls != 0u &&
        controls == input.quic_connections_observed &&
        input.retirement_controls_dispatched == controls &&
        input.retirement_controls_normal_dequeued == controls &&
        input.owner_retire_dequeued == controls &&
        input.owner_retire_acked == controls &&
        input.adapter_retire_calls == controls &&
        input.adapter_retire_acked == controls &&
        input.cid_connections_retired_pending_owner_ack == controls &&
        input.cid_retirement_publication_marks == controls &&
        input.cid_retirement_ack_calls == controls &&
        input.cid_retirement_acks == controls &&
        input.retirement_control_failures == 0u;
}

}  // namespace

extern "C" {

fk_finite_live_quic_correctness_gate_result
fk_finite_live_quic_correctness_gate_evaluate(
        const fk_finite_live_quic_correctness_gate_input *input) {
    fk_finite_live_quic_correctness_gate_result result{};
    if (input == nullptr ||
        input->abi_version !=
            FK_FINITE_LIVE_QUIC_CORRECTNESS_GATE_ABI_VERSION) {
        result.blocker_mask =
            bit(FK_FINITE_LIVE_QUIC_BLOCKER_INVALID_INPUT);
        return result;
    }

    uint64_t blockers = 0u;
    if (input->rx_queue_count != 1u || input->owner_count != 1u)
        blockers |= bit(FK_FINITE_LIVE_QUIC_BLOCKER_TOPOLOGY_SCOPE);

    if (!input->actual_nic_rx_connected ||
        !input->nic_port_stop_succeeded ||
        !input->nic_port_close_succeeded ||
        !input->nic_promiscuous_disabled || !input->nic_mtu_restored ||
        !input->nic_stats_baseline_valid ||
        !input->nic_stats_end_valid || !input->nic_stats_monotonic ||
        !input->nic_drop_xstat_resolved ||
        !input->nic_drop_xstat_baseline_valid ||
        !input->nic_drop_xstat_end_valid ||
        !input->nic_drop_xstat_monotonic ||
        input->nic_missed_packets != 0u ||
        input->nic_input_errors != 0u || input->nic_rx_nombuf != 0u ||
        input->nic_drop_xstat_delta != 0u) {
        blockers |= bit(FK_FINITE_LIVE_QUIC_BLOCKER_NIC_ZERO_LOSS);
    }

    if (!input->finite_sidecar_preflight_verified ||
        !input->transport_exact_recovery_complete ||
        input->expected_packets == 0u ||
        input->transport_packets_recovered != input->expected_packets ||
        input->transport_sequence_gaps != 0u ||
        input->transport_sequence_duplicates != 0u ||
        input->transport_identity_mismatches != 0u ||
        input->transport_decode_failures != 0u ||
        input->transport_tracking_failures != 0u) {
        blockers |=
            bit(FK_FINITE_LIVE_QUIC_BLOCKER_TRANSPORT_EXACT_RECOVERY);
    }

    if (!exact_packet_conservation(*input))
        blockers |= bit(FK_FINITE_LIVE_QUIC_BLOCKER_PACKET_CONSERVATION);

    if (!input->source_exhausted || input->source_failed ||
        !input->partial_epoch_closed || !input->bridge_sealed ||
        !input->reorder_drained || !input->ownership_conserved ||
        !input->global_order_conserved || !input->normal_complete ||
        !input->router_parser_reason_conserved ||
        !input->packet_disposition_conserved ||
        !input->controlled_state_accounting_valid ||
        !input->state_byte_seconds_complete ||
        !input->evidence_transition_receipt_complete ||
        !input->service_memory_receipt_valid ||
        input->controlled_state_hard_budget_violations != 0u) {
        blockers |= bit(FK_FINITE_LIVE_QUIC_BLOCKER_PIPELINE_CLOSURE);
    }

    result.quic_activity_observed = input->quic_packets_observed != 0u;
    if (!result.quic_activity_observed ||
        input->quic_connections_observed == 0u ||
        !quic_disposition_conserved(*input)) {
        blockers |= bit(FK_FINITE_LIVE_QUIC_BLOCKER_QUIC_ACTIVITY);
    }

    if (!identity_capacity_valid(*input))
        blockers |= bit(FK_FINITE_LIVE_QUIC_BLOCKER_IDENTITY_CAPACITY);

    if (!input->finite_epoch_drain_requested ||
        !input->finite_epoch_drain_after_source_eof ||
        !input->finite_epoch_drain_timestamp_formal ||
        !input->finite_epoch_drain_before_publisher_terminal ||
        !input->cid_finite_epoch_drain_succeeded ||
        !input->path_finite_epoch_drain_succeeded ||
        !drain_conserved(
            input->cid_active_connections_before_drain,
            input->cid_connections_drained,
            input->cid_active_connections_after_drain) ||
        !path_directory_shape_conserved(
            input->path_active_connections_before_drain,
            input->path_active_paths_before_drain) ||
        !drain_conserved(
            input->path_active_paths_before_drain,
            input->path_paths_drained,
            input->path_active_paths_after_drain)) {
        blockers |= bit(FK_FINITE_LIVE_QUIC_BLOCKER_IDENTITY_EOF_DRAIN);
    }

    if (input->cid_active_connections_after_drain != 0u ||
        input->path_active_connections_after_drain != 0u ||
        input->path_active_paths_after_drain != 0u ||
        input->cid_active_connections_at_end != 0u ||
        input->cid_active_cids_at_end != 0u ||
        input->cid_pending_handshakes_at_end != 0u ||
        input->cid_pending_bindings_at_end != 0u ||
        input->cid_retired_pending_owner_ack_at_end != 0u ||
        input->path_active_connections_at_end != 0u ||
        input->path_active_paths_at_end != 0u ||
        input->owner_active_bindings_at_end != 0u ||
        input->owner_unbound_slots_at_end != 0u ||
        input->owner_retired_pending_cid_ack_slots_at_end != 0u) {
        blockers |=
            bit(FK_FINITE_LIVE_QUIC_BLOCKER_IDENTITY_TERMINAL_ZERO);
    }

    if (!input->retirement_publisher_formal_mode ||
        !input->retirement_observations_sealed ||
        !input->retirement_publisher_terminal ||
        !input->retirement_publisher_queue_empty ||
        input->retirement_publisher_failed) {
        blockers |= bit(FK_FINITE_LIVE_QUIC_BLOCKER_PUBLISHER_FORMAL);
    }

    if (!retirement_conserved(*input)) {
        blockers |= bit(
            FK_FINITE_LIVE_QUIC_BLOCKER_RETIREMENT_ACK_CONSERVATION);
    }

    if (!input->require_quic_identity_proof) {
        blockers |=
            bit(FK_FINITE_LIVE_QUIC_BLOCKER_QUIC_PROOF_NOT_REQUIRED);
    }

    const uint64_t pipeline_blockers =
        bit(FK_FINITE_LIVE_QUIC_BLOCKER_INVALID_INPUT) |
        bit(FK_FINITE_LIVE_QUIC_BLOCKER_TOPOLOGY_SCOPE) |
        bit(FK_FINITE_LIVE_QUIC_BLOCKER_NIC_ZERO_LOSS) |
        bit(FK_FINITE_LIVE_QUIC_BLOCKER_TRANSPORT_EXACT_RECOVERY) |
        bit(FK_FINITE_LIVE_QUIC_BLOCKER_PACKET_CONSERVATION) |
        bit(FK_FINITE_LIVE_QUIC_BLOCKER_PIPELINE_CLOSURE);
    const uint64_t identity_blockers =
        bit(FK_FINITE_LIVE_QUIC_BLOCKER_QUIC_ACTIVITY) |
        bit(FK_FINITE_LIVE_QUIC_BLOCKER_IDENTITY_CAPACITY) |
        bit(FK_FINITE_LIVE_QUIC_BLOCKER_IDENTITY_EOF_DRAIN) |
        bit(FK_FINITE_LIVE_QUIC_BLOCKER_IDENTITY_TERMINAL_ZERO) |
        bit(FK_FINITE_LIVE_QUIC_BLOCKER_PUBLISHER_FORMAL) |
        bit(FK_FINITE_LIVE_QUIC_BLOCKER_RETIREMENT_ACK_CONSERVATION);

    result.blocker_mask = blockers;
    result.actual_nic_finite_pipeline_ready =
        (blockers & pipeline_blockers) == 0u;
    result.quic_identity_correctness_ready =
        result.actual_nic_finite_pipeline_ready &&
        (blockers & identity_blockers) == 0u;
    result.scoped_capability_promoted =
        input->require_quic_identity_proof && blockers == 0u &&
        result.quic_identity_correctness_ready;
    return result;
}

}  // extern "C"
