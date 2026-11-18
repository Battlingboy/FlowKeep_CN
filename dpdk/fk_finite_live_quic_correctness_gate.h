#ifndef FLOWKEEP_FK_FINITE_LIVE_QUIC_CORRECTNESS_GATE_H
#define FLOWKEEP_FK_FINITE_LIVE_QUIC_CORRECTNESS_GATE_H

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define FK_FINITE_LIVE_QUIC_CORRECTNESS_GATE_ABI_VERSION 1u

/*
 * Fail-closed blockers for the deliberately narrow capability proved by this
 * gate: one finite replay through one real NIC RX queue and one fixed owner.
 * The values are bits because a receipt must preserve every failed equation,
 * rather than hiding later failures behind a first-error result.
 */
enum fk_finite_live_quic_correctness_blocker {
    FK_FINITE_LIVE_QUIC_BLOCKER_NONE = 0u,
    FK_FINITE_LIVE_QUIC_BLOCKER_INVALID_INPUT = 1u << 0,
    FK_FINITE_LIVE_QUIC_BLOCKER_TOPOLOGY_SCOPE = 1u << 1,
    FK_FINITE_LIVE_QUIC_BLOCKER_NIC_ZERO_LOSS = 1u << 2,
    FK_FINITE_LIVE_QUIC_BLOCKER_TRANSPORT_EXACT_RECOVERY = 1u << 3,
    FK_FINITE_LIVE_QUIC_BLOCKER_PACKET_CONSERVATION = 1u << 4,
    FK_FINITE_LIVE_QUIC_BLOCKER_PIPELINE_CLOSURE = 1u << 5,
    FK_FINITE_LIVE_QUIC_BLOCKER_QUIC_ACTIVITY = 1u << 6,
    FK_FINITE_LIVE_QUIC_BLOCKER_IDENTITY_CAPACITY = 1u << 7,
    FK_FINITE_LIVE_QUIC_BLOCKER_IDENTITY_EOF_DRAIN = 1u << 8,
    FK_FINITE_LIVE_QUIC_BLOCKER_IDENTITY_TERMINAL_ZERO = 1u << 9,
    FK_FINITE_LIVE_QUIC_BLOCKER_PUBLISHER_FORMAL = 1u << 10,
    FK_FINITE_LIVE_QUIC_BLOCKER_RETIREMENT_ACK_CONSERVATION = 1u << 11,
    /* Promotion is opt-in even when every measured equation is valid. */
    FK_FINITE_LIVE_QUIC_BLOCKER_QUIC_PROOF_NOT_REQUIRED = 1u << 12,
};

struct fk_finite_live_quic_correctness_gate_input {
    uint32_t abi_version;
    bool require_quic_identity_proof;

    /* This v1 capability is intentionally not a multi-queue/RSS claim. */
    uint16_t rx_queue_count;
    uint16_t owner_count;

    /* Stopped-port, baseline-to-end NIC receipt. */
    bool actual_nic_rx_connected;
    bool nic_port_stop_succeeded;
    bool nic_port_close_succeeded;
    bool nic_promiscuous_disabled;
    bool nic_mtu_restored;
    bool nic_stats_baseline_valid;
    bool nic_stats_end_valid;
    bool nic_stats_monotonic;
    bool nic_drop_xstat_resolved;
    bool nic_drop_xstat_baseline_valid;
    bool nic_drop_xstat_end_valid;
    bool nic_drop_xstat_monotonic;
    uint64_t nic_missed_packets;
    uint64_t nic_input_errors;
    uint64_t nic_rx_nombuf;
    uint64_t nic_drop_xstat_delta;

    /* Frozen transport sidecar and exact sequence restoration receipt. */
    bool finite_sidecar_preflight_verified;
    bool transport_exact_recovery_complete;
    uint64_t expected_packets;
    uint64_t transport_packets_recovered;
    uint64_t transport_sequence_gaps;
    uint64_t transport_sequence_duplicates;
    uint64_t transport_identity_mismatches;
    uint64_t transport_decode_failures;
    uint64_t transport_tracking_failures;

    /* End-to-end packet and mbuf ownership conservation. */
    uint64_t nic_received_packets;
    uint64_t nic_non_trace_packets_filtered;
    uint64_t pipeline_rx_packets;
    uint64_t sequencer_transferred_packets;
    uint64_t identity_data_transfers;
    uint64_t identity_skip_reclaims;
    uint64_t identity_reject_reclaims;
    uint64_t owner_packets_completed;
    uint64_t mbufs_reclaimed;
    uint64_t live_mbufs_at_end;
    uint64_t duplicate_reclaims;
    uint64_t forced_failure_reclaims;

    /* Normal finite-epoch closure; abort/drain paths cannot satisfy it. */
    bool source_exhausted;
    bool source_failed;
    bool partial_epoch_closed;
    bool bridge_sealed;
    bool reorder_drained;
    bool ownership_conserved;
    bool global_order_conserved;
    bool normal_complete;
    bool router_parser_reason_conserved;
    bool packet_disposition_conserved;
    bool controlled_state_accounting_valid;
    bool state_byte_seconds_complete;
    bool evidence_transition_receipt_complete;
    bool service_memory_receipt_valid;
    uint64_t controlled_state_hard_budget_violations;

    /* Non-vacuous QUIC exercise and identity-stage conservation. */
    uint64_t quic_packets_observed;
    uint64_t quic_connections_observed;
    bool quic_identity_disposition_conserved;
    uint64_t quic_identity_packets_routed;
    uint64_t quic_identity_packets_skipped;
    uint64_t quic_owner_packets_processed;

    /* Preallocated, controlled identity-directory capacity. */
    bool quic_identity_parser_complete;
    bool quic_identity_semantic_ordering_connected;
    bool quic_cid_map_connected;
    bool quic_presentation_path_connected;
    bool owner_flow_bindings_connected;
    bool identity_capacity_accounting_valid;
    uint32_t configured_quic_connection_capacity;
    uint32_t quic_cid_connection_capacity;
    uint32_t quic_path_connection_capacity;
    uint32_t owner_binding_connection_capacity;
    uint32_t peak_active_quic_connections;

    /* Explicit finite-epoch drain after the last source observation. */
    bool finite_epoch_drain_requested;
    bool finite_epoch_drain_after_source_eof;
    bool finite_epoch_drain_timestamp_formal;
    bool finite_epoch_drain_before_publisher_terminal;
    bool cid_finite_epoch_drain_succeeded;
    bool path_finite_epoch_drain_succeeded;
    uint64_t cid_active_connections_before_drain;
    uint64_t cid_connections_drained;
    uint64_t cid_active_connections_after_drain;
    uint64_t path_active_connections_before_drain;
    uint64_t path_active_connections_after_drain;
    uint64_t path_active_paths_before_drain;
    uint64_t path_paths_drained;
    uint64_t path_active_paths_after_drain;

    /* All identity state must be empty after publication and owner ACKs. */
    uint64_t cid_active_connections_at_end;
    uint64_t cid_active_cids_at_end;
    uint64_t cid_pending_handshakes_at_end;
    uint64_t cid_pending_bindings_at_end;
    uint64_t cid_retired_pending_owner_ack_at_end;
    uint64_t path_active_connections_at_end;
    uint64_t path_active_paths_at_end;
    uint64_t owner_active_bindings_at_end;
    uint64_t owner_unbound_slots_at_end;
    uint64_t owner_retired_pending_cid_ack_slots_at_end;

    /* Formal publisher terminal receipt. */
    bool retirement_publisher_formal_mode;
    bool retirement_observations_sealed;
    bool retirement_publisher_terminal;
    bool retirement_publisher_queue_empty;
    bool retirement_publisher_failed;

    /* Cumulative cross-module retirement-control conservation. */
    uint64_t retirement_controls_committed;
    uint64_t retirement_controls_dispatched;
    uint64_t retirement_controls_normal_dequeued;
    uint64_t owner_retire_dequeued;
    uint64_t owner_retire_acked;
    uint64_t adapter_retire_calls;
    uint64_t adapter_retire_acked;
    uint64_t cid_connections_retired_pending_owner_ack;
    uint64_t cid_retirement_publication_marks;
    uint64_t cid_retirement_ack_calls;
    uint64_t cid_retirement_acks;
    uint64_t retirement_control_failures;
};

struct fk_finite_live_quic_correctness_gate_result {
    uint64_t blocker_mask;
    bool actual_nic_finite_pipeline_ready;
    bool quic_activity_observed;
    bool quic_identity_correctness_ready;
    bool scoped_capability_promoted;
};

struct fk_finite_live_quic_correctness_gate_result
fk_finite_live_quic_correctness_gate_evaluate(
    const struct fk_finite_live_quic_correctness_gate_input *input);

#ifdef __cplusplus
}
#endif

#endif
