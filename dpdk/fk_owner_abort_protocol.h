#ifndef FLOWKEEP_FK_OWNER_ABORT_PROTOCOL_H
#define FLOWKEEP_FK_OWNER_ABORT_PROTOCOL_H

#include <stdbool.h>
#include <stdint.h>

#include "fk_exact_identity_sequencer.h"

#ifdef __cplusplus
extern "C" {
#endif

#define FK_OWNER_ABORT_PROTOCOL_ABI_VERSION 1u
#define FK_OWNER_ABORT_MAX_FIXED_OWNERS 64u
#define FK_OWNER_ABORT_IDENTITY_RX_PARTICIPANT_ID 0u

/*
 * Owner-local phase-one evidence.  This value is deliberately not a global
 * shutdown capability: the coordinator accepts it only after the borrowed
 * pump validates an exact byte-for-byte match against its immutable stored
 * receipt and rechecks the live ring/ownership state.
 */
struct fk_fixed_owner_abort_prepared_receipt_v1 {
    uint32_t abi_version;
    uint16_t fixed_owner;
    uint16_t owner_count;
    uint64_t receipt_ordinal;
    uint64_t pump_instance_token;
    uint64_t first_sequence_candidate;
    uint64_t committed_outbox_transaction_epoch;
    uint64_t exact_mbufs_reclaimed;
    uint64_t retire_controls_discarded;
    uint64_t completion_values_discarded;
    uint8_t first_sequence_candidate_present;
    uint8_t committed_outbox_discarded;
    /* Resolved means either already published before abort or explicitly
     * discarded by the owner-thread-only failure-atomic adapter API. */
    uint8_t outbox_resolved;
    uint8_t output_ring_stopped;
    uint8_t no_local_ownership;
    uint8_t reserved[3];
};

/*
 * Identity/RX phase-one evidence.  The descriptor is an exact candidate,
 * never an assertion that the bridge has already been made terminal.
 */
struct fk_owner_abort_identity_prepared_receipt_v1 {
    uint32_t abi_version;
    uint16_t producer_count;
    uint16_t reserved0;
    uint64_t receipt_ordinal;
    uint64_t pump_instance_token;
    uint64_t submitted_packets;
    uint64_t data_transfers;
    uint64_t reclaimed_packets;
    struct fk_exact_identity_packet candidate;
    uint32_t first_reason;
    uint8_t candidate_present;
    uint8_t router_candidate_present;
    uint8_t reserved[2];
};

/* Filled only by a component-owned verifier after it compares the supplied
 * receipt with the pump's immutable stored receipt and reads live state. */
struct fk_owner_abort_identity_live_summary_v1 {
    uint32_t abi_version;
    uint16_t producer_count;
    uint16_t reserved0;
    uint64_t exact_owned_mbufs;
    uint64_t sequencer_owned_packets;
    uint64_t submitted_packets;
    uint64_t data_transfers;
    uint64_t reclaimed_packets;
    uint8_t inputs_stopped;
    uint8_t admissions_stopped;
    uint8_t rx_handoffs_resolved;
    uint8_t router_candidate_declared;
    uint8_t accounting_conserved;
    uint8_t reserved[3];
};

typedef bool (*fk_owner_abort_identity_prepared_verify_fn)(
    const void *context,
    const struct fk_owner_abort_identity_prepared_receipt_v1 *receipt,
    struct fk_owner_abort_identity_live_summary_v1 *summary);

enum fk_owner_pipeline_abort_bridge_outcome {
    FK_OWNER_PIPELINE_ABORT_BRIDGE_OUTCOME_INVALID = 0,
    FK_OWNER_PIPELINE_ABORT_BRIDGE_ACTIVE_RECORDED = 1,
    FK_OWNER_PIPELINE_ABORT_BRIDGE_NO_ACTIVE = 2,
};

enum fk_owner_pipeline_abort_participant_kind {
    FK_OWNER_PIPELINE_ABORT_PARTICIPANT_IDENTITY_RX = 1,
    FK_OWNER_PIPELINE_ABORT_PARTICIPANT_FIXED_OWNER = 2,
};

/*
 * Immutable global phase-two capability.  No participant may authorize
 * itself by inspecting these fields: finalize must pass both this value and
 * its coordinator back to the coordinator validation/authorization APIs.
 * auth_tag[0] and auth_tag[1] are independent SipHash-2-4 tags over every
 * preceding byte.  Validation additionally requires an exact match with the
 * coordinator's private stored receipt and current clean bridge state.
 */
struct fk_owner_pipeline_abort_receipt_v1 {
    uint32_t abi_version;
    uint16_t owner_count;
    uint16_t identity_participant_count;
    uint64_t coordinator_epoch;
    uint64_t receipt_ordinal;
    uint64_t prepared_owner_mask;
    uint64_t bridge_abort_packet_sequence;
    uint64_t bridge_abort_receipt_ordinal;
    uint64_t reservations_cleaned;
    uint64_t ring_batches_cleaned;
    uint64_t reorder_envelopes_cleaned;
    uint64_t checkpoint_payloads_cleaned;
    uint64_t completion_values_discarded;
    uint64_t dispatch_data_reclaimed;
    uint64_t dispatch_retire_controls_discarded;
    uint64_t bridge_bound_loss_candidates;
    uint64_t bridge_bound_candidates_exact_verified;
    uint16_t bridge_abort_expected_owner;
    uint8_t bridge_abort_route_kind;
    uint8_t bridge_abort_reason;
    uint8_t bridge_abort_slot_was_bound;
    uint8_t bridge_outcome;
    uint8_t identity_prepared_verified;
    uint8_t dispatch_admissions_stopped;
    uint8_t dispatch_drained;
    uint8_t all_owner_prepared_verified;
    uint8_t outboxes_resolved;
    uint8_t all_owner_rings_stopped;
    uint8_t bridge_cleanup_done;
    uint8_t bridge_clean_state_verified;
    uint8_t dispatch_pending_ownership;
    uint8_t reserved[1];
    uint64_t auth_tag[2];
};

#ifdef __cplusplus
}
#endif

#endif
