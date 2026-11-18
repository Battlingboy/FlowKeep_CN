#ifndef FLOWKEEP_FK_EXACT_IDENTITY_RX_WORKER_PUMP_H
#define FLOWKEEP_FK_EXACT_IDENTITY_RX_WORKER_PUMP_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "fk_dpdk_exact_identity_mbuf_source.h"
#include "fk_exact_identity_router.h"
#include "fk_exact_identity_sequencer.h"
#include "fk_owner_abort_protocol.h"
#include "fk_owner_output_sequence_bridge.h"

#ifdef __cplusplus
extern "C" {
#endif

#define FK_EXACT_IDENTITY_RX_WORKER_PUMP_ABI_VERSION 1u

/* Failure-atomic exact-handle reclamation. true means the callback consumed
 * the ownership exactly once (normally by rte_pktmbuf_free). false means no
 * ownership transfer occurred and the pump will offer the identical handle
 * again without re-claiming or re-routing it. The callback runs on the
 * identity thread and must not re-enter the pump or any borrowed dependency. */
typedef bool (*fk_exact_identity_rx_reclaim_callback)(
    void *context,
    uintptr_t exact_packet_handle);

struct fk_exact_identity_rx_worker_pump_config {
    uint32_t abi_version;
    uint16_t producer_count;
    uint8_t reserved0[2];
    struct fk_exact_identity_sequencer *sequencer;
    struct fk_dpdk_exact_identity_mbuf_source *source;
    struct fk_exact_identity_router *router;
    struct fk_owner_output_sequence_bridge *completion_bridge;
    void *reclaim_context;
    fk_exact_identity_rx_reclaim_callback reclaim;
    uint8_t reserved[8];
};

enum fk_exact_identity_rx_worker_step_result {
    FK_EXACT_IDENTITY_RX_WORKER_STEP_INVALID = 0,
    FK_EXACT_IDENTITY_RX_WORKER_STEP_IDLE = 1,
    FK_EXACT_IDENTITY_RX_WORKER_STEP_DATA_TRANSFERRED = 2,
    FK_EXACT_IDENTITY_RX_WORKER_STEP_PACKET_RECLAIMED = 3,
    FK_EXACT_IDENTITY_RX_WORKER_STEP_BACKPRESSURE_RETAINED = 4,
    FK_EXACT_IDENTITY_RX_WORKER_STEP_RECLAIM_RETRY = 5,
    FK_EXACT_IDENTITY_RX_WORKER_STEP_COMPLETE = 6,
    FK_EXACT_IDENTITY_RX_WORKER_STEP_TERMINAL = 7,
    FK_EXACT_IDENTITY_RX_WORKER_STEP_STOPPED = 8,
    FK_EXACT_IDENTITY_RX_WORKER_STEP_WRONG_THREAD = 9,
};

enum fk_exact_identity_rx_worker_terminal_reason {
    FK_EXACT_IDENTITY_RX_WORKER_TERMINAL_NONE = 0,
    FK_EXACT_IDENTITY_RX_WORKER_TERMINAL_CONFIGURATION = 1,
    FK_EXACT_IDENTITY_RX_WORKER_TERMINAL_IDENTITY_CLAIM = 2,
    FK_EXACT_IDENTITY_RX_WORKER_TERMINAL_COUNTER_OVERFLOW = 3,
    FK_EXACT_IDENTITY_RX_WORKER_TERMINAL_SEQUENCER = 4,
    FK_EXACT_IDENTITY_RX_WORKER_TERMINAL_SOURCE_CLAIM = 5,
    FK_EXACT_IDENTITY_RX_WORKER_TERMINAL_ROUTER = 6,
    FK_EXACT_IDENTITY_RX_WORKER_TERMINAL_SOURCE_TRANSITION = 7,
    FK_EXACT_IDENTITY_RX_WORKER_TERMINAL_EXPLICIT_ABORT = 8,
    FK_EXACT_IDENTITY_RX_WORKER_TERMINAL_RESERVATION_STOP = 9,
    FK_EXACT_IDENTITY_RX_WORKER_TERMINAL_OWNERSHIP_INDETERMINATE = 10,
};

enum fk_exact_identity_rx_worker_stop_result {
    FK_EXACT_IDENTITY_RX_WORKER_STOP_INVALID = 0,
    FK_EXACT_IDENTITY_RX_WORKER_STOP_NOT_READY = 1,
    FK_EXACT_IDENTITY_RX_WORKER_STOPPED_NORMAL = 2,
    FK_EXACT_IDENTITY_RX_WORKER_STOP_WRONG_THREAD = 3,
    FK_EXACT_IDENTITY_RX_WORKER_STOP_TERMINAL = 4,
    FK_EXACT_IDENTITY_RX_WORKER_STOP_ALREADY_STOPPED = 5,
};

enum fk_exact_identity_rx_worker_abort_prepare_result {
    FK_EXACT_IDENTITY_RX_WORKER_ABORT_PREPARE_INVALID = 0,
    FK_EXACT_IDENTITY_RX_WORKER_ABORT_PREPARE_RETRY_REQUIRED = 1,
    FK_EXACT_IDENTITY_RX_WORKER_ABORT_PREPARED_NEEDS_GLOBAL = 2,
    FK_EXACT_IDENTITY_RX_WORKER_ABORT_PREPARE_WRONG_THREAD = 3,
    FK_EXACT_IDENTITY_RX_WORKER_ABORT_PREPARE_ALREADY_PREPARED = 4,
    FK_EXACT_IDENTITY_RX_WORKER_ABORT_PREPARE_UNRECOVERABLE = 5,
};

enum fk_exact_identity_rx_worker_abort_finalize_result {
    FK_EXACT_IDENTITY_RX_WORKER_ABORT_FINALIZE_INVALID = 0,
    FK_EXACT_IDENTITY_RX_WORKER_ABORT_FINALIZE_NOT_READY = 1,
    FK_EXACT_IDENTITY_RX_WORKER_ABORT_FINALIZED = 2,
    FK_EXACT_IDENTITY_RX_WORKER_ABORT_FINALIZE_WRONG_THREAD = 3,
    FK_EXACT_IDENTITY_RX_WORKER_ABORT_FINALIZE_ALREADY_STOPPED = 4,
    FK_EXACT_IDENTITY_RX_WORKER_ABORT_FINALIZE_UNRECOVERABLE = 5,
};

struct fk_owner_pipeline_abort_coordinator;

/* Immutable first-failure receipt. If descriptor_present is one, descriptor
 * is the complete value transferred from the sequencer. The optional bridge
 * receipt is copied only when that same packet already owned a reservation. */
struct fk_exact_identity_rx_worker_abort_receipt_v1 {
    uint32_t abi_version;
    enum fk_exact_identity_rx_worker_terminal_reason first_reason;
    uint64_t receipt_ordinal;
    struct fk_exact_identity_packet descriptor;
    struct fk_owner_reserved_abort_receipt_v1 bridge_receipt;
    uint8_t descriptor_present;
    uint8_t bridge_receipt_present;
    uint8_t reserved[6];
};

struct fk_exact_identity_rx_worker_pump_stats {
    uint64_t identity_claim_attempts;
    uint64_t identity_claim_successes;
    uint64_t identity_claim_rejections;
    uint64_t wrong_thread_calls;

    uint64_t step_calls;
    uint64_t step_idle;
    uint64_t step_data_transferred;
    uint64_t step_packet_reclaimed;
    uint64_t step_backpressure_retained;
    uint64_t step_reclaim_retry;
    uint64_t step_complete;
    uint64_t step_terminal;
    uint64_t step_stopped;

    uint64_t sequencer_poll_calls;
    uint64_t sequencer_poll_released;
    uint64_t sequencer_poll_idle;
    uint64_t sequencer_poll_complete;
    uint64_t sequencer_poll_terminal;
    uint64_t sequencer_poll_invalid;
    uint64_t sequencer_abort_attempts;
    uint64_t sequencer_abort_acknowledged;
    uint64_t sequencer_abort_failures;
    uint64_t sequencer_drain_attempts;
    uint64_t sequencer_drain_handoffs;
    uint64_t sequencer_drain_empty;

    /* A submitted packet is any handle transferred from the sequencer to
     * this pump, by ordered RELEASED or abort drain_next. */
    uint64_t submitted_packets;
    uint64_t source_claim_attempts;
    uint64_t source_claim_successes;
    uint64_t source_claim_failures;
    uint64_t router_calls;
    uint64_t router_data_committed;
    uint64_t router_skip_committed;
    uint64_t router_backpressure;
    uint64_t router_terminal_or_invalid;
    uint64_t source_retain_attempts;
    uint64_t source_retain_successes;
    uint64_t source_retain_failures;
    uint64_t source_transfer_clear_attempts;
    uint64_t source_transfer_clears;
    uint64_t source_transfer_clear_failures;
    uint64_t source_skip_clear_attempts;
    uint64_t source_skip_clears;
    uint64_t source_skip_clear_failures;
    uint64_t source_reject_clear_attempts;
    uint64_t source_reject_clears;
    uint64_t source_reject_clear_failures;

    uint64_t reclaim_attempts;
    uint64_t reclaim_successes;
    uint64_t reclaim_failures;
    uint64_t reclaimed_skip_packets;
    uint64_t reclaimed_reject_packets;
    uint64_t reclaimed_abort_drain_packets;
    uint64_t data_transfers;
    uint64_t reclaimed_packets;
    uint64_t pending_owned_packets;
    uint64_t peak_pending_owned_packets;

    uint64_t router_detach_attempts;
    uint64_t router_detach_successes;
    uint64_t router_detach_already_detached;
    uint64_t router_detach_none;
    uint64_t router_detach_failures;
    uint64_t bridge_stop_reservation_attempts;
    uint64_t bridge_stop_reservation_successes;
    uint64_t bridge_stop_reservation_failures;
    uint64_t normal_stop_attempts;
    uint64_t normal_stop_successes;
    uint64_t normal_stop_rejections;
    uint64_t abort_prepare_calls;
    uint64_t abort_prepare_retries;
    uint64_t abort_prepare_successes;
    uint64_t abort_prepare_unrecoverable;
    uint64_t abort_finalize_calls;
    uint64_t abort_finalize_not_ready;
    uint64_t abort_finalize_successes;
    uint64_t abort_finalize_unrecoverable;
    uint64_t coordinator_validate_attempts;
    uint64_t coordinator_validate_successes;
    uint64_t coordinator_validate_rejections;
    uint64_t coordinator_authorize_attempts;
    uint64_t coordinator_authorize_successes;
    uint64_t coordinator_authorize_already;
    uint64_t coordinator_authorize_rejections;
    uint64_t reserved_bytes;
    uint64_t service_memory_bytes;

    uintptr_t pending_packet_handle;
    uint64_t pending_packet_sequence;
    uint32_t abi_version;
    uint16_t producer_count;
    enum fk_exact_identity_rx_worker_terminal_reason terminal_reason;
    uint8_t initialized;
    uint8_t identity_thread_claimed;
    uint8_t current_packet;
    uint8_t source_claimed;
    uint8_t reclaim_pending;
    uint8_t sequencer_complete_observed;
    uint8_t reservations_stopped;
    uint8_t abort_receipt_present;
    uint8_t abort_prepared;
    uint8_t needs_global_abort;
    uint8_t stopped_normal;
    uint8_t stopped_abort;
    uint8_t counter_overflow;
    uint8_t ownership_indeterminate;
    uint8_t accounting_conserved;
    uint8_t reserved[1];
};

struct fk_exact_identity_rx_worker_pump;

void fk_exact_identity_rx_worker_pump_default_config_init(
    struct fk_exact_identity_rx_worker_pump_config *config);

bool fk_exact_identity_rx_worker_pump_config_valid(
    const struct fk_exact_identity_rx_worker_pump_config *config);

size_t fk_exact_identity_rx_worker_pump_storage_bytes(
    const struct fk_exact_identity_rx_worker_pump_config *config);

/* Dependencies are borrowed and must outlive the pump. Initialization proves
 * the sequencer/source producer topology and requires pristine source/router
 * identity claims. It does not alter any production capability flag. */
struct fk_exact_identity_rx_worker_pump *
fk_exact_identity_rx_worker_pump_initialize(
    void *storage,
    size_t storage_bytes,
    const struct fk_exact_identity_rx_worker_pump_config *config,
    char *error,
    size_t error_capacity);

/* One-shot claim of this pump, the exact mbuf source, and the router on the
 * same identity thread. A partial dependency claim failure is terminal. */
bool fk_exact_identity_rx_worker_pump_claim_identity_thread(
    struct fk_exact_identity_rx_worker_pump *pump);

/* One bounded identity iteration. A pending descriptor/reclaim is always
 * handled before another sequencer poll. */
enum fk_exact_identity_rx_worker_step_result
fk_exact_identity_rx_worker_pump_step(
    struct fk_exact_identity_rx_worker_pump *pump);

/* Legal only after all producers closed/joined, POLL_COMPLETE was observed,
 * and no packet is pending. Stops new reservations only; owner completions
 * deliberately remain enabled for the downstream shutdown coordinator. */
enum fk_exact_identity_rx_worker_stop_result
fk_exact_identity_rx_worker_pump_stop_normal(
    struct fk_exact_identity_rx_worker_pump *pump);

/* Phase 1 is bounded and never makes the completion bridge terminal. It
 * aborts the sequencer, stops new reservations, detaches any exact router
 * candidate without touching the bridge, clears/reclaims the current packet,
 * and drains at most one queued handle. Call until PREPARED. Producer
 * threads may still need to close/join; until then an empty drain returns
 * RETRY_REQUIRED without losing any handle. */
enum fk_exact_identity_rx_worker_abort_prepare_result
fk_exact_identity_rx_worker_pump_abort_prepare(
    struct fk_exact_identity_rx_worker_pump *pump);

/* Phase 2 accepts only a coordinator-produced, privately stored, tagged
 * receipt. The implementation validates and authorizes it through that same
 * coordinator; caller-filled receipt fields can never authorize shutdown. */
enum fk_exact_identity_rx_worker_abort_finalize_result
fk_exact_identity_rx_worker_pump_abort_finalize(
    struct fk_exact_identity_rx_worker_pump *pump,
    struct fk_owner_pipeline_abort_coordinator *coordinator,
    const struct fk_owner_pipeline_abort_receipt_v1 *global_receipt);

bool fk_exact_identity_rx_worker_pump_get_abort_receipt(
    const struct fk_exact_identity_rx_worker_pump *pump,
    struct fk_exact_identity_rx_worker_abort_receipt_v1 *receipt);

/* The prepared receipt is opaque evidence, not a self-authenticating bool.
 * A coordinator must call the component-owned live verifier below, which
 * requires an exact byte match with the pump's immutable stored receipt.
 * Verification is a cold control-thread operation after the identity thread
 * has returned from PREPARED and joined. */
bool fk_exact_identity_rx_worker_pump_get_abort_prepared_receipt(
    const struct fk_exact_identity_rx_worker_pump *pump,
    struct fk_owner_abort_identity_prepared_receipt_v1 *receipt);

bool fk_exact_identity_rx_worker_pump_verify_abort_prepared_receipt(
    const struct fk_exact_identity_rx_worker_pump *pump,
    const struct fk_owner_abort_identity_prepared_receipt_v1 *receipt,
    struct fk_owner_abort_identity_live_summary_v1 *summary);

bool fk_exact_identity_rx_worker_pump_abort_prepared_verify_callback(
    const void *context,
    const struct fk_owner_abort_identity_prepared_receipt_v1 *receipt,
    struct fk_owner_abort_identity_live_summary_v1 *summary);

/* Live reads are identity-thread-only; joined control threads may read after
 * normal or abort stop. */
bool fk_exact_identity_rx_worker_pump_get_stats(
    const struct fk_exact_identity_rx_worker_pump *pump,
    struct fk_exact_identity_rx_worker_pump_stats *stats);

bool fk_exact_identity_rx_worker_pump_accounting_conserved(
    const struct fk_exact_identity_rx_worker_pump *pump);

bool fk_exact_identity_rx_worker_pump_formal_ready(
    const struct fk_exact_identity_rx_worker_pump *pump);

/* Requires a successful normal stop, or complete abort cleanup, and no
 * pump-owned handle. Dependencies remain caller-owned. */
bool fk_exact_identity_rx_worker_pump_destroy_checked(
    struct fk_exact_identity_rx_worker_pump *pump);

const char *fk_exact_identity_rx_worker_step_result_name(
    enum fk_exact_identity_rx_worker_step_result result);

#ifdef __cplusplus
}
#endif

#endif
