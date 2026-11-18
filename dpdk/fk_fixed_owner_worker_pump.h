#ifndef FLOWKEEP_FK_FIXED_OWNER_WORKER_PUMP_H
#define FLOWKEEP_FK_FIXED_OWNER_WORKER_PUMP_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "fk_dpdk_owner_mbuf_bytes_source.h"
#include "fk_owner_dispatch.h"
#include "fk_owner_abort_protocol.h"
#include "fk_owner_output_batch_ring.h"
#include "fk_owner_output_sequence_bridge.h"
#include "fk_owner_runtime_adapter.h"

#ifdef __cplusplus
extern "C" {
#endif

#define FK_FIXED_OWNER_WORKER_PUMP_ABI_VERSION 3u

/*
 * Failure-atomic exact-handle reclamation.  true means ownership was
 * transferred exactly once and the handle is no longer usable.  false means
 * no ownership transfer occurred; the pump retains the same handle and will
 * offer it only to the explicit abort-reclaim path.  A production DPDK
 * callback normally performs rte_pktmbuf_free((struct rte_mbuf *)handle).
 */
typedef bool (*fk_fixed_owner_mbuf_reclaim_callback)(
    void *context,
    uintptr_t exact_packet_handle);

struct fk_fixed_owner_worker_pump_config {
    uint32_t abi_version;
    uint16_t fixed_owner;
    uint16_t owner_count;
    struct fk_owner_dispatch *dispatch;
    struct fk_dpdk_owner_mbuf_bytes_source *mbuf_source;
    struct fk_owner_runtime_adapter *adapter;
    struct fk_owner_output_batch_ring *output_ring;
    struct fk_owner_output_sequence_bridge *output_bridge;
    void *reclaim_context;
    fk_fixed_owner_mbuf_reclaim_callback reclaim;
    uint8_t reserved[8];
};

enum fk_fixed_owner_worker_pump_step_result {
    FK_FIXED_OWNER_WORKER_PUMP_STEP_INVALID = 0,
    FK_FIXED_OWNER_WORKER_PUMP_STEP_IDLE = 1,
    FK_FIXED_OWNER_WORKER_PUMP_STEP_PROGRESSED = 2,
    FK_FIXED_OWNER_WORKER_PUMP_STEP_OUTPUT_RING_FULL = 3,
    FK_FIXED_OWNER_WORKER_PUMP_STEP_DATA_RETRY = 4,
    FK_FIXED_OWNER_WORKER_PUMP_STEP_RETIRE_RETRY = 5,
    FK_FIXED_OWNER_WORKER_PUMP_STEP_TERMINAL = 6,
    FK_FIXED_OWNER_WORKER_PUMP_STEP_STOPPED = 7,
    FK_FIXED_OWNER_WORKER_PUMP_STEP_WRONG_THREAD = 8,
};

enum fk_fixed_owner_worker_pump_terminal_reason {
    FK_FIXED_OWNER_WORKER_PUMP_TERMINAL_NONE = 0,
    FK_FIXED_OWNER_WORKER_PUMP_TERMINAL_CONFIGURATION = 1,
    FK_FIXED_OWNER_WORKER_PUMP_TERMINAL_OWNER_THREAD = 2,
    FK_FIXED_OWNER_WORKER_PUMP_TERMINAL_COUNTER_OVERFLOW = 3,
    FK_FIXED_OWNER_WORKER_PUMP_TERMINAL_ENVELOPE = 4,
    FK_FIXED_OWNER_WORKER_PUMP_TERMINAL_PACKET_SEQUENCE = 5,
    FK_FIXED_OWNER_WORKER_PUMP_TERMINAL_MBUF_CLAIM = 6,
    FK_FIXED_OWNER_WORKER_PUMP_TERMINAL_SOURCE_RELEASE = 7,
    FK_FIXED_OWNER_WORKER_PUMP_TERMINAL_RECLAIM = 8,
    FK_FIXED_OWNER_WORKER_PUMP_TERMINAL_DATA_ADAPTER = 9,
    FK_FIXED_OWNER_WORKER_PUMP_TERMINAL_RETIRE_ADAPTER = 10,
    FK_FIXED_OWNER_WORKER_PUMP_TERMINAL_OUTPUT_BATCH = 11,
    FK_FIXED_OWNER_WORKER_PUMP_TERMINAL_OUTPUT_PUBLISH = 12,
    FK_FIXED_OWNER_WORKER_PUMP_TERMINAL_COMPLETION_PUBLISH = 13,
    FK_FIXED_OWNER_WORKER_PUMP_TERMINAL_ABORT_RECEIPT = 14,
};

enum fk_fixed_owner_worker_pump_stop_result {
    FK_FIXED_OWNER_WORKER_PUMP_STOP_INVALID = 0,
    FK_FIXED_OWNER_WORKER_PUMP_STOP_NOT_READY = 1,
    FK_FIXED_OWNER_WORKER_PUMP_STOPPED_NORMAL = 2,
    FK_FIXED_OWNER_WORKER_PUMP_STOP_WRONG_THREAD = 3,
    FK_FIXED_OWNER_WORKER_PUMP_STOP_TERMINAL = 4,
    FK_FIXED_OWNER_WORKER_PUMP_STOP_ALREADY_STOPPED = 5,
};

enum fk_fixed_owner_worker_pump_abort_result {
    FK_FIXED_OWNER_WORKER_PUMP_ABORT_INVALID = 0,
    FK_FIXED_OWNER_WORKER_PUMP_ABORT_RETRY_REQUIRED = 1,
    FK_FIXED_OWNER_WORKER_PUMP_ABORTED_AND_STOPPED = 2,
    FK_FIXED_OWNER_WORKER_PUMP_ABORT_WRONG_THREAD = 3,
    FK_FIXED_OWNER_WORKER_PUMP_ABORT_ALREADY_STOPPED = 4,
    FK_FIXED_OWNER_WORKER_PUMP_ABORT_UNRECOVERABLE = 5,
    FK_FIXED_OWNER_WORKER_PUMP_ABORT_NEEDS_COORDINATOR = 6,
};

enum fk_fixed_owner_worker_pump_abort_prepare_result {
    FK_FIXED_OWNER_WORKER_PUMP_ABORT_PREPARE_INVALID = 0,
    FK_FIXED_OWNER_WORKER_PUMP_ABORT_PREPARE_RETRY_REQUIRED = 1,
    FK_FIXED_OWNER_WORKER_PUMP_ABORT_PREPARED_NEEDS_COORDINATOR = 2,
    FK_FIXED_OWNER_WORKER_PUMP_ABORT_PREPARE_WRONG_THREAD = 3,
    FK_FIXED_OWNER_WORKER_PUMP_ABORT_PREPARE_ALREADY_PREPARED = 4,
    FK_FIXED_OWNER_WORKER_PUMP_ABORT_PREPARE_UNRECOVERABLE = 5,
};

enum fk_fixed_owner_worker_pump_abort_finalize_result {
    FK_FIXED_OWNER_WORKER_PUMP_ABORT_FINALIZE_INVALID = 0,
    FK_FIXED_OWNER_WORKER_PUMP_ABORT_FINALIZE_NOT_READY = 1,
    FK_FIXED_OWNER_WORKER_PUMP_ABORT_FINALIZED = 2,
    FK_FIXED_OWNER_WORKER_PUMP_ABORT_FINALIZE_WRONG_THREAD = 3,
    FK_FIXED_OWNER_WORKER_PUMP_ABORT_FINALIZE_ALREADY_STOPPED = 4,
    FK_FIXED_OWNER_WORKER_PUMP_ABORT_FINALIZE_UNRECOVERABLE = 5,
};

struct fk_fixed_owner_worker_pump_stats {
    uint64_t owner_claim_attempts;
    uint64_t owner_claim_successes;
    uint64_t owner_claim_rejections;
    uint64_t owner_thread_rejections;

    uint64_t step_calls;
    uint64_t step_idle;
    uint64_t step_progressed;
    uint64_t step_output_ring_full;
    uint64_t step_data_retry;
    uint64_t step_retire_retry;
    uint64_t step_terminal;
    uint64_t step_stopped;
    uint64_t step_wrong_thread;

    uint64_t dequeue_attempts;
    uint64_t data_dequeued;
    uint64_t retire_dequeued;
    uint64_t dequeue_empty;
    uint64_t invalid_envelopes;
    uint64_t packet_sequence_checks;
    uint64_t packet_sequence_rejections;
    uint64_t last_packet_sequence;

    uint64_t mbuf_claim_attempts;
    uint64_t mbuf_claim_successes;
    uint64_t mbuf_claim_failures;
    uint64_t data_process_calls;
    uint64_t data_ordinary;
    uint64_t data_quic;
    uint64_t data_ignored;
    uint64_t data_admission_rejected;
    uint64_t data_output_backpressure;
    uint64_t data_semantic_drain_required;
    uint64_t data_terminal_results;
    uint64_t source_release_attempts;
    uint64_t source_release_successes;
    uint64_t source_release_failures;
    uint64_t reclaim_attempts;
    uint64_t reclaim_successes;
    uint64_t reclaim_failures;

    uint64_t retire_process_calls;
    uint64_t retire_acked;
    uint64_t retire_retry_required;
    uint64_t retire_output_backpressure;
    uint64_t retire_semantic_drain_required;
    uint64_t retire_terminal_results;
    uint64_t retire_controls_aborted;

    uint64_t orphan_outbox_recoveries;
    uint64_t output_publish_attempts;
    uint64_t output_batches_published_and_acked;
    uint64_t output_ring_full;
    uint64_t output_publish_failures;
    uint64_t completion_publish_attempts;
    uint64_t completions_published;
    uint64_t completions_with_batch;
    uint64_t completions_without_batch;
    uint64_t completion_publish_failures;
    uint64_t data_packets_completed;

    uint64_t terminal_transitions;
    uint64_t normal_stop_attempts;
    uint64_t normal_stop_successes;
    uint64_t normal_stop_rejections;
    uint64_t normal_stop_already_stopped;
    uint64_t abort_calls;
    uint64_t abort_retries;
    uint64_t abort_successes;
    uint64_t abort_unrecoverable;
    uint64_t abort_already_stopped;
    uint64_t abort_needs_coordinator;
    uint64_t abort_receipt_attempts;
    uint64_t abort_receipts_recorded;
    uint64_t abort_receipt_failures;
    uint64_t abort_prepare_calls;
    uint64_t abort_prepare_retries;
    uint64_t abort_prepare_successes;
    uint64_t abort_prepare_already_prepared;
    uint64_t abort_prepare_unrecoverable;
    uint64_t abort_finalize_calls;
    uint64_t abort_finalize_not_ready;
    uint64_t abort_finalize_successes;
    uint64_t abort_finalize_already_stopped;
    uint64_t abort_finalize_unrecoverable;
    uint64_t abort_committed_outboxes_discarded;
    uint64_t abort_completion_values_discarded;
    uint64_t service_memory_bytes;

    uintptr_t pending_reclaim_handle;
    uint64_t pending_packet_sequence;
    uint32_t abi_version;
    uint16_t fixed_owner;
    uint16_t owner_count;
    enum fk_fixed_owner_worker_pump_terminal_reason terminal_reason;
    uint8_t initialized;
    uint8_t owner_claimed;
    uint8_t packet_sequence_initialized;
    uint8_t pending_data;
    uint8_t active_mbuf_claim;
    uint8_t pending_reclaim;
    uint8_t pending_retire;
    uint8_t pending_outbox;
    uint8_t pending_completion;
    uint8_t stopped_normal;
    uint8_t stopped_abort;
    uint8_t abort_prepared;
    uint8_t counter_overflow;
    uint8_t accounting_conserved;
    uint8_t formal_ready;
    uint8_t service_memory_exact;
};

struct fk_fixed_owner_worker_pump;
struct fk_owner_pipeline_abort_coordinator;

void fk_fixed_owner_worker_pump_default_config_init(
    struct fk_fixed_owner_worker_pump_config *config);

bool fk_fixed_owner_worker_pump_config_valid(
    const struct fk_fixed_owner_worker_pump_config *config);

/* Exact placement reservation.  No pump API allocates. */
size_t fk_fixed_owner_worker_pump_storage_bytes(
    const struct fk_fixed_owner_worker_pump_config *config);

struct fk_fixed_owner_worker_pump *
fk_fixed_owner_worker_pump_initialize(
    void *storage,
    size_t storage_bytes,
    const struct fk_fixed_owner_worker_pump_config *config);

/* One-shot owner-thread claim.  The adapter must already have been
 * initialized on this same thread; this call also claims the exact mbuf
 * source. */
bool fk_fixed_owner_worker_pump_claim_owner(
    struct fk_fixed_owner_worker_pump *pump);

/* One bounded owner iteration.  It never dequeues while an outbox,
 * completion, reclaim, DATA retry, or RETIRE retry is pending. */
enum fk_fixed_owner_worker_pump_step_result
fk_fixed_owner_worker_pump_step(
    struct fk_fixed_owner_worker_pump *pump);

/* Normal shutdown requires STOPPED_NORMAL dispatch, this owner's empty input
 * queue, no mbuf/control/reclaim/outbox/completion, and exact source
 * accounting.  It seals the adapter receipt before stopping its output ring.
 */
enum fk_fixed_owner_worker_pump_stop_result
fk_fixed_owner_worker_pump_stop_normal(
    struct fk_fixed_owner_worker_pump *pump);

/* Compatibility wrapper. It can prepare local ownership but never records a
 * global bridge terminal. For multi-owner (and any prepared-but-unfinalized)
 * pipeline it returns NEEDS_COORDINATOR, never false success. */
enum fk_fixed_owner_worker_pump_abort_result
fk_fixed_owner_worker_pump_abort_reclaim_and_stop(
    struct fk_fixed_owner_worker_pump *pump);

/* Phase one is owner-thread-only and failure-atomic. It stops new dequeue,
 * reclaims the exact owned mbuf, discards retire/completion values, aborts a
 * committed adapter outbox without ring space, stops this owner's ring, and
 * publishes immutable local evidence. It never makes the bridge terminal. */
enum fk_fixed_owner_worker_pump_abort_prepare_result
fk_fixed_owner_worker_pump_abort_prepare(
    struct fk_fixed_owner_worker_pump *pump,
    struct fk_fixed_owner_abort_prepared_receipt_v1 *receipt);

bool fk_fixed_owner_worker_pump_get_abort_prepared_receipt(
    const struct fk_fixed_owner_worker_pump *pump,
    struct fk_fixed_owner_abort_prepared_receipt_v1 *receipt);

/* Safe control-thread evidence verifier used by the coordinator. It requires
 * an exact stored receipt and rechecks live source/adapter/ring ownership. */
bool fk_fixed_owner_worker_pump_validate_abort_prepared_receipt(
    const struct fk_fixed_owner_worker_pump *pump,
    const struct fk_fixed_owner_abort_prepared_receipt_v1 *receipt);

/* Phase two is owner-thread-only. Raw receipt fields are never trusted: the
 * coordinator must validate and authorize this exact owner first. */
enum fk_fixed_owner_worker_pump_abort_finalize_result
fk_fixed_owner_worker_pump_abort_finalize(
    struct fk_fixed_owner_worker_pump *pump,
    struct fk_owner_pipeline_abort_coordinator *coordinator,
    const struct fk_owner_pipeline_abort_receipt_v1 *receipt);

/* Live snapshots are owner-thread-only.  Post-stop snapshots are immutable
 * and may be read by the joined control thread. */
bool fk_fixed_owner_worker_pump_get_stats(
    const struct fk_fixed_owner_worker_pump *pump,
    struct fk_fixed_owner_worker_pump_stats *stats);

bool fk_fixed_owner_worker_pump_accounting_conserved(
    const struct fk_fixed_owner_worker_pump *pump);

bool fk_fixed_owner_worker_pump_formal_ready(
    const struct fk_fixed_owner_worker_pump *pump);

/* Requires either successful normal stop or successful abort stop and no
 * pending ownership/value.  Bound modules remain caller-owned. */
bool fk_fixed_owner_worker_pump_destroy_checked(
    struct fk_fixed_owner_worker_pump *pump);

const char *fk_fixed_owner_worker_pump_step_result_name(
    enum fk_fixed_owner_worker_pump_step_result result);

const char *fk_fixed_owner_worker_pump_terminal_reason_name(
    enum fk_fixed_owner_worker_pump_terminal_reason reason);

#ifdef __cplusplus
}
#endif

#endif
