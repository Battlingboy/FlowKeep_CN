#ifndef FLOWKEEP_FK_OWNER_RUNTIME_ADAPTER_H
#define FLOWKEEP_FK_OWNER_RUNTIME_ADAPTER_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "fk_compact_runtime.h"
#include "fk_owner_dispatch.h"
#include "fk_owner_flow_bindings.h"
#include "fk_owner_output_batch_ring.h"
#include "fk_owner_runtime_output_abi.h"
#include "fk_quic_cid_map.h"
#include "fk_quic_owner_cleanup.h"
#include "fk_quic_route_receipt.h"

#ifdef __cplusplus
extern "C" {
#endif

#define FK_OWNER_RUNTIME_ADAPTER_ABI_VERSION 6u
#define FK_OWNER_PACKET_BYTES_SOURCE_ABI_VERSION 1u
#define FK_OWNER_RUNTIME_OUTBOX_ABORT_RECEIPT_ABI_VERSION 1u

/*
 * Trusted ingress boundary.  The resolver must return the immutable,
 * contiguous Ethernet bytes owned by exactly packet_handle; the adapter then
 * invokes the native parser itself.  This prevents a caller from pairing one
 * queued handle with another packet's already-parsed view.
 */
typedef bool (*fk_owner_packet_bytes_resolve_callback)(
    void *context,
    uintptr_t packet_handle,
    const uint8_t **frame,
    size_t *captured_length,
    uint32_t *wire_length);

struct fk_owner_packet_bytes_source {
    uint32_t abi_version;
    uint8_t exact_handle_binding;
    uint8_t immutable_while_owned;
    uint8_t contiguous_frame;
    uint8_t reserved0;
    void *context;
    fk_owner_packet_bytes_resolve_callback resolve;
};

enum fk_owner_runtime_adapter_result {
    FK_OWNER_RUNTIME_ADAPTER_INVALID = 0,
    FK_OWNER_RUNTIME_ADAPTER_ORDINARY_OBSERVED = 1,
    FK_OWNER_RUNTIME_ADAPTER_QUIC_OBSERVED = 2,
    FK_OWNER_RUNTIME_ADAPTER_RETIRE_ACKED = 3,
    FK_OWNER_RUNTIME_ADAPTER_RUNTIME_IGNORED = 4,
    FK_OWNER_RUNTIME_ADAPTER_ADMISSION_REJECTED = 5,
    FK_OWNER_RUNTIME_ADAPTER_RUNTIME_FAILED = 6,
    FK_OWNER_RUNTIME_ADAPTER_OWNER_PROOF_REJECTED = 7,
    FK_OWNER_RUNTIME_ADAPTER_BINDING_FAILED = 8,
    FK_OWNER_RUNTIME_ADAPTER_CID_MARK_FAILED = 9,
    FK_OWNER_RUNTIME_ADAPTER_REBIND_FAILED = 10,
    FK_OWNER_RUNTIME_ADAPTER_RETIRE_FAILED = 11,
    FK_OWNER_RUNTIME_ADAPTER_ROLLBACK_FAILED = 12,
    FK_OWNER_RUNTIME_ADAPTER_ROUTE_PREVALIDATION_REJECTED = 13,
    FK_OWNER_RUNTIME_ADAPTER_TERMINAL_STOPPED = 14,
    /* The caller retains the dequeued DATA/control and must retry only after
     * the committed output batch has been atomically published and ACKed. */
    FK_OWNER_RUNTIME_ADAPTER_OUTPUT_BACKPRESSURE = 15,
    /* Rejected and atomically accounted by the binding directory before any
     * non-atomic adapter/runtime field is read or written. */
    FK_OWNER_RUNTIME_ADAPTER_OWNER_THREAD_REJECTED = 16,
    FK_OWNER_RUNTIME_ADAPTER_RUNTIME_CLAIM_REJECTED = 17,
    FK_OWNER_RUNTIME_ADAPTER_SEALED = 18,
    /* Cleanup made no CID ACK; caller retains the exact control and retries
     * it. Binding/runtime cleanup is generation-tagged and idempotent. */
    FK_OWNER_RUNTIME_ADAPTER_RETIRE_RETRY_REQUIRED = 19,
    /* Optional-state timer releases filled one bounded audit batch before
     * this input was consumed. The owner must drain evidence transitions and
     * retry the exact same DATA/control value. This is semantic maintenance,
     * not output backpressure or a packet drop. */
    FK_OWNER_RUNTIME_ADAPTER_SEMANTIC_DRAIN_REQUIRED = 20,
};

enum fk_owner_runtime_output_publish_result {
    FK_OWNER_RUNTIME_OUTPUT_PUBLISH_INVALID = 0,
    FK_OWNER_RUNTIME_OUTPUT_PUBLISH_EMPTY = 1,
    FK_OWNER_RUNTIME_OUTPUT_PUBLISHED = 2,
    FK_OWNER_RUNTIME_OUTPUT_RING_FULL = 3,
    FK_OWNER_RUNTIME_OUTPUT_RING_STOPPED = 4,
    FK_OWNER_RUNTIME_OUTPUT_PUBLISH_FAILED = 5,
};

enum fk_owner_runtime_outbox_abort_result {
    FK_OWNER_RUNTIME_OUTBOX_ABORT_INVALID = 0,
    FK_OWNER_RUNTIME_OUTBOX_ABORT_EMPTY = 1,
    FK_OWNER_RUNTIME_OUTBOX_ABORT_DISCARDED = 2,
    FK_OWNER_RUNTIME_OUTBOX_ABORT_WRONG_THREAD = 3,
    FK_OWNER_RUNTIME_OUTBOX_ABORT_SEALED = 4,
    FK_OWNER_RUNTIME_OUTBOX_ABORT_COUNTER_OVERFLOW = 5,
};

enum fk_owner_runtime_outbox_presence_mask {
    FK_OWNER_RUNTIME_OUTBOX_HAS_FLOW_OPEN = 1u << 0u,
    FK_OWNER_RUNTIME_OUTBOX_HAS_DETECTION = 1u << 1u,
    FK_OWNER_RUNTIME_OUTBOX_HAS_ACTION = 1u << 2u,
};

/* Exact value-only transaction discarded during non-formal abort.  No ring
 * space is required and no packet/mbuf ownership is represented here. */
struct fk_owner_runtime_outbox_abort_receipt_v1 {
    uint32_t abi_version;
    uint16_t fixed_owner;
    uint8_t output_presence_mask;
    uint8_t reserved0;
    uint64_t transaction_epoch;
    uint64_t packet_sequence;
    uint64_t receipt_ordinal;
};

struct fk_owner_runtime_adapter_stats {
    uint64_t data_calls;
    uint64_t ordinary_calls;
    uint64_t logical_quic_calls;
    uint64_t retire_calls;

    uint64_t ordinary_observed;
    uint64_t logical_quic_observed;
    uint64_t retire_acked;
    uint64_t runtime_ignored;
    uint64_t admission_rejected;
    uint64_t runtime_failures;

    uint64_t owner_proof_validations;
    uint64_t owner_proof_rejections;
    uint64_t ordinary_route_proof_rejections;
    uint64_t quic_shape_rejections;
    uint64_t ordinary_canonical_proof_calls;

    /* Derived at snapshot time from the binding directory's atomic receipt;
     * a wrong thread never writes this non-atomic adapter object. */
    uint64_t owner_thread_rejections;
    uint64_t terminal_stop_data_calls;
    uint64_t terminal_stop_retire_calls;
    uint64_t output_backpressure_data_calls;
    uint64_t output_backpressure_retire_calls;
    uint64_t runtime_scope_begin_rejections;
    uint64_t runtime_scope_data_rejections;
    uint64_t runtime_scope_retire_rejections;
    uint64_t runtime_scope_end_failures;
    uint64_t semantic_data_step_calls;
    uint64_t semantic_data_step_completions;
    uint64_t semantic_data_drain_required;
    uint64_t semantic_data_step_failures;
    uint64_t semantic_retire_step_calls;
    uint64_t semantic_retire_step_completions;
    uint64_t semantic_retire_drain_required;
    uint64_t semantic_retire_step_failures;
    uint64_t packet_bytes_resolution_calls;
    uint64_t packet_bytes_resolution_successes;
    uint64_t packet_bytes_resolution_rejections;

    uint64_t quic_route_prevalidation_calls;
    uint64_t quic_route_prevalidation_active;
    uint64_t quic_route_prevalidation_retired_pending;
    uint64_t quic_route_prevalidation_rejections;
    uint64_t quic_route_retired_cutoff_rejections;
    uint64_t quic_route_receipt_validations;
    uint64_t quic_route_receipt_verified;
    uint64_t quic_route_receipt_rejections;

    uint64_t binding_lookup_found;
    uint64_t binding_lookup_not_found;
    uint64_t initial_distinct_admissions;
    uint64_t bindings_created;
    uint64_t binding_creation_receipts;
    uint64_t binding_creation_commits;
    uint64_t binding_creation_commit_failures;
    uint64_t binding_failures;
    uint64_t initial_bind_failures;
    uint64_t binding_lookup_failures;
    uint64_t direction_resolution_failures;
    uint64_t cid_binding_marks;
    uint64_t cid_binding_mark_failures;
    uint64_t live_bound_packets;
    uint64_t stale_bound_packets;
    uint64_t successful_rebinds;
    uint64_t rebind_failures;

    uint64_t rollback_attempts;
    uint64_t rollback_runtime_releases;
    uint64_t rollback_binding_aborts;
    uint64_t rollback_output_discard_calls;
    uint64_t rollback_flow_open_discards;
    uint64_t rollback_detection_discards;
    uint64_t rollback_action_discards;
    uint64_t rollback_output_discard_failures;
    uint64_t rollback_failures;

    uint64_t output_transactions_staged;
    uint64_t output_transactions_identity_committed;
    uint64_t output_transactions_acked;
    uint64_t output_transactions_aborted;
    uint64_t output_transactions_committed_discarded;
    uint64_t output_committed_discard_calls;
    uint64_t output_committed_discard_empty;
    uint64_t output_committed_discard_successes;
    uint64_t output_publish_calls;
    uint64_t output_ring_commits;
    uint64_t output_ring_full;
    uint64_t output_ring_stopped;
    uint64_t output_ring_failures;
    uint64_t output_ring_commit_ack_failures;
    uint64_t post_seal_rejections;
    uint64_t flow_open_outputs_taken;
    uint64_t flow_open_outputs_acked;
    uint64_t flow_open_outputs_aborted;
    uint64_t flow_open_outputs_committed_discarded;
    uint64_t detection_outputs_taken;
    uint64_t detection_outputs_acked;
    uint64_t detection_outputs_aborted;
    uint64_t detection_outputs_committed_discarded;
    uint64_t action_outputs_taken;
    uint64_t action_outputs_acked;
    uint64_t action_outputs_aborted;
    uint64_t action_outputs_committed_discarded;

    uint64_t retirement_peek_ready;
    uint64_t retirement_peek_failures;
    uint64_t retirement_control_mismatches;
    uint64_t retirement_context_failures;
    uint64_t retirement_ack_failures;
    uint64_t retirement_retry_required;

    uint64_t invalid_calls;
    uint64_t terminal_failures;
    uint32_t abi_version;
    uint16_t fixed_owner;
    uint8_t initialized;
    uint8_t formal_ready;
    uint8_t nonformal_abort_used;
    uint8_t reserved0;
};

/*
 * One zero-initialized adapter belongs to one fixed-owner lcore. initialize()
 * is one-shot, claims that owner in the binding directory, and must therefore
 * run on the same thread that later invokes process/peek/ack. The adapter
 * performs no allocation. It never owns an mbuf, but OUTPUT_BACKPRESSURE does
 * not consume the observation: the caller must retain and retry that exact
 * dequeued DATA handle after publishing the committed outbox.
 */
struct fk_owner_runtime_adapter {
    struct fk_compact_runtime *runtime;
    struct fk_owner_dispatch *dispatch;
    struct fk_owner_flow_bindings *bindings;
    struct fk_quic_cid_map *cid_map;
    struct fk_quic_route_receipt_state *route_receipts;
    struct fk_owner_output_batch_ring *output_ring;
    struct fk_owner_packet_bytes_source packet_bytes_source;
    struct fk_quic_owner_cleanup_adapter cleanup;
    struct fk_owner_runtime_output_batch_v2 output;
    struct fk_owner_runtime_adapter_stats stats;
    /* Written once by the owner before exit, published with release/acquire,
     * and never modified again.  This makes post-join control-thread reads
     * data-race free without making every hot counter atomic. */
    struct fk_owner_runtime_adapter_stats sealed_stats;
    uint64_t next_output_transaction_epoch;
    uint64_t owner_thread_violations_baseline;
    uint16_t fixed_owner;
    uint16_t owner_count;
    uint8_t initialized;
    uint8_t terminal_failure;
    uint8_t receipt_sealed;
    uint8_t sealed_accounting_conserved;
    uint8_t sealed_formal_ready;
    uint8_t nonformal_abort_used;
    /* Atomic-by-builtin diagnostic written only by calls arriving after the
     * immutable receipt publication. It is outside sealed_stats so a late
     * caller can never preserve a previously true formal result. */
    uint64_t post_seal_rejections;
};

bool fk_owner_runtime_adapter_initialize(
    struct fk_owner_runtime_adapter *adapter,
    struct fk_compact_runtime *runtime,
    struct fk_owner_dispatch *dispatch,
    struct fk_owner_flow_bindings *bindings,
    struct fk_quic_cid_map *cid_map,
    struct fk_quic_route_receipt_state *route_receipts,
    struct fk_owner_output_batch_ring *output_ring,
    const struct fk_owner_packet_bytes_source *packet_bytes_source,
    uint16_t fixed_owner);

/* The adapter resolves and parses the exact handle through its frozen byte
 * source; no independently supplied packet view crosses this boundary.
 * OUTPUT_BACKPRESSURE, SEMANTIC_DRAIN_REQUIRED, OWNER_THREAD_REJECTED,
 * RUNTIME_CLAIM_REJECTED, and SEALED leave the dequeued packet owned by the
 * caller. SEMANTIC_DRAIN_REQUIRED may advance only optional timer state and
 * requires the owner to drain its transition trace before exact retry. Every
 * other return consumes the observation. */
enum fk_owner_runtime_adapter_result fk_owner_runtime_adapter_process_data(
    struct fk_owner_runtime_adapter *adapter,
    const struct fk_owner_packet *packet);

/* RETIRE_RETRY_REQUIRED and SEMANTIC_DRAIN_REQUIRED leave the exact control
 * owned by the caller. The latter advances only optional timer state and must
 * be retried after transition drain; cleanup/ACK has not begun. */
enum fk_owner_runtime_adapter_result fk_owner_runtime_adapter_process_retire(
    struct fk_owner_runtime_adapter *adapter,
    const struct fk_owner_quic_retire_control *control);

/*
 * Atomically transfers the entire committed transaction into the bound
 * owner output ring.  The adapter clears its outbox only after validating
 * the ring's opaque commit receipt; callers can no longer self-certify an
 * unpublished batch with a bare ACK.
 */
enum fk_owner_runtime_output_publish_result
fk_owner_runtime_adapter_publish_output_batch_v2(
    struct fk_owner_runtime_adapter *adapter);

/* Owner-thread-only, failure-atomic abort of an IDENTITY_COMMITTED value-only
 * outbox.  It never touches the output ring and therefore cannot wait for
 * ring capacity.  EMPTY is idempotent and returns a zero receipt. */
enum fk_owner_runtime_outbox_abort_result
fk_owner_runtime_adapter_abort_committed_outbox(
    struct fk_owner_runtime_adapter *adapter,
    struct fk_owner_runtime_outbox_abort_receipt_v1 *receipt);

/* Called exactly once by the fixed-owner thread after all inputs and output
 * batches are drained.  It publishes an immutable receipt for post-join
 * control-thread reads; live cross-thread reads are rejected. */
bool fk_owner_runtime_adapter_seal_receipt(
    struct fk_owner_runtime_adapter *adapter);

bool fk_owner_runtime_adapter_get_stats(
    const struct fk_owner_runtime_adapter *adapter,
    struct fk_owner_runtime_adapter_stats *stats);

bool fk_owner_runtime_adapter_accounting_conserved(
    const struct fk_owner_runtime_adapter *adapter);

/* Strict clean-run gate; runtime, dispatch, CID, and binding terminal gates
 * remain separate and must also pass. */
bool fk_owner_runtime_adapter_formal_ready(
    const struct fk_owner_runtime_adapter *adapter);

const char *fk_owner_runtime_adapter_result_name(
    enum fk_owner_runtime_adapter_result result);

#ifdef __cplusplus
}
#endif

#endif
