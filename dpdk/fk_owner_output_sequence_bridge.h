#ifndef FLOWKEEP_FK_OWNER_OUTPUT_SEQUENCE_BRIDGE_H
#define FLOWKEEP_FK_OWNER_OUTPUT_SEQUENCE_BRIDGE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "fk_checkpoint_reorder.h"
#include "fk_compact_runtime.h"
#include "fk_owner_output_batch_ring.h"
#include "fk_trace_message_barrier.h"

#ifdef __cplusplus
extern "C" {
#endif

#define FK_OWNER_OUTPUT_SEQUENCE_BRIDGE_ABI_VERSION 4u
#define FK_OWNER_OUTPUT_SEQUENCE_BRIDGE_SKIP_OWNER UINT16_MAX

/*
 * One completion exists for every ordered input packet, including packets
 * which generated no downstream output.  OUTPUT_COMMIT_ACKED is a promise:
 * the fixed-owner pump may publish it only after the complete output batch
 * was committed to that owner's ring and its authenticated commit receipt
 * was ACKed.  The bridge's acquire-load then happens after the ring commit.
 */
enum fk_owner_packet_completion_kind {
    FK_OWNER_PACKET_COMPLETION_OWNER_NO_OUTPUT = 1,
    FK_OWNER_PACKET_COMPLETION_OUTPUT_COMMIT_ACKED = 2,
    FK_OWNER_PACKET_COMPLETION_ORDERED_SKIP = 3,
};

struct fk_owner_packet_completion_v1 {
    uint64_t packet_sequence;
    uint16_t fixed_owner;
    uint8_t completion_kind;
    /* Exact FLOW_OPEN/CHECKPOINT mask.  It is zero for no-output, skip, and
     * a valid action-only output batch. */
    uint8_t expected_association_mask;
    uint8_t reserved[4];
};

enum fk_owner_packet_completion_publish_result {
    FK_OWNER_PACKET_COMPLETION_PUBLISH_INVALID = 0,
    FK_OWNER_PACKET_COMPLETION_PUBLISHED = 1,
    FK_OWNER_PACKET_COMPLETION_DUPLICATE = 2,
    FK_OWNER_PACKET_COMPLETION_OUT_OF_RANGE = 3,
    FK_OWNER_PACKET_COMPLETION_STOPPED = 4,
    FK_OWNER_PACKET_COMPLETION_INTERNAL_FAILURE = 5,
    FK_OWNER_PACKET_COMPLETION_UNRESERVED = 6,
    FK_OWNER_PACKET_COMPLETION_TERMINAL = 7,
};

enum fk_owner_packet_reservation_result {
    FK_OWNER_PACKET_RESERVATION_INVALID = 0,
    FK_OWNER_PACKET_RESERVED = 1,
    FK_OWNER_PACKET_ALREADY_RESERVED = 2,
    FK_OWNER_PACKET_RESERVATION_FULL = 3,
    FK_OWNER_PACKET_RESERVATION_OUT_OF_ORDER = 4,
    FK_OWNER_PACKET_RESERVATION_OUT_OF_RANGE = 5,
    FK_OWNER_PACKET_RESERVATION_STOPPED = 6,
    FK_OWNER_PACKET_RESERVATION_INTERNAL_FAILURE = 7,
    FK_OWNER_PACKET_RESERVATION_TERMINAL = 8,
};

enum fk_owner_reserved_route_kind {
    FK_OWNER_RESERVED_ROUTE_DATA = 1,
    FK_OWNER_RESERVED_ROUTE_SKIP = 2,
};

struct fk_owner_reserved_route_v1 {
    uint64_t packet_sequence;
    uint16_t expected_owner;
    uint8_t route_kind;
    uint8_t reserved[5];
};

enum fk_owner_reserved_route_bind_result {
    FK_OWNER_RESERVED_ROUTE_BIND_INVALID = 0,
    FK_OWNER_RESERVED_ROUTE_BOUND = 1,
    FK_OWNER_RESERVED_ROUTE_ALREADY_BOUND = 2,
    FK_OWNER_RESERVED_ROUTE_UNRESERVED = 3,
    FK_OWNER_RESERVED_ROUTE_MISMATCH_TERMINAL = 4,
    FK_OWNER_RESERVED_ROUTE_STOPPED = 5,
    FK_OWNER_RESERVED_ROUTE_TERMINAL = 6,
};

enum fk_owner_reserved_abort_reason {
    FK_OWNER_RESERVED_ABORT_ROUTER_TERMINAL = 1,
    FK_OWNER_RESERVED_ABORT_DISPATCH_TERMINAL = 2,
    FK_OWNER_RESERVED_ABORT_OWNER_TERMINAL = 3,
    FK_OWNER_RESERVED_ABORT_SHUTDOWN_TERMINAL = 4,
};

struct fk_owner_reserved_abort_receipt_v1 {
    uint64_t packet_sequence;
    uint64_t receipt_ordinal;
    uint16_t expected_owner;
    uint8_t route_kind;
    uint8_t abort_reason;
    uint8_t slot_was_bound;
    uint8_t reserved[3];
};

enum fk_owner_reserved_abort_result {
    FK_OWNER_RESERVED_ABORT_INVALID = 0,
    FK_OWNER_RESERVED_ABORT_RECORDED = 1,
    FK_OWNER_RESERVED_ABORT_ALREADY_RECORDED = 2,
    FK_OWNER_RESERVED_ABORT_UNRESERVED = 3,
};

enum fk_owner_abort_first_active_result {
    FK_OWNER_ABORT_FIRST_ACTIVE_INVALID = 0,
    FK_OWNER_ABORT_FIRST_ACTIVE_RECORDED = 1,
    FK_OWNER_ABORT_FIRST_ACTIVE_ALREADY_RECORDED = 2,
    FK_OWNER_ABORT_FIRST_ACTIVE_NO_ACTIVE = 3,
    FK_OWNER_ABORT_FIRST_ACTIVE_NOT_STOPPED = 4,
    FK_OWNER_ABORT_FIRST_ACTIVE_INTEGRITY_FAILURE = 5,
    FK_OWNER_ABORT_FIRST_ACTIVE_WRONG_CONSUMER = 6,
};

enum fk_owner_active_reservation_state {
    FK_OWNER_ACTIVE_RESERVATION_INVALID = 0,
    FK_OWNER_ACTIVE_RESERVATION_INACTIVE = 1,
    FK_OWNER_ACTIVE_RESERVATION_UNBOUND = 2,
    FK_OWNER_ACTIVE_RESERVATION_BOUND = 3,
    FK_OWNER_ACTIVE_RESERVATION_COMPLETION_PUBLISHED = 4,
    FK_OWNER_ACTIVE_RESERVATION_INTEGRITY_FAILURE = 5,
};

struct fk_owner_active_reservation_v1 {
    uint64_t packet_sequence;
    uint16_t expected_owner;
    uint8_t route_kind;
    uint8_t state;
    uint8_t reserved[4];
};

struct fk_owner_output_sequence_bridge_config {
    /* Maximum packet count in this epoch, not a storage dimension. */
    uint64_t expected_packets;
    uint32_t checkpoint_payload_capacity;
    /* Bounded number of dispatched packets awaiting owner completion. */
    uint32_t completion_window_capacity;
    uint16_t owner_count;
    uint16_t reserved0;
    /* Zero preserves the finite-barrier compatibility path. */
    uint8_t readiness_mode;
    uint8_t reserved1[7];
    /* Global packet sequence of the first packet in this epoch.  A zero
     * value preserves the V2 source contract. */
    uint64_t sequence_base;
};

enum fk_owner_output_sequence_bridge_close_result {
    FK_OWNER_OUTPUT_SEQUENCE_BRIDGE_CLOSE_INVALID = 0,
    FK_OWNER_OUTPUT_SEQUENCE_BRIDGE_CLOSED = 1,
    FK_OWNER_OUTPUT_SEQUENCE_BRIDGE_ALREADY_CLOSED = 2,
    FK_OWNER_OUTPUT_SEQUENCE_BRIDGE_CLOSE_PREFIX_MISMATCH = 3,
    FK_OWNER_OUTPUT_SEQUENCE_BRIDGE_CLOSE_UNBOUND_ROUTE = 4,
    FK_OWNER_OUTPUT_SEQUENCE_BRIDGE_CLOSE_TERMINAL = 5,
    FK_OWNER_OUTPUT_SEQUENCE_BRIDGE_CLOSE_EMPTY_EPOCH = 6,
};

enum fk_owner_output_sequence_bridge_readiness_mode {
    FK_OWNER_OUTPUT_SEQUENCE_BRIDGE_READINESS_FINITE_BARRIER = 0,
    FK_OWNER_OUTPUT_SEQUENCE_BRIDGE_READINESS_STREAMING_STRICT_PREFIX = 1,
};

enum fk_owner_output_sequence_bridge_poll_result {
    FK_OWNER_OUTPUT_SEQUENCE_BRIDGE_POLL_INVALID = 0,
    FK_OWNER_OUTPUT_SEQUENCE_BRIDGE_POLL_IDLE = 1,
    FK_OWNER_OUTPUT_SEQUENCE_BRIDGE_POLL_PROGRESSED = 2,
    FK_OWNER_OUTPUT_SEQUENCE_BRIDGE_POLL_BACKPRESSURED = 3,
    FK_OWNER_OUTPUT_SEQUENCE_BRIDGE_POLL_DRAINED = 4,
    FK_OWNER_OUTPUT_SEQUENCE_BRIDGE_POLL_TERMINAL = 5,
    FK_OWNER_OUTPUT_SEQUENCE_BRIDGE_POLL_SEALED = 6,
};

struct fk_owner_output_sequence_bridge_stats {
    /* Formal packet count.  Before close this is the configured capacity. */
    uint64_t expected_packets;
    uint64_t configured_packet_capacity;
    uint64_t sequence_base;
    uint64_t packet_sequence_exclusive;
    uint64_t next_packet_sequence;
    uint64_t next_reservation_sequence;
    uint64_t ready_prefix_packets;
    uint64_t ready_boundary_reads;
    uint64_t ready_boundary_counter_overflows;
    uint64_t finite_barrier_packets_completed;
    uint64_t streaming_prefix_packets_advanced;
    uint64_t reservation_attempts;
    uint64_t reservations;
    uint64_t idempotent_reservations;
    uint64_t reservation_full_backpressure;
    uint64_t out_of_order_reservations;
    uint64_t out_of_range_reservations;
    uint64_t stopped_reservations;
    uint64_t terminal_reservations;
    uint64_t reservation_thread_claims;
    uint64_t reservation_thread_rejections;
    uint64_t reservation_internal_failures;
    uint64_t reservation_stop_attempts;
    uint64_t reservation_stop_transitions;
    uint64_t epoch_close_attempts;
    uint64_t epoch_close_transitions;
    uint64_t epoch_close_prefix_mismatches;
    uint64_t epoch_close_unbound_routes;
    uint64_t epoch_close_empty_rejections;
    uint64_t active_reservations;
    uint64_t peak_active_reservations;
    uint64_t route_bind_attempts;
    uint64_t routes_bound;
    uint64_t idempotent_route_bindings;
    uint64_t unreserved_route_bindings;
    uint64_t mismatched_route_bindings;
    uint64_t terminal_route_bindings;
    uint64_t terminal_publications;
    uint64_t abort_attempts;
    uint64_t abort_receipts;
    uint64_t abort_first_active_attempts;
    uint64_t abort_first_active_scanned_slots;
    uint64_t abort_first_active_no_active;
    uint64_t abort_first_active_integrity_failures;
    uint64_t consumer_thread_claims;
    uint64_t consumer_thread_rejections;
    uint64_t abort_cleanup_attempts;
    uint64_t abort_cleanup_successes;
    uint64_t abort_cleanup_counter_overflows;
    uint64_t aborted_reservations_cleaned;
    uint64_t aborted_ring_batches_drained;
    uint64_t aborted_pending_batches_cleaned;
    uint64_t aborted_reorder_envelopes_drained;
    uint64_t aborted_reorder_checkpoint_payloads_released;
    uint64_t aborted_pending_payloads_released;
    uint64_t aborted_orphan_payloads_released;
    uint64_t reorder_envelopes_remaining;
    uint64_t owner_ring_batches_remaining;
    uint64_t publication_attempts;
    uint64_t published_completions;
    uint64_t published_owner_no_output;
    uint64_t published_output_batches;
    uint64_t published_ordered_skips;
    uint64_t invalid_publications;
    uint64_t duplicate_publications;
    uint64_t out_of_range_publications;
    uint64_t stopped_publications;
    uint64_t unreserved_publications;
    uint64_t completion_stop_attempts;
    uint64_t completion_stop_transitions;
    uint64_t poll_calls;
    uint64_t invalid_poll_calls;
    uint64_t idle_polls;
    uint64_t backpressured_polls;
    uint64_t completions_consumed;
    uint64_t completions_without_batch;
    uint64_t batches_dequeued;
    uint64_t batches_completed;
    uint64_t action_records_consumed;
    uint64_t expected_flow_open_messages;
    uint64_t expected_checkpoint_messages;
    uint64_t flow_open_messages_pushed;
    uint64_t checkpoint_messages_pushed;
    uint64_t atomic_reorder_push_attempts;
    uint64_t atomic_reorder_pushes;
    uint64_t atomic_reorder_push_failures;
    uint64_t reorder_capacity_backpressure;
    uint64_t ring_empty_after_completion;
    uint64_t ring_take_failures;
    uint64_t missing_completions_after_stop;
    uint64_t owner_mismatches;
    uint64_t packet_sequence_mismatches;
    uint64_t association_mask_mismatches;
    uint64_t invalid_output_batches;
    uint64_t flow_identity_failures;
    uint64_t barrier_ingest_failures;
    uint64_t barrier_completion_failures;
    uint64_t payload_allocations;
    uint64_t payload_releases;
    uint64_t payload_exhaustions;
    uint64_t payload_invalid_releases;
    uint64_t payloads_in_use;
    uint64_t peak_payloads_in_use;
    uint64_t seal_attempts;
    uint64_t seal_successes;
    uint64_t seal_rejections;
    uint64_t service_memory_bytes;
    uint64_t service_metadata_bytes;
    uint64_t service_completion_bytes;
    uint64_t service_payload_bytes;
    uint32_t checkpoint_payload_capacity;
    uint32_t completion_window_capacity;
    uint16_t owner_count;
    uint16_t abi_version;
    uint8_t readiness_mode;
    bool completions_stopped;
    bool reservations_stopped;
    bool epoch_endpoint_frozen;
    bool partial_epoch;
    bool pending_batch;
    bool publication_accounting_conserved;
    bool reservation_accounting_conserved;
    bool readiness_accounting_conserved;
    bool completion_accounting_conserved;
    bool payload_accounting_conserved;
    bool terminal_failure;
    bool abort_receipt_present;
    bool abort_no_active;
    bool abort_cleanup_done;
    bool sealed;
    bool formal_ready;
};

struct fk_owner_output_sequence_bridge;

/* Exact O(completion_window_capacity) caller-owned placement reservation;
 * no bridge API allocates. */
size_t fk_owner_output_sequence_bridge_storage_bytes(
    const struct fk_owner_output_sequence_bridge_config *config);

/*
 * owner_rings[index] must be the accepting ring whose fixed_owner is index.
 * FINITE_BARRIER requires a pristine whole-trace barrier and a finite-indexed
 * reorder. STREAMING_STRICT_PREFIX requires barrier==NULL and an O(1)
 * monotonic-V2 reorder. expected_packets is the maximum packet count for this
 * finite epoch, sequence_base is its global first packet, and neither is a
 * storage dimension. stop_reservations() freezes a full endpoint;
 * close_epoch() can freeze an exact partial endpoint in streaming mode.
 * True unbounded operation still requires the cross-module epoch handoff
 * protocol documented in OWNER_EPOCH_ROTATION_AUDIT.md.
 */
struct fk_owner_output_sequence_bridge *
fk_owner_output_sequence_bridge_init(
    void *storage,
    size_t storage_bytes,
    const struct fk_owner_output_sequence_bridge_config *config,
    struct fk_owner_output_batch_ring *const *owner_rings,
    struct fk_trace_message_barrier *barrier,
    struct fk_checkpoint_reorder *reorder,
    char *error,
    size_t error_capacity);

/*
 * Single fixed identity/dispatch thread reserves exactly the next sequence
 * before handing the packet to an owner.  FULL returns without reserving and
 * requires that thread to retain the exact packet/mbuf and retry.  Repeating
 * the most recently reserved sequence is idempotent.
 */
enum fk_owner_packet_reservation_result
fk_owner_output_sequence_bridge_reserve_next(
    struct fk_owner_output_sequence_bridge *bridge,
    uint64_t packet_sequence);

/*
 * Fail-closed route binding between reservation and dispatch.  DATA binds an
 * exact fixed owner; SKIP binds UINT16_MAX.  Retrying the identical binding
 * is idempotent.  Any attempted owner/kind change is a sticky terminal fault.
 */
enum fk_owner_reserved_route_bind_result
fk_owner_output_sequence_bridge_bind_reserved_route(
    struct fk_owner_output_sequence_bridge *bridge,
    const struct fk_owner_reserved_route_v1 *route);

/* Records the first terminal loss of a reserved packet as an immutable
 * receipt.  It never converts an aborted packet into a normal completion. */
enum fk_owner_reserved_abort_result
fk_owner_output_sequence_bridge_abort_reserved(
    struct fk_owner_output_sequence_bridge *bridge,
    uint64_t packet_sequence,
    uint8_t abort_reason);

/* Cold O(completion_window_capacity) coordinator path. Legal only after both
 * reservation and completion admissions are stopped. It records the minimum
 * active global sequence, or freezes an explicit non-formal NO_ACTIVE abort
 * state. It never guesses from a caller-supplied sequence candidate. */
enum fk_owner_abort_first_active_result
fk_owner_output_sequence_bridge_abort_first_active(
    struct fk_owner_output_sequence_bridge *bridge,
    uint8_t abort_reason);

/* One-shot consumer ownership used by poll(), checkpoint-payload take, and
 * cold abort cleanup. A coordinator must call this before any other abort
 * mutation; a different thread is rejected without transferring ownership. */
bool fk_owner_output_sequence_bridge_claim_abort_consumer_thread(
    struct fk_owner_output_sequence_bridge *bridge);

/* Read-only exact query after reservation admission is stopped. It never
 * infers activity from aggregate counts. */
enum fk_owner_active_reservation_state
fk_owner_output_sequence_bridge_query_active_reservation(
    const struct fk_owner_output_sequence_bridge *bridge,
    uint64_t packet_sequence,
    struct fk_owner_active_reservation_v1 *reservation);

bool fk_owner_output_sequence_bridge_get_abort_receipt(
    const struct fk_owner_output_sequence_bridge *bridge,
    struct fk_owner_reserved_abort_receipt_v1 *receipt);

/* Explicit non-formal terminal ownership cleanup.  Legal only after both
 * reservations and completions are stopped and every owner ring is stopped. */
bool fk_owner_output_sequence_bridge_cleanup_aborted(
    struct fk_owner_output_sequence_bridge *bridge);

/* Stop reservation only after the identity input source is closed. */
bool fk_owner_output_sequence_bridge_stop_reservations(
    struct fk_owner_output_sequence_bridge *bridge);

/*
 * Normal finite-epoch close.  The single reservation producer calls this
 * after its input side is closed.  packet_sequence_exclusive is global and
 * must equal the exact non-empty reserved prefix; every reservation must
 * already have an immutable route.  There is deliberately no empty-epoch
 * formal ABI. The endpoint freezes exactly once. This is the only
 * normal path that can create a formally sealable partial epoch.
 */
enum fk_owner_output_sequence_bridge_close_result
fk_owner_output_sequence_bridge_close_epoch(
    struct fk_owner_output_sequence_bridge *bridge,
    uint64_t packet_sequence_exclusive);

/* MP-safe, bounded, allocation-free owner-side publication.  The sequence
 * must already hold a live reservation credit. */
enum fk_owner_packet_completion_publish_result
fk_owner_output_sequence_bridge_publish_completion_after_commit_ack(
    struct fk_owner_output_sequence_bridge *bridge,
    const struct fk_owner_packet_completion_v1 *completion);

/* Idempotently stops new publications after all fixed-owner pumps join. */
bool fk_owner_output_sequence_bridge_stop_completions(
    struct fk_owner_output_sequence_bridge *bridge);

/*
 * Single-consumer operation.  It consumes only next_packet_sequence and, for
 * OUTPUT_COMMIT_ACKED, dequeues the exact specified owner's ring head.
 * physical_now_ns becomes association_enqueue_timestamp_ns; semantic and
 * physical-ingress timestamps remain those frozen in the output batch.
 */
enum fk_owner_output_sequence_bridge_poll_result
fk_owner_output_sequence_bridge_poll(
    struct fk_owner_output_sequence_bridge *bridge,
    uint64_t physical_now_ns);

/* Single-consumer readiness receipt. ready_prefix_packets is the global
 * packet-sequence exclusive boundary (equal to sequence_base before the first
 * completion), and input_sequence_exclusive is exactly twice that global
 * boundary for reorder_pop_sequence_ready_v3(). */
bool fk_owner_output_sequence_bridge_ready_boundary(
    const struct fk_owner_output_sequence_bridge *bridge,
    uint64_t *ready_prefix_packets,
    uint64_t *input_sequence_exclusive);

/* Complete checkpoint payload retained across the exact-order bridge.  The
 * action belongs to the same immutable owner transaction as detection. */
struct fk_owner_checkpoint_payload_v1 {
    struct fk_compact_detection_request_v2 detection;
    struct fk_compact_action_record action;
    uint8_t has_action;
    uint8_t reserved[7];
};

/* Copies and releases one complete payload slot named by a popped checkpoint
 * envelope.  It is single-consumer and succeeds exactly once per slot. */
bool fk_owner_output_sequence_bridge_take_checkpoint_payload_v1(
    struct fk_owner_output_sequence_bridge *bridge,
    uint32_t payload_slot,
    struct fk_owner_checkpoint_payload_v1 *payload);

/* Backward-compatible detector-only view.  The complete slot is still released
 * exactly once, including any attached action record. */
bool fk_owner_output_sequence_bridge_take_checkpoint_payload(
    struct fk_owner_output_sequence_bridge *bridge,
    uint32_t payload_slot,
    struct fk_compact_detection_request_v2 *request);

bool fk_owner_output_sequence_bridge_get_stats(
    const struct fk_owner_output_sequence_bridge *bridge,
    struct fk_owner_output_sequence_bridge_stats *stats);

/* Requires stopped publication, all completions consumed, every owner ring
 * stopped/empty/formal, empty reorder and payload pool, and a complete exact
 * barrier.  Any atomic reorder batch failure is a formal failure. */
bool fk_owner_output_sequence_bridge_seal(
    struct fk_owner_output_sequence_bridge *bridge);

/* Placement destruction is legal only after a formal seal or explicit
 * terminal abort cleanup, with no live publisher/reserver, payload, ring,
 * reorder, or completion ownership.  Failure leaves the object live. */
bool fk_owner_output_sequence_bridge_destroy_checked(
    struct fk_owner_output_sequence_bridge *bridge);

#ifdef __cplusplus
}
#endif

#endif
