#ifndef FLOWKEEP_FK_OWNER_DISPATCH_H
#define FLOWKEEP_FK_OWNER_DISPATCH_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "fk_native_parser.h"
#include "fk_quic_route_receipt_abi.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * The CID directory, not this dispatcher, is responsible for proving that a
 * QUIC packet belongs to a logical connection.  Once it has done so, the
 * opaque stable token below is sufficient to choose the same state owner
 * after connection migration or NAT rebinding.  Raw, unassociated CIDs must
 * never be labelled FK_OWNER_IDENTITY_QUIC_LOGICAL.
 */
enum fk_owner_identity_kind {
    FK_OWNER_IDENTITY_FLOW_KEY = 1,
    FK_OWNER_IDENTITY_QUIC_LOGICAL = 2,
    /* Used only to propose the immutable owner when the CID directory creates
     * a logical connection.  Later packets use the directory's fixed_owner;
     * they must not re-hash a different CID or the generated logical id. */
    FK_OWNER_IDENTITY_QUIC_INITIAL_CID = 3,
};

#define FK_OWNER_IDENTITY_MAX_BYTES 40u
#define FK_OWNER_DISPATCH_KEY_BYTES 16u
#define FK_OWNER_FLOW_KEY_IDENTITY_BYTES 38u

struct fk_owner_identity {
    uint8_t kind;
    uint8_t length;
    uint8_t bytes[FK_OWNER_IDENTITY_MAX_BYTES];
};

struct fk_owner_dispatch_config {
    uint16_t worker_count;
    uint32_t queue_capacity_per_owner;
    uint8_t owner_hash_key[FK_OWNER_DISPATCH_KEY_BYTES];
    bool owner_hash_key_precommitted;
};

/*
 * DPDK-independent handoff descriptor.  packet_handle is intended to carry
 * an rte_mbuf pointer as an integer, but the module never dereferences it.
 * Ownership transfers to the destination queue only on FORWARDED.
 */
struct fk_owner_packet {
    uintptr_t packet_handle;
    uint64_t logical_connection_id;
    uint64_t packet_sequence;
    uint64_t physical_ingress_timestamp_ns;
    uint64_t semantic_timestamp_ns;
    uint32_t captured_length;
    uint32_t wire_length;
    uint16_t ingress_worker;
    uint16_t owner_worker;
    uint8_t identity_kind;
    /* QUIC endpoint direction from the CID directory.  Owner-local binding
     * translates it into the first presentation tuple's canonical axis. */
    uint8_t feature_direction;
    uint8_t feature_direction_known;
    uint8_t reserved[5];
    /* All-zero for FLOW_KEY.  QUIC_LOGICAL carries a packet-specific 128-bit
     * authenticated route receipt; dispatch validates only its transport
     * shape, while the fixed owner must verify it against the exact mbuf. */
    struct fk_quic_route_receipt route_receipt;
};

enum fk_owner_envelope_kind {
    FK_OWNER_ENVELOPE_DATA = 1,
    FK_OWNER_ENVELOPE_QUIC_RETIRE = 2,
};

/* Value-only bridge from the CID retirement FIFO to its immutable owner.
 * binding_expected_at_enqueue is diagnostic only: an earlier DATA envelope
 * may establish the binding after this hint was captured. The owner must
 * re-peek the CID FIFO before deciding cleanup or acknowledgement. */
struct fk_owner_quic_retire_control {
    uint64_t logical_connection_id;
    uint64_t retirement_ordinal;
    uint16_t fixed_owner;
    uint8_t binding_expected_at_enqueue;
    uint8_t reserved[5];
};

union fk_owner_envelope_payload {
    struct fk_owner_packet data;
    struct fk_owner_quic_retire_control quic_retire;
};

/* QUIC_RETIRE is value-only and never owns or aliases an mbuf. */
struct fk_owner_envelope {
    enum fk_owner_envelope_kind kind;
    uint8_t reserved[4];
    union fk_owner_envelope_payload payload;
};

/* Routed-packet identity contract:
 * - FLOW_KEY has logical_connection_id == 0;
 * - QUIC_LOGICAL has logical_connection_id != 0;
 * - QUIC_INITIAL_CID is proposal-only and is never a routed packet kind.
 * FLOW_KEY requires both direction fields to be zero. QUIC_LOGICAL permits
 * an explicitly unknown direction only as (known=0,value=0); formal logical
 * state processing must reject it rather than guess a presentation axis.
 * packet_handle and both lengths must describe a live, non-empty packet.
 * QUIC_LOGICAL must already carry ingress_worker/owner_worker equal to the
 * submit route because those values are committed by its route receipt. */

enum fk_owner_dispatch_result {
    FK_OWNER_DISPATCH_LOCAL = 0,
    FK_OWNER_DISPATCH_FORWARDED = 1,
    FK_OWNER_DISPATCH_QUEUE_FULL = 2,
    FK_OWNER_DISPATCH_INVALID = 3,
    /* No ownership transfer: packet_handle remains owned by the caller. */
    FK_OWNER_DISPATCH_STOPPED = 4,
    /* DATA was sealed while lifecycle remains open for terminal controls. */
    FK_OWNER_DISPATCH_OBSERVATIONS_SEALED = 5,
    /* The exact observation sequence advanced without creating a DATA
     * envelope or transferring a packet handle. */
    FK_OWNER_DISPATCH_SKIPPED = 6,
};

/* A tombstone is an explicit explanation for why one sequenced ingress
 * observation cannot become DATA.  Values are a frozen, finite metrics ABI;
 * zero and values at/above COUNT are invalid. */
enum fk_owner_observation_skip_reason {
    FK_OWNER_OBSERVATION_SKIP_FILTERED = 1,
    FK_OWNER_OBSERVATION_SKIP_PARSE_REJECTED = 2,
    FK_OWNER_OBSERVATION_SKIP_UNRESOLVED_IDENTITY = 3,
    FK_OWNER_OBSERVATION_SKIP_CAPTURE_TRUNCATED = 4,
    FK_OWNER_OBSERVATION_SKIP_UNSUPPORTED_PACKET = 5,
    FK_OWNER_OBSERVATION_SKIP_REASON_COUNT = 6,
};

enum fk_owner_dispatch_lifecycle {
    FK_OWNER_DISPATCH_ACCEPTING = 0,
    FK_OWNER_DISPATCH_STOPPED_NORMAL = 1,
    FK_OWNER_DISPATCH_ABORTED = 2,
};

struct fk_owner_dispatch_stats {
    uint64_t submit_attempts;
    /* Legacy non-ordered local fast-path packets, never queued. */
    uint64_t local_packets;
    uint64_t local_enqueued;
    uint64_t local_dequeued;
    uint64_t remote_enqueued;
    uint64_t remote_dequeued;
    uint64_t queued_enqueued;
    uint64_t queued_dequeued;
    /* DATA accepted through submit_observation_batch or its submit_ordered
     * wrapper. Formal exact mode requires this to equal queued_enqueued. */
    uint64_t ordered_accepted_packets;
    /* Accepted sequence tombstones.  They never enter an owner queue and
     * never participate in DATA ownership conservation. */
    uint64_t ordered_skipped_observations;
    uint64_t ordered_skipped_filtered;
    uint64_t ordered_skipped_parse_rejected;
    uint64_t ordered_skipped_unresolved_identity;
    uint64_t ordered_skipped_capture_truncated;
    uint64_t ordered_skipped_unsupported_packet;
    /* Next globally expected packet_sequence for ordered DATA or skip. */
    uint64_t next_ordered_sequence;
    /* Sticky count of valid ordered submissions that did not present exactly
     * next_ordered_sequence. */
    uint64_t ordered_sequence_failures;
    uint64_t retire_controls_enqueued;
    uint64_t retire_controls_dequeued;
    uint64_t retire_controls_normal_dequeued;
    uint64_t retire_controls_drained;
    uint64_t retire_control_depth;
    uint64_t peak_retire_control_depth;
    uint64_t envelope_depth;
    uint64_t peak_envelope_depth;
    /* Diagnostic maximum of every successfully committed CID-global ordinal.
     * It is not a dispatcher ordering cursor: ordering is per fixed owner. */
    uint64_t maximum_retirement_ordinal_observed;
    uint64_t retirement_ordinal_failures;
    /* Pre-observation, controls-only prefixes.  They are bound to the exact
     * current packet_sequence but deliberately do not advance it. */
    uint64_t observation_retire_prefix_attempts;
    uint64_t observation_retire_prefixes_accepted;
    uint64_t terminal_batch_attempts;
    uint64_t terminal_batches_accepted;
    uint64_t next_terminal_ordinal;
    uint64_t terminal_ordinal_failures;
    uint64_t observation_seal_attempts;
    uint64_t observation_seal_transitions;
    uint64_t observation_seal_failures;
    uint64_t submit_rejected_observations_sealed;
    uint64_t atomic_batch_preflight_failures;
    uint64_t queue_full;
    uint64_t invalid_routes;
    uint64_t total_depth;
    uint64_t peak_total_depth;
    uint64_t reserved_bytes;
    uint16_t worker_count;
    uint32_t queue_capacity_per_owner;

    /* Ownership conservation: accepted == dequeued + drained + owned. */
    uint64_t accepted_packets;
    uint64_t dequeued_packets;
    uint64_t drained_packets;
    uint64_t owned_packets;
    uint64_t in_flight_submitters;
    uint64_t stop_attempts;
    uint64_t stop_transitions;
    uint64_t abort_attempts;
    uint64_t abort_transitions;
    uint64_t submit_rejected_stopped;
    uint64_t submit_rejected_aborted;
    uint64_t destroy_rejected_live_ownership;
    enum fk_owner_dispatch_lifecycle lifecycle;
    bool ownership_conserved;
    bool retire_controls_conserved;
    bool ordered_skip_reasons_conserved;
    bool ordered_observation_accounting_conserved;
    bool observations_sealed;
};

struct fk_owner_dispatch_owner_stats {
    uint64_t local_enqueued;
    uint64_t local_dequeued;
    uint64_t remote_enqueued;
    uint64_t remote_dequeued;
    uint64_t queued_enqueued;
    uint64_t queued_dequeued;
    uint64_t depth;
    uint64_t peak_depth;
    uint16_t owner_worker;
    uint32_t queue_capacity;
    uint64_t dequeued_packets;
    uint64_t drained_packets;
    uint64_t retire_controls_enqueued;
    uint64_t retire_controls_dequeued;
    uint64_t retire_controls_normal_dequeued;
    uint64_t retire_controls_drained;
    uint64_t retire_control_depth;
    uint64_t last_retirement_ordinal;
    bool retirement_ordinal_initialized;
};

struct fk_owner_dispatch;

/* Returns zero for an invalid topology or on size overflow. */
size_t fk_owner_dispatch_storage_bytes(
    const struct fk_owner_dispatch_config *config);

/*
 * Initializes all queues in caller-owned storage.  No allocation is made at
 * submit/dequeue time.  storage must be aligned to max_align_t and remain live
 * until destroy.
 */
bool fk_owner_dispatch_initialize(
    void *storage,
    size_t storage_bytes,
    const struct fk_owner_dispatch_config *config,
    struct fk_owner_dispatch **dispatch);

/*
 * Stops admission and destroys only when no packet handle remains owned and
 * no value-only control remains queued. The caller must first stop and join
 * every thread that can invoke
 * any dispatch API, including producers, owner consumers, metrics readers,
 * stop/abort callers, and drainers.  Exactly one thread may invoke successful
 * destruction.  Lifecycle shutdown prevents new admission but is not a
 * general API-reference count.  A false result leaves dispatch intact so the
 * caller can drain and retry; it never silently discards an accepted handle.
 */
bool fk_owner_dispatch_destroy_checked(struct fk_owner_dispatch *dispatch);

/* Compatibility wrapper.  It delegates to destroy_checked and becomes a
 * no-op on live envelopes; formal code must use the checked entry point. */
void fk_owner_dispatch_destroy(struct fk_owner_dispatch *dispatch);

/*
 * Serializes a canonical native flow key explicitly as:
 * ip_version || protocol || low_addr[16] || high_addr[16] ||
 * low_port_be16 || high_port_be16.
 * No structure padding or host byte order enters the owner hash ABI.
 */
bool fk_owner_identity_from_flow_key(
    const struct fk_flow_key *key,
    struct fk_owner_identity *identity);

/* Keyed, deterministic owner selection for a canonical flow key or the first
 * visible QUIC DCID.  QUIC_LOGICAL is deliberately rejected here: once the
 * CID directory creates a connection, callers must use its stored
 * fixed_owner rather than re-hash the generated logical id.  The key must be
 * frozen in the run contract before READY; otherwise formal_owner is false. */
bool fk_owner_dispatch_select_owner(
    const struct fk_owner_dispatch *dispatch,
    const struct fk_owner_identity *identity,
    uint16_t *owner,
    bool *formal_owner);

enum fk_owner_dispatch_result fk_owner_dispatch_submit(
    struct fk_owner_dispatch *dispatch,
    uint16_t ingress_worker,
    uint16_t owner_worker,
    const struct fk_owner_packet *packet);

/*
 * Ordered path: enqueue even when ingress_worker == owner_worker.  Calls are
 * globally serialized through preallocated state and packet_sequence must be
 * exactly 0,1,... . A sequence mismatch returns INVALID, increments a sticky
 * ordered-sequence failure, and permanently makes formal completion false.
 * QUEUE_FULL, INVALID, STOPPED, and OBSERVATIONS_SEALED do not advance the
 * expected sequence.
 * Formal exact replay must use this entry point after the exact sequencer so a
 * local packet cannot overtake an earlier remote handoff.  FORWARDED means
 * queue ownership was accepted; the caller must not free packet_handle.
 */
enum fk_owner_dispatch_result fk_owner_dispatch_submit_ordered(
    struct fk_owner_dispatch *dispatch,
    uint16_t ingress_worker,
    uint16_t owner_worker,
    const struct fk_owner_packet *packet);

/*
 * Atomic ordered tombstone for a sequencer-released observation that produces
 * no DATA envelope. Retirement controls discovered while classifying that
 * same observation are preflighted and enqueued before the tombstone advances
 * the global sequence. Failure changes no ring, retirement ordinal,
 * accepted-skip counter, or expected sequence. Success returns SKIPPED and
 * transfers no packet_handle ownership. A clean formal run requires zero
 * accepted tombstones; this API keeps later packet sequences diagnosable.
 * controls[0..control_count) must remain immutable until the call returns.
 * Atomicity here means failure atomicity: after the first cell publication no
 * operation can fail. Concurrent owner consumers may observe a published
 * prefix while the no-fail remainder is committed, but a later DATA for that
 * owner cannot overtake any control in this batch.
 */
enum fk_owner_dispatch_result
fk_owner_dispatch_submit_skipped_observation_batch(
    struct fk_owner_dispatch *dispatch,
    uint64_t packet_sequence,
    enum fk_owner_observation_skip_reason reason,
    const struct fk_owner_quic_retire_control *controls,
    size_t control_count);

/* Zero-control wrapper for submit_skipped_observation_batch. It creates one
 * submit attempt and, on success, exactly one accepted skip. */
enum fk_owner_dispatch_result fk_owner_dispatch_skip_ordered_observation(
    struct fk_owner_dispatch *dispatch,
    uint64_t packet_sequence,
    enum fk_owner_observation_skip_reason reason);

/*
 * Controls-only prefix for the exact current observation. packet_sequence
 * must equal next_ordered_sequence, but success does not advance that
 * sequence and owns no packet handle. This lets a bounded producer scratch
 * drain an arbitrarily long retirement suffix before the one DATA/SKIP
 * commit for that observation. The API is rejected after observations are
 * sealed; terminal retirement batches remain a distinct lifecycle stream.
 */
enum fk_owner_dispatch_result
fk_owner_dispatch_submit_observation_retire_prefix(
    struct fk_owner_dispatch *dispatch,
    uint64_t packet_sequence,
    const struct fk_owner_quic_retire_control *controls,
    size_t control_count);

/* Atomic observation commit. Controls for the same fixed owner must carry
 * strictly increasing CID-global retirement ordinals; ordinals across owners
 * are deliberately not merged or compared. Controls are enqueued before DATA.
 * All destination rings are preflighted under the global producer lock;
 * failure enqueues nothing and advances neither DATA sequence nor per-owner
 * retirement metadata. control_count may be zero. */
enum fk_owner_dispatch_result fk_owner_dispatch_submit_observation_batch(
    struct fk_owner_dispatch *dispatch,
    uint16_t ingress_worker,
    uint16_t owner_worker,
    const struct fk_owner_packet *packet,
    const struct fk_owner_quic_retire_control *controls,
    size_t control_count);

/* Irreversibly close DATA admission at exactly the expected next observation
 * sequence. This must succeed exactly once, even when no terminal controls
 * exist. Terminal retire batches are rejected before the seal. */
bool fk_owner_dispatch_seal_observations(
    struct fk_owner_dispatch *dispatch,
    uint64_t expected_next_packet_sequence);

/* Controls-only terminal flush. terminal_ordinal is an independent 0,1,...
 * batch stream. CID ordinals remain strictly increasing only within each
 * fixed owner's stream; cross-owner discovery order is unconstrained. It
 * never changes next_ordered_sequence and owns no packet handle. */
enum fk_owner_dispatch_result fk_owner_dispatch_submit_terminal_retire_batch(
    struct fk_owner_dispatch *dispatch,
    uint64_t terminal_ordinal,
    const struct fk_owner_quic_retire_control *controls,
    size_t control_count);

/* Exactly one consumer may dequeue a given owner queue. */
bool fk_owner_dispatch_dequeue_envelope(
    struct fk_owner_dispatch *dispatch,
    uint16_t owner_worker,
    struct fk_owner_envelope *envelope);

/* DATA-only compatibility API. If QUIC_RETIRE is at the FIFO head it returns
 * false without consuming it; formal control integration uses envelopes. */
bool fk_owner_dispatch_dequeue(
    struct fk_owner_dispatch *dispatch,
    uint16_t owner_worker,
    struct fk_owner_packet *packet);

/*
 * Linearizable admission shutdown. A submit whose reservation precedes the
 * stop may still be admitted; stop waits until its enqueue and dispatcher
 * accounting are complete. Because a thread can be descheduled at function
 * exit, that caller may observe its already-linearized FORWARDED response only
 * after stop returns. Shutdown must therefore stop RX, call this function,
 * join every submit caller, and only then interpret final caller outcomes.
 * No submit can newly reserve admission after the stop transition. Abort is
 * sticky and cannot formally complete.
 */
bool fk_owner_dispatch_stop_accepting(
    struct fk_owner_dispatch *dispatch);

bool fk_owner_dispatch_abort(
    struct fk_owner_dispatch *dispatch);

/* Abort does not wait for a dequeue that entered before the abort transition.
 * Called only after the owner consumer has been stopped and joined. On success
 * DATA-only drain_next returns ownership of exactly one packet_handle for
 * reclamation. It deliberately stops at a control head. The envelope variant
 * returns either a DATA handle or one value-only control and is required to
 * drain mixed FIFOs. Neither variant may race dequeue or another drainer.
 */
bool fk_owner_dispatch_drain_next(
    struct fk_owner_dispatch *dispatch,
    uint16_t owner_worker,
    struct fk_owner_packet *packet);

bool fk_owner_dispatch_drain_next_envelope(
    struct fk_owner_dispatch *dispatch,
    uint16_t owner_worker,
    struct fk_owner_envelope *envelope);

bool fk_owner_dispatch_owned_packets(
    const struct fk_owner_dispatch *dispatch,
    uint64_t *owned_packets);

bool fk_owner_dispatch_drain_complete(
    const struct fk_owner_dispatch *dispatch);

bool fk_owner_dispatch_get_stats(
    const struct fk_owner_dispatch *dispatch,
    struct fk_owner_dispatch_stats *stats);

bool fk_owner_dispatch_get_owner_stats(
    const struct fk_owner_dispatch *dispatch,
    uint16_t owner_worker,
    struct fk_owner_dispatch_owner_stats *stats);

/*
 * Formal completion is fail-closed: admission stopped normally, no submit was
 * rejected/lost/invalid, observations were sealed exactly once at the final
 * DATA/skip sequence, zero observation tombstones were accepted, no abort
 * drain was needed, every accepted DATA/control was consumed normally, both
 * ordinal streams are exact, and every queue is empty.
 * This is only the dispatch-stage gate; the caller must additionally prove
 * that every dequeued packet completed state processing.
 */
bool fk_owner_dispatch_formal_complete(
    const struct fk_owner_dispatch *dispatch);

enum fk_owner_consistency_blocker {
    FK_OWNER_CONSISTENCY_BLOCKER_NONE = 0,
    FK_OWNER_CONSISTENCY_BLOCKER_INVALID_TOPOLOGY,
    FK_OWNER_CONSISTENCY_BLOCKER_MIGRATION_REQUIRES_DISPATCH,
    FK_OWNER_CONSISTENCY_BLOCKER_NO_VERIFIED_MECHANISM,
    FK_OWNER_CONSISTENCY_BLOCKER_STABLE_IDENTITY,
    FK_OWNER_CONSISTENCY_BLOCKER_HASH_KEY_NOT_PRECOMMITTED,
    FK_OWNER_CONSISTENCY_BLOCKER_DISPATCH_NOT_IN_SERVICE_CEILING,
    FK_OWNER_CONSISTENCY_BLOCKER_DISPATCH_LOSS,
    FK_OWNER_CONSISTENCY_BLOCKER_DISPATCH_NOT_DRAINED,
    FK_OWNER_CONSISTENCY_BLOCKER_STATE_PROCESSING_INCOMPLETE,
    FK_OWNER_CONSISTENCY_BLOCKER_OWNER_VIOLATION,
};

struct fk_owner_consistency_gate_input {
    uint16_t worker_count;
    bool quic_migration_in_scope;
    bool symmetric_rss_verified;
    bool software_dispatch_connected;
    bool stable_logical_identity_connected;
    bool owner_hash_key_precommitted;
    bool dispatch_reserved_inside_bounded_service_ceiling;
    uint64_t unresolved_quic_packets;
    uint64_t queue_full;
    uint64_t invalid_routes;
    uint64_t remote_enqueued;
    uint64_t remote_dequeued;
    uint64_t local_enqueued;
    uint64_t local_dequeued;
    uint64_t dispatch_depth_end;
    uint64_t dequeued_state_processed;
    uint64_t owner_violations;
};

struct fk_owner_consistency_gate_result {
    bool passed;
    enum fk_owner_consistency_blocker blocker;
};

/* Symmetric RSS is sufficient for bidirectional five-tuples, but it is not a
 * proof for migration: a changed tuple may hash to another queue. */
struct fk_owner_consistency_gate_result fk_owner_consistency_gate_evaluate(
    const struct fk_owner_consistency_gate_input *input);

const char *fk_owner_consistency_blocker_name(
    enum fk_owner_consistency_blocker blocker);

#ifdef __cplusplus
}
#endif

#endif
