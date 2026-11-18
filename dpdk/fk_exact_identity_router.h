#ifndef FLOWKEEP_FK_EXACT_IDENTITY_ROUTER_H
#define FLOWKEEP_FK_EXACT_IDENTITY_ROUTER_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "fk_exact_identity_packet_bytes_resolver.h"
#include "fk_exact_identity_sequencer.h"
#include "fk_owner_dispatch.h"
#include "fk_owner_output_sequence_bridge.h"
#include "fk_quic_cid_map.h"
#include "fk_quic_initial_auth.h"
#include "fk_quic_initial_crypto_admission_gate.h"
#include "fk_quic_presentation_path_directory.h"
#include "fk_quic_retirement_publisher.h"
#include "fk_quic_route_receipt.h"

#ifdef __cplusplus
extern "C" {
#endif

#define FK_EXACT_IDENTITY_ROUTER_ABI_VERSION 4u

/* The callback must read the same monotonic physical clock domain used for
 * physical_ingress_timestamp_ns.  It must never derive admission time from
 * packet/event timestamps. */
typedef bool (*fk_exact_identity_router_monotonic_now_ns_callback)(
    void *context,
    uint64_t *physical_now_ns);

struct fk_exact_identity_router_config {
    uint32_t abi_version;
    uint16_t owner_count;
    uint8_t reserved[10];
};

/* The result is an ownership receipt for the exact packet passed to process:
 *
 * DATA_COMMITTED_TRANSFER: dispatch owns the packet; the identity source must
 *   clear its claim without freeing it.
 * SKIP_COMMITTED_RECLAIM: the sequence tombstone committed; the caller must
 *   clear the source claim and reclaim/free the packet exactly once.
 * BACKPRESSURE_RETAIN: nothing committed; retain the same immutable source
 *   claim and retry that exact descriptor.
 * TERMINAL_RECLAIM_ABORT: nothing owns the packet downstream (except for the
 *   publisher's explicitly documented committed-packet-retained integrity
 *   result); reclaim it exactly once and abort the formal run.
 * TERMINAL_PENDING_GLOBAL_ABORT: the caller still owns/reclaims the packet,
 *   while the router freezes a bridge reservation for phase-one detach and
 *   later coordinator cleanup. The bridge is still nonterminal on return.
 *
 * This core deliberately does not include or call rte_mbuf APIs.  A later
 * main-loop adapter must execute the indicated source transition. */
enum fk_exact_identity_router_outcome {
    FK_EXACT_IDENTITY_ROUTER_INVALID = 0,
    FK_EXACT_IDENTITY_ROUTER_DATA_COMMITTED_TRANSFER = 1,
    FK_EXACT_IDENTITY_ROUTER_SKIP_COMMITTED_RECLAIM = 2,
    FK_EXACT_IDENTITY_ROUTER_BACKPRESSURE_RETAIN = 3,
    FK_EXACT_IDENTITY_ROUTER_TERMINAL_RECLAIM_ABORT = 4,
    FK_EXACT_IDENTITY_ROUTER_NOT_IDENTITY_THREAD = 5,
    /* A bridge reservation is frozen but deliberately not aborted here.
     * The caller reclaims its exact mbuf, detaches the candidate during
     * identity abort-prepare, and lets the global coordinator terminate and
     * clean the bridge only after every participant is prepared. */
    FK_EXACT_IDENTITY_ROUTER_TERMINAL_PENDING_GLOBAL_ABORT = 6,
};

enum fk_exact_identity_router_packet_kind {
    FK_EXACT_IDENTITY_ROUTER_PACKET_NONE = 0,
    FK_EXACT_IDENTITY_ROUTER_PACKET_FLOW_KEY_TCP = 1,
    FK_EXACT_IDENTITY_ROUTER_PACKET_FLOW_KEY_UDP = 2,
    FK_EXACT_IDENTITY_ROUTER_PACKET_QUIC_INITIAL = 3,
    FK_EXACT_IDENTITY_ROUTER_PACKET_QUIC_LONG = 4,
    FK_EXACT_IDENTITY_ROUTER_PACKET_QUIC_SHORT = 5,
    FK_EXACT_IDENTITY_ROUTER_PACKET_SKIPPED = 6,
};

enum fk_exact_identity_router_abort_pending_result {
    FK_EXACT_IDENTITY_ROUTER_ABORT_PENDING_INVALID = 0,
    FK_EXACT_IDENTITY_ROUTER_ABORT_PENDING_RECORDED = 1,
    FK_EXACT_IDENTITY_ROUTER_ABORT_PENDING_ALREADY_RECORDED = 2,
    FK_EXACT_IDENTITY_ROUTER_ABORT_PENDING_NONE = 3,
    FK_EXACT_IDENTITY_ROUTER_ABORT_PENDING_DESCRIPTOR_MISMATCH = 4,
    FK_EXACT_IDENTITY_ROUTER_ABORT_PENDING_BRIDGE_REJECTED = 5,
    FK_EXACT_IDENTITY_ROUTER_ABORT_PENDING_NOT_IDENTITY_THREAD = 6,
};

#define FK_EXACT_IDENTITY_ROUTER_DETACH_RECEIPT_ABI_VERSION 1u

/* Phase-one global-abort detach never calls or terminates the completion
 * bridge.  DETACHED freezes this receipt, clears only the router-local
 * prepared transaction, and leaves the exact bridge reservation for the
 * global abort coordinator. */
enum fk_exact_identity_router_detach_pending_result {
    FK_EXACT_IDENTITY_ROUTER_DETACH_PENDING_INVALID = 0,
    FK_EXACT_IDENTITY_ROUTER_DETACH_PENDING_DETACHED = 1,
    FK_EXACT_IDENTITY_ROUTER_DETACH_PENDING_ALREADY_DETACHED = 2,
    FK_EXACT_IDENTITY_ROUTER_DETACH_PENDING_NONE = 3,
    FK_EXACT_IDENTITY_ROUTER_DETACH_PENDING_DESCRIPTOR_MISMATCH = 4,
    FK_EXACT_IDENTITY_ROUTER_DETACH_PENDING_NOT_IDENTITY_THREAD = 5,
};

enum fk_exact_identity_router_detach_kind {
    FK_EXACT_IDENTITY_ROUTER_DETACH_KIND_NONE = 0,
    FK_EXACT_IDENTITY_ROUTER_DETACH_KIND_PREPARED_DATA = 1,
    FK_EXACT_IDENTITY_ROUTER_DETACH_KIND_PREPARED_SKIP = 2,
    FK_EXACT_IDENTITY_ROUTER_DETACH_KIND_TERMINAL_PENDING = 3,
};

struct fk_exact_identity_router_detach_receipt_v1 {
    uint32_t abi_version;
    uint32_t prepared_kind;
    uint64_t receipt_ordinal;
    struct fk_exact_identity_packet descriptor;
    uint8_t bridge_reservation_left_active;
    uint8_t reserved[7];
};

struct fk_exact_identity_router_result {
    enum fk_exact_identity_router_outcome outcome;
    enum fk_exact_identity_router_packet_kind packet_kind;
    enum fk_native_parse_code parse_code;
    enum fk_owner_observation_skip_reason skip_reason;
    enum fk_quic_initial_auth_reason initial_auth_reason;
    enum fk_quic_initial_crypto_admission_decision
        initial_crypto_admission_decision;
    enum fk_quic_initial_crypto_admission_reason
        initial_crypto_admission_reason;
    enum fk_quic_cid_result_code cid_code;
    enum fk_quic_cid_reject_reason cid_reason;
    enum fk_quic_retirement_publisher_result publisher_result;
    uint64_t logical_connection_id;
    uint16_t owner_worker;
    uint8_t feature_direction;
    uint8_t feature_direction_known;
    uint8_t resolved_destination_cid_length;
    uint8_t route_evidence_kind;
    uint8_t route_placement_context;
    uint8_t reserved[5];
};

struct fk_exact_identity_router_stats {
    uint64_t process_attempts;
    uint64_t resolver_attempts;
    uint64_t resolver_successes;
    uint64_t resolver_rejections;
    uint64_t parser_successes;
    uint64_t parser_rejections;
    uint64_t flow_key_tcp_packets;
    uint64_t flow_key_udp_packets;
    uint64_t quic_initial_packets;
    uint64_t quic_long_packets;
    uint64_t quic_short_packets;
    uint64_t initial_clear_bounds_inspections;
    uint64_t initial_clear_bounds_candidates;
    uint64_t initial_clear_bounds_rejections;
    uint64_t initial_crypto_gate_begin_attempts;
    uint64_t initial_crypto_gate_allows;
    uint64_t initial_crypto_gate_rejections;
    uint64_t initial_crypto_gate_completion_attempts;
    uint64_t initial_crypto_gate_completions;
    uint64_t initial_crypto_gate_completion_rejections;
    uint64_t exact_cid_no_crypto_routes;
    uint64_t initial_auth_attempts;
    uint64_t initial_auth_successes;
    uint64_t initial_auth_rejections;
    uint64_t cid_created;
    uint64_t cid_resolved;
    uint64_t cid_unresolved;
    uint64_t cid_ambiguous;
    uint64_t cid_rejected;
    uint64_t path_classify_calls;
    uint64_t path_register_calls;
    uint64_t path_register_rejections;
    uint64_t path_registrations_created;
    uint64_t path_registrations_refreshed;
    uint64_t path_registration_skipped_existing;
    uint64_t route_receipt_issue_attempts;
    uint64_t route_receipts_issued;
    uint64_t route_receipt_rejections;
    uint64_t completion_reservation_attempts;
    uint64_t completion_reservations;
    uint64_t completion_idempotent_reservations;
    uint64_t completion_reservation_backpressure;
    uint64_t completion_reservation_rejections;
    uint64_t completion_route_bind_attempts;
    uint64_t completion_routes_bound;
    uint64_t completion_route_idempotent_bindings;
    uint64_t completion_route_bind_rejections;
    uint64_t completion_abort_attempts;
    uint64_t completion_aborts_recorded;
    uint64_t completion_abort_rejections;
    uint64_t skip_completion_publish_attempts;
    uint64_t skip_completions_published;
    uint64_t skip_completion_publish_rejections;
    uint64_t publisher_data_calls;
    uint64_t publisher_skip_calls;
    uint64_t data_committed_transfers;
    uint64_t skip_committed_reclaims;
    /* Exact terminal disposition partition for packets that were explicitly
     * classified as QUIC_INITIAL/LONG/SHORT.  These two counters must sum to
     * quic_initial_packets + quic_long_packets + quic_short_packets on a
     * normal finite run; a bounded, policy-driven identity skip is not an
     * unaccounted packet loss. */
    uint64_t quic_data_committed_transfers;
    uint64_t quic_skip_committed_reclaims;
    uint64_t backpressure_retentions;
    uint64_t terminal_reclaim_aborts;
    uint64_t terminal_pending_global_aborts;
    uint64_t terminal_pending_exact_replays;
    uint64_t terminal_pending_descriptor_mismatches;
    uint64_t authenticated_initial_path_registrations;
    uint64_t exact_cid_guard_registrations;
    uint64_t prepared_transactions;
    uint64_t prepared_data_transactions;
    uint64_t prepared_skip_transactions;
    uint64_t prepared_retry_attempts;
    uint64_t prepared_data_retries;
    uint64_t prepared_skip_retries;
    uint64_t prepared_retry_resolver_bypasses;
    uint64_t prepared_data_queue_preflight_backpressure;
    uint64_t prepared_transactions_cleared;
    uint64_t prepared_transactions_normal_cleared;
    uint64_t prepared_transactions_abort_pending_cleared;
    uint64_t prepared_transactions_detached_global;
    uint64_t abort_pending_attempts;
    uint64_t abort_pending_recorded;
    uint64_t abort_pending_already_recorded;
    uint64_t abort_pending_none;
    uint64_t abort_pending_descriptor_mismatches;
    uint64_t abort_pending_bridge_rejections;
    uint64_t abort_pending_wrong_thread;
    uint64_t detach_pending_attempts;
    uint64_t detach_pending_detached;
    uint64_t detach_pending_already_detached;
    uint64_t detach_pending_none;
    uint64_t detach_pending_descriptor_mismatches;
    uint64_t detach_pending_wrong_thread;
    uint64_t detached_destroy_bridge_not_clean_rejections;
    uint64_t reserved_bytes;
    uint64_t identity_thread_claim_attempts;
    uint64_t identity_thread_claim_successes;
    uint64_t identity_thread_claim_rejections;
    uint64_t identity_thread_call_rejections;
    uint32_t abi_version;
    uint16_t owner_count;
    uint8_t initialized;
    uint8_t identity_thread_claimed;
    uint8_t sticky_failure;
    uint8_t accounting_conserved;
    uint8_t prepared_transaction;
    uint8_t detached_global_abort;
    uint8_t terminal_pending_global_abort;
    uint8_t reserved[1];
    /* Append-only stable FK_PARSE_* partition.  Slot zero (FK_PARSE_OK) is
     * always zero; slots 1..FK_PARSE_CAP_EXCEEDED sum exactly to
     * parser_rejections. */
    uint64_t parser_rejections_by_code[FK_PARSE_CAP_EXCEEDED + 1u];
    uint8_t parser_reason_conserved;
    uint8_t reserved_parser[7];
};

struct fk_exact_identity_router;

void fk_exact_identity_router_default_config_init(
    struct fk_exact_identity_router_config *config);

bool fk_exact_identity_router_config_valid(
    const struct fk_exact_identity_router_config *config);

size_t fk_exact_identity_router_storage_bytes(
    const struct fk_exact_identity_router_config *config);

/* Every dependency is borrowed and must outlive the router.  Initialization
 * verifies the shared owner topology but deliberately does not promote route
 * receipt production formal_issuance_capable.  The identity-thread claim
 * validates and claims the supplied gate on that exact thread. */
struct fk_exact_identity_router *fk_exact_identity_router_initialize(
    void *storage,
    size_t storage_bytes,
    const struct fk_exact_identity_router_config *config,
    const struct fk_exact_identity_packet_bytes_resolver *resolver,
    struct fk_quic_cid_map *cid_map,
    struct fk_quic_presentation_path_directory *path_directory,
    struct fk_owner_dispatch *dispatch,
    struct fk_quic_route_receipt_state *route_receipts,
    struct fk_quic_retirement_publisher *retirement_publisher,
    struct fk_owner_output_sequence_bridge *completion_bridge,
    struct fk_quic_initial_crypto_admission_gate *initial_crypto_gate,
    void *monotonic_clock_context,
    fk_exact_identity_router_monotonic_now_ns_callback monotonic_now_ns,
    char *error,
    size_t error_capacity);

bool fk_exact_identity_router_claim_identity_thread(
    struct fk_exact_identity_router *router);

/* No parsed view or caller-provided CID is accepted.  The router resolves and
 * parses the exact handle internally on every call. */
enum fk_exact_identity_router_outcome fk_exact_identity_router_process(
    struct fk_exact_identity_router *router,
    const struct fk_exact_identity_packet *exact_packet,
    struct fk_exact_identity_router_result *result);

/* Legacy single-owner/cold nonformal terminal cleanup for a
 * publisher-backpressured prepared transaction. The production multi-owner
 * path must use detach_pending_for_global_abort plus the global coordinator.
 * The
 * exact complete descriptor must match the frozen retry descriptor. This is
 * an abort receipt, never a normal cancellation: success makes the router
 * sticky-terminal, records/accepts the bridge's immutable first-loss receipt,
 * and clears only the router's local retry state. Repeating the same abort is
 * idempotent; a different descriptor can never clear the pending packet. */
enum fk_exact_identity_router_abort_pending_result
fk_exact_identity_router_abort_pending(
    struct fk_exact_identity_router *router,
    const struct fk_exact_identity_packet *exact_packet);

/* Multi-owner abort phase one. The exact descriptor must match the frozen
 * publisher-backpressured transaction. Success is idempotent for that same
 * descriptor, makes the router sticky-nonformal, and leaves the bridge
 * reservation active for coordinator cleanup. A mismatch can never clear
 * another packet. */
enum fk_exact_identity_router_detach_pending_result
fk_exact_identity_router_detach_pending_for_global_abort(
    struct fk_exact_identity_router *router,
    const struct fk_exact_identity_packet *exact_packet,
    struct fk_exact_identity_router_detach_receipt_v1 *receipt);

/* The mutable router counters are single-identity-thread state.  Live
 * snapshots/accounting checks are identity-thread-only; a joined control
 * thread may read them after the identity thread has stopped. */
bool fk_exact_identity_router_get_stats(
    const struct fk_exact_identity_router *router,
    struct fk_exact_identity_router_stats *stats);

bool fk_exact_identity_router_accounting_conserved(
    const struct fk_exact_identity_router *router);

/* Call only after the identity thread has joined. */
bool fk_exact_identity_router_destroy_checked(
    struct fk_exact_identity_router *router);

#ifdef __cplusplus
}
#endif

#endif
