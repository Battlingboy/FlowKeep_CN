#ifndef FLOWKEEP_FK_QUIC_RETIREMENT_PUBLISHER_H
#define FLOWKEEP_FK_QUIC_RETIREMENT_PUBLISHER_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "fk_owner_dispatch.h"
#include "fk_quic_cid_map.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Fixed producer-side scratch plan. owner_count must exactly match both the
 * CID directory's fixed-owner count and owner dispatch's worker count.
 */
struct fk_quic_retirement_publisher_config {
    uint16_t owner_count;
    uint16_t reserved0;
    uint32_t maximum_controls_per_batch;
    uint32_t reserved1[2];
};

enum fk_quic_retirement_publisher_result {
    FK_QUIC_RETIREMENT_PUBLISHER_INVALID = 0,
    FK_QUIC_RETIREMENT_PUBLISHER_DATA_COMMITTED = 1,
    FK_QUIC_RETIREMENT_PUBLISHER_SKIP_COMMITTED = 2,
    FK_QUIC_RETIREMENT_PUBLISHER_TERMINAL_COMMITTED = 3,
    FK_QUIC_RETIREMENT_PUBLISHER_TERMINAL_EMPTY = 4,
    FK_QUIC_RETIREMENT_PUBLISHER_SCRATCH_OVERFLOW = 5,
    FK_QUIC_RETIREMENT_PUBLISHER_CID_PEEK_FAILED = 6,
    FK_QUIC_RETIREMENT_PUBLISHER_CID_MARK_FAILED = 7,
    FK_QUIC_RETIREMENT_PUBLISHER_DISPATCH_QUEUE_FULL = 8,
    FK_QUIC_RETIREMENT_PUBLISHER_DISPATCH_INVALID = 9,
    FK_QUIC_RETIREMENT_PUBLISHER_DISPATCH_STOPPED = 10,
    FK_QUIC_RETIREMENT_PUBLISHER_DISPATCH_OBSERVATIONS_SEALED = 11,
    FK_QUIC_RETIREMENT_PUBLISHER_DISPATCH_UNEXPECTED_COMMITTED = 12,
    FK_QUIC_RETIREMENT_PUBLISHER_DISPATCH_UNEXPECTED_NOT_COMMITTED = 13,
    FK_QUIC_RETIREMENT_PUBLISHER_ROLLBACK_FAILED = 14,
    FK_QUIC_RETIREMENT_PUBLISHER_ROLLBACK_RECOVERED = 15,
    FK_QUIC_RETIREMENT_PUBLISHER_STICKY_FAILURE = 16,
    FK_QUIC_RETIREMENT_PUBLISHER_REENTRANT = 17,
    /* Integrity-only DATA outcome: controls/sequence committed as a skip,
     * but the DATA packet itself was not enqueued and remains caller-owned. */
    FK_QUIC_RETIREMENT_PUBLISHER_DISPATCH_UNEXPECTED_COMMITTED_PACKET_RETAINED = 18,
};

struct fk_quic_retirement_publisher_stats {
    uint64_t data_calls;
    uint64_t skipped_calls;
    uint64_t terminal_calls;
    uint64_t invalid_calls;
    uint64_t reentrant_rejections;
    uint64_t sticky_rejections;

    uint64_t collection_attempts;
    uint64_t collection_successes;
    uint64_t owner_scans;
    uint64_t cid_peek_calls;
    uint64_t cid_peek_ready;
    uint64_t cid_peek_empty;
    uint64_t cid_peek_invalid;
    uint64_t cid_mark_attempts;
    uint64_t cid_marks;
    uint64_t cid_mark_failures;
    uint64_t scratch_overflows;

    uint64_t dispatch_attempts;
    uint64_t dispatch_committed_batches;
    uint64_t observation_prefix_dispatch_attempts;
    uint64_t observation_prefix_batches_committed;
    uint64_t data_batches_committed;
    uint64_t skipped_batches_committed;
    uint64_t terminal_batches_committed;
    uint64_t terminal_empty;
    uint64_t unexpected_committed_batches;
    uint64_t dispatch_queue_full;
    uint64_t dispatch_invalid;
    uint64_t dispatch_stopped;
    uint64_t dispatch_observations_sealed;
    uint64_t dispatch_unexpected;

    uint64_t controls_committed;
    uint64_t rollback_attempts;
    uint64_t controls_rolled_back;
    uint64_t rollback_failures;
    uint64_t rollback_recovery_calls;
    uint64_t rollback_recoveries;

    uint64_t reserved_bytes;
    uint32_t current_marked_controls;
    uint32_t peak_marked_controls;
    uint16_t owner_count;
    uint16_t reserved0;
    uint32_t maximum_controls_per_batch;
    bool sticky_failure;
    bool sticky_rollback_failure;
    uint8_t reserved1[6];
};

struct fk_quic_retirement_publisher;

bool fk_quic_retirement_publisher_config_valid(
    const struct fk_quic_retirement_publisher_config *config);

/* Exact placement reservation including worst-case initial alignment. */
size_t fk_quic_retirement_publisher_storage_bytes(
    const struct fk_quic_retirement_publisher_config *config);

/*
 * Initializes placement state and caller-owned token/control scratch. The CID
 * map and dispatch must outlive the publisher. No API allocates dynamically.
 */
struct fk_quic_retirement_publisher *
fk_quic_retirement_publisher_initialize(
    void *storage,
    size_t storage_bytes,
    const struct fk_quic_retirement_publisher_config *config,
    struct fk_quic_cid_map *cid_map,
    struct fk_owner_dispatch *dispatch,
    char *error,
    size_t error_capacity);

/* Fails while a transaction or an unrecovered rollback remains live. */
bool fk_quic_retirement_publisher_destroy_checked(
    struct fk_quic_retirement_publisher *publisher);

/*
 * Each DATA/SKIP submit drains the complete owner-ordered undispatched CID
 * retirement suffix through controls-only bounded prefixes, then commits the
 * unique DATA/SKIP operation with no hidden retirement remainder. A suffix
 * may exceed maximum_controls_per_batch by any amount; bounded scratch is a
 * scheduling quantum, not packet loss or an integrity failure. If dispatch
 * backpressures after an earlier prefix committed, that prefix remains an
 * exact lifecycle commit while the current observation and its packet remain
 * unsubmitted/owned for exact retry. Controls therefore always precede DATA,
 * including across such a retry. A failure for the currently marked prefix
 * rolls that prefix back in reverse collection order.
 * For DATA, only DATA_COMMITTED transfers packet_handle ownership.  The
 * integrity-only ...COMMITTED_PACKET_RETAINED result means that dispatch
 * consumed the ordered sequence/controls as a tombstone but did not enqueue
 * DATA; the caller still owns packet_handle and the run is permanently
 * fail-closed.  Every other non-DATA_COMMITTED result also leaves the packet
 * with the caller.
 */
enum fk_quic_retirement_publisher_result
fk_quic_retirement_publisher_submit_data_observation(
    struct fk_quic_retirement_publisher *publisher,
    uint16_t ingress_worker,
    uint16_t owner_worker,
    const struct fk_owner_packet *packet);

enum fk_quic_retirement_publisher_result
fk_quic_retirement_publisher_submit_skipped_observation(
    struct fk_quic_retirement_publisher *publisher,
    uint64_t packet_sequence,
    enum fk_owner_observation_skip_reason reason);

/* Dispatch observations must already be sealed. No-control flush is a
 * successful no-op and does not consume terminal_ordinal. */
enum fk_quic_retirement_publisher_result
fk_quic_retirement_publisher_submit_terminal_batch(
    struct fk_quic_retirement_publisher *publisher,
    uint64_t terminal_ordinal);

/*
 * Safety-only recovery after a sticky rollback failure. Successful recovery
 * removes every still-marked token, but sticky_failure remains set and the
 * run can never pass the formal gate.
 */
enum fk_quic_retirement_publisher_result
fk_quic_retirement_publisher_retry_pending_rollback(
    struct fk_quic_retirement_publisher *publisher);

/* Quiescent diagnostics; they return false while the producer is active. */
bool fk_quic_retirement_publisher_get_stats(
    const struct fk_quic_retirement_publisher *publisher,
    struct fk_quic_retirement_publisher_stats *stats);

/* Proves local counter algebra plus exact CID mark/rollback and dispatch
 * control-enqueue deltas since initialization. */
bool fk_quic_retirement_publisher_accounting_conserved(
    const struct fk_quic_retirement_publisher *publisher);

/* Transaction-stage gate only. The full system must additionally apply the
 * CID, dispatch, state-processing, and no-tombstone formal gates. */
bool fk_quic_retirement_publisher_formal_complete(
    const struct fk_quic_retirement_publisher *publisher);

const char *fk_quic_retirement_publisher_result_name(
    enum fk_quic_retirement_publisher_result result);

#ifdef __cplusplus
}
#endif

#endif
