#ifndef FLOWKEEP_FK_EXACT_IDENTITY_SEQUENCER_H
#define FLOWKEEP_FK_EXACT_IDENTITY_SEQUENCER_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define FK_EXACT_IDENTITY_SEQUENCER_MAX_PRODUCERS 64u
#define FK_EXACT_IDENTITY_SEQUENCER_MAX_PACKETS (UINT64_C(1) << 40u)

/*
 * Experimental transport/service storage.  These queues and reorder slots
 * are not retained FLOWKEEP evidence and must be accounted outside the
 * controlled 16/32/64 MiB state budget.
 */
struct fk_exact_identity_sequencer_config {
    uint16_t producer_count;
    uint32_t ingress_capacity_per_producer;
    uint32_t reorder_capacity;
    uint64_t expected_packets;
};

/*
 * Value-only ingress envelope. packet_handle is opaque to this module and is
 * intended to carry an rte_mbuf pointer as an integer.  No pointer into an RX
 * worker's scratch storage may be placed here.
 */
struct fk_exact_identity_packet {
    uintptr_t packet_handle;
    uint64_t packet_sequence;
    uint64_t semantic_timestamp_ns;
    uint64_t physical_ingress_timestamp_ns;
    uint32_t captured_length;
    uint32_t wire_length;
    uint16_t ingress_worker;
    uint16_t reserved;
};

enum fk_exact_identity_submit_result {
    FK_EXACT_IDENTITY_SUBMIT_ACCEPTED = 0,
    FK_EXACT_IDENTITY_SUBMIT_QUEUE_FULL = 1,
    FK_EXACT_IDENTITY_SUBMIT_PRODUCER_CLOSED = 2,
    FK_EXACT_IDENTITY_SUBMIT_ABORTED = 3,
    FK_EXACT_IDENTITY_SUBMIT_OUT_OF_RANGE = 4,
    FK_EXACT_IDENTITY_SUBMIT_INVALID = 5,
};

enum fk_exact_identity_poll_result {
    FK_EXACT_IDENTITY_POLL_RELEASED = 0,
    FK_EXACT_IDENTITY_POLL_IDLE = 1,
    FK_EXACT_IDENTITY_POLL_COMPLETE = 2,
    FK_EXACT_IDENTITY_POLL_TERMINAL = 3,
    FK_EXACT_IDENTITY_POLL_INVALID = 4,
};

enum fk_exact_identity_terminal_reason {
    FK_EXACT_IDENTITY_TERMINAL_NONE = 0,
    FK_EXACT_IDENTITY_TERMINAL_ABORTED = 1,
    FK_EXACT_IDENTITY_TERMINAL_DUPLICATE = 2,
    FK_EXACT_IDENTITY_TERMINAL_WINDOW_OVERFLOW = 3,
    FK_EXACT_IDENTITY_TERMINAL_SLOT_CONFLICT = 4,
    FK_EXACT_IDENTITY_TERMINAL_TIME_REGRESSION = 5,
    FK_EXACT_IDENTITY_TERMINAL_GAP = 6,
};

struct fk_exact_identity_sequencer_stats {
    uint64_t expected_packets;
    uint64_t submit_attempts;
    uint64_t accepted_packets;
    uint64_t ordered_released_packets;
    uint64_t abort_drained_packets;
    uint64_t invalid_submissions;
    uint64_t out_of_range_submissions;
    uint64_t queue_full_rejections;
    uint64_t closed_producer_rejections;
    uint64_t aborted_rejections;
    uint64_t invalid_close_attempts;
    uint64_t duplicate_sequences;
    uint64_t window_overflows;
    uint64_t slot_conflicts;
    uint64_t semantic_time_regressions;
    uint64_t terminal_gaps;
    uint64_t abort_calls;
    uint64_t next_sequence;
    uint64_t last_released_semantic_timestamp_ns;
    uint64_t ingress_depth;
    uint64_t peak_ingress_depth;
    uint64_t reorder_depth;
    uint64_t peak_reorder_depth;
    uint64_t owned_packets;
    uint64_t reserved_bytes;
    uint16_t producer_count;
    uint16_t closed_producers;
    uint32_t ingress_capacity_per_producer;
    uint32_t reorder_capacity;
    enum fk_exact_identity_terminal_reason terminal_reason;
    bool semantic_time_initialized;
    bool all_producers_closed;
    bool sequence_complete;
    bool timestamp_complete;
    bool aborted;
    bool drain_complete;
    bool formal_complete;
};

struct fk_exact_identity_sequencer;

/* Returns zero for an invalid configuration or size overflow. */
size_t fk_exact_identity_sequencer_storage_bytes(
    const struct fk_exact_identity_sequencer_config *config);

/* Placement initialization. No heap allocation is performed. */
struct fk_exact_identity_sequencer *
fk_exact_identity_sequencer_initialize(
    void *storage,
    size_t storage_bytes,
    const struct fk_exact_identity_sequencer_config *config,
    char *error,
    size_t error_capacity);

/*
 * Destroy succeeds only after every producer is closed and the sequencer
 * owns no packet handle.  On false the object remains live so it can be
 * aborted and drained; handles are never silently discarded.
 */
bool fk_exact_identity_sequencer_destroy(
    struct fk_exact_identity_sequencer *sequencer);

/*
 * Exactly one thread may submit for a given producer_index. Ownership of the
 * packet_handle transfers only on ACCEPTED. All failure results leave the
 * handle with the caller.
 */
enum fk_exact_identity_submit_result
fk_exact_identity_sequencer_submit(
    struct fk_exact_identity_sequencer *sequencer,
    uint16_t producer_index,
    const struct fk_exact_identity_packet *packet);

/* The producer calls close once, after its final submit has returned. */
bool fk_exact_identity_sequencer_close_producer(
    struct fk_exact_identity_sequencer *sequencer,
    uint16_t producer_index);

/*
 * Exactly one consumer may call poll. RELEASED is the only result that
 * writes packet and transfers a handle to the caller. Releases are strictly
 * packet_sequence 0,1,... and semantic timestamps must be nondecreasing.
 */
enum fk_exact_identity_poll_result fk_exact_identity_sequencer_poll(
    struct fk_exact_identity_sequencer *sequencer,
    struct fk_exact_identity_packet *packet);

/*
 * Stop ordered release and retain every still-owned handle for drain_next.
 * Producers may race with abort, but they must subsequently close and join
 * before drain_complete can become true.
 */
bool fk_exact_identity_sequencer_abort(
    struct fk_exact_identity_sequencer *sequencer);

/*
 * Transfer one unreleased handle back to the caller after abort or a
 * terminal failure. false means no handle is currently available; callers
 * use drain_complete to distinguish a temporary empty state from completion.
 */
bool fk_exact_identity_sequencer_drain_next(
    struct fk_exact_identity_sequencer *sequencer,
    struct fk_exact_identity_packet *packet);

bool fk_exact_identity_sequencer_drain_complete(
    const struct fk_exact_identity_sequencer *sequencer);

bool fk_exact_identity_sequencer_get_stats(
    const struct fk_exact_identity_sequencer *sequencer,
    struct fk_exact_identity_sequencer_stats *stats);

/* Fail closed: no failure counter may be nonzero. */
bool fk_exact_identity_sequencer_formal_complete(
    const struct fk_exact_identity_sequencer *sequencer);

#ifdef __cplusplus
}
#endif

#endif
