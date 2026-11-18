#ifndef FLOWKEEP_FK_TRACE_MESSAGE_BARRIER_H
#define FLOWKEEP_FK_TRACE_MESSAGE_BARRIER_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Exact per-packet publication barrier for the formal FKTSV1 receive path.
 *
 * RX workers call complete_packet() only after publishing every association
 * message derived from a packet.  The single association aggregator records
 * each message after dequeuing it from the input rings, then advances the
 * longest prefix for which publication and ingestion masks match exactly.
 *
 * This is necessary even when the packet-sequence bitmap is contiguous:
 * messages from multiple MP rings can be dequeued in a different order from
 * the PCAP sequence.  Releasing only messages below ready_prefix_packets
 * prevents a later packet from overtaking an earlier FLOW_OPEN/checkpoint.
 *
 * Storage is allocated once by the caller.  RX completion is lock-free;
 * aggregator operations allocate nothing and are single-owner.
 */

#define FK_TRACE_MESSAGE_FLOW_OPEN UINT8_C(1)
#define FK_TRACE_MESSAGE_CHECKPOINT UINT8_C(2)
#define FK_TRACE_MESSAGE_VALID_MASK UINT8_C(3)

struct fk_trace_message_barrier;

struct fk_trace_message_barrier_stats {
    uint64_t expected_packets;
    uint64_t completed_packets;
    uint64_t explicitly_dropped_packets;
    uint64_t ready_prefix_packets;
    uint64_t expected_unique_messages;
    uint64_t ingested_unique_messages;
    uint64_t duplicate_packet_completions;
    uint64_t out_of_range_packet_completions;
    uint64_t invalid_expected_masks;
    uint64_t duplicate_ingested_messages;
    uint64_t out_of_range_ingested_messages;
    uint64_t invalid_ingested_masks;
    uint64_t packets_with_missing_messages;
    uint64_t packets_with_unexpected_messages;
    uint64_t completion_bitmap_bytes;
    uint64_t ingested_bitmap_bytes;
    uint64_t reserved_bytes;
    bool packets_complete;
    bool messages_complete;
    bool integrity_passed;
};

size_t fk_trace_message_barrier_storage_bytes(
    uint64_t expected_packets);

struct fk_trace_message_barrier *fk_trace_message_barrier_init(
    void *storage,
    size_t storage_bytes,
    uint64_t expected_packets,
    char *error,
    size_t error_capacity);

/*
 * expected_mask is the exact OR of FK_TRACE_MESSAGE_* values published for
 * this packet and may be zero.  The worker must invoke this after all ring
 * enqueue calls for the packet have returned.
 */
bool fk_trace_message_barrier_complete_packet(
    struct fk_trace_message_barrier *barrier,
    uint64_t packet_sequence,
    uint8_t expected_mask);

/* A proved absent/rejected packet publishes no messages. Its separate loss
 * marker permits scheduling progress but never counts as packet completion. */
bool fk_trace_message_barrier_drop_packet(
    struct fk_trace_message_barrier *barrier, uint64_t packet_sequence);

/* Vector completion for a strictly increasing batch which is proven to
 * publish no FLOW_OPEN/checkpoint message (the final-tail case). */
bool fk_trace_message_barrier_complete_zero_mask_batch(
    struct fk_trace_message_barrier *barrier,
    const uint64_t *packet_sequences,
    uint32_t count);

/*
 * Single-aggregator operation.  Invoke after a message has been dequeued from
 * an input ring and admitted to the sequence reorder buffer.
 */
bool fk_trace_message_barrier_ingest_message(
    struct fk_trace_message_barrier *barrier,
    uint64_t packet_sequence,
    uint8_t message_mask);

/*
 * Single-aggregator operation. For [0,N), every packet has either completed
 * with exactly the published messages ingested, or has an explicit loss
 * marker with no messages. get_stats() keeps dropped packets separate and
 * never grants a complete-input integrity receipt for the latter case.
 */
bool fk_trace_message_barrier_advance_ready(
    struct fk_trace_message_barrier *barrier,
    uint64_t *ready_prefix_packets);

/*
 * Take the formal final snapshot only after RX workers and the aggregator
 * have stopped.  A concurrent call is memory-safe but not a formal receipt.
 */
bool fk_trace_message_barrier_get_stats(
    const struct fk_trace_message_barrier *barrier,
    struct fk_trace_message_barrier_stats *stats);

#ifdef __cplusplus
}
#endif

#endif
