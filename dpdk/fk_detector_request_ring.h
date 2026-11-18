#ifndef FLOWKEEP_FK_DETECTOR_REQUEST_RING_H
#define FLOWKEEP_FK_DETECTOR_REQUEST_RING_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "fk_native_parser.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Fixed, truth-free detector-request ABI.  The record is native little-endian
 * IEEE-754 binary32; an eventual POSIX-SHM adapter must attest those host
 * properties before mapping it.  This module itself is deliberately limited
 * to one-process caller-owned placement storage.
 */
/*
 * ABI v2 added a causal FLOW_OPEN control record.  ABI v3 added explicit
 * FLOW_CONTINUE and the immutable semantic first-packet timestamp.  ABI v4
 * consumes the remaining fixed header reserve for the producer-attested
 * predecessor handle and last published checkpoint. ABI v5 added coverage
 * OPEN/TERMINAL. ABI v6 permits TERMINAL to carry the last real prefix before
 * EOF (packet, source mask, feature vector and evidence timestamp), rather
 * than only packet 1. The feature offset and 768-byte record size remain
 * unchanged. Every semantic revision changes magic/version so an older peer
 * fails closed.
 */
#define FK_DETECTOR_REQUEST_ABI_VERSION 6u
#define FK_DETECTOR_REQUEST_MAGIC UINT64_C(0x0000365152444b46)
#define FK_DETECTOR_REQUEST_HEADER_BYTES 128u
#define FK_DETECTOR_REQUEST_RECORD_BYTES 768u
#define FK_DETECTOR_REQUEST_FEATURE_COUNT 159u
#define FK_DETECTOR_REQUEST_SOURCE_MASK_ALL 0x07u
#define FK_DETECTOR_REQUEST_FLAG_FLOW_OPEN 0x01u
#define FK_DETECTOR_REQUEST_FLAG_FLOW_CONTINUE 0x02u
#define FK_DETECTOR_REQUEST_FLAG_COVERAGE_OPEN 0x04u
#define FK_DETECTOR_REQUEST_FLAG_COVERAGE_TERMINAL 0x08u
#define FK_DETECTOR_REQUEST_FLAGS_ALL \
    (FK_DETECTOR_REQUEST_FLAG_FLOW_OPEN | \
     FK_DETECTOR_REQUEST_FLAG_FLOW_CONTINUE | \
     FK_DETECTOR_REQUEST_FLAG_COVERAGE_OPEN | \
     FK_DETECTOR_REQUEST_FLAG_COVERAGE_TERMINAL)

/* v6 keeps 768 bytes. COVERAGE_OPEN is an unscored OPEN with actual packet-1
 * Core features. COVERAGE_TERMINAL is generated only by the verified live EOF
 * source after all producer input and carries the last real cumulative prefix
 * available before a pending adaptive observation. Its semantic_timestamp is
 * the trigger frontier, NOT the evidence time. The otherwise-unused
 * predecessor index/gen words encode the immutable evidence time little-word
 * first; predecessor checkpoint is zero. Ordinary OPEN/CONTINUE/checkpoints
 * retain v4 semantics. */

#define FK_DETECTOR_REQUEST_RING_ABI_VERSION 1u
#define FK_DETECTOR_REQUEST_RING_MAGIC UINT64_C(0x0031474e52444b46)
#define FK_DETECTOR_REQUEST_RING_CONFIG_BYTES 32u
#define FK_DETECTOR_REQUEST_RING_MIN_CAPACITY 2u
#define FK_DETECTOR_REQUEST_RING_MAX_CAPACITY 1048576u
#define FK_DETECTOR_REQUEST_RING_STORAGE_ALIGNMENT 64u

/*
 * canonical_key is the exact bidirectional five tuple emitted by
 * fk_native_flow_key().  flow_index/generation identify its current FlowTable
 * incarnation; logical_connection_id is zero for ordinary TCP/UDP and may
 * carry a complete QUIC generation-safe identity without replacing the
 * canonical key.  event_routing_token is an opaque nonzero token owned by the
 * association adapter and is never a model feature.
 *
 * semantic_timestamp_ns is event time.  flow_first_timestamp_ns is the
 * immutable semantic time of the semantic flow instance's original first
 * packet; a CONTINUE successor preserves it across presentation generations.
 * It is nonzero and no later than semantic_timestamp_ns.
 * physical_timestamp_ns is monotonic service time and is intentionally not
 * compared with either semantic timestamp.
 * source_mask uses bits {STAT, SEQ, JA4}; zero is the valid core-only state.
 * A checkpoint has flags=0 and checkpoint_packet>0.  A control record has
 * exactly one of FLOW_OPEN or FLOW_CONTINUE set, checkpoint_packet/source_mask
 * zero, and a bitwise +0 feature vector.  FLOW_OPEN additionally requires
 * flow_first_timestamp_ns equal to semantic_timestamp_ns; FLOW_CONTINUE keeps
 * the same immutable first timestamp and may occur later.  FLOW_CONTINUE also
 * carries the exact producer-observed predecessor generation and its last
 * published checkpoint cursor; all predecessor fields are zero otherwise.
 * Control records are association input, never model input.
 */
struct fk_detector_request_v1 {
    uint64_t magic;
    uint16_t abi_version;
    uint16_t header_bytes;
    uint16_t record_bytes;
    uint16_t feature_count;

    struct fk_flow_key canonical_key;
    uint16_t reserved_key_alignment;

    uint32_t flow_index;
    uint32_t flow_generation;
    uint32_t checkpoint_packet;
    uint8_t source_mask;
    uint8_t flags;
    uint8_t reserved0[2];

    uint64_t semantic_timestamp_ns;
    uint64_t physical_timestamp_ns;
    uint64_t event_routing_token;
    uint64_t logical_connection_id;
    uint64_t flow_first_timestamp_ns;

    uint32_t predecessor_flow_index;
    uint32_t predecessor_flow_generation;
    uint32_t predecessor_checkpoint_packet;
    uint8_t reserved_header[4];
    float features[FK_DETECTOR_REQUEST_FEATURE_COUNT];
    uint8_t reserved_tail[4];
};

static inline uint64_t fk_detector_coverage_evidence_ns(const struct fk_detector_request_v1 *r) {
    return ((uint64_t)r->predecessor_flow_generation<<32u)|r->predecessor_flow_index;
}
static inline void fk_detector_coverage_set_evidence_ns(struct fk_detector_request_v1 *r,uint64_t ns) {
    r->predecessor_flow_index=(uint32_t)ns;r->predecessor_flow_generation=(uint32_t)(ns>>32u);
    r->predecessor_checkpoint_packet=0u;
}

/* All fields, including magic/version/size, are caller-attested at init. */
struct fk_detector_request_ring_config {
    uint64_t magic;
    uint16_t abi_version;
    uint16_t config_bytes;
    uint16_t request_bytes;
    uint16_t reserved0;
    uint32_t capacity;
    uint8_t fail_closed_on_overflow;
    uint8_t reserved[11];
};

enum fk_detector_request_ring_enqueue_result {
    FK_DETECTOR_REQUEST_RING_ENQUEUE_INVALID_ARGUMENT = 0,
    FK_DETECTOR_REQUEST_RING_ENQUEUE_COMMITTED = 1,
    FK_DETECTOR_REQUEST_RING_ENQUEUE_OVERFLOW_FAIL_CLOSED = 2,
    FK_DETECTOR_REQUEST_RING_ENQUEUE_CLOSED = 3,
    FK_DETECTOR_REQUEST_RING_ENQUEUE_WRONG_PRODUCER = 4,
    FK_DETECTOR_REQUEST_RING_ENQUEUE_REQUEST_REJECTED = 5,
    FK_DETECTOR_REQUEST_RING_ENQUEUE_FAULTED = 6,
    FK_DETECTOR_REQUEST_RING_ENQUEUE_INTERNAL_FAILURE = 7,
};

enum fk_detector_request_ring_dequeue_result {
    FK_DETECTOR_REQUEST_RING_DEQUEUE_INVALID_ARGUMENT = 0,
    FK_DETECTOR_REQUEST_RING_DEQUEUE_ITEM = 1,
    FK_DETECTOR_REQUEST_RING_DEQUEUE_EMPTY = 2,
    FK_DETECTOR_REQUEST_RING_DEQUEUE_CLOSED_EMPTY = 3,
    FK_DETECTOR_REQUEST_RING_DEQUEUE_FAULTED_EMPTY = 4,
    FK_DETECTOR_REQUEST_RING_DEQUEUE_WRONG_CONSUMER = 5,
    FK_DETECTOR_REQUEST_RING_DEQUEUE_CORRUPT = 6,
};

enum fk_detector_request_ring_lifecycle {
    FK_DETECTOR_REQUEST_RING_ACCEPTING = 0,
    FK_DETECTOR_REQUEST_RING_PRODUCER_CLOSED = 1,
};

/* Snapshot counters.  reserved is always zero on a successful query. */
struct fk_detector_request_ring_stats {
    uint64_t enqueue_attempts;
    uint64_t enqueued;
    uint64_t request_validation_failures;
    uint64_t overflow_failures;
    uint64_t closed_rejections;
    uint64_t faulted_enqueue_rejections;
    uint64_t producer_thread_claims;
    uint64_t producer_thread_rejections;

    uint64_t dequeue_attempts;
    uint64_t dequeued;
    uint64_t empty_observations;
    uint64_t faulted_empty_observations;
    uint64_t consumer_thread_claims;
    uint64_t consumer_thread_rejections;

    uint64_t close_attempts;
    uint64_t close_transitions;
    uint64_t internal_integrity_failures;
    uint64_t destroy_rejections;

    uint64_t head;
    uint64_t tail;
    uint64_t depth;
    uint64_t peak_depth;
    uint64_t storage_bytes;
    uint64_t metadata_bytes;
    uint64_t request_storage_bytes;
    uint64_t ring_magic;

    uint32_t capacity;
    uint16_t request_bytes;
    uint16_t abi_version;
    uint8_t lifecycle;
    uint8_t fail_closed;
    uint8_t accounting_conserved;
    uint8_t formal_ready;
    uint8_t reserved[4];
};

struct fk_detector_request_ring;

/* Convenience initializers write the complete fixed header and zero reserve. */
bool fk_detector_request_v1_prepare(struct fk_detector_request_v1 *request);
bool fk_detector_request_v1_valid(
    const struct fk_detector_request_v1 *request);
bool fk_detector_request_v1_is_flow_open(
    const struct fk_detector_request_v1 *request);
bool fk_detector_request_v1_is_flow_continue(
    const struct fk_detector_request_v1 *request);
bool fk_detector_request_ring_config_prepare(
    struct fk_detector_request_ring_config *config,
    uint32_t capacity);

/* Worst-case bytes for an arbitrarily aligned caller-owned placement block. */
size_t fk_detector_request_ring_storage_bytes(
    const struct fk_detector_request_ring_config *config);

/*
 * No API call allocates, opens files, maps SHM, or takes a mutex.  The first
 * enqueue/close call claims exactly one producer thread; the first dequeue
 * call claims exactly one consumer thread.  A role violation, malformed
 * request, capacity overflow, or internal inconsistency is a sticky fail-close
 * condition.  Already committed records remain drainable after that fault.
 */
bool fk_detector_request_ring_initialize(
    void *storage,
    size_t storage_bytes,
    const struct fk_detector_request_ring_config *config,
    struct fk_detector_request_ring **ring);

enum fk_detector_request_ring_enqueue_result
fk_detector_request_ring_enqueue(
    struct fk_detector_request_ring *ring,
    const struct fk_detector_request_v1 *request);

enum fk_detector_request_ring_dequeue_result
fk_detector_request_ring_dequeue(
    struct fk_detector_request_ring *ring,
    struct fk_detector_request_v1 *request);

/* Idempotent on the producer thread.  A never-used ring is claimed then shut. */
bool fk_detector_request_ring_close_producer(
    struct fk_detector_request_ring *ring);

bool fk_detector_request_ring_get_stats(
    const struct fk_detector_request_ring *ring,
    struct fk_detector_request_ring_stats *stats);

/* Closed, empty, conserved, and free of every sticky failure/rejection. */
bool fk_detector_request_ring_formal_ready(
    const struct fk_detector_request_ring *ring);

/* Caller must first join producer/consumer.  Faulted-but-empty rings clean up. */
bool fk_detector_request_ring_destroy_checked(
    struct fk_detector_request_ring *ring);

#ifdef __cplusplus
}
#endif

#endif
