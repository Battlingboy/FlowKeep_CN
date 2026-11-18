#ifndef FLOWKEEP_FK_OWNER_OUTPUT_BATCH_RING_H
#define FLOWKEEP_FK_OWNER_OUTPUT_BATCH_RING_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "fk_owner_runtime_output_abi.h"

#ifdef __cplusplus
extern "C" {
#endif

#define FK_OWNER_OUTPUT_BATCH_RING_ABI_VERSION 2u
#define FK_OWNER_OUTPUT_BATCH_RING_KEY_BYTES 16u
#define FK_OWNER_OUTPUT_BATCH_RING_TAG_BYTES 16u

/*
 * The two independent keys are frozen run configuration, never result data.
 * A receipt is opaque to its caller: copy it byte-for-byte and give it back
 * to ack_commit(); constructing or editing one is outside the API contract.
 */
struct fk_owner_output_batch_ring_config {
    uint64_t ring_epoch;
    uint32_t capacity;
    uint16_t fixed_owner;
    uint16_t reserved0;
    uint8_t authentication_key_0[FK_OWNER_OUTPUT_BATCH_RING_KEY_BYTES];
    uint8_t authentication_key_1[FK_OWNER_OUTPUT_BATCH_RING_KEY_BYTES];
    uint8_t keys_precommitted;
    uint8_t reserved[7];
};

struct fk_owner_output_batch_commit_receipt {
    uint64_t ring_epoch;
    uint64_t batch_transaction_epoch;
    uint64_t commit_ordinal;
    uint16_t fixed_owner;
    uint16_t abi_version;
    uint32_t reserved0;
    uint8_t tag[FK_OWNER_OUTPUT_BATCH_RING_TAG_BYTES];
};

enum fk_owner_output_batch_enqueue_result {
    FK_OWNER_OUTPUT_BATCH_ENQUEUE_INVALID = 0,
    FK_OWNER_OUTPUT_BATCH_ENQUEUE_COMMITTED = 1,
    FK_OWNER_OUTPUT_BATCH_ENQUEUE_FULL = 2,
    FK_OWNER_OUTPUT_BATCH_ENQUEUE_STOPPED = 3,
    FK_OWNER_OUTPUT_BATCH_ENQUEUE_COMMIT_ACK_REQUIRED = 4,
    FK_OWNER_OUTPUT_BATCH_ENQUEUE_WRONG_PRODUCER = 5,
    FK_OWNER_OUTPUT_BATCH_ENQUEUE_INTERNAL_FAILURE = 6,
};

enum fk_owner_output_batch_commit_ack_result {
    FK_OWNER_OUTPUT_BATCH_COMMIT_ACK_INVALID = 0,
    FK_OWNER_OUTPUT_BATCH_COMMIT_ACKED = 1,
    FK_OWNER_OUTPUT_BATCH_COMMIT_ACK_WRONG_PRODUCER = 2,
    FK_OWNER_OUTPUT_BATCH_COMMIT_ACK_NO_PENDING = 3,
    FK_OWNER_OUTPUT_BATCH_COMMIT_ACK_RECEIPT_REJECTED = 4,
};

enum fk_owner_output_batch_take_result {
    FK_OWNER_OUTPUT_BATCH_TAKE_INVALID = 0,
    FK_OWNER_OUTPUT_BATCH_DEQUEUED = 1,
    FK_OWNER_OUTPUT_BATCH_DRAINED = 2,
    FK_OWNER_OUTPUT_BATCH_EMPTY = 3,
    FK_OWNER_OUTPUT_BATCH_STOPPED_EMPTY = 4,
    FK_OWNER_OUTPUT_BATCH_DRAIN_REQUIRES_STOP = 5,
};

enum fk_owner_output_batch_ring_lifecycle {
    FK_OWNER_OUTPUT_BATCH_RING_ACCEPTING = 0,
    FK_OWNER_OUTPUT_BATCH_RING_STOPPED = 1,
};

struct fk_owner_output_batch_ring_stats {
    uint64_t enqueue_attempts;
    uint64_t accepted_batches;
    uint64_t full_rejections;
    uint64_t stopped_rejections;
    uint64_t invalid_enqueue_rejections;
    uint64_t transaction_replay_rejections;
    uint64_t commit_ack_required_rejections;
    uint64_t producer_thread_claims;
    uint64_t producer_thread_rejections;

    uint64_t commit_ack_attempts;
    uint64_t commit_acks;
    uint64_t commit_ack_no_pending_rejections;
    uint64_t commit_receipt_rejections;

    uint64_t dequeue_attempts;
    uint64_t dequeued_batches;
    uint64_t drain_attempts;
    uint64_t drained_batches;
    uint64_t drain_before_stop_rejections;
    uint64_t empty_observations;

    uint64_t stop_attempts;
    uint64_t stop_transitions;
    uint64_t internal_integrity_failures;
    uint64_t destroy_rejected_live_ownership;

    uint64_t depth;
    uint64_t peak_depth;
    uint64_t owned_batches;
    uint64_t pending_commit_ordinal;
    uint64_t last_batch_transaction_epoch;
    uint64_t next_commit_ordinal;

    /* Exact placement reservation; all three fields are service memory. */
    uint64_t service_memory_bytes;
    uint64_t service_metadata_bytes;
    uint64_t service_batch_storage_bytes;
    uint32_t capacity;
    uint32_t batch_element_bytes;
    uint64_t ring_epoch;
    uint16_t fixed_owner;
    uint16_t abi_version;
    enum fk_owner_output_batch_ring_lifecycle lifecycle;
    bool ownership_conserved;
    bool commit_receipts_conserved;
    bool service_memory_exact;
    bool formal_ready;
};

struct fk_owner_output_batch_ring;

/* Returns the exact placement reservation or zero for invalid configuration. */
size_t fk_owner_output_batch_ring_storage_bytes(
    const struct fk_owner_output_batch_ring_config *config);

/*
 * Initializes entirely inside aligned caller-owned storage.  No ring API
 * allocates.  The first successful producer-side call claims one OS thread;
 * every later enqueue/commit ACK must run on that same fixed-owner thread.
 * There is exactly one serialized downstream consumer of dequeue/drain.
 */
bool fk_owner_output_batch_ring_initialize(
    void *storage,
    size_t storage_bytes,
    const struct fk_owner_output_batch_ring_config *config,
    struct fk_owner_output_batch_ring **ring);

/*
 * Copies the complete batch or nothing.  On FULL/STOPPED/INVALID ownership
 * remains with the caller and receipt is all-zero.  Only an
 * IDENTITY_COMMITTED non-empty V2 batch is admissible.
 */
enum fk_owner_output_batch_enqueue_result
fk_owner_output_batch_ring_enqueue(
    struct fk_owner_output_batch_ring *ring,
    const struct fk_owner_runtime_output_batch_v2 *batch,
    struct fk_owner_output_batch_commit_receipt *receipt);

/* Validates the exact epoch/owner/transaction/ordinal and both secret tags. */
enum fk_owner_output_batch_commit_ack_result
fk_owner_output_batch_ring_ack_commit(
    struct fk_owner_output_batch_ring *ring,
    const struct fk_owner_output_batch_commit_receipt *receipt);

/* Transfers one complete batch to the normal downstream consumer. */
enum fk_owner_output_batch_take_result
fk_owner_output_batch_ring_dequeue(
    struct fk_owner_output_batch_ring *ring,
    struct fk_owner_runtime_output_batch_v2 *batch);

/* Explicit terminal discard/take path; legal only after stop(). */
enum fk_owner_output_batch_take_result
fk_owner_output_batch_ring_drain(
    struct fk_owner_output_batch_ring *ring,
    struct fk_owner_runtime_output_batch_v2 *batch);

/* Idempotently seals enqueue admission and waits for an in-flight producer. */
bool fk_owner_output_batch_ring_stop(
    struct fk_owner_output_batch_ring *ring);

bool fk_owner_output_batch_ring_get_stats(
    const struct fk_owner_output_batch_ring *ring,
    struct fk_owner_output_batch_ring_stats *stats);

/* accepted == dequeued + drained + owned. */
bool fk_owner_output_batch_ring_accounting_conserved(
    const struct fk_owner_output_batch_ring *ring);

/*
 * A formal result run must be stopped, empty, fully commit-ACKed, undrained,
 * and free of malformed calls, forged receipts, thread violations, or
 * internal failures.  Queue-full backpressure alone is not a formal failure.
 */
bool fk_owner_output_batch_ring_formal_ready(
    const struct fk_owner_output_batch_ring *ring);

/* Requires stopped + no owned or pending batch; failure leaves storage live. */
bool fk_owner_output_batch_ring_destroy_checked(
    struct fk_owner_output_batch_ring *ring);

#ifdef __cplusplus
}
#endif

#endif
