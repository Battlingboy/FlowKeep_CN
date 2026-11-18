#ifndef FLOWKEEP_FK_DETECTOR_REQUEST_SHM_ABI_H
#define FLOWKEEP_FK_DETECTOR_REQUEST_SHM_ABI_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "fk_detector_request_ring.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Linux/POSIX cross-process transport ABI.  All integer fields and the
 * embedded request are native little-endian.  Mutable uint64_t fields are
 * naturally aligned and accessed with lock-free acquire/release atomics.
 * The ABI deliberately separates producer and consumer writes by page:
 *
 *   [0, 4096)       producer header, producer RW / consumers RO
 *   [4096, 8192)    consumer control, formal consumer RW / producer RO
 *   [8192, end)     slots, producer RW / consumers RO
 *
 * An O_RDONLY observer maps every region read-only and can never ACK.  It is
 * audit-only and cannot be reported as the formal detector consumer.
 * Transport ABI v2 is independent of the embedded request revision: every
 * slot carries one request ABI v4 record whose own magic/version are validated
 * before delivery.
 */
#define FK_DETECTOR_REQUEST_SHM_ABI_VERSION 2u
#define FK_DETECTOR_REQUEST_SHM_CONFIG_MAGIC \
    UINT64_C(0x3247464352444b46)
#define FK_DETECTOR_REQUEST_SHM_PRODUCER_MAGIC \
    UINT64_C(0x324d485352444b46)
#define FK_DETECTOR_REQUEST_SHM_CONSUMER_MAGIC \
    UINT64_C(0x324e4f4352444b46)
#define FK_DETECTOR_REQUEST_SHM_SLOT_MAGIC \
    UINT64_C(0x32544c5352444b46)

#define FK_DETECTOR_REQUEST_SHM_CONFIG_BYTES 32u
#define FK_DETECTOR_REQUEST_SHM_PRODUCER_HEADER_BYTES 256u
#define FK_DETECTOR_REQUEST_SHM_CONSUMER_CONTROL_BYTES 256u
#define FK_DETECTOR_REQUEST_SHM_PAGE_BYTES 4096u
#define FK_DETECTOR_REQUEST_SHM_CONSUMER_OFFSET 4096u
#define FK_DETECTOR_REQUEST_SHM_SLOTS_OFFSET 8192u
#define FK_DETECTOR_REQUEST_SHM_SLOT_HEADER_BYTES 64u
#define FK_DETECTOR_REQUEST_SHM_SLOT_BYTES 832u
#define FK_DETECTOR_REQUEST_SHM_MIN_CAPACITY 2u
#define FK_DETECTOR_REQUEST_SHM_MAX_CAPACITY 8388608u
#define FK_DETECTOR_REQUEST_SHM_REQUIRED_MODE 0600u
#define FK_DETECTOR_REQUEST_SHM_MAX_NAME_BYTES 200u
#define FK_DETECTOR_REQUEST_SHM_MAX_SEQUENCE (UINT64_MAX >> 1u)

#define FK_DETECTOR_REQUEST_SHM_FNV1A_OFFSET \
    UINT64_C(14695981039346656037)
#define FK_DETECTOR_REQUEST_SHM_FNV1A_PRIME UINT64_C(1099511628211)

/* payload_checksum is FNV-1a-64 over all 768 request bytes, in order. */

struct fk_detector_request_shm_config_v1 {
    uint64_t magic;
    uint64_t run_epoch;
    uint32_t capacity;
    uint16_t abi_version;
    uint16_t config_bytes;
    uint8_t reserved[8];
};

/* Producer-owned fields.  Consumers must map this page PROT_READ. */
struct fk_detector_request_shm_producer_header_v1 {
    uint64_t magic;
    uint16_t abi_version;
    uint16_t header_bytes;
    uint16_t request_bytes;
    uint16_t slot_header_bytes;
    uint32_t slot_bytes;
    uint32_t capacity;
    uint32_t producer_page_bytes;
    uint32_t consumer_page_bytes;
    uint64_t slots_offset;
    uint64_t mapping_bytes;
    uint64_t run_epoch;
    uint32_t owner_uid;
    uint32_t owner_gid;
    uint64_t producer_pid;
    uint64_t created_mono_ns;

    uint64_t producer_stop_mono_ns;
    uint64_t write_sequence;
    uint64_t publish_attempts;
    uint64_t published;
    uint64_t dropped;
    uint64_t overrun;
    uint64_t producer_done;
    uint64_t fail_closed;
    uint64_t request_validation_failures;
    uint64_t internal_integrity_failures;
    uint64_t finish_attempts;
    uint64_t finish_transitions;
    uint64_t done_rejections;
    uint64_t wrong_producer_rejections;
    uint8_t reserved[64];
};

/*
 * Formal-consumer-owned fields.  The claim rule is one lock-free CAS from
 * claim_token=0 to an arbitrary nonzero, non-UINT64_MAX run-scoped token.
 * Only that claimant may update this page.  It releases the claim by CAS from
 * its exact token back to zero after publishing all close fields.
 */
struct fk_detector_request_shm_consumer_control_v1 {
    uint64_t magic;
    uint16_t abi_version;
    uint16_t control_bytes;
    uint16_t reserved0;
    uint16_t reserved1;
    uint64_t run_epoch;

    uint64_t claim_token;
    uint64_t consumer_pid;
    uint64_t consumer_start_mono_ns;
    uint64_t consumer_stop_mono_ns;
    uint64_t read_sequence;
    uint64_t open_count;
    uint64_t close_count;
    uint64_t peek_attempts;
    uint64_t records_peeked;
    uint64_t ack_attempts;
    uint64_t records_acked;
    uint64_t empty_observations;
    uint64_t done_empty_observations;
    uint64_t sequence_gaps;
    uint64_t validation_failures;
    uint64_t ack_rejections;
    uint64_t unacked_on_close;
    uint64_t consumer_fault;
    uint8_t reserved[88];
};

/*
 * publish_state is the sole slot publication word.  For sequence s>=1:
 *
 *   WRITING(s)   = 2*s - 1 (odd)
 *   COMMITTED(s) = 2*s     (even, nonzero)
 *
 * The producer release-stores WRITING before changing a recycled slot, fills
 * header/payload/checksum, then release-stores COMMITTED.  It only then
 * release-stores producer.write_sequence=s.  A consumer acquire-loads both,
 * copies and validates the slot, then acquire-loads publish_state again.
 */
struct fk_detector_request_shm_slot_v1 {
    uint64_t magic;
    uint16_t abi_version;
    uint16_t slot_header_bytes;
    uint16_t request_bytes;
    uint16_t reserved0;
    uint64_t publish_state;
    uint64_t run_epoch;
    uint32_t slot_index;
    uint32_t reserved1;
    uint64_t payload_checksum;
    uint8_t reserved_header[16];
    struct fk_detector_request_v1 request;
};

enum fk_detector_request_shm_publish_result {
    FK_DETECTOR_REQUEST_SHM_PUBLISH_INVALID_ARGUMENT = 0,
    FK_DETECTOR_REQUEST_SHM_PUBLISH_COMMITTED = 1,
    FK_DETECTOR_REQUEST_SHM_PUBLISH_OVERFLOW_FAIL_CLOSED = 2,
    FK_DETECTOR_REQUEST_SHM_PUBLISH_PRODUCER_DONE = 3,
    FK_DETECTOR_REQUEST_SHM_PUBLISH_REQUEST_REJECTED = 4,
    FK_DETECTOR_REQUEST_SHM_PUBLISH_FAULTED = 5,
    FK_DETECTOR_REQUEST_SHM_PUBLISH_WRONG_PRODUCER = 6,
    FK_DETECTOR_REQUEST_SHM_PUBLISH_INTERNAL_FAILURE = 7,
};

enum fk_detector_request_shm_peek_result {
    FK_DETECTOR_REQUEST_SHM_PEEK_INVALID_ARGUMENT = 0,
    FK_DETECTOR_REQUEST_SHM_PEEK_ITEM = 1,
    FK_DETECTOR_REQUEST_SHM_PEEK_EMPTY = 2,
    FK_DETECTOR_REQUEST_SHM_PEEK_PRODUCER_DONE_EMPTY = 3,
    FK_DETECTOR_REQUEST_SHM_PEEK_FAULTED_EMPTY = 4,
    FK_DETECTOR_REQUEST_SHM_PEEK_WRONG_CONSUMER = 5,
    FK_DETECTOR_REQUEST_SHM_PEEK_CORRUPT = 6,
};

enum fk_detector_request_shm_ack_result {
    FK_DETECTOR_REQUEST_SHM_ACK_INVALID_ARGUMENT = 0,
    FK_DETECTOR_REQUEST_SHM_ACK_COMMITTED = 1,
    FK_DETECTOR_REQUEST_SHM_ACK_OUT_OF_RANGE = 2,
    FK_DETECTOR_REQUEST_SHM_ACK_WRONG_CONSUMER = 3,
    FK_DETECTOR_REQUEST_SHM_ACK_CORRUPT = 4,
};

enum fk_detector_request_shm_observe_result {
    FK_DETECTOR_REQUEST_SHM_OBSERVE_INVALID_ARGUMENT = 0,
    FK_DETECTOR_REQUEST_SHM_OBSERVE_ITEM = 1,
    FK_DETECTOR_REQUEST_SHM_OBSERVE_NOT_PUBLISHED = 2,
    FK_DETECTOR_REQUEST_SHM_OBSERVE_PRODUCER_DONE_NOT_PUBLISHED = 3,
    FK_DETECTOR_REQUEST_SHM_OBSERVE_WRITING = 4,
    FK_DETECTOR_REQUEST_SHM_OBSERVE_RECYCLED = 5,
    FK_DETECTOR_REQUEST_SHM_OBSERVE_CORRUPT = 6,
};

struct fk_detector_request_shm;

bool fk_detector_request_shm_config_prepare(
    struct fk_detector_request_shm_config_v1 *config,
    uint64_t run_epoch,
    uint32_t capacity);

size_t fk_detector_request_shm_mapping_bytes(
    const struct fk_detector_request_shm_config_v1 *config);

/* O_CREAT|O_EXCL, owner euid, exact mode 0600. */
bool fk_detector_request_shm_create_producer(
    const char *name,
    const struct fk_detector_request_shm_config_v1 *config,
    struct fk_detector_request_shm **transport);

/* O_RDWR, but the adapter maps only the consumer-control page writable. */
bool fk_detector_request_shm_open_consumer(
    const char *name,
    uint64_t expected_run_epoch,
    struct fk_detector_request_shm **transport);

/* O_RDONLY audit path.  It cannot ACK or satisfy formal_ready(). */
bool fk_detector_request_shm_open_observer(
    const char *name,
    uint64_t expected_run_epoch,
    struct fk_detector_request_shm **transport);

enum fk_detector_request_shm_publish_result
fk_detector_request_shm_publish(
    struct fk_detector_request_shm *transport,
    const struct fk_detector_request_v1 *request);

/* Idempotent only for the exact same nonzero monotonic stop timestamp. */
bool fk_detector_request_shm_finish_producer(
    struct fk_detector_request_shm *transport,
    uint64_t producer_stop_mono_ns);

/*
 * Two-phase durable consumption.  peek() copies and validates consecutive
 * requests without advancing shared read_sequence.  After the corresponding
 * decision segment and manifest are fsync'd, ack(sequence) may ACK any
 * consecutive prefix through the final successfully peeked sequence.  One
 * release CAS publishes the chunk ACK; a crash before it causes replay, not
 * silent request loss.
 */
enum fk_detector_request_shm_peek_result
fk_detector_request_shm_consumer_peek(
    struct fk_detector_request_shm *transport,
    struct fk_detector_request_v1 *request,
    uint64_t *sequence);

enum fk_detector_request_shm_ack_result
fk_detector_request_shm_consumer_ack(
    struct fk_detector_request_shm *transport,
    uint64_t sequence);

enum fk_detector_request_shm_observe_result
fk_detector_request_shm_observer_read(
    struct fk_detector_request_shm *transport,
    uint64_t sequence,
    struct fk_detector_request_v1 *request);

/* Atomic snapshots; output reserve is always zero on success. */
bool fk_detector_request_shm_snapshot(
    const struct fk_detector_request_shm *transport,
    struct fk_detector_request_shm_producer_header_v1 *producer,
    struct fk_detector_request_shm_consumer_control_v1 *consumer);

/*
 * Producer-side pre-ingress gate.  This is true only after exactly one live
 * formal consumer has claimed the run while the producer is still empty and
 * accepting.  Empty polling before ingress is permitted; peeking or ACKing a
 * record, closing, or any producer/consumer fault makes the gate false.
 */
bool fk_detector_request_shm_consumer_start_ready(
    const struct fk_detector_request_shm *transport);

/* Requires one formal consumer, durable ACK of every record, and no fault. */
bool fk_detector_request_shm_formal_ready(
    const struct fk_detector_request_shm *transport);

/*
 * Producer close requires finish_producer().  Consumer close release-CASes
 * its claim; unACKed peeks are counted and remain replayable.  On success the
 * opaque handle is destroyed.  This never unlinks the POSIX object.
 */
bool fk_detector_request_shm_close_checked(
    struct fk_detector_request_shm *transport);

/* Validates name, owner, mode, fixed ABI, exact size and run epoch first. */
bool fk_detector_request_shm_unlink_checked(
    const char *name,
    uint64_t expected_run_epoch);

#ifdef __cplusplus
}
#endif

#endif
