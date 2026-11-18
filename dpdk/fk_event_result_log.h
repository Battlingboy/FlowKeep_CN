#ifndef FLOWKEEP_FK_EVENT_RESULT_LOG_H
#define FLOWKEEP_FK_EVENT_RESULT_LOG_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "fk_student_shards.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * FKERES1 is a truth-free, append-only event-result interchange format.
 * It deliberately has no label, scenario, attack-family, or dataset-row ID.
 * Every integer and IEEE-754 bit pattern is serialized explicitly little
 * endian; C structs, bools, enum widths, and padding are never written.
 */
#define FK_EVENT_RESULT_LOG_VERSION 1u
#define FK_EVENT_RESULT_LOG_HEADER_BYTES 512u
#define FK_EVENT_RESULT_LOG_RECORD_BYTES 320u
#define FK_EVENT_RESULT_LOG_SHA256_BYTES 32u
#define FK_EVENT_RESULT_LOG_UUID_BYTES 16u
#define FK_EVENT_RESULT_LOG_MAX_WORKERS 8u

#define FK_EVENT_RESULT_LOG_ENDIAN_TAG UINT32_C(0x01020304)
/* 0x1f is the frozen legacy FKERES1 header.  Extension bits are opt-in so a
 * receiver that has not yet supplied a loss summary continues to emit the
 * byte-identical legacy format. */
#define FK_EVENT_RESULT_LOG_BASE_HEADER_FLAGS UINT32_C(0x0000001f)
#define FK_EVENT_RESULT_LOG_HEADER_FLAGS \
    FK_EVENT_RESULT_LOG_BASE_HEADER_FLAGS
#define FK_EVENT_RESULT_LOG_HAS_LOSS_SUMMARY UINT32_C(0x00000020)
#define FK_EVENT_RESULT_LOG_EXTENDED_HEADER_FLAGS \
    (FK_EVENT_RESULT_LOG_BASE_HEADER_FLAGS | \
     FK_EVENT_RESULT_LOG_HAS_LOSS_SUMMARY)
/* Set only by a producer executing the fail-closed --formal-datacon path.
 * This is an attestation of the producer path, not a substitute for the
 * evaluator's independently precommitted run contract. */
#define FK_EVENT_RESULT_LOG_FORMAL_RUN_ATTESTED UINT32_C(0x00000040)
#define FK_EVENT_RESULT_LOG_HAS_TRIGGER_PROTOCOL_V2 UINT32_C(0x00000080)
#define FK_EVENT_RESULT_LOG_TRIGGER_V2_HEADER_FLAGS \
    (FK_EVENT_RESULT_LOG_EXTENDED_HEADER_FLAGS | \
     FK_EVENT_RESULT_LOG_HAS_TRIGGER_PROTOCOL_V2)
#define FK_EVENT_RESULT_LOG_FORMAL_TRIGGER_V2_HEADER_FLAGS \
    (FK_EVENT_RESULT_LOG_FORMAL_HEADER_FLAGS | \
     FK_EVENT_RESULT_LOG_HAS_TRIGGER_PROTOCOL_V2)
#define FK_EVENT_RESULT_LOG_FORMAL_HEADER_FLAGS \
    (FK_EVENT_RESULT_LOG_EXTENDED_HEADER_FLAGS | \
     FK_EVENT_RESULT_LOG_FORMAL_RUN_ATTESTED)

/* Legacy files use the single PASSED bit.  A HAS_LOSS_SUMMARY file instead
 * uses the composable contract below.  Intentional, reason-accounted policy
 * loss may be nonzero; transport/infrastructure/runtime fatal loss may not. */
#define FK_EVENT_RESULT_LOG_UPSTREAM_INTEGRITY_PASSED UINT32_C(0x00000001)
#define FK_EVENT_RESULT_LOG_INTEGRITY_TRANSPORT_COMPLETE \
    UINT32_C(0x00000001)
#define FK_EVENT_RESULT_LOG_INTEGRITY_ADMITTED_PIPELINE_CONSERVED \
    UINT32_C(0x00000002)
#define FK_EVENT_RESULT_LOG_INTEGRITY_POLICY_LOSS_ACCOUNTED \
    UINT32_C(0x00000004)
#define FK_EVENT_RESULT_LOG_INTEGRITY_NO_SERVICE_POLICY_LOSS \
    UINT32_C(0x00000008)
#define FK_EVENT_RESULT_LOG_INTEGRITY_BUDGET_SAFE \
    UINT32_C(0x00000010)
#define FK_EVENT_RESULT_LOG_INTEGRITY_SEMANTIC_WATERMARK_COMPLETE \
    UINT32_C(0x00000020)
#define FK_EVENT_RESULT_LOG_INTEGRITY_KNOWN_MASK UINT32_C(0x0000003f)
#define FK_EVENT_RESULT_LOG_INTEGRITY_REQUIRED_CLEAN_MASK \
    (FK_EVENT_RESULT_LOG_INTEGRITY_TRANSPORT_COMPLETE | \
     FK_EVENT_RESULT_LOG_INTEGRITY_ADMITTED_PIPELINE_CONSERVED | \
     FK_EVENT_RESULT_LOG_INTEGRITY_POLICY_LOSS_ACCOUNTED | \
     FK_EVENT_RESULT_LOG_INTEGRITY_BUDGET_SAFE | \
     FK_EVENT_RESULT_LOG_INTEGRITY_SEMANTIC_WATERMARK_COMPLETE)

#define FK_EVENT_RESULT_LOG_LOSS_REASON_SCHEMA 2u

enum fk_event_result_log_record_type {
    FK_EVENT_RESULT_LOG_EVENT_BIND = 1,
    FK_EVENT_RESULT_LOG_WINDOW_RESULT = 2,
    FK_EVENT_RESULT_LOG_FOOTER = 3,
    FK_EVENT_RESULT_LOG_RUN_LOSS_SUMMARY = 4,
    FK_EVENT_RESULT_LOG_TRIGGER_RECEIPT_V2 = 5,
};

enum fk_event_result_log_error {
    FK_EVENT_RESULT_LOG_ERROR_NONE = 0,
    FK_EVENT_RESULT_LOG_ERROR_INVALID_CONFIG = 1,
    FK_EVENT_RESULT_LOG_ERROR_INVALID_RECORD = 2,
    FK_EVENT_RESULT_LOG_ERROR_RING_FULL = 3,
    FK_EVENT_RESULT_LOG_ERROR_OPEN = 4,
    FK_EVENT_RESULT_LOG_ERROR_WRITE = 5,
    FK_EVENT_RESULT_LOG_ERROR_SHORT_WRITE = 6,
    FK_EVENT_RESULT_LOG_ERROR_FSYNC = 7,
    FK_EVENT_RESULT_LOG_ERROR_CLOSE = 8,
    FK_EVENT_RESULT_LOG_ERROR_RENAME = 9,
    FK_EVENT_RESULT_LOG_ERROR_CONSERVATION = 10,
    FK_EVENT_RESULT_LOG_ERROR_FINAL_ACK = 11,
    FK_EVENT_RESULT_LOG_ERROR_STATE = 12,
    FK_EVENT_RESULT_LOG_ERROR_COLLECTOR_SEQUENCE = 13,
    FK_EVENT_RESULT_LOG_ERROR_UPSTREAM_INTEGRITY = 14,
    FK_EVENT_RESULT_LOG_ERROR_LOSS_SUMMARY = 15,
    FK_EVENT_RESULT_LOG_ERROR_TRIGGER_RECEIPT = 16,
};

/*
 * Terminal trigger conservation supplied by the exact-order owner.  The
 * logger independently derives result counts and ordinal summaries from the
 * WINDOW_RESULT bytes and requires an exact match before committing.
 */
struct fk_event_result_log_trigger_receipt_v2 {
    uint64_t checkpoint_trigger_messages;
    uint64_t scheduled_periodic_ticks;
    uint64_t empty_periodic_ticks;
    uint64_t same_timestamp_unchanged_periodic_coalesces;
    uint64_t checkpoint_trigger_results;
    uint64_t periodic_trigger_results;
    uint64_t output_results;
    uint64_t trigger_ordinal_sum;
    uint64_t trigger_ordinal_xor;
    uint64_t trigger_ordinal_max;
    uint64_t checkpoint_packet_4_results;
    uint64_t checkpoint_packet_8_results;
    uint64_t checkpoint_packet_12_results;
    uint64_t checkpoint_packet_20_results;
    uint32_t trigger_protocol;
    uint32_t reserved32;
};

/*
 * Truth-free, run-level reason counters.  The four totals and the two derived
 * totals are independently serialized and must conserve exactly.  Policy
 * reasons are scoreable outcomes.  Every infrastructure/runtime/transport
 * reason is fatal for a clean commit.
 */
struct fk_event_result_log_loss_summary {
    uint64_t policy_loss_total;
    uint64_t policy_flow_overload_rejects;
    uint64_t policy_flow_quota_rejects;
    uint64_t policy_detector_admission_rejects;
    uint64_t policy_deadline_cancellations;
    uint64_t policy_intentional_packet_drops;

    uint64_t infrastructure_fatal_total;
    uint64_t infrastructure_input_ring_full;
    uint64_t infrastructure_reorder_rejections;
    uint64_t infrastructure_student_queue_failures;
    uint64_t infrastructure_result_queue_drops;
    uint64_t infrastructure_logger_drops;

    uint64_t runtime_fatal_total;
    uint64_t runtime_flow_capacity_errors;
    uint64_t runtime_checkpoint_failures;
    uint64_t runtime_action_record_overwrites;
    uint64_t runtime_detection_window_overwrites;
    uint64_t runtime_model_failures;

    uint64_t transport_fatal_total;
    uint64_t transport_sequence_gaps;
    uint64_t transport_nic_drops;
    uint64_t transport_read_failures;
    uint64_t transport_truncated_frames;
    uint64_t transport_parse_failures;

    uint64_t all_loss_total;
    uint64_t fatal_loss_total;

    /*
     * Reason-schema v2 append-only extension.  These fields are serialized
     * after the complete v1 prefix above, so all v1 field offsets remain
     * unchanged.  Producers must supply mutually exclusive leaf counts: a
     * parent/aggregate diagnostic and one of its child counters must never
     * both contribute to these totals.
     */
    uint64_t runtime_state_update_failures;
    uint64_t runtime_flow_open_observation_overwrites;
    uint64_t runtime_action_transition_failures;
    uint64_t runtime_association_failures;
    uint64_t runtime_association_state_evictions;
    uint64_t runtime_semantic_contract_failures;
    uint64_t transport_source_filter_rejections;
};

struct fk_event_result_log_header_binding {
    uint8_t run_uuid[FK_EVENT_RESULT_LOG_UUID_BYTES];
    uint8_t capture_sha256[FK_EVENT_RESULT_LOG_SHA256_BYTES];
    /* FKTSV1 header field records_sha256: record-region bytes only. */
    uint8_t sidecar_records_sha256[FK_EVENT_RESULT_LOG_SHA256_BYTES];
    uint8_t model_sha256[FK_EVENT_RESULT_LOG_SHA256_BYTES];
    uint8_t manifest_sha256[FK_EVENT_RESULT_LOG_SHA256_BYTES];
    uint8_t feature_schema_sha256[FK_EVENT_RESULT_LOG_SHA256_BYTES];
    uint8_t config_sha256[FK_EVENT_RESULT_LOG_SHA256_BYTES];
    /* SHA-256 of the exact pre-run FKRCV1 bytes. Formal-only provenance. */
    uint8_t run_contract_sha256[FK_EVENT_RESULT_LOG_SHA256_BYTES];
    uint32_t decision_threshold_bits;
    uint64_t window_ns;
    uint64_t stride_ns;
    uint64_t capture_first_timestamp_ns;
    uint64_t capture_last_timestamp_ns;
    uint16_t route_worker_count; /* exactly 2, 4, or 8 */
};

/*
 * One stable actor/event identity binding. identity is exactly the public,
 * byte-isomorphic actor AssociationKey: it intentionally contains neither
 * transport protocol nor ports because neither is part of event identity.
 */
struct fk_event_result_log_event_bind {
    uint64_t run_event_id;
    uint32_t event_generation;
    uint32_t event_slot; /* diagnostic only; never an identity */
    struct fk_actor_event_identity identity;
    uint64_t event_start_trace_ns;
    /* Shared EVENT_BIND/WINDOW_RESULT producer sequence: global, 0-based. */
    uint64_t collector_sequence;
};

/*
 * Finalize is called only after the producer has stopped and the writer has
 * drained the ring. Expected counts bind upstream conservation to the file.
 * final_ack_mask uses bit i for Student worker i. Per-worker command counts
 * are diagnostic and truth-free; per-worker window counts are derived by the
 * logger from successfully written WINDOW_RESULT records.
 */
struct fk_event_result_log_finalize {
    uint64_t final_watermark_ns;
    uint64_t expected_event_bind_records;
    uint64_t expected_window_records;
    uint64_t final_ack_mask;
    /* Independent of worker ACKs; required before a clean commit. */
    uint32_t upstream_integrity_flags;
    /* Required and serialized only when HAS_LOSS_SUMMARY was requested. */
    struct fk_event_result_log_loss_summary loss_summary;
    uint64_t per_worker_command_records[FK_EVENT_RESULT_LOG_MAX_WORKERS];
    /* Required only when HAS_TRIGGER_PROTOCOL_V2 is set. */
    struct fk_event_result_log_trigger_receipt_v2 trigger_receipt_v2;
};

/* Injectable cold-path I/O. Either all callbacks are null (POSIX defaults),
 * or every callback is supplied. Hot enqueue APIs never invoke these. */
struct fk_event_result_log_io {
    void *context;
    int (*open_partial)(void *context, const char *path);
    int64_t (*write_bytes)(
        void *context, int descriptor, const uint8_t *data, size_t bytes);
    bool (*sync_file)(void *context, int descriptor);
    bool (*close_file)(void *context, int descriptor);
    bool (*rename_file)(
        void *context, const char *partial_path, const char *final_path);
};

struct fk_event_result_log_config {
    uint32_t ring_capacity; /* power of two, at least two */
    /* Zero emits legacy 0x1f. HAS_LOSS_SUMMARY emits 0x3f. A formal run must
     * request HAS_LOSS_SUMMARY|FORMAL_RUN_ATTESTED and emits 0x7f. */
    uint32_t header_extension_flags;
    const char *final_path;
    struct fk_event_result_log_header_binding header;
    struct fk_event_result_log_io io;
};

struct fk_event_result_log_stats {
    uint64_t event_bind_enqueued;
    uint64_t window_enqueued;
    uint64_t event_bind_written;
    uint64_t window_written;
    uint64_t producer_drops;
    uint64_t writer_errors;
    uint64_t data_records_written;
    uint64_t bytes_before_footer;
    uint64_t rolling_crc64;
    uint64_t final_watermark_ns;
    uint64_t final_ack_mask;
    uint32_t header_flags;
    uint32_t upstream_integrity_flags;
    struct fk_event_result_log_loss_summary loss_summary;
    uint64_t per_worker_windows_enqueued[FK_EVENT_RESULT_LOG_MAX_WORKERS];
    uint64_t per_worker_windows_written[FK_EVENT_RESULT_LOG_MAX_WORKERS];
    uint64_t per_worker_command_records[FK_EVENT_RESULT_LOG_MAX_WORKERS];
    struct fk_event_result_log_trigger_receipt_v2 trigger_receipt_v2;
    uint64_t observed_checkpoint_trigger_results;
    uint64_t observed_periodic_trigger_results;
    uint64_t observed_trigger_ordinal_sum;
    uint64_t observed_trigger_ordinal_xor;
    uint64_t observed_trigger_ordinal_max;
    uint64_t observed_checkpoint_packet_4_results;
    uint64_t observed_checkpoint_packet_8_results;
    uint64_t observed_checkpoint_packet_12_results;
    uint64_t observed_checkpoint_packet_20_results;
    uint64_t ring_reserved_bytes;
    uint64_t total_reserved_bytes;
    uint32_t ring_capacity;
    uint32_t ring_depth;
    uint32_t ring_peak_depth;
    enum fk_event_result_log_error first_error;
    bool writer_opened;
    bool loss_summary_written;
    bool trigger_receipt_written;
    bool footer_written;
    bool footer_clean;
    bool committed;
    bool failed;
};

struct fk_event_result_log;

/* Initialization may allocate. No API below create allocates memory. */
struct fk_event_result_log *fk_event_result_log_create(
    const struct fk_event_result_log_config *config,
    char *error,
    size_t error_capacity);

void fk_event_result_log_destroy(struct fk_event_result_log *log);

/* Producer-only, allocation-free, lock-free, and file-I/O-free hot APIs. */
bool fk_event_result_log_enqueue_event_bind(
    struct fk_event_result_log *log,
    const struct fk_event_result_log_event_bind *record);

bool fk_event_result_log_enqueue_window(
    struct fk_event_result_log *log,
    const struct fk_student_shard_result *result,
    /* Shared EVENT_BIND/WINDOW_RESULT producer sequence: global, 0-based. */
    uint64_t collector_sequence);

/* Writer-only cold APIs; suitable for a dedicated writer lcore/thread. */
bool fk_event_result_log_writer_open(
    struct fk_event_result_log *log,
    char *error,
    size_t error_capacity);

bool fk_event_result_log_writer_drain(
    struct fk_event_result_log *log,
    uint32_t maximum_records,
    uint32_t *drained,
    char *error,
    size_t error_capacity);

/* Writes an unclean footer to .partial when conservation/ACK already failed
 * but I/O is still usable. Only a clean footer + fsync + close is renamed. */
bool fk_event_result_log_writer_finalize(
    struct fk_event_result_log *log,
    const struct fk_event_result_log_finalize *finalize,
    char *error,
    size_t error_capacity);

bool fk_event_result_log_failed(const struct fk_event_result_log *log);

/* Lock-free live pressure queries; safe while producer/writer are running. */
uint32_t fk_event_result_log_ring_depth(
    const struct fk_event_result_log *log);

/* Full snapshot is intended after producer and writer have stopped. */
bool fk_event_result_log_get_stats(
    const struct fk_event_result_log *log,
    struct fk_event_result_log_stats *stats);

const char *fk_event_result_log_partial_path(
    const struct fk_event_result_log *log);

#ifdef __cplusplus
}
#endif

#endif
