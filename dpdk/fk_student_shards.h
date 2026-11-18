#ifndef FLOWKEEP_FK_STUDENT_SHARDS_H
#define FLOWKEEP_FK_STUDENT_SHARDS_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "fk_actor_session.h"
#include "fk_event_student.h"
#include "fk_online_event_windows.h"

#ifdef __cplusplus
extern "C" {
#endif

#define FK_STUDENT_SHARDS_MAX_WORKERS 8u
#define FK_STUDENT_SHARDS_LOGICAL_IDENTITY_V2_ABI_VERSION 2u
#define FK_STUDENT_SHARDS_IDENTITY_ABI_MODE_UNSET 0u
#define FK_STUDENT_SHARDS_IDENTITY_ABI_MODE_V1 1u
#define FK_STUDENT_SHARDS_IDENTITY_ABI_MODE_V2 2u
#define FK_STUDENT_SHARDS_COMMAND_ENTRY_V2_BYTES 88u

/*
 * One producer (the exact-order association lcore) and one consumer per
 * shard.  Every queue is fixed-size and allocated before packet processing.
 */
struct fk_student_shards_config {
    uint16_t worker_count;              /* exactly 2, 4, or 8 */
    uint32_t command_queue_capacity;    /* power of two */
    uint32_t result_queue_capacity;     /* power of two */
    uint32_t maximum_events;
    uint32_t maximum_flows_per_event;
    uint32_t maximum_total_flows;
    const char *artifact_path;
    struct fk_event_student_load_config load_config;
};

struct fk_student_shard_result {
    struct fk_online_event_window_result window;
    uint64_t command_enqueue_monotonic_ns;
    uint64_t command_start_monotonic_ns;
    uint64_t decision_monotonic_ns;
    uint16_t worker_index;
    uint16_t reserved16;
    uint32_t reserved32;
};

struct fk_student_shard_worker_stats {
    uint64_t flow_open_commands;
    uint64_t checkpoint_commands;
    uint64_t retire_commands;
    uint64_t watermark_commands;
    uint64_t final_watermark_commands;
    uint64_t commands_processed;
    uint64_t command_queue_full;
    uint64_t command_queue_peak;
    uint64_t result_queue_full;
    uint64_t result_queue_stalls;
    uint64_t result_queue_peak;
    uint64_t sequence_failures;
    uint64_t route_failures;
    uint64_t output_results;
    uint64_t payload_completions;
    uint64_t checkpoint_processing_ns;
    uint64_t watermark_processing_ns;
    uint64_t last_enqueued_sequence;
    uint64_t last_processed_sequence;
    uint64_t last_watermark_ns;
    uint64_t final_watermark_ns;
    bool watermark_initialized;
    bool final_flush_complete;
    bool worker_failed;
    struct fk_online_event_windows_stats windows;
    /* Append-only logical-identity transport receipt. */
    uint64_t logical_flow_open_commands;
    uint64_t logical_checkpoint_commands;
    /* Explicit event-epoch rebinding commands, never true FLOW_OPENs. */
    uint64_t flow_reopen_commands;
    uint64_t logical_flow_reopen_commands;
};

struct fk_student_shards_stats {
    uint16_t worker_count;
    uint16_t reserved16;
    uint32_t command_queue_capacity;
    uint32_t result_queue_capacity;
    uint32_t reserved32;
    uint64_t flow_open_enqueues;
    uint64_t checkpoint_enqueues;
    uint64_t retire_enqueues;
    uint64_t watermark_broadcasts;
    uint64_t final_watermark_broadcasts;
    uint64_t data_queue_full;
    uint64_t watermark_queue_full;
    uint64_t watermark_regressions;
    uint64_t invalid_routes;
    uint64_t slot_owner_mismatches;
    uint64_t slot_reuse_retirements;
    uint64_t feature_payload_exhaustions;
    uint32_t feature_payload_capacity;
    uint32_t feature_payloads_in_use;
    uint32_t feature_payloads_peak;
    uint32_t reserved_payload32;
    uint64_t command_queue_reserved_bytes;
    uint64_t result_queue_reserved_bytes;
    uint64_t feature_payload_reserved_bytes;
    uint64_t slot_binding_reserved_bytes;
    uint64_t windows_reserved_bytes;
    uint64_t model_parameter_bytes;
    uint64_t total_reserved_bytes;
    uint64_t last_broadcast_watermark_ns;
    uint64_t final_broadcast_watermark_ns;
    bool watermark_initialized;
    bool final_broadcast_enqueued;
    bool topology_complete;
    bool formal_completeness;
    struct fk_student_shard_worker_stats
        workers[FK_STUDENT_SHARDS_MAX_WORKERS];
    /*
     * Identity-routing receipt.  command_queue_reserved_bytes already
     * includes the complete v2 command entry.  The extension field is the
     * exact eight-byte-per-entry subset attributable to carrying the full
     * logical_connection_id and must not be added to total_reserved_bytes a
     * second time.
     */
    uint64_t identity_mode_rejections;
    uint64_t logical_identity_queue_extension_reserved_bytes;
    uint32_t command_entry_bytes;
    uint16_t logical_identity_v2_abi_version;
    uint8_t identity_abi_mode;
    uint8_t reserved_identity8;
    /* Append-only global side of the logical transport conservation receipt. */
    uint64_t logical_flow_open_enqueues;
    uint64_t logical_checkpoint_enqueues;
    uint64_t flow_reopen_enqueues;
    uint64_t logical_flow_reopen_enqueues;
    uint64_t flow_reopen_checkpoint_pair_enqueues;
    /* Append-only checkpoint+periodic V2 trigger transport receipt. */
    uint64_t checkpoint_trigger_enqueues;
    uint64_t trigger_protocol_rejections;
    uint64_t invalid_checkpoint_packet_rejections;
    uint8_t trigger_protocol;
    uint8_t reserved_trigger8[7];
};

struct fk_student_shards;

/* Initialization may allocate/load; all subsequent APIs are allocation-free. */
struct fk_student_shards *fk_student_shards_create(
    const struct fk_student_shards_config *config,
    char *error,
    size_t error_capacity);

void fk_student_shards_destroy(struct fk_student_shards *shards);

/* Stable deployment mapping. worker_count is constrained to powers of two. */
uint16_t fk_student_shards_worker_for_event(
    uint64_t event_id,
    uint16_t worker_count);

bool fk_student_shards_enqueue_flow_open(
    struct fk_student_shards *shards,
    const struct fk_actor_session_result *association,
    const struct fk_actor_flow_identity *flow_identity,
    uint64_t observation_timestamp_ns,
    uint64_t enqueue_monotonic_ns);

/*
 * Logical-identity ingress.  The complete 64-bit logical_connection_id is
 * copied into the bounded worker command queue.  An instance is permanently
 * typed by its first successful v1 or v2 data enqueue; mixing the two API
 * families is rejected so a logical id can never be silently discarded.
 */
bool fk_student_shards_enqueue_flow_open_v2(
    struct fk_student_shards *shards,
    const struct fk_actor_session_result *association,
    const struct fk_actor_flow_identity_v2 *flow_identity,
    uint64_t observation_timestamp_ns,
    uint64_t enqueue_monotonic_ns);

bool fk_student_shards_enqueue_checkpoint(
    struct fk_student_shards *shards,
    const struct fk_actor_session_result *association,
    const struct fk_actor_flow_identity *flow_identity,
    uint64_t observation_timestamp_ns,
    const float *features,
    size_t feature_count,
    uint64_t enqueue_monotonic_ns);

bool fk_student_shards_enqueue_checkpoint_v2(
    struct fk_student_shards *shards,
    const struct fk_actor_session_result *association,
    const struct fk_actor_flow_identity_v2 *flow_identity,
    uint64_t observation_timestamp_ns,
    const float *features,
    size_t feature_count,
    uint64_t enqueue_monotonic_ns);

/*
 * Trigger-protocol V2 checkpoint transport.  checkpoint_packet is copied
 * into the bounded command entry and must be exactly 4, 8, 12, or 20.  An
 * instance is permanently typed by its first successful legacy or triggered
 * checkpoint enqueue; the two protocols cannot be mixed across shards.
 */
bool fk_student_shards_enqueue_checkpoint_triggered(
    struct fk_student_shards *shards,
    const struct fk_actor_session_result *association,
    const struct fk_actor_flow_identity *flow_identity,
    uint64_t observation_timestamp_ns,
    uint8_t checkpoint_packet,
    const float *features,
    size_t feature_count,
    uint64_t enqueue_monotonic_ns);

bool fk_student_shards_enqueue_checkpoint_triggered_v2(
    struct fk_student_shards *shards,
    const struct fk_actor_session_result *association,
    const struct fk_actor_flow_identity_v2 *flow_identity,
    uint64_t observation_timestamp_ns,
    uint8_t checkpoint_packet,
    const float *features,
    size_t feature_count,
    uint64_t enqueue_monotonic_ns);

/*
 * Atomically reserve and enqueue FLOW_REOPEN followed by its checkpoint on
 * the same event shard.  Queue slots and the feature payload are preflighted
 * before any command is visible, so a checkpoint can never be admitted
 * without its per-flow epoch binding (or vice versa).
 */
bool fk_student_shards_enqueue_flow_reopen_checkpoint(
    struct fk_student_shards *shards,
    const struct fk_actor_session_result *association,
    const struct fk_actor_flow_identity *flow_identity,
    uint64_t observation_timestamp_ns,
    const float *features,
    size_t feature_count,
    uint64_t enqueue_monotonic_ns);

bool fk_student_shards_enqueue_flow_reopen_checkpoint_v2(
    struct fk_student_shards *shards,
    const struct fk_actor_session_result *association,
    const struct fk_actor_flow_identity_v2 *flow_identity,
    uint64_t observation_timestamp_ns,
    const float *features,
    size_t feature_count,
    uint64_t enqueue_monotonic_ns);

bool fk_student_shards_enqueue_flow_reopen_checkpoint_triggered(
    struct fk_student_shards *shards,
    const struct fk_actor_session_result *association,
    const struct fk_actor_flow_identity *flow_identity,
    uint64_t observation_timestamp_ns,
    uint8_t checkpoint_packet,
    const float *features,
    size_t feature_count,
    uint64_t enqueue_monotonic_ns);

bool fk_student_shards_enqueue_flow_reopen_checkpoint_triggered_v2(
    struct fk_student_shards *shards,
    const struct fk_actor_session_result *association,
    const struct fk_actor_flow_identity_v2 *flow_identity,
    uint64_t observation_timestamp_ns,
    uint8_t checkpoint_packet,
    const float *features,
    size_t feature_count,
    uint64_t enqueue_monotonic_ns);

/*
 * Broadcasts are all-or-none: capacity is checked on every SPSC queue before
 * any worker receives the control command.  Equal non-final watermarks are a
 * no-op; an exact final watermark is still enqueued once for acknowledgement.
 */
bool fk_student_shards_broadcast_watermark(
    struct fk_student_shards *shards,
    uint64_t inclusive_watermark_ns,
    bool final_capture_flush,
    uint64_t enqueue_monotonic_ns);

/* Called only by the dedicated worker owning worker_index. */
bool fk_student_shards_process(
    struct fk_student_shards *shards,
    uint16_t worker_index,
    uint32_t maximum_commands,
    uint32_t *processed);

/* Called only by the association/result aggregator. */
bool fk_student_shards_pop_result(
    struct fk_student_shards *shards,
    uint16_t worker_index,
    struct fk_student_shard_result *result);

bool fk_student_shards_command_queues_empty(
    const struct fk_student_shards *shards);

bool fk_student_shards_result_queues_empty(
    const struct fk_student_shards *shards);

uint64_t fk_student_shards_command_queue_depth(
    const struct fk_student_shards *shards);

uint64_t fk_student_shards_result_queue_depth(
    const struct fk_student_shards *shards);

bool fk_student_shards_any_worker_failed(
    const struct fk_student_shards *shards);

bool fk_student_shards_final_flush_complete(
    const struct fk_student_shards *shards,
    uint64_t exact_capture_watermark_ns);

/* Full snapshot is valid only after every worker has joined.  Runtime gates
 * use the dedicated atomic query APIs above. */
bool fk_student_shards_get_stats(
    const struct fk_student_shards *shards,
    struct fk_student_shards_stats *stats);

bool fk_student_shards_get_metadata(
    const struct fk_student_shards *shards,
    struct fk_event_student_metadata *metadata);

#ifdef __cplusplus
}
#endif

#endif
