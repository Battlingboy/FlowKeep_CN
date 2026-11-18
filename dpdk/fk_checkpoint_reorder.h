#ifndef FLOWKEEP_FK_CHECKPOINT_REORDER_H
#define FLOWKEEP_FK_CHECKPOINT_REORDER_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "fk_actor_session.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Immutable handoff from an RX lcore to the single global association lcore.
 * Event time and physical monotonic time are deliberately separate domains.
 */
enum fk_checkpoint_message_kind {
    FK_CHECKPOINT_MESSAGE_FLOW_OPEN = 1,
    FK_CHECKPOINT_MESSAGE_DETECTION_CHECKPOINT = 2,
};

struct fk_checkpoint_envelope {
    struct fk_flow_key key;
    struct fk_actor_flow_identity flow_identity;
    uint64_t observation_timestamp_ns;
    uint64_t physical_ingress_timestamp_ns;
    uint64_t association_enqueue_timestamp_ns;
    uint64_t input_sequence;
    uint32_t checkpoint_payload_slot;
    uint16_t shard;
    uint8_t message_kind;
    /* Historical v1/v2 ABI: this byte is reserved and must remain zero. */
    uint8_t reserved;
};

/*
 * Logical-identity ABI.  `presentation` remains the immutable legacy record
 * used for ordering and diagnostics.  A zero logical_connection_id denotes
 * the legacy TCP/TLS presentation identity; a nonzero value is the complete
 * generation-safe QUIC logical-connection identity and must never be
 * truncated or reconstructed from a FlowTable slot.
 */
#define FK_CHECKPOINT_ENVELOPE_V2_ABI_VERSION 2u
// Historical API symbol retained; this candidate's in-process layout is v4.
#define FK_CHECKPOINT_ENVELOPE_V3_ABI_VERSION 4u
#define FK_CHECKPOINT_IDENTITY_ABI_MODE_V1 1u
#define FK_CHECKPOINT_IDENTITY_ABI_MODE_V2 2u
#define FK_CHECKPOINT_IDENTITY_ABI_MODE_V3 3u

enum fk_checkpoint_flow_control_kind {
    FK_CHECKPOINT_FLOW_CONTROL_NONE = 0,
    FK_CHECKPOINT_FLOW_CONTROL_OPEN = 1,
    FK_CHECKPOINT_FLOW_CONTROL_CONTINUE = 2,
};

enum fk_checkpoint_reorder_admission_mode {
    /* Backward-compatible mode.  A nonzero maximum sequence enables the
     * finite exact occupancy index used by older replay validation. */
    FK_CHECKPOINT_REORDER_ADMISSION_LEGACY = 0,
    FK_CHECKPOINT_REORDER_ADMISSION_FINITE_INDEXED = 1,
    /* Atomic v2/v3 batches only.  Every batch is internally strictly increasing
     * and its first sequence must exceed the last sequence ever admitted.
     * Gaps are legal.  This proves order/uniqueness with O(1) state. */
    FK_CHECKPOINT_REORDER_ADMISSION_STREAMING_MONOTONIC_V2 = 2,
};

struct fk_checkpoint_envelope_v2 {
    struct fk_checkpoint_envelope presentation;
    uint64_t logical_connection_id;
};

/*
 * Explicit generation-control ABI.  The complete v2 envelope is a stable
 * prefix, so historical v2 records remain readable.  `presentation.reserved`
 * remains zero; FLOW_OPEN versus FLOW_CONTINUE is carried only here and can
 * no longer be silently interpreted as a legacy FLOW_OPEN.
 */
struct fk_checkpoint_envelope_v3 {
    struct fk_checkpoint_envelope presentation;
    uint64_t logical_connection_id;
    uint8_t control_kind;
    uint8_t reserved0[3];
    uint32_t predecessor_flow_index;
    uint32_t predecessor_flow_generation;
    uint32_t predecessor_last_checkpoint_packet;
    /*
     * Receiver-stage observability (diagnostic-only, same-sequence).  These
     * split the physical_ingress -> association_enqueue interval into
     * ordered-slot residence, owner packet-ring residence, and owner
     * processing/message construction.  Zero means the boundary is not
     * applicable (direct-RX path) or was not observed; the existing
     * presentation timestamp ordering contract remains authoritative.
     */
    uint64_t ordered_dispatch_timestamp_ns;
    uint64_t owner_dequeue_timestamp_ns;
    /* Candidate-only in-process extension, bound to the new RX executable.
     * Preserve the immutable Core prefix through owner -> reorder -> SHM.
     * No pointer into a recyclable FlowTable slot may cross this handoff. */
    uint32_t coverage_prefix_present;
    float coverage_prefix[159];
};

struct fk_checkpoint_reorder_config {
    uint32_t capacity;
    uint64_t trace_horizon_ns;
    uint64_t maximum_wait_ns;
    /*
     * Optional exact buffered-input-sequence domain.  Zero keeps the legacy
     * interface footprint.  A nonzero value reserves one occupancy bit for
     * every input sequence in [0, value), making duplicate admission O(1).
     * Atomic batch admission requires this index so it never hides an
     * O(capacity) scan on the association hot path.
     */
#ifdef __cplusplus
    uint64_t maximum_input_sequence_exclusive = 0u;
    uint8_t admission_mode = FK_CHECKPOINT_REORDER_ADMISSION_LEGACY;
    uint8_t reserved0[7]{};
#else
    uint64_t maximum_input_sequence_exclusive;
    uint8_t admission_mode;
    uint8_t reserved0[7];
#endif
};

enum fk_checkpoint_release_reason {
    FK_CHECKPOINT_RELEASE_NONE = 0,
    FK_CHECKPOINT_RELEASE_WATERMARK = 1,
    FK_CHECKPOINT_RELEASE_MAXIMUM_WAIT = 2,
    FK_CHECKPOINT_RELEASE_INPUT_CLOSED = 3,
    FK_CHECKPOINT_RELEASE_CAPACITY = 4,
    FK_CHECKPOINT_RELEASE_EXACT_SEQUENCE = 5,
};

struct fk_checkpoint_reorder_stats {
    uint64_t inserted;
    uint64_t released;
    uint64_t full_rejections;
    uint64_t watermark_releases;
    uint64_t maximum_wait_releases;
    uint64_t input_closed_releases;
    uint64_t capacity_releases;
    uint64_t exact_sequence_releases;
    uint64_t late_inputs;
    uint64_t release_order_violations;
    uint64_t input_sequence_order_violations;
    uint64_t maximum_trace_observation_ns;
    uint64_t last_released_observation_ns;
    uint64_t last_released_input_sequence;
    uint32_t current_depth;
    uint32_t peak_depth;
    uint64_t reserved_bytes;
    uint64_t identity_mode_rejections;
    uint64_t batch_push_attempts;
    uint64_t batch_pushes;
    uint64_t batch_items_inserted;
    uint64_t batch_invalid_rejections;
    uint64_t duplicate_input_sequence_rejections;
    uint64_t input_sequence_domain_rejections;
    uint64_t batch_identity_rejections;
    uint64_t batch_capacity_rejections;
    uint64_t batch_duplicate_rejections;
    uint64_t batch_sequence_domain_rejections;
    uint64_t batch_streaming_order_rejections;
    uint64_t batch_internal_rejections;
    uint64_t batch_single_commits;
    uint64_t batch_double_commits;
    uint64_t batch_counter_overflows;
    uint64_t maximum_input_sequence_exclusive;
    uint64_t sequence_index_bytes;
    uint64_t sequence_index_probes;
    uint64_t sequence_index_peak_probes_per_lookup;
    uint64_t sequence_index_active;
    uint64_t sequence_index_peak_active;
    uint64_t sequence_index_integrity_failures;
    uint64_t streaming_last_admitted_input_sequence;
    uint64_t streaming_batch_commits;
    uint64_t streaming_items_admitted;
    uint64_t streaming_order_rejections;
    uint64_t streaming_api_rejections;
    uint32_t capacity;
    uint32_t entry_bytes;
    uint8_t identity_abi_mode;
    uint8_t sequence_index_enabled;
    uint8_t batch_accounting_conserved;
    uint8_t admission_mode;
    uint8_t streaming_has_last_admitted;
    uint8_t streaming_accounting_conserved;
    uint8_t reserved0[5];
};

struct fk_checkpoint_reorder;

size_t fk_checkpoint_reorder_storage_bytes(
    const struct fk_checkpoint_reorder_config *config);

struct fk_checkpoint_reorder *fk_checkpoint_reorder_init(
    void *storage,
    size_t storage_bytes,
    const struct fk_checkpoint_reorder_config *config,
    char *error,
    size_t error_capacity);

bool fk_checkpoint_reorder_push(
    struct fk_checkpoint_reorder *reorder,
    const struct fk_checkpoint_envelope *checkpoint);

/* A reorder instance is permanently typed by its first successful push.
 * Mixing v1, v2, and v3 APIs is rejected so logical/control semantics can
 * never be silently consumed through an older pop API. */
bool fk_checkpoint_reorder_push_v2(
    struct fk_checkpoint_reorder *reorder,
    const struct fk_checkpoint_envelope_v2 *checkpoint);

bool fk_checkpoint_reorder_push_v3(
    struct fk_checkpoint_reorder *reorder,
    const struct fk_checkpoint_envelope_v3 *checkpoint);

/* Atomic V2 admission for the one or two association messages produced by
 * one packet.  The function preflights identity mode, total capacity, free
 * slots, and duplicate input_sequence values (both within the batch and
 * against an exact O(1) occupancy index) before changing the contents.
 * FINITE_INDEXED/legacy exact replay must provide
 * maximum_input_sequence_exclusive. STREAMING_MONOTONIC_V2 instead forbids
 * that bitmap and proves uniqueness/order from one last-admitted sequence.
 * Failure inserts neither message and does not select an identity mode.
 * Rejection counters may still advance as audit evidence. */
bool fk_checkpoint_reorder_push_batch_v2(
    struct fk_checkpoint_reorder *reorder,
    const struct fk_checkpoint_envelope_v2 *checkpoints,
    uint8_t count);

bool fk_checkpoint_reorder_push_batch_v3(
    struct fk_checkpoint_reorder *reorder,
    const struct fk_checkpoint_envelope_v3 *checkpoints,
    uint8_t count);

/*
 * Release the globally earliest (observation_timestamp_ns, input_sequence)
 * compact association message when the trace watermark advances, any
 * buffered item reaches the physical maximum-wait bound, or input_closed
 * requests a sorted flush. Detector feature vectors are deliberately not
 * stored or copied here; checkpoint_payload_slot refers to caller-owned
 * bounded storage.
 */
bool fk_checkpoint_reorder_pop_ready(
    struct fk_checkpoint_reorder *reorder,
    uint64_t physical_now_ns,
    bool input_closed,
    struct fk_checkpoint_envelope *checkpoint,
    enum fk_checkpoint_release_reason *reason);

bool fk_checkpoint_reorder_pop_ready_v2(
    struct fk_checkpoint_reorder *reorder,
    uint64_t physical_now_ns,
    bool input_closed,
    struct fk_checkpoint_envelope_v2 *checkpoint,
    enum fk_checkpoint_release_reason *reason);

bool fk_checkpoint_reorder_pop_ready_v3(
    struct fk_checkpoint_reorder *reorder,
    uint64_t physical_now_ns,
    bool input_closed,
    struct fk_checkpoint_envelope_v3 *checkpoint,
    enum fk_checkpoint_release_reason *reason);

/*
 * Formal exact-trace release. input_sequence_exclusive is supplied by the
 * per-packet message barrier and proves that every association message below
 * the boundary has been published and ingested. Unlike the heuristic
 * trace-horizon/maximum-wait path, this function never releases a later
 * input sequence while an earlier buffered sequence exists.
 */
bool fk_checkpoint_reorder_pop_sequence_ready(
    struct fk_checkpoint_reorder *reorder,
    uint64_t input_sequence_exclusive,
    struct fk_checkpoint_envelope *checkpoint,
    enum fk_checkpoint_release_reason *reason);

bool fk_checkpoint_reorder_pop_sequence_ready_v2(
    struct fk_checkpoint_reorder *reorder,
    uint64_t input_sequence_exclusive,
    struct fk_checkpoint_envelope_v2 *checkpoint,
    enum fk_checkpoint_release_reason *reason);

bool fk_checkpoint_reorder_pop_sequence_ready_v3(
    struct fk_checkpoint_reorder *reorder,
    uint64_t input_sequence_exclusive,
    struct fk_checkpoint_envelope_v3 *checkpoint,
    enum fk_checkpoint_release_reason *reason);

/* Release the globally earliest item to make room after a bounded-buffer hit. */
bool fk_checkpoint_reorder_force_pop(
    struct fk_checkpoint_reorder *reorder,
    struct fk_checkpoint_envelope *checkpoint,
    enum fk_checkpoint_release_reason *reason);

bool fk_checkpoint_reorder_force_pop_v2(
    struct fk_checkpoint_reorder *reorder,
    struct fk_checkpoint_envelope_v2 *checkpoint,
    enum fk_checkpoint_release_reason *reason);

bool fk_checkpoint_reorder_force_pop_v3(
    struct fk_checkpoint_reorder *reorder,
    struct fk_checkpoint_envelope_v3 *checkpoint,
    enum fk_checkpoint_release_reason *reason);

uint32_t fk_checkpoint_reorder_count(
    const struct fk_checkpoint_reorder *reorder);

bool fk_checkpoint_reorder_get_stats(
    const struct fk_checkpoint_reorder *reorder,
    struct fk_checkpoint_reorder_stats *stats);

/* Placement destruction is legal only when every admitted envelope has been
 * released and all exact occupancy ownership is empty.  Failure leaves the
 * object live. */
bool fk_checkpoint_reorder_destroy_checked(
    struct fk_checkpoint_reorder *reorder);

#ifdef __cplusplus
}
#endif

#endif
