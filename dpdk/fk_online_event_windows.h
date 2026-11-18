#ifndef FLOWKEEP_FK_ONLINE_EVENT_WINDOWS_H
#define FLOWKEEP_FK_ONLINE_EVENT_WINDOWS_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "fk_actor_session.h"
#include "fk_event_student.h"
#include "fk_stage_aware_aggregator.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Frozen online timer/state contract used by StrictCausalEventStudent V1. */
#define FK_ONLINE_EVENT_WINDOW_NS UINT64_C(30000000000)
#define FK_ONLINE_EVENT_STRIDE_NS UINT64_C(5000000000)
#define FK_ONLINE_EVENT_IDLE_NS UINT64_C(120000000000)
#define FK_ONLINE_EVENT_MAX_LIFETIME_NS UINT64_C(300000000000)
#define FK_ONLINE_EVENT_MAX_FLOWS 256u
#define FK_ONLINE_EVENT_CAUSAL_STATE_COLUMNS 7u

/*
 * Trigger protocol is part of the scored-window identity.  V1 is the legacy
 * periodic-only contract.  V2 adds an immediate score after each frozen
 * 4/8/12/20-packet checkpoint while retaining the same periodic timer grid.
 */
#define FK_ONLINE_EVENT_TRIGGER_PROTOCOL_PERIODIC_V1 1u
#define FK_ONLINE_EVENT_TRIGGER_PROTOCOL_CHECKPOINT_PERIODIC_V2 2u
#define FK_ONLINE_EVENT_TRIGGER_KIND_PERIODIC 1u
#define FK_ONLINE_EVENT_TRIGGER_KIND_CHECKPOINT 2u

struct fk_online_event_window_result {
    uint64_t event_id;
    uint64_t event_start_ns;
    uint64_t anchor_ns;
    uint32_t event_slot;
    uint32_t event_generation;
    uint32_t retained_flow_snapshots;
    float raw_window_logit;
    float prefix_event_logit;
    float operational_logit;
    float operational_probability;
    bool threshold_crossed;
    bool alert_latched;
    bool first_alert;
    /* Stable id is (event_id, event_generation, trigger_ordinal). */
    uint64_t trigger_ordinal;
    uint8_t trigger_protocol;
    uint8_t trigger_kind;
    /* Zero for periodic triggers; otherwise exactly 4, 8, 12, or 20. */
    uint8_t checkpoint_packet;
    /* Frozen V2 binary-log byte; must remain at its original offset. */
    uint8_t reserved_trigger8;
    uint8_t behavior_stage;
    uint8_t alert_state;
    bool alert_state_changed;
    bool correction_emitted;
    bool reopen_emitted;
    uint8_t reserved_stage8[3];
};

/*
 * Called synchronously by watermark advancement.  Returning false records an
 * output loss and permanently makes formal_completeness false.
 */
typedef bool (*fk_online_event_window_sink)(
    void *context,
    const struct fk_online_event_window_result *result);

/*
 * Optional production causal-calibrator route.  The window scheduler retains
 * one latest truth-free record per flow and presents exactly the records that
 * would have entered the frozen Student window.  original_action_mask is the
 * per-record policy action (0..7), not an effective/protocol-applicable mask.
 */
struct fk_online_event_causal_record_v1 {
    double record_score;
    float masked_state_columns[FK_ONLINE_EVENT_CAUSAL_STATE_COLUMNS];
    uint8_t original_action_mask;
    uint8_t reserved[7];
};

struct fk_online_event_causal_trigger_v1 {
    uint64_t event_id;
    uint64_t event_start_ns;
    uint64_t anchor_ns;
    uint64_t trigger_ordinal;
    uint32_t event_slot;
    uint32_t event_generation;
    uint32_t retained_records;
    uint8_t trigger_kind;
    uint8_t checkpoint_packet;
    uint8_t reserved[6];
};

typedef bool (*fk_online_event_causal_model_v1)(
    void *context,
    const struct fk_online_event_causal_trigger_v1 *trigger,
    const struct fk_online_event_causal_record_v1 *records,
    size_t record_count,
    float *probability);

struct fk_online_event_windows_config {
    uint32_t maximum_events;
    uint32_t maximum_flows_per_event;
    /* Global pool; normally identical to actor maximum_total_flows. */
    uint32_t maximum_total_flows;
    struct fk_event_student *student;
    fk_online_event_window_sink sink;
    void *sink_context;
    /* Exactly one inference route is selected: student or causal_model. */
    fk_online_event_causal_model_v1 causal_model;
    void *causal_model_context;
    float causal_decision_threshold;
    /* Sharded router supplies every exact T-1/T watermark explicitly. */
    bool external_watermarks_only;
    /* Optional; storage is charged exactly when enabled. */
    bool stage_aware_enabled;
    struct fk_stage_aware_policy stage_aware_policy;
};

struct fk_online_event_windows_stats {
    uint64_t flow_open_messages;
    uint64_t duplicate_flow_open_messages;
    uint64_t non_first_packet_flow_open_rejections;
    uint64_t noncreating_event_activation_rejections;
    uint64_t checkpoint_messages;
    uint64_t encoded_checkpoints;
    uint64_t encode_failures;
    uint64_t student_window_failures;
    uint64_t unopened_checkpoint_rejections;
    uint64_t stale_handle_rejections;
    uint64_t out_of_order_rejections;
    uint64_t closed_timestamp_rejections;
    uint64_t event_slots_activated;
    uint64_t event_slots_reused;
    uint64_t live_slot_reuse_conflicts;
    uint64_t idle_retirements;
    uint64_t lifetime_retirements;
    uint64_t explicit_retire_commands;
    uint64_t explicit_retirements;
    uint64_t explicit_retire_noops;
    uint64_t ticks_due;
    uint64_t empty_ticks;
    uint64_t inferred_windows;
    uint64_t first_alerts;
    uint64_t output_rejections;
    uint64_t flow_capacity_overflows;
    uint64_t watermark_advances;
    uint64_t watermark_step_calls;
    uint64_t partial_watermark_steps;
    uint64_t automatic_exclusive_advances;
    uint64_t due_heap_updates;
    uint64_t due_heap_peak;
    uint32_t active_events;
    uint32_t peak_active_events;
    uint32_t retained_flows;
    uint32_t peak_retained_flows;
    uint32_t maximum_events;
    uint32_t maximum_flows_per_event;
    uint32_t maximum_total_flows;
    uint64_t reserved_bytes;
    bool watermark_initialized;
    uint64_t inclusive_watermark_ns;
    bool formal_completeness;
    /* Same non-zero logical id presented through a new five tuple/incarnation. */
    uint64_t logical_rebind_confirmations;
    /* v1/v2 ingress entry points were mixed after the first successful one. */
    uint64_t identity_mode_rejections;
    /*
     * Explicit per-flow event-epoch rebinding.  FLOW_REOPEN is distinct from
     * the immutable first-packet FLOW_OPEN and never invokes the Student.
     */
    uint64_t flow_reopen_messages;
    uint64_t duplicate_flow_reopen_messages;
    uint64_t noncausal_flow_reopen_rejections;
    uint64_t flow_reopen_new_event_activations;
    uint64_t flow_reopen_existing_event_joins;
    /* Append-only checkpoint+periodic V2 trigger receipt. */
    uint64_t checkpoint_trigger_messages;
    uint64_t checkpoint_trigger_inferred_windows;
    uint64_t periodic_trigger_inferred_windows;
    uint64_t invalid_checkpoint_packet_rejections;
    uint64_t trigger_protocol_rejections;
    uint64_t trigger_ordinal_overflows;
    uint64_t snapshot_version_overflows;
    /* Scheduled periodic tick suppressed after an unchanged same-T score. */
    uint64_t same_timestamp_unchanged_periodic_coalesces;
    uint64_t causal_model_calls;
    uint64_t causal_model_failures;
    uint64_t causal_records_presented;
    uint64_t causal_mixed_mask_triggers;
    uint64_t provisional_alerts;
    uint64_t confirmed_alerts;
    uint64_t corrected_alerts;
    uint64_t reopened_alerts;
    uint8_t trigger_protocol;
    uint8_t reserved_trigger8[7];
    /* Append-only: valid successor after actor event-capacity retirement. */
    uint64_t capacity_supersession_retirements;
};

struct fk_online_event_windows;

/*
 * The returned size includes alignment padding.  Initialization and all hot
 * APIs use only caller-owned preallocated storage; no new/vector/lock/I/O is
 * used by this module.
 */
size_t fk_online_event_windows_storage_bytes(
    const struct fk_online_event_windows_config *config);

struct fk_online_event_windows *fk_online_event_windows_init(
    void *storage,
    size_t storage_bytes,
    const struct fk_online_event_windows_config *config,
    char *error,
    size_t error_capacity);

/*
 * FLOW_OPEN creates/looks up the exact flow identity and establishes the
 * event's start+5s tick grid.  It never calls the Student model.
 */
bool fk_online_event_windows_flow_open(
    struct fk_online_event_windows *windows,
    const struct fk_actor_session_result *association,
    const struct fk_actor_flow_identity *flow_identity,
    uint64_t observation_timestamp_ns);

/*
 * Logical-identity FLOW_OPEN.  For logical_connection_id != 0 the complete
 * 64-bit id is the flow identity and presentation is diagnostic.  A later
 * presentation for the same id confirms migration/readmission without
 * allocating or resetting the retained snapshot or event state.
 *
 * The first successful ingress call locks an instance to either the v1 or v2
 * entry-point family.  Mixing families thereafter fails closed, even when a
 * v2 identity happens to carry logical_connection_id == 0.
 */
bool fk_online_event_windows_flow_open_v2(
    struct fk_online_event_windows *windows,
    const struct fk_actor_session_result *association,
    const struct fk_actor_flow_identity_v2 *flow_identity,
    uint64_t observation_timestamp_ns);

/*
 * Re-establish one previously opened flow in its current actor-session event
 * epoch before processing the checkpoint at the same observation timestamp.
 * The immutable first_timestamp_ns is preserved and may precede the new event
 * start.  created=true activates a new event at observation_timestamp_ns;
 * created=false joins an already-active event for the actor.
 */
bool fk_online_event_windows_flow_reopen(
    struct fk_online_event_windows *windows,
    const struct fk_actor_session_result *association,
    const struct fk_actor_flow_identity *flow_identity,
    uint64_t observation_timestamp_ns);

bool fk_online_event_windows_flow_reopen_v2(
    struct fk_online_event_windows *windows,
    const struct fk_actor_session_result *association,
    const struct fk_actor_flow_identity_v2 *flow_identity,
    uint64_t observation_timestamp_ns);

/* Encode one 159D snapshot immediately and replace that flow's latest copy. */
bool fk_online_event_windows_checkpoint(
    struct fk_online_event_windows *windows,
    const struct fk_actor_session_result *association,
    const struct fk_actor_flow_identity *flow_identity,
    uint64_t observation_timestamp_ns,
    const float *features,
    size_t feature_count);

bool fk_online_event_windows_checkpoint_v2(
    struct fk_online_event_windows *windows,
    const struct fk_actor_session_result *association,
    const struct fk_actor_flow_identity_v2 *flow_identity,
    uint64_t observation_timestamp_ns,
    const float *features,
    size_t feature_count);

/*
 * Trigger-protocol V2 checkpoint entry points.  After the latest snapshot is
 * encoded and installed, the Student is invoked synchronously at the same
 * observation timestamp.  Calls are accepted only for the frozen packet
 * checkpoints 4/8/12/20.  Mixing legacy periodic-only checkpoint APIs with
 * these APIs on one instance fails closed.  If a periodic tick is due at the
 * exact same timestamp after the last checkpoint and no snapshot changed in
 * between, the scheduled tick is audited but causally coalesced: identical
 * evidence is not added to the event accumulator twice.
 */
bool fk_online_event_windows_checkpoint_triggered(
    struct fk_online_event_windows *windows,
    const struct fk_actor_session_result *association,
    const struct fk_actor_flow_identity *flow_identity,
    uint64_t observation_timestamp_ns,
    uint8_t checkpoint_packet,
    const float *features,
    size_t feature_count);

bool fk_online_event_windows_checkpoint_triggered_v2(
    struct fk_online_event_windows *windows,
    const struct fk_actor_session_result *association,
    const struct fk_actor_flow_identity_v2 *flow_identity,
    uint64_t observation_timestamp_ns,
    uint8_t checkpoint_packet,
    const float *features,
    size_t feature_count);

/*
 * Causal-calibrator checkpoint.  It is valid only when config.causal_model is
 * selected.  The 159D row is copied only as seven state-contract columns;
 * score and original action mask are retained with the latest flow snapshot.
 */
bool fk_online_event_windows_checkpoint_triggered_causal_v2(
    struct fk_online_event_windows *windows,
    const struct fk_actor_session_result *association,
    const struct fk_actor_flow_identity_v2 *flow_identity,
    uint64_t observation_timestamp_ns,
    uint8_t checkpoint_packet,
    const float *features,
    size_t feature_count,
    double record_score,
    uint8_t original_action_mask);

/*
 * Retire an exact immutable event handle before a global actor slot is reused
 * by an event routed to another Student worker.  An already timer-retired
 * handle is an idempotent success; retiring a different live generation fails
 * closed.  No pending tick is invented by this operation: the router must
 * broadcast the exact safe watermark before issuing the command.
 */
bool fk_online_event_windows_retire_event(
    struct fk_online_event_windows *windows,
    const struct fk_actor_session_result *association);

/*
 * Advance an inclusive event-time watermark.  The caller must ingest every
 * FLOW_OPEN/checkpoint at timestamp T before advancing through T.  Ingest APIs
 * automatically emit all anchors strictly before their observation time, so
 * a later latest-snapshot update can never rewrite an earlier tick.
 */
bool fk_online_event_windows_advance_watermark(
    struct fk_online_event_windows *windows,
    uint64_t inclusive_watermark_ns);

/*
 * Lossless resumable advancement for bounded output queues.  At most
 * max_due_ticks due anchors are consumed (empty anchors conservatively count
 * too).  A partial step keeps target fixed and sets complete=false; callers
 * must resume the same target before ingesting more data or changing target.
 */
bool fk_online_event_windows_advance_watermark_step(
    struct fk_online_event_windows *windows,
    uint64_t inclusive_watermark_ns,
    uint32_t max_due_ticks,
    bool *complete);

bool fk_online_event_windows_get_stats(
    const struct fk_online_event_windows *windows,
    struct fk_online_event_windows_stats *stats);

#ifdef __cplusplus
}
#endif

#endif
