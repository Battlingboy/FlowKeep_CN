#ifndef FLOWKEEP_FK_DETECTION_EVENT_PATH_H
#define FLOWKEEP_FK_DETECTION_EVENT_PATH_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "fk_actor_session.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Immutable checkpoint presented before detector inference.  The first and
 * observation timestamps must share one event-time domain.  Every checkpoint,
 * including one that later receives a non-alert decision, enters association.
 */
struct fk_detection_event_checkpoint {
    struct fk_flow_key key;
    struct fk_actor_flow_identity flow_identity;
    uint64_t observation_timestamp_ns;
};

/* v2 checkpoint.  The v1 presentation prefix remains available for
 * diagnostics, while a non-zero logical_connection_id supplies the stable
 * QUIC identity used by actor/session association. */
struct fk_detection_event_checkpoint_v2 {
    struct fk_flow_key key;
    struct fk_actor_flow_identity_v2 flow_identity;
    uint64_t observation_timestamp_ns;
};

struct fk_detection_event_checkpoint_result {
    struct fk_actor_session_result association;
    bool associated;
};

struct fk_detection_event_decision_result {
    bool accepted;
    bool first_alert_for_event;
};

struct fk_detection_event_path_stats {
    uint64_t checkpoint_observations;
    uint64_t detector_decisions;
    uint64_t non_alert_decisions;
    uint64_t alert_windows;
    uint64_t alert_events;
    uint64_t association_failures;
    uint64_t timestamp_domain_rejections;
    uint64_t stale_decision_handles;
    uint64_t last_event_id;
    uint32_t last_event_generation;
    struct fk_actor_session_stats association;
};

struct fk_detection_event_path;

/*
 * The path and the nested actor-session table are placement-constructed in
 * caller-owned storage.  Initialization may allocate that storage;
 * observe_checkpoint() and record_decision() perform no allocation, locking,
 * file I/O, or model access.  One global association lcore must own the path.
 */
size_t fk_detection_event_path_storage_bytes(
    const struct fk_actor_session_config *config);

struct fk_detection_event_path *fk_detection_event_path_init(
    void *storage,
    size_t storage_bytes,
    const struct fk_actor_session_config *config,
    char *error,
    size_t error_capacity);

/*
 * Stage 1: associate every checkpoint before inference and return a stable
 * (event_id, slot, generation) handle for the detector request.  FLOW_OPEN
 * observations use this same stage but never proceed to detector inference.
 */
bool fk_detection_event_path_observe_checkpoint(
    struct fk_detection_event_path *path,
    const struct fk_detection_event_checkpoint *checkpoint,
    struct fk_detection_event_checkpoint_result *result);

bool fk_detection_event_path_observe_checkpoint_v2(
    struct fk_detection_event_path *path,
    const struct fk_detection_event_checkpoint_v2 *checkpoint,
    struct fk_detection_event_checkpoint_result *result);

/*
 * Resolve the truth-free canonical actor/pair identity for an active handle.
 * The lookup is allocation-free, read-only, and validates the complete
 * (event_id, slot, generation) tuple.  It is intended for emitting one
 * EVENT_BIND record immediately after an event is created; it never exposes
 * labels, scenarios, or dataset-specific truth identifiers.
 */
bool fk_detection_event_path_get_event_identity(
    const struct fk_detection_event_path *path,
    const struct fk_actor_session_result *association,
    struct fk_actor_event_identity *identity);

/*
 * Stage 2: consume the detector result using only the handle assigned by
 * stage 1.  This function never performs association.  A delayed result for
 * an expired or reused slot fails closed and increments stale_decision_handles.
 */
bool fk_detection_event_path_record_decision(
    struct fk_detection_event_path *path,
    const struct fk_actor_session_result *association,
    bool alert,
    struct fk_detection_event_decision_result *result);

bool fk_detection_event_path_get_stats(
    const struct fk_detection_event_path *path,
    struct fk_detection_event_path_stats *stats);

#ifdef __cplusplus
}
#endif

#endif
