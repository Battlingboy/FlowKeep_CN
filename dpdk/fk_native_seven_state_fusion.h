#ifndef FLOWKEEP_FK_NATIVE_SEVEN_STATE_FUSION_H
#define FLOWKEEP_FK_NATIVE_SEVEN_STATE_FUSION_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define FK_NATIVE_FUSION_RAW_FEATURES 159u
#define FK_NATIVE_FUSION_STATE_HEADS 7u
#define FK_NATIVE_FUSION_META_FEATURES 10u
#define FK_NATIVE_FUSION_MODEL_SHA256_BYTES 32u
#define FK_NATIVE_FUSION_BUNDLE_SHA256_BYTES 32u

struct fk_native_fusion_model;
struct fk_native_fusion_session;

struct fk_native_fusion_request {
    uint64_t sequence;
    uint64_t event_token;
    uint8_t source_mask;
    uint8_t reserved[7];
    float features[FK_NATIVE_FUSION_RAW_FEATURES];
};

struct fk_native_fusion_result {
    uint64_t sequence;
    uint64_t event_token;
    double score;
    uint8_t threshold_met;
    uint8_t first_alert;
    uint8_t alert_latched;
    uint8_t reserved[5];
};

/* Non-owning transactional state backend. Callbacks must not throw.
 * The owner must bind event-token namespace/model/schema across recovery.
 * commit must persist state and last_sequence atomically before returning.
 * On any failed callback the scorer calls rollback and rejects the batch.
 * This interface alone does not establish TTL, cross-event identity, or quotas.
 */
struct fk_native_fusion_state_backend {
    void *context;
    bool (*begin)(void *);
    bool (*load)(void *, uint64_t, double *, uint8_t *, bool *);
    bool (*save)(void *, uint64_t, const double *, uint8_t);
    bool (*commit)(void *, uint64_t);
    void (*rollback)(void *);
};

/* Explicit deferred submission ABI. submit preserves read-your-writes but
 * is NOT durable. The caller MUST fence before result publication or ACK.
 * Attach is startup-only; wait_durable may run concurrently with scoring. */
struct fk_native_fusion_submitted_backend {
    void *context;
    bool (*begin)(void *);
    bool (*load)(void *, uint64_t, double *, uint8_t *, bool *);
    bool (*save)(void *, uint64_t, const double *, uint8_t);
    bool (*submit)(void *, uint64_t);
    void (*rollback)(void *);
    bool (*wait_durable)(void *, uint64_t);
};
bool fk_native_fusion_session_attach_submitted_backend(
    struct fk_native_fusion_session *, const struct fk_native_fusion_submitted_backend *,
    char *, size_t);
bool fk_native_fusion_session_wait_history(struct fk_native_fusion_session *, uint64_t);

struct fk_native_fusion_phase_profile {
    uint64_t batches, rows;
    uint64_t meta_cache_hits, meta_cache_misses;
    /* validation, seven-head wall, history-fold, meta-fusion, history-submit */
    uint64_t phase_ns[5];
    /* Sum of parallel thread wall durations, not additive to phase_ns. */
    uint64_t head_thread_ns[7];
};
bool fk_native_fusion_session_profile(struct fk_native_fusion_session *,
    struct fk_native_fusion_phase_profile *);

bool fk_native_fusion_session_attach_backend(
    struct fk_native_fusion_session *session,
    const struct fk_native_fusion_state_backend *backend,
    bool has_committed_sequence, uint64_t committed_sequence,
    char *error, size_t error_capacity);

struct fk_native_fusion_metadata {
    uint32_t format_version;
    uint32_t ensemble_count;
    uint32_t tree_count;
    uint32_t node_count;
    uint32_t reference_length;
    uint32_t maximum_threads;
    double weights[4];
    double threshold;
    uint8_t source_model_sha256[FK_NATIVE_FUSION_MODEL_SHA256_BYTES];
    uint64_t model_bytes;
    uint64_t locked_bytes;
    uint8_t mlock_succeeded;
    uint8_t reserved[7];
};

struct fk_native_fusion_model *fk_native_fusion_model_load(
    const char *path,
    const uint8_t expected_bundle_sha256[FK_NATIVE_FUSION_BUNDLE_SHA256_BYTES],
    const uint8_t expected_source_model_sha256[
        FK_NATIVE_FUSION_MODEL_SHA256_BYTES],
    char *error,
    size_t error_capacity);

void fk_native_fusion_model_destroy(struct fk_native_fusion_model *model);

bool fk_native_fusion_model_get_metadata(
    const struct fk_native_fusion_model *model,
    struct fk_native_fusion_metadata *metadata);

/*
 * Explicitly pins the complete immutable model mapping in memory.  Loading a
 * model does not call this function: production online services can require
 * fail-closed residency without imposing that policy on offline callers.
 * The operation is idempotent and reports the exact number of locked model
 * bytes on success.
 */
bool fk_native_fusion_model_mlock(
    struct fk_native_fusion_model *model,
    uint64_t *locked_bytes,
    char *error,
    size_t error_capacity);

struct fk_native_fusion_session *fk_native_fusion_session_create(
    const struct fk_native_fusion_model *model,
    uint32_t maximum_threads,
    char *error,
    size_t error_capacity);

/* Replace only the legacy three-meta/rank fusion stage with one frozen
 * FKMETA3 history model over [seven maxima, mean, stddev, range]. The seven
 * state heads and their projection remain byte-identical. Startup only. */
bool fk_native_fusion_session_attach_history_meta(
    struct fk_native_fusion_session *session,
    const char *path,
    double threshold,
    char *error,
    size_t error_capacity);

void fk_native_fusion_session_destroy(struct fk_native_fusion_session *session);

/* Explicit in-memory-only mode: independent events may be evaluated in
 * frontier batches. Sequence order remains strict WITHIN each event and
 * within each submitted batch. Persistent history backends are forbidden. */
bool fk_native_fusion_session_enable_event_frontiers(
    struct fk_native_fusion_session *session);

/*
 * Requests must be strictly sequence ordered.  State-head work is parallel,
 * while per-event maxima are committed in that exact input order.  Results
 * preserve input order, allowing a caller to release one consecutive durable
 * ACK only after the matching result prefix has been persisted.
 */
/* Optional per-row history reset, before this row's maxima and alert latch.
 * reset_history has request_count entries, each 0 or 1; NULL means no resets.
 * Resets participate in the same atomic state transaction as the batch. */
bool fk_native_fusion_score_batch_with_resets(
    struct fk_native_fusion_session *session,
    const struct fk_native_fusion_request *requests,
    size_t request_count, uint32_t threads, const uint8_t *reset_history,
    struct fk_native_fusion_result *results, char *error, size_t error_capacity);

bool fk_native_fusion_score_batch(
    struct fk_native_fusion_session *session,
    const struct fk_native_fusion_request *requests,
    size_t request_count,
    uint32_t threads,
    struct fk_native_fusion_result *results,
    char *error,
    size_t error_capacity);

#ifdef __cplusplus
}
#endif

#endif
