#ifndef FLOWKEEP_FK_EVENT_STUDENT_H
#define FLOWKEEP_FK_EVENT_STUDENT_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Frozen StrictCausalEventStudent V1 inference contract. */
#define FK_EVENT_STUDENT_FORMAT_VERSION 1u
#define FK_EVENT_STUDENT_CONTINUOUS_FEATURES 119u
#define FK_EVENT_STUDENT_INPUT_FEATURES 159u
#define FK_EVENT_STUDENT_JA4_FIELDS 10u
#define FK_EVENT_STUDENT_JA4_TABLES 2u
#define FK_EVENT_STUDENT_JA4_VOCABULARY 4097u
#define FK_EVENT_STUDENT_MAX_HIDDEN 128u
#define FK_EVENT_STUDENT_MAX_IDENTITY_EMBEDDING 16u
#define FK_EVENT_STUDENT_MAX_FLOWS_PER_WINDOW 256u
#define FK_EVENT_STUDENT_SHA256_CHARS 64u
#define FK_EVENT_STUDENT_INVALID_LOGIT (-10000.0f)

/*
 * Loading is deliberately fail closed.  All three expected digests are
 * mandatory lowercase SHA-256 strings supplied by the frozen deployment
 * receipt, not learned from the artifact being checked.
 */
struct fk_event_student_load_config {
    const char *expected_artifact_sha256;
    const char *expected_feature_schema_sha256;
    const char *expected_source_state_sha256;
    uint32_t expected_hidden;
    uint32_t expected_identity_embedding;
};

struct fk_event_student_metadata {
    uint32_t format_version;
    uint32_t continuous_features;
    uint32_t input_features;
    uint32_t ja4_fields;
    uint32_t ja4_tables;
    uint32_t ja4_vocabulary;
    uint32_t hidden;
    uint32_t identity_embedding;
    uint32_t event_hidden;
    uint32_t parameter_floats;
    float layer_norm_epsilon;
    float decision_threshold;
    char artifact_sha256[FK_EVENT_STUDENT_SHA256_CHARS + 1u];
    char feature_schema_sha256[FK_EVENT_STUDENT_SHA256_CHARS + 1u];
    char architecture_sha256[FK_EVENT_STUDENT_SHA256_CHARS + 1u];
    char source_state_sha256[FK_EVENT_STUDENT_SHA256_CHARS + 1u];
    char payload_sha256[FK_EVENT_STUDENT_SHA256_CHARS + 1u];
};

struct fk_event_student;

/*
 * A successfully loaded model is immutable.  All inference entry points take
 * const model pointers and keep scratch state on the caller's stack or in the
 * caller-owned window/event structures.  Concurrent inference from multiple
 * workers is therefore supported as long as destroy() runs only after every
 * worker has joined.
 */

/* Auditable pure FKDETV5 uint16x4 -> double-SplitMix category transform. */
bool fk_event_student_identity_categories(
    const float *features,
    size_t feature_count,
    uint16_t *categories,
    size_t category_capacity);

/* A fixed-size flow/window vector; only metadata.hidden entries are live. */
struct fk_event_student_embedding {
    float values[FK_EVENT_STUDENT_MAX_HIDDEN];
};

/*
 * Exact streaming softmax accumulator for one causal 30-second window.
 * The structure is caller-owned and introduces no hot-path allocation.
 */
struct fk_event_student_window_state {
    float maximum_attention_logit;
    float denominator;
    float weighted_sum[FK_EVENT_STUDENT_MAX_HIDDEN];
    uint32_t valid_flows;
};

/*
 * Exact streaming softmax accumulator over the causal prefix of windows.
 * operational_logit implements the deployment alert latch's score statistic:
 * max(prefix_event_logit[0..t]); thresholding/latching remains caller-owned.
 */
struct fk_event_student_event_state {
    float maximum_attention_logit;
    float denominator;
    float weighted_sum[FK_EVENT_STUDENT_MAX_HIDDEN];
    float operational_logit;
    uint32_t windows_seen;
    uint32_t valid_windows;
};

struct fk_event_student *fk_event_student_load(
    const char *path,
    const struct fk_event_student_load_config *config,
    char *error,
    size_t error_capacity);

void fk_event_student_destroy(struct fk_event_student *model);

bool fk_event_student_get_metadata(
    const struct fk_event_student *model,
    struct fk_event_student_metadata *metadata);

/*
 * Encode one masked FKDETV5 snapshot.  The first 119 values follow V4's
 * continuous schema.  Values 119..158 are ten little-endian uint16x4 JA4
 * identity hashes; they are reconstructed and double-SplitMix categorized,
 * never interpreted as continuous quantities.
 */
bool fk_event_student_encode_flow(
    const struct fk_event_student *model,
    const float *features,
    size_t feature_count,
    struct fk_event_student_embedding *encoded);

void fk_event_student_window_reset(
    struct fk_event_student_window_state *state);

/* instance_mask must be finite and non-negative; zero means absent. */
bool fk_event_student_window_add(
    const struct fk_event_student *model,
    struct fk_event_student_window_state *state,
    const struct fk_event_student_embedding *encoded,
    float instance_mask);

/* Returns false for a window with no retained evidence. */
bool fk_event_student_window_finish(
    const struct fk_event_student *model,
    const struct fk_event_student_window_state *state,
    struct fk_event_student_embedding *window_embedding,
    float *raw_window_logit);

void fk_event_student_event_reset(
    struct fk_event_student_event_state *state);

/*
 * Add one window in event-time order.  A zero window_mask leaves the prefix
 * unchanged, matching PyTorch's masked prefix semantics.  prefix_event_logit
 * is -10000 until the first valid window.
 */
bool fk_event_student_event_add(
    const struct fk_event_student *model,
    struct fk_event_student_event_state *state,
    const struct fk_event_student_embedding *window_embedding,
    float window_mask,
    float *prefix_event_logit,
    float *operational_logit);

/* Stable sigmoid helper for applying the frozen threshold outside the model. */
float fk_event_student_sigmoid(float logit);

#ifdef __cplusplus
}
#endif

#endif
