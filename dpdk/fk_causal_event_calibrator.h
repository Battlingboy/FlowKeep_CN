#ifndef FLOWKEEP_FK_CAUSAL_EVENT_CALIBRATOR_H
#define FLOWKEEP_FK_CAUSAL_EVENT_CALIBRATOR_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define FK_CAUSAL_EVENT_CALIBRATOR_FEATURES 32u
#define FK_CAUSAL_EVENT_CALIBRATOR_HIDDEN 16u
#define FK_CAUSAL_EVENT_CALIBRATOR_SHA256_CHARS 64u
#define FK_CAUSAL_EVENT_CALIBRATOR_MAX_FILE_BYTES (128u * 1024u)

struct fk_causal_event_calibrator_metadata_v1 {
    uint32_t format_version;
    uint32_t feature_count;
    uint32_t hidden_count;
    char source_npz_sha256[FK_CAUSAL_EVENT_CALIBRATOR_SHA256_CHARS + 1u];
    char feature_contract_sha256[
        FK_CAUSAL_EVENT_CALIBRATOR_SHA256_CHARS + 1u];
};

struct fk_causal_event_calibrator;

/* Startup-only loader for the frozen 32x16x1 ReLU artifact. */
struct fk_causal_event_calibrator *fk_causal_event_calibrator_load(
    const char *path,
    const char *expected_source_npz_sha256,
    const char *expected_feature_contract_sha256,
    char *error,
    size_t error_capacity);

void fk_causal_event_calibrator_destroy(
    struct fk_causal_event_calibrator *model);

bool fk_causal_event_calibrator_predict(
    const struct fk_causal_event_calibrator *model,
    const float features[FK_CAUSAL_EVENT_CALIBRATOR_FEATURES],
    float *probability);

bool fk_causal_event_calibrator_get_metadata(
    const struct fk_causal_event_calibrator *model,
    struct fk_causal_event_calibrator_metadata_v1 *metadata);

size_t fk_causal_event_calibrator_reserved_bytes(
    const struct fk_causal_event_calibrator *model);

#ifdef __cplusplus
}
#endif

#endif
