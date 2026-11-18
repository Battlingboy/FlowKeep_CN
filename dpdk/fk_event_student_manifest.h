#ifndef FLOWKEEP_FK_EVENT_STUDENT_MANIFEST_H
#define FLOWKEEP_FK_EVENT_STUDENT_MANIFEST_H

#include "fk_event_student.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Hard input bounds for the startup-only deployment verifier. */
#define FK_EVENT_STUDENT_MANIFEST_MAX_BYTES (256u * 1024u)
#define FK_EVENT_STUDENT_MANIFEST_MAX_ARTIFACT_BYTES \
    (256u + 8u * 1024u * 1024u * 4u)
#define FK_EVENT_STUDENT_MANIFEST_MAX_FEATURE_SCHEMA_BYTES \
    (4u * 1024u * 1024u)
#define FK_EVENT_STUDENT_FORMAT_CHARS 6u
#define FK_EVENT_STUDENT_TRAINING_RUN_MODE_CHARS 20u

struct fk_event_student_manifest_request {
    const char *artifact_path;
    const char *manifest_path;
    const char *feature_schema_path;
    const char *expected_manifest_sha256;
    /* Formal callers fail closed on smoke/non-evidence-eligible exports. */
    bool require_formal_eligible;
};

/*
 * A successful receipt owns every string referenced by load_config.  Callers
 * must therefore keep this receipt alive while loading the model.  A copied
 * receipt must be validated again so its internal pointers are rebound.
 */
struct fk_event_student_manifest_receipt {
    struct fk_event_student_load_config load_config;

    char manifest_sha256[FK_EVENT_STUDENT_SHA256_CHARS + 1u];
    char artifact_sha256[FK_EVENT_STUDENT_SHA256_CHARS + 1u];
    char feature_schema_sha256[FK_EVENT_STUDENT_SHA256_CHARS + 1u];
    char source_state_sha256[FK_EVENT_STUDENT_SHA256_CHARS + 1u];
    char training_receipt_sha256[FK_EVENT_STUDENT_SHA256_CHARS + 1u];
    char format[FK_EVENT_STUDENT_FORMAT_CHARS + 1u];
    char training_run_mode[FK_EVENT_STUDENT_TRAINING_RUN_MODE_CHARS + 1u];

    uint64_t manifest_bytes;
    uint64_t artifact_bytes;
    uint64_t feature_schema_bytes;
    uint32_t manifest_fields;
    uint32_t format_version;
    uint32_t input_features;
    uint32_t maximum_flows_per_window;
    uint32_t hidden;
    uint32_t identity_embedding;
    float decision_threshold;
    bool locked_test_accessed;
    bool formal_evidence_eligible;
    bool manifest_sha256_matched;
    bool artifact_sha256_matched;
    bool feature_schema_sha256_matched;
};

/*
 * Validate only the three explicitly supplied files.  The function has no
 * dataset discovery or Locked-Test path.  On failure receipt is zeroed and a
 * fail-closed diagnostic is written when error/error_capacity permit it.
 */
bool fk_event_student_manifest_validate(
    const struct fk_event_student_manifest_request *request,
    struct fk_event_student_manifest_receipt *receipt,
    char *error,
    size_t error_capacity);

#ifdef __cplusplus
}
#endif

#endif
