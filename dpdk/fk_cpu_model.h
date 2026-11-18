#ifndef FLOWKEEP_FK_CPU_MODEL_H
#define FLOWKEEP_FK_CPU_MODEL_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define FK_CPU_MODEL_SCHEMA_SHA256_CHARS 64u
#define FK_CPU_MODEL_MAX_FEATURES 512u
#define FK_CPU_MODEL_MAX_OUTPUTS 8u
#define FK_CPU_MODEL_MAX_TREES 2048u
#define FK_CPU_MODEL_MAX_NODES_PER_TREE 63u
#define FK_CPU_MODEL_MAX_FILE_BYTES (64u * 1024u * 1024u)

enum fk_cpu_model_role {
    FK_CPU_MODEL_ACTION_VALUE = 1,
    FK_CPU_MODEL_DETECTOR = 2,
    /* Single-output causal value of one explicit state transition. */
    FK_CPU_MODEL_TRANSITION_VALUE = 3,
};

enum fk_cpu_model_link {
    FK_CPU_MODEL_IDENTITY = 0,
    FK_CPU_MODEL_SIGMOID = 1,
};

struct fk_cpu_model_metadata {
    uint32_t format_version;
    enum fk_cpu_model_role role;
    enum fk_cpu_model_link link;
    uint32_t feature_count;
    uint32_t output_count;
    uint32_t linear_weight_count;
    uint32_t tree_count;
    char feature_schema_sha256[FK_CPU_MODEL_SCHEMA_SHA256_CHARS + 1u];
};

struct fk_cpu_model;

struct fk_cpu_model *fk_cpu_model_load(
    const char *path,
    char *error,
    size_t error_capacity);

/* Hash and parse the same opened file snapshot.  A non-null expected hash is
 * mandatory for deployable learned transition models. */
struct fk_cpu_model *fk_cpu_model_load_verified(
    const char *path,
    const char *expected_artifact_sha256,
    char *error,
    size_t error_capacity);

void fk_cpu_model_destroy(struct fk_cpu_model *model);

bool fk_cpu_model_predict(
    const struct fk_cpu_model *model,
    const float *features,
    size_t feature_count,
    float *outputs,
    size_t output_capacity);

bool fk_cpu_model_get_metadata(
    const struct fk_cpu_model *model,
    struct fk_cpu_model_metadata *metadata);

#ifdef __cplusplus
}
#endif

#endif
