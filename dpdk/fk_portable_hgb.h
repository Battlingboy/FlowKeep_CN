#ifndef FLOWKEEP_FK_PORTABLE_HGB_H
#define FLOWKEEP_FK_PORTABLE_HGB_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

struct fk_portable_hgb;

/* Load the numeric binary/regression FKMETA3 tree ABI.  expected_features=0
 * accepts the feature count carried by the file; a nonzero value fails
 * closed on schema mismatch. */
struct fk_portable_hgb *fk_portable_hgb_load(
    const char *path, uint32_t expected_features,
    char *error, size_t error_capacity);
void fk_portable_hgb_destroy(struct fk_portable_hgb *model);
uint32_t fk_portable_hgb_feature_count(const struct fk_portable_hgb *model);
bool fk_portable_hgb_predict(
    const struct fk_portable_hgb *model,
    const double *features, size_t feature_count,
    double *probability);

#ifdef __cplusplus
}
#endif

#endif
