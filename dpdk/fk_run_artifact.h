#ifndef FK_RUN_ARTIFACT_H
#define FK_RUN_ARTIFACT_H

#include <cstddef>
#include <cstdio>
#include <string>

/*
 * Immutable-input/output path gate used before starting a run.  Every final
 * output is required.  A null or empty immutable-input entry is treated as an
 * unused optional input, but a null/empty final output fails closed.
 *
 * The gate checks every final output and its "<final>.partial" path against
 * all other output paths and all immutable inputs.  Existing paths are
 * compared by (st_dev, st_ino), so hard-link and followed-symlink aliases are
 * detected.  Non-existing paths are compared as
 * realpath(parent-directory) + basename.
 */
struct fk_run_artifact_path_set {
    const char *const *immutable_inputs = nullptr;
    std::size_t immutable_input_count = 0u;
    const char *const *required_final_outputs = nullptr;
    std::size_t required_final_output_count = 0u;
};

bool fk_run_artifact_paths_are_safe(
    const fk_run_artifact_path_set &paths,
    std::string *error = nullptr);

/*
 * One atomic, immutable text receipt.  Call begin(), write through stream(),
 * and then commit().  A failed commit closes the stream but deliberately
 * leaves the .partial file in place for diagnosis.  It never replaces an
 * existing final file.
 *
 * The fields are public only so the object remains a small dependency-free
 * value type.  Callers must not modify them while active and should always
 * initialize a receipt through fk_atomic_text_receipt_begin().
 */
struct fk_atomic_text_receipt {
    FILE *file = nullptr;
    std::string final_path;
    std::string partial_path;
    bool active = false;
};

bool fk_atomic_text_receipt_begin(
    const char *final_path,
    fk_atomic_text_receipt *receipt,
    std::string *error = nullptr);

FILE *fk_atomic_text_receipt_stream(fk_atomic_text_receipt *receipt);

bool fk_atomic_text_receipt_commit(
    fk_atomic_text_receipt *receipt,
    std::string *error = nullptr);

/* Close an uncommitted stream without unlinking its partial path. */
bool fk_atomic_text_receipt_abandon(
    fk_atomic_text_receipt *receipt,
    std::string *error = nullptr);

#endif  // FK_RUN_ARTIFACT_H
