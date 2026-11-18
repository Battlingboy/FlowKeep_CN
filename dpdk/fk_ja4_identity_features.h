#ifndef FLOWKEEP_FK_JA4_IDENTITY_FEATURES_H
#define FLOWKEEP_FK_JA4_IDENTITY_FEATURES_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "fk_compact_flow_table.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Detector schema V4 keeps the frozen 119-field V3 vector as an exact prefix
 * and appends a lossless, float32-safe representation of every 64-bit
 * fingerprint hash already retained by fk_compact_ja4_state.
 *
 * A uint64_t is split into four little-endian uint16 limbs.  Every limb is an
 * integer in [0,65535], so IEEE-754 float32 represents it exactly.  This adds
 * no collision beyond the upstream 64-bit fingerprint hash and never casts a
 * 64-bit category identifier directly to float.
 */
#define FK_COMPACT_DETECTOR_FEATURES_V3 119u
#define FK_COMPACT_JA4_IDENTITY_BASE 119u
#define FK_COMPACT_JA4_IDENTITY_HASHES 10u
#define FK_COMPACT_JA4_IDENTITY_LIMBS 4u
#define FK_COMPACT_JA4_IDENTITY_FEATURES \
    (FK_COMPACT_JA4_IDENTITY_HASHES * FK_COMPACT_JA4_IDENTITY_LIMBS)
#define FK_COMPACT_DETECTOR_FEATURES_V4 \
    (FK_COMPACT_JA4_IDENTITY_BASE + FK_COMPACT_JA4_IDENTITY_FEATURES)
#define FK_COMPACT_TEACHER_PROJECTED_FEATURES 139u

enum fk_compact_ja4_identity_hash {
    FK_JA4_HASH_CLIENT_CIPHER_SET = 0,
    FK_JA4_HASH_CLIENT_EXTENSION_SET = 1,
    FK_JA4_HASH_CLIENT_SIGNATURE_SET = 2,
    FK_JA4_HASH_CLIENT_SERVER_NAME = 3,
    FK_JA4_HASH_CLIENT_ALPN = 4,
    FK_JA4_HASH_SERVER_CIPHER_SET = 5,
    FK_JA4_HASH_SERVER_EXTENSION_SET = 6,
    FK_JA4_HASH_SERVER_SIGNATURE_SET = 7,
    FK_JA4_HASH_SERVER_SERVER_NAME = 8,
    FK_JA4_HASH_SERVER_ALPN = 9,
};

bool fk_compact_ja4_encode_hash(
    uint64_t hash,
    float *limbs,
    size_t limb_capacity);

bool fk_compact_ja4_decode_hash(
    const float *limbs,
    size_t limb_count,
    uint64_t *hash);

bool fk_compact_ja4_encode_identity(
    const struct fk_compact_ja4_state *state,
    float *features,
    size_t feature_capacity);

/* Exact Python Teacher-v2 projection: 119 continuous + 20 bounded categories. */
bool fk_compact_teacher_project_features(
    const float *features,
    size_t feature_count,
    float *projected,
    size_t projected_capacity);

#ifdef __cplusplus
}
#endif

#endif
