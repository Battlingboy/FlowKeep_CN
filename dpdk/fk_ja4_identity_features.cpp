#include "fk_ja4_identity_features.h"

#include <cmath>

namespace {

static uint64_t splitmix64(uint64_t value) {
    value += UINT64_C(0x9e3779b97f4a7c15);
    value = (value ^ (value >> 30u)) * UINT64_C(0xbf58476d1ce4e5b9);
    value = (value ^ (value >> 27u)) * UINT64_C(0x94d049bb133111eb);
    return value ^ (value >> 31u);
}

static const uint64_t *identity_hashes(
        const fk_compact_ja4_state &state,
        uint64_t (&hashes)[FK_COMPACT_JA4_IDENTITY_HASHES]) {
    hashes[FK_JA4_HASH_CLIENT_CIPHER_SET] =
        state.client.cipher_set_hash;
    hashes[FK_JA4_HASH_CLIENT_EXTENSION_SET] =
        state.client.extension_set_hash;
    hashes[FK_JA4_HASH_CLIENT_SIGNATURE_SET] =
        state.client.signature_set_hash;
    hashes[FK_JA4_HASH_CLIENT_SERVER_NAME] =
        state.client.server_name_hash;
    hashes[FK_JA4_HASH_CLIENT_ALPN] =
        state.client.alpn_hash;
    hashes[FK_JA4_HASH_SERVER_CIPHER_SET] =
        state.server.cipher_set_hash;
    hashes[FK_JA4_HASH_SERVER_EXTENSION_SET] =
        state.server.extension_set_hash;
    hashes[FK_JA4_HASH_SERVER_SIGNATURE_SET] =
        state.server.signature_set_hash;
    hashes[FK_JA4_HASH_SERVER_SERVER_NAME] =
        state.server.server_name_hash;
    hashes[FK_JA4_HASH_SERVER_ALPN] =
        state.server.alpn_hash;
    return hashes;
}

}  // namespace

extern "C" {

bool fk_compact_ja4_encode_hash(
        uint64_t hash,
        float *limbs,
        size_t limb_capacity) {
    if (limbs == nullptr ||
        limb_capacity < FK_COMPACT_JA4_IDENTITY_LIMBS)
        return false;
    for (uint32_t limb = 0u;
         limb < FK_COMPACT_JA4_IDENTITY_LIMBS;
         ++limb) {
        const uint16_t value = static_cast<uint16_t>(
            hash >> (limb * 16u));
        limbs[limb] = static_cast<float>(value);
    }
    return true;
}

bool fk_compact_ja4_decode_hash(
        const float *limbs,
        size_t limb_count,
        uint64_t *hash) {
    if (limbs == nullptr || hash == nullptr ||
        limb_count < FK_COMPACT_JA4_IDENTITY_LIMBS)
        return false;
    uint64_t result = 0u;
    for (uint32_t limb = 0u;
         limb < FK_COMPACT_JA4_IDENTITY_LIMBS;
         ++limb) {
        const float value = limbs[limb];
        if (!std::isfinite(value) ||
            value < 0.0f || value > 65535.0f ||
            std::floor(value) != value)
            return false;
        result |=
            static_cast<uint64_t>(static_cast<uint16_t>(value))
            << (limb * 16u);
    }
    *hash = result;
    return true;
}

bool fk_compact_ja4_encode_identity(
        const fk_compact_ja4_state *state,
        float *features,
        size_t feature_capacity) {
    if (state == nullptr || features == nullptr ||
        feature_capacity < FK_COMPACT_JA4_IDENTITY_FEATURES)
        return false;
    uint64_t hashes[FK_COMPACT_JA4_IDENTITY_HASHES]{};
    identity_hashes(*state, hashes);
    for (uint32_t field = 0u;
         field < FK_COMPACT_JA4_IDENTITY_HASHES;
         ++field) {
        if (!fk_compact_ja4_encode_hash(
                hashes[field],
                features +
                    field * FK_COMPACT_JA4_IDENTITY_LIMBS,
                feature_capacity -
                    field * FK_COMPACT_JA4_IDENTITY_LIMBS))
            return false;
    }
    return true;
}

bool fk_compact_teacher_project_features(
        const float *features,
        size_t feature_count,
        float *projected,
        size_t projected_capacity) {
    if (features == nullptr || projected == nullptr ||
        feature_count != FK_COMPACT_DETECTOR_FEATURES_V4 ||
        projected_capacity < FK_COMPACT_TEACHER_PROJECTED_FEATURES)
        return false;
    for (uint32_t index = 0u;
         index < FK_COMPACT_DETECTOR_FEATURES_V3; ++index) {
        if (!std::isfinite(features[index]))
            return false;
        projected[index] = features[index];
    }
    constexpr uint64_t seeds[2] = {
        UINT64_C(0x243f6a8885a308d3),
        UINT64_C(0x13198a2e03707344),
    };
    for (uint32_t field = 0u;
         field < FK_COMPACT_JA4_IDENTITY_HASHES; ++field) {
        uint64_t hash = 0u;
        if (!fk_compact_ja4_decode_hash(
                features + FK_COMPACT_JA4_IDENTITY_BASE +
                    field * FK_COMPACT_JA4_IDENTITY_LIMBS,
                FK_COMPACT_JA4_IDENTITY_LIMBS,
                &hash))
            return false;
        const uint64_t salt =
            static_cast<uint64_t>(field) * UINT64_C(0x9e3779b97f4a7c15);
        for (uint32_t table = 0u; table < 2u; ++table) {
            uint32_t category = 0u;
            if (hash != 0u) {
                const uint32_t student_category = 1u + static_cast<uint32_t>(
                    splitmix64(hash ^ salt ^ seeds[table]) % 4096u);
                category = 1u + ((student_category - 1u) % 254u);
            }
            projected[FK_COMPACT_DETECTOR_FEATURES_V3 + field * 2u + table] =
                static_cast<float>(category);
        }
    }
    return true;
}

}  // extern "C"
