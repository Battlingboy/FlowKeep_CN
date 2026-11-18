#include "fk_quic_initial_auth.h"

#include <algorithm>
#include <array>
#include <cstring>
#include <limits>

#define OPENSSL_SUPPRESS_DEPRECATED
#include <openssl/aes.h>
#include <openssl/crypto.h>
#include <openssl/sha.h>

namespace {

constexpr size_t kSha256Bytes = 32u;
constexpr size_t kSha256BlockBytes = 64u;
constexpr size_t kAesBlockBytes = 16u;
constexpr size_t kAeadTagBytes = 16u;
constexpr size_t kIvBytes = 12u;

static_assert(
    sizeof(fk_quic_initial_auth_result) == FK_QUIC_INITIAL_AUTH_RESULT_BYTES,
    "Initial auth result C ABI changed");
static_assert(
    sizeof(fk_quic_initial_clear_bounds_v1) ==
        FK_QUIC_INITIAL_CLEAR_BOUNDS_V1_BYTES,
    "Initial clear-bounds C ABI changed");

constexpr std::array<uint8_t, 20> kV1InitialSalt{
    0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17,
    0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a,
};

constexpr std::array<uint8_t, 20> kV2InitialSalt{
    0x0d, 0xed, 0xe3, 0xde, 0xf7, 0x00, 0xa6, 0xdb, 0x81, 0x93,
    0x81, 0xbe, 0x6e, 0x26, 0x9d, 0xcb, 0xf9, 0xbd, 0x2e, 0xd9,
};

struct InitialKeys {
    std::array<uint8_t, 16> key{};
    std::array<uint8_t, kIvBytes> iv{};
    std::array<uint8_t, 16> hp{};
};

struct GhashState {
    std::array<uint8_t, kAesBlockBytes> hash_subkey{};
    std::array<uint8_t, kAesBlockBytes> state{};
    std::array<uint8_t, kAesBlockBytes> partial{};
    size_t partial_bytes{0};
};

void secure_clean(void *value, size_t bytes) {
    if (value != nullptr && bytes != 0u) {
        OPENSSL_cleanse(value, bytes);
    }
}

bool sha256_parts(
    const uint8_t *first,
    size_t first_bytes,
    const uint8_t *second,
    size_t second_bytes,
    uint8_t output[kSha256Bytes]) {
    SHA256_CTX context{};
    if (SHA256_Init(&context) != 1) {
        return false;
    }
    const bool ok =
        (first_bytes == 0u || SHA256_Update(&context, first, first_bytes) == 1) &&
        (second_bytes == 0u || SHA256_Update(&context, second, second_bytes) == 1) &&
        SHA256_Final(output, &context) == 1;
    secure_clean(&context, sizeof(context));
    return ok;
}

bool hmac_sha256_parts(
    const uint8_t *key,
    size_t key_bytes,
    const uint8_t *first,
    size_t first_bytes,
    const uint8_t *second,
    size_t second_bytes,
    uint8_t output[kSha256Bytes]) {
    std::array<uint8_t, kSha256BlockBytes> normalized_key{};
    std::array<uint8_t, kSha256BlockBytes> inner_pad{};
    std::array<uint8_t, kSha256BlockBytes> outer_pad{};
    std::array<uint8_t, kSha256Bytes> hashed_key{};
    std::array<uint8_t, kSha256Bytes> inner_hash{};

    if (key_bytes > normalized_key.size()) {
        if (!sha256_parts(key, key_bytes, nullptr, 0u, hashed_key.data())) {
            return false;
        }
        std::memcpy(normalized_key.data(), hashed_key.data(), hashed_key.size());
    } else if (key_bytes != 0u) {
        std::memcpy(normalized_key.data(), key, key_bytes);
    }
    for (size_t index = 0; index < normalized_key.size(); ++index) {
        inner_pad[index] = static_cast<uint8_t>(normalized_key[index] ^ 0x36u);
        outer_pad[index] = static_cast<uint8_t>(normalized_key[index] ^ 0x5cu);
    }

    SHA256_CTX context{};
    bool ok = SHA256_Init(&context) == 1 &&
              SHA256_Update(&context, inner_pad.data(), inner_pad.size()) == 1 &&
              (first_bytes == 0u || SHA256_Update(&context, first, first_bytes) == 1) &&
              (second_bytes == 0u || SHA256_Update(&context, second, second_bytes) == 1) &&
              SHA256_Final(inner_hash.data(), &context) == 1;
    secure_clean(&context, sizeof(context));
    if (ok) {
        ok = sha256_parts(
            outer_pad.data(), outer_pad.size(),
            inner_hash.data(), inner_hash.size(), output);
    }

    secure_clean(normalized_key.data(), normalized_key.size());
    secure_clean(inner_pad.data(), inner_pad.size());
    secure_clean(outer_pad.data(), outer_pad.size());
    secure_clean(hashed_key.data(), hashed_key.size());
    secure_clean(inner_hash.data(), inner_hash.size());
    return ok;
}

bool hkdf_expand_label(
    const uint8_t secret[kSha256Bytes],
    const char *label,
    uint8_t *output,
    size_t output_bytes) {
    constexpr char kPrefix[] = "tls13 ";
    std::array<uint8_t, 64> info{};
    const size_t prefix_bytes = sizeof(kPrefix) - 1u;
    const size_t label_bytes = std::strlen(label);
    const size_t complete_label_bytes = prefix_bytes + label_bytes;
    if (output_bytes == 0u || output_bytes > kSha256Bytes ||
        complete_label_bytes > 255u || 4u + complete_label_bytes > info.size()) {
        return false;
    }

    size_t offset = 0u;
    info[offset++] = static_cast<uint8_t>((output_bytes >> 8u) & 0xffu);
    info[offset++] = static_cast<uint8_t>(output_bytes & 0xffu);
    info[offset++] = static_cast<uint8_t>(complete_label_bytes);
    std::memcpy(info.data() + offset, kPrefix, prefix_bytes);
    offset += prefix_bytes;
    std::memcpy(info.data() + offset, label, label_bytes);
    offset += label_bytes;
    info[offset++] = 0u;  // Empty HkdfLabel.context.

    const uint8_t block_index = 1u;
    std::array<uint8_t, kSha256Bytes> expanded{};
    const bool ok = hmac_sha256_parts(
        secret, kSha256Bytes,
        info.data(), offset,
        &block_index, sizeof(block_index),
        expanded.data());
    if (ok) {
        std::memcpy(output, expanded.data(), output_bytes);
    }
    secure_clean(info.data(), info.size());
    secure_clean(expanded.data(), expanded.size());
    return ok;
}

bool derive_initial_keys(
    uint32_t version,
    const uint8_t *destination_cid,
    size_t destination_cid_bytes,
    InitialKeys *keys) {
    const auto &salt = version == FK_QUIC_INITIAL_AUTH_VERSION_V1
        ? kV1InitialSalt : kV2InitialSalt;
    const char *key_label = version == FK_QUIC_INITIAL_AUTH_VERSION_V1
        ? "quic key" : "quicv2 key";
    const char *iv_label = version == FK_QUIC_INITIAL_AUTH_VERSION_V1
        ? "quic iv" : "quicv2 iv";
    const char *hp_label = version == FK_QUIC_INITIAL_AUTH_VERSION_V1
        ? "quic hp" : "quicv2 hp";

    std::array<uint8_t, kSha256Bytes> initial_secret{};
    std::array<uint8_t, kSha256Bytes> client_secret{};
    bool ok = hmac_sha256_parts(
        salt.data(), salt.size(), destination_cid, destination_cid_bytes,
        nullptr, 0u, initial_secret.data());
    ok = ok && hkdf_expand_label(
        initial_secret.data(), "client in", client_secret.data(), client_secret.size());
    ok = ok && hkdf_expand_label(
        client_secret.data(), key_label, keys->key.data(), keys->key.size());
    ok = ok && hkdf_expand_label(
        client_secret.data(), iv_label, keys->iv.data(), keys->iv.size());
    ok = ok && hkdf_expand_label(
        client_secret.data(), hp_label, keys->hp.data(), keys->hp.size());
    secure_clean(initial_secret.data(), initial_secret.size());
    secure_clean(client_secret.data(), client_secret.size());
    return ok;
}

void shift_right_one(std::array<uint8_t, kAesBlockBytes> *value) {
    uint8_t carry = 0u;
    for (size_t index = 0; index < value->size(); ++index) {
        const uint8_t next_carry = static_cast<uint8_t>((*value)[index] & 1u);
        (*value)[index] = static_cast<uint8_t>(((*value)[index] >> 1u) | (carry << 7u));
        carry = next_carry;
    }
}

void gf128_multiply(
    std::array<uint8_t, kAesBlockBytes> *value,
    const std::array<uint8_t, kAesBlockBytes> &multiplier) {
    std::array<uint8_t, kAesBlockBytes> product{};
    std::array<uint8_t, kAesBlockBytes> current = multiplier;
    for (size_t bit = 0; bit < 128u; ++bit) {
        const uint8_t selected = static_cast<uint8_t>(
            ((*value)[bit / 8u] >> (7u - (bit % 8u))) & 1u);
        if (selected != 0u) {
            for (size_t index = 0; index < product.size(); ++index) {
                product[index] ^= current[index];
            }
        }
        const bool reduce = (current.back() & 1u) != 0u;
        shift_right_one(&current);
        if (reduce) {
            current[0] ^= 0xe1u;
        }
    }
    *value = product;
    secure_clean(current.data(), current.size());
    secure_clean(product.data(), product.size());
}

void ghash_block(GhashState *ghash, const uint8_t block[kAesBlockBytes]) {
    for (size_t index = 0; index < ghash->state.size(); ++index) {
        ghash->state[index] ^= block[index];
    }
    gf128_multiply(&ghash->state, ghash->hash_subkey);
}

void ghash_update(GhashState *ghash, const uint8_t *data, size_t bytes) {
    while (bytes != 0u) {
        const size_t copied = std::min(bytes, ghash->partial.size() - ghash->partial_bytes);
        std::memcpy(ghash->partial.data() + ghash->partial_bytes, data, copied);
        ghash->partial_bytes += copied;
        data += copied;
        bytes -= copied;
        if (ghash->partial_bytes == ghash->partial.size()) {
            ghash_block(ghash, ghash->partial.data());
            ghash->partial.fill(0u);
            ghash->partial_bytes = 0u;
        }
    }
}

void ghash_pad(GhashState *ghash) {
    if (ghash->partial_bytes != 0u) {
        ghash_block(ghash, ghash->partial.data());
        ghash->partial.fill(0u);
        ghash->partial_bytes = 0u;
    }
}

void store_u64_be(uint64_t value, uint8_t output[8]) {
    for (size_t index = 0; index < 8u; ++index) {
        output[7u - index] = static_cast<uint8_t>(value & 0xffu);
        value >>= 8u;
    }
}

bool aes_gcm_tag(
    const std::array<uint8_t, 16> &key,
    const std::array<uint8_t, kIvBytes> &nonce,
    uint8_t first_header_byte,
    const uint8_t *protected_header_middle,
    size_t protected_header_middle_bytes,
    const uint8_t *packet_number,
    size_t packet_number_bytes,
    const uint8_t *ciphertext,
    size_t ciphertext_bytes,
    uint8_t tag[kAeadTagBytes]) {
    AES_KEY aes_key{};
    if (AES_set_encrypt_key(key.data(), 128, &aes_key) != 0) {
        return false;
    }

    GhashState ghash{};
    const std::array<uint8_t, kAesBlockBytes> zero{};
    AES_encrypt(zero.data(), ghash.hash_subkey.data(), &aes_key);

    ghash_update(&ghash, &first_header_byte, 1u);
    ghash_update(&ghash, protected_header_middle, protected_header_middle_bytes);
    ghash_update(&ghash, packet_number, packet_number_bytes);
    ghash_pad(&ghash);
    ghash_update(&ghash, ciphertext, ciphertext_bytes);
    ghash_pad(&ghash);

    std::array<uint8_t, kAesBlockBytes> lengths{};
    const uint64_t aad_bytes = 1u + protected_header_middle_bytes + packet_number_bytes;
    store_u64_be(aad_bytes * 8u, lengths.data());
    store_u64_be(static_cast<uint64_t>(ciphertext_bytes) * 8u, lengths.data() + 8u);
    ghash_block(&ghash, lengths.data());

    std::array<uint8_t, kAesBlockBytes> counter{};
    std::copy(nonce.begin(), nonce.end(), counter.begin());
    counter[15] = 1u;
    std::array<uint8_t, kAesBlockBytes> encrypted_counter{};
    AES_encrypt(counter.data(), encrypted_counter.data(), &aes_key);
    for (size_t index = 0; index < kAeadTagBytes; ++index) {
        tag[index] = static_cast<uint8_t>(encrypted_counter[index] ^ ghash.state[index]);
    }

    secure_clean(&aes_key, sizeof(aes_key));
    secure_clean(&ghash, sizeof(ghash));
    secure_clean(lengths.data(), lengths.size());
    secure_clean(counter.data(), counter.size());
    secure_clean(encrypted_counter.data(), encrypted_counter.size());
    return true;
}

bool read_varint(
    const uint8_t *data,
    size_t bytes,
    size_t *offset,
    uint64_t *value) {
    if (*offset >= bytes) {
        return false;
    }
    const uint8_t first = data[*offset];
    const size_t encoded_bytes = size_t{1u} << (first >> 6u);
    if (encoded_bytes > bytes - *offset) {
        return false;
    }
    uint64_t decoded = static_cast<uint64_t>(first & 0x3fu);
    for (size_t index = 1u; index < encoded_bytes; ++index) {
        decoded = (decoded << 8u) | data[*offset + index];
    }
    *offset += encoded_bytes;
    *value = decoded;
    return true;
}

enum fk_quic_initial_auth_reason classify_packet_type(
    uint32_t version,
    uint8_t first_byte) {
    const uint8_t type = static_cast<uint8_t>((first_byte >> 4u) & 0x03u);
    if (version == FK_QUIC_INITIAL_AUTH_VERSION_V1) {
        switch (type) {
        case 0u: return FK_QUIC_INITIAL_AUTH_REASON_NONE;
        case 1u: return FK_QUIC_INITIAL_AUTH_REASON_ZERO_RTT;
        case 2u: return FK_QUIC_INITIAL_AUTH_REASON_HANDSHAKE;
        default: return FK_QUIC_INITIAL_AUTH_REASON_RETRY;
        }
    }
    switch (type) {
    case 0u: return FK_QUIC_INITIAL_AUTH_REASON_RETRY;
    case 1u: return FK_QUIC_INITIAL_AUTH_REASON_NONE;
    case 2u: return FK_QUIC_INITIAL_AUTH_REASON_ZERO_RTT;
    default: return FK_QUIC_INITIAL_AUTH_REASON_HANDSHAKE;
    }
}

enum fk_quic_initial_auth_decision finish(
    struct fk_quic_initial_auth_result *result,
    struct fk_quic_initial_auth_stats *stats,
    enum fk_quic_initial_auth_reason reason) {
    const bool authenticated = reason == FK_QUIC_INITIAL_AUTH_REASON_NONE;
    if (result != nullptr) {
        result->reason = reason;
        result->decision = authenticated
            ? FK_QUIC_INITIAL_AUTHENTICATED : FK_QUIC_INITIAL_AUTH_REJECTED;
    }
    if (stats != nullptr) {
        if (stats->abi_version != FK_QUIC_INITIAL_AUTH_ABI_VERSION) {
            fk_quic_initial_auth_stats_initialize(stats);
        }
        ++stats->attempts;
        if (authenticated) {
            ++stats->authenticated;
            if (result != nullptr && result->version == FK_QUIC_INITIAL_AUTH_VERSION_V1) {
                ++stats->v1_authenticated;
            } else if (result != nullptr && result->version == FK_QUIC_INITIAL_AUTH_VERSION_V2) {
                ++stats->v2_authenticated;
            }
        } else {
            ++stats->rejected;
            const size_t index = static_cast<size_t>(reason);
            if (index < FK_QUIC_INITIAL_AUTH_REASON_COUNT) {
                ++stats->reason_counts[index];
            }
        }
    }
    return authenticated
        ? FK_QUIC_INITIAL_AUTHENTICATED : FK_QUIC_INITIAL_AUTH_REJECTED;
}

uint32_t load_u32_be(const uint8_t *value) {
    return (static_cast<uint32_t>(value[0]) << 24u) |
           (static_cast<uint32_t>(value[1]) << 16u) |
           (static_cast<uint32_t>(value[2]) << 8u) |
           static_cast<uint32_t>(value[3]);
}

}  // namespace

extern "C" enum fk_quic_initial_clear_inspection_decision
fk_quic_initial_inspect_client_clear_bounds(
        const uint8_t *udp_payload,
        size_t udp_payload_bytes,
        fk_quic_initial_clear_bounds_v1 *bounds) {
    if (bounds != nullptr) {
        std::memset(bounds, 0, sizeof(*bounds));
        bounds->abi_version = FK_QUIC_INITIAL_CLEAR_BOUNDS_ABI_VERSION;
        bounds->decision = FK_QUIC_INITIAL_CLEAR_REJECTED;
        bounds->reason = FK_QUIC_INITIAL_AUTH_REASON_INVALID_ARGUMENT;
    }
    if (udp_payload == nullptr || bounds == nullptr)
        return FK_QUIC_INITIAL_CLEAR_REJECTED;
    if (udp_payload_bytes > FK_QUIC_INITIAL_AUTH_MAX_DATAGRAM_BYTES) {
        bounds->reason = FK_QUIC_INITIAL_AUTH_REASON_DATAGRAM_TOO_LARGE;
        return bounds->decision;
    }
    bounds->datagram_bytes = static_cast<uint32_t>(udp_payload_bytes);
    if (udp_payload_bytes < 1u) {
        bounds->reason = FK_QUIC_INITIAL_AUTH_REASON_TRUNCATED;
        return bounds->decision;
    }
    const uint8_t protected_first_byte = udp_payload[0];
    if ((protected_first_byte & 0x80u) == 0u) {
        bounds->reason = FK_QUIC_INITIAL_AUTH_REASON_NOT_LONG_HEADER;
        return bounds->decision;
    }
    if ((protected_first_byte & 0x40u) == 0u) {
        bounds->reason = FK_QUIC_INITIAL_AUTH_REASON_FIXED_BIT_CLEAR;
        return bounds->decision;
    }
    if (udp_payload_bytes < 5u) {
        bounds->reason = FK_QUIC_INITIAL_AUTH_REASON_TRUNCATED;
        return bounds->decision;
    }
    bounds->version = load_u32_be(udp_payload + 1u);
    if (bounds->version == 0u) {
        bounds->reason = FK_QUIC_INITIAL_AUTH_REASON_VERSION_NEGOTIATION;
        return bounds->decision;
    }
    if (bounds->version != FK_QUIC_INITIAL_AUTH_VERSION_V1 &&
        bounds->version != FK_QUIC_INITIAL_AUTH_VERSION_V2) {
        bounds->reason = FK_QUIC_INITIAL_AUTH_REASON_UNSUPPORTED_VERSION;
        return bounds->decision;
    }
    bounds->long_packet_type_bits = static_cast<uint8_t>(
        (protected_first_byte >> 4u) & 0x03u);
    const auto packet_type_reason =
        classify_packet_type(bounds->version, protected_first_byte);
    if (packet_type_reason != FK_QUIC_INITIAL_AUTH_REASON_NONE) {
        bounds->reason = packet_type_reason;
        return bounds->decision;
    }
    if (udp_payload_bytes < FK_QUIC_INITIAL_AUTH_MIN_DATAGRAM_BYTES) {
        bounds->reason = FK_QUIC_INITIAL_AUTH_REASON_DATAGRAM_TOO_SMALL;
        return bounds->decision;
    }

    size_t offset = 5u;
    if (offset >= udp_payload_bytes) {
        bounds->reason = FK_QUIC_INITIAL_AUTH_REASON_TRUNCATED;
        return bounds->decision;
    }
    const uint8_t destination_cid_bytes = udp_payload[offset++];
    if (destination_cid_bytes < FK_QUIC_INITIAL_AUTH_MIN_CLIENT_DCID_BYTES ||
        destination_cid_bytes > FK_QUIC_INITIAL_AUTH_MAX_CID_BYTES) {
        bounds->reason = FK_QUIC_INITIAL_AUTH_REASON_DCID_LENGTH;
        return bounds->decision;
    }
    if (destination_cid_bytes > udp_payload_bytes - offset) {
        bounds->reason = FK_QUIC_INITIAL_AUTH_REASON_TRUNCATED;
        return bounds->decision;
    }
    bounds->destination_cid_length = destination_cid_bytes;
    std::memcpy(
        bounds->destination_cid,
        udp_payload + offset,
        destination_cid_bytes);
    offset += destination_cid_bytes;

    if (offset >= udp_payload_bytes) {
        bounds->reason = FK_QUIC_INITIAL_AUTH_REASON_TRUNCATED;
        return bounds->decision;
    }
    const uint8_t source_cid_bytes = udp_payload[offset++];
    if (source_cid_bytes > FK_QUIC_INITIAL_AUTH_MAX_CID_BYTES) {
        bounds->reason = FK_QUIC_INITIAL_AUTH_REASON_SCID_LENGTH;
        return bounds->decision;
    }
    if (source_cid_bytes > udp_payload_bytes - offset) {
        bounds->reason = FK_QUIC_INITIAL_AUTH_REASON_TRUNCATED;
        return bounds->decision;
    }
    bounds->source_cid_length = source_cid_bytes;
    std::memcpy(
        bounds->source_cid,
        udp_payload + offset,
        source_cid_bytes);
    offset += source_cid_bytes;

    uint64_t token_bytes = 0u;
    if (!read_varint(udp_payload, udp_payload_bytes, &offset, &token_bytes)) {
        bounds->reason = FK_QUIC_INITIAL_AUTH_REASON_VARINT_MALFORMED;
        return bounds->decision;
    }
    if (token_bytes > FK_QUIC_INITIAL_AUTH_MAX_TOKEN_BYTES) {
        bounds->reason = FK_QUIC_INITIAL_AUTH_REASON_TOKEN_TOO_LARGE;
        return bounds->decision;
    }
    if (token_bytes > udp_payload_bytes - offset) {
        bounds->reason = FK_QUIC_INITIAL_AUTH_REASON_TRUNCATED;
        return bounds->decision;
    }
    bounds->token_bytes = static_cast<uint32_t>(token_bytes);
    offset += static_cast<size_t>(token_bytes);

    uint64_t packet_length = 0u;
    if (!read_varint(
            udp_payload, udp_payload_bytes, &offset, &packet_length)) {
        bounds->reason = FK_QUIC_INITIAL_AUTH_REASON_VARINT_MALFORMED;
        return bounds->decision;
    }
    const size_t packet_number_offset = offset;
    if (packet_length > FK_QUIC_INITIAL_AUTH_MAX_DATAGRAM_BYTES ||
        packet_length >
            std::numeric_limits<size_t>::max() - packet_number_offset) {
        bounds->reason = FK_QUIC_INITIAL_AUTH_REASON_PACKET_LENGTH_INVALID;
        return bounds->decision;
    }
    const size_t packet_end =
        packet_number_offset + static_cast<size_t>(packet_length);
    if (packet_end > udp_payload_bytes) {
        bounds->reason = FK_QUIC_INITIAL_AUTH_REASON_TRUNCATED;
        return bounds->decision;
    }
    if (packet_end - packet_number_offset < 1u + kAeadTagBytes) {
        bounds->reason = FK_QUIC_INITIAL_AUTH_REASON_PACKET_LENGTH_INVALID;
        return bounds->decision;
    }
    if (packet_end - packet_number_offset < 4u + kAesBlockBytes) {
        bounds->reason = FK_QUIC_INITIAL_AUTH_REASON_HP_SAMPLE_TRUNCATED;
        return bounds->decision;
    }
    bounds->packet_number_offset =
        static_cast<uint32_t>(packet_number_offset);
    bounds->packet_end_bytes = static_cast<uint32_t>(packet_end);
    bounds->trailing_coalesced_bytes =
        static_cast<uint32_t>(udp_payload_bytes - packet_end);
    bounds->fixed_bit_verified = 1u;
    bounds->reason = FK_QUIC_INITIAL_AUTH_REASON_NONE;
    bounds->decision = FK_QUIC_INITIAL_CLEAR_CRYPTO_CANDIDATE;
    return bounds->decision;
}

extern "C" void fk_quic_initial_auth_stats_initialize(
    struct fk_quic_initial_auth_stats *stats) {
    if (stats == nullptr) {
        return;
    }
    std::memset(stats, 0, sizeof(*stats));
    stats->abi_version = FK_QUIC_INITIAL_AUTH_ABI_VERSION;
}

extern "C" enum fk_quic_initial_auth_decision
fk_quic_initial_authenticate_client(
    const uint8_t *udp_payload,
    size_t udp_payload_bytes,
    struct fk_quic_initial_auth_result *result,
    struct fk_quic_initial_auth_stats *stats) {
    if (result != nullptr) {
        std::memset(result, 0, sizeof(*result));
        result->abi_version = FK_QUIC_INITIAL_AUTH_ABI_VERSION;
        result->decision = FK_QUIC_INITIAL_AUTH_REJECTED;
        result->reason = FK_QUIC_INITIAL_AUTH_REASON_INVALID_ARGUMENT;
    }
    if (udp_payload == nullptr || result == nullptr) {
        return finish(result, stats, FK_QUIC_INITIAL_AUTH_REASON_INVALID_ARGUMENT);
    }
    fk_quic_initial_clear_bounds_v1 bounds{};
    const auto inspection = fk_quic_initial_inspect_client_clear_bounds(
        udp_payload, udp_payload_bytes, &bounds);
    result->version = bounds.version;
    result->datagram_bytes = bounds.datagram_bytes;
    result->token_bytes = bounds.token_bytes;
    result->long_packet_type_bits = bounds.long_packet_type_bits;
    result->destination_cid_length = bounds.destination_cid_length;
    result->source_cid_length = bounds.source_cid_length;
    std::memcpy(
        result->destination_cid,
        bounds.destination_cid,
        sizeof(result->destination_cid));
    std::memcpy(
        result->source_cid,
        bounds.source_cid,
        sizeof(result->source_cid));
    if (inspection != FK_QUIC_INITIAL_CLEAR_CRYPTO_CANDIDATE) {
        return finish(result, stats, bounds.reason);
    }
    const uint8_t protected_first_byte = udp_payload[0];
    const size_t packet_number_offset = bounds.packet_number_offset;
    const size_t packet_end = bounds.packet_end_bytes;

    InitialKeys keys{};
    if (!derive_initial_keys(
            result->version,
            result->destination_cid,
            result->destination_cid_length,
            &keys)) {
        secure_clean(&keys, sizeof(keys));
        return finish(result, stats, FK_QUIC_INITIAL_AUTH_REASON_CRYPTO_FAILURE);
    }

    AES_KEY hp_key{};
    std::array<uint8_t, kAesBlockBytes> mask{};
    if (AES_set_encrypt_key(keys.hp.data(), 128, &hp_key) != 0) {
        secure_clean(&keys, sizeof(keys));
        secure_clean(&hp_key, sizeof(hp_key));
        return finish(result, stats, FK_QUIC_INITIAL_AUTH_REASON_CRYPTO_FAILURE);
    }
    AES_encrypt(udp_payload + packet_number_offset + 4u, mask.data(), &hp_key);
    secure_clean(&hp_key, sizeof(hp_key));

    const uint8_t unprotected_first_byte = static_cast<uint8_t>(
        protected_first_byte ^ (mask[0] & 0x0fu));
    if ((unprotected_first_byte & 0x0cu) != 0u) {
        secure_clean(&keys, sizeof(keys));
        secure_clean(mask.data(), mask.size());
        return finish(result, stats, FK_QUIC_INITIAL_AUTH_REASON_RESERVED_BITS);
    }
    const size_t packet_number_bytes = (unprotected_first_byte & 0x03u) + 1u;
    if (packet_number_bytes > packet_end - packet_number_offset ||
        packet_end - packet_number_offset - packet_number_bytes < kAeadTagBytes) {
        secure_clean(&keys, sizeof(keys));
        secure_clean(mask.data(), mask.size());
        return finish(result, stats, FK_QUIC_INITIAL_AUTH_REASON_PACKET_NUMBER_INVALID);
    }
    std::array<uint8_t, 4> packet_number{};
    uint64_t decoded_packet_number = 0u;
    for (size_t index = 0; index < packet_number_bytes; ++index) {
        packet_number[index] = static_cast<uint8_t>(
            udp_payload[packet_number_offset + index] ^ mask[index + 1u]);
        decoded_packet_number = (decoded_packet_number << 8u) | packet_number[index];
    }

    /* New connection: largest received is -1, so expected is zero. */
    if (decoded_packet_number >= (uint64_t{1u} << 62u)) {
        secure_clean(&keys, sizeof(keys));
        secure_clean(mask.data(), mask.size());
        secure_clean(packet_number.data(), packet_number.size());
        return finish(result, stats, FK_QUIC_INITIAL_AUTH_REASON_PACKET_NUMBER_INVALID);
    }
    std::array<uint8_t, kIvBytes> nonce = keys.iv;
    uint64_t packet_number_for_nonce = decoded_packet_number;
    for (size_t index = 0; index < 8u; ++index) {
        nonce[nonce.size() - 1u - index] ^=
            static_cast<uint8_t>(packet_number_for_nonce & 0xffu);
        packet_number_for_nonce >>= 8u;
    }

    const size_t protected_payload_offset = packet_number_offset + packet_number_bytes;
    const size_t ciphertext_and_tag_bytes = packet_end - protected_payload_offset;
    const size_t ciphertext_bytes = ciphertext_and_tag_bytes - kAeadTagBytes;
    const uint8_t *provided_tag = udp_payload + packet_end - kAeadTagBytes;
    std::array<uint8_t, kAeadTagBytes> expected_tag{};
    const bool tag_computed = aes_gcm_tag(
        keys.key,
        nonce,
        unprotected_first_byte,
        udp_payload + 1u,
        packet_number_offset - 1u,
        packet_number.data(),
        packet_number_bytes,
        udp_payload + protected_payload_offset,
        ciphertext_bytes,
        expected_tag.data());
    const bool tag_matches = tag_computed &&
        CRYPTO_memcmp(expected_tag.data(), provided_tag, expected_tag.size()) == 0;

    secure_clean(&keys, sizeof(keys));
    secure_clean(mask.data(), mask.size());
    secure_clean(packet_number.data(), packet_number.size());
    secure_clean(nonce.data(), nonce.size());
    secure_clean(expected_tag.data(), expected_tag.size());
    if (!tag_computed) {
        return finish(result, stats, FK_QUIC_INITIAL_AUTH_REASON_CRYPTO_FAILURE);
    }
    if (!tag_matches) {
        return finish(result, stats, FK_QUIC_INITIAL_AUTH_REASON_AEAD_TAG_INVALID);
    }

    result->packet_number = decoded_packet_number;
    result->packet_number_bytes = static_cast<uint8_t>(packet_number_bytes);
    result->datagram_bytes = bounds.datagram_bytes;
    result->authenticated_packet_bytes = bounds.packet_end_bytes;
    result->trailing_coalesced_bytes = bounds.trailing_coalesced_bytes;
    result->authenticated_header_bytes = static_cast<uint32_t>(
        packet_number_offset + packet_number_bytes);
    result->authenticated_ciphertext_bytes = static_cast<uint32_t>(ciphertext_bytes);
    result->fixed_bit_verified = 1u;
    return finish(result, stats, FK_QUIC_INITIAL_AUTH_REASON_NONE);
}

extern "C" const char *fk_quic_initial_auth_reason_name(
    enum fk_quic_initial_auth_reason reason) {
    static constexpr const char *kNames[] = {
        "none",
        "invalid_argument",
        "truncated",
        "datagram_too_small",
        "datagram_too_large",
        "not_long_header",
        "fixed_bit_clear",
        "version_negotiation",
        "unsupported_version",
        "retry",
        "zero_rtt",
        "handshake",
        "dcid_length",
        "scid_length",
        "varint_malformed",
        "token_too_large",
        "packet_length_invalid",
        "hp_sample_truncated",
        "reserved_bits",
        "packet_number_invalid",
        "aead_tag_invalid",
        "crypto_failure",
    };
    static_assert(
        sizeof(kNames) / sizeof(kNames[0]) == FK_QUIC_INITIAL_AUTH_REASON_COUNT,
        "reason name table must match the public ABI");
    const size_t index = static_cast<size_t>(reason);
    return index < FK_QUIC_INITIAL_AUTH_REASON_COUNT ? kNames[index] : "unknown";
}
