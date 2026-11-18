#include "fk_trace_transport_shim.h"

#include <isa-l/crc.h>
#include <string.h>

#if defined(__x86_64__) || defined(__i386__)
#include <nmmintrin.h>
#endif

static uint16_t load_be16(const uint8_t bytes[2]) {
    return (uint16_t)((uint16_t)bytes[0] << 8u | bytes[1]);
}

static uint32_t load_be32(const uint8_t bytes[4]) {
    return (uint32_t)bytes[0] << 24u | (uint32_t)bytes[1] << 16u |
        (uint32_t)bytes[2] << 8u | bytes[3];
}

static uint64_t load_be64(const uint8_t bytes[8]) {
    uint64_t value = 0u;
    for (size_t index = 0u; index < 8u; ++index)
        value = value << 8u | bytes[index];
    return value;
}

static void store_be16(uint8_t bytes[2], uint16_t value) {
    bytes[0] = (uint8_t)(value >> 8u);
    bytes[1] = (uint8_t)value;
}

static void store_be32(uint8_t bytes[4], uint32_t value) {
    bytes[0] = (uint8_t)(value >> 24u);
    bytes[1] = (uint8_t)(value >> 16u);
    bytes[2] = (uint8_t)(value >> 8u);
    bytes[3] = (uint8_t)value;
}

static void store_be64(uint8_t bytes[8], uint64_t value) {
    for (size_t index = 0u; index < 8u; ++index) {
        bytes[7u - index] = (uint8_t)value;
        value >>= 8u;
    }
}

#if defined(__x86_64__) || defined(__i386__)
__attribute__((target("sse4.2")))
#endif
static uint32_t crc32c_update(
        uint32_t crc, const uint8_t *bytes, size_t length) {
#if defined(__x86_64__) || defined(__i386__)
    /* ISA-L selects its PCLMUL/AVX implementation once and folds long
     * payloads with multiple independent lanes.  Retain direct CRC32
     * instructions for the short fixed trailer/L2 prefixes, where a
     * dispatcher call costs more than it saves. */
    if (length >= 128u)
        return crc32_iscsi((unsigned char *)(void *)bytes, (int)length, crc);
    while (length >= sizeof(uint64_t)) {
        uint64_t word = 0u;
        memcpy(&word, bytes, sizeof(word));
        crc = (uint32_t)_mm_crc32_u64(crc, word);
        bytes += sizeof(word);
        length -= sizeof(word);
    }
    if (length >= sizeof(uint32_t)) {
        uint32_t word = 0u;
        memcpy(&word, bytes, sizeof(word));
        crc = _mm_crc32_u32(crc, word);
        bytes += sizeof(word);
        length -= sizeof(word);
    }
    if (length >= sizeof(uint16_t)) {
        uint16_t word = 0u;
        memcpy(&word, bytes, sizeof(word));
        crc = _mm_crc32_u16(crc, word);
        bytes += sizeof(word);
        length -= sizeof(word);
    }
    if (length != 0u)
        crc = _mm_crc32_u8(crc, *bytes);
    return crc;
#else
    for (size_t index = 0u; index < length; ++index) {
        crc ^= bytes[index];
        for (unsigned bit = 0u; bit < 8u; ++bit) {
            const uint32_t mask = 0u - (crc & 1u);
            crc = (crc >> 1u) ^ (UINT32_C(0x82f63b78) & mask);
        }
    }
    return crc;
#endif
}

static uint32_t frame_crc32c(
        const struct fk_trace_transport_shim_v1 *shim,
        const uint8_t *frame,
        uint16_t captured_length) {
    uint32_t crc = UINT32_MAX;
    crc = crc32c_update(
        crc, (const uint8_t *)shim, FK_TRACE_TRANSPORT_PREFIX_BYTES);
    crc = crc32c_update(crc, frame, captured_length);
    return ~crc;
}

bool fk_trace_transport_shim_encode_v1(
        struct fk_trace_transport_shim_v1 *shim,
        uint64_t packet_sequence,
        uint16_t captured_length,
        uint16_t wire_length,
        const uint8_t *original_frame) {
    if (shim == NULL || original_frame == NULL ||
        captured_length < FK_TRACE_TRANSPORT_L2_BYTES ||
        wire_length < captured_length)
        return false;
    memset(shim, 0, sizeof(*shim));
    shim->magic_version[0] = 'F';
    shim->magic_version[1] = 'K';
    shim->magic_version[2] = 'S';
    shim->magic_version[3] = FK_TRACE_TRANSPORT_SHIM_VERSION;
    store_be64(shim->packet_sequence_be, packet_sequence);
    store_be16(shim->captured_length_be, captured_length);
    store_be16(shim->wire_length_be, wire_length);
    memcpy(
        shim->original_destination_mac,
        original_frame,
        sizeof(shim->original_destination_mac));
    memcpy(
        shim->original_source_mac,
        original_frame + sizeof(shim->original_destination_mac),
        sizeof(shim->original_source_mac));
    store_be32(
        shim->crc32c_be,
        frame_crc32c(shim, original_frame, captured_length));
    return true;
}

enum fk_trace_transport_shim_status fk_trace_transport_shim_parse_v1(
        const struct fk_trace_transport_shim_v1 *shim,
        uint32_t enveloped_captured_length,
        struct fk_trace_transport_decoded_v1 *decoded) {
    if (shim == NULL || decoded == NULL)
        return FK_TRACE_TRANSPORT_SHIM_ARGUMENT;
    memset(decoded, 0, sizeof(*decoded));
    if (shim->magic_version[0] != 'F' ||
        shim->magic_version[1] != 'K' ||
        shim->magic_version[2] != 'S' ||
        shim->magic_version[3] != FK_TRACE_TRANSPORT_SHIM_VERSION)
        return FK_TRACE_TRANSPORT_SHIM_MAGIC_VERSION;
    const uint16_t captured = load_be16(shim->captured_length_be);
    const uint16_t wire = load_be16(shim->wire_length_be);
    if (captured < FK_TRACE_TRANSPORT_L2_BYTES)
        return FK_TRACE_TRANSPORT_SHIM_CAPTURED_LENGTH;
    if (wire < captured)
        return FK_TRACE_TRANSPORT_SHIM_WIRE_LENGTH;
    if ((uint32_t)captured + FK_TRACE_TRANSPORT_SHIM_BYTES !=
        enveloped_captured_length)
        return FK_TRACE_TRANSPORT_SHIM_ENVELOPE_LENGTH;
    decoded->packet_sequence = load_be64(shim->packet_sequence_be);
    decoded->captured_length = captured;
    decoded->wire_length = wire;
    memcpy(
        decoded->original_l2,
        shim->original_destination_mac,
        sizeof(shim->original_destination_mac));
    memcpy(
        decoded->original_l2 + sizeof(shim->original_destination_mac),
        shim->original_source_mac,
        sizeof(shim->original_source_mac));
    return FK_TRACE_TRANSPORT_SHIM_OK;
}

enum fk_trace_transport_shim_status fk_trace_transport_shim_verify_crc_v1(
        const struct fk_trace_transport_shim_v1 *shim,
        const uint8_t *restored_original_frame,
        uint16_t restored_captured_length) {
    if (shim == NULL || restored_original_frame == NULL)
        return FK_TRACE_TRANSPORT_SHIM_ARGUMENT;
    if (load_be16(shim->captured_length_be) != restored_captured_length)
        return FK_TRACE_TRANSPORT_SHIM_CAPTURED_LENGTH;
    return load_be32(shim->crc32c_be) == frame_crc32c(
               shim, restored_original_frame, restored_captured_length)
        ? FK_TRACE_TRANSPORT_SHIM_OK
        : FK_TRACE_TRANSPORT_SHIM_CRC32C;
}

enum fk_trace_transport_shim_status
fk_trace_transport_shim_verify_crc_replaced_l2_v1(
        const struct fk_trace_transport_shim_v1 *shim,
        const uint8_t original_l2[FK_TRACE_TRANSPORT_L2_BYTES],
        const uint8_t *transported_frame,
        uint16_t transported_captured_length) {
    if (shim == NULL || original_l2 == NULL || transported_frame == NULL)
        return FK_TRACE_TRANSPORT_SHIM_ARGUMENT;
    if (transported_captured_length < FK_TRACE_TRANSPORT_L2_BYTES ||
        load_be16(shim->captured_length_be) != transported_captured_length)
        return FK_TRACE_TRANSPORT_SHIM_CAPTURED_LENGTH;
    uint32_t crc = UINT32_MAX;
    crc = crc32c_update(
        crc, (const uint8_t *)shim, FK_TRACE_TRANSPORT_PREFIX_BYTES);
    crc = crc32c_update(crc, original_l2, FK_TRACE_TRANSPORT_L2_BYTES);
    crc = crc32c_update(
        crc,
        transported_frame + FK_TRACE_TRANSPORT_L2_BYTES,
        transported_captured_length - FK_TRACE_TRANSPORT_L2_BYTES);
    crc = ~crc;
    return load_be32(shim->crc32c_be) == crc
        ? FK_TRACE_TRANSPORT_SHIM_OK
        : FK_TRACE_TRANSPORT_SHIM_CRC32C;
}
