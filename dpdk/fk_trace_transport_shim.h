#ifndef FLOWKEEP_FK_TRACE_TRANSPORT_SHIM_H
#define FLOWKEEP_FK_TRACE_TRANSPORT_SHIM_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define FK_TRACE_TRANSPORT_SHIM_VERSION 1u
#define FK_TRACE_TRANSPORT_SHIM_BYTES 32u
#define FK_TRACE_TRANSPORT_L2_BYTES 12u
#define FK_TRACE_TRANSPORT_PREFIX_BYTES 16u

/*
 * Exact 32-byte wire trailer, with all integers in network byte order:
 *
 *   0..2   magic "FKS"
 *   3      version (1)
 *   4..11  zero-based PCAP record sequence (uint64)
 *  12..13  original captured length (uint16)
 *  14..15  original wire length (uint16)
 *  16..21  original destination MAC
 *  22..27  original source MAC
 *  28..31  CRC32C (uint32)
 *
 * CRC32C uses the standard Castagnoli polynomial, initial/final xor
 * 0xffffffff.  It covers trailer bytes 0..15 followed by the complete
 * restored original captured frame.  Thus it binds sequence, both lengths,
 * and every byte delivered to the parser after L2 restoration and trim.
 */
struct fk_trace_transport_shim_v1 {
    uint8_t magic_version[4];
    uint8_t packet_sequence_be[8];
    uint8_t captured_length_be[2];
    uint8_t wire_length_be[2];
    uint8_t original_destination_mac[6];
    uint8_t original_source_mac[6];
    uint8_t crc32c_be[4];
};

#if defined(__cplusplus)
static_assert(sizeof(struct fk_trace_transport_shim_v1) ==
    FK_TRACE_TRANSPORT_SHIM_BYTES, "transport shim must be exactly 32 bytes");
static_assert(offsetof(struct fk_trace_transport_shim_v1,
    packet_sequence_be) == 4u, "sequence offset");
static_assert(offsetof(struct fk_trace_transport_shim_v1,
    captured_length_be) == 12u, "captured-length offset");
static_assert(offsetof(struct fk_trace_transport_shim_v1,
    wire_length_be) == 14u, "wire-length offset");
static_assert(offsetof(struct fk_trace_transport_shim_v1,
    original_destination_mac) == 16u, "destination-MAC offset");
static_assert(offsetof(struct fk_trace_transport_shim_v1,
    original_source_mac) == 22u, "source-MAC offset");
static_assert(offsetof(struct fk_trace_transport_shim_v1,
    crc32c_be) == 28u, "CRC32C offset");
#else
_Static_assert(sizeof(struct fk_trace_transport_shim_v1) ==
    FK_TRACE_TRANSPORT_SHIM_BYTES, "transport shim must be exactly 32 bytes");
_Static_assert(offsetof(struct fk_trace_transport_shim_v1,
    packet_sequence_be) == 4u, "sequence offset");
_Static_assert(offsetof(struct fk_trace_transport_shim_v1,
    captured_length_be) == 12u, "captured-length offset");
_Static_assert(offsetof(struct fk_trace_transport_shim_v1,
    wire_length_be) == 14u, "wire-length offset");
_Static_assert(offsetof(struct fk_trace_transport_shim_v1,
    original_destination_mac) == 16u, "destination-MAC offset");
_Static_assert(offsetof(struct fk_trace_transport_shim_v1,
    original_source_mac) == 22u, "source-MAC offset");
_Static_assert(offsetof(struct fk_trace_transport_shim_v1,
    crc32c_be) == 28u, "CRC32C offset");
#endif

enum fk_trace_transport_shim_status {
    FK_TRACE_TRANSPORT_SHIM_OK = 0,
    FK_TRACE_TRANSPORT_SHIM_ARGUMENT,
    FK_TRACE_TRANSPORT_SHIM_MAGIC_VERSION,
    FK_TRACE_TRANSPORT_SHIM_CAPTURED_LENGTH,
    FK_TRACE_TRANSPORT_SHIM_WIRE_LENGTH,
    FK_TRACE_TRANSPORT_SHIM_ENVELOPE_LENGTH,
    FK_TRACE_TRANSPORT_SHIM_CRC32C,
};

struct fk_trace_transport_decoded_v1 {
    uint64_t packet_sequence;
    uint16_t captured_length;
    uint16_t wire_length;
    uint8_t original_l2[FK_TRACE_TRANSPORT_L2_BYTES];
};

bool fk_trace_transport_shim_encode_v1(
    struct fk_trace_transport_shim_v1 *shim,
    uint64_t packet_sequence,
    uint16_t captured_length,
    uint16_t wire_length,
    const uint8_t *original_frame);

enum fk_trace_transport_shim_status fk_trace_transport_shim_parse_v1(
    const struct fk_trace_transport_shim_v1 *shim,
    uint32_t enveloped_captured_length,
    struct fk_trace_transport_decoded_v1 *decoded);

enum fk_trace_transport_shim_status fk_trace_transport_shim_verify_crc_v1(
    const struct fk_trace_transport_shim_v1 *shim,
    const uint8_t *restored_original_frame,
    uint16_t restored_captured_length);

/* Verify the logical original frame without copying the transported frame
 * just to restore its Ethernet addresses. */
enum fk_trace_transport_shim_status
fk_trace_transport_shim_verify_crc_replaced_l2_v1(
    const struct fk_trace_transport_shim_v1 *shim,
    const uint8_t original_l2[FK_TRACE_TRANSPORT_L2_BYTES],
    const uint8_t *transported_frame,
    uint16_t transported_captured_length);

#ifdef __cplusplus
}
#endif

#endif
