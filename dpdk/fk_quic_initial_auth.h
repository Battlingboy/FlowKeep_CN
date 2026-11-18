#ifndef FLOWKEEP_FK_QUIC_INITIAL_AUTH_H
#define FLOWKEEP_FK_QUIC_INITIAL_AUTH_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * A deliberately narrow QUIC capability.
 *
 * This module authenticates one complete, client-sent QUIC Initial packet
 * using the publicly derivable Initial keys from RFC 9001 (QUIC v1) or
 * RFC 9369 (QUIC v2).  Success proves packet integrity under those Initial
 * keys.  It does NOT authenticate an endpoint, parse CRYPTO frames, reassemble
 * a ClientHello, or constitute a complete QUIC parser.
 *
 * The input is exactly one UDP payload.  The first client Initial is bounded
 * by its authenticated Length field; trailing coalesced packets remain
 * outside the AEAD operation and are reported explicitly.  The implementation
 * has fixed stack bounds and performs no allocation; callers should keep one
 * stats object per worker because stats updates are intentionally non-atomic.
 */

#define FK_QUIC_INITIAL_AUTH_ABI_VERSION 2u
#define FK_QUIC_INITIAL_CLEAR_BOUNDS_ABI_VERSION 1u
#define FK_QUIC_INITIAL_AUTH_RESULT_BYTES 96u
#define FK_QUIC_INITIAL_CLEAR_BOUNDS_V1_BYTES 84u
#define FK_QUIC_INITIAL_AUTH_VERSION_V1 0x00000001u
#define FK_QUIC_INITIAL_AUTH_VERSION_V2 0x6b3343cfu
#define FK_QUIC_INITIAL_AUTH_MIN_DATAGRAM_BYTES 1200u
#define FK_QUIC_INITIAL_AUTH_MAX_DATAGRAM_BYTES 65527u
#define FK_QUIC_INITIAL_AUTH_MIN_CLIENT_DCID_BYTES 8u
#define FK_QUIC_INITIAL_AUTH_MAX_CID_BYTES 20u
#define FK_QUIC_INITIAL_AUTH_MAX_TOKEN_BYTES 4096u

enum fk_quic_initial_auth_decision {
    FK_QUIC_INITIAL_AUTH_REJECTED = 0,
    FK_QUIC_INITIAL_AUTHENTICATED = 1,
};

enum fk_quic_initial_auth_reason {
    FK_QUIC_INITIAL_AUTH_REASON_NONE = 0,
    FK_QUIC_INITIAL_AUTH_REASON_INVALID_ARGUMENT,
    FK_QUIC_INITIAL_AUTH_REASON_TRUNCATED,
    FK_QUIC_INITIAL_AUTH_REASON_DATAGRAM_TOO_SMALL,
    FK_QUIC_INITIAL_AUTH_REASON_DATAGRAM_TOO_LARGE,
    FK_QUIC_INITIAL_AUTH_REASON_NOT_LONG_HEADER,
    FK_QUIC_INITIAL_AUTH_REASON_FIXED_BIT_CLEAR,
    FK_QUIC_INITIAL_AUTH_REASON_VERSION_NEGOTIATION,
    FK_QUIC_INITIAL_AUTH_REASON_UNSUPPORTED_VERSION,
    FK_QUIC_INITIAL_AUTH_REASON_RETRY,
    FK_QUIC_INITIAL_AUTH_REASON_ZERO_RTT,
    FK_QUIC_INITIAL_AUTH_REASON_HANDSHAKE,
    FK_QUIC_INITIAL_AUTH_REASON_DCID_LENGTH,
    FK_QUIC_INITIAL_AUTH_REASON_SCID_LENGTH,
    FK_QUIC_INITIAL_AUTH_REASON_VARINT_MALFORMED,
    FK_QUIC_INITIAL_AUTH_REASON_TOKEN_TOO_LARGE,
    FK_QUIC_INITIAL_AUTH_REASON_PACKET_LENGTH_INVALID,
    FK_QUIC_INITIAL_AUTH_REASON_HP_SAMPLE_TRUNCATED,
    FK_QUIC_INITIAL_AUTH_REASON_RESERVED_BITS,
    FK_QUIC_INITIAL_AUTH_REASON_PACKET_NUMBER_INVALID,
    FK_QUIC_INITIAL_AUTH_REASON_AEAD_TAG_INVALID,
    FK_QUIC_INITIAL_AUTH_REASON_CRYPTO_FAILURE,
    FK_QUIC_INITIAL_AUTH_REASON_COUNT,
};

enum fk_quic_initial_clear_inspection_decision {
    FK_QUIC_INITIAL_CLEAR_REJECTED = 0,
    FK_QUIC_INITIAL_CLEAR_CRYPTO_CANDIDATE = 1,
};

/* Allocation-free, clear-header-only bounds inspection shared by the future
 * router/gate composition and authenticate_client.  packet_end_bytes is the
 * exact first-packet work bound to charge before HP/AEAD.  It is only a
 * candidate boundary until authentication succeeds; malformed headers are
 * rejected without cryptographic work. */
struct fk_quic_initial_clear_bounds_v1 {
    uint32_t abi_version;
    enum fk_quic_initial_clear_inspection_decision decision;
    enum fk_quic_initial_auth_reason reason;
    uint32_t version;
    uint32_t datagram_bytes;
    uint32_t packet_end_bytes;
    uint32_t trailing_coalesced_bytes;
    uint32_t packet_number_offset;
    uint32_t token_bytes;
    uint8_t destination_cid_length;
    uint8_t source_cid_length;
    uint8_t long_packet_type_bits;
    uint8_t fixed_bit_verified;
    uint8_t reserved0[4];
    uint8_t destination_cid[FK_QUIC_INITIAL_AUTH_MAX_CID_BYTES];
    uint8_t source_cid[FK_QUIC_INITIAL_AUTH_MAX_CID_BYTES];
};

struct fk_quic_initial_auth_result {
    uint32_t abi_version;
    enum fk_quic_initial_auth_decision decision;
    enum fk_quic_initial_auth_reason reason;
    uint32_t version;
    uint64_t packet_number;
    uint32_t datagram_bytes;
    uint32_t authenticated_packet_bytes;
    uint32_t trailing_coalesced_bytes;
    uint32_t authenticated_header_bytes;
    /* AEAD ciphertext only; the trailing 16-byte authentication tag is not
     * included. */
    uint32_t authenticated_ciphertext_bytes;
    uint32_t token_bytes;
    uint8_t packet_number_bytes;
    uint8_t destination_cid_length;
    uint8_t source_cid_length;
    uint8_t long_packet_type_bits;
    uint8_t fixed_bit_verified;
    uint8_t reserved0[3];
    uint8_t destination_cid[FK_QUIC_INITIAL_AUTH_MAX_CID_BYTES];
    uint8_t source_cid[FK_QUIC_INITIAL_AUTH_MAX_CID_BYTES];
};

struct fk_quic_initial_auth_stats {
    uint32_t abi_version;
    uint32_t reserved0;
    uint64_t attempts;
    uint64_t authenticated;
    uint64_t rejected;
    uint64_t v1_authenticated;
    uint64_t v2_authenticated;
    uint64_t reason_counts[FK_QUIC_INITIAL_AUTH_REASON_COUNT];
};

/* stats may be NULL. result must be non-NULL for callers to consume success. */
enum fk_quic_initial_clear_inspection_decision
fk_quic_initial_inspect_client_clear_bounds(
    const uint8_t *udp_payload,
    size_t udp_payload_bytes,
    struct fk_quic_initial_clear_bounds_v1 *bounds);

enum fk_quic_initial_auth_decision fk_quic_initial_authenticate_client(
    const uint8_t *udp_payload,
    size_t udp_payload_bytes,
    struct fk_quic_initial_auth_result *result,
    struct fk_quic_initial_auth_stats *stats);

void fk_quic_initial_auth_stats_initialize(
    struct fk_quic_initial_auth_stats *stats);

const char *fk_quic_initial_auth_reason_name(
    enum fk_quic_initial_auth_reason reason);

#ifdef __cplusplus
}
#endif

#endif
