#ifndef FLOWKEEP_FK_NATIVE_SHM_H
#define FLOWKEEP_FK_NATIVE_SHM_H

#include <stdatomic.h>
#include <stdint.h>

#include "fk_native_parser.h"

/*
 * Sparse native-parser event ring.  This is a second ABI and does not alter
 * FKRING1.  It is single-producer/single-consumer and targets x86_64 Linux,
 * matching the packet-ring ABI consumed by flowkeep_dpdk/shm.py.
 */
#define FK_NATIVE_RING_MAGIC "FKNATV1"
#define FK_NATIVE_RING_VERSION 1u
#define FK_NATIVE_RING_HEADER_BYTES 128u
#define FK_NATIVE_EVENT_BYTES 1536u

#define FK_NATIVE_RING_FLAG_TCP_TLS 0x00000001u
#define FK_NATIVE_RING_FLAG_QUIC_CLEAR_HEADER_ONLY 0x00000002u
#define FK_NATIVE_RING_FLAG_DETECTION_PARITY_UNAVAILABLE 0x00000004u

enum fk_native_event_type {
    FK_NATIVE_EVENT_TLS_HELLO = 1,
    FK_NATIVE_EVENT_TLS_STATUS = 2,
    FK_NATIVE_EVENT_QUIC_PARTIAL = 3,
};

struct __attribute__((packed, aligned(64))) fk_native_ring_header {
    char magic[8];
    uint32_t version;
    uint32_t header_bytes;
    uint32_t event_bytes;
    uint32_t capacity;
    uint32_t parser_abi_version;
    uint32_t flags;
    _Atomic uint64_t write_seq;
    _Atomic uint64_t read_seq;
    _Atomic uint64_t producer_drops;
    _Atomic uint64_t producer_events;
    _Atomic uint64_t frames_processed;
    _Atomic uint64_t processed_packet_sequence;
    uint64_t created_mono_ns;
    _Atomic uint32_t stop;
    uint32_t reserved0;
    uint8_t padding[32];
};

/*
 * All integer fields use the host little-endian representation.  Counts are
 * exact retained lengths; exceeding a parser cap is represented by
 * completeness=CAP_EXCEEDED rather than truncating a COMPLETE event.
 */
struct __attribute__((packed, aligned(64))) fk_native_event {
    uint64_t packet_sequence;
    uint64_t event_sequence;
    uint32_t event_type;
    uint32_t parse_code;
    uint32_t completeness;
    uint8_t ip_version;
    uint8_t protocol;
    uint8_t direction;
    uint8_t framing;
    uint8_t hello_kind;
    uint8_t hello_retry_request;
    uint8_t reserved0[2];
    uint8_t low_addr[16];
    uint8_t high_addr[16];
    uint16_t low_port;
    uint16_t high_port;
    uint16_t legacy_version;
    uint16_t selected_cipher;
    uint16_t cipher_count;
    uint16_t extension_count;
    uint16_t supported_version_count;
    uint16_t signature_algorithm_count;
    uint16_t server_name_length;
    uint16_t alpn_length;
    uint8_t reserved1[8];
    uint16_t ciphers[FK_TLS_CIPHER_CAP];
    uint16_t extensions[FK_TLS_EXTENSION_CAP];
    uint16_t supported_versions[FK_TLS_SUPPORTED_VERSION_CAP];
    uint16_t signature_algorithms[FK_TLS_SIGNATURE_ALGORITHM_CAP];
    char server_name[FK_TLS_SNI_CAP];
    char alpn[FK_TLS_ALPN_CAP];
};

_Static_assert(
    sizeof(struct fk_native_ring_header) == FK_NATIVE_RING_HEADER_BYTES,
    "fk_native_ring_header must be 128 bytes");
_Static_assert(
    sizeof(struct fk_native_event) == FK_NATIVE_EVENT_BYTES,
    "fk_native_event must be 1536 bytes");

#endif
