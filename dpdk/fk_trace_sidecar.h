#ifndef FLOWKEEP_FK_TRACE_SIDECAR_H
#define FLOWKEEP_FK_TRACE_SIDECAR_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define FK_TRACE_SIDECAR_VERSION 1u
#define FK_TRACE_SIDECAR_HEADER_BYTES 128u
#define FK_TRACE_SIDECAR_RECORD_BYTES 8u
#define FK_TRACE_SIDECAR_SHA256_BYTES 32u
#define FK_TRACE_SIDECAR_MAX_PACKETS (UINT64_C(1) << 40)
#define FK_TRACE_SIDECAR_FLAGS 7u
#define FK_TRACE_SIDECAR_FLAG_DEVELOPMENT_LOGICAL_REPEAT (1u << 3u)
#define FK_TRACE_SIDECAR_DEVELOPMENT_REPEAT_FLAGS \
    (FK_TRACE_SIDECAR_FLAGS | \
     FK_TRACE_SIDECAR_FLAG_DEVELOPMENT_LOGICAL_REPEAT)

/*
 * Native reader for the FKTSV1 ABI emitted by
 * scripts/trace_timestamp_sidecar.py.
 *
 * Opening performs all expensive integrity checks once: exact ABI/length,
 * reserved bytes, SHA-256 of the timestamp record region, monotonicity, and
 * first/last bounds.  Lookup is then a read-only O(1) operation with no
 * allocation or locking on the packet path.
 */
struct fk_trace_sidecar {
    int fd;
    const uint8_t *mapping;
    size_t mapping_bytes;
    uint64_t packet_count;
    uint64_t pcap_file_bytes;
    uint64_t first_timestamp_ns;
    uint64_t last_timestamp_ns;
    uint32_t flags;
    uint8_t pcap_sha256[FK_TRACE_SIDECAR_SHA256_BYTES];
    uint8_t records_sha256[FK_TRACE_SIDECAR_SHA256_BYTES];
};

void fk_trace_sidecar_reset(struct fk_trace_sidecar *sidecar);

bool fk_trace_sidecar_open(
    struct fk_trace_sidecar *sidecar,
    const char *path,
    char *error,
    size_t error_capacity);

void fk_trace_sidecar_close(struct fk_trace_sidecar *sidecar);

bool fk_trace_sidecar_timestamp(
    const struct fk_trace_sidecar *sidecar,
    uint64_t packet_sequence,
    uint64_t *timestamp_ns);

/*
 * Convert a contiguous ready packet prefix [0,N) into a safe inclusive
 * event-time watermark.  If packet N has the same timestamp as packet N-1,
 * only timestamp-1 is safe because the equal-timestamp group is incomplete.
 * At N==packet_count the exact capture last timestamp is returned.  N==0 (or
 * timestamp zero with an incomplete equal group) has no representable
 * inclusive watermark and sets available=false.
 */
bool fk_trace_sidecar_safe_inclusive_watermark(
    const struct fk_trace_sidecar *sidecar,
    uint64_t ready_prefix_packets,
    bool *available,
    uint64_t *watermark_ns);

/*
 * Sender-only binding check.  This verifies both the exact PCAP byte length
 * and the SHA-256 stored in the sidecar header.  Per-record timestamp parity
 * is additionally checked by the replay loop as each record is read.
 */
bool fk_trace_sidecar_verify_pcap(
    const struct fk_trace_sidecar *sidecar,
    const char *pcap_path,
    char *error,
    size_t error_capacity);

/*
 * Legacy/no-NIC test encoding.  The production finite live-RX transport keeps
 * real wire MACs and carries its 64-bit sequence in
 * fk_trace_transport_shim_v1 instead.  These helpers remain only for existing
 * deterministic fixtures and must not be used by the live link gate.
 */
bool fk_trace_sequence_encode_destination_mac(
    uint64_t packet_sequence,
    uint8_t destination_mac[6]);

bool fk_trace_sequence_decode_destination_mac(
    const uint8_t destination_mac[6],
    uint64_t *packet_sequence);

#ifdef __cplusplus
}
#endif

#endif
