#ifndef FLOWKEEP_FK_NATIVE_PARSER_H
#define FLOWKEEP_FK_NATIVE_PARSER_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * This module is deliberately independent of libpcap, TShark, and DPDK data
 * structures.  A DPDK RX worker can pass a contiguous rte_mbuf view to it, and
 * the offline validator can pass the exact same Ethernet bytes.
 *
 * Every variable-length protocol object has a compile-time bound.  Exceeding a
 * bound is an explicit PARTIAL/CAP_EXCEEDED outcome, never silent truncation.
 */

#define FK_NATIVE_PARSER_ABI_VERSION 2u
#define FK_MAX_VLAN_TAGS 2u
#define FK_MAX_IPV6_EXTENSION_HEADERS 8u
#define FK_MAX_IPV6_EXTENSION_BYTES 256u

#define FK_TLS_RECORD_PLAINTEXT_MAX 18432u
#define FK_TLS_HANDSHAKE_BODY_CAP 16384u
#define FK_TLS_CONTENT_CHANGE_CIPHER_SPEC 20u
#define FK_TLS_CONTENT_ALERT 21u
#define FK_TLS_CONTENT_HANDSHAKE 22u
#define FK_TLS_CONTENT_APPLICATION_DATA 23u
#define FK_TLS_CONTENT_HEARTBEAT 24u
#define FK_TLS_CIPHER_CAP 256u
#define FK_TLS_EXTENSION_CAP 128u
#define FK_TLS_SUPPORTED_VERSION_CAP 16u
#define FK_TLS_SIGNATURE_ALGORITHM_CAP 64u
#define FK_TLS_SNI_CAP 256u
#define FK_TLS_ALPN_CAP 256u

#define FK_TCP_OOO_SLOTS 8u
#define FK_TCP_OOO_PAYLOAD_CAP 2048u

#define FK_TCP_FLAG_FIN 0x01u
#define FK_TCP_FLAG_SYN 0x02u
#define FK_TCP_FLAG_RST 0x04u
#define FK_TCP_FLAG_PSH 0x08u
#define FK_TCP_FLAG_ACK 0x10u

enum fk_native_parse_code {
    FK_PARSE_OK = 0,
    FK_PARSE_TRUNCATED,
    FK_PARSE_MALFORMED,
    FK_PARSE_UNSUPPORTED_L2,
    FK_PARSE_UNSUPPORTED_L3,
    FK_PARSE_UNSUPPORTED_L4,
    FK_PARSE_FRAGMENTED,
    FK_PARSE_CAP_EXCEEDED,
};

enum fk_protocol_completeness {
    FK_COMPLETENESS_NONE = 0,
    FK_COMPLETENESS_COMPLETE,
    FK_COMPLETENESS_PARTIAL,
    FK_COMPLETENESS_MALFORMED,
    FK_COMPLETENESS_CAP_EXCEEDED,
};

struct fk_packet_view {
    enum fk_native_parse_code code;
    uint8_t vlan_count;
    uint16_t vlan_tci[FK_MAX_VLAN_TAGS];
    uint16_t ether_type;

    uint8_t ip_version;
    uint8_t l4_protocol;
    uint8_t src_addr[16];
    uint8_t dst_addr[16];
    uint16_t src_port;
    uint16_t dst_port;

    uint32_t captured_size;
    uint32_t wire_size;
    uint32_t ip_size;
    uint32_t transport_size;
    uint32_t payload_size;

    uint32_t tcp_sequence;
    uint32_t tcp_acknowledgement;
    uint16_t tcp_window;
    uint8_t tcp_flags;

    const uint8_t *payload;
    /* The L3/L4 headers are complete, but the capture ends before the
     * protocol-declared payload length.  Header-derived state remains valid;
     * payload-derived evidence is explicitly missing. */
    bool payload_truncated;
};

struct fk_flow_key {
    uint8_t ip_version;
    uint8_t protocol;
    uint8_t low_addr[16];
    uint8_t high_addr[16];
    uint16_t low_port;
    uint16_t high_port;
};

/*
 * direction is the canonical lookup direction: 0 means low->high, 1 means
 * high->low.  The FLOWKEEP feature direction remains "first observed
 * endpoint" and must be recorded by the owning flow-table shard.
 */
enum fk_native_parse_code fk_native_parse_ethernet(
    const uint8_t *frame,
    size_t captured_len,
    uint32_t wire_len,
    struct fk_packet_view *view);

enum fk_native_parse_code fk_native_flow_key(
    const struct fk_packet_view *view,
    struct fk_flow_key *key,
    uint8_t *direction);

bool fk_flow_key_equal(
    const struct fk_flow_key *left,
    const struct fk_flow_key *right);

uint64_t fk_flow_key_hash(const struct fk_flow_key *key);

/*
 * Exact packet-level primitives for the 30-field offline TCP-G1 schema.
 * They deliberately contain no endpoint identity or payload content.  The
 * caller still owns the bounded per-window flow table and timestamp needed
 * for lifecycle and same-direction burst aggregation.
 */
struct fk_tcp_g1_packet_observation {
    bool syn_without_ack;
    bool syn_ack;
    bool ack_only;
    bool psh;
    bool rst;
    bool fin;
    uint32_t payload_sequence;
    uint32_t payload_size;
    uint32_t wire_size;
};

enum fk_native_parse_code fk_native_tcp_g1_packet(
    const struct fk_packet_view *view,
    struct fk_tcp_g1_packet_observation *observation);

int32_t fk_native_tcp_sequence_delta(uint32_t left, uint32_t right);

enum fk_quic_inspection {
    FK_QUIC_NOT_DETECTED = 0,
    FK_QUIC_LONG_HEADER_PARTIAL,
    FK_QUIC_VERSION_NEGOTIATION_PARTIAL,
};

enum fk_quic_long_packet_type {
    FK_QUIC_LONG_PACKET_UNKNOWN = 0,
    FK_QUIC_LONG_PACKET_INITIAL,
    FK_QUIC_LONG_PACKET_ZERO_RTT,
    FK_QUIC_LONG_PACKET_HANDSHAKE,
    FK_QUIC_LONG_PACKET_RETRY,
};

struct fk_quic_header_observation {
    enum fk_quic_inspection status;
    enum fk_protocol_completeness completeness;
    enum fk_quic_long_packet_type long_packet_type;
    uint32_t version;
    uint8_t long_packet_type_bits;
    uint8_t destination_cid_length;
    uint8_t source_cid_length;
    uint8_t destination_cid[20];
    uint8_t source_cid[20];
};

/*
 * This is intentionally only a bounded clear-header inspector.  It always
 * reports PARTIAL for QUIC.  It must not be used as evidence that QUIC Initial
 * header protection, AEAD decryption, or CRYPTO reassembly is implemented.
 */
enum fk_native_parse_code fk_native_inspect_quic_header(
    const struct fk_packet_view *view,
    struct fk_quic_header_observation *observation);

enum fk_tls_hello_kind {
    FK_TLS_CLIENT_HELLO = 1,
    FK_TLS_SERVER_HELLO = 2,
};

enum fk_tls_hello_framing {
    FK_TLS_RECORD_FRAMING = 1,
    FK_SSLV2_COMPATIBLE_FRAMING = 2,
};

struct fk_tls_hello {
    enum fk_tls_hello_kind kind;
    enum fk_tls_hello_framing framing;
    enum fk_protocol_completeness completeness;
    uint16_t legacy_version;
    uint16_t selected_cipher;
    bool hello_retry_request;

    uint16_t cipher_count;
    uint16_t ciphers[FK_TLS_CIPHER_CAP];
    uint16_t extension_count;
    uint16_t extensions[FK_TLS_EXTENSION_CAP];
    uint16_t supported_version_count;
    uint16_t supported_versions[FK_TLS_SUPPORTED_VERSION_CAP];
    uint16_t signature_algorithm_count;
    uint16_t signature_algorithms[FK_TLS_SIGNATURE_ALGORITHM_CAP];

    char server_name[FK_TLS_SNI_CAP];
    char alpn[FK_TLS_ALPN_CAP];
};

typedef void (*fk_tls_hello_callback)(
    const struct fk_tls_hello *hello,
    void *user);

bool fk_tls_parse_hello_body(
    enum fk_tls_hello_kind kind,
    const uint8_t *body,
    size_t body_length,
    struct fk_tls_hello *hello);

bool fk_tls_parse_sslv2_client_hello_body(
    const uint8_t *body,
    size_t body_length,
    struct fk_tls_hello *hello);

struct fk_tls_stream {
    uint8_t record_header[5];
    uint8_t record_header_bytes;
    uint8_t record_content_type;
    bool record_is_sslv2_client_hello;
    uint32_t record_remaining;

    uint8_t handshake_header[4];
    uint8_t handshake_header_bytes;
    uint8_t handshake_type;
    uint32_t handshake_length;
    uint32_t handshake_remaining;
    uint32_t handshake_body_bytes;
    uint8_t handshake_body[FK_TLS_HANDSHAKE_BODY_CAP];

    enum fk_protocol_completeness completeness;
    uint64_t bytes_seen;
    uint64_t records_seen;
    uint64_t handshake_messages_seen;
    uint64_t hello_messages_emitted;
    uint64_t malformed_records;
    uint64_t cap_exceeded_messages;
};

void fk_tls_stream_init(struct fk_tls_stream *stream);

enum fk_protocol_completeness fk_tls_stream_feed(
    struct fk_tls_stream *stream,
    const uint8_t *data,
    size_t length,
    fk_tls_hello_callback callback,
    void *user);

struct fk_tcp_ooo_slot {
    bool used;
    uint32_t sequence;
    uint16_t length;
    uint8_t data[FK_TCP_OOO_PAYLOAD_CAP];
};

struct fk_tcp_tls_direction {
    bool sequence_initialized;
    bool desynchronized;
    bool closed;
    uint32_t next_sequence;
    struct fk_tcp_ooo_slot ooo[FK_TCP_OOO_SLOTS];
    struct fk_tls_stream tls;
    uint64_t retransmitted_bytes;
    uint64_t out_of_order_segments;
    uint64_t gap_events;
};

struct fk_tcp_tls_flow {
    struct fk_tcp_tls_direction direction[2];
    enum fk_protocol_completeness completeness;
};

void fk_tcp_tls_flow_init(struct fk_tcp_tls_flow *flow);

enum fk_protocol_completeness fk_tcp_tls_flow_feed(
    struct fk_tcp_tls_flow *flow,
    uint8_t direction,
    uint32_t tcp_sequence,
    uint8_t tcp_flags,
    const uint8_t *payload,
    size_t payload_length,
    fk_tls_hello_callback callback,
    void *user);

const char *fk_native_parse_code_name(enum fk_native_parse_code code);
const char *fk_protocol_completeness_name(
    enum fk_protocol_completeness completeness);

#ifdef __cplusplus
}
#endif

#endif
