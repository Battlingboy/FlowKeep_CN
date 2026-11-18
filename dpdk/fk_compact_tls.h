#ifndef FLOWKEEP_FK_COMPACT_TLS_H
#define FLOWKEEP_FK_COMPACT_TLS_H

#include <stddef.h>
#include <stdint.h>

#include "fk_native_parser.h"

#ifdef __cplusplus
extern "C" {
#endif

#define FK_COMPACT_TLS_HELLO_CAP 4096u

struct fk_compact_tls_stream {
    uint8_t record_header[5];
    uint8_t handshake_header[4];
    uint8_t record_header_bytes;
    uint8_t handshake_header_bytes;
    uint8_t record_content_type;
    uint8_t handshake_type;
    uint8_t application_data_seen;
    uint8_t record_is_sslv2_client_hello;
    uint32_t record_remaining;
    uint32_t handshake_length;
    uint32_t handshake_remaining;
    uint32_t retained_body_bytes;
    uint8_t hello_body[FK_COMPACT_TLS_HELLO_CAP];
    enum fk_protocol_completeness completeness;
    uint64_t bytes_seen;
    uint64_t records_seen;
    uint64_t hello_messages_emitted;
    uint64_t cap_exceeded_messages;
    uint64_t malformed_records;
};

struct fk_compact_tls_direction {
    struct fk_compact_tls_stream tls;
    uint32_t next_sequence;
    uint8_t sequence_initialized;
    uint8_t desynchronized;
    uint8_t closed;
    uint8_t reserved;
    uint64_t retransmitted_bytes;
    uint64_t gap_events;
};

struct fk_compact_tls_flow {
    struct fk_compact_tls_direction direction[2];
    enum fk_protocol_completeness completeness;
};

void fk_compact_tls_flow_init(struct fk_compact_tls_flow *flow);

enum fk_protocol_completeness fk_compact_tls_flow_feed(
    struct fk_compact_tls_flow *flow,
    uint8_t direction,
    uint32_t tcp_sequence,
    uint8_t tcp_flags,
    const uint8_t *payload,
    size_t payload_length,
    fk_tls_hello_callback callback,
    void *user);

#ifdef __cplusplus
}
#endif

#endif
