#include "fk_compact_tls.h"

#include <algorithm>
#include <cstring>
#include <limits>

namespace {

static uint16_t read_be16(const uint8_t *data) {
    return static_cast<uint16_t>(
        (static_cast<uint16_t>(data[0]) << 8u) | data[1]);
}

static uint32_t read_be24(const uint8_t *data) {
    return
        (static_cast<uint32_t>(data[0]) << 16u) |
        (static_cast<uint32_t>(data[1]) << 8u) |
        static_cast<uint32_t>(data[2]);
}

static bool sequence_after(uint32_t left, uint32_t right) {
    return static_cast<int32_t>(left - right) > 0;
}

static void reset_handshake(fk_compact_tls_stream &stream) {
    stream.handshake_header_bytes = 0u;
    stream.handshake_type = 0u;
    stream.handshake_length = 0u;
    stream.handshake_remaining = 0u;
    stream.retained_body_bytes = 0u;
}

static void complete_handshake(
        fk_compact_tls_stream &stream,
        fk_tls_hello_callback callback,
        void *user) {
    if (stream.handshake_type == FK_TLS_CLIENT_HELLO ||
        stream.handshake_type == FK_TLS_SERVER_HELLO) {
        if (stream.handshake_length > FK_COMPACT_TLS_HELLO_CAP) {
            stream.completeness = FK_COMPLETENESS_CAP_EXCEEDED;
        } else {
            fk_tls_hello hello{};
            const bool valid = fk_tls_parse_hello_body(
                static_cast<fk_tls_hello_kind>(stream.handshake_type),
                stream.hello_body,
                stream.retained_body_bytes,
                &hello);
            if (!valid) {
                stream.malformed_records++;
                stream.completeness = FK_COMPLETENESS_MALFORMED;
            } else {
                stream.completeness = hello.completeness;
                stream.hello_messages_emitted++;
                if (callback != nullptr)
                    callback(&hello, user);
            }
        }
    }
    reset_handshake(stream);
}

static void feed_handshake(
        fk_compact_tls_stream &stream,
        const uint8_t *data,
        size_t length,
        fk_tls_hello_callback callback,
        void *user) {
    size_t offset = 0u;
    while (offset < length) {
        if (stream.handshake_header_bytes < 4u) {
            const size_t copy = std::min(
                static_cast<size_t>(4u - stream.handshake_header_bytes),
                length - offset);
            std::memcpy(
                stream.handshake_header + stream.handshake_header_bytes,
                data + offset,
                copy);
            stream.handshake_header_bytes += static_cast<uint8_t>(copy);
            offset += copy;
            if (stream.handshake_header_bytes < 4u)
                continue;
            stream.handshake_type = stream.handshake_header[0];
            stream.handshake_length =
                read_be24(stream.handshake_header + 1u);
            stream.handshake_remaining = stream.handshake_length;
            stream.retained_body_bytes = 0u;
            if (stream.handshake_length > FK_COMPACT_TLS_HELLO_CAP &&
                (stream.handshake_type == FK_TLS_CLIENT_HELLO ||
                 stream.handshake_type == FK_TLS_SERVER_HELLO)) {
                stream.cap_exceeded_messages++;
                stream.completeness = FK_COMPLETENESS_CAP_EXCEEDED;
            }
            if (stream.handshake_remaining == 0u) {
                complete_handshake(stream, callback, user);
                continue;
            }
        }
        const size_t consume = std::min(
            static_cast<size_t>(stream.handshake_remaining),
            length - offset);
        const bool retain =
            (stream.handshake_type == FK_TLS_CLIENT_HELLO ||
             stream.handshake_type == FK_TLS_SERVER_HELLO) &&
            stream.handshake_length <= FK_COMPACT_TLS_HELLO_CAP;
        if (retain) {
            std::memcpy(
                stream.hello_body + stream.retained_body_bytes,
                data + offset,
                consume);
            stream.retained_body_bytes += static_cast<uint32_t>(consume);
        }
        stream.handshake_remaining -= static_cast<uint32_t>(consume);
        offset += consume;
        if (stream.handshake_remaining == 0u)
            complete_handshake(stream, callback, user);
    }
}

static enum fk_protocol_completeness feed_stream(
        fk_compact_tls_stream &stream,
        const uint8_t *data,
        size_t length,
        fk_tls_hello_callback callback,
        void *user) {
    if (stream.completeness == FK_COMPLETENESS_MALFORMED ||
        stream.completeness == FK_COMPLETENESS_CAP_EXCEEDED)
        return stream.completeness;
    stream.bytes_seen += length;
    size_t offset = 0u;
    while (offset < length) {
        if (stream.record_remaining == 0u &&
            stream.record_header_bytes < 2u) {
            const size_t copy = std::min(
                static_cast<size_t>(2u - stream.record_header_bytes),
                length - offset);
            std::memcpy(
                stream.record_header + stream.record_header_bytes,
                data + offset, copy);
            stream.record_header_bytes += static_cast<uint8_t>(copy);
            offset += copy;
            if (stream.record_header_bytes < 2u)
                continue;
        }
        if (stream.record_remaining == 0u &&
            stream.record_header_bytes == 2u &&
            (stream.record_header[0] & 0x80u) != 0u) {
            const uint16_t record_length = static_cast<uint16_t>(
                ((stream.record_header[0] & 0x7fu) << 8u) |
                stream.record_header[1]);
            if (record_length < 9u ||
                stream.handshake_header_bytes != 0u ||
                stream.handshake_remaining != 0u) {
                stream.malformed_records++;
                stream.completeness = FK_COMPLETENESS_MALFORMED;
                return stream.completeness;
            }
            if (record_length > FK_COMPACT_TLS_HELLO_CAP) {
                stream.cap_exceeded_messages++;
                stream.completeness = FK_COMPLETENESS_CAP_EXCEEDED;
                return stream.completeness;
            }
            stream.record_is_sslv2_client_hello = 1u;
            stream.record_content_type = 0u;
            stream.record_remaining = record_length;
            stream.retained_body_bytes = 0u;
            stream.records_seen++;
        } else if (stream.record_remaining == 0u) {
            const size_t copy = std::min(
                static_cast<size_t>(5u - stream.record_header_bytes),
                length - offset);
            std::memcpy(
                stream.record_header + stream.record_header_bytes,
                data + offset,
                copy);
            stream.record_header_bytes += static_cast<uint8_t>(copy);
            offset += copy;
            if (stream.record_header_bytes < 5u)
                continue;
            const uint8_t type = stream.record_header[0];
            const uint16_t version = read_be16(stream.record_header + 1u);
            const uint16_t record_length =
                read_be16(stream.record_header + 3u);
            if (type < FK_TLS_CONTENT_CHANGE_CIPHER_SPEC ||
                type > FK_TLS_CONTENT_HEARTBEAT ||
                (version & 0xff00u) != 0x0300u ||
                record_length > FK_TLS_RECORD_PLAINTEXT_MAX) {
                stream.malformed_records++;
                stream.completeness = FK_COMPLETENESS_MALFORMED;
                return stream.completeness;
            }
            stream.record_is_sslv2_client_hello = 0u;
            stream.record_content_type = type;
            if (type == FK_TLS_CONTENT_APPLICATION_DATA)
                stream.application_data_seen = 1u;
            stream.record_remaining = record_length;
            stream.records_seen++;
            if (record_length == 0u) {
                stream.record_header_bytes = 0u;
                continue;
            }
        }
        const size_t consume = std::min(
            static_cast<size_t>(stream.record_remaining),
            length - offset);
        if (stream.record_is_sslv2_client_hello != 0u) {
            std::memcpy(
                stream.hello_body + stream.retained_body_bytes,
                data + offset, consume);
            stream.retained_body_bytes += static_cast<uint32_t>(consume);
        } else if (stream.record_content_type == FK_TLS_CONTENT_HANDSHAKE) {
            feed_handshake(
                stream, data + offset, consume, callback, user);
        }
        stream.record_remaining -= static_cast<uint32_t>(consume);
        offset += consume;
        if (stream.record_remaining == 0u) {
            if (stream.record_is_sslv2_client_hello != 0u) {
                fk_tls_hello hello{};
                if (!fk_tls_parse_sslv2_client_hello_body(
                        stream.hello_body, stream.retained_body_bytes, &hello)) {
                    stream.malformed_records++;
                    stream.completeness = FK_COMPLETENESS_MALFORMED;
                    return stream.completeness;
                }
                stream.completeness = hello.completeness;
                stream.hello_messages_emitted++;
                if (callback != nullptr)
                    callback(&hello, user);
                stream.retained_body_bytes = 0u;
            }
            stream.record_header_bytes = 0u;
            stream.record_is_sslv2_client_hello = 0u;
        }
    }
    if (stream.completeness == FK_COMPLETENESS_NONE)
        stream.completeness = FK_COMPLETENESS_PARTIAL;
    return stream.completeness;
}

static enum fk_protocol_completeness aggregate_flow_completeness(
        const fk_compact_tls_flow &flow) {
    for (const auto &direction : flow.direction) {
        if (direction.tls.completeness == FK_COMPLETENESS_MALFORMED)
            return FK_COMPLETENESS_MALFORMED;
    }
    for (const auto &direction : flow.direction) {
        if (direction.tls.completeness == FK_COMPLETENESS_CAP_EXCEEDED)
            return FK_COMPLETENESS_CAP_EXCEEDED;
    }
    for (const auto &direction : flow.direction) {
        if (direction.desynchronized != 0u)
            return FK_COMPLETENESS_PARTIAL;
    }
    for (const auto &direction : flow.direction) {
        if (direction.tls.completeness == FK_COMPLETENESS_COMPLETE)
            return FK_COMPLETENESS_COMPLETE;
    }
    for (const auto &direction : flow.direction) {
        if (direction.tls.completeness == FK_COMPLETENESS_PARTIAL)
            return FK_COMPLETENESS_PARTIAL;
    }
    return FK_COMPLETENESS_NONE;
}

}  // namespace

extern "C" {

void fk_compact_tls_flow_init(fk_compact_tls_flow *flow) {
    if (flow == nullptr)
        return;
    *flow = {};
    flow->completeness = FK_COMPLETENESS_NONE;
}

fk_protocol_completeness fk_compact_tls_flow_feed(
        fk_compact_tls_flow *flow,
        uint8_t direction_index,
        uint32_t tcp_sequence,
        uint8_t tcp_flags,
        const uint8_t *payload,
        size_t payload_length,
        fk_tls_hello_callback callback,
        void *user) {
    if (flow == nullptr || direction_index > 1u ||
        (payload == nullptr && payload_length != 0u) ||
        payload_length > std::numeric_limits<uint32_t>::max())
        return FK_COMPLETENESS_MALFORMED;
    fk_compact_tls_direction &direction =
        flow->direction[direction_index];
    const uint32_t data_sequence =
        tcp_sequence + ((tcp_flags & FK_TCP_FLAG_SYN) != 0u ? 1u : 0u);
    if (!direction.sequence_initialized &&
        ((tcp_flags & FK_TCP_FLAG_SYN) != 0u || payload_length != 0u)) {
        direction.sequence_initialized = 1u;
        direction.next_sequence = data_sequence;
    }
    if (payload_length != 0u && direction.sequence_initialized) {
        if (sequence_after(data_sequence, direction.next_sequence)) {
            direction.desynchronized = 1u;
            direction.gap_events++;
        } else {
            const uint32_t overlap =
                direction.next_sequence - data_sequence;
            if (overlap >= payload_length) {
                direction.retransmitted_bytes += payload_length;
            } else {
                direction.retransmitted_bytes += overlap;
                (void)feed_stream(
                    direction.tls,
                    payload + overlap,
                    payload_length - overlap,
                    callback,
                    user);
                direction.next_sequence +=
                    static_cast<uint32_t>(payload_length - overlap);
            }
        }
    }
    if ((tcp_flags & (FK_TCP_FLAG_FIN | FK_TCP_FLAG_RST)) != 0u)
        direction.closed = 1u;
    flow->completeness = aggregate_flow_completeness(*flow);
    return flow->completeness;
}

}  // extern "C"
