#include "fk_native_parser.h"

#include <limits.h>
#include <string.h>

#define FK_ETHERNET_HEADER_BYTES 14u
#define FK_IPV4_MIN_HEADER_BYTES 20u
#define FK_IPV6_HEADER_BYTES 40u
#define FK_TCP_MIN_HEADER_BYTES 20u
#define FK_UDP_HEADER_BYTES 8u

#define FK_ETHERTYPE_IPV4 0x0800u
#define FK_ETHERTYPE_IPV6 0x86ddu
#define FK_ETHERTYPE_VLAN 0x8100u
#define FK_ETHERTYPE_QINQ 0x88a8u
#define FK_ETHERTYPE_VLAN_9100 0x9100u

#define FK_IPPROTO_TCP 6u
#define FK_IPPROTO_UDP 17u


#define FK_TLS_EXT_SERVER_NAME 0u
#define FK_TLS_EXT_SIGNATURE_ALGORITHMS 13u
#define FK_TLS_EXT_ALPN 16u
#define FK_TLS_EXT_SUPPORTED_VERSIONS 43u

static uint16_t read_be16(const uint8_t *data) {
    return (uint16_t)(((uint16_t)data[0] << 8) | (uint16_t)data[1]);
}

static uint32_t read_be24(const uint8_t *data) {
    return ((uint32_t)data[0] << 16) |
           ((uint32_t)data[1] << 8) |
           (uint32_t)data[2];
}

static uint32_t read_be32(const uint8_t *data) {
    return ((uint32_t)data[0] << 24) |
           ((uint32_t)data[1] << 16) |
           ((uint32_t)data[2] << 8) |
           (uint32_t)data[3];
}

static bool vlan_ethertype(uint16_t ether_type) {
    return ether_type == FK_ETHERTYPE_VLAN ||
           ether_type == FK_ETHERTYPE_QINQ ||
           ether_type == FK_ETHERTYPE_VLAN_9100;
}

static enum fk_native_parse_code parse_transport(
        const uint8_t *transport,
        size_t transport_bytes,
        struct fk_packet_view *view) {
    if (view->l4_protocol == FK_IPPROTO_TCP) {
        if (transport_bytes < FK_TCP_MIN_HEADER_BYTES)
            return FK_PARSE_TRUNCATED;
        size_t header_bytes =
            (size_t)((transport[12] >> 4) & 0x0fu) * 4u;
        if (header_bytes < FK_TCP_MIN_HEADER_BYTES)
            return FK_PARSE_MALFORMED;
        if (header_bytes > transport_bytes)
            return FK_PARSE_TRUNCATED;
        view->src_port = read_be16(transport);
        view->dst_port = read_be16(transport + 2u);
        view->tcp_sequence = read_be32(transport + 4u);
        view->tcp_acknowledgement = read_be32(transport + 8u);
        view->tcp_flags = transport[13];
        view->tcp_window = read_be16(transport + 14u);
        view->transport_size = (uint32_t)transport_bytes;
        view->payload_size =
            (uint32_t)(transport_bytes - header_bytes);
        view->payload = transport + header_bytes;
        return FK_PARSE_OK;
    }
    if (view->l4_protocol == FK_IPPROTO_UDP) {
        if (transport_bytes < FK_UDP_HEADER_BYTES)
            return FK_PARSE_TRUNCATED;
        uint16_t udp_length = read_be16(transport + 4u);
        if (udp_length < FK_UDP_HEADER_BYTES)
            return FK_PARSE_MALFORMED;
        if ((size_t)udp_length > transport_bytes)
            return FK_PARSE_TRUNCATED;
        view->src_port = read_be16(transport);
        view->dst_port = read_be16(transport + 2u);
        view->transport_size = udp_length;
        view->payload_size =
            (uint32_t)udp_length - FK_UDP_HEADER_BYTES;
        view->payload = transport + FK_UDP_HEADER_BYTES;
        return FK_PARSE_OK;
    }
    return FK_PARSE_UNSUPPORTED_L4;
}

static enum fk_native_parse_code parse_ipv4(
        const uint8_t *packet,
        size_t packet_bytes,
        struct fk_packet_view *view) {
    if (packet_bytes < FK_IPV4_MIN_HEADER_BYTES)
        return FK_PARSE_TRUNCATED;
    if ((packet[0] >> 4) != 4u)
        return FK_PARSE_MALFORMED;
    size_t header_bytes = (size_t)(packet[0] & 0x0fu) * 4u;
    if (header_bytes < FK_IPV4_MIN_HEADER_BYTES)
        return FK_PARSE_MALFORMED;
    if (header_bytes > packet_bytes)
        return FK_PARSE_TRUNCATED;
    uint16_t total_length = read_be16(packet + 2u);
    if ((size_t)total_length < header_bytes)
        return FK_PARSE_MALFORMED;
    size_t available_length = total_length;
    if (available_length > packet_bytes) {
        available_length = packet_bytes;
        view->payload_truncated = true;
    }
    uint16_t fragment = read_be16(packet + 6u);
    if ((fragment & 0x3fffu) != 0u)
        return FK_PARSE_FRAGMENTED;

    view->ip_version = 4u;
    view->l4_protocol = packet[9];
    memcpy(view->src_addr, packet + 12u, 4u);
    memcpy(view->dst_addr, packet + 16u, 4u);
    view->ip_size = total_length;
    return parse_transport(
        packet + header_bytes,
        available_length - header_bytes,
        view);
}

static enum fk_native_parse_code parse_ipv6(
        const uint8_t *packet,
        size_t packet_bytes,
        struct fk_packet_view *view) {
    if (packet_bytes < FK_IPV6_HEADER_BYTES)
        return FK_PARSE_TRUNCATED;
    if ((packet[0] >> 4) != 6u)
        return FK_PARSE_MALFORMED;
    uint16_t payload_length = read_be16(packet + 4u);
    if (payload_length == 0u) {
        /* IPv6 jumbograms require Hop-by-Hop Jumbo Payload processing. */
        return FK_PARSE_UNSUPPORTED_L3;
    }
    size_t packet_end = FK_IPV6_HEADER_BYTES + (size_t)payload_length;
    if (packet_end > packet_bytes)
        return FK_PARSE_TRUNCATED;

    view->ip_version = 6u;
    memcpy(view->src_addr, packet + 8u, 16u);
    memcpy(view->dst_addr, packet + 24u, 16u);
    view->ip_size = (uint32_t)packet_end;

    uint8_t next_header = packet[6];
    size_t offset = FK_IPV6_HEADER_BYTES;
    unsigned extension_count = 0u;
    size_t extension_bytes = 0u;
    for (;;) {
        size_t current_bytes = 0u;
        uint8_t following = 0u;
        if (next_header == 0u || next_header == 43u ||
            next_header == 60u) {
            if (offset + 2u > packet_end)
                return FK_PARSE_TRUNCATED;
            following = packet[offset];
            current_bytes = ((size_t)packet[offset + 1u] + 1u) * 8u;
        } else if (next_header == 44u) {
            if (offset + 8u > packet_end)
                return FK_PARSE_TRUNCATED;
            following = packet[offset];
            uint16_t fragment = read_be16(packet + offset + 2u);
            if ((fragment & 0xfff9u) != 0u)
                return FK_PARSE_FRAGMENTED;
            current_bytes = 8u;
        } else if (next_header == 51u) {
            if (offset + 2u > packet_end)
                return FK_PARSE_TRUNCATED;
            following = packet[offset];
            current_bytes = ((size_t)packet[offset + 1u] + 2u) * 4u;
        } else {
            break;
        }
        extension_count++;
        extension_bytes += current_bytes;
        if (extension_count > FK_MAX_IPV6_EXTENSION_HEADERS ||
            extension_bytes > FK_MAX_IPV6_EXTENSION_BYTES)
            return FK_PARSE_CAP_EXCEEDED;
        if (current_bytes < 8u || offset + current_bytes > packet_end)
            return FK_PARSE_TRUNCATED;
        offset += current_bytes;
        next_header = following;
    }

    view->l4_protocol = next_header;
    return parse_transport(
        packet + offset,
        packet_end - offset,
        view);
}

enum fk_native_parse_code fk_native_parse_ethernet(
        const uint8_t *frame,
        size_t captured_len,
        uint32_t wire_len,
        struct fk_packet_view *view) {
    if (view == NULL)
        return FK_PARSE_MALFORMED;
    memset(view, 0, sizeof(*view));
    if (frame == NULL || captured_len < FK_ETHERNET_HEADER_BYTES) {
        view->code = FK_PARSE_TRUNCATED;
        return view->code;
    }
    if (captured_len > UINT32_MAX) {
        view->code = FK_PARSE_CAP_EXCEEDED;
        return view->code;
    }
    view->captured_size = (uint32_t)captured_len;
    view->wire_size = wire_len;

    size_t offset = FK_ETHERNET_HEADER_BYTES;
    uint16_t ether_type = read_be16(frame + 12u);
    while (vlan_ethertype(ether_type)) {
        if (view->vlan_count >= FK_MAX_VLAN_TAGS) {
            view->code = FK_PARSE_CAP_EXCEEDED;
            return view->code;
        }
        if (offset + 4u > captured_len) {
            view->code = FK_PARSE_TRUNCATED;
            return view->code;
        }
        view->vlan_tci[view->vlan_count] = read_be16(frame + offset);
        view->vlan_count++;
        ether_type = read_be16(frame + offset + 2u);
        offset += 4u;
    }
    view->ether_type = ether_type;
    if (offset > captured_len) {
        view->code = FK_PARSE_TRUNCATED;
        return view->code;
    }
    if (ether_type == FK_ETHERTYPE_IPV4)
        view->code = parse_ipv4(frame + offset, captured_len - offset, view);
    else if (ether_type == FK_ETHERTYPE_IPV6)
        view->code = parse_ipv6(frame + offset, captured_len - offset, view);
    else
        view->code = FK_PARSE_UNSUPPORTED_L3;
    return view->code;
}

static int endpoint_compare(
        const uint8_t *left_addr,
        uint16_t left_port,
        const uint8_t *right_addr,
        uint16_t right_port,
        size_t address_bytes) {
    int result = memcmp(left_addr, right_addr, address_bytes);
    if (result != 0)
        return result;
    if (left_port < right_port)
        return -1;
    if (left_port > right_port)
        return 1;
    return 0;
}

enum fk_native_parse_code fk_native_flow_key(
        const struct fk_packet_view *view,
        struct fk_flow_key *key,
        uint8_t *direction) {
    if (view == NULL || key == NULL || direction == NULL)
        return FK_PARSE_MALFORMED;
    if (view->code != FK_PARSE_OK)
        return view->code;
    if (view->ip_version != 4u && view->ip_version != 6u)
        return FK_PARSE_UNSUPPORTED_L3;
    if (view->l4_protocol != FK_IPPROTO_TCP &&
        view->l4_protocol != FK_IPPROTO_UDP)
        return FK_PARSE_UNSUPPORTED_L4;

    memset(key, 0, sizeof(*key));
    key->ip_version = view->ip_version;
    key->protocol = view->l4_protocol;
    size_t address_bytes = view->ip_version == 4u ? 4u : 16u;
    int order = endpoint_compare(
        view->src_addr,
        view->src_port,
        view->dst_addr,
        view->dst_port,
        address_bytes);
    if (order <= 0) {
        memcpy(key->low_addr, view->src_addr, address_bytes);
        memcpy(key->high_addr, view->dst_addr, address_bytes);
        key->low_port = view->src_port;
        key->high_port = view->dst_port;
        *direction = 0u;
    } else {
        memcpy(key->low_addr, view->dst_addr, address_bytes);
        memcpy(key->high_addr, view->src_addr, address_bytes);
        key->low_port = view->dst_port;
        key->high_port = view->src_port;
        *direction = 1u;
    }
    return FK_PARSE_OK;
}

bool fk_flow_key_equal(
        const struct fk_flow_key *left,
        const struct fk_flow_key *right) {
    if (left == NULL || right == NULL)
        return false;
    return memcmp(left, right, sizeof(*left)) == 0;
}

uint64_t fk_flow_key_hash(const struct fk_flow_key *key) {
    if (key == NULL)
        return 0u;
    const uint8_t *data = (const uint8_t *)key;
    uint64_t hash = 1469598103934665603ull;
    for (size_t index = 0; index < sizeof(*key); ++index) {
        hash ^= data[index];
        hash *= 1099511628211ull;
    }
    return hash;
}

enum fk_native_parse_code fk_native_tcp_g1_packet(
        const struct fk_packet_view *view,
        struct fk_tcp_g1_packet_observation *observation) {
    if (observation == NULL)
        return FK_PARSE_MALFORMED;
    memset(observation, 0, sizeof(*observation));
    if (view == NULL)
        return FK_PARSE_MALFORMED;
    if (view->code != FK_PARSE_OK)
        return view->code;
    if (view->l4_protocol != FK_IPPROTO_TCP)
        return FK_PARSE_UNSUPPORTED_L4;
    observation->syn_without_ack =
        (view->tcp_flags & FK_TCP_FLAG_SYN) != 0u &&
        (view->tcp_flags & FK_TCP_FLAG_ACK) == 0u;
    observation->syn_ack =
        (view->tcp_flags & (FK_TCP_FLAG_SYN | FK_TCP_FLAG_ACK)) ==
        (FK_TCP_FLAG_SYN | FK_TCP_FLAG_ACK);
    observation->ack_only =
        (view->tcp_flags & FK_TCP_FLAG_ACK) != 0u &&
        (view->tcp_flags &
         (FK_TCP_FLAG_SYN | FK_TCP_FLAG_FIN | FK_TCP_FLAG_RST)) == 0u &&
        view->payload_size == 0u;
    observation->psh =
        (view->tcp_flags & FK_TCP_FLAG_PSH) != 0u;
    observation->rst =
        (view->tcp_flags & FK_TCP_FLAG_RST) != 0u;
    observation->fin =
        (view->tcp_flags & FK_TCP_FLAG_FIN) != 0u;
    observation->payload_sequence =
        view->tcp_sequence +
        ((view->tcp_flags & FK_TCP_FLAG_SYN) != 0u ? 1u : 0u);
    observation->payload_size = view->payload_size;
    observation->wire_size = view->wire_size;
    return FK_PARSE_OK;
}

int32_t fk_native_tcp_sequence_delta(uint32_t left, uint32_t right) {
    return (int32_t)(left - right);
}

enum fk_native_parse_code fk_native_inspect_quic_header(
        const struct fk_packet_view *view,
        struct fk_quic_header_observation *observation) {
    if (observation == NULL)
        return FK_PARSE_MALFORMED;
    memset(observation, 0, sizeof(*observation));
    observation->status = FK_QUIC_NOT_DETECTED;
    observation->completeness = FK_COMPLETENESS_NONE;
    if (view == NULL || view->code != FK_PARSE_OK)
        return view == NULL ? FK_PARSE_MALFORMED : view->code;
    if (view->l4_protocol != FK_IPPROTO_UDP || view->payload_size == 0u)
        return FK_PARSE_OK;

    const uint8_t *data = view->payload;
    size_t length = view->payload_size;
    /* RFC 8999 makes only the most-significant Header Form bit invariant
     * across long headers.  In particular, Version Negotiation leaves the
     * remaining seven bits unused and receivers must ignore their values. */
    if ((data[0] & 0x80u) == 0u)
        return FK_PARSE_OK;
    observation->completeness = FK_COMPLETENESS_PARTIAL;
    if (length < 6u)
        return FK_PARSE_TRUNCATED;
    const uint32_t version = read_be32(data + 1u);
    const uint8_t long_packet_type_bits =
        (uint8_t)((data[0] >> 4u) & 0x03u);
    enum fk_quic_long_packet_type long_packet_type =
        FK_QUIC_LONG_PACKET_UNKNOWN;
    /* RFC 9000 Section 17.2 and RFC 9369 Section 3.2 use different
     * version-specific encodings.  Header protection masks only the low four
     * bits of a long header, so these two type bits remain inspectable. */
    if (version == 0x00000001u) {
        static const enum fk_quic_long_packet_type v1_types[4] = {
            FK_QUIC_LONG_PACKET_INITIAL,
            FK_QUIC_LONG_PACKET_ZERO_RTT,
            FK_QUIC_LONG_PACKET_HANDSHAKE,
            FK_QUIC_LONG_PACKET_RETRY,
        };
        long_packet_type = v1_types[long_packet_type_bits];
    } else if (version == 0x6b3343cfu) {
        static const enum fk_quic_long_packet_type v2_types[4] = {
            FK_QUIC_LONG_PACKET_RETRY,
            FK_QUIC_LONG_PACKET_INITIAL,
            FK_QUIC_LONG_PACKET_ZERO_RTT,
            FK_QUIC_LONG_PACKET_HANDSHAKE,
        };
        long_packet_type = v2_types[long_packet_type_bits];
    }
    size_t offset = 5u;
    const uint8_t dcid_length = data[offset++];
    if (dcid_length > sizeof(observation->destination_cid)) {
        observation->completeness = FK_COMPLETENESS_CAP_EXCEEDED;
        return FK_PARSE_CAP_EXCEEDED;
    }
    if (offset + dcid_length + 1u > length)
        return FK_PARSE_TRUNCATED;
    const uint8_t *destination_cid = data + offset;
    offset += dcid_length;
    const uint8_t scid_length = data[offset++];
    if (scid_length > sizeof(observation->source_cid)) {
        observation->completeness = FK_COMPLETENESS_CAP_EXCEEDED;
        return FK_PARSE_CAP_EXCEEDED;
    }
    if (offset + scid_length > length)
        return FK_PARSE_TRUNCATED;

    /* Publish the observation atomically from the caller's perspective only
     * after the complete clear-text CID envelope is present.  In particular,
     * a truncated SCID must not leave a consumable DCID behind. */
    observation->version = version;
    observation->long_packet_type_bits = long_packet_type_bits;
    observation->long_packet_type = long_packet_type;
    observation->destination_cid_length = dcid_length;
    memcpy(
        observation->destination_cid,
        destination_cid,
        dcid_length);
    observation->source_cid_length = scid_length;
    memcpy(observation->source_cid, data + offset, scid_length);
    if (version == 0u)
        observation->status = FK_QUIC_VERSION_NEGOTIATION_PARTIAL;
    else
        observation->status = FK_QUIC_LONG_HEADER_PARTIAL;
    return FK_PARSE_OK;
}

void fk_tls_stream_init(struct fk_tls_stream *stream) {
    if (stream == NULL)
        return;
    memset(stream, 0, sizeof(*stream));
    stream->completeness = FK_COMPLETENESS_NONE;
}

static bool take_bytes(
        const uint8_t *data,
        size_t length,
        size_t *offset,
        size_t count,
        const uint8_t **result) {
    if (*offset > length || count > length - *offset)
        return false;
    if (result != NULL)
        *result = data + *offset;
    *offset += count;
    return true;
}

static void mark_hello_partial(struct fk_tls_hello *hello) {
    if (hello->completeness == FK_COMPLETENESS_COMPLETE)
        hello->completeness = FK_COMPLETENESS_PARTIAL;
}

static void append_u16_bounded(
        uint16_t value,
        uint16_t *values,
        uint16_t capacity,
        uint16_t *count,
        struct fk_tls_hello *hello) {
    if (*count < capacity) {
        values[*count] = value;
        (*count)++;
    } else {
        mark_hello_partial(hello);
    }
}

static bool parse_server_name(
        const uint8_t *data,
        size_t length,
        struct fk_tls_hello *hello) {
    if (length < 2u)
        return false;
    size_t list_length = read_be16(data);
    if (list_length > length - 2u)
        return false;
    size_t offset = 2u;
    size_t end = offset + list_length;
    while (offset < end) {
        if (end - offset < 3u)
            return false;
        uint8_t name_type = data[offset++];
        uint16_t name_length = read_be16(data + offset);
        offset += 2u;
        if ((size_t)name_length > end - offset)
            return false;
        if (name_type == 0u && hello->server_name[0] == '\0') {
            size_t copy = name_length;
            if (copy >= sizeof(hello->server_name)) {
                copy = sizeof(hello->server_name) - 1u;
                mark_hello_partial(hello);
            }
            memcpy(hello->server_name, data + offset, copy);
            hello->server_name[copy] = '\0';
        }
        offset += name_length;
    }
    return offset == end;
}

static bool parse_alpn(
        const uint8_t *data,
        size_t length,
        struct fk_tls_hello *hello) {
    if (length < 2u)
        return false;
    size_t list_length = read_be16(data);
    if (list_length > length - 2u)
        return false;
    size_t offset = 2u;
    size_t end = offset + list_length;
    bool first = true;
    while (offset < end) {
        uint8_t item_length = data[offset++];
        if ((size_t)item_length > end - offset)
            return false;
        if (first) {
            size_t copy = item_length;
            if (copy >= sizeof(hello->alpn)) {
                copy = sizeof(hello->alpn) - 1u;
                mark_hello_partial(hello);
            }
            memcpy(hello->alpn, data + offset, copy);
            hello->alpn[copy] = '\0';
            first = false;
        }
        offset += item_length;
    }
    return offset == end;
}

static bool parse_signature_algorithms(
        const uint8_t *data,
        size_t length,
        struct fk_tls_hello *hello) {
    if (length < 2u)
        return false;
    size_t list_length = read_be16(data);
    if ((list_length & 1u) != 0u || list_length > length - 2u)
        return false;
    for (size_t offset = 2u; offset < 2u + list_length; offset += 2u) {
        append_u16_bounded(
            read_be16(data + offset),
            hello->signature_algorithms,
            FK_TLS_SIGNATURE_ALGORITHM_CAP,
            &hello->signature_algorithm_count,
            hello);
    }
    return true;
}

static bool parse_supported_versions(
        const uint8_t *data,
        size_t length,
        bool client,
        struct fk_tls_hello *hello) {
    if (client) {
        if (length < 1u)
            return false;
        size_t list_length = data[0];
        if ((list_length & 1u) != 0u || list_length > length - 1u)
            return false;
        for (size_t offset = 1u;
             offset < 1u + list_length;
             offset += 2u) {
            append_u16_bounded(
                read_be16(data + offset),
                hello->supported_versions,
                FK_TLS_SUPPORTED_VERSION_CAP,
                &hello->supported_version_count,
                hello);
        }
        return true;
    }
    if (length != 2u)
        return false;
    append_u16_bounded(
        read_be16(data),
        hello->supported_versions,
        FK_TLS_SUPPORTED_VERSION_CAP,
        &hello->supported_version_count,
        hello);
    return true;
}

static bool parse_extensions(
        const uint8_t *data,
        size_t length,
        bool client,
        struct fk_tls_hello *hello) {
    if (length == 0u)
        return true;
    if (length < 2u)
        return false;
    size_t extensions_length = read_be16(data);
    if (extensions_length != length - 2u)
        return false;
    size_t offset = 2u;
    while (offset < length) {
        if (length - offset < 4u)
            return false;
        uint16_t type = read_be16(data + offset);
        uint16_t extension_length = read_be16(data + offset + 2u);
        offset += 4u;
        if ((size_t)extension_length > length - offset)
            return false;
        append_u16_bounded(
            type,
            hello->extensions,
            FK_TLS_EXTENSION_CAP,
            &hello->extension_count,
            hello);
        const uint8_t *extension = data + offset;
        bool valid = true;
        /*
         * ClientHello carries the ServerNameList.  A ServerHello may carry an
         * empty server_name acknowledgement, so interpreting it as the client
         * list would incorrectly classify a valid TLS 1.2 hello as malformed.
         */
        if (type == FK_TLS_EXT_SERVER_NAME && client)
            valid = parse_server_name(extension, extension_length, hello);
        else if (type == FK_TLS_EXT_ALPN)
            valid = parse_alpn(extension, extension_length, hello);
        else if (type == FK_TLS_EXT_SIGNATURE_ALGORITHMS)
            valid = parse_signature_algorithms(
                extension,
                extension_length,
                hello);
        else if (type == FK_TLS_EXT_SUPPORTED_VERSIONS)
            valid = parse_supported_versions(
                extension,
                extension_length,
                client,
                hello);
        if (!valid)
            return false;
        offset += extension_length;
    }
    return offset == length;
}

static bool parse_client_hello(
        const uint8_t *body,
        size_t length,
        struct fk_tls_hello *hello) {
    size_t offset = 0u;
    const uint8_t *value = NULL;
    if (!take_bytes(body, length, &offset, 2u, &value))
        return false;
    hello->legacy_version = read_be16(value);
    if (!take_bytes(body, length, &offset, 32u, NULL))
        return false;
    if (!take_bytes(body, length, &offset, 1u, &value))
        return false;
    size_t session_length = value[0];
    if (!take_bytes(body, length, &offset, session_length, NULL))
        return false;
    if (!take_bytes(body, length, &offset, 2u, &value))
        return false;
    size_t cipher_bytes = read_be16(value);
    if ((cipher_bytes & 1u) != 0u ||
        !take_bytes(body, length, &offset, cipher_bytes, &value))
        return false;
    for (size_t index = 0u; index < cipher_bytes; index += 2u) {
        append_u16_bounded(
            read_be16(value + index),
            hello->ciphers,
            FK_TLS_CIPHER_CAP,
            &hello->cipher_count,
            hello);
    }
    if (!take_bytes(body, length, &offset, 1u, &value))
        return false;
    size_t compression_bytes = value[0];
    if (compression_bytes == 0u ||
        !take_bytes(body, length, &offset, compression_bytes, NULL))
        return false;
    return parse_extensions(body + offset, length - offset, true, hello);
}

static const uint8_t hello_retry_request_random[32] = {
    0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11,
    0xbe, 0x1d, 0x8c, 0x02, 0x1e, 0x65, 0xb8, 0x91,
    0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb, 0x8c, 0x5e,
    0x07, 0x9e, 0x09, 0xe2, 0xc8, 0xa8, 0x33, 0x9c,
};

static bool parse_server_hello(
        const uint8_t *body,
        size_t length,
        struct fk_tls_hello *hello) {
    size_t offset = 0u;
    const uint8_t *value = NULL;
    if (!take_bytes(body, length, &offset, 2u, &value))
        return false;
    hello->legacy_version = read_be16(value);
    if (!take_bytes(body, length, &offset, 32u, &value))
        return false;
    hello->hello_retry_request =
        memcmp(value, hello_retry_request_random, sizeof(hello_retry_request_random))
        == 0;
    if (!take_bytes(body, length, &offset, 1u, &value))
        return false;
    size_t session_length = value[0];
    if (!take_bytes(body, length, &offset, session_length, NULL))
        return false;
    if (!take_bytes(body, length, &offset, 2u, &value))
        return false;
    hello->selected_cipher = read_be16(value);
    if (!take_bytes(body, length, &offset, 1u, NULL))
        return false;
    return parse_extensions(body + offset, length - offset, false, hello);
}

bool fk_tls_parse_hello_body(
        enum fk_tls_hello_kind kind,
        const uint8_t *body,
        size_t body_length,
        struct fk_tls_hello *hello) {
    if (body == NULL || hello == NULL ||
        (kind != FK_TLS_CLIENT_HELLO &&
         kind != FK_TLS_SERVER_HELLO))
        return false;
    memset(hello, 0, sizeof(*hello));
    hello->kind = kind;
    hello->framing = FK_TLS_RECORD_FRAMING;
    hello->completeness = FK_COMPLETENESS_COMPLETE;
    bool valid = kind == FK_TLS_CLIENT_HELLO
        ? parse_client_hello(body, body_length, hello)
        : parse_server_hello(body, body_length, hello);
    if (!valid)
        hello->completeness = FK_COMPLETENESS_MALFORMED;
    return valid;
}

bool fk_tls_parse_sslv2_client_hello_body(
        const uint8_t *body,
        size_t length,
        struct fk_tls_hello *hello) {
    if (body == NULL || hello == NULL)
        return false;
    memset(hello, 0, sizeof(*hello));
    hello->kind = FK_TLS_CLIENT_HELLO;
    hello->framing = FK_SSLV2_COMPATIBLE_FRAMING;
    hello->completeness = FK_COMPLETENESS_COMPLETE;
    bool valid = length >= 9u && body[0] == FK_TLS_CLIENT_HELLO;
    uint16_t cipher_bytes = 0u;
    uint16_t session_bytes = 0u;
    uint16_t challenge_bytes = 0u;
    if (valid) {
        hello->legacy_version = read_be16(body + 1u);
        cipher_bytes = read_be16(body + 3u);
        session_bytes = read_be16(body + 5u);
        challenge_bytes = read_be16(body + 7u);
        size_t variable_bytes =
            (size_t)cipher_bytes + session_bytes + challenge_bytes;
        valid = cipher_bytes % 3u == 0u &&
                variable_bytes == length - 9u;
    }
    if (valid) {
        for (size_t offset = 9u;
             offset < 9u + cipher_bytes;
             offset += 3u) {
            /*
             * SSLv2 cipher specs are 24-bit.  Only the 0x00xxxx values
             * map losslessly into the TLS uint16_t cipher namespace.
             */
            if (body[offset] != 0u) {
                mark_hello_partial(hello);
                continue;
            }
            append_u16_bounded(
                read_be16(body + offset + 1u),
                hello->ciphers,
                FK_TLS_CIPHER_CAP,
                &hello->cipher_count,
                hello);
        }
    } else {
        hello->completeness = FK_COMPLETENESS_MALFORMED;
    }
    return valid;
}

static void complete_sslv2_client_hello(
        struct fk_tls_stream *stream,
        fk_tls_hello_callback callback,
        void *user) {
    stream->handshake_messages_seen++;
    struct fk_tls_hello hello;
    const bool valid = fk_tls_parse_sslv2_client_hello_body(
        stream->handshake_body, stream->handshake_body_bytes, &hello);
    if (valid) {
        if (stream->completeness != FK_COMPLETENESS_MALFORMED &&
            stream->completeness != FK_COMPLETENESS_CAP_EXCEEDED)
            stream->completeness = hello.completeness;
        stream->hello_messages_emitted++;
        if (callback != NULL)
            callback(&hello, user);
    } else {
        if (stream->completeness != FK_COMPLETENESS_CAP_EXCEEDED)
            stream->completeness = FK_COMPLETENESS_MALFORMED;
        stream->malformed_records++;
    }
    stream->handshake_body_bytes = 0u;
}

static void complete_handshake(
        struct fk_tls_stream *stream,
        fk_tls_hello_callback callback,
        void *user) {
    stream->handshake_messages_seen++;
    if (stream->handshake_type == FK_TLS_CLIENT_HELLO ||
        stream->handshake_type == FK_TLS_SERVER_HELLO) {
        if (stream->handshake_length > FK_TLS_HANDSHAKE_BODY_CAP) {
            stream->cap_exceeded_messages++;
            stream->completeness = FK_COMPLETENESS_CAP_EXCEEDED;
        } else {
            struct fk_tls_hello hello;
            bool valid = fk_tls_parse_hello_body(
                (enum fk_tls_hello_kind)stream->handshake_type,
                stream->handshake_body,
                stream->handshake_body_bytes,
                &hello);
            if (!valid) {
                hello.completeness = FK_COMPLETENESS_MALFORMED;
                if (stream->completeness != FK_COMPLETENESS_CAP_EXCEEDED)
                    stream->completeness = FK_COMPLETENESS_MALFORMED;
                stream->malformed_records++;
            } else {
                /*
                 * PARTIAL means "waiting for more bytes" and can become
                 * COMPLETE.  MALFORMED and CAP_EXCEEDED are terminal evidence
                 * and must never be hidden by a later valid hello.
                 */
                if (stream->completeness != FK_COMPLETENESS_MALFORMED &&
                    stream->completeness != FK_COMPLETENESS_CAP_EXCEEDED)
                    stream->completeness = hello.completeness;
                stream->hello_messages_emitted++;
                if (callback != NULL)
                    callback(&hello, user);
            }
        }
    }
    stream->handshake_header_bytes = 0u;
    stream->handshake_type = 0u;
    stream->handshake_length = 0u;
    stream->handshake_remaining = 0u;
    stream->handshake_body_bytes = 0u;
}

static void feed_handshake_bytes(
        struct fk_tls_stream *stream,
        const uint8_t *data,
        size_t length,
        fk_tls_hello_callback callback,
        void *user) {
    size_t offset = 0u;
    while (offset < length) {
        if (stream->handshake_header_bytes < 4u) {
            size_t needed = 4u - stream->handshake_header_bytes;
            size_t available = length - offset;
            size_t copy = needed < available ? needed : available;
            memcpy(
                stream->handshake_header + stream->handshake_header_bytes,
                data + offset,
                copy);
            stream->handshake_header_bytes += (uint8_t)copy;
            offset += copy;
            if (stream->handshake_header_bytes < 4u)
                continue;
            stream->handshake_type = stream->handshake_header[0];
            stream->handshake_length =
                read_be24(stream->handshake_header + 1u);
            stream->handshake_remaining = stream->handshake_length;
            stream->handshake_body_bytes = 0u;
            if (stream->handshake_remaining == 0u) {
                complete_handshake(stream, callback, user);
                continue;
            }
        }

        size_t available = length - offset;
        size_t consume =
            stream->handshake_remaining < available
                ? stream->handshake_remaining
                : available;
        bool retained =
            stream->handshake_type == FK_TLS_CLIENT_HELLO ||
            stream->handshake_type == FK_TLS_SERVER_HELLO;
        if (retained &&
            stream->handshake_length <= FK_TLS_HANDSHAKE_BODY_CAP) {
            memcpy(
                stream->handshake_body + stream->handshake_body_bytes,
                data + offset,
                consume);
            stream->handshake_body_bytes += (uint32_t)consume;
        }
        stream->handshake_remaining -= (uint32_t)consume;
        offset += consume;
        if (stream->handshake_remaining == 0u)
            complete_handshake(stream, callback, user);
    }
}

enum fk_protocol_completeness fk_tls_stream_feed(
        struct fk_tls_stream *stream,
        const uint8_t *data,
        size_t length,
        fk_tls_hello_callback callback,
        void *user) {
    if (stream == NULL || (data == NULL && length != 0u))
        return FK_COMPLETENESS_MALFORMED;
    if (stream->completeness == FK_COMPLETENESS_MALFORMED ||
        stream->completeness == FK_COMPLETENESS_CAP_EXCEEDED)
        return stream->completeness;
    if (length == 0u)
        return stream->completeness;
    stream->bytes_seen += length;
    size_t offset = 0u;
    while (offset < length) {
        if (stream->record_remaining == 0u &&
            stream->record_header_bytes < 2u) {
            size_t needed = 2u - stream->record_header_bytes;
            size_t available = length - offset;
            size_t copy = needed < available ? needed : available;
            memcpy(
                stream->record_header + stream->record_header_bytes,
                data + offset,
                copy);
            stream->record_header_bytes += (uint8_t)copy;
            offset += copy;
            if (stream->record_header_bytes < 2u)
                continue;
        }

        if (stream->record_remaining == 0u &&
            stream->record_header_bytes == 2u &&
            (stream->record_header[0] & 0x80u) != 0u) {
            uint16_t record_length =
                (uint16_t)(
                    ((uint16_t)(stream->record_header[0] & 0x7fu) << 8) |
                    stream->record_header[1]);
            if (record_length < 9u ||
                stream->handshake_header_bytes != 0u ||
                stream->handshake_remaining != 0u) {
                stream->malformed_records++;
                stream->completeness = FK_COMPLETENESS_MALFORMED;
                return stream->completeness;
            }
            if (record_length > FK_TLS_HANDSHAKE_BODY_CAP) {
                stream->cap_exceeded_messages++;
                stream->completeness = FK_COMPLETENESS_CAP_EXCEEDED;
                return stream->completeness;
            }
            stream->record_is_sslv2_client_hello = true;
            stream->record_content_type = 0u;
            stream->record_remaining = record_length;
            stream->handshake_body_bytes = 0u;
            stream->records_seen++;
        } else if (stream->record_remaining == 0u) {
            if (stream->record_header_bytes < 5u) {
                size_t needed = 5u - stream->record_header_bytes;
                size_t available = length - offset;
                size_t copy = needed < available ? needed : available;
                memcpy(
                    stream->record_header + stream->record_header_bytes,
                    data + offset,
                    copy);
                stream->record_header_bytes += (uint8_t)copy;
                offset += copy;
                if (stream->record_header_bytes < 5u)
                    continue;
            }
            uint8_t type = stream->record_header[0];
            uint16_t version = read_be16(stream->record_header + 1u);
            uint16_t record_length =
                read_be16(stream->record_header + 3u);
            if (type < FK_TLS_CONTENT_CHANGE_CIPHER_SPEC ||
                type > FK_TLS_CONTENT_HEARTBEAT ||
                (version & 0xff00u) != 0x0300u) {
                stream->malformed_records++;
                stream->completeness = FK_COMPLETENESS_MALFORMED;
                return stream->completeness;
            }
            if (record_length > FK_TLS_RECORD_PLAINTEXT_MAX) {
                stream->cap_exceeded_messages++;
                stream->completeness = FK_COMPLETENESS_CAP_EXCEEDED;
                return stream->completeness;
            }
            stream->record_is_sslv2_client_hello = false;
            stream->record_content_type = type;
            stream->record_remaining = record_length;
            stream->records_seen++;
            if (stream->record_remaining == 0u) {
                stream->record_header_bytes = 0u;
                stream->record_is_sslv2_client_hello = false;
                continue;
            }
        }

        size_t available = length - offset;
        size_t consume =
            stream->record_remaining < available
                ? stream->record_remaining
                : available;
        if (stream->record_is_sslv2_client_hello) {
            memcpy(
                stream->handshake_body + stream->handshake_body_bytes,
                data + offset,
                consume);
            stream->handshake_body_bytes += (uint32_t)consume;
        } else if (
            stream->record_content_type == FK_TLS_CONTENT_HANDSHAKE) {
            feed_handshake_bytes(
                stream,
                data + offset,
                consume,
                callback,
                user);
        }
        offset += consume;
        stream->record_remaining -= (uint32_t)consume;
        if (stream->record_remaining == 0u) {
            if (stream->record_is_sslv2_client_hello)
                complete_sslv2_client_hello(stream, callback, user);
            stream->record_header_bytes = 0u;
            stream->record_is_sslv2_client_hello = false;
        }
    }
    if (stream->completeness == FK_COMPLETENESS_NONE)
        stream->completeness = FK_COMPLETENESS_PARTIAL;
    return stream->completeness;
}

void fk_tcp_tls_flow_init(struct fk_tcp_tls_flow *flow) {
    if (flow == NULL)
        return;
    memset(flow, 0, sizeof(*flow));
    fk_tls_stream_init(&flow->direction[0].tls);
    fk_tls_stream_init(&flow->direction[1].tls);
    flow->completeness = FK_COMPLETENESS_NONE;
}

static bool sequence_before(uint32_t left, uint32_t right) {
    return (int32_t)(left - right) < 0;
}

static bool sequence_after(uint32_t left, uint32_t right) {
    return (int32_t)(left - right) > 0;
}

static enum fk_protocol_completeness feed_contiguous(
        struct fk_tcp_tls_direction *direction,
        const uint8_t *data,
        size_t length,
        fk_tls_hello_callback callback,
        void *user) {
    enum fk_protocol_completeness result = fk_tls_stream_feed(
        &direction->tls,
        data,
        length,
        callback,
        user);
    direction->next_sequence += (uint32_t)length;
    return result;
}

static enum fk_protocol_completeness drain_out_of_order(
        struct fk_tcp_tls_direction *direction,
        fk_tls_hello_callback callback,
        void *user) {
    enum fk_protocol_completeness result = direction->tls.completeness;
    for (;;) {
        int selected = -1;
        uint32_t selected_sequence = 0u;
        for (unsigned index = 0u; index < FK_TCP_OOO_SLOTS; ++index) {
            struct fk_tcp_ooo_slot *slot = &direction->ooo[index];
            if (!slot->used || sequence_after(
                    slot->sequence,
                    direction->next_sequence))
                continue;
            if (selected < 0 ||
                sequence_before(slot->sequence, selected_sequence)) {
                selected = (int)index;
                selected_sequence = slot->sequence;
            }
        }
        if (selected < 0)
            break;
        struct fk_tcp_ooo_slot *slot = &direction->ooo[selected];
        uint32_t overlap =
            direction->next_sequence - slot->sequence;
        if (overlap < slot->length) {
            result = feed_contiguous(
                direction,
                slot->data + overlap,
                (size_t)slot->length - overlap,
                callback,
                user);
        } else {
            direction->retransmitted_bytes += slot->length;
        }
        slot->used = false;
    }
    return result;
}

static bool store_out_of_order(
        struct fk_tcp_tls_direction *direction,
        uint32_t sequence,
        const uint8_t *payload,
        size_t payload_length) {
    if (payload_length > FK_TCP_OOO_PAYLOAD_CAP)
        return false;
    for (unsigned index = 0u; index < FK_TCP_OOO_SLOTS; ++index) {
        struct fk_tcp_ooo_slot *slot = &direction->ooo[index];
        if (slot->used && slot->sequence == sequence &&
            slot->length == payload_length) {
            if (memcmp(slot->data, payload, payload_length) != 0)
                return false;
            return true;
        }
    }
    for (unsigned index = 0u; index < FK_TCP_OOO_SLOTS; ++index) {
        struct fk_tcp_ooo_slot *slot = &direction->ooo[index];
        if (!slot->used) {
            slot->used = true;
            slot->sequence = sequence;
            slot->length = (uint16_t)payload_length;
            memcpy(slot->data, payload, payload_length);
            direction->out_of_order_segments++;
            return true;
        }
    }
    return false;
}

enum fk_protocol_completeness fk_tcp_tls_flow_feed(
        struct fk_tcp_tls_flow *flow,
        uint8_t direction_index,
        uint32_t tcp_sequence,
        uint8_t tcp_flags,
        const uint8_t *payload,
        size_t payload_length,
        fk_tls_hello_callback callback,
        void *user) {
    if (flow == NULL || direction_index > 1u ||
        (payload == NULL && payload_length != 0u) ||
        payload_length > UINT32_MAX) {
        return FK_COMPLETENESS_MALFORMED;
    }
    struct fk_tcp_tls_direction *direction =
        &flow->direction[direction_index];
    if (direction->desynchronized)
        return FK_COMPLETENESS_PARTIAL;
    uint32_t data_sequence =
        tcp_sequence + ((tcp_flags & FK_TCP_FLAG_SYN) != 0u ? 1u : 0u);

    if (!direction->sequence_initialized) {
        if ((tcp_flags & FK_TCP_FLAG_SYN) != 0u || payload_length > 0u) {
            direction->sequence_initialized = true;
            direction->next_sequence = data_sequence;
        }
    }

    enum fk_protocol_completeness result = direction->tls.completeness;
    if (payload_length > 0u && direction->sequence_initialized) {
        if (sequence_after(data_sequence, direction->next_sequence)) {
            if (!store_out_of_order(
                    direction,
                    data_sequence,
                    payload,
                    payload_length)) {
                direction->desynchronized = true;
                direction->gap_events++;
                flow->completeness = FK_COMPLETENESS_PARTIAL;
                return flow->completeness;
            }
            result = FK_COMPLETENESS_PARTIAL;
        } else {
            uint32_t overlap =
                direction->next_sequence - data_sequence;
            if (overlap >= payload_length) {
                direction->retransmitted_bytes += payload_length;
            } else {
                if (overlap > 0u)
                    direction->retransmitted_bytes += overlap;
                result = feed_contiguous(
                    direction,
                    payload + overlap,
                    payload_length - overlap,
                    callback,
                    user);
                result = drain_out_of_order(direction, callback, user);
            }
        }
    }

    if ((tcp_flags & (FK_TCP_FLAG_FIN | FK_TCP_FLAG_RST)) != 0u)
        direction->closed = true;
    if (direction->desynchronized)
        result = FK_COMPLETENESS_PARTIAL;
    flow->completeness = result;
    return result;
}

const char *fk_native_parse_code_name(enum fk_native_parse_code code) {
    switch (code) {
    case FK_PARSE_OK:
        return "OK";
    case FK_PARSE_TRUNCATED:
        return "TRUNCATED";
    case FK_PARSE_MALFORMED:
        return "MALFORMED";
    case FK_PARSE_UNSUPPORTED_L2:
        return "UNSUPPORTED_L2";
    case FK_PARSE_UNSUPPORTED_L3:
        return "UNSUPPORTED_L3";
    case FK_PARSE_UNSUPPORTED_L4:
        return "UNSUPPORTED_L4";
    case FK_PARSE_FRAGMENTED:
        return "FRAGMENTED";
    case FK_PARSE_CAP_EXCEEDED:
        return "CAP_EXCEEDED";
    }
    return "UNKNOWN";
}

const char *fk_protocol_completeness_name(
        enum fk_protocol_completeness completeness) {
    switch (completeness) {
    case FK_COMPLETENESS_NONE:
        return "NONE";
    case FK_COMPLETENESS_COMPLETE:
        return "COMPLETE";
    case FK_COMPLETENESS_PARTIAL:
        return "PARTIAL";
    case FK_COMPLETENESS_MALFORMED:
        return "MALFORMED";
    case FK_COMPLETENESS_CAP_EXCEEDED:
        return "CAP_EXCEEDED";
    }
    return "UNKNOWN";
}
