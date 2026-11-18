#ifndef FK_RX_OWNER_FASTPATH_H
#define FK_RX_OWNER_FASTPATH_H

#include "fk_native_parser.h"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstring>

namespace fk_rx_owner_fastpath {

/* The legacy owner parser sees at most this many frame bytes.  Keeping this
 * bound here lets the UDP checks reproduce its truncation decision exactly. */
constexpr uint32_t kSlowHeaderBytes = 512u;
constexpr uint32_t kCommonHeaderBytes = 96u;

enum class Result : uint8_t {
    kNeedSlowPath = 0u,
    kFlowKey = 1u,
    kNoFlowKey = 2u,
};

struct Observation {
    fk_flow_key flow_key{};
    uint32_t wire_size = 0u;
    uint32_t payload_size = 0u;
    uint32_t tcp_sequence = 0u;
    uint8_t canonical_direction = 0u;
    uint8_t l4_protocol = 0u;
    uint8_t tcp_flags = 0u;
    uint8_t payload_truncated = 0u;
    bool packet_metadata_valid = false;
    bool common_ipv4 = false;
    bool udp = false;
};

/* Value-only transport after the pump has validated the original frame.
 * The RX-only consumer can reuse the mbuf's unused TX-offload word and
 * packet_type word. The canonical addresses/ports use the existing stamp.
 * No extra mbuf bytes, packet allocation, or shared flow pointer is needed.
 * This is not an on-wire format and must never be accepted without the
 * pump's per-packet valid flag. */
static inline bool pack_verified_ipv4_metadata(
        const Observation &value, uint64_t &sizes_sequence, uint32_t &flags) {
    if (!value.packet_metadata_valid || !value.common_ipv4 ||
        value.flow_key.ip_version != 4u ||
        value.flow_key.protocol != value.l4_protocol ||
        (value.l4_protocol != 6u && value.l4_protocol != 17u) ||
        value.wire_size > UINT16_MAX || value.payload_size > value.wire_size ||
        value.canonical_direction > 1u || value.payload_truncated > 1u)
        return false;
    sizes_sequence = static_cast<uint64_t>(value.tcp_sequence) |
        (static_cast<uint64_t>(value.wire_size) << 32u) |
        (static_cast<uint64_t>(value.payload_size) << 48u);
    flags = 0xa5000000u | value.l4_protocol |
        (static_cast<uint32_t>(value.tcp_flags) << 8u) |
        (static_cast<uint32_t>(value.canonical_direction) << 16u) |
        (static_cast<uint32_t>(value.payload_truncated) << 17u);
    return true;
}

static inline bool unpack_verified_ipv4_metadata(
        const fk_flow_key &key, uint64_t sizes_sequence, uint32_t flags,
        Observation &value) {
    value = {};
    const uint8_t protocol = static_cast<uint8_t>(flags);
    const uint32_t wire_size = (sizes_sequence >> 32u) & 0xffffu;
    const uint32_t payload_size = sizes_sequence >> 48u;
    if ((flags & 0xfffc0000u) != 0xa5000000u ||
        key.ip_version != 4u || key.protocol != protocol ||
        (protocol != 6u && protocol != 17u) ||
        wire_size < (protocol == 6u ? 54u : 42u) ||
        payload_size > wire_size)
        return false;
    value.flow_key = key;
    value.wire_size = wire_size;
    value.payload_size = payload_size;
    value.tcp_sequence = static_cast<uint32_t>(sizes_sequence);
    value.l4_protocol = protocol;
    value.tcp_flags = static_cast<uint8_t>(flags >> 8u);
    value.canonical_direction = (flags >> 16u) & 1u;
    value.payload_truncated = (flags >> 17u) & 1u;
    value.packet_metadata_valid = true;
    value.common_ipv4 = true;
    value.udp = protocol == 17u;
    return true;
}

static inline uint16_t read_be16(const uint8_t *data) {
    return static_cast<uint16_t>(
        (static_cast<uint16_t>(data[0]) << 8u) |
        static_cast<uint16_t>(data[1]));
}

static inline uint32_t read_be32(const uint8_t *data) {
    return static_cast<uint32_t>(data[0]) << 24u |
        static_cast<uint32_t>(data[1]) << 16u |
        static_cast<uint32_t>(data[2]) << 8u |
        static_cast<uint32_t>(data[3]);
}

static inline void canonical_ipv4_flow_key(
        const uint8_t *source_address,
        uint16_t source_port,
        const uint8_t *destination_address,
        uint16_t destination_port,
        uint8_t protocol,
        fk_flow_key &key,
        uint8_t &direction) {
    std::memset(&key, 0, sizeof(key));
    key.ip_version = 4u;
    key.protocol = protocol;
    const int address_order =
        std::memcmp(source_address, destination_address, 4u);
    const bool source_first = address_order < 0 ||
        (address_order == 0 && source_port <= destination_port);
    const uint8_t *low_address =
        source_first ? source_address : destination_address;
    const uint8_t *high_address =
        source_first ? destination_address : source_address;
    std::memcpy(key.low_addr, low_address, 4u);
    std::memcpy(key.high_addr, high_address, 4u);
    key.low_port = source_first ? source_port : destination_port;
    key.high_port = source_first ? destination_port : source_port;
    direction = source_first ? 0u : 1u;
}

/*
 * Recognize the dominant untagged Ethernet + fixed-header IPv4 case, with a
 * bounded legal TCP header (including TCP options).  VLAN, IPv4 options,
 * IPv6, fragments, malformed or short data return kNeedSlowPath and are
 * handled by fk_native_parse_ethernet.
 * The UDP declared-length check uses the same 512-byte captured view as the
 * old path, so taking this branch cannot turn a legacy fallback into a flow.
 */
static inline Result classify_common_ipv4(
        const uint8_t *frame,
        size_t available_bytes,
        uint32_t frame_length,
        Observation &observation) {
    observation = Observation{};
    constexpr uint16_t kEtherTypeIpv4 = 0x0800u;
    constexpr uint16_t kEtherTypeArp = 0x0806u;
    constexpr uint8_t kTcp = 6u;
    constexpr uint8_t kUdp = 17u;
    constexpr size_t kEthernetBytes = 14u;
    constexpr size_t kIpv4Bytes = 20u;
    constexpr size_t kTcpMinimumBytes = 20u;
    constexpr size_t kUdpBytes = 8u;

    if (frame == nullptr || frame_length < kEthernetBytes ||
        available_bytes < kEthernetBytes) {
        return Result::kNeedSlowPath;
    }
    const uint16_t ether_type = read_be16(frame + 12u);
    if (ether_type == kEtherTypeArp)
        return Result::kNoFlowKey;
    if (ether_type != kEtherTypeIpv4 ||
        available_bytes < kEthernetBytes + kIpv4Bytes) {
        return Result::kNeedSlowPath;
    }
    const uint8_t *ipv4 = frame + kEthernetBytes;
    if (ipv4[0] != 0x45u)
        return Result::kNeedSlowPath;
    const uint16_t total_length = read_be16(ipv4 + 2u);
    if (total_length < kIpv4Bytes ||
        (read_be16(ipv4 + 6u) & 0x3fffu) != 0u) {
        return Result::kNeedSlowPath;
    }
    const uint8_t protocol = ipv4[9u];
    const size_t legacy_captured_bytes =
        std::min<size_t>(frame_length, kSlowHeaderBytes);
    if (legacy_captured_bytes < kEthernetBytes + kIpv4Bytes)
        return Result::kNeedSlowPath;
    const size_t legacy_ipv4_bytes = legacy_captured_bytes - kEthernetBytes;
    const size_t legacy_available_ipv4 =
        std::min<size_t>(total_length, legacy_ipv4_bytes);
    if (legacy_available_ipv4 < kIpv4Bytes)
        return Result::kNeedSlowPath;
    const size_t legacy_transport_bytes =
        legacy_available_ipv4 - kIpv4Bytes;
    const uint8_t *transport = ipv4 + kIpv4Bytes;

    size_t tcp_header_bytes = kTcpMinimumBytes;
    if (protocol == kTcp) {
        if (available_bytes <
                kEthernetBytes + kIpv4Bytes + kTcpMinimumBytes ||
            legacy_transport_bytes < kTcpMinimumBytes) {
            return Result::kNeedSlowPath;
        }
        const uint8_t tcp_words = transport[12u] >> 4u;
        if (tcp_words < 5u)
            return Result::kNeedSlowPath;
        tcp_header_bytes = static_cast<size_t>(tcp_words) * 4u;
        if (available_bytes <
                kEthernetBytes + kIpv4Bytes + tcp_header_bytes ||
            legacy_transport_bytes < tcp_header_bytes) {
            return Result::kNeedSlowPath;
        }
    } else if (protocol == kUdp) {
        if (available_bytes < kEthernetBytes + kIpv4Bytes + kUdpBytes ||
            legacy_transport_bytes < kUdpBytes) {
            return Result::kNeedSlowPath;
        }
        const uint16_t udp_length = read_be16(transport + 4u);
        if (udp_length < kUdpBytes || udp_length > legacy_transport_bytes)
            return Result::kNeedSlowPath;
    } else {
        return Result::kNeedSlowPath;
    }

    canonical_ipv4_flow_key(
        ipv4 + 12u,
        read_be16(transport),
        ipv4 + 16u,
        read_be16(transport + 2u),
        protocol,
        observation.flow_key,
        observation.canonical_direction);
    const size_t captured_ipv4_bytes =
        frame_length - kEthernetBytes;
    const size_t available_ipv4_bytes =
        std::min<size_t>(total_length, captured_ipv4_bytes);
    observation.wire_size = frame_length;
    observation.l4_protocol = protocol;
    observation.payload_truncated =
        total_length > captured_ipv4_bytes ? 1u : 0u;
    if (protocol == kTcp) {
        observation.payload_size = static_cast<uint32_t>(
            available_ipv4_bytes - kIpv4Bytes - tcp_header_bytes);
        observation.tcp_sequence = read_be32(transport + 4u);
        observation.tcp_flags = transport[13u];
    } else {
        observation.payload_size =
            static_cast<uint32_t>(read_be16(transport + 4u) - kUdpBytes);
    }
    observation.packet_metadata_valid = true;
    observation.common_ipv4 = true;
    observation.udp = protocol == kUdp;
    return Result::kFlowKey;
}

/*
 * Exact one-flow specialization for a pump-local cache.  It accepts only the
 * same common IPv4 envelope as classify_common_ipv4(), validates the complete
 * TCP/UDP header contract, and compares both tuple directions against a
 * previously canonicalized key.  A mismatch returns kNeedSlowPath so the
 * caller executes the ordinary classifier; no packet is classified solely
 * by its physical RSS queue.
 */
static inline Result classify_cached_common_ipv4(
        const uint8_t *frame,
        size_t captured_length,
        const fk_flow_key &expected,
        Observation &observation) {
    observation = Observation{};
    constexpr size_t kEthernetBytes = 14u;
    constexpr size_t kIpv4Bytes = 20u;
    constexpr size_t kTcpMinimumBytes = 20u;
    constexpr size_t kUdpBytes = 8u;
    if (frame == nullptr || expected.ip_version != 4u ||
        captured_length < kEthernetBytes + kIpv4Bytes ||
        read_be16(frame + 12u) != 0x0800u)
        return Result::kNeedSlowPath;
    const uint8_t *ipv4 = frame + kEthernetBytes;
    if (ipv4[0] != 0x45u ||
        (read_be16(ipv4 + 6u) & 0x3fffu) != 0u ||
        ipv4[9u] != expected.protocol)
        return Result::kNeedSlowPath;
    const uint16_t total_length = read_be16(ipv4 + 2u);
    if (total_length < kIpv4Bytes)
        return Result::kNeedSlowPath;
    const size_t legacy_captured_bytes =
        std::min<size_t>(captured_length, kSlowHeaderBytes);
    const size_t legacy_available_ipv4 = std::min<size_t>(
        total_length, legacy_captured_bytes - kEthernetBytes);
    if (legacy_available_ipv4 < kIpv4Bytes)
        return Result::kNeedSlowPath;
    const size_t legacy_transport_bytes =
        legacy_available_ipv4 - kIpv4Bytes;
    const uint8_t *transport = ipv4 + kIpv4Bytes;
    const size_t minimum_transport_bytes =
        expected.protocol == 6u ? kTcpMinimumBytes :
        (expected.protocol == 17u ? kUdpBytes : 0u);
    if (minimum_transport_bytes == 0u ||
        captured_length <
            kEthernetBytes + kIpv4Bytes + minimum_transport_bytes ||
        legacy_transport_bytes < minimum_transport_bytes)
        return Result::kNeedSlowPath;
    const uint16_t source_port = read_be16(transport);
    const uint16_t destination_port = read_be16(transport + 2u);
    const int address_order = std::memcmp(ipv4 + 12u, ipv4 + 16u, 4u);
    const bool source_first = address_order < 0 ||
        (address_order == 0 && source_port <= destination_port);
    const uint8_t *low_address = source_first ? ipv4 + 12u : ipv4 + 16u;
    const uint8_t *high_address = source_first ? ipv4 + 16u : ipv4 + 12u;
    if (std::memcmp(low_address, expected.low_addr, 4u) != 0 ||
        std::memcmp(high_address, expected.high_addr, 4u) != 0 ||
        (source_first ? source_port : destination_port) !=
            expected.low_port ||
        (source_first ? destination_port : source_port) !=
            expected.high_port)
        return Result::kNeedSlowPath;

    size_t transport_header_bytes = 0u;
    if (expected.protocol == 6u) {
        const uint8_t tcp_words = transport[12u] >> 4u;
        if (tcp_words < 5u)
            return Result::kNeedSlowPath;
        transport_header_bytes = static_cast<size_t>(tcp_words) * 4u;
        if (captured_length <
                kEthernetBytes + kIpv4Bytes + transport_header_bytes ||
            legacy_transport_bytes < transport_header_bytes)
            return Result::kNeedSlowPath;
    } else if (expected.protocol == 17u) {
        const uint16_t udp_length = read_be16(transport + 4u);
        if (udp_length < kUdpBytes || udp_length > legacy_transport_bytes)
            return Result::kNeedSlowPath;
        transport_header_bytes = kUdpBytes;
    } else {
        return Result::kNeedSlowPath;
    }

    observation.flow_key = expected;
    observation.canonical_direction = source_first ? 0u : 1u;
    observation.wire_size = static_cast<uint32_t>(captured_length);
    observation.l4_protocol = expected.protocol;
    const size_t captured_ipv4_bytes = captured_length - kEthernetBytes;
    const size_t available_ipv4_bytes =
        std::min<size_t>(total_length, captured_ipv4_bytes);
    observation.payload_truncated =
        total_length > captured_ipv4_bytes ? 1u : 0u;
    if (expected.protocol == 6u) {
        observation.payload_size = static_cast<uint32_t>(
            available_ipv4_bytes - kIpv4Bytes - transport_header_bytes);
        observation.tcp_sequence = read_be32(transport + 4u);
        observation.tcp_flags = transport[13u];
    } else {
        observation.payload_size = static_cast<uint32_t>(
            read_be16(transport + 4u) - kUdpBytes);
        observation.udp = true;
    }
    observation.packet_metadata_valid = true;
    observation.common_ipv4 = true;
    return Result::kFlowKey;
}

/*
 * Classify a complete captured frame for software-owner routing.  The common
 * fixed-header IPv4 path avoids the general parser.  Packets that need the
 * slow path are parsed with the complete capture, not the bounded 512-byte
 * prefix used by the historical RX code.  That distinction is required for
 * UDP: the canonical parser deliberately rejects a view that does not contain
 * the declared UDP length, and routing such a packet by its physical RSS
 * queue can fork one bidirectional five-tuple across state owners.
 */
static inline Result classify_complete_frame(
        const uint8_t *frame,
        size_t captured_length,
        uint32_t wire_length,
        Observation &observation) {
    observation = Observation{};
    const Result common = classify_common_ipv4(
        frame,
        std::min<size_t>(captured_length, kCommonHeaderBytes),
        static_cast<uint32_t>(captured_length),
        observation);
    if (common != Result::kNeedSlowPath)
        return common;

    fk_packet_view packet_view{};
    if (fk_native_parse_ethernet(
            frame,
            captured_length,
            wire_length,
            &packet_view) != FK_PARSE_OK) {
        return Result::kNoFlowKey;
    }
    uint8_t direction = 0u;
    if (fk_native_flow_key(
            &packet_view,
            &observation.flow_key,
            &direction) != FK_PARSE_OK) {
        observation = Observation{};
        return Result::kNoFlowKey;
    }
    observation.wire_size = packet_view.wire_size;
    observation.payload_size = packet_view.payload_size;
    observation.tcp_sequence = packet_view.tcp_sequence;
    observation.canonical_direction = direction;
    observation.l4_protocol = packet_view.l4_protocol;
    observation.tcp_flags = packet_view.tcp_flags;
    observation.payload_truncated =
        packet_view.payload_truncated ? 1u : 0u;
    observation.packet_metadata_valid = true;
    observation.udp = packet_view.l4_protocol == 17u;
    return Result::kFlowKey;
}

}  // namespace fk_rx_owner_fastpath

#endif
