#ifndef FK_HOT_TAIL_SUMMARY_H
#define FK_HOT_TAIL_SUMMARY_H
#include "fk_compact_flow_table.h"
#include <algorithm>
#include <array>
#include <cstdint>

namespace fk_hot_tail_summary {
struct PoolProbeGate {
    uint64_t unavailable = 0u;
    void Reset() { unavailable = 0u; }
    bool ShouldTry(uint16_t owner) const {
        return owner < 64u && !(unavailable & (UINT64_C(1) << owner));
    }
    void Failed(uint16_t owner) {
        if (owner < 64u) unavailable |= UINT64_C(1) << owner;
    }
};
inline bool SameHandle(fk_compact_flow_handle a, fk_compact_flow_handle b) {
    return a.index == b.index && a.generation == b.generation;
}
inline bool PrefixMatches(uint16_t cursor, uint16_t end,
                          fk_compact_flow_handle previous, fk_compact_flow_handle live) {
    return cursor == 0u || (cursor == end && SameHandle(previous, live));
}
// Record a contiguous prefix scheduled on this owner. Buffered updates MUST
// be flushed successfully before Range() can rely on this receipt. A gap or
// generation change cannot retroactively prove an earlier prefix.
inline void RecordPrefix(uint16_t &end, fk_compact_flow_handle &previous,
                         uint16_t index, fk_compact_flow_handle live) {
    if (index == 0u) {
        previous = live;
        end = 1u;
    } else if (end == index && SameHandle(previous, live)) {
        end = static_cast<uint16_t>(index + 1u);
    }
}
// At most 64 frames of at most 65535 bytes: both sums fit uint32_t.
struct Prefix {
    uint32_t wire_bytes = 0, envelope_bytes = 0;
    uint16_t direction0 = 0, truncated = 0, maximum_wire_size = 0;
    uint8_t ack_rst = 0, fin_mask = 0;
};
static_assert(sizeof(Prefix) == 16u, "bounded pump-side summary");
inline Prefix Append(Prefix p, const fk_compact_final_tail_observation &o,
                     uint32_t envelope) {
    p.wire_bytes += o.wire_size;
    p.envelope_bytes += envelope;
    p.direction0 += o.canonical_direction == 0u;
    p.truncated += o.payload_truncated != 0u;
    p.maximum_wire_size = std::max(p.maximum_wire_size, static_cast<uint16_t>(o.wire_size));
    p.ack_rst |= static_cast<uint8_t>(o.tcp_flags & (FK_TCP_FLAG_ACK | FK_TCP_FLAG_RST));
    if (o.tcp_flags & FK_TCP_FLAG_FIN)
        p.fin_mask |= static_cast<uint8_t>(1u << o.canonical_direction);
    return p;
}
// The prefix before 'begin' MUST have been applied to the same live handle.
// Counts subtract; max/OR include only values already present in that handle.
inline fk_compact_final_tail_delta Range(const Prefix &before, const Prefix &end,
        uint32_t count, uint64_t first_ns, uint64_t last_ns, uint8_t protocol) {
    fk_compact_final_tail_delta d{};
    d.first_timestamp_ns = first_ns; d.last_timestamp_ns = last_ns;
    d.wire_bytes = end.wire_bytes - before.wire_bytes;
    d.payload_truncated_frames = end.truncated - before.truncated;
    d.packet_count = count;
    d.canonical_direction_packets[0] = end.direction0 - before.direction0;
    d.canonical_direction_packets[1] = count - d.canonical_direction_packets[0];
    d.maximum_wire_size = end.maximum_wire_size;
    d.l4_protocol = protocol;
    d.tcp_ack_observed = (end.ack_rst & FK_TCP_FLAG_ACK) != 0u;
    d.tcp_rst_observed = (end.ack_rst & FK_TCP_FLAG_RST) != 0u;
    d.tcp_fin_canonical_mask = end.fin_mask;
    return d;
}
inline void Merge(fk_compact_final_tail_delta &a, const fk_compact_final_tail_delta &b) {
    if (!a.packet_count) { a = b; return; }
    a.first_timestamp_ns = std::min(a.first_timestamp_ns, b.first_timestamp_ns);
    a.last_timestamp_ns = std::max(a.last_timestamp_ns, b.last_timestamp_ns);
    a.packet_count += b.packet_count; a.wire_bytes += b.wire_bytes;
    a.payload_truncated_frames += b.payload_truncated_frames;
    for (unsigned i=0; i<2; ++i) a.canonical_direction_packets[i] += b.canonical_direction_packets[i];
    a.maximum_wire_size = std::max(a.maximum_wire_size, b.maximum_wire_size);
    a.tcp_ack_observed |= b.tcp_ack_observed;
    a.tcp_rst_observed |= b.tcp_rst_observed;
    a.tcp_fin_canonical_mask |= b.tcp_fin_canonical_mask;
}
struct HeadBoundary {
    bool present = false, same_generation = false;
    uint64_t first = UINT64_MAX, following = UINT64_MAX;
};
constexpr uint16_t kMaximumChain = 4u;
using CompletionMask128 = std::array<uint64_t, 2u>;
inline bool AnyCompletion(const CompletionMask128 &mask) {
    return mask[0] != 0u || mask[1] != 0u;
}
inline bool MarkCompletionRange(CompletionMask128 &mask,
                                uint16_t begin, uint16_t end) {
    if (begin > end || end > 128u)
        return false;
    while (begin < end) {
        const uint16_t word = begin / 64u;
        const uint16_t offset = begin % 64u;
        const uint16_t count = std::min<uint16_t>(
            static_cast<uint16_t>(64u - offset),
            static_cast<uint16_t>(end - begin));
        const uint64_t bits = count == 64u
            ? UINT64_MAX
            : ((UINT64_C(1) << count) - 1u) << offset;
        mask[word] |= bits;
        begin = static_cast<uint16_t>(begin + count);
    }
    return true;
}
// At cache exhaustion, a nonempty ring may hide an ordinary packet below
// ready. Only the included descriptor's endpoint is then a safe bound.
inline uint64_t ChainEndBoundary(uint64_t ready, uint64_t last_sequence,
                                 bool queue_empty) {
    return queue_empty ? ready : std::min(ready, last_sequence + 1u);
}
// Look BEHIND every candidate head: its next queue object may contain a
// different flow inside another stream's descriptor interval.
inline uint64_t Boundary(uint64_t ready, const HeadBoundary *heads, uint16_t count) {
    uint64_t limit = ready;
    for (uint16_t i=0; i<count; ++i)
        if (heads[i].present)
            limit = std::min(limit, heads[i].same_generation
                ? heads[i].following : heads[i].first);
    return limit;
}
} // namespace fk_hot_tail_summary
#endif
