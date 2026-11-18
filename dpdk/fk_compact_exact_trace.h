#ifndef FLOWKEEP_FK_COMPACT_EXACT_TRACE_H
#define FLOWKEEP_FK_COMPACT_EXACT_TRACE_H

#include <stdbool.h>
#include <stdint.h>

#include "fk_checkpoint_reorder.h"
#include "fk_trace_message_barrier.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Stable sequence contract shared by the NIC-free tests and compact RX.
 * Each trace packet owns two ordered association-message ordinals:
 * FLOW_OPEN first, then DETECTION_CHECKPOINT.  An ordinal may be absent, but
 * no later packet can be released until the packet barrier proves the exact
 * set of messages published for every earlier packet.
 */
#define FK_COMPACT_EXACT_TRACE_MAX_PACKETS (UINT64_C(1) << 40)

static inline bool fk_compact_exact_trace_message_fields(
        uint64_t packet_sequence,
        uint8_t message_kind,
        uint64_t *input_sequence,
        uint8_t *message_mask) {
    if (input_sequence == NULL || message_mask == NULL ||
        packet_sequence >= FK_COMPACT_EXACT_TRACE_MAX_PACKETS)
        return false;
    uint64_t ordinal = 0u;
    if (message_kind == FK_CHECKPOINT_MESSAGE_FLOW_OPEN) {
        ordinal = 0u;
        *message_mask = FK_TRACE_MESSAGE_FLOW_OPEN;
    } else if (message_kind ==
            FK_CHECKPOINT_MESSAGE_DETECTION_CHECKPOINT) {
        ordinal = 1u;
        *message_mask = FK_TRACE_MESSAGE_CHECKPOINT;
    } else {
        return false;
    }
    *input_sequence = packet_sequence * UINT64_C(2) + ordinal;
    return true;
}

static inline bool fk_compact_exact_trace_decode_message(
        uint64_t input_sequence,
        uint8_t message_kind,
        uint64_t *packet_sequence,
        uint8_t *message_mask) {
    if (packet_sequence == NULL || message_mask == NULL)
        return false;
    const uint64_t packet = input_sequence / UINT64_C(2);
    uint64_t canonical = 0u;
    if (!fk_compact_exact_trace_message_fields(
            packet, message_kind, &canonical, message_mask) ||
        canonical != input_sequence)
        return false;
    *packet_sequence = packet;
    return true;
}

static inline bool fk_compact_exact_trace_ready_boundary(
        uint64_t ready_prefix_packets,
        uint64_t *input_sequence_exclusive) {
    if (input_sequence_exclusive == NULL ||
        ready_prefix_packets > FK_COMPACT_EXACT_TRACE_MAX_PACKETS)
        return false;
    *input_sequence_exclusive = ready_prefix_packets * UINT64_C(2);
    return true;
}

#ifdef __cplusplus
}
#endif

#endif
