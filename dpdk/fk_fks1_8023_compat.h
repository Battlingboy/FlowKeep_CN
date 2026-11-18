#ifndef FK_FKS1_8023_COMPAT_H
#define FK_FKS1_8023_COMPAT_H

#include <stdbool.h>
#include <stdint.h>

/* Preserve IEEE 802.3 length frames while the 32-byte FKS1 trailer is on the
 * wire.  The marker is restored to the original length before CRC checking
 * and parsing.  This dataset-bound encoding requires cap == wire == len+14. */
static inline bool fk_fks1_is_8023_marker(
        const uint8_t *frame, uint32_t captured_length) {
    return frame != 0 && captured_length >= 14u &&
        frame[12] == 0x88u && frame[13] == 0xb5u;
}

static inline bool fk_fks1_mark_outer_8023(
        uint8_t *frame, uint32_t captured_length) {
    if (frame == 0)
        return false;
    if (captured_length < 14u)
        return true;
    const uint16_t field = (uint16_t)(
        ((uint16_t)frame[12] << 8u) | frame[13]);
    if (field == 0x88b5u)
        return false;
    if (field >= 0x0600u)
        return true;
    if (field > 1500u || captured_length != (uint32_t)field + 14u)
        return false;
    frame[12] = 0x88u;
    frame[13] = 0xb5u;
    return true;
}

static inline bool fk_fks1_restore_outer_8023(
        uint8_t *frame, uint32_t captured_length, uint32_t wire_length) {
    if (!fk_fks1_is_8023_marker(frame, captured_length))
        return frame != 0;
    if (captured_length != wire_length || captured_length - 14u > 1500u)
        return false;
    const uint16_t field = (uint16_t)(captured_length - 14u);
    frame[12] = (uint8_t)(field >> 8u);
    frame[13] = (uint8_t)field;
    return true;
}

#endif
