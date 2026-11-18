#ifndef FLOWKEEP_FK_QUIC_LOGICAL_ID_H
#define FLOWKEEP_FK_QUIC_LOGICAL_ID_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Stable logical-connection identity ABI shared by the CID directory and
 * the direct owner-binding table.  Zero is never a valid identity.  Keeping
 * the slot encoded as slot+1 reserves a zero low word for invalid/unbound
 * values; generation zero is likewise forbidden.
 */
#define FK_QUIC_LOGICAL_ID_ABI_VERSION 1u

static inline bool fk_quic_logical_id_encode(
        uint32_t connection_slot,
        uint32_t generation,
        uint64_t *logical_connection_id) {
    if (logical_connection_id == NULL || generation == 0u ||
        connection_slot == UINT32_MAX)
        return false;
    *logical_connection_id =
        ((uint64_t)generation << 32u) |
        ((uint64_t)connection_slot + UINT64_C(1));
    return true;
}

static inline bool fk_quic_logical_id_decode(
        uint64_t logical_connection_id,
        uint32_t maximum_connection_slots,
        uint32_t *connection_slot,
        uint32_t *generation) {
    if (connection_slot == NULL || generation == NULL ||
        maximum_connection_slots == 0u)
        return false;
    const uint32_t encoded_slot = (uint32_t)logical_connection_id;
    const uint32_t decoded_generation =
        (uint32_t)(logical_connection_id >> 32u);
    if (encoded_slot == 0u || decoded_generation == 0u)
        return false;
    const uint32_t decoded_slot = encoded_slot - 1u;
    if (decoded_slot >= maximum_connection_slots)
        return false;
    *connection_slot = decoded_slot;
    *generation = decoded_generation;
    return true;
}

#ifdef __cplusplus
}
#endif

#endif
