#ifndef FLOWKEEP_FK_OWNER_TOPOLOGY_ATTESTATION_H
#define FLOWKEEP_FK_OWNER_TOPOLOGY_ATTESTATION_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "fk_owner_flow_bindings.h"
#include "fk_quic_cid_map.h"

#ifdef __cplusplus
extern "C" {
#endif

#define FK_OWNER_TOPOLOGY_ATTESTATION_ABI_VERSION 1u

/* Every explicit receipt field remains authoritative.  These flags are an
 * audit aid only: acceptance requires the complete mask to be zero. */
enum fk_owner_topology_attestation_failure_flag {
    FK_OWNER_TOPOLOGY_ATTESTATION_FAILURE_INVALID_ARGUMENT = 1u << 0u,
    FK_OWNER_TOPOLOGY_ATTESTATION_FAILURE_RECEIPT_ABI = 1u << 1u,
    FK_OWNER_TOPOLOGY_ATTESTATION_FAILURE_LOGICAL_ID_ABI = 1u << 2u,
    FK_OWNER_TOPOLOGY_ATTESTATION_FAILURE_LOGICAL_ID_BITS = 1u << 3u,
    FK_OWNER_TOPOLOGY_ATTESTATION_FAILURE_FULL_WIDTH = 1u << 4u,
    FK_OWNER_TOPOLOGY_ATTESTATION_FAILURE_GENERATION_BITS = 1u << 5u,
    FK_OWNER_TOPOLOGY_ATTESTATION_FAILURE_ENCODED_SLOT_BITS = 1u << 6u,
    FK_OWNER_TOPOLOGY_ATTESTATION_FAILURE_RETIRE_ACK = 1u << 7u,
    FK_OWNER_TOPOLOGY_ATTESTATION_FAILURE_FIXED_OWNER_COUNT = 1u << 8u,
    FK_OWNER_TOPOLOGY_ATTESTATION_FAILURE_CONNECTION_SLOTS = 1u << 9u,
    FK_OWNER_TOPOLOGY_ATTESTATION_FAILURE_RESERVED_FIELD = 1u << 10u,
    FK_OWNER_TOPOLOGY_ATTESTATION_FAILURE_RECEIPT_HASH_MISMATCH = 1u << 11u,
    FK_OWNER_TOPOLOGY_ATTESTATION_FAILURE_CID_CANONICAL_HASH = 1u << 12u,
    FK_OWNER_TOPOLOGY_ATTESTATION_FAILURE_BINDING_CANONICAL_HASH = 1u << 13u,
};

/* Value-only startup evidence retained by the production process.  It is
 * immutable after startup and safe to serialize in a terminal report. */
struct fk_owner_topology_attestation {
    uint32_t attestation_abi_version;
    uint8_t passed;
    uint8_t reserved0[3];
    uint32_t failure_flags;
    uint32_t reserved1;
    uint64_t canonical_config_hash;
    struct fk_quic_cid_map_topology_receipt cid_receipt;
    struct fk_owner_flow_bindings_topology_receipt binding_receipt;
};

/* Recomputes the canonical topology checksum independently from the two
 * producers and also compares every explicit field.  The checksum is never
 * treated as collision-resistant authority.  On rejection, attestation is
 * still populated with failure evidence but passed remains zero. */
bool fk_owner_topology_attest_receipts(
    const struct fk_quic_cid_map_topology_receipt *cid_receipt,
    const struct fk_owner_flow_bindings_topology_receipt *binding_receipt,
    struct fk_owner_topology_attestation *attestation,
    char *error,
    size_t error_capacity);

#ifdef __cplusplus
}
#endif

#endif
