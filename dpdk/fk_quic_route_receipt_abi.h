#ifndef FLOWKEEP_FK_QUIC_ROUTE_RECEIPT_ABI_H
#define FLOWKEEP_FK_QUIC_ROUTE_RECEIPT_ABI_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define FK_QUIC_ROUTE_RECEIPT_ABI_VERSION 1u
#define FK_QUIC_ROUTE_RECEIPT_TAG_BYTES 16u
#define FK_QUIC_ROUTE_RECEIPT_BYTES 24u

/* What exact wire object justified this packet's logical association. */
enum fk_quic_route_evidence_kind {
    FK_QUIC_ROUTE_EVIDENCE_AUTHENTICATED_INITIAL_DCID = 1,
    FK_QUIC_ROUTE_EVIDENCE_EXACT_LONG_HEADER_DCID = 2,
    FK_QUIC_ROUTE_EVIDENCE_EXACT_SHORT_HEADER_DCID = 3,
};

/* Placement-path fact committed by the identity stage for this packet. */
enum fk_quic_route_placement_context {
    FK_QUIC_ROUTE_PLACEMENT_AUTHENTICATED_REGISTRATION = 1,
    FK_QUIC_ROUTE_PLACEMENT_EXACT_CID_RESOLUTION = 2,
};

/* CID-directory lifecycle fact used to authorize the immutable owner. */
enum fk_quic_route_fixed_owner_context {
    FK_QUIC_ROUTE_FIXED_OWNER_CREATED = 1,
    FK_QUIC_ROUTE_FIXED_OWNER_ACTIVE = 2,
    FK_QUIC_ROUTE_FIXED_OWNER_RETIRED_PENDING_OWNER_ACK = 3,
};

/*
 * Compact transport ABI.  The tag commits the run epoch, the complete owner
 * packet descriptor (except this receipt), the full-width logical id, fixed
 * owner and direction, canonical UDP key, evidence/context fields, exact CID
 * length and exact wire CID bytes.  Those values are deliberately not copied
 * into every queue cell: the verifier reconstructs them from the packet and
 * its wire view.
 *
 * Ordinary FLOW_KEY packets must contain the all-zero 24-byte value.  A
 * QUIC_LOGICAL packet must contain a structurally valid value; structural
 * validity alone is not authentication and owner code must verify the tag.
 */
struct fk_quic_route_receipt {
    uint32_t abi_version;
    uint8_t evidence_kind;
    uint8_t placement_context;
    uint8_t fixed_owner_context;
    uint8_t cid_length;
    uint8_t tag[FK_QUIC_ROUTE_RECEIPT_TAG_BYTES];
};

static inline bool fk_quic_route_receipt_is_zero(
        const struct fk_quic_route_receipt *receipt) {
    if (receipt == NULL)
        return false;
    const uint8_t *bytes = (const uint8_t *)receipt;
    uint8_t combined = 0u;
    for (size_t index = 0u; index < sizeof(*receipt); ++index)
        combined = (uint8_t)(combined | bytes[index]);
    return combined == 0u;
}

static inline bool fk_quic_route_receipt_shape_valid(
        const struct fk_quic_route_receipt *receipt) {
    if (receipt == NULL ||
        receipt->abi_version != FK_QUIC_ROUTE_RECEIPT_ABI_VERSION ||
        receipt->cid_length == 0u || receipt->cid_length > 20u)
        return false;
    const bool evidence_valid =
        receipt->evidence_kind ==
            FK_QUIC_ROUTE_EVIDENCE_AUTHENTICATED_INITIAL_DCID ||
        receipt->evidence_kind ==
            FK_QUIC_ROUTE_EVIDENCE_EXACT_LONG_HEADER_DCID ||
        receipt->evidence_kind ==
            FK_QUIC_ROUTE_EVIDENCE_EXACT_SHORT_HEADER_DCID;
    const bool placement_valid =
        receipt->placement_context ==
            FK_QUIC_ROUTE_PLACEMENT_AUTHENTICATED_REGISTRATION ||
        receipt->placement_context ==
            FK_QUIC_ROUTE_PLACEMENT_EXACT_CID_RESOLUTION;
    const bool fixed_owner_valid =
        receipt->fixed_owner_context ==
            FK_QUIC_ROUTE_FIXED_OWNER_CREATED ||
        receipt->fixed_owner_context ==
            FK_QUIC_ROUTE_FIXED_OWNER_ACTIVE ||
        receipt->fixed_owner_context ==
            FK_QUIC_ROUTE_FIXED_OWNER_RETIRED_PENDING_OWNER_ACK;
    if (!evidence_valid || !placement_valid || !fixed_owner_valid)
        return false;
    if (receipt->evidence_kind ==
            FK_QUIC_ROUTE_EVIDENCE_AUTHENTICATED_INITIAL_DCID) {
        return receipt->placement_context ==
                FK_QUIC_ROUTE_PLACEMENT_AUTHENTICATED_REGISTRATION &&
            (receipt->fixed_owner_context ==
                FK_QUIC_ROUTE_FIXED_OWNER_CREATED ||
             receipt->fixed_owner_context ==
                FK_QUIC_ROUTE_FIXED_OWNER_ACTIVE);
    }
    return receipt->placement_context ==
            FK_QUIC_ROUTE_PLACEMENT_EXACT_CID_RESOLUTION &&
        (receipt->fixed_owner_context ==
            FK_QUIC_ROUTE_FIXED_OWNER_ACTIVE ||
         receipt->fixed_owner_context ==
            FK_QUIC_ROUTE_FIXED_OWNER_RETIRED_PENDING_OWNER_ACK);
}

#ifdef __cplusplus
}
#endif

#endif
