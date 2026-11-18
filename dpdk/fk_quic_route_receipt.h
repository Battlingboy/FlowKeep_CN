#ifndef FLOWKEEP_FK_QUIC_ROUTE_RECEIPT_H
#define FLOWKEEP_FK_QUIC_ROUTE_RECEIPT_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "fk_owner_dispatch.h"
#include "fk_quic_initial_auth.h"

#ifdef __cplusplus
extern "C" {
#endif

#define FK_QUIC_ROUTE_RECEIPT_KEY_BYTES 16u
#define FK_QUIC_ROUTE_RECEIPT_MAX_OWNERS 64u

struct fk_quic_route_receipt_config {
    uint64_t run_epoch;
    uint16_t owner_count;
    uint8_t authentication_key_0[FK_QUIC_ROUTE_RECEIPT_KEY_BYTES];
    uint8_t authentication_key_1[FK_QUIC_ROUTE_RECEIPT_KEY_BYTES];
    uint8_t keys_precommitted;
    uint8_t reserved[5];
};

/*
 * Restricted bridge input.  It is intentionally packet-specific: callers
 * must supply both the complete descriptor that will enter owner dispatch and
 * a parsed view whose payload is the exact UDP datagram.  For an Initial, a
 * successful authenticator result for the first packet in that exact
 * datagram is mandatory.  Signed material binds the datagram length,
 * authenticated first-packet length, and trailing coalesced length.  For a
 * short header, resolved_short_dcid_length selects payload[1..length]; the
 * bridge copies those exact wire bytes and never accepts caller-provided CID
 * bytes.  A naked CID-directory resolution cannot be signed by this API.
 *
 * This is a route-association receipt, not a payload-integrity MAC.  It binds
 * the exact packet_handle and descriptor plus the wire fields that determine
 * routing.  A production composition must prove exclusive mbuf ownership and
 * reparse that same handle without an intervening writer; otherwise it must
 * additionally freeze or authenticate the whole captured byte range.
 */
struct fk_quic_route_receipt_bridge_request {
    const struct fk_owner_packet *packet;
    const struct fk_packet_view *packet_view;
    const struct fk_quic_initial_auth_result *authenticated_initial;
    enum fk_quic_route_evidence_kind evidence_kind;
    enum fk_quic_route_placement_context placement_context;
    enum fk_quic_route_fixed_owner_context fixed_owner_context;
    uint8_t resolved_short_dcid_length;
    uint8_t reserved[7];
};

enum fk_quic_route_receipt_result {
    FK_QUIC_ROUTE_RECEIPT_ACCEPTED = 0,
    FK_QUIC_ROUTE_RECEIPT_INVALID = 1,
    FK_QUIC_ROUTE_RECEIPT_TAG_MISMATCH = 2,
    FK_QUIC_ROUTE_RECEIPT_REPLAY_OR_REORDER = 3,
    FK_QUIC_ROUTE_RECEIPT_INTERNAL_INTEGRITY = 4,
};

struct fk_quic_route_receipt_stats {
    uint64_t issue_attempts;
    uint64_t issued;
    uint64_t issue_rejections;
    uint64_t verify_attempts;
    uint64_t verified;
    uint64_t invalid_rejections;
    uint64_t tag_mismatch_rejections;
    uint64_t replay_or_reorder_rejections;
    uint64_t internal_integrity_rejections;
    uint64_t reserved_bytes;
    uint64_t run_epoch;
    uint16_t owner_count;
    uint8_t keys_precommitted;
    /* False until a live parser -> CID transaction -> issuance path invokes
     * this bridge atomically.  Unit tests must not promote that capability. */
    uint8_t production_formal_issuance_capable;
    uint8_t reserved[4];
};

struct fk_quic_route_receipt_state;

void fk_quic_route_receipt_default_config_init(
    struct fk_quic_route_receipt_config *config);

bool fk_quic_route_receipt_config_valid(
    const struct fk_quic_route_receipt_config *config);

size_t fk_quic_route_receipt_storage_bytes(
    const struct fk_quic_route_receipt_config *config);

struct fk_quic_route_receipt_state *fk_quic_route_receipt_initialize(
    void *storage,
    size_t storage_bytes,
    const struct fk_quic_route_receipt_config *config);

void fk_quic_route_receipt_destroy(
    struct fk_quic_route_receipt_state *state);

/* Test/bridge-only issuance.  Output is zeroed on every rejection. */
enum fk_quic_route_receipt_result fk_quic_route_receipt_bridge_issue(
    struct fk_quic_route_receipt_state *state,
    const struct fk_quic_route_receipt_bridge_request *request,
    struct fk_quic_route_receipt *receipt);

/* Constant-time comparison applies to the complete 128-bit tag.  Shape,
 * wire parsing and anti-replay checks are necessarily data-dependent. */
enum fk_quic_route_receipt_result fk_quic_route_receipt_verify_and_consume(
    struct fk_quic_route_receipt_state *state,
    const struct fk_owner_packet *packet,
    const struct fk_packet_view *packet_view,
    const struct fk_quic_initial_auth_result *authenticated_initial);

bool fk_quic_route_receipt_get_stats(
    const struct fk_quic_route_receipt_state *state,
    struct fk_quic_route_receipt_stats *stats);

/* Pure fail-closed validator for persisted or externally aggregated stats. */
bool fk_quic_route_receipt_stats_accounting_conserved(
    const struct fk_quic_route_receipt_stats *stats);

bool fk_quic_route_receipt_production_formal_issuance_capable(
    const struct fk_quic_route_receipt_state *state);

#ifdef __cplusplus
}
#endif

#endif
