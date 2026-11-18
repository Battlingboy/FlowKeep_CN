#ifndef FLOWKEEP_FK_QUIC_CID_MAP_H
#define FLOWKEEP_FK_QUIC_CID_MAP_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "fk_native_parser.h"
#include "fk_quic_logical_id.h"

#ifdef __cplusplus
extern "C" {
#endif

#define FK_QUIC_CID_MAX_BYTES 20u

/*
 * Creation-capable admission is a separate ABI from the clear-header
 * inspector.  A trusted QUIC parser fills this value only after verifying a
 * v1/v2 Initial with header protection removal and AEAD authentication.  The
 * CID directory validates that the proof is canonically encoded and bound to
 * the exact clear CID envelope, but it does not perform AEAD itself.
 */
#define FK_QUIC_CID_INITIAL_ADMISSION_PROOF_ABI_VERSION 1u
#define FK_QUIC_CID_INITIAL_ADMISSION_PROOF_BYTES 60u
#define FK_QUIC_CID_INITIAL_AUTH_NONE 0u
#define FK_QUIC_CID_INITIAL_AUTH_AEAD_VERIFIED 1u

/* Stable, value-only receipt for wiring the CID directory to the direct
 * owner-binding directory.  The hash is a deterministic checksum over every
 * field that must agree; initialization must still compare the explicit
 * fields, so the checksum is never used as collision-resistant authority. */
#define FK_QUIC_CID_MAP_TOPOLOGY_RECEIPT_ABI_VERSION 1u
#define FK_QUIC_LOGICAL_ID_FULL_WIDTH_BITS 64u
#define FK_QUIC_LOGICAL_ID_GENERATION_BITS 32u
#define FK_QUIC_LOGICAL_ID_ENCODED_SLOT_BITS 32u

struct fk_quic_cid_map_topology_receipt {
    uint32_t receipt_abi_version;
    uint16_t logical_id_abi_version;
    uint8_t logical_id_bits;
    uint8_t logical_id_full_width;
    uint8_t logical_id_generation_bits;
    uint8_t logical_id_encoded_slot_bits;
    uint8_t retire_ack_required;
    uint8_t reserved0;
    uint16_t fixed_owner_count;
    uint16_t reserved1;
    uint32_t maximum_connection_slots;
    uint32_t reserved2;
    uint64_t topology_config_hash;
};

struct fk_quic_cid_initial_admission_proof {
    uint32_t abi_version;
    uint32_t authentication_method;
    uint32_t version;
    uint8_t fixed_bit;
    uint8_t long_packet_type_bits;
    uint8_t destination_cid_length;
    uint8_t source_cid_length;
    uint8_t destination_cid[FK_QUIC_CID_MAX_BYTES];
    uint8_t source_cid[FK_QUIC_CID_MAX_BYTES];
    uint8_t reserved[4];
};

/*
 * Every byte owned by this directory is allocated before packet processing.
 * Raw QUIC Initial payload retention is deliberately unsupported here: both
 * byte limits must be zero.  The bounded pending-handshake entries retain
 * identity metadata only.  A future QUIC CRYPTO reassembler must contribute
 * its own preallocated arena to the same controlled-state ceiling.
 */
struct fk_quic_cid_map_config {
    uint32_t maximum_connections;
    uint32_t maximum_cids;
    uint16_t maximum_cids_per_connection;
    uint16_t maximum_pending_handshakes;
    uint32_t expiration_scan_per_observation;
    uint64_t connection_ttl_ns;
    uint64_t cid_ttl_ns;
    uint64_t maximum_pending_initial_bytes;
    uint32_t maximum_pending_initial_bytes_per_connection;
    uint32_t maximum_hash_chain;
    uint8_t siphash_key[16];
    uint8_t siphash_key_precommitted;
    uint8_t reserved[3];
    /* Must match the owner-dispatch topology.  Admission is rejected before
     * allocation when one immutable fixed owner reaches its binding-table
     * capacity, even if global connection slots remain. */
    uint16_t fixed_owner_count;
    uint16_t maximum_connections_per_fixed_owner;
};

enum fk_quic_cid_result_code {
    FK_QUIC_CID_NOT_QUIC = 0,
    FK_QUIC_CID_RESOLVED = 1,
    FK_QUIC_CID_CREATED = 2,
    FK_QUIC_CID_UNRESOLVED = 3,
    FK_QUIC_CID_REJECTED = 4,
    FK_QUIC_CID_AMBIGUOUS = 5,
    FK_QUIC_CID_INVALID = 6,
};

enum fk_quic_cid_reject_reason {
    FK_QUIC_CID_REJECT_NONE = 0,
    FK_QUIC_CID_REJECT_INVALID_INPUT,
    FK_QUIC_CID_REJECT_TIME_REGRESSION,
    FK_QUIC_CID_REJECT_CONNECTION_CAPACITY,
    FK_QUIC_CID_REJECT_CID_CAPACITY,
    FK_QUIC_CID_REJECT_PER_CONNECTION_CID_CAPACITY,
    FK_QUIC_CID_REJECT_PENDING_HANDSHAKE_CAPACITY,
    FK_QUIC_CID_REJECT_COLLISION,
    FK_QUIC_CID_REJECT_UNSUPPORTED_HEADER,
    FK_QUIC_CID_REJECT_SHORT_HEADER_PREFIX_AMBIGUITY,
    FK_QUIC_CID_REJECT_HASH_CHAIN_CAPACITY,
    FK_QUIC_CID_REJECT_DIRECTION_CONFLICT,
    FK_QUIC_CID_REJECT_INTERNAL_INTEGRITY,
    FK_QUIC_CID_REJECT_FIXED_BIT_ZERO_UNNEGOTIATED,
    FK_QUIC_CID_REJECT_FIXED_OWNER_CAPACITY,
    FK_QUIC_CID_REJECT_INITIAL_AUTH_REQUIRED,
    FK_QUIC_CID_REJECT_INITIAL_PROOF_MISMATCH,
    FK_QUIC_CID_REJECT_NON_INITIAL_MUTATION,
    FK_QUIC_CID_REJECT_FIXED_BIT_ZERO,
};

struct fk_quic_cid_resolution {
    uint64_t logical_connection_id;
    uint64_t reserved_bytes;
    uint16_t fixed_owner;
    uint16_t ingress_owner;
    uint8_t visible_cid_count;
    uint8_t created;
    uint8_t cross_owner;
    uint8_t pending_handshake;
    uint8_t feature_direction;
    uint8_t feature_direction_known;
    /* Exact destination-CID length used for a successful association.  It is
     * zero for every non-success result.  This consumes existing padding;
     * reserved0 preserves the enum offsets and 40-byte value ABI. */
    uint8_t resolved_destination_cid_length;
    uint8_t reserved0;
    enum fk_quic_cid_result_code code;
    enum fk_quic_cid_reject_reason reason;
};

struct fk_quic_cid_map_stats {
    uint64_t observations;
    uint64_t resolved_observations;
    uint64_t unresolved_observations;
    uint64_t connections_created;
    uint64_t connections_expired;
    uint64_t cids_registered;
    uint64_t cids_expired;
    uint64_t duplicate_cids;
    uint64_t cid_collisions;
    uint64_t ambiguous_cid_hits;
    uint64_t short_header_attempts;
    uint64_t short_header_resolved;
    uint64_t short_header_unresolved;
    uint64_t short_header_ambiguous;
    uint64_t short_header_hash_probes;
    uint64_t peak_short_header_hash_probes;
    uint64_t short_header_same_connection_prefix_ambiguities;
    uint64_t short_header_cross_connection_prefix_ambiguities;
    uint64_t hash_chain_limit_rejects;
    uint64_t hash_chain_lookup_rejects;
    uint64_t hash_chain_registration_rejects;
    uint64_t hash_chain_internal_rejects;
    uint64_t hard_integrity_failures;
    uint64_t peak_hash_chain_traversed;
    uint64_t direction_conflicts;
    uint64_t same_cid_dual_role_rejects;
    uint64_t direction_unknown_resolutions;
    uint64_t connection_capacity_rejects;
    uint64_t cid_capacity_rejects;
    uint64_t per_connection_cid_capacity_rejects;
    uint64_t pending_handshake_capacity_rejects;
    uint64_t clock_regressions;
    uint64_t hard_budget_violations;
    uint32_t active_connections;
    uint32_t peak_active_connections;
    uint32_t active_cids;
    uint32_t peak_active_cids;
    uint32_t pending_handshakes;
    uint32_t peak_pending_handshakes;
    uint64_t reserved_bytes;
    uint64_t used_bytes;
    uint64_t peak_used_bytes;
    /* Append-only RFC 9287 counters; preserves every pre-existing offset. */
    uint64_t short_header_fixed_zero_candidates;
    uint64_t short_header_fixed_zero_resolved;
    uint64_t short_header_fixed_zero_unnegotiated_rejects;
    /* Append-only immutable-owner quota counters. */
    uint64_t fixed_owner_capacity_rejects;
    uint32_t peak_active_connections_per_fixed_owner;
    uint32_t reserved0;
    /* Append-only published-connection lifecycle accounting. */
    uint64_t connections_retired_pending_owner_ack;
    uint64_t connection_allocation_rollbacks;
    uint64_t rollback_cleanup_failures;
    uint64_t allocator_integrity_failures;
    uint64_t retirement_ordinal_exhaustions;
    uint64_t retirement_peek_calls;
    uint64_t retirement_peek_ready;
    uint64_t retirement_peek_empty;
    uint64_t retirement_peek_invalid;
    uint64_t retirement_ack_calls;
    uint64_t retirement_acks;
    uint64_t retirement_ack_empty;
    uint64_t retirement_ack_mismatches;
    uint64_t retirement_ack_invalid;
    uint64_t binding_established_mark_calls;
    uint64_t binding_established_marks;
    uint64_t binding_established_mark_idempotent;
    uint64_t binding_established_mark_rejects;
    uint64_t generation_exhaustions;
    uint32_t binding_credits_in_use;
    uint32_t peak_binding_credits_in_use;
    uint32_t retired_pending_owner_ack;
    uint32_t peak_retired_pending_owner_ack;
    uint32_t free_connection_slots;
    uint32_t quarantined_connection_slots;
    uint32_t peak_binding_credits_per_fixed_owner;
    uint32_t reserved1;
    uint64_t retirement_ack_cleanup_failures;
    /* Append-only retirement-publication transaction accounting. */
    uint64_t retirement_publication_peek_calls;
    uint64_t retirement_publication_peek_ready;
    uint64_t retirement_publication_peek_empty;
    uint64_t retirement_publication_peek_invalid;
    uint64_t retirement_publication_mark_calls;
    uint64_t retirement_publication_marks;
    uint64_t retirement_publication_mark_empty;
    uint64_t retirement_publication_mark_mismatches;
    uint64_t retirement_publication_mark_invalid;
    uint64_t retirement_publication_rollback_calls;
    uint64_t retirement_publication_rollbacks;
    uint64_t retirement_publication_rollback_mismatches;
    uint64_t retirement_publication_rollback_invalid;
    uint64_t retirement_ack_not_dispatched;
    /* Append-only exact logical-id route prevalidation diagnostics. */
    uint64_t route_prevalidation_calls;
    uint64_t route_prevalidation_active;
    uint64_t route_prevalidation_retired_pending_owner_ack;
    uint64_t route_prevalidation_owner_mismatches;
    uint64_t route_prevalidation_stale_generations;
    uint64_t route_prevalidation_not_found;
    uint64_t route_prevalidation_invalid;
    uint64_t route_prevalidation_internal_integrity;
};

/*
 * Value-only retirement token.  It never aliases placement storage.  The
 * logical id contains the exact slot and generation; retirement_ordinal makes
 * a delayed acknowledgement distinguishable even before generation reuse.
 * packet_sequence is meaningful only when packet_sequence_known is one.
 * retirement_timestamp_ns is meaningful only when
 * retirement_timestamp_known is one; formal distinguishes an ordered/expiry
 * semantic timestamp from the compatibility API's last-observed fallback.
 * binding_expected is a live delivery hint: it may change from zero to one
 * after a peek when the fixed owner establishes a binding for an earlier
 * packet.  It is deliberately excluded from acknowledgement identity.
 */
struct fk_quic_cid_retirement {
    uint64_t logical_connection_id;
    uint64_t retirement_ordinal;
    uint64_t packet_sequence;
    uint64_t retirement_timestamp_ns;
    uint16_t fixed_owner;
    uint8_t packet_sequence_known;
    uint8_t expired;
    uint8_t binding_expected;
    uint8_t retirement_timestamp_known;
    uint8_t retirement_timestamp_formal;
    uint8_t reserved[1];
};

/* Minimal immutable control-plane acknowledgement identity. */
struct fk_quic_cid_retirement_token {
    uint64_t logical_connection_id;
    uint64_t retirement_ordinal;
    uint16_t fixed_owner;
    uint16_t reserved0;
    uint32_t reserved1;
};

struct fk_quic_cid_fixed_owner_lifecycle {
    uint32_t active_connections;
    uint32_t binding_credits_in_use;
    uint32_t retired_pending_owner_ack;
};

#define FK_QUIC_CID_FINITE_EPOCH_DRAIN_RECEIPT_ABI_VERSION 1u

enum fk_quic_cid_finite_epoch_drain_reason {
    FK_QUIC_CID_FINITE_EPOCH_DRAIN_REASON_NONE = 0,
    FK_QUIC_CID_FINITE_EPOCH_DRAIN_IDLE_TIMEOUT_AFTER_EOF = 1,
};

/* Value-only proof that a quiescent finite input epoch advanced to its
 * preregistered idle-timeout boundary and retired every remaining live QUIC
 * connection.  It never authorizes a caller to end an epoch: the caller must
 * first stop/join packet producers and identity processing. */
struct fk_quic_cid_finite_epoch_drain_receipt_v1 {
    uint32_t abi_version;
    enum fk_quic_cid_finite_epoch_drain_reason reason;
    uint64_t terminal_semantic_timestamp_ns;
    uint32_t active_connections_before;
    uint32_t connections_drained;
    uint32_t active_connections_after;
    uint8_t complete;
    uint8_t reserved[3];
};

enum fk_quic_cid_retirement_peek_result {
    FK_QUIC_CID_RETIREMENT_PEEK_INVALID = 0,
    FK_QUIC_CID_RETIREMENT_PEEK_EMPTY = 1,
    FK_QUIC_CID_RETIREMENT_PEEK_READY = 2,
};

enum fk_quic_cid_retirement_ack_result {
    FK_QUIC_CID_RETIREMENT_ACK_INVALID = 0,
    FK_QUIC_CID_RETIREMENT_ACK_EMPTY = 1,
    FK_QUIC_CID_RETIREMENT_ACK_MISMATCH = 2,
    FK_QUIC_CID_RETIREMENT_ACKED = 3,
    FK_QUIC_CID_RETIREMENT_ACK_CLEANUP_FAILED = 4,
    FK_QUIC_CID_RETIREMENT_ACK_NOT_DISPATCHED = 5,
};

enum fk_quic_cid_route_prevalidation_result {
    FK_QUIC_CID_ROUTE_PREVALIDATION_INVALID = 0,
    FK_QUIC_CID_ROUTE_PREVALIDATION_ACTIVE = 1,
    FK_QUIC_CID_ROUTE_PREVALIDATION_RETIRED_PENDING_OWNER_ACK = 2,
    FK_QUIC_CID_ROUTE_PREVALIDATION_OWNER_MISMATCH = 3,
    FK_QUIC_CID_ROUTE_PREVALIDATION_STALE_GENERATION = 4,
    FK_QUIC_CID_ROUTE_PREVALIDATION_NOT_FOUND = 5,
    FK_QUIC_CID_ROUTE_PREVALIDATION_INTERNAL_INTEGRITY = 6,
};

/*
 * Immutable logical-route snapshot returned while holding the CID-directory
 * lock.  A RETIRED_PENDING route is usable only for DATA that was ordered no
 * later than this exact retirement cutoff.  ACTIVE snapshots deliberately
 * carry no cutoff.  The value record never aliases directory storage.
 */
struct fk_quic_cid_route_guard_v2 {
    uint64_t logical_connection_id;
    uint64_t retirement_packet_sequence;
    uint64_t retirement_timestamp_ns;
    uint16_t immutable_fixed_owner;
    uint8_t lifecycle;
    uint8_t packet_sequence_known;
    uint8_t retirement_timestamp_known;
    uint8_t retirement_timestamp_formal;
    uint8_t reserved[2];
};

enum fk_quic_cid_route_guard_lifecycle {
    FK_QUIC_CID_ROUTE_GUARD_NONE = 0,
    FK_QUIC_CID_ROUTE_GUARD_ACTIVE = 1,
    FK_QUIC_CID_ROUTE_GUARD_RETIRED_PENDING_OWNER_ACK = 2,
};

/*
 * Result for the producer-side publication transaction.  MARKED advances the
 * owner's first-undispatched cursor.  ROLLED_BACK moves it back by exactly one
 * token.  EMPTY is meaningful only for mark when no unpublished retirement
 * remains.  MISMATCH includes a stale generation, a non-current token, and a
 * rollback attempted in any order other than exact reverse mark order.
 */
enum fk_quic_cid_retirement_publication_result {
    FK_QUIC_CID_RETIREMENT_PUBLICATION_INVALID = 0,
    FK_QUIC_CID_RETIREMENT_PUBLICATION_EMPTY = 1,
    FK_QUIC_CID_RETIREMENT_PUBLICATION_MISMATCH = 2,
    FK_QUIC_CID_RETIREMENT_PUBLICATION_MARKED = 3,
    FK_QUIC_CID_RETIREMENT_PUBLICATION_ROLLED_BACK = 4,
};

struct fk_quic_cid_map;

typedef bool (*fk_quic_cid_config_hash_field_callback)(
    void *user,
    uint16_t field_id,
    const uint8_t *bytes,
    uint32_t byte_count);

/* Public only so the implementation can be checked against official vectors. */
uint64_t fk_quic_cid_map_siphash24(
    const uint8_t key[16],
    const uint8_t *data,
    size_t length);

/* Canonical CONFIG-V4 fields 80..82; used by the receiver and unit tests. */
bool fk_quic_cid_map_visit_config_hash_v4_fields(
    const struct fk_quic_cid_map_config *config,
    fk_quic_cid_config_hash_field_callback callback,
    void *callback_user);

/* Validation-selected Q2 sizing candidate; not a parser capability claim. */
void fk_quic_cid_map_q2_config_init(
    struct fk_quic_cid_map_config *config);

bool fk_quic_cid_map_config_valid(
    const struct fk_quic_cid_map_config *config);

/* Includes alignment padding. Returns zero for an invalid/overflowing plan. */
size_t fk_quic_cid_map_storage_bytes(
    const struct fk_quic_cid_map_config *config);

/* Placement initialization; never allocates from the process heap. */
struct fk_quic_cid_map *fk_quic_cid_map_init(
    void *storage,
    size_t storage_bytes,
    const struct fk_quic_cid_map_config *config,
    char *error,
    size_t error_capacity);

/* Caller must stop all users before destroying placement state. */
void fk_quic_cid_map_destroy(struct fk_quic_cid_map *map);

/* Immutable and allocation-free; valid during normal packet processing. */
bool fk_quic_cid_map_get_topology_receipt(
    const struct fk_quic_cid_map *map,
    struct fk_quic_cid_map_topology_receipt *receipt);

/*
 * Resolve a clear, self-describing long header only through its already-known
 * destination CID.  This compatibility entry point never creates a logical
 * connection, never registers either visible CID, and never refreshes state.
 * In particular, a clear-only Initial is not authentication evidence.
 */
enum fk_quic_cid_result_code fk_quic_cid_map_observe_long_header(
    struct fk_quic_cid_map *map,
    const struct fk_quic_header_observation *observation,
    uint64_t timestamp_ns,
    uint16_t ingress_owner,
    uint16_t proposed_fixed_owner,
    struct fk_quic_cid_resolution *result);

/*
 * The sole long-header API permitted to create a connection or learn the
 * Initial's visible SCID.  The proof must be AEAD_VERIFIED, fixed-bit one,
 * canonical, and byte-for-byte bound to a supported v1/v2 Initial
 * observation.  Retry, Handshake and 0-RTT are rejected here even when a
 * caller supplies a forged proof.  This API boundary is not a parser
 * capability claim; no proof producer exists in the clear-only native parser.
 */
enum fk_quic_cid_result_code
fk_quic_cid_map_observe_authenticated_initial(
    struct fk_quic_cid_map *map,
    const struct fk_quic_header_observation *observation,
    const struct fk_quic_cid_initial_admission_proof *proof,
    uint64_t timestamp_ns,
    uint16_t ingress_owner,
    uint16_t proposed_fixed_owner,
    struct fk_quic_cid_resolution *result);

/* Lookup one already registered CID; this function never registers. */
enum fk_quic_cid_result_code fk_quic_cid_map_lookup(
    struct fk_quic_cid_map *map,
    const uint8_t *cid,
    uint8_t cid_length,
    uint64_t timestamp_ns,
    uint16_t ingress_owner,
    struct fk_quic_cid_resolution *result);

/*
 * Resolve a QUIC short header only from an already authenticated CID alias.
 * Header-form must be zero. Fixed-bit=1 follows RFC 9000. Fixed-bit=0 follows
 * RFC 9287 and may resolve only when the unique matching logical connection
 * was marked by fk_quic_cid_map_mark_grease_quic_bit_negotiated() after an
 * authenticated transport-parameter parser proved that both endpoints
 * negotiated grease_quic_bit. Because the short header carries no DCID
 * length, this probes only currently active CID lengths and performs at most
 * 20 exact hash lookups for payload[1..length]. Each lookup visits at most
 * config.maximum_hash_chain entries; the API never scans the CID table or
 * allocates.
 * Zero hits are UNRESOLVED. More than one hit is AMBIGUOUS even when every
 * prefix belongs to the same logical connection: accepting one would guess
 * an unauthenticated wire CID length. An ambiguous collision tombstone also
 * fails closed. A unique fixed-bit=0 hit without authenticated negotiation is
 * REJECTED and does not refresh either CID or connection TTL. This API does
 * not recover encrypted NEW_CONNECTION_ID or RETIRE_CONNECTION_ID frames and
 * is not a complete QUIC parser.
 */
enum fk_quic_cid_result_code
fk_quic_cid_map_resolve_known_short_header(
    struct fk_quic_cid_map *map,
    const uint8_t *udp_payload,
    size_t udp_payload_length,
    uint64_t timestamp_ns,
    uint16_t ingress_owner,
    struct fk_quic_cid_resolution *result);

bool fk_quic_cid_map_register_authenticated_cid(
    struct fk_quic_cid_map *map,
    uint64_t logical_connection_id,
    const uint8_t *cid,
    uint8_t cid_length,
    uint64_t timestamp_ns);

/*
 * Register a trusted alias and its direction when used as a destination CID.
 * The legacy API above intentionally creates a direction-unknown alias.
 */
bool fk_quic_cid_map_register_authenticated_cid_with_direction(
    struct fk_quic_cid_map *map,
    uint64_t logical_connection_id,
    const uint8_t *cid,
    uint8_t cid_length,
    uint8_t destination_feature_direction,
    uint64_t timestamp_ns);

/*
 * Only an authenticated QUIC transport-parameter parser may call this after
 * proving that both endpoints negotiated RFC 9287 grease_quic_bit. The mark
 * applies to one live logical connection and never refreshes its TTL.
 */
bool fk_quic_cid_map_mark_grease_quic_bit_negotiated(
    struct fk_quic_cid_map *map,
    uint64_t logical_connection_id,
    uint64_t timestamp_ns);

bool fk_quic_cid_map_mark_handshake_complete(
    struct fk_quic_cid_map *map,
    uint64_t logical_connection_id,
    uint64_t timestamp_ns);

bool fk_quic_cid_map_release(
    struct fk_quic_cid_map *map,
    uint64_t logical_connection_id);

/*
 * Ordered release is the packet-path form.  The supplied sequence and
 * semantic timestamp are copied into the retirement snapshot and must come
 * from the same semantic order as owner dispatch.  This timestamp is marked
 * formal.  The compatibility release above records no packet sequence and
 * uses the directory's last semantic time as a known but non-formal fallback.
 */
bool fk_quic_cid_map_release_ordered(
    struct fk_quic_cid_map *map,
    uint64_t logical_connection_id,
    uint64_t packet_sequence,
    uint64_t semantic_timestamp_ns);

/* Quiescent finite-epoch drain.  The timestamp must be no earlier than every
 * live connection's frozen idle expiry; a premature call fails before
 * changing lifecycle state.  Successful retirement is marked as formal
 * idle-timeout expiry and remains pending for the ordinary publisher/owner
 * acknowledgement path. */
bool fk_quic_cid_map_drain_finite_epoch(
    struct fk_quic_cid_map *map,
    uint64_t terminal_semantic_timestamp_ns,
    struct fk_quic_cid_finite_epoch_drain_receipt_v1 *receipt);

/*
 * Called by the fixed owner only after it has successfully created the exact
 * logical-id binding.  It is valid for ACTIVE and RETIRED_PENDING_OWNER_ACK so
 * an ordered retire queued behind the first packet observes the final truth.
 */
bool fk_quic_cid_map_mark_binding_established(
    struct fk_quic_cid_map *map,
    uint64_t logical_connection_id,
    uint16_t fixed_owner);

/*
 * Read-only owner-route guard. Under the CID-directory lock it decodes the
 * complete slot+generation identity and accepts either a published ACTIVE
 * connection or RETIRED_PENDING_OWNER_ACK. The latter is required when DATA
 * reached an owner queue before its later retirement control. A successful
 * state result and OWNER_MISMATCH return the immutable directory owner;
 * stale/not-found results deliberately leave it UINT16_MAX. This API never
 * advances semantic time, refreshes TTLs, expires state, or changes lifecycle
 * accounting; only the append-only diagnostic counters above are updated.
 */
enum fk_quic_cid_route_prevalidation_result
fk_quic_cid_map_prevalidate_logical_route(
    const struct fk_quic_cid_map *map,
    uint64_t logical_connection_id,
    uint16_t expected_fixed_owner,
    uint16_t *immutable_fixed_owner);

/*
 * V2 additionally snapshots the immutable retirement ordering boundary.
 * ACTIVE, RETIRED_PENDING_OWNER_ACK, and OWNER_MISMATCH return a populated
 * guard.  All other results leave it zeroed.  As with the compatibility API,
 * this changes only append-only diagnostic counters.
 */
enum fk_quic_cid_route_prevalidation_result
fk_quic_cid_map_prevalidate_logical_route_v2(
    const struct fk_quic_cid_map *map,
    uint64_t logical_connection_id,
    uint16_t expected_fixed_owner,
    struct fk_quic_cid_route_guard_v2 *guard);

/* Peek never removes the fixed owner's FIFO head. */
enum fk_quic_cid_retirement_peek_result
fk_quic_cid_map_peek_retired(
    struct fk_quic_cid_map *map,
    uint16_t fixed_owner,
    struct fk_quic_cid_retirement *retirement);

/*
 * Return the next retirement that has not yet been published to owner
 * dispatch.  Unlike fk_quic_cid_map_peek_retired(), this cursor advances past
 * already-dispatched FIFO entries and therefore makes every newly retired
 * control visible before a producer submits later DATA.  Peek is read-only;
 * the exact returned token must be marked separately.
 */
enum fk_quic_cid_retirement_peek_result
fk_quic_cid_map_peek_next_undispatched_retirement(
    struct fk_quic_cid_map *map,
    uint16_t fixed_owner,
    struct fk_quic_cid_retirement *retirement);

/*
 * Mark only the exact current first-undispatched retirement.  The single
 * identity/CID producer calls this for every control in an owner-dispatch
 * observation batch before its atomic submit.  If that submit fails, it must
 * call rollback in exact reverse mark order before doing any other CID work.
 * A successful submit is the commit point and must never be rolled back.
 */
enum fk_quic_cid_retirement_publication_result
fk_quic_cid_map_mark_retirement_dispatched(
    struct fk_quic_cid_map *map,
    const struct fk_quic_cid_retirement_token *token);

enum fk_quic_cid_retirement_publication_result
fk_quic_cid_map_rollback_retirement_dispatched(
    struct fk_quic_cid_map *map,
    const struct fk_quic_cid_retirement_token *token);

/*
 * Acknowledge only the exact current FIFO head.  The control path returns only
 * its immutable logical id, fixed owner and globally monotonic retirement
 * ordinal.  Under the CID lock, the callback is
 * given a fresh head snapshot and must perform the fixed owner's idempotent,
 * O(1), nonblocking prepare+finalize cleanup.  It must not allocate or reenter
 * this map.  An exact but undispatched head returns NOT_DISPATCHED without
 * invoking the callback.  A false callback result leaves the CID FIFO, credit
 * and slot untouched for retry.  A true result is followed only by no-fail
 * local bookkeeping.  This is the sole published-connection path that
 * returns its binding credit and connection slot.  A UINT32_MAX generation
 * slot is quarantined instead of being wrapped and reused.
 */
typedef bool (*fk_quic_cid_owner_cleanup_callback)(
    void *user,
    const struct fk_quic_cid_retirement *current_retirement);

enum fk_quic_cid_retirement_ack_result
fk_quic_cid_map_ack_retired_with_cleanup(
    struct fk_quic_cid_map *map,
    const struct fk_quic_cid_retirement_token *token,
    fk_quic_cid_owner_cleanup_callback cleanup,
    void *cleanup_user);

bool fk_quic_cid_map_get_stats(
    const struct fk_quic_cid_map *map,
    struct fk_quic_cid_map_stats *stats);

/* Terminal/quiescent accounting helper for the immutable owner quota. */
bool fk_quic_cid_map_get_fixed_owner_active_connections(
    const struct fk_quic_cid_map *map,
    uint16_t fixed_owner,
    uint32_t *active_connections);

bool fk_quic_cid_map_get_fixed_owner_lifecycle(
    const struct fk_quic_cid_map *map,
    uint16_t fixed_owner,
    struct fk_quic_cid_fixed_owner_lifecycle *lifecycle);

/* Cold/quiescent bounded traversal of slots, free list and retired FIFOs. */
bool fk_quic_cid_map_accounting_conserved(
    const struct fk_quic_cid_map *map);

const char *fk_quic_cid_retirement_peek_result_name(
    enum fk_quic_cid_retirement_peek_result result);

const char *fk_quic_cid_retirement_ack_result_name(
    enum fk_quic_cid_retirement_ack_result result);

const char *fk_quic_cid_route_prevalidation_result_name(
    enum fk_quic_cid_route_prevalidation_result result);

const char *fk_quic_cid_retirement_publication_result_name(
    enum fk_quic_cid_retirement_publication_result result);

const char *fk_quic_cid_reject_reason_name(
    enum fk_quic_cid_reject_reason reason);

#ifdef FK_QUIC_CID_MAP_TEST_HOOKS
/* Unit-test fault injection; absent from production builds. */
bool fk_quic_cid_map_test_override_hash_chain_limit(
    struct fk_quic_cid_map *map,
    uint32_t maximum_hash_chain);

/* Set only the current free-list head's stored generation. */
bool fk_quic_cid_map_test_set_free_head_generation(
    struct fk_quic_cid_map *map,
    uint32_t generation);

/* Replace the addressed CID bucket head, including with one-past-end, and
 * return the prior value so a fault test can restore valid state. */
bool fk_quic_cid_map_test_override_bucket_head(
    struct fk_quic_cid_map *map,
    const uint8_t *cid,
    uint8_t cid_length,
    uint32_t replacement_head,
    uint32_t *prior_head);
#endif

#ifdef __cplusplus
}
#endif

#endif
