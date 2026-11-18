#ifndef FLOWKEEP_FK_OWNER_FLOW_BINDINGS_H
#define FLOWKEEP_FK_OWNER_FLOW_BINDINGS_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "fk_quic_logical_id.h"

#ifdef __cplusplus
extern "C" {
#endif

#define FK_OWNER_FLOW_BINDINGS_ABI_VERSION 4u
#define FK_OWNER_FLOW_BINDINGS_DEFAULT_OWNERS 8u
#define FK_OWNER_FLOW_BINDINGS_DEFAULT_CONNECTION_SLOTS 4096u
#define FK_OWNER_FLOW_BINDINGS_MAX_FLOW_INDEX UINT32_C(0x00ffffff)
#define FK_OWNER_FLOW_BINDING_ENTRY_BYTES 16u
#define FK_OWNER_FLOW_BINDINGS_TOPOLOGY_RECEIPT_ABI_VERSION 1u
#define FK_OWNER_FLOW_BINDING_CREATION_RECEIPT_ABI_VERSION 1u
#define FK_OWNER_FLOW_BINDING_CREATION_RECEIPT_WORDS 6u

/* Same canonical topology payload and hash as the CID-directory receipt.
 * Explicit fields remain authoritative; the hash is a stable audit checksum
 * that detects accidental construction/configuration drift. */
struct fk_owner_flow_bindings_topology_receipt {
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

/*
 * The directory contains exactly one 16-byte entry for every connection slot
 * in the QUIC CID directory.  The low word of a logical connection id is the
 * slot plus one, so lookup never hashes or probes.  Both topology fields must
 * exactly match the CID directory before either component is connected.
 *
 * retire_ack_required is deliberately mandatory.  A CID slot may not be
 * reused until its immutable owner has prepared a generation-tagged retired
 * marker, the CID directory has durably recorded owner cleanup, and the owner
 * has finalized that exact marker to FREE.
 */
struct fk_owner_flow_bindings_config {
    uint16_t owner_count;
    uint16_t logical_id_abi_version;
    uint32_t maximum_connection_slots;
    uint8_t retire_ack_required;
    uint8_t reserved[7];
};

/* Kept module-local so cleanup enumeration does not depend on or call into a
 * FlowTable implementation.  The main-path adapter copies the compact
 * FlowTable handle's index and generation into this value. */
struct fk_owner_flow_handle {
    uint32_t index;
    uint32_t generation;
};

struct fk_owner_flow_binding {
    uint64_t logical_connection_id;
    struct fk_owner_flow_handle handle;
    /*
     * presentation_canonical_direction =
     *     logical_feature_to_presentation_direction_xor XOR
     *     current_logical_feature_direction
     */
    uint8_t logical_feature_to_presentation_direction_xor;
    uint8_t reserved[7];
};

/*
 * Opaque, one-use proof that bind_from_admission_v2() created one exact
 * unpublished binding.  Callers may copy the bytes but must not interpret or
 * modify them.  The receipt is bound to the directory lifetime, fixed owner,
 * logical-id generation, FlowTable handle, direction axis, prior slot state,
 * and a non-reused per-owner creation epoch.  It is consumed only by the V2
 * commit/abort operations below.
 */
struct fk_owner_flow_binding_creation_receipt {
    uint64_t opaque[FK_OWNER_FLOW_BINDING_CREATION_RECEIPT_WORDS];
};

enum fk_owner_flow_binding_result {
    FK_OWNER_FLOW_BINDING_INVALID = 0,
    FK_OWNER_FLOW_BINDING_NOT_OWNER = 1,
    FK_OWNER_FLOW_BINDING_NOT_FOUND = 2,
    FK_OWNER_FLOW_BINDING_FOUND = 3,
    FK_OWNER_FLOW_BINDING_CREATED = 4,
    FK_OWNER_FLOW_BINDING_IDEMPOTENT = 5,
    FK_OWNER_FLOW_BINDING_REBOUND = 6,
    FK_OWNER_FLOW_BINDING_RELEASED = 7,
    FK_OWNER_FLOW_BINDING_CONFLICT = 8,
    /* FlowTable generation mismatch, not CID-slot generation mismatch. */
    FK_OWNER_FLOW_BINDING_STALE_GENERATION = 9,
    FK_OWNER_FLOW_BINDING_HANDLE_MISMATCH = 10,
    FK_OWNER_FLOW_BINDING_DIRECTION_MISMATCH = 11,
    FK_OWNER_FLOW_BINDING_CID_GENERATION_MISMATCH = 12,
    FK_OWNER_FLOW_BINDING_FIXED_OWNER_MISMATCH = 13,
    FK_OWNER_FLOW_BINDING_SLOT_REUSE_BEFORE_RETIRE_ACK = 14,
    FK_OWNER_FLOW_BINDING_RETIRE_EXPECTATION_MISMATCH = 15,
    FK_OWNER_FLOW_BINDING_RETIRE_PREPARED = 16,
    FK_OWNER_FLOW_BINDING_RETIRE_PREPARE_IDEMPOTENT = 17,
    FK_OWNER_FLOW_BINDING_RETIRE_FINALIZED = 18,
    FK_OWNER_FLOW_BINDING_RETIRE_PENDING_CID_ACK = 19,
    FK_OWNER_FLOW_BINDING_STATE_INTEGRITY_FAILURE = 20,
};

enum fk_owner_flow_binding_scan_result {
    FK_OWNER_FLOW_BINDING_SCAN_INVALID = 0,
    FK_OWNER_FLOW_BINDING_SCAN_NOT_OWNER = 1,
    FK_OWNER_FLOW_BINDING_SCAN_ACTIVE = 2,
    FK_OWNER_FLOW_BINDING_SCAN_MORE = 3,
    FK_OWNER_FLOW_BINDING_SCAN_END = 4,
};

/* Atomic counters are maintained per owner and summed for the global view. */
struct fk_owner_flow_binding_counters {
    uint64_t lookup_attempts;
    uint64_t lookup_found;
    uint64_t lookup_not_found;
    uint64_t bind_attempts;
    uint64_t bindings_created;
    uint64_t bind_idempotent;
    uint64_t bind_conflicts;
    uint64_t rebind_attempts;
    uint64_t rebind_success;
    uint64_t rebind_idempotent;
    uint64_t release_attempts;
    uint64_t releases;
    uint64_t retire_prepare_attempts;
    uint64_t retire_prepared_bound;
    uint64_t retire_prepared_unbound;
    uint64_t retire_prepared_absent;
    uint64_t retire_prepare_idempotent;
    uint64_t retire_finalize_attempts;
    uint64_t retire_finalize_success;
    uint64_t scan_calls;
    uint64_t scan_slots;
    uint64_t scan_active;
    uint64_t scan_passes_completed;
    uint64_t missing_binding_rejects;
    uint64_t stale_generation_rejects;
    uint64_t handle_mismatch_rejects;
    uint64_t direction_mismatch_rejects;
    uint64_t cid_generation_mismatch_rejects;
    uint64_t fixed_owner_mismatch_rejects;
    uint64_t slot_reuse_before_retire_ack_rejects;
    uint64_t retire_expectation_mismatch_rejects;
    uint64_t slot_out_of_range_rejects;
    uint64_t invalid_requests;
    uint64_t state_integrity_failures;
    uint64_t owner_thread_claims;
    uint64_t owner_thread_violations;
};

struct fk_owner_flow_bindings_owner_stats {
    struct fk_owner_flow_binding_counters counters;
    uint64_t active_bindings;
    uint64_t peak_active_bindings;
    uint64_t unbound_slots;
    uint64_t peak_unbound_slots;
    uint64_t retired_pending_cid_ack_slots;
    uint64_t peak_retired_pending_cid_ack_slots;
    uint16_t owner;
    uint16_t owner_thread_claimed;
    uint32_t maximum_connection_slots;
};

struct fk_owner_flow_bindings_stats {
    struct fk_owner_flow_binding_counters counters;
    uint64_t active_bindings;
    uint64_t peak_active_bindings_sum;
    uint64_t unbound_slots;
    uint64_t peak_unbound_slots_sum;
    uint64_t retired_pending_cid_ack_slots;
    uint64_t peak_retired_pending_cid_ack_slots_sum;
    uint64_t empty_slots;
    uint64_t total_capacity;
    uint64_t reserved_bytes;
    uint16_t owner_count;
    uint16_t logical_id_abi_version;
    uint32_t maximum_connection_slots;
    uint16_t entry_bytes;
    uint8_t retire_ack_required;
    uint8_t reserved0;
};

struct fk_owner_flow_bindings;

void fk_owner_flow_bindings_default_config_init(
    struct fk_owner_flow_bindings_config *config);

bool fk_owner_flow_bindings_config_valid(
    const struct fk_owner_flow_bindings_config *config);

/* Includes all metadata and alignment.  Zero means invalid or overflow. */
size_t fk_owner_flow_bindings_storage_bytes(
    const struct fk_owner_flow_bindings_config *config);

/* Caller-owned placement initialization; no heap allocation is performed. */
struct fk_owner_flow_bindings *fk_owner_flow_bindings_initialize(
    void *storage,
    size_t storage_bytes,
    const struct fk_owner_flow_bindings_config *config);

/* All owner threads must be stopped before destroy. */
void fk_owner_flow_bindings_destroy(
    struct fk_owner_flow_bindings *bindings);

/* Immutable and allocation-free; does not require an owner-thread claim. */
bool fk_owner_flow_bindings_get_topology_receipt(
    const struct fk_owner_flow_bindings *bindings,
    struct fk_owner_flow_bindings_topology_receipt *receipt);

/* A claim is an immutable, one-shot ownership transfer for the directory
 * lifetime. A second claim is rejected even from the same thread, preventing
 * two adapters/runtimes from sharing one fixed-owner binding domain. Every
 * entry operation is rejected unless made by the originally claimed thread.
 *
 * Thread identity is a process-global, monotonically allocated, non-reused
 * 64-bit token rather than a TLS address (TLS storage addresses can be reused
 * after thread exit). Token exhaustion fails closed and is durably accounted
 * as both an owner-thread violation and a state-integrity failure. */
bool fk_owner_flow_bindings_claim_owner(
    struct fk_owner_flow_bindings *bindings,
    uint16_t owner);

bool fk_owner_flow_bindings_is_owner_thread(
    const struct fk_owner_flow_bindings *bindings,
    uint16_t owner);

/* Owner-bound public entry points call this before touching any non-atomic
 * owner-local object.  Unlike is_owner_thread(), a rejection is durably
 * recorded in the directory's atomic owner_thread_violations receipt, so the
 * wrong thread need not write the adapter's non-atomic statistics. */
bool fk_owner_flow_bindings_validate_owner_thread_and_account(
    struct fk_owner_flow_bindings *bindings,
    uint16_t owner);

/* RETIRED_PENDING_CID_ACK is observable rather than reported as absent.  In
 * that result, binding contains the retained FlowTable handle/axis for a
 * BOUND-origin marker, or a zero handle for UNBOUND/absent origin. */
enum fk_owner_flow_binding_result fk_owner_flow_bindings_lookup(
    struct fk_owner_flow_bindings *bindings,
    uint16_t owner,
    uint64_t logical_connection_id,
    struct fk_owner_flow_binding *binding);

/* The stored direction axis is the admitted FlowTable presentation direction
 * XOR the packet's logical QUIC feature direction. */
enum fk_owner_flow_binding_result
fk_owner_flow_bindings_bind_from_admission(
    struct fk_owner_flow_bindings *bindings,
    uint16_t owner,
    uint64_t logical_connection_id,
    struct fk_owner_flow_handle handle,
    uint8_t admitted_identity_first_canonical_direction,
    uint8_t current_logical_feature_direction,
    struct fk_owner_flow_binding *binding);

/* Formal transactional creation path.  A nonzero receipt is returned only
 * with CREATED.  At most one V2 creation may remain unpublished per owner;
 * it must be committed after the corresponding CID-directory mark succeeds,
 * or aborted if that mark fails, before another V2 creation is attempted. */
enum fk_owner_flow_binding_result
fk_owner_flow_bindings_bind_from_admission_v2(
    struct fk_owner_flow_bindings *bindings,
    uint16_t owner,
    uint64_t logical_connection_id,
    struct fk_owner_flow_handle handle,
    uint8_t admitted_identity_first_canonical_direction,
    uint8_t current_logical_feature_direction,
    struct fk_owner_flow_binding *binding,
    struct fk_owner_flow_binding_creation_receipt *creation_receipt);

/* Converts the exact receipt's unpublished binding into an ordinary BOUND
 * entry.  Successful commit consumes the receipt epoch and makes all copies
 * of that receipt permanently unusable for commit or abort. */
bool fk_owner_flow_bindings_commit_creation_v2(
    struct fk_owner_flow_bindings *bindings,
    uint16_t owner,
    uint64_t logical_connection_id,
    struct fk_owner_flow_handle expected,
    const struct fk_owner_flow_binding_creation_receipt *creation_receipt);

/* Failure-only rollback of the exact unpublished V2 creation.  The prior
 * FREE or UNBOUND state encoded in the nonce-bound receipt is restored.
 * Successful abort consumes the epoch, so copied/replayed receipts fail. */
bool fk_owner_flow_bindings_abort_unpublished_creation_v2(
    struct fk_owner_flow_bindings *bindings,
    uint16_t owner,
    uint64_t logical_connection_id,
    struct fk_owner_flow_handle expected,
    const struct fk_owner_flow_binding_creation_receipt *creation_receipt);

/*
 * Legacy source/ABI compatibility only.  This receipt-less API always fails:
 * a BOUND entry alone cannot prove that it is the caller's still-unpublished
 * creation.  Formal rollback must use the V2 receipt-bearing API above.
 */
bool fk_owner_flow_bindings_abort_unpublished_creation(
    struct fk_owner_flow_bindings *bindings,
    uint16_t owner,
    uint64_t logical_connection_id,
    struct fk_owner_flow_handle expected);

/* Compatibility wrapper equivalent to bind_from_admission with logical
 * feature direction zero. */
enum fk_owner_flow_binding_result fk_owner_flow_bindings_bind_once(
    struct fk_owner_flow_bindings *bindings,
    uint16_t owner,
    uint64_t logical_connection_id,
    struct fk_owner_flow_handle handle,
    uint8_t first_canonical_direction,
    struct fk_owner_flow_binding *binding);

/* Compare the exact FlowTable generation handle and publish desired handle
 * plus its recomputed direction axis in one lock-free 64-bit store. */
enum fk_owner_flow_binding_result
fk_owner_flow_bindings_compare_exchange_rebind_from_admission(
    struct fk_owner_flow_bindings *bindings,
    uint16_t owner,
    uint64_t logical_connection_id,
    struct fk_owner_flow_handle expected,
    struct fk_owner_flow_handle desired,
    uint8_t admitted_identity_first_canonical_direction,
    uint8_t current_logical_feature_direction,
    struct fk_owner_flow_binding *binding);

bool fk_owner_flow_binding_resolve_presentation_direction(
    const struct fk_owner_flow_binding *binding,
    uint8_t current_logical_feature_direction,
    uint8_t *presentation_canonical_direction);

/* FlowTable release only: BOUND becomes UNBOUND while the CID generation and
 * immutable owner remain.  CID slot retirement uses the API below. */
enum fk_owner_flow_binding_result fk_owner_flow_bindings_release(
    struct fk_owner_flow_bindings *bindings,
    uint16_t owner,
    uint64_t logical_connection_id,
    struct fk_owner_flow_handle expected);

/*
 * Prepare the owner-serialized half of the CID retire transaction.  When
 * binding_expected is true, the exact generation/owner must be BOUND or
 * UNBOUND.  When false, only FREE is accepted.  Either case installs a
 * RETIRED_PENDING_CID_ACK marker that retains the exact CID generation and
 * owner.  A BOUND prepare also retains its FlowTable handle/axis so the CID
 * cleanup callback can release it generation-safely; UNBOUND/absent markers
 * carry a zero handle.  Repeating prepare for the same marker is idempotent
 * and returns the retained handle if it is still present.  This function never
 * clears directly to FREE.
 */
enum fk_owner_flow_binding_result
fk_owner_flow_bindings_retire_connection(
    struct fk_owner_flow_bindings *bindings,
    uint16_t owner,
    uint64_t logical_connection_id,
    bool binding_expected,
    struct fk_owner_flow_binding *retired_binding);

/* Finalize only an exact RETIRED_PENDING_CID_ACK marker to FREE.  The caller
 * must still hold the exact CID RETIRING record's lock and must first complete
 * generation-safe FlowTable cleanup for the retained handle, if any.  Only
 * after successful finalization and callback return may the CID directory
 * complete its ACK and return the slot to its free list. */
enum fk_owner_flow_binding_result
fk_owner_flow_bindings_finalize_retire_exact(
    struct fk_owner_flow_bindings *bindings,
    uint16_t owner,
    uint64_t logical_connection_id);

/* Scans the global direct-slot domain, but returns only BOUND entries owned by
 * caller.  Every call examines at most maximum_slots_to_scan slots. */
enum fk_owner_flow_binding_scan_result
fk_owner_flow_bindings_inspect_next_active(
    struct fk_owner_flow_bindings *bindings,
    uint16_t owner,
    uint32_t *cursor,
    uint32_t maximum_slots_to_scan,
    struct fk_owner_flow_binding *binding,
    uint32_t *slots_scanned);

bool fk_owner_flow_bindings_get_owner_stats(
    const struct fk_owner_flow_bindings *bindings,
    uint16_t owner,
    struct fk_owner_flow_bindings_owner_stats *stats);

/* Atomic loads are data-race safe during processing.  Exact entry/state
 * conservation is a terminal, quiescent-run property. */
bool fk_owner_flow_bindings_get_stats(
    const struct fk_owner_flow_bindings *bindings,
    struct fk_owner_flow_bindings_stats *stats);

/* Verifies FREE + UNBOUND + BOUND + RETIRED_PENDING_CID_ACK equals the slot
 * ceiling, exact per-owner state counts, zero reserved bits, and counter sums. */
bool fk_owner_flow_bindings_accounting_conserved(
    const struct fk_owner_flow_bindings *bindings);

#ifdef FK_OWNER_FLOW_BINDINGS_TEST_HOOKS
/* Tests only: advances the process-global allocator to UINT64_MAX without
 * ever decreasing or reusing a token. Exactly one subsequent fresh thread
 * can receive that final token; every later fresh thread must fail closed. */
bool fk_owner_flow_bindings_test_reserve_final_thread_token(void);

/* Tests only: exposes the immutable token assigned to the calling thread. */
uint64_t fk_owner_flow_bindings_test_current_thread_token(void);
#endif

const char *fk_owner_flow_binding_result_name(
    enum fk_owner_flow_binding_result result);

const char *fk_owner_flow_binding_scan_result_name(
    enum fk_owner_flow_binding_scan_result result);

#ifdef __cplusplus
}
#endif

#endif
