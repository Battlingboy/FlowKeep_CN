#ifndef FLOWKEEP_FK_OWNER_PIPELINE_ABORT_COORDINATOR_H
#define FLOWKEEP_FK_OWNER_PIPELINE_ABORT_COORDINATOR_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "fk_owner_abort_protocol.h"

#ifdef __cplusplus
extern "C" {
#endif

#define FK_OWNER_PIPELINE_ABORT_COORDINATOR_ABI_VERSION 1u
#define FK_OWNER_PIPELINE_ABORT_AUTH_KEY_BYTES 16u

struct fk_owner_dispatch;
struct fk_owner_output_batch_ring;
struct fk_owner_output_sequence_bridge;
struct fk_fixed_owner_worker_pump;

typedef bool (*fk_owner_pipeline_abort_dispatch_reclaim_callback)(
    void *context,
    uint16_t fixed_owner,
    uintptr_t exact_packet_handle);

struct fk_owner_pipeline_abort_coordinator_config {
    uint32_t abi_version;
    uint16_t owner_count;
    uint16_t reserved0;
    uint64_t coordinator_epoch;
    uint8_t authentication_key_0[
        FK_OWNER_PIPELINE_ABORT_AUTH_KEY_BYTES];
    uint8_t authentication_key_1[
        FK_OWNER_PIPELINE_ABORT_AUTH_KEY_BYTES];
    uint8_t keys_precommitted;
    uint8_t reserved[7];
    struct fk_owner_dispatch *dispatch;
    struct fk_owner_output_sequence_bridge *bridge;
    struct fk_owner_output_batch_ring *const *owner_rings;
    struct fk_fixed_owner_worker_pump *const *owner_pumps;
    const void *identity_verify_context;
    fk_owner_abort_identity_prepared_verify_fn identity_verify;
    void *dispatch_reclaim_context;
    fk_owner_pipeline_abort_dispatch_reclaim_callback dispatch_reclaim;
};

enum fk_owner_pipeline_abort_record_result {
    FK_OWNER_PIPELINE_ABORT_RECORD_INVALID = 0,
    FK_OWNER_PIPELINE_ABORT_RECORDED = 1,
    FK_OWNER_PIPELINE_ABORT_ALREADY_RECORDED = 2,
    FK_OWNER_PIPELINE_ABORT_RECEIPT_MISMATCH = 3,
    FK_OWNER_PIPELINE_ABORT_NOT_VERIFIED = 4,
    FK_OWNER_PIPELINE_ABORT_ALREADY_COMMITTED = 5,
    FK_OWNER_PIPELINE_ABORT_RECORD_TERMINAL = 6,
};

enum fk_owner_pipeline_abort_commit_result {
    FK_OWNER_PIPELINE_ABORT_COMMIT_INVALID = 0,
    FK_OWNER_PIPELINE_ABORT_COMMITTED = 1,
    FK_OWNER_PIPELINE_ABORT_COMMIT_NOT_READY = 2,
    FK_OWNER_PIPELINE_ABORT_COMMIT_ALREADY_COMMITTED = 3,
    FK_OWNER_PIPELINE_ABORT_COMMIT_EVIDENCE_REJECTED = 4,
    FK_OWNER_PIPELINE_ABORT_COMMIT_BRIDGE_FAILED = 5,
    FK_OWNER_PIPELINE_ABORT_COMMIT_CLEANUP_FAILED = 6,
    FK_OWNER_PIPELINE_ABORT_COMMIT_TERMINAL = 7,
    FK_OWNER_PIPELINE_ABORT_COMMIT_RETRY_REQUIRED = 8,
};

enum fk_owner_pipeline_abort_authorize_result {
    FK_OWNER_PIPELINE_ABORT_AUTHORIZE_INVALID = 0,
    FK_OWNER_PIPELINE_ABORT_AUTHORIZED = 1,
    FK_OWNER_PIPELINE_ABORT_ALREADY_AUTHORIZED = 2,
};

struct fk_owner_pipeline_abort_coordinator_stats {
    uint64_t coordinator_epoch;
    uint64_t prepared_owner_mask;
    uint64_t owner_record_attempts;
    uint64_t owner_receipts_recorded;
    uint64_t owner_receipt_duplicates;
    uint64_t owner_receipt_rejections;
    uint64_t identity_record_attempts;
    uint64_t identity_receipts_recorded;
    uint64_t identity_receipt_duplicates;
    uint64_t identity_receipt_rejections;
    uint64_t commit_attempts;
    uint64_t commit_not_ready;
    uint64_t commit_successes;
    uint64_t commit_failures;
    uint64_t dispatch_abort_attempts;
    uint64_t dispatch_abort_successes;
    uint64_t dispatch_drain_attempts;
    uint64_t dispatch_drain_empty;
    uint64_t dispatch_data_drained;
    uint64_t dispatch_retire_controls_discarded;
    uint64_t dispatch_reclaim_attempts;
    uint64_t dispatch_reclaim_successes;
    uint64_t dispatch_reclaim_failures;
    uint64_t bridge_bound_loss_candidates;
    uint64_t bridge_bound_candidates_exact_verified;
    uint64_t receipt_validation_attempts;
    uint64_t receipt_validation_successes;
    uint64_t receipt_validation_failures;
    uint64_t fixed_owner_finalize_mask;
    uint64_t identity_finalize_authorizations;
    uint64_t service_memory_bytes;
    uintptr_t pending_dispatch_packet_handle;
    uint32_t abi_version;
    uint16_t owner_count;
    uint8_t identity_prepared;
    uint8_t committed;
    uint8_t terminal_failure;
    uint8_t pending_dispatch_envelope;
    uint8_t service_memory_exact;
    uint8_t reserved[3];
};

struct fk_owner_pipeline_abort_coordinator;

void fk_owner_pipeline_abort_coordinator_default_config_init(
    struct fk_owner_pipeline_abort_coordinator_config *config);

bool fk_owner_pipeline_abort_coordinator_config_valid(
    const struct fk_owner_pipeline_abort_coordinator_config *config);

size_t fk_owner_pipeline_abort_coordinator_storage_bytes(
    const struct fk_owner_pipeline_abort_coordinator_config *config);

struct fk_owner_pipeline_abort_coordinator *
fk_owner_pipeline_abort_coordinator_initialize(
    void *storage,
    size_t storage_bytes,
    const struct fk_owner_pipeline_abort_coordinator_config *config);

enum fk_owner_pipeline_abort_record_result
fk_owner_pipeline_abort_coordinator_record_owner_prepared(
    struct fk_owner_pipeline_abort_coordinator *coordinator,
    const struct fk_fixed_owner_abort_prepared_receipt_v1 *receipt);

enum fk_owner_pipeline_abort_record_result
fk_owner_pipeline_abort_coordinator_record_identity_prepared(
    struct fk_owner_pipeline_abort_coordinator *coordinator,
    const struct fk_owner_abort_identity_prepared_receipt_v1 *receipt);

enum fk_owner_pipeline_abort_commit_result
fk_owner_pipeline_abort_coordinator_commit(
    struct fk_owner_pipeline_abort_coordinator *coordinator);

bool fk_owner_pipeline_abort_coordinator_get_receipt(
    const struct fk_owner_pipeline_abort_coordinator *coordinator,
    struct fk_owner_pipeline_abort_receipt_v1 *receipt);

/* Receipt fields never self-authorize.  This validates both independent tags,
 * an exact match with private immutable coordinator state, and the live clean
 * bridge/ring state created by commit(). */
bool fk_owner_pipeline_abort_coordinator_validate_receipt(
    const struct fk_owner_pipeline_abort_coordinator *coordinator,
    const struct fk_owner_pipeline_abort_receipt_v1 *receipt);

enum fk_owner_pipeline_abort_authorize_result
fk_owner_pipeline_abort_coordinator_authorize_finalize(
    struct fk_owner_pipeline_abort_coordinator *coordinator,
    const struct fk_owner_pipeline_abort_receipt_v1 *receipt,
    enum fk_owner_pipeline_abort_participant_kind participant_kind,
    uint16_t participant_id);

bool fk_owner_pipeline_abort_coordinator_get_stats(
    const struct fk_owner_pipeline_abort_coordinator *coordinator,
    struct fk_owner_pipeline_abort_coordinator_stats *stats);

bool fk_owner_pipeline_abort_coordinator_destroy_checked(
    struct fk_owner_pipeline_abort_coordinator *coordinator);

#ifdef __cplusplus
}
#endif

#endif
