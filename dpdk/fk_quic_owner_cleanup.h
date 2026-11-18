#ifndef FLOWKEEP_FK_QUIC_OWNER_CLEANUP_H
#define FLOWKEEP_FK_QUIC_OWNER_CLEANUP_H

#include <stdbool.h>
#include <stdint.h>

#include "fk_owner_flow_bindings.h"
#include "fk_quic_cid_map.h"

#ifdef __cplusplus
extern "C" {
#endif

#define FK_QUIC_OWNER_CLEANUP_ABI_VERSION 1u

/*
 * The callback is invoked exactly once on every cleanup attempt after the
 * binding directory has installed (or rediscovered) its durable RETIRED
 * marker.  A zero-generation handle means that no FlowTable binding exists;
 * the callback must still advance the owner's semantic residency watermark
 * and return ALREADY_ABSENT.  A nonzero-generation handle is released by
 * exact generation and may return RELEASED or ALREADY_ABSENT.
 */
enum fk_quic_owner_flow_release_result {
    FK_QUIC_OWNER_FLOW_RELEASE_INVALID = 0,
    FK_QUIC_OWNER_FLOW_RELEASE_RELEASED = 1,
    FK_QUIC_OWNER_FLOW_RELEASE_ALREADY_ABSENT = 2,
    FK_QUIC_OWNER_FLOW_RELEASE_TIME_REGRESSION = 3,
    FK_QUIC_OWNER_FLOW_RELEASE_FAILED = 4,
};

typedef enum fk_quic_owner_flow_release_result
(*fk_quic_owner_flow_release_callback)(
    void *user,
    struct fk_owner_flow_handle handle,
    uint64_t retirement_timestamp_ns);

struct fk_quic_owner_cleanup_stats {
    uint64_t context_prepare_attempts;
    uint64_t contexts_prepared;
    uint64_t context_prepare_rejects;

    uint64_t callback_calls;
    uint64_t callback_successes;
    uint64_t callback_failures;
    uint64_t invalid_callback_rejects;
    uint64_t stale_context_rejects;
    uint64_t reentrant_callback_rejects;
    uint64_t retirement_snapshot_mismatches;
    uint64_t retirement_snapshot_matches;

    uint64_t timestamp_known_calls;
    uint64_t timestamp_formal_calls;
    uint64_t timestamp_nonformal_calls;
    uint64_t timestamp_unknown_rejects;
    uint64_t timestamp_regression_rejects;

    uint64_t binding_prepare_attempts;
    uint64_t binding_prepare_fresh;
    uint64_t binding_prepare_idempotent;
    uint64_t binding_prepare_failures;
    uint64_t retired_binding_contract_failures;

    uint64_t flow_release_attempts;
    uint64_t flow_release_released;
    uint64_t flow_release_already_absent;
    uint64_t flow_release_time_regressions;
    uint64_t flow_release_failures;
    uint64_t flow_release_contract_violations;

    uint64_t binding_finalize_attempts;
    uint64_t binding_finalize_successes;
    uint64_t binding_finalize_failures;

    uint64_t successful_formal_cleanups;
    uint64_t successful_nonformal_cleanups;
    uint64_t timestamp_watermark_ns;
    uint64_t latest_context_epoch;
    uint16_t fixed_owner;
    uint8_t timestamp_watermark_valid;
    uint8_t formal_replay_ready;
    uint8_t reserved[4];
};

/*
 * One preallocated adapter belongs to exactly one immutable fixed owner and
 * is called only by that claimed owner's thread.  No operation allocates.
 * Public layout allows placement in caller-owned service state or on a stack.
 */
struct fk_quic_owner_cleanup_adapter {
    struct fk_owner_flow_bindings *bindings;
    fk_quic_owner_flow_release_callback release_callback;
    void *release_user;
    struct fk_quic_owner_cleanup_stats stats;
    uint64_t latest_context_epoch;
    uint64_t timestamp_watermark_ns;
    uint32_t maximum_connection_slots;
    uint16_t fixed_owner;
    uint8_t initialized;
    uint8_t timestamp_watermark_valid;
    uint8_t callback_active;
    uint8_t reserved[3];
};

/*
 * A stack context snapshots the latest FIFO-head peek.  The fresh snapshot
 * supplied by fk_quic_cid_map_ack_retired_with_cleanup must match every
 * immutable field.  binding_expected may legally change only from zero to
 * one after the peek when an earlier ordered owner packet establishes its
 * binding; a one-to-zero change is rejected.
 */
struct fk_quic_owner_cleanup_context {
    struct fk_quic_owner_cleanup_adapter *adapter;
    struct fk_quic_cid_retirement expected_retirement;
    uint64_t epoch;
    uint8_t ready;
    uint8_t completed;
    uint8_t reserved[6];
};

bool fk_quic_owner_cleanup_adapter_initialize(
    struct fk_quic_owner_cleanup_adapter *adapter,
    struct fk_owner_flow_bindings *bindings,
    uint16_t fixed_owner,
    fk_quic_owner_flow_release_callback release_callback,
    void *release_user);

/* Copies the latest successful FIFO-head peek into caller-owned stack state. */
bool fk_quic_owner_cleanup_context_prepare(
    struct fk_quic_owner_cleanup_adapter *adapter,
    const struct fk_quic_cid_retirement *latest_retirement,
    struct fk_quic_owner_cleanup_context *context);

/* Pass this function and a prepared context to the CID acknowledgement API. */
bool fk_quic_owner_cleanup_callback(
    void *user,
    const struct fk_quic_cid_retirement *current_retirement);

bool fk_quic_owner_cleanup_get_stats(
    const struct fk_quic_owner_cleanup_adapter *adapter,
    struct fk_quic_owner_cleanup_stats *stats);

/* Counter conservation plus exact adapter metadata consistency. */
bool fk_quic_owner_cleanup_accounting_conserved(
    const struct fk_quic_owner_cleanup_adapter *adapter);

/*
 * Strict artifact gate.  Non-formal cleanup is operationally permitted but
 * makes this false, as do missing timestamps, retries, or any integrity/error
 * path.  An empty, otherwise clean adapter is ready.
 */
bool fk_quic_owner_cleanup_formal_replay_ready(
    const struct fk_quic_owner_cleanup_adapter *adapter);

struct fk_compact_runtime;

/* DPDK-free bridge to fk_compact_runtime_release_bound_flow. */
enum fk_quic_owner_flow_release_result
fk_quic_owner_cleanup_compact_runtime_release(
    void *runtime_user,
    struct fk_owner_flow_handle handle,
    uint64_t retirement_timestamp_ns);

const char *fk_quic_owner_flow_release_result_name(
    enum fk_quic_owner_flow_release_result result);

#ifdef __cplusplus
}
#endif

#endif
