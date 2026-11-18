#ifndef FLOWKEEP_FK_DPDK_EXACT_IDENTITY_MBUF_SOURCE_H
#define FLOWKEEP_FK_DPDK_EXACT_IDENTITY_MBUF_SOURCE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "fk_exact_identity_sequencer.h"
#include "fk_exact_identity_packet_bytes_resolver.h"

#ifdef __cplusplus
extern "C" {
#endif

#define FK_DPDK_EXACT_IDENTITY_MBUF_SOURCE_ABI_VERSION 1u

struct fk_dpdk_exact_identity_mbuf_source;

struct fk_dpdk_exact_identity_mbuf_source_config {
    uint32_t abi_version;
    uint16_t producer_count;
    uint8_t reserved[10];
};

enum fk_dpdk_exact_identity_mbuf_claim_result {
    FK_DPDK_EXACT_IDENTITY_MBUF_CLAIM_INVALID = 0,
    FK_DPDK_EXACT_IDENTITY_MBUF_CLAIM_NOT_IDENTITY_THREAD = 1,
    FK_DPDK_EXACT_IDENTITY_MBUF_CLAIMED = 2,
    FK_DPDK_EXACT_IDENTITY_MBUF_CLAIM_BUSY = 3,
    FK_DPDK_EXACT_IDENTITY_MBUF_CLAIM_DESCRIPTOR_REJECTED = 4,
    FK_DPDK_EXACT_IDENTITY_MBUF_CLAIM_SHAPE_REJECTED = 5,
};

enum fk_dpdk_exact_identity_mbuf_clear_result {
    FK_DPDK_EXACT_IDENTITY_MBUF_CLEAR_INVALID = 0,
    FK_DPDK_EXACT_IDENTITY_MBUF_CLEAR_NOT_IDENTITY_THREAD = 1,
    FK_DPDK_EXACT_IDENTITY_MBUF_CLEARED = 2,
    FK_DPDK_EXACT_IDENTITY_MBUF_CLEAR_NO_ACTIVE_CLAIM = 3,
    FK_DPDK_EXACT_IDENTITY_MBUF_CLEAR_DESCRIPTOR_MISMATCH = 4,
    FK_DPDK_EXACT_IDENTITY_MBUF_CLEAR_MBUF_MUTATED = 5,
};

enum fk_dpdk_exact_identity_mbuf_retain_result {
    FK_DPDK_EXACT_IDENTITY_MBUF_RETAIN_INVALID = 0,
    FK_DPDK_EXACT_IDENTITY_MBUF_RETAIN_NOT_IDENTITY_THREAD = 1,
    FK_DPDK_EXACT_IDENTITY_MBUF_RETAINED = 2,
    FK_DPDK_EXACT_IDENTITY_MBUF_RETAIN_NO_ACTIVE_CLAIM = 3,
    FK_DPDK_EXACT_IDENTITY_MBUF_RETAIN_DESCRIPTOR_MISMATCH = 4,
    FK_DPDK_EXACT_IDENTITY_MBUF_RETAIN_MBUF_MUTATED = 5,
};

struct fk_dpdk_exact_identity_mbuf_source_stats {
    uint64_t identity_thread_claim_attempts;
    uint64_t identity_thread_claim_successes;
    uint64_t identity_thread_claim_rejections;
    uint64_t identity_thread_rejections;

    uint64_t released_claim_attempts;
    uint64_t released_claim_successes;
    uint64_t double_claim_rejections;
    uint64_t descriptor_rejections;
    uint64_t mbuf_shape_rejections;

    uint64_t resolver_calls;
    uint64_t resolver_successes;
    uint64_t resolver_no_active_rejections;
    uint64_t resolver_handle_mismatch_rejections;
    uint64_t resolver_mbuf_mutation_rejections;

    uint64_t backpressure_retain_attempts;
    uint64_t backpressure_retentions;
    uint64_t backpressure_no_active_rejections;
    uint64_t backpressure_descriptor_mismatch_rejections;
    uint64_t backpressure_mbuf_mutation_rejections;

    uint64_t transfer_clear_attempts;
    uint64_t transfer_clears;
    uint64_t skip_reclaim_clear_attempts;
    uint64_t skip_reclaim_clears;
    uint64_t reject_reclaim_clear_attempts;
    uint64_t reject_reclaim_clears;
    uint64_t clear_no_active_rejections;
    uint64_t clear_descriptor_mismatch_rejections;
    uint64_t clear_mbuf_mutation_rejections;

    uint64_t destroy_live_claim_rejections;
    uintptr_t active_packet_handle;
    uint64_t active_packet_sequence;
    uint32_t active_captured_length;
    uint32_t active_wire_length;
    uint32_t abi_version;
    uint16_t producer_count;
    uint8_t initialized;
    uint8_t identity_thread_claimed;
    uint8_t active_claim;
    uint8_t accounting_conserved;
};

void fk_dpdk_exact_identity_mbuf_source_default_config_init(
    struct fk_dpdk_exact_identity_mbuf_source_config *config);

bool fk_dpdk_exact_identity_mbuf_source_config_valid(
    const struct fk_dpdk_exact_identity_mbuf_source_config *config);

size_t fk_dpdk_exact_identity_mbuf_source_storage_bytes(
    const struct fk_dpdk_exact_identity_mbuf_source_config *config);

struct fk_dpdk_exact_identity_mbuf_source *
fk_dpdk_exact_identity_mbuf_source_initialize(
    void *storage,
    size_t storage_bytes,
    const struct fk_dpdk_exact_identity_mbuf_source_config *config);

/* One-shot claim by the only exact-identity consumer thread. */
bool fk_dpdk_exact_identity_mbuf_source_claim_identity_thread(
    struct fk_dpdk_exact_identity_mbuf_source *source);

bool fk_dpdk_exact_identity_mbuf_source_get_resolver(
    struct fk_dpdk_exact_identity_mbuf_source *source,
    struct fk_exact_identity_packet_bytes_resolver *resolver);

/* Called for exactly one packet returned as POLL_RELEASED. */
enum fk_dpdk_exact_identity_mbuf_claim_result
fk_dpdk_exact_identity_mbuf_source_claim_released(
    struct fk_dpdk_exact_identity_mbuf_source *source,
    const struct fk_exact_identity_packet *packet);

/* Explicit backpressure receipt: validates and retains the same claim. */
enum fk_dpdk_exact_identity_mbuf_retain_result
fk_dpdk_exact_identity_mbuf_source_retain_backpressure(
    struct fk_dpdk_exact_identity_mbuf_source *source,
    const struct fk_exact_identity_packet *exact_packet);

/* Use only after publisher DATA_COMMITTED. This clears identity-stage
 * ownership because dispatch now owns the mbuf; neither this module nor the
 * caller may free it. The owner may already have freed the mbuf, so this
 * post-commit transition verifies only the frozen exact descriptor and never
 * dereferences packet_handle. */
enum fk_dpdk_exact_identity_mbuf_clear_result
fk_dpdk_exact_identity_mbuf_source_transfer_data_committed(
    struct fk_dpdk_exact_identity_mbuf_source *source,
    const struct fk_exact_identity_packet *exact_packet);

/* Use after a parser/router skip was committed. On CLEARED the caller still
 * owns the mbuf and must reclaim/free it exactly once. */
enum fk_dpdk_exact_identity_mbuf_clear_result
fk_dpdk_exact_identity_mbuf_source_clear_skip_for_reclaim(
    struct fk_dpdk_exact_identity_mbuf_source *source,
    const struct fk_exact_identity_packet *exact_packet);

/* Use after a noncommitting reject/failure. On CLEARED the caller still owns
 * the mbuf and must reclaim/free it exactly once. */
enum fk_dpdk_exact_identity_mbuf_clear_result
fk_dpdk_exact_identity_mbuf_source_clear_reject_for_reclaim(
    struct fk_dpdk_exact_identity_mbuf_source *source,
    const struct fk_exact_identity_packet *exact_packet);

bool fk_dpdk_exact_identity_mbuf_source_get_stats(
    const struct fk_dpdk_exact_identity_mbuf_source *source,
    struct fk_dpdk_exact_identity_mbuf_source_stats *stats);

bool fk_dpdk_exact_identity_mbuf_source_accounting_conserved(
    const struct fk_dpdk_exact_identity_mbuf_source *source);

bool fk_dpdk_exact_identity_mbuf_source_destroy_checked(
    struct fk_dpdk_exact_identity_mbuf_source *source);

#ifdef __cplusplus
}
#endif

#endif
