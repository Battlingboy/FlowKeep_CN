#ifndef FLOWKEEP_FK_DPDK_OWNER_MBUF_BYTES_SOURCE_H
#define FLOWKEEP_FK_DPDK_OWNER_MBUF_BYTES_SOURCE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "fk_owner_dispatch.h"

#ifdef __cplusplus
extern "C" {
#endif

#define FK_DPDK_OWNER_MBUF_BYTES_SOURCE_ABI_VERSION 1u

struct fk_owner_packet_bytes_source;
struct fk_dpdk_owner_mbuf_bytes_source;

struct fk_dpdk_owner_mbuf_bytes_source_config {
    uint32_t abi_version;
    uint16_t fixed_owner;
    uint16_t owner_count;
    uint8_t reserved[8];
};

enum fk_dpdk_owner_mbuf_claim_result {
    FK_DPDK_OWNER_MBUF_CLAIM_INVALID = 0,
    FK_DPDK_OWNER_MBUF_CLAIM_NOT_OWNER = 1,
    FK_DPDK_OWNER_MBUF_CLAIMED = 2,
    FK_DPDK_OWNER_MBUF_CLAIM_BUSY = 3,
    FK_DPDK_OWNER_MBUF_CLAIM_DESCRIPTOR_REJECTED = 4,
    FK_DPDK_OWNER_MBUF_CLAIM_SHAPE_REJECTED = 5,
};

enum fk_dpdk_owner_mbuf_release_result {
    FK_DPDK_OWNER_MBUF_RELEASE_INVALID = 0,
    FK_DPDK_OWNER_MBUF_RELEASE_NOT_OWNER = 1,
    FK_DPDK_OWNER_MBUF_RELEASED = 2,
    FK_DPDK_OWNER_MBUF_RELEASE_NO_ACTIVE_CLAIM = 3,
    FK_DPDK_OWNER_MBUF_RELEASE_HANDLE_MISMATCH = 4,
};

struct fk_dpdk_owner_mbuf_bytes_source_stats {
    uint64_t owner_claim_attempts;
    uint64_t owner_claim_successes;
    uint64_t owner_claim_rejections;
    uint64_t owner_thread_rejections;

    uint64_t packet_claim_attempts;
    uint64_t packet_claim_successes;
    uint64_t double_claim_rejections;
    uint64_t descriptor_rejections;
    uint64_t mbuf_shape_rejections;

    uint64_t resolver_calls;
    uint64_t resolver_successes;
    uint64_t resolver_no_active_rejections;
    uint64_t resolver_handle_mismatch_rejections;
    uint64_t resolver_mbuf_mutation_rejections;

    uint64_t release_attempts;
    uint64_t release_successes;
    uint64_t release_no_active_rejections;
    uint64_t release_handle_mismatch_rejections;

    uint64_t destroy_live_claim_rejections;
    uintptr_t active_packet_handle;
    uint32_t active_captured_length;
    uint32_t active_wire_length;
    uint32_t abi_version;
    uint16_t fixed_owner;
    uint16_t owner_count;
    uint8_t initialized;
    uint8_t owner_claimed;
    uint8_t active_claim;
    uint8_t accounting_conserved;
};

void fk_dpdk_owner_mbuf_bytes_source_default_config_init(
    struct fk_dpdk_owner_mbuf_bytes_source_config *config);

bool fk_dpdk_owner_mbuf_bytes_source_config_valid(
    const struct fk_dpdk_owner_mbuf_bytes_source_config *config);

size_t fk_dpdk_owner_mbuf_bytes_source_storage_bytes(
    const struct fk_dpdk_owner_mbuf_bytes_source_config *config);

/* Caller-owned placement initialization; no heap allocation or EAL service
 * is used. The returned object belongs to one immutable fixed owner. */
struct fk_dpdk_owner_mbuf_bytes_source *
fk_dpdk_owner_mbuf_bytes_source_initialize(
    void *storage,
    size_t storage_bytes,
    const struct fk_dpdk_owner_mbuf_bytes_source_config *config);

/* One-shot transfer to the calling owner thread. A second claim is rejected,
 * even from the same thread. Thread identities are monotonically allocated
 * process tokens and are never deliberately reused. */
bool fk_dpdk_owner_mbuf_bytes_source_claim_owner(
    struct fk_dpdk_owner_mbuf_bytes_source *source);

/* Produces the exact-handle adapter resolver. The returned descriptor remains
 * valid until destroy; claim_dequeued() controls which one mbuf it can expose. */
bool fk_dpdk_owner_mbuf_bytes_source_get_adapter_source(
    struct fk_dpdk_owner_mbuf_bytes_source *source,
    struct fk_owner_packet_bytes_source *adapter_source);

/* Called immediately after this fixed owner dequeues one DATA descriptor.
 * The descriptor's handle must be an rte_mbuf pointer. Strict mode accepts
 * only a nonempty, untruncated, single-segment, DIRECT mbuf with refcnt==1
 * whose pkt_len/data_len are exactly captured_length and wire_length.
 * Resolver calls revalidate those conditions and the claimed metadata. */
enum fk_dpdk_owner_mbuf_claim_result
fk_dpdk_owner_mbuf_bytes_source_claim_dequeued(
    struct fk_dpdk_owner_mbuf_bytes_source *source,
    const struct fk_owner_packet *packet);

/* OUTPUT_BACKPRESSURE requires no state transition: retain the active claim
 * and retry the same adapter packet. Every consuming adapter result must call
 * this exact-handle release before the caller frees or recycles the mbuf. */
enum fk_dpdk_owner_mbuf_release_result
fk_dpdk_owner_mbuf_bytes_source_release_consumed(
    struct fk_dpdk_owner_mbuf_bytes_source *source,
    uintptr_t exact_packet_handle);

bool fk_dpdk_owner_mbuf_bytes_source_get_stats(
    const struct fk_dpdk_owner_mbuf_bytes_source *source,
    struct fk_dpdk_owner_mbuf_bytes_source_stats *stats);

/* Quiescent owner accounting. */
bool fk_dpdk_owner_mbuf_bytes_source_accounting_conserved(
    const struct fk_dpdk_owner_mbuf_bytes_source *source);

/* Fails without destruction while one exact mbuf claim remains live. */
bool fk_dpdk_owner_mbuf_bytes_source_destroy_checked(
    struct fk_dpdk_owner_mbuf_bytes_source *source);

const char *fk_dpdk_owner_mbuf_claim_result_name(
    enum fk_dpdk_owner_mbuf_claim_result result);

const char *fk_dpdk_owner_mbuf_release_result_name(
    enum fk_dpdk_owner_mbuf_release_result result);

#ifdef __cplusplus
}
#endif

#endif
