#ifndef FLOWKEEP_FK_ACTOR_NAMESPACE_MONITOR_MAP_H
#define FLOWKEEP_FK_ACTOR_NAMESPACE_MONITOR_MAP_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define FK_ACTOR_NAMESPACE_MONITOR_MAP_VERSION 1u
#define FK_ACTOR_NAMESPACE_MONITOR_MAP_HEADER_BYTES 80u
#define FK_ACTOR_NAMESPACE_MONITOR_MAP_ENTRY_BYTES 4u
#define FK_ACTOR_NAMESPACE_MONITOR_MAP_SOURCE_SHA256_BYTES 32u
#define FK_ACTOR_NAMESPACE_MONITOR_MAP_MAX_NAMESPACES 1048576u
#define FK_ACTOR_NAMESPACE_MONITOR_MAP_MAX_FILE_BYTES \
    (FK_ACTOR_NAMESPACE_MONITOR_MAP_HEADER_BYTES + \
     FK_ACTOR_NAMESPACE_MONITOR_MAP_MAX_NAMESPACES * \
         FK_ACTOR_NAMESPACE_MONITOR_MAP_ENTRY_BYTES)

/*
 * Canonical FKANM01 wire format (all integer fields little endian):
 *
 *   0   magic[8] = "FKANM01\0"
 *   8   u16 version
 *   10  u16 header_bytes
 *   12  u16 entry_bytes
 *   14  u16 flags (zero)
 *   16  u8 IPv4 pool_base[4]
 *   20  u8 pool_prefix_length
 *   21  reserved[3] (zero)
 *   24  u32 slots_per_namespace
 *   28  u32 namespace_count
 *   32  u32 entry_count (must equal namespace_count)
 *   36  reserved[4] (zero)
 *   40  source_mapping_sha256[32] (nonzero)
 *   72  reserved[8] (zero)
 *   80  u32 monitored_identity_index[namespace_count]
 *
 * Entry n is the one-based monitored identity for namespace n+1.  The file
 * has exact size header_bytes + namespace_count*4 with no trailing data.
 */
struct fk_actor_namespace_monitor_map_metadata {
    uint8_t pool_base[4];
    uint8_t pool_prefix_length;
    uint8_t reserved0[3];
    uint32_t slots_per_namespace;
    uint32_t namespace_count;
    uint8_t source_mapping_sha256[
        FK_ACTOR_NAMESPACE_MONITOR_MAP_SOURCE_SHA256_BYTES];
};

/*
 * Validate and decode one complete immutable sidecar.  Passing entries=null
 * and entry_capacity=0 performs a validating metadata-only pass.  Otherwise
 * entry_capacity must cover namespace_count.  Metadata and entries are
 * cleared before validation so a failed call cannot leave usable stale data.
 */
bool fk_actor_namespace_monitor_map_decode(
    const uint8_t *bytes,
    size_t byte_count,
    struct fk_actor_namespace_monitor_map_metadata *metadata,
    uint32_t *entries,
    uint32_t entry_capacity,
    char *error,
    size_t error_capacity);

#ifdef __cplusplus
}
#endif

#endif
