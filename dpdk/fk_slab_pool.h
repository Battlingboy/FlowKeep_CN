#ifndef FLOWKEEP_FK_SLAB_POOL_H
#define FLOWKEEP_FK_SLAB_POOL_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

struct fk_slab_handle {
    uint16_t index;
    uint16_t generation;
};

struct fk_slab_pool_stats {
    uint32_t block_size;
    uint32_t capacity;
    uint32_t in_use;
    uint32_t peak_in_use;
    uint64_t storage_bytes;
    uint64_t metadata_bytes;
    uint64_t allocations;
    uint64_t allocation_rejects;
    uint64_t releases;
    uint64_t stale_release_rejects;
};

struct fk_slab_pool;

struct fk_slab_pool *fk_slab_pool_create(
    uint32_t block_size,
    uint32_t capacity,
    char *error,
    size_t error_capacity);

uint64_t fk_slab_pool_allocation_bytes(
    uint32_t block_size,
    uint32_t capacity);

void fk_slab_pool_destroy(struct fk_slab_pool *pool);

bool fk_slab_pool_acquire(
    struct fk_slab_pool *pool,
    struct fk_slab_handle *handle,
    void **block);

bool fk_slab_pool_acquire_index(
    struct fk_slab_pool *pool,
    uint16_t *index,
    void **block);

bool fk_slab_pool_release(
    struct fk_slab_pool *pool,
    struct fk_slab_handle handle);

bool fk_slab_pool_release_index(
    struct fk_slab_pool *pool,
    uint16_t index);

void *fk_slab_pool_get(
    struct fk_slab_pool *pool,
    struct fk_slab_handle handle);

void *fk_slab_pool_get_index(
    struct fk_slab_pool *pool,
    uint16_t index);

bool fk_slab_pool_get_stats(
    const struct fk_slab_pool *pool,
    struct fk_slab_pool_stats *stats);

#ifdef __cplusplus
}
#endif

#endif
