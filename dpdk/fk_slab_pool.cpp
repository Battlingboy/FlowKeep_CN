#include "fk_slab_pool.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <limits>
#include <memory>
#include <new>

namespace {

constexpr uint16_t kNoIndex = std::numeric_limits<uint16_t>::max();
constexpr size_t kCacheLine = 64u;

struct Slot {
    uint16_t next;
    uint16_t generation;
    uint8_t used;
    uint8_t reserved[7];
};

struct SlabPool {
    uint32_t block_size = 0u;
    uint32_t capacity = 0u;
    uint16_t free_head = kNoIndex;
    uint8_t *storage = nullptr;
    std::unique_ptr<Slot[]> slots;
    fk_slab_pool_stats stats{};
};

static SlabPool *implementation(fk_slab_pool *pool) {
    return reinterpret_cast<SlabPool *>(pool);
}

static const SlabPool *implementation(const fk_slab_pool *pool) {
    return reinterpret_cast<const SlabPool *>(pool);
}

static void set_error(char *error, size_t capacity, const char *message) {
    if (error != nullptr && capacity != 0u)
        std::snprintf(error, capacity, "%s", message);
}

static bool valid_handle(
        const SlabPool &pool,
        fk_slab_handle handle) {
    return handle.index < pool.capacity &&
        pool.slots[handle.index].used != 0u &&
        pool.slots[handle.index].generation == handle.generation;
}

}  // namespace

extern "C" {

uint64_t fk_slab_pool_allocation_bytes(
        uint32_t block_size,
        uint32_t capacity) {
    if (block_size == 0u || capacity == 0u ||
        capacity > kNoIndex)
        return 0u;
    return sizeof(SlabPool) +
        static_cast<uint64_t>(block_size) * capacity +
        static_cast<uint64_t>(sizeof(Slot)) * capacity;
}

fk_slab_pool *fk_slab_pool_create(
        uint32_t block_size,
        uint32_t capacity,
        char *error,
        size_t error_capacity) {
    set_error(error, error_capacity, "");
    if (block_size == 0u || capacity == 0u ||
        capacity > kNoIndex ||
        static_cast<uint64_t>(block_size) * capacity >
            std::numeric_limits<size_t>::max()) {
        set_error(error, error_capacity, "invalid slab configuration");
        return nullptr;
    }
    SlabPool *pool = new (std::nothrow) SlabPool();
    if (pool == nullptr) {
        set_error(error, error_capacity, "slab allocation failed");
        return nullptr;
    }
    pool->block_size = block_size;
    pool->capacity = capacity;
    const size_t storage_bytes =
        static_cast<size_t>(block_size) * capacity;
    void *storage = nullptr;
    if (posix_memalign(&storage, kCacheLine, storage_bytes) != 0) {
        delete pool;
        set_error(error, error_capacity, "slab storage allocation failed");
        return nullptr;
    }
    pool->storage = static_cast<uint8_t *>(storage);
    /*
     * Fault and zero every pool page during initialization.  The RX worker
     * must never pay a first-touch page-fault penalty when acquiring a block.
     */
    std::memset(pool->storage, 0, storage_bytes);
    pool->slots.reset(new (std::nothrow) Slot[capacity]());
    if (!pool->slots) {
        std::free(pool->storage);
        delete pool;
        set_error(error, error_capacity, "slab metadata allocation failed");
        return nullptr;
    }
    for (uint16_t index = 0u; index < capacity; ++index)
        pool->slots[index].next =
            index + 1u < capacity ? index + 1u : kNoIndex;
    pool->free_head = 0u;
    pool->stats.block_size = block_size;
    pool->stats.capacity = capacity;
    pool->stats.storage_bytes = storage_bytes;
    pool->stats.metadata_bytes = sizeof(SlabPool) +
        static_cast<uint64_t>(capacity) * sizeof(Slot);
    return reinterpret_cast<fk_slab_pool *>(pool);
}

void fk_slab_pool_destroy(fk_slab_pool *pool) {
    if (pool == nullptr)
        return;
    SlabPool *state = implementation(pool);
    std::free(state->storage);
    delete state;
}

bool fk_slab_pool_acquire(
        fk_slab_pool *pool,
        fk_slab_handle *handle,
        void **block) {
    if (pool == nullptr || handle == nullptr || block == nullptr)
        return false;
    SlabPool &state = *implementation(pool);
    if (state.free_head == kNoIndex) {
        state.stats.allocation_rejects++;
        return false;
    }
    const uint16_t index = state.free_head;
    Slot &slot = state.slots[index];
    state.free_head = slot.next;
    slot.generation = static_cast<uint16_t>(
        slot.generation + 1u == 0u ? 1u : slot.generation + 1u);
    slot.used = 1u;
    slot.next = kNoIndex;
    uint8_t *memory =
        state.storage + static_cast<size_t>(index) * state.block_size;
    std::memset(memory, 0, state.block_size);
    *handle = {index, slot.generation};
    *block = memory;
    state.stats.allocations++;
    state.stats.in_use++;
    if (state.stats.in_use > state.stats.peak_in_use)
        state.stats.peak_in_use = state.stats.in_use;
    return true;
}

bool fk_slab_pool_release(
        fk_slab_pool *pool,
        fk_slab_handle handle) {
    if (pool == nullptr)
        return false;
    SlabPool &state = *implementation(pool);
    if (!valid_handle(state, handle)) {
        state.stats.stale_release_rejects++;
        return false;
    }
    Slot &slot = state.slots[handle.index];
    slot.used = 0u;
    slot.next = state.free_head;
    state.free_head = handle.index;
    state.stats.releases++;
    state.stats.in_use--;
    return true;
}

bool fk_slab_pool_acquire_index(
        fk_slab_pool *pool,
        uint16_t *index,
        void **block) {
    if (index == nullptr)
        return false;
    fk_slab_handle handle{};
    if (!fk_slab_pool_acquire(pool, &handle, block))
        return false;
    *index = handle.index;
    return true;
}

bool fk_slab_pool_release_index(
        fk_slab_pool *pool,
        uint16_t index) {
    if (pool == nullptr)
        return false;
    SlabPool &state = *implementation(pool);
    if (index >= state.capacity || state.slots[index].used == 0u) {
        state.stats.stale_release_rejects++;
        return false;
    }
    return fk_slab_pool_release(
        pool, {index, state.slots[index].generation});
}

void *fk_slab_pool_get(
        fk_slab_pool *pool,
        fk_slab_handle handle) {
    if (pool == nullptr)
        return nullptr;
    SlabPool &state = *implementation(pool);
    if (!valid_handle(state, handle))
        return nullptr;
    return state.storage +
        static_cast<size_t>(handle.index) * state.block_size;
}

void *fk_slab_pool_get_index(
        fk_slab_pool *pool,
        uint16_t index) {
    if (pool == nullptr)
        return nullptr;
    SlabPool &state = *implementation(pool);
    if (index >= state.capacity || state.slots[index].used == 0u)
        return nullptr;
    return state.storage +
        static_cast<size_t>(index) * state.block_size;
}

bool fk_slab_pool_get_stats(
        const fk_slab_pool *pool,
        fk_slab_pool_stats *stats) {
    if (pool == nullptr || stats == nullptr)
        return false;
    *stats = implementation(pool)->stats;
    return true;
}

}  // extern "C"
