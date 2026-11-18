#define _POSIX_C_SOURCE 200809L
#include "fk_native_event_ring.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

int fk_native_event_ring_open(
        struct fk_native_event_ring *ring,
        const char *name,
        uint32_t capacity,
        bool recreate,
        uint64_t created_mono_ns) {
    if (ring == NULL || name == NULL || name[0] != '/' ||
        capacity == 0u || (capacity & (capacity - 1u)) != 0u) {
        errno = EINVAL;
        return -1;
    }
    memset(ring, 0, sizeof(*ring));
    ring->fd = -1;
    if (recreate)
        (void)shm_unlink(name);
    int fd = shm_open(name, O_RDWR | O_CREAT, 0666);
    if (fd < 0)
        return -1;
    (void)fchmod(fd, 0666);
    size_t map_bytes =
        FK_NATIVE_RING_HEADER_BYTES +
        (size_t)capacity * FK_NATIVE_EVENT_BYTES;
    if (ftruncate(fd, (off_t)map_bytes) != 0) {
        int saved = errno;
        close(fd);
        errno = saved;
        return -1;
    }
    void *mapping = mmap(
        NULL,
        map_bytes,
        PROT_READ | PROT_WRITE,
        MAP_SHARED,
        fd,
        0);
    if (mapping == MAP_FAILED) {
        int saved = errno;
        close(fd);
        errno = saved;
        return -1;
    }
    ring->fd = fd;
    ring->map_bytes = map_bytes;
    ring->base = mapping;
    ring->header = mapping;
    memset(mapping, 0, map_bytes);
    memcpy(ring->header->magic, FK_NATIVE_RING_MAGIC, 8u);
    ring->header->version = FK_NATIVE_RING_VERSION;
    ring->header->header_bytes = FK_NATIVE_RING_HEADER_BYTES;
    ring->header->event_bytes = FK_NATIVE_EVENT_BYTES;
    ring->header->capacity = capacity;
    ring->header->parser_abi_version = FK_NATIVE_PARSER_ABI_VERSION;
    ring->header->flags =
        FK_NATIVE_RING_FLAG_TCP_TLS |
        FK_NATIVE_RING_FLAG_QUIC_CLEAR_HEADER_ONLY |
        FK_NATIVE_RING_FLAG_DETECTION_PARITY_UNAVAILABLE;
    ring->header->created_mono_ns = created_mono_ns;
    atomic_store_explicit(
        &ring->header->write_seq,
        0u,
        memory_order_relaxed);
    atomic_store_explicit(
        &ring->header->read_seq,
        0u,
        memory_order_relaxed);
    atomic_store_explicit(
        &ring->header->producer_drops,
        0u,
        memory_order_relaxed);
    atomic_store_explicit(
        &ring->header->producer_events,
        0u,
        memory_order_relaxed);
    atomic_store_explicit(
        &ring->header->frames_processed,
        0u,
        memory_order_relaxed);
    atomic_store_explicit(
        &ring->header->processed_packet_sequence,
        0u,
        memory_order_relaxed);
    atomic_store_explicit(
        &ring->header->stop,
        0u,
        memory_order_relaxed);
    return 0;
}

bool fk_native_event_ring_push(
        struct fk_native_event_ring *ring,
        const struct fk_native_event *event) {
    if (ring == NULL || ring->header == NULL || event == NULL)
        return false;
    struct fk_native_ring_header *header = ring->header;
    uint64_t write = atomic_load_explicit(
        &header->write_seq,
        memory_order_relaxed);
    uint64_t read = atomic_load_explicit(
        &header->read_seq,
        memory_order_acquire);
    if (write - read >= header->capacity) {
        atomic_fetch_add_explicit(
            &header->producer_drops,
            1u,
            memory_order_relaxed);
        return false;
    }
    uint8_t *slot =
        ring->base + header->header_bytes +
        (write & (header->capacity - 1u)) * header->event_bytes;
    struct fk_native_event published = *event;
    published.event_sequence = write;
    memcpy(slot, &published, sizeof(published));
    atomic_thread_fence(memory_order_release);
    atomic_store_explicit(
        &header->write_seq,
        write + 1u,
        memory_order_release);
    atomic_fetch_add_explicit(
        &header->producer_events,
        1u,
        memory_order_relaxed);
    return true;
}

void fk_native_event_ring_mark_frame(
        struct fk_native_event_ring *ring,
        uint64_t packet_sequence) {
    if (ring == NULL || ring->header == NULL)
        return;
    atomic_fetch_add_explicit(
        &ring->header->frames_processed,
        1u,
        memory_order_relaxed);
    atomic_store_explicit(
        &ring->header->processed_packet_sequence,
        packet_sequence,
        memory_order_release);
}

void fk_native_event_ring_close(struct fk_native_event_ring *ring) {
    if (ring == NULL || ring->base == NULL)
        return;
    atomic_store_explicit(
        &ring->header->stop,
        1u,
        memory_order_release);
    (void)msync(
        ring->base,
        FK_NATIVE_RING_HEADER_BYTES,
        MS_SYNC);
    munmap(ring->base, ring->map_bytes);
    close(ring->fd);
    memset(ring, 0, sizeof(*ring));
    ring->fd = -1;
}
