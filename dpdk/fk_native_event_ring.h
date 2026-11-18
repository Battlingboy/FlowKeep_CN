#ifndef FLOWKEEP_FK_NATIVE_EVENT_RING_H
#define FLOWKEEP_FK_NATIVE_EVENT_RING_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "fk_native_shm.h"

struct fk_native_event_ring {
    int fd;
    size_t map_bytes;
    uint8_t *base;
    struct fk_native_ring_header *header;
};

int fk_native_event_ring_open(
    struct fk_native_event_ring *ring,
    const char *name,
    uint32_t capacity,
    bool recreate,
    uint64_t created_mono_ns);

bool fk_native_event_ring_push(
    struct fk_native_event_ring *ring,
    const struct fk_native_event *event);

void fk_native_event_ring_mark_frame(
    struct fk_native_event_ring *ring,
    uint64_t packet_sequence);

void fk_native_event_ring_close(struct fk_native_event_ring *ring);

#endif
