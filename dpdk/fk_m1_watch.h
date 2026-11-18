#ifndef FLOWKEEP_M1_WATCH_H
#define FLOWKEEP_M1_WATCH_H
#include "fk_native_parser.h"
#include <cinttypes>
#include <cstdio>
#include <cstring>

// Revision13 diagnostic only. No labels, policy actions, or mutable flow
// state are consulted. Instrumented runs cannot establish performance.
inline bool fk_m1_watched(const fk_flow_key &key) {
#ifndef FK_M1_ENABLE_WATCH
    (void)key;
    return false; // R14 production build: compile out fixed-target tracing.
#else
    const uint8_t low[4] = {10, 29, 210, 102};
    const uint8_t high[4] = {10, 29, 210, 103};
    return key.ip_version == 4u && key.protocol == 6u &&
        key.low_port == 1035u && key.high_port == 443u &&
        std::memcmp(key.low_addr, low, 4) == 0 &&
        std::memcmp(key.high_addr, high, 4) == 0;
#endif
}

inline void fk_m1_watch(const char *stage, uint64_t sequence,
        uint64_t timestamp, uint64_t last, uint64_t packets,
        uint32_t index, uint32_t generation, uint32_t detail) {
    // A single stdio call keeps each record intact across pump/owner threads.
    std::fprintf(stderr, "FK_M1_WATCH stage=%s seq=%" PRIu64
        " ts=%" PRIu64 " last=%" PRIu64 " packets=%" PRIu64
        " index=%u generation=%u detail=%u\n", stage, sequence,
        timestamp, last, packets, index, generation, detail);
}
#endif
