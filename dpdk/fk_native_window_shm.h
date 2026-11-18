#ifndef FLOWKEEP_FK_NATIVE_WINDOW_SHM_H
#define FLOWKEEP_FK_NATIVE_WINDOW_SHM_H

#include <stdatomic.h>
#include <stdint.h>

#define FK_WINDOW_RING_MAGIC "FKWINV3"
#define FK_WINDOW_RING_VERSION 3u
#define FK_WINDOW_RING_HEADER_BYTES 128u
#define FK_WINDOW_EVENT_BYTES 1024u
#define FK_WINDOW_HISTORY_PACKETS 20u
#define FK_WINDOW_RETENTION_FEATURES 30u

struct __attribute__((packed, aligned(64))) fk_window_ring_header {
    char magic[8];
    uint32_t version;
    uint32_t header_bytes;
    uint32_t event_bytes;
    uint32_t capacity;
    uint32_t history_packets;
    uint32_t flags;
    _Atomic uint64_t write_seq;
    _Atomic uint64_t read_seq;
    _Atomic uint64_t producer_drops;
    _Atomic uint64_t producer_events;
    _Atomic uint64_t source_frames;
    _Atomic uint64_t source_packet_sequence;
    uint64_t created_mono_ns;
    _Atomic uint32_t stop;
    uint32_t reserved0;
    uint8_t padding[32];
};

struct __attribute__((packed)) fk_window_packet {
    uint32_t wire_size;
    uint32_t payload_size;
    uint32_t delta_time_us;
    uint16_t tcp_window;
    uint8_t direction;
    uint8_t tcp_flags;
};

struct __attribute__((packed, aligned(64))) fk_window_event {
    uint64_t packet_sequence;
    uint64_t event_sequence;
    uint64_t first_timestamp_ns;
    uint64_t last_timestamp_ns;
    uint64_t decision_ready_timestamp_ns;
    uint8_t ip_version;
    uint8_t protocol;
    uint8_t low_addr[16];
    uint8_t high_addr[16];
    uint16_t low_port;
    uint16_t high_port;
    uint32_t lifecycle;
    uint64_t packets;
    uint64_t bytes;
    uint64_t direction_packets[2];
    uint64_t direction_bytes[2];
    uint32_t minimum_wire_size;
    uint32_t maximum_wire_size;
    uint32_t history_count;
    uint32_t handshake_bytes;
    uint32_t emission_reason;
    uint32_t observation_complete;
    float retention_value;
    uint32_t retention_action;
    uint64_t budget_before;
    uint64_t budget_after;
    uint64_t available_features_hash;
    uint32_t value_model_version;
    float retention_features[FK_WINDOW_RETENTION_FEATURES];
    uint64_t evicted_flow_hash;
    float evicted_retention_value;
    uint32_t evicted_lifecycle;
    uint32_t predicted_deadline_feasible;
    struct fk_window_packet history[FK_WINDOW_HISTORY_PACKETS];
    uint8_t padding[374];
};

_Static_assert(
    sizeof(struct fk_window_ring_header) == FK_WINDOW_RING_HEADER_BYTES,
    "fk_window_ring_header must be 128 bytes");
_Static_assert(
    sizeof(struct fk_window_packet) == 16u,
    "fk_window_packet must be 16 bytes");
_Static_assert(
    sizeof(struct fk_window_event) == FK_WINDOW_EVENT_BYTES,
    "fk_window_event must be 1024 bytes");

#endif
