#ifndef FLOWKEEP_FK_NATIVE_RUNTIME_H
#define FLOWKEEP_FK_NATIVE_RUNTIME_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "fk_native_shm.h"
#include "fk_native_flowkeep.h"

struct fk_native_runtime;

struct fk_native_runtime_stats {
    uint64_t frames_processed;
    uint64_t captured_bytes_processed;
    uint64_t parse_codes[FK_PARSE_CAP_EXCEEDED + 1u];
    uint64_t tcp_packets;
    uint64_t udp_packets;
    uint64_t tls_candidate_flows;
    uint64_t tls_flow_table_full;
    uint64_t peak_allocated_tls_flows;
    uint64_t tls_connection_resets;
    uint64_t tls_hello_events;
    uint64_t tls_client_hello_events;
    uint64_t tls_server_hello_events;
    uint64_t tls_partial_hello_events;
    uint64_t tls_terminal_status_events;
    uint64_t quic_partial_events;
    uint64_t parser_budget_rejects;
    uint64_t controlled_budget_violations;
    double controlled_state_byte_seconds;
    uint64_t events_generated;
    uint64_t event_delivery_failures;
    uint32_t state_latency_sample_interval_packets;
    uint64_t state_latency_samples;
    uint64_t state_latency_total_ns;
    uint64_t state_latency_max_ns;
    uint64_t state_latency_log2_ns[32];
};

typedef bool (*fk_native_event_callback)(
    const struct fk_native_event *event,
    void *user);

struct fk_native_runtime *fk_native_runtime_create(
    uint32_t maximum_tls_flows);

struct fk_native_runtime *fk_native_runtime_create_with_state(
    uint32_t maximum_tls_flows,
    enum fk_native_state_method state_method,
    uint32_t maximum_state_flows,
    uint64_t idle_timeout_ns);

bool fk_native_runtime_configure_value_policy(
    struct fk_native_runtime *runtime,
    const struct fk_native_value_model *model,
    uint64_t controlled_budget_bytes,
    uint32_t replacement_candidates);

bool fk_native_runtime_configure_budget_policy(
    struct fk_native_runtime *runtime,
    uint64_t controlled_budget_bytes,
    uint32_t replacement_candidates,
    uint64_t fixed_ttl_ns);

void fk_native_runtime_destroy(struct fk_native_runtime *runtime);

void fk_native_runtime_process_frame(
    struct fk_native_runtime *runtime,
    uint64_t packet_sequence,
    const uint8_t *frame,
    size_t captured_length,
    uint32_t wire_length,
    fk_native_event_callback callback,
    void *user);

void fk_native_runtime_process_frame_at(
    struct fk_native_runtime *runtime,
    uint64_t packet_sequence,
    uint64_t timestamp_ns,
    const uint8_t *frame,
    size_t captured_length,
    uint32_t wire_length,
    fk_native_event_callback callback,
    void *user);

const struct fk_native_runtime_stats *fk_native_runtime_get_stats(
    const struct fk_native_runtime *runtime);

uint64_t fk_native_runtime_owned_bytes(
    const struct fk_native_runtime *runtime);

uint64_t fk_native_runtime_peak_owned_bytes(
    const struct fk_native_runtime *runtime);

uint32_t fk_native_runtime_maximum_tls_flows(
    const struct fk_native_runtime *runtime);

uint32_t fk_native_runtime_allocated_tls_flows(
    const struct fk_native_runtime *runtime);

const struct fk_native_flowkeep_stats *
fk_native_runtime_get_flowkeep_stats(
    const struct fk_native_runtime *runtime);

enum fk_native_state_method fk_native_runtime_state_method(
    const struct fk_native_runtime *runtime);

void fk_native_runtime_set_q4_policy(
    struct fk_native_runtime *runtime,
    bool impact_enabled,
    bool lease_enabled);

void fk_native_runtime_set_pressure(
    struct fk_native_runtime *runtime,
    uint32_t pressure_level);

bool fk_native_runtime_take_window(
    struct fk_native_runtime *runtime,
    uint64_t *packet_sequence,
    struct fk_native_flow_snapshot *snapshot,
    uint32_t *emission_reason,
    bool *observation_complete);

uint64_t fk_native_runtime_state_latency_percentile_ns(
    const struct fk_native_runtime *runtime,
    uint32_t numerator,
    uint32_t denominator);

#endif
