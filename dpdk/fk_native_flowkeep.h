#ifndef FLOWKEEP_FK_NATIVE_FLOWKEEP_H
#define FLOWKEEP_FK_NATIVE_FLOWKEEP_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "fk_native_parser.h"

#define FK_NATIVE_HISTORY_PACKETS 20u
#define FK_NATIVE_BOOTSTRAP_PACKETS 4u
#define FK_NATIVE_VALUE_FEATURES 30u
#define FK_NATIVE_VALUE_MODEL_VERSION 3u
#define FK_NATIVE_VALUE_MODEL_LINEAR_VERSION 2u
#define FK_NATIVE_VALUE_MAX_TREES 32u
#define FK_NATIVE_VALUE_MAX_TREE_NODES 7u
#define FK_NATIVE_DEFAULT_REPLACEMENT_CANDIDATES 64u

enum fk_native_retention_action {
    FK_NATIVE_ACTION_NONE = 0,
    FK_NATIVE_ACTION_KEEP_SUMMARY = 1,
    FK_NATIVE_ACTION_KEEP_HISTORY = 2,
    FK_NATIVE_ACTION_KEEP_HANDSHAKE = 3,
    FK_NATIVE_ACTION_REPLACE_HISTORY = 4,
    FK_NATIVE_ACTION_REPLACE_HANDSHAKE = 5,
    FK_NATIVE_ACTION_BUDGET_DOWNGRADE = 6,
    FK_NATIVE_ACTION_PRESSURE_DOWNGRADE = 7,
    FK_NATIVE_ACTION_MODEL_UNAVAILABLE = 8,
    FK_NATIVE_ACTION_IMPACT_DISABLED = 9,
};

enum fk_native_state_method {
    FK_NATIVE_STATE_SUMMARY = 1,
    FK_NATIVE_STATE_HISTORY = 2,
    FK_NATIVE_STATE_HANDSHAKE = 3,
    FK_NATIVE_STATE_FULL = 4,
    FK_NATIVE_STATE_FLOWKEEP = 5,
    FK_NATIVE_STATE_NETBEACON = 6,
    FK_NATIVE_STATE_SPLIDT = 7,
    FK_NATIVE_STATE_OCTOSKETCH = 8,
    FK_NATIVE_STATE_FLM = 9,
    FK_NATIVE_STATE_FLOWKEEP_HEURISTIC = 10,
    FK_NATIVE_STATE_LRU = 11,
    FK_NATIVE_STATE_FIXED_TTL = 12,
    FK_NATIVE_STATE_PROTOCOL_AWARE = 13,
    FK_NATIVE_STATE_PROTOCOL_DEADLINE = 14,
    FK_NATIVE_STATE_HANDSHAKE_ONLY = 15,
};

enum fk_native_lifecycle {
    FK_NATIVE_BOOTSTRAP = 1,
    FK_NATIVE_SUMMARY = 2,
    FK_NATIVE_HIST = 3,
    FK_NATIVE_HS = 4,
    FK_NATIVE_FULL = 5,
    FK_NATIVE_RELEASED = 6,
};

struct fk_native_packet_metadata {
    uint32_t wire_size;
    uint32_t payload_size;
    uint32_t delta_time_us;
    uint16_t tcp_window;
    uint8_t direction;
    uint8_t tcp_flags;
};

struct fk_native_flow_snapshot {
    struct fk_flow_key key;
    uint64_t first_timestamp_ns;
    uint64_t last_timestamp_ns;
    uint64_t packets;
    uint64_t bytes;
    uint64_t direction_packets[2];
    uint64_t direction_bytes[2];
    uint32_t minimum_wire_size;
    uint32_t maximum_wire_size;
    uint32_t history_count;
    uint32_t handshake_bytes;
    float retention_value;
    uint32_t retention_action;
    uint64_t budget_before;
    uint64_t budget_after;
    uint64_t available_features_hash;
    uint32_t value_model_version;
    float retention_features[FK_NATIVE_VALUE_FEATURES];
    uint64_t evicted_flow_hash;
    float evicted_retention_value;
    uint32_t evicted_lifecycle;
    struct fk_native_packet_metadata history[FK_NATIVE_HISTORY_PACKETS];
    enum fk_native_lifecycle lifecycle;
};

/*
 * A deliberately small, auditable online model.  Training/export is handled
 * offline; the RX path only evaluates prefixes that are available at the
 * decision timestamp.  History and Handshake have separate coefficients
 * because malicious probability and retention value are not interchangeable.
 */
struct fk_native_value_tree_node {
    int16_t feature;
    int16_t left;
    int16_t right;
    float threshold;
    float value;
};

struct fk_native_value_tree {
    uint8_t node_count;
    struct fk_native_value_tree_node
        nodes[FK_NATIVE_VALUE_MAX_TREE_NODES];
};

struct fk_native_value_model {
    uint32_t version;
    uint32_t feature_count;
    /* ABI v2 fast gate, retained unchanged for reproducible ablations. */
    float intercept[2];
    float weights[2][FK_NATIVE_VALUE_FEATURES];
    float threshold[2];
    float state_cost_penalty[2];
    /* ABI v3 bounded GBDT ranker, evaluated only after the fast gate. */
    float gate_threshold[2];
    float ranker_bias[2];
    float ranker_learning_rate[2];
    uint32_t ranker_tree_count[2];
    struct fk_native_value_tree
        ranker_trees[2][FK_NATIVE_VALUE_MAX_TREES];
    float pressure_margin;
    float overload_margin;
};

struct fk_native_flowkeep_stats {
    uint64_t packets_seen;
    uint64_t bytes_seen;
    uint64_t flows_created;
    uint64_t flow_table_full;
    uint64_t active_flows;
    uint64_t peak_active_flows;
    uint64_t terminal_releases;
    uint64_t idle_releases;
    uint64_t lease_release_suppressed;
    uint64_t impact_neutral_transitions;
    uint64_t pressure_summary_downgrades;
    uint64_t history_budget_downgrades;
    uint64_t handshake_budget_downgrades;
    uint64_t model_unavailable_downgrades;
    uint64_t value_evaluations;
    uint64_t fast_gate_rejects;
    uint64_t ranker_evaluations;
    uint64_t value_history_selections;
    uint64_t value_handshake_selections;
    uint64_t bounded_candidate_scans;
    uint64_t expensive_replacements;
    uint64_t replacement_failures;
    uint64_t hard_budget_checks;
    uint64_t hard_budget_rejects;
    uint64_t hard_budget_violations;
    uint64_t controlled_budget_bytes;
    uint64_t state_transitions[FK_NATIVE_RELEASED + 1u];
    uint64_t owned_bytes;
    uint64_t peak_owned_bytes;
};

struct fk_native_flowkeep;

struct fk_native_flowkeep *fk_native_flowkeep_create(
    enum fk_native_state_method method,
    uint32_t maximum_flows,
    uint64_t idle_timeout_ns);

bool fk_native_flowkeep_configure_value_policy(
    struct fk_native_flowkeep *runtime,
    const struct fk_native_value_model *model,
    uint64_t controlled_budget_bytes,
    uint32_t replacement_candidates);

bool fk_native_flowkeep_configure_budget_policy(
    struct fk_native_flowkeep *runtime,
    uint64_t controlled_budget_bytes,
    uint32_t replacement_candidates,
    uint64_t fixed_ttl_ns);

bool fk_native_value_model_load(
    const char *path,
    struct fk_native_value_model *model);

void fk_native_flowkeep_set_q4_policy(
    struct fk_native_flowkeep *runtime,
    bool impact_enabled,
    bool lease_enabled);

void fk_native_flowkeep_set_pressure(
    struct fk_native_flowkeep *runtime,
    uint32_t pressure_level);

void fk_native_flowkeep_set_external_owned_bytes(
    struct fk_native_flowkeep *runtime,
    uint64_t external_owned_bytes);

void fk_native_flowkeep_destroy(struct fk_native_flowkeep *runtime);

bool fk_native_flowkeep_process(
    struct fk_native_flowkeep *runtime,
    uint64_t timestamp_ns,
    const struct fk_packet_view *view,
    struct fk_native_flow_snapshot *snapshot);

void fk_native_flowkeep_expire(
    struct fk_native_flowkeep *runtime,
    uint64_t timestamp_ns);

const struct fk_native_flowkeep_stats *fk_native_flowkeep_get_stats(
    const struct fk_native_flowkeep *runtime);

uint64_t fk_native_flowkeep_owned_bytes(
    const struct fk_native_flowkeep *runtime);

const char *fk_native_state_method_name(enum fk_native_state_method method);

bool fk_native_state_method_parse(
    const char *text,
    enum fk_native_state_method *method);

#endif
