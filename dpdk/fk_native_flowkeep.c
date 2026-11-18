#include "fk_native_flowkeep.h"

#include <errno.h>
#include <limits.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct summary_state {
    uint64_t packets;
    uint64_t bytes;
    uint64_t direction_packets[2];
    uint64_t direction_bytes[2];
    uint32_t minimum_wire_size;
    uint32_t maximum_wire_size;
};

struct history_state {
    struct fk_native_packet_metadata packets[FK_NATIVE_HISTORY_PACKETS];
    uint32_t count;
    uint32_t next;
};

struct handshake_state {
    uint32_t retained_bytes;
    uint32_t cap_exceeded;
};

struct netbeacon_style_state {
    uint8_t next_stage;
};

struct splidt_style_state {
    uint64_t tcp_syn_count;
    uint64_t tcp_fin_rst_count;
};

struct octosketch_style_state {
    uint8_t counters[8][32];
};

struct flm_style_state {
    struct fk_native_packet_metadata tokens[32];
    uint32_t count;
};

struct native_flow_state {
    struct summary_state summary;
    struct history_state *history;
    struct handshake_state *handshake;
    void *style;
    uint32_t style_bytes;
};

struct native_flow_entry {
    bool used;
    bool tombstone;
    bool fin_seen[2];
    bool baseline_ttl_expired;
    bool baseline_lru_linked;
    size_t baseline_lru_previous;
    size_t baseline_lru_next;
    struct fk_flow_key key;
    uint64_t first_timestamp_ns;
    uint64_t last_timestamp_ns;
    float retention_value;
    uint32_t retention_action;
    uint64_t budget_before;
    uint64_t budget_after;
    uint64_t available_features_hash;
    float retention_features[FK_NATIVE_VALUE_FEATURES];
    uint32_t bootstrap_wire_size[FK_NATIVE_BOOTSTRAP_PACKETS];
    uint32_t bootstrap_payload_size[FK_NATIVE_BOOTSTRAP_PACKETS];
    uint64_t bootstrap_timestamp_ns[FK_NATIVE_BOOTSTRAP_PACKETS];
    uint8_t bootstrap_direction[FK_NATIVE_BOOTSTRAP_PACKETS];
    uint64_t evicted_flow_hash;
    float evicted_retention_value;
    uint32_t evicted_lifecycle;
    enum fk_native_lifecycle lifecycle;
    struct native_flow_state state;
};

struct fk_native_flowkeep {
    enum fk_native_state_method method;
    uint32_t maximum_flows;
    uint64_t idle_timeout_ns;
    size_t capacity;
    struct native_flow_entry *entries;
    uint64_t allocated_histories;
    uint64_t allocated_handshakes;
    uint64_t allocated_style_bytes;
    bool impact_enabled;
    bool lease_enabled;
    uint32_t pressure_level;
    uint64_t history_budget;
    uint64_t handshake_budget;
    uint64_t controlled_budget_bytes;
    uint64_t external_owned_bytes;
    uint64_t fixed_ttl_ns;
    uint32_t replacement_candidates;
    size_t replacement_cursor;
    size_t baseline_lru_head;
    size_t baseline_lru_tail;
    bool value_model_configured;
    struct fk_native_value_model value_model;
    struct fk_native_flowkeep_stats stats;
};

enum value_state_index {
    VALUE_HISTORY = 0,
    VALUE_HANDSHAKE = 1,
};

static enum fk_native_lifecycle fixed_lifecycle(
        enum fk_native_state_method method) {
    switch (method) {
    case FK_NATIVE_STATE_SUMMARY:
        return FK_NATIVE_SUMMARY;
    case FK_NATIVE_STATE_HISTORY:
        return FK_NATIVE_HIST;
    case FK_NATIVE_STATE_HANDSHAKE:
        return FK_NATIVE_HS;
    case FK_NATIVE_STATE_FULL:
        return FK_NATIVE_FULL;
    case FK_NATIVE_STATE_FLOWKEEP:
    case FK_NATIVE_STATE_FLOWKEEP_HEURISTIC:
    case FK_NATIVE_STATE_LRU:
    case FK_NATIVE_STATE_FIXED_TTL:
    case FK_NATIVE_STATE_PROTOCOL_AWARE:
    case FK_NATIVE_STATE_PROTOCOL_DEADLINE:
    case FK_NATIVE_STATE_HANDSHAKE_ONLY:
        return FK_NATIVE_BOOTSTRAP;
    case FK_NATIVE_STATE_NETBEACON:
    case FK_NATIVE_STATE_SPLIDT:
    case FK_NATIVE_STATE_OCTOSKETCH:
        return FK_NATIVE_SUMMARY;
    case FK_NATIVE_STATE_FLM:
        return FK_NATIVE_HIST;
    default:
        return FK_NATIVE_BOOTSTRAP;
    }
}

static void refresh_owned_bytes(struct fk_native_flowkeep *runtime) {
    uint64_t bytes = sizeof(*runtime) +
        (uint64_t)runtime->capacity * sizeof(*runtime->entries) +
        runtime->allocated_histories * sizeof(struct history_state) +
        runtime->allocated_handshakes * sizeof(struct handshake_state);
    bytes += runtime->allocated_style_bytes;
    runtime->stats.owned_bytes = bytes;
    if (bytes > runtime->stats.peak_owned_bytes)
        runtime->stats.peak_owned_bytes = bytes;
}

static uint64_t hash_bytes(
        uint64_t seed,
        const void *data,
        size_t length) {
    const uint8_t *bytes = data;
    uint64_t value = seed;
    for (size_t index = 0u; index < length; ++index) {
        value ^= bytes[index];
        value *= 1099511628211ull;
    }
    return value;
}

static uint64_t online_feature_hash(
        const float features[FK_NATIVE_VALUE_FEATURES]) {
    return hash_bytes(
        1469598103934665603ull,
        features,
        sizeof(float) * FK_NATIVE_VALUE_FEATURES);
}

static float bounded_log1p(uint64_t value) {
    return (float)log1p((double)value);
}

static bool tls_candidate(const struct fk_packet_view *view) {
    if (view->l4_protocol != 6u)
        return false;
    switch (view->src_port) {
    case 443u:
    case 465u:
    case 636u:
    case 853u:
    case 989u:
    case 990u:
    case 993u:
    case 995u:
    case 5061u:
    case 8443u:
    case 9443u:
        return true;
    default:
        break;
    }
    switch (view->dst_port) {
    case 443u:
    case 465u:
    case 636u:
    case 853u:
    case 989u:
    case 990u:
    case 993u:
    case 995u:
    case 5061u:
    case 8443u:
    case 9443u:
        return true;
    default:
        return false;
    }
}

static void online_value_features(
        const struct fk_native_flowkeep *runtime,
        const struct native_flow_entry *entry,
        const struct fk_packet_view *view,
        float features[FK_NATIVE_VALUE_FEATURES]) {
    const struct summary_state *summary = &entry->state.summary;
    double packets = summary->packets == 0u ? 1.0 :
        (double)summary->packets;
    double direction_total =
        (double)summary->direction_packets[0] +
        (double)summary->direction_packets[1];
    double direction_imbalance = direction_total == 0.0 ? 0.0 :
        fabs(
            (double)summary->direction_packets[0] -
            (double)summary->direction_packets[1]) /
        direction_total;
    double age_ms =
        entry->last_timestamp_ns >= entry->first_timestamp_ns
        ? (double)(entry->last_timestamp_ns -
                   entry->first_timestamp_ns) / 1000000.0
        : 0.0;
    features[0] = bounded_log1p(summary->packets);
    features[1] = bounded_log1p(summary->bytes);
    features[2] = (float)((double)summary->bytes / packets / 1514.0);
    features[3] = (float)summary->maximum_wire_size / 1514.0f;
    features[4] = (float)direction_imbalance;
    features[5] = view->l4_protocol == 6u ? 1.0f : 0.0f;
    features[6] = view->l4_protocol == 17u ? 1.0f : 0.0f;
    features[7] = tls_candidate(view) ? 1.0f : 0.0f;
    features[8] = runtime->pressure_level == 1u ? 1.0f : 0.0f;
    features[9] = runtime->pressure_level == 2u ? 1.0f : 0.0f;
    features[10] = (float)log1p(age_ms);
    features[11] = view->wire_size == 0u ? 0.0f :
        (float)view->payload_size / (float)view->wire_size;
    for (uint32_t index = 0u;
         index < FK_NATIVE_BOOTSTRAP_PACKETS; ++index) {
        float normalized =
            (float)entry->bootstrap_wire_size[index] / 1514.0f;
        features[12u + index] =
            entry->bootstrap_direction[index] == 0u
            ? normalized : -normalized;
    }
    for (uint32_t index = 1u;
         index < FK_NATIVE_BOOTSTRAP_PACKETS; ++index) {
        uint64_t previous = entry->bootstrap_timestamp_ns[index - 1u];
        uint64_t current = entry->bootstrap_timestamp_ns[index];
        double delta_ms = current >= previous
            ? (double)(current - previous) / 1000000.0 : 0.0;
        features[15u + index] = (float)log1p(delta_ms);
    }
    for (uint32_t index = 0u;
         index < FK_NATIVE_BOOTSTRAP_PACKETS; ++index) {
        uint32_t wire = entry->bootstrap_wire_size[index];
        features[19u + index] = wire == 0u ? 0.0f :
            (float)entry->bootstrap_payload_size[index] / (float)wire;
    }
    features[23] =
        (float)(log1p((double)entry->key.low_port) / log(65536.0));
    features[24] =
        (float)(log1p((double)entry->key.high_port) / log(65536.0));
    features[25] =
        (view->tcp_flags & FK_TCP_FLAG_SYN) != 0u ? 1.0f : 0.0f;
    features[26] =
        (view->tcp_flags & FK_TCP_FLAG_ACK) != 0u ? 1.0f : 0.0f;
    features[27] =
        (view->tcp_flags & FK_TCP_FLAG_FIN) != 0u ? 1.0f : 0.0f;
    features[28] =
        (view->tcp_flags & FK_TCP_FLAG_RST) != 0u ? 1.0f : 0.0f;
    features[29] =
        (view->tcp_flags & FK_TCP_FLAG_PSH) != 0u ? 1.0f : 0.0f;
}

static float sigmoid(float value) {
    if (value >= 0.0f) {
        float decay = expf(-value);
        return 1.0f / (1.0f + decay);
    }
    float growth = expf(value);
    return growth / (1.0f + growth);
}

static float tree_value(
        const struct fk_native_value_tree *tree,
        const float features[FK_NATIVE_VALUE_FEATURES]) {
    int16_t node_index = 0;
    for (uint32_t step = 0u;
         step < FK_NATIVE_VALUE_MAX_TREE_NODES; ++step) {
        if (node_index < 0 ||
            (uint32_t)node_index >= tree->node_count)
            return 0.0f;
        const struct fk_native_value_tree_node *node =
            &tree->nodes[node_index];
        if (node->feature < 0)
            return node->value;
        node_index =
            features[(uint32_t)node->feature] <= node->threshold
            ? node->left : node->right;
    }
    return 0.0f;
}

static float retention_value(
        struct fk_native_flowkeep *runtime,
        enum value_state_index state,
        const float features[FK_NATIVE_VALUE_FEATURES]) {
    float logit = runtime->value_model.intercept[state];
    for (uint32_t index = 0u;
         index < FK_NATIVE_VALUE_FEATURES; ++index)
        logit += runtime->value_model.weights[state][index] *
            features[index];
    float gate_score = sigmoid(logit);
    runtime->stats.value_evaluations++;
    if (runtime->value_model.version ==
            FK_NATIVE_VALUE_MODEL_LINEAR_VERSION)
        return gate_score -
            runtime->value_model.state_cost_penalty[state];
    if (gate_score < runtime->value_model.gate_threshold[state]) {
        runtime->stats.fast_gate_rejects++;
        return -1.0f;
    }
    float ranker_logit = runtime->value_model.ranker_bias[state];
    for (uint32_t tree = 0u;
         tree < runtime->value_model.ranker_tree_count[state]; ++tree) {
        ranker_logit +=
            runtime->value_model.ranker_learning_rate[state] *
            tree_value(
                &runtime->value_model.ranker_trees[state][tree],
                features);
    }
    runtime->stats.ranker_evaluations++;
    return sigmoid(ranker_logit) -
        runtime->value_model.state_cost_penalty[state];
}

static uint64_t incremental_state_bytes(
        enum fk_native_lifecycle lifecycle) {
    if (lifecycle == FK_NATIVE_HIST)
        return sizeof(struct history_state);
    if (lifecycle == FK_NATIVE_HS)
        return sizeof(struct handshake_state);
    if (lifecycle == FK_NATIVE_FULL)
        return sizeof(struct history_state) +
            sizeof(struct handshake_state);
    return 0u;
}

static bool is_budget_baseline(enum fk_native_state_method method) {
    return method == FK_NATIVE_STATE_LRU ||
        method == FK_NATIVE_STATE_FIXED_TTL ||
        method == FK_NATIVE_STATE_PROTOCOL_AWARE ||
        method == FK_NATIVE_STATE_PROTOCOL_DEADLINE ||
        method == FK_NATIVE_STATE_HANDSHAKE_ONLY;
}

static size_t entry_index(
        const struct fk_native_flowkeep *runtime,
        const struct native_flow_entry *entry) {
    return (size_t)(entry - runtime->entries);
}

static void baseline_lru_unlink(
        struct fk_native_flowkeep *runtime,
        struct native_flow_entry *entry) {
    if (!entry->baseline_lru_linked)
        return;
    size_t previous = entry->baseline_lru_previous;
    size_t next = entry->baseline_lru_next;
    if (previous == SIZE_MAX)
        runtime->baseline_lru_head = next;
    else
        runtime->entries[previous].baseline_lru_next = next;
    if (next == SIZE_MAX)
        runtime->baseline_lru_tail = previous;
    else
        runtime->entries[next].baseline_lru_previous = previous;
    entry->baseline_lru_linked = false;
    entry->baseline_lru_previous = SIZE_MAX;
    entry->baseline_lru_next = SIZE_MAX;
}

static void baseline_lru_touch(
        struct fk_native_flowkeep *runtime,
        struct native_flow_entry *entry) {
    if (!is_budget_baseline(runtime->method) ||
        (entry->state.history == NULL &&
         entry->state.handshake == NULL))
        return;
    baseline_lru_unlink(runtime, entry);
    size_t index = entry_index(runtime, entry);
    entry->baseline_lru_linked = true;
    entry->baseline_lru_previous = SIZE_MAX;
    entry->baseline_lru_next = runtime->baseline_lru_head;
    if (runtime->baseline_lru_head != SIZE_MAX)
        runtime->entries[
            runtime->baseline_lru_head].baseline_lru_previous = index;
    else
        runtime->baseline_lru_tail = index;
    runtime->baseline_lru_head = index;
}

static void release_expensive_state(
    struct fk_native_flowkeep *runtime,
    struct native_flow_entry *entry);
static void audit_hard_budget(struct fk_native_flowkeep *runtime);
static bool ensure_history(
    struct fk_native_flowkeep *runtime,
    struct native_flow_entry *entry);
static bool ensure_handshake(
    struct fk_native_flowkeep *runtime,
    struct native_flow_entry *entry);

static bool reserve_baseline_state(
        struct fk_native_flowkeep *runtime,
        struct native_flow_entry *incoming,
        enum fk_native_lifecycle lifecycle) {
    uint64_t required = incremental_state_bytes(lifecycle);
    runtime->stats.hard_budget_checks++;
    refresh_owned_bytes(runtime);
    uint64_t combined = runtime->stats.owned_bytes >
            UINT64_MAX - runtime->external_owned_bytes
        ? UINT64_MAX
        : runtime->stats.owned_bytes + runtime->external_owned_bytes;
    if (required == 0u ||
        (combined <= runtime->controlled_budget_bytes &&
         required <= runtime->controlled_budget_bytes - combined))
        return true;
    if (runtime->method == FK_NATIVE_STATE_FIXED_TTL) {
        runtime->stats.hard_budget_rejects++;
        return false;
    }
    struct native_flow_entry *victim =
        runtime->baseline_lru_tail == SIZE_MAX
        ? NULL : &runtime->entries[runtime->baseline_lru_tail];
    if (victim == NULL) {
        runtime->stats.replacement_failures++;
        runtime->stats.hard_budget_rejects++;
        return false;
    }
    incoming->evicted_flow_hash = fk_flow_key_hash(&victim->key);
    incoming->evicted_lifecycle = (uint32_t)victim->lifecycle;
    release_expensive_state(runtime, victim);
    runtime->stats.bounded_candidate_scans++;
    runtime->stats.expensive_replacements++;
    refresh_owned_bytes(runtime);
    combined = runtime->stats.owned_bytes >
            UINT64_MAX - runtime->external_owned_bytes
        ? UINT64_MAX
        : runtime->stats.owned_bytes + runtime->external_owned_bytes;
    if (combined > runtime->controlled_budget_bytes ||
        required > runtime->controlled_budget_bytes - combined) {
        runtime->stats.hard_budget_rejects++;
        return false;
    }
    return true;
}

static void baseline_transition(
        struct fk_native_flowkeep *runtime,
        struct native_flow_entry *entry,
        const struct fk_packet_view *view) {
    if (!is_budget_baseline(runtime->method))
        return;
    uint64_t packets = entry->state.summary.packets;
    bool review =
        runtime->method == FK_NATIVE_STATE_PROTOCOL_DEADLINE &&
        runtime->pressure_level >= 1u &&
        (entry->lifecycle == FK_NATIVE_HIST ||
         entry->lifecycle == FK_NATIVE_HS ||
         entry->lifecycle == FK_NATIVE_FULL);
    if (review) {
        release_expensive_state(runtime, entry);
        entry->retention_action = FK_NATIVE_ACTION_PRESSURE_DOWNGRADE;
        runtime->stats.pressure_summary_downgrades++;
        audit_hard_budget(runtime);
        return;
    }
    if (runtime->method == FK_NATIVE_STATE_FIXED_TTL &&
        runtime->fixed_ttl_ns > 0u &&
        view != NULL &&
        entry->last_timestamp_ns >= entry->first_timestamp_ns &&
        entry->last_timestamp_ns - entry->first_timestamp_ns >=
            runtime->fixed_ttl_ns) {
        if (entry->state.history != NULL ||
            entry->state.handshake != NULL)
            release_expensive_state(runtime, entry);
        entry->baseline_ttl_expired = true;
        return;
    }
    if (entry->baseline_ttl_expired ||
        entry->lifecycle != FK_NATIVE_BOOTSTRAP ||
        packets < FK_NATIVE_BOOTSTRAP_PACKETS)
        return;
    enum fk_native_lifecycle next = FK_NATIVE_SUMMARY;
    bool tls = tls_candidate(view);
    if (runtime->method == FK_NATIVE_STATE_LRU ||
        runtime->method == FK_NATIVE_STATE_FIXED_TTL)
        next = FK_NATIVE_FULL;
    else if (runtime->method == FK_NATIVE_STATE_HANDSHAKE_ONLY)
        next = tls ? FK_NATIVE_HS : FK_NATIVE_SUMMARY;
    else
        next = tls ? FK_NATIVE_HS : FK_NATIVE_HIST;
    if (runtime->method == FK_NATIVE_STATE_PROTOCOL_DEADLINE &&
        runtime->pressure_level >= 1u)
        next = FK_NATIVE_SUMMARY;
    if (next != FK_NATIVE_SUMMARY &&
        !reserve_baseline_state(runtime, entry, next)) {
        entry->retention_action = FK_NATIVE_ACTION_BUDGET_DOWNGRADE;
        next = FK_NATIVE_SUMMARY;
    } else if (next == FK_NATIVE_HIST) {
        if (!ensure_history(runtime, entry))
            next = FK_NATIVE_SUMMARY;
    } else if (next == FK_NATIVE_HS) {
        if (!ensure_handshake(runtime, entry))
            next = FK_NATIVE_SUMMARY;
    } else if (next == FK_NATIVE_FULL) {
        bool history = ensure_history(runtime, entry);
        bool handshake = history && ensure_handshake(runtime, entry);
        if (!history || !handshake) {
            release_expensive_state(runtime, entry);
            next = FK_NATIVE_SUMMARY;
        }
    }
    entry->lifecycle = next;
    baseline_lru_touch(runtime, entry);
    runtime->stats.state_transitions[next]++;
    audit_hard_budget(runtime);
}

static void release_expensive_state(
        struct fk_native_flowkeep *runtime,
        struct native_flow_entry *entry) {
    baseline_lru_unlink(runtime, entry);
    if (entry->state.history != NULL) {
        free(entry->state.history);
        entry->state.history = NULL;
        runtime->allocated_histories--;
    }
    if (entry->state.handshake != NULL) {
        free(entry->state.handshake);
        entry->state.handshake = NULL;
        runtime->allocated_handshakes--;
    }
    entry->lifecycle = FK_NATIVE_SUMMARY;
    entry->retention_value = 0.0f;
    runtime->stats.state_transitions[FK_NATIVE_SUMMARY]++;
    refresh_owned_bytes(runtime);
}

static bool reserve_with_bounded_replacement(
        struct fk_native_flowkeep *runtime,
        enum fk_native_lifecycle lifecycle,
        float incoming_value,
        uint32_t *action,
        uint64_t *evicted_flow_hash,
        float *evicted_retention_value,
        uint32_t *evicted_lifecycle) {
    uint64_t required = incremental_state_bytes(lifecycle);
    runtime->stats.hard_budget_checks++;
    refresh_owned_bytes(runtime);
    uint64_t combined = runtime->stats.owned_bytes >
            UINT64_MAX - runtime->external_owned_bytes
        ? UINT64_MAX
        : runtime->stats.owned_bytes + runtime->external_owned_bytes;
    if (required == 0u || runtime->controlled_budget_bytes == 0u ||
        (combined <= runtime->controlled_budget_bytes &&
         required <= runtime->controlled_budget_bytes - combined))
        return true;

    struct native_flow_entry *victim = NULL;
    float victim_value = incoming_value;
    uint32_t scanned = 0u;
    uint32_t limit = runtime->replacement_candidates;
    if (limit == 0u)
        limit = FK_NATIVE_DEFAULT_REPLACEMENT_CANDIDATES;
    for (uint32_t offset = 0u;
         offset < limit && offset < runtime->capacity; ++offset) {
        size_t index =
            (runtime->replacement_cursor + offset) &
            (runtime->capacity - 1u);
        struct native_flow_entry *candidate =
            &runtime->entries[index];
        scanned++;
        if (!candidate->used ||
            (candidate->lifecycle != FK_NATIVE_HIST &&
             candidate->lifecycle != FK_NATIVE_HS))
            continue;
        if (candidate->retention_value < victim_value) {
            victim = candidate;
            victim_value = candidate->retention_value;
        }
    }
    runtime->replacement_cursor =
        (runtime->replacement_cursor + scanned) &
        (runtime->capacity - 1u);
    runtime->stats.bounded_candidate_scans += scanned;
    if (victim == NULL ||
        incremental_state_bytes(victim->lifecycle) < required) {
        runtime->stats.replacement_failures++;
        runtime->stats.hard_budget_rejects++;
        return false;
    }
    enum fk_native_lifecycle victim_lifecycle = victim->lifecycle;
    *evicted_flow_hash = fk_flow_key_hash(&victim->key);
    *evicted_retention_value = victim->retention_value;
    *evicted_lifecycle = (uint32_t)victim_lifecycle;
    release_expensive_state(runtime, victim);
    runtime->stats.expensive_replacements++;
    *action = victim_lifecycle == FK_NATIVE_HIST
        ? FK_NATIVE_ACTION_REPLACE_HISTORY
        : FK_NATIVE_ACTION_REPLACE_HANDSHAKE;
    refresh_owned_bytes(runtime);
    combined = runtime->stats.owned_bytes >
            UINT64_MAX - runtime->external_owned_bytes
        ? UINT64_MAX
        : runtime->stats.owned_bytes + runtime->external_owned_bytes;
    if (combined > runtime->controlled_budget_bytes ||
        required > runtime->controlled_budget_bytes -
            combined) {
        runtime->stats.hard_budget_rejects++;
        return false;
    }
    return true;
}

static void audit_hard_budget(struct fk_native_flowkeep *runtime) {
    refresh_owned_bytes(runtime);
    uint64_t combined = runtime->stats.owned_bytes >
            UINT64_MAX - runtime->external_owned_bytes
        ? UINT64_MAX
        : runtime->stats.owned_bytes + runtime->external_owned_bytes;
    if (runtime->controlled_budget_bytes != 0u &&
        combined > runtime->controlled_budget_bytes)
        runtime->stats.hard_budget_violations++;
}

static bool ensure_style(
        struct fk_native_flowkeep *runtime,
        struct native_flow_entry *entry) {
    size_t bytes = 0u;
    switch (runtime->method) {
    case FK_NATIVE_STATE_NETBEACON:
        bytes = sizeof(struct netbeacon_style_state);
        break;
    case FK_NATIVE_STATE_SPLIDT:
        bytes = sizeof(struct splidt_style_state);
        break;
    case FK_NATIVE_STATE_OCTOSKETCH:
        bytes = sizeof(struct octosketch_style_state);
        break;
    case FK_NATIVE_STATE_FLM:
        bytes = sizeof(struct flm_style_state);
        break;
    default:
        return true;
    }
    entry->state.style = calloc(1u, bytes);
    if (entry->state.style == NULL)
        return false;
    entry->state.style_bytes = (uint32_t)bytes;
    runtime->allocated_style_bytes += bytes;
    return true;
}

static bool ensure_history(
        struct fk_native_flowkeep *runtime,
        struct native_flow_entry *entry) {
    if (entry->state.history != NULL)
        return true;
    entry->state.history = calloc(1u, sizeof(*entry->state.history));
    if (entry->state.history == NULL)
        return false;
    runtime->allocated_histories++;
    return true;
}

static bool ensure_handshake(
        struct fk_native_flowkeep *runtime,
        struct native_flow_entry *entry) {
    if (entry->state.handshake != NULL)
        return true;
    entry->state.handshake = calloc(1u, sizeof(*entry->state.handshake));
    if (entry->state.handshake == NULL)
        return false;
    runtime->allocated_handshakes++;
    return true;
}

static void release_entry(
        struct fk_native_flowkeep *runtime,
        struct native_flow_entry *entry,
        bool terminal) {
    if (!entry->used)
        return;
    baseline_lru_unlink(runtime, entry);
    if (entry->state.history != NULL) {
        free(entry->state.history);
        runtime->allocated_histories--;
    }
    if (entry->state.handshake != NULL) {
        free(entry->state.handshake);
        runtime->allocated_handshakes--;
    }
    if (entry->state.style != NULL) {
        free(entry->state.style);
        runtime->allocated_style_bytes -= entry->state.style_bytes;
    }
    memset(entry, 0, sizeof(*entry));
    entry->tombstone = true;
    runtime->stats.active_flows--;
    if (terminal)
        runtime->stats.terminal_releases++;
    else
        runtime->stats.idle_releases++;
    runtime->stats.state_transitions[FK_NATIVE_RELEASED]++;
    refresh_owned_bytes(runtime);
}

static struct native_flow_entry *find_entry(
        struct fk_native_flowkeep *runtime,
        const struct fk_flow_key *key) {
    size_t mask = runtime->capacity - 1u;
    size_t start = (size_t)fk_flow_key_hash(key) & mask;
    for (size_t probe = 0u; probe < runtime->capacity; ++probe) {
        struct native_flow_entry *entry =
            &runtime->entries[(start + probe) & mask];
        if (!entry->used && !entry->tombstone)
            return NULL;
        if (fk_flow_key_equal(&entry->key, key))
            return entry;
    }
    return NULL;
}

static struct native_flow_entry *create_entry(
        struct fk_native_flowkeep *runtime,
        const struct fk_flow_key *key,
        uint64_t timestamp_ns) {
    if (runtime->stats.active_flows >= runtime->maximum_flows) {
        runtime->stats.flow_table_full++;
        return NULL;
    }
    size_t mask = runtime->capacity - 1u;
    size_t start = (size_t)fk_flow_key_hash(key) & mask;
    struct native_flow_entry *available = NULL;
    for (size_t probe = 0u; probe < runtime->capacity; ++probe) {
        struct native_flow_entry *entry =
            &runtime->entries[(start + probe) & mask];
        if (entry->used)
            continue;
        if (entry->tombstone) {
            if (available == NULL)
                available = entry;
            continue;
        }
        available = available == NULL ? entry : available;
        break;
    }
    if (available != NULL) {
        struct native_flow_entry *entry = available;
        memset(entry, 0, sizeof(*entry));
        entry->used = true;
        entry->key = *key;
        entry->first_timestamp_ns = timestamp_ns;
        entry->last_timestamp_ns = timestamp_ns;
        entry->lifecycle = fixed_lifecycle(runtime->method);
        if ((runtime->method == FK_NATIVE_STATE_HISTORY ||
             runtime->method == FK_NATIVE_STATE_FLM ||
             runtime->method == FK_NATIVE_STATE_FULL) &&
            !ensure_history(runtime, entry)) {
            memset(entry, 0, sizeof(*entry));
            return NULL;
        }
        if ((runtime->method == FK_NATIVE_STATE_HANDSHAKE ||
             runtime->method == FK_NATIVE_STATE_FULL) &&
            !ensure_handshake(runtime, entry)) {
            if (entry->state.history != NULL) {
                free(entry->state.history);
                runtime->allocated_histories--;
            }
            memset(entry, 0, sizeof(*entry));
            return NULL;
        }
        if (!ensure_style(runtime, entry)) {
            if (entry->state.history != NULL) {
                free(entry->state.history);
                runtime->allocated_histories--;
            }
            if (entry->state.handshake != NULL) {
                free(entry->state.handshake);
                runtime->allocated_handshakes--;
            }
            memset(entry, 0, sizeof(*entry));
            return NULL;
        }
        runtime->stats.flows_created++;
        runtime->stats.active_flows++;
        if (runtime->stats.active_flows >
            runtime->stats.peak_active_flows)
            runtime->stats.peak_active_flows =
                runtime->stats.active_flows;
        runtime->stats.state_transitions[entry->lifecycle]++;
        refresh_owned_bytes(runtime);
        return entry;
    }
    runtime->stats.flow_table_full++;
    return NULL;
}

static void heuristic_transition(
        struct fk_native_flowkeep *runtime,
        struct native_flow_entry *entry,
        const struct fk_packet_view *view) {
    if (runtime->method != FK_NATIVE_STATE_FLOWKEEP_HEURISTIC ||
        entry->lifecycle != FK_NATIVE_BOOTSTRAP ||
        entry->state.summary.packets < FK_NATIVE_BOOTSTRAP_PACKETS)
        return;
    enum fk_native_lifecycle next = FK_NATIVE_SUMMARY;
    if (!runtime->impact_enabled) {
        entry->lifecycle = next;
        runtime->stats.impact_neutral_transitions++;
        runtime->stats.state_transitions[next]++;
        refresh_owned_bytes(runtime);
        return;
    }
    bool handshake =
        view->l4_protocol == 6u &&
        (view->src_port == 443u || view->dst_port == 443u ||
         view->src_port == 853u || view->dst_port == 853u ||
         view->src_port == 8443u || view->dst_port == 8443u);
    if (handshake) {
        if (runtime->pressure_level >= 1u) {
            runtime->stats.pressure_summary_downgrades++;
        } else if (runtime->allocated_handshakes >=
                   runtime->handshake_budget) {
            runtime->stats.handshake_budget_downgrades++;
        } else {
            next = FK_NATIVE_HS;
        }
        if (next == FK_NATIVE_HS &&
            !ensure_handshake(runtime, entry))
            next = FK_NATIVE_SUMMARY;
    } else if (entry->state.summary.maximum_wire_size >= 1200u) {
        if (runtime->pressure_level >= 1u) {
            runtime->stats.pressure_summary_downgrades++;
        } else if (runtime->allocated_histories >=
                   runtime->history_budget) {
            runtime->stats.history_budget_downgrades++;
        } else {
            next = FK_NATIVE_HIST;
        }
        if (next == FK_NATIVE_HIST &&
            !ensure_history(runtime, entry))
            next = FK_NATIVE_SUMMARY;
    }
    entry->lifecycle = next;
    runtime->stats.state_transitions[next]++;
    refresh_owned_bytes(runtime);
}

static void value_transition(
        struct fk_native_flowkeep *runtime,
        struct native_flow_entry *entry,
        const struct fk_packet_view *view) {
    if (runtime->method != FK_NATIVE_STATE_FLOWKEEP)
        return;
    uint64_t packets = entry->state.summary.packets;
    bool bootstrap_decision =
        entry->lifecycle == FK_NATIVE_BOOTSTRAP &&
        packets >= FK_NATIVE_BOOTSTRAP_PACKETS;
    bool future_reconsideration =
        entry->lifecycle == FK_NATIVE_SUMMARY &&
        (packets == 8u || packets == FK_NATIVE_HISTORY_PACKETS);
    bool pressure_review =
        (entry->lifecycle == FK_NATIVE_HIST ||
         entry->lifecycle == FK_NATIVE_HS) &&
        runtime->pressure_level >= 1u &&
        packets % 8u == 0u;
    if (!bootstrap_decision && !future_reconsideration &&
        !pressure_review)
        return;
    entry->budget_before = runtime->stats.owned_bytes;
    entry->retention_action = FK_NATIVE_ACTION_KEEP_SUMMARY;
    if (!runtime->impact_enabled) {
        entry->lifecycle = FK_NATIVE_SUMMARY;
        entry->retention_action = FK_NATIVE_ACTION_IMPACT_DISABLED;
        runtime->stats.impact_neutral_transitions++;
        runtime->stats.state_transitions[FK_NATIVE_SUMMARY]++;
        entry->budget_after = runtime->stats.owned_bytes;
        return;
    }
    if (!runtime->value_model_configured) {
        entry->lifecycle = FK_NATIVE_SUMMARY;
        entry->retention_action = FK_NATIVE_ACTION_MODEL_UNAVAILABLE;
        runtime->stats.model_unavailable_downgrades++;
        runtime->stats.state_transitions[FK_NATIVE_SUMMARY]++;
        entry->budget_after = runtime->stats.owned_bytes;
        return;
    }

    float features[FK_NATIVE_VALUE_FEATURES];
    online_value_features(runtime, entry, view, features);
    memcpy(
        entry->retention_features,
        features,
        sizeof(entry->retention_features));
    entry->available_features_hash = online_feature_hash(features);
    float history_value =
        retention_value(runtime, VALUE_HISTORY, features);
    float handshake_value = tls_candidate(view)
        ? retention_value(runtime, VALUE_HANDSHAKE, features)
        : -1.0f;
    float margin = runtime->pressure_level == 2u
        ? runtime->value_model.overload_margin :
        runtime->pressure_level == 1u
        ? runtime->value_model.pressure_margin : 0.0f;
    if (pressure_review) {
        enum value_state_index current =
            entry->lifecycle == FK_NATIVE_HIST
            ? VALUE_HISTORY : VALUE_HANDSHAKE;
        float current_value = current == VALUE_HISTORY
            ? history_value : handshake_value;
        if (current_value <
                runtime->value_model.threshold[current] + margin) {
            release_expensive_state(runtime, entry);
            entry->retention_action =
                FK_NATIVE_ACTION_PRESSURE_DOWNGRADE;
            entry->budget_after = runtime->stats.owned_bytes;
        } else {
            entry->retention_value = current_value;
            entry->retention_action = current == VALUE_HISTORY
                ? FK_NATIVE_ACTION_KEEP_HISTORY
                : FK_NATIVE_ACTION_KEEP_HANDSHAKE;
            entry->budget_after = runtime->stats.owned_bytes;
        }
        audit_hard_budget(runtime);
        return;
    }
    bool history_eligible =
        history_value >= runtime->value_model.threshold[VALUE_HISTORY] +
            margin;
    bool handshake_eligible =
        handshake_value >=
            runtime->value_model.threshold[VALUE_HANDSHAKE] + margin;
    enum fk_native_lifecycle next = FK_NATIVE_SUMMARY;
    float selected_value = 0.0f;
    if (handshake_eligible &&
        (!history_eligible || handshake_value >= history_value)) {
        next = FK_NATIVE_HS;
        selected_value = handshake_value;
    } else if (history_eligible) {
        next = FK_NATIVE_HIST;
        selected_value = history_value;
    }
    if (next == FK_NATIVE_SUMMARY) {
        if (runtime->pressure_level >= 1u)
            entry->retention_action =
                FK_NATIVE_ACTION_PRESSURE_DOWNGRADE;
    } else {
        uint32_t action = next == FK_NATIVE_HIST
            ? FK_NATIVE_ACTION_KEEP_HISTORY
            : FK_NATIVE_ACTION_KEEP_HANDSHAKE;
        if (!reserve_with_bounded_replacement(
                runtime,
                next,
                selected_value,
                &action,
                &entry->evicted_flow_hash,
                &entry->evicted_retention_value,
                &entry->evicted_lifecycle)) {
            if (next == FK_NATIVE_HIST)
                runtime->stats.history_budget_downgrades++;
            else
                runtime->stats.handshake_budget_downgrades++;
            entry->retention_action =
                FK_NATIVE_ACTION_BUDGET_DOWNGRADE;
            next = FK_NATIVE_SUMMARY;
            selected_value = 0.0f;
        } else {
            bool allocated = next == FK_NATIVE_HIST
                ? ensure_history(runtime, entry)
                : ensure_handshake(runtime, entry);
            if (!allocated) {
                entry->retention_action =
                    FK_NATIVE_ACTION_BUDGET_DOWNGRADE;
                next = FK_NATIVE_SUMMARY;
                selected_value = 0.0f;
            } else {
                entry->retention_action = action;
                if (next == FK_NATIVE_HIST)
                    runtime->stats.value_history_selections++;
                else
                    runtime->stats.value_handshake_selections++;
            }
        }
    }
    entry->lifecycle = next;
    entry->retention_value = selected_value;
    runtime->stats.state_transitions[next]++;
    audit_hard_budget(runtime);
    entry->budget_after = runtime->stats.owned_bytes;
}

void fk_native_flowkeep_set_pressure(
        struct fk_native_flowkeep *runtime,
        uint32_t pressure_level) {
    if (runtime == NULL)
        return;
    runtime->pressure_level = pressure_level > 2u ? 2u : pressure_level;
}

static void update_entry(
        struct fk_native_flowkeep *runtime,
        struct native_flow_entry *entry,
        uint64_t timestamp_ns,
        const struct fk_packet_view *view,
        uint8_t direction) {
    uint64_t previous_timestamp_ns = entry->last_timestamp_ns;
    if (runtime->method == FK_NATIVE_STATE_FLOWKEEP) {
        entry->retention_action = FK_NATIVE_ACTION_NONE;
        entry->budget_before = runtime->stats.owned_bytes;
        entry->budget_after = runtime->stats.owned_bytes;
        entry->evicted_flow_hash = 0u;
        entry->evicted_retention_value = 0.0f;
        entry->evicted_lifecycle = 0u;
    }
    struct summary_state *summary = &entry->state.summary;
    summary->packets++;
    summary->bytes += view->wire_size;
    summary->direction_packets[direction]++;
    summary->direction_bytes[direction] += view->wire_size;
    if (summary->minimum_wire_size == 0u ||
        view->wire_size < summary->minimum_wire_size)
        summary->minimum_wire_size = view->wire_size;
    if (view->wire_size > summary->maximum_wire_size)
        summary->maximum_wire_size = view->wire_size;
    entry->last_timestamp_ns = timestamp_ns;
    if (summary->packets <= FK_NATIVE_BOOTSTRAP_PACKETS) {
        uint32_t bootstrap_index = (uint32_t)summary->packets - 1u;
        entry->bootstrap_wire_size[bootstrap_index] = view->wire_size;
        entry->bootstrap_payload_size[bootstrap_index] =
            view->payload_size;
        entry->bootstrap_timestamp_ns[bootstrap_index] = timestamp_ns;
        entry->bootstrap_direction[bootstrap_index] = direction;
    }

    heuristic_transition(runtime, entry, view);
    baseline_transition(runtime, entry, view);
    value_transition(runtime, entry, view);
    if (entry->state.history != NULL) {
        struct history_state *history = entry->state.history;
        struct fk_native_packet_metadata *metadata =
            &history->packets[history->next];
        metadata->wire_size = view->wire_size;
        metadata->payload_size = view->payload_size;
        uint64_t delta_ns = timestamp_ns >= previous_timestamp_ns
            ? timestamp_ns - previous_timestamp_ns : 0u;
        metadata->delta_time_us = delta_ns / 1000u > UINT32_MAX
            ? UINT32_MAX : (uint32_t)(delta_ns / 1000u);
        metadata->tcp_window = view->tcp_window;
        metadata->direction = direction;
        metadata->tcp_flags = view->tcp_flags;
        history->next =
            (history->next + 1u) % FK_NATIVE_HISTORY_PACKETS;
        if (history->count < FK_NATIVE_HISTORY_PACKETS)
            history->count++;
    }
    if (entry->state.handshake != NULL && view->payload_size > 0u) {
        struct handshake_state *handshake = entry->state.handshake;
        uint32_t available =
            handshake->retained_bytes >= 8192u
            ? 0u : 8192u - handshake->retained_bytes;
        uint32_t retained =
            view->payload_size < available ? view->payload_size : available;
        handshake->retained_bytes += retained;
        if (retained < view->payload_size)
            handshake->cap_exceeded++;
    }
    baseline_lru_touch(runtime, entry);
    if (runtime->method == FK_NATIVE_STATE_NETBEACON) {
        static const uint64_t stages[] = {4u, 8u, 16u, 32u};
        struct netbeacon_style_state *style = entry->state.style;
        if (style->next_stage < 4u &&
            summary->packets == stages[style->next_stage])
            style->next_stage++;
    } else if (runtime->method == FK_NATIVE_STATE_SPLIDT) {
        struct splidt_style_state *style = entry->state.style;
        if ((view->tcp_flags & FK_TCP_FLAG_SYN) != 0u)
            style->tcp_syn_count++;
        if ((view->tcp_flags &
             (FK_TCP_FLAG_FIN | FK_TCP_FLAG_RST)) != 0u)
            style->tcp_fin_rst_count++;
    } else if (runtime->method == FK_NATIVE_STATE_OCTOSKETCH) {
        struct octosketch_style_state *style = entry->state.style;
        uint64_t seed = summary->packets ^ ((uint64_t)view->wire_size << 17u);
        for (uint32_t depth = 0u; depth < 8u; ++depth) {
            uint32_t bucket = (uint32_t)(
                (seed * (0x9e3779b97f4a7c15ull + depth * 2u)) >> 59u);
            if (style->counters[depth][bucket] != UINT8_MAX)
                style->counters[depth][bucket]++;
        }
    } else if (runtime->method == FK_NATIVE_STATE_FLM) {
        struct flm_style_state *style = entry->state.style;
        if (style->count < 32u) {
            struct fk_native_packet_metadata *token =
                &style->tokens[style->count++];
            token->wire_size = view->wire_size;
            token->payload_size = view->payload_size;
            token->direction = direction;
            token->tcp_flags = view->tcp_flags;
        }
    }
}

static void fill_snapshot(
        const struct native_flow_entry *entry,
        struct fk_native_flow_snapshot *snapshot) {
    if (snapshot == NULL)
        return;
    memset(snapshot, 0, sizeof(*snapshot));
    snapshot->key = entry->key;
    snapshot->first_timestamp_ns = entry->first_timestamp_ns;
    snapshot->last_timestamp_ns = entry->last_timestamp_ns;
    snapshot->packets = entry->state.summary.packets;
    snapshot->bytes = entry->state.summary.bytes;
    memcpy(
        snapshot->direction_packets,
        entry->state.summary.direction_packets,
        sizeof(snapshot->direction_packets));
    memcpy(
        snapshot->direction_bytes,
        entry->state.summary.direction_bytes,
        sizeof(snapshot->direction_bytes));
    snapshot->minimum_wire_size =
        entry->state.summary.minimum_wire_size;
    snapshot->maximum_wire_size =
        entry->state.summary.maximum_wire_size;
    snapshot->history_count = entry->state.history == NULL
        ? 0u : entry->state.history->count;
    if (entry->state.history != NULL) {
        const struct history_state *history = entry->state.history;
        uint32_t start = history->count < FK_NATIVE_HISTORY_PACKETS
            ? 0u : history->next;
        for (uint32_t index = 0u; index < history->count; ++index) {
            snapshot->history[index] = history->packets[
                (start + index) % FK_NATIVE_HISTORY_PACKETS
            ];
        }
    }
    snapshot->handshake_bytes = entry->state.handshake == NULL
        ? 0u : entry->state.handshake->retained_bytes;
    snapshot->retention_value = entry->retention_value;
    snapshot->retention_action = entry->retention_action;
    snapshot->budget_before = entry->budget_before;
    snapshot->budget_after = entry->budget_after;
    snapshot->available_features_hash =
        entry->available_features_hash;
    snapshot->value_model_version =
        entry->available_features_hash == 0u
        ? 0u : FK_NATIVE_VALUE_MODEL_VERSION;
    memcpy(
        snapshot->retention_features,
        entry->retention_features,
        sizeof(snapshot->retention_features));
    snapshot->evicted_flow_hash = entry->evicted_flow_hash;
    snapshot->evicted_retention_value =
        entry->evicted_retention_value;
    snapshot->evicted_lifecycle = entry->evicted_lifecycle;
    snapshot->lifecycle = entry->lifecycle;
}

struct fk_native_flowkeep *fk_native_flowkeep_create(
        enum fk_native_state_method method,
        uint32_t maximum_flows,
        uint64_t idle_timeout_ns) {
    if (method < FK_NATIVE_STATE_SUMMARY ||
        method > FK_NATIVE_STATE_HANDSHAKE_ONLY ||
        maximum_flows == 0u || maximum_flows > 1048576u)
        return NULL;
    struct fk_native_flowkeep *runtime =
        calloc(1u, sizeof(*runtime));
    if (runtime == NULL)
        return NULL;
    size_t target = (size_t)maximum_flows * 2u;
    size_t capacity = 2u;
    while (capacity < target)
        capacity *= 2u;
    runtime->entries = calloc(capacity, sizeof(*runtime->entries));
    if (runtime->entries == NULL) {
        free(runtime);
        return NULL;
    }
    runtime->method = method;
    runtime->maximum_flows = maximum_flows;
    runtime->idle_timeout_ns = idle_timeout_ns;
    runtime->impact_enabled = true;
    runtime->lease_enabled = true;
    runtime->baseline_lru_head = SIZE_MAX;
    runtime->baseline_lru_tail = SIZE_MAX;
    /* Each expensive class is independently bounded; Summary remains the
     * fail-safe representation when either budget is exhausted. */
    runtime->history_budget = maximum_flows / 4u;
    runtime->handshake_budget = maximum_flows / 4u;
    if (runtime->history_budget == 0u)
        runtime->history_budget = 1u;
    if (runtime->handshake_budget == 0u)
        runtime->handshake_budget = 1u;
    runtime->capacity = capacity;
    runtime->replacement_candidates =
        FK_NATIVE_DEFAULT_REPLACEMENT_CANDIDATES;
    refresh_owned_bytes(runtime);
    return runtime;
}

static bool valid_value_model(
        const struct fk_native_value_model *model) {
    if (model == NULL ||
        (model->version != FK_NATIVE_VALUE_MODEL_VERSION &&
         model->version != FK_NATIVE_VALUE_MODEL_LINEAR_VERSION) ||
        model->feature_count != FK_NATIVE_VALUE_FEATURES ||
        !isfinite(model->pressure_margin) ||
        !isfinite(model->overload_margin) ||
        model->pressure_margin < 0.0f ||
        model->overload_margin < model->pressure_margin)
        return false;
    for (uint32_t state = 0u; state < 2u; ++state) {
        if (!isfinite(model->intercept[state]) ||
            !isfinite(model->threshold[state]) ||
            !isfinite(model->state_cost_penalty[state]) ||
            model->threshold[state] < 0.0f ||
            model->threshold[state] > 1.0f ||
            model->state_cost_penalty[state] < 0.0f ||
            model->state_cost_penalty[state] >= 1.0f)
            return false;
        for (uint32_t feature = 0u;
             feature < FK_NATIVE_VALUE_FEATURES; ++feature) {
            if (!isfinite(model->weights[state][feature]))
                return false;
        }
        if (model->version == FK_NATIVE_VALUE_MODEL_VERSION) {
            if (!isfinite(model->gate_threshold[state]) ||
                model->gate_threshold[state] < 0.0f ||
                model->gate_threshold[state] > 1.0f ||
                !isfinite(model->ranker_bias[state]) ||
                !isfinite(model->ranker_learning_rate[state]) ||
                model->ranker_learning_rate[state] <= 0.0f ||
                model->ranker_tree_count[state] == 0u ||
                model->ranker_tree_count[state] >
                    FK_NATIVE_VALUE_MAX_TREES)
                return false;
            for (uint32_t tree = 0u;
                 tree < model->ranker_tree_count[state]; ++tree) {
                const struct fk_native_value_tree *ranker_tree =
                    &model->ranker_trees[state][tree];
                if (ranker_tree->node_count == 0u ||
                    ranker_tree->node_count >
                        FK_NATIVE_VALUE_MAX_TREE_NODES)
                    return false;
                for (uint32_t node = 0u;
                     node < ranker_tree->node_count; ++node) {
                    const struct fk_native_value_tree_node *item =
                        &ranker_tree->nodes[node];
                    if (item->feature < -1 ||
                        item->feature >=
                            (int16_t)FK_NATIVE_VALUE_FEATURES ||
                        !isfinite(item->threshold) ||
                        !isfinite(item->value))
                        return false;
                    if (item->feature >= 0 &&
                        (item->left < 0 || item->right < 0 ||
                         item->left >=
                            (int16_t)ranker_tree->node_count ||
                         item->right >=
                            (int16_t)ranker_tree->node_count))
                        return false;
                }
            }
        }
    }
    return true;
}

bool fk_native_flowkeep_configure_value_policy(
        struct fk_native_flowkeep *runtime,
        const struct fk_native_value_model *model,
        uint64_t controlled_budget_bytes,
        uint32_t replacement_candidates) {
    if (runtime == NULL ||
        runtime->method != FK_NATIVE_STATE_FLOWKEEP ||
        !valid_value_model(model) ||
        controlled_budget_bytes == 0u)
        return false;
    refresh_owned_bytes(runtime);
    if (runtime->stats.owned_bytes > controlled_budget_bytes ||
        runtime->external_owned_bytes >
            controlled_budget_bytes - runtime->stats.owned_bytes)
        return false;
    runtime->value_model = *model;
    runtime->controlled_budget_bytes = controlled_budget_bytes;
    runtime->replacement_candidates = replacement_candidates == 0u
        ? FK_NATIVE_DEFAULT_REPLACEMENT_CANDIDATES
        : replacement_candidates;
    runtime->value_model_configured = true;
    runtime->stats.controlled_budget_bytes = controlled_budget_bytes;
    audit_hard_budget(runtime);
    return runtime->stats.hard_budget_violations == 0u;
}

bool fk_native_flowkeep_configure_budget_policy(
        struct fk_native_flowkeep *runtime,
        uint64_t controlled_budget_bytes,
        uint32_t replacement_candidates,
        uint64_t fixed_ttl_ns) {
    if (runtime == NULL ||
        (!is_budget_baseline(runtime->method) &&
         runtime->method != FK_NATIVE_STATE_SUMMARY) ||
        controlled_budget_bytes == 0u)
        return false;
    refresh_owned_bytes(runtime);
    if (runtime->stats.owned_bytes > controlled_budget_bytes ||
        runtime->external_owned_bytes >
            controlled_budget_bytes - runtime->stats.owned_bytes)
        return false;
    runtime->controlled_budget_bytes = controlled_budget_bytes;
    runtime->replacement_candidates = replacement_candidates;
    runtime->fixed_ttl_ns = fixed_ttl_ns;
    runtime->stats.controlled_budget_bytes = controlled_budget_bytes;
    audit_hard_budget(runtime);
    return runtime->stats.hard_budget_violations == 0u;
}

static bool read_named_float(
        FILE *stream,
        const char *expected,
        float *value) {
    char name[64];
    return fscanf(stream, "%63s %f", name, value) == 2 &&
        strcmp(name, expected) == 0;
}

static bool read_named_weights(
        FILE *stream,
        const char *expected,
        float weights[FK_NATIVE_VALUE_FEATURES]) {
    char name[64];
    if (fscanf(stream, "%63s", name) != 1 ||
        strcmp(name, expected) != 0)
        return false;
    for (uint32_t index = 0u;
         index < FK_NATIVE_VALUE_FEATURES; ++index) {
        if (fscanf(stream, "%f", &weights[index]) != 1)
            return false;
    }
    return true;
}

static bool read_ranker(
        FILE *stream,
        const char *prefix,
        enum value_state_index state,
        struct fk_native_value_model *model) {
    char expected[64];
    snprintf(expected, sizeof(expected), "%s_gate_threshold", prefix);
    if (!read_named_float(
            stream, expected, &model->gate_threshold[state]))
        return false;
    snprintf(expected, sizeof(expected), "%s_ranker_bias", prefix);
    if (!read_named_float(stream, expected, &model->ranker_bias[state]))
        return false;
    snprintf(
        expected, sizeof(expected), "%s_ranker_learning_rate", prefix);
    if (!read_named_float(
            stream, expected, &model->ranker_learning_rate[state]))
        return false;
    char name[64];
    unsigned tree_count = 0u;
    snprintf(expected, sizeof(expected), "%s_ranker_tree_count", prefix);
    if (fscanf(stream, "%63s %u", name, &tree_count) != 2 ||
        strcmp(name, expected) != 0 ||
        tree_count == 0u || tree_count > FK_NATIVE_VALUE_MAX_TREES)
        return false;
    model->ranker_tree_count[state] = tree_count;
    snprintf(expected, sizeof(expected), "%s_ranker_tree", prefix);
    for (uint32_t tree = 0u; tree < tree_count; ++tree) {
        unsigned tree_index = 0u;
        unsigned node_count = 0u;
        if (fscanf(
                stream, "%63s %u %u",
                name, &tree_index, &node_count) != 3 ||
            strcmp(name, expected) != 0 || tree_index != tree ||
            node_count == 0u ||
            node_count > FK_NATIVE_VALUE_MAX_TREE_NODES)
            return false;
        model->ranker_trees[state][tree].node_count =
            (uint8_t)node_count;
        for (uint32_t node = 0u; node < node_count; ++node) {
            int feature = 0;
            int left = 0;
            int right = 0;
            float threshold = 0.0f;
            float value = 0.0f;
            if (fscanf(
                    stream, "%d %f %d %d %f",
                    &feature, &threshold, &left, &right, &value) != 5)
                return false;
            struct fk_native_value_tree_node *item =
                &model->ranker_trees[state][tree].nodes[node];
            item->feature = (int16_t)feature;
            item->threshold = threshold;
            item->left = (int16_t)left;
            item->right = (int16_t)right;
            item->value = value;
        }
    }
    return true;
}

bool fk_native_value_model_load(
        const char *path,
        struct fk_native_value_model *model) {
    if (path == NULL || model == NULL) {
        errno = EINVAL;
        return false;
    }
    FILE *stream = fopen(path, "r");
    if (stream == NULL)
        return false;
    struct fk_native_value_model parsed;
    memset(&parsed, 0, sizeof(parsed));
    char magic[64];
    char feature_name[64];
    unsigned version = 0u;
    unsigned feature_count = 0u;
    bool ok =
        fscanf(stream, "%63s %u", magic, &version) == 2 &&
        strcmp(magic, "FLOWKEEP_VALUE_MODEL") == 0 &&
        fscanf(stream, "%63s %u", feature_name, &feature_count) == 2 &&
        strcmp(feature_name, "feature_count") == 0;
    parsed.version = version;
    parsed.feature_count = feature_count;
    ok = ok && read_named_float(
        stream, "history_intercept", &parsed.intercept[VALUE_HISTORY]);
    ok = ok && read_named_float(
        stream, "history_threshold", &parsed.threshold[VALUE_HISTORY]);
    ok = ok && read_named_weights(
        stream, "history_weights", parsed.weights[VALUE_HISTORY]);
    ok = ok && read_named_float(
        stream, "history_cost_penalty",
        &parsed.state_cost_penalty[VALUE_HISTORY]);
    if (ok && version == FK_NATIVE_VALUE_MODEL_VERSION)
        ok = read_ranker(
            stream, "history", VALUE_HISTORY, &parsed);
    ok = ok && read_named_float(
        stream, "handshake_intercept",
        &parsed.intercept[VALUE_HANDSHAKE]);
    ok = ok && read_named_float(
        stream, "handshake_threshold",
        &parsed.threshold[VALUE_HANDSHAKE]);
    ok = ok && read_named_weights(
        stream, "handshake_weights", parsed.weights[VALUE_HANDSHAKE]);
    ok = ok && read_named_float(
        stream, "handshake_cost_penalty",
        &parsed.state_cost_penalty[VALUE_HANDSHAKE]);
    if (ok && version == FK_NATIVE_VALUE_MODEL_VERSION)
        ok = read_ranker(
            stream, "handshake", VALUE_HANDSHAKE, &parsed);
    ok = ok && read_named_float(
        stream, "pressure_margin", &parsed.pressure_margin);
    ok = ok && read_named_float(
        stream, "overload_margin", &parsed.overload_margin);
    if (fclose(stream) != 0)
        ok = false;
    if (!ok || !valid_value_model(&parsed)) {
        errno = EINVAL;
        return false;
    }
    *model = parsed;
    return true;
}

void fk_native_flowkeep_set_q4_policy(
        struct fk_native_flowkeep *runtime,
        bool impact_enabled,
        bool lease_enabled) {
    if (runtime == NULL)
        return;
    runtime->impact_enabled = impact_enabled;
    runtime->lease_enabled = lease_enabled;
}

void fk_native_flowkeep_set_external_owned_bytes(
        struct fk_native_flowkeep *runtime,
        uint64_t external_owned_bytes) {
    if (runtime == NULL)
        return;
    runtime->external_owned_bytes = external_owned_bytes;
    audit_hard_budget(runtime);
}

void fk_native_flowkeep_destroy(struct fk_native_flowkeep *runtime) {
    if (runtime == NULL)
        return;
    for (size_t index = 0u; index < runtime->capacity; ++index) {
        free(runtime->entries[index].state.history);
        free(runtime->entries[index].state.handshake);
        free(runtime->entries[index].state.style);
    }
    free(runtime->entries);
    free(runtime);
}

bool fk_native_flowkeep_process(
        struct fk_native_flowkeep *runtime,
        uint64_t timestamp_ns,
        const struct fk_packet_view *view,
        struct fk_native_flow_snapshot *snapshot) {
    if (runtime == NULL || view == NULL || view->code != FK_PARSE_OK)
        return false;
    struct fk_flow_key key;
    uint8_t direction = 0u;
    if (fk_native_flow_key(view, &key, &direction) != FK_PARSE_OK)
        return false;
    struct native_flow_entry *entry = find_entry(runtime, &key);
    if (entry == NULL)
        entry = create_entry(runtime, &key, timestamp_ns);
    if (entry == NULL)
        return false;
    runtime->stats.packets_seen++;
    runtime->stats.bytes_seen += view->wire_size;
    update_entry(runtime, entry, timestamp_ns, view, direction);
    fill_snapshot(entry, snapshot);
    bool terminal = false;
    if (view->l4_protocol == 6u) {
        if ((view->tcp_flags & FK_TCP_FLAG_FIN) != 0u)
            entry->fin_seen[direction] = true;
        terminal =
            (view->tcp_flags & FK_TCP_FLAG_RST) != 0u ||
            (entry->fin_seen[0] && entry->fin_seen[1]);
    }
    if (terminal) {
        if (runtime->lease_enabled)
            release_entry(runtime, entry, true);
        else
            runtime->stats.lease_release_suppressed++;
    }
    audit_hard_budget(runtime);
    return true;
}

void fk_native_flowkeep_expire(
        struct fk_native_flowkeep *runtime,
        uint64_t timestamp_ns) {
    if (runtime == NULL || runtime->idle_timeout_ns == 0u)
        return;
    for (size_t index = 0u; index < runtime->capacity; ++index) {
        struct native_flow_entry *entry = &runtime->entries[index];
        if (!entry->used || timestamp_ns < entry->last_timestamp_ns)
            continue;
        if (runtime->method == FK_NATIVE_STATE_FIXED_TTL &&
            !entry->baseline_ttl_expired &&
            runtime->fixed_ttl_ns > 0u &&
            timestamp_ns >= entry->first_timestamp_ns &&
            timestamp_ns - entry->first_timestamp_ns >=
                runtime->fixed_ttl_ns) {
            if (entry->state.history != NULL ||
                entry->state.handshake != NULL)
                release_expensive_state(runtime, entry);
            entry->baseline_ttl_expired = true;
        }
        if (timestamp_ns - entry->last_timestamp_ns >=
            runtime->idle_timeout_ns) {
            if (runtime->lease_enabled)
                release_entry(runtime, entry, false);
            else
                runtime->stats.lease_release_suppressed++;
        }
    }
    audit_hard_budget(runtime);
}

const struct fk_native_flowkeep_stats *fk_native_flowkeep_get_stats(
        const struct fk_native_flowkeep *runtime) {
    return runtime == NULL ? NULL : &runtime->stats;
}

uint64_t fk_native_flowkeep_owned_bytes(
        const struct fk_native_flowkeep *runtime) {
    return runtime == NULL ? 0u : runtime->stats.owned_bytes;
}

const char *fk_native_state_method_name(enum fk_native_state_method method) {
    switch (method) {
    case FK_NATIVE_STATE_SUMMARY:
        return "summary";
    case FK_NATIVE_STATE_HISTORY:
        return "history";
    case FK_NATIVE_STATE_HANDSHAKE:
        return "handshake";
    case FK_NATIVE_STATE_FULL:
        return "full";
    case FK_NATIVE_STATE_FLOWKEEP:
        return "flowkeep";
    case FK_NATIVE_STATE_NETBEACON:
        return "netbeacon";
    case FK_NATIVE_STATE_SPLIDT:
        return "splidt";
    case FK_NATIVE_STATE_OCTOSKETCH:
        return "octosketch";
    case FK_NATIVE_STATE_FLM:
        return "flm";
    case FK_NATIVE_STATE_FLOWKEEP_HEURISTIC:
        return "flowkeep_heuristic";
    case FK_NATIVE_STATE_LRU:
        return "lru";
    case FK_NATIVE_STATE_FIXED_TTL:
        return "fixed_ttl";
    case FK_NATIVE_STATE_PROTOCOL_AWARE:
        return "protocol_aware";
    case FK_NATIVE_STATE_PROTOCOL_DEADLINE:
        return "protocol_deadline";
    case FK_NATIVE_STATE_HANDSHAKE_ONLY:
        return "handshake_only";
    default:
        return "unknown";
    }
}

bool fk_native_state_method_parse(
        const char *text,
        enum fk_native_state_method *method) {
    if (text == NULL || method == NULL)
        return false;
    for (int value = FK_NATIVE_STATE_SUMMARY;
         value <= FK_NATIVE_STATE_HANDSHAKE_ONLY; ++value) {
        enum fk_native_state_method candidate =
            (enum fk_native_state_method)value;
        if (strcmp(text, fk_native_state_method_name(candidate)) == 0) {
            *method = candidate;
            return true;
        }
    }
    return false;
}
