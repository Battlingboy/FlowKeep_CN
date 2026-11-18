#include "fk_compact_runtime.h"
#include "fk_value_model_v3_context.h"
#include "fk_evidence_archive.h"

#include <algorithm>
#include <atomic>
#include <cmath>
#include <cstdio>
#include <cstring>
#include <new>

namespace {

enum class RuntimeApiMode : uint8_t {
    UNSET = 0u,
    V1_ZERO_ID = 1u,
    V2_EXPLICIT_ID = 2u,
};

static_assert(
    static_cast<uint8_t>(RuntimeApiMode::UNSET) ==
            FK_COMPACT_RUNTIME_API_MODE_UNSET &&
    static_cast<uint8_t>(RuntimeApiMode::V1_ZERO_ID) ==
            FK_COMPACT_RUNTIME_API_MODE_V1_ZERO_ID &&
    static_cast<uint8_t>(RuntimeApiMode::V2_EXPLICIT_ID) ==
            FK_COMPACT_RUNTIME_API_MODE_V2_EXPLICIT_ID,
    "internal runtime mode must match the public completeness receipt ABI");

struct CompactRuntime {
    fk_compact_flow_table *table = nullptr;
    fk_cpu_pipeline *pipeline = nullptr;
    fk_compact_release_guard checkpoint_release_guard{};
    fk_compact_runtime_config config{};
    /* Optional-state occupancy and service backlog are independent causal
     * inputs.  Decisions consume their maximum so neither source can clear
     * pressure still asserted by the other source. */
    fk_pressure_mode pressure = FK_PRESSURE_NORMAL;
    fk_pressure_mode automatic_pressure = FK_PRESSURE_NORMAL;
    fk_pressure_mode external_pressure = FK_PRESSURE_NORMAL;
    fk_compact_runtime_stats stats{};
    uint32_t detector_feature_count = 0u;
    bool seven_state_detectors = false;
    bool value_model_v3 = false;
    RuntimeApiMode api_mode = RuntimeApiMode::UNSET;
    fk_compact_flow_open_observation_v2 pending_flow_open{};
    bool flow_open_pending = false;
    fk_compact_detection_request_v2 pending_detection{};
    fk_compact_prefix_callback prefix_callback = nullptr;
    void *prefix_context = nullptr;
    uint32_t prefix_packet_limit = 20u;
    bool detection_pending = false;
    fk_compact_action_record pending_action{};
    bool action_pending = false;
    bool first_packet_coverage = false;
    bool eof_coverage_deposit = false;
    bool adaptive_detection_candidates = false;
    bool marginal_detection_candidates = false;
    uint8_t adaptive_first_packet = 0u;
    uint8_t adaptive_near_gap = 0u;
    uint8_t adaptive_far_gap = 0u;
    uint8_t adaptive_horizon_packet = 0u;
    uint64_t first_packet_coverage_requests = 0u;
    uint64_t semantic_first_timestamp_ns = 0u;
    uint64_t semantic_last_timestamp_ns = 0u;
    long double controlled_state_byte_nanoseconds = 0.0L;
    long double component_byte_nanoseconds[FK_MEMORY_COMPONENT_COUNT]{};
    bool semantic_time_initialized = false;
    bool semantic_time_complete = true;
    bool optional_occupancy_changed_since_pressure_update = false;
    std::atomic<uintptr_t> owner_adapter_token{0u};
    std::atomic<uint32_t> owner_adapter_fixed_owner_plus_one{0u};
    std::atomic<uint64_t> owner_adapter_claim_attempts{0u};
    std::atomic<uint64_t> owner_adapter_claim_successes{0u};
    std::atomic<uint64_t> owner_adapter_claim_rejections{0u};
    std::atomic<uint64_t> owner_adapter_validation_calls{0u};
    std::atomic<uint64_t> owner_adapter_validation_successes{0u};
    std::atomic<uint64_t> owner_adapter_validation_rejections{0u};
    std::atomic<uint64_t> owner_adapter_scope_begin_calls{0u};
    std::atomic<uint64_t> owner_adapter_scope_begin_successes{0u};
    std::atomic<uint64_t> owner_adapter_scope_begin_rejections{0u};
    std::atomic<uint64_t> owner_adapter_scope_end_calls{0u};
    std::atomic<uint64_t> owner_adapter_scope_end_successes{0u};
    std::atomic<uint64_t> owner_adapter_scope_end_rejections{0u};
    std::atomic<uint64_t> owner_adapter_unscoped_mutation_rejections{0u};
    std::atomic<uint64_t>
        owner_adapter_foreign_scope_mutation_rejections{0u};
    std::atomic<uint64_t> owner_adapter_scope_thread_token{0u};
    std::atomic<uint8_t> owner_adapter_scope_active{0u};
};

static CompactRuntime *implementation(fk_compact_runtime *runtime) {
    return reinterpret_cast<CompactRuntime *>(runtime);
}

static const CompactRuntime *implementation(
        const fk_compact_runtime *runtime) {
    return reinterpret_cast<const CompactRuntime *>(runtime);
}

static void set_error(char *error, size_t capacity, const char *message) {
    if (error != nullptr && capacity != 0u)
        std::snprintf(error, capacity, "%s", message);
}

static bool bytes_zero(const uint8_t *bytes, size_t count) {
    if (bytes == nullptr)
        return false;
    for (size_t index = 0u; index < count; ++index) {
        if (bytes[index] != 0u)
            return false;
    }
    return true;
}

static bool flow_key_zero(const fk_flow_key &key) {
    const fk_flow_key zero{};
    return std::memcmp(&key, &zero, sizeof(key)) == 0;
}

static bool intervention_flow_key_valid(
        const fk_flow_key &key,
        uint64_t logical_connection_id) {
    if ((key.ip_version != 4u && key.ip_version != 6u) ||
        (key.protocol != 6u && key.protocol != 17u) ||
        (key.protocol == 6u && logical_connection_id != 0u)) {
        return false;
    }
    const size_t address_bytes = key.ip_version == 4u ? 4u : 16u;
    if (key.ip_version == 4u &&
        (!bytes_zero(key.low_addr + 4u, 12u) ||
         !bytes_zero(key.high_addr + 4u, 12u))) {
        return false;
    }
    const int address_order = std::memcmp(
        key.low_addr, key.high_addr, address_bytes);
    return address_order < 0 ||
        (address_order == 0 && key.low_port <= key.high_port);
}

static bool intervention_victim_zero(
        const fk_compact_checkpoint_intervention_victim_v1 &victim) {
    return flow_key_zero(victim.key) &&
        victim.logical_connection_id == 0u &&
        victim.flow_first_timestamp_ns == 0u &&
        victim.flow_index == 0u && victim.flow_generation == 0u &&
        victim.expected_previous_mask == 0u &&
        victim.expected_behavior_final_mask == 0u &&
        victim.expected_intervention_final_mask == 0u &&
        bytes_zero(victim.reserved, sizeof(victim.reserved));
}

static bool intervention_victim_shape_valid(
        const fk_compact_checkpoint_intervention_victim_v1 &victim,
        uint32_t maximum_flows) {
    const bool key_valid = intervention_flow_key_valid(
        victim.key, victim.logical_connection_id);
    return key_valid && victim.flow_first_timestamp_ns != 0u &&
        victim.flow_index < maximum_flows &&
        victim.flow_generation != 0u &&
        victim.expected_previous_mask <= FK_COMPONENT_FULL &&
        victim.expected_behavior_final_mask <= FK_COMPONENT_FULL &&
        victim.expected_behavior_final_mask !=
            victim.expected_previous_mask &&
        (victim.expected_behavior_final_mask &
             ~victim.expected_previous_mask) == 0u &&
        victim.expected_intervention_final_mask ==
            victim.expected_previous_mask &&
        bytes_zero(victim.reserved, sizeof(victim.reserved));
}

static bool checkpoint_intervention_config_valid(
        const fk_compact_runtime_config &config) {
    const auto &value = config.checkpoint_intervention;
    if (value.enabled == 0u) {
        bool victims_zero = value.victim_count == 0u;
        for (const auto &victim : value.victims)
            victims_zero = victims_zero && intervention_victim_zero(victim);
        return victims_zero &&
            value.abi_version == 0u && value.record_bytes == 0u &&
            value.source_packet_sequence == 0u &&
            flow_key_zero(value.candidate_key) &&
            value.logical_connection_id == 0u &&
            value.flow_first_timestamp_ns == 0u &&
            value.observation_timestamp_ns == 0u &&
            value.flow_index == 0u && value.flow_generation == 0u &&
            value.checkpoint_packet == 0u &&
            value.expected_previous_mask == 0u &&
            value.expected_behavior_requested_mask == 0u &&
            value.expected_behavior_final_mask == 0u &&
            value.forced_requested_mask == 0u &&
            value.mode == FK_COMPACT_CHECKPOINT_INTERVENTION_DISABLED &&
            bytes_zero(value.reserved0, sizeof(value.reserved0)) &&
            bytes_zero(value.reserved, sizeof(value.reserved));
    }
    const bool checkpoint_valid = value.checkpoint_packet == 4u ||
        value.checkpoint_packet == 8u ||
        value.checkpoint_packet == 12u ||
        value.checkpoint_packet == 20u;
    const bool key_valid = intervention_flow_key_valid(
        value.candidate_key, value.logical_connection_id);
    bool victims_valid = value.victim_count != 0u &&
        value.victim_count <=
            FK_COMPACT_CHECKPOINT_INTERVENTION_MAX_VICTIMS;
    for (uint32_t index = 0u;
         index < FK_COMPACT_CHECKPOINT_INTERVENTION_MAX_VICTIMS; ++index) {
        if (index < value.victim_count) {
            const auto &victim = value.victims[index];
            victims_valid = victims_valid &&
                intervention_victim_shape_valid(
                    victim, config.maximum_flows) &&
                !(victim.flow_index == value.flow_index &&
                  victim.flow_generation == value.flow_generation);
            for (uint32_t prior = 0u; prior < index; ++prior) {
                victims_valid = victims_valid &&
                    !(victim.flow_index ==
                          value.victims[prior].flow_index &&
                      victim.flow_generation ==
                          value.victims[prior].flow_generation);
            }
        } else {
            victims_valid = victims_valid &&
                intervention_victim_zero(value.victims[index]);
        }
    }
    return victims_valid && value.enabled == 1u &&
        value.abi_version ==
            FK_COMPACT_CHECKPOINT_INTERVENTION_ABI_VERSION &&
        value.record_bytes == sizeof(value) &&
        value.source_packet_sequence != UINT64_MAX && key_valid &&
        value.flow_first_timestamp_ns != 0u &&
        value.observation_timestamp_ns >=
            value.flow_first_timestamp_ns &&
        value.flow_index < config.maximum_flows &&
        value.flow_generation != 0u && checkpoint_valid &&
        value.expected_previous_mask <= FK_COMPONENT_FULL &&
        value.expected_behavior_requested_mask <= FK_COMPONENT_FULL &&
        value.expected_behavior_final_mask <= FK_COMPONENT_FULL &&
        value.expected_behavior_requested_mask !=
            value.expected_previous_mask &&
        value.expected_behavior_final_mask !=
            value.expected_previous_mask &&
        (value.expected_behavior_final_mask &
             ~value.expected_behavior_requested_mask) == 0u &&
        value.forced_requested_mask == value.expected_previous_mask &&
        value.mode ==
            FK_COMPACT_CHECKPOINT_INTERVENTION_KEEP_EXISTING &&
        bytes_zero(value.reserved0, sizeof(value.reserved0)) &&
        bytes_zero(value.reserved, sizeof(value.reserved));
}

static void initialize_checkpoint_intervention_receipt(
        CompactRuntime &runtime) {
    auto &receipt = runtime.stats.checkpoint_intervention;
    const auto &config = runtime.config.checkpoint_intervention;
    receipt = {};
    receipt.abi_version =
        FK_COMPACT_CHECKPOINT_INTERVENTION_ABI_VERSION;
    receipt.record_bytes = sizeof(receipt);
    receipt.source_packet_sequence = config.source_packet_sequence;
    receipt.flow_index = config.flow_index;
    receipt.flow_generation = config.flow_generation;
    receipt.checkpoint_packet = config.checkpoint_packet;
    receipt.victim_count = config.victim_count;
    receipt.expected_previous_mask = config.expected_previous_mask;
    receipt.expected_behavior_requested_mask =
        config.expected_behavior_requested_mask;
    receipt.expected_behavior_final_mask =
        config.expected_behavior_final_mask;
    receipt.forced_requested_mask = config.forced_requested_mask;
    receipt.mode = config.mode;
    receipt.enabled = config.enabled;
    receipt.complete = config.enabled == 0u ? 1u : 0u;
}

static bool build_value_v3_context(
        CompactRuntime &state,
        const fk_component_flow &flow,
        const float base_30[FK_COMPACT_ACTION_FEATURES],
        bool ja4_protocol_applicable,
        uint64_t packet_count,
        float context[FK_VALUE_MODEL_V3_CONTEXT_FEATURES]) {
    const uint8_t protocol_mask = static_cast<uint8_t>(
        FK_COMPONENT_STAT | FK_COMPONENT_SEQ |
        (ja4_protocol_applicable
            ? FK_COMPONENT_JA4 : FK_COMPONENT_NONE));
    if (packet_count > UINT8_MAX ||
        (flow.mask & flow.released_mask) != 0u ||
        (flow.mask & ~protocol_mask) != 0u ||
        (protocol_mask !=
             (FK_COMPONENT_STAT | FK_COMPONENT_SEQ) &&
         protocol_mask != FK_COMPONENT_FULL)) {
        state.stats.value_v3_protocol_domain_violations++;
        state.stats.value_v3_context_failures++;
        return false;
    }
    fk_value_model_v3_context_input input{};
    std::memcpy(input.base_30, base_30, sizeof(input.base_30));
    input.current_mask = flow.mask;
    input.released_mask = flow.released_mask;
    input.materialized_mask = protocol_mask;
    for (size_t index = 0u; index < 3u; ++index) {
        /* Carry the actual causal state at this checkpoint.  In particular,
         * retained evidence may be PRESENT/NOT_YET_AVAILABLE while released
         * evidence remains LOST_OR_FAILED; only protocol-inapplicable JA4 is
         * normalized here. */
        input.missing_reason[index] =
            index == 2u && !ja4_protocol_applicable
            ? static_cast<uint8_t>(FK_MISSING_NOT_APPLICABLE)
            : flow.missing_reason[index];
    }
    input.trigger_kind = FK_VALUE_MODEL_V3_TRIGGER_CHECKPOINT;
    input.checkpoint_packet = static_cast<uint8_t>(packet_count);
    if (!fk_value_model_v3_build_context(&input, context)) {
        state.stats.value_v3_context_failures++;
        return false;
    }
    state.stats.value_v3_contexts_built++;
    return true;
}

static bool claim_api_mode(CompactRuntime &state, RuntimeApiMode mode) {
    if (state.api_mode == RuntimeApiMode::UNSET)
        state.api_mode = mode;
    if (state.api_mode == mode)
        return true;
    state.stats.api_mode_rejections++;
    return false;
}

static bool owner_capability_matches(
        const CompactRuntime &state,
        uintptr_t adapter_token,
        uint16_t fixed_owner) {
    return adapter_token != 0u &&
        state.owner_adapter_token.load(std::memory_order_acquire) ==
            adapter_token &&
        state.owner_adapter_fixed_owner_plus_one.load(
            std::memory_order_acquire) ==
                static_cast<uint32_t>(fixed_owner) + 1u;
}

/* A process-wide monotonic value, copied into TLS, identifies an individual
 * thread lifetime.  Unlike a TLS address, it cannot be reused when a thread
 * exits and a later thread is assigned the same TLS storage.  UINT64_MAX is
 * reserved as permanent exhaustion, so wraparound fails closed. */
static uint64_t non_reused_thread_token() {
    static std::atomic<uint64_t> next_token{1u};
    static thread_local uint64_t thread_token = 0u;
    if (thread_token != 0u)
        return thread_token;
    uint64_t candidate = next_token.load(std::memory_order_relaxed);
    while (candidate != UINT64_MAX) {
        if (next_token.compare_exchange_weak(
                candidate, candidate + 1u,
                std::memory_order_relaxed,
                std::memory_order_relaxed)) {
            thread_token = candidate;
            return thread_token;
        }
    }
    return 0u;
}

/*
 * All callers reach this guard before touching owner-local runtime state.
 * The unclaimed case preserves the standalone/test ABI.  Once claimed, the
 * adapter must hold its exact non-nestable capability scope.  Rejections are
 * atomic because an erroneous foreign caller must be countable without
 * racing owner-local stats.
 */
static bool mutating_api_allowed(CompactRuntime &state) {
    if (state.owner_adapter_token.load(std::memory_order_acquire) == 0u)
        return true;
    const uint8_t scope_active = state.owner_adapter_scope_active.load(
        std::memory_order_acquire);
    const uint64_t caller_thread = non_reused_thread_token();
    if (scope_active == 1u && caller_thread != 0u &&
        state.owner_adapter_scope_thread_token.load(
            std::memory_order_acquire) == caller_thread)
        return true;
    if (scope_active == 1u) {
        state.owner_adapter_foreign_scope_mutation_rejections.fetch_add(
            1u, std::memory_order_relaxed);
    } else {
        state.owner_adapter_unscoped_mutation_rejections.fetch_add(
            1u, std::memory_order_relaxed);
    }
    return false;
}

static bool ja4_applicable(const fk_packet_view &view) {
    if (view.l4_protocol != 6u)
        return false;
    const uint16_t ports[2]{view.src_port, view.dst_port};
    for (uint16_t port : ports) {
        switch (port) {
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
    }
    return false;
}

static bool advance_residency_accounting(
        CompactRuntime &state,
        uint64_t timestamp_ns) {
    if (!state.semantic_time_initialized) {
        state.semantic_first_timestamp_ns = timestamp_ns;
        state.semantic_last_timestamp_ns = timestamp_ns;
        state.semantic_time_initialized = true;
        return true;
    }
    if (timestamp_ns < state.semantic_last_timestamp_ns) {
        state.stats.semantic_time_regressions++;
        state.semantic_time_complete = false;
        return false;
    }
    const uint64_t elapsed_ns =
        timestamp_ns - state.semantic_last_timestamp_ns;
    if (elapsed_ns != 0u) {
        fk_budget_snapshot budget{};
        fk_compact_flow_table_budget_snapshot(state.table, &budget);
        state.controlled_state_byte_nanoseconds +=
            static_cast<long double>(budget.used_bytes) *
            static_cast<long double>(elapsed_ns);
        for (size_t component = 0u;
             component < FK_MEMORY_COMPONENT_COUNT;
             ++component) {
            state.component_byte_nanoseconds[component] +=
                static_cast<long double>(
                    budget.used_by_component[component]) *
                static_cast<long double>(elapsed_ns);
        }
    }
    state.semantic_last_timestamp_ns = timestamp_ns;
    return true;
}

static bool add_optional_pool_utilization(
        uint32_t in_use,
        uint32_t capacity,
        uint32_t block_bytes,
        uint64_t &current_bytes,
        uint64_t &capacity_bytes) {
    if (block_bytes == 0u || in_use > capacity ||
        static_cast<uint64_t>(in_use) > UINT64_MAX / block_bytes ||
        static_cast<uint64_t>(capacity) > UINT64_MAX / block_bytes) {
        return false;
    }
    const uint64_t current = static_cast<uint64_t>(in_use) * block_bytes;
    const uint64_t available = static_cast<uint64_t>(capacity) * block_bytes;
    if (current_bytes > UINT64_MAX - current ||
        capacity_bytes > UINT64_MAX - available) {
        return false;
    }
    current_bytes += current;
    capacity_bytes += available;
    return true;
}

static bool optional_evidence_pressure_utilization(
        const CompactRuntime &state,
        uint64_t &current_slots,
        uint64_t &capacity_slots) {
    fk_compact_flow_table_stats stats{};
    if (!fk_compact_flow_table_get_stats(state.table, &stats))
        return false;
    return fk_compact_runtime_max_optional_pool_utilization_from_stats(
        &stats, &current_slots, &capacity_slots);
}

static fk_resource_costs online_resource_costs(
        const CompactRuntime &state) {
    fk_resource_costs costs = state.config.resource_costs;
    /* The frozen Development deployment gate is a one-sided lower confidence
     * bound: value = mean - uncertainty.  Re-adding uncertainty when pools
     * have headroom changes both the selected action and the validated policy
     * family, and made larger budgets execute a progressively less
     * conservative, unvalidated policy.  Capacity adaptation belongs in the
     * explicit value-per-byte/resource-price comparison, never in the model
     * confidence bound. */
    costs.uncertainty_recovery = 0.0f;
    return costs;
}

static void update_automatic_pressure(CompactRuntime &state) {
    state.optional_occupancy_changed_since_pressure_update = false;
    if (state.config.automatic_pressure_enabled == 0u)
        return;
    /* State-selection pressure is competition for reclaimable evidence, not
     * the mandatory FlowTable/CORE/lease floor.  The hard total budget remains
     * enforced independently by fk_state_budget on every transition.  Queue
     * pressure remains an independent external input through set_pressure(). */
    uint64_t current_slots = 0u;
    uint64_t capacity_slots = 0u;
    if (!optional_evidence_pressure_utilization(
            state, current_slots, capacity_slots)) {
        /* A missing/overflowed denominator is not evidence of spare capacity.
         * Fail closed so corrupted accounting can never silently leave state
         * selection in NORMAL.  Repeated failures are observable, while the
         * mode-transition receipt is emitted exactly once. */
        state.stats.pressure_accounting_failures++;
        if (state.automatic_pressure != FK_PRESSURE_OVERLOAD) {
            state.stats.automatic_overload_transitions++;
            state.automatic_pressure = FK_PRESSURE_OVERLOAD;
            state.pressure = static_cast<fk_pressure_mode>(std::max(
                static_cast<unsigned>(state.automatic_pressure),
                static_cast<unsigned>(state.external_pressure)));
        }
        return;
    }
    const uint64_t percent = current_slots >= capacity_slots ||
            current_slots > UINT64_MAX / 100u
        ? 100u : current_slots * 100u / capacity_slots;
    fk_pressure_mode next = state.automatic_pressure;
    if (state.automatic_pressure == FK_PRESSURE_NORMAL) {
        if (percent >= state.config.overload_enter_percent)
            next = FK_PRESSURE_OVERLOAD;
        else if (percent >= state.config.pressure_enter_percent)
            next = FK_PRESSURE_PRESSURE;
    } else if (state.automatic_pressure == FK_PRESSURE_PRESSURE) {
        if (percent >= state.config.overload_enter_percent)
            next = FK_PRESSURE_OVERLOAD;
        else if (percent <= state.config.pressure_exit_percent)
            next = FK_PRESSURE_NORMAL;
    } else if (percent <= state.config.overload_exit_percent) {
        next = percent <= state.config.pressure_exit_percent
            ? FK_PRESSURE_NORMAL : FK_PRESSURE_PRESSURE;
    }
    if (next == state.automatic_pressure)
        return;
    if (next == FK_PRESSURE_OVERLOAD)
        state.stats.automatic_overload_transitions++;
    else if (next == FK_PRESSURE_PRESSURE)
        state.stats.automatic_pressure_transitions++;
    else
        state.stats.automatic_recovery_transitions++;
    state.automatic_pressure = next;
    state.pressure = static_cast<fk_pressure_mode>(std::max(
        static_cast<unsigned>(state.automatic_pressure),
        static_cast<unsigned>(state.external_pressure)));
}

static fk_compact_timer_config optional_timer_config(
        const CompactRuntime &state) {
    fk_compact_timer_config config{};
    if (state.config.baseline_policy.kind == FK_COMPACT_POLICY_FIXED_TTL)
        config.fixed_ttl_ns = state.config.baseline_policy.fixed_ttl_ns;
    /* Pressure-triggered retention changes remain checkpoint decisions in
     * this runtime.  The timer scanner is enabled here for semantic lease and
     * Fixed-TTL expiry; it must not invent a second idle policy. */
    config.pressure_idle_ns = 0u;
    config.overload_idle_ns = 0u;
    config.maximum_component_releases =
        FK_VALUE_EVICTION_DEFAULT_MAX_VICTIMS;
    return config;
}

static uint32_t scan_optional_timers(
        CompactRuntime &state,
        uint64_t timestamp_ns,
        uint32_t scan_limit) {
    const fk_compact_timer_config config = optional_timer_config(state);
    state.stats.optional_timer_scan_calls++;
    const uint32_t released = fk_compact_flow_table_scan_optional_timers(
        state.table,
        timestamp_ns,
        state.pressure,
        &config,
        fk_compact_flow_handle{},
        0u,
        scan_limit);
    state.stats.optional_timer_component_releases += released;
    if (released != 0u)
        state.optional_occupancy_changed_since_pressure_update = true;
    return released;
}

/* Account residency only up to the next semantic optional-state deadline,
 * release every component due at that exact timestamp, and then continue.
 * The table's indexed-min query is O(1).  Repeating a
 * boundary is required because one bounded scan may release at most 64
 * components; a zero-release repeat is a fail-closed no-progress condition,
 * most commonly a full undrained transition queue. */
static bool advance_residency_through_optional_deadlines(
        CompactRuntime &state,
        uint64_t target_timestamp_ns) {
    if (!state.semantic_time_initialized)
        return advance_residency_accounting(state, target_timestamp_ns);
    if (target_timestamp_ns < state.semantic_last_timestamp_ns)
        return advance_residency_accounting(state, target_timestamp_ns);

    const uint64_t maximum_boundary_passes =
        static_cast<uint64_t>(state.config.maximum_flows) * 3u + 1u;
    for (;;) {
        uint64_t deadline_ns = 0u;
        if (!fk_compact_flow_table_next_optional_timer_deadline(
                state.table, 0u, target_timestamp_ns, &deadline_ns))
            break;
        if (deadline_ns < state.semantic_last_timestamp_ns) {
            state.stats.optional_timer_boundary_stalls++;
            state.semantic_time_complete = false;
            return false;
        }
        if (!advance_residency_accounting(state, deadline_ns))
            return false;
        state.stats.optional_timer_exact_boundaries++;
        uint64_t boundary_passes = 0u;
        for (;;) {
            if(state.config.baseline_policy.kind!=FK_COMPACT_POLICY_FIXED_TTL &&
                !fk_compact_flow_table_prepare_due_optional(state.table,target_timestamp_ns)) {
                state.semantic_time_complete=false;return false;
            }
            const uint32_t released = scan_optional_timers(
                state, deadline_ns, state.config.maximum_flows);
            uint64_t still_due_ns = 0u;
            const bool still_due =
                fk_compact_flow_table_next_optional_timer_deadline(
                    state.table, 0u, deadline_ns, &still_due_ns);
            if (!still_due)
                break;
            if (still_due_ns != deadline_ns || released == 0u ||
                ++boundary_passes > maximum_boundary_passes) {
                state.stats.optional_timer_boundary_stalls++;
                state.semantic_time_complete = false;
                return false;
            }
        }
    }
    return advance_residency_accounting(state, target_timestamp_ns);
}

/*
 * Execute at most one timer pass that emits evidence transitions.  Stopping
 * after every non-empty pass is intentional: the owner must durably consume
 * those records before another pass can fill the fixed transition ring.
 * Re-entering at the same exact deadline does not account residency or count
 * a second boundary; it only continues bounded due-root consumption.
 */
static bool advance_residency_through_optional_deadlines_step(
        CompactRuntime &state,
        uint64_t target_timestamp_ns,
        bool &complete) {
    complete = false;
    if (!state.semantic_time_initialized) {
        complete = advance_residency_accounting(
            state, target_timestamp_ns);
        return complete;
    }
    if (target_timestamp_ns < state.semantic_last_timestamp_ns) {
        /* Preserve the shared regression counter/receipt, but never expose a
         * successful NEEDS_DRAIN result for a backwards watermark. */
        (void)advance_residency_accounting(state, target_timestamp_ns);
        return false;
    }

    const uint64_t maximum_boundary_passes =
        static_cast<uint64_t>(state.config.maximum_flows) * 3u + 1u;
    uint64_t zero_release_boundaries = 0u;
    for (;;) {
        uint64_t deadline_ns = 0u;
        if (!fk_compact_flow_table_next_optional_timer_deadline(
                state.table, 0u, target_timestamp_ns, &deadline_ns)) {
            complete = advance_residency_accounting(
                state, target_timestamp_ns);
            return complete;
        }
        if (deadline_ns < state.semantic_last_timestamp_ns) {
            state.stats.optional_timer_boundary_stalls++;
            state.semantic_time_complete = false;
            return false;
        }
        if(state.config.baseline_policy.kind!=FK_COMPACT_POLICY_FIXED_TTL &&
            !fk_compact_flow_table_prepare_due_optional(state.table,target_timestamp_ns)) {
            state.semantic_time_complete=false;return false;
        }
        if (deadline_ns > state.semantic_last_timestamp_ns) {
            if (!advance_residency_accounting(state, deadline_ns))
                return false;
            state.stats.optional_timer_exact_boundaries++;
        }

        const uint32_t released = scan_optional_timers(
            state, deadline_ns, state.config.maximum_flows);
        uint64_t still_due_ns = 0u;
        const bool still_due =
            fk_compact_flow_table_next_optional_timer_deadline(
                state.table, 0u, deadline_ns, &still_due_ns);
        if (still_due &&
            (still_due_ns != deadline_ns || released == 0u)) {
            state.stats.optional_timer_boundary_stalls++;
            state.semantic_time_complete = false;
            return false;
        }
        if (released != 0u)
            return true;

        /* An indexed minimum may disappear without emitting a record only
         * through a no-resident cleanup path.  Permit bounded cleanup, but
         * never spin indefinitely on corruption. */
        if (++zero_release_boundaries > maximum_boundary_passes) {
            state.stats.optional_timer_boundary_stalls++;
            state.semantic_time_complete = false;
            return false;
        }
    }
}

static void publish_flow_open_observation(
        CompactRuntime &state,
        const fk_flow_key &key,
        const fk_compact_flow_handle &handle,
        const fk_compact_flow_snapshot &snapshot,
        uint64_t observation_timestamp_ns,
        uint64_t logical_connection_id,
        bool capacity_continuation,
        const fk_compact_capacity_continuation_predecessor &predecessor) {
    if (state.flow_open_pending)
        state.stats.flow_open_observations_overwritten++;
    fk_compact_flow_open_observation_v2 &observation =
        state.pending_flow_open;
    observation = {};
    observation.presentation.key = key;
    observation.presentation.flow_first_timestamp_ns =
        snapshot.first_timestamp_ns;
    observation.presentation.observation_timestamp_ns =
        observation_timestamp_ns;
    observation.presentation.flow_index = handle.index;
    observation.presentation.flow_generation = handle.generation;
    observation.presentation.predecessor_flow_index =
        predecessor.flow_index;
    observation.presentation.predecessor_flow_generation =
        predecessor.flow_generation;
    observation.presentation.predecessor_checkpoint_packet =
        predecessor.last_checkpoint_packet;
    // Initial coverage is scoring-only, so the retention cursor legitimately
    // still says "no packet-4 decision". In this startup-only mode every
    // admitted predecessor has emitted packet 1. Attest that scoring cursor
    // on CONTINUE; otherwise the service correctly rejects 0 after seeing 1.
    if (capacity_continuation && state.first_packet_coverage &&
        observation.presentation.predecessor_checkpoint_packet == 0u)
        observation.presentation.predecessor_checkpoint_packet = 1u;
    observation.presentation.control_kind = capacity_continuation
        ? FK_COMPACT_FLOW_CONTROL_CONTINUE
        : FK_COMPACT_FLOW_CONTROL_OPEN;
    observation.logical_connection_id = logical_connection_id;
    state.flow_open_pending = true;
    state.stats.flow_open_observations_ready++;
    if (capacity_continuation)
        state.stats.flow_continue_observations_ready++;
}

static void publish_action_record(
        CompactRuntime &state,
        const fk_flow_key &key,
        uint64_t timestamp_ns,
        uint64_t packet_count,
        const fk_compact_controller_result &decision) {
    if (state.action_pending)
        state.stats.action_records_overwritten++;
    fk_compact_action_record &record = state.pending_action;
    record = {};
    record.key = key;
    record.observation_timestamp_ns = timestamp_ns;
    record.packet_count = packet_count;
    record.controlled_bytes_before =
        decision.controlled_bytes_before;
    record.controlled_bytes_after =
        decision.controlled_bytes_after;
    record.selected_utility = decision.requested_utility;
    record.pressure = static_cast<uint8_t>(state.pressure);
    record.previous_mask = decision.previous_mask;
    record.selected_mask = decision.requested_mask;
    record.protocol_applicable_mask = decision.protocol_applicable_mask;
    record.final_mask = decision.final_mask;
    record.released_mask_before = decision.released_mask_before;
    record.released_mask_after = decision.released_mask_after;
    record.materializable_mask = decision.materializable_mask;
    record.pool_unavailable_mask = decision.pool_unavailable_mask;
    record.observation_complete = decision.observation_complete;
    for (size_t index = 0u; index < 3u; ++index)
        record.missing_reason[index] = decision.missing_reason[index];
    record.candidates_considered =
        decision.decision.candidates_considered;
    record.budget_rejections = decision.decision.budget_rejections;
    record.transition_result =
        static_cast<uint8_t>(decision.decision.result);
    if (record.selected_mask <= FK_COMPONENT_FULL)
        state.stats.action_selected_mask_counts[record.selected_mask]++;
    if (record.pool_unavailable_mask != FK_COMPONENT_NONE) {
        state.stats.action_pool_unavailable_records++;
        if ((record.pool_unavailable_mask & FK_COMPONENT_STAT) != 0u)
            state.stats.action_pool_unavailable_component_counts[0]++;
        if ((record.pool_unavailable_mask & FK_COMPONENT_SEQ) != 0u)
            state.stats.action_pool_unavailable_component_counts[1]++;
        if ((record.pool_unavailable_mask & FK_COMPONENT_JA4) != 0u)
            state.stats.action_pool_unavailable_component_counts[2]++;
    }
    state.stats.action_budget_rejections += record.budget_rejections;
    if (record.transition_result <= FK_TRANSITION_STORAGE_FAILED &&
        record.transition_result != FK_TRANSITION_APPLIED &&
        record.transition_result != FK_TRANSITION_NO_CHANGE) {
        state.stats.action_transition_failure_counts[
            record.transition_result]++;
    }
    state.action_pending = true;
    state.stats.action_records_ready++;
}

}  // namespace

extern "C" {

bool fk_compact_runtime_evidence_transition_shape_valid(
        const fk_compact_evidence_transition *transition) {
    if (transition == nullptr)
        return false;
    const uint8_t component = transition->component;
    const unsigned reason = static_cast<unsigned>(transition->reason);
    if ((component != FK_COMPONENT_STAT &&
         component != FK_COMPONENT_SEQ &&
         component != FK_COMPONENT_JA4) ||
        reason < FK_COMPACT_TRANSITION_VALUE_REPLACED ||
        reason > FK_COMPACT_TRANSITION_SEEDED_RANDOM_EVICTED ||
        transition->previous_mask > FK_COMPONENT_FULL ||
        transition->final_mask > FK_COMPONENT_FULL ||
        transition->released_mask > FK_COMPONENT_FULL ||
        (transition->released_mask & component) == 0u ||
        transition->bytes_released == 0u) {
        return false;
    }
    return (transition->previous_mask & component) != 0u &&
        transition->final_mask == static_cast<uint8_t>(
            transition->previous_mask & ~component);
}

bool fk_compact_runtime_optional_evidence_utilization_from_stats(
        const fk_compact_flow_table_stats *stats,
        uint64_t *current_bytes,
        uint64_t *capacity_bytes) {
    if (stats == nullptr || current_bytes == nullptr ||
        capacity_bytes == nullptr) {
        return false;
    }
    uint64_t current = 0u;
    uint64_t capacity = 0u;
    if (!add_optional_pool_utilization(
            stats->stat_pool_in_use,
            stats->stat_pool_capacity,
            stats->stat_pool_block_bytes,
            current,
            capacity) ||
        !add_optional_pool_utilization(
            stats->seq_pool_in_use,
            stats->seq_pool_capacity,
            stats->seq_pool_block_bytes,
            current,
            capacity) ||
        !add_optional_pool_utilization(
            stats->ja4_pending_pool_in_use,
            stats->ja4_pending_pool_capacity,
            stats->ja4_pending_pool_block_bytes,
            current,
            capacity) ||
        !add_optional_pool_utilization(
            stats->ja4_summary_pool_in_use,
            stats->ja4_summary_pool_capacity,
            stats->ja4_summary_pool_block_bytes,
            current,
            capacity) ||
        capacity == 0u) {
        return false;
    }
    *current_bytes = current;
    *capacity_bytes = capacity;
    return true;
}

bool fk_compact_runtime_max_optional_pool_utilization_from_stats(
        const fk_compact_flow_table_stats *stats,
        uint64_t *current_slots,
        uint64_t *capacity_slots) {
    if (stats == nullptr || current_slots == nullptr ||
        capacity_slots == nullptr) {
        return false;
    }
    const uint32_t in_use[] = {
        stats->stat_pool_in_use,
        stats->seq_pool_in_use,
        stats->ja4_pending_pool_in_use,
        stats->ja4_summary_pool_in_use,
    };
    const uint32_t capacity[] = {
        stats->stat_pool_capacity,
        stats->seq_pool_capacity,
        stats->ja4_pending_pool_capacity,
        stats->ja4_summary_pool_capacity,
    };
    const uint32_t block_bytes[] = {
        stats->stat_pool_block_bytes,
        stats->seq_pool_block_bytes,
        stats->ja4_pending_pool_block_bytes,
        stats->ja4_summary_pool_block_bytes,
    };
    uint64_t selected_current = 0u;
    uint64_t selected_capacity = 0u;
    for (size_t index = 0u; index < 4u; ++index) {
        if (block_bytes[index] == 0u || in_use[index] > capacity[index])
            return false;
        if (capacity[index] == 0u)
            continue;
        if (selected_capacity == 0u ||
            static_cast<uint64_t>(in_use[index]) * selected_capacity >
                selected_current * static_cast<uint64_t>(capacity[index])) {
            selected_current = in_use[index];
            selected_capacity = capacity[index];
        }
    }
    if (selected_capacity == 0u)
        return false;
    *current_slots = selected_current;
    *capacity_slots = selected_capacity;
    return true;
}

static bool build_observation_request(
        CompactRuntime &state,
        const fk_compact_flow_handle &handle,
        const fk_compact_flow_snapshot &snapshot,
        uint64_t timestamp_ns,
        const float *features,
        fk_compact_detection_request &request) {
    const fk_component_flow *flow =
        fk_compact_flow_table_component_flow(state.table, handle);
    if (flow == nullptr)
        return false;
    request.key = snapshot.key;
    request.flow_first_timestamp_ns = snapshot.first_timestamp_ns;
    request.observation_timestamp_ns = timestamp_ns;
    request.packet_count = snapshot.packets;
    request.feature_count = state.detector_feature_count;
    request.flow_index = handle.index;
    request.flow_generation = handle.generation;
    request.component_mask = flow->mask;
    request.observation_complete = flow->observation_complete;
    request.checkpoint_packet =
        static_cast<uint8_t>(snapshot.packets > 255u
            ? 255u : snapshot.packets);
    const uint32_t causal_features =
        state.detector_feature_count < FK_COMPACT_ACTION_FEATURES
        ? state.detector_feature_count : FK_COMPACT_ACTION_FEATURES;
    for (uint32_t index = 0u; index < causal_features; ++index)
        request.features[index] = features[index];
    if (state.detector_feature_count > 30u)
        request.features[30] =
            (flow->mask & FK_COMPONENT_STAT) != 0u ? 1.0f : 0.0f;
    if (state.detector_feature_count > 31u)
        request.features[31] =
            (flow->mask & FK_COMPONENT_SEQ) != 0u ? 1.0f : 0.0f;
    if (state.detector_feature_count > 32u)
        request.features[32] =
            (flow->mask & FK_COMPONENT_JA4) != 0u ? 1.0f : 0.0f;
    for (uint32_t index = 0u;
         index < 3u && 33u + index < state.detector_feature_count;
         ++index) {
        request.features[33u + index] =
            static_cast<float>(flow->missing_reason[index]);
    }
    if (state.detector_feature_count > 36u)
        request.features[36] =
            flow->observation_complete != 0u ? 1.0f : 0.0f;
    const fk_compact_stat_state *stat =
        fk_compact_flow_table_stat(state.table, handle);
    const fk_compact_seq_state *seq =
        fk_compact_flow_table_seq(state.table, handle);
    const fk_compact_ja4_state *ja4 =
        fk_compact_flow_table_ja4(state.table, handle);
    if (state.detector_feature_count > 37u)
        request.features[37] =
            static_cast<float>(snapshot.packets) / 20.0f;
    if (state.detector_feature_count > 38u)
        request.features[38] = stat != nullptr ? 1.0f : 0.0f;
    if (state.detector_feature_count > 39u)
        request.features[39] = seq != nullptr ? 1.0f : 0.0f;
    if (state.detector_feature_count > 40u)
        request.features[40] = ja4 != nullptr ? 1.0f : 0.0f;
    if (state.detector_feature_count > 41u)
        request.features[41] = seq == nullptr ? 0.0f :
            static_cast<float>(seq->count) /
            static_cast<float>(FK_COMPACT_SEQ_PACKETS);
    /* ``features`` and the component pointers represent the state that was
     * physically resident during the completed observation interval.  Clear
     * absent blocks before selectively rebuilding that state.  From packet 8
     * onward the new retention action is committed only after this request is
     * materialized, so it cannot retroactively erase current causal evidence. */
    const auto clear_detector_block = [&request](
            uint32_t first, uint32_t last) {
        for (uint32_t index = first; index < last; ++index)
            request.features[index] = 0.0f;
    };
    if (stat == nullptr)
        clear_detector_block(42u, 58u);
    if (seq == nullptr) {
        request.features[41] = 0.0f;
        clear_detector_block(58u, 98u);
    }
    if (ja4 == nullptr) {
        clear_detector_block(98u, 116u);
        if (state.detector_feature_count ==
                FK_COMPACT_DETECTOR_FEATURES_V4) {
            clear_detector_block(
                FK_COMPACT_JA4_IDENTITY_BASE,
                FK_COMPACT_DETECTOR_FEATURES_V4);
        }
    }
    if (stat != nullptr && state.detector_feature_count > 57u) {
        const double direction_packets[2]{
            static_cast<double>(stat->direction_packets[0]),
            static_cast<double>(stat->direction_packets[1]),
        };
        request.features[42] =
            static_cast<float>(std::log1p(direction_packets[0]));
        request.features[43] =
            static_cast<float>(std::log1p(direction_packets[1]));
        request.features[44] =
            static_cast<float>(std::log1p(stat->direction_bytes[0]));
        request.features[45] =
            static_cast<float>(std::log1p(stat->direction_bytes[1]));
        for (uint32_t direction_index = 0u;
             direction_index < 2u; ++direction_index) {
            request.features[46u + direction_index] =
                stat->direction_bytes[direction_index] == 0u ? 0.0f :
                static_cast<float>(
                    static_cast<double>(
                        stat->payload_bytes[direction_index]) /
                    static_cast<double>(
                        stat->direction_bytes[direction_index]));
            const double samples =
                direction_packets[direction_index] > 1.0
                ? direction_packets[direction_index] - 1.0 : 0.0;
            if (samples > 0.0) {
                const double mean_ns =
                    static_cast<double>(
                        stat->interarrival_sum_ns[direction_index]) /
                    samples;
                const double mean_square_ns =
                    static_cast<double>(
                        stat->interarrival_squared_sum_ns[
                            direction_index]) /
                    samples;
                const double variance_ns =
                    std::fmax(
                        0.0, mean_square_ns - mean_ns * mean_ns);
                request.features[48u + direction_index] =
                    static_cast<float>(
                        std::log1p(mean_ns / 1000.0));
                request.features[50u + direction_index] =
                    static_cast<float>(
                        std::log1p(std::sqrt(variance_ns) / 1000.0));
            }
        }
        request.features[52] =
            static_cast<float>(stat->minimum_wire_size) / 1514.0f;
        request.features[53] =
            static_cast<float>(stat->maximum_wire_size) / 1514.0f;
        const double packet_denominator =
            snapshot.packets == 0u ? 1.0 :
            static_cast<double>(snapshot.packets);
        request.features[54] = static_cast<float>(
            stat->tcp_flag_counts[1] / packet_denominator);
        request.features[55] = static_cast<float>(
            stat->tcp_flag_counts[4] / packet_denominator);
        request.features[56] = static_cast<float>(
            stat->tcp_flag_counts[0] / packet_denominator);
        request.features[57] = static_cast<float>(
            stat->tcp_flag_counts[2] / packet_denominator);
    }
    if (seq != nullptr && state.detector_feature_count > 97u) {
        const uint32_t count =
            seq->count > FK_COMPACT_SEQ_PACKETS
            ? FK_COMPACT_SEQ_PACKETS : seq->count;
        const uint32_t start =
            seq->count < FK_COMPACT_SEQ_PACKETS ? 0u : seq->next;
        for (uint32_t index = 0u; index < count; ++index) {
            const fk_compact_packet_metadata &packet =
                seq->packets[
                    (start + index) % FK_COMPACT_SEQ_PACKETS];
            const float normalized =
                static_cast<float>(packet.wire_size) / 1514.0f;
            request.features[58u + index] =
                packet.direction == 0u ? normalized : -normalized;
            request.features[78u + index] =
                static_cast<float>(
                    std::log1p(
                        static_cast<double>(packet.delta_time_us) /
                        1000.0));
        }
    }
    if (ja4 != nullptr && state.detector_feature_count > 115u) {
        request.features[98] =
            ja4->client.present != 0u ? 1.0f : 0.0f;
        request.features[99] =
            ja4->server.present != 0u ? 1.0f : 0.0f;
        request.features[100] =
            static_cast<float>(ja4->client.legacy_version) / 65535.0f;
        request.features[101] =
            static_cast<float>(ja4->server.legacy_version) / 65535.0f;
        request.features[102] =
            static_cast<float>(std::log1p(ja4->client.cipher_count));
        request.features[103] =
            static_cast<float>(std::log1p(ja4->client.extension_count));
        request.features[104] = static_cast<float>(
            std::log1p(ja4->client.signature_algorithm_count));
        request.features[105] =
            static_cast<float>(std::log1p(ja4->server.cipher_count));
        request.features[106] =
            static_cast<float>(std::log1p(ja4->server.extension_count));
        request.features[107] = static_cast<float>(
            std::log1p(ja4->server.signature_algorithm_count));
        request.features[108] =
            ja4->client.server_name_hash != 0u ? 1.0f : 0.0f;
        request.features[109] =
            ja4->client.alpn_hash != 0u ? 1.0f : 0.0f;
        request.features[110] =
            ja4->server.alpn_hash != 0u ? 1.0f : 0.0f;
        request.features[111] =
            ja4->server.hello_retry_request != 0u ? 1.0f : 0.0f;
        request.features[112] =
            static_cast<float>(ja4->server.selected_cipher) / 65535.0f;
        request.features[113] =
            static_cast<float>(ja4->client.selected_cipher) / 65535.0f;
        request.features[114] =
            ja4->client.cipher_set_hash != 0u ? 1.0f : 0.0f;
        request.features[115] =
            ja4->client.extension_set_hash != 0u ? 1.0f : 0.0f;
    }
    if (state.detector_feature_count >
            FK_COMPACT_DETECTOR_COMPONENT_START_BASE + 2u) {
        constexpr float kStartPacketNormalizer = 255.0f;
        for (uint32_t index = 0u; index < 3u; ++index) {
            request.features[
                FK_COMPACT_DETECTOR_COMPONENT_START_BASE + index] =
                static_cast<float>(
                    flow->component_start_packet[index]) /
                kStartPacketNormalizer;
        }
    }
    if (state.detector_feature_count ==
            FK_COMPACT_DETECTOR_FEATURES_V4 &&
        ja4 != nullptr &&
        !fk_compact_ja4_encode_identity(
            ja4,
            request.features + FK_COMPACT_JA4_IDENTITY_BASE,
            FK_COMPACT_JA4_IDENTITY_FEATURES)) {
        state.stats.checkpoint_ja4_identity_failures++;
        state.stats.checkpoint_failures++;
        return false;
    }
    return true;
}

static bool emit_prefix_observation(
        CompactRuntime &state,
        const fk_compact_flow_handle &handle,
        const fk_compact_detection_request &request,
        bool checkpoint) {
    if (state.prefix_callback == nullptr ||
        request.packet_count > state.prefix_packet_limit)
        return true;
    fk_compact_core_state core{};
    if (!fk_compact_flow_table_capture_core(state.table, handle, &core))
        return false;
    return state.prefix_callback(state.prefix_context, &request,
                                 core.terminal_observed != 0u, checkpoint);
}

static bool adaptive_detection_candidate(
        const CompactRuntime &state,
        uint64_t packet_count) {
    if (state.marginal_detection_candidates)
        return packet_count != 0u &&
            packet_count <= state.adaptive_horizon_packet;
    if (!state.adaptive_detection_candidates ||
        packet_count < state.adaptive_first_packet ||
        packet_count > state.adaptive_horizon_packet)
        return false;
    if (packet_count == state.adaptive_first_packet ||
        packet_count == state.adaptive_horizon_packet)
        return true;
    const uint32_t delta = static_cast<uint32_t>(
        packet_count - state.adaptive_first_packet);
    for (uint32_t near_steps = 0u;
         near_steps <= delta / state.adaptive_near_gap;
         ++near_steps) {
        const uint32_t remainder =
            delta - near_steps * state.adaptive_near_gap;
        if (remainder % state.adaptive_far_gap == 0u)
            return true;
    }
    return false;
}

static bool publish_adaptive_candidate(
        CompactRuntime &state,
        const fk_compact_flow_handle &handle,
        const fk_compact_flow_snapshot &snapshot,
        uint64_t timestamp_ns,
        const fk_packet_view &view,
        uint64_t logical_connection_id) {
    float features[FK_COMPACT_ACTION_FEATURES]{};
    fk_compact_detection_request request{};
    if (!fk_compact_flow_table_action_features(
            state.table, handle, &view, state.pressure, features) ||
        !build_observation_request(
            state, handle, snapshot, timestamp_ns, features, request) ||
        !emit_prefix_observation(state, handle, request, false))
        return false;
    if (state.detection_pending)
        state.stats.detection_windows_overwritten++;
    state.pending_detection = {};
    state.pending_detection.presentation = request;
    state.pending_detection.logical_connection_id = logical_connection_id;
    state.detection_pending = true;
    state.stats.detection_windows_ready++;
    return true;
}

static fk_compact_runtime_result process_view_impl(
    fk_compact_runtime *runtime,
    const fk_packet_view *view,
    const fk_compact_flow_handle *bound_handle,
    uint8_t bound_feature_direction,
    bool recover_stale_bound,
    bool residency_already_advanced,
    uint64_t timestamp_ns,
    uint64_t logical_connection_id,
    const fk_flow_key *canonical_flow_key_proof,
    fk_compact_runtime_flow_identity_v2 *identity,
    fk_compact_runtime_packet_once_outcome_v2 *packet_once_outcome,
    const fk_flow_key *prederived_observed_key,
    uint8_t prederived_observed_direction);

static fk_compact_runtime_result process_frame_impl(
    fk_compact_runtime *runtime,
    const uint8_t *frame,
    size_t captured_length,
    uint32_t wire_length,
    uint64_t timestamp_ns,
    uint64_t logical_connection_id);

bool fk_compact_runtime_attach_checkpoint_release_guard(
        fk_compact_runtime *runtime, const fk_compact_release_guard *guard) {
    if (!runtime || !guard || !guard->authorize) return false;
    auto &state = *implementation(runtime);
    if (!mutating_api_allowed(state) || state.semantic_time_initialized ||
        state.checkpoint_release_guard.authorize || state.config.checkpoint_intervention.enabled)
        return false;
    const auto kind=state.config.baseline_policy.kind;
    if (kind != FK_COMPACT_POLICY_FLOWKEEP && kind != FK_COMPACT_POLICY_LRU &&
        kind != FK_COMPACT_POLICY_CLOCK && kind != FK_COMPACT_POLICY_TWO_Q &&
        kind != FK_COMPACT_POLICY_FIFO && kind != FK_COMPACT_POLICY_SUMMARY_HISTORY &&
        kind != FK_COMPACT_POLICY_FULL_STATE && kind != FK_COMPACT_POLICY_CORE_ONLY) return false;
    state.checkpoint_release_guard=*guard;
    return true;
}

fk_compact_runtime *fk_compact_runtime_create(
        const fk_compact_runtime_config *config,
        char *error,
        size_t error_capacity) {
    set_error(error, error_capacity, "");
    const bool value_v3 = config != nullptr &&
        config->action_value_model_kind ==
            FK_COMPACT_ACTION_VALUE_V3_64D;
    const bool no_selector = config != nullptr &&
        config->action_value_model_kind ==
            FK_COMPACT_ACTION_VALUE_NONE;
    const bool learned_selector = config != nullptr &&
        fk_compact_retention_policy_uses_learned_selector(
            config->baseline_policy.kind);
    const bool learned_detection_loss_per_byte = config != nullptr &&
        config->baseline_policy.kind ==
            FK_COMPACT_POLICY_LEARNED_DETECTION_LOSS_PER_BYTE;
    const bool seeded_random_contract_valid = config != nullptr &&
        (config->baseline_policy.kind ==
             FK_COMPACT_POLICY_SEEDED_RANDOM_RETENTION
            ? config->baseline_policy.seeded_random_seed_precommitted == 1u
            : (config->baseline_policy.seeded_random_seed_precommitted == 0u &&
               config->baseline_policy.seeded_random_seed == 0u));
    const bool transition_value_requested = config != nullptr &&
        (config->transition_value_model_path != nullptr ||
         config->transition_value_schema_sha256 != nullptr ||
         config->transition_value_model_sha256 != nullptr);
    const bool transition_value_complete = config != nullptr &&
        config->transition_value_model_path != nullptr &&
        config->transition_value_schema_sha256 != nullptr &&
        config->transition_value_model_sha256 != nullptr;
    static constexpr uint8_t kZeroReserved[6]{};
    if (config == nullptr || config->maximum_flows == 0u ||
        !seeded_random_contract_valid ||
        !checkpoint_intervention_config_valid(*config) ||
        (!config->full_capacity_state &&
         config->controlled_budget_bytes == 0u) ||
        config->idle_timeout_ns == 0u ||
        config->expiration_scan_per_packet == 0u ||
        config->cache_initial_value_v3 > 1u ||
        config->detector_schema_sha256 == nullptr ||
        config->action_value_model_kind >
            FK_COMPACT_ACTION_VALUE_NONE ||
        std::memcmp(
            config->action_value_model_reserved,
            kZeroReserved,
            sizeof(kZeroReserved)) != 0 ||
        (learned_selector == no_selector) ||
        (no_selector &&
         (config->action_value_model_path != nullptr ||
          config->action_schema_sha256 != nullptr ||
          config->action_value_model_sha256 != nullptr ||
          transition_value_requested ||
          config->action_value_model_v3_expected_role != 0u)) ||
        (!no_selector &&
         (config->action_value_model_path == nullptr ||
          config->action_schema_sha256 == nullptr)) ||
        (value_v3 &&
         (config->action_value_model_v3_expected_role <
                FK_VALUE_MODEL_V3_FLOWKEEP ||
          config->action_value_model_v3_expected_role >
                FK_VALUE_MODEL_V3_DETECTION_LOSS ||
          config->action_value_model_sha256 == nullptr ||
          std::strcmp(
              config->action_schema_sha256,
              FK_VALUE_MODEL_V3_ONLINE_CONTEXT_SCHEMA_SHA256) != 0 ||
          config->policy.checkpoint_count == 0u ||
          config->policy.allow_prospective_late_start != 0u)) ||
        (!value_v3 && !no_selector &&
         config->action_value_model_v3_expected_role != 0u) ||
        (transition_value_requested &&
         (!transition_value_complete || !value_v3 ||
          config->baseline_policy.kind != FK_COMPACT_POLICY_FLOWKEEP ||
          config->action_value_model_v3_expected_role !=
              FK_VALUE_MODEL_V3_FLOWKEEP)) ||
        (learned_detection_loss_per_byte &&
         (!value_v3 ||
          config->action_value_model_v3_expected_role !=
              FK_VALUE_MODEL_V3_DETECTION_LOSS ||
          config->policy.rank_by_marginal_value_per_byte !=
              FK_COMPONENT_RANK_VALUE_PER_BYTE)) ||
        (config->automatic_pressure_enabled != 0u &&
         (config->pressure_exit_percent >= config->pressure_enter_percent ||
          config->pressure_enter_percent >= config->overload_enter_percent ||
          config->overload_exit_percent >= config->overload_enter_percent ||
          config->overload_enter_percent > 100u))) {
        set_error(error, error_capacity, "invalid compact runtime config");
        return nullptr;
    }
    CompactRuntime *runtime = new (std::nothrow) CompactRuntime();
    if (runtime == nullptr) {
        set_error(error, error_capacity, "runtime allocation failed");
        return nullptr;
    }
    runtime->config = *config;
    initialize_checkpoint_intervention_receipt(*runtime);
    bool seven_state = true;
    for (uint8_t mask = 0u; mask < 8u; ++mask)
        seven_state = seven_state &&
            config->detector_state_model_paths[mask] != nullptr;
    if (no_selector) {
        runtime->pipeline = seven_state
            ? fk_cpu_pipeline_create_seven_state_detector_only_verified(
                config->detector_state_model_paths,
                config->detector_schema_sha256,
                error,
                error_capacity)
            : fk_cpu_pipeline_create_detector_only_verified(
                config->detector_model_path,
                config->detector_schema_sha256,
                error,
                error_capacity);
    } else if (value_v3) {
        const fk_value_model_v3_role expected_role =
            static_cast<fk_value_model_v3_role>(
                config->action_value_model_v3_expected_role);
        runtime->pipeline = seven_state
            ? fk_cpu_pipeline_create_seven_state_value_v3_verified(
                config->action_value_model_path,
                config->detector_state_model_paths,
                expected_role,
                config->action_schema_sha256,
                config->action_value_model_sha256,
                config->detector_schema_sha256,
                error,
                error_capacity)
            : fk_cpu_pipeline_create_value_v3_verified(
                config->action_value_model_path,
                config->detector_model_path,
                expected_role,
                config->action_schema_sha256,
                config->action_value_model_sha256,
                config->detector_schema_sha256,
                error,
                error_capacity);
    } else {
        runtime->pipeline = seven_state
            ? fk_cpu_pipeline_create_seven_state_verified(
                config->action_value_model_path,
                config->detector_state_model_paths,
                config->action_schema_sha256,
                config->detector_schema_sha256,
                error,
                error_capacity)
            : fk_cpu_pipeline_create_verified(
                config->action_value_model_path,
                config->detector_model_path,
                config->action_schema_sha256,
                config->detector_schema_sha256,
                error,
                error_capacity);
    }
    if (runtime->pipeline == nullptr) {
        delete runtime;
        return nullptr;
    }
    if (transition_value_requested &&
        !fk_cpu_pipeline_attach_transition_value_verified(
            runtime->pipeline,
            config->transition_value_model_path,
            config->transition_value_schema_sha256,
            config->transition_value_model_sha256,
            error,
            error_capacity)) {
        fk_cpu_pipeline_destroy(runtime->pipeline);
        delete runtime;
        return nullptr;
    }
    uint32_t action_features = 0u;
    uint32_t detector_features = 0u;
    if (!fk_cpu_pipeline_feature_counts(
            runtime->pipeline,
            &action_features,
            &detector_features) ||
        action_features != (no_selector
            ? 0u
            : (value_v3
                ? FK_VALUE_MODEL_V3_CONTEXT_FEATURES
                : FK_COMPACT_ACTION_FEATURES)) ||
        ((!seven_state &&
          detector_features != FK_COMPACT_DETECTOR_FEATURES_V3 &&
          detector_features != FK_COMPACT_DETECTOR_FEATURES_V4) ||
         (seven_state &&
          detector_features != FK_COMPACT_TEACHER_PROJECTED_FEATURES))) {
        fk_cpu_pipeline_destroy(runtime->pipeline);
        delete runtime;
        set_error(
            error,
            error_capacity,
            "compact runtime requires selector-none, 30D, or ABI64 action "
            "contract and the "
            "canonical 119-field V3 or 159-field V4 detector schema");
        return nullptr;
    }
    runtime->seven_state_detectors = seven_state;
    runtime->value_model_v3 = value_v3;
    if (value_v3 && !fk_cpu_pipeline_get_action_uncertainty(
            runtime->pipeline,
            runtime->config.resource_costs.action_uncertainty)) {
        fk_cpu_pipeline_destroy(runtime->pipeline);
        delete runtime;
        set_error(error, error_capacity,
                  "value-v3 uncertainty binding failed");
        return nullptr;
    }
    runtime->detector_feature_count = seven_state
        ? FK_COMPACT_DETECTOR_FEATURES_V4 : detector_features;
    fk_component_pool_weights pool_weights =
        config->pool_weights;
    const uint32_t pool_weight_total =
        static_cast<uint32_t>(pool_weights.stat_percent) +
        pool_weights.seq_percent +
        pool_weights.ja4_pending_percent +
        pool_weights.ja4_summary_percent;
    if (pool_weight_total == 0u)
        pool_weights = {10u, 15u, 60u, 15u};
    runtime->table = config->full_capacity_state
        ? fk_compact_flow_table_create_full_capacity(
            config->maximum_flows,
            &config->policy,
            error,
            error_capacity)
        : fk_compact_flow_table_create_with_pool_weights(
            config->maximum_flows,
            config->controlled_budget_bytes,
            &config->policy,
            &pool_weights,
            error,
            error_capacity);
    if (runtime->table == nullptr) {
        fk_cpu_pipeline_destroy(runtime->pipeline);
        delete runtime;
        return nullptr;
    }
    fk_compact_retention_metadata_mode retention_metadata =
        FK_COMPACT_RETENTION_METADATA_NONE;
    switch (config->baseline_policy.kind) {
    case FK_COMPACT_POLICY_CLOCK:
        retention_metadata = FK_COMPACT_RETENTION_METADATA_CLOCK;
        break;
    case FK_COMPACT_POLICY_TWO_Q:
        retention_metadata = FK_COMPACT_RETENTION_METADATA_TWO_Q;
        break;
    case FK_COMPACT_POLICY_ARC:
        retention_metadata = FK_COMPACT_RETENTION_METADATA_ARC;
        break;
    case FK_COMPACT_POLICY_GDSF:
        retention_metadata = FK_COMPACT_RETENTION_METADATA_GDSF;
        break;
    default:
        break;
    }
    if (!fk_compact_flow_table_set_retention_metadata_mode(
            runtime->table, retention_metadata)) {
        fk_compact_flow_table_destroy(runtime->table);
        fk_cpu_pipeline_destroy(runtime->pipeline);
        delete runtime;
        set_error(error, error_capacity,
                  "retention metadata binding failed");
        return nullptr;
    }
    if (!fk_compact_flow_table_set_capacity_continuation_gap(
            runtime->table, config->idle_timeout_ns)) {
        fk_compact_flow_table_destroy(runtime->table);
        fk_cpu_pipeline_destroy(runtime->pipeline);
        delete runtime;
        set_error(error, error_capacity,
                  "capacity continuation gap binding failed");
        return nullptr;
    }
    return reinterpret_cast<fk_compact_runtime *>(runtime);
}

void fk_compact_runtime_destroy(fk_compact_runtime *runtime) {
    if (runtime == nullptr)
        return;
    CompactRuntime *state = implementation(runtime);
    fk_compact_flow_table_destroy(state->table);
    fk_cpu_pipeline_destroy(state->pipeline);
    delete state;
}

bool fk_compact_runtime_claim_owner_adapter(
        fk_compact_runtime *runtime,
        uintptr_t adapter_token,
        uint16_t fixed_owner) {
    if (runtime == nullptr || adapter_token == 0u)
        return false;
    CompactRuntime &state = *implementation(runtime);
    state.owner_adapter_claim_attempts.fetch_add(
        1u, std::memory_order_relaxed);
    uintptr_t expected = 0u;
    if (!state.owner_adapter_token.compare_exchange_strong(
            expected, adapter_token,
            std::memory_order_acq_rel,
            std::memory_order_acquire)) {
        state.owner_adapter_claim_rejections.fetch_add(
            1u, std::memory_order_relaxed);
        return false;
    }
    state.owner_adapter_fixed_owner_plus_one.store(
        static_cast<uint32_t>(fixed_owner) + 1u,
        std::memory_order_release);
    state.owner_adapter_claim_successes.fetch_add(
        1u, std::memory_order_relaxed);
    return true;
}

bool fk_compact_runtime_validate_owner_adapter_and_account(
        fk_compact_runtime *runtime,
        uintptr_t adapter_token,
        uint16_t fixed_owner) {
    if (runtime == nullptr || adapter_token == 0u)
        return false;
    CompactRuntime &state = *implementation(runtime);
    state.owner_adapter_validation_calls.fetch_add(
        1u, std::memory_order_relaxed);
    const bool valid = state.owner_adapter_token.load(
            std::memory_order_acquire) == adapter_token &&
        state.owner_adapter_fixed_owner_plus_one.load(
            std::memory_order_acquire) ==
                static_cast<uint32_t>(fixed_owner) + 1u;
    if (valid) {
        state.owner_adapter_validation_successes.fetch_add(
            1u, std::memory_order_relaxed);
    } else {
        state.owner_adapter_validation_rejections.fetch_add(
            1u, std::memory_order_relaxed);
    }
    return valid;
}

bool fk_compact_runtime_owner_adapter_scope_begin(
        fk_compact_runtime *runtime,
        uintptr_t adapter_token,
        uint16_t fixed_owner) {
    if (runtime == nullptr)
        return false;
    CompactRuntime &state = *implementation(runtime);
    state.owner_adapter_scope_begin_calls.fetch_add(
        1u, std::memory_order_relaxed);
    if (!owner_capability_matches(
            state, adapter_token, fixed_owner)) {
        state.owner_adapter_scope_begin_rejections.fetch_add(
            1u, std::memory_order_relaxed);
        return false;
    }
    const uint64_t caller_thread = non_reused_thread_token();
    if (caller_thread == 0u) {
        state.owner_adapter_scope_begin_rejections.fetch_add(
            1u, std::memory_order_relaxed);
        return false;
    }
    uint8_t expected = 0u;
    if (!state.owner_adapter_scope_active.compare_exchange_strong(
            expected, 2u,
            std::memory_order_acq_rel,
            std::memory_order_acquire)) {
        state.owner_adapter_scope_begin_rejections.fetch_add(
            1u, std::memory_order_relaxed);
        return false;
    }
    state.owner_adapter_scope_thread_token.store(
        caller_thread, std::memory_order_release);
    state.owner_adapter_scope_active.store(1u, std::memory_order_release);
    state.owner_adapter_scope_begin_successes.fetch_add(
        1u, std::memory_order_relaxed);
    return true;
}

bool fk_compact_runtime_owner_adapter_scope_end(
        fk_compact_runtime *runtime,
        uintptr_t adapter_token,
        uint16_t fixed_owner) {
    if (runtime == nullptr)
        return false;
    CompactRuntime &state = *implementation(runtime);
    state.owner_adapter_scope_end_calls.fetch_add(
        1u, std::memory_order_relaxed);
    if (!owner_capability_matches(
            state, adapter_token, fixed_owner)) {
        state.owner_adapter_scope_end_rejections.fetch_add(
            1u, std::memory_order_relaxed);
        return false;
    }
    const uint64_t caller_thread = non_reused_thread_token();
    if (caller_thread == 0u ||
        state.owner_adapter_scope_thread_token.load(
            std::memory_order_acquire) != caller_thread) {
        state.owner_adapter_scope_end_rejections.fetch_add(
            1u, std::memory_order_relaxed);
        return false;
    }
    uint8_t expected = 1u;
    if (!state.owner_adapter_scope_active.compare_exchange_strong(
            expected, 2u,
            std::memory_order_acq_rel,
            std::memory_order_acquire)) {
        state.owner_adapter_scope_end_rejections.fetch_add(
            1u, std::memory_order_relaxed);
        return false;
    }
    state.owner_adapter_scope_thread_token.store(
        0u, std::memory_order_release);
    state.owner_adapter_scope_active.store(0u, std::memory_order_release);
    state.owner_adapter_scope_end_successes.fetch_add(
        1u, std::memory_order_relaxed);
    return true;
}

bool fk_compact_runtime_owner_adapter_formal_ready(
        const fk_compact_runtime *runtime,
        uintptr_t adapter_token,
        uint16_t fixed_owner) {
    if (runtime == nullptr)
        return false;
    const CompactRuntime &state = *implementation(runtime);
    if (!owner_capability_matches(state, adapter_token, fixed_owner))
        return false;
    const uint64_t claim_attempts =
        state.owner_adapter_claim_attempts.load(std::memory_order_relaxed);
    const uint64_t claim_successes =
        state.owner_adapter_claim_successes.load(std::memory_order_relaxed);
    const uint64_t claim_rejections =
        state.owner_adapter_claim_rejections.load(std::memory_order_relaxed);
    const uint64_t validation_calls =
        state.owner_adapter_validation_calls.load(std::memory_order_relaxed);
    const uint64_t validation_successes =
        state.owner_adapter_validation_successes.load(
            std::memory_order_relaxed);
    const uint64_t validation_rejections =
        state.owner_adapter_validation_rejections.load(
            std::memory_order_relaxed);
    const uint64_t begin_calls =
        state.owner_adapter_scope_begin_calls.load(std::memory_order_relaxed);
    const uint64_t begin_successes =
        state.owner_adapter_scope_begin_successes.load(
            std::memory_order_relaxed);
    const uint64_t begin_rejections =
        state.owner_adapter_scope_begin_rejections.load(
            std::memory_order_relaxed);
    const uint64_t end_calls =
        state.owner_adapter_scope_end_calls.load(std::memory_order_relaxed);
    const uint64_t end_successes =
        state.owner_adapter_scope_end_successes.load(
            std::memory_order_relaxed);
    const uint64_t end_rejections =
        state.owner_adapter_scope_end_rejections.load(
            std::memory_order_relaxed);
    return claim_attempts == claim_successes + claim_rejections &&
        claim_successes == 1u && claim_rejections == 0u &&
        validation_calls == validation_successes + validation_rejections &&
        validation_rejections == 0u &&
        begin_calls == begin_successes + begin_rejections &&
        end_calls == end_successes + end_rejections &&
        begin_successes == end_successes &&
        begin_rejections == 0u && end_rejections == 0u &&
        state.owner_adapter_unscoped_mutation_rejections.load(
            std::memory_order_relaxed) == 0u &&
        state.owner_adapter_foreign_scope_mutation_rejections.load(
            std::memory_order_relaxed) == 0u &&
        state.owner_adapter_scope_thread_token.load(
            std::memory_order_acquire) == 0u &&
        state.owner_adapter_scope_active.load(
            std::memory_order_acquire) == 0u;
}

static fk_compact_runtime_result process_frame_impl(
        fk_compact_runtime *runtime,
        const uint8_t *frame,
        size_t captured_length,
        uint32_t wire_length,
        uint64_t timestamp_ns,
        uint64_t logical_connection_id) {
    if (runtime == nullptr)
        return FK_COMPACT_RUNTIME_STATE_FAILED;
    CompactRuntime &state = *implementation(runtime);
    state.stats.frames++;
    if (!advance_residency_through_optional_deadlines(
            state, timestamp_ns))
        return FK_COMPACT_RUNTIME_STATE_FAILED;
    fk_packet_view view{};
    if (fk_native_parse_ethernet(
            frame, captured_length, wire_length, &view) != FK_PARSE_OK) {
        state.stats.parse_ignored++;
        return FK_COMPACT_RUNTIME_IGNORED;
    }
    if (view.payload_truncated)
        state.stats.payload_truncated_frames++;
    return process_view_impl(
        runtime,
        &view,
        nullptr,
        0u,
        false,
        true,
        timestamp_ns,
        logical_connection_id,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        0u);
}

fk_compact_runtime_result fk_compact_runtime_process_frame(
        fk_compact_runtime *runtime,
        const uint8_t *frame,
        size_t captured_length,
        uint32_t wire_length,
        uint64_t timestamp_ns) {
    if (runtime == nullptr)
        return FK_COMPACT_RUNTIME_STATE_FAILED;
    CompactRuntime &state = *implementation(runtime);
    if (!mutating_api_allowed(state) ||
        !claim_api_mode(state, RuntimeApiMode::V1_ZERO_ID))
        return FK_COMPACT_RUNTIME_STATE_FAILED;
    return process_frame_impl(
        runtime,
        frame,
        captured_length,
        wire_length,
        timestamp_ns,
        0u);
}

fk_compact_runtime_result fk_compact_runtime_process_frame_v2(
        fk_compact_runtime *runtime,
        const uint8_t *frame,
        size_t captured_length,
        uint32_t wire_length,
        uint64_t timestamp_ns,
        const fk_compact_runtime_ingress_identity_v2 *ingress_identity) {
    if (runtime == nullptr || ingress_identity == nullptr)
        return FK_COMPACT_RUNTIME_STATE_FAILED;
    CompactRuntime &state = *implementation(runtime);
    if (!mutating_api_allowed(state) ||
        !claim_api_mode(state, RuntimeApiMode::V2_EXPLICIT_ID))
        return FK_COMPACT_RUNTIME_STATE_FAILED;
    return process_frame_impl(
        runtime,
        frame,
        captured_length,
        wire_length,
        timestamp_ns,
        ingress_identity->logical_connection_id);
}

static fk_compact_runtime_result process_view_impl(
        fk_compact_runtime *runtime,
        const fk_packet_view *view,
        const fk_compact_flow_handle *bound_handle,
        uint8_t bound_feature_direction,
        bool recover_stale_bound,
        bool residency_already_advanced,
        uint64_t timestamp_ns,
        uint64_t logical_connection_id,
    const fk_flow_key *canonical_flow_key_proof,
    fk_compact_runtime_flow_identity_v2 *identity,
    fk_compact_runtime_packet_once_outcome_v2 *packet_once_outcome,
    const fk_flow_key *prederived_observed_key,
    uint8_t prederived_observed_direction) {
    if (identity != nullptr)
        *identity = {};
    if (packet_once_outcome != nullptr)
        *packet_once_outcome = {};
    if (runtime == nullptr || view == nullptr ||
        (bound_handle != nullptr && bound_feature_direction > 1u))
        return FK_COMPACT_RUNTIME_STATE_FAILED;
    CompactRuntime &state = *implementation(runtime);
    if (!residency_already_advanced &&
        !advance_residency_through_optional_deadlines(
            state, timestamp_ns))
        return FK_COMPACT_RUNTIME_STATE_FAILED;
    const uint32_t packet_idle_expirations =
        fk_compact_flow_table_expire_idle(
        state.table,
        timestamp_ns,
        state.config.idle_timeout_ns,
        state.config.expiration_scan_per_packet);
    state.stats.idle_expirations += packet_idle_expirations;
    fk_flow_key observed_key{};
    uint8_t observed_direction = 0u;
    const bool prederived_valid = prederived_observed_key != nullptr &&
        prederived_observed_direction <= 1u;
    if (prederived_valid) {
        observed_key = *prederived_observed_key;
        observed_direction = prederived_observed_direction;
    } else if (fk_native_flow_key(
            view, &observed_key, &observed_direction) != FK_PARSE_OK) {
        if (canonical_flow_key_proof != nullptr)
            state.stats.v2_canonical_key_proof_rejections++;
        state.stats.parse_ignored++;
        return FK_COMPACT_RUNTIME_IGNORED;
    }
    if (canonical_flow_key_proof != nullptr) {
        const bool proof_valid =
            logical_connection_id == 0u &&
            (view->l4_protocol == 6u || view->l4_protocol == 17u) &&
            fk_flow_key_equal(
                &observed_key, canonical_flow_key_proof);
        if (!proof_valid) {
            state.stats.v2_canonical_key_proof_rejections++;
            return FK_COMPACT_RUNTIME_STATE_FAILED;
        }
        state.stats.v2_canonical_key_proof_validations++;
    }
    /* Non-zero logical identities belong to the QUIC/UDP owner path.  This
     * validates the routing domain; it never derives an id from the packet. */
    if (logical_connection_id != 0u && view->l4_protocol != 17u) {
        state.stats.v2_invalid_logical_protocol_rejections++;
        return FK_COMPACT_RUNTIME_STATE_FAILED;
    }
    // Separate investigation tail sees the same valid canonical packet before
    // ordinary R16 admission. Its void/noexcept result cannot alter detection.
    if(logical_connection_id==0u)
        flowkeep::EvidenceContinue(flowkeep::EvidenceFor(state.table),
            &observed_key,observed_direction,view,timestamp_ns);
    bool tcp_epoch_retired = false;
    const fk_compact_flow_handle *effective_bound_handle = bound_handle;
    const bool bare_tcp_syn = view->l4_protocol == 6u &&
        (view->tcp_flags & FK_TCP_FLAG_SYN) != 0u &&
        (view->tcp_flags & FK_TCP_FLAG_ACK) == 0u;
    if (logical_connection_id == 0u && bare_tcp_syn &&
        !fk_compact_flow_table_retire_reused_tcp_tuple(
            state.table,
            &observed_key,
            bound_handle,
            view->tcp_flags,
            view->tcp_sequence,
            timestamp_ns,
            &tcp_epoch_retired)) {
        state.stats.state_update_failures++;
        return FK_COMPACT_RUNTIME_STATE_FAILED;
    }
    if (tcp_epoch_retired)
        effective_bound_handle = nullptr;
    fk_compact_flow_handle handle{};
    bool created = false;
    bool used_bound_handle = false;
    bool recovered_stale_bound =
        tcp_epoch_retired && bound_handle != nullptr;
    uint8_t feature_direction = observed_direction;
    if (effective_bound_handle != nullptr) {
        handle = *effective_bound_handle;
        feature_direction = bound_feature_direction;
        if (!fk_compact_flow_table_handle_valid(state.table, handle)) {
            if (!recover_stale_bound) {
                state.stats.stale_bound_handle_rejects++;
                return FK_COMPACT_RUNTIME_STALE_BOUND_HANDLE;
            }
            recovered_stale_bound = true;
            state.stats.packet_once_stale_bound_handles++;
            if (packet_once_outcome != nullptr)
                packet_once_outcome->stale_bound_handle = 1u;
            feature_direction = observed_direction;
            const bool admitted = logical_connection_id != 0u
                ? fk_compact_flow_table_admit_distinct(
                    state.table,
                    &observed_key,
                    observed_direction,
                    timestamp_ns,
                    &handle)
                : fk_compact_flow_table_lookup_or_admit_scored_only(
                    state.table,
                    &observed_key,
                    observed_direction,
                    timestamp_ns,
                    &handle,
                    &created);
            if (logical_connection_id != 0u && admitted)
                created = true;
            if (!admitted) {
                state.stats.flow_admission_rejects++;
                state.stats.packet_once_recovery_failures++;
                return FK_COMPACT_RUNTIME_ADMISSION_REJECTED;
            }
        } else {
            used_bound_handle = true;
        }
    } else {
        const bool admitted = logical_connection_id != 0u
            ? fk_compact_flow_table_admit_distinct(
                state.table,
                &observed_key,
                observed_direction,
                timestamp_ns,
                &handle)
            : fk_compact_flow_table_lookup_or_admit(
                state.table,
                &observed_key,
                observed_direction,
                timestamp_ns,
                &handle,
                &created);
        if (logical_connection_id != 0u && admitted)
            created = true;
        if (!admitted) {
            state.stats.flow_admission_rejects++;
            return FK_COMPACT_RUNTIME_ADMISSION_REJECTED;
        }
    }
    fk_component_flow *flow =
        fk_compact_flow_table_component_flow(state.table, handle);
    if (flow == nullptr) {
        state.stats.state_update_failures++;
        return FK_COMPACT_RUNTIME_STATE_FAILED;
    }
    const bool bound_final_tail_fast_path =
        used_bound_handle && logical_connection_id == 0u &&
        !bare_tcp_syn && flow->next_checkpoint_packet == 0u &&
        state.config.checkpoint_intervention.enabled == 0u;
    if (bound_final_tail_fast_path) {
        /* This generation is already proven by the caller's exact key and
         * handle.  No later checkpoint can emit FLOW_OPEN, ACTION, or
         * DETECTION output, so retain only the mandatory observation and
         * packet-once receipt work.  Deadline/idle advancement above remains
         * exact, and any TCP epoch-opening SYN deliberately takes the full
         * path. */
        if (identity != nullptr) {
            identity->presentation.handle = handle;
            identity->presentation.handle_available = 1u;
            identity->logical_connection_id = 0u;
        }
        fk_compact_flow_snapshot snapshot{};
        uint8_t first_direction = 0u;
        const bool observed = residency_already_advanced
            ? fk_compact_flow_table_observe_prepared_final_tail_packet(
                state.table,
                handle,
                feature_direction,
                view,
                timestamp_ns,
                &first_direction)
            : fk_compact_flow_table_observe_packet_with_flags(
                state.table,
                handle,
                feature_direction,
                view,
                timestamp_ns,
                FK_COMPACT_OBSERVE_ELIDE_OPTIONAL_AFTER_FINAL_CHECKPOINT,
                nullptr,
                nullptr,
                &snapshot);
        if (!observed) {
            state.stats.state_update_failures++;
            return FK_COMPACT_RUNTIME_STATE_FAILED;
        }
        state.stats.post_final_checkpoint_tail_packets++;
        state.stats.bound_final_tail_fast_path_packets++;
        if (packet_idle_expirations != 0u ||
            state.optional_occupancy_changed_since_pressure_update) {
            update_automatic_pressure(state);
        }
        if (identity != nullptr) {
            identity->presentation.presentation_key =
                residency_already_advanced ? observed_key : snapshot.key;
            identity->presentation.handle = handle;
            identity->presentation.first_canonical_direction =
                residency_already_advanced
                    ? first_direction : snapshot.first_direction;
            identity->presentation.created = 0u;
            identity->presentation.handle_available = 1u;
            identity->presentation.valid = 1u;
            identity->logical_connection_id = 0u;
        }
        if (packet_once_outcome != nullptr) {
            packet_once_outcome->used_bound_handle = 1u;
            packet_once_outcome->no_pending_outputs = 1u;
            /* A completed prepare step proves that all optional-deadline
             * transitions through this timestamp were already drained by
             * the owner.  The final-tail observation itself cannot change
             * optional residency, so only idle expiry can have emitted a
             * transition in this call. */
            if (residency_already_advanced &&
                packet_idle_expirations == 0u) {
                packet_once_outcome->no_pending_evidence_transitions = 1u;
            }
        }
        if (recover_stale_bound)
            state.stats.packet_once_used_bound_handles++;
        return FK_COMPACT_RUNTIME_OBSERVED;
    }
    /* Capture the immutable routing owner before any observation, policy,
     * timer, or rollback path can emit a transition or reclaim this core. */
    /* Ordinary tuple-owned generations are born with identity zero and can
     * never be rebound to a non-zero identity.  Only the QUIC distinct-flow
     * path needs the binding transaction; avoiding the redundant ordinary
     * call also removes a second generation validation from every packet. */
    if (logical_connection_id != 0u &&
        !fk_compact_flow_table_bind_logical_connection_id(
            state.table, handle, logical_connection_id)) {
        state.stats.state_update_failures++;
        if (created && !fk_compact_flow_table_release(state.table, handle))
            state.stats.state_update_failures++;
        return FK_COMPACT_RUNTIME_STATE_FAILED;
    }
    /*
     * A non-zero logical id may enter an existing generation only through a
     * live bound handle.  Initial and stale-recovery admissions deliberately
     * allocate an unindexed distinct generation, so simultaneous QUIC
     * connections can share one UDP tuple.  An explicit-zero ordinary
     * TCP/UDP lookup hit is accepted only through the dedicated canonical-key
     * proof API; generic unbound v2 calls remain fail-closed.
     */
    const bool unbound_existing_v2 =
        state.api_mode == RuntimeApiMode::V2_EXPLICIT_ID && !created &&
        (effective_bound_handle == nullptr || recovered_stale_bound);
    if (unbound_existing_v2 && canonical_flow_key_proof == nullptr) {
        state.stats.v2_unproven_existing_rejections++;
        if (recovered_stale_bound)
            state.stats.packet_once_recovery_failures++;
        return FK_COMPACT_RUNTIME_STATE_FAILED;
    }
    bool capacity_continuation = false;
    fk_compact_capacity_continuation_predecessor
        continuation_predecessor{};
    if (created && logical_connection_id == 0u &&
        !fk_compact_flow_table_resume_capacity_continuation(
            state.table,
            handle,
            view->tcp_flags,
            view->tcp_sequence,
            observed_direction,
            timestamp_ns,
            state.config.idle_timeout_ns,
            &capacity_continuation,
            &continuation_predecessor)) {
        state.stats.state_update_failures++;
        if (!fk_compact_flow_table_release(state.table, handle))
            state.stats.state_update_failures++;
        return FK_COMPACT_RUNTIME_STATE_FAILED;
    }
    if (created &&
        !capacity_continuation &&
        state.config.baseline_policy.kind == FK_COMPACT_POLICY_FIXED_TTL) {
        if (state.config.baseline_policy.fixed_ttl_ns == 0u ||
            !fk_compact_flow_table_set_fixed_ttl(
                state.table,
                handle,
                state.config.baseline_policy.fixed_ttl_ns)) {
            state.stats.fixed_ttl_creation_install_failures++;
            if (!fk_compact_flow_table_release(state.table, handle))
                state.stats.state_update_failures++;
            return FK_COMPACT_RUNTIME_STATE_FAILED;
        }
        state.stats.fixed_ttl_creation_installs++;
    }
    /* Publish the generation cleanup capability at the allocation boundary,
     * before any observation/checkpoint path that can fail.  valid remains
     * zero until this complete call is known to return OBSERVED. */
    if (identity != nullptr) {
        identity->presentation.handle = handle;
        identity->presentation.created = created ? 1u : 0u;
        identity->presentation.handle_available = 1u;
        identity->logical_connection_id = logical_connection_id;
        if (created) {
            identity->presentation.presentation_key = observed_key;
            identity->presentation.first_canonical_direction =
                observed_direction;
        }
    }
    const bool post_final_checkpoint_tail =
        flow->next_checkpoint_packet == 0u;
    fk_compact_flow_snapshot snapshot{};
    /* CORE-only is a physical storage contract, not merely the mask selected
     * at packet four.  Disable provisional TLS at the observation boundary so
     * no optional slab is ever acquired or updated for this baseline. */
    uint32_t observation_flags =
        state.config.baseline_policy.kind == FK_COMPACT_POLICY_CORE_ONLY
        ? 0u : static_cast<uint32_t>(
            FK_COMPACT_OBSERVE_PROVISIONAL_TLS);
    if (post_final_checkpoint_tail) {
        observation_flags |= static_cast<uint32_t>(
            FK_COMPACT_OBSERVE_ELIDE_OPTIONAL_AFTER_FINAL_CHECKPOINT);
    }
    if (!fk_compact_flow_table_observe_packet_with_flags(
            state.table,
            handle,
            feature_direction,
            view,
            timestamp_ns,
            observation_flags,
            nullptr,
            nullptr,
            &snapshot)) {
        state.stats.state_update_failures++;
        if (recovered_stale_bound)
            state.stats.packet_once_recovery_failures++;
        return FK_COMPACT_RUNTIME_STATE_FAILED;
    }
    if (post_final_checkpoint_tail)
        state.stats.post_final_checkpoint_tail_packets++;
    /* Automatic pressure depends only on optional-pool occupancy.  A
     * post-final observation cannot change that occupancy.  Re-evaluate only
     * if this packet crossed an optional deadline or idle-reclaimed a flow;
     * otherwise copying the full allocator receipt on every long-flow tail
     * packet is semantically redundant. */
    if (!post_final_checkpoint_tail || packet_idle_expirations != 0u ||
        state.optional_occupancy_changed_since_pressure_update) {
        update_automatic_pressure(state);
    }
    if (identity != nullptr) {
        identity->presentation.presentation_key = snapshot.key;
        identity->presentation.handle = handle;
        identity->presentation.first_canonical_direction =
            snapshot.first_direction;
        identity->presentation.created = created ? 1u : 0u;
        identity->presentation.handle_available = 1u;
        identity->logical_connection_id = logical_connection_id;
    }
    if (packet_once_outcome != nullptr) {
        if (used_bound_handle)
            packet_once_outcome->used_bound_handle = 1u;
        else if (recovered_stale_bound && created)
            packet_once_outcome->readmitted = 1u;
        else if (recovered_stale_bound)
            packet_once_outcome->rebound_existing = 1u;
    }
    if (recover_stale_bound) {
        if (used_bound_handle)
            state.stats.packet_once_used_bound_handles++;
        else if (recovered_stale_bound && created)
            state.stats.packet_once_readmissions++;
        else if (recovered_stale_bound)
            state.stats.packet_once_rebound_existing++;
    }
    if (created) {
        publish_flow_open_observation(
            state,
            snapshot.key,
            handle,
            snapshot,
            timestamp_ns,
            logical_connection_id,
            capacity_continuation,
            continuation_predecessor);
    }
    const auto &intervention = state.config.checkpoint_intervention;
    auto &intervention_receipt =
        state.stats.checkpoint_intervention;
    const bool intervention_pending = intervention.enabled == 1u &&
        intervention_receipt.applications == 0u;
    if (intervention_pending &&
        timestamp_ns > intervention.observation_timestamp_ns) {
        intervention_receipt.target_missed_before_later_timestamp++;
        state.stats.state_update_failures++;
        return FK_COMPACT_RUNTIME_STATE_FAILED;
    }
    const bool decision_due = fk_component_flow_decision_due(
        flow,
        static_cast<uint32_t>(snapshot.packets),
        timestamp_ns);
    const bool intervention_semantic_actor = intervention_pending &&
        timestamp_ns == intervention.observation_timestamp_ns &&
        logical_connection_id == intervention.logical_connection_id &&
        fk_flow_key_equal(&snapshot.key, &intervention.candidate_key);
    const bool intervention_checkpoint = intervention_semantic_actor &&
        snapshot.packets == intervention.checkpoint_packet;
    if (intervention_checkpoint && !decision_due) {
        intervention_receipt.identity_mismatches++;
        state.stats.checkpoint_controller_failures++;
        state.stats.checkpoint_failures++;
        return FK_COMPACT_RUNTIME_STATE_FAILED;
    }
    if (!decision_due) {
        const bool initial_coverage = (state.first_packet_coverage || state.eof_coverage_deposit) && created &&
            !capacity_continuation && snapshot.packets == 1u;
        if (initial_coverage ||
            (state.prefix_callback != nullptr &&
             snapshot.packets < state.prefix_packet_limit)) {
            float prefix_features[FK_COMPACT_ACTION_FEATURES]{};
            fk_compact_detection_request prefix{};
            if (!fk_compact_flow_table_action_features(
                    state.table, handle, view, state.pressure, prefix_features) ||
                !build_observation_request(state, handle, snapshot,
                                           timestamp_ns, prefix_features, prefix) ||
                !emit_prefix_observation(state, handle, prefix, false))
                return FK_COMPACT_RUNTIME_STATE_FAILED;
            if (initial_coverage) {
                if (state.eof_coverage_deposit) {
                    if (!state.flow_open_pending) return FK_COMPACT_RUNTIME_STATE_FAILED;
                    auto &open=state.pending_flow_open.presentation;
                    open.coverage_prefix_present=1u;
                    std::memcpy(open.coverage_prefix,prefix.features,sizeof(open.coverage_prefix));
                } else {
                // The owner outbox already supports OPEN+DETECTION from one
                // input. Reuse its ordering/backpressure/ACK path; do not
                // inject a late old-timestamp message at Core retirement.
                if (state.detection_pending) {
                    state.stats.checkpoint_failures++;
                    return FK_COMPACT_RUNTIME_STATE_FAILED;
                }
                state.pending_detection = {};
                state.pending_detection.presentation = prefix;
                state.pending_detection.logical_connection_id = logical_connection_id;
                state.detection_pending = true;
                state.stats.detection_windows_ready++;
                }
                state.first_packet_coverage_requests++;
            }
        }
        if (adaptive_detection_candidate(state, snapshot.packets) &&
            !publish_adaptive_candidate(
                state, handle, snapshot, timestamp_ns, *view,
                logical_connection_id)) {
            state.stats.checkpoint_action_feature_failures++;
            state.stats.checkpoint_failures++;
            return FK_COMPACT_RUNTIME_STATE_FAILED;
        }
        if (identity != nullptr)
            identity->presentation.valid = 1u;
        return FK_COMPACT_RUNTIME_OBSERVED;
    }
    bool apply_checkpoint_intervention = false;
    if (intervention_checkpoint) {
        intervention_receipt.semantic_candidate_matches++;
        const bool exact_identity =
            snapshot.first_timestamp_ns ==
                intervention.flow_first_timestamp_ns &&
            handle.index == intervention.flow_index &&
            handle.generation == intervention.flow_generation &&
            snapshot.packets <= UINT32_MAX &&
            static_cast<uint32_t>(snapshot.packets) ==
                intervention.checkpoint_packet &&
            flow->mask == intervention.expected_previous_mask &&
            intervention.forced_requested_mask == flow->mask;
        if (!exact_identity) {
            intervention_receipt.identity_mismatches++;
            state.stats.checkpoint_controller_failures++;
            state.stats.checkpoint_failures++;
            return FK_COMPACT_RUNTIME_STATE_FAILED;
        }
        apply_checkpoint_intervention = true;
    } else if (intervention_semantic_actor &&
               snapshot.packets > intervention.checkpoint_packet) {
        intervention_receipt.identity_mismatches++;
        state.stats.checkpoint_controller_failures++;
        state.stats.checkpoint_failures++;
        return FK_COMPACT_RUNTIME_STATE_FAILED;
    }

    float features[FK_COMPACT_ACTION_FEATURES]{};
    if (!fk_compact_flow_table_action_features(
            state.table,
            handle,
            view,
            state.pressure,
            features)) {
        state.stats.checkpoint_action_feature_failures++;
        state.stats.checkpoint_failures++;
        return FK_COMPACT_RUNTIME_STATE_FAILED;
    }
    fk_compact_controller_result decision{};
    state.stats.checkpoint_decisions++;
    const bool has_ja4_protocol = ja4_applicable(*view);
    const uint64_t flow_age_ns = timestamp_ns >= snapshot.first_timestamp_ns
        ? timestamp_ns - snapshot.first_timestamp_ns : 0u;
    float value_v3_context[FK_VALUE_MODEL_V3_CONTEXT_FEATURES]{};
    const float *value_features = features;
    size_t value_feature_count = FK_COMPACT_ACTION_FEATURES;
    const bool learned_selector =
        fk_compact_retention_policy_uses_learned_selector(
            state.config.baseline_policy.kind);
    const bool transition_head_attached = learned_selector &&
        fk_cpu_pipeline_has_transition_value(state.pipeline);
    const bool transition_refresh_required = transition_head_attached &&
        state.pressure != FK_PRESSURE_NORMAL;
    const bool reuse_frozen_value_v3 = state.value_model_v3 &&
        state.config.cache_initial_value_v3 != 0u &&
        learned_selector && !transition_refresh_required &&
        flow->decision_started != 0u &&
        flow->initial_action_values_valid != 0u &&
        flow->replacement_values_physical == 0u;
    if (state.value_model_v3 && learned_selector) {
        value_features = value_v3_context;
        value_feature_count = FK_VALUE_MODEL_V3_CONTEXT_FEATURES;
        if (reuse_frozen_value_v3) {
            state.stats.value_v3_cache_hits++;
            state.stats.value_v3_inferences_avoided++;
        } else {
            state.stats.value_v3_cache_misses++;
        }
        if (!reuse_frozen_value_v3 && !build_value_v3_context(
                state,
                *flow,
                features,
                has_ja4_protocol,
                snapshot.packets,
                value_v3_context)) {
            state.stats.checkpoint_value_context_failures++;
            state.stats.checkpoint_failures++;
            return FK_COMPACT_RUNTIME_STATE_FAILED;
        }
    }
    const fk_resource_costs decision_resource_costs =
        online_resource_costs(state);
    const bool initial_retention_decision = flow->decision_started == 0u;
    const auto apply_retention_decision = [&]() {
        fk_compact_flow_table_stats intervention_allocator_before{};
        const bool intervention_allocator_before_valid =
            !apply_checkpoint_intervention ||
            fk_compact_flow_table_get_stats(
                state.table, &intervention_allocator_before);
        bool checkpoint_ok = false;
        if (state.checkpoint_release_guard.authorize) {
            // The synchronous owner callback waits for asynchronous WAL writes.
            // No packet re-entry: features, detector ordering, timestamp and
            // packet counters stay on this stack until the decision finishes.
            bool pending = false;
            const auto *guard = &state.checkpoint_release_guard;
            checkpoint_ok = learned_selector
                ? (reuse_frozen_value_v3
                    ? fk_compact_controller_checkpoint_from_values_persistent(
                        state.table, handle, flow->initial_action_values, 8u,
                        &decision_resource_costs, has_ja4_protocol, state.pressure,
                        static_cast<uint32_t>(snapshot.packets), timestamp_ns,
                        &state.config.policy, &decision, guard, &pending)
                    : fk_compact_controller_checkpoint_persistent(
                        state.pipeline, state.table, handle, value_features,
                        value_feature_count, &decision_resource_costs,
                        has_ja4_protocol, state.pressure,
                        static_cast<uint32_t>(snapshot.packets), timestamp_ns,
                        &state.config.policy, &decision, guard, &pending))
                : fk_compact_controller_checkpoint_baseline_persistent(
                    state.table, handle, &decision_resource_costs,
                    has_ja4_protocol, state.pressure,
                    static_cast<uint32_t>(snapshot.packets), timestamp_ns,
                    flow_age_ns, &state.config.policy,
                    &state.config.baseline_policy, &decision, guard, &pending);
            if (!checkpoint_ok || pending) {
                state.stats.checkpoint_controller_failures++;
                state.stats.checkpoint_failures++;
                return false; // Never publish uncommitted action/detection output.
            }
        } else {
        checkpoint_ok = intervention_allocator_before_valid && (
            apply_checkpoint_intervention
            ? fk_compact_controller_checkpoint_keep_existing_intervention(
                state.table, handle, &decision_resource_costs,
                has_ja4_protocol, state.pressure,
                static_cast<uint32_t>(snapshot.packets), timestamp_ns,
                &state.config.policy, &decision)
            : learned_selector
            ? (reuse_frozen_value_v3
                ? fk_compact_controller_checkpoint_from_values(
                    state.table, handle, flow->initial_action_values, 8u,
                    &decision_resource_costs, has_ja4_protocol,
                    state.pressure,
                    static_cast<uint32_t>(snapshot.packets), timestamp_ns,
                    &state.config.policy, &decision)
                : fk_compact_controller_checkpoint(
                    state.pipeline, state.table, handle, value_features,
                    value_feature_count, &decision_resource_costs,
                    has_ja4_protocol, state.pressure,
                    static_cast<uint32_t>(snapshot.packets), timestamp_ns,
                    &state.config.policy, &decision))
            : fk_compact_controller_checkpoint_baseline(
                state.table, handle, &decision_resource_costs,
                has_ja4_protocol, state.pressure,
                static_cast<uint32_t>(snapshot.packets), timestamp_ns,
                flow_age_ns, &state.config.policy,
                &state.config.baseline_policy, &decision));
        }
        state.stats.baseline_lru_victims_released +=
            decision.lru_victims_released;
        state.stats.baseline_lfu_victims_released +=
            decision.lfu_victims_released;
        state.stats.baseline_fifo_victims_released +=
            decision.fifo_victims_released;
        state.stats.baseline_seeded_random_victims_released +=
            decision.seeded_random_victims_released;
        state.stats.baseline_clock_victims_released +=
            decision.clock_victims_released;
        state.stats.baseline_two_q_victims_released +=
            decision.two_q_victims_released;
        state.stats.baseline_arc_victims_released +=
            decision.arc_victims_released;
        state.stats.baseline_gdsf_victims_released +=
            decision.gdsf_victims_released;
        state.stats.transition_value_fallback_attempts +=
            decision.transition_value_fallback_attempted;
        state.stats.transition_value_fallback_successes +=
            decision.transition_value_fallback_succeeded;
        publish_action_record(
            state,
            snapshot.key,
            timestamp_ns,
            snapshot.packets,
            decision);
        if (apply_checkpoint_intervention) {
            fk_compact_flow_table_stats intervention_allocator_after{};
            bool allocator_audit_valid =
                intervention_allocator_before_valid &&
                fk_compact_flow_table_get_stats(
                    state.table, &intervention_allocator_after);
            uint64_t allocation_delta = 0u;
            uint64_t rejection_delta = 0u;
            const auto add_delta = [](
                    uint64_t before, uint64_t after,
                    uint64_t &total) {
                if (after < before || total > UINT64_MAX - (after - before))
                    return false;
                total += after - before;
                return true;
            };
            allocator_audit_valid = allocator_audit_valid &&
                add_delta(
                    intervention_allocator_before.stat_pool_allocations,
                    intervention_allocator_after.stat_pool_allocations,
                    allocation_delta) &&
                add_delta(
                    intervention_allocator_before.seq_pool_allocations,
                    intervention_allocator_after.seq_pool_allocations,
                    allocation_delta) &&
                add_delta(
                    intervention_allocator_before.ja4_pending_pool_allocations,
                    intervention_allocator_after.ja4_pending_pool_allocations,
                    allocation_delta) &&
                add_delta(
                    intervention_allocator_before.ja4_summary_pool_allocations,
                    intervention_allocator_after.ja4_summary_pool_allocations,
                    allocation_delta) &&
                add_delta(
                    intervention_allocator_before.stat_pool_allocation_rejects,
                    intervention_allocator_after.stat_pool_allocation_rejects,
                    rejection_delta) &&
                add_delta(
                    intervention_allocator_before.seq_pool_allocation_rejects,
                    intervention_allocator_after.seq_pool_allocation_rejects,
                    rejection_delta) &&
                add_delta(
                    intervention_allocator_before
                        .ja4_pending_pool_allocation_rejects,
                    intervention_allocator_after
                        .ja4_pending_pool_allocation_rejects,
                    rejection_delta) &&
                add_delta(
                    intervention_allocator_before
                        .ja4_summary_pool_allocation_rejects,
                    intervention_allocator_after
                        .ja4_summary_pool_allocation_rejects,
                    rejection_delta);
            intervention_receipt.candidate_evidence_allocations =
                allocation_delta;
            intervention_receipt
                .candidate_evidence_allocation_rejections = rejection_delta;
            uint64_t alternative_releases =
                static_cast<uint64_t>(decision.value_victims_released) +
                decision.lru_victims_released +
                decision.lfu_victims_released +
                decision.fifo_victims_released +
                decision.seeded_random_victims_released +
                decision.clock_victims_released +
                decision.two_q_victims_released +
                decision.arc_victims_released +
                decision.gdsf_victims_released;
            intervention_receipt.alternative_victim_releases +=
                alternative_releases;
            if (!checkpoint_ok ||
                !allocator_audit_valid || allocation_delta != 0u ||
                rejection_delta != 0u ||
                decision.previous_mask !=
                    intervention.expected_previous_mask ||
                decision.requested_mask !=
                    intervention.forced_requested_mask ||
                decision.final_mask !=
                    intervention.expected_previous_mask ||
                decision.controlled_bytes_after >
                    decision.controlled_bytes_before ||
                decision.value_replacement_attempted != 0u ||
                decision.value_replacement_committed != 0u ||
                decision.value_victims_released != 0u ||
                decision.lru_victims_released != 0u ||
                decision.lfu_victims_released != 0u ||
                decision.fifo_victims_released != 0u ||
                decision.seeded_random_victims_released != 0u ||
                decision.clock_victims_released != 0u ||
                decision.two_q_victims_released != 0u ||
                decision.arc_victims_released != 0u ||
                decision.gdsf_victims_released != 0u) {
                intervention_receipt.controller_failures++;
                checkpoint_ok = false;
            } else {
                bool victims_unchanged = true;
                for (uint32_t victim_index = 0u;
                     victim_index < intervention.victim_count;
                     ++victim_index) {
                    const auto &expected =
                        intervention.victims[victim_index];
                    const fk_compact_flow_handle victim_handle{
                        expected.flow_index, expected.flow_generation};
                    fk_compact_flow_snapshot victim_snapshot{};
                    uint8_t victim_resident_mask = FK_COMPONENT_NONE;
                    uint64_t victim_logical_connection_id = 0u;
                    intervention_receipt.victim_identity_checks++;
                    const bool exact =
                        fk_compact_flow_table_snapshot(
                            state.table, victim_handle, &victim_snapshot) &&
                        fk_compact_flow_table_resident_component_mask(
                            state.table, victim_handle,
                            &victim_resident_mask) &&
                        fk_compact_flow_table_logical_connection_id(
                            state.table, victim_handle,
                            &victim_logical_connection_id) &&
                        fk_flow_key_equal(
                            &victim_snapshot.key, &expected.key) &&
                        victim_snapshot.first_timestamp_ns ==
                            expected.flow_first_timestamp_ns &&
                        victim_logical_connection_id ==
                            expected.logical_connection_id &&
                        victim_resident_mask ==
                            expected.expected_previous_mask &&
                        victim_resident_mask ==
                            expected.expected_intervention_final_mask;
                    if (!exact) {
                        intervention_receipt.victim_identity_mismatches++;
                        victims_unchanged = false;
                    }
                }
                if (!victims_unchanged) {
                    intervention_receipt.controller_failures++;
                    checkpoint_ok = false;
                }
            }
            if (checkpoint_ok) {
                intervention_receipt.applications++;
                /* applications is the sole runtime arm.  Publishing the
                 * disarmed bit in the same successful transaction proves
                 * that every later checkpoint takes the unmodified policy
                 * branch; no persistent override mode exists. */
                intervention_receipt.one_shot_disarmed = 1u;
                intervention_receipt.applied_previous_mask =
                    decision.previous_mask;
                intervention_receipt.applied_requested_mask =
                    decision.requested_mask;
                intervention_receipt.applied_final_mask =
                    decision.final_mask;
                intervention_receipt.applied_controlled_bytes_before =
                    decision.controlled_bytes_before;
                intervention_receipt.applied_controlled_bytes_after =
                    decision.controlled_bytes_after;
                intervention_receipt.complete = 1u;
            }
        } else if (checkpoint_ok && intervention.enabled == 1u &&
                   intervention_receipt.applications == 1u &&
                   intervention_receipt.one_shot_disarmed == 1u) {
            intervention_receipt
                .post_intervention_original_policy_decisions++;
        }
        if (!checkpoint_ok) {
            if (decision.decision.result == FK_TRANSITION_STORAGE_FAILED)
                state.stats.component_sync_failures++;
            state.stats.checkpoint_controller_failures++;
            state.stats.checkpoint_failures++;
        }
        return checkpoint_ok;
    };
    /* Packet 4 admits the initial evidence bundle before it can be observed
     * by the detector.  At later checkpoints, evidence retained throughout
     * the just-finished interval belongs to the current causal observation;
     * the new action governs only the next interval.  Releasing first used
     * to erase already-observed evidence from the same checkpoint and made
     * FLOWKEEP lose recall specifically when it chose to save memory. */
    if (initial_retention_decision && !apply_retention_decision())
        return FK_COMPACT_RUNTIME_STATE_FAILED;
    fk_compact_detection_request request{};
    if (!build_observation_request(state, handle, snapshot,
                                   timestamp_ns, features, request) ||
        !emit_prefix_observation(state, handle, request, true))
        return FK_COMPACT_RUNTIME_STATE_FAILED;
    if (!initial_retention_decision && !apply_retention_decision())
        return FK_COMPACT_RUNTIME_STATE_FAILED;
    if (!state.adaptive_detection_candidates ||
        adaptive_detection_candidate(state, snapshot.packets)) {
        if (state.detection_pending)
            state.stats.detection_windows_overwritten++;
        state.pending_detection = {};
        state.pending_detection.presentation = request;
        state.pending_detection.logical_connection_id =
            logical_connection_id;
        state.detection_pending = true;
        state.stats.detection_windows_ready++;
    }
    if (identity != nullptr)
        identity->presentation.valid = 1u;
    return FK_COMPACT_RUNTIME_OBSERVED;
}

fk_compact_runtime_result fk_compact_runtime_process_view(
        fk_compact_runtime *runtime,
        const fk_packet_view *view,
        uint64_t timestamp_ns) {
    if (runtime == nullptr)
        return FK_COMPACT_RUNTIME_STATE_FAILED;
    CompactRuntime &state = *implementation(runtime);
    if (!mutating_api_allowed(state) ||
        !claim_api_mode(state, RuntimeApiMode::V1_ZERO_ID))
        return FK_COMPACT_RUNTIME_STATE_FAILED;
    return process_view_impl(
        runtime,
        view,
        nullptr,
        0u,
        false,
        false,
        timestamp_ns,
        0u,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        0u);
}

fk_compact_runtime_result fk_compact_runtime_process_view_v2(
        fk_compact_runtime *runtime,
        const fk_packet_view *view,
        uint64_t timestamp_ns,
        const fk_compact_runtime_ingress_identity_v2 *ingress_identity) {
    if (runtime == nullptr || ingress_identity == nullptr)
        return FK_COMPACT_RUNTIME_STATE_FAILED;
    CompactRuntime &state = *implementation(runtime);
    if (!mutating_api_allowed(state) ||
        !claim_api_mode(state, RuntimeApiMode::V2_EXPLICIT_ID))
        return FK_COMPACT_RUNTIME_STATE_FAILED;
    return process_view_impl(
        runtime,
        view,
        nullptr,
        0u,
        false,
        false,
        timestamp_ns,
        ingress_identity->logical_connection_id,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        0u);
}

fk_compact_runtime_result fk_compact_runtime_process_parsed_packet(
        fk_compact_runtime *runtime,
        const fk_packet_view *view,
        uint64_t timestamp_ns,
        fk_compact_runtime_flow_identity *identity) {
    if (identity != nullptr)
        *identity = {};
    if (runtime == nullptr)
        return FK_COMPACT_RUNTIME_STATE_FAILED;
    CompactRuntime &state = *implementation(runtime);
    if (!mutating_api_allowed(state) ||
        !claim_api_mode(state, RuntimeApiMode::V1_ZERO_ID))
        return FK_COMPACT_RUNTIME_STATE_FAILED;
    fk_compact_runtime_flow_identity_v2 identity_v2{};
    state.stats.frames++;
    const fk_compact_runtime_result result = process_view_impl(
        runtime,
        view,
        nullptr,
        0u,
        false,
        false,
        timestamp_ns,
        0u,
        nullptr,
        identity == nullptr ? nullptr : &identity_v2,
        nullptr,
        nullptr,
        0u);
    if (identity != nullptr)
        *identity = identity_v2.presentation;
    return result;
}

static fk_compact_runtime_result process_cached_packet_impl(
        fk_compact_runtime *runtime,
        const fk_packet_view *view,
        const fk_flow_key *cached_key,
        fk_compact_flow_handle cached_handle,
        uint64_t timestamp_ns,
        fk_compact_runtime_packet_once_outcome *outcome,
        bool *cache_hit,
        bool residency_already_advanced) {
    if (outcome != nullptr)
        *outcome = {};
    if (cache_hit != nullptr)
        *cache_hit = false;
    if (runtime == nullptr || view == nullptr)
        return FK_COMPACT_RUNTIME_STATE_FAILED;
    CompactRuntime &state = *implementation(runtime);
    if (!mutating_api_allowed(state) ||
        !claim_api_mode(state, RuntimeApiMode::V1_ZERO_ID))
        return FK_COMPACT_RUNTIME_STATE_FAILED;
    if (view->payload_truncated)
        state.stats.payload_truncated_frames++;

    fk_flow_key observed_key{};
    uint8_t observed_direction = 0u;
    const bool observed_key_valid = fk_native_flow_key(
        view, &observed_key, &observed_direction) == FK_PARSE_OK;
    const bool hit = observed_key_valid && cached_key != nullptr &&
        fk_flow_key_equal(&observed_key, cached_key);
    if (cache_hit != nullptr)
        *cache_hit = hit;

    fk_compact_runtime_packet_once_outcome_v2 outcome_v2{};
    fk_compact_runtime_flow_identity_v2 *identity =
        outcome == nullptr ? nullptr : &outcome_v2.identity;
    state.stats.frames++;
    state.stats.packet_once_calls++;
    if (hit)
        state.stats.bound_handle_calls++;
    const fk_compact_runtime_result result = process_view_impl(
        runtime,
        view,
        hit ? &cached_handle : nullptr,
        observed_direction,
        hit,
        residency_already_advanced,
        timestamp_ns,
        0u,
        nullptr,
        identity,
        outcome == nullptr ? nullptr : &outcome_v2,
        observed_key_valid ? &observed_key : nullptr,
        observed_direction);
    if (hit) {
        if (result == FK_COMPACT_RUNTIME_OBSERVED)
            state.stats.bound_handle_successes++;
        else
            state.stats.bound_handle_other_failures++;
    }
    if (outcome != nullptr) {
        outcome->identity = outcome_v2.identity.presentation;
        outcome->used_bound_handle = outcome_v2.used_bound_handle;
        outcome->stale_bound_handle = outcome_v2.stale_bound_handle;
        outcome->rebound_existing = outcome_v2.rebound_existing;
        outcome->readmitted = outcome_v2.readmitted;
        outcome->no_pending_outputs = outcome_v2.no_pending_outputs;
        outcome->no_pending_evidence_transitions =
            outcome_v2.no_pending_evidence_transitions;
    }
    return result;
}

fk_compact_runtime_result fk_compact_runtime_process_cached_packet(
        fk_compact_runtime *runtime,
        const fk_packet_view *view,
        const fk_flow_key *cached_key,
        fk_compact_flow_handle cached_handle,
        uint64_t timestamp_ns,
        fk_compact_runtime_packet_once_outcome *outcome,
        bool *cache_hit) {
    return process_cached_packet_impl(
        runtime,
        view,
        cached_key,
        cached_handle,
        timestamp_ns,
        outcome,
        cache_hit,
        false);
}

fk_compact_runtime_result fk_compact_runtime_process_prepared_cached_packet(
        fk_compact_runtime *runtime,
        const fk_packet_view *view,
        const fk_flow_key *cached_key,
        fk_compact_flow_handle cached_handle,
        uint64_t timestamp_ns,
        fk_compact_runtime_packet_once_outcome *outcome,
        bool *cache_hit) {
    return process_cached_packet_impl(
        runtime,
        view,
        cached_key,
        cached_handle,
        timestamp_ns,
        outcome,
        cache_hit,
        true);
}

bool fk_compact_runtime_final_tail_batch_limit_diagnostic(
        fk_compact_runtime *runtime,
        const fk_flow_key *cached_key,
        fk_compact_flow_handle cached_handle,
        uint64_t *exclusive_timestamp_ns,
        fk_compact_tail_limit_reason *reason) {
    const auto reject = [&](fk_compact_tail_limit_reason value) {
        if (reason != nullptr) *reason = value;
        return false;
    };
    if (exclusive_timestamp_ns != nullptr)
        *exclusive_timestamp_ns = 0u;
    if (runtime == nullptr || cached_key == nullptr ||
        exclusive_timestamp_ns == nullptr)
        return reject(FK_TAIL_LIMIT_INVALID_REQUEST);
    CompactRuntime &state = *implementation(runtime);
    if (!mutating_api_allowed(state) ||
        state.api_mode != RuntimeApiMode::V1_ZERO_ID ||
        state.config.checkpoint_intervention.enabled != 0u)
        return reject(FK_TAIL_LIMIT_RUNTIME_MODE);
    if (state.optional_occupancy_changed_since_pressure_update)
        return reject(FK_TAIL_LIMIT_OCCUPANCY_CHANGED);
    fk_compact_flow_snapshot snapshot{};
    if (!fk_compact_flow_table_snapshot(
            state.table, cached_handle, &snapshot))
        return reject(FK_TAIL_LIMIT_HANDLE);
    if (snapshot.next_checkpoint_packet != 0u)
        return reject(FK_TAIL_LIMIT_CHECKPOINT);
    if (!fk_flow_key_equal(&snapshot.key, cached_key))
        return reject(FK_TAIL_LIMIT_KEY);
    uint64_t limit = 0u;
    if (!fk_compact_flow_table_idle_scan_not_before(
            state.table, &limit))
        return reject(FK_TAIL_LIMIT_IDLE_SCAN);
    const uint64_t idle_limit = limit;
    uint64_t deadline_ns = 0u;
    if (fk_compact_flow_table_next_optional_timer_deadline(
            state.table,
            state.semantic_time_initialized
                ? state.semantic_last_timestamp_ns : 0u,
            UINT64_MAX,
            &deadline_ns)) {
        limit = std::min(limit, deadline_ns);
    }
    if (state.semantic_time_initialized &&
        limit <= state.semantic_last_timestamp_ns)
        return reject(idle_limit <= state.semantic_last_timestamp_ns
            ? FK_TAIL_LIMIT_IDLE_SCAN : FK_TAIL_LIMIT_OPTIONAL_TIMER);
    *exclusive_timestamp_ns = limit;
    if (reason != nullptr) *reason = FK_TAIL_LIMIT_READY;
    return true;
}

bool fk_compact_runtime_final_tail_batch_limit(
        fk_compact_runtime *runtime, const fk_flow_key *cached_key,
        fk_compact_flow_handle cached_handle, uint64_t *exclusive_timestamp_ns) {
    return fk_compact_runtime_final_tail_batch_limit_diagnostic(
        runtime, cached_key, cached_handle, exclusive_timestamp_ns, nullptr);
}

bool fk_compact_runtime_demote_terminal_core(
        fk_compact_runtime *runtime,
        const fk_flow_key *cached_key,
        fk_compact_flow_handle cached_handle,
        bool *demoted) {
    if (demoted != nullptr)
        *demoted = false;
    if (runtime == nullptr || cached_key == nullptr || demoted == nullptr)
        return false;
    CompactRuntime &state = *implementation(runtime);
    if (!mutating_api_allowed(state) ||
        state.api_mode != RuntimeApiMode::V1_ZERO_ID ||
        state.config.baseline_policy.kind != FK_COMPACT_POLICY_FLOWKEEP ||
        state.config.checkpoint_intervention.enabled != 0u ||
        !state.semantic_time_initialized ||
        !state.semantic_time_complete ||
        state.flow_open_pending || state.detection_pending ||
        state.action_pending ||
        state.optional_occupancy_changed_since_pressure_update) {
        return false;
    }
    fk_compact_flow_table_stats table_stats{};
    if (!fk_compact_flow_table_get_stats(state.table, &table_stats) ||
        table_stats.transition_queue_pending != 0u) {
        return false;
    }
    fk_compact_flow_snapshot snapshot{};
    if (!fk_compact_flow_table_snapshot(
            state.table, cached_handle, &snapshot) ||
        !fk_flow_key_equal(&snapshot.key, cached_key)) {
        return false;
    }
    return fk_compact_flow_table_demote_terminal_core(
        state.table,
        cached_handle,
        state.semantic_last_timestamp_ns,
        demoted);
}

fk_compact_runtime_result fk_compact_runtime_process_final_tail_batch(
        fk_compact_runtime *runtime,
        const fk_flow_key *cached_key,
        fk_compact_flow_handle cached_handle,
        const fk_compact_final_tail_observation *observations,
        uint32_t count,
        fk_compact_runtime_packet_once_outcome *outcome) {
    if (outcome != nullptr)
        *outcome = {};
    if (runtime == nullptr || cached_key == nullptr ||
        observations == nullptr || count == 0u ||
        count > FK_COMPACT_FINAL_TAIL_BATCH_MAX)
        return FK_COMPACT_RUNTIME_STATE_FAILED;
    CompactRuntime &state = *implementation(runtime);
    uint64_t exclusive_limit = 0u;
    if (!fk_compact_runtime_final_tail_batch_limit(
            runtime, cached_key, cached_handle, &exclusive_limit))
        return FK_COMPACT_RUNTIME_STATE_FAILED;
    uint64_t previous_timestamp_ns = state.semantic_time_initialized
        ? state.semantic_last_timestamp_ns : 0u;
    uint64_t payload_truncated = 0u;
    for (uint32_t index = 0u; index < count; ++index) {
        const fk_compact_final_tail_observation &observation =
            observations[index];
        if ((state.semantic_time_initialized || index != 0u) &&
            observation.timestamp_ns < previous_timestamp_ns)
            return FK_COMPACT_RUNTIME_STATE_FAILED;
        if (observation.timestamp_ns >= exclusive_limit)
            return FK_COMPACT_RUNTIME_STATE_FAILED;
        if (observation.l4_protocol == 6u &&
            (observation.tcp_flags & FK_TCP_FLAG_SYN) != 0u &&
            (observation.tcp_flags & FK_TCP_FLAG_ACK) == 0u)
            return FK_COMPACT_RUNTIME_STATE_FAILED;
        previous_timestamp_ns = observation.timestamp_ns;
        payload_truncated += observation.payload_truncated != 0u ? 1u : 0u;
    }
    if (!advance_residency_accounting(
            state, observations[count - 1u].timestamp_ns))
        return FK_COMPACT_RUNTIME_STATE_FAILED;
    uint8_t first_direction = 0u;
    if (!fk_compact_flow_table_observe_prepared_final_tail_batch(
            state.table,
            cached_handle,
            observations,
            count,
            &first_direction)) {
        state.stats.state_update_failures++;
        return FK_COMPACT_RUNTIME_STATE_FAILED;
    }
    state.stats.frames += count;
    state.stats.payload_truncated_frames += payload_truncated;
    state.stats.packet_once_calls += count;
    state.stats.bound_handle_calls += count;
    state.stats.bound_handle_successes += count;
    state.stats.packet_once_used_bound_handles += count;
    state.stats.post_final_checkpoint_tail_packets += count;
    state.stats.bound_final_tail_fast_path_packets += count;
    state.stats.final_tail_batch_calls++;
    state.stats.final_tail_batch_packets += count;
    if (outcome != nullptr) {
        outcome->identity.presentation_key = *cached_key;
        outcome->identity.handle = cached_handle;
        outcome->identity.first_canonical_direction = first_direction;
        outcome->identity.valid = 1u;
        outcome->identity.handle_available = 1u;
        outcome->used_bound_handle = 1u;
        outcome->no_pending_outputs = 1u;
        outcome->no_pending_evidence_transitions = 1u;
    }
    return FK_COMPACT_RUNTIME_OBSERVED;
}

fk_compact_runtime_result fk_compact_runtime_process_final_tail_delta(
        fk_compact_runtime *runtime,
        const fk_flow_key *cached_key,
        fk_compact_flow_handle cached_handle,
        const fk_compact_final_tail_delta *delta,
        fk_compact_runtime_packet_once_outcome *outcome) {
    if (outcome != nullptr)
        *outcome = {};
    if (runtime == nullptr || cached_key == nullptr || delta == nullptr ||
        delta->packet_count == 0u ||
        delta->payload_truncated_frames > delta->packet_count ||
        delta->first_timestamp_ns > delta->last_timestamp_ns)
        return FK_COMPACT_RUNTIME_STATE_FAILED;
    CompactRuntime &state = *implementation(runtime);
    uint64_t exclusive_limit = 0u;
    if (!fk_compact_runtime_final_tail_batch_limit(
            runtime, cached_key, cached_handle, &exclusive_limit) ||
        (state.semantic_time_initialized &&
         delta->first_timestamp_ns < state.semantic_last_timestamp_ns) ||
        delta->last_timestamp_ns >= exclusive_limit)
        return FK_COMPACT_RUNTIME_STATE_FAILED;
    if (!advance_residency_accounting(state, delta->last_timestamp_ns))
        return FK_COMPACT_RUNTIME_STATE_FAILED;
    uint8_t first_direction = 0u;
    if (!fk_compact_flow_table_apply_prepared_final_tail_delta(
            state.table,
            cached_handle,
            delta,
            &first_direction)) {
        state.stats.state_update_failures++;
        return FK_COMPACT_RUNTIME_STATE_FAILED;
    }
    state.stats.frames += delta->packet_count;
    state.stats.payload_truncated_frames +=
        delta->payload_truncated_frames;
    state.stats.packet_once_calls += delta->packet_count;
    state.stats.bound_handle_calls += delta->packet_count;
    state.stats.bound_handle_successes += delta->packet_count;
    state.stats.packet_once_used_bound_handles += delta->packet_count;
    state.stats.post_final_checkpoint_tail_packets += delta->packet_count;
    state.stats.bound_final_tail_fast_path_packets += delta->packet_count;
    state.stats.final_tail_batch_calls++;
    state.stats.final_tail_batch_packets += delta->packet_count;
    if (outcome != nullptr) {
        outcome->identity.presentation_key = *cached_key;
        outcome->identity.handle = cached_handle;
        outcome->identity.first_canonical_direction = first_direction;
        outcome->identity.valid = 1u;
        outcome->identity.handle_available = 1u;
        outcome->used_bound_handle = 1u;
        outcome->no_pending_outputs = 1u;
        outcome->no_pending_evidence_transitions = 1u;
    }
    return FK_COMPACT_RUNTIME_OBSERVED;
}

fk_compact_runtime_result fk_compact_runtime_process_parsed_packet_v2(
        fk_compact_runtime *runtime,
        const fk_packet_view *view,
        uint64_t timestamp_ns,
        const fk_compact_runtime_ingress_identity_v2 *ingress_identity,
        fk_compact_runtime_flow_identity_v2 *identity) {
    if (identity != nullptr)
        *identity = {};
    if (runtime == nullptr || ingress_identity == nullptr)
        return FK_COMPACT_RUNTIME_STATE_FAILED;
    CompactRuntime &state = *implementation(runtime);
    if (!mutating_api_allowed(state) ||
        !claim_api_mode(state, RuntimeApiMode::V2_EXPLICIT_ID))
        return FK_COMPACT_RUNTIME_STATE_FAILED;
    state.stats.frames++;
    return process_view_impl(
        runtime,
        view,
        nullptr,
        0u,
        false,
        false,
        timestamp_ns,
        ingress_identity->logical_connection_id,
        nullptr,
        identity,
        nullptr,
        nullptr,
        0u);
}

fk_compact_runtime_result
fk_compact_runtime_process_canonical_packet_v2(
        fk_compact_runtime *runtime,
        const fk_packet_view *view,
        uint64_t timestamp_ns,
        const fk_compact_runtime_ingress_identity_v2 *ingress_identity,
        const fk_flow_key *canonical_flow_key_proof,
        fk_compact_runtime_flow_identity_v2 *identity) {
    if (identity != nullptr)
        *identity = {};
    if (runtime == nullptr)
        return FK_COMPACT_RUNTIME_STATE_FAILED;
    CompactRuntime &state = *implementation(runtime);
    if (!mutating_api_allowed(state) ||
        !claim_api_mode(state, RuntimeApiMode::V2_EXPLICIT_ID))
        return FK_COMPACT_RUNTIME_STATE_FAILED;
    state.stats.v2_canonical_key_proof_calls++;
    if (view == nullptr || ingress_identity == nullptr ||
        canonical_flow_key_proof == nullptr) {
        state.stats.v2_canonical_key_proof_rejections++;
        return FK_COMPACT_RUNTIME_STATE_FAILED;
    }
    state.stats.frames++;
    const uint64_t validations_before =
        state.stats.v2_canonical_key_proof_validations;
    const uint64_t rejections_before =
        state.stats.v2_canonical_key_proof_rejections;
    const fk_compact_runtime_result result = process_view_impl(
        runtime,
        view,
        nullptr,
        0u,
        false,
        false,
        timestamp_ns,
        ingress_identity->logical_connection_id,
        canonical_flow_key_proof,
        identity,
        nullptr,
        nullptr,
        0u);
    /* Timestamp regression and any future pre-validation early return must
     * still terminate the proof receipt exactly once.  Runtime is fixed-owner
     * and therefore has no concurrent writer to these counters. */
    if (state.stats.v2_canonical_key_proof_validations ==
            validations_before &&
        state.stats.v2_canonical_key_proof_rejections ==
            rejections_before)
        state.stats.v2_canonical_key_proof_rejections++;
    return result;
}

fk_compact_runtime_result fk_compact_runtime_process_bound_view(
        fk_compact_runtime *runtime,
        const fk_packet_view *view,
        fk_compact_flow_handle handle,
        uint8_t canonical_direction_in_presentation_axis,
        uint64_t timestamp_ns) {
    if (runtime == nullptr)
        return FK_COMPACT_RUNTIME_STATE_FAILED;
    CompactRuntime &state = *implementation(runtime);
    if (!mutating_api_allowed(state) ||
        !claim_api_mode(state, RuntimeApiMode::V1_ZERO_ID))
        return FK_COMPACT_RUNTIME_STATE_FAILED;
    state.stats.frames++;
    state.stats.bound_handle_calls++;
    const fk_compact_runtime_result result = process_view_impl(
        runtime,
        view,
        &handle,
        canonical_direction_in_presentation_axis,
        false,
        false,
        timestamp_ns,
        0u,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        0u);
    if (result == FK_COMPACT_RUNTIME_OBSERVED)
        state.stats.bound_handle_successes++;
    else if (result != FK_COMPACT_RUNTIME_STALE_BOUND_HANDLE)
        state.stats.bound_handle_other_failures++;
    return result;
}

fk_compact_runtime_result fk_compact_runtime_process_bound_view_v2(
        fk_compact_runtime *runtime,
        const fk_packet_view *view,
        fk_compact_flow_handle handle,
        uint8_t canonical_direction_in_presentation_axis,
        uint64_t timestamp_ns,
        const fk_compact_runtime_ingress_identity_v2 *caller_identity_proof) {
    if (runtime == nullptr || caller_identity_proof == nullptr)
        return FK_COMPACT_RUNTIME_STATE_FAILED;
    CompactRuntime &state = *implementation(runtime);
    if (!mutating_api_allowed(state) ||
        !claim_api_mode(state, RuntimeApiMode::V2_EXPLICIT_ID))
        return FK_COMPACT_RUNTIME_STATE_FAILED;
    /* Unlike the legacy synthetic-view API, each bound view represents one
     * packet already parsed by the shared CID/owner ingress stage. */
    state.stats.frames++;
    state.stats.bound_handle_calls++;
    const fk_compact_runtime_result result = process_view_impl(
        runtime,
        view,
        &handle,
        canonical_direction_in_presentation_axis,
        false,
        false,
        timestamp_ns,
        caller_identity_proof->logical_connection_id,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        0u);
    if (result == FK_COMPACT_RUNTIME_OBSERVED)
        state.stats.bound_handle_successes++;
    else if (result != FK_COMPACT_RUNTIME_STALE_BOUND_HANDLE)
        state.stats.bound_handle_other_failures++;
    return result;
}

fk_compact_runtime_result fk_compact_runtime_process_packet_once(
        fk_compact_runtime *runtime,
        const fk_packet_view *view,
        fk_compact_flow_handle bound_handle,
        uint8_t canonical_direction_in_presentation_axis,
        uint64_t timestamp_ns,
        fk_compact_runtime_packet_once_outcome *outcome) {
    if (outcome != nullptr)
        *outcome = {};
    if (runtime == nullptr)
        return FK_COMPACT_RUNTIME_STATE_FAILED;
    CompactRuntime &state = *implementation(runtime);
    if (!mutating_api_allowed(state) ||
        !claim_api_mode(state, RuntimeApiMode::V1_ZERO_ID))
        return FK_COMPACT_RUNTIME_STATE_FAILED;
    fk_compact_runtime_packet_once_outcome_v2 outcome_v2{};
    state.stats.frames++;
    state.stats.bound_handle_calls++;
    state.stats.packet_once_calls++;
    fk_compact_runtime_flow_identity_v2 *identity =
        outcome == nullptr ? nullptr : &outcome_v2.identity;
    const fk_compact_runtime_result result = process_view_impl(
        runtime,
        view,
        &bound_handle,
        canonical_direction_in_presentation_axis,
        true,
        false,
        timestamp_ns,
        0u,
        nullptr,
        identity,
        outcome == nullptr ? nullptr : &outcome_v2,
        nullptr,
        0u);
    if (result == FK_COMPACT_RUNTIME_OBSERVED)
        state.stats.bound_handle_successes++;
    else
        state.stats.bound_handle_other_failures++;
    if (outcome != nullptr) {
        outcome->identity = outcome_v2.identity.presentation;
        outcome->used_bound_handle = outcome_v2.used_bound_handle;
        outcome->stale_bound_handle = outcome_v2.stale_bound_handle;
        outcome->rebound_existing = outcome_v2.rebound_existing;
        outcome->readmitted = outcome_v2.readmitted;
        outcome->no_pending_outputs = outcome_v2.no_pending_outputs;
        outcome->no_pending_evidence_transitions =
            outcome_v2.no_pending_evidence_transitions;
    }
    return result;
}

fk_compact_runtime_result fk_compact_runtime_process_packet_once_v2(
        fk_compact_runtime *runtime,
        const fk_packet_view *view,
        fk_compact_flow_handle bound_handle,
        uint8_t canonical_direction_in_presentation_axis,
        uint64_t timestamp_ns,
        const fk_compact_runtime_ingress_identity_v2 *caller_identity_proof,
        fk_compact_runtime_packet_once_outcome_v2 *outcome) {
    if (outcome != nullptr)
        *outcome = {};
    if (runtime == nullptr || caller_identity_proof == nullptr)
        return FK_COMPACT_RUNTIME_STATE_FAILED;
    CompactRuntime &state = *implementation(runtime);
    if (!mutating_api_allowed(state) ||
        !claim_api_mode(state, RuntimeApiMode::V2_EXPLICIT_ID))
        return FK_COMPACT_RUNTIME_STATE_FAILED;
    state.stats.frames++;
    state.stats.bound_handle_calls++;
    state.stats.packet_once_calls++;
    fk_compact_runtime_flow_identity_v2 *identity =
        outcome == nullptr ? nullptr : &outcome->identity;
    const fk_compact_runtime_result result = process_view_impl(
        runtime,
        view,
        &bound_handle,
        canonical_direction_in_presentation_axis,
        true,
        false,
        timestamp_ns,
        caller_identity_proof->logical_connection_id,
        nullptr,
        identity,
        outcome,
        nullptr,
        0u);
    if (result == FK_COMPACT_RUNTIME_OBSERVED)
        state.stats.bound_handle_successes++;
    else
        state.stats.bound_handle_other_failures++;
    return result;
}

fk_compact_runtime_flow_release_result
fk_compact_runtime_release_bound_flow(
        fk_compact_runtime *runtime,
        fk_compact_flow_handle handle,
        uint64_t retirement_timestamp_ns) {
    if (runtime == nullptr)
        return FK_COMPACT_RUNTIME_FLOW_RELEASE_INVALID;
    CompactRuntime &state = *implementation(runtime);
    if (!mutating_api_allowed(state))
        return FK_COMPACT_RUNTIME_FLOW_RELEASE_INVALID;
    state.stats.bound_flow_release_calls++;
    const bool time_regression = state.semantic_time_initialized &&
        retirement_timestamp_ns < state.semantic_last_timestamp_ns;
    if (!advance_residency_through_optional_deadlines(
            state, retirement_timestamp_ns)) {
        if (time_regression) {
            state.stats.bound_flow_release_time_regressions++;
            return FK_COMPACT_RUNTIME_FLOW_RELEASE_TIME_REGRESSION;
        }
        state.stats.bound_flow_release_failures++;
        return FK_COMPACT_RUNTIME_FLOW_RELEASE_FAILED;
    }
    if (handle.generation == 0u) {
        state.stats.bound_flow_release_already_absent++;
        state.stats.bound_flow_release_proven_absent++;
        return FK_COMPACT_RUNTIME_FLOW_RELEASE_ALREADY_ABSENT;
    }
    if (!fk_compact_flow_table_handle_valid(state.table, handle)) {
        state.stats.bound_flow_release_already_absent++;
        return FK_COMPACT_RUNTIME_FLOW_RELEASE_ALREADY_ABSENT;
    }
    if (!fk_compact_flow_table_release(state.table, handle)) {
        state.stats.bound_flow_release_failures++;
        return FK_COMPACT_RUNTIME_FLOW_RELEASE_FAILED;
    }
    state.stats.bound_flow_releases++;
    return FK_COMPACT_RUNTIME_FLOW_RELEASE_RELEASED;
}

bool fk_compact_runtime_advance_semantic_time(
        fk_compact_runtime *runtime,
        uint64_t timestamp_ns) {
    if (runtime == nullptr)
        return false;
    CompactRuntime &state = *implementation(runtime);
    if (!mutating_api_allowed(state))
        return false;
    if (!advance_residency_through_optional_deadlines(
            state, timestamp_ns))
        return false;
    state.stats.idle_expirations += fk_compact_flow_table_expire_idle(
        state.table,
        timestamp_ns,
        state.config.idle_timeout_ns,
        state.config.maximum_flows);
    return true;
}

bool fk_compact_runtime_prepare_semantic_time_step(
        fk_compact_runtime *runtime,
        uint64_t timestamp_ns,
        bool *complete) {
    if (complete != nullptr)
        *complete = false;
    if (runtime == nullptr || complete == nullptr)
        return false;
    CompactRuntime &state = *implementation(runtime);
    if (!mutating_api_allowed(state))
        return false;
    bool reached = false;
    if (!advance_residency_through_optional_deadlines_step(
            state, timestamp_ns, reached))
        return false;
    *complete = reached;
    return true;
}

bool fk_compact_runtime_advance_semantic_time_step(
        fk_compact_runtime *runtime,
        uint64_t timestamp_ns,
        bool *complete) {
    if (complete != nullptr)
        *complete = false;
    if (runtime == nullptr || complete == nullptr)
        return false;
    CompactRuntime &state = *implementation(runtime);
    if (!mutating_api_allowed(state))
        return false;
    bool reached = false;
    if (!advance_residency_through_optional_deadlines_step(
            state, timestamp_ns, reached))
        return false;
    if (reached) {
        state.stats.idle_expirations += fk_compact_flow_table_expire_idle(
            state.table,
            timestamp_ns,
            state.config.idle_timeout_ns,
            state.config.maximum_flows);
    }
    *complete = reached;
    return true;
}

bool fk_compact_runtime_scan_optional_timers(
        fk_compact_runtime *runtime,
        uint64_t timestamp_ns,
        uint32_t scan_limit,
        uint32_t *component_releases) {
    if (component_releases != nullptr)
        *component_releases = 0u;
    if (runtime == nullptr || component_releases == nullptr ||
        scan_limit == 0u)
        return false;
    CompactRuntime &state = *implementation(runtime);
    if (!mutating_api_allowed(state) || !state.semantic_time_initialized ||
        timestamp_ns != state.semantic_last_timestamp_ns)
        return false;
    *component_releases = scan_optional_timers(
        state, timestamp_ns, scan_limit);
    return true;
}

size_t fk_compact_runtime_drain_evidence_transitions(
        fk_compact_runtime *runtime,
        fk_compact_evidence_transition *transitions,
        size_t capacity) {
    if (runtime == nullptr || transitions == nullptr || capacity == 0u)
        return 0u;
    CompactRuntime &state = *implementation(runtime);
    if (!mutating_api_allowed(state))
        return 0u;
    state.stats.evidence_transition_drain_calls++;
    const size_t count = fk_compact_flow_table_drain_evidence_transitions(
        state.table, transitions, capacity);
    state.stats.evidence_transition_records_drained += count;
    return count;
}

bool fk_compact_runtime_flow_snapshot(
        fk_compact_runtime *runtime,
        fk_compact_flow_handle handle,
        fk_compact_flow_snapshot *snapshot) {
    if (snapshot != nullptr)
        *snapshot = {};
    if (runtime == nullptr || snapshot == nullptr)
        return false;
    CompactRuntime &state = *implementation(runtime);
    return mutating_api_allowed(state) &&
        fk_compact_flow_table_snapshot(state.table, handle, snapshot);
}

bool fk_compact_runtime_take_flow_open_observation(
        fk_compact_runtime *runtime,
        fk_compact_flow_open_observation *observation) {
    if (runtime == nullptr || observation == nullptr)
        return false;
    CompactRuntime &state = *implementation(runtime);
    if (!mutating_api_allowed(state))
        return false;
    if (!state.flow_open_pending)
        return false;
    if (state.api_mode != RuntimeApiMode::V1_ZERO_ID ||
        state.pending_flow_open.logical_connection_id != 0u) {
        state.stats.api_mode_rejections++;
        return false;
    }
    *observation = state.pending_flow_open.presentation;
    state.flow_open_pending = false;
    return true;
}

bool fk_compact_runtime_take_flow_open_observation_v2(
        fk_compact_runtime *runtime,
        fk_compact_flow_open_observation_v2 *observation) {
    if (runtime == nullptr || observation == nullptr)
        return false;
    CompactRuntime &state = *implementation(runtime);
    if (!mutating_api_allowed(state))
        return false;
    if (!state.flow_open_pending)
        return false;
    if (state.api_mode != RuntimeApiMode::V2_EXPLICIT_ID) {
        state.stats.api_mode_rejections++;
        return false;
    }
    *observation = state.pending_flow_open;
    state.flow_open_pending = false;
    return true;
}

bool fk_compact_runtime_enable_first_packet_coverage(fk_compact_runtime *runtime) {
    if (!runtime) return false;
    auto &state = *implementation(runtime);
    const auto &policy = state.config.policy;
    if (!mutating_api_allowed(state) || state.first_packet_coverage || state.eof_coverage_deposit ||
        state.api_mode != RuntimeApiMode::UNSET || state.semantic_time_initialized ||
        state.owner_adapter_token.load(std::memory_order_acquire) != 0u ||
        state.config.checkpoint_intervention.enabled != 0u ||
        state.detector_feature_count != FK_COMPACT_DETECTOR_FEATURES_V4 ||
        policy.checkpoint_count != 4u || policy.checkpoints[0] != 4u ||
        policy.checkpoints[1] != 8u || policy.checkpoints[2] != 12u ||
        policy.checkpoints[3] != 20u) return false;
    state.first_packet_coverage = true;
    return true;
}

bool fk_compact_runtime_enable_eof_coverage_deposit(fk_compact_runtime *runtime) {
    if (!fk_compact_runtime_enable_first_packet_coverage(runtime)) return false;
    auto &s=*implementation(runtime);s.first_packet_coverage=false;s.eof_coverage_deposit=true;
    return true;
}

bool fk_compact_runtime_enable_adaptive_detection_candidates(
        fk_compact_runtime *runtime,
        uint32_t first_packet,
        uint32_t near_gap,
        uint32_t far_gap,
        uint32_t horizon_packet) {
    if (runtime == nullptr)
        return false;
    auto &state = *implementation(runtime);
    const auto &policy = state.config.policy;
    if (!mutating_api_allowed(state) ||
        state.adaptive_detection_candidates ||
        state.api_mode != RuntimeApiMode::UNSET ||
        state.semantic_time_initialized ||
        state.owner_adapter_token.load(std::memory_order_acquire) != 0u ||
        state.config.checkpoint_intervention.enabled != 0u ||
        state.detector_feature_count != FK_COMPACT_DETECTOR_FEATURES_V4 ||
        policy.checkpoint_count != 4u || policy.checkpoints[0] != 4u ||
        policy.checkpoints[1] != 8u || policy.checkpoints[2] != 12u ||
        policy.checkpoints[3] != 20u || first_packet != 4u ||
        near_gap == 0u || far_gap == 0u || horizon_packet != 20u ||
        near_gap > horizon_packet || far_gap > horizon_packet)
        return false;
    state.adaptive_detection_candidates = true;
    state.adaptive_first_packet = static_cast<uint8_t>(first_packet);
    state.adaptive_near_gap = static_cast<uint8_t>(near_gap);
    state.adaptive_far_gap = static_cast<uint8_t>(far_gap);
    state.adaptive_horizon_packet = static_cast<uint8_t>(horizon_packet);
    return true;
}

bool fk_compact_runtime_enable_marginal_detection_candidates(
        fk_compact_runtime *runtime, uint32_t horizon_packet) {
    if (runtime == nullptr)
        return false;
    auto &state = *implementation(runtime);
    const auto &policy = state.config.policy;
    if (!mutating_api_allowed(state) || state.adaptive_detection_candidates ||
        state.marginal_detection_candidates ||
        state.api_mode != RuntimeApiMode::UNSET ||
        state.semantic_time_initialized ||
        state.owner_adapter_token.load(std::memory_order_acquire) != 0u ||
        state.config.checkpoint_intervention.enabled != 0u ||
        state.detector_feature_count != FK_COMPACT_DETECTOR_FEATURES_V4 ||
        policy.checkpoint_count != 4u || policy.checkpoints[0] != 4u ||
        policy.checkpoints[1] != 8u || policy.checkpoints[2] != 12u ||
        policy.checkpoints[3] != 20u || horizon_packet == 0u ||
        horizon_packet > UINT8_MAX)
        return false;
    state.adaptive_detection_candidates = true;
    state.marginal_detection_candidates = true;
    state.adaptive_first_packet = 1u;
    state.adaptive_horizon_packet = static_cast<uint8_t>(horizon_packet);
    return true;
}

uint64_t fk_compact_runtime_first_packet_coverage_requests(
        const fk_compact_runtime *runtime) {
    return runtime ? implementation(runtime)->first_packet_coverage_requests : 0u;
}

bool fk_compact_runtime_attach_prefix_callback(
        fk_compact_runtime *runtime,
        fk_compact_prefix_callback callback,
        void *context) {
    return fk_compact_runtime_attach_prefix_callback_until(
        runtime, callback, context, 20u);
}

bool fk_compact_runtime_attach_prefix_callback_until(
        fk_compact_runtime *runtime,
        fk_compact_prefix_callback callback,
        void *context,
        uint32_t maximum_packet) {
    if (runtime == nullptr || callback == nullptr)
        return false;
    CompactRuntime &state = *implementation(runtime);
    if (state.api_mode != RuntimeApiMode::UNSET || state.prefix_callback != nullptr)
        return false;
    if (maximum_packet == 0u || maximum_packet > 255u)
        return false;
    state.prefix_callback = callback;
    state.prefix_context = context;
    state.prefix_packet_limit = maximum_packet;
    return true;
}

bool fk_compact_runtime_take_detection_request(
        fk_compact_runtime *runtime,
        fk_compact_detection_request *request) {
    if (runtime == nullptr || request == nullptr)
        return false;
    CompactRuntime &state = *implementation(runtime);
    if (!mutating_api_allowed(state))
        return false;
    if (!state.detection_pending)
        return false;
    if (state.api_mode != RuntimeApiMode::V1_ZERO_ID ||
        state.pending_detection.logical_connection_id != 0u) {
        state.stats.api_mode_rejections++;
        return false;
    }
    *request = state.pending_detection.presentation;
    state.detection_pending = false;
    return true;
}

bool fk_compact_runtime_take_detection_request_v2(
        fk_compact_runtime *runtime,
        fk_compact_detection_request_v2 *request) {
    if (runtime == nullptr || request == nullptr)
        return false;
    CompactRuntime &state = *implementation(runtime);
    if (!mutating_api_allowed(state))
        return false;
    if (!state.detection_pending)
        return false;
    if (state.api_mode != RuntimeApiMode::V2_EXPLICIT_ID) {
        state.stats.api_mode_rejections++;
        return false;
    }
    *request = state.pending_detection;
    state.detection_pending = false;
    return true;
}

bool fk_compact_runtime_take_action_record(
        fk_compact_runtime *runtime,
        fk_compact_action_record *record) {
    if (runtime == nullptr || record == nullptr)
        return false;
    CompactRuntime &state = *implementation(runtime);
    if (!mutating_api_allowed(state))
        return false;
    if (!state.action_pending)
        return false;
    *record = state.pending_action;
    state.action_pending = false;
    return true;
}

bool fk_compact_runtime_detect(
        fk_compact_runtime *runtime,
        const fk_compact_detection_request *request,
        float *score) {
    if (runtime == nullptr || request == nullptr || score == nullptr)
        return false;
    CompactRuntime &state = *implementation(runtime);
    state.stats.detector_calls++;
    bool detected = false;
    if (request->feature_count == state.detector_feature_count) {
        if (state.seven_state_detectors) {
            float projected[FK_COMPACT_TEACHER_PROJECTED_FEATURES]{};
            uint8_t mask = 0u;
            bool valid_mask = true;
            for (uint8_t component = 0u; component < 3u; ++component) {
                const float selected = request->features[30u + component];
                if (!std::isfinite(selected) ||
                    (selected != 0.0f && selected != 1.0f)) {
                    valid_mask = false;
                    break;
                }
                if (selected == 1.0f)
                    mask |= static_cast<uint8_t>(1u << component);
            }
            detected = valid_mask &&
                fk_compact_teacher_project_features(
                    request->features,
                    request->feature_count,
                    projected,
                    FK_COMPACT_TEACHER_PROJECTED_FEATURES) &&
                fk_cpu_pipeline_detect_state(
                    state.pipeline,
                    mask,
                    projected,
                    FK_COMPACT_TEACHER_PROJECTED_FEATURES,
                    score);
        } else {
            detected = fk_cpu_pipeline_detect(
                state.pipeline,
                request->features,
                request->feature_count,
                score);
        }
    }
    if (!detected) {
        state.stats.detector_failures++;
        return false;
    }
    return true;
}

bool fk_compact_runtime_detect_v2(
        fk_compact_runtime *runtime,
        const fk_compact_detection_request_v2 *request,
        float *score) {
    if (request == nullptr)
        return false;
    /* logical_connection_id is an event-routing key, never a detector input. */
    return fk_compact_runtime_detect(runtime, &request->presentation, score);
}

void fk_compact_runtime_set_pressure(
        fk_compact_runtime *runtime,
        fk_pressure_mode pressure) {
    if (runtime == nullptr || pressure < FK_PRESSURE_NORMAL ||
        pressure > FK_PRESSURE_OVERLOAD)
        return;
    CompactRuntime &state = *implementation(runtime);
    if (!mutating_api_allowed(state))
        return;
    state.external_pressure = pressure;
    state.pressure = static_cast<fk_pressure_mode>(std::max(
        static_cast<unsigned>(state.automatic_pressure),
        static_cast<unsigned>(state.external_pressure)));
}

bool fk_compact_runtime_get_stats(
        const fk_compact_runtime *runtime,
        fk_compact_runtime_stats *stats) {
    if (runtime == nullptr || stats == nullptr)
        return false;
    const CompactRuntime &state = *implementation(runtime);
    *stats = state.stats;
    stats->semantic_first_timestamp_ns =
        state.semantic_first_timestamp_ns;
    stats->semantic_last_timestamp_ns =
        state.semantic_last_timestamp_ns;
    stats->semantic_time_initialized =
        state.semantic_time_initialized;
    stats->semantic_time_complete =
        state.semantic_time_complete;
    fk_compact_flow_table_stats table_stats{};
    if (fk_compact_flow_table_get_stats(state.table, &table_stats)) {
        // Deferred idle retirements can finish during admission or shutdown,
        // outside expire_idle(). Report the table's confirmed release count.
        stats->idle_expirations = table_stats.idle_expirations;
        stats->optional_timer_deadline_queries =
            table_stats.timer_deadline_queries;
        stats->optional_timer_deadline_rebuilds =
            table_stats.timer_deadline_rebuilds;
        stats->optional_timer_deadline_probes =
            table_stats.timer_deadline_probes;
        stats->idle_scan_calls = table_stats.idle_scan_calls;
        stats->idle_scan_probes = table_stats.idle_scan_probes;
        stats->idle_scan_gated_calls =
            table_stats.idle_scan_gated_calls;
        stats->idle_scan_completed_cycles =
            table_stats.idle_scan_completed_cycles;
        stats->mandatory_floor_bytes =
            table_stats.mandatory_allocation_bytes;
        stats->optional_evidence_current_bytes =
            table_stats.evidence_storage_bytes;
        stats->optional_evidence_peak_bytes =
            table_stats.peak_evidence_storage_bytes;
        uint64_t ignored_current_bytes = 0u;
        uint64_t optional_capacity_bytes = 0u;
        if (add_optional_pool_utilization(
                0u, table_stats.stat_pool_capacity,
                table_stats.stat_pool_block_bytes,
                ignored_current_bytes, optional_capacity_bytes) &&
            add_optional_pool_utilization(
                0u, table_stats.seq_pool_capacity,
                table_stats.seq_pool_block_bytes,
                ignored_current_bytes, optional_capacity_bytes) &&
            add_optional_pool_utilization(
                0u, table_stats.ja4_pending_pool_capacity,
                table_stats.ja4_pending_pool_block_bytes,
                ignored_current_bytes, optional_capacity_bytes) &&
            add_optional_pool_utilization(
                0u, table_stats.ja4_summary_pool_capacity,
                table_stats.ja4_summary_pool_block_bytes,
                ignored_current_bytes, optional_capacity_bytes)) {
            stats->optional_evidence_capacity_bytes =
                optional_capacity_bytes;
        }
    }
    stats->automatic_pressure_enabled =
        state.config.automatic_pressure_enabled;
    stats->pressure_enter_percent = state.config.pressure_enter_percent;
    stats->pressure_exit_percent = state.config.pressure_exit_percent;
    stats->overload_enter_percent = state.config.overload_enter_percent;
    stats->overload_exit_percent = state.config.overload_exit_percent;
    stats->pressure_denominator = static_cast<uint8_t>(
        FK_COMPACT_PRESSURE_DENOMINATOR_MAX_OPTIONAL_TYPED_POOL_UTILIZATION);
    stats->current_pressure_mode = static_cast<uint8_t>(state.pressure);
    stats->automatic_pressure_mode =
        static_cast<uint8_t>(state.automatic_pressure);
    stats->external_pressure_mode =
        static_cast<uint8_t>(state.external_pressure);
    for (size_t index = 0u; index < 3u; ++index) {
        stats->resolved_policy_maximum_components[index] =
            state.config.policy.maximum_components[index];
        stats->resolved_policy_minimum_utility[index] =
            state.config.policy.minimum_utility[index];
    }
    stats->resolved_policy_preserve_full_state_in_normal =
        state.config.policy.preserve_full_state_in_normal;
    stats->identity_abi_version =
        FK_COMPACT_RUNTIME_IDENTITY_ABI_VERSION;
    stats->identity_api_mode =
        static_cast<uint8_t>(state.api_mode);
    stats->owner_adapter_claim_attempts =
        state.owner_adapter_claim_attempts.load(std::memory_order_relaxed);
    stats->owner_adapter_claim_successes =
        state.owner_adapter_claim_successes.load(std::memory_order_relaxed);
    stats->owner_adapter_claim_rejections =
        state.owner_adapter_claim_rejections.load(std::memory_order_relaxed);
    stats->owner_adapter_validation_calls =
        state.owner_adapter_validation_calls.load(std::memory_order_relaxed);
    stats->owner_adapter_validation_successes =
        state.owner_adapter_validation_successes.load(
            std::memory_order_relaxed);
    stats->owner_adapter_validation_rejections =
        state.owner_adapter_validation_rejections.load(
            std::memory_order_relaxed);
    stats->owner_adapter_scope_begin_calls =
        state.owner_adapter_scope_begin_calls.load(
            std::memory_order_relaxed);
    stats->owner_adapter_scope_begin_successes =
        state.owner_adapter_scope_begin_successes.load(
            std::memory_order_relaxed);
    stats->owner_adapter_scope_begin_rejections =
        state.owner_adapter_scope_begin_rejections.load(
            std::memory_order_relaxed);
    stats->owner_adapter_scope_end_calls =
        state.owner_adapter_scope_end_calls.load(
            std::memory_order_relaxed);
    stats->owner_adapter_scope_end_successes =
        state.owner_adapter_scope_end_successes.load(
            std::memory_order_relaxed);
    stats->owner_adapter_scope_end_rejections =
        state.owner_adapter_scope_end_rejections.load(
            std::memory_order_relaxed);
    stats->owner_adapter_unscoped_mutation_rejections =
        state.owner_adapter_unscoped_mutation_rejections.load(
            std::memory_order_relaxed);
    stats->owner_adapter_foreign_scope_mutation_rejections =
        state.owner_adapter_foreign_scope_mutation_rejections.load(
            std::memory_order_relaxed);
    stats->owner_adapter_scope_active =
        state.owner_adapter_scope_active.load(
            std::memory_order_acquire) != 0u ? 1u : 0u;
    stats->owner_adapter_scope_thread_bound =
        state.owner_adapter_scope_thread_token.load(
            std::memory_order_acquire) != 0u ? 1u : 0u;
    const uint32_t claimed_owner =
        state.owner_adapter_fixed_owner_plus_one.load(
            std::memory_order_acquire);
    stats->owner_adapter_claimed = claimed_owner != 0u ? 1u : 0u;
    stats->owner_adapter_fixed_owner = claimed_owner == 0u
        ? UINT16_MAX
        : static_cast<uint16_t>(claimed_owner - 1u);
    stats->controlled_state_byte_seconds =
        static_cast<double>(
            state.controlled_state_byte_nanoseconds / 1000000000.0L);
    for (size_t component = 0u;
         component < FK_MEMORY_COMPONENT_COUNT;
         ++component) {
        stats->state_byte_seconds_by_component[component] =
            static_cast<double>(
                state.component_byte_nanoseconds[component] /
                1000000000.0L);
    }
    fk_cpu_pipeline_stats pipeline{};
    if (fk_cpu_pipeline_get_stats(state.pipeline, &pipeline)) {
        stats->value_model_calls = pipeline.value_calls;
        stats->value_model_failures = pipeline.value_failures;
        stats->value_inference_failures =
            pipeline.value_inference_failures;
        stats->value_transition_failures =
            pipeline.value_transition_failures;
        stats->value_inference_ns = pipeline.value_inference_ns;
        stats->detector_inference_ns =
            pipeline.detector_inference_ns;
        stats->value_v3_inferences = pipeline.value_v3_inferences;
        stats->value_v3_inference_failures =
            pipeline.value_v3_inference_failures;
        stats->value_v3_core_zero_violations =
            pipeline.value_v3_core_zero_violations;
        stats->transition_value_calls = pipeline.transition_value_calls;
        stats->transition_value_failures =
            pipeline.transition_value_failures;
        stats->transition_value_inference_ns =
            pipeline.transition_value_inference_ns;
    }
    return true;
}

bool fk_compact_runtime_detector_feature_count(
        const fk_compact_runtime *runtime,
        uint32_t *feature_count) {
    if (runtime == nullptr || feature_count == nullptr)
        return false;
    *feature_count = implementation(runtime)->detector_feature_count;
    return true;
}

bool fk_compact_runtime_get_action_model_metadata(
        const fk_compact_runtime *runtime,
        fk_cpu_pipeline_action_model_metadata *metadata) {
    if (runtime == nullptr || metadata == nullptr)
        return false;
    return fk_cpu_pipeline_get_action_model_metadata(
        implementation(runtime)->pipeline, metadata);
}

fk_compact_flow_table *fk_compact_runtime_flow_table(
        fk_compact_runtime *runtime) {
    if (runtime == nullptr)
        return nullptr;
    CompactRuntime &state = *implementation(runtime);
    return mutating_api_allowed(state) ? state.table : nullptr;
}

}  // extern "C"
