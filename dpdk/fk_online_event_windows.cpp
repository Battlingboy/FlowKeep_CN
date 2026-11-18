#include "fk_online_event_windows.h"

#include <algorithm>
#include <array>
#include <cmath>
#include <cstdio>
#include <limits>
#include <new>

namespace {

constexpr uint32_t kNone = UINT32_MAX;

enum class IngressIdentityMode : uint8_t {
    Unset = 0u,
    V1 = 1u,
    V2 = 2u,
};

enum class TriggerProtocol : uint8_t {
    Unset = 0u,
    PeriodicV1 = FK_ONLINE_EVENT_TRIGGER_PROTOCOL_PERIODIC_V1,
    CheckpointPeriodicV2 =
        FK_ONLINE_EVENT_TRIGGER_PROTOCOL_CHECKPOINT_PERIODIC_V2,
};

/*
 * Zero-growth internal representation.  V1 consumes both words as its exact
 * 16-byte presentation.  Logical mode consumes word[0] as the complete 64-bit
 * logical id and word[1] as diagnostic generation+location; the diagnostic
 * first timestamp reuses open_timestamp_ns below.  Identity equality in
 * logical mode never reads the diagnostic word.
 */
struct CompactFlowIdentity {
    uint64_t words[2]{};
};

struct FlowSnapshot {
    CompactFlowIdentity identity{};
    uint64_t open_timestamp_ns = 0u;
    uint64_t snapshot_timestamp_ns = 0u;
    fk_event_student_embedding embedding{};
    uint32_t next = kNone;
    bool has_snapshot = false;
    bool logical_identity = false;
};

struct CausalFlowSnapshot {
    double record_score = 0.0;
    float masked_state_columns[FK_ONLINE_EVENT_CAUSAL_STATE_COLUMNS]{};
    uint8_t original_action_mask = 0u;
    uint8_t reserved[7]{};
};

struct LegacyFlowSnapshotLayout {
    fk_actor_flow_identity identity{};
    uint64_t open_timestamp_ns = 0u;
    uint64_t snapshot_timestamp_ns = 0u;
    fk_event_student_embedding embedding{};
    uint32_t next = kNone;
    bool has_snapshot = false;
};

static_assert(sizeof(CompactFlowIdentity) == sizeof(fk_actor_flow_identity),
    "compact v2 key must retain the v1 16-byte footprint");
static_assert(sizeof(FlowSnapshot) == sizeof(LegacyFlowSnapshotLayout),
    "logical identity must not increase per-snapshot memory");

struct EventSlot {
    uint64_t event_id = 0u;
    uint64_t start_ns = 0u;
    uint64_t last_activity_ns = 0u;
    uint64_t next_anchor_ns = 0u;
    uint64_t next_trigger_ordinal = 0u;
    uint64_t snapshot_version = 0u;
    uint64_t last_scored_snapshot_version = 0u;
    uint64_t last_accumulator_update_ns = 0u;
    uint32_t generation = 0u;
    uint32_t flow_count = 0u;
    uint32_t flow_head = kNone;
    uint32_t heap_position = kNone;
    fk_event_student_event_state student_state{};
    bool active = false;
    bool alert_latched = false;
    bool has_accumulator_update = false;
    uint8_t behavior_stage = FK_EVENT_STAGE_BOOTSTRAP;
    uint8_t behavior_evidence_mask = 0u;
    bool stage_reopened_pending = false;
};

struct OnlineEventWindows {
    fk_event_student *student = nullptr;
    fk_event_student_metadata metadata{};
    fk_online_event_window_sink sink = nullptr;
    void *sink_context = nullptr;
    fk_online_event_causal_model_v1 causal_model = nullptr;
    void *causal_model_context = nullptr;
    float causal_decision_threshold = 0.0f;
    EventSlot *events = nullptr;
    fk_stage_aware_event_state *stage_states = nullptr;
    fk_stage_aware_policy stage_policy{};
    FlowSnapshot *flows = nullptr;
    CausalFlowSnapshot *causal_flows = nullptr;
    uint32_t *due_heap = nullptr;
    uint32_t due_heap_count = 0u;
    uint32_t maximum_events = 0u;
    uint32_t maximum_flows_per_event = 0u;
    uint32_t maximum_total_flows = 0u;
    uint32_t flow_free_head = kNone;
    uint64_t reserved_bytes = 0u;
    uint64_t inclusive_watermark_ns = 0u;
    uint64_t last_input_timestamp_ns = 0u;
    bool watermark_initialized = false;
    bool input_timestamp_initialized = false;
    bool external_watermarks_only = false;
    bool stage_aware_enabled = false;
    bool advance_in_progress = false;
    uint64_t advance_target_ns = 0u;
    IngressIdentityMode identity_mode = IngressIdentityMode::Unset;
    TriggerProtocol trigger_protocol = TriggerProtocol::Unset;
    bool complete = true;
    fk_online_event_windows_stats stats{};
};

static OnlineEventWindows *implementation(fk_online_event_windows *windows) {
    return reinterpret_cast<OnlineEventWindows *>(windows);
}

static const OnlineEventWindows *implementation(
        const fk_online_event_windows *windows) {
    return reinterpret_cast<const OnlineEventWindows *>(windows);
}

static void set_error(
        char *error,
        size_t capacity,
        const char *message) {
    if (error != nullptr && capacity != 0u)
        std::snprintf(error, capacity, "%s", message);
}

static bool add_size(size_t &total, size_t count, size_t width) {
    if (count != 0u && width >
        std::numeric_limits<size_t>::max() / count)
        return false;
    const size_t amount = count * width;
    if (amount > std::numeric_limits<size_t>::max() - total)
        return false;
    total += amount;
    return true;
}

static uintptr_t align_up(uintptr_t value, size_t alignment) {
    return (value + alignment - 1u) & ~(uintptr_t(alignment) - 1u);
}

static uint64_t saturating_add(uint64_t left, uint64_t right) {
    return right > std::numeric_limits<uint64_t>::max() - left
        ? std::numeric_limits<uint64_t>::max()
        : left + right;
}

static bool valid_checkpoint_packet(uint8_t packet) {
    return packet == 4u || packet == 8u || packet == 12u || packet == 20u;
}

static bool trigger_protocol_allowed(
        OnlineEventWindows &state,
        TriggerProtocol requested) {
    if (requested == TriggerProtocol::Unset)
        return false;
    if (state.trigger_protocol == TriggerProtocol::Unset ||
        state.trigger_protocol == requested)
        return true;
    state.stats.trigger_protocol_rejections++;
    state.complete = false;
    return false;
}

static void lock_trigger_protocol(
        OnlineEventWindows &state,
        TriggerProtocol requested) {
    if (state.trigger_protocol == TriggerProtocol::Unset) {
        state.trigger_protocol = requested;
        state.stats.trigger_protocol = static_cast<uint8_t>(requested);
    }
}

static bool compact_identity_equal(
        const FlowSnapshot &stored,
        const fk_actor_flow_identity_v2 &input) {
    const bool logical = input.logical_connection_id != 0u;
    if (stored.logical_identity != logical)
        return false;
    if (logical)
        return stored.identity.words[0] == input.logical_connection_id;
    return stored.identity.words[0] == input.presentation.first_timestamp_ns &&
        stored.identity.words[1] ==
            ((static_cast<uint64_t>(input.presentation.generation) << 32u) |
                input.presentation.packed_location);
}

static uint64_t pack_presentation_suffix(
        const fk_actor_flow_identity &presentation) {
    return (static_cast<uint64_t>(presentation.generation) << 32u) |
        presentation.packed_location;
}

static bool compact_presentation_equal(
        const FlowSnapshot &stored,
        const fk_actor_flow_identity &presentation) {
    return stored.logical_identity &&
        stored.open_timestamp_ns == presentation.first_timestamp_ns &&
        stored.identity.words[1] == pack_presentation_suffix(presentation);
}

static void store_compact_identity(
        FlowSnapshot &stored,
        const fk_actor_flow_identity_v2 &input) {
    stored.logical_identity = input.logical_connection_id != 0u;
    if (stored.logical_identity) {
        stored.identity.words[0] = input.logical_connection_id;
        stored.identity.words[1] =
            pack_presentation_suffix(input.presentation);
    } else {
        stored.identity.words[0] = input.presentation.first_timestamp_ns;
        stored.identity.words[1] =
            pack_presentation_suffix(input.presentation);
    }
    stored.open_timestamp_ns = input.presentation.first_timestamp_ns;
}

static void update_compact_diagnostic_presentation(
        FlowSnapshot &stored,
        const fk_actor_flow_identity &presentation) {
    stored.identity.words[1] = pack_presentation_suffix(presentation);
    stored.open_timestamp_ns = presentation.first_timestamp_ns;
}

static bool logical_connection_id_valid(uint64_t logical_connection_id) {
    if (logical_connection_id == 0u)
        return true;
    /* Mirrors the shared generation:slot+1 wire representation.  This module
     * has no CID-directory capacity, so the directory remains responsible
     * for the upper-bound check. */
    return static_cast<uint32_t>(logical_connection_id) != 0u &&
        static_cast<uint32_t>(logical_connection_id >> 32u) != 0u;
}

static bool valid_association(
        const OnlineEventWindows &state,
        const fk_actor_session_result *association,
        const fk_actor_flow_identity_v2 *identity,
        uint64_t observation_ns) {
    return association != nullptr && identity != nullptr &&
        association->event_id != 0u &&
        association->event_generation != 0u &&
        association->event_slot < state.maximum_events &&
        identity->presentation.generation != 0u &&
        identity->presentation.first_timestamp_ns <= observation_ns &&
        logical_connection_id_valid(identity->logical_connection_id);
}

static bool identity_mode_allowed(
        OnlineEventWindows &state,
        IngressIdentityMode requested) {
    if (state.identity_mode == IngressIdentityMode::Unset ||
        state.identity_mode == requested) {
        return true;
    }
    state.stats.identity_mode_rejections++;
    state.complete = false;
    return false;
}

static void lock_identity_mode(
        OnlineEventWindows &state,
        IngressIdentityMode requested) {
    if (state.identity_mode == IngressIdentityMode::Unset)
        state.identity_mode = requested;
}

static void refresh_peaks(OnlineEventWindows &state) {
    state.stats.peak_active_events = std::max(
        state.stats.peak_active_events, state.stats.active_events);
    state.stats.peak_retained_flows = std::max(
        state.stats.peak_retained_flows, state.stats.retained_flows);
}

enum class RetirementReason {
    Idle,
    Lifetime,
    Reuse,
    Explicit,
};

static uint64_t event_cutoff(const EventSlot &event) {
    return std::min(
        saturating_add(event.start_ns, FK_ONLINE_EVENT_MAX_LIFETIME_NS),
        saturating_add(event.last_activity_ns, FK_ONLINE_EVENT_IDLE_NS));
}

static uint64_t due_key(const EventSlot &event) {
    return std::min(event.next_anchor_ns, event_cutoff(event));
}

static bool heap_less(
        const OnlineEventWindows &state,
        uint32_t left_slot,
        uint32_t right_slot) {
    const uint64_t left = due_key(state.events[left_slot]);
    const uint64_t right = due_key(state.events[right_slot]);
    return left < right || (left == right && left_slot < right_slot);
}

static void heap_swap(
        OnlineEventWindows &state,
        uint32_t left,
        uint32_t right) {
    std::swap(state.due_heap[left], state.due_heap[right]);
    state.events[state.due_heap[left]].heap_position = left;
    state.events[state.due_heap[right]].heap_position = right;
}

static void heap_sift_up(OnlineEventWindows &state, uint32_t position) {
    while (position != 0u) {
        const uint32_t parent = (position - 1u) / 2u;
        if (!heap_less(
                state, state.due_heap[position], state.due_heap[parent]))
            break;
        heap_swap(state, position, parent);
        position = parent;
    }
}

static void heap_sift_down(OnlineEventWindows &state, uint32_t position) {
    for (;;) {
        const uint32_t left = position * 2u + 1u;
        if (left >= state.due_heap_count)
            break;
        const uint32_t right = left + 1u;
        uint32_t smallest = left;
        if (right < state.due_heap_count &&
            heap_less(
                state, state.due_heap[right], state.due_heap[left]))
            smallest = right;
        if (!heap_less(
                state, state.due_heap[smallest],
                state.due_heap[position]))
            break;
        heap_swap(state, position, smallest);
        position = smallest;
    }
}

static void heap_insert(OnlineEventWindows &state, uint32_t slot) {
    EventSlot &event = state.events[slot];
    if (event.heap_position != kNone)
        return;
    const uint32_t position = state.due_heap_count++;
    state.due_heap[position] = slot;
    event.heap_position = position;
    heap_sift_up(state, position);
    state.stats.due_heap_updates++;
    state.stats.due_heap_peak = std::max<uint64_t>(
        state.stats.due_heap_peak, state.due_heap_count);
}

static void heap_update(OnlineEventWindows &state, uint32_t slot) {
    const uint32_t position = state.events[slot].heap_position;
    if (position == kNone || position >= state.due_heap_count)
        return;
    heap_sift_up(state, position);
    heap_sift_down(state, state.events[slot].heap_position);
    state.stats.due_heap_updates++;
}

static void heap_remove(OnlineEventWindows &state, uint32_t slot) {
    EventSlot &event = state.events[slot];
    const uint32_t position = event.heap_position;
    if (position == kNone || position >= state.due_heap_count)
        return;
    const uint32_t last_position = --state.due_heap_count;
    event.heap_position = kNone;
    if (position != last_position) {
        const uint32_t moved_slot = state.due_heap[last_position];
        state.due_heap[position] = moved_slot;
        state.events[moved_slot].heap_position = position;
        heap_sift_up(state, position);
        heap_sift_down(
            state,
            state.events[moved_slot].heap_position);
    }
    state.stats.due_heap_updates++;
}

static void retire_event(
        OnlineEventWindows &state,
        uint32_t slot,
        RetirementReason reason) {
    EventSlot &event = state.events[slot];
    if (!event.active)
        return;
    heap_remove(state, slot);
    state.stats.active_events--;
    state.stats.retained_flows -= event.flow_count;
    uint32_t flow_index = event.flow_head;
    while (flow_index != kNone) {
        FlowSnapshot &flow = state.flows[flow_index];
        const uint32_t next = flow.next;
        flow.next = state.flow_free_head;
        flow.has_snapshot = false;
        flow.logical_identity = false;
        state.flow_free_head = flow_index;
        flow_index = next;
    }
    if (reason == RetirementReason::Idle)
        state.stats.idle_retirements++;
    else if (reason == RetirementReason::Lifetime)
        state.stats.lifetime_retirements++;
    else if (reason == RetirementReason::Reuse)
        state.stats.event_slots_reused++;
    else
        state.stats.explicit_retirements++;
    event.active = false;
    event.flow_count = 0u;
    event.flow_head = kNone;
    event.alert_latched = false;
    event.has_accumulator_update = false;
    event.behavior_stage = FK_EVENT_STAGE_BOOTSTRAP;
    event.behavior_evidence_mask = 0u;
    event.stage_reopened_pending = false;
    if (state.stage_aware_enabled && state.stage_states != nullptr)
        fk_stage_aware_event_reset(&state.stage_states[slot]);
}

static bool emit_trigger(
        OnlineEventWindows &state,
        uint32_t slot,
        uint64_t anchor_ns,
        uint8_t trigger_kind,
        uint8_t checkpoint_packet) {
    EventSlot &event = state.events[slot];
    const bool periodic =
        trigger_kind == FK_ONLINE_EVENT_TRIGGER_KIND_PERIODIC;
    const bool checkpoint =
        trigger_kind == FK_ONLINE_EVENT_TRIGGER_KIND_CHECKPOINT;
    if ((!periodic && !checkpoint) ||
        (periodic && checkpoint_packet != 0u) ||
        (checkpoint &&
         (state.trigger_protocol != TriggerProtocol::CheckpointPeriodicV2 ||
          !valid_checkpoint_packet(checkpoint_packet)))) {
        state.complete = false;
        return false;
    }
    if (periodic)
        state.stats.ticks_due++;
    /*
     * The inclusive T watermark follows every checkpoint command at T.  If
     * the last immediate checkpoint score already consumed the identical
     * snapshot version at T, another event_add would overweight evidence
     * without either new state or elapsed event time.  Keep the timer receipt
     * but do not mint a second score or trigger id.
     */
    if (periodic && event.has_accumulator_update &&
        event.last_accumulator_update_ns == anchor_ns &&
        event.last_scored_snapshot_version == event.snapshot_version) {
        state.stats.same_timestamp_unchanged_periodic_coalesces++;
        return true;
    }
    fk_event_student_window_state window_state{};
    fk_event_student_window_reset(&window_state);
    std::array<
        fk_online_event_causal_record_v1,
        FK_ONLINE_EVENT_MAX_FLOWS> causal_records{};
    uint8_t first_action_mask = 0u;
    bool first_action_mask_set = false;
    bool mixed_action_masks = false;
    const uint64_t lower_exclusive = anchor_ns >= FK_ONLINE_EVENT_WINDOW_NS
        ? anchor_ns - FK_ONLINE_EVENT_WINDOW_NS
        : 0u;
    uint32_t retained = 0u;
    uint32_t flow_index = event.flow_head;
    uint32_t visited = 0u;
    while (flow_index != kNone && visited < event.flow_count) {
        const FlowSnapshot &flow = state.flows[flow_index];
        if (!flow.has_snapshot ||
            flow.snapshot_timestamp_ns > anchor_ns ||
            (anchor_ns >= FK_ONLINE_EVENT_WINDOW_NS &&
             flow.snapshot_timestamp_ns <= lower_exclusive)) {
            flow_index = flow.next;
            visited++;
            continue;
        }
        if (state.causal_model != nullptr) {
            const uint32_t causal_index = flow_index;
            if (state.causal_flows == nullptr ||
                causal_index >= state.maximum_total_flows ||
                retained >= causal_records.size()) {
                state.stats.causal_model_failures++;
                state.complete = false;
                return false;
            }
            const CausalFlowSnapshot &source =
                state.causal_flows[causal_index];
            fk_online_event_causal_record_v1 &destination =
                causal_records[retained];
            destination.record_score = source.record_score;
            std::copy(
                std::begin(source.masked_state_columns),
                std::end(source.masked_state_columns),
                std::begin(destination.masked_state_columns));
            destination.original_action_mask = source.original_action_mask;
            if (!first_action_mask_set) {
                first_action_mask = source.original_action_mask;
                first_action_mask_set = true;
            } else if (source.original_action_mask != first_action_mask) {
                mixed_action_masks = true;
            }
        } else if (!fk_event_student_window_add(
                       state.student, &window_state, &flow.embedding, 1.0f)) {
                state.stats.student_window_failures++;
                state.complete = false;
                return false;
        }
        retained++;
        flow_index = flow.next;
        visited++;
    }
    if (visited != event.flow_count || flow_index != kNone) {
        state.complete = false;
        return false;
    }
    if (retained == 0u) {
        if (periodic) {
            state.stats.empty_ticks++;
            return true;
        }
        state.complete = false;
        return false;
    }

    if (event.next_trigger_ordinal == UINT64_MAX) {
        state.stats.trigger_ordinal_overflows++;
        state.complete = false;
        return false;
    }

    float probability = 0.0f;
    float raw_logit = FK_EVENT_STUDENT_INVALID_LOGIT;
    float prefix_logit = FK_EVENT_STUDENT_INVALID_LOGIT;
    float operational_logit = FK_EVENT_STUDENT_INVALID_LOGIT;
    if (state.causal_model != nullptr) {
        fk_online_event_causal_trigger_v1 trigger{};
        trigger.event_id = event.event_id;
        trigger.event_start_ns = event.start_ns;
        trigger.anchor_ns = anchor_ns;
        trigger.trigger_ordinal = event.next_trigger_ordinal;
        trigger.event_slot = slot;
        trigger.event_generation = event.generation;
        trigger.retained_records = retained;
        trigger.trigger_kind = trigger_kind;
        trigger.checkpoint_packet = checkpoint_packet;
        state.stats.causal_model_calls++;
        state.stats.causal_records_presented += retained;
        if (mixed_action_masks)
            state.stats.causal_mixed_mask_triggers++;
        if (!state.causal_model(
                state.causal_model_context, &trigger,
                causal_records.data(), retained, &probability) ||
            !std::isfinite(probability) || probability < 0.0f ||
            probability > 1.0f) {
            state.stats.causal_model_failures++;
            state.complete = false;
            return false;
        }
        const double clipped = std::min(
            std::max(static_cast<double>(probability), 1.0e-7),
            1.0 - 1.0e-7);
        operational_logit = static_cast<float>(
            std::log(clipped / (1.0 - clipped)));
        raw_logit = operational_logit;
        prefix_logit = operational_logit;
    } else {
        fk_event_student_embedding window_embedding{};
        if (!fk_event_student_window_finish(
                state.student,
                &window_state,
                &window_embedding,
                &raw_logit)) {
            state.stats.student_window_failures++;
            state.complete = false;
            return false;
        }
        if (!fk_event_student_event_add(
                state.student,
                &event.student_state,
                &window_embedding,
                1.0f,
                &prefix_logit,
                &operational_logit)) {
            state.stats.student_window_failures++;
            state.complete = false;
            return false;
        }
        probability = fk_event_student_sigmoid(operational_logit);
    }
    event.last_accumulator_update_ns = anchor_ns;
    event.last_scored_snapshot_version = event.snapshot_version;
    event.has_accumulator_update = true;

    const float causal_prefix_probability =
        state.causal_model != nullptr
            ? probability : fk_event_student_sigmoid(prefix_logit);
    fk_stage_aware_transition stage_transition{};
    if (state.stage_aware_enabled) {
        if (state.stage_states == nullptr || !fk_stage_aware_event_update(
                &state.stage_states[slot], &state.stage_policy,
                event.behavior_stage, causal_prefix_probability, anchor_ns,
                event.behavior_evidence_mask, &stage_transition)) {
            state.complete = false;
            return false;
        }
        event.stage_reopened_pending = false;
        if (stage_transition.changed &&
            stage_transition.current_alert_state == FK_EVENT_ALERT_PROVISIONAL)
            state.stats.provisional_alerts++;
        if (stage_transition.changed &&
            stage_transition.current_alert_state == FK_EVENT_ALERT_CONFIRMED)
            state.stats.confirmed_alerts++;
        if (stage_transition.correction_emitted)
            state.stats.corrected_alerts++;
        if (stage_transition.reopen_emitted)
            state.stats.reopened_alerts++;
    }
    const float decision_threshold = state.causal_model != nullptr
        ? state.causal_decision_threshold : state.metadata.decision_threshold;
    const bool crossed = std::isfinite(probability) &&
        probability >= decision_threshold;
    const bool first_alert = crossed && !event.alert_latched;
    event.alert_latched = event.alert_latched || crossed;
    if (first_alert)
        state.stats.first_alerts++;
    state.stats.inferred_windows++;
    if (periodic)
        state.stats.periodic_trigger_inferred_windows++;
    else
        state.stats.checkpoint_trigger_inferred_windows++;

    fk_online_event_window_result result{};
    result.event_id = event.event_id;
    result.event_start_ns = event.start_ns;
    result.anchor_ns = anchor_ns;
    result.event_slot = slot;
    result.event_generation = event.generation;
    result.retained_flow_snapshots = retained;
    result.raw_window_logit = raw_logit;
    result.prefix_event_logit = prefix_logit;
    result.operational_logit = operational_logit;
    result.operational_probability = probability;
    result.threshold_crossed = crossed;
    result.alert_latched = event.alert_latched;
    result.first_alert = first_alert;
    result.trigger_ordinal = event.next_trigger_ordinal++;
    result.trigger_protocol = state.trigger_protocol == TriggerProtocol::Unset
        ? FK_ONLINE_EVENT_TRIGGER_PROTOCOL_PERIODIC_V1
        : static_cast<uint8_t>(state.trigger_protocol);
    result.trigger_kind = trigger_kind;
    result.checkpoint_packet = checkpoint_packet;
    result.behavior_stage = event.behavior_stage;
    result.alert_state = state.stage_aware_enabled
        ? stage_transition.current_alert_state
        : static_cast<uint8_t>(event.alert_latched
              ? FK_EVENT_ALERT_CONFIRMED : FK_EVENT_ALERT_UNKNOWN);
    result.alert_state_changed = state.stage_aware_enabled
        ? stage_transition.changed : first_alert;
    result.correction_emitted = state.stage_aware_enabled &&
        stage_transition.correction_emitted;
    result.reopen_emitted = state.stage_aware_enabled &&
        stage_transition.reopen_emitted;
    if (state.sink == nullptr || !state.sink(state.sink_context, &result)) {
        state.stats.output_rejections++;
        state.complete = false;
        return false;
    }
    return true;
}

static bool advance_step_internal(
        OnlineEventWindows &state,
        uint64_t target_ns,
        uint32_t max_due_ticks,
        bool &complete) {
    complete = false;
    state.stats.watermark_step_calls++;
    if (state.watermark_initialized &&
        target_ns < state.inclusive_watermark_ns) {
        state.stats.out_of_order_rejections++;
        state.complete = false;
        return false;
    }
    if (state.advance_in_progress &&
        target_ns != state.advance_target_ns) {
        state.stats.out_of_order_rejections++;
        state.complete = false;
        return false;
    }
    if (!state.advance_in_progress && state.watermark_initialized &&
        target_ns == state.inclusive_watermark_ns) {
        complete = true;
        return true;
    }
    if (!state.advance_in_progress) {
        state.advance_in_progress = true;
        state.advance_target_ns = target_ns;
    }

    uint32_t consumed_ticks = 0u;
    while (state.due_heap_count != 0u) {
        const uint32_t slot = state.due_heap[0u];
        EventSlot &event = state.events[slot];
        if (!event.active || event.heap_position != 0u) {
            state.complete = false;
            return false;
        }
        const uint64_t cutoff = event_cutoff(event);
        const uint64_t next_due = std::min(
            event.next_anchor_ns, cutoff);
        if (next_due > target_ns)
            break;
        if (event.next_anchor_ns <= cutoff &&
            event.next_anchor_ns <= target_ns) {
            if (consumed_ticks >= max_due_ticks) {
                state.stats.partial_watermark_steps++;
                return true;
            }
            if (!emit_trigger(
                    state,
                    slot,
                    event.next_anchor_ns,
                    FK_ONLINE_EVENT_TRIGGER_KIND_PERIODIC,
                    0u))
                return false;
            const uint64_t next = saturating_add(
                event.next_anchor_ns, FK_ONLINE_EVENT_STRIDE_NS);
            if (next == event.next_anchor_ns) {
                state.complete = false;
                return false;
            }
            event.next_anchor_ns = next;
            consumed_ticks++;
        }
        if (target_ns >= cutoff && event.next_anchor_ns > cutoff) {
            const uint64_t lifetime_cutoff = saturating_add(
                event.start_ns, FK_ONLINE_EVENT_MAX_LIFETIME_NS);
            retire_event(
                state,
                slot,
                lifetime_cutoff <= saturating_add(
                    event.last_activity_ns, FK_ONLINE_EVENT_IDLE_NS)
                    ? RetirementReason::Lifetime
                    : RetirementReason::Idle);
        } else {
            heap_update(state, slot);
        }
    }
    state.inclusive_watermark_ns = target_ns;
    state.watermark_initialized = true;
    state.advance_in_progress = false;
    state.stats.watermark_advances++;
    complete = true;
    return true;
}

static bool advance_internal(OnlineEventWindows &state, uint64_t target_ns) {
    bool complete = false;
    do {
        if (!advance_step_internal(
                state, target_ns, UINT32_MAX, complete))
            return false;
    } while (!complete);
    return true;
}

/* Close every timestamp strictly before a just-arriving observation. */
static bool prepare_input(OnlineEventWindows &state, uint64_t timestamp_ns) {
    if (state.advance_in_progress) {
        state.stats.out_of_order_rejections++;
        state.complete = false;
        return false;
    }
    if (state.input_timestamp_initialized &&
        timestamp_ns < state.last_input_timestamp_ns) {
        state.stats.out_of_order_rejections++;
        state.complete = false;
        return false;
    }
    if (state.watermark_initialized &&
        timestamp_ns <= state.inclusive_watermark_ns) {
        state.stats.closed_timestamp_rejections++;
        state.complete = false;
        return false;
    }
    if (timestamp_ns != 0u) {
        const uint64_t exclusive_target = timestamp_ns - 1u;
        if (state.external_watermarks_only &&
            (!state.watermark_initialized ||
             exclusive_target > state.inclusive_watermark_ns)) {
            state.stats.out_of_order_rejections++;
            state.complete = false;
            return false;
        }
        if (!state.external_watermarks_only &&
            (!state.watermark_initialized ||
             exclusive_target > state.inclusive_watermark_ns)) {
            state.stats.automatic_exclusive_advances++;
            if (!advance_internal(state, exclusive_target))
                return false;
        }
    }
    state.last_input_timestamp_ns = timestamp_ns;
    state.input_timestamp_initialized = true;
    return true;
}

static EventSlot *resolve_event(
        OnlineEventWindows &state,
        const fk_actor_session_result &association) {
    EventSlot &event = state.events[association.event_slot];
    if (!event.active || event.event_id != association.event_id ||
        event.generation != association.event_generation)
        return nullptr;
    return &event;
}

static FlowSnapshot *find_flow(
        OnlineEventWindows &state,
        uint32_t slot,
        const fk_actor_flow_identity_v2 &identity) {
    EventSlot &event = state.events[slot];
    uint32_t flow_index = event.flow_head;
    uint32_t visited = 0u;
    while (flow_index != kNone && visited < event.flow_count) {
        FlowSnapshot &flow = state.flows[flow_index];
        if (compact_identity_equal(flow, identity))
            return &flow;
        flow_index = flow.next;
        visited++;
    }
    return nullptr;
}

}  // namespace

size_t fk_online_event_windows_storage_bytes(
        const fk_online_event_windows_config *config) {
    if (config == nullptr || config->maximum_events == 0u ||
        config->maximum_flows_per_event == 0u ||
        config->maximum_flows_per_event > FK_ONLINE_EVENT_MAX_FLOWS ||
        config->maximum_total_flows < config->maximum_flows_per_event)
        return 0u;
    size_t total = alignof(OnlineEventWindows) - 1u;
    if (!add_size(total, 1u, sizeof(OnlineEventWindows)) ||
        !add_size(total, alignof(EventSlot) - 1u, 1u) ||
        !add_size(total, config->maximum_events, sizeof(EventSlot)) ||
        !add_size(total, alignof(uint32_t) - 1u, 1u) ||
        !add_size(total, config->maximum_events, sizeof(uint32_t)) ||
        (config->stage_aware_enabled &&
         (!add_size(total, alignof(fk_stage_aware_event_state) - 1u, 1u) ||
          !add_size(total, config->maximum_events,
                    sizeof(fk_stage_aware_event_state)))) ||
        !add_size(total, alignof(FlowSnapshot) - 1u, 1u) ||
        !add_size(
            total,
            config->maximum_total_flows,
            sizeof(FlowSnapshot)) ||
        (config->causal_model != nullptr &&
         (!add_size(total, alignof(CausalFlowSnapshot) - 1u, 1u) ||
          !add_size(total, config->maximum_total_flows,
                    sizeof(CausalFlowSnapshot)))))
        return 0u;
    return total;
}

fk_online_event_windows *fk_online_event_windows_init(
        void *storage,
        size_t storage_bytes,
        const fk_online_event_windows_config *config,
        char *error,
        size_t error_capacity) {
    const size_t required = fk_online_event_windows_storage_bytes(config);
    if (storage == nullptr || config == nullptr || required == 0u ||
        storage_bytes < required) {
        set_error(error, error_capacity, "invalid online-window storage/config");
        return nullptr;
    }
    const bool student_route = config->student != nullptr;
    const bool causal_route = config->causal_model != nullptr;
    if (config->sink == nullptr || student_route == causal_route) {
        set_error(
            error, error_capacity,
            "exactly one inference route and an output sink are required");
        return nullptr;
    }
    fk_event_student_metadata metadata{};
    if (student_route &&
        (!fk_event_student_get_metadata(config->student, &metadata) ||
         metadata.input_features != FK_EVENT_STUDENT_INPUT_FEATURES ||
         metadata.hidden == 0u ||
         metadata.hidden > FK_EVENT_STUDENT_MAX_HIDDEN ||
         !std::isfinite(metadata.decision_threshold) ||
         metadata.decision_threshold < 0.0f ||
         metadata.decision_threshold > 1.0f)) {
        set_error(error, error_capacity, "student metadata violates frozen contract");
        return nullptr;
    }
    if (causal_route &&
        (!std::isfinite(config->causal_decision_threshold) ||
         config->causal_decision_threshold <= 0.0f ||
         config->causal_decision_threshold > 1.0f ||
         config->stage_aware_enabled)) {
        set_error(error, error_capacity, "causal threshold violates frozen contract");
        return nullptr;
    }

    const uintptr_t begin = reinterpret_cast<uintptr_t>(storage);
    const uintptr_t end = begin + storage_bytes;
    uintptr_t cursor = align_up(begin, alignof(OnlineEventWindows));
    if (cursor > end || sizeof(OnlineEventWindows) > end - cursor) {
        set_error(error, error_capacity, "online-window object alignment failed");
        return nullptr;
    }
    auto *state = new (reinterpret_cast<void *>(cursor)) OnlineEventWindows();
    cursor += sizeof(*state);
    cursor = align_up(cursor, alignof(EventSlot));
    const size_t event_bytes =
        static_cast<size_t>(config->maximum_events) * sizeof(EventSlot);
    if (cursor > end || event_bytes > end - cursor) {
        set_error(error, error_capacity, "online-window event storage failed");
        return nullptr;
    }
    state->events = reinterpret_cast<EventSlot *>(cursor);
    for (uint32_t slot = 0u; slot < config->maximum_events; ++slot)
        new (&state->events[slot]) EventSlot();
    cursor += event_bytes;
    cursor = align_up(cursor, alignof(uint32_t));
    const size_t heap_bytes =
        static_cast<size_t>(config->maximum_events) * sizeof(uint32_t);
    if (cursor > end || heap_bytes > end - cursor) {
        set_error(error, error_capacity, "online-window heap storage failed");
        return nullptr;
    }
    state->due_heap = reinterpret_cast<uint32_t *>(cursor);
    cursor += heap_bytes;
    if (config->stage_aware_enabled) {
        cursor = align_up(cursor, alignof(fk_stage_aware_event_state));
        const size_t stage_bytes = static_cast<size_t>(config->maximum_events) *
            sizeof(fk_stage_aware_event_state);
        if (cursor > end || stage_bytes > end - cursor) {
            set_error(error, error_capacity, "online-window stage storage failed");
            return nullptr;
        }
        state->stage_states =
            reinterpret_cast<fk_stage_aware_event_state *>(cursor);
        for (uint32_t slot = 0u; slot < config->maximum_events; ++slot)
            fk_stage_aware_event_reset(&state->stage_states[slot]);
        cursor += stage_bytes;
    }
    cursor = align_up(cursor, alignof(FlowSnapshot));
    const size_t flow_count = config->maximum_total_flows;
    const size_t flow_bytes = flow_count * sizeof(FlowSnapshot);
    if (cursor > end || flow_bytes > end - cursor) {
        set_error(error, error_capacity, "online-window flow storage failed");
        return nullptr;
    }
    state->flows = reinterpret_cast<FlowSnapshot *>(cursor);
    for (size_t index = 0u; index < flow_count; ++index)
        new (&state->flows[index]) FlowSnapshot();
    cursor += flow_bytes;

    if (causal_route) {
        cursor = align_up(cursor, alignof(CausalFlowSnapshot));
        const size_t causal_bytes = flow_count * sizeof(CausalFlowSnapshot);
        if (cursor > end || causal_bytes > end - cursor) {
            set_error(error, error_capacity, "causal flow storage failed");
            return nullptr;
        }
        state->causal_flows = reinterpret_cast<CausalFlowSnapshot *>(cursor);
        for (size_t index = 0u; index < flow_count; ++index)
            new (&state->causal_flows[index]) CausalFlowSnapshot();
        cursor += causal_bytes;
    }

    state->student = config->student;
    state->metadata = metadata;
    state->sink = config->sink;
    state->sink_context = config->sink_context;
    state->causal_model = config->causal_model;
    state->causal_model_context = config->causal_model_context;
    state->causal_decision_threshold = config->causal_decision_threshold;
    state->external_watermarks_only = config->external_watermarks_only;
    state->stage_aware_enabled = config->stage_aware_enabled;
    state->stage_policy = config->stage_aware_policy;
    if (state->stage_aware_enabled &&
        !fk_stage_aware_policy_valid(&state->stage_policy)) {
        set_error(error, error_capacity, "invalid stage-aware policy");
        return nullptr;
    }
    state->maximum_events = config->maximum_events;
    state->maximum_flows_per_event = config->maximum_flows_per_event;
    state->maximum_total_flows = config->maximum_total_flows;
    state->flow_free_head = 0u;
    for (uint32_t index = 0u; index < config->maximum_total_flows; ++index)
        state->flows[index].next =
            index + 1u < config->maximum_total_flows
                ? index + 1u
                : kNone;
    state->reserved_bytes = cursor - begin;
    state->complete = true;
    state->stats.maximum_events = config->maximum_events;
    state->stats.maximum_flows_per_event =
        config->maximum_flows_per_event;
    state->stats.maximum_total_flows = config->maximum_total_flows;
    state->stats.reserved_bytes = state->reserved_bytes;
    set_error(error, error_capacity, "");
    return reinterpret_cast<fk_online_event_windows *>(state);
}

static bool flow_epoch_bind_internal(
        OnlineEventWindows &state,
        const fk_actor_session_result *association,
        const fk_actor_flow_identity_v2 *flow_identity,
        uint64_t observation_timestamp_ns,
        IngressIdentityMode requested_mode,
        bool flow_reopen) {
    if (flow_reopen)
        state.stats.flow_reopen_messages++;
    else
        state.stats.flow_open_messages++;
    if (!identity_mode_allowed(state, requested_mode))
        return false;
    if (!valid_association(
            state, association, flow_identity, observation_timestamp_ns)) {
        state.stats.stale_handle_rejections++;
        state.complete = false;
        return false;
    }
    if (!flow_reopen &&
        flow_identity->presentation.first_timestamp_ns !=
            observation_timestamp_ns) {
        state.stats.non_first_packet_flow_open_rejections++;
        state.complete = false;
        return false;
    }
    if (flow_reopen &&
        flow_identity->presentation.first_timestamp_ns >
            observation_timestamp_ns) {
        state.stats.noncausal_flow_reopen_rejections++;
        state.complete = false;
        return false;
    }
    if (!prepare_input(state, observation_timestamp_ns))
        return false;

    EventSlot &event = state.events[association->event_slot];
    bool activated_event = false;
    if (!event.active || event.event_id != association->event_id ||
        event.generation != association->event_generation) {
        if (!association->created) {
            state.stats.noncreating_event_activation_rejections++;
            state.complete = false;
            return false;
        }
        if (event.active) {
            /* Even an exact actor generation successor is evidence that the
             * bounded actor table discarded an event before the window layer
             * reached its semantic retirement horizon.  Audit the conflict
             * and fail closed; formal runs must provision enough independent
             * detection-service capacity that this branch is unreachable. */
            state.stats.live_slot_reuse_conflicts++;
            state.complete = false;
            retire_event(
                state, association->event_slot, RetirementReason::Reuse);
        } else if (event.event_id != 0u) {
            state.stats.event_slots_reused++;
        }
        event.event_id = association->event_id;
        event.generation = association->event_generation;
        event.start_ns = flow_reopen
            ? observation_timestamp_ns
            : flow_identity->presentation.first_timestamp_ns;
        event.last_activity_ns = observation_timestamp_ns;
        event.next_anchor_ns = event.start_ns;
        event.next_trigger_ordinal = 0u;
        event.snapshot_version = 0u;
        event.last_scored_snapshot_version = 0u;
        event.last_accumulator_update_ns = 0u;
        event.flow_count = 0u;
        event.flow_head = kNone;
        event.active = true;
        event.alert_latched = false;
        event.has_accumulator_update = false;
        event.behavior_stage = flow_reopen
            ? FK_EVENT_STAGE_REOPENED : FK_EVENT_STAGE_BOOTSTRAP;
        event.behavior_evidence_mask = 0u;
        event.stage_reopened_pending = flow_reopen;
        fk_event_student_event_reset(&event.student_state);
        if (state.stage_aware_enabled)
            fk_stage_aware_event_reset(
                &state.stage_states[association->event_slot]);
        state.stats.event_slots_activated++;
        state.stats.active_events++;
        activated_event = true;
    }
    if (flow_reopen && association->created != activated_event) {
        state.stats.noncreating_event_activation_rejections++;
        state.complete = false;
        return false;
    }
    FlowSnapshot *existing = find_flow(
        state, association->event_slot, *flow_identity);
    if (existing != nullptr) {
        if (flow_reopen) {
            state.stats.duplicate_flow_reopen_messages++;
            state.complete = false;
            return false;
        }
        if (flow_identity->logical_connection_id != 0u &&
            !compact_presentation_equal(
                *existing, flow_identity->presentation)) {
            /* A new five-tuple/FlowTable incarnation for the same immutable
             * logical connection confirms rebind.  Preserve event start,
             * latest embedding/timestamp, tick grid, prefix state, and alert
             * latch; only diagnostic presentation and activity move forward. */
            update_compact_diagnostic_presentation(
                *existing, flow_identity->presentation);
            event.last_activity_ns = std::max(
                event.last_activity_ns, observation_timestamp_ns);
            heap_update(state, association->event_slot);
            state.stats.logical_rebind_confirmations++;
            lock_identity_mode(state, requested_mode);
            return true;
        }
        state.stats.duplicate_flow_open_messages++;
        state.complete = false;
        return false;
    }
    if (event.flow_count >= state.maximum_flows_per_event ||
        state.flow_free_head == kNone) {
        state.stats.flow_capacity_overflows++;
        state.complete = false;
        return false;
    }
    const uint32_t flow_index = state.flow_free_head;
    FlowSnapshot &flow = state.flows[flow_index];
    state.flow_free_head = flow.next;
    flow.next = event.flow_head;
    event.flow_head = flow_index;
    event.flow_count++;
    store_compact_identity(flow, *flow_identity);
    flow.snapshot_timestamp_ns = 0u;
    flow.has_snapshot = false;
    event.last_activity_ns = std::max(
        event.last_activity_ns, observation_timestamp_ns);
    if (event.heap_position == kNone)
        heap_insert(state, association->event_slot);
    else
        heap_update(state, association->event_slot);
    state.stats.retained_flows++;
    if (flow_reopen) {
        event.behavior_stage = FK_EVENT_STAGE_REOPENED;
        event.stage_reopened_pending = true;
        if (activated_event)
            state.stats.flow_reopen_new_event_activations++;
        else
            state.stats.flow_reopen_existing_event_joins++;
    }
    refresh_peaks(state);
    lock_identity_mode(state, requested_mode);
    return true;
}

bool fk_online_event_windows_flow_open(
        fk_online_event_windows *windows,
        const fk_actor_session_result *association,
        const fk_actor_flow_identity *flow_identity,
        uint64_t observation_timestamp_ns) {
    if (windows == nullptr)
        return false;
    fk_actor_flow_identity_v2 identity_v2{};
    const fk_actor_flow_identity_v2 *identity_pointer = nullptr;
    if (flow_identity != nullptr) {
        identity_v2.presentation = *flow_identity;
        identity_v2.logical_connection_id = 0u;
        identity_pointer = &identity_v2;
    }
    return flow_epoch_bind_internal(
        *implementation(windows),
        association,
        identity_pointer,
        observation_timestamp_ns,
        IngressIdentityMode::V1,
        false);
}

bool fk_online_event_windows_flow_open_v2(
        fk_online_event_windows *windows,
        const fk_actor_session_result *association,
        const fk_actor_flow_identity_v2 *flow_identity,
        uint64_t observation_timestamp_ns) {
    if (windows == nullptr)
        return false;
    return flow_epoch_bind_internal(
        *implementation(windows),
        association,
        flow_identity,
        observation_timestamp_ns,
        IngressIdentityMode::V2,
        false);
}

bool fk_online_event_windows_flow_reopen(
        fk_online_event_windows *windows,
        const fk_actor_session_result *association,
        const fk_actor_flow_identity *flow_identity,
        uint64_t observation_timestamp_ns) {
    if (windows == nullptr)
        return false;
    fk_actor_flow_identity_v2 identity_v2{};
    const fk_actor_flow_identity_v2 *identity_pointer = nullptr;
    if (flow_identity != nullptr) {
        identity_v2.presentation = *flow_identity;
        identity_v2.logical_connection_id = 0u;
        identity_pointer = &identity_v2;
    }
    return flow_epoch_bind_internal(
        *implementation(windows),
        association,
        identity_pointer,
        observation_timestamp_ns,
        IngressIdentityMode::V1,
        true);
}

bool fk_online_event_windows_flow_reopen_v2(
        fk_online_event_windows *windows,
        const fk_actor_session_result *association,
        const fk_actor_flow_identity_v2 *flow_identity,
        uint64_t observation_timestamp_ns) {
    if (windows == nullptr)
        return false;
    return flow_epoch_bind_internal(
        *implementation(windows),
        association,
        flow_identity,
        observation_timestamp_ns,
        IngressIdentityMode::V2,
        true);
}

static bool checkpoint_internal(
        OnlineEventWindows &state,
        const fk_actor_session_result *association,
        const fk_actor_flow_identity_v2 *flow_identity,
        uint64_t observation_timestamp_ns,
        const float *features,
        size_t feature_count,
        IngressIdentityMode requested_mode,
        TriggerProtocol requested_trigger_protocol,
        uint8_t checkpoint_packet,
        double record_score,
        uint8_t original_action_mask,
        bool causal_input) {
    state.stats.checkpoint_messages++;
    if (!identity_mode_allowed(state, requested_mode))
        return false;
    if (!trigger_protocol_allowed(state, requested_trigger_protocol))
        return false;
    const bool triggered = requested_trigger_protocol ==
        TriggerProtocol::CheckpointPeriodicV2;
    const bool causal_route = state.causal_model != nullptr;
    if (causal_input != causal_route ||
        (causal_route &&
         (!std::isfinite(record_score) || record_score < 0.0 ||
          record_score > 1.0 || original_action_mask > 7u))) {
        state.stats.causal_model_failures++;
        state.complete = false;
        return false;
    }
    if ((triggered && !valid_checkpoint_packet(checkpoint_packet)) ||
        (!triggered && checkpoint_packet != 0u)) {
        state.stats.invalid_checkpoint_packet_rejections++;
        state.complete = false;
        return false;
    }
    if (triggered)
        state.stats.checkpoint_trigger_messages++;
    if (!valid_association(
            state, association, flow_identity, observation_timestamp_ns) ||
        features == nullptr ||
        feature_count != FK_EVENT_STUDENT_INPUT_FEATURES) {
        state.stats.stale_handle_rejections++;
        state.complete = false;
        return false;
    }
    if (!prepare_input(state, observation_timestamp_ns))
        return false;
    EventSlot *event = resolve_event(state, *association);
    if (event == nullptr) {
        state.stats.stale_handle_rejections++;
        state.complete = false;
        return false;
    }
    FlowSnapshot *flow = find_flow(
        state, association->event_slot, *flow_identity);
    if (flow == nullptr) {
        state.stats.unopened_checkpoint_rejections++;
        state.complete = false;
        return false;
    }
    if (observation_timestamp_ns < flow->open_timestamp_ns ||
        (flow->has_snapshot &&
         observation_timestamp_ns < flow->snapshot_timestamp_ns)) {
        state.stats.out_of_order_rejections++;
        state.complete = false;
        return false;
    }
    if (event->snapshot_version == UINT64_MAX) {
        state.stats.snapshot_version_overflows++;
        state.complete = false;
        return false;
    }
    if (causal_route) {
        const ptrdiff_t flow_index = flow - state.flows;
        if (state.causal_flows == nullptr || flow_index < 0 ||
            static_cast<uint64_t>(flow_index) >= state.maximum_total_flows) {
            state.stats.causal_model_failures++;
            state.complete = false;
            return false;
        }
        CausalFlowSnapshot &causal = state.causal_flows[flow_index];
        causal.record_score = record_score;
        for (size_t column = 0u;
             column < FK_ONLINE_EVENT_CAUSAL_STATE_COLUMNS; ++column) {
            const float value = features[30u + column];
            if (!std::isfinite(value)) {
                state.stats.causal_model_failures++;
                state.complete = false;
                return false;
            }
            causal.masked_state_columns[column] = value;
        }
        causal.original_action_mask = original_action_mask;
    } else {
        fk_event_student_embedding encoded{};
        if (!fk_event_student_encode_flow(
                state.student, features, feature_count, &encoded)) {
            state.stats.encode_failures++;
            state.complete = false;
            return false;
        }
        flow->embedding = encoded;
    }
    flow->snapshot_timestamp_ns = observation_timestamp_ns;
    flow->has_snapshot = true;
    event->snapshot_version++;
    if (state.stage_aware_enabled) {
        uint8_t stage = FK_EVENT_STAGE_BOOTSTRAP;
        const bool tls_or_quic_candidate = features[7] > 0.5f;
        const bool handshake_complete = features[99] > 0.5f;
        const bool application_data_observed = handshake_complete &&
            checkpoint_packet == 20u && features[11] > 0.0f;
        const bool retry_or_migration = features[28] > 0.5f ||
            features[111] > 0.5f;
        if (!fk_stage_aware_infer_stage(
                checkpoint_packet, tls_or_quic_candidate,
                handshake_complete, application_data_observed,
                retry_or_migration, event->stage_reopened_pending, &stage)) {
            state.complete = false;
            return false;
        }
        event->behavior_stage = stage;
        event->behavior_evidence_mask =
            static_cast<uint8_t>((features[38] > 0.5f ? 1u : 0u) |
                                 (features[39] > 0.5f ? 2u : 0u) |
                                 (features[40] > 0.5f ? 4u : 0u));
    }
    event->last_activity_ns = std::max(
        event->last_activity_ns, observation_timestamp_ns);
    heap_update(state, association->event_slot);
    state.stats.encoded_checkpoints++;
    lock_identity_mode(state, requested_mode);
    lock_trigger_protocol(state, requested_trigger_protocol);
    if (triggered && !emit_trigger(
            state,
            association->event_slot,
            observation_timestamp_ns,
            FK_ONLINE_EVENT_TRIGGER_KIND_CHECKPOINT,
            checkpoint_packet))
        return false;
    return true;
}

bool fk_online_event_windows_checkpoint(
        fk_online_event_windows *windows,
        const fk_actor_session_result *association,
        const fk_actor_flow_identity *flow_identity,
        uint64_t observation_timestamp_ns,
        const float *features,
        size_t feature_count) {
    if (windows == nullptr)
        return false;
    fk_actor_flow_identity_v2 identity_v2{};
    const fk_actor_flow_identity_v2 *identity_pointer = nullptr;
    if (flow_identity != nullptr) {
        identity_v2.presentation = *flow_identity;
        identity_v2.logical_connection_id = 0u;
        identity_pointer = &identity_v2;
    }
    return checkpoint_internal(
        *implementation(windows),
        association,
        identity_pointer,
        observation_timestamp_ns,
        features,
        feature_count,
        IngressIdentityMode::V1,
        TriggerProtocol::PeriodicV1,
        0u, 0.0, 0u, false);
}

bool fk_online_event_windows_checkpoint_v2(
        fk_online_event_windows *windows,
        const fk_actor_session_result *association,
        const fk_actor_flow_identity_v2 *flow_identity,
        uint64_t observation_timestamp_ns,
        const float *features,
        size_t feature_count) {
    if (windows == nullptr)
        return false;
    return checkpoint_internal(
        *implementation(windows),
        association,
        flow_identity,
        observation_timestamp_ns,
        features,
        feature_count,
        IngressIdentityMode::V2,
        TriggerProtocol::PeriodicV1,
        0u, 0.0, 0u, false);
}


bool fk_online_event_windows_checkpoint_triggered(
        fk_online_event_windows *windows,
        const fk_actor_session_result *association,
        const fk_actor_flow_identity *flow_identity,
        uint64_t observation_timestamp_ns,
        uint8_t checkpoint_packet,
        const float *features,
        size_t feature_count) {
    if (windows == nullptr)
        return false;
    fk_actor_flow_identity_v2 identity_v2{};
    const fk_actor_flow_identity_v2 *identity_pointer = nullptr;
    if (flow_identity != nullptr) {
        identity_v2.presentation = *flow_identity;
        identity_v2.logical_connection_id = 0u;
        identity_pointer = &identity_v2;
    }
    return checkpoint_internal(
        *implementation(windows),
        association,
        identity_pointer,
        observation_timestamp_ns,
        features,
        feature_count,
        IngressIdentityMode::V1,
        TriggerProtocol::CheckpointPeriodicV2,
        checkpoint_packet, 0.0, 0u, false);
}

bool fk_online_event_windows_checkpoint_triggered_v2(
        fk_online_event_windows *windows,
        const fk_actor_session_result *association,
        const fk_actor_flow_identity_v2 *flow_identity,
        uint64_t observation_timestamp_ns,
        uint8_t checkpoint_packet,
        const float *features,
        size_t feature_count) {
    if (windows == nullptr)
        return false;
    return checkpoint_internal(
        *implementation(windows),
        association,
        flow_identity,
        observation_timestamp_ns,
        features,
        feature_count,
        IngressIdentityMode::V2,
        TriggerProtocol::CheckpointPeriodicV2,
        checkpoint_packet, 0.0, 0u, false);
}

bool fk_online_event_windows_checkpoint_triggered_causal_v2(
        fk_online_event_windows *windows,
        const fk_actor_session_result *association,
        const fk_actor_flow_identity_v2 *flow_identity,
        uint64_t observation_timestamp_ns,
        uint8_t checkpoint_packet,
        const float *features,
        size_t feature_count,
        double record_score,
        uint8_t original_action_mask) {
    if (windows == nullptr)
        return false;
    return checkpoint_internal(
        *implementation(windows), association, flow_identity,
        observation_timestamp_ns, features, feature_count,
        IngressIdentityMode::V2,
        TriggerProtocol::CheckpointPeriodicV2,
        checkpoint_packet, record_score, original_action_mask, true);
}

bool fk_online_event_windows_retire_event(
        fk_online_event_windows *windows,
        const fk_actor_session_result *association) {
    if (windows == nullptr || association == nullptr)
        return false;
    OnlineEventWindows &state = *implementation(windows);
    state.stats.explicit_retire_commands++;
    if (association->event_id == 0u ||
        association->event_generation == 0u ||
        association->event_slot >= state.maximum_events) {
        state.stats.stale_handle_rejections++;
        state.complete = false;
        return false;
    }
    EventSlot &event = state.events[association->event_slot];
    if (!event.active) {
        state.stats.explicit_retire_noops++;
        return true;
    }
    if (event.event_id != association->event_id ||
        event.generation != association->event_generation) {
        state.stats.stale_handle_rejections++;
        state.complete = false;
        return false;
    }
    retire_event(
        state, association->event_slot, RetirementReason::Explicit);
    return true;
}

bool fk_online_event_windows_advance_watermark(
        fk_online_event_windows *windows,
        uint64_t inclusive_watermark_ns) {
    if (windows == nullptr)
        return false;
    return advance_internal(
        *implementation(windows), inclusive_watermark_ns);
}

bool fk_online_event_windows_advance_watermark_step(
        fk_online_event_windows *windows,
        uint64_t inclusive_watermark_ns,
        uint32_t max_due_ticks,
        bool *complete) {
    if (complete != nullptr)
        *complete = false;
    if (windows == nullptr || complete == nullptr)
        return false;
    return advance_step_internal(
        *implementation(windows),
        inclusive_watermark_ns,
        max_due_ticks,
        *complete);
}

bool fk_online_event_windows_get_stats(
        const fk_online_event_windows *windows,
        fk_online_event_windows_stats *stats) {
    if (windows == nullptr || stats == nullptr)
        return false;
    const OnlineEventWindows &state = *implementation(windows);
    *stats = state.stats;
    stats->watermark_initialized = state.watermark_initialized;
    stats->inclusive_watermark_ns = state.inclusive_watermark_ns;
    stats->formal_completeness = state.complete;
    return true;
}
