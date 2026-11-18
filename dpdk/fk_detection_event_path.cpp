#include "fk_detection_event_path.h"

#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <limits>
#include <new>

namespace {

constexpr uint64_t kMagic = 0x464b444554455631ull;  // "FKDETEV1"

static_assert(
    sizeof(fk_detection_event_checkpoint) == 64u &&
    offsetof(fk_detection_event_checkpoint, key) == 0u &&
    offsetof(fk_detection_event_checkpoint, flow_identity) == 40u &&
    offsetof(
        fk_detection_event_checkpoint,
        observation_timestamp_ns) == 56u,
    "v1 detection checkpoint ABI must remain unchanged");
static_assert(
    sizeof(fk_detection_event_checkpoint_v2) == 72u &&
    offsetof(fk_detection_event_checkpoint_v2, key) == 0u &&
    offsetof(fk_detection_event_checkpoint_v2, flow_identity) == 40u &&
    offsetof(
        fk_detection_event_checkpoint_v2,
        observation_timestamp_ns) == 64u,
    "v2 detection checkpoint ABI must remain stable");

struct State {
    uint64_t magic;
    fk_detection_event_path_stats stats;
    fk_actor_session *sessions;
    uint32_t *alerted_generation;
    uint32_t maximum_events;
};

static State *implementation(fk_detection_event_path *path) {
    return reinterpret_cast<State *>(path);
}

static const State *implementation(
        const fk_detection_event_path *path) {
    return reinterpret_cast<const State *>(path);
}

static uintptr_t aligned(uintptr_t value, size_t alignment) {
    const uintptr_t remainder = value % alignment;
    return remainder == 0u
        ? value
        : value + alignment - remainder;
}

static bool checked_add(size_t &value, size_t increment) {
    if (increment > std::numeric_limits<size_t>::max() - value)
        return false;
    value += increment;
    return true;
}

static bool aligned_offset(size_t &value, size_t alignment) {
    const size_t remainder = value % alignment;
    return remainder == 0u ||
        checked_add(value, alignment - remainder);
}

static bool checked_multiply(
        size_t left, size_t right, size_t &result) {
    if (left != 0u &&
        right > std::numeric_limits<size_t>::max() / left)
        return false;
    result = left * right;
    return true;
}

static void set_error(
        char *error,
        size_t capacity,
        const char *message) {
    if (error != nullptr && capacity != 0u)
        std::snprintf(error, capacity, "%s", message);
}

}  // namespace

extern "C" {

size_t fk_detection_event_path_storage_bytes(
        const fk_actor_session_config *config) {
    const size_t actor_bytes =
        fk_actor_session_storage_bytes(config);
    if (actor_bytes == 0u || config == nullptr)
        return 0u;
    size_t bytes = alignof(std::max_align_t) - 1u;
    size_t generations_bytes = 0u;
    if (!aligned_offset(bytes, alignof(State)) ||
        !checked_add(bytes, sizeof(State)) ||
        !aligned_offset(bytes, alignof(uint32_t)) ||
        !checked_multiply(
            config->maximum_events,
            sizeof(uint32_t),
            generations_bytes) ||
        !checked_add(bytes, generations_bytes) ||
        !checked_add(bytes, actor_bytes))
        return 0u;
    return bytes;
}

fk_detection_event_path *fk_detection_event_path_init(
        void *storage,
        size_t storage_bytes,
        const fk_actor_session_config *config,
        char *error,
        size_t error_capacity) {
    set_error(error, error_capacity, "");
    const size_t required =
        fk_detection_event_path_storage_bytes(config);
    if (storage == nullptr || required == 0u ||
        storage_bytes < required) {
        set_error(
            error,
            error_capacity,
            "invalid detection-event storage or actor config");
        return nullptr;
    }
    const uintptr_t start = reinterpret_cast<uintptr_t>(storage);
    if (storage_bytes >
        std::numeric_limits<uintptr_t>::max() - start) {
        set_error(
            error, error_capacity, "detection-event storage overflows");
        return nullptr;
    }
    const uintptr_t end = start + storage_bytes;
    const uintptr_t state_address = aligned(start, alignof(State));
    if (state_address > end ||
        sizeof(State) > end - state_address) {
        set_error(
            error, error_capacity, "detection-event storage is too small");
        return nullptr;
    }
    State *state = new (
        reinterpret_cast<void *>(state_address)) State{};
    uintptr_t cursor = state_address + sizeof(State);
    cursor = aligned(cursor, alignof(uint32_t));
    const size_t generations_bytes =
        static_cast<size_t>(config->maximum_events) *
        sizeof(uint32_t);
    if (cursor > end || generations_bytes > end - cursor) {
        set_error(
            error, error_capacity, "detection-event generation storage failed");
        return nullptr;
    }
    state->alerted_generation =
        reinterpret_cast<uint32_t *>(cursor);
    std::memset(
        state->alerted_generation, 0, generations_bytes);
    state->maximum_events = config->maximum_events;
    const uintptr_t actor_address = cursor + generations_bytes;
    const size_t actor_bytes = static_cast<size_t>(end - actor_address);
    state->sessions = fk_actor_session_init(
        reinterpret_cast<void *>(actor_address),
        actor_bytes,
        config,
        error,
        error_capacity);
    if (state->sessions == nullptr)
        return nullptr;
    state->magic = kMagic;
    return reinterpret_cast<fk_detection_event_path *>(state);
}

bool fk_detection_event_path_observe_checkpoint_v2(
        fk_detection_event_path *path,
        const fk_detection_event_checkpoint_v2 *checkpoint,
        fk_detection_event_checkpoint_result *result) {
    if (result != nullptr)
        std::memset(result, 0, sizeof(*result));
    if (path == nullptr || checkpoint == nullptr || result == nullptr)
        return false;
    State &state = *implementation(path);
    if (state.magic != kMagic)
        return false;
    state.stats.checkpoint_observations++;
    if (checkpoint->observation_timestamp_ns <
        checkpoint->flow_identity.presentation.first_timestamp_ns) {
        state.stats.timestamp_domain_rejections++;
        state.stats.association_failures++;
        result->association.reason = FK_ACTOR_REASON_INVALID_INPUT;
        return false;
    }
    if (!fk_actor_session_observe_v2(
            state.sessions,
            &checkpoint->key,
            &checkpoint->flow_identity,
            checkpoint->observation_timestamp_ns,
            &result->association)) {
        state.stats.association_failures++;
        return false;
    }
    result->associated = true;
    state.stats.last_event_id = result->association.event_id;
    state.stats.last_event_generation =
        result->association.event_generation;
    return true;
}

bool fk_detection_event_path_observe_checkpoint(
        fk_detection_event_path *path,
        const fk_detection_event_checkpoint *checkpoint,
        fk_detection_event_checkpoint_result *result) {
    if (checkpoint == nullptr) {
        return fk_detection_event_path_observe_checkpoint_v2(
            path, nullptr, result);
    }
    fk_detection_event_checkpoint_v2 checkpoint_v2{};
    checkpoint_v2.key = checkpoint->key;
    checkpoint_v2.flow_identity.presentation =
        checkpoint->flow_identity;
    checkpoint_v2.flow_identity.logical_connection_id = 0u;
    checkpoint_v2.observation_timestamp_ns =
        checkpoint->observation_timestamp_ns;
    return fk_detection_event_path_observe_checkpoint_v2(
        path, &checkpoint_v2, result);
}

bool fk_detection_event_path_record_decision(
        fk_detection_event_path *path,
        const fk_actor_session_result *association,
        bool alert,
        fk_detection_event_decision_result *result) {
    if (result != nullptr)
        std::memset(result, 0, sizeof(*result));
    if (path == nullptr || association == nullptr || result == nullptr)
        return false;
    State &state = *implementation(path);
    if (state.magic != kMagic)
        return false;
    state.stats.detector_decisions++;
    if (!fk_actor_session_event_handle_active(
            state.sessions,
            association->event_slot,
            association->event_generation,
            association->event_id)) {
        state.stats.stale_decision_handles++;
        return false;
    }
    result->accepted = true;
    if (!alert) {
        state.stats.non_alert_decisions++;
        return true;
    }
    state.stats.alert_windows++;
    if (association->event_slot >= state.maximum_events) {
        state.stats.stale_decision_handles++;
        result->accepted = false;
        return false;
    }
    uint32_t &latched_generation =
        state.alerted_generation[association->event_slot];
    if (latched_generation != association->event_generation) {
        latched_generation = association->event_generation;
        result->first_alert_for_event = true;
        state.stats.alert_events++;
    }
    return true;
}

bool fk_detection_event_path_get_event_identity(
        const fk_detection_event_path *path,
        const fk_actor_session_result *association,
        fk_actor_event_identity *identity) {
    if (identity != nullptr)
        std::memset(identity, 0, sizeof(*identity));
    if (path == nullptr || association == nullptr || identity == nullptr)
        return false;
    const State &state = *implementation(path);
    if (state.magic != kMagic)
        return false;
    return fk_actor_session_get_event_identity(
        state.sessions,
        association->event_slot,
        association->event_generation,
        association->event_id,
        identity);
}

bool fk_detection_event_path_get_stats(
        const fk_detection_event_path *path,
        fk_detection_event_path_stats *stats) {
    if (path == nullptr || stats == nullptr)
        return false;
    const State &state = *implementation(path);
    if (state.magic != kMagic)
        return false;
    *stats = state.stats;
    return fk_actor_session_get_stats(
        state.sessions, &stats->association);
}

}  // extern "C"
