#include "fk_student_shards.h"

#include <algorithm>
#include <atomic>
#include <cstdio>
#include <cstring>
#include <limits>
#include <memory>
#include <new>
#include <time.h>

namespace {

enum class CommandKind : uint8_t {
    FlowOpen = 1u,
    Checkpoint = 2u,
    Retire = 3u,
    Watermark = 4u,
    FinalWatermark = 5u,
    FlowReopen = 6u,
};

enum class IdentityMode : uint8_t {
    Unset = FK_STUDENT_SHARDS_IDENTITY_ABI_MODE_UNSET,
    V1 = FK_STUDENT_SHARDS_IDENTITY_ABI_MODE_V1,
    V2 = FK_STUDENT_SHARDS_IDENTITY_ABI_MODE_V2,
};

enum class TriggerMode : uint8_t {
    Unset = 0u,
    PeriodicV1 = FK_ONLINE_EVENT_TRIGGER_PROTOCOL_PERIODIC_V1,
    CheckpointPeriodicV2 =
        FK_ONLINE_EVENT_TRIGGER_PROTOCOL_CHECKPOINT_PERIODIC_V2,
};

struct Command {
    fk_actor_session_result association{};
    fk_actor_flow_identity_v2 flow_identity{};
    uint64_t observation_timestamp_ns = 0u;
    uint64_t enqueue_monotonic_ns = 0u;
    uint64_t sequence = 0u;
    uint32_t payload_slot = UINT32_MAX;
    CommandKind kind = CommandKind::FlowOpen;
    IdentityMode identity_mode = IdentityMode::Unset;
    TriggerMode trigger_mode = TriggerMode::Unset;
    uint8_t checkpoint_packet = 0u;
};

struct Response {
    fk_student_shard_result result{};
};

static_assert(sizeof(fk_actor_flow_identity) == 16u);
static_assert(sizeof(fk_actor_flow_identity_v2) == 24u);
static_assert(sizeof(Command) == FK_STUDENT_SHARDS_COMMAND_ENTRY_V2_BYTES);
static_assert(sizeof(Response) % 4u == 0u);

constexpr uint32_t kLogicalIdentityCommandExtensionBytes =
    sizeof(fk_actor_flow_identity_v2) - sizeof(fk_actor_flow_identity);
static_assert(kLogicalIdentityCommandExtensionBytes == 8u);

template <typename T>
class SpscRing {
public:
    bool initialize(uint32_t capacity) {
        if (capacity < 2u || (capacity & (capacity - 1u)) != 0u)
            return false;
        storage_.reset(new (std::nothrow) T[capacity]);
        if (!storage_)
            return false;
        capacity_ = capacity;
        mask_ = capacity - 1u;
        return true;
    }

    bool can_push(uint32_t count = 1u) const {
        const uint64_t tail = tail_.load(std::memory_order_relaxed);
        const uint64_t head = head_.load(std::memory_order_acquire);
        return tail - head <= capacity_ &&
            count <= capacity_ - static_cast<uint32_t>(tail - head);
    }

    bool push(const T &value) {
        const uint64_t tail = tail_.load(std::memory_order_relaxed);
        const uint64_t head = head_.load(std::memory_order_acquire);
        if (tail - head >= capacity_)
            return false;
        storage_[static_cast<uint32_t>(tail) & mask_] = value;
        tail_.store(tail + 1u, std::memory_order_release);
        return true;
    }

    bool pop(T &value) {
        const uint64_t head = head_.load(std::memory_order_relaxed);
        const uint64_t tail = tail_.load(std::memory_order_acquire);
        if (head == tail)
            return false;
        value = storage_[static_cast<uint32_t>(head) & mask_];
        head_.store(head + 1u, std::memory_order_release);
        return true;
    }

    uint32_t count() const {
        const uint64_t tail = tail_.load(std::memory_order_acquire);
        const uint64_t head = head_.load(std::memory_order_acquire);
        return static_cast<uint32_t>(tail - head);
    }

    uint32_t free_count() const {
        return capacity_ - count();
    }

    bool empty() const { return count() == 0u; }
    uint64_t reserved_bytes() const {
        return static_cast<uint64_t>(capacity_) * sizeof(T);
    }

private:
    std::unique_ptr<T[]> storage_;
    uint32_t capacity_ = 0u;
    uint32_t mask_ = 0u;
    alignas(64) std::atomic<uint64_t> head_{0u};
    alignas(64) std::atomic<uint64_t> tail_{0u};
};

struct FeaturePayload {
    float features[FK_EVENT_STUDENT_INPUT_FEATURES]{};
    uint32_t next_free = UINT32_MAX;
    std::atomic<uint8_t> in_use{0u};
};

struct SlotBinding {
    uint64_t event_id = 0u;
    uint32_t generation = 0u;
    uint16_t owner = UINT16_MAX;
    bool active = false;
    uint8_t reserved = 0u;
};

struct Worker;

static uint64_t monotonic_ns() {
    timespec value{};
    (void)clock_gettime(CLOCK_MONOTONIC, &value);
    return static_cast<uint64_t>(value.tv_sec) * UINT64_C(1000000000) +
        static_cast<uint64_t>(value.tv_nsec);
}

static void set_error(char *error, size_t capacity, const char *message) {
    if (error != nullptr && capacity != 0u)
        std::snprintf(error, capacity, "%s", message);
}

static bool valid_worker_count(uint16_t count) {
    return count == 2u || count == 4u || count == 8u;
}

static bool power_of_two(uint32_t value) {
    return value >= 2u && (value & (value - 1u)) == 0u;
}

static void update_peak(uint64_t &peak, uint64_t value) {
    peak = std::max(peak, value);
}

}  // namespace

struct fk_student_shards {
    fk_student_shards_config config{};
    std::unique_ptr<fk_event_student, decltype(&fk_event_student_destroy)>
        student{nullptr, fk_event_student_destroy};
    fk_event_student_metadata metadata{};
    std::unique_ptr<Worker[]> workers;
    std::unique_ptr<SlotBinding[]> bindings;
    uint64_t flow_open_enqueues = 0u;
    uint64_t checkpoint_enqueues = 0u;
    uint64_t retire_enqueues = 0u;
    uint64_t watermark_broadcasts = 0u;
    uint64_t final_watermark_broadcasts = 0u;
    uint64_t data_queue_full = 0u;
    uint64_t watermark_queue_full = 0u;
    uint64_t watermark_regressions = 0u;
    uint64_t invalid_routes = 0u;
    uint64_t slot_owner_mismatches = 0u;
    uint64_t slot_reuse_retirements = 0u;
    uint64_t feature_payload_exhaustions = 0u;
    uint64_t identity_mode_rejections = 0u;
    uint64_t logical_flow_open_enqueues = 0u;
    uint64_t logical_checkpoint_enqueues = 0u;
    uint64_t flow_reopen_enqueues = 0u;
    uint64_t logical_flow_reopen_enqueues = 0u;
    uint64_t flow_reopen_checkpoint_pair_enqueues = 0u;
    uint64_t checkpoint_trigger_enqueues = 0u;
    uint64_t trigger_protocol_rejections = 0u;
    uint64_t invalid_checkpoint_packet_rejections = 0u;
    uint64_t last_broadcast_watermark_ns = 0u;
    uint64_t final_broadcast_watermark_ns = 0u;
    bool watermark_initialized = false;
    bool final_broadcast_enqueued = false;
    IdentityMode identity_mode = IdentityMode::Unset;
    TriggerMode trigger_mode = TriggerMode::Unset;
    std::atomic<bool> topology_complete{true};
};

namespace {

struct Worker {
    fk_student_shards *owner = nullptr;
    uint16_t index = 0u;
    SpscRing<Command> commands;
    SpscRing<Response> responses;
    SpscRing<uint32_t> completions;
    std::unique_ptr<FeaturePayload[]> payloads;
    uint32_t payload_capacity = 0u;
    uint32_t payload_free_head = UINT32_MAX;
    uint32_t payloads_in_use = 0u;
    uint32_t payloads_peak = 0u;
    std::unique_ptr<uint8_t[]> windows_storage;
    size_t windows_storage_bytes = 0u;
    fk_online_event_windows *windows = nullptr;
    uint64_t next_enqueue_sequence = 0u;
    uint64_t expected_sequence = 0u;
    uint64_t flow_open_commands = 0u;
    uint64_t checkpoint_commands = 0u;
    uint64_t logical_flow_open_commands = 0u;
    uint64_t logical_checkpoint_commands = 0u;
    uint64_t flow_reopen_commands = 0u;
    uint64_t logical_flow_reopen_commands = 0u;
    uint64_t retire_commands = 0u;
    uint64_t watermark_commands = 0u;
    uint64_t final_watermark_commands = 0u;
    uint64_t commands_processed = 0u;
    uint64_t command_queue_full = 0u;
    uint64_t command_queue_peak = 0u;
    uint64_t result_queue_full = 0u;
    uint64_t result_queue_stalls = 0u;
    uint64_t result_queue_peak = 0u;
    uint64_t sequence_failures = 0u;
    uint64_t route_failures = 0u;
    uint64_t output_results = 0u;
    uint64_t payload_completions = 0u;
    uint64_t checkpoint_processing_ns = 0u;
    uint64_t watermark_processing_ns = 0u;
    uint64_t current_command_enqueue_ns = 0u;
    uint64_t current_command_start_ns = 0u;
    std::atomic<bool> pending_watermark{false};
    Command pending_watermark_command{};
    std::atomic<uint64_t> last_processed_sequence{0u};
    std::atomic<uint64_t> last_watermark_ns{0u};
    std::atomic<uint64_t> final_watermark_ns{0u};
    std::atomic<bool> watermark_initialized{false};
    std::atomic<bool> final_flush_complete{false};
    std::atomic<bool> failed{false};
};

static void fail_worker(Worker &worker) {
    worker.failed.store(true, std::memory_order_release);
    worker.owner->topology_complete.store(false, std::memory_order_release);
}

static bool push_response(Worker &worker, const Response &response) {
    if (!worker.responses.push(response)) {
        worker.result_queue_full++;
        fail_worker(worker);
        return false;
    }
    update_peak(worker.result_queue_peak, worker.responses.count());
    return true;
}

static bool collect_window(
        void *opaque,
        const fk_online_event_window_result *result) {
    if (opaque == nullptr || result == nullptr)
        return false;
    Worker &worker = *static_cast<Worker *>(opaque);
    Response response{};
    response.result.window = *result;
    response.result.command_enqueue_monotonic_ns =
        worker.current_command_enqueue_ns;
    response.result.command_start_monotonic_ns =
        worker.current_command_start_ns;
    response.result.decision_monotonic_ns = monotonic_ns();
    response.result.worker_index = worker.index;
    if (!push_response(worker, response))
        return false;
    worker.output_results++;
    return true;
}

static bool enqueue_command(Worker &worker, Command &command) {
    if (!worker.commands.can_push()) {
        worker.command_queue_full++;
        return false;
    }
    command.sequence = worker.next_enqueue_sequence;
    if (!worker.commands.push(command)) {
        worker.command_queue_full++;
        return false;
    }
    worker.next_enqueue_sequence++;
    update_peak(worker.command_queue_peak, worker.commands.count());
    return true;
}

static bool acquire_payload(
        fk_student_shards &shards,
        Worker &worker,
        const float *features,
        uint32_t &slot) {
    if (worker.payload_free_head == UINT32_MAX) {
        shards.feature_payload_exhaustions++;
        shards.topology_complete.store(false, std::memory_order_release);
        return false;
    }
    slot = worker.payload_free_head;
    FeaturePayload &payload = worker.payloads[slot];
    worker.payload_free_head = payload.next_free;
    if (payload.in_use.exchange(
            1u, std::memory_order_acq_rel) != 0u) {
        payload.next_free = worker.payload_free_head;
        worker.payload_free_head = slot;
        shards.feature_payload_exhaustions++;
        shards.topology_complete.store(false, std::memory_order_release);
        return false;
    }
    std::memcpy(
        payload.features,
        features,
        sizeof(payload.features));
    worker.payloads_in_use++;
    worker.payloads_peak = std::max(
        worker.payloads_peak, worker.payloads_in_use);
    return true;
}

static bool release_payload(Worker &worker, uint32_t slot) {
    if (slot >= worker.payload_capacity ||
        worker.payloads_in_use == 0u ||
        worker.payloads[slot].in_use.exchange(
            0u, std::memory_order_acq_rel) != 1u) {
        fail_worker(worker);
        return false;
    }
    worker.payloads[slot].next_free = worker.payload_free_head;
    worker.payload_free_head = slot;
    worker.payloads_in_use--;
    return true;
}

static void drain_completions(Worker &worker) {
    uint32_t slot = UINT32_MAX;
    while (worker.completions.pop(slot))
        (void)release_payload(worker, slot);
}

static bool command_capacity_for(
        const Worker &worker,
        uint32_t commands) {
    return worker.commands.can_push(commands);
}

static bool valid_association(
        const fk_student_shards &shards,
        const fk_actor_session_result *association) {
    return association != nullptr && association->event_id != 0u &&
        association->event_generation != 0u &&
        association->event_slot < shards.config.maximum_events;
}

static bool identity_mode_allowed(
        fk_student_shards &shards,
        IdentityMode requested) {
    if (requested == IdentityMode::Unset)
        return false;
    if (shards.identity_mode == IdentityMode::Unset ||
        shards.identity_mode == requested)
        return true;
    shards.identity_mode_rejections++;
    shards.topology_complete.store(false, std::memory_order_release);
    return false;
}

static void lock_identity_mode(
        fk_student_shards &shards,
        IdentityMode requested) {
    if (shards.identity_mode == IdentityMode::Unset)
        shards.identity_mode = requested;
}

static bool valid_checkpoint_packet(uint8_t checkpoint_packet) {
    return checkpoint_packet == 4u || checkpoint_packet == 8u ||
        checkpoint_packet == 12u || checkpoint_packet == 20u;
}

static bool trigger_mode_allowed(
        fk_student_shards &shards,
        TriggerMode requested) {
    if (requested == TriggerMode::Unset)
        return false;
    if (shards.trigger_mode == TriggerMode::Unset ||
        shards.trigger_mode == requested)
        return true;
    shards.trigger_protocol_rejections++;
    shards.topology_complete.store(false, std::memory_order_release);
    return false;
}

static void lock_trigger_mode(
        fk_student_shards &shards,
        TriggerMode requested) {
    if (shards.trigger_mode == TriggerMode::Unset)
        shards.trigger_mode = requested;
}

}  // namespace

extern "C" {

fk_student_shards *fk_student_shards_create(
        const fk_student_shards_config *config,
        char *error,
        size_t error_capacity) {
    set_error(error, error_capacity, "");
    if (config == nullptr || !valid_worker_count(config->worker_count) ||
        !power_of_two(config->command_queue_capacity) ||
        !power_of_two(config->result_queue_capacity) ||
        config->maximum_events == 0u ||
        config->maximum_flows_per_event == 0u ||
        config->maximum_total_flows == 0u ||
        config->artifact_path == nullptr) {
        set_error(error, error_capacity, "invalid Student shard config");
        return nullptr;
    }
    std::unique_ptr<fk_student_shards> shards(
        new (std::nothrow) fk_student_shards);
    if (!shards) {
        set_error(error, error_capacity, "cannot allocate Student shards");
        return nullptr;
    }
    shards->config = *config;
    shards->student.reset(fk_event_student_load(
        config->artifact_path,
        &config->load_config,
        error,
        error_capacity));
    if (!shards->student)
        return nullptr;
    if (!fk_event_student_get_metadata(
            shards->student.get(), &shards->metadata) ||
        shards->metadata.input_features !=
            FK_EVENT_STUDENT_INPUT_FEATURES) {
        set_error(error, error_capacity, "invalid shared Student metadata");
        return nullptr;
    }
    shards->workers.reset(
        new (std::nothrow) Worker[config->worker_count]);
    const uint64_t per_worker_payload_capacity =
        static_cast<uint64_t>(config->command_queue_capacity) + 1u;
    const uint64_t completion_capacity =
        static_cast<uint64_t>(config->command_queue_capacity) * 2u;
    const uint64_t total_payload_capacity =
        per_worker_payload_capacity * config->worker_count;
    if (per_worker_payload_capacity > UINT32_MAX ||
        completion_capacity > UINT32_MAX ||
        total_payload_capacity > UINT32_MAX) {
        set_error(error, error_capacity, "Student payload capacity overflows");
        return nullptr;
    }
    shards->bindings.reset(
        new (std::nothrow) SlotBinding[config->maximum_events]);
    if (!shards->workers || !shards->bindings) {
        set_error(error, error_capacity, "cannot reserve shard queues/state");
        return nullptr;
    }
    for (uint16_t index = 0u; index < config->worker_count; ++index) {
        Worker &worker = shards->workers[index];
        worker.owner = shards.get();
        worker.index = index;
        worker.payload_capacity =
            static_cast<uint32_t>(per_worker_payload_capacity);
        worker.payloads.reset(
            new (std::nothrow) FeaturePayload[worker.payload_capacity]);
        if (!worker.payloads) {
            set_error(error, error_capacity, "cannot reserve feature payloads");
            return nullptr;
        }
        worker.payload_free_head = 0u;
        for (uint32_t slot = 0u;
             slot < worker.payload_capacity; ++slot) {
            worker.payloads[slot].next_free =
                slot + 1u < worker.payload_capacity
                    ? slot + 1u : UINT32_MAX;
        }
        if (!worker.commands.initialize(config->command_queue_capacity) ||
            !worker.responses.initialize(config->result_queue_capacity) ||
            !worker.completions.initialize(
                static_cast<uint32_t>(completion_capacity))) {
            set_error(error, error_capacity, "cannot reserve shard SPSC rings");
            return nullptr;
        }
        fk_online_event_windows_config windows_config{};
        windows_config.maximum_events = config->maximum_events;
        windows_config.maximum_flows_per_event =
            config->maximum_flows_per_event;
        /* Full per-shard capacity is deliberate and reported.  It makes
         * adversarial event-id skew explicit rather than silently relying on
         * uniform hashing. */
        windows_config.maximum_total_flows = config->maximum_total_flows;
        windows_config.student = shards->student.get();
        windows_config.sink = collect_window;
        windows_config.sink_context = &worker;
        windows_config.external_watermarks_only = true;
        worker.windows_storage_bytes =
            fk_online_event_windows_storage_bytes(&windows_config);
        worker.windows_storage.reset(
            new (std::nothrow) uint8_t[worker.windows_storage_bytes]);
        if (!worker.windows_storage) {
            set_error(error, error_capacity, "cannot reserve worker windows");
            return nullptr;
        }
        worker.windows = fk_online_event_windows_init(
            worker.windows_storage.get(),
            worker.windows_storage_bytes,
            &windows_config,
            error,
            error_capacity);
        if (worker.windows == nullptr)
            return nullptr;
    }
    return shards.release();
}

void fk_student_shards_destroy(fk_student_shards *shards) {
    delete shards;
}

uint16_t fk_student_shards_worker_for_event(
        uint64_t event_id,
        uint16_t worker_count) {
    if (event_id == 0u || !valid_worker_count(worker_count))
        return UINT16_MAX;
    return static_cast<uint16_t>((event_id - 1u) & (worker_count - 1u));
}

static bool enqueue_flow_open_internal(
        fk_student_shards *opaque,
        const fk_actor_session_result *association,
        const fk_actor_flow_identity_v2 *flow_identity,
        uint64_t observation_timestamp_ns,
        uint64_t enqueue_monotonic_ns,
        IdentityMode requested_mode) {
    if (opaque == nullptr || flow_identity == nullptr)
        return false;
    fk_student_shards &shards = *opaque;
    if (!identity_mode_allowed(shards, requested_mode))
        return false;
    if (!valid_association(shards, association) ||
        flow_identity->presentation.generation == 0u ||
        flow_identity->presentation.first_timestamp_ns !=
            observation_timestamp_ns) {
        shards.invalid_routes++;
        shards.topology_complete.store(false, std::memory_order_release);
        return false;
    }
    const uint16_t destination = fk_student_shards_worker_for_event(
        association->event_id, shards.config.worker_count);
    SlotBinding &binding = shards.bindings[association->event_slot];
    const bool same = binding.active &&
        binding.event_id == association->event_id &&
        binding.generation == association->event_generation;
    if (same && association->created) {
        shards.invalid_routes++;
        shards.topology_complete.store(false, std::memory_order_release);
        return false;
    }
    if (same && binding.owner != destination) {
        shards.slot_owner_mismatches++;
        shards.topology_complete.store(false, std::memory_order_release);
        return false;
    }
    const bool replacing = binding.active && !same;
    if (!same && !association->created) {
        shards.invalid_routes++;
        shards.topology_complete.store(false, std::memory_order_release);
        return false;
    }
    if (replacing) {
        const uint32_t old_needed = binding.owner == destination ? 2u : 1u;
        if (binding.owner >= shards.config.worker_count ||
            !command_capacity_for(shards.workers[binding.owner], old_needed) ||
            (binding.owner != destination &&
             !command_capacity_for(shards.workers[destination], 1u))) {
            shards.data_queue_full++;
            shards.workers[
                binding.owner < shards.config.worker_count
                    ? binding.owner : destination].command_queue_full++;
            shards.topology_complete.store(false, std::memory_order_release);
            return false;
        }
        Command retire{};
        retire.kind = CommandKind::Retire;
        retire.association.event_id = binding.event_id;
        retire.association.event_slot = association->event_slot;
        retire.association.event_generation = binding.generation;
        retire.enqueue_monotonic_ns = enqueue_monotonic_ns;
        if (!enqueue_command(shards.workers[binding.owner], retire)) {
            shards.data_queue_full++;
            shards.topology_complete.store(false, std::memory_order_release);
            return false;
        }
        shards.retire_enqueues++;
        shards.slot_reuse_retirements++;
    } else if (!command_capacity_for(shards.workers[destination], 1u)) {
        shards.data_queue_full++;
        shards.workers[destination].command_queue_full++;
        shards.topology_complete.store(false, std::memory_order_release);
        return false;
    }
    Command command{};
    command.kind = CommandKind::FlowOpen;
    command.association = *association;
    command.flow_identity = *flow_identity;
    command.observation_timestamp_ns = observation_timestamp_ns;
    command.enqueue_monotonic_ns = enqueue_monotonic_ns;
    command.identity_mode = requested_mode;
    if (!enqueue_command(shards.workers[destination], command)) {
        /* Preflight makes this unreachable for an SPSC producer.  If it ever
         * happens after a retire was queued, the run is permanently nonformal. */
        shards.data_queue_full++;
        shards.topology_complete.store(false, std::memory_order_release);
        return false;
    }
    binding.event_id = association->event_id;
    binding.generation = association->event_generation;
    binding.owner = destination;
    binding.active = true;
    shards.flow_open_enqueues++;
    if (flow_identity->logical_connection_id != 0u)
        shards.logical_flow_open_enqueues++;
    lock_identity_mode(shards, requested_mode);
    return true;
}

bool fk_student_shards_enqueue_flow_open(
        fk_student_shards *opaque,
        const fk_actor_session_result *association,
        const fk_actor_flow_identity *flow_identity,
        uint64_t observation_timestamp_ns,
        uint64_t enqueue_monotonic_ns) {
    fk_actor_flow_identity_v2 identity_v2{};
    const fk_actor_flow_identity_v2 *identity_pointer = nullptr;
    if (flow_identity != nullptr) {
        identity_v2.presentation = *flow_identity;
        identity_v2.logical_connection_id = 0u;
        identity_pointer = &identity_v2;
    }
    return enqueue_flow_open_internal(
        opaque,
        association,
        identity_pointer,
        observation_timestamp_ns,
        enqueue_monotonic_ns,
        IdentityMode::V1);
}

bool fk_student_shards_enqueue_flow_open_v2(
        fk_student_shards *opaque,
        const fk_actor_session_result *association,
        const fk_actor_flow_identity_v2 *flow_identity,
        uint64_t observation_timestamp_ns,
        uint64_t enqueue_monotonic_ns) {
    return enqueue_flow_open_internal(
        opaque,
        association,
        flow_identity,
        observation_timestamp_ns,
        enqueue_monotonic_ns,
        IdentityMode::V2);
}

static bool enqueue_checkpoint_internal(
        fk_student_shards *opaque,
        const fk_actor_session_result *association,
        const fk_actor_flow_identity_v2 *flow_identity,
        uint64_t observation_timestamp_ns,
        const float *features,
        size_t feature_count,
        uint64_t enqueue_monotonic_ns,
        IdentityMode requested_mode,
        TriggerMode requested_trigger_mode,
        uint8_t checkpoint_packet) {
    if (opaque == nullptr || flow_identity == nullptr || features == nullptr)
        return false;
    fk_student_shards &shards = *opaque;
    if (!identity_mode_allowed(shards, requested_mode))
        return false;
    if (!trigger_mode_allowed(shards, requested_trigger_mode))
        return false;
    if (requested_trigger_mode == TriggerMode::CheckpointPeriodicV2 &&
        !valid_checkpoint_packet(checkpoint_packet)) {
        shards.invalid_checkpoint_packet_rejections++;
        shards.topology_complete.store(false, std::memory_order_release);
        return false;
    }
    if (requested_trigger_mode == TriggerMode::PeriodicV1 &&
        checkpoint_packet != 0u) {
        shards.invalid_checkpoint_packet_rejections++;
        shards.topology_complete.store(false, std::memory_order_release);
        return false;
    }
    if (!valid_association(shards, association) ||
        feature_count != FK_EVENT_STUDENT_INPUT_FEATURES) {
        shards.invalid_routes++;
        shards.topology_complete.store(false, std::memory_order_release);
        return false;
    }
    const uint16_t destination = fk_student_shards_worker_for_event(
        association->event_id, shards.config.worker_count);
    const SlotBinding &binding = shards.bindings[association->event_slot];
    if (!binding.active || binding.event_id != association->event_id ||
        binding.generation != association->event_generation ||
        binding.owner != destination) {
        shards.slot_owner_mismatches++;
        shards.topology_complete.store(false, std::memory_order_release);
        return false;
    }
    Worker &worker = shards.workers[destination];
    drain_completions(worker);
    if (!command_capacity_for(worker, 1u)) {
        shards.data_queue_full++;
        worker.command_queue_full++;
        shards.topology_complete.store(false, std::memory_order_release);
        return false;
    }
    uint32_t payload_slot = UINT32_MAX;
    if (!acquire_payload(shards, worker, features, payload_slot))
        return false;
    Command command{};
    command.kind = CommandKind::Checkpoint;
    command.association = *association;
    command.flow_identity = *flow_identity;
    command.observation_timestamp_ns = observation_timestamp_ns;
    command.enqueue_monotonic_ns = enqueue_monotonic_ns;
    command.payload_slot = payload_slot;
    command.identity_mode = requested_mode;
    command.trigger_mode = requested_trigger_mode;
    command.checkpoint_packet = checkpoint_packet;
    if (!enqueue_command(worker, command)) {
        (void)release_payload(worker, payload_slot);
        shards.data_queue_full++;
        shards.topology_complete.store(false, std::memory_order_release);
        return false;
    }
    shards.checkpoint_enqueues++;
    if (flow_identity->logical_connection_id != 0u)
        shards.logical_checkpoint_enqueues++;
    lock_identity_mode(shards, requested_mode);
    lock_trigger_mode(shards, requested_trigger_mode);
    if (requested_trigger_mode == TriggerMode::CheckpointPeriodicV2)
        shards.checkpoint_trigger_enqueues++;
    return true;
}

bool fk_student_shards_enqueue_checkpoint(
        fk_student_shards *opaque,
        const fk_actor_session_result *association,
        const fk_actor_flow_identity *flow_identity,
        uint64_t observation_timestamp_ns,
        const float *features,
        size_t feature_count,
        uint64_t enqueue_monotonic_ns) {
    fk_actor_flow_identity_v2 identity_v2{};
    const fk_actor_flow_identity_v2 *identity_pointer = nullptr;
    if (flow_identity != nullptr) {
        identity_v2.presentation = *flow_identity;
        identity_v2.logical_connection_id = 0u;
        identity_pointer = &identity_v2;
    }
    return enqueue_checkpoint_internal(
        opaque,
        association,
        identity_pointer,
        observation_timestamp_ns,
        features,
        feature_count,
        enqueue_monotonic_ns,
        IdentityMode::V1,
        TriggerMode::PeriodicV1,
        0u);
}

bool fk_student_shards_enqueue_checkpoint_v2(
        fk_student_shards *opaque,
        const fk_actor_session_result *association,
        const fk_actor_flow_identity_v2 *flow_identity,
        uint64_t observation_timestamp_ns,
        const float *features,
        size_t feature_count,
        uint64_t enqueue_monotonic_ns) {
    return enqueue_checkpoint_internal(
        opaque,
        association,
        flow_identity,
        observation_timestamp_ns,
        features,
        feature_count,
        enqueue_monotonic_ns,
        IdentityMode::V2,
        TriggerMode::PeriodicV1,
        0u);
}

bool fk_student_shards_enqueue_checkpoint_triggered(
        fk_student_shards *opaque,
        const fk_actor_session_result *association,
        const fk_actor_flow_identity *flow_identity,
        uint64_t observation_timestamp_ns,
        uint8_t checkpoint_packet,
        const float *features,
        size_t feature_count,
        uint64_t enqueue_monotonic_ns) {
    fk_actor_flow_identity_v2 identity_v2{};
    const fk_actor_flow_identity_v2 *identity_pointer = nullptr;
    if (flow_identity != nullptr) {
        identity_v2.presentation = *flow_identity;
        identity_pointer = &identity_v2;
    }
    return enqueue_checkpoint_internal(
        opaque, association, identity_pointer, observation_timestamp_ns,
        features, feature_count, enqueue_monotonic_ns, IdentityMode::V1,
        TriggerMode::CheckpointPeriodicV2, checkpoint_packet);
}

bool fk_student_shards_enqueue_checkpoint_triggered_v2(
        fk_student_shards *opaque,
        const fk_actor_session_result *association,
        const fk_actor_flow_identity_v2 *flow_identity,
        uint64_t observation_timestamp_ns,
        uint8_t checkpoint_packet,
        const float *features,
        size_t feature_count,
        uint64_t enqueue_monotonic_ns) {
    return enqueue_checkpoint_internal(
        opaque, association, flow_identity, observation_timestamp_ns,
        features, feature_count, enqueue_monotonic_ns, IdentityMode::V2,
        TriggerMode::CheckpointPeriodicV2, checkpoint_packet);
}

static bool enqueue_flow_reopen_checkpoint_internal(
        fk_student_shards *opaque,
        const fk_actor_session_result *association,
        const fk_actor_flow_identity_v2 *flow_identity,
        uint64_t observation_timestamp_ns,
        const float *features,
        size_t feature_count,
        uint64_t enqueue_monotonic_ns,
        IdentityMode requested_mode,
        TriggerMode requested_trigger_mode,
        uint8_t checkpoint_packet) {
    if (opaque == nullptr || flow_identity == nullptr || features == nullptr)
        return false;
    fk_student_shards &shards = *opaque;
    if (!identity_mode_allowed(shards, requested_mode))
        return false;
    if (!trigger_mode_allowed(shards, requested_trigger_mode))
        return false;
    if (requested_trigger_mode == TriggerMode::CheckpointPeriodicV2 &&
        !valid_checkpoint_packet(checkpoint_packet)) {
        shards.invalid_checkpoint_packet_rejections++;
        shards.topology_complete.store(false, std::memory_order_release);
        return false;
    }
    if (requested_trigger_mode == TriggerMode::PeriodicV1 &&
        checkpoint_packet != 0u) {
        shards.invalid_checkpoint_packet_rejections++;
        shards.topology_complete.store(false, std::memory_order_release);
        return false;
    }
    if (!valid_association(shards, association) ||
        feature_count != FK_EVENT_STUDENT_INPUT_FEATURES ||
        flow_identity->presentation.generation == 0u ||
        flow_identity->presentation.first_timestamp_ns >
            observation_timestamp_ns ||
        association->reason == FK_ACTOR_REASON_INVALID_INPUT ||
        association->reason == FK_ACTOR_REASON_OUT_OF_ORDER ||
        association->reason == FK_ACTOR_REASON_EXISTING_FLOW_STICKY) {
        shards.invalid_routes++;
        shards.topology_complete.store(false, std::memory_order_release);
        return false;
    }

    const uint16_t destination = fk_student_shards_worker_for_event(
        association->event_id, shards.config.worker_count);
    SlotBinding &binding = shards.bindings[association->event_slot];
    const bool same = binding.active &&
        binding.event_id == association->event_id &&
        binding.generation == association->event_generation;
    if (same && association->created) {
        shards.invalid_routes++;
        shards.topology_complete.store(false, std::memory_order_release);
        return false;
    }
    if (same && binding.owner != destination) {
        shards.slot_owner_mismatches++;
        shards.topology_complete.store(false, std::memory_order_release);
        return false;
    }
    const bool replacing = binding.active && !same;
    if (!same && !association->created) {
        shards.invalid_routes++;
        shards.topology_complete.store(false, std::memory_order_release);
        return false;
    }
    if (replacing && binding.owner >= shards.config.worker_count) {
        shards.slot_owner_mismatches++;
        shards.topology_complete.store(false, std::memory_order_release);
        return false;
    }

    Worker &destination_worker = shards.workers[destination];
    drain_completions(destination_worker);
    const uint32_t destination_commands =
        replacing && binding.owner == destination ? 3u : 2u;
    const bool old_worker_has_capacity =
        !replacing || binding.owner == destination ||
        command_capacity_for(shards.workers[binding.owner], 1u);
    if (!old_worker_has_capacity ||
        !command_capacity_for(destination_worker, destination_commands)) {
        shards.data_queue_full++;
        destination_worker.command_queue_full++;
        shards.topology_complete.store(false, std::memory_order_release);
        return false;
    }

    uint32_t payload_slot = UINT32_MAX;
    if (!acquire_payload(
            shards, destination_worker, features, payload_slot))
        return false;

    if (replacing) {
        Command retire{};
        retire.kind = CommandKind::Retire;
        retire.association.event_id = binding.event_id;
        retire.association.event_slot = association->event_slot;
        retire.association.event_generation = binding.generation;
        retire.enqueue_monotonic_ns = enqueue_monotonic_ns;
        if (!enqueue_command(shards.workers[binding.owner], retire)) {
            (void)release_payload(destination_worker, payload_slot);
            shards.data_queue_full++;
            shards.topology_complete.store(false, std::memory_order_release);
            return false;
        }
        shards.retire_enqueues++;
        shards.slot_reuse_retirements++;
    }

    Command reopen{};
    reopen.kind = CommandKind::FlowReopen;
    reopen.association = *association;
    reopen.flow_identity = *flow_identity;
    reopen.observation_timestamp_ns = observation_timestamp_ns;
    reopen.enqueue_monotonic_ns = enqueue_monotonic_ns;
    reopen.identity_mode = requested_mode;
    if (!enqueue_command(destination_worker, reopen)) {
        (void)release_payload(destination_worker, payload_slot);
        shards.data_queue_full++;
        shards.topology_complete.store(false, std::memory_order_release);
        return false;
    }

    Command checkpoint{};
    checkpoint.kind = CommandKind::Checkpoint;
    checkpoint.association = *association;
    checkpoint.flow_identity = *flow_identity;
    checkpoint.observation_timestamp_ns = observation_timestamp_ns;
    checkpoint.enqueue_monotonic_ns = enqueue_monotonic_ns;
    checkpoint.payload_slot = payload_slot;
    checkpoint.identity_mode = requested_mode;
    checkpoint.trigger_mode = requested_trigger_mode;
    checkpoint.checkpoint_packet = checkpoint_packet;
    if (!enqueue_command(destination_worker, checkpoint)) {
        /* The two-slot preflight and single producer make this unreachable.
         * If the invariant is ever violated, the visible reopen is marked
         * permanently nonformal rather than silently accepted. */
        (void)release_payload(destination_worker, payload_slot);
        shards.data_queue_full++;
        shards.topology_complete.store(false, std::memory_order_release);
        return false;
    }

    binding.event_id = association->event_id;
    binding.generation = association->event_generation;
    binding.owner = destination;
    binding.active = true;
    shards.flow_reopen_enqueues++;
    shards.checkpoint_enqueues++;
    shards.flow_reopen_checkpoint_pair_enqueues++;
    if (flow_identity->logical_connection_id != 0u) {
        shards.logical_flow_reopen_enqueues++;
        shards.logical_checkpoint_enqueues++;
    }
    lock_identity_mode(shards, requested_mode);
    lock_trigger_mode(shards, requested_trigger_mode);
    if (requested_trigger_mode == TriggerMode::CheckpointPeriodicV2)
        shards.checkpoint_trigger_enqueues++;
    return true;
}

bool fk_student_shards_enqueue_flow_reopen_checkpoint(
        fk_student_shards *opaque,
        const fk_actor_session_result *association,
        const fk_actor_flow_identity *flow_identity,
        uint64_t observation_timestamp_ns,
        const float *features,
        size_t feature_count,
        uint64_t enqueue_monotonic_ns) {
    fk_actor_flow_identity_v2 identity_v2{};
    const fk_actor_flow_identity_v2 *identity_pointer = nullptr;
    if (flow_identity != nullptr) {
        identity_v2.presentation = *flow_identity;
        identity_v2.logical_connection_id = 0u;
        identity_pointer = &identity_v2;
    }
    return enqueue_flow_reopen_checkpoint_internal(
        opaque,
        association,
        identity_pointer,
        observation_timestamp_ns,
        features,
        feature_count,
        enqueue_monotonic_ns,
        IdentityMode::V1,
        TriggerMode::PeriodicV1,
        0u);
}

bool fk_student_shards_enqueue_flow_reopen_checkpoint_v2(
        fk_student_shards *opaque,
        const fk_actor_session_result *association,
        const fk_actor_flow_identity_v2 *flow_identity,
        uint64_t observation_timestamp_ns,
        const float *features,
        size_t feature_count,
        uint64_t enqueue_monotonic_ns) {
    return enqueue_flow_reopen_checkpoint_internal(
        opaque,
        association,
        flow_identity,
        observation_timestamp_ns,
        features,
        feature_count,
        enqueue_monotonic_ns,
        IdentityMode::V2,
        TriggerMode::PeriodicV1,
        0u);
}

bool fk_student_shards_enqueue_flow_reopen_checkpoint_triggered(
        fk_student_shards *opaque,
        const fk_actor_session_result *association,
        const fk_actor_flow_identity *flow_identity,
        uint64_t observation_timestamp_ns,
        uint8_t checkpoint_packet,
        const float *features,
        size_t feature_count,
        uint64_t enqueue_monotonic_ns) {
    fk_actor_flow_identity_v2 identity_v2{};
    const fk_actor_flow_identity_v2 *identity_pointer = nullptr;
    if (flow_identity != nullptr) {
        identity_v2.presentation = *flow_identity;
        identity_pointer = &identity_v2;
    }
    return enqueue_flow_reopen_checkpoint_internal(
        opaque, association, identity_pointer, observation_timestamp_ns,
        features, feature_count, enqueue_monotonic_ns, IdentityMode::V1,
        TriggerMode::CheckpointPeriodicV2, checkpoint_packet);
}

bool fk_student_shards_enqueue_flow_reopen_checkpoint_triggered_v2(
        fk_student_shards *opaque,
        const fk_actor_session_result *association,
        const fk_actor_flow_identity_v2 *flow_identity,
        uint64_t observation_timestamp_ns,
        uint8_t checkpoint_packet,
        const float *features,
        size_t feature_count,
        uint64_t enqueue_monotonic_ns) {
    return enqueue_flow_reopen_checkpoint_internal(
        opaque, association, flow_identity, observation_timestamp_ns,
        features, feature_count, enqueue_monotonic_ns, IdentityMode::V2,
        TriggerMode::CheckpointPeriodicV2, checkpoint_packet);
}

bool fk_student_shards_broadcast_watermark(
        fk_student_shards *opaque,
        uint64_t inclusive_watermark_ns,
        bool final_capture_flush,
        uint64_t enqueue_monotonic_ns) {
    if (opaque == nullptr)
        return false;
    fk_student_shards &shards = *opaque;
    if (shards.watermark_initialized &&
        inclusive_watermark_ns < shards.last_broadcast_watermark_ns) {
        shards.watermark_regressions++;
        shards.topology_complete.store(false, std::memory_order_release);
        return false;
    }
    if (shards.final_broadcast_enqueued) {
        if (final_capture_flush && inclusive_watermark_ns ==
                shards.final_broadcast_watermark_ns)
            return true;
        shards.watermark_regressions++;
        shards.topology_complete.store(false, std::memory_order_release);
        return false;
    }
    if (!final_capture_flush && shards.watermark_initialized &&
        inclusive_watermark_ns == shards.last_broadcast_watermark_ns)
        return true;
    for (uint16_t index = 0u;
         index < shards.config.worker_count; ++index) {
        if (!command_capacity_for(shards.workers[index], 1u)) {
            shards.watermark_queue_full++;
            shards.workers[index].command_queue_full++;
            shards.topology_complete.store(false, std::memory_order_release);
            return false;
        }
    }
    for (uint16_t index = 0u;
         index < shards.config.worker_count; ++index) {
        Command command{};
        command.kind = final_capture_flush
            ? CommandKind::FinalWatermark : CommandKind::Watermark;
        command.observation_timestamp_ns = inclusive_watermark_ns;
        command.enqueue_monotonic_ns = enqueue_monotonic_ns;
        if (!enqueue_command(shards.workers[index], command)) {
            shards.watermark_queue_full++;
            shards.topology_complete.store(false, std::memory_order_release);
            return false;
        }
    }
    shards.watermark_initialized = true;
    shards.last_broadcast_watermark_ns = inclusive_watermark_ns;
    shards.watermark_broadcasts++;
    if (final_capture_flush) {
        shards.final_broadcast_enqueued = true;
        shards.final_broadcast_watermark_ns = inclusive_watermark_ns;
        shards.final_watermark_broadcasts++;
    }
    return true;
}

bool fk_student_shards_process(
        fk_student_shards *opaque,
        uint16_t worker_index,
        uint32_t maximum_commands,
        uint32_t *processed) {
    if (processed != nullptr)
        *processed = 0u;
    if (opaque == nullptr || processed == nullptr || maximum_commands == 0u ||
        worker_index >= opaque->config.worker_count)
        return false;
    Worker &worker = opaque->workers[worker_index];
    for (uint32_t count = 0u; count < maximum_commands; ++count) {
        Command command{};
        const bool resuming_watermark =
            worker.pending_watermark.load(std::memory_order_acquire);
        if (resuming_watermark) {
            command = worker.pending_watermark_command;
        } else {
            if (!worker.commands.pop(command))
                break;
            if (command.sequence != worker.expected_sequence) {
                worker.sequence_failures++;
                fail_worker(worker);
                worker.expected_sequence = command.sequence + 1u;
            } else {
                worker.expected_sequence++;
            }
            worker.current_command_enqueue_ns =
                command.enqueue_monotonic_ns;
            worker.current_command_start_ns = monotonic_ns();
        }
        bool valid = true;
        bool command_complete = true;
        switch (command.kind) {
        case CommandKind::FlowOpen:
            worker.flow_open_commands++;
            if (command.identity_mode == IdentityMode::V1) {
                valid = fk_online_event_windows_flow_open(
                    worker.windows,
                    &command.association,
                    &command.flow_identity.presentation,
                    command.observation_timestamp_ns);
            } else if (command.identity_mode == IdentityMode::V2) {
                valid = fk_online_event_windows_flow_open_v2(
                    worker.windows,
                    &command.association,
                    &command.flow_identity,
                    command.observation_timestamp_ns);
            } else {
                valid = false;
            }
            break;
        case CommandKind::FlowReopen:
            worker.flow_reopen_commands++;
            if (command.identity_mode == IdentityMode::V1) {
                valid = fk_online_event_windows_flow_reopen(
                    worker.windows,
                    &command.association,
                    &command.flow_identity.presentation,
                    command.observation_timestamp_ns);
            } else if (command.identity_mode == IdentityMode::V2) {
                valid = fk_online_event_windows_flow_reopen_v2(
                    worker.windows,
                    &command.association,
                    &command.flow_identity,
                    command.observation_timestamp_ns);
            } else {
                valid = false;
            }
            break;
        case CommandKind::Checkpoint: {
            worker.checkpoint_commands++;
            const uint64_t start_ns = monotonic_ns();
            if (command.payload_slot >= worker.payload_capacity ||
                worker.payloads[command.payload_slot].in_use.load(
                    std::memory_order_acquire) != 1u) {
                valid = false;
            } else {
                if (command.identity_mode == IdentityMode::V1 &&
                    command.trigger_mode == TriggerMode::PeriodicV1) {
                    valid = fk_online_event_windows_checkpoint(
                        worker.windows, &command.association,
                        &command.flow_identity.presentation,
                        command.observation_timestamp_ns,
                        worker.payloads[command.payload_slot].features,
                        FK_EVENT_STUDENT_INPUT_FEATURES);
                } else if (command.identity_mode == IdentityMode::V2 &&
                    command.trigger_mode == TriggerMode::PeriodicV1) {
                    valid = fk_online_event_windows_checkpoint_v2(
                        worker.windows, &command.association,
                        &command.flow_identity,
                        command.observation_timestamp_ns,
                        worker.payloads[command.payload_slot].features,
                        FK_EVENT_STUDENT_INPUT_FEATURES);
                } else if (command.identity_mode == IdentityMode::V1 &&
                    command.trigger_mode ==
                        TriggerMode::CheckpointPeriodicV2) {
                    valid = fk_online_event_windows_checkpoint_triggered(
                        worker.windows, &command.association,
                        &command.flow_identity.presentation,
                        command.observation_timestamp_ns,
                        command.checkpoint_packet,
                        worker.payloads[command.payload_slot].features,
                        FK_EVENT_STUDENT_INPUT_FEATURES);
                } else if (command.identity_mode == IdentityMode::V2 &&
                    command.trigger_mode ==
                        TriggerMode::CheckpointPeriodicV2) {
                    valid = fk_online_event_windows_checkpoint_triggered_v2(
                        worker.windows, &command.association,
                        &command.flow_identity,
                        command.observation_timestamp_ns,
                        command.checkpoint_packet,
                        worker.payloads[command.payload_slot].features,
                        FK_EVENT_STUDENT_INPUT_FEATURES);
                } else {
                    valid = false;
                }
            }
            worker.checkpoint_processing_ns += monotonic_ns() - start_ns;
            if (!worker.completions.push(command.payload_slot)) {
                worker.result_queue_stalls++;
                valid = false;
            } else {
                worker.payload_completions++;
            }
            break;
        }
        case CommandKind::Retire:
            worker.retire_commands++;
            valid = fk_online_event_windows_retire_event(
                worker.windows, &command.association);
            break;
        case CommandKind::Watermark:
        case CommandKind::FinalWatermark: {
            const bool final =
                command.kind == CommandKind::FinalWatermark;
            if (!resuming_watermark) {
                if (final)
                    worker.final_watermark_commands++;
                else
                    worker.watermark_commands++;
            }
            const uint64_t start_ns = monotonic_ns();
            bool watermark_complete = false;
            valid = fk_online_event_windows_advance_watermark_step(
                worker.windows,
                command.observation_timestamp_ns,
                worker.responses.free_count(),
                &watermark_complete);
            worker.watermark_processing_ns += monotonic_ns() - start_ns;
            command_complete = valid && watermark_complete;
            if (valid && !watermark_complete) {
                worker.pending_watermark_command = command;
                worker.pending_watermark.store(
                    true, std::memory_order_release);
            } else {
                worker.pending_watermark.store(
                    false, std::memory_order_release);
            }
            if (command_complete) {
                worker.last_watermark_ns.store(
                    command.observation_timestamp_ns,
                    std::memory_order_relaxed);
                worker.watermark_initialized.store(
                    true, std::memory_order_release);
                if (final) {
                    worker.final_watermark_ns.store(
                        command.observation_timestamp_ns,
                        std::memory_order_relaxed);
                    worker.final_flush_complete.store(
                        true, std::memory_order_release);
                }
            }
            break;
        }
        }
        if (valid && command.flow_identity.logical_connection_id != 0u) {
            if (command.kind == CommandKind::FlowOpen)
                worker.logical_flow_open_commands++;
            else if (command.kind == CommandKind::FlowReopen)
                worker.logical_flow_reopen_commands++;
            else if (command.kind == CommandKind::Checkpoint)
                worker.logical_checkpoint_commands++;
        }
        if (!valid) {
            worker.route_failures++;
            fail_worker(worker);
        }
        if (!command_complete)
            break;
        worker.commands_processed++;
        (*processed)++;
        worker.last_processed_sequence.store(
            command.sequence, std::memory_order_release);
    }
    return !worker.failed.load(std::memory_order_acquire);
}

bool fk_student_shards_pop_result(
        fk_student_shards *opaque,
        uint16_t worker_index,
        fk_student_shard_result *result) {
    if (opaque == nullptr || result == nullptr ||
        worker_index >= opaque->config.worker_count)
        return false;
    Worker &worker = opaque->workers[worker_index];
    drain_completions(worker);
    Response response{};
    if (worker.responses.pop(response)) {
        *result = response.result;
        return true;
    }
    return false;
}

bool fk_student_shards_command_queues_empty(
        const fk_student_shards *shards) {
    if (shards == nullptr)
        return false;
    for (uint16_t index = 0u;
         index < shards->config.worker_count; ++index) {
        if (!shards->workers[index].commands.empty() ||
            shards->workers[index].pending_watermark.load(
                std::memory_order_acquire))
            return false;
    }
    return true;
}

bool fk_student_shards_result_queues_empty(
        const fk_student_shards *shards) {
    if (shards == nullptr)
        return false;
    for (uint16_t index = 0u;
         index < shards->config.worker_count; ++index) {
        const Worker &worker = shards->workers[index];
        if (!worker.responses.empty() || !worker.completions.empty() ||
            worker.payloads_in_use != 0u)
            return false;
    }
    return true;
}

uint64_t fk_student_shards_command_queue_depth(
        const fk_student_shards *shards) {
    if (shards == nullptr)
        return 0u;
    uint64_t depth = 0u;
    for (uint16_t index = 0u;
         index < shards->config.worker_count; ++index) {
        depth += shards->workers[index].commands.count();
        if (shards->workers[index].pending_watermark.load(
                std::memory_order_acquire))
            depth++;
    }
    return depth;
}

uint64_t fk_student_shards_result_queue_depth(
        const fk_student_shards *shards) {
    if (shards == nullptr)
        return 0u;
    uint64_t depth = 0u;
    for (uint16_t index = 0u;
         index < shards->config.worker_count; ++index) {
        const Worker &worker = shards->workers[index];
        depth += worker.responses.count();
        depth += worker.completions.count();
    }
    return depth;
}

bool fk_student_shards_any_worker_failed(
        const fk_student_shards *shards) {
    if (shards == nullptr)
        return true;
    if (!shards->topology_complete.load(std::memory_order_acquire))
        return true;
    for (uint16_t index = 0u;
         index < shards->config.worker_count; ++index) {
        if (shards->workers[index].failed.load(std::memory_order_acquire))
            return true;
    }
    return false;
}

bool fk_student_shards_final_flush_complete(
        const fk_student_shards *shards,
        uint64_t exact_capture_watermark_ns) {
    if (shards == nullptr || !shards->final_broadcast_enqueued ||
        shards->final_broadcast_watermark_ns !=
            exact_capture_watermark_ns)
        return false;
    for (uint16_t index = 0u;
         index < shards->config.worker_count; ++index) {
        const Worker &worker = shards->workers[index];
        if (!worker.final_flush_complete.load(std::memory_order_acquire) ||
            worker.final_watermark_ns.load(std::memory_order_relaxed) !=
                exact_capture_watermark_ns)
            return false;
    }
    return true;
}

bool fk_student_shards_get_stats(
        const fk_student_shards *shards,
        fk_student_shards_stats *stats) {
    if (shards == nullptr || stats == nullptr)
        return false;
    std::memset(stats, 0, sizeof(*stats));
    stats->worker_count = shards->config.worker_count;
    stats->command_queue_capacity =
        shards->config.command_queue_capacity;
    stats->result_queue_capacity =
        shards->config.result_queue_capacity;
    stats->flow_open_enqueues = shards->flow_open_enqueues;
    stats->checkpoint_enqueues = shards->checkpoint_enqueues;
    stats->retire_enqueues = shards->retire_enqueues;
    stats->watermark_broadcasts = shards->watermark_broadcasts;
    stats->final_watermark_broadcasts =
        shards->final_watermark_broadcasts;
    stats->data_queue_full = shards->data_queue_full;
    stats->watermark_queue_full = shards->watermark_queue_full;
    stats->watermark_regressions = shards->watermark_regressions;
    stats->invalid_routes = shards->invalid_routes;
    stats->slot_owner_mismatches = shards->slot_owner_mismatches;
    stats->slot_reuse_retirements = shards->slot_reuse_retirements;
    stats->feature_payload_exhaustions =
        shards->feature_payload_exhaustions;
    stats->identity_mode_rejections =
        shards->identity_mode_rejections;
    stats->logical_flow_open_enqueues =
        shards->logical_flow_open_enqueues;
    stats->logical_checkpoint_enqueues =
        shards->logical_checkpoint_enqueues;
    stats->flow_reopen_enqueues = shards->flow_reopen_enqueues;
    stats->logical_flow_reopen_enqueues =
        shards->logical_flow_reopen_enqueues;
    stats->flow_reopen_checkpoint_pair_enqueues =
        shards->flow_reopen_checkpoint_pair_enqueues;
    stats->checkpoint_trigger_enqueues =
        shards->checkpoint_trigger_enqueues;
    stats->trigger_protocol_rejections =
        shards->trigger_protocol_rejections;
    stats->invalid_checkpoint_packet_rejections =
        shards->invalid_checkpoint_packet_rejections;
    stats->trigger_protocol = static_cast<uint8_t>(shards->trigger_mode);
    stats->command_entry_bytes = sizeof(Command);
    stats->logical_identity_v2_abi_version =
        FK_STUDENT_SHARDS_LOGICAL_IDENTITY_V2_ABI_VERSION;
    stats->identity_abi_mode =
        static_cast<uint8_t>(shards->identity_mode);
    stats->logical_identity_queue_extension_reserved_bytes =
        static_cast<uint64_t>(shards->config.worker_count) *
        shards->config.command_queue_capacity *
        kLogicalIdentityCommandExtensionBytes;
    stats->slot_binding_reserved_bytes =
        static_cast<uint64_t>(shards->config.maximum_events) *
        sizeof(SlotBinding);
    stats->last_broadcast_watermark_ns =
        shards->last_broadcast_watermark_ns;
    stats->final_broadcast_watermark_ns =
        shards->final_broadcast_watermark_ns;
    stats->watermark_initialized = shards->watermark_initialized;
    stats->final_broadcast_enqueued =
        shards->final_broadcast_enqueued;
    stats->topology_complete =
        shards->topology_complete.load(std::memory_order_acquire);
    bool complete = stats->topology_complete;
    for (uint16_t index = 0u;
         index < shards->config.worker_count; ++index) {
        const Worker &worker = shards->workers[index];
        fk_student_shard_worker_stats &output = stats->workers[index];
        output.flow_open_commands = worker.flow_open_commands;
        output.checkpoint_commands = worker.checkpoint_commands;
        output.logical_flow_open_commands =
            worker.logical_flow_open_commands;
        output.logical_checkpoint_commands =
            worker.logical_checkpoint_commands;
        output.flow_reopen_commands = worker.flow_reopen_commands;
        output.logical_flow_reopen_commands =
            worker.logical_flow_reopen_commands;
        output.retire_commands = worker.retire_commands;
        output.watermark_commands = worker.watermark_commands;
        output.final_watermark_commands =
            worker.final_watermark_commands;
        output.commands_processed = worker.commands_processed;
        output.command_queue_full = worker.command_queue_full;
        output.command_queue_peak = worker.command_queue_peak;
        output.result_queue_full = worker.result_queue_full;
        output.result_queue_stalls = worker.result_queue_stalls;
        output.result_queue_peak = worker.result_queue_peak;
        output.sequence_failures = worker.sequence_failures;
        output.route_failures = worker.route_failures;
        output.output_results = worker.output_results;
        output.payload_completions = worker.payload_completions;
        output.checkpoint_processing_ns =
            worker.checkpoint_processing_ns;
        output.watermark_processing_ns =
            worker.watermark_processing_ns;
        output.last_enqueued_sequence = worker.next_enqueue_sequence == 0u
            ? 0u : worker.next_enqueue_sequence - 1u;
        output.last_processed_sequence =
            worker.last_processed_sequence.load(std::memory_order_acquire);
        output.last_watermark_ns =
            worker.last_watermark_ns.load(std::memory_order_relaxed);
        output.final_watermark_ns =
            worker.final_watermark_ns.load(std::memory_order_relaxed);
        output.watermark_initialized =
            worker.watermark_initialized.load(std::memory_order_acquire);
        output.final_flush_complete =
            worker.final_flush_complete.load(std::memory_order_acquire);
        output.worker_failed =
            worker.failed.load(std::memory_order_acquire);
        if (!fk_online_event_windows_get_stats(
                worker.windows, &output.windows)) {
            complete = false;
        } else {
            complete = complete && output.windows.formal_completeness;
        }
        stats->command_queue_reserved_bytes +=
            worker.commands.reserved_bytes();
        stats->result_queue_reserved_bytes +=
            worker.responses.reserved_bytes();
        stats->feature_payload_capacity += worker.payload_capacity;
        stats->feature_payloads_in_use += worker.payloads_in_use;
        stats->feature_payloads_peak += worker.payloads_peak;
        stats->feature_payload_reserved_bytes +=
            static_cast<uint64_t>(worker.payload_capacity) *
                sizeof(FeaturePayload) +
            worker.completions.reserved_bytes();
        stats->windows_reserved_bytes +=
            worker.windows_storage_bytes;
        complete = complete && !output.worker_failed;
    }
    stats->model_parameter_bytes =
        static_cast<uint64_t>(shards->metadata.parameter_floats) *
        sizeof(float);
    stats->total_reserved_bytes =
        stats->command_queue_reserved_bytes +
        stats->result_queue_reserved_bytes +
        stats->feature_payload_reserved_bytes +
        stats->slot_binding_reserved_bytes +
        stats->windows_reserved_bytes +
        stats->model_parameter_bytes;
    stats->formal_completeness = complete;
    return true;
}

bool fk_student_shards_get_metadata(
        const fk_student_shards *shards,
        fk_event_student_metadata *metadata) {
    if (shards == nullptr || metadata == nullptr)
        return false;
    *metadata = shards->metadata;
    return true;
}

}  // extern "C"
