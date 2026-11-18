#include "fk_event_result_log.h"

#include <algorithm>
#include <array>
#include <atomic>
#include <cmath>
#include <cstdio>
#include <cstring>
#include <fcntl.h>
#include <limits>
#include <memory>
#include <new>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

namespace {

constexpr uint8_t kMagic[8] = {'F', 'K', 'E', 'R', 'E', 'S', '1', '\0'};
constexpr uint32_t kEventBindPayloadBytes = 68u;
constexpr uint32_t kWindowPayloadBytes = 96u;
constexpr uint32_t kWindowTriggerV2PayloadBytes = 108u;
constexpr uint32_t kTriggerReceiptV2PayloadBytes = 200u;
/* Schema v2 preserves the complete 216-byte v1 payload prefix and appends
 * seven uint64_t leaf counters.  The fixed record remains 320 bytes. */
constexpr uint32_t kLossSummaryPayloadBytes = 272u;
constexpr uint32_t kFooterPayloadBytes = 256u;
constexpr uint32_t kFooterCrcOffset = 264u;
constexpr size_t kMaximumQueuePayload =
    sizeof(fk_student_shard_result) + sizeof(uint64_t);

enum class QueueKind : uint8_t {
    EventBind = 1u,
    Window = 2u,
};

struct QueueRecord {
    QueueKind kind = QueueKind::EventBind;
    uint8_t reserved[7]{};
    alignas(8) uint8_t payload[
        kMaximumQueuePayload > sizeof(fk_event_result_log_event_bind)
            ? kMaximumQueuePayload
            : sizeof(fk_event_result_log_event_bind)]{};
};

struct QueuedWindow {
    fk_student_shard_result result;
    uint64_t collector_sequence;
};

static_assert(
    __atomic_always_lock_free(sizeof(uint64_t), nullptr),
    "FKERES1 requires lock-free 64-bit atomics");
static_assert(
    __atomic_always_lock_free(sizeof(uint32_t), nullptr),
    "FKERES1 requires lock-free 32-bit atomics");
static_assert(
    __atomic_always_lock_free(sizeof(bool), nullptr),
    "FKERES1 requires lock-free bool atomics");
static_assert(sizeof(QueuedWindow) <= sizeof(QueueRecord::payload));
static_assert(sizeof(fk_event_result_log_event_bind) <=
    sizeof(QueueRecord::payload));

class SpscRing {
public:
    bool initialize(uint32_t capacity) {
        if (capacity < 2u || (capacity & (capacity - 1u)) != 0u)
            return false;
        storage_.reset(new (std::nothrow) QueueRecord[capacity]);
        if (!storage_)
            return false;
        capacity_ = capacity;
        mask_ = capacity - 1u;
        return true;
    }

    bool push(const QueueRecord &record, uint32_t &depth) {
        const uint64_t tail = tail_.load(std::memory_order_relaxed);
        const uint64_t head = head_.load(std::memory_order_acquire);
        if (tail - head >= capacity_)
            return false;
        storage_[static_cast<uint32_t>(tail) & mask_] = record;
        depth = depth_.fetch_add(1u, std::memory_order_relaxed) + 1u;
        tail_.store(tail + 1u, std::memory_order_release);
        return true;
    }

    bool peek(QueueRecord &record) const {
        const uint64_t head = head_.load(std::memory_order_relaxed);
        const uint64_t tail = tail_.load(std::memory_order_acquire);
        if (head == tail)
            return false;
        record = storage_[static_cast<uint32_t>(head) & mask_];
        return true;
    }

    bool consume() {
        const uint64_t head = head_.load(std::memory_order_relaxed);
        const uint64_t tail = tail_.load(std::memory_order_acquire);
        if (head == tail)
            return false;
        depth_.fetch_sub(1u, std::memory_order_relaxed);
        head_.store(head + 1u, std::memory_order_release);
        return true;
    }

    uint32_t count() const {
        return depth_.load(std::memory_order_acquire);
    }

private:
    std::unique_ptr<QueueRecord[]> storage_;
    uint32_t capacity_ = 0u;
    uint32_t mask_ = 0u;
    alignas(64) std::atomic<uint64_t> head_{0u};
    alignas(64) std::atomic<uint64_t> tail_{0u};
    alignas(64) std::atomic<uint32_t> depth_{0u};
};

static void set_error(char *error, size_t capacity, const char *message) {
    if (error != nullptr && capacity != 0u)
        std::snprintf(error, capacity, "%s", message);
}

static bool any_nonzero(const uint8_t *value, size_t bytes) {
    uint8_t combined = 0u;
    for (size_t index = 0u; index < bytes; ++index)
        combined = static_cast<uint8_t>(combined | value[index]);
    return combined != 0u;
}

static void put_u16(uint8_t *output, uint16_t value) {
    output[0] = static_cast<uint8_t>(value);
    output[1] = static_cast<uint8_t>(value >> 8u);
}

static void put_u32(uint8_t *output, uint32_t value) {
    for (uint32_t index = 0u; index < 4u; ++index)
        output[index] = static_cast<uint8_t>(value >> (index * 8u));
}

static void put_u64(uint8_t *output, uint64_t value) {
    for (uint32_t index = 0u; index < 8u; ++index)
        output[index] = static_cast<uint8_t>(value >> (index * 8u));
}

static uint32_t float_bits(float value) {
    uint32_t bits = 0u;
    std::memcpy(&bits, &value, sizeof(bits));
    return bits;
}

/* CRC-64/ECMA-182: poly=0x42f0e1eba9ea3693, init=0, xorout=0. */
static uint64_t crc64_update(
        uint64_t crc, const uint8_t *data, size_t bytes) {
    constexpr uint64_t polynomial = UINT64_C(0x42f0e1eba9ea3693);
    for (size_t index = 0u; index < bytes; ++index) {
        crc ^= static_cast<uint64_t>(data[index]) << 56u;
        for (uint32_t bit = 0u; bit < 8u; ++bit) {
            crc = (crc & (UINT64_C(1) << 63u)) != 0u
                ? (crc << 1u) ^ polynomial : crc << 1u;
        }
    }
    return crc;
}

static int default_open(void *, const char *path) {
    return ::open(path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0644);
}

static int64_t default_write(
        void *, int descriptor, const uint8_t *data, size_t bytes) {
    const ssize_t written = ::write(descriptor, data, bytes);
    return written < 0 ? -1 : static_cast<int64_t>(written);
}

static bool default_sync(void *, int descriptor) {
    return ::fsync(descriptor) == 0;
}

static bool default_close(void *, int descriptor) {
    return ::close(descriptor) == 0;
}

static bool default_rename(
        void *, const char *partial_path, const char *final_path) {
#if defined(SYS_renameat2)
    /* A completed run is immutable: never replace an existing final file. */
    constexpr unsigned int kRenameNoReplace = 1u;
    return ::syscall(
        SYS_renameat2,
        AT_FDCWD,
        partial_path,
        AT_FDCWD,
        final_path,
        kRenameNoReplace) == 0;
#else
    (void)partial_path;
    (void)final_path;
    errno = ENOSYS;
    return false;
#endif
}

static bool io_callbacks_valid(const fk_event_result_log_io &io) {
    const bool any = io.open_partial != nullptr ||
        io.write_bytes != nullptr || io.sync_file != nullptr ||
        io.close_file != nullptr || io.rename_file != nullptr;
    const bool all = io.open_partial != nullptr &&
        io.write_bytes != nullptr && io.sync_file != nullptr &&
        io.close_file != nullptr && io.rename_file != nullptr;
    return !any || all;
}

static bool header_valid(
        const fk_event_result_log_header_binding &header,
        uint32_t extension_flags) {
    float threshold = 0.0f;
    std::memcpy(
        &threshold, &header.decision_threshold_bits, sizeof(threshold));
    const bool worker_count = header.route_worker_count == 2u ||
        header.route_worker_count == 4u ||
        header.route_worker_count == 8u;
    const bool formal =
        (extension_flags & FK_EVENT_RESULT_LOG_FORMAL_RUN_ATTESTED) != 0u;
    const bool contract_digest_present = any_nonzero(
        header.run_contract_sha256, sizeof(header.run_contract_sha256));
    return formal == contract_digest_present &&
        worker_count && header.window_ns != 0u &&
        header.stride_ns != 0u && header.stride_ns <= header.window_ns &&
        header.capture_first_timestamp_ns <=
            header.capture_last_timestamp_ns &&
        std::isfinite(threshold) && threshold >= 0.0f && threshold <= 1.0f &&
        any_nonzero(header.run_uuid, sizeof(header.run_uuid)) &&
        any_nonzero(header.capture_sha256, sizeof(header.capture_sha256)) &&
        any_nonzero(
            header.sidecar_records_sha256,
            sizeof(header.sidecar_records_sha256)) &&
        any_nonzero(header.model_sha256, sizeof(header.model_sha256)) &&
        any_nonzero(header.manifest_sha256, sizeof(header.manifest_sha256)) &&
        any_nonzero(
            header.feature_schema_sha256,
            sizeof(header.feature_schema_sha256)) &&
        any_nonzero(header.config_sha256, sizeof(header.config_sha256));
}

static void serialize_header(
        const fk_event_result_log_header_binding &header,
        uint32_t header_flags,
        uint8_t output[FK_EVENT_RESULT_LOG_HEADER_BYTES]) {
    std::memset(output, 0, FK_EVENT_RESULT_LOG_HEADER_BYTES);
    std::memcpy(output, kMagic, sizeof(kMagic));
    put_u32(output + 8u, FK_EVENT_RESULT_LOG_VERSION);
    put_u32(output + 12u, FK_EVENT_RESULT_LOG_HEADER_BYTES);
    put_u32(output + 16u, FK_EVENT_RESULT_LOG_RECORD_BYTES);
    put_u32(output + 20u, FK_EVENT_RESULT_LOG_ENDIAN_TAG);
    put_u32(output + 24u, header_flags);
    put_u32(output + 28u, header.route_worker_count);
    put_u32(output + 32u, header.decision_threshold_bits);
    put_u64(output + 40u, header.window_ns);
    put_u64(output + 48u, header.stride_ns);
    std::memcpy(output + 56u, header.run_uuid, sizeof(header.run_uuid));
    std::memcpy(output + 72u,
        header.capture_sha256, sizeof(header.capture_sha256));
    std::memcpy(output + 104u,
        header.sidecar_records_sha256,
        sizeof(header.sidecar_records_sha256));
    std::memcpy(output + 136u,
        header.model_sha256, sizeof(header.model_sha256));
    std::memcpy(output + 168u,
        header.manifest_sha256, sizeof(header.manifest_sha256));
    std::memcpy(output + 200u,
        header.feature_schema_sha256,
        sizeof(header.feature_schema_sha256));
    std::memcpy(output + 232u,
        header.config_sha256, sizeof(header.config_sha256));
    put_u64(output + 264u, header.capture_first_timestamp_ns);
    put_u64(output + 272u, header.capture_last_timestamp_ns);
    std::memcpy(output + 280u,
        header.run_contract_sha256,
        sizeof(header.run_contract_sha256));
}

static void serialize_common(
        uint8_t output[FK_EVENT_RESULT_LOG_RECORD_BYTES],
        uint32_t type,
        uint32_t payload_bytes,
        uint64_t record_sequence) {
    std::memset(output, 0, FK_EVENT_RESULT_LOG_RECORD_BYTES);
    put_u32(output, type);
    put_u32(output + 4u, payload_bytes);
    put_u64(output + 8u, record_sequence);
}

static void serialize_event_bind(
        const fk_event_result_log_event_bind &record,
        uint64_t record_sequence,
        uint8_t output[FK_EVENT_RESULT_LOG_RECORD_BYTES]) {
    serialize_common(
        output, FK_EVENT_RESULT_LOG_EVENT_BIND,
        kEventBindPayloadBytes, record_sequence);
    put_u64(output + 16u, record.run_event_id);
    put_u32(output + 24u, record.event_generation);
    put_u32(output + 28u, record.event_slot);
    output[32u] = record.identity.key_kind;
    output[33u] = record.identity.ip_version;
    output[34u] = record.identity.reserved[0];
    output[35u] = record.identity.reserved[1];
    std::memcpy(output + 36u,
        record.identity.low, sizeof(record.identity.low));
    std::memcpy(output + 52u,
        record.identity.high, sizeof(record.identity.high));
    put_u64(output + 68u, record.event_start_trace_ns);
    put_u64(output + 76u, record.collector_sequence);
}

static void serialize_window(
        const QueuedWindow &queued,
        uint64_t record_sequence,
        bool trigger_protocol_v2,
        uint8_t output[FK_EVENT_RESULT_LOG_RECORD_BYTES]) {
    serialize_common(
        output, FK_EVENT_RESULT_LOG_WINDOW_RESULT,
        trigger_protocol_v2
            ? kWindowTriggerV2PayloadBytes : kWindowPayloadBytes,
        record_sequence);
    const fk_online_event_window_result &record = queued.result.window;
    put_u64(output + 16u, record.event_id);
    put_u64(output + 24u, record.event_start_ns);
    put_u64(output + 32u, record.anchor_ns);
    put_u32(output + 40u, record.event_slot);
    put_u32(output + 44u, record.event_generation);
    put_u32(output + 48u, record.retained_flow_snapshots);
    put_u32(output + 52u, float_bits(record.raw_window_logit));
    put_u32(output + 56u, float_bits(record.prefix_event_logit));
    put_u32(output + 60u, float_bits(record.operational_logit));
    put_u32(output + 64u, float_bits(record.operational_probability));
    uint32_t flags = 0u;
    if (record.threshold_crossed)
        flags |= 1u;
    if (record.alert_latched)
        flags |= 2u;
    if (record.first_alert)
        flags |= 4u;
    put_u32(output + 68u, flags);
    put_u16(output + 72u, queued.result.worker_index);
    put_u64(output + 80u,
        queued.result.command_enqueue_monotonic_ns);
    put_u64(output + 88u,
        queued.result.command_start_monotonic_ns);
    put_u64(output + 96u,
        queued.result.decision_monotonic_ns);
    put_u64(output + 104u, queued.collector_sequence);
    if (trigger_protocol_v2) {
        put_u64(output + 112u, record.trigger_ordinal);
        output[120u] = record.trigger_protocol;
        output[121u] = record.trigger_kind;
        output[122u] = record.checkpoint_packet;
        output[123u] = record.reserved_trigger8;
    }
}

static void serialize_trigger_receipt_v2(
        const fk_event_result_log_trigger_receipt_v2 &expected,
        const fk_event_result_log &log,
        uint64_t record_sequence,
        uint8_t output[FK_EVENT_RESULT_LOG_RECORD_BYTES]);

static void serialize_loss_summary(
        const fk_event_result_log_loss_summary &summary,
        uint32_t integrity_flags,
        uint64_t record_sequence,
        uint8_t output[FK_EVENT_RESULT_LOG_RECORD_BYTES]) {
    serialize_common(
        output, FK_EVENT_RESULT_LOG_RUN_LOSS_SUMMARY,
        kLossSummaryPayloadBytes, record_sequence);
    put_u32(output + 16u, integrity_flags);
    put_u32(output + 20u, FK_EVENT_RESULT_LOG_LOSS_REASON_SCHEMA);
    const uint64_t values[]{
        summary.policy_loss_total,
        summary.policy_flow_overload_rejects,
        summary.policy_flow_quota_rejects,
        summary.policy_detector_admission_rejects,
        summary.policy_deadline_cancellations,
        summary.policy_intentional_packet_drops,
        summary.infrastructure_fatal_total,
        summary.infrastructure_input_ring_full,
        summary.infrastructure_reorder_rejections,
        summary.infrastructure_student_queue_failures,
        summary.infrastructure_result_queue_drops,
        summary.infrastructure_logger_drops,
        summary.runtime_fatal_total,
        summary.runtime_flow_capacity_errors,
        summary.runtime_checkpoint_failures,
        summary.runtime_action_record_overwrites,
        summary.runtime_detection_window_overwrites,
        summary.runtime_model_failures,
        summary.transport_fatal_total,
        summary.transport_sequence_gaps,
        summary.transport_nic_drops,
        summary.transport_read_failures,
        summary.transport_truncated_frames,
        summary.transport_parse_failures,
        summary.all_loss_total,
        summary.fatal_loss_total,
        summary.runtime_state_update_failures,
        summary.runtime_flow_open_observation_overwrites,
        summary.runtime_action_transition_failures,
        summary.runtime_association_failures,
        summary.runtime_association_state_evictions,
        summary.runtime_semantic_contract_failures,
        summary.transport_source_filter_rejections,
    };
    for (size_t index = 0u;
         index < sizeof(values) / sizeof(values[0]); ++index)
        put_u64(output + 24u + index * 8u, values[index]);
}

}  // namespace

struct fk_event_result_log {
    fk_event_result_log_header_binding header{};
    uint32_t header_flags = FK_EVENT_RESULT_LOG_BASE_HEADER_FLAGS;
    float decision_threshold = 0.0f;
    fk_event_result_log_io io{};
    std::unique_ptr<char[]> final_path;
    std::unique_ptr<char[]> partial_path;
    SpscRing ring;
    uint32_t ring_capacity = 0u;
    uint64_t ring_reserved_bytes = 0u;
    uint64_t total_reserved_bytes = 0u;
    std::atomic<uint32_t> ring_peak_depth{0u};

    std::atomic<uint64_t> event_bind_enqueued{0u};
    std::atomic<uint64_t> window_enqueued{0u};
    uint64_t next_collector_sequence = 0u; /* single producer only */
    std::atomic<uint64_t> producer_drops{0u};
    std::array<std::atomic<uint64_t>, FK_EVENT_RESULT_LOG_MAX_WORKERS>
        per_worker_windows_enqueued{};
    std::atomic<uint64_t> writer_errors{0u};
    std::atomic<uint32_t> first_error{FK_EVENT_RESULT_LOG_ERROR_NONE};
    std::atomic<bool> failed{false};
    std::atomic<bool> committed{false};

    int descriptor = -1;
    bool writer_opened = false;
    bool writer_finalized = false;
    bool writer_io_failed = false;
    bool loss_summary_written = false;
    bool trigger_receipt_written = false;
    bool footer_written = false;
    bool footer_clean = false;
    uint64_t event_bind_written = 0u;
    uint64_t window_written = 0u;
    uint64_t data_records_written = 0u;
    uint64_t bytes_before_footer = 0u;
    uint64_t rolling_crc64 = 0u;
    uint64_t final_watermark_ns = 0u;
    uint64_t final_ack_mask = 0u;
    uint32_t upstream_integrity_flags = 0u;
    fk_event_result_log_loss_summary loss_summary{};
    fk_event_result_log_trigger_receipt_v2 trigger_receipt_v2{};
    uint64_t observed_checkpoint_trigger_results = 0u;
    uint64_t observed_periodic_trigger_results = 0u;
    uint64_t observed_trigger_ordinal_sum = 0u;
    uint64_t observed_trigger_ordinal_xor = 0u;
    uint64_t observed_trigger_ordinal_max = 0u;
    uint64_t observed_checkpoint_packet_4_results = 0u;
    uint64_t observed_checkpoint_packet_8_results = 0u;
    uint64_t observed_checkpoint_packet_12_results = 0u;
    uint64_t observed_checkpoint_packet_20_results = 0u;
    std::array<uint64_t, FK_EVENT_RESULT_LOG_MAX_WORKERS>
        per_worker_windows_written{};
    std::array<uint64_t, FK_EVENT_RESULT_LOG_MAX_WORKERS>
        per_worker_command_records{};
};

namespace {

static void serialize_trigger_receipt_v2(
        const fk_event_result_log_trigger_receipt_v2 &expected,
        const fk_event_result_log &log,
        uint64_t record_sequence,
        uint8_t output[FK_EVENT_RESULT_LOG_RECORD_BYTES]) {
    serialize_common(
        output,
        FK_EVENT_RESULT_LOG_TRIGGER_RECEIPT_V2,
        kTriggerReceiptV2PayloadBytes,
        record_sequence);
    put_u32(output + 16u, 2u); /* receipt schema */
    put_u32(output + 20u, expected.trigger_protocol);
    const uint64_t values[]{
        expected.checkpoint_trigger_messages,
        expected.scheduled_periodic_ticks,
        expected.empty_periodic_ticks,
        expected.same_timestamp_unchanged_periodic_coalesces,
        expected.checkpoint_trigger_results,
        expected.periodic_trigger_results,
        expected.output_results,
        expected.trigger_ordinal_sum,
        expected.trigger_ordinal_xor,
        expected.trigger_ordinal_max,
        expected.checkpoint_packet_4_results,
        expected.checkpoint_packet_8_results,
        expected.checkpoint_packet_12_results,
        expected.checkpoint_packet_20_results,
        log.observed_checkpoint_trigger_results,
        log.observed_periodic_trigger_results,
        log.window_written,
        log.observed_trigger_ordinal_sum,
        log.observed_trigger_ordinal_xor,
        log.observed_trigger_ordinal_max,
        log.observed_checkpoint_packet_4_results,
        log.observed_checkpoint_packet_8_results,
        log.observed_checkpoint_packet_12_results,
        log.observed_checkpoint_packet_20_results,
    };
    for (size_t index = 0u;
         index < sizeof(values) / sizeof(values[0]); ++index) {
        put_u64(output + 24u + index * 8u, values[index]);
    }
}

template <size_t N>
static bool exact_sum(
        const uint64_t (&values)[N], uint64_t &result) {
    result = 0u;
    for (uint64_t value : values) {
        if (value > std::numeric_limits<uint64_t>::max() - result)
            return false;
        result += value;
    }
    return true;
}

static bool loss_summary_conserves(
        const fk_event_result_log_loss_summary &summary) {
    const uint64_t policy[]{
        summary.policy_flow_overload_rejects,
        summary.policy_flow_quota_rejects,
        summary.policy_detector_admission_rejects,
        summary.policy_deadline_cancellations,
        summary.policy_intentional_packet_drops,
    };
    const uint64_t infrastructure[]{
        summary.infrastructure_input_ring_full,
        summary.infrastructure_reorder_rejections,
        summary.infrastructure_student_queue_failures,
        summary.infrastructure_result_queue_drops,
        summary.infrastructure_logger_drops,
    };
    const uint64_t runtime[]{
        summary.runtime_flow_capacity_errors,
        summary.runtime_checkpoint_failures,
        summary.runtime_action_record_overwrites,
        summary.runtime_detection_window_overwrites,
        summary.runtime_model_failures,
        summary.runtime_state_update_failures,
        summary.runtime_flow_open_observation_overwrites,
        summary.runtime_action_transition_failures,
        summary.runtime_association_failures,
        summary.runtime_association_state_evictions,
        summary.runtime_semantic_contract_failures,
    };
    const uint64_t transport[]{
        summary.transport_sequence_gaps,
        summary.transport_nic_drops,
        summary.transport_read_failures,
        summary.transport_truncated_frames,
        summary.transport_parse_failures,
        summary.transport_source_filter_rejections,
    };
    uint64_t policy_total = 0u;
    uint64_t infrastructure_total = 0u;
    uint64_t runtime_total = 0u;
    uint64_t transport_total = 0u;
    if (!exact_sum(policy, policy_total) ||
        !exact_sum(infrastructure, infrastructure_total) ||
        !exact_sum(runtime, runtime_total) ||
        !exact_sum(transport, transport_total) ||
        policy_total != summary.policy_loss_total ||
        infrastructure_total != summary.infrastructure_fatal_total ||
        runtime_total != summary.runtime_fatal_total ||
        transport_total != summary.transport_fatal_total) {
        return false;
    }
    const uint64_t fatal[]{
        infrastructure_total, runtime_total, transport_total,
    };
    uint64_t fatal_total = 0u;
    if (!exact_sum(fatal, fatal_total) ||
        fatal_total != summary.fatal_loss_total) {
        return false;
    }
    const uint64_t all[]{policy_total, fatal_total};
    uint64_t all_total = 0u;
    return exact_sum(all, all_total) && all_total == summary.all_loss_total;
}

static bool extended_integrity_valid(
        uint32_t flags,
        const fk_event_result_log_loss_summary &summary) {
    if ((flags & ~FK_EVENT_RESULT_LOG_INTEGRITY_KNOWN_MASK) != 0u ||
        (flags & FK_EVENT_RESULT_LOG_INTEGRITY_REQUIRED_CLEAN_MASK) !=
            FK_EVENT_RESULT_LOG_INTEGRITY_REQUIRED_CLEAN_MASK ||
        summary.fatal_loss_total != 0u) {
        return false;
    }
    const bool no_policy_loss = summary.policy_loss_total == 0u;
    const bool no_policy_flag =
        (flags &
         FK_EVENT_RESULT_LOG_INTEGRITY_NO_SERVICE_POLICY_LOSS) != 0u;
    return no_policy_loss == no_policy_flag;
}

static bool trigger_receipt_v2_conserves(
        const fk_event_result_log &log,
        const fk_event_result_log_finalize &finalize) {
    const fk_event_result_log_trigger_receipt_v2 &receipt =
        finalize.trigger_receipt_v2;
    uint64_t scheduled_partition = 0u;
    const uint64_t scheduled_parts[]{
        receipt.empty_periodic_ticks,
        receipt.same_timestamp_unchanged_periodic_coalesces,
        receipt.periodic_trigger_results,
    };
    uint64_t output_partition = 0u;
    const uint64_t output_parts[]{
        receipt.checkpoint_trigger_results,
        receipt.periodic_trigger_results,
    };
    uint64_t packet_partition = 0u;
    const uint64_t packet_parts[]{
        receipt.checkpoint_packet_4_results,
        receipt.checkpoint_packet_8_results,
        receipt.checkpoint_packet_12_results,
        receipt.checkpoint_packet_20_results,
    };
    return receipt.trigger_protocol ==
            FK_ONLINE_EVENT_TRIGGER_PROTOCOL_CHECKPOINT_PERIODIC_V2 &&
        receipt.reserved32 == 0u &&
        exact_sum(scheduled_parts, scheduled_partition) &&
        scheduled_partition == receipt.scheduled_periodic_ticks &&
        exact_sum(output_parts, output_partition) &&
        output_partition == receipt.output_results &&
        exact_sum(packet_parts, packet_partition) &&
        packet_partition == receipt.checkpoint_trigger_results &&
        receipt.checkpoint_trigger_messages ==
            receipt.checkpoint_trigger_results &&
        receipt.output_results == finalize.expected_window_records &&
        receipt.output_results == log.window_written &&
        receipt.checkpoint_trigger_results ==
            log.observed_checkpoint_trigger_results &&
        receipt.periodic_trigger_results ==
            log.observed_periodic_trigger_results &&
        receipt.trigger_ordinal_sum ==
            log.observed_trigger_ordinal_sum &&
        receipt.trigger_ordinal_xor ==
            log.observed_trigger_ordinal_xor &&
        receipt.trigger_ordinal_max ==
            log.observed_trigger_ordinal_max &&
        receipt.checkpoint_packet_4_results ==
            log.observed_checkpoint_packet_4_results &&
        receipt.checkpoint_packet_8_results ==
            log.observed_checkpoint_packet_8_results &&
        receipt.checkpoint_packet_12_results ==
            log.observed_checkpoint_packet_12_results &&
        receipt.checkpoint_packet_20_results ==
            log.observed_checkpoint_packet_20_results;
}

static void mark_failure(
        fk_event_result_log &log,
        fk_event_result_log_error error,
        bool producer_drop,
        bool writer_error) {
    uint32_t expected = FK_EVENT_RESULT_LOG_ERROR_NONE;
    (void)log.first_error.compare_exchange_strong(
        expected, static_cast<uint32_t>(error),
        std::memory_order_acq_rel, std::memory_order_relaxed);
    if (producer_drop)
        log.producer_drops.fetch_add(1u, std::memory_order_relaxed);
    if (writer_error)
        log.writer_errors.fetch_add(1u, std::memory_order_relaxed);
    log.failed.store(true, std::memory_order_release);
}

static void update_peak(
        std::atomic<uint32_t> &peak, uint32_t candidate) {
    uint32_t current = peak.load(std::memory_order_relaxed);
    while (current < candidate &&
           !peak.compare_exchange_weak(
               current, candidate,
               std::memory_order_relaxed,
               std::memory_order_relaxed)) {
    }
}

static bool write_exact(
        fk_event_result_log &log,
        const uint8_t *data,
        size_t bytes,
        char *error,
        size_t error_capacity) {
    if (log.writer_io_failed || log.descriptor < 0)
        return false;
    const int64_t result = log.io.write_bytes(
        log.io.context, log.descriptor, data, bytes);
    if (result < 0) {
        mark_failure(
            log, FK_EVENT_RESULT_LOG_ERROR_WRITE, false, true);
        log.writer_io_failed = true;
        set_error(error, error_capacity, "FKERES1 write failed");
        return false;
    }
    if (static_cast<uint64_t>(result) != bytes) {
        mark_failure(
            log, FK_EVENT_RESULT_LOG_ERROR_SHORT_WRITE, false, true);
        log.writer_io_failed = true;
        set_error(error, error_capacity, "FKERES1 short write");
        return false;
    }
    return true;
}

static bool event_bind_valid(
        const fk_event_result_log &log,
        const fk_event_result_log_event_bind &record) {
    const fk_actor_event_identity &identity = record.identity;
    if (record.run_event_id == 0u || record.event_generation == 0u ||
        record.event_start_trace_ns <
            log.header.capture_first_timestamp_ns ||
        record.event_start_trace_ns >
            log.header.capture_last_timestamp_ns ||
        (identity.key_kind != FK_ACTOR_SESSION_MONITORED_ACTOR &&
         identity.key_kind != FK_ACTOR_SESSION_ENDPOINT_PAIR) ||
        (identity.ip_version != 4u && identity.ip_version != 6u) ||
        identity.reserved[0] != 0u || identity.reserved[1] != 0u) {
        return false;
    }
    if (identity.ip_version == 4u) {
        for (uint32_t index = 4u; index < 16u; ++index) {
            if (identity.low[index] != 0u || identity.high[index] != 0u)
                return false;
        }
    }
    const size_t address_bytes = identity.ip_version == 4u ? 4u : 16u;
    if (!any_nonzero(identity.low, address_bytes))
        return false;
    if (identity.key_kind == FK_ACTOR_SESSION_MONITORED_ACTOR) {
        for (uint8_t value : identity.high) {
            if (value != 0u)
                return false;
        }
    } else {
        if (!any_nonzero(identity.high, address_bytes) ||
            std::memcmp(
                identity.low, identity.high, address_bytes) >= 0) {
            return false;
        }
    }
    return true;
}

static bool window_valid(
        const fk_event_result_log &log,
        const fk_student_shard_result &result) {
    const fk_online_event_window_result &window = result.window;
    const bool trigger_v2 =
        (log.header_flags &
         FK_EVENT_RESULT_LOG_HAS_TRIGGER_PROTOCOL_V2) != 0u;
    const bool periodic = window.trigger_kind ==
        FK_ONLINE_EVENT_TRIGGER_KIND_PERIODIC;
    const bool checkpoint = window.trigger_kind ==
        FK_ONLINE_EVENT_TRIGGER_KIND_CHECKPOINT;
    const bool checkpoint_packet_valid =
        window.checkpoint_packet == 4u ||
        window.checkpoint_packet == 8u ||
        window.checkpoint_packet == 12u ||
        window.checkpoint_packet == 20u;
    const bool anchor_ordered =
        window.event_start_ns <= window.anchor_ns;
    const bool periodic_grid_aligned = anchor_ordered &&
        (window.anchor_ns - window.event_start_ns) %
            log.header.stride_ns == 0u;
    const bool trigger_valid = !trigger_v2 ||
        (window.trigger_protocol ==
             FK_ONLINE_EVENT_TRIGGER_PROTOCOL_CHECKPOINT_PERIODIC_V2 &&
         window.reserved_trigger8 == 0u &&
         ((periodic && window.checkpoint_packet == 0u &&
           periodic_grid_aligned) ||
          (checkpoint && checkpoint_packet_valid)));
    const bool expected_crossed =
        window.operational_probability >= log.decision_threshold;
    return window.event_id != 0u && window.event_generation != 0u &&
        result.worker_index < log.header.route_worker_count &&
        result.worker_index == static_cast<uint16_t>(
            (window.event_id - 1u) &
            (log.header.route_worker_count - 1u)) &&
        window.event_start_ns >= log.header.capture_first_timestamp_ns &&
        anchor_ordered &&
        window.anchor_ns <= log.header.capture_last_timestamp_ns &&
        (!trigger_v2 || trigger_valid) &&
        (trigger_v2 || periodic_grid_aligned) &&
        result.command_enqueue_monotonic_ns <=
            result.command_start_monotonic_ns &&
        result.command_start_monotonic_ns <= result.decision_monotonic_ns &&
        window.retained_flow_snapshots > 0u &&
        window.retained_flow_snapshots <= FK_ONLINE_EVENT_MAX_FLOWS &&
        std::isfinite(window.raw_window_logit) &&
        std::isfinite(window.prefix_event_logit) &&
        std::isfinite(window.operational_logit) &&
        std::isfinite(window.operational_probability) &&
        window.operational_probability >= 0.0f &&
        window.operational_probability <= 1.0f &&
        window.threshold_crossed == expected_crossed &&
        (!window.first_alert ||
         (window.threshold_crossed && window.alert_latched));
}

static void serialize_footer(
        const fk_event_result_log &log,
        const fk_event_result_log_finalize &finalize,
        bool clean,
        uint8_t output[FK_EVENT_RESULT_LOG_RECORD_BYTES]) {
    serialize_common(
        output, FK_EVENT_RESULT_LOG_FOOTER,
        kFooterPayloadBytes, log.data_records_written);
    put_u32(output + 16u, clean ? 1u : 0u);
    put_u32(output + 20u,
        log.first_error.load(std::memory_order_acquire));
    put_u64(output + 24u, finalize.final_watermark_ns);
    put_u64(output + 32u, finalize.expected_event_bind_records);
    put_u64(output + 40u, finalize.expected_window_records);
    put_u64(output + 48u,
        log.event_bind_enqueued.load(std::memory_order_acquire));
    put_u64(output + 56u,
        log.window_enqueued.load(std::memory_order_acquire));
    put_u64(output + 64u, log.event_bind_written);
    put_u64(output + 72u, log.window_written);
    put_u64(output + 80u, log.data_records_written);
    put_u64(output + 88u,
        log.producer_drops.load(std::memory_order_acquire));
    put_u64(output + 96u,
        log.writer_errors.load(std::memory_order_acquire));
    put_u64(output + 104u, finalize.final_ack_mask);
    put_u32(output + 112u, log.header.route_worker_count);
    put_u32(output + 116u, finalize.upstream_integrity_flags);
    for (uint16_t worker = 0u;
         worker < FK_EVENT_RESULT_LOG_MAX_WORKERS; ++worker) {
        put_u64(output + 120u + worker * 8u,
            log.per_worker_windows_written[worker]);
        put_u64(output + 184u + worker * 8u,
            finalize.per_worker_command_records[worker]);
    }
    put_u64(output + 248u, log.rolling_crc64);
    put_u64(output + 256u, log.bytes_before_footer);
    put_u64(output + kFooterCrcOffset,
        crc64_update(0u, output, kFooterCrcOffset));
}

static bool close_writer(
        fk_event_result_log &log,
        char *error,
        size_t error_capacity) {
    if (log.descriptor < 0)
        return true;
    const int descriptor = log.descriptor;
    log.descriptor = -1;
    log.writer_opened = false;
    if (!log.io.close_file(log.io.context, descriptor)) {
        mark_failure(
            log, FK_EVENT_RESULT_LOG_ERROR_CLOSE, false, true);
        log.writer_io_failed = true;
        set_error(error, error_capacity, "FKERES1 close failed");
        return false;
    }
    return true;
}

}  // namespace

extern "C" {

fk_event_result_log *fk_event_result_log_create(
        const fk_event_result_log_config *config,
        char *error,
        size_t error_capacity) {
    set_error(error, error_capacity, "");
    if (config == nullptr || config->final_path == nullptr ||
        config->final_path[0] == '\0' ||
        (config->header_extension_flags &
         ~(FK_EVENT_RESULT_LOG_HAS_LOSS_SUMMARY |
           FK_EVENT_RESULT_LOG_FORMAL_RUN_ATTESTED |
           FK_EVENT_RESULT_LOG_HAS_TRIGGER_PROTOCOL_V2)) != 0u ||
        ((config->header_extension_flags &
          FK_EVENT_RESULT_LOG_FORMAL_RUN_ATTESTED) != 0u &&
         (config->header_extension_flags &
          FK_EVENT_RESULT_LOG_HAS_LOSS_SUMMARY) == 0u) ||
        ((config->header_extension_flags &
          FK_EVENT_RESULT_LOG_HAS_TRIGGER_PROTOCOL_V2) != 0u &&
         (config->header_extension_flags &
          FK_EVENT_RESULT_LOG_HAS_LOSS_SUMMARY) == 0u) ||
        !io_callbacks_valid(config->io) ||
        !header_valid(config->header, config->header_extension_flags) ||
        config->ring_capacity < 2u ||
        (config->ring_capacity & (config->ring_capacity - 1u)) != 0u) {
        set_error(error, error_capacity, "invalid FKERES1 configuration");
        return nullptr;
    }
    const size_t path_bytes = std::strlen(config->final_path);
    constexpr char suffix[] = ".partial";
    if (path_bytes > std::numeric_limits<size_t>::max() - sizeof(suffix)) {
        set_error(error, error_capacity, "FKERES1 path is too long");
        return nullptr;
    }
    std::unique_ptr<fk_event_result_log> log(
        new (std::nothrow) fk_event_result_log);
    if (!log) {
        set_error(error, error_capacity, "cannot allocate FKERES1 logger");
        return nullptr;
    }
    log->final_path.reset(new (std::nothrow) char[path_bytes + 1u]);
    log->partial_path.reset(
        new (std::nothrow) char[path_bytes + sizeof(suffix)]);
    if (!log->final_path || !log->partial_path ||
        !log->ring.initialize(config->ring_capacity)) {
        set_error(error, error_capacity, "cannot reserve FKERES1 ring/path");
        return nullptr;
    }
    std::memcpy(log->final_path.get(), config->final_path, path_bytes + 1u);
    std::memcpy(log->partial_path.get(), config->final_path, path_bytes);
    std::memcpy(
        log->partial_path.get() + path_bytes, suffix, sizeof(suffix));
    log->header = config->header;
    log->header_flags = FK_EVENT_RESULT_LOG_BASE_HEADER_FLAGS |
        config->header_extension_flags;
    std::memcpy(
        &log->decision_threshold,
        &config->header.decision_threshold_bits,
        sizeof(log->decision_threshold));
    log->ring_capacity = config->ring_capacity;
    log->ring_reserved_bytes =
        static_cast<uint64_t>(config->ring_capacity) * sizeof(QueueRecord);
    log->total_reserved_bytes = sizeof(fk_event_result_log) +
        log->ring_reserved_bytes + path_bytes + 1u +
        path_bytes + sizeof(suffix);
    if (config->io.open_partial == nullptr) {
        log->io.context = nullptr;
        log->io.open_partial = default_open;
        log->io.write_bytes = default_write;
        log->io.sync_file = default_sync;
        log->io.close_file = default_close;
        log->io.rename_file = default_rename;
    } else {
        log->io = config->io;
    }
    return log.release();
}

void fk_event_result_log_destroy(fk_event_result_log *log) {
    if (log == nullptr)
        return;
    if (log->descriptor >= 0) {
        (void)log->io.close_file(log->io.context, log->descriptor);
        log->descriptor = -1;
    }
    delete log;
}

bool fk_event_result_log_enqueue_event_bind(
        fk_event_result_log *opaque,
        const fk_event_result_log_event_bind *record) {
    if (opaque == nullptr || record == nullptr)
        return false;
    fk_event_result_log &log = *opaque;
    if (log.failed.load(std::memory_order_acquire) ||
        !event_bind_valid(log, *record) ||
        record->collector_sequence != log.next_collector_sequence) {
        const bool valid_record = event_bind_valid(log, *record);
        mark_failure(
            log,
            !valid_record ? FK_EVENT_RESULT_LOG_ERROR_INVALID_RECORD :
            record->collector_sequence != log.next_collector_sequence
                ? FK_EVENT_RESULT_LOG_ERROR_COLLECTOR_SEQUENCE
                : FK_EVENT_RESULT_LOG_ERROR_STATE,
            true,
            false);
        return false;
    }
    QueueRecord queued{};
    queued.kind = QueueKind::EventBind;
    std::memcpy(queued.payload, record, sizeof(*record));
    uint32_t depth = 0u;
    if (!log.ring.push(queued, depth)) {
        mark_failure(
            log, FK_EVENT_RESULT_LOG_ERROR_RING_FULL, true, false);
        return false;
    }
    update_peak(log.ring_peak_depth, depth);
    log.next_collector_sequence++;
    log.event_bind_enqueued.fetch_add(1u, std::memory_order_relaxed);
    return true;
}

bool fk_event_result_log_enqueue_window(
        fk_event_result_log *opaque,
        const fk_student_shard_result *result,
        uint64_t collector_sequence) {
    if (opaque == nullptr || result == nullptr)
        return false;
    fk_event_result_log &log = *opaque;
    if (log.failed.load(std::memory_order_acquire) ||
        !window_valid(log, *result) ||
        collector_sequence != log.next_collector_sequence) {
        const bool valid_record = window_valid(log, *result);
        mark_failure(
            log,
            !valid_record ? FK_EVENT_RESULT_LOG_ERROR_INVALID_RECORD :
            collector_sequence != log.next_collector_sequence
                ? FK_EVENT_RESULT_LOG_ERROR_COLLECTOR_SEQUENCE
                : FK_EVENT_RESULT_LOG_ERROR_STATE,
            true,
            false);
        return false;
    }
    QueuedWindow window{};
    window.result = *result;
    window.collector_sequence = collector_sequence;
    QueueRecord queued{};
    queued.kind = QueueKind::Window;
    std::memcpy(queued.payload, &window, sizeof(window));
    uint32_t depth = 0u;
    if (!log.ring.push(queued, depth)) {
        mark_failure(
            log, FK_EVENT_RESULT_LOG_ERROR_RING_FULL, true, false);
        return false;
    }
    update_peak(log.ring_peak_depth, depth);
    log.next_collector_sequence++;
    log.window_enqueued.fetch_add(1u, std::memory_order_relaxed);
    log.per_worker_windows_enqueued[result->worker_index].fetch_add(
        1u, std::memory_order_relaxed);
    return true;
}

bool fk_event_result_log_writer_open(
        fk_event_result_log *opaque,
        char *error,
        size_t error_capacity) {
    set_error(error, error_capacity, "");
    if (opaque == nullptr)
        return false;
    fk_event_result_log &log = *opaque;
    if (log.writer_opened || log.writer_finalized || log.descriptor >= 0) {
        mark_failure(log, FK_EVENT_RESULT_LOG_ERROR_STATE, false, false);
        set_error(error, error_capacity, "FKERES1 writer state is invalid");
        return false;
    }
    log.descriptor = log.io.open_partial(
        log.io.context, log.partial_path.get());
    if (log.descriptor < 0) {
        mark_failure(log, FK_EVENT_RESULT_LOG_ERROR_OPEN, false, true);
        log.writer_io_failed = true;
        set_error(error, error_capacity, "cannot open FKERES1 partial file");
        return false;
    }
    log.writer_opened = true;
    std::array<uint8_t, FK_EVENT_RESULT_LOG_HEADER_BYTES> header{};
    serialize_header(log.header, log.header_flags, header.data());
    if (!write_exact(
            log, header.data(), header.size(), error, error_capacity)) {
        (void)close_writer(log, nullptr, 0u);
        return false;
    }
    log.rolling_crc64 = crc64_update(
        log.rolling_crc64, header.data(), header.size());
    log.bytes_before_footer = header.size();
    return true;
}

bool fk_event_result_log_writer_drain(
        fk_event_result_log *opaque,
        uint32_t maximum_records,
        uint32_t *drained,
        char *error,
        size_t error_capacity) {
    if (drained != nullptr)
        *drained = 0u;
    set_error(error, error_capacity, "");
    if (opaque == nullptr || drained == nullptr || maximum_records == 0u)
        return false;
    fk_event_result_log &log = *opaque;
    if (!log.writer_opened || log.writer_finalized || log.writer_io_failed) {
        mark_failure(log, FK_EVENT_RESULT_LOG_ERROR_STATE, false, false);
        set_error(error, error_capacity, "FKERES1 writer is not drainable");
        return false;
    }
    for (uint32_t count = 0u; count < maximum_records; ++count) {
        QueueRecord queued{};
        if (!log.ring.peek(queued))
            break;
        std::array<uint8_t, FK_EVENT_RESULT_LOG_RECORD_BYTES> bytes{};
        if (queued.kind == QueueKind::EventBind) {
            fk_event_result_log_event_bind record{};
            std::memcpy(&record, queued.payload, sizeof(record));
            if (record.collector_sequence != log.data_records_written) {
                mark_failure(
                    log, FK_EVENT_RESULT_LOG_ERROR_COLLECTOR_SEQUENCE,
                    false, false);
                set_error(error, error_capacity,
                    "FKERES1 EVENT_BIND sequence mismatch");
                return false;
            }
            serialize_event_bind(
                record, log.data_records_written, bytes.data());
        } else if (queued.kind == QueueKind::Window) {
            QueuedWindow record{};
            std::memcpy(&record, queued.payload, sizeof(record));
            if (record.collector_sequence != log.data_records_written) {
                mark_failure(
                    log, FK_EVENT_RESULT_LOG_ERROR_COLLECTOR_SEQUENCE,
                    false, false);
                set_error(error, error_capacity,
                    "FKERES1 WINDOW_RESULT sequence mismatch");
                return false;
            }
            serialize_window(
                record,
                log.data_records_written,
                (log.header_flags &
                 FK_EVENT_RESULT_LOG_HAS_TRIGGER_PROTOCOL_V2) != 0u,
                bytes.data());
        } else {
            mark_failure(
                log, FK_EVENT_RESULT_LOG_ERROR_INVALID_RECORD,
                false, false);
            set_error(error, error_capacity, "invalid FKERES1 queue record");
            return false;
        }
        if (!write_exact(
                log, bytes.data(), bytes.size(), error, error_capacity))
            return false;
        log.rolling_crc64 = crc64_update(
            log.rolling_crc64, bytes.data(), bytes.size());
        log.bytes_before_footer += bytes.size();
        if (!log.ring.consume()) {
            mark_failure(
                log, FK_EVENT_RESULT_LOG_ERROR_STATE, false, false);
            set_error(error, error_capacity, "FKERES1 ring consume failed");
            return false;
        }
        if (queued.kind == QueueKind::EventBind) {
            log.event_bind_written++;
        } else {
            QueuedWindow record{};
            std::memcpy(&record, queued.payload, sizeof(record));
            log.window_written++;
            log.per_worker_windows_written[
                record.result.worker_index]++;
            if ((log.header_flags &
                 FK_EVENT_RESULT_LOG_HAS_TRIGGER_PROTOCOL_V2) != 0u) {
                const fk_online_event_window_result &window =
                    record.result.window;
                if (window.trigger_ordinal >
                    std::numeric_limits<uint64_t>::max() -
                        log.observed_trigger_ordinal_sum) {
                    mark_failure(
                        log,
                        FK_EVENT_RESULT_LOG_ERROR_TRIGGER_RECEIPT,
                        false,
                        false);
                } else {
                    log.observed_trigger_ordinal_sum +=
                        window.trigger_ordinal;
                }
                log.observed_trigger_ordinal_xor ^=
                    window.trigger_ordinal;
                log.observed_trigger_ordinal_max = std::max(
                    log.observed_trigger_ordinal_max,
                    window.trigger_ordinal);
                if (window.trigger_kind ==
                        FK_ONLINE_EVENT_TRIGGER_KIND_CHECKPOINT) {
                    log.observed_checkpoint_trigger_results++;
                    if (window.checkpoint_packet == 4u)
                        log.observed_checkpoint_packet_4_results++;
                    else if (window.checkpoint_packet == 8u)
                        log.observed_checkpoint_packet_8_results++;
                    else if (window.checkpoint_packet == 12u)
                        log.observed_checkpoint_packet_12_results++;
                    else if (window.checkpoint_packet == 20u)
                        log.observed_checkpoint_packet_20_results++;
                } else {
                    log.observed_periodic_trigger_results++;
                }
            }
        }
        log.data_records_written++;
        (*drained)++;
    }
    return true;
}

bool fk_event_result_log_writer_finalize(
        fk_event_result_log *opaque,
        const fk_event_result_log_finalize *finalize,
        char *error,
        size_t error_capacity) {
    set_error(error, error_capacity, "");
    if (opaque == nullptr || finalize == nullptr)
        return false;
    fk_event_result_log &log = *opaque;
    if (!log.writer_opened || log.writer_finalized || log.descriptor < 0 ||
        log.writer_io_failed) {
        mark_failure(log, FK_EVENT_RESULT_LOG_ERROR_STATE, false, false);
        set_error(error, error_capacity, "FKERES1 writer cannot finalize");
        return false;
    }
    log.writer_finalized = true;
    log.final_watermark_ns = finalize->final_watermark_ns;
    log.final_ack_mask = finalize->final_ack_mask;
    log.upstream_integrity_flags = finalize->upstream_integrity_flags;
    log.loss_summary = finalize->loss_summary;
    log.trigger_receipt_v2 = finalize->trigger_receipt_v2;
    std::copy(
        std::begin(finalize->per_worker_command_records),
        std::end(finalize->per_worker_command_records),
        log.per_worker_command_records.begin());

    if (log.ring.count() != 0u) {
        mark_failure(
            log, FK_EVENT_RESULT_LOG_ERROR_CONSERVATION, false, false);
        (void)close_writer(log, nullptr, 0u);
        set_error(error, error_capacity, "FKERES1 ring was not drained");
        return false;
    }
    const uint64_t enqueued_binds =
        log.event_bind_enqueued.load(std::memory_order_acquire);
    const uint64_t enqueued_windows =
        log.window_enqueued.load(std::memory_order_acquire);
    uint64_t worker_window_sum = 0u;
    for (uint16_t worker = 0u;
         worker < log.header.route_worker_count; ++worker) {
        worker_window_sum += log.per_worker_windows_written[worker];
    }
    const bool conservation =
        finalize->expected_event_bind_records == enqueued_binds &&
        finalize->expected_window_records == enqueued_windows &&
        enqueued_binds == log.event_bind_written &&
        enqueued_windows == log.window_written &&
        log.next_collector_sequence ==
            enqueued_binds + enqueued_windows &&
        log.next_collector_sequence == log.data_records_written &&
        log.data_records_written ==
            log.event_bind_written + log.window_written &&
        worker_window_sum == log.window_written;
    if (!conservation) {
        mark_failure(
            log, FK_EVENT_RESULT_LOG_ERROR_CONSERVATION, false, false);
    }
    const uint64_t expected_ack_mask =
        (UINT64_C(1) << log.header.route_worker_count) - 1u;
    if (finalize->final_ack_mask != expected_ack_mask) {
        mark_failure(
            log, FK_EVENT_RESULT_LOG_ERROR_FINAL_ACK, false, false);
    }
    const bool extended =
        (log.header_flags & FK_EVENT_RESULT_LOG_HAS_LOSS_SUMMARY) != 0u;
    const bool trigger_v2 =
        (log.header_flags &
         FK_EVENT_RESULT_LOG_HAS_TRIGGER_PROTOCOL_V2) != 0u;
    const bool trigger_conservation =
        !trigger_v2 || trigger_receipt_v2_conserves(log, *finalize);
    if (!trigger_conservation) {
        mark_failure(
            log, FK_EVENT_RESULT_LOG_ERROR_TRIGGER_RECEIPT, false, false);
    }
    const bool summary_conserves =
        loss_summary_conserves(finalize->loss_summary);
    const bool legacy_summary_empty =
        summary_conserves && finalize->loss_summary.all_loss_total == 0u;
    if (!summary_conserves || (!extended && !legacy_summary_empty)) {
        mark_failure(
            log, FK_EVENT_RESULT_LOG_ERROR_LOSS_SUMMARY, false, false);
    }
    const bool upstream_integrity =
        finalize->final_watermark_ns ==
            log.header.capture_last_timestamp_ns &&
        (extended
            ? summary_conserves && extended_integrity_valid(
                finalize->upstream_integrity_flags,
                finalize->loss_summary)
            : finalize->upstream_integrity_flags ==
                FK_EVENT_RESULT_LOG_UPSTREAM_INTEGRITY_PASSED &&
              legacy_summary_empty);
    if (!upstream_integrity) {
        mark_failure(
            log, FK_EVENT_RESULT_LOG_ERROR_UPSTREAM_INTEGRITY,
            false, false);
    }
    if (extended) {
        std::array<uint8_t, FK_EVENT_RESULT_LOG_RECORD_BYTES> summary{};
        serialize_loss_summary(
            finalize->loss_summary,
            finalize->upstream_integrity_flags,
            log.data_records_written,
            summary.data());
        if (!write_exact(
                log, summary.data(), summary.size(), error, error_capacity)) {
            (void)close_writer(log, nullptr, 0u);
            return false;
        }
        log.rolling_crc64 = crc64_update(
            log.rolling_crc64, summary.data(), summary.size());
        log.bytes_before_footer += summary.size();
        log.data_records_written++;
        log.loss_summary_written = true;
    }
    if (trigger_v2) {
        std::array<uint8_t, FK_EVENT_RESULT_LOG_RECORD_BYTES> receipt{};
        serialize_trigger_receipt_v2(
            finalize->trigger_receipt_v2,
            log,
            log.data_records_written,
            receipt.data());
        if (!write_exact(
                log, receipt.data(), receipt.size(), error, error_capacity)) {
            (void)close_writer(log, nullptr, 0u);
            return false;
        }
        log.rolling_crc64 = crc64_update(
            log.rolling_crc64, receipt.data(), receipt.size());
        log.bytes_before_footer += receipt.size();
        log.data_records_written++;
        log.trigger_receipt_written = true;
    }
    const bool clean = conservation &&
        finalize->final_ack_mask == expected_ack_mask &&
        upstream_integrity &&
        trigger_conservation &&
        summary_conserves &&
        log.producer_drops.load(std::memory_order_acquire) == 0u &&
        log.writer_errors.load(std::memory_order_acquire) == 0u &&
        log.first_error.load(std::memory_order_acquire) ==
            FK_EVENT_RESULT_LOG_ERROR_NONE;
    std::array<uint8_t, FK_EVENT_RESULT_LOG_RECORD_BYTES> footer{};
    serialize_footer(log, *finalize, clean, footer.data());
    if (!write_exact(
            log, footer.data(), footer.size(), error, error_capacity)) {
        (void)close_writer(log, nullptr, 0u);
        return false;
    }
    log.footer_written = true;
    log.footer_clean = clean;
    if (!log.io.sync_file(log.io.context, log.descriptor)) {
        mark_failure(log, FK_EVENT_RESULT_LOG_ERROR_FSYNC, false, true);
        log.writer_io_failed = true;
        (void)close_writer(log, nullptr, 0u);
        set_error(error, error_capacity, "FKERES1 fsync failed");
        return false;
    }
    if (!close_writer(log, error, error_capacity))
        return false;
    if (!clean) {
        set_error(error, error_capacity,
            "FKERES1 conservation/final-ACK gate failed");
        return false;
    }
    if (!log.io.rename_file(
            log.io.context,
            log.partial_path.get(),
            log.final_path.get())) {
        mark_failure(log, FK_EVENT_RESULT_LOG_ERROR_RENAME, false, true);
        log.writer_io_failed = true;
        set_error(error, error_capacity, "FKERES1 atomic rename failed");
        return false;
    }
    log.committed.store(true, std::memory_order_release);
    return true;
}

bool fk_event_result_log_failed(const fk_event_result_log *log) {
    return log == nullptr || log->failed.load(std::memory_order_acquire);
}

uint32_t fk_event_result_log_ring_depth(
        const fk_event_result_log *log) {
    return log == nullptr ? 0u : log->ring.count();
}

bool fk_event_result_log_get_stats(
        const fk_event_result_log *log,
        fk_event_result_log_stats *stats) {
    if (log == nullptr || stats == nullptr)
        return false;
    std::memset(stats, 0, sizeof(*stats));
    stats->event_bind_enqueued =
        log->event_bind_enqueued.load(std::memory_order_acquire);
    stats->window_enqueued =
        log->window_enqueued.load(std::memory_order_acquire);
    stats->event_bind_written = log->event_bind_written;
    stats->window_written = log->window_written;
    stats->producer_drops =
        log->producer_drops.load(std::memory_order_acquire);
    stats->writer_errors =
        log->writer_errors.load(std::memory_order_acquire);
    stats->data_records_written = log->data_records_written;
    stats->bytes_before_footer = log->bytes_before_footer;
    stats->rolling_crc64 = log->rolling_crc64;
    stats->final_watermark_ns = log->final_watermark_ns;
    stats->final_ack_mask = log->final_ack_mask;
    stats->header_flags = log->header_flags;
    stats->upstream_integrity_flags = log->upstream_integrity_flags;
    stats->loss_summary = log->loss_summary;
    stats->trigger_receipt_v2 = log->trigger_receipt_v2;
    stats->observed_checkpoint_trigger_results =
        log->observed_checkpoint_trigger_results;
    stats->observed_periodic_trigger_results =
        log->observed_periodic_trigger_results;
    stats->observed_trigger_ordinal_sum =
        log->observed_trigger_ordinal_sum;
    stats->observed_trigger_ordinal_xor =
        log->observed_trigger_ordinal_xor;
    stats->observed_trigger_ordinal_max =
        log->observed_trigger_ordinal_max;
    stats->observed_checkpoint_packet_4_results =
        log->observed_checkpoint_packet_4_results;
    stats->observed_checkpoint_packet_8_results =
        log->observed_checkpoint_packet_8_results;
    stats->observed_checkpoint_packet_12_results =
        log->observed_checkpoint_packet_12_results;
    stats->observed_checkpoint_packet_20_results =
        log->observed_checkpoint_packet_20_results;
    for (uint16_t worker = 0u;
         worker < FK_EVENT_RESULT_LOG_MAX_WORKERS; ++worker) {
        stats->per_worker_windows_enqueued[worker] =
            log->per_worker_windows_enqueued[worker].load(
                std::memory_order_acquire);
        stats->per_worker_windows_written[worker] =
            log->per_worker_windows_written[worker];
        stats->per_worker_command_records[worker] =
            log->per_worker_command_records[worker];
    }
    stats->ring_reserved_bytes = log->ring_reserved_bytes;
    stats->total_reserved_bytes = log->total_reserved_bytes;
    stats->ring_capacity = log->ring_capacity;
    stats->ring_depth = log->ring.count();
    stats->ring_peak_depth =
        log->ring_peak_depth.load(std::memory_order_acquire);
    stats->first_error = static_cast<fk_event_result_log_error>(
        log->first_error.load(std::memory_order_acquire));
    stats->writer_opened = log->writer_opened;
    stats->loss_summary_written = log->loss_summary_written;
    stats->trigger_receipt_written = log->trigger_receipt_written;
    stats->footer_written = log->footer_written;
    stats->footer_clean = log->footer_clean;
    stats->committed = log->committed.load(std::memory_order_acquire);
    stats->failed = log->failed.load(std::memory_order_acquire);
    return true;
}

const char *fk_event_result_log_partial_path(
        const fk_event_result_log *log) {
    return log == nullptr ? nullptr : log->partial_path.get();
}

}  // extern "C"
