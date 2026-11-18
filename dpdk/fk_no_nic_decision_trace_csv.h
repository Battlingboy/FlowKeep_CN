#ifndef FLOWKEEP_FK_NO_NIC_DECISION_TRACE_CSV_H
#define FLOWKEEP_FK_NO_NIC_DECISION_TRACE_CSV_H

#include "fk_no_nic_full_composition.h"

#include <array>
#include <cinttypes>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <cstdio>

/* A bounded append-only exporter. The stdio buffer and each encoded row are
 * fixed-size storage owned by this object; the decision callback neither
 * allocates nor grows a container on the packet/decision path. */
class fk_no_nic_decision_trace_csv_writer {
public:
    fk_no_nic_decision_trace_csv_writer() = default;
    fk_no_nic_decision_trace_csv_writer(
        const fk_no_nic_decision_trace_csv_writer &) = delete;
    fk_no_nic_decision_trace_csv_writer &operator=(
        const fk_no_nic_decision_trace_csv_writer &) = delete;

    ~fk_no_nic_decision_trace_csv_writer() { (void)finish(); }

    bool open_exclusive(const char *path) {
        if (path == nullptr || *path == '\0' || stream_ != nullptr || closed_)
            return false;
        stream_ = std::fopen(path, "wx");
        if (stream_ == nullptr)
            return false;
        if (std::setvbuf(
                stream_, stream_buffer_.data(), _IOFBF,
                stream_buffer_.size()) != 0) {
            (void)std::fclose(stream_);
            stream_ = nullptr;
            return false;
        }
        static constexpr char kHeader[] =
            "trace_abi,record_sequence,trace_kind,input_sequence,packet_sequence,"
            "ip_version,protocol,low_addr_hex,high_addr_hex,low_port,high_port,"
            "logical_connection_id,flow_index,flow_generation,flow_first_ns,"
            "observation_ns,physical_ingress_ns,association_enqueue_ns,"
            "detector_start_ns,decision_ns,detection_latency_ns,"
            "packet_to_decision_ns,flow_detector_latency_ns,event_id,event_slot,"
            "event_generation,event_start_ns,event_anchor_ns,trigger_ordinal,"
            "packet_count,retained_flow_snapshots,event_score,flow_score,"
            "selected_utility,trigger_protocol,trigger_kind,checkpoint_packet,"
            "flow_association_available,action_available,flow_score_available,"
            "packet_latency_available,previous_mask,selected_mask,"
            "protocol_applicable_mask,final_mask,"
            "released_mask_before,released_mask_after,materializable_mask,"
            "pool_unavailable_mask,observation_complete,pressure,missing_stat,"
            "missing_seq,missing_ja4,candidates_considered,budget_rejections,"
            "action_reason,controlled_bytes_before,controlled_bytes_after,"
            "threshold_crossed,alert_latched,first_alert,behavior_stage,"
            "alert_state,alert_state_changed,correction_emitted,reopen_emitted,"
            "transition_sequence,transition_timestamp_ns,transition_component,"
            "transition_reason,transition_victim_index,"
            "transition_victim_generation,transition_causing_index,"
            "transition_causing_generation,transition_causing_packet_count,"
            "transition_bytes_released,transition_victim_loss,"
            "transition_victim_value_per_byte,transition_incoming_bundle_gain,"
            "transition_victim_total_loss,transition_hysteresis_eta\n";
        if (std::fwrite(kHeader, 1u, sizeof(kHeader) - 1u, stream_) !=
            sizeof(kHeader) - 1u) {
            failed_ = true;
            return false;
        }
        bytes_ = sizeof(kHeader) - 1u;
        return true;
    }

    static bool sink(
            void *context,
            const fk_no_nic_decision_trace_record_v1 *record) {
        return context != nullptr && record != nullptr &&
            static_cast<fk_no_nic_decision_trace_csv_writer *>(context)->
                append(*record);
    }

    bool finish() {
        if (closed_)
            return !failed_;
        closed_ = true;
        bool valid = !failed_;
        if (stream_ == nullptr) {
            failed_ = !valid;
            return valid;
        }
        const bool flushed = std::fflush(stream_) == 0;
        const bool closed = std::fclose(stream_) == 0;
        valid = flushed && closed && valid;
        stream_ = nullptr;
        failed_ = !valid;
        return valid;
    }

    uint64_t records() const { return records_; }
    uint64_t bytes() const { return bytes_; }
    uint64_t checkpoint_records() const { return checkpoint_records_; }
    uint64_t checkpoint_fifo_order_violations() const {
        return checkpoint_fifo_order_violations_;
    }
    uint64_t maximum_flow_detector_latency_ns() const {
        return maximum_flow_detector_latency_ns_;
    }
    uint64_t maximum_flow_detector_schedule_latency_ns() const {
        return maximum_flow_detector_schedule_latency_ns_;
    }
    bool failed() const { return failed_; }
    bool opened() const { return stream_ != nullptr; }

private:
    static void hex_address(const uint8_t address[16], char output[33]) {
        static constexpr char kHex[] = "0123456789abcdef";
        for (size_t index = 0u; index < 16u; ++index) {
            output[index * 2u] = kHex[address[index] >> 4u];
            output[index * 2u + 1u] = kHex[address[index] & 15u];
        }
        output[32] = '\0';
    }

    bool append(const fk_no_nic_decision_trace_record_v1 &r) {
        if (stream_ == nullptr || failed_ ||
            r.abi_version != FK_NO_NIC_DECISION_TRACE_ABI_VERSION ||
            r.record_bytes != sizeof(r)) {
            failed_ = true;
            return false;
        }
        char low[33]{};
        char high[33]{};
        hex_address(r.flow_key.low_addr, low);
        hex_address(r.flow_key.high_addr, high);
        std::array<char, 4096u> row{};
        size_t used = 0u;
        const auto append = [&row, &used](const char *format, auto... values) {
            const int encoded = std::snprintf(
                row.data() + used, row.size() - used, format, values...);
            if (encoded <= 0 ||
                static_cast<size_t>(encoded) >= row.size() - used)
                return false;
            used += static_cast<size_t>(encoded);
            return true;
        };
        if (!append(
            "%u,%" PRIu64 ",%u,%" PRIu64 ",%" PRIu64
            ",%u,%u,%s,%s,%u,%u,%" PRIu64 ",%u,%u",
            r.abi_version, r.record_sequence, r.trace_kind, r.input_sequence,
            r.packet_sequence, r.flow_key.ip_version, r.flow_key.protocol, low,
            high, r.flow_key.low_port, r.flow_key.high_port,
            r.logical_connection_id, r.flow_index, r.flow_generation) ||
            !append(
            ",%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",%" PRIu64
            ",%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",%" PRIu64
            ",%" PRIu64,
            r.flow_first_timestamp_ns, r.observation_timestamp_ns,
            r.physical_ingress_timestamp_ns,
            r.association_enqueue_timestamp_ns, r.detector_start_monotonic_ns,
            r.decision_monotonic_ns, r.detection_latency_ns,
            r.packet_to_decision_latency_ns, r.flow_detector_latency_ns) ||
            !append(
            ",%" PRIu64 ",%u,%u,%" PRIu64 ",%" PRIu64 ",%" PRIu64
            ",%" PRIu64 ",%u",
            r.event_id, r.event_slot, r.event_generation, r.event_start_ns,
            r.event_anchor_ns, r.trigger_ordinal, r.packet_count,
            r.retained_flow_snapshots) ||
            !append(
            ",%.9g,%.9g,%.9g,%u,%u,%u,%u,%u,%u,%u",
            static_cast<double>(r.event_detector_score),
            static_cast<double>(r.flow_detector_score),
            static_cast<double>(r.selected_utility), r.trigger_protocol,
            r.trigger_kind, r.checkpoint_packet,
            r.flow_association_available, r.action_available,
            r.flow_detector_score_available, r.packet_latency_available) ||
            !append(
            ",%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u",
            r.previous_mask, r.selected_mask, r.protocol_applicable_mask,
            r.final_mask,
            r.released_mask_before,
            r.released_mask_after, r.materializable_mask,
            r.pool_unavailable_mask, r.observation_complete, r.pressure,
            r.missing_reason[0], r.missing_reason[1], r.missing_reason[2],
            r.candidates_considered, r.budget_rejections, r.action_reason) ||
            !append(
            ",%" PRIu64 ",%" PRIu64 ",%u,%u,%u,%u,%u,%u,%u,%u",
            r.controlled_bytes_before, r.controlled_bytes_after,
            r.threshold_crossed, r.alert_latched, r.first_alert,
            r.behavior_stage, r.alert_state, r.alert_state_changed,
            r.correction_emitted, r.reopen_emitted) ||
            !append(
            ",%" PRIu64 ",%" PRIu64 ",%u,%u,%u,%u,%u,%u,%u,%" PRIu64
            ",%.9g,%.9g,%.9g,%.9g,%.9g\n",
            r.evidence_transition_sequence,
            r.evidence_transition_timestamp_ns,
            r.transition_component,
            r.transition_reason,
            r.transition_victim_index,
            r.transition_victim_generation,
            r.transition_causing_index,
            r.transition_causing_generation,
            r.transition_causing_packet_count,
            r.evidence_transition_bytes_released,
            static_cast<double>(r.transition_victim_loss),
            static_cast<double>(r.transition_victim_value_per_byte),
            static_cast<double>(r.transition_incoming_bundle_gain),
            static_cast<double>(r.transition_victim_total_loss),
            static_cast<double>(r.transition_hysteresis_eta)) ||
            std::fwrite(row.data(), 1u, used, stream_) != used ||
            bytes_ > UINT64_MAX - static_cast<uint64_t>(used) ||
            records_ == UINT64_MAX) {
            failed_ = true;
            return false;
        }
        bytes_ += static_cast<uint64_t>(used);
        records_++;
        if (r.trace_kind == FK_NO_NIC_DECISION_TRACE_CHECKPOINT) {
            checkpoint_records_++;
            if (has_checkpoint_input_sequence_ &&
                r.input_sequence <= last_checkpoint_input_sequence_) {
                checkpoint_fifo_order_violations_++;
            }
            has_checkpoint_input_sequence_ = true;
            last_checkpoint_input_sequence_ = r.input_sequence;
            if (r.flow_detector_latency_ns >
                maximum_flow_detector_latency_ns_) {
                maximum_flow_detector_latency_ns_ =
                    r.flow_detector_latency_ns;
            }
            const uint64_t queue_wait_ns =
                r.detector_start_monotonic_ns >=
                        r.association_enqueue_timestamp_ns
                ? r.detector_start_monotonic_ns -
                    r.association_enqueue_timestamp_ns
                : UINT64_MAX;
            const uint64_t scheduled_latency_ns =
                queue_wait_ns <=
                        UINT64_MAX - r.flow_detector_latency_ns
                ? queue_wait_ns + r.flow_detector_latency_ns
                : UINT64_MAX;
            if (scheduled_latency_ns >
                maximum_flow_detector_schedule_latency_ns_) {
                maximum_flow_detector_schedule_latency_ns_ =
                    scheduled_latency_ns;
            }
        }
        return true;
    }

    FILE *stream_ = nullptr;
    std::array<char, 1u << 20u> stream_buffer_{};
    uint64_t records_ = 0u;
    uint64_t bytes_ = 0u;
    uint64_t checkpoint_records_ = 0u;
    uint64_t checkpoint_fifo_order_violations_ = 0u;
    uint64_t last_checkpoint_input_sequence_ = 0u;
    uint64_t maximum_flow_detector_latency_ns_ = 0u;
    uint64_t maximum_flow_detector_schedule_latency_ns_ = 0u;
    bool has_checkpoint_input_sequence_ = false;
    bool failed_ = false;
    bool closed_ = false;
};

/* Separate opt-in exporter for exact detector requests.  The object (and its
 * fixed stdio buffer) need not exist when instrumentation is disabled. */
class fk_no_nic_detector_request_trace_csv_writer {
public:
    fk_no_nic_detector_request_trace_csv_writer() = default;
    fk_no_nic_detector_request_trace_csv_writer(
        const fk_no_nic_detector_request_trace_csv_writer &) = delete;
    fk_no_nic_detector_request_trace_csv_writer &operator=(
        const fk_no_nic_detector_request_trace_csv_writer &) = delete;

    ~fk_no_nic_detector_request_trace_csv_writer() { (void)finish(); }

    bool open_exclusive(const char *path) {
        if (path == nullptr || *path == '\0' || stream_ != nullptr || closed_)
            return false;
        stream_ = std::fopen(path, "wx");
        if (stream_ == nullptr)
            return false;
        if (std::setvbuf(
                stream_, stream_buffer_.data(), _IOFBF,
                stream_buffer_.size()) != 0) {
            (void)std::fclose(stream_);
            stream_ = nullptr;
            return false;
        }
        static constexpr char kPrefix[] =
            "trace_record_sequence,ip_version,protocol,low_addr_hex,"
            "high_addr_hex,low_port,high_port,logical_connection_id,"
            "flow_index,flow_generation,flow_first_ns,checkpoint_packet,"
            "observation_ns,feature_count";
        if (std::fwrite(
                kPrefix, 1u, sizeof(kPrefix) - 1u, stream_) !=
                sizeof(kPrefix) - 1u) {
            failed_ = true;
            return false;
        }
        bytes_ = sizeof(kPrefix) - 1u;
        std::array<char, 32u> column{};
        for (uint32_t index = 0u;
             index < FK_NO_NIC_DECISION_TRACE_DETECTOR_FEATURES; ++index) {
            const int encoded = std::snprintf(
                column.data(), column.size(), ",feature_%03u", index);
            if (encoded <= 0 ||
                static_cast<size_t>(encoded) >= column.size() ||
                std::fwrite(
                    column.data(), 1u, static_cast<size_t>(encoded), stream_) !=
                    static_cast<size_t>(encoded) ||
                bytes_ > UINT64_MAX - static_cast<uint64_t>(encoded)) {
                failed_ = true;
                return false;
            }
            bytes_ += static_cast<uint64_t>(encoded);
        }
        if (std::fwrite("\n", 1u, 1u, stream_) != 1u ||
            bytes_ == UINT64_MAX) {
            failed_ = true;
            return false;
        }
        bytes_++;
        return true;
    }

    static bool sink(
            void *context,
            const fk_no_nic_detector_request_trace_record_v1 *record) {
        return context != nullptr && record != nullptr &&
            static_cast<fk_no_nic_detector_request_trace_csv_writer *>(
                context)->append(*record);
    }

    bool finish() {
        if (closed_)
            return !failed_;
        closed_ = true;
        if (stream_ == nullptr)
            return !failed_;
        const bool flushed = std::fflush(stream_) == 0;
        const bool closed = std::fclose(stream_) == 0;
        stream_ = nullptr;
        failed_ = !(flushed && closed && !failed_);
        return !failed_;
    }

    uint64_t records() const { return records_; }
    uint64_t bytes() const { return bytes_; }
    bool failed() const { return failed_; }

private:
    static void hex_address(const uint8_t address[16], char output[33]) {
        static constexpr char kHex[] = "0123456789abcdef";
        for (size_t index = 0u; index < 16u; ++index) {
            output[index * 2u] = kHex[address[index] >> 4u];
            output[index * 2u + 1u] = kHex[address[index] & 15u];
        }
        output[32] = '\0';
    }

    bool append(const fk_no_nic_detector_request_trace_record_v1 &r) {
        if (stream_ == nullptr || failed_ ||
            r.abi_version != FK_NO_NIC_DETECTOR_REQUEST_TRACE_ABI_VERSION ||
            r.record_bytes != sizeof(r) ||
            r.feature_count !=
                FK_NO_NIC_DECISION_TRACE_DETECTOR_FEATURES) {
            failed_ = true;
            return false;
        }
        for (uint32_t index = 0u;
             index < FK_NO_NIC_DECISION_TRACE_DETECTOR_FEATURES; ++index) {
            if (!std::isfinite(r.features[index])) {
                failed_ = true;
                return false;
            }
        }
        char low[33]{};
        char high[33]{};
        hex_address(r.flow_key.low_addr, low);
        hex_address(r.flow_key.high_addr, high);
        std::array<char, 8192u> row{};
        size_t used = 0u;
        const auto append = [&row, &used](const char *format, auto... values) {
            const int encoded = std::snprintf(
                row.data() + used, row.size() - used, format, values...);
            if (encoded <= 0 ||
                static_cast<size_t>(encoded) >= row.size() - used)
                return false;
            used += static_cast<size_t>(encoded);
            return true;
        };
        if (!append(
                "%" PRIu64 ",%u,%u,%s,%s,%u,%u,%" PRIu64
                ",%u,%u,%" PRIu64 ",%u,%" PRIu64 ",%u",
                r.trace_record_sequence, r.flow_key.ip_version,
                r.flow_key.protocol, low, high, r.flow_key.low_port,
                r.flow_key.high_port, r.logical_connection_id, r.flow_index,
                r.flow_generation, r.flow_first_timestamp_ns,
                r.checkpoint_packet, r.observation_timestamp_ns,
                r.feature_count)) {
            failed_ = true;
            return false;
        }
        for (uint32_t index = 0u;
             index < FK_NO_NIC_DECISION_TRACE_DETECTOR_FEATURES; ++index) {
            if (!append(
                    ",%.9g", static_cast<double>(r.features[index]))) {
                failed_ = true;
                return false;
            }
        }
        if (!append("\n") ||
            std::fwrite(row.data(), 1u, used, stream_) != used ||
            bytes_ > UINT64_MAX - static_cast<uint64_t>(used) ||
            records_ == UINT64_MAX) {
            failed_ = true;
            return false;
        }
        bytes_ += static_cast<uint64_t>(used);
        records_++;
        return true;
    }

    FILE *stream_ = nullptr;
    std::array<char, 1u << 20u> stream_buffer_{};
    uint64_t records_ = 0u;
    uint64_t bytes_ = 0u;
    bool failed_ = false;
    bool closed_ = false;
};

#endif
