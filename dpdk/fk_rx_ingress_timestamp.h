#ifndef FK_RX_INGRESS_TIMESTAMP_H
#define FK_RX_INGRESS_TIMESTAMP_H

#include <cstdint>

namespace fk_rx_ingress_timestamp {

enum class SelectionStatus : uint8_t {
    kDirectWorker,
    kPropagatedPump,
    kMissingPumpStamp,
    kInvalidTimestamp,
};

struct Selection {
    SelectionStatus status = SelectionStatus::kInvalidTimestamp;
    uint64_t timestamp_ns = 0u;
};

/*
 * Select the single receiver-local physical-ingress clock boundary used by
 * both throughput and end-to-end deadline accounting.  A pumped packet may
 * never fall back to the later owner-worker observation: a missing, zero or
 * future pump stamp remains an explicit fail-closed result.  Direct RX keeps
 * its local post-rx_burst observation because there is no pump/handoff stage.
 */
inline Selection select(
        bool pumped,
        bool pump_stamp_valid,
        uint64_t pump_timestamp_ns,
        uint64_t worker_observation_ns) {
    if (worker_observation_ns == 0u)
        return {};
    if (!pumped) {
        return {
            SelectionStatus::kDirectWorker,
            worker_observation_ns,
        };
    }
    if (!pump_stamp_valid) {
        return {
            SelectionStatus::kMissingPumpStamp,
            0u,
        };
    }
    if (pump_timestamp_ns == 0u ||
        pump_timestamp_ns > worker_observation_ns) {
        return {};
    }
    return {
        SelectionStatus::kPropagatedPump,
        pump_timestamp_ns,
    };
}

inline bool usable(const Selection &selection) {
    return selection.status == SelectionStatus::kDirectWorker ||
        selection.status == SelectionStatus::kPropagatedPump;
}

}  // namespace fk_rx_ingress_timestamp

#endif
