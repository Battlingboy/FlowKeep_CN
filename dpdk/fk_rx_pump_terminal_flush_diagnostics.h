#ifndef FLOWKEEP_FK_RX_PUMP_TERMINAL_FLUSH_DIAGNOSTICS_H_
#define FLOWKEEP_FK_RX_PUMP_TERMINAL_FLUSH_DIAGNOSTICS_H_

#include <array>
#include <cstddef>
#include <cstdint>
#include <ostream>

namespace flowkeep {

constexpr std::uint32_t kRxPumpTerminalFlushMaximum = 512u;
constexpr std::uint64_t kRxPumpTerminalLongFlushThresholdNs = 100000u;

// A zero-sized backing buffer cannot accept a flush; callers must not append to it.
constexpr bool RxPumpTerminalFlushCapacityReached(std::uint32_t count,
                                                 std::size_t capacity) noexcept {
  return capacity != 0u &&
         static_cast<std::size_t>(count) >=
             (capacity < kRxPumpTerminalFlushMaximum
                  ? capacity
                  : static_cast<std::size_t>(kRxPumpTerminalFlushMaximum));
}

enum class RxPumpTerminalFlushReason {
  kCapacity,
  kIdle,
  kNonmonotonic,
  kShutdown
};

struct RxPumpTerminalFlushSnapshot {
  RxPumpTerminalFlushReason reason = RxPumpTerminalFlushReason::kCapacity;
  std::uint32_t count = 0u;
  std::uint64_t first_sequence = 0u;
  std::uint64_t last_sequence = 0u;
  std::uint64_t received_packets = 0u;
  std::uint64_t start_cycles = 0u;
  std::uint64_t end_cycles = 0u;
  // Durations, not timestamps. The caller must clamp any subtraction on regression.
  std::uint64_t barrier_cycles = 0u;
  std::uint64_t sequence_audit_cycles = 0u;
  std::uint64_t ingress_audit_cycles = 0u;
};

// Single-writer diagnostic: read/serialize only after its pump has stopped.
// Record performs no allocation, I/O, clock reads, or synchronization.
class RxPumpTerminalFlushDiagnostics {
 public:
  using Snapshot = RxPumpTerminalFlushSnapshot;

  void Record(const Snapshot& snapshot, std::uint64_t tsc_hz) noexcept {
    const std::uint64_t duration = Duration(snapshot);
    if (calls_ == 0u) {
      first_ = snapshot;
      max_ = snapshot;
    } else if (duration > Duration(max_)) {
      max_ = snapshot;
    }
    ++calls_;
    if (snapshot.count > count_max_) count_max_ = snapshot.count;
    total_cycles_ += duration;
    barrier_cycles_ += snapshot.barrier_cycles;
    sequence_audit_cycles_ += snapshot.sequence_audit_cycles;
    ingress_audit_cycles_ += snapshot.ingress_audit_cycles;
    if (snapshot.end_cycles < snapshot.start_cycles) ++clock_regressions_;

    // 100 us = 1 / 10000 second. Round up without a potentially overflowing
    // cycles-to-nanoseconds multiplication. A missing frequency disables capture.
    const std::uint64_t threshold_cycles =
        tsc_hz / 10000u + (tsc_hz % 10000u != 0u ? 1u : 0u);
    if (tsc_hz != 0u && duration >= threshold_cycles) {
      ++long_flush_calls_;
      if (long_flush_snapshot_count_ < first_long_flushes_.size()) {
        first_long_flushes_[long_flush_snapshot_count_++] = snapshot;
      }
    }
  }

  std::uint64_t calls() const noexcept { return calls_; }
  std::uint32_t count_max() const noexcept { return count_max_; }
  std::uint64_t total_cycles() const noexcept { return total_cycles_; }
  std::uint64_t barrier_cycles() const noexcept { return barrier_cycles_; }
  std::uint64_t sequence_audit_cycles() const noexcept {
    return sequence_audit_cycles_;
  }
  std::uint64_t ingress_audit_cycles() const noexcept {
    return ingress_audit_cycles_;
  }
  std::uint64_t clock_regressions() const noexcept { return clock_regressions_; }
  std::uint64_t long_flush_calls() const noexcept { return long_flush_calls_; }
  std::size_t long_flush_snapshot_count() const noexcept {
    return long_flush_snapshot_count_;
  }
  // first/max are zero-valued until calls() != 0. The long array's valid prefix
  // has long_flush_snapshot_count() entries.
  const Snapshot& first_snapshot() const noexcept { return first_; }
  const Snapshot& max_snapshot() const noexcept { return max_; }
  const std::array<Snapshot, 3>& first_long_flushes() const noexcept {
    return first_long_flushes_;
  }

  void WriteJson(std::ostream& out) const {
    out << "{\"schema\":\"flowkeep.rx_pump_terminal_flush_diagnostics.v1\""
        << ",\"metadata_bytes\":" << sizeof(*this)
        << ",\"fixed_snapshot_capacity\":2"
        << ",\"long_flush_snapshot_capacity\":3"
        << ",\"total_snapshot_capacity\":5"
        << ",\"long_flush_threshold_ns\":"
        << kRxPumpTerminalLongFlushThresholdNs
        << ",\"flush_limit\":" << kRxPumpTerminalFlushMaximum
        << ",\"calls\":" << calls_
        << ",\"count_max\":" << count_max_
        << ",\"total_cycles\":" << total_cycles_
        << ",\"barrier_cycles\":" << barrier_cycles_
        << ",\"sequence_audit_cycles\":" << sequence_audit_cycles_
        << ",\"ingress_audit_cycles\":" << ingress_audit_cycles_
        << ",\"clock_regressions\":" << clock_regressions_
        << ",\"long_flush_calls\":" << long_flush_calls_
        << ",\"first\":";
    if (calls_ == 0u) out << "null";
    else WriteSnapshot(out, first_);
    out << ",\"max\":";
    if (calls_ == 0u) out << "null";
    else WriteSnapshot(out, max_);
    out << ",\"long_flushes\":[";
    for (std::size_t i = 0u; i < long_flush_snapshot_count_; ++i) {
      if (i != 0u) out << ',';
      WriteSnapshot(out, first_long_flushes_[i]);
    }
    out << "]}";
  }

 private:
  static std::uint64_t Duration(const Snapshot& snapshot) noexcept {
    return snapshot.end_cycles >= snapshot.start_cycles
               ? snapshot.end_cycles - snapshot.start_cycles
               : 0u;
  }

  static const char* ReasonName(RxPumpTerminalFlushReason reason) noexcept {
    switch (reason) {
      case RxPumpTerminalFlushReason::kCapacity: return "capacity";
      case RxPumpTerminalFlushReason::kIdle: return "idle";
      case RxPumpTerminalFlushReason::kNonmonotonic: return "nonmonotonic";
      case RxPumpTerminalFlushReason::kShutdown: return "shutdown";
    }
    return "unknown";
  }

  static void WriteSnapshot(std::ostream& out, const Snapshot& snapshot) {
    out << "{\"reason\":\"" << ReasonName(snapshot.reason) << '"'
        << ",\"count\":" << snapshot.count
        << ",\"first_sequence\":" << snapshot.first_sequence
        << ",\"last_sequence\":" << snapshot.last_sequence
        << ",\"received_packets\":" << snapshot.received_packets
        << ",\"start_cycles\":" << snapshot.start_cycles
        << ",\"end_cycles\":" << snapshot.end_cycles
        << ",\"total_cycles\":" << Duration(snapshot)
        << ",\"barrier_cycles\":" << snapshot.barrier_cycles
        << ",\"sequence_audit_cycles\":" << snapshot.sequence_audit_cycles
        << ",\"ingress_audit_cycles\":" << snapshot.ingress_audit_cycles << '}';
  }

  Snapshot first_{};
  Snapshot max_{};
  std::array<Snapshot, 3> first_long_flushes_{};
  std::uint64_t calls_ = 0u;
  std::uint64_t total_cycles_ = 0u;
  std::uint64_t barrier_cycles_ = 0u;
  std::uint64_t sequence_audit_cycles_ = 0u;
  std::uint64_t ingress_audit_cycles_ = 0u;
  std::uint64_t clock_regressions_ = 0u;
  std::uint64_t long_flush_calls_ = 0u;
  std::size_t long_flush_snapshot_count_ = 0u;
  std::uint32_t count_max_ = 0u;
};

}  // namespace flowkeep

#endif  // FLOWKEEP_FK_RX_PUMP_TERMINAL_FLUSH_DIAGNOSTICS_H_
