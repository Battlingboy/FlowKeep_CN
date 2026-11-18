#ifndef FLOWKEEP_FK_RX_PUMP_PHASE_DIAGNOSTICS_H_
#define FLOWKEEP_FK_RX_PUMP_PHASE_DIAGNOSTICS_H_

#include <array>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <ostream>

namespace flowkeep {

// One nonempty round is one burst in the supported single-queue/pump mode.
// All state is pump-local, normally aligned, and serialized only after join.
struct RxPumpPhaseSnapshot {
  std::uint64_t round_id = 0, burst_id = 0, queue_id = 0;
  std::uint64_t packets = 0, requested = 0, terminal_packets = 0;
  std::uint64_t published_packets = 0, dropped_packets = 0, owner_groups = 0;
  std::uint64_t valid_sequences = 0, first_sequence = 0, last_sequence = 0;
  std::uint64_t received_total = 0, ingress_monotonic_ns = 0;
  std::uint64_t start_cycles = 0, end_cycles = 0;
  std::uint64_t terminal_flush_calls = 0, terminal_flush_cycles = 0;
  std::uint64_t invalid_reasons = 0, additional_tsc_reads = 0;
  std::array<std::uint64_t, 8> phase_cycles{};
};

class RxPumpPhaseDiagnostics {
 public:
  using Snapshot = RxPumpPhaseSnapshot;
  enum : std::uint64_t {
    kClockRegression = 1, kCounterRegression = 2, kBadMetadata = 4,
    kOverflow = 8, kBadPhaseOrder = 16, kMissingPhase = 32,
    kNonconserving = 64
  };

  void Initialize(std::uint64_t hz, bool supported_scope) noexcept {
    // Initialization is outside the polling loop; discard old-frequency data.
    *this = RxPumpPhaseDiagnostics{};
    tsc_hz_ = hz;
    state_ = supported_scope && hz != 0 ? 1u : 0u;
  }
  bool supported() const noexcept { return (state_ & 1u) != 0; }

  // No clock reads in this class. The caller conditionally samples only after
  // a nonempty burst, and reuses the pre-existing round start/end timestamps.
  void Begin(std::uint64_t round_id, std::uint64_t burst_id,
             std::uint64_t queue_id, std::uint64_t packets,
             std::uint64_t requested, std::uint64_t received_total,
             std::uint64_t start, std::uint64_t post_pmd,
             std::uint64_t flush_calls, std::uint64_t flush_cycles) noexcept {
    if (!supported()) return;
    if (Active()) InvalidateAggregate();
    current_ = Snapshot{};
    state_ = 3u;
    current_.round_id = round_id;
    current_.burst_id = burst_id;
    current_.queue_id = queue_id;
    current_.packets = packets;
    current_.requested = requested;
    current_.received_total = received_total;
    current_.start_cycles = current_.end_cycles = start;
    // Baselines are replaced by deltas at Finish.
    current_.terminal_flush_calls = flush_calls;
    current_.terminal_flush_cycles = flush_cycles;
    if (round_id == 0 || burst_id == 0 || packets == 0 ||
        packets > requested || received_total < packets)
      current_.invalid_reasons |= kBadMetadata;
    MarkInternal(0u, post_pmd, true);
  }

  void Mark(std::size_t phase, std::uint64_t cycles) noexcept {
    if (!supported()) return;
    if (!Active()) { InvalidateAggregate(); return; }
    if (phase == 0u || phase >= 7u) {
      current_.invalid_reasons |= kBadPhaseOrder;
      return;
    }
    MarkInternal(phase, cycles, true);
  }
  void ObserveSequence(std::uint64_t sequence) noexcept {
    if (!Active() || sequence == std::numeric_limits<std::uint64_t>::max())
      return;
    if (current_.valid_sequences == 0u) current_.first_sequence = sequence;
    current_.last_sequence = sequence;
    AddCurrent(current_.valid_sequences, 1u);
  }
  void SetIngressTimestamp(std::uint64_t ns) noexcept {
    if (Active()) current_.ingress_monotonic_ns = ns;
  }
  void SetTerminalPackets(std::uint64_t packets) noexcept {
    if (Active()) current_.terminal_packets = packets;
  }
  void RecordPublish(std::uint64_t enqueued, std::uint64_t dropped) noexcept {
    if (!Active()) return;
    AddCurrent(current_.owner_groups, 1u);
    AddCurrent(current_.published_packets, enqueued);
    AddCurrent(current_.dropped_packets, dropped);
  }

  void Finish(std::uint64_t end, std::uint64_t flush_calls,
              std::uint64_t flush_cycles) noexcept {
    if (!supported()) return;
    if (!Active()) { InvalidateAggregate(); return; }
    MarkInternal(7u, end, false);
    current_.terminal_flush_calls = Delta(flush_calls,
        current_.terminal_flush_calls, kCounterRegression);
    current_.terminal_flush_cycles = Delta(flush_cycles,
        current_.terminal_flush_cycles, kCounterRegression);
    const std::uint64_t expected = current_.terminal_packets == 0u
                                      ? 0xc7u : 0xffu;
    if ((state_ >> 8u) != expected)
      current_.invalid_reasons |= kMissingPhase;
    if (current_.terminal_packets > current_.packets ||
        current_.published_packets > current_.packets ||
        current_.dropped_packets > current_.packets ||
        current_.valid_sequences > current_.packets ||
        current_.terminal_flush_cycles > current_.phase_cycles[3])
      current_.invalid_reasons |= kBadMetadata;
    std::uint64_t accounted = current_.terminal_packets;
    AddCurrent(accounted, current_.published_packets);
    AddCurrent(accounted, current_.dropped_packets);
    if (accounted > current_.packets)
      current_.invalid_reasons |= kBadMetadata;
    std::uint64_t total = 0u;
    for (const auto cycles : current_.phase_cycles) AddCurrent(total, cycles);
    if (end < current_.start_cycles || total != Duration(current_))
      current_.invalid_reasons |= kNonconserving;
    if (events_ == 0u) first_ = max_ = current_;
    else if (Duration(current_) > Duration(max_)) max_ = current_;
    if (current_.invalid_reasons != 0u) InvalidateAggregate();
    AddAggregate(events_, 1u);
    AddAggregate(additional_tsc_reads_, current_.additional_tsc_reads);
    if (current_.packets > max_packets_) max_packets_ = current_.packets;
    for (std::size_t i = 0; i < current_.phase_cycles.size(); ++i) {
      AddAggregate(phase_sum_[i], current_.phase_cycles[i]);
      if (current_.phase_cycles[i] > phase_max_[i]) {
        phase_max_[i] = current_.phase_cycles[i];
        phase_max_round_[i] = current_.round_id;
        phase_max_burst_[i] = current_.burst_id;
      }
    }
    const std::uint64_t threshold = tsc_hz_ / 10000u +
                                    (tsc_hz_ % 10000u != 0u ? 1u : 0u);
    if (Duration(current_) >= threshold) {
      AddAggregate(long_events_, 1u);
      if (long_saved_ < first_long_.size()) first_long_[long_saved_++] = current_;
    }
    state_ = 1u;
  }

  std::uint64_t events() const noexcept { return events_; }
  std::uint64_t invalid_observations() const noexcept { return invalid_; }
  std::uint64_t long_events() const noexcept { return long_events_; }
  std::uint64_t long_saved() const noexcept { return long_saved_; }
  const Snapshot& first_snapshot() const noexcept { return first_; }
  const Snapshot& max_snapshot() const noexcept { return max_; }
  const std::array<Snapshot, 3>& first_long_snapshots() const noexcept {
    return first_long_;
  }
  static std::uint64_t Duration(const Snapshot& s) noexcept {
    return s.end_cycles >= s.start_cycles ? s.end_cycles - s.start_cycles : 0u;
  }

  void WriteJson(std::ostream& out) const {
    out << "{\"schema\":\"flowkeep.rx_pump_phase_diagnostics.v1\""
        << ",\"scope\":\"single_queue_per_pump_non_rx_only_non_ordered_slots\""
        << ",\"supported\":" << (supported() ? "true" : "false")
        << ",\"valid\":" << (supported() && events_ != 0u && invalid_ == 0u &&
                                 !Active() ? "true" : "false")
        << ",\"unsupported_reason\":";
    if (supported()) out << "null";
    else out << '"' << (tsc_hz_ == 0u ? "missing_tsc_frequency" :
                          "unsupported_rx_pump_mapping_or_mode") << '"';
    out << ",\"tsc_hz\":" << tsc_hz_
        << ",\"metadata_bytes\":" << sizeof(*this)
        << ",\"snapshot_bytes\":" << sizeof(Snapshot)
        << ",\"retained_snapshot_capacity\":5,\"working_snapshot_capacity\":1"
        << ",\"long_threshold_ns\":100000,\"additional_empty_loop_tsc_reads\":0"
        << ",\"additional_nonempty_tsc_reads_max\":7"
        << ",\"additional_tsc_reads\":" << additional_tsc_reads_
        << ",\"events\":" << events_ << ",\"invalid_observations\":" << invalid_
        << ",\"max_packets\":" << max_packets_
        << ",\"long_events\":" << long_events_
        << ",\"round_setup_plus_pmd_is_coarse\":true"
        << ",\"terminal_flush_cycles_nested_in_phase_3\":true"
        << ",\"phase_sum_cycles\":";
    WriteArray(out, phase_sum_);
    out << ",\"phase_max_cycles\":"; WriteArray(out, phase_max_);
    out << ",\"phase_max_round_id\":"; WriteArray(out, phase_max_round_);
    out << ",\"phase_max_burst_id\":"; WriteArray(out, phase_max_burst_);
    out << ",\"phase_names\":[\"round_setup_plus_pmd\",\"ingress_setup\","
           "\"classify\",\"terminal_gather_flush\",\"terminal_recycle\","
           "\"terminal_counters\",\"publish_settle_notify\","
           "\"burst_counters_and_round_tail\"],\"first\":";
    if (events_ == 0u) out << "null"; else WriteSnapshot(out, first_);
    out << ",\"max\":";
    if (events_ == 0u) out << "null"; else WriteSnapshot(out, max_);
    out << ",\"first_long\":[";
    for (std::size_t i = 0; i < long_saved_; ++i) {
      if (i != 0u) out << ',';
      WriteSnapshot(out, first_long_[i]);
    }
    out << "]}";
  }

 private:
  bool Active() const noexcept { return (state_ & 2u) != 0u; }
  static bool Add(std::uint64_t& target, std::uint64_t value) noexcept {
    if (value > std::numeric_limits<std::uint64_t>::max() - target) {
      target = std::numeric_limits<std::uint64_t>::max();
      return false;
    }
    target += value;
    return true;
  }
  void InvalidateAggregate() noexcept {
    if (invalid_ != std::numeric_limits<std::uint64_t>::max()) ++invalid_;
  }
  void AddAggregate(std::uint64_t& target, std::uint64_t value) noexcept {
    if (!Add(target, value)) InvalidateAggregate();
  }
  void AddCurrent(std::uint64_t& target, std::uint64_t value) noexcept {
    if (!Add(target, value)) current_.invalid_reasons |= kOverflow;
  }
  std::uint64_t Delta(std::uint64_t end, std::uint64_t start,
                      std::uint64_t reason) noexcept {
    if (end < start) { current_.invalid_reasons |= reason; return 0u; }
    return end - start;
  }
  void MarkInternal(std::size_t phase, std::uint64_t cycles,
                    bool new_sample) noexcept {
    const std::uint64_t mask = state_ >> 8u;
    const std::uint64_t bit = std::uint64_t{1} << phase;
    if (mask >= bit) current_.invalid_reasons |= kBadPhaseOrder;
    state_ |= bit << 8u;
    AddCurrent(current_.phase_cycles[phase],
               Delta(cycles, current_.end_cycles, kClockRegression));
    current_.end_cycles = cycles;
    if (new_sample) AddCurrent(current_.additional_tsc_reads, 1u);
  }
  static void WriteArray(std::ostream& out,
                         const std::array<std::uint64_t, 8>& values) {
    out << '[';
    for (std::size_t i = 0; i < values.size(); ++i) {
      if (i != 0u) out << ',';
      out << values[i];
    }
    out << ']';
  }
  void WriteSnapshot(std::ostream& out, const Snapshot& s) const {
    out << "{\"valid\":" << (s.invalid_reasons == 0u ? "true" : "false")
        << ",\"invalid_reasons\":" << s.invalid_reasons
        << ",\"round_id\":" << s.round_id << ",\"burst_id\":" << s.burst_id
        << ",\"queue_id\":" << s.queue_id << ",\"packets\":" << s.packets
        << ",\"requested\":" << s.requested
        << ",\"terminal_packets\":" << s.terminal_packets
        << ",\"published_packets\":" << s.published_packets
        << ",\"dropped_packets\":" << s.dropped_packets
        << ",\"owner_groups\":" << s.owner_groups
        << ",\"valid_sequences\":" << s.valid_sequences
        << ",\"first_sequence\":";
    if (s.valid_sequences == 0u) out << "null"; else out << s.first_sequence;
    out << ",\"last_sequence\":";
    if (s.valid_sequences == 0u) out << "null"; else out << s.last_sequence;
    out << ",\"received_total\":" << s.received_total
        << ",\"ingress_monotonic_ns\":" << s.ingress_monotonic_ns
        << ",\"start_cycles\":" << s.start_cycles
        << ",\"end_cycles\":" << s.end_cycles
        << ",\"total_cycles\":" << Duration(s) << ",\"total_ns\":";
    if (tsc_hz_ == 0u || s.invalid_reasons != 0u) out << "null";
    else out << static_cast<long double>(Duration(s)) * 1000000000.0L / tsc_hz_;
    out << ",\"terminal_flush_calls\":" << s.terminal_flush_calls
        << ",\"terminal_flush_cycles\":" << s.terminal_flush_cycles
        << ",\"additional_tsc_reads\":" << s.additional_tsc_reads
        << ",\"phase_cycles\":";
    WriteArray(out, s.phase_cycles);
    out << '}';
  }

  Snapshot current_{}, first_{}, max_{};
  std::array<Snapshot, 3> first_long_{};
  std::array<std::uint64_t, 8> phase_sum_{}, phase_max_{};
  std::array<std::uint64_t, 8> phase_max_round_{}, phase_max_burst_{};
  std::uint64_t tsc_hz_ = 0, state_ = 0, events_ = 0, long_events_ = 0;
  std::uint64_t long_saved_ = 0, invalid_ = 0, additional_tsc_reads_ = 0;
  std::uint64_t max_packets_ = 0;
};

static_assert(sizeof(RxPumpPhaseSnapshot) == 224u, "fixed phase snapshot budget");
static_assert(sizeof(RxPumpPhaseDiagnostics) == 1664u, "fixed phase pump budget");
static_assert(alignof(RxPumpPhaseDiagnostics) <= alignof(std::max_align_t),
              "C++14 nothrow array-new requires ordinary alignment");

}  // namespace flowkeep
#endif  // FLOWKEEP_FK_RX_PUMP_PHASE_DIAGNOSTICS_H_
