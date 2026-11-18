#include "fk_native_fusion_service.h"
#include "fk_batch_age_guard.h"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <limits>
#include <map>
#include <mutex>
#include <condition_variable>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#include <pthread.h>
#include <sched.h>
#include <time.h>

#define CHECK(condition) do {                                             \
    if (!(condition)) {                                                   \
        std::fprintf(stderr, "CHECK failed at %s:%d: %s\n",            \
            __FILE__, __LINE__, #condition);                              \
        return false;                                                     \
    }                                                                     \
} while (false)

namespace {

bool test_thread_phase_clock_distinguishes_sleep_and_cpu() {
    const auto a=flowkeep::ReadThreadPhaseStamp();
    std::this_thread::sleep_for(std::chrono::milliseconds(20));
    const auto b=flowkeep::ReadThreadPhaseStamp();
    const auto slept=flowkeep::ThreadPhaseBetween(a,b);
    CHECK(slept.valid);CHECK(slept.off_cpu_ns>=10000000u);
    CHECK(slept.voluntary_switches>0);
    volatile uint64_t sum=0;
    for(uint64_t i=0;i<1000000u;++i)sum+=i;
    const auto busy=flowkeep::ThreadPhaseBetween(b,flowkeep::ReadThreadPhaseStamp());
    CHECK(busy.valid);CHECK(busy.cpu_ns>0);CHECK(sum>0);
    CHECK(!flowkeep::ThreadPhaseBetween(b,a).valid);
    CHECK(!flowkeep::ThreadPhaseBetween({},b).valid);
    return true;
}

bool test_batch_age_guard_saturates_without_resetting_old_work() {
    using flowkeep::BatchAgeRemainingNs;
    CHECK(BatchAgeRemainingNs(100, 100, 20) == 20);
    CHECK(BatchAgeRemainingNs(100, 112, 20) == 8);
    CHECK(BatchAgeRemainingNs(100, 120, 20) == 0);
    CHECK(BatchAgeRemainingNs(100, 400, 20) == 0);
    CHECK(BatchAgeRemainingNs(100, 100, 0) == 0);
    CHECK(BatchAgeRemainingNs(0, 100, 20) == 0);
    CHECK(BatchAgeRemainingNs(100, 0, 20) == 0);
    CHECK(BatchAgeRemainingNs(100, 99, 20) == 0);
    CHECK(BatchAgeRemainingNs(UINT64_MAX - 10, UINT64_MAX, 20) == 10);
    CHECK(BatchAgeRemainingNs(1, UINT64_MAX, UINT64_MAX) == 1);
    using flowkeep::OverdueBatchRecoveryNs;
    CHECK(OverdueBatchRecoveryNs(100, 195, 200, 101, 20) == 0);
    CHECK(OverdueBatchRecoveryNs(100, 195, 200, 100, 20) == 15);
    CHECK(OverdueBatchRecoveryNs(100, 195, 220, 100, 20) == 0);
    CHECK(OverdueBatchRecoveryNs(1, 2000000, 2000000, 10, 5000000) == 1000000);
    CHECK(OverdueBatchRecoveryNs(1, 2000000, 2500000, 10, 5000000) == 500000);
    CHECK(OverdueBatchRecoveryNs(1, 2000000, 3000000, 10, 5000000) == 0);
    CHECK(OverdueBatchRecoveryNs(0, 100, 200, 10, 20) == 0);
    // An old queued row gets a recovery window only once its batch activates;
    // an identical original physical age still counts as a missed deadline.
    CHECK(OverdueBatchRecoveryNs(1, 4000000, 4000000, 10, 5000000) == 1000000);
    CHECK(OverdueBatchRecoveryNs(1, 4000000, 5000000, 10, 5000000) == 0);
    return true;
}

uint64_t now_ns() {
    timespec value{};
    if (::clock_gettime(CLOCK_MONOTONIC, &value) != 0)
        return 0u;
    return static_cast<uint64_t>(value.tv_sec) * UINT64_C(1000000000) +
        static_cast<uint64_t>(value.tv_nsec);
}

fk_detector_request_v1 request_for(uint64_t sequence, uint16_t flow_port) {
    fk_detector_request_v1 request{};
    if (!fk_detector_request_v1_prepare(&request))
        std::abort();
    request.canonical_key.ip_version = 4u;
    request.canonical_key.protocol = 6u;
    request.canonical_key.low_addr[0] = 10u;
    request.canonical_key.low_addr[3] = 1u;
    request.canonical_key.high_addr[0] = 10u;
    request.canonical_key.high_addr[3] = 2u;
    request.canonical_key.low_port = flow_port;
    request.canonical_key.high_port = 443u;
    request.flow_index = static_cast<uint32_t>(sequence - 1u);
    request.flow_generation = static_cast<uint32_t>(sequence);
    request.checkpoint_packet = static_cast<uint32_t>(sequence + 4u);
    request.source_mask = static_cast<uint8_t>(sequence & 7u);
    request.semantic_timestamp_ns = sequence;
    request.flow_first_timestamp_ns = 1u;
    request.physical_timestamp_ns = now_ns();
    request.event_routing_token = sequence;
    for (size_t index = 0u;
         index < FK_DETECTOR_REQUEST_FEATURE_COUNT; ++index) {
        request.features[index] = static_cast<float>(sequence + index);
    }
    return request;
}

fk_detector_request_v1 flow_open_for(
        uint64_t sequence,
        uint16_t flow_port,
        uint32_t flow_index,
        uint32_t flow_generation) {
    fk_detector_request_v1 request = request_for(sequence, flow_port);
    request.flow_index = flow_index;
    request.flow_generation = flow_generation;
    request.checkpoint_packet = 0u;
    request.source_mask = 0u;
    request.flags = FK_DETECTOR_REQUEST_FLAG_FLOW_OPEN;
    request.flow_first_timestamp_ns = request.semantic_timestamp_ns;
    std::memset(request.features, 0, sizeof(request.features));
    return request;
}

fk_detector_request_v1 checkpoint_for(
        uint64_t sequence,
        uint16_t flow_port,
        uint32_t flow_index,
        uint32_t flow_generation,
        uint32_t checkpoint_packet,
        uint64_t flow_first_timestamp_ns) {
    fk_detector_request_v1 request = request_for(sequence, flow_port);
    request.flow_index = flow_index;
    request.flow_generation = flow_generation;
    request.checkpoint_packet = checkpoint_packet;
    request.flow_first_timestamp_ns = flow_first_timestamp_ns;
    return request;
}

fk_detector_request_v1 flow_continue_for(
        uint64_t sequence,
        uint16_t flow_port,
        uint32_t flow_index,
        uint32_t flow_generation,
        uint64_t flow_first_timestamp_ns,
        uint32_t predecessor_flow_index,
        uint32_t predecessor_flow_generation,
        uint32_t predecessor_checkpoint_packet) {
    fk_detector_request_v1 request = request_for(sequence, flow_port);
    request.flow_index = flow_index;
    request.flow_generation = flow_generation;
    request.flow_first_timestamp_ns = flow_first_timestamp_ns;
    request.checkpoint_packet = 0u;
    request.source_mask = 0u;
    request.flags = FK_DETECTOR_REQUEST_FLAG_FLOW_CONTINUE;
    request.predecessor_flow_index = predecessor_flow_index;
    request.predecessor_flow_generation = predecessor_flow_generation;
    request.predecessor_checkpoint_packet =
        predecessor_checkpoint_packet;
    std::memset(request.features, 0, sizeof(request.features));
    return request;
}

class FakeSource final : public flowkeep::NativeFusionRequestSource {
public:
    explicit FakeSource(std::vector<fk_detector_request_v1> requests)
        : requests_(std::move(requests)) {}

    flowkeep::NativeFusionSourceResult Peek(
            fk_detector_request_v1 *request,
            uint64_t *sequence,
            std::string *) noexcept override {
        if (faulted_ || next_ == fault_after_peeks_) {
            faulted_ = true;
            return flowkeep::NativeFusionSourceResult::Fault;
        }
        if(gate_next_until_ack && next_>acked_)return flowkeep::NativeFusionSourceResult::Empty;
        if (next_ != 0u && peek_gate_ != nullptr &&
                !peek_gate_->load(std::memory_order_acquire)) {
            return flowkeep::NativeFusionSourceResult::Empty;
        }
        if (next_ != 0u && peek_delay_after_first_ms_ != 0u) {
            std::this_thread::sleep_for(
                std::chrono::milliseconds(peek_delay_after_first_ms_));
        }
        if (next_ == requests_.size())
            return flowkeep::NativeFusionSourceResult::ProducerDone;
        *request = requests_[next_];
        *sequence = static_cast<uint64_t>(next_ + 1u);
        ++next_;
        peeked_count.store(next_, std::memory_order_release);
        return flowkeep::NativeFusionSourceResult::Item;
    }

    bool Ack(uint64_t sequence, std::string *) noexcept override {
        if (faulted_ || sequence <= acked_ || sequence > next_)
            return false;
        if (durable_prefix_ != nullptr &&
                durable_prefix_->load(std::memory_order_acquire) < sequence) {
            ack_before_durable_ = true;
            return false;
        }
        acked_ = sequence;
        ack_log.push_back(sequence);
        return true;
    }

    bool Snapshot(
            flowkeep::NativeFusionSourceSnapshot *snapshot,
            std::string *) const noexcept override {
        *snapshot = {};
        snapshot->capacity = capacity_;
        snapshot->write_sequence = requests_.size();
        snapshot->published = requests_.size();
        if ((transient_inconsistent_snapshots_ != 0u ||
                persistent_inconsistent_snapshot_) &&
                snapshot->published != 0u) {
            --snapshot->published;
            if (transient_inconsistent_snapshots_ != 0u)
                --transient_inconsistent_snapshots_;
        }
        snapshot->producer_done = 1u;
        snapshot->producer_stop_monotonic_ns = now_ns();
        snapshot->read_sequence = acked_;
        snapshot->records_peeked = next_;
        snapshot->records_acked = acked_;
        snapshot->consumer_open_count = 1u;
        snapshot->consumer_close_count = closed_ ? 1u : 0u;
        snapshot->consumer_claim_token = closed_ ? 0u : 1u;
        if (closed_ && next_ > acked_)
            snapshot->unacked_on_close = next_ - acked_;
        if (faulted_) {
            snapshot->producer_drops = 1u;
            snapshot->producer_overruns = 1u;
            snapshot->producer_fail_closed = 1u;
        }
        return true;
    }

    bool Close(std::string *) noexcept override {
        closed_ = true;
        return true;
    }

    void SetCapacity(uint64_t capacity) { capacity_ = capacity; }
    void Fault() { faulted_ = true; }
    void FaultAfterPeekCount(uint64_t count) { fault_after_peeks_ = count; }
    void InjectTransientInconsistentSnapshots(uint32_t count) {
        transient_inconsistent_snapshots_ = count;
    }
    void InjectPersistentInconsistentSnapshot() {
        persistent_inconsistent_snapshot_ = true;
    }
    void GateAfterFirstUntil(std::atomic<bool> *gate) {
        peek_gate_ = gate;
    }
    void DelayAfterFirstPeekMs(uint32_t delay_ms) {
        peek_delay_after_first_ms_ = delay_ms;
    }
    void RequireDurablePrefix(std::atomic<uint64_t> *prefix) {
        durable_prefix_ = prefix;
    }
    bool ack_before_durable() const { return ack_before_durable_; }
    bool InputFenceReached() const noexcept override { return input_fence && !faulted_; }

    std::vector<uint64_t> ack_log;
    bool input_fence=false,gate_next_until_ack=false;
    std::atomic<uint64_t> peeked_count{0u};

private:
    std::vector<fk_detector_request_v1> requests_;
    uint64_t capacity_ = 64u;
    uint64_t next_ = 0u;
    uint64_t acked_ = 0u;
    bool faulted_ = false;
    uint64_t fault_after_peeks_ = UINT64_MAX;
    bool closed_ = false;
    mutable uint32_t transient_inconsistent_snapshots_ = 0u;
    bool persistent_inconsistent_snapshot_ = false;
    std::atomic<bool> *peek_gate_ = nullptr;
    uint32_t peek_delay_after_first_ms_ = 0u;
    std::atomic<uint64_t> *durable_prefix_ = nullptr;
    bool ack_before_durable_ = false;
};

class MapRouter final : public flowkeep::NativeFusionEventRouter {
public:
    bool Resolve(
            const fk_detector_request_v1 &request,
            Route *route,
            std::string *error) noexcept override {
        ++resolve_calls;
        const auto found = routes.find(request.canonical_key.low_port);
        if (found == routes.end()) {
            if (error != nullptr)
                *error = "unknown frozen flow route";
            return false;
        }
        route->event_token = found->second;
        const auto name = event_names.find(found->second);
        if (name == event_names.end())
            return false;
        route->event_id = &name->second;
        return true;
    }
    std::map<uint16_t, uint64_t> routes;
    std::map<uint64_t, std::string> event_names;
    uint64_t resolve_calls = 0u;
};

class DeterministicScorer final : public flowkeep::NativeFusionBatchScorer {
public:
    bool WaitHistoryDurable(uint64_t sequence,std::string *error) noexcept override {
        history_fences.push_back(sequence);
        if(history_delay_ms)std::this_thread::sleep_for(std::chrono::milliseconds(history_delay_ms));
        history_finished_ns=now_ns();
        if(history_fail && error)*error="injected history durability failure";
        return !history_fail;
    }
    bool history_fail=false;
    uint32_t history_delay_ms=0;
    uint64_t history_finished_ns=0;
    std::vector<uint64_t> history_fences;
    bool ScoreBatch(
            const fk_native_fusion_request *requests,
            size_t count,
            fk_native_fusion_result *results,
            std::string *error) noexcept override {
        if (first_call_ns == 0u)
            first_call_ns = now_ns();
        if (delay_ms != 0u)
            std::this_thread::sleep_for(std::chrono::milliseconds(delay_ms));
        if (fail) {
            if (error != nullptr)
                *error = "injected scorer failure";
            return false;
        }
        std::vector<uint64_t> batch;
        for (size_t index = 0u; index < count; ++index) {
            batch.push_back(requests[index].sequence);
            seen_events.push_back(requests[index].event_token);
            results[index].sequence = requests[index].sequence;
            results[index].event_token = requests[index].event_token;
            results[index].score =
                static_cast<double>(requests[index].sequence) / 100.0;
        }
        batches.push_back(std::move(batch));
        return true;
    }

    uint32_t delay_ms = 0u;
    bool fail = false;
    uint64_t first_call_ns = 0u;
    std::vector<std::vector<uint64_t>> batches;
    std::vector<uint64_t> seen_events;
};

class DeterministicFlowOpenScorer final
        : public flowkeep::NativeFusionFlowOpenScorer {
public:
    bool ScoreFlowOpen(
            const fk_flow_key &key,
            double *score,
            std::string *) noexcept override {
        ++calls;
        *score = key.low_port == 1801u ? 0.97 : 0.03;
        return true;
    }
    uint64_t calls = 0u;
};

class MemoryCommitter final : public flowkeep::NativeFusionCommitter {
public:
    bool CommitConsecutive(
            const flowkeep::NativeFusionDecision *decisions,
            size_t count,
            flowkeep::NativeFusionCommitResult *result,
            std::string *error) noexcept override {
        if (fail) {
            if (error != nullptr)
                *error = "injected commit failure";
            return false;
        }
        if (first_commit_started_ns == 0u)
            first_commit_started_ns = now_ns();
        if (commit_started != nullptr)
            commit_started->store(true, std::memory_order_release);
        commit_sizes.push_back(count);
        if (delay_ms != 0u)
            std::this_thread::sleep_for(std::chrono::milliseconds(delay_ms));
        for (size_t index = 0u; index < count; ++index) {
            if (!sequences.empty() &&
                decisions[index].sequence != sequences.back() + 1u) {
                return false;
            }
            sequences.push_back(decisions[index].sequence);
            event_ids.push_back(decisions[index].event_token);
            decision_kinds.push_back(decisions[index].kind);
            score_present.push_back(decisions[index].score_present);
            scores.push_back(decisions[index].score);
            predecessor_indices.push_back(
                decisions[index].predecessor_flow_index);
            predecessor_generations.push_back(
                decisions[index].predecessor_flow_generation);
            predecessor_checkpoints.push_back(
                decisions[index].predecessor_checkpoint_packet);
            physical_times.push_back(
                decisions[index].physical_enqueue_monotonic_ns);
            decision_times.push_back(decisions[index].decision_monotonic_ns);
        }
        if (commit_calls == 0u && observed_peeks != nullptr) {
            peeked_before_first_return = observed_peeks->load(
                std::memory_order_acquire);
        }
        ++commit_calls;
        if (durable_prefix != nullptr) {
            durable_prefix->store(
                decisions[count - 1u].sequence, std::memory_order_release);
        }
        result->completed_monotonic_ns = now_ns();
        result->durability =
            flowkeep::NativeFusionDurability::TestOnlyMemory;
        if (fault_source_after_commit != nullptr)
            fault_source_after_commit->Fault();
        return true;
    }

    bool fail = false;
    uint32_t delay_ms = 0u;
    uint64_t commit_calls = 0u;
    uint64_t first_commit_started_ns = 0u;
    uint64_t peeked_before_first_return = 0u;
    std::atomic<bool> *commit_started = nullptr;
    std::atomic<uint64_t> *observed_peeks = nullptr;
    std::atomic<uint64_t> *durable_prefix = nullptr;
    FakeSource *fault_source_after_commit = nullptr;
    std::vector<uint64_t> sequences;
    std::vector<uint64_t> event_ids;
    std::vector<flowkeep::NativeFusionDecisionKind> decision_kinds;
    std::vector<uint8_t> score_present;
    std::vector<double> scores;
    std::vector<uint32_t> predecessor_indices;
    std::vector<uint32_t> predecessor_generations;
    std::vector<uint32_t> predecessor_checkpoints;
    std::vector<uint64_t> physical_times;
    std::vector<uint64_t> decision_times;
    std::vector<size_t> commit_sizes;
};

flowkeep::NativeFusionServiceConfig config_for(
        uint32_t workers, uint32_t batch, uint32_t inflight) {
    flowkeep::NativeFusionServiceConfig config{};
    config.worker_count = workers;
    config.batch_capacity = batch;
    config.max_inflight = inflight;
    config.worker_batch_wait_ns = UINT64_C(5000000);
    config.idle_poll_ns = 10000u;
    config.detector_deadline_ns = UINT64_C(1000000000);
    config.allow_test_only_durability = true;
    config.require_flow_open = false;
    return config;
}

bool test_flow_open_only_quic_events_receive_live_null_terminals() {
    std::vector<fk_detector_request_v1> requests;
    requests.push_back(flow_open_for(1u, 1801u, 10u, 1u));
    requests.push_back(flow_open_for(2u, 1802u, 11u, 1u));
    requests.push_back(flow_open_for(3u, 1803u, 12u, 1u));
    requests.push_back(checkpoint_for(4u, 1803u, 12u, 1u, 4u, 3u));
    FakeSource source(std::move(requests));
    MapRouter router;
    router.routes = {{1801u, 101u}, {1802u, 102u}, {1803u, 103u}};
    router.event_names = {
        {101u, "capture||short-one"},
        {102u, "capture||short-two"},
        {103u, "capture||checkpoint"},
    };
    DeterministicScorer scorer;
    std::vector<flowkeep::NativeFusionBatchScorer *> scorers = {&scorer};
    MemoryCommitter committer;
    flowkeep::NativeFusionServiceConfig config = config_for(1u, 4u, 4u);
    config.require_flow_open = true;
    flowkeep::NativeFusionServiceReceipt receipt{};
    std::string error;
    const bool succeeded = flowkeep::RunNativeFusionService(
        &source, &router, scorers, &committer, config, &receipt, &error);
    if (!succeeded)
        std::fprintf(stderr, "FLOW control service error: %s\n",
            error.c_str());
    CHECK(succeeded);
    CHECK(receipt.completed == 1u);
    CHECK(receipt.requests_peeked == 4u);
    CHECK(receipt.flow_open_records == 3u);
    CHECK(receipt.checkpoint_records == 1u);
    CHECK(receipt.requests_scored == 1u);
    CHECK(receipt.requests_persisted == 4u);
    CHECK(receipt.requests_acked == 4u);
    CHECK(receipt.flow_open_only_event_terminals == 2u);
    CHECK(receipt.flow_open_coverage_closed == 1u);
    CHECK(receipt.flow_state_capacity == 4u);
    CHECK(receipt.flow_state_capacity_failures == 0u);
    CHECK(receipt.flow_state_runtime_rehashes == 0u);
    CHECK(receipt.flow_state_capacity_closed == 1u);
    CHECK(receipt.flow_state_no_runtime_rehash == 1u);
    CHECK(receipt.stable_flow_routes_map.peak_entries == 3u);
    CHECK(receipt.flow_coverage_map.peak_entries == 3u);
    CHECK(receipt.active_semantic_generations_map.peak_entries == 3u);
    CHECK(receipt.event_coverage_map.peak_entries == 3u);
    CHECK(receipt.stable_flow_routes_map.post_reserve_bucket_count ==
        receipt.stable_flow_routes_map.terminal_bucket_count);
    CHECK(scorer.batches.size() == 1u);
    CHECK(scorer.batches[0] == std::vector<uint64_t>({4u}));
    CHECK(committer.sequences == std::vector<uint64_t>({1u, 2u, 3u, 4u}));
    CHECK(committer.decision_kinds.size() == 4u);
    CHECK(committer.decision_kinds[0] ==
        flowkeep::NativeFusionDecisionKind::FlowOpen);
    CHECK(committer.decision_kinds[1] ==
        flowkeep::NativeFusionDecisionKind::FlowOpen);
    CHECK(committer.decision_kinds[2] ==
        flowkeep::NativeFusionDecisionKind::FlowOpen);
    CHECK(committer.decision_kinds[3] ==
        flowkeep::NativeFusionDecisionKind::Checkpoint);
    CHECK(committer.score_present ==
        std::vector<uint8_t>({0u, 0u, 0u, 1u}));
    return true;
}

bool test_flow_open_head_scores_provisional_rows_without_checkpoint_work() {
    std::vector<fk_detector_request_v1> requests;
    requests.push_back(flow_open_for(1u, 1801u, 10u, 1u));
    requests.push_back(flow_open_for(2u, 1802u, 11u, 1u));
    requests.push_back(checkpoint_for(3u, 1802u, 11u, 1u, 4u, 2u));
    FakeSource source(std::move(requests));
    MapRouter router;
    router.routes = {{1801u, 101u}, {1802u, 102u}};
    router.event_names = {
        {101u, "capture||short"},
        {102u, "capture||checkpoint"},
    };
    DeterministicScorer checkpoint_scorer;
    DeterministicFlowOpenScorer flow_open_scorer;
    MemoryCommitter committer;
    flowkeep::NativeFusionServiceConfig config = config_for(1u, 3u, 3u);
    config.require_flow_open = true;
    config.flow_open_scorer = &flow_open_scorer;
    config.flow_open_threshold = 0.9;
    flowkeep::NativeFusionServiceReceipt receipt{};
    std::string error;
    CHECK(flowkeep::RunNativeFusionService(
        &source, &router, {&checkpoint_scorer}, &committer,
        config, &receipt, &error));
    CHECK(flow_open_scorer.calls == 2u);
    CHECK(receipt.flow_open_records == 2u);
    CHECK(receipt.flow_open_records_scored == 2u);
    CHECK(receipt.checkpoint_records == 1u);
    CHECK(receipt.requests_scored == 1u);
    CHECK(committer.score_present == std::vector<uint8_t>({1u, 1u, 1u}));
    CHECK(committer.scores.size() == 3u);
    CHECK(committer.scores[0] == 0.97);
    CHECK(committer.scores[1] == 0.03);
    CHECK(committer.scores[2] == 0.03);
    return true;
}

bool test_run_wide_flow_state_capacity_fails_closed_without_rehash() {
    std::vector<fk_detector_request_v1> requests;
    requests.push_back(flow_open_for(1u, 1821u, 10u, 1u));
    requests.push_back(flow_open_for(2u, 1822u, 11u, 1u));
    requests.push_back(flow_open_for(3u, 1823u, 12u, 1u));
    FakeSource source(std::move(requests));
    MapRouter router;
    router.routes = {{1821u, 121u}, {1822u, 122u}, {1823u, 123u}};
    router.event_names = {
        {121u, "capacity-one"},
        {122u, "capacity-two"},
        {123u, "capacity-three"},
    };
    DeterministicScorer scorer;
    std::vector<flowkeep::NativeFusionBatchScorer *> scorers = {&scorer};
    MemoryCommitter committer;
    flowkeep::NativeFusionServiceConfig config = config_for(1u, 1u, 1u);
    config.flow_state_capacity = 2u;
    config.require_flow_open = true;
    flowkeep::NativeFusionServiceReceipt receipt{};
    std::string error;
    CHECK(!flowkeep::RunNativeFusionService(
        &source, &router, scorers, &committer, config, &receipt, &error));
    CHECK(error ==
        "stable_flow_routes exceeded configured run-wide flow-state capacity");
    CHECK(receipt.flow_state_capacity == 2u);
    CHECK(receipt.flow_state_capacity_failures == 1u);
    CHECK(receipt.flow_state_runtime_rehashes == 0u);
    CHECK(receipt.flow_state_capacity_closed == 0u);
    CHECK(receipt.flow_state_no_runtime_rehash == 1u);
    CHECK(receipt.stable_flow_routes_map.peak_entries == 2u);
    CHECK(receipt.stable_flow_routes_map.post_reserve_bucket_count ==
        receipt.stable_flow_routes_map.terminal_bucket_count);
    return true;
}

bool test_explicit_flow_continue_authorizes_one_successor_generation() {
    std::vector<fk_detector_request_v1> requests;
    requests.push_back(flow_open_for(1u, 1811u, 10u, 1u));
    requests.push_back(checkpoint_for(2u, 1811u, 10u, 1u, 4u, 1u));
    requests.push_back(flow_continue_for(
        3u, 1811u, 11u, 2u, 1u, 10u, 1u, 4u));
    requests.push_back(checkpoint_for(4u, 1811u, 11u, 2u, 8u, 1u));
    FakeSource source(std::move(requests));
    MapRouter router;
    router.routes = {{1811u, 111u}};
    router.event_names = {{111u, "event-continuation"}};
    DeterministicScorer scorer;
    std::vector<flowkeep::NativeFusionBatchScorer *> scorers = {&scorer};
    MemoryCommitter committer;
    flowkeep::NativeFusionServiceConfig config = config_for(1u, 4u, 4u);
    config.require_flow_open = true;
    flowkeep::NativeFusionServiceReceipt receipt{};
    std::string error;
    const bool succeeded = flowkeep::RunNativeFusionService(
        &source, &router, scorers, &committer, config, &receipt, &error);
    if (!succeeded)
        std::fprintf(stderr, "FLOW_CONTINUE service error: %s\n",
            error.c_str());
    CHECK(succeeded);
    CHECK(receipt.flow_open_records == 1u);
    CHECK(receipt.flow_continue_records == 1u);
    CHECK(receipt.capacity_continuation_rebindings == 1u);
    CHECK(receipt.superseded_generation_retirements == 1u);
    CHECK(receipt.flow_coverage_map.peak_entries == 1u);
    CHECK(receipt.flow_coverage_map.terminal_entries == 1u);
    CHECK(receipt.checkpoint_records == 2u);
    CHECK(receipt.requests_scored == 2u);
    CHECK(receipt.route_failures == 0u);
    CHECK(receipt.flow_open_coverage_closed == 1u);
    CHECK(committer.decision_kinds ==
        std::vector<flowkeep::NativeFusionDecisionKind>({
            flowkeep::NativeFusionDecisionKind::FlowOpen,
            flowkeep::NativeFusionDecisionKind::Checkpoint,
            flowkeep::NativeFusionDecisionKind::FlowContinue,
            flowkeep::NativeFusionDecisionKind::Checkpoint,
        }));
    CHECK(committer.predecessor_indices[2] == 10u);
    CHECK(committer.predecessor_generations[2] == 1u);
    CHECK(committer.predecessor_checkpoints[2] == 4u);
    return true;
}

bool test_many_continuations_reuse_active_generation_capacity() {
    std::vector<fk_detector_request_v1> requests;
    requests.push_back(flow_open_for(1u, 1817u, 70u, 1u));
    requests.push_back(checkpoint_for(2u, 1817u, 70u, 1u, 4u, 1u));
    uint32_t predecessor_index = 70u;
    uint32_t predecessor_generation = 1u;
    uint32_t predecessor_checkpoint = 4u;
    uint64_t sequence = 3u;
    constexpr uint32_t kContinuationCount = 12u;
    for (uint32_t offset = 0u; offset < kContinuationCount; ++offset) {
        const uint32_t successor_index = 71u + offset;
        const uint32_t successor_generation = 2u + offset;
        requests.push_back(flow_continue_for(
            sequence++, 1817u, successor_index, successor_generation, 1u,
            predecessor_index, predecessor_generation,
            predecessor_checkpoint));
        predecessor_checkpoint += 4u;
        requests.push_back(checkpoint_for(
            sequence++, 1817u, successor_index, successor_generation,
            predecessor_checkpoint, 1u));
        predecessor_index = successor_index;
        predecessor_generation = successor_generation;
    }
    FakeSource source(std::move(requests));
    MapRouter router;
    router.routes = {{1817u, 117u}};
    router.event_names = {{117u, "event-many-continuations"}};
    DeterministicScorer scorer;
    std::vector<flowkeep::NativeFusionBatchScorer *> scorers = {&scorer};
    MemoryCommitter committer;
    flowkeep::NativeFusionServiceConfig config = config_for(1u, 4u, 4u);
    config.flow_state_capacity = 4u;
    config.require_flow_open = true;
    flowkeep::NativeFusionServiceReceipt receipt{};
    std::string error;
    const bool succeeded = flowkeep::RunNativeFusionService(
        &source, &router, scorers, &committer, config, &receipt, &error);
    if (!succeeded)
        std::fprintf(stderr, "many FLOW_CONTINUE service error: %s\n",
            error.c_str());
    CHECK(succeeded);
    CHECK(receipt.flow_open_records == 1u);
    CHECK(receipt.flow_continue_records == kContinuationCount);
    CHECK(receipt.capacity_continuation_rebindings == kContinuationCount);
    CHECK(receipt.superseded_generation_retirements ==
        kContinuationCount);
    CHECK(receipt.flow_coverage_map.peak_entries == 1u);
    CHECK(receipt.flow_coverage_map.terminal_entries == 1u);
    CHECK(receipt.active_semantic_generations_map.peak_entries == 1u);
    CHECK(receipt.flow_state_capacity_failures == 0u);
    CHECK(receipt.flow_state_runtime_rehashes == 0u);
    CHECK(receipt.flow_open_coverage_closed == 1u);
    return true;
}

bool test_checkpoint_cannot_infer_a_missing_flow_continue() {
    std::vector<fk_detector_request_v1> requests;
    requests.push_back(flow_open_for(1u, 1812u, 20u, 1u));
    requests.push_back(checkpoint_for(2u, 1812u, 21u, 2u, 8u, 1u));
    FakeSource source(std::move(requests));
    MapRouter router;
    router.routes = {{1812u, 112u}};
    router.event_names = {{112u, "event-missing-continuation"}};
    DeterministicScorer scorer;
    std::vector<flowkeep::NativeFusionBatchScorer *> scorers = {&scorer};
    MemoryCommitter committer;
    flowkeep::NativeFusionServiceConfig config = config_for(1u, 2u, 2u);
    config.require_flow_open = true;
    flowkeep::NativeFusionServiceReceipt receipt{};
    std::string error;
    CHECK(!flowkeep::RunNativeFusionService(&source, &router, scorers,
        &committer, config, &receipt, &error));
    CHECK(receipt.route_failures == 1u);
    CHECK(receipt.requests_peeked == 2u);
    CHECK(receipt.requests_acked == 0u);
    CHECK(receipt.requests_unacked_replayable == 2u);
    return true;
}

bool test_flow_continue_inherits_checkpoint_cursor() {
    std::vector<fk_detector_request_v1> requests;
    requests.push_back(flow_open_for(1u, 1813u, 30u, 1u));
    requests.push_back(checkpoint_for(2u, 1813u, 30u, 1u, 12u, 1u));
    requests.push_back(flow_continue_for(
        3u, 1813u, 31u, 2u, 1u, 30u, 1u, 12u));
    requests.push_back(checkpoint_for(4u, 1813u, 31u, 2u, 8u, 1u));
    FakeSource source(std::move(requests));
    MapRouter router;
    router.routes = {{1813u, 113u}};
    router.event_names = {{113u, "event-regressed-continuation-cursor"}};
    DeterministicScorer scorer;
    std::vector<flowkeep::NativeFusionBatchScorer *> scorers = {&scorer};
    MemoryCommitter committer;
    flowkeep::NativeFusionServiceConfig config = config_for(1u, 4u, 4u);
    config.require_flow_open = true;
    flowkeep::NativeFusionServiceReceipt receipt{};
    std::string error;
    CHECK(!flowkeep::RunNativeFusionService(&source, &router, scorers,
        &committer, config, &receipt, &error));
    CHECK(receipt.route_failures == 1u);
    CHECK(receipt.requests_peeked == 4u);
    CHECK(receipt.requests_acked == 0u);
    CHECK(receipt.requests_unacked_replayable == 4u);
    return true;
}

bool test_flow_continue_requires_producer_attested_predecessor() {
    std::vector<fk_detector_request_v1> requests;
    requests.push_back(flow_open_for(1u, 1816u, 60u, 1u));
    requests.push_back(checkpoint_for(2u, 1816u, 60u, 1u, 4u, 1u));
    /* Structurally valid v4 control, but its producer cursor contradicts the
     * service-observed predecessor and must never be inferred/repaired. */
    requests.push_back(flow_continue_for(
        3u, 1816u, 61u, 2u, 1u, 60u, 1u, 0u));
    FakeSource source(std::move(requests));
    MapRouter router;
    router.routes = {{1816u, 116u}};
    router.event_names = {{116u, "event-bad-predecessor-attestation"}};
    DeterministicScorer scorer;
    std::vector<flowkeep::NativeFusionBatchScorer *> scorers = {&scorer};
    MemoryCommitter committer;
    flowkeep::NativeFusionServiceConfig config = config_for(1u, 3u, 3u);
    config.require_flow_open = true;
    flowkeep::NativeFusionServiceReceipt receipt{};
    std::string error;
    CHECK(!flowkeep::RunNativeFusionService(&source, &router, scorers,
        &committer, config, &receipt, &error));
    CHECK(receipt.route_failures == 1u);
    CHECK(receipt.requests_acked == 0u);
    CHECK(receipt.requests_unacked_replayable == 3u);
    return true;
}

bool test_new_tuple_epoch_retains_exact_old_epoch() {
    {
        std::vector<fk_detector_request_v1> requests;
        requests.push_back(flow_open_for(1u, 1814u, 40u, 1u));
        requests.push_back(checkpoint_for(2u, 1814u, 40u, 1u, 4u, 1u));
        requests.push_back(flow_open_for(3u, 1814u, 41u, 2u));
        requests.push_back(checkpoint_for(4u, 1814u, 41u, 2u, 4u, 3u));
        FakeSource source(std::move(requests));
        MapRouter router;
        router.routes = {{1814u, 114u}};
        router.event_names = {{114u, "event-tuple-reuse-positive"}};
        DeterministicScorer scorer;
        std::vector<flowkeep::NativeFusionBatchScorer *> scorers = {&scorer};
        MemoryCommitter committer;
        flowkeep::NativeFusionServiceConfig config = config_for(1u, 4u, 4u);
        config.require_flow_open = true;
        flowkeep::NativeFusionServiceReceipt receipt{};
        std::string error;
        CHECK(flowkeep::RunNativeFusionService(&source, &router, scorers,
            &committer, config, &receipt, &error));
        CHECK(receipt.flow_open_records == 2u);
        CHECK(receipt.checkpoint_records == 2u);
        CHECK(receipt.superseded_generation_retirements == 0u);
        CHECK(receipt.flow_coverage_map.peak_entries == 2u);
        CHECK(receipt.flow_coverage_map.terminal_entries == 2u);
        CHECK(receipt.flow_open_coverage_closed == 1u);
    }
    {
        std::vector<fk_detector_request_v1> requests;
        requests.push_back(flow_open_for(1u, 1815u, 50u, 1u));
        requests.push_back(flow_open_for(2u, 1815u, 51u, 2u));
        requests.push_back(checkpoint_for(3u, 1815u, 50u, 1u, 4u, 1u));
        FakeSource source(std::move(requests));
        MapRouter router;
        router.routes = {{1815u, 115u}};
        router.event_names = {{115u, "event-tuple-reuse-stale"}};
        DeterministicScorer scorer;
        std::vector<flowkeep::NativeFusionBatchScorer *> scorers = {&scorer};
        MemoryCommitter committer;
        flowkeep::NativeFusionServiceConfig config = config_for(1u, 3u, 3u);
        config.require_flow_open = true;
        flowkeep::NativeFusionServiceReceipt receipt{};
        std::string error;
        CHECK(flowkeep::RunNativeFusionService(&source, &router, scorers,
            &committer, config, &receipt, &error));
        CHECK(receipt.route_failures == 0u);
        CHECK(receipt.requests_acked == 3u);
        CHECK(receipt.flow_coverage_map.terminal_entries == 2u);
        CHECK(receipt.flow_open_coverage_closed == 1u);
    }
    return true;
}

bool test_scenario_event_two_flows_stays_one_ordered_shard() {
    std::vector<fk_detector_request_v1> requests;
    requests.push_back(request_for(1u, 1001u));
    requests.push_back(request_for(2u, 1002u));
    requests.push_back(request_for(3u, 1001u));
    requests.push_back(request_for(4u, 1002u));
    FakeSource source(std::move(requests));
    MapRouter router;
    const uint64_t scenario_event = UINT64_C(0xaabbccdd);
    router.routes = {{1001u, scenario_event}, {1002u, scenario_event}};
    router.event_names = {{scenario_event, "scenario-a"}};
    DeterministicScorer scorer0;
    DeterministicScorer scorer1;
    std::vector<flowkeep::NativeFusionBatchScorer *> scorers = {
        &scorer0, &scorer1};
    MemoryCommitter committer;
    flowkeep::NativeFusionServiceReceipt receipt{};
    std::string error;
    CHECK(flowkeep::RunNativeFusionService(&source, &router, scorers,
        &committer, config_for(2u, 2u, 2u), &receipt, &error));
    CHECK(receipt.completed == 1u);
    CHECK(receipt.production_durability_attested == 0u);
    CHECK(receipt.requests_acked == 4u);
    CHECK(receipt.requests_unacked_replayable == 0u);
    CHECK(receipt.durable_commit_batch_capacity == 2u);
    CHECK(receipt.route_quantum == 2u);
    CHECK(router.resolve_calls == 2u);
    CHECK(receipt.route_cache_misses == 2u);
    CHECK(receipt.route_cache_hits == 2u);
    CHECK(receipt.frozen_flow_routes == 2u);
    CHECK(receipt.route_bindings_validated == 4u);
    CHECK(receipt.source_delivers_validated_items == 0u);
    CHECK(receipt.request_validations_performed == 4u);
    CHECK(receipt.request_validations_elided == 0u);
    CHECK(receipt.worker_metrics.size() == 2u);
    CHECK((committer.sequences == std::vector<uint64_t>{1u, 2u, 3u, 4u}));
    const uint32_t shard = flowkeep::NativeFusionWorkerShard(
        scenario_event, 2u);
    DeterministicScorer &used = shard == 0u ? scorer0 : scorer1;
    DeterministicScorer &unused = shard == 0u ? scorer1 : scorer0;
    CHECK(used.batches.size() == 2u);
    CHECK((used.batches[0] == std::vector<uint64_t>{1u, 2u}));
    CHECK((used.batches[1] == std::vector<uint64_t>{3u, 4u}));
    CHECK(std::all_of(used.seen_events.begin(), used.seen_events.end(),
        [scenario_event](uint64_t value) { return value == scenario_event; }));
    CHECK(unused.batches.empty());
    const auto &used_metrics = receipt.worker_metrics[shard];
    const auto &unused_metrics =
        receipt.worker_metrics[shard == 0u ? 1u : 0u];
    CHECK(used_metrics.worker_shard == shard);
    CHECK(used_metrics.requests_routed == 4u);
    CHECK(used_metrics.requests_dequeued == 4u);
    CHECK(used_metrics.requests_scored == 4u);
    CHECK(used_metrics.batches_started == 2u);
    CHECK(used_metrics.batches_scored == 2u);
    CHECK(used_metrics.maximum_batch_rows == 2u);
    CHECK(used_metrics.terminal_queue_depth == 0u);
    CHECK(unused_metrics.requests_routed == 0u);
    CHECK(unused_metrics.requests_scored == 0u);
    return true;
}

bool test_generic_source_still_revalidates_every_item() {
    fk_detector_request_v1 invalid = request_for(1u, 1051u);
    invalid.features[0] = std::numeric_limits<float>::quiet_NaN();
    FakeSource source({invalid});
    MapRouter router;
    router.routes[1051u] = 51u;
    router.event_names[51u] = "event-51";
    DeterministicScorer scorer;
    MemoryCommitter committer;
    flowkeep::NativeFusionServiceReceipt receipt{};
    std::string error;
    CHECK(!flowkeep::RunNativeFusionService(
        &source, &router, {&scorer}, &committer, config_for(1u, 1u, 1u),
        &receipt, &error));
    CHECK(!error.empty());
    CHECK(receipt.source_delivers_validated_items == 0u);
    CHECK(receipt.request_validations_performed == 1u);
    CHECK(receipt.request_validations_elided == 0u);
    CHECK(receipt.requests_peeked == 0u);
    CHECK(receipt.source_failures == 1u);
    CHECK(scorer.batches.empty());
    CHECK(committer.sequences.empty());
    return true;
}

bool test_exact_thread_affinity_is_attested() {
    cpu_set_t allowed;
    CPU_ZERO(&allowed);
    CHECK(::pthread_getaffinity_np(
        ::pthread_self(), sizeof(allowed), &allowed) == 0);
    std::vector<uint32_t> cpus;
    for (uint32_t cpu = 0u; cpu < CPU_SETSIZE && cpus.size() < 3u; ++cpu) {
        if (CPU_ISSET(cpu, &allowed))
            cpus.push_back(cpu);
    }
    /* Minimal CI containers may expose fewer than three disjoint logical
     * CPUs; production validation still rejects overlapping role sets. */
    if (cpus.size() < 3u)
        return true;

    FakeSource source({request_for(1u, 1061u)});
    MapRouter router;
    router.routes[1061u] = 61u;
    router.event_names[61u] = "event-61";
    DeterministicScorer scorer;
    MemoryCommitter committer;
    flowkeep::NativeFusionServiceConfig config = config_for(1u, 1u, 1u);
    config.coordinator_cpu_set = {cpus[0]};
    config.committer_cpu_set = {cpus[1]};
    config.worker_cpu_sets = {{cpus[2]}};
    flowkeep::NativeFusionServiceReceipt receipt{};
    std::string error;
    bool success = false;
    std::thread runner([&] {
        cpu_set_t coordinator;
        CPU_ZERO(&coordinator);
        CPU_SET(cpus[0], &coordinator);
        if (::pthread_setaffinity_np(::pthread_self(), sizeof(coordinator),
                &coordinator) != 0) {
            return;
        }
        success = flowkeep::RunNativeFusionService(
            &source, &router, {&scorer}, &committer, config,
            &receipt, &error);
    });
    runner.join();
    CHECK(success);
    CHECK(error.empty());
    CHECK(receipt.coordinator_affinity_requested == 1u);
    CHECK(receipt.coordinator_affinity_attested == 1u);
    CHECK(receipt.committer_affinity_requested == 1u);
    CHECK(receipt.committer_affinity_attested == 1u);
    CHECK(receipt.worker_affinity_plan_requested == 1u);
    CHECK(receipt.worker_affinity_plan_attested == 1u);
    CHECK(receipt.worker_metrics.size() == 1u);
    CHECK(receipt.worker_metrics[0].affinity_requested == 1u);
    CHECK(receipt.worker_metrics[0].affinity_attested == 1u);
    CHECK(receipt.worker_metrics[0].affinity_cpu_count == 1u);
    return true;
}

bool test_overlapping_affinity_roles_are_rejected() {
    FakeSource source({request_for(1u, 1071u)});
    MapRouter router;
    DeterministicScorer scorer;
    MemoryCommitter committer;
    flowkeep::NativeFusionServiceConfig config = config_for(1u, 1u, 1u);
    config.coordinator_cpu_set = {0u};
    config.committer_cpu_set = {0u};
    config.worker_cpu_sets = {{1u}};
    flowkeep::NativeFusionServiceReceipt receipt{};
    std::string error;
    CHECK(!flowkeep::RunNativeFusionService(
        &source, &router, {&scorer}, &committer, config, &receipt, &error));
    CHECK(!error.empty());
    CHECK(receipt.requests_peeked == 0u);
    return true;
}

bool test_cross_event_out_of_order_completion_commits_prefix_only() {
    uint64_t event_a = 1u;
    uint64_t event_b = 2u;
    while (flowkeep::NativeFusionWorkerShard(event_a, 2u) ==
            flowkeep::NativeFusionWorkerShard(event_b, 2u)) {
        ++event_b;
    }
    FakeSource source({request_for(1u, 1101u), request_for(2u, 1102u)});
    MapRouter router;
    router.routes = {{1101u, event_a}, {1102u, event_b}};
    router.event_names = {{event_a, "event-a"}, {event_b, "event-b"}};
    DeterministicScorer scorer0;
    DeterministicScorer scorer1;
    const uint32_t slow = flowkeep::NativeFusionWorkerShard(event_a, 2u);
    (slow == 0u ? scorer0 : scorer1).delay_ms = 30u;
    std::vector<flowkeep::NativeFusionBatchScorer *> scorers = {
        &scorer0, &scorer1};
    MemoryCommitter committer;
    flowkeep::NativeFusionServiceReceipt receipt{};
    std::string error;
    CHECK(flowkeep::RunNativeFusionService(&source, &router, scorers,
        &committer, config_for(2u, 1u, 2u), &receipt, &error));
    CHECK(receipt.out_of_order_worker_completions >= 1u);
    CHECK((committer.sequences == std::vector<uint64_t>{1u, 2u}));
    CHECK((source.ack_log == std::vector<uint64_t>{1u, 2u}));
    CHECK(receipt.last_persisted_sequence == receipt.last_acked_sequence);
    return true;
}

bool test_worker_failure_never_commits_or_acks() {
    FakeSource source({request_for(1u, 1201u)});
    MapRouter router;
    router.routes = {{1201u, 7u}};
    router.event_names = {{7u, "event-seven"}};
    DeterministicScorer scorer;
    scorer.fail = true;
    std::vector<flowkeep::NativeFusionBatchScorer *> scorers = {&scorer};
    MemoryCommitter committer;
    flowkeep::NativeFusionServiceReceipt receipt{};
    std::string error;
    CHECK(!flowkeep::RunNativeFusionService(&source, &router, scorers,
        &committer, config_for(1u, 1u, 1u), &receipt, &error));
    CHECK(receipt.scorer_failures == 1u);
    CHECK(receipt.requests_persisted == 0u);
    CHECK(receipt.requests_acked == 0u);
    CHECK(receipt.requests_unacked_replayable == 1u);
    CHECK(committer.sequences.empty());
    CHECK(source.ack_log.empty());
    return true;
}

bool test_history_fence_precedes_ledger_and_failure_never_acks() {
    for(bool fail:{false,true}) {
        FakeSource source({request_for(1u,1201u)});
        MapRouter router;router.routes={{1201u,7u}};router.event_names={{7u,"history-event"}};
        DeterministicScorer scorer;scorer.history_fail=fail;scorer.history_delay_ms=10;
        std::vector<flowkeep::NativeFusionBatchScorer *> scorers={&scorer};
        MemoryCommitter committer;flowkeep::NativeFusionServiceReceipt receipt{};std::string error;
        CHECK(flowkeep::RunNativeFusionService(&source,&router,scorers,&committer,
            config_for(1u,1u,1u),&receipt,&error)==!fail);
        CHECK(scorer.history_fences==std::vector<uint64_t>({1}));
        if(fail) {
            CHECK(committer.sequences.empty() && source.ack_log.empty());
            CHECK(receipt.requests_acked==0 && receipt.durable_commit_failed_calls==1);
        } else {
            CHECK(committer.first_commit_started_ns>=scorer.history_finished_ns);
            CHECK(committer.decision_times[0]<scorer.history_finished_ns);
            CHECK(receipt.requests_acked==1);
        }
    }
    return true;
}

bool test_producer_overrun_is_terminal_before_ack() {
    FakeSource source({request_for(1u, 1301u)});
    source.Fault();
    MapRouter router;
    router.routes = {{1301u, 9u}};
    router.event_names = {{9u, "event-nine"}};
    DeterministicScorer scorer;
    std::vector<flowkeep::NativeFusionBatchScorer *> scorers = {&scorer};
    MemoryCommitter committer;
    flowkeep::NativeFusionServiceReceipt receipt{};
    std::string error;
    CHECK(!flowkeep::RunNativeFusionService(&source, &router, scorers,
        &committer, config_for(1u, 1u, 1u), &receipt, &error));
    CHECK(receipt.source_failures >= 1u);
    CHECK(receipt.final_source.producer_overruns == 1u);
    CHECK(receipt.requests_acked == 0u);
    CHECK(committer.sequences.empty());
    return true;
}

bool test_unknown_flow_is_unacked_replayable() {
    FakeSource source({request_for(1u, 1401u)});
    MapRouter router;
    DeterministicScorer scorer;
    std::vector<flowkeep::NativeFusionBatchScorer *> scorers = {&scorer};
    MemoryCommitter committer;
    flowkeep::NativeFusionServiceReceipt receipt{};
    std::string error;
    CHECK(!flowkeep::RunNativeFusionService(&source, &router, scorers,
        &committer, config_for(1u, 1u, 1u), &receipt, &error));
    CHECK(receipt.route_failures == 1u);
    CHECK(receipt.requests_peeked == 1u);
    CHECK(receipt.requests_acked == 0u);
    CHECK(receipt.requests_unacked_replayable == 1u);
    CHECK(committer.sequences.empty());
    return true;
}

bool test_global_semantic_time_regression_never_acks() {
    fk_detector_request_v1 first = request_for(1u, 1501u);
    fk_detector_request_v1 second = request_for(2u, 1502u);
    first.semantic_timestamp_ns = 20u;
    second.semantic_timestamp_ns = 19u;
    FakeSource source({first, second});
    MapRouter router;
    router.routes = {{1501u, 11u}, {1502u, 12u}};
    router.event_names = {{11u, "event-eleven"}, {12u, "event-twelve"}};
    DeterministicScorer scorer;
    std::vector<flowkeep::NativeFusionBatchScorer *> scorers = {&scorer};
    MemoryCommitter committer;
    flowkeep::NativeFusionServiceReceipt receipt{};
    std::string error;
    CHECK(!flowkeep::RunNativeFusionService(&source, &router, scorers,
        &committer, config_for(1u, 2u, 2u), &receipt, &error));
    CHECK(receipt.timestamp_failures == 1u);
    CHECK(receipt.requests_acked == 0u);
    CHECK(receipt.requests_unacked_replayable == 2u);
    CHECK(committer.sequences.empty());
    return true;
}

bool test_transient_write_published_snapshot_is_reread() {
    FakeSource source({request_for(1u, 1601u)});
    source.InjectTransientInconsistentSnapshots(3u);
    MapRouter router;
    router.routes = {{1601u, 13u}};
    router.event_names = {{13u, "event-thirteen"}};
    DeterministicScorer scorer;
    std::vector<flowkeep::NativeFusionBatchScorer *> scorers = {&scorer};
    MemoryCommitter committer;
    flowkeep::NativeFusionServiceReceipt receipt{};
    std::string error;
    CHECK(flowkeep::RunNativeFusionService(&source, &router, scorers,
        &committer, config_for(1u, 1u, 1u), &receipt, &error));
    CHECK(receipt.requests_acked == 1u);
    CHECK((source.ack_log == std::vector<uint64_t>{1u}));
    return true;
}

bool test_persistent_write_published_mismatch_fails_closed() {
    FakeSource source({request_for(1u, 1701u)});
    source.InjectPersistentInconsistentSnapshot();
    MapRouter router;
    router.routes = {{1701u, 14u}};
    router.event_names = {{14u, "event-fourteen"}};
    DeterministicScorer scorer;
    std::vector<flowkeep::NativeFusionBatchScorer *> scorers = {&scorer};
    MemoryCommitter committer;
    flowkeep::NativeFusionServiceReceipt receipt{};
    std::string error;
    CHECK(!flowkeep::RunNativeFusionService(&source, &router, scorers,
        &committer, config_for(1u, 1u, 1u), &receipt, &error));
    CHECK(receipt.source_failures >= 1u);
    CHECK(receipt.requests_peeked == 0u);
    CHECK(receipt.requests_acked == 0u);
    CHECK(committer.sequences.empty());
    return true;
}

bool test_prepared_pipeline_overlaps_and_fails_closed() {
    class Pipeline final : public flowkeep::NativeFusionCommitter {
    public:
        struct Item : flowkeep::NativeFusionPreparedCommit {uint64_t last=0;};
        std::mutex mutex;std::condition_variable cv;unsigned prepared=0;
        std::atomic<uint64_t> durable{0};bool fail=false,overlapped=false;
        bool idle=false,activated=false,idle_seen=false;
        uint32_t depth=2;
        std::vector<uint32_t> expected_drain_cpus;
        bool SupportsPreparedCommit() const noexcept override{return true;}
        uint32_t PreparedCommitCapacity() const noexcept override{return depth;}
        bool SupportsDrainPreparationOverlap() const noexcept override{return idle;}
        void BeginDrainPreparationOverlap() noexcept override {
            activated=true;idle_seen=::sched_getscheduler(0)==SCHED_IDLE;
            cpu_set_t observed;CPU_ZERO(&observed);
            if(::pthread_getaffinity_np(::pthread_self(),sizeof(observed),&observed)!=0)
                idle_seen=false;
            for(uint32_t cpu=0;cpu<CPU_SETSIZE;++cpu)
                if(bool(CPU_ISSET(cpu,&observed)) !=
                   (std::find(expected_drain_cpus.begin(),expected_drain_cpus.end(),cpu)!=expected_drain_cpus.end()))
                    idle_seen=false;
        }
        bool PrepareConsecutive(const flowkeep::NativeFusionDecision *d,size_t n,
                std::unique_ptr<flowkeep::NativeFusionPreparedCommit> *out,std::string*) noexcept override {
            if(activated && ::sched_getscheduler(0)!=SCHED_IDLE)return false;
            auto p=std::make_unique<Item>();p->last=d[n-1].sequence;*out=std::move(p);
            {std::lock_guard<std::mutex> lock(mutex);++prepared;}cv.notify_all();return true;
        }
        bool PublishPrepared(flowkeep::NativeFusionPreparedCommit *p,
                flowkeep::NativeFusionCommitResult *r,std::string*) noexcept override {
            if(::sched_getscheduler(0)==SCHED_IDLE)return false;
            auto *item=dynamic_cast<Item*>(p);if(!item)return false;
            if(item->last==1) {
                std::unique_lock<std::mutex> lock(mutex);
                overlapped=cv.wait_for(lock,std::chrono::seconds(2),[&]{return prepared>=depth;});
                if(!overlapped || fail)return false;
            }
            if(item->last!=durable.load()+1)return false;
            durable=item->last;r->completed_monotonic_ns=now_ns();
            r->durability=flowkeep::NativeFusionDurability::TestOnlyMemory;return true;
        }
        bool CommitConsecutive(const flowkeep::NativeFusionDecision*,size_t,
                flowkeep::NativeFusionCommitResult*,std::string*) noexcept override{return false;}
    };
    cpu_set_t allowed;CPU_ZERO(&allowed);
    CHECK(::pthread_getaffinity_np(::pthread_self(),sizeof(allowed),&allowed)==0);
    std::vector<uint32_t> cpus;
    for(uint32_t cpu=0;cpu<CPU_SETSIZE && cpus.size()<3;++cpu)
        if(CPU_ISSET(cpu,&allowed))cpus.push_back(cpu);
    for(uint32_t depth:{2u,4u}) for(bool idle:{false,true}) for(bool fail:{false,true}) {
        if(idle && cpus.size()<3)continue;
        FakeSource source({request_for(1,1801),request_for(2,1801),
            request_for(3,1801),request_for(4,1801)});
        source.input_fence=idle;
        MapRouter router;router.routes={{1801,15}};router.event_names={{15,"pipeline"}};
        DeterministicScorer scorer;Pipeline committer;committer.fail=fail;
        committer.depth=depth;
        committer.idle=idle;
        source.RequireDurablePrefix(&committer.durable);
        flowkeep::NativeFusionServiceReceipt receipt;std::string error;
        auto config=config_for(1,1,4);
        if(idle) {
            config.coordinator_cpu_set={cpus[0]};config.committer_cpu_set={cpus[1]};
            config.worker_cpu_sets={{cpus[2]}};
            committer.expected_drain_cpus={cpus[2]};
        }
        bool ok=false,coordinator_policy_unchanged=false;
        std::thread runner([&] {
            const int original_policy=::sched_getscheduler(0);
            if(idle) {
                cpu_set_t selected;CPU_ZERO(&selected);CPU_SET(cpus[0],&selected);
                if(::pthread_setaffinity_np(::pthread_self(),sizeof(selected),&selected)!=0)return;
            }
            ok=flowkeep::RunNativeFusionService(&source,&router,{&scorer},
                &committer,config,&receipt,&error);
            coordinator_policy_unchanged=::sched_getscheduler(0)==original_policy;
        });
        runner.join();
        CHECK(coordinator_policy_unchanged);
        CHECK(receipt.drain_preparation_idle_attested==idle);
        CHECK(committer.idle_seen==idle);
        if(idle)CHECK(receipt.drain_preparation_batches>=2);
        CHECK(ok==!fail);CHECK(committer.overlapped);CHECK(!source.ack_before_durable());
        CHECK(receipt.durable_commit_queue_depth==depth);
        CHECK(receipt.durable_commit_peak_depth==depth);
        if(fail){CHECK(source.ack_log.empty());CHECK(committer.durable==0);}
        else {
            CHECK((source.ack_log==std::vector<uint64_t>{1,2,3,4}));
            CHECK(receipt.commit_trace.size()==4);
            CHECK(receipt.commit_trace[1].prepare_finished_ns <= receipt.commit_trace[0].publish_finished_ns);
            CHECK(receipt.commit_trace[0].ack_ns>=receipt.commit_trace[0].publish_finished_ns);
            for(const auto &trace:receipt.commit_trace) {
                CHECK(trace.prepare_cost.valid);CHECK(trace.publish_cost.valid);
                CHECK(trace.history_cost.valid);
            }
        }
    }
    return true;
}

bool test_slow_durable_commit_does_not_block_ingest_or_early_ack() {
    std::atomic<bool> commit_started{false};
    std::atomic<uint64_t> durable_prefix{0u};
    FakeSource source({
        request_for(1u, 1801u), request_for(2u, 1801u),
        request_for(3u, 1801u), request_for(4u, 1801u)});
    source.GateAfterFirstUntil(&commit_started);
    source.RequireDurablePrefix(&durable_prefix);
    MapRouter router;
    router.routes = {{1801u, 15u}};
    router.event_names = {{15u, "event-fifteen"}};
    DeterministicScorer scorer;
    std::vector<flowkeep::NativeFusionBatchScorer *> scorers = {&scorer};
    MemoryCommitter committer;
    committer.delay_ms = 50u;
    committer.commit_started = &commit_started;
    committer.observed_peeks = &source.peeked_count;
    committer.durable_prefix = &durable_prefix;
    flowkeep::NativeFusionServiceReceipt receipt{};
    std::string error;
    CHECK(flowkeep::RunNativeFusionService(&source, &router, scorers,
        &committer, config_for(1u, 1u, 4u), &receipt, &error));
    CHECK(committer.peeked_before_first_return == 4u);
    CHECK(!source.ack_before_durable());
    CHECK((source.ack_log == std::vector<uint64_t>{1u, 2u, 3u, 4u}));
    CHECK(receipt.requests_scored == 4u);
    CHECK(receipt.requests_persisted == 4u);
    CHECK(receipt.requests_acked == 4u);
    CHECK(receipt.durable_sequence_equals_acked_sequence == 1u);
    CHECK(receipt.durable_commit_queue_depth == 1u);
    CHECK(receipt.detector_ingest_decoupled_from_durable_fsync == 1u);
    CHECK(receipt.ack_after_durable_only == 1u);
    return true;
}

bool test_durable_commit_batch_is_independent_of_scorer_batch() {
    std::vector<fk_detector_request_v1> requests;
    for (uint64_t sequence = 1u; sequence <= 8u; ++sequence)
        requests.push_back(request_for(sequence, 1901u));
    FakeSource source(std::move(requests));
    MapRouter router;
    router.routes = {{1901u, 16u}};
    router.event_names = {{16u, "event-sixteen"}};
    DeterministicScorer scorer;
    std::vector<flowkeep::NativeFusionBatchScorer *> scorers = {&scorer};
    MemoryCommitter committer;
    committer.delay_ms = 50u;
    flowkeep::NativeFusionServiceConfig config = config_for(1u, 2u, 8u);
    config.durable_commit_batch_capacity = 4u;
    flowkeep::NativeFusionServiceReceipt receipt{};
    std::string error;
    CHECK(flowkeep::RunNativeFusionService(&source, &router, scorers,
        &committer, config, &receipt, &error));
    CHECK(receipt.requests_acked == 8u);
    CHECK(receipt.durable_commit_batch_capacity == 4u);
    CHECK(std::all_of(committer.commit_sizes.begin(),
        committer.commit_sizes.end(),
        [](size_t value) { return value <= 4u; }));
    CHECK(std::any_of(committer.commit_sizes.begin(),
        committer.commit_sizes.end(),
        [](size_t value) { return value > 2u; }));
    return true;
}

bool test_durable_full_capacity_batches_are_coalesced() {
    std::vector<fk_detector_request_v1> requests;
    for (uint64_t sequence = 1u; sequence <= 8u; ++sequence)
        requests.push_back(request_for(sequence, 1902u));
    FakeSource source(std::move(requests));
    MapRouter router;
    router.routes = {{1902u, 1602u}};
    router.event_names = {{1602u, "event-capacity-batches"}};
    DeterministicScorer scorer;
    MemoryCommitter committer;
    flowkeep::NativeFusionServiceConfig config = config_for(1u, 8u, 8u);
    config.durable_commit_batch_capacity = 4u;
    config.durable_commit_max_wait_ns = UINT64_C(1000000000);
    flowkeep::NativeFusionServiceReceipt receipt{};
    std::string error;
    CHECK(flowkeep::RunNativeFusionService(
        &source, &router, {&scorer}, &committer, config, &receipt, &error));
    CHECK(committer.commit_sizes == std::vector<size_t>({4u, 4u}));
    CHECK(source.ack_log == std::vector<uint64_t>({4u, 8u}));
    CHECK(receipt.durable_commit_submissions == 2u);
    CHECK(receipt.durable_commit_calls == 2u);
    CHECK(receipt.durable_commit_failed_calls == 0u);
    CHECK(receipt.durable_commit_trigger_capacity == 2u);
    CHECK(receipt.durable_commit_trigger_terminal == 0u);
    CHECK(receipt.durable_commit_trigger_max_wait == 0u);
    CHECK(receipt.minimum_durable_commit_batch_rows == 4u);
    CHECK(receipt.maximum_durable_commit_batch_rows == 4u);
    CHECK(receipt.durable_commit_elapsed_ns_sum >=
        receipt.maximum_durable_commit_elapsed_ns);
    CHECK(receipt.first_durable_commit_submit_monotonic_ns != 0u);
    CHECK(receipt.last_durable_commit_completion_monotonic_ns >=
        receipt.first_durable_commit_submit_monotonic_ns);
    CHECK(receipt.durable_commit_active_span_ns ==
        receipt.last_durable_commit_completion_monotonic_ns -
            receipt.first_durable_commit_submit_monotonic_ns);
    CHECK(receipt.maximum_decision_to_durable_ns != 0u);
    CHECK(receipt.maximum_physical_enqueue_to_durable_ns != 0u);
    CHECK(receipt.maximum_decision_to_ack_ns >=
        receipt.maximum_decision_to_durable_ns);
    CHECK(receipt.maximum_physical_enqueue_to_ack_ns >=
        receipt.maximum_physical_enqueue_to_durable_ns);
    return true;
}

bool test_durable_terminal_partial_batch_flushes_once() {
    std::vector<fk_detector_request_v1> requests;
    for (uint64_t sequence = 1u; sequence <= 6u; ++sequence)
        requests.push_back(request_for(sequence, 1903u));
    FakeSource source(std::move(requests));
    MapRouter router;
    router.routes = {{1903u, 1603u}};
    router.event_names = {{1603u, "event-terminal-batch"}};
    DeterministicScorer scorer;
    MemoryCommitter committer;
    flowkeep::NativeFusionServiceConfig config = config_for(1u, 6u, 6u);
    config.durable_commit_batch_capacity = 4u;
    config.durable_commit_max_wait_ns = UINT64_C(1000000000);
    flowkeep::NativeFusionServiceReceipt receipt{};
    std::string error;
    CHECK(flowkeep::RunNativeFusionService(
        &source, &router, {&scorer}, &committer, config, &receipt, &error));
    CHECK(committer.commit_sizes == std::vector<size_t>({4u, 2u}));
    CHECK(source.ack_log == std::vector<uint64_t>({4u, 6u}));
    CHECK(receipt.durable_commit_submissions == 2u);
    CHECK(receipt.durable_commit_calls == 2u);
    CHECK(receipt.durable_commit_failed_calls == 0u);
    CHECK(receipt.durable_commit_trigger_capacity == 1u);
    CHECK(receipt.durable_commit_trigger_terminal == 1u);
    CHECK(receipt.durable_commit_trigger_max_wait == 0u);
    CHECK(receipt.minimum_durable_commit_batch_rows == 2u);
    CHECK(receipt.maximum_durable_commit_batch_rows == 4u);
    CHECK(receipt.requests_persisted == 6u);
    CHECK(receipt.requests_acked == 6u);
    return true;
}

bool test_quiescent_feedback_flush_preserves_durable_ack() {
    for(bool enabled:{false,true})for(bool fenced:{false,true})for(bool fail:{false,true}) {
        setenv("FK_QUIESCENT_FEEDBACK_COMMIT",enabled?"1":"0",1);
        FakeSource source({request_for(1u,1904u),request_for(2u,1904u)});
        source.gate_next_until_ack=true;source.input_fence=fenced;
        std::atomic<uint64_t> durable{0};source.RequireDurablePrefix(&durable);
        MapRouter router;router.routes={{1904u,1604u}};router.event_names={{1604u,"feedback"}};
        DeterministicScorer scorer;MemoryCommitter committer;
        committer.durable_prefix=&durable;committer.fail=fail;committer.delay_ms=2;
        auto config=config_for(1u,1u,4u);config.durable_commit_batch_capacity=4;
        config.durable_commit_max_wait_ns=20000000;
        config.durable_commit_max_wait_age_anchor=flowkeep::NativeFusionDurableAgeAnchor::FirstDurableCandidate;
        flowkeep::NativeFusionServiceReceipt receipt{};std::string error;
        const bool ok=flowkeep::RunNativeFusionService(&source,&router,{&scorer},&committer,config,&receipt,&error);
        CHECK(ok==!fail);CHECK(!source.ack_before_durable());
        if(fail){CHECK(source.ack_log.empty());CHECK(receipt.requests_acked==0);}
        else {CHECK(source.ack_log==std::vector<uint64_t>({1,2}));CHECK(committer.sequences==source.ack_log);CHECK(receipt.requests_persisted==2);}
        const uint64_t expected=fail?1:2;
        CHECK(receipt.durable_commit_trigger_quiescent_feedback==((enabled&&fenced)?expected:0));
        CHECK(receipt.durable_commit_trigger_max_wait==((enabled&&fenced)?0:expected));
        if(enabled&&fenced)CHECK(receipt.durable_commit_trigger_terminal==expected);
    }
    unsetenv("FK_QUIESCENT_FEEDBACK_COMMIT");return true;
}

bool test_drain_wait_preserves_durable_ack() {
    for(bool enabled:{false,true})for(bool fenced:{false,true})for(bool fail:{false,true}) {
        setenv("FK_QUIESCENT_FEEDBACK_COMMIT","0",1);
        setenv("FK_DRAIN_COMMIT_WAIT_US",enabled?"1000":"0",1);
        FakeSource source({request_for(1u,1904u),request_for(2u,1904u)});
        source.gate_next_until_ack=true;source.input_fence=fenced;
        std::atomic<uint64_t> durable{0};source.RequireDurablePrefix(&durable);
        MapRouter router;router.routes={{1904u,1604u}};router.event_names={{1604u,"feedback"}};
        DeterministicScorer scorer;MemoryCommitter committer;
        committer.durable_prefix=&durable;committer.fail=fail;committer.delay_ms=2;
        auto config=config_for(1u,1u,4u);config.durable_commit_batch_capacity=4;
        config.durable_commit_max_wait_ns=20000000;
        config.durable_commit_max_wait_age_anchor=flowkeep::NativeFusionDurableAgeAnchor::FirstDurableCandidate;
        flowkeep::NativeFusionServiceReceipt receipt{};std::string error;
        const bool ok=flowkeep::RunNativeFusionService(&source,&router,{&scorer},&committer,config,&receipt,&error);
        CHECK(ok==!fail);CHECK(!source.ack_before_durable());
        if(fail){CHECK(source.ack_log.empty());CHECK(receipt.requests_acked==0);}
        else {CHECK(source.ack_log==std::vector<uint64_t>({1,2}));CHECK(committer.sequences==source.ack_log);CHECK(receipt.requests_persisted==2);}
        const uint64_t expected=fail?1:2;
        CHECK(receipt.durable_commit_trigger_drain_wait==((enabled&&fenced)?expected:0));
        CHECK(receipt.durable_commit_trigger_max_wait==expected);
        CHECK(receipt.durable_commit_trigger_terminal==0);
    }
    unsetenv("FK_QUIESCENT_FEEDBACK_COMMIT");unsetenv("FK_DRAIN_COMMIT_WAIT_US");return true;
}

bool test_durable_max_wait_bounds_low_rate_partial_prefix() {
    constexpr uint64_t kDurableMaxWaitNs = UINT64_C(5000000);
    constexpr uint64_t kIdlePollNs = UINT64_C(250000000);
    std::atomic<bool> first_commit_started{false};
    fk_detector_request_v1 first = request_for(1u, 1904u);
    const uint64_t first_physical_ns = first.physical_timestamp_ns;
    FakeSource source({first, request_for(2u, 1904u)});
    source.GateAfterFirstUntil(&first_commit_started);
    MapRouter router;
    router.routes = {{1904u, 1604u}};
    router.event_names = {{1604u, "event-max-wait-batch"}};
    DeterministicScorer scorer;
    MemoryCommitter committer;
    committer.commit_started = &first_commit_started;
    flowkeep::NativeFusionServiceConfig config = config_for(1u, 1u, 4u);
    config.durable_commit_batch_capacity = 4u;
    config.durable_commit_max_wait_ns = kDurableMaxWaitNs;
    config.idle_poll_ns = kIdlePollNs;
    flowkeep::NativeFusionServiceReceipt receipt{};
    std::string error;
    CHECK(flowkeep::RunNativeFusionService(
        &source, &router, {&scorer}, &committer, config, &receipt, &error));
    CHECK(committer.commit_sizes == std::vector<size_t>({1u, 1u}));
    CHECK(source.ack_log == std::vector<uint64_t>({1u, 2u}));
    CHECK(receipt.durable_commit_submissions == 2u);
    CHECK(receipt.durable_commit_calls == 2u);
    CHECK(receipt.durable_commit_trigger_capacity == 0u);
    CHECK(receipt.durable_commit_trigger_terminal == 1u);
    CHECK(receipt.durable_commit_trigger_max_wait == 1u);
    CHECK(committer.first_commit_started_ns >=
        first_physical_ns + kDurableMaxWaitNs);
    CHECK(committer.first_commit_started_ns - first_physical_ns <
        kIdlePollNs / 2u);
    CHECK(receipt.maximum_durable_commit_batch_wait_ns <
        kIdlePollNs / 2u);
    CHECK(receipt.minimum_durable_commit_batch_rows == 1u);
    CHECK(receipt.maximum_durable_commit_batch_rows == 1u);
    CHECK(receipt.requests_acked == 2u);
    return true;
}

bool test_durable_max_wait_uses_physical_head_age() {
    constexpr uint64_t kDurableMaxWaitNs = UINT64_C(200000000);
    constexpr uint64_t kPhysicalPreAgeNs = UINT64_C(250000000);
    constexpr uint64_t kImmediateSubmitAllowanceNs = UINT64_C(100000000);
    std::atomic<bool> first_commit_started{false};
    fk_detector_request_v1 first = request_for(1u, 1906u);
    CHECK(first.physical_timestamp_ns > kPhysicalPreAgeNs);
    first.physical_timestamp_ns -= kPhysicalPreAgeNs;
    FakeSource source({first, request_for(2u, 1906u)});
    source.GateAfterFirstUntil(&first_commit_started);
    MapRouter router;
    router.routes = {{1906u, 1606u}};
    router.event_names = {{1606u, "event-physical-age-max-wait"}};
    DeterministicScorer scorer;
    MemoryCommitter committer;
    committer.commit_started = &first_commit_started;
    flowkeep::NativeFusionServiceConfig config = config_for(1u, 1u, 4u);
    config.durable_commit_batch_capacity = 4u;
    config.durable_commit_max_wait_ns = kDurableMaxWaitNs;
    config.idle_poll_ns = UINT64_C(500000000);
    flowkeep::NativeFusionServiceReceipt receipt{};
    std::string error;
    CHECK(flowkeep::RunNativeFusionService(
        &source, &router, {&scorer}, &committer, config, &receipt, &error));
    CHECK(scorer.first_call_ns != 0u);
    CHECK(committer.first_commit_started_ns >= scorer.first_call_ns);
    CHECK(committer.first_commit_started_ns - scorer.first_call_ns <
        kImmediateSubmitAllowanceNs);
    CHECK(committer.commit_sizes == std::vector<size_t>({1u, 1u}));
    CHECK(source.ack_log == std::vector<uint64_t>({1u, 2u}));
    CHECK(receipt.durable_commit_trigger_capacity == 0u);
    CHECK(receipt.durable_commit_trigger_max_wait == 1u);
    CHECK(receipt.durable_commit_trigger_terminal == 1u);
    CHECK(receipt.requests_acked == 2u);
    return true;
}

bool test_durable_candidate_window_preserves_physical_misses_and_ack_order() {
    for (const auto anchor : {
            flowkeep::NativeFusionDurableAgeAnchor::ConsumerReceive,
            flowkeep::NativeFusionDurableAgeAnchor::FirstDurableCandidate}) {
        std::atomic<bool> first_commit_started{false};
        std::atomic<uint64_t> durable_prefix{0u};
        auto first = request_for(1u, 1907u);
        auto second = request_for(2u, 1907u);
        const uint64_t past = now_ns() - UINT64_C(1000000000);
        first.physical_timestamp_ns = past;
        second.physical_timestamp_ns = past + 1u;
        FakeSource source({first, second});
        source.SetCapacity(8192u);
        source.GateAfterFirstUntil(&first_commit_started);
        source.RequireDurablePrefix(&durable_prefix);
        MapRouter router;
        router.routes = {{1907u, 1607u}};
        router.event_names = {{1607u, "candidate-coalescing"}};
        DeterministicScorer scorer;
        scorer.delay_ms = 25u; // Receive-age has expired before inference ends.
        MemoryCommitter committer;
        committer.commit_started = &first_commit_started;
        committer.durable_prefix = &durable_prefix;
        auto config = config_for(1u, 64u, 8192u);
        config.durable_commit_batch_capacity = 5120u;
        config.durable_commit_max_wait_ns = UINT64_C(20000000);
        config.durable_commit_max_wait_age_anchor = anchor;
        config.detector_deadline_ns = UINT64_C(100000000);
        flowkeep::NativeFusionServiceReceipt receipt{};
        std::string error;
        const bool succeeded = flowkeep::RunNativeFusionService(
            &source, &router, {&scorer}, &committer, config, &receipt, &error);
        if (!succeeded) std::fprintf(stderr, "candidate configuration failure: %s\n", error.c_str());
        CHECK(succeeded);
        CHECK(receipt.deadline_misses == 2u);
        CHECK(receipt.first_deadline_miss.physical_enqueue_monotonic_ns == past);
        CHECK(committer.physical_times == std::vector<uint64_t>({past, past + 1u}));
        CHECK(committer.sequences == std::vector<uint64_t>({1u, 2u}));
        CHECK(committer.commit_sizes == std::vector<size_t>({1u, 1u}));
        CHECK(source.ack_log == std::vector<uint64_t>({1u, 2u}));
        CHECK(!source.ack_before_durable());
        CHECK(receipt.durable_commit_trigger_max_wait == 1u);
        CHECK(receipt.durable_commit_trigger_terminal == 1u);
        if (anchor == flowkeep::NativeFusionDurableAgeAnchor::FirstDurableCandidate)
            CHECK(committer.first_commit_started_ns >=
                committer.decision_times.front() + UINT64_C(20000000));
    }
    return true;
}

bool test_durable_candidate_window_validation_and_failed_commit() {
    for (const uint64_t wait_ns : {UINT64_C(0), UINT64_C(20001000), UINT64_C(20000000), UINT64_C(5000000), UINT64_C(1000000)}) {
        FakeSource source({request_for(1u, 1908u)});
        source.SetCapacity(8192u);
        MapRouter router;
        router.routes = {{1908u, 1608u}};
        router.event_names = {{1608u, "candidate-failure"}};
        DeterministicScorer scorer;
        MemoryCommitter committer;
        committer.fail = true;
        auto config = config_for(1u, 64u, 8192u);
        config.durable_commit_batch_capacity = 5120u;
        config.durable_commit_max_wait_ns = wait_ns;
        config.durable_commit_max_wait_age_anchor =
            flowkeep::NativeFusionDurableAgeAnchor::FirstDurableCandidate;
        flowkeep::NativeFusionServiceReceipt receipt{};
        std::string error;
        CHECK(!flowkeep::RunNativeFusionService(
            &source, &router, {&scorer}, &committer, config, &receipt, &error));
        CHECK(source.ack_log.empty());
        CHECK(receipt.requests_acked == 0u);
        if (wait_ns == 0u || wait_ns > UINT64_C(20000000))
            CHECK(error.find("configuration is invalid") != std::string::npos);
        else
            CHECK(receipt.durable_commit_failed_calls == 1u);
    }
    return true;
}

bool test_durable_commit_failure_never_acks() {
    std::vector<fk_detector_request_v1> requests;
    for (uint64_t sequence = 1u; sequence <= 4u; ++sequence)
        requests.push_back(request_for(sequence, 1905u));
    FakeSource source(std::move(requests));
    MapRouter router;
    router.routes = {{1905u, 1605u}};
    router.event_names = {{1605u, "event-commit-failure"}};
    DeterministicScorer scorer;
    MemoryCommitter committer;
    committer.fail = true;
    flowkeep::NativeFusionServiceConfig config = config_for(1u, 4u, 4u);
    config.durable_commit_batch_capacity = 4u;
    config.durable_commit_max_wait_ns = UINT64_C(1000000000);
    flowkeep::NativeFusionServiceReceipt receipt{};
    std::string error;
    CHECK(!flowkeep::RunNativeFusionService(
        &source, &router, {&scorer}, &committer, config, &receipt, &error));
    CHECK(!error.empty());
    CHECK(receipt.durable_commit_submissions == 1u);
    CHECK(receipt.durable_commit_calls == 0u);
    CHECK(receipt.durable_commit_failed_calls == 1u);
    CHECK(receipt.durable_commit_trigger_capacity == 1u);
    CHECK(receipt.durable_commit_trigger_terminal == 0u);
    CHECK(receipt.durable_commit_trigger_max_wait == 0u);
    CHECK(receipt.commit_failures >= 1u);
    CHECK(receipt.requests_persisted == 0u);
    CHECK(receipt.requests_acked == 0u);
    CHECK(receipt.ack_calls == 0u);
    CHECK(source.ack_log.empty());
    return true;
}

bool test_out_of_order_producer_done_submits_one_terminal_batch() {
    uint64_t slow_event = 1u;
    uint64_t fast_event = 2u;
    while (flowkeep::NativeFusionWorkerShard(slow_event, 2u) ==
            flowkeep::NativeFusionWorkerShard(fast_event, 2u)) {
        ++fast_event;
    }
    FakeSource source({
        request_for(1u, 1906u), request_for(2u, 1907u)});
    MapRouter router;
    router.routes = {{1906u, slow_event}, {1907u, fast_event}};
    router.event_names = {
        {slow_event, "event-slow-sequence-one"},
        {fast_event, "event-fast-sequence-two"},
    };
    DeterministicScorer scorer0;
    DeterministicScorer scorer1;
    const uint32_t slow_shard =
        flowkeep::NativeFusionWorkerShard(slow_event, 2u);
    (slow_shard == 0u ? scorer0 : scorer1).delay_ms = 30u;
    MemoryCommitter committer;
    flowkeep::NativeFusionServiceConfig config = config_for(2u, 1u, 4u);
    config.durable_commit_batch_capacity = 4u;
    config.durable_commit_max_wait_ns = UINT64_C(1000000000);
    flowkeep::NativeFusionServiceReceipt receipt{};
    std::string error;
    CHECK(flowkeep::RunNativeFusionService(
        &source, &router, {&scorer0, &scorer1}, &committer,
        config, &receipt, &error));
    CHECK(receipt.out_of_order_worker_completions >= 1u);
    CHECK(committer.commit_sizes == std::vector<size_t>({2u}));
    CHECK(committer.sequences == std::vector<uint64_t>({1u, 2u}));
    CHECK(source.ack_log == std::vector<uint64_t>({2u}));
    CHECK(receipt.durable_commit_submissions == 1u);
    CHECK(receipt.durable_commit_trigger_capacity == 0u);
    CHECK(receipt.durable_commit_trigger_terminal == 1u);
    CHECK(receipt.durable_commit_trigger_max_wait == 0u);
    CHECK(receipt.minimum_durable_commit_batch_rows == 2u);
    CHECK(receipt.maximum_durable_commit_batch_rows == 2u);
    return true;
}

bool test_source_fault_after_durable_commit_never_acks() {
    FakeSource source({request_for(1u, 1908u)});
    MapRouter router;
    router.routes = {{1908u, 1608u}};
    router.event_names = {{1608u, "event-post-durable-source-fault"}};
    DeterministicScorer scorer;
    MemoryCommitter committer;
    committer.fault_source_after_commit = &source;
    flowkeep::NativeFusionServiceConfig config = config_for(1u, 1u, 1u);
    config.durable_commit_batch_capacity = 1u;
    config.durable_commit_max_wait_ns = UINT64_C(1000000000);
    flowkeep::NativeFusionServiceReceipt receipt{};
    std::string error;
    CHECK(!flowkeep::RunNativeFusionService(
        &source, &router, {&scorer}, &committer, config, &receipt, &error));
    CHECK(!error.empty());
    CHECK(committer.sequences == std::vector<uint64_t>({1u}));
    CHECK(receipt.durable_commit_submissions == 1u);
    CHECK(receipt.durable_commit_calls == 1u);
    CHECK(receipt.durable_commit_failed_calls == 0u);
    CHECK(receipt.requests_persisted == 1u);
    CHECK(receipt.last_persisted_sequence == 1u);
    CHECK(receipt.requests_acked == 0u);
    CHECK(receipt.ack_calls == 0u);
    CHECK(receipt.source_failures >= 1u);
    CHECK(receipt.requests_unacked_replayable == 1u);
    CHECK(source.ack_log.empty());
    return true;
}

bool test_positive_durable_route_slice_is_not_preempted_by_completion_wakes() {
    std::atomic<bool> commit_started{false};
    std::vector<fk_detector_request_v1> requests;
    for (uint64_t sequence = 1u; sequence <= 33u; ++sequence)
        requests.push_back(request_for(sequence, 2001u));
    FakeSource source(std::move(requests));
    source.GateAfterFirstUntil(&commit_started);
    source.DelayAfterFirstPeekMs(10u);
    MapRouter router;
    router.routes = {{2001u, 17u}};
    router.event_names = {{17u, "event-seventeen"}};
    DeterministicScorer scorer;
    std::vector<flowkeep::NativeFusionBatchScorer *> scorers = {&scorer};
    MemoryCommitter committer;
    committer.delay_ms = 5u;
    committer.commit_started = &commit_started;
    flowkeep::NativeFusionServiceConfig config = config_for(1u, 1u, 64u);
    config.route_quantum = 64u;
    config.durable_commit_batch_capacity = 1u;
    config.durable_commit_max_wait_ns = UINT64_C(1000000000);
    config.detector_deadline_ns = UINT64_C(2000000000);
    flowkeep::NativeFusionServiceReceipt receipt{};
    std::string error;
    CHECK(flowkeep::RunNativeFusionService(&source, &router, scorers,
        &committer, config, &receipt, &error));
    CHECK(receipt.requests_peeked == 33u);
    CHECK(receipt.requests_persisted == 33u);
    CHECK(receipt.requests_acked == 33u);
    CHECK(receipt.route_quantum == 64u);
    CHECK(receipt.route_quantum_yields == 0u);
    CHECK(receipt.effective_route_slice_capacity == 32u);
    CHECK(receipt.route_slice_yields == 1u);
    CHECK(scorer.batches.size() == 33u);
    CHECK(std::all_of(scorer.batches.begin(), scorer.batches.end(),
        [](const std::vector<uint64_t> &batch) { return batch.size() == 1u; }));
    return true;
}

bool test_first_deadline_miss_is_lowest_sequence_across_workers() {
    uint64_t event_a=1u,event_b=2u;
    while(flowkeep::NativeFusionWorkerShard(event_a,2u)==flowkeep::NativeFusionWorkerShard(event_b,2u))++event_b;
    auto first=request_for(1u,1101u),second=request_for(2u,1102u);
    const uint64_t past=now_ns()-UINT64_C(1000000000);
    first.physical_timestamp_ns=past;second.physical_timestamp_ns=past+1u;
    FakeSource source({first,second});MapRouter router;
    router.routes={{1101u,event_a},{1102u,event_b}};
    router.event_names={{event_a,"event-a"},{event_b,"event-b"}};
    DeterministicScorer scorer0,scorer1;
    const auto slow=flowkeep::NativeFusionWorkerShard(event_a,2u);
    (slow==0u?scorer0:scorer1).delay_ms=50u;
    MemoryCommitter committer;flowkeep::NativeFusionServiceReceipt receipt{};std::string error;
    auto config=config_for(2u,1u,2u);config.detector_deadline_ns=UINT64_C(100000000);
    CHECK(flowkeep::RunNativeFusionService(&source,&router,{&scorer0,&scorer1},&committer,config,&receipt,&error));
    CHECK(receipt.out_of_order_worker_completions>=1u);
    CHECK(receipt.deadline_misses==2u);
    CHECK(receipt.first_deadline_miss.present==1u && receipt.first_deadline_miss.sequence==1u);
    CHECK(receipt.first_deadline_miss.physical_enqueue_monotonic_ns==past);
    CHECK(committer.sequences==std::vector<uint64_t>({1u,2u}));
    return true;
}

bool test_first_deadline_miss_latches_first_completion_row() {
    const uint64_t now = now_ns();
    CHECK(now > UINT64_C(1000000000));
    const uint64_t past = now - UINT64_C(1000000000);
    fk_detector_request_v1 first = request_for(1u, 2111u);
    fk_detector_request_v1 second = request_for(2u, 2112u);
    first.physical_timestamp_ns = past;
    second.physical_timestamp_ns = past + 1u;
    FakeSource source({first, second});
    MapRouter router;
    router.routes = {{2111u, 21u}, {2112u, 22u}};
    router.event_names = {{21u, "event-twenty-one"},
        {22u, "event-twenty-two"}};
    DeterministicScorer scorer;
    MemoryCommitter committer;
    flowkeep::NativeFusionServiceConfig config = config_for(1u, 2u, 2u);
    config.worker_batch_wait_ns = UINT64_C(1000000000);
    config.detector_deadline_ns = UINT64_C(100000000);
    flowkeep::NativeFusionServiceReceipt receipt{};
    std::string error;
    CHECK(flowkeep::RunNativeFusionService(
        &source, &router, {&scorer}, &committer, config, &receipt, &error));
    CHECK(error.empty());
    CHECK(receipt.requests_scored == 2u);
    CHECK(receipt.deadline_misses == 2u);
    const flowkeep::NativeFusionFirstDeadlineMissMetrics &miss =
        receipt.first_deadline_miss;
    CHECK(miss.present == 1u);
    CHECK(miss.sequence == 1u);
    CHECK(miss.event_routing_token == 1u);
    CHECK(miss.worker_shard == 0u);
    CHECK(miss.physical_enqueue_monotonic_ns == past);
    CHECK(miss.transport_queue_wait_ns + miss.worker_queue_wait_ns +
            miss.inference_ns == miss.end_to_end_ns);
    CHECK(miss.end_to_end_ns > config.detector_deadline_ns);
    return true;
}

bool test_terminal_completion_records_deadline_miss_once() {
    const uint64_t now = now_ns();
    CHECK(now > UINT64_C(1000000000));
    fk_detector_request_v1 first = request_for(1u, 2121u);
    first.physical_timestamp_ns = now - UINT64_C(1000000000);
    fk_detector_request_v1 unreachable = request_for(2u, 2122u);
    FakeSource source({first, unreachable});
    source.FaultAfterPeekCount(1u);
    MapRouter router;
    router.routes = {{2121u, 23u}, {2122u, 24u}};
    router.event_names = {{23u, "event-twenty-three"},
        {24u, "event-twenty-four"}};
    DeterministicScorer scorer;
    MemoryCommitter committer;
    flowkeep::NativeFusionServiceConfig config = config_for(1u, 1u, 2u);
    config.detector_deadline_ns = UINT64_C(100000000);
    flowkeep::NativeFusionServiceReceipt receipt{};
    std::string error;
    CHECK(!flowkeep::RunNativeFusionService(
        &source, &router, {&scorer}, &committer, config, &receipt, &error));
    CHECK(!error.empty());
    CHECK(receipt.source_failures >= 1u);
    CHECK(receipt.requests_scored == 1u);
    CHECK(receipt.deadline_misses == 1u);
    const flowkeep::NativeFusionFirstDeadlineMissMetrics &miss =
        receipt.first_deadline_miss;
    CHECK(miss.present == 1u);
    CHECK(miss.sequence == 1u);
    CHECK(miss.event_routing_token == 1u);
    CHECK(miss.physical_enqueue_monotonic_ns ==
        first.physical_timestamp_ns);
    CHECK(miss.end_to_end_ns > config.detector_deadline_ns);
    return true;
}

bool test_overdue_coalescing_preserves_decisions_and_miss_accounting() {
    constexpr uint64_t count = 96;
    std::vector<fk_detector_request_v1> requests;
    const uint64_t physical = now_ns() - UINT64_C(1000000000);
    for (uint64_t seq = 1; seq <= count; ++seq) {
        auto request = request_for(seq, 2101u);
        request.physical_timestamp_ns = physical;
        request.checkpoint_packet = 4;
        requests.push_back(request);
    }
    FakeSource source(requests);
    MapRouter router;
    router.routes = {{2101u, 18u}};
    router.event_names = {{18u, "event-eighteen"}};
    DeterministicScorer scorer;
    MemoryCommitter committer;
    auto config = config_for(1u, 32u, 64u);
    config.worker_batch_wait_ns = UINT64_C(20000000);
    config.detector_deadline_ns = UINT64_C(300000000);
    config.detector_schedule = flowkeep::NativeFusionDetectorSchedule::DeadlineGuardBatchFifo;
    flowkeep::NativeFusionServiceReceipt receipt{};
    std::string error;
    const bool success = flowkeep::RunNativeFusionService(&source, &router, {&scorer},
        &committer, config, &receipt, &error);
    if (!success) std::fprintf(stderr, "overdue test: %s\n", error.c_str());
    CHECK(success);
    CHECK(receipt.deadline_misses == count);
    CHECK(receipt.requests_acked == count);
    CHECK(committer.sequences.size() == count);
    for (size_t i = 0; i < count; ++i) CHECK(committer.sequences[i] == i + 1);
    CHECK(scorer.batches.size() < count);
    return true;
}

bool test_deadline_guard_flushes_low_rate_fifo_before_fixed_wait() {
    constexpr uint64_t kBatchWaitNs = UINT64_C(500000000);
    constexpr uint64_t kDeadlineNs = UINT64_C(300000000);
    constexpr uint64_t kDispatchGuardNs = UINT64_C(100000000);

    fk_detector_request_v1 baseline_request = request_for(1u, 2101u);
    const uint64_t baseline_enqueue_ns =
        baseline_request.physical_timestamp_ns;
    FakeSource baseline_source({baseline_request});
    MapRouter baseline_router;
    baseline_router.routes = {{2101u, 18u}};
    baseline_router.event_names = {{18u, "event-eighteen"}};
    DeterministicScorer baseline_scorer;
    MemoryCommitter baseline_committer;
    flowkeep::NativeFusionServiceConfig baseline = config_for(1u, 8u, 8u);
    baseline.worker_batch_wait_ns = kBatchWaitNs;
    baseline.detector_deadline_ns = kDeadlineNs;
    baseline.detector_schedule =
        flowkeep::NativeFusionDetectorSchedule::BatchFifo;
    flowkeep::NativeFusionServiceReceipt baseline_receipt{};
    std::string baseline_error;
    CHECK(flowkeep::RunNativeFusionService(
        &baseline_source, &baseline_router, {&baseline_scorer},
        &baseline_committer, baseline, &baseline_receipt, &baseline_error));
    CHECK(baseline_error.empty());
    CHECK(baseline_scorer.first_call_ns >= baseline_enqueue_ns);
    CHECK(baseline_receipt.detector_schedule ==
        flowkeep::NativeFusionDetectorSchedule::BatchFifo);
    CHECK(baseline_receipt.batch_trigger_wait_timeout == 1u);
    CHECK(baseline_receipt.batch_trigger_deadline_guard == 0u);
    CHECK(baseline_receipt.deadline_misses == 1u);
    const flowkeep::NativeFusionFirstDeadlineMissMetrics &first_miss =
        baseline_receipt.first_deadline_miss;
    CHECK(first_miss.present == 1u);
    CHECK(first_miss.sequence == 1u);
    CHECK(first_miss.event_routing_token == 1u);
    CHECK(first_miss.sequence == first_miss.event_routing_token);
    CHECK(first_miss.worker_shard == 0u);
    CHECK(first_miss.physical_enqueue_monotonic_ns == baseline_enqueue_ns);
    CHECK(first_miss.physical_enqueue_monotonic_ns <=
        first_miss.consumer_receive_monotonic_ns);
    CHECK(first_miss.consumer_receive_monotonic_ns <=
        first_miss.inference_start_monotonic_ns);
    CHECK(first_miss.inference_start_monotonic_ns <=
        first_miss.decision_monotonic_ns);
    CHECK(first_miss.transport_queue_wait_ns ==
        first_miss.consumer_receive_monotonic_ns -
            first_miss.physical_enqueue_monotonic_ns);
    CHECK(first_miss.worker_queue_wait_ns ==
        first_miss.inference_start_monotonic_ns -
            first_miss.consumer_receive_monotonic_ns);
    CHECK(first_miss.inference_ns ==
        first_miss.decision_monotonic_ns -
            first_miss.inference_start_monotonic_ns);
    CHECK(first_miss.end_to_end_ns ==
        first_miss.decision_monotonic_ns -
            first_miss.physical_enqueue_monotonic_ns);
    CHECK(first_miss.transport_queue_wait_ns +
            first_miss.worker_queue_wait_ns + first_miss.inference_ns ==
        first_miss.end_to_end_ns);
    CHECK(first_miss.end_to_end_ns > kDeadlineNs);

    fk_detector_request_v1 guarded_request = request_for(1u, 2101u);
    const uint64_t guarded_enqueue_ns = guarded_request.physical_timestamp_ns;
    FakeSource guarded_source({guarded_request});
    MapRouter guarded_router;
    guarded_router.routes = {{2101u, 18u}};
    guarded_router.event_names = {{18u, "event-eighteen"}};
    DeterministicScorer guarded_scorer;
    MemoryCommitter guarded_committer;
    flowkeep::NativeFusionServiceConfig guarded = config_for(1u, 8u, 8u);
    guarded.worker_batch_wait_ns = kBatchWaitNs;
    guarded.detector_deadline_ns = kDeadlineNs;
    guarded.detector_schedule =
        flowkeep::NativeFusionDetectorSchedule::DeadlineGuardBatchFifo;
    flowkeep::NativeFusionServiceReceipt guarded_receipt{};
    std::string guarded_error;
    CHECK(flowkeep::RunNativeFusionService(
        &guarded_source, &guarded_router, {&guarded_scorer},
        &guarded_committer, guarded, &guarded_receipt, &guarded_error));
    CHECK(guarded_scorer.first_call_ns >= guarded_enqueue_ns);
    CHECK(guarded_receipt.detector_schedule ==
        flowkeep::NativeFusionDetectorSchedule::DeadlineGuardBatchFifo);
    CHECK(guarded_receipt.detector_dispatch_guard_ns == kDispatchGuardNs);
    CHECK(guarded_receipt.batch_trigger_deadline_guard == 1u);
    CHECK(guarded_receipt.batch_trigger_wait_timeout == 0u);
    CHECK(guarded_receipt.deadline_misses == 0u);
    CHECK(guarded_receipt.first_deadline_miss.present == 0u);
    CHECK(guarded_scorer.first_call_ns - guarded_enqueue_ns <
        baseline_scorer.first_call_ns - baseline_enqueue_ns);
    CHECK(guarded_receipt.detector_schedule_uses_retention_signal == 0u);
    CHECK(guarded_receipt.retention_detector_coupling ==
        flowkeep::NativeFusionRetentionDetectorCoupling::Decoupled);
    return true;
}

bool test_both_fifo_schedules_preserve_high_rate_exactly_once_order() {
    constexpr uint64_t kCount = 32u;
    const auto run = [=](flowkeep::NativeFusionDetectorSchedule schedule) {
        struct Result {
            bool success = false;
            flowkeep::NativeFusionServiceReceipt receipt{};
            std::vector<uint64_t> committed;
            std::vector<uint64_t> scored;
            std::vector<uint64_t> acked;
        } result;
        std::vector<fk_detector_request_v1> requests;
        for (uint64_t sequence = 1u; sequence <= kCount; ++sequence)
            requests.push_back(request_for(sequence, 2201u));
        FakeSource source(std::move(requests));
        MapRouter router;
        router.routes = {{2201u, 19u}};
        router.event_names = {{19u, "event-nineteen"}};
        DeterministicScorer scorer;
        MemoryCommitter committer;
        flowkeep::NativeFusionServiceConfig config = config_for(1u, 4u, 32u);
        config.durable_commit_batch_capacity = 8u;
        config.worker_batch_wait_ns = UINT64_C(500000000);
        config.detector_deadline_ns = UINT64_C(1000000000);
        config.detector_schedule = schedule;
        std::string error;
        result.success = flowkeep::RunNativeFusionService(
            &source, &router, {&scorer}, &committer, config,
            &result.receipt, &error);
        result.committed = committer.sequences;
        for (const std::vector<uint64_t> &batch : scorer.batches)
            result.scored.insert(result.scored.end(), batch.begin(), batch.end());
        result.acked = source.ack_log;
        return result;
    };

    const auto baseline = run(
        flowkeep::NativeFusionDetectorSchedule::BatchFifo);
    const auto guarded = run(
        flowkeep::NativeFusionDetectorSchedule::DeadlineGuardBatchFifo);
    std::vector<uint64_t> expected;
    for (uint64_t sequence = 1u; sequence <= kCount; ++sequence)
        expected.push_back(sequence);
    CHECK(baseline.success);
    CHECK(guarded.success);
    CHECK(baseline.committed == expected);
    CHECK(guarded.committed == expected);
    CHECK(baseline.scored == expected);
    CHECK(guarded.scored == expected);
    CHECK(!baseline.acked.empty() && baseline.acked.back() == kCount);
    CHECK(!guarded.acked.empty() && guarded.acked.back() == kCount);
    CHECK(baseline.receipt.requests_peeked == kCount);
    CHECK(baseline.receipt.requests_persisted == kCount);
    CHECK(baseline.receipt.requests_acked == kCount);
    CHECK(guarded.receipt.requests_peeked == kCount);
    CHECK(guarded.receipt.requests_persisted == kCount);
    CHECK(guarded.receipt.requests_acked == kCount);
    CHECK(baseline.receipt.deadline_misses == 0u);
    CHECK(guarded.receipt.deadline_misses == 0u);
    return true;
}

}  // namespace

bool test_packet_one_coverage_continues_through_normal_durable_order() {
    auto initial=checkpoint_for(2u,1814u,40u,1u,1u,1u);
    initial.semantic_timestamp_ns=1u; // same input as OPEN, not a fake timer
    initial.source_mask=0;
    std::vector<fk_detector_request_v1> requests{
        flow_open_for(1u,1814u,40u,1u), initial,
        flow_continue_for(3u,1814u,41u,2u,1u,40u,1u,1u),
        checkpoint_for(4u,1814u,41u,2u,4u,1u)};
    FakeSource source(std::move(requests));
    MapRouter router;router.routes={{1814u,114u}};
    router.event_names={{114u,"initial-coverage-continue"}};
    DeterministicScorer scorer;
    std::vector<flowkeep::NativeFusionBatchScorer *> scorers={&scorer};
    MemoryCommitter committer;
    auto config=config_for(1u,4u,4u);config.require_flow_open=true;
    flowkeep::NativeFusionServiceReceipt receipt{};std::string error;
    CHECK(flowkeep::RunNativeFusionService(&source,&router,scorers,&committer,config,&receipt,&error));
    CHECK(receipt.requests_acked==4u && receipt.checkpoint_records==2u);
    CHECK(receipt.flow_open_records==1u && receipt.flow_continue_records==1u);
    CHECK(receipt.requests_unacked_replayable==0u);
    return true;
}

int main() {
    if(!test_drain_wait_preserves_durable_ack())return 1;
    if(!test_quiescent_feedback_flush_preserves_durable_ack())return 1;
    if(!test_thread_phase_clock_distinguishes_sleep_and_cpu())return 1;
    if(!test_packet_one_coverage_continues_through_normal_durable_order())return 1;
    if(!test_prepared_pipeline_overlaps_and_fails_closed())return 1;
    if (!test_batch_age_guard_saturates_without_resetting_old_work() ||
        !test_history_fence_precedes_ledger_and_failure_never_acks() ||
        !test_flow_open_only_quic_events_receive_live_null_terminals() ||
        !test_flow_open_head_scores_provisional_rows_without_checkpoint_work() ||
        !test_run_wide_flow_state_capacity_fails_closed_without_rehash() ||
        !test_explicit_flow_continue_authorizes_one_successor_generation() ||
        !test_many_continuations_reuse_active_generation_capacity() ||
        !test_checkpoint_cannot_infer_a_missing_flow_continue() ||
        !test_flow_continue_inherits_checkpoint_cursor() ||
        !test_flow_continue_requires_producer_attested_predecessor() ||
        !test_new_tuple_epoch_retains_exact_old_epoch() ||
        !test_scenario_event_two_flows_stays_one_ordered_shard() ||
        !test_generic_source_still_revalidates_every_item() ||
        !test_exact_thread_affinity_is_attested() ||
        !test_overlapping_affinity_roles_are_rejected() ||
        !test_cross_event_out_of_order_completion_commits_prefix_only() ||
        !test_worker_failure_never_commits_or_acks() ||
        !test_producer_overrun_is_terminal_before_ack() ||
        !test_unknown_flow_is_unacked_replayable() ||
        !test_global_semantic_time_regression_never_acks() ||
        !test_transient_write_published_snapshot_is_reread() ||
        !test_persistent_write_published_mismatch_fails_closed() ||
        !test_slow_durable_commit_does_not_block_ingest_or_early_ack() ||
        !test_durable_commit_batch_is_independent_of_scorer_batch() ||
        !test_durable_full_capacity_batches_are_coalesced() ||
        !test_durable_terminal_partial_batch_flushes_once() ||
        !test_durable_max_wait_bounds_low_rate_partial_prefix() ||
        !test_durable_max_wait_uses_physical_head_age() ||
        !test_durable_candidate_window_preserves_physical_misses_and_ack_order() ||
        !test_durable_candidate_window_validation_and_failed_commit() ||
        !test_durable_commit_failure_never_acks() ||
        !test_out_of_order_producer_done_submits_one_terminal_batch() ||
        !test_source_fault_after_durable_commit_never_acks() ||
        !test_positive_durable_route_slice_is_not_preempted_by_completion_wakes() ||
        !test_first_deadline_miss_is_lowest_sequence_across_workers() ||
        !test_first_deadline_miss_latches_first_completion_row() ||
        !test_terminal_completion_records_deadline_miss_once() ||
        !test_overdue_coalescing_preserves_decisions_and_miss_accounting() ||
        !test_deadline_guard_flushes_low_rate_fifo_before_fixed_wait() ||
        !test_both_fifo_schedules_preserve_high_rate_exactly_once_order()) {
        return 1;
    }
    std::puts("fk_native_fusion_service tests passed");
    return 0;
}
