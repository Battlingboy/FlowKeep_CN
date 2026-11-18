#include "fk_native_event_context.h"
#ifndef FLOWKEEP_FK_NATIVE_FUSION_SERVICE_H
#define FLOWKEEP_FK_NATIVE_FUSION_SERVICE_H

#include <stddef.h>
#include <stdint.h>

#include <memory>
#include <array>
#include <string>
#include <vector>

#include "fk_detector_request_shm_abi.h"
#include "fk_native_seven_state_fusion.h"
#include "fk_thread_phase_clock.h"

namespace flowkeep {

struct NativeFusionDecision;

enum class NativeFusionSourceResult : uint8_t {
    Item = 1u,
    Empty = 2u,
    ProducerDone = 3u,
    Fault = 4u,
};

struct NativeFusionSourceSnapshot {
    uint32_t capacity = 0u;
    uint64_t run_epoch = 0u;
    uint64_t write_sequence = 0u;
    uint64_t published = 0u;
    uint64_t producer_drops = 0u;
    uint64_t producer_overruns = 0u;
    uint64_t producer_fail_closed = 0u;
    uint64_t producer_validation_failures = 0u;
    uint64_t producer_integrity_failures = 0u;
    uint64_t producer_done = 0u;
    uint64_t producer_stop_monotonic_ns = 0u;
    uint64_t read_sequence = 0u;
    uint64_t records_peeked = 0u;
    uint64_t records_acked = 0u;
    uint64_t sequence_gaps = 0u;
    uint64_t consumer_validation_failures = 0u;
    uint64_t ack_rejections = 0u;
    uint64_t unacked_on_close = 0u;
    uint64_t consumer_fault = 0u;
    uint64_t consumer_open_count = 0u;
    uint64_t consumer_close_count = 0u;
    uint64_t consumer_claim_token = 0u;
};

class NativeFusionRequestSource {
public:
    virtual ~NativeFusionRequestSource() = default;
    // A selected-observation source may interleave independent frozen events.
    // Per-event time/order remains checked by routing and the durable ledger.
    virtual bool IndependentEventClocks() const noexcept { return false; }
    // Scheduling hint only, after a verified physical input fence. Selected
    // observations may still remain; this never authorizes early ACK/EOF.
    virtual bool InputFenceReached() const noexcept { return false; }
    // Last Peek completed bounded lifecycle work but emitted no scoring item.
    // This is scheduling progress, never a request, durable ACK or EOF claim.
    virtual bool LastPeekMadeMaintenanceProgress() const noexcept { return false; }

    /*
     * True is reserved for a source whose Peek implementation has already
     * checked the complete fk_detector_request_v1 ABI immediately before it
     * returns Item.  Generic/test sources remain false and are revalidated by
     * the service.  The production SHM source may return true because its
     * read_slot path verifies both the payload checksum and
     * fk_detector_request_v1_valid() on the same copied record.
     */
    virtual bool DeliversValidatedItems() const noexcept { return false; }

    /* Peek never advances the producer-visible durable prefix. */
    virtual NativeFusionSourceResult Peek(
        fk_detector_request_v1 *request,
        uint64_t *sequence,
        std::string *error) noexcept = 0;

    /* ACK may advance only one already persisted consecutive prefix. */
    virtual bool Ack(uint64_t sequence, std::string *error) noexcept = 0;
    // Called only after the real history/ledger commit succeeded, before ACK.
    virtual bool ObserveDurableDecision(const NativeFusionDecision &,
        std::string *) noexcept { return true; }
    virtual bool Snapshot(
        NativeFusionSourceSnapshot *snapshot,
        std::string *error) const noexcept = 0;
    virtual bool Close(std::string *error) noexcept = 0;
};

/*
 * A production router is backed by a frozen, label-blind flow_key,event_id
 * map.  DataCon/DoH/Real may return one event_id for multiple flows in one
 * scenario event; QUIC returns the prebound capture_id||five_tuple event
 * identity.  The exact event unit comes from the frozen event-assets receipt;
 * the service never invents an event by hashing a flow and rejects zero.
 */
class NativeFusionEventRouter {
public:
    virtual ~NativeFusionEventRouter() = default;
    struct Route {
        uint64_t event_token = 0u;
        /* Interned immutable UTF-8 owned by the router for the whole run. */
        const std::string *event_id = nullptr;
    };
    virtual bool Resolve(
        const fk_detector_request_v1 &request,
        Route *route,
        std::string *error) noexcept = 0;
};

/*
 * This exactly matches fk_native_fusion_score_batch().  An adapter owns one
 * native fusion session per worker.  Inputs are strictly sequence ordered;
 * false is a terminal error and must leave model event state uncommitted.
 */
class NativeFusionBatchScorer {
public:
    virtual ~NativeFusionBatchScorer() = default;
    virtual bool WaitHistoryDurable(uint64_t, std::string *) noexcept { return true; }
    virtual bool ScoreBatchWithContext(const fk_native_fusion_request *requests,
        size_t count, const NativeEventContext *, fk_native_fusion_result *results,
        std::string *error) noexcept { return ScoreBatch(requests,count,results,error); }
    virtual bool ScoreBatch(
        const fk_native_fusion_request *requests,
        size_t request_count,
        fk_native_fusion_result *results,
        std::string *error) noexcept = 0;
    virtual bool PhaseProfile(
        fk_native_fusion_phase_profile *) const noexcept { return false; }
    virtual uint64_t CandidateRows() const noexcept { return 0u; }
    virtual uint64_t ActualModelCalls() const noexcept { return 0u; }
    virtual uint64_t SyntheticRows() const noexcept { return 0u; }
    virtual uint64_t ContextPrepareNs() const noexcept { return 0u; }
    virtual uint64_t ContextClearNs() const noexcept { return 0u; }
};

/*
 * Optional packet-1/flow-open detector.  It is deliberately separate from
 * the seven-state checkpoint scorer: the result is provisional until the
 * presentation chain closes.  A later checkpoint supersedes the flow-open
 * score for that semantic flow; a flow that never reaches a checkpoint uses
 * this score as its terminal detector observation.
 */
class NativeFusionFlowOpenScorer {
public:
    virtual ~NativeFusionFlowOpenScorer() = default;
    virtual bool ScoreFlowOpen(
        const fk_flow_key &canonical_key,
        double *score,
        std::string *error) noexcept = 0;
};

/*
 * Detector scheduling is deliberately independent of retention.  BatchFifo
 * is the historical fixed batch-wait policy.  DeadlineGuardBatchFifo keeps
 * exactly the same FIFO order, but bounds that wait by a causal latest-start
 * time derived from physical_enqueue_monotonic_ns and the run-wide detector
 * SLO.  It is not EDF: with one common relative deadline EDF would reduce to
 * FIFO, and no request is reordered here.
 */
enum class NativeFusionDetectorSchedule : uint8_t {
    BatchFifo = 1u,
    DeadlineGuardBatchFifo = 2u,
};

enum class NativeFusionRetentionDetectorCoupling : uint8_t {
    Decoupled = 1u,
};

/*
 * Clock anchor for the durable-commit max-wait guard.  Physical-enqueue
 * measures the complete end-to-end age (receiver transport included);
 * consumer-receive measures only the service-local stall after the SHM
 * record was dequeued.  The decision deadline is independently enforced on
 * physical enqueue, so the durable guard's ack bound is intentionally
 * service-local in the consumer-receive mode.
 */
enum class NativeFusionDurableAgeAnchor : uint8_t {
    PhysicalEnqueue = 1u,
    ConsumerReceive = 2u,
    // Opt-in bounded coalescing after an ordered candidate becomes eligible.
    // The physical detection/ACK latency clocks remain unchanged.
    FirstDurableCandidate = 3u,
};

const char *NativeFusionDurableAgeAnchorName(
    NativeFusionDurableAgeAnchor anchor) noexcept;

const char *NativeFusionDetectorScheduleName(
    NativeFusionDetectorSchedule schedule) noexcept;

struct NativeFusionDecision {
    enum class Kind : uint8_t {
        FlowOpen = 1u,
        Checkpoint = 2u,
        FlowContinue = 3u,
    };
    Kind kind = Kind::Checkpoint;
    uint8_t score_present = 1u;
    uint64_t sequence = 0u;
    uint64_t event_token = 0u;
    const std::string *event_id = nullptr;
    uint32_t worker_shard = 0u;
    fk_flow_key canonical_key{};
    uint32_t flow_index = 0u;
    uint32_t flow_generation = 0u;
    /* Stable semantic generation identity.  Unlike the two fields above,
     * this value survives a bounded FlowTable capacity relocation. */
    uint64_t flow_first_timestamp_ns = 0u;
    /* Nonzero only for FlowContinue; copied from the producer-attested
     * request after the service validates it against the exact ordered
     * semantic-identity state. */
    uint32_t predecessor_flow_index = 0u;
    uint32_t predecessor_flow_generation = 0u;
    uint32_t predecessor_checkpoint_packet = 0u;
    uint32_t checkpoint_packet = 0u;
    uint8_t source_mask = 0u;
    // Ordinary checkpoints retain their exact meaning. An EOF completion is
    // separately tagged and carries the time of its actual packet-1 evidence.
    bool coverage_terminal = false;
    uint64_t coverage_evidence_timestamp_ns = 0u;
    std::shared_ptr<const std::array<float, FK_DETECTOR_REQUEST_FEATURE_COUNT>> coverage_prefix;
    uint64_t semantic_timestamp_ns = 0u;
    uint64_t physical_enqueue_monotonic_ns = 0u;
    uint64_t event_routing_token = 0u;
    uint64_t consumer_receive_monotonic_ns = 0u;
    uint64_t inference_start_monotonic_ns = 0u;
    uint64_t decision_monotonic_ns = 0u;
    uint64_t logical_connection_id = 0u;
    double score = 0.0;
    uint8_t threshold_met = 0u;
    uint8_t first_alert = 0u;
    uint8_t alert_latched = 0u;
};

using NativeFusionDecisionKind = NativeFusionDecision::Kind;

enum class NativeFusionDurability : uint8_t {
    TestOnlyMemory = 0u,
    FsyncRecoverableSegmentDirectory = 1u,
    SyncWriteAheadLog = 2u,
};

struct NativeFusionCommitResult {
    uint64_t completed_monotonic_ns = 0u;
    NativeFusionDurability durability =
        NativeFusionDurability::TestOnlyMemory;
    // Per-batch diagnostics; never part of ledger bytes or ACK eligibility.
    ThreadPhaseTiming serialize_cost, compression_cost, state_cost;
    ThreadPhaseTiming file_sync_cost, directory_sync_cost;
};

struct NativeFusionPreparedCommit {
    virtual ~NativeFusionPreparedCommit() = default;
};

class NativeFusionCommitter {
public:
    virtual ~NativeFusionCommitter() = default;
    // One ordered preparation thread and one ordered publication thread.
    // Prepared state is speculative, never an ACK or a recovery point.
    virtual bool SupportsPreparedCommit() const noexcept { return false; }
    virtual bool SupportsGroupedPublication() const noexcept { return false; }
    virtual bool PublishPreparedGroup(NativeFusionPreparedCommit *const *,size_t,
        NativeFusionCommitResult *,std::string *) noexcept { return false; }
    virtual uint32_t PreparedCommitCapacity() const noexcept {
        return SupportsPreparedCommit() ? 2u : 1u;
    }
    // The preparation stage emits bounded raw bytes; compression is owned by
    // the ordered publisher. The idle coordinator core may assist at drain.
    virtual bool SupportsDrainPreparationOverlap() const noexcept { return false; }
    virtual void BeginDrainPreparationOverlap() noexcept {}
    virtual bool PrepareConsecutive(const NativeFusionDecision *, size_t,
        std::unique_ptr<NativeFusionPreparedCommit> *, std::string *) noexcept {
        return false;
    }
    virtual bool PublishPrepared(NativeFusionPreparedCommit *,
        NativeFusionCommitResult *, std::string *) noexcept { return false; }

    /*
     * The service itself does not claim or emulate fsync.  A production
     * implementation may return FsyncRecoverableSegmentDirectory only after
     * the exact decision prefix is recoverable from a data file whose bytes
     * and directory entry have both completed fsync.  A derived closure
     * manifest need not be on the per-commit ACK path.  ACK happens
     * afterwards. SyncWriteAheadLog instead requires an atomic WAL-enabled
     * synchronous database write of the exact segment and its prefix manifest.
     * It is not reported as a segment-directory fsync.
     */
    virtual bool CommitConsecutive(
        const NativeFusionDecision *decisions,
        size_t decision_count,
        NativeFusionCommitResult *result,
        std::string *error) noexcept = 0;
};

struct NativeFusionServiceConfig {
    uint32_t worker_count = 1u;
    uint32_t batch_capacity = 512u;
    /* Zero preserves the legacy behavior: use batch_capacity. */
    uint32_t durable_commit_batch_capacity = 0u;
    /* Dispatch guard, anchored at physical enqueue, for the oldest decision
     * in the next consecutive durable prefix while the single durable worker
     * is idle.  It is not an ACK or fsync completion bound: an already-running
     * commit may finish after this interval.  Zero preserves legacy immediate
     * submission for library callers; the production CLI supplies a positive
     * default. FirstDurableCandidate is opt-in and requires 1..20000000 ns;
     * its clock begins when an ordered candidate is observed with the writer
     * idle. This bounds intentional additional batching, not OS/IO latency. */
    uint64_t durable_commit_max_wait_ns = 0u;
    NativeFusionDurableAgeAnchor durable_commit_max_wait_age_anchor =
        NativeFusionDurableAgeAnchor::PhysicalEnqueue;
    uint32_t max_inflight = 1024u;
    /* Maximum entries in each run-wide flow identity/coverage map.  This is
     * deliberately independent of max_inflight: max_inflight bounds the
     * instantaneous reorder window, while these maps retain identities for
     * the complete run.  Zero keeps library callers backward compatible by
     * using max_inflight. */
    uint32_t flow_state_capacity = 0u;
    /* Zero preserves the legacy behavior: route up to max_inflight. */
    uint32_t route_quantum = 0u;
    uint64_t worker_batch_wait_ns = 5000000u;
    uint64_t idle_poll_ns = 50000u;
    uint64_t detector_deadline_ns = 30000000u;
    NativeFusionDetectorSchedule detector_schedule =
        NativeFusionDetectorSchedule::BatchFifo;
    /* Only the no-retention-signal path is implemented.  This fail-closed
     * enum prevents a CLI label from inventing a coupled experiment. */
    NativeFusionRetentionDetectorCoupling retention_detector_coupling =
        NativeFusionRetentionDetectorCoupling::Decoupled;
    /* Null preserves the historical no-numeric-score FLOW_OPEN protocol. */
    NativeFusionFlowOpenScorer *flow_open_scorer = nullptr;
    double flow_open_threshold = 0.0;
    /* Optional exact thread placement.  Either all three roles are empty, or
     * every role is present and logical CPUs are disjoint across roles. */
    std::vector<uint32_t> coordinator_cpu_set;
    std::vector<uint32_t> committer_cpu_set;
    std::vector<std::vector<uint32_t>> worker_cpu_sets;
    /* Unit-test sources only.  Production must leave this false. */
    bool allow_test_only_durability = false;
    /* Production v4 requires one preceding FLOW_OPEN/FLOW_CONTINUE control
     * for every presentation generation.
     * The false setting exists only for legacy unit-test fixtures and is
     * rejected unless allow_test_only_durability is also true. */
    bool require_flow_open = true;
};

struct NativeFusionWorkerMetrics {
    uint32_t worker_shard = 0u;
    uint64_t active_batch_wait_ns=0,drain_batch_wait_ns=0,input_fence_transitions=0;
    uint64_t active_phase_batches=0,drain_phase_batches=0,active_phase_rows=0,drain_phase_rows=0;
    uint64_t batch_trigger_input_fence=0;
    uint64_t requests_routed = 0u;
    uint64_t requests_dequeued = 0u;
    uint64_t requests_scored = 0u;
    uint64_t batches_started = 0u;
    uint64_t batches_scored = 0u;
    uint64_t maximum_batch_rows = 0u;
    uint64_t peak_queue_depth = 0u;
    uint64_t terminal_queue_depth = 0u;
    uint64_t maximum_transport_queue_wait_ns = 0u;
    uint64_t maximum_worker_queue_wait_ns = 0u;
    uint64_t maximum_inference_ns = 0u;
    uint64_t maximum_end_to_end_ns = 0u;
    uint64_t batch_trigger_capacity = 0u;
    uint64_t batch_trigger_wait_timeout = 0u;
    uint64_t batch_trigger_deadline_guard = 0u;
    uint64_t batch_trigger_close = 0u;
    uint32_t affinity_cpu_count = 0u;
    uint8_t affinity_requested = 0u;
    uint8_t affinity_attested = 0u;
};

struct NativeFusionFlowStateMapMetrics {
    uint64_t peak_entries = 0u;
    uint64_t terminal_entries = 0u;
    uint64_t post_reserve_bucket_count = 0u;
    uint64_t terminal_bucket_count = 0u;
};

/* Coordinator-observed evidence for the decision that first trips the
 * configured detector deadline.  The timestamps are copied from the exact
 * decision, while the four durations are derived only after timestamp-order
 * validation succeeds. */
struct NativeFusionFirstDeadlineMissMetrics {
    uint8_t present = 0u;
    uint64_t sequence = 0u;
    uint64_t event_routing_token = 0u;
    uint32_t worker_shard = 0u;
    uint64_t physical_enqueue_monotonic_ns = 0u;
    uint64_t consumer_receive_monotonic_ns = 0u;
    uint64_t inference_start_monotonic_ns = 0u;
    uint64_t decision_monotonic_ns = 0u;
    uint64_t transport_queue_wait_ns = 0u;
    uint64_t worker_queue_wait_ns = 0u;
    uint64_t inference_ns = 0u;
    uint64_t end_to_end_ns = 0u;
};

struct NativeFusionCommitTrace {
    uint64_t first_sequence=0, last_sequence=0, oldest_sequence=0;
    uint64_t oldest_enqueue_ns=0, oldest_decision_ns=0, last_decision_ns=0;
    uint64_t submitted_ns=0, prepare_started_ns=0, prepare_finished_ns=0;
    uint64_t history_started_ns=0, history_finished_ns=0;
    uint64_t publish_started_ns=0, publish_finished_ns=0, ack_ns=0;
    ThreadPhaseTiming prepare_cost, history_cost, publish_cost;
    ThreadPhaseTiming serialize_cost, compression_cost, state_cost;
    ThreadPhaseTiming file_sync_cost, directory_sync_cost;
};

struct NativeFusionServiceReceipt {
    bool paged_reorder=false;
    uint64_t reorder_peak_payload_bytes=0,reorder_allocated_bytes_at_end=0,reorder_page_reuses=0;
    std::array<uint64_t,5> coordinator_wait_ns{},coordinator_wait_calls{},coordinator_fence_wait_ns{};
    uint64_t coordinator_notified_wakes=0,coordinator_timeout_wakes=0;
    ThreadPhaseTiming coordinator_fence_to_source_done,coordinator_source_done_to_drained;
    bool drain_preparation_overlap=false;
    uint64_t drain_preparation_batches=0;
    bool drain_preparation_idle_attested=false;
    std::vector<NativeFusionCommitTrace> commit_trace; // bounded to 4096
    uint64_t commit_trace_dropped=0;
    NativeFusionCommitTrace slowest_ack_trace{};
    uint64_t started_monotonic_ns = 0u;
    uint64_t stopped_monotonic_ns = 0u;
    uint64_t requests_peeked = 0u;
    uint64_t requests_routed = 0u;
    uint64_t requests_scored = 0u;
    uint64_t flow_open_records = 0u;
    uint64_t flow_open_records_scored = 0u;
    uint64_t flow_continue_records = 0u;
    uint64_t checkpoint_records = 0u;
    uint64_t flow_open_only_event_terminals = 0u;
    uint64_t requests_persisted = 0u;
    uint64_t requests_acked = 0u;
    uint64_t requests_unacked_replayable = 0u;
    uint64_t scorer_batches = 0u;
    uint64_t durable_commit_submissions = 0u;
    uint64_t durable_commit_calls = 0u;
    uint64_t durable_commit_batch_capacity = 0u;
    uint64_t durable_commit_max_wait_ns = 0u;
    uint64_t durable_commit_trigger_capacity = 0u;
    uint64_t durable_commit_trigger_terminal = 0u;
    // Subset of terminal triggers: input fenced, source awaiting feedback,
    // all routed requests scored in order, and no commit already running.
    uint64_t durable_commit_trigger_quiescent_feedback = 0u;
    uint64_t durable_commit_trigger_max_wait = 0u;
    uint64_t drain_commit_max_wait_ns = 0u;
    // Subset of max-wait triggers under the shorter input-fenced drain window.
    uint64_t durable_commit_trigger_drain_wait = 0u;
    uint64_t durable_commit_failed_calls = 0u;
    uint64_t minimum_durable_commit_batch_rows = 0u;
    uint64_t maximum_durable_commit_batch_rows = 0u;
    /* Decision-ready-to-submit wait; the dispatch guard itself is anchored at
     * physical enqueue. */
    uint64_t maximum_durable_commit_batch_wait_ns = 0u;
    uint64_t durable_commit_total_ns = 0u;
    uint64_t maximum_durable_commit_ns = 0u;
    uint64_t durable_commit_elapsed_ns_sum = 0u;
    uint64_t maximum_durable_commit_elapsed_ns = 0u;
    uint64_t first_durable_commit_submit_monotonic_ns = 0u;
    uint64_t last_durable_commit_completion_monotonic_ns = 0u;
    uint64_t durable_commit_active_span_ns = 0u;
    uint64_t maximum_decision_to_durable_ns = 0u;
    uint64_t maximum_physical_enqueue_to_durable_ns = 0u;
    uint64_t maximum_decision_to_ack_ns = 0u;
    uint64_t maximum_physical_enqueue_to_ack_ns = 0u;
    uint64_t fsync_attested_commit_calls = 0u;
    uint64_t sync_wal_attested_commit_calls = 0u;
    uint64_t ack_calls = 0u;
    uint64_t route_quantum = 0u;
    uint64_t source_maintenance_progress_turns = 0u;
    uint64_t route_quantum_yields = 0u;
    /* Actual bounded coordinator ingress slice.  It equals route_quantum for
     * legacy immediate-commit runs and is capped at the durable-guard slice
     * for positive max-wait runs. */
    uint64_t effective_route_slice_capacity = 0u;
    uint64_t route_slice_yields = 0u;
    uint64_t route_cache_hits = 0u;
    uint64_t route_cache_misses = 0u;
    uint64_t route_bindings_validated = 0u;
    uint64_t frozen_flow_routes = 0u;
    uint64_t flow_state_capacity = 0u;
    uint64_t flow_state_capacity_failures = 0u;
    uint64_t flow_state_runtime_rehashes = 0u;
    NativeFusionFlowStateMapMetrics stable_flow_routes_map;
    NativeFusionFlowStateMapMetrics flow_coverage_map;
    NativeFusionFlowStateMapMetrics active_semantic_generations_map;
    NativeFusionFlowStateMapMetrics event_coverage_map;
    /* Checkpoints whose resident FlowTable handle changed while their exact
     * (canonical key, first timestamp, logical id) identity stayed live. */
    uint64_t capacity_continuation_rebindings = 0u;
    /* Presentation generations removed from resident coverage after an
     * ordered FLOW_CONTINUE made them unreachable. Tuple-reuse FLOW_OPEN
     * epochs stay resident because an original EOF fallback can still refer
     * to the exact older generation after the physical frontier closes. */
    uint64_t superseded_generation_retirements = 0u;
    uint64_t request_validations_performed = 0u;
    uint64_t request_validations_elided = 0u;
    uint64_t peak_inflight = 0u;
    uint64_t out_of_order_worker_completions = 0u;
    uint64_t first_sequence = 0u;
    uint64_t last_sequence = 0u;
    uint64_t last_persisted_sequence = 0u;
    uint64_t last_acked_sequence = 0u;
    uint64_t minimum_physical_enqueue_ns = 0u;
    uint64_t maximum_physical_enqueue_ns = 0u;
    uint64_t maximum_queue_wait_ns = 0u;
    uint64_t maximum_end_to_end_ns = 0u;
    uint64_t deadline_misses = 0u;
    NativeFusionFirstDeadlineMissMetrics first_deadline_miss;
    uint64_t detector_dispatch_guard_ns = 0u;
    uint64_t batch_trigger_input_fence=0;
    uint64_t batch_trigger_capacity = 0u;
    uint64_t batch_trigger_wait_timeout = 0u;
    uint64_t batch_trigger_deadline_guard = 0u;
    uint64_t batch_trigger_close = 0u;
    uint64_t durable_commit_queue_depth = 0u;
    uint64_t durable_commit_peak_depth = 0u;
    uint64_t route_failures = 0u;
    uint64_t timestamp_failures = 0u;
    uint64_t source_failures = 0u;
    uint64_t scorer_failures = 0u;
    uint64_t result_validation_failures = 0u;
    uint64_t commit_failures = 0u;
    uint64_t ack_failures = 0u;
    uint8_t producer_done = 0u;
    uint8_t source_clean = 0u;
    uint8_t completed = 0u;
    uint8_t production_durability_attested = 0u;
    uint8_t durable_sequence_equals_acked_sequence = 0u;
    uint8_t production_service_ready = 0u;
    uint8_t flow_open_coverage_closed = 0u;
    uint8_t flow_state_capacity_closed = 0u;
    uint8_t flow_state_no_runtime_rehash = 0u;
    uint8_t detector_ingest_decoupled_from_durable_fsync = 0u;
    uint8_t detector_schedule_uses_retention_signal = 0u;
    uint8_t ack_after_durable_only = 0u;
    uint8_t source_delivers_validated_items = 0u;
    uint8_t coordinator_affinity_requested = 0u;
    uint8_t coordinator_affinity_attested = 0u;
    uint8_t committer_affinity_requested = 0u;
    uint8_t committer_affinity_attested = 0u;
    uint8_t worker_affinity_plan_requested = 0u;
    uint8_t worker_affinity_plan_attested = 0u;
    NativeFusionDetectorSchedule detector_schedule =
        NativeFusionDetectorSchedule::BatchFifo;
    NativeFusionRetentionDetectorCoupling retention_detector_coupling =
        NativeFusionRetentionDetectorCoupling::Decoupled;
    std::vector<NativeFusionWorkerMetrics> worker_metrics;
    NativeFusionSourceSnapshot final_source{};
};

/* Stable public shard rule used by event-map qualification and tests. */
uint32_t NativeFusionWorkerShard(uint64_t event_id, uint32_t worker_count);

/* Concrete reuse of the existing C++ POSIX-SHM formal consumer ABI. */
std::unique_ptr<NativeFusionRequestSource> OpenNativeFusionShmSource(
    const std::string &shm_name,
    uint64_t expected_run_epoch,
    std::string *error);

/*
 * scorers.size() must equal config.worker_count and each scorer is owned by
 * exactly one worker thread.  The caller owns source/router/scorers/committer.
 */
bool RunNativeFusionService(
    NativeFusionRequestSource *source,
    NativeFusionEventRouter *router,
    const std::vector<NativeFusionBatchScorer *> &scorers,
    NativeFusionCommitter *committer,
    const NativeFusionServiceConfig &config,
    NativeFusionServiceReceipt *receipt,
    std::string *error) noexcept;

}  // namespace flowkeep

#endif
