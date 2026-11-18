#ifndef FLOWKEEP_FK_NATIVE_FUSION_JSONL_LEDGER_H
#define FLOWKEEP_FK_NATIVE_FUSION_JSONL_LEDGER_H

#include <stdint.h>

#include <memory>
#include <string>

#include "fk_native_fusion_service.h"

namespace flowkeep {

struct NativeFusionJsonlLedgerConfig {
    std::string output_directory;
    std::string run_uuid_hex;
    double threshold = 0.0;
    uint64_t detector_deadline_ns = 30000000u;
    /* Exact run-wide physical-epoch and frozen-event bounds. Zero keeps the
     * generic/test path dynamically sized; production supplies both values
     * before any row is accepted. */
    uint64_t expected_semantic_chains = 0u;
    uint64_t expected_event_states = 0u;
    /* Enables decision-v5/ledger-v7 provisional FLOW_OPEN scores. */
    bool provisional_flow_open_scores = false;
    // decision-v6/ledger-v8: durable real prefix deposits and EOF completions.
    bool terminal_coverage = false;
    bool defer_compression_to_publish = false;
    bool reuse_payload_buffers = false;
    // Opt-in two-stage I/O: preparation writes/fsyncs an unpublished temporary
    // segment. Ordered publication, after the service history fence, still
    // links without replacement and fsyncs the directory before any ACK.
    // Compression stays on the preparation thread when this option is enabled.
    bool stage_segment_file_in_prepare = false;
    uint32_t prepared_commit_capacity = 2u;
    bool synchronous_wal_segments = false;
    bool group_wal_publication = false;
    // Test-only blocking/failure injection; never enabled by the live adapter.
    bool (*before_wal_write_for_test)(void *) = nullptr;
    void *wal_test_context = nullptr;
};

struct NativeFusionJsonlLedgerAudit {
    bool synchronous_wal_segments = false;
    bool wal_test_hook_enabled = false;
    uint64_t wal_write_calls = 0u, wal_segment_bytes = 0u;
    uint64_t wal_segment_commits=0,wal_group_writes=0,wal_max_group_segments=0;
    uint64_t wal_write_wall_ns = 0u, wal_write_cpu_ns = 0u;
    uint64_t segments_committed = 0u;
    uint64_t decisions_committed = 0u;
    uint64_t first_sequence = 0u;
    uint64_t last_sequence = 0u;
    uint64_t segment_fsync_calls = 0u;
    uint64_t segment_directory_fsync_calls = 0u;
    uint64_t manifest_fsync_calls = 0u;
    uint64_t initial_manifest_fsync_calls = 0u;
    uint64_t commit_manifest_fsync_calls = 0u;
    uint64_t closure_manifest_fsync_calls = 0u;
    uint64_t directory_fsync_calls = 0u;
    uint64_t bytes_committed = 0u;
    uint64_t uncompressed_bytes_committed = 0u;
    bool payload_buffer_reuse_enabled = false;
    uint64_t payload_buffer_moves = 0u;
    uint64_t payload_buffer_moved_bytes = 0u;
    uint64_t payload_buffer_reuse_hits = 0u;
    bool stage_segment_file_in_prepare_enabled = false;
    uint64_t staged_segments_prepared = 0u;
    uint64_t staged_records_prepared = 0u;
    uint64_t staged_payload_bytes_prepared = 0u;
    uint64_t staged_publish_calls = 0u;
    uint64_t staged_publish_succeeded = 0u;
    uint64_t staged_files_outstanding = 0u;
    uint64_t staged_files_peak = 0u;
    uint64_t staged_bytes_outstanding = 0u;
    uint64_t staged_bytes_peak = 0u;
    /* Successful per-segment phase wall timings. Preparation and publication
     * may execute on different threads and overlap across segments; these
     * totals are neither process CPU nor additive end-to-end wall time.
     * Maxima identify a single slow fsync or metadata publication. */
    uint64_t validate_serialize_total_ns = 0u;
    uint64_t validate_serialize_max_ns = 0u;
    uint64_t compression_total_ns = 0u;
    uint64_t compression_max_ns = 0u;
    uint64_t prepare_state_total_ns = 0u;
    uint64_t prepare_state_max_ns = 0u;
    uint64_t segment_open_total_ns = 0u;
    uint64_t segment_open_max_ns = 0u;
    uint64_t segment_write_total_ns = 0u;
    uint64_t segment_write_max_ns = 0u;
    uint64_t segment_file_fsync_total_ns = 0u;
    uint64_t segment_file_fsync_max_ns = 0u;
    uint64_t segment_publish_total_ns = 0u;
    uint64_t segment_publish_max_ns = 0u;
    uint64_t segment_directory_fsync_total_ns = 0u;
    uint64_t segment_directory_fsync_max_ns = 0u;
    uint64_t state_apply_total_ns = 0u;
    uint64_t state_apply_max_ns = 0u;
    /* Correlated phase breakdown for the successful segment with the largest
     * sum of its own measured phase work (including early file staging).
     * This is not its queue-inclusive ACK latency or the run's critical path.
     * Per-phase maxima above can belong to different segments; this record
     * identifies the exact tail batch that can extend shutdown drain. */
    uint64_t slowest_commit_total_ns = 0u;
    uint64_t slowest_commit_segment_index = 0u;
    uint64_t slowest_commit_decisions = 0u;
    uint64_t slowest_commit_validate_serialize_ns = 0u;
    uint64_t slowest_commit_compression_ns = 0u;
    uint64_t slowest_commit_prepare_state_ns = 0u;
    uint64_t slowest_commit_segment_open_ns = 0u;
    uint64_t slowest_commit_segment_write_ns = 0u;
    uint64_t slowest_commit_segment_file_fsync_ns = 0u;
    uint64_t slowest_commit_segment_publish_ns = 0u;
    uint64_t slowest_commit_segment_directory_fsync_ns = 0u;
    uint64_t slowest_commit_state_apply_ns = 0u;
    std::string chain_sha256;
    std::string manifest_json;
    std::string manifest_path;
    uint8_t faulted = 0u;
    uint8_t closed = 0u;
};

/*
 * Exact native writer for flowkeep-atomic-decision-segment-ledger-v6.
 * Each callback creates one deterministic level-1 zstd frame with content
 * size and checksum at decision_segments/segment_%08d.jsonl.zst, fsyncs it,
 * atomically publishes it without replacement, and fsyncs the segment
 * directory.  That
 * independently recoverable segment is the production ACK boundary.  The
 * manifest is an initial/closure snapshot and is not rewritten per commit;
 * after a crash a scanner must ignore temporary files and accept only the
 * gap-free, strictly validated final segment prefix.  It never writes
 * receipt.json.
 */
class NativeFusionJsonlLedger final : public NativeFusionCommitter {
public:
    static std::unique_ptr<NativeFusionJsonlLedger> Create(
        const NativeFusionJsonlLedgerConfig &config,
        std::string *error);

    ~NativeFusionJsonlLedger() override;

    bool SupportsPreparedCommit() const noexcept override { return true; }
    bool SupportsGroupedPublication() const noexcept override;
    bool PublishPreparedGroup(NativeFusionPreparedCommit *const *,size_t,
        NativeFusionCommitResult *,std::string *) noexcept override;
    uint32_t PreparedCommitCapacity() const noexcept override;
    bool SupportsDrainPreparationOverlap() const noexcept override;
    void BeginDrainPreparationOverlap() noexcept override;
    bool PrepareConsecutive(const NativeFusionDecision *, size_t,
        std::unique_ptr<NativeFusionPreparedCommit> *, std::string *) noexcept override;
    bool PublishPrepared(NativeFusionPreparedCommit *, NativeFusionCommitResult *,
        std::string *) noexcept override;

    bool CommitConsecutive(
        const NativeFusionDecision *decisions,
        size_t decision_count,
        NativeFusionCommitResult *result,
        std::string *error) noexcept override;

    bool Audit(
        NativeFusionJsonlLedgerAudit *audit,
        std::string *error) const noexcept;
    bool Close(std::string *error) noexcept;

private:
    bool PublishPreparedInternal(NativeFusionPreparedCommit *,NativeFusionCommitResult *,
        std::string *,bool already_durable) noexcept;
    struct Implementation;
    explicit NativeFusionJsonlLedger(Implementation *implementation) noexcept;
    Implementation *implementation_;
};

}  // namespace flowkeep

#endif
