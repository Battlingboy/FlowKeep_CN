#ifndef FK_ONLINE_COLD_CHECKPOINT_H
#define FK_ONLINE_COLD_CHECKPOINT_H
#include "fk_cold_release_coordinator.h"
#include <chrono>
#include <fstream>
#include <filesystem>
#include <iomanip>
#include <atomic>
namespace flowkeep {
// All owners may share this backend: one bounded queue, one RocksDB WAL and
// one sync per group. The caller must quiesce every owner before Finish().
class OnlineColdBackend {
public:
    OnlineColdBackend(const std::string &path,const std::string &scope,
        std::shared_ptr<NativeRocksDbResources> resources=nullptr,
        size_t capacity=1024,size_t batch_size=64,uint32_t maximum_coalesce_us=50,
        uint64_t maximum_logical_bytes=256ull*1024*1024,size_t expected_owner_count=0,
        bool async_handoff=false,bool snapshot_gc=false,bool final_roots_only=false,bool write_only=false)
        :path_(path),scope_(scope),maximum_coalesce_us_(maximum_coalesce_us),async_handoff_(async_handoff),
         store_(path,scope,std::move(resources),maximum_logical_bytes,CheckedGc(async_handoff,snapshot_gc,final_roots_only),ColdStorageProfile{},write_only),
         queue_(store_,capacity,batch_size,maximum_coalesce_us,async_handoff?0:expected_owner_count,async_handoff),
         final_roots_only_(final_roots_only) {
        if(write_only && !async_handoff)throw std::invalid_argument("write-only storage requires detached handoff");
    }
    ~OnlineColdBackend(){queue_.Stop();WriteReceipt();}
    OnlineColdBackend(const OnlineColdBackend&)=delete;
    OnlineColdBackend &operator=(const OnlineColdBackend&)=delete;
    ColdMigrationQueue &Queue(){return queue_;}
    void SetGainFeedback(std::shared_ptr<EvidenceGainChannel> feedback){queue_.SetGainFeedback(std::move(feedback));}
    const std::string &Path() const{return path_;}
    const std::string &Scope() const{return scope_;}
    ColdMigrationStats Stats() const{return queue_.Stats();}
    ColdEvidenceStoreSyncStats StoreSyncStats() const{return store_.SyncStats();}
    uint64_t MaximumLogicalBytes() const noexcept{return store_.MaximumLogicalBytes();}
    uint64_t LogicalBytes() const{return store_.LogicalBytes();}
    const NativeRocksDbResources *ResourceIdentity() const noexcept{return store_.ResourceIdentity();}
    // Read at the common shutdown boundary, after every owner has joined.
    bool Finished() const noexcept{return finished_;}
    bool AsyncHandoff() const noexcept{return async_handoff_;}
    bool SnapshotGcEnabled() const noexcept{return store_.SnapshotGcEnabled();}
    bool WriteOnly() const noexcept{return store_.WriteOnly();}
    bool FinalRootsOnly() const noexcept{return final_roots_only_;}
    const char *RetentionContract() const noexcept {
        return final_roots_only_ ? "final_roots_only_clean_shutdown_v1" : "all_transition_snapshots_v1";
    }
    bool VerifyRecoveryRoot(const std::string &id) const{return store_.VerifyRecoveryRoot(id);}
    bool VerifyRecoveryRoots(const std::vector<std::string_view> &ids) const{return store_.VerifyRecoveryRoots(ids);}
    bool AnyFailure() const noexcept {return final_failure_.load(std::memory_order_acquire) || queue_.HasWriteFailure();}
    const char *PersistenceMode() const noexcept {
        if(final_roots_only_)return "final_roots_only_clean_shutdown";
        return async_handoff_?"release_after_bounded_snapshot_handoff":"release_after_durable_confirmation";
    }
    int WriterCpu() const{return writer_cpu_;}
    bool BindWriterCpu(int cpu) noexcept {
        if(!queue_.SetWriterCpu(cpu))return false;
        writer_cpu_=cpu;return true;
    }
    bool Finish() noexcept {
        queue_.Stop();
        try {
            const auto s=queue_.Stats();
            finished_=!AnyFailure() && s.accepted==s.written && !s.outstanding && !s.write_failed && !s.stale;
            if(async_handoff_)finished_=finished_ && s.detached_only && s.validated==0 &&
                s.detached_accepted==s.accepted && s.detached_written==s.written &&
                !s.detached_failed && !s.detached_outstanding;
            else finished_=finished_ && !s.detached_only && !s.detached_accepted && !s.detached_written &&
                !s.detached_failed && !s.detached_outstanding && s.validated==s.written;
            if(!finished_)final_failure_.store(true,std::memory_order_release);
            if(!WriteReceipt()){finished_=false;final_failure_.store(true,std::memory_order_release);}
        }catch(...){finished_=false;final_failure_.store(true,std::memory_order_release);}
        return finished_;
    }
    bool WriteReceipt() const noexcept {
        try {
            const auto s=queue_.Stats();const auto sync=store_.SyncStats();
            std::ofstream out(path_+"/online_cold_backend.json");
            out<<"{\"metrics_scope\":\"backend_global\",\"scope\":"<<std::quoted(scope_)
               <<",\"sync_wal\":true,\"writer_cpu\":"<<writer_cpu_
               <<",\"application_write_only\":"<<(WriteOnly()?"true":"false")
               <<",\"rocksdb_number_keys_read\":"<<store_.RocksDbReadKeys()
               <<",\"logical_quota_accounting\":"<<std::quoted(WriteOnly()?"upper_bound_including_duplicate_submissions":"exact_live_key_value_bytes")
               <<",\"persistence_mode\":"<<std::quoted(PersistenceMode())
               <<",\"cold_retention_contract\":"<<std::quoted(RetentionContract())
               <<",\"all_transition_snapshots_persisted\":"<<(final_roots_only_?"false":"true")
               <<",\"async_handoff_enabled\":"<<(async_handoff_?"true":"false")
               <<",\"backend_finish_success\":"<<(finished_&&!AnyFailure()?"true":"false")
               <<",\"snapshot_handoff_is_durable\":false"
               <<",\"utility_competitions\":"<<s.utility_competitions
               <<",\"utility_reorders\":"<<s.utility_reorders
               <<",\"gain_feedback_hits\":"<<s.gain_feedback_hits
               <<",\"gain_feedback_misses\":"<<s.gain_feedback_misses
               <<",\"expired_evidence_candidates\":"<<s.expired_evidence_candidates
               <<",\"utility_schedule_drops\":0"
               <<",\"release_waits_for_durable\":"<<(async_handoff_?"false":"true")
               <<",\"detached_accepted\":"<<s.detached_accepted
               <<",\"detached_written\":"<<s.detached_written
               <<",\"detached_failed\":"<<s.detached_failed
               <<",\"detached_outstanding\":"<<s.detached_outstanding
               <<",\"detached_peak_outstanding\":"<<s.detached_peak_outstanding
               <<",\"detached_backpressure_full\":"<<s.detached_backpressure_full
               <<",\"detached_backpressure_busy\":"<<s.detached_backpressure_busy
               <<",\"queue_batch_capacity\":"<<queue_.BatchSize()
               <<",\"maximum_coalesce_us\":"<<maximum_coalesce_us_
               <<",\"owner_aware_coalescing\":{"<<"\"enabled\":"<<(s.owner_coalesce.enabled?"true":"false")
               <<",\"expected_owners\":"<<s.owner_coalesce.expected_owners
               <<",\"registered_owners\":"<<s.owner_coalesce.registered_owners
               <<",\"closed_owners\":"<<s.owner_coalesce.closed_owners
               <<",\"metadata_bytes\":"<<s.owner_coalesce.metadata_bytes
               <<",\"wait_entries\":"<<s.owner_coalesce.wait_entries
               <<",\"wait_calls\":"<<s.owner_coalesce.wait_calls
               <<",\"wait_total_ns\":"<<s.owner_coalesce.wait_total_ns
               <<",\"wait_max_ns\":"<<s.owner_coalesce.wait_max_ns
               <<",\"flush_all_owners_blocked\":"<<s.owner_coalesce.flush_all_owners_blocked
               <<",\"flush_capacity\":"<<s.owner_coalesce.flush_capacity
               <<",\"flush_deadline\":"<<s.owner_coalesce.flush_deadline
               <<",\"flush_stop\":"<<s.owner_coalesce.flush_stop
               <<",\"waiting_owner_sum_at_flush\":"<<s.owner_coalesce.waiting_owner_sum_at_flush
               <<",\"waiting_owner_max_at_flush\":"<<s.owner_coalesce.waiting_owner_max_at_flush<<"}"
               <<",\"logical_quota_bytes\":"<<store_.MaximumLogicalBytes()
               <<",\"logical_bytes\":"<<store_.LogicalBytes()
               <<",\"records_accepted\":"<<s.accepted<<",\"records_written\":"<<s.written
               <<",\"write_batches\":"<<s.write_batches<<",\"write_failed\":"<<s.write_failed
               <<",\"write_batches_is_sync_count\":false"
               <<",\"sync_write_metrics_scope\":\"save_batch_db_write_including_atomic_gc\""
               <<",\"sync_write_counts_fsync_syscalls\":false"
               <<",\"sync_write_attempts\":"<<sync.sync_write_attempts
               <<",\"sync_write_successes\":"<<sync.sync_write_successes
               <<",\"sync_write_failures\":"<<sync.sync_write_failures
               <<",\"sync_write_total_ns\":"<<sync.sync_write_total_ns
               <<",\"sync_write_max_ns\":"<<sync.sync_write_max_ns
               <<",\"dedup_no_write_batches\":"<<sync.dedup_no_write_batches
               <<",\"dedup_no_write_records\":"<<sync.dedup_no_write_records
               <<",\"write_breakdown\":";sync.breakdown.WriteJson(out);
            out<<",\"snapshot_gc\":";store_.WriteGcJson(out);
            out
               <<",\"validated\":"<<s.validated<<",\"stale\":"<<s.stale
               <<",\"outstanding\":"<<s.outstanding<<",\"queue_capacity\":"<<s.capacity
               <<",\"queue_peak_outstanding\":"<<s.peak_outstanding
               <<",\"queue_slot_object_bytes\":"<<s.slot_object_bytes<<"}\n";
            out.flush();return out.good();
        }catch(...){return false;}
    }
private:
    static bool CheckedGc(bool async_handoff,bool snapshot_gc,bool final_roots_only) {
        if(final_roots_only && (!async_handoff || !snapshot_gc))
            throw std::invalid_argument("final roots mode requires async handoff and snapshot GC");
        if(snapshot_gc && !async_handoff)throw std::invalid_argument("snapshot GC requires detached-only online handoff");
        return snapshot_gc;
    }
    std::string path_,scope_;uint32_t maximum_coalesce_us_;int writer_cpu_=-1;
    bool async_handoff_=false,finished_=false;std::atomic<bool> final_failure_{false};
    mutable ColdEvidenceStore store_;ColdMigrationQueue queue_;
    const bool final_roots_only_;
};
// Sync mode confirms persistence before reuse. Explicit async mode releases
// after a bounded immutable snapshot handoff; only backend Finish can establish
// the final durable shutdown/recovery boundary.
class OnlineColdCheckpoint {
public:
    OnlineColdCheckpoint(const std::string &path,const std::string &scope,
        fk_compact_flow_table *table,std::shared_ptr<NativeRocksDbResources> resources)
        :OnlineColdCheckpoint(path,table,
            std::make_shared<OnlineColdBackend>(path,scope,std::move(resources),128,64,0)) {
        shared_backend_=false;
    }
    OnlineColdCheckpoint(const std::string &receipt_path,fk_compact_flow_table *table,
                         std::shared_ptr<OnlineColdBackend> backend)
        :path_(receipt_path),scope_(CheckedBackend(backend).Scope()),table_(table),
         backend_(std::move(backend)),queue_(backend_->Queue()),owner_id_(queue_.RegisterOwner()),coordinator_(queue_,table,scope_,owner_id_) {
        std::filesystem::create_directories(path_);
    }
    fk_compact_release_guard callbacks(){return {this,&Authorize};}
    bool BindWriterCpu(int cpu) noexcept {
        return backend_->BindWriterCpu(cpu);
    }
    bool AttachLifecycle(bool optional_prefetch=true) {
        lifecycle_={this,&Persist};
        lifecycle_attached_=fk_compact_flow_table_attach_lifecycle_guard(table_,&lifecycle_);
        if(lifecycle_attached_) {
            // In async mode defer returns RETRY and poll only checks failure:
            // no Core freeze/prefetch occurs. Retained control metadata is still
            // charged through the existing bounded lifecycle guard attachment.
            idle_.guard={this,sizeof(idle_)+queue_.OwnerMetadataBytes()+AsyncMetadataBytes(),&DeferIdle,&PollIdle,
                optional_prefetch && !backend_->AsyncHandoff() ? &PrepareOptional : nullptr};
            lifecycle_attached_=fk_compact_flow_table_attach_idle_retirement_guard(table_,&idle_.guard);
        }
        return lifecycle_attached_;
    }
    bool PrepareShutdown() {
        if(shutdown_ready_)return backend_->AsyncHandoff()?HandoffReady():true;
        if(!lifecycle_attached_ || failed_sticky_ || backend_->AnyFailure() || idle_.optional_count)return false;
        const auto start=std::chrono::steady_clock::now();
        if(backend_->AsyncHandoff()) {
            // Final live entries are quiescent. PersistAsync records their IDs
            // at handoff; only Backend::Finish can make them recovery roots.
            shutdown_ready_=fk_compact_flow_table_prepare_shutdown(table_) && !backend_->AnyFailure();
            shutdown_wait_ns_+=static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::nanoseconds>(
                std::chrono::steady_clock::now()-start).count());
            if(!shutdown_ready_){++lifecycle_failures_;failed_sticky_=true;}
            return shutdown_ready_;
        }
        std::vector<ColdEvidence> pending;
        try {
            pending.reserve(kShutdownBatch);shutdown_pending_=&pending;
            const bool captured=fk_compact_flow_table_prepare_shutdown(table_);
            shutdown_ready_=captured && FlushShutdownBatch();
        }catch(...){shutdown_ready_=false;}
        shutdown_pending_=nullptr;
        shutdown_wait_ns_+=static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::nanoseconds>(
            std::chrono::steady_clock::now()-start).count());
        if(shutdown_ready_ && !queue_.CloseOwner(owner_id_))shutdown_ready_=false;
        if(!shutdown_ready_) {++lifecycle_failures_;failed_sticky_=true;}
        return shutdown_ready_;
    }
    bool RecordRecoveryBoundary(uint64_t ack,uint64_t durable,uint64_t input_cursor,uint64_t watermark) {
        if(!ShutdownReady() || ack!=durable || watermark<shutdown_watermark_)return false;
        recovery_ack_=ack;recovery_input_=input_cursor;recovery_watermark_=watermark;
        recovery_boundary_=true;return true;
    }
    // Read only after every owner has joined and remains quiescent. These
    // expose the confirmed clean-shutdown root, not online crash recovery.
    bool HandoffReady() const noexcept {
        return shutdown_ready_ && lifecycle_attached_ && !failed_sticky_ && !backend_->AnyFailure() &&
            !shutdown_pending_ && !idle_.count;
    }
    bool ShutdownReady() const noexcept {
        return HandoffReady() && (!backend_->AsyncHandoff() || backend_->Finished());
    }
    bool AsyncHandoff() const noexcept{return backend_->AsyncHandoff();}
    uint64_t OmittedCheckpointSnapshots() const noexcept{return async_.omitted_checkpoint;}
    uint64_t OmittedLifecycleSnapshots() const noexcept{return async_.omitted_lifecycle;}
    uint64_t HandedOffColdRecords() const noexcept {
        return backend_->AsyncHandoff()?async_.checkpoint_records+async_.lifecycle_records:
            checkpoint_records_confirmed_+lifecycle_records_;
    }
    bool RecoveryBoundaryRecorded() const noexcept {return recovery_boundary_;}
    const std::string &Scope() const noexcept {return scope_;}
    const std::vector<std::string> &ShutdownLiveCoreIds() const noexcept {return shutdown_ids_;}
    uint64_t RecoveryAck() const noexcept {return recovery_ack_;}
    uint64_t RecoveryInputCursor() const noexcept {return recovery_input_;}
    uint64_t RecoveryWatermark() const noexcept {return recovery_watermark_;}
    uint64_t ConfirmedColdRecords() const noexcept {
        return CheckpointRecordsConfirmed()+LifecycleRecordsConfirmed();
    }
    const OnlineColdBackend *Backend() const noexcept {return backend_.get();}
    struct OptionalPrefetchStats {
        uint64_t calls,candidates,submitted,confirmed,hits,batches,maximum_batch,fallbacks;
        size_t pending,shared_pending,shared_peak;
    };
    OptionalPrefetchStats PrefetchStats() const noexcept {
        return {idle_.optional_calls,idle_.optional_candidates,idle_.optional_submitted,
            idle_.optional_confirmed,idle_.optional_hits,idle_.optional_batches,
            idle_.optional_maximum_batch,idle_.optional_fallbacks,idle_.optional_count,
            idle_.count,idle_.shared_peak};
    }
    ~OnlineColdCheckpoint() {
        if(!shared_backend_)backend_->Finish();
        try {
            const auto s=queue_.Stats();std::ofstream out(path_+"/online_checkpoint.json");
            out<<"{\"checkpoint_release_enabled\":true,\"all_release_paths_guarded\":"<<(lifecycle_attached_?"true":"false")<<","
                "\"sync_wal\":true,\"owner_wait_mode\":"<<std::quoted(backend_->AsyncHandoff()?
                    "bounded_snapshot_handoff_backpressure_only_30s":"async_idle_due_optional_prefetch_release_blocking_30s")
                <<",\"persistence_mode\":"<<std::quoted(backend_->PersistenceMode())
                <<",\"cold_retention_contract\":"<<std::quoted(backend_->RetentionContract())
                <<",\"intermediate_snapshots_not_persisted\":"<<(backend_->FinalRootsOnly()?"true":"false")
                <<",\"checkpoint_snapshots_omitted\":"<<async_.omitted_checkpoint
                <<",\"lifecycle_snapshots_omitted\":"<<async_.omitted_lifecycle
                <<",\"release_plans_authorized_without_persistence\":"<<(backend_->FinalRootsOnly()?async_.plans:0)
                <<",\"async_handoff_enabled\":"<<(backend_->AsyncHandoff()?"true":"false")
                <<",\"snapshot_handoff_is_durable\":false"
                <<",\"release_waits_for_durable\":"<<(backend_->AsyncHandoff()?"false":"true")
                <<",\"idle_freeze_enabled\":"<<(backend_->AsyncHandoff()?"false":"true")
                <<",\"checkpoint_records_handed_off\":"<<async_.checkpoint_records
                <<",\"lifecycle_records_handed_off\":"<<async_.lifecycle_records
                <<",\"handoff_plans\":"<<(backend_->FinalRootsOnly()?0:async_.plans)
                <<",\"handoff_ready\":"<<(HandoffReady()?"true":"false")
                <<",\"durable_ready\":"<<(ShutdownReady()?"true":"false")
                <<",\"writer_cpu\":"<<backend_->WriterCpu()<<",\"plans\":"<<plans_<<",\"confirmed_plans\":"<<
                    (backend_->FinalRootsOnly()?0:(backend_->AsyncHandoff()?(backend_->Finished()&&!backend_->AnyFailure()?async_.plans:0):confirmed_))
                <<",\"failed_plans\":"<<failed_<<",\"wait_ns\":"<<wait_ns_
                <<",\"max_wait_ns\":"<<max_wait_ns_
                <<",\"async_enqueue_calls\":"<<async_.enqueue_calls
                <<",\"async_enqueue_total_ns\":"<<async_.enqueue_ns
                <<",\"async_enqueue_max_ns\":"<<async_.enqueue_max_ns
                <<",\"async_enqueue_blocked_calls\":"<<async_.blocked_calls
                <<",\"async_enqueue_blocked_ns\":"<<async_.blocked_ns
                <<",\"async_enqueue_blocked_max_ns\":"<<async_.blocked_max_ns
                <<",\"checkpoint_records_confirmed\":"<<CheckpointRecordsConfirmed()
                <<",\"lifecycle_records\":"<<LifecycleRecordsConfirmed()
                <<",\"lifecycle_failures\":"<<lifecycle_failures_
                <<",\"idle_deferred_capacity\":"<<kIdleCapacity
                <<",\"idle_deferred_metadata_bytes\":"<<(sizeof(idle_)+queue_.OwnerMetadataBytes()+AsyncMetadataBytes())
                <<",\"idle_deferred_base_metadata_bytes\":"<<sizeof(idle_)
                <<",\"owner_coalescing_metadata_bytes\":"<<queue_.OwnerMetadataBytes()
                <<",\"async_handoff_metadata_bytes\":"<<AsyncMetadataBytes()
                <<",\"idle_deferred_submitted\":"<<idle_.submitted
                <<",\"idle_deferred_confirmed\":"<<idle_.confirmed
                <<",\"idle_deferred_pending\":"<<(idle_.count-idle_.optional_count)
                <<",\"idle_deferred_peak\":"<<idle_.peak
                <<",\"optional_prefetch_calls\":"<<idle_.optional_calls
                <<",\"optional_prefetch_candidates\":"<<idle_.optional_candidates
                <<",\"optional_prefetch_submitted\":"<<idle_.optional_submitted
                <<",\"optional_prefetch_confirmed\":"<<idle_.optional_confirmed
                <<",\"optional_prefetch_hits\":"<<idle_.optional_hits
                <<",\"optional_prefetch_batches\":"<<idle_.optional_batches
                <<",\"optional_prefetch_maximum_batch\":"<<idle_.optional_maximum_batch
                <<",\"optional_prefetch_fallbacks\":"<<idle_.optional_fallbacks
                <<",\"optional_prefetch_pending\":"<<idle_.optional_count
                <<",\"lifecycle_shared_pending_capacity\":"<<kIdleCapacity
                <<",\"lifecycle_shared_pending_peak\":"<<idle_.shared_peak
                <<",\"shutdown_batch_capacity\":"<<kShutdownBatch
                <<",\"shutdown_batches\":"<<shutdown_batches_
                <<",\"shutdown_wait_ns\":"<<shutdown_wait_ns_
                <<",\"shutdown_persisted\":"<<(ShutdownReady()?"true":"false")
                <<",\"recovery_boundary_recorded\":"<<(recovery_boundary_?"true":"false")
                <<",\"recovery_ack_sequence\":"<<recovery_ack_
                <<",\"recovery_input_cursor\":"<<recovery_input_
                <<",\"recovery_semantic_watermark_ns\":"<<recovery_watermark_
                <<",\"queue_metrics_scope\":\""<<(shared_backend_?"shared_backend":"private_backend")<<"\""
                <<",\"queue_backend_path\":"<<std::quoted(backend_->Path());
            if(!shared_backend_) {
                out<<",\"records_written\":"<<s.written<<",\"write_batches\":"<<s.write_batches
                   <<",\"write_failed\":"<<s.write_failed<<",\"outstanding\":"<<s.outstanding
                   <<",\"queue_capacity\":"<<s.capacity<<",\"queue_peak_outstanding\":"<<s.peak_outstanding
                   <<",\"queue_slot_object_bytes\":"<<s.slot_object_bytes;
            }
            out<<",\"shutdown_live_core_ids\":[";
            for(size_t i=0;i<shutdown_ids_.size();++i){if(i)out<<",";out<<"\""<<shutdown_ids_[i]<<"\"";}
            out<<"]}\n";
        }catch(...){}
    }
private:
    std::string path_,scope_;fk_compact_flow_table *table_;
    fk_compact_lifecycle_guard lifecycle_{};bool lifecycle_attached_=false,shutdown_ready_=false;
    uint64_t lifecycle_records_=0,lifecycle_failures_=0;
    static constexpr size_t kShutdownBatch=64;
    std::vector<ColdEvidence> *shutdown_pending_=nullptr;
    uint64_t shutdown_batches_=0,shutdown_wait_ns_=0;
    std::vector<std::string> shutdown_ids_;uint64_t shutdown_watermark_=0;
    uint64_t recovery_ack_=0,recovery_input_=0,recovery_watermark_=0;bool recovery_boundary_=false;
    std::shared_ptr<OnlineColdBackend> backend_;bool shared_backend_=true;
    ColdMigrationQueue &queue_;size_t owner_id_;ColdReleaseCoordinator coordinator_;
    uint64_t plans_=0,confirmed_=0,failed_=0,wait_ns_=0,max_wait_ns_=0;bool failed_sticky_=false;
    uint64_t checkpoint_records_confirmed_=0;
    struct AsyncHandoffState {
        uint64_t checkpoint_records=0,lifecycle_records=0,plans=0;
        uint64_t omitted_checkpoint=0,omitted_lifecycle=0;
        uint64_t enqueue_calls=0,enqueue_ns=0,enqueue_max_ns=0;
        uint64_t blocked_calls=0,blocked_ns=0,blocked_max_ns=0;
    } async_;
    // Fixed allowance also covers detached queue/backend counters/control.
    // Existing immutable queue slots are reused; no extra payload batch lives here.
    size_t AsyncMetadataBytes() const noexcept {return backend_->AsyncHandoff()?sizeof(async_)+256:0;}
    uint64_t CheckpointRecordsConfirmed() const noexcept {
        return backend_->AsyncHandoff()?(backend_->Finished()&&!backend_->AnyFailure()?async_.checkpoint_records:0):checkpoint_records_confirmed_;
    }
    uint64_t LifecycleRecordsConfirmed() const noexcept {
        return backend_->AsyncHandoff()?(backend_->Finished()&&!backend_->AnyFailure()?async_.lifecycle_records:0):lifecycle_records_;
    }
    bool EnqueueAsync(const ColdEvidence &record,bool recovery_root=false) noexcept {
        if(backend_->FinalRootsOnly() && !recovery_root)return false;
        const auto until=std::chrono::steady_clock::now()+std::chrono::seconds(30);
        if(failed_sticky_ || backend_->AnyFailure())return false;
        const bool retain=recovery_root || !backend_->SnapshotGcEnabled();
        const auto start=std::chrono::steady_clock::now();
        auto result=queue_.TrySubmitDetached(record,retain);
        if(result==ColdSubmit::Busy || result==ColdSubmit::Full) {
            const auto blocked_start=std::chrono::steady_clock::now();
            result=queue_.WaitSubmitDetached(record,until,retain);
            const uint64_t elapsed=std::chrono::duration_cast<std::chrono::nanoseconds>(
                std::chrono::steady_clock::now()-blocked_start).count();
            ++async_.blocked_calls;async_.blocked_ns+=elapsed;
            async_.blocked_max_ns=std::max(async_.blocked_max_ns,elapsed);
        }
        const uint64_t elapsed=std::chrono::duration_cast<std::chrono::nanoseconds>(
            std::chrono::steady_clock::now()-start).count();
        ++async_.enqueue_calls;async_.enqueue_ns+=elapsed;
        async_.enqueue_max_ns=std::max(async_.enqueue_max_ns,elapsed);
        return result==ColdSubmit::Accepted;
    }
    bool PersistAsync(fk_compact_flow_handle handle,fk_compact_persist_reason reason) noexcept {
        if(failed_sticky_ || backend_->AnyFailure())return FailIdle();
        if(shutdown_ready_ && reason==FK_COMPACT_PERSIST_SHUTDOWN)return true;
        if(shutdown_ready_)return FailIdle();
        if(backend_->FinalRootsOnly() && reason!=FK_COMPACT_PERSIST_SHUTDOWN) {
            if(!ValidateTransient(handle,0))return FailIdle();
            ++async_.omitted_lifecycle;return true;
        }
        try {
            ColdEvidence record;std::string id;
            if(!CaptureColdEvidence(table_,handle,scope_,&record))return FailIdle();
            if(reason==FK_COMPACT_PERSIST_SHUTDOWN) {
                std::string encoded;if(!EncodeColdEvidence(record,&encoded))return FailIdle();
                id=ColdEvidenceStore::Digest(encoded);
                // Reserve the final ID before accepting a snapshot so allocation
                // failure cannot claim a complete handoff with a missing root.
                shutdown_ids_.push_back(id);
            }
            if(!EnqueueAsync(record,reason==FK_COMPACT_PERSIST_SHUTDOWN))return FailIdle();
            ++async_.lifecycle_records;
            if(reason==FK_COMPACT_PERSIST_SHUTDOWN)
                shutdown_watermark_=std::max(shutdown_watermark_,record.snapshot.last_timestamp_ns);
            return !backend_->AnyFailure() || FailIdle();
        }catch(...){return FailIdle();}
    }
    bool AuthorizeAsync(const fk_compact_release_request *requests,size_t count) noexcept {
        const auto start=std::chrono::steady_clock::now();++plans_;bool ok=false;
        try {
            ok=!failed_sticky_ && !backend_->AnyFailure() && !shutdown_ready_ && requests && count &&
                count<=ColdReleaseCoordinator::kCapacity;
            for(size_t i=0;ok && i<count;++i) {
                ok=requests[i].mask && !(requests[i].mask&~FK_COMPONENT_FULL);
                for(size_t j=0;ok && j<i;++j)ok=requests[i].handle.index!=requests[j].handle.index;
            }
            for(size_t i=0;ok && i<count;++i) {
                if(backend_->FinalRootsOnly()) {
                    ok=ValidateTransient(requests[i].handle,requests[i].mask);
                    if(ok)++async_.omitted_checkpoint;
                    continue;
                }
                ColdEvidence record;
                ok=CaptureColdEvidence(table_,requests[i].handle,scope_,&record) &&
                    (requests[i].mask&record.resident_mask)==requests[i].mask && EnqueueAsync(record);
                if(ok)++async_.checkpoint_records;
            }
            ok=ok && !backend_->AnyFailure();
        }catch(...){ok=false;}
        const auto elapsed=static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::nanoseconds>(
            std::chrono::steady_clock::now()-start).count());
        wait_ns_+=elapsed;max_wait_ns_=std::max(max_wait_ns_,elapsed);
        if(ok){++async_.plans;return true;}
        ++failed_;failed_sticky_=true;return false;
    }
    // Owner-thread validation only. This authorizes irreversible release,
    // not a disk write or recovery promise. No payload copy, DB or labels.
    bool ValidateTransient(fk_compact_flow_handle handle,uint8_t requested_mask) noexcept {
        fk_compact_flow_snapshot snapshot{};fk_compact_core_state core{};
        if(!fk_compact_flow_table_snapshot(table_,handle,&snapshot) ||
           !fk_compact_flow_table_capture_core(table_,handle,&core))return false;
        uint8_t resident=0;bool full_tls=false;
        if(fk_compact_flow_table_stat(table_,handle))resident|=FK_COMPONENT_STAT;
        if(fk_compact_flow_table_seq(table_,handle))resident|=FK_COMPONENT_SEQ;
        if(fk_compact_flow_table_resident_ja4(table_,handle,&full_tls))resident|=FK_COMPONENT_JA4;
        return (requested_mask&resident)==requested_mask;
    }
    static constexpr size_t kIdleCapacity=128;
    struct IdlePending {
        fk_compact_flow_handle handle{};ColdMigrationTicket ticket{};
        std::array<char,64> durable_id{};
        bool occupied=false,durable=false,optional=false;
    };
    struct IdleRetirementState {
        fk_compact_idle_retirement_guard guard{};
        std::array<IdlePending,kIdleCapacity> entries{};
        size_t count=0,cursor=0,peak=0,optional_count=0,shared_peak=0;
        uint64_t submitted=0,confirmed=0;
        uint64_t optional_calls=0,optional_candidates=0,optional_submitted=0;
        uint64_t optional_confirmed=0,optional_hits=0,optional_batches=0;
        uint64_t optional_maximum_batch=0,optional_fallbacks=0;
        std::array<fk_compact_flow_handle,64> optional_candidates_buffer{};
    } idle_;
    IdlePending *FindPending(fk_compact_flow_handle handle) noexcept {
        if(!idle_.count)return nullptr;
        for(auto &entry:idle_.entries)if(entry.occupied && entry.handle.index==handle.index &&
            entry.handle.generation==handle.generation)return &entry;
        return nullptr;
    }
    IdlePending *FindIdle(fk_compact_flow_handle handle) noexcept {
        auto *entry=FindPending(handle);return entry && !entry->optional ? entry : nullptr;
    }
    bool FailIdle() noexcept {failed_sticky_=true;++lifecycle_failures_;return false;}
    bool ValidateIdle(IdlePending &entry,bool wait) noexcept {
        if(entry.durable)return true;
        const auto until=std::chrono::steady_clock::now()+std::chrono::seconds(30);
        do {
            std::string id;const auto result=queue_.TryValidate(entry.ticket,table_,scope_,&id,wait?owner_id_:ColdMigrationQueue::kNoOwner);
            if(result==ColdCompletion::DurableCurrent) {
                if(id.size()!=entry.durable_id.size())return FailIdle();
                std::copy(id.begin(),id.end(),entry.durable_id.begin());
                entry.durable=true;
                if(entry.optional)++idle_.optional_confirmed;else ++idle_.confirmed;
                ++lifecycle_records_;return true;
            }
            if(result!=ColdCompletion::Pending && result!=ColdCompletion::Busy)return FailIdle();
            if(!wait)return true;
            std::this_thread::yield();
        }while(std::chrono::steady_clock::now()<until);
        return FailIdle();
    }
    bool CurrentIdleVersion(const IdlePending &entry) noexcept {
        try {
            ColdEvidence record;std::string encoded;
            if(!entry.durable || !CaptureColdEvidence(table_,entry.handle,scope_,&record) ||
                !EncodeColdEvidence(record,&encoded))return FailIdle();
            const auto id=ColdEvidenceStore::Digest(encoded);
            if(id.size()!=entry.durable_id.size() ||
                !std::equal(id.begin(),id.end(),entry.durable_id.begin()))return FailIdle();
            return true;
        }catch(...){return FailIdle();}
    }
    // This is safe inside an atomic checkpoint guard: it returns completed
    // queue credits but does not free a Core, mutate its state, or its budget.
    bool CollectIdleCompletions(bool release_cores,bool drain_all) noexcept {
        if(failed_sticky_)return false;
        if(!idle_.count)return true;
        const size_t probes=drain_all?kIdleCapacity:16;
        for(size_t i=0;i<probes;++i) {
            auto &entry=idle_.entries[idle_.cursor];idle_.cursor=(idle_.cursor+1)%kIdleCapacity;
            if(!entry.occupied)continue;
            if(!ValidateIdle(entry,drain_all))return false;
            if(release_cores && entry.durable && !entry.optional) {
                const auto handle=entry.handle;
                if(!fk_compact_flow_table_release(table_,handle))return FailIdle();
            }
        }
        return !drain_all || !release_cores || idle_.count==idle_.optional_count;
    }
    static fk_compact_idle_retirement_result DeferIdle(void *context,
            fk_compact_flow_table *table,fk_compact_flow_handle handle) noexcept {
        auto &self=*static_cast<OnlineColdCheckpoint*>(context);
        if(table!=self.table_ || self.failed_sticky_ || self.shutdown_ready_ || self.backend_->AnyFailure())
            return FK_COMPACT_IDLE_RETIRE_FAILED;
        if(self.backend_->AsyncHandoff())return FK_COMPACT_IDLE_RETIRE_RETRY;
        if(self.idle_.count==kIdleCapacity)return FK_COMPACT_IDLE_RETIRE_RETRY;
        if(self.FindPending(handle)) {self.FailIdle();return FK_COMPACT_IDLE_RETIRE_FAILED;}
        ColdEvidence record;
        if(!CaptureColdEvidence(table,handle,self.scope_,&record)) {
            self.FailIdle();return FK_COMPACT_IDLE_RETIRE_FAILED;
        }
        ColdMigrationTicket ticket{};ColdSubmit result;
        const auto until=std::chrono::steady_clock::now()+std::chrono::microseconds(50);
        do {
            result=self.queue_.TrySubmit(record,&ticket);
            if(result!=ColdSubmit::Busy)break;
            std::this_thread::yield();
        }while(std::chrono::steady_clock::now()<until);
        if(result==ColdSubmit::Busy || result==ColdSubmit::Full)return FK_COMPACT_IDLE_RETIRE_RETRY;
        if(result!=ColdSubmit::Accepted){self.FailIdle();return FK_COMPACT_IDLE_RETIRE_FAILED;}
        for(auto &entry:self.idle_.entries)if(!entry.occupied) {
            entry.handle=handle;entry.ticket=ticket;entry.occupied=true;entry.durable=false;
            ++self.idle_.count;++self.idle_.submitted;
            self.idle_.peak=std::max(self.idle_.peak,self.idle_.count-self.idle_.optional_count);
            self.idle_.shared_peak=std::max(self.idle_.shared_peak,self.idle_.count);
            return FK_COMPACT_IDLE_RETIRE_DEFERRED;
        }
        self.FailIdle();return FK_COMPACT_IDLE_RETIRE_FAILED;
    }
    static bool PrepareOptional(void *context,fk_compact_flow_table *table,uint64_t target_ns) noexcept {
        auto &self=*static_cast<OnlineColdCheckpoint*>(context);
        if(table!=self.table_ || self.failed_sticky_ || self.shutdown_ready_)return false;
        ++self.idle_.optional_calls;
        // The sorted prefix remains immutable until the runtime finishes the
        // same target; its next packet has not been observed yet.
        if(self.idle_.optional_count)return true;
        if(!self.CollectIdleCompletions(false,false))return false;
        const auto capacity=static_cast<uint32_t>(std::min<size_t>(
            self.idle_.optional_candidates_buffer.size(),kIdleCapacity-self.idle_.count));
        if(!capacity){++self.idle_.optional_fallbacks;return true;}
        uint32_t count=0;
        if(!fk_compact_flow_table_due_optional_batch(table,target_ns,
            self.idle_.optional_candidates_buffer.data(),capacity,&count))return self.FailIdle();
        self.idle_.optional_candidates+=count;
        uint64_t submitted=0;
        for(uint32_t i=0;i<count;++i) {
            const auto handle=self.idle_.optional_candidates_buffer[i];
            if(self.FindPending(handle))return self.FailIdle();
            ColdEvidence record;
            if(!CaptureColdEvidence(table,handle,self.scope_,&record))return self.FailIdle();
            ColdMigrationTicket ticket{};ColdSubmit result;
            const auto until=std::chrono::steady_clock::now()+std::chrono::microseconds(50);
            do {
                result=self.queue_.TrySubmit(record,&ticket);
                if(result!=ColdSubmit::Busy)break;
                std::this_thread::yield();
            }while(std::chrono::steady_clock::now()<until);
            if(result==ColdSubmit::Busy || result==ColdSubmit::Full) {
                ++self.idle_.optional_fallbacks;break;
            }
            if(result!=ColdSubmit::Accepted)return self.FailIdle();
            IdlePending *slot=nullptr;
            for(auto &entry:self.idle_.entries)if(!entry.occupied){slot=&entry;break;}
            if(!slot)return self.FailIdle();
            slot->handle=handle;slot->ticket=ticket;slot->occupied=true;slot->optional=true;
            ++self.idle_.count;++self.idle_.optional_count;++submitted;
            ++self.idle_.optional_submitted;
            if(submitted==1)++self.idle_.optional_batches;
            self.idle_.optional_maximum_batch=std::max(self.idle_.optional_maximum_batch,submitted);
            self.idle_.shared_peak=std::max(self.idle_.shared_peak,self.idle_.count);
        }
        return true;
    }
    static bool PollIdle(void *context,fk_compact_flow_table *table,bool drain_all) noexcept {
        auto &self=*static_cast<OnlineColdCheckpoint*>(context);
        if(self.backend_->AsyncHandoff())return table==self.table_ && !self.failed_sticky_ && !self.backend_->AnyFailure();
        return table==self.table_ && self.CollectIdleCompletions(true,drain_all);
    }
    static OnlineColdBackend &CheckedBackend(const std::shared_ptr<OnlineColdBackend> &backend) {
        if(!backend)throw std::invalid_argument("null online cold backend");
        return *backend;
    }
    bool FlushShutdownBatch() noexcept {
        if(!shutdown_pending_)return false;
        auto &pending=*shutdown_pending_;if(pending.empty())return true;
        std::array<const ColdEvidence*,kShutdownBatch> records{};
        std::array<ColdMigrationTicket,kShutdownBatch> tickets{};
        for(size_t i=0;i<pending.size();++i)records[i]=&pending[i];
        const auto until=std::chrono::steady_clock::now()+std::chrono::seconds(30);
        for(;;) {
            const auto result=queue_.TrySubmitBatch(records.data(),pending.size(),tickets.data());
            if(result==ColdSubmit::Accepted)break;
            if((result!=ColdSubmit::Busy && result!=ColdSubmit::Full) ||
                std::chrono::steady_clock::now()>=until)return false;
            std::this_thread::yield();
        }
        for(size_t i=0;i<pending.size();++i) {
            for(;;) {
                std::string id;const auto result=queue_.TryValidate(tickets[i],table_,scope_,&id,owner_id_);
                if(result==ColdCompletion::DurableCurrent) {
                    try {shutdown_ids_.push_back(std::move(id));}catch(...){return false;}
                    shutdown_watermark_=std::max(shutdown_watermark_,pending[i].snapshot.last_timestamp_ns);
                    ++lifecycle_records_;break;
                }
                if((result!=ColdCompletion::Busy && result!=ColdCompletion::Pending) ||
                    std::chrono::steady_clock::now()>=until)return false;
                std::this_thread::yield();
            }
        }
        ++shutdown_batches_;pending.clear();return true;
    }
    static bool Persist(void *context,fk_compact_flow_table *table,
            fk_compact_flow_handle handle,uint8_t,fk_compact_persist_reason reason) noexcept {
        auto &self=*static_cast<OnlineColdCheckpoint*>(context);
        if(self.failed_sticky_ || self.backend_->AnyFailure())return false;
        if(self.backend_->AsyncHandoff())return self.PersistAsync(handle,reason);
        if(auto *pending=self.FindPending(handle);pending && pending->optional) {
            if(reason==FK_COMPACT_PERSIST_SHUTDOWN)return self.FailIdle();
            if(!self.ValidateIdle(*pending,true) || !self.CurrentIdleVersion(*pending))return false;
            *pending={};--self.idle_.count;--self.idle_.optional_count;
            ++self.idle_.optional_hits;return true;
        }
        if(reason==FK_COMPACT_PERSIST_CORE_RETIRE) {
            if(auto *pending=self.FindIdle(handle)) {
                if(!self.ValidateIdle(*pending,true) || !self.CurrentIdleVersion(*pending))return false;
                *pending={};--self.idle_.count;return true;
            }
        }
        if(self.shutdown_ready_ && reason==FK_COMPACT_PERSIST_SHUTDOWN)return true;
        ColdEvidence record;
        if(!CaptureColdEvidence(table,handle,self.scope_,&record)) {
            ++self.lifecycle_failures_;self.failed_sticky_=true;return false;
        }
        if(reason==FK_COMPACT_PERSIST_SHUTDOWN && self.shutdown_pending_) {
            // table_prepare_shutdown only visits live entries; it does not
            // free them. PrepareShutdown must confirm the final partial batch
            // before setting shutdown_ready_ or allowing destruction.
            try {self.shutdown_pending_->push_back(std::move(record));}
            catch(...){++self.lifecycle_failures_;self.failed_sticky_=true;return false;}
            return self.shutdown_pending_->size()<kShutdownBatch || self.FlushShutdownBatch();
        }
        ColdMigrationTicket ticket{};bool submitted=false;
        const auto until=std::chrono::steady_clock::now()+std::chrono::seconds(30);
        do {
            if(!self.CollectIdleCompletions(false,false))break;
            if(!submitted) {
                const auto result=self.queue_.TrySubmit(record,&ticket);
                if(result==ColdSubmit::Accepted)submitted=true;
                else if(result!=ColdSubmit::Busy && result!=ColdSubmit::Full)break;
            }
            if(submitted) {
                std::string id;const auto result=self.queue_.TryValidate(ticket,table,self.scope_,&id,self.owner_id_);
                if(result==ColdCompletion::DurableCurrent){
                    if(reason==FK_COMPACT_PERSIST_SHUTDOWN) {
                        try {self.shutdown_ids_.push_back(id);}catch(...){break;}
                        self.shutdown_watermark_=std::max(self.shutdown_watermark_,record.snapshot.last_timestamp_ns);
                    }
                    ++self.lifecycle_records_;return true;
                }
                if(result!=ColdCompletion::Busy && result!=ColdCompletion::Pending)break;
            }
            std::this_thread::yield();
        }while(std::chrono::steady_clock::now()<until);
        ++self.lifecycle_failures_;self.failed_sticky_=true;return false;
    }
    static bool Authorize(void *p,const fk_compact_release_request *requests,size_t count) noexcept {
        auto &self=*static_cast<OnlineColdCheckpoint*>(p);
        if(self.failed_sticky_ || self.backend_->AnyFailure())return false;
        if(self.backend_->AsyncHandoff())return self.AuthorizeAsync(requests,count);
        const auto start=std::chrono::steady_clock::now();bool ready=false;
        ++self.plans_;
        const auto cb=self.coordinator_.callbacks();
        do {
            if(!self.CollectIdleCompletions(false,false))break;
            if(cb.authorize(cb.context,requests,count)){ready=true;break;}
            if(self.coordinator_.status()==ColdReleaseCoordinator::Status::Failed)break;
            std::this_thread::yield();
        }while(std::chrono::steady_clock::now()-start<std::chrono::seconds(30));
        const auto elapsed=static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::nanoseconds>(
            std::chrono::steady_clock::now()-start).count());
        self.wait_ns_+=elapsed;self.max_wait_ns_=std::max(self.max_wait_ns_,elapsed);
        if(ready) {
            const auto records=self.coordinator_.count();
            if(self.coordinator_.Finish()) {
                ++self.confirmed_;self.checkpoint_records_confirmed_+=records;return true;
            }
        }
        ++self.failed_;self.failed_sticky_=true;return false;
    }
};
}
#endif
