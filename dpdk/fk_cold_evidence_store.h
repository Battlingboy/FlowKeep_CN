#ifndef FK_COLD_EVIDENCE_STORE_H
#define FK_COLD_EVIDENCE_STORE_H
#include "fk_cold_evidence.h"
#include "fk_native_rocksdb_state.h"
#include "fk_prewritten_wal_env.h"
#include "fk_committed_batch_cache.h"
#include "fk_cold_key_filter.h"
#include <chrono>
#include <array>
#include <atomic>
#include <cstdio>
#include <ostream>
#include <mutex>
#include <time.h>
#include <unordered_set>
#include <unordered_map>
#include <map>
#include <optional>
#include <string_view>
#include <rocksdb/perf_context.h>
#include <rocksdb/iostats_context.h>
#include <rocksdb/statistics.h>
namespace flowkeep {
// Defaults for this candidate only. The historical profile remains explicitly
// selectable by regression fixtures; durability and the shared budget do not
// depend on this physical layout choice.
struct ColdStorageProfile {
    bool prewrite_wal=false;
    size_t memtable_bytes=2u<<20;
    int maximum_write_buffers=2;
    bool committed_batch_cache=true;
    bool negative_key_filter=true;
};
// Thread-local RocksDB durations overlap (e.g. WAL contains the sync wrapper).
// They are diagnostic dimensions, not quantities to add into a total latency.
// Histograms count actual Write attempts, including failed calls; rejected and
// entirely deduplicated batches never enter them. The final bucket is unbounded.
struct ColdEvidenceWriteBreakdown {
    static constexpr std::array<uint64_t,8> batch_bounds{{1,2,4,8,16,32,64,UINT64_MAX}};
    static constexpr std::array<uint64_t,16> latency_bounds_ns{{
        1000,5000,10000,50000,100000,500000,1000000,2000000,
        5000000,10000000,20000000,50000000,100000000,200000000,1000000000,UINT64_MAX}};
    uint64_t samples=0,records_attempted=0;
    uint64_t cpu_samples=0,cpu_clock_failures=0,cpu_total_ns=0,cpu_max_ns=0;
    uint64_t perf_timers_observed_samples=0,io_timers_observed_samples=0,counter_regressions=0;
    uint64_t perf_wal_ns=0,perf_memtable_ns=0,perf_delay_ns=0,perf_scheduling_ns=0;
    uint64_t perf_pre_post_ns=0,perf_thread_wait_ns=0,perf_db_mutex_ns=0,perf_db_condition_ns=0;
    uint64_t io_write_ns=0,io_fsync_ns=0,io_range_sync_ns=0,io_prepare_write_ns=0,io_bytes_written=0;
    uint64_t wal_sync_events=0,wal_bytes=0;
    std::array<uint64_t,batch_bounds.size()> batch_histogram{};
    std::array<uint64_t,latency_bounds_ns.size()> latency_histogram{};
    PrewrittenWalStats wal_prewritten{};
    uint64_t configured_memtable_bytes=0;
    uint64_t detached_prepare_calls=0,detached_prepare_ns=0;
    uint64_t detached_prefetch_calls=0,detached_prefetch_keys=0,detached_prefetch_ns=0;
    uint64_t detached_prefetch_max_value_bytes=0;
    uint64_t committed_cache_allocated_bytes=0,committed_cache_lookups=0,committed_cache_hits=0;
    uint64_t committed_cache_installs=0,committed_cache_install_ns=0,committed_cache_skipped_entries=0;
    uint64_t negative_filter_allocated_bytes=0,negative_filter_set_bits=0;
    uint64_t negative_filter_rebuild_keys=0,negative_filter_rebuild_ns=0;
    uint64_t negative_filter_lookups=0,negative_filter_absent=0;
    uint64_t detached_prefetch_found=0,detached_prefetch_not_found=0;
    int configured_maximum_write_buffers=0;
    void WriteJson(std::ostream &out) const {
        out<<"{\"version\":1,\"enabled\":true,\"scope\":\"db_write_calls_including_failures\","
            "\"timings_are_additive\":false,\"perf_level\":\"kEnableTime\","
            "\"wal_counter_source\":\"rocksdb_statistics\","
            "\"wal_counter_scope\":\"db_statistics_deltas_during_write_calls\","
            "\"wal_sync_counts_fsync_syscalls\":false,\"histogram_bounds_inclusive\":true"
           <<",\"samples\":"<<samples<<",\"records_attempted\":"<<records_attempted
           <<",\"cpu_samples\":"<<cpu_samples<<",\"cpu_clock_failures\":"<<cpu_clock_failures
           <<",\"cpu_total_ns\":"<<cpu_total_ns<<",\"cpu_max_ns\":"<<cpu_max_ns
           <<",\"perf_timers_observed_samples\":"<<perf_timers_observed_samples
           <<",\"io_timers_observed_samples\":"<<io_timers_observed_samples
           <<",\"counter_regressions\":"<<counter_regressions
           <<",\"perf_wal_ns\":"<<perf_wal_ns<<",\"perf_memtable_ns\":"<<perf_memtable_ns
           <<",\"perf_delay_ns\":"<<perf_delay_ns<<",\"perf_scheduling_ns\":"<<perf_scheduling_ns
           <<",\"perf_pre_post_ns\":"<<perf_pre_post_ns<<",\"perf_thread_wait_ns\":"<<perf_thread_wait_ns
           <<",\"perf_db_mutex_ns\":"<<perf_db_mutex_ns<<",\"perf_db_condition_ns\":"<<perf_db_condition_ns
           <<",\"io_write_ns\":"<<io_write_ns<<",\"io_fsync_ns\":"<<io_fsync_ns
           <<",\"io_range_sync_ns\":"<<io_range_sync_ns<<",\"io_prepare_write_ns\":"<<io_prepare_write_ns
           <<",\"io_bytes_written\":"<<io_bytes_written
           <<",\"wal_sync_events\":"<<wal_sync_events<<",\"wal_bytes\":"<<wal_bytes
           <<",\"batch_records_upper_bounds\":";BoundsJson(out,batch_bounds);
        out<<",\"batch_records_histogram\":";ArrayJson(out,batch_histogram);
        out<<",\"write_latency_upper_bounds_ns\":";BoundsJson(out,latency_bounds_ns);
        out<<",\"write_latency_histogram\":";ArrayJson(out,latency_histogram);
        out<<",\"configured_memtable_bytes\":"<<configured_memtable_bytes
           <<",\"configured_maximum_write_buffers\":"<<configured_maximum_write_buffers;
        out<<",\"detached_prepare_calls\":"<<detached_prepare_calls
           <<",\"detached_prepare_ns\":"<<detached_prepare_ns
           <<",\"detached_prefetch_calls\":"<<detached_prefetch_calls
           <<",\"detached_prefetch_keys\":"<<detached_prefetch_keys
           <<",\"detached_prefetch_ns\":"<<detached_prefetch_ns
           <<",\"detached_prefetch_max_value_bytes\":"<<detached_prefetch_max_value_bytes;
        out<<",\"committed_cache_allocated_bytes\":"<<committed_cache_allocated_bytes
           <<",\"committed_cache_lookups\":"<<committed_cache_lookups
           <<",\"committed_cache_hits\":"<<committed_cache_hits
           <<",\"committed_cache_installs\":"<<committed_cache_installs
           <<",\"committed_cache_install_ns\":"<<committed_cache_install_ns
           <<",\"committed_cache_skipped_entries\":"<<committed_cache_skipped_entries;
        out<<",\"negative_filter_allocated_bytes\":"<<negative_filter_allocated_bytes
           <<",\"negative_filter_set_bits\":"<<negative_filter_set_bits
           <<",\"negative_filter_rebuild_keys\":"<<negative_filter_rebuild_keys
           <<",\"negative_filter_rebuild_ns\":"<<negative_filter_rebuild_ns
           <<",\"negative_filter_lookups\":"<<negative_filter_lookups
           <<",\"negative_filter_absent\":"<<negative_filter_absent
           <<",\"detached_prefetch_found\":"<<detached_prefetch_found
           <<",\"detached_prefetch_not_found\":"<<detached_prefetch_not_found
           <<",\"negative_filter_contract\":\"insert_only_rebuild_on_open_positive_requires_exact_lookup\"";
        out<<",\"wal_prewritten\":";wal_prewritten.WriteJson(out);out<<"}";
    }
private:
    template<size_t N> static void ArrayJson(std::ostream &out,const std::array<uint64_t,N> &values) {
        out<<"[";for(size_t i=0;i<N;++i){if(i)out<<",";out<<values[i];}out<<"]";
    }
    template<size_t N> static void BoundsJson(std::ostream &out,const std::array<uint64_t,N> &values) {
        out<<"[";for(size_t i=0;i<N;++i){if(i)out<<",";if(values[i]==UINT64_MAX)out<<"null";else out<<values[i];}out<<"]";
    }
};
// Only SaveBatch DB::Write(sync=true) calls are measured. Opening/binding the
// database, recovery SyncWAL, compaction and individual fsync syscalls are not.
struct ColdEvidenceStoreSyncStats {
    uint64_t sync_write_attempts=0,sync_write_successes=0,sync_write_failures=0;
    uint64_t sync_write_total_ns=0,sync_write_max_ns=0;
    uint64_t dedup_no_write_batches=0,dedup_no_write_records=0;
    ColdEvidenceWriteBreakdown breakdown{};
};
// Synchronous durable writer used by the bounded online migration queue.
// A successful write alone does not authorize releasing a live generation.
class ColdEvidenceBatchWriter {
public:
    virtual ~ColdEvidenceBatchWriter() = default;
    // Success means every returned content ID is durable in the same batch.
    virtual bool SaveBatch(const ColdEvidence *const *records,size_t count,
                           std::string *ids) noexcept = 0;
    virtual bool SaveDetachedBatch(const ColdEvidence *const *records,size_t count,
                                   std::string *ids,const uint8_t *) noexcept {
        return SaveBatch(records,count,ids);
    }
    virtual bool AcknowledgeDetachedBatch(const std::string *,size_t) noexcept {return true;}
};
class ColdEvidenceStore : public ColdEvidenceBatchWriter {
public:
    static rocksdb::BlockBasedTableOptions TableOptions(const std::shared_ptr<rocksdb::Cache> &cache) {
        rocksdb::BlockBasedTableOptions table;
        table.block_cache=cache;
        table.cache_index_and_filter_blocks=true;
        table.index_type=rocksdb::BlockBasedTableOptions::kTwoLevelIndexSearch;
        table.metadata_block_size=4096;
        table.pin_top_level_index_and_filter=false;
        return table;
    }
    ColdEvidenceStore(const std::string &path,const std::string &scope,
                     std::shared_ptr<NativeRocksDbResources> resources=nullptr,
                     uint64_t maximum_logical_bytes=256ull*1024*1024,bool snapshot_gc=false,
                     ColdStorageProfile profile={},bool write_only=false)
        :scope_(scope),maximum_logical_bytes_(maximum_logical_bytes),snapshot_gc_(snapshot_gc),write_only_(write_only),resources_(resources ? std::move(resources) : std::make_shared<NativeRocksDbResources>()) {
        if(write_only_ && snapshot_gc_)throw std::invalid_argument("write-only snapshots cannot use read-based GC");
        if(!maximum_logical_bytes)throw std::invalid_argument("zero cold logical quota");
        if(scope.empty() || scope.size()>256)throw std::invalid_argument("invalid evidence namespace");
        if(profile.memtable_bytes<(64u<<10) || profile.memtable_bytes>(2u<<20) ||
           profile.maximum_write_buffers!=2)
            throw std::invalid_argument("cold profile exceeds bounded memtable allocation");
        if(snapshot_gc_ && profile.committed_batch_cache) {
            const uint64_t bounded_quota=std::min<uint64_t>(maximum_logical_bytes_,256ull<<20);
            // Split the existing allocation; do not increase the total fixed
            // cache+filter budget. Last-batch values still cover collectible
            // blobs; the filter covers unseen blob/root/entity identities.
            const unsigned split=profile.negative_key_filter?2:1;
            committed_cache_.Configure(bounded_quota/(256*split),bounded_quota/(65536*split));
            if(profile.negative_key_filter)negative_filter_.Configure(bounded_quota/512);
        }
        sync_stats_.breakdown.committed_cache_allocated_bytes=committed_cache_.AllocatedBytes();
        sync_stats_.breakdown.negative_filter_allocated_bytes=negative_filter_.AllocatedBytes();
        rocksdb::Options options;options.create_if_missing=true;options.paranoid_checks=true;
        options.error_if_exists=write_only_;
        if(profile.prewrite_wal) {
            wal_env_=std::make_unique<PrewrittenWalEnv>(path);options.env=wal_env_->Env();
        }
        sync_stats_.breakdown.wal_prewritten.enabled=profile.prewrite_wal;
        sync_stats_.breakdown.configured_memtable_bytes=profile.memtable_bytes;
        sync_stats_.breakdown.configured_maximum_write_buffers=profile.maximum_write_buffers;
        statistics_=rocksdb::CreateDBStatistics();
        // Native tickers distinguish Write calls from WAL sync events. All
        // native histograms/timers are disabled; our fixed histograms suffice.
        statistics_->set_stats_level(rocksdb::StatsLevel::kExceptHistogramOrTimers);
        options.statistics=statistics_;
        options.write_buffer_size=profile.memtable_bytes;
        options.max_write_buffer_number=profile.maximum_write_buffers;options.max_background_jobs=2;
        options.max_open_files=128;options.write_buffer_manager=resources_->write_buffers;
        const auto table=TableOptions(resources_->block_cache);
        options.table_factory.reset(rocksdb::NewBlockBasedTableFactory(table));
        rocksdb::DB *raw=nullptr;require(rocksdb::DB::Open(options,path,&raw));db_.reset(raw);
        write_.sync=true;write_.disableWAL=false;
        const std::string binding=std::string(kColdRecordSchema)+(snapshot_gc_?":detached-lease-gc-v1:quota=":":quota=")+std::to_string(maximum_logical_bytes_)+":"+scope;
        if(write_only_) {
            // Fresh DB required by Open(error_if_exists). No historical
            // index, payload or dedup reads are necessary in append mode.
            const std::string mode_binding=binding+":write-only-blobs-v1";
            logical_bytes_=std::string("binding").size()+mode_binding.size()+
                std::string("meta/logical-bytes").size()+8u;
            if(logical_bytes_>maximum_logical_bytes_)throw std::runtime_error("write-only binding exceeds quota");
            rocksdb::WriteBatch batch;
            batch.Put("binding",mode_binding);
            batch.Put("meta/logical-bytes",EncodeCount(logical_bytes_));
            require(db_->Write(write_,&batch));
            logical_bytes_valid_=true;
            return;
        }
        std::string previous;auto status=db_->Get(rocksdb::ReadOptions(),"binding",&previous);
        if(status.IsNotFound()) {
            std::unique_ptr<rocksdb::Iterator> it(db_->NewIterator(rocksdb::ReadOptions()));it->SeekToFirst();require(it->status());
            if(it->Valid())throw std::runtime_error("unbound nonempty evidence database");
            if(snapshot_gc_) {
                const uint64_t initial=std::string("binding").size()+binding.size()+std::string("meta/logical-bytes").size()+8;
                if(initial>maximum_logical_bytes_)throw std::runtime_error("GC binding exceeds quota");
                rocksdb::WriteBatch batch;batch.Put("binding",binding);batch.Put("meta/logical-bytes",EncodeCount(initial));
                require(db_->Write(write_,&batch));
            }else require(db_->Put(write_,"binding",binding));
        }else {
            require(status);if(previous!=binding)throw std::runtime_error("evidence namespace mismatch");
            // Reopening after an uncertain write must not turn visible but
            // unsynced WAL bytes into a successful read-only retry.
            require(db_->SyncWAL());
        }
        if(negative_filter_.AllocatedBytes()) {
            const auto start=std::chrono::steady_clock::now();
            rocksdb::ReadOptions read;read.fill_cache=false;read.verify_checksums=true;
            std::unique_ptr<rocksdb::Iterator> it(db_->NewIterator(read));
            for(it->SeekToFirst();it->Valid();it->Next()) {
                const auto key=it->key();negative_filter_.Add(std::string_view(key.data(),key.size()));
                ++sync_stats_.breakdown.negative_filter_rebuild_keys;
            }
            require(it->status());
            sync_stats_.breakdown.negative_filter_set_bits=negative_filter_.SetBits();
            sync_stats_.breakdown.negative_filter_rebuild_ns=std::chrono::duration_cast<std::chrono::nanoseconds>(
                std::chrono::steady_clock::now()-start).count();
        }
    }
    // A returned content ID certifies a synced WAL write, not permission to
    // free a live flow. The controller must still validate its exact version.
    std::string Save(const ColdEvidence &record) {
        const ColdEvidence *input=&record;std::string id;
        if(!SaveBatch(&input,1,&id))throw std::runtime_error("cold evidence commit failed");
        return id;
    }
    bool SaveBatch(const ColdEvidence *const *records,size_t count,std::string *ids) noexcept override {
        try {
            if(snapshot_gc_)return RejectBatch("managed store requires detached reference contract");
            if(!records || !ids || !count || count>65536)return RejectBatch("invalid batch arguments");
            std::lock_guard<std::mutex> lock(write_mutex_);
            if(write_failed_)return RejectBatch("previous uncertain write");
            if(write_only_)return SaveWriteOnlyLocked(records,count,ids);
            if(count==1)return SaveOneLocked(records[0],ids);
            // RocksDB holds the exclusive DB lock for this store's lifetime.
            // Only successful synced writes advance this cached quota counter.
            uint64_t used=LogicalBytesLocked();
            rocksdb::WriteBatch batch;
            std::unordered_set<std::string> examined_blobs;
            std::unordered_map<std::string,PendingEntity> entities;
            examined_blobs.reserve(count);entities.reserve(count);
            std::vector<std::string> prepared;prepared.reserve(count);
            for(size_t i=0;i<count;++i) {
                std::string encoded;
                if(!PrepareRecord(records[i],&encoded))return false;
                prepared.push_back(Digest(encoded));const std::string key="blob/"+prepared.back();
                const std::string entity=EntityKey(*records[i]);
                auto insertion=entities.emplace(entity,PendingEntity{});
                auto &pending=insertion.first->second;
                if(insertion.second) {
                    auto status=db_->Get(rocksdb::ReadOptions(),entity,&pending.original_id);
                    if(status.IsNotFound()) {
                        if(!Charge(entity.size()+64,&used))return false;
                    }else {
                        require(status);pending.has_cursor=true;
                        if(pending.original_id==prepared.back()) {
                            // The blob check below proves exact content equality;
                            // decoding that identical record adds no validation.
                            pending.cursor=SemanticCursor(*records[i]);
                        }else {
                            ColdEvidence prior;
                            if(!Load(pending.original_id,&prior))throw std::runtime_error("dangling cold index");
                            if(EntityKey(prior)!=entity)throw std::runtime_error("corrupt cold index");
                            pending.cursor=SemanticCursor(prior);
                        }
                    }
                }
                const SemanticCursor candidate(*records[i]);
                if(pending.has_cursor && candidate.RegressesFrom(pending.cursor))return RejectBatch("semantic cursor regression");
                pending.has_cursor=true;pending.cursor=candidate;pending.latest_id=prepared.back();
                // A blob is immutable and is written at most once in this batch.
                // Existing bytes must equal the freshly validated/hash-addressed
                // encoding: never silently repair corrupted durable evidence.
                if(examined_blobs.insert(key).second) {
                    std::string previous;
                    const auto status=db_->Get(rocksdb::ReadOptions(),key,&previous);
                    if(status.IsNotFound()) {
                        if(pending.original_id==prepared.back())throw std::runtime_error("dangling cold index");
                        if(!Charge(key.size()+encoded.size(),&used))return false;
                        batch.Put(key,encoded);
                    }else {
                        require(status);
                        if(previous!=encoded)throw std::runtime_error("corrupt cold evidence");
                    }
                }
            }
            for(const auto &entry:entities) {
                const auto &pending=entry.second;
                if(pending.latest_id!=pending.original_id)batch.Put(entry.first,pending.latest_id);
            }
            if(used!=logical_bytes_)batch.Put("meta/logical-bytes",EncodeCount(used));
            // Identical content and the same latest pointer were already synced.
            // A read-only retry needs neither WAL bytes nor another fdatasync.
            if(batch.Count()) {
                // After an uncertain Write, no read-only retry may certify
                // potentially unsynced bytes. Fail closed until DB reopen.
                logical_bytes_valid_=false;write_failed_=true;
                SyncWriteLocked(&batch,count);
                logical_bytes_=used;logical_bytes_valid_=true;write_failed_=false;
            }else {++sync_stats_.dedup_no_write_batches;sync_stats_.dedup_no_write_records+=count;}
            for(size_t i=0;i<count;++i)ids[i]=std::move(prepared[i]);
            return true;
        }catch(const std::exception &error){return RejectBatch(error.what());}
        catch(...){return RejectBatch("unknown exception");}
    }
    bool Load(const std::string &id,ColdEvidence *output) {
        if(id.size()!=64)return false;
        std::string encoded;auto status=db_->Get(rocksdb::ReadOptions(),"blob/"+id,&encoded);
        if(status.IsNotFound())return false;
        require(status);
        if(Digest(encoded)!=id || !DecodeColdEvidence(encoded,scope_,output))throw std::runtime_error("corrupt cold evidence");
        return true;
    }
    // Stable across allocator handle reuse: canonical key + semantic epoch + logical ID.
    static std::string EntityKey(const ColdEvidence &record) {
        cold_codec::Wire w;auto key=record.snapshot.key;
        w.field(key.ip_version);w.field(key.protocol);w.array(key.low_addr);w.array(key.high_addr);
        w.field(key.low_port);w.field(key.high_port);
        auto epoch=record.snapshot.first_timestamp_ns;auto logical=record.core.logical_connection_id;
        w.field(epoch);w.field(logical);return "entity/"+Digest(w.bytes);
    }
    bool LoadLatest(const ColdEvidence &identity,ColdEvidence *output) {
        if(snapshot_gc_)throw std::runtime_error("latest historical payload unavailable in detached lease mode");
        if(identity.scope!=scope_)return false;
        std::string id;auto status=db_->Get(rocksdb::ReadOptions(),EntityKey(identity),&id);
        if(status.IsNotFound())return false;
        require(status);
        return Load(id,output);
    }
    uint64_t LogicalBytes() const {
        std::lock_guard<std::mutex> lock(write_mutex_);return LogicalBytesLocked();
    }
    uint64_t MaximumLogicalBytes() const noexcept {return maximum_logical_bytes_;}
    const NativeRocksDbResources *ResourceIdentity() const noexcept {return resources_.get();}
    ColdEvidenceStoreSyncStats SyncStats() const {
        // Existing writer exclusion provides a consistent snapshot without
        // adding atomics or allocations to the write path. Final receipts read
        // this after stopping the queue; live readers may wait for a commit.
        std::lock_guard<std::mutex> lock(write_mutex_);auto stats=sync_stats_;
        if(wal_env_)stats.breakdown.wal_prewritten=wal_env_->Stats();
        return stats;
    }
    bool SnapshotGcEnabled() const noexcept {return snapshot_gc_;}
    bool WriteOnly() const noexcept{return write_only_;}
    uint64_t RocksDbReadKeys() const noexcept {
        return statistics_->getTickerCount(rocksdb::NUMBER_KEYS_READ);
    }
    bool VerifyRecoveryRoots(const std::vector<std::string_view> &ids) {
        std::lock_guard<std::mutex> lock(write_mutex_);
        constexpr size_t kBatch=512;
        for(size_t begin=0;begin<ids.size();begin+=kBatch) {
            const size_t count=std::min(kBatch,ids.size()-begin);
            const size_t keys_per_id=snapshot_gc_?2u:1u;
            std::vector<std::string> keys;keys.reserve(count*keys_per_id);
            for(size_t offset=0;offset<count;++offset) {
                const auto id=ids[begin+offset];
                if(id.size()!=64)return false;
                if(snapshot_gc_)keys.push_back("root/"+std::string(id));
                keys.push_back("blob/"+std::string(id));
            }
            std::vector<rocksdb::Slice> slices;slices.reserve(keys.size());
            for(const auto &key:keys)slices.emplace_back(key);
            std::vector<rocksdb::PinnableSlice> values(keys.size());
            std::vector<rocksdb::Status> statuses(keys.size());
            db_->MultiGet(rocksdb::ReadOptions(),db_->DefaultColumnFamily(),keys.size(),
                slices.data(),values.data(),statuses.data(),false);
            size_t key=0;
            for(size_t offset=0;offset<count;++offset) {
                if(snapshot_gc_) {
                    if(statuses[key].IsNotFound())return false;
                    require(statuses[key]);
                    if(values[key].ToString()!="1")throw std::runtime_error("invalid recovery root");
                    ++key;
                }
                if(statuses[key].IsNotFound())return false;
                require(statuses[key]);
                const std::string encoded=values[key].ToString();
                ColdEvidence record;
                if(Digest(encoded)!=ids[begin+offset] ||
                   !DecodeColdEvidence(encoded,scope_,&record))
                    throw std::runtime_error("corrupt cold evidence");
                ++key;
            }
        }
        return true;
    }
    bool VerifyRecoveryRoot(const std::string &id) {
        return VerifyRecoveryRoots({std::string_view(id)});
    }
    void WriteGcJson(std::ostream &out) const {
        std::lock_guard<std::mutex> lock(write_mutex_);
        std::string state;
        // GC is disabled in write-only mode. Even shutdown diagnostics must
        // not query an absent GC record from the DB.
        if(!write_only_) {
            const auto status=db_->Get(rocksdb::ReadOptions(),"meta/gc-state",&state);
            if(!status.IsNotFound())require(status);
        }
        if(state.empty())state=std::string(32,'\0')+std::string(64,'0');
        if(state.size()!=96)throw std::runtime_error("invalid GC state");
        out<<"{\"enabled\":"<<(snapshot_gc_?"true":"false")
           <<",\"contract\":\""<<(snapshot_gc_?"detached_handoff_and_pinned_clean_shutdown_roots":"immutable_history")<<"\""
           <<",\"historical_payload_archive\":"<<(snapshot_gc_?"false":"true")<<",\"online_crash_recovery_supported\":false"
           <<",\"retired_blobs\":"<<DecodeCount(state.substr(0,8))
           <<",\"retired_blob_bytes\":"<<DecodeCount(state.substr(8,8))
           <<",\"protected_roots\":"<<DecodeCount(state.substr(16,8))
           <<",\"peak_logical_bytes\":"<<DecodeCount(state.substr(24,8))
           <<",\"commit_chain_sha256\":\""<<state.substr(32)<<"\""
           <<",\"unacknowledged_batch_ids\":"<<inflight_ids_.size()
           <<",\"acknowledged_gc_candidates\":"<<collectible_ids_.size()<<"}";
    }
    bool SaveDetachedBatch(const ColdEvidence *const *records,size_t count,std::string *ids,
                           const uint8_t *retain) noexcept override {
        if(!snapshot_gc_)return SaveBatch(records,count,ids);
        try {
            if(!records || !ids || !retain || !count || count>65536)return RejectBatch("invalid detached batch");
            std::lock_guard<std::mutex> lock(write_mutex_);
            if(write_failed_ || !inflight_ids_.empty())return RejectBatch("uncertain write or unacknowledged detached batch");
            const auto preparation_start=std::chrono::steady_clock::now();
            uint64_t used=LogicalBytesLocked();
            std::map<std::string,std::optional<std::string>> changes;
            // Immutable batch-local base under the existing writer mutex.
            // Staged updates override it for repeated entities, quota and
            // root promotion. The optional fixed last-COMMITTED-batch cache
            // supplies only exact DB values under this same writer mutex.
            std::map<std::string,std::optional<std::string>> base;
            const auto get=[&](const std::string &key)->std::optional<std::string> {
                const auto staged=changes.find(key);if(staged!=changes.end())return staged->second;
                const auto original=base.find(key);
                if(original==base.end())throw std::runtime_error("unprefetched detached GC key");
                return original->second;
            };
            const auto put=[&](const std::string &key,std::optional<std::string> value) {
                const auto prior=get(key);
                if(prior) {
                    const uint64_t charge=key.size()+prior->size();
                    if(charge>used)throw std::runtime_error("GC quota underflow");
                    used-=charge;
                }
                if(value) {
                    const uint64_t charge=key.size()+value->size();
                    if(charge>UINT64_MAX-used)throw std::runtime_error("GC quota overflow");
                    used+=charge;
                }
                changes[key]=std::move(value);
            };
            std::vector<std::string> prepared,encoded,transient;
            prepared.reserve(count);encoded.reserve(count);transient.reserve(count);
            std::unordered_set<std::string> incoming;
            for(size_t index=0;index<count;++index) {
                if(retain[index]>1)return RejectBatch("invalid detached root flag");
                encoded.emplace_back();if(!PrepareRecord(records[index],&encoded.back()))return false;
                prepared.push_back(Digest(encoded.back()));incoming.insert(prepared.back());
            }
            base.emplace("meta/gc-state",std::nullopt);
            for(const auto &id:collectible_ids_) {
                base.emplace("blob/"+id,std::nullopt);base.emplace("root/"+id,std::nullopt);
            }
            for(size_t index=0;index<count;++index) {
                base.emplace("blob/"+prepared[index],std::nullopt);
                base.emplace("root/"+prepared[index],std::nullopt);
                base.emplace("cursor/"+EntityKey(*records[index]).substr(7),std::nullopt);
            }
            {
                const auto prefetch_start=std::chrono::steady_clock::now();
                std::vector<rocksdb::Slice> keys;keys.reserve(base.size());
                using BaseEntry=decltype(base)::value_type;
                std::vector<BaseEntry*> misses;misses.reserve(base.size());
                auto &profile=sync_stats_.breakdown;
                for(auto &entry:base) {
                    ++profile.committed_cache_lookups;
                    if(committed_cache_.Find(entry.first,&entry.second))++profile.committed_cache_hits;
                    else {
                        ++profile.negative_filter_lookups;
                        if(!negative_filter_.MayContain(entry.first))++profile.negative_filter_absent;
                        else {keys.emplace_back(entry.first);misses.push_back(&entry);}
                    }
                }
                std::vector<rocksdb::PinnableSlice> values(keys.size());
                std::vector<rocksdb::Status> statuses(keys.size());
                if(!keys.empty())db_->MultiGet(rocksdb::ReadOptions(),db_->DefaultColumnFamily(),keys.size(),
                    keys.data(),values.data(),statuses.data(),true);
                uint64_t value_bytes=0;
                for(size_t index=0;index<misses.size();++index) {
                    if(!statuses[index].IsNotFound()) {
                        require(statuses[index]);misses[index]->second=values[index].ToString();
                        ++profile.detached_prefetch_found;
                    }else ++profile.detached_prefetch_not_found;
                }
                // Preserve the original field's scope: all materialized base
                // values, including cache hits, not only bytes fetched by DB.
                for(const auto &entry:base)if(entry.second)value_bytes+=entry.second->size();
                ++profile.detached_prefetch_calls;profile.detached_prefetch_keys+=keys.size();
                profile.detached_prefetch_ns+=std::chrono::duration_cast<std::chrono::nanoseconds>(
                    std::chrono::steady_clock::now()-prefetch_start).count();
                profile.detached_prefetch_max_value_bytes=std::max(profile.detached_prefetch_max_value_bytes,value_bytes);
            }
            std::string state=get("meta/gc-state").value_or(std::string(32,'\0')+std::string(64,'0'));
            if(state.size()!=96)throw std::runtime_error("invalid GC state");
            uint64_t retired=DecodeCount(state.substr(0,8)),retired_bytes=DecodeCount(state.substr(8,8));
            uint64_t roots=DecodeCount(state.substr(16,8)),peak=DecodeCount(state.substr(24,8));
            std::string chain=state.substr(32);
            for(const auto &id:collectible_ids_) {
                if(incoming.count(id) || get("root/"+id))continue;
                const std::string key="blob/"+id;const auto prior=get(key);
                if(!prior)continue;
                if(Digest(*prior)!=id)throw std::runtime_error("corrupt GC candidate");
                ++retired;retired_bytes+=key.size()+prior->size();chain+="D"+id;
                put(key,std::nullopt);
            }
            for(size_t index=0;index<count;++index) {
                const auto &id=prepared[index];const std::string key="blob/"+id;
                const auto prior=get(key);
                if(prior && *prior!=encoded[index])throw std::runtime_error("corrupt cold evidence");
                if(!prior && get("root/"+id))throw std::runtime_error("dangling protected recovery root");
                if(!prior)put(key,encoded[index]);
                const std::string cursor_key="cursor/"+EntityKey(*records[index]).substr(7);
                const auto cursor=get(cursor_key);const SemanticCursor candidate(*records[index]);
                if(cursor) {
                    if(cursor->size()!=24)throw std::runtime_error("invalid retained semantic cursor");
                    SemanticCursor previous;previous.packets=DecodeCount(cursor->substr(0,8));
                    previous.time=DecodeCount(cursor->substr(8,8));previous.bytes=DecodeCount(cursor->substr(16,8));
                    if(candidate.RegressesFrom(previous))return RejectBatch("semantic cursor regression");
                }
                put(cursor_key,EncodeCount(candidate.packets)+EncodeCount(candidate.time)+EncodeCount(candidate.bytes));
                if(retain[index]) {
                    const auto root=get("root/"+id);
                    if(root && *root!="1")throw std::runtime_error("corrupt recovery root");
                    if(!root){put("root/"+id,std::string("1"));++roots;}
                    chain+="R"+id;
                }else {transient.push_back(id);chain+="T"+id;}
            }
            put("meta/gc-state",EncodeCount(retired)+EncodeCount(retired_bytes)+EncodeCount(roots)+EncodeCount(peak)+Digest(chain));
            peak=std::max(peak,used);
            put("meta/gc-state",EncodeCount(retired)+EncodeCount(retired_bytes)+EncodeCount(roots)+EncodeCount(peak)+Digest(chain));
            if(used>maximum_logical_bytes_)return RejectBatch("logical byte quota exhausted after safe GC");
            auto awaiting=prepared;
            rocksdb::WriteBatch batch;
            for(const auto &entry:changes) {
                if(entry.second)batch.Put(entry.first,*entry.second);else batch.Delete(entry.first);
            }
            batch.Put("meta/logical-bytes",EncodeCount(used));
            ++sync_stats_.breakdown.detached_prepare_calls;
            sync_stats_.breakdown.detached_prepare_ns+=std::chrono::duration_cast<std::chrono::nanoseconds>(
                std::chrono::steady_clock::now()-preparation_start).count();
            logical_bytes_valid_=false;write_failed_=true;
            SyncWriteLocked(&batch,count);
            const auto install_start=std::chrono::steady_clock::now();
            // No allocations/exceptions here. Failed writes never publish
            // negative knowledge; sticky write_failed_ forbids further use.
            for(const auto &entry:changes)if(entry.second)negative_filter_.Add(entry.first);
            negative_filter_.Add("meta/logical-bytes");
            sync_stats_.breakdown.negative_filter_set_bits=negative_filter_.SetBits();
            committed_cache_.Remember(changes);
            ++sync_stats_.breakdown.committed_cache_installs;
            sync_stats_.breakdown.committed_cache_skipped_entries=committed_cache_.skipped;
            sync_stats_.breakdown.committed_cache_install_ns+=std::chrono::duration_cast<std::chrono::nanoseconds>(
                std::chrono::steady_clock::now()-install_start).count();
            logical_bytes_=used;logical_bytes_valid_=true;write_failed_=false;
            inflight_ids_.swap(awaiting);inflight_transient_.swap(transient);collectible_ids_.clear();
            for(size_t index=0;index<count;++index)ids[index]=std::move(prepared[index]);
            return true;
        }catch(const std::exception &error){return RejectBatch(error.what());}
        catch(...){return RejectBatch("unknown detached write exception");}
    }
    bool AcknowledgeDetachedBatch(const std::string *ids,size_t count) noexcept override {
        if(!snapshot_gc_)return true;
        try {
            std::lock_guard<std::mutex> lock(write_mutex_);
            if(write_failed_ || !ids || !count || inflight_ids_.size()!=count)return false;
            for(size_t index=0;index<count;++index)if(ids[index]!=inflight_ids_[index])return false;
            collectible_ids_.swap(inflight_transient_);inflight_transient_.clear();inflight_ids_.clear();return true;
        }catch(...){return false;}
    }
private:
    class SyncWriteMeasurement {
    public:
        SyncWriteMeasurement(ColdEvidenceStoreSyncStats &stats,rocksdb::Statistics &native,size_t count) noexcept
            :stats_(stats),native_(native),count_(count),old_level_(rocksdb::GetPerfLevel()),
             perf_(rocksdb::get_perf_context()),io_(rocksdb::get_iostats_context()) {
            // Do not reset the caller's thread-local contexts. Snapshot only
            // fixed fields; no ToString, per-level context or per-call logging.
            rocksdb::SetPerfLevel(rocksdb::PerfLevel::kEnableTime);
            before_=Read();
            wal_before_=native_.getTickerCount(rocksdb::WAL_FILE_SYNCED);
            wal_bytes_before_=native_.getTickerCount(rocksdb::WAL_FILE_BYTES);
            cpu_started_=ThreadCpu(&cpu_start_);
            ++stats_.sync_write_attempts;start_=std::chrono::steady_clock::now();
        }
        void Finish(bool success) noexcept {
            const auto elapsed=static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::nanoseconds>(
                std::chrono::steady_clock::now()-start_).count());
            uint64_t cpu_end=0;const bool cpu_finished=ThreadCpu(&cpu_end);
            const auto after=Read();
            const auto wal_after=native_.getTickerCount(rocksdb::WAL_FILE_SYNCED);
            const auto wal_bytes_after=native_.getTickerCount(rocksdb::WAL_FILE_BYTES);
            rocksdb::SetPerfLevel(old_level_);
            stats_.sync_write_total_ns+=elapsed;
            if(elapsed>stats_.sync_write_max_ns)stats_.sync_write_max_ns=elapsed;
            if(success)++stats_.sync_write_successes;else ++stats_.sync_write_failures;
            auto &d=stats_.breakdown;++d.samples;d.records_attempted+=count_;
            if(cpu_started_ && cpu_finished && cpu_end>=cpu_start_) {
                const uint64_t cpu=cpu_end-cpu_start_;++d.cpu_samples;d.cpu_total_ns+=cpu;
                if(cpu>d.cpu_max_ns)d.cpu_max_ns=cpu;
            }else ++d.cpu_clock_failures;
            uint64_t perf_observed=0,io_observed=0;
            const auto fields=Fields(d);
            for(size_t i=0;i<after.size();++i) {
                const uint64_t value=Delta(before_[i],after[i]);
                *fields[i]+=value;
                if(i<8)perf_observed|=value;
                else if(i<12)io_observed|=value;
            }
            if(perf_observed)++d.perf_timers_observed_samples;
            if(io_observed)++d.io_timers_observed_samples;
            d.wal_sync_events+=Delta(wal_before_,wal_after);
            d.wal_bytes+=Delta(wal_bytes_before_,wal_bytes_after);
            Bucket(d.batch_histogram,d.batch_bounds,count_);
            Bucket(d.latency_histogram,d.latency_bounds_ns,elapsed);
            finished_=true;
        }
        ~SyncWriteMeasurement() noexcept {if(!finished_)Finish(false);}
    private:
        ColdEvidenceStoreSyncStats &stats_;
        rocksdb::Statistics &native_;size_t count_;
        rocksdb::PerfLevel old_level_;rocksdb::PerfContext *perf_;rocksdb::IOStatsContext *io_;
        std::array<uint64_t,13> before_{};
        uint64_t wal_before_=0,wal_bytes_before_=0,cpu_start_=0;bool cpu_started_=false;
        std::chrono::steady_clock::time_point start_;
        bool finished_=false;
        std::array<uint64_t,13> Read() const noexcept {
            return {{perf_->write_wal_time,perf_->write_memtable_time,perf_->write_delay_time,
                perf_->write_scheduling_flushes_compactions_time,perf_->write_pre_and_post_process_time,
                perf_->write_thread_wait_nanos,perf_->db_mutex_lock_nanos,perf_->db_condition_wait_nanos,
                io_->write_nanos,io_->fsync_nanos,io_->range_sync_nanos,io_->prepare_write_nanos,io_->bytes_written}};
        }
        static std::array<uint64_t*,13> Fields(ColdEvidenceWriteBreakdown &d) noexcept {
            return {{&d.perf_wal_ns,&d.perf_memtable_ns,&d.perf_delay_ns,&d.perf_scheduling_ns,
                &d.perf_pre_post_ns,&d.perf_thread_wait_ns,&d.perf_db_mutex_ns,&d.perf_db_condition_ns,
                &d.io_write_ns,&d.io_fsync_ns,&d.io_range_sync_ns,&d.io_prepare_write_ns,&d.io_bytes_written}};
        }
        uint64_t Delta(uint64_t before,uint64_t after) noexcept {
            if(after>=before)return after-before;
            ++stats_.breakdown.counter_regressions;return 0;
        }
        static bool ThreadCpu(uint64_t *value) noexcept {
            timespec time{};if(clock_gettime(CLOCK_THREAD_CPUTIME_ID,&time)!=0)return false;
            *value=uint64_t(time.tv_sec)*1000000000ull+uint64_t(time.tv_nsec);return true;
        }
        template<size_t N> static void Bucket(std::array<uint64_t,N> &histogram,
                                             const std::array<uint64_t,N> &bounds,uint64_t value) noexcept {
            for(size_t i=0;i<N;++i)if(value<=bounds[i]){++histogram[i];return;}
        }
    };
    void SyncWriteLocked(rocksdb::WriteBatch *batch,size_t count) {
        // Failed/uncertain writes must never leave a usable stale cache.
        committed_cache_.Clear();
        SyncWriteMeasurement measurement(sync_stats_,*statistics_,count);
        const auto status=db_->Write(write_,batch);
        measurement.Finish(status.ok());
        require(status);
    }
    struct SemanticCursor {
        uint64_t packets=0,time=0,bytes=0;
        SemanticCursor()=default;
        explicit SemanticCursor(const ColdEvidence &v)
            :packets(v.snapshot.packets),time(v.snapshot.last_timestamp_ns),bytes(v.snapshot.bytes) {}
        bool RegressesFrom(const SemanticCursor &prior) const {
            return packets<prior.packets || time<prior.time || bytes<prior.bytes;
        }
    };
    struct PendingEntity {
        std::string original_id,latest_id;SemanticCursor cursor;bool has_cursor=false;
    };
    bool SaveWriteOnlyLocked(const ColdEvidence *const *records,size_t count,std::string *ids) {
        uint64_t used=logical_bytes_;
        rocksdb::WriteBatch batch;
        std::vector<std::string> prepared;prepared.reserve(count);
        for(size_t i=0;i<count;++i) {
            std::string encoded;
            if(!PrepareRecord(records[i],&encoded))return false;
            prepared.push_back(Digest(encoded));
            const std::string key="blob/"+prepared.back();
            // Charge every submission, including duplicates: a conservative
            // bound without a read or an unbounded deduplication index.
            if(!Charge(key.size()+encoded.size(),&used))return false;
            batch.Put(key,encoded);
        }
        batch.Put("meta/logical-bytes",EncodeCount(used));
        logical_bytes_valid_=false;write_failed_=true;
        SyncWriteLocked(&batch,count);
        logical_bytes_=used;logical_bytes_valid_=true;write_failed_=false;
        for(size_t i=0;i<count;++i)ids[i]=std::move(prepared[i]);
        return true;
    }
    bool SaveOneLocked(const ColdEvidence *record,std::string *id) {
        std::string encoded;
        if(!PrepareRecord(record,&encoded))return false;
        std::string prepared=Digest(encoded);
        const std::string entity=EntityKey(*record),key="blob/"+prepared;
        std::string previous_id;
        const auto index_status=db_->Get(rocksdb::ReadOptions(),entity,&previous_id);
        if(!index_status.IsNotFound()) {
            require(index_status);
            if(previous_id!=prepared) {
                ColdEvidence prior;
                if(!Load(previous_id,&prior))throw std::runtime_error("dangling cold index");
                if(EntityKey(prior)!=entity)throw std::runtime_error("corrupt cold index");
                if(SemanticCursor(*record).RegressesFrom(SemanticCursor(prior)))return RejectBatch("semantic cursor regression");
            }
        }
        uint64_t used=LogicalBytesLocked();
        if(index_status.IsNotFound() && !Charge(entity.size()+64,&used))return false;
        rocksdb::WriteBatch batch;std::string previous;
        const auto status=db_->Get(rocksdb::ReadOptions(),key,&previous);
        if(status.IsNotFound()) {
            if(previous_id==prepared)throw std::runtime_error("dangling cold index");
            if(!Charge(key.size()+encoded.size(),&used))return false;
            batch.Put(key,encoded);
        }else {
            require(status);
            if(previous!=encoded)throw std::runtime_error("corrupt cold evidence");
        }
        if(previous_id!=prepared)batch.Put(entity,prepared);
        if(used!=logical_bytes_)batch.Put("meta/logical-bytes",EncodeCount(used));
        if(batch.Count()) {
            logical_bytes_valid_=false;write_failed_=true;
            SyncWriteLocked(&batch,1);
            logical_bytes_=used;logical_bytes_valid_=true;write_failed_=false;
        }else {++sync_stats_.dedup_no_write_batches;++sync_stats_.dedup_no_write_records;}
        *id=std::move(prepared);return true;
    }
    bool Charge(uint64_t added,uint64_t *used) const {
        if(added>maximum_logical_bytes_ || *used>maximum_logical_bytes_-added)return RejectBatch("logical byte quota exhausted");
        *used+=added;return true;
    }
    bool PrepareRecord(const ColdEvidence *record,std::string *encoded) const {
        if(!record)return RejectBatch("null record");
        if(record->scope!=scope_)return RejectBatch("record namespace mismatch");
        if(EncodeColdEvidence(*record,encoded))return true;
        try {
            auto copy=*record;cold_codec::Wire wire;cold_codec::body(wire,copy);
        }catch(const std::exception &error){return RejectBatch(error.what());}
        return RejectBatch("evidence encoding failed");
    }
    bool RejectBatch(const char *reason) const noexcept {
        if(!rejection_reported_.exchange(true))
            std::fprintf(stderr,"FLOWKEEP_COLD_BATCH_REJECT reason=%s\n",reason);
        return false;
    }
    mutable std::atomic<bool> rejection_reported_{false};
    uint64_t LogicalBytesLocked() const {
        if(write_only_)return logical_bytes_; // last confirmed charge, including after a failed write
        if(!logical_bytes_valid_) {
            std::string value;
            const auto status=db_->Get(rocksdb::ReadOptions(),"meta/logical-bytes",&value);
            if(status.IsNotFound())logical_bytes_=0;
            else {require(status);logical_bytes_=DecodeCount(value);}
            if(logical_bytes_>maximum_logical_bytes_)throw std::runtime_error("cold logical quota exceeded");
            logical_bytes_valid_=true;
        }
        return logical_bytes_;
    }
    static std::string EncodeCount(uint64_t count) {
        std::string value;for(unsigned i=0;i<8;++i)value.push_back(char(count>>(i*8)));return value;
    }
    static uint64_t DecodeCount(const std::string &value) {
        if(value.size()!=8)throw std::runtime_error("invalid cold quota counter");
        uint64_t count=0;for(unsigned i=0;i<8;++i)count|=uint64_t(static_cast<unsigned char>(value[i]))<<(i*8);return count;
    }
    std::string scope_;
    uint64_t maximum_logical_bytes_;mutable std::mutex write_mutex_;
    CommittedBatchCache committed_cache_;
    ColdKeyFilter negative_filter_;
    mutable uint64_t logical_bytes_=0;mutable bool logical_bytes_valid_=false;
    bool write_failed_=false;
    bool snapshot_gc_=false;
    bool write_only_=false;
    std::vector<std::string> inflight_ids_,inflight_transient_,collectible_ids_;
    ColdEvidenceStoreSyncStats sync_stats_{};
    std::shared_ptr<rocksdb::Statistics> statistics_;
    std::shared_ptr<NativeRocksDbResources> resources_;
    // Declaration order makes DB/background teardown precede Env teardown.
    std::unique_ptr<PrewrittenWalEnv> wal_env_;
    std::unique_ptr<rocksdb::DB> db_;
    rocksdb::WriteOptions write_;
    static void require(const rocksdb::Status &s){if(!s.ok())throw std::runtime_error(s.ToString());}
public:
    static std::string Digest(const std::string &value) {
        unsigned char digest[SHA256_DIGEST_LENGTH];
        SHA256(reinterpret_cast<const unsigned char*>(value.data()),value.size(),digest);
        const char *hex="0123456789abcdef";std::string out;out.reserve(64);
        for(unsigned char c:digest){out.push_back(hex[c>>4]);out.push_back(hex[c&15]);}return out;
    }
};
}
#endif
