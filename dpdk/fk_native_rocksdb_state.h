#ifndef FLOWKEEP_NATIVE_ROCKSDB_STATE_H
#define FLOWKEEP_NATIVE_ROCKSDB_STATE_H
#include "fk_native_seven_state_fusion.h"
#include "fk_native_event_context.h"
#include "fk_history_write_batch.h"
#include <rocksdb/db.h>
#include <rocksdb/cache.h>
#include <rocksdb/table.h>
#include <rocksdb/write_batch.h>
#include <rocksdb/write_buffer_manager.h>
#include <rocksdb/perf_context.h>
#include <rocksdb/iostats_context.h>
#include <cmath>
#include <chrono>
#include <cstring>
#include <limits>
#include <map>
#include <memory>
#include <stdexcept>
#include <string>
#include <vector>
#include <atomic>
#include <condition_variable>
#include <deque>
#include <mutex>
#include <thread>
#ifdef FK_HISTORY_PIPELINE_TESTING
#include <functional>
#endif

namespace flowkeep {
/* One scorer owns one backend. State and replay watermark use one synced
 * WriteBatch, with WAL enabled. No SQLite fallback or on-disk compatibility.
 * Binding must include model, event-token namespace and worker partition.
 * This does not persist the output ledger or implement end-to-end ACK replay.
 */
struct NativeRocksDbResources {
    std::shared_ptr<rocksdb::Cache> block_cache;
    std::shared_ptr<rocksdb::WriteBufferManager> write_buffers;
    NativeRocksDbResources()
        : block_cache(rocksdb::NewLRUCache(4u<<20,-1,true)),
          write_buffers(std::make_shared<rocksdb::WriteBufferManager>(8u<<20)) {}
    // WBM's threshold initiates flushes, not a process-RSS hard limit.
};

class NativeRocksDbState : public NativeEventContextSink {
public:
    NativeRocksDbState(const std::string &path,const std::string &binding,
                      std::shared_ptr<NativeRocksDbResources> resources=nullptr,
                      uint64_t history_ttl_ns=90ull*86400ull*1000000000ull)
        : resources_(resources ? std::move(resources) : std::make_shared<NativeRocksDbResources>()),
          history_ttl_ns_(history_ttl_ns) {
        if(!history_ttl_ns_)throw std::invalid_argument("zero history TTL");
        if(binding.empty())throw std::invalid_argument("empty state namespace");
        rocksdb::Options options;
        options.create_if_missing=true;
        options.paranoid_checks=true;
        options.write_buffer_size=1u<<20;
        options.write_buffer_manager=resources_->write_buffers;
        options.max_write_buffer_number=2;
        options.max_background_jobs=2;
        options.max_open_files=128;
        rocksdb::BlockBasedTableOptions table;
        cache_=resources_->block_cache;
        table.block_cache=cache_;
        table.cache_index_and_filter_blocks=true;
        options.table_factory.reset(rocksdb::NewBlockBasedTableFactory(table));
        rocksdb::DB *raw=nullptr;
        require(rocksdb::DB::Open(options,path,&raw));db_.reset(raw);
        write_.sync=true;write_.disableWAL=false;
        std::string previous;
        auto status=db_->Get(rocksdb::ReadOptions(),"meta/binding",&previous);
        const std::string contract="fk-native-seven-state-le-v2:ttl="+std::to_string(history_ttl_ns_)+":"+binding;
        if(status.IsNotFound()) {
            // Never adopt a nonempty database with missing namespace metadata.
            std::unique_ptr<rocksdb::Iterator> it(db_->NewIterator(rocksdb::ReadOptions()));
            it->SeekToFirst();require(it->status());
            if(it->Valid())throw std::runtime_error("unbound nonempty RocksDB");
            require(db_->Put(write_,"meta/binding",contract));
        } else {
            require(status);
            if(previous!=contract)throw std::runtime_error("persistent state binding mismatch");
        }
    }
    NativeRocksDbState(const NativeRocksDbState&)=delete;
    NativeRocksDbState& operator=(const NativeRocksDbState&)=delete;
    ~NativeRocksDbState() override { FinishAsync(); }
    // Inherits the scorer's attested affinity; no additional CPU set.
    void EnableAsync(size_t max_bytes=2u<<20,size_t max_batches=8) {
        if(async_ || active_ || !max_bytes || !max_batches)
            throw std::runtime_error("invalid async history activation");
        max_async_bytes_=max_bytes;max_async_batches_=max_batches;async_=true;
        writer_=std::thread(&NativeRocksDbState::WriterLoop,this);
    }
    bool FinishAsync() noexcept {
        if(!async_)return true;
        {std::lock_guard<std::mutex> lock(async_mutex_);closing_=true;}
        async_ready_.notify_all();
        if(writer_.joinable())writer_.join();
        return !async_failed_;
    }
    bool WaitDurable(uint64_t sequence,std::string *error) noexcept override {
        if(!async_)return true;
        try {
            std::unique_lock<std::mutex> lock(async_mutex_);
            if(!has_submitted_ || sequence>submitted_sequence_)
                throw std::runtime_error("history fence exceeds submitted sequence");
            async_ready_.wait(lock,[&]{return async_failed_ ||
                (has_durable_ && durable_sequence_>=sequence);});
            if(async_failed_)throw std::runtime_error("asynchronous synced history write failed");
            return true;
        }catch(const std::exception &e){if(error)*error=e.what();return false;}
        catch(...){return false;}
    }
    uint64_t submitted_batches() const {return submitted_batches_;}
    uint64_t maximum_merged_batches() const {return maximum_merged_batches_;}
    uint64_t maximum_outstanding_charge_bytes() const {return peak_async_bytes_;}
    uint64_t maximum_outstanding_batches() const {return peak_async_batches_;}
    uint64_t submission_wait_ns() const {return submission_wait_ns_;}
    uint64_t maximum_charge_bytes() const {return max_async_bytes_;}
    uint64_t maximum_batches() const {return max_async_batches_;}
    uint64_t gc_fenced_batches() const {return gc_fenced_batches_;}
    uint64_t wal_write_ns() const {return wal_write_ns_;}
    uint64_t io_fsync_ns() const {return io_fsync_ns_;}
    uint64_t memtable_write_ns() const {return memtable_write_ns_;}
    uint64_t write_delay_ns() const {return write_delay_ns_;}
    uint64_t write_thread_wait_ns() const {return write_thread_wait_ns_;}
#ifdef FK_HISTORY_PIPELINE_TESTING
    // Installed before EnableAsync; absent from production builds.
    std::function<bool()> before_sync_for_test;
#endif
    bool watermark(uint64_t *sequence) {
        std::string value;auto status=db_->Get(rocksdb::ReadOptions(),"meta/watermark",&value);
        if(status.IsNotFound())return false;
        require(status);
        if(value.size()!=8)throw std::runtime_error("invalid RocksDB watermark");
        *sequence=get64(value.data());return true;
    }
    fk_native_fusion_state_backend callbacks() {
        return {this,
            [](void *p)->bool{return static_cast<NativeRocksDbState*>(p)->begin();},
            [](void *p,uint64_t k,double *v,uint8_t *a,bool *f)->bool{return static_cast<NativeRocksDbState*>(p)->load(k,v,a,f);},
            [](void *p,uint64_t k,const double *v,uint8_t a)->bool{return static_cast<NativeRocksDbState*>(p)->save(k,v,a);},
            [](void *p,uint64_t s)->bool{
                auto *store=static_cast<NativeRocksDbState*>(p);
                return store->commit(s) && store->WaitDurable(s,nullptr);
            },
            [](void *p){static_cast<NativeRocksDbState*>(p)->rollback();}};
    }
    fk_native_fusion_submitted_backend submission_callbacks() {
        const auto cb=callbacks();
        return {cb.context,cb.begin,cb.load,cb.save,
            [](void *p,uint64_t s)->bool{return static_cast<NativeRocksDbState*>(p)->commit(s);},
            cb.rollback,
            [](void *p,uint64_t s)->bool{return static_cast<NativeRocksDbState*>(p)->WaitDurable(s,nullptr);}};
    }
    bool EventMetadata(uint64_t token, uint64_t *time, std::string *identity) {
        std::lock_guard<std::mutex> lock(async_mutex_);
        std::string value;
        auto visible=visible_.find(token);
        if(visible!=visible_.end())value=visible->second.metadata;
        else {
            auto status=db_->Get(rocksdb::ReadOptions(),"event/"+key(token),&value);
            if(status.IsNotFound())return false;
            require(status);
        }
        if(value.size()<9)throw std::runtime_error("invalid event metadata");
        *time=get64(value.data());*identity=value.substr(8);return true;
    }
    uint64_t multiget_calls() const { return multiget_calls_; }
    uint64_t last_prefetch_keys() const { return last_prefetch_keys_; }
    uint64_t last_prefetch_value_bytes() const { return last_prefetch_value_bytes_; }
    uint64_t history_ttl_ns() const { return history_ttl_ns_; }
    uint64_t last_gc_examined() const { return last_gc_examined_; }
    uint64_t last_gc_deleted() const { return last_gc_deleted_; }
    uint64_t commit_write_calls() const { return commit_write_calls_; }
    uint64_t commit_write_failures() const { return commit_write_failures_; }
    uint64_t commit_write_ns() const { return commit_write_ns_; }
    uint64_t maximum_commit_write_ns() const { return maximum_commit_write_ns_; }
    bool EventWatermark(uint64_t *time) {
        std::string value;auto status=db_->Get(rocksdb::ReadOptions(),"meta/event-watermark",&value);
        if(status.IsNotFound())return false;
        require(status);
        if(value.size()!=8)throw std::runtime_error("invalid event watermark");
        *time=get64(value.data());return true;
    }
    bool PrepareContext(const NativeEventContext *rows,size_t count,std::string *error) noexcept override {
        try {
            ClearContext();
            if(active_ || !rows || !count || count>65536)throw std::runtime_error("invalid context batch");
            uint64_t previous_watermark=0,previous_sequence=0;
            bool has_time=false,has_sequence=false;
            {
                std::lock_guard<std::mutex> lock(async_mutex_);
                if(async_failed_ || closing_)throw std::runtime_error("history pipeline unavailable");
                if(async_ && has_submitted_) {
                    previous_watermark=submitted_time_;previous_sequence=submitted_sequence_;
                    has_time=has_sequence=true;
                } else {
                    has_time=EventWatermark(&previous_watermark);
                    has_sequence=watermark(&previous_sequence);
                }
            }
            if((has_time && rows[0].semantic_timestamp_ns<previous_watermark) ||
                (has_sequence && rows[0].sequence<=previous_sequence))
                throw std::runtime_error("persistent batch watermark regression");
            Prefetch(rows,count);
            reset_rows_.assign(count,0);
            size_t bytes=0;
            for(size_t i=0;i<count;++i) {
                const auto &r=rows[i];
                if(!r.event_id || r.event_id->empty() || r.event_id->size()>4096 ||
                    (i && (r.sequence<=rows[i-1].sequence || r.semantic_timestamp_ns<rows[i-1].semantic_timestamp_ns)))
                    throw std::runtime_error("invalid event identity/time order");
                uint64_t previous_time=0;std::string previous_id;
                auto p=contexts_.find(r.event_token);
                bool found=p!=contexts_.end();
                if(found){previous_time=get64(p->second.data());previous_id=p->second.substr(8);}
                else {
                    const auto &record=prefetched_.at(r.event_token);
                    found=record.has_metadata;
                    if(found) {
                        previous_time=get64(record.metadata.data());previous_id=record.metadata.substr(8);
                        previous_times_[r.event_token]=previous_time;
                    }
                }
                if(found && (previous_id!=*r.event_id || r.semantic_timestamp_ns<previous_time))
                    throw std::runtime_error("persistent identity/time mismatch");
                reset_rows_[i]=found && r.semantic_timestamp_ns-previous_time>=history_ttl_ns_ ? 1u : 0u;
                std::string value;put64(value,r.semantic_timestamp_ns);value+=*r.event_id;
                if(p==contexts_.end())bytes+=value.size();
                if(bytes>(1u<<20))throw std::runtime_error("context payload budget exceeded");
                contexts_[r.event_token]=std::move(value);
            }
            context_sequence_=rows[count-1].sequence;context_time_=rows[count-1].semantic_timestamp_ns;context_ready_=true;return true;
        }catch(const std::exception &e){ClearContext();if(error)*error=e.what();return false;}
        catch(...){ClearContext();return false;}
    }
    void ClearContext() noexcept override {
        contexts_.clear();previous_times_.clear();reset_rows_.clear();prefetched_.clear();context_ready_=false;
    }
    const uint8_t *HistoryResetRows() const noexcept override {
        return context_ready_ ? reset_rows_.data() : nullptr;
    }
    const NativeRocksDbResources *resource_identity() const {return resources_.get();}
    uint64_t shared_memtable_bytes() const {return resources_->write_buffers->memory_usage();}
    uint64_t block_cache_usage() const {return cache_->GetUsage();}
    uint64_t memtable_bytes() const {
        uint64_t bytes=0;db_->GetIntProperty("rocksdb.cur-size-all-mem-tables",&bytes);return bytes;
    }
private:
    std::shared_ptr<NativeRocksDbResources> resources_;
    std::shared_ptr<rocksdb::Cache> cache_;
    std::unique_ptr<rocksdb::DB> db_;
    rocksdb::WriteOptions write_;
    std::map<uint64_t,std::string> pending_;
    std::map<uint64_t,std::string> contexts_;
    struct Prefetched {
        std::string metadata,state;
        bool has_metadata=false,has_state=false;
    };
    std::map<uint64_t,Prefetched> prefetched_;
    uint64_t multiget_calls_=0,last_prefetch_keys_=0,last_prefetch_value_bytes_=0;
    std::map<uint64_t,uint64_t> previous_times_;
    std::vector<uint8_t> reset_rows_;
    uint64_t history_ttl_ns_;
    uint64_t context_time_=0;
    uint64_t last_gc_examined_=0,last_gc_deleted_=0;
    std::atomic<uint64_t> commit_write_calls_{0},commit_write_failures_{0};
    std::atomic<uint64_t> commit_write_ns_{0},maximum_commit_write_ns_{0};
    uint64_t context_sequence_=0;
    bool context_ready_=false;
    bool active_=false;
    struct VisibleState {uint64_t sequence;std::string metadata,state;};
    struct AsyncJob {std::unique_ptr<rocksdb::WriteBatch> batch;uint64_t sequence;size_t charge;};
    std::mutex async_mutex_;
    std::condition_variable async_ready_;
    std::deque<AsyncJob> jobs_;
    std::map<uint64_t,VisibleState> visible_;
    std::thread writer_;
    bool async_=false,closing_=false,async_failed_=false;
    bool has_submitted_=false,has_durable_=false;
    uint64_t submitted_sequence_=0,submitted_time_=0,durable_sequence_=0;
    size_t max_async_bytes_=0,max_async_batches_=0,outstanding_bytes_=0,outstanding_batches_=0;
    std::atomic<uint64_t> submitted_batches_{0},maximum_merged_batches_{0};
    std::atomic<uint64_t> peak_async_bytes_{0},peak_async_batches_{0},submission_wait_ns_{0};
    uint64_t gc_fenced_batches_=0;
    std::atomic<uint64_t> wal_write_ns_{0},io_fsync_ns_{0},memtable_write_ns_{0};
    std::atomic<uint64_t> write_delay_ns_{0},write_thread_wait_ns_{0};
    bool NeedsGcFence() {
        if(!async_ || context_time_<history_ttl_ns_)return false;
        const uint64_t cutoff=context_time_-history_ttl_ns_;
        std::lock_guard<std::mutex> lock(async_mutex_);
        for(const auto &entry:visible_)
            if(get64(entry.second.metadata.data())<=cutoff)return true;
        rocksdb::ReadOptions ro;ro.fill_cache=false;
        std::unique_ptr<rocksdb::Iterator> it(db_->NewIterator(ro));
        it->Seek("idle/");require(it->status());
        if(!it->Valid() || !it->key().starts_with("idle/"))return false;
        if(it->key().size()!=21)throw std::runtime_error("invalid expiry index key");
        return idle_time(it->key().data()+5)<=cutoff;
    }
    void DrainForGc() {
        uint64_t sequence=0;bool present=false;
        {std::lock_guard<std::mutex> lock(async_mutex_);sequence=submitted_sequence_;present=has_submitted_;}
        std::string error;
        if(present && !WaitDurable(sequence,&error))throw std::runtime_error(error);
    }
    bool WriteSynced(rocksdb::WriteBatch &batch) {
        struct RestorePerf {rocksdb::PerfLevel level;~RestorePerf(){rocksdb::SetPerfLevel(level);}} restore{rocksdb::GetPerfLevel()};
        rocksdb::SetPerfLevel(rocksdb::PerfLevel::kEnableTimeExceptForMutex);
        auto *perf=rocksdb::get_perf_context();auto *io=rocksdb::get_iostats_context();
        perf->Reset();io->Reset();
        const auto start=std::chrono::steady_clock::now();
        rocksdb::Status status;
#ifdef FK_HISTORY_PIPELINE_TESTING
        if(before_sync_for_test && !before_sync_for_test())status=rocksdb::Status::IOError("injected history failure");
        else
#endif
        status=db_->Write(write_,&batch);
        // WAL duration includes fsync. These nested counters must not be added
        // together as disjoint stages; worker durations also overlap.
        wal_write_ns_+=perf->write_wal_time;io_fsync_ns_+=io->fsync_nanos;
        memtable_write_ns_+=perf->write_memtable_time;write_delay_ns_+=perf->write_delay_time;
        write_thread_wait_ns_+=perf->write_thread_wait_nanos;
        const uint64_t ns=static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::nanoseconds>(
            std::chrono::steady_clock::now()-start).count());
        ++commit_write_calls_;commit_write_ns_+=ns;
        maximum_commit_write_ns_=std::max(maximum_commit_write_ns_.load(),ns);
        if(!status.ok())++commit_write_failures_;
        return status.ok();
    }
    bool SubmitHistory(const rocksdb::WriteBatch &batch,uint64_t sequence) {
        if(!context_ready_)return false;
        // Charge queued payload plus overlay payload/node allowance. Merge
        // scratch is additionally bounded by this cap, not total process RSS.
        size_t charge=batch.GetDataSize()+sizeof(AsyncJob);
        for(const auto &entry:pending_)charge+=entry.second.size()+contexts_.at(entry.first).size()+256;
        if(charge>max_async_bytes_)return false;
        auto copy=std::make_unique<rocksdb::WriteBatch>(batch.Data());
        std::unique_lock<std::mutex> lock(async_mutex_);
        const auto start=std::chrono::steady_clock::now();
        async_ready_.wait(lock,[&]{return async_failed_ || closing_ ||
            (outstanding_batches_<max_async_batches_ && charge<=max_async_bytes_-outstanding_bytes_);});
        submission_wait_ns_+=static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::nanoseconds>(
            std::chrono::steady_clock::now()-start).count());
        if(async_failed_ || closing_)return false;
        if(has_submitted_ && sequence<=submitted_sequence_)return false;
        try {
            for(const auto &entry:pending_)
                visible_[entry.first]={sequence,contexts_.at(entry.first),entry.second};
            jobs_.push_back({std::move(copy),sequence,charge});
        } catch(...) {async_failed_=true;async_ready_.notify_all();throw;}
        submitted_sequence_=sequence;submitted_time_=context_time_;has_submitted_=true;
        outstanding_bytes_+=charge;++outstanding_batches_;++submitted_batches_;
        peak_async_bytes_=std::max<uint64_t>(peak_async_bytes_.load(),outstanding_bytes_);
        peak_async_batches_=std::max<uint64_t>(peak_async_batches_.load(),outstanding_batches_);
        lock.unlock();async_ready_.notify_all();return true;
    }
    void WriterLoop() noexcept {
        try {
            for(;;) {
                std::deque<AsyncJob> group;
                {
                    std::unique_lock<std::mutex> lock(async_mutex_);
                    async_ready_.wait(lock,[&]{return closing_ || async_failed_ || !jobs_.empty();});
                    if(async_failed_ || (closing_ && jobs_.empty()))return;
                    group.swap(jobs_);
                }
                rocksdb::WriteBatch merged;
                size_t charge=0;
                for(const auto &job:group){require(AppendHistoryWriteBatch(*job.batch,merged));charge+=job.charge;}
                const uint64_t sequence=group.back().sequence;
                const bool ok=WriteSynced(merged);
                {
                    std::lock_guard<std::mutex> lock(async_mutex_);
                    maximum_merged_batches_=std::max<uint64_t>(maximum_merged_batches_.load(),group.size());
                    if(!ok)async_failed_=true;
                    else {
                        durable_sequence_=sequence;has_durable_=true;
                        for(auto it=visible_.begin();it!=visible_.end();)
                            if(it->second.sequence<=sequence)it=visible_.erase(it);else ++it;
                        outstanding_bytes_-=charge;outstanding_batches_-=group.size();
                    }
                }
                async_ready_.notify_all();
                if(!ok)return;
            }
        }catch(...) {
            {std::lock_guard<std::mutex> lock(async_mutex_);async_failed_=true;}
            async_ready_.notify_all();
        }
    }
    static void require(const rocksdb::Status &s) {if(!s.ok())throw std::runtime_error(s.ToString());}
    static void put64(std::string &s,uint64_t v) {for(unsigned i=0;i<8;++i)s.push_back(static_cast<char>((v>>(8*i))&255));}
    static uint64_t get64(const char *s) {uint64_t v=0;for(unsigned i=0;i<8;++i)v|=uint64_t(static_cast<unsigned char>(s[i]))<<(8*i);return v;}
    static std::string key(uint64_t token) {std::string s="state/";put64(s,token);return s;}
    static std::string idle_key(uint64_t time,uint64_t token) {
        std::string s="idle/";
        for(int i=7;i>=0;--i)s.push_back(static_cast<char>((time>>(8*i))&255));
        put64(s,token);return s;
    }
    static uint64_t idle_time(const char *s) {
        uint64_t v=0;for(unsigned i=0;i<8;++i)v=(v<<8)|static_cast<unsigned char>(s[i]);return v;
    }
    void Prefetch(const NativeEventContext *rows,size_t count) {
        // Atomic disk+overlay view: removal after a stale MultiGet must not
        // lose read-your-writes. Writer holds this lock only after disk sync.
        std::lock_guard<std::mutex> lock(async_mutex_);
        size_t bytes=0;
        for(size_t i=0;i<count;++i) {
            const auto &r=rows[i];
            if(!r.event_id || r.event_id->empty() || r.event_id->size()>4096)
                throw std::runtime_error("invalid prefetch identity");
            if(prefetched_.emplace(r.event_token,Prefetched{}).second)bytes+=8+r.event_id->size();
            if(bytes>(1u<<20))throw std::runtime_error("context payload budget exceeded");
        }
        std::vector<std::string> keys;keys.reserve(2*prefetched_.size());
        for(const auto &item:prefetched_) {
            keys.push_back("event/"+key(item.first));keys.push_back(key(item.first));
        }
        std::vector<rocksdb::Slice> slices;slices.reserve(keys.size());
        for(const auto &k:keys)slices.emplace_back(k);
        std::vector<rocksdb::PinnableSlice> values(keys.size());
        std::vector<rocksdb::Status> statuses(keys.size());
        db_->MultiGet(rocksdb::ReadOptions(),db_->DefaultColumnFamily(),keys.size(),
            slices.data(),values.data(),statuses.data(),false);
        ++multiget_calls_;last_prefetch_keys_=keys.size();last_prefetch_value_bytes_=0;
        size_t offset=0;
        for(auto &item:prefetched_) {
            auto &record=item.second;
            if(!statuses[offset].IsNotFound()) {
                require(statuses[offset]);
                if(values[offset].size()<9 || values[offset].size()>4104)
                    throw std::runtime_error("invalid prefetched metadata");
                record.metadata=values[offset].ToString();record.has_metadata=true;
            }
            ++offset;
            if(!statuses[offset].IsNotFound()) {
                require(statuses[offset]);
                if(values[offset].size()!=57)throw std::runtime_error("invalid prefetched state");
                record.state=values[offset].ToString();record.has_state=true;
            }
            const auto visible=visible_.find(item.first);
            if(visible!=visible_.end()) {
                record.metadata=visible->second.metadata;record.has_metadata=true;
                record.state=visible->second.state;record.has_state=true;
            }
            last_prefetch_value_bytes_+=record.metadata.size()+record.state.size();++offset;
            if(last_prefetch_value_bytes_>(5u<<20))throw std::runtime_error("prefetched value budget exceeded");
        }
    }
    // Bounded, event-driven reclamation. Tombstones are durable at commit;
    // physical SST disk space is reclaimed later by RocksDB compaction.
    void CollectExpired(rocksdb::WriteBatch &batch,uint64_t *examined,uint64_t *deleted) {
        if(context_time_<history_ttl_ns_)return;
        const uint64_t cutoff=context_time_-history_ttl_ns_;
        rocksdb::ReadOptions options;options.fill_cache=false;
        std::unique_ptr<rocksdb::Iterator> it(db_->NewIterator(options));
        for(it->Seek("idle/");it->Valid() && *examined<256;it->Next()) {
            const auto k=it->key();
            if(!k.starts_with("idle/"))break;
            if(k.size()!=21)throw std::runtime_error("invalid expiry index key");
            const uint64_t time=idle_time(k.data()+5),token=get64(k.data()+13);
            if(time>cutoff)break;
            ++*examined;batch.Delete(k);
            if(contexts_.count(token))continue;
            uint64_t current=0;std::string identity;
            if(EventMetadata(token,&current,&identity) && current==time) {
                batch.Delete(key(token));batch.Delete("event/"+key(token));++*deleted;
            }
        }
        require(it->status());
    }
    bool begin() noexcept {if(active_)return false;pending_.clear();active_=true;return true;}
    void rollback() noexcept {pending_.clear();active_=false;}
    bool load(uint64_t token,double *values,uint8_t *latched,bool *found) noexcept {
        try {
            if(!active_)return false;
            std::string value;auto i=pending_.find(token);
            if(i!=pending_.end())value=i->second;
            else if(context_ready_) {
                auto prefetched=prefetched_.find(token);
                if(prefetched==prefetched_.end())return false;
                if(!prefetched->second.has_state){*found=false;return true;}
                value=prefetched->second.state;
            } else {
                auto status=db_->Get(rocksdb::ReadOptions(),key(token),&value);
                if(status.IsNotFound()){*found=false;return true;}
                if(!status.ok())return false;
            }
            if(value.size()!=57 || static_cast<unsigned char>(value[56])>1)return false;
            for(unsigned ihead=0;ihead<7;++ihead){
                uint64_t bits=get64(value.data()+8*ihead);
                std::memcpy(&values[ihead],&bits,8);
                if(!std::isfinite(values[ihead])||values[ihead]<0||values[ihead]>1)return false;
            }
            *latched=static_cast<uint8_t>(value[56]);*found=true;return true;
        }catch(...){return false;}
    }
    bool save(uint64_t token,const double *values,uint8_t latched) noexcept {
        static_assert(sizeof(double)==8 && std::numeric_limits<double>::is_iec559,"IEEE binary64 required");
        try {
            if(!active_||latched>1)return false;
            // Bound pending transaction cardinality. Allocator overhead is
            // reported separately by the process; this is not a 64 MiB RSS cap.
            if(pending_.size()>=65536 && pending_.find(token)==pending_.end())return false;
            std::string value;value.reserve(57);
            for(unsigned i=0;i<7;++i){
                if(!std::isfinite(values[i])||values[i]<0||values[i]>1)return false;
                uint64_t bits;std::memcpy(&bits,&values[i],8);put64(value,bits);
            }
            value.push_back(static_cast<char>(latched));pending_[token]=std::move(value);return true;
        }catch(...){return false;}
    }
    bool commit(uint64_t sequence) noexcept {
        try {
            if(!active_)return false;
            if(context_ready_ && (sequence!=context_sequence_ || pending_.size()!=contexts_.size()))return false;
            rocksdb::WriteBatch batch;
            uint64_t examined=0,deleted=0;
            const bool gc_fence=NeedsGcFence();
            if(gc_fence)DrainForGc();
            if(context_ready_) {
                // Reclamation is an ordered state mutation, not a background
                // best-effort delete. Drain prior writes, reclaim, and publish
                // this batch synchronously when an expired index is present.
                if(!async_ || gc_fence)CollectExpired(batch,&examined,&deleted);
                for(const auto &item:contexts_) {
                    if(!pending_.count(item.first))return false;
                    auto prior=previous_times_.find(item.first);
                    if(prior!=previous_times_.end())batch.Delete(idle_key(prior->second,item.first));
                    batch.Put("event/"+key(item.first),item.second);
                    batch.Put(idle_key(get64(item.second.data()),item.first),"");
                }
                std::string time;put64(time,context_time_);batch.Put("meta/event-watermark",time);
            }
            for(const auto &item:pending_)batch.Put(key(item.first),item.second);
            std::string value;put64(value,sequence);batch.Put("meta/watermark",value);
            if(async_ && !gc_fence) {
                if(!SubmitHistory(batch,sequence))return false;
            } else {
                if(!WriteSynced(batch))return false;
                if(gc_fence) {
                    std::lock_guard<std::mutex> lock(async_mutex_);
                    submitted_sequence_=durable_sequence_=sequence;submitted_time_=context_time_;
                    has_submitted_=has_durable_=true;++gc_fenced_batches_;
                    async_ready_.notify_all();
                }
            }
            last_gc_examined_=examined;last_gc_deleted_=deleted;
            pending_.clear();active_=false;ClearContext();return true;
        }catch(...){return false;}
    }
};
}
#endif
