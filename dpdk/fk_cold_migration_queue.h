#ifndef FK_COLD_MIGRATION_QUEUE_H
#define FK_COLD_MIGRATION_QUEUE_H
#include "fk_cold_evidence_store.h"
#include "fk_evidence_gain_feedback.h"
#include "fk_evidence_persistence_schedule.h"
#include <condition_variable>
#include <chrono>
#include <atomic>
#include <algorithm>
#include <array>
#include <mutex>
#include <thread>
#include <vector>
#include <pthread.h>
#include <sched.h>
namespace flowkeep {
struct ColdMigrationTicket { uint32_t slot=0;uint64_t generation=0;uint64_t queue_id=0; };
enum class ColdSubmit { Accepted, Busy, Full, Invalid, Stopped, WriteFailed };
enum class ColdCompletion { Pending, Busy, Invalid, WriteFailed, Stale, DurableCurrent };
struct ColdOwnerCoalesceStats {
    bool enabled=false;
    size_t expected_owners=0,registered_owners=0,closed_owners=0,metadata_bytes=0;
    uint64_t wait_entries=0,wait_calls=0,wait_total_ns=0,wait_max_ns=0;
    uint64_t flush_all_owners_blocked=0,flush_capacity=0,flush_deadline=0,flush_stop=0;
    uint64_t waiting_owner_sum_at_flush=0,waiting_owner_max_at_flush=0;
};
struct ColdMigrationStats {
    uint64_t utility_competitions=0,utility_reorders=0,gain_feedback_hits=0,gain_feedback_misses=0;
    uint64_t expired_evidence_candidates=0;
    uint64_t accepted=0,full=0,busy=0,write_batches=0,written=0,write_failed=0,stale=0,validated=0;
    size_t outstanding=0,peak_outstanding=0,capacity=0,slot_object_bytes=0;
    uint64_t detached_accepted=0,detached_written=0,detached_failed=0;
    uint64_t detached_backpressure_full=0,detached_backpressure_busy=0;
    size_t detached_outstanding=0,detached_peak_outstanding=0;
    bool write_failure=false,detached_only=false;
    ColdOwnerCoalesceStats owner_coalesce{};
};
// Non-owning writer outlives this queue. The owner supplies immutable copies;
// one worker batches sync WAL writes. Capacity includes queued, writing AND
// completed-but-unconsumed slots, so a stalled owner cannot grow an ACK queue.
class ColdMigrationQueue {
public:
    static constexpr size_t kNoOwner=SIZE_MAX;
    static constexpr size_t kMaximumOwners=64;
    ColdMigrationQueue(ColdEvidenceBatchWriter &writer,size_t capacity,size_t batch_size,
                       uint32_t maximum_coalesce_us=0,size_t expected_owner_count=0,bool detached_only=false)
        :writer_(writer),slots_(CheckedCapacity(capacity)),ring_(capacity),batch_size_(batch_size),
         maximum_coalesce_us_(maximum_coalesce_us),detached_only_(detached_only),
         owner_waits_(CheckedOwners(maximum_coalesce_us,expected_owner_count,detached_only)) {
        if(!batch_size || batch_size>capacity)throw std::invalid_argument("invalid migration batch size");
        if(maximum_coalesce_us>(detached_only ? 20000u : 500u))
            throw std::invalid_argument("migration aggregation exceeds mode-specific bound");
        stats_.owner_coalesce.enabled=OwnerAware();
        stats_.owner_coalesce.expected_owners=owner_waits_.size();
        stats_.owner_coalesce.metadata_bytes=OwnerMetadataBytes()*owner_waits_.size();
        for(auto &slot:slots_){slot.record.scope.reserve(256);slot.id.reserve(64);}
        stats_.capacity=capacity;stats_.slot_object_bytes=capacity*sizeof(Slot);
        stats_.detached_only=detached_only_;
        worker_=std::thread([this]{Run();});
    }
    ~ColdMigrationQueue(){Stop();}
    ColdMigrationQueue(const ColdMigrationQueue&)=delete;
    ColdMigrationQueue &operator=(const ColdMigrationQueue&)=delete;
    size_t BatchSize() const noexcept {return batch_size_;}
    void SetGainFeedback(std::shared_ptr<EvidenceGainChannel> feedback) {
        std::lock_guard<std::mutex> lock(mutex_);gain_feedback_=std::move(feedback);
    }
    bool OwnerAware() const noexcept {return !owner_waits_.empty();}
    bool HasWriteFailure() const noexcept {return write_failure_.load(std::memory_order_acquire);}
    // Includes the exact per-owner wait slot and conservatively amortizes
    // new fixed control/receipt storage. Charged by each lifecycle provider.
    size_t OwnerMetadataBytes() const noexcept {
        return OwnerAware()?sizeof(OwnerWaitState)+2*sizeof(size_t)+(256+owner_waits_.size()-1)/owner_waits_.size():0;
    }
    size_t RegisterOwner() {
        if(!OwnerAware())return kNoOwner;
        std::lock_guard<std::mutex> lock(mutex_);
        if(stopping_ || stats_.owner_coalesce.registered_owners==owner_waits_.size())
            throw std::invalid_argument("cold owner registration exceeds fixed capacity");
        return stats_.owner_coalesce.registered_owners++;
    }
    // Call only once this exclusive owner has completed shutdown validation.
    // A close is a scheduling hint, never a durable confirmation.
    bool CloseOwner(size_t owner) noexcept {
        if(!OwnerAware())return owner==kNoOwner;
        std::lock_guard<std::mutex> lock(mutex_);
        if(owner>=stats_.owner_coalesce.registered_owners)return false;
        auto &wait=owner_waits_[owner];
        if(wait.waiting && wait.ticket.queue_id==queue_id_ && wait.ticket.slot<slots_.size()) {
            const auto &slot=slots_[wait.ticket.slot];
            if(slot.generation==wait.ticket.generation && slot.state!=State::Free)return false;
        }
        if(!wait.closed){wait.closed=true;wait.waiting=false;++stats_.owner_coalesce.closed_owners;changed_.notify_one();}
        return true;
    }
    // std::thread inherits the creator's affinity. Configure explicitly when
    // a DPDK main lcore creates multiple independent persistence writers.
    bool SetWriterCpu(int cpu) noexcept {
        if(cpu<0 || cpu>=CPU_SETSIZE)return false;
        std::lock_guard<std::mutex> lock(mutex_);
        if(stopping_ || !worker_.joinable())return false;
        cpu_set_t cpus;CPU_ZERO(&cpus);CPU_SET(cpu,&cpus);
        if(pthread_setaffinity_np(worker_.native_handle(),sizeof(cpus),&cpus)!=0)return false;
        cpu_set_t observed;CPU_ZERO(&observed);
        return pthread_getaffinity_np(worker_.native_handle(),sizeof(observed),&observed)==0 &&
            CPU_COUNT(&observed)==1 && CPU_ISSET(cpu,&observed);
    }
    ColdSubmit TrySubmit(const ColdEvidence &record,ColdMigrationTicket *ticket) noexcept {
        if(HasWriteFailure())return ColdSubmit::WriteFailed;
        if(detached_only_)return ColdSubmit::Invalid;
        if(!ticket || record.scope.empty() || record.scope.size()>256)return ColdSubmit::Invalid;
        std::unique_lock<std::mutex> lock(mutex_,std::try_to_lock);
        if(!lock.owns_lock()){++busy_;return ColdSubmit::Busy;}
        if(HasWriteFailure())return ColdSubmit::WriteFailed;
        if(stopping_)return ColdSubmit::Stopped;
        if(stats_.outstanding==slots_.size()){++stats_.full;return ColdSubmit::Full;}
        size_t index=next_free_;
        for(size_t n=0;n<slots_.size();++n,index=(index+1)%slots_.size()) {
            auto &slot=slots_[index];
            if(slot.state!=State::Free)continue;
            if(slot.generation==UINT64_MAX)return ColdSubmit::Invalid;
            try {slot.record=record;}catch(...){return ColdSubmit::Invalid;}
            ++slot.generation;slot.state=State::Queued;slot.id.clear();slot.detached=false;
            semantic_watermark_=std::max(semantic_watermark_,record.snapshot.last_timestamp_ns);
            ring_[(head_+queued_)%ring_.size()]=static_cast<uint32_t>(index);++queued_;
            *ticket={static_cast<uint32_t>(index),slot.generation,queue_id_};next_free_=(index+1)%slots_.size();
            ++stats_.accepted;++stats_.outstanding;
            stats_.peak_outstanding=std::max(stats_.peak_outstanding,stats_.outstanding);
            lock.unlock();changed_.notify_one();return ColdSubmit::Accepted;
        }
        return ColdSubmit::Full;
    }
    // Publish an entire bounded batch under one lock. The writer cannot wake
    // between its first and last record and split a shutdown batch into
    // individual WAL syncs. Failure publishes no slot and changes no ticket.
    ColdSubmit TrySubmitBatch(const ColdEvidence *const *records,size_t count,
                             ColdMigrationTicket *tickets) noexcept {
        if(HasWriteFailure())return ColdSubmit::WriteFailed;
        if(detached_only_ || !tickets)return ColdSubmit::Invalid;
        return SubmitBatch(records,count,tickets,false);
    }
    // Acceptance transfers an immutable copy to bounded storage work. It is
    // not a durable acknowledgement and never validates a live flow table.
    ColdSubmit TrySubmitDetached(const ColdEvidence &record,bool retain=true) noexcept {
        const ColdEvidence *pointer=&record;return SubmitBatch(&pointer,1,nullptr,true,nullptr,retain);
    }
    ColdSubmit TrySubmitDetachedBatch(const ColdEvidence *const *records,size_t count) noexcept {
        return SubmitBatch(records,count,nullptr,true);
    }
    // Slow path only after Busy/Full: acquire the producer lock without
    // polling, then wait for bounded capacity. Admission and snapshot copy
    // share this lock, so another producer cannot steal a wakeup's slot.
    // Acceptance remains volatile handoff; this does not wait for its write.
    ColdSubmit WaitSubmitDetached(const ColdEvidence &record,
                                 std::chrono::steady_clock::time_point until,bool retain=true) noexcept {
        const ColdEvidence *pointer=&record;
        return SubmitBatch(&pointer,1,nullptr,true,&until,retain);
    }
private:
    ColdSubmit SubmitBatch(const ColdEvidence *const *records,size_t count,
                          ColdMigrationTicket *tickets,bool detached,
                          const std::chrono::steady_clock::time_point *until=nullptr,bool retain=true) noexcept {
        if(HasWriteFailure())return ColdSubmit::WriteFailed;
        if(!records || !count || count>64 || count>batch_size_)
            return ColdSubmit::Invalid;
        for(size_t i=0;i<count;++i)
            if(!records[i] || records[i]->scope.empty() || records[i]->scope.size()>256)
                return ColdSubmit::Invalid;
        std::unique_lock<std::mutex> lock(mutex_,std::defer_lock);
        if(until) {
            try {
                lock.lock();
                if(!space_available_.wait_until(lock,*until,[this,count]{
                    return stopping_ || HasWriteFailure() || count<=slots_.size()-stats_.outstanding;
                }))return ColdSubmit::Full;
            }catch(...){return ColdSubmit::Invalid;}
        }else if(!lock.try_lock()) {
            ++busy_;if(detached)detached_busy_.fetch_add(1,std::memory_order_relaxed);return ColdSubmit::Busy;
        }
        if(HasWriteFailure())return ColdSubmit::WriteFailed;
        if(stopping_)return ColdSubmit::Stopped;
        if(count>slots_.size()-stats_.outstanding){++stats_.full;if(detached)++stats_.detached_backpressure_full;return ColdSubmit::Full;}
        std::array<uint32_t,64> indices{};size_t found=0;
        for(size_t n=0,index=next_free_;n<slots_.size() && found<count;
            ++n,index=(index+1)%slots_.size()) {
            if(slots_[index].state!=State::Free)continue;
            if(slots_[index].generation==UINT64_MAX)return ColdSubmit::Invalid;
            indices[found++]=static_cast<uint32_t>(index);
        }
        if(found!=count)return ColdSubmit::Full;
        // Copies may allocate scope strings; all slot states stay Free until
        // every copy has succeeded, so even allocation failure is atomic.
        try {for(size_t i=0;i<count;++i)slots_[indices[i]].record=*records[i];}
        catch(...){return ColdSubmit::Invalid;}
        for(size_t i=0;i<count;++i) {
            const uint32_t index=indices[i];auto &slot=slots_[index];
            ++slot.generation;slot.state=State::Queued;slot.id.clear();slot.detached=detached;
            slot.retain=retain;
            semantic_watermark_=std::max(semantic_watermark_,slot.record.snapshot.last_timestamp_ns);
            ring_[(head_+queued_)%ring_.size()]=index;++queued_;
            if(tickets)tickets[i]={index,slot.generation,queue_id_};
        }
        next_free_=(indices[count-1]+1)%slots_.size();
        stats_.accepted+=count;stats_.outstanding+=count;
        stats_.peak_outstanding=std::max(stats_.peak_outstanding,stats_.outstanding);
        if(detached) {
            stats_.detached_accepted+=count;stats_.detached_outstanding+=count;
            stats_.detached_peak_outstanding=std::max(stats_.detached_peak_outstanding,stats_.detached_outstanding);
        }
        lock.unlock();changed_.notify_one();return ColdSubmit::Accepted;
    }
public:
    // Call on the exclusive flow-table owner. A successful validation is only
    // valid until the next mutation of that flow. The controller must consume
    // it in the same owner operation as its atomic release plan. This function
    // does NOT release slabs, admit flows, or change policy missing flags.
    ColdCompletion TryValidate(ColdMigrationTicket ticket,fk_compact_flow_table *table,
                               const std::string &scope,std::string *durable_id,
                               size_t blocking_owner=kNoOwner) noexcept {
        if(!durable_id)return ColdCompletion::Invalid;
        durable_id->clear();
        if(ticket.queue_id!=queue_id_)return ColdCompletion::Invalid;
        std::unique_lock<std::mutex> lock(mutex_,std::try_to_lock);
        if(!lock.owns_lock()){++busy_;return ColdCompletion::Busy;}
        if(ticket.slot>=slots_.size())return ColdCompletion::Invalid;
        auto &slot=slots_[ticket.slot];
        if(slot.generation!=ticket.generation || slot.state==State::Free || slot.detached)return ColdCompletion::Invalid;
        if(blocking_owner!=kNoOwner &&
            (blocking_owner>=stats_.owner_coalesce.registered_owners || owner_waits_[blocking_owner].closed))
            return ColdCompletion::Invalid;
        if(slot.state==State::Queued || slot.state==State::Writing) {
            if(blocking_owner!=kNoOwner) {
                auto &wait=owner_waits_[blocking_owner];
                // A multi-record barrier needs only one still-pending ticket
                // as its scheduling witness. Do not oscillate/notify between
                // all its tickets on every owner polling pass.
                bool pending_witness=false;
                if(wait.waiting && wait.ticket.queue_id==queue_id_ && wait.ticket.slot<slots_.size()) {
                    const auto &witness=slots_[wait.ticket.slot];
                    pending_witness=witness.generation==wait.ticket.generation &&
                        (witness.state==State::Queued || witness.state==State::Writing);
                }
                if(!pending_witness) {
                    wait.ticket=ticket;wait.waiting=true;++stats_.owner_coalesce.wait_entries;
                    changed_.notify_one();
                }
            }
            return ColdCompletion::Pending;
        }
        if(blocking_owner!=kNoOwner && SameTicket(owner_waits_[blocking_owner].ticket,ticket))
            owner_waits_[blocking_owner].waiting=false;
        if(slot.state==State::Failed) {
            slot.state=State::Free;slot.record.scope.clear();slot.id.clear();--stats_.outstanding;
            space_available_.notify_all();return ColdCompletion::WriteFailed;
        }
        if(slot.state!=State::Durable)return ColdCompletion::Invalid;
        // Copy only immutable ticket metadata under the shared queue lock.
        // Capturing and hashing a full TLS record must not serialize owners.
        fk_compact_flow_handle handle{};std::string expected_scope,expected_id;
        try {handle=slot.record.handle;expected_scope=slot.record.scope;expected_id=slot.id;}
        catch(...){return ColdCompletion::Invalid;}
        lock.unlock();
        ColdCompletion result=ColdCompletion::Stale;
        try {
            ColdEvidence current;std::string encoded;
            if(scope==expected_scope && CaptureColdEvidence(table,handle,scope,&current) &&
                EncodeColdEvidence(current,&encoded) && ColdEvidenceStore::Digest(encoded)==expected_id)
                result=ColdCompletion::DurableCurrent;
        }catch(...){return ColdCompletion::Invalid;}
        if(!lock.try_lock()){++busy_;return ColdCompletion::Busy;}
        // Another consumer can finish and immediately reuse this numeric slot
        // while hashing runs. Recheck the complete identity before touching it.
        auto &current_slot=slots_[ticket.slot];
        if(ticket.queue_id!=queue_id_ || current_slot.generation!=ticket.generation ||
            current_slot.state!=State::Durable || current_slot.id!=expected_id ||
            current_slot.record.scope!=expected_scope ||
            current_slot.record.handle.index!=handle.index ||
            current_slot.record.handle.generation!=handle.generation)return ColdCompletion::Invalid;
        if(result==ColdCompletion::DurableCurrent){*durable_id=std::move(expected_id);++stats_.validated;}
        else ++stats_.stale;
        current_slot.state=State::Free;current_slot.record.scope.clear();current_slot.id.clear();--stats_.outstanding;
        space_available_.notify_all();return result;
    }
    ColdMigrationStats Stats() const {std::lock_guard<std::mutex> lock(mutex_);auto result=stats_;result.busy=busy_.load();result.detached_backpressure_busy=detached_busy_.load(std::memory_order_relaxed);result.write_failure=HasWriteFailure();return result;}
    // Shutdown drains accepted writes. It may wait for storage; never call
    // Stop/destruction on the packet receive fast path.
    void Stop() noexcept {
        {std::lock_guard<std::mutex> lock(mutex_);stopping_=true;}
        changed_.notify_one();space_available_.notify_all();if(worker_.joinable())worker_.join();
    }
private:
    std::shared_ptr<EvidenceGainChannel> gain_feedback_;
    uint64_t semantic_watermark_=0;
    void OrderContendedBatch() {
        if(!gain_feedback_ || queued_<=batch_size_)return;
        ++stats_.utility_competitions;
        std::vector<EvidencePersistenceCandidate> candidates;
        std::vector<uint32_t> slots;candidates.reserve(queued_);slots.reserve(queued_);
        for(size_t i=0;i<queued_;++i) {
            const uint32_t index=ring_[(head_+i)%ring_.size()];slots.push_back(index);
            const auto &r=slots_[index].record;
            EvidencePersistenceCandidate candidate{};
            candidate.chain=r.scope+ColdEvidenceStore::EntityKey(r);
            candidate.recoverability_deadline_ns=r.core.component.absolute_deadline_ns;
            candidate.estimated_write_bytes=sizeof(r.core)+sizeof(r.snapshot)+
                r.core.component.owned.stat_bytes+r.core.component.owned.seq_bytes+
                r.core.component.owned.ja4_bytes;
            EvidenceGainFeedback feedback{};
            candidate.gain_known=gain_feedback_->Lookup(r.snapshot.key,
                r.snapshot.first_timestamp_ns,r.core.logical_connection_id,
                static_cast<uint32_t>(std::min<uint64_t>(r.snapshot.packets,UINT32_MAX)),&feedback) &&
                (feedback.required_mask&r.resident_mask)==feedback.required_mask;
            if(candidate.gain_known){candidate.marginal_gain=feedback.gain;++stats_.gain_feedback_hits;}
            else ++stats_.gain_feedback_misses;
            if(candidate.recoverability_deadline_ns && candidate.recoverability_deadline_ns<=semantic_watermark_)
                ++stats_.expired_evidence_candidates;
            candidates.push_back(std::move(candidate));
        }
        const auto order=EvidencePersistenceOrder(candidates,batch_size_,semantic_watermark_,true);
        for(size_t i=0;i<order.size();++i) {
            if(order[i]!=i)++stats_.utility_reorders;
            ring_[(head_+i)%ring_.size()]=slots[order[i]];
        }
    }
    enum class State {Free,Queued,Writing,Durable,Failed};
    struct Slot {ColdEvidence record;std::string id;uint64_t generation=0;State state=State::Free;bool detached=false;bool retain=true;};
    struct OwnerWaitState {ColdMigrationTicket ticket{};bool waiting=false,closed=false;};
    static size_t CheckedOwners(uint32_t us,size_t count,bool detached_only) {
        if(detached_only) {
            // Detached records are already immutable bounded copies, so this
            // wait cannot pin an owner's synchronous migration ticket. The
            // same queue bound, capacity flush, stop flush and sync ACK apply.
            if(us>20000 || count)throw std::invalid_argument("detached migration needs 0 owners and at most 20000 us");
            return 0;
        }
        if(us<=50)return 0; // Preserve the complete legacy scheduling path.
        if(us>500 || !count || count>kMaximumOwners)
            throw std::invalid_argument("51..500 us coalescing requires 1..64 fixed owners");
        return count;
    }
    static bool SameTicket(const ColdMigrationTicket &a,const ColdMigrationTicket &b) noexcept {
        return a.queue_id==b.queue_id && a.slot==b.slot && a.generation==b.generation;
    }
    // Called only under mutex_. Writing/durable/free/old-generation tickets
    // cannot make the next group appear aligned while its owners resume.
    size_t QueuedBlockingOwners() const noexcept {
        size_t count=0;
        for(size_t owner=0;owner<stats_.owner_coalesce.registered_owners;++owner) {
            const auto &wait=owner_waits_[owner];
            if(wait.closed || !wait.waiting || wait.ticket.queue_id!=queue_id_ || wait.ticket.slot>=slots_.size())continue;
            const auto &slot=slots_[wait.ticket.slot];
            if(slot.generation==wait.ticket.generation && slot.state==State::Queued)++count;
        }
        return count;
    }
    bool AllOwnersBlocked() const noexcept {
        if(!OwnerAware() || stats_.owner_coalesce.registered_owners!=owner_waits_.size())return false;
        const auto live=owner_waits_.size()-stats_.owner_coalesce.closed_owners;
        return live && QueuedBlockingOwners()==live;
    }
    inline static std::atomic<uint64_t> next_queue_id_{1};
    const uint64_t queue_id_=NextQueueId();
    std::atomic<uint64_t> busy_{0};
    std::atomic<uint64_t> detached_busy_{0};
    std::atomic<bool> write_failure_{false};
    static uint64_t NextQueueId() {
        uint64_t id=next_queue_id_.load();
        while(id!=0 && id!=UINT64_MAX) {
            if(next_queue_id_.compare_exchange_weak(id,id+1))return id;
        }
        throw std::runtime_error("migration queue identity exhausted");
    }
    ColdEvidenceBatchWriter &writer_;
    std::vector<Slot> slots_;std::vector<uint32_t> ring_;size_t batch_size_;uint32_t maximum_coalesce_us_;
    const bool detached_only_;
    std::vector<OwnerWaitState> owner_waits_;
    // This fixed condition variable fits the existing async control allowance;
    // it owns no additional snapshots, queue slots, or per-waiter heap state.
    static_assert(sizeof(std::condition_variable)<=64,"async producer wait control allowance");
    mutable std::mutex mutex_;std::condition_variable changed_,space_available_;std::thread worker_;
    size_t head_=0,queued_=0,next_free_=0;bool stopping_=false;ColdMigrationStats stats_{};
    static size_t CheckedCapacity(size_t capacity) {
        if(!capacity || capacity>65536)throw std::invalid_argument("invalid migration capacity");
        return capacity;
    }
    void ReclaimDetached(Slot &slot) noexcept {
        slot.state=State::Free;slot.record.scope.clear();slot.id.clear();slot.detached=false;
        --stats_.outstanding;--stats_.detached_outstanding;
    }
    void FailSlot(Slot &slot) noexcept {
        ++stats_.write_failed;
        if(slot.detached){++stats_.detached_failed;ReclaimDetached(slot);}
        else slot.state=State::Failed;
    }
    // A failed batch leaves uncertain durability. No subsequent work can be
    // advertised as successful by this queue; retain failed ticket receipts
    // and reclaim detached work, including accepted but unattempted entries.
    void FailPending() noexcept {
        write_failure_.store(true,std::memory_order_release);stopping_=true;queued_=0;
        for(auto &slot:slots_)if(slot.state==State::Queued || slot.state==State::Writing)FailSlot(slot);
        space_available_.notify_all();
    }
    void Run() noexcept {
        try {
            std::vector<uint32_t> indices;indices.reserve(batch_size_);
            std::vector<const ColdEvidence*> records;records.reserve(batch_size_);
            std::vector<std::string> ids(batch_size_);
            std::vector<uint8_t> retain(batch_size_,1);
            for(;;) {
                {
                    std::unique_lock<std::mutex> lock(mutex_);
                    changed_.wait(lock,[this]{return stopping_ || queued_;});
                    if(!queued_ && stopping_)return;
                    if(!stopping_ && maximum_coalesce_us_ && queued_<batch_size_) {
                        const auto start=std::chrono::steady_clock::now();
                        const auto until=start+std::chrono::microseconds(maximum_coalesce_us_);
                        changed_.wait_until(lock,until,[this]{return stopping_ || queued_>=batch_size_ || AllOwnersBlocked();});
                        if(OwnerAware()) {
                            const auto elapsed=static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::nanoseconds>(
                                std::chrono::steady_clock::now()-start).count());
                            ++stats_.owner_coalesce.wait_calls;stats_.owner_coalesce.wait_total_ns+=elapsed;
                            stats_.owner_coalesce.wait_max_ns=std::max(stats_.owner_coalesce.wait_max_ns,elapsed);
                        }
                    }
                    if(OwnerAware()) {
                        auto &s=stats_.owner_coalesce;
                        const auto waiting=QueuedBlockingOwners();
                        s.waiting_owner_sum_at_flush+=waiting;
                        s.waiting_owner_max_at_flush=std::max<uint64_t>(s.waiting_owner_max_at_flush,waiting);
                        if(stopping_)++s.flush_stop;
                        else if(queued_>=batch_size_)++s.flush_capacity;
                        else if(AllOwnersBlocked())++s.flush_all_owners_blocked;
                        else ++s.flush_deadline;
                    }
                    OrderContendedBatch();
                    indices.clear();records.clear();
                    while(queued_ && indices.size()<batch_size_) {
                        const uint32_t index=ring_[head_];head_=(head_+1)%ring_.size();--queued_;
                        slots_[index].state=State::Writing;indices.push_back(index);records.push_back(&slots_[index].record);
                        retain[indices.size()-1]=slots_[index].retain?1:0;
                    }
                }
                const bool ok=detached_only_?
                    writer_.SaveDetachedBatch(records.data(),records.size(),ids.data(),retain.data()):
                    writer_.SaveBatch(records.data(),records.size(),ids.data());
                if(!ok)write_failure_.store(true,std::memory_order_release);
                {
                    std::lock_guard<std::mutex> lock(mutex_);++stats_.write_batches;
                    for(size_t i=0;i<indices.size();++i) {
                        auto &slot=slots_[indices[i]];
                        if(ok) {
                            ++stats_.written;
                            if(slot.detached){++stats_.detached_written;ReclaimDetached(slot);}
                            else {slot.id=std::move(ids[i]);slot.state=State::Durable;}
                        }else FailSlot(slot);
                    }
                    if(!ok){FailPending();return;}
                }
                if(detached_only_ && !writer_.AcknowledgeDetachedBatch(ids.data(),records.size())) {
                    std::lock_guard<std::mutex> lock(mutex_);FailPending();return;
                }
                space_available_.notify_all();
            }
        }catch(...) {
            std::lock_guard<std::mutex> lock(mutex_);FailPending();
        }
    }
};
}
#endif
