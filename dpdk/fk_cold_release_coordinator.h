#ifndef FK_COLD_RELEASE_COORDINATOR_H
#define FK_COLD_RELEASE_COORDINATOR_H
#include "fk_cold_migration_queue.h"
#include <array>
namespace flowkeep {
// One owner-thread transaction, at most 64 victims plus the incoming flow.
// Caller freezes table mutations across pending retries. IDs remain available
// until explicit Finish() after commit; the coordinator never releases slabs.
class ColdReleaseCoordinator {
public:
    static constexpr size_t kCapacity=65;
    enum class Status { Idle, Waiting, Ready, Failed };
    ColdReleaseCoordinator(ColdMigrationQueue &queue,fk_compact_flow_table *table,std::string scope,
                           size_t blocking_owner=ColdMigrationQueue::kNoOwner)
        :queue_(queue),table_(table),scope_(std::move(scope)),blocking_owner_(blocking_owner) {
        if(!table_ || scope_.empty() || scope_.size()>256)throw std::invalid_argument("invalid release coordinator");
    }
    ColdReleaseCoordinator(const ColdReleaseCoordinator&)=delete;
    ColdReleaseCoordinator &operator=(const ColdReleaseCoordinator&)=delete;
    fk_compact_release_guard callbacks(){return {this,&Authorize};}
    Status status() const{return status_;}
    size_t count() const{return count_;}
    const std::string *durable_id(size_t index) const {
        return status_==Status::Ready && index<count_ ? &entries_[index].id : nullptr;
    }
    // Failure cleanup is nonblocking; poll until accepted tickets have completed.
    // Failed state is sticky until Finish(), so failures cannot authorize release.
    bool Drain() noexcept {
        status_=Status::Failed;
        bool drained=true;
        for(size_t i=0;i<count_;++i)if(entries_[i].submitted) {
            std::string id;
            const auto result=queue_.TryValidate(entries_[i].ticket,table_,scope_,&id);
            if(result==ColdCompletion::Pending || result==ColdCompletion::Busy)drained=false;
            else if(result==ColdCompletion::Invalid) {status_=Status::Failed;drained=false;}
            else {entries_[i].submitted=false;if(result==ColdCompletion::DurableCurrent)entries_[i].id=std::move(id);}
        }
        return drained;
    }
    // Caller must copy IDs into its durable manifest before finishing a commit.
    bool Finish() noexcept {
        for(size_t i=0;i<count_;++i)if(entries_[i].submitted)return false;
        for(size_t i=0;i<count_;++i)entries_[i]={};
        count_=0;status_=Status::Idle;return true;
    }
private:
    struct Entry {fk_compact_release_request request{};ColdMigrationTicket ticket{};bool submitted=false;std::string id;};
    ColdMigrationQueue &queue_;fk_compact_flow_table *table_;std::string scope_;
    size_t blocking_owner_;
    std::array<Entry,kCapacity> entries_{};size_t count_=0;Status status_=Status::Idle;
    static bool Same(const fk_compact_release_request &a,const fk_compact_release_request &b) {
        return a.handle.index==b.handle.index && a.handle.generation==b.handle.generation && a.mask==b.mask;
    }
    static bool Authorize(void *context,const fk_compact_release_request *requests,size_t count) noexcept {
        auto &self=*static_cast<ColdReleaseCoordinator*>(context);
        try{return self.Check(requests,count);}catch(...){self.status_=Status::Failed;return false;}
    }
    bool Check(const fk_compact_release_request *requests,size_t count) {
        if(status_==Status::Failed)return false;
        if(!requests || !count || count>kCapacity){status_=Status::Failed;return false;}
        if(status_==Status::Idle) {
            // Validate the complete shape before accepting any writes.
            for(size_t i=0;i<count;++i) {
                if(!requests[i].mask || (requests[i].mask&~FK_COMPONENT_FULL)){status_=Status::Failed;return false;}
                for(size_t j=0;j<i;++j)if(requests[i].handle.index==requests[j].handle.index){status_=Status::Failed;return false;}
            }
            count_=count;for(size_t i=0;i<count;++i)entries_[i].request=requests[i];
            status_=Status::Waiting;
        }else {
            if(count!=count_){status_=Status::Failed;return false;}
            for(size_t i=0;i<count;++i)if(!Same(entries_[i].request,requests[i])){status_=Status::Failed;return false;}
        }
        bool ready=true;
        for(size_t i=0;i<count_;++i) {
            auto &entry=entries_[i];
            if(entry.submitted) {
                const auto result=queue_.TryValidate(entry.ticket,table_,scope_,&entry.id,blocking_owner_);
                if(result==ColdCompletion::Pending || result==ColdCompletion::Busy){ready=false;continue;}
                if(result==ColdCompletion::Invalid){status_=Status::Failed;return false;}
                entry.submitted=false;
                if(result!=ColdCompletion::DurableCurrent){status_=Status::Failed;return false;}
            }
            ColdEvidence record;std::string encoded;
            if(!CaptureColdEvidence(table_,entry.request.handle,scope_,&record) ||
                (entry.request.mask&record.resident_mask)!=entry.request.mask){status_=Status::Failed;return false;}
            if(!entry.id.empty()) {
                if(!EncodeColdEvidence(record,&encoded) || ColdEvidenceStore::Digest(encoded)!=entry.id){status_=Status::Failed;return false;}
                continue;
            }
            ready=false;
            const auto result=queue_.TrySubmit(record,&entry.ticket);
            if(result==ColdSubmit::Accepted)entry.submitted=true;
            else if(result!=ColdSubmit::Busy && result!=ColdSubmit::Full){status_=Status::Failed;return false;}
        }
        status_=ready?Status::Ready:Status::Waiting;return ready;
    }
};
}
#endif
