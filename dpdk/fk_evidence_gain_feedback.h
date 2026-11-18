#ifndef FK_EVIDENCE_GAIN_FEEDBACK_H
#define FK_EVIDENCE_GAIN_FEEDBACK_H
#include "fk_native_event_context.h"
#include <array>
#include <atomic>
#include <cmath>
#include <cstring>
#include <fcntl.h>
#include <memory>
#include <new>
#include <stdexcept>
#include <string>
#include <type_traits>
#include <sys/file.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

namespace flowkeep {
// Advisory only: never authorizes an ACK, evidence deletion or slab release.
struct EvidenceGainFeedback {
    fk_flow_key key{};
    uint64_t first_timestamp_ns=0, logical_connection_id=0, sequence=0;
    uint32_t evidence_packet=0, next_packet=0;
    double gain=0, net_utility=0;
    uint8_t required_mask=0, stopped=0;
};
static_assert(std::is_trivially_copyable<EvidenceGainFeedback>::value,"feedback wire copy must be trivial");

// Bounded, per-run cross-process cache. Exact identity checks turn collisions,
// stale observations and unavailable feedback into misses, never wrong values.
class EvidenceGainChannel {
    static constexpr size_t kEntries=16384;
    static constexpr size_t kWords=(sizeof(EvidenceGainFeedback)+7)/8;
    struct alignas(64) Entry {
        std::atomic<uint64_t> sequence{0};
        std::array<std::atomic<uint64_t>,kWords> words{};
    };
    struct Region {uint64_t magic=0,epoch=0;Entry entries[kEntries];};
    static constexpr uint64_t kMagic=UINT64_C(0x464b4741494e3031);
public:
    EvidenceGainChannel(const std::string &base,uint64_t epoch)
        :name_(base+".gain") {
        static_assert(std::atomic<uint64_t>::is_always_lock_free,
                      "cross-process gain feedback requires lock-free atomics");
        if(base.empty() || base[0]!='/' || base.find('/',1)!=std::string::npos ||
           name_.size()>240 || !epoch)throw std::invalid_argument("invalid gain channel binding");
        int fd=shm_open(name_.c_str(),O_CREAT|O_RDWR,0600);
        if(fd<0)throw std::runtime_error("cannot open gain feedback channel");
        bool locked=false;
        try {
            if(flock(fd,LOCK_EX)!=0)throw std::runtime_error("gain channel init lock failed");
            locked=true;struct stat st{};
            if(fstat(fd,&st)!=0)throw std::runtime_error("gain channel stat failed");
            const bool fresh=st.st_size==0;
            if(fresh && ftruncate(fd,sizeof(Region))!=0)
                throw std::runtime_error("gain channel allocation failed");
            if(!fresh && st.st_size!=sizeof(Region))
                throw std::runtime_error("gain channel size mismatch");
            void *p=mmap(nullptr,sizeof(Region),PROT_READ|PROT_WRITE,MAP_SHARED,fd,0);
            if(p==MAP_FAILED)throw std::runtime_error("gain channel mmap failed");
            region_=static_cast<Region*>(p);
            if(fresh) {
                new(region_) Region{};region_->epoch=epoch;region_->magic=kMagic;
                owner_=true;
            }
            if(region_->magic!=kMagic || region_->epoch!=epoch)
                throw std::runtime_error("gain channel run epoch mismatch");
            flock(fd,LOCK_UN);close(fd);
        } catch(...) {
            if(region_){munmap(region_,sizeof(Region));region_=nullptr;}
            if(locked)flock(fd,LOCK_UN);
            close(fd);if(owner_)shm_unlink(name_.c_str());throw;
        }
    }
    ~EvidenceGainChannel(){if(region_)munmap(region_,sizeof(Region));if(owner_)shm_unlink(name_.c_str());}
    EvidenceGainChannel(const EvidenceGainChannel&)=delete;
    EvidenceGainChannel &operator=(const EvidenceGainChannel&)=delete;
    static constexpr size_t Bytes(){return sizeof(Region);}
    uint64_t Published() const noexcept {return published_.load(std::memory_order_relaxed);}
    bool Publish(const EvidenceGainFeedback &value) noexcept {
        if(!value.sequence || !value.first_timestamp_ns || !value.evidence_packet ||
           !std::isfinite(value.gain) || value.gain<0 || !std::isfinite(value.net_utility))return false;
        auto &entry=region_->entries[Hash(value.key,value.first_timestamp_ns,value.logical_connection_id)%kEntries];
        uint64_t version=entry.sequence.load(std::memory_order_acquire);
        if((version&1) || version>UINT64_MAX-2 ||
           !entry.sequence.compare_exchange_strong(version,version+1,std::memory_order_acq_rel))return false;
        std::array<uint64_t,kWords> words{};
        for(size_t i=0;i<kWords;++i)words[i]=entry.words[i].load(std::memory_order_relaxed);
        EvidenceGainFeedback prior{};std::memcpy(static_cast<void*>(&prior),words.data(),sizeof(prior));
        const bool stale=Same(prior,value.key,value.first_timestamp_ns,value.logical_connection_id) &&
            prior.sequence>=value.sequence;
        if(!stale) {
            words={};std::memcpy(words.data(),&value,sizeof(value));
            for(size_t i=0;i<kWords;++i)entry.words[i].store(words[i],std::memory_order_relaxed);
        }
        entry.sequence.store(version+2,std::memory_order_release);
        if(!stale)published_.fetch_add(1,std::memory_order_relaxed);
        return !stale;
    }
    bool Lookup(const fk_flow_key &key,uint64_t first,uint64_t logical,
                uint32_t packet,EvidenceGainFeedback *out) const noexcept {
        if(!out)return false;
        const auto &entry=region_->entries[Hash(key,first,logical)%kEntries];
        const auto before=entry.sequence.load(std::memory_order_acquire);
        if(!before || (before&1))return false;
        std::array<uint64_t,kWords> words{};
        for(size_t i=0;i<kWords;++i)words[i]=entry.words[i].load(std::memory_order_relaxed);
        std::atomic_thread_fence(std::memory_order_acquire);
        if(entry.sequence.load(std::memory_order_acquire)!=before)return false;
        EvidenceGainFeedback value{};std::memcpy(static_cast<void*>(&value),words.data(),sizeof(value));
        if(!Same(value,key,first,logical) || value.evidence_packet>packet)return false;
        *out=value;return true;
    }
private:
    static bool Same(const EvidenceGainFeedback &v,const fk_flow_key &k,uint64_t first,uint64_t logical) {
        return v.first_timestamp_ns==first && v.logical_connection_id==logical &&
            std::memcmp(&v.key,&k,sizeof(k))==0;
    }
    static uint64_t Hash(const fk_flow_key &k,uint64_t first,uint64_t logical) {
        uint64_t h=UINT64_C(14695981039346656037);
        const auto *p=reinterpret_cast<const uint8_t*>(&k);
        for(size_t i=0;i<sizeof(k);++i)h=(h^p[i])*UINT64_C(1099511628211);
        return ((h^first)*UINT64_C(1099511628211))^logical;
    }
    std::string name_;Region *region_=nullptr;bool owner_=false;
    std::atomic<uint64_t> published_{0};
};
}
#endif
