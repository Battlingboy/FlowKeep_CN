#ifndef FK_SPARSE_PREFIX_CHANNEL_H
#define FK_SPARSE_PREFIX_CHANNEL_H
#include "fk_native_event_context.h"
#include <array>
#include <atomic>
#include <cstring>
#include <fcntl.h>
#include <new>
#include <stdexcept>
#include <string>
#include <sys/file.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

namespace flowkeep {
// Lossless sparse transport: only prefixes below a known NEXT (or after STOP)
// may be omitted. An exact terminal snapshot is deposited BEFORE omission.
// Missing/colliding control state falls back to ordinary transport. No slot is
// ever evicted, and identities survive physical slot/generation reuse.
class SparsePrefixChannel {
public:
    struct Identity {
        fk_flow_key key{};
        uint64_t first=0, logical=0;
    };
    struct Prefix {
        uint64_t observation_ns=0;
        uint32_t packet=0, flow_index=0, generation=0;
        uint8_t mask=0;
        std::array<float,FK_DETECTOR_REQUEST_FEATURE_COUNT> features{};
    };
private:
    static constexpr size_t kEntries=262144, kProbes=64;
    static constexpr size_t kWords=(sizeof(Prefix)+7)/8;
    struct alignas(64) Entry {
        std::atomic<uint32_t> occupied{0}; // 0 free, 1 initializing, 2 immutable identity
        Identity identity{};
        std::atomic<uint32_t> initial_next{0}, control{0};
        std::atomic<uint64_t> version{0};
        std::array<std::atomic<uint64_t>,kWords> words{};
    };
    struct Region {uint64_t magic=0,epoch=0;std::atomic<uint64_t> threshold_bits{0};Entry entries[kEntries];};
    static constexpr uint64_t kMagic=UINT64_C(0x464b535052463031);
    static bool Same(const Identity &a,const Identity &b) {
        return a.first==b.first && a.logical==b.logical &&
            std::memcmp(&a.key,&b.key,sizeof(a.key))==0;
    }
    Entry *Find(const Identity &id,bool create) const noexcept {
        uint64_t hash=UINT64_C(14695981039346656037);
        const auto *bytes=reinterpret_cast<const uint8_t*>(&id.key);
        for(size_t i=0;i<sizeof(id.key);++i)hash=(hash^bytes[i])*UINT64_C(1099511628211);
        hash=((hash^id.first)*UINT64_C(1099511628211))^id.logical;
        for(size_t probe=0;probe<kProbes;++probe) {
            auto &entry=region_->entries[(hash+probe)%kEntries];
            auto occupied=entry.occupied.load(std::memory_order_acquire);
            // Never skip an in-progress claim and create a duplicate identity.
            if(occupied==1)return nullptr;
            if(occupied==2) {if(Same(entry.identity,id))return &entry;continue;}
            if(!create)return nullptr;
            if(!entry.occupied.compare_exchange_strong(occupied,1,std::memory_order_acq_rel))
                return nullptr;
            entry.identity=id;
            entry.occupied.store(2,std::memory_order_release);
            return &entry;
        }
        return nullptr;
    }
public:
    SparsePrefixChannel(const std::string &base,uint64_t epoch):name_(base+".prefix") {
        static_assert(std::atomic<uint64_t>::is_always_lock_free &&
                      std::atomic<uint32_t>::is_always_lock_free,"process-shared atomics");
        if(base.empty() || base[0]!='/' || base.find('/',1)!=std::string::npos || name_.size()>240 || !epoch)
            throw std::invalid_argument("invalid sparse prefix binding");
        int fd=shm_open(name_.c_str(),O_CREAT|O_RDWR,0600);
        if(fd<0)throw std::runtime_error("sparse prefix shm_open failed");
        bool locked=false;
        try {
            if(flock(fd,LOCK_EX))throw std::runtime_error("sparse prefix lock failed");
            locked=true;struct stat st{};
            if(fstat(fd,&st))throw std::runtime_error("sparse prefix stat failed");
            const bool fresh=st.st_size==0;
            if(fresh && ftruncate(fd,sizeof(Region)))throw std::runtime_error("sparse prefix allocation failed");
            if(!fresh && st.st_size!=sizeof(Region))throw std::runtime_error("sparse prefix size mismatch");
            void *p=mmap(nullptr,sizeof(Region),PROT_READ|PROT_WRITE,MAP_SHARED,fd,0);
            if(p==MAP_FAILED)throw std::runtime_error("sparse prefix mmap failed");
            region_=static_cast<Region*>(p);
            if(fresh){new(region_) Region{};region_->epoch=epoch;region_->magic=kMagic;owner_=true;}
            if(region_->magic!=kMagic || region_->epoch!=epoch)throw std::runtime_error("sparse prefix epoch mismatch");
            flock(fd,LOCK_UN);close(fd);
        }catch(...) {
            if(region_){munmap(region_,sizeof(Region));region_=nullptr;}
            if(locked)flock(fd,LOCK_UN);
            close(fd);if(owner_)shm_unlink(name_.c_str());throw;
        }
    }
    ~SparsePrefixChannel(){if(region_)munmap(region_,sizeof(Region));if(owner_)shm_unlink(name_.c_str());}
    SparsePrefixChannel(const SparsePrefixChannel&)=delete;
    SparsePrefixChannel &operator=(const SparsePrefixChannel&)=delete;
    static constexpr size_t Bytes(){return sizeof(Region);}
    bool BindThreshold(double threshold) noexcept {
        if(!(threshold>0 && threshold<=1))return false;
        uint64_t bits=0,expected=0;std::memcpy(&bits,&threshold,sizeof(bits));
        return region_->threshold_bits.compare_exchange_strong(expected,bits,std::memory_order_acq_rel) || expected==bits;
    }
    // The first packet is always transported, so service and RX plan from
    // exactly the same input. A failed local plan means no initial pruning.
    void Initialize(const Identity &id,uint32_t next) noexcept {
        if(next<1 || next>20)return;
        if(auto *entry=Find(id,true))entry->initial_next.store(next,std::memory_order_release);
    }
    void PublishControl(const Identity &id,uint32_t observed,uint32_t next,bool stopped) noexcept {
        if(observed>20 || next>20 || (!next && !stopped))return;
        if(auto *entry=Find(id,false)) {
            const uint32_t value=observed | (next<<8) | (stopped?1u<<16:0) | (1u<<17);
            entry->control.store(value,std::memory_order_release);
        }
    }
    bool MayOmit(const Identity &id,uint32_t packet) const noexcept {
        if(packet<=1 || packet>20)return false;
        auto *entry=Find(id,false);if(!entry)return false;
        const uint32_t control=entry->control.load(std::memory_order_acquire);
        if((control&(1u<<17)) && (control&255u)<=packet) {
            if(control&(1u<<16))return true;
            return packet<((control>>8)&255u);
        }
        return packet<entry->initial_next.load(std::memory_order_acquire);
    }
    bool Deposit(const Identity &id,const Prefix &prefix) noexcept {
        if(prefix.packet<1 || prefix.packet>20)return false;
        auto *entry=Find(id,false);if(!entry)return false;
        uint64_t version=entry->version.load(std::memory_order_acquire);
        if((version&1) || version>UINT64_MAX-2 ||
           !entry->version.compare_exchange_strong(version,version+1,std::memory_order_acq_rel))return false;
        std::array<uint64_t,kWords> words{};std::memcpy(words.data(),&prefix,sizeof(prefix));
        for(size_t i=0;i<kWords;++i)entry->words[i].store(words[i],std::memory_order_relaxed);
        entry->version.store(version+2,std::memory_order_release);return true;
    }
    bool Lookup(const Identity &id,Prefix *prefix) const noexcept {
        auto *entry=Find(id,false);if(!entry || !prefix)return false;
        const auto before=entry->version.load(std::memory_order_acquire);
        if(!before || (before&1))return false;
        std::array<uint64_t,kWords> words{};
        for(size_t i=0;i<kWords;++i)words[i]=entry->words[i].load(std::memory_order_relaxed);
        std::atomic_thread_fence(std::memory_order_acquire);
        if(entry->version.load(std::memory_order_acquire)!=before)return false;
        std::memcpy(static_cast<void*>(prefix),words.data(),sizeof(*prefix));return true;
    }
private:
    std::string name_;Region *region_=nullptr;bool owner_=false;
};
}
#endif
