#ifndef FK_PREFIX_VERSION_STORE_H
#define FK_PREFIX_VERSION_STORE_H

#include "fk_sparse_prefix_channel.h"
#include "fk_ready_bitmap.h"
#include "fk_feature_validation.h"
#include <algorithm>
#include <cmath>
#include <new>
#include <type_traits>

namespace flowkeep {

// Run-bounded immutable evidence, indexed by semantic identity AND packet.
// No last-prefix overwrite or speculative acknowledgement. Optional recycling
// is gated by final selection and durable selected evidence, never by age.
class PrefixVersionStore {
public:
    using Identity=SparsePrefixChannel::Identity;
    class ReadHandle {
        friend class PrefixVersionStore;
        const void *region_=nullptr;
        uint32_t index_=0;
    public:
        bool Bound() const noexcept {return region_!=nullptr;}
        uint32_t Slot() const noexcept {return index_;}
    };
    // Per-reader hint to an immutable directory key, never a cached STOP
    // decision. Re-read current generation and restart atomics on every hit.
    class CutoffHandle {
        friend class PrefixVersionStore;
        const void *region_=nullptr;
        uint32_t index_=0;
    };
    struct Prefix {
        SparsePrefixChannel::Prefix evidence{};
        uint64_t physical_ns=0;
    };
private:
    static constexpr uint32_t kEntries=262144, kVersions=1048576;
    struct Entry {
        std::atomic<uint32_t> occupied{0};
        Identity identity{};
        uint64_t first_input_sequence=UINT64_MAX;
        std::atomic<uint32_t> stopped{0};
        std::atomic<uint32_t> payload_users{0},sealed{0};
        std::atomic<uint32_t> versions[20]{};
        std::atomic<uint32_t> latest{0},first_next{0};
    };
    union EntrySlot { Entry value; EntrySlot() noexcept {} };
    struct CutoffEntry {
        std::atomic<uint32_t> occupied{0};
        fk_flow_key key{};
        std::atomic<uint32_t> current{0};
        std::atomic<uint64_t> restart_plus_one{0};
    };
    // Start each slot's lifetime without constructing or touching an unused
    // Prefix. Publish constructs the member exactly once, before its existing
    // release publication; published rows remain immutable for this whole run.
    union VersionSlot {
        Prefix value;
        VersionSlot() noexcept {}
    };
    static_assert(std::is_trivially_copyable<Prefix>::value &&
                  std::is_trivially_destructible<Prefix>::value &&
                  std::is_nothrow_copy_constructible<Prefix>::value,
                  "immutable prefixes must support nonthrowing in-place copies");
    static_assert(sizeof(VersionSlot)==sizeof(Prefix) &&
                  alignof(VersionSlot)==alignof(Prefix) &&
                  std::is_standard_layout<VersionSlot>::value &&
                  std::is_trivially_destructible<VersionSlot>::value,
                  "lazy slots must preserve the shared prefix representation");
    struct Region {
        uint64_t magic=0,epoch=0;
        std::atomic<uint32_t> used{0},fault{0};
        std::atomic<uint32_t> recycling_mode{0},bulk_recycling_mode{0},allocated{0},live{0},peak_live{0};
        std::atomic<uint64_t> free_head{0},recycled{0},late_discarded{0},retired{0};
        std::atomic<uint64_t> threshold_bits{0};
        std::atomic<uint64_t> maximum_semantic{0};
        std::atomic<uint32_t> cutoff_enabled{0};
        CutoffEntry cutoffs[kEntries];
        // The directory is pinned and small; identity objects are contiguous,
        // constructed once on first claim and never moved/reused in this run.
        std::atomic<uint32_t> directory[kEntries]{};
        std::atomic<uint32_t> entry_count{0};
        std::atomic<uint32_t> free_next[kVersions]{};
        ReadyBitmap<kEntries> ready;
        EntrySlot entries[kEntries];
        VersionSlot versions[kVersions];
        // Explicit default construction initializes metadata through its member
        // initializers, without aggregate value-initialization of all payload.
        Region() noexcept {}
    };
    static_assert(std::is_standard_layout<Region>::value,
                  "the shared region must retain a standard layout");
    static constexpr uint64_t kMagic=UINT64_C(0x464b505652533037);
    static constexpr uint32_t kRetired=uint32_t(1)<<31;
    bool AcquirePayload(Entry &entry) const noexcept {
        if(!RecyclingEnabled())return true;
        auto users=entry.payload_users.load(std::memory_order_acquire);
        while(!(users&kRetired)) {
            if(users==kRetired-1)return false;
            if(entry.payload_users.compare_exchange_weak(users,users+1,
                    std::memory_order_acq_rel,std::memory_order_acquire))return true;
        }
        return false;
    }
    void RecyclePayloads(Entry &entry) const noexcept {
        // Each immutable identity is retired once, after its last reader exits.
        // Link its private chain before publishing the whole chain in one CAS.
        if(BulkRecyclingEnabled()) {
            uint32_t slots[20],count=0;
            for(auto &version:entry.versions) {
                const auto slot=version.exchange(0,std::memory_order_acq_rel);
                if(slot)slots[count++]=slot;
            }
            if(!count)return;
            for(uint32_t i=1;i<count;++i)
                region_->free_next[slots[i-1]-1].store(slots[i],std::memory_order_relaxed);
            region_->live.fetch_sub(count,std::memory_order_relaxed);
            region_->recycled.fetch_add(count,std::memory_order_relaxed);
            auto head=region_->free_head.load(std::memory_order_acquire);
            for(;;) {
                region_->free_next[slots[count-1]-1].store(uint32_t(head),std::memory_order_relaxed);
                const uint64_t next=((head>>32)+1)<<32 | slots[0];
                if(region_->free_head.compare_exchange_weak(head,next,
                        std::memory_order_acq_rel,std::memory_order_acquire))return;
            }
        }
        // Scalar control retains H4's exact reclaim path.
        for(auto &version:entry.versions) {
            const uint32_t slot=version.exchange(0,std::memory_order_acq_rel);
            if(!slot)continue;
            region_->live.fetch_sub(1,std::memory_order_relaxed);
            region_->recycled.fetch_add(1,std::memory_order_relaxed);
            auto head=region_->free_head.load(std::memory_order_acquire);
            for(;;) {
                region_->free_next[slot-1].store(uint32_t(head),std::memory_order_relaxed);
                const uint64_t next=((head>>32)+1)<<32 | slot;
                if(region_->free_head.compare_exchange_weak(head,next,
                        std::memory_order_release,std::memory_order_acquire))break;
            }
        }
    }
    void ReleasePayload(Entry &entry) const noexcept {
        if(RecyclingEnabled() && entry.payload_users.fetch_sub(1,
                std::memory_order_acq_rel)==kRetired+1)RecyclePayloads(entry);
    }
    struct PayloadLease {
        const PrefixVersionStore *store;Entry *entry;
        ~PayloadLease(){if(entry)store->ReleasePayload(*entry);}
    };
    uint32_t AllocatePayload() noexcept {
        auto head=region_->free_head.load(std::memory_order_acquire);
        while(uint32_t(head)) {
            const auto slot=uint32_t(head);
            const uint64_t next=((head>>32)+1)<<32 |
                region_->free_next[slot-1].load(std::memory_order_relaxed);
            if(region_->free_head.compare_exchange_weak(head,next,
                    std::memory_order_acq_rel,std::memory_order_acquire))return slot-1;
        }
        return region_->allocated.fetch_add(1,std::memory_order_relaxed);
    }
    ReadyBitmap<kEntries>::Cursor ready_cursor_;
    bool ready_top_=false;
    CutoffEntry *FindCutoff(const fk_flow_key &key,bool create) const noexcept {
        uint64_t hash=UINT64_C(14695981039346656037);
        const auto *bytes=reinterpret_cast<const uint8_t*>(&key);
        for(size_t i=0;i<sizeof(key);++i)hash=(hash^bytes[i])*UINT64_C(1099511628211);
        for(size_t probe=0;probe<256;++probe) {
            auto &e=region_->cutoffs[(hash+probe)%kEntries];
            auto state=e.occupied.load(std::memory_order_acquire);
            for(unsigned spin=0;state==1 && create && spin<100000;++spin)
                state=e.occupied.load(std::memory_order_acquire);
            if(state==1)return nullptr;
            if(state==2){if(std::memcmp(&e.key,&key,sizeof(key))==0)return &e;continue;}
            if(!create)return nullptr;
            if(!e.occupied.compare_exchange_strong(state,1,std::memory_order_acq_rel)){--probe;continue;}
            e.key=key;e.occupied.store(2,std::memory_order_release);return &e;
        }
        return nullptr;
    }
    static bool Same(const Identity &a,const Identity &b) {
        return a.first==b.first && a.logical==b.logical &&
            std::memcmp(&a.key,&b.key,sizeof(a.key))==0;
    }
    Entry &EntryAt(uint32_t index) const noexcept {return region_->entries[index].value;}
    uint32_t EntryIndex(const Entry *entry) const noexcept {
        const auto *base=reinterpret_cast<const unsigned char*>(region_->entries);
        const auto *address=reinterpret_cast<const unsigned char*>(entry);
        return static_cast<uint32_t>((address-base)/sizeof(EntrySlot));
    }
    Entry *Find(const Identity &id,bool create) const noexcept {
        uint64_t hash=UINT64_C(14695981039346656037);
        const auto *bytes=reinterpret_cast<const uint8_t*>(&id.key);
        for(size_t i=0;i<sizeof(id.key);++i)hash=(hash^bytes[i])*UINT64_C(1099511628211);
        hash=((hash^id.first)*UINT64_C(1099511628211))^id.logical;
        for(size_t probe=0;probe<256;++probe) {
            auto &bucket=region_->directory[(hash+probe)%kEntries];
            auto occupied=bucket.load(std::memory_order_acquire);
            for(unsigned spin=0;occupied==1 && create && spin<100000;++spin)
                occupied=bucket.load(std::memory_order_acquire);
            if(occupied==1)return nullptr;
            if(occupied>=2){
                const uint32_t index=occupied-2;
                if(index>=kEntries){region_->fault.store(1,std::memory_order_release);return nullptr;}
                auto &entry=EntryAt(index);
                if(Same(entry.identity,id))return &entry;
                continue;
            }
            if(!create)return nullptr;
            if(!bucket.compare_exchange_strong(occupied,1,std::memory_order_acq_rel)){
                --probe;continue;
            }
            const uint32_t index=region_->entry_count.fetch_add(1,std::memory_order_relaxed);
            if(index>=kEntries){region_->fault.store(1,std::memory_order_release);return nullptr;}
            auto *entry=::new (static_cast<void*>(&region_->entries[index].value)) Entry;
            entry->identity=id;entry->occupied.store(2,std::memory_order_relaxed);
            // Release publishes object lifetime, identity and initialized atomics.
            bucket.store(index+2,std::memory_order_release);return entry;
        }
        return nullptr;
    }

public:
    // Bind once before publication; peers attaching later inherit this mode.
    bool BindRecycling(bool enabled) noexcept {
        const uint32_t wanted=enabled?2:1;
        uint32_t expected=0;
        if(region_->used.load(std::memory_order_acquire))
            return region_->recycling_mode.load(std::memory_order_acquire)==wanted;
        return region_->recycling_mode.compare_exchange_strong(expected,wanted,
            std::memory_order_acq_rel) || expected==wanted;
    }
    bool BindBulkRecycling(bool enabled) noexcept {
        const uint32_t wanted=enabled?2:1;uint32_t expected=0;
        if(region_->used.load(std::memory_order_acquire))
            return region_->bulk_recycling_mode.load(std::memory_order_acquire)==wanted;
        return region_->bulk_recycling_mode.compare_exchange_strong(expected,wanted,
            std::memory_order_acq_rel) || expected==wanted;
    }
    bool BulkRecyclingEnabled() const noexcept {
        return region_->bulk_recycling_mode.load(std::memory_order_acquire)==2;
    }
    bool RecyclingEnabled() const noexcept {
        return region_->recycling_mode.load(std::memory_order_acquire)==2;
    }
    // A local binding names an immutable, non-reused identity-directory entry.
    // Validate both mapping and semantic identity before any lifecycle mutation.
    // This is not a payload lease or proof of durability.
    bool Matches(const ReadHandle &handle,const Identity &id) const noexcept {
        return handle.region_==region_ && handle.index_<region_->entry_count.load(std::memory_order_acquire) &&
            handle.index_<kEntries && !Faulted() &&
            EntryAt(handle.index_).occupied.load(std::memory_order_acquire)==2 &&
            Same(EntryAt(handle.index_).identity,id);
    }
    // Caller proves no more scoring requests can be issued for this identity.
    // Sealing alone does not free any bytes: selection can still read history.
    bool SealFinalized(const Identity &id) noexcept {
        if(!RecyclingEnabled())return true;
        auto *entry=Find(id,false);if(!entry || Faulted())return false;
        // Monotone seal bits: re-sealing must never restore a consumed claim.
        entry->sealed.fetch_or(1u,std::memory_order_acq_rel);return true;
    }
    bool SealFinalized(const Identity &id,const ReadHandle &handle) noexcept {
        if(!Matches(handle,id))return false;
        if(!RecyclingEnabled())return true;
        auto *entry=&EntryAt(handle.index_);if(!entry || Faulted())return false;
        // Monotone seal bits: re-sealing must never restore a consumed claim.
        entry->sealed.fetch_or(1u,std::memory_order_acq_rel);return true;
    }
    // Opt-in single-final-sink contract for a fresh, exclusively owned evidence
    // database. Identity directory entries never move or reuse in this run.
    // This claim is NOT a durable acknowledgement and does not reclaim payload.
    bool ClaimFinalEvidenceSubmission(const Identity &id) noexcept {
        if(!RecyclingEnabled() || Faulted())return false;
        auto *entry=Find(id,false);
        if(!entry || (entry->payload_users.load(std::memory_order_acquire)&kRetired))return false;
        uint32_t expected=1u;
        if(!entry->sealed.compare_exchange_strong(expected,3u,
                std::memory_order_acq_rel,std::memory_order_acquire))return false;
        return !(entry->payload_users.load(std::memory_order_acquire)&kRetired);
    }
    bool ClaimFinalEvidenceSubmission(const Identity &id,const ReadHandle &handle) noexcept {
        if(!RecyclingEnabled() || Faulted())return false;
        auto *entry=Matches(handle,id)?&EntryAt(handle.index_):nullptr;
        if(!entry || (entry->payload_users.load(std::memory_order_acquire)&kRetired))return false;
        uint32_t expected=1u;
        if(!entry->sealed.compare_exchange_strong(expected,3u,
                std::memory_order_acq_rel,std::memory_order_acquire))return false;
        return !(entry->payload_users.load(std::memory_order_acquire)&kRetired);
    }
    // Called only after synchronous selected-WAL success (or no actual score).
    // Readers never observe a different identity through a recycled slot.
    bool RetireFinalized(const Identity &id) noexcept {
        if(!RecyclingEnabled())return true;
        auto *entry=Find(id,false);
        if(!entry || Faulted() || !entry->sealed.load(std::memory_order_acquire))return false;
        const auto old=entry->payload_users.fetch_or(kRetired,std::memory_order_acq_rel);
        if(old&kRetired)return true;
        region_->retired.fetch_add(1,std::memory_order_relaxed);
        if(!old)RecyclePayloads(*entry);
        return true;
    }
    bool RetireFinalized(const Identity &id,const ReadHandle &handle) noexcept {
        if(!Matches(handle,id))return false;
        if(!RecyclingEnabled())return true;
        auto *entry=&EntryAt(handle.index_);
        if(!entry || Faulted() || !entry->sealed.load(std::memory_order_acquire))return false;
        const auto old=entry->payload_users.fetch_or(kRetired,std::memory_order_acq_rel);
        if(old&kRetired)return true;
        region_->retired.fetch_add(1,std::memory_order_relaxed);
        if(!old)RecyclePayloads(*entry);
        return true;
    }
    uint32_t PayloadSlotsAllocated() const noexcept {return region_->allocated.load();}
    uint32_t PayloadsLive() const noexcept {return region_->live.load();}
    uint32_t PayloadsPeakLive() const noexcept {return region_->peak_live.load();}
    uint64_t PayloadsRecycled() const noexcept {return region_->recycled.load();}
    uint64_t LateDiscarded() const noexcept {return region_->late_discarded.load();}
    uint64_t RetiredIdentities() const noexcept {return region_->retired.load();}
    void EnableCutoff() noexcept {region_->cutoff_enabled.store(1,std::memory_order_release);}
    void Stop(const ReadHandle &handle) noexcept {
        if(handle.region_==region_ && handle.index_<kEntries)
            EntryAt(handle.index_).stopped.store(1,std::memory_order_release);
    }
    // A read-only terminal marker replaces lifecycle work after STOP/packet 20.
    // A new TCP SYN invalidates the old generation before its owner sees it.
    bool DiscardAfterCutoff(const fk_flow_key &key,uint64_t sequence,bool bare_syn,
                           CutoffHandle *hint=nullptr) const noexcept {
        if(!region_->cutoff_enabled.load(std::memory_order_acquire))return false;
        CutoffEntry *c=nullptr;
        if(hint && hint->region_==region_ && hint->index_<kEntries) {
            auto *candidate=&region_->cutoffs[hint->index_];
            if(std::memcmp(&candidate->key,&key,sizeof(key))==0)c=candidate;
        }
        if(!c)c=FindCutoff(key,bare_syn);
        if(!c)return false;
        if(hint){hint->region_=region_;hint->index_=static_cast<uint32_t>(c-region_->cutoffs);}
        if(bare_syn) {
            if(sequence==UINT64_MAX)return false;
            auto old=c->restart_plus_one.load(std::memory_order_relaxed);
            while(old<sequence+1 && !c->restart_plus_one.compare_exchange_weak(
                old,sequence+1,std::memory_order_release,std::memory_order_relaxed)){}
            return false;
        }
        const uint32_t slot=c->current.load(std::memory_order_acquire);
        if(!slot || slot>kEntries)return false;
        const auto &e=EntryAt(slot-1);
        const auto restart=c->restart_plus_one.load(std::memory_order_acquire);
        if(e.first_input_sequence==UINT64_MAX || sequence<=e.first_input_sequence ||
           (sequence>=restart && e.first_input_sequence+1<restart))return false;
        return e.stopped.load(std::memory_order_acquire) || e.latest.load(std::memory_order_acquire)>=20;
    }
    static constexpr uint32_t EntryCapacity(){return kEntries;}
    uint32_t IdentitySlotsAllocated() const noexcept {return region_->entry_count.load(std::memory_order_acquire);}
    static constexpr size_t IdentityMetadataBytesPerSlot(){return sizeof(EntrySlot);}
    static constexpr size_t PinnedMetadataBytes(){return offsetof(Region,entries);}
    bool TakeNotification(uint32_t *index) noexcept {
        return ready_top_?region_->ready.TakeTop(ready_cursor_,index):
                          region_->ready.Take(ready_cursor_,index);
    }
    bool ReadyTopEnabled() const noexcept {return ready_top_;}
    // A semantic identity never moves, is overwritten or reused in this
    // run-bounded pool. Resolve it once; packet publication still uses acquire
    // loads on every access. Handles are local to this mapping, not SHM ABI.
    bool Resolve(const Identity &id,ReadHandle *handle) const noexcept {
        if(!handle || Faulted())return false;
        auto *entry=Find(id,false);if(!entry)return false;
        handle->region_=region_;handle->index_=EntryIndex(entry);
        return true;
    }
    bool Lookup(const ReadHandle &handle,uint32_t packet,Prefix *prefix) const noexcept {
        if(handle.region_!=region_ || handle.index_>=kEntries || !prefix ||
           packet<1 || packet>20 || Faulted())return false;
        auto &entry=EntryAt(handle.index_);
        if(!AcquirePayload(entry))return false;
        PayloadLease lease{this,&entry};
        const uint32_t slot=entry.versions[packet-1].load(std::memory_order_acquire);
        if(!slot || slot>kVersions)return false;
        *prefix=region_->versions[slot-1].value;return prefix->evidence.packet==packet;
    }
    uint32_t Latest(const ReadHandle &handle) const noexcept {
        return handle.region_==region_ && handle.index_<kEntries?
            EntryAt(handle.index_).latest.load(std::memory_order_acquire):0;
    }
    uint32_t FirstNext(const ReadHandle &handle) const noexcept {
        if(handle.region_!=region_ || handle.index_>=kEntries)return 0;
        const auto &entry=EntryAt(handle.index_);
        return entry.latest.load(std::memory_order_acquire)?entry.first_next.load(std::memory_order_relaxed):0;
    }
    PrefixVersionStore(const std::string &base,uint64_t epoch):name_(base+".versions") {
        if(const char *v=std::getenv("FK_READY_BITMAP_TOP")) {
            if(std::strcmp(v,"0") && std::strcmp(v,"1"))
                throw std::invalid_argument("invalid ready bitmap top flag");
            ready_top_=std::strcmp(v,"1")==0;
        }
        static_assert(std::atomic<uint64_t>::is_always_lock_free &&
                      std::atomic<uint32_t>::is_always_lock_free,"shared atomics must be lock free");
        if(base.empty() || base[0]!='/' || base.find('/',1)!=std::string::npos || name_.size()>240 || !epoch)
            throw std::invalid_argument("invalid prefix version binding");
        int fd=shm_open(name_.c_str(),O_CREAT|O_RDWR,0600);
        if(fd<0)throw std::runtime_error("prefix versions shm_open failed");
        bool locked=false;
        try {
            if(flock(fd,LOCK_EX))throw std::runtime_error("prefix versions lock failed");
            locked=true;struct stat st{};
            if(fstat(fd,&st))throw std::runtime_error("prefix versions stat failed");
            const bool fresh=st.st_size==0;
            if(fresh && ftruncate(fd,sizeof(Region)))throw std::runtime_error("prefix versions allocation failed");
            if(!fresh && st.st_size!=sizeof(Region))throw std::runtime_error("prefix versions size mismatch");
            void *p=mmap(nullptr,sizeof(Region),PROT_READ|PROT_WRITE,MAP_SHARED,fd,0);
            if(p==MAP_FAILED)throw std::runtime_error("prefix versions mmap failed");
            region_=static_cast<Region*>(p);
            if(fresh){new(region_) Region{};region_->epoch=epoch;region_->magic=kMagic;owner_=true;}
            if(region_->magic!=kMagic || region_->epoch!=epoch)throw std::runtime_error("prefix versions epoch mismatch");
            // Optional RX experiment: keep the hot directory resident without
            // faulting the lazy payload arena or changing its reclaim rules.
            if(const char* pin=std::getenv("FK_RX_PIN_METADATA")) {
                if(std::strcmp(pin,"1")==0 && mlock(region_,offsetof(Region,entries))!=0)
                    throw std::runtime_error("version hot metadata mlock failed");
            }
            flock(fd,LOCK_UN);close(fd);
        }catch(...) {
            if(region_){munmap(region_,sizeof(Region));region_=nullptr;}
            if(locked)flock(fd,LOCK_UN);
            close(fd);if(owner_)shm_unlink(name_.c_str());throw;
        }
    }
    ~PrefixVersionStore(){if(region_)munmap(region_,sizeof(Region));if(owner_)shm_unlink(name_.c_str());}
    PrefixVersionStore(const PrefixVersionStore&)=delete;
    PrefixVersionStore &operator=(const PrefixVersionStore&)=delete;
    static constexpr size_t Bytes(){return sizeof(Region);}
    bool BindThreshold(double threshold) noexcept {
        if(!(threshold>0 && threshold<=1))return false;
        uint64_t bits=0,expected=0;std::memcpy(&bits,&threshold,sizeof(bits));
        return region_->threshold_bits.compare_exchange_strong(expected,bits,std::memory_order_acq_rel) || expected==bits;
    }
    // Sole producer for a semantic flow must publish consecutively, including
    // packet 1. This is checked before making a version visible to readers.
    bool Publish(const Identity &id,const Prefix &prefix,uint32_t first_next=0,
                 uint64_t input_sequence=UINT64_MAX) noexcept {
        const uint32_t packet=prefix.evidence.packet;
        if(Faulted() || !id.first || !prefix.physical_ns || packet<1 || packet>20 ||
           prefix.evidence.observation_ns<id.first || !prefix.evidence.generation ||
           (packet==1 && (first_next<1 || first_next>20)))return Fail();
        auto *entry=Find(id,packet==1);
        if(!entry || entry->latest.load(std::memory_order_acquire)+1!=packet)return Fail();
        if(packet==1) {
            entry->first_input_sequence=input_sequence;
            if(region_->cutoff_enabled.load(std::memory_order_acquire)) {
                auto *c=FindCutoff(id.key,true);if(!c)return Fail();
                c->current.store(EntryIndex(entry)+1,std::memory_order_release);
            }
        }
        if(!FeatureValuesValid(prefix.evidence.features.data(),
                              prefix.evidence.features.size()))return Fail();
        if(region_->used.fetch_add(1,std::memory_order_relaxed)>=kVersions)return Fail();
        const bool retained=AcquirePayload(*entry);
        PayloadLease lease{this,retained?entry:nullptr};
        if(retained) {
            const uint32_t slot=AllocatePayload();if(slot>=kVersions)return Fail();
            const auto live=region_->live.fetch_add(1,std::memory_order_relaxed)+1;
            auto peak=region_->peak_live.load(std::memory_order_relaxed);
            while(peak<live && !region_->peak_live.compare_exchange_weak(peak,live,std::memory_order_relaxed)){}
            ::new (static_cast<void*>(&region_->versions[slot].value)) Prefix(prefix);
            entry->versions[packet-1].store(slot+1,std::memory_order_release);
        }else {
            if(!(entry->payload_users.load(std::memory_order_acquire)&kRetired))return Fail();
            region_->late_discarded.fetch_add(1,std::memory_order_relaxed);
        }
        if(packet==1)entry->first_next.store(first_next,std::memory_order_relaxed);
        entry->latest.store(packet,std::memory_order_release);
        auto prior=region_->maximum_semantic.load(std::memory_order_relaxed);
        while(prior<prefix.evidence.observation_ns && !region_->maximum_semantic.compare_exchange_weak(
            prior,prefix.evidence.observation_ns,std::memory_order_release,std::memory_order_relaxed)){}
        region_->ready.Notify(EntryIndex(entry));
        return true;
    }
    bool Lookup(const Identity &id,uint32_t packet,Prefix *prefix) const noexcept {
        if(!prefix || packet<1 || packet>20 || Faulted())return false;
        auto *entry=Find(id,false);if(!entry)return false;
        if(!AcquirePayload(*entry))return false;
        PayloadLease lease{this,entry};
        const uint32_t slot=entry->versions[packet-1].load(std::memory_order_acquire);
        if(!slot || slot>kVersions)return false;
        *prefix=region_->versions[slot-1].value;return prefix->evidence.packet==packet;
    }
    uint32_t Latest(const Identity &id) const noexcept {
        auto *entry=Find(id,false);return entry?entry->latest.load(std::memory_order_acquire):0;
    }
    uint32_t FirstNext(const Identity &id) const noexcept {
        auto *entry=Find(id,false);
        return entry && entry->latest.load(std::memory_order_acquire)?entry->first_next.load(std::memory_order_relaxed):0;
    }
    uint32_t Used() const noexcept {return region_->used.load(std::memory_order_acquire);}
    uint64_t MaximumSemantic() const noexcept {return region_->maximum_semantic.load(std::memory_order_acquire);}
    bool Faulted() const noexcept {return region_->fault.load(std::memory_order_acquire)!=0;}
private:
    bool Fail() noexcept {region_->fault.store(1,std::memory_order_release);return false;}
    std::string name_;Region *region_=nullptr;bool owner_=false;
};
}
#endif
