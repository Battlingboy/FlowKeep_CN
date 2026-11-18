#ifndef FK_PAGED_REORDER_RING_H
#define FK_PAGED_REORDER_RING_H
#include <algorithm>
#include <array>
#include <memory>
#include <stdexcept>
#include <vector>
namespace flowkeep {
// Coordinator-owned storage only. The caller retains sequence/occupied checks.
// A page may be recycled only after every contained decision crosses durable ACK.
// Returned pointers stay valid until Released for that exact occupied slot.
// No history, input version, policy, capacity or scheduling order is changed.
template<class T,size_t Slots=256,size_t CachedPages=8>
class PagedReorderRing {
 struct Page {std::array<T,Slots> slots{};size_t live=0;};
 bool paged_;size_t capacity_=0,allocated_=0,peak_=0,reuses_=0;
 std::vector<T> flat_;
 std::vector<std::unique_ptr<Page>> pages_,cache_;
public:
 explicit PagedReorderRing(bool paged):paged_(paged){}
 void resize(size_t n){if(capacity_)throw std::logic_error("reorder resize after initialization");capacity_=n;if(paged_){pages_.resize((n+Slots-1)/Slots);cache_.reserve(CachedPages);}else flat_.resize(n);}
 bool empty()const{return capacity_==0;}
 size_t size()const{return capacity_;}
 T* Find(size_t index){if(index>=capacity_)throw std::out_of_range("reorder index");if(!paged_)return &flat_[index];auto&p=pages_[index/Slots];return p?&p->slots[index%Slots]:nullptr;}
 T& Acquire(size_t index){if(index>=capacity_)throw std::out_of_range("reorder index");if(!paged_)return flat_[index];auto&p=pages_[index/Slots];if(!p){if(cache_.empty()){p.reset(new Page);peak_=std::max(peak_,++allocated_);}else{p=std::move(cache_.back());cache_.pop_back();++reuses_;}}return p->slots[index%Slots];}
 void Stored(size_t index){if(paged_){auto&p=pages_.at(index/Slots);if(!p||p->live>=Slots)throw std::logic_error("reorder page occupancy");++p->live;}}
 void Released(size_t index){if(!paged_)return;auto&p=pages_.at(index/Slots);if(!p||!p->live)throw std::logic_error("reorder release without occupied slot");if(--p->live==0){if(cache_.size()<CachedPages)cache_.push_back(std::move(p));else{p.reset();--allocated_;}}}
 size_t AllocatedBytes()const{return paged_?allocated_*sizeof(Page)+pages_.capacity()*sizeof(std::unique_ptr<Page>)+cache_.capacity()*sizeof(std::unique_ptr<Page>):flat_.capacity()*sizeof(T);}
 size_t PeakPayloadBytes()const{return paged_?peak_*sizeof(Page):flat_.capacity()*sizeof(T);}
 size_t PageReuses()const{return reuses_;}
 bool Paged()const{return paged_;}
};
}
#endif
