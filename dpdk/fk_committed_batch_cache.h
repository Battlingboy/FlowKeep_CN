#ifndef FK_COMMITTED_BATCH_CACHE_H
#define FK_COMMITTED_BATCH_CACHE_H
#include <cstdint>
#include <cstring>
#include <map>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>

namespace flowkeep {
// One committed batch only, not a write-back cache. The caller holds the DB
// writer mutex, invalidates BEFORE every DB mutation, and remembers entries
// only AFTER a successful synchronous commit. Reopening starts empty.
// Fixed arrays bound storage independently of the number of flows/updates.
class CommittedBatchCache {
    struct Entry {uint32_t offset, key_bytes, value_bytes, present;};
    std::unique_ptr<char[]> arena_;
    std::unique_ptr<Entry[]> entries_;
    size_t arena_bytes_=0, capacity_=0, used_=0, count_=0;
public:
    uint64_t skipped=0;
    void Configure(size_t bytes,size_t entries) {
        if(bytes>(1u<<20) || entries>4096 || arena_ || entries_)
            throw std::invalid_argument("invalid committed-batch cache allocation");
        if(!bytes || !entries)return;
        arena_=std::make_unique<char[]>(bytes);
        entries_=std::make_unique<Entry[]>(entries);
        arena_bytes_=bytes;capacity_=entries;
    }
    size_t AllocatedBytes() const noexcept {return arena_bytes_+capacity_*sizeof(Entry);}
    size_t Count() const noexcept {return count_;}
    size_t UsedBytes() const noexcept {return used_+count_*sizeof(Entry);}
    void Clear() noexcept {used_=0;count_=0;}
    bool Find(std::string_view key,std::optional<std::string> *value) const {
        if(!value)throw std::invalid_argument("null cache output");
        size_t low=0,high=count_;
        while(low<high) {
            const size_t middle=low+(high-low)/2;const auto &entry=entries_[middle];
            const std::string_view stored(arena_.get()+entry.offset,entry.key_bytes);
            const int comparison=stored.compare(key);
            if(comparison<0)low=middle+1;
            else if(comparison>0)high=middle;
            else {
                if(entry.present)*value=std::string(stored.data()+entry.key_bytes,entry.value_bytes);
                else value->reset();
                return true;
            }
        }
        return false;
    }
    void Remember(const std::map<std::string,std::optional<std::string>> &changes) noexcept {
        Clear();
        for(const auto &item:changes) {
            const size_t key_bytes=item.first.size(),value_bytes=item.second?item.second->size():0;
            if(count_==capacity_ || key_bytes>arena_bytes_-used_ ||
               value_bytes>arena_bytes_-used_-key_bytes) {++skipped;continue;}
            auto &entry=entries_[count_++];
            entry={static_cast<uint32_t>(used_),static_cast<uint32_t>(key_bytes),
                   static_cast<uint32_t>(value_bytes),item.second?1u:0u};
            std::memcpy(arena_.get()+used_,item.first.data(),key_bytes);used_+=key_bytes;
            if(item.second){std::memcpy(arena_.get()+used_,item.second->data(),value_bytes);used_+=value_bytes;}
        }
    }
};
}
#endif
