#ifndef FK_MONOTONIC_RADIX_HEAP_H
#define FK_MONOTONIC_RADIX_HEAP_H

#include <array>
#include <cstddef>
#include <cstdint>
#include <utility>
#include <vector>

namespace fk_monotonic_radix_heap {

/*
 * Integer-key minimum queue for a stream whose extracted keys never regress.
 * Insertions may arrive in arbitrary order as long as their key is not below
 * the last key already extracted.  Unlike a binary heap, insertion is O(1)
 * and redistribution is amortized over the 64 key bits.
 *
 * minimum() deliberately does not advance the monotonic floor.  This matters
 * to FlowKeep's time-held reorder: a smaller packet may still arrive while
 * the current minimum is waiting for its safe-release age.
 */
template <typename Value, typename Key>
class Heap {
public:
    explicit Heap(Key key) : key_(std::move(key)) {}

    Heap(const Heap &) = delete;
    Heap &operator=(const Heap &) = delete;

    bool empty() const {
        return size_ == 0u;
    }

    size_t size() const {
        return size_;
    }

    uint64_t last_extracted_key() const {
        return last_extracted_key_;
    }

    bool push(Value value) {
        const uint64_t value_key = key_(value);
        if (value_key < last_extracted_key_)
            return false;
        const bool was_empty = size_ == 0u;
        const size_t bucket = bucket_for(
            value_key, last_extracted_key_);
        buckets_[bucket].push_back(std::move(value));
        ++size_;
        const size_t inserted_index = buckets_[bucket].size() - 1u;
        if (was_empty ||
            (minimum_cached_ && value_key < minimum_key_)) {
            minimum_cached_ = true;
            minimum_key_ = value_key;
            minimum_bucket_ = bucket;
            minimum_index_ = inserted_index;
        }
        return true;
    }

    const Value *minimum() {
        if (!ensure_minimum())
            return nullptr;
        return &buckets_[minimum_bucket_][minimum_index_];
    }

    bool pop_minimum(Value &value) {
        if (!ensure_minimum())
            return false;
        std::vector<Value> &source = buckets_[minimum_bucket_];
        value = std::move(source[minimum_index_]);
        if (minimum_index_ + 1u != source.size()) {
            source[minimum_index_] = std::move(source.back());
        }
        source.pop_back();
        --size_;
        last_extracted_key_ = minimum_key_;

        /* Only the bucket containing the extracted minimum needs to be
         * redistributed after the monotonic floor advances.  All higher
         * buckets retain the radix-heap prefix invariant. */
        if (minimum_bucket_ != 0u) {
            for (Value &remaining : source) {
                const uint64_t remaining_key = key_(remaining);
                const size_t destination = bucket_for(
                    remaining_key, last_extracted_key_);
                buckets_[destination].push_back(std::move(remaining));
            }
            source.clear();
        }
        minimum_cached_ = false;
        minimum_key_ = 0u;
        minimum_bucket_ = 0u;
        minimum_index_ = 0u;
        return true;
    }

private:
    static size_t bucket_for(uint64_t key, uint64_t floor) {
        const uint64_t difference = key ^ floor;
        if (difference == 0u)
            return 0u;
        return static_cast<size_t>(
            64u - static_cast<unsigned>(__builtin_clzll(difference)));
    }

    bool ensure_minimum() {
        if (minimum_cached_)
            return true;
        if (size_ == 0u)
            return false;
        for (size_t bucket = 0u; bucket < buckets_.size(); ++bucket) {
            const std::vector<Value> &values = buckets_[bucket];
            if (values.empty())
                continue;
            size_t best_index = 0u;
            uint64_t best_key = key_(values[0]);
            for (size_t index = 1u; index < values.size(); ++index) {
                const uint64_t candidate = key_(values[index]);
                if (candidate < best_key) {
                    best_key = candidate;
                    best_index = index;
                }
            }
            minimum_cached_ = true;
            minimum_key_ = best_key;
            minimum_bucket_ = bucket;
            minimum_index_ = best_index;
            return true;
        }
        return false;
    }

    Key key_;
    std::array<std::vector<Value>, 65u> buckets_{};
    size_t size_ = 0u;
    uint64_t last_extracted_key_ = 0u;
    bool minimum_cached_ = false;
    uint64_t minimum_key_ = 0u;
    size_t minimum_bucket_ = 0u;
    size_t minimum_index_ = 0u;
};

}  // namespace fk_monotonic_radix_heap

#endif
