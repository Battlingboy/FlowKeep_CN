#ifndef FK_PROGRESS_OWNER_MERGE_H
#define FK_PROGRESS_OWNER_MERGE_H

#include <array>
#include <cstdint>

namespace fk_progress_owner_merge {

constexpr uint16_t kMaximumStreams = 32u;
constexpr uint64_t kPackedStreamShift = 59u;
constexpr uint64_t kPackedSequenceMask =
    (UINT64_C(1) << kPackedStreamShift) - 1u;

inline bool pack_sequence_stream(
        uint64_t sequence, uint16_t stream, uint64_t &packed) {
    if (sequence >= kPackedSequenceMask || stream >= kMaximumStreams) {
        packed = UINT64_MAX;
        return false;
    }
    packed = sequence |
        (static_cast<uint64_t>(stream) << kPackedStreamShift);
    return true;
}

inline uint64_t unpack_sequence(uint64_t packed) {
    return packed == UINT64_MAX
        ? UINT64_MAX : packed & kPackedSequenceMask;
}

inline uint16_t unpack_stream(uint64_t packed) {
    return packed == UINT64_MAX
        ? UINT16_MAX
        : static_cast<uint16_t>(packed >> kPackedStreamShift);
}

enum class Status : uint8_t {
    kEmpty = 0u,
    kWait = 1u,
    kRelease = 2u,
    kInvalid = 3u,
};

struct Plan {
    Status status = Status::kInvalid;
    uint16_t stream = UINT16_MAX;
    uint64_t sequence = UINT64_MAX;
};

enum class SharedStatus : uint8_t {
    kEmpty = 0u,
    kWait = 1u,
    kRelease = 2u,
    kDrain = 3u,
    kInvalid = 4u,
};

struct SharedPlan {
    SharedStatus status = SharedStatus::kInvalid;
    uint16_t stream = UINT16_MAX;
    uint64_t sequence = UINT64_MAX;
};

/*
 * A shared MPSC owner ring is work-conserving but hides individual producer
 * heads.  Each producer publishes its own successful-enqueue count before
 * settling those global sequences.  The consumer demultiplexes only until
 * every stream that had outstanding work in the acquired snapshot has at
 * least one staged packet.  Per-producer FIFO order makes those staged items
 * the exact stream heads, so their global minimum is safe below the settled
 * exclusive prefix.  This proof does not require draining future packets
 * into owner-local memory.
 */
inline SharedPlan plan_shared(
        const uint64_t *published_packets,
        const uint64_t *dequeued_packets,
        const uint64_t *staged_packets,
        uint16_t stream_count,
        bool minimum_present,
        uint64_t minimum_sequence,
        uint64_t ingress_prefix,
        bool input_closed) {
    SharedPlan result{};
    if (published_packets == nullptr || dequeued_packets == nullptr ||
        staged_packets == nullptr || stream_count == 0u ||
        stream_count > kMaximumStreams) {
        return result;
    }
    for (uint16_t stream = 0u; stream < stream_count; ++stream) {
        if (staged_packets[stream] == 0u &&
            published_packets[stream] > dequeued_packets[stream]) {
            result.status = SharedStatus::kDrain;
            result.stream = stream;
            return result;
        }
    }
    if (!minimum_present) {
        result.status = SharedStatus::kEmpty;
        return result;
    }
    if (minimum_sequence == UINT64_MAX)
        return result;
    result.sequence = minimum_sequence;
    result.status = input_closed || minimum_sequence < ingress_prefix
        ? SharedStatus::kRelease : SharedStatus::kWait;
    return result;
}

/*
 * Incremental minimum frontier for the owner hot path.  The original
 * stateless planner below is deliberately retained as the small reference
 * implementation used by unit tests and cold paths.  Frontier replaces its
 * O(stream_count) scan on every packet with one O(log stream_count) update
 * when the released stream exposes its next monotonic head.
 *
 * Streams are ordered by (sequence, stream).  A duplicate minimum is still
 * rejected before either copy can be released, preserving the fail-closed
 * contract of plan().
 */
class Frontier {
public:
    bool reset(uint16_t stream_count) {
        if (stream_count == 0u || stream_count > kMaximumStreams) {
            valid_ = false;
            return false;
        }
        stream_count_ = stream_count;
        size_ = 0u;
        heap_.fill(UINT16_MAX);
        positions_.fill(UINT16_MAX);
        sequences_.fill(UINT64_MAX);
        valid_ = true;
        return true;
    }

    bool set(uint16_t stream, bool present, uint64_t sequence) {
        if (!valid_ || stream >= stream_count_)
            return false;
        const uint16_t position = positions_[stream];
        if (!present) {
            if (position == UINT16_MAX)
                return true;
            remove_at(position);
            sequences_[stream] = UINT64_MAX;
            return true;
        }
        sequences_[stream] = sequence;
        if (position == UINT16_MAX) {
            if (size_ >= stream_count_)
                return false;
            const uint16_t inserted = size_++;
            heap_[inserted] = stream;
            positions_[stream] = inserted;
            sift_up(inserted);
            return true;
        }
        const uint16_t parent = position == 0u
            ? 0u : static_cast<uint16_t>((position - 1u) / 2u);
        if (position != 0u && less(stream, heap_[parent]))
            sift_up(position);
        else
            sift_down(position);
        return true;
    }

    Plan plan(uint64_t ingress_prefix, bool input_closed) const {
        if (!valid_)
            return {};
        Plan result{};
        if (size_ == 0u) {
            result.status = Status::kEmpty;
            return result;
        }
        result.stream = heap_[0u];
        result.sequence = sequences_[result.stream];
        if (size_ > 1u) {
            uint16_t second = heap_[1u];
            if (size_ > 2u && less(heap_[2u], second))
                second = heap_[2u];
            if (sequences_[second] == result.sequence) {
                result.status = Status::kInvalid;
                return result;
            }
        }
        result.status = input_closed || result.sequence < ingress_prefix
            ? Status::kRelease : Status::kWait;
        return result;
    }

    uint16_t size() const {
        return size_;
    }

    // Once plan() validates the minimum, packets from that same monotonic
    // stream can be consumed below this exclusive bound without repairing
    // the heap after each packet. Ties must still return to plan().
    uint64_t competing_sequence() const {
        if (size_ < 2u)
            return UINT64_MAX;
        uint16_t second = heap_[1u];
        if (size_ > 2u && less(heap_[2u], second))
            second = heap_[2u];
        return sequences_[second];
    }

private:
    bool less(uint16_t left, uint16_t right) const {
        return sequences_[left] < sequences_[right] ||
            (sequences_[left] == sequences_[right] && left < right);
    }

    void swap_positions(uint16_t left, uint16_t right) {
        const uint16_t left_stream = heap_[left];
        const uint16_t right_stream = heap_[right];
        heap_[left] = right_stream;
        heap_[right] = left_stream;
        positions_[left_stream] = right;
        positions_[right_stream] = left;
    }

    void sift_up(uint16_t position) {
        while (position != 0u) {
            const uint16_t parent =
                static_cast<uint16_t>((position - 1u) / 2u);
            if (!less(heap_[position], heap_[parent]))
                break;
            swap_positions(position, parent);
            position = parent;
        }
    }

    void sift_down(uint16_t position) {
        for (;;) {
            const uint16_t left =
                static_cast<uint16_t>(position * 2u + 1u);
            if (left >= size_)
                return;
            const uint16_t right = static_cast<uint16_t>(left + 1u);
            uint16_t smallest = left;
            if (right < size_ && less(heap_[right], heap_[left]))
                smallest = right;
            if (!less(heap_[smallest], heap_[position]))
                return;
            swap_positions(position, smallest);
            position = smallest;
        }
    }

    void remove_at(uint16_t position) {
        const uint16_t removed = heap_[position];
        const uint16_t last_position = static_cast<uint16_t>(size_ - 1u);
        positions_[removed] = UINT16_MAX;
        if (position == last_position) {
            heap_[last_position] = UINT16_MAX;
            --size_;
            return;
        }
        const uint16_t replacement = heap_[last_position];
        heap_[position] = replacement;
        positions_[replacement] = position;
        heap_[last_position] = UINT16_MAX;
        --size_;
        const uint16_t parent = position == 0u
            ? 0u : static_cast<uint16_t>((position - 1u) / 2u);
        if (position != 0u && less(heap_[position], heap_[parent]))
            sift_up(position);
        else
            sift_down(position);
    }

    std::array<uint16_t, kMaximumStreams> heap_{};
    std::array<uint16_t, kMaximumStreams> positions_{};
    std::array<uint64_t, kMaximumStreams> sequences_{};
    uint16_t stream_count_ = 0u;
    uint16_t size_ = 0u;
    bool valid_ = false;
};

/*
 * Select the next owner-local packet from one head per SPSC pump stream.
 * `ingress_prefix` is an exclusive global sequence watermark: every packet
 * below it has already completed either its owner-ring enqueue or an
 * explicitly accounted drop.  With a monotonic producer stream, a head below
 * that prefix can therefore be released immediately; no wall-clock hold is
 * part of the correctness proof.
 */
template <typename Head>
Plan plan(
        const Head *heads,
        const bool *valid,
        uint16_t stream_count,
        uint64_t ingress_prefix,
        bool input_closed) {
    if (heads == nullptr || valid == nullptr || stream_count == 0u ||
        stream_count > kMaximumStreams) {
        return {};
    }
    Plan result{};
    result.status = Status::kEmpty;
    bool duplicate_minimum = false;
    for (uint16_t stream = 0u; stream < stream_count; ++stream) {
        if (!valid[stream])
            continue;
        const uint64_t sequence = heads[stream].sequence;
        if (result.stream == UINT16_MAX || sequence < result.sequence) {
            result.stream = stream;
            result.sequence = sequence;
            duplicate_minimum = false;
        } else if (sequence == result.sequence) {
            duplicate_minimum = true;
        }
    }
    if (result.stream == UINT16_MAX)
        return result;
    if (duplicate_minimum) {
        result.status = Status::kInvalid;
        return result;
    }
    result.status = input_closed || result.sequence < ingress_prefix
        ? Status::kRelease : Status::kWait;
    return result;
}

}  // namespace fk_progress_owner_merge

#endif
