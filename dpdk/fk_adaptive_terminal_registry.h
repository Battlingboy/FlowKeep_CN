#ifndef FLOWKEEP_FK_ADAPTIVE_TERMINAL_REGISTRY_H
#define FLOWKEEP_FK_ADAPTIVE_TERMINAL_REGISTRY_H

#include "fk_detector_request_shm_abi.h"
#include "fk_marginal_checkpoint_scheduler.h"
#include "fk_native_event_context.h"
#include "fk_sparse_prefix_channel.h"
#include "fk_prefix_version_store.h"

#include <array>
#include <atomic>
#include <cstring>
#include <mutex>
#include <memory>
#include <unordered_map>
#include <deque>

namespace flowkeep {

/* Shared online handoff from the marginal scheduler to EOF finalization.
 * The receiver may publish speculative packet prefixes, but only the scorer
 * knows whether the last real observation selected STOP or a successor NEXT.
 * This bounded run-local registry prevents the EOF adapter from guessing. */
class AdaptiveTerminalRegistry final {
public:
    explicit AdaptiveTerminalRegistry(std::shared_ptr<SparsePrefixChannel> channel=nullptr)
        : channel_(std::move(channel)) {}
    void SetNaturalAuditVersions(std::shared_ptr<PrefixVersionStore> v) { natural_versions_=std::move(v); }
    struct Snapshot {
        uint8_t last_observation_packet = 0u;
        uint8_t pending_packet = 0u;
        uint8_t latest_candidate_packet = 0u;
        uint64_t latest_candidate_sequence = 0u;
        bool stopped = false;
        uint32_t natural_authorization_latest = 0;
    };
    struct Notification {uint32_t token;Snapshot snapshot;};
    // Optional single selected-source subscriber; older adapters still Lookup.
    void Watch(const fk_flow_key &flow,uint64_t first,uint64_t logical,uint32_t token) {
        std::lock_guard<std::mutex> lock(mutex_);
        const auto key=MakeKey(flow,first,logical);
        watches_[key]=token;
        const auto found=states_.find(key);
        if(found!=states_.end())QueueNotification(key,found->second);
    }
    size_t TakeNotifications(Notification *out,size_t capacity) {
        if(!notification_count_.load(std::memory_order_acquire))return 0;
        std::lock_guard<std::mutex> lock(mutex_);size_t n=0;
        while(n<capacity && !notifications_.empty()) {
            const uint32_t token=notifications_.front();notifications_.pop_front();
            auto found=pending_.find(token);out[n++]={token,found->second};pending_.erase(found);
        }
        notification_count_.store(notifications_.size(),std::memory_order_release);return n;
    }

    void Publish(const NativeEventContext &context,
                 const fk_marginal_checkpoint_state &state) {
        if ((context.request_flags &
             FK_DETECTOR_REQUEST_FLAG_COVERAGE_TERMINAL) != 0u)
            return;
        const Key key = MakeKey(context.canonical_key,
            context.flow_first_timestamp_ns, context.logical_connection_id);
        {
            std::lock_guard<std::mutex> lock(mutex_);
            states_[key] = Snapshot{state.last_observation_packet,
                state.pending_packet,
                static_cast<uint8_t>(context.checkpoint_packet),
                context.sequence,
                state.stopped != 0u};
            if(natural_versions_)states_[key].natural_authorization_latest=natural_versions_->Latest(
                {context.canonical_key,context.flow_first_timestamp_ns,context.logical_connection_id});
            QueueNotification(key,states_[key]);
        }
        published_rows_.fetch_add(1u, std::memory_order_release);
        if(channel_)
            channel_->PublishControl({context.canonical_key,
                context.flow_first_timestamp_ns,context.logical_connection_id},
                state.last_observation_packet,state.pending_packet,state.stopped!=0);
    }

    bool Lookup(const fk_flow_key &flow_key, uint64_t first_timestamp_ns,
                uint64_t logical_connection_id, Snapshot *snapshot) const {
        if (snapshot == nullptr)
            return false;
        const Key key = MakeKey(flow_key, first_timestamp_ns,
            logical_connection_id);
        std::lock_guard<std::mutex> lock(mutex_);
        const auto found = states_.find(key);
        if (found == states_.end())
            return false;
        *snapshot = found->second;
        return true;
    }

    uint64_t PublishedRows() const noexcept {
        return published_rows_.load(std::memory_order_acquire);
    }

private:
    struct Key {
        std::array<uint8_t, sizeof(fk_flow_key)> flow{};
        uint64_t first_timestamp_ns = 0u;
        uint64_t logical_connection_id = 0u;
        bool operator==(const Key &other) const noexcept {
            return flow == other.flow &&
                first_timestamp_ns == other.first_timestamp_ns &&
                logical_connection_id == other.logical_connection_id;
        }
    };
    struct Hash {
        size_t operator()(const Key &key) const noexcept {
            uint64_t hash = UINT64_C(14695981039346656037);
            for (uint8_t byte : key.flow) {
                hash ^= byte;
                hash *= UINT64_C(1099511628211);
            }
            hash ^= key.first_timestamp_ns;
            hash *= UINT64_C(1099511628211);
            hash ^= key.logical_connection_id;
            return static_cast<size_t>(hash);
        }
    };
    static Key MakeKey(const fk_flow_key &flow_key,
                       uint64_t first_timestamp_ns,
                       uint64_t logical_connection_id) {
        Key key{};
        std::memcpy(key.flow.data(), &flow_key, sizeof(flow_key));
        key.first_timestamp_ns = first_timestamp_ns;
        key.logical_connection_id = logical_connection_id;
        return key;
    }

    mutable std::mutex mutex_;
    std::unordered_map<Key, Snapshot, Hash> states_;
    std::atomic<uint64_t> published_rows_{0u};
    std::shared_ptr<SparsePrefixChannel> channel_;
    std::shared_ptr<PrefixVersionStore> natural_versions_;
    std::unordered_map<Key,uint32_t,Hash> watches_;
    std::unordered_map<uint32_t,Snapshot> pending_;
    std::deque<uint32_t> notifications_;
    std::atomic<size_t> notification_count_{0};
    void QueueNotification(const Key &key,const Snapshot &snapshot) {
        const auto watcher=watches_.find(key);if(watcher==watches_.end())return;
        const uint32_t token=watcher->second;
        auto inserted=pending_.emplace(token,snapshot);
        if(inserted.second)notifications_.push_back(token);else inserted.first->second=snapshot;
        notification_count_.store(notifications_.size(),std::memory_order_release);
    }
};

}  // namespace flowkeep

#endif
