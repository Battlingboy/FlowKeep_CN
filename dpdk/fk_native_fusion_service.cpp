#include "fk_native_fusion_service.h"
#include "fk_phase_batch_wait.h"
#include "fk_batch_age_guard.h"
#include "fk_paged_reorder_ring.h"
#include <cstdlib>

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cmath>
#include <condition_variable>
#include <cstring>
#include <deque>
#include <limits>
#include <map>
#include <mutex>
#include <new>
#include <set>
#include <thread>
#include <unordered_map>
#include <utility>

#include <pthread.h>
#include <sched.h>
#include <time.h>

namespace flowkeep {
namespace {

constexpr uint32_t kDurableGuardRouteSlice = 32u;

uint64_t durable_age_anchor_ns(
        const NativeFusionDecision &decision,
        NativeFusionDurableAgeAnchor anchor) {
    if (anchor == NativeFusionDurableAgeAnchor::ConsumerReceive)
        return decision.consumer_receive_monotonic_ns;
    return decision.physical_enqueue_monotonic_ns;
}

uint64_t monotonic_ns() {
    timespec value{};
    if (::clock_gettime(CLOCK_MONOTONIC, &value) != 0 ||
        value.tv_sec < 0 || value.tv_nsec < 0 ||
        value.tv_nsec >= 1000000000L) {
        return 0u;
    }
    const uint64_t seconds = static_cast<uint64_t>(value.tv_sec);
    if (seconds > (UINT64_MAX - static_cast<uint64_t>(value.tv_nsec)) /
            UINT64_C(1000000000)) {
        return 0u;
    }
    return seconds * UINT64_C(1000000000) +
        static_cast<uint64_t>(value.tv_nsec);
}

void observe_deadline_miss(
        const NativeFusionDecision &decision,
        uint64_t detector_deadline_ns,
        NativeFusionServiceReceipt *receipt) {
    const uint64_t end_to_end_ns =
        decision.decision_monotonic_ns -
        decision.physical_enqueue_monotonic_ns;
    if (end_to_end_ns <= detector_deadline_ns)
        return;
    ++receipt->deadline_misses;
    NativeFusionFirstDeadlineMissMetrics &first =
        receipt->first_deadline_miss;
    // The durable ledger is in input sequence order, independently of worker
    // completion order. Report the first miss in that same canonical order.
    if (first.present != 0u && decision.sequence >= first.sequence)
        return;
    first.present = 1u;
    first.sequence = decision.sequence;
    first.event_routing_token = decision.event_routing_token;
    first.worker_shard = decision.worker_shard;
    first.physical_enqueue_monotonic_ns =
        decision.physical_enqueue_monotonic_ns;
    first.consumer_receive_monotonic_ns =
        decision.consumer_receive_monotonic_ns;
    first.inference_start_monotonic_ns =
        decision.inference_start_monotonic_ns;
    first.decision_monotonic_ns = decision.decision_monotonic_ns;
    first.transport_queue_wait_ns =
        decision.consumer_receive_monotonic_ns -
        decision.physical_enqueue_monotonic_ns;
    first.worker_queue_wait_ns =
        decision.inference_start_monotonic_ns -
        decision.consumer_receive_monotonic_ns;
    first.inference_ns =
        decision.decision_monotonic_ns -
        decision.inference_start_monotonic_ns;
    first.end_to_end_ns = end_to_end_ns;
}

void set_error(std::string *output, const std::string &message) {
    if (output != nullptr)
        *output = message;
}

bool cpu_set_valid(const std::vector<uint32_t> &cpus) {
    if (cpus.empty())
        return false;
    std::set<uint32_t> unique;
    for (uint32_t cpu : cpus) {
        if (cpu >= CPU_SETSIZE || !unique.insert(cpu).second)
            return false;
    }
    return true;
}

bool affinity_plan_valid(const NativeFusionServiceConfig &config) {
    const bool requested = !config.coordinator_cpu_set.empty() ||
        !config.committer_cpu_set.empty() ||
        !config.worker_cpu_sets.empty();
    if (!requested)
        return true;
    if (!cpu_set_valid(config.coordinator_cpu_set) ||
        !cpu_set_valid(config.committer_cpu_set) ||
        config.worker_cpu_sets.size() != config.worker_count) {
        return false;
    }
    std::set<uint32_t> assigned;
    const auto add_role = [&](const std::vector<uint32_t> &cpus) {
        if (!cpu_set_valid(cpus))
            return false;
        for (uint32_t cpu : cpus) {
            if (!assigned.insert(cpu).second)
                return false;
        }
        return true;
    };
    if (!add_role(config.coordinator_cpu_set) ||
        !add_role(config.committer_cpu_set)) {
        return false;
    }
    return std::all_of(config.worker_cpu_sets.begin(),
        config.worker_cpu_sets.end(), add_role);
}

bool current_affinity_exact(const std::vector<uint32_t> &cpus) {
    if (cpus.empty())
        return true;
    cpu_set_t expected;
    cpu_set_t observed;
    CPU_ZERO(&expected);
    CPU_ZERO(&observed);
    for (uint32_t cpu : cpus)
        CPU_SET(cpu, &expected);
    if (::pthread_getaffinity_np(
            ::pthread_self(), sizeof(observed), &observed) != 0) {
        return false;
    }
    for (uint32_t cpu = 0u; cpu < CPU_SETSIZE; ++cpu) {
        if (CPU_ISSET(cpu, &expected) != CPU_ISSET(cpu, &observed))
            return false;
    }
    return true;
}

bool pin_current_thread_exact(const std::vector<uint32_t> &cpus) {
    if (cpus.empty())
        return true;
    cpu_set_t requested;
    CPU_ZERO(&requested);
    for (uint32_t cpu : cpus)
        CPU_SET(cpu, &requested);
    return ::pthread_setaffinity_np(
               ::pthread_self(), sizeof(requested), &requested) == 0 &&
        current_affinity_exact(cpus);
}

bool source_snapshot_clean(const NativeFusionSourceSnapshot &snapshot) {
    return snapshot.capacity >= FK_DETECTOR_REQUEST_SHM_MIN_CAPACITY &&
        snapshot.write_sequence == snapshot.published &&
        snapshot.producer_drops == 0u &&
        snapshot.producer_overruns == 0u &&
        snapshot.producer_fail_closed == 0u &&
        snapshot.producer_validation_failures == 0u &&
        snapshot.producer_integrity_failures == 0u &&
        snapshot.read_sequence <= snapshot.write_sequence &&
        snapshot.records_acked == snapshot.read_sequence &&
        snapshot.sequence_gaps == 0u &&
        snapshot.consumer_validation_failures == 0u &&
        snapshot.ack_rejections == 0u &&
        snapshot.unacked_on_close == 0u && snapshot.consumer_fault == 0u;
}

bool source_snapshot_consistent(
        const NativeFusionRequestSource *source,
        NativeFusionSourceSnapshot *snapshot,
        std::string *error) {
    if (source == nullptr || snapshot == nullptr)
        return false;
    for (uint32_t attempt = 0u; attempt < 256u; ++attempt) {
        if (!source->Snapshot(snapshot, error))
            return false;
        if (snapshot->write_sequence == snapshot->published)
            return true;
        std::this_thread::yield();
    }
    set_error(error,
        "source write/published counters remained inconsistent");
    return false;
}

class ShmSource final : public NativeFusionRequestSource {
public:
    ShmSource(
            std::string name,
            uint64_t epoch,
            fk_detector_request_shm *transport) noexcept
        : name_(std::move(name)), epoch_(epoch), transport_(transport) {}

    ~ShmSource() override {
        if (transport_ != nullptr)
            (void)fk_detector_request_shm_close_checked(transport_);
    }

    bool DeliversValidatedItems() const noexcept override { return true; }

    NativeFusionSourceResult Peek(
            fk_detector_request_v1 *request,
            uint64_t *sequence,
            std::string *error) noexcept override {
        if (request == nullptr || sequence == nullptr || transport_ == nullptr) {
            set_error(error, "SHM source peek has an invalid argument");
            return NativeFusionSourceResult::Fault;
        }
        /*
         * The SHM peek ABI already validates the static mapping, the formal
         * consumer identity, the consumer fault latch, the expected sequence,
         * and the committed slot before it returns an item.  Re-copying every
         * producer and consumer audit counter here made routing O(records x
         * audit_fields) and consumed most of the 100 ms detector deadline
         * during line-rate bursts.  Full counter closure is still checked at
         * service start, before every durable commit, before every ACK, and at
         * close.  A producer fault can therefore never cross the durable/ACK
         * boundary, while the per-record hot path remains fail-closed through
         * the ABI result below.
         */
        switch (fk_detector_request_shm_consumer_peek(
                transport_, request, sequence)) {
        case FK_DETECTOR_REQUEST_SHM_PEEK_ITEM:
            return NativeFusionSourceResult::Item;
        case FK_DETECTOR_REQUEST_SHM_PEEK_EMPTY:
            return NativeFusionSourceResult::Empty;
        case FK_DETECTOR_REQUEST_SHM_PEEK_PRODUCER_DONE_EMPTY:
            return NativeFusionSourceResult::ProducerDone;
        case FK_DETECTOR_REQUEST_SHM_PEEK_FAULTED_EMPTY:
            set_error(error, "SHM producer entered fail-closed state");
            return NativeFusionSourceResult::Fault;
        case FK_DETECTOR_REQUEST_SHM_PEEK_WRONG_CONSUMER:
            set_error(error, "SHM formal consumer identity changed");
            return NativeFusionSourceResult::Fault;
        case FK_DETECTOR_REQUEST_SHM_PEEK_CORRUPT:
            set_error(error, "SHM request slot is corrupt");
            return NativeFusionSourceResult::Fault;
        case FK_DETECTOR_REQUEST_SHM_PEEK_INVALID_ARGUMENT:
            break;
        }
        set_error(error, "SHM consumer peek rejected its arguments");
        return NativeFusionSourceResult::Fault;
    }

    bool Ack(uint64_t sequence, std::string *error) noexcept override {
        NativeFusionSourceSnapshot before{};
        if (transport_ == nullptr || !Snapshot(&before, error) ||
            !source_snapshot_clean(before)) {
            set_error(error, "SHM source became faulted before ACK");
            return false;
        }
        if (fk_detector_request_shm_consumer_ack(transport_, sequence) !=
                FK_DETECTOR_REQUEST_SHM_ACK_COMMITTED) {
            set_error(error, "SHM consecutive-prefix ACK was rejected");
            return false;
        }
        return true;
    }

    bool Snapshot(
            NativeFusionSourceSnapshot *snapshot,
            std::string *error) const noexcept override {
        if (snapshot == nullptr) {
            set_error(error, "SHM snapshot output is null");
            return false;
        }
        *snapshot = {};
        if (transport_ == nullptr) {
            if (!closed_snapshot_valid_) {
                set_error(error, "SHM source is closed without a snapshot");
                return false;
            }
            *snapshot = closed_snapshot_;
            return true;
        }
        fk_detector_request_shm_producer_header_v1 producer{};
        fk_detector_request_shm_consumer_control_v1 consumer{};
        bool consistent = false;
        for (uint32_t attempt = 0u; attempt < 256u; ++attempt) {
            if (!fk_detector_request_shm_snapshot(
                    transport_, &producer, &consumer)) {
                break;
            }
            /*
             * publish() release-stores published before write_sequence.
             * The ABI snapshot copies independent atomics, so a concurrent
             * producer can transiently yield old write/new published even
             * though the shared state is sound.  A bounded stable reread is
             * required before treating inequality as a producer fault.
             */
            if (producer.write_sequence == producer.published) {
                consistent = true;
                break;
            }
            std::this_thread::yield();
        }
        if (!consistent) {
            set_error(error, "SHM atomic snapshot failed");
            return false;
        }
        snapshot->capacity = producer.capacity;
        snapshot->run_epoch = producer.run_epoch;
        snapshot->write_sequence = producer.write_sequence;
        snapshot->published = producer.published;
        snapshot->producer_drops = producer.dropped;
        snapshot->producer_overruns = producer.overrun;
        snapshot->producer_fail_closed = producer.fail_closed;
        snapshot->producer_validation_failures =
            producer.request_validation_failures;
        snapshot->producer_integrity_failures =
            producer.internal_integrity_failures;
        snapshot->producer_done = producer.producer_done;
        snapshot->producer_stop_monotonic_ns =
            producer.producer_stop_mono_ns;
        snapshot->read_sequence = consumer.read_sequence;
        snapshot->records_peeked = consumer.records_peeked;
        snapshot->records_acked = consumer.records_acked;
        snapshot->sequence_gaps = consumer.sequence_gaps;
        snapshot->consumer_validation_failures =
            consumer.validation_failures;
        snapshot->ack_rejections = consumer.ack_rejections;
        snapshot->unacked_on_close = consumer.unacked_on_close;
        snapshot->consumer_fault = consumer.consumer_fault;
        snapshot->consumer_open_count = consumer.open_count;
        snapshot->consumer_close_count = consumer.close_count;
        snapshot->consumer_claim_token = consumer.claim_token;
        return true;
    }

    bool Close(std::string *error) noexcept override {
        if (transport_ == nullptr)
            return closed_snapshot_valid_;
        NativeFusionSourceSnapshot before{};
        if (!Snapshot(&before, error))
            return false;
        fk_detector_request_shm *closing = transport_;
        transport_ = nullptr;
        if (!fk_detector_request_shm_close_checked(closing)) {
            set_error(error, "SHM formal consumer close failed");
            return false;
        }
        fk_detector_request_shm *observer = nullptr;
        if (!fk_detector_request_shm_open_observer(
                name_.c_str(), epoch_, &observer)) {
            closed_snapshot_ = before;
            closed_snapshot_valid_ = true;
            set_error(error, "SHM post-close observer open failed");
            return false;
        }
        transport_ = observer;
        NativeFusionSourceSnapshot after{};
        const bool snap_ok = Snapshot(&after, error);
        observer = transport_;
        transport_ = nullptr;
        const bool close_ok = fk_detector_request_shm_close_checked(observer);
        if (!snap_ok || !close_ok) {
            set_error(error, "SHM post-close snapshot failed");
            return false;
        }
        closed_snapshot_ = after;
        closed_snapshot_valid_ = true;
        return true;
    }

private:
    std::string name_;
    uint64_t epoch_;
    fk_detector_request_shm *transport_;
    NativeFusionSourceSnapshot closed_snapshot_{};
    bool closed_snapshot_valid_ = false;
};

struct WorkItem {
    fk_detector_request_v1 request{};
    uint64_t sequence = 0u;
    uint64_t event_token = 0u;
    const std::string *event_id = nullptr;
    uint32_t shard = 0u;
    uint64_t receive_ns = 0u;
};

struct Completion {
    bool success = false;
    std::vector<NativeFusionDecision> decisions;
    std::string error;
    bool scorer_output = false;
};

struct CompletionQueue {
    std::mutex mutex;
    std::condition_variable ready;
    std::deque<Completion> queue;
    /* Monotonic wake generation prevents a completion notification from
     * being lost between the coordinator's poll and its timed wait.  The
     * routing loop also samples it after every item so a large route quantum
     * cannot hide newly ordered work or a completed durable call. */
    std::atomic<uint64_t> wake_generation{0u};
};

struct DurableCompletion {
    bool success = false;
    uint64_t first_sequence = 0u;
    uint64_t last_sequence = 0u;
    size_t decision_count = 0u;
    uint64_t submitted_monotonic_ns = 0u;
    uint64_t commit_started_monotonic_ns = 0u;
    uint64_t commit_finished_monotonic_ns = 0u;
    NativeFusionCommitResult result{};
    NativeFusionCommitTrace trace{};
    std::string error;
};

/*
 * A bounded prefix queue: ordered preparation can overlap ordered publication.
 * Legacy committers keep one prefix and the original synchronous callback.
 * Both threads initially share the assigned committer CPU. Opt-in ledgers
 * can borrow idle time from existing inference CPUs after verified input
 * closure; the coordinator is excluded and no CPU or thread is added.
 */
class DurableCommitWorker {
    struct Job {
        std::vector<NativeFusionDecision> decisions;
        std::unique_ptr<NativeFusionPreparedCommit> prepared;
        DurableCompletion completion;
        bool ready = true;
    };
public:
    DurableCommitWorker(NativeFusionCommitter *committer, CompletionQueue *wake,
        std::vector<uint32_t> cpus, const std::vector<NativeFusionBatchScorer *> &scorers,
        std::vector<uint32_t> drain_cpus)
        : committer_(committer), wake_(wake), cpus_(std::move(cpus)), scorers_(scorers),
          pipelined_(committer->SupportsPreparedCommit()),drain_cpus_(std::move(drain_cpus)) {}
    bool Start() {
        try {
            if (pipelined_) prepare_thread_ = std::thread(&DurableCommitWorker::PrepareLoop,this);
            publish_thread_ = std::thread(&DurableCommitWorker::PublishLoop,this);
        } catch (...) { Close(); Join(); return false; }
        std::unique_lock<std::mutex> lock(mutex_);
        ready_.wait(lock,[&]{return starts_ == (pipelined_ ? 2u : 1u);});
        const bool ok=affinity_ok_;lock.unlock();
        if(!ok){Close();Join();}
        return ok;
    }
    bool Submit(std::vector<NativeFusionDecision> decisions, uint64_t submitted) {
        std::lock_guard<std::mutex> lock(mutex_);
        if (closing_ || failed_ || decisions.empty() || !submitted ||
            outstanding_ >= committer_->PreparedCommitCapacity()) return false;
        Job job; job.decisions=std::move(decisions);
        auto &c=job.completion;
        c.first_sequence=job.decisions.front().sequence;
        c.last_sequence=job.decisions.back().sequence;
        c.decision_count=job.decisions.size(); c.submitted_monotonic_ns=submitted;
        c.trace.first_sequence=c.first_sequence; c.trace.last_sequence=c.last_sequence;
        c.trace.submitted_ns=submitted;
        c.trace.oldest_enqueue_ns=UINT64_MAX;
        for(const auto &d:job.decisions) {
            if(d.physical_enqueue_monotonic_ns<c.trace.oldest_enqueue_ns) {
                c.trace.oldest_enqueue_ns=d.physical_enqueue_monotonic_ns;
                c.trace.oldest_sequence=d.sequence;
                c.trace.oldest_decision_ns=d.decision_monotonic_ns;
            }
            c.trace.last_decision_ns=std::max(c.trace.last_decision_ns,d.decision_monotonic_ns);
        }
        jobs_.push_back(std::move(job)); ++outstanding_; ready_.notify_all(); return true;
    }
    bool Take(DurableCompletion *c) {
        std::lock_guard<std::mutex> lock(mutex_);
        if(!c || completed_.empty())return false;
        *c=std::move(completed_.front());completed_.pop_front();--outstanding_;
        return true;
    }
    void Close() {
        {std::lock_guard<std::mutex> lock(mutex_);closing_=true;}ready_.notify_all();
    }
    void Join() {
        if(prepare_thread_.joinable())prepare_thread_.join();
        if(publish_thread_.joinable())publish_thread_.join();
    }
    bool affinity_attested() const noexcept {return !cpus_.empty() && affinity_ok_;}
    void BeginDrain() noexcept {
        if(!drain_requested_.load(std::memory_order_relaxed) &&
           committer_->SupportsDrainPreparationOverlap() && !drain_cpus_.empty())
            drain_requested_.store(true,std::memory_order_release);
    }
    uint64_t drain_batches() const noexcept {return drain_batches_.load();}
    bool drain_idle_attested() const noexcept {return drain_idle_attested_.load();}
private:
    bool Pin() {
        const bool ok=pin_current_thread_exact(cpus_);
        {std::lock_guard<std::mutex> lock(mutex_);affinity_ok_=affinity_ok_&&ok;++starts_;}
        if(!ok)failed_=true;
        ready_.notify_all();return ok;
    }
    void PrepareLoop() {
        const bool pinned=Pin();
        bool drain_pinned=false;
        for(;;) {
            Job job;
            {
                std::unique_lock<std::mutex> lock(mutex_);
                ready_.wait(lock,[&]{return closing_ || !jobs_.empty();});
                if(jobs_.empty() && closing_)break;
                job=std::move(jobs_.front());jobs_.pop_front();
            }
            auto &c=job.completion;
            if(!drain_pinned && drain_requested_.load(std::memory_order_acquire)) {
                // This thread borrows existing inference CPUs, not priority.
                // Change policy before moving so even the handover cannot
                // compete at normal priority with outstanding inference work.
                sched_param idle{};
                const bool idle_ok=::sched_setscheduler(0,SCHED_IDLE,&idle)==0 &&
                    ::sched_getscheduler(0)==SCHED_IDLE;
                drain_pinned=idle_ok && pin_current_thread_exact(drain_cpus_);
                if(!drain_pinned) {
                    std::lock_guard<std::mutex> lock(mutex_);affinity_ok_=false;failed_=true;
                    c.error="drain preparation idle scheduling or affinity failed";
                }else {
                    drain_idle_attested_.store(true);
                    committer_->BeginDrainPreparationOverlap();
                }
            }
            if(drain_pinned)++drain_batches_;
            c.trace.prepare_started_ns=monotonic_ns();
            const auto prepare_clock=ReadThreadPhaseStamp();
            job.ready=pinned && !failed_ && committer_->PrepareConsecutive(
                job.decisions.data(),job.decisions.size(),&job.prepared,&c.error);
            c.trace.prepare_cost=ThreadPhaseBetween(prepare_clock,ReadThreadPhaseStamp());
            c.trace.prepare_finished_ns=monotonic_ns();
            if(!job.ready)failed_=true;
            {std::lock_guard<std::mutex> lock(mutex_);prepared_.push_back(std::move(job));}
            ready_.notify_all();
        }
        {std::lock_guard<std::mutex> lock(mutex_);prepare_done_=true;}ready_.notify_all();
    }
    void PublishLoop() {
        const bool pinned=Pin();
        for(;;) {
            std::vector<Job> group;group.reserve(4);
            {
                std::unique_lock<std::mutex> lock(mutex_);
                auto &queue=pipelined_?prepared_:jobs_;
                ready_.wait(lock,[&]{return !queue.empty() || (pipelined_?prepare_done_:closing_);});
                if(queue.empty() && (pipelined_?prepare_done_:closing_))return;
                group.push_back(std::move(queue.front()));queue.pop_front();
                // Never delay a ready prefix to form a group. Only combine
                // already-prepared jobs within the existing bounded credits.
                if(pipelined_ && committer_->SupportsGroupedPublication())
                    while(!queue.empty() && group.size()<committer_->PreparedCommitCapacity()) {
                        group.push_back(std::move(queue.front()));queue.pop_front();
                    }
            }
            const uint64_t started=monotonic_ns();
            const auto history_clock=ReadThreadPhaseStamp();
            ThreadPhaseTiming history_cost{},publish_cost{};
            std::array<NativeFusionCommitResult,4> results{};
            std::string error;bool success=false;uint64_t history_end=started;
            try {
                if(!pinned)throw std::runtime_error("durable publisher affinity failed");
                if(failed_)throw std::runtime_error("pipeline is terminal");
                std::vector<uint64_t> required(scorers_.size(),0u);
                for(const auto &job:group) {
                    if(!job.ready)throw std::runtime_error(job.completion.error.empty()?"durable preparation failed":job.completion.error);
                    for(const auto &d:job.decisions) {
                        if(d.kind!=NativeFusionDecisionKind::Checkpoint)continue;
                        if(d.worker_shard>=scorers_.size())throw std::runtime_error("history shard out of range");
                        required[d.worker_shard]=std::max(required[d.worker_shard],d.sequence);
                    }
                }
                for(size_t i=0;i<required.size();++i)
                    if(required[i] && !scorers_[i]->WaitHistoryDurable(required[i],&error))
                        throw std::runtime_error("history fence failed: "+error);
                history_end=monotonic_ns();history_cost=ThreadPhaseBetween(history_clock,ReadThreadPhaseStamp());
                const auto publish_clock=ReadThreadPhaseStamp();
                if(group.size()>1) {
                    std::array<NativeFusionPreparedCommit*,4> prepared{};
                    for(size_t i=0;i<group.size();++i)prepared[i]=group[i].prepared.get();
                    success=committer_->PublishPreparedGroup(prepared.data(),group.size(),results.data(),&error);
                } else success=pipelined_?committer_->PublishPrepared(group[0].prepared.get(),&results[0],&error):
                    committer_->CommitConsecutive(group[0].decisions.data(),group[0].decisions.size(),&results[0],&error);
                publish_cost=ThreadPhaseBetween(publish_clock,ReadThreadPhaseStamp());
            } catch(const std::exception &e){error=e.what();}
              catch(...){error="durable pipeline exception";}
            const uint64_t finished=monotonic_ns();if(!success)failed_=true;
            {
                std::lock_guard<std::mutex> lock(mutex_);
                for(size_t i=0;i<group.size();++i) {
                    auto &c=group[i].completion;c.success=success;c.error=error;c.result=results[i];
                    c.commit_started_monotonic_ns=started;c.commit_finished_monotonic_ns=finished;
                    c.trace.history_started_ns=started;c.trace.history_finished_ns=history_end;
                    c.trace.publish_started_ns=history_end;c.trace.publish_finished_ns=finished;
                    if(i==0){c.trace.history_cost=history_cost;c.trace.publish_cost=publish_cost;}
                    c.trace.serialize_cost=c.result.serialize_cost;c.trace.compression_cost=c.result.compression_cost;
                    c.trace.state_cost=c.result.state_cost;c.trace.file_sync_cost=c.result.file_sync_cost;
                    c.trace.directory_sync_cost=c.result.directory_sync_cost;
                    completed_.push_back(std::move(c));
                }
            }
            if(wake_){wake_->wake_generation.fetch_add(1u,std::memory_order_release);wake_->ready.notify_one();}
        }
    }
    NativeFusionCommitter *committer_;
    CompletionQueue *wake_;
    std::vector<uint32_t> cpus_;
    const std::vector<NativeFusionBatchScorer *> &scorers_;
    bool pipelined_;
    std::vector<uint32_t> drain_cpus_;
    std::atomic<bool> drain_requested_{false};
    std::atomic<uint64_t> drain_batches_{0};
    std::atomic<bool> drain_idle_attested_{false};
    std::mutex mutex_;std::condition_variable ready_;
    std::thread prepare_thread_,publish_thread_;
    std::deque<Job> jobs_,prepared_;
    std::deque<DurableCompletion> completed_;
    std::atomic<bool> failed_{false};
    uint32_t outstanding_=0,starts_=0;
    bool closing_=false,prepare_done_=false,affinity_ok_=true;
};

bool reserved_zero(const uint8_t *bytes, size_t count) {
    uint8_t combined = 0u;
    for (size_t index = 0u; index < count; ++index)
        combined = static_cast<uint8_t>(combined | bytes[index]);
    return combined == 0u;
}

bool valid_result(
        const fk_native_fusion_result &result,
        const WorkItem &work) {
    return result.sequence == work.sequence &&
        result.event_token == work.event_token &&
        std::isfinite(result.score) &&
        result.threshold_met <= 1u && result.first_alert <= 1u &&
        result.alert_latched <= 1u &&
        (result.threshold_met == 0u || result.alert_latched == 1u) &&
        (result.first_alert == 0u || result.threshold_met == 1u) &&
        reserved_zero(result.reserved, sizeof(result.reserved));
}

class Worker {
public:
    Worker(
            uint32_t shard,
            uint32_t batch_capacity,
            uint64_t batch_wait_ns,
            NativeFusionDetectorSchedule detector_schedule,
            uint64_t detector_deadline_ns,
            NativeFusionBatchScorer *scorer,
            CompletionQueue *completions,
            std::vector<uint32_t> cpu_set)
        : shard_(shard),
          batch_capacity_(batch_capacity),
          batch_wait_policy_(batch_wait_ns),
          detector_schedule_(detector_schedule),
          detector_deadline_ns_(detector_deadline_ns),
          scorer_(scorer),
          completions_(completions),
          cpu_set_(std::move(cpu_set)) {
        metrics_.affinity_cpu_count = cpu_set_.size();
        metrics_.affinity_requested = cpu_set_.empty() ? 0u : 1u;
        metrics_.active_batch_wait_ns=batch_wait_policy_.active_ns;
        metrics_.drain_batch_wait_ns=batch_wait_policy_.drain_ns;
    }

    void BeginInputDrain() {
        {
            std::lock_guard<std::mutex> lock(mutex_);
            if(!batch_wait_policy_.InputFence())return;
            ++metrics_.input_fence_transitions;
        }
        ready_.notify_one();
    }

    bool Start() {
        try {
            thread_ = std::thread(&Worker::Loop, this);
        } catch (...) {
            return false;
        }
        std::unique_lock<std::mutex> lock(mutex_);
        started_.wait(lock, [this] { return startup_complete_; });
        const bool success = startup_success_;
        lock.unlock();
        if (!success && thread_.joinable())
            thread_.join();
        return success;
    }

    bool Enqueue(WorkItem &&item) {
        std::lock_guard<std::mutex> lock(mutex_);
        if (closing_ || failed_)
            return false;
        queue_.push_back(std::move(item));
        ++metrics_.requests_routed;
        metrics_.peak_queue_depth = std::max<uint64_t>(
            metrics_.peak_queue_depth, queue_.size());
        ready_.notify_one();
        return true;
    }

    void Close() {
        {
            std::lock_guard<std::mutex> lock(mutex_);
            closing_ = true;
        }
        ready_.notify_one();
    }

    void Join() {
        if (thread_.joinable())
            thread_.join();
    }

    NativeFusionWorkerMetrics Snapshot() const noexcept {
        NativeFusionWorkerMetrics result = metrics_;
        result.terminal_queue_depth = queue_.size();
        return result;
    }

private:
    void Publish(Completion completion) {
        {
            std::lock_guard<std::mutex> lock(completions_->mutex);
            completions_->queue.push_back(std::move(completion));
            completions_->wake_generation.fetch_add(
                1u, std::memory_order_release);
        }
        completions_->ready.notify_one();
    }

    void Loop() {
        const bool affinity_ok = pin_current_thread_exact(cpu_set_);
        {
            std::lock_guard<std::mutex> lock(mutex_);
            metrics_.affinity_attested =
                !cpu_set_.empty() && affinity_ok ? 1u : 0u;
            startup_success_ = affinity_ok;
            startup_complete_ = true;
        }
        started_.notify_one();
        if (!affinity_ok)
            return;
        std::vector<WorkItem> batch;
        std::vector<fk_native_fusion_request> inputs;
        std::vector<fk_native_fusion_result> outputs;
        try {
            batch.reserve(batch_capacity_);
            inputs.resize(batch_capacity_);
            outputs.resize(batch_capacity_);
        } catch (...) {
            {
                std::lock_guard<std::mutex> lock(mutex_);
                failed_ = true;
            }
            Publish({false, {}, "worker scratch allocation failed"});
            return;
        }
        for (;;) {
            batch.clear();
            {
                std::unique_lock<std::mutex> lock(mutex_);
                ready_.wait(lock, [this] { return closing_ || !queue_.empty(); });
                if (queue_.empty() && closing_)
                    return;
                const bool phase_at_wait=batch_wait_policy_.draining;
                const uint64_t batch_wait_ns=batch_wait_policy_.WaitNs();
                uint64_t effective_wait_ns = batch_wait_ns;
                if (!closing_ && queue_.size() < batch_capacity_ &&
                    detector_schedule_ ==
                        NativeFusionDetectorSchedule::DeadlineGuardBatchFifo) {
                    effective_wait_ns = BatchAgeRemainingNs(
                        queue_.front().receive_ns, monotonic_ns(), batch_wait_ns);
                }
                if (!closing_ && queue_.size() < batch_capacity_ &&
                    detector_schedule_ ==
                        NativeFusionDetectorSchedule::
                            DeadlineGuardBatchFifo) {
                    /* A common relative SLO means absolute deadlines have
                     * the same order as causal physical enqueue times.  We
                     * retain FIFO and only shorten the batching wait.  Keep
                     * the established half-SLO guard for short deadlines,
                     * but never surrender more than 100 ms of dispatch
                     * headroom when the production SLO is 300 ms. */
                    const uint64_t guard_ns = std::min<uint64_t>(
                        detector_deadline_ns_ / 2u, UINT64_C(100000000));
                    const uint64_t dispatch_slack_ns =
                        detector_deadline_ns_ - guard_ns;
                    const uint64_t enqueue_ns =
                        queue_.front().request.physical_timestamp_ns;
                    const uint64_t latest_start_ns =
                        enqueue_ns > UINT64_MAX - dispatch_slack_ns ?
                            UINT64_MAX : enqueue_ns + dispatch_slack_ns;
                    const uint64_t now = monotonic_ns();
                    const uint64_t until_latest_start =
                        now == 0u || now >= latest_start_ns ?
                            0u : latest_start_ns - now;
                    effective_wait_ns = std::min(
                        effective_wait_ns, until_latest_start);
                    // A head may already have spent >1 ms in this worker's
                    // queue. Its old receive timestamp cannot anchor recovery
                    // coalescing: that would expire every recovery window
                    // before it starts and flush tiny batches indefinitely.
                    // For an ALREADY missed deadline, allow one bounded 1 ms
                    // window from this batch's activation. wait_for(predicate)
                    // does not reset the window on arrivals/spurious wakes.
                    // Original request clocks and miss accounting stay intact.
                    effective_wait_ns = std::max(effective_wait_ns,
                        OverdueBatchRecoveryNs(enqueue_ns,
                            now, now,
                            detector_deadline_ns_, batch_wait_ns));
                }
                if (!closing_ && queue_.size() < batch_capacity_ &&
                    effective_wait_ns != 0u) {
                    (void)ready_.wait_for(lock,
                        std::chrono::nanoseconds(effective_wait_ns),
                        [this,phase_at_wait] {
                            return closing_ || queue_.size() >= batch_capacity_ ||
                                batch_wait_policy_.draining!=phase_at_wait;
                        });
                }
                if (queue_.size() >= batch_capacity_) {
                    ++metrics_.batch_trigger_capacity;
                } else if (closing_) {
                    ++metrics_.batch_trigger_close;
                } else if (batch_wait_policy_.draining!=phase_at_wait) {
                    ++metrics_.batch_trigger_input_fence;
                } else if (detector_schedule_ ==
                        NativeFusionDetectorSchedule::
                            DeadlineGuardBatchFifo) {
                    const uint64_t guard_ns = std::min<uint64_t>(
                        detector_deadline_ns_ / 2u, UINT64_C(100000000));
                    const uint64_t dispatch_slack_ns =
                        detector_deadline_ns_ - guard_ns;
                    const uint64_t enqueue_ns =
                        queue_.front().request.physical_timestamp_ns;
                    const uint64_t latest_start_ns =
                        enqueue_ns > UINT64_MAX - dispatch_slack_ns ?
                            UINT64_MAX : enqueue_ns + dispatch_slack_ns;
                    const uint64_t now = monotonic_ns();
                    if (now == 0u || now >= latest_start_ns) {
                        ++metrics_.batch_trigger_deadline_guard;
                    } else {
                        ++metrics_.batch_trigger_wait_timeout;
                    }
                } else {
                    ++metrics_.batch_trigger_wait_timeout;
                }
                const size_t count = std::min<size_t>(
                    batch_capacity_, queue_.size());
                try {
                    for (size_t index = 0u; index < count; ++index) {
                        batch.push_back(std::move(queue_.front()));
                        queue_.pop_front();
                    }
                    metrics_.requests_dequeued += count;
                    ++metrics_.batches_started;
                    if(batch_wait_policy_.draining) {
                        ++metrics_.drain_phase_batches;metrics_.drain_phase_rows+=count;
                    } else {
                        ++metrics_.active_phase_batches;metrics_.active_phase_rows+=count;
                    }
                    metrics_.maximum_batch_rows = std::max<uint64_t>(
                        metrics_.maximum_batch_rows, count);
                } catch (...) {
                    failed_ = true;
                    Publish({false, {}, "worker batch allocation failed"});
                    return;
                }
            }

            try {
                Completion completion{};
                completion.scorer_output = true;
                for (size_t index = 0u; index < batch.size(); ++index) {
                    inputs[index].sequence = batch[index].sequence;
                    inputs[index].event_token = batch[index].event_token;
                    inputs[index].source_mask =
                        batch[index].request.source_mask;
                    std::memcpy(inputs[index].features,
                        batch[index].request.features,
                        sizeof(inputs[index].features));
                }
                std::vector<NativeEventContext> contexts;
                contexts.reserve(batch.size());
                for (const WorkItem &work : batch)
                    contexts.push_back({work.sequence, work.event_token,
                        work.request.semantic_timestamp_ns, work.event_id,
                        work.request.canonical_key,
                        work.request.flow_first_timestamp_ns,
                        work.request.logical_connection_id,
                        work.request.checkpoint_packet,
                        work.request.flags});
                const uint64_t inference_start = monotonic_ns();
                for (const WorkItem &work : batch) {
                    if (work.receive_ns >=
                            work.request.physical_timestamp_ns) {
                        metrics_.maximum_transport_queue_wait_ns =
                            std::max(metrics_.maximum_transport_queue_wait_ns,
                                work.receive_ns -
                                    work.request.physical_timestamp_ns);
                    }
                    if (inference_start >= work.receive_ns) {
                        metrics_.maximum_worker_queue_wait_ns =
                            std::max(metrics_.maximum_worker_queue_wait_ns,
                                inference_start - work.receive_ns);
                    }
                }
                std::string scorer_error;
                if (inference_start == 0u || !scorer_->ScoreBatchWithContext(
                        inputs.data(), batch.size(), contexts.data(), outputs.data(),
                        &scorer_error)) {
                    {
                        std::lock_guard<std::mutex> lock(mutex_);
                        failed_ = true;
                    }
                    completion.error = scorer_error.empty() ?
                        "native scorer rejected a batch" : scorer_error;
                    Publish(std::move(completion));
                    return;
                }
                const uint64_t decision_ns = monotonic_ns();
                if (decision_ns < inference_start) {
                    {
                        std::lock_guard<std::mutex> lock(mutex_);
                        failed_ = true;
                    }
                    completion.error = "worker monotonic clock regressed";
                    Publish(std::move(completion));
                    return;
                }
                ++metrics_.batches_scored;
                metrics_.requests_scored += batch.size();
                metrics_.maximum_inference_ns = std::max(
                    metrics_.maximum_inference_ns,
                    decision_ns - inference_start);
                for (const WorkItem &work : batch) {
                    if (decision_ns >=
                            work.request.physical_timestamp_ns) {
                        metrics_.maximum_end_to_end_ns = std::max(
                            metrics_.maximum_end_to_end_ns,
                            decision_ns -
                                work.request.physical_timestamp_ns);
                    }
                }
                completion.decisions.reserve(batch.size());
                for (size_t index = 0u; index < batch.size(); ++index) {
                    if (!valid_result(outputs[index], batch[index])) {
                        {
                            std::lock_guard<std::mutex> lock(mutex_);
                            failed_ = true;
                        }
                        completion.decisions.clear();
                        completion.error =
                            "native scorer result identity/ABI invalid";
                        Publish(std::move(completion));
                        return;
                    }
                    NativeFusionDecision decision{};
                    decision.kind = NativeFusionDecisionKind::Checkpoint;
                    decision.score_present = 1u;
                    decision.sequence = batch[index].sequence;
                    decision.event_token = batch[index].event_token;
                    decision.event_id = batch[index].event_id;
                    decision.worker_shard = shard_;
                    decision.canonical_key =
                        batch[index].request.canonical_key;
                    decision.flow_index = batch[index].request.flow_index;
                    decision.flow_generation =
                        batch[index].request.flow_generation;
                    decision.flow_first_timestamp_ns =
                        batch[index].request.flow_first_timestamp_ns;
                    decision.checkpoint_packet =
                        batch[index].request.checkpoint_packet;
                    decision.source_mask = batch[index].request.source_mask;
                    decision.coverage_terminal = batch[index].request.flags ==
                        FK_DETECTOR_REQUEST_FLAG_COVERAGE_TERMINAL;
                    if (decision.coverage_terminal) {
                        decision.coverage_evidence_timestamp_ns =
                            fk_detector_coverage_evidence_ns(&batch[index].request);
                        auto prefix = std::make_shared<std::array<float, FK_DETECTOR_REQUEST_FEATURE_COUNT>>();
                        std::copy(std::begin(batch[index].request.features),
                            std::end(batch[index].request.features), prefix->begin());
                        decision.coverage_prefix = prefix;
                    }
                    decision.semantic_timestamp_ns =
                        batch[index].request.semantic_timestamp_ns;
                    decision.physical_enqueue_monotonic_ns =
                        batch[index].request.physical_timestamp_ns;
                    decision.event_routing_token =
                        batch[index].request.event_routing_token;
                    decision.consumer_receive_monotonic_ns =
                        batch[index].receive_ns;
                    decision.inference_start_monotonic_ns = inference_start;
                    decision.decision_monotonic_ns = decision_ns;
                    decision.logical_connection_id =
                        batch[index].request.logical_connection_id;
                    decision.score = outputs[index].score;
                    decision.threshold_met = outputs[index].threshold_met;
                    decision.first_alert = outputs[index].first_alert;
                    decision.alert_latched = outputs[index].alert_latched;
                    completion.decisions.push_back(decision);
                }
                completion.success = true;
                Publish(std::move(completion));
            } catch (const std::exception &exception) {
                {
                    std::lock_guard<std::mutex> lock(mutex_);
                    failed_ = true;
                }
                Completion failure{};
                failure.error = std::string("worker exception: ") +
                    exception.what();
                Publish(std::move(failure));
                return;
            } catch (...) {
                {
                    std::lock_guard<std::mutex> lock(mutex_);
                    failed_ = true;
                }
                Completion failure{};
                failure.error = "worker non-standard exception";
                Publish(std::move(failure));
                return;
            }
        }
    }

    uint32_t shard_;
    uint32_t batch_capacity_;
    PhaseBatchWait batch_wait_policy_;
    NativeFusionDetectorSchedule detector_schedule_;
    uint64_t detector_deadline_ns_;
    NativeFusionBatchScorer *scorer_;
    CompletionQueue *completions_;
    std::vector<uint32_t> cpu_set_;
    std::mutex mutex_;
    std::condition_variable ready_;
    std::condition_variable started_;
    std::deque<WorkItem> queue_;
    NativeFusionWorkerMetrics metrics_{shard_};
    bool closing_ = false;
    bool failed_ = false;
    bool startup_complete_ = false;
    bool startup_success_ = false;
    std::thread thread_;
};

bool valid_config(
        const NativeFusionServiceConfig &config,
        const std::vector<NativeFusionBatchScorer *> &scorers) {
    const uint32_t durable_commit_batch_capacity =
        config.durable_commit_batch_capacity == 0u ?
            config.batch_capacity : config.durable_commit_batch_capacity;
    const uint32_t route_quantum = config.route_quantum == 0u ?
        config.max_inflight : config.route_quantum;
    const uint32_t flow_state_capacity = config.flow_state_capacity == 0u ?
        config.max_inflight : config.flow_state_capacity;
    const bool schedule_valid =
        config.detector_schedule ==
            NativeFusionDetectorSchedule::BatchFifo ||
        config.detector_schedule ==
            NativeFusionDetectorSchedule::DeadlineGuardBatchFifo;
    if (config.worker_count == 0u || config.worker_count > 256u ||
        config.batch_capacity == 0u || config.batch_capacity > 65536u ||
        durable_commit_batch_capacity == 0u ||
        durable_commit_batch_capacity > config.max_inflight ||
        config.max_inflight == 0u ||
        config.max_inflight < config.batch_capacity ||
        flow_state_capacity < config.max_inflight ||
        route_quantum == 0u || route_quantum > config.max_inflight ||
        config.detector_deadline_ns < 2u ||
        config.detector_deadline_ns >
            static_cast<uint64_t>(std::numeric_limits<int64_t>::max()) ||
        config.durable_commit_max_wait_ns >
            static_cast<uint64_t>(std::numeric_limits<int64_t>::max()) ||
        config.idle_poll_ns >
            static_cast<uint64_t>(std::numeric_limits<int64_t>::max()) ||
        config.worker_batch_wait_ns >
            static_cast<uint64_t>(std::numeric_limits<int64_t>::max()) ||
        (config.durable_commit_max_wait_age_anchor ==
             NativeFusionDurableAgeAnchor::FirstDurableCandidate &&
         (config.durable_commit_max_wait_ns == 0u ||
          config.durable_commit_max_wait_ns > UINT64_C(20000000))) ||
        !schedule_valid ||
        config.retention_detector_coupling !=
            NativeFusionRetentionDetectorCoupling::Decoupled ||
        (config.flow_open_scorer != nullptr &&
         (!std::isfinite(config.flow_open_threshold) ||
          config.flow_open_threshold < 0.0 ||
          config.flow_open_threshold > 1.0)) ||
        (!config.require_flow_open &&
         !config.allow_test_only_durability) ||
        scorers.size() != config.worker_count ||
        !affinity_plan_valid(config)) {
        return false;
    }
    return std::all_of(scorers.begin(), scorers.end(),
        [](const NativeFusionBatchScorer *scorer) {
            return scorer != nullptr;
        });
}

}  // namespace

const char *NativeFusionDetectorScheduleName(
        NativeFusionDetectorSchedule schedule) noexcept {
    switch (schedule) {
    case NativeFusionDetectorSchedule::BatchFifo:
        return "batch_fifo";
    case NativeFusionDetectorSchedule::DeadlineGuardBatchFifo:
        return "deadline_guard_batch_fifo";
    }
    return "invalid";
}

const char *NativeFusionDurableAgeAnchorName(
        NativeFusionDurableAgeAnchor anchor) noexcept {
    switch (anchor) {
    case NativeFusionDurableAgeAnchor::PhysicalEnqueue:
        return "physical_enqueue_monotonic_ns";
    case NativeFusionDurableAgeAnchor::ConsumerReceive:
        return "consumer_receive_monotonic_ns";
    case NativeFusionDurableAgeAnchor::FirstDurableCandidate:
        return "first_durable_candidate_monotonic_ns";
    }
    return "invalid";
}

uint32_t NativeFusionWorkerShard(
        uint64_t event_id, uint32_t worker_count) {
    if (event_id == 0u || worker_count == 0u)
        return UINT32_MAX;
    uint64_t mixed = event_id + UINT64_C(0x9e3779b97f4a7c15);
    mixed = (mixed ^ (mixed >> 30u)) * UINT64_C(0xbf58476d1ce4e5b9);
    mixed = (mixed ^ (mixed >> 27u)) * UINT64_C(0x94d049bb133111eb);
    mixed ^= mixed >> 31u;
    return static_cast<uint32_t>(mixed % worker_count);
}

std::unique_ptr<NativeFusionRequestSource> OpenNativeFusionShmSource(
        const std::string &shm_name,
        uint64_t expected_run_epoch,
        std::string *error) {
    if (shm_name.empty() || expected_run_epoch == 0u) {
        set_error(error, "invalid SHM source name/run epoch");
        return nullptr;
    }
    fk_detector_request_shm *transport = nullptr;
    if (!fk_detector_request_shm_open_consumer(
            shm_name.c_str(), expected_run_epoch, &transport)) {
        set_error(error, "failed to open formal detector SHM consumer");
        return nullptr;
    }
    std::unique_ptr<NativeFusionRequestSource> result(
        new (std::nothrow) ShmSource(
            shm_name, expected_run_epoch, transport));
    if (!result) {
        (void)fk_detector_request_shm_close_checked(transport);
        set_error(error, "failed to allocate native SHM source adapter");
    }
    return result;
}

bool RunNativeFusionService(
        NativeFusionRequestSource *source,
        NativeFusionEventRouter *router,
        const std::vector<NativeFusionBatchScorer *> &scorers,
        NativeFusionCommitter *committer,
        const NativeFusionServiceConfig &config,
        NativeFusionServiceReceipt *receipt,
        std::string *error) noexcept {
    if (receipt != nullptr)
        *receipt = {};
    if (error != nullptr)
        error->clear();
    if (source == nullptr || router == nullptr || committer == nullptr ||
        receipt == nullptr || !valid_config(config, scorers)) {
        set_error(error, "native fusion service configuration is invalid");
        return false;
    }

    const uint32_t durable_commit_batch_capacity =
        config.durable_commit_batch_capacity == 0u ?
            config.batch_capacity : config.durable_commit_batch_capacity;
    const uint32_t route_quantum = config.route_quantum == 0u ?
        config.max_inflight : config.route_quantum;
    const uint32_t route_slice_capacity =
        config.durable_commit_max_wait_ns == 0u ? route_quantum :
            std::min(route_quantum, kDurableGuardRouteSlice);
    const uint32_t flow_state_capacity = config.flow_state_capacity == 0u ?
        config.max_inflight : config.flow_state_capacity;
    NativeFusionServiceReceipt local{};
    const uint32_t commit_depth = committer->PreparedCommitCapacity();
    if ((committer->SupportsPreparedCommit() && commit_depth!=2u && commit_depth!=4u) ||
        (!committer->SupportsPreparedCommit() && commit_depth!=1u)) {
        set_error(error,"invalid prepared commit capacity");return false;
    }
    local.durable_commit_queue_depth = commit_depth;
    local.durable_commit_batch_capacity = durable_commit_batch_capacity;
    local.durable_commit_max_wait_ns = config.durable_commit_max_wait_ns;
    if(const char *value=std::getenv("FK_DRAIN_COMMIT_WAIT_US")) {
        uint64_t us=0;
        if(!*value){set_error(error,"empty drain commit wait");return false;}
        for(const char *c=value;*c;++c) {
            if(*c<'0' || *c>'9' || us>20000u){set_error(error,"invalid drain commit wait");return false;}
            us=us*10u+uint64_t(*c-'0');
        }
        if(us>20000u){set_error(error,"drain commit wait exceeds 20ms");return false;}
        local.drain_commit_max_wait_ns=us*1000u;
    }
    local.route_quantum = route_quantum;
    local.effective_route_slice_capacity = route_slice_capacity;
    local.flow_state_capacity = flow_state_capacity;
    local.detector_ingest_decoupled_from_durable_fsync = 1u;
    local.detector_schedule = config.detector_schedule;
    local.retention_detector_coupling =
        config.retention_detector_coupling;
    local.detector_schedule_uses_retention_signal = 0u;
    local.detector_dispatch_guard_ns =
        config.detector_schedule ==
            NativeFusionDetectorSchedule::DeadlineGuardBatchFifo ?
                std::min<uint64_t>(config.detector_deadline_ns / 2u,
                    UINT64_C(100000000)) : 0u;
    local.ack_after_durable_only = 1u;
    const bool source_delivers_validated_items =
        source->DeliversValidatedItems();
    local.source_delivers_validated_items =
        source_delivers_validated_items ? 1u : 0u;
    const bool affinity_requested =
        !config.coordinator_cpu_set.empty();
    local.coordinator_affinity_requested = affinity_requested ? 1u : 0u;
    local.committer_affinity_requested = affinity_requested ? 1u : 0u;
    local.worker_affinity_plan_requested = affinity_requested ? 1u : 0u;
    local.coordinator_affinity_attested = affinity_requested &&
        current_affinity_exact(config.coordinator_cpu_set) ? 1u : 0u;
    local.started_monotonic_ns = monotonic_ns();
    CompletionQueue completions{};
    // The coordinator still has routing/feedback work after physical EOF.
    // Borrowing only that CPU starved either routing or preparation. Allow
    // the existing low-priority preparer to use idle inference-pool cycles;
    // do not include coordinator, publisher, DPDK or any new CPU.
    std::vector<uint32_t> drain_cpus;
    for(const auto &cpus:config.worker_cpu_sets)
        drain_cpus.insert(drain_cpus.end(),cpus.begin(),cpus.end());
    DurableCommitWorker durable_worker(
        committer, &completions, config.committer_cpu_set, scorers,std::move(drain_cpus));
    std::vector<std::unique_ptr<Worker>> workers;
    struct ReorderSlot {
        NativeFusionDecision decision{};
        uint64_t sequence = 0u;
        bool occupied = false;
    };
    const char *paged_reorder_env=std::getenv("FK_PAGED_REORDER");
    PagedReorderRing<ReorderSlot> reordered(paged_reorder_env && std::string(paged_reorder_env)=="1");
    uint64_t reordered_count = 0u;
    /* Number of already-materialized decisions starting exactly at
     * next_commit_sequence.  Each slot advances this frontier at most once
     * before it is ACKed, avoiding a repeated O(prefix) scan every turn. */
    uint64_t contiguous_ready_count = 0u;
    struct StableRoute {
        uint64_t event_token;
        const std::string *event_id;
    };
    using StableFlowKey = std::array<uint8_t, sizeof(fk_flow_key)>;
    struct StableFlowKeyHash {
        size_t operator()(const StableFlowKey &key) const noexcept {
            /* FNV-1a over the fixed canonical-key ABI; lookup allocates no
             * heap memory on repeated checkpoints. */
            uint64_t hash = UINT64_C(1469598103934665603);
            for (const uint8_t byte : key) {
                hash ^= byte;
                hash *= UINT64_C(1099511628211);
            }
            return static_cast<size_t>(hash);
        }
    };
    std::unordered_map<StableFlowKey, StableRoute, StableFlowKeyHash>
        stable_flow_routes;
    struct PresentationGenerationIdentity {
        StableFlowKey key{};
        uint32_t flow_index = 0u;
        uint32_t flow_generation = 0u;
        uint64_t flow_first_timestamp_ns = 0u;
        uint64_t logical_connection_id = 0u;

        bool operator==(
                const PresentationGenerationIdentity &other) const noexcept {
            return key == other.key && flow_index == other.flow_index &&
                flow_generation == other.flow_generation &&
                flow_first_timestamp_ns == other.flow_first_timestamp_ns &&
                logical_connection_id == other.logical_connection_id;
        }
    };
    struct PresentationGenerationIdentityHash {
        size_t operator()(const PresentationGenerationIdentity &identity)
                const noexcept {
            uint64_t hash = UINT64_C(1469598103934665603);
            const auto append = [&hash](const uint8_t *bytes, size_t count) {
                for (size_t index = 0u; index < count; ++index) {
                    hash ^= bytes[index];
                    hash *= UINT64_C(1099511628211);
                }
            };
            append(identity.key.data(), identity.key.size());
            append(reinterpret_cast<const uint8_t *>(&identity.flow_index),
                sizeof(identity.flow_index));
            append(reinterpret_cast<const uint8_t *>(
                &identity.flow_generation), sizeof(identity.flow_generation));
            append(reinterpret_cast<const uint8_t *>(
                &identity.flow_first_timestamp_ns),
                sizeof(identity.flow_first_timestamp_ns));
            append(reinterpret_cast<const uint8_t *>(
                &identity.logical_connection_id),
                sizeof(identity.logical_connection_id));
            return static_cast<size_t>(hash);
        }
    };
    /* This immutable identity authorizes exactly one ordered chain of
     * presentation generations.  A CONTINUE control must advance the chain;
     * a checkpoint can never create or infer such an edge. */
    struct SemanticGenerationIdentity {
        StableFlowKey key{};
        uint64_t logical_connection_id = 0u;

        bool operator==(
                const SemanticGenerationIdentity &other) const noexcept {
            return key == other.key &&
                logical_connection_id == other.logical_connection_id;
        }
    };
    struct SemanticGenerationIdentityHash {
        size_t operator()(const SemanticGenerationIdentity &identity)
                const noexcept {
            uint64_t hash = UINT64_C(1469598103934665603);
            const auto append = [&hash](const uint8_t *bytes, size_t count) {
                for (size_t index = 0u; index < count; ++index) {
                    hash ^= bytes[index];
                    hash *= UINT64_C(1099511628211);
                }
            };
            append(identity.key.data(), identity.key.size());
            append(reinterpret_cast<const uint8_t *>(
                &identity.logical_connection_id),
                sizeof(identity.logical_connection_id));
            return static_cast<size_t>(hash);
        }
    };
    struct FlowCoverage {
        uint64_t event_token = 0u;
        uint32_t last_checkpoint_packet = 0u;
        bool checkpoint_seen = false;
    };
    struct EventCoverage {
        uint64_t flow_opens = 0u;
        uint64_t flow_continues = 0u;
        uint64_t checkpoints = 0u;
    };
    std::unordered_map<PresentationGenerationIdentity, FlowCoverage,
        PresentationGenerationIdentityHash> flow_coverage;
    std::unordered_map<SemanticGenerationIdentity,
        PresentationGenerationIdentity, SemanticGenerationIdentityHash>
        active_semantic_generations;
    std::unordered_map<uint64_t, EventCoverage> event_coverage;
    std::string failure;
    bool failed = local.started_monotonic_ns == 0u ||
        (affinity_requested &&
         local.coordinator_affinity_attested == 0u);
    bool producer_done = false;
    ThreadPhaseStamp coordinator_fence_clock,coordinator_source_done_clock;
    uint64_t inflight = 0u;
    const char *quiescent_env=std::getenv("FK_QUIESCENT_FEEDBACK_COMMIT");
    const bool quiescent_feedback_commit=quiescent_env && std::strcmp(quiescent_env,"1")==0;
    bool source_empty_after_fence=false;
    const auto effective_durable_wait_ns=[&] {
        return coordinator_fence_clock.valid && local.drain_commit_max_wait_ns
            ? std::min(config.durable_commit_max_wait_ns,local.drain_commit_max_wait_ns)
            : config.durable_commit_max_wait_ns;
    };
    uint64_t expected_sequence = 0u;
    uint64_t next_commit_sequence = 0u;
    uint64_t last_semantic_timestamp_ns = 0u;
    bool have_semantic_timestamp = false;
    bool all_commits_production_durable = true;
    bool durable_worker_started = false;
    uint32_t commit_in_progress = 0u;
    uint64_t submitted_rows = 0u;
    if (failed && local.started_monotonic_ns != 0u)
        failure = "coordinator thread affinity differs from contract";

    const auto flow_state_has_capacity =
        [&](size_t current_size, const char *map_name) {
            if (current_size < flow_state_capacity)
                return true;
            failed = true;
            ++local.flow_state_capacity_failures;
            ++local.route_failures;
            failure = std::string(map_name) +
                " exceeded configured run-wide flow-state capacity";
            return false;
        };
    const auto observe_flow_state_map =
        [&](const auto &map, NativeFusionFlowStateMapMetrics *metrics,
                const char *map_name) {
            metrics->peak_entries = std::max<uint64_t>(
                metrics->peak_entries, map.size());
            if (map.bucket_count() ==
                    metrics->post_reserve_bucket_count) {
                return true;
            }
            failed = true;
            ++local.flow_state_runtime_rehashes;
            ++local.route_failures;
            failure = std::string(map_name) +
                " rehashed after service startup";
            return false;
        };

    const auto reordered_decision =
        [&](uint64_t sequence) -> NativeFusionDecision * {
            if (reordered.empty())
                return nullptr;
            ReorderSlot *slot = reordered.Find(sequence % reordered.size());
            return slot && slot->occupied && slot->sequence == sequence ?
                &slot->decision : nullptr;
        };

    // A candidate's coalescing clock is local to the current ordered head and
    // begins only after the previous durable call has completed. It is never
    // copied into packet/decision timestamps, and is not reset as more records
    // join the prefix. Capacity and terminal flushes continue to bypass delay.
    uint64_t durable_candidate_sequence = UINT64_MAX;
    uint64_t durable_candidate_started_ns = 0u;
    const auto durable_wait_anchor_ns = [&](const NativeFusionDecision &decision,
                                           uint64_t sampled_ns) {
        if (config.durable_commit_max_wait_age_anchor !=
                NativeFusionDurableAgeAnchor::FirstDurableCandidate)
            return durable_age_anchor_ns(decision,
                config.durable_commit_max_wait_age_anchor);
        if (durable_candidate_sequence != next_commit_sequence + submitted_rows) {
            durable_candidate_sequence = next_commit_sequence + submitted_rows;
            durable_candidate_started_ns = sampled_ns;
        }
        return durable_candidate_started_ns;
    };

    /* This is a configurable-age dispatch guard for the oldest decision
     * in the currently ordered prefix, not an ACK deadline.  It applies only
     * while the single durable worker is idle; an already-running durable
     * commit may finish after the configured interval. */
    const auto durable_head_remaining_ns = [&](uint64_t *remaining_ns) {
        if (remaining_ns == nullptr)
            return false;
        *remaining_ns = UINT64_MAX;
        if (commit_in_progress >= commit_depth || contiguous_ready_count <= submitted_rows)
            return true;
        NativeFusionDecision *oldest =
            reordered_decision(next_commit_sequence + submitted_rows);
        const uint64_t sampled_ns = monotonic_ns();
        if (oldest == nullptr) {
            failed = true;
            ++local.result_validation_failures;
            if (failure.empty())
                failure = "tracked durable ordered head is missing";
            return false;
        }
        if (sampled_ns == 0u ||
            oldest->decision_monotonic_ns <
                oldest->physical_enqueue_monotonic_ns ||
            sampled_ns < oldest->decision_monotonic_ns) {
            failed = true;
            ++local.timestamp_failures;
            if (failure.empty())
                failure = "durable dispatch guard clock is invalid";
            return false;
        }
        const uint64_t age_ns =
            sampled_ns - durable_wait_anchor_ns(*oldest, sampled_ns);
        const uint64_t wait_ns=effective_durable_wait_ns();
        *remaining_ns = age_ns >= wait_ns ? 0u : wait_ns - age_ns;
        return true;
    };

    const auto process_durable_completion =
        [&](DurableCompletion completion, bool allow_ack) {
            bool call_failure_recorded = false;
            const auto fail_commit_call = [&](const std::string &message) {
                failed = true;
                ++local.commit_failures;
                if (!call_failure_recorded) {
                    ++local.durable_commit_failed_calls;
                    call_failure_recorded = true;
                }
                if (failure.empty())
                    failure = message;
            };
            if (!commit_in_progress || completion.decision_count == 0u ||
                completion.first_sequence != next_commit_sequence ||
                completion.last_sequence < completion.first_sequence ||
                completion.last_sequence - completion.first_sequence + 1u !=
                    completion.decision_count) {
                fail_commit_call(
                    "durable completion prefix identity differs");
                commit_in_progress = false;
                return;
            }
            --commit_in_progress;
            if (completion.submitted_monotonic_ns == 0u ||
                completion.commit_started_monotonic_ns <
                    completion.submitted_monotonic_ns ||
                completion.commit_finished_monotonic_ns <
                    completion.commit_started_monotonic_ns) {
                fail_commit_call("durable commit worker clock is invalid");
                return;
            }
            const uint64_t commit_ns =
                completion.commit_finished_monotonic_ns -
                completion.commit_started_monotonic_ns;
            const uint64_t elapsed_ns =
                completion.commit_finished_monotonic_ns -
                completion.submitted_monotonic_ns;
            if (commit_ns > UINT64_MAX - local.durable_commit_total_ns ||
                elapsed_ns >
                    UINT64_MAX - local.durable_commit_elapsed_ns_sum) {
                fail_commit_call("durable commit timing counter overflowed");
                return;
            }
            local.durable_commit_total_ns += commit_ns;
            local.maximum_durable_commit_ns = std::max(
                local.maximum_durable_commit_ns, commit_ns);
            local.durable_commit_elapsed_ns_sum += elapsed_ns;
            local.maximum_durable_commit_elapsed_ns = std::max(
                local.maximum_durable_commit_elapsed_ns, elapsed_ns);
            local.last_durable_commit_completion_monotonic_ns =
                completion.commit_finished_monotonic_ns;
            const NativeFusionDecision *last =
                reordered_decision(completion.last_sequence);
            if (!completion.success) {
                fail_commit_call(completion.error.empty() ?
                    "durable committer rejected a prefix" :
                    completion.error);
                return;
            }
            if (last == nullptr ||
                completion.decision_count > contiguous_ready_count ||
                completion.decision_count > reordered_count ||
                completion.decision_count > inflight ||
                completion.result.completed_monotonic_ns <
                    completion.commit_started_monotonic_ns ||
                completion.result.completed_monotonic_ns >
                    completion.commit_finished_monotonic_ns ||
                (completion.result.durability !=
                     NativeFusionDurability::
                         FsyncRecoverableSegmentDirectory &&
                 completion.result.durability != NativeFusionDurability::SyncWriteAheadLog &&
                 completion.result.durability !=
                     NativeFusionDurability::TestOnlyMemory)) {
                fail_commit_call(
                    "committer returned invalid durability/time/prefix");
                return;
            }
            if (completion.result.durability ==
                    NativeFusionDurability::TestOnlyMemory &&
                !config.allow_test_only_durability) {
                fail_commit_call(
                    "test-only committer is forbidden in production");
                return;
            }
            uint64_t maximum_decision_to_durable_ns = 0u;
            uint64_t maximum_physical_to_durable_ns = 0u;
            for (uint64_t offset = 0u;
                    offset < completion.decision_count; ++offset) {
                if (completion.first_sequence > UINT64_MAX - offset) {
                    fail_commit_call("durable prefix sequence overflowed");
                    return;
                }
                const uint64_t sequence =
                    completion.first_sequence + offset;
                const NativeFusionDecision *decision =
                    reordered_decision(sequence);
                if (decision == nullptr || decision->sequence != sequence ||
                    decision->decision_monotonic_ns <
                        decision->physical_enqueue_monotonic_ns ||
                    completion.result.completed_monotonic_ns <
                        decision->decision_monotonic_ns) {
                    fail_commit_call(
                        "durable prefix decision/timestamp changed");
                    return;
                }
                maximum_decision_to_durable_ns = std::max(
                    maximum_decision_to_durable_ns,
                    completion.result.completed_monotonic_ns -
                        decision->decision_monotonic_ns);
                maximum_physical_to_durable_ns = std::max(
                    maximum_physical_to_durable_ns,
                    completion.result.completed_monotonic_ns -
                        decision->physical_enqueue_monotonic_ns);
            }
            ++local.durable_commit_calls;
            if (completion.result.durability ==
                    NativeFusionDurability::
                        FsyncRecoverableSegmentDirectory) {
                ++local.fsync_attested_commit_calls;
            } else if(completion.result.durability == NativeFusionDurability::SyncWriteAheadLog) {
                ++local.sync_wal_attested_commit_calls;
            } else {
                all_commits_production_durable = false;
            }
            local.maximum_decision_to_durable_ns = std::max(
                local.maximum_decision_to_durable_ns,
                maximum_decision_to_durable_ns);
            local.maximum_physical_enqueue_to_durable_ns = std::max(
                local.maximum_physical_enqueue_to_durable_ns,
                maximum_physical_to_durable_ns);
            local.requests_persisted += completion.decision_count;
            local.last_persisted_sequence = completion.last_sequence;
            if (!allow_ack || failed)
                return;

            NativeFusionSourceSnapshot before_ack{};
            if (!source_snapshot_consistent(
                    source, &before_ack, &failure) ||
                !source_snapshot_clean(before_ack)) {
                failed = true;
                ++local.source_failures;
                if (failure.empty())
                    failure = "source faulted after commit and before ACK";
                return;
            }
            const uint64_t ack_call_started_monotonic_ns = monotonic_ns();
            if (ack_call_started_monotonic_ns <
                    completion.result.completed_monotonic_ns) {
                failed = true;
                ++local.ack_failures;
                if (failure.empty())
                    failure = "durable ACK clock is invalid";
                return;
            }
            for (uint64_t offset = 0; offset < completion.decision_count; ++offset) {
                const auto *d = reordered_decision(completion.first_sequence + offset);
                if (!d || !source->ObserveDurableDecision(*d, &failure)) {
                    failed = true; ++local.ack_failures;
                    return;
                }
            }
            if (!source->Ack(completion.last_sequence, &failure)) {
                failed = true;
                ++local.ack_failures;
                if (failure.empty())
                    failure = "source rejected durable-prefix ACK";
                return;
            }
            // An ACK may authorize a new adaptive target. Observe Peek again
            // before using source quiescence to end a partial commit batch.
            source_empty_after_fence=false;
            const uint64_t ack_completed_monotonic_ns = monotonic_ns();
            const bool ack_clock_valid =
                ack_completed_monotonic_ns >=
                    ack_call_started_monotonic_ns;
            ++local.ack_calls;
            local.requests_acked += completion.decision_count;
            local.last_acked_sequence = completion.last_sequence;
            if (ack_clock_valid) {
                uint64_t maximum_decision_to_ack_ns = 0u;
                uint64_t maximum_physical_to_ack_ns = 0u;
                for (uint64_t offset = 0u;
                        offset < completion.decision_count; ++offset) {
                    const uint64_t sequence =
                        completion.first_sequence + offset;
                    const NativeFusionDecision *decision =
                        reordered_decision(sequence);
                    maximum_decision_to_ack_ns = std::max(
                        maximum_decision_to_ack_ns,
                        ack_completed_monotonic_ns -
                            decision->decision_monotonic_ns);
                    maximum_physical_to_ack_ns = std::max(
                        maximum_physical_to_ack_ns,
                        ack_completed_monotonic_ns -
                            decision->physical_enqueue_monotonic_ns);
                }
                completion.trace.ack_ns = ack_completed_monotonic_ns;
                if (local.commit_trace.size() < 4096u)
                    local.commit_trace.push_back(completion.trace);
                else ++local.commit_trace_dropped;
                if (maximum_physical_to_ack_ns >= local.maximum_physical_enqueue_to_ack_ns)
                    local.slowest_ack_trace = completion.trace;
                local.maximum_decision_to_ack_ns = std::max(
                    local.maximum_decision_to_ack_ns,
                    maximum_decision_to_ack_ns);
                local.maximum_physical_enqueue_to_ack_ns = std::max(
                    local.maximum_physical_enqueue_to_ack_ns,
                    maximum_physical_to_ack_ns);
            } else {
                failed = true;
                ++local.ack_failures;
                if (failure.empty())
                    failure = "durable ACK completion clock is invalid";
            }
            inflight -= completion.decision_count;
            for (uint64_t offset = 0u;
                    offset < completion.decision_count; ++offset) {
                const uint64_t sequence =
                    completion.first_sequence + offset;
                ReorderSlot &slot =
                    reordered.Acquire(sequence % reordered.size());
                if (!slot.occupied || slot.sequence != sequence ||
                    reordered_count == 0u) {
                    failed = true;
                    ++local.result_validation_failures;
                    if (failure.empty())
                        failure = "reorder ring durable prefix changed";
                    return;
                }
                slot.occupied = false;
                // Coverage evidence has now crossed the real durable ACK.
                // Do not retain shared payloads until this large ring wraps.
                slot.decision.coverage_prefix.reset();
                reordered.Released(sequence % reordered.size());
                --reordered_count;
            }
            submitted_rows -= completion.decision_count;
            contiguous_ready_count -= completion.decision_count;
            next_commit_sequence = completion.last_sequence + 1u;
        };

    try {
        NativeFusionSourceSnapshot initial{};
        if (!failed && (!source_snapshot_consistent(
                source, &initial, &failure) ||
            !source_snapshot_clean(initial))) {
            failed = true;
            ++local.source_failures;
            if (failure.empty())
                failure = "initial source snapshot is faulted";
        }
        if (!failed) {
            if (config.max_inflight > initial.capacity) {
                failed = true;
                failure = "max_inflight exceeds the SHM source capacity";
                ++local.source_failures;
            } else {
                expected_sequence = initial.read_sequence + 1u;
                next_commit_sequence = expected_sequence;
            }
        }
        if (!failed) {
            try {
                reordered.resize(config.max_inflight);
                /* Build every bucket array before the producer is released.
                 * These maps are run-wide, not max-inflight state.  A live
                 * rehash pauses the single routing coordinator and therefore
                 * directly consumes the detector's physical-enqueue SLA. */
                stable_flow_routes.max_load_factor(2.0f);
                stable_flow_routes.reserve(flow_state_capacity);
                flow_coverage.max_load_factor(2.0f);
                flow_coverage.reserve(flow_state_capacity);
                active_semantic_generations.max_load_factor(2.0f);
                active_semantic_generations.reserve(flow_state_capacity);
                event_coverage.max_load_factor(2.0f);
                event_coverage.reserve(flow_state_capacity);
                local.stable_flow_routes_map.post_reserve_bucket_count =
                    stable_flow_routes.bucket_count();
                local.flow_coverage_map.post_reserve_bucket_count =
                    flow_coverage.bucket_count();
                local.active_semantic_generations_map.
                    post_reserve_bucket_count =
                        active_semantic_generations.bucket_count();
                local.event_coverage_map.post_reserve_bucket_count =
                    event_coverage.bucket_count();
            } catch (const std::bad_alloc &) {
                failed = true;
                failure = "failed to preallocate bounded service state";
            }
        }
        if (!failed) {
            if (!durable_worker.Start()) {
                failed = true;
                failure = "failed to start the durable commit worker";
                ++local.commit_failures;
            } else {
                durable_worker_started = true;
            }
        }
        if (!failed) {
            workers.reserve(config.worker_count);
            for (uint32_t shard = 0u; shard < config.worker_count; ++shard) {
                workers.emplace_back(new Worker(shard,
                    config.batch_capacity, config.worker_batch_wait_ns,
                    config.detector_schedule,
                    config.detector_deadline_ns,
                    scorers[shard], &completions,
                    affinity_requested ? config.worker_cpu_sets[shard] :
                        std::vector<uint32_t>{}));
                if (!workers.back()->Start()) {
                    failed = true;
                    failure = "failed to start a native scorer worker";
                    ++local.scorer_failures;
                    break;
                }
            }
        }

        while (!failed) {
            bool progressed = false;
            const uint64_t turn_wake_generation =
                completions.wake_generation.load(std::memory_order_acquire);
            DurableCompletion durable_completion{};
            if (durable_worker.Take(&durable_completion)) {
                process_durable_completion(
                    std::move(durable_completion), true);
                progressed = true;
            }
            std::deque<Completion> ready;
            {
                std::lock_guard<std::mutex> lock(completions.mutex);
                ready.swap(completions.queue);
            }
            bool reordered_changed = false;
            while (!ready.empty() && !failed) {
                Completion completion = std::move(ready.front());
                ready.pop_front();
                progressed = true;
                if (!completion.success) {
                    failed = true;
                    failure = completion.error.empty() ?
                        "native scorer worker failed" : completion.error;
                    if (failure.find("result identity/ABI") !=
                            std::string::npos) {
                        ++local.result_validation_failures;
                    } else {
                        ++local.scorer_failures;
                    }
                    break;
                }
                const bool completion_kind_valid = std::all_of(
                    completion.decisions.begin(),
                    completion.decisions.end(),
                    [&completion, &config](
                            const NativeFusionDecision &decision) {
                        return completion.scorer_output
                            ? decision.kind ==
                                  NativeFusionDecisionKind::Checkpoint &&
                                  decision.score_present == 1u
                            : ((decision.kind ==
                                   NativeFusionDecisionKind::FlowOpen &&
                                decision.score_present ==
                                    (config.flow_open_scorer != nullptr ?
                                        1u : 0u)) ||
                               (decision.kind ==
                                   NativeFusionDecisionKind::FlowContinue &&
                                decision.score_present == 0u));
                    });
                if (!completion_kind_valid || completion.decisions.empty()) {
                    failed = true;
                    ++local.result_validation_failures;
                    failure = "native completion kind/score contract differs";
                    break;
                }
                if (completion.scorer_output) {
                    ++local.scorer_batches;
                    local.requests_scored += completion.decisions.size();
                }
                const uint64_t misses_before = local.deadline_misses;
                for (const NativeFusionDecision &decision :
                        completion.decisions) {
                    if (!(decision.physical_enqueue_monotonic_ns <=
                              decision.consumer_receive_monotonic_ns &&
                          decision.consumer_receive_monotonic_ns <=
                              decision.inference_start_monotonic_ns &&
                          decision.inference_start_monotonic_ns <=
                              decision.decision_monotonic_ns)) {
                        failed = true;
                        ++local.timestamp_failures;
                        failure = "scored decision timestamp order differs";
                        break;
                    }
                    const uint64_t queue_wait =
                        decision.consumer_receive_monotonic_ns -
                        decision.physical_enqueue_monotonic_ns;
                    const uint64_t end_to_end =
                        decision.decision_monotonic_ns -
                        decision.physical_enqueue_monotonic_ns;
                    local.maximum_queue_wait_ns = std::max(
                        local.maximum_queue_wait_ns, queue_wait);
                    local.maximum_end_to_end_ns = std::max(
                        local.maximum_end_to_end_ns, end_to_end);
                    observe_deadline_miss(
                        decision, config.detector_deadline_ns, &local);
                }
                if (failed)
                    break;
                // A deadline miss is an observed performance outcome, not a
                // transport-integrity failure.  Keep draining the exact input
                // stream so the receipt contains the complete miss count and
                // terminal latency evidence.  Formal readiness still requires
                // deadline_misses == 0; corrupt input, queue overflow, commit
                // failure, and ordering violations remain fail-closed.
                (void)misses_before;
                for (NativeFusionDecision &decision : completion.decisions) {
                    if (decision.sequence != next_commit_sequence &&
                        reordered_decision(next_commit_sequence) == nullptr) {
                        ++local.out_of_order_worker_completions;
                    }
                    ReorderSlot &slot = reordered.Acquire(
                        decision.sequence % reordered.size());
                    if (slot.occupied) {
                        failed = true;
                        failure = slot.sequence == decision.sequence ?
                            "worker returned a duplicate sequence" :
                            "worker exceeded bounded reorder capacity";
                        ++local.result_validation_failures;
                        break;
                    }
                    slot.sequence = decision.sequence;
                    slot.decision = std::move(decision);
                    slot.occupied = true;
                    reordered.Stored(slot.sequence % reordered.size());
                    ++reordered_count;
                    reordered_changed = true;
                }
            }
            if (failed && !ready.empty()) {
                /* Preserve honest terminal accounting for completions that
                 * were removed from the shared queue in the same turn as the
                 * first fail-closed completion. */
                std::lock_guard<std::mutex> lock(completions.mutex);
                while (!ready.empty()) {
                    completions.queue.push_back(std::move(ready.front()));
                    ready.pop_front();
                }
            }
            if (!failed && reordered_changed) {
                while (contiguous_ready_count < reordered_count) {
                    if (next_commit_sequence >
                            UINT64_MAX - contiguous_ready_count) {
                        failed = true;
                        ++local.result_validation_failures;
                        failure = "reorder prefix sequence overflowed";
                        break;
                    }
                    const uint64_t sequence =
                        next_commit_sequence + contiguous_ready_count;
                    if (reordered_decision(sequence) == nullptr)
                        break;
                    ++contiguous_ready_count;
                }
            }

            if (!failed && commit_in_progress < commit_depth &&
                    contiguous_ready_count > submitted_rows) {
                NativeFusionDecision *oldest =
                    reordered_decision(next_commit_sequence + submitted_rows);
                const uint64_t submit_ns = monotonic_ns();
                if (oldest == nullptr || submit_ns == 0u ||
                    oldest->decision_monotonic_ns <
                        oldest->physical_enqueue_monotonic_ns ||
                    submit_ns < oldest->decision_monotonic_ns) {
                    failed = true;
                    ++local.timestamp_failures;
                    failure = "durable prefix submit clock is invalid";
                } else {
                    const bool capacity_trigger =
                        contiguous_ready_count - submitted_rows >=
                            durable_commit_batch_capacity;
                    const bool quiescent_feedback = quiescent_feedback_commit &&
                        !producer_done && source_empty_after_fence && commit_in_progress==0u;
                    const bool terminal_trigger = !capacity_trigger &&
                        (producer_done || quiescent_feedback) &&
                        reordered_count == inflight &&
                        contiguous_ready_count == inflight;
                    const uint64_t oldest_decision_wait_ns =
                        submit_ns - oldest->decision_monotonic_ns;
                    const uint64_t oldest_physical_age_ns =
                        submit_ns - durable_wait_anchor_ns(*oldest, submit_ns);
                    const bool max_wait_trigger = !capacity_trigger &&
                        !terminal_trigger &&
                        (effective_durable_wait_ns() == 0u ||
                         oldest_physical_age_ns >= effective_durable_wait_ns());
                    if (capacity_trigger || terminal_trigger ||
                            max_wait_trigger) {
                        const uint64_t prefix_rows = capacity_trigger ?
                            durable_commit_batch_capacity :
                            contiguous_ready_count - submitted_rows;
                        std::vector<NativeFusionDecision> prefix;
                        prefix.reserve(static_cast<size_t>(prefix_rows));
                        for (uint64_t offset = 0u;
                                offset < prefix_rows; ++offset) {
                            const NativeFusionDecision *found =
                                reordered_decision(
                                    next_commit_sequence + submitted_rows + offset);
                            if (found == nullptr) {
                                failed = true;
                                ++local.result_validation_failures;
                                failure =
                                    "tracked durable prefix changed";
                                break;
                            }
                            prefix.push_back(*found);
                        }
                        NativeFusionSourceSnapshot before_commit{};
                        if (!failed && (!source_snapshot_consistent(
                                source, &before_commit, &failure) ||
                            !source_snapshot_clean(before_commit))) {
                            failed = true;
                            ++local.source_failures;
                            if (failure.empty())
                                failure =
                                    "source faulted before durable commit";
                        } else if (!failed && !durable_worker.Submit(
                                std::move(prefix), submit_ns)) {
                            failed = true;
                            ++local.commit_failures;
                            failure =
                                "durable commit worker rejected a prefix";
                        } else if (!failed) {
                            ++local.durable_commit_submissions;
                            if (capacity_trigger) {
                                ++local.durable_commit_trigger_capacity;
                            } else if (terminal_trigger) {
                                ++local.durable_commit_trigger_terminal;
                                if(quiescent_feedback)++local.durable_commit_trigger_quiescent_feedback;
                            } else {
                                ++local.durable_commit_trigger_max_wait;
                                if(effective_durable_wait_ns()<config.durable_commit_max_wait_ns)
                                    ++local.durable_commit_trigger_drain_wait;
                            }
                            if (local.minimum_durable_commit_batch_rows ==
                                    0u) {
                                local.minimum_durable_commit_batch_rows =
                                    prefix_rows;
                            } else {
                                local.minimum_durable_commit_batch_rows =
                                    std::min(
                                        local.
                                            minimum_durable_commit_batch_rows,
                                        prefix_rows);
                            }
                            local.maximum_durable_commit_batch_rows =
                                std::max(
                                    local.maximum_durable_commit_batch_rows,
                                    prefix_rows);
                            local.maximum_durable_commit_batch_wait_ns =
                                std::max(
                                    local.
                                        maximum_durable_commit_batch_wait_ns,
                                    oldest_decision_wait_ns);
                            if (local.
                                    first_durable_commit_submit_monotonic_ns ==
                                    0u) {
                                local.
                                    first_durable_commit_submit_monotonic_ns =
                                    submit_ns;
                            }
                            ++commit_in_progress;
                            local.durable_commit_peak_depth=std::max<uint64_t>(local.durable_commit_peak_depth,commit_in_progress);
                            submitted_rows += prefix_rows;
                            progressed = true;
                        }
                    }
                }
            }

            uint32_t routed_this_turn = 0u;
            /* Positive max-wait production runs return to ordered scheduling
             * after a bounded routing slice even when every routed record is
             * a coordinator-local flow-control decision.  Keep this bound
             * independent of the transport burst: a wider B64 slice did not
             * reduce the observed upstream queue tail and needlessly delayed
             * completion, durable-commit, and ACK progress. */
            while (!failed && !producer_done &&
                    inflight < config.max_inflight &&
                    routed_this_turn < route_slice_capacity) {
                /* Finish this bounded (at most 32-record) ingress slice even
                 * when worker or durable completions arrive.  This prevents
                 * completion storms from starving source Peek.  A known
                 * ordered durable head is still checked before every record
                 * and preempts immediately when its deadline expires. */
                uint64_t durable_head_remaining = UINT64_MAX;
                if (!durable_head_remaining_ns(
                        &durable_head_remaining) ||
                    durable_head_remaining == 0u) {
                    break;
                }
                fk_detector_request_v1 request{};
                uint64_t sequence = 0u;
                std::string source_error;
                const NativeFusionSourceResult status =
                    source->Peek(&request, &sequence, &source_error);
                if(status!=NativeFusionSourceResult::Fault && source->InputFenceReached()) {
                    if(!coordinator_fence_clock.valid) {
                        coordinator_fence_clock=ReadThreadPhaseStamp();
                        for(auto &worker:workers)worker->BeginInputDrain();
                    }
                    durable_worker.BeginDrain();
                }
                source_empty_after_fence = status==NativeFusionSourceResult::Empty && source->InputFenceReached();
                if (status == NativeFusionSourceResult::Empty) {
                    // Re-enter the coordinator to drain completions/commits,
                    // but do not sleep while bounded finalization made progress.
                    if(source->LastPeekMadeMaintenanceProgress()) {
                        progressed=true;++local.source_maintenance_progress_turns;
                    }
                    break;
                }
                if (status == NativeFusionSourceResult::ProducerDone) {
                    coordinator_source_done_clock=ReadThreadPhaseStamp();
                    local.coordinator_fence_to_source_done=ThreadPhaseBetween(
                        coordinator_fence_clock,coordinator_source_done_clock);
                    producer_done = true;
                    durable_worker.BeginDrain();
                    progressed = true;
                    break;
                }
                if (status == NativeFusionSourceResult::Fault) {
                    failed = true;
                    ++local.source_failures;
                    failure = source_error.empty() ?
                        "native request source faulted" : source_error;
                    break;
                }
                bool request_record_valid = true;
                if (source_delivers_validated_items) {
                    ++local.request_validations_elided;
                } else {
                    ++local.request_validations_performed;
                    request_record_valid =
                        fk_detector_request_v1_valid(&request);
                }
                if (status != NativeFusionSourceResult::Item ||
                    sequence != expected_sequence ||
                    !request_record_valid ||
                    request.event_routing_token != sequence) {
                    failed = true;
                    ++local.source_failures;
                    failure = "native request source sequence/record invalid";
                    break;
                }
                const bool flow_open =
                    request.flags == FK_DETECTOR_REQUEST_FLAG_FLOW_OPEN ||
                    request.flags == FK_DETECTOR_REQUEST_FLAG_COVERAGE_OPEN;
                const bool flow_continue =
                    request.flags == FK_DETECTOR_REQUEST_FLAG_FLOW_CONTINUE;
                const bool flow_control = flow_open || flow_continue;
                ++local.requests_peeked;
                ++inflight;
                local.peak_inflight = std::max(local.peak_inflight, inflight);
                if (local.first_sequence == 0u)
                    local.first_sequence = sequence;
                local.last_sequence = sequence;
                if (local.minimum_physical_enqueue_ns == 0u ||
                    request.physical_timestamp_ns <
                        local.minimum_physical_enqueue_ns) {
                    local.minimum_physical_enqueue_ns =
                        request.physical_timestamp_ns;
                }
                local.maximum_physical_enqueue_ns = std::max(
                    local.maximum_physical_enqueue_ns,
                    request.physical_timestamp_ns);
                ++expected_sequence;
                const uint64_t receive_ns = monotonic_ns();
                if (receive_ns == 0u ||
                    request.physical_timestamp_ns > receive_ns ||
                    (have_semantic_timestamp && !source->IndependentEventClocks() &&
                     request.semantic_timestamp_ns <
                        last_semantic_timestamp_ns)) {
                    failed = true;
                    ++local.timestamp_failures;
                    failure = "native request physical/semantic time regressed";
                    break;
                }
                last_semantic_timestamp_ns = request.semantic_timestamp_ns;
                have_semantic_timestamp = true;
                StableFlowKey flow_identity{};
                std::memcpy(flow_identity.data(), &request.canonical_key,
                    flow_identity.size());
                NativeFusionEventRouter::Route event_route{};
                const auto cached = stable_flow_routes.find(flow_identity);
                if (cached != stable_flow_routes.end()) {
                    if (cached->second.event_token == 0u ||
                        cached->second.event_id == nullptr ||
                        cached->second.event_id->empty()) {
                        failed = true;
                        ++local.route_failures;
                        failure = "frozen flow route cache is invalid";
                        break;
                    }
                    event_route.event_token = cached->second.event_token;
                    event_route.event_id = cached->second.event_id;
                    ++local.route_cache_hits;
                } else {
                    if (!flow_state_has_capacity(
                            stable_flow_routes.size(),
                            "stable_flow_routes")) {
                        break;
                    }
                    std::string route_error;
                    if (!router->Resolve(request, &event_route, &route_error) ||
                        event_route.event_token == 0u ||
                        event_route.event_id == nullptr ||
                        event_route.event_id->empty()) {
                        failed = true;
                        ++local.route_failures;
                        failure = route_error.empty() ?
                            "canonical flow has no frozen event route" :
                            route_error;
                        break;
                    }
                    const auto frozen = stable_flow_routes.emplace(
                        flow_identity, StableRoute{event_route.event_token,
                            event_route.event_id});
                    if (!frozen.second) {
                        failed = true;
                        ++local.route_failures;
                        failure = "frozen flow route insertion raced";
                        break;
                    }
                    if (!observe_flow_state_map(stable_flow_routes,
                            &local.stable_flow_routes_map,
                            "stable_flow_routes")) {
                        break;
                    }
                    ++local.route_cache_misses;
                    ++local.frozen_flow_routes;
                }
                const uint32_t shard = NativeFusionWorkerShard(
                    event_route.event_token, config.worker_count);
                if (shard >= workers.size()) {
                    failed = true;
                    ++local.route_failures;
                    failure = "frozen event route selected an invalid shard";
                    break;
                }
                const PresentationGenerationIdentity generation_identity{
                    flow_identity,
                    request.flow_index,
                    request.flow_generation,
                    request.flow_first_timestamp_ns,
                    request.logical_connection_id,
                };
                const SemanticGenerationIdentity semantic_identity{
                    flow_identity,
                    request.logical_connection_id,
                };
                PresentationGenerationIdentity predecessor_identity{};
                const auto event_coverage_for_route = [&]()
                        -> EventCoverage * {
                    const auto existing = event_coverage.find(
                        event_route.event_token);
                    if (existing != event_coverage.end())
                        return &existing->second;
                    if (!flow_state_has_capacity(event_coverage.size(),
                            "event_coverage")) {
                        return nullptr;
                    }
                    const auto inserted = event_coverage.emplace(
                        event_route.event_token, EventCoverage{});
                    if (!inserted.second) {
                        failed = true;
                        ++local.route_failures;
                        failure = "event coverage insertion raced";
                        return nullptr;
                    }
                    if (!observe_flow_state_map(event_coverage,
                            &local.event_coverage_map,
                            "event_coverage")) {
                        return nullptr;
                    }
                    return &inserted.first->second;
                };
                if (flow_open) {
                    if (flow_coverage.find(generation_identity) !=
                            flow_coverage.end()) {
                        failed = true;
                        ++local.route_failures;
                        failure = "duplicate FLOW_OPEN generation identity";
                        break;
                    }
                    const auto active = active_semantic_generations.find(
                        semantic_identity);
                    if (active != active_semantic_generations.end() &&
                        active->second.flow_first_timestamp_ns ==
                            generation_identity.flow_first_timestamp_ns) {
                        failed = true;
                        ++local.route_failures;
                        failure = "duplicate FLOW_OPEN semantic epoch";
                        break;
                    }
                    if (!flow_state_has_capacity(flow_coverage.size(),
                            "flow_coverage") ||
                        (active == active_semantic_generations.end() &&
                         !flow_state_has_capacity(
                             active_semantic_generations.size(),
                             "active_semantic_generations"))) {
                        break;
                    }
                    EventCoverage *event = event_coverage_for_route();
                    if (event == nullptr)
                        break;
                    const auto inserted = flow_coverage.emplace(
                        generation_identity,
                        FlowCoverage{
                            event_route.event_token,
                            0u,
                            false,
                        });
                    if (!inserted.second) {
                        failed = true;
                        ++local.route_failures;
                        failure = "duplicate FLOW_OPEN generation identity";
                        break;
                    }
                    if (!observe_flow_state_map(flow_coverage,
                            &local.flow_coverage_map, "flow_coverage")) {
                        break;
                    }
                    if (active == active_semantic_generations.end()) {
                        const auto active_inserted =
                            active_semantic_generations.emplace(
                            semantic_identity, generation_identity);
                        if (!active_inserted.second ||
                            !observe_flow_state_map(
                                active_semantic_generations,
                                &local.active_semantic_generations_map,
                                "active_semantic_generations")) {
                            if (!failed) {
                                failed = true;
                                ++local.route_failures;
                                failure = "active semantic generation "
                                    "insertion raced";
                            }
                            break;
                        }
                    } else {
                        /* A real tuple can be reused for a later physical
                         * epoch.  Keep the older exact generation resident:
                         * EOF coverage for that epoch may be appended only
                         * after the physical input frontier closes. */
                        active->second = generation_identity;
                    }
                    ++event->flow_opens;
                    ++local.flow_open_records;
                } else if (flow_continue) {
                    const auto active = active_semantic_generations.find(
                        semantic_identity);
                    if (request.logical_connection_id != 0u ||
                        active == active_semantic_generations.end()) {
                        failed = true;
                        ++local.route_failures;
                        failure = request.logical_connection_id != 0u
                            ? "FLOW_CONTINUE is illegal for a logical "
                                "connection"
                            : "FLOW_CONTINUE lacks an active predecessor";
                        break;
                    }
                    predecessor_identity = active->second;
                    const auto predecessor = flow_coverage.find(
                        predecessor_identity);
                    if (predecessor == flow_coverage.end() ||
                        predecessor->second.event_token !=
                            event_route.event_token ||
                        predecessor_identity.flow_first_timestamp_ns !=
                            request.flow_first_timestamp_ns ||
                        predecessor_identity.flow_index !=
                            request.predecessor_flow_index ||
                        predecessor_identity.flow_generation !=
                            request.predecessor_flow_generation ||
                        predecessor->second.last_checkpoint_packet !=
                            request.predecessor_checkpoint_packet ||
                        predecessor_identity == generation_identity) {
                        failed = true;
                        ++local.route_failures;
                        failure = "FLOW_CONTINUE predecessor/route/"
                            "successor contract is invalid";
                        break;
                    }
                    if (flow_coverage.find(generation_identity) !=
                            flow_coverage.end()) {
                        failed = true;
                        ++local.route_failures;
                        failure = "duplicate FLOW_CONTINUE successor identity";
                        break;
                    }
                    EventCoverage *event = event_coverage_for_route();
                    if (event == nullptr)
                        break;
                    const FlowCoverage successor_coverage =
                        predecessor->second;
                    /* CONTINUE is an explicitly attested edge.  Once it is
                     * accepted, the predecessor can no longer receive a
                     * checkpoint, so replace it instead of accumulating
                     * every historical FlowTable presentation. */
                    flow_coverage.erase(predecessor);
                    ++local.superseded_generation_retirements;
                    const auto inserted = flow_coverage.emplace(
                        generation_identity,
                        FlowCoverage{
                            event_route.event_token,
                            successor_coverage.last_checkpoint_packet,
                            successor_coverage.checkpoint_seen,
                        });
                    if (!inserted.second) {
                        failed = true;
                        ++local.route_failures;
                        failure = "duplicate FLOW_CONTINUE successor identity";
                        break;
                    }
                    if (!observe_flow_state_map(flow_coverage,
                            &local.flow_coverage_map, "flow_coverage")) {
                        break;
                    }
                    active->second = generation_identity;
                    ++event->flow_continues;
                    ++local.flow_continue_records;
                    ++local.capacity_continuation_rebindings;
                } else {
                    const auto opened = flow_coverage.find(
                        generation_identity);
                    if (config.require_flow_open &&
                        (opened == flow_coverage.end() ||
                         opened->second.event_token !=
                             event_route.event_token)) {
                        failed = true;
                        ++local.route_failures;
                        failure = "checkpoint lacks its preceding FLOW_OPEN";
                        break;
                    }
                    if (opened != flow_coverage.end()) {
                        FlowCoverage &coverage = opened->second;
                        const bool terminal = request.flags ==
                            FK_DETECTOR_REQUEST_FLAG_COVERAGE_TERMINAL;
                        if ((!terminal && request.checkpoint_packet <=
                                 coverage.last_checkpoint_packet) ||
                            (terminal && request.checkpoint_packet <
                                 coverage.last_checkpoint_packet)) {
                            failed = true;
                            ++local.route_failures;
                            failure = terminal
                                ? "coverage terminal precedes last real prefix"
                                : "checkpoint packet cursor did not advance "
                                  "within semantic flow identity";
                            break;
                        }
                        coverage.last_checkpoint_packet =
                            request.checkpoint_packet;
                        coverage.checkpoint_seen = true;
                    }
                    EventCoverage *event = event_coverage_for_route();
                    if (event == nullptr)
                        break;
                    ++event->checkpoints;
                    ++local.checkpoint_records;
                }
                ++local.route_bindings_validated;
                if (flow_control) {
                    double flow_open_score = 0.0;
                    const uint64_t inference_start_ns = monotonic_ns();
                    if (inference_start_ns < receive_ns) {
                        failed = true;
                        ++local.timestamp_failures;
                        failure = "flow-control inference clock regressed";
                        break;
                    }
                    if (flow_open && config.flow_open_scorer != nullptr &&
                        (!config.flow_open_scorer->ScoreFlowOpen(
                             request.canonical_key, &flow_open_score,
                             &failure) ||
                         !std::isfinite(flow_open_score) ||
                         flow_open_score < 0.0 || flow_open_score > 1.0)) {
                        failed = true;
                        ++local.scorer_failures;
                        if (failure.empty())
                            failure = "flow-open scorer output is invalid";
                        break;
                    }
                    const uint64_t decision_ns = monotonic_ns();
                    if (decision_ns < inference_start_ns) {
                        failed = true;
                        ++local.timestamp_failures;
                        failure = "flow-control decision clock regressed";
                        break;
                    }
                    NativeFusionDecision decision{};
                    decision.kind = flow_open
                        ? NativeFusionDecisionKind::FlowOpen
                        : NativeFusionDecisionKind::FlowContinue;
                    decision.score_present = flow_open &&
                        config.flow_open_scorer != nullptr ? 1u : 0u;
                    decision.sequence = sequence;
                    decision.event_token = event_route.event_token;
                    decision.event_id = event_route.event_id;
                    decision.worker_shard = shard;
                    decision.canonical_key = request.canonical_key;
                    decision.flow_index = request.flow_index;
                    decision.flow_generation = request.flow_generation;
                    decision.flow_first_timestamp_ns =
                        request.flow_first_timestamp_ns;
                    if (flow_continue) {
                        decision.predecessor_flow_index =
                            predecessor_identity.flow_index;
                        decision.predecessor_flow_generation =
                            predecessor_identity.flow_generation;
                        decision.predecessor_checkpoint_packet =
                            request.predecessor_checkpoint_packet;
                    }
                    decision.checkpoint_packet = 0u;
                    decision.source_mask = 0u;
                    if (request.flags == FK_DETECTOR_REQUEST_FLAG_COVERAGE_OPEN) {
                        if (config.flow_open_scorer != nullptr) {
                            failed = true; ++local.scorer_failures;
                            failure = "coverage deposit must not score FLOW_OPEN";
                            break;
                        }
                        auto prefix = std::make_shared<std::array<float, FK_DETECTOR_REQUEST_FEATURE_COUNT>>();
                        std::copy(std::begin(request.features), std::end(request.features), prefix->begin());
                        decision.coverage_prefix = prefix;
                        decision.coverage_evidence_timestamp_ns = request.flow_first_timestamp_ns;
                    }
                    decision.semantic_timestamp_ns =
                        request.semantic_timestamp_ns;
                    decision.physical_enqueue_monotonic_ns =
                        request.physical_timestamp_ns;
                    decision.event_routing_token =
                        request.event_routing_token;
                    decision.consumer_receive_monotonic_ns = receive_ns;
                    decision.inference_start_monotonic_ns =
                        inference_start_ns;
                    decision.decision_monotonic_ns = decision_ns;
                    decision.logical_connection_id =
                        request.logical_connection_id;
                    decision.score = flow_open_score;
                    const bool flow_open_was_scored =
                        decision.score_present == 1u;
                    Completion completion{};
                    completion.success = true;
                    completion.scorer_output = false;
                    completion.decisions.push_back(std::move(decision));
                    {
                        std::lock_guard<std::mutex> lock(completions.mutex);
                        completions.queue.push_back(std::move(completion));
                    }
                    completions.ready.notify_one();
                    if (flow_open_was_scored)
                        ++local.flow_open_records_scored;
                    ++local.requests_routed;
                    ++routed_this_turn;
                    progressed = true;
                    continue;
                }
                WorkItem work{};
                work.request = request;
                work.sequence = sequence;
                work.event_token = event_route.event_token;
                work.event_id = event_route.event_id;
                work.shard = shard;
                work.receive_ns = receive_ns;
                if (!workers[shard]->Enqueue(std::move(work))) {
                    failed = true;
                    ++local.scorer_failures;
                    failure = "failed to enqueue a scorer work item";
                    break;
                }
                ++local.requests_routed;
                ++routed_this_turn;
                progressed = true;
            }
            if (!failed && !producer_done &&
                    routed_this_turn == route_quantum) {
                ++local.route_quantum_yields;
            }
            if (!failed && !producer_done &&
                    routed_this_turn == route_slice_capacity) {
                ++local.route_slice_yields;
            }

            if (!failed && producer_done && inflight == 0u &&
                    !commit_in_progress && reordered_count == 0u)
                break;
            if (!failed && !progressed) {
                uint64_t wait_ns = config.idle_poll_ns;
                uint64_t durable_head_remaining = UINT64_MAX;
                if (!durable_head_remaining_ns(
                        &durable_head_remaining)) {
                    continue;
                }
                if (durable_head_remaining != UINT64_MAX) {
                    wait_ns = std::min(
                        wait_ns, durable_head_remaining);
                }
                std::unique_lock<std::mutex> lock(completions.mutex);
                // Mutually exclusive state at wait entry, not a claim that
                // all off-CPU time is caused by a single resource.
                const unsigned wait_reason=producer_done && inflight==reordered_count ? 4u :
                    commit_in_progress>=commit_depth && contiguous_ready_count>submitted_rows ? 2u :
                    inflight>reordered_count ? 1u : durable_head_remaining!=UINT64_MAX ? 3u : 0u;
                const uint64_t wait_started=monotonic_ns();
                const bool notified=completions.ready.wait_for(lock,
                    std::chrono::nanoseconds(
                        static_cast<int64_t>(wait_ns)),
                    [&completions, turn_wake_generation] {
                        return completions.wake_generation.load(
                                   std::memory_order_acquire) !=
                            turn_wake_generation;
                    });
                const uint64_t waited=monotonic_ns()-wait_started;
                local.coordinator_wait_ns[wait_reason]+=waited;
                ++local.coordinator_wait_calls[wait_reason];
                if(coordinator_fence_clock.valid && !producer_done)local.coordinator_fence_wait_ns[wait_reason]+=waited;
                if(notified)++local.coordinator_notified_wakes;else ++local.coordinator_timeout_wakes;
            }
        }
        local.coordinator_source_done_to_drained=ThreadPhaseBetween(
            coordinator_source_done_clock,ReadThreadPhaseStamp());
    } catch (const std::exception &exception) {
        failed = true;
        failure = std::string("native service exception: ") + exception.what();
    } catch (...) {
        failed = true;
        failure = "native service raised a non-standard exception";
    }

    /* The routing loop exits successfully only after producer EOF, every
     * inference completion, the ordered durable prefix, and every source ACK
     * have closed.  Release the formal SHM consumer claim at that semantic
     * completion point.  Worker/committer thread teardown and receipt metric
     * collection below are administrative closure; keeping the consumer
     * claim across that work needlessly serialized the producer's terminal
     * transport gate behind service cleanup.  The source adapter retains an
     * immutable post-close snapshot, so all final evidence checks below are
     * unchanged. */
    // These maps are coordinator-owned and immutable after the successful
    // routing loop drains. Perform the same checks while the bounded selected
    // writer drains, and apply their outcome at the original final-check site.
    uint64_t flow_open_only_event_terminals=0,covered_flow_opens=0,covered_flow_continues=0;
    bool closure_scanned=false,closure_overflow=false,active_semantic_generations_valid=false;
    const auto scan_closure=[&] {
    for (const auto &entry : event_coverage) {
        if (entry.second.flow_opens >
                UINT64_MAX - covered_flow_opens ||
            entry.second.flow_continues >
                UINT64_MAX - covered_flow_continues) {
            closure_overflow = true;
            break;
        }
        covered_flow_opens += entry.second.flow_opens;
        covered_flow_continues += entry.second.flow_continues;
        if (entry.second.flow_opens != 0u &&
            entry.second.checkpoints == 0u) {
            ++flow_open_only_event_terminals;
        }
    }
    active_semantic_generations_valid = std::all_of(
        active_semantic_generations.begin(),
        active_semantic_generations.end(),
        [&flow_coverage](const auto &entry) {
            return flow_coverage.find(entry.second) != flow_coverage.end();
        });
        closure_scanned=true;
    };
    const char *overlap_closure=std::getenv("FK_OVERLAP_FINAL_VALIDATION");
    if(overlap_closure && std::strcmp(overlap_closure,"1")==0 && !failed && producer_done &&
       inflight==0u && !commit_in_progress && reordered_count==0u)scan_closure();
    bool source_close_attempted = false;
    if (!failed && producer_done && inflight == 0u &&
            !commit_in_progress && reordered_count == 0u) {
        source_close_attempted = true;
        std::string early_close_error;
        if (!source->Close(&early_close_error)) {
            failed = true;
            ++local.source_failures;
            if (failure.empty()) {
                failure = early_close_error.empty() ?
                    "source close failed" : early_close_error;
            }
        }
    }

    for (const std::unique_ptr<Worker> &worker : workers)
        worker->Close();
    for (const std::unique_ptr<Worker> &worker : workers)
        worker->Join();
    try {
        local.worker_metrics.reserve(workers.size());
        for (const std::unique_ptr<Worker> &worker : workers) {
            const NativeFusionWorkerMetrics metrics = worker->Snapshot();
            local.batch_trigger_capacity += metrics.batch_trigger_capacity;
            local.batch_trigger_wait_timeout +=
                metrics.batch_trigger_wait_timeout;
            local.batch_trigger_deadline_guard +=
                metrics.batch_trigger_deadline_guard;
            local.batch_trigger_close += metrics.batch_trigger_close;
            local.batch_trigger_input_fence += metrics.batch_trigger_input_fence;
            local.worker_metrics.push_back(metrics);
        }
        local.worker_affinity_plan_attested = affinity_requested &&
            local.worker_metrics.size() == config.worker_count &&
            std::all_of(local.worker_metrics.begin(),
                local.worker_metrics.end(),
                [](const NativeFusionWorkerMetrics &metrics) {
                    return metrics.affinity_requested == 1u &&
                        metrics.affinity_attested == 1u &&
                        metrics.affinity_cpu_count != 0u;
                }) ? 1u : 0u;
    } catch (...) {
        failed = true;
        local.worker_metrics.clear();
        if (failure.empty())
            failure = "failed to collect native worker metrics";
    }

    /* Account work that completed while another terminal failure unwound. */
    std::deque<Completion> terminal_scores;
    {
        std::lock_guard<std::mutex> lock(completions.mutex);
        terminal_scores.swap(completions.queue);
    }
    while (!terminal_scores.empty()) {
        Completion completion = std::move(terminal_scores.front());
        terminal_scores.pop_front();
        if (!completion.success) {
            if (completion.error.find("result identity/ABI") !=
                    std::string::npos) {
                ++local.result_validation_failures;
            } else {
                ++local.scorer_failures;
            }
            continue;
        }
        if (completion.scorer_output) {
            ++local.scorer_batches;
            local.requests_scored += completion.decisions.size();
        }
        for (const NativeFusionDecision &decision : completion.decisions) {
            if (!(decision.physical_enqueue_monotonic_ns <=
                      decision.consumer_receive_monotonic_ns &&
                  decision.consumer_receive_monotonic_ns <=
                      decision.inference_start_monotonic_ns &&
                  decision.inference_start_monotonic_ns <=
                      decision.decision_monotonic_ns)) {
                ++local.timestamp_failures;
                continue;
            }
            const uint64_t queue_wait =
                decision.consumer_receive_monotonic_ns -
                decision.physical_enqueue_monotonic_ns;
            const uint64_t end_to_end =
                decision.decision_monotonic_ns -
                decision.physical_enqueue_monotonic_ns;
            local.maximum_queue_wait_ns = std::max(
                local.maximum_queue_wait_ns, queue_wait);
            local.maximum_end_to_end_ns = std::max(
                local.maximum_end_to_end_ns, end_to_end);
            observe_deadline_miss(
                decision, config.detector_deadline_ns, &local);
        }
    }

    if (durable_worker_started) {
        durable_worker.Close();
        durable_worker.Join();
        DurableCompletion terminal_commit{};
        while (durable_worker.Take(&terminal_commit)) {
            process_durable_completion(
                std::move(terminal_commit), !failed);
        }
        if (commit_in_progress) {
            failed = true;
            ++local.commit_failures;
            ++local.durable_commit_failed_calls;
            commit_in_progress = false;
            if (failure.empty())
                failure = "durable commit worker ended without completion";
        }
    }
    if (local.first_durable_commit_submit_monotonic_ns != 0u &&
        local.last_durable_commit_completion_monotonic_ns >=
            local.first_durable_commit_submit_monotonic_ns) {
        local.durable_commit_active_span_ns =
            local.last_durable_commit_completion_monotonic_ns -
            local.first_durable_commit_submit_monotonic_ns;
    }
    local.committer_affinity_attested = affinity_requested &&
        durable_worker.affinity_attested() ? 1u : 0u;
    local.drain_preparation_overlap=committer->SupportsDrainPreparationOverlap();
    local.drain_preparation_batches=durable_worker.drain_batches();
    local.drain_preparation_idle_attested=durable_worker.drain_idle_attested();

    std::string close_error;
    if (!source_close_attempted && !source->Close(&close_error)) {
        failed = true;
        ++local.source_failures;
        if (failure.empty())
            failure = close_error.empty() ? "source close failed" : close_error;
    }
    std::string snapshot_error;
    if (!source_snapshot_consistent(
            source, &local.final_source, &snapshot_error)) {
        failed = true;
        ++local.source_failures;
        if (failure.empty())
            failure = snapshot_error.empty() ?
                "final source snapshot failed" : snapshot_error;
    }

    local.requests_unacked_replayable =
        local.requests_peeked - local.requests_acked;
    local.producer_done = local.final_source.producer_done == 1u ? 1u : 0u;
    local.source_clean = source_snapshot_clean(local.final_source) ? 1u : 0u;
    local.production_durability_attested =
        local.durable_commit_calls != 0u && all_commits_production_durable &&
        local.durable_commit_calls == local.fsync_attested_commit_calls + local.sync_wal_attested_commit_calls ? 1u : 0u;
    local.durable_sequence_equals_acked_sequence =
        local.last_persisted_sequence == local.last_acked_sequence &&
        local.requests_persisted == local.requests_acked ? 1u : 0u;
    const auto close_flow_state_map = [](const auto &map,
            NativeFusionFlowStateMapMetrics *metrics) {
        metrics->terminal_entries = map.size();
        metrics->terminal_bucket_count = map.bucket_count();
        metrics->peak_entries = std::max<uint64_t>(
            metrics->peak_entries, map.size());
    };
    close_flow_state_map(stable_flow_routes,
        &local.stable_flow_routes_map);
    close_flow_state_map(flow_coverage, &local.flow_coverage_map);
    close_flow_state_map(active_semantic_generations,
        &local.active_semantic_generations_map);
    close_flow_state_map(event_coverage, &local.event_coverage_map);
    const bool flow_state_no_runtime_rehash =
        local.flow_state_runtime_rehashes == 0u &&
        local.stable_flow_routes_map.post_reserve_bucket_count ==
            local.stable_flow_routes_map.terminal_bucket_count &&
        local.flow_coverage_map.post_reserve_bucket_count ==
            local.flow_coverage_map.terminal_bucket_count &&
        local.active_semantic_generations_map.post_reserve_bucket_count ==
            local.active_semantic_generations_map.terminal_bucket_count &&
        local.event_coverage_map.post_reserve_bucket_count ==
            local.event_coverage_map.terminal_bucket_count;
    const bool flow_state_capacity_closed =
        local.flow_state_capacity_failures == 0u &&
        local.stable_flow_routes_map.peak_entries <= flow_state_capacity &&
        local.flow_coverage_map.peak_entries <= flow_state_capacity &&
        local.active_semantic_generations_map.peak_entries <=
            flow_state_capacity &&
        local.event_coverage_map.peak_entries <= flow_state_capacity;
    local.flow_state_no_runtime_rehash =
        flow_state_no_runtime_rehash ? 1u : 0u;
    local.flow_state_capacity_closed =
        flow_state_capacity_closed ? 1u : 0u;
    const bool route_cache_closed =
        local.route_cache_hits <=
            UINT64_MAX - local.route_cache_misses &&
        local.route_cache_hits + local.route_cache_misses ==
            local.route_bindings_validated &&
        local.route_bindings_validated == local.requests_routed &&
        local.route_cache_misses == local.frozen_flow_routes &&
        local.frozen_flow_routes == stable_flow_routes.size();
    if(!closure_scanned)scan_closure();
    if(closure_overflow) {
        failed=true;
        if(failure.empty())failure="flow-control event coverage counter overflowed";
    }
    local.flow_open_only_event_terminals =
        flow_open_only_event_terminals;
    const bool flow_control_count_valid =
        local.flow_open_records <=
            UINT64_MAX - local.flow_continue_records;
    const uint64_t flow_control_records = flow_control_count_valid
        ? local.flow_open_records + local.flow_continue_records : 0u;
    const bool resident_flow_generation_count_valid =
        local.superseded_generation_retirements <=
            UINT64_MAX - static_cast<uint64_t>(flow_coverage.size());
    const uint64_t accounted_flow_generations =
        resident_flow_generation_count_valid
        ? local.superseded_generation_retirements +
            static_cast<uint64_t>(flow_coverage.size())
        : 0u;
    const bool flow_open_coverage_closed = !config.require_flow_open ||
        (covered_flow_opens == local.flow_open_records &&
         covered_flow_continues == local.flow_continue_records &&
         flow_control_count_valid &&
         resident_flow_generation_count_valid &&
         accounted_flow_generations == flow_control_records &&
         !active_semantic_generations.empty() &&
         flow_coverage.size() >= active_semantic_generations.size() &&
         active_semantic_generations_valid &&
         local.capacity_continuation_rebindings ==
             local.flow_continue_records &&
         local.flow_open_records != 0u);
    local.flow_open_coverage_closed =
        flow_open_coverage_closed ? 1u : 0u;
    const bool affinity_closed = !affinity_requested ||
        (local.coordinator_affinity_attested == 1u &&
         local.committer_affinity_attested == 1u &&
         local.worker_affinity_plan_attested == 1u);
    const bool durable_trigger_count_valid =
        local.durable_commit_trigger_capacity <=
            UINT64_MAX - local.durable_commit_trigger_terminal &&
        local.durable_commit_trigger_capacity +
                local.durable_commit_trigger_terminal <=
            UINT64_MAX - local.durable_commit_trigger_max_wait;
    const uint64_t durable_trigger_count = durable_trigger_count_valid ?
        local.durable_commit_trigger_capacity +
            local.durable_commit_trigger_terminal +
            local.durable_commit_trigger_max_wait : 0u;
    const bool durable_call_count_valid =
        local.durable_commit_calls <=
            UINT64_MAX - local.durable_commit_failed_calls;
    const uint64_t durable_call_count = durable_call_count_valid ?
        local.durable_commit_calls +
            local.durable_commit_failed_calls : 0u;
    const bool durable_metrics_closed =
        local.durable_commit_trigger_quiescent_feedback <= local.durable_commit_trigger_terminal &&
        local.durable_commit_trigger_drain_wait <= local.durable_commit_trigger_max_wait &&
        durable_trigger_count_valid && durable_call_count_valid &&
        local.durable_commit_submissions == durable_trigger_count &&
        local.durable_commit_submissions == durable_call_count &&
        local.durable_commit_failed_calls == 0u &&
        local.durable_commit_submissions == local.ack_calls &&
        local.minimum_durable_commit_batch_rows != 0u &&
        local.minimum_durable_commit_batch_rows <=
            local.maximum_durable_commit_batch_rows &&
        local.maximum_durable_commit_batch_rows <=
            local.durable_commit_batch_capacity &&
        local.first_durable_commit_submit_monotonic_ns != 0u &&
        local.last_durable_commit_completion_monotonic_ns >=
            local.first_durable_commit_submit_monotonic_ns &&
        contiguous_ready_count == 0u && reordered_count == 0u &&
        inflight == 0u;
    local.completed = !failed && producer_done &&
        flow_control_count_valid &&
        flow_control_records <= UINT64_MAX - local.checkpoint_records &&
        local.requests_peeked ==
            flow_control_records + local.checkpoint_records &&
        local.checkpoint_records == local.requests_scored &&
        (config.flow_open_scorer == nullptr
            ? local.flow_open_records_scored == 0u
            : local.flow_open_records_scored == local.flow_open_records) &&
        local.requests_peeked == local.requests_persisted &&
        local.requests_persisted == local.requests_acked &&
        route_cache_closed &&
        flow_open_coverage_closed &&
        flow_state_no_runtime_rehash &&
        flow_state_capacity_closed &&
        affinity_closed &&
        durable_metrics_closed &&
        local.requests_unacked_replayable == 0u &&
        local.last_persisted_sequence == local.last_acked_sequence &&
        local.source_clean == 1u ? 1u : 0u;
    local.production_service_ready = local.completed == 1u &&
        local.production_durability_attested == 1u &&
        local.durable_sequence_equals_acked_sequence == 1u &&
        local.durable_commit_max_wait_ns != 0u ? 1u : 0u;
    local.paged_reorder=reordered.Paged();
    local.reorder_peak_payload_bytes=reordered.PeakPayloadBytes();
    local.reorder_allocated_bytes_at_end=reordered.AllocatedBytes();
    local.reorder_page_reuses=reordered.PageReuses();
    local.stopped_monotonic_ns = monotonic_ns();
    if (local.stopped_monotonic_ns < local.started_monotonic_ns) {
        failed = true;
        local.completed = 0u;
        local.production_service_ready = 0u;
        if (failure.empty())
            failure = "service monotonic clock regressed";
    }
    *receipt = local;
    if (failed || local.completed == 0u) {
        set_error(error, failure.empty() ?
            "native fusion service did not close cleanly" : failure);
        return false;
    }
    return true;
}

}  // namespace flowkeep
