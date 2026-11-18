#ifndef FK_FINAL_SCORED_EVIDENCE_SELECTOR_H
#define FK_FINAL_SCORED_EVIDENCE_SELECTOR_H
#include "fk_selected_evidence_observer.h"
#include "fk_selected_evidence_store.h"
#include "fk_prefix_version_store.h"
#include "fk_evidence_gain_feedback.h"
#include <memory>
#include <algorithm>
#include <array>
#include <mutex>
#include <condition_variable>
#include <thread>
#include <deque>
#include <unordered_map>
#include <unordered_set>

namespace flowkeep {
// Common B/C selection path. The oracle is the request actually delivered to
// the scorer; the persisted copy is independently fetched by exact packet.
// A semantic flow with only inherited/synthetic results has no actual target.
class FinalScoredEvidenceSelector final : public SelectedEvidenceObserver {
public:
    FinalScoredEvidenceSelector(std::shared_ptr<PrefixVersionStore>,
        std::shared_ptr<EvidenceGainChannel>, std::shared_ptr<SelectedEvidenceStore>,
        size_t flow_capacity, size_t pending_capacity);
    ~FinalScoredEvidenceSelector() override;
    bool Issued(const fk_detector_request_v1 &, uint64_t, uint64_t,
                std::string *) noexcept override;
    bool UsesBoundIssueRequests() const noexcept override {return bound_issue_;}
    bool IssuedBound(const fk_detector_request_v1 &,uint64_t,uint64_t,
        const PrefixVersionStore::ReadHandle &,std::string *) noexcept override;
    bool Scored(uint64_t, bool, double, std::string *) noexcept override;
    bool Durable(const NativeFusionDecision &, std::string *) noexcept override;
    bool Finalize(const fk_flow_key &, uint64_t, uint64_t, uint64_t,
                  std::string *) noexcept override;
    bool FinalizeAdmissionReady() const noexcept override;
    bool UsesBoundFinalizationRequests() const noexcept override {return final_queue_binding_;}
    bool SupportsFinalizeBatch() const noexcept override {return batch_finalization_;}
    size_t FinalizeBatchAdmission(size_t maximum) const noexcept override;
    bool FinalizeBatch(const SelectedFinalizationRequest *,size_t,std::string *) noexcept override;
    bool Finish(std::string *) noexcept override;
    bool Verify(std::string *) noexcept;
    std::string ReceiptJson() const;
private:
    struct Flow { uint64_t last_candidate=0,pending=0; bool has_actual=false,finalizing=false,finalization_queued=false; SelectedEvidenceRecord last_actual{}; PrefixVersionStore::ReadHandle version_handle; };
    // Map nodes survive rehash. A Flow cannot be erased while pending!=0;
    // all Pending->Flow accesses and finalization use the same selector mutex.
    // The request binding therefore carries its exact selection owner through
    // scoring and durable join without rebuilding a serialized identity key.
    struct Pending { SelectedEvidenceRecord record{}; bool attested=false,actual=false; double score=0; Flow *owner=nullptr; };
    bool bound_handoff_=true,final_owner_handoff_=false,final_version_handoff_=false;
    bool batch_finalization_=false;
    bool split_selection_=false,final_queue_binding_=false;
    bool bound_issue_=false,pending_inplace_=false;
    uint64_t source_issue_bindings_=0,issue_directory_resolves_=0,pending_inplace_records_=0;
    bool IssuedImpl(const fk_detector_request_v1 &,uint64_t,uint64_t,
        const PrefixVersionStore::ReadHandle *,std::string *) noexcept;
    uint64_t final_queue_source_bindings_=0,final_queue_fallback_resolves_=0,final_queue_worker_bindings_=0;
    bool async_selection_=false,selection_stopping_=false,selection_ready_=false;
    size_t selection_outstanding_=0,selection_peak_=0;
    uint64_t selection_enqueued_=0,selection_completed_=0,selection_work_cpu_ns_=0,selection_work_wall_ns_=0;
    int selection_cpu_=-1,selection_requested_cpu_=-1;
    std::deque<SelectedFinalizationRequest> selection_queue_;
    std::condition_variable selection_ready_cv_,selection_space_cv_;
    std::thread selection_thread_;
    std::mutex selection_finish_mutex_;
    void SelectionLoop() noexcept;
    void JoinSelection() noexcept;
    bool EnqueueFinal(const SelectedFinalizationRequest*,size_t,std::string*) noexcept;
    bool FinalizeNow(const fk_flow_key&,uint64_t,uint64_t,uint64_t,bool,std::string*) noexcept;
    bool FinalizeBatchNow(const SelectedFinalizationRequest*,size_t,bool,std::string*) noexcept;

    uint64_t finalize_batch_calls_=0,finalize_batch_rows_=0,finalize_batch_max_=0;
    struct PreparedFinal {
        SelectedEvidenceRecord expected{},actual{};
        std::string identity;
        PrefixVersionStore::ReadHandle binding;
        uint32_t directory_slot=0;
        bool has_actual=false,payload_deferred=false;
        Flow *owner=nullptr;
    };
    // Both scalar and batched paths call these identical checks while holding
    // mutex_. Queue waits always happen outside the scorer attestation mutex.
    bool PrepareFinalLocked(const SelectedFinalizationRequest &,PreparedFinal &,bool,std::string *);
    bool PrepareFinalPayload(PreparedFinal &,bool,std::string *);
    bool CompleteFinalLocked(PreparedFinal &,std::string *);

    // Version identity entries are immutable and never reused within the run.
    // Reuse that identity directory for the selection lifecycle. Payload slots
    // may recycle independently; no raw FlowTable slot indexes this state.
    std::vector<std::unique_ptr<Flow>> directory_flows_;
    std::vector<uint8_t> directory_finalized_;
    size_t directory_active_=0;
    uint64_t directory_owner_joins_=0,directory_finalizations_=0;
    uint64_t bound_owner_joins_=0,independent_owner_lookups_=0,cached_version_lookups_=0;
    std::shared_ptr<PrefixVersionStore> versions_;
    std::shared_ptr<EvidenceGainChannel> gains_;
    std::shared_ptr<SelectedEvidenceStore> store_;
    size_t flow_capacity_,pending_capacity_;
    mutable std::mutex mutex_;
    std::unordered_map<uint64_t,Pending> pending_;
    std::unordered_map<std::string,Flow> flows_;
    std::unordered_set<std::string> finalized_;
    std::vector<SelectedEvidenceRecord> expected_;
    uint64_t issued_=0,attested_=0,actual_=0,synthetic_=0,durable_=0,finalized_count_=0;
    uint64_t zero_actual_=0,history_exact_=0,feedback_exact_=0,feedback_unknown_=0;
    size_t peak_pending_=0,peak_flows_=0;
    bool failed_=false,finished_=false,verified_=false;
    std::string failure_;
    bool Fail(std::string *,const std::string &) noexcept;
    static std::string Identity(const fk_flow_key &,uint64_t,uint64_t);
};
}
#endif
