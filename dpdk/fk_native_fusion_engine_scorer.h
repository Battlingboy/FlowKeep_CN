#ifndef FLOWKEEP_FK_NATIVE_FUSION_ENGINE_SCORER_H
#define FLOWKEEP_FK_NATIVE_FUSION_ENGINE_SCORER_H

#include <stdint.h>
#include <memory>
#include <string>

#include "fk_native_fusion_service.h"
#include "fk_marginal_checkpoint_scheduler.h"
#include "fk_adaptive_terminal_registry.h"
#include "fk_evidence_gain_feedback.h"
#include "fk_trained_checkpoint_policy.h"
#include "fk_prefix_version_store.h"

namespace flowkeep {

uint32_t NativeFusionActiveEngineThreads(
    uint32_t configured_threads,
    size_t request_count) noexcept;

/* Thin, non-owning adapter from the service interface to the frozen engine. */
class NativeFusionEngineScorer final : public NativeFusionBatchScorer {
public:
    NativeFusionEngineScorer(
        fk_native_fusion_session *session,
        uint32_t engine_threads) noexcept;

    void SetContextSink(NativeEventContextSink *sink) noexcept { context_sink_=sink; }
    bool WaitHistoryDurable(uint64_t sequence, std::string *error) noexcept override {
        const bool ok=fk_native_fusion_session_wait_history(session_,sequence);
        if(!ok && error)*error="session-bound history fence failed";
        return ok;
    }
    uint64_t context_prepare_ns=0, context_clear_ns=0;
    bool PhaseProfile(fk_native_fusion_phase_profile *p) const noexcept override {
        return fk_native_fusion_session_profile(session_,p);
    }
    uint64_t CandidateRows() const noexcept override {
        fk_native_fusion_phase_profile p{};
        return PhaseProfile(&p) ? p.rows : 0u;
    }
    uint64_t ActualModelCalls() const noexcept override {
        return CandidateRows();
    }
    uint64_t ContextPrepareNs() const noexcept override {
        return context_prepare_ns;
    }
    uint64_t ContextClearNs() const noexcept override {
        return context_clear_ns;
    }
    bool ScoreBatchWithContext(const fk_native_fusion_request *, size_t,
        const NativeEventContext *, fk_native_fusion_result *, std::string *) noexcept override;
    bool valid() const noexcept;
    uint32_t engine_threads() const noexcept;

    bool ScoreBatch(
        const fk_native_fusion_request *requests,
        size_t request_count,
        fk_native_fusion_result *results,
        std::string *error) noexcept override;

private:
    NativeEventContextSink *context_sink_ = nullptr;
    fk_native_fusion_session *session_;
    uint32_t engine_threads_;
};

class SelectedEvidenceObserver;
struct AdaptiveCheckpointScorerConfig {
    uint32_t first_packet = 4u;
    uint32_t near_gap = 0u;
    uint32_t far_gap = 0u;
    uint32_t horizon_packet = 20u;
    double watch_ratio = 0.0;
    double threshold = 0.0;
    /* New production path. When enabled, the legacy first/near/far fields
     * are ignored and every actual model call is selected by the calibrated
     * marginal-evidence scheduler. */
    bool marginal_enabled = false;
    // Matched ablation: same engine, EOF and transport, only fixed score points.
    bool fixed_checkpoint_control = false;
    bool event_frontier_batching = false;
    std::vector<uint8_t> fixed_points{4, 8, 12, 20};
    std::shared_ptr<const TrainedCheckpointPolicy> trained_policy;
    std::string action_risk_model_path;
    fk_marginal_checkpoint_config marginal{};
    std::shared_ptr<AdaptiveTerminalRegistry> terminal_registry;
    std::shared_ptr<EvidenceGainChannel> evidence_feedback;
    std::shared_ptr<PrefixVersionStore> prefix_versions;
    std::shared_ptr<SelectedEvidenceObserver> selected_evidence_observer;
};

/* Online causal scheduler around the frozen seven-head engine. Candidate
 * snapshots may arrive speculatively; only due rows enter the model/history.
 * Non-due rows repeat the latest event score solely to keep the durable input
 * ledger consecutive. ActualModelCalls is the model-compute denominator. */
class AdaptiveCheckpointEngineScorer final : public NativeFusionBatchScorer {
public:
    AdaptiveCheckpointEngineScorer(
        fk_native_fusion_session *session,
        uint32_t engine_threads,
        const AdaptiveCheckpointScorerConfig &config);
    ~AdaptiveCheckpointEngineScorer() override;
    void SetContextSink(NativeEventContextSink *sink) noexcept;
    bool WaitHistoryDurable(uint64_t sequence,
        std::string *error) noexcept override;
    bool ScoreBatchWithContext(const fk_native_fusion_request *, size_t,
        const NativeEventContext *, fk_native_fusion_result *,
        std::string *) noexcept override;
    bool ScoreBatch(const fk_native_fusion_request *, size_t,
        fk_native_fusion_result *, std::string *) noexcept override;
    bool valid() const noexcept;
    uint64_t CandidateRows() const noexcept override;
    uint64_t ActualModelCalls() const noexcept override;
    uint64_t SyntheticRows() const noexcept override;
    bool PhaseProfile(fk_native_fusion_phase_profile *) const noexcept override;
    uint64_t ContextPrepareNs() const noexcept override;
    uint64_t ContextClearNs() const noexcept override;

private:
    struct Implementation;
    std::unique_ptr<Implementation> implementation_;
};

}  // namespace flowkeep

#endif
