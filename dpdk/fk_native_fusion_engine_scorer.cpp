#include "fk_native_fusion_engine_scorer.h"
#include "fk_selected_evidence_observer.h"
#include "fk_target_demand_audit.h"
#include "fk_portable_hgb.h"

#include <algorithm>
#include <array>
#include <chrono>
#include <cmath>
#include <cstring>
#include <map>
#include <mutex>
#include <stdexcept>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace flowkeep {

uint32_t NativeFusionActiveEngineThreads(
        uint32_t configured_threads,
        size_t request_count) noexcept {
    if (configured_threads == 0u || request_count == 0u)
        return 0u;
    return static_cast<uint32_t>(std::min<size_t>(
        configured_threads, request_count));
}

NativeFusionEngineScorer::NativeFusionEngineScorer(
        fk_native_fusion_session *session,
        uint32_t engine_threads) noexcept
    : session_(session), engine_threads_(engine_threads) {}

bool NativeFusionEngineScorer::ScoreBatchWithContext(
        const fk_native_fusion_request *requests, size_t count,
        const NativeEventContext *contexts, fk_native_fusion_result *results,
        std::string *error) noexcept {
    const auto now=[]()->uint64_t{return std::chrono::duration_cast<std::chrono::nanoseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();};
    const uint64_t start=now();
    if (context_sink_) {
        if (!requests || !contexts || !count) return false;
        for (size_t i=0;i<count;++i)
            if (requests[i].sequence!=contexts[i].sequence ||
                requests[i].event_token!=contexts[i].event_token) return false;
        if (!context_sink_->PrepareContext(contexts,count,error)) return false;
    }
    context_prepare_ns+=now()-start;
    const bool ok=ScoreBatch(requests,count,results,error);
    const uint64_t clear_start=now();
    if (context_sink_) context_sink_->ClearContext();
    context_clear_ns+=now()-clear_start;
    return ok;
}

bool NativeFusionEngineScorer::valid() const noexcept {
    return session_ != nullptr && engine_threads_ != 0u;
}

uint32_t NativeFusionEngineScorer::engine_threads() const noexcept {
    return engine_threads_;
}

bool NativeFusionEngineScorer::ScoreBatch(
        const fk_native_fusion_request *requests,
        size_t request_count,
        fk_native_fusion_result *results,
        std::string *error) noexcept {
    if (error != nullptr)
        error->clear();
    if (!valid() || requests == nullptr || request_count == 0u ||
        results == nullptr) {
        if (error != nullptr)
            *error = "native fusion engine scorer arguments are invalid";
        return false;
    }
    if (context_sink_ && !context_sink_->HistoryResetRows()) {
        if (error) *error="persistent scoring requires prepared event context";
        return false;
    }
    std::array<char, 1024u> native_error{};
    const uint32_t active_threads = NativeFusionActiveEngineThreads(
        request_count < 16u ? 1u : engine_threads_, request_count);
    if (!fk_native_fusion_score_batch_with_resets(session_, requests, request_count,
            active_threads, context_sink_ ? context_sink_->HistoryResetRows() : nullptr, results, native_error.data(),
            native_error.size())) {
        if (error != nullptr) {
            *error = native_error[0] == '\0' ?
                "native fusion engine rejected the batch" :
                std::string(native_error.data());
        }
        return false;
    }
    return true;
}

namespace {

struct AdaptiveFlowKey {
    std::array<uint8_t, sizeof(fk_flow_key)> key{};
    uint64_t first_timestamp_ns = 0u;
    uint64_t logical_connection_id = 0u;
    bool operator==(const AdaptiveFlowKey &other) const noexcept {
        return key == other.key &&
            first_timestamp_ns == other.first_timestamp_ns &&
            logical_connection_id == other.logical_connection_id;
    }
};

struct AdaptiveFlowKeyHash {
    size_t operator()(const AdaptiveFlowKey &key) const noexcept {
        uint64_t hash = UINT64_C(14695981039346656037);
        for (uint8_t byte : key.key) {
            hash ^= byte;
            hash *= UINT64_C(1099511628211);
        }
        hash ^= key.first_timestamp_ns;
        hash *= UINT64_C(1099511628211);
        hash ^= key.logical_connection_id;
        return static_cast<size_t>(hash);
    }
};

AdaptiveFlowKey adaptive_flow_key(const NativeEventContext &context) {
    AdaptiveFlowKey result{};
    std::memcpy(result.key.data(), &context.canonical_key,
                sizeof(context.canonical_key));
    result.first_timestamp_ns = context.flow_first_timestamp_ns;
    result.logical_connection_id = context.logical_connection_id;
    return result;
}

}  // namespace

struct AdaptiveCheckpointEngineScorer::Implementation {
    struct FlowState {
        uint8_t calls = 0u;
        uint8_t last_packet = 0u;
        double last_score = 0.0;
        bool has_score = false;
        fk_marginal_checkpoint_state marginal{};
        uint32_t gain_anchor_packet = 0u;
        uint8_t gain_source_mask = 0u;
        bool feedback_published = false;
        uint8_t published_calls = 0u, published_pending = 0u, published_stopped = 0u;
    };
    struct EventState {
        double last_score = 0.0;
        bool has_score = false;
        bool alert_latched = false;
    };

    Implementation(fk_native_fusion_session *session,
                   uint32_t engine_threads,
                   const AdaptiveCheckpointScorerConfig &configuration)
        : engine(session, engine_threads), config(configuration) {
        frontier_ready = !config.event_frontier_batching ||
            fk_native_fusion_session_enable_event_frontiers(session);
        if (config.marginal_enabled) {
            std::array<char, 256u> error{};
            action_risk = fk_portable_hgb_load(
                config.action_risk_model_path.c_str(), 34u,
                error.data(), error.size());
        }
    }

    ~Implementation() { fk_portable_hgb_destroy(action_risk); }

    void publish_gain(FlowState &flow,const fk_native_fusion_request &request,
                      const NativeEventContext &context) const {
        if(!config.evidence_feedback)return;
        // Synthetic carrier rows do not change the forecast. Do not spend a
        // cross-process cache write on every packet of an unchanged decision.
        if(flow.feedback_published && flow.published_calls==flow.marginal.calls &&
           flow.published_pending==flow.marginal.pending_packet &&
           flow.published_stopped==flow.marginal.stopped)return;
        EvidenceGainFeedback value{};
        value.key=context.canonical_key;
        value.first_timestamp_ns=context.flow_first_timestamp_ns;
        value.logical_connection_id=context.logical_connection_id;
        value.sequence=context.sequence;
        value.evidence_packet=flow.gain_anchor_packet ? flow.gain_anchor_packet : context.checkpoint_packet;
        value.next_packet=flow.marginal.pending_packet;
        value.required_mask=flow.gain_anchor_packet ? flow.gain_source_mask : request.source_mask;
        value.stopped=flow.marginal.stopped;
        value.gain=value.stopped?0.0:flow.marginal.predicted_evidence_gain;
        value.net_utility=value.stopped?0.0:flow.marginal.predicted_net_utility;
        if(config.evidence_feedback->Publish(value)) {
            flow.feedback_published=true;
            flow.published_calls=flow.marginal.calls;
            flow.published_pending=flow.marginal.pending_packet;
            flow.published_stopped=flow.marginal.stopped;
        }
    }

    bool risk(const fk_native_fusion_request &request,
              const NativeEventContext &context, double *output) const {
        if (action_risk == nullptr || output == nullptr)
            return false;
        double features[34]{};
        for (size_t index = 0u; index < 30u; ++index)
            features[index] = request.features[index];
        features[30] = (request.source_mask & 1u) != 0u ? 1.0 : 0.0;
        features[31] = (request.source_mask & 2u) != 0u ? 1.0 : 0.0;
        features[32] = (request.source_mask & 4u) != 0u ? 1.0 : 0.0;
        features[33] = static_cast<double>(context.checkpoint_packet) /
            static_cast<double>(config.marginal.horizon_packet);
        return fk_portable_hgb_predict(
            action_risk, features, 34u, output);
    }

    bool marginal_due(FlowState &flow,
                      const fk_native_fusion_request &request,
                      const NativeEventContext &context,
                      double *risk_value) const {
        const uint32_t packet = context.checkpoint_packet;
        const bool eof = (context.request_flags &
            FK_DETECTOR_REQUEST_FLAG_COVERAGE_TERMINAL) != 0u;
        if (eof) {
            flow.gain_anchor_packet=packet;
            flow.gain_source_mask=request.source_mask;
            fk_marginal_checkpoint_action action{};
            return packet <= UINT8_MAX &&
                fk_marginal_checkpoint_eof(
                    &flow.marginal, static_cast<uint8_t>(packet), &action) &&
                action.kind == FK_MARGINAL_ACTION_CHECK_EOF;
        }
        if (packet == 0u || packet > config.marginal.horizon_packet ||
            flow.marginal.stopped != 0u)
            return false;
        if (flow.marginal.pending_packet == 0u &&
            flow.marginal.calls == 0u && flow.marginal.stopped == 0u) {
            flow.gain_anchor_packet=packet;
            flow.gain_source_mask=request.source_mask;
            if (config.fixed_checkpoint_control) {
                flow.marginal.pending_packet = config.fixed_points.front();
                return packet >= flow.marginal.pending_packet;
            }
            fk_native_fusion_request admission=request;
            NativeEventContext admission_context=context;
            if(config.prefix_versions) {
                PrefixVersionStore::Prefix prefix{};
                if(!config.prefix_versions->Lookup({context.canonical_key,
                    context.flow_first_timestamp_ns,context.logical_connection_id},1,&prefix))
                    throw std::runtime_error("selected observation lacks immutable packet-one evidence");
                std::copy(prefix.evidence.features.begin(),prefix.evidence.features.end(),std::begin(admission.features));
                admission.source_mask=prefix.evidence.mask;admission_context.checkpoint_packet=1;
                flow.gain_anchor_packet=1;flow.gain_source_mask=prefix.evidence.mask;
            }
            if (!risk(admission, admission_context, risk_value))
                throw std::runtime_error("initial checkpoint risk prediction failed");
            if (config.trained_policy) {
                config.trained_policy->Plan(flow.marginal, *risk_value);
                if(config.prefix_versions && config.prefix_versions->FirstNext({context.canonical_key,
                    context.flow_first_timestamp_ns,context.logical_connection_id})!=flow.marginal.pending_packet)
                    throw std::runtime_error("RX/scorer trained initial checkpoint differs");
                return packet >= flow.marginal.pending_packet;
            }
            fk_marginal_checkpoint_action action{};
            if (!fk_marginal_checkpoint_plan_first(
                    &config.marginal, &flow.marginal, *risk_value,
                    1.0, false, &action) ||
                action.kind != FK_MARGINAL_ACTION_NEXT)
                return false;
            if(config.prefix_versions && config.prefix_versions->FirstNext({context.canonical_key,
                context.flow_first_timestamp_ns,context.logical_connection_id})!=flow.marginal.pending_packet)
                throw std::runtime_error("RX/scorer initial selected checkpoint differs");
        }
        return flow.marginal.stopped == 0u &&
            flow.marginal.pending_packet != 0u &&
            packet >= flow.marginal.pending_packet;
    }

    bool observe(FlowState &flow, uint8_t packet, double score) const {
        if (config.fixed_checkpoint_control) {
            ++flow.marginal.calls;
            flow.marginal.last_observation_packet = packet;
            flow.marginal.pending_packet = 0u;
            if (score < config.threshold) {
                for (uint8_t next : config.fixed_points) {
                    if (next > packet) {
                        flow.marginal.pending_packet = next;
                        break;
                    }
                }
            }
            flow.marginal.stopped = flow.marginal.pending_packet == 0u;
            return true;
        }
        if (config.trained_policy)
            return config.trained_policy->Observe(flow.marginal, packet, score);
        fk_marginal_checkpoint_action action{};
        return fk_marginal_checkpoint_observe(&config.marginal,
            &flow.marginal, packet, score, 1.0, false, &action);
    }

    bool due(const FlowState &flow, const NativeEventContext &context) const {
        const uint32_t packet = context.checkpoint_packet;
        const bool eof =
            (context.request_flags &
             FK_DETECTOR_REQUEST_FLAG_COVERAGE_TERMINAL) != 0u;
        if (eof)
            return flow.calls == 0u && packet == 1u;
        if (packet < config.first_packet ||
            packet > config.horizon_packet)
            return false;
        if (flow.calls == 0u)
            return packet == config.first_packet;
        if (packet == config.horizon_packet)
            return flow.calls < 5u;
        if (flow.calls >= 4u || !flow.has_score)
            return false;
        const uint32_t gap = flow.last_score >=
                config.watch_ratio * config.threshold
            ? config.near_gap : config.far_gap;
        return packet >= static_cast<uint32_t>(flow.last_packet) + gap;
    }

    NativeFusionEngineScorer engine;
    bool frontier_ready = false;
    uint64_t last_candidate_sequence = 0;
    AdaptiveCheckpointScorerConfig config;
    fk_portable_hgb *action_risk = nullptr;
    std::unordered_map<AdaptiveFlowKey, FlowState,
        AdaptiveFlowKeyHash> flows;
    std::unordered_map<uint64_t, EventState> events;
    /* Candidate decisions are consecutive in the service ledger, but only
     * real observations submit history.  Translate a candidate fence to the
     * latest real history sequence at or before it. */
    std::mutex history_fence_mutex;
    std::map<uint64_t, uint64_t> history_fences;
    uint64_t latest_actual_sequence = 0u;
    uint64_t candidate_rows = 0u;
    uint64_t actual_model_calls = 0u;
    uint64_t synthetic_rows = 0u;
};

AdaptiveCheckpointEngineScorer::AdaptiveCheckpointEngineScorer(
        fk_native_fusion_session *session,
        uint32_t engine_threads,
        const AdaptiveCheckpointScorerConfig &config)
    : implementation_(new Implementation(session, engine_threads, config)) {}

AdaptiveCheckpointEngineScorer::~AdaptiveCheckpointEngineScorer() = default;

void AdaptiveCheckpointEngineScorer::SetContextSink(
        NativeEventContextSink *sink) noexcept {
    if (implementation_) {
        if (sink && implementation_->config.event_frontier_batching)
            implementation_->frontier_ready = false;
        implementation_->engine.SetContextSink(sink);
    }
}

bool AdaptiveCheckpointEngineScorer::WaitHistoryDurable(
        uint64_t sequence, std::string *error) noexcept {
    if (!implementation_)
        return false;
    uint64_t history_sequence = 0u;
    {
        std::lock_guard<std::mutex> lock(
            implementation_->history_fence_mutex);
        const auto fence = implementation_->history_fences.find(sequence);
        if (fence == implementation_->history_fences.end()) {
            if (error)
                *error = "adaptive decision lacks a history-fence mapping";
            return false;
        }
        history_sequence = fence->second;
    }
    return history_sequence == 0u ||
        implementation_->engine.WaitHistoryDurable(history_sequence, error);
}

bool AdaptiveCheckpointEngineScorer::valid() const noexcept {
    if (!implementation_ || !implementation_->engine.valid() || !implementation_->frontier_ready)
        return false;
    const auto &config = implementation_->config;
    if (config.fixed_checkpoint_control &&
        (config.fixed_points.empty() || config.fixed_points.size() > 4 ||
         config.fixed_points.front() == 0 || config.fixed_points.back() != 20 ||
         std::adjacent_find(config.fixed_points.begin(), config.fixed_points.end(),
             [](uint8_t a, uint8_t b) { return a >= b; }) != config.fixed_points.end()))
        return false;
    if (config.marginal_enabled)
        return implementation_->action_risk != nullptr &&
            fk_marginal_checkpoint_config_valid(&config.marginal) &&
            std::isfinite(config.threshold) && config.threshold >= 0.0 &&
            config.threshold <= 1.0;
    return config.first_packet == 4u && config.near_gap != 0u &&
        config.far_gap != 0u && config.horizon_packet == 20u &&
        std::isfinite(config.watch_ratio) && config.watch_ratio >= 0.0 &&
        config.watch_ratio <= 1.0 && std::isfinite(config.threshold) &&
        config.threshold >= 0.0 && config.threshold <= 1.0;
}

bool AdaptiveCheckpointEngineScorer::ScoreBatch(
        const fk_native_fusion_request *, size_t,
        fk_native_fusion_result *, std::string *error) noexcept {
    if (error)
        *error = "adaptive checkpoint scorer requires request context";
    return false;
}

bool AdaptiveCheckpointEngineScorer::ScoreBatchWithContext(
        const fk_native_fusion_request *requests,
        size_t count,
        const NativeEventContext *contexts,
        fk_native_fusion_result *results,
        std::string *error) noexcept {
    if (error)
        error->clear();
    if (!valid() || !requests || !contexts || !results || count == 0u) {
        if (error)
            *error = "adaptive checkpoint scorer arguments are invalid";
        return false;
    }
    Implementation &state = *implementation_;
    try {
        std::vector<AdaptiveFlowKey> keys(count);
        std::vector<uint8_t> status(count, 0u);  // 1 actual, 2 synthetic
        std::vector<double> marginal_risk(count, 0.0);
        std::vector<fk_native_fusion_result> actual(count);
        std::unordered_map<uint64_t, Implementation::EventState>
            initial_events;
        initial_events.reserve(count);
        for (size_t index = 0u; index < count; ++index) {
            if (requests[index].sequence != contexts[index].sequence ||
                requests[index].sequence <= (index ? requests[index - 1].sequence : state.last_candidate_sequence) ||
                requests[index].event_token != contexts[index].event_token ||
                contexts[index].flow_first_timestamp_ns == 0u ||
                contexts[index].checkpoint_packet == 0u) {
                if (error)
                    *error = "adaptive request/context identity differs";
                return false;
            }
            keys[index] = adaptive_flow_key(contexts[index]);
            initial_events.emplace(contexts[index].event_token,
                state.events[contexts[index].event_token]);
        }
        state.last_candidate_sequence = requests[count - 1].sequence;

        {
            // Submit consecutive prefixes only. A later row of the same
            // event depends on the real score/history of its previous row,
            // even when it belongs to another physical flow generation.
            size_t cursor = 0u;
            std::vector<size_t> selected;
            std::unordered_set<uint64_t> selected_events;
            std::vector<fk_native_fusion_request> inputs;
            std::vector<NativeEventContext> selected_contexts;
            std::vector<fk_native_fusion_result> outputs;
            selected.reserve(count);
            selected_events.reserve(count);
            inputs.reserve(count);
            selected_contexts.reserve(count);
            outputs.reserve(count);
            // One causal cursor per event. Different events are independent;
            // all rows of a shared event (including reused flow generations)
            // remain in source order. Ledger/output order is restored below.
            std::vector<size_t> links(count, count), frontiers;
            if (state.config.event_frontier_batching) {
                std::unordered_map<uint64_t, size_t> tails;
                for (size_t i = 0; i < count; ++i) {
                    auto found = tails.find(contexts[i].event_token);
                    if (found == tails.end()) frontiers.push_back(i);
                    else links[found->second] = i;
                    tails[contexts[i].event_token] = i;
                }
            }
            while (state.config.event_frontier_batching ? !frontiers.empty() : cursor < count) {
                selected.clear();
                selected_events.clear();
                auto examine = [&](size_t index) {
                    const AdaptiveFlowKey &key = keys[index];
                    auto &flow = state.flows[key];
                    auto &event = state.events[contexts[index].event_token];
                    const bool due = !event.alert_latched &&
                        (state.config.marginal_enabled ?
                            state.marginal_due(flow, requests[index],
                                contexts[index], &marginal_risk[index]) :
                            state.due(flow, contexts[index]));
                    if (due) {
                        selected.push_back(index);
                    } else {
                        status[index] = 2u;
                        if(event.alert_latched && !flow.marginal.stopped) {
                            flow.marginal.stopped=1;
                            flow.marginal.pending_packet=0;
                            flow.gain_anchor_packet=contexts[index].checkpoint_packet;
                            flow.gain_source_mask=requests[index].source_mask;
                        }
                        state.publish_gain(flow,requests[index],contexts[index]);
                    }
                    return due;
                };
                if (state.config.event_frontier_batching) {
                    for (size_t &head : frontiers) {
                        while (head < count) {
                            const size_t index = head;
                            head = links[index];
                            if (examine(index)) break;
                        }
                    }
                    frontiers.erase(std::remove(frontiers.begin(), frontiers.end(), count), frontiers.end());
                    std::sort(selected.begin(), selected.end());
                } else {
                    for (; cursor < count; ++cursor) {
                        if (selected_events.count(contexts[cursor].event_token)) break;
                        if (examine(cursor)) selected_events.insert(contexts[cursor].event_token);
                    }
                }
                if (selected.empty())
                    continue;
                inputs.clear();
                selected_contexts.clear();
                outputs.resize(selected.size());
                for (size_t index : selected) {
                    inputs.push_back(requests[index]);
                    selected_contexts.push_back(contexts[index]);
                }
                std::string scorer_error;
                if (!state.engine.ScoreBatchWithContext(
                        inputs.data(), inputs.size(), selected_contexts.data(),
                        outputs.data(), &scorer_error)) {
                    if (error)
                        *error = scorer_error.empty()
                            ? "adaptive seven-head scoring failed" : scorer_error;
                    return false;
                }
                for (size_t offset = 0u; offset < selected.size(); ++offset) {
                    const size_t index = selected[offset];
                    actual[index] = outputs[offset];
                    status[index] = 1u;
                    auto &flow = state.flows[keys[index]];
                    ++flow.calls;
                    flow.last_packet = static_cast<uint8_t>(
                        contexts[index].checkpoint_packet);
                    flow.last_score = outputs[offset].score;
                    flow.has_score = true;
                    flow.gain_anchor_packet=contexts[index].checkpoint_packet;
                    flow.gain_source_mask=requests[index].source_mask;
                    if (state.config.marginal_enabled &&
                        (contexts[index].request_flags &
                         FK_DETECTOR_REQUEST_FLAG_COVERAGE_TERMINAL) == 0u &&
                        !state.observe(flow, flow.last_packet, flow.last_score)) {
                        if (error)
                            *error = "actual-score checkpoint transition failed";
                        return false;
                    }
                    if(state.config.marginal_enabled)
                        TargetDemandAudit::Get().AfterActual(state.config.prefix_versions.get(),
                            {contexts[index].canonical_key,contexts[index].flow_first_timestamp_ns,
                             contexts[index].logical_connection_id},requests[index].sequence,
                            contexts[index].event_token,contexts[index].checkpoint_packet,
                            (contexts[index].request_flags & FK_DETECTOR_REQUEST_FLAG_COVERAGE_TERMINAL)!=0u,
                            flow.marginal,outputs[offset].alert_latched!=0u);
                    auto &event = state.events[contexts[index].event_token];
                    event.last_score = outputs[offset].score;
                    event.has_score = true;
                    event.alert_latched = outputs[offset].alert_latched != 0u;
                    if(event.alert_latched) {
                        flow.marginal.stopped=1;
                        flow.marginal.pending_packet=0;
                    }
                    state.publish_gain(flow,requests[index],contexts[index]);
                }
                state.actual_model_calls += selected.size();
            }
        }

        {
            std::lock_guard<std::mutex> lock(state.history_fence_mutex);
            uint64_t fence = state.latest_actual_sequence;
            for (size_t index = 0u; index < count; ++index) {
                if (status[index] == 1u)
                    fence = requests[index].sequence;
                state.history_fences[requests[index].sequence] = fence;
            }
            state.latest_actual_sequence = fence;
        }

        auto display = std::move(initial_events);
        for (size_t index = 0u; index < count; ++index) {
            auto &event = display[contexts[index].event_token];
            if (status[index] == 1u) {
                results[index] = actual[index];
                event.last_score = actual[index].score;
                event.has_score = true;
                event.alert_latched = actual[index].alert_latched != 0u;
                continue;
            }
            if (status[index] != 2u) {
                if (error)
                    *error = "adaptive row has invalid scheduler status";
                return false;
            }
            results[index] = {};
            results[index].sequence = requests[index].sequence;
            results[index].event_token = requests[index].event_token;
            results[index].score = event.has_score ? event.last_score : 0.0;
            results[index].threshold_met =
                event.has_score &&
                event.last_score >= state.config.threshold ? 1u : 0u;
            results[index].first_alert =
                results[index].threshold_met != 0u && !event.alert_latched
                ? 1u : 0u;
            event.alert_latched = event.alert_latched ||
                results[index].threshold_met != 0u;
            results[index].alert_latched = event.alert_latched ? 1u : 0u;
            ++state.synthetic_rows;
        }
        if (state.config.selected_evidence_observer) {
            for (size_t index = 0u; index < count; ++index)
                if (!state.config.selected_evidence_observer->Scored(
                        requests[index].sequence, status[index] == 1u,
                        results[index].score, error))
                    return false;
        }
        if (state.config.marginal_enabled &&
            state.config.terminal_registry) {
            for (size_t index = 0u; index < count; ++index) {
                auto &flow = state.flows[keys[index]];
                const auto event = state.events.find(
                    contexts[index].event_token);
                if (event != state.events.end() &&
                    event->second.alert_latched) {
                    flow.marginal.pending_packet = 0u;
                    flow.marginal.stopped = 1u;
                }
                state.config.terminal_registry->Publish(
                    contexts[index], flow.marginal);
            }
        }
        state.candidate_rows += count;
        return true;
    } catch (const std::exception &exception) {
        if (error)
            *error = std::string("adaptive checkpoint scorer failed: ") +
                exception.what();
        return false;
    } catch (...) {
        if (error)
            *error = "adaptive checkpoint scorer failed";
        return false;
    }
}

uint64_t AdaptiveCheckpointEngineScorer::CandidateRows() const noexcept {
    return implementation_ ? implementation_->candidate_rows : 0u;
}

uint64_t AdaptiveCheckpointEngineScorer::ActualModelCalls() const noexcept {
    return implementation_ ? implementation_->actual_model_calls : 0u;
}

uint64_t AdaptiveCheckpointEngineScorer::SyntheticRows() const noexcept {
    return implementation_ ? implementation_->synthetic_rows : 0u;
}

bool AdaptiveCheckpointEngineScorer::PhaseProfile(
        fk_native_fusion_phase_profile *profile) const noexcept {
    return implementation_ && implementation_->engine.PhaseProfile(profile);
}

uint64_t AdaptiveCheckpointEngineScorer::ContextPrepareNs() const noexcept {
    return implementation_ ? implementation_->engine.ContextPrepareNs() : 0u;
}

uint64_t AdaptiveCheckpointEngineScorer::ContextClearNs() const noexcept {
    return implementation_ ? implementation_->engine.ContextClearNs() : 0u;
}

}  // namespace flowkeep
