#ifndef FLOWKEEP_TRAINED_CHECKPOINT_POLICY_H
#define FLOWKEEP_TRAINED_CHECKPOINT_POLICY_H
#include <algorithm>
#include <array>
#include <cmath>
#include <cstdio>
#include <cstring>
#include <limits>
#include <memory>
#include <vector>
#include "fk_marginal_checkpoint_scheduler.h"

namespace flowkeep {
// Expected reduction of classification errors under the original detector.
// Trained on Train only; prices selected on Validation. V1 retains its old
// horizon fallback. V2 compares signed expected error reduction against STOP
// (zero incremental utility); it is a learned decision, not a no-miss guarantee.
// V3 conditionally exposes packet 1--3 using the already-computed admission
// risk.  This avoids both global candidate pruning and a fixed early score for
// every flow.
// EOF uses the unchanged marginal EOF state machine.
struct TrainedCheckpointPolicy {
    std::array<uint8_t, 32> model_sha{}, action_sha{}, history_meta_sha{};
    bool utility_stop=false;
    double threshold = 0., call_cost = 0., wait_cost = 0.;
    std::vector<uint8_t> candidates;
    std::array<double, 160> first{};
    std::vector<double> successor=std::vector<double>(3360);
    std::vector<double> rescue;
    double stop_risk_budget=1.;
    uint8_t early_gate_max_packet=0;
    uint8_t early_gate_min_admission_bin=0;

    static std::shared_ptr<TrainedCheckpointPolicy> Load(const char *path) {
        FILE *file = std::fopen(path, "rb");
        if (!file) return {};
        auto p = std::make_shared<TrainedCheckpointPolicy>();
        char magic[8]{}; uint8_t n = 0, points[20]{};
        bool ok = std::fread(magic, 1, 8, file) == 8;
        const bool v3=ok && std::memcmp(magic, "FKDCP3\0\0", 8)==0;
        p->utility_stop=v3 || (ok && std::memcmp(magic, "FKDCP2\0\0", 8)==0);
        if(p->utility_stop){p->successor.resize(26880);p->rescue.resize(26880);}
        ok = ok && (p->utility_stop || std::memcmp(magic, "FKDCP1\0\0", 8) == 0) &&
            std::fread(p->model_sha.data(), 1, 32, file) == 32 &&
            std::fread(p->action_sha.data(), 1, 32, file) == 32 &&
            (!p->utility_stop || std::fread(p->history_meta_sha.data(),1,32,file)==32) &&
            std::fread(&p->threshold, sizeof(double), 1, file) == 1 &&
            std::fread(&p->call_cost, sizeof(double), 1, file) == 1 &&
            std::fread(&p->wait_cost, sizeof(double), 1, file) == 1 &&
            std::fread(&n, 1, 1, file) == 1 && n > 0 && n <= 20 &&
            std::fread(points, 1, n, file) == n &&
            std::fread(p->first.data(), sizeof(double), 160, file) == 160 &&
            std::fread(p->successor.data(), sizeof(double), p->successor.size(), file) == p->successor.size() &&
            (!p->utility_stop || (std::fread(&p->stop_risk_budget,sizeof(double),1,file)==1 &&
             (!v3 || (std::fread(&p->early_gate_max_packet,1,1,file)==1 &&
                      std::fread(&p->early_gate_min_admission_bin,1,1,file)==1)) &&
             std::fread(p->rescue.data(),sizeof(double),p->rescue.size(),file)==p->rescue.size())) &&
            std::fgetc(file) == EOF;
        std::fclose(file);
        if (!ok) return {};
        p->candidates.assign(points, points + n);
        if (!std::isfinite(p->threshold) || p->threshold < 0 || p->threshold > 1 ||
            !std::isfinite(p->call_cost) || p->call_cost < 0 ||
            !std::isfinite(p->wait_cost) || p->wait_cost < 0 ||
            p->candidates.front() == 0 || p->candidates.back() != 20 ||
            std::adjacent_find(p->candidates.begin(), p->candidates.end(),
                [](uint8_t a, uint8_t b) { return a >= b; }) != p->candidates.end()) return {};
        for (double v : p->first) if (!std::isfinite(v) || v < -1 || v > 1) return {};
        for (double v : p->successor) if (!std::isfinite(v) || v < -1 || v > 1) return {};
        if(!std::isfinite(p->stop_risk_budget) || p->stop_risk_budget<0 || p->stop_risk_budget>1)return {};
        if(p->early_gate_max_packet>20 || p->early_gate_min_admission_bin>8)return {};
        for(double v:p->rescue)if(!std::isfinite(v) || v<0 || v>1)return {};
        return p;
    }

    void Plan(fk_marginal_checkpoint_state &state, double value) const {
        const unsigned bin = std::min(7u, static_cast<unsigned>(std::max(0., value) * 8));
        const uint8_t packet = state.last_observation_packet;
        if(!packet)state.admission_risk_bin=bin;
        double best = -std::numeric_limits<double>::infinity(), best_gain = 0;
        uint8_t next = 20;
        double recoverable=0.;uint8_t recovery_point=20;
        for (uint8_t p : candidates) {
            if (p <= packet || (!utility_stop && state.calls >= 3 && p != 20)) continue;
            if (!packet && p <= early_gate_max_packet &&
                bin < early_gate_min_admission_bin) continue;
            const size_t cell=utility_stop?(packet*8+bin)*8+state.admission_risk_bin:packet*8+bin;
            const double gain = packet == 0 ? first[bin * 20 + p - 1] :
                successor[cell * 20 + p - 1];
            const double utility = gain - call_cost - wait_cost * (p - packet);
            if(utility_stop && packet && rescue[cell*20+p-1]>recoverable) {
                recoverable=rescue[cell*20+p-1];recovery_point=p;
            }
            if (utility > best) { best = utility; best_gain = gain; next = p; }
        }
        if (packet && best <= 0) {
            if(utility_stop) {
                if(recoverable>stop_risk_budget) {
                    const size_t cell=(packet*8+bin)*8+state.admission_risk_bin;
                    state.pending_packet=recovery_point;
                    state.predicted_evidence_gain=std::max(0.,successor[cell*20+recovery_point-1]);
                    state.predicted_net_utility=successor[cell*20+recovery_point-1]-call_cost-wait_cost*(recovery_point-packet);
                    return;
                }
                state.stopped=1;state.stop_reason=3;state.pending_packet=0;
                state.predicted_evidence_gain=0;state.predicted_net_utility=best;
                return;
            }
            next = 20;
            best_gain = successor[(packet * 8 + bin) * 20 + 19];
            best = best_gain - call_cost - wait_cost * (20 - packet);
        }
        state.pending_packet = next;
        state.predicted_evidence_gain = std::max(0., best_gain);
        state.predicted_net_utility = best;
    }

    bool Observe(fk_marginal_checkpoint_state &state, uint8_t packet, double score) const {
        if (state.stopped || packet <= state.last_observation_packet || packet > 20 ||
            !std::isfinite(score) || score < 0 || score > 1) return false;
        ++state.calls; state.last_observation_packet = packet; state.last_score = score;
        if (score >= threshold || packet == 20 || state.calls >= 4) {
            state.stopped = 1; state.pending_packet = 0;
            state.predicted_evidence_gain = state.predicted_net_utility = 0;
            state.stop_reason = score >= threshold ? 1 : packet == 20 ? 2 : 4;
        } else Plan(state, score);
        return true;
    }
};
}
#endif
