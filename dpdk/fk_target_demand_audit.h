#ifndef FK_TARGET_DEMAND_AUDIT_H
#define FK_TARGET_DEMAND_AUDIT_H

#include "fk_detector_request_shm_abi.h"
#include "fk_prefix_version_store.h"
#include "fk_marginal_checkpoint_scheduler.h"
#include <chrono>
#include <cmath>
#include <cstdio>
#include <cstring>
#include <mutex>
#include <memory>
#include <string>
#include <vector>

namespace flowkeep {

// Observation-only audit. No waits, new targets, changed inputs, or receiver
// changes. Capture happens immediately after the successful policy transition,
// before event-latch override, gain feedback, or registry publication. A single
// acquire Latest fixes L; subsequent reads never replace that captured value.
// H7 recycles payloads. Exact pairs are copied immediately after fixed-L sampling
// while the score is in flight. Save only serializes the retained diagnostic copies.
class TargetDemandAudit {
    struct Pair {PrefixVersionStore::Prefix target{},latest{};};
    struct Row {
        PrefixVersionStore::Identity identity{};
        uint64_t sequence=0,event=0,before_ns=0,after_ns=0,after_latest_ns=0;
        uint32_t parent_packet=0,pending=0,calls=0,last_observation=0;
        uint32_t latest=0,latest_after_sample=0,slot=0,stop_reason=0;
        bool terminal=false,stopped=false,alert_latched=false,resolved=false;
        std::unique_ptr<Pair> pair;
        bool have_target=false,have_latest=false;
    };
    std::mutex mutex_;
    std::vector<Row> rows_;
    TargetDemandAudit(){rows_.reserve(300000);}
    static uint64_t Now() noexcept {
        return static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::nanoseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count());
    }
    static std::string Hex(const void *data,size_t size) {
        static const char hex[]="0123456789abcdef";
        const auto *p=static_cast<const unsigned char*>(data);
        std::string out(size*2,'0');
        for(size_t i=0;i<size;++i){out[i*2]=hex[p[i]>>4];out[i*2+1]=hex[p[i]&15];}
        return out;
    }
    static const char *Bool(bool value) noexcept{return value?"true":"false";}
public:
    static TargetDemandAudit &Get(){static TargetDemandAudit value;return value;}
    void AfterActual(const PrefixVersionStore *versions,
                     const PrefixVersionStore::Identity &identity,
                     uint64_t sequence,uint64_t event,uint32_t parent_packet,
                     bool terminal,const fk_marginal_checkpoint_state &state,
                     bool alert_latched) {
        Row row{};
        row.identity=identity;row.sequence=sequence;row.event=event;
        row.parent_packet=parent_packet;row.terminal=terminal;
        row.pending=state.pending_packet;row.calls=state.calls;
        row.last_observation=state.last_observation_packet;
        row.stopped=state.stopped!=0;row.stop_reason=state.stop_reason;
        row.alert_latched=alert_latched;
        if(!terminal && row.pending && !row.stopped) {
            PrefixVersionStore::ReadHandle handle;
            row.before_ns=Now();
            row.resolved=versions && versions->Resolve(identity,&handle);
            if(row.resolved){row.slot=handle.Slot();row.latest=versions->Latest(handle);}
            row.after_ns=Now();
            if(row.resolved)row.latest_after_sample=versions->Latest(handle);
            row.after_latest_ns=Now();
            // Copy while this score is in flight, before finalization can retire this identity.
            if(row.resolved && row.latest>row.pending) {
                row.pair=std::make_unique<Pair>();
                row.have_target=versions->Lookup(handle,row.pending,&row.pair->target);
                row.have_latest=versions->Lookup(handle,row.latest,&row.pair->latest);
            }
        }
        std::lock_guard<std::mutex> lock(mutex_);
        rows_.push_back(std::move(row));
    }
    // Called after RunNativeFusionService and history drain; never during
    // scheduling. Feature comparison deliberately excludes timestamps,
    // physical generation, and struct padding. Keep raw bytes for an
    // independent bitwise/numeric/mask comparison, not just a Boolean result.
    bool Save(const std::string &directory,const PrefixVersionStore *versions) {
        std::lock_guard<std::mutex> lock(mutex_);
        FILE *events=std::fopen((directory+"/target_demand.jsonl").c_str(),"wx");
        if(!events)return false;
        bool ok=true,valid=true;
        uint64_t ordinary=0,terminal=0,proposed=0,effective=0,cancelled=0;
        uint64_t past=0,current=0,future=0,missing=0,missing_pairs=0;
        uint64_t pair_count=0,feature_bitwise_different=0,feature_numeric_different=0,mask_different=0;
        uint64_t sample_advanced=0,invalid_transition=0;
        for(size_t index=0;index<rows_.size();++index) {
            const auto &row=rows_[index];
            if(row.terminal)++terminal;else ++ordinary;
            const bool is_proposed=!row.terminal && row.pending!=0 && !row.stopped;
            const bool is_effective=is_proposed && !row.alert_latched;
            const bool was_cancelled=is_proposed && row.alert_latched;
            if(is_proposed)++proposed;
            if(is_effective)++effective;
            if(was_cancelled)++cancelled;
            if(!row.terminal && ((row.stopped && row.pending) || (!row.stopped && !row.pending))) {
                ++invalid_transition;valid=false;
            }
            const char *relation="not_next";
            bool pair_required=false,pair_ok=false,have_target=false,have_latest=false;
            bool bitwise_different=false,numeric_different=false,different_mask=false;
            PrefixVersionStore::Prefix target{},latest{};
            PrefixVersionStore::ReadHandle handle;
            const bool end_resolved=versions && versions->Resolve(row.identity,&handle);
            const uint32_t end_latest=end_resolved?versions->Latest(handle):0;
            const bool slot_stable=!is_proposed || (row.resolved && end_resolved && handle.Slot()==row.slot);
            if(is_proposed) {
                const bool snapshot_ok=row.resolved && slot_stable && row.latest>=row.parent_packet &&
                    row.latest<=20 && row.pending>row.parent_packet && row.pending<=20 &&
                    row.before_ns<=row.after_ns && row.after_ns<=row.after_latest_ns &&
                    row.latest_after_sample>=row.latest && end_latest>=row.latest_after_sample;
                if(!snapshot_ok){++missing;relation="unknown_snapshot";valid=false;}
                else if(row.latest>row.pending){++past;relation="past";pair_required=true;}
                else if(row.latest==row.pending){++current;relation="current";}
                else {++future;relation="future";}
                if(row.latest_after_sample>row.latest)++sample_advanced;
            }
            if(pair_required) {
                have_target=row.have_target;if(row.pair)target=row.pair->target;
                have_latest=row.have_latest;if(row.pair)latest=row.pair->latest;
                pair_ok=have_target && have_latest;
                if(!pair_ok){++missing_pairs;valid=false;}
                else {
                    ++pair_count;
                    bitwise_different=std::memcmp(target.evidence.features.data(),latest.evidence.features.data(),
                        sizeof(target.evidence.features))!=0;
                    for(size_t i=0;i<target.evidence.features.size();++i) {
                        const float a=target.evidence.features[i],b=latest.evidence.features[i];
                        if(!(a==b || (std::isnan(a) && std::isnan(b))))numeric_different=true;
                    }
                    different_mask=target.evidence.mask!=latest.evidence.mask;
                    feature_bitwise_different+=bitwise_different;
                    feature_numeric_different+=numeric_different;
                    mask_different+=different_mask;
                }
            }
            const std::string key=Hex(&row.identity.key,sizeof(row.identity.key));
            int written=std::fprintf(events,
                "{\"schema\":\"flowkeep-target-demand-v1\",\"row\":%zu,\"kind\":\"%s\","
                "\"sequence\":%llu,\"parent_sequence\":%llu,\"event_token\":%llu,"
                "\"key\":\"%s\",\"first\":%llu,\"logical\":%llu,\"parent_packet\":%u,"
                "\"actual\":true,\"terminal\":%s,\"policy_observe_called\":%s,"
                "\"policy_pending\":%u,\"policy_stopped\":%s,\"policy_calls\":%u,"
                "\"policy_last_observation_packet\":%u,\"policy_stop_reason\":%u,"
                "\"actual_alert_latched\":%s,\"proposed_next\":%s,\"effective_next\":%s,"
                "\"later_latch_cancelled\":%s,\"k\":%u,\"L\":%u,\"resolved\":%s,"
                "\"slot\":%u,\"slot_stable_at_save\":%s,\"sample_before_ns\":%llu,"
                "\"sample_after_ns\":%llu,\"latest_after_sample\":%u,\"after_latest_ns\":%llu,"
                "\"end_latest\":%u,\"relation\":\"%s\",\"pair_required\":%s,"
                "\"target_lookup_ok\":%s,\"latest_lookup_ok\":%s,\"pair_ok\":%s,",
                index,row.terminal?"terminal_actual_no_observe":"ordinary_actual_transition",
                static_cast<unsigned long long>(row.sequence),static_cast<unsigned long long>(row.sequence),
                static_cast<unsigned long long>(row.event),key.c_str(),
                static_cast<unsigned long long>(row.identity.first),static_cast<unsigned long long>(row.identity.logical),
                row.parent_packet,Bool(row.terminal),Bool(!row.terminal),row.pending,Bool(row.stopped),row.calls,
                row.last_observation,row.stop_reason,Bool(row.alert_latched),Bool(is_proposed),Bool(is_effective),
                Bool(was_cancelled),row.pending,row.latest,Bool(row.resolved),row.slot,Bool(slot_stable),
                static_cast<unsigned long long>(row.before_ns),static_cast<unsigned long long>(row.after_ns),
                row.latest_after_sample,static_cast<unsigned long long>(row.after_latest_ns),end_latest,relation,
                Bool(pair_required),Bool(have_target),Bool(have_latest),Bool(pair_ok));
            if(written<0)ok=false;
            if(pair_ok) {
                const auto target_hex=Hex(target.evidence.features.data(),sizeof(target.evidence.features));
                const auto latest_hex=Hex(latest.evidence.features.data(),sizeof(latest.evidence.features));
                written=std::fprintf(events,
                    "\"target_mask\":%u,\"latest_mask\":%u,\"target_features_hex\":\"%s\","
                    "\"latest_features_hex\":\"%s\",\"feature_bitwise_different\":%s,"
                    "\"feature_numeric_different\":%s,\"mask_different\":%s}\n",
                    target.evidence.mask,latest.evidence.mask,target_hex.c_str(),latest_hex.c_str(),
                    Bool(bitwise_different),Bool(numeric_different),Bool(different_mask));
            } else {
                written=std::fprintf(events,
                    "\"target_mask\":null,\"latest_mask\":null,\"target_features_hex\":null,"
                    "\"latest_features_hex\":null,\"feature_bitwise_different\":null,"
                    "\"feature_numeric_different\":null,\"mask_different\":null}\n");
            }
            if(written<0)ok=false;
        }
        if(std::fclose(events)!=0)ok=false;
        FILE *receipt=std::fopen((directory+"/target_demand_receipt.json").c_str(),"wx");
        if(!receipt)return false;
        const int written=std::fprintf(receipt,
            "{\"schema\":\"flowkeep-target-demand-receipt-v1\",\"actual_rows\":%zu,"
            "\"ordinary_actual_transitions\":%llu,\"terminal_actual_no_observe\":%llu,"
            "\"proposed_successor_next\":%llu,\"effective_successor_next\":%llu,\"later_latch_cancelled\":%llu,"
            "\"past\":%llu,\"current\":%llu,\"future\":%llu,\"unknown_snapshots\":%llu,"
            "\"historical_pairs\":%llu,\"missing_historical_pairs\":%llu,"
            "\"feature_bitwise_different\":%llu,\"feature_numeric_different\":%llu,\"mask_different\":%llu,"
            "\"latest_advanced_during_sampling\":%llu,\"invalid_transitions\":%llu,"
            "\"row_bytes\":%zu,\"row_capacity\":%zu,\"feature_count\":159,\"feature_bytes\":636,"
            "\"feature_encoding\":\"native-little-endian-ieee754-float32-hex\","
            "\"sampling_point\":\"immediately_after_successful_observe_before_event_latch_gain_registry\","
            "\"payload_read_point\":\"immediately_after_fixed_L_sample_before_score_return_and_retirement\","
            "\"snapshot_contract\":\"one_acquire_L_then_copy_exact_pair_while_actual_score_is_inflight\","
            "\"first_next_included\":false,\"synthetic_rows_included\":false,"
            "\"payload_copies_during_sampling\":2,\"invariants_passed\":%s,\"io_passed\":%s}\n",
            rows_.size(),static_cast<unsigned long long>(ordinary),static_cast<unsigned long long>(terminal),
            static_cast<unsigned long long>(proposed),static_cast<unsigned long long>(effective),
            static_cast<unsigned long long>(cancelled),static_cast<unsigned long long>(past),
            static_cast<unsigned long long>(current),static_cast<unsigned long long>(future),
            static_cast<unsigned long long>(missing),static_cast<unsigned long long>(pair_count),
            static_cast<unsigned long long>(missing_pairs),static_cast<unsigned long long>(feature_bitwise_different),
            static_cast<unsigned long long>(feature_numeric_different),static_cast<unsigned long long>(mask_different),
            static_cast<unsigned long long>(sample_advanced),static_cast<unsigned long long>(invalid_transition),
            sizeof(Row),rows_.capacity(),Bool(valid),Bool(ok));
        if(written<0)ok=false;
        if(std::fclose(receipt)!=0)ok=false;
        return ok && valid;
    }
};
}
#endif
