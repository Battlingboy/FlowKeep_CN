#ifndef FK_RX_PUMP_DIAGNOSTICS_H
#define FK_RX_PUMP_DIAGNOSTICS_H
#include <array>
#include <cstdint>
#include <limits>
#include <ostream>
namespace flowkeep {
// Passive, pump-local telemetry. No allocation, locks or clock reads on the
// packet path. Callers provide the round TSC samples they already collect.
struct RxPumpDiagnostics {
    static constexpr size_t kBoundCount=8;
    static constexpr size_t kBucketCount=kBoundCount+1;
    struct Histogram {
        std::array<uint64_t,kBucketCount> buckets{};
        uint64_t maximum_cycles=0;
        void Observe(uint64_t cycles,const std::array<uint64_t,kBoundCount> &bounds) noexcept {
            size_t bucket=0;while(bucket<kBoundCount && cycles>=bounds[bucket])++bucket;
            ++buckets[bucket];if(cycles>maximum_cycles)maximum_cycles=cycles;
        }
        uint64_t Count() const noexcept {uint64_t n=0;for(auto x:buckets)n+=x;return n;}
    };
    uint64_t tsc_hz=0,poll_calls=0,nonempty_bursts=0,full_bursts=0,packets=0;
    uint64_t rounds=0,nonempty_rounds=0,first_ingress_monotonic_ns=0,last_ingress_monotonic_ns=0;
    uint64_t clock_regressions=0,invalid_burst_counts=0,zero_ingress_samples=0;
    uint64_t before_first_rounds=0,before_first_maximum_poll_gap_cycles=0;
    Histogram active_poll_gap,active_between_round_gap,nonempty_round_processing;
    // These running counters are snapshotted only on a nonempty round. The
    // final long empty drain is excluded from both active-window histograms.
    Histogram running_poll_gap,running_between_round_gap;
    std::array<uint64_t,kBoundCount> bounds_cycles{};
    uint64_t current_start=0,previous_start=0,previous_end=0,current_packets=0;
    uint64_t last_nonempty_end=0,last_nonempty_round=0,final_end=0;
    bool have_previous=false,have_previous_end=false,seen_nonempty=false;
    static constexpr std::array<uint64_t,kBoundCount> BoundsNs() noexcept {
        return {{1000,5000,10000,50000,100000,500000,1000000,5000000}};
    }
    bool Initialize(uint64_t hz) noexcept {
        if(!hz)return false;
        tsc_hz=hz;const auto limits=BoundsNs();
        for(size_t i=0;i<kBoundCount;++i) {
            // ceil(hz * ns / 1e9), with each product bounded even at UINT64_MAX Hz.
            bounds_cycles[i]=(hz/1000000000u)*limits[i]+
                ((hz%1000000000u)*limits[i]+999999999u)/1000000000u;
        }
        return true;
    }
    void BeginRound(uint64_t start) noexcept {
        current_start=start;current_packets=0;
        if(have_previous) {
            if(start<previous_start)++clock_regressions;
            else if(seen_nonempty)running_poll_gap.Observe(start-previous_start,bounds_cycles);
            else if(start-previous_start>before_first_maximum_poll_gap_cycles)
                before_first_maximum_poll_gap_cycles=start-previous_start;
        }
        if(have_previous_end) {
            if(start<previous_end)++clock_regressions;
            else if(seen_nonempty)running_between_round_gap.Observe(start-previous_end,bounds_cycles);
        }
        previous_start=start;have_previous=true;
    }
    void ObserveBurst(uint16_t count,uint16_t requested) noexcept {
        ++poll_calls;
        if(!requested || count>requested){++invalid_burst_counts;return;}
        if(!count)return;
        ++nonempty_bursts;if(count==requested)++full_bursts;
        packets+=count;current_packets+=count;
    }
    void ObserveIngress(uint64_t timestamp_ns) noexcept {
        if(!timestamp_ns){++zero_ingress_samples;return;}
        if(last_ingress_monotonic_ns && timestamp_ns<last_ingress_monotonic_ns)++clock_regressions;
        if(!first_ingress_monotonic_ns)first_ingress_monotonic_ns=timestamp_ns;
        last_ingress_monotonic_ns=timestamp_ns;
    }
    void EndRound(uint64_t end) noexcept {
        ++rounds;final_end=end;
        if(end<current_start)++clock_regressions;
        if(current_packets) {
            ++nonempty_rounds;
            if(end>=current_start)nonempty_round_processing.Observe(end-current_start,bounds_cycles);
            active_poll_gap=running_poll_gap;
            active_between_round_gap=running_between_round_gap;
            last_nonempty_end=end;last_nonempty_round=rounds;seen_nonempty=true;
        }else if(!seen_nonempty)++before_first_rounds;
        previous_end=end;have_previous_end=true;
    }
    uint64_t Ns(uint64_t cycles) const noexcept {
        if(!tsc_hz)return 0;
        const long double ns=static_cast<long double>(cycles)*1000000000.0L/tsc_hz;
        return ns>=std::numeric_limits<uint64_t>::max()?std::numeric_limits<uint64_t>::max():
            static_cast<uint64_t>(ns);
    }
    void WriteHistogram(std::ostream &out,const Histogram &value) const {
        out<<"{\"samples\":"<<value.Count()<<",\"maximum_cycles\":"<<value.maximum_cycles
            <<",\"maximum_ns\":"<<Ns(value.maximum_cycles)<<",\"buckets\":[";
        for(size_t i=0;i<kBucketCount;++i){if(i)out<<',';out<<value.buckets[i];}out<<"]}";
    }
    void WriteJson(std::ostream &out) const {
        out<<"{\"schema\":\"flowkeep-rx-pump-poll-diagnostics-v1\",\"tsc_hz\":"<<tsc_hz
            <<",\"metadata_bytes\":"<<sizeof(*this)<<",\"ingress_clock\":\"CLOCK_MONOTONIC\""
            <<",\"first_ingress_monotonic_ns\":"<<first_ingress_monotonic_ns
            <<",\"last_ingress_monotonic_ns\":"<<last_ingress_monotonic_ns
            <<",\"ingress_scope\":\"all_nonempty_NIC_bursts_existing_receiver_monotonic_sample\""
            <<",\"active_window_present\":"<<(seen_nonempty && first_ingress_monotonic_ns?"true":"false")
            <<",\"poll_calls\":"<<poll_calls<<",\"nonempty_bursts\":"<<nonempty_bursts
            <<",\"full_bursts\":"<<full_bursts<<",\"packets\":"<<packets
            <<",\"rounds\":"<<rounds<<",\"nonempty_rounds\":"<<nonempty_rounds
            <<",\"before_first_rounds\":"<<before_first_rounds
            <<",\"before_first_maximum_poll_gap_ns\":"<<Ns(before_first_maximum_poll_gap_cycles)
            <<",\"after_last_rounds\":"<<(seen_nonempty?rounds-last_nonempty_round:0)
            <<",\"after_last_empty_elapsed_ns\":"<<Ns(seen_nonempty && final_end>=last_nonempty_end?
                final_end-last_nonempty_end:0)
            <<",\"clock_regressions\":"<<clock_regressions<<",\"zero_ingress_samples\":"<<zero_ingress_samples
            <<",\"invalid_burst_counts\":"<<invalid_burst_counts
            <<",\"valid\":"<<(tsc_hz && !clock_regressions && !zero_ingress_samples && !invalid_burst_counts?"true":"false")
            <<",\"bucket_upper_bounds_ns_exclusive\":[";
        const auto bounds=BoundsNs();for(size_t i=0;i<kBoundCount;++i){if(i)out<<',';out<<bounds[i];}
        out<<"],\"last_bucket_unbounded\":true"
            <<",\"poll_gap_scope\":\"outer_round_start_to_start_between_first_and_last_nonempty_round\""
            <<",\"between_round_gap_scope\":\"previous_round_end_to_next_start_within_active_window\""
            <<",\"processing_scope\":\"round_start_to_end_only_rounds_with_received_packets\""
            <<",\"poll_gap_is_per_queue_poll_gap_only_with_one_owned_queue\":true"
            <<",\"long_gap_proves_preemption\":false,\"active_poll_gap\":";
        WriteHistogram(out,active_poll_gap);out<<",\"active_between_round_gap\":";
        WriteHistogram(out,active_between_round_gap);out<<",\"nonempty_round_processing\":";
        WriteHistogram(out,nonempty_round_processing);out<<'}';
    }
};
}
#endif
