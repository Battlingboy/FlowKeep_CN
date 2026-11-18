#ifndef FK_EVIDENCE_PERSISTENCE_SCHEDULE_H
#define FK_EVIDENCE_PERSISTENCE_SCHEDULE_H
#include <algorithm>
#include <cmath>
#include <cstdint>
#include <limits>
#include <numeric>
#include <queue>
#include <string>
#include <unordered_map>
#include <vector>

namespace flowkeep {
struct EvidencePersistenceCandidate {
    std::string chain;
    // Same semantic clock as the captured evidence. Zero means unknown, not
    // an invented TTL. Immutable queue copies still remain until sync ACK.
    uint64_t recoverability_deadline_ns=0;
    uint64_t estimated_write_bytes=1;
    double marginal_gain=0;
    bool gain_known=false;
};

// Pure ordering: no admission rejection, evidence discard or durable ACK.
// A chain's successor cannot overtake its predecessor, even if its gain is
// higher. Only a budget-limited batch invokes utility competition.
inline std::vector<size_t> EvidencePersistenceOrder(
        const std::vector<EvidencePersistenceCandidate> &rows,
        size_t batch_capacity,uint64_t semantic_watermark,
        bool next_batch_only=false) {
    std::vector<size_t> order(rows.size());
    std::iota(order.begin(),order.end(),0);
    if(!batch_capacity || rows.size()<=batch_capacity)return order;
    const size_t none=rows.size();
    std::vector<size_t> next(rows.size(),none),roots;
    std::unordered_map<std::string,size_t> tail;
    for(size_t i=0;i<rows.size();++i) {
        const auto inserted=tail.emplace(rows[i].chain,i);
        if(inserted.second)roots.push_back(i);
        else {next[inserted.first->second]=i;inserted.first->second=i;}
    }
    // A successor deadline also constrains its not-yet-written predecessors.
    // Inherit the earliest deadline backwards along the dependency chain.
    std::vector<uint64_t> deadline(rows.size());
    for(size_t i=rows.size();i-- >0;) {
        deadline[i]=rows[i].recoverability_deadline_ns;
        if(next[i]!=none && deadline[next[i]] &&
           (!deadline[i] || deadline[next[i]]<deadline[i]))deadline[i]=deadline[next[i]];
    }
    const auto later=[&](size_t a,size_t b) {
        const auto &x=rows[a];const auto &y=rows[b];
        const bool xd=deadline[a] && deadline[a]<=semantic_watermark;
        const bool yd=deadline[b] && deadline[b]<=semantic_watermark;
        if(xd!=yd)return !xd;
        if(xd && deadline[a]!=deadline[b])return deadline[a]>deadline[b];
        // Unknown evidence value is protected, not silently assigned zero.
        if(x.gain_known!=y.gain_known)return x.gain_known;
        if(x.gain_known) {
            const double xv=std::isfinite(x.marginal_gain)?std::max(0.0,x.marginal_gain):0.0;
            const double yv=std::isfinite(y.marginal_gain)?std::max(0.0,y.marginal_gain):0.0;
            const double xu=xv/std::max<uint64_t>(1,x.estimated_write_bytes);
            const double yu=yv/std::max<uint64_t>(1,y.estimated_write_bytes);
            if(xu!=yu)return xu<yu;
        }
        return a>b;
    };
    // Heapify all ready chain frontiers in linear time. Incremental pushes
    // needlessly add logarithmic work while the producer mutex is held.
    std::priority_queue<size_t,std::vector<size_t>,decltype(later)> ready(later,std::move(roots));
    order.clear();
    const size_t limit=next_batch_only?batch_capacity:rows.size();
    std::vector<uint8_t> selected(next_batch_only?rows.size():0,0);
    while(!ready.empty() && order.size()<limit) {
        const size_t i=ready.top();ready.pop();order.push_back(i);
        if(next_batch_only)selected[i]=1;
        if(next[i]!=none)ready.push(next[i]);
    }
    // Only this batch can be written. Leave unselected records in their
    // existing FIFO order; fresh feedback/deadlines are evaluated next batch.
    // Selected chain prefixes guarantee no successor overtakes a predecessor.
    if(next_batch_only)
        for(size_t i=0;i<rows.size();++i)if(!selected[i])order.push_back(i);
    return order;
}
}
#endif
