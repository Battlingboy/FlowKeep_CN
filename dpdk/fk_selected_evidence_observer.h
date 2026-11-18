#ifndef FK_SELECTED_EVIDENCE_OBSERVER_H
#define FK_SELECTED_EVIDENCE_OBSERVER_H
#include "fk_detector_request_ring.h"
#include "fk_prefix_version_store.h"
#include <string>
#include <cstddef>

namespace flowkeep {
struct NativeFusionDecision;
struct SelectedFinalizationRequest {
    fk_flow_key key{};
    uint64_t first=0,logical=0,last_candidate=0;
    // Optional in-process identity-directory binding. Not a payload lease,
    // not a physical flow slot, and never serialized into evidence.
    PrefixVersionStore::ReadHandle binding{};

};
// Optional observational side path. Never changes scores, NEXT/STOP or EOF.
// Actual model execution is attested by the scorer, not inferred from a
// ledger row that may merely carry an already-latched event score.
class SelectedEvidenceObserver {
public:
    virtual ~SelectedEvidenceObserver() = default;
    virtual bool Issued(const fk_detector_request_v1 &, uint64_t sequence,
                        uint64_t event, std::string *) noexcept = 0;
    virtual bool UsesBoundIssueRequests() const noexcept {return false;}
    virtual bool IssuedBound(const fk_detector_request_v1 &request,uint64_t sequence,uint64_t event,
            const PrefixVersionStore::ReadHandle &,std::string *error) noexcept {
        return Issued(request,sequence,event,error);
    }
    virtual bool Scored(uint64_t sequence, bool actual, double score,
                        std::string *) noexcept = 0;
    virtual bool Durable(const NativeFusionDecision &, std::string *) noexcept = 0;
    virtual bool Finalize(const fk_flow_key &, uint64_t first, uint64_t logical,
                          uint64_t last_candidate, std::string *) noexcept = 0;
    virtual bool FinalizeAdmissionReady() const noexcept {return true;}
    virtual bool UsesBoundFinalizationRequests() const noexcept {return false;}
    virtual bool SupportsFinalizeBatch() const noexcept {return false;}
    virtual size_t FinalizeBatchAdmission(size_t maximum) const noexcept {
        return maximum && FinalizeAdmissionReady() ? 1 : 0;
    }
    virtual bool FinalizeBatch(const SelectedFinalizationRequest *rows,size_t count,
                               std::string *error) noexcept {
        if(!rows || !count){if(error)*error="empty finalization batch";return false;}
        for(size_t i=0;i<count;++i)
            if(!Finalize(rows[i].key,rows[i].first,rows[i].logical,rows[i].last_candidate,error))return false;
        return true;
    }

    virtual bool Finish(std::string *) noexcept = 0;
};
}
#endif
