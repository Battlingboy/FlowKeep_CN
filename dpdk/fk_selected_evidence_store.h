#ifndef FK_SELECTED_EVIDENCE_STORE_H
#define FK_SELECTED_EVIDENCE_STORE_H

#include "fk_detector_request_ring.h"
#include "fk_prefix_version_store.h"
#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <vector>

namespace flowkeep {
class PrefixVersionStore;

// The caller supplies the actual last scored immutable request, not the
// receiver's current state. Scheduling hints never enter the durable payload.
struct SelectedEvidenceRecord {
    fk_detector_request_v1 request{};
    uint64_t decision_sequence=0,event_token=0,evidence_timestamp_ns=0;
    double score=0;
    uint8_t threshold_met=0,alert_latched=0;
    uint64_t recoverability_deadline_ns=0,semantic_watermark_ns=0;
    double marginal_gain=0;
    bool gain_known=false;
};

struct SelectedEvidenceStoreConfig {
    std::string mode,directory,model_sha256,policy_sha256,run_uuid;
    size_t capacity_records=4096,capacity_bytes=8u<<20,batch_size=512;
    uint32_t coalesce_us=2000,writer_cpu=31,full_wait_ms=30000;
    // Opt-in: one final-evidence sink for this run's non-reused identity
    // directory. Requires BindVersionRetirement before any Submit. A consumed
    // seal claim replaces redundant DB/batch duplicate probes; sync WAL still
    // gates completion and payload retirement. Existing databases are forbidden.
    bool version_submission_guard=false;
    size_t wal_group_batches=1;
    bool compress_values=false;
    // Two bounded stages on the same assigned writer CPU. Prepared rows keep
    // their original slots/versions until the publisher's synchronous WAL.
    bool prepare_pipeline=false;
    // Deterministic local correctness fixtures only. Empty in physical runs;
    // activation is explicitly recorded in the manifest and final receipt.
    std::function<bool(const SelectedEvidenceRecord *const *,size_t)> before_write_for_test;
};

class SelectedEvidenceStore {
public:
    using Config=SelectedEvidenceStoreConfig;
    explicit SelectedEvidenceStore(const Config &);
    ~SelectedEvidenceStore();
    SelectedEvidenceStore(const SelectedEvidenceStore&)=delete;
    SelectedEvidenceStore &operator=(const SelectedEvidenceStore&)=delete;
    bool Submit(const SelectedEvidenceRecord &,std::string *error);
    // Retain the identity binding with the immutable queue slot through sync WAL.
    // This overload still validates the request and binding; it never releases
    // payload at enqueue or at encoder completion.
    bool SubmitBound(const SelectedEvidenceRecord &,const PrefixVersionStore::ReadHandle &,std::string *error);
    bool SupportsBoundSubmission() const;
    // Single submitting coordinator: only the writer can change capacity
    // between this query and Submit, and it can only release capacity.
    // Fault/close returns ready so the normal Submit path reports the failure.
    bool AdmissionReady() const;
    // A readiness hint, not a reservation. SubmitBatch rechecks capacity and
    // waits outside the selector mutex if another producer consumes it.
    size_t AdmissionAvailable(size_t maximum) const;
    // At most 16 finalized records. Every record retains its own validation,
    // identity claim and slot; one queue critical section and notification.
    bool SubmitBatch(const SelectedEvidenceRecord *const *records,size_t count,
                     const PrefixVersionStore::ReadHandle *bindings,std::string *error);


    // Bind before the first submission. Retirement follows successful sync WAL,
    // never queue acceptance or a test gate opening.
    bool BindVersionRetirement(std::shared_ptr<PrefixVersionStore>,std::string *error);
    uint32_t WriterCpu() const noexcept;
    uint32_t FullWaitMs() const noexcept;
    size_t CapacityRecords() const noexcept;
    bool Finish(std::string *error);
    // After Finish, reopen the database read-only and compare every full wire
    // record with this independently captured scoring-request oracle.
    bool Verify(const std::vector<SelectedEvidenceRecord> &independently_expected,std::string *error);
    std::string ReceiptJson() const;
    static std::string Encode(const SelectedEvidenceRecord &);
    // Exactly the equality relation of Encode(a)==Encode(b), including signed
    // zero and all reserved request bytes. Both inputs retain full validation;
    // scheduling hints are not wire fields and therefore do not affect equality.
    static bool SameEncodedPayload(const SelectedEvidenceRecord &,const SelectedEvidenceRecord &);
    static SelectedEvidenceRecord Decode(const std::string &);
    static std::string IdentityKey(const SelectedEvidenceRecord &);
    // Normalized content excludes run-dependent sequence/routing/physical time
    // and FlowTable incarnation fields, but retains all 159 float bit patterns.
    static std::string ContentKey(const SelectedEvidenceRecord &);
    static std::string ContentDigest(const SelectedEvidenceRecord &);
    static std::string ContentDigest(const std::vector<SelectedEvidenceRecord> &);
    static size_t RecordChargeBytes() noexcept {return sizeof(SelectedEvidenceRecord);}
private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};
}
#endif
