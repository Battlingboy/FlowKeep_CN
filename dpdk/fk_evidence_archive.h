#ifndef FK_EVIDENCE_ARCHIVE_H
#define FK_EVIDENCE_ARCHIVE_H
#include "fk_compact_flow_table.h"
#include <cstddef>
#include <cstdint>
#include <string>

namespace flowkeep {
// Separate investigation module. It never owns, restores, or vetoes R16 state.
struct EvidenceTracker;
enum EvidenceTrigger : uint32_t {
    EvidenceObservation=1, EvidenceBeforeRelease=2,
    EvidenceBeforeCompaction=3, EvidenceBeforeDestroy=4,
    EvidenceCompatibility=5, EvidenceContinuation=6
};
EvidenceTracker *EvidenceAttach(fk_compact_flow_table *, uint32_t capacity);
EvidenceTracker *EvidenceFor(fk_compact_flow_table *) noexcept;
void EvidenceDetach(EvidenceTracker *) noexcept;
void EvidenceObserve(EvidenceTracker *, fk_compact_flow_table *,
                     fk_compact_flow_handle, uint8_t updated_mask) noexcept;
void EvidenceCapture(EvidenceTracker *, fk_compact_flow_table *,
                     fk_compact_flow_handle, uint8_t mask,
                     EvidenceTrigger, uint32_t release_reason=0) noexcept;
// Optional evidence-only TLS tail. Called before ordinary runtime ingress; it
// never changes an R16 packet result or reclaims any original component.
void EvidenceContinue(EvidenceTracker *, const fk_flow_key *,uint8_t direction,
                      const fk_packet_view *,uint64_t timestamp_ns) noexcept;
bool EvidenceFinish() noexcept;
uint64_t EvidencePendingRecords() noexcept;
// Standalone read-only database verification/query; does not create an R16 runtime.
int EvidenceRead(const std::string &db, const std::string &oracle,
                 const std::string &output, const std::string &flow_filter="",
                 size_t limit=0);
}
#endif
