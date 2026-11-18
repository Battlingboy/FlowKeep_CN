#ifndef FLOWKEEP_FK_NATIVE_FUSION_EVENT_ROUTER_H
#define FLOWKEEP_FK_NATIVE_FUSION_EVENT_ROUTER_H

#include <stddef.h>
#include <stdint.h>

#include <memory>
#include <string>

#include "fk_native_fusion_service.h"

namespace flowkeep {

enum class NativeFusionEventUnit : uint8_t {
    Scenario = 1u,
    FiveTuple = 2u,
};

struct NativeFusionEventRouterAudit {
    std::string event_map_sha256;
    std::string event_unit;
    uint64_t entries = 0u;
    uint64_t unique_events = 0u;
    uint8_t exact_header_verified = 0u;
    uint8_t canonical_flow_keys_verified = 0u;
    uint8_t event_semantics_verified = 0u;
    uint8_t label_blind_schema_verified = 0u;
};

struct NativeFusionDetailedRoute {
    uint64_t event_token = 0u;
    /* Both strings are immutable and owned by the router for its lifetime. */
    const std::string *event_id = nullptr;
    const std::string *canonical_flow_key = nullptr;
};

/*
 * Production, label-blind router for the frozen exact-header
 * flow_key,event_id CSV.  Load verifies the bytes against expected_sha256
 * before parsing.  Event tokens are the 1-based positions of event_id in
 * unsigned UTF-8 byte order, hence deterministic and nonzero.
 */
class NativeFusionCsvEventRouter final : public NativeFusionEventRouter {
public:
    static std::unique_ptr<NativeFusionCsvEventRouter> Load(
        const std::string &event_map_path,
        const std::string &expected_sha256,
        NativeFusionEventUnit event_unit,
        std::string *error);

    static std::unique_ptr<NativeFusionCsvEventRouter> Load(
        const std::string &event_map_path,
        const std::string &expected_sha256,
        const std::string &event_unit,
        std::string *error);

    ~NativeFusionCsvEventRouter() override;

    bool Resolve(
        const fk_detector_request_v1 &request,
        Route *route,
        std::string *error) noexcept override;

    bool ResolveDetailed(
        const fk_detector_request_v1 &request,
        NativeFusionDetailedRoute *route,
        std::string *error) const noexcept;

    bool Audit(
        NativeFusionEventRouterAudit *audit,
        std::string *error) const noexcept;

    /* Exact Python ipaddress-style canonical text for a binary flow key. */
    static bool CanonicalFlowKeyText(
        const fk_flow_key &key,
        std::string *text,
        std::string *error) noexcept;

private:
    struct Implementation;
    explicit NativeFusionCsvEventRouter(Implementation *implementation)
        noexcept;
    Implementation *implementation_;
};

}  // namespace flowkeep

#endif
