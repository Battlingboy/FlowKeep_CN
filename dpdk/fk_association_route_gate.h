#ifndef FLOWKEEP_DPDK_FK_ASSOCIATION_ROUTE_GATE_H
#define FLOWKEEP_DPDK_FK_ASSOCIATION_ROUTE_GATE_H

#include <cstdint>

/*
 * The receiver has two truthful association routes:
 *
 *  - the in-process actor path associates FLOW_OPEN/checkpoint messages before
 *    a local detector queue; and
 *  - the external SHM path publishes both first-packet FLOW_OPEN identity and
 *    checkpoint requests to the frozen event-map service, where event
 *    association happens before any optional model inference.
 *
 * Do not make the second mode look like the first by synthesizing
 * associated_* counters.  Its receiver-side gate is exact lossless handoff;
 * the service receipt is the separate proof of downstream event association.
 */
struct fk_association_route_gate_input {
    bool external_mode = false;
    bool in_process_coverage_valid = false;
    uint64_t submitted_flow_open = 0u;
    uint64_t submitted_checkpoints = 0u;
    uint64_t submitted_total = 0u;
    uint64_t external_flow_open_bypassed = 0u;
    uint64_t external_flow_open_published = 0u;
    uint64_t external_checkpoint_published = 0u;
    uint64_t external_publish_attempts = 0u;
    uint64_t external_published = 0u;
    uint64_t processed_total = 0u;
    uint64_t forwarded_checkpoints = 0u;
    uint64_t external_conversion_failures = 0u;
    uint64_t external_publish_failures = 0u;
};

static inline bool fk_association_route_gate_passed(
        const fk_association_route_gate_input &input) {
    if (!input.external_mode)
        return input.in_process_coverage_valid;
    return
        input.submitted_flow_open <=
            UINT64_MAX - input.submitted_checkpoints &&
        input.submitted_total ==
            input.submitted_flow_open + input.submitted_checkpoints &&
        input.external_flow_open_bypassed == 0u &&
        input.external_flow_open_published == input.submitted_flow_open &&
        input.external_checkpoint_published == input.submitted_checkpoints &&
        input.external_publish_attempts == input.submitted_total &&
        input.external_published == input.submitted_total &&
        input.processed_total == input.submitted_total &&
        input.forwarded_checkpoints == input.submitted_checkpoints &&
        input.external_conversion_failures == 0u &&
        input.external_publish_failures == 0u;
}

#endif
