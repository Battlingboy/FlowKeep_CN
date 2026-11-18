#ifndef FLOWKEEP_FK_COMPACT_DETECTOR_REQUEST_ADAPTER_H
#define FLOWKEEP_FK_COMPACT_DETECTOR_REQUEST_ADAPTER_H

#include <stdbool.h>
#include <stdint.h>

#include "fk_compact_runtime.h"
#include "fk_detector_request_shm_abi.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Convert the already ordered compact-runtime checkpoint into the fixed
 * detector-service ABI.  flow_index in the compact runtime is shard local;
 * the service ABI uses one run-global, generation-safe index.
 *
 * event_routing_token is deliberately supplied by the transport adapter.  In
 * production it must equal the sequence that the SHM publish is about to
 * commit (first record 1, then strictly consecutive).
 */
bool fk_compact_detector_request_adapter_build(
    const struct fk_compact_detection_request_v2 *input,
    uint16_t shard,
    uint16_t shard_count,
    uint32_t maximum_flows,
    uint64_t physical_ingress_timestamp_ns,
    uint64_t event_routing_token,
    struct fk_detector_request_v1 *output);

/*
 * Publish one explicit presentation-generation control to the external
 * service without fabricating a detector checkpoint.  input.control_kind
 * selects a v4 FLOW_OPEN or FLOW_CONTINUE record; CONTINUE carries the exact
 * producer-observed predecessor handle/cursor and neither kind has a
 * model-visible feature payload.
 */
bool fk_compact_detector_flow_open_adapter_build(
    const struct fk_compact_flow_open_observation_v2 *input,
    uint16_t shard,
    uint16_t shard_count,
    uint32_t maximum_flows,
    uint64_t physical_ingress_timestamp_ns,
    uint64_t event_routing_token,
    struct fk_detector_request_v1 *output);

#ifdef __cplusplus
}
#endif

#endif
