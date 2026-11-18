#ifndef FLOWKEEP_FK_OWNER_RUNTIME_OUTPUT_ABI_H
#define FLOWKEEP_FK_OWNER_RUNTIME_OUTPUT_ABI_H

#include <stdint.h>

#include "fk_compact_runtime.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Frozen value-only boundary between one fixed owner and downstream rings. */
#define FK_OWNER_RUNTIME_OUTPUT_ABI_VERSION 5u

enum fk_owner_runtime_output_state {
    FK_OWNER_RUNTIME_OUTPUT_EMPTY = 0,
    FK_OWNER_RUNTIME_OUTPUT_STAGED = 1,
    FK_OWNER_RUNTIME_OUTPUT_IDENTITY_COMMITTED = 2,
};

/*
 * One transaction is the indivisible queue element.  The three optional
 * payloads must never be split across queues: FLOW_OPEN, when present, is
 * consumed before the checkpoint/detection and action from this same value.
 */
/* The historical C type suffix remains v2 because contained detector and
 * FLOW_OPEN records use identity ABI v2.  `abi_version` is the authoritative
 * outer transport layout and is currently v5.  Version 4 carries both the
 * value policy's selected action mask and the final physical retained mask.
 * Version 5 makes OPEN versus CONTINUE explicit and carries the producer-
 * attested predecessor index, generation, and checkpoint cursor. */
struct fk_owner_runtime_output_batch_v2 {
    uint64_t transaction_epoch;
    uint64_t packet_sequence;
    /* Keep the two time domains attached to the exact packet transaction.
     * semantic time orders the frozen replay; physical ingress time is the
     * only valid origin for packet-to-decision latency. */
    uint64_t physical_ingress_timestamp_ns;
    uint64_t semantic_timestamp_ns;
    uint64_t logical_connection_id;
    struct fk_compact_flow_handle handle;
    struct fk_compact_flow_open_observation_v2 flow_open;
    struct fk_compact_detection_request_v2 detection;
    struct fk_compact_action_record action;
    uint32_t abi_version;
    uint8_t has_flow_open;
    uint8_t has_detection;
    uint8_t has_action;
    uint8_t state;
    uint8_t reserved[8];
};

#ifdef __cplusplus
}
#endif

#endif
