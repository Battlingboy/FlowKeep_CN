#ifndef FLOWKEEP_FK_IDENTITY_PIPELINE_CONTRACT_H
#define FLOWKEEP_FK_IDENTITY_PIPELINE_CONTRACT_H

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define FK_IDENTITY_PIPELINE_CONTRACT_ABI \
    "flowkeep.dpdk.identity.pipeline.contract.v2"
#define FK_IDENTITY_PIPELINE_SHA256_BYTES 32u

/*
 * Every placement reservation which transports an observation or a derived
 * message outside the controlled per-flow state budget has an explicit slot.
 * Keeping this list finite and ABI-versioned prevents a newly connected queue
 * from disappearing into an unreported "miscellaneous" allowance.
 */
enum fk_identity_pipeline_service_component {
    FK_IDENTITY_SERVICE_EXACT_IDENTITY_SEQUENCER = 0,
    FK_IDENTITY_SERVICE_EXACT_IDENTITY_MBUF_SOURCE,
    FK_IDENTITY_SERVICE_RETIREMENT_PUBLISHER,
    FK_IDENTITY_SERVICE_OWNER_DISPATCH,
    FK_IDENTITY_SERVICE_QUIC_ROUTE_RECEIPTS,
    FK_IDENTITY_SERVICE_OWNER_MBUF_SOURCES,
    FK_IDENTITY_SERVICE_OWNER_RUNTIME_ADAPTERS,
    FK_IDENTITY_SERVICE_OWNER_OUTPUT_RINGS,
    FK_IDENTITY_SERVICE_OWNER_OUTPUT_SEQUENCE_BRIDGE,
    FK_IDENTITY_SERVICE_TRACE_MESSAGE_BARRIER,
    FK_IDENTITY_SERVICE_CHECKPOINT_REORDER,
    FK_IDENTITY_SERVICE_DETECTOR_TRANSPORT,
    FK_IDENTITY_SERVICE_AGGREGATOR_TRANSPORT,
    FK_IDENTITY_SERVICE_RESULT_WRITER_TRANSPORT,
    FK_IDENTITY_SERVICE_COMPONENT_COUNT,
};

struct fk_identity_pipeline_service_memory_receipt {
    uint64_t configured_reserved_bytes;
    uint64_t observed_reserved_bytes;
    uint64_t peak_bytes;
    uint8_t reserved[8];
};

/*
 * DPDK-independent, fail-closed contract for the experimental exact-identity
 * topology.  It is not evidence that the production RX executable is wired
 * to this topology; a caller must explicitly prove every input.
 */
enum fk_identity_pipeline_contract_blocker {
    FK_IDENTITY_PIPELINE_BLOCKER_NONE = 0,
    FK_IDENTITY_PIPELINE_BLOCKER_INVALID_INPUT,
    FK_IDENTITY_PIPELINE_BLOCKER_ABI_MISMATCH,
    FK_IDENTITY_PIPELINE_BLOCKER_EXPERIMENTAL_PATH_NOT_CONNECTED,
    FK_IDENTITY_PIPELINE_BLOCKER_REPLAY_NOT_FROZEN,
    FK_IDENTITY_PIPELINE_BLOCKER_SIDECAR_NOT_FROZEN,
    FK_IDENTITY_PIPELINE_BLOCKER_EXPECTED_PACKETS_INVALID,
    FK_IDENTITY_PIPELINE_BLOCKER_TOPOLOGY_INVALID,
    FK_IDENTITY_PIPELINE_BLOCKER_LCORE_ARITHMETIC_OVERFLOW,
    FK_IDENTITY_PIPELINE_BLOCKER_REQUIRED_LCORES_MISMATCH,
    FK_IDENTITY_PIPELINE_BLOCKER_INSUFFICIENT_LCORES,
    FK_IDENTITY_PIPELINE_BLOCKER_SERVICE_MEMORY_NOT_FROZEN,
    FK_IDENTITY_PIPELINE_BLOCKER_SERVICE_MEMORY_COMPONENT_SET_MISMATCH,
    FK_IDENTITY_PIPELINE_BLOCKER_SERVICE_MEMORY_UNBOUNDED,
    FK_IDENTITY_PIPELINE_BLOCKER_SERVICE_MEMORY_ARITHMETIC_OVERFLOW,
    FK_IDENTITY_PIPELINE_BLOCKER_SERVICE_MEMORY_ACCOUNTING,
    FK_IDENTITY_PIPELINE_BLOCKER_SERVICE_MEMORY_NOT_SEPARATE,
    FK_IDENTITY_PIPELINE_BLOCKER_OWNER_HASH_DIGEST_NOT_PRECOMMITTED,
    FK_IDENTITY_PIPELINE_BLOCKER_ORDERED_SKIP_NOT_CONNECTED,
    FK_IDENTITY_PIPELINE_BLOCKER_ORDERED_OBSERVATION_ACCOUNTING,
    FK_IDENTITY_PIPELINE_BLOCKER_ORDERED_OBSERVATION_SKIPPED,
    FK_IDENTITY_PIPELINE_BLOCKER_RETIREMENT_VISIBILITY,
    FK_IDENTITY_PIPELINE_BLOCKER_RETIREMENT_PUBLICATION,
    FK_IDENTITY_PIPELINE_BLOCKER_RETIREMENT_ACCOUNTING,
    FK_IDENTITY_PIPELINE_BLOCKER_DATA_CONSERVATION,
    FK_IDENTITY_PIPELINE_BLOCKER_DATA_NOT_NORMALLY_COMPLETED,
    FK_IDENTITY_PIPELINE_BLOCKER_SEQUENCER_GATE,
    FK_IDENTITY_PIPELINE_BLOCKER_DISPATCH_GATE,
    FK_IDENTITY_PIPELINE_BLOCKER_RUNTIME_GATE,
    FK_IDENTITY_PIPELINE_BLOCKER_CID_GATE,
    FK_IDENTITY_PIPELINE_BLOCKER_BINDING_GATE,
    FK_IDENTITY_PIPELINE_BLOCKER_CLEANUP_GATE,
    FK_IDENTITY_PIPELINE_BLOCKER_IDENTITY_ROUTER_GATE,
    FK_IDENTITY_PIPELINE_BLOCKER_ROUTE_RECEIPT_GATE,
    FK_IDENTITY_PIPELINE_BLOCKER_OWNER_WORKER_GATE,
    FK_IDENTITY_PIPELINE_BLOCKER_OWNER_OUTPUT_SEQUENCE_GATE,
    FK_IDENTITY_PIPELINE_BLOCKER_EVENT_PIPELINE_GATE,
    FK_IDENTITY_PIPELINE_BLOCKER_NORMAL_SHUTDOWN_GATE,
    FK_IDENTITY_PIPELINE_BLOCKER_QUIC_PARSER_INCOMPLETE,
    FK_IDENTITY_PIPELINE_BLOCKER_LOGICAL_EVENT_IDENTITY_NOT_CONNECTED,
    FK_IDENTITY_PIPELINE_BLOCKER_UNRESOLVED_QUIC,
    FK_IDENTITY_PIPELINE_BLOCKER_AMBIGUOUS_QUIC,
    FK_IDENTITY_PIPELINE_BLOCKER_PERFORMANCE_NOT_SEPARATE,
    FK_IDENTITY_PIPELINE_BLOCKER_PERFORMANCE_NOT_MEASURED,
    FK_IDENTITY_PIPELINE_BLOCKER_PERFORMANCE_FAILED,
    FK_IDENTITY_PIPELINE_BLOCKER_COUNT,
};

struct fk_identity_pipeline_contract_input {
    const char *contract_abi;

    /* Immutable experiment inputs, committed before READY. */
    bool experimental_path_connected;
    bool replay_artifact_frozen;
    bool replay_digest_precommitted;
    bool sidecar_artifact_frozen;
    bool sidecar_digest_precommitted;
    uint64_t expected_packets;
    uint64_t sequencer_consumed_packets;
    uint64_t ordered_data_observations;
    uint64_t ordered_skipped_observations;

    /* Exact topology: R RX + 1 identity + R owners + D detectors +
     * 1 aggregator + 1 main + optional 1 writer. */
    uint64_t rx_producers;
    uint64_t identity_workers;
    uint64_t owner_workers;
    uint64_t detector_workers;
    uint64_t aggregator_workers;
    uint64_t main_workers;
    bool writer_enabled;
    uint64_t writer_workers;
    uint64_t declared_required_lcores;
    uint64_t available_lcores;

    /* Bounded service/transport memory.  Each observed reservation must
     * equal its frozen configured value, each peak must fit, and configured
     * reservations plus unassigned bytes must exactly equal the ceiling. */
    bool service_memory_contract_precommitted;
    uint64_t service_memory_ceiling_bytes;
    uint32_t service_memory_component_count;
    struct fk_identity_pipeline_service_memory_receipt
        service_memory_components[FK_IDENTITY_SERVICE_COMPONENT_COUNT];
    uint64_t service_memory_unassigned_bytes;
    bool service_memory_separate_from_controlled_state_budget;
    uint64_t service_bytes_charged_to_controlled_state_budget;
    uint64_t controlled_state_budget_bytes;

    bool owner_hash_key_digest_precommitted;
    uint32_t owner_hash_key_digest_bytes;
    bool ordered_skip_api_connected;

    /* Retirement controls are value-only. Publication is one atomic
     * transaction with the observation that discovered them. */
    bool retirement_control_generation_complete;
    bool retirement_controls_all_visible;
    bool retirement_publication_transactional;
    uint64_t retirement_controls_generated;
    uint64_t retirement_controls_published;
    uint64_t retirement_controls_normally_processed;
    uint64_t retirement_controls_pending;

    /* Sole DATA/mbuf ownership equation. */
    uint64_t data_accepted;
    uint64_t data_normally_dequeued;
    uint64_t data_drained;
    uint64_t data_owned;

    /* Results from each component's own stricter terminal gate. */
    bool sequencer_gate_complete;
    bool dispatch_gate_complete;
    bool runtime_gate_complete;
    bool cid_gate_complete;
    bool binding_gate_complete;
    bool cleanup_gate_complete;
    bool identity_router_gate_complete;
    bool route_receipt_gate_complete;
    bool owner_worker_gate_complete;
    bool owner_output_sequence_gate_complete;
    bool event_pipeline_gate_complete;
    bool normal_shutdown_gate_complete;

    /* These are additionally required only for a complete-QUIC claim. */
    bool complete_quic_claim_requested;
    bool quic_parser_complete;
    bool logical_event_identity_connected;
    uint64_t unresolved_quic_packets;
    uint64_t ambiguous_quic_packets;

    /* Correctness never implies performance. */
    bool performance_claim_requested;
    bool performance_measurement_separate_from_correctness;
    bool performance_measurement_completed;
    bool performance_measurement_passed;
};

struct fk_identity_pipeline_contract_result {
    bool passed;
    enum fk_identity_pipeline_contract_blocker blocker;
    uint64_t required_lcores;
    uint64_t available_lcores;
    uint64_t service_memory_accounted_bytes;
    uint32_t service_memory_component_count;
    bool complete_quic_claim_authorized;
    bool performance_claim_authorized;
};

struct fk_identity_pipeline_contract_result
fk_identity_pipeline_contract_evaluate(
    const struct fk_identity_pipeline_contract_input *input);

const char *fk_identity_pipeline_contract_blocker_name(
    enum fk_identity_pipeline_contract_blocker blocker);

const char *fk_identity_pipeline_contract_abi(void);

const char *fk_identity_pipeline_service_component_name(
    enum fk_identity_pipeline_service_component component);

#ifdef __cplusplus
}
#endif

#endif
