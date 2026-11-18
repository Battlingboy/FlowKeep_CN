#ifndef FLOWKEEP_FK_FORMAL_GATE_H
#define FLOWKEEP_FK_FORMAL_GATE_H

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * One fail-closed decision shared by the pre-commit FKERES gate, the metrics
 * receipt, and the formal process exit status.  Keeping this policy in a
 * small DPDK-independent module prevents those three consumers from silently
 * drifting apart.
 */
enum fk_formal_budget_blocker {
    FK_FORMAL_BUDGET_BLOCKER_NONE = 0,
    FK_FORMAL_BUDGET_BLOCKER_BASE_ACCOUNTING,
    FK_FORMAL_BUDGET_BLOCKER_QUIC_CID_NOT_CONNECTED,
    FK_FORMAL_BUDGET_BLOCKER_QUIC_IDENTITY_PARSER_INCOMPLETE,
    FK_FORMAL_BUDGET_BLOCKER_QUIC_IDENTITY_SEMANTIC_ORDERING_NOT_CONNECTED,
    FK_FORMAL_BUDGET_BLOCKER_QUIC_CID_NOT_BUDGETED,
    FK_FORMAL_BUDGET_BLOCKER_OWNER_FLOW_BINDINGS_NOT_CONNECTED,
    FK_FORMAL_BUDGET_BLOCKER_OWNER_FLOW_BINDINGS_NOT_BUDGETED,
    FK_FORMAL_BUDGET_BLOCKER_IDENTITY_LOSS_ACCOUNTING_INCOMPLETE,
    FK_FORMAL_BUDGET_BLOCKER_IDENTITY_INTEGRITY_FAILURE,
    FK_FORMAL_BUDGET_BLOCKER_HARD_BUDGET_VIOLATION,
};

struct fk_formal_budget_gate_input {
    bool base_accounting_valid;
    bool quic_cid_map_connected;
    bool quic_cid_map_in_controlled_ceiling;
    uint64_t quic_cid_map_reserved_bytes;
    uint64_t hard_budget_violations;
    /*
     * True only when short-header DCID length and authenticated
     * NEW_CONNECTION_ID/RETIRE_CONNECTION_ID updates reach the directory.
     * Clear long-header CID inspection alone must leave this false.
     */
    bool quic_identity_parser_complete;
    /*
     * True only when all identity mutations and packet observations are
     * serialized in the same semantic order consumed by the flow owner.
     */
    bool quic_identity_semantic_ordering_connected;
    /* Owner-local logical-connection to FlowTable-handle directory. */
    bool owner_flow_bindings_connected;
    bool owner_flow_bindings_in_controlled_ceiling;
    uint64_t owner_flow_bindings_reserved_bytes;
    /* Every fail-closed identity rejection/loss must reach the receipt. */
    bool identity_loss_accounting_complete;
    /* Aggregate of conservation, stale-handle, and association failures. */
    uint64_t identity_integrity_failures;
};

struct fk_formal_budget_gate_result {
    bool passed;
    enum fk_formal_budget_blocker blocker;
};

struct fk_formal_budget_gate_result fk_formal_budget_gate_evaluate(
    const struct fk_formal_budget_gate_input *input);

/* Shared byte-accounting predicate used before FKERES commit and again by
 * the metrics/exit receipt.  Every addition is overflow checked. */
struct fk_controlled_budget_accounting_input {
    uint64_t controlled_ceiling_bytes;
    uint64_t configured_actor_reserved_bytes;
    uint64_t observed_actor_reserved_bytes;
    uint64_t mandatory_bytes;
    uint64_t pool_reserved_bytes;
    uint64_t configured_partition_unassigned_bytes;
    uint64_t pool_unassigned_bytes;
    uint64_t flow_budget_bytes;
    uint64_t flow_peak_bytes;
    uint64_t configured_quic_cid_reserved_bytes;
    uint64_t observed_quic_cid_reserved_bytes;
    uint64_t configured_quic_presentation_path_reserved_bytes;
    uint64_t observed_quic_presentation_path_reserved_bytes;
    uint64_t configured_owner_flow_bindings_reserved_bytes;
    uint64_t observed_owner_flow_bindings_reserved_bytes;
    uint64_t configured_terminal_tail_accelerator_reserved_bytes;
    uint64_t observed_terminal_tail_accelerator_reserved_bytes;
};

bool fk_controlled_budget_accounting_valid(
    const struct fk_controlled_budget_accounting_input *input);

struct fk_pipeline_readiness_gate_input {
    uint16_t expected_rx_workers;
    uint16_t observed_rx_workers;
    uint16_t expected_detection_workers;
    uint16_t observed_detection_workers;
    bool aggregator_ready;
    bool barrier_passed;
    bool run_released;
};

bool fk_pipeline_readiness_gate_valid(
    const struct fk_pipeline_readiness_gate_input *input);

struct fk_nic_packet_conservation_gate_input {
    bool formal_mode;
    bool port_stop_succeeded;
    bool baseline_valid;
    bool end_valid;
    bool counters_monotonic;
    uint64_t received_packets;
    uint64_t processed_packets;
    uint64_t missed_packets;
    uint64_t input_errors;
    uint64_t rx_nombuf;
    bool drop_xstat_resolved;
    bool drop_xstat_baseline_valid;
    bool drop_xstat_end_valid;
    bool drop_xstat_monotonic;
    uint64_t drop_xstat_delta;
};

bool fk_nic_packet_conservation_gate_valid(
    const struct fk_nic_packet_conservation_gate_input *input);

/* The formal NIC scope is closed at a physical capture endpoint: counters are
 * reset/read after every data-path lcore is ready but before run release, then
 * the port is stopped exactly once after exact expected EOF and every RX pump
 * has joined, and before waiting for the closed association input to drain.
 * Only that baseline-to-stopped-port interval may feed the zero-loss/partition
 * gate.  A later service-drain snapshot is never an input to this gate. */
struct fk_nic_scoped_packet_conservation_gate_input {
    bool formal_mode;
    bool baseline_after_all_workers_ready_pre_release;
    bool exact_expected_eof_observed;
    bool all_rx_pumps_joined;
    uint32_t port_stop_call_count;
    bool capture_end_after_port_stop;
    uint64_t baseline_monotonic_ns;
    uint64_t exact_expected_eof_monotonic_ns;
    uint64_t rx_pumps_joined_monotonic_ns;
    uint64_t capture_end_monotonic_ns;
    bool port_stop_succeeded;
    bool baseline_valid;
    bool end_valid;
    bool counters_monotonic;
    uint64_t received_packets;
    uint64_t scoped_processed_packets;
    uint64_t maximum_scope_boundary_packets;
    uint64_t missed_packets;
    uint64_t input_errors;
    uint64_t rx_nombuf;
    bool drop_xstat_resolved;
    bool drop_xstat_baseline_valid;
    bool drop_xstat_end_valid;
    bool drop_xstat_monotonic;
    uint64_t drop_xstat_delta;
};

bool fk_nic_scoped_packet_conservation_gate_valid(
    const struct fk_nic_scoped_packet_conservation_gate_input *input);

const char *fk_formal_budget_blocker_name(
    enum fk_formal_budget_blocker blocker);

/* Non-formal smoke/Validation artifacts remain usable diagnostics. */
bool fk_formal_budget_allows_commit(
    bool formal_mode,
    const struct fk_formal_budget_gate_result *result);

enum fk_formal_rss_owner_blocker {
    FK_FORMAL_RSS_OWNER_BLOCKER_NONE = 0,
    FK_FORMAL_RSS_OWNER_BLOCKER_INVALID_TOPOLOGY,
    FK_FORMAL_RSS_OWNER_BLOCKER_ALGORITHM_UNSUPPORTED,
    FK_FORMAL_RSS_OWNER_BLOCKER_READBACK_FAILED,
    FK_FORMAL_RSS_OWNER_BLOCKER_ALGORITHM_MISMATCH,
    FK_FORMAL_RSS_OWNER_BLOCKER_HASH_FIELDS_MISMATCH,
    FK_FORMAL_RSS_OWNER_BLOCKER_HASH_KEY_BINDING,
};

struct fk_formal_rss_owner_gate_input {
    uint16_t worker_count;
    bool requested_algorithm_supported;
    bool runtime_query_succeeded;
    uint32_t requested_algorithm;
    uint32_t observed_algorithm;
    uint64_t requested_hash_fields;
    uint64_t observed_hash_fields;
    uint32_t requested_hash_key_length;
    uint32_t observed_hash_key_length;
    bool observed_hash_key_digest_valid;
};

struct fk_formal_rss_owner_gate_result {
    bool passed;
    enum fk_formal_rss_owner_blocker blocker;
};

struct fk_formal_rss_owner_gate_result
fk_formal_rss_owner_gate_evaluate(
    const struct fk_formal_rss_owner_gate_input *input);

const char *fk_formal_rss_owner_blocker_name(
    enum fk_formal_rss_owner_blocker blocker);

#ifdef __cplusplus
}
#endif

#endif
