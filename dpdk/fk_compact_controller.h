#ifndef FLOWKEEP_FK_COMPACT_CONTROLLER_H
#define FLOWKEEP_FK_COMPACT_CONTROLLER_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "fk_compact_flow_table.h"
#include "fk_cpu_pipeline.h"

#ifdef __cplusplus
extern "C" {
#endif

struct fk_compact_controller_result {
    bool decision_due;
    bool applied;
    uint8_t previous_mask;
    uint8_t final_mask;
    uint8_t released_mask_before;
    uint8_t released_mask_after;
    uint8_t materializable_mask;
    uint8_t pool_unavailable_mask;
    uint8_t observation_complete;
    /* Policy request inside the trained protocol-applicable action domain,
     * but before irreversible release, typed-pool capacity, and controlled-
     * budget feasibility. */
    uint8_t requested_mask;
    uint8_t protocol_applicable_mask;
    uint8_t missing_reason[3];
    uint64_t controlled_bytes_before;
    uint64_t controlled_bytes_after;
    struct fk_component_decision decision;
    uint32_t lru_victims_released;
    uint32_t lfu_victims_released;
    uint32_t fifo_victims_released;
    uint32_t seeded_random_victims_released;
    uint32_t clock_victims_released;
    uint32_t two_q_victims_released;
    uint32_t arc_victims_released;
    uint32_t gdsf_victims_released;
    uint32_t value_victims_released;
    uint32_t value_victim_probes;
    uint8_t value_replacement_attempted;
    uint8_t value_replacement_committed;
    uint8_t transition_value_fallback_attempted;
    uint8_t transition_value_fallback_succeeded;
    float incoming_bundle_gain;
    float victim_total_loss;
    float value_eviction_hysteresis_eta;
    float requested_utility;
};

enum fk_compact_retention_policy_kind {
    FK_COMPACT_POLICY_FLOWKEEP = 0,
    FK_COMPACT_POLICY_LRU = 1,
    FK_COMPACT_POLICY_FIXED_TTL = 2,
    FK_COMPACT_POLICY_PROTOCOL_AWARE = 3,
    FK_COMPACT_POLICY_PROTOCOL_DEADLINE = 4,
    FK_COMPACT_POLICY_HANDSHAKE_ONLY = 5,
    FK_COMPACT_POLICY_FULL_STATE = 6,
    FK_COMPACT_POLICY_SUMMARY_ONLY = 7,
    FK_COMPACT_POLICY_HISTORY_ONLY = 8,
    FK_COMPACT_POLICY_SUMMARY_HISTORY = 9,
    FK_COMPACT_POLICY_SUMMARY_HANDSHAKE = 10,
    FK_COMPACT_POLICY_HISTORY_HANDSHAKE = 11,
    /* Mandatory FlowTable CORE only; retain no optional evidence. */
    FK_COMPACT_POLICY_CORE_ONLY = 12,
    /* Prefix-only learned counterfactual detector-loss divided by the exact
     * retained optional-component bytes.  This is deliberately not named
     * score_per_byte: the live detector score is produced after retention
     * and is therefore unavailable at the retention checkpoint. */
    FK_COMPACT_POLICY_LEARNED_DETECTION_LOSS_PER_BYTE = 13,
    FK_COMPACT_POLICY_LFU = 14,
    FK_COMPACT_POLICY_FIFO = 15,
    FK_COMPACT_POLICY_SEEDED_RANDOM_RETENTION = 16,
    FK_COMPACT_POLICY_CLOCK = 17,
    FK_COMPACT_POLICY_TWO_Q = 18,
    FK_COMPACT_POLICY_ARC = 19,
    FK_COMPACT_POLICY_GDSF = 20,
};

/* One canonical CLI spelling/mapping shared by every native runner. */
bool fk_compact_retention_policy_parse(
    const char *name,
    enum fk_compact_retention_policy_kind *kind);

/* Learned policies require an action/value selector.  Deterministic
 * baselines must never enter that inference path. */
bool fk_compact_retention_policy_uses_learned_selector(
    enum fk_compact_retention_policy_kind kind);

struct fk_compact_baseline_policy_config {
    enum fk_compact_retention_policy_kind kind;
    uint64_t fixed_ttl_ns;
    uint32_t maximum_lru_victims_per_decision;
    /* Frozen externally.  It is consumed only by
     * SEEDED_RANDOM_RETENTION and never advances mutable PRNG state. */
    uint64_t seeded_random_seed;
    uint8_t seeded_random_seed_precommitted;
    uint8_t fixed_state_lru_replacement;
};

/*
 * Execute one checkpoint decision and atomically bind the logical mask to
 * its concrete STAT/SEQ/JA4 storage. The caller supplies only causal prefix
 * features; the controller refuses calls between checkpoints.
 */
bool fk_compact_controller_checkpoint(
    struct fk_cpu_pipeline *pipeline,
    struct fk_compact_flow_table *table,
    struct fk_compact_flow_handle handle,
    const float *features,
    size_t feature_count,
    const struct fk_resource_costs *resource_costs,
    bool ja4_applicable,
    enum fk_pressure_mode pressure,
    uint32_t packet_count,
    uint64_t timestamp_ns,
    const struct fk_component_policy_config *config,
    struct fk_compact_controller_result *result);

/* Offline one-step oracle variant; only value-model inference is bypassed. */
bool fk_compact_controller_checkpoint_from_values(
    struct fk_compact_flow_table *table,
    struct fk_compact_flow_handle handle,
    const float *action_values,
    size_t action_value_count,
    const struct fk_resource_costs *resource_costs,
    bool ja4_applicable,
    enum fk_pressure_mode pressure,
    uint32_t packet_count,
    uint64_t timestamp_ns,
    const struct fk_component_policy_config *config,
    struct fk_compact_controller_result *result);

/* Development-only causal intervention used by the source-record suffix
 * executor.  It executes the real checkpoint transaction while forcing the
 * candidate to keep exactly its already-resident mask.  The function cannot
 * materialize released evidence, select a replacement victim, or consult an
 * action model.  Those restrictions make ``keep_victim`` a single causal
 * change: reject the incoming candidate state request and leave every
 * resident victim untouched. */
bool fk_compact_controller_checkpoint_keep_existing_intervention(
    struct fk_compact_flow_table *table,
    struct fk_compact_flow_handle handle,
    const struct fk_resource_costs *resource_costs,
    bool ja4_applicable,
    enum fk_pressure_mode pressure,
    uint32_t packet_count,
    uint64_t timestamp_ns,
    const struct fk_component_policy_config *config,
    struct fk_compact_controller_result *result);

/* Execute a deterministic baseline through the same component transition,
 * typed pools and hard-budget accounting used by learned FLOWKEEP. */
bool fk_compact_controller_checkpoint_baseline(
    struct fk_compact_flow_table *table,
    struct fk_compact_flow_handle handle,
    const struct fk_resource_costs *resource_costs,
    bool ja4_applicable,
    enum fk_pressure_mode pressure,
    uint32_t packet_count,
    uint64_t timestamp_ns,
    uint64_t flow_age_ns,
    const struct fk_component_policy_config *component_config,
    const struct fk_compact_baseline_policy_config *baseline_config,
    struct fk_compact_controller_result *result);

/* Opt-in controller entry points. true + persistence_pending means valid
 * deferred work, NOT applied: retain evidence and the checkpoint, retry on
 * the same causal input before advancing this flow. No alternative candidate
 * is selected while waiting. Old result struct and entry points are unchanged.
 * Baseline persistent entry accepts only LRU/CLOCK/2Q. */
bool fk_compact_controller_checkpoint_persistent(
    struct fk_cpu_pipeline *pipeline,
    struct fk_compact_flow_table *table,
    struct fk_compact_flow_handle handle,
    const float *features,
    size_t feature_count,
    const struct fk_resource_costs *resource_costs,
    bool ja4_applicable,
    enum fk_pressure_mode pressure,
    uint32_t packet_count,
    uint64_t timestamp_ns,
    const struct fk_component_policy_config *config,
    struct fk_compact_controller_result *result,
    const struct fk_compact_release_guard *release_guard, bool *persistence_pending);

bool fk_compact_controller_checkpoint_from_values_persistent(
    struct fk_compact_flow_table *table,
    struct fk_compact_flow_handle handle,
    const float *action_values,
    size_t action_value_count,
    const struct fk_resource_costs *resource_costs,
    bool ja4_applicable,
    enum fk_pressure_mode pressure,
    uint32_t packet_count,
    uint64_t timestamp_ns,
    const struct fk_component_policy_config *config,
    struct fk_compact_controller_result *result,
    const struct fk_compact_release_guard *release_guard, bool *persistence_pending);

bool fk_compact_controller_checkpoint_baseline_persistent(
    struct fk_compact_flow_table *table,
    struct fk_compact_flow_handle handle,
    const struct fk_resource_costs *resource_costs,
    bool ja4_applicable,
    enum fk_pressure_mode pressure,
    uint32_t packet_count,
    uint64_t timestamp_ns,
    uint64_t flow_age_ns,
    const struct fk_component_policy_config *component_config,
    const struct fk_compact_baseline_policy_config *baseline_config,
    struct fk_compact_controller_result *result,
    const struct fk_compact_release_guard *release_guard, bool *persistence_pending);

#ifdef __cplusplus
}
#endif

#endif
