#ifndef FLOWKEEP_FK_COMPONENT_STATE_H
#define FLOWKEEP_FK_COMPONENT_STATE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define FK_COMPONENT_CHECKPOINT_CAP 6u
#define FK_VALUE_EVICTION_DEFAULT_ETA 0.05f
#define FK_VALUE_EVICTION_DEFAULT_EPSILON 0.000001f
#define FK_VALUE_EVICTION_DEFAULT_MAX_VICTIMS 64u

/*
 * The optional evidence state is deliberately represented as a bit mask.
 * CORE is mandatory and therefore is not a bit in the optional mask.
 */
enum fk_component_mask {
    FK_COMPONENT_NONE = 0u,
    FK_COMPONENT_STAT = 1u << 0,
    FK_COMPONENT_SEQ = 1u << 1,
    FK_COMPONENT_JA4 = 1u << 2,
    FK_COMPONENT_FULL =
        FK_COMPONENT_STAT | FK_COMPONENT_SEQ | FK_COMPONENT_JA4,
};

enum fk_memory_component {
    FK_MEMORY_FLOW_TABLE = 0,
    FK_MEMORY_CORE = 1,
    FK_MEMORY_STAT = 2,
    FK_MEMORY_SEQ = 3,
    FK_MEMORY_JA4 = 4,
    FK_MEMORY_CID_MAP = 5,
    FK_MEMORY_LEASE = 6,
    FK_MEMORY_LEDGER = 7,
    FK_MEMORY_COMPONENT_COUNT = 8,
};

enum fk_missing_reason {
    FK_MISSING_PRESENT = 0,
    FK_MISSING_NOT_SELECTED = 1,
    FK_MISSING_NOT_APPLICABLE = 2,
    FK_MISSING_NOT_YET_AVAILABLE = 3,
    FK_MISSING_LOST_OR_FAILED = 4,
};

enum fk_pressure_mode {
    FK_PRESSURE_NORMAL = 0,
    FK_PRESSURE_PRESSURE = 1,
    FK_PRESSURE_OVERLOAD = 2,
};

enum fk_transition_result {
    FK_TRANSITION_APPLIED = 0,
    FK_TRANSITION_NO_CHANGE = 1,
    FK_TRANSITION_BUDGET_REJECTED = 2,
    FK_TRANSITION_ILLEGAL_MASK = 3,
    FK_TRANSITION_NON_MONOTONE = 4,
    FK_TRANSITION_EXPIRED = 5,
    FK_TRANSITION_STORAGE_FAILED = 6,
};

struct fk_component_bytes {
    uint64_t stat_bytes;
    uint64_t seq_bytes;
    uint64_t ja4_bytes;
};

struct fk_component_owned_bytes {
    uint32_t stat_bytes;
    uint32_t seq_bytes;
    uint32_t ja4_bytes;
};

struct fk_budget_snapshot {
    uint64_t budget_bytes;
    uint64_t used_bytes;
    uint64_t peak_bytes;
    uint64_t used_by_component[FK_MEMORY_COMPONENT_COUNT];
    uint64_t peak_by_component[FK_MEMORY_COMPONENT_COUNT];
    uint64_t reserve_checks;
    uint64_t reserve_rejects;
    uint64_t release_errors;
    uint64_t hard_budget_violations;
};

struct fk_budget_calibration {
    uint64_t mandatory_bytes;
    uint64_t full_state_bytes;
    uint64_t low_budget_bytes;
    bool mandatory_fits;
    bool optional_competition_exists;
    bool suitable_for_retention_q2;
};

struct fk_component_flow {
    uint64_t absolute_deadline_ns;
    /* Latest causal-checkpoint action-value vector.  The historical field
     * name is retained for source/ABI compatibility, but learned FLOWKEEP
     * refreshes this vector at every due checkpoint.  Each refresh sees only
     * the prefix available at that checkpoint; released evidence remains
     * irrecoverable.  Cross-flow replacement must update its heap keys in the
     * same transaction as this vector (see the compact-flow-table wrapper). */
    float initial_action_values[8];
    struct fk_component_owned_bytes owned;
    uint8_t mask;
    uint8_t decision_started : 1;
    uint8_t observation_complete : 1;
    uint8_t initial_action_values_valid : 1;
    /* Zero means historical logical action values; one means physical-
     * residency transition potentials used only by replacement. */
    uint8_t replacement_values_physical : 1;
    uint8_t compact_flags_reserved : 4;
    uint8_t checkpoint_index;
    uint8_t missing_reason[3];
    uint8_t next_checkpoint_packet;
    uint8_t component_start_packet[3];
    /*
     * Evidence that was actually retained and then released is
     * irrecoverable. Formal FLOWKEEP also marks components omitted by the
     * first checkpoint as irrecoverable. The explicit non-formal prospective
     * mode may start a never-selected component later; component_start_packet
     * then records its left-censoring for missing-aware inference.
     */
    uint8_t released_mask;
};

struct fk_component_policy_config {
    uint32_t checkpoints[FK_COMPONENT_CHECKPOINT_CAP];
    uint8_t checkpoint_count;
    uint64_t maximum_lifetime_ns;
    uint8_t maximum_components[3];
    float minimum_utility[3];
    /*
     * Formal FLOWKEEP sets this to zero: the first checkpoint is an
     * irreversible admission decision, and later checkpoints may only keep
     * or release admitted evidence.  A value of one retains the historical
     * left-censored prospective-start mode for explicitly non-formal studies.
     */
    uint8_t allow_prospective_late_start;
    /*
     * Restrict a decision to one nested CORE->single->pair->FULL path in
     * the three-bit evidence lattice.  This gives the per-flow selector the
     * stack property: increasing byte headroom can keep the same action or
     * a strict superset, but cannot switch to an incomparable evidence set.
     * The path is selected from the causal utilities available at the
     * current checkpoint and is shared by learned and baseline policies.
     */
    uint8_t enforce_budget_monotone_chain;
    /* Candidate ranking mode:
     *   0: raw causal utility;
     *   1: causal utility per retained byte;
     *   2: online budget-adaptive ranking.  NORMAL ranks raw causal utility
     *      so spare hard-budget capacity can protect additional evidence;
     *      PRESSURE/OVERLOAD rank utility per byte so the current causal value
     *      estimate degrades compactly as optional-state occupancy rises.
     * Mode 2 consumes only causal prefix values and live allocator pressure;
     * it never observes labels, suffix packets, or future occupancy. */
    uint8_t rank_by_marginal_value_per_byte;
    /*
     * Learned FLOWKEEP may protect a small evidence floor while the first
     * prefix is still too short to value irreversible releases reliably.
     * At checkpoints strictly before provisional_until_packet, the
     * controller first tries (model_request | provisional_minimum_mask),
     * then the minimum mask, before the ordinary learned fallbacks.  Hard
     * budget, typed-pool availability and the pressure component cap remain
     * authoritative.  Zero/zero disables the mechanism; deterministic
     * baselines never consume it.
     */
    uint8_t provisional_minimum_mask;
    uint8_t provisional_until_packet;
    /* FLOWKEEP is a pressure-management policy, not an unconditional feature
     * compressor.  When enabled, NORMAL mode first retains every applicable
     * component that has not been irreversibly released.  The learned value
     * ranking becomes authoritative only in PRESSURE/OVERLOAD, where evidence
     * actually competes for the controlled budget. */
    uint8_t preserve_full_state_in_normal;
};

#define FK_COMPONENT_RANK_RAW_VALUE 0u
#define FK_COMPONENT_RANK_VALUE_PER_BYTE 1u
#define FK_COMPONENT_RANK_BUDGET_ADAPTIVE 2u

struct fk_component_candidate {
    uint8_t mask;
    uint8_t reserved[3];
    float utility;
    float rank_value;
};

struct fk_component_decision {
    uint8_t selected_mask;
    uint8_t candidates_considered;
    uint8_t budget_rejections;
    uint8_t reserved;
    float selected_utility;
    enum fk_transition_result result;
};

struct fk_state_budget;

struct fk_state_budget *fk_state_budget_create(uint64_t budget_bytes);

void fk_state_budget_destroy(struct fk_state_budget *budget);

uint64_t fk_state_budget_overhead_bytes(void);

bool fk_state_budget_try_reserve(
    struct fk_state_budget *budget,
    enum fk_memory_component component,
    uint64_t bytes);

bool fk_state_budget_release(
    struct fk_state_budget *budget,
    enum fk_memory_component component,
    uint64_t bytes);

/* Apply a multi-component release/reservation as one budget transaction.
 * The final state is installed only after every component balance and the
 * hard total ceiling have been validated.  This is the budget half of the
 * cross-flow atomic evidence hand-off; no transient over-budget state is
 * exposed when released bytes finance an incoming state. */
bool fk_state_budget_apply_transaction(
    struct fk_state_budget *budget,
    const uint64_t release_by_component[FK_MEMORY_COMPONENT_COUNT],
    const uint64_t reserve_by_component[FK_MEMORY_COMPONENT_COUNT]);

void fk_state_budget_snapshot(
    const struct fk_state_budget *budget,
    struct fk_budget_snapshot *snapshot);

void fk_budget_calibrate(
    uint64_t mandatory_bytes,
    uint64_t full_state_bytes,
    uint64_t low_budget_bytes,
    struct fk_budget_calibration *calibration);

bool fk_component_policy_config_valid(
    const struct fk_component_policy_config *config);

void fk_component_flow_init(
    struct fk_component_flow *flow,
    uint64_t first_timestamp_ns,
    const struct fk_component_policy_config *config);

bool fk_component_flow_decision_due(
    const struct fk_component_flow *flow,
    uint32_t packet_count,
    uint64_t timestamp_ns);

bool fk_component_flow_expired(
    const struct fk_component_flow *flow,
    uint64_t timestamp_ns);

enum fk_transition_result fk_component_flow_transition(
    struct fk_state_budget *budget,
    struct fk_component_flow *flow,
    uint8_t desired_mask,
    const struct fk_component_bytes *component_bytes,
    bool ja4_applicable,
    uint32_t packet_count,
    uint64_t timestamp_ns,
    const struct fk_component_policy_config *config);

/* Pure transition planner.  It never changes the budget or source flow.
 * release_bytes/reserve_bytes use STAT,SEQ,JA4 order.  A semantic rejection
 * is returned in result while the function itself reports valid arguments.
 * The planned copy can be installed after typed storage and the budget
 * transaction are guaranteed, preventing a split logical/physical commit. */
bool fk_component_flow_plan_transition(
    const struct fk_component_flow *flow,
    uint8_t desired_mask,
    const struct fk_component_bytes *component_bytes,
    bool ja4_applicable,
    uint32_t packet_count,
    uint64_t timestamp_ns,
    const struct fk_component_policy_config *config,
    struct fk_component_flow *planned,
    uint64_t release_bytes[3],
    uint64_t reserve_bytes[3],
    enum fk_transition_result *result);

/*
 * utilities[mask] is the action-conditioned event-loss reduction after
 * resource shadow prices have been applied.  The controller considers only
 * protocol-legal masks, refuses to reacquire released history, and falls
 * back to a cheaper action when the atomic budget reservation fails.
 */
bool fk_component_choose_and_transition(
    struct fk_state_budget *budget,
    struct fk_component_flow *flow,
    const float utilities[8],
    const struct fk_component_bytes *component_bytes,
    bool ja4_applicable,
    enum fk_pressure_mode pressure,
    uint32_t packet_count,
    uint64_t timestamp_ns,
    const struct fk_component_policy_config *config,
    struct fk_component_decision *decision);

/* Pure, deterministic candidate ordering used by the global replacement
 * planner before it mutates any resident.  It applies the exact same
 * protocol, pressure, monotonic-chain and value/byte ordering as the local
 * transition path, but performs no reservation or release. */
size_t fk_component_rank_candidates(
    const struct fk_component_flow *flow,
    const float utilities[8],
    const struct fk_component_bytes *component_bytes,
    uint8_t available_mask,
    bool ja4_applicable,
    enum fk_pressure_mode pressure,
    const struct fk_component_policy_config *config,
    struct fk_component_candidate candidates[8]);

/* Freeze a causal first-prefix value vector.  Repeated calls must be
 * bit-identical (within a small floating-point tolerance) and never rewrite
 * the resident value used by cross-flow replacement. */
bool fk_component_flow_freeze_initial_values(
    struct fk_component_flow *flow,
    const float action_values[8]);

/* Replace the cached vector with the latest causal-checkpoint estimate.
 * This low-level helper does not maintain cross-flow heap indexes; production
 * controllers must call fk_compact_flow_table_refresh_action_values(). */
bool fk_component_flow_update_action_values(
    struct fk_component_flow *flow,
    const float action_values[8]);

bool fk_component_flow_update_transition_values(
    struct fk_component_flow *flow,
    const float transition_potentials[8]);

/* V_t(m)-V_t(m\\c), clamped at zero, from the latest checkpoint vector. */
bool fk_component_flow_removal_loss(
    const struct fk_component_flow *flow,
    uint8_t mask,
    uint8_t component,
    float *loss);

void fk_component_flow_mark_loss(
    struct fk_component_flow *flow,
    uint8_t affected_mask);

bool fk_component_flow_shrink_owned(
    struct fk_state_budget *budget,
    struct fk_component_flow *flow,
    uint8_t component,
    uint32_t new_bytes);

bool fk_component_flow_release_provisional(
    struct fk_state_budget *budget,
    struct fk_component_flow *flow,
    uint8_t component);

/* Release one owned component and make the loss irreversible.  This is the
 * budget-ledger half of a table-level atomic replacement plan; the owning
 * table releases the corresponding typed-pool slab in the same commit. */
bool fk_component_flow_release_irreversible(
    struct fk_state_budget *budget,
    struct fk_component_flow *flow,
    uint8_t component);

void fk_component_flow_release_all(
    struct fk_state_budget *budget,
    struct fk_component_flow *flow);

const char *fk_component_mask_name(uint8_t mask);

#ifdef __cplusplus
}
#endif

#endif
