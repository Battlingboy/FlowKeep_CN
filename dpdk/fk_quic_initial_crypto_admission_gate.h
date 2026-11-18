#ifndef FLOWKEEP_FK_QUIC_INITIAL_CRYPTO_ADMISSION_GATE_H
#define FLOWKEEP_FK_QUIC_INITIAL_CRYPTO_ADMISSION_GATE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define FK_QUIC_INITIAL_CRYPTO_ADMISSION_GATE_ABI_VERSION 1u
#define FK_QUIC_INITIAL_CRYPTO_ADMISSION_KEY_BYTES 16u
#define FK_QUIC_INITIAL_CRYPTO_ADMISSION_TAG_BYTES 16u
#define FK_QUIC_INITIAL_CRYPTO_ADMISSION_MAX_PREFIX_SLOTS 65536u
#define FK_QUIC_INITIAL_CRYPTO_ADMISSION_MIN_INPUT_BYTES 1u
#define FK_QUIC_INITIAL_CRYPTO_ADMISSION_CONFIG_BYTES 136u
#define FK_QUIC_INITIAL_CRYPTO_ADMISSION_REQUEST_V1_BYTES 72u
#define FK_QUIC_INITIAL_CRYPTO_ADMISSION_RECEIPT_V1_BYTES 112u
#define FK_QUIC_INITIAL_CRYPTO_ADMISSION_BEGIN_RESULT_V1_BYTES 128u
#define FK_QUIC_INITIAL_CRYPTO_ADMISSION_STATS_BYTES 656u

/* This gate is called if and only if the composition intends to execute QUIC
 * Initial cryptography.  Every first ALLOW is metered.  A known CID which can
 * be routed without any crypto does not call this API and must be counted by
 * a separate composition-level known_cid_no_crypto metric.  A known path
 * which still needs authentication is not exempt from this gate. */

enum fk_quic_initial_crypto_admission_decision {
    FK_QUIC_INITIAL_CRYPTO_ADMISSION_REJECT = 0,
    FK_QUIC_INITIAL_CRYPTO_ADMISSION_ALLOW = 1,
    /* Reserved for a future scheduler which can bypass a blocked sequence.
     * The strict ordered v1 gate never emits DEFER: resource pressure is an
     * explicit REJECT so the caller can publish an ordered skip. */
    FK_QUIC_INITIAL_CRYPTO_ADMISSION_DEFER = 2,
};

enum fk_quic_initial_crypto_admission_reason {
    FK_QUIC_INITIAL_CRYPTO_REASON_NONE = 0,
    FK_QUIC_INITIAL_CRYPTO_REASON_CHARGED_PREFIX_CRYPTO = 1,
    FK_QUIC_INITIAL_CRYPTO_REASON_IDEMPOTENT_ACTIVE_RETRY = 2,
    FK_QUIC_INITIAL_CRYPTO_REASON_GLOBAL_TOKENS_EXHAUSTED = 3,
    FK_QUIC_INITIAL_CRYPTO_REASON_PREFIX_CREDITS_EXHAUSTED = 4,
    FK_QUIC_INITIAL_CRYPTO_REASON_PREFIX_TABLE_PRESSURE = 5,
    FK_QUIC_INITIAL_CRYPTO_REASON_CRYPTO_INPUT_TOO_LARGE = 6,
    FK_QUIC_INITIAL_CRYPTO_REASON_INVALID_REQUEST = 7,
    FK_QUIC_INITIAL_CRYPTO_REASON_ACTIVE_DESCRIPTOR_MISMATCH = 8,
    FK_QUIC_INITIAL_CRYPTO_REASON_SEQUENCE_REPLAY = 9,
    FK_QUIC_INITIAL_CRYPTO_REASON_COMPLETED_DESCRIPTOR_REPLAY = 10,
    FK_QUIC_INITIAL_CRYPTO_REASON_CLOCK_REGRESSION = 11,
    FK_QUIC_INITIAL_CRYPTO_REASON_STOPPED = 12,
    FK_QUIC_INITIAL_CRYPTO_REASON_TERMINAL = 13,
    FK_QUIC_INITIAL_CRYPTO_REASON_COUNTER_OVERFLOW = 14,
    FK_QUIC_INITIAL_CRYPTO_REASON_INTERNAL_FAILURE = 15,
    FK_QUIC_INITIAL_CRYPTO_REASON_COUNT = 16,
};

enum fk_quic_initial_crypto_completion_outcome {
    FK_QUIC_INITIAL_CRYPTO_COMPLETION_AUTHENTICATED = 1,
    FK_QUIC_INITIAL_CRYPTO_COMPLETION_INVALID_AUTH = 2,
    FK_QUIC_INITIAL_CRYPTO_COMPLETION_CRYPTO_FAILURE = 3,
    FK_QUIC_INITIAL_CRYPTO_COMPLETION_DOWNSTREAM_ABORTED = 4,
};

enum fk_quic_initial_crypto_completion_result {
    FK_QUIC_INITIAL_CRYPTO_COMPLETE_INVALID = 0,
    FK_QUIC_INITIAL_CRYPTO_COMPLETED = 1,
    FK_QUIC_INITIAL_CRYPTO_COMPLETE_ALREADY_COMPLETED = 2,
    FK_QUIC_INITIAL_CRYPTO_COMPLETE_WRONG_THREAD = 3,
    FK_QUIC_INITIAL_CRYPTO_COMPLETE_STOPPED = 4,
    FK_QUIC_INITIAL_CRYPTO_COMPLETE_TERMINAL = 5,
};

enum fk_quic_initial_crypto_gate_lifecycle {
    FK_QUIC_INITIAL_CRYPTO_GATE_ACCEPTING = 0,
    FK_QUIC_INITIAL_CRYPTO_GATE_SEALED_NORMAL = 1,
    FK_QUIC_INITIAL_CRYPTO_GATE_SEALED_ABORT = 2,
};

enum fk_quic_initial_crypto_terminal_reason {
    FK_QUIC_INITIAL_CRYPTO_TERMINAL_NONE = 0,
    FK_QUIC_INITIAL_CRYPTO_TERMINAL_OWNER_THREAD = 1,
    FK_QUIC_INITIAL_CRYPTO_TERMINAL_CLOCK_REGRESSION = 2,
    FK_QUIC_INITIAL_CRYPTO_TERMINAL_DESCRIPTOR_MISMATCH = 3,
    FK_QUIC_INITIAL_CRYPTO_TERMINAL_SEQUENCE_REPLAY = 4,
    FK_QUIC_INITIAL_CRYPTO_TERMINAL_RECEIPT_MISMATCH = 5,
    FK_QUIC_INITIAL_CRYPTO_TERMINAL_COUNTER_OVERFLOW = 6,
    FK_QUIC_INITIAL_CRYPTO_TERMINAL_ARITHMETIC_OVERFLOW = 7,
    FK_QUIC_INITIAL_CRYPTO_TERMINAL_INTERNAL = 8,
};

struct fk_quic_initial_crypto_admission_gate_config {
    uint32_t abi_version;
    uint32_t prefix_table_capacity;
    uint32_t maximum_probe_length;
    /* Independent fairness denominator N.  It is deliberately not the table
     * capacity.  Validation requires N*prefix_burst <= global_burst and
     * N*prefix_refill <= global_refill.  One canonical prefix cannot consume
     * another prefix's reserved share.  An attacker spoofing multiple
     * prefixes can consume multiple shares, but the keyed bounded table and
     * global bucket remain hard caps; this gate does not claim source
     * authenticity. */
    uint32_t fair_share_divisor;
    /* Unknown Initial work is ceil(crypto_input_bytes / quantum).  Both
     * buckets must be able to admit one maximum-sized request. */
    uint32_t cost_quantum_bytes;
    uint32_t max_admissible_crypto_input_bytes;
    uint64_t global_burst_tokens;
    uint64_t prefix_burst_credits;
    uint64_t global_refill_tokens_per_interval;
    uint64_t prefix_refill_credits_per_interval;
    uint64_t refill_interval_ns;
    uint64_t prefix_idle_timeout_ns;
    uint8_t ipv4_prefix_bits;
    uint8_t ipv6_prefix_bits;
    /* default_config leaves this zero and all three keys empty.  Before
     * initialize, the run controller must inject and freeze three independent
     * nonzero secret keys, then set keys_precommitted=1.  For reproducible
     * Validation, derive them with separate KDF labels from the frozen run
     * seed and store only commitments in a protected manifest; production
     * must use a CSPRNG. */
    uint8_t keys_precommitted;
    uint8_t reserved0[5];
    uint8_t prefix_hash_key[FK_QUIC_INITIAL_CRYPTO_ADMISSION_KEY_BYTES];
    uint8_t receipt_key_0[FK_QUIC_INITIAL_CRYPTO_ADMISSION_KEY_BYTES];
    uint8_t receipt_key_1[FK_QUIC_INITIAL_CRYPTO_ADMISSION_KEY_BYTES];
    uint8_t reserved1[8];
};

/* source_address[0..3] is IPv4 and [4..15] must be zero for ip_version=4;
 * all sixteen bytes are IPv6 for ip_version=6. physical_now_ns is the local
 * processing clock and is intentionally excluded from exact retry identity.
 * crypto_input_bytes is the bounded first QUIC packet which will actually be
 * authenticated (not necessarily the whole coalesced UDP datagram); it is
 * immutable identity and determines charged work.  The authenticator, not
 * this gate, enforces the complete datagram's 1200-byte Initial minimum. */
struct fk_quic_initial_crypto_admission_request_v1 {
    uint32_t abi_version;
    uint32_t crypto_input_bytes;
    uint8_t ip_version;
    uint8_t reserved0[7];
    uint64_t packet_sequence;
    uintptr_t packet_handle;
    uint64_t physical_ingress_timestamp_ns;
    uint64_t physical_now_ns;
    uint8_t source_address[16];
    uint8_t reserved1[8];
};

/* Opaque-by-contract value receipt.  Copy byte-for-byte; callers must not
 * construct or edit it.  Every issued receipt has cost_units > 0 and names a
 * charged prefix-table slot. */
struct fk_quic_initial_crypto_admission_receipt_v1 {
    uint32_t abi_version;
    uint32_t prefix_slot;
    uint64_t receipt_ordinal;
    uint64_t packet_sequence;
    uintptr_t packet_handle;
    uint64_t physical_ingress_timestamp_ns;
    uint64_t begin_physical_now_ns;
    uint64_t prefix_generation;
    uint64_t cost_units;
    uint64_t descriptor_hash_0;
    uint64_t descriptor_hash_1;
    uint32_t crypto_input_bytes;
    uint32_t cost_quantum_bytes;
    uint8_t ip_version;
    uint8_t prefix_bits;
    uint8_t reserved[6];
    uint8_t tag[FK_QUIC_INITIAL_CRYPTO_ADMISSION_TAG_BYTES];
};

struct fk_quic_initial_crypto_admission_begin_result_v1 {
    uint32_t abi_version;
    enum fk_quic_initial_crypto_admission_decision decision;
    enum fk_quic_initial_crypto_admission_reason reason;
    uint8_t reserved[4];
    struct fk_quic_initial_crypto_admission_receipt_v1 receipt;
};

struct fk_quic_initial_crypto_admission_gate_stats {
    uint64_t owner_claim_attempts;
    uint64_t owner_claim_successes;
    uint64_t owner_claim_rejections;
    uint64_t owner_thread_rejections;

    uint64_t begin_attempts;
    uint64_t begin_allowed;
    uint64_t begin_deferred;
    uint64_t begin_rejected;
    uint64_t charged_crypto_allows;
    uint64_t idempotent_active_allows;
    /* Orthogonal subset of begin_rejected; the original reason partition is
     * incremented as well, but no clock, lookup, refill, or credit changes. */
    uint64_t idempotent_reject_retries;
    uint64_t pressure_rejects;
    uint64_t global_token_rejects;
    uint64_t prefix_credit_rejects;
    uint64_t prefix_table_rejects;
    uint64_t oversized_crypto_input_rejects;
    uint64_t invalid_request_rejects;
    uint64_t active_mismatch_rejects;
    uint64_t sequence_replay_rejects;
    uint64_t completed_replay_rejects;
    uint64_t clock_regression_rejects;
    uint64_t stopped_rejects;
    uint64_t terminal_rejects;
    uint64_t internal_rejects;

    uint64_t global_refill_events;
    uint64_t global_tokens_refilled;
    uint64_t prefix_refill_events;
    uint64_t prefix_credits_refilled;
    uint64_t global_tokens_charged;
    uint64_t prefix_credits_charged;
    uint64_t charged_work_units;
    uint64_t charged_crypto_input_bytes;
    /* Sum(cost_units * cost_quantum_bytes), a checked upper bound on bytes
     * presented to unknown-Initial crypto work. */
    uint64_t charged_crypto_byte_upper_bound;
    uint64_t token_refunds;
    uint64_t pressure_entries;
    uint64_t pressure_recoveries;
    uint64_t pressure_observations;

    uint64_t prefix_lookups;
    uint64_t prefix_hits;
    uint64_t prefix_insertions;
    uint64_t prefix_evictions;
    uint64_t prefix_collision_steps;
    uint64_t prefix_probe_exhaustions;
    uint64_t active_prefix_entries;
    uint64_t peak_prefix_entries;

    uint64_t receipts_issued;
    uint64_t completion_attempts;
    uint64_t completions;
    uint64_t idempotent_completions;
    uint64_t completion_rejections;
    uint64_t authenticated_completions;
    uint64_t invalid_auth_completions;
    uint64_t crypto_failure_completions;
    uint64_t downstream_abort_completions;

    uint64_t normal_seal_attempts;
    uint64_t normal_seal_successes;
    uint64_t normal_seal_rejections;
    uint64_t abort_seal_attempts;
    uint64_t abort_seal_successes;
    uint64_t abort_seal_already;
    uint64_t active_receipts_abandoned;
    uint64_t terminal_transitions;
    uint64_t clock_regressions;
    uint64_t counter_overflows;
    uint64_t arithmetic_overflows;

    uint64_t global_tokens_available;
    uint64_t last_physical_now_ns;
    uint64_t next_receipt_ordinal;
    uint64_t service_memory_bytes;
    uint64_t service_metadata_bytes;
    uint64_t service_prefix_table_bytes;
    uint32_t prefix_table_capacity;
    uint32_t maximum_probe_length;
    uint32_t fair_share_divisor;
    uint32_t cost_quantum_bytes;
    uint32_t max_admissible_crypto_input_bytes;
    uint32_t abi_version;
    enum fk_quic_initial_crypto_gate_lifecycle lifecycle;
    enum fk_quic_initial_crypto_terminal_reason terminal_reason;
    uint8_t initialized;
    uint8_t owner_claimed;
    uint8_t active_receipt;
    uint8_t pressure_active;
    uint8_t accounting_conserved;
    uint8_t service_memory_exact;
    uint8_t formal_ready;
    uint8_t keys_injected;
    /* Non-secret, domain-separated 128-bit commitments.  Source keys are
     * never copied to stats or receipts. */
    uint8_t prefix_hash_key_commitment[16];
    uint8_t receipt_key_0_commitment[16];
    uint8_t receipt_key_1_commitment[16];
};

struct fk_quic_initial_crypto_admission_gate;

void fk_quic_initial_crypto_admission_gate_default_config_init(
    struct fk_quic_initial_crypto_admission_gate_config *config);

bool fk_quic_initial_crypto_admission_gate_config_valid(
    const struct fk_quic_initial_crypto_admission_gate_config *config);

size_t fk_quic_initial_crypto_admission_gate_storage_bytes(
    const struct fk_quic_initial_crypto_admission_gate_config *config);

struct fk_quic_initial_crypto_admission_gate *
fk_quic_initial_crypto_admission_gate_initialize(
    void *storage,
    size_t storage_bytes,
    const struct fk_quic_initial_crypto_admission_gate_config *config);

bool fk_quic_initial_crypto_admission_gate_claim_owner(
    struct fk_quic_initial_crypto_admission_gate *gate);

/* Exactly one begin receipt may be active on the claimed identity thread.
 * An exact retry before complete returns the byte-identical ALLOW receipt
 * without another charge.  A resource-pressure REJECT is also frozen: an
 * exact retry of that descriptor returns the same REJECT before consulting
 * time or buckets.  Only a strictly higher packet_sequence advances it;
 * changing a descriptor at the same sequence fails closed. */
enum fk_quic_initial_crypto_admission_decision
fk_quic_initial_crypto_admission_gate_begin(
    struct fk_quic_initial_crypto_admission_gate *gate,
    const struct fk_quic_initial_crypto_admission_request_v1 *request,
    struct fk_quic_initial_crypto_admission_begin_result_v1 *result);

/* Every completion outcome consumes the charged attempt permanently.  In
 * particular INVALID_AUTH and CRYPTO_FAILURE never refund either bucket. */
enum fk_quic_initial_crypto_completion_result
fk_quic_initial_crypto_admission_gate_complete(
    struct fk_quic_initial_crypto_admission_gate *gate,
    const struct fk_quic_initial_crypto_admission_receipt_v1 *receipt,
    enum fk_quic_initial_crypto_completion_outcome outcome);

/* Normal seal rejects a live receipt.  Abort seal explicitly abandons one
 * live receipt without refund and is permanently non-formal. */
bool fk_quic_initial_crypto_admission_gate_seal_normal(
    struct fk_quic_initial_crypto_admission_gate *gate);

bool fk_quic_initial_crypto_admission_gate_seal_abort(
    struct fk_quic_initial_crypto_admission_gate *gate);

bool fk_quic_initial_crypto_admission_gate_get_stats(
    const struct fk_quic_initial_crypto_admission_gate *gate,
    struct fk_quic_initial_crypto_admission_gate_stats *stats);

bool fk_quic_initial_crypto_admission_gate_accounting_conserved(
    const struct fk_quic_initial_crypto_admission_gate *gate);

bool fk_quic_initial_crypto_admission_gate_formal_ready(
    const struct fk_quic_initial_crypto_admission_gate *gate);

bool fk_quic_initial_crypto_admission_gate_destroy_checked(
    struct fk_quic_initial_crypto_admission_gate *gate);

const char *fk_quic_initial_crypto_admission_reason_name(
    enum fk_quic_initial_crypto_admission_reason reason);

#ifdef FK_QUIC_INITIAL_CRYPTO_ADMISSION_GATE_TEST_HOOKS
bool fk_quic_initial_crypto_admission_gate_test_force_begin_attempts(
    struct fk_quic_initial_crypto_admission_gate *gate,
    uint64_t value);
#endif

#ifdef __cplusplus
}
#endif

#endif
