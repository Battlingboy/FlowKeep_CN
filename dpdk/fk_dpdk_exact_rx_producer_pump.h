#ifndef FLOWKEEP_FK_DPDK_EXACT_RX_PRODUCER_PUMP_H
#define FLOWKEEP_FK_DPDK_EXACT_RX_PRODUCER_PUMP_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "fk_exact_identity_sequencer.h"

struct rte_mbuf;

#ifdef __cplusplus
extern "C" {
#endif

#define FK_DPDK_EXACT_RX_PRODUCER_PUMP_ABI_VERSION 1u
#define FK_DPDK_EXACT_RX_PRODUCER_PUMP_MAX_BURST 256u

/*
 * Failure-atomic callback contract:
 *
 * - burst false transfers no mbuf and must set received to zero;
 * - clock/decode false changes no externally visible state and leaves the
 *   exact mbuf with the pump for an identical retry;
 * - reclaim true consumes the exact mbuf once, normally with
 *   rte_pktmbuf_free(); false consumes nothing and is retried verbatim.
 *
 * The trusted decoder is the only source of packet_sequence and semantic
 * time.  A production decoder must authenticate a replay sidecar/MAC.  This
 * module deliberately does not claim that such a sidecar is wired yet.
 */
typedef bool (*fk_dpdk_exact_rx_burst_callback)(
    void *context,
    uint16_t port_id,
    uint16_t queue_id,
    struct rte_mbuf **packets,
    uint16_t capacity,
    uint16_t *received);

typedef bool (*fk_dpdk_exact_rx_clock_callback)(
    void *context,
    uint64_t *physical_ingress_timestamp_ns);

typedef bool (*fk_dpdk_exact_rx_identity_decode_callback)(
    void *context,
    const struct rte_mbuf *packet,
    uint16_t producer_index,
    uint64_t physical_ingress_timestamp_ns,
    uint64_t *packet_sequence,
    uint64_t *semantic_timestamp_ns,
    uint32_t *wire_length);

typedef bool (*fk_dpdk_exact_rx_reclaim_callback)(
    void *context,
    struct rte_mbuf *packet);

struct fk_dpdk_exact_rx_producer_pump_config {
    uint32_t abi_version;
    uint16_t port_id;
    uint16_t queue_id;
    uint16_t producer_index;
    uint16_t producer_count;
    uint16_t burst_capacity;
    uint8_t reserved0[2];
    struct fk_exact_identity_sequencer *sequencer;
    void *burst_context;
    fk_dpdk_exact_rx_burst_callback burst;
    void *clock_context;
    fk_dpdk_exact_rx_clock_callback clock;
    void *decode_context;
    fk_dpdk_exact_rx_identity_decode_callback decode;
    void *reclaim_context;
    fk_dpdk_exact_rx_reclaim_callback reclaim;
    uint8_t reserved[8];
};

enum fk_dpdk_exact_rx_producer_step_result {
    FK_DPDK_EXACT_RX_PRODUCER_STEP_INVALID = 0,
    FK_DPDK_EXACT_RX_PRODUCER_STEP_IDLE = 1,
    FK_DPDK_EXACT_RX_PRODUCER_STEP_BURST_RETAINED = 2,
    FK_DPDK_EXACT_RX_PRODUCER_STEP_PACKET_TRANSFERRED = 3,
    FK_DPDK_EXACT_RX_PRODUCER_STEP_QUEUE_FULL_RETAINED = 4,
    FK_DPDK_EXACT_RX_PRODUCER_STEP_CALLBACK_RETRY = 5,
    FK_DPDK_EXACT_RX_PRODUCER_STEP_ABORT_RECLAIMED = 6,
    FK_DPDK_EXACT_RX_PRODUCER_STEP_ABORT_RECLAIM_RETRY = 7,
    FK_DPDK_EXACT_RX_PRODUCER_STEP_STOPPED_NORMAL = 8,
    FK_DPDK_EXACT_RX_PRODUCER_STEP_ABORTED_LOCAL = 9,
    FK_DPDK_EXACT_RX_PRODUCER_STEP_TERMINAL = 10,
    FK_DPDK_EXACT_RX_PRODUCER_STEP_WRONG_THREAD = 11,
};

enum fk_dpdk_exact_rx_producer_terminal_reason {
    FK_DPDK_EXACT_RX_PRODUCER_TERMINAL_NONE = 0,
    FK_DPDK_EXACT_RX_PRODUCER_TERMINAL_CONFIGURATION = 1,
    FK_DPDK_EXACT_RX_PRODUCER_TERMINAL_COUNTER_OVERFLOW = 2,
    FK_DPDK_EXACT_RX_PRODUCER_TERMINAL_BURST_CONTRACT = 3,
    FK_DPDK_EXACT_RX_PRODUCER_TERMINAL_NULL_MBUF = 4,
    FK_DPDK_EXACT_RX_PRODUCER_TERMINAL_MULTI_SEGMENT = 5,
    FK_DPDK_EXACT_RX_PRODUCER_TERMINAL_NOT_DIRECT = 6,
    FK_DPDK_EXACT_RX_PRODUCER_TERMINAL_NOT_FULL_CAPTURE = 7,
    FK_DPDK_EXACT_RX_PRODUCER_TERMINAL_MBUF_SHAPE = 8,
    FK_DPDK_EXACT_RX_PRODUCER_TERMINAL_DUPLICATE_HANDLE = 9,
    FK_DPDK_EXACT_RX_PRODUCER_TERMINAL_MBUF_MUTATED = 10,
    FK_DPDK_EXACT_RX_PRODUCER_TERMINAL_SEQUENCE_REPLAY = 11,
    FK_DPDK_EXACT_RX_PRODUCER_TERMINAL_SEQUENCE_RANGE = 12,
    FK_DPDK_EXACT_RX_PRODUCER_TERMINAL_TIMESTAMP = 13,
    FK_DPDK_EXACT_RX_PRODUCER_TERMINAL_SEQUENCER_REJECTED = 14,
    FK_DPDK_EXACT_RX_PRODUCER_TERMINAL_CLOSE_FAILED = 15,
    FK_DPDK_EXACT_RX_PRODUCER_TERMINAL_EXPLICIT_ABORT = 16,
};

struct fk_dpdk_exact_rx_producer_pump_stats {
    uint64_t thread_claim_attempts;
    uint64_t thread_claim_successes;
    uint64_t thread_claim_rejections;
    uint64_t wrong_thread_calls;

    uint64_t step_calls;
    uint64_t burst_calls;
    uint64_t burst_callback_retries;
    uint64_t empty_bursts;
    uint64_t received_bursts;
    uint64_t rx_received;
    uint64_t clock_calls;
    uint64_t clock_callback_retries;
    uint64_t decode_calls;
    uint64_t decode_callback_retries;
    uint64_t submit_calls;
    uint64_t sequencer_transferred;
    uint64_t queue_full_retries;
    uint64_t sequencer_terminal_rejections;
    uint64_t reclaim_calls;
    uint64_t reclaim_callback_retries;
    uint64_t reclaimed;
    uint64_t pending;
    uint64_t peak_pending;

    uint64_t null_mbuf_failures;
    uint64_t multi_segment_failures;
    uint64_t non_direct_failures;
    uint64_t full_capture_failures;
    uint64_t shape_failures;
    uint64_t duplicate_handle_failures;
    uint64_t mutation_failures;
    uint64_t sequence_replay_failures;
    uint64_t sequence_range_failures;
    uint64_t timestamp_failures;

    uint64_t normal_stop_requests;
    uint64_t abort_requests;
    uint64_t close_attempts;
    uint64_t close_successes;
    uint64_t close_failures;
    uint64_t service_memory_bytes;

    uint64_t pending_packet_sequence;
    uintptr_t pending_packet_handle;
    uint32_t abi_version;
    uint16_t port_id;
    uint16_t queue_id;
    uint16_t producer_index;
    uint16_t producer_count;
    uint16_t burst_capacity;
    enum fk_dpdk_exact_rx_producer_terminal_reason terminal_reason;
    uint8_t initialized;
    uint8_t producer_thread_claimed;
    uint8_t acquisition_stopped;
    uint8_t normal_stop_requested;
    uint8_t abort_requested;
    uint8_t producer_closed;
    uint8_t stopped_normal;
    uint8_t stopped_abort;
    uint8_t requires_global_abort;
    uint8_t counter_overflow;
    uint8_t accounting_conserved;
    uint8_t service_memory_exact;
    uint8_t reserved[4];
};

struct fk_dpdk_exact_rx_producer_pump;

void fk_dpdk_exact_rx_producer_pump_default_config_init(
    struct fk_dpdk_exact_rx_producer_pump_config *config);

bool fk_dpdk_exact_rx_producer_pump_config_valid(
    const struct fk_dpdk_exact_rx_producer_pump_config *config);

size_t fk_dpdk_exact_rx_producer_pump_storage_bytes(
    const struct fk_dpdk_exact_rx_producer_pump_config *config);

/* Placement initialization; all burst slots are part of returned storage. */
struct fk_dpdk_exact_rx_producer_pump *
fk_dpdk_exact_rx_producer_pump_initialize(
    void *storage,
    size_t storage_bytes,
    const struct fk_dpdk_exact_rx_producer_pump_config *config,
    char *error,
    size_t error_capacity);

/* One-shot claim by the fixed RX producer/lcore. */
bool fk_dpdk_exact_rx_producer_pump_claim_thread(
    struct fk_dpdk_exact_rx_producer_pump *pump);

/* One bounded action: at most one burst, decode, submit, or reclaim. */
enum fk_dpdk_exact_rx_producer_step_result
fk_dpdk_exact_rx_producer_pump_step(
    struct fk_dpdk_exact_rx_producer_pump *pump);

/* Stop acquisition, flush all retained packets, then close this producer. */
bool fk_dpdk_exact_rx_producer_pump_request_stop(
    struct fk_dpdk_exact_rx_producer_pump *pump);

/* Stop acquisition and begin failure-atomic local reclaim. The caller keeps
 * stepping until ABORTED_LOCAL. This closes only this producer; it never
 * aborts or drains the sequencer. That is the identity/global coordinator's
 * responsibility. */
bool fk_dpdk_exact_rx_producer_pump_request_abort(
    struct fk_dpdk_exact_rx_producer_pump *pump);

bool fk_dpdk_exact_rx_producer_pump_get_stats(
    const struct fk_dpdk_exact_rx_producer_pump *pump,
    struct fk_dpdk_exact_rx_producer_pump_stats *stats);

/* Checked destruction requires a normal or local-abort terminal state and
 * zero locally owned mbufs. */
bool fk_dpdk_exact_rx_producer_pump_destroy_checked(
    struct fk_dpdk_exact_rx_producer_pump *pump);

/* Production burst adapter. It performs no allocation and delegates to
 * rte_eth_rx_burst(port_id, queue_id, ...). context must be null. */
bool fk_dpdk_exact_rx_producer_rte_eth_rx_burst(
    void *context,
    uint16_t port_id,
    uint16_t queue_id,
    struct rte_mbuf **packets,
    uint16_t capacity,
    uint16_t *received);

#ifdef FK_DPDK_EXACT_RX_PRODUCER_PUMP_TEST_HOOKS
/* Coherent counter seed used only to prove pre-acquisition overflow gates. */
bool fk_dpdk_exact_rx_producer_pump_test_seed_accounting(
    struct fk_dpdk_exact_rx_producer_pump *pump,
    uint64_t rx_received,
    uint64_t sequencer_transferred,
    uint64_t reclaimed);
#endif

#ifdef __cplusplus
}
#endif

#endif
