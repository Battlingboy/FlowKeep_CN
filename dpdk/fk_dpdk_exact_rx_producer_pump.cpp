#include "fk_dpdk_exact_rx_producer_pump.h"

#include <rte_ethdev.h>
#include <rte_mbuf.h>

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <limits>
#include <new>

namespace {

constexpr uint64_t kMagic = UINT64_C(0x464b525850554d31);  // "FKRXPUM1"

struct MbufSnapshot {
    void *buf_addr;
    void *data;
    rte_mbuf *next;
    uint64_t ol_flags;
    uint32_t pkt_len;
    uint16_t data_len;
    uint16_t data_off;
    uint16_t buf_len;
    uint16_t refcnt;
    uint16_t nb_segs;
};

struct PendingSlot {
    rte_mbuf *mbuf;
    MbufSnapshot snapshot;
    fk_exact_identity_packet descriptor;
    uint8_t snapshot_valid;
    uint8_t clock_ready;
    uint8_t descriptor_ready;
    uint8_t reserved[5];
};

struct PumpState {
    uint64_t magic;
    fk_dpdk_exact_rx_producer_pump_config config;
    PendingSlot *slots;
    rte_mbuf **burst_scratch;
    size_t reserved_bytes;
    std::atomic<uint64_t> thread_token;
    std::atomic<uint64_t> thread_claim_attempts;
    std::atomic<uint64_t> thread_claim_successes;
    std::atomic<uint64_t> thread_claim_rejections;
    std::atomic<uint64_t> wrong_thread_calls;
    fk_dpdk_exact_rx_producer_pump_stats counters;
    uint64_t last_transferred_sequence;
    uint16_t pending_begin;
    uint16_t pending_count;
    uint8_t last_sequence_initialized;
    uint8_t initialized;
    uint8_t acquisition_stopped;
    uint8_t normal_stop_requested;
    uint8_t abort_requested;
    uint8_t producer_closed;
    uint8_t stopped_normal;
    uint8_t stopped_abort;
    uint8_t requires_global_abort;
    uint8_t counter_overflow;
    uint8_t ownership_indeterminate;
    uint8_t reserved[5];
};

static_assert(
    alignof(PumpState) <= alignof(std::max_align_t),
    "RX producer pump must fit max_align_t placement storage");
static_assert(
    alignof(PendingSlot) <= alignof(std::max_align_t),
    "RX producer slot must fit max_align_t placement storage");

std::atomic<uint64_t> g_next_thread_token{1u};

PumpState *implementation(fk_dpdk_exact_rx_producer_pump *pump) {
    return reinterpret_cast<PumpState *>(pump);
}

const PumpState *implementation(
        const fk_dpdk_exact_rx_producer_pump *pump) {
    return reinterpret_cast<const PumpState *>(pump);
}

void set_error(char *error, size_t capacity, const char *message) {
    if (error != nullptr && capacity != 0u)
        std::snprintf(error, capacity, "%s", message);
}

bool checked_add(size_t &value, size_t increment) {
    if (increment > std::numeric_limits<size_t>::max() - value)
        return false;
    value += increment;
    return true;
}

bool checked_multiply(size_t left, size_t right, size_t &result) {
    if (left != 0u &&
        right > std::numeric_limits<size_t>::max() / left)
        return false;
    result = left * right;
    return true;
}

bool align_offset(size_t &offset, size_t alignment) {
    const size_t remainder = offset % alignment;
    return remainder == 0u || checked_add(offset, alignment - remainder);
}

bool reserved_zero(
        const fk_dpdk_exact_rx_producer_pump_config &config) {
    for (uint8_t value : config.reserved0) {
        if (value != 0u)
            return false;
    }
    for (uint8_t value : config.reserved) {
        if (value != 0u)
            return false;
    }
    return true;
}

bool basic_config_valid(
        const fk_dpdk_exact_rx_producer_pump_config *config) {
    return config != nullptr &&
        config->abi_version ==
            FK_DPDK_EXACT_RX_PRODUCER_PUMP_ABI_VERSION &&
        config->producer_count != 0u &&
        config->producer_count <= FK_EXACT_IDENTITY_SEQUENCER_MAX_PRODUCERS &&
        config->producer_index < config->producer_count &&
        config->burst_capacity != 0u &&
        config->burst_capacity <= FK_DPDK_EXACT_RX_PRODUCER_PUMP_MAX_BURST &&
        config->sequencer != nullptr && config->burst != nullptr &&
        config->clock != nullptr && config->decode != nullptr &&
        config->reclaim != nullptr && reserved_zero(*config);
}

size_t required_bytes(
        const fk_dpdk_exact_rx_producer_pump_config *config) {
    if (!basic_config_valid(config))
        return 0u;
    size_t bytes = alignof(std::max_align_t) - 1u;
    if (!align_offset(bytes, alignof(PumpState)) ||
        !checked_add(bytes, sizeof(PumpState)) ||
        !align_offset(bytes, alignof(PendingSlot))) {
        return 0u;
    }
    size_t slot_bytes = 0u;
    if (!checked_multiply(
            config->burst_capacity, sizeof(PendingSlot), slot_bytes) ||
        !checked_add(bytes, slot_bytes) ||
        !align_offset(bytes, alignof(rte_mbuf *))) {
        return 0u;
    }
    size_t scratch_bytes = 0u;
    if (!checked_multiply(
            config->burst_capacity, sizeof(rte_mbuf *), scratch_bytes) ||
        !checked_add(bytes, scratch_bytes))
        return 0u;
    return bytes;
}

uint64_t allocate_thread_token() {
    uint64_t candidate =
        g_next_thread_token.load(std::memory_order_relaxed);
    while (candidate != 0u) {
        const uint64_t successor =
            candidate == std::numeric_limits<uint64_t>::max()
                ? 0u : candidate + 1u;
        if (g_next_thread_token.compare_exchange_weak(
                candidate,
                successor,
                std::memory_order_relaxed,
                std::memory_order_relaxed)) {
            return candidate;
        }
    }
    return 0u;
}

uint64_t current_thread_token() {
    static thread_local const uint64_t token = allocate_thread_token();
    return token;
}

bool producer_thread(PumpState &state) {
    const uint64_t current = current_thread_token();
    const uint64_t claimed =
        state.thread_token.load(std::memory_order_acquire);
    if (current != 0u && claimed != 0u && current == claimed)
        return true;
    state.wrong_thread_calls.fetch_add(1u, std::memory_order_relaxed);
    return false;
}

void mark_terminal(
        PumpState &state,
        fk_dpdk_exact_rx_producer_terminal_reason reason) {
    if (state.counters.terminal_reason ==
        FK_DPDK_EXACT_RX_PRODUCER_TERMINAL_NONE) {
        state.counters.terminal_reason = reason;
    }
    state.acquisition_stopped = 1u;
    state.abort_requested = 1u;
    state.requires_global_abort = 1u;
}

bool increment(
        PumpState &state, uint64_t &counter, uint64_t amount = 1u) {
    if (amount > std::numeric_limits<uint64_t>::max() - counter) {
        state.counter_overflow = 1u;
        mark_terminal(
            state, FK_DPDK_EXACT_RX_PRODUCER_TERMINAL_COUNTER_OVERFLOW);
        return false;
    }
    counter += amount;
    return true;
}

bool snapshot_mbuf(const rte_mbuf &mbuf, MbufSnapshot &snapshot) {
    const auto *data = rte_pktmbuf_mtod(&mbuf, const uint8_t *);
    if (data == nullptr)
        return false;
    snapshot.buf_addr = mbuf.buf_addr;
    snapshot.data = const_cast<uint8_t *>(data);
    snapshot.next = mbuf.next;
    snapshot.ol_flags = mbuf.ol_flags;
    snapshot.pkt_len = mbuf.pkt_len;
    snapshot.data_len = mbuf.data_len;
    snapshot.data_off = mbuf.data_off;
    snapshot.buf_len = mbuf.buf_len;
    snapshot.refcnt = rte_mbuf_refcnt_read(&mbuf);
    snapshot.nb_segs = mbuf.nb_segs;
    return true;
}

fk_dpdk_exact_rx_producer_terminal_reason classify_mbuf(
        const rte_mbuf *mbuf) {
    if (mbuf == nullptr)
        return FK_DPDK_EXACT_RX_PRODUCER_TERMINAL_NULL_MBUF;
    if (mbuf->nb_segs != 1u || mbuf->next != nullptr)
        return FK_DPDK_EXACT_RX_PRODUCER_TERMINAL_MULTI_SEGMENT;
    if (!RTE_MBUF_DIRECT(mbuf) || rte_mbuf_refcnt_read(mbuf) != 1u)
        return FK_DPDK_EXACT_RX_PRODUCER_TERMINAL_NOT_DIRECT;
    if (mbuf->buf_addr == nullptr || mbuf->pkt_len == 0u ||
        mbuf->data_len == 0u || mbuf->data_off > mbuf->buf_len ||
        mbuf->data_len >
            static_cast<uint32_t>(mbuf->buf_len - mbuf->data_off) ||
        rte_pktmbuf_mtod(mbuf, const uint8_t *) == nullptr) {
        return FK_DPDK_EXACT_RX_PRODUCER_TERMINAL_MBUF_SHAPE;
    }
    if (mbuf->pkt_len != mbuf->data_len)
        return FK_DPDK_EXACT_RX_PRODUCER_TERMINAL_NOT_FULL_CAPTURE;
    return FK_DPDK_EXACT_RX_PRODUCER_TERMINAL_NONE;
}

bool snapshot_equal(const PendingSlot &slot) {
    if (slot.mbuf == nullptr || slot.snapshot_valid == 0u)
        return false;
    const rte_mbuf &mbuf = *slot.mbuf;
    const auto *data = rte_pktmbuf_mtod(&mbuf, const uint8_t *);
    return mbuf.buf_addr == slot.snapshot.buf_addr &&
        data == slot.snapshot.data && mbuf.next == slot.snapshot.next &&
        mbuf.ol_flags == slot.snapshot.ol_flags &&
        mbuf.pkt_len == slot.snapshot.pkt_len &&
        mbuf.data_len == slot.snapshot.data_len &&
        mbuf.data_off == slot.snapshot.data_off &&
        mbuf.buf_len == slot.snapshot.buf_len &&
        rte_mbuf_refcnt_read(&mbuf) == slot.snapshot.refcnt &&
        mbuf.nb_segs == slot.snapshot.nb_segs;
}

void count_shape_failure(
        PumpState &state,
        fk_dpdk_exact_rx_producer_terminal_reason reason) {
    switch (reason) {
    case FK_DPDK_EXACT_RX_PRODUCER_TERMINAL_NULL_MBUF:
        (void)increment(state, state.counters.null_mbuf_failures);
        break;
    case FK_DPDK_EXACT_RX_PRODUCER_TERMINAL_MULTI_SEGMENT:
        (void)increment(state, state.counters.multi_segment_failures);
        break;
    case FK_DPDK_EXACT_RX_PRODUCER_TERMINAL_NOT_DIRECT:
        (void)increment(state, state.counters.non_direct_failures);
        break;
    case FK_DPDK_EXACT_RX_PRODUCER_TERMINAL_NOT_FULL_CAPTURE:
        (void)increment(state, state.counters.full_capture_failures);
        break;
    case FK_DPDK_EXACT_RX_PRODUCER_TERMINAL_MBUF_SHAPE:
        (void)increment(state, state.counters.shape_failures);
        break;
    default:
        break;
    }
}

PendingSlot &current_slot(PumpState &state) {
    return state.slots[state.pending_begin];
}

void remove_current_without_dereference(PumpState &state) {
    PendingSlot &slot = current_slot(state);
    slot = {};
    state.pending_begin = static_cast<uint16_t>(state.pending_begin + 1u);
    state.pending_count = static_cast<uint16_t>(state.pending_count - 1u);
    if (state.pending_count == 0u)
        state.pending_begin = 0u;
}

bool close_producer(PumpState &state) {
    if (state.producer_closed != 0u)
        return true;
    if (!increment(state, state.counters.close_attempts))
        return false;
    if (!fk_exact_identity_sequencer_close_producer(
            state.config.sequencer, state.config.producer_index)) {
        (void)increment(state, state.counters.close_failures);
        mark_terminal(
            state, FK_DPDK_EXACT_RX_PRODUCER_TERMINAL_CLOSE_FAILED);
        return false;
    }
    state.producer_closed = 1u;
    (void)increment(state, state.counters.close_successes);
    return true;
}

fk_dpdk_exact_rx_producer_step_result abort_one(PumpState &state) {
    if (state.pending_count != 0u) {
        PendingSlot &slot = current_slot(state);
        if (slot.mbuf == nullptr) {
            state.ownership_indeterminate = 1u;
            return FK_DPDK_EXACT_RX_PRODUCER_STEP_TERMINAL;
        }
        if (slot.snapshot_valid != 0u && !snapshot_equal(slot)) {
            (void)increment(state, state.counters.mutation_failures);
            mark_terminal(
                state, FK_DPDK_EXACT_RX_PRODUCER_TERMINAL_MBUF_MUTATED);
        }
        if (state.counters.reclaimed ==
            std::numeric_limits<uint64_t>::max()) {
            state.counter_overflow = 1u;
            mark_terminal(
                state, FK_DPDK_EXACT_RX_PRODUCER_TERMINAL_COUNTER_OVERFLOW);
            return FK_DPDK_EXACT_RX_PRODUCER_STEP_TERMINAL;
        }
        if (!increment(state, state.counters.reclaim_calls))
            return FK_DPDK_EXACT_RX_PRODUCER_STEP_TERMINAL;
        rte_mbuf *const exact = slot.mbuf;
        if (!state.config.reclaim(state.config.reclaim_context, exact)) {
            (void)increment(
                state, state.counters.reclaim_callback_retries);
            return FK_DPDK_EXACT_RX_PRODUCER_STEP_ABORT_RECLAIM_RETRY;
        }
        state.counters.reclaimed++;
        remove_current_without_dereference(state);
        return FK_DPDK_EXACT_RX_PRODUCER_STEP_ABORT_RECLAIMED;
    }
    if (!close_producer(state))
        return FK_DPDK_EXACT_RX_PRODUCER_STEP_TERMINAL;
    state.stopped_abort = 1u;
    return FK_DPDK_EXACT_RX_PRODUCER_STEP_ABORTED_LOCAL;
}

fk_dpdk_exact_rx_producer_step_result acquire_burst(PumpState &state) {
    if (state.counters.rx_received >
        std::numeric_limits<uint64_t>::max() -
            state.config.burst_capacity) {
        state.counter_overflow = 1u;
        mark_terminal(
            state, FK_DPDK_EXACT_RX_PRODUCER_TERMINAL_COUNTER_OVERFLOW);
        return abort_one(state);
    }
    if (!increment(state, state.counters.burst_calls))
        return abort_one(state);
    std::memset(
        state.burst_scratch,
        0,
        static_cast<size_t>(state.config.burst_capacity) *
            sizeof(*state.burst_scratch));
    uint16_t received = 0u;
    if (!state.config.burst(
            state.config.burst_context,
            state.config.port_id,
            state.config.queue_id,
            state.burst_scratch,
            state.config.burst_capacity,
            &received)) {
        if (received != 0u) {
            state.ownership_indeterminate = 1u;
            mark_terminal(
                state,
                FK_DPDK_EXACT_RX_PRODUCER_TERMINAL_BURST_CONTRACT);
            return FK_DPDK_EXACT_RX_PRODUCER_STEP_TERMINAL;
        }
        (void)increment(state, state.counters.burst_callback_retries);
        return FK_DPDK_EXACT_RX_PRODUCER_STEP_CALLBACK_RETRY;
    }
    if (received > state.config.burst_capacity) {
        state.ownership_indeterminate = 1u;
        mark_terminal(
            state, FK_DPDK_EXACT_RX_PRODUCER_TERMINAL_BURST_CONTRACT);
        return FK_DPDK_EXACT_RX_PRODUCER_STEP_TERMINAL;
    }
    if (received == 0u) {
        (void)increment(state, state.counters.empty_bursts);
        return FK_DPDK_EXACT_RX_PRODUCER_STEP_IDLE;
    }
    state.pending_begin = 0u;
    state.pending_count = received;
    (void)increment(state, state.counters.received_bursts);
    (void)increment(state, state.counters.rx_received, received);
    if (state.pending_count > state.counters.peak_pending)
        state.counters.peak_pending = state.pending_count;

    fk_dpdk_exact_rx_producer_terminal_reason first_failure =
        FK_DPDK_EXACT_RX_PRODUCER_TERMINAL_NONE;
    for (uint16_t index = 0u; index < received; ++index) {
        PendingSlot &slot = state.slots[index];
        slot = {};
        slot.mbuf = state.burst_scratch[index];
        const auto shape = classify_mbuf(slot.mbuf);
        if (shape == FK_DPDK_EXACT_RX_PRODUCER_TERMINAL_NONE) {
            slot.snapshot_valid = snapshot_mbuf(
                *slot.mbuf, slot.snapshot) ? 1u : 0u;
            if (slot.snapshot_valid == 0u &&
                first_failure ==
                    FK_DPDK_EXACT_RX_PRODUCER_TERMINAL_NONE) {
                first_failure =
                    FK_DPDK_EXACT_RX_PRODUCER_TERMINAL_MBUF_SHAPE;
                count_shape_failure(state, first_failure);
            }
        } else if (first_failure ==
                   FK_DPDK_EXACT_RX_PRODUCER_TERMINAL_NONE) {
            first_failure = shape;
            count_shape_failure(state, shape);
        }
        if (slot.mbuf == nullptr)
            continue;
        for (uint16_t prior = 0u; prior < index; ++prior) {
            if (state.slots[prior].mbuf != slot.mbuf)
                continue;
            (void)increment(
                state, state.counters.duplicate_handle_failures);
            state.ownership_indeterminate = 1u;
            if (first_failure ==
                FK_DPDK_EXACT_RX_PRODUCER_TERMINAL_NONE) {
                first_failure =
                    FK_DPDK_EXACT_RX_PRODUCER_TERMINAL_DUPLICATE_HANDLE;
            }
            break;
        }
    }
    if (first_failure != FK_DPDK_EXACT_RX_PRODUCER_TERMINAL_NONE) {
        mark_terminal(state, first_failure);
        return FK_DPDK_EXACT_RX_PRODUCER_STEP_BURST_RETAINED;
    }
    return FK_DPDK_EXACT_RX_PRODUCER_STEP_BURST_RETAINED;
}

fk_dpdk_exact_rx_producer_step_result process_current(PumpState &state) {
    PendingSlot &slot = current_slot(state);
    if (!snapshot_equal(slot)) {
        (void)increment(state, state.counters.mutation_failures);
        mark_terminal(
            state, FK_DPDK_EXACT_RX_PRODUCER_TERMINAL_MBUF_MUTATED);
        return FK_DPDK_EXACT_RX_PRODUCER_STEP_TERMINAL;
    }
    if (slot.clock_ready == 0u) {
        if (!increment(state, state.counters.clock_calls))
            return FK_DPDK_EXACT_RX_PRODUCER_STEP_TERMINAL;
        uint64_t physical = 0u;
        if (!state.config.clock(state.config.clock_context, &physical)) {
            (void)increment(
                state, state.counters.clock_callback_retries);
            return FK_DPDK_EXACT_RX_PRODUCER_STEP_CALLBACK_RETRY;
        }
        if (physical == 0u) {
            (void)increment(state, state.counters.timestamp_failures);
            mark_terminal(
                state, FK_DPDK_EXACT_RX_PRODUCER_TERMINAL_TIMESTAMP);
            return FK_DPDK_EXACT_RX_PRODUCER_STEP_TERMINAL;
        }
        slot.descriptor.physical_ingress_timestamp_ns = physical;
        slot.clock_ready = 1u;
    }
    if (slot.descriptor_ready == 0u) {
        if (!increment(state, state.counters.decode_calls))
            return FK_DPDK_EXACT_RX_PRODUCER_STEP_TERMINAL;
        uint64_t sequence = 0u;
        uint64_t semantic = 0u;
        uint32_t wire_length = 0u;
        if (!state.config.decode(
                state.config.decode_context,
                slot.mbuf,
                state.config.producer_index,
                slot.descriptor.physical_ingress_timestamp_ns,
                &sequence,
                &semantic,
                &wire_length)) {
            (void)increment(
                state, state.counters.decode_callback_retries);
            return FK_DPDK_EXACT_RX_PRODUCER_STEP_CALLBACK_RETRY;
        }
        if (sequence >= FK_EXACT_IDENTITY_SEQUENCER_MAX_PACKETS) {
            (void)increment(state, state.counters.sequence_range_failures);
            mark_terminal(
                state, FK_DPDK_EXACT_RX_PRODUCER_TERMINAL_SEQUENCE_RANGE);
            return FK_DPDK_EXACT_RX_PRODUCER_STEP_TERMINAL;
        }
        if (state.last_sequence_initialized != 0u &&
            sequence <= state.last_transferred_sequence) {
            (void)increment(state, state.counters.sequence_replay_failures);
            mark_terminal(
                state, FK_DPDK_EXACT_RX_PRODUCER_TERMINAL_SEQUENCE_REPLAY);
            return FK_DPDK_EXACT_RX_PRODUCER_STEP_TERMINAL;
        }
        if (wire_length != slot.snapshot.pkt_len) {
            (void)increment(state, state.counters.full_capture_failures);
            mark_terminal(
                state,
                FK_DPDK_EXACT_RX_PRODUCER_TERMINAL_NOT_FULL_CAPTURE);
            return FK_DPDK_EXACT_RX_PRODUCER_STEP_TERMINAL;
        }
        slot.descriptor.packet_handle =
            reinterpret_cast<uintptr_t>(slot.mbuf);
        slot.descriptor.packet_sequence = sequence;
        slot.descriptor.semantic_timestamp_ns = semantic;
        slot.descriptor.captured_length = slot.snapshot.pkt_len;
        slot.descriptor.wire_length = wire_length;
        slot.descriptor.ingress_worker = state.config.producer_index;
        slot.descriptor.reserved = 0u;
        slot.descriptor_ready = 1u;
    }
    if (!snapshot_equal(slot)) {
        (void)increment(state, state.counters.mutation_failures);
        mark_terminal(
            state, FK_DPDK_EXACT_RX_PRODUCER_TERMINAL_MBUF_MUTATED);
        return FK_DPDK_EXACT_RX_PRODUCER_STEP_TERMINAL;
    }
    if (state.counters.sequencer_transferred ==
        std::numeric_limits<uint64_t>::max()) {
        state.counter_overflow = 1u;
        mark_terminal(
            state, FK_DPDK_EXACT_RX_PRODUCER_TERMINAL_COUNTER_OVERFLOW);
        return FK_DPDK_EXACT_RX_PRODUCER_STEP_TERMINAL;
    }
    if (!increment(state, state.counters.submit_calls))
        return FK_DPDK_EXACT_RX_PRODUCER_STEP_TERMINAL;
    const fk_exact_identity_submit_result result =
        fk_exact_identity_sequencer_submit(
            state.config.sequencer,
            state.config.producer_index,
            &slot.descriptor);
    if (result == FK_EXACT_IDENTITY_SUBMIT_ACCEPTED) {
        /* Do not dereference mbuf after ACCEPTED: the identity/owner path may
         * already have consumed and freed it on another lcore. */
        state.counters.sequencer_transferred++;
        state.last_transferred_sequence = slot.descriptor.packet_sequence;
        state.last_sequence_initialized = 1u;
        remove_current_without_dereference(state);
        return FK_DPDK_EXACT_RX_PRODUCER_STEP_PACKET_TRANSFERRED;
    }
    if (result == FK_EXACT_IDENTITY_SUBMIT_QUEUE_FULL) {
        (void)increment(state, state.counters.queue_full_retries);
        return FK_DPDK_EXACT_RX_PRODUCER_STEP_QUEUE_FULL_RETAINED;
    }
    (void)increment(state, state.counters.sequencer_terminal_rejections);
    mark_terminal(
        state, FK_DPDK_EXACT_RX_PRODUCER_TERMINAL_SEQUENCER_REJECTED);
    return FK_DPDK_EXACT_RX_PRODUCER_STEP_TERMINAL;
}

bool accounting_conserved(const PumpState &state) {
    if (state.ownership_indeterminate != 0u)
        return false;
    const uint64_t transferred = state.counters.sequencer_transferred;
    const uint64_t reclaimed = state.counters.reclaimed;
    if (transferred > state.counters.rx_received ||
        reclaimed > state.counters.rx_received - transferred) {
        return false;
    }
    return transferred + reclaimed + state.pending_count ==
        state.counters.rx_received;
}

}  // namespace

extern "C" {

void fk_dpdk_exact_rx_producer_pump_default_config_init(
        fk_dpdk_exact_rx_producer_pump_config *config) {
    if (config == nullptr)
        return;
    *config = {};
    config->abi_version = FK_DPDK_EXACT_RX_PRODUCER_PUMP_ABI_VERSION;
    config->producer_count = 1u;
    config->burst_capacity = 32u;
}

bool fk_dpdk_exact_rx_producer_pump_config_valid(
        const fk_dpdk_exact_rx_producer_pump_config *config) {
    return basic_config_valid(config);
}

size_t fk_dpdk_exact_rx_producer_pump_storage_bytes(
        const fk_dpdk_exact_rx_producer_pump_config *config) {
    return required_bytes(config);
}

fk_dpdk_exact_rx_producer_pump *
fk_dpdk_exact_rx_producer_pump_initialize(
        void *storage,
        size_t storage_bytes,
        const fk_dpdk_exact_rx_producer_pump_config *config,
        char *error,
        size_t error_capacity) {
    set_error(error, error_capacity, "");
    const size_t required = required_bytes(config);
    if (storage == nullptr || required == 0u || storage_bytes < required ||
        reinterpret_cast<uintptr_t>(storage) % alignof(std::max_align_t) !=
            0u) {
        set_error(error, error_capacity,
            "invalid RX producer pump storage or configuration");
        return nullptr;
    }
    fk_exact_identity_sequencer_stats sequencer_stats{};
    if (!fk_exact_identity_sequencer_get_stats(
            config->sequencer, &sequencer_stats) ||
        sequencer_stats.producer_count != config->producer_count ||
        config->producer_index >= sequencer_stats.producer_count ||
        sequencer_stats.aborted || sequencer_stats.all_producers_closed) {
        set_error(error, error_capacity,
            "RX producer topology does not match live sequencer");
        return nullptr;
    }
    uintptr_t cursor = reinterpret_cast<uintptr_t>(storage);
    const uintptr_t end = cursor + storage_bytes;
    const uintptr_t state_remainder = cursor % alignof(PumpState);
    if (state_remainder != 0u)
        cursor += alignof(PumpState) - state_remainder;
    if (cursor > end || sizeof(PumpState) > end - cursor)
        return nullptr;
    auto *state = new (reinterpret_cast<void *>(cursor)) PumpState{};
    cursor += sizeof(PumpState);
    const uintptr_t slot_remainder = cursor % alignof(PendingSlot);
    if (slot_remainder != 0u)
        cursor += alignof(PendingSlot) - slot_remainder;
    size_t slot_bytes = 0u;
    if (!checked_multiply(
            config->burst_capacity, sizeof(PendingSlot), slot_bytes) ||
        cursor > end || slot_bytes > end - cursor) {
        state->~PumpState();
        return nullptr;
    }
    state->slots = reinterpret_cast<PendingSlot *>(cursor);
    for (uint16_t index = 0u; index < config->burst_capacity; ++index)
        new (&state->slots[index]) PendingSlot{};
    cursor += slot_bytes;
    const uintptr_t scratch_remainder = cursor % alignof(rte_mbuf *);
    if (scratch_remainder != 0u)
        cursor += alignof(rte_mbuf *) - scratch_remainder;
    size_t scratch_bytes = 0u;
    if (!checked_multiply(
            config->burst_capacity, sizeof(rte_mbuf *), scratch_bytes) ||
        cursor > end || scratch_bytes > end - cursor) {
        for (uint16_t index = 0u; index < config->burst_capacity; ++index)
            state->slots[index].~PendingSlot();
        state->~PumpState();
        return nullptr;
    }
    state->burst_scratch = reinterpret_cast<rte_mbuf **>(cursor);
    std::memset(state->burst_scratch, 0, scratch_bytes);
    state->magic = kMagic;
    state->config = *config;
    state->reserved_bytes = required;
    state->initialized = 1u;
    state->counters.abi_version =
        FK_DPDK_EXACT_RX_PRODUCER_PUMP_ABI_VERSION;
    state->counters.port_id = config->port_id;
    state->counters.queue_id = config->queue_id;
    state->counters.producer_index = config->producer_index;
    state->counters.producer_count = config->producer_count;
    state->counters.burst_capacity = config->burst_capacity;
    state->counters.initialized = 1u;
    state->counters.service_memory_bytes = required;
    return reinterpret_cast<fk_dpdk_exact_rx_producer_pump *>(state);
}

bool fk_dpdk_exact_rx_producer_pump_claim_thread(
        fk_dpdk_exact_rx_producer_pump *pump) {
    if (pump == nullptr)
        return false;
    PumpState &state = *implementation(pump);
    if (state.magic != kMagic || state.initialized == 0u)
        return false;
    state.thread_claim_attempts.fetch_add(1u, std::memory_order_relaxed);
    const uint64_t token = current_thread_token();
    uint64_t expected = 0u;
    if (token == 0u || !state.thread_token.compare_exchange_strong(
            expected,
            token,
            std::memory_order_acq_rel,
            std::memory_order_acquire)) {
        state.thread_claim_rejections.fetch_add(
            1u, std::memory_order_relaxed);
        return false;
    }
    state.thread_claim_successes.fetch_add(1u, std::memory_order_relaxed);
    return true;
}

fk_dpdk_exact_rx_producer_step_result
fk_dpdk_exact_rx_producer_pump_step(
        fk_dpdk_exact_rx_producer_pump *pump) {
    if (pump == nullptr)
        return FK_DPDK_EXACT_RX_PRODUCER_STEP_INVALID;
    PumpState &state = *implementation(pump);
    if (state.magic != kMagic || state.initialized == 0u)
        return FK_DPDK_EXACT_RX_PRODUCER_STEP_INVALID;
    if (!producer_thread(state))
        return FK_DPDK_EXACT_RX_PRODUCER_STEP_WRONG_THREAD;
    if (!increment(state, state.counters.step_calls))
        return abort_one(state);
    if (state.stopped_normal != 0u)
        return FK_DPDK_EXACT_RX_PRODUCER_STEP_STOPPED_NORMAL;
    if (state.stopped_abort != 0u)
        return FK_DPDK_EXACT_RX_PRODUCER_STEP_ABORTED_LOCAL;
    if (state.abort_requested != 0u)
        return abort_one(state);
    if (state.pending_count != 0u)
        return process_current(state);
    if (state.normal_stop_requested != 0u) {
        if (!close_producer(state))
            return FK_DPDK_EXACT_RX_PRODUCER_STEP_TERMINAL;
        state.stopped_normal = 1u;
        return FK_DPDK_EXACT_RX_PRODUCER_STEP_STOPPED_NORMAL;
    }
    return acquire_burst(state);
}

bool fk_dpdk_exact_rx_producer_pump_request_stop(
        fk_dpdk_exact_rx_producer_pump *pump) {
    if (pump == nullptr)
        return false;
    PumpState &state = *implementation(pump);
    if (state.magic != kMagic || state.initialized == 0u ||
        !producer_thread(state) || state.abort_requested != 0u ||
        state.stopped_abort != 0u) {
        return false;
    }
    if (state.normal_stop_requested == 0u) {
        if (!increment(state, state.counters.normal_stop_requests))
            return false;
        state.normal_stop_requested = 1u;
        state.acquisition_stopped = 1u;
    }
    return true;
}

bool fk_dpdk_exact_rx_producer_pump_request_abort(
        fk_dpdk_exact_rx_producer_pump *pump) {
    if (pump == nullptr)
        return false;
    PumpState &state = *implementation(pump);
    if (state.magic != kMagic || state.initialized == 0u ||
        !producer_thread(state) || state.stopped_normal != 0u) {
        return false;
    }
    if (state.abort_requested == 0u) {
        if (!increment(state, state.counters.abort_requests))
            return false;
        mark_terminal(
            state, FK_DPDK_EXACT_RX_PRODUCER_TERMINAL_EXPLICIT_ABORT);
    }
    return true;
}

bool fk_dpdk_exact_rx_producer_pump_get_stats(
        const fk_dpdk_exact_rx_producer_pump *pump,
        fk_dpdk_exact_rx_producer_pump_stats *stats) {
    if (pump == nullptr || stats == nullptr)
        return false;
    const PumpState &state = *implementation(pump);
    if (state.magic != kMagic || state.initialized == 0u)
        return false;
    *stats = state.counters;
    stats->thread_claim_attempts =
        state.thread_claim_attempts.load(std::memory_order_acquire);
    stats->thread_claim_successes =
        state.thread_claim_successes.load(std::memory_order_acquire);
    stats->thread_claim_rejections =
        state.thread_claim_rejections.load(std::memory_order_acquire);
    stats->wrong_thread_calls =
        state.wrong_thread_calls.load(std::memory_order_acquire);
    stats->pending = state.pending_count;
    if (state.pending_count != 0u) {
        const PendingSlot &slot = state.slots[state.pending_begin];
        stats->pending_packet_handle =
            reinterpret_cast<uintptr_t>(slot.mbuf);
        stats->pending_packet_sequence = slot.descriptor_ready != 0u
            ? slot.descriptor.packet_sequence : UINT64_MAX;
    } else {
        stats->pending_packet_handle = 0u;
        stats->pending_packet_sequence = UINT64_MAX;
    }
    stats->producer_thread_claimed =
        state.thread_token.load(std::memory_order_acquire) != 0u ? 1u : 0u;
    stats->acquisition_stopped = state.acquisition_stopped;
    stats->normal_stop_requested = state.normal_stop_requested;
    stats->abort_requested = state.abort_requested;
    stats->producer_closed = state.producer_closed;
    stats->stopped_normal = state.stopped_normal;
    stats->stopped_abort = state.stopped_abort;
    stats->requires_global_abort = state.requires_global_abort;
    stats->counter_overflow = state.counter_overflow;
    stats->accounting_conserved = accounting_conserved(state) ? 1u : 0u;
    stats->service_memory_exact =
        state.reserved_bytes == state.counters.service_memory_bytes ? 1u : 0u;
    return true;
}

bool fk_dpdk_exact_rx_producer_pump_destroy_checked(
        fk_dpdk_exact_rx_producer_pump *pump) {
    if (pump == nullptr)
        return false;
    PumpState &state = *implementation(pump);
    if (state.magic != kMagic || state.initialized == 0u ||
        state.pending_count != 0u || state.producer_closed == 0u ||
        (state.stopped_normal == 0u && state.stopped_abort == 0u) ||
        !accounting_conserved(state)) {
        return false;
    }
    for (uint16_t index = 0u;
         index < state.config.burst_capacity; ++index) {
        state.slots[index].~PendingSlot();
    }
    state.magic = 0u;
    state.initialized = 0u;
    state.~PumpState();
    return true;
}

bool fk_dpdk_exact_rx_producer_rte_eth_rx_burst(
        void *context,
        uint16_t port_id,
        uint16_t queue_id,
        rte_mbuf **packets,
        uint16_t capacity,
        uint16_t *received) {
    if (received != nullptr)
        *received = 0u;
    if (context != nullptr || packets == nullptr || received == nullptr ||
        capacity == 0u)
        return false;
    *received = rte_eth_rx_burst(port_id, queue_id, packets, capacity);
    return true;
}

#ifdef FK_DPDK_EXACT_RX_PRODUCER_PUMP_TEST_HOOKS
bool fk_dpdk_exact_rx_producer_pump_test_seed_accounting(
        fk_dpdk_exact_rx_producer_pump *pump,
        uint64_t rx_received,
        uint64_t sequencer_transferred,
        uint64_t reclaimed) {
    if (pump == nullptr)
        return false;
    PumpState &state = *implementation(pump);
    if (state.magic != kMagic || state.initialized == 0u ||
        state.thread_token.load(std::memory_order_acquire) != 0u ||
        state.pending_count != 0u || sequencer_transferred > rx_received ||
        reclaimed > rx_received - sequencer_transferred) {
        return false;
    }
    state.counters.rx_received = rx_received;
    state.counters.sequencer_transferred = sequencer_transferred;
    state.counters.reclaimed = reclaimed;
    return true;
}
#endif

}  // extern "C"
