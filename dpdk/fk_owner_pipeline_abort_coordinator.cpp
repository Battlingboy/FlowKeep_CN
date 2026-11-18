#include "fk_owner_pipeline_abort_coordinator.h"

#include <atomic>
#include <cstddef>
#include <cstring>
#include <limits>
#include <new>

#include "fk_fixed_owner_worker_pump.h"
#include "fk_owner_dispatch.h"
#include "fk_owner_output_batch_ring.h"
#include "fk_owner_output_sequence_bridge.h"

namespace {

constexpr uint64_t kMagic = UINT64_C(0x464b4142434f4f31);  // "FKABCOO1"

struct State {
    fk_owner_pipeline_abort_coordinator_config config{};
    fk_owner_output_batch_ring **owner_rings = nullptr;
    fk_fixed_owner_worker_pump **owner_pumps = nullptr;
    fk_fixed_owner_abort_prepared_receipt_v1 *owner_receipts = nullptr;
    fk_owner_abort_identity_prepared_receipt_v1 identity_receipt{};
    fk_owner_abort_identity_live_summary_v1 identity_summary{};
    fk_owner_envelope pending_dispatch_envelope{};
    uint16_t pending_dispatch_owner = UINT16_MAX;
    uint8_t pending_dispatch_envelope_present = 0u;
    uint8_t pending_dispatch_bridge_verified = 0u;
    uint8_t static_bridge_candidates_verified = 0u;
    fk_owner_pipeline_abort_receipt_v1 receipt{};
    fk_owner_pipeline_abort_coordinator_stats counters{};
    std::atomic<uint64_t> prepared_owner_mask{0u};
    std::atomic<uint64_t> fixed_owner_finalize_mask{0u};
    std::atomic<uint64_t> receipt_validation_attempts{0u};
    std::atomic<uint64_t> receipt_validation_successes{0u};
    std::atomic<uint64_t> receipt_validation_failures{0u};
    std::atomic<uint64_t> identity_finalize_authorizations{0u};
    std::atomic<uint8_t> identity_prepared{0u};
    std::atomic<uint8_t> committed{0u};
    std::atomic<uint8_t> terminal_failure{0u};
    size_t reserved_bytes = 0u;
    uint64_t magic = 0u;
};

static_assert(
    alignof(State) <= alignof(std::max_align_t),
    "abort coordinator exceeds max_align_t placement alignment");

State *implementation(fk_owner_pipeline_abort_coordinator *coordinator) {
    return reinterpret_cast<State *>(coordinator);
}

const State *implementation(
        const fk_owner_pipeline_abort_coordinator *coordinator) {
    return reinterpret_cast<const State *>(coordinator);
}

bool all_zero(const uint8_t *bytes, size_t length) {
    uint8_t combined = 0u;
    for (size_t index = 0u; index < length; ++index)
        combined = static_cast<uint8_t>(combined | bytes[index]);
    return combined == 0u;
}

bool independent_nonzero_keys(
        const fk_owner_pipeline_abort_coordinator_config &config) {
    uint8_t key0 = 0u;
    uint8_t key1 = 0u;
    uint8_t difference = 0u;
    for (size_t index = 0u;
         index < FK_OWNER_PIPELINE_ABORT_AUTH_KEY_BYTES; ++index) {
        key0 = static_cast<uint8_t>(
            key0 | config.authentication_key_0[index]);
        key1 = static_cast<uint8_t>(
            key1 | config.authentication_key_1[index]);
        difference = static_cast<uint8_t>(
            difference |
            (config.authentication_key_0[index] ^
             config.authentication_key_1[index]));
    }
    return key0 != 0u && key1 != 0u && difference != 0u;
}

bool valid_config_shape(
        const fk_owner_pipeline_abort_coordinator_config *config) {
    if (config == nullptr ||
        config->abi_version !=
            FK_OWNER_PIPELINE_ABORT_COORDINATOR_ABI_VERSION ||
        config->owner_count == 0u ||
        config->owner_count > FK_OWNER_ABORT_MAX_FIXED_OWNERS ||
        config->reserved0 != 0u || config->coordinator_epoch == 0u ||
        config->coordinator_epoch == UINT64_MAX ||
        config->keys_precommitted != 1u ||
        !all_zero(config->reserved, sizeof(config->reserved)) ||
        !independent_nonzero_keys(*config) || config->dispatch == nullptr ||
        config->bridge == nullptr || config->owner_rings == nullptr ||
        config->owner_pumps == nullptr ||
        config->identity_verify == nullptr ||
        config->identity_verify_context == nullptr ||
        config->dispatch_reclaim == nullptr) {
        return false;
    }
    for (uint16_t owner = 0u; owner < config->owner_count; ++owner) {
        if (config->owner_rings[owner] == nullptr ||
            config->owner_pumps[owner] == nullptr)
            return false;
        for (uint16_t previous = 0u; previous < owner; ++previous) {
            if (config->owner_rings[owner] ==
                    config->owner_rings[previous] ||
                config->owner_pumps[owner] ==
                    config->owner_pumps[previous]) {
                return false;
            }
        }
    }
    return true;
}

bool checked_add(size_t &value, size_t addend) {
    if (addend > std::numeric_limits<size_t>::max() - value)
        return false;
    value += addend;
    return true;
}

bool checked_multiply(size_t left, size_t right, size_t &result) {
    if (left != 0u &&
        right > std::numeric_limits<size_t>::max() / left) {
        return false;
    }
    result = left * right;
    return true;
}

bool align_size(size_t &value, size_t alignment) {
    const size_t remainder = value % alignment;
    return remainder == 0u || checked_add(value, alignment - remainder);
}

uintptr_t align_pointer(uintptr_t value, size_t alignment) {
    const uintptr_t remainder = value % alignment;
    return remainder == 0u ? value : value + alignment - remainder;
}

template <typename T>
T *take(uintptr_t &cursor, uintptr_t end, size_t count) {
    cursor = align_pointer(cursor, alignof(T));
    size_t bytes = 0u;
    if (!checked_multiply(count, sizeof(T), bytes) || cursor > end ||
        bytes > end - cursor) {
        return nullptr;
    }
    T *result = reinterpret_cast<T *>(cursor);
    cursor += bytes;
    return result;
}

size_t required_bytes(
        const fk_owner_pipeline_abort_coordinator_config *config) {
    if (!valid_config_shape(config))
        return 0u;
    size_t bytes = alignof(std::max_align_t) - 1u;
    size_t region = 0u;
    if (!align_size(bytes, alignof(State)) ||
        !checked_add(bytes, sizeof(State)) ||
        !align_size(bytes, alignof(fk_owner_output_batch_ring *)) ||
        !checked_multiply(
            config->owner_count,
            sizeof(fk_owner_output_batch_ring *),
            region) ||
        !checked_add(bytes, region) ||
        !align_size(bytes, alignof(fk_fixed_owner_worker_pump *)) ||
        !checked_multiply(
            config->owner_count,
            sizeof(fk_fixed_owner_worker_pump *),
            region) ||
        !checked_add(bytes, region) ||
        !align_size(
            bytes, alignof(fk_fixed_owner_abort_prepared_receipt_v1)) ||
        !checked_multiply(
            config->owner_count,
            sizeof(fk_fixed_owner_abort_prepared_receipt_v1),
            region) ||
        !checked_add(bytes, region)) {
        return 0u;
    }
    return bytes;
}

uint64_t full_owner_mask(uint16_t owner_count) {
    return owner_count == 64u
        ? UINT64_MAX
        : (UINT64_C(1) << owner_count) - UINT64_C(1);
}

bool increment(State &state, uint64_t &counter) {
    if (counter == UINT64_MAX) {
        state.terminal_failure.store(1u, std::memory_order_release);
        return false;
    }
    ++counter;
    return true;
}

bool checked_delta(uint64_t before, uint64_t after, uint64_t &delta) {
    if (after < before)
        return false;
    delta = after - before;
    return true;
}

bool identity_summary_valid(
        const fk_owner_abort_identity_prepared_receipt_v1 &receipt,
        const fk_owner_abort_identity_live_summary_v1 &summary) {
    if (receipt.abi_version != FK_OWNER_ABORT_PROTOCOL_ABI_VERSION ||
        receipt.receipt_ordinal != 1u ||
        receipt.pump_instance_token == 0u ||
        receipt.producer_count == 0u || receipt.candidate_present > 1u ||
        receipt.router_candidate_present > 1u ||
        summary.abi_version != FK_OWNER_ABORT_PROTOCOL_ABI_VERSION ||
        summary.producer_count != receipt.producer_count ||
        summary.exact_owned_mbufs != 0u ||
        summary.sequencer_owned_packets != 0u ||
        summary.inputs_stopped != 1u ||
        summary.admissions_stopped != 1u ||
        summary.rx_handoffs_resolved != 1u ||
        summary.accounting_conserved != 1u ||
        summary.router_candidate_declared !=
            receipt.router_candidate_present ||
        summary.submitted_packets != receipt.submitted_packets ||
        summary.data_transfers != receipt.data_transfers ||
        summary.reclaimed_packets != receipt.reclaimed_packets ||
        !all_zero(receipt.reserved, sizeof(receipt.reserved)) ||
        !all_zero(summary.reserved, sizeof(summary.reserved))) {
        return false;
    }
    return receipt.candidate_present != 0u ||
        receipt.router_candidate_present == 0u;
}

bool dispatch_stopped_and_drained(const State &state) {
    fk_owner_dispatch_stats stats{};
    return fk_owner_dispatch_get_stats(state.config.dispatch, &stats) &&
        stats.worker_count == state.config.owner_count &&
        stats.lifecycle != FK_OWNER_DISPATCH_ACCEPTING &&
        stats.in_flight_submitters == 0u && stats.total_depth == 0u &&
        stats.envelope_depth == 0u && stats.retire_control_depth == 0u &&
        stats.owned_packets == 0u && stats.ownership_conserved &&
        stats.retire_controls_conserved &&
        /* Reject only the legacy local bypass.  Ordered same-owner DATA is
         * intentionally queued and therefore leaves nonzero cumulative
         * local_enqueued/local_dequeued counters after a clean drain. */
        stats.local_packets == 0u &&
        stats.local_enqueued == stats.local_dequeued &&
        stats.remote_enqueued == stats.remote_dequeued &&
        stats.queued_enqueued == stats.queued_dequeued &&
        stats.ordered_sequence_failures == 0u &&
        stats.ordered_accepted_packets == stats.accepted_packets &&
        fk_owner_dispatch_drain_complete(state.config.dispatch);
}

bool dispatch_admission_stopped(const State &state) {
    fk_owner_dispatch_stats stats{};
    return fk_owner_dispatch_get_stats(state.config.dispatch, &stats) &&
        stats.worker_count == state.config.owner_count &&
        stats.lifecycle != FK_OWNER_DISPATCH_ACCEPTING &&
        stats.in_flight_submitters == 0u;
}

enum class DispatchDrainProgress : uint8_t {
    Complete,
    Retry,
    Failed,
};

bool exact_active_data_reservation(
        const State &state,
        uint64_t packet_sequence,
        uint16_t expected_owner) {
    fk_owner_active_reservation_v1 reservation{};
    return fk_owner_output_sequence_bridge_query_active_reservation(
            state.config.bridge,
            packet_sequence,
            &reservation) == FK_OWNER_ACTIVE_RESERVATION_BOUND &&
        reservation.packet_sequence == packet_sequence &&
        reservation.expected_owner == expected_owner &&
        reservation.route_kind == FK_OWNER_RESERVED_ROUTE_DATA;
}

bool exact_active_router_reservation(
        const State &state,
        uint64_t packet_sequence) {
    fk_owner_active_reservation_v1 reservation{};
    const fk_owner_active_reservation_state result =
        fk_owner_output_sequence_bridge_query_active_reservation(
            state.config.bridge, packet_sequence, &reservation);
    return reservation.packet_sequence == packet_sequence &&
        (result == FK_OWNER_ACTIVE_RESERVATION_UNBOUND ||
         result == FK_OWNER_ACTIVE_RESERVATION_BOUND);
}

bool verify_static_bridge_candidates(State &state) {
    if (state.static_bridge_candidates_verified != 0u)
        return true;
    uint64_t sequences[FK_OWNER_ABORT_MAX_FIXED_OWNERS + 1u]{};
    size_t sequence_count = 0u;
    uint64_t verified = 0u;
    for (uint16_t owner = 0u; owner < state.config.owner_count; ++owner) {
        const fk_fixed_owner_abort_prepared_receipt_v1 &receipt =
            state.owner_receipts[owner];
        if (receipt.first_sequence_candidate_present == 0u)
            continue;
        if (!exact_active_data_reservation(
                state, receipt.first_sequence_candidate, owner)) {
            return false;
        }
        for (size_t index = 0u; index < sequence_count; ++index) {
            if (sequences[index] == receipt.first_sequence_candidate)
                return false;
        }
        sequences[sequence_count++] = receipt.first_sequence_candidate;
        ++verified;
    }
    if (state.identity_receipt.router_candidate_present != 0u) {
        const uint64_t sequence =
            state.identity_receipt.candidate.packet_sequence;
        if (state.identity_receipt.candidate_present == 0u ||
            !exact_active_router_reservation(state, sequence)) {
            return false;
        }
        for (size_t index = 0u; index < sequence_count; ++index) {
            if (sequences[index] == sequence)
                return false;
        }
        sequences[sequence_count++] = sequence;
        ++verified;
    }
    state.counters.bridge_bound_loss_candidates = verified;
    state.counters.bridge_bound_candidates_exact_verified = verified;
    state.static_bridge_candidates_verified = 1u;
    return true;
}

DispatchDrainProgress reclaim_pending_dispatch_data(State &state) {
    if (state.pending_dispatch_envelope_present == 0u)
        return DispatchDrainProgress::Complete;
    if (state.pending_dispatch_owner >= state.config.owner_count ||
        state.pending_dispatch_envelope.kind != FK_OWNER_ENVELOPE_DATA ||
        state.pending_dispatch_envelope.payload.data.packet_handle == 0u ||
        state.pending_dispatch_envelope.payload.data.owner_worker !=
            state.pending_dispatch_owner ||
        state.pending_dispatch_bridge_verified == 0u ||
        state.counters.dispatch_reclaim_attempts == UINT64_MAX ||
        state.counters.dispatch_reclaim_successes == UINT64_MAX ||
        state.counters.dispatch_reclaim_failures == UINT64_MAX) {
        state.terminal_failure.store(1u, std::memory_order_release);
        return DispatchDrainProgress::Failed;
    }
    ++state.counters.dispatch_reclaim_attempts;
    const uintptr_t handle =
        state.pending_dispatch_envelope.payload.data.packet_handle;
    if (!state.config.dispatch_reclaim(
            state.config.dispatch_reclaim_context,
            state.pending_dispatch_owner,
            handle)) {
        ++state.counters.dispatch_reclaim_failures;
        return DispatchDrainProgress::Retry;
    }
    ++state.counters.dispatch_reclaim_successes;
    state.pending_dispatch_envelope = {};
    state.pending_dispatch_owner = UINT16_MAX;
    state.pending_dispatch_envelope_present = 0u;
    state.pending_dispatch_bridge_verified = 0u;
    return DispatchDrainProgress::Complete;
}

DispatchDrainProgress drain_dispatch(State &state) {
    const DispatchDrainProgress pending =
        reclaim_pending_dispatch_data(state);
    if (pending != DispatchDrainProgress::Complete)
        return pending;
    for (uint16_t owner = 0u; owner < state.config.owner_count; ++owner) {
        for (;;) {
            if (!increment(state, state.counters.dispatch_drain_attempts))
                return DispatchDrainProgress::Failed;
            fk_owner_envelope envelope{};
            if (!fk_owner_dispatch_drain_next_envelope(
                    state.config.dispatch, owner, &envelope)) {
                if (!increment(state, state.counters.dispatch_drain_empty))
                    return DispatchDrainProgress::Failed;
                break;
            }
            if (envelope.kind == FK_OWNER_ENVELOPE_QUIC_RETIRE) {
                if (envelope.payload.quic_retire.fixed_owner != owner ||
                    !increment(
                        state,
                        state.counters
                            .dispatch_retire_controls_discarded)) {
                    return DispatchDrainProgress::Failed;
                }
                continue;
            }
            if (envelope.kind != FK_OWNER_ENVELOPE_DATA ||
                envelope.payload.data.owner_worker != owner ||
                envelope.payload.data.packet_handle == 0u) {
                return DispatchDrainProgress::Failed;
            }
            state.pending_dispatch_envelope = envelope;
            state.pending_dispatch_owner = owner;
            state.pending_dispatch_envelope_present = 1u;
            if (!exact_active_data_reservation(
                    state, envelope.payload.data.packet_sequence, owner) ||
                state.counters.dispatch_data_drained == UINT64_MAX ||
                state.counters.bridge_bound_loss_candidates == UINT64_MAX ||
                state.counters
                        .bridge_bound_candidates_exact_verified ==
                    UINT64_MAX) {
                state.terminal_failure.store(1u, std::memory_order_release);
                return DispatchDrainProgress::Failed;
            }
            state.pending_dispatch_bridge_verified = 1u;
            ++state.counters.dispatch_data_drained;
            ++state.counters.bridge_bound_loss_candidates;
            ++state.counters.bridge_bound_candidates_exact_verified;
            const DispatchDrainProgress reclaimed =
                reclaim_pending_dispatch_data(state);
            if (reclaimed != DispatchDrainProgress::Complete)
                return reclaimed;
        }
    }
    return fk_owner_dispatch_drain_complete(state.config.dispatch)
        ? DispatchDrainProgress::Complete
        : DispatchDrainProgress::Failed;
}

bool rings_stopped(const State &state, bool require_empty) {
    for (uint16_t owner = 0u; owner < state.config.owner_count; ++owner) {
        fk_owner_output_batch_ring_stats stats{};
        if (!fk_owner_output_batch_ring_get_stats(
                state.owner_rings[owner], &stats) ||
            stats.fixed_owner != owner ||
            stats.lifecycle != FK_OWNER_OUTPUT_BATCH_RING_STOPPED ||
            stats.pending_commit_ordinal != 0u ||
            !stats.ownership_conserved ||
            (require_empty &&
             (stats.depth != 0u || stats.owned_batches != 0u))) {
            return false;
        }
    }
    return true;
}

uint64_t rotate_left(uint64_t value, unsigned shift) {
    return (value << shift) | (value >> (64u - shift));
}

uint64_t load_u64_le(const uint8_t *bytes) {
    uint64_t result = 0u;
    for (unsigned index = 0u; index < 8u; ++index)
        result |= static_cast<uint64_t>(bytes[index]) << (index * 8u);
    return result;
}

void sip_round(uint64_t &v0, uint64_t &v1, uint64_t &v2, uint64_t &v3) {
    v0 += v1;
    v1 = rotate_left(v1, 13u);
    v1 ^= v0;
    v0 = rotate_left(v0, 32u);
    v2 += v3;
    v3 = rotate_left(v3, 16u);
    v3 ^= v2;
    v0 += v3;
    v3 = rotate_left(v3, 21u);
    v3 ^= v0;
    v2 += v1;
    v1 = rotate_left(v1, 17u);
    v1 ^= v2;
    v2 = rotate_left(v2, 32u);
}

uint64_t siphash24(
        const uint8_t key[FK_OWNER_PIPELINE_ABORT_AUTH_KEY_BYTES],
        const uint8_t *message,
        size_t length) {
    const uint64_t k0 = load_u64_le(key);
    const uint64_t k1 = load_u64_le(key + 8u);
    uint64_t v0 = UINT64_C(0x736f6d6570736575) ^ k0;
    uint64_t v1 = UINT64_C(0x646f72616e646f6d) ^ k1;
    uint64_t v2 = UINT64_C(0x6c7967656e657261) ^ k0;
    uint64_t v3 = UINT64_C(0x7465646279746573) ^ k1;
    const size_t blocks = length / 8u;
    for (size_t index = 0u; index < blocks; ++index) {
        const uint64_t word = load_u64_le(message + index * 8u);
        v3 ^= word;
        sip_round(v0, v1, v2, v3);
        sip_round(v0, v1, v2, v3);
        v0 ^= word;
    }
    uint64_t tail = static_cast<uint64_t>(length) << 56u;
    const size_t offset = blocks * 8u;
    for (size_t index = 0u; index < length - offset; ++index) {
        tail |= static_cast<uint64_t>(message[offset + index]) <<
            (index * 8u);
    }
    v3 ^= tail;
    sip_round(v0, v1, v2, v3);
    sip_round(v0, v1, v2, v3);
    v0 ^= tail;
    v2 ^= UINT64_C(0xff);
    for (unsigned index = 0u; index < 4u; ++index)
        sip_round(v0, v1, v2, v3);
    return v0 ^ v1 ^ v2 ^ v3;
}

uint64_t receipt_tag(
        const State &state,
        const fk_owner_pipeline_abort_receipt_v1 &receipt,
        size_t key_index) {
    constexpr uint8_t domain[8] = {
        'F', 'K', 'A', 'B', 'O', 'R', 'T', '1',
    };
    constexpr size_t payload_bytes =
        offsetof(fk_owner_pipeline_abort_receipt_v1, auth_tag);
    uint8_t material[sizeof(domain) + payload_bytes]{};
    std::memcpy(material, domain, sizeof(domain));
    std::memcpy(
        material + sizeof(domain), &receipt, payload_bytes);
    return siphash24(
        key_index == 0u ? state.config.authentication_key_0
                        : state.config.authentication_key_1,
        material,
        sizeof(material));
}

bool constant_time_equal_u64(uint64_t left, uint64_t right) {
    uint64_t difference = left ^ right;
    difference |= difference >> 32u;
    difference |= difference >> 16u;
    difference |= difference >> 8u;
    return (difference & UINT64_C(0xff)) == 0u;
}

bool receipt_shape_valid(
        const State &state,
        const fk_owner_pipeline_abort_receipt_v1 &receipt) {
    return receipt.abi_version == FK_OWNER_ABORT_PROTOCOL_ABI_VERSION &&
        receipt.owner_count == state.config.owner_count &&
        receipt.identity_participant_count == 1u &&
        receipt.coordinator_epoch == state.config.coordinator_epoch &&
        receipt.receipt_ordinal == 1u &&
        receipt.prepared_owner_mask ==
            full_owner_mask(state.config.owner_count) &&
        (receipt.bridge_outcome ==
             FK_OWNER_PIPELINE_ABORT_BRIDGE_ACTIVE_RECORDED ||
         receipt.bridge_outcome ==
             FK_OWNER_PIPELINE_ABORT_BRIDGE_NO_ACTIVE) &&
        receipt.identity_prepared_verified == 1u &&
        receipt.dispatch_admissions_stopped == 1u &&
        receipt.dispatch_drained == 1u &&
        receipt.all_owner_prepared_verified == 1u &&
        receipt.outboxes_resolved == 1u &&
        receipt.all_owner_rings_stopped == 1u &&
        receipt.bridge_cleanup_done == 1u &&
        receipt.bridge_clean_state_verified == 1u &&
        receipt.dispatch_pending_ownership == 0u &&
        receipt.bridge_bound_candidates_exact_verified ==
            receipt.bridge_bound_loss_candidates &&
        all_zero(receipt.reserved, sizeof(receipt.reserved)) &&
        (receipt.bridge_outcome !=
             FK_OWNER_PIPELINE_ABORT_BRIDGE_NO_ACTIVE ||
         receipt.bridge_bound_loss_candidates == 0u);
}

bool live_receipt_state_valid(
        const State &state,
        const fk_owner_pipeline_abort_receipt_v1 &receipt) {
    fk_owner_output_sequence_bridge_stats bridge{};
    if (!dispatch_stopped_and_drained(state) ||
        !rings_stopped(state, true) ||
        !fk_owner_output_sequence_bridge_get_stats(
            state.config.bridge, &bridge) ||
        !bridge.reservations_stopped || !bridge.completions_stopped ||
        !bridge.abort_cleanup_done || bridge.active_reservations != 0u ||
        bridge.payloads_in_use != 0u ||
        bridge.reorder_envelopes_remaining != 0u ||
        bridge.owner_ring_batches_remaining != 0u) {
        return false;
    }
    if (receipt.bridge_outcome ==
            FK_OWNER_PIPELINE_ABORT_BRIDGE_ACTIVE_RECORDED) {
        fk_owner_reserved_abort_receipt_v1 abort{};
        return bridge.abort_receipt_present && !bridge.abort_no_active &&
            fk_owner_output_sequence_bridge_get_abort_receipt(
                state.config.bridge, &abort) &&
            abort.packet_sequence == receipt.bridge_abort_packet_sequence &&
            abort.receipt_ordinal ==
                receipt.bridge_abort_receipt_ordinal &&
            abort.expected_owner == receipt.bridge_abort_expected_owner &&
            abort.route_kind == receipt.bridge_abort_route_kind &&
            abort.abort_reason == receipt.bridge_abort_reason &&
            abort.slot_was_bound ==
                receipt.bridge_abort_slot_was_bound;
    }
    return bridge.abort_no_active && !bridge.abort_receipt_present &&
        receipt.bridge_abort_packet_sequence == 0u &&
        receipt.bridge_abort_receipt_ordinal == 0u;
}

bool validate_receipt_impl(
        const State &state,
        const fk_owner_pipeline_abort_receipt_v1 *receipt) {
    if (receipt == nullptr ||
        state.committed.load(std::memory_order_acquire) == 0u ||
        !receipt_shape_valid(state, *receipt) ||
        std::memcmp(receipt, &state.receipt, sizeof(*receipt)) != 0) {
        return false;
    }
    const uint64_t tag0 = receipt_tag(state, *receipt, 0u);
    const uint64_t tag1 = receipt_tag(state, *receipt, 1u);
    return constant_time_equal_u64(receipt->auth_tag[0], tag0) &&
        constant_time_equal_u64(receipt->auth_tag[1], tag1) &&
        live_receipt_state_valid(state, *receipt);
}

void saturating_atomic_increment(std::atomic<uint64_t> &counter) {
    uint64_t value = counter.load(std::memory_order_relaxed);
    while (value != UINT64_MAX &&
           !counter.compare_exchange_weak(
               value,
               value + 1u,
               std::memory_order_relaxed,
               std::memory_order_relaxed)) {
    }
}

}  // namespace

extern "C" {

void fk_owner_pipeline_abort_coordinator_default_config_init(
        fk_owner_pipeline_abort_coordinator_config *config) {
    if (config == nullptr)
        return;
    *config = {};
    config->abi_version =
        FK_OWNER_PIPELINE_ABORT_COORDINATOR_ABI_VERSION;
    config->owner_count = 1u;
    /* Keys intentionally remain zero and uncommitted. */
}

bool fk_owner_pipeline_abort_coordinator_config_valid(
        const fk_owner_pipeline_abort_coordinator_config *config) {
    if (!valid_config_shape(config))
        return false;
    fk_owner_dispatch_stats dispatch{};
    fk_owner_output_sequence_bridge_stats bridge{};
    if (!fk_owner_dispatch_get_stats(config->dispatch, &dispatch) ||
        dispatch.worker_count != config->owner_count ||
        !fk_owner_output_sequence_bridge_get_stats(
            config->bridge, &bridge) ||
        bridge.abi_version != FK_OWNER_OUTPUT_SEQUENCE_BRIDGE_ABI_VERSION ||
        bridge.owner_count != config->owner_count ||
        bridge.abort_cleanup_done || bridge.sealed) {
        return false;
    }
    for (uint16_t owner = 0u; owner < config->owner_count; ++owner) {
        fk_owner_output_batch_ring_stats ring{};
        if (!fk_owner_output_batch_ring_get_stats(
                config->owner_rings[owner], &ring) ||
            ring.fixed_owner != owner)
            return false;
    }
    return true;
}

size_t fk_owner_pipeline_abort_coordinator_storage_bytes(
        const fk_owner_pipeline_abort_coordinator_config *config) {
    return fk_owner_pipeline_abort_coordinator_config_valid(config)
        ? required_bytes(config) : 0u;
}

fk_owner_pipeline_abort_coordinator *
fk_owner_pipeline_abort_coordinator_initialize(
        void *storage,
        size_t storage_bytes,
        const fk_owner_pipeline_abort_coordinator_config *config) {
    const size_t required =
        fk_owner_pipeline_abort_coordinator_storage_bytes(config);
    if (storage == nullptr || required == 0u || storage_bytes < required ||
        reinterpret_cast<uintptr_t>(storage) % alignof(std::max_align_t) !=
            0u ||
        storage_bytes > std::numeric_limits<uintptr_t>::max() -
            reinterpret_cast<uintptr_t>(storage)) {
        return nullptr;
    }
    uintptr_t cursor = reinterpret_cast<uintptr_t>(storage);
    const uintptr_t end = cursor + storage_bytes;
    State *state = take<State>(cursor, end, 1u);
    fk_owner_output_batch_ring **rings =
        take<fk_owner_output_batch_ring *>(
            cursor, end, config->owner_count);
    fk_fixed_owner_worker_pump **pumps =
        take<fk_fixed_owner_worker_pump *>(
            cursor, end, config->owner_count);
    fk_fixed_owner_abort_prepared_receipt_v1 *receipts =
        take<fk_fixed_owner_abort_prepared_receipt_v1>(
            cursor, end, config->owner_count);
    if (state == nullptr || rings == nullptr || pumps == nullptr ||
        receipts == nullptr) {
        return nullptr;
    }
    state = new (state) State{};
    for (uint16_t owner = 0u; owner < config->owner_count; ++owner) {
        rings[owner] = config->owner_rings[owner];
        pumps[owner] = config->owner_pumps[owner];
        receipts[owner] = {};
    }
    state->config = *config;
    state->owner_rings = rings;
    state->owner_pumps = pumps;
    state->owner_receipts = receipts;
    state->config.owner_rings = rings;
    state->config.owner_pumps = pumps;
    state->reserved_bytes = required;
    state->counters.abi_version =
        FK_OWNER_PIPELINE_ABORT_COORDINATOR_ABI_VERSION;
    state->counters.owner_count = config->owner_count;
    state->counters.coordinator_epoch = config->coordinator_epoch;
    state->counters.service_memory_bytes = required;
    state->counters.service_memory_exact = 1u;
    state->magic = kMagic;
    return reinterpret_cast<fk_owner_pipeline_abort_coordinator *>(state);
}

fk_owner_pipeline_abort_record_result
fk_owner_pipeline_abort_coordinator_record_owner_prepared(
        fk_owner_pipeline_abort_coordinator *coordinator,
        const fk_fixed_owner_abort_prepared_receipt_v1 *receipt) {
    if (coordinator == nullptr || receipt == nullptr)
        return FK_OWNER_PIPELINE_ABORT_RECORD_INVALID;
    State &state = *implementation(coordinator);
    if (state.magic != kMagic)
        return FK_OWNER_PIPELINE_ABORT_RECORD_INVALID;
    if (!increment(state, state.counters.owner_record_attempts))
        return FK_OWNER_PIPELINE_ABORT_RECORD_TERMINAL;
    if (state.terminal_failure.load(std::memory_order_acquire) != 0u)
        return FK_OWNER_PIPELINE_ABORT_RECORD_TERMINAL;
    if (state.committed.load(std::memory_order_acquire) != 0u)
        return FK_OWNER_PIPELINE_ABORT_ALREADY_COMMITTED;
    if (receipt->fixed_owner >= state.config.owner_count ||
        !fk_fixed_owner_worker_pump_validate_abort_prepared_receipt(
            state.owner_pumps[receipt->fixed_owner], receipt)) {
        (void)increment(state, state.counters.owner_receipt_rejections);
        return FK_OWNER_PIPELINE_ABORT_NOT_VERIFIED;
    }
    const uint64_t bit = UINT64_C(1) << receipt->fixed_owner;
    const uint64_t mask =
        state.prepared_owner_mask.load(std::memory_order_acquire);
    if ((mask & bit) != 0u) {
        if (std::memcmp(
                &state.owner_receipts[receipt->fixed_owner],
                receipt,
                sizeof(*receipt)) == 0) {
            (void)increment(
                state, state.counters.owner_receipt_duplicates);
            return FK_OWNER_PIPELINE_ABORT_ALREADY_RECORDED;
        }
        (void)increment(state, state.counters.owner_receipt_rejections);
        state.terminal_failure.store(1u, std::memory_order_release);
        return FK_OWNER_PIPELINE_ABORT_RECEIPT_MISMATCH;
    }
    state.owner_receipts[receipt->fixed_owner] = *receipt;
    state.prepared_owner_mask.store(mask | bit, std::memory_order_release);
    (void)increment(state, state.counters.owner_receipts_recorded);
    return FK_OWNER_PIPELINE_ABORT_RECORDED;
}

fk_owner_pipeline_abort_record_result
fk_owner_pipeline_abort_coordinator_record_identity_prepared(
        fk_owner_pipeline_abort_coordinator *coordinator,
        const fk_owner_abort_identity_prepared_receipt_v1 *receipt) {
    if (coordinator == nullptr || receipt == nullptr)
        return FK_OWNER_PIPELINE_ABORT_RECORD_INVALID;
    State &state = *implementation(coordinator);
    if (state.magic != kMagic)
        return FK_OWNER_PIPELINE_ABORT_RECORD_INVALID;
    if (!increment(state, state.counters.identity_record_attempts))
        return FK_OWNER_PIPELINE_ABORT_RECORD_TERMINAL;
    if (state.terminal_failure.load(std::memory_order_acquire) != 0u)
        return FK_OWNER_PIPELINE_ABORT_RECORD_TERMINAL;
    if (state.committed.load(std::memory_order_acquire) != 0u)
        return FK_OWNER_PIPELINE_ABORT_ALREADY_COMMITTED;
    fk_owner_abort_identity_live_summary_v1 summary{};
    if (!state.config.identity_verify(
            state.config.identity_verify_context, receipt, &summary) ||
        !identity_summary_valid(*receipt, summary)) {
        (void)increment(state, state.counters.identity_receipt_rejections);
        return FK_OWNER_PIPELINE_ABORT_NOT_VERIFIED;
    }
    if (state.identity_prepared.load(std::memory_order_acquire) != 0u) {
        if (std::memcmp(
                &state.identity_receipt, receipt, sizeof(*receipt)) == 0 &&
            std::memcmp(
                &state.identity_summary, &summary, sizeof(summary)) == 0) {
            (void)increment(
                state, state.counters.identity_receipt_duplicates);
            return FK_OWNER_PIPELINE_ABORT_ALREADY_RECORDED;
        }
        (void)increment(state, state.counters.identity_receipt_rejections);
        state.terminal_failure.store(1u, std::memory_order_release);
        return FK_OWNER_PIPELINE_ABORT_RECEIPT_MISMATCH;
    }
    state.identity_receipt = *receipt;
    state.identity_summary = summary;
    state.identity_prepared.store(1u, std::memory_order_release);
    (void)increment(state, state.counters.identity_receipts_recorded);
    return FK_OWNER_PIPELINE_ABORT_RECORDED;
}

fk_owner_pipeline_abort_commit_result
fk_owner_pipeline_abort_coordinator_commit(
        fk_owner_pipeline_abort_coordinator *coordinator) {
    if (coordinator == nullptr)
        return FK_OWNER_PIPELINE_ABORT_COMMIT_INVALID;
    State &state = *implementation(coordinator);
    if (state.magic != kMagic)
        return FK_OWNER_PIPELINE_ABORT_COMMIT_INVALID;
    if (!increment(state, state.counters.commit_attempts))
        return FK_OWNER_PIPELINE_ABORT_COMMIT_TERMINAL;
    if (state.committed.load(std::memory_order_acquire) != 0u)
        return FK_OWNER_PIPELINE_ABORT_COMMIT_ALREADY_COMMITTED;
    if (state.terminal_failure.load(std::memory_order_acquire) != 0u)
        return FK_OWNER_PIPELINE_ABORT_COMMIT_TERMINAL;
    const uint64_t expected_mask = full_owner_mask(state.config.owner_count);
    if (state.prepared_owner_mask.load(std::memory_order_acquire) !=
            expected_mask ||
        state.identity_prepared.load(std::memory_order_acquire) == 0u) {
        (void)increment(state, state.counters.commit_not_ready);
        return FK_OWNER_PIPELINE_ABORT_COMMIT_NOT_READY;
    }
    for (uint16_t owner = 0u; owner < state.config.owner_count; ++owner) {
        if (!fk_fixed_owner_worker_pump_validate_abort_prepared_receipt(
                state.owner_pumps[owner], &state.owner_receipts[owner])) {
            (void)increment(state, state.counters.commit_failures);
            return FK_OWNER_PIPELINE_ABORT_COMMIT_EVIDENCE_REJECTED;
        }
    }
    fk_owner_abort_identity_live_summary_v1 identity_live{};
    if (!state.config.identity_verify(
            state.config.identity_verify_context,
            &state.identity_receipt,
            &identity_live) ||
        !identity_summary_valid(state.identity_receipt, identity_live) ||
        std::memcmp(
            &identity_live,
            &state.identity_summary,
            sizeof(identity_live)) != 0 ||
        !rings_stopped(state, false)) {
        (void)increment(state, state.counters.commit_not_ready);
        return FK_OWNER_PIPELINE_ABORT_COMMIT_NOT_READY;
    }
    if (!fk_owner_output_sequence_bridge_claim_abort_consumer_thread(
            state.config.bridge) ||
        !verify_static_bridge_candidates(state)) {
        (void)increment(state, state.counters.commit_failures);
        return FK_OWNER_PIPELINE_ABORT_COMMIT_EVIDENCE_REJECTED;
    }
    if (!increment(state, state.counters.dispatch_abort_attempts) ||
        !fk_owner_dispatch_abort(state.config.dispatch)) {
        (void)increment(state, state.counters.commit_failures);
        return FK_OWNER_PIPELINE_ABORT_COMMIT_EVIDENCE_REJECTED;
    }
    (void)increment(state, state.counters.dispatch_abort_successes);
    if (!dispatch_admission_stopped(state)) {
        (void)increment(state, state.counters.commit_not_ready);
        return FK_OWNER_PIPELINE_ABORT_COMMIT_NOT_READY;
    }
    const DispatchDrainProgress drained = drain_dispatch(state);
    if (drained == DispatchDrainProgress::Retry) {
        (void)increment(state, state.counters.commit_not_ready);
        return FK_OWNER_PIPELINE_ABORT_COMMIT_RETRY_REQUIRED;
    }
    if (drained != DispatchDrainProgress::Complete ||
        !dispatch_stopped_and_drained(state)) {
        (void)increment(state, state.counters.commit_failures);
        state.terminal_failure.store(1u, std::memory_order_release);
        return FK_OWNER_PIPELINE_ABORT_COMMIT_EVIDENCE_REJECTED;
    }
    fk_owner_output_sequence_bridge_stats before{};
    if (!fk_owner_output_sequence_bridge_get_stats(
            state.config.bridge, &before) ||
        !before.reservations_stopped || before.abort_cleanup_done) {
        (void)increment(state, state.counters.commit_failures);
        return FK_OWNER_PIPELINE_ABORT_COMMIT_BRIDGE_FAILED;
    }

    const uint64_t bridge_bound_candidates =
        state.counters.bridge_bound_loss_candidates;
    if (before.active_reservations < bridge_bound_candidates) {
        (void)increment(state, state.counters.commit_failures);
        return FK_OWNER_PIPELINE_ABORT_COMMIT_EVIDENCE_REJECTED;
    }
    if (!fk_owner_output_sequence_bridge_stop_completions(
            state.config.bridge)) {
        (void)increment(state, state.counters.commit_failures);
        return FK_OWNER_PIPELINE_ABORT_COMMIT_BRIDGE_FAILED;
    }

    const fk_owner_abort_first_active_result bridge_abort =
        fk_owner_output_sequence_bridge_abort_first_active(
            state.config.bridge,
            FK_OWNER_RESERVED_ABORT_SHUTDOWN_TERMINAL);
    if (bridge_abort != FK_OWNER_ABORT_FIRST_ACTIVE_RECORDED &&
        bridge_abort != FK_OWNER_ABORT_FIRST_ACTIVE_ALREADY_RECORDED &&
        bridge_abort != FK_OWNER_ABORT_FIRST_ACTIVE_NO_ACTIVE) {
        (void)increment(state, state.counters.commit_failures);
        state.terminal_failure.store(1u, std::memory_order_release);
        return FK_OWNER_PIPELINE_ABORT_COMMIT_BRIDGE_FAILED;
    }
    if (!fk_owner_output_sequence_bridge_cleanup_aborted(
            state.config.bridge)) {
        (void)increment(state, state.counters.commit_failures);
        state.terminal_failure.store(1u, std::memory_order_release);
        return FK_OWNER_PIPELINE_ABORT_COMMIT_CLEANUP_FAILED;
    }
    fk_owner_output_sequence_bridge_stats after{};
    if (!fk_owner_output_sequence_bridge_get_stats(
            state.config.bridge, &after) ||
        !after.reservations_stopped || !after.completions_stopped ||
        !after.abort_cleanup_done || after.active_reservations != 0u ||
        after.payloads_in_use != 0u ||
        after.reorder_envelopes_remaining != 0u ||
        after.owner_ring_batches_remaining != 0u ||
        !rings_stopped(state, true)) {
        (void)increment(state, state.counters.commit_failures);
        state.terminal_failure.store(1u, std::memory_order_release);
        return FK_OWNER_PIPELINE_ABORT_COMMIT_CLEANUP_FAILED;
    }

    fk_owner_pipeline_abort_receipt_v1 result{};
    result.abi_version = FK_OWNER_ABORT_PROTOCOL_ABI_VERSION;
    result.owner_count = state.config.owner_count;
    result.identity_participant_count = 1u;
    result.coordinator_epoch = state.config.coordinator_epoch;
    result.receipt_ordinal = 1u;
    result.prepared_owner_mask = expected_mask;
    if (!checked_delta(
            before.aborted_reservations_cleaned,
            after.aborted_reservations_cleaned,
            result.reservations_cleaned) ||
        !checked_delta(
            before.aborted_ring_batches_drained,
            after.aborted_ring_batches_drained,
            result.ring_batches_cleaned) ||
        !checked_delta(
            before.aborted_reorder_envelopes_drained,
            after.aborted_reorder_envelopes_drained,
            result.reorder_envelopes_cleaned) ||
        !checked_delta(
            before.aborted_reorder_checkpoint_payloads_released,
            after.aborted_reorder_checkpoint_payloads_released,
            result.checkpoint_payloads_cleaned)) {
        (void)increment(state, state.counters.commit_failures);
        state.terminal_failure.store(1u, std::memory_order_release);
        return FK_OWNER_PIPELINE_ABORT_COMMIT_TERMINAL;
    }
    for (uint16_t owner = 0u; owner < state.config.owner_count; ++owner) {
        const uint64_t value =
            state.owner_receipts[owner].completion_values_discarded;
        if (value > UINT64_MAX - result.completion_values_discarded) {
            (void)increment(state, state.counters.commit_failures);
            state.terminal_failure.store(1u, std::memory_order_release);
            return FK_OWNER_PIPELINE_ABORT_COMMIT_TERMINAL;
        }
        result.completion_values_discarded += value;
    }
    if (bridge_abort == FK_OWNER_ABORT_FIRST_ACTIVE_NO_ACTIVE) {
        if (bridge_bound_candidates != 0u) {
            (void)increment(state, state.counters.commit_failures);
            state.terminal_failure.store(1u, std::memory_order_release);
            return FK_OWNER_PIPELINE_ABORT_COMMIT_BRIDGE_FAILED;
        }
        result.bridge_outcome =
            FK_OWNER_PIPELINE_ABORT_BRIDGE_NO_ACTIVE;
    } else {
        fk_owner_reserved_abort_receipt_v1 abort{};
        if (!fk_owner_output_sequence_bridge_get_abort_receipt(
                state.config.bridge, &abort)) {
            (void)increment(state, state.counters.commit_failures);
            state.terminal_failure.store(1u, std::memory_order_release);
            return FK_OWNER_PIPELINE_ABORT_COMMIT_BRIDGE_FAILED;
        }
        result.bridge_outcome =
            FK_OWNER_PIPELINE_ABORT_BRIDGE_ACTIVE_RECORDED;
        result.bridge_abort_packet_sequence = abort.packet_sequence;
        result.bridge_abort_receipt_ordinal = abort.receipt_ordinal;
        result.bridge_abort_expected_owner = abort.expected_owner;
        result.bridge_abort_route_kind = abort.route_kind;
        result.bridge_abort_reason = abort.abort_reason;
        result.bridge_abort_slot_was_bound = abort.slot_was_bound;
    }
    result.identity_prepared_verified = 1u;
    result.dispatch_data_reclaimed =
        state.counters.dispatch_reclaim_successes;
    result.dispatch_retire_controls_discarded =
        state.counters.dispatch_retire_controls_discarded;
    result.bridge_bound_loss_candidates = bridge_bound_candidates;
    result.bridge_bound_candidates_exact_verified =
        state.counters.bridge_bound_candidates_exact_verified;
    result.dispatch_admissions_stopped = 1u;
    result.dispatch_drained = 1u;
    result.all_owner_prepared_verified = 1u;
    result.outboxes_resolved = 1u;
    result.all_owner_rings_stopped = 1u;
    result.bridge_cleanup_done = 1u;
    result.bridge_clean_state_verified = 1u;
    result.auth_tag[0] = receipt_tag(state, result, 0u);
    result.auth_tag[1] = receipt_tag(state, result, 1u);
    state.receipt = result;
    state.committed.store(1u, std::memory_order_release);
    (void)increment(state, state.counters.commit_successes);
    return FK_OWNER_PIPELINE_ABORT_COMMITTED;
}

bool fk_owner_pipeline_abort_coordinator_get_receipt(
        const fk_owner_pipeline_abort_coordinator *coordinator,
        fk_owner_pipeline_abort_receipt_v1 *receipt) {
    if (receipt != nullptr)
        *receipt = {};
    if (coordinator == nullptr || receipt == nullptr)
        return false;
    const State &state = *implementation(coordinator);
    if (state.magic != kMagic ||
        state.committed.load(std::memory_order_acquire) == 0u)
        return false;
    *receipt = state.receipt;
    return true;
}

bool fk_owner_pipeline_abort_coordinator_validate_receipt(
        const fk_owner_pipeline_abort_coordinator *coordinator,
        const fk_owner_pipeline_abort_receipt_v1 *receipt) {
    if (coordinator == nullptr)
        return false;
    const State &state = *implementation(coordinator);
    if (state.magic != kMagic)
        return false;
    State &mutable_state = *const_cast<State *>(&state);
    saturating_atomic_increment(mutable_state.receipt_validation_attempts);
    const bool valid = validate_receipt_impl(state, receipt);
    if (valid) {
        saturating_atomic_increment(
            mutable_state.receipt_validation_successes);
    } else {
        saturating_atomic_increment(
            mutable_state.receipt_validation_failures);
    }
    return valid;
}

fk_owner_pipeline_abort_authorize_result
fk_owner_pipeline_abort_coordinator_authorize_finalize(
        fk_owner_pipeline_abort_coordinator *coordinator,
        const fk_owner_pipeline_abort_receipt_v1 *receipt,
        fk_owner_pipeline_abort_participant_kind participant_kind,
        uint16_t participant_id) {
    if (coordinator == nullptr)
        return FK_OWNER_PIPELINE_ABORT_AUTHORIZE_INVALID;
    State &state = *implementation(coordinator);
    if (state.magic != kMagic || !validate_receipt_impl(state, receipt))
        return FK_OWNER_PIPELINE_ABORT_AUTHORIZE_INVALID;
    if (participant_kind ==
            FK_OWNER_PIPELINE_ABORT_PARTICIPANT_IDENTITY_RX) {
        if (participant_id != FK_OWNER_ABORT_IDENTITY_RX_PARTICIPANT_ID)
            return FK_OWNER_PIPELINE_ABORT_AUTHORIZE_INVALID;
        uint64_t expected = 0u;
        if (state.identity_finalize_authorizations.compare_exchange_strong(
                expected,
                1u,
                std::memory_order_acq_rel,
                std::memory_order_acquire)) {
            return FK_OWNER_PIPELINE_ABORT_AUTHORIZED;
        }
        return expected == 1u
            ? FK_OWNER_PIPELINE_ABORT_ALREADY_AUTHORIZED
            : FK_OWNER_PIPELINE_ABORT_AUTHORIZE_INVALID;
    }
    if (participant_kind !=
            FK_OWNER_PIPELINE_ABORT_PARTICIPANT_FIXED_OWNER ||
        participant_id >= state.config.owner_count) {
        return FK_OWNER_PIPELINE_ABORT_AUTHORIZE_INVALID;
    }
    const uint64_t bit = UINT64_C(1) << participant_id;
    uint64_t observed =
        state.fixed_owner_finalize_mask.load(std::memory_order_acquire);
    for (;;) {
        if ((observed & bit) != 0u)
            return FK_OWNER_PIPELINE_ABORT_ALREADY_AUTHORIZED;
        if (state.fixed_owner_finalize_mask.compare_exchange_weak(
                observed,
                observed | bit,
                std::memory_order_acq_rel,
                std::memory_order_acquire)) {
            return FK_OWNER_PIPELINE_ABORT_AUTHORIZED;
        }
    }
}

bool fk_owner_pipeline_abort_coordinator_get_stats(
        const fk_owner_pipeline_abort_coordinator *coordinator,
        fk_owner_pipeline_abort_coordinator_stats *stats) {
    if (coordinator == nullptr || stats == nullptr)
        return false;
    const State &state = *implementation(coordinator);
    if (state.magic != kMagic)
        return false;
    *stats = state.counters;
    stats->prepared_owner_mask =
        state.prepared_owner_mask.load(std::memory_order_acquire);
    stats->fixed_owner_finalize_mask =
        state.fixed_owner_finalize_mask.load(std::memory_order_acquire);
    stats->receipt_validation_attempts =
        state.receipt_validation_attempts.load(std::memory_order_acquire);
    stats->receipt_validation_successes =
        state.receipt_validation_successes.load(std::memory_order_acquire);
    stats->receipt_validation_failures =
        state.receipt_validation_failures.load(std::memory_order_acquire);
    stats->identity_finalize_authorizations =
        state.identity_finalize_authorizations.load(
            std::memory_order_acquire);
    stats->identity_prepared =
        state.identity_prepared.load(std::memory_order_acquire);
    stats->committed = state.committed.load(std::memory_order_acquire);
    stats->terminal_failure =
        state.terminal_failure.load(std::memory_order_acquire);
    stats->pending_dispatch_envelope =
        state.pending_dispatch_envelope_present;
    stats->pending_dispatch_packet_handle =
        state.pending_dispatch_envelope_present != 0u &&
            state.pending_dispatch_envelope.kind == FK_OWNER_ENVELOPE_DATA
        ? state.pending_dispatch_envelope.payload.data.packet_handle : 0u;
    stats->service_memory_exact =
        state.reserved_bytes == stats->service_memory_bytes ? 1u : 0u;
    return true;
}

bool fk_owner_pipeline_abort_coordinator_destroy_checked(
        fk_owner_pipeline_abort_coordinator *coordinator) {
    if (coordinator == nullptr)
        return false;
    State &state = *implementation(coordinator);
    if (state.magic != kMagic ||
        state.committed.load(std::memory_order_acquire) == 0u ||
        state.terminal_failure.load(std::memory_order_acquire) != 0u ||
        state.fixed_owner_finalize_mask.load(std::memory_order_acquire) !=
            full_owner_mask(state.config.owner_count) ||
        state.identity_finalize_authorizations.load(
            std::memory_order_acquire) != 1u ||
        state.pending_dispatch_envelope_present != 0u ||
        state.counters.service_memory_bytes != state.reserved_bytes ||
        !validate_receipt_impl(state, &state.receipt)) {
        return false;
    }
    state.magic = 0u;
    state.~State();
    return true;
}

}  // extern "C"
