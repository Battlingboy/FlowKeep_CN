#include "fk_owner_runtime_adapter.h"

#include <cstring>
#include <initializer_list>
#include <limits>

namespace {

fk_owner_flow_handle owner_handle(fk_compact_flow_handle handle) {
    fk_owner_flow_handle result{};
    result.index = handle.index;
    result.generation = handle.generation;
    return result;
}

fk_compact_flow_handle compact_handle(fk_owner_flow_handle handle) {
    fk_compact_flow_handle result{};
    result.index = handle.index;
    result.generation = handle.generation;
    return result;
}

bool same_handle(
        fk_owner_flow_handle left,
        fk_owner_flow_handle right) {
    return left.index == right.index &&
        left.generation == right.generation;
}

bool checked_sum(
        std::initializer_list<uint64_t> values,
        uint64_t &sum) {
    sum = 0u;
    for (const uint64_t value : values) {
        if (value > std::numeric_limits<uint64_t>::max() - sum)
            return false;
        sum += value;
    }
    return true;
}

bool sum_equals(
        uint64_t expected,
        std::initializer_list<uint64_t> values) {
    uint64_t sum = 0u;
    return checked_sum(values, sum) && sum == expected;
}

bool sum_at_most(
        uint64_t limit,
        std::initializer_list<uint64_t> values) {
    uint64_t sum = 0u;
    return checked_sum(values, sum) && sum <= limit;
}

bool can_increment(uint64_t value) {
    return value != std::numeric_limits<uint64_t>::max();
}

bool ranges_overlap(
        const void *left,
        size_t left_size,
        const void *right,
        size_t right_size) {
    const uintptr_t left_begin = reinterpret_cast<uintptr_t>(left);
    const uintptr_t right_begin = reinterpret_cast<uintptr_t>(right);
    if (left_size > std::numeric_limits<uintptr_t>::max() - left_begin ||
        right_size > std::numeric_limits<uintptr_t>::max() - right_begin) {
        return true;
    }
    const uintptr_t left_end = left_begin + left_size;
    const uintptr_t right_end = right_begin + right_size;
    return left_begin < right_end && right_begin < left_end;
}

bool topology_receipts_match(
        const fk_quic_cid_map_topology_receipt &cid,
        const fk_owner_flow_bindings_topology_receipt &binding) {
    return cid.receipt_abi_version ==
            FK_QUIC_CID_MAP_TOPOLOGY_RECEIPT_ABI_VERSION &&
        binding.receipt_abi_version ==
            FK_OWNER_FLOW_BINDINGS_TOPOLOGY_RECEIPT_ABI_VERSION &&
        cid.receipt_abi_version == binding.receipt_abi_version &&
        cid.logical_id_abi_version == FK_QUIC_LOGICAL_ID_ABI_VERSION &&
        cid.logical_id_abi_version == binding.logical_id_abi_version &&
        cid.logical_id_bits == FK_QUIC_LOGICAL_ID_FULL_WIDTH_BITS &&
        cid.logical_id_bits == binding.logical_id_bits &&
        cid.logical_id_full_width == 1u &&
        cid.logical_id_full_width == binding.logical_id_full_width &&
        cid.logical_id_generation_bits ==
            FK_QUIC_LOGICAL_ID_GENERATION_BITS &&
        cid.logical_id_generation_bits ==
            binding.logical_id_generation_bits &&
        cid.logical_id_encoded_slot_bits ==
            FK_QUIC_LOGICAL_ID_ENCODED_SLOT_BITS &&
        cid.logical_id_encoded_slot_bits ==
            binding.logical_id_encoded_slot_bits &&
        cid.retire_ack_required == 1u &&
        cid.retire_ack_required == binding.retire_ack_required &&
        cid.fixed_owner_count == binding.fixed_owner_count &&
        cid.maximum_connection_slots ==
            binding.maximum_connection_slots &&
        cid.topology_config_hash != 0u &&
        cid.topology_config_hash == binding.topology_config_hash &&
        cid.reserved0 == 0u && cid.reserved1 == 0u &&
        cid.reserved2 == 0u && binding.reserved0 == 0u &&
        binding.reserved1 == 0u && binding.reserved2 == 0u;
}

bool packet_shape_valid(
        const fk_owner_runtime_adapter &adapter,
        const fk_owner_packet &packet,
        const fk_packet_view &view) {
    if (adapter.initialized == 0u || packet.packet_handle == 0u ||
        packet.owner_worker != adapter.fixed_owner ||
        packet.ingress_worker >= adapter.owner_count ||
        packet.packet_sequence == UINT64_MAX ||
        packet.physical_ingress_timestamp_ns == 0u ||
        packet.captured_length == 0u || packet.wire_length == 0u ||
        packet.wire_length < packet.captured_length ||
        packet.captured_length != view.captured_size ||
        packet.wire_length != view.wire_size ||
        view.code != FK_PARSE_OK ||
        (view.l4_protocol != 6u && view.l4_protocol != 17u)) {
        return false;
    }
    for (uint8_t byte : packet.reserved) {
        if (byte != 0u)
            return false;
    }
    return true;
}

/* Validate every value-only descriptor field before advancing the runtime
 * watermark. Byte resolution and native parsing intentionally happen only
 * after bounded timer maintenance; failures discovered from packet bytes are
 * therefore distinct from malformed queued descriptors. */
bool packet_descriptor_shape_valid(
        const fk_owner_runtime_adapter &adapter,
        const fk_owner_packet *packet) {
    if (packet == nullptr || adapter.initialized == 0u ||
        packet->packet_handle == 0u ||
        packet->owner_worker != adapter.fixed_owner ||
        packet->ingress_worker >= adapter.owner_count ||
        packet->packet_sequence == UINT64_MAX ||
        packet->physical_ingress_timestamp_ns == 0u ||
        packet->captured_length == 0u || packet->wire_length == 0u ||
        packet->wire_length < packet->captured_length)
        return false;
    for (const uint8_t byte : packet->reserved) {
        if (byte != 0u)
            return false;
    }
    if (packet->identity_kind == FK_OWNER_IDENTITY_FLOW_KEY) {
        return packet->logical_connection_id == 0u &&
            packet->feature_direction == 0u &&
            packet->feature_direction_known == 0u &&
            fk_quic_route_receipt_is_zero(&packet->route_receipt);
    }
    return packet->identity_kind == FK_OWNER_IDENTITY_QUIC_LOGICAL &&
        packet->logical_connection_id != 0u &&
        packet->feature_direction <= 1u &&
        packet->feature_direction_known <= 1u &&
        (packet->feature_direction_known != 0u ||
         packet->feature_direction == 0u) &&
        fk_quic_route_receipt_shape_valid(&packet->route_receipt);
}

bool packet_bytes_source_shape_valid(
        const fk_owner_packet_bytes_source &source) {
    return source.abi_version ==
            FK_OWNER_PACKET_BYTES_SOURCE_ABI_VERSION &&
        source.exact_handle_binding == 1u &&
        source.immutable_while_owned == 1u &&
        source.contiguous_frame == 1u && source.reserved0 == 0u &&
        source.resolve != nullptr;
}

bool resolve_and_parse_packet(
        fk_owner_runtime_adapter &adapter,
        const fk_owner_packet &packet,
        fk_packet_view &view) {
    adapter.stats.packet_bytes_resolution_calls++;
    const uint8_t *frame = nullptr;
    size_t captured_length = 0u;
    uint32_t wire_length = 0u;
    if (!adapter.packet_bytes_source.resolve(
            adapter.packet_bytes_source.context,
            packet.packet_handle,
            &frame,
            &captured_length,
            &wire_length) || frame == nullptr || captured_length == 0u ||
        captured_length != packet.captured_length ||
        wire_length != packet.wire_length ||
        captured_length > UINT32_MAX ||
        fk_native_parse_ethernet(
            frame, captured_length, wire_length, &view) != FK_PARSE_OK) {
        adapter.stats.packet_bytes_resolution_rejections++;
        view = {};
        return false;
    }
    adapter.stats.packet_bytes_resolution_successes++;
    return true;
}

bool ordinary_route_proof(
        fk_owner_runtime_adapter &adapter,
        const fk_owner_packet &packet,
        const fk_packet_view &view,
        fk_flow_key &key) {
    adapter.stats.owner_proof_validations++;
    if (packet.identity_kind != FK_OWNER_IDENTITY_FLOW_KEY ||
        packet.logical_connection_id != 0u ||
        packet.feature_direction != 0u ||
        packet.feature_direction_known != 0u ||
        !fk_quic_route_receipt_is_zero(&packet.route_receipt)) {
        adapter.stats.owner_proof_rejections++;
        adapter.stats.ordinary_route_proof_rejections++;
        return false;
    }
    uint8_t canonical_direction = 0u;
    if (fk_native_flow_key(&view, &key, &canonical_direction) !=
            FK_PARSE_OK || canonical_direction > 1u) {
        adapter.stats.owner_proof_rejections++;
        adapter.stats.ordinary_route_proof_rejections++;
        return false;
    }
    fk_owner_identity identity{};
    uint16_t selected_owner = UINT16_MAX;
    bool formal_owner = false;
    if (!fk_owner_identity_from_flow_key(&key, &identity) ||
        !fk_owner_dispatch_select_owner(
            adapter.dispatch, &identity, &selected_owner, &formal_owner) ||
        !formal_owner || selected_owner != adapter.fixed_owner) {
        adapter.stats.owner_proof_rejections++;
        adapter.stats.ordinary_route_proof_rejections++;
        return false;
    }
    return true;
}

bool quic_route_proof(
        fk_owner_runtime_adapter &adapter,
        const fk_owner_packet &packet,
        const fk_packet_view &view) {
    adapter.stats.owner_proof_validations++;
    if (packet.identity_kind != FK_OWNER_IDENTITY_QUIC_LOGICAL ||
        packet.logical_connection_id == 0u ||
        packet.feature_direction_known != 1u ||
        packet.feature_direction > 1u || view.l4_protocol != 17u ||
        !fk_quic_route_receipt_shape_valid(&packet.route_receipt)) {
        adapter.stats.owner_proof_rejections++;
        adapter.stats.quic_shape_rejections++;
        return false;
    }
    fk_quic_initial_auth_result authenticated{};
    const fk_quic_initial_auth_result *authenticated_ptr = nullptr;
    if (packet.route_receipt.evidence_kind ==
            FK_QUIC_ROUTE_EVIDENCE_AUTHENTICATED_INITIAL_DCID) {
        if (view.payload == nullptr ||
            fk_quic_initial_authenticate_client(
                view.payload, view.payload_size, &authenticated, nullptr) !=
                FK_QUIC_INITIAL_AUTHENTICATED) {
            adapter.stats.owner_proof_rejections++;
            adapter.stats.quic_route_receipt_rejections++;
            adapter.stats.quic_route_receipt_validations++;
            return false;
        }
        authenticated_ptr = &authenticated;
    }
    adapter.stats.quic_route_receipt_validations++;
    if (fk_quic_route_receipt_verify_and_consume(
            adapter.route_receipts, &packet, &view,
            authenticated_ptr) != FK_QUIC_ROUTE_RECEIPT_ACCEPTED) {
        adapter.stats.owner_proof_rejections++;
        adapter.stats.quic_route_receipt_rejections++;
        return false;
    }
    adapter.stats.quic_route_receipt_verified++;
    return true;
}

fk_owner_runtime_adapter_result runtime_result(
        fk_owner_runtime_adapter &adapter,
        fk_compact_runtime_result result,
        bool logical) {
    if (result == FK_COMPACT_RUNTIME_OBSERVED) {
        if (logical) {
            adapter.stats.logical_quic_observed++;
            return FK_OWNER_RUNTIME_ADAPTER_QUIC_OBSERVED;
        }
        adapter.stats.ordinary_observed++;
        return FK_OWNER_RUNTIME_ADAPTER_ORDINARY_OBSERVED;
    }
    if (result == FK_COMPACT_RUNTIME_IGNORED) {
        adapter.stats.runtime_ignored++;
        return FK_OWNER_RUNTIME_ADAPTER_RUNTIME_IGNORED;
    }
    if (result == FK_COMPACT_RUNTIME_ADMISSION_REJECTED) {
        /* A monitor that cannot admit a flow has lost coverage at this exact
         * packet.  Latch terminal state immediately; continuing would turn a
         * measured capacity failure into silent fail-open traffic. */
        adapter.terminal_failure = 1u;
        adapter.stats.admission_rejected++;
        return FK_OWNER_RUNTIME_ADAPTER_ADMISSION_REJECTED;
    }
    adapter.terminal_failure = 1u;
    adapter.stats.terminal_failures++;
    adapter.stats.runtime_failures++;
    return FK_OWNER_RUNTIME_ADAPTER_RUNTIME_FAILED;
}

bool output_empty(const fk_owner_runtime_adapter &adapter) {
    return adapter.output.state == FK_OWNER_RUNTIME_OUTPUT_EMPTY;
}

bool receipt_is_sealed(const fk_owner_runtime_adapter &adapter) {
    return __atomic_load_n(
        &adapter.receipt_sealed, __ATOMIC_ACQUIRE) != 0u;
}

class RuntimeOwnerScope {
public:
    explicit RuntimeOwnerScope(fk_owner_runtime_adapter &adapter)
        : adapter_(adapter), active_(
              fk_compact_runtime_owner_adapter_scope_begin(
                  adapter.runtime,
                  reinterpret_cast<uintptr_t>(&adapter),
                  adapter.fixed_owner)) {
        if (!active_)
            adapter_.stats.runtime_scope_begin_rejections++;
    }

    RuntimeOwnerScope(const RuntimeOwnerScope &) = delete;
    RuntimeOwnerScope &operator=(const RuntimeOwnerScope &) = delete;

    ~RuntimeOwnerScope() { (void)close(); }

    bool close() {
        if (!active_)
            return true;
        active_ = false;
        if (!fk_compact_runtime_owner_adapter_scope_end(
                adapter_.runtime,
                reinterpret_cast<uintptr_t>(&adapter_),
                adapter_.fixed_owner)) {
            adapter_.stats.runtime_scope_end_failures++;
            adapter_.terminal_failure = 1u;
            return false;
        }
        return true;
    }

    bool active() const { return active_; }

private:
    fk_owner_runtime_adapter &adapter_;
    bool active_;
};

enum class SemanticPrepareResult {
    Complete,
    DrainRequired,
    ClaimRejected,
    Failed,
};

SemanticPrepareResult prepare_semantic_time(
        fk_owner_runtime_adapter &adapter,
        uint64_t timestamp_ns,
        bool data_path) {
    uint64_t &calls = data_path
        ? adapter.stats.semantic_data_step_calls
        : adapter.stats.semantic_retire_step_calls;
    uint64_t &completions = data_path
        ? adapter.stats.semantic_data_step_completions
        : adapter.stats.semantic_retire_step_completions;
    uint64_t &drains = data_path
        ? adapter.stats.semantic_data_drain_required
        : adapter.stats.semantic_retire_drain_required;
    uint64_t &failures = data_path
        ? adapter.stats.semantic_data_step_failures
        : adapter.stats.semantic_retire_step_failures;
    calls++;
    RuntimeOwnerScope scope(adapter);
    if (!scope.active()) {
        failures++;
        if (data_path)
            adapter.stats.runtime_scope_data_rejections++;
        else
            adapter.stats.runtime_scope_retire_rejections++;
        return SemanticPrepareResult::ClaimRejected;
    }
    bool complete = false;
    const bool advanced = fk_compact_runtime_prepare_semantic_time_step(
        adapter.runtime, timestamp_ns, &complete);
    if (!scope.close() || !advanced) {
        failures++;
        return SemanticPrepareResult::Failed;
    }
    if (!complete) {
        drains++;
        return SemanticPrepareResult::DrainRequired;
    }
    completions++;
    return SemanticPrepareResult::Complete;
}

uint64_t post_seal_rejections(
        const fk_owner_runtime_adapter &adapter) {
    return __atomic_load_n(
        &adapter.post_seal_rejections, __ATOMIC_ACQUIRE);
}

void reject_after_seal(fk_owner_runtime_adapter &adapter) {
    (void)__atomic_fetch_add(
        &adapter.post_seal_rejections, UINT64_C(1), __ATOMIC_RELAXED);
}

void clear_output(fk_owner_runtime_adapter &adapter) {
    adapter.output = {};
}

bool stage_runtime_outputs(
        fk_owner_runtime_adapter &adapter,
        const fk_owner_packet &packet,
        const fk_compact_runtime_flow_identity_v2 *identity) {
    if (!output_empty(adapter))
        return false;
    fk_owner_runtime_output_batch_v2 &batch = adapter.output;
    batch = {};
    batch.packet_sequence = packet.packet_sequence;
    batch.physical_ingress_timestamp_ns =
        packet.physical_ingress_timestamp_ns;
    batch.semantic_timestamp_ns = packet.semantic_timestamp_ns;
    batch.logical_connection_id = packet.logical_connection_id;
    batch.abi_version = FK_OWNER_RUNTIME_OUTPUT_ABI_VERSION;
    if (identity != nullptr && identity->presentation.valid == 1u)
        batch.handle = identity->presentation.handle;

    batch.has_flow_open =
        fk_compact_runtime_take_flow_open_observation_v2(
            adapter.runtime, &batch.flow_open) ? 1u : 0u;
    batch.has_detection =
        fk_compact_runtime_take_detection_request_v2(
            adapter.runtime, &batch.detection) ? 1u : 0u;
    batch.has_action = fk_compact_runtime_take_action_record(
        adapter.runtime, &batch.action) ? 1u : 0u;
    adapter.stats.flow_open_outputs_taken += batch.has_flow_open;
    adapter.stats.detection_outputs_taken += batch.has_detection;
    adapter.stats.action_outputs_taken += batch.has_action;
    if (batch.has_flow_open == 0u && batch.has_detection == 0u &&
        batch.has_action == 0u) {
        batch = {};
        return true;
    }
    batch.transaction_epoch = adapter.next_output_transaction_epoch++;
    batch.state = FK_OWNER_RUNTIME_OUTPUT_STAGED;
    adapter.stats.output_transactions_staged++;

    /* Since the previous committed outbox must have been ACKed before this
     * packet, every value just taken belongs to this exact runtime call. */
    if (identity == nullptr || identity->presentation.valid != 1u)
        return true;  /* Failure path will abort the staged values. */
    const fk_compact_flow_handle expected = identity->presentation.handle;
    if (batch.has_flow_open != 0u &&
        (batch.flow_open.logical_connection_id !=
             packet.logical_connection_id ||
         (batch.flow_open.presentation.control_kind !=
              FK_COMPACT_FLOW_CONTROL_OPEN &&
          batch.flow_open.presentation.control_kind !=
              FK_COMPACT_FLOW_CONTROL_CONTINUE) ||
         batch.flow_open.presentation.reserved[0] != 0u ||
         batch.flow_open.presentation.reserved[1] != 0u ||
         batch.flow_open.presentation.reserved[2] != 0u ||
         batch.flow_open.presentation.flow_index != expected.index ||
         batch.flow_open.presentation.flow_generation !=
             expected.generation ||
         batch.flow_open.presentation.observation_timestamp_ns !=
             packet.semantic_timestamp_ns ||
         !fk_flow_key_equal(
             &batch.flow_open.presentation.key,
             &identity->presentation.presentation_key))) {
        return false;
    }
    if (batch.has_detection != 0u &&
        (batch.detection.logical_connection_id !=
             packet.logical_connection_id ||
         batch.detection.presentation.flow_index != expected.index ||
         batch.detection.presentation.flow_generation !=
             expected.generation ||
         batch.detection.presentation.observation_timestamp_ns !=
             packet.semantic_timestamp_ns ||
         !fk_flow_key_equal(
             &batch.detection.presentation.key,
             &identity->presentation.presentation_key))) {
        return false;
    }
    if (batch.has_action != 0u &&
        (batch.action.observation_timestamp_ns !=
             packet.semantic_timestamp_ns ||
         !fk_flow_key_equal(
             &batch.action.key,
             &identity->presentation.presentation_key))) {
        return false;
    }
    return true;
}

bool abort_staged_outputs(fk_owner_runtime_adapter &adapter) {
    adapter.stats.rollback_output_discard_calls++;
    if (output_empty(adapter))
        return true;
    if (adapter.output.state != FK_OWNER_RUNTIME_OUTPUT_STAGED) {
        adapter.stats.rollback_output_discard_failures++;
        return false;
    }
    adapter.stats.flow_open_outputs_aborted +=
        adapter.output.has_flow_open;
    adapter.stats.detection_outputs_aborted +=
        adapter.output.has_detection;
    adapter.stats.action_outputs_aborted += adapter.output.has_action;
    adapter.stats.rollback_flow_open_discards +=
        adapter.output.has_flow_open;
    adapter.stats.rollback_detection_discards +=
        adapter.output.has_detection;
    adapter.stats.rollback_action_discards += adapter.output.has_action;
    adapter.stats.output_transactions_aborted++;
    clear_output(adapter);
    return true;
}

bool commit_staged_outputs(fk_owner_runtime_adapter &adapter) {
    if (output_empty(adapter))
        return true;
    if (adapter.output.state != FK_OWNER_RUNTIME_OUTPUT_STAGED)
        return false;
    adapter.output.state = FK_OWNER_RUNTIME_OUTPUT_IDENTITY_COMMITTED;
    adapter.stats.output_transactions_identity_committed++;
    return true;
}

bool rollback_new_generation(
        fk_owner_runtime_adapter &adapter,
        uint64_t logical_connection_id,
        fk_compact_flow_handle handle,
        uint64_t timestamp_ns,
        const fk_owner_flow_binding_creation_receipt *creation_receipt) {
    adapter.stats.rollback_attempts++;
    bool ok = abort_staged_outputs(adapter);
    if (creation_receipt != nullptr) {
        if (fk_owner_flow_bindings_abort_unpublished_creation_v2(
                adapter.bindings, adapter.fixed_owner,
                logical_connection_id, owner_handle(handle),
                creation_receipt)) {
            adapter.stats.rollback_binding_aborts++;
        } else {
            ok = false;
        }
    }
    if (handle.generation != 0u &&
        fk_compact_runtime_release_bound_flow(
            adapter.runtime, handle, timestamp_ns) ==
            FK_COMPACT_RUNTIME_FLOW_RELEASE_RELEASED) {
        adapter.stats.rollback_runtime_releases++;
    } else {
        ok = false;
    }
    if (!ok)
        adapter.stats.rollback_failures++;
    return ok;
}

bool cleanup_failed_runtime_transaction(
        fk_owner_runtime_adapter &adapter,
        const fk_owner_packet &packet,
        const fk_compact_runtime_flow_identity_v2 &identity) {
    if (!stage_runtime_outputs(adapter, packet, nullptr))
        return false;
    if (identity.presentation.valid != 0u ||
        identity.presentation.created > 1u ||
        identity.presentation.handle_available > 1u) {
        (void)abort_staged_outputs(adapter);
        return false;
    }
    if (identity.presentation.created == 0u)
        return abort_staged_outputs(adapter);
    if (identity.presentation.handle_available != 1u ||
        identity.presentation.handle.generation == 0u ||
        identity.logical_connection_id !=
            packet.logical_connection_id) {
        (void)abort_staged_outputs(adapter);
        return false;
    }
    return rollback_new_generation(
        adapter, packet.logical_connection_id,
        identity.presentation.handle,
        packet.semantic_timestamp_ns, nullptr);
}

bool counters_conserved(const fk_owner_runtime_adapter &adapter) {
    const fk_owner_runtime_adapter_stats &stats = adapter.stats;
    const bool output_committed = adapter.output.state ==
        FK_OWNER_RUNTIME_OUTPUT_IDENTITY_COMMITTED;
    const uint64_t outstanding_transactions = output_committed ? 1u : 0u;
    const uint64_t outstanding_flow_open = output_committed
        ? adapter.output.has_flow_open : 0u;
    const uint64_t outstanding_detection = output_committed
        ? adapter.output.has_detection : 0u;
    const uint64_t outstanding_action = output_committed
        ? adapter.output.has_action : 0u;
    if (adapter.output.state >
            FK_OWNER_RUNTIME_OUTPUT_IDENTITY_COMMITTED ||
        !sum_at_most(stats.output_transactions_identity_committed,
            {stats.output_transactions_acked,
             stats.output_transactions_committed_discarded}) ||
        stats.flow_open_outputs_committed_discarded >
            stats.flow_open_outputs_aborted ||
        stats.detection_outputs_committed_discarded >
            stats.detection_outputs_aborted ||
        stats.action_outputs_committed_discarded >
            stats.action_outputs_aborted ||
        !sum_at_most(stats.flow_open_outputs_taken,
            {stats.flow_open_outputs_acked,
             stats.flow_open_outputs_aborted}) ||
        !sum_at_most(stats.detection_outputs_taken,
            {stats.detection_outputs_acked,
             stats.detection_outputs_aborted}) ||
        !sum_at_most(stats.action_outputs_taken,
            {stats.action_outputs_acked,
             stats.action_outputs_aborted})) {
        return false;
    }
    uint64_t total_calls = 0u;
    uint64_t prevalidated_routes = 0u;
    return sum_equals(stats.data_calls,
            {stats.ordinary_calls, stats.logical_quic_calls,
             stats.invalid_calls, stats.terminal_stop_data_calls,
             stats.output_backpressure_data_calls}) &&
        sum_equals(stats.semantic_data_step_calls,
            {stats.semantic_data_step_completions,
             stats.semantic_data_drain_required,
             stats.semantic_data_step_failures}) &&
        sum_equals(stats.semantic_retire_step_calls,
            {stats.semantic_retire_step_completions,
             stats.semantic_retire_drain_required,
             stats.semantic_retire_step_failures}) &&
        sum_equals(stats.packet_bytes_resolution_calls,
            {stats.packet_bytes_resolution_successes,
             stats.packet_bytes_resolution_rejections}) &&
        checked_sum({stats.data_calls, stats.retire_calls}, total_calls) &&
        checked_sum(
            {stats.quic_route_prevalidation_active,
             stats.quic_route_prevalidation_retired_pending},
            prevalidated_routes) &&
        sum_equals(stats.runtime_scope_begin_rejections,
            {stats.runtime_scope_data_rejections,
             stats.runtime_scope_retire_rejections}) &&
        sum_equals(total_calls,
            {stats.ordinary_observed, stats.logical_quic_observed,
             stats.retire_acked, stats.runtime_ignored,
             stats.admission_rejected,
             stats.retirement_retry_required,
             stats.terminal_failures,
             stats.runtime_scope_begin_rejections,
             stats.output_backpressure_data_calls,
             stats.output_backpressure_retire_calls}) &&
        sum_equals(stats.owner_proof_validations,
            {stats.ordinary_calls, stats.logical_quic_calls}) &&
        sum_equals(stats.owner_proof_rejections,
            {stats.ordinary_route_proof_rejections,
             stats.quic_shape_rejections,
             stats.quic_route_receipt_rejections,
             stats.quic_route_prevalidation_rejections}) &&
        sum_equals(stats.logical_quic_calls,
            {stats.quic_route_receipt_validations,
             stats.quic_shape_rejections}) &&
        sum_equals(stats.quic_route_receipt_validations,
            {stats.quic_route_receipt_verified,
             stats.quic_route_receipt_rejections}) &&
        stats.quic_route_prevalidation_calls ==
            stats.quic_route_receipt_verified &&
        sum_equals(stats.quic_route_prevalidation_calls,
            {stats.quic_route_prevalidation_active,
             stats.quic_route_prevalidation_retired_pending,
             stats.quic_route_prevalidation_rejections}) &&
        sum_equals(prevalidated_routes,
            {stats.binding_lookup_found,
             stats.binding_lookup_not_found,
             stats.binding_lookup_failures}) &&
        sum_equals(stats.initial_distinct_admissions,
            {stats.bindings_created, stats.initial_bind_failures}) &&
        sum_equals(stats.binding_failures,
            {stats.initial_bind_failures,
             stats.binding_creation_commit_failures,
             stats.binding_lookup_failures,
             stats.direction_resolution_failures}) &&
        sum_equals(stats.bindings_created,
            {stats.cid_binding_marks,
             stats.cid_binding_mark_failures}) &&
        stats.bindings_created == stats.binding_creation_receipts &&
        sum_equals(stats.binding_creation_receipts,
            {stats.binding_creation_commits,
             stats.rollback_binding_aborts}) &&
        sum_equals(stats.retire_calls,
            {stats.retire_acked, stats.retirement_peek_failures,
             stats.retirement_control_mismatches,
             stats.retirement_context_failures,
             stats.retirement_ack_failures,
             stats.retirement_retry_required,
             stats.terminal_stop_retire_calls,
             stats.output_backpressure_retire_calls,
             stats.runtime_scope_retire_rejections}) &&
        sum_equals(stats.output_transactions_staged,
            {stats.output_transactions_identity_committed,
             stats.output_transactions_aborted}) &&
        sum_equals(stats.output_transactions_identity_committed,
            {stats.output_transactions_acked,
             stats.output_transactions_committed_discarded,
             outstanding_transactions}) &&
        sum_equals(stats.output_committed_discard_calls,
            {stats.output_committed_discard_empty,
             stats.output_committed_discard_successes}) &&
        stats.output_transactions_committed_discarded ==
            stats.output_committed_discard_successes &&
        stats.output_transactions_acked == stats.output_ring_commits &&
        sum_equals(stats.output_publish_calls,
            {stats.output_ring_commits, stats.output_ring_full,
             stats.output_ring_stopped, stats.output_ring_failures,
             stats.output_ring_commit_ack_failures}) &&
        sum_equals(stats.flow_open_outputs_taken,
            {stats.flow_open_outputs_acked,
             stats.flow_open_outputs_aborted,
             outstanding_flow_open}) &&
        sum_equals(stats.detection_outputs_taken,
            {stats.detection_outputs_acked,
             stats.detection_outputs_aborted,
             outstanding_detection}) &&
        sum_equals(stats.action_outputs_taken,
            {stats.action_outputs_acked,
             stats.action_outputs_aborted,
             outstanding_action});
}

bool owner_thread_receipt(
        const fk_owner_runtime_adapter &adapter,
        uint64_t &rejections) {
    fk_owner_flow_bindings_owner_stats owner{};
    if (!fk_owner_flow_bindings_get_owner_stats(
            adapter.bindings, adapter.fixed_owner, &owner) ||
        owner.counters.owner_thread_violations <
            adapter.owner_thread_violations_baseline) {
        return false;
    }
    rejections = owner.counters.owner_thread_violations -
        adapter.owner_thread_violations_baseline;
    return true;
}

bool runtime_claim_receipt(const fk_owner_runtime_adapter &adapter) {
    fk_compact_runtime_stats runtime{};
    return fk_compact_runtime_get_stats(adapter.runtime, &runtime) &&
        runtime.owner_adapter_claimed == 1u &&
        runtime.owner_adapter_fixed_owner == adapter.fixed_owner &&
        sum_equals(runtime.owner_adapter_claim_attempts,
            {runtime.owner_adapter_claim_successes,
             runtime.owner_adapter_claim_rejections}) &&
        runtime.owner_adapter_claim_successes == 1u &&
        runtime.owner_adapter_claim_rejections == 0u &&
        sum_equals(runtime.owner_adapter_validation_calls,
            {runtime.owner_adapter_validation_successes,
             runtime.owner_adapter_validation_rejections}) &&
        runtime.owner_adapter_validation_rejections == 0u &&
        fk_compact_runtime_owner_adapter_formal_ready(
            adapter.runtime,
            reinterpret_cast<uintptr_t>(&adapter),
            adapter.fixed_owner);
}

bool route_receipt_state_clean(
        const fk_owner_runtime_adapter &adapter) {
    fk_quic_route_receipt_stats receipt{};
    return fk_quic_route_receipt_get_stats(
            adapter.route_receipts, &receipt) &&
        receipt.owner_count != 0u &&
        adapter.fixed_owner < receipt.owner_count &&
        receipt.keys_precommitted == 1u &&
        receipt.issue_attempts == receipt.issued &&
        receipt.verify_attempts == receipt.verified &&
        receipt.issued == receipt.verified &&
        receipt.issue_rejections == 0u &&
        receipt.invalid_rejections == 0u &&
        receipt.tag_mismatch_rejections == 0u &&
        receipt.replay_or_reorder_rejections == 0u &&
        receipt.internal_integrity_rejections == 0u;
}

bool output_ring_commit_receipt(
        const fk_owner_runtime_adapter &adapter) {
    fk_owner_output_batch_ring_stats ring{};
    return fk_owner_output_batch_ring_get_stats(
            adapter.output_ring, &ring) &&
        ring.abi_version == FK_OWNER_OUTPUT_BATCH_RING_ABI_VERSION &&
        ring.fixed_owner == adapter.fixed_owner &&
        ring.accepted_batches == adapter.stats.output_ring_commits &&
        ring.commit_acks == adapter.stats.output_ring_commits &&
        ring.pending_commit_ordinal == 0u &&
        ring.commit_ack_no_pending_rejections == 0u &&
        ring.commit_receipt_rejections == 0u &&
        ring.producer_thread_rejections == 0u &&
        ring.internal_integrity_failures == 0u &&
        ring.destroy_rejected_live_ownership == 0u &&
        ring.ownership_conserved && ring.commit_receipts_conserved &&
        ring.service_memory_exact;
}

bool formal_ready_impl(const fk_owner_runtime_adapter &adapter) {
    const fk_owner_runtime_adapter_stats &stats = adapter.stats;
    uint64_t owner_thread_rejections = 0u;
    return adapter.initialized != 0u && adapter.terminal_failure == 0u &&
        owner_thread_receipt(adapter, owner_thread_rejections) &&
        owner_thread_rejections == 0u && counters_conserved(adapter) &&
        runtime_claim_receipt(adapter) &&
        route_receipt_state_clean(adapter) &&
        output_ring_commit_receipt(adapter) &&
        output_empty(adapter) && stats.invalid_calls == 0u &&
        packet_bytes_source_shape_valid(adapter.packet_bytes_source) &&
        stats.packet_bytes_resolution_rejections == 0u &&
        stats.owner_proof_rejections == 0u &&
        stats.quic_route_receipt_rejections == 0u &&
        stats.runtime_ignored == 0u && stats.admission_rejected == 0u &&
        stats.runtime_failures == 0u && stats.binding_failures == 0u &&
        stats.binding_creation_commit_failures == 0u &&
        stats.cid_binding_mark_failures == 0u &&
        stats.rebind_failures == 0u && stats.rollback_attempts == 0u &&
        stats.rollback_failures == 0u &&
        stats.output_backpressure_data_calls == 0u &&
        stats.output_backpressure_retire_calls == 0u &&
        stats.semantic_data_step_failures == 0u &&
        stats.semantic_retire_step_failures == 0u &&
        stats.semantic_data_step_completions == stats.data_calls &&
        stats.semantic_retire_step_completions == stats.retire_calls &&
        stats.runtime_scope_begin_rejections == 0u &&
        stats.runtime_scope_end_failures == 0u &&
        stats.output_ring_stopped == 0u &&
        stats.output_ring_failures == 0u &&
        stats.output_ring_commit_ack_failures == 0u &&
        stats.output_transactions_aborted == 0u &&
        stats.output_transactions_committed_discarded == 0u &&
        stats.output_committed_discard_calls == 0u &&
        adapter.nonformal_abort_used == 0u &&
        stats.retirement_peek_failures == 0u &&
        stats.retirement_control_mismatches == 0u &&
        stats.retirement_context_failures == 0u &&
        stats.retirement_ack_failures == 0u &&
        stats.retirement_retry_required == 0u &&
        fk_quic_owner_cleanup_accounting_conserved(&adapter.cleanup) &&
        fk_quic_owner_cleanup_formal_replay_ready(&adapter.cleanup);
}

fk_owner_runtime_adapter_result fail(
        fk_owner_runtime_adapter &adapter,
        fk_owner_runtime_adapter_result result) {
    adapter.terminal_failure = 1u;
    adapter.stats.terminal_failures++;
    return result;
}

}  // namespace

bool fk_owner_runtime_adapter_initialize(
        fk_owner_runtime_adapter *adapter,
        fk_compact_runtime *runtime,
        fk_owner_dispatch *dispatch,
        fk_owner_flow_bindings *bindings,
        fk_quic_cid_map *cid_map,
        fk_quic_route_receipt_state *route_receipts,
        fk_owner_output_batch_ring *output_ring,
        const fk_owner_packet_bytes_source *packet_bytes_source,
        uint16_t fixed_owner) {
    if (adapter == nullptr || adapter->initialized != 0u)
        return false;
    if (runtime == nullptr || dispatch == nullptr || bindings == nullptr ||
        cid_map == nullptr || route_receipts == nullptr ||
        output_ring == nullptr || packet_bytes_source == nullptr ||
        !packet_bytes_source_shape_valid(*packet_bytes_source))
        return false;
    fk_owner_runtime_adapter candidate{};
    fk_owner_dispatch_stats dispatch_stats{};
    fk_owner_flow_bindings_stats binding_stats{};
    fk_compact_runtime_stats runtime_stats{};
    fk_quic_route_receipt_stats receipt_stats{};
    fk_owner_output_batch_ring_stats output_ring_stats{};
    fk_quic_cid_map_topology_receipt cid_topology{};
    fk_owner_flow_bindings_topology_receipt binding_topology{};
    uint32_t active_connections = 0u;
    if (!fk_owner_dispatch_get_stats(dispatch, &dispatch_stats) ||
        !fk_owner_flow_bindings_get_stats(bindings, &binding_stats) ||
        !fk_compact_runtime_get_stats(runtime, &runtime_stats) ||
        !fk_quic_route_receipt_get_stats(
            route_receipts, &receipt_stats) ||
        !fk_owner_output_batch_ring_get_stats(
            output_ring, &output_ring_stats) ||
        !fk_quic_cid_map_get_topology_receipt(
            cid_map, &cid_topology) ||
        !fk_owner_flow_bindings_get_topology_receipt(
            bindings, &binding_topology) ||
        !topology_receipts_match(cid_topology, binding_topology) ||
        fixed_owner >= dispatch_stats.worker_count ||
        fixed_owner >= binding_stats.owner_count ||
        dispatch_stats.worker_count != binding_stats.owner_count ||
        dispatch_stats.worker_count != cid_topology.fixed_owner_count ||
        fixed_owner >= cid_topology.fixed_owner_count ||
        receipt_stats.owner_count != dispatch_stats.worker_count ||
        receipt_stats.keys_precommitted != 1u ||
        output_ring_stats.abi_version !=
            FK_OWNER_OUTPUT_BATCH_RING_ABI_VERSION ||
        output_ring_stats.fixed_owner != fixed_owner ||
        output_ring_stats.lifecycle !=
            FK_OWNER_OUTPUT_BATCH_RING_ACCEPTING ||
        output_ring_stats.depth != 0u ||
        output_ring_stats.accepted_batches != 0u ||
        output_ring_stats.pending_commit_ordinal != 0u ||
        runtime_stats.frames != 0u ||
        runtime_stats.flow_open_observations_ready != 0u ||
        runtime_stats.detection_windows_ready != 0u ||
        runtime_stats.action_records_ready != 0u ||
        runtime_stats.identity_api_mode != FK_COMPACT_RUNTIME_API_MODE_UNSET ||
        !fk_quic_cid_map_get_fixed_owner_active_connections(
            cid_map, fixed_owner, &active_connections) ||
        !fk_owner_flow_bindings_claim_owner(bindings, fixed_owner)) {
        return false;
    }
    (void)active_connections;
    fk_owner_flow_bindings_owner_stats owner_stats{};
    if (!fk_owner_flow_bindings_get_owner_stats(
            bindings, fixed_owner, &owner_stats))
        return false;
    candidate.runtime = runtime;
    candidate.dispatch = dispatch;
    candidate.bindings = bindings;
    candidate.cid_map = cid_map;
    candidate.route_receipts = route_receipts;
    candidate.output_ring = output_ring;
    candidate.packet_bytes_source = *packet_bytes_source;
    candidate.fixed_owner = fixed_owner;
    candidate.owner_count = dispatch_stats.worker_count;
    candidate.next_output_transaction_epoch = 1u;
    candidate.owner_thread_violations_baseline =
        owner_stats.counters.owner_thread_violations;
    if (!fk_quic_owner_cleanup_adapter_initialize(
            &candidate.cleanup, bindings, fixed_owner,
            fk_quic_owner_cleanup_compact_runtime_release, runtime)) {
        return false;
    }
    if (!fk_compact_runtime_claim_owner_adapter(
            runtime, reinterpret_cast<uintptr_t>(adapter), fixed_owner)) {
        return false;
    }
    candidate.initialized = 1u;
    candidate.stats.abi_version = FK_OWNER_RUNTIME_ADAPTER_ABI_VERSION;
    candidate.stats.fixed_owner = fixed_owner;
    candidate.stats.initialized = 1u;
    *adapter = candidate;
    return true;
}

fk_owner_runtime_adapter_result fk_owner_runtime_adapter_process_data(
        fk_owner_runtime_adapter *adapter,
        const fk_owner_packet *packet) {
    if (adapter == nullptr)
        return FK_OWNER_RUNTIME_ADAPTER_INVALID;
    if (adapter->initialized == 0u ||
        !fk_owner_flow_bindings_validate_owner_thread_and_account(
            adapter->bindings, adapter->fixed_owner)) {
        return FK_OWNER_RUNTIME_ADAPTER_OWNER_THREAD_REJECTED;
    }
    if (!fk_compact_runtime_validate_owner_adapter_and_account(
            adapter->runtime, reinterpret_cast<uintptr_t>(adapter),
            adapter->fixed_owner)) {
        return FK_OWNER_RUNTIME_ADAPTER_RUNTIME_CLAIM_REJECTED;
    }
    if (receipt_is_sealed(*adapter)) {
        reject_after_seal(*adapter);
        return FK_OWNER_RUNTIME_ADAPTER_SEALED;
    }
    if (adapter->terminal_failure != 0u) {
        adapter->stats.data_calls++;
        adapter->stats.terminal_stop_data_calls++;
        return fail(*adapter, FK_OWNER_RUNTIME_ADAPTER_TERMINAL_STOPPED);
    }
    if (!output_empty(*adapter)) {
        adapter->stats.data_calls++;
        adapter->stats.output_backpressure_data_calls++;
        return FK_OWNER_RUNTIME_ADAPTER_OUTPUT_BACKPRESSURE;
    }
    if (adapter->next_output_transaction_epoch == 0u) {
        adapter->stats.data_calls++;
        adapter->stats.invalid_calls++;
        return fail(*adapter, FK_OWNER_RUNTIME_ADAPTER_RUNTIME_FAILED);
    }
    if (!packet_descriptor_shape_valid(*adapter, packet)) {
        adapter->stats.data_calls++;
        adapter->stats.invalid_calls++;
        return fail(*adapter, FK_OWNER_RUNTIME_ADAPTER_INVALID);
    }
    const SemanticPrepareResult semantic = prepare_semantic_time(
        *adapter, packet->semantic_timestamp_ns, true);
    if (semantic == SemanticPrepareResult::DrainRequired)
        return FK_OWNER_RUNTIME_ADAPTER_SEMANTIC_DRAIN_REQUIRED;
    adapter->stats.data_calls++;
    if (semantic == SemanticPrepareResult::ClaimRejected)
        return FK_OWNER_RUNTIME_ADAPTER_RUNTIME_CLAIM_REJECTED;
    if (semantic != SemanticPrepareResult::Complete) {
        adapter->stats.runtime_failures++;
        return fail(*adapter, FK_OWNER_RUNTIME_ADAPTER_RUNTIME_FAILED);
    }
    fk_packet_view view{};
    if (!resolve_and_parse_packet(*adapter, *packet, view) ||
        !packet_shape_valid(*adapter, *packet, view)) {
        adapter->stats.invalid_calls++;
        return fail(*adapter, FK_OWNER_RUNTIME_ADAPTER_INVALID);
    }

    if (packet->identity_kind != FK_OWNER_IDENTITY_FLOW_KEY &&
        packet->identity_kind != FK_OWNER_IDENTITY_QUIC_LOGICAL) {
        adapter->stats.invalid_calls++;
        return fail(*adapter, FK_OWNER_RUNTIME_ADAPTER_INVALID);
    }

    if (packet->identity_kind == FK_OWNER_IDENTITY_FLOW_KEY) {
        adapter->stats.ordinary_calls++;
        fk_flow_key canonical_key{};
        if (!ordinary_route_proof(
                *adapter, *packet, view, canonical_key)) {
            return fail(
                *adapter,
                FK_OWNER_RUNTIME_ADAPTER_OWNER_PROOF_REJECTED);
        }
        const fk_compact_runtime_ingress_identity_v2 zero_identity{};
        fk_compact_runtime_flow_identity_v2 identity{};
        adapter->stats.ordinary_canonical_proof_calls++;
        RuntimeOwnerScope runtime_scope(*adapter);
        if (!runtime_scope.active()) {
            adapter->stats.runtime_scope_data_rejections++;
            return FK_OWNER_RUNTIME_ADAPTER_RUNTIME_CLAIM_REJECTED;
        }
        const fk_compact_runtime_result result =
            fk_compact_runtime_process_canonical_packet_v2(
                adapter->runtime, &view, packet->semantic_timestamp_ns,
                &zero_identity, &canonical_key, &identity);
        if (result != FK_COMPACT_RUNTIME_OBSERVED) {
            if (!cleanup_failed_runtime_transaction(
                    *adapter, *packet, identity)) {
                return fail(
                    *adapter, FK_OWNER_RUNTIME_ADAPTER_ROLLBACK_FAILED);
            }
            return runtime_result(*adapter, result, false);
        }
        if (identity.presentation.valid != 1u ||
            identity.presentation.handle_available != 1u ||
            identity.logical_connection_id != 0u ||
            !stage_runtime_outputs(*adapter, *packet, &identity) ||
            !commit_staged_outputs(*adapter)) {
            (void)abort_staged_outputs(*adapter);
            adapter->stats.runtime_failures++;
            return fail(
                *adapter, FK_OWNER_RUNTIME_ADAPTER_RUNTIME_FAILED);
        }
        return runtime_result(*adapter, result, false);
    }

    adapter->stats.logical_quic_calls++;
    if (!quic_route_proof(*adapter, *packet, view)) {
        return fail(
            *adapter, FK_OWNER_RUNTIME_ADAPTER_OWNER_PROOF_REJECTED);
    }
    adapter->stats.quic_route_prevalidation_calls++;
    fk_quic_cid_route_guard_v2 route_guard{};
    const fk_quic_cid_route_prevalidation_result prevalidation =
        fk_quic_cid_map_prevalidate_logical_route_v2(
            adapter->cid_map, packet->logical_connection_id,
            adapter->fixed_owner, &route_guard);
    bool route_guard_reserved_zero = true;
    for (const uint8_t byte : route_guard.reserved)
        route_guard_reserved_zero = route_guard_reserved_zero && byte == 0u;
    const bool route_guard_common_valid =
        route_guard_reserved_zero &&
        route_guard.logical_connection_id ==
            packet->logical_connection_id &&
        route_guard.immutable_fixed_owner == adapter->fixed_owner &&
        route_guard.packet_sequence_known <= 1u &&
        route_guard.retirement_timestamp_known <= 1u &&
        route_guard.retirement_timestamp_formal <= 1u &&
        (route_guard.retirement_timestamp_formal == 0u ||
         route_guard.retirement_timestamp_known != 0u);
    if (prevalidation == FK_QUIC_CID_ROUTE_PREVALIDATION_ACTIVE &&
        route_guard_common_valid &&
        route_guard.lifecycle == FK_QUIC_CID_ROUTE_GUARD_ACTIVE &&
        route_guard.packet_sequence_known == 0u &&
        route_guard.retirement_timestamp_known == 0u &&
        route_guard.retirement_timestamp_formal == 0u &&
        route_guard.retirement_packet_sequence == 0u &&
        route_guard.retirement_timestamp_ns == 0u) {
        adapter->stats.quic_route_prevalidation_active++;
    } else if (prevalidation ==
            FK_QUIC_CID_ROUTE_PREVALIDATION_RETIRED_PENDING_OWNER_ACK &&
        route_guard_common_valid &&
        route_guard.lifecycle ==
            FK_QUIC_CID_ROUTE_GUARD_RETIRED_PENDING_OWNER_ACK &&
        route_guard.packet_sequence_known == 1u &&
        packet->packet_sequence <=
            route_guard.retirement_packet_sequence &&
        (route_guard.retirement_timestamp_known == 0u ||
         packet->semantic_timestamp_ns <=
            route_guard.retirement_timestamp_ns)) {
        adapter->stats.quic_route_prevalidation_retired_pending++;
    } else {
        if (prevalidation ==
            FK_QUIC_CID_ROUTE_PREVALIDATION_RETIRED_PENDING_OWNER_ACK) {
            adapter->stats.quic_route_retired_cutoff_rejections++;
        }
        adapter->stats.quic_route_prevalidation_rejections++;
        adapter->stats.owner_proof_rejections++;
        return fail(
            *adapter,
            FK_OWNER_RUNTIME_ADAPTER_ROUTE_PREVALIDATION_REJECTED);
    }
    const fk_compact_runtime_ingress_identity_v2 ingress_identity{
        packet->logical_connection_id};
    fk_owner_flow_binding binding{};
    const fk_owner_flow_binding_result lookup =
        fk_owner_flow_bindings_lookup(
            adapter->bindings, adapter->fixed_owner,
            packet->logical_connection_id, &binding);
    if (lookup == FK_OWNER_FLOW_BINDING_NOT_FOUND) {
        adapter->stats.binding_lookup_not_found++;
        fk_compact_runtime_flow_identity_v2 admitted{};
        RuntimeOwnerScope runtime_scope(*adapter);
        if (!runtime_scope.active()) {
            adapter->stats.runtime_scope_data_rejections++;
            return FK_OWNER_RUNTIME_ADAPTER_RUNTIME_CLAIM_REJECTED;
        }
        const fk_compact_runtime_result result =
            fk_compact_runtime_process_parsed_packet_v2(
                adapter->runtime, &view, packet->semantic_timestamp_ns,
                &ingress_identity, &admitted);
        if (result != FK_COMPACT_RUNTIME_OBSERVED) {
            if (!cleanup_failed_runtime_transaction(
                    *adapter, *packet, admitted)) {
                return fail(
                    *adapter, FK_OWNER_RUNTIME_ADAPTER_ROLLBACK_FAILED);
            }
            return runtime_result(*adapter, result, true);
        }
        if (admitted.presentation.valid != 1u ||
            admitted.presentation.handle_available != 1u ||
            admitted.presentation.created != 1u ||
            admitted.logical_connection_id !=
                packet->logical_connection_id) {
            (void)stage_runtime_outputs(*adapter, *packet, nullptr);
            (void)abort_staged_outputs(*adapter);
            adapter->stats.runtime_failures++;
            return fail(
                *adapter, FK_OWNER_RUNTIME_ADAPTER_RUNTIME_FAILED);
        }
        if (!stage_runtime_outputs(*adapter, *packet, &admitted)) {
            if (!rollback_new_generation(
                    *adapter, packet->logical_connection_id,
                    admitted.presentation.handle,
                    packet->semantic_timestamp_ns, nullptr)) {
                return fail(
                    *adapter, FK_OWNER_RUNTIME_ADAPTER_ROLLBACK_FAILED);
            }
            return fail(
                *adapter, FK_OWNER_RUNTIME_ADAPTER_RUNTIME_FAILED);
        }
        adapter->stats.initial_distinct_admissions++;
        const fk_owner_flow_handle handle =
            owner_handle(admitted.presentation.handle);
        fk_owner_flow_binding_creation_receipt creation_receipt{};
        const fk_owner_flow_binding_result bound =
            fk_owner_flow_bindings_bind_from_admission_v2(
                adapter->bindings, adapter->fixed_owner,
                packet->logical_connection_id, handle,
                admitted.presentation.first_canonical_direction,
                packet->feature_direction, &binding,
                &creation_receipt);
        if (bound != FK_OWNER_FLOW_BINDING_CREATED) {
            adapter->stats.binding_failures++;
            adapter->stats.initial_bind_failures++;
            if (!rollback_new_generation(
                    *adapter, packet->logical_connection_id,
                    admitted.presentation.handle,
                    packet->semantic_timestamp_ns, nullptr)) {
                return fail(
                    *adapter, FK_OWNER_RUNTIME_ADAPTER_ROLLBACK_FAILED);
            }
            return fail(
                *adapter, FK_OWNER_RUNTIME_ADAPTER_BINDING_FAILED);
        }
        adapter->stats.bindings_created++;
        adapter->stats.binding_creation_receipts++;
        if (!fk_quic_cid_map_mark_binding_established(
                adapter->cid_map, packet->logical_connection_id,
                adapter->fixed_owner)) {
            adapter->stats.cid_binding_mark_failures++;
            if (!rollback_new_generation(
                    *adapter, packet->logical_connection_id,
                    admitted.presentation.handle,
                    packet->semantic_timestamp_ns,
                    &creation_receipt)) {
                return fail(
                    *adapter, FK_OWNER_RUNTIME_ADAPTER_ROLLBACK_FAILED);
            }
            return fail(
                *adapter, FK_OWNER_RUNTIME_ADAPTER_CID_MARK_FAILED);
        }
        adapter->stats.cid_binding_marks++;
        if (!fk_owner_flow_bindings_commit_creation_v2(
                adapter->bindings, adapter->fixed_owner,
                packet->logical_connection_id, handle,
                &creation_receipt)) {
            adapter->stats.binding_creation_commit_failures++;
            adapter->stats.binding_failures++;
            (void)abort_staged_outputs(*adapter);
            return fail(
                *adapter, FK_OWNER_RUNTIME_ADAPTER_BINDING_FAILED);
        }
        adapter->stats.binding_creation_commits++;
        if (!commit_staged_outputs(*adapter)) {
            adapter->stats.runtime_failures++;
            return fail(
                *adapter, FK_OWNER_RUNTIME_ADAPTER_RUNTIME_FAILED);
        }
        adapter->stats.logical_quic_observed++;
        return FK_OWNER_RUNTIME_ADAPTER_QUIC_OBSERVED;
    }
    if (lookup != FK_OWNER_FLOW_BINDING_FOUND) {
        adapter->stats.binding_failures++;
        adapter->stats.binding_lookup_failures++;
        return fail(*adapter, FK_OWNER_RUNTIME_ADAPTER_BINDING_FAILED);
    }
    adapter->stats.binding_lookup_found++;
    uint8_t presentation_direction = 0u;
    if (!fk_owner_flow_binding_resolve_presentation_direction(
            &binding, packet->feature_direction,
            &presentation_direction)) {
        adapter->stats.binding_failures++;
        adapter->stats.direction_resolution_failures++;
        return fail(*adapter, FK_OWNER_RUNTIME_ADAPTER_BINDING_FAILED);
    }
    fk_compact_runtime_packet_once_outcome_v2 outcome{};
    RuntimeOwnerScope runtime_scope(*adapter);
    if (!runtime_scope.active()) {
        adapter->stats.runtime_scope_data_rejections++;
        return FK_OWNER_RUNTIME_ADAPTER_RUNTIME_CLAIM_REJECTED;
    }
    const fk_compact_runtime_result result =
        fk_compact_runtime_process_packet_once_v2(
            adapter->runtime, &view, compact_handle(binding.handle),
            presentation_direction, packet->semantic_timestamp_ns,
            &ingress_identity, &outcome);
    if (result != FK_COMPACT_RUNTIME_OBSERVED) {
        if (!cleanup_failed_runtime_transaction(
                *adapter, *packet, outcome.identity)) {
            return fail(
                *adapter, FK_OWNER_RUNTIME_ADAPTER_ROLLBACK_FAILED);
        }
        return runtime_result(*adapter, result, true);
    }
    if (outcome.identity.presentation.valid != 1u ||
        outcome.identity.presentation.handle_available != 1u ||
        outcome.identity.logical_connection_id !=
            packet->logical_connection_id) {
        (void)stage_runtime_outputs(*adapter, *packet, nullptr);
        (void)abort_staged_outputs(*adapter);
        adapter->stats.runtime_failures++;
        return fail(*adapter, FK_OWNER_RUNTIME_ADAPTER_RUNTIME_FAILED);
    }
    if (!stage_runtime_outputs(*adapter, *packet, &outcome.identity)) {
        if (outcome.identity.presentation.created == 1u) {
            if (!rollback_new_generation(
                    *adapter, packet->logical_connection_id,
                    outcome.identity.presentation.handle,
                    packet->semantic_timestamp_ns, nullptr)) {
                return fail(
                    *adapter, FK_OWNER_RUNTIME_ADAPTER_ROLLBACK_FAILED);
            }
        } else {
            (void)abort_staged_outputs(*adapter);
        }
        return fail(*adapter, FK_OWNER_RUNTIME_ADAPTER_RUNTIME_FAILED);
    }
    if (outcome.stale_bound_handle == 0u) {
        if (outcome.used_bound_handle != 1u ||
            outcome.readmitted != 0u ||
            outcome.rebound_existing != 0u) {
            (void)abort_staged_outputs(*adapter);
            adapter->stats.runtime_failures++;
            return fail(
                *adapter, FK_OWNER_RUNTIME_ADAPTER_RUNTIME_FAILED);
        }
        adapter->stats.live_bound_packets++;
    } else {
        adapter->stats.stale_bound_packets++;
        if (outcome.readmitted != 1u ||
            outcome.rebound_existing != 0u ||
            outcome.identity.presentation.created != 1u) {
            if (outcome.identity.presentation.created == 1u) {
                (void)rollback_new_generation(
                    *adapter, packet->logical_connection_id,
                    outcome.identity.presentation.handle,
                    packet->semantic_timestamp_ns, nullptr);
            } else {
                (void)abort_staged_outputs(*adapter);
            }
            adapter->stats.rebind_failures++;
            return fail(*adapter, FK_OWNER_RUNTIME_ADAPTER_REBIND_FAILED);
        }
        const fk_owner_flow_handle desired =
            owner_handle(outcome.identity.presentation.handle);
        const fk_owner_flow_binding_result rebound =
            fk_owner_flow_bindings_compare_exchange_rebind_from_admission(
                adapter->bindings, adapter->fixed_owner,
                packet->logical_connection_id, binding.handle, desired,
                outcome.identity.presentation.first_canonical_direction,
                packet->feature_direction, &binding);
        if (rebound != FK_OWNER_FLOW_BINDING_REBOUND) {
            adapter->stats.rebind_failures++;
            fk_owner_flow_binding current{};
            const fk_owner_flow_binding_result current_result =
                fk_owner_flow_bindings_lookup(
                    adapter->bindings, adapter->fixed_owner,
                    packet->logical_connection_id, &current);
            if (current_result == FK_OWNER_FLOW_BINDING_FOUND &&
                same_handle(current.handle, desired)) {
                /* An impossible re-entrant commit already made desired live:
                 * do not release a generation still referenced by binding. */
                (void)abort_staged_outputs(*adapter);
                return fail(
                    *adapter, FK_OWNER_RUNTIME_ADAPTER_REBIND_FAILED);
            }
            if (!rollback_new_generation(
                    *adapter, packet->logical_connection_id,
                    outcome.identity.presentation.handle,
                    packet->semantic_timestamp_ns, nullptr)) {
                return fail(
                    *adapter, FK_OWNER_RUNTIME_ADAPTER_ROLLBACK_FAILED);
            }
            return fail(*adapter, FK_OWNER_RUNTIME_ADAPTER_REBIND_FAILED);
        }
        adapter->stats.successful_rebinds++;
    }
    if (!commit_staged_outputs(*adapter)) {
        adapter->stats.runtime_failures++;
        return fail(*adapter, FK_OWNER_RUNTIME_ADAPTER_RUNTIME_FAILED);
    }
    adapter->stats.logical_quic_observed++;
    return FK_OWNER_RUNTIME_ADAPTER_QUIC_OBSERVED;
}

fk_owner_runtime_adapter_result fk_owner_runtime_adapter_process_retire(
        fk_owner_runtime_adapter *adapter,
        const fk_owner_quic_retire_control *control) {
    if (adapter == nullptr)
        return FK_OWNER_RUNTIME_ADAPTER_INVALID;
    if (adapter->initialized == 0u ||
        !fk_owner_flow_bindings_validate_owner_thread_and_account(
            adapter->bindings, adapter->fixed_owner)) {
        return FK_OWNER_RUNTIME_ADAPTER_OWNER_THREAD_REJECTED;
    }
    if (!fk_compact_runtime_validate_owner_adapter_and_account(
            adapter->runtime, reinterpret_cast<uintptr_t>(adapter),
            adapter->fixed_owner)) {
        return FK_OWNER_RUNTIME_ADAPTER_RUNTIME_CLAIM_REJECTED;
    }
    if (receipt_is_sealed(*adapter)) {
        reject_after_seal(*adapter);
        return FK_OWNER_RUNTIME_ADAPTER_SEALED;
    }
    if (adapter->terminal_failure != 0u) {
        adapter->stats.retire_calls++;
        adapter->stats.terminal_stop_retire_calls++;
        return fail(*adapter, FK_OWNER_RUNTIME_ADAPTER_TERMINAL_STOPPED);
    }
    if (!output_empty(*adapter)) {
        adapter->stats.retire_calls++;
        adapter->stats.output_backpressure_retire_calls++;
        return FK_OWNER_RUNTIME_ADAPTER_OUTPUT_BACKPRESSURE;
    }
    bool reserved_zero = control != nullptr;
    if (control != nullptr) {
        for (const uint8_t value : control->reserved)
            reserved_zero = reserved_zero && value == 0u;
    }
    if (control == nullptr ||
        control->fixed_owner != adapter->fixed_owner ||
        control->logical_connection_id == 0u ||
        control->retirement_ordinal == 0u ||
        control->binding_expected_at_enqueue > 1u ||
        !reserved_zero) {
        adapter->stats.retire_calls++;
        adapter->stats.retirement_control_mismatches++;
        return fail(*adapter, FK_OWNER_RUNTIME_ADAPTER_RETIRE_FAILED);
    }
    fk_quic_cid_retirement retirement{};
    if (fk_quic_cid_map_peek_retired(
            adapter->cid_map, adapter->fixed_owner, &retirement) !=
            FK_QUIC_CID_RETIREMENT_PEEK_READY) {
        adapter->stats.retire_calls++;
        adapter->stats.retirement_peek_failures++;
        return fail(*adapter, FK_OWNER_RUNTIME_ADAPTER_RETIRE_FAILED);
    }
    if (retirement.logical_connection_id !=
            control->logical_connection_id ||
        retirement.retirement_ordinal != control->retirement_ordinal ||
        retirement.fixed_owner != control->fixed_owner ||
        (control->binding_expected_at_enqueue != 0u &&
         retirement.binding_expected == 0u)) {
        adapter->stats.retire_calls++;
        adapter->stats.retirement_control_mismatches++;
        return fail(*adapter, FK_OWNER_RUNTIME_ADAPTER_RETIRE_FAILED);
    }
    if (retirement.retirement_timestamp_known != 1u) {
        adapter->stats.retire_calls++;
        adapter->stats.retirement_context_failures++;
        return fail(*adapter, FK_OWNER_RUNTIME_ADAPTER_RETIRE_FAILED);
    }
    const SemanticPrepareResult semantic = prepare_semantic_time(
        *adapter, retirement.retirement_timestamp_ns, false);
    if (semantic == SemanticPrepareResult::DrainRequired)
        return FK_OWNER_RUNTIME_ADAPTER_SEMANTIC_DRAIN_REQUIRED;
    adapter->stats.retire_calls++;
    if (semantic == SemanticPrepareResult::ClaimRejected)
        return FK_OWNER_RUNTIME_ADAPTER_RUNTIME_CLAIM_REJECTED;
    if (semantic != SemanticPrepareResult::Complete) {
        adapter->stats.runtime_failures++;
        return fail(*adapter, FK_OWNER_RUNTIME_ADAPTER_RUNTIME_FAILED);
    }
    adapter->stats.retirement_peek_ready++;
    fk_quic_owner_cleanup_context context{};
    if (!fk_quic_owner_cleanup_context_prepare(
            &adapter->cleanup, &retirement, &context)) {
        adapter->stats.retirement_context_failures++;
        return fail(*adapter, FK_OWNER_RUNTIME_ADAPTER_RETIRE_FAILED);
    }
    fk_quic_cid_retirement_token token{};
    token.logical_connection_id = control->logical_connection_id;
    token.retirement_ordinal = control->retirement_ordinal;
    token.fixed_owner = control->fixed_owner;
    RuntimeOwnerScope runtime_scope(*adapter);
    if (!runtime_scope.active()) {
        adapter->stats.runtime_scope_retire_rejections++;
        return FK_OWNER_RUNTIME_ADAPTER_RUNTIME_CLAIM_REJECTED;
    }
    const fk_quic_cid_retirement_ack_result ack =
        fk_quic_cid_map_ack_retired_with_cleanup(
            adapter->cid_map, &token,
            fk_quic_owner_cleanup_callback, &context);
    if (ack == FK_QUIC_CID_RETIREMENT_ACK_CLEANUP_FAILED &&
        context.completed == 0u) {
        adapter->stats.retirement_retry_required++;
        return FK_OWNER_RUNTIME_ADAPTER_RETIRE_RETRY_REQUIRED;
    }
    if (ack != FK_QUIC_CID_RETIREMENT_ACKED || context.completed != 1u) {
        adapter->stats.retirement_ack_failures++;
        return fail(*adapter, FK_OWNER_RUNTIME_ADAPTER_RETIRE_FAILED);
    }
    adapter->stats.retire_acked++;
    return FK_OWNER_RUNTIME_ADAPTER_RETIRE_ACKED;
}

fk_owner_runtime_output_publish_result
fk_owner_runtime_adapter_publish_output_batch_v2(
        fk_owner_runtime_adapter *adapter) {
    if (adapter == nullptr || adapter->initialized == 0u ||
        !fk_owner_flow_bindings_validate_owner_thread_and_account(
            adapter->bindings, adapter->fixed_owner)) {
        return FK_OWNER_RUNTIME_OUTPUT_PUBLISH_INVALID;
    }
    if (!fk_compact_runtime_validate_owner_adapter_and_account(
            adapter->runtime, reinterpret_cast<uintptr_t>(adapter),
            adapter->fixed_owner))
        return FK_OWNER_RUNTIME_OUTPUT_PUBLISH_INVALID;
    if (receipt_is_sealed(*adapter)) {
        reject_after_seal(*adapter);
        return FK_OWNER_RUNTIME_OUTPUT_PUBLISH_INVALID;
    }
    if (output_empty(*adapter))
        return FK_OWNER_RUNTIME_OUTPUT_PUBLISH_EMPTY;
    adapter->stats.output_publish_calls++;
    if (adapter->output.state !=
            FK_OWNER_RUNTIME_OUTPUT_IDENTITY_COMMITTED ||
        adapter->output.transaction_epoch == 0u) {
        adapter->stats.output_ring_failures++;
        adapter->terminal_failure = 1u;
        return FK_OWNER_RUNTIME_OUTPUT_PUBLISH_FAILED;
    }
    fk_owner_output_batch_commit_receipt receipt{};
    const fk_owner_output_batch_enqueue_result enqueue =
        fk_owner_output_batch_ring_enqueue(
            adapter->output_ring, &adapter->output, &receipt);
    if (enqueue == FK_OWNER_OUTPUT_BATCH_ENQUEUE_FULL) {
        adapter->stats.output_ring_full++;
        return FK_OWNER_RUNTIME_OUTPUT_RING_FULL;
    }
    if (enqueue == FK_OWNER_OUTPUT_BATCH_ENQUEUE_STOPPED) {
        adapter->stats.output_ring_stopped++;
        adapter->terminal_failure = 1u;
        return FK_OWNER_RUNTIME_OUTPUT_RING_STOPPED;
    }
    if (enqueue != FK_OWNER_OUTPUT_BATCH_ENQUEUE_COMMITTED) {
        adapter->stats.output_ring_failures++;
        adapter->terminal_failure = 1u;
        return FK_OWNER_RUNTIME_OUTPUT_PUBLISH_FAILED;
    }
    if (fk_owner_output_batch_ring_ack_commit(
            adapter->output_ring, &receipt) !=
            FK_OWNER_OUTPUT_BATCH_COMMIT_ACKED) {
        adapter->stats.output_ring_commit_ack_failures++;
        adapter->terminal_failure = 1u;
        return FK_OWNER_RUNTIME_OUTPUT_PUBLISH_FAILED;
    }
    adapter->stats.output_ring_commits++;
    adapter->stats.flow_open_outputs_acked +=
        adapter->output.has_flow_open;
    adapter->stats.detection_outputs_acked +=
        adapter->output.has_detection;
    adapter->stats.action_outputs_acked += adapter->output.has_action;
    adapter->stats.output_transactions_acked++;
    clear_output(*adapter);
    return FK_OWNER_RUNTIME_OUTPUT_PUBLISHED;
}

fk_owner_runtime_outbox_abort_result
fk_owner_runtime_adapter_abort_committed_outbox(
        fk_owner_runtime_adapter *adapter,
        fk_owner_runtime_outbox_abort_receipt_v1 *receipt) {
    if (adapter == nullptr || receipt == nullptr ||
        ranges_overlap(
            adapter, sizeof(*adapter), receipt, sizeof(*receipt))) {
        return FK_OWNER_RUNTIME_OUTBOX_ABORT_INVALID;
    }
    *receipt = {};
    if (adapter->initialized == 0u)
        return FK_OWNER_RUNTIME_OUTBOX_ABORT_INVALID;
    if (!fk_owner_flow_bindings_validate_owner_thread_and_account(
            adapter->bindings, adapter->fixed_owner) ||
        !fk_compact_runtime_validate_owner_adapter_and_account(
            adapter->runtime, reinterpret_cast<uintptr_t>(adapter),
            adapter->fixed_owner)) {
        return FK_OWNER_RUNTIME_OUTBOX_ABORT_WRONG_THREAD;
    }
    if (receipt_is_sealed(*adapter)) {
        reject_after_seal(*adapter);
        return FK_OWNER_RUNTIME_OUTBOX_ABORT_SEALED;
    }

    const bool empty = output_empty(*adapter);
    if (!can_increment(adapter->stats.output_committed_discard_calls) ||
        (empty && !can_increment(
            adapter->stats.output_committed_discard_empty))) {
        return FK_OWNER_RUNTIME_OUTBOX_ABORT_COUNTER_OVERFLOW;
    }
    if (empty) {
        ++adapter->stats.output_committed_discard_calls;
        ++adapter->stats.output_committed_discard_empty;
        return FK_OWNER_RUNTIME_OUTBOX_ABORT_EMPTY;
    }

    const fk_owner_runtime_output_batch_v2 &batch = adapter->output;
    if (batch.state != FK_OWNER_RUNTIME_OUTPUT_IDENTITY_COMMITTED ||
        batch.abi_version != FK_OWNER_RUNTIME_OUTPUT_ABI_VERSION ||
        batch.transaction_epoch == 0u ||
        batch.packet_sequence == std::numeric_limits<uint64_t>::max() ||
        batch.has_flow_open > 1u || batch.has_detection > 1u ||
        batch.has_action > 1u ||
        (batch.has_flow_open | batch.has_detection |
         batch.has_action) == 0u) {
        return FK_OWNER_RUNTIME_OUTBOX_ABORT_INVALID;
    }

    const uint64_t flow = batch.has_flow_open;
    const uint64_t detection = batch.has_detection;
    const uint64_t action = batch.has_action;
    if (!can_increment(
            adapter->stats.output_committed_discard_successes) ||
        !can_increment(
            adapter->stats.output_transactions_committed_discarded) ||
        flow > std::numeric_limits<uint64_t>::max() -
            adapter->stats.flow_open_outputs_aborted ||
        flow > std::numeric_limits<uint64_t>::max() -
            adapter->stats.flow_open_outputs_committed_discarded ||
        detection > std::numeric_limits<uint64_t>::max() -
            adapter->stats.detection_outputs_aborted ||
        detection > std::numeric_limits<uint64_t>::max() -
            adapter->stats.detection_outputs_committed_discarded ||
        action > std::numeric_limits<uint64_t>::max() -
            adapter->stats.action_outputs_aborted ||
        action > std::numeric_limits<uint64_t>::max() -
            adapter->stats.action_outputs_committed_discarded) {
        return FK_OWNER_RUNTIME_OUTBOX_ABORT_COUNTER_OVERFLOW;
    }

    fk_owner_runtime_outbox_abort_receipt_v1 candidate{};
    candidate.abi_version =
        FK_OWNER_RUNTIME_OUTBOX_ABORT_RECEIPT_ABI_VERSION;
    candidate.fixed_owner = adapter->fixed_owner;
    if (flow != 0u)
        candidate.output_presence_mask |= static_cast<uint8_t>(
            FK_OWNER_RUNTIME_OUTBOX_HAS_FLOW_OPEN);
    if (detection != 0u)
        candidate.output_presence_mask |= static_cast<uint8_t>(
            FK_OWNER_RUNTIME_OUTBOX_HAS_DETECTION);
    if (action != 0u)
        candidate.output_presence_mask |= static_cast<uint8_t>(
            FK_OWNER_RUNTIME_OUTBOX_HAS_ACTION);
    candidate.transaction_epoch = batch.transaction_epoch;
    candidate.packet_sequence = batch.packet_sequence;
    candidate.receipt_ordinal =
        adapter->stats.output_transactions_committed_discarded + 1u;

    ++adapter->stats.output_committed_discard_calls;
    ++adapter->stats.output_committed_discard_successes;
    ++adapter->stats.output_transactions_committed_discarded;
    adapter->stats.flow_open_outputs_aborted += flow;
    adapter->stats.flow_open_outputs_committed_discarded += flow;
    adapter->stats.detection_outputs_aborted += detection;
    adapter->stats.detection_outputs_committed_discarded += detection;
    adapter->stats.action_outputs_aborted += action;
    adapter->stats.action_outputs_committed_discarded += action;
    adapter->nonformal_abort_used = 1u;
    adapter->stats.nonformal_abort_used = 1u;
    clear_output(*adapter);
    *receipt = candidate;
    return FK_OWNER_RUNTIME_OUTBOX_ABORT_DISCARDED;
}

bool fk_owner_runtime_adapter_seal_receipt(
        fk_owner_runtime_adapter *adapter) {
    if (adapter == nullptr || adapter->initialized == 0u ||
        receipt_is_sealed(*adapter) ||
        !fk_owner_flow_bindings_validate_owner_thread_and_account(
            adapter->bindings, adapter->fixed_owner) ||
        !fk_compact_runtime_validate_owner_adapter_and_account(
            adapter->runtime, reinterpret_cast<uintptr_t>(adapter),
            adapter->fixed_owner) || !output_empty(*adapter)) {
        return false;
    }
    uint64_t owner_thread_rejections = 0u;
    if (!owner_thread_receipt(*adapter, owner_thread_rejections))
        return false;
    adapter->sealed_stats = adapter->stats;
    adapter->sealed_stats.owner_thread_rejections =
        owner_thread_rejections;
    adapter->sealed_stats.post_seal_rejections = 0u;
    adapter->sealed_accounting_conserved =
        (counters_conserved(*adapter) &&
         fk_quic_owner_cleanup_accounting_conserved(&adapter->cleanup))
            ? 1u : 0u;
    adapter->sealed_formal_ready = formal_ready_impl(*adapter) ? 1u : 0u;
    adapter->sealed_stats.formal_ready = adapter->sealed_formal_ready;
    __atomic_store_n(&adapter->receipt_sealed, 1u, __ATOMIC_RELEASE);
    return true;
}

bool fk_owner_runtime_adapter_get_stats(
        const fk_owner_runtime_adapter *adapter,
        fk_owner_runtime_adapter_stats *stats) {
    if (adapter == nullptr || stats == nullptr ||
        adapter->initialized == 0u)
        return false;
    if (receipt_is_sealed(*adapter)) {
        *stats = adapter->sealed_stats;
        if (!owner_thread_receipt(
                *adapter, stats->owner_thread_rejections))
            return false;
        stats->post_seal_rejections = post_seal_rejections(*adapter);
        stats->formal_ready =
            adapter->sealed_formal_ready != 0u &&
            stats->owner_thread_rejections == 0u &&
            stats->post_seal_rejections == 0u;
        return true;
    }
    if (!fk_owner_flow_bindings_is_owner_thread(
            adapter->bindings, adapter->fixed_owner))
        return false;
    *stats = adapter->stats;
    stats->post_seal_rejections = post_seal_rejections(*adapter);
    if (!owner_thread_receipt(*adapter, stats->owner_thread_rejections))
        return false;
    stats->formal_ready = formal_ready_impl(*adapter) ? 1u : 0u;
    return true;
}

bool fk_owner_runtime_adapter_accounting_conserved(
        const fk_owner_runtime_adapter *adapter) {
    if (adapter == nullptr || adapter->initialized == 0u)
        return false;
    if (receipt_is_sealed(*adapter))
        return adapter->sealed_accounting_conserved != 0u;
    return fk_owner_flow_bindings_is_owner_thread(
            adapter->bindings, adapter->fixed_owner) &&
        counters_conserved(*adapter) &&
        fk_quic_owner_cleanup_accounting_conserved(&adapter->cleanup);
}

bool fk_owner_runtime_adapter_formal_ready(
        const fk_owner_runtime_adapter *adapter) {
    if (adapter == nullptr || adapter->initialized == 0u)
        return false;
    if (receipt_is_sealed(*adapter))
    {
        uint64_t owner_thread_rejections = 0u;
        return adapter->sealed_formal_ready != 0u &&
            owner_thread_receipt(
                *adapter, owner_thread_rejections) &&
            owner_thread_rejections == 0u &&
            post_seal_rejections(*adapter) == 0u;
    }
    return fk_owner_flow_bindings_is_owner_thread(
            adapter->bindings, adapter->fixed_owner) &&
        formal_ready_impl(*adapter);
}

const char *fk_owner_runtime_adapter_result_name(
        fk_owner_runtime_adapter_result result) {
    switch (result) {
    case FK_OWNER_RUNTIME_ADAPTER_INVALID:
        return "invalid";
    case FK_OWNER_RUNTIME_ADAPTER_ORDINARY_OBSERVED:
        return "ordinary_observed";
    case FK_OWNER_RUNTIME_ADAPTER_QUIC_OBSERVED:
        return "quic_observed";
    case FK_OWNER_RUNTIME_ADAPTER_RETIRE_ACKED:
        return "retire_acked";
    case FK_OWNER_RUNTIME_ADAPTER_RUNTIME_IGNORED:
        return "runtime_ignored";
    case FK_OWNER_RUNTIME_ADAPTER_ADMISSION_REJECTED:
        return "admission_rejected";
    case FK_OWNER_RUNTIME_ADAPTER_RUNTIME_FAILED:
        return "runtime_failed";
    case FK_OWNER_RUNTIME_ADAPTER_OWNER_PROOF_REJECTED:
        return "owner_proof_rejected";
    case FK_OWNER_RUNTIME_ADAPTER_BINDING_FAILED:
        return "binding_failed";
    case FK_OWNER_RUNTIME_ADAPTER_CID_MARK_FAILED:
        return "cid_mark_failed";
    case FK_OWNER_RUNTIME_ADAPTER_REBIND_FAILED:
        return "rebind_failed";
    case FK_OWNER_RUNTIME_ADAPTER_RETIRE_FAILED:
        return "retire_failed";
    case FK_OWNER_RUNTIME_ADAPTER_ROLLBACK_FAILED:
        return "rollback_failed";
    case FK_OWNER_RUNTIME_ADAPTER_ROUTE_PREVALIDATION_REJECTED:
        return "route_prevalidation_rejected";
    case FK_OWNER_RUNTIME_ADAPTER_TERMINAL_STOPPED:
        return "terminal_stopped";
    case FK_OWNER_RUNTIME_ADAPTER_OUTPUT_BACKPRESSURE:
        return "output_backpressure";
    case FK_OWNER_RUNTIME_ADAPTER_OWNER_THREAD_REJECTED:
        return "owner_thread_rejected";
    case FK_OWNER_RUNTIME_ADAPTER_RUNTIME_CLAIM_REJECTED:
        return "runtime_claim_rejected";
    case FK_OWNER_RUNTIME_ADAPTER_SEALED:
        return "sealed";
    case FK_OWNER_RUNTIME_ADAPTER_RETIRE_RETRY_REQUIRED:
        return "retire_retry_required";
    case FK_OWNER_RUNTIME_ADAPTER_SEMANTIC_DRAIN_REQUIRED:
        return "semantic_drain_required";
    }
    return "unknown";
}
