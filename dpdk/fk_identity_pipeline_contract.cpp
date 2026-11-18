#include "fk_identity_pipeline_contract.h"

#include <cstring>
#include <limits>

namespace {

bool checked_add_u64(uint64_t left, uint64_t right, uint64_t &sum) {
    if (right > std::numeric_limits<uint64_t>::max() - left)
        return false;
    sum = left + right;
    return true;
}

bool exact_topology_shape(
        const fk_identity_pipeline_contract_input &input) {
    return input.rx_producers != 0u &&
        input.identity_workers == 1u &&
        input.owner_workers == input.rx_producers &&
        input.detector_workers != 0u &&
        input.aggregator_workers == 1u &&
        input.main_workers == 1u &&
        ((input.writer_enabled && input.writer_workers == 1u) ||
         (!input.writer_enabled && input.writer_workers == 0u));
}

bool calculate_required_lcores(
        const fk_identity_pipeline_contract_input &input,
        uint64_t &required) {
    required = 0u;
    const uint64_t roles[] = {
        input.rx_producers,
        input.identity_workers,
        input.owner_workers,
        input.detector_workers,
        input.aggregator_workers,
        input.main_workers,
        input.writer_workers,
    };
    for (const uint64_t role : roles) {
        if (!checked_add_u64(required, role, required))
            return false;
    }
    return true;
}

bool calculate_service_memory(
        const fk_identity_pipeline_contract_input &input,
        uint64_t &accounted) {
    accounted = 0u;
    for (uint32_t index = 0u;
         index < FK_IDENTITY_SERVICE_COMPONENT_COUNT; ++index) {
        if (!checked_add_u64(
                accounted,
                input.service_memory_components[index]
                    .configured_reserved_bytes,
                accounted)) {
            return false;
        }
    }
    return checked_add_u64(
        accounted, input.service_memory_unassigned_bytes, accounted);
}

bool receipt_reserved_zero(
        const fk_identity_pipeline_service_memory_receipt &receipt) {
    for (const uint8_t byte : receipt.reserved) {
        if (byte != 0u)
            return false;
    }
    return true;
}

bool service_component_required(
        const fk_identity_pipeline_contract_input &input,
        uint32_t index) {
    return index != FK_IDENTITY_SERVICE_RESULT_WRITER_TRANSPORT ||
        input.writer_enabled;
}

fk_identity_pipeline_contract_result blocked(
        fk_identity_pipeline_contract_result result,
        fk_identity_pipeline_contract_blocker blocker) {
    result.blocker = blocker;
    return result;
}

}  // namespace

extern "C" {

fk_identity_pipeline_contract_result
fk_identity_pipeline_contract_evaluate(
        const fk_identity_pipeline_contract_input *input) {
    fk_identity_pipeline_contract_result result{};
    result.blocker = FK_IDENTITY_PIPELINE_BLOCKER_INVALID_INPUT;
    if (input == nullptr)
        return result;
    result.available_lcores = input->available_lcores;
    result.service_memory_component_count =
        input->service_memory_component_count;

    if (input->contract_abi == nullptr ||
        std::strcmp(
            input->contract_abi,
            FK_IDENTITY_PIPELINE_CONTRACT_ABI) != 0) {
        return blocked(result, FK_IDENTITY_PIPELINE_BLOCKER_ABI_MISMATCH);
    }
    if (!input->experimental_path_connected) {
        return blocked(
            result,
            FK_IDENTITY_PIPELINE_BLOCKER_EXPERIMENTAL_PATH_NOT_CONNECTED);
    }
    if (!input->replay_artifact_frozen ||
        !input->replay_digest_precommitted) {
        return blocked(result, FK_IDENTITY_PIPELINE_BLOCKER_REPLAY_NOT_FROZEN);
    }
    if (!input->sidecar_artifact_frozen ||
        !input->sidecar_digest_precommitted) {
        return blocked(
            result, FK_IDENTITY_PIPELINE_BLOCKER_SIDECAR_NOT_FROZEN);
    }
    if (input->expected_packets == 0u) {
        return blocked(
            result, FK_IDENTITY_PIPELINE_BLOCKER_EXPECTED_PACKETS_INVALID);
    }

    if (!exact_topology_shape(*input)) {
        return blocked(result, FK_IDENTITY_PIPELINE_BLOCKER_TOPOLOGY_INVALID);
    }
    if (!calculate_required_lcores(*input, result.required_lcores)) {
        return blocked(
            result,
            FK_IDENTITY_PIPELINE_BLOCKER_LCORE_ARITHMETIC_OVERFLOW);
    }
    if (input->declared_required_lcores != result.required_lcores) {
        return blocked(
            result,
            FK_IDENTITY_PIPELINE_BLOCKER_REQUIRED_LCORES_MISMATCH);
    }
    if (input->available_lcores < result.required_lcores) {
        return blocked(
            result, FK_IDENTITY_PIPELINE_BLOCKER_INSUFFICIENT_LCORES);
    }

    if (!input->service_memory_contract_precommitted) {
        return blocked(
            result,
            FK_IDENTITY_PIPELINE_BLOCKER_SERVICE_MEMORY_NOT_FROZEN);
    }
    if (input->service_memory_component_count !=
            FK_IDENTITY_SERVICE_COMPONENT_COUNT) {
        return blocked(
            result,
            FK_IDENTITY_PIPELINE_BLOCKER_SERVICE_MEMORY_COMPONENT_SET_MISMATCH);
    }
    if (input->service_memory_ceiling_bytes == 0u ||
        input->controlled_state_budget_bytes == 0u) {
        return blocked(
            result,
            FK_IDENTITY_PIPELINE_BLOCKER_SERVICE_MEMORY_UNBOUNDED);
    }
    for (uint32_t index = 0u;
         index < FK_IDENTITY_SERVICE_COMPONENT_COUNT; ++index) {
        const fk_identity_pipeline_service_memory_receipt &receipt =
            input->service_memory_components[index];
        const bool required = service_component_required(*input, index);
        if (required && receipt.configured_reserved_bytes == 0u) {
            return blocked(
                result,
                FK_IDENTITY_PIPELINE_BLOCKER_SERVICE_MEMORY_UNBOUNDED);
        }
        if ((!required &&
                (receipt.configured_reserved_bytes != 0u ||
                 receipt.observed_reserved_bytes != 0u ||
                 receipt.peak_bytes != 0u)) ||
            !receipt_reserved_zero(receipt)) {
            return blocked(
                result,
                FK_IDENTITY_PIPELINE_BLOCKER_SERVICE_MEMORY_ACCOUNTING);
        }
    }
    if (!calculate_service_memory(
            *input, result.service_memory_accounted_bytes)) {
        return blocked(
            result,
            FK_IDENTITY_PIPELINE_BLOCKER_SERVICE_MEMORY_ARITHMETIC_OVERFLOW);
    }
    bool component_receipts_exact = true;
    for (uint32_t index = 0u;
         index < FK_IDENTITY_SERVICE_COMPONENT_COUNT; ++index) {
        const fk_identity_pipeline_service_memory_receipt &receipt =
            input->service_memory_components[index];
        component_receipts_exact = component_receipts_exact &&
            receipt.observed_reserved_bytes ==
                receipt.configured_reserved_bytes &&
            receipt.peak_bytes <= receipt.configured_reserved_bytes;
    }
    if (!component_receipts_exact ||
        result.service_memory_accounted_bytes !=
            input->service_memory_ceiling_bytes) {
        return blocked(
            result,
            FK_IDENTITY_PIPELINE_BLOCKER_SERVICE_MEMORY_ACCOUNTING);
    }
    if (!input->service_memory_separate_from_controlled_state_budget ||
        input->service_bytes_charged_to_controlled_state_budget != 0u) {
        return blocked(
            result,
            FK_IDENTITY_PIPELINE_BLOCKER_SERVICE_MEMORY_NOT_SEPARATE);
    }

    if (!input->owner_hash_key_digest_precommitted ||
        input->owner_hash_key_digest_bytes !=
            FK_IDENTITY_PIPELINE_SHA256_BYTES) {
        return blocked(
            result,
            FK_IDENTITY_PIPELINE_BLOCKER_OWNER_HASH_DIGEST_NOT_PRECOMMITTED);
    }
    if (!input->ordered_skip_api_connected) {
        return blocked(
            result,
            FK_IDENTITY_PIPELINE_BLOCKER_ORDERED_SKIP_NOT_CONNECTED);
    }

    uint64_t ordered_observations = 0u;
    if (!checked_add_u64(
            input->ordered_data_observations,
            input->ordered_skipped_observations,
            ordered_observations) ||
        input->sequencer_consumed_packets != input->expected_packets ||
        ordered_observations != input->expected_packets ||
        input->ordered_data_observations != input->data_accepted) {
        return blocked(
            result,
            FK_IDENTITY_PIPELINE_BLOCKER_ORDERED_OBSERVATION_ACCOUNTING);
    }
    if (input->ordered_skipped_observations != 0u) {
        return blocked(
            result,
            FK_IDENTITY_PIPELINE_BLOCKER_ORDERED_OBSERVATION_SKIPPED);
    }

    if (!input->retirement_control_generation_complete ||
        !input->retirement_controls_all_visible) {
        return blocked(
            result, FK_IDENTITY_PIPELINE_BLOCKER_RETIREMENT_VISIBILITY);
    }
    if (!input->retirement_publication_transactional) {
        return blocked(
            result, FK_IDENTITY_PIPELINE_BLOCKER_RETIREMENT_PUBLICATION);
    }
    uint64_t accounted_retirement_controls = 0u;
    if (!checked_add_u64(
            input->retirement_controls_normally_processed,
            input->retirement_controls_pending,
            accounted_retirement_controls) ||
        input->retirement_controls_generated !=
            input->retirement_controls_published ||
        input->retirement_controls_published !=
            accounted_retirement_controls ||
        input->retirement_controls_pending != 0u) {
        return blocked(
            result, FK_IDENTITY_PIPELINE_BLOCKER_RETIREMENT_ACCOUNTING);
    }

    uint64_t completed_or_owned_data = 0u;
    if (!checked_add_u64(
            input->data_normally_dequeued,
            input->data_drained,
            completed_or_owned_data) ||
        !checked_add_u64(
            completed_or_owned_data,
            input->data_owned,
            completed_or_owned_data) ||
        completed_or_owned_data != input->data_accepted) {
        return blocked(
            result, FK_IDENTITY_PIPELINE_BLOCKER_DATA_CONSERVATION);
    }
    if (input->data_drained != 0u || input->data_owned != 0u ||
        input->data_normally_dequeued != input->data_accepted) {
        return blocked(
            result,
            FK_IDENTITY_PIPELINE_BLOCKER_DATA_NOT_NORMALLY_COMPLETED);
    }

    if (!input->sequencer_gate_complete)
        return blocked(result, FK_IDENTITY_PIPELINE_BLOCKER_SEQUENCER_GATE);
    if (!input->dispatch_gate_complete)
        return blocked(result, FK_IDENTITY_PIPELINE_BLOCKER_DISPATCH_GATE);
    if (!input->runtime_gate_complete)
        return blocked(result, FK_IDENTITY_PIPELINE_BLOCKER_RUNTIME_GATE);
    if (!input->cid_gate_complete)
        return blocked(result, FK_IDENTITY_PIPELINE_BLOCKER_CID_GATE);
    if (!input->binding_gate_complete)
        return blocked(result, FK_IDENTITY_PIPELINE_BLOCKER_BINDING_GATE);
    if (!input->cleanup_gate_complete)
        return blocked(result, FK_IDENTITY_PIPELINE_BLOCKER_CLEANUP_GATE);
    if (!input->identity_router_gate_complete) {
        return blocked(
            result, FK_IDENTITY_PIPELINE_BLOCKER_IDENTITY_ROUTER_GATE);
    }
    if (!input->route_receipt_gate_complete) {
        return blocked(
            result, FK_IDENTITY_PIPELINE_BLOCKER_ROUTE_RECEIPT_GATE);
    }
    if (!input->owner_worker_gate_complete) {
        return blocked(
            result, FK_IDENTITY_PIPELINE_BLOCKER_OWNER_WORKER_GATE);
    }
    if (!input->owner_output_sequence_gate_complete) {
        return blocked(
            result,
            FK_IDENTITY_PIPELINE_BLOCKER_OWNER_OUTPUT_SEQUENCE_GATE);
    }
    if (!input->event_pipeline_gate_complete) {
        return blocked(
            result, FK_IDENTITY_PIPELINE_BLOCKER_EVENT_PIPELINE_GATE);
    }
    if (!input->normal_shutdown_gate_complete) {
        return blocked(
            result, FK_IDENTITY_PIPELINE_BLOCKER_NORMAL_SHUTDOWN_GATE);
    }

    if (input->complete_quic_claim_requested) {
        if (!input->quic_parser_complete) {
            return blocked(
                result,
                FK_IDENTITY_PIPELINE_BLOCKER_QUIC_PARSER_INCOMPLETE);
        }
        if (!input->logical_event_identity_connected) {
            return blocked(
                result,
                FK_IDENTITY_PIPELINE_BLOCKER_LOGICAL_EVENT_IDENTITY_NOT_CONNECTED);
        }
        if (input->unresolved_quic_packets != 0u) {
            return blocked(
                result, FK_IDENTITY_PIPELINE_BLOCKER_UNRESOLVED_QUIC);
        }
        if (input->ambiguous_quic_packets != 0u) {
            return blocked(
                result, FK_IDENTITY_PIPELINE_BLOCKER_AMBIGUOUS_QUIC);
        }
    }

    if (input->performance_claim_requested) {
        if (!input->performance_measurement_separate_from_correctness) {
            return blocked(
                result,
                FK_IDENTITY_PIPELINE_BLOCKER_PERFORMANCE_NOT_SEPARATE);
        }
        if (!input->performance_measurement_completed) {
            return blocked(
                result,
                FK_IDENTITY_PIPELINE_BLOCKER_PERFORMANCE_NOT_MEASURED);
        }
        if (!input->performance_measurement_passed) {
            return blocked(
                result, FK_IDENTITY_PIPELINE_BLOCKER_PERFORMANCE_FAILED);
        }
    }

    result.passed = true;
    result.blocker = FK_IDENTITY_PIPELINE_BLOCKER_NONE;
    result.complete_quic_claim_authorized =
        input->complete_quic_claim_requested;
    result.performance_claim_authorized =
        input->performance_claim_requested;
    return result;
}

const char *fk_identity_pipeline_contract_blocker_name(
        fk_identity_pipeline_contract_blocker blocker) {
    switch (blocker) {
    case FK_IDENTITY_PIPELINE_BLOCKER_NONE:
        return "none";
    case FK_IDENTITY_PIPELINE_BLOCKER_INVALID_INPUT:
        return "invalid_contract_input";
    case FK_IDENTITY_PIPELINE_BLOCKER_ABI_MISMATCH:
        return "identity_pipeline_contract_ABI_mismatch";
    case FK_IDENTITY_PIPELINE_BLOCKER_EXPERIMENTAL_PATH_NOT_CONNECTED:
        return "experimental_exact_identity_path_not_connected";
    case FK_IDENTITY_PIPELINE_BLOCKER_REPLAY_NOT_FROZEN:
        return "replay_artifact_not_frozen_and_precommitted";
    case FK_IDENTITY_PIPELINE_BLOCKER_SIDECAR_NOT_FROZEN:
        return "sidecar_artifact_not_frozen_and_precommitted";
    case FK_IDENTITY_PIPELINE_BLOCKER_EXPECTED_PACKETS_INVALID:
        return "expected_packets_must_be_positive";
    case FK_IDENTITY_PIPELINE_BLOCKER_TOPOLOGY_INVALID:
        return "exact_identity_pipeline_topology_invalid";
    case FK_IDENTITY_PIPELINE_BLOCKER_LCORE_ARITHMETIC_OVERFLOW:
        return "required_lcores_arithmetic_overflow";
    case FK_IDENTITY_PIPELINE_BLOCKER_REQUIRED_LCORES_MISMATCH:
        return "declared_required_lcores_mismatch";
    case FK_IDENTITY_PIPELINE_BLOCKER_INSUFFICIENT_LCORES:
        return "available_lcores_insufficient";
    case FK_IDENTITY_PIPELINE_BLOCKER_SERVICE_MEMORY_NOT_FROZEN:
        return "service_memory_contract_not_precommitted";
    case FK_IDENTITY_PIPELINE_BLOCKER_SERVICE_MEMORY_COMPONENT_SET_MISMATCH:
        return "service_memory_component_set_mismatch";
    case FK_IDENTITY_PIPELINE_BLOCKER_SERVICE_MEMORY_UNBOUNDED:
        return "service_memory_component_unbounded";
    case FK_IDENTITY_PIPELINE_BLOCKER_SERVICE_MEMORY_ARITHMETIC_OVERFLOW:
        return "service_memory_arithmetic_overflow";
    case FK_IDENTITY_PIPELINE_BLOCKER_SERVICE_MEMORY_ACCOUNTING:
        return "service_memory_accounting_failed";
    case FK_IDENTITY_PIPELINE_BLOCKER_SERVICE_MEMORY_NOT_SEPARATE:
        return "service_memory_not_separate_from_controlled_state";
    case FK_IDENTITY_PIPELINE_BLOCKER_OWNER_HASH_DIGEST_NOT_PRECOMMITTED:
        return "owner_hash_key_digest_not_precommitted";
    case FK_IDENTITY_PIPELINE_BLOCKER_ORDERED_SKIP_NOT_CONNECTED:
        return "ordered_observation_skip_API_not_connected";
    case FK_IDENTITY_PIPELINE_BLOCKER_ORDERED_OBSERVATION_ACCOUNTING:
        return "ordered_observation_accounting_failed";
    case FK_IDENTITY_PIPELINE_BLOCKER_ORDERED_OBSERVATION_SKIPPED:
        return "formal_observation_was_skipped";
    case FK_IDENTITY_PIPELINE_BLOCKER_RETIREMENT_VISIBILITY:
        return "retirement_controls_not_completely_visible";
    case FK_IDENTITY_PIPELINE_BLOCKER_RETIREMENT_PUBLICATION:
        return "retirement_control_publication_not_transactional";
    case FK_IDENTITY_PIPELINE_BLOCKER_RETIREMENT_ACCOUNTING:
        return "retirement_control_accounting_failed";
    case FK_IDENTITY_PIPELINE_BLOCKER_DATA_CONSERVATION:
        return "DATA_mbuf_ownership_not_conserved";
    case FK_IDENTITY_PIPELINE_BLOCKER_DATA_NOT_NORMALLY_COMPLETED:
        return "DATA_not_normally_completed";
    case FK_IDENTITY_PIPELINE_BLOCKER_SEQUENCER_GATE:
        return "exact_sequencer_gate_incomplete";
    case FK_IDENTITY_PIPELINE_BLOCKER_DISPATCH_GATE:
        return "owner_dispatch_gate_incomplete";
    case FK_IDENTITY_PIPELINE_BLOCKER_RUNTIME_GATE:
        return "compact_runtime_gate_incomplete";
    case FK_IDENTITY_PIPELINE_BLOCKER_CID_GATE:
        return "QUIC_CID_gate_incomplete";
    case FK_IDENTITY_PIPELINE_BLOCKER_BINDING_GATE:
        return "owner_binding_gate_incomplete";
    case FK_IDENTITY_PIPELINE_BLOCKER_CLEANUP_GATE:
        return "owner_cleanup_gate_incomplete";
    case FK_IDENTITY_PIPELINE_BLOCKER_IDENTITY_ROUTER_GATE:
        return "exact_identity_router_gate_incomplete";
    case FK_IDENTITY_PIPELINE_BLOCKER_ROUTE_RECEIPT_GATE:
        return "QUIC_route_receipt_gate_incomplete";
    case FK_IDENTITY_PIPELINE_BLOCKER_OWNER_WORKER_GATE:
        return "fixed_owner_worker_gate_incomplete";
    case FK_IDENTITY_PIPELINE_BLOCKER_OWNER_OUTPUT_SEQUENCE_GATE:
        return "owner_output_sequence_gate_incomplete";
    case FK_IDENTITY_PIPELINE_BLOCKER_EVENT_PIPELINE_GATE:
        return "event_pipeline_gate_incomplete";
    case FK_IDENTITY_PIPELINE_BLOCKER_NORMAL_SHUTDOWN_GATE:
        return "normal_shutdown_gate_incomplete";
    case FK_IDENTITY_PIPELINE_BLOCKER_QUIC_PARSER_INCOMPLETE:
        return "complete_QUIC_parser_claim_not_proven";
    case FK_IDENTITY_PIPELINE_BLOCKER_LOGICAL_EVENT_IDENTITY_NOT_CONNECTED:
        return "logical_event_identity_not_connected";
    case FK_IDENTITY_PIPELINE_BLOCKER_UNRESOLVED_QUIC:
        return "unresolved_QUIC_packets_nonzero";
    case FK_IDENTITY_PIPELINE_BLOCKER_AMBIGUOUS_QUIC:
        return "ambiguous_QUIC_packets_nonzero";
    case FK_IDENTITY_PIPELINE_BLOCKER_PERFORMANCE_NOT_SEPARATE:
        return "performance_measurement_not_separate_from_correctness";
    case FK_IDENTITY_PIPELINE_BLOCKER_PERFORMANCE_NOT_MEASURED:
        return "performance_measurement_not_completed";
    case FK_IDENTITY_PIPELINE_BLOCKER_PERFORMANCE_FAILED:
        return "performance_measurement_failed";
    case FK_IDENTITY_PIPELINE_BLOCKER_COUNT:
        break;
    }
    return "unknown_identity_pipeline_contract_blocker";
}

const char *fk_identity_pipeline_contract_abi(void) {
    return FK_IDENTITY_PIPELINE_CONTRACT_ABI;
}

const char *fk_identity_pipeline_service_component_name(
        fk_identity_pipeline_service_component component) {
    switch (component) {
    case FK_IDENTITY_SERVICE_EXACT_IDENTITY_SEQUENCER:
        return "exact_identity_sequencer";
    case FK_IDENTITY_SERVICE_EXACT_IDENTITY_MBUF_SOURCE:
        return "exact_identity_mbuf_source";
    case FK_IDENTITY_SERVICE_RETIREMENT_PUBLISHER:
        return "retirement_publisher";
    case FK_IDENTITY_SERVICE_OWNER_DISPATCH:
        return "owner_dispatch";
    case FK_IDENTITY_SERVICE_QUIC_ROUTE_RECEIPTS:
        return "quic_route_receipts";
    case FK_IDENTITY_SERVICE_OWNER_MBUF_SOURCES:
        return "owner_mbuf_sources";
    case FK_IDENTITY_SERVICE_OWNER_RUNTIME_ADAPTERS:
        return "owner_runtime_adapters";
    case FK_IDENTITY_SERVICE_OWNER_OUTPUT_RINGS:
        return "owner_output_rings";
    case FK_IDENTITY_SERVICE_OWNER_OUTPUT_SEQUENCE_BRIDGE:
        return "owner_output_sequence_bridge";
    case FK_IDENTITY_SERVICE_TRACE_MESSAGE_BARRIER:
        return "trace_message_barrier";
    case FK_IDENTITY_SERVICE_CHECKPOINT_REORDER:
        return "checkpoint_reorder";
    case FK_IDENTITY_SERVICE_DETECTOR_TRANSPORT:
        return "detector_transport";
    case FK_IDENTITY_SERVICE_AGGREGATOR_TRANSPORT:
        return "aggregator_transport";
    case FK_IDENTITY_SERVICE_RESULT_WRITER_TRANSPORT:
        return "result_writer_transport";
    case FK_IDENTITY_SERVICE_COMPONENT_COUNT:
        break;
    }
    return "unknown_identity_service_component";
}

}  // extern "C"
