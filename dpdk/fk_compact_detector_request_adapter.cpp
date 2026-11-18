#include "fk_compact_detector_request_adapter.h"

#include <cstring>
#include <limits>

static_assert(
    FK_COMPACT_DETECTOR_FEATURES_MAX == FK_DETECTOR_REQUEST_FEATURE_COUNT,
    "compact/external detector feature ABI diverged");

namespace {

bool global_flow_index(
        uint32_t flow_index,
        uint16_t shard,
        uint16_t shard_count,
        uint32_t maximum_flows,
        uint32_t *output) {
    if (output == nullptr || shard_count == 0u || shard >= shard_count ||
        maximum_flows == 0u || maximum_flows % shard_count != 0u) {
        return false;
    }
    const uint32_t flows_per_shard = maximum_flows / shard_count;
    if (flow_index >= flows_per_shard)
        return false;
    const uint64_t global =
        static_cast<uint64_t>(shard) * flows_per_shard + flow_index;
    if (global >= maximum_flows ||
        global >= std::numeric_limits<uint32_t>::max()) {
        return false;
    }
    *output = static_cast<uint32_t>(global);
    return true;
}

bool common_transport_fields_valid(
        uint64_t physical_ingress_timestamp_ns,
        uint64_t event_routing_token) {
    return physical_ingress_timestamp_ns != 0u &&
        event_routing_token != 0u &&
        event_routing_token <= FK_DETECTOR_REQUEST_SHM_MAX_SEQUENCE;
}

}  // namespace

extern "C" bool fk_compact_detector_request_adapter_build(
        const fk_compact_detection_request_v2 *input,
        uint16_t shard,
        uint16_t shard_count,
        uint32_t maximum_flows,
        uint64_t physical_ingress_timestamp_ns,
        uint64_t event_routing_token,
        fk_detector_request_v1 *output) {
    if (output != nullptr)
        std::memset(output, 0, sizeof(*output));
    if (input == nullptr || output == nullptr ||
        !common_transport_fields_valid(
            physical_ingress_timestamp_ns, event_routing_token)) {
        return false;
    }

    const fk_compact_detection_request &source = input->presentation;
    if (source.feature_count != FK_DETECTOR_REQUEST_FEATURE_COUNT ||
        source.flow_generation == 0u || source.checkpoint_packet == 0u ||
        source.reserved != 0u ||
        (source.component_mask & static_cast<uint8_t>(
            ~FK_DETECTOR_REQUEST_SOURCE_MASK_ALL)) != 0u) {
        return false;
    }
    uint32_t global_index = 0u;
    if (!global_flow_index(
            source.flow_index, shard, shard_count, maximum_flows,
            &global_index)) {
        return false;
    }

    if (!fk_detector_request_v1_prepare(output))
        return false;
    output->canonical_key = source.key;
    output->flow_index = global_index;
    output->flow_generation = source.flow_generation;
    output->checkpoint_packet = source.checkpoint_packet;
    output->source_mask = source.component_mask;
    output->semantic_timestamp_ns = source.observation_timestamp_ns;
    output->flow_first_timestamp_ns = source.flow_first_timestamp_ns;
    output->physical_timestamp_ns = physical_ingress_timestamp_ns;
    output->event_routing_token = event_routing_token;
    output->logical_connection_id = input->logical_connection_id;
    std::memcpy(
        output->features,
        source.features,
        sizeof(output->features));
    if (!fk_detector_request_v1_valid(output)) {
        std::memset(output, 0, sizeof(*output));
        return false;
    }
    return true;
}


extern "C" bool fk_compact_detector_flow_open_adapter_build(
        const fk_compact_flow_open_observation_v2 *input,
        uint16_t shard,
        uint16_t shard_count,
        uint32_t maximum_flows,
        uint64_t physical_ingress_timestamp_ns,
        uint64_t event_routing_token,
        fk_detector_request_v1 *output) {
    if (output != nullptr)
        std::memset(output, 0, sizeof(*output));
    if (input == nullptr || output == nullptr ||
        !common_transport_fields_valid(
            physical_ingress_timestamp_ns, event_routing_token)) {
        return false;
    }
    const fk_compact_flow_open_observation &source = input->presentation;
    const bool flow_open =
        source.control_kind == FK_COMPACT_FLOW_CONTROL_OPEN;
    const bool flow_continue =
        source.control_kind == FK_COMPACT_FLOW_CONTROL_CONTINUE;
    uint32_t global_index = 0u;
    uint32_t predecessor_global_index = 0u;
    if (source.flow_generation == 0u ||
        (!flow_open && !flow_continue) ||
        (source.reserved[0] | source.reserved[1] | source.reserved[2]) != 0u ||
        source.flow_first_timestamp_ns == 0u ||
        source.flow_first_timestamp_ns > source.observation_timestamp_ns ||
        (flow_open && source.flow_first_timestamp_ns !=
            source.observation_timestamp_ns) ||
        (flow_open &&
         (source.predecessor_flow_index != 0u ||
          source.predecessor_flow_generation != 0u ||
          source.predecessor_checkpoint_packet != 0u)) ||
        (flow_continue &&
         (source.predecessor_flow_generation == 0u ||
          (source.predecessor_flow_index == source.flow_index &&
           source.predecessor_flow_generation ==
               source.flow_generation))) ||
        !global_flow_index(
            source.flow_index, shard, shard_count, maximum_flows,
            &global_index) ||
        (flow_continue && !global_flow_index(
            source.predecessor_flow_index, shard, shard_count,
            maximum_flows, &predecessor_global_index)) ||
        !fk_detector_request_v1_prepare(output)) {
        return false;
    }
    output->canonical_key = source.key;
    output->flow_index = global_index;
    output->flow_generation = source.flow_generation;
    output->predecessor_flow_index = predecessor_global_index;
    output->predecessor_flow_generation =
        source.predecessor_flow_generation;
    output->predecessor_checkpoint_packet =
        source.predecessor_checkpoint_packet;
    output->flags = flow_open ? FK_DETECTOR_REQUEST_FLAG_FLOW_OPEN :
        FK_DETECTOR_REQUEST_FLAG_FLOW_CONTINUE;
    output->semantic_timestamp_ns = source.observation_timestamp_ns;
    output->flow_first_timestamp_ns = source.flow_first_timestamp_ns;
    output->physical_timestamp_ns = physical_ingress_timestamp_ns;
    output->event_routing_token = event_routing_token;
    output->logical_connection_id = input->logical_connection_id;
    if(source.coverage_prefix_present>1u || (flow_continue && source.coverage_prefix_present))return false;
    if(source.coverage_prefix_present) {
        output->flags=FK_DETECTOR_REQUEST_FLAG_COVERAGE_OPEN;
        std::memcpy(output->features,source.coverage_prefix,sizeof(output->features));
    }
    if (!fk_detector_request_v1_valid(output)) {
        std::memset(output, 0, sizeof(*output));
        return false;
    }
    return true;
}
