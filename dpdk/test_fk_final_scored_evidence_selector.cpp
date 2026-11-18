#include "fk_final_scored_evidence_selector.h"
#include "fk_native_fusion_service.h"
#include <algorithm>
#include <filesystem>
#include <iostream>
#include <jansson.h>
#include <sched.h>
#include <stdexcept>

using namespace flowkeep;

void require(bool condition, const std::string &message) {
    if (!condition) throw std::runtime_error(message);
}

uint64_t count(const std::string &receipt, const char *key) {
    json_error_t error{};
    json_t *root = json_loads(receipt.c_str(), 0, &error);
    require(root != nullptr, "invalid receipt");
    json_t *value = json_object_get(root, key);
    require(json_is_integer(value), key);
    const uint64_t result = json_integer_value(value);
    json_decref(root);
    return result;
}

std::string exercise(const std::string &mode, bool corrupt) {
    const std::string name = "/fk_abc_selector_" + std::to_string(getpid()) + mode + (corrupt ? "bad" : "good");
    auto versions = std::make_shared<PrefixVersionStore>(name, 20260925);
    PrefixVersionStore::Identity identity{};
    identity.key.ip_version = 4;
    identity.key.protocol = 17;
    identity.key.low_addr[0] = 10;
    identity.key.high_addr[0] = 20;
    identity.key.low_port = 12345;
    identity.key.high_port = 443;
    identity.first = 100;
    identity.logical = 42;
    for (uint32_t packet = 1; packet <= 20; ++packet) {
        PrefixVersionStore::Prefix prefix{};
        prefix.physical_ns = 1000 + packet;
        prefix.evidence.packet = packet;
        prefix.evidence.observation_ns = 100 + packet;
        prefix.evidence.flow_index = packet < 12 ? 7 : 19;
        prefix.evidence.generation = packet < 12 ? 3 : 4;
        prefix.evidence.mask = 3;
        for (size_t feature = 0; feature < prefix.evidence.features.size(); ++feature)
            prefix.evidence.features[feature] = float(packet * 1000 + feature);
        require(versions->Publish(identity, prefix, packet == 1 ? 5 : 0), "publish");
    }
    SelectedEvidenceStoreConfig config;
    config.mode = mode;
    config.directory = "/tmp" + name;
    config.model_sha256 = std::string(64, 'a');
    config.policy_sha256 = std::string(64, 'b');
    config.run_uuid = "selector-delayed-fixture";
    cpu_set_t allowed;
    CPU_ZERO(&allowed);
    require(sched_getaffinity(0, sizeof(allowed), &allowed) == 0, "affinity");
    for (unsigned cpu = 0; cpu < CPU_SETSIZE; ++cpu)
        if (CPU_ISSET(cpu, &allowed)) { config.writer_cpu = cpu; break; }
    std::string receipt;
    {
        auto store = std::make_shared<SelectedEvidenceStore>(config);
        FinalScoredEvidenceSelector selector(versions, nullptr, store, 16, 16);
        std::string error;
        for (uint32_t packet : {5u, 10u}) {
            PrefixVersionStore::Prefix prefix{};
            require(versions->Lookup(identity, packet, &prefix), "lookup");
            fk_detector_request_v1 request{};
            request.magic = FK_DETECTOR_REQUEST_MAGIC;
            request.abi_version = FK_DETECTOR_REQUEST_ABI_VERSION;
            request.header_bytes = FK_DETECTOR_REQUEST_HEADER_BYTES;
            request.record_bytes = FK_DETECTOR_REQUEST_RECORD_BYTES;
            request.feature_count = FK_DETECTOR_REQUEST_FEATURE_COUNT;
            request.canonical_key = identity.key;
            request.flow_first_timestamp_ns = identity.first;
            request.logical_connection_id = identity.logical;
            request.flow_index = prefix.evidence.flow_index;
            request.flow_generation = prefix.evidence.generation;
            request.checkpoint_packet = packet;
            request.source_mask = prefix.evidence.mask;
            request.semantic_timestamp_ns = prefix.evidence.observation_ns;
            request.physical_timestamp_ns = prefix.physical_ns;
            request.event_routing_token = packet;
            std::copy(prefix.evidence.features.begin(), prefix.evidence.features.end(), request.features);
            if (corrupt && packet == 5) request.features[0] += 1;
            require(selector.Issued(request, packet, 42, &error), error);
            require(selector.Scored(packet, packet == 5, .75, &error), error);
            NativeFusionDecision decision{};
            decision.kind = NativeFusionDecisionKind::Checkpoint;
            decision.sequence = packet;
            decision.event_token = 42;
            decision.canonical_key = identity.key;
            decision.flow_first_timestamp_ns = identity.first;
            decision.logical_connection_id = identity.logical;
            decision.flow_index = request.flow_index;
            decision.flow_generation = request.flow_generation;
            decision.checkpoint_packet = packet;
            decision.source_mask = request.source_mask;
            decision.semantic_timestamp_ns = request.semantic_timestamp_ns;
            decision.physical_enqueue_monotonic_ns = request.physical_timestamp_ns;
            decision.score_present = true;
            decision.score = .75;
            decision.threshold_met = true;
            decision.alert_latched = true;
            require(selector.Durable(decision, &error), error);
        }
        const bool finalized = selector.Finalize(identity.key, identity.first, identity.logical, 10, &error);
        if (corrupt) {
            require(!finalized && error.find("historical payload") != std::string::npos,
                    "wrong historical request must fail closed");
            require(!selector.Finish(&error), "failed selector cannot finish successfully");
        } else {
            require(finalized, error);
            require(selector.Finish(&error), error);
            require(selector.Verify(&error), error);
            receipt = selector.ReceiptJson();
            require(count(receipt, "expected_records") == 1, "one last actual score");
            require(count(receipt, "durable_records") == 1, "one durable record");
            require(count(receipt, "exact_historical_payload_matches") == 1, "historical bytes verified");
            require(count(receipt, "synthetic_rows_attested") == 1, "synthetic latest not selected");
        }
    }
    std::filesystem::remove_all(config.directory);
    return receipt;
}

int main() {
    try {
        for (const std::string mode : {"baseline", "flowkeep"}) {
            exercise(mode, false);
            exercise(mode, true);
            std::cout << "PASS " << mode << ": latest=20, synthetic=10, selected=5; historical generation and 159 features read back; wrong oracle rejected\n";
        }
    } catch (const std::exception &error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
    return 0;
}
