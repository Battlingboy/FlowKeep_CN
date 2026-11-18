#include "fk_dpdk_finite_live_runner.h"

#include "fk_dpdk_exact_rx_producer_pump.h"
#include "fk_finite_live_quic_correctness_gate.h"
#include "fk_fixed_ttl_retention_contract.h"
#include "fk_no_nic_decision_trace_csv.h"
#include "fk_no_nic_full_composition.h"
#include "fk_quic_cid_map.h"
#include "fk_quic_presentation_path_directory.h"
#include "fk_trace_sidecar.h"
#include "fk_trace_transport_shim.h"

#include <rte_ethdev.h>
#include <rte_dev.h>
#include <rte_errno.h>
#include <rte_mbuf.h>

#include <openssl/evp.h>

#include <array>
#include <cerrno>
#include <cinttypes>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <limits>
#include <memory>
#include <new>
#include <string>
#include <sys/stat.h>
#include <time.h>

namespace {

constexpr uint16_t kRxDescriptors = 4096u;
constexpr uint32_t kMbufCount = 16383u;
constexpr uint32_t kMbufCache = 256u;
constexpr uint16_t kDefaultBurst = 32u;
constexpr uint32_t kDefaultMaximumFlows = 45056u;
constexpr uint32_t kDefaultIdleTimeoutMs = 30000u;
constexpr uint64_t kFlowIdleTimeoutNs = UINT64_C(120000000000);
constexpr size_t kTrackCapacity = 32768u;
constexpr size_t kSha256Bytes = 32u;
static_assert(
    (kTrackCapacity & (kTrackCapacity - 1u)) == 0u,
    "live mbuf tracker capacity must be a power of two");

struct Options {
    uint16_t port = UINT16_MAX;
    uint16_t burst = kDefaultBurst;
    uint32_t expected_packets = 0u;
    uint16_t maximum_captured_length = 0u;
    uint32_t maximum_flows = kDefaultMaximumFlows;
    uint32_t maximum_quic_connections = 0u;
    uint32_t idle_timeout_ms = kDefaultIdleTimeoutMs;
    fk_no_nic_full_composition_budget_mode budget =
        FK_NO_NIC_FULL_COMPOSITION_BUDGET_16_MIB;
    const char *budget_name = "16";
    const char *sidecar_path = nullptr;
    const char *sidecar_sha256 = nullptr;
    std::array<uint8_t, kSha256Bytes> observed_sidecar_sha256{};
    bool observed_sidecar_sha256_valid = false;
    bool sidecar_sha256_verified = false;
    const char *expected_nic_device = nullptr;
    const char *expected_nic_driver = nullptr;
    const char *action_model = nullptr;
    const char *value_model_v3_artifact = nullptr;
    const char *value_model_v3_artifact_sha = nullptr;
    const char *value_model_v3_training_receipt_sha = nullptr;
    const char *value_model_v3_schema_sha = nullptr;
    const char *value_model_v3_action_domain_sha = nullptr;
    const char *value_model_v3_deadline_contract_sha = nullptr;
    fk_value_model_v3_role value_model_v3_role = FK_VALUE_MODEL_V3_FLOWKEEP;
    bool value_model_v3_role_seen = false;
    const char *detector_model = nullptr;
    const char *detector_state_model_dir = nullptr;
    const char *action_schema = nullptr;
    const char *detector_schema = nullptr;
    const char *event_student_artifact = nullptr;
    const char *event_student_artifact_sha = nullptr;
    const char *event_student_feature_schema_sha = nullptr;
    const char *event_student_source_state_sha = nullptr;
    const char *aggregation_mode = nullptr;
    const char *aggregation_rule = nullptr;
    const char *aggregation_threshold_profile = nullptr;
    const char *aggregation_contract_sha = nullptr;
    const char *development_oof_receipt_sha = nullptr;
    const char *causal_event_calibrator_artifact = nullptr;
    const char *causal_event_calibrator_artifact_sha = nullptr;
    const char *causal_event_calibrator_source_npz_sha = nullptr;
    const char *causal_event_calibrator_feature_contract_sha = nullptr;
    const char *causal_event_calibrator_real_prefix_receipt_sha = nullptr;
    float aggregation_threshold = 0.0f;
    bool aggregation_threshold_seen = false;
    const char *monitored_cidr = nullptr;
    const char *decision_trace = nullptr;
    const char *decision_trace_features = nullptr;
    uint32_t event_student_hidden = 0u;
    uint32_t event_student_identity_embedding = 0u;
    const char *output = nullptr;
    rte_ether_addr expected_wire_source_mac{};
    bool expected_wire_source_mac_set = false;
    fk_component_pool_weights pool_weights{};
    bool pool_weights_seen = false;
    fk_compact_retention_policy_kind retention_policy =
        FK_COMPACT_POLICY_FLOWKEEP;
    const char *retention_policy_name = "flowkeep";
    bool retention_policy_seen = false;
    fk_fixed_ttl_retention_binding fixed_ttl_retention{};
    /* Explicit promotion request for the narrowly scoped actual-NIC QUIC
     * correctness claim.  Without this flag the runner remains a diagnostic
     * finite-live receipt even if every underlying gate happens to pass. */
    bool require_quic_identity_proof = false;
};

static const char *resolved_action_model(const Options &options) {
    return options.value_model_v3_artifact != nullptr
        ? options.value_model_v3_artifact : options.action_model;
}

struct DecisionTraceFeaturesReceipt {
    std::array<uint8_t, kSha256Bytes> sha256{};
    uint64_t rows = 0u;
    bool enabled = false;
    bool sha256_valid = false;
    bool row_conservation_valid = false;
};

struct NicReceipt {
    rte_eth_stats baseline{};
    rte_eth_stats end{};
    rte_eth_stats delta{};
    rte_ether_addr mac{};
    rte_eth_link start_link{};
    rte_eth_link end_link{};
    bool device_valid = false;
    std::array<char, 128u> device_name{};
    std::array<char, 128u> driver_name{};
    bool device_info_valid = false;
    bool device_identity_verified = false;
    bool configured = false;
    bool queue_ready = false;
    bool started = false;
    bool promiscuous_enabled = false;
    bool baseline_valid = false;
    bool end_valid = false;
    uint64_t rx_dropped_packets_xstat_id = UINT64_MAX;
    uint64_t rx_dropped_packets_baseline = 0u;
    uint64_t rx_dropped_packets_end = 0u;
    uint64_t rx_dropped_packets_delta = 0u;
    bool rx_dropped_packets_xstat_resolved = false;
    bool rx_dropped_packets_baseline_valid = false;
    bool rx_dropped_packets_end_valid = false;
    bool rx_dropped_packets_monotonic = false;
    bool mac_valid = false;
    bool start_link_valid = false;
    bool end_link_valid = false;
    bool counters_monotonic = false;
    uint16_t original_mtu = 0u;
    uint16_t required_mtu = 0u;
    uint16_t configured_mtu = 0u;
    uint16_t restored_mtu = 0u;
    int original_mtu_status = 0;
    int configure_mtu_status = 0;
    int configured_mtu_status = 0;
    int restore_mtu_status = 0;
    int restored_mtu_status = 0;
    int promiscuous_enable_status = 0;
    int promiscuous_disable_status = 0;
    int stop_status = 0;
    int close_status = 0;
    bool original_mtu_valid = false;
    bool configured_mtu_valid = false;
    bool mtu_changed = false;
    bool mtu_restored = false;
    bool promiscuous_disabled = false;
    bool stop_succeeded = false;
    bool close_succeeded = false;
};

uint64_t monotonic_ns() {
    timespec value{};
    if (clock_gettime(CLOCK_MONOTONIC, &value) != 0)
        return 0u;
    return static_cast<uint64_t>(value.tv_sec) * UINT64_C(1000000000) +
        static_cast<uint64_t>(value.tv_nsec);
}

bool add_u64(uint64_t &value, uint64_t amount) {
    if (amount > std::numeric_limits<uint64_t>::max() - value)
        return false;
    value += amount;
    return true;
}

bool parse_u32(const char *text, uint32_t &value) {
    if (text == nullptr || *text == '\0')
        return false;
    errno = 0;
    char *end = nullptr;
    const unsigned long parsed = std::strtoul(text, &end, 10);
    if (errno != 0 || end == text || *end != '\0' || parsed == 0u ||
        parsed > UINT32_MAX)
        return false;
    value = static_cast<uint32_t>(parsed);
    return true;
}

bool parse_u16(const char *text, uint16_t &value) {
    uint32_t parsed = 0u;
    if (!parse_u32(text, parsed) || parsed > UINT16_MAX)
        return false;
    value = static_cast<uint16_t>(parsed);
    return true;
}

bool parse_port(const char *text, uint16_t &value) {
    if (text == nullptr || *text == '\0')
        return false;
    errno = 0;
    char *end = nullptr;
    const unsigned long parsed = std::strtoul(text, &end, 10);
    if (errno != 0 || end == text || *end != '\0' ||
        parsed > UINT16_MAX)
        return false;
    value = static_cast<uint16_t>(parsed);
    return true;
}

bool parse_probability(const char *text, float &value) {
    if (text == nullptr || *text == '\0')
        return false;
    errno = 0;
    char *end = nullptr;
    const float parsed = std::strtof(text, &end);
    if (errno != 0 || end == text || *end != '\0' ||
        !std::isfinite(parsed) || parsed <= 0.0f || parsed > 1.0f)
        return false;
    value = parsed;
    return true;
}

bool parse_unicast_mac(const char *text, rte_ether_addr &address) {
    if (text == nullptr)
        return false;
    unsigned values[RTE_ETHER_ADDR_LEN]{};
    int consumed = 0;
    if (std::sscanf(
            text,
            "%2x:%2x:%2x:%2x:%2x:%2x%n",
            &values[0], &values[1], &values[2],
            &values[3], &values[4], &values[5], &consumed) !=
            static_cast<int>(RTE_ETHER_ADDR_LEN) ||
        consumed <= 0 || text[consumed] != '\0')
        return false;
    bool any = false;
    for (size_t index = 0u; index < RTE_ETHER_ADDR_LEN; ++index) {
        if (values[index] > UINT8_MAX)
            return false;
        address.addr_bytes[index] = static_cast<uint8_t>(values[index]);
        any = any || values[index] != 0u;
    }
    return any && (address.addr_bytes[0] & 1u) == 0u;
}

bool valid_sha256(const char *text) {
    if (text == nullptr || std::strlen(text) != 64u)
        return false;
    for (size_t index = 0u; index < 64u; ++index) {
        if (!((text[index] >= '0' && text[index] <= '9') ||
              (text[index] >= 'a' && text[index] <= 'f')))
            return false;
    }
    return true;
}

bool set_once(const char *&target, const char *value) {
    if (target != nullptr || value == nullptr)
        return false;
    target = value;
    return true;
}

bool existing_files_alias(const char *left, const char *right) {
    if (left == nullptr || right == nullptr)
        return false;
    struct stat left_status{};
    struct stat right_status{};
    return stat(left, &left_status) == 0 && stat(right, &right_status) == 0 &&
        left_status.st_dev == right_status.st_dev &&
        left_status.st_ino == right_status.st_ino;
}

void usage(FILE *stream, const char *program) {
    std::fprintf(
        stream,
        "usage: %s --rx-port N --expected-packets N "
        "--trace-timestamp-sidecar FKTSV1 "
        "[--trace-timestamp-sidecar-sha256 SHA256] "
        "--maximum-captured-length N "
        "--expected-wire-source-mac MAC --budget 16|32|64|unlimited "
        "[--expected-nic-device DPDK_DEVICE_NAME "
        "--expected-nic-driver DPDK_DRIVER_NAME] "
        "[--pool-weights STAT,SEQ,JA4_PENDING,JA4_SUMMARY] "
        "[--retention-policy flowkeep|lru|fixed_ttl|protocol_aware|"
        "protocol_deadline|handshake_only|full_state|summary_only|history_only|"
        "summary_history|summary_handshake|history_handshake|core_only] "
        "[--fixed-ttl-ns POSITIVE_DECIMAL_UINT64_NS] "
        "[--maximum-flows N] --maximum-quic-connections N "
        "[--burst 1..256] [--idle-timeout-ms N] "
        "--action-model FILE "
        "(--detector-model FILE | --detector-state-model-dir DIR) "
        "--action-schema SHA256 "
        "--detector-schema SHA256 "
        "[--aggregation-mode frozen_cpp_causal --aggregation-rule "
        "max|causal_event_calibrator_max "
        "--aggregation-threshold-profile NAME --aggregation-threshold P "
        "--aggregation-contract-sha256 SHA256 "
        "--development-oof-receipt-sha256 SHA256 "
        "[--causal-event-calibrator-artifact FILE "
        "--causal-event-calibrator-artifact-sha SHA256 "
        "--causal-event-calibrator-source-npz-sha SHA256 "
        "--causal-event-calibrator-feature-contract-sha SHA256 "
        "--causal-event-calibrator-real-prefix-receipt-sha SHA256]] "
        "[--monitored-cidr CIDR --event-student-artifact FKESV1 "
        "--event-student-artifact-sha SHA256 "
        "--event-student-feature-schema-sha SHA256 "
        "--event-student-source-state-sha SHA256 "
        "--event-student-hidden N --event-student-identity-embedding N] "
        "[--decision-trace CSV [--decision-trace-features CSV]] "
        "[--require-quic-identity-proof] "
        "--output JSON\n",
        program == nullptr ? "--finite-live-rx-pump" : program);
}

bool parse_pool_weights(const char *text, fk_component_pool_weights &weights) {
    unsigned values[4]{};
    char tail = '\0';
    if (text == nullptr || std::sscanf(text, "%u,%u,%u,%u%c",
            &values[0], &values[1], &values[2], &values[3], &tail) != 4)
        return false;
    unsigned total = 0u;
    for (unsigned value : values) {
        if (value > 100u)
            return false;
        total += value;
    }
    if (total != 100u)
        return false;
    weights = {static_cast<uint8_t>(values[0]),
               static_cast<uint8_t>(values[1]),
               static_cast<uint8_t>(values[2]),
               static_cast<uint8_t>(values[3])};
    return true;
}

bool parse_options(int argc, char **argv, Options &options) {
    bool port_seen = false;
    bool expected_seen = false;
    bool maximum_length_seen = false;
    bool budget_seen = false;
    bool burst_seen = false;
    bool flows_seen = false;
    bool quic_connections_seen = false;
    bool idle_seen = false;
    bool event_hidden_seen = false;
    bool event_embedding_seen = false;
    for (int index = 1; index < argc; ++index) {
        const char *name = argv[index];
        if (std::strcmp(name, "--help") == 0)
            return false;
        if (std::strcmp(name, "--require-quic-identity-proof") == 0) {
            if (options.require_quic_identity_proof)
                return false;
            options.require_quic_identity_proof = true;
            continue;
        }
        if (index + 1 >= argc)
            return false;
        const char *value = argv[++index];
        if (std::strcmp(name, "--rx-port") == 0) {
            if (port_seen || !parse_port(value, options.port))
                return false;
            port_seen = true;
        } else if (std::strcmp(name, "--expected-packets") == 0) {
            if (expected_seen || !parse_u32(value, options.expected_packets))
                return false;
            expected_seen = true;
        } else if (std::strcmp(name, "--trace-timestamp-sidecar") == 0) {
            if (!set_once(options.sidecar_path, value))
                return false;
        } else if (std::strcmp(
                       name, "--trace-timestamp-sidecar-sha256") == 0) {
            if (!set_once(options.sidecar_sha256, value))
                return false;
        } else if (std::strcmp(name, "--maximum-captured-length") == 0) {
            if (maximum_length_seen || !parse_u16(
                    value, options.maximum_captured_length) ||
                options.maximum_captured_length <
                    FK_TRACE_TRANSPORT_L2_BYTES ||
                options.maximum_captured_length >
                    UINT16_MAX - FK_TRACE_TRANSPORT_SHIM_BYTES)
                return false;
            maximum_length_seen = true;
        } else if (std::strcmp(name, "--expected-wire-source-mac") == 0) {
            if (options.expected_wire_source_mac_set || !parse_unicast_mac(
                    value, options.expected_wire_source_mac))
                return false;
            options.expected_wire_source_mac_set = true;
        } else if (std::strcmp(name, "--expected-nic-device") == 0) {
            if (!set_once(options.expected_nic_device, value) ||
                value[0] == '\0')
                return false;
        } else if (std::strcmp(name, "--expected-nic-driver") == 0) {
            if (!set_once(options.expected_nic_driver, value) ||
                value[0] == '\0')
                return false;
        } else if (std::strcmp(name, "--action-model") == 0) {
            if (!set_once(options.action_model, value))
                return false;
        } else if (std::strcmp(name, "--value-model-v3-artifact") == 0) {
            if (!set_once(options.value_model_v3_artifact, value))
                return false;
        } else if (std::strcmp(
                       name, "--value-model-v3-artifact-sha") == 0) {
            if (!set_once(options.value_model_v3_artifact_sha, value))
                return false;
        } else if (std::strcmp(
                       name, "--value-model-v3-training-receipt-sha") == 0) {
            if (!set_once(
                    options.value_model_v3_training_receipt_sha, value))
                return false;
        } else if (std::strcmp(
                       name, "--value-model-v3-schema-sha") == 0) {
            if (!set_once(options.value_model_v3_schema_sha, value))
                return false;
        } else if (std::strcmp(
                       name, "--value-model-v3-action-domain-sha") == 0) {
            if (!set_once(options.value_model_v3_action_domain_sha, value))
                return false;
        } else if (std::strcmp(
                       name, "--value-model-v3-deadline-contract-sha") == 0) {
            if (!set_once(
                    options.value_model_v3_deadline_contract_sha, value))
                return false;
        } else if (std::strcmp(name, "--value-model-v3-role") == 0) {
            if (options.value_model_v3_role_seen ||
                std::strcmp(value, "flowkeep") != 0)
                return false;
            options.value_model_v3_role = FK_VALUE_MODEL_V3_FLOWKEEP;
            options.value_model_v3_role_seen = true;
        } else if (std::strcmp(name, "--detector-model") == 0) {
            if (!set_once(options.detector_model, value))
                return false;
        } else if (std::strcmp(name, "--detector-state-model-dir") == 0) {
            if (!set_once(options.detector_state_model_dir, value))
                return false;
        } else if (std::strcmp(name, "--action-schema") == 0) {
            if (!set_once(options.action_schema, value))
                return false;
        } else if (std::strcmp(name, "--detector-schema") == 0) {
            if (!set_once(options.detector_schema, value))
                return false;
        } else if (std::strcmp(name, "--aggregation-mode") == 0) {
            if (!set_once(options.aggregation_mode, value))
                return false;
        } else if (std::strcmp(name, "--aggregation-rule") == 0) {
            if (!set_once(options.aggregation_rule, value))
                return false;
        } else if (std::strcmp(
                       name, "--aggregation-threshold-profile") == 0) {
            if (!set_once(options.aggregation_threshold_profile, value))
                return false;
        } else if (std::strcmp(name, "--aggregation-threshold") == 0) {
            if (options.aggregation_threshold_seen ||
                !parse_probability(value, options.aggregation_threshold))
                return false;
            options.aggregation_threshold_seen = true;
        } else if (std::strcmp(
                       name, "--aggregation-contract-sha256") == 0) {
            if (!set_once(options.aggregation_contract_sha, value))
                return false;
        } else if (std::strcmp(
                       name, "--development-oof-receipt-sha256") == 0) {
            if (!set_once(options.development_oof_receipt_sha, value))
                return false;
        } else if (std::strcmp(
                       name, "--causal-event-calibrator-artifact") == 0) {
            if (!set_once(options.causal_event_calibrator_artifact, value))
                return false;
        } else if (std::strcmp(
                       name,
                       "--causal-event-calibrator-artifact-sha") == 0) {
            if (!set_once(
                    options.causal_event_calibrator_artifact_sha, value))
                return false;
        } else if (std::strcmp(
                       name,
                       "--causal-event-calibrator-source-npz-sha") == 0) {
            if (!set_once(
                    options.causal_event_calibrator_source_npz_sha, value))
                return false;
        } else if (std::strcmp(
                       name,
                       "--causal-event-calibrator-feature-contract-sha") ==
                   0) {
            if (!set_once(
                    options.causal_event_calibrator_feature_contract_sha,
                    value))
                return false;
        } else if (std::strcmp(
                       name,
                       "--causal-event-calibrator-real-prefix-receipt-sha") ==
                   0) {
            if (!set_once(
                    options.causal_event_calibrator_real_prefix_receipt_sha,
                    value))
                return false;
        } else if (std::strcmp(name, "--event-student-artifact") == 0) {
            if (!set_once(options.event_student_artifact, value))
                return false;
        } else if (std::strcmp(
                       name, "--event-student-artifact-sha") == 0) {
            if (!set_once(options.event_student_artifact_sha, value))
                return false;
        } else if (std::strcmp(
                       name, "--event-student-feature-schema-sha") == 0) {
            if (!set_once(
                    options.event_student_feature_schema_sha, value))
                return false;
        } else if (std::strcmp(
                       name, "--event-student-source-state-sha") == 0) {
            if (!set_once(options.event_student_source_state_sha, value))
                return false;
        } else if (std::strcmp(name, "--event-student-hidden") == 0) {
            if (event_hidden_seen ||
                !parse_u32(value, options.event_student_hidden) ||
                options.event_student_hidden >
                    FK_EVENT_STUDENT_MAX_HIDDEN)
                return false;
            event_hidden_seen = true;
        } else if (std::strcmp(
                       name, "--event-student-identity-embedding") == 0) {
            if (event_embedding_seen ||
                !parse_u32(
                    value, options.event_student_identity_embedding) ||
                options.event_student_identity_embedding >
                    FK_EVENT_STUDENT_MAX_IDENTITY_EMBEDDING)
                return false;
            event_embedding_seen = true;
        } else if (std::strcmp(name, "--monitored-cidr") == 0) {
            if (!set_once(options.monitored_cidr, value))
                return false;
        } else if (std::strcmp(name, "--output") == 0) {
            if (!set_once(options.output, value))
                return false;
        } else if (std::strcmp(name, "--decision-trace") == 0) {
            if (!set_once(options.decision_trace, value))
                return false;
        } else if (std::strcmp(
                       name, "--decision-trace-features") == 0) {
            if (!set_once(options.decision_trace_features, value))
                return false;
        } else if (std::strcmp(name, "--maximum-flows") == 0) {
            if (flows_seen || !parse_u32(value, options.maximum_flows) ||
                options.maximum_flows > UINT16_MAX)
                return false;
            flows_seen = true;
        } else if (std::strcmp(
                       name, "--maximum-quic-connections") == 0) {
            if (quic_connections_seen ||
                !parse_u32(value, options.maximum_quic_connections) ||
                options.maximum_quic_connections > UINT16_MAX) {
                return false;
            }
            quic_connections_seen = true;
        } else if (std::strcmp(name, "--burst") == 0) {
            if (burst_seen || !parse_u16(value, options.burst) ||
                options.burst > FK_DPDK_EXACT_RX_PRODUCER_PUMP_MAX_BURST)
                return false;
            burst_seen = true;
        } else if (std::strcmp(name, "--idle-timeout-ms") == 0) {
            if (idle_seen || !parse_u32(value, options.idle_timeout_ms))
                return false;
            idle_seen = true;
        } else if (std::strcmp(name, "--pool-weights") == 0) {
            if (options.pool_weights_seen ||
                !parse_pool_weights(value, options.pool_weights))
                return false;
            options.pool_weights_seen = true;
        } else if (std::strcmp(name, "--retention-policy") == 0) {
            fk_compact_retention_policy_kind parsed_policy =
                FK_COMPACT_POLICY_FLOWKEEP;
            if (options.retention_policy_seen ||
                !fk_compact_retention_policy_parse(value, &parsed_policy))
                return false;
            options.retention_policy_seen = true;
            options.retention_policy_name = value;
            options.retention_policy = parsed_policy;
        } else if (std::strcmp(name, "--fixed-ttl-ns") == 0) {
            if (!fk_fixed_ttl_retention_parse_ns_once(
                    value, &options.fixed_ttl_retention)) {
                return false;
            }
        } else if (std::strcmp(name, "--budget") == 0) {
            if (budget_seen)
                return false;
            budget_seen = true;
            options.budget_name = value;
            if (std::strcmp(value, "16") == 0) {
                options.budget =
                    FK_NO_NIC_FULL_COMPOSITION_BUDGET_16_MIB;
            } else if (std::strcmp(value, "32") == 0) {
                options.budget =
                    FK_NO_NIC_FULL_COMPOSITION_BUDGET_32_MIB;
            } else if (std::strcmp(value, "64") == 0) {
                options.budget =
                    FK_NO_NIC_FULL_COMPOSITION_BUDGET_64_MIB;
            } else if (std::strcmp(value, "unlimited") == 0) {
                options.budget =
                    FK_NO_NIC_FULL_COMPOSITION_BUDGET_UNLIMITED_FULL_STATE;
            } else {
                return false;
            }
        } else {
            return false;
        }
    }
    const bool no_event_student =
        options.event_student_artifact == nullptr &&
        options.event_student_artifact_sha == nullptr &&
        options.event_student_feature_schema_sha == nullptr &&
        options.event_student_source_state_sha == nullptr &&
        !event_hidden_seen && !event_embedding_seen;
    const bool complete_event_student =
        options.event_student_artifact != nullptr &&
        valid_sha256(options.event_student_artifact_sha) &&
        valid_sha256(options.event_student_feature_schema_sha) &&
        valid_sha256(options.event_student_source_state_sha) &&
        event_hidden_seen && event_embedding_seen;
    const bool no_frozen_aggregation =
        options.aggregation_mode == nullptr &&
        options.aggregation_rule == nullptr &&
        options.aggregation_threshold_profile == nullptr &&
        options.aggregation_contract_sha == nullptr &&
        options.development_oof_receipt_sha == nullptr &&
        options.causal_event_calibrator_artifact == nullptr &&
        options.causal_event_calibrator_artifact_sha == nullptr &&
        options.causal_event_calibrator_source_npz_sha == nullptr &&
        options.causal_event_calibrator_feature_contract_sha == nullptr &&
        options.causal_event_calibrator_real_prefix_receipt_sha == nullptr &&
        !options.aggregation_threshold_seen;
    const bool no_causal_calibrator =
        options.causal_event_calibrator_artifact == nullptr &&
        options.causal_event_calibrator_artifact_sha == nullptr &&
        options.causal_event_calibrator_source_npz_sha == nullptr &&
        options.causal_event_calibrator_feature_contract_sha == nullptr &&
        options.causal_event_calibrator_real_prefix_receipt_sha == nullptr;
    const bool complete_causal_calibrator =
        options.causal_event_calibrator_artifact != nullptr &&
        options.causal_event_calibrator_artifact[0] != '\0' &&
        valid_sha256(options.causal_event_calibrator_artifact_sha) &&
        valid_sha256(options.causal_event_calibrator_source_npz_sha) &&
        valid_sha256(options.causal_event_calibrator_feature_contract_sha) &&
        valid_sha256(
            options.causal_event_calibrator_real_prefix_receipt_sha);
    const bool complete_frozen_aggregation_common =
        options.aggregation_mode != nullptr &&
        std::strcmp(options.aggregation_mode, "frozen_cpp_causal") == 0 &&
        options.aggregation_rule != nullptr &&
        options.aggregation_threshold_profile != nullptr &&
        options.aggregation_threshold_profile[0] != '\0' &&
        std::strlen(options.aggregation_threshold_profile) <
            FK_NO_NIC_FROZEN_CAUSAL_TEXT_BYTES &&
        options.aggregation_threshold_seen &&
        valid_sha256(options.aggregation_contract_sha) &&
        valid_sha256(options.development_oof_receipt_sha);
    const bool complete_frozen_aggregation =
        complete_frozen_aggregation_common &&
        ((no_causal_calibrator &&
          std::strcmp(options.aggregation_rule, "max") == 0) ||
         (complete_causal_calibrator &&
          std::strcmp(
              options.aggregation_rule,
              "causal_event_calibrator_max") == 0));
    fk_actor_session_config actor_check{};
    fk_actor_session_config_init(&actor_check);
    const bool cidr_valid = options.monitored_cidr == nullptr ||
        fk_actor_session_config_add_cidr_text(
            &actor_check, options.monitored_cidr);
    const bool no_value_v3 =
        options.value_model_v3_artifact == nullptr &&
        options.value_model_v3_artifact_sha == nullptr &&
        options.value_model_v3_training_receipt_sha == nullptr &&
        options.value_model_v3_schema_sha == nullptr &&
        options.value_model_v3_action_domain_sha == nullptr &&
        options.value_model_v3_deadline_contract_sha == nullptr &&
        !options.value_model_v3_role_seen;
    const bool complete_value_v3 =
        options.value_model_v3_artifact != nullptr &&
        valid_sha256(options.value_model_v3_artifact_sha) &&
        valid_sha256(options.value_model_v3_training_receipt_sha) &&
        valid_sha256(options.value_model_v3_schema_sha) &&
        valid_sha256(options.value_model_v3_action_domain_sha) &&
        valid_sha256(options.value_model_v3_deadline_contract_sha) &&
        options.value_model_v3_role_seen;
    const char *action_path = resolved_action_model(options);
    return port_seen && expected_seen && maximum_length_seen &&
        quic_connections_seen &&
        options.maximum_quic_connections <= options.maximum_flows &&
        options.expected_wire_source_mac_set && budget_seen &&
        fk_fixed_ttl_retention_binding_valid(
            options.retention_policy,
            &options.fixed_ttl_retention) &&
        options.sidecar_path != nullptr && action_path != nullptr &&
        (options.sidecar_sha256 == nullptr ||
         valid_sha256(options.sidecar_sha256)) &&
        (!options.require_quic_identity_proof ||
         valid_sha256(options.sidecar_sha256)) &&
        ((options.expected_nic_device == nullptr) ==
         (options.expected_nic_driver == nullptr)) &&
        (!options.require_quic_identity_proof ||
         (options.expected_nic_device != nullptr &&
          options.expected_nic_driver != nullptr)) &&
        ((options.action_model != nullptr) != complete_value_v3) &&
        (no_value_v3 || complete_value_v3) &&
        ((options.detector_model != nullptr) !=
         (options.detector_state_model_dir != nullptr)) &&
        options.action_schema != nullptr &&
        options.detector_schema != nullptr && options.output != nullptr &&
        std::strcmp(options.output, "-") != 0 &&
        valid_sha256(options.action_schema) &&
        valid_sha256(options.detector_schema) &&
        !existing_files_alias(options.output, options.sidecar_path) &&
        !existing_files_alias(options.output, action_path) &&
        (options.detector_model == nullptr ||
         !existing_files_alias(options.output, options.detector_model)) &&
        (options.decision_trace == nullptr ||
         (std::strcmp(options.decision_trace, options.output) != 0 &&
          std::strcmp(options.decision_trace, options.sidecar_path) != 0 &&
          std::strcmp(options.decision_trace, action_path) != 0 &&
          (options.detector_model == nullptr ||
           std::strcmp(options.decision_trace, options.detector_model) != 0))) &&
        (options.decision_trace_features == nullptr ||
         (options.decision_trace != nullptr &&
          options.decision_trace_features[0] != '\0' &&
          std::strcmp(
              options.decision_trace_features, options.decision_trace) != 0 &&
          std::strcmp(options.decision_trace_features, options.output) != 0 &&
          std::strcmp(
              options.decision_trace_features, options.sidecar_path) != 0 &&
          std::strcmp(
              options.decision_trace_features, action_path) != 0 &&
          (options.detector_model == nullptr ||
           std::strcmp(
               options.decision_trace_features,
               options.detector_model) != 0) &&
          (options.event_student_artifact == nullptr ||
           std::strcmp(
               options.decision_trace_features,
               options.event_student_artifact) != 0))) &&
        ((complete_frozen_aggregation && no_event_student) ||
         (no_frozen_aggregation &&
          (no_event_student || complete_event_student))) && cidr_valid &&
        (options.event_student_artifact == nullptr ||
         !existing_files_alias(
             options.output, options.event_student_artifact));
}

void json_string(FILE *stream, const char *text) {
    std::fputc('"', stream);
    if (text != nullptr) {
        for (const unsigned char *cursor =
                 reinterpret_cast<const unsigned char *>(text);
             *cursor != 0u; ++cursor) {
            const unsigned char value = *cursor;
            if (value == '"' || value == '\\') {
                std::fputc('\\', stream);
                std::fputc(value, stream);
            } else if (value == '\n') {
                std::fputs("\\n", stream);
            } else if (value == '\r') {
                std::fputs("\\r", stream);
            } else if (value == '\t') {
                std::fputs("\\t", stream);
            } else if (value < 0x20u) {
                std::fprintf(stream, "\\u%04x", value);
            } else {
                std::fputc(value, stream);
            }
        }
    }
    std::fputc('"', stream);
}

bool sha256_file(
        const char *path,
        std::array<uint8_t, kSha256Bytes> &digest) {
    if (path == nullptr || *path == '\0')
        return false;
    FILE *stream = std::fopen(path, "rb");
    EVP_MD_CTX *context = EVP_MD_CTX_new();
    if (stream == nullptr || context == nullptr) {
        if (stream != nullptr)
            (void)std::fclose(stream);
        EVP_MD_CTX_free(context);
        return false;
    }
    bool valid = EVP_DigestInit_ex(context, EVP_sha256(), nullptr) == 1;
    std::array<uint8_t, 1u << 16u> buffer{};
    while (valid) {
        const size_t count = std::fread(
            buffer.data(), 1u, buffer.size(), stream);
        if (count != 0u &&
            EVP_DigestUpdate(context, buffer.data(), count) != 1) {
            valid = false;
            break;
        }
        if (count < buffer.size()) {
            valid = std::feof(stream) != 0 && std::ferror(stream) == 0;
            break;
        }
    }
    unsigned int digest_bytes = 0u;
    if (valid) {
        valid = EVP_DigestFinal_ex(
            context, digest.data(), &digest_bytes) == 1 &&
            digest_bytes == digest.size();
    }
    EVP_MD_CTX_free(context);
    const bool closed = std::fclose(stream) == 0;
    return valid && closed;
}

bool sha256_bytes(
        const uint8_t *data,
        size_t bytes,
        std::array<uint8_t, kSha256Bytes> &digest) {
    if (data == nullptr || bytes == 0u)
        return false;
    unsigned int digest_bytes = 0u;
    return EVP_Digest(
               data,
               bytes,
               digest.data(),
               &digest_bytes,
               EVP_sha256(),
               nullptr) == 1 &&
        digest_bytes == digest.size();
}

bool sha256_matches_hex(
        const std::array<uint8_t, kSha256Bytes> &digest,
        const char *expected_hex) {
    if (!valid_sha256(expected_hex))
        return false;
    static constexpr char kHex[] = "0123456789abcdef";
    for (size_t index = 0u; index < digest.size(); ++index) {
        if (expected_hex[index * 2u] != kHex[digest[index] >> 4u] ||
            expected_hex[index * 2u + 1u] !=
                kHex[digest[index] & 0x0fu]) {
            return false;
        }
    }
    return true;
}

void write_sha256_hex(
        FILE *stream,
        const std::array<uint8_t, kSha256Bytes> &digest) {
    static constexpr char kHex[] = "0123456789abcdef";
    for (uint8_t value : digest) {
        std::fputc(kHex[value >> 4u], stream);
        std::fputc(kHex[value & 0x0fu], stream);
    }
}

void write_decision_trace_features(
        FILE *stream,
        const Options &options,
        const DecisionTraceFeaturesReceipt &receipt) {
    std::fputs(
        "  \"decision_trace_features\": {\n"
        "    \"protocol\": \"flowkeep-no-nic-decision-trace-features-v1\",\n"
        "    \"enabled\": ",
        stream);
    std::fputs(receipt.enabled ? "true" : "false", stream);
    std::fputs(",\n    \"path\": ", stream);
    if (options.decision_trace_features == nullptr)
        std::fputs("null", stream);
    else
        json_string(stream, options.decision_trace_features);
    std::fputs(",\n    \"sha256\": ", stream);
    if (!receipt.sha256_valid) {
        std::fputs("null", stream);
    } else {
        std::fputc('"', stream);
        write_sha256_hex(stream, receipt.sha256);
        std::fputc('"', stream);
    }
    std::fprintf(
        stream,
        ",\n    \"rows\": %" PRIu64 ",\n"
        "    \"feature_count\": %u,\n"
        "    \"checkpoint_rows_conserved\": %s\n"
        "  },\n",
        receipt.rows,
        FK_NO_NIC_DECISION_TRACE_DETECTOR_FEATURES,
        receipt.row_conservation_valid ? "true" : "false");
}

bool counter_delta(uint64_t before, uint64_t after, uint64_t &delta) {
    if (after < before) {
        delta = 0u;
        return false;
    }
    delta = after - before;
    return true;
}

void finalize_nic_receipt(NicReceipt &receipt) {
    if (!receipt.baseline_valid || !receipt.end_valid)
        return;
    bool valid = true;
    valid = counter_delta(
        receipt.baseline.ipackets, receipt.end.ipackets,
        receipt.delta.ipackets) && valid;
    valid = counter_delta(
        receipt.baseline.ibytes, receipt.end.ibytes,
        receipt.delta.ibytes) && valid;
    valid = counter_delta(
        receipt.baseline.imissed, receipt.end.imissed,
        receipt.delta.imissed) && valid;
    valid = counter_delta(
        receipt.baseline.ierrors, receipt.end.ierrors,
        receipt.delta.ierrors) && valid;
    valid = counter_delta(
        receipt.baseline.rx_nombuf, receipt.end.rx_nombuf,
        receipt.delta.rx_nombuf) && valid;
    receipt.counters_monotonic = valid;
    receipt.rx_dropped_packets_monotonic =
        receipt.rx_dropped_packets_baseline_valid &&
        receipt.rx_dropped_packets_end_valid &&
        counter_delta(
            receipt.rx_dropped_packets_baseline,
            receipt.rx_dropped_packets_end,
            receipt.rx_dropped_packets_delta);
}

class LiveSource {
public:
    struct TrackSlot {
        rte_mbuf *packet = nullptr;
        uint64_t packet_sequence = 0u;
        uint16_t wire_length = 0u;
        uint8_t state = 0u;  // 0 empty, 1 live, 2 tombstone
        uint8_t reserved[5]{};
    };

    LiveSource(
            uint16_t port,
            uint32_t expected,
            uint16_t maximum_captured_length,
            uint32_t idle_timeout_ms,
            const fk_trace_sidecar *sidecar,
            const rte_ether_addr &wire_source,
            const rte_ether_addr &wire_destination)
        : port_(port), expected_(expected),
          maximum_captured_length_(maximum_captured_length),
          sidecar_(sidecar),
          idle_timeout_ns_(static_cast<uint64_t>(idle_timeout_ms) *
              UINT64_C(1000000)),
          wire_source_(wire_source), wire_destination_(wire_destination) {
        last_progress_ns_ = monotonic_ns();
    }

    static bool burst_callback(
            void *context,
            uint16_t port,
            uint16_t queue,
            rte_mbuf **packets,
            uint16_t capacity,
            uint16_t *received) {
        if (context == nullptr)
            return false;
        return static_cast<LiveSource *>(context)->burst(
            port, queue, packets, capacity, received);
    }

    static bool clock_callback(void *context, uint64_t *now_ns) {
        if (context == nullptr || now_ns == nullptr)
            return false;
        const uint64_t now = monotonic_ns();
        if (now == 0u)
            return false;
        *now_ns = now;
        return true;
    }

    static bool decode_callback(
            void *context,
            const rte_mbuf *packet,
            uint16_t producer_index,
            uint64_t,
            uint64_t *packet_sequence,
            uint64_t *semantic_timestamp_ns,
            uint32_t *wire_length) {
        if (context == nullptr)
            return false;
        return static_cast<LiveSource *>(context)->decode(
            packet, producer_index, packet_sequence,
            semantic_timestamp_ns, wire_length);
    }

    static bool reclaim_callback(void *context, rte_mbuf *packet) {
        if (context == nullptr)
            return false;
        return static_cast<LiveSource *>(context)->reclaim(packet);
    }

    static bool stats_callback(
            void *context,
            fk_no_nic_full_composition_io_stats_v1 *stats) {
        if (context == nullptr || stats == nullptr)
            return false;
        return static_cast<LiveSource *>(context)->stats(*stats);
    }

    uint64_t decode_failures() const { return decode_failures_; }
    uint64_t tracking_failures() const { return tracking_failures_; }
    uint64_t peak_live() const { return peak_live_; }
    uint64_t filtered_packets() const { return filtered_packets_; }
    uint64_t filtered_wire_bytes() const { return filtered_wire_bytes_; }
    uint64_t acquired() const { return acquired_; }
    uint64_t restored_packets() const { return restored_packets_; }
    uint64_t restored_bytes() const { return restored_bytes_; }
    uint64_t crc_verified_packets() const { return crc_verified_packets_; }
    uint64_t invalid_shim_packets() const { return invalid_shim_packets_; }
    uint64_t shim_magic_failures() const { return shim_magic_failures_; }
    uint64_t shim_length_failures() const { return shim_length_failures_; }
    uint64_t shim_crc_failures() const { return shim_crc_failures_; }
    uint64_t shim_sequence_failures() const {
        return shim_sequence_failures_;
    }
    uint64_t shim_shape_failures() const { return shim_shape_failures_; }
    uint64_t envelope_mac_mismatches() const {
        return envelope_mac_mismatches_;
    }

    uint64_t recover_after_failure() {
        uint64_t recovered = 0u;
        for (TrackSlot &slot : tracking_) {
            if (slot.state != 1u || slot.packet == nullptr)
                continue;
            rte_pktmbuf_free(slot.packet);
            slot.packet = nullptr;
            slot.packet_sequence = 0u;
            slot.wire_length = 0u;
            slot.state = 2u;
            ++recovered;
        }
        if (recovered <= live_)
            live_ -= recovered;
        else
            live_ = 0u;
        forced_reclaims_ += recovered;
        return recovered;
    }

private:
    static size_t hash_packet(const rte_mbuf *packet) {
        uint64_t value = static_cast<uint64_t>(
            reinterpret_cast<uintptr_t>(packet) >> 6u);
        value *= UINT64_C(11400714819323198485);
        return static_cast<size_t>(value) & (kTrackCapacity - 1u);
    }

    bool insert(rte_mbuf *packet, uint64_t sequence, uint16_t wire_length) {
        const size_t start = hash_packet(packet);
        size_t first_tombstone = kTrackCapacity;
        for (size_t probe = 0u; probe < kTrackCapacity; ++probe) {
            const size_t index = (start + probe) & (kTrackCapacity - 1u);
            TrackSlot &slot = tracking_[index];
            if (slot.state == 1u && slot.packet == packet)
                return false;
            if (slot.state == 2u && first_tombstone == kTrackCapacity)
                first_tombstone = index;
            if (slot.state != 0u)
                continue;
            const size_t target = first_tombstone == kTrackCapacity
                ? index : first_tombstone;
            tracking_[target].packet = packet;
            tracking_[target].packet_sequence = sequence;
            tracking_[target].wire_length = wire_length;
            tracking_[target].state = 1u;
            ++live_;
            if (live_ > peak_live_)
                peak_live_ = live_;
            return true;
        }
        if (first_tombstone != kTrackCapacity) {
            tracking_[first_tombstone].packet = packet;
            tracking_[first_tombstone].packet_sequence = sequence;
            tracking_[first_tombstone].wire_length = wire_length;
            tracking_[first_tombstone].state = 1u;
            ++live_;
            if (live_ > peak_live_)
                peak_live_ = live_;
            return true;
        }
        return false;
    }

    bool lookup(
            const rte_mbuf *packet,
            uint64_t &sequence,
            uint16_t &wire_length) const {
        const size_t start = hash_packet(packet);
        for (size_t probe = 0u; probe < kTrackCapacity; ++probe) {
            const size_t index = (start + probe) & (kTrackCapacity - 1u);
            const TrackSlot &slot = tracking_[index];
            if (slot.state == 0u)
                return false;
            if (slot.state == 1u && slot.packet == packet) {
                sequence = slot.packet_sequence;
                wire_length = slot.wire_length;
                return true;
            }
        }
        return false;
    }

    bool erase(rte_mbuf *packet) {
        const size_t start = hash_packet(packet);
        for (size_t probe = 0u; probe < kTrackCapacity; ++probe) {
            const size_t index = (start + probe) & (kTrackCapacity - 1u);
            TrackSlot &slot = tracking_[index];
            if (slot.state == 0u)
                return false;
            if (slot.state == 1u && slot.packet == packet) {
                slot.packet = nullptr;
                slot.packet_sequence = 0u;
                slot.wire_length = 0u;
                slot.state = 2u;
                if (live_ == 0u)
                    return false;
                --live_;
                return true;
            }
        }
        return false;
    }

    enum class EnvelopeStatus : uint8_t {
        Background = 0u,
        Accepted = 1u,
        Invalid = 2u,
    };

    EnvelopeStatus invalid_shim(uint64_t &specific_counter) {
        ++invalid_shim_packets_;
        ++specific_counter;
        return EnvelopeStatus::Invalid;
    }

    EnvelopeStatus restore_envelope(
            rte_mbuf *packet,
            uint64_t &sequence,
            uint16_t &wire_length) {
        sequence = 0u;
        wire_length = 0u;
        if (packet == nullptr)
            return invalid_shim(shim_shape_failures_);

        uint8_t ethernet[FK_TRACE_TRANSPORT_L2_BYTES]{};
        const void *header = rte_pktmbuf_read(
            packet, 0u, sizeof(ethernet), ethernet);
        if (header == nullptr)
            return EnvelopeStatus::Background;
        const auto *wire_l2 = static_cast<const uint8_t *>(header);
        const bool destination_matches = std::memcmp(
            wire_l2,
            wire_destination_.addr_bytes,
            RTE_ETHER_ADDR_LEN) == 0;
        const bool source_matches = std::memcmp(
            wire_l2 + RTE_ETHER_ADDR_LEN,
            wire_source_.addr_bytes,
            RTE_ETHER_ADDR_LEN) == 0;
        if (!destination_matches || !source_matches) {
            if (destination_matches != source_matches)
                ++envelope_mac_mismatches_;
            return EnvelopeStatus::Background;
        }

        const uint32_t envelope_length = rte_pktmbuf_pkt_len(packet);
        if (packet->nb_segs != 1u || packet->next != nullptr ||
            !RTE_MBUF_DIRECT(packet) || rte_mbuf_refcnt_read(packet) != 1u ||
            packet->buf_addr == nullptr ||
            packet->data_off > packet->buf_len ||
            packet->data_len >
                static_cast<uint32_t>(packet->buf_len - packet->data_off) ||
            envelope_length != rte_pktmbuf_data_len(packet) ||
            envelope_length <
                FK_TRACE_TRANSPORT_L2_BYTES +
                    FK_TRACE_TRANSPORT_SHIM_BYTES ||
            envelope_length >
                static_cast<uint32_t>(maximum_captured_length_) +
                    FK_TRACE_TRANSPORT_SHIM_BYTES) {
            return invalid_shim(shim_shape_failures_);
        }
        auto *frame = rte_pktmbuf_mtod(packet, uint8_t *);
        if (frame == nullptr)
            return invalid_shim(shim_shape_failures_);

        fk_trace_transport_shim_v1 shim{};
        std::memcpy(
            &shim,
            frame + envelope_length - FK_TRACE_TRANSPORT_SHIM_BYTES,
            sizeof(shim));
        fk_trace_transport_decoded_v1 decoded{};
        const fk_trace_transport_shim_status parse_status =
            fk_trace_transport_shim_parse_v1(
                &shim, envelope_length, &decoded);
        if (parse_status != FK_TRACE_TRANSPORT_SHIM_OK) {
            if (parse_status == FK_TRACE_TRANSPORT_SHIM_MAGIC_VERSION)
                return invalid_shim(shim_magic_failures_);
            if (parse_status == FK_TRACE_TRANSPORT_SHIM_CAPTURED_LENGTH ||
                parse_status == FK_TRACE_TRANSPORT_SHIM_WIRE_LENGTH ||
                parse_status == FK_TRACE_TRANSPORT_SHIM_ENVELOPE_LENGTH)
                return invalid_shim(shim_length_failures_);
            return invalid_shim(shim_shape_failures_);
        }
        if (decoded.captured_length > maximum_captured_length_)
            return invalid_shim(shim_length_failures_);
        if (decoded.packet_sequence >= expected_ ||
            decoded.packet_sequence != next_sequence_) {
            return invalid_shim(shim_sequence_failures_);
        }

        std::memcpy(frame, decoded.original_l2, sizeof(decoded.original_l2));
        const fk_trace_transport_shim_status crc_status =
            fk_trace_transport_shim_verify_crc_v1(
                &shim, frame, decoded.captured_length);
        if (crc_status != FK_TRACE_TRANSPORT_SHIM_OK)
            return invalid_shim(shim_crc_failures_);
        if (rte_pktmbuf_trim(packet, FK_TRACE_TRANSPORT_SHIM_BYTES) != 0 ||
            rte_pktmbuf_pkt_len(packet) != decoded.captured_length ||
            rte_pktmbuf_data_len(packet) != decoded.captured_length) {
            return invalid_shim(shim_shape_failures_);
        }
        sequence = decoded.packet_sequence;
        wire_length = decoded.wire_length;
        ++crc_verified_packets_;
        ++next_sequence_;
        ++restored_packets_;
        restored_bytes_ += decoded.captured_length;
        return EnvelopeStatus::Accepted;
    }

    bool burst(
            uint16_t port,
            uint16_t queue,
            rte_mbuf **packets,
            uint16_t capacity,
            uint16_t *received) {
        if (received != nullptr)
            *received = 0u;
        if (port != port_ || queue != 0u || packets == nullptr ||
            received == nullptr || capacity == 0u || source_failed_)
            return false;
        if (acquired_ == expected_)
            return true;
        /*
         * Keep the NIC request vector-sized even for the final partial
         * logical burst.  i40e vector RX may return zero indefinitely when
         * nb_pkts is reduced to a non-vector tail (for example 7 after
         * receiving 93/100).  The exact sequence gate below still prevents
         * accepting more than expected_.
         */
        const uint16_t bounded = capacity;
        std::array<
            rte_mbuf *, FK_DPDK_EXACT_RX_PRODUCER_PUMP_MAX_BURST> raw{};
        std::array<
            uint64_t, FK_DPDK_EXACT_RX_PRODUCER_PUMP_MAX_BURST> sequences{};
        std::array<
            uint16_t, FK_DPDK_EXACT_RX_PRODUCER_PUMP_MAX_BURST> wire_lengths{};
        uint16_t raw_count = 0u;
        if (!fk_dpdk_exact_rx_producer_rte_eth_rx_burst(
                nullptr, port, queue, raw.data(), bounded, &raw_count)) {
            source_failed_ = true;
            return false;
        }
        uint16_t count = 0u;
        for (uint16_t index = 0u; index < raw_count; ++index) {
            rte_mbuf *packet = raw[index];
            uint64_t sequence = 0u;
            uint16_t wire_length = 0u;
            const EnvelopeStatus status = restore_envelope(
                packet, sequence, wire_length);
            if (status == EnvelopeStatus::Accepted) {
                packets[count++] = packet;
                sequences[count - 1u] = sequence;
                wire_lengths[count - 1u] = wire_length;
                continue;
            }
            if (status == EnvelopeStatus::Invalid) {
                for (uint16_t accepted = 0u; accepted < count; ++accepted)
                    rte_pktmbuf_free(packets[accepted]);
                for (uint16_t pending = index; pending < raw_count; ++pending) {
                    if (raw[pending] != nullptr)
                        rte_pktmbuf_free(raw[pending]);
                }
                source_failed_ = true;
                return true;
            }
            const uint64_t length = packet == nullptr
                ? 0u : static_cast<uint64_t>(rte_pktmbuf_pkt_len(packet));
            if (filtered_packets_ == std::numeric_limits<uint64_t>::max() ||
                !add_u64(filtered_wire_bytes_, length)) {
                if (packet != nullptr)
                    rte_pktmbuf_free(packet);
                for (uint16_t accepted = 0u; accepted < count; ++accepted)
                    rte_pktmbuf_free(packets[accepted]);
                for (uint16_t pending = index + 1u;
                     pending < raw_count; ++pending) {
                    if (raw[pending] != nullptr)
                        rte_pktmbuf_free(raw[pending]);
                }
                source_failed_ = true;
                return true;
            }
            ++filtered_packets_;
            if (packet != nullptr)
                rte_pktmbuf_free(packet);
        }
        if (count == 0u) {
            const uint64_t now = monotonic_ns();
            if (now == 0u || now < last_progress_ns_ ||
                now - last_progress_ns_ >= idle_timeout_ns_) {
                source_failed_ = true;
            }
            return true;
        }
        uint64_t burst_bytes = 0u;
        for (uint16_t index = 0u; index < count; ++index)
            burst_bytes += wire_lengths[index];
        uint16_t inserted = 0u;
        for (; inserted < count; ++inserted) {
            if (packets[inserted] == nullptr || !insert(
                    packets[inserted],
                    sequences[inserted],
                    wire_lengths[inserted]))
                break;
        }
        if (inserted != count) {
            ++tracking_failures_;
            for (uint16_t index = 0u; index < count; ++index) {
                if (index < inserted)
                    (void)erase(packets[index]);
                if (packets[index] != nullptr)
                    rte_pktmbuf_free(packets[index]);
            }
            source_failed_ = true;
            return true;
        }
        if (!add_u64(acquired_, count) ||
            !add_u64(acquired_wire_bytes_, burst_bytes)) {
            source_failed_ = true;
            return true;
        }
        last_progress_ns_ = monotonic_ns();
        *received = count;
        return true;
    }

    bool decode(
            const rte_mbuf *packet,
            uint16_t producer_index,
            uint64_t *packet_sequence,
            uint64_t *semantic_timestamp_ns,
            uint32_t *wire_length) {
        if (packet == nullptr || producer_index != 0u ||
            packet_sequence == nullptr || semantic_timestamp_ns == nullptr ||
            wire_length == nullptr || sidecar_ == nullptr) {
            ++decode_failures_;
            source_failed_ = true;
            return false;
        }
        uint64_t sequence = 0u;
        uint16_t tracked_wire_length = 0u;
        uint64_t semantic = 0u;
        const uint32_t captured_length = rte_pktmbuf_pkt_len(packet);
        if (!lookup(packet, sequence, tracked_wire_length) ||
            sequence >= expected_ || captured_length == 0u ||
            captured_length > maximum_captured_length_ ||
            tracked_wire_length < captured_length ||
            !fk_trace_sidecar_timestamp(sidecar_, sequence, &semantic)) {
            ++decode_failures_;
            source_failed_ = true;
            return false;
        }
        *packet_sequence = sequence;
        *semantic_timestamp_ns = semantic;
        *wire_length = tracked_wire_length;
        return true;
    }

    bool reclaim(rte_mbuf *packet) {
        ++reclaim_attempts_;
        if (packet == nullptr || !erase(packet)) {
            ++duplicate_reclaims_;
            return false;
        }
        rte_pktmbuf_free(packet);
        ++reclaim_successes_;
        return true;
    }

    bool stats(fk_no_nic_full_composition_io_stats_v1 &output) const {
        output = {};
        output.acquired_packets = acquired_;
        output.acquired_wire_bytes = acquired_wire_bytes_;
        output.reclaim_attempts = reclaim_attempts_;
        output.reclaim_successes = reclaim_successes_;
        output.duplicate_reclaims = duplicate_reclaims_;
        output.live_mbufs = live_;
        output.forced_failure_reclaims = forced_reclaims_;
        output.bounded_source_reserved_bytes = sizeof(tracking_);
        output.bounded_source_peak_bytes = sizeof(tracking_);
        output.bounded_source_capacity = kTrackCapacity;
        output.source_exhausted = acquired_ == expected_ ? 1u : 0u;
        output.source_failed = source_failed_ ? 1u : 0u;
        output.accounting_conserved =
            duplicate_reclaims_ == 0u &&
            reclaim_successes_ + live_ + forced_reclaims_ == acquired_
                ? 1u : 0u;
        output.ownership_recovered = live_ == 0u ? 1u : 0u;
        output.bounded_source_memory_exact = 1u;
        output.bounded_source_trace_independent = 1u;
        return true;
    }

    uint16_t port_;
    uint32_t expected_;
    uint16_t maximum_captured_length_;
    const fk_trace_sidecar *sidecar_;
    uint64_t idle_timeout_ns_;
    rte_ether_addr wire_source_{};
    rte_ether_addr wire_destination_{};
    uint64_t last_progress_ns_ = 0u;
    std::array<TrackSlot, kTrackCapacity> tracking_{};
    uint64_t acquired_ = 0u;
    uint64_t acquired_wire_bytes_ = 0u;
    uint64_t reclaim_attempts_ = 0u;
    uint64_t reclaim_successes_ = 0u;
    uint64_t duplicate_reclaims_ = 0u;
    uint64_t forced_reclaims_ = 0u;
    uint64_t live_ = 0u;
    uint64_t peak_live_ = 0u;
    uint64_t decode_failures_ = 0u;
    uint64_t tracking_failures_ = 0u;
    uint64_t filtered_packets_ = 0u;
    uint64_t filtered_wire_bytes_ = 0u;
    uint64_t next_sequence_ = 0u;
    uint64_t restored_packets_ = 0u;
    uint64_t restored_bytes_ = 0u;
    uint64_t crc_verified_packets_ = 0u;
    uint64_t invalid_shim_packets_ = 0u;
    uint64_t shim_magic_failures_ = 0u;
    uint64_t shim_length_failures_ = 0u;
    uint64_t shim_crc_failures_ = 0u;
    uint64_t shim_sequence_failures_ = 0u;
    uint64_t shim_shape_failures_ = 0u;
    uint64_t envelope_mac_mismatches_ = 0u;
    bool source_failed_ = false;
};

uint64_t configured_budget_bytes(
        fk_no_nic_full_composition_budget_mode budget) {
    switch (budget) {
    case FK_NO_NIC_FULL_COMPOSITION_BUDGET_16_MIB:
        return UINT64_C(16) * 1024u * 1024u;
    case FK_NO_NIC_FULL_COMPOSITION_BUDGET_32_MIB:
        return UINT64_C(32) * 1024u * 1024u;
    case FK_NO_NIC_FULL_COMPOSITION_BUDGET_64_MIB:
        return UINT64_C(64) * 1024u * 1024u;
    case FK_NO_NIC_FULL_COMPOSITION_BUDGET_128_MIB:
        return UINT64_C(128) * 1024u * 1024u;
    case FK_NO_NIC_FULL_COMPOSITION_BUDGET_UNLIMITED_FULL_STATE:
        return 0u;
    }
    return 0u;
}

const char *json_bool(bool value) {
    return value ? "true" : "false";
}

void write_nic_receipt(
        FILE *stream,
        const Options &options,
        const NicReceipt &nic) {
    std::fprintf(
        stream,
        "  \"nic\": {\n"
        "    \"device_valid\": %s,\n"
        "    \"device_info_valid\": %s,\n"
        "    \"device_name\": ",
        json_bool(nic.device_valid),
        json_bool(nic.device_info_valid));
    if (!nic.device_info_valid)
        std::fputs("null", stream);
    else
        json_string(stream, nic.device_name.data());
    std::fputs(",\n    \"driver_name\": ", stream);
    if (!nic.device_info_valid)
        std::fputs("null", stream);
    else
        json_string(stream, nic.driver_name.data());
    std::fputs(",\n    \"expected_device_name\": ", stream);
    if (options.expected_nic_device == nullptr)
        std::fputs("null", stream);
    else
        json_string(stream, options.expected_nic_device);
    std::fputs(",\n    \"expected_driver_name\": ", stream);
    if (options.expected_nic_driver == nullptr)
        std::fputs("null", stream);
    else
        json_string(stream, options.expected_nic_driver);
    std::fprintf(
        stream,
        ",\n    \"device_identity_verified\": %s,\n"
        "    \"configured\": %s,\n"
        "    \"queue_ready\": %s,\n"
        "    \"started\": %s,\n"
        "    \"mac_valid\": %s,\n"
        "    \"mac\": \"%02x:%02x:%02x:%02x:%02x:%02x\",\n"
        "    \"start_link_valid\": %s,\n"
        "    \"start_link_up\": %s,\n"
        "    \"start_link_speed_mbps\": %u,\n"
        "    \"end_link_valid\": %s,\n"
        "    \"end_link_up\": %s,\n"
        "    \"end_link_speed_mbps\": %u,\n"
        "    \"promiscuous_enabled_during_run\": %s,\n"
        "    \"promiscuous_enable_status\": %d,\n"
        "    \"promiscuous_disable_status\": %d,\n"
        "    \"promiscuous_disabled_at_end\": %s,\n"
        "    \"baseline_valid\": %s,\n"
        "    \"end_valid\": %s,\n"
        "    \"counters_monotonic\": %s,\n"
        "    \"ipackets_delta\": %" PRIu64 ",\n"
        "    \"ibytes_delta\": %" PRIu64 ",\n"
        "    \"imissed_delta\": %" PRIu64 ",\n"
        "    \"ierrors_delta\": %" PRIu64 ",\n"
        "    \"rx_nombuf_delta\": %" PRIu64 ",\n"
        "    \"rx_dropped_packets_xstat\": {\"name\": "
        "\"rx_dropped_packets\", \"resolved\": %s, \"id\": %" PRIu64
        ", \"baseline_valid\": %s, \"end_valid\": %s, "
        "\"monotonic\": %s, \"baseline\": %" PRIu64
        ", \"end\": %" PRIu64 ", \"delta\": %" PRIu64 "},\n"
        "    \"mtu\": {\"original_status\": %d, "
        "\"original_valid\": %s, \"original\": %u, "
        "\"required\": %u, \"configure_status\": %d, "
        "\"changed\": %s, \"configured_status\": %d, "
        "\"configured_valid\": %s, \"configured\": %u, "
        "\"restore_status\": %d, \"restored_status\": %d, "
        "\"restored_value\": %u, \"restored\": %s},\n"
        "    \"stop_status\": %d,\n"
        "    \"stop_succeeded\": %s,\n"
        "    \"close_success_semantics\": \"status>=0\",\n"
        "    \"close_status\": %d,\n"
        "    \"close_succeeded\": %s\n  },\n",
        json_bool(nic.device_identity_verified),
        json_bool(nic.configured),
        json_bool(nic.queue_ready),
        json_bool(nic.started),
        json_bool(nic.mac_valid),
        nic.mac.addr_bytes[0], nic.mac.addr_bytes[1],
        nic.mac.addr_bytes[2], nic.mac.addr_bytes[3],
        nic.mac.addr_bytes[4], nic.mac.addr_bytes[5],
        json_bool(nic.start_link_valid),
        json_bool(nic.start_link.link_status != 0u),
        nic.start_link.link_speed,
        json_bool(nic.end_link_valid),
        json_bool(nic.end_link.link_status != 0u),
        nic.end_link.link_speed,
        json_bool(nic.promiscuous_enabled),
        nic.promiscuous_enable_status,
        nic.promiscuous_disable_status,
        json_bool(nic.promiscuous_disabled),
        json_bool(nic.baseline_valid),
        json_bool(nic.end_valid),
        json_bool(nic.counters_monotonic),
        nic.delta.ipackets, nic.delta.ibytes, nic.delta.imissed,
        nic.delta.ierrors, nic.delta.rx_nombuf,
        json_bool(nic.rx_dropped_packets_xstat_resolved),
        nic.rx_dropped_packets_xstat_id,
        json_bool(nic.rx_dropped_packets_baseline_valid),
        json_bool(nic.rx_dropped_packets_end_valid),
        json_bool(nic.rx_dropped_packets_monotonic),
        nic.rx_dropped_packets_baseline,
        nic.rx_dropped_packets_end,
        nic.rx_dropped_packets_delta,
        nic.original_mtu_status,
        json_bool(nic.original_mtu_valid),
        nic.original_mtu,
        nic.required_mtu,
        nic.configure_mtu_status,
        json_bool(nic.mtu_changed),
        nic.configured_mtu_status,
        json_bool(nic.configured_mtu_valid),
        nic.configured_mtu,
        nic.restore_mtu_status,
        nic.restored_mtu_status,
        nic.restored_mtu,
        json_bool(nic.mtu_restored),
        nic.stop_status,
        json_bool(nic.stop_succeeded),
        nic.close_status,
        json_bool(nic.close_succeeded));
}

void write_transport_receipt(
        FILE *stream,
        const Options &options,
        const NicReceipt &nic,
        const LiveSource *source) {
    const uint64_t restored = source == nullptr
        ? 0u : source->restored_packets();
    const uint64_t verified = source == nullptr
        ? 0u : source->crc_verified_packets();
    const uint64_t invalid = source == nullptr
        ? 0u : source->invalid_shim_packets();
    const bool exact = source != nullptr &&
        restored == options.expected_packets && verified == restored &&
        invalid == 0u;
    std::fputs(
        "  \"trace_timestamp_sidecar\": {\n"
        "    \"protocol\": \"FKTSV1\",\n"
        "    \"path\": ",
        stream);
    json_string(stream, options.sidecar_path);
    std::fputs(",\n    \"expected_whole_file_sha256\": ", stream);
    if (options.sidecar_sha256 == nullptr)
        std::fputs("null", stream);
    else
        json_string(stream, options.sidecar_sha256);
    std::fputs(",\n    \"observed_whole_file_sha256\": ", stream);
    if (!options.observed_sidecar_sha256_valid) {
        std::fputs("null", stream);
    } else {
        std::fputc('"', stream);
        write_sha256_hex(stream, options.observed_sidecar_sha256);
        std::fputc('"', stream);
    }
    std::fprintf(
        stream,
        ",\n    \"whole_file_sha256_verified\": %s\n  },\n",
        json_bool(options.sidecar_sha256_verified));
    std::fprintf(
        stream,
        "  \"transport_restore\": {\n"
        "    \"shim_version\": %u,\n"
        "    \"shim_bytes\": %u,\n"
        "    \"integer_byte_order\": \"network-big-endian\",\n"
        "    \"crc32c_scope\": \"shim[0:16]+restored_original_frame\",\n"
        "    \"expected_wire_source_mac\": " ,
        FK_TRACE_TRANSPORT_SHIM_VERSION,
        FK_TRACE_TRANSPORT_SHIM_BYTES);
    std::fprintf(
        stream,
        "\"%02x:%02x:%02x:%02x:%02x:%02x\",\n"
        "    \"expected_wire_destination_mac\": "
        "\"%02x:%02x:%02x:%02x:%02x:%02x\",\n"
        "    \"maximum_original_captured_length\": %u,\n"
        "    \"strict_sequence_validation\": true,\n"
        "    \"invalid_shim_fail_closed\": true,\n"
        "    \"hot_path_heap_allocations\": 0,\n"
        "    \"restored_packets\": %" PRIu64 ",\n"
        "    \"restored_original_bytes\": %" PRIu64 ",\n"
        "    \"crc_verified_packets\": %" PRIu64 ",\n"
        "    \"invalid_shim_packets\": %" PRIu64 ",\n"
        "    \"magic_version_failures\": %" PRIu64 ",\n"
        "    \"length_failures\": %" PRIu64 ",\n"
        "    \"crc_failures\": %" PRIu64 ",\n"
        "    \"sequence_failures\": %" PRIu64 ",\n"
        "    \"shape_failures\": %" PRIu64 ",\n"
        "    \"envelope_mac_mismatches_filtered\": %" PRIu64 ",\n"
        "    \"exact_original_byte_restoration_verified\": %s\n  },\n",
        options.expected_wire_source_mac.addr_bytes[0],
        options.expected_wire_source_mac.addr_bytes[1],
        options.expected_wire_source_mac.addr_bytes[2],
        options.expected_wire_source_mac.addr_bytes[3],
        options.expected_wire_source_mac.addr_bytes[4],
        options.expected_wire_source_mac.addr_bytes[5],
        nic.mac.addr_bytes[0], nic.mac.addr_bytes[1],
        nic.mac.addr_bytes[2], nic.mac.addr_bytes[3],
        nic.mac.addr_bytes[4], nic.mac.addr_bytes[5],
        options.maximum_captured_length,
        restored,
        source == nullptr ? 0u : source->restored_bytes(),
        verified,
        invalid,
        source == nullptr ? 0u : source->shim_magic_failures(),
        source == nullptr ? 0u : source->shim_length_failures(),
        source == nullptr ? 0u : source->shim_crc_failures(),
        source == nullptr ? 0u : source->shim_sequence_failures(),
        source == nullptr ? 0u : source->shim_shape_failures(),
        source == nullptr ? 0u : source->envelope_mac_mismatches(),
        json_bool(exact));
}

void write_service_memory_component(
        FILE *stream,
        const char *name,
        const fk_no_nic_service_memory_component_receipt_v1 &component,
        bool trailing_comma) {
    std::fputs("      {\"name\": ", stream);
    json_string(stream, name);
    std::fputs(", \"disposition\": ", stream);
    json_string(
        stream,
        fk_no_nic_service_memory_disposition_name_v1(
            component.disposition));
    std::fprintf(
        stream,
        ", \"configured_reserved_bytes\": %" PRIu64
        ", \"observed_reserved_bytes\": %" PRIu64
        ", \"peak_bytes\": %" PRIu64
        ", \"reservation_exact\": %s"
        ", \"trace_independent\": %s"
        ", \"bounded_window\": %s"
        ", \"hash_bound\": %s}%s\n",
        component.configured_reserved_bytes,
        component.observed_reserved_bytes,
        component.peak_bytes,
        json_bool(component.reservation_exact != 0u),
        json_bool(component.trace_independent != 0u),
        json_bool(component.bounded_window != 0u),
        json_bool(component.hash_bound != 0u),
        trailing_comma ? "," : "");
}

void write_service_memory_receipt(
        FILE *stream,
        const fk_no_nic_service_memory_receipt_v1 &receipt) {
    std::fputs(
        "  \"service_memory\": {\n"
        "    \"receipt_abi\": \"flowkeep.no_nic.service_memory.receipt.v1\",\n"
        "    \"receipt_sha256\": \"",
        stream);
    static constexpr char hex[] = "0123456789abcdef";
    for (uint8_t value : receipt.receipt_sha256) {
        std::fputc(hex[value >> 4u], stream);
        std::fputc(hex[value & 0x0fu], stream);
    }
    std::fprintf(
        stream,
        "\",\n"
        "    \"receipt_hash_valid\": %s,\n"
        "    \"trace_packet_count\": %" PRIu64 ",\n"
        "    \"bridge_epoch_packet_limit\": %" PRIu64 ",\n"
        "    \"completion_window_capacity\": %u,\n"
        "    \"configured_reserved_bytes\": %" PRIu64 ",\n"
        "    \"observed_reserved_bytes\": %" PRIu64 ",\n"
        "    \"peak_bytes\": %" PRIu64 ",\n"
        "    \"trace_sized_active_reserved_bytes\": %" PRIu64 ",\n"
        "    \"separate_from_controlled_state\": %s,\n"
        "    \"active_reservations_trace_independent\": %s,\n"
        "    \"completion_transport_window_bounded\": %s,\n"
        "    \"external_source_window_bounded\": %s,\n"
        "    \"finite_epoch_handoff_required\": %s,\n"
        "    \"formal_14_component_complete\": %s,\n"
        "    \"formal_non_active_component_mask\": %u,\n"
        "    \"components\": [\n",
        json_bool(fk_no_nic_service_memory_receipt_verify_v1(&receipt)),
        receipt.trace_packet_count,
        receipt.bridge_epoch_packet_limit,
        receipt.completion_window_capacity,
        receipt.total_configured_reserved_bytes,
        receipt.total_observed_reserved_bytes,
        receipt.total_peak_bytes,
        receipt.trace_sized_active_reserved_bytes,
        json_bool(
            receipt.service_memory_separate_from_controlled_state != 0u),
        json_bool(receipt.active_reservations_trace_independent != 0u),
        json_bool(receipt.completion_transport_window_bounded != 0u),
        json_bool(receipt.external_source_window_bounded != 0u),
        json_bool(receipt.finite_epoch_handoff_required != 0u),
        json_bool(receipt.formal_14_component_complete != 0u),
        receipt.formal_non_active_component_mask);
    for (uint32_t index = 0u;
         index < FK_IDENTITY_SERVICE_COMPONENT_COUNT; ++index) {
        write_service_memory_component(
            stream,
            fk_identity_pipeline_service_component_name(
                static_cast<fk_identity_pipeline_service_component>(index)),
            receipt.components[index],
            index + 1u != FK_IDENTITY_SERVICE_COMPONENT_COUNT);
    }
    std::fputs("    ],\n    \"auxiliary_components\": [\n", stream);
    for (uint32_t index = 0u;
         index < FK_NO_NIC_SERVICE_MEMORY_AUXILIARY_COMPONENT_COUNT;
         ++index) {
        write_service_memory_component(
            stream,
            fk_no_nic_service_memory_auxiliary_component_name_v1(index),
            receipt.auxiliary_components[index],
            index + 1u !=
                FK_NO_NIC_SERVICE_MEMORY_AUXILIARY_COMPONENT_COUNT);
    }
    std::fputs("    ]\n  },\n", stream);
}

void write_trigger_receipt(
        FILE *stream,
        const fk_no_nic_trigger_receipt_v2 &receipt) {
    std::fprintf(
        stream,
        "  \"event_student_trigger_receipt_v2\": {\n"
        "    \"abi_version\": %u, \"trigger_protocol\": %u, "
        "\"ordinal_base\": %u, \"worker_count\": %u,\n"
        "    \"checkpoint_trigger_messages\": %" PRIu64
        ", \"scheduled_periodic_ticks\": %" PRIu64
        ", \"empty_periodic_ticks\": %" PRIu64 ",\n"
        "    \"same_timestamp_unchanged_periodic_coalesces\": %" PRIu64
        ", \"checkpoint_trigger_results\": %" PRIu64
        ", \"periodic_trigger_results\": %" PRIu64 ",\n"
        "    \"output_results\": %" PRIu64
        ", \"trigger_ordinal_sum\": %" PRIu64
        ", \"trigger_ordinal_xor\": %" PRIu64
        ", \"trigger_ordinal_max\": %" PRIu64 ",\n"
        "    \"checkpoint_packet_results\": {\"4\": %" PRIu64
        ", \"8\": %" PRIu64 ", \"12\": %" PRIu64
        ", \"20\": %" PRIu64 "},\n"
        "    \"invalid_checkpoint_packet_rejections\": %" PRIu64
        ", \"trigger_protocol_rejections\": %" PRIu64 ",\n"
        "    \"final_watermark_ns\": %" PRIu64
        ", \"event_path_reserved_bytes\": %" PRIu64
        ", \"student_shards_reserved_bytes\": %" PRIu64 ",\n"
        "    \"student_model\": {\"continuous_features\": %u, "
        "\"input_features\": %u, \"hidden\": %u, "
        "\"identity_embedding\": %u, \"event_hidden\": %u, "
        "\"parameter_floats\": %u, \"decision_threshold\": %.9g,\n"
        "      \"artifact_sha256\": \"%s\", "
        "\"feature_schema_sha256\": \"%s\",\n"
        "      \"architecture_sha256\": \"%s\", "
        "\"source_state_sha256\": \"%s\", "
        "\"payload_sha256\": \"%s\"},\n"
        "    \"final_flush_complete\": %s, \"command_queues_empty\": %s, "
        "\"result_queues_empty\": %s, \"worker_failure\": %s,\n"
        "    \"conservation_valid\": %s, "
        "\"deterministic_smoke_model\": %s\n  },\n",
        receipt.abi_version,
        receipt.trigger_protocol,
        receipt.ordinal_base,
        receipt.worker_count,
        receipt.checkpoint_trigger_messages,
        receipt.scheduled_periodic_ticks,
        receipt.empty_periodic_ticks,
        receipt.same_timestamp_unchanged_periodic_coalesces,
        receipt.checkpoint_trigger_results,
        receipt.periodic_trigger_results,
        receipt.output_results,
        receipt.trigger_ordinal_sum,
        receipt.trigger_ordinal_xor,
        receipt.trigger_ordinal_max,
        receipt.checkpoint_packet_4_results,
        receipt.checkpoint_packet_8_results,
        receipt.checkpoint_packet_12_results,
        receipt.checkpoint_packet_20_results,
        receipt.invalid_checkpoint_packet_rejections,
        receipt.trigger_protocol_rejections,
        receipt.final_watermark_ns,
        receipt.event_path_reserved_bytes,
        receipt.student_shards_reserved_bytes,
        receipt.student_continuous_features,
        receipt.student_input_features,
        receipt.student_hidden,
        receipt.student_identity_embedding,
        receipt.student_event_hidden,
        receipt.student_parameter_floats,
        static_cast<double>(receipt.student_decision_threshold),
        receipt.student_artifact_sha256,
        receipt.student_feature_schema_sha256,
        receipt.student_architecture_sha256,
        receipt.student_source_state_sha256,
        receipt.student_payload_sha256,
        json_bool(receipt.final_flush_complete != 0u),
        json_bool(receipt.command_queues_empty != 0u),
        json_bool(receipt.result_queues_empty != 0u),
        json_bool(receipt.worker_failure != 0u),
        json_bool(receipt.conservation_valid != 0u),
        json_bool(receipt.deterministic_smoke_model != 0u));
}

void write_quic_correctness_receipt(
    FILE *stream,
    const fk_no_nic_quic_identity_observability_v1 &quic,
    uint64_t owner_quic_packets,
    uint16_t owner_count,
    const fk_finite_live_quic_correctness_gate_result &gate);

bool write_failure(
        const Options &options,
        const NicReceipt &nic,
        const char *stage,
        const char *message,
        const LiveSource *source = nullptr,
        const fk_no_nic_full_composition_result *result = nullptr,
        const fk_finite_live_quic_correctness_gate_result *quic_gate =
            nullptr) {
    if (options.output == nullptr || std::strcmp(options.output, "-") == 0)
        return false;
    FILE *stream = std::fopen(options.output, "w");
    if (stream == nullptr)
        return false;
    std::fputs(
        "{\n  \"protocol\": \"flowkeep-dpdk-finite-live-rx-v2\",\n"
        "  \"status\": \"failed\",\n  \"stage\": ",
        stream);
    json_string(stream, stage);
    std::fputs(",\n  \"error\": ", stream);
    json_string(stream, message);
    std::fprintf(
        stream,
        ",\n  \"integration\": {\n"
        "    \"production_main_opt_in\": true,\n"
        "    \"eal_initialized_before_entry\": true,\n"
        "    \"rte_eth_device_valid\": %s,\n"
        "    \"rte_eth_port_started\": %s,\n"
        "    \"actual_nic_rx_connected\": %s,\n"
        "    \"exact_rx_producer_pump_connected\": %s,\n"
        "    \"production_capability_promoted\": false\n  },\n",
        json_bool(nic.device_valid), json_bool(nic.started),
        json_bool(
            nic.started && source != nullptr &&
            (source->acquired() != 0u ||
             source->filtered_packets() != 0u)),
        json_bool(result != nullptr && result->rx_received != 0u));
    write_nic_receipt(stream, options, nic);
    write_transport_receipt(stream, options, nic, source);
    if (result != nullptr && quic_gate != nullptr) {
        write_quic_correctness_receipt(
            stream, result->quic_identity, result->owner_quic,
            result->service_memory.owner_count, *quic_gate);
    }
    std::fprintf(
        stream,
        "  \"pipeline_diagnostic\": {\n"
        "    \"source_acquired_packets\": %" PRIu64 ",\n"
        "    \"non_trace_packets_filtered\": %" PRIu64 ",\n"
        "    \"non_trace_wire_bytes_filtered\": %" PRIu64 ",\n"
        "    \"decode_failures\": %" PRIu64 ",\n"
        "    \"tracking_failures\": %" PRIu64 ",\n"
        "    \"composition_rx_received\": %" PRIu64 ",\n"
        "    \"forced_failure_reclaims\": %" PRIu64 "\n  },\n"
        "  \"formal_detection_result\": false,\n"
        "  \"throughput_claim\": false\n}\n",
        source == nullptr ? 0u : source->acquired(),
        source == nullptr ? 0u : source->filtered_packets(),
        source == nullptr ? 0u : source->filtered_wire_bytes(),
        source == nullptr ? 0u : source->decode_failures(),
        source == nullptr ? 0u : source->tracking_failures(),
        result == nullptr ? 0u : result->rx_received,
        result == nullptr ? 0u : result->io_forced_failure_reclaims);
    return std::fclose(stream) == 0;
}

void write_decision_observability(
        FILE *stream,
        const Options &options,
        const fk_no_nic_decision_observability_v1 &value) {
    std::fputs("  \"decision_observability\": {\"trace_path\": ", stream);
    if (options.decision_trace == nullptr)
        std::fputs("null", stream);
    else
        json_string(stream, options.decision_trace);
    std::fprintf(
        stream,
        ", \"trace_abi\": %u, "
        "\"records\": {\"all\": %" PRIu64 ", \"checkpoint\": %" PRIu64
        ", \"periodic\": %" PRIu64 ", \"exported\": %" PRIu64
        ", \"sink_rejections\": %" PRIu64
        ", \"rolling_hash64\": \"%016" PRIx64 "\"}, "
        "\"trace_export_complete\": %s,\n"
        "    \"timing\": {\"definition\": "
        "\"physical_steady_clock; packet_to_decision=RX_ingress_to_Event_Student_decision\", "
        "\"quantile_method\": \"log2_lower_bound_histogram_64_bins\", "
        "\"detection_ns\": {\"samples\": %" PRIu64 ", \"p50\": %" PRIu64
        ", \"p95\": %" PRIu64 ", \"p99\": %" PRIu64 "}, "
        "\"packet_to_decision_ns\": {\"samples\": %" PRIu64
        ", \"p50\": %" PRIu64 ", \"p95\": %" PRIu64
        ", \"p99\": %" PRIu64 "}, "
        "\"flow_detector_ns\": {\"samples\": %" PRIu64
        ", \"p50\": %" PRIu64 ", \"p95\": %" PRIu64
        ", \"p99\": %" PRIu64 "}, \"timestamp_failures\": %" PRIu64
        ", \"order_failures\": %" PRIu64 ", \"complete\": %s},\n"
        "    \"queue\": {\"scope\": "
        "\"offered_interval_source_start_to_rx_stop\", \"samples\": %" PRIu64
        ", \"max_stage_peak_entries\": %" PRIu64
        ", \"ols_slope_entries_per_second\": %.17g"
        ", \"peak_positive_slope_entries_per_second\": %.17g, "
        "\"stage_peaks\": {\"sequencer_ingress\": %" PRIu64
        ", \"sequencer_reorder\": %" PRIu64 ", \"dispatch\": %" PRIu64
        ", \"owner_output\": %" PRIu64 ", \"checkpoint_reorder\": %" PRIu64
        ", \"student_command\": %" PRIu64 ", \"student_result\": %" PRIu64
        "}},\n"
        "    \"recovery\": {\"definition\": "
        "\"RX_normal_stop_to_all_pipeline_and_Student_queues_drained\", "
        "\"start_ns\": %" PRIu64 ", \"complete_ns\": %" PRIu64
        ", \"time_ns\": %" PRIu64 ", \"complete\": %s},\n"
        "    \"loss_accounting\": {\"fatal\": {\"packet_drops\": %" PRIu64
        ", \"decision_drops\": %" PRIu64 ", \"integrity_events\": %" PRIu64
        "}, \"policy_reject\": {\"flows\": %" PRIu64
        ", \"state_actions\": %" PRIu64 ", \"evidence\": %" PRIu64
        "}, \"retry_only_backpressure_events\": %" PRIu64
        ", \"complete\": %s}\n  },\n",
        value.abi_version,
        value.decision_records, value.checkpoint_records,
        value.periodic_records, value.trace_sink_records,
        value.trace_sink_rejections, value.trace_rolling_hash64,
        value.trace_export_complete ? "true" : "false",
        value.detection_latency_samples, value.detection_latency_p50_ns,
        value.detection_latency_p95_ns, value.detection_latency_p99_ns,
        value.packet_to_decision_samples, value.packet_to_decision_p50_ns,
        value.packet_to_decision_p95_ns, value.packet_to_decision_p99_ns,
        value.flow_detector_latency_samples, value.flow_detector_latency_p50_ns,
        value.flow_detector_latency_p95_ns, value.flow_detector_latency_p99_ns,
        value.timestamp_failures, value.order_failures,
        value.timing_complete ? "true" : "false",
        value.queue_samples, value.queue_peak_entries,
        value.queue_ols_slope_entries_per_second,
        value.queue_peak_positive_slope_entries_per_second,
        value.sequencer_ingress_peak, value.sequencer_reorder_peak,
        value.dispatch_peak, value.owner_output_peak,
        value.checkpoint_reorder_peak, value.student_command_peak,
        value.student_result_peak, value.recovery_start_monotonic_ns,
        value.recovery_complete_monotonic_ns, value.recovery_time_ns,
        value.recovery_complete ? "true" : "false",
        value.fatal_packet_drops, value.fatal_decision_drops,
        value.fatal_integrity_events, value.policy_flow_rejects,
        value.policy_state_action_rejects, value.policy_evidence_rejects,
        value.transient_backpressure_events,
        value.drop_accounting_complete ? "true" : "false");
}

void write_detection_service_capacity(
        FILE *stream,
        const fk_no_nic_detection_service_capacity_receipt_v1 &value) {
    std::fprintf(
        stream,
        "  \"detection_service_capacity\": {"
        "\"abi_version\": %u, "
        "\"budget_disposition\": \"separate_detection_service_state\", "
        "\"actor_maximum_events\": %u, "
        "\"actor_maximum_total_flows\": %u, "
        "\"actor_maximum_flows_per_event\": %u, "
        "\"window_maximum_events\": %u, "
        "\"window_maximum_total_flows\": %u, "
        "\"actor_active_events\": %u, "
        "\"actor_peak_active_events\": %u, "
        "\"actor_active_flows\": %u, "
        "\"actor_peak_active_flows\": %u, "
        "\"actor_event_capacity_evictions\": %" PRIu64 ", "
        "\"actor_total_flow_capacity_evictions\": %" PRIu64 ", "
        "\"actor_flow_capacity_rollovers\": %" PRIu64 ", "
        "\"window_live_slot_reuse_conflicts\": %" PRIu64 ", "
        "\"window_event_slots_reused\": %" PRIu64 ", "
        "\"capacity_clean\": %s},\n",
        value.abi_version,
        value.actor_maximum_events,
        value.actor_maximum_total_flows,
        value.actor_maximum_flows_per_event,
        value.window_maximum_events,
        value.window_maximum_total_flows,
        value.actor_active_events,
        value.actor_peak_active_events,
        value.actor_active_flows,
        value.actor_peak_active_flows,
        value.actor_event_capacity_evictions,
        value.actor_total_flow_capacity_evictions,
        value.actor_flow_capacity_rollovers,
        value.window_live_slot_reuse_conflicts,
        value.window_event_slots_reused,
        json_bool(value.capacity_clean != 0u));
}

void write_frozen_causal_aggregation(
        FILE *stream,
        const fk_no_nic_frozen_causal_aggregation_receipt_v1 &receipt) {
    std::fprintf(
        stream,
        "  \"frozen_causal_aggregation\": {\n"
        "    \"abi_version\": %u,\n"
        "    \"aggregation_mode\": %s,\n"
        "    \"aggregation_rule\": ",
        receipt.abi_version,
        receipt.enabled != 0u ? "\"frozen_cpp_causal\"" : "null");
    if (receipt.enabled != 0u)
        json_string(stream, receipt.aggregation_rule);
    else
        std::fputs("null", stream);
    std::fputs(",\n    \"threshold_profile\": ", stream);
    if (receipt.enabled != 0u)
        json_string(stream, receipt.threshold_profile);
    else
        std::fputs("null", stream);
    std::fprintf(
        stream,
        ",\n    \"threshold\": %.9g,\n"
        "    \"aggregation_contract_sha256\": ",
        static_cast<double>(receipt.threshold));
    if (receipt.enabled != 0u)
        json_string(stream, receipt.aggregation_contract_sha256);
    else
        std::fputs("null", stream);
    std::fputs(",\n    \"development_oof_receipt_sha256\": ", stream);
    if (receipt.enabled != 0u)
        json_string(stream, receipt.development_oof_receipt_sha256);
    else
        std::fputs("null", stream);
    std::fprintf(
        stream,
        ",\n    \"checkpoint_updates\": %" PRIu64 ",\n"
        "    \"periodic_updates\": %" PRIu64 ",\n"
        "    \"initialized_event_generations\": %" PRIu64 ",\n"
        "    \"threshold_crossings\": %" PRIu64 ",\n"
        "    \"latched_alert_outputs\": %" PRIu64 ",\n"
        "    \"requested_mask_or\": %u,\n"
        "    \"physical_final_mask_or\": %u,\n"
        "    \"reserved_bytes\": %" PRIu64 ",\n"
        "    \"enabled\": %s,\n"
        "    \"deterministic_smoke_model\": %s,\n"
        "    \"complete\": %s\n"
        "  },\n",
        receipt.checkpoint_updates,
        receipt.periodic_updates,
        receipt.initialized_event_generations,
        receipt.threshold_crossings,
        receipt.latched_alert_outputs,
        receipt.requested_mask_or,
        receipt.physical_final_mask_or,
        receipt.reserved_bytes,
        json_bool(receipt.enabled != 0u),
        json_bool(receipt.deterministic_smoke_model != 0u),
        json_bool(receipt.complete != 0u));
}

fk_finite_live_quic_correctness_gate_input
make_quic_correctness_gate_input(
        const Options &options,
        const fk_trace_sidecar &sidecar,
        const LiveSource &source,
        const NicReceipt &nic,
        const fk_no_nic_full_composition_result &result) {
    fk_finite_live_quic_correctness_gate_input input{};
    input.abi_version =
        FK_FINITE_LIVE_QUIC_CORRECTNESS_GATE_ABI_VERSION;
    input.require_quic_identity_proof =
        options.require_quic_identity_proof;
    input.rx_queue_count = 1u;
    input.owner_count = result.service_memory.owner_count;

    input.actual_nic_rx_connected = nic.started && result.rx_received != 0u;
    input.actual_nic_rx_connected = input.actual_nic_rx_connected &&
        (!options.require_quic_identity_proof ||
         nic.device_identity_verified);
    input.nic_port_stop_succeeded = nic.stop_succeeded;
    input.nic_port_close_succeeded = nic.close_succeeded;
    input.nic_promiscuous_disabled = nic.promiscuous_disabled;
    input.nic_mtu_restored = nic.mtu_restored;
    input.nic_stats_baseline_valid = nic.baseline_valid;
    input.nic_stats_end_valid = nic.end_valid;
    input.nic_stats_monotonic = nic.counters_monotonic;
    input.nic_drop_xstat_resolved =
        nic.rx_dropped_packets_xstat_resolved;
    input.nic_drop_xstat_baseline_valid =
        nic.rx_dropped_packets_baseline_valid;
    input.nic_drop_xstat_end_valid = nic.rx_dropped_packets_end_valid;
    input.nic_drop_xstat_monotonic =
        nic.rx_dropped_packets_monotonic;
    input.nic_missed_packets = nic.delta.imissed;
    input.nic_input_errors = nic.delta.ierrors;
    input.nic_rx_nombuf = nic.delta.rx_nombuf;
    input.nic_drop_xstat_delta = nic.rx_dropped_packets_delta;

    input.finite_sidecar_preflight_verified =
        sidecar.packet_count == options.expected_packets &&
        sidecar.packet_count != 0u &&
        (!options.require_quic_identity_proof ||
         options.sidecar_sha256_verified);
    input.transport_exact_recovery_complete =
        source.restored_packets() == options.expected_packets &&
        source.crc_verified_packets() == options.expected_packets &&
        source.invalid_shim_packets() == 0u &&
        source.decode_failures() == 0u &&
        source.tracking_failures() == 0u;
    input.expected_packets = options.expected_packets;
    input.transport_packets_recovered = source.restored_packets();
    input.transport_sequence_gaps = source.shim_sequence_failures();
    input.transport_sequence_duplicates = 0u;
    input.transport_identity_mismatches =
        source.envelope_mac_mismatches();
    input.transport_decode_failures = source.decode_failures();
    input.transport_tracking_failures = source.tracking_failures();

    input.nic_received_packets = nic.delta.ipackets;
    input.nic_non_trace_packets_filtered = source.filtered_packets();
    input.pipeline_rx_packets = result.rx_received;
    input.sequencer_transferred_packets = result.sequencer_transferred;
    input.identity_data_transfers = result.identity_data_transfers;
    input.identity_skip_reclaims = result.identity_skip_reclaims;
    input.identity_reject_reclaims = result.identity_reject_reclaims;
    input.owner_packets_completed = result.owner_packets_completed;
    input.mbufs_reclaimed = result.mbufs_reclaimed;
    input.live_mbufs_at_end = result.io_live_mbufs;
    input.duplicate_reclaims = result.io_duplicate_reclaims;
    input.forced_failure_reclaims = result.io_forced_failure_reclaims;

    input.source_exhausted = result.source_exhausted != 0u;
    input.source_failed = result.source_failed != 0u;
    input.partial_epoch_closed = result.partial_epoch_closed != 0u;
    input.bridge_sealed = result.bridge_sealed != 0u;
    input.reorder_drained = result.reorder_drained != 0u;
    input.ownership_conserved = result.mbuf_ownership_conserved != 0u;
    input.global_order_conserved = result.global_order_conserved != 0u;
    input.normal_complete = result.normal_complete != 0u;
    input.router_parser_reason_conserved =
        result.router_parser_reason_conserved != 0u;
    input.packet_disposition_conserved =
        result.packet_disposition_conserved != 0u;
    input.controlled_state_accounting_valid =
        result.controlled_state_accounting_valid != 0u;
    input.state_byte_seconds_complete =
        result.state_byte_seconds_complete != 0u;
    input.evidence_transition_receipt_complete =
        result.evidence_transitions.complete != 0u;
    input.service_memory_receipt_valid =
        fk_no_nic_service_memory_receipt_verify_v1(&result.service_memory);
    input.controlled_state_hard_budget_violations =
        result.controlled_state_hard_budget_violations;

    const auto &quic = result.quic_identity;
    uint64_t quic_packets = quic.router_quic_initial_packets;
    if (!add_u64(quic_packets, quic.router_quic_long_packets) ||
        !add_u64(quic_packets, quic.router_quic_short_packets)) {
        quic_packets = UINT64_MAX;
    }
    input.quic_packets_observed = quic_packets;
    input.quic_connections_observed = quic.cid_connections_created;
    input.quic_identity_disposition_conserved =
        quic.router_quic_disposition_conserved != 0u;
    input.quic_identity_packets_routed =
        quic.router_quic_data_committed_transfers;
    input.quic_identity_packets_skipped =
        quic.router_quic_skip_committed_reclaims;
    input.quic_owner_packets_processed = result.owner_quic;

    const bool identity_abi_valid =
        quic.abi_version ==
            FK_NO_NIC_QUIC_IDENTITY_OBSERVABILITY_ABI_VERSION;
    input.quic_identity_parser_complete = identity_abi_valid;
    input.quic_identity_semantic_ordering_connected =
        identity_abi_valid && result.global_order_conserved != 0u;
    input.quic_cid_map_connected = identity_abi_valid;
    input.quic_presentation_path_connected = identity_abi_valid;
    input.owner_flow_bindings_connected = identity_abi_valid;
    input.identity_capacity_accounting_valid =
        identity_abi_valid && quic.capacity_conserved != 0u &&
        result.controlled_state_accounting_valid != 0u;
    input.configured_quic_connection_capacity =
        result.maximum_quic_connections_configured;
    input.quic_cid_connection_capacity =
        result.quic_cid_connection_capacity;
    input.quic_path_connection_capacity =
        result.quic_path_connection_capacity;
    input.owner_binding_connection_capacity =
        result.owner_binding_connection_capacity;
    input.peak_active_quic_connections =
        quic.cid_peak_active_connections;

    uint64_t expected_terminal_timestamp = sidecar.last_timestamp_ns;
    const bool terminal_timestamp_valid =
        add_u64(expected_terminal_timestamp, kFlowIdleTimeoutNs) &&
        add_u64(expected_terminal_timestamp, 1u) &&
        quic.finite_epoch_drain_timestamp_ns == expected_terminal_timestamp;
    input.finite_epoch_drain_requested =
        quic.finite_epoch_drain_requested != 0u;
    input.finite_epoch_drain_after_source_eof =
        quic.finite_epoch_drain_after_input_eof != 0u;
    input.finite_epoch_drain_timestamp_formal = terminal_timestamp_valid;
    input.finite_epoch_drain_before_publisher_terminal =
        quic.finite_epoch_drain_before_publisher_terminal != 0u;
    input.cid_finite_epoch_drain_succeeded =
        quic.finite_epoch_drain_complete != 0u &&
        quic.finite_epoch_drain_reason ==
            FK_QUIC_CID_FINITE_EPOCH_DRAIN_IDLE_TIMEOUT_AFTER_EOF;
    input.path_finite_epoch_drain_succeeded =
        quic.finite_epoch_path_drain_complete != 0u &&
        quic.finite_epoch_path_drain_reason ==
            FK_QUIC_PRESENTATION_PATH_FINITE_EPOCH_DRAIN_IDLE_TIMEOUT_AFTER_EOF;
    input.cid_active_connections_before_drain =
        quic.finite_epoch_active_before;
    input.cid_connections_drained = quic.finite_epoch_connections_drained;
    input.cid_active_connections_after_drain =
        quic.finite_epoch_active_after;
    input.path_active_connections_before_drain =
        quic.finite_epoch_path_active_connections_before;
    input.path_active_connections_after_drain =
        quic.finite_epoch_path_active_connections_after;
    input.path_active_paths_before_drain = quic.finite_epoch_paths_before;
    input.path_paths_drained = quic.finite_epoch_paths_drained;
    input.path_active_paths_after_drain = quic.finite_epoch_paths_after;

    input.cid_active_connections_at_end =
        quic.cid_active_connections_at_end;
    input.cid_active_cids_at_end = quic.cid_active_cids_at_end;
    input.cid_pending_handshakes_at_end =
        quic.cid_pending_handshakes_at_end;
    input.cid_pending_bindings_at_end =
        quic.cid_binding_credits_in_use_at_end;
    input.cid_retired_pending_owner_ack_at_end =
        quic.cid_retired_pending_owner_ack_at_end;
    input.path_active_connections_at_end =
        quic.path_active_connections_at_end;
    input.path_active_paths_at_end = quic.path_active_paths_at_end;
    input.owner_active_bindings_at_end = quic.binding_active_at_end;
    input.owner_unbound_slots_at_end = quic.binding_unbound_at_end;
    input.owner_retired_pending_cid_ack_slots_at_end =
        quic.binding_retired_pending_at_end;

    uint64_t publisher_terminal_outcomes =
        quic.publisher_terminal_batches_committed;
    const bool publisher_terminal_sum_valid =
        add_u64(publisher_terminal_outcomes, quic.publisher_terminal_empty);
    input.retirement_publisher_formal_mode =
        quic.publisher_accounting_conserved != 0u &&
        quic.publisher_formal_complete != 0u;
    input.retirement_observations_sealed =
        quic.dispatch_observations_sealed != 0u;
    input.retirement_publisher_terminal =
        publisher_terminal_sum_valid && publisher_terminal_outcomes == 1u;
    input.retirement_publisher_queue_empty =
        quic.publisher_marked_controls_at_end == 0u &&
        quic.dispatch_retire_control_depth_at_end == 0u;
    input.retirement_publisher_failed =
        quic.publisher_formal_complete == 0u ||
        quic.retirement_ack_failures != 0u;
    input.retirement_controls_committed =
        quic.publisher_controls_committed;
    input.retirement_controls_dispatched =
        quic.dispatch_retire_controls_enqueued;
    input.retirement_controls_normal_dequeued =
        quic.dispatch_retire_controls_normal_dequeued;
    input.owner_retire_dequeued = quic.owner_retire_controls_dequeued;
    input.owner_retire_acked = quic.owner_retire_controls_acked;
    input.adapter_retire_calls = quic.adapter_retire_calls;
    input.adapter_retire_acked = quic.adapter_retire_acked;
    input.cid_connections_retired_pending_owner_ack =
        quic.cid_connections_retired_pending_owner_ack_total;
    input.cid_retirement_publication_marks =
        quic.cid_retirement_publication_marks;
    input.cid_retirement_ack_calls = quic.cid_retirement_ack_calls;
    input.cid_retirement_acks = quic.cid_retirement_acks;
    input.retirement_control_failures = quic.retirement_ack_failures;
    return input;
}

void write_quic_correctness_receipt(
        FILE *stream,
        const fk_no_nic_quic_identity_observability_v1 &quic,
        uint64_t owner_quic_packets,
        uint16_t owner_count,
        const fk_finite_live_quic_correctness_gate_result &gate) {
    uint64_t router_quic_packets = quic.router_quic_initial_packets;
    if (!add_u64(router_quic_packets, quic.router_quic_long_packets) ||
        !add_u64(router_quic_packets, quic.router_quic_short_packets)) {
        router_quic_packets = UINT64_MAX;
    }
    const uint64_t controls = quic.publisher_controls_committed;
    const bool retirement_gate_conserved = controls != 0u &&
        controls == quic.cid_connections_created &&
        quic.dispatch_retire_controls_enqueued == controls &&
        quic.dispatch_retire_controls_normal_dequeued == controls &&
        quic.owner_retire_controls_dequeued == controls &&
        quic.owner_retire_controls_acked == controls &&
        quic.adapter_retire_calls == controls &&
        quic.adapter_retire_acked == controls &&
        quic.cid_connections_retired_pending_owner_ack_total == controls &&
        quic.cid_retirement_publication_marks == controls &&
        quic.cid_retirement_ack_calls == controls &&
        quic.cid_retirement_acks == controls &&
        quic.retirement_ack_failures == 0u;
    const bool terminal_identity_gate_zero =
        quic.finite_epoch_active_after == 0u &&
        quic.finite_epoch_path_active_connections_after == 0u &&
        quic.finite_epoch_paths_after == 0u &&
        quic.cid_active_connections_at_end == 0u &&
        quic.cid_active_cids_at_end == 0u &&
        quic.cid_pending_handshakes_at_end == 0u &&
        quic.cid_binding_credits_in_use_at_end == 0u &&
        quic.cid_retired_pending_owner_ack_at_end == 0u &&
        quic.path_active_connections_at_end == 0u &&
        quic.path_active_paths_at_end == 0u &&
        quic.binding_active_at_end == 0u &&
        quic.binding_unbound_at_end == 0u &&
        quic.binding_retired_pending_at_end == 0u;
    uint64_t publisher_terminal_outcomes =
        quic.publisher_terminal_batches_committed;
    const bool publisher_terminal_sum_valid = add_u64(
        publisher_terminal_outcomes, quic.publisher_terminal_empty);
    const bool publisher_gate_formal =
        quic.publisher_accounting_conserved != 0u &&
        quic.publisher_formal_complete != 0u &&
        quic.dispatch_observations_sealed != 0u &&
        publisher_terminal_sum_valid && publisher_terminal_outcomes == 1u &&
        quic.publisher_marked_controls_at_end == 0u &&
        quic.dispatch_retire_control_depth_at_end == 0u &&
        quic.retirement_ack_failures == 0u;
    std::fprintf(
        stream,
        "  \"quic_actual_nic_correctness\": {\n"
        "    \"gate_abi_version\": %u,\n"
        "    \"scope\": \"single_rx_queue_single_fixed_owner_finite_replay\",\n"
        "    \"topology\": {\"rx_queue_count\": 1, "
        "\"owner_count\": %u},\n"
        "    \"blocker_mask\": \"0x%016" PRIx64 "\",\n"
        "    \"actual_nic_finite_pipeline_ready\": %s,\n"
        "    \"quic_activity_observed\": %s,\n"
        "    \"quic_identity_correctness_ready\": %s,\n"
        "    \"scoped_capability_promoted\": %s,\n"
        "    \"default_multicore_capability_promoted\": false,\n"
        "    \"blockers\": {\"invalid_input\": %s, "
        "\"topology_scope\": %s, \"nic_zero_loss\": %s, "
        "\"transport_exact_recovery\": %s, "
        "\"packet_conservation\": %s, \"pipeline_closure\": %s, "
        "\"quic_activity\": %s, \"identity_capacity\": %s, "
        "\"identity_eof_drain\": %s, "
        "\"identity_terminal_zero\": %s, "
        "\"publisher_formal\": %s, "
        "\"retirement_ack_conservation\": %s, "
        "\"quic_proof_not_required\": %s},\n"
        "    \"identity\": {\"abi_version\": %u, "
        "\"router_quic_packets\": %" PRIu64 ", "
        "\"connections_created\": %" PRIu64 ", "
        "\"quic_data_committed\": %" PRIu64 ", "
        "\"quic_skip_committed\": %" PRIu64 ", "
        "\"owner_quic_packets\": %" PRIu64 ", "
        "\"quic_disposition_conserved\": %s, "
        "\"maximum_connections\": %u, "
        "\"peak_active_connections\": %u},\n"
        "    \"initial_crypto_admission\": {\"begin_attempts\": %" PRIu64
        ", \"allowed\": %" PRIu64 ", \"deferred\": %" PRIu64
        ", \"rejected\": %" PRIu64
        ", \"pressure_rejects\": %" PRIu64
        ", \"global_token_rejects\": %" PRIu64
        ", \"prefix_credit_rejects\": %" PRIu64
        ", \"prefix_table_rejects\": %" PRIu64
        ", \"oversized_rejects\": %" PRIu64
        ", \"invalid_request_rejects\": %" PRIu64
        ", \"internal_rejects\": %" PRIu64 "},\n"
        "    \"finite_epoch_drain\": {\"requested\": %s, "
        "\"after_source_eof\": %s, \"before_publisher_terminal\": %s, "
        "\"timestamp_ns\": %" PRIu64 ", "
        "\"cid_reason\": %u, \"cid_before\": %u, "
        "\"cid_drained\": %u, \"cid_after\": %u, "
        "\"cid_complete\": %s, \"complete\": %s, "
        "\"path_reason\": %u, \"path_connections_before\": %u, "
        "\"paths_before\": %u, \"paths_drained\": %u, "
        "\"path_connections_after\": %u, \"paths_after\": %u, "
        "\"path_complete\": %s},\n"
        "    \"retirement_delivery\": {"
        "\"publisher_controls_committed\": %" PRIu64 ", "
        "\"dispatch_controls_enqueued\": %" PRIu64 ", "
        "\"dispatch_controls_normal_dequeued\": %" PRIu64 ", "
        "\"owner_controls_dequeued\": %" PRIu64 ", "
        "\"owner_controls_acked\": %" PRIu64 ", "
        "\"adapter_retire_calls\": %" PRIu64 ", "
        "\"adapter_retire_acked\": %" PRIu64 ", "
        "\"cid_retired_pending_owner_ack_total\": %" PRIu64 ", "
        "\"cid_publication_marks\": %" PRIu64 ", "
        "\"cid_ack_calls\": %" PRIu64 ", "
        "\"cid_acks\": %" PRIu64 ", \"failures\": %" PRIu64 ", "
        "\"publisher_accounting_conserved\": %s, "
        "\"observations_sealed\": %s, "
        "\"publisher_terminal_batches_committed\": %" PRIu64 ", "
        "\"publisher_terminal_empty\": %" PRIu64 ", "
        "\"publisher_marked_controls_at_end\": %u, "
        "\"dispatch_control_depth_at_end\": %" PRIu64 ", "
        "\"publisher_formal_complete\": %s, "
        "\"gate_publisher_formal\": %s, "
        "\"delivery_conserved\": %s, "
        "\"gate_delivery_conserved\": %s, "
        "\"owner_ack_complete\": %s},\n"
        "    \"terminal_identity_zero\": %s,\n"
        "    \"terminal_identity\": {"
        "\"cid_active_connections_after_drain\": %u, "
        "\"path_active_connections_after_drain\": %u, "
        "\"path_active_paths_after_drain\": %u, "
        "\"cid_active_connections_at_end\": %u, "
        "\"cid_active_cids_at_end\": %u, "
        "\"cid_pending_handshakes_at_end\": %u, "
        "\"cid_binding_credits_in_use_at_end\": %u, "
        "\"cid_retired_pending_owner_ack_at_end\": %u, "
        "\"path_active_connections_at_end\": %u, "
        "\"path_active_paths_at_end\": %u, "
        "\"owner_active_bindings_at_end\": %" PRIu64 ", "
        "\"owner_unbound_slots_at_end\": %" PRIu64 ", "
        "\"owner_retired_pending_cid_ack_slots_at_end\": %" PRIu64 ", "
        "\"module_terminal_active_zero\": %s, "
        "\"gate_terminal_zero\": %s}\n"
        "  },\n",
        FK_FINITE_LIVE_QUIC_CORRECTNESS_GATE_ABI_VERSION,
        static_cast<unsigned>(owner_count),
        gate.blocker_mask,
        json_bool(gate.actual_nic_finite_pipeline_ready),
        json_bool(gate.quic_activity_observed),
        json_bool(gate.quic_identity_correctness_ready),
        json_bool(gate.scoped_capability_promoted),
        json_bool(
            (gate.blocker_mask &
             FK_FINITE_LIVE_QUIC_BLOCKER_INVALID_INPUT) != 0u),
        json_bool(
            (gate.blocker_mask &
             FK_FINITE_LIVE_QUIC_BLOCKER_TOPOLOGY_SCOPE) != 0u),
        json_bool(
            (gate.blocker_mask &
             FK_FINITE_LIVE_QUIC_BLOCKER_NIC_ZERO_LOSS) != 0u),
        json_bool(
            (gate.blocker_mask &
             FK_FINITE_LIVE_QUIC_BLOCKER_TRANSPORT_EXACT_RECOVERY) != 0u),
        json_bool(
            (gate.blocker_mask &
             FK_FINITE_LIVE_QUIC_BLOCKER_PACKET_CONSERVATION) != 0u),
        json_bool(
            (gate.blocker_mask &
             FK_FINITE_LIVE_QUIC_BLOCKER_PIPELINE_CLOSURE) != 0u),
        json_bool(
            (gate.blocker_mask &
             FK_FINITE_LIVE_QUIC_BLOCKER_QUIC_ACTIVITY) != 0u),
        json_bool(
            (gate.blocker_mask &
             FK_FINITE_LIVE_QUIC_BLOCKER_IDENTITY_CAPACITY) != 0u),
        json_bool(
            (gate.blocker_mask &
             FK_FINITE_LIVE_QUIC_BLOCKER_IDENTITY_EOF_DRAIN) != 0u),
        json_bool(
            (gate.blocker_mask &
             FK_FINITE_LIVE_QUIC_BLOCKER_IDENTITY_TERMINAL_ZERO) != 0u),
        json_bool(
            (gate.blocker_mask &
             FK_FINITE_LIVE_QUIC_BLOCKER_PUBLISHER_FORMAL) != 0u),
        json_bool(
            (gate.blocker_mask &
             FK_FINITE_LIVE_QUIC_BLOCKER_RETIREMENT_ACK_CONSERVATION) !=
                0u),
        json_bool(
            (gate.blocker_mask &
             FK_FINITE_LIVE_QUIC_BLOCKER_QUIC_PROOF_NOT_REQUIRED) != 0u),
        quic.abi_version,
        router_quic_packets,
        quic.cid_connections_created,
        quic.router_quic_data_committed_transfers,
        quic.router_quic_skip_committed_reclaims,
        owner_quic_packets,
        json_bool(quic.router_quic_disposition_conserved != 0u),
        quic.maximum_connections,
        quic.cid_peak_active_connections,
        quic.crypto_gate_begin_attempts,
        quic.crypto_gate_begin_allowed,
        quic.crypto_gate_begin_deferred,
        quic.crypto_gate_begin_rejected,
        quic.crypto_gate_pressure_rejects,
        quic.crypto_gate_global_token_rejects,
        quic.crypto_gate_prefix_credit_rejects,
        quic.crypto_gate_prefix_table_rejects,
        quic.crypto_gate_oversized_rejects,
        quic.crypto_gate_invalid_request_rejects,
        quic.crypto_gate_internal_rejects,
        json_bool(quic.finite_epoch_drain_requested != 0u),
        json_bool(quic.finite_epoch_drain_after_input_eof != 0u),
        json_bool(
            quic.finite_epoch_drain_before_publisher_terminal != 0u),
        quic.finite_epoch_drain_timestamp_ns,
        static_cast<unsigned>(quic.finite_epoch_drain_reason),
        quic.finite_epoch_active_before,
        quic.finite_epoch_connections_drained,
        quic.finite_epoch_active_after,
        json_bool(quic.finite_epoch_drain_complete != 0u),
        json_bool(quic.finite_epoch_drain_complete != 0u),
        static_cast<unsigned>(quic.finite_epoch_path_drain_reason),
        quic.finite_epoch_path_active_connections_before,
        quic.finite_epoch_paths_before,
        quic.finite_epoch_paths_drained,
        quic.finite_epoch_path_active_connections_after,
        quic.finite_epoch_paths_after,
        json_bool(quic.finite_epoch_path_drain_complete != 0u),
        quic.publisher_controls_committed,
        quic.dispatch_retire_controls_enqueued,
        quic.dispatch_retire_controls_normal_dequeued,
        quic.owner_retire_controls_dequeued,
        quic.owner_retire_controls_acked,
        quic.adapter_retire_calls,
        quic.adapter_retire_acked,
        quic.cid_connections_retired_pending_owner_ack_total,
        quic.cid_retirement_publication_marks,
        quic.cid_retirement_ack_calls,
        quic.cid_retirement_acks,
        quic.retirement_ack_failures,
        json_bool(quic.publisher_accounting_conserved != 0u),
        json_bool(quic.dispatch_observations_sealed != 0u),
        quic.publisher_terminal_batches_committed,
        quic.publisher_terminal_empty,
        quic.publisher_marked_controls_at_end,
        quic.dispatch_retire_control_depth_at_end,
        json_bool(quic.publisher_formal_complete != 0u),
        json_bool(publisher_gate_formal),
        json_bool(quic.retirement_delivery_conserved != 0u),
        json_bool(retirement_gate_conserved),
        json_bool(quic.owner_ack_complete != 0u),
        json_bool(quic.terminal_active_zero != 0u),
        quic.finite_epoch_active_after,
        quic.finite_epoch_path_active_connections_after,
        quic.finite_epoch_paths_after,
        quic.cid_active_connections_at_end,
        quic.cid_active_cids_at_end,
        quic.cid_pending_handshakes_at_end,
        quic.cid_binding_credits_in_use_at_end,
        quic.cid_retired_pending_owner_ack_at_end,
        quic.path_active_connections_at_end,
        quic.path_active_paths_at_end,
        quic.binding_active_at_end,
        quic.binding_unbound_at_end,
        quic.binding_retired_pending_at_end,
        json_bool(quic.terminal_active_zero != 0u),
        json_bool(terminal_identity_gate_zero));
}

bool write_success(
        const Options &options,
        const fk_trace_sidecar &sidecar,
        const LiveSource &source,
        const NicReceipt &nic,
        const fk_no_nic_full_composition_result &result,
        const DecisionTraceFeaturesReceipt &trace_features,
        const fk_finite_live_quic_correctness_gate_result &quic_gate) {
    char fixed_ttl_receipt[320]{};
    if (!fk_fixed_ttl_retention_format_receipt_json(
            fixed_ttl_receipt,
            sizeof(fixed_ttl_receipt),
            options.retention_policy,
            &options.fixed_ttl_retention)) {
        return false;
    }
    FILE *stream = std::fopen(options.output, "w");
    if (stream == nullptr)
        return false;
    const bool sidecar_preflight_verified =
        sidecar.packet_count == options.expected_packets &&
        sidecar.packet_count != 0u &&
        (!options.require_quic_identity_proof ||
         options.sidecar_sha256_verified);
    std::fputs(
        "{\n  \"protocol\": \"flowkeep-dpdk-finite-live-rx-v2\",\n"
        "  \"status\": \"complete\",\n",
        stream);
    std::fprintf(
        stream,
        "  \"configuration\": {\"rx_port\": %u, "
        "\"rx_queue\": 0, \"expected_packets\": %u, "
        "\"maximum_original_captured_length\": %u, "
        "\"burst\": %u, \"budget\": ",
        options.port,
        options.expected_packets,
        options.maximum_captured_length,
        options.burst);
    json_string(stream, options.budget_name);
    std::fprintf(
        stream,
        ", \"configured_budget_bytes\": %" PRIu64
        ", \"maximum_flows\": %u, "
        "\"maximum_quic_connections\": %u, "
        "\"retention_policy\": \"%s\", "
        "\"fixed_ttl_retention_receipt\": %s, "
        "\"pool_weights\": [%u, %u, %u, %u], \"sidecar\": ",
        configured_budget_bytes(options.budget),
        options.maximum_flows,
        options.maximum_quic_connections,
        options.retention_policy_name,
        fixed_ttl_receipt,
        options.pool_weights.stat_percent,
        options.pool_weights.seq_percent,
        options.pool_weights.ja4_pending_percent,
        options.pool_weights.ja4_summary_percent);
    json_string(stream, options.sidecar_path);
    std::fprintf(
        stream,
        ", \"sidecar_packets\": %" PRIu64
        ", \"require_quic_identity_proof\": %s},\n",
        sidecar.packet_count,
        json_bool(options.require_quic_identity_proof));
    std::fprintf(
        stream,
        "  \"integration\": {\n"
        "    \"production_main_opt_in\": true,\n"
        "    \"eal_initialized_before_entry\": true,\n"
        "    \"single_rx_queue\": true,\n"
        "    \"finite_sidecar_preflight_verified\": %s,\n"
        "    \"rte_eth_device_valid\": true,\n"
        "    \"rte_eth_port_started\": true,\n"
        "    \"actual_nic_rx_connected\": %s,\n"
        "    \"exact_rx_producer_pump_connected\": %s,\n"
        "    \"production_capability_scope\": "
        "\"single_rx_queue_single_fixed_owner_finite_replay\",\n"
        "    \"production_capability_promoted\": %s,\n"
        "    \"default_multicore_production_capability_promoted\": false\n"
        "  },\n",
        json_bool(sidecar_preflight_verified),
        result.rx_received != 0u && nic.started ? "true" : "false",
        result.normal_complete && result.rx_received != 0u
            ? "true" : "false",
        json_bool(quic_gate.scoped_capability_promoted));
    write_nic_receipt(stream, options, nic);
    write_transport_receipt(stream, options, nic, &source);
    std::fprintf(
        stream,
        "  \"pipeline\": {\n"
        "    \"rx_received\": %" PRIu64 ",\n"
        "    \"sequencer_transferred\": %" PRIu64 ",\n"
        "    \"identity_data_transfers\": %" PRIu64 ",\n"
        "    \"owner_packets_completed\": %" PRIu64 ",\n"
        "    \"exact_reclaims\": %" PRIu64 ",\n"
        "    \"forced_failure_reclaims\": %" PRIu64 ",\n"
        "    \"duplicate_reclaims\": %" PRIu64 ",\n"
        "    \"live_mbufs_at_end\": %" PRIu64 ",\n"
        "    \"peak_live_mbufs\": %" PRIu64 ",\n"
        "    \"non_trace_packets_filtered\": %" PRIu64 ",\n"
        "    \"non_trace_wire_bytes_filtered\": %" PRIu64 ",\n"
        "    \"decode_failures\": %" PRIu64 ",\n"
        "    \"tracking_failures\": %" PRIu64 ",\n"
        "    \"ownership_conserved\": %s,\n"
        "    \"global_order_conserved\": %s,\n"
        "    \"reorder_drained\": %s\n  },\n",
        result.rx_received,
        result.sequencer_transferred,
        result.identity_data_transfers,
        result.owner_packets_completed,
        result.mbufs_reclaimed,
        result.io_forced_failure_reclaims,
        result.io_duplicate_reclaims,
        result.io_live_mbufs,
        source.peak_live(),
        source.filtered_packets(),
        source.filtered_wire_bytes(),
        source.decode_failures(),
        source.tracking_failures(),
        result.mbuf_ownership_conserved ? "true" : "false",
        result.global_order_conserved ? "true" : "false",
        result.reorder_drained ? "true" : "false");
    std::fprintf(
        stream,
        "  \"controlled_state\": {\"ceiling_bytes\": %" PRIu64
        ", \"reserved_bytes\": %" PRIu64
        ", \"peak_bytes\": %" PRIu64
        ", \"hard_budget_violations\": %" PRIu64
        ", \"accounting_valid\": %s, "
        "\"components\": {"
        "\"quic_cid_map\": {\"configured_capacity\": %u, "
        "\"actual_capacity\": %u, \"reserved_bytes\": %" PRIu64 "}, "
        "\"quic_presentation_path\": {\"configured_capacity\": %u, "
        "\"actual_capacity\": %u, \"reserved_bytes\": %" PRIu64 "}, "
        "\"owner_flow_bindings\": {\"configured_capacity\": %u, "
        "\"actual_capacity\": %u, \"reserved_bytes\": %" PRIu64 "}}},\n",
        result.controlled_state_ceiling_bytes,
        result.controlled_allocation_bytes,
        result.controlled_state_peak_bytes,
        result.controlled_state_hard_budget_violations,
        result.controlled_state_accounting_valid ? "true" : "false",
        result.maximum_quic_connections_configured,
        result.quic_cid_connection_capacity,
        result.quic_cid_reserved_bytes,
        result.maximum_quic_connections_configured,
        result.quic_path_connection_capacity,
        result.quic_path_reserved_bytes,
        result.maximum_quic_connections_configured,
        result.owner_binding_connection_capacity,
        result.owner_binding_reserved_bytes);
    write_quic_correctness_receipt(
        stream, result.quic_identity, result.owner_quic,
        result.service_memory.owner_count, quic_gate);
    write_trigger_receipt(stream, result.trigger_receipt);
    write_frozen_causal_aggregation(
        stream, result.frozen_causal_aggregation);
    write_detection_service_capacity(
        stream, result.detection_service_capacity);
    write_decision_trace_features(stream, options, trace_features);
    write_decision_observability(stream, options, result.observability);
    write_service_memory_receipt(stream, result.service_memory);
    std::fprintf(
        stream,
        "  \"terminal\": {\n"
        "    \"source_exhausted\": %s,\n"
        "    \"source_failed\": %s,\n"
        "    \"partial_epoch_closed\": %s,\n"
        "    \"bridge_sealed\": %s,\n"
        "    \"reorder_drained\": %s,\n"
        "    \"end_barrier_reached\": %s,\n"
        "    \"normal_complete\": %s\n  },\n"
        "  \"online_detection_path\": %s,\n"
        "  \"formal_detection_result\": false,\n"
        "  \"throughput_claim\": false,\n"
        "  \"scope\": \"single-queue/single-owner finite actual-NIC "
        "correctness receipt; optional QUIC identity proof; not a "
        "multi-queue throughput claim and not a labeled paper metric\"\n"
        "}\n",
        result.source_exhausted ? "true" : "false",
        result.source_failed ? "true" : "false",
        result.partial_epoch_closed ? "true" : "false",
        result.bridge_sealed ? "true" : "false",
        result.reorder_drained ? "true" : "false",
        result.source_exhausted && !result.source_failed &&
                result.partial_epoch_closed && result.bridge_sealed &&
                result.reorder_drained && result.normal_complete
            ? "true" : "false",
        result.normal_complete ? "true" : "false",
        result.frozen_causal_aggregation.enabled != 0u &&
                result.frozen_causal_aggregation.complete != 0u &&
                result.frozen_causal_aggregation.deterministic_smoke_model == 0u
            ? "true" : "false");
    return std::fclose(stream) == 0;
}

bool setup_port(
        const Options &options,
        NicReceipt &receipt,
        rte_mempool *pool,
        char *error,
        size_t error_capacity) {
    receipt.device_valid = rte_eth_dev_is_valid_port(options.port);
    if (!receipt.device_valid) {
        std::snprintf(error, error_capacity, "invalid DPDK RX port");
        return false;
    }
    rte_eth_dev_info info{};
    int status = rte_eth_dev_info_get(options.port, &info);
    if (status != 0 || info.max_rx_queues < 1u) {
        std::snprintf(error, error_capacity, "RX device info unavailable");
        return false;
    }
    const char *device_name =
        info.device == nullptr ? nullptr : rte_dev_name(info.device);
    if (device_name == nullptr || info.driver_name == nullptr ||
        std::snprintf(
            receipt.device_name.data(),
            receipt.device_name.size(),
            "%s",
            device_name) < 0 ||
        std::strlen(device_name) >= receipt.device_name.size() ||
        std::snprintf(
            receipt.driver_name.data(),
            receipt.driver_name.size(),
            "%s",
            info.driver_name) < 0 ||
        std::strlen(info.driver_name) >= receipt.driver_name.size()) {
        std::snprintf(error, error_capacity, "RX device identity unavailable");
        return false;
    }
    receipt.device_info_valid = true;
    receipt.device_identity_verified =
        options.expected_nic_device != nullptr &&
        options.expected_nic_driver != nullptr &&
        std::strcmp(device_name, options.expected_nic_device) == 0 &&
        std::strcmp(info.driver_name, options.expected_nic_driver) == 0;
    if ((options.expected_nic_device != nullptr ||
         options.expected_nic_driver != nullptr) &&
        !receipt.device_identity_verified) {
        std::snprintf(
            error,
            error_capacity,
            "RX device name or driver does not match frozen expectation");
        return false;
    }
    rte_eth_conf configuration{};
    configuration.rxmode.mq_mode = RTE_ETH_MQ_RX_NONE;
    status = rte_eth_dev_configure(options.port, 1u, 0u, &configuration);
    if (status != 0) {
        std::snprintf(error, error_capacity, "RX device configure failed");
        return false;
    }
    receipt.configured = true;
    receipt.original_mtu_status =
        rte_eth_dev_get_mtu(options.port, &receipt.original_mtu);
    receipt.original_mtu_valid = receipt.original_mtu_status == 0;
    const uint32_t maximum_envelope =
        static_cast<uint32_t>(options.maximum_captured_length) +
        FK_TRACE_TRANSPORT_SHIM_BYTES;
    const uint32_t required_mtu = maximum_envelope > RTE_ETHER_HDR_LEN
        ? maximum_envelope - RTE_ETHER_HDR_LEN : maximum_envelope;
    if (!receipt.original_mtu_valid || required_mtu > UINT16_MAX) {
        std::snprintf(error, error_capacity, "RX MTU preflight failed");
        return false;
    }
    receipt.required_mtu = static_cast<uint16_t>(required_mtu);
    if (receipt.required_mtu > receipt.original_mtu) {
        receipt.configure_mtu_status = rte_eth_dev_set_mtu(
            options.port, receipt.required_mtu);
        receipt.mtu_changed = receipt.configure_mtu_status == 0;
        if (!receipt.mtu_changed) {
            std::snprintf(error, error_capacity, "RX MTU configure failed");
            return false;
        }
    }
    receipt.configured_mtu_status =
        rte_eth_dev_get_mtu(options.port, &receipt.configured_mtu);
    receipt.configured_mtu_valid = receipt.configured_mtu_status == 0 &&
        receipt.configured_mtu >= receipt.required_mtu;
    if (!receipt.configured_mtu_valid) {
        std::snprintf(error, error_capacity, "configured RX MTU insufficient");
        return false;
    }
    uint16_t rx_descriptors = kRxDescriptors;
    uint16_t tx_descriptors = 0u;
    status = rte_eth_dev_adjust_nb_rx_tx_desc(
        options.port, &rx_descriptors, &tx_descriptors);
    if (status != 0) {
        std::snprintf(error, error_capacity, "RX descriptor adjust failed");
        return false;
    }
    rte_eth_rxconf rx_configuration = info.default_rxconf;
    status = rte_eth_rx_queue_setup(
        options.port,
        0u,
        rx_descriptors,
        rte_eth_dev_socket_id(options.port),
        &rx_configuration,
        pool);
    if (status != 0) {
        std::snprintf(error, error_capacity, "RX queue setup failed");
        return false;
    }
    receipt.queue_ready = true;
    status = rte_eth_dev_start(options.port);
    if (status != 0) {
        std::snprintf(error, error_capacity, "RX port start failed");
        return false;
    }
    receipt.started = true;
    receipt.mac_valid =
        rte_eth_macaddr_get(options.port, &receipt.mac) == 0;
    receipt.start_link_valid =
        rte_eth_link_get_nowait(options.port, &receipt.start_link) == 0;
    receipt.promiscuous_enable_status =
        rte_eth_promiscuous_enable(options.port);
    receipt.promiscuous_enabled =
        receipt.promiscuous_enable_status == 0 &&
        rte_eth_promiscuous_get(options.port) == 1;
    receipt.rx_dropped_packets_xstat_resolved =
        rte_eth_xstats_get_id_by_name(
            options.port,
            "rx_dropped_packets",
            &receipt.rx_dropped_packets_xstat_id) == 0;
    if (options.require_quic_identity_proof &&
        !receipt.rx_dropped_packets_xstat_resolved) {
        std::snprintf(
            error, error_capacity,
            "formal QUIC NIC gate requires rx_dropped_packets xstat");
        return false;
    }
    receipt.baseline_valid =
        rte_eth_stats_reset(options.port) == 0 &&
        rte_eth_stats_get(options.port, &receipt.baseline) == 0;
    if (receipt.rx_dropped_packets_xstat_resolved) {
        receipt.rx_dropped_packets_baseline_valid =
            rte_eth_xstats_get_by_id(
                options.port,
                &receipt.rx_dropped_packets_xstat_id,
                &receipt.rx_dropped_packets_baseline,
                1u) == 1;
    }
    if (!receipt.baseline_valid) {
        std::snprintf(error, error_capacity, "NIC baseline counters failed");
        return false;
    }
    if (options.require_quic_identity_proof &&
        !receipt.rx_dropped_packets_baseline_valid) {
        std::snprintf(
            error, error_capacity,
            "formal QUIC NIC xstat baseline could not be read");
        return false;
    }
    return true;
}

void stop_port(uint16_t port, NicReceipt &receipt) {
    if (receipt.started) {
        receipt.end_link_valid =
            rte_eth_link_get_nowait(port, &receipt.end_link) == 0;
        if (receipt.promiscuous_enabled)
            receipt.promiscuous_disable_status =
                rte_eth_promiscuous_disable(port);
        receipt.promiscuous_disabled =
            rte_eth_promiscuous_get(port) == 0;
        receipt.stop_status = rte_eth_dev_stop(port);
        receipt.stop_succeeded = receipt.stop_status == 0;
        /* Freeze ingress before the terminal snapshot.  Reading counters
         * first leaves a race in which packets accepted between stats_get
         * and dev_stop are absent from both the source partition and the NIC
         * receipt.  i40e counters remain readable on a stopped, open port. */
        receipt.end_valid = rte_eth_stats_get(port, &receipt.end) == 0;
        if (receipt.rx_dropped_packets_xstat_resolved) {
            receipt.rx_dropped_packets_end_valid =
                rte_eth_xstats_get_by_id(
                    port,
                    &receipt.rx_dropped_packets_xstat_id,
                    &receipt.rx_dropped_packets_end,
                    1u) == 1;
        }
    }
    if (receipt.configured && receipt.original_mtu_valid) {
        receipt.mtu_restored = !receipt.mtu_changed;
        if (receipt.mtu_changed) {
            receipt.restore_mtu_status =
                rte_eth_dev_set_mtu(port, receipt.original_mtu);
            receipt.mtu_restored = receipt.restore_mtu_status == 0;
        }
        receipt.restored_mtu_status =
            rte_eth_dev_get_mtu(port, &receipt.restored_mtu);
        receipt.mtu_restored = receipt.mtu_restored &&
            receipt.restored_mtu_status == 0 &&
            receipt.restored_mtu == receipt.original_mtu;
    }
    if (receipt.configured) {
        receipt.close_status = rte_eth_dev_close(port);
        receipt.close_succeeded = receipt.close_status >= 0;
    }
    finalize_nic_receipt(receipt);
}

int runner_impl(int argc, char **argv) {
    if (argc == 2 && argv != nullptr && argv[1] != nullptr &&
        std::strcmp(argv[1], "--help") == 0) {
        usage(stdout, argc > 0 ? argv[0] : nullptr);
        return 0;
    }
    Options options{};
    if (!parse_options(argc, argv, options)) {
        usage(stderr, argc > 0 ? argv[0] : nullptr);
        return 2;
    }
    if (options.decision_trace != nullptr &&
        (existing_files_alias(options.decision_trace, options.sidecar_path) ||
         existing_files_alias(
             options.decision_trace, resolved_action_model(options)) ||
         (options.detector_model != nullptr &&
          existing_files_alias(
              options.decision_trace, options.detector_model)))) {
        std::fputs("decision trace aliases an immutable input\n", stderr);
        return 2;
    }
    if (options.decision_trace_features != nullptr &&
        (existing_files_alias(
             options.decision_trace_features, options.decision_trace) ||
         existing_files_alias(
             options.decision_trace_features, options.sidecar_path) ||
         existing_files_alias(
             options.decision_trace_features,
             resolved_action_model(options)) ||
         (options.detector_model != nullptr &&
          existing_files_alias(
              options.decision_trace_features, options.detector_model)) ||
         (options.event_student_artifact != nullptr &&
          existing_files_alias(
              options.decision_trace_features,
              options.event_student_artifact)))) {
        std::fputs(
            "decision trace features alias another output or immutable input\n",
            stderr);
        return 2;
    }
    NicReceipt nic{};
    fk_trace_sidecar sidecar{};
    fk_trace_sidecar_reset(&sidecar);
    char error[256]{};
    if (!fk_trace_sidecar_open(
            &sidecar, options.sidecar_path, error, sizeof(error)) ||
        sidecar.packet_count != options.expected_packets ||
        sidecar.packet_count == 0u || sidecar.packet_count >= UINT32_MAX) {
        if (error[0] == '\0')
            std::snprintf(
                error,
                sizeof(error),
                "sidecar count must exactly match finite expected packets");
        (void)write_failure(options, nic, "sidecar_preflight", error);
        fk_trace_sidecar_close(&sidecar);
        return 2;
    }
    options.observed_sidecar_sha256_valid = sha256_bytes(
        sidecar.mapping,
        sidecar.mapping_bytes,
        options.observed_sidecar_sha256);
    options.sidecar_sha256_verified =
        options.observed_sidecar_sha256_valid &&
        sha256_matches_hex(
            options.observed_sidecar_sha256, options.sidecar_sha256);
    if (!options.observed_sidecar_sha256_valid ||
        (options.sidecar_sha256 != nullptr &&
         !options.sidecar_sha256_verified)) {
        std::snprintf(
            error,
            sizeof(error),
            "sidecar whole-file SHA-256 read or binding failed");
        (void)write_failure(options, nic, "sidecar_integrity", error);
        fk_trace_sidecar_close(&sidecar);
        return 2;
    }
    if (sidecar.last_timestamp_ns >
        std::numeric_limits<uint64_t>::max() - kFlowIdleTimeoutNs - 1u) {
        std::snprintf(error, sizeof(error), "terminal semantic time overflow");
        (void)write_failure(options, nic, "sidecar_preflight", error);
        fk_trace_sidecar_close(&sidecar);
        return 2;
    }
    if (static_cast<uint32_t>(options.maximum_captured_length) +
            FK_TRACE_TRANSPORT_SHIM_BYTES >
        RTE_MBUF_DEFAULT_DATAROOM) {
        std::snprintf(
            error,
            sizeof(error),
            "maximum enveloped frame exceeds single-segment data room");
        (void)write_failure(options, nic, "mbuf_preflight", error);
        fk_trace_sidecar_close(&sidecar);
        return 2;
    }

    nic.device_valid = rte_eth_dev_is_valid_port(options.port);
    if (!nic.device_valid) {
        std::snprintf(error, sizeof(error), "invalid DPDK RX port");
        (void)write_failure(options, nic, "nic_preflight", error);
        fk_trace_sidecar_close(&sidecar);
        return 1;
    }

    rte_mempool *pool = rte_pktmbuf_pool_create(
        "FK_FINITE_LIVE_RX_MBUF",
        kMbufCount,
        kMbufCache,
        0u,
        RTE_MBUF_DEFAULT_BUF_SIZE,
        rte_socket_id());
    if (pool == nullptr) {
        std::snprintf(
            error, sizeof(error), "mbuf pool creation failed: %s",
            rte_strerror(rte_errno));
        (void)write_failure(options, nic, "mbuf_pool", error);
        fk_trace_sidecar_close(&sidecar);
        return 1;
    }
    if (!setup_port(options, nic, pool, error, sizeof(error))) {
        stop_port(options.port, nic);
        (void)write_failure(options, nic, "nic_setup", error);
        rte_mempool_free(pool);
        fk_trace_sidecar_close(&sidecar);
        return 1;
    }

    std::fprintf(
        stdout,
        "FLOWKEEP_EXACT_RX_READY port=%u queue=0 expected=%u "
        "capability_promoted=pending proof_required=%s "
        "scope=single_rx_queue_single_fixed_owner_finite_replay\n",
        options.port,
        options.expected_packets,
        json_bool(options.require_quic_identity_proof));
    std::fflush(stdout);

    LiveSource source(
        options.port,
        options.expected_packets,
        options.maximum_captured_length,
        options.idle_timeout_ms,
        &sidecar,
        options.expected_wire_source_mac,
        nic.mac);
    fk_no_nic_decision_trace_csv_writer trace_writer;
    std::unique_ptr<fk_no_nic_detector_request_trace_csv_writer>
        trace_features_writer;
    if (options.decision_trace != nullptr &&
        !trace_writer.open_exclusive(options.decision_trace)) {
        std::fputs("cannot create decision trace output exclusively\n", stderr);
        stop_port(options.port, nic);
        rte_mempool_free(pool);
        fk_trace_sidecar_close(&sidecar);
        return 2;
    }
    if (options.decision_trace_features != nullptr) {
        trace_features_writer.reset(
            new (std::nothrow)
                fk_no_nic_detector_request_trace_csv_writer());
        if (trace_features_writer == nullptr ||
            !trace_features_writer->open_exclusive(
                options.decision_trace_features)) {
            std::fputs(
                "cannot create decision trace features output exclusively\n",
                stderr);
            stop_port(options.port, nic);
            rte_mempool_free(pool);
            fk_trace_sidecar_close(&sidecar);
            return 2;
        }
    }
    fk_no_nic_full_composition_config configuration{};
    fk_no_nic_full_composition_default_config_init(&configuration);
    configuration.budget_mode = options.budget;
    configuration.packet_count = options.expected_packets;
    configuration.bridge_epoch_packet_limit =
        options.expected_packets <= UINT32_MAX - 64u
            ? options.expected_packets + 64u : options.expected_packets;
    configuration.completion_window_capacity = 64u;
    configuration.sequencer_ingress_capacity = 64u;
    configuration.rx_burst_capacity = options.burst;
    configuration.maximum_flows = options.maximum_flows;
    configuration.maximum_quic_connections =
        options.maximum_quic_connections;
    configuration.pool_weights = options.pool_weights;
    configuration.baseline_policy.kind = options.retention_policy;
    configuration.baseline_policy.maximum_lru_victims_per_decision = 64u;
    if (!fk_fixed_ttl_retention_bind_baseline(
            options.retention_policy,
            &options.fixed_ttl_retention,
            &configuration.baseline_policy)) {
        std::snprintf(
            error, sizeof(error),
            "invalid fixed-TTL nanosecond binding");
        (void)write_failure(
            options, nic, "configuration", error, &source);
        stop_port(options.port, nic);
        rte_mempool_free(pool);
        fk_trace_sidecar_close(&sidecar);
        return 2;
    }
    configuration.idle_timeout_ns = kFlowIdleTimeoutNs;
    configuration.terminal_semantic_timestamp_ns =
        sidecar.last_timestamp_ns + kFlowIdleTimeoutNs + 1u;
    configuration.maximum_run_iterations = UINT64_MAX;
    configuration.action_value_model_path = resolved_action_model(options);
    if (options.value_model_v3_artifact != nullptr) {
        configuration.value_model_v3.artifact_path =
            options.value_model_v3_artifact;
        configuration.value_model_v3.artifact_sha256 =
            options.value_model_v3_artifact_sha;
        configuration.value_model_v3.training_receipt_sha256 =
            options.value_model_v3_training_receipt_sha;
        configuration.value_model_v3.online_context_schema_sha256 =
            options.value_model_v3_schema_sha;
        configuration.value_model_v3.requested_action_domain_sha256 =
            options.value_model_v3_action_domain_sha;
        configuration.value_model_v3.online_deadline_contract_sha256 =
            options.value_model_v3_deadline_contract_sha;
        configuration.value_model_v3.expected_role =
            options.value_model_v3_role;
    }
    configuration.detector_model_path = options.detector_model;
    std::array<std::string, 8> detector_state_models{};
    if (options.detector_state_model_dir != nullptr) {
        for (uint8_t mask = 0u; mask < 8u; ++mask) {
            detector_state_models[mask] =
                std::string(options.detector_state_model_dir) +
                "/state_" + std::to_string(mask) + ".fkmodel";
            configuration.detector_state_model_paths[mask] =
                detector_state_models[mask].c_str();
        }
    }
    configuration.action_schema_sha256 = options.action_schema;
    configuration.detector_schema_sha256 = options.detector_schema;
    if (options.aggregation_mode != nullptr) {
        configuration.frozen_causal_aggregation.mode =
            FK_NO_NIC_EVENT_AGGREGATION_FROZEN_CPP_CAUSAL;
        configuration.frozen_causal_aggregation.threshold =
            options.aggregation_threshold;
        configuration.frozen_causal_aggregation.threshold_profile =
            options.aggregation_threshold_profile;
        configuration.frozen_causal_aggregation
            .aggregation_contract_sha256 = options.aggregation_contract_sha;
        configuration.frozen_causal_aggregation
            .development_oof_receipt_sha256 =
                options.development_oof_receipt_sha;
        configuration.frozen_causal_aggregation
            .causal_event_calibrator_artifact_path =
                options.causal_event_calibrator_artifact;
        configuration.frozen_causal_aggregation
            .causal_event_calibrator_artifact_sha256 =
                options.causal_event_calibrator_artifact_sha;
        configuration.frozen_causal_aggregation
            .causal_event_calibrator_source_npz_sha256 =
                options.causal_event_calibrator_source_npz_sha;
        configuration.frozen_causal_aggregation
            .causal_event_feature_contract_sha256 =
                options.causal_event_calibrator_feature_contract_sha;
        configuration.frozen_causal_aggregation
            .causal_event_real_prefix_receipt_sha256 =
                options.causal_event_calibrator_real_prefix_receipt_sha;
    }
    if (options.event_student_artifact != nullptr) {
        configuration.event_student_artifact_path =
            options.event_student_artifact;
        configuration.event_student_load_config.expected_artifact_sha256 =
            options.event_student_artifact_sha;
        configuration.event_student_load_config
            .expected_feature_schema_sha256 =
                options.event_student_feature_schema_sha;
        configuration.event_student_load_config.expected_source_state_sha256 =
            options.event_student_source_state_sha;
        configuration.event_student_load_config.expected_hidden =
            options.event_student_hidden;
        configuration.event_student_load_config
            .expected_identity_embedding =
                options.event_student_identity_embedding;
    }
    if (options.monitored_cidr != nullptr) {
        fk_actor_session_config_init(&configuration.actor_session);
        if (!fk_actor_session_config_add_cidr_text(
                &configuration.actor_session, options.monitored_cidr)) {
            std::snprintf(error, sizeof(error), "invalid monitored CIDR");
            (void)write_failure(
                options, nic, "actor_session_config", error, &source);
            stop_port(options.port, nic);
            rte_mempool_free(pool);
            fk_trace_sidecar_close(&sidecar);
            return 2;
        }
    }
    /* Keep finite-live and finite-PCAP formal paths on the same independent,
     * preallocated detection-service capacity contract. */
    configuration.actor_session.maximum_events =
        FK_ACTOR_SESSION_MAX_EVENTS;
    configuration.actor_session.maximum_total_flows =
        FK_ACTOR_SESSION_DEFAULT_TOTAL_FLOWS;
    configuration.preserve_actor_session_capacities = 1u;
    configuration.burst_context = &source;
    configuration.burst = LiveSource::burst_callback;
    configuration.clock_context = &source;
    configuration.clock = LiveSource::clock_callback;
    configuration.decode_context = &source;
    configuration.decode = LiveSource::decode_callback;
    configuration.reclaim_context = &source;
    configuration.reclaim = LiveSource::reclaim_callback;
    configuration.monotonic_clock_context = &source;
    configuration.monotonic_now_ns = LiveSource::clock_callback;
    configuration.io_stats_context = &source;
    configuration.io_stats = LiveSource::stats_callback;
    if (options.decision_trace != nullptr) {
        configuration.decision_trace_context = &trace_writer;
        configuration.decision_trace_sink =
            fk_no_nic_decision_trace_csv_writer::sink;
        if (options.decision_trace_features != nullptr) {
            configuration.decision_trace_features_context =
                trace_features_writer.get();
            configuration.decision_trace_features_sink =
                fk_no_nic_detector_request_trace_csv_writer::sink;
        }
    }
    configuration.external_io = 1u;

    fk_no_nic_full_composition_result result{};
    const bool pipeline_ok = fk_no_nic_full_composition_run(
        &configuration, &result, error, sizeof(error));
    if (!pipeline_ok)
        (void)source.recover_after_failure();
    DecisionTraceFeaturesReceipt trace_features{};
    trace_features.enabled = options.decision_trace_features != nullptr;
    const bool main_trace_finished = trace_writer.finish();
    const bool feature_trace_finished = trace_features_writer == nullptr ||
        trace_features_writer->finish();
    const bool trace_finished =
        main_trace_finished && feature_trace_finished;
    trace_features.rows = trace_features_writer == nullptr
        ? 0u : trace_features_writer->records();
    trace_features.row_conservation_valid = !trace_features.enabled ||
        trace_features.rows == result.observability.checkpoint_records;
    if (trace_features.enabled && trace_finished) {
        trace_features.sha256_valid = sha256_file(
            options.decision_trace_features, trace_features.sha256);
    }
    const bool trace_ok = trace_finished &&
        (options.decision_trace == nullptr ||
         trace_writer.records() ==
             result.observability.decision_records +
                 result.observability.evidence_transition_records) &&
        trace_features.row_conservation_valid &&
        (!trace_features.enabled || trace_features.sha256_valid);
    stop_port(options.port, nic);
    const fk_finite_live_quic_correctness_gate_input quic_gate_input =
        make_quic_correctness_gate_input(
            options, sidecar, source, nic, result);
    const fk_finite_live_quic_correctness_gate_result quic_gate =
        fk_finite_live_quic_correctness_gate_evaluate(&quic_gate_input);
    int status = 0;
    if (!pipeline_ok) {
        (void)write_failure(
            options, nic, "finite_live_pipeline", error, &source, &result,
            &quic_gate);
        status = 1;
    } else if (!trace_ok) {
        (void)write_failure(
            options, nic, "decision_trace_receipt",
            "decision trace finalization/conservation failed",
            &source, &result, &quic_gate);
        status = 1;
    } else if (options.aggregation_mode == nullptr &&
               (result.trigger_receipt.conservation_valid == 0u ||
                result.trigger_receipt.final_flush_complete == 0u)) {
        (void)write_failure(
            options, nic, "event_student_trigger_receipt",
            "checkpoint+periodic V2 terminal receipt failed conservation",
            &source, &result, &quic_gate);
        status = 1;
    } else if (options.aggregation_mode != nullptr &&
               (result.frozen_causal_aggregation.abi_version !=
                    FK_NO_NIC_FROZEN_CAUSAL_AGGREGATION_RECEIPT_ABI_VERSION ||
                result.frozen_causal_aggregation.enabled == 0u ||
                result.frozen_causal_aggregation.complete == 0u ||
                result.frozen_causal_aggregation.deterministic_smoke_model !=
                    0u ||
                (options.causal_event_calibrator_artifact != nullptr &&
                 (result.frozen_causal_aggregation.calibrator_enabled == 0u ||
                  result.frozen_causal_aggregation.model_loaded == 0u ||
                  result.frozen_causal_aggregation.model_used == 0u ||
                  result.frozen_causal_aggregation.model_load_failures != 0u ||
                  result.frozen_causal_aggregation.inference_failures != 0u)) ||
                std::strcmp(
                    result.frozen_causal_aggregation.aggregation_rule,
                    options.aggregation_rule) != 0 ||
                std::strcmp(
                    result.frozen_causal_aggregation.threshold_profile,
                    options.aggregation_threshold_profile) != 0 ||
                result.frozen_causal_aggregation.threshold !=
                    options.aggregation_threshold ||
                std::strcmp(
                    result.frozen_causal_aggregation
                        .aggregation_contract_sha256,
                    options.aggregation_contract_sha) != 0 ||
                std::strcmp(
                    result.frozen_causal_aggregation
                        .development_oof_receipt_sha256,
                    options.development_oof_receipt_sha) != 0)) {
        (void)write_failure(
            options, nic, "frozen_causal_aggregation_receipt",
            "online frozen causal aggregation failed closed",
            &source, &result, &quic_gate);
        status = 1;
    } else if (result.detection_service_capacity.abi_version !=
                   FK_NO_NIC_DETECTION_SERVICE_CAPACITY_RECEIPT_ABI_VERSION ||
               result.detection_service_capacity.actor_maximum_events !=
                   FK_ACTOR_SESSION_MAX_EVENTS ||
               result.detection_service_capacity
                       .actor_maximum_total_flows !=
                   FK_ACTOR_SESSION_DEFAULT_TOTAL_FLOWS ||
               result.detection_service_capacity
                       .actor_maximum_flows_per_event !=
                   FK_ACTOR_SESSION_MAX_FLOWS_PER_EVENT ||
               result.detection_service_capacity
                       .actor_event_capacity_evictions != 0u ||
               result.detection_service_capacity
                       .actor_total_flow_capacity_evictions != 0u ||
               result.detection_service_capacity
                       .actor_flow_capacity_rollovers != 0u ||
               result.detection_service_capacity
                       .window_live_slot_reuse_conflicts != 0u ||
               result.detection_service_capacity.capacity_clean == 0u) {
        (void)write_failure(
            options, nic, "detection_service_capacity",
            "actor/window capacity receipt failed closed",
            &source, &result, &quic_gate);
        status = 1;
    } else if (result.maximum_quic_connections_configured !=
                   options.maximum_quic_connections ||
               result.quic_cid_connection_capacity !=
                   options.maximum_quic_connections ||
               result.quic_path_connection_capacity !=
                   options.maximum_quic_connections ||
               result.owner_binding_connection_capacity !=
                   options.maximum_quic_connections) {
        (void)write_failure(
            options, nic, "quic_identity_capacity",
            "configured/actual QUIC identity capacities diverged",
            &source, &result, &quic_gate);
        status = 1;
    } else if (!fk_no_nic_service_memory_receipt_verify_v1(
                   &result.service_memory)) {
        (void)write_failure(
            options, nic, "service_memory_receipt",
            "service-memory result receipt failed verification",
            &source, &result, &quic_gate);
        status = 1;
    } else if (!nic.end_valid || !nic.counters_monotonic ||
               !nic.promiscuous_disabled || !nic.mtu_restored ||
               !nic.stop_succeeded || !nic.close_succeeded) {
        (void)write_failure(
            options, nic, "nic_terminal_receipt",
            "NIC terminal counters/promiscuous/MTU/stop/close receipt incomplete",
            &source, &result, &quic_gate);
        status = 1;
    } else if (nic.delta.ipackets < options.expected_packets ||
               nic.delta.imissed != 0u || nic.delta.ierrors != 0u ||
               nic.delta.rx_nombuf != 0u) {
        (void)write_failure(
            options, nic, "nic_loss_gate",
            "NIC exact-receipt/drop/error gate failed", &source, &result,
            &quic_gate);
        status = 1;
    } else if (source.restored_packets() != options.expected_packets ||
               source.crc_verified_packets() != options.expected_packets ||
               source.invalid_shim_packets() != 0u ||
               source.decode_failures() != 0u ||
               source.tracking_failures() != 0u) {
        (void)write_failure(
            options, nic, "transport_restore_gate",
            "strict sequence/CRC/original-byte restoration gate failed",
            &source, &result, &quic_gate);
        status = 1;
    } else if (options.require_quic_identity_proof &&
               !quic_gate.scoped_capability_promoted) {
        char gate_error[160]{};
        std::snprintf(
            gate_error,
            sizeof(gate_error),
            "actual-NIC finite QUIC correctness gate blocked: mask=0x%016" PRIx64,
            quic_gate.blocker_mask);
        (void)write_failure(
            options, nic, "quic_actual_nic_correctness_gate",
            gate_error, &source, &result, &quic_gate);
        status = 1;
    } else if (!write_success(
                   options, sidecar, source, nic, result, trace_features,
                   quic_gate)) {
        std::fputs("failed to write finite live RX JSON\n", stderr);
        status = 1;
    }
    rte_mempool_free(pool);
    fk_trace_sidecar_close(&sidecar);
    return status;
}

}  // namespace

extern "C" int fk_dpdk_finite_live_runner_entry_after_eal(
        int argc,
        char **argv) {
    try {
        return runner_impl(argc, argv);
    } catch (const std::bad_alloc &) {
        std::fputs("finite live RX allocation failed\n", stderr);
        return 1;
    } catch (...) {
        std::fputs("finite live RX internal exception\n", stderr);
        return 1;
    }
}
