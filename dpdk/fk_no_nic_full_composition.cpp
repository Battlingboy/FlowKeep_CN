#define _POSIX_C_SOURCE 200809L

#include "fk_no_nic_full_composition.h"

#include "fk_checkpoint_reorder.h"
#include "fk_causal_event_calibrator.h"
#include "fk_causal_event_features.h"
#include "fk_compact_flow_table.h"
#include "fk_compact_runtime.h"
#include "fk_detection_event_path.h"
#include "fk_dpdk_exact_identity_mbuf_source.h"
#include "fk_dpdk_exact_rx_producer_pump.h"
#include "fk_dpdk_owner_mbuf_bytes_source.h"
#include "fk_exact_identity_router.h"
#include "fk_exact_identity_rx_worker_pump.h"
#include "fk_exact_identity_sequencer.h"
#include "fk_fixed_ttl_retention_contract.h"
#include "fk_fixed_owner_worker_pump.h"
#include "fk_no_nic_controlled_state_sizing.h"
#include "fk_owner_dispatch.h"
#include "fk_owner_flow_bindings.h"
#include "fk_owner_output_batch_ring.h"
#include "fk_owner_output_sequence_bridge.h"
#include "fk_owner_pipeline_abort_coordinator.h"
#include "fk_owner_runtime_adapter.h"
#include "fk_online_event_windows.h"
#include "fk_quic_cid_map.h"
#include "fk_quic_initial_crypto_admission_gate.h"
#include "fk_quic_presentation_path_directory.h"
#include "fk_quic_retirement_publisher.h"
#include "fk_quic_route_receipt.h"
#include "fk_student_shards.h"

#include <rte_mbuf.h>

#include <openssl/crypto.h>
#include <openssl/evp.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <limits>
#include <memory>
#include <new>
#include <string>
#include <sys/stat.h>
#include <utility>
#include <vector>
#include <unistd.h>

namespace {

constexpr uint16_t kOwners = 1u;
constexpr uint16_t kProducers = 1u;
constexpr uint32_t kExternalMinimumOwnerQueueCapacity = 256u;
constexpr uint32_t kExternalRetirementControlsPerPrefix = 256u;

uint32_t external_owner_queue_capacity(uint32_t maximum_connections) {
    /* A successful observation call may publish every live connection's
     * retirement before its one DATA envelope. maximum_connections is capped
     * at UINT16_MAX by config validation, so this loop tops out at 65536. */
    uint32_t capacity = kExternalMinimumOwnerQueueCapacity;
    while (capacity <= maximum_connections)
        capacity <<= 1u;
    return capacity;
}
constexpr uint64_t kSemanticBase = UINT64_C(1000000000);
constexpr uint64_t kPhysicalBase = UINT64_C(2000000000);
constexpr char kSchema[] =
    "0123456789abcdef0123456789abcdef"
    "0123456789abcdef0123456789abcdef";

uint64_t steady_monotonic_ns() {
    return static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::nanoseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count());
}

uint32_t latency_histogram_bin(uint64_t value_ns) {
    if (value_ns == 0u)
        return 0u;
    const uint32_t leading =
        static_cast<uint32_t>(__builtin_clzll(value_ns));
    const uint32_t bin = 64u - leading;
    return bin > 63u ? 63u : bin;
}

uint64_t latency_histogram_percentile(
        const std::array<uint64_t,
            FK_NO_NIC_DECISION_TRACE_HISTOGRAM_BINS> &histogram,
        uint64_t count,
        uint32_t numerator,
        uint32_t denominator) {
    if (count == 0u)
        return 0u;
    const uint64_t target =
        (count * numerator + denominator - 1u) / denominator;
    uint64_t cumulative = 0u;
    for (uint32_t index = 0u; index < histogram.size(); ++index) {
        cumulative += histogram[index];
        if (cumulative >= target)
            return index == 0u ? 0u : UINT64_C(1) << (index - 1u);
    }
    return UINT64_C(1) << 62u;
}

uint64_t trace_hash_mix(uint64_t value, const void *bytes, size_t length) {
    constexpr uint64_t kFnvPrime = UINT64_C(1099511628211);
    const auto *cursor = static_cast<const uint8_t *>(bytes);
    for (size_t index = 0u; index < length; ++index) {
        value ^= cursor[index];
        value *= kFnvPrime;
    }
    return value;
}

struct QueueRegression {
    uint64_t samples = 0u;
    uint64_t origin_ns = 0u;
    uint64_t prior_ns = 0u;
    uint64_t prior_depth = 0u;
    uint64_t peak = 0u;
    double mean_time_ns = 0.0;
    double mean_depth = 0.0;
    double time_m2 = 0.0;
    double time_depth_covariance = 0.0;
    double peak_positive_slope_per_second = 0.0;

    bool observe(uint64_t now_ns, uint64_t depth) {
        if (now_ns == 0u || (samples != 0u && now_ns < prior_ns))
            return false;
        if (samples == 0u)
            origin_ns = now_ns;
        const double time_ns = static_cast<double>(now_ns - origin_ns);
        const double depth_value = static_cast<double>(depth);
        const uint64_t next_count = samples + 1u;
        const double delta_time = time_ns - mean_time_ns;
        const double delta_depth = depth_value - mean_depth;
        mean_time_ns += delta_time / static_cast<double>(next_count);
        mean_depth += delta_depth / static_cast<double>(next_count);
        time_m2 += delta_time * (time_ns - mean_time_ns);
        time_depth_covariance +=
            delta_time * (depth_value - mean_depth);
        if (samples != 0u && now_ns > prior_ns && depth > prior_depth) {
            const double slope = static_cast<double>(depth - prior_depth) *
                1.0e9 / static_cast<double>(now_ns - prior_ns);
            peak_positive_slope_per_second = std::max(
                peak_positive_slope_per_second, slope);
        }
        samples = next_count;
        prior_ns = now_ns;
        prior_depth = depth;
        peak = std::max(peak, depth);
        return true;
    }

    double ols_slope_per_second() const {
        return time_m2 > 0.0
            ? time_depth_covariance / time_m2 * 1.0e9 : 0.0;
    }
};

void set_error(char *error, size_t capacity, const char *message) {
    if (error != nullptr && capacity != 0u)
        std::snprintf(error, capacity, "%s", message);
}

bool checked_add_u64(uint64_t &value, uint64_t increment) {
    if (increment > std::numeric_limits<uint64_t>::max() - value)
        return false;
    value += increment;
    return true;
}

class ReceiptSha256 {
public:
    ReceiptSha256() : context_(EVP_MD_CTX_new()) {}
    ~ReceiptSha256() {
        if (context_ != nullptr)
            EVP_MD_CTX_free(context_);
    }
    ReceiptSha256(const ReceiptSha256 &) = delete;
    ReceiptSha256 &operator=(const ReceiptSha256 &) = delete;

    bool begin() {
        return context_ != nullptr &&
            EVP_DigestInit_ex(context_, EVP_sha256(), nullptr) == 1;
    }

    bool bytes(const void *value, size_t length) {
        return value != nullptr &&
            EVP_DigestUpdate(context_, value, length) == 1;
    }

    bool u8(uint8_t value) { return bytes(&value, sizeof(value)); }

    bool u16(uint16_t value) {
        const uint8_t encoded[2]{
            static_cast<uint8_t>(value >> 8u),
            static_cast<uint8_t>(value)};
        return bytes(encoded, sizeof(encoded));
    }

    bool u32(uint32_t value) {
        const uint8_t encoded[4]{
            static_cast<uint8_t>(value >> 24u),
            static_cast<uint8_t>(value >> 16u),
            static_cast<uint8_t>(value >> 8u),
            static_cast<uint8_t>(value)};
        return bytes(encoded, sizeof(encoded));
    }

    bool u64(uint64_t value) {
        const uint8_t encoded[8]{
            static_cast<uint8_t>(value >> 56u),
            static_cast<uint8_t>(value >> 48u),
            static_cast<uint8_t>(value >> 40u),
            static_cast<uint8_t>(value >> 32u),
            static_cast<uint8_t>(value >> 24u),
            static_cast<uint8_t>(value >> 16u),
            static_cast<uint8_t>(value >> 8u),
            static_cast<uint8_t>(value)};
        return bytes(encoded, sizeof(encoded));
    }

    bool finish(uint8_t digest[FK_NO_NIC_SERVICE_MEMORY_RECEIPT_SHA256_BYTES]) {
        unsigned int length = 0u;
        return digest != nullptr &&
            EVP_DigestFinal_ex(context_, digest, &length) == 1 &&
            length == FK_NO_NIC_SERVICE_MEMORY_RECEIPT_SHA256_BYTES;
    }

private:
    EVP_MD_CTX *context_ = nullptr;
};

bool receipt_digest(
        const fk_no_nic_service_memory_receipt_v1 &receipt,
        uint8_t digest[FK_NO_NIC_SERVICE_MEMORY_RECEIPT_SHA256_BYTES]) {
    static constexpr char kDomain[] =
        "flowkeep.no_nic.service_memory.receipt.v1";
    ReceiptSha256 hash;
    if (!hash.begin() || !hash.bytes(kDomain, sizeof(kDomain) - 1u) ||
        !hash.u32(receipt.abi_version) ||
        !hash.u32(receipt.component_count) ||
        !hash.u32(receipt.auxiliary_component_count) ||
        !hash.u32(receipt.active_component_mask) ||
        !hash.u32(receipt.inline_component_mask) ||
        !hash.u32(receipt.disabled_component_mask) ||
        !hash.u32(receipt.formal_non_active_component_mask) ||
        !hash.u32(receipt.auxiliary_active_mask) ||
        !hash.u64(receipt.trace_packet_count) ||
        !hash.u64(receipt.bridge_epoch_packet_limit) ||
        !hash.u32(receipt.completion_window_capacity) ||
        !hash.u32(receipt.checkpoint_payload_capacity) ||
        !hash.u32(receipt.sequencer_ingress_capacity) ||
        !hash.u32(receipt.sequencer_reorder_capacity) ||
        !hash.u32(receipt.rx_burst_capacity) ||
        !hash.u32(receipt.owner_dispatch_capacity) ||
        !hash.u32(receipt.owner_output_ring_capacity) ||
        !hash.u32(receipt.checkpoint_reorder_capacity) ||
        !hash.u16(receipt.producer_count) ||
        !hash.u16(receipt.owner_count) ||
        !hash.u64(receipt.component_configured_reserved_bytes) ||
        !hash.u64(receipt.component_observed_reserved_bytes) ||
        !hash.u64(receipt.component_peak_bytes) ||
        !hash.u64(receipt.auxiliary_configured_reserved_bytes) ||
        !hash.u64(receipt.auxiliary_observed_reserved_bytes) ||
        !hash.u64(receipt.auxiliary_peak_bytes) ||
        !hash.u64(receipt.total_configured_reserved_bytes) ||
        !hash.u64(receipt.total_observed_reserved_bytes) ||
        !hash.u64(receipt.total_peak_bytes) ||
        !hash.u64(receipt.trace_sized_active_reserved_bytes) ||
        !hash.u8(receipt.service_memory_separate_from_controlled_state) ||
        !hash.u8(receipt.component_accounting_exact) ||
        !hash.u8(receipt.auxiliary_accounting_exact) ||
        !hash.u8(receipt.active_reservations_trace_independent) ||
        !hash.u8(receipt.completion_transport_window_bounded) ||
        !hash.u8(receipt.external_source_window_bounded) ||
        !hash.u8(receipt.finite_epoch_handoff_required) ||
        !hash.u8(receipt.formal_14_component_complete) ||
        !hash.u8(receipt.post_run_hash_bound)) {
        return false;
    }
    const auto add_component = [&hash](
            uint32_t index,
            const fk_no_nic_service_memory_component_receipt_v1 &component) {
        return hash.u32(index) &&
            hash.u64(component.configured_reserved_bytes) &&
            hash.u64(component.observed_reserved_bytes) &&
            hash.u64(component.peak_bytes) &&
            hash.u8(component.disposition) &&
            hash.u8(component.reservation_exact) &&
            hash.u8(component.trace_independent) &&
            hash.u8(component.bounded_window) &&
            hash.u8(component.hash_bound);
    };
    for (uint32_t index = 0u;
         index < FK_IDENTITY_SERVICE_COMPONENT_COUNT; ++index) {
        if (!add_component(index, receipt.components[index]))
            return false;
    }
    for (uint32_t index = 0u;
         index < FK_NO_NIC_SERVICE_MEMORY_AUXILIARY_COMPONENT_COUNT;
         ++index) {
        if (!add_component(
                UINT32_C(0x80000000) | index,
                receipt.auxiliary_components[index])) {
            return false;
        }
    }
    return hash.finish(digest);
}

void set_memory_component(
        fk_no_nic_service_memory_component_receipt_v1 &component,
        uint64_t reserved_bytes,
        fk_no_nic_service_memory_disposition_v1 disposition,
        bool exact,
        bool trace_independent,
        bool bounded_window) {
    component = {};
    component.configured_reserved_bytes = reserved_bytes;
    component.observed_reserved_bytes = reserved_bytes;
    component.peak_bytes = reserved_bytes;
    component.disposition = static_cast<uint8_t>(disposition);
    component.reservation_exact = exact ? 1u : 0u;
    component.trace_independent = trace_independent ? 1u : 0u;
    component.bounded_window = bounded_window ? 1u : 0u;
    component.hash_bound = 1u;
}

bool reserved_zero(const uint8_t *bytes, size_t count) {
    if (bytes == nullptr)
        return false;
    for (size_t index = 0u; index < count; ++index) {
        if (bytes[index] != 0u)
            return false;
    }
    return true;
}

bool bit_value(uint32_t mask, uint32_t index) {
    return (mask & (UINT32_C(1) << index)) != 0u;
}

bool boolean_byte(uint8_t value) {
    return value == 0u || value == 1u;
}

bool validate_receipt_component(
        const fk_no_nic_service_memory_component_receipt_v1 &component,
        bool auxiliary,
        bool &active,
        bool &inline_component,
        bool &disabled,
        bool &trace_sized) {
    active = false;
    inline_component = false;
    disabled = false;
    trace_sized = false;
    if (!boolean_byte(component.reservation_exact) ||
        !boolean_byte(component.trace_independent) ||
        !boolean_byte(component.bounded_window) ||
        component.hash_bound != 1u ||
        !reserved_zero(component.reserved, sizeof(component.reserved))) {
        return false;
    }
    switch (component.disposition) {
    case FK_NO_NIC_SERVICE_MEMORY_ACTIVE_BOUNDED:
        active = true;
        return component.configured_reserved_bytes != 0u &&
            component.observed_reserved_bytes ==
                component.configured_reserved_bytes &&
            component.peak_bytes <= component.configured_reserved_bytes &&
            component.reservation_exact == 1u &&
            component.trace_independent == 1u &&
            component.bounded_window == 1u;
    case FK_NO_NIC_SERVICE_MEMORY_INLINE_NO_TRANSPORT:
        inline_component = true;
        return component.configured_reserved_bytes == 0u &&
            component.observed_reserved_bytes == 0u &&
            component.peak_bytes == 0u &&
            component.reservation_exact == 1u &&
            component.trace_independent == 1u &&
            component.bounded_window == 1u;
    case FK_NO_NIC_SERVICE_MEMORY_DISABLED:
        disabled = true;
        return component.configured_reserved_bytes == 0u &&
            component.observed_reserved_bytes == 0u &&
            component.peak_bytes == 0u &&
            component.reservation_exact == 1u &&
            component.trace_independent == 1u &&
            component.bounded_window == 1u;
    case FK_NO_NIC_SERVICE_MEMORY_TEST_ONLY_TRACE_SIZED:
        if (!auxiliary)
            return false;
        active = true;
        trace_sized = true;
        return component.configured_reserved_bytes != 0u &&
            component.observed_reserved_bytes ==
                component.configured_reserved_bytes &&
            component.peak_bytes <= component.configured_reserved_bytes &&
            component.reservation_exact == 0u &&
            component.trace_independent == 0u &&
            component.bounded_window == 0u;
    }
    return false;
}

bool receipt_semantics_valid(
        const fk_no_nic_service_memory_receipt_v1 &receipt) {
    constexpr uint32_t kFormalMask =
        (UINT32_C(1) << FK_IDENTITY_SERVICE_COMPONENT_COUNT) - 1u;
    constexpr uint32_t kAuxiliaryMask =
        (UINT32_C(1) <<
            FK_NO_NIC_SERVICE_MEMORY_AUXILIARY_COMPONENT_COUNT) - 1u;
    if (receipt.abi_version !=
            FK_NO_NIC_SERVICE_MEMORY_RECEIPT_ABI_VERSION ||
        receipt.component_count != FK_IDENTITY_SERVICE_COMPONENT_COUNT ||
        receipt.auxiliary_component_count !=
            FK_NO_NIC_SERVICE_MEMORY_AUXILIARY_COMPONENT_COUNT ||
        receipt.trace_packet_count == 0u ||
        receipt.bridge_epoch_packet_limit < receipt.trace_packet_count ||
        receipt.completion_window_capacity < 2u ||
        receipt.completion_window_capacity >
            receipt.bridge_epoch_packet_limit ||
        receipt.checkpoint_payload_capacity == 0u ||
        receipt.sequencer_ingress_capacity < 2u ||
        receipt.sequencer_reorder_capacity == 0u ||
        receipt.rx_burst_capacity == 0u ||
        receipt.owner_dispatch_capacity == 0u ||
        receipt.owner_output_ring_capacity == 0u ||
        receipt.checkpoint_reorder_capacity == 0u ||
        receipt.producer_count == 0u || receipt.owner_count == 0u ||
        (receipt.active_component_mask & ~kFormalMask) != 0u ||
        (receipt.inline_component_mask & ~kFormalMask) != 0u ||
        (receipt.disabled_component_mask & ~kFormalMask) != 0u ||
        (receipt.formal_non_active_component_mask & ~kFormalMask) != 0u ||
        (receipt.auxiliary_active_mask & ~kAuxiliaryMask) != 0u ||
        receipt.service_memory_separate_from_controlled_state != 1u ||
        !boolean_byte(receipt.component_accounting_exact) ||
        !boolean_byte(receipt.auxiliary_accounting_exact) ||
        !boolean_byte(receipt.active_reservations_trace_independent) ||
        receipt.completion_transport_window_bounded != 1u ||
        !boolean_byte(receipt.external_source_window_bounded) ||
        receipt.finite_epoch_handoff_required != 1u ||
        !boolean_byte(receipt.formal_14_component_complete) ||
        receipt.post_run_hash_bound != 1u ||
        !reserved_zero(receipt.reserved, sizeof(receipt.reserved))) {
        return false;
    }
    if ((receipt.active_component_mask & receipt.inline_component_mask) != 0u ||
        (receipt.active_component_mask & receipt.disabled_component_mask) !=
            0u ||
        (receipt.inline_component_mask & receipt.disabled_component_mask) !=
            0u ||
        (receipt.active_component_mask | receipt.inline_component_mask |
            receipt.disabled_component_mask) != kFormalMask ||
        receipt.formal_non_active_component_mask !=
            (receipt.inline_component_mask |
                receipt.disabled_component_mask) ||
        receipt.formal_14_component_complete !=
            (receipt.formal_non_active_component_mask == 0u ? 1u : 0u)) {
        return false;
    }

    uint64_t component_configured = 0u;
    uint64_t component_observed = 0u;
    uint64_t component_peak = 0u;
    uint64_t auxiliary_configured = 0u;
    uint64_t auxiliary_observed = 0u;
    uint64_t auxiliary_peak = 0u;
    uint64_t trace_sized_reserved = 0u;
    bool component_exact = true;
    bool auxiliary_exact = true;
    bool all_active_trace_independent = true;
    for (uint32_t index = 0u;
         index < FK_IDENTITY_SERVICE_COMPONENT_COUNT; ++index) {
        const auto &component = receipt.components[index];
        bool active = false;
        bool inline_component = false;
        bool disabled = false;
        bool trace_sized = false;
        if (!validate_receipt_component(
                component, false, active, inline_component, disabled,
                trace_sized) ||
            bit_value(receipt.active_component_mask, index) != active ||
            bit_value(receipt.inline_component_mask, index) !=
                inline_component ||
            bit_value(receipt.disabled_component_mask, index) != disabled ||
            !checked_add_u64(
                component_configured,
                component.configured_reserved_bytes) ||
            !checked_add_u64(
                component_observed,
                component.observed_reserved_bytes) ||
            !checked_add_u64(component_peak, component.peak_bytes)) {
            return false;
        }
        component_exact = component_exact &&
            component.reservation_exact != 0u;
        if (active)
            all_active_trace_independent = all_active_trace_independent &&
                component.trace_independent != 0u;
    }
    for (uint32_t index = 0u;
         index < FK_NO_NIC_SERVICE_MEMORY_AUXILIARY_COMPONENT_COUNT;
         ++index) {
        const auto &component = receipt.auxiliary_components[index];
        bool active = false;
        bool inline_component = false;
        bool disabled = false;
        bool trace_sized = false;
        if (!validate_receipt_component(
                component, true, active, inline_component, disabled,
                trace_sized) || inline_component ||
            bit_value(receipt.auxiliary_active_mask, index) != active ||
            !checked_add_u64(
                auxiliary_configured,
                component.configured_reserved_bytes) ||
            !checked_add_u64(
                auxiliary_observed,
                component.observed_reserved_bytes) ||
            !checked_add_u64(auxiliary_peak, component.peak_bytes)) {
            return false;
        }
        auxiliary_exact = auxiliary_exact &&
            component.reservation_exact != 0u;
        if (active)
            all_active_trace_independent = all_active_trace_independent &&
                component.trace_independent != 0u;
        if (trace_sized && !checked_add_u64(
                trace_sized_reserved,
                component.configured_reserved_bytes)) {
            return false;
        }
    }
    uint64_t total_configured = component_configured;
    uint64_t total_observed = component_observed;
    uint64_t total_peak = component_peak;
    if (!checked_add_u64(total_configured, auxiliary_configured) ||
        !checked_add_u64(total_observed, auxiliary_observed) ||
        !checked_add_u64(total_peak, auxiliary_peak) ||
        receipt.component_configured_reserved_bytes != component_configured ||
        receipt.component_observed_reserved_bytes != component_observed ||
        receipt.component_peak_bytes != component_peak ||
        receipt.auxiliary_configured_reserved_bytes != auxiliary_configured ||
        receipt.auxiliary_observed_reserved_bytes != auxiliary_observed ||
        receipt.auxiliary_peak_bytes != auxiliary_peak ||
        receipt.total_configured_reserved_bytes != total_configured ||
        receipt.total_observed_reserved_bytes != total_observed ||
        receipt.total_peak_bytes != total_peak ||
        receipt.total_observed_reserved_bytes !=
            receipt.total_configured_reserved_bytes ||
        receipt.total_peak_bytes > receipt.total_configured_reserved_bytes ||
        receipt.trace_sized_active_reserved_bytes != trace_sized_reserved ||
        receipt.component_accounting_exact != (component_exact ? 1u : 0u) ||
        receipt.auxiliary_accounting_exact != (auxiliary_exact ? 1u : 0u) ||
        receipt.active_reservations_trace_independent !=
            (all_active_trace_independent ? 1u : 0u)) {
        return false;
    }
    const auto &source = receipt.auxiliary_components[
        FK_NO_NIC_SERVICE_AUX_EXTERNAL_SOURCE_WINDOW];
    if (receipt.external_source_window_bounded !=
            (source.disposition ==
                    FK_NO_NIC_SERVICE_MEMORY_ACTIVE_BOUNDED
                ? 1u : 0u)) {
        return false;
    }
    uint8_t observed[FK_NO_NIC_SERVICE_MEMORY_RECEIPT_SHA256_BYTES]{};
    return receipt_digest(receipt, observed) &&
        CRYPTO_memcmp(
            observed,
            receipt.receipt_sha256,
            sizeof(observed)) == 0;
}

struct AlignedStorage {
    size_t bytes = 0u;
    std::vector<std::max_align_t> words;

    bool allocate(size_t requested) {
        bytes = requested;
        if (bytes == 0u)
            return false;
        words.resize(
            (bytes + sizeof(std::max_align_t) - 1u) /
            sizeof(std::max_align_t));
        std::memset(words.data(), 0, words.size() * sizeof(words[0]));
        return true;
    }

    void *data() { return words.data(); }
    size_t capacity_bytes() const {
        return words.size() * sizeof(std::max_align_t);
    }
};

class TestModel {
public:
    TestModel() = default;
    TestModel(const TestModel &) = delete;
    TestModel &operator=(const TestModel &) = delete;

    ~TestModel() {
        if (exists_)
            (void)unlink(path_);
    }

    bool create(const char *pattern, const char *role) {
        if (pattern == nullptr || role == nullptr || exists_ ||
            std::snprintf(path_, sizeof(path_), "%s", pattern) <= 0)
            return false;
        const int descriptor = mkstemp(path_);
        if (descriptor < 0)
            return false;
        exists_ = true;
        FILE *stream = fdopen(descriptor, "w");
        if (stream == nullptr) {
            (void)close(descriptor);
            return false;
        }
        const bool action = std::strcmp(role, "action_value") == 0;
        const int written = std::fprintf(
            stream,
            "FLOWKEEP_CPU_MODEL 1\n"
            "role %s\n"
            "link %s\n"
            "feature_schema_sha256 %s\n"
            "feature_count %u\n"
            "output_count %u\n"
            "bias %s\n"
            "tree_count 0\n"
            "end\n",
            role,
            action ? "identity" : "sigmoid",
            kSchema,
            action ? FK_COMPACT_ACTION_FEATURES :
                FK_COMPACT_DETECTOR_FEATURES_V4,
            action ? 8u : 1u,
            action ? "0 0.1 0.2 0.3 0.4 0.5 0.9 0.7" : "0");
        const int close_result = std::fclose(stream);
        return written > 0 && close_result == 0;
    }

    bool unlink_after_load() {
        if (!exists_)
            return true;
        if (unlink(path_) != 0)
            return false;
        exists_ = false;
        return true;
    }

    const char *path() const { return path_; }

private:
    char path_[112]{};
    bool exists_ = false;
};

bool hex_digest(const char *text, uint8_t output[32]);

bool sha256_bytes(
        const uint8_t *bytes,
        size_t length,
        uint8_t digest[32]) {
    if (bytes == nullptr || digest == nullptr)
        return false;
    EVP_MD_CTX *context = EVP_MD_CTX_new();
    if (context == nullptr)
        return false;
    unsigned int output_length = 0u;
    const bool valid =
        EVP_DigestInit_ex(context, EVP_sha256(), nullptr) == 1 &&
        EVP_DigestUpdate(context, bytes, length) == 1 &&
        EVP_DigestFinal_ex(context, digest, &output_length) == 1 &&
        output_length == 32u;
    EVP_MD_CTX_free(context);
    return valid;
}

bool file_sha256_matches(const char *path, const char *expected_hex) {
    uint8_t expected[32]{};
    if (path == nullptr || !hex_digest(expected_hex, expected))
        return false;
    FILE *stream = std::fopen(path, "rb");
    if (stream == nullptr)
        return false;
    EVP_MD_CTX *context = EVP_MD_CTX_new();
    bool valid = context != nullptr &&
        EVP_DigestInit_ex(context, EVP_sha256(), nullptr) == 1;
    std::array<uint8_t, 16384u> buffer{};
    while (valid) {
        const size_t count = std::fread(buffer.data(), 1u, buffer.size(), stream);
        if (count != 0u &&
            EVP_DigestUpdate(context, buffer.data(), count) != 1) {
            valid = false;
            break;
        }
        if (count < buffer.size()) {
            if (std::ferror(stream))
                valid = false;
            break;
        }
    }
    uint8_t observed[32]{};
    unsigned int length = 0u;
    valid = valid &&
        EVP_DigestFinal_ex(context, observed, &length) == 1 &&
        length == sizeof(observed) &&
        CRYPTO_memcmp(observed, expected, sizeof(observed)) == 0;
    if (context != nullptr)
        EVP_MD_CTX_free(context);
    valid = std::fclose(stream) == 0 && valid;
    return valid;
}

void digest_hex(const uint8_t digest[32], char output[65]) {
    static constexpr char kHex[] = "0123456789abcdef";
    for (size_t index = 0u; index < 32u; ++index) {
        output[index * 2u] = kHex[digest[index] >> 4u];
        output[index * 2u + 1u] = kHex[digest[index] & 15u];
    }
    output[64] = '\0';
}

bool hex_digest(const char *text, uint8_t output[32]) {
    if (text == nullptr || output == nullptr || std::strlen(text) != 64u)
        return false;
    const auto nibble = [](char value, uint8_t &result) {
        if (value >= '0' && value <= '9') {
            result = static_cast<uint8_t>(value - '0');
            return true;
        }
        if (value >= 'a' && value <= 'f') {
            result = static_cast<uint8_t>(10 + value - 'a');
            return true;
        }
        return false;
    };
    for (size_t index = 0u; index < 32u; ++index) {
        uint8_t high = 0u;
        uint8_t low = 0u;
        if (!nibble(text[index * 2u], high) ||
            !nibble(text[index * 2u + 1u], low)) {
            return false;
        }
        output[index] = static_cast<uint8_t>((high << 4u) | low);
    }
    return true;
}

bool bounded_nonempty_text(const char *text, size_t capacity) {
    if (text == nullptr || capacity < 2u)
        return false;
    const size_t length = strnlen(text, capacity);
    return length != 0u && length < capacity;
}

bool frozen_causal_enabled(
        const fk_no_nic_full_composition_config &config) {
    return config.frozen_causal_aggregation.mode ==
        FK_NO_NIC_EVENT_AGGREGATION_FROZEN_CPP_CAUSAL;
}

bool causal_calibrator_enabled(
        const fk_no_nic_full_composition_config &config) {
    return frozen_causal_enabled(config) &&
        config.frozen_causal_aggregation
            .causal_event_calibrator_artifact_path != nullptr;
}

bool value_model_v3_enabled(
        const fk_no_nic_full_composition_config &config) {
    return config.value_model_v3.artifact_path != nullptr;
}

bool value_model_v3_config_valid(
        const fk_no_nic_full_composition_config &config) {
    const auto &value = config.value_model_v3;
    uint8_t digest[32]{};
    if (!value_model_v3_enabled(config)) {
        return value.artifact_sha256 == nullptr &&
            value.training_receipt_sha256 == nullptr &&
            value.online_context_schema_sha256 == nullptr &&
            value.requested_action_domain_sha256 == nullptr &&
            value.online_deadline_contract_sha256 == nullptr &&
            value.expected_role == 0;
    }
    return fk_compact_retention_policy_uses_learned_selector(
               config.baseline_policy.kind) &&
        (config.baseline_policy.kind !=
             FK_COMPACT_POLICY_LEARNED_DETECTION_LOSS_PER_BYTE ||
         value.expected_role == FK_VALUE_MODEL_V3_DETECTION_LOSS) &&
        bounded_nonempty_text(value.artifact_path, 4096u) &&
        config.action_value_model_path != nullptr &&
        std::strcmp(value.artifact_path, config.action_value_model_path) == 0 &&
        hex_digest(value.artifact_sha256, digest) &&
        hex_digest(value.training_receipt_sha256, digest) &&
        hex_digest(value.online_context_schema_sha256, digest) &&
        hex_digest(value.requested_action_domain_sha256, digest) &&
        hex_digest(value.online_deadline_contract_sha256, digest) &&
        config.action_schema_sha256 != nullptr &&
        std::strcmp(
            value.online_context_schema_sha256,
            config.action_schema_sha256) == 0 &&
        std::strcmp(
            value.requested_action_domain_sha256,
            FK_VALUE_MODEL_V3_REQUESTED_ACTION_DOMAIN_SHA256) == 0 &&
        std::strcmp(
            value.online_deadline_contract_sha256,
            FK_VALUE_MODEL_V3_ONLINE_DEADLINE_CONTRACT_SHA256) == 0 &&
        value.expected_role >= FK_VALUE_MODEL_V3_FLOWKEEP &&
        value.expected_role <= FK_VALUE_MODEL_V3_DETECTION_LOSS;
}

bool transition_value_config_valid(
        const fk_no_nic_full_composition_config &config) {
    const bool requested = config.transition_value_model_path != nullptr ||
        config.transition_value_schema_sha256 != nullptr ||
        config.transition_value_model_sha256 != nullptr;
    if (!requested)
        return true;
    uint8_t digest[32]{};
    return config.baseline_policy.kind == FK_COMPACT_POLICY_FLOWKEEP &&
        value_model_v3_enabled(config) &&
        config.value_model_v3.expected_role == FK_VALUE_MODEL_V3_FLOWKEEP &&
        bounded_nonempty_text(config.transition_value_model_path, 4096u) &&
        hex_digest(config.transition_value_schema_sha256, digest) &&
        hex_digest(config.transition_value_model_sha256, digest);
}

bool frozen_causal_config_valid(
        const fk_no_nic_full_composition_config &config) {
    if (!frozen_causal_enabled(config))
        return config.frozen_causal_aggregation.mode ==
            FK_NO_NIC_EVENT_AGGREGATION_EVENT_STUDENT;
    uint8_t digest[32]{};
    const bool calibrator = causal_calibrator_enabled(config);
    const auto &frozen = config.frozen_causal_aggregation;
    const bool calibrator_binding_valid = calibrator
        ? bounded_nonempty_text(
              frozen.causal_event_calibrator_artifact_path, 4096u) &&
          hex_digest(
              frozen.causal_event_calibrator_artifact_sha256, digest) &&
          hex_digest(
              frozen.causal_event_calibrator_source_npz_sha256, digest) &&
          hex_digest(
              frozen.causal_event_feature_contract_sha256, digest) &&
          hex_digest(
              frozen.causal_event_real_prefix_receipt_sha256, digest)
        : frozen.causal_event_calibrator_artifact_sha256 == nullptr &&
          frozen.causal_event_calibrator_source_npz_sha256 == nullptr &&
          frozen.causal_event_feature_contract_sha256 == nullptr &&
          frozen.causal_event_real_prefix_receipt_sha256 == nullptr;
    return calibrator_binding_valid &&
        config.event_student_artifact_path == nullptr &&
        std::isfinite(config.frozen_causal_aggregation.threshold) &&
        config.frozen_causal_aggregation.threshold > 0.0f &&
        config.frozen_causal_aggregation.threshold <= 1.0f &&
        bounded_nonempty_text(
            config.frozen_causal_aggregation.threshold_profile,
            FK_NO_NIC_FROZEN_CAUSAL_TEXT_BYTES) &&
        hex_digest(
            config.frozen_causal_aggregation.aggregation_contract_sha256,
            digest) &&
        hex_digest(
            config.frozen_causal_aggregation.development_oof_receipt_sha256,
            digest);
}

void write_le32(uint8_t *bytes, size_t offset, uint32_t value) {
    bytes[offset] = static_cast<uint8_t>(value);
    bytes[offset + 1u] = static_cast<uint8_t>(value >> 8u);
    bytes[offset + 2u] = static_cast<uint8_t>(value >> 16u);
    bytes[offset + 3u] = static_cast<uint8_t>(value >> 24u);
}

void write_le64(uint8_t *bytes, size_t offset, uint64_t value) {
    write_le32(bytes, offset, static_cast<uint32_t>(value));
    write_le32(bytes, offset + 4u, static_cast<uint32_t>(value >> 32u));
}

void write_le_float(uint8_t *bytes, size_t offset, float value) {
    uint32_t bits = 0u;
    static_assert(sizeof(bits) == sizeof(value), "float32 is required");
    std::memcpy(&bits, &value, sizeof(bits));
    write_le32(bytes, offset, bits);
}

class TestEventStudent {
public:
    TestEventStudent() = default;
    TestEventStudent(const TestEventStudent &) = delete;
    TestEventStudent &operator=(const TestEventStudent &) = delete;

    ~TestEventStudent() {
        if (exists_)
            (void)unlink(path_);
    }

    bool create() {
        static constexpr size_t kHeaderBytes = 256u;
        static constexpr uint32_t kHidden = 2u;
        static constexpr uint32_t kEmbedding = 1u;
        static constexpr uint32_t kEventHidden = 1u;
        static constexpr char kArchitecture[] =
            "flowkeep.strict_causal_event_student.v1;continuous=119;input=159;"
            "ja4_fields=10;ja4_tables=2;vocab=4097;normalizer=clamp10;"
            "encoder=linear-ln-gelu-linear-gelu;"
            "identity=embedding-projection-gelu;fusion=linear-ln-gelu;"
            "flow_pool=attention;window_head=linear-gelu-linear;"
            "event_pool=causal_attention;event_head=ln-linear-gelu-linear;"
            "gelu=erf;ln_eps=1e-5";
        if (exists_ || std::snprintf(
                path_, sizeof(path_),
                "/tmp/fk_no_nic_event_student.XXXXXX") <= 0) {
            return false;
        }
        uint64_t parameter_count = 0u;
        const auto add = [&parameter_count](uint64_t rows, uint64_t columns) {
            if (rows != 0u && columns > UINT64_MAX / rows)
                return false;
            const uint64_t amount = rows * columns;
            if (amount > UINT64_MAX - parameter_count)
                return false;
            parameter_count += amount;
            return true;
        };
        const uint64_t identity_width =
            FK_EVENT_STUDENT_JA4_FIELDS *
            FK_EVENT_STUDENT_JA4_TABLES * kEmbedding;
        const uint64_t fusion_width = kHidden * 2u + 1u;
        const bool count_valid =
            add(FK_EVENT_STUDENT_CONTINUOUS_FEATURES, 1u) &&
            add(FK_EVENT_STUDENT_CONTINUOUS_FEATURES, 1u) &&
            add(kHidden, FK_EVENT_STUDENT_CONTINUOUS_FEATURES) &&
            add(kHidden, 1u) && add(kHidden, 1u) && add(kHidden, 1u) &&
            add(kHidden, kHidden) && add(kHidden, 1u) &&
            add(FK_EVENT_STUDENT_JA4_FIELDS *
                    FK_EVENT_STUDENT_JA4_TABLES *
                    FK_EVENT_STUDENT_JA4_VOCABULARY,
                kEmbedding) &&
            add(kHidden, identity_width) && add(kHidden, 1u) &&
            add(kHidden, fusion_width) && add(kHidden, 1u) &&
            add(kHidden, 1u) && add(kHidden, 1u) &&
            add(kHidden, 1u) && add(1u, 1u) &&
            add(kHidden, kHidden) && add(kHidden, 1u) &&
            add(kHidden, 1u) && add(1u, 1u) &&
            add(kHidden, 1u) && add(1u, 1u) &&
            add(kHidden, 1u) && add(kHidden, 1u) &&
            add(kEventHidden, kHidden) && add(kEventHidden, 1u) &&
            add(kEventHidden, 1u) && add(1u, 1u);
        if (!count_valid || parameter_count > UINT32_MAX ||
            parameter_count > (SIZE_MAX - kHeaderBytes) / 4u) {
            return false;
        }
        std::vector<uint8_t> bytes(
            kHeaderBytes + static_cast<size_t>(parameter_count) * 4u, 0u);
        const uint8_t magic[8]{'F', 'K', 'E', 'S', 'V', '1', 0u, 0u};
        std::memcpy(bytes.data(), magic, sizeof(magic));
        write_le32(bytes.data(), 8u, FK_EVENT_STUDENT_FORMAT_VERSION);
        write_le32(bytes.data(), 12u, UINT32_C(0x01020304));
        write_le32(bytes.data(), 16u, static_cast<uint32_t>(kHeaderBytes));
        write_le32(bytes.data(), 20u, 1u);
        write_le64(bytes.data(), 24u, parameter_count * 4u);
        write_le32(bytes.data(), 32u, static_cast<uint32_t>(parameter_count));
        write_le32(bytes.data(), 36u, FK_EVENT_STUDENT_CONTINUOUS_FEATURES);
        write_le32(bytes.data(), 40u, FK_EVENT_STUDENT_INPUT_FEATURES);
        write_le32(bytes.data(), 44u, FK_EVENT_STUDENT_JA4_FIELDS);
        write_le32(bytes.data(), 48u, FK_EVENT_STUDENT_JA4_TABLES);
        write_le32(bytes.data(), 52u, FK_EVENT_STUDENT_JA4_VOCABULARY);
        write_le32(bytes.data(), 56u, kHidden);
        write_le32(bytes.data(), 60u, kEmbedding);
        write_le32(bytes.data(), 64u, kEventHidden);
        write_le32(bytes.data(), 68u, FK_EVENT_STUDENT_MAX_FLOWS_PER_WINDOW);
        write_le_float(bytes.data(), 72u, 1.0e-5f);
        write_le_float(bytes.data(), 76u, 0.5f);
        uint8_t schema[32]{};
        uint8_t architecture[32]{};
        if (!hex_digest(kSchema, schema) ||
            !sha256_bytes(
                reinterpret_cast<const uint8_t *>(kArchitecture),
                sizeof(kArchitecture) - 1u,
                architecture)) {
            return false;
        }
        std::memcpy(bytes.data() + 80u, schema, sizeof(schema));
        std::memcpy(bytes.data() + 112u, architecture, sizeof(architecture));
        std::memcpy(bytes.data() + 144u, schema, sizeof(schema));
        /* Zero weights produce deterministic 0 logits.  The only strict
         * loader invariant on parameters is a positive feature scale. */
        for (uint32_t index = 0u;
             index < FK_EVENT_STUDENT_CONTINUOUS_FEATURES; ++index) {
            write_le_float(
                bytes.data(),
                kHeaderBytes +
                    (FK_EVENT_STUDENT_CONTINUOUS_FEATURES + index) * 4u,
                1.0f);
        }
        uint8_t payload_digest[32]{};
        if (!sha256_bytes(
                bytes.data() + kHeaderBytes,
                bytes.size() - kHeaderBytes,
                payload_digest)) {
            return false;
        }
        std::memcpy(
            bytes.data() + 176u, payload_digest, sizeof(payload_digest));
        uint8_t artifact_digest[32]{};
        if (!sha256_bytes(
                bytes.data(), bytes.size(), artifact_digest)) {
            return false;
        }
        digest_hex(artifact_digest, artifact_sha256_);
        const int descriptor = mkstemp(path_);
        if (descriptor < 0)
            return false;
        exists_ = true;
        FILE *stream = fdopen(descriptor, "wb");
        if (stream == nullptr) {
            (void)close(descriptor);
            return false;
        }
        const bool written = std::fwrite(
            bytes.data(), 1u, bytes.size(), stream) == bytes.size();
        return std::fclose(stream) == 0 && written;
    }

    bool unlink_after_load() {
        if (!exists_)
            return true;
        if (unlink(path_) != 0)
            return false;
        exists_ = false;
        return true;
    }

    const char *path() const { return path_; }

    fk_event_student_load_config load_config() const {
        fk_event_student_load_config config{};
        config.expected_artifact_sha256 = artifact_sha256_;
        config.expected_feature_schema_sha256 = kSchema;
        config.expected_source_state_sha256 = kSchema;
        config.expected_hidden = 2u;
        config.expected_identity_embedding = 1u;
        return config;
    }

private:
    char path_[112]{};
    char artifact_sha256_[65]{};
    bool exists_ = false;
};

void write_be16(uint8_t *bytes, size_t offset, uint16_t value) {
    bytes[offset] = static_cast<uint8_t>(value >> 8u);
    bytes[offset + 1u] = static_cast<uint8_t>(value);
}

void write_be32(uint8_t *bytes, size_t offset, uint32_t value) {
    bytes[offset] = static_cast<uint8_t>(value >> 24u);
    bytes[offset + 1u] = static_cast<uint8_t>(value >> 16u);
    bytes[offset + 2u] = static_cast<uint8_t>(value >> 8u);
    bytes[offset + 3u] = static_cast<uint8_t>(value);
}

struct TestPacket {
    alignas(RTE_CACHE_LINE_SIZE)
        std::array<uint8_t, sizeof(rte_mbuf)> mbuf_storage{};
    alignas(RTE_CACHE_LINE_SIZE) std::array<uint8_t, 256u> data{};
    uint64_t sequence = 0u;
    bool reclaimed = false;

    explicit TestPacket(uint64_t packet_sequence) : sequence(packet_sequence) {
        constexpr uint16_t frame_bytes = 14u + 20u + 20u;
        data[12] = 0x08u;
        data[13] = 0x00u;
        data[14] = 0x45u;
        write_be16(data.data(), 16u, 40u);
        data[22] = 64u;
        data[23] = 6u;
        data[26] = 10u;
        data[29] = 3u;
        data[30] = 10u;
        data[33] = 9u;
        write_be16(data.data(), 34u, 43123u);
        write_be16(data.data(), 36u, 443u);
        write_be32(
            data.data(), 38u,
            static_cast<uint32_t>(1000u + packet_sequence));
        write_be32(data.data(), 42u, 0u);
        data[46] = 0x50u;
        data[47] = FK_TCP_FLAG_ACK;
        write_be16(data.data(), 48u, 4096u);

        (void)new (mbuf_storage.data()) rte_mbuf{};
        mbuf()->buf_addr = data.data();
        mbuf()->buf_iova = RTE_BAD_IOVA;
        mbuf()->buf_len = static_cast<uint16_t>(data.size());
        mbuf()->data_off = 0u;
        mbuf()->data_len = frame_bytes;
        mbuf()->pkt_len = frame_bytes;
        mbuf()->nb_segs = 1u;
        mbuf()->next = nullptr;
        rte_mbuf_refcnt_set(mbuf(), 1u);
    }

    rte_mbuf *mbuf() {
        return reinterpret_cast<rte_mbuf *>(mbuf_storage.data());
    }
};

struct TraceIo {
    std::vector<std::unique_ptr<TestPacket>> packets;
    bool burst_issued = false;
    uint64_t clock_next = kPhysicalBase;
    uint64_t reclaim_attempts = 0u;
    uint64_t reclaim_successes = 0u;
    uint64_t duplicate_reclaims = 0u;

    TestPacket *find(const rte_mbuf *mbuf) const {
        for (const auto &packet : packets) {
            if (packet->mbuf() == mbuf)
                return packet.get();
        }
        return nullptr;
    }

    bool reclaim(rte_mbuf *mbuf) {
        reclaim_attempts++;
        TestPacket *packet = find(mbuf);
        if (packet == nullptr || packet->reclaimed) {
            duplicate_reclaims++;
            return false;
        }
        packet->reclaimed = true;
        reclaim_successes++;
        /* Poison only after the ownership transfer. Any later read is a test
         * failure in the real DPDK source adapters. */
        packet->mbuf()->ol_flags ^= UINT64_C(0x8000000000000000);
        return true;
    }

    bool all_reclaimed() const {
        if (reclaim_successes != packets.size() ||
            duplicate_reclaims != 0u)
            return false;
        for (const auto &packet : packets) {
            if (!packet->reclaimed)
                return false;
        }
        return true;
    }
};

bool rx_burst(
        void *context,
        uint16_t,
        uint16_t,
        rte_mbuf **output,
        uint16_t capacity,
        uint16_t *received) {
    if (context == nullptr || output == nullptr || received == nullptr)
        return false;
    auto &trace = *static_cast<TraceIo *>(context);
    *received = 0u;
    if (trace.burst_issued)
        return true;
    if (trace.packets.size() > capacity)
        return false;
    for (size_t index = 0u; index < trace.packets.size(); ++index)
        output[index] = trace.packets[index]->mbuf();
    *received = static_cast<uint16_t>(trace.packets.size());
    trace.burst_issued = true;
    return true;
}

bool rx_clock(void *context, uint64_t *timestamp) {
    if (context == nullptr || timestamp == nullptr)
        return false;
    (void)context;
    *timestamp = steady_monotonic_ns();
    return *timestamp != 0u;
}

bool rx_decode(
        void *context,
        const rte_mbuf *mbuf,
        uint16_t,
        uint64_t,
        uint64_t *sequence,
        uint64_t *semantic,
        uint32_t *wire_length) {
    if (context == nullptr || mbuf == nullptr || sequence == nullptr ||
        semantic == nullptr || wire_length == nullptr)
        return false;
    const auto &trace = *static_cast<const TraceIo *>(context);
    TestPacket *packet = trace.find(mbuf);
    if (packet == nullptr)
        return false;
    *sequence = packet->sequence;
    *semantic = kSemanticBase + packet->sequence;
    *wire_length = mbuf->pkt_len;
    return true;
}

bool rx_reclaim(void *context, rte_mbuf *mbuf) {
    return context != nullptr && mbuf != nullptr &&
        static_cast<TraceIo *>(context)->reclaim(mbuf);
}

bool exact_reclaim(void *context, uintptr_t handle) {
    return rx_reclaim(
        context, reinterpret_cast<rte_mbuf *>(handle));
}

bool dispatch_reclaim(
        void *context, uint16_t, uintptr_t handle) {
    return exact_reclaim(context, handle);
}

struct ExternalReclaimAdapter {
    void *context = nullptr;
    fk_dpdk_exact_rx_reclaim_callback reclaim = nullptr;
};

bool external_exact_reclaim(void *context, uintptr_t handle) {
    if (context == nullptr || handle == 0u)
        return false;
    const auto &adapter =
        *static_cast<const ExternalReclaimAdapter *>(context);
    return adapter.reclaim != nullptr &&
        adapter.reclaim(
            adapter.context, reinterpret_cast<rte_mbuf *>(handle));
}

bool external_dispatch_reclaim(
        void *context, uint16_t, uintptr_t handle) {
    return external_exact_reclaim(context, handle);
}

bool router_monotonic_now(void *context, uint64_t *now_ns) {
    return rx_clock(context, now_ns);
}

bool external_io_enabled(
        const fk_no_nic_full_composition_config &config) {
    return config.external_io == 1u;
}

uint64_t controlled_budget_bytes(
        fk_no_nic_full_composition_budget_mode mode) {
    switch (mode) {
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

bool pointers_all_present(
        const fk_no_nic_full_composition_config &config) {
    bool seven_state = true;
    for (uint8_t mask = 0u; mask < 8u; ++mask)
        seven_state = seven_state &&
            config.detector_state_model_paths[mask] != nullptr;
    const bool learned_selector =
        fk_compact_retention_policy_uses_learned_selector(
            config.baseline_policy.kind);
    const bool selector_binding = learned_selector
        ? config.action_value_model_path != nullptr &&
            config.action_schema_sha256 != nullptr
        : config.action_value_model_path == nullptr &&
            config.action_schema_sha256 == nullptr;
    return selector_binding &&
        (config.detector_model_path != nullptr || seven_state) &&
        config.detector_schema_sha256 != nullptr &&
        config.burst != nullptr && config.clock != nullptr &&
        config.decode != nullptr && config.reclaim != nullptr &&
        config.monotonic_now_ns != nullptr && config.io_stats != nullptr;
}

bool config_valid(const fk_no_nic_full_composition_config *config) {
    static constexpr uint8_t kZeroReserved[6]{};
    static constexpr uint8_t kZeroRolloverReserved[7]{};
    static constexpr uint8_t kZeroOwnerHashReserved[7]{};
    return config != nullptr &&
        (config->budget_mode ==
             FK_NO_NIC_FULL_COMPOSITION_BUDGET_16_MIB ||
         config->budget_mode ==
             FK_NO_NIC_FULL_COMPOSITION_BUDGET_32_MIB ||
         config->budget_mode ==
             FK_NO_NIC_FULL_COMPOSITION_BUDGET_64_MIB ||
         config->budget_mode ==
             FK_NO_NIC_FULL_COMPOSITION_BUDGET_128_MIB ||
         config->budget_mode ==
             FK_NO_NIC_FULL_COMPOSITION_BUDGET_UNLIMITED_FULL_STATE) &&
        config->packet_count != 0u &&
        config->packet_count < FK_EXACT_IDENTITY_SEQUENCER_MAX_PACKETS &&
        config->bridge_epoch_packet_limit >= config->packet_count &&
        config->completion_window_capacity >= 2u &&
        config->completion_window_capacity <=
            config->bridge_epoch_packet_limit &&
        config->sequencer_ingress_capacity >= 2u &&
        (config->sequencer_ingress_capacity &
            (config->sequencer_ingress_capacity - 1u)) == 0u &&
        config->rx_burst_capacity != 0u &&
        config->rx_burst_capacity <=
            FK_DPDK_EXACT_RX_PRODUCER_PUMP_MAX_BURST &&
        config->abort_after_identity_transfers < config->packet_count &&
        config->maximum_flows != 0u &&
        config->maximum_flows <= FK_ACTOR_SESSION_DEFAULT_TOTAL_FLOWS &&
        config->owner_hash_key_precommitted == 1u &&
        std::memcmp(
            config->reserved_owner_hash_key, kZeroOwnerHashReserved,
            sizeof(kZeroOwnerHashReserved)) == 0 &&
        config->maximum_quic_connections != 0u &&
        config->maximum_quic_connections <= config->maximum_flows &&
        config->preserve_actor_session_capacities <= 1u &&
        std::memcmp(
            config->reserved, kZeroReserved,
            sizeof(kZeroReserved)) == 0 &&
        config->enforce_flow_rollover_contract <= 1u &&
        std::memcmp(
            config->reserved_rollover_contract,
            kZeroRolloverReserved,
            sizeof(kZeroRolloverReserved)) == 0 &&
        ((config->decision_trace_features_sink == nullptr &&
          config->decision_trace_features_context == nullptr) ||
         (config->decision_trace_features_sink != nullptr &&
          config->decision_trace_features_context != nullptr &&
          config->decision_trace_sink != nullptr)) &&
        (config->enforce_flow_rollover_contract != 0u ||
         config->expected_flow_capacity_rollovers == 0u) &&
        (config->checkpoint_intervention.enabled == 0u ||
         (external_io_enabled(*config) &&
          config->abort_after_identity_transfers == 0u &&
          config->decision_trace_sink != nullptr &&
          config->checkpoint_intervention.source_packet_sequence <
              config->packet_count)) &&
        config->idle_timeout_ns != 0u &&
        std::isfinite(config->lambda_memory_per_byte) &&
        std::isfinite(config->retention_discount) &&
        std::isfinite(config->lambda_queue) &&
        std::isfinite(config->lambda_deadline) &&
        config->lambda_memory_per_byte >= 0.0f &&
        config->retention_discount >= 0.0f &&
        config->lambda_queue >= 0.0f &&
        config->lambda_deadline >= 0.0f &&
        frozen_causal_config_valid(*config) &&
        value_model_v3_config_valid(*config) &&
        transition_value_config_valid(*config) &&
        fk_actor_session_config_valid(&config->actor_session) &&
        (config->event_student_worker_count == 2u ||
         config->event_student_worker_count == 4u ||
         config->event_student_worker_count == 8u) &&
        config->event_student_command_queue_capacity != 0u &&
        (config->event_student_command_queue_capacity &
            (config->event_student_command_queue_capacity - 1u)) == 0u &&
        config->event_student_result_queue_capacity != 0u &&
        (config->event_student_result_queue_capacity &
            (config->event_student_result_queue_capacity - 1u)) == 0u &&
        ((config->external_io == 0u &&
          config->packet_count <= config->rx_burst_capacity) ||
         (external_io_enabled(*config) &&
          config->abort_after_identity_transfers == 0u &&
          config->terminal_semantic_timestamp_ns != 0u &&
          pointers_all_present(*config)));
}

}  // namespace

namespace {

struct FrozenCausalEventState {
    uint64_t event_id = 0u;
    uint64_t event_start_ns = 0u;
    uint64_t next_trigger_ordinal = 0u;
    uint32_t event_generation = 0u;
    uint32_t checkpoint_updates = 0u;
    uint32_t periodic_updates = 0u;
    float maximum_score = 0.0f;
    fk_causal_event_feature_state_v1 causal_features{};
    bool initialized = false;
    bool alert_latched = false;
};

class Composition {
public:
    Composition(
            const fk_no_nic_full_composition_config &configuration,
            fk_no_nic_full_composition_result &output,
            char *error_output,
            size_t error_output_capacity)
        : config_(configuration),
          result_(output),
          error_(error_output),
          error_capacity_(error_output_capacity) {
        result_ = {};
        result_.topology_smoke_only = 1u;
        external_reclaim_.context = config_.reclaim_context;
        external_reclaim_.reclaim = config_.reclaim;
        bridge_now_ns_ = 0u;
    }

    ~Composition() {
        /* Successful paths null every pointer in cleanup_normal/abort.  This
         * fallback is for initialization/run failures: no worker thread is
         * live in this no-NIC composition, so at minimum release the only
         * heap-owning runtime and destruct placement-only identity state
         * before their backing vectors disappear. */
        if (runtime_ != nullptr) {
            fk_compact_runtime_destroy(runtime_);
            runtime_ = nullptr;
        }
        if (student_shards_ != nullptr) {
            fk_student_shards_destroy(student_shards_);
            student_shards_ = nullptr;
        }
        event_path_ = nullptr;
        if (bindings_ != nullptr) {
            fk_owner_flow_bindings_destroy(bindings_);
            bindings_ = nullptr;
        }
        if (route_receipts_ != nullptr) {
            fk_quic_route_receipt_destroy(route_receipts_);
            route_receipts_ = nullptr;
        }
        if (path_directory_ != nullptr) {
            fk_quic_presentation_path_directory_destroy(path_directory_);
            path_directory_ = nullptr;
        }
        if (cid_map_ != nullptr) {
            fk_quic_cid_map_destroy(cid_map_);
            cid_map_ = nullptr;
        }
    }

    bool initialize() {
        if (!external_io_enabled(config_)) {
            for (uint32_t sequence = 0u; sequence < config_.packet_count;
                 ++sequence) {
                trace_.packets.push_back(
                    std::make_unique<TestPacket>(sequence));
            }
        }
        result_.packets_created = config_.packet_count;
        result_.evidence_transitions.abi_version =
            FK_NO_NIC_EVIDENCE_TRANSITION_RECEIPT_ABI_VERSION;
        if (!external_io_enabled(config_) &&
            (!action_model_.create(
                 "/tmp/fk_no_nic_full_action.XXXXXX", "action_value") ||
             !detector_model_.create(
                 "/tmp/fk_no_nic_full_detector.XXXXXX", "detector"))) {
            return fail("failed to create deterministic smoke models");
        }
        if (!initialize_sequencer() || !initialize_dispatch_identity() ||
            !initialize_output_path() || !initialize_runtime_owner() ||
            !initialize_event_student_path() ||
            !initialize_identity_path() || !initialize_rx_producer()) {
            return false;
        }
        if (config_.abort_after_identity_transfers != 0u &&
            !initialize_abort_coordinator()) {
            return false;
        }
        if (!external_io_enabled(config_) &&
            (!action_model_.unlink_after_load() ||
             !detector_model_.unlink_after_load())) {
            return fail("failed to unlink loaded smoke models");
        }
        if (!frozen_causal_enabled(config_) &&
            !event_student_model_.unlink_after_load()) {
            return fail("failed to unlink loaded smoke Event Student");
        }
        return true;
    }

    bool run() {
        return config_.abort_after_identity_transfers == 0u
            ? run_normal() : run_abort();
    }

private:
    bool fail(const char *message) {
        set_error(error_, error_capacity_, message);
        return false;
    }

    bool initialize_sequencer() {
        fk_exact_identity_sequencer_config config{};
        config.producer_count = kProducers;
        config.ingress_capacity_per_producer =
            config_.sequencer_ingress_capacity;
        config.reorder_capacity = 16u;
        config.expected_packets = config_.packet_count;
        const size_t bytes =
            fk_exact_identity_sequencer_storage_bytes(&config);
        if (!sequencer_storage_.allocate(bytes))
            return fail("sequencer storage failed");
        char detail[256]{};
        sequencer_ = fk_exact_identity_sequencer_initialize(
            sequencer_storage_.data(),
            sequencer_storage_.capacity_bytes(),
            &config,
            detail,
            sizeof(detail));
        if (sequencer_ == nullptr)
            return fail("sequencer initialize failed");
        return true;
    }

    bool initialize_dispatch_identity() {
        char detail[256]{};
        fk_owner_dispatch_config dispatch_config{};
        dispatch_config.worker_count = kOwners;
        dispatch_config.queue_capacity_per_owner =
            external_io_enabled(config_)
            ? external_owner_queue_capacity(
                config_.maximum_quic_connections)
            : 16u;
        dispatch_config.owner_hash_key_precommitted = true;
        for (size_t index = 0u; index < FK_OWNER_DISPATCH_KEY_BYTES;
             ++index) {
            dispatch_config.owner_hash_key[index] =
                config_.owner_hash_key[index];
        }
        if (!dispatch_storage_.allocate(
                fk_owner_dispatch_storage_bytes(&dispatch_config)) ||
            !fk_owner_dispatch_initialize(
                dispatch_storage_.data(),
                dispatch_storage_.capacity_bytes(),
                &dispatch_config,
                &dispatch_)) {
            return fail("dispatch initialize failed");
        }

        fk_no_nic_controlled_identity_plan_v1 identity_plan{};
        if (!fk_no_nic_controlled_identity_plan_make_v1(
                config_.maximum_quic_connections,
                kOwners,
                external_io_enabled(config_),
                &identity_plan) ||
            identity_plan.exact_accounting == 0u) {
            return fail("controlled identity sizing plan failed");
        }
        const uint32_t identity_capacity =
            identity_plan.maximum_quic_connections;
        identity_capacity_ = identity_capacity;
        cid_reserved_bytes_ = identity_plan.quic_cid_reserved_bytes;
        if (!cid_storage_.allocate(cid_reserved_bytes_))
            return fail("CID storage failed");
        cid_map_ = fk_quic_cid_map_init(
            cid_storage_.data(),
            cid_storage_.capacity_bytes(),
            &identity_plan.cid_config,
            detail,
            sizeof(detail));
        if (cid_map_ == nullptr)
            return fail("CID map initialize failed");

        path_reserved_bytes_ =
            identity_plan.quic_presentation_path_reserved_bytes;
        if (!path_storage_.allocate(path_reserved_bytes_))
            return fail("path directory storage failed");
        path_directory_ = fk_quic_presentation_path_directory_initialize(
            path_storage_.data(),
            path_storage_.capacity_bytes(),
            &identity_plan.path_config,
            detail,
            sizeof(detail));
        if (path_directory_ == nullptr)
            return fail("path directory initialize failed");

        fk_quic_route_receipt_config receipt_config{};
        fk_quic_route_receipt_default_config_init(&receipt_config);
        receipt_config.run_epoch = UINT64_C(0x4e4f4e4943000001);
        receipt_config.owner_count = kOwners;
        receipt_config.keys_precommitted = 1u;
        if (!route_storage_.allocate(
                fk_quic_route_receipt_storage_bytes(&receipt_config)))
            return fail("route receipt storage failed");
        route_receipts_ = fk_quic_route_receipt_initialize(
            route_storage_.data(),
            route_storage_.capacity_bytes(),
            &receipt_config);
        if (route_receipts_ == nullptr)
            return fail("route receipt initialize failed");

        fk_quic_retirement_publisher_config publisher_config{};
        publisher_config.owner_count = kOwners;
        /* The producer fully drains retirement suffixes through controls-only
         * prefixes before its unique DATA/SKIP commit. Scratch stays bounded;
         * the external owner ring above is sized for the maximum entire
         * suffix plus that one DATA envelope. */
        publisher_config.maximum_controls_per_batch =
            external_io_enabled(config_)
            ? kExternalRetirementControlsPerPrefix : 8u;
        if (!publisher_storage_.allocate(
                fk_quic_retirement_publisher_storage_bytes(
                    &publisher_config)))
            return fail("retirement publisher storage failed");
        publisher_ = fk_quic_retirement_publisher_initialize(
            publisher_storage_.data(),
            publisher_storage_.capacity_bytes(),
            &publisher_config,
            cid_map_,
            dispatch_,
            detail,
            sizeof(detail));
        if (publisher_ == nullptr)
            return fail("retirement publisher initialize failed");

        binding_reserved_bytes_ =
            identity_plan.owner_flow_bindings_reserved_bytes;
        if (!binding_storage_.allocate(binding_reserved_bytes_))
            return fail("owner bindings storage failed");
        bindings_ = fk_owner_flow_bindings_initialize(
            binding_storage_.data(),
            binding_storage_.capacity_bytes(),
            &identity_plan.binding_config);
        if (bindings_ == nullptr)
            return fail("owner bindings initialize failed");
        if (external_io_enabled(config_)) {
            identity_controlled_reserved_bytes_ =
                identity_plan.identity_reserved_bytes;
        }
        return true;
    }

    bool initialize_output_path() {
        fk_owner_output_batch_ring_config ring_config{};
        ring_config.ring_epoch = UINT64_C(0x4e4f4e494352494e);
        ring_config.capacity = external_io_enabled(config_) ? 128u : 8u;
        ring_config.fixed_owner = 0u;
        ring_config.keys_precommitted = 1u;
        for (size_t index = 0u;
             index < FK_OWNER_OUTPUT_BATCH_RING_KEY_BYTES; ++index) {
            ring_config.authentication_key_0[index] =
                static_cast<uint8_t>(0x11u + index);
            ring_config.authentication_key_1[index] =
                static_cast<uint8_t>(0xa1u + index);
        }
        if (!ring_storage_.allocate(
                fk_owner_output_batch_ring_storage_bytes(&ring_config)) ||
            !fk_owner_output_batch_ring_initialize(
                ring_storage_.data(),
                ring_storage_.capacity_bytes(),
                &ring_config,
                &ring_)) {
            return fail("owner output ring initialize failed");
        }
        ring_pointers_[0] = ring_;

        fk_checkpoint_reorder_config reorder_config{};
        reorder_config.capacity =
            external_io_enabled(config_) ? 128u : 16u;
        reorder_config.trace_horizon_ns = UINT64_C(1000000000);
        reorder_config.maximum_wait_ns = UINT64_C(1000000000);
        reorder_config.admission_mode =
            FK_CHECKPOINT_REORDER_ADMISSION_STREAMING_MONOTONIC_V2;
        if (!reorder_storage_.allocate(
                fk_checkpoint_reorder_storage_bytes(&reorder_config)))
            return fail("checkpoint reorder storage failed");
        char detail[256]{};
        reorder_ = fk_checkpoint_reorder_init(
            reorder_storage_.data(),
            reorder_storage_.capacity_bytes(),
            &reorder_config,
            detail,
            sizeof(detail));
        if (reorder_ == nullptr)
            return fail("checkpoint reorder initialize failed");

        fk_owner_output_sequence_bridge_config bridge_config{};
        bridge_config.expected_packets = config_.bridge_epoch_packet_limit;
        bridge_config.checkpoint_payload_capacity =
            external_io_enabled(config_) ? 64u : 8u;
        bridge_config.completion_window_capacity =
            config_.completion_window_capacity;
        bridge_config.owner_count = kOwners;
        bridge_config.readiness_mode =
            FK_OWNER_OUTPUT_SEQUENCE_BRIDGE_READINESS_STREAMING_STRICT_PREFIX;
        if (!bridge_storage_.allocate(
                fk_owner_output_sequence_bridge_storage_bytes(
                    &bridge_config)))
            return fail("output bridge storage failed");
        bridge_ = fk_owner_output_sequence_bridge_init(
            bridge_storage_.data(),
            bridge_storage_.capacity_bytes(),
            &bridge_config,
            ring_pointers_.data(),
            nullptr,
            reorder_,
            detail,
            sizeof(detail));
        if (bridge_ == nullptr)
            return fail("output bridge initialize failed");
        return true;
    }

    bool initialize_runtime_owner() {
        fk_compact_runtime_config runtime_config{};
        runtime_config.maximum_flows = config_.maximum_flows;
        const uint64_t requested_controlled_ceiling =
            controlled_budget_bytes(config_.budget_mode);
        runtime_config.controlled_budget_bytes = requested_controlled_ceiling;
        runtime_config.pool_weights = config_.pool_weights;
        runtime_config.baseline_policy = config_.baseline_policy;
        runtime_config.automatic_pressure_enabled = 1u;
        runtime_config.pressure_enter_percent = 80u;
        runtime_config.overload_enter_percent = 95u;
        runtime_config.pressure_exit_percent = 70u;
        runtime_config.overload_exit_percent = 85u;
        if (external_io_enabled(config_) &&
            config_.budget_mode !=
                FK_NO_NIC_FULL_COMPOSITION_BUDGET_UNLIMITED_FULL_STATE) {
            if (!fk_no_nic_controlled_flow_table_partition_v1(
                    requested_controlled_ceiling,
                    identity_controlled_reserved_bytes_,
                    &runtime_config.controlled_budget_bytes)) {
                return fail(
                    "controlled budget cannot fit bounded identity state");
            }
        }
        runtime_config.full_capacity_state =
            config_.budget_mode ==
                    FK_NO_NIC_FULL_COMPOSITION_BUDGET_UNLIMITED_FULL_STATE;
        runtime_config.idle_timeout_ns = config_.idle_timeout_ns;
        runtime_config.expiration_scan_per_packet = 64u;
        runtime_config.action_value_model_path =
            external_io_enabled(config_)
                ? config_.action_value_model_path : action_model_.path();
        runtime_config.detector_model_path =
            external_io_enabled(config_)
                ? config_.detector_model_path : detector_model_.path();
        if (external_io_enabled(config_)) {
            for (uint8_t mask = 0u; mask < 8u; ++mask)
                runtime_config.detector_state_model_paths[mask] =
                    config_.detector_state_model_paths[mask];
        }
        runtime_config.action_schema_sha256 =
            external_io_enabled(config_)
                ? config_.action_schema_sha256 : kSchema;
        runtime_config.detector_schema_sha256 =
            external_io_enabled(config_)
                ? config_.detector_schema_sha256 : kSchema;
        if (value_model_v3_enabled(config_)) {
            runtime_config.action_value_model_kind =
                FK_COMPACT_ACTION_VALUE_V3_64D;
            runtime_config.action_value_model_v3_expected_role =
                static_cast<uint8_t>(config_.value_model_v3.expected_role);
            runtime_config.action_value_model_sha256 =
                config_.value_model_v3.artifact_sha256;
        } else if (!fk_compact_retention_policy_uses_learned_selector(
                       config_.baseline_policy.kind)) {
            runtime_config.action_value_model_kind =
                FK_COMPACT_ACTION_VALUE_NONE;
            runtime_config.action_value_model_path = nullptr;
            runtime_config.action_schema_sha256 = nullptr;
            runtime_config.action_value_model_sha256 = nullptr;
            runtime_config.action_value_model_v3_expected_role = 0u;
        }
        runtime_config.transition_value_model_path =
            config_.transition_value_model_path;
        runtime_config.transition_value_schema_sha256 =
            config_.transition_value_schema_sha256;
        runtime_config.transition_value_model_sha256 =
            config_.transition_value_model_sha256;
        runtime_config.checkpoint_intervention =
            config_.checkpoint_intervention;
        runtime_config.policy = {
            {4u, 8u, 12u, 20u, 0u, 0u},
            4u,
            UINT64_C(30000000000),
            {3u, 2u, 1u},
            {0.0f, 0.1f, 0.2f},
            0u,
            1u,
            1u,
            0u,
            0u,
            0u,
        };
        if (!fk_fixed_ttl_retention_align_component_lifetime(
                &runtime_config.baseline_policy,
                &runtime_config.policy)) {
            return fail("fixed-TTL component lifetime alignment failed");
        }
        if (config_.baseline_policy.kind == FK_COMPACT_POLICY_FLOWKEEP) {
            /* Keep the no-NIC composition identical to the frozen X710
             * receiver.  DataCon Development rejected forcing FULL in
             * NORMAL; doing so here erased FlowKeep's learned retention
             * treatment and made resource/CPU diagnostics compare FULL to
             * LRU instead of the deployed value policy. */
            runtime_config.policy.preserve_full_state_in_normal = 0u;
        }
        if (value_model_v3_enabled(config_) &&
            config_.value_model_v3.expected_role ==
                FK_VALUE_MODEL_V3_FLOWKEEP) {
            /*
             * FLOWKEEP predicts a lower confidence bound of causal,
             * CORE-relative decision impact.  CORE is exactly zero, so a
             * second absolute 0.1/0.2 cutoff is scale-dependent and
             * redundant.  Pressure is expressed by the component caps;
             * exact bytes, LCB-per-byte replacement and the hard budget
             * decide which positive-value evidence survives.  The learned
             * baseline roles retain their separately calibrated scale.
             */
            runtime_config.policy.minimum_utility[1] = 0.0f;
            runtime_config.policy.minimum_utility[2] = 0.0f;
            /* Match the frozen Development deployment gate exactly: rank the
             * lower confidence bound by exact candidate-owned bytes in every
             * pressure mode.  NORMAL/raw ranking is a different policy and
             * previously made no-NIC validation disagree with actual NIC. */
            runtime_config.policy.rank_by_marginal_value_per_byte =
                FK_COMPONENT_RANK_VALUE_PER_BYTE;
            runtime_config.policy.provisional_minimum_mask =
                static_cast<uint8_t>(FK_COMPONENT_STAT | FK_COMPONENT_SEQ);
            runtime_config.policy.provisional_until_packet = 20u;
        } else if (config_.baseline_policy.kind ==
                   FK_COMPACT_POLICY_LEARNED_DETECTION_LOSS_PER_BYTE) {
            /* This baseline is intentionally named after its actual online
             * signal.  The detector malicious score is emitted only after
             * retention, so the controller consumes the separately frozen
             * prefix-only learned detection-loss model and divides by the
             * exact candidate-owned bytes at every pressure level. */
            runtime_config.policy.rank_by_marginal_value_per_byte =
                FK_COMPONENT_RANK_VALUE_PER_BYTE;
        }
        for (float &probability :
             runtime_config.resource_costs.completion_probability) {
            probability = 1.0f;
        }
        runtime_config.resource_costs.lambda_memory_per_byte =
            config_.lambda_memory_per_byte;
        runtime_config.resource_costs.retention_discount =
            config_.retention_discount;
        runtime_config.resource_costs.lambda_queue = config_.lambda_queue;
        runtime_config.resource_costs.lambda_deadline =
            config_.lambda_deadline;
        char detail[256]{};
        runtime_ = fk_compact_runtime_create(
            &runtime_config, detail, sizeof(detail));
        if (runtime_ == nullptr) {
            char message[384]{};
            std::snprintf(
                message,
                sizeof(message),
                "compact runtime initialize failed: %s",
                detail[0] != '\0' ? detail : "no detail");
            return fail(message);
        }

        fk_dpdk_owner_mbuf_bytes_source_config source_config{};
        fk_dpdk_owner_mbuf_bytes_source_default_config_init(&source_config);
        source_config.fixed_owner = 0u;
        source_config.owner_count = kOwners;
        if (!owner_source_storage_.allocate(
                fk_dpdk_owner_mbuf_bytes_source_storage_bytes(
                    &source_config)))
            return fail("owner mbuf source storage failed");
        owner_source_ = fk_dpdk_owner_mbuf_bytes_source_initialize(
            owner_source_storage_.data(),
            owner_source_storage_.capacity_bytes(),
            &source_config);
        if (owner_source_ == nullptr ||
            !fk_dpdk_owner_mbuf_bytes_source_get_adapter_source(
                owner_source_, &owner_packet_source_)) {
            return fail("owner mbuf source initialize failed");
        }
        if (!fk_owner_runtime_adapter_initialize(
                &adapter_,
                runtime_,
                dispatch_,
                bindings_,
                cid_map_,
                route_receipts_,
                ring_,
                &owner_packet_source_,
                0u)) {
            return fail("owner runtime adapter initialize failed");
        }

        fk_fixed_owner_worker_pump_config pump_config{};
        fk_fixed_owner_worker_pump_default_config_init(&pump_config);
        pump_config.fixed_owner = 0u;
        pump_config.owner_count = kOwners;
        pump_config.dispatch = dispatch_;
        pump_config.mbuf_source = owner_source_;
        pump_config.adapter = &adapter_;
        pump_config.output_ring = ring_;
        pump_config.output_bridge = bridge_;
        pump_config.reclaim_context = external_io_enabled(config_)
            ? static_cast<void *>(&external_reclaim_)
            : static_cast<void *>(&trace_);
        pump_config.reclaim = external_io_enabled(config_)
            ? external_exact_reclaim : exact_reclaim;
        if (!owner_pump_storage_.allocate(
                fk_fixed_owner_worker_pump_storage_bytes(&pump_config)))
            return fail("owner pump storage failed");
        owner_pump_ = fk_fixed_owner_worker_pump_initialize(
            owner_pump_storage_.data(),
            owner_pump_storage_.capacity_bytes(),
            &pump_config);
        if (owner_pump_ == nullptr ||
            !fk_fixed_owner_worker_pump_claim_owner(owner_pump_)) {
            return fail("owner pump initialize/claim failed");
        }
        owner_pump_pointers_[0] = owner_pump_;
        return true;
    }

    static bool causal_model_callback(
            void *context,
            const fk_online_event_causal_trigger_v1 *trigger,
            const fk_online_event_causal_record_v1 *records,
            size_t record_count,
            float *probability) {
        return context != nullptr &&
            static_cast<Composition *>(context)->infer_causal_trigger(
                trigger, records, record_count, probability);
    }

    static bool causal_window_callback(
            void *context,
            const fk_online_event_window_result *result) {
        return context != nullptr &&
            static_cast<Composition *>(context)->consume_causal_window(result);
    }

    bool infer_causal_trigger(
            const fk_online_event_causal_trigger_v1 *trigger,
            const fk_online_event_causal_record_v1 *records,
            size_t record_count,
            float *probability) {
        auto &receipt = result_.frozen_causal_aggregation;
        if (trigger == nullptr || records == nullptr || probability == nullptr ||
            causal_calibrator_ == nullptr ||
            trigger->event_id == 0u || trigger->event_generation == 0u ||
            trigger->event_start_ns == 0u || trigger->anchor_ns == 0u ||
            trigger->anchor_ns < trigger->event_start_ns ||
            trigger->event_slot >= frozen_event_states_.size() ||
            record_count == 0u ||
            record_count != trigger->retained_records ||
            record_count > FK_ONLINE_EVENT_MAX_FLOWS ||
            (trigger->trigger_kind !=
                 FK_ONLINE_EVENT_TRIGGER_KIND_CHECKPOINT &&
             trigger->trigger_kind !=
                 FK_ONLINE_EVENT_TRIGGER_KIND_PERIODIC)) {
            receipt.inference_failures++;
            return false;
        }
        FrozenCausalEventState &state =
            frozen_event_states_[trigger->event_slot];
        if (!state.initialized || state.event_id != trigger->event_id ||
            state.event_generation != trigger->event_generation) {
            state = {};
            state.initialized = true;
            state.event_id = trigger->event_id;
            state.event_generation = trigger->event_generation;
            state.event_start_ns = trigger->event_start_ns;
            fk_causal_event_feature_state_reset(&state.causal_features);
            receipt.initialized_event_generations++;
            receipt.feature_state_resets++;
        }
        if (state.event_start_ns != trigger->event_start_ns ||
            trigger->trigger_ordinal != state.causal_features.trigger_count) {
            receipt.inference_failures++;
            return false;
        }
        std::array<double, FK_ONLINE_EVENT_MAX_FLOWS> scores{};
        std::array<uint8_t, FK_ONLINE_EVENT_MAX_FLOWS> action_masks{};
        std::array<
            float,
            FK_ONLINE_EVENT_MAX_FLOWS *
                FK_CAUSAL_EVENT_MASKED_STATE_COLUMNS> columns{};
        bool mixed = false;
        for (size_t index = 0u; index < record_count; ++index) {
            const auto &record = records[index];
            if (!std::isfinite(record.record_score) ||
                record.record_score < 0.0 || record.record_score > 1.0 ||
                record.original_action_mask > 7u) {
                receipt.inference_failures++;
                return false;
            }
            scores[index] = record.record_score;
            action_masks[index] = record.original_action_mask;
            if (index != 0u && action_masks[index] != action_masks[0])
                mixed = true;
            for (size_t column = 0u;
                 column < FK_CAUSAL_EVENT_MASKED_STATE_COLUMNS; ++column) {
                const float value = record.masked_state_columns[column];
                if (!std::isfinite(value)) {
                    receipt.inference_failures++;
                    return false;
                }
                columns[index * FK_CAUSAL_EVENT_MASKED_STATE_COLUMNS + column] =
                    value;
            }
        }
        fk_causal_event_trigger_input_v1 input{};
        input.trigger_kind = trigger->trigger_kind;
        input.checkpoint_packet = trigger->checkpoint_packet;
        input.event_start_ns = trigger->event_start_ns;
        input.anchor_ns = trigger->anchor_ns;
        input.record_count = record_count;
        input.record_scores = scores.data();
        input.record_action_masks = action_masks.data();
        input.masked_state_columns = columns.data();
        float features[FK_CAUSAL_EVENT_CALIBRATOR_FEATURES]{};
        float calibrated = 0.0f;
        if (!fk_causal_event_features_update(
                &state.causal_features, &input, features) ||
            !fk_causal_event_calibrator_predict(
                causal_calibrator_, features, &calibrated)) {
            receipt.inference_failures++;
            return false;
        }
        state.maximum_score = std::max(state.maximum_score, calibrated);
        if (trigger->trigger_kind ==
                FK_ONLINE_EVENT_TRIGGER_KIND_CHECKPOINT) {
            state.checkpoint_updates++;
            receipt.checkpoint_updates++;
        } else {
            state.periodic_updates++;
            receipt.periodic_updates++;
        }
        receipt.total_feature_updates++;
        receipt.inference_calls++;
        receipt.causal_records_presented += record_count;
        if (mixed)
            receipt.mixed_mask_triggers++;
        *probability = calibrated;
        return true;
    }

    bool consume_causal_window(
            const fk_online_event_window_result *window) {
        if (window == nullptr || window->event_id == 0u ||
            window->event_generation == 0u ||
            window->event_slot >= frozen_event_states_.size() ||
            window->trigger_protocol !=
                FK_ONLINE_EVENT_TRIGGER_PROTOCOL_CHECKPOINT_PERIODIC_V2 ||
            (window->trigger_kind !=
                 FK_ONLINE_EVENT_TRIGGER_KIND_CHECKPOINT &&
             window->trigger_kind !=
                 FK_ONLINE_EVENT_TRIGGER_KIND_PERIODIC) ||
            !std::isfinite(window->operational_probability)) {
            return fail("causal window output contract failed");
        }
        fk_actor_session_result association{};
        association.event_id = window->event_id;
        association.event_slot = window->event_slot;
        association.event_generation = window->event_generation;
        fk_detection_event_decision_result decision{};
        if (!fk_detection_event_path_record_decision(
                event_path_, &association, window->threshold_crossed,
                &decision) || !decision.accepted ||
            decision.first_alert_for_event != window->first_alert) {
            result_.frozen_causal_aggregation.stale_handle_rejections++;
            return fail("causal window event decision handle is stale");
        }
        fk_student_shard_result synthetic{};
        synthetic.window = *window;
        if (window->trigger_kind ==
                FK_ONLINE_EVENT_TRIGGER_KIND_CHECKPOINT) {
            if (!checkpoint_trace_active_ ||
                checkpoint_association_.event_id != window->event_id ||
                checkpoint_association_.event_slot != window->event_slot ||
                checkpoint_association_.event_generation !=
                    window->event_generation ||
                causal_current_detector_start_ns_ == 0u ||
                causal_current_detector_end_ns_ <
                    causal_current_detector_start_ns_) {
                return fail("causal checkpoint callback association failed");
            }
            synthetic.command_enqueue_monotonic_ns =
                causal_current_detector_start_ns_;
            synthetic.command_start_monotonic_ns =
                causal_current_detector_start_ns_;
            synthetic.decision_monotonic_ns =
                causal_current_detector_end_ns_;
            checkpoint_student_result_ = synthetic;
            checkpoint_student_result_ready_ = true;
            student_checkpoint_results_++;
            if (window->checkpoint_packet >=
                    student_checkpoint_packet_results_.size()) {
                return fail("causal checkpoint packet is out of range");
            }
            student_checkpoint_packet_results_[window->checkpoint_packet]++;
        } else {
            const uint64_t start = next_student_monotonic_ns();
            synthetic.command_enqueue_monotonic_ns = start;
            synthetic.command_start_monotonic_ns = start;
            synthetic.decision_monotonic_ns = next_student_monotonic_ns();
            student_periodic_results_++;
            if (!emit_periodic_decision(synthetic))
                return false;
        }
        student_output_results_++;
        student_ordinal_sum_ += window->trigger_ordinal;
        student_ordinal_xor_ ^= window->trigger_ordinal;
        student_ordinal_max_ = std::max(
            student_ordinal_max_, window->trigger_ordinal);
        auto &receipt = result_.frozen_causal_aggregation;
        if (window->first_alert)
            receipt.threshold_crossings++;
        if (window->alert_latched)
            receipt.latched_alert_outputs++;
        return true;
    }

    bool initialize_event_student_path() {
        actor_config_ = config_.actor_session;
        if (config_.preserve_actor_session_capacities == 0u) {
            actor_config_.maximum_events = std::min(
                actor_config_.maximum_events,
                std::min(config_.maximum_flows,
                    static_cast<uint32_t>(FK_ACTOR_SESSION_MAX_EVENTS)));
            actor_config_.maximum_total_flows = std::min(
                actor_config_.maximum_total_flows, config_.maximum_flows);
        }
        actor_config_.maximum_flows_per_event = std::min(
            actor_config_.maximum_flows_per_event,
            actor_config_.maximum_total_flows);
        actor_config_.maximum_logical_connection_slots = identity_capacity_;
        if (!fk_actor_session_config_valid(&actor_config_))
            return fail("bounded actor/session config is invalid");
        const size_t event_path_bytes =
            fk_detection_event_path_storage_bytes(&actor_config_);
        if (!event_path_storage_.allocate(event_path_bytes))
            return fail("event association path storage failed");
        char detail[256]{};
        event_path_ = fk_detection_event_path_init(
            event_path_storage_.data(),
            event_path_storage_.capacity_bytes(),
            &actor_config_,
            detail,
            sizeof(detail));
        if (event_path_ == nullptr)
            return fail("event association path initialize failed");

        if (frozen_causal_enabled(config_)) {
            frozen_event_states_.assign(
                actor_config_.maximum_events, FrozenCausalEventState{});
            auto &receipt = result_.frozen_causal_aggregation;
            receipt = {};
            receipt.abi_version =
                FK_NO_NIC_FROZEN_CAUSAL_AGGREGATION_RECEIPT_ABI_VERSION;
            receipt.threshold = config_.frozen_causal_aggregation.threshold;
            receipt.reserved_bytes =
                static_cast<uint64_t>(frozen_event_states_.capacity()) *
                sizeof(FrozenCausalEventState);
            const bool calibrator = causal_calibrator_enabled(config_);
            std::snprintf(
                receipt.aggregation_rule,
                sizeof(receipt.aggregation_rule), "%s",
                calibrator ? "causal_event_calibrator_max" : "max");
            std::snprintf(
                receipt.threshold_profile,
                sizeof(receipt.threshold_profile), "%s",
                config_.frozen_causal_aggregation.threshold_profile);
            std::snprintf(
                receipt.aggregation_contract_sha256,
                sizeof(receipt.aggregation_contract_sha256), "%s",
                config_.frozen_causal_aggregation
                    .aggregation_contract_sha256);
            std::snprintf(
                receipt.development_oof_receipt_sha256,
                sizeof(receipt.development_oof_receipt_sha256), "%s",
                config_.frozen_causal_aggregation
                    .development_oof_receipt_sha256);
            receipt.enabled = 1u;
            receipt.deterministic_smoke_model = 0u;
            if (!calibrator)
                return true;
            const auto &frozen = config_.frozen_causal_aggregation;
            receipt.calibrator_enabled = 1u;
            if (!file_sha256_matches(
                    frozen.causal_event_calibrator_artifact_path,
                    frozen.causal_event_calibrator_artifact_sha256)) {
                receipt.model_load_failures++;
                return fail("causal calibrator artifact SHA-256 mismatch");
            }
            causal_calibrator_ = fk_causal_event_calibrator_load(
                frozen.causal_event_calibrator_artifact_path,
                frozen.causal_event_calibrator_source_npz_sha256,
                frozen.causal_event_feature_contract_sha256,
                detail, sizeof(detail));
            if (causal_calibrator_ == nullptr) {
                receipt.model_load_failures++;
                return fail("causal calibrator startup load failed");
            }
            receipt.model_load_successes++;
            receipt.model_loaded = 1u;
            std::snprintf(
                receipt.causal_event_calibrator_artifact_sha256,
                sizeof(receipt.causal_event_calibrator_artifact_sha256),
                "%s", frozen.causal_event_calibrator_artifact_sha256);
            std::snprintf(
                receipt.causal_event_calibrator_source_npz_sha256,
                sizeof(receipt.causal_event_calibrator_source_npz_sha256),
                "%s", frozen.causal_event_calibrator_source_npz_sha256);
            std::snprintf(
                receipt.causal_event_feature_contract_sha256,
                sizeof(receipt.causal_event_feature_contract_sha256),
                "%s", frozen.causal_event_feature_contract_sha256);
            std::snprintf(
                receipt.causal_event_real_prefix_receipt_sha256,
                sizeof(receipt.causal_event_real_prefix_receipt_sha256),
                "%s", frozen.causal_event_real_prefix_receipt_sha256);
            fk_online_event_windows_config causal_config{};
            causal_config.maximum_events = actor_config_.maximum_events;
            causal_config.maximum_flows_per_event =
                actor_config_.maximum_flows_per_event;
            causal_config.maximum_total_flows =
                actor_config_.maximum_total_flows;
            causal_config.sink = causal_window_callback;
            causal_config.sink_context = this;
            causal_config.causal_model = causal_model_callback;
            causal_config.causal_model_context = this;
            causal_config.causal_decision_threshold = receipt.threshold;
            causal_config.external_watermarks_only = true;
            const size_t causal_window_bytes =
                fk_online_event_windows_storage_bytes(&causal_config);
            if (causal_window_bytes == 0u ||
                !causal_windows_storage_.allocate(causal_window_bytes)) {
                return fail("causal window storage failed");
            }
            causal_windows_ = fk_online_event_windows_init(
                causal_windows_storage_.data(),
                causal_windows_storage_.capacity_bytes(),
                &causal_config, detail, sizeof(detail));
            if (causal_windows_ == nullptr)
                return fail("causal V2 window scheduler initialize failed");
            const uint64_t model_bytes =
                fk_causal_event_calibrator_reserved_bytes(causal_calibrator_);
            if (!checked_add_u64(receipt.reserved_bytes, model_bytes) ||
                !checked_add_u64(
                    receipt.reserved_bytes,
                    causal_windows_storage_.capacity_bytes())) {
                return fail("causal calibrator reserved bytes overflow");
            }
            return true;
        }

        const char *artifact = config_.event_student_artifact_path;
        fk_event_student_load_config load =
            config_.event_student_load_config;
        if (artifact == nullptr) {
            if (!event_student_model_.create())
                return fail("deterministic FKESV1 model creation failed");
            artifact = event_student_model_.path();
            load = event_student_model_.load_config();
            result_.trigger_receipt.deterministic_smoke_model = 1u;
        }
        fk_student_shards_config shard_config{};
        shard_config.worker_count = config_.event_student_worker_count;
        shard_config.command_queue_capacity =
            config_.event_student_command_queue_capacity;
        shard_config.result_queue_capacity =
            config_.event_student_result_queue_capacity;
        shard_config.maximum_events = actor_config_.maximum_events;
        shard_config.maximum_flows_per_event =
            actor_config_.maximum_flows_per_event;
        shard_config.maximum_total_flows =
            actor_config_.maximum_total_flows;
        shard_config.artifact_path = artifact;
        shard_config.load_config = load;
        student_shards_ = fk_student_shards_create(
            &shard_config, detail, sizeof(detail));
        if (student_shards_ == nullptr)
            return fail("bounded Event Student shards initialize failed");
        fk_event_student_metadata metadata{};
        if (!fk_student_shards_get_metadata(student_shards_, &metadata) ||
            metadata.input_features != FK_EVENT_STUDENT_INPUT_FEATURES)
            return fail("Event Student metadata mismatch");
        return true;
    }

    bool initialize_gate() {
        fk_quic_initial_crypto_admission_gate_config gate_config{};
        fk_quic_initial_crypto_admission_gate_default_config_init(
            &gate_config);
        gate_config.prefix_table_capacity = 8u;
        gate_config.maximum_probe_length = 8u;
        gate_config.fair_share_divisor = 4u;
        gate_config.global_burst_tokens = 64u;
        gate_config.prefix_burst_credits = 16u;
        gate_config.global_refill_tokens_per_interval = 64u;
        gate_config.prefix_refill_credits_per_interval = 16u;
        gate_config.keys_precommitted = 1u;
        for (size_t index = 0u;
             index < FK_QUIC_INITIAL_CRYPTO_ADMISSION_KEY_BYTES; ++index) {
            gate_config.prefix_hash_key[index] =
                static_cast<uint8_t>(0x21u + index);
            gate_config.receipt_key_0[index] =
                static_cast<uint8_t>(0x61u + index);
            gate_config.receipt_key_1[index] =
                static_cast<uint8_t>(0xa1u + index);
        }
        if (!gate_storage_.allocate(
                fk_quic_initial_crypto_admission_gate_storage_bytes(
                    &gate_config)))
            return fail("QUIC crypto gate storage failed");
        gate_ = fk_quic_initial_crypto_admission_gate_initialize(
            gate_storage_.data(),
            gate_storage_.capacity_bytes(),
            &gate_config);
        return gate_ != nullptr || fail("QUIC crypto gate initialize failed");
    }

    bool initialize_identity_path() {
        if (!initialize_gate())
            return false;
        fk_dpdk_exact_identity_mbuf_source_config source_config{};
        fk_dpdk_exact_identity_mbuf_source_default_config_init(
            &source_config);
        source_config.producer_count = kProducers;
        if (!identity_source_storage_.allocate(
                fk_dpdk_exact_identity_mbuf_source_storage_bytes(
                    &source_config)))
            return fail("identity mbuf source storage failed");
        identity_source_ = fk_dpdk_exact_identity_mbuf_source_initialize(
            identity_source_storage_.data(),
            identity_source_storage_.capacity_bytes(),
            &source_config);
        if (identity_source_ == nullptr ||
            !fk_dpdk_exact_identity_mbuf_source_get_resolver(
                identity_source_, &identity_resolver_)) {
            return fail("identity mbuf source initialize failed");
        }

        fk_exact_identity_router_config router_config{};
        fk_exact_identity_router_default_config_init(&router_config);
        router_config.owner_count = kOwners;
        if (!router_storage_.allocate(
                fk_exact_identity_router_storage_bytes(&router_config)))
            return fail("identity router storage failed");
        char detail[256]{};
        router_ = fk_exact_identity_router_initialize(
            router_storage_.data(),
            router_storage_.capacity_bytes(),
            &router_config,
            &identity_resolver_,
            cid_map_,
            path_directory_,
            dispatch_,
            route_receipts_,
            publisher_,
            bridge_,
#if FK_EXACT_IDENTITY_ROUTER_ABI_VERSION >= 3u
            gate_,
            external_io_enabled(config_)
                ? config_.monotonic_clock_context
                : static_cast<void *>(&trace_),
            external_io_enabled(config_)
                ? config_.monotonic_now_ns : router_monotonic_now,
#endif
            detail,
            sizeof(detail));
        if (router_ == nullptr)
            return fail("identity router initialize failed");

        fk_exact_identity_rx_worker_pump_config pump_config{};
        fk_exact_identity_rx_worker_pump_default_config_init(&pump_config);
        pump_config.producer_count = kProducers;
        pump_config.sequencer = sequencer_;
        pump_config.source = identity_source_;
        pump_config.router = router_;
        pump_config.completion_bridge = bridge_;
        pump_config.reclaim_context = external_io_enabled(config_)
            ? static_cast<void *>(&external_reclaim_)
            : static_cast<void *>(&trace_);
        pump_config.reclaim = external_io_enabled(config_)
            ? external_exact_reclaim : exact_reclaim;
        if (!identity_pump_storage_.allocate(
                fk_exact_identity_rx_worker_pump_storage_bytes(
                    &pump_config)))
            return fail("identity pump storage failed");
        identity_pump_ = fk_exact_identity_rx_worker_pump_initialize(
            identity_pump_storage_.data(),
            identity_pump_storage_.capacity_bytes(),
            &pump_config,
            detail,
            sizeof(detail));
        if (identity_pump_ == nullptr)
            return fail("identity pump initialize failed");
        if (!fk_exact_identity_rx_worker_pump_claim_identity_thread(
                identity_pump_))
            return fail("identity pump claim failed");
#if FK_EXACT_IDENTITY_ROUTER_ABI_VERSION < 3u
        if (!fk_quic_initial_crypto_admission_gate_claim_owner(gate_))
            return fail("standalone QUIC gate claim failed");
#endif
        return true;
    }

    bool initialize_rx_producer() {
        fk_dpdk_exact_rx_producer_pump_config pump_config{};
        fk_dpdk_exact_rx_producer_pump_default_config_init(&pump_config);
        pump_config.port_id = 0u;
        pump_config.queue_id = 0u;
        pump_config.producer_index = 0u;
        pump_config.producer_count = kProducers;
        pump_config.burst_capacity =
            static_cast<uint16_t>(config_.rx_burst_capacity);
        pump_config.sequencer = sequencer_;
        pump_config.burst_context = external_io_enabled(config_)
            ? config_.burst_context : static_cast<void *>(&trace_);
        pump_config.burst = external_io_enabled(config_)
            ? config_.burst : rx_burst;
        pump_config.clock_context = external_io_enabled(config_)
            ? config_.clock_context : static_cast<void *>(&trace_);
        pump_config.clock = external_io_enabled(config_)
            ? config_.clock : rx_clock;
        pump_config.decode_context = external_io_enabled(config_)
            ? config_.decode_context : static_cast<void *>(&trace_);
        pump_config.decode = external_io_enabled(config_)
            ? config_.decode : rx_decode;
        pump_config.reclaim_context = external_io_enabled(config_)
            ? config_.reclaim_context : static_cast<void *>(&trace_);
        pump_config.reclaim = external_io_enabled(config_)
            ? config_.reclaim : rx_reclaim;
        if (!rx_pump_storage_.allocate(
                fk_dpdk_exact_rx_producer_pump_storage_bytes(
                    &pump_config)))
            return fail("RX producer storage failed");
        char detail[256]{};
        rx_pump_ = fk_dpdk_exact_rx_producer_pump_initialize(
            rx_pump_storage_.data(),
            rx_pump_storage_.capacity_bytes(),
            &pump_config,
            detail,
            sizeof(detail));
        if (rx_pump_ == nullptr ||
            !fk_dpdk_exact_rx_producer_pump_claim_thread(rx_pump_)) {
            return fail("RX producer initialize/claim failed");
        }
        return true;
    }

    bool initialize_abort_coordinator() {
        fk_owner_pipeline_abort_coordinator_config coordinator_config{};
        fk_owner_pipeline_abort_coordinator_default_config_init(
            &coordinator_config);
        coordinator_config.owner_count = kOwners;
        coordinator_config.coordinator_epoch =
            UINT64_C(0x4e4f4e4943414254);
        coordinator_config.keys_precommitted = 1u;
        for (size_t index = 0u;
             index < FK_OWNER_PIPELINE_ABORT_AUTH_KEY_BYTES; ++index) {
            coordinator_config.authentication_key_0[index] =
                static_cast<uint8_t>(0x41u + index);
            coordinator_config.authentication_key_1[index] =
                static_cast<uint8_t>(0xc1u + index);
        }
        coordinator_config.dispatch = dispatch_;
        coordinator_config.bridge = bridge_;
        coordinator_config.owner_rings = ring_pointers_.data();
        coordinator_config.owner_pumps = owner_pump_pointers_.data();
        coordinator_config.identity_verify_context = identity_pump_;
        coordinator_config.identity_verify =
            fk_exact_identity_rx_worker_pump_abort_prepared_verify_callback;
        coordinator_config.dispatch_reclaim_context =
            external_io_enabled(config_)
                ? static_cast<void *>(&external_reclaim_)
                : static_cast<void *>(&trace_);
        coordinator_config.dispatch_reclaim =
            external_io_enabled(config_)
                ? external_dispatch_reclaim : dispatch_reclaim;
        if (!coordinator_storage_.allocate(
                fk_owner_pipeline_abort_coordinator_storage_bytes(
                    &coordinator_config)))
            return fail("abort coordinator storage failed");
        coordinator_ = fk_owner_pipeline_abort_coordinator_initialize(
            coordinator_storage_.data(),
            coordinator_storage_.capacity_bytes(),
            &coordinator_config);
        return coordinator_ != nullptr ||
            fail("abort coordinator initialize failed");
    }

    bool sample_queue_depth(bool offered_interval) {
        fk_exact_identity_sequencer_stats sequencer{};
        fk_owner_dispatch_stats dispatch{};
        fk_owner_output_batch_ring_stats ring{};
        fk_checkpoint_reorder_stats reorder{};
        if (sequencer_ == nullptr || dispatch_ == nullptr || ring_ == nullptr ||
            reorder_ == nullptr ||
            (!frozen_causal_enabled(config_) && student_shards_ == nullptr) ||
            !fk_exact_identity_sequencer_get_stats(sequencer_, &sequencer) ||
            !fk_owner_dispatch_get_stats(dispatch_, &dispatch) ||
            !fk_owner_output_batch_ring_get_stats(ring_, &ring) ||
            !fk_checkpoint_reorder_get_stats(reorder_, &reorder)) {
            return fail("queue observability snapshot failed");
        }
        uint64_t depth = sequencer.ingress_depth;
        if (!checked_add_u64(depth, sequencer.reorder_depth) ||
            !checked_add_u64(depth, dispatch.total_depth) ||
            !checked_add_u64(depth, ring.depth) ||
            !checked_add_u64(depth, reorder.current_depth)) {
            return fail("queue observability depth overflow");
        }
        if (!frozen_causal_enabled(config_) &&
            (!checked_add_u64(
                 depth,
                 fk_student_shards_command_queue_depth(student_shards_)) ||
             !checked_add_u64(
                 depth,
                 fk_student_shards_result_queue_depth(student_shards_)))) {
            return fail("student queue observability depth overflow");
        }
        queue_peak_all_ = std::max(queue_peak_all_, depth);
        queue_samples_total_++;
        if (offered_interval &&
            !offered_queue_regression_.observe(steady_monotonic_ns(), depth)) {
            return fail("queue observability clock regressed");
        }
        return true;
    }

    void begin_recovery_observation() {
        if (recovery_start_monotonic_ns_ == 0u)
            recovery_start_monotonic_ns_ = steady_monotonic_ns();
    }

    bool complete_recovery_observation() {
        if (recovery_start_monotonic_ns_ == 0u)
            begin_recovery_observation();
        if (!sample_queue_depth(false))
            return false;
        recovery_complete_monotonic_ns_ = steady_monotonic_ns();
        return recovery_complete_monotonic_ns_ >= recovery_start_monotonic_ns_;
    }

    bool finalize_observability_receipt(
            const fk_exact_identity_sequencer_stats &sequencer,
            const fk_owner_dispatch_stats &dispatch,
            const fk_owner_output_batch_ring_stats &ring,
            const fk_checkpoint_reorder_stats &reorder,
            const fk_compact_runtime_stats &runtime,
            const fk_compact_flow_table_stats &table,
            const fk_no_nic_full_composition_io_stats_v1 &io) {
        auto &summary = result_.observability;
        summary.abi_version = FK_NO_NIC_DECISION_TRACE_ABI_VERSION;
        summary.histogram_bins =
            FK_NO_NIC_DECISION_TRACE_HISTOGRAM_BINS;
        summary.trace_sink_enabled =
            config_.decision_trace_sink != nullptr ? 1u : 0u;
        summary.trace_export_complete =
            config_.decision_trace_sink != nullptr &&
                    summary.trace_sink_records ==
                        summary.decision_records +
                            summary.evidence_transition_records &&
                    summary.trace_sink_rejections == 0u
                ? 1u : 0u;
        summary.detection_latency_p50_ns = latency_histogram_percentile(
            detection_latency_histogram_, summary.detection_latency_samples,
            50u, 100u);
        summary.detection_latency_p95_ns = latency_histogram_percentile(
            detection_latency_histogram_, summary.detection_latency_samples,
            95u, 100u);
        summary.detection_latency_p99_ns = latency_histogram_percentile(
            detection_latency_histogram_, summary.detection_latency_samples,
            99u, 100u);
        summary.packet_to_decision_p50_ns = latency_histogram_percentile(
            packet_latency_histogram_, summary.packet_to_decision_samples,
            50u, 100u);
        summary.packet_to_decision_p95_ns = latency_histogram_percentile(
            packet_latency_histogram_, summary.packet_to_decision_samples,
            95u, 100u);
        summary.packet_to_decision_p99_ns = latency_histogram_percentile(
            packet_latency_histogram_, summary.packet_to_decision_samples,
            99u, 100u);
        summary.flow_detector_latency_p50_ns = latency_histogram_percentile(
            flow_detector_latency_histogram_,
            summary.flow_detector_latency_samples, 50u, 100u);
        summary.flow_detector_latency_p95_ns = latency_histogram_percentile(
            flow_detector_latency_histogram_,
            summary.flow_detector_latency_samples, 95u, 100u);
        summary.flow_detector_latency_p99_ns = latency_histogram_percentile(
            flow_detector_latency_histogram_,
            summary.flow_detector_latency_samples, 99u, 100u);
        summary.queue_samples = queue_samples_total_;
        summary.queue_peak_entries = queue_peak_all_;
        summary.sequencer_ingress_peak = sequencer.peak_ingress_depth;
        summary.sequencer_reorder_peak = sequencer.peak_reorder_depth;
        summary.dispatch_peak = dispatch.peak_total_depth;
        summary.owner_output_peak = ring.peak_depth;
        summary.checkpoint_reorder_peak = reorder.peak_depth;
        if (!frozen_causal_enabled(config_)) {
            fk_student_shards_stats shard_stats{};
            if (!fk_student_shards_get_stats(student_shards_, &shard_stats))
                return fail("student queue observability unavailable");
            for (uint16_t worker = 0u;
                 worker < shard_stats.worker_count; ++worker) {
                summary.student_command_peak = std::max(
                    summary.student_command_peak,
                    shard_stats.workers[worker].command_queue_peak);
                summary.student_result_peak = std::max(
                    summary.student_result_peak,
                    shard_stats.workers[worker].result_queue_peak);
            }
        }
        summary.queue_peak_entries = std::max(
            {summary.queue_peak_entries,
             summary.sequencer_ingress_peak,
             summary.sequencer_reorder_peak,
             summary.dispatch_peak,
             summary.owner_output_peak,
             summary.checkpoint_reorder_peak,
             summary.student_command_peak,
             summary.student_result_peak});
        summary.queue_ols_slope_entries_per_second =
            offered_queue_regression_.ols_slope_per_second();
        summary.queue_peak_positive_slope_entries_per_second =
            offered_queue_regression_.peak_positive_slope_per_second;
        summary.recovery_start_monotonic_ns = recovery_start_monotonic_ns_;
        summary.recovery_complete_monotonic_ns =
            recovery_complete_monotonic_ns_;
        if (recovery_complete_monotonic_ns_ >= recovery_start_monotonic_ns_ &&
            recovery_start_monotonic_ns_ != 0u) {
            summary.recovery_time_ns =
                recovery_complete_monotonic_ns_ - recovery_start_monotonic_ns_;
            summary.recovery_complete = 1u;
        }
        summary.fatal_packet_drops = io.forced_failure_reclaims;
        if (!checked_add_u64(
                summary.fatal_packet_drops, result_.identity_reject_reclaims)) {
            return fail("fatal packet drop accounting overflow");
        }
        if (result_.detection_requests < result_.detector_executions ||
            student_output_results_ >
                student_checkpoint_results_ + student_periodic_results_) {
            return fail("fatal decision drop accounting regressed");
        }
        summary.fatal_decision_drops =
            result_.detection_requests - result_.detector_executions;
        const uint64_t expected_student_outputs =
            student_checkpoint_results_ + student_periodic_results_;
        if (student_output_results_ > expected_student_outputs ||
            !checked_add_u64(
                summary.fatal_decision_drops,
                expected_student_outputs - student_output_results_) ||
            !checked_add_u64(
                summary.fatal_decision_drops,
                summary.trace_sink_rejections)) {
            return fail("fatal decision drop accounting overflow");
        }
        summary.policy_flow_rejects = runtime.flow_admission_rejects;
        summary.policy_state_action_rejects = runtime.action_budget_rejections;
        summary.policy_evidence_rejects = table.evidence_allocation_failures;
        summary.fatal_integrity_events =
            result_.rx_shape_rejections +
            result_.sequencer_integrity_rejections +
            result_.router_resolver_rejections +
            result_.router_identity_rejections +
            result_.router_completion_rejections +
            result_.dispatch_invalid_routes +
            result_.owner_terminal_results +
            result_.owner_reclaim_failures +
            result_.bridge_publication_rejections +
            result_.bridge_integrity_rejections +
            runtime.state_update_failures + runtime.checkpoint_failures +
            summary.timestamp_failures + summary.order_failures;
        /* Unsupported L2/L3/L4 and other parser outcomes are explicit ordered
         * skips with exact reclamation, not lost packets or terminal integrity
         * failures. Their raw counter remains in drops_rejects diagnostics. */
        summary.transient_backpressure_events =
            result_.sequencer_queue_full_rejections +
            result_.identity_backpressure +
            result_.router_completion_backpressure +
            result_.dispatch_queue_full +
            result_.owner_output_backpressure +
            result_.bridge_reservation_backpressure +
            result_.bridge_reorder_backpressure;
        summary.timing_complete =
            summary.timestamp_failures == 0u &&
                    summary.order_failures == 0u &&
                    summary.detection_latency_samples ==
                        summary.decision_records &&
                    summary.packet_to_decision_samples ==
                        summary.checkpoint_records &&
                    summary.flow_detector_latency_samples ==
                        summary.checkpoint_records
                ? 1u : 0u;
        summary.drop_accounting_complete = 1u;
        return true;
    }

    bool snapshot_result() {
        fk_dpdk_exact_rx_producer_pump_stats rx_stats{};
        fk_exact_identity_rx_worker_pump_stats identity_stats{};
        fk_fixed_owner_worker_pump_stats owner_stats{};
        fk_owner_output_sequence_bridge_stats bridge_stats{};
        fk_checkpoint_reorder_stats reorder_stats{};
        fk_compact_flow_table_stats table_stats{};
        fk_compact_runtime_stats runtime_stats{};
        fk_exact_identity_sequencer_stats sequencer_stats{};
        fk_exact_identity_router_stats router_stats{};
        fk_owner_dispatch_stats dispatch_stats{};
        fk_budget_snapshot budget_stats{};
        fk_quic_cid_map_stats cid_stats{};
        fk_quic_cid_map_topology_receipt cid_topology{};
        fk_quic_presentation_path_directory_stats path_stats{};
        fk_owner_flow_bindings_stats binding_stats{};
        fk_dpdk_exact_identity_mbuf_source_stats identity_source_stats{};
        fk_dpdk_owner_mbuf_bytes_source_stats owner_source_stats{};
        fk_owner_runtime_adapter_stats adapter_stats{};
        fk_owner_output_batch_ring_stats ring_stats{};
        fk_quic_retirement_publisher_stats publisher_stats{};
        fk_quic_route_receipt_stats route_receipt_stats{};
        fk_quic_initial_crypto_admission_gate_stats gate_stats{};
        fk_owner_pipeline_abort_coordinator_stats coordinator_stats{};
        fk_no_nic_full_composition_io_stats_v1 io_stats{};
        if (!fk_dpdk_exact_rx_producer_pump_get_stats(
                rx_pump_, &rx_stats))
            return fail("failed to snapshot RX producer receipt");
        if (!fk_exact_identity_rx_worker_pump_get_stats(
                identity_pump_, &identity_stats))
            return fail("failed to snapshot identity receipt");
        if (!fk_fixed_owner_worker_pump_get_stats(
                owner_pump_, &owner_stats))
            return fail("failed to snapshot owner receipt");
        if (!fk_owner_output_sequence_bridge_get_stats(
                bridge_, &bridge_stats))
            return fail("failed to snapshot bridge receipt");
        if (!fk_checkpoint_reorder_get_stats(reorder_, &reorder_stats))
            return fail("failed to snapshot reorder receipt");
        if (!fk_compact_runtime_get_stats(runtime_, &runtime_stats) ||
            !fk_exact_identity_sequencer_get_stats(
                sequencer_, &sequencer_stats) ||
            !fk_exact_identity_router_get_stats(router_, &router_stats) ||
            !fk_owner_dispatch_get_stats(dispatch_, &dispatch_stats)) {
            return fail("failed to snapshot pipeline layer receipts");
        }
        if (!fk_dpdk_exact_identity_mbuf_source_get_stats(
                identity_source_, &identity_source_stats) ||
            !fk_dpdk_owner_mbuf_bytes_source_get_stats(
                owner_source_, &owner_source_stats) ||
            !fk_owner_runtime_adapter_get_stats(&adapter_, &adapter_stats) ||
            !fk_owner_output_batch_ring_get_stats(ring_, &ring_stats) ||
            !fk_quic_retirement_publisher_get_stats(
                publisher_, &publisher_stats) ||
            !fk_quic_route_receipt_get_stats(
                route_receipts_, &route_receipt_stats) ||
            !fk_quic_initial_crypto_admission_gate_get_stats(
                gate_, &gate_stats) ||
            (coordinator_ != nullptr &&
             !fk_owner_pipeline_abort_coordinator_get_stats(
                 coordinator_, &coordinator_stats))) {
            return fail("failed to snapshot service-memory receipts");
        }
        if (!fk_quic_cid_map_get_stats(cid_map_, &cid_stats) ||
            !fk_quic_cid_map_get_topology_receipt(
                cid_map_, &cid_topology) ||
            !fk_quic_presentation_path_directory_get_stats(
                path_directory_, &path_stats) ||
            !fk_owner_flow_bindings_get_stats(bindings_, &binding_stats) ||
            !fk_quic_cid_map_accounting_conserved(cid_map_) ||
            !fk_quic_presentation_path_directory_accounting_conserved(
                path_directory_) ||
            !fk_owner_flow_bindings_accounting_conserved(bindings_)) {
            return fail("failed controlled identity-state accounting receipt");
        }
        if (cid_topology.maximum_connection_slots != identity_capacity_ ||
            path_stats.maximum_logical_connections != identity_capacity_ ||
            binding_stats.maximum_connection_slots != identity_capacity_ ||
            binding_stats.total_capacity != identity_capacity_ ||
            identity_capacity_ != config_.maximum_quic_connections) {
            return fail("controlled identity capacity topology mismatch");
        }
        result_.maximum_quic_connections_configured =
            config_.maximum_quic_connections;
        result_.quic_cid_connection_capacity =
            cid_topology.maximum_connection_slots;
        result_.quic_path_connection_capacity =
            path_stats.maximum_logical_connections;
        result_.owner_binding_connection_capacity =
            binding_stats.maximum_connection_slots;

        auto &quic = result_.quic_identity;
        quic = {};
        quic.abi_version =
            FK_NO_NIC_QUIC_IDENTITY_OBSERVABILITY_ABI_VERSION;
        quic.maximum_connections = config_.maximum_quic_connections;
        quic.cid_map_maximum_connections =
            cid_topology.maximum_connection_slots;
        quic.path_maximum_connections =
            path_stats.maximum_logical_connections;
        quic.binding_maximum_connections =
            binding_stats.maximum_connection_slots;
        quic.cid_active_connections_at_end = cid_stats.active_connections;
        quic.cid_peak_active_connections = cid_stats.peak_active_connections;
        quic.cid_active_cids_at_end = cid_stats.active_cids;
        quic.cid_peak_active_cids = cid_stats.peak_active_cids;
        quic.cid_pending_handshakes_at_end = cid_stats.pending_handshakes;
        quic.cid_peak_pending_handshakes =
            cid_stats.peak_pending_handshakes;
        quic.cid_retired_pending_owner_ack_at_end =
            cid_stats.retired_pending_owner_ack;
        quic.cid_binding_credits_in_use_at_end =
            cid_stats.binding_credits_in_use;
        quic.path_active_connections_at_end =
            path_stats.active_logical_connections;
        quic.path_peak_active_connections =
            path_stats.peak_active_logical_connections;
        quic.path_active_paths_at_end = path_stats.active_paths;
        quic.path_peak_active_paths = path_stats.peak_active_paths;
        quic.binding_active_at_end = binding_stats.active_bindings;
        quic.binding_peak_active_sum =
            binding_stats.peak_active_bindings_sum;
        quic.binding_unbound_at_end = binding_stats.unbound_slots;
        quic.binding_retired_pending_at_end =
            binding_stats.retired_pending_cid_ack_slots;

        quic.router_quic_initial_packets = router_stats.quic_initial_packets;
        quic.router_quic_long_packets = router_stats.quic_long_packets;
        quic.router_quic_short_packets = router_stats.quic_short_packets;
        quic.cid_observations = cid_stats.observations;
        quic.cid_connections_created = cid_stats.connections_created;
        quic.cid_connection_capacity_rejects =
            cid_stats.connection_capacity_rejects;
        quic.cid_fixed_owner_capacity_rejects =
            cid_stats.fixed_owner_capacity_rejects;
        quic.cid_capacity_rejects = cid_stats.cid_capacity_rejects;
        quic.cid_per_connection_capacity_rejects =
            cid_stats.per_connection_cid_capacity_rejects;
        quic.cid_pending_handshake_capacity_rejects =
            cid_stats.pending_handshake_capacity_rejects;
        quic.cid_hash_chain_lookup_rejects =
            cid_stats.hash_chain_lookup_rejects;
        quic.cid_hash_chain_registration_rejects =
            cid_stats.hash_chain_registration_rejects;
        quic.cid_hash_chain_internal_rejects =
            cid_stats.hash_chain_internal_rejects;
        quic.cid_direction_conflicts = cid_stats.direction_conflicts;
        quic.cid_same_cid_dual_role_rejects =
            cid_stats.same_cid_dual_role_rejects;
        quic.cid_hard_integrity_failures =
            cid_stats.hard_integrity_failures;
        quic.cid_allocator_integrity_failures =
            cid_stats.allocator_integrity_failures;

        quic.path_classify_calls = path_stats.classify_calls;
        quic.path_register_calls = path_stats.authenticated_register_calls;
        quic.path_rejected_operations = path_stats.rejected_operations;
        quic.path_global_capacity_rejects =
            path_stats.global_capacity_rejects;
        quic.path_per_connection_capacity_rejects =
            path_stats.per_connection_capacity_rejects;
        quic.path_hash_chain_capacity_rejects =
            path_stats.hash_chain_capacity_rejects;
        quic.path_invalid_input_rejects =
            path_stats.invalid_input_rejects;
        quic.path_generation_conflict_rejects =
            path_stats.logical_generation_conflict_rejects;
        quic.path_internal_integrity_rejects =
            path_stats.internal_integrity_rejects;

        const auto &binding_counters = binding_stats.counters;
        quic.binding_bind_attempts = binding_counters.bind_attempts;
        quic.binding_created = binding_counters.bindings_created;
        quic.binding_idempotent = binding_counters.bind_idempotent;
        quic.binding_conflicts = binding_counters.bind_conflicts;
        quic.binding_missing_rejects =
            binding_counters.missing_binding_rejects;
        quic.binding_stale_generation_rejects =
            binding_counters.stale_generation_rejects;
        quic.binding_handle_mismatch_rejects =
            binding_counters.handle_mismatch_rejects;
        quic.binding_direction_mismatch_rejects =
            binding_counters.direction_mismatch_rejects;
        quic.binding_cid_generation_mismatch_rejects =
            binding_counters.cid_generation_mismatch_rejects;
        quic.binding_fixed_owner_mismatch_rejects =
            binding_counters.fixed_owner_mismatch_rejects;
        quic.binding_slot_reuse_rejects =
            binding_counters.slot_reuse_before_retire_ack_rejects;
        quic.binding_retire_expectation_rejects =
            binding_counters.retire_expectation_mismatch_rejects;
        quic.binding_slot_out_of_range_rejects =
            binding_counters.slot_out_of_range_rejects;
        quic.binding_invalid_requests = binding_counters.invalid_requests;
        quic.binding_state_integrity_failures =
            binding_counters.state_integrity_failures;

        quic.crypto_gate_begin_attempts = gate_stats.begin_attempts;
        quic.crypto_gate_begin_allowed = gate_stats.begin_allowed;
        quic.crypto_gate_begin_deferred = gate_stats.begin_deferred;
        quic.crypto_gate_begin_rejected = gate_stats.begin_rejected;
        quic.crypto_gate_pressure_rejects = gate_stats.pressure_rejects;
        quic.crypto_gate_global_token_rejects =
            gate_stats.global_token_rejects;
        quic.crypto_gate_prefix_credit_rejects =
            gate_stats.prefix_credit_rejects;
        quic.crypto_gate_prefix_table_rejects =
            gate_stats.prefix_table_rejects;
        quic.crypto_gate_oversized_rejects =
            gate_stats.oversized_crypto_input_rejects;
        quic.crypto_gate_invalid_request_rejects =
            gate_stats.invalid_request_rejects;
        quic.crypto_gate_internal_rejects = gate_stats.internal_rejects;

        const auto add_rejection = [this](
                uint64_t &total, uint64_t value) {
            return checked_add_u64(total, value) ||
                fail("QUIC identity rejection counter overflow");
        };
        bool rejection_sums_valid = true;
        for (uint64_t value : {
                 quic.cid_connection_capacity_rejects,
                 quic.cid_fixed_owner_capacity_rejects,
                 quic.cid_capacity_rejects,
                 quic.cid_per_connection_capacity_rejects,
                 quic.cid_pending_handshake_capacity_rejects,
                 quic.cid_hash_chain_registration_rejects,
                 quic.cid_direction_conflicts,
                 quic.cid_allocator_integrity_failures}) {
            rejection_sums_valid = rejection_sums_valid &&
                add_rejection(quic.cid_map_admission_rejections, value);
        }
        quic.path_admission_rejections = path_stats.rejected_operations;
        for (uint64_t value : {
                 quic.binding_conflicts,
                 quic.binding_missing_rejects,
                 quic.binding_stale_generation_rejects,
                 quic.binding_handle_mismatch_rejects,
                 quic.binding_direction_mismatch_rejects,
                 quic.binding_cid_generation_mismatch_rejects,
                 quic.binding_fixed_owner_mismatch_rejects,
                 quic.binding_slot_reuse_rejects,
                 quic.binding_retire_expectation_rejects,
                 quic.binding_slot_out_of_range_rejects,
                 quic.binding_invalid_requests,
                 quic.binding_state_integrity_failures}) {
            rejection_sums_valid = rejection_sums_valid &&
                add_rejection(quic.binding_admission_rejections, value);
        }
        rejection_sums_valid = rejection_sums_valid &&
            add_rejection(
                quic.admission_rejections,
                quic.cid_map_admission_rejections) &&
            add_rejection(
                quic.admission_rejections,
                quic.path_admission_rejections) &&
            add_rejection(
                quic.admission_rejections,
                quic.binding_admission_rejections);
        if (!rejection_sums_valid)
            return false;
        quic.capacity_conserved =
            quic.maximum_connections == quic.cid_map_maximum_connections &&
                    quic.maximum_connections ==
                        quic.path_maximum_connections &&
                    quic.maximum_connections ==
                        quic.binding_maximum_connections
                ? 1u : 0u;
        quic.finite_epoch_drain_timestamp_ns =
            finite_epoch_quic_drain_.terminal_semantic_timestamp_ns;
        quic.finite_epoch_active_before =
            finite_epoch_quic_drain_.active_connections_before;
        quic.finite_epoch_connections_drained =
            finite_epoch_quic_drain_.connections_drained;
        quic.finite_epoch_active_after =
            finite_epoch_quic_drain_.active_connections_after;
        quic.finite_epoch_drain_reason = static_cast<uint8_t>(
            finite_epoch_quic_drain_.reason);
        quic.finite_epoch_drain_requested =
            external_io_enabled(config_) ? 1u : 0u;
        quic.finite_epoch_drain_after_input_eof =
            finite_epoch_quic_drain_after_input_eof_ ? 1u : 0u;
        quic.finite_epoch_path_active_connections_before =
            finite_epoch_quic_path_drain_
                .active_logical_connections_before;
        quic.finite_epoch_paths_before =
            finite_epoch_quic_path_drain_.active_paths_before;
        quic.finite_epoch_paths_drained =
            finite_epoch_quic_path_drain_.paths_drained;
        quic.finite_epoch_path_active_connections_after =
            finite_epoch_quic_path_drain_
                .active_logical_connections_after;
        quic.finite_epoch_paths_after =
            finite_epoch_quic_path_drain_.active_paths_after;
        quic.finite_epoch_path_drain_reason = static_cast<uint8_t>(
            finite_epoch_quic_path_drain_.reason);
        quic.finite_epoch_path_drain_complete =
            external_io_enabled(config_)
                ? finite_epoch_quic_path_drain_.complete : 1u;
        quic.finite_epoch_drain_complete =
            external_io_enabled(config_)
                ? static_cast<uint8_t>(
                    finite_epoch_quic_drain_.complete != 0u &&
                    finite_epoch_quic_path_drain_.complete != 0u)
                : 1u;

        quic.router_quic_data_committed_transfers =
            router_stats.quic_data_committed_transfers;
        quic.router_quic_skip_committed_reclaims =
            router_stats.quic_skip_committed_reclaims;
        uint64_t router_quic_observations =
            quic.router_quic_initial_packets;
        uint64_t router_quic_dispositions =
            quic.router_quic_data_committed_transfers;
        const bool router_quic_sums_valid =
            checked_add_u64(
                router_quic_observations,
                quic.router_quic_long_packets) &&
            checked_add_u64(
                router_quic_observations,
                quic.router_quic_short_packets) &&
            checked_add_u64(
                router_quic_dispositions,
                quic.router_quic_skip_committed_reclaims);
        quic.router_quic_disposition_conserved =
            router_quic_sums_valid &&
                    router_quic_observations == router_quic_dispositions &&
                    quic.router_quic_data_committed_transfers ==
                        owner_stats.data_quic
                ? 1u : 0u;

        quic.publisher_controls_committed =
            publisher_stats.controls_committed;
        quic.publisher_terminal_batches_committed =
            publisher_stats.terminal_batches_committed;
        quic.publisher_terminal_empty = publisher_stats.terminal_empty;
        quic.publisher_marked_controls_at_end =
            publisher_stats.current_marked_controls;
        quic.dispatch_retire_controls_enqueued =
            dispatch_stats.retire_controls_enqueued;
        quic.dispatch_retire_controls_normal_dequeued =
            dispatch_stats.retire_controls_normal_dequeued;
        quic.dispatch_retire_control_depth_at_end =
            dispatch_stats.retire_control_depth;
        quic.owner_retire_controls_dequeued = owner_stats.retire_dequeued;
        quic.owner_retire_controls_acked = owner_stats.retire_acked;
        quic.adapter_retire_calls = adapter_stats.retire_calls;
        quic.adapter_retire_acked = adapter_stats.retire_acked;
        quic.cid_retirement_ack_calls = cid_stats.retirement_ack_calls;
        quic.cid_retirement_acks = cid_stats.retirement_acks;
        quic.cid_connections_retired_pending_owner_ack_total =
            cid_stats.connections_retired_pending_owner_ack;
        quic.cid_retirement_publication_marks =
            cid_stats.retirement_publication_marks;
        quic.dispatch_observations_sealed =
            dispatch_stats.observations_sealed ? 1u : 0u;
        bool retirement_failure_sum_valid = true;
        for (const uint64_t failure : {
                 cid_stats.retirement_ack_empty,
                 cid_stats.retirement_ack_mismatches,
                 cid_stats.retirement_ack_invalid,
                 cid_stats.retirement_ack_cleanup_failures,
                 cid_stats.retirement_ack_not_dispatched,
                 adapter_stats.retirement_ack_failures,
                 owner_stats.retire_terminal_results,
                 owner_stats.retire_controls_aborted}) {
            retirement_failure_sum_valid =
                checked_add_u64(quic.retirement_ack_failures, failure) &&
                retirement_failure_sum_valid;
        }
        if (!retirement_failure_sum_valid)
            return fail("QUIC retirement ACK counter overflow");
        quic.publisher_accounting_conserved =
            fk_quic_retirement_publisher_accounting_conserved(publisher_)
                ? 1u : 0u;
        quic.publisher_formal_complete =
            fk_quic_retirement_publisher_formal_complete(publisher_)
                ? 1u : 0u;
        uint64_t publisher_terminal_outcomes =
            publisher_stats.terminal_batches_committed;
        uint64_t cid_retirement_ack_outcomes =
            quic.cid_retirement_acks;
        const bool retirement_outcome_sums_valid =
            checked_add_u64(
                publisher_terminal_outcomes,
                publisher_stats.terminal_empty) &&
            checked_add_u64(
                cid_retirement_ack_outcomes,
                quic.retirement_ack_failures);
        quic.retirement_delivery_conserved =
            retirement_outcome_sums_valid &&
                    quic.publisher_accounting_conserved != 0u &&
                    quic.publisher_formal_complete != 0u &&
                    publisher_stats.terminal_calls != 0u &&
                    publisher_stats.terminal_empty == 1u &&
                    publisher_terminal_outcomes ==
                        publisher_stats.terminal_calls &&
                    quic.publisher_marked_controls_at_end == 0u &&
                    dispatch_stats.retire_controls_conserved &&
                    quic.dispatch_retire_control_depth_at_end == 0u &&
                    quic.publisher_controls_committed ==
                        quic.dispatch_retire_controls_enqueued &&
                    quic.publisher_controls_committed ==
                        quic.cid_connections_retired_pending_owner_ack_total &&
                    quic.publisher_controls_committed ==
                        quic.cid_retirement_publication_marks &&
                    quic.dispatch_retire_controls_enqueued ==
                        quic.dispatch_retire_controls_normal_dequeued &&
                    quic.dispatch_retire_controls_normal_dequeued ==
                        quic.owner_retire_controls_dequeued &&
                    quic.owner_retire_controls_dequeued ==
                        quic.owner_retire_controls_acked &&
                    quic.owner_retire_controls_acked ==
                        quic.adapter_retire_calls &&
                    quic.adapter_retire_calls ==
                        quic.adapter_retire_acked &&
                    quic.adapter_retire_acked ==
                        quic.cid_retirement_acks &&
                    quic.cid_retirement_ack_calls ==
                        cid_retirement_ack_outcomes
                ? 1u : 0u;
        quic.terminal_active_zero =
            quic.cid_active_connections_at_end == 0u &&
                    quic.cid_active_cids_at_end == 0u &&
                    quic.cid_pending_handshakes_at_end == 0u &&
                    quic.cid_retired_pending_owner_ack_at_end == 0u &&
                    quic.cid_binding_credits_in_use_at_end == 0u &&
                    quic.path_active_connections_at_end == 0u &&
                    quic.path_active_paths_at_end == 0u &&
                    quic.binding_active_at_end == 0u &&
                    quic.binding_unbound_at_end == 0u &&
                    quic.binding_retired_pending_at_end == 0u
                ? 1u : 0u;
        quic.owner_ack_complete =
            quic.retirement_delivery_conserved != 0u &&
                    quic.retirement_ack_failures == 0u &&
                    quic.terminal_active_zero != 0u
                ? 1u : 0u;
        quic.finite_epoch_drain_before_publisher_terminal =
            (!external_io_enabled(config_) ||
             (quic.finite_epoch_drain_after_input_eof != 0u &&
              quic.finite_epoch_drain_complete != 0u &&
              publisher_stats.terminal_calls != 0u &&
              publisher_terminal_outcomes ==
                  publisher_stats.terminal_calls))
                ? 1u : 0u;
        quic.admission_rejections_zero =
            quic.admission_rejections == 0u &&
                    quic.crypto_gate_begin_rejected == 0u
                ? 1u : 0u;
        quic.tcp_only_no_quic_activity =
            quic.router_quic_initial_packets == 0u &&
                    quic.router_quic_long_packets == 0u &&
                    quic.router_quic_short_packets == 0u &&
                    quic.cid_observations == 0u &&
                    quic.path_classify_calls == 0u &&
                    quic.path_register_calls == 0u &&
                    quic.binding_bind_attempts == 0u &&
                    quic.crypto_gate_begin_attempts == 0u &&
                    quic.terminal_active_zero != 0u &&
                    quic.admission_rejections_zero != 0u
                ? 1u : 0u;
        const uintptr_t adapter_token =
            reinterpret_cast<uintptr_t>(&adapter_);
        if (!fk_compact_runtime_owner_adapter_scope_begin(
                runtime_, adapter_token, 0u))
            return fail("failed to enter compact table receipt scope");
        fk_compact_flow_table *table =
            fk_compact_runtime_flow_table(runtime_);
        const bool table_stats_ok = table != nullptr &&
            fk_compact_flow_table_get_stats(table, &table_stats);
        if (table_stats_ok)
            fk_compact_flow_table_budget_snapshot(table, &budget_stats);
        const bool scope_ended =
            fk_compact_runtime_owner_adapter_scope_end(
                runtime_, adapter_token, 0u);
        if (!table_stats_ok || !scope_ended)
            return fail("failed to snapshot compact table receipt");
        result_.rx_received = rx_stats.rx_received;
        result_.sequencer_transferred = rx_stats.sequencer_transferred;
        result_.identity_data_transfers = identity_stats.data_transfers;
        result_.owner_packets_completed = owner_stats.data_packets_completed;
        bool io_conserved = false;
        if (external_io_enabled(config_)) {
            if (!config_.io_stats(config_.io_stats_context, &io_stats))
                return fail("failed to snapshot external IO receipt");
            result_.mbufs_reclaimed = io_stats.reclaim_successes;
            result_.io_duplicate_reclaims = io_stats.duplicate_reclaims;
            result_.io_live_mbufs = io_stats.live_mbufs;
            result_.io_forced_failure_reclaims =
                io_stats.forced_failure_reclaims;
            result_.source_exhausted = io_stats.source_exhausted;
            result_.source_failed = io_stats.source_failed;
            io_conserved = io_stats.accounting_conserved != 0u;
        } else {
            result_.mbufs_reclaimed = trace_.reclaim_successes;
            result_.io_duplicate_reclaims = trace_.duplicate_reclaims;
            result_.io_live_mbufs =
                trace_.packets.size() - trace_.reclaim_successes;
            result_.source_exhausted = 1u;
            io_conserved = trace_.all_reclaimed();
        }
        result_.flow_table_reserved_bytes =
            table_stats.mandatory_allocation_bytes +
            table_stats.pool_reserved_bytes;
        result_.flow_table_current_bytes = budget_stats.used_bytes;
        result_.flow_table_peak_bytes = budget_stats.peak_bytes;
        result_.controlled_allocation_bytes =
            result_.flow_table_reserved_bytes;
        result_.controlled_state_ceiling_bytes = budget_stats.budget_bytes;
        result_.controlled_state_unassigned_bytes =
            table_stats.pool_unassigned_bytes;
        result_.controlled_state_current_bytes = budget_stats.used_bytes;
        result_.controlled_state_peak_bytes = budget_stats.peak_bytes;
        result_.controlled_state_hard_budget_violations =
            budget_stats.hard_budget_violations;
        result_.controlled_state_byte_seconds =
            runtime_stats.controlled_state_byte_seconds;
        double component_byte_seconds_sum = 0.0;
        bool byte_seconds_finite =
            std::isfinite(result_.controlled_state_byte_seconds) &&
            result_.controlled_state_byte_seconds >= 0.0;
        for (size_t component = 0u;
             component < FK_MEMORY_COMPONENT_COUNT; ++component) {
            result_.state_byte_seconds_by_component[component] =
                runtime_stats.state_byte_seconds_by_component[component];
            const double value =
                result_.state_byte_seconds_by_component[component];
            byte_seconds_finite = byte_seconds_finite &&
                std::isfinite(value) && value >= 0.0;
            component_byte_seconds_sum += value;
        }
        const double byte_seconds_tolerance = std::max(
            1.0e-6,
            std::fabs(result_.controlled_state_byte_seconds) * 1.0e-9);
        result_.state_byte_seconds_complete =
            byte_seconds_finite && runtime_stats.semantic_time_initialized &&
                    (!external_io_enabled(config_) ||
                     runtime_stats.semantic_last_timestamp_ns ==
                         config_.terminal_semantic_timestamp_ns) &&
                    std::fabs(
                        component_byte_seconds_sum -
                        result_.controlled_state_byte_seconds) <=
                        byte_seconds_tolerance
                ? 1u : 0u;
        result_.controlled_state_accounting_valid = 1u;
        if (external_io_enabled(config_)) {
            if (cid_stats.reserved_bytes != cid_reserved_bytes_ ||
                path_stats.reserved_bytes != path_reserved_bytes_ ||
                binding_stats.reserved_bytes != binding_reserved_bytes_ ||
                binding_stats.entry_bytes == 0u ||
                binding_stats.total_capacity >
                    std::numeric_limits<uint64_t>::max() /
                        binding_stats.entry_bytes) {
                return fail("controlled identity reservation mismatch");
            }
            const uint64_t binding_variable_capacity =
                binding_stats.total_capacity * binding_stats.entry_bytes;
            if (binding_variable_capacity > binding_stats.reserved_bytes ||
                binding_stats.empty_slots > binding_stats.total_capacity) {
                return fail("controlled binding byte accounting mismatch");
            }
            const uint64_t binding_fixed_bytes =
                binding_stats.reserved_bytes - binding_variable_capacity;
            const uint64_t binding_occupied =
                binding_stats.total_capacity - binding_stats.empty_slots;
            uint64_t binding_peak_occupied =
                binding_stats.peak_active_bindings_sum;
            if (!checked_add_u64(
                    binding_peak_occupied,
                    binding_stats.peak_unbound_slots_sum) ||
                !checked_add_u64(
                    binding_peak_occupied,
                    binding_stats.peak_retired_pending_cid_ack_slots_sum)) {
                return fail("controlled binding peak overflow");
            }
            binding_peak_occupied = std::min(
                binding_peak_occupied, binding_stats.total_capacity);
            result_.quic_cid_reserved_bytes = cid_stats.reserved_bytes;
            result_.quic_cid_current_bytes = cid_stats.used_bytes;
            result_.quic_cid_peak_bytes = cid_stats.peak_used_bytes;
            result_.quic_path_reserved_bytes = path_stats.reserved_bytes;
            result_.quic_path_current_bytes = path_stats.used_bytes;
            result_.quic_path_peak_bytes = path_stats.peak_used_bytes;
            result_.owner_binding_reserved_bytes =
                binding_stats.reserved_bytes;
            result_.owner_binding_current_bytes = binding_fixed_bytes +
                binding_occupied * binding_stats.entry_bytes;
            result_.owner_binding_peak_bytes = binding_fixed_bytes +
                binding_peak_occupied * binding_stats.entry_bytes;

            result_.controlled_allocation_bytes =
                identity_controlled_reserved_bytes_;
            result_.controlled_state_current_bytes =
                result_.flow_table_current_bytes;
            result_.controlled_state_peak_bytes =
                result_.flow_table_peak_bytes;
            result_.controlled_state_hard_budget_violations =
                budget_stats.hard_budget_violations +
                cid_stats.hard_budget_violations;
            bool combined = checked_add_u64(
                    result_.controlled_allocation_bytes,
                    result_.flow_table_reserved_bytes) &&
                checked_add_u64(
                    result_.controlled_state_current_bytes,
                    result_.quic_cid_current_bytes) &&
                checked_add_u64(
                    result_.controlled_state_current_bytes,
                    result_.quic_path_current_bytes) &&
                checked_add_u64(
                    result_.controlled_state_current_bytes,
                    result_.owner_binding_current_bytes) &&
                checked_add_u64(
                    result_.controlled_state_peak_bytes,
                    result_.quic_cid_peak_bytes) &&
                checked_add_u64(
                    result_.controlled_state_peak_bytes,
                    result_.quic_path_peak_bytes) &&
                checked_add_u64(
                    result_.controlled_state_peak_bytes,
                    result_.owner_binding_peak_bytes);
            result_.controlled_state_ceiling_bytes =
                identity_controlled_reserved_bytes_;
            combined = combined && checked_add_u64(
                result_.controlled_state_ceiling_bytes,
                budget_stats.budget_bytes);
            if (!combined ||
                result_.controlled_allocation_bytes >
                    result_.controlled_state_ceiling_bytes ||
                result_.controlled_state_peak_bytes >
                    result_.controlled_state_ceiling_bytes) {
                ++result_.controlled_state_hard_budget_violations;
                result_.controlled_state_accounting_valid = 0u;
            } else {
                result_.controlled_state_unassigned_bytes =
                    result_.controlled_state_ceiling_bytes -
                    result_.controlled_allocation_bytes;
                const uint64_t configured_ceiling =
                    controlled_budget_bytes(config_.budget_mode);
                if ((configured_ceiling != 0u &&
                     configured_ceiling !=
                         result_.controlled_state_ceiling_bytes) ||
                    result_.controlled_state_unassigned_bytes !=
                        table_stats.pool_unassigned_bytes) {
                    ++result_.controlled_state_hard_budget_violations;
                    result_.controlled_state_accounting_valid = 0u;
                }
            }
        }
        result_.peak_evidence_storage_bytes =
            table_stats.peak_evidence_storage_bytes;
        result_.bridge_service_memory_bytes =
            bridge_stats.service_memory_bytes;
        result_.reorder_service_memory_bytes = reorder_stats.reserved_bytes;
        result_.rx_callback_retries =
            rx_stats.burst_callback_retries +
            rx_stats.clock_callback_retries +
            rx_stats.decode_callback_retries +
            rx_stats.reclaim_callback_retries;
        result_.rx_shape_rejections =
            rx_stats.null_mbuf_failures + rx_stats.multi_segment_failures +
            rx_stats.non_direct_failures + rx_stats.full_capture_failures +
            rx_stats.shape_failures + rx_stats.duplicate_handle_failures +
            rx_stats.mutation_failures +
            rx_stats.sequence_replay_failures +
            rx_stats.sequence_range_failures + rx_stats.timestamp_failures;
        result_.sequencer_queue_full_rejections =
            sequencer_stats.queue_full_rejections;
        result_.sequencer_integrity_rejections =
            sequencer_stats.invalid_submissions +
            sequencer_stats.out_of_range_submissions +
            sequencer_stats.closed_producer_rejections +
            sequencer_stats.aborted_rejections +
            sequencer_stats.invalid_close_attempts +
            sequencer_stats.duplicate_sequences +
            sequencer_stats.window_overflows +
            sequencer_stats.slot_conflicts +
            sequencer_stats.semantic_time_regressions +
            sequencer_stats.terminal_gaps;
        result_.identity_skip_reclaims =
            identity_stats.reclaimed_skip_packets;
        result_.identity_reject_reclaims =
            identity_stats.reclaimed_reject_packets;
        result_.identity_backpressure = identity_stats.router_backpressure;
        result_.router_resolver_rejections = router_stats.resolver_rejections;
        result_.router_parser_rejections = router_stats.parser_rejections;
        result_.router_parser_successes = router_stats.parser_successes;
        uint64_t parser_reason_total = 0u;
        for (unsigned code = FK_PARSE_OK;
             code <= FK_PARSE_CAP_EXCEEDED; ++code) {
            result_.router_parser_rejections_by_code[code] =
                router_stats.parser_rejections_by_code[code];
            if (!checked_add_u64(
                    parser_reason_total,
                    router_stats.parser_rejections_by_code[code])) {
                return fail("router parser reason counter overflow");
            }
        }
        result_.router_parser_reason_conserved =
            router_stats.parser_reason_conserved != 0u &&
                    router_stats.parser_rejections_by_code[FK_PARSE_OK] ==
                        0u &&
                    parser_reason_total == router_stats.parser_rejections
                ? 1u : 0u;
        result_.router_identity_rejections =
            router_stats.cid_unresolved + router_stats.cid_ambiguous +
            router_stats.cid_rejected +
            router_stats.path_register_rejections +
            router_stats.route_receipt_rejections;
        result_.router_completion_backpressure =
            router_stats.completion_reservation_backpressure +
            router_stats.backpressure_retentions;
        result_.router_completion_rejections =
            router_stats.completion_reservation_rejections +
            router_stats.completion_route_bind_rejections +
            router_stats.skip_completion_publish_rejections;
        result_.dispatch_ordered_skips =
            dispatch_stats.ordered_skipped_observations;
        result_.dispatch_queue_full = dispatch_stats.queue_full;
        result_.dispatch_invalid_routes = dispatch_stats.invalid_routes;
        result_.owner_ignored = owner_stats.data_ignored;
        result_.owner_ordinary = owner_stats.data_ordinary;
        result_.owner_quic = owner_stats.data_quic;
        result_.owner_admission_rejected =
            owner_stats.data_admission_rejected;
        result_.owner_output_backpressure =
            owner_stats.data_output_backpressure +
            owner_stats.output_ring_full;
        result_.owner_terminal_results =
            owner_stats.data_terminal_results +
            owner_stats.retire_terminal_results;
        result_.owner_reclaim_failures = owner_stats.reclaim_failures;
        result_.owner_data_semantic_drain_retries =
            owner_stats.data_semantic_drain_required;
        result_.owner_retire_semantic_drain_retries =
            owner_stats.retire_semantic_drain_required;
        result_.adapter_semantic_data_step_calls =
            adapter_stats.semantic_data_step_calls;
        result_.adapter_semantic_data_step_completions =
            adapter_stats.semantic_data_step_completions;
        result_.adapter_semantic_data_drain_required =
            adapter_stats.semantic_data_drain_required;
        result_.adapter_semantic_data_step_failures =
            adapter_stats.semantic_data_step_failures;
        result_.adapter_semantic_retire_step_calls =
            adapter_stats.semantic_retire_step_calls;
        result_.adapter_semantic_retire_step_completions =
            adapter_stats.semantic_retire_step_completions;
        result_.adapter_semantic_retire_drain_required =
            adapter_stats.semantic_retire_drain_required;
        result_.adapter_semantic_retire_step_failures =
            adapter_stats.semantic_retire_step_failures;
        result_.bridge_reservation_backpressure =
            bridge_stats.reservation_full_backpressure;
        result_.bridge_reorder_backpressure =
            bridge_stats.reorder_capacity_backpressure;
        result_.bridge_publication_rejections =
            bridge_stats.invalid_publications +
            bridge_stats.duplicate_publications +
            bridge_stats.out_of_range_publications +
            bridge_stats.stopped_publications +
            bridge_stats.unreserved_publications +
            bridge_stats.terminal_publications;
        result_.bridge_integrity_rejections =
            bridge_stats.out_of_order_reservations +
            bridge_stats.out_of_range_reservations +
            bridge_stats.reservation_thread_rejections +
            bridge_stats.reservation_internal_failures +
            bridge_stats.epoch_close_prefix_mismatches +
            bridge_stats.epoch_close_unbound_routes +
            bridge_stats.atomic_reorder_push_failures +
            bridge_stats.owner_mismatches +
            bridge_stats.packet_sequence_mismatches +
            bridge_stats.association_mask_mismatches +
            bridge_stats.invalid_output_batches +
            bridge_stats.flow_identity_failures;
        result_.runtime_parse_ignored = runtime_stats.parse_ignored;
        result_.runtime_frames = runtime_stats.frames;
        result_.runtime_post_final_checkpoint_tail_packets =
            runtime_stats.post_final_checkpoint_tail_packets;
        result_.runtime_bound_final_tail_fast_path_packets =
            runtime_stats.bound_final_tail_fast_path_packets;
        result_.runtime_flow_admission_rejects =
            runtime_stats.flow_admission_rejects;
        result_.runtime_state_update_failures =
            runtime_stats.state_update_failures;
        result_.runtime_checkpoint_failures =
            runtime_stats.checkpoint_failures;
        result_.checkpoint_intervention =
            runtime_stats.checkpoint_intervention;
        auto &intervention_receipt = result_.checkpoint_intervention;
        intervention_receipt.trace_checkpoint_matches =
            checkpoint_intervention_trace_matches_;
        intervention_receipt.trace_binding_mismatches =
            checkpoint_intervention_trace_binding_mismatches_;
        intervention_receipt.trace_binding_complete =
            config_.checkpoint_intervention.enabled == 0u
            ? 1u
            : (checkpoint_intervention_trace_matches_ == 1u &&
               checkpoint_intervention_trace_binding_mismatches_ == 0u
                ? 1u : 0u);
        intervention_receipt.complete =
            intervention_receipt.complete != 0u &&
                    (config_.checkpoint_intervention.enabled == 0u ||
                     intervention_receipt.one_shot_disarmed != 0u) &&
                    intervention_receipt.trace_binding_complete != 0u
                ? 1u : 0u;
        if (config_.checkpoint_intervention.enabled != 0u &&
            intervention_receipt.complete == 0u) {
            return fail(
                "source-record checkpoint intervention receipt incomplete");
        }
        result_.runtime_optional_timer_exact_boundaries =
            runtime_stats.optional_timer_exact_boundaries;
        result_.runtime_optional_timer_boundary_stalls =
            runtime_stats.optional_timer_boundary_stalls;
        result_.runtime_timer_deadline_queries =
            runtime_stats.optional_timer_deadline_queries;
        result_.runtime_timer_deadline_rebuilds =
            runtime_stats.optional_timer_deadline_rebuilds;
        result_.runtime_timer_deadline_probes =
            runtime_stats.optional_timer_deadline_probes;
        result_.runtime_idle_scan_calls =
            runtime_stats.idle_scan_calls;
        result_.runtime_idle_scan_probes =
            runtime_stats.idle_scan_probes;
        result_.runtime_idle_scan_gated_calls =
            runtime_stats.idle_scan_gated_calls;
        result_.runtime_idle_scan_completed_cycles =
            runtime_stats.idle_scan_completed_cycles;
        result_.table_admission_rejects = table_stats.admission_rejects;
        result_.table_evidence_allocation_failures =
            table_stats.evidence_allocation_failures;
        uint64_t owner_final_dispositions = result_.owner_ordinary;
        uint64_t ingress_dispositions = result_.runtime_frames;
        uint64_t parser_dispositions = result_.router_parser_successes;
        const bool disposition_sums_valid =
            checked_add_u64(owner_final_dispositions, result_.owner_quic) &&
            checked_add_u64(owner_final_dispositions, result_.owner_ignored) &&
            checked_add_u64(
                owner_final_dispositions,
                result_.owner_admission_rejected) &&
            checked_add_u64(
                ingress_dispositions, result_.identity_skip_reclaims) &&
            checked_add_u64(
                ingress_dispositions, result_.identity_reject_reclaims) &&
            checked_add_u64(
                parser_dispositions, result_.router_parser_rejections);
        if (!disposition_sums_valid)
            return fail("packet disposition counter overflow");
        result_.packet_disposition_conserved =
            result_.router_parser_reason_conserved != 0u &&
                    parser_dispositions == result_.packets_created &&
                    ingress_dispositions == result_.packets_created &&
                    result_.owner_packets_completed ==
                        result_.runtime_frames &&
                    owner_final_dispositions == result_.runtime_frames &&
                    result_.owner_ignored == result_.runtime_parse_ignored &&
                    result_.owner_admission_rejected ==
                        result_.runtime_flow_admission_rejects &&
                    result_.owner_terminal_results == 0u
                ? 1u : 0u;
        auto &transition_receipt = result_.evidence_transitions;
        transition_receipt.table_records_emitted =
            table_stats.transition_records_emitted;
        transition_receipt.runtime_records_drained =
            runtime_stats.evidence_transition_records_drained;
        transition_receipt.queue_full_rejects =
            table_stats.transition_queue_full_rejects;
        transition_receipt.terminal_pending =
            table_stats.transition_queue_pending;
        transition_receipt.sequence_contiguous =
            transition_receipt.sequence_failures == 0u &&
                    (transition_receipt.trace_records_emitted == 0u ||
                     transition_receipt.last_transition_sequence + 1u ==
                         transition_receipt.trace_records_emitted)
                ? 1u : 0u;
        transition_receipt.terminal_queue_empty =
            transition_receipt.terminal_pending == 0u ? 1u : 0u;
        transition_receipt.complete =
            transition_receipt.sequence_contiguous != 0u &&
                    transition_receipt.terminal_queue_empty != 0u &&
                    transition_receipt.queue_full_rejects == 0u &&
                    transition_receipt.table_records_emitted ==
                        transition_receipt.runtime_records_drained &&
                    transition_receipt.runtime_records_drained ==
                        transition_receipt.trace_records_emitted &&
                    transition_receipt.trace_records_emitted ==
                        result_.observability.evidence_transition_records &&
                    (config_.abort_after_identity_transfers != 0u ||
                     transition_receipt.terminal_timer_scan_passes != 0u)
                ? 1u : 0u;
        if (config_.abort_after_identity_transfers == 0u &&
            transition_receipt.complete == 0u) {
            return fail("evidence transition terminal receipt is incomplete");
        }
        result_.flows_created = table_stats.flows_created;
        result_.flows_released = table_stats.flows_released;
        result_.active_flows = table_stats.active_flows;
        result_.peak_active_flows = table_stats.peak_active_flows;
        result_.stat_pool = {
            table_stats.stat_pool_block_bytes,
            table_stats.stat_pool_capacity,
            table_stats.stat_pool_in_use,
            table_stats.stat_pool_peak_in_use,
            table_stats.stat_pool_allocations,
            table_stats.stat_pool_allocation_rejects};
        result_.seq_pool = {
            table_stats.seq_pool_block_bytes,
            table_stats.seq_pool_capacity,
            table_stats.seq_pool_in_use,
            table_stats.seq_pool_peak_in_use,
            table_stats.seq_pool_allocations,
            table_stats.seq_pool_allocation_rejects};
        result_.ja4_pending_pool = {
            table_stats.ja4_pending_pool_block_bytes,
            table_stats.ja4_pending_pool_capacity,
            table_stats.ja4_pending_pool_in_use,
            table_stats.ja4_pending_pool_peak_in_use,
            table_stats.ja4_pending_pool_allocations,
            table_stats.ja4_pending_pool_allocation_rejects};
        result_.ja4_summary_pool = {
            table_stats.ja4_summary_pool_block_bytes,
            table_stats.ja4_summary_pool_capacity,
            table_stats.ja4_summary_pool_in_use,
            table_stats.ja4_summary_pool_peak_in_use,
            table_stats.ja4_summary_pool_allocations,
            table_stats.ja4_summary_pool_allocation_rejects};
        result_.checkpoint_decisions = runtime_stats.checkpoint_decisions;
        result_.value_model_calls = runtime_stats.value_model_calls;
        result_.value_model_failures = runtime_stats.value_model_failures;
        result_.value_inference_failures =
            runtime_stats.value_inference_failures;
        result_.value_transition_failures =
            runtime_stats.value_transition_failures;
        result_.value_inference_ns = runtime_stats.value_inference_ns;
        result_.detector_inference_ns = runtime_stats.detector_inference_ns;
        result_.value_v3_cache_hits = runtime_stats.value_v3_cache_hits;
        result_.value_v3_cache_misses = runtime_stats.value_v3_cache_misses;
        result_.value_v3_inferences_avoided =
            runtime_stats.value_v3_inferences_avoided;
        result_.transition_value_calls = runtime_stats.transition_value_calls;
        result_.transition_value_failures =
            runtime_stats.transition_value_failures;
        result_.transition_value_inference_ns =
            runtime_stats.transition_value_inference_ns;
        result_.transition_value_fallback_attempts =
            runtime_stats.transition_value_fallback_attempts;
        result_.transition_value_fallback_successes =
            runtime_stats.transition_value_fallback_successes;
        for (size_t index = 0u; index < 8u; ++index) {
            result_.action_selected_mask_counts[index] =
                runtime_stats.action_selected_mask_counts[index];
        }
        result_.action_pool_unavailable_records =
            runtime_stats.action_pool_unavailable_records;
        for (size_t index = 0u; index < 3u; ++index) {
            result_.action_pool_unavailable_component_counts[index] =
                runtime_stats.action_pool_unavailable_component_counts[index];
        }
        result_.action_budget_rejections =
            runtime_stats.action_budget_rejections;
        result_.baseline_lru_victims_released =
            runtime_stats.baseline_lru_victims_released;
        result_.baseline_lfu_victims_released =
            runtime_stats.baseline_lfu_victims_released;
        result_.baseline_fifo_victims_released =
            runtime_stats.baseline_fifo_victims_released;
        result_.baseline_seeded_random_victims_released =
            runtime_stats.baseline_seeded_random_victims_released;
        result_.automatic_pressure_transitions =
            runtime_stats.automatic_pressure_transitions;
        result_.automatic_overload_transitions =
            runtime_stats.automatic_overload_transitions;
        result_.automatic_recovery_transitions =
            runtime_stats.automatic_recovery_transitions;
        for (size_t index = 0u; index < 7u; ++index) {
            result_.action_transition_failure_counts[index] =
                runtime_stats.action_transition_failure_counts[index];
        }
        result_.mandatory_floor_bytes = runtime_stats.mandatory_floor_bytes;
        result_.optional_evidence_capacity_bytes =
            runtime_stats.optional_evidence_capacity_bytes;
        result_.optional_evidence_current_bytes =
            runtime_stats.optional_evidence_current_bytes;
        result_.optional_evidence_peak_bytes =
            runtime_stats.optional_evidence_peak_bytes;
        result_.automatic_pressure_enabled =
            runtime_stats.automatic_pressure_enabled;
        result_.pressure_enter_percent =
            runtime_stats.pressure_enter_percent;
        result_.pressure_exit_percent =
            runtime_stats.pressure_exit_percent;
        result_.overload_enter_percent =
            runtime_stats.overload_enter_percent;
        result_.overload_exit_percent =
            runtime_stats.overload_exit_percent;
        result_.pressure_denominator = runtime_stats.pressure_denominator;
        for (size_t index = 0u; index < 3u; ++index) {
            result_.resolved_policy_maximum_components[index] =
                runtime_stats.resolved_policy_maximum_components[index];
            result_.resolved_policy_minimum_utility[index] =
                runtime_stats.resolved_policy_minimum_utility[index];
        }
        result_.resolved_policy_preserve_full_state_in_normal =
            runtime_stats.resolved_policy_preserve_full_state_in_normal;
        result_.pressure_accounting_failures =
            runtime_stats.pressure_accounting_failures;
        result_.bridge_sealed = bridge_stats.sealed ? 1u : 0u;
        result_.reorder_drained =
            reorder_stats.sequence_index_active == 0u &&
                    reorder_stats.inserted == reorder_stats.released
                ? 1u : 0u;
        result_.global_order_conserved =
            sequencer_stats.formal_complete &&
                    sequencer_stats.ordered_released_packets ==
                        config_.packet_count &&
                    sequencer_stats.next_sequence == config_.packet_count &&
                    bridge_stats.completions_consumed == config_.packet_count &&
                    bridge_stats.next_packet_sequence == config_.packet_count &&
                    result_.reorder_drained != 0u
                ? 1u : 0u;
        result_.mbuf_ownership_conserved =
            io_conserved && rx_stats.accounting_conserved != 0u &&
            identity_stats.accounting_conserved != 0u &&
            owner_stats.accounting_conserved != 0u ? 1u : 0u;
        if (!snapshot_value_model_v3(runtime_stats))
            return false;
        if (!snapshot_student_trigger_receipt())
            return false;
        if (!finalize_observability_receipt(
                sequencer_stats,
                dispatch_stats,
                ring_stats,
                reorder_stats,
                runtime_stats,
                table_stats,
                io_stats)) {
            return false;
        }
        return snapshot_service_memory(
            rx_stats,
            identity_stats,
            owner_stats,
            bridge_stats,
            reorder_stats,
            sequencer_stats,
            dispatch_stats,
            identity_source_stats,
            owner_source_stats,
            adapter_stats,
            ring_stats,
            publisher_stats,
            route_receipt_stats,
            gate_stats,
            coordinator_stats,
            io_stats);
    }

    bool snapshot_value_model_v3(
            const fk_compact_runtime_stats &runtime_stats) {
        auto &receipt = result_.value_model_v3;
        receipt = {};
        if (!value_model_v3_enabled(config_))
            return true;

        fk_cpu_pipeline_action_model_metadata metadata{};
        if (!fk_compact_runtime_get_action_model_metadata(
                runtime_, &metadata)) {
            return fail("V3 action-model metadata unavailable");
        }
        const auto &binding = config_.value_model_v3;
        const bool supported_format_version =
            metadata.format_version == 1u || metadata.format_version == 2u;
        /* FKVM3/1 predates detector-threshold provenance.  The loader maps
         * those absent fields to the threshold-independent defaults.  Keep
         * legacy artifacts usable for no-NIC development diagnostics only,
         * while failing closed if a future loader ever reports non-default
         * threshold/formal metadata for version 1.  Do not rewrite the
         * reported format version: the receipt must expose the legacy input. */
        const bool legacy_v1_defaults_valid =
            metadata.format_version != 1u ||
            (metadata.training_target_uses_detector_threshold == 0u &&
             metadata.formal_event_student_counterfactual_semantics_aligned ==
                 0u &&
             metadata.detector_threshold_bits == 0u &&
             std::strcmp(
                 metadata.detector_threshold_binding_sha256, "none") == 0 &&
             std::strcmp(
                 metadata.detector_threshold_selection_receipt_sha256,
                 "none") == 0 &&
             std::strcmp(
                 metadata.detector_operating_point_receipt_sha256,
                 "none") == 0);
        const bool metadata_valid =
            metadata.kind == FK_CPU_PIPELINE_ACTION_VALUE_V3_64D &&
            metadata.v3_role == binding.expected_role &&
            supported_format_version && legacy_v1_defaults_valid &&
            metadata.context_feature_count ==
                FK_VALUE_MODEL_V3_CONTEXT_FEATURES &&
            metadata.query_feature_count ==
                FK_VALUE_MODEL_V3_QUERY_FEATURES &&
            metadata.model_feature_count ==
                FK_VALUE_MODEL_V3_MODEL_FEATURES &&
            metadata.learned_action_count == FK_VALUE_MODEL_V3_ACTIONS &&
            metadata.output_count == FK_VALUE_MODEL_V3_OUTPUTS &&
            std::isfinite(metadata.conditional_equivalence_tolerance) &&
            metadata.conditional_equivalence_tolerance >= 0.0f &&
            metadata.conditional_equivalence_tolerance < 1.0f &&
            (metadata.v3_family == FK_VALUE_MODEL_V3_HYBRID_GATE_FOREST ||
             metadata.conditional_equivalence_tolerance == 0.0f) &&
            metadata.training_target_uses_detector_threshold <= 1u &&
            metadata.formal_event_student_counterfactual_semantics_aligned <= 1u &&
            metadata.frozen_context_reserved_bytes == 0u &&
            metadata.load_attempts == 1u &&
            metadata.load_successes == 1u &&
            metadata.load_failures == 0u &&
            std::strcmp(
                metadata.artifact_sha256, binding.artifact_sha256) == 0 &&
            std::strcmp(
                metadata.online_context_schema_sha256,
                binding.online_context_schema_sha256) == 0 &&
            std::strcmp(
                metadata.requested_action_domain_sha256,
                binding.requested_action_domain_sha256) == 0 &&
            std::strcmp(
                metadata.online_deadline_contract_sha256,
                binding.online_deadline_contract_sha256) == 0;
        if (!metadata_valid)
            return fail("V3 action-model metadata binding mismatch");

        receipt.abi_version = FK_NO_NIC_VALUE_MODEL_V3_RECEIPT_ABI_VERSION;
        receipt.format_version = metadata.format_version;
        receipt.family = metadata.v3_family;
        receipt.role = metadata.v3_role;
        receipt.context_features = metadata.context_feature_count;
        receipt.query_features = metadata.query_feature_count;
        receipt.model_features = metadata.model_feature_count;
        receipt.learned_actions = metadata.learned_action_count;
        receipt.outputs = metadata.output_count;
        receipt.conditional_equivalence_tolerance =
            metadata.conditional_equivalence_tolerance;
        receipt.training_target_uses_detector_threshold =
            metadata.training_target_uses_detector_threshold;
        receipt.formal_event_student_counterfactual_semantics_aligned =
            metadata.formal_event_student_counterfactual_semantics_aligned;
        receipt.detector_threshold_bits = metadata.detector_threshold_bits;
        receipt.artifact_file_bytes = metadata.artifact_file_bytes;
        receipt.model_reserved_bytes = metadata.model_reserved_bytes;
        receipt.frozen_context_reserved_bytes =
            metadata.frozen_context_reserved_bytes;
        receipt.load_attempts = metadata.load_attempts;
        receipt.load_successes = metadata.load_successes;
        receipt.load_failures = metadata.load_failures;
        receipt.contexts_built = runtime_stats.value_v3_contexts_built;
        receipt.context_failures = runtime_stats.value_v3_context_failures;
        receipt.inference_calls = runtime_stats.value_v3_inferences;
        receipt.inference_failures =
            runtime_stats.value_v3_inference_failures;
        receipt.core_zero_violations =
            runtime_stats.value_v3_core_zero_violations;
        receipt.protocol_domain_violations =
            runtime_stats.value_v3_protocol_domain_violations;
        std::memcpy(
            receipt.artifact_sha256, metadata.artifact_sha256,
            sizeof(receipt.artifact_sha256));
        std::memcpy(
            receipt.training_receipt_sha256,
            binding.training_receipt_sha256,
            sizeof(receipt.training_receipt_sha256));
        std::memcpy(
            receipt.online_context_schema_sha256,
            metadata.online_context_schema_sha256,
            sizeof(receipt.online_context_schema_sha256));
        std::memcpy(
            receipt.requested_action_domain_sha256,
            metadata.requested_action_domain_sha256,
            sizeof(receipt.requested_action_domain_sha256));
        std::memcpy(
            receipt.online_deadline_contract_sha256,
            metadata.online_deadline_contract_sha256,
            sizeof(receipt.online_deadline_contract_sha256));
        std::memcpy(
            receipt.detector_threshold_binding_sha256,
            metadata.detector_threshold_binding_sha256,
            sizeof(receipt.detector_threshold_binding_sha256));
        std::memcpy(
            receipt.detector_threshold_selection_receipt_sha256,
            metadata.detector_threshold_selection_receipt_sha256,
            sizeof(receipt.detector_threshold_selection_receipt_sha256));
        std::memcpy(
            receipt.detector_operating_point_receipt_sha256,
            metadata.detector_operating_point_receipt_sha256,
            sizeof(receipt.detector_operating_point_receipt_sha256));
        receipt.enabled = 1u;
        receipt.loaded = 1u;
        receipt.used = receipt.contexts_built != 0u &&
                receipt.inference_calls != 0u
            ? 1u : 0u;
        receipt.complete =
            receipt.used != 0u && receipt.context_failures == 0u &&
                receipt.inference_failures == 0u &&
                receipt.core_zero_violations == 0u &&
                receipt.protocol_domain_violations == 0u &&
                receipt.contexts_built == receipt.inference_calls
            ? 1u : 0u;
        return receipt.complete != 0u ||
            fail("V3 action-model receipt is incomplete");
    }

    bool snapshot_service_memory(
            const fk_dpdk_exact_rx_producer_pump_stats &rx_stats,
            const fk_exact_identity_rx_worker_pump_stats &identity_stats,
            const fk_fixed_owner_worker_pump_stats &owner_stats,
            const fk_owner_output_sequence_bridge_stats &bridge_stats,
            const fk_checkpoint_reorder_stats &reorder_stats,
            const fk_exact_identity_sequencer_stats &sequencer_stats,
            const fk_owner_dispatch_stats &dispatch_stats,
            const fk_dpdk_exact_identity_mbuf_source_stats &identity_source_stats,
            const fk_dpdk_owner_mbuf_bytes_source_stats &owner_source_stats,
            const fk_owner_runtime_adapter_stats &adapter_stats,
            const fk_owner_output_batch_ring_stats &ring_stats,
            const fk_quic_retirement_publisher_stats &publisher_stats,
            const fk_quic_route_receipt_stats &route_receipt_stats,
            const fk_quic_initial_crypto_admission_gate_stats &gate_stats,
            const fk_owner_pipeline_abort_coordinator_stats &coordinator_stats,
            const fk_no_nic_full_composition_io_stats_v1 &io_stats) {
        (void)identity_source_stats;
        (void)owner_source_stats;
        (void)adapter_stats;
        const bool coordinator_active = coordinator_ != nullptr;
        if (sequencer_stats.reserved_bytes != sequencer_storage_.bytes ||
            rx_stats.service_memory_exact == 0u ||
            rx_stats.service_memory_bytes != rx_pump_storage_.bytes ||
            identity_stats.reserved_bytes != identity_pump_storage_.bytes ||
            identity_stats.service_memory_bytes !=
                identity_pump_storage_.bytes ||
            owner_stats.service_memory_exact == 0u ||
            owner_stats.service_memory_bytes != owner_pump_storage_.bytes ||
            bridge_stats.service_memory_bytes != bridge_storage_.bytes ||
            reorder_stats.reserved_bytes != reorder_storage_.bytes ||
            dispatch_stats.reserved_bytes != dispatch_storage_.bytes ||
            publisher_stats.reserved_bytes != publisher_storage_.bytes ||
            route_receipt_stats.reserved_bytes != route_storage_.bytes ||
            ring_stats.service_memory_exact == false ||
            ring_stats.service_memory_bytes != ring_storage_.bytes ||
            gate_stats.service_memory_exact == 0u ||
            gate_stats.service_memory_bytes != gate_storage_.bytes ||
            (coordinator_active &&
             (coordinator_stats.service_memory_exact == 0u ||
              coordinator_stats.service_memory_bytes !=
                  coordinator_storage_.bytes))) {
            return fail("service-memory placement receipt mismatch");
        }
        if (external_io_enabled(config_) &&
            (io_stats.bounded_source_reserved_bytes == 0u ||
             io_stats.bounded_source_peak_bytes >
                 io_stats.bounded_source_reserved_bytes ||
             io_stats.bounded_source_capacity == 0u ||
             io_stats.bounded_source_memory_exact == 0u ||
             io_stats.bounded_source_trace_independent == 0u)) {
            return fail("external source did not provide bounded-memory receipt");
        }

        auto &receipt = result_.service_memory;
        receipt = {};
        receipt.abi_version =
            FK_NO_NIC_SERVICE_MEMORY_RECEIPT_ABI_VERSION;
        receipt.component_count = FK_IDENTITY_SERVICE_COMPONENT_COUNT;
        receipt.auxiliary_component_count =
            FK_NO_NIC_SERVICE_MEMORY_AUXILIARY_COMPONENT_COUNT;
        receipt.trace_packet_count = config_.packet_count;
        receipt.bridge_epoch_packet_limit =
            config_.bridge_epoch_packet_limit;
        receipt.completion_window_capacity =
            config_.completion_window_capacity;
        receipt.checkpoint_payload_capacity =
            external_io_enabled(config_) ? 64u : 8u;
        receipt.sequencer_ingress_capacity =
            config_.sequencer_ingress_capacity;
        receipt.sequencer_reorder_capacity = 16u;
        receipt.rx_burst_capacity = config_.rx_burst_capacity;
        receipt.owner_dispatch_capacity =
            external_io_enabled(config_) ? 256u : 16u;
        receipt.owner_output_ring_capacity =
            external_io_enabled(config_) ? 128u : 8u;
        receipt.checkpoint_reorder_capacity =
            external_io_enabled(config_) ? 128u : 16u;
        receipt.producer_count = kProducers;
        receipt.owner_count = kOwners;

        set_memory_component(
            receipt.components[FK_IDENTITY_SERVICE_EXACT_IDENTITY_SEQUENCER],
            sequencer_storage_.bytes,
            FK_NO_NIC_SERVICE_MEMORY_ACTIVE_BOUNDED,
            true, true, true);
        set_memory_component(
            receipt.components[
                FK_IDENTITY_SERVICE_EXACT_IDENTITY_MBUF_SOURCE],
            identity_source_storage_.bytes,
            FK_NO_NIC_SERVICE_MEMORY_ACTIVE_BOUNDED,
            true, true, true);
        set_memory_component(
            receipt.components[FK_IDENTITY_SERVICE_RETIREMENT_PUBLISHER],
            publisher_storage_.bytes,
            FK_NO_NIC_SERVICE_MEMORY_ACTIVE_BOUNDED,
            true, true, true);
        set_memory_component(
            receipt.components[FK_IDENTITY_SERVICE_OWNER_DISPATCH],
            dispatch_storage_.bytes,
            FK_NO_NIC_SERVICE_MEMORY_ACTIVE_BOUNDED,
            true, true, true);
        set_memory_component(
            receipt.components[FK_IDENTITY_SERVICE_QUIC_ROUTE_RECEIPTS],
            route_storage_.bytes,
            FK_NO_NIC_SERVICE_MEMORY_ACTIVE_BOUNDED,
            true, true, true);
        set_memory_component(
            receipt.components[FK_IDENTITY_SERVICE_OWNER_MBUF_SOURCES],
            owner_source_storage_.bytes,
            FK_NO_NIC_SERVICE_MEMORY_ACTIVE_BOUNDED,
            true, true, true);
        uint64_t owner_runtime_adapter_bytes = sizeof(adapter_);
        if (!checked_add_u64(
                owner_runtime_adapter_bytes,
                result_.value_model_v3.model_reserved_bytes)) {
            return fail("V3 owner-runtime model reservation overflow");
        }
        set_memory_component(
            receipt.components[FK_IDENTITY_SERVICE_OWNER_RUNTIME_ADAPTERS],
            owner_runtime_adapter_bytes,
            FK_NO_NIC_SERVICE_MEMORY_ACTIVE_BOUNDED,
            true, true, true);
        set_memory_component(
            receipt.components[FK_IDENTITY_SERVICE_OWNER_OUTPUT_RINGS],
            ring_storage_.bytes,
            FK_NO_NIC_SERVICE_MEMORY_ACTIVE_BOUNDED,
            true, true, true);
        set_memory_component(
            receipt.components[
                FK_IDENTITY_SERVICE_OWNER_OUTPUT_SEQUENCE_BRIDGE],
            bridge_storage_.bytes,
            FK_NO_NIC_SERVICE_MEMORY_ACTIVE_BOUNDED,
            true, true, true);
        set_memory_component(
            receipt.components[FK_IDENTITY_SERVICE_TRACE_MESSAGE_BARRIER],
            0u,
            FK_NO_NIC_SERVICE_MEMORY_DISABLED,
            true, true, true);
        set_memory_component(
            receipt.components[FK_IDENTITY_SERVICE_CHECKPOINT_REORDER],
            reorder_storage_.bytes,
            FK_NO_NIC_SERVICE_MEMORY_ACTIVE_BOUNDED,
            true, true, true);
        set_memory_component(
            receipt.components[FK_IDENTITY_SERVICE_DETECTOR_TRANSPORT],
            result_.trigger_receipt.student_shards_reserved_bytes,
            FK_NO_NIC_SERVICE_MEMORY_ACTIVE_BOUNDED,
            true, true, true);
        set_memory_component(
            receipt.components[FK_IDENTITY_SERVICE_AGGREGATOR_TRANSPORT],
            result_.trigger_receipt.event_path_reserved_bytes,
            FK_NO_NIC_SERVICE_MEMORY_ACTIVE_BOUNDED,
            true, true, true);
        set_memory_component(
            receipt.components[FK_IDENTITY_SERVICE_RESULT_WRITER_TRANSPORT],
            0u,
            FK_NO_NIC_SERVICE_MEMORY_DISABLED,
            true, true, true);

        set_memory_component(
            receipt.auxiliary_components[
                FK_NO_NIC_SERVICE_AUX_RX_PRODUCER_PUMP],
            rx_pump_storage_.bytes,
            FK_NO_NIC_SERVICE_MEMORY_ACTIVE_BOUNDED,
            true, true, true);
        set_memory_component(
            receipt.auxiliary_components[
                FK_NO_NIC_SERVICE_AUX_IDENTITY_WORKER_PUMP],
            identity_pump_storage_.bytes,
            FK_NO_NIC_SERVICE_MEMORY_ACTIVE_BOUNDED,
            true, true, true);
        set_memory_component(
            receipt.auxiliary_components[
                FK_NO_NIC_SERVICE_AUX_IDENTITY_ROUTER],
            router_storage_.bytes,
            FK_NO_NIC_SERVICE_MEMORY_ACTIVE_BOUNDED,
            true, true, true);
        set_memory_component(
            receipt.auxiliary_components[
                FK_NO_NIC_SERVICE_AUX_QUIC_ADMISSION_GATE],
            gate_storage_.bytes,
            FK_NO_NIC_SERVICE_MEMORY_ACTIVE_BOUNDED,
            true, true, true);
        set_memory_component(
            receipt.auxiliary_components[
                FK_NO_NIC_SERVICE_AUX_OWNER_WORKER_PUMP],
            owner_pump_storage_.bytes,
            FK_NO_NIC_SERVICE_MEMORY_ACTIVE_BOUNDED,
            true, true, true);
        set_memory_component(
            receipt.auxiliary_components[
                FK_NO_NIC_SERVICE_AUX_ABORT_COORDINATOR],
            coordinator_active ? coordinator_storage_.bytes : 0u,
            coordinator_active
                ? FK_NO_NIC_SERVICE_MEMORY_ACTIVE_BOUNDED
                : FK_NO_NIC_SERVICE_MEMORY_DISABLED,
            true, true, true);
        if (external_io_enabled(config_)) {
            set_memory_component(
                receipt.auxiliary_components[
                    FK_NO_NIC_SERVICE_AUX_EXTERNAL_SOURCE_WINDOW],
                io_stats.bounded_source_reserved_bytes,
                FK_NO_NIC_SERVICE_MEMORY_ACTIVE_BOUNDED,
                true, true, true);
            receipt.auxiliary_components[
                FK_NO_NIC_SERVICE_AUX_EXTERNAL_SOURCE_WINDOW].peak_bytes =
                io_stats.bounded_source_peak_bytes;
        } else {
            uint64_t logical_trace_bytes =
                static_cast<uint64_t>(trace_.packets.capacity()) *
                    sizeof(trace_.packets[0]);
            if (config_.packet_count >
                (std::numeric_limits<uint64_t>::max() -
                    logical_trace_bytes) / sizeof(TestPacket)) {
                return fail("synthetic trace memory receipt overflow");
            }
            logical_trace_bytes +=
                static_cast<uint64_t>(config_.packet_count) *
                    sizeof(TestPacket);
            set_memory_component(
                receipt.auxiliary_components[
                    FK_NO_NIC_SERVICE_AUX_EXTERNAL_SOURCE_WINDOW],
                logical_trace_bytes,
                FK_NO_NIC_SERVICE_MEMORY_TEST_ONLY_TRACE_SIZED,
                false, false, false);
        }

        bool component_exact = true;
        bool auxiliary_exact = true;
        bool all_active_trace_independent = true;
        for (uint32_t index = 0u;
             index < FK_IDENTITY_SERVICE_COMPONENT_COUNT; ++index) {
            const auto &component = receipt.components[index];
            const uint32_t bit = UINT32_C(1) << index;
            if (component.disposition ==
                    FK_NO_NIC_SERVICE_MEMORY_ACTIVE_BOUNDED) {
                receipt.active_component_mask |= bit;
            } else if (component.disposition ==
                    FK_NO_NIC_SERVICE_MEMORY_INLINE_NO_TRANSPORT) {
                receipt.inline_component_mask |= bit;
            } else {
                receipt.disabled_component_mask |= bit;
            }
            component_exact = component_exact &&
                component.reservation_exact != 0u;
            if (!checked_add_u64(
                    receipt.component_configured_reserved_bytes,
                    component.configured_reserved_bytes) ||
                !checked_add_u64(
                    receipt.component_observed_reserved_bytes,
                    component.observed_reserved_bytes) ||
                !checked_add_u64(
                    receipt.component_peak_bytes,
                    component.peak_bytes)) {
                return fail("formal service-memory receipt overflow");
            }
        }
        receipt.formal_non_active_component_mask =
            receipt.inline_component_mask | receipt.disabled_component_mask;
        for (uint32_t index = 0u;
             index < FK_NO_NIC_SERVICE_MEMORY_AUXILIARY_COMPONENT_COUNT;
             ++index) {
            const auto &component = receipt.auxiliary_components[index];
            if (component.disposition !=
                    FK_NO_NIC_SERVICE_MEMORY_DISABLED) {
                receipt.auxiliary_active_mask |= UINT32_C(1) << index;
                all_active_trace_independent =
                    all_active_trace_independent &&
                    component.trace_independent != 0u;
            }
            auxiliary_exact = auxiliary_exact &&
                component.reservation_exact != 0u;
            if (!checked_add_u64(
                    receipt.auxiliary_configured_reserved_bytes,
                    component.configured_reserved_bytes) ||
                !checked_add_u64(
                    receipt.auxiliary_observed_reserved_bytes,
                    component.observed_reserved_bytes) ||
                !checked_add_u64(
                    receipt.auxiliary_peak_bytes,
                    component.peak_bytes)) {
                return fail("auxiliary service-memory receipt overflow");
            }
            if (component.disposition ==
                    FK_NO_NIC_SERVICE_MEMORY_TEST_ONLY_TRACE_SIZED &&
                !checked_add_u64(
                    receipt.trace_sized_active_reserved_bytes,
                    component.configured_reserved_bytes)) {
                return fail("trace-sized service-memory receipt overflow");
            }
        }
        receipt.total_configured_reserved_bytes =
            receipt.component_configured_reserved_bytes;
        receipt.total_observed_reserved_bytes =
            receipt.component_observed_reserved_bytes;
        receipt.total_peak_bytes = receipt.component_peak_bytes;
        if (!checked_add_u64(
                receipt.total_configured_reserved_bytes,
                receipt.auxiliary_configured_reserved_bytes) ||
            !checked_add_u64(
                receipt.total_observed_reserved_bytes,
                receipt.auxiliary_observed_reserved_bytes) ||
            !checked_add_u64(
                receipt.total_peak_bytes,
                receipt.auxiliary_peak_bytes)) {
            return fail("total service-memory receipt overflow");
        }
        receipt.service_memory_separate_from_controlled_state = 1u;
        receipt.component_accounting_exact = component_exact ? 1u : 0u;
        receipt.auxiliary_accounting_exact = auxiliary_exact ? 1u : 0u;
        receipt.active_reservations_trace_independent =
            all_active_trace_independent ? 1u : 0u;
        receipt.completion_transport_window_bounded = 1u;
        receipt.external_source_window_bounded =
            external_io_enabled(config_) ? 1u : 0u;
        receipt.finite_epoch_handoff_required = 1u;
        receipt.formal_14_component_complete = 0u;
        receipt.post_run_hash_bound = 1u;
        if (!receipt_digest(receipt, receipt.receipt_sha256) ||
            !receipt_semantics_valid(receipt)) {
            return fail("service-memory receipt finalization failed closed");
        }
        return true;
    }

    void snapshot_detection_service_capacity(
            const fk_detection_event_path_stats &event_stats,
            uint32_t window_maximum_events,
            uint32_t window_maximum_total_flows,
            uint64_t window_live_slot_reuse_conflicts,
            uint64_t window_event_slots_reused) {
        auto &receipt = result_.detection_service_capacity;
        receipt = {};
        receipt.abi_version =
            FK_NO_NIC_DETECTION_SERVICE_CAPACITY_RECEIPT_ABI_VERSION;
        receipt.actor_maximum_events =
            event_stats.association.maximum_events;
        receipt.actor_maximum_total_flows =
            event_stats.association.maximum_total_flows;
        receipt.actor_maximum_flows_per_event =
            event_stats.association.maximum_flows_per_event;
        receipt.window_maximum_events = window_maximum_events;
        receipt.window_maximum_total_flows =
            window_maximum_total_flows;
        receipt.actor_active_events =
            event_stats.association.active_events;
        receipt.actor_peak_active_events =
            event_stats.association.peak_active_events;
        receipt.actor_active_flows =
            event_stats.association.active_flows;
        receipt.actor_peak_active_flows =
            event_stats.association.peak_active_flows;
        receipt.actor_event_capacity_evictions =
            event_stats.association.event_capacity_evictions;
        receipt.actor_total_flow_capacity_evictions =
            event_stats.association.total_flow_capacity_evictions;
        receipt.actor_flow_capacity_rollovers =
            event_stats.association.flow_capacity_rollovers;
        receipt.window_live_slot_reuse_conflicts =
            window_live_slot_reuse_conflicts;
        receipt.window_event_slots_reused = window_event_slots_reused;
        receipt.capacity_clean =
            receipt.actor_event_capacity_evictions == 0u &&
                receipt.actor_total_flow_capacity_evictions == 0u &&
                receipt.window_live_slot_reuse_conflicts == 0u
            ? 1u : 0u;
        receipt.expected_flow_capacity_rollovers =
            config_.expected_flow_capacity_rollovers;
        receipt.flow_rollover_contract_enforced =
            config_.enforce_flow_rollover_contract;
        receipt.flow_rollover_contract_valid =
            config_.enforce_flow_rollover_contract == 0u ||
                receipt.actor_flow_capacity_rollovers ==
                    config_.expected_flow_capacity_rollovers
            ? 1u : 0u;
    }

    bool detection_service_capacity_contract_valid() const {
        return result_.detection_service_capacity.capacity_clean != 0u &&
            result_.detection_service_capacity
                .flow_rollover_contract_valid != 0u;
    }

    bool fail_detection_service_capacity_gate(const char *prefix) {
        const auto &capacity = result_.detection_service_capacity;
        char detail[384]{};
        std::snprintf(
            detail,
            sizeof(detail),
            "%s: event_evictions=%" PRIu64
            ",total_flow_evictions=%" PRIu64
            ",flow_rollovers=%" PRIu64
            ",expected_flow_rollovers=%" PRIu64
            ",active_events=%u,active_flows=%u",
            prefix,
            capacity.actor_event_capacity_evictions,
            capacity.actor_total_flow_capacity_evictions,
            capacity.actor_flow_capacity_rollovers,
            capacity.expected_flow_capacity_rollovers,
            capacity.actor_active_events,
            capacity.actor_active_flows);
        return fail(detail);
    }

    bool snapshot_frozen_causal_trigger_receipt() {
        if (!frozen_causal_enabled(config_) || event_path_ == nullptr)
            return fail("frozen causal terminal stats unavailable");
        auto &frozen = result_.frozen_causal_aggregation;
        if (!causal_calibrator_enabled(config_))
            frozen.complete = 1u;
        auto &receipt = result_.trigger_receipt;
        receipt = {};
        receipt.abi_version = FK_NO_NIC_TRIGGER_RECEIPT_V2_ABI_VERSION;
        receipt.worker_count = 0u;
        receipt.trigger_protocol =
            FK_ONLINE_EVENT_TRIGGER_PROTOCOL_CHECKPOINT_PERIODIC_V2;
        receipt.ordinal_base = 0u;
        receipt.checkpoint_trigger_messages = frozen.checkpoint_updates;
        receipt.checkpoint_trigger_results = student_checkpoint_results_;
        receipt.output_results = student_output_results_;
        receipt.trigger_ordinal_sum = student_ordinal_sum_;
        receipt.trigger_ordinal_xor = student_ordinal_xor_;
        receipt.trigger_ordinal_max = student_ordinal_max_;
        receipt.checkpoint_packet_4_results =
            student_checkpoint_packet_results_[4u];
        receipt.checkpoint_packet_8_results =
            student_checkpoint_packet_results_[8u];
        receipt.checkpoint_packet_12_results =
            student_checkpoint_packet_results_[12u];
        receipt.checkpoint_packet_20_results =
            student_checkpoint_packet_results_[20u];
        receipt.scheduled_periodic_ticks = frozen.scheduled_periodic_ticks;
        receipt.empty_periodic_ticks = frozen.empty_periodic_ticks;
        receipt.same_timestamp_unchanged_periodic_coalesces =
            frozen.same_timestamp_periodic_coalesces;
        receipt.periodic_trigger_results = student_periodic_results_;
        receipt.final_watermark_ns = causal_calibrator_enabled(config_)
            ? (student_watermark_initialized_
                  ? student_last_watermark_ns_ : 0u)
            : (frozen_observation_timestamp_initialized_
                  ? frozen_last_observation_timestamp_ns_ : 0u);
        receipt.event_path_reserved_bytes = event_path_storage_.bytes;
        receipt.student_shards_reserved_bytes = frozen.reserved_bytes;
        receipt.student_decision_threshold = frozen.threshold;
        receipt.final_flush_complete = 1u;
        receipt.command_queues_empty = 1u;
        receipt.result_queues_empty = 1u;
        receipt.worker_failure = 0u;
        receipt.deterministic_smoke_model = 0u;
        uint64_t checkpoint_distribution =
            receipt.checkpoint_packet_4_results;
        const bool arithmetic =
            checked_add_u64(
                checkpoint_distribution,
                receipt.checkpoint_packet_8_results) &&
            checked_add_u64(
                checkpoint_distribution,
                receipt.checkpoint_packet_12_results) &&
            checked_add_u64(
                checkpoint_distribution,
                receipt.checkpoint_packet_20_results);
        if (causal_calibrator_enabled(config_)) {
            uint64_t expected_outputs = student_checkpoint_results_;
            uint64_t tick_partition = frozen.empty_periodic_ticks;
            const bool causal_arithmetic = arithmetic &&
                checked_add_u64(expected_outputs, student_periodic_results_) &&
                checked_add_u64(
                    tick_partition,
                    frozen.same_timestamp_periodic_coalesces) &&
                checked_add_u64(tick_partition, student_periodic_results_);
            receipt.conservation_valid =
                causal_arithmetic && frozen.enabled != 0u &&
                    detection_service_capacity_contract_valid() &&
                    frozen.complete != 0u &&
                    frozen.calibrator_enabled != 0u &&
                    frozen.model_loaded != 0u && frozen.model_used != 0u &&
                    frozen.deterministic_smoke_model == 0u &&
                    frozen.checkpoint_updates == student_checkpoint_results_ &&
                    frozen.periodic_updates == student_periodic_results_ &&
                    frozen.total_feature_updates == expected_outputs &&
                    student_output_results_ == expected_outputs &&
                    checkpoint_distribution == student_checkpoint_results_ &&
                    tick_partition == frozen.scheduled_periodic_ticks
                ? 1u : 0u;
        } else {
            receipt.conservation_valid =
                arithmetic && frozen.enabled != 0u && frozen.complete != 0u &&
                    detection_service_capacity_contract_valid() &&
                    frozen.deterministic_smoke_model == 0u &&
                    frozen.checkpoint_updates == student_checkpoint_results_ &&
                    student_checkpoint_results_ == student_output_results_ &&
                    checkpoint_distribution == student_checkpoint_results_
                ? 1u : 0u;
        }
        return receipt.conservation_valid != 0u ||
            fail("frozen causal trigger conservation failed");
    }

    bool snapshot_student_trigger_receipt() {
        if (frozen_causal_enabled(config_))
            return snapshot_frozen_causal_trigger_receipt();
        fk_student_shards_stats shard_stats{};
        fk_detection_event_path_stats event_stats{};
        fk_event_student_metadata metadata{};
        if (student_shards_ == nullptr || event_path_ == nullptr ||
            !fk_student_shards_get_stats(student_shards_, &shard_stats) ||
            !fk_student_shards_get_metadata(student_shards_, &metadata) ||
            !fk_detection_event_path_get_stats(event_path_, &event_stats)) {
            return fail("Event Student terminal stats unavailable");
        }
        uint64_t checkpoint_messages = 0u;
        uint64_t ticks = 0u;
        uint64_t empty_ticks = 0u;
        uint64_t coalesces = 0u;
        uint64_t checkpoint_outputs = 0u;
        uint64_t periodic_outputs = 0u;
        uint64_t worker_outputs = 0u;
        uint64_t window_live_slot_reuse_conflicts = 0u;
        uint64_t window_event_slots_reused = 0u;
        bool workers_formal = true;
        for (uint16_t worker = 0u;
             worker < shard_stats.worker_count; ++worker) {
            const auto &stats = shard_stats.workers[worker];
            if (!checked_add_u64(
                    checkpoint_messages,
                    stats.windows.checkpoint_trigger_messages) ||
                !checked_add_u64(ticks, stats.windows.ticks_due) ||
                !checked_add_u64(empty_ticks, stats.windows.empty_ticks) ||
                !checked_add_u64(
                    coalesces,
                    stats.windows.same_timestamp_unchanged_periodic_coalesces) ||
                !checked_add_u64(
                    checkpoint_outputs,
                    stats.windows.checkpoint_trigger_inferred_windows) ||
                !checked_add_u64(
                    periodic_outputs,
                    stats.windows.periodic_trigger_inferred_windows) ||
                !checked_add_u64(worker_outputs, stats.output_results) ||
                !checked_add_u64(
                    window_live_slot_reuse_conflicts,
                    stats.windows.live_slot_reuse_conflicts) ||
                !checked_add_u64(
                    window_event_slots_reused,
                    stats.windows.event_slots_reused)) {
                return fail("Event Student terminal receipt overflow");
            }
            workers_formal = workers_formal &&
                stats.windows.formal_completeness &&
                !stats.worker_failed;
        }
        snapshot_detection_service_capacity(
            event_stats,
            actor_config_.maximum_events,
            actor_config_.maximum_total_flows,
            window_live_slot_reuse_conflicts,
            window_event_slots_reused);
        const uint8_t smoke =
            result_.trigger_receipt.deterministic_smoke_model;
        auto &receipt = result_.trigger_receipt;
        receipt = {};
        receipt.abi_version = FK_NO_NIC_TRIGGER_RECEIPT_V2_ABI_VERSION;
        receipt.worker_count = shard_stats.worker_count;
        /* A capture with no eligible checkpoint still ran under the V2
         * deployment contract; the internal lock legitimately remains
         * unset because there was no data command on which to lock it. */
        receipt.trigger_protocol =
            shard_stats.trigger_protocol == 0u &&
                    shard_stats.checkpoint_enqueues == 0u
                ? FK_ONLINE_EVENT_TRIGGER_PROTOCOL_CHECKPOINT_PERIODIC_V2
                : shard_stats.trigger_protocol;
        receipt.ordinal_base = 0u;
        receipt.checkpoint_trigger_messages = checkpoint_messages;
        receipt.scheduled_periodic_ticks = ticks;
        receipt.empty_periodic_ticks = empty_ticks;
        receipt.same_timestamp_unchanged_periodic_coalesces = coalesces;
        receipt.checkpoint_trigger_results = student_checkpoint_results_;
        receipt.periodic_trigger_results = student_periodic_results_;
        receipt.output_results = student_output_results_;
        receipt.trigger_ordinal_sum = student_ordinal_sum_;
        receipt.trigger_ordinal_xor = student_ordinal_xor_;
        receipt.trigger_ordinal_max = student_ordinal_max_;
        receipt.checkpoint_packet_4_results =
            student_checkpoint_packet_results_[4u];
        receipt.checkpoint_packet_8_results =
            student_checkpoint_packet_results_[8u];
        receipt.checkpoint_packet_12_results =
            student_checkpoint_packet_results_[12u];
        receipt.checkpoint_packet_20_results =
            student_checkpoint_packet_results_[20u];
        receipt.invalid_checkpoint_packet_rejections =
            shard_stats.invalid_checkpoint_packet_rejections;
        receipt.trigger_protocol_rejections =
            shard_stats.trigger_protocol_rejections;
        receipt.final_watermark_ns = shard_stats.final_broadcast_watermark_ns;
        receipt.event_path_reserved_bytes = event_path_storage_.bytes;
        receipt.student_shards_reserved_bytes =
            shard_stats.total_reserved_bytes;
        receipt.student_continuous_features = metadata.continuous_features;
        receipt.student_input_features = metadata.input_features;
        receipt.student_hidden = metadata.hidden;
        receipt.student_identity_embedding = metadata.identity_embedding;
        receipt.student_event_hidden = metadata.event_hidden;
        receipt.student_parameter_floats = metadata.parameter_floats;
        receipt.student_decision_threshold = metadata.decision_threshold;
        std::memcpy(
            receipt.student_artifact_sha256,
            metadata.artifact_sha256,
            sizeof(receipt.student_artifact_sha256));
        std::memcpy(
            receipt.student_feature_schema_sha256,
            metadata.feature_schema_sha256,
            sizeof(receipt.student_feature_schema_sha256));
        std::memcpy(
            receipt.student_architecture_sha256,
            metadata.architecture_sha256,
            sizeof(receipt.student_architecture_sha256));
        std::memcpy(
            receipt.student_source_state_sha256,
            metadata.source_state_sha256,
            sizeof(receipt.student_source_state_sha256));
        std::memcpy(
            receipt.student_payload_sha256,
            metadata.payload_sha256,
            sizeof(receipt.student_payload_sha256));
        receipt.final_flush_complete =
            shard_stats.final_broadcast_enqueued &&
                fk_student_shards_final_flush_complete(
                    student_shards_, shard_stats.final_broadcast_watermark_ns)
            ? 1u : 0u;
        receipt.command_queues_empty =
            fk_student_shards_command_queues_empty(student_shards_) ? 1u : 0u;
        receipt.result_queues_empty =
            fk_student_shards_result_queues_empty(student_shards_) ? 1u : 0u;
        receipt.worker_failure =
            fk_student_shards_any_worker_failed(student_shards_) ? 1u : 0u;
        receipt.deterministic_smoke_model = smoke;
        uint64_t tick_partition = empty_ticks;
        uint64_t output_partition = checkpoint_outputs;
        uint64_t checkpoint_distribution =
            receipt.checkpoint_packet_4_results;
        uint8_t metadata_digest[32]{};
        const bool metadata_bound =
            metadata.format_version == 1u &&
            metadata.continuous_features == 119u &&
            metadata.input_features == FK_EVENT_STUDENT_INPUT_FEATURES &&
            metadata.hidden != 0u && metadata.event_hidden != 0u &&
            metadata.parameter_floats != 0u &&
            std::isfinite(metadata.decision_threshold) &&
            hex_digest(metadata.artifact_sha256, metadata_digest) &&
            hex_digest(metadata.feature_schema_sha256, metadata_digest) &&
            hex_digest(metadata.architecture_sha256, metadata_digest) &&
            hex_digest(metadata.source_state_sha256, metadata_digest) &&
            hex_digest(metadata.payload_sha256, metadata_digest);
        const bool arithmetic =
            checked_add_u64(tick_partition, periodic_outputs) &&
            checked_add_u64(tick_partition, coalesces) &&
            checked_add_u64(output_partition, periodic_outputs) &&
            checked_add_u64(
                checkpoint_distribution,
                receipt.checkpoint_packet_8_results) &&
            checked_add_u64(
                checkpoint_distribution,
                receipt.checkpoint_packet_12_results) &&
            checked_add_u64(
                checkpoint_distribution,
                receipt.checkpoint_packet_20_results);
        receipt.conservation_valid =
            arithmetic && metadata_bound && workers_formal &&
                detection_service_capacity_contract_valid() &&
                shard_stats.topology_complete &&
                shard_stats.formal_completeness &&
                receipt.trigger_protocol ==
                    FK_ONLINE_EVENT_TRIGGER_PROTOCOL_CHECKPOINT_PERIODIC_V2 &&
                shard_stats.checkpoint_trigger_enqueues ==
                    checkpoint_messages &&
                checkpoint_messages == checkpoint_outputs &&
                checkpoint_outputs == student_checkpoint_results_ &&
                periodic_outputs == student_periodic_results_ &&
                tick_partition == ticks &&
                output_partition == worker_outputs &&
                worker_outputs == student_output_results_ &&
                checkpoint_distribution == student_checkpoint_results_ &&
                receipt.invalid_checkpoint_packet_rejections == 0u &&
                receipt.trigger_protocol_rejections == 0u &&
                receipt.worker_failure == 0u
            ? 1u : 0u;
        return true;
    }

    uint64_t next_student_monotonic_ns() {
        uint64_t now_ns = steady_monotonic_ns();
        if (now_ns <= student_monotonic_ns_ &&
            student_monotonic_ns_ != UINT64_MAX) {
            now_ns = student_monotonic_ns_ + 1u;
        }
        student_monotonic_ns_ = now_ns;
        return now_ns;
    }

    void fill_event_decision_fields(
            fk_no_nic_decision_trace_record_v1 &trace,
            const fk_student_shard_result &result) const {
        trace.event_id = result.window.event_id;
        trace.event_start_ns = result.window.event_start_ns;
        trace.event_anchor_ns = result.window.anchor_ns;
        trace.event_slot = result.window.event_slot;
        trace.event_generation = result.window.event_generation;
        trace.retained_flow_snapshots = result.window.retained_flow_snapshots;
        trace.trigger_ordinal = result.window.trigger_ordinal;
        trace.trigger_protocol = result.window.trigger_protocol;
        trace.trigger_kind = result.window.trigger_kind;
        trace.checkpoint_packet = result.window.checkpoint_packet;
        trace.event_detector_score = result.window.operational_probability;
        trace.detector_start_monotonic_ns =
            result.command_start_monotonic_ns;
        trace.decision_monotonic_ns = result.decision_monotonic_ns;
        trace.threshold_crossed = result.window.threshold_crossed ? 1u : 0u;
        trace.alert_latched = result.window.alert_latched ? 1u : 0u;
        trace.first_alert = result.window.first_alert ? 1u : 0u;
        trace.behavior_stage = result.window.behavior_stage;
        trace.alert_state = result.window.alert_state;
        trace.alert_state_changed =
            result.window.alert_state_changed ? 1u : 0u;
        trace.correction_emitted =
            result.window.correction_emitted ? 1u : 0u;
        trace.reopen_emitted = result.window.reopen_emitted ? 1u : 0u;
        if (result.decision_monotonic_ns >=
                result.command_start_monotonic_ns) {
            trace.detection_latency_ns =
                result.decision_monotonic_ns -
                result.command_start_monotonic_ns;
        }
    }

    bool audit_checkpoint_intervention_trace(
            const fk_no_nic_decision_trace_record_v1 &trace) {
        const auto &intervention = config_.checkpoint_intervention;
        if (intervention.enabled == 0u ||
            trace.trace_kind != FK_NO_NIC_DECISION_TRACE_CHECKPOINT) {
            return true;
        }
        const bool packet_anchor = trace.packet_sequence ==
            intervention.source_packet_sequence;
        const bool semantic_anchor =
            trace.observation_timestamp_ns ==
                intervention.observation_timestamp_ns &&
            trace.logical_connection_id ==
                intervention.logical_connection_id &&
            trace.flow_first_timestamp_ns ==
                intervention.flow_first_timestamp_ns &&
            trace.flow_index == intervention.flow_index &&
            trace.flow_generation == intervention.flow_generation &&
            trace.checkpoint_packet == intervention.checkpoint_packet &&
            fk_flow_key_equal(
                &trace.flow_key, &intervention.candidate_key);
        if (!packet_anchor && !semantic_anchor)
            return true;
        const bool exact = packet_anchor && semantic_anchor &&
            trace.action_available == 1u &&
            trace.previous_mask == intervention.expected_previous_mask &&
            trace.selected_mask == intervention.forced_requested_mask &&
            trace.final_mask == intervention.expected_previous_mask &&
            trace.controlled_bytes_after <= trace.controlled_bytes_before &&
            trace.candidates_considered == 1u &&
            trace.budget_rejections == 0u &&
            (trace.action_reason == FK_TRANSITION_NO_CHANGE ||
             trace.action_reason == FK_TRANSITION_APPLIED);
        if (!exact) {
            checkpoint_intervention_trace_binding_mismatches_++;
            return fail(
                "source-record checkpoint intervention trace binding failed");
        }
        checkpoint_intervention_trace_matches_++;
        if (checkpoint_intervention_trace_matches_ != 1u) {
            checkpoint_intervention_trace_binding_mismatches_++;
            return fail(
                "source-record checkpoint intervention matched more than once");
        }
        return true;
    }

    bool emit_decision_trace(
            fk_no_nic_decision_trace_record_v1 &trace,
            fk_no_nic_detector_request_trace_record_v1 *detector_request_trace =
                nullptr) {
        auto &summary = result_.observability;
        trace.abi_version = FK_NO_NIC_DECISION_TRACE_ABI_VERSION;
        trace.record_bytes = sizeof(trace);
        trace.record_sequence = next_trace_record_sequence_++;
        const bool evidence_transition =
            trace.trace_kind ==
                FK_NO_NIC_DECISION_TRACE_EVIDENCE_TRANSITION;
        const bool common_valid =
            evidence_transition ||
            (trace.event_id != 0u && trace.event_generation != 0u &&
             trace.event_start_ns != 0u && trace.event_anchor_ns != 0u &&
             trace.decision_monotonic_ns != 0u &&
             trace.detector_start_monotonic_ns != 0u &&
             trace.decision_monotonic_ns >=
                 trace.detector_start_monotonic_ns &&
             std::isfinite(trace.event_detector_score) &&
             trace.event_detector_score >= 0.0f &&
             trace.event_detector_score <= 1.0f);
        const bool checkpoint_valid =
            trace.trace_kind != FK_NO_NIC_DECISION_TRACE_CHECKPOINT ||
            (trace.flow_association_available == 1u &&
             trace.action_available == 1u &&
             trace.flow_detector_score_available == 1u &&
             trace.packet_latency_available == 1u &&
             trace.physical_ingress_timestamp_ns != 0u &&
             trace.association_enqueue_timestamp_ns >=
                 trace.physical_ingress_timestamp_ns &&
             trace.detector_start_monotonic_ns >=
                 trace.association_enqueue_timestamp_ns &&
             trace.decision_monotonic_ns >=
                 trace.physical_ingress_timestamp_ns &&
             (trace.selected_mask & ~FK_COMPONENT_FULL) == 0u &&
             (trace.protocol_applicable_mask & ~FK_COMPONENT_FULL) == 0u &&
             (trace.selected_mask & ~trace.protocol_applicable_mask) == 0u &&
             (trace.final_mask & ~FK_COMPONENT_FULL) == 0u &&
             std::isfinite(trace.flow_detector_score));
        const bool transition_valid =
            !evidence_transition ||
            (trace.evidence_transition_timestamp_ns != 0u &&
             trace.observation_timestamp_ns ==
                 trace.evidence_transition_timestamp_ns &&
             trace.flow_association_available == 1u &&
             (trace.flow_key.ip_version == 4u ||
              trace.flow_key.ip_version == 6u) &&
             (trace.flow_key.protocol == 6u ||
              trace.flow_key.protocol == 17u) &&
             (trace.flow_key.protocol == 17u ||
              trace.logical_connection_id == 0u) &&
             trace.flow_first_timestamp_ns <=
                 trace.evidence_transition_timestamp_ns &&
             trace.flow_index == trace.transition_victim_index &&
             trace.flow_generation != 0u &&
             trace.flow_generation == trace.transition_victim_generation &&
             trace.evidence_transition_bytes_released != 0u &&
             (trace.transition_component == FK_COMPONENT_STAT ||
              trace.transition_component == FK_COMPONENT_SEQ ||
              trace.transition_component == FK_COMPONENT_JA4) &&
             trace.transition_reason >=
                 FK_COMPACT_TRANSITION_VALUE_REPLACED &&
             trace.transition_reason <=
                 FK_COMPACT_TRANSITION_SEEDED_RANDOM_EVICTED &&
             (trace.previous_mask & ~FK_COMPONENT_FULL) == 0u &&
             (trace.final_mask & ~FK_COMPONENT_FULL) == 0u &&
             (trace.released_mask_after & ~FK_COMPONENT_FULL) == 0u &&
             std::isfinite(trace.transition_victim_loss) &&
             std::isfinite(trace.transition_victim_value_per_byte) &&
             std::isfinite(trace.transition_incoming_bundle_gain) &&
             std::isfinite(trace.transition_victim_total_loss) &&
             std::isfinite(trace.transition_hysteresis_eta));
        if (!common_valid || !checkpoint_valid || !transition_valid) {
            summary.timestamp_failures++;
            if (evidence_transition) {
                char detail[320]{};
                std::snprintf(
                    detail, sizeof(detail),
                    "evidence transition trace contract failed: ts=%llu obs=%llu first=%llu bytes=%llu component=%u reason=%u victim=%u/%u owner=%u/%u ip=%u protocol=%u previous=%u final=%u released=%u",
                    static_cast<unsigned long long>(
                        trace.evidence_transition_timestamp_ns),
                    static_cast<unsigned long long>(
                        trace.observation_timestamp_ns),
                    static_cast<unsigned long long>(
                        trace.flow_first_timestamp_ns),
                    static_cast<unsigned long long>(
                        trace.evidence_transition_bytes_released),
                    trace.transition_component, trace.transition_reason,
                    trace.transition_victim_index,
                    trace.transition_victim_generation,
                    trace.flow_index, trace.flow_generation,
                    trace.flow_key.ip_version, trace.flow_key.protocol,
                    trace.previous_mask, trace.final_mask,
                    trace.released_mask_after);
                return fail(detail);
            }
            return fail("decision trace timestamp/association contract failed");
        }
        if (!audit_checkpoint_intervention_trace(trace))
            return false;
        /* Completion timestamps may legitimately interleave across Student
         * shards. record_sequence is append order; event reconstruction sorts
         * by event identity and semantic anchor. */
        if (trace.trace_kind == FK_NO_NIC_DECISION_TRACE_CHECKPOINT) {
            summary.decision_records++;
            summary.checkpoint_records++;
        } else if (trace.trace_kind == FK_NO_NIC_DECISION_TRACE_PERIODIC) {
            summary.decision_records++;
            summary.periodic_records++;
        } else if (evidence_transition) {
            summary.evidence_transition_records++;
        } else {
            return fail("decision trace kind invalid");
        }
        if (!evidence_transition) {
            detection_latency_histogram_[latency_histogram_bin(
                trace.detection_latency_ns)]++;
            summary.detection_latency_samples++;
            if (trace.packet_latency_available != 0u) {
                packet_latency_histogram_[latency_histogram_bin(
                    trace.packet_to_decision_latency_ns)]++;
                summary.packet_to_decision_samples++;
            }
            if (trace.flow_detector_score_available != 0u) {
                flow_detector_latency_histogram_[latency_histogram_bin(
                    trace.flow_detector_latency_ns)]++;
                summary.flow_detector_latency_samples++;
            }
        }
        uint64_t digest = summary.trace_rolling_hash64;
        if (digest == 0u)
            digest = UINT64_C(1469598103934665603);
        digest = trace_hash_mix(
            digest, &trace.record_sequence, sizeof(trace.record_sequence));
        digest = trace_hash_mix(digest, &trace.input_sequence,
            sizeof(trace.input_sequence));
        digest = trace_hash_mix(digest, &trace.event_id, sizeof(trace.event_id));
        digest = trace_hash_mix(
            digest, &trace.event_generation, sizeof(trace.event_generation));
        digest = trace_hash_mix(
            digest, &trace.event_anchor_ns, sizeof(trace.event_anchor_ns));
        digest = trace_hash_mix(
            digest, &trace.event_detector_score,
            sizeof(trace.event_detector_score));
        digest = trace_hash_mix(
            digest, &trace.previous_mask, sizeof(trace.previous_mask));
        digest = trace_hash_mix(
            digest, &trace.selected_mask, sizeof(trace.selected_mask));
        digest = trace_hash_mix(
            digest, &trace.protocol_applicable_mask,
            sizeof(trace.protocol_applicable_mask));
        digest = trace_hash_mix(
            digest, &trace.final_mask, sizeof(trace.final_mask));
        digest = trace_hash_mix(
            digest, &trace.released_mask_before,
            sizeof(trace.released_mask_before));
        digest = trace_hash_mix(
            digest, &trace.released_mask_after,
            sizeof(trace.released_mask_after));
        digest = trace_hash_mix(
            digest, &trace.evidence_transition_sequence,
            sizeof(trace.evidence_transition_sequence));
        digest = trace_hash_mix(
            digest, &trace.evidence_transition_bytes_released,
            sizeof(trace.evidence_transition_bytes_released));
        summary.trace_rolling_hash64 = digest;
        if (config_.decision_trace_sink != nullptr) {
            if (!config_.decision_trace_sink(
                    config_.decision_trace_context, &trace)) {
                summary.trace_sink_rejections++;
                return fail("decision trace sink rejected record");
            }
            summary.trace_sink_records++;
        }
        if (config_.decision_trace_features_sink != nullptr &&
            trace.trace_kind == FK_NO_NIC_DECISION_TRACE_CHECKPOINT) {
            /* The complete request snapshot was taken before detector
             * execution and checked again immediately afterwards.  Only the
             * append-order join key is assigned here; this path must never
             * reconstruct detector input from a possibly modified request. */
            if (detector_request_trace == nullptr)
                return fail("detector request trace snapshot missing");
            detector_request_trace->trace_record_sequence =
                trace.record_sequence;
            if (!config_.decision_trace_features_sink(
                    config_.decision_trace_features_context,
                    detector_request_trace)) {
                return fail("detector request trace sink rejected record");
            }
        } else if (detector_request_trace != nullptr &&
                   trace.trace_kind !=
                       FK_NO_NIC_DECISION_TRACE_CHECKPOINT) {
            return fail(
                "detector request trace attached to non-checkpoint trace");
        }
        return true;
    }

    bool emit_evidence_transition(
            const fk_compact_evidence_transition &transition) {
        auto &receipt = result_.evidence_transitions;
        const uint64_t expected = receipt.trace_records_emitted;
        if (transition.sequence != expected) {
            receipt.sequence_failures++;
            result_.observability.order_failures++;
            char detail[192]{};
            std::snprintf(
                detail, sizeof(detail),
                "evidence transition sequence is not contiguous: expected=%llu actual=%llu",
                static_cast<unsigned long long>(expected),
                static_cast<unsigned long long>(transition.sequence));
            return fail(detail);
        }
        const fk_flow_key &victim_key = transition.victim_key;
        if ((victim_key.ip_version != 4u && victim_key.ip_version != 6u) ||
            (victim_key.protocol != 6u && victim_key.protocol != 17u) ||
            transition.victim_flow_first_timestamp_ns >
                transition.timestamp_ns ||
            (victim_key.protocol == 6u &&
             transition.victim_logical_connection_id != 0u)) {
            return fail(
                "evidence transition queued victim owner is invalid");
        }
        fk_no_nic_decision_trace_record_v1 trace{};
        trace.trace_kind = FK_NO_NIC_DECISION_TRACE_EVIDENCE_TRANSITION;
        trace.input_sequence = UINT64_MAX;
        trace.packet_sequence = UINT64_MAX;
        trace.flow_key = victim_key;
        trace.logical_connection_id =
            transition.victim_logical_connection_id;
        trace.flow_index = transition.victim_handle.index;
        trace.flow_generation = transition.victim_handle.generation;
        trace.flow_first_timestamp_ns =
            transition.victim_flow_first_timestamp_ns;
        trace.observation_timestamp_ns = transition.timestamp_ns;
        trace.flow_association_available = 1u;
        trace.previous_mask = transition.previous_mask;
        trace.final_mask = transition.final_mask;
        trace.released_mask_after = transition.released_mask;
        trace.action_reason = static_cast<uint8_t>(transition.reason);
        trace.transition_component = transition.component;
        trace.transition_reason = static_cast<uint8_t>(transition.reason);
        trace.evidence_transition_sequence = transition.sequence;
        trace.evidence_transition_timestamp_ns = transition.timestamp_ns;
        trace.evidence_transition_bytes_released = transition.bytes_released;
        trace.transition_victim_index = transition.victim_handle.index;
        trace.transition_victim_generation = transition.victim_handle.generation;
        trace.transition_causing_index = transition.causing_handle.index;
        trace.transition_causing_generation = transition.causing_handle.generation;
        trace.transition_causing_packet_count = transition.causing_packet_count;
        trace.transition_victim_loss = transition.victim_loss;
        trace.transition_victim_value_per_byte =
            transition.victim_value_per_byte;
        trace.transition_incoming_bundle_gain =
            transition.incoming_bundle_gain;
        trace.transition_victim_total_loss = transition.victim_total_loss;
        trace.transition_hysteresis_eta = transition.hysteresis_eta;
        if (!emit_decision_trace(trace))
            return false;
        receipt.last_transition_sequence = transition.sequence;
        receipt.trace_records_emitted++;
        return true;
    }

    bool drain_evidence_transitions_in_owner_scope() {
        std::array<fk_compact_evidence_transition, 64u> transitions;
        auto &receipt = result_.evidence_transitions;
        for (;;) {
            receipt.drain_calls++;
            const size_t count =
                fk_compact_runtime_drain_evidence_transitions(
                    runtime_, transitions.data(), transitions.size());
            for (size_t index = 0u; index < count; ++index) {
                if (!emit_evidence_transition(transitions[index]))
                    return false;
            }
            if (count < transitions.size())
                return true;
        }
    }

    bool drain_evidence_transitions() {
        const uintptr_t adapter_token =
            reinterpret_cast<uintptr_t>(&adapter_);
        if (!fk_compact_runtime_owner_adapter_scope_begin(
                runtime_, adapter_token, 0u)) {
            return fail("evidence transition drain scope begin failed");
        }
        const bool drained = drain_evidence_transitions_in_owner_scope();
        const bool ended = fk_compact_runtime_owner_adapter_scope_end(
            runtime_, adapter_token, 0u);
        if (!drained)
            return false;
        return ended || fail("evidence transition drain scope end failed");
    }

    bool emit_periodic_decision(const fk_student_shard_result &result) {
        fk_no_nic_decision_trace_record_v1 trace{};
        trace.trace_kind = FK_NO_NIC_DECISION_TRACE_PERIODIC;
        trace.input_sequence = UINT64_MAX;
        trace.packet_sequence = UINT64_MAX;
        fill_event_decision_fields(trace, result);
        return emit_decision_trace(trace);
    }

    bool collect_student_results() {
        for (uint16_t worker = 0u;
             worker < config_.event_student_worker_count; ++worker) {
            for (;;) {
                fk_student_shard_result result{};
                if (!fk_student_shards_pop_result(
                        student_shards_, worker, &result)) {
                    break;
                }
                if (result.worker_index != worker ||
                    result.window.trigger_protocol !=
                        FK_ONLINE_EVENT_TRIGGER_PROTOCOL_CHECKPOINT_PERIODIC_V2 ||
                    (result.window.trigger_kind ==
                         FK_ONLINE_EVENT_TRIGGER_KIND_PERIODIC &&
                     result.window.checkpoint_packet != 0u) ||
                    (result.window.trigger_kind ==
                         FK_ONLINE_EVENT_TRIGGER_KIND_CHECKPOINT &&
                     !(result.window.checkpoint_packet == 4u ||
                       result.window.checkpoint_packet == 8u ||
                       result.window.checkpoint_packet == 12u ||
                       result.window.checkpoint_packet == 20u)) ||
                    (result.window.trigger_kind !=
                         FK_ONLINE_EVENT_TRIGGER_KIND_PERIODIC &&
                     result.window.trigger_kind !=
                         FK_ONLINE_EVENT_TRIGGER_KIND_CHECKPOINT)) {
                    return fail("Event Student V2 result protocol mismatch");
                }
                if (student_output_results_ == UINT64_MAX ||
                    result.window.trigger_ordinal > UINT64_MAX -
                        student_ordinal_sum_) {
                    return fail("Event Student result receipt overflow");
                }
                ++student_output_results_;
                student_ordinal_sum_ += result.window.trigger_ordinal;
                student_ordinal_xor_ ^= result.window.trigger_ordinal;
                student_ordinal_max_ = std::max(
                    student_ordinal_max_, result.window.trigger_ordinal);
                if (result.window.trigger_kind ==
                        FK_ONLINE_EVENT_TRIGGER_KIND_CHECKPOINT) {
                    if (!checkpoint_trace_active_ ||
                        checkpoint_student_result_ready_) {
                        return fail(
                            "checkpoint Student result lacks unique trace context");
                    }
                    checkpoint_student_result_ = result;
                    checkpoint_student_result_ready_ = true;
                    ++student_checkpoint_results_;
                    ++student_checkpoint_packet_results_[
                        result.window.checkpoint_packet];
                } else {
                    ++student_periodic_results_;
                    if (!emit_periodic_decision(result))
                        return false;
                }
            }
        }
        return true;
    }

    bool pump_student_until_idle() {
        if (student_shards_ == nullptr)
            return fail("Event Student route is absent");
        const uint64_t iteration_limit =
            static_cast<uint64_t>(actor_config_.maximum_events) * 4u +
            static_cast<uint64_t>(
                config_.event_student_command_queue_capacity) *
                config_.event_student_worker_count * 4u + 4096u;
        for (uint64_t iteration = 0u;
             iteration < iteration_limit; ++iteration) {
            for (uint16_t worker = 0u;
                 worker < config_.event_student_worker_count; ++worker) {
                uint32_t processed = 0u;
                if (!fk_student_shards_process(
                        student_shards_, worker, 64u, &processed)) {
                    return fail("Event Student worker failed");
                }
            }
            if (!collect_student_results())
                return false;
            if (fk_student_shards_any_worker_failed(student_shards_))
                return fail("Event Student topology failed closed");
            if (fk_student_shards_command_queues_empty(student_shards_)) {
                if (!collect_student_results())
                    return false;
                if (fk_student_shards_result_queues_empty(student_shards_))
                    return true;
            }
        }
        return fail("Event Student drain exceeded bounded iteration count");
    }

    bool broadcast_student_watermark(uint64_t watermark_ns, bool final) {
        if (student_watermark_initialized_ &&
            watermark_ns < student_last_watermark_ns_) {
            return fail("Event Student watermark regressed");
        }
        if (causal_calibrator_enabled(config_)) {
            if (causal_windows_ == nullptr ||
                !fk_online_event_windows_advance_watermark(
                    causal_windows_, watermark_ns)) {
                return fail("causal V2 watermark advance failed");
            }
            (void)final;
        } else {
            if (!fk_student_shards_broadcast_watermark(
                    student_shards_, watermark_ns, final,
                    next_student_monotonic_ns())) {
                return fail("Event Student watermark enqueue failed");
            }
            if (!pump_student_until_idle())
                return false;
        }
        student_watermark_initialized_ = true;
        student_last_watermark_ns_ = watermark_ns;
        return true;
    }

    bool prepare_student_timestamp(uint64_t observation_timestamp_ns) {
        if (observation_timestamp_ns == 0u)
            return fail("Event Student observation timestamp is zero");
        if (student_timestamp_pending_ &&
            observation_timestamp_ns < student_pending_timestamp_ns_) {
            return fail("Event Student association timestamp regressed");
        }
        if (student_timestamp_pending_ &&
            observation_timestamp_ns > student_pending_timestamp_ns_) {
            if (!broadcast_student_watermark(
                    student_pending_timestamp_ns_, false)) {
                return false;
            }
            student_timestamp_pending_ = false;
        }
        const uint64_t strict_previous = observation_timestamp_ns - 1u;
        if (!student_watermark_initialized_ ||
            strict_previous > student_last_watermark_ns_) {
            if (!broadcast_student_watermark(strict_previous, false))
                return false;
        }
        student_timestamp_pending_ = true;
        student_pending_timestamp_ns_ = observation_timestamp_ns;
        return true;
    }

    bool update_frozen_causal_checkpoint(
            const fk_compact_detection_request_v2 &request,
            float record_score,
            uint64_t detector_start_ns,
            uint64_t detector_end_ns,
            const fk_compact_action_record *action) {
        if (!frozen_causal_enabled(config_) ||
            checkpoint_association_.event_id == 0u ||
            checkpoint_association_.event_generation == 0u ||
            checkpoint_association_.event_slot >= frozen_event_states_.size() ||
            !std::isfinite(record_score) || record_score < 0.0f ||
            record_score > 1.0f || detector_end_ns < detector_start_ns) {
            return fail("frozen causal checkpoint input is invalid");
        }
        if (causal_calibrator_enabled(config_)) {
            auto &receipt = result_.frozen_causal_aggregation;
            if (action == nullptr || causal_windows_ == nullptr ||
                causal_calibrator_ == nullptr || action->selected_mask > 7u ||
                action->protocol_applicable_mask > 7u ||
                action->final_mask > 7u || request.presentation.feature_count <= 36u ||
                checkpoint_flow_identity_.presentation.first_timestamp_ns !=
                    request.presentation.flow_first_timestamp_ns ||
                checkpoint_flow_identity_.presentation.generation !=
                    request.presentation.flow_generation) {
                return fail("causal calibrator checkpoint state is invalid");
            }
            receipt.protocol_action_domain_checks++;
            if ((action->selected_mask &
                    static_cast<uint8_t>(~action->protocol_applicable_mask)) !=
                0u) {
                receipt.protocol_action_domain_violations++;
                return fail("causal requested action is protocol-illegal");
            }
            uint8_t physical_feature_mask = FK_COMPONENT_NONE;
            for (size_t component = 0u; component < 3u; ++component) {
                const float retained =
                    request.presentation.features[30u + component];
                if (!std::isfinite(retained) ||
                    (retained != 0.0f && retained != 1.0f)) {
                    receipt.physical_feature_mask_mismatches++;
                    return fail("causal retained-state feature is not binary");
                }
                if (retained == 1.0f)
                    physical_feature_mask |=
                        static_cast<uint8_t>(UINT8_C(1) << component);
            }
            receipt.physical_feature_mask_checks++;
            const uint8_t detector_interval_mask =
                request.presentation.checkpoint_packet == 4u
                ? action->final_mask : action->previous_mask;
            if (physical_feature_mask != detector_interval_mask) {
                receipt.physical_feature_mask_mismatches++;
                return fail(
                    "causal retained-state features do not match detector interval");
            }
            const bool reopen = checkpoint_association_.reason !=
                FK_ACTOR_REASON_EXISTING_FLOW_STICKY;
            if (reopen && !fk_online_event_windows_flow_reopen_v2(
                    causal_windows_, &checkpoint_association_,
                    &checkpoint_flow_identity_,
                    request.presentation.observation_timestamp_ns)) {
                return fail("causal V2 FLOW_REOPEN route failed");
            }
            causal_current_detector_start_ns_ = detector_start_ns;
            causal_current_detector_end_ns_ = detector_end_ns;
            const bool updated =
                fk_online_event_windows_checkpoint_triggered_causal_v2(
                    causal_windows_, &checkpoint_association_,
                    &checkpoint_flow_identity_,
                    request.presentation.observation_timestamp_ns,
                    request.presentation.checkpoint_packet,
                    request.presentation.features,
                    request.presentation.feature_count,
                    static_cast<double>(record_score),
                    detector_interval_mask);
            causal_current_detector_start_ns_ = 0u;
            causal_current_detector_end_ns_ = 0u;
            if (!updated)
                return fail("causal V2 checkpoint/model route failed");
            receipt.requested_mask_or |= action->selected_mask;
            receipt.physical_final_mask_or |= action->final_mask;
            if (action->selected_mask != action->final_mask)
                receipt.requested_effective_mask_divergences++;
            return true;
        }
        FrozenCausalEventState &state =
            frozen_event_states_[checkpoint_association_.event_slot];
        auto &receipt = result_.frozen_causal_aggregation;
        if (!state.initialized ||
            state.event_id != checkpoint_association_.event_id ||
            state.event_generation !=
                checkpoint_association_.event_generation) {
            state = {};
            state.initialized = true;
            state.event_id = checkpoint_association_.event_id;
            state.event_generation =
                checkpoint_association_.event_generation;
            state.event_start_ns = request.presentation.observation_timestamp_ns;
            state.maximum_score = record_score;
            ++receipt.initialized_event_generations;
        } else {
            state.maximum_score = std::max(state.maximum_score, record_score);
        }
        if (state.checkpoint_updates != UINT32_MAX)
            ++state.checkpoint_updates;
        const bool threshold_crossed = state.maximum_score >=
            config_.frozen_causal_aggregation.threshold;
        const bool first_alert = threshold_crossed && !state.alert_latched;
        state.alert_latched = state.alert_latched || threshold_crossed;
        fk_detection_event_decision_result decision{};
        if (!fk_detection_event_path_record_decision(
                event_path_, &checkpoint_association_, threshold_crossed,
                &decision) || !decision.accepted ||
            decision.first_alert_for_event != first_alert) {
            ++receipt.stale_handle_rejections;
            return fail("frozen causal event decision handle is stale");
        }
        fk_student_shard_result synthetic{};
        synthetic.window.event_id = state.event_id;
        synthetic.window.event_start_ns = state.event_start_ns;
        synthetic.window.anchor_ns = request.presentation.observation_timestamp_ns;
        synthetic.window.event_slot = checkpoint_association_.event_slot;
        synthetic.window.event_generation = state.event_generation;
        synthetic.window.retained_flow_snapshots = state.checkpoint_updates;
        synthetic.window.raw_window_logit = record_score;
        synthetic.window.prefix_event_logit = state.maximum_score;
        synthetic.window.operational_logit = state.maximum_score;
        synthetic.window.operational_probability = state.maximum_score;
        synthetic.window.threshold_crossed = threshold_crossed;
        synthetic.window.alert_latched = state.alert_latched;
        synthetic.window.first_alert = first_alert;
        synthetic.window.trigger_ordinal = state.next_trigger_ordinal++;
        synthetic.window.trigger_protocol =
            FK_ONLINE_EVENT_TRIGGER_PROTOCOL_CHECKPOINT_PERIODIC_V2;
        synthetic.window.trigger_kind =
            FK_ONLINE_EVENT_TRIGGER_KIND_CHECKPOINT;
        synthetic.window.checkpoint_packet =
            request.presentation.checkpoint_packet;
        synthetic.window.alert_state = state.alert_latched
            ? FK_EVENT_ALERT_CONFIRMED : FK_EVENT_ALERT_UNKNOWN;
        synthetic.window.alert_state_changed = first_alert;
        synthetic.command_enqueue_monotonic_ns = detector_start_ns;
        synthetic.command_start_monotonic_ns = detector_start_ns;
        synthetic.decision_monotonic_ns = detector_end_ns;
        checkpoint_student_result_ = synthetic;
        checkpoint_student_result_ready_ = true;

        ++receipt.checkpoint_updates;
        if (first_alert)
            ++receipt.threshold_crossings;
        if (state.alert_latched)
            ++receipt.latched_alert_outputs;
        ++student_checkpoint_results_;
        ++student_output_results_;
        const uint64_t ordinal = synthetic.window.trigger_ordinal;
        student_ordinal_sum_ += ordinal;
        student_ordinal_xor_ ^= ordinal;
        student_ordinal_max_ = std::max(student_ordinal_max_, ordinal);
        if (request.presentation.checkpoint_packet <
                student_checkpoint_packet_results_.size()) {
            ++student_checkpoint_packet_results_[
                request.presentation.checkpoint_packet];
        } else {
            return fail("frozen causal checkpoint packet is out of range");
        }
        return true;
    }

    bool associate_and_route_student(
            const fk_checkpoint_envelope_v3 &envelope,
            const fk_compact_detection_request_v2 *request) {
        const uint64_t observation_ns =
            envelope.presentation.observation_timestamp_ns;
        if (causal_calibrator_enabled(config_)) {
            if (!prepare_student_timestamp(observation_ns))
                return false;
            frozen_observation_timestamp_initialized_ = true;
            frozen_last_observation_timestamp_ns_ = observation_ns;
        } else if (frozen_causal_enabled(config_)) {
            if (observation_ns == 0u ||
                (frozen_observation_timestamp_initialized_ &&
                 observation_ns < frozen_last_observation_timestamp_ns_)) {
                return fail("frozen causal observation timestamp regressed");
            }
            frozen_observation_timestamp_initialized_ = true;
            frozen_last_observation_timestamp_ns_ = observation_ns;
        } else if (!prepare_student_timestamp(observation_ns)) {
            return false;
        }
        fk_detection_event_checkpoint_v2 checkpoint{};
        checkpoint.key = envelope.presentation.key;
        checkpoint.flow_identity.presentation =
            envelope.presentation.flow_identity;
        checkpoint.flow_identity.logical_connection_id =
            envelope.logical_connection_id;
        checkpoint.observation_timestamp_ns =
            envelope.presentation.observation_timestamp_ns;
        fk_detection_event_checkpoint_result association{};
        if (!fk_detection_event_path_observe_checkpoint_v2(
                event_path_, &checkpoint, &association) ||
            !association.associated) {
            return fail("event association rejected ordered observation");
        }
        if (request != nullptr && checkpoint_trace_active_) {
            checkpoint_association_ = association.association;
            checkpoint_flow_identity_ = checkpoint.flow_identity;
        }
        if (causal_calibrator_enabled(config_)) {
            if (envelope.presentation.message_kind ==
                    FK_CHECKPOINT_MESSAGE_FLOW_OPEN) {
                if (request != nullptr || causal_windows_ == nullptr ||
                    !fk_online_event_windows_flow_open_v2(
                        causal_windows_, &association.association,
                        &checkpoint.flow_identity,
                        checkpoint.observation_timestamp_ns)) {
                    fk_online_event_windows_stats debug_stats{};
                    fk_online_event_windows_get_stats(
                        causal_windows_, &debug_stats);
                    std::fprintf(
                        stderr,
                        "DEBUG_FLOW_OPEN_FAIL flow_open=%llu "
                        "dup_open=%llu nonfirst=%llu noncreating=%llu "
                        "stale=%llu reuse=%llu slot_reuse_conflict=%llu "
                        "flow_capacity_overflow=%llu retained=%u "
                        "max_events=%u max_flows_per_event=%u "
                        "max_total=%u\n",
                        static_cast<unsigned long long>(
                            debug_stats.flow_open_messages),
                        static_cast<unsigned long long>(
                            debug_stats.duplicate_flow_open_messages),
                        static_cast<unsigned long long>(
                            debug_stats.non_first_packet_flow_open_rejections),
                        static_cast<unsigned long long>(
                            debug_stats.noncreating_event_activation_rejections),
                        static_cast<unsigned long long>(
                            debug_stats.stale_handle_rejections),
                        static_cast<unsigned long long>(
                            debug_stats.event_slots_reused),
                        static_cast<unsigned long long>(
                            debug_stats.live_slot_reuse_conflicts),
                        static_cast<unsigned long long>(
                            debug_stats.flow_capacity_overflows),
                        debug_stats.retained_flows,
                        debug_stats.maximum_events,
                        debug_stats.maximum_flows_per_event,
                        debug_stats.maximum_total_flows);
                    return fail("causal V2 FLOW_OPEN route failed");
                }
            } else if (request == nullptr) {
                return fail("causal V2 checkpoint payload absent");
            }
            return true;
        }
        if (frozen_causal_enabled(config_))
            return true;
        const uint64_t enqueue_ns = next_student_monotonic_ns();
        if (envelope.presentation.message_kind ==
                FK_CHECKPOINT_MESSAGE_FLOW_OPEN) {
            if (request != nullptr ||
                !fk_student_shards_enqueue_flow_open_v2(
                    student_shards_,
                    &association.association,
                    &checkpoint.flow_identity,
                    checkpoint.observation_timestamp_ns,
                    enqueue_ns)) {
                return fail("Event Student FLOW_OPEN enqueue failed");
            }
        } else {
            if (request == nullptr ||
                request->logical_connection_id !=
                    envelope.logical_connection_id ||
                !fk_flow_key_equal(
                    &request->presentation.key,
                    &envelope.presentation.key) ||
                request->presentation.flow_first_timestamp_ns !=
                    checkpoint.flow_identity.presentation.first_timestamp_ns ||
                request->presentation.flow_generation !=
                    checkpoint.flow_identity.presentation.generation ||
                request->presentation.flow_index !=
                    (checkpoint.flow_identity.presentation.packed_location &
                     UINT32_C(0x00ffffff))) {
                return fail("checkpoint identity payload mismatch");
            }
            const bool reopen = association.association.reason !=
                FK_ACTOR_REASON_EXISTING_FLOW_STICKY;
            const bool accepted = reopen
                ? fk_student_shards_enqueue_flow_reopen_checkpoint_triggered_v2(
                    student_shards_,
                    &association.association,
                    &checkpoint.flow_identity,
                    checkpoint.observation_timestamp_ns,
                    request->presentation.checkpoint_packet,
                    request->presentation.features,
                    request->presentation.feature_count,
                    enqueue_ns)
                : fk_student_shards_enqueue_checkpoint_triggered_v2(
                    student_shards_,
                    &association.association,
                    &checkpoint.flow_identity,
                    checkpoint.observation_timestamp_ns,
                    request->presentation.checkpoint_packet,
                    request->presentation.features,
                    request->presentation.feature_count,
                    enqueue_ns);
            if (!accepted)
                return fail("Event Student checkpoint enqueue failed");
        }
        return pump_student_until_idle();
    }

    bool drain_ready_messages() {
        uint64_t ready_packets = 0u;
        uint64_t input_exclusive = 0u;
        if (!fk_owner_output_sequence_bridge_ready_boundary(
                bridge_, &ready_packets, &input_exclusive)) {
            return fail("bridge ready boundary failed");
        }
        (void)ready_packets;
        for (;;) {
            fk_checkpoint_envelope_v3 envelope{};
            fk_checkpoint_release_reason reason = FK_CHECKPOINT_RELEASE_NONE;
            if (!fk_checkpoint_reorder_pop_sequence_ready_v3(
                    reorder_, input_exclusive, &envelope, &reason)) {
                break;
            }
            if (reason != FK_CHECKPOINT_RELEASE_EXACT_SEQUENCE)
                return fail("reorder used non-exact release in smoke trace");
            const uint64_t sequence = envelope.presentation.input_sequence;
            if (has_reorder_sequence_ && sequence <= last_reorder_sequence_)
                return fail("global association input order regressed");
            has_reorder_sequence_ = true;
            last_reorder_sequence_ = sequence;
            result_.last_reorder_input_sequence = sequence;
            result_.reorder_messages++;
            if (envelope.presentation.message_kind ==
                FK_CHECKPOINT_MESSAGE_FLOW_OPEN) {
                if (envelope.control_kind ==
                        FK_CHECKPOINT_FLOW_CONTROL_OPEN) {
                    if (envelope.predecessor_flow_index != 0u ||
                        envelope.predecessor_flow_generation != 0u ||
                        envelope.predecessor_last_checkpoint_packet != 0u ||
                        !associate_and_route_student(envelope, nullptr)) {
                        return fail("invalid FLOW_OPEN generation control");
                    }
                    result_.flow_open_messages++;
                } else if (envelope.control_kind ==
                               FK_CHECKPOINT_FLOW_CONTROL_CONTINUE) {
                    const uint32_t successor_index =
                        envelope.presentation.flow_identity.packed_location &
                        UINT32_C(0x00ffffff);
                    const uint32_t successor_generation =
                        envelope.presentation.flow_identity.generation;
                    if (envelope.logical_connection_id != 0u ||
                        envelope.predecessor_flow_generation == 0u ||
                        (envelope.predecessor_flow_index == successor_index &&
                         envelope.predecessor_flow_generation ==
                             successor_generation)) {
                        return fail("invalid FLOW_CONTINUE generation edge");
                    }
                    result_.flow_continue_messages++;
                    /* This diagnostic composition has no v4 predecessor
                     * generation table, so it cannot prove that the edge is
                     * live or that its checkpoint cursor is current.  Never
                     * report semantic equivalence by silently dropping the
                     * control.  The production external v4 service owns the
                     * online generation-chain validation path. */
                    return fail(
                        "FLOW_CONTINUE requires external v4 "
                        "generation-chain validation");
                } else {
                    return fail("unknown generation control kind");
                }
            } else if (envelope.presentation.message_kind ==
                       FK_CHECKPOINT_MESSAGE_DETECTION_CHECKPOINT) {
                if (envelope.control_kind !=
                        FK_CHECKPOINT_FLOW_CONTROL_NONE ||
                    envelope.predecessor_flow_index != 0u ||
                    envelope.predecessor_flow_generation != 0u ||
                    envelope.predecessor_last_checkpoint_packet != 0u) {
                    return fail("checkpoint carried generation-control data");
                }
                fk_owner_checkpoint_payload_v1 payload{};
                if (!fk_owner_output_sequence_bridge_take_checkpoint_payload_v1(
                        bridge_,
                        envelope.presentation.checkpoint_payload_slot,
                        &payload)) {
                    return fail("checkpoint payload take failed");
                }
                fk_compact_detection_request_v2 &request = payload.detection;
                checkpoint_trace_active_ = true;
                checkpoint_student_result_ready_ = false;
                checkpoint_association_ = {};
                checkpoint_flow_identity_ = {};
                if (!associate_and_route_student(envelope, &request))
                    return false;
                if (!frozen_causal_enabled(config_) &&
                    (!checkpoint_student_result_ready_ ||
                    checkpoint_student_result_.window.event_id !=
                        checkpoint_association_.event_id ||
                    checkpoint_student_result_.window.event_generation !=
                        checkpoint_association_.event_generation ||
                    checkpoint_student_result_.window.checkpoint_packet !=
                        request.presentation.checkpoint_packet)) {
                    return fail("checkpoint Student trace association mismatch");
                }
                float score = 0.0f;
                /* Deliberately uninitialized while the opt-in sink is off:
                 * the default data plane performs no 159-float clear or copy.
                 * When enabled, this is the exact immutable presentation
                 * observed by fk_compact_runtime_detect_v2 below. */
                fk_no_nic_detector_request_trace_record_v1
                    detector_request_trace;
                const bool detector_request_trace_enabled =
                    config_.decision_trace_features_sink != nullptr;
                if (detector_request_trace_enabled) {
                    detector_request_trace = {};
                    detector_request_trace.abi_version =
                        FK_NO_NIC_DETECTOR_REQUEST_TRACE_ABI_VERSION;
                    detector_request_trace.record_bytes =
                        sizeof(detector_request_trace);
                    detector_request_trace.flow_key =
                        request.presentation.key;
                    detector_request_trace.logical_connection_id =
                        request.logical_connection_id;
                    detector_request_trace.flow_first_timestamp_ns =
                        request.presentation.flow_first_timestamp_ns;
                    detector_request_trace.observation_timestamp_ns =
                        request.presentation.observation_timestamp_ns;
                    detector_request_trace.flow_index =
                        request.presentation.flow_index;
                    detector_request_trace.flow_generation =
                        request.presentation.flow_generation;
                    detector_request_trace.checkpoint_packet =
                        request.presentation.checkpoint_packet;
                    detector_request_trace.feature_count =
                        request.presentation.feature_count;
                    if (detector_request_trace.feature_count !=
                            FK_NO_NIC_DECISION_TRACE_DETECTOR_FEATURES) {
                        return fail(
                            "detector request trace feature count invalid");
                    }
                    std::memcpy(
                        detector_request_trace.features,
                        request.presentation.features,
                        sizeof(detector_request_trace.features));
                    for (uint32_t index = 0u;
                         index <
                            FK_NO_NIC_DECISION_TRACE_DETECTOR_FEATURES;
                         ++index) {
                        if (!std::isfinite(
                                detector_request_trace.features[index])) {
                            return fail(
                                "detector request trace feature is non-finite");
                        }
                    }
                }
                const uint64_t flow_detector_start_ns = steady_monotonic_ns();
                if (!fk_compact_runtime_detect_v2(
                        runtime_, &request, &score)) {
                    return fail("deterministic detector execution failed");
                }
                if (detector_request_trace_enabled &&
                    (!fk_flow_key_equal(
                        &detector_request_trace.flow_key,
                        &request.presentation.key) ||
                     detector_request_trace.logical_connection_id !=
                        request.logical_connection_id ||
                     detector_request_trace.flow_first_timestamp_ns !=
                        request.presentation.flow_first_timestamp_ns ||
                     detector_request_trace.observation_timestamp_ns !=
                        request.presentation.observation_timestamp_ns ||
                     detector_request_trace.flow_index !=
                        request.presentation.flow_index ||
                     detector_request_trace.flow_generation !=
                        request.presentation.flow_generation ||
                     detector_request_trace.checkpoint_packet !=
                        request.presentation.checkpoint_packet ||
                     detector_request_trace.feature_count !=
                        request.presentation.feature_count ||
                     std::memcmp(
                        detector_request_trace.features,
                        request.presentation.features,
                        sizeof(detector_request_trace.features)) != 0)) {
                    return fail(
                        "detector mutated immutable request presentation");
                }
                const uint64_t flow_detector_end_ns = steady_monotonic_ns();
                if (flow_detector_end_ns < flow_detector_start_ns)
                    return fail("flow detector physical clock regressed");
                if (frozen_causal_enabled(config_) &&
                    !update_frozen_causal_checkpoint(
                        request, score, flow_detector_start_ns,
                        flow_detector_end_ns,
                        payload.has_action != 0u ? &payload.action : nullptr)) {
                    return false;
                }
                if (!checkpoint_student_result_ready_ ||
                    checkpoint_student_result_.window.event_id !=
                        checkpoint_association_.event_id ||
                    checkpoint_student_result_.window.event_generation !=
                        checkpoint_association_.event_generation ||
                    checkpoint_student_result_.window.checkpoint_packet !=
                        request.presentation.checkpoint_packet) {
                    return fail("checkpoint event aggregation result mismatch");
                }
                result_.detection_requests++;
                result_.detector_executions++;
                if (result_.detector_executions == 1u) {
                    result_.detection_score_min = score;
                    result_.detection_score_max = score;
                } else {
                    if (score < result_.detection_score_min)
                        result_.detection_score_min = score;
                    if (score > result_.detection_score_max)
                        result_.detection_score_max = score;
                }
                result_.detection_score_sum += score;
                if (score >= 0.5f)
                    result_.positive_detection_decisions++;
                fk_no_nic_decision_trace_record_v1 trace{};
                trace.trace_kind = FK_NO_NIC_DECISION_TRACE_CHECKPOINT;
                trace.input_sequence = envelope.presentation.input_sequence;
                trace.packet_sequence =
                    envelope.presentation.input_sequence / 2u;
                trace.flow_key = request.presentation.key;
                trace.logical_connection_id = request.logical_connection_id;
                trace.flow_first_timestamp_ns =
                    request.presentation.flow_first_timestamp_ns;
                trace.observation_timestamp_ns =
                    request.presentation.observation_timestamp_ns;
                trace.physical_ingress_timestamp_ns =
                    envelope.presentation.physical_ingress_timestamp_ns;
                trace.association_enqueue_timestamp_ns =
                    envelope.presentation.association_enqueue_timestamp_ns;
                trace.packet_count = request.presentation.packet_count;
                trace.flow_index = request.presentation.flow_index;
                trace.flow_generation = request.presentation.flow_generation;
                trace.flow_association_available = 1u;
                trace.flow_detector_score = score;
                trace.flow_detector_score_available = 1u;
                trace.flow_detector_latency_ns =
                    flow_detector_end_ns - flow_detector_start_ns;
                fill_event_decision_fields(
                    trace, checkpoint_student_result_);
                if (trace.decision_monotonic_ns >=
                        trace.physical_ingress_timestamp_ns) {
                    trace.packet_to_decision_latency_ns =
                        trace.decision_monotonic_ns -
                        trace.physical_ingress_timestamp_ns;
                    trace.packet_latency_available = 1u;
                }
                if (payload.has_action != 0u) {
                    const fk_compact_action_record &action = payload.action;
                    if (!fk_flow_key_equal(
                            &action.key, &request.presentation.key) ||
                        action.observation_timestamp_ns !=
                            request.presentation.observation_timestamp_ns ||
                        action.packet_count != request.presentation.packet_count) {
                        return fail("checkpoint action trace identity mismatch");
                    }
                    trace.action_available = 1u;
                    trace.controlled_bytes_before =
                        action.controlled_bytes_before;
                    trace.controlled_bytes_after =
                        action.controlled_bytes_after;
                    trace.selected_utility = action.selected_utility;
                    trace.pressure = action.pressure;
                    trace.previous_mask = action.previous_mask;
                    trace.selected_mask = action.selected_mask;
                    trace.protocol_applicable_mask =
                        action.protocol_applicable_mask;
                    trace.final_mask = action.final_mask;
                    trace.released_mask_before = action.released_mask_before;
                    trace.released_mask_after = action.released_mask_after;
                    trace.materializable_mask = action.materializable_mask;
                    trace.pool_unavailable_mask = action.pool_unavailable_mask;
                    trace.observation_complete = action.observation_complete;
                    std::memcpy(
                        trace.missing_reason, action.missing_reason,
                        sizeof(trace.missing_reason));
                    trace.candidates_considered = action.candidates_considered;
                    trace.budget_rejections = action.budget_rejections;
                    trace.action_reason = action.transition_result;
                }
                if (!emit_decision_trace(
                        trace,
                        detector_request_trace_enabled
                            ? &detector_request_trace : nullptr))
                    return false;
                checkpoint_trace_active_ = false;
                checkpoint_student_result_ready_ = false;
            } else {
                return fail("unexpected reorder message kind");
            }
        }
        result_.global_order_conserved = 1u;
        return true;
    }

    bool poll_bridge_once() {
        uint64_t now_ns = 0u;
        if (external_io_enabled(config_)) {
            if (!config_.monotonic_now_ns(
                    config_.monotonic_clock_context, &now_ns) ||
                now_ns == 0u || now_ns < bridge_now_ns_) {
                return fail("external bridge clock regressed");
            }
            bridge_now_ns_ = now_ns;
        } else {
            now_ns = steady_monotonic_ns();
            if (now_ns == 0u || now_ns < bridge_now_ns_)
                return fail("internal bridge clock regressed");
            bridge_now_ns_ = now_ns;
        }
        const auto status = fk_owner_output_sequence_bridge_poll(
            bridge_, now_ns);
        if (status == FK_OWNER_OUTPUT_SEQUENCE_BRIDGE_POLL_INVALID ||
            status == FK_OWNER_OUTPUT_SEQUENCE_BRIDGE_POLL_TERMINAL) {
            return fail("output bridge entered terminal state");
        }
        return drain_ready_messages();
    }

    bool step_rx_normal(bool &stopped) {
        if (stopped)
            return true;
        const auto step = fk_dpdk_exact_rx_producer_pump_step(rx_pump_);
        if (step == FK_DPDK_EXACT_RX_PRODUCER_STEP_INVALID ||
            step == FK_DPDK_EXACT_RX_PRODUCER_STEP_TERMINAL ||
            step == FK_DPDK_EXACT_RX_PRODUCER_STEP_WRONG_THREAD ||
            step == FK_DPDK_EXACT_RX_PRODUCER_STEP_ABORTED_LOCAL) {
            return fail("RX producer failed on normal trace");
        }
        if (step == FK_DPDK_EXACT_RX_PRODUCER_STEP_STOPPED_NORMAL) {
            stopped = true;
            return true;
        }
        if (external_io_enabled(config_)) {
            fk_no_nic_full_composition_io_stats_v1 io{};
            if (!config_.io_stats(config_.io_stats_context, &io))
                return fail("external source stats failed during RX");
            if (io.source_failed != 0u)
                return fail("external source failed before finite end");
        }
        fk_dpdk_exact_rx_producer_pump_stats stats{};
        if (!rx_stop_requested_ &&
            fk_dpdk_exact_rx_producer_pump_get_stats(rx_pump_, &stats) &&
            stats.sequencer_transferred == config_.packet_count &&
            stats.pending == 0u) {
            if (!fk_dpdk_exact_rx_producer_pump_request_stop(rx_pump_))
                return fail("RX normal stop request failed");
            rx_stop_requested_ = true;
        }
        return true;
    }

    bool step_identity_normal(bool &complete) {
        if (complete)
            return true;
        const auto step =
            fk_exact_identity_rx_worker_pump_step(identity_pump_);
        if (step == FK_EXACT_IDENTITY_RX_WORKER_STEP_INVALID ||
            step == FK_EXACT_IDENTITY_RX_WORKER_STEP_TERMINAL ||
            step == FK_EXACT_IDENTITY_RX_WORKER_STEP_WRONG_THREAD ||
            step == FK_EXACT_IDENTITY_RX_WORKER_STEP_STOPPED) {
            fk_exact_identity_rx_worker_pump_stats pump{};
            fk_exact_identity_rx_worker_abort_receipt_v1 abort{};
            fk_exact_identity_router_stats router{};
            fk_quic_retirement_publisher_stats publisher{};
            fk_owner_dispatch_stats dispatch{};
            fk_quic_cid_map_stats cid{};
            const bool pump_ok =
                fk_exact_identity_rx_worker_pump_get_stats(
                    identity_pump_, &pump);
            const bool abort_ok =
                fk_exact_identity_rx_worker_pump_get_abort_receipt(
                    identity_pump_, &abort);
            const bool router_ok = fk_exact_identity_router_get_stats(
                router_, &router);
            const bool publisher_ok =
                fk_quic_retirement_publisher_get_stats(
                    publisher_, &publisher);
            const bool dispatch_ok = fk_owner_dispatch_get_stats(
                dispatch_, &dispatch);
            const bool cid_ok = fk_quic_cid_map_get_stats(cid_map_, &cid);
            char detail[1400]{};
            std::snprintf(
                detail,
                sizeof(detail),
                "identity pump failed on normal trace: step=%s,pump_ok=%u,"
                "terminal=%u,submitted=%" PRIu64 ",abort_ok=%u,abort_seq=%" PRIu64
                ",router_ok=%u,router_sticky=%u,quic_short=%" PRIu64
                ",cid_resolved=%" PRIu64 ",publisher_ok=%u,scratch=%u,"
                "peak_marked=%u,scratch_overflows=%" PRIu64
                ",publisher_queue_full=%" PRIu64
                ",prefix_attempts=%" PRIu64
                ",prefix_committed=%" PRIu64
                ",data_calls=%" PRIu64 ",data_committed=%" PRIu64
                ",controls_committed=%" PRIu64
                ",dispatch_ok=%u,queue_capacity=%u,total_depth=%" PRIu64
                ",retire_depth=%" PRIu64 ",dispatch_prefix_attempts=%" PRIu64
                ",dispatch_prefix_committed=%" PRIu64
                ",dispatch_queue_full=%" PRIu64
                ",cid_ok=%u,active_connections=%u,retired_pending_ack=%u,"
                "publication_ready=%" PRIu64,
                fk_exact_identity_rx_worker_step_result_name(step),
                pump_ok ? 1u : 0u,
                static_cast<unsigned>(pump.terminal_reason),
                pump.submitted_packets,
                abort_ok ? 1u : 0u,
                abort_ok ? abort.descriptor.packet_sequence : 0u,
                router_ok ? 1u : 0u,
                static_cast<unsigned>(router.sticky_failure),
                router.quic_short_packets,
                router.cid_resolved,
                publisher_ok ? 1u : 0u,
                publisher.maximum_controls_per_batch,
                publisher.peak_marked_controls,
                publisher.scratch_overflows,
                publisher.dispatch_queue_full,
                publisher.observation_prefix_dispatch_attempts,
                publisher.observation_prefix_batches_committed,
                publisher.data_calls,
                publisher.data_batches_committed,
                publisher.controls_committed,
                dispatch_ok ? 1u : 0u,
                dispatch.queue_capacity_per_owner,
                dispatch.total_depth,
                dispatch.retire_control_depth,
                dispatch.observation_retire_prefix_attempts,
                dispatch.observation_retire_prefixes_accepted,
                dispatch.queue_full,
                cid_ok ? 1u : 0u,
                cid.active_connections,
                cid.retired_pending_owner_ack,
                cid.retirement_publication_peek_ready);
            return fail(detail);
        }
        if (step == FK_EXACT_IDENTITY_RX_WORKER_STEP_COMPLETE)
            complete = true;
        return true;
    }

    bool step_owner_normal(bool stopped) {
        if (stopped)
            return true;
        const auto step = fk_fixed_owner_worker_pump_step(owner_pump_);
        if (step == FK_FIXED_OWNER_WORKER_PUMP_STEP_INVALID ||
            step == FK_FIXED_OWNER_WORKER_PUMP_STEP_TERMINAL ||
            step == FK_FIXED_OWNER_WORKER_PUMP_STEP_WRONG_THREAD ||
            step == FK_FIXED_OWNER_WORKER_PUMP_STEP_STOPPED) {
            fk_fixed_owner_worker_pump_stats pump{};
            fk_owner_runtime_adapter_stats adapter{};
            const bool pump_ok = fk_fixed_owner_worker_pump_get_stats(
                owner_pump_, &pump);
            const bool adapter_ok = fk_owner_runtime_adapter_get_stats(
                &adapter_, &adapter);
            char detail[512]{};
            std::snprintf(
                detail, sizeof(detail),
                "fixed owner pump failed on normal trace: step=%s pump_stats=%u terminal=%s last_packet=%llu data_terminal=%llu retire_terminal=%llu adapter_stats=%u runtime_failures=%llu binding_failures=%llu semantic_data_failures=%llu",
                fk_fixed_owner_worker_pump_step_result_name(step),
                pump_ok ? 1u : 0u,
                pump_ok
                    ? fk_fixed_owner_worker_pump_terminal_reason_name(
                        pump.terminal_reason)
                    : "unavailable",
                static_cast<unsigned long long>(pump.last_packet_sequence),
                static_cast<unsigned long long>(pump.data_terminal_results),
                static_cast<unsigned long long>(pump.retire_terminal_results),
                adapter_ok ? 1u : 0u,
                static_cast<unsigned long long>(adapter.runtime_failures),
                static_cast<unsigned long long>(adapter.binding_failures),
                static_cast<unsigned long long>(
                    adapter.semantic_data_step_failures));
            return fail(detail);
        }
        return drain_evidence_transitions();
    }

    bool close_normal_identity_and_dispatch() {
        const auto closed = fk_owner_output_sequence_bridge_close_epoch(
            bridge_, config_.packet_count);
        if (closed != FK_OWNER_OUTPUT_SEQUENCE_BRIDGE_CLOSED)
            return fail("streaming partial epoch close failed");
        result_.partial_epoch_closed =
            config_.bridge_epoch_packet_limit > config_.packet_count ? 1u : 0u;
        const auto identity_stop =
            fk_exact_identity_rx_worker_pump_stop_normal(identity_pump_);
        if (identity_stop != FK_EXACT_IDENTITY_RX_WORKER_STOPPED_NORMAL) {
            fk_exact_identity_rx_worker_pump_stats identity{};
            fk_exact_identity_sequencer_stats sequencer{};
            fk_dpdk_exact_identity_mbuf_source_stats source{};
            fk_exact_identity_router_stats router{};
            const bool identity_ok =
                fk_exact_identity_rx_worker_pump_get_stats(
                    identity_pump_, &identity);
            const bool sequencer_ok = fk_exact_identity_sequencer_get_stats(
                sequencer_, &sequencer);
            const bool source_ok =
                fk_dpdk_exact_identity_mbuf_source_get_stats(
                    identity_source_, &source);
            const bool router_ok = fk_exact_identity_router_get_stats(
                router_, &router);
            char detail[1024]{};
            std::snprintf(
                detail, sizeof(detail),
                "identity normal stop failed: result=%u identity_ok=%u "
                "complete_seen=%u current=%u source_claimed=%u reclaim=%u "
                "identity_conserved=%u terminal=%u counter_overflow=%u "
                "sequencer_ok=%u formal_complete=%u closed=%u expected=%llu "
                "accepted=%llu released=%llu next=%llu ingress=%llu "
                "reorder=%llu owned=%llu source_ok=%u active_claim=%u "
                "source_conserved=%u router_ok=%u prepared=%u sticky=%u "
                "router_conserved=%u",
                static_cast<unsigned>(identity_stop),
                identity_ok ? 1u : 0u,
                static_cast<unsigned>(identity.sequencer_complete_observed),
                static_cast<unsigned>(identity.current_packet),
                static_cast<unsigned>(identity.source_claimed),
                static_cast<unsigned>(identity.reclaim_pending),
                static_cast<unsigned>(identity.accounting_conserved),
                static_cast<unsigned>(identity.terminal_reason),
                static_cast<unsigned>(identity.counter_overflow),
                sequencer_ok ? 1u : 0u,
                sequencer.formal_complete ? 1u : 0u,
                static_cast<unsigned>(sequencer.closed_producers),
                static_cast<unsigned long long>(sequencer.expected_packets),
                static_cast<unsigned long long>(sequencer.accepted_packets),
                static_cast<unsigned long long>(
                    sequencer.ordered_released_packets),
                static_cast<unsigned long long>(sequencer.next_sequence),
                static_cast<unsigned long long>(sequencer.ingress_depth),
                static_cast<unsigned long long>(sequencer.reorder_depth),
                static_cast<unsigned long long>(sequencer.owned_packets),
                source_ok ? 1u : 0u,
                static_cast<unsigned>(source.active_claim),
                static_cast<unsigned>(source.accounting_conserved),
                router_ok ? 1u : 0u,
                static_cast<unsigned>(router.prepared_transaction),
                static_cast<unsigned>(router.sticky_failure),
                static_cast<unsigned>(router.accounting_conserved));
            return fail(detail);
        }
        if (external_io_enabled(config_)) {
            finite_epoch_quic_drain_after_input_eof_ = true;
            if (!fk_quic_presentation_path_directory_drain_finite_epoch(
                    path_directory_,
                    config_.terminal_semantic_timestamp_ns,
                    &finite_epoch_quic_path_drain_)) {
                return fail("finite-epoch QUIC path drain failed");
            }
            if (!fk_quic_cid_map_drain_finite_epoch(
                    cid_map_,
                    config_.terminal_semantic_timestamp_ns,
                    &finite_epoch_quic_drain_)) {
                return fail("finite-epoch QUIC drain failed");
            }
        }
        if (!fk_owner_dispatch_seal_observations(
                dispatch_, config_.packet_count))
            return fail("dispatch observation seal failed");
        return true;
    }

    bool advance_terminal_retirement_drain(bool &complete) {
        if (complete)
            return true;
        fk_owner_dispatch_stats dispatch{};
        fk_fixed_owner_worker_pump_stats owner{};
        if (!fk_owner_dispatch_get_stats(dispatch_, &dispatch) ||
            !fk_fixed_owner_worker_pump_get_stats(owner_pump_, &owner)) {
            return fail("terminal retirement drain stats unavailable");
        }
        /* A terminal control batch is atomic.  Wait for the preceding batch
         * and every owner-local retry/outbox/completion to quiesce so a full
         * bounded prefix cannot observe artificial queue pressure. */
        if (dispatch.total_depth != 0u || owner.pending_data != 0u ||
            owner.active_mbuf_claim != 0u || owner.pending_reclaim != 0u ||
            owner.pending_retire != 0u || owner.pending_outbox != 0u ||
            owner.pending_completion != 0u) {
            return true;
        }
        const auto terminal =
            fk_quic_retirement_publisher_submit_terminal_batch(
                publisher_, terminal_retirement_ordinal_);
        if (terminal == FK_QUIC_RETIREMENT_PUBLISHER_TERMINAL_COMMITTED) {
            if (terminal_retirement_ordinal_ == UINT64_MAX)
                return fail("terminal retirement ordinal overflow");
            ++terminal_retirement_ordinal_;
            return true;
        }
        if (terminal != FK_QUIC_RETIREMENT_PUBLISHER_TERMINAL_EMPTY) {
            fk_quic_retirement_publisher_stats publisher{};
            fk_quic_cid_map_stats cid{};
            (void)fk_quic_retirement_publisher_get_stats(
                publisher_, &publisher);
            (void)fk_quic_cid_map_get_stats(cid_map_, &cid);
            char detail[512]{};
            std::snprintf(
                detail,
                sizeof(detail),
                "retirement terminal drain failed: result=%s ordinal=%" PRIu64
                ",scratch=%u,marked=%u,scratch_overflows=%" PRIu64
                ",dispatch_queue_full=%" PRIu64
                ",retired_pending_ack=%u,publication_ready=%" PRIu64,
                fk_quic_retirement_publisher_result_name(terminal),
                terminal_retirement_ordinal_,
                publisher.maximum_controls_per_batch,
                publisher.current_marked_controls,
                publisher.scratch_overflows,
                publisher.dispatch_queue_full,
                cid.retired_pending_owner_ack,
                cid.retirement_publication_peek_ready);
            return fail(detail);
        }
        if (!fk_owner_dispatch_stop_accepting(dispatch_))
            return fail("dispatch normal stop failed after retirement drain");
        complete = true;
        return true;
    }

    bool advance_runtime_to_terminal_watermark() {
        const uintptr_t adapter_token =
            reinterpret_cast<uintptr_t>(&adapter_);
        if (!fk_compact_runtime_owner_adapter_scope_begin(
                runtime_, adapter_token, 0u))
            return fail("runtime terminal scope begin failed");
        const uint64_t terminal_ns = external_io_enabled(config_)
            ? config_.terminal_semantic_timestamp_ns
            : kSemanticBase + config_.packet_count +
                  UINT64_C(2000000000);
        auto &transition_receipt = result_.evidence_transitions;
        const uint64_t pass_limit =
            static_cast<uint64_t>(config_.maximum_flows) * 3u + 2u;
        bool advanced = true;
        bool complete = false;
        for (uint64_t pass = 0u;
             advanced && !complete && pass < pass_limit; ++pass) {
            fk_compact_runtime_stats before{};
            fk_compact_runtime_stats after{};
            advanced = fk_compact_runtime_get_stats(runtime_, &before) &&
                fk_compact_runtime_advance_semantic_time_step(
                    runtime_, terminal_ns, &complete) &&
                fk_compact_runtime_get_stats(runtime_, &after);
            if (!advanced)
                break;
            transition_receipt.terminal_timer_scan_passes++;
            if (after.optional_timer_component_releases <
                    before.optional_timer_component_releases) {
                advanced = false;
            } else {
                transition_receipt.terminal_timer_component_releases +=
                    after.optional_timer_component_releases -
                    before.optional_timer_component_releases;
            }
            if (advanced)
                advanced = drain_evidence_transitions_in_owner_scope();
        }
        if (!complete)
            advanced = false;

        /* A zero-release scan is an explicit terminal quiescence proof.  It
         * must run only after every bounded advance step has been persisted. */
        bool timer_quiescent = false;
        for (uint64_t pass = 0u;
             advanced && pass < pass_limit; ++pass) {
            uint32_t releases = 0u;
            transition_receipt.terminal_timer_scan_passes++;
            if (!fk_compact_runtime_scan_optional_timers(
                    runtime_, terminal_ns, config_.maximum_flows,
                    &releases)) {
                advanced = false;
                break;
            }
            transition_receipt.terminal_timer_component_releases += releases;
            if (!drain_evidence_transitions_in_owner_scope()) {
                advanced = false;
                break;
            }
            if (releases == 0u) {
                timer_quiescent = true;
                break;
            }
        }
        const bool ended = fk_compact_runtime_owner_adapter_scope_end(
            runtime_, adapter_token, 0u);
        if (!advanced || !timer_quiescent || !ended)
            return fail("runtime terminal semantic watermark failed");
        return true;
    }

    bool finalize_student_to_terminal_watermark() {
        if (frozen_causal_enabled(config_) &&
            !causal_calibrator_enabled(config_)) {
            fk_detection_event_path_stats event_stats{};
            if (event_path_ == nullptr ||
                !fk_detection_event_path_get_stats(
                    event_path_, &event_stats)) {
                return fail("frozen causal actor capacity stats unavailable");
            }
            snapshot_detection_service_capacity(
                event_stats, 0u, 0u, 0u, 0u);
            if (!detection_service_capacity_contract_valid())
                return fail_detection_service_capacity_gate(
                    "frozen causal actor capacity gate failed");
            result_.frozen_causal_aggregation.complete = 1u;
            return true;
        }
        if (student_timestamp_pending_) {
            if (!broadcast_student_watermark(
                    student_pending_timestamp_ns_, false)) {
                return false;
            }
            student_timestamp_pending_ = false;
        }
        const uint64_t final_watermark_ns = external_io_enabled(config_)
            ? config_.terminal_semantic_timestamp_ns
            : kSemanticBase + config_.packet_count +
                UINT64_C(2000000000);
        if (student_watermark_initialized_ &&
            final_watermark_ns < student_last_watermark_ns_) {
            return fail("Event Student final watermark precedes observations");
        }
        if (!broadcast_student_watermark(final_watermark_ns, true))
            return false;
        if (causal_calibrator_enabled(config_)) {
            fk_online_event_windows_stats stats{};
            fk_detection_event_path_stats event_stats{};
            auto &receipt = result_.frozen_causal_aggregation;
            if (causal_windows_ == nullptr ||
                event_path_ == nullptr ||
                !fk_online_event_windows_get_stats(causal_windows_, &stats) ||
                !fk_detection_event_path_get_stats(
                    event_path_, &event_stats)) {
                return fail("causal V2 terminal stats unavailable");
            }
            snapshot_detection_service_capacity(
                event_stats,
                stats.maximum_events,
                stats.maximum_total_flows,
                stats.live_slot_reuse_conflicts,
                stats.event_slots_reused);
            receipt.scheduled_periodic_ticks = stats.ticks_due;
            receipt.empty_periodic_ticks = stats.empty_ticks;
            receipt.same_timestamp_periodic_coalesces =
                stats.same_timestamp_unchanged_periodic_coalesces;
            receipt.mixed_mask_triggers = stats.causal_mixed_mask_triggers;
            receipt.causal_records_presented =
                stats.causal_records_presented;
            uint64_t periodic_partition = receipt.empty_periodic_ticks;
            const bool arithmetic = checked_add_u64(
                    periodic_partition,
                    receipt.same_timestamp_periodic_coalesces) &&
                checked_add_u64(
                    periodic_partition, receipt.periodic_updates);
            receipt.model_used =
                receipt.inference_calls != 0u ? 1u : 0u;
            receipt.complete =
                arithmetic && stats.formal_completeness &&
                    detection_service_capacity_contract_valid() &&
                    stats.trigger_protocol ==
                        FK_ONLINE_EVENT_TRIGGER_PROTOCOL_CHECKPOINT_PERIODIC_V2 &&
                    stats.causal_model_failures == 0u &&
                    receipt.inference_failures == 0u &&
                    receipt.model_load_successes == 1u &&
                    receipt.model_load_failures == 0u &&
                    receipt.model_loaded != 0u && receipt.model_used != 0u &&
                    receipt.total_feature_updates ==
                        receipt.checkpoint_updates + receipt.periodic_updates &&
                    receipt.inference_calls == receipt.total_feature_updates &&
                    receipt.feature_state_resets ==
                        receipt.initialized_event_generations &&
                    stats.causal_model_calls == receipt.inference_calls &&
                    stats.checkpoint_trigger_inferred_windows ==
                        receipt.checkpoint_updates &&
                    stats.periodic_trigger_inferred_windows ==
                        receipt.periodic_updates &&
                    periodic_partition == receipt.scheduled_periodic_ticks
                ? 1u : 0u;
            if (receipt.complete == 0u) {
                char detail[2048]{};
                std::snprintf(
                    detail,
                    sizeof(detail),
                    "causal V2 terminal conservation failed: "
                    "arith=%u formal=%u protocol=%u/%u "
                    "model_fail=%" PRIu64 " infer_fail=%" PRIu64 " "
                    "load_ok/fail=%" PRIu64 "/%" PRIu64 " "
                    "loaded/used=%u/%u "
                    "feature_total/checkpoint+periodic=%" PRIu64
                    "/%" PRIu64 "+%" PRIu64 " "
                    "inference/feature_total=%" PRIu64 "/%" PRIu64 " "
                    "reset/init=%" PRIu64 "/%" PRIu64 " "
                    "model_calls/inference=%" PRIu64 "/%" PRIu64 " "
                    "checkpoint_windows/updates=%" PRIu64 "/%" PRIu64 " "
                    "periodic_windows/updates=%" PRIu64 "/%" PRIu64 " "
                    "periodic_partition/scheduled=%" PRIu64 "/%" PRIu64
                    "[empty=%" PRIu64 ",coalesced=%" PRIu64
                    ",updates=%" PRIu64 "] "
                    "window_failures[encode=%" PRIu64
                    ",student=%" PRIu64 ",unopened=%" PRIu64
                    ",stale=%" PRIu64 ",order=%" PRIu64
                    ",closed=%" PRIu64 ",output=%" PRIu64
                    ",capacity=%" PRIu64 ",identity=%" PRIu64
                    ",trigger=%" PRIu64 ",checkpoint=%" PRIu64
                    ",ordinal=%" PRIu64 ",snapshot=%" PRIu64 "] "
                    "flow_epoch[open=%" PRIu64 ",dup_open=%" PRIu64
                    ",nonfirst=%" PRIu64 ",noncreate=%" PRIu64
                    ",live_reuse=%" PRIu64 ",capacity_supersession=%" PRIu64
                    ",slot_reuse=%" PRIu64
                    ",reopen=%" PRIu64 ",dup_reopen=%" PRIu64
                    ",noncausal_reopen=%" PRIu64
                    ",reopen_new/existing=%" PRIu64 "/%" PRIu64 "] "
                    "actor_capacity[clean=%u,event_evict=%" PRIu64
                    ",flow_evict=%" PRIu64 ",flow_rollover=%" PRIu64
                    ",active/peak_events=%u/%u"
                    ",active/peak_flows=%u/%u,max_events/flows/per_event=%u/%u/%u] "
                    "watermark[advances=%" PRIu64 ",steps=%" PRIu64
                    ",partial=%" PRIu64 ",auto=%" PRIu64
                    ",initialized=%u,inclusive=%" PRIu64 "]",
                    arithmetic ? 1u : 0u,
                    stats.formal_completeness ? 1u : 0u,
                    static_cast<unsigned>(stats.trigger_protocol),
                    static_cast<unsigned>(
                        FK_ONLINE_EVENT_TRIGGER_PROTOCOL_CHECKPOINT_PERIODIC_V2),
                    stats.causal_model_failures,
                    receipt.inference_failures,
                    receipt.model_load_successes,
                    receipt.model_load_failures,
                    static_cast<unsigned>(receipt.model_loaded),
                    static_cast<unsigned>(receipt.model_used),
                    receipt.total_feature_updates,
                    receipt.checkpoint_updates,
                    receipt.periodic_updates,
                    receipt.inference_calls,
                    receipt.total_feature_updates,
                    receipt.feature_state_resets,
                    receipt.initialized_event_generations,
                    stats.causal_model_calls,
                    receipt.inference_calls,
                    stats.checkpoint_trigger_inferred_windows,
                    receipt.checkpoint_updates,
                    stats.periodic_trigger_inferred_windows,
                    receipt.periodic_updates,
                    periodic_partition,
                    receipt.scheduled_periodic_ticks,
                    receipt.empty_periodic_ticks,
                    receipt.same_timestamp_periodic_coalesces,
                    receipt.periodic_updates,
                    stats.encode_failures,
                    stats.student_window_failures,
                    stats.unopened_checkpoint_rejections,
                    stats.stale_handle_rejections,
                    stats.out_of_order_rejections,
                    stats.closed_timestamp_rejections,
                    stats.output_rejections,
                    stats.flow_capacity_overflows,
                    stats.identity_mode_rejections,
                    stats.trigger_protocol_rejections,
                    stats.invalid_checkpoint_packet_rejections,
                    stats.trigger_ordinal_overflows,
                    stats.snapshot_version_overflows,
                    stats.flow_open_messages,
                    stats.duplicate_flow_open_messages,
                    stats.non_first_packet_flow_open_rejections,
                    stats.noncreating_event_activation_rejections,
                    stats.live_slot_reuse_conflicts,
                    stats.capacity_supersession_retirements,
                    stats.event_slots_reused,
                    stats.flow_reopen_messages,
                    stats.duplicate_flow_reopen_messages,
                    stats.noncausal_flow_reopen_rejections,
                    stats.flow_reopen_new_event_activations,
                    stats.flow_reopen_existing_event_joins,
                    static_cast<unsigned>(
                        result_.detection_service_capacity.capacity_clean),
                    result_.detection_service_capacity
                        .actor_event_capacity_evictions,
                    result_.detection_service_capacity
                        .actor_total_flow_capacity_evictions,
                    result_.detection_service_capacity
                        .actor_flow_capacity_rollovers,
                    result_.detection_service_capacity.actor_active_events,
                    result_.detection_service_capacity
                        .actor_peak_active_events,
                    result_.detection_service_capacity.actor_active_flows,
                    result_.detection_service_capacity
                        .actor_peak_active_flows,
                    result_.detection_service_capacity.actor_maximum_events,
                    result_.detection_service_capacity
                        .actor_maximum_total_flows,
                    result_.detection_service_capacity
                        .actor_maximum_flows_per_event,
                    stats.watermark_advances,
                    stats.watermark_step_calls,
                    stats.partial_watermark_steps,
                    stats.automatic_exclusive_advances,
                    stats.watermark_initialized ? 1u : 0u,
                    stats.inclusive_watermark_ns);
                return fail(detail);
            }
            return true;
        }
        if (!fk_student_shards_final_flush_complete(
                student_shards_, final_watermark_ns) ||
            !fk_student_shards_command_queues_empty(student_shards_) ||
            !fk_student_shards_result_queues_empty(student_shards_) ||
            fk_student_shards_any_worker_failed(student_shards_)) {
            return fail("Event Student final flush receipt is incomplete");
        }
        return true;
    }

    bool run_normal() {
        bool rx_stopped = false;
        bool identity_complete = false;
        bool identity_stopped = false;
        bool owner_stopped = false;
        bool completions_stopped = false;
        bool runtime_advanced = false;
        bool terminal_retirements_complete = false;

        const uint64_t iteration_limit =
            config_.maximum_run_iterations != 0u
                ? config_.maximum_run_iterations
                : static_cast<uint64_t>(config_.packet_count) * 64u +
                      200000u;
        if (!sample_queue_depth(true))
            return false;
        for (uint64_t iteration = 0u; iteration < iteration_limit;
             ++iteration) {
            const bool rx_was_stopped = rx_stopped;
            if (!step_rx_normal(rx_stopped) ||
                !step_identity_normal(identity_complete) ||
                !step_owner_normal(owner_stopped) ||
                !poll_bridge_once()) {
                return false;
            }
            if (!rx_was_stopped && rx_stopped)
                begin_recovery_observation();
            if (!sample_queue_depth(!rx_stopped))
                return false;
            if (identity_complete && !identity_stopped) {
                if (!rx_stopped)
                    continue;
                if (!close_normal_identity_and_dispatch())
                    return false;
                identity_stopped = true;
            }
            if (identity_stopped && !owner_stopped) {
                fk_fixed_owner_worker_pump_stats stats{};
                fk_exact_identity_rx_worker_pump_stats identity_stats{};
                if (!fk_fixed_owner_worker_pump_get_stats(
                        owner_pump_, &stats) ||
                    !fk_exact_identity_rx_worker_pump_get_stats(
                        identity_pump_, &identity_stats))
                    return fail("owner stats failed before stop");
                if (!advance_terminal_retirement_drain(
                        terminal_retirements_complete)) {
                    return false;
                }
                if (stats.data_packets_completed ==
                        identity_stats.data_transfers &&
                    terminal_retirements_complete &&
                    !runtime_advanced) {
                    if (!advance_runtime_to_terminal_watermark())
                        return false;
                    runtime_advanced = true;
                }
                if (runtime_advanced) {
                    const auto stopped =
                        fk_fixed_owner_worker_pump_stop_normal(owner_pump_);
                    if (stopped ==
                        FK_FIXED_OWNER_WORKER_PUMP_STOPPED_NORMAL) {
                        owner_stopped = true;
                    } else if (stopped !=
                               FK_FIXED_OWNER_WORKER_PUMP_STOP_NOT_READY) {
                        return fail("owner normal stop failed");
                    }
                }
            }
            if (owner_stopped && !completions_stopped) {
                if (!fk_owner_output_sequence_bridge_stop_completions(
                        bridge_))
                    return fail("bridge completion stop failed");
                completions_stopped = true;
            }
            if (completions_stopped) {
                if (!drain_ready_messages())
                    return false;
                if (fk_owner_output_sequence_bridge_seal(bridge_)) {
                    if (!finalize_student_to_terminal_watermark())
                        return false;
                    if (!complete_recovery_observation())
                        return fail("queue recovery receipt is incomplete");
                    if (!fk_quic_initial_crypto_admission_gate_seal_normal(
                            gate_))
                        return fail("QUIC crypto gate normal seal failed");
                    if (!snapshot_result())
                        return false;
                    if (!detection_service_capacity_contract_valid()) {
                        return fail_detection_service_capacity_gate(
                            "normal topology actor capacity gate failed");
                    }
                    const bool expected_associations =
                        external_io_enabled(config_) ||
                        (result_.flow_open_messages != 0u &&
                         result_.detection_requests != 0u);
                    const uint64_t identity_reclaimed =
                        result_.identity_skip_reclaims +
                        result_.identity_reject_reclaims;
                    if (!expected_associations ||
                        result_.detector_executions !=
                            result_.detection_requests ||
                        result_.owner_packets_completed +
                                identity_reclaimed !=
                            config_.packet_count ||
                        result_.identity_data_transfers +
                                identity_reclaimed !=
                            config_.packet_count ||
                        result_.rx_received != config_.packet_count ||
                        result_.sequencer_transferred !=
                            config_.packet_count ||
                        result_.mbufs_reclaimed != config_.packet_count ||
                        result_.mbuf_ownership_conserved == 0u ||
                        result_.global_order_conserved == 0u ||
                        result_.source_exhausted == 0u ||
                        result_.source_failed != 0u ||
                        result_.io_forced_failure_reclaims != 0u ||
                        result_.bridge_sealed == 0u ||
                        result_.reorder_drained == 0u ||
                        result_.trigger_receipt.conservation_valid == 0u ||
                        result_.trigger_receipt.final_flush_complete == 0u ||
                        result_.controlled_state_accounting_valid == 0u ||
                        result_.state_byte_seconds_complete == 0u ||
                        result_.evidence_transitions.complete == 0u ||
                        result_.controlled_state_hard_budget_violations !=
                            0u) {
                        return fail("normal topology receipts incomplete");
                    }
                    result_.normal_complete = 1u;
                    return cleanup_normal();
                }
            }
        }
        return fail("normal topology loop exceeded bound");
    }

    bool run_abort() {
        bool rx_locally_aborted = false;
        bool abort_triggered = false;
        for (uint32_t iteration = 0u; iteration < 200000u; ++iteration) {
            if (!abort_triggered) {
                const auto rx =
                    fk_dpdk_exact_rx_producer_pump_step(rx_pump_);
                if (rx == FK_DPDK_EXACT_RX_PRODUCER_STEP_INVALID ||
                    rx == FK_DPDK_EXACT_RX_PRODUCER_STEP_TERMINAL ||
                    rx == FK_DPDK_EXACT_RX_PRODUCER_STEP_WRONG_THREAD)
                    return fail("RX failed before abort trigger");
                const auto identity =
                    fk_exact_identity_rx_worker_pump_step(identity_pump_);
                if (identity == FK_EXACT_IDENTITY_RX_WORKER_STEP_INVALID ||
                    identity == FK_EXACT_IDENTITY_RX_WORKER_STEP_TERMINAL ||
                    identity == FK_EXACT_IDENTITY_RX_WORKER_STEP_WRONG_THREAD)
                    return fail("identity failed before abort trigger");
                if (!step_owner_normal(false) || !poll_bridge_once())
                    return false;
                fk_exact_identity_rx_worker_pump_stats identity_stats{};
                if (!fk_exact_identity_rx_worker_pump_get_stats(
                        identity_pump_, &identity_stats))
                    return fail("identity abort trigger stats failed");
                if (identity_stats.data_transfers >=
                    config_.abort_after_identity_transfers) {
                    if (!fk_dpdk_exact_rx_producer_pump_request_abort(
                            rx_pump_))
                        return fail("RX abort request failed");
                    abort_triggered = true;
                }
                continue;
            }
            if (!rx_locally_aborted) {
                const auto rx =
                    fk_dpdk_exact_rx_producer_pump_step(rx_pump_);
                if (rx == FK_DPDK_EXACT_RX_PRODUCER_STEP_ABORTED_LOCAL) {
                    rx_locally_aborted = true;
                } else if (rx !=
                               FK_DPDK_EXACT_RX_PRODUCER_STEP_ABORT_RECLAIMED &&
                           rx != FK_DPDK_EXACT_RX_PRODUCER_STEP_ABORT_RECLAIM_RETRY) {
                    return fail("RX local abort failed");
                }
                continue;
            }
            break;
        }
        if (!rx_locally_aborted)
            return fail("RX local abort exceeded bound");

        fk_owner_abort_identity_prepared_receipt_v1 identity_receipt{};
        bool identity_prepared = false;
        for (uint32_t iteration = 0u; iteration < 1000u; ++iteration) {
            const auto prepared =
                fk_exact_identity_rx_worker_pump_abort_prepare(
                    identity_pump_);
            if (prepared ==
                FK_EXACT_IDENTITY_RX_WORKER_ABORT_PREPARED_NEEDS_GLOBAL) {
                identity_prepared = true;
                break;
            }
            if (prepared !=
                FK_EXACT_IDENTITY_RX_WORKER_ABORT_PREPARE_RETRY_REQUIRED)
                return fail("identity abort prepare failed");
        }
        if (!identity_prepared ||
            !fk_exact_identity_rx_worker_pump_get_abort_prepared_receipt(
                identity_pump_, &identity_receipt))
            return fail("identity abort receipt missing");

        fk_fixed_owner_abort_prepared_receipt_v1 owner_receipt{};
        bool owner_prepared = false;
        for (uint32_t iteration = 0u; iteration < 1000u; ++iteration) {
            const auto prepared = fk_fixed_owner_worker_pump_abort_prepare(
                owner_pump_, &owner_receipt);
            if (prepared ==
                FK_FIXED_OWNER_WORKER_PUMP_ABORT_PREPARED_NEEDS_COORDINATOR) {
                owner_prepared = true;
                break;
            }
            if (prepared !=
                FK_FIXED_OWNER_WORKER_PUMP_ABORT_PREPARE_RETRY_REQUIRED)
                return fail("owner abort prepare failed");
        }
        if (!owner_prepared)
            return fail("owner abort prepare exceeded bound");
        if (!fk_quic_initial_crypto_admission_gate_seal_abort(gate_))
            return fail("QUIC crypto gate abort seal failed");

        if (fk_owner_pipeline_abort_coordinator_record_owner_prepared(
                coordinator_, &owner_receipt) !=
                FK_OWNER_PIPELINE_ABORT_RECORDED ||
            fk_owner_pipeline_abort_coordinator_record_identity_prepared(
                coordinator_, &identity_receipt) !=
                FK_OWNER_PIPELINE_ABORT_RECORDED) {
            return fail("abort coordinator receipt admission failed");
        }
        if (fk_owner_pipeline_abort_coordinator_commit(coordinator_) !=
            FK_OWNER_PIPELINE_ABORT_COMMITTED)
            return fail("global abort coordinator commit failed");
        fk_owner_pipeline_abort_receipt_v1 global{};
        if (!fk_owner_pipeline_abort_coordinator_get_receipt(
                coordinator_, &global) ||
            fk_fixed_owner_worker_pump_abort_finalize(
                owner_pump_, coordinator_, &global) !=
                FK_FIXED_OWNER_WORKER_PUMP_ABORT_FINALIZED ||
            fk_exact_identity_rx_worker_pump_abort_finalize(
                identity_pump_, coordinator_, &global) !=
                FK_EXACT_IDENTITY_RX_WORKER_ABORT_FINALIZED) {
            return fail("abort participant finalize failed");
        }
        if (!snapshot_result())
            return false;
        if (result_.mbuf_ownership_conserved == 0u ||
            result_.mbufs_reclaimed != config_.packet_count)
            return fail("abort mbuf ownership not conserved");
        result_.abort_complete = 1u;
        return cleanup_abort();
    }

    bool cleanup_normal() {
        if (causal_calibrator_ != nullptr) {
            fk_causal_event_calibrator_destroy(causal_calibrator_);
            causal_calibrator_ = nullptr;
        }
        causal_windows_ = nullptr;
        if (student_shards_ != nullptr) {
            fk_student_shards_destroy(student_shards_);
            student_shards_ = nullptr;
        }
        event_path_ = nullptr;
        if (!fk_dpdk_exact_rx_producer_pump_destroy_checked(rx_pump_))
            return fail("normal destroy RX producer failed");
        rx_pump_ = nullptr;
        if (!fk_exact_identity_rx_worker_pump_destroy_checked(
                identity_pump_))
            return fail("normal destroy identity pump failed");
        identity_pump_ = nullptr;
        if (!fk_fixed_owner_worker_pump_destroy_checked(owner_pump_))
            return fail("normal destroy owner pump failed");
        owner_pump_ = nullptr;
        if (!fk_exact_identity_router_destroy_checked(router_))
            return fail("normal destroy identity router failed");
        router_ = nullptr;
        if (!fk_owner_output_sequence_bridge_destroy_checked(bridge_))
            return fail("normal destroy output bridge failed");
        bridge_ = nullptr;
        if (!fk_checkpoint_reorder_destroy_checked(reorder_))
            return fail("normal destroy checkpoint reorder failed");
        reorder_ = nullptr;
        if (!fk_owner_output_batch_ring_destroy_checked(ring_))
            return fail("normal destroy output ring failed");
        ring_ = nullptr;
        if (!fk_dpdk_exact_identity_mbuf_source_destroy_checked(
                identity_source_))
            return fail("normal destroy identity source failed");
        identity_source_ = nullptr;
        if (!fk_dpdk_owner_mbuf_bytes_source_destroy_checked(owner_source_))
            return fail("normal destroy owner source failed");
        owner_source_ = nullptr;
        if (!fk_exact_identity_sequencer_destroy(sequencer_))
            return fail("normal destroy sequencer failed");
        sequencer_ = nullptr;
        if (!fk_quic_initial_crypto_admission_gate_destroy_checked(gate_))
            return fail("normal destroy QUIC gate failed");
        gate_ = nullptr;
        if (!fk_quic_retirement_publisher_destroy_checked(publisher_))
            return fail("normal destroy retirement publisher failed");
        publisher_ = nullptr;
        if (!fk_owner_dispatch_destroy_checked(dispatch_))
            return fail("normal destroy dispatch failed");
        dispatch_ = nullptr;
        fk_owner_flow_bindings_destroy(bindings_);
        bindings_ = nullptr;
        fk_quic_route_receipt_destroy(route_receipts_);
        route_receipts_ = nullptr;
        fk_quic_presentation_path_directory_destroy(path_directory_);
        path_directory_ = nullptr;
        fk_quic_cid_map_destroy(cid_map_);
        cid_map_ = nullptr;
        fk_compact_runtime_destroy(runtime_);
        runtime_ = nullptr;
        return true;
    }

    bool cleanup_abort() {
        if (causal_calibrator_ != nullptr) {
            fk_causal_event_calibrator_destroy(causal_calibrator_);
            causal_calibrator_ = nullptr;
        }
        causal_windows_ = nullptr;
        if (student_shards_ != nullptr) {
            fk_student_shards_destroy(student_shards_);
            student_shards_ = nullptr;
        }
        event_path_ = nullptr;
        if (!fk_owner_pipeline_abort_coordinator_destroy_checked(
                coordinator_))
            return fail("abort destroy coordinator failed");
        coordinator_ = nullptr;
        if (!fk_dpdk_exact_rx_producer_pump_destroy_checked(rx_pump_))
            return fail("abort destroy RX producer failed");
        rx_pump_ = nullptr;
        if (!fk_exact_identity_rx_worker_pump_destroy_checked(
                identity_pump_))
            return fail("abort destroy identity pump failed");
        identity_pump_ = nullptr;
        if (!fk_fixed_owner_worker_pump_destroy_checked(owner_pump_))
            return fail("abort destroy owner pump failed");
        owner_pump_ = nullptr;
        if (!fk_exact_identity_router_destroy_checked(router_))
            return fail("abort destroy identity router failed");
        router_ = nullptr;
        if (!fk_owner_output_sequence_bridge_destroy_checked(bridge_))
            return fail("abort destroy output bridge failed");
        bridge_ = nullptr;
        if (!fk_checkpoint_reorder_destroy_checked(reorder_))
            return fail("abort destroy checkpoint reorder failed");
        reorder_ = nullptr;
        if (!fk_owner_output_batch_ring_destroy_checked(ring_))
            return fail("abort destroy output ring failed");
        ring_ = nullptr;
        if (!fk_dpdk_exact_identity_mbuf_source_destroy_checked(
                identity_source_))
            return fail("abort destroy identity source failed");
        identity_source_ = nullptr;
        if (!fk_dpdk_owner_mbuf_bytes_source_destroy_checked(owner_source_))
            return fail("abort destroy owner source failed");
        owner_source_ = nullptr;
        if (!fk_exact_identity_sequencer_destroy(sequencer_))
            return fail("abort destroy sequencer failed");
        sequencer_ = nullptr;
        if (!fk_quic_initial_crypto_admission_gate_destroy_checked(gate_))
            return fail("abort destroy QUIC gate failed");
        gate_ = nullptr;
        if (!fk_quic_retirement_publisher_destroy_checked(publisher_))
            return fail("abort destroy retirement publisher failed");
        publisher_ = nullptr;
        if (!fk_owner_dispatch_destroy_checked(dispatch_))
            return fail("abort destroy dispatch failed");
        dispatch_ = nullptr;
        fk_owner_flow_bindings_destroy(bindings_);
        bindings_ = nullptr;
        fk_quic_route_receipt_destroy(route_receipts_);
        route_receipts_ = nullptr;
        fk_quic_presentation_path_directory_destroy(path_directory_);
        path_directory_ = nullptr;
        fk_quic_cid_map_destroy(cid_map_);
        cid_map_ = nullptr;
        fk_compact_runtime_destroy(runtime_);
        runtime_ = nullptr;
        return true;
    }

    const fk_no_nic_full_composition_config &config_;
    fk_no_nic_full_composition_result &result_;
    char *error_;
    size_t error_capacity_;
    TraceIo trace_;
    TestModel action_model_;
    TestModel detector_model_;
    TestEventStudent event_student_model_;
    ExternalReclaimAdapter external_reclaim_{};

    AlignedStorage sequencer_storage_;
    fk_exact_identity_sequencer *sequencer_ = nullptr;
    AlignedStorage rx_pump_storage_;
    fk_dpdk_exact_rx_producer_pump *rx_pump_ = nullptr;
    AlignedStorage identity_source_storage_;
    fk_dpdk_exact_identity_mbuf_source *identity_source_ = nullptr;
    fk_exact_identity_packet_bytes_resolver identity_resolver_{};

    AlignedStorage dispatch_storage_;
    fk_owner_dispatch *dispatch_ = nullptr;
    AlignedStorage cid_storage_;
    fk_quic_cid_map *cid_map_ = nullptr;
    fk_quic_cid_finite_epoch_drain_receipt_v1
        finite_epoch_quic_drain_{};
    fk_quic_presentation_path_finite_epoch_drain_receipt_v1
        finite_epoch_quic_path_drain_{};
    bool finite_epoch_quic_drain_after_input_eof_ = false;
    AlignedStorage path_storage_;
    fk_quic_presentation_path_directory *path_directory_ = nullptr;
    AlignedStorage route_storage_;
    fk_quic_route_receipt_state *route_receipts_ = nullptr;
    AlignedStorage publisher_storage_;
    fk_quic_retirement_publisher *publisher_ = nullptr;
    AlignedStorage binding_storage_;
    fk_owner_flow_bindings *bindings_ = nullptr;
    uint64_t cid_reserved_bytes_ = 0u;
    uint64_t path_reserved_bytes_ = 0u;
    uint64_t binding_reserved_bytes_ = 0u;
    uint64_t identity_controlled_reserved_bytes_ = 0u;
    uint32_t identity_capacity_ = 0u;

    fk_actor_session_config actor_config_{};
    AlignedStorage event_path_storage_;
    fk_detection_event_path *event_path_ = nullptr;
    fk_student_shards *student_shards_ = nullptr;
    AlignedStorage causal_windows_storage_;
    fk_online_event_windows *causal_windows_ = nullptr;
    fk_causal_event_calibrator *causal_calibrator_ = nullptr;
    std::vector<FrozenCausalEventState> frozen_event_states_;
    uint64_t causal_current_detector_start_ns_ = 0u;
    uint64_t causal_current_detector_end_ns_ = 0u;
    bool frozen_observation_timestamp_initialized_ = false;
    uint64_t frozen_last_observation_timestamp_ns_ = 0u;
    bool student_timestamp_pending_ = false;
    uint64_t student_pending_timestamp_ns_ = 0u;
    bool student_watermark_initialized_ = false;
    uint64_t student_last_watermark_ns_ = 0u;
    uint64_t student_monotonic_ns_ = 0u;
    uint64_t student_checkpoint_results_ = 0u;
    uint64_t student_periodic_results_ = 0u;
    uint64_t student_output_results_ = 0u;
    uint64_t student_ordinal_sum_ = 0u;
    uint64_t student_ordinal_xor_ = 0u;
    uint64_t student_ordinal_max_ = 0u;
    std::array<uint64_t, 21u> student_checkpoint_packet_results_{};
    fk_actor_session_result checkpoint_association_{};
    fk_actor_flow_identity_v2 checkpoint_flow_identity_{};
    fk_student_shard_result checkpoint_student_result_{};
    bool checkpoint_trace_active_ = false;
    bool checkpoint_student_result_ready_ = false;
    std::array<uint64_t, FK_NO_NIC_DECISION_TRACE_HISTOGRAM_BINS>
        detection_latency_histogram_{};
    std::array<uint64_t, FK_NO_NIC_DECISION_TRACE_HISTOGRAM_BINS>
        packet_latency_histogram_{};
    std::array<uint64_t, FK_NO_NIC_DECISION_TRACE_HISTOGRAM_BINS>
        flow_detector_latency_histogram_{};
    QueueRegression offered_queue_regression_{};
    uint64_t queue_peak_all_ = 0u;
    uint64_t queue_samples_total_ = 0u;
    uint64_t recovery_start_monotonic_ns_ = 0u;
    uint64_t recovery_complete_monotonic_ns_ = 0u;
    uint64_t next_trace_record_sequence_ = 0u;
    uint64_t checkpoint_intervention_trace_matches_ = 0u;
    uint64_t checkpoint_intervention_trace_binding_mismatches_ = 0u;

    AlignedStorage ring_storage_;
    fk_owner_output_batch_ring *ring_ = nullptr;
    std::array<fk_owner_output_batch_ring *, kOwners> ring_pointers_{};
    AlignedStorage reorder_storage_;
    fk_checkpoint_reorder *reorder_ = nullptr;
    AlignedStorage bridge_storage_;
    fk_owner_output_sequence_bridge *bridge_ = nullptr;
    AlignedStorage gate_storage_;
    fk_quic_initial_crypto_admission_gate *gate_ = nullptr;
    AlignedStorage router_storage_;
    fk_exact_identity_router *router_ = nullptr;
    AlignedStorage identity_pump_storage_;
    fk_exact_identity_rx_worker_pump *identity_pump_ = nullptr;

    fk_compact_runtime *runtime_ = nullptr;
    AlignedStorage owner_source_storage_;
    fk_dpdk_owner_mbuf_bytes_source *owner_source_ = nullptr;
    fk_owner_packet_bytes_source owner_packet_source_{};
    fk_owner_runtime_adapter adapter_{};
    AlignedStorage owner_pump_storage_;
    fk_fixed_owner_worker_pump *owner_pump_ = nullptr;
    std::array<fk_fixed_owner_worker_pump *, kOwners>
        owner_pump_pointers_{};

    AlignedStorage coordinator_storage_;
    fk_owner_pipeline_abort_coordinator *coordinator_ = nullptr;
    bool rx_stop_requested_ = false;
    bool has_reorder_sequence_ = false;
    uint64_t last_reorder_sequence_ = 0u;
    uint64_t bridge_now_ns_ = 0u;
    uint64_t terminal_retirement_ordinal_ = 0u;
};

}  // namespace

extern "C" {

void fk_no_nic_full_composition_default_config_init(
        fk_no_nic_full_composition_config *config) {
    if (config == nullptr)
        return;
    *config = {};
    config->budget_mode = FK_NO_NIC_FULL_COMPOSITION_BUDGET_16_MIB;
    config->packet_count = 8u;
    config->bridge_epoch_packet_limit = 16u;
    config->completion_window_capacity = 4u;
    config->sequencer_ingress_capacity = 2u;
    config->rx_burst_capacity = 8u;
    config->maximum_flows = 64u;
    config->owner_hash_key_precommitted = 1u;
    for (size_t index = 0u; index < FK_NO_NIC_OWNER_HASH_KEY_BYTES; ++index)
        config->owner_hash_key[index] = static_cast<uint8_t>(0x31u + index);
    config->maximum_quic_connections = 8u;
    config->idle_timeout_ns = UINT64_C(1000000000);
    config->event_student_worker_count = 2u;
    config->event_student_command_queue_capacity = 64u;
    config->event_student_result_queue_capacity = 64u;
    fk_actor_session_config_init(&config->actor_session);
    static const uint8_t monitored_ipv4[4]{10u, 0u, 0u, 0u};
    (void)fk_actor_session_config_add_cidr(
        &config->actor_session, 4u, monitored_ipv4, 8u);
}

bool fk_no_nic_full_composition_run(
        const fk_no_nic_full_composition_config *config,
        fk_no_nic_full_composition_result *result,
        char *error,
        size_t error_capacity) {
    set_error(error, error_capacity, "");
    if (!config_valid(config) || result == nullptr) {
        set_error(error, error_capacity, "invalid no-NIC composition config");
        return false;
    }
    try {
        Composition composition(*config, *result, error, error_capacity);
        return composition.initialize() && composition.run();
    } catch (const std::bad_alloc &) {
        set_error(error, error_capacity,
            "no-NIC composition allocation failed");
        return false;
    } catch (...) {
        set_error(error, error_capacity,
            "no-NIC composition internal exception");
        return false;
    }
}

bool fk_no_nic_service_memory_receipt_verify_v1(
        const fk_no_nic_service_memory_receipt_v1 *receipt) {
    return receipt != nullptr && receipt_semantics_valid(*receipt);
}

const char *fk_no_nic_service_memory_disposition_name_v1(uint8_t value) {
    switch (value) {
    case FK_NO_NIC_SERVICE_MEMORY_DISABLED:
        return "disabled";
    case FK_NO_NIC_SERVICE_MEMORY_ACTIVE_BOUNDED:
        return "active_bounded";
    case FK_NO_NIC_SERVICE_MEMORY_INLINE_NO_TRANSPORT:
        return "inline_no_transport";
    case FK_NO_NIC_SERVICE_MEMORY_TEST_ONLY_TRACE_SIZED:
        return "test_only_trace_sized";
    }
    return "unknown";
}

const char *fk_no_nic_service_memory_auxiliary_component_name_v1(
        uint32_t value) {
    switch (value) {
    case FK_NO_NIC_SERVICE_AUX_RX_PRODUCER_PUMP:
        return "rx_producer_pump";
    case FK_NO_NIC_SERVICE_AUX_IDENTITY_WORKER_PUMP:
        return "identity_worker_pump";
    case FK_NO_NIC_SERVICE_AUX_IDENTITY_ROUTER:
        return "identity_router";
    case FK_NO_NIC_SERVICE_AUX_QUIC_ADMISSION_GATE:
        return "quic_admission_gate";
    case FK_NO_NIC_SERVICE_AUX_OWNER_WORKER_PUMP:
        return "owner_worker_pump";
    case FK_NO_NIC_SERVICE_AUX_ABORT_COORDINATOR:
        return "abort_coordinator";
    case FK_NO_NIC_SERVICE_AUX_EXTERNAL_SOURCE_WINDOW:
        return "external_source_window";
    }
    return "unknown";
}

}  // extern "C"
