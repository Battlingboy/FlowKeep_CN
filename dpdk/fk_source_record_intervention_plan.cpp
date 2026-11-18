#define _POSIX_C_SOURCE 200809L

#include "fk_source_record_intervention_plan.h"

#include <openssl/evp.h>

#include <array>
#include <climits>
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <limits>
#include <sys/stat.h>

namespace {

constexpr std::array<uint8_t, 8u> kPlanMagic{
    'F', 'K', 'S', 'R', 'I', 'N', 'T', '1'};
constexpr std::array<uint8_t, 8u> kLineageMagic{
    'F', 'K', 'P', 'L', 'V', '1', 0u, 0u};
constexpr uint32_t kLineageHeaderBytes = 64u;
constexpr uint32_t kLineageRecordBytes = 48u;
constexpr uint8_t kDevelopmentScope = 1u;

void set_error(char *error, size_t capacity, const char *message) {
    if (error != nullptr && capacity != 0u)
        std::snprintf(error, capacity, "%s", message == nullptr ? "" : message);
}

uint16_t le16(const uint8_t *value) {
    return static_cast<uint16_t>(value[0]) |
        static_cast<uint16_t>(value[1]) << 8u;
}

uint32_t le32(const uint8_t *value) {
    return static_cast<uint32_t>(value[0]) |
        static_cast<uint32_t>(value[1]) << 8u |
        static_cast<uint32_t>(value[2]) << 16u |
        static_cast<uint32_t>(value[3]) << 24u;
}

uint64_t le64(const uint8_t *value) {
    uint64_t result = 0u;
    for (unsigned index = 0u; index < 8u; ++index)
        result |= static_cast<uint64_t>(value[index]) << (index * 8u);
    return result;
}

bool all_zero(const uint8_t *value, size_t count) {
    if (value == nullptr)
        return false;
    for (size_t index = 0u; index < count; ++index) {
        if (value[index] != 0u)
            return false;
    }
    return true;
}

bool exact_file_size(FILE *stream, uint64_t &size) {
    struct stat status{};
    if (stream == nullptr || fstat(fileno(stream), &status) != 0 ||
        !S_ISREG(status.st_mode) || status.st_size < 0) {
        return false;
    }
    size = static_cast<uint64_t>(status.st_size);
    return true;
}

bool sha256_file(
        const char *path,
        uint8_t output[FK_SOURCE_RECORD_INTERVENTION_SHA256_BYTES],
        uint64_t &file_bytes) {
    if (path == nullptr || output == nullptr)
        return false;
    FILE *stream = std::fopen(path, "rb");
    if (stream == nullptr || !exact_file_size(stream, file_bytes)) {
        if (stream != nullptr)
            (void)std::fclose(stream);
        return false;
    }
    EVP_MD_CTX *context = EVP_MD_CTX_new();
    if (context == nullptr) {
        (void)std::fclose(stream);
        return false;
    }
    std::array<uint8_t, 1u << 16u> buffer{};
    bool valid = EVP_DigestInit_ex(context, EVP_sha256(), nullptr) == 1;
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
    unsigned digest_bytes = 0u;
    valid = valid && EVP_DigestFinal_ex(
        context, output, &digest_bytes) == 1 &&
        digest_bytes == FK_SOURCE_RECORD_INTERVENTION_SHA256_BYTES;
    EVP_MD_CTX_free(context);
    return std::fclose(stream) == 0 && valid;
}

bool read_exact(FILE *stream, void *output, size_t count) {
    return stream != nullptr && output != nullptr &&
        std::fread(output, 1u, count, stream) == count;
}

void decode_key(
        const uint8_t low_addr[16],
        const uint8_t high_addr[16],
        uint16_t low_port,
        uint16_t high_port,
        uint8_t ip_version,
        uint8_t protocol,
        fk_flow_key &key) {
    key = {};
    key.ip_version = ip_version;
    key.protocol = protocol;
    std::memcpy(key.low_addr, low_addr, sizeof(key.low_addr));
    std::memcpy(key.high_addr, high_addr, sizeof(key.high_addr));
    key.low_port = low_port;
    key.high_port = high_port;
}

bool canonical_key_valid(
        const fk_flow_key &key,
        uint64_t logical_connection_id) {
    if ((key.ip_version != 4u && key.ip_version != 6u) ||
        (key.protocol != 6u && key.protocol != 17u) ||
        (key.protocol == 6u && logical_connection_id != 0u)) {
        return false;
    }
    const size_t address_bytes = key.ip_version == 4u ? 4u : 16u;
    if (key.ip_version == 4u &&
        (!all_zero(key.low_addr + 4u, 12u) ||
         !all_zero(key.high_addr + 4u, 12u))) {
        return false;
    }
    const int address_order = std::memcmp(
        key.low_addr, key.high_addr, address_bytes);
    return address_order < 0 ||
        (address_order == 0 && key.low_port <= key.high_port);
}

bool decoded_intervention_valid(
        const fk_compact_checkpoint_intervention_v1 &value,
        const fk_source_record_intervention_plan_receipt_v1 &receipt) {
    const bool checkpoint_valid = value.checkpoint_packet == 4u ||
        value.checkpoint_packet == 8u || value.checkpoint_packet == 12u ||
        value.checkpoint_packet == 20u;
    bool valid = value.enabled == 1u &&
        value.abi_version ==
            FK_COMPACT_CHECKPOINT_INTERVENTION_ABI_VERSION &&
        value.record_bytes == sizeof(value) &&
        canonical_key_valid(
            value.candidate_key, value.logical_connection_id) &&
        value.flow_first_timestamp_ns != 0u &&
        value.observation_timestamp_ns >= value.flow_first_timestamp_ns &&
        value.flow_generation != 0u && checkpoint_valid &&
        value.expected_previous_mask <= FK_COMPONENT_FULL &&
        value.expected_behavior_requested_mask <= FK_COMPONENT_FULL &&
        value.expected_behavior_final_mask <= FK_COMPONENT_FULL &&
        value.forced_requested_mask <= FK_COMPONENT_FULL &&
        value.expected_behavior_requested_mask !=
            value.expected_previous_mask &&
        value.expected_behavior_final_mask != value.expected_previous_mask &&
        (value.expected_behavior_final_mask &
             ~value.expected_behavior_requested_mask) == 0u &&
        value.forced_requested_mask == value.expected_previous_mask &&
        value.mode == FK_COMPACT_CHECKPOINT_INTERVENTION_KEEP_EXISTING &&
        receipt.source_segment_count != 0u &&
        receipt.source_segment_index < receipt.source_segment_count;
    for (uint32_t index = 0u; index < value.victim_count; ++index) {
        const auto &victim = value.victims[index];
        valid = valid && canonical_key_valid(
                victim.key, victim.logical_connection_id) &&
            victim.flow_first_timestamp_ns != 0u &&
            victim.flow_generation != 0u &&
            victim.expected_previous_mask <= FK_COMPONENT_FULL &&
            victim.expected_behavior_final_mask <= FK_COMPONENT_FULL &&
            victim.expected_intervention_final_mask <= FK_COMPONENT_FULL &&
            victim.expected_behavior_final_mask !=
                victim.expected_previous_mask &&
            (victim.expected_behavior_final_mask &
                 ~victim.expected_previous_mask) == 0u &&
            victim.expected_intervention_final_mask ==
                victim.expected_previous_mask &&
            !(victim.flow_index == value.flow_index &&
              victim.flow_generation == value.flow_generation);
        for (uint32_t prior = 0u; prior < index; ++prior) {
            valid = valid &&
                !(victim.flow_index == value.victims[prior].flow_index &&
                  victim.flow_generation ==
                      value.victims[prior].flow_generation);
        }
    }
    return valid;
}

bool decode_plan(
        const uint8_t *bytes,
        size_t byte_count,
        const uint8_t observed_pcap_sha256[32],
        uint64_t observed_pcap_packet_count,
        fk_compact_checkpoint_intervention_v1 &intervention,
        fk_source_record_intervention_plan_receipt_v1 &receipt) {
    if (bytes == nullptr || byte_count <
            FK_SOURCE_RECORD_INTERVENTION_PLAN_HEADER_BYTES ||
        std::memcmp(bytes, kPlanMagic.data(), kPlanMagic.size()) != 0 ||
        le32(bytes + 8u) != FK_SOURCE_RECORD_INTERVENTION_PLAN_ABI_VERSION ||
        le32(bytes + 12u) !=
            FK_SOURCE_RECORD_INTERVENTION_PLAN_HEADER_BYTES ||
        le32(bytes + 16u) !=
            FK_SOURCE_RECORD_INTERVENTION_PLAN_VICTIM_BYTES) {
        return false;
    }
    const uint32_t victim_count = le32(bytes + 20u);
    const uint64_t expected_bytes =
        FK_SOURCE_RECORD_INTERVENTION_PLAN_HEADER_BYTES +
        static_cast<uint64_t>(victim_count) *
            FK_SOURCE_RECORD_INTERVENTION_PLAN_VICTIM_BYTES;
    if (victim_count == 0u || victim_count >
            FK_COMPACT_CHECKPOINT_INTERVENTION_MAX_VICTIMS ||
        expected_bytes != byte_count ||
        le64(bytes + 24u) != expected_bytes ||
        bytes[147u] != kDevelopmentScope ||
        bytes[148u] != 0u || bytes[149u] != 0u ||
        bytes[150u] != 0u || bytes[151u] != 0u ||
        bytes[152u] != 1u || bytes[153u] != 1u ||
        bytes[154u] != 1u || bytes[155u] != 0u ||
        !all_zero(bytes + 156u, 4u) ||
        !all_zero(bytes + 288u, 32u) ||
        std::memcmp(bytes + 160u, observed_pcap_sha256, 32u) != 0) {
        return false;
    }
    const uint64_t source_packet_sequence = le64(bytes + 32u);
    if (source_packet_sequence >= observed_pcap_packet_count)
        return false;

    intervention = {};
    intervention.abi_version =
        FK_COMPACT_CHECKPOINT_INTERVENTION_ABI_VERSION;
    intervention.record_bytes = sizeof(intervention);
    intervention.source_packet_sequence = source_packet_sequence;
    decode_key(
        bytes + 80u, bytes + 96u, le16(bytes + 136u),
        le16(bytes + 138u), bytes[140u], bytes[141u],
        intervention.candidate_key);
    intervention.logical_connection_id = le64(bytes + 72u);
    intervention.flow_first_timestamp_ns = le64(bytes + 64u);
    intervention.observation_timestamp_ns = le64(bytes + 56u);
    intervention.flow_index = le32(bytes + 112u);
    intervention.flow_generation = le32(bytes + 116u);
    intervention.checkpoint_packet = le32(bytes + 120u);
    intervention.victim_count = victim_count;
    intervention.expected_previous_mask = bytes[142u];
    intervention.expected_behavior_requested_mask = bytes[143u];
    intervention.expected_behavior_final_mask = bytes[144u];
    intervention.forced_requested_mask = bytes[145u];
    intervention.mode = bytes[146u];
    intervention.enabled = 1u;

    for (uint32_t index = 0u; index < victim_count; ++index) {
        const uint8_t *raw = bytes +
            FK_SOURCE_RECORD_INTERVENTION_PLAN_HEADER_BYTES +
            static_cast<size_t>(index) *
                FK_SOURCE_RECORD_INTERVENTION_PLAN_VICTIM_BYTES;
        if (!all_zero(raw + 65u, 15u))
            return false;
        auto &victim = intervention.victims[index];
        decode_key(
            raw, raw + 16u, le16(raw + 56u), le16(raw + 58u),
            raw[60u], raw[61u], victim.key);
        victim.logical_connection_id = le64(raw + 32u);
        victim.flow_first_timestamp_ns = le64(raw + 40u);
        victim.flow_index = le32(raw + 48u);
        victim.flow_generation = le32(raw + 52u);
        victim.expected_previous_mask = raw[62u];
        victim.expected_behavior_final_mask = raw[63u];
        victim.expected_intervention_final_mask = raw[64u];
    }

    receipt.source_packet_sequence = source_packet_sequence;
    receipt.source_record_sequence = le64(bytes + 40u);
    receipt.source_timestamp_ns = le64(bytes + 48u);
    receipt.output_timestamp_ns = le64(bytes + 56u);
    receipt.source_index = le32(bytes + 124u);
    receipt.source_segment_index = le32(bytes + 128u);
    receipt.source_segment_count = le32(bytes + 132u);
    receipt.victim_count = victim_count;
    std::memcpy(receipt.pcap_sha256, bytes + 160u, 32u);
    std::memcpy(receipt.packet_lineage_sha256, bytes + 192u, 32u);
    std::memcpy(receipt.checkpoint_sidecar_sha256, bytes + 224u, 32u);
    std::memcpy(receipt.conflict_id_sha256, bytes + 256u, 32u);
    receipt.development_scope = 1u;
    receipt.official_test_accessed = 0u;
    receipt.primary_validation_accessed = 0u;
    receipt.offline_event_bag_used = 0u;
    receipt.global_optimal_closed_loop_claimed = 0u;
    receipt.independent_process_required = 1u;
    receipt.controlled_one_step_intervention = 1u;
    receipt.pcap_sha256_match = 1u;
    return decoded_intervention_valid(intervention, receipt);
}

bool validate_lineage(
        const char *path,
        const fk_source_record_intervention_plan_receipt_v1 &plan,
        fk_source_record_intervention_plan_receipt_v1 &receipt) {
    FILE *stream = std::fopen(path, "rb");
    if (stream == nullptr)
        return false;
    uint64_t size = 0u;
    std::array<uint8_t, kLineageHeaderBytes> header{};
    bool valid = exact_file_size(stream, size) &&
        read_exact(stream, header.data(), header.size()) &&
        std::memcmp(header.data(), kLineageMagic.data(), kLineageMagic.size()) == 0 &&
        le32(header.data() + 8u) == 1u &&
        le32(header.data() + 12u) == kLineageHeaderBytes &&
        le32(header.data() + 16u) == kLineageRecordBytes &&
        le32(header.data() + 20u) == 0u;
    const uint64_t records = valid ? le64(header.data() + 24u) : 0u;
    valid = valid && records <=
        (std::numeric_limits<uint64_t>::max() - kLineageHeaderBytes) /
            kLineageRecordBytes &&
        size == kLineageHeaderBytes + records * kLineageRecordBytes &&
        plan.source_packet_sequence < records;
    const uint64_t offset = kLineageHeaderBytes +
        plan.source_packet_sequence * kLineageRecordBytes;
    valid = valid && offset <= static_cast<uint64_t>(LONG_MAX) &&
        std::fseek(stream, static_cast<long>(offset), SEEK_SET) == 0;
    std::array<uint8_t, kLineageRecordBytes> record{};
    valid = valid && read_exact(stream, record.data(), record.size());
    valid = valid && le64(record.data()) == plan.source_packet_sequence &&
        le32(record.data() + 8u) == plan.source_index &&
        le64(record.data() + 12u) == plan.source_record_sequence &&
        le32(record.data() + 20u) == plan.source_segment_index &&
        le32(record.data() + 24u) == plan.source_segment_count &&
        le64(record.data() + 28u) == plan.source_timestamp_ns &&
        le64(record.data() + 36u) == plan.output_timestamp_ns &&
        le32(record.data() + 44u) == 0u &&
        plan.source_segment_count != 0u &&
        plan.source_segment_index < plan.source_segment_count;
    const bool closed = std::fclose(stream) == 0;
    receipt.packet_lineage_file_bytes = size;
    receipt.packet_lineage_record_count = records;
    receipt.packet_lineage_exact_match = valid && closed ? 1u : 0u;
    return valid && closed;
}

}  // namespace

extern "C" bool fk_source_record_intervention_plan_load(
        const char *plan_path,
        const char *packet_lineage_path,
        const uint8_t observed_pcap_sha256[32],
        uint64_t observed_pcap_packet_count,
        fk_compact_checkpoint_intervention_v1 *intervention,
        fk_source_record_intervention_plan_receipt_v1 *receipt,
        char *error,
        size_t error_capacity) {
    set_error(error, error_capacity, "");
    if (plan_path == nullptr || packet_lineage_path == nullptr ||
        observed_pcap_sha256 == nullptr || observed_pcap_packet_count == 0u ||
        intervention == nullptr || receipt == nullptr) {
        set_error(error, error_capacity, "invalid source-record plan arguments");
        return false;
    }
    *intervention = {};
    *receipt = {};
    receipt->abi_version = FK_SOURCE_RECORD_INTERVENTION_PLAN_ABI_VERSION;
    receipt->record_bytes = sizeof(*receipt);
    uint64_t plan_size = 0u;
    if (!sha256_file(
            plan_path, receipt->plan_sha256, plan_size) ||
        plan_size < FK_SOURCE_RECORD_INTERVENTION_PLAN_HEADER_BYTES ||
        plan_size > FK_SOURCE_RECORD_INTERVENTION_PLAN_HEADER_BYTES +
            FK_COMPACT_CHECKPOINT_INTERVENTION_MAX_VICTIMS *
                FK_SOURCE_RECORD_INTERVENTION_PLAN_VICTIM_BYTES) {
        set_error(error, error_capacity, "source-record plan hash/size failed");
        return false;
    }
    receipt->plan_file_bytes = plan_size;
    std::array<uint8_t,
        FK_SOURCE_RECORD_INTERVENTION_PLAN_HEADER_BYTES +
        FK_COMPACT_CHECKPOINT_INTERVENTION_MAX_VICTIMS *
            FK_SOURCE_RECORD_INTERVENTION_PLAN_VICTIM_BYTES> bytes{};
    FILE *plan_stream = std::fopen(plan_path, "rb");
    const bool plan_read = plan_stream != nullptr &&
        read_exact(plan_stream, bytes.data(), static_cast<size_t>(plan_size)) &&
        std::fgetc(plan_stream) == EOF && std::feof(plan_stream) != 0 &&
        std::ferror(plan_stream) == 0;
    const bool plan_closed = plan_stream != nullptr &&
        std::fclose(plan_stream) == 0;
    if (!plan_read || !plan_closed || !decode_plan(
            bytes.data(), static_cast<size_t>(plan_size),
            observed_pcap_sha256, observed_pcap_packet_count,
            *intervention, *receipt)) {
        *intervention = {};
        set_error(error, error_capacity, "source-record plan ABI/content failed");
        return false;
    }
    uint64_t lineage_size = 0u;
    uint8_t lineage_sha[32]{};
    if (!sha256_file(packet_lineage_path, lineage_sha, lineage_size) ||
        std::memcmp(
            lineage_sha, receipt->packet_lineage_sha256, 32u) != 0 ||
        !validate_lineage(packet_lineage_path, *receipt, *receipt)) {
        *intervention = {};
        set_error(error, error_capacity, "source-record FKPLV1 binding failed");
        return false;
    }
    receipt->packet_lineage_file_bytes = lineage_size;
    receipt->complete = 1u;
    return true;
}
