#include "fk_formal_run_contract.h"

#include <array>
#include <cerrno>
#include <cmath>
#include <cstdio>
#include <cstring>
#include <fcntl.h>
#include <openssl/evp.h>
#include <sys/stat.h>
#include <unistd.h>

namespace {

constexpr uint8_t kMagic[8] = {'F', 'K', 'R', 'C', 'V', '1', '\0', '\0'};

static void set_error(char *error, size_t capacity, const char *message) {
    if (error != nullptr && capacity != 0u)
        std::snprintf(error, capacity, "%s", message);
}

static uint32_t get_u32(const uint8_t *input) {
    uint32_t value = 0u;
    for (uint32_t index = 0u; index < 4u; ++index)
        value |= static_cast<uint32_t>(input[index]) << (index * 8u);
    return value;
}

static uint64_t get_u64(const uint8_t *input) {
    uint64_t value = 0u;
    for (uint32_t index = 0u; index < 8u; ++index)
        value |= static_cast<uint64_t>(input[index]) << (index * 8u);
    return value;
}

static void put_u32(uint8_t *output, uint32_t value) {
    for (uint32_t index = 0u; index < 4u; ++index)
        output[index] = static_cast<uint8_t>(value >> (index * 8u));
}

static void put_u64(uint8_t *output, uint64_t value) {
    for (uint32_t index = 0u; index < 8u; ++index)
        output[index] = static_cast<uint8_t>(value >> (index * 8u));
}

static uint8_t hex_nibble(char value) {
    if (value >= '0' && value <= '9')
        return static_cast<uint8_t>(value - '0');
    if (value >= 'a' && value <= 'f')
        return static_cast<uint8_t>(value - 'a' + 10);
    return UINT8_MAX;
}

static bool parse_expected_digest(const char *text, uint8_t output[32]) {
    if (text == nullptr || std::strlen(text) != 64u)
        return false;
    for (size_t index = 0u; index < 32u; ++index) {
        const uint8_t high = hex_nibble(text[index * 2u]);
        const uint8_t low = hex_nibble(text[index * 2u + 1u]);
        if (high == UINT8_MAX || low == UINT8_MAX)
            return false;
        output[index] = static_cast<uint8_t>((high << 4u) | low);
    }
    return true;
}

static bool any_nonzero(const uint8_t *data, size_t bytes) {
    uint8_t value = 0u;
    for (size_t index = 0u; index < bytes; ++index)
        value = static_cast<uint8_t>(value | data[index]);
    return value != 0u;
}

static bool all_zero(const uint8_t *data, size_t bytes) {
    return !any_nonzero(data, bytes);
}

static bool read_exact_contract(
        const char *path,
        std::array<uint8_t, FK_FORMAL_RUN_CONTRACT_BYTES> &bytes) {
    const int descriptor = ::open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (descriptor < 0)
        return false;
    struct stat status{};
    bool valid = ::fstat(descriptor, &status) == 0 &&
        S_ISREG(status.st_mode) &&
        status.st_size == static_cast<off_t>(bytes.size());
    size_t offset = 0u;
    while (valid && offset < bytes.size()) {
        const ssize_t result = ::read(
            descriptor, bytes.data() + offset, bytes.size() - offset);
        if (result > 0) {
            offset += static_cast<size_t>(result);
        } else if (result < 0 && errno == EINTR) {
            continue;
        } else {
            valid = false;
        }
    }
    uint8_t extra = 0u;
    if (valid && ::read(descriptor, &extra, 1u) != 0)
        valid = false;
    if (::close(descriptor) != 0)
        valid = false;
    return valid && offset == bytes.size();
}

static bool digest_bytes(
        const uint8_t *data, size_t bytes, uint8_t output[32]) {
    unsigned int output_bytes = 0u;
    return EVP_Digest(
        data, bytes, output, &output_bytes, EVP_sha256(), nullptr) == 1 &&
        output_bytes == 32u;
}

}  // namespace

extern "C" {

bool fk_formal_run_contract_encode(
        const fk_event_result_log_header_binding *header,
        uint8_t output[FK_FORMAL_RUN_CONTRACT_BYTES],
        char *error,
        size_t error_capacity) {
    set_error(error, error_capacity, "");
    if (header == nullptr || output == nullptr) {
        set_error(error, error_capacity, "missing FKRCV1 header/output");
        return false;
    }
    float threshold = 0.0f;
    std::memcpy(&threshold, &header->decision_threshold_bits, 4u);
    const bool valid =
        any_nonzero(header->run_uuid, 16u) &&
        any_nonzero(header->capture_sha256, 32u) &&
        any_nonzero(header->sidecar_records_sha256, 32u) &&
        any_nonzero(header->model_sha256, 32u) &&
        any_nonzero(header->manifest_sha256, 32u) &&
        any_nonzero(header->feature_schema_sha256, 32u) &&
        any_nonzero(header->config_sha256, 32u) &&
        all_zero(header->run_contract_sha256, 32u) &&
        std::isfinite(threshold) && threshold >= 0.0f && threshold <= 1.0f &&
        (header->route_worker_count == 2u ||
         header->route_worker_count == 4u ||
         header->route_worker_count == 8u) &&
        header->window_ns != 0u && header->stride_ns != 0u &&
        header->stride_ns <= header->window_ns &&
        header->capture_first_timestamp_ns <=
            header->capture_last_timestamp_ns;
    if (!valid) {
        set_error(error, error_capacity, "invalid FKRCV1 source header");
        return false;
    }
    std::memset(output, 0, FK_FORMAL_RUN_CONTRACT_BYTES);
    std::memcpy(output, kMagic, sizeof(kMagic));
    put_u32(output + 8u, FK_FORMAL_RUN_CONTRACT_VERSION);
    put_u32(output + 12u, FK_FORMAL_RUN_CONTRACT_BYTES);
    put_u32(output + 16u, FK_FORMAL_RUN_CONTRACT_ENDIAN_TAG);
    put_u32(output + 20u, FK_FORMAL_RUN_CONTRACT_FORMAL_DATACON);
    std::memcpy(output + 24u, header->run_uuid, 16u);
    std::memcpy(output + 40u, header->capture_sha256, 32u);
    std::memcpy(output + 72u, header->sidecar_records_sha256, 32u);
    std::memcpy(output + 104u, header->model_sha256, 32u);
    std::memcpy(output + 136u, header->manifest_sha256, 32u);
    std::memcpy(output + 168u, header->feature_schema_sha256, 32u);
    std::memcpy(output + 200u, header->config_sha256, 32u);
    put_u32(output + 232u, header->decision_threshold_bits);
    put_u32(output + 236u, header->route_worker_count);
    put_u64(output + 240u, header->window_ns);
    put_u64(output + 248u, header->stride_ns);
    put_u64(output + 256u, header->capture_first_timestamp_ns);
    put_u64(output + 264u, header->capture_last_timestamp_ns);
    return true;
}

bool fk_formal_run_contract_load(
        const char *path,
        const char *expected_file_sha256,
        fk_formal_run_contract *contract,
        char *error,
        size_t error_capacity) {
    set_error(error, error_capacity, "");
    if (path == nullptr || path[0] == '\0' || contract == nullptr) {
        set_error(error, error_capacity, "missing formal run contract");
        return false;
    }
    uint8_t expected[32]{};
    if (!parse_expected_digest(expected_file_sha256, expected)) {
        set_error(error, error_capacity, "invalid formal contract SHA-256");
        return false;
    }
    std::array<uint8_t, FK_FORMAL_RUN_CONTRACT_BYTES> bytes{};
    if (!read_exact_contract(path, bytes)) {
        set_error(error, error_capacity, "cannot read exact FKRCV1 contract");
        return false;
    }
    uint8_t observed[32]{};
    if (!digest_bytes(bytes.data(), bytes.size(), observed) ||
        std::memcmp(observed, expected, sizeof(observed)) != 0) {
        set_error(error, error_capacity, "formal contract SHA-256 mismatch");
        return false;
    }
    if (std::memcmp(bytes.data(), kMagic, sizeof(kMagic)) != 0 ||
        get_u32(bytes.data() + 8u) != FK_FORMAL_RUN_CONTRACT_VERSION ||
        get_u32(bytes.data() + 12u) != FK_FORMAL_RUN_CONTRACT_BYTES ||
        get_u32(bytes.data() + 16u) != FK_FORMAL_RUN_CONTRACT_ENDIAN_TAG ||
        get_u32(bytes.data() + 20u) !=
            FK_FORMAL_RUN_CONTRACT_FORMAL_DATACON ||
        !all_zero(bytes.data() + 272u, bytes.size() - 272u)) {
        set_error(error, error_capacity, "invalid FKRCV1 envelope");
        return false;
    }
    fk_formal_run_contract parsed{};
    std::memcpy(parsed.header.run_uuid, bytes.data() + 24u, 16u);
    std::memcpy(parsed.header.capture_sha256, bytes.data() + 40u, 32u);
    std::memcpy(
        parsed.header.sidecar_records_sha256, bytes.data() + 72u, 32u);
    std::memcpy(parsed.header.model_sha256, bytes.data() + 104u, 32u);
    std::memcpy(parsed.header.manifest_sha256, bytes.data() + 136u, 32u);
    std::memcpy(
        parsed.header.feature_schema_sha256, bytes.data() + 168u, 32u);
    std::memcpy(parsed.header.config_sha256, bytes.data() + 200u, 32u);
    parsed.header.decision_threshold_bits = get_u32(bytes.data() + 232u);
    const uint32_t workers = get_u32(bytes.data() + 236u);
    parsed.header.window_ns = get_u64(bytes.data() + 240u);
    parsed.header.stride_ns = get_u64(bytes.data() + 248u);
    parsed.header.capture_first_timestamp_ns = get_u64(bytes.data() + 256u);
    parsed.header.capture_last_timestamp_ns = get_u64(bytes.data() + 264u);
    if (workers > UINT16_MAX) {
        set_error(error, error_capacity, "invalid FKRCV1 worker count");
        return false;
    }
    parsed.header.route_worker_count = static_cast<uint16_t>(workers);
    float threshold = 0.0f;
    std::memcpy(&threshold, &parsed.header.decision_threshold_bits, 4u);
    const bool valid =
        any_nonzero(parsed.header.run_uuid, 16u) &&
        any_nonzero(parsed.header.capture_sha256, 32u) &&
        any_nonzero(parsed.header.sidecar_records_sha256, 32u) &&
        any_nonzero(parsed.header.model_sha256, 32u) &&
        any_nonzero(parsed.header.manifest_sha256, 32u) &&
        any_nonzero(parsed.header.feature_schema_sha256, 32u) &&
        any_nonzero(parsed.header.config_sha256, 32u) &&
        std::isfinite(threshold) && threshold >= 0.0f && threshold <= 1.0f &&
        (workers == 2u || workers == 4u || workers == 8u) &&
        parsed.header.window_ns != 0u && parsed.header.stride_ns != 0u &&
        parsed.header.stride_ns <= parsed.header.window_ns &&
        parsed.header.capture_first_timestamp_ns <=
            parsed.header.capture_last_timestamp_ns;
    if (!valid) {
        set_error(error, error_capacity, "invalid FKRCV1 field contract");
        return false;
    }
    std::memcpy(parsed.file_sha256, observed, sizeof(observed));
    *contract = parsed;
    return true;
}

bool fk_formal_run_contract_matches_header(
        const fk_formal_run_contract *contract,
        const fk_event_result_log_header_binding *header,
        char *error,
        size_t error_capacity) {
    set_error(error, error_capacity, "");
    if (contract == nullptr || header == nullptr) {
        set_error(error, error_capacity, "missing formal contract/header");
        return false;
    }
#define FK_MATCH_FIELD(field) \
    if (std::memcmp(&contract->header.field, &header->field, \
                    sizeof(header->field)) != 0) { \
        set_error(error, error_capacity, \
                  "formal run contract field mismatch: " #field); \
        return false; \
    }
    FK_MATCH_FIELD(run_uuid)
    FK_MATCH_FIELD(capture_sha256)
    FK_MATCH_FIELD(sidecar_records_sha256)
    FK_MATCH_FIELD(model_sha256)
    FK_MATCH_FIELD(manifest_sha256)
    FK_MATCH_FIELD(feature_schema_sha256)
    FK_MATCH_FIELD(config_sha256)
    FK_MATCH_FIELD(decision_threshold_bits)
    FK_MATCH_FIELD(window_ns)
    FK_MATCH_FIELD(stride_ns)
    FK_MATCH_FIELD(capture_first_timestamp_ns)
    FK_MATCH_FIELD(capture_last_timestamp_ns)
    FK_MATCH_FIELD(route_worker_count)
#undef FK_MATCH_FIELD
    return true;
}

}  // extern "C"
