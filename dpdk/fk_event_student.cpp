#include "fk_event_student.h"

#include <openssl/evp.h>

#include <algorithm>
#include <array>
#include <cerrno>
#include <cmath>
#include <cstdio>
#include <cstring>
#include <limits>
#include <new>
#include <string>
#include <vector>

namespace {

constexpr std::size_t kHeaderBytes = 256u;
constexpr uint32_t kEndianTag = 0x01020304u;
constexpr uint32_t kRequiredFlags = 1u;
constexpr float kLayerNormEpsilon = 1.0e-5f;
constexpr uint32_t kMaximumParameterFloats = 8u * 1024u * 1024u;
constexpr char kMagic[8] = {'F', 'K', 'E', 'S', 'V', '1', '\0', '\0'};
constexpr char kArchitectureContract[] =
    "flowkeep.strict_causal_event_student.v1;continuous=119;input=159;"
    "ja4_fields=10;ja4_tables=2;vocab=4097;normalizer=clamp10;"
    "encoder=linear-ln-gelu-linear-gelu;"
    "identity=embedding-projection-gelu;fusion=linear-ln-gelu;"
    "flow_pool=attention;window_head=linear-gelu-linear;"
    "event_pool=causal_attention;event_head=ln-linear-gelu-linear;"
    "gelu=erf;ln_eps=1e-5";

struct ParameterView {
    const float *mean = nullptr;
    const float *scale = nullptr;
    const float *encoder_one_weight = nullptr;
    const float *encoder_one_bias = nullptr;
    const float *encoder_norm_weight = nullptr;
    const float *encoder_norm_bias = nullptr;
    const float *encoder_two_weight = nullptr;
    const float *encoder_two_bias = nullptr;
    const float *identity_embeddings = nullptr;
    const float *identity_projection_weight = nullptr;
    const float *identity_projection_bias = nullptr;
    const float *fusion_weight = nullptr;
    const float *fusion_bias = nullptr;
    const float *fusion_norm_weight = nullptr;
    const float *fusion_norm_bias = nullptr;
    const float *flow_attention_weight = nullptr;
    const float *flow_attention_bias = nullptr;
    const float *window_one_weight = nullptr;
    const float *window_one_bias = nullptr;
    const float *window_two_weight = nullptr;
    const float *window_two_bias = nullptr;
    const float *event_attention_weight = nullptr;
    const float *event_attention_bias = nullptr;
    const float *event_norm_weight = nullptr;
    const float *event_norm_bias = nullptr;
    const float *event_one_weight = nullptr;
    const float *event_one_bias = nullptr;
    const float *event_two_weight = nullptr;
    const float *event_two_bias = nullptr;
};

struct EventStudent {
    fk_event_student_metadata metadata{};
    std::vector<float> parameters;
    ParameterView view;
};

static EventStudent *implementation(fk_event_student *model) {
    return reinterpret_cast<EventStudent *>(model);
}

static const EventStudent *implementation(const fk_event_student *model) {
    return reinterpret_cast<const EventStudent *>(model);
}

static void set_error(
        char *error,
        std::size_t capacity,
        const std::string &message) {
    if (error == nullptr || capacity == 0u)
        return;
    std::snprintf(error, capacity, "%s", message.c_str());
}

static uint32_t read_u32(const uint8_t *bytes) {
    return static_cast<uint32_t>(bytes[0]) |
        (static_cast<uint32_t>(bytes[1]) << 8u) |
        (static_cast<uint32_t>(bytes[2]) << 16u) |
        (static_cast<uint32_t>(bytes[3]) << 24u);
}

static uint64_t read_u64(const uint8_t *bytes) {
    return static_cast<uint64_t>(read_u32(bytes)) |
        (static_cast<uint64_t>(read_u32(bytes + 4u)) << 32u);
}

static float read_f32(const uint8_t *bytes) {
    const uint32_t bits = read_u32(bytes);
    float result = 0.0f;
    static_assert(sizeof(result) == sizeof(bits), "float32 is required");
    std::memcpy(&result, &bits, sizeof(result));
    return result;
}

static bool valid_hex_digest(const char *digest) {
    if (digest == nullptr ||
        std::strlen(digest) != FK_EVENT_STUDENT_SHA256_CHARS)
        return false;
    for (std::size_t index = 0u;
         index < FK_EVENT_STUDENT_SHA256_CHARS; ++index) {
        const char value = digest[index];
        if (!((value >= '0' && value <= '9') ||
              (value >= 'a' && value <= 'f')))
            return false;
    }
    return true;
}

static void digest_to_hex(
        const uint8_t digest[32],
        char output[FK_EVENT_STUDENT_SHA256_CHARS + 1u]) {
    constexpr char alphabet[] = "0123456789abcdef";
    for (std::size_t index = 0u; index < 32u; ++index) {
        output[index * 2u] = alphabet[digest[index] >> 4u];
        output[index * 2u + 1u] = alphabet[digest[index] & 15u];
    }
    output[FK_EVENT_STUDENT_SHA256_CHARS] = '\0';
}

static bool sha256(
        const uint8_t *bytes,
        std::size_t size,
        uint8_t output[32]) {
    EVP_MD_CTX *context = EVP_MD_CTX_new();
    if (context == nullptr)
        return false;
    unsigned int output_size = 0u;
    const bool valid =
        EVP_DigestInit_ex(context, EVP_sha256(), nullptr) == 1 &&
        EVP_DigestUpdate(context, bytes, size) == 1 &&
        EVP_DigestFinal_ex(context, output, &output_size) == 1 &&
        output_size == 32u;
    EVP_MD_CTX_free(context);
    return valid;
}

static bool digest_equals_hex(const uint8_t digest[32], const char *hex) {
    char observed[FK_EVENT_STUDENT_SHA256_CHARS + 1u];
    digest_to_hex(digest, observed);
    return std::strcmp(observed, hex) == 0;
}

static bool read_file(
        const char *path,
        std::vector<uint8_t> &bytes,
        std::string &reason) {
    FILE *stream = std::fopen(path, "rb");
    if (stream == nullptr) {
        reason = std::string("cannot open model: ") + std::strerror(errno);
        return false;
    }
    bool valid = std::fseek(stream, 0, SEEK_END) == 0;
    const long signed_size = valid ? std::ftell(stream) : -1L;
    valid = valid && signed_size >= 0 &&
        static_cast<unsigned long>(signed_size) <=
            static_cast<unsigned long>(kHeaderBytes) +
            static_cast<unsigned long>(kMaximumParameterFloats) * 4ul;
    valid = valid && std::fseek(stream, 0, SEEK_SET) == 0;
    if (!valid) {
        std::fclose(stream);
        reason = "model file size is invalid";
        return false;
    }
    try {
        bytes.resize(static_cast<std::size_t>(signed_size));
    } catch (const std::bad_alloc &) {
        std::fclose(stream);
        reason = "model file allocation failed";
        return false;
    }
    valid = bytes.empty() ||
        std::fread(bytes.data(), 1u, bytes.size(), stream) == bytes.size();
    valid = valid && std::fgetc(stream) == EOF && !std::ferror(stream);
    std::fclose(stream);
    if (!valid) {
        reason = "model file read failed";
        return false;
    }
    return true;
}

static bool add_count(
        uint64_t &total, uint64_t rows, uint64_t columns = 1u) {
    if (rows != 0u && columns >
        std::numeric_limits<uint64_t>::max() / rows)
        return false;
    const uint64_t amount = rows * columns;
    if (amount > std::numeric_limits<uint64_t>::max() - total)
        return false;
    total += amount;
    return true;
}

static bool expected_parameter_count(
        uint32_t hidden,
        uint32_t embedding,
        uint32_t event_hidden,
        uint32_t &result) {
    uint64_t total = 0u;
    const uint64_t identity_width =
        FK_EVENT_STUDENT_JA4_FIELDS *
        FK_EVENT_STUDENT_JA4_TABLES * embedding;
    const uint64_t fusion_width = hidden * 2u + 1u;
    bool valid =
        add_count(total, FK_EVENT_STUDENT_CONTINUOUS_FEATURES) && /* mean */
        add_count(total, FK_EVENT_STUDENT_CONTINUOUS_FEATURES) && /* scale */
        add_count(total, hidden, FK_EVENT_STUDENT_CONTINUOUS_FEATURES) &&
        add_count(total, hidden) &&
        add_count(total, hidden) && add_count(total, hidden) &&
        add_count(total, hidden, hidden) && add_count(total, hidden) &&
        add_count(
            total,
            FK_EVENT_STUDENT_JA4_FIELDS *
                FK_EVENT_STUDENT_JA4_TABLES *
                FK_EVENT_STUDENT_JA4_VOCABULARY,
            embedding) &&
        add_count(total, hidden, identity_width) &&
        add_count(total, hidden) &&
        add_count(total, hidden, fusion_width) && add_count(total, hidden) &&
        add_count(total, hidden) && add_count(total, hidden) &&
        add_count(total, hidden) && add_count(total, 1u) &&
        add_count(total, hidden, hidden) && add_count(total, hidden) &&
        add_count(total, hidden) && add_count(total, 1u) &&
        add_count(total, hidden) && add_count(total, 1u) &&
        add_count(total, hidden) && add_count(total, hidden) &&
        add_count(total, event_hidden, hidden) &&
        add_count(total, event_hidden) &&
        add_count(total, event_hidden) && add_count(total, 1u);
    if (!valid || total > kMaximumParameterFloats)
        return false;
    result = static_cast<uint32_t>(total);
    return true;
}

static const float *take(
        const std::vector<float> &parameters,
        std::size_t &offset,
        std::size_t count) {
    if (count > parameters.size() - offset)
        return nullptr;
    const float *result = parameters.data() + offset;
    offset += count;
    return result;
}

static bool bind_parameter_view(EventStudent &model) {
    const std::size_t hidden = model.metadata.hidden;
    const std::size_t embedding = model.metadata.identity_embedding;
    const std::size_t event_hidden = model.metadata.event_hidden;
    const std::size_t identity_tables =
        FK_EVENT_STUDENT_JA4_FIELDS * FK_EVENT_STUDENT_JA4_TABLES;
    const std::size_t identity_width = identity_tables * embedding;
    const std::size_t fusion_width = hidden * 2u + 1u;
    std::size_t offset = 0u;
    ParameterView &view = model.view;
#define FK_TAKE(name, count) \
    do { \
        view.name = take(model.parameters, offset, (count)); \
        if (view.name == nullptr) return false; \
    } while (false)
    FK_TAKE(mean, FK_EVENT_STUDENT_CONTINUOUS_FEATURES);
    FK_TAKE(scale, FK_EVENT_STUDENT_CONTINUOUS_FEATURES);
    FK_TAKE(encoder_one_weight,
            hidden * FK_EVENT_STUDENT_CONTINUOUS_FEATURES);
    FK_TAKE(encoder_one_bias, hidden);
    FK_TAKE(encoder_norm_weight, hidden);
    FK_TAKE(encoder_norm_bias, hidden);
    FK_TAKE(encoder_two_weight, hidden * hidden);
    FK_TAKE(encoder_two_bias, hidden);
    FK_TAKE(identity_embeddings,
            identity_tables * FK_EVENT_STUDENT_JA4_VOCABULARY * embedding);
    FK_TAKE(identity_projection_weight, hidden * identity_width);
    FK_TAKE(identity_projection_bias, hidden);
    FK_TAKE(fusion_weight, hidden * fusion_width);
    FK_TAKE(fusion_bias, hidden);
    FK_TAKE(fusion_norm_weight, hidden);
    FK_TAKE(fusion_norm_bias, hidden);
    FK_TAKE(flow_attention_weight, hidden);
    FK_TAKE(flow_attention_bias, 1u);
    FK_TAKE(window_one_weight, hidden * hidden);
    FK_TAKE(window_one_bias, hidden);
    FK_TAKE(window_two_weight, hidden);
    FK_TAKE(window_two_bias, 1u);
    FK_TAKE(event_attention_weight, hidden);
    FK_TAKE(event_attention_bias, 1u);
    FK_TAKE(event_norm_weight, hidden);
    FK_TAKE(event_norm_bias, hidden);
    FK_TAKE(event_one_weight, event_hidden * hidden);
    FK_TAKE(event_one_bias, event_hidden);
    FK_TAKE(event_two_weight, event_hidden);
    FK_TAKE(event_two_bias, 1u);
#undef FK_TAKE
    return offset == model.parameters.size();
}

static float dot(const float *left, const float *right, std::size_t count) {
    float result = 0.0f;
    for (std::size_t index = 0u; index < count; ++index)
        result += left[index] * right[index];
    return result;
}

static void linear(
        const float *input,
        const float *weight,
        const float *bias,
        std::size_t input_size,
        std::size_t output_size,
        float *output) {
    for (std::size_t row = 0u; row < output_size; ++row)
        output[row] = bias[row] +
            dot(weight + row * input_size, input, input_size);
}

static void layer_norm(
        const float *input,
        const float *weight,
        const float *bias,
        std::size_t count,
        float *output) {
    float mean = 0.0f;
    for (std::size_t index = 0u; index < count; ++index)
        mean += input[index];
    mean /= static_cast<float>(count);
    float variance = 0.0f;
    for (std::size_t index = 0u; index < count; ++index) {
        const float delta = input[index] - mean;
        variance += delta * delta;
    }
    variance /= static_cast<float>(count);
    const float inverse = 1.0f / std::sqrt(variance + kLayerNormEpsilon);
    for (std::size_t index = 0u; index < count; ++index)
        output[index] =
            (input[index] - mean) * inverse * weight[index] + bias[index];
}

static float gelu_value(float value) {
    constexpr float inverse_sqrt_two = 0.70710678118654752440f;
    return 0.5f * value *
        (1.0f + std::erf(value * inverse_sqrt_two));
}

static void gelu(float *values, std::size_t count) {
    for (std::size_t index = 0u; index < count; ++index)
        values[index] = gelu_value(values[index]);
}

static uint64_t splitmix64(uint64_t value) {
    value += UINT64_C(0x9e3779b97f4a7c15);
    value = (value ^ (value >> 30u)) * UINT64_C(0xbf58476d1ce4e5b9);
    value = (value ^ (value >> 27u)) * UINT64_C(0x94d049bb133111eb);
    return value ^ (value >> 31u);
}

static uint32_t identity_category(
        uint64_t hash,
        uint32_t field,
        uint32_t table) {
    if (hash == 0u)
        return 0u;
    constexpr uint64_t seeds[2] = {
        UINT64_C(0x243f6a8885a308d3),
        UINT64_C(0x13198a2e03707344),
    };
    const uint64_t salt =
        static_cast<uint64_t>(field) * UINT64_C(0x9e3779b97f4a7c15);
    return 1u + static_cast<uint32_t>(
        splitmix64(hash ^ salt ^ seeds[table]) % 4096u);
}

static bool decode_identity(
        const float *features,
        uint32_t field,
        uint64_t &result) {
    result = 0u;
    const std::size_t base =
        FK_EVENT_STUDENT_CONTINUOUS_FEATURES + field * 4u;
    for (uint32_t limb = 0u; limb < 4u; ++limb) {
        const float value = features[base + limb];
        if (!std::isfinite(value) || value < 0.0f || value > 65535.0f ||
            value != std::floor(value))
            return false;
        result |= static_cast<uint64_t>(value) << (limb * 16u);
    }
    return true;
}

static float window_head(
        const EventStudent &model,
        const float *embedding) {
    std::array<float, FK_EVENT_STUDENT_MAX_HIDDEN> temporary{};
    const std::size_t hidden = model.metadata.hidden;
    linear(
        embedding,
        model.view.window_one_weight,
        model.view.window_one_bias,
        hidden,
        hidden,
        temporary.data());
    gelu(temporary.data(), hidden);
    return model.view.window_two_bias[0] +
        dot(model.view.window_two_weight, temporary.data(), hidden);
}

static float event_head(
        const EventStudent &model,
        const float *embedding) {
    std::array<float, FK_EVENT_STUDENT_MAX_HIDDEN> normalized{};
    std::array<float, FK_EVENT_STUDENT_MAX_HIDDEN> temporary{};
    const std::size_t hidden = model.metadata.hidden;
    const std::size_t event_hidden = model.metadata.event_hidden;
    layer_norm(
        embedding,
        model.view.event_norm_weight,
        model.view.event_norm_bias,
        hidden,
        normalized.data());
    linear(
        normalized.data(),
        model.view.event_one_weight,
        model.view.event_one_bias,
        hidden,
        event_hidden,
        temporary.data());
    gelu(temporary.data(), event_hidden);
    return model.view.event_two_bias[0] +
        dot(model.view.event_two_weight, temporary.data(), event_hidden);
}

static bool add_softmax_item(
        float attention,
        float mask,
        const float *embedding,
        std::size_t hidden,
        float &maximum,
        float &denominator,
        float *weighted_sum,
        uint32_t &valid_count) {
    if (!std::isfinite(attention) || !std::isfinite(mask) || mask < 0.0f)
        return false;
    if (mask == 0.0f)
        return true;
    if (valid_count == std::numeric_limits<uint32_t>::max())
        return false;
    if (valid_count == 0u) {
        maximum = attention;
        denominator = mask;
        for (std::size_t index = 0u; index < hidden; ++index)
            weighted_sum[index] = embedding[index] * mask;
    } else if (attention <= maximum) {
        const float weight = std::exp(attention - maximum) * mask;
        denominator += weight;
        for (std::size_t index = 0u; index < hidden; ++index)
            weighted_sum[index] += embedding[index] * weight;
    } else {
        const float old_scale = std::exp(maximum - attention);
        denominator = denominator * old_scale + mask;
        for (std::size_t index = 0u; index < hidden; ++index)
            weighted_sum[index] =
                weighted_sum[index] * old_scale + embedding[index] * mask;
        maximum = attention;
    }
    ++valid_count;
    return std::isfinite(denominator) && denominator > 0.0f;
}

}  // namespace

extern "C" {

fk_event_student *fk_event_student_load(
        const char *path,
        const fk_event_student_load_config *config,
        char *error,
        std::size_t error_capacity) {
    set_error(error, error_capacity, "");
    if (path == nullptr || path[0] == '\0' || config == nullptr) {
        set_error(error, error_capacity, "model path/config is missing");
        return nullptr;
    }
    if (!valid_hex_digest(config->expected_artifact_sha256) ||
        !valid_hex_digest(config->expected_feature_schema_sha256) ||
        !valid_hex_digest(config->expected_source_state_sha256) ||
        config->expected_hidden == 0u ||
        config->expected_identity_embedding == 0u) {
        set_error(error, error_capacity, "strict expected hashes/dimensions are invalid");
        return nullptr;
    }
    std::vector<uint8_t> bytes;
    std::string reason;
    if (!read_file(path, bytes, reason)) {
        set_error(error, error_capacity, reason);
        return nullptr;
    }
    if (bytes.size() < kHeaderBytes) {
        set_error(error, error_capacity, "model header is truncated");
        return nullptr;
    }
    uint8_t digest[32];
    if (!sha256(bytes.data(), bytes.size(), digest) ||
        !digest_equals_hex(digest, config->expected_artifact_sha256)) {
        set_error(error, error_capacity, "artifact SHA-256 mismatch");
        return nullptr;
    }
    const uint8_t *header = bytes.data();
    const uint32_t version = read_u32(header + 8u);
    const uint32_t endian = read_u32(header + 12u);
    const uint32_t header_bytes = read_u32(header + 16u);
    const uint32_t flags = read_u32(header + 20u);
    const uint64_t payload_bytes = read_u64(header + 24u);
    const uint32_t parameter_floats = read_u32(header + 32u);
    const uint32_t continuous = read_u32(header + 36u);
    const uint32_t input = read_u32(header + 40u);
    const uint32_t fields = read_u32(header + 44u);
    const uint32_t tables = read_u32(header + 48u);
    const uint32_t vocabulary = read_u32(header + 52u);
    const uint32_t hidden = read_u32(header + 56u);
    const uint32_t embedding = read_u32(header + 60u);
    const uint32_t event_hidden = read_u32(header + 64u);
    const uint32_t maximum_flows = read_u32(header + 68u);
    const float epsilon = read_f32(header + 72u);
    const float threshold = read_f32(header + 76u);
    bool valid =
        std::memcmp(header, kMagic, sizeof(kMagic)) == 0 &&
        version == FK_EVENT_STUDENT_FORMAT_VERSION &&
        endian == kEndianTag && header_bytes == kHeaderBytes &&
        flags == kRequiredFlags &&
        continuous == FK_EVENT_STUDENT_CONTINUOUS_FEATURES &&
        input == FK_EVENT_STUDENT_INPUT_FEATURES &&
        fields == FK_EVENT_STUDENT_JA4_FIELDS &&
        tables == FK_EVENT_STUDENT_JA4_TABLES &&
        vocabulary == FK_EVENT_STUDENT_JA4_VOCABULARY &&
        hidden > 0u && hidden <= FK_EVENT_STUDENT_MAX_HIDDEN &&
        embedding > 0u &&
            embedding <= FK_EVENT_STUDENT_MAX_IDENTITY_EMBEDDING &&
        event_hidden == hidden / 2u && event_hidden > 0u &&
        maximum_flows == FK_EVENT_STUDENT_MAX_FLOWS_PER_WINDOW &&
        epsilon == kLayerNormEpsilon &&
        std::isfinite(threshold) && threshold >= 0.0f && threshold <= 1.0f &&
        hidden == config->expected_hidden &&
        embedding == config->expected_identity_embedding &&
        payload_bytes == static_cast<uint64_t>(parameter_floats) * 4u &&
        payload_bytes == bytes.size() - kHeaderBytes;
    uint32_t expected_floats = 0u;
    valid = valid && expected_parameter_count(
        hidden, embedding, event_hidden, expected_floats) &&
        parameter_floats == expected_floats;
    for (std::size_t index = 208u; valid && index < kHeaderBytes; ++index)
        valid = header[index] == 0u;
    if (!valid) {
        set_error(error, error_capacity, "artifact ABI/dimensions are invalid");
        return nullptr;
    }
    uint8_t expected_architecture[32];
    if (!sha256(
            reinterpret_cast<const uint8_t *>(kArchitectureContract),
            sizeof(kArchitectureContract) - 1u,
            expected_architecture) ||
        std::memcmp(header + 112u, expected_architecture, 32u) != 0) {
        set_error(error, error_capacity, "architecture SHA-256 mismatch");
        return nullptr;
    }
    if (!digest_equals_hex(header + 80u,
            config->expected_feature_schema_sha256) ||
        !digest_equals_hex(header + 144u,
            config->expected_source_state_sha256)) {
        set_error(error, error_capacity, "schema/source SHA-256 mismatch");
        return nullptr;
    }
    uint8_t payload_digest[32];
    if (!sha256(bytes.data() + kHeaderBytes,
                static_cast<std::size_t>(payload_bytes), payload_digest) ||
        std::memcmp(header + 176u, payload_digest, 32u) != 0) {
        set_error(error, error_capacity, "payload SHA-256 mismatch");
        return nullptr;
    }
    EventStudent *model = new (std::nothrow) EventStudent();
    if (model == nullptr) {
        set_error(error, error_capacity, "model allocation failed");
        return nullptr;
    }
    try {
        model->parameters.resize(parameter_floats);
    } catch (const std::bad_alloc &) {
        delete model;
        set_error(error, error_capacity, "parameter allocation failed");
        return nullptr;
    }
    for (uint32_t index = 0u; index < parameter_floats; ++index) {
        model->parameters[index] =
            read_f32(bytes.data() + kHeaderBytes + index * 4u);
        if (!std::isfinite(model->parameters[index])) {
            delete model;
            set_error(error, error_capacity, "model parameter is non-finite");
            return nullptr;
        }
    }
    model->metadata.format_version = version;
    model->metadata.continuous_features = continuous;
    model->metadata.input_features = input;
    model->metadata.ja4_fields = fields;
    model->metadata.ja4_tables = tables;
    model->metadata.ja4_vocabulary = vocabulary;
    model->metadata.hidden = hidden;
    model->metadata.identity_embedding = embedding;
    model->metadata.event_hidden = event_hidden;
    model->metadata.parameter_floats = parameter_floats;
    model->metadata.layer_norm_epsilon = epsilon;
    model->metadata.decision_threshold = threshold;
    std::snprintf(model->metadata.artifact_sha256,
        sizeof(model->metadata.artifact_sha256), "%s",
        config->expected_artifact_sha256);
    digest_to_hex(header + 80u, model->metadata.feature_schema_sha256);
    digest_to_hex(header + 112u, model->metadata.architecture_sha256);
    digest_to_hex(header + 144u, model->metadata.source_state_sha256);
    digest_to_hex(header + 176u, model->metadata.payload_sha256);
    if (!bind_parameter_view(*model)) {
        delete model;
        set_error(error, error_capacity, "parameter layout is invalid");
        return nullptr;
    }
    for (uint32_t index = 0u;
         index < FK_EVENT_STUDENT_CONTINUOUS_FEATURES; ++index) {
        if (!(model->view.scale[index] > 0.0f)) {
            delete model;
            set_error(error, error_capacity, "normalizer scale is not positive");
            return nullptr;
        }
    }
    const std::size_t table_stride =
        static_cast<std::size_t>(vocabulary) * embedding;
    for (uint32_t table = 0u; table < fields * tables; ++table) {
        const float *padding =
            model->view.identity_embeddings + table * table_stride;
        for (uint32_t component = 0u; component < embedding; ++component) {
            if (padding[component] != 0.0f) {
                delete model;
                set_error(error, error_capacity,
                    "identity padding embedding is not exactly zero");
                return nullptr;
            }
        }
    }
    return reinterpret_cast<fk_event_student *>(model);
}

void fk_event_student_destroy(fk_event_student *model) {
    delete implementation(model);
}

bool fk_event_student_get_metadata(
        const fk_event_student *model,
        fk_event_student_metadata *metadata) {
    if (model == nullptr || metadata == nullptr)
        return false;
    *metadata = implementation(model)->metadata;
    return true;
}

bool fk_event_student_identity_categories(
        const float *features,
        std::size_t feature_count,
        uint16_t *categories,
        std::size_t category_capacity) {
    constexpr std::size_t category_count =
        FK_EVENT_STUDENT_JA4_FIELDS * FK_EVENT_STUDENT_JA4_TABLES;
    if (features == nullptr || categories == nullptr ||
        feature_count != FK_EVENT_STUDENT_INPUT_FEATURES ||
        category_capacity < category_count)
        return false;
    for (uint32_t field = 0u;
         field < FK_EVENT_STUDENT_JA4_FIELDS; ++field) {
        uint64_t hash = 0u;
        if (!decode_identity(features, field, hash))
            return false;
        for (uint32_t table = 0u;
             table < FK_EVENT_STUDENT_JA4_TABLES; ++table) {
            categories[field * FK_EVENT_STUDENT_JA4_TABLES + table] =
                static_cast<uint16_t>(identity_category(hash, field, table));
        }
    }
    return true;
}

bool fk_event_student_encode_flow(
        const fk_event_student *opaque,
        const float *features,
        std::size_t feature_count,
        fk_event_student_embedding *encoded) {
    if (opaque == nullptr || features == nullptr || encoded == nullptr ||
        feature_count != FK_EVENT_STUDENT_INPUT_FEATURES)
        return false;
    const EventStudent &model = *implementation(opaque);
    const std::size_t hidden = model.metadata.hidden;
    const std::size_t embedding = model.metadata.identity_embedding;
    const std::size_t identity_tables =
        FK_EVENT_STUDENT_JA4_FIELDS * FK_EVENT_STUDENT_JA4_TABLES;
    const std::size_t identity_width = identity_tables * embedding;
    std::array<float, FK_EVENT_STUDENT_CONTINUOUS_FEATURES> normalized{};
    std::array<float, FK_EVENT_STUDENT_MAX_HIDDEN> continuous{};
    std::array<float, FK_EVENT_STUDENT_MAX_HIDDEN> temporary{};
    std::array<float,
        FK_EVENT_STUDENT_JA4_FIELDS * FK_EVENT_STUDENT_JA4_TABLES *
            FK_EVENT_STUDENT_MAX_IDENTITY_EMBEDDING> identity_flat{};
    std::array<float, FK_EVENT_STUDENT_MAX_HIDDEN> identity_encoded{};
    std::array<float, FK_EVENT_STUDENT_MAX_HIDDEN * 2u + 1u> fusion{};
    std::array<uint16_t,
        FK_EVENT_STUDENT_JA4_FIELDS * FK_EVENT_STUDENT_JA4_TABLES>
        categories{};
    for (std::size_t index = 0u;
         index < FK_EVENT_STUDENT_CONTINUOUS_FEATURES; ++index) {
        if (!std::isfinite(features[index]))
            return false;
        normalized[index] = std::max(-10.0f, std::min(10.0f,
            (features[index] - model.view.mean[index]) /
                model.view.scale[index]));
    }
    linear(
        normalized.data(), model.view.encoder_one_weight,
        model.view.encoder_one_bias,
        FK_EVENT_STUDENT_CONTINUOUS_FEATURES, hidden,
        temporary.data());
    layer_norm(
        temporary.data(), model.view.encoder_norm_weight,
        model.view.encoder_norm_bias, hidden, continuous.data());
    gelu(continuous.data(), hidden);
    linear(
        continuous.data(), model.view.encoder_two_weight,
        model.view.encoder_two_bias, hidden, hidden, temporary.data());
    gelu(temporary.data(), hidden);
    std::copy_n(temporary.data(), hidden, continuous.data());

    if (!fk_event_student_identity_categories(
            features, feature_count, categories.data(), categories.size()))
        return false;
    bool identity_present = false;
    const std::size_t table_stride =
        static_cast<std::size_t>(FK_EVENT_STUDENT_JA4_VOCABULARY) *
        embedding;
    for (uint32_t field = 0u;
         field < FK_EVENT_STUDENT_JA4_FIELDS; ++field) {
        for (uint32_t table = 0u;
             table < FK_EVENT_STUDENT_JA4_TABLES; ++table) {
            const std::size_t table_index = field * 2u + table;
            const uint32_t category = categories[table_index];
            identity_present = identity_present || category != 0u;
            const float *source = model.view.identity_embeddings +
                table_index * table_stride +
                static_cast<std::size_t>(category) * embedding;
            std::copy_n(
                source,
                embedding,
                identity_flat.data() + table_index * embedding);
        }
    }
    linear(
        identity_flat.data(), model.view.identity_projection_weight,
        model.view.identity_projection_bias, identity_width, hidden,
        identity_encoded.data());
    gelu(identity_encoded.data(), hidden);
    if (!identity_present)
        std::fill_n(identity_encoded.data(), hidden, 0.0f);
    for (std::size_t index = 0u; index < hidden; ++index) {
        fusion[index] = continuous[index];
        fusion[hidden + index] = identity_encoded[index];
    }
    fusion[hidden * 2u] = identity_present ? 1.0f : 0.0f;
    linear(
        fusion.data(), model.view.fusion_weight, model.view.fusion_bias,
        hidden * 2u + 1u, hidden, temporary.data());
    layer_norm(
        temporary.data(), model.view.fusion_norm_weight,
        model.view.fusion_norm_bias, hidden, encoded->values);
    gelu(encoded->values, hidden);
    std::fill(
        encoded->values + hidden,
        encoded->values + FK_EVENT_STUDENT_MAX_HIDDEN,
        0.0f);
    for (std::size_t index = 0u; index < hidden; ++index) {
        if (!std::isfinite(encoded->values[index]))
            return false;
    }
    return true;
}

void fk_event_student_window_reset(fk_event_student_window_state *state) {
    if (state == nullptr)
        return;
    std::memset(state, 0, sizeof(*state));
    state->maximum_attention_logit =
        -std::numeric_limits<float>::infinity();
}

bool fk_event_student_window_add(
        const fk_event_student *opaque,
        fk_event_student_window_state *state,
        const fk_event_student_embedding *encoded,
        float instance_mask) {
    if (opaque == nullptr || state == nullptr || encoded == nullptr ||
        !std::isfinite(instance_mask) || instance_mask < 0.0f)
        return false;
    if (instance_mask > 0.0f &&
        state->valid_flows >= FK_EVENT_STUDENT_MAX_FLOWS_PER_WINDOW)
        return false;
    const EventStudent &model = *implementation(opaque);
    const std::size_t hidden = model.metadata.hidden;
    for (std::size_t index = 0u; index < hidden; ++index) {
        if (!std::isfinite(encoded->values[index]))
            return false;
    }
    const float attention = model.view.flow_attention_bias[0] +
        dot(model.view.flow_attention_weight, encoded->values, hidden);
    return add_softmax_item(
        attention, instance_mask, encoded->values, hidden,
        state->maximum_attention_logit, state->denominator,
        state->weighted_sum, state->valid_flows);
}

bool fk_event_student_window_finish(
        const fk_event_student *opaque,
        const fk_event_student_window_state *state,
        fk_event_student_embedding *window_embedding,
        float *raw_window_logit) {
    if (opaque == nullptr || state == nullptr ||
        window_embedding == nullptr || raw_window_logit == nullptr ||
        state->valid_flows == 0u || !std::isfinite(state->denominator) ||
        !(state->denominator > 0.0f))
        return false;
    const EventStudent &model = *implementation(opaque);
    const std::size_t hidden = model.metadata.hidden;
    for (std::size_t index = 0u; index < hidden; ++index)
        window_embedding->values[index] =
            state->weighted_sum[index] / state->denominator;
    std::fill(
        window_embedding->values + hidden,
        window_embedding->values + FK_EVENT_STUDENT_MAX_HIDDEN,
        0.0f);
    *raw_window_logit = window_head(model, window_embedding->values);
    return std::isfinite(*raw_window_logit);
}

void fk_event_student_event_reset(fk_event_student_event_state *state) {
    if (state == nullptr)
        return;
    std::memset(state, 0, sizeof(*state));
    state->maximum_attention_logit =
        -std::numeric_limits<float>::infinity();
    state->operational_logit = FK_EVENT_STUDENT_INVALID_LOGIT;
}

bool fk_event_student_event_add(
        const fk_event_student *opaque,
        fk_event_student_event_state *state,
        const fk_event_student_embedding *window_embedding,
        float window_mask,
        float *prefix_event_logit,
        float *operational_logit) {
    if (opaque == nullptr || state == nullptr || window_embedding == nullptr ||
        prefix_event_logit == nullptr || operational_logit == nullptr ||
        !std::isfinite(window_mask) || window_mask < 0.0f ||
        state->windows_seen == std::numeric_limits<uint32_t>::max())
        return false;
    const EventStudent &model = *implementation(opaque);
    const std::size_t hidden = model.metadata.hidden;
    for (std::size_t index = 0u; index < hidden; ++index) {
        if (!std::isfinite(window_embedding->values[index]))
            return false;
    }
    const float attention = model.view.event_attention_bias[0] +
        dot(model.view.event_attention_weight,
            window_embedding->values, hidden);
    if (!add_softmax_item(
            attention, window_mask, window_embedding->values, hidden,
            state->maximum_attention_logit, state->denominator,
            state->weighted_sum, state->valid_windows))
        return false;
    ++state->windows_seen;
    if (state->valid_windows == 0u) {
        *prefix_event_logit = FK_EVENT_STUDENT_INVALID_LOGIT;
        *operational_logit = state->operational_logit;
        return true;
    }
    std::array<float, FK_EVENT_STUDENT_MAX_HIDDEN> event_embedding{};
    for (std::size_t index = 0u; index < hidden; ++index)
        event_embedding[index] =
            state->weighted_sum[index] / state->denominator;
    *prefix_event_logit = event_head(model, event_embedding.data());
    if (!std::isfinite(*prefix_event_logit))
        return false;
    state->operational_logit = std::max(
        state->operational_logit, *prefix_event_logit);
    *operational_logit = state->operational_logit;
    return true;
}

float fk_event_student_sigmoid(float logit) {
    if (std::isnan(logit))
        return std::numeric_limits<float>::quiet_NaN();
    if (logit >= 0.0f) {
        const float decay = std::exp(-logit);
        return 1.0f / (1.0f + decay);
    }
    const float growth = std::exp(logit);
    return growth / (1.0f + growth);
}

}  // extern "C"
