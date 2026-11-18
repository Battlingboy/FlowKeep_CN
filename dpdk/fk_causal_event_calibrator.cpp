#include "fk_causal_event_calibrator.h"

#include <cerrno>
#include <cmath>
#include <cstdio>
#include <cstring>
#include <new>
#include <sys/stat.h>
#include <unistd.h>

namespace {

struct Model {
    fk_causal_event_calibrator_metadata_v1 metadata{};
    float center[FK_CAUSAL_EVENT_CALIBRATOR_FEATURES]{};
    float scale[FK_CAUSAL_EVENT_CALIBRATOR_FEATURES]{};
    float hidden_weight[
        FK_CAUSAL_EVENT_CALIBRATOR_HIDDEN]
        [FK_CAUSAL_EVENT_CALIBRATOR_FEATURES]{};
    float hidden_bias[FK_CAUSAL_EVENT_CALIBRATOR_HIDDEN]{};
    float output_weight[FK_CAUSAL_EVENT_CALIBRATOR_HIDDEN]{};
    float output_bias = 0.0f;
};

Model *implementation(fk_causal_event_calibrator *model) {
    return reinterpret_cast<Model *>(model);
}

const Model *implementation(const fk_causal_event_calibrator *model) {
    return reinterpret_cast<const Model *>(model);
}

void set_error(char *error, size_t capacity, const char *message) {
    if (error != nullptr && capacity != 0u)
        std::snprintf(error, capacity, "%s", message);
}

bool valid_sha256(const char *value) {
    if (value == nullptr ||
        std::strlen(value) != FK_CAUSAL_EVENT_CALIBRATOR_SHA256_CHARS)
        return false;
    for (size_t index = 0u;
         index < FK_CAUSAL_EVENT_CALIBRATOR_SHA256_CHARS; ++index) {
        if (!((value[index] >= '0' && value[index] <= '9') ||
              (value[index] >= 'a' && value[index] <= 'f')))
            return false;
    }
    return true;
}

bool token(FILE *stream, const char *expected) {
    char value[96]{};
    return std::fscanf(stream, "%95s", value) == 1 &&
        std::strcmp(value, expected) == 0;
}

bool read_floats(FILE *stream, float *values, size_t count) {
    for (size_t index = 0u; index < count; ++index) {
        if (std::fscanf(stream, "%f", &values[index]) != 1 ||
            !std::isfinite(values[index]))
            return false;
    }
    return true;
}

float sigmoid(float value) {
    if (value >= 0.0f) {
        const float decay = std::exp(-value);
        return 1.0f / (1.0f + decay);
    }
    const float growth = std::exp(value);
    return growth / (1.0f + growth);
}

}  // namespace

extern "C" {

fk_causal_event_calibrator *fk_causal_event_calibrator_load(
        const char *path,
        const char *expected_source_npz_sha256,
        const char *expected_feature_contract_sha256,
        char *error,
        size_t error_capacity) {
    set_error(error, error_capacity, "");
    if (path == nullptr || path[0] == '\0' ||
        !valid_sha256(expected_source_npz_sha256) ||
        !valid_sha256(expected_feature_contract_sha256)) {
        set_error(error, error_capacity, "invalid calibrator load contract");
        return nullptr;
    }
    FILE *stream = std::fopen(path, "r");
    if (stream == nullptr) {
        set_error(error, error_capacity, std::strerror(errno));
        return nullptr;
    }
    struct stat status{};
    if (::fstat(::fileno(stream), &status) != 0 ||
        !S_ISREG(status.st_mode) || status.st_size <= 0 ||
        static_cast<uint64_t>(status.st_size) >
            FK_CAUSAL_EVENT_CALIBRATOR_MAX_FILE_BYTES) {
        std::fclose(stream);
        set_error(error, error_capacity, "calibrator is not a bounded file");
        return nullptr;
    }
    Model *model = new (std::nothrow) Model();
    if (model == nullptr) {
        std::fclose(stream);
        set_error(error, error_capacity, "calibrator allocation failed");
        return nullptr;
    }
    char magic[64]{};
    unsigned int version = 0u;
    unsigned int features = 0u;
    unsigned int hidden = 0u;
    char source_sha[65]{};
    char feature_sha[65]{};
    bool valid =
        std::fscanf(stream, "%63s %u", magic, &version) == 2 &&
        std::strcmp(magic, "FLOWKEEP_CAUSAL_EVENT_CALIBRATOR") == 0 &&
        version == 1u && token(stream, "feature_count") &&
        std::fscanf(stream, "%u", &features) == 1 &&
        features == FK_CAUSAL_EVENT_CALIBRATOR_FEATURES &&
        token(stream, "hidden_count") &&
        std::fscanf(stream, "%u", &hidden) == 1 &&
        hidden == FK_CAUSAL_EVENT_CALIBRATOR_HIDDEN &&
        token(stream, "source_npz_sha256") &&
        std::fscanf(stream, "%64s", source_sha) == 1 &&
        valid_sha256(source_sha) &&
        std::strcmp(source_sha, expected_source_npz_sha256) == 0 &&
        token(stream, "feature_contract_sha256") &&
        std::fscanf(stream, "%64s", feature_sha) == 1 &&
        valid_sha256(feature_sha) &&
        std::strcmp(feature_sha, expected_feature_contract_sha256) == 0 &&
        token(stream, "center") &&
        read_floats(stream, model->center, features) &&
        token(stream, "scale") &&
        read_floats(stream, model->scale, features) &&
        token(stream, "hidden_weight") &&
        read_floats(
            stream,
            &model->hidden_weight[0][0],
            static_cast<size_t>(features) * hidden) &&
        token(stream, "hidden_bias") &&
        read_floats(stream, model->hidden_bias, hidden) &&
        token(stream, "output_weight") &&
        read_floats(stream, model->output_weight, hidden) &&
        token(stream, "output_bias") &&
        read_floats(stream, &model->output_bias, 1u) &&
        token(stream, "END");
    for (float value : model->scale)
        valid = valid && value >= 1.0e-6f;
    char trailing[2]{};
    valid = valid && std::fscanf(stream, "%1s", trailing) != 1 &&
        !std::ferror(stream) && std::fclose(stream) == 0;
    if (!valid) {
        delete model;
        set_error(error, error_capacity, "calibrator artifact contract failed");
        return nullptr;
    }
    model->metadata.format_version = 1u;
    model->metadata.feature_count = features;
    model->metadata.hidden_count = hidden;
    std::snprintf(
        model->metadata.source_npz_sha256,
        sizeof(model->metadata.source_npz_sha256), "%s", source_sha);
    std::snprintf(
        model->metadata.feature_contract_sha256,
        sizeof(model->metadata.feature_contract_sha256), "%s", feature_sha);
    return reinterpret_cast<fk_causal_event_calibrator *>(model);
}

void fk_causal_event_calibrator_destroy(
        fk_causal_event_calibrator *model) {
    delete implementation(model);
}

bool fk_causal_event_calibrator_predict(
        const fk_causal_event_calibrator *model,
        const float features[FK_CAUSAL_EVENT_CALIBRATOR_FEATURES],
        float *probability) {
    if (model == nullptr || features == nullptr || probability == nullptr)
        return false;
    const Model &state = *implementation(model);
    float hidden[FK_CAUSAL_EVENT_CALIBRATOR_HIDDEN]{};
    for (size_t output = 0u;
         output < FK_CAUSAL_EVENT_CALIBRATOR_HIDDEN; ++output) {
        float value = state.hidden_bias[output];
        for (size_t feature = 0u;
             feature < FK_CAUSAL_EVENT_CALIBRATOR_FEATURES; ++feature) {
            if (!std::isfinite(features[feature]))
                return false;
            const float normalized =
                (features[feature] - state.center[feature]) /
                state.scale[feature];
            value += state.hidden_weight[output][feature] * normalized;
        }
        hidden[output] = std::fmax(value, 0.0f);
    }
    float logit = state.output_bias;
    for (size_t index = 0u;
         index < FK_CAUSAL_EVENT_CALIBRATOR_HIDDEN; ++index)
        logit += state.output_weight[index] * hidden[index];
    *probability = sigmoid(logit);
    return std::isfinite(*probability) && *probability >= 0.0f &&
        *probability <= 1.0f;
}

bool fk_causal_event_calibrator_get_metadata(
        const fk_causal_event_calibrator *model,
        fk_causal_event_calibrator_metadata_v1 *metadata) {
    if (model == nullptr || metadata == nullptr)
        return false;
    *metadata = implementation(model)->metadata;
    return true;
}

size_t fk_causal_event_calibrator_reserved_bytes(
        const fk_causal_event_calibrator *model) {
    return model == nullptr ? 0u : sizeof(Model);
}

}  // extern "C"
