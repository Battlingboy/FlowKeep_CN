#include "fk_cpu_model.h"

#include <array>
#include <cerrno>
#include <cmath>
#include <cstdio>
#include <cstring>
#include <limits>
#include <new>
#include <openssl/evp.h>
#include <string>
#include <sys/stat.h>
#include <unistd.h>
#include <vector>

namespace {

constexpr uint32_t kTreeFormatVersion = 1u;
constexpr uint32_t kLinearFormatVersion = 2u;
constexpr uint32_t kCategoricalTreeFormatVersion = 3u;

struct Node {
    int32_t feature;
    int32_t left;
    int32_t right;
    float threshold;
    float value;
    uint32_t categorical_set;
    uint8_t missing_left;
};

struct CategoricalSet {
    uint32_t words[8];
};

struct Tree {
    uint32_t output;
    uint32_t node_offset;
    uint32_t node_count;
    float learning_rate;
};

struct CpuModel {
    fk_cpu_model_metadata metadata{};
    std::vector<float> bias;
    std::vector<float> linear_weights;
    std::vector<Tree> trees;
    std::vector<Node> nodes;
    std::vector<CategoricalSet> categorical_sets;
};

constexpr uint32_t kNoCategoricalSet = UINT32_MAX;
constexpr std::size_t kDigestBytes = 32u;

static CpuModel *implementation(fk_cpu_model *model) {
    return reinterpret_cast<CpuModel *>(model);
}

static const CpuModel *implementation(const fk_cpu_model *model) {
    return reinterpret_cast<const CpuModel *>(model);
}

static void set_error(
        char *error,
        size_t capacity,
        const std::string &message) {
    if (error == nullptr || capacity == 0u)
        return;
    std::snprintf(error, capacity, "%s", message.c_str());
}

static bool read_token(FILE *stream, const char *expected) {
    char token[96];
    return std::fscanf(stream, "%95s", token) == 1 &&
        std::strcmp(token, expected) == 0;
}

static bool valid_sha256(const char *text) {
    if (std::strlen(text) != FK_CPU_MODEL_SCHEMA_SHA256_CHARS)
        return false;
    for (std::size_t index = 0u;
         index < FK_CPU_MODEL_SCHEMA_SHA256_CHARS; ++index) {
        const char value = text[index];
        if (!((value >= '0' && value <= '9') ||
              (value >= 'a' && value <= 'f')))
            return false;
    }
    return true;
}

static bool same_file_snapshot(const struct stat &left, const struct stat &right) {
    return left.st_dev == right.st_dev && left.st_ino == right.st_ino &&
        left.st_mode == right.st_mode && left.st_size == right.st_size &&
        left.st_mtim.tv_sec == right.st_mtim.tv_sec &&
        left.st_mtim.tv_nsec == right.st_mtim.tv_nsec &&
        left.st_ctim.tv_sec == right.st_ctim.tv_sec &&
        left.st_ctim.tv_nsec == right.st_ctim.tv_nsec;
}

static bool hash_and_rewind(
        FILE *stream,
        char output[FK_CPU_MODEL_SCHEMA_SHA256_CHARS + 1u]) {
    if (stream == nullptr || output == nullptr ||
        std::fseek(stream, 0, SEEK_SET) != 0)
        return false;
    EVP_MD_CTX *context = EVP_MD_CTX_new();
    if (context == nullptr)
        return false;
    bool valid = EVP_DigestInit_ex(context, EVP_sha256(), nullptr) == 1;
    std::array<unsigned char, 64u * 1024u> buffer{};
    while (valid) {
        const std::size_t count =
            std::fread(buffer.data(), 1u, buffer.size(), stream);
        if (count != 0u &&
            EVP_DigestUpdate(context, buffer.data(), count) != 1) {
            valid = false;
            break;
        }
        if (count != buffer.size()) {
            if (std::ferror(stream) != 0)
                valid = false;
            break;
        }
    }
    std::array<unsigned char, kDigestBytes> digest{};
    unsigned int digest_bytes = 0u;
    valid = valid && EVP_DigestFinal_ex(
        context, digest.data(), &digest_bytes) == 1 &&
        digest_bytes == digest.size();
    EVP_MD_CTX_free(context);
    if (!valid)
        return false;
    static constexpr char kHex[] = "0123456789abcdef";
    for (std::size_t index = 0u; index < digest.size(); ++index) {
        output[index * 2u] = kHex[digest[index] >> 4u];
        output[index * 2u + 1u] = kHex[digest[index] & 0x0fu];
    }
    output[FK_CPU_MODEL_SCHEMA_SHA256_CHARS] = '\0';
    std::clearerr(stream);
    return std::fseek(stream, 0, SEEK_SET) == 0;
}

static bool read_role(FILE *stream, fk_cpu_model_role &role) {
    char text[32];
    if (!read_token(stream, "role") ||
        std::fscanf(stream, "%31s", text) != 1)
        return false;
    if (std::strcmp(text, "action_value") == 0) {
        role = FK_CPU_MODEL_ACTION_VALUE;
        return true;
    }
    if (std::strcmp(text, "detector") == 0) {
        role = FK_CPU_MODEL_DETECTOR;
        return true;
    }
    if (std::strcmp(text, "transition_value") == 0) {
        role = FK_CPU_MODEL_TRANSITION_VALUE;
        return true;
    }
    return false;
}

static bool read_link(FILE *stream, fk_cpu_model_link &link) {
    char text[32];
    if (!read_token(stream, "link") ||
        std::fscanf(stream, "%31s", text) != 1)
        return false;
    if (std::strcmp(text, "identity") == 0) {
        link = FK_CPU_MODEL_IDENTITY;
        return true;
    }
    if (std::strcmp(text, "sigmoid") == 0) {
        link = FK_CPU_MODEL_SIGMOID;
        return true;
    }
    return false;
}

static bool validate_tree(
        const Node *nodes,
        std::size_t node_count,
        std::size_t categorical_set_count,
        uint32_t feature_count,
        std::string &reason) {
    if (nodes == nullptr || node_count == 0u ||
        node_count > FK_CPU_MODEL_MAX_NODES_PER_TREE) {
        reason = "invalid tree node count";
        return false;
    }
    bool has_leaf = false;
    for (std::size_t index = 0u; index < node_count; ++index) {
        const Node &node = nodes[index];
        if (!std::isfinite(node.threshold) ||
            !std::isfinite(node.value)) {
            reason = "non-finite node value";
            return false;
        }
        if (node.feature == -1) {
            has_leaf = true;
            continue;
        }
        if (node.feature < 0 ||
            static_cast<uint32_t>(node.feature) >= feature_count ||
            node.left < 0 || node.right < 0 ||
            static_cast<std::size_t>(node.left) >= node_count ||
            static_cast<std::size_t>(node.right) >= node_count ||
            node.missing_left > 1u ||
            (node.categorical_set != kNoCategoricalSet &&
             node.categorical_set >= categorical_set_count)) {
            reason = "invalid internal node";
            return false;
        }
        /*
         * Requiring children to appear later makes a cycle impossible and
         * bounds every inference traversal by node_count.
         */
        if (static_cast<std::size_t>(node.left) <= index ||
            static_cast<std::size_t>(node.right) <= index) {
            reason = "tree is cyclic or not topologically ordered";
            return false;
        }
    }
    if (!has_leaf) {
        reason = "tree has no leaf";
        return false;
    }
    return true;
}

static float apply_link(fk_cpu_model_link link, float value) {
    if (link == FK_CPU_MODEL_IDENTITY)
        return value;
    if (value >= 0.0f) {
        const float decay = std::exp(-value);
        return 1.0f / (1.0f + decay);
    }
    const float growth = std::exp(value);
    return growth / (1.0f + growth);
}

static bool evaluate_tree(
        const Tree &tree,
        const Node *model_nodes,
        const CategoricalSet *categorical_sets,
        const float *features,
        float &result) {
    const Node *nodes = model_nodes + tree.node_offset;
    std::size_t index = 0u;
    for (std::size_t steps = 0u; steps < tree.node_count; ++steps) {
        if (index >= tree.node_count)
            return false;
        const Node &node = nodes[index];
        if (node.feature == -1) {
            result = node.value;
            return true;
        }
        const float feature = features[node.feature];
        if (std::isnan(feature))
            index = node.missing_left != 0u
                ? static_cast<std::size_t>(node.left)
                : static_cast<std::size_t>(node.right);
        else if (node.categorical_set != kNoCategoricalSet) {
            const float rounded = std::floor(feature);
            bool member = false;
            if (feature == rounded && rounded >= 0.0f && rounded < 256.0f) {
                const uint32_t category = static_cast<uint32_t>(rounded);
                member = (categorical_sets[node.categorical_set]
                              .words[category / 32u] &
                          (1u << (category % 32u))) != 0u;
            }
            index = member
                ? static_cast<std::size_t>(node.left)
                : static_cast<std::size_t>(node.right);
        } else
            index = feature <= node.threshold
                ? static_cast<std::size_t>(node.left)
                : static_cast<std::size_t>(node.right);
    }
    return false;
}

}  // namespace

extern "C" {

fk_cpu_model *fk_cpu_model_load(
        const char *path,
        char *error,
        size_t error_capacity) {
    return fk_cpu_model_load_verified(
        path, nullptr, error, error_capacity);
}

fk_cpu_model *fk_cpu_model_load_verified(
        const char *path,
        const char *expected_artifact_sha256,
        char *error,
        size_t error_capacity) {
    set_error(error, error_capacity, "");
    if (path == nullptr || path[0] == '\0') {
        set_error(error, error_capacity, "model path is empty");
        return nullptr;
    }
    FILE *stream = std::fopen(path, "r");
    if (stream == nullptr) {
        set_error(
            error,
            error_capacity,
            std::string("cannot open model: ") + std::strerror(errno));
        return nullptr;
    }
    if (expected_artifact_sha256 != nullptr &&
        !valid_sha256(expected_artifact_sha256)) {
        std::fclose(stream);
        set_error(error, error_capacity, "invalid expected artifact SHA-256");
        return nullptr;
    }
    struct stat status_before {};
    if (::fstat(::fileno(stream), &status_before) != 0 ||
        !S_ISREG(status_before.st_mode) || status_before.st_size < 0 ||
        static_cast<uint64_t>(status_before.st_size) >
            FK_CPU_MODEL_MAX_FILE_BYTES) {
        std::fclose(stream);
        set_error(
            error,
            error_capacity,
            "model is not a bounded regular file");
        return nullptr;
    }
    if (expected_artifact_sha256 != nullptr) {
        char observed[FK_CPU_MODEL_SCHEMA_SHA256_CHARS + 1u]{};
        struct stat status_after {};
        if (!hash_and_rewind(stream, observed) ||
            ::fstat(::fileno(stream), &status_after) != 0 ||
            !same_file_snapshot(status_before, status_after) ||
            std::strcmp(observed, expected_artifact_sha256) != 0) {
            std::fclose(stream);
            set_error(error, error_capacity,
                      "artifact SHA-256 or file snapshot mismatch");
            return nullptr;
        }
    }
    CpuModel *model = new (std::nothrow) CpuModel();
    if (model == nullptr) {
        std::fclose(stream);
        set_error(error, error_capacity, "model allocation failed");
        return nullptr;
    }

    char magic[32];
    unsigned int version = 0u;
    bool valid =
        std::fscanf(stream, "%31s %u", magic, &version) == 2 &&
        std::strcmp(magic, "FLOWKEEP_CPU_MODEL") == 0 &&
        (version == kTreeFormatVersion ||
         version == kLinearFormatVersion ||
         version == kCategoricalTreeFormatVersion);
    model->metadata.format_version = version;
    valid = valid && read_role(stream, model->metadata.role);
    valid = valid && read_link(stream, model->metadata.link);
    valid = valid && read_token(stream, "feature_schema_sha256") &&
        std::fscanf(
            stream,
            "%64s",
            model->metadata.feature_schema_sha256) == 1 &&
        valid_sha256(model->metadata.feature_schema_sha256);
    valid = valid && read_token(stream, "feature_count") &&
        std::fscanf(stream, "%u", &model->metadata.feature_count) == 1 &&
        model->metadata.feature_count > 0u &&
        model->metadata.feature_count <= FK_CPU_MODEL_MAX_FEATURES;
    valid = valid && read_token(stream, "output_count") &&
        std::fscanf(stream, "%u", &model->metadata.output_count) == 1 &&
        model->metadata.output_count > 0u &&
        model->metadata.output_count <= FK_CPU_MODEL_MAX_OUTPUTS;
    if (valid && model->metadata.role == FK_CPU_MODEL_ACTION_VALUE)
        valid = model->metadata.output_count == 8u;
    if (valid && model->metadata.role == FK_CPU_MODEL_DETECTOR)
        valid = model->metadata.output_count == 1u;
    if (valid && model->metadata.role == FK_CPU_MODEL_TRANSITION_VALUE)
        valid = model->metadata.output_count == 1u;

    model->bias.resize(model->metadata.output_count);
    valid = valid && read_token(stream, "bias");
    for (uint32_t output = 0u;
         valid && output < model->metadata.output_count; ++output) {
        valid = std::fscanf(stream, "%f", &model->bias[output]) == 1 &&
            std::isfinite(model->bias[output]);
    }
    if (valid && version == kLinearFormatVersion) {
        const uint64_t expected_weights =
            static_cast<uint64_t>(model->metadata.feature_count) *
            static_cast<uint64_t>(model->metadata.output_count);
        valid = expected_weights <=
            static_cast<uint64_t>(FK_CPU_MODEL_MAX_FEATURES) *
            static_cast<uint64_t>(FK_CPU_MODEL_MAX_OUTPUTS);
        model->metadata.linear_weight_count =
            static_cast<uint32_t>(expected_weights);
        model->linear_weights.resize(
            model->metadata.linear_weight_count);
        valid = valid && read_token(stream, "linear_weights");
        for (uint32_t index = 0u;
             valid && index < model->metadata.linear_weight_count;
             ++index) {
            valid =
                std::fscanf(stream, "%f",
                            &model->linear_weights[index]) == 1 &&
                std::isfinite(model->linear_weights[index]);
        }
    }
    valid = valid && read_token(stream, "tree_count") &&
        std::fscanf(stream, "%u", &model->metadata.tree_count) == 1 &&
        model->metadata.tree_count <= FK_CPU_MODEL_MAX_TREES;

    std::string validation_error;
    model->trees.reserve(model->metadata.tree_count);
    for (uint32_t tree_index = 0u;
         valid && tree_index < model->metadata.tree_count; ++tree_index) {
        Tree tree{};
        unsigned int output = 0u;
        unsigned int node_count = 0u;
        valid = read_token(stream, "tree") &&
            std::fscanf(
                stream,
                "%u %f %u",
                &output,
                &tree.learning_rate,
                &node_count) == 3 &&
            output < model->metadata.output_count &&
            std::isfinite(tree.learning_rate) &&
            node_count > 0u &&
            node_count <= FK_CPU_MODEL_MAX_NODES_PER_TREE;
        tree.output = output;
        tree.node_offset = static_cast<uint32_t>(model->nodes.size());
        tree.node_count = node_count;
        for (uint32_t node_index = 0u;
             valid && node_index < node_count; ++node_index) {
            Node node{};
            node.categorical_set = kNoCategoricalSet;
            unsigned int missing_left = 0u;
            valid = read_token(stream, "node") &&
                std::fscanf(
                    stream,
                    "%d %d %d %u %f %f",
                    &node.feature,
                    &node.left,
                    &node.right,
                    &missing_left,
                    &node.threshold,
                    &node.value) == 6 &&
                missing_left <= 1u;
            node.missing_left = static_cast<uint8_t>(missing_left);
            if (valid && version == kCategoricalTreeFormatVersion) {
                unsigned int categorical = 0u;
                valid = std::fscanf(stream, "%u", &categorical) == 1 &&
                    categorical <= 1u;
                CategoricalSet categorical_set{};
                for (uint32_t word = 0u; valid && word < 8u; ++word) {
                    unsigned int value = 0u;
                    valid = std::fscanf(stream, "%u", &value) == 1;
                    categorical_set.words[word] = value;
                }
                if (valid && categorical != 0u) {
                    node.categorical_set = static_cast<uint32_t>(
                        model->categorical_sets.size());
                    model->categorical_sets.push_back(categorical_set);
                }
            }
            model->nodes.push_back(node);
        }
        if (valid)
            valid = validate_tree(
                model->nodes.data() + tree.node_offset,
                tree.node_count,
                model->categorical_sets.size(),
                model->metadata.feature_count,
                validation_error);
        model->trees.push_back(tree);
    }
    valid = valid && read_token(stream, "end");
    std::fclose(stream);
    if (!valid) {
        delete model;
        set_error(
            error,
            error_capacity,
            validation_error.empty()
                ? "malformed or incompatible model"
                : validation_error);
        return nullptr;
    }
    return reinterpret_cast<fk_cpu_model *>(model);
}

void fk_cpu_model_destroy(fk_cpu_model *model) {
    delete implementation(model);
}

bool fk_cpu_model_predict(
        const fk_cpu_model *model,
        const float *features,
        size_t feature_count,
        float *outputs,
        size_t output_capacity) {
    if (model == nullptr || features == nullptr || outputs == nullptr)
        return false;
    const CpuModel &state = *implementation(model);
    if (feature_count != state.metadata.feature_count ||
        output_capacity < state.metadata.output_count)
        return false;
    for (uint32_t output = 0u;
         output < state.metadata.output_count; ++output)
        outputs[output] = state.bias[output];
    if (!state.linear_weights.empty()) {
        for (uint32_t feature = 0u;
             feature < state.metadata.feature_count; ++feature) {
            if (!std::isfinite(features[feature]))
                return false;
        }
        for (uint32_t output = 0u;
             output < state.metadata.output_count; ++output) {
            const float *weights =
                state.linear_weights.data() +
                static_cast<std::size_t>(output) *
                    state.metadata.feature_count;
            float contribution = 0.0f;
            for (uint32_t feature = 0u;
                 feature < state.metadata.feature_count; ++feature)
                contribution += weights[feature] * features[feature];
            outputs[output] += contribution;
        }
    }
    for (const Tree &tree : state.trees) {
        float value = 0.0f;
        if (!evaluate_tree(
                tree,
                state.nodes.data(),
                state.categorical_sets.data(),
                features,
                value))
            return false;
        outputs[tree.output] += tree.learning_rate * value;
    }
    for (uint32_t output = 0u;
         output < state.metadata.output_count; ++output)
        outputs[output] = apply_link(state.metadata.link, outputs[output]);
    return true;
}

bool fk_cpu_model_get_metadata(
        const fk_cpu_model *model,
        struct fk_cpu_model_metadata *metadata) {
    if (model == nullptr || metadata == nullptr)
        return false;
    *metadata = implementation(model)->metadata;
    return true;
}

}  // extern "C"
