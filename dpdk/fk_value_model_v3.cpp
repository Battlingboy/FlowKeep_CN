#include "fk_value_model_v3.h"

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
#include <sys/stat.h>
#include <unistd.h>
#include <utility>
#include <vector>

namespace {

constexpr uint32_t kLegacyFormatVersion = 1u;
constexpr uint32_t kCurrentFormatVersion = 2u;
constexpr uint32_t kMaximumTreeNodes = 63u;
constexpr uint32_t kMaximumConditionalTrees = 256u;
constexpr uint32_t kMaximumHiddenUnits = 64u;
constexpr uint64_t kMaximumFileBytes = UINT64_C(8) * 1024u * 1024u;
constexpr size_t kDigestBytes = 32u;

struct Node {
    int32_t left;
    int32_t right;
    int32_t feature;
    float threshold;
    float value;
};

struct ConditionalTree {
    uint8_t action = 0u;
    float learning_rate = 0.0f;
    std::vector<Node> nodes;
};

struct ValueModel {
    fk_value_model_v3_metadata metadata{};
    std::array<float, FK_VALUE_MODEL_V3_MODEL_FEATURES> mean{};
    std::array<float, FK_VALUE_MODEL_V3_MODEL_FEATURES> scale{};
    std::array<float, FK_VALUE_MODEL_V3_ACTIONS> uncertainty{};
    float clip_min = 0.0f;
    float clip_max = 0.0f;
    float ridge_intercept = 0.0f;
    std::array<float, FK_VALUE_MODEL_V3_MODEL_FEATURES> ridge_weights{};
    std::array<float, FK_VALUE_MODEL_V3_CONTEXT_FEATURES>
        action_ridge_mean{};
    std::array<float, FK_VALUE_MODEL_V3_CONTEXT_FEATURES>
        action_ridge_scale{};
    std::array<float, FK_VALUE_MODEL_V3_ACTIONS>
        action_ridge_intercepts{};
    std::array<
        std::array<float, FK_VALUE_MODEL_V3_CONTEXT_FEATURES>,
        FK_VALUE_MODEL_V3_ACTIONS> action_ridge_weights{};
    std::vector<Node> tree;
    std::array<float, FK_VALUE_MODEL_V3_ACTIONS> conditional_bias{};
    std::vector<ConditionalTree> conditional_trees;
    std::vector<float> mlp_input_weights;
    std::vector<float> mlp_hidden_bias;
    std::vector<float> mlp_output_weights;
    float mlp_output_bias = 0.0f;
};

static ValueModel *implementation(fk_value_model_v3 *model) {
    return reinterpret_cast<ValueModel *>(model);
}

static const ValueModel *implementation(const fk_value_model_v3 *model) {
    return reinterpret_cast<const ValueModel *>(model);
}

static void set_error(char *error, size_t capacity, const std::string &text) {
    if (error != nullptr && capacity > 0u)
        std::snprintf(error, capacity, "%s", text.c_str());
}

static bool token(FILE *stream, const char *expected) {
    char observed[96];
    return std::fscanf(stream, "%95s", observed) == 1 &&
        std::strcmp(observed, expected) == 0;
}

static bool valid_sha256(const char *text) {
    if (std::strlen(text) != FK_VALUE_MODEL_V3_SCHEMA_SHA256_CHARS)
        return false;
    for (size_t index = 0u;
         index < FK_VALUE_MODEL_V3_SCHEMA_SHA256_CHARS; ++index) {
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
        char output[FK_VALUE_MODEL_V3_SCHEMA_SHA256_CHARS + 1u]) {
    if (stream == nullptr || output == nullptr || std::fseek(stream, 0, SEEK_SET) != 0)
        return false;
    EVP_MD_CTX *context = EVP_MD_CTX_new();
    if (context == nullptr)
        return false;
    bool valid = EVP_DigestInit_ex(context, EVP_sha256(), nullptr) == 1;
    std::array<unsigned char, 64u * 1024u> buffer{};
    while (valid) {
        const size_t count = std::fread(buffer.data(), 1u, buffer.size(), stream);
        if (count != 0u && EVP_DigestUpdate(context, buffer.data(), count) != 1) {
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
    for (size_t index = 0u; index < digest.size(); ++index) {
        output[index * 2u] = kHex[digest[index] >> 4u];
        output[index * 2u + 1u] = kHex[digest[index] & 0x0fu];
    }
    output[FK_VALUE_MODEL_V3_SCHEMA_SHA256_CHARS] = '\0';
    std::clearerr(stream);
    return std::fseek(stream, 0, SEEK_SET) == 0;
}

static uint64_t reserved_model_bytes(const ValueModel &model) {
    uint64_t conditional_bytes =
        model.conditional_trees.capacity() * sizeof(ConditionalTree);
    for (const ConditionalTree &tree : model.conditional_trees)
        conditional_bytes += tree.nodes.capacity() * sizeof(Node);
    return sizeof(ValueModel) + conditional_bytes +
        model.tree.capacity() * sizeof(Node) +
        model.mlp_input_weights.capacity() * sizeof(float) +
        model.mlp_hidden_bias.capacity() * sizeof(float) +
        model.mlp_output_weights.capacity() * sizeof(float);
}

static bool read_role(FILE *stream, fk_value_model_v3_role &role) {
    char text[48];
    if (!token(stream, "model_role") ||
        std::fscanf(stream, "%47s", text) != 1)
        return false;
    if (std::strcmp(text, "flowkeep") == 0)
        role = FK_VALUE_MODEL_V3_FLOWKEEP;
    else if (std::strcmp(text, "learned_immediate_risk") == 0)
        role = FK_VALUE_MODEL_V3_IMMEDIATE_RISK;
    else if (std::strcmp(text, "learned_future_risk") == 0)
        role = FK_VALUE_MODEL_V3_FUTURE_RISK;
    else if (std::strcmp(text, "learned_detection_loss") == 0)
        role = FK_VALUE_MODEL_V3_DETECTION_LOSS;
    else
        return false;
    return true;
}

static bool read_family(FILE *stream, fk_value_model_v3_family &family) {
    char text[32];
    if (!token(stream, "family") ||
        std::fscanf(stream, "%31s", text) != 1)
        return false;
    if (std::strcmp(text, "ridge") == 0)
        family = FK_VALUE_MODEL_V3_RIDGE;
    else if (std::strcmp(text, "bounded_tree") == 0)
        family = FK_VALUE_MODEL_V3_BOUNDED_TREE;
    else if (std::strcmp(text, "light_mlp") == 0)
        family = FK_VALUE_MODEL_V3_LIGHT_MLP;
    else if (std::strcmp(text, "action_ridge") == 0)
        family = FK_VALUE_MODEL_V3_ACTION_RIDGE;
    else if (std::strcmp(text, "hybrid_gate_forest") == 0)
        family = FK_VALUE_MODEL_V3_HYBRID_GATE_FOREST;
    else
        return false;
    return true;
}

template <size_t Count>
static bool read_finite_array(
        FILE *stream,
        const char *name,
        std::array<float, Count> &values,
        bool positive = false) {
    if (!token(stream, name))
        return false;
    for (float &value : values) {
        if (std::fscanf(stream, "%f", &value) != 1 ||
            !std::isfinite(value) || (positive && value <= 0.0f))
            return false;
    }
    return true;
}

static bool read_finite_vector(
        FILE *stream,
        const char *name,
        std::vector<float> &values) {
    if (!token(stream, name))
        return false;
    for (float &value : values) {
        if (std::fscanf(stream, "%f", &value) != 1 ||
            !std::isfinite(value))
            return false;
    }
    return true;
}

static bool validate_tree(const std::vector<Node> &nodes) {
    if (nodes.empty() || nodes.size() > kMaximumTreeNodes)
        return false;
    bool leaf = false;
    for (size_t index = 0u; index < nodes.size(); ++index) {
        const Node &node = nodes[index];
        if (!std::isfinite(node.threshold) || !std::isfinite(node.value))
            return false;
        if (node.feature == -1) {
            if (node.left != -1 || node.right != -1)
                return false;
            leaf = true;
            continue;
        }
        if (node.feature < 0 ||
            static_cast<uint32_t>(node.feature) >=
                FK_VALUE_MODEL_V3_MODEL_FEATURES ||
            node.left <= static_cast<int32_t>(index) ||
            node.right <= static_cast<int32_t>(index) ||
            static_cast<size_t>(node.left) >= nodes.size() ||
            static_cast<size_t>(node.right) >= nodes.size())
            return false;
    }
    return leaf;
}

static bool valid_context(const float *context) {
    if (context == nullptr)
        return false;
    for (size_t index = 0u; index < FK_VALUE_MODEL_V3_CONTEXT_FEATURES;
         ++index) {
        if (!std::isfinite(context[index]))
            return false;
    }
    return context[8] == 0.0f && context[9] == 0.0f &&
        context[62] == 0.0f && context[63] == 0.0f;
}

static bool model_features(
        const ValueModel &model,
        const float *context,
        uint8_t action,
        std::array<double, FK_VALUE_MODEL_V3_MODEL_FEATURES> &features) {
    if (!valid_context(context) || action < 1u || action > 7u)
        return false;
    for (size_t index = 0u; index < FK_VALUE_MODEL_V3_CONTEXT_FEATURES;
         ++index)
        features[index] = context[index];
    features[64] = (action & 1u) != 0u ? 1.0 : 0.0;
    features[65] = (action & 2u) != 0u ? 1.0 : 0.0;
    features[66] = (action & 4u) != 0u ? 1.0 : 0.0;
    if (model.metadata.family == FK_VALUE_MODEL_V3_ACTION_RIDGE ||
        model.metadata.family == FK_VALUE_MODEL_V3_HYBRID_GATE_FOREST) {
        for (size_t index = 0u;
             index < FK_VALUE_MODEL_V3_CONTEXT_FEATURES; ++index) {
            features[index] =
                (features[index] - model.action_ridge_mean[index]) /
                model.action_ridge_scale[index];
        }
    } else if (model.metadata.family != FK_VALUE_MODEL_V3_BOUNDED_TREE) {
        for (size_t index = 0u; index < features.size(); ++index)
            features[index] =
                (features[index] - model.mean[index]) / model.scale[index];
    }
    return true;
}

static bool normalized_action_context(
        const ValueModel &model,
        const float *context,
        std::array<double, FK_VALUE_MODEL_V3_MODEL_FEATURES> &features) {
    if (!valid_context(context))
        return false;
    for (size_t index = 0u;
         index < FK_VALUE_MODEL_V3_CONTEXT_FEATURES; ++index) {
        features[index] =
            (context[index] - model.action_ridge_mean[index]) /
            model.action_ridge_scale[index];
    }
    /* Hybrid trees are trained on the deployed 64D context only.  Keep the
     * query suffix deterministically zero so a malformed artifact cannot
     * inherit stale stack state. */
    features[64] = 0.0;
    features[65] = 0.0;
    features[66] = 0.0;
    return true;
}

static bool predict_mean(
        const ValueModel &model,
        const std::array<double, FK_VALUE_MODEL_V3_MODEL_FEATURES> &features,
        uint8_t action,
        float &output) {
    double value = 0.0;
    if (model.metadata.family == FK_VALUE_MODEL_V3_ACTION_RIDGE) {
        if (action < 1u || action > FK_VALUE_MODEL_V3_ACTIONS)
            return false;
        const size_t head = static_cast<size_t>(action - 1u);
        value = model.action_ridge_intercepts[head];
        for (size_t index = 0u;
             index < FK_VALUE_MODEL_V3_CONTEXT_FEATURES; ++index) {
            value += features[index] *
                model.action_ridge_weights[head][index];
        }
    } else if (model.metadata.family == FK_VALUE_MODEL_V3_RIDGE) {
        value = model.ridge_intercept;
        for (size_t index = 0u; index < features.size(); ++index)
            value += features[index] * model.ridge_weights[index];
    } else if (model.metadata.family == FK_VALUE_MODEL_V3_BOUNDED_TREE) {
        size_t index = 0u;
        for (size_t steps = 0u; steps < model.tree.size(); ++steps) {
            if (index >= model.tree.size())
                return false;
            const Node &node = model.tree[index];
            if (node.feature == -1) {
                value = node.value;
                break;
            }
            index = features[static_cast<size_t>(node.feature)] <= node.threshold
                ? static_cast<size_t>(node.left)
                : static_cast<size_t>(node.right);
            if (steps + 1u == model.tree.size())
                return false;
        }
    } else {
        const size_t hidden_units = model.metadata.hidden_units;
        std::array<double, kMaximumHiddenUnits> hidden{};
        for (size_t hidden_index = 0u; hidden_index < hidden_units;
             ++hidden_index) {
            double local = model.mlp_hidden_bias[hidden_index];
            for (size_t feature = 0u; feature < features.size(); ++feature) {
                local += features[feature] * model.mlp_input_weights[
                    feature * hidden_units + hidden_index];
            }
            hidden[hidden_index] = std::max(0.0, local);
        }
        value = model.mlp_output_bias;
        for (size_t index = 0u; index < hidden_units; ++index)
            value += hidden[index] * model.mlp_output_weights[index];
    }
    value = std::min(
        static_cast<double>(model.clip_max),
        std::max(static_cast<double>(model.clip_min), value));
    if (!std::isfinite(value))
        return false;
    output = static_cast<float>(value);
    return std::isfinite(output);
}

static bool evaluate_tree(
        const std::vector<Node> &nodes,
        const std::array<double, FK_VALUE_MODEL_V3_MODEL_FEATURES> &features,
        double &output) {
    size_t index = 0u;
    for (size_t steps = 0u; steps < nodes.size(); ++steps) {
        if (index >= nodes.size())
            return false;
        const Node &node = nodes[index];
        if (node.feature == -1) {
            output = node.value;
            return std::isfinite(output);
        }
        index = features[static_cast<size_t>(node.feature)] <= node.threshold
            ? static_cast<size_t>(node.left)
            : static_cast<size_t>(node.right);
    }
    return false;
}

static bool predict_hybrid_all(
        const ValueModel &model,
        const float context[FK_VALUE_MODEL_V3_CONTEXT_FEATURES],
        float outputs[FK_VALUE_MODEL_V3_OUTPUTS]) {
    std::array<double, FK_VALUE_MODEL_V3_ACTIONS> gate{};
    std::array<double, FK_VALUE_MODEL_V3_ACTIONS> conditional{};
    std::array<double, FK_VALUE_MODEL_V3_MODEL_FEATURES> features{};
    if (!normalized_action_context(model, context, features))
        return false;
    for (size_t head = 0u; head < FK_VALUE_MODEL_V3_ACTIONS; ++head) {
        double gate_value = model.action_ridge_intercepts[head];
        for (size_t feature = 0u;
             feature < FK_VALUE_MODEL_V3_CONTEXT_FEATURES; ++feature) {
            gate_value += features[feature] *
                model.action_ridge_weights[head][feature];
        }
        gate[head] = gate_value;
        conditional[head] = model.conditional_bias[head];
    }
    for (const ConditionalTree &tree : model.conditional_trees) {
        if (tree.action < 1u || tree.action > FK_VALUE_MODEL_V3_ACTIONS)
            return false;
        double leaf = 0.0;
        if (!evaluate_tree(tree.nodes, features, leaf))
            return false;
        conditional[tree.action - 1u] +=
            static_cast<double>(tree.learning_rate) * leaf;
    }
    const double gate_scale = std::max(
        0.0, *std::max_element(gate.begin(), gate.end()));
    double conditional_scale = 0.0;
    for (double value : conditional)
        conditional_scale = std::max(conditional_scale, value);
    conditional_scale = std::max(0.0, conditional_scale);
    const double equivalence_floor = conditional_scale *
        (1.0 - static_cast<double>(
            model.metadata.conditional_equivalence_tolerance));
    for (size_t head = 0u; head < FK_VALUE_MODEL_V3_ACTIONS; ++head) {
        const double positive_conditional =
            std::max(0.0, conditional[head]);
        double value = 0.0;
        if (conditional_scale > 1.0e-12) {
            value = positive_conditional >= equivalence_floor
                ? gate_scale
                : gate_scale * positive_conditional / conditional_scale;
        }
        value = std::min(
            static_cast<double>(model.clip_max),
            std::max(static_cast<double>(model.clip_min), value));
        if (!std::isfinite(value))
            return false;
        outputs[head] = static_cast<float>(value);
        outputs[FK_VALUE_MODEL_V3_ACTIONS + head] =
            model.uncertainty[head];
    }
    return true;
}

static bool predict_action_ridge_all(
        const ValueModel &model,
        const float context[FK_VALUE_MODEL_V3_CONTEXT_FEATURES],
        float outputs[FK_VALUE_MODEL_V3_OUTPUTS]) {
    std::array<double, FK_VALUE_MODEL_V3_MODEL_FEATURES> features{};
    if (!normalized_action_context(model, context, features))
        return false;
    for (size_t head = 0u; head < FK_VALUE_MODEL_V3_ACTIONS; ++head) {
        double value = model.action_ridge_intercepts[head];
        for (size_t feature = 0u;
             feature < FK_VALUE_MODEL_V3_CONTEXT_FEATURES; ++feature) {
            value += features[feature] *
                model.action_ridge_weights[head][feature];
        }
        value = std::min(
            static_cast<double>(model.clip_max),
            std::max(static_cast<double>(model.clip_min), value));
        if (!std::isfinite(value) ||
            !std::isfinite(model.uncertainty[head]) ||
            model.uncertainty[head] < 0.0f)
            return false;
        outputs[head] = static_cast<float>(value);
        outputs[FK_VALUE_MODEL_V3_ACTIONS + head] =
            model.uncertainty[head];
    }
    return true;
}

}  // namespace

extern "C" {

fk_value_model_v3 *fk_value_model_v3_load(
        const char *path,
        char *error,
        size_t error_capacity) {
    return fk_value_model_v3_load_verified(
        path, nullptr, error, error_capacity);
}

fk_value_model_v3 *fk_value_model_v3_load_verified(
        const char *path,
        const char *expected_artifact_sha256,
        char *error,
        size_t error_capacity) {
    set_error(error, error_capacity, "");
    if (path == nullptr || path[0] == '\0') {
        set_error(error, error_capacity, "value-v3 path is empty");
        return nullptr;
    }
    if (expected_artifact_sha256 != nullptr &&
        !valid_sha256(expected_artifact_sha256)) {
        set_error(error, error_capacity, "value-v3 expected SHA-256 is invalid");
        return nullptr;
    }
    FILE *stream = std::fopen(path, "rb");
    if (stream == nullptr) {
        set_error(error, error_capacity,
                  std::string("cannot open value-v3 model: ") +
                  std::strerror(errno));
        return nullptr;
    }
    char artifact_sha256[FK_VALUE_MODEL_V3_SCHEMA_SHA256_CHARS + 1u]{};
    if (!hash_and_rewind(stream, artifact_sha256) ||
        (expected_artifact_sha256 != nullptr &&
         std::strcmp(artifact_sha256, expected_artifact_sha256) != 0)) {
        std::fclose(stream);
        set_error(error, error_capacity, "value-v3 artifact SHA-256 mismatch");
        return nullptr;
    }
    struct stat status {};
    if (::fstat(::fileno(stream), &status) != 0 ||
        !S_ISREG(status.st_mode) || status.st_size <= 0 ||
        static_cast<uint64_t>(status.st_size) > kMaximumFileBytes) {
        std::fclose(stream);
        set_error(error, error_capacity, "value-v3 model is not a bounded file");
        return nullptr;
    }
    ValueModel *model = new (std::nothrow) ValueModel();
    if (model == nullptr) {
        std::fclose(stream);
        set_error(error, error_capacity, "value-v3 allocation failed");
        return nullptr;
    }
    char magic[48];
    unsigned int version = 0u;
    bool valid = std::fscanf(stream, "%47s %u", magic, &version) == 2 &&
        std::strcmp(magic, "FLOWKEEP_VALUE_MODEL_V3") == 0 &&
        (version == kLegacyFormatVersion || version == kCurrentFormatVersion);
    model->metadata.format_version = version;
    valid = valid && read_role(stream, model->metadata.role);
    valid = valid && read_family(stream, model->metadata.family);
    valid = valid && token(stream, "online_context_schema_sha256") &&
        std::fscanf(stream, "%64s",
                    model->metadata.online_context_schema_sha256) == 1 &&
        valid_sha256(model->metadata.online_context_schema_sha256);
    valid = valid && token(stream, "requested_action_domain_sha256") &&
        std::fscanf(stream, "%64s",
                    model->metadata.requested_action_domain_sha256) == 1 &&
        valid_sha256(model->metadata.requested_action_domain_sha256) &&
        std::strcmp(
            model->metadata.requested_action_domain_sha256,
            FK_VALUE_MODEL_V3_REQUESTED_ACTION_DOMAIN_SHA256) == 0;
    valid = valid && token(stream, "online_deadline_contract_sha256") &&
        std::fscanf(stream, "%64s",
                    model->metadata.online_deadline_contract_sha256) == 1 &&
        valid_sha256(model->metadata.online_deadline_contract_sha256) &&
        std::strcmp(
            model->metadata.online_deadline_contract_sha256,
            FK_VALUE_MODEL_V3_ONLINE_DEADLINE_CONTRACT_SHA256) == 0;
    unsigned int threshold_used = 0u;
    unsigned int threshold_bits = 0u;
    unsigned int formal_event_semantics_aligned = 0u;
    if (version == kCurrentFormatVersion) {
        valid = valid && token(
            stream, "training_target_uses_detector_threshold") &&
            std::fscanf(stream, "%u", &threshold_used) == 1 &&
            threshold_used <= 1u;
        valid = valid && token(
            stream, "formal_event_student_counterfactual_semantics_aligned") &&
            std::fscanf(stream, "%u", &formal_event_semantics_aligned) == 1 &&
            formal_event_semantics_aligned <= 1u;
        valid = valid && token(stream, "detector_threshold_bits") &&
            std::fscanf(stream, "%u", &threshold_bits) == 1;
        float detector_threshold = 0.0f;
        std::memcpy(
            &detector_threshold, &threshold_bits, sizeof(detector_threshold));
        valid = valid && (
            (threshold_used == 0u && threshold_bits == 0u) ||
            (threshold_used == 1u && std::isfinite(detector_threshold) &&
             detector_threshold > 0.0f && detector_threshold < 1.0f));
        valid = valid && token(stream, "detector_threshold_binding_sha256") &&
            std::fscanf(stream, "%64s",
                        model->metadata.detector_threshold_binding_sha256) == 1;
        valid = valid && (threshold_used == 1u
            ? valid_sha256(model->metadata.detector_threshold_binding_sha256)
            : std::strcmp(
                model->metadata.detector_threshold_binding_sha256,
                "none") == 0);
        valid = valid && token(
            stream, "detector_threshold_selection_receipt_sha256") &&
            std::fscanf(
                stream, "%64s",
                model->metadata.detector_threshold_selection_receipt_sha256
            ) == 1;
        valid = valid && (threshold_used == 1u
            ? valid_sha256(
                model->metadata.detector_threshold_selection_receipt_sha256)
            : std::strcmp(
                model->metadata.detector_threshold_selection_receipt_sha256,
                "none") == 0);
        valid = valid && token(
            stream, "detector_operating_point_receipt_sha256") &&
            std::fscanf(
                stream, "%64s",
                model->metadata.detector_operating_point_receipt_sha256
            ) == 1;
        valid = valid && (threshold_used == 1u
            ? valid_sha256(
                model->metadata.detector_operating_point_receipt_sha256)
            : std::strcmp(
                model->metadata.detector_operating_point_receipt_sha256,
                "none") == 0);
    } else {
        /* V1 predates detector-threshold provenance fields.  Preserve its
         * numeric model exactly and expose conservative, unattested metadata;
         * deployment must separately bind the immutable training receipt. */
        std::snprintf(
            model->metadata.detector_threshold_binding_sha256,
            sizeof(model->metadata.detector_threshold_binding_sha256),
            "%s", "none");
        std::snprintf(
            model->metadata.detector_threshold_selection_receipt_sha256,
            sizeof(
                model->metadata.detector_threshold_selection_receipt_sha256),
            "%s", "none");
        std::snprintf(
            model->metadata.detector_operating_point_receipt_sha256,
            sizeof(model->metadata.detector_operating_point_receipt_sha256),
            "%s", "none");
    }
    model->metadata.training_target_uses_detector_threshold = threshold_used;
    model->metadata.formal_event_student_counterfactual_semantics_aligned =
        formal_event_semantics_aligned;
    model->metadata.detector_threshold_bits = threshold_bits;
    unsigned int context_count = 0u;
    unsigned int query_count = 0u;
    unsigned int model_count = 0u;
    unsigned int action_count = 0u;
    unsigned int output_count = 0u;
    valid = valid && token(stream, "context_feature_count") &&
        std::fscanf(stream, "%u", &context_count) == 1 &&
        context_count == FK_VALUE_MODEL_V3_CONTEXT_FEATURES;
    valid = valid && token(stream, "query_feature_count") &&
        std::fscanf(stream, "%u", &query_count) == 1 &&
        query_count == FK_VALUE_MODEL_V3_QUERY_FEATURES;
    valid = valid && token(stream, "model_feature_count") &&
        std::fscanf(stream, "%u", &model_count) == 1 &&
        model_count == FK_VALUE_MODEL_V3_MODEL_FEATURES;
    valid = valid && token(stream, "learned_action_count") &&
        std::fscanf(stream, "%u", &action_count) == 1 &&
        action_count == FK_VALUE_MODEL_V3_ACTIONS;
    valid = valid && token(stream, "output_count") &&
        std::fscanf(stream, "%u", &output_count) == 1 &&
        output_count == FK_VALUE_MODEL_V3_OUTPUTS;
    model->metadata.context_feature_count = context_count;
    model->metadata.query_feature_count = query_count;
    model->metadata.model_feature_count = model_count;
    model->metadata.learned_action_count = action_count;
    model->metadata.output_count = output_count;
    valid = valid && token(stream, "value_clip") &&
        std::fscanf(stream, "%f %f", &model->clip_min, &model->clip_max) == 2 &&
        std::isfinite(model->clip_min) && std::isfinite(model->clip_max) &&
        model->clip_min < model->clip_max;
    if (valid &&
        (model->metadata.family == FK_VALUE_MODEL_V3_ACTION_RIDGE ||
         model->metadata.family == FK_VALUE_MODEL_V3_HYBRID_GATE_FOREST)) {
        valid = read_finite_array(
            stream, "normalization_mean", model->action_ridge_mean);
        valid = valid && read_finite_array(
            stream, "normalization_scale", model->action_ridge_scale, true);
    } else {
        valid = valid && read_finite_array(
            stream, "normalization_mean", model->mean);
        valid = valid && read_finite_array(
            stream, "normalization_scale", model->scale, true);
    }
    valid = valid && read_finite_array(
        stream, "uncertainty", model->uncertainty);
    valid = valid && std::all_of(
        model->uncertainty.begin(), model->uncertainty.end(),
        [](float value) { return value >= 0.0f; });
    if (valid && model->metadata.family == FK_VALUE_MODEL_V3_RIDGE) {
        valid = token(stream, "ridge_intercept") &&
            std::fscanf(stream, "%f", &model->ridge_intercept) == 1 &&
            std::isfinite(model->ridge_intercept) &&
            read_finite_array(stream, "ridge_weights", model->ridge_weights);
    } else if (valid &&
               (model->metadata.family == FK_VALUE_MODEL_V3_ACTION_RIDGE ||
                model->metadata.family ==
                    FK_VALUE_MODEL_V3_HYBRID_GATE_FOREST)) {
        unsigned int head_count = 0u;
        valid = token(stream, "action_ridge_head_count") &&
            std::fscanf(stream, "%u", &head_count) == 1 &&
            head_count == FK_VALUE_MODEL_V3_ACTIONS;
        for (uint32_t index = 0u;
             valid && index < FK_VALUE_MODEL_V3_ACTIONS; ++index) {
            unsigned int action_mask = 0u;
            float intercept = 0.0f;
            valid = token(stream, "action_ridge_head") &&
                std::fscanf(
                    stream, "%u %f", &action_mask, &intercept) == 2 &&
                action_mask == index + 1u && std::isfinite(intercept);
            model->action_ridge_intercepts[index] = intercept;
            for (float &weight : model->action_ridge_weights[index]) {
                if (!valid || std::fscanf(stream, "%f", &weight) != 1 ||
                    !std::isfinite(weight)) {
                    valid = false;
                    break;
                }
            }
        }
        if (valid && model->metadata.family ==
                FK_VALUE_MODEL_V3_HYBRID_GATE_FOREST) {
            float equivalence_tolerance = 0.0f;
            valid = token(stream, "conditional_equivalence_tolerance") &&
                std::fscanf(stream, "%f", &equivalence_tolerance) == 1 &&
                std::isfinite(equivalence_tolerance) &&
                equivalence_tolerance >= 0.0f &&
                equivalence_tolerance < 1.0f;
            model->metadata.conditional_equivalence_tolerance =
                equivalence_tolerance;
            unsigned int conditional_head_count = 0u;
            valid = token(stream, "conditional_head_count") &&
                std::fscanf(stream, "%u", &conditional_head_count) == 1 &&
                conditional_head_count == FK_VALUE_MODEL_V3_ACTIONS;
            uint32_t total_nodes = 0u;
            uint32_t total_trees = 0u;
            for (uint32_t head = 0u;
                 valid && head < FK_VALUE_MODEL_V3_ACTIONS; ++head) {
                unsigned int action_mask = 0u;
                unsigned int tree_count = 0u;
                float bias = 0.0f;
                valid = token(stream, "conditional_head") &&
                    std::fscanf(
                        stream, "%u %f %u", &action_mask, &bias,
                        &tree_count) == 3 &&
                    action_mask == head + 1u && std::isfinite(bias) &&
                    tree_count > 0u &&
                    total_trees + tree_count <= kMaximumConditionalTrees;
                model->conditional_bias[head] = bias;
                for (uint32_t tree_index = 0u;
                     valid && tree_index < tree_count; ++tree_index) {
                    unsigned int declared_action = 0u;
                    unsigned int node_count = 0u;
                    float learning_rate = 0.0f;
                    valid = token(stream, "conditional_tree") &&
                        std::fscanf(
                            stream, "%u %f %u", &declared_action,
                            &learning_rate, &node_count) == 3 &&
                        declared_action == action_mask &&
                        std::isfinite(learning_rate) && learning_rate > 0.0f &&
                        node_count > 0u && node_count <= kMaximumTreeNodes;
                    ConditionalTree tree{};
                    tree.action = static_cast<uint8_t>(action_mask);
                    tree.learning_rate = learning_rate;
                    tree.nodes.reserve(node_count);
                    for (uint32_t node_index = 0u;
                         valid && node_index < node_count; ++node_index) {
                        Node node{};
                        valid = token(stream, "node") &&
                            std::fscanf(
                                stream, "%d %d %d %f %f",
                                &node.left, &node.right, &node.feature,
                                &node.threshold, &node.value) == 5;
                        tree.nodes.push_back(node);
                    }
                    valid = valid && validate_tree(tree.nodes) &&
                        std::all_of(
                            tree.nodes.begin(), tree.nodes.end(),
                            [](const Node &node) {
                                return node.feature < 0 ||
                                    static_cast<uint32_t>(node.feature) <
                                        FK_VALUE_MODEL_V3_CONTEXT_FEATURES;
                            });
                    total_nodes += node_count;
                    model->conditional_trees.push_back(std::move(tree));
                }
                total_trees += tree_count;
            }
            model->metadata.node_count = total_nodes;
            valid = valid && total_trees == model->conditional_trees.size();
        }
    } else if (valid &&
               model->metadata.family == FK_VALUE_MODEL_V3_BOUNDED_TREE) {
        unsigned int node_count = 0u;
        valid = token(stream, "tree_node_count") &&
            std::fscanf(stream, "%u", &node_count) == 1 &&
            node_count > 0u && node_count <= kMaximumTreeNodes;
        model->metadata.node_count = node_count;
        model->tree.reserve(node_count);
        for (uint32_t index = 0u; valid && index < node_count; ++index) {
            Node node{};
            valid = token(stream, "node") &&
                std::fscanf(stream, "%d %d %d %f %f",
                            &node.left, &node.right, &node.feature,
                            &node.threshold, &node.value) == 5;
            model->tree.push_back(node);
        }
        valid = valid && validate_tree(model->tree);
    } else if (valid &&
               model->metadata.family == FK_VALUE_MODEL_V3_LIGHT_MLP) {
        unsigned int hidden_units = 0u;
        valid = token(stream, "mlp_hidden_units") &&
            std::fscanf(stream, "%u", &hidden_units) == 1 &&
            hidden_units > 0u && hidden_units <= kMaximumHiddenUnits;
        model->metadata.hidden_units = hidden_units;
        model->mlp_input_weights.resize(
            FK_VALUE_MODEL_V3_MODEL_FEATURES * hidden_units);
        model->mlp_hidden_bias.resize(hidden_units);
        model->mlp_output_weights.resize(hidden_units);
        valid = valid && read_finite_vector(
            stream, "mlp_input_weights", model->mlp_input_weights);
        valid = valid && read_finite_vector(
            stream, "mlp_hidden_bias", model->mlp_hidden_bias);
        valid = valid && read_finite_vector(
            stream, "mlp_output_weights", model->mlp_output_weights);
        valid = valid && token(stream, "mlp_output_bias") &&
            std::fscanf(stream, "%f", &model->mlp_output_bias) == 1 &&
            std::isfinite(model->mlp_output_bias);
    }
    valid = valid && token(stream, "end");
    char trailing[2];
    valid = valid && std::fscanf(stream, "%1s", trailing) == EOF;
    struct stat status_after {};
    valid = valid && ::fstat(::fileno(stream), &status_after) == 0 &&
        same_file_snapshot(status, status_after);
    if (valid) {
        std::memcpy(
            model->metadata.artifact_sha256,
            artifact_sha256,
            sizeof(model->metadata.artifact_sha256));
        model->metadata.artifact_file_bytes =
            static_cast<uint64_t>(status.st_size);
        model->metadata.model_reserved_bytes = reserved_model_bytes(*model);
    }
    std::fclose(stream);
    if (!valid) {
        delete model;
        set_error(error, error_capacity, "invalid value-v3 model contract");
        return nullptr;
    }
    return reinterpret_cast<fk_value_model_v3 *>(model);
}

void fk_value_model_v3_destroy(fk_value_model_v3 *model) {
    delete implementation(model);
}

bool fk_value_model_v3_get_metadata(
        const fk_value_model_v3 *model,
        fk_value_model_v3_metadata *metadata) {
    if (model == nullptr || metadata == nullptr)
        return false;
    *metadata = implementation(model)->metadata;
    return true;
}

bool fk_value_model_v3_predict_action(
        const fk_value_model_v3 *model,
        const float context[FK_VALUE_MODEL_V3_CONTEXT_FEATURES],
        uint8_t action_mask,
        float *mean,
        float *uncertainty) {
    if (model == nullptr || mean == nullptr || uncertainty == nullptr)
        return false;
    const ValueModel &state = *implementation(model);
    if (state.metadata.family == FK_VALUE_MODEL_V3_HYBRID_GATE_FOREST) {
        if (action_mask < 1u || action_mask > FK_VALUE_MODEL_V3_ACTIONS)
            return false;
        std::array<float, FK_VALUE_MODEL_V3_OUTPUTS> outputs{};
        if (!predict_hybrid_all(state, context, outputs.data()))
            return false;
        *mean = outputs[action_mask - 1u];
        *uncertainty = outputs[
            FK_VALUE_MODEL_V3_ACTIONS + action_mask - 1u];
        return true;
    }
    std::array<double, FK_VALUE_MODEL_V3_MODEL_FEATURES> features{};
    if (!model_features(state, context, action_mask, features) ||
        !predict_mean(state, features, action_mask, *mean))
        return false;
    *uncertainty = state.uncertainty[action_mask - 1u];
    return std::isfinite(*uncertainty) && *uncertainty >= 0.0f;
}

bool fk_value_model_v3_predict_all(
        const fk_value_model_v3 *model,
        const float context[FK_VALUE_MODEL_V3_CONTEXT_FEATURES],
        float outputs[FK_VALUE_MODEL_V3_OUTPUTS]) {
    if (model == nullptr || outputs == nullptr)
        return false;
    const ValueModel &state = *implementation(model);
    if (state.metadata.family == FK_VALUE_MODEL_V3_HYBRID_GATE_FOREST)
        return predict_hybrid_all(state, context, outputs);
    if (state.metadata.family == FK_VALUE_MODEL_V3_ACTION_RIDGE)
        return predict_action_ridge_all(state, context, outputs);
    for (uint8_t action = 1u; action <= 7u; ++action) {
        if (!fk_value_model_v3_predict_action(
                model, context, action, &outputs[action - 1u],
                &outputs[7u + action - 1u]))
            return false;
    }
    return true;
}

}  // extern "C"
