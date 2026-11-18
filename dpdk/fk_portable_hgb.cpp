#include "fk_portable_hgb.h"

#include <algorithm>
#include <cmath>
#include <cstdio>
#include <cstring>
#include <memory>
#include <new>
#include <string>
#include <vector>

namespace {

struct Node {
    int32_t feature;
    int32_t left;
    int32_t right;
    int32_t missing_left;
    double threshold;
    double value;
};
static_assert(sizeof(Node) == 32u, "FKMETA3 node ABI changed");

struct Model {
    uint32_t feature_count = 0u;
    uint32_t classifier = 0u;
    double bias = 0.0;
    std::vector<int32_t> roots;
    std::vector<Node> nodes;
};

void fail(char *error, size_t capacity, const char *message) {
    if (error != nullptr && capacity != 0u)
        std::snprintf(error, capacity, "%s", message);
}

bool valid(const Model &model) {
    if (model.feature_count == 0u || model.classifier > 1u ||
        !std::isfinite(model.bias) || model.roots.empty() ||
        model.nodes.empty())
        return false;
    for (int32_t root : model.roots)
        if (root < 0 || static_cast<size_t>(root) >= model.nodes.size())
            return false;
    for (size_t index = 0u; index < model.nodes.size(); ++index) {
        const Node &node = model.nodes[index];
        if (!std::isfinite(node.threshold) || !std::isfinite(node.value) ||
            node.missing_left < 0 || node.missing_left > 1)
            return false;
        if (node.feature < 0) {
            if (node.feature != -1)
                return false;
        } else if (static_cast<uint32_t>(node.feature) >= model.feature_count ||
                   node.left <= static_cast<int32_t>(index) ||
                   node.right <= static_cast<int32_t>(index) ||
                   static_cast<size_t>(node.left) >= model.nodes.size() ||
                   static_cast<size_t>(node.right) >= model.nodes.size()) {
            return false;
        }
    }
    return true;
}

}  // namespace

struct fk_portable_hgb { Model value; };

extern "C" fk_portable_hgb *fk_portable_hgb_load(
        const char *path, uint32_t expected_features,
        char *error, size_t error_capacity) {
    if (error != nullptr && error_capacity != 0u)
        error[0] = '\0';
    FILE *file = path == nullptr ? nullptr : std::fopen(path, "rb");
    if (file == nullptr) {
        fail(error, error_capacity, "cannot open FKMETA3 model");
        return nullptr;
    }
    auto result = std::unique_ptr<fk_portable_hgb>(
        new (std::nothrow) fk_portable_hgb());
    char magic[8]{};
    uint32_t trees = 0u, nodes = 0u;
    bool ok = result != nullptr &&
        std::fread(magic, 1u, sizeof(magic), file) == sizeof(magic) &&
        std::memcmp(magic, "FKMETA3\0", sizeof(magic)) == 0 &&
        std::fread(&trees, sizeof(trees), 1u, file) == 1u &&
        std::fread(&nodes, sizeof(nodes), 1u, file) == 1u &&
        std::fread(&result->value.feature_count,
                   sizeof(result->value.feature_count), 1u, file) == 1u &&
        std::fread(&result->value.classifier,
                   sizeof(result->value.classifier), 1u, file) == 1u &&
        std::fread(&result->value.bias,
                   sizeof(result->value.bias), 1u, file) == 1u &&
        trees != 0u && trees <= 4096u &&
        nodes != 0u && nodes <= 1000000u &&
        (expected_features == 0u ||
         result->value.feature_count == expected_features);
    try {
        if (ok) {
            result->value.roots.resize(trees);
            result->value.nodes.resize(nodes);
            ok = std::fread(result->value.roots.data(), sizeof(int32_t),
                            trees, file) == trees &&
                std::fread(result->value.nodes.data(), sizeof(Node),
                           nodes, file) == nodes &&
                std::fgetc(file) == EOF && valid(result->value);
        }
    } catch (...) {
        ok = false;
    }
    (void)std::fclose(file);
    if (!ok) {
        fail(error, error_capacity, "FKMETA3 model is malformed or incompatible");
        return nullptr;
    }
    return result.release();
}

extern "C" void fk_portable_hgb_destroy(fk_portable_hgb *model) {
    delete model;
}

extern "C" uint32_t fk_portable_hgb_feature_count(
        const fk_portable_hgb *model) {
    return model == nullptr ? 0u : model->value.feature_count;
}

extern "C" bool fk_portable_hgb_predict(
        const fk_portable_hgb *model, const double *features,
        size_t feature_count, double *probability) {
    if (model == nullptr || features == nullptr || probability == nullptr ||
        feature_count < model->value.feature_count)
        return false;
    double raw = model->value.bias;
    for (int32_t root : model->value.roots) {
        int32_t index = root;
        while (model->value.nodes[static_cast<size_t>(index)].feature >= 0) {
            const Node &node = model->value.nodes[static_cast<size_t>(index)];
            const double value = features[node.feature];
            const bool left = std::isnan(value)
                ? node.missing_left != 0 : value <= node.threshold;
            index = left ? node.left : node.right;
        }
        raw += model->value.nodes[static_cast<size_t>(index)].value;
    }
    *probability = model->value.classifier != 0u
        ? 1.0 / (1.0 + std::exp(-raw))
        : std::min(1.0, std::max(0.0, raw));
    return std::isfinite(*probability) && *probability >= 0.0 &&
        *probability <= 1.0;
}
