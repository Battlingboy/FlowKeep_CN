#include "fk_portable_hgb.h"

#include <cassert>
#include <cmath>
#include <cstdio>
#include <cstring>
#include <string>
#include <unistd.h>

struct Node {
    int32_t feature, left, right, missing_left;
    double threshold, value;
};

int main() {
    char path[] = "/tmp/fk-portable-hgb-XXXXXX";
    const int descriptor = mkstemp(path);
    assert(descriptor >= 0);
    FILE *file = fdopen(descriptor, "wb");
    assert(file != nullptr);
    const char magic[8] = {'F','K','M','E','T','A','3','\0'};
    const uint32_t trees = 1u, nodes = 3u, features = 2u, classifier = 1u;
    const double bias = 0.0;
    const int32_t root = 0;
    const Node body[] = {
        {0, 1, 2, 1, .5, 0.0},
        {-1, 1, 1, 0, 0.0, -1.0},
        {-1, 2, 2, 0, 0.0, 1.0},
    };
    assert(fwrite(magic, 1, sizeof(magic), file) == sizeof(magic));
    assert(fwrite(&trees, sizeof(trees), 1, file) == 1);
    assert(fwrite(&nodes, sizeof(nodes), 1, file) == 1);
    assert(fwrite(&features, sizeof(features), 1, file) == 1);
    assert(fwrite(&classifier, sizeof(classifier), 1, file) == 1);
    assert(fwrite(&bias, sizeof(bias), 1, file) == 1);
    assert(fwrite(&root, sizeof(root), 1, file) == 1);
    assert(fwrite(body, sizeof(Node), 3, file) == 3);
    assert(fclose(file) == 0);

    char error[128]{};
    fk_portable_hgb *model = fk_portable_hgb_load(path, 2u, error, sizeof(error));
    assert(model != nullptr && fk_portable_hgb_feature_count(model) == 2u);
    double low[] = {.25, 0.0}, high[] = {.75, 0.0}, output = 0.0;
    assert(fk_portable_hgb_predict(model, low, 2u, &output));
    assert(std::fabs(output - 1.0 / (1.0 + std::exp(1.0))) < 1e-12);
    assert(fk_portable_hgb_predict(model, high, 2u, &output));
    assert(std::fabs(output - 1.0 / (1.0 + std::exp(-1.0))) < 1e-12);
    fk_portable_hgb_destroy(model);
    assert(fk_portable_hgb_load(path, 3u, error, sizeof(error)) == nullptr);
    assert(std::remove(path) == 0);
    return 0;
}
