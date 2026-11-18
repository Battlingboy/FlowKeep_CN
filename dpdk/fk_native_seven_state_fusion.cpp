#include "fk_native_seven_state_fusion.h"

#include <algorithm>
#include <chrono>
#include <array>
#include <atomic>
#include <cerrno>
#include <cmath>
#include <condition_variable>
#include <cstdio>
#include <cstring>
#include <functional>
#include <limits>
#include <memory>
#include <mutex>
#include <new>
#include <openssl/evp.h>
#include <string>
#include <stdexcept>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <thread>
#include <unistd.h>
#include <unordered_map>
#include <utility>
#include <vector>

namespace {

constexpr char kMagic[8] = {'F', 'K', 'F', 'U', 'S', 'N', '1', '\0'};
constexpr uint32_t kVersion = 1u;
constexpr uint32_t kEndianTag = UINT32_C(0x01020304);
constexpr uint32_t kHeaderBytes = 256u;
constexpr uint32_t kEnsembleCount = 10u;
constexpr uint32_t kReferenceCount = 4u;
constexpr uint32_t kProjectedFeatures = 139u;
constexpr uint32_t kMaximumThreads = 32u;
constexpr uint32_t kMaximumTrees = 4096u;
constexpr uint32_t kMaximumNodes = 6000000u;
constexpr uint32_t kMaximumReferenceLength = 1000000u;
constexpr std::size_t kMaximumBatch = 1048576u;
/* The production online service dispatches batches of at most 512 rows.
 * Keep ExtraTrees parallelism tree-major when their deduplicated meta rows
 * fit that complete range: every worker then walks a disjoint model region
 * and the ordered reduction below preserves bit-for-bit scoring semantics. */
constexpr std::size_t kTreeParallelMaximumUniqueMetaRows = 512u;

constexpr uint32_t kHistogramLogit = 1u;
constexpr uint32_t kGradientLogit = 2u;
constexpr uint32_t kExtraTreesProbability = 3u;
constexpr uint16_t kNodeLeaf = 1u;
constexpr uint16_t kNodeMissingLeft = 2u;

struct Header {
    char magic[8];
    uint32_t version;
    uint32_t header_bytes;
    uint32_t endian_tag;
    uint32_t ensemble_count;
    uint32_t tree_count;
    uint32_t node_count;
    uint32_t reference_count;
    uint32_t raw_features;
    uint32_t projected_features;
    uint32_t meta_features;
    uint32_t state_heads;
    uint32_t reference_length;
    uint64_t ensemble_offset;
    uint64_t tree_offset;
    uint64_t node_offset;
    uint64_t reference_offset;
    uint64_t file_bytes;
    uint64_t reserved0;
    uint8_t source_model_sha256[32];
    double weights[4];
    double threshold;
    uint8_t reserved[80];
};

struct Ensemble {
    uint32_t kind;
    uint32_t feature_count;
    uint32_t tree_first;
    uint32_t tree_count;
    double bias;
    double divisor;
};

struct Tree {
    uint64_t node_first;
    uint32_t node_count;
    uint32_t reserved;
    double scale;
};

struct Node {
    double split_or_value;
    uint16_t left;
    uint16_t right;
    int16_t feature;
    uint16_t flags;
};

struct FloatNode {
    float split;
    uint8_t left, right, feature, leaf;
};
static_assert(sizeof(FloatNode) == 8u, "compact float node layout");

static_assert(sizeof(Header) == 256u, "native fusion header ABI changed");
static_assert(sizeof(Ensemble) == 32u, "native fusion ensemble ABI changed");
static_assert(sizeof(Tree) == 24u, "native fusion tree ABI changed");
static_assert(sizeof(Node) == 16u, "native fusion node ABI changed");

struct MappedModel {
    void *mapping = MAP_FAILED;
    std::size_t mapping_bytes = 0u;
    bool locked = false;
    const Header *header = nullptr;
    const Ensemble *ensembles = nullptr;
    const Tree *trees = nullptr;
    const Node *nodes = nullptr;
    const double *references = nullptr;
    std::vector<FloatNode> float_nodes;
    std::vector<uint8_t> compact_trees;

    ~MappedModel() {
        if (mapping != MAP_FAILED) {
            if (locked)
                (void)::munlock(mapping, mapping_bytes);
            ::munmap(mapping, mapping_bytes);
        }
    }
};

class WorkerPool {
  public:
    explicit WorkerPool(uint32_t maximum_threads)
        : maximum_threads_(maximum_threads) {
        workers_.reserve(maximum_threads_ > 0u ? maximum_threads_ - 1u : 0u);
        for (uint32_t id = 1u; id < maximum_threads_; ++id)
            workers_.emplace_back([this, id]() { worker(id); });
    }

    WorkerPool(const WorkerPool &) = delete;
    WorkerPool &operator=(const WorkerPool &) = delete;

    ~WorkerPool() {
        {
            std::lock_guard<std::mutex> lock(mutex_);
            stopping_ = true;
            generation_++;
        }
        start_.notify_all();
        for (std::thread &worker_thread : workers_)
            worker_thread.join();
    }

    void run(uint32_t threads, const std::function<void(uint32_t)> &task) {
        if (threads <= 1u) {
            task(0u);
            return;
        }
        {
            std::lock_guard<std::mutex> lock(mutex_);
            task_ = task;
            active_threads_ = threads;
            pending_ = threads - 1u;
            generation_++;
        }
        start_.notify_all();
        task(0u);
        std::unique_lock<std::mutex> lock(mutex_);
        finished_.wait(lock, [this]() { return pending_ == 0u; });
        task_ = {};
    }

  private:
    void worker(uint32_t id) {
        uint64_t observed_generation = 0u;
        for (;;) {
            std::function<void(uint32_t)> task;
            bool active = false;
            {
                std::unique_lock<std::mutex> lock(mutex_);
                start_.wait(lock, [this, observed_generation]() {
                    return stopping_ || generation_ != observed_generation;
                });
                if (stopping_)
                    return;
                observed_generation = generation_;
                active = id < active_threads_;
                if (active)
                    task = task_;
            }
            if (!active)
                continue;
            task(id);
            {
                std::lock_guard<std::mutex> lock(mutex_);
                pending_--;
                if (pending_ == 0u)
                    finished_.notify_one();
            }
        }
    }

    uint32_t maximum_threads_ = 0u;
    std::vector<std::thread> workers_;
    std::mutex mutex_;
    std::condition_variable start_;
    std::condition_variable finished_;
    std::function<void(uint32_t)> task_;
    uint64_t generation_ = 0u;
    uint32_t active_threads_ = 0u;
    uint32_t pending_ = 0u;
    bool stopping_ = false;
};

struct EventState {
    std::array<double, FK_NATIVE_FUSION_STATE_HEADS> maxima{};
    bool alert_latched = false;
    uint64_t last_sequence = 0u;
};

struct PortableMetaNode {
    int32_t feature;
    int32_t left;
    int32_t right;
    int32_t missing_left;
    double threshold;
    double value;
};
static_assert(sizeof(PortableMetaNode) == 32u,
              "FKMETA3 node ABI changed");

struct PortableHistoryMeta {
    uint32_t feature_count = 0u;
    uint32_t kind = 0u;
    double bias = 0.0;
    std::vector<int32_t> roots;
    std::vector<PortableMetaNode> nodes;

    double predict(const double *features) const {
        double value = bias;
        for (int32_t root : roots) {
            int32_t index = root;
            while (nodes[static_cast<size_t>(index)].feature >= 0) {
                const PortableMetaNode &node =
                    nodes[static_cast<size_t>(index)];
                const double feature = features[node.feature];
                const bool left = std::isnan(feature)
                    ? node.missing_left != 0 : feature <= node.threshold;
                index = left ? node.left : node.right;
            }
            value += nodes[static_cast<size_t>(index)].value;
        }
        if (kind != 0u)
            return 1.0 / (1.0 + std::exp(-value));
        return std::min(1.0, std::max(0.0, value));
    }
};

struct Session {
    explicit Session(const MappedModel *source, uint32_t maximum_threads)
        : model(source), pool(maximum_threads), maximum_threads(maximum_threads),
          meta_cache(32768u) {}

    const MappedModel *model;
    WorkerPool pool;
    uint32_t maximum_threads;
    std::unordered_map<uint64_t, EventState> events;
    std::unique_ptr<PortableHistoryMeta> history_meta;
    double history_meta_threshold = 0.0;
    fk_native_fusion_state_backend backend{};
    bool backend_enabled = false;
    bool (*history_fence)(void *, uint64_t) = nullptr;
    fk_native_fusion_phase_profile profile{};
    std::vector<float> projected;
    std::vector<float> projection_categories;
    std::vector<double> head_scores;
    std::vector<double> meta;
    std::vector<double> components;
    std::vector<double> unique_meta;
    std::vector<double> unique_components;
    std::vector<double> extra_tree_leaves;
    std::vector<uint32_t> meta_owner;
    // Exact pure-function memoization, not retained event evidence. Bounded
    // direct mapping: collisions only cause recomputation, never approximation.
    struct MetaCacheEntry {
        std::array<uint64_t, FK_NATIVE_FUSION_META_FEATURES> bits{};
        std::array<double, 3u> components{};
        bool valid = false;
    };
    std::vector<MetaCacheEntry> meta_cache;
    bool has_sequence = false;
    bool event_frontiers = false;
    uint64_t last_sequence = 0u;
    std::mutex score_mutex;
};

struct MetaKey {
    std::array<uint64_t, FK_NATIVE_FUSION_META_FEATURES> bits{};

    bool operator==(const MetaKey &other) const noexcept {
        return bits == other.bits;
    }
};

struct MetaKeyHash {
    std::size_t operator()(const MetaKey &key) const noexcept {
        uint64_t hash = UINT64_C(0xcbf29ce484222325);
        for (uint64_t value : key.bits) {
            hash ^= value;
            hash *= UINT64_C(0x100000001b3);
            hash ^= hash >> 32u;
        }
        return static_cast<std::size_t>(hash);
    }
};

static MappedModel *implementation(fk_native_fusion_model *model) {
    return reinterpret_cast<MappedModel *>(model);
}

static const MappedModel *implementation(const fk_native_fusion_model *model) {
    return reinterpret_cast<const MappedModel *>(model);
}

static Session *implementation(fk_native_fusion_session *session) {
    return reinterpret_cast<Session *>(session);
}

static void set_error(char *error, std::size_t capacity, const std::string &message) {
    if (error != nullptr && capacity > 0u)
        std::snprintf(error, capacity, "%s", message.c_str());
}

static bool zero_bytes(const uint8_t *values, std::size_t count) {
    for (std::size_t index = 0u; index < count; ++index) {
        if (values[index] != 0u)
            return false;
    }
    return true;
}

static bool section_inside(
        uint64_t offset,
        uint64_t count,
        uint64_t item_bytes,
        uint64_t file_bytes) {
    if ((offset & 63u) != 0u || offset > file_bytes)
        return false;
    if (item_bytes != 0u && count > (UINT64_MAX - offset) / item_bytes)
        return false;
    return offset + count * item_bytes <= file_bytes;
}

static bool host_little_endian();

static bool temporary_path(const char *path) {
    const std::size_t length = std::strlen(path);
    return length >= 4u && std::memcmp(path + length - 4u, ".tmp", 4u) == 0;
}

static bool sha256_descriptor(
        int descriptor,
        uint8_t digest[FK_NATIVE_FUSION_BUNDLE_SHA256_BYTES],
        std::string &reason) {
    EVP_MD_CTX *context = EVP_MD_CTX_new();
    if (context == nullptr) {
        reason = "cannot allocate native fusion SHA-256 context";
        return false;
    }
    bool ok = EVP_DigestInit_ex(context, EVP_sha256(), nullptr) == 1;
    std::array<uint8_t, 1u << 20u> buffer{};
    off_t offset = 0;
    while (ok) {
        const ssize_t count = ::pread(
            descriptor, buffer.data(), buffer.size(), offset);
        if (count < 0) {
            if (errno == EINTR)
                continue;
            reason = std::string("cannot hash native fusion bundle: ") +
                std::strerror(errno);
            ok = false;
            break;
        }
        if (count == 0)
            break;
        ok = EVP_DigestUpdate(
            context, buffer.data(), static_cast<std::size_t>(count)) == 1;
        offset += count;
    }
    unsigned int length = 0u;
    if (ok)
        ok = EVP_DigestFinal_ex(context, digest, &length) == 1 &&
            length == FK_NATIVE_FUSION_BUNDLE_SHA256_BYTES;
    EVP_MD_CTX_free(context);
    if (!ok && reason.empty())
        reason = "cannot calculate native fusion bundle SHA-256";
    return ok;
}

static bool validate_header(const MappedModel &model, std::string &reason) {
    const Header &header = *model.header;
    if (!host_little_endian() ||
        std::memcmp(header.magic, kMagic, sizeof(kMagic)) != 0 ||
        header.version != kVersion || header.header_bytes != kHeaderBytes ||
        header.endian_tag != kEndianTag ||
        header.ensemble_count != kEnsembleCount ||
        header.reference_count != kReferenceCount ||
        header.raw_features != FK_NATIVE_FUSION_RAW_FEATURES ||
        header.projected_features != kProjectedFeatures ||
        header.meta_features != FK_NATIVE_FUSION_META_FEATURES ||
        header.state_heads != FK_NATIVE_FUSION_STATE_HEADS ||
        header.tree_count == 0u || header.tree_count > kMaximumTrees ||
        header.node_count == 0u || header.node_count > kMaximumNodes ||
        header.reference_length == 0u ||
        header.reference_length > kMaximumReferenceLength ||
        header.file_bytes != model.mapping_bytes || header.reserved0 != 0u ||
        !zero_bytes(header.reserved, sizeof(header.reserved))) {
        reason = "native fusion header is incompatible";
        return false;
    }
    if (!section_inside(
            header.ensemble_offset, header.ensemble_count,
            sizeof(Ensemble), header.file_bytes) ||
        !section_inside(
            header.tree_offset, header.tree_count,
            sizeof(Tree), header.file_bytes) ||
        !section_inside(
            header.node_offset, header.node_count,
            sizeof(Node), header.file_bytes) ||
        !section_inside(
            header.reference_offset,
            static_cast<uint64_t>(header.reference_count) *
                header.reference_length,
            sizeof(double), header.file_bytes)) {
        reason = "native fusion section is outside the file";
        return false;
    }
    if (!(header.ensemble_offset >= header.header_bytes &&
          header.tree_offset >= header.ensemble_offset +
              header.ensemble_count * sizeof(Ensemble) &&
          header.node_offset >= header.tree_offset +
              header.tree_count * sizeof(Tree) &&
          header.reference_offset >= header.node_offset +
              static_cast<uint64_t>(header.node_count) * sizeof(Node))) {
        reason = "native fusion sections overlap";
        return false;
    }
    return true;
}

static bool host_little_endian() {
    const uint32_t value = 1u;
    return *reinterpret_cast<const uint8_t *>(&value) == 1u;
}

static bool validate_model(const MappedModel &model, std::string &reason) {
    const Header &header = *model.header;
    if (!validate_header(model, reason))
        return false;
    for (double weight : header.weights) {
        if (!std::isfinite(weight)) {
            reason = "native fusion weight is non-finite";
            return false;
        }
    }
    if (!std::isfinite(header.threshold) ||
        !(header.threshold > 0.0 && header.threshold <= 1.0)) {
        reason = "native fusion threshold is invalid";
        return false;
    }

    uint32_t expected_tree = 0u;
    for (uint32_t ensemble_index = 0u;
         ensemble_index < header.ensemble_count; ++ensemble_index) {
        const Ensemble &ensemble = model.ensembles[ensemble_index];
        const uint32_t expected_kind = ensemble_index < 7u
            ? kHistogramLogit
            : (ensemble_index == 7u
                ? kExtraTreesProbability
                : (ensemble_index == 8u ? kGradientLogit : kHistogramLogit));
        const uint32_t expected_features = ensemble_index < 7u
            ? kProjectedFeatures : FK_NATIVE_FUSION_META_FEATURES;
        if (ensemble.kind != expected_kind ||
            ensemble.feature_count != expected_features ||
            ensemble.tree_first != expected_tree ||
            ensemble.tree_count == 0u ||
            ensemble.tree_count > header.tree_count - ensemble.tree_first ||
            !std::isfinite(ensemble.bias) ||
            !std::isfinite(ensemble.divisor) || ensemble.divisor <= 0.0) {
            reason = "native fusion ensemble descriptor is invalid";
            return false;
        }
        if ((ensemble.kind == kExtraTreesProbability &&
             ensemble.divisor != static_cast<double>(ensemble.tree_count)) ||
            (ensemble.kind != kExtraTreesProbability && ensemble.divisor != 1.0)) {
            reason = "native fusion ensemble divisor changed";
            return false;
        }
        for (uint32_t tree_offset = 0u;
             tree_offset < ensemble.tree_count; ++tree_offset) {
            const Tree &tree = model.trees[ensemble.tree_first + tree_offset];
            if (tree.reserved != 0u || tree.node_count == 0u ||
                tree.node_count >= UINT16_MAX ||
                tree.node_first > header.node_count ||
                tree.node_count > header.node_count - tree.node_first ||
                !std::isfinite(tree.scale)) {
                reason = "native fusion tree descriptor is invalid";
                return false;
            }
            const Node *nodes = model.nodes + tree.node_first;
            bool has_leaf = false;
            for (uint32_t index = 0u; index < tree.node_count; ++index) {
                const Node &node = nodes[index];
                if (!std::isfinite(node.split_or_value) ||
                    (node.flags & ~(kNodeLeaf | kNodeMissingLeft)) != 0u) {
                    reason = "native fusion node value or flags are invalid";
                    return false;
                }
                if ((node.flags & kNodeLeaf) != 0u) {
                    has_leaf = true;
                    if (node.feature != -1 || node.left != UINT16_MAX ||
                        node.right != UINT16_MAX) {
                        reason = "native fusion leaf encoding is invalid";
                        return false;
                    }
                    continue;
                }
                if (node.feature < 0 ||
                    static_cast<uint32_t>(node.feature) >= ensemble.feature_count ||
                    node.left <= index || node.right <= index ||
                    node.left >= tree.node_count || node.right >= tree.node_count) {
                    reason = "native fusion internal node is invalid";
                    return false;
                }
            }
            if (!has_leaf) {
                reason = "native fusion tree has no leaf";
                return false;
            }
        }
        expected_tree += ensemble.tree_count;
    }
    if (expected_tree != header.tree_count) {
        reason = "native fusion trees are not completely owned";
        return false;
    }
    for (uint32_t reference = 0u;
         reference < header.reference_count; ++reference) {
        const double *values = model.references +
            static_cast<std::size_t>(reference) * header.reference_length;
        for (uint32_t index = 0u; index < header.reference_length; ++index) {
            if (!std::isfinite(values[index]) ||
                (index > 0u && values[index] < values[index - 1u])) {
                reason = "native fusion ECDF reference is invalid";
                return false;
            }
        }
    }
    return true;
}

static double sigmoid(double value) {
    if (value >= 0.0) {
        const double decay = std::exp(-value);
        return 1.0 / (1.0 + decay);
    }
    const double growth = std::exp(value);
    return growth / (1.0 + growth);
}

static double evaluate_float_tree(
        const MappedModel &model,
        const Tree &tree,
        const float *features) {
    const Node *nodes = model.nodes + tree.node_first;
    uint16_t index = 0u;
    for (uint32_t step = 0u; step < tree.node_count; ++step) {
        const Node &node = nodes[index];
        if ((node.flags & kNodeLeaf) != 0u)
            return node.split_or_value;
        const double value = static_cast<double>(features[node.feature]);
        index = value <= node.split_or_value ? node.left : node.right;
    }
    return std::numeric_limits<double>::quiet_NaN();
}

// Inputs are finite float32. Rounding a double split down to float32 makes
// the float comparison exactly equivalent, including adjacent float values.
static void compile_float_nodes(MappedModel &model) {
    uint64_t needed_nodes = 0;
    for (uint32_t head = 0; head < 7u; ++head) {
        const auto &ensemble = model.ensembles[head];
        for (uint32_t t = ensemble.tree_first; t < ensemble.tree_first + ensemble.tree_count; ++t)
            needed_nodes = std::max(needed_nodes, model.trees[t].node_first + model.trees[t].node_count);
    }
    model.float_nodes.resize(needed_nodes);
    model.compact_trees.resize(model.header->tree_count, 0u);
    for (uint32_t head = 0; head < 7u; ++head) {
        const auto &ensemble = model.ensembles[head];
        for (uint32_t t = ensemble.tree_first; t < ensemble.tree_first + ensemble.tree_count; ++t) {
            const auto &tree = model.trees[t];
            if (tree.node_count > 256u) continue;
            model.compact_trees[t] = 1u;
            for (uint32_t n = 0; n < tree.node_count; ++n) {
                const auto &source = model.nodes[tree.node_first + n];
                auto &dest = model.float_nodes[tree.node_first + n];
                const bool leaf = (source.flags & kNodeLeaf) != 0u;
                const double source_split = leaf ? 0.0 : source.split_or_value;
                const float limit = std::numeric_limits<float>::max();
                float split = source_split >= limit ? limit :
                    source_split < -static_cast<double>(limit) ?
                    -std::numeric_limits<float>::infinity() : static_cast<float>(source_split);
                if (!leaf && static_cast<double>(split) > source.split_or_value)
                    split = std::nextafter(split, -std::numeric_limits<float>::infinity());
                for (float probe : {split, std::nextafter(split, -std::numeric_limits<float>::infinity()),
                                    std::nextafter(split, std::numeric_limits<float>::infinity())}) {
                    if (!leaf && std::isfinite(probe) &&
                        ((probe <= split) != (static_cast<double>(probe) <= source.split_or_value)))
                        throw std::runtime_error("compact float split boundary mismatch");
                }
                dest = {split, static_cast<uint8_t>(source.left),
                    static_cast<uint8_t>(source.right),
                    static_cast<uint8_t>(leaf ? 0 : source.feature),
                    static_cast<uint8_t>(leaf)};
            }
        }
    }
}

static double evaluate_compact_float_tree(
        const MappedModel &model, const Tree &tree, const float *features) {
    const FloatNode *nodes = model.float_nodes.data() + tree.node_first;
    uint8_t index = 0u;
    // The source model was validated as a forward-only, terminating DAG.
    while (!nodes[index].leaf) {
        const auto &node = nodes[index];
        index = features[node.feature] <= node.split ? node.left : node.right;
    }
    return model.nodes[tree.node_first + index].split_or_value;
}

static double evaluate_meta_tree(
        const MappedModel &model,
        const Tree &tree,
        const double *features,
        bool float_features) {
    const Node *nodes = model.nodes + tree.node_first;
    uint16_t index = 0u;
    for (uint32_t step = 0u; step < tree.node_count; ++step) {
        const Node &node = nodes[index];
        if ((node.flags & kNodeLeaf) != 0u)
            return node.split_or_value;
        const double source = features[node.feature];
        const double value = float_features
            ? static_cast<double>(static_cast<float>(source)) : source;
        index = value <= node.split_or_value ? node.left : node.right;
    }
    return std::numeric_limits<double>::quiet_NaN();
}

static bool exact_code(float value, uint32_t maximum, uint32_t &result) {
    if (!std::isfinite(value) || value < 0.0f ||
        value > static_cast<float>(maximum) || std::floor(value) != value)
        return false;
    result = static_cast<uint32_t>(value);
    return true;
}

static uint64_t splitmix64(uint64_t value) {
    value += UINT64_C(0x9e3779b97f4a7c15);
    value = (value ^ (value >> 30u)) * UINT64_C(0xbf58476d1ce4e5b9);
    value = (value ^ (value >> 27u)) * UINT64_C(0x94d049bb133111eb);
    return value ^ (value >> 31u);
}

static bool validate_request(
        const fk_native_fusion_request &request,
        std::string &reason) {
    if (request.event_token == 0u || !zero_bytes(request.reserved, sizeof(request.reserved))) {
        reason = "native fusion request identity or reserve is invalid";
        return false;
    }
    for (float value : request.features) {
        if (!std::isfinite(value)) {
            reason = "native fusion request feature is non-finite";
            return false;
        }
    }
    uint32_t tls = 0u;
    uint32_t selected[3]{};
    uint32_t reasons[3]{};
    uint32_t materialized[3]{};
    uint32_t ja4_present[2]{};
    if (!exact_code(request.features[7], 1u, tls) ||
        !exact_code(request.features[98], 1u, ja4_present[0]) ||
        !exact_code(request.features[99], 1u, ja4_present[1])) {
        reason = "native fusion request protocol code is invalid";
        return false;
    }
    uint32_t observed_mask = 0u;
    for (uint32_t component = 0u; component < 3u; ++component) {
        if (!exact_code(request.features[30u + component], 1u, selected[component]) ||
            !exact_code(request.features[33u + component], 4u, reasons[component]) ||
            !exact_code(request.features[38u + component], 1u, materialized[component])) {
            reason = "native fusion request component code is invalid";
            return false;
        }
        if (selected[component] != 0u) {
            observed_mask |= 1u << component;
            if (materialized[component] == 0u || reasons[component] == 1u ||
                reasons[component] == 2u) {
                reason = "native fusion selected component lacks factual storage";
                return false;
            }
        }
    }
    if (observed_mask != request.source_mask || request.source_mask > 7u ||
        (tls == 0u && (observed_mask & 4u) != 0u)) {
        reason = "native fusion source mask is inconsistent";
        return false;
    }
    for (uint32_t limb = 119u; limb < 159u; ++limb) {
        const float value = request.features[limb];
        if (value < 0.0f || value > 65535.0f || std::floor(value) != value) {
            reason = "native fusion JA4 limb is invalid";
            return false;
        }
    }
    return true;
}

static void project_categories(
        const fk_native_fusion_request &request,
        float *categories) {
    std::fill(categories, categories + 20u, 0.0f);
    constexpr uint64_t seeds[2] = {
        UINT64_C(0x243f6a8885a308d3),
        UINT64_C(0x13198a2e03707344),
    };
    for (uint32_t field = 0u; field < 10u; ++field) {
        const uint32_t base = 119u + field * 4u;
        const uint64_t hash =
            static_cast<uint64_t>(request.features[base]) |
            (static_cast<uint64_t>(request.features[base + 1u]) << 16u) |
            (static_cast<uint64_t>(request.features[base + 2u]) << 32u) |
            (static_cast<uint64_t>(request.features[base + 3u]) << 48u);
        if (hash == 0u)
            continue;
        const uint64_t salt = static_cast<uint64_t>(field) *
            UINT64_C(0x9e3779b97f4a7c15);
        for (uint32_t table = 0u; table < 2u; ++table) {
            const uint64_t mixed = splitmix64(hash ^ salt ^ seeds[table]);
            categories[field * 2u + table] = static_cast<float>(
                1u + static_cast<uint32_t>((mixed % 4096u) % 254u));
        }
    }

}

static void project_request_state(
        const fk_native_fusion_request &request,
        uint32_t state,
        const float *categories,
        float *destination) {
    uint32_t tls = static_cast<uint32_t>(request.features[7]);
    uint32_t original_reason[3] = {
        static_cast<uint32_t>(request.features[33]),
        static_cast<uint32_t>(request.features[34]),
        static_cast<uint32_t>(request.features[35]),
    };
    const bool ja4_observed = request.features[98] == 1.0f ||
        request.features[99] == 1.0f;

    std::memcpy(destination, request.features, 119u * sizeof(float));
    const uint32_t requested = static_cast<uint32_t>(request.source_mask) &
        (tls != 0u ? 7u : 3u) & (state + 1u);
    for (uint32_t component = 0u; component < 3u; ++component) {
        const uint32_t bit = 1u << component;
        const bool retained = (requested & bit) != 0u;
        destination[30u + component] = retained ? 1.0f : 0.0f;
        destination[38u + component] = retained ? 1.0f : 0.0f;
        uint32_t reason = 1u;
        if (bit == 4u && tls == 0u)
            reason = 2u;
        else if (retained) {
            if (original_reason[component] == 4u)
                reason = 4u;
            else if (bit == 4u)
                reason = ja4_observed ? 0u : 3u;
            else
                reason = original_reason[component];
        } else if (original_reason[component] == 4u)
            reason = 4u;
        destination[33u + component] = static_cast<float>(reason);
    }
    if ((requested & 1u) == 0u)
        std::fill(destination + 42u, destination + 58u, 0.0f);
    if ((requested & 2u) == 0u) {
        destination[41] = 0.0f;
        std::fill(destination + 58u, destination + 98u, 0.0f);
    }
    if ((requested & 4u) == 0u)
        std::fill(destination + 98u, destination + 116u, 0.0f);
    for (uint32_t category = 0u; category < 20u; ++category)
        destination[119u + category] = (requested & 4u) != 0u
            ? categories[category] : 0.0f;
}

static void predict_state_range(
        Session &session,
        std::size_t first,
        std::size_t last,
        uint32_t state) {
    const MappedModel &model = *session.model;
    const Ensemble &ensemble = model.ensembles[state];
    for (std::size_t row = first; row < last; ++row)
        session.head_scores[row * 7u + state] = ensemble.bias;
    for (uint32_t offset = 0u; offset < ensemble.tree_count; ++offset) {
        const Tree &tree = model.trees[ensemble.tree_first + offset];
        std::size_t row = first;
        if (model.compact_trees[ensemble.tree_first + offset]) {
            for (; row < last; ++row) {
                session.head_scores[row * 7u + state] += tree.scale *
                    evaluate_compact_float_tree(model, tree,
                        session.projected.data() + row * kProjectedFeatures);
            }
        }
        for (; row < last; ++row) {
            const float *features = session.projected.data() +
                row * kProjectedFeatures;
            session.head_scores[row * 7u + state] +=
                tree.scale * evaluate_float_tree(model, tree, features);
        }
    }
    for (std::size_t row = first; row < last; ++row)
        session.head_scores[row * 7u + state] =
            sigmoid(session.head_scores[row * 7u + state]);
}

static void predict_meta_range(
        Session &session,
        std::size_t first,
        std::size_t last,
        uint32_t first_model) {
    const MappedModel &model = *session.model;
    for (uint32_t meta_model = first_model; meta_model < 3u; ++meta_model) {
        const uint32_t ensemble_index = 7u + meta_model;
        const Ensemble &ensemble = model.ensembles[ensemble_index];
        for (std::size_t row = first; row < last; ++row)
            session.unique_components[row * 3u + meta_model] = ensemble.bias;
        const bool float_features = ensemble.kind != kHistogramLogit;
        for (uint32_t offset = 0u; offset < ensemble.tree_count; ++offset) {
            const Tree &tree = model.trees[ensemble.tree_first + offset];
            for (std::size_t row = first; row < last; ++row) {
                const double leaf = evaluate_meta_tree(
                    model, tree, session.unique_meta.data() + row * 10u,
                    float_features);
                session.unique_components[row * 3u + meta_model] +=
                    tree.scale * leaf;
            }
        }
        for (std::size_t row = first; row < last; ++row) {
            double &value = session.unique_components[row * 3u + meta_model];
            value = ensemble.kind == kExtraTreesProbability
                ? value / ensemble.divisor : sigmoid(value);
        }
    }
}

static void predict_extra_tree_range(
        Session &session,
        std::size_t rows,
        uint32_t thread,
        uint32_t threads) {
    const MappedModel &model = *session.model;
    const Ensemble &ensemble = model.ensembles[7u];
    const uint32_t first_tree = ensemble.tree_count * thread / threads;
    const uint32_t last_tree = ensemble.tree_count * (thread + 1u) / threads;
    for (uint32_t offset = first_tree; offset < last_tree; ++offset) {
        const Tree &tree = model.trees[ensemble.tree_first + offset];
        double *leaves = session.extra_tree_leaves.data() +
            static_cast<std::size_t>(offset) * rows;
        for (std::size_t row = 0u; row < rows; ++row) {
            leaves[row] = evaluate_meta_tree(
                model, tree, session.unique_meta.data() + row * 10u, true);
        }
    }
}

static std::size_t deduplicate_meta(Session &session, std::size_t rows) {
    session.unique_meta.clear();
    session.unique_meta.reserve(rows * FK_NATIVE_FUSION_META_FEATURES);
    session.meta_owner.resize(rows);
    std::unordered_map<MetaKey, uint32_t, MetaKeyHash> owners;
    owners.reserve(rows);
    for (std::size_t row = 0u; row < rows; ++row) {
        MetaKey key{};
        std::memcpy(
            key.bits.data(), session.meta.data() + row * 10u,
            sizeof(key.bits));
        const auto &cached = session.meta_cache[
            MetaKeyHash{}(key) % session.meta_cache.size()];
        if (cached.valid && cached.bits == key.bits) {
            session.meta_owner[row] = UINT32_MAX;
            std::copy(cached.components.begin(), cached.components.end(),
                session.components.begin() + row * 4u);
            ++session.profile.meta_cache_hits;
            continue;
        }
        ++session.profile.meta_cache_misses;
        const uint32_t candidate = static_cast<uint32_t>(owners.size());
        const auto inserted = owners.emplace(key, candidate);
        const uint32_t owner = inserted.first->second;
        session.meta_owner[row] = owner;
        if (inserted.second) {
            const double *source = session.meta.data() + row * 10u;
            session.unique_meta.insert(session.unique_meta.end(), source, source + 10u);
        }
    }
    const std::size_t unique_rows = owners.size();
    session.unique_components.resize(unique_rows * 3u);
    return unique_rows;
}

static void commit_event_states(
        Session &session,
        const std::unordered_map<uint64_t, EventState> &working) {
    /*
     * Preserve the public all-or-nothing batch contract without cloning the
     * complete lifetime event table on every checkpoint batch.  Every
     * potentially throwing allocation happens before existing event states
     * are changed.  If a new node allocation fails, only nodes inserted by
     * this attempt are erased and the prior semantic state is unchanged.
     */
    struct PendingUpdate {
        uint64_t token;
        EventState *existing;
        const EventState *source;
        bool inserted;
    };
    std::vector<PendingUpdate> pending;
    pending.reserve(working.size());
    /* One batch of slack prevents rehash on an all-existing update while
     * still allowing a single lookup/insertion per touched event. */
    session.events.reserve(session.events.size() + working.size());
    try {
        for (const auto &entry : working) {
            const auto result = session.events.emplace(
                entry.first, entry.second);
            pending.push_back(PendingUpdate{
                entry.first,
                result.second ? nullptr : &result.first->second,
                &entry.second,
                result.second});
        }
    } catch (...) {
        for (const PendingUpdate &update : pending) {
            if (update.inserted)
                session.events.erase(update.token);
        }
        throw;
    }
    /* EventState is a fixed scalar/array value; these assignments cannot
     * allocate or throw after every missing node has been materialized. */
    for (const PendingUpdate &update : pending) {
        if (update.existing != nullptr)
            *update.existing = *update.source;
    }
}

static std::unique_ptr<PortableHistoryMeta> load_history_meta(
        const char *path,
        std::string &reason) {
    FILE *file = path == nullptr ? nullptr : std::fopen(path, "rb");
    if (file == nullptr) {
        reason = "cannot open FKMETA3 history model";
        return nullptr;
    }
    auto close_file = [&]() { (void)std::fclose(file); };
    char magic[8]{};
    uint32_t tree_count = 0u, node_count = 0u;
    auto model = std::make_unique<PortableHistoryMeta>();
    bool ok = std::fread(magic, 1u, sizeof(magic), file) == sizeof(magic) &&
        std::memcmp(magic, "FKMETA3\0", sizeof(magic)) == 0 &&
        std::fread(&tree_count, sizeof(tree_count), 1u, file) == 1u &&
        std::fread(&node_count, sizeof(node_count), 1u, file) == 1u &&
        std::fread(&model->feature_count, sizeof(model->feature_count), 1u,
                   file) == 1u &&
        std::fread(&model->kind, sizeof(model->kind), 1u, file) == 1u &&
        std::fread(&model->bias, sizeof(model->bias), 1u, file) == 1u;
    ok = ok && tree_count != 0u && tree_count <= 4096u &&
        node_count != 0u && node_count <= 1000000u &&
        model->feature_count == FK_NATIVE_FUSION_META_FEATURES &&
        model->kind <= 1u && std::isfinite(model->bias);
    if (ok) {
        model->roots.resize(tree_count);
        model->nodes.resize(node_count);
        ok = std::fread(model->roots.data(), sizeof(int32_t), tree_count,
                        file) == tree_count &&
            std::fread(model->nodes.data(), sizeof(PortableMetaNode),
                       node_count, file) == node_count &&
            std::fgetc(file) == EOF;
    }
    close_file();
    if (ok) {
        for (int32_t root : model->roots)
            ok = ok && root >= 0 && static_cast<uint32_t>(root) < node_count;
        for (uint32_t index = 0u; ok && index < node_count; ++index) {
            const PortableMetaNode &node = model->nodes[index];
            ok = std::isfinite(node.threshold) && std::isfinite(node.value) &&
                node.missing_left >= 0 && node.missing_left <= 1;
            if (node.feature < 0) {
                ok = ok && node.feature == -1;
            } else {
                ok = ok && static_cast<uint32_t>(node.feature) <
                        model->feature_count &&
                    node.left > static_cast<int32_t>(index) &&
                    node.right > static_cast<int32_t>(index) &&
                    static_cast<uint32_t>(node.left) < node_count &&
                    static_cast<uint32_t>(node.right) < node_count;
            }
        }
    }
    if (!ok) {
        reason = "FKMETA3 history model is malformed or incompatible";
        return nullptr;
    }
    return model;
}

}  // namespace

extern "C" {

fk_native_fusion_model *fk_native_fusion_model_load(
        const char *path,
        const uint8_t expected_bundle_sha256[
            FK_NATIVE_FUSION_BUNDLE_SHA256_BYTES],
        const uint8_t expected_source_model_sha256[
            FK_NATIVE_FUSION_MODEL_SHA256_BYTES],
        char *error,
        size_t error_capacity) {
    set_error(error, error_capacity, "");
    if (path == nullptr || path[0] == '\0' || temporary_path(path) ||
        expected_bundle_sha256 == nullptr ||
        expected_source_model_sha256 == nullptr) {
        set_error(error, error_capacity, "native fusion model arguments are invalid");
        return nullptr;
    }
    const int descriptor = ::open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (descriptor < 0) {
        set_error(error, error_capacity,
                  std::string("cannot open native fusion model: ") +
                      std::strerror(errno));
        return nullptr;
    }
    struct stat status {};
    if (::fstat(descriptor, &status) != 0 || !S_ISREG(status.st_mode) ||
        status.st_size < static_cast<off_t>(sizeof(Header)) ||
        status.st_size > static_cast<off_t>(128u * 1024u * 1024u)) {
        ::close(descriptor);
        set_error(error, error_capacity, "native fusion model is not a bounded regular file");
        return nullptr;
    }
    uint8_t actual_bundle_sha256[FK_NATIVE_FUSION_BUNDLE_SHA256_BYTES]{};
    std::string hash_reason;
    if (!sha256_descriptor(descriptor, actual_bundle_sha256, hash_reason) ||
        std::memcmp(
            actual_bundle_sha256, expected_bundle_sha256,
            sizeof(actual_bundle_sha256)) != 0) {
        ::close(descriptor);
        set_error(
            error, error_capacity,
            hash_reason.empty()
                ? "native fusion bundle SHA-256 mismatch" : hash_reason);
        return nullptr;
    }
    MappedModel *model = new (std::nothrow) MappedModel();
    if (model == nullptr) {
        ::close(descriptor);
        set_error(error, error_capacity, "native fusion model allocation failed");
        return nullptr;
    }
    model->mapping_bytes = static_cast<std::size_t>(status.st_size);
    model->mapping = ::mmap(
        nullptr, model->mapping_bytes, PROT_READ, MAP_PRIVATE, descriptor, 0);
    const int close_result = ::close(descriptor);
    if (model->mapping == MAP_FAILED || close_result != 0) {
        const int saved_errno = errno;
        delete model;
        set_error(error, error_capacity,
                  std::string("cannot map native fusion model: ") +
                      std::strerror(saved_errno));
        return nullptr;
    }
    model->header = static_cast<const Header *>(model->mapping);
    std::string reason;
    if (!validate_header(*model, reason)) {
        delete model;
        set_error(error, error_capacity, reason);
        return nullptr;
    }
    if (std::memcmp(
            model->header->source_model_sha256,
            expected_source_model_sha256,
            FK_NATIVE_FUSION_MODEL_SHA256_BYTES) != 0) {
        delete model;
        set_error(error, error_capacity, "native fusion source model SHA-256 mismatch");
        return nullptr;
    }
    const uint8_t *bytes = static_cast<const uint8_t *>(model->mapping);
    model->ensembles = reinterpret_cast<const Ensemble *>(
        bytes + model->header->ensemble_offset);
    model->trees = reinterpret_cast<const Tree *>(
        bytes + model->header->tree_offset);
    model->nodes = reinterpret_cast<const Node *>(
        bytes + model->header->node_offset);
    model->references = reinterpret_cast<const double *>(
        bytes + model->header->reference_offset);
    if (!validate_model(*model, reason)) {
        delete model;
        set_error(error, error_capacity, reason);
        return nullptr;
    }
    try {
        compile_float_nodes(*model);
    } catch (const std::exception &exception) {
        delete model;
        set_error(error, error_capacity, exception.what());
        return nullptr;
    }
    return reinterpret_cast<fk_native_fusion_model *>(model);
}

void fk_native_fusion_model_destroy(fk_native_fusion_model *model) {
    delete implementation(model);
}

bool fk_native_fusion_model_get_metadata(
        const fk_native_fusion_model *model,
        fk_native_fusion_metadata *metadata) {
    if (model == nullptr || metadata == nullptr)
        return false;
    const MappedModel &state = *implementation(model);
    *metadata = {};
    metadata->format_version = state.header->version;
    metadata->ensemble_count = state.header->ensemble_count;
    metadata->tree_count = state.header->tree_count;
    metadata->node_count = state.header->node_count;
    metadata->reference_length = state.header->reference_length;
    metadata->maximum_threads = kMaximumThreads;
    std::memcpy(metadata->weights, state.header->weights, sizeof(metadata->weights));
    metadata->threshold = state.header->threshold;
    std::memcpy(
        metadata->source_model_sha256,
        state.header->source_model_sha256,
        sizeof(metadata->source_model_sha256));
    metadata->model_bytes = static_cast<uint64_t>(state.mapping_bytes);
    metadata->locked_bytes = state.locked ? metadata->model_bytes : 0u;
    metadata->mlock_succeeded = state.locked ? 1u : 0u;
    return true;
}

bool fk_native_fusion_model_mlock(
        fk_native_fusion_model *model,
        uint64_t *locked_bytes,
        char *error,
        size_t error_capacity) {
    set_error(error, error_capacity, "");
    if (locked_bytes != nullptr)
        *locked_bytes = 0u;
    if (model == nullptr || locked_bytes == nullptr) {
        set_error(error, error_capacity,
                  "native fusion model mlock arguments are invalid");
        return false;
    }
    MappedModel &state = *implementation(model);
    if (state.mapping == MAP_FAILED || state.mapping_bytes == 0u) {
        set_error(error, error_capacity,
                  "native fusion model mapping is invalid");
        return false;
    }
    if (!state.locked && ::mlock(state.mapping, state.mapping_bytes) != 0) {
        const int saved_errno = errno;
        (void)::munlock(state.mapping, state.mapping_bytes);
        set_error(error, error_capacity,
                  std::string("cannot mlock native fusion model: ") +
                      std::strerror(saved_errno));
        return false;
    }
    state.locked = true;
    *locked_bytes = static_cast<uint64_t>(state.mapping_bytes);
    return true;
}

fk_native_fusion_session *fk_native_fusion_session_create(
        const fk_native_fusion_model *model,
        uint32_t maximum_threads,
        char *error,
        size_t error_capacity) {
    set_error(error, error_capacity, "");
    if (model == nullptr || maximum_threads == 0u ||
        maximum_threads > kMaximumThreads) {
        set_error(error, error_capacity, "native fusion thread count is invalid");
        return nullptr;
    }
    try {
        Session *session = new Session(implementation(model), maximum_threads);
        return reinterpret_cast<fk_native_fusion_session *>(session);
    } catch (const std::exception &exception) {
        set_error(error, error_capacity,
                  std::string("native fusion session creation failed: ") +
                      exception.what());
        return nullptr;
    } catch (...) {
        set_error(error, error_capacity, "native fusion session creation failed");
        return nullptr;
    }
}

bool fk_native_fusion_session_attach_history_meta(
        fk_native_fusion_session *session,
        const char *path,
        double threshold,
        char *error,
        size_t error_capacity) {
    set_error(error, error_capacity, "");
    if (session == nullptr || path == nullptr || path[0] == '\0' ||
        !std::isfinite(threshold) || threshold < 0.0 || threshold > 1.0) {
        set_error(error, error_capacity,
                  "history meta attachment arguments are invalid");
        return false;
    }
    Session &state = *implementation(session);
    std::lock_guard<std::mutex> lock(state.score_mutex);
    if (state.history_meta || state.has_sequence || state.backend_enabled) {
        set_error(error, error_capacity,
                  "history meta must be attached once before scoring/backend");
        return false;
    }
    std::string reason;
    std::unique_ptr<PortableHistoryMeta> model =
        load_history_meta(path, reason);
    if (!model) {
        set_error(error, error_capacity, reason);
        return false;
    }
    state.history_meta = std::move(model);
    state.history_meta_threshold = threshold;
    return true;
}

void fk_native_fusion_session_destroy(fk_native_fusion_session *session) {
    delete implementation(session);
}

bool fk_native_fusion_session_attach_backend(
        fk_native_fusion_session *session,
        const fk_native_fusion_state_backend *backend,
        bool has_committed_sequence, uint64_t committed_sequence,
        char *error, size_t error_capacity) {
    if (!session || !backend || !backend->begin || !backend->load ||
        !backend->save || !backend->commit || !backend->rollback) {
        set_error(error,error_capacity,"invalid persistent state backend");
        return false;
    }
    Session &state=*implementation(session);
    std::lock_guard<std::mutex> lock(state.score_mutex);
    if (state.has_sequence || !state.events.empty() || state.backend_enabled || state.event_frontiers) {
        set_error(error,error_capacity,"attach requires an unused session");
        return false;
    }
    state.backend=*backend;state.backend_enabled=true;
    state.has_sequence=has_committed_sequence;
    state.last_sequence=committed_sequence;
    set_error(error,error_capacity,"");return true;
}

bool fk_native_fusion_session_attach_submitted_backend(
        fk_native_fusion_session *session, const fk_native_fusion_submitted_backend *b,
        char *error, size_t capacity) {
    if(!b || !b->submit || !b->wait_durable) {
        set_error(error,capacity,"submitted backend requires submit and durability fence");
        return false;
    }
    fk_native_fusion_state_backend transaction{b->context,b->begin,b->load,b->save,b->submit,b->rollback};
    if(!fk_native_fusion_session_attach_backend(session,&transaction,false,0,error,capacity))
        return false;
    implementation(session)->history_fence=b->wait_durable;
    return true;
}
bool fk_native_fusion_session_wait_history(fk_native_fusion_session *session,uint64_t sequence) {
    if(!session)return false;
    auto &s=*implementation(session);
    return !s.history_fence || s.history_fence(s.backend.context,sequence);
}
bool fk_native_fusion_session_enable_event_frontiers(fk_native_fusion_session *session) {
    if (!session) return false;
    auto &state = *implementation(session);
    std::lock_guard<std::mutex> lock(state.score_mutex);
    if (state.has_sequence || state.backend_enabled || !state.events.empty()) return false;
    state.event_frontiers = true;
    return true;
}
bool fk_native_fusion_session_profile(fk_native_fusion_session *session,
        fk_native_fusion_phase_profile *profile) {
    if(!session || !profile)return false;
    auto &s=*implementation(session);
    std::lock_guard<std::mutex> lock(s.score_mutex);
    *profile=s.profile;return true;
}

bool fk_native_fusion_score_batch(
        fk_native_fusion_session *session, const fk_native_fusion_request *requests,
        size_t request_count, uint32_t threads, fk_native_fusion_result *results,
        char *error, size_t error_capacity) {
    return fk_native_fusion_score_batch_with_resets(session,requests,request_count,
        threads,nullptr,results,error,error_capacity);
}

bool fk_native_fusion_score_batch_with_resets(
        fk_native_fusion_session *session,
        const fk_native_fusion_request *requests,
        size_t request_count,
        uint32_t threads,
        const uint8_t *reset_history,
        fk_native_fusion_result *results,
        char *error,
        size_t error_capacity) {
    set_error(error, error_capacity, "");
    if (session == nullptr || requests == nullptr || results == nullptr ||
        request_count == 0u || request_count > kMaximumBatch) {
        set_error(error, error_capacity, "native fusion batch arguments are invalid");
        return false;
    }
    Session &state = *implementation(session);
    std::lock_guard<std::mutex> score_lock(state.score_mutex);
    if (threads == 0u || threads > state.maximum_threads ||
        threads > request_count) {
        set_error(error, error_capacity, "native fusion active thread count is invalid");
        return false;
    }
    bool backend_transaction = false;
    const auto now_ns=[]()->uint64_t {
        return std::chrono::duration_cast<std::chrono::nanoseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count();
    };
    const uint64_t t0=now_ns();
    std::array<std::array<uint64_t,7>,kMaximumThreads> head_times{};
    try {
        uint64_t prior_sequence = state.event_frontiers ? 0u : state.last_sequence;
        bool has_prior = state.event_frontiers ? false : state.has_sequence;
        std::string validation_error;
        for (std::size_t row = 0u; row < request_count; ++row) {
            if (state.event_frontiers) {
                const auto event = state.events.find(requests[row].event_token);
                if (event != state.events.end() &&
                    requests[row].sequence <= event->second.last_sequence) {
                    set_error(error, error_capacity, "event frontier sequence regressed");
                    return false;
                }
            }
            if ((reset_history && reset_history[row]>1u) ||
                (has_prior && requests[row].sequence <= prior_sequence) ||
                !validate_request(requests[row], validation_error)) {
                set_error(
                    error, error_capacity,
                    validation_error.empty()
                        ? "native fusion request sequence is not strictly increasing"
                        : validation_error);
                return false;
            }
            has_prior = true;
            prior_sequence = requests[row].sequence;
        }

        state.projected.resize(request_count * kProjectedFeatures);
        state.projection_categories.resize(request_count * 20u);
        state.head_scores.resize(request_count * FK_NATIVE_FUSION_STATE_HEADS);
        state.meta.resize(request_count * FK_NATIVE_FUSION_META_FEATURES);
        state.components.resize(request_count * 4u);

        const uint64_t t1=now_ns();
        state.pool.run(threads, [&](uint32_t thread) {
            const std::size_t first = request_count * thread / threads;
            const std::size_t last = request_count * (thread + 1u) / threads;
            for (std::size_t row = first; row < last; ++row) {
                project_categories(
                    requests[row],
                    state.projection_categories.data() + row * 20u);
            }
            for (uint32_t state_head = 0u;
                 state_head < FK_NATIVE_FUSION_STATE_HEADS; ++state_head) {
                const uint64_t head_start=now_ns();
                for (std::size_t row = first; row < last; ++row) {
                    project_request_state(
                        requests[row], state_head,
                        state.projection_categories.data() + row * 20u,
                        state.projected.data() + row * kProjectedFeatures);
                }
                predict_state_range(state, first, last, state_head);
                head_times[thread][state_head]=now_ns()-head_start;
            }
        });

        const uint64_t t2=now_ns();
        if (state.backend_enabled) {
            backend_transaction=true;
            if (!state.backend.begin(state.backend.context))
                throw std::runtime_error("persistent state begin failed");
        }
        std::unordered_map<uint64_t, EventState> working;
        working.reserve(request_count);
        for (std::size_t row = 0u; row < request_count; ++row) {
            const uint64_t token = requests[row].event_token;
            auto position = working.find(token);
            if (position == working.end()) {
                EventState prior{};
                if (state.backend_enabled) {
                    bool found=false;uint8_t latched=0;
                    if (!state.backend.load(state.backend.context,token,
                            prior.maxima.data(),&latched,&found))
                        throw std::runtime_error("persistent state load failed");
                    if (!found) prior=EventState{};
                    else {
                        if (latched>1u) throw std::runtime_error("invalid persisted latch");
                        for (double value:prior.maxima)
                            if (!std::isfinite(value) || value<0.0 || value>1.0)
                                throw std::runtime_error("invalid persisted maximum");
                        prior.alert_latched=latched!=0u;
                    }
                } else {
                    const auto existing=state.events.find(token);
                    if (existing!=state.events.end()) prior=existing->second;
                }
                position=working.emplace(token,prior).first;
            }
            EventState &event = position->second;
            event.last_sequence = requests[row].sequence;
            // Reset maxima here; the alert latch is reset in its ordered pass,
            // so a later expiry cannot retroactively change earlier alerts.
            if (reset_history && reset_history[row]) event.maxima.fill(0.0);
            double sum = 0.0;
            double minimum = std::numeric_limits<double>::infinity();
            double maximum = -std::numeric_limits<double>::infinity();
            for (uint32_t head = 0u; head < 7u; ++head) {
                const double current = state.head_scores[row * 7u + head];
                if (current > event.maxima[head])
                    event.maxima[head] = current;
                const double value = event.maxima[head];
                state.meta[row * 10u + head] = value;
                sum += value;
                minimum = std::min(minimum, value);
                maximum = std::max(maximum, value);
            }
            const double mean = sum / 7.0;
            double squared = 0.0;
            for (double value : event.maxima) {
                const double difference = value - mean;
                squared += difference * difference;
            }
            state.meta[row * 10u + 7u] = mean;
            state.meta[row * 10u + 8u] = std::sqrt(squared / 7.0);
            state.meta[row * 10u + 9u] = maximum - minimum;
            state.components[row * 4u + 3u] = maximum;
        }

        const uint64_t t3=now_ns();
        if (state.history_meta) {
            for (std::size_t row = 0u; row < request_count; ++row) {
                const double score = state.history_meta->predict(
                    state.meta.data() + row * FK_NATIVE_FUSION_META_FEATURES);
                results[row] = {};
                results[row].sequence = requests[row].sequence;
                results[row].event_token = requests[row].event_token;
                results[row].score = score;
                results[row].threshold_met =
                    score >= state.history_meta_threshold ? 1u : 0u;
            }
        } else {
        const std::size_t unique_meta_rows = deduplicate_meta(state, request_count);
        if (unique_meta_rows != 0u) {
        uint32_t first_meta_model = 0u;
        if (unique_meta_rows <= kTreeParallelMaximumUniqueMetaRows &&
            threads > 1u) {
            const Ensemble &extra_trees = state.model->ensembles[7u];
            state.extra_tree_leaves.resize(
                unique_meta_rows * extra_trees.tree_count);
            state.pool.run(threads, [&](uint32_t thread) {
                predict_extra_tree_range(
                    state, unique_meta_rows, thread, threads);
            });
            for (std::size_t row = 0u; row < unique_meta_rows; ++row)
                state.unique_components[row * 3u] = extra_trees.bias;
            /* Leaves are tree-major.  Accumulate one contiguous tree slice
             * at a time instead of reading one value from each 4 KiB-spaced
             * slice for every row.  Each row still receives trees in exact
             * ascending order, so floating-point results remain bitwise
             * identical while the full 512-row online batch avoids a severe
             * TLB/cache-stride penalty. */
            for (uint32_t tree = 0u; tree < extra_trees.tree_count; ++tree) {
                const Tree &descriptor =
                    state.model->trees[extra_trees.tree_first + tree];
                const double *leaves = state.extra_tree_leaves.data() +
                    static_cast<std::size_t>(tree) * unique_meta_rows;
                for (std::size_t row = 0u; row < unique_meta_rows; ++row) {
                    state.unique_components[row * 3u] +=
                        descriptor.scale * leaves[row];
                }
            }
            for (std::size_t row = 0u; row < unique_meta_rows; ++row)
                state.unique_components[row * 3u] /= extra_trees.divisor;
            first_meta_model = 1u;
        }
        state.pool.run(threads, [&](uint32_t thread) {
            const std::size_t first = unique_meta_rows * thread / threads;
            const std::size_t last = unique_meta_rows * (thread + 1u) / threads;
            predict_meta_range(state, first, last, first_meta_model);
        });
        for (std::size_t row = 0u; row < unique_meta_rows; ++row) {
            MetaKey key{};
            std::memcpy(key.bits.data(), state.unique_meta.data() + row * 10u,
                sizeof(key.bits));
            auto &cached = state.meta_cache[
                MetaKeyHash{}(key) % state.meta_cache.size()];
            cached.bits = key.bits;
            std::copy_n(state.unique_components.data() + row * 3u, 3u,
                cached.components.begin());
            cached.valid = true;
        }
        }
        const Header &header = *state.model->header;
        for (std::size_t row = 0u; row < request_count; ++row) {
            const std::size_t owner = state.meta_owner[row];
            for (uint32_t component = 0u; owner != UINT32_MAX && component < 3u; ++component) {
                state.components[row * 4u + component] =
                    state.unique_components[owner * 3u + component];
            }
            double score = 0.0;
            for (uint32_t component = 0u; component < 4u; ++component) {
                const double value = state.components[row * 4u + component];
                const double *reference = state.model->references +
                    static_cast<std::size_t>(component) * header.reference_length;
                const std::size_t count = static_cast<std::size_t>(
                    std::upper_bound(
                        reference, reference + header.reference_length, value) -
                    reference);
                const double rank = static_cast<double>(count) /
                    static_cast<double>(header.reference_length);
                score += rank * header.weights[component];
            }
            results[row] = {};
            results[row].sequence = requests[row].sequence;
            results[row].event_token = requests[row].event_token;
            results[row].score = score;
            results[row].threshold_met = score >= header.threshold ? 1u : 0u;
        }
        }

        const uint64_t t4=now_ns();
        for (std::size_t row = 0u; row < request_count; ++row) {
            EventState &event = working.at(requests[row].event_token);
            bool &latched = event.alert_latched;
            if (reset_history && reset_history[row]) latched=false;
            const bool threshold_met = results[row].threshold_met != 0u;
            results[row].first_alert = threshold_met && !latched ? 1u : 0u;
            if (threshold_met) latched=true;
            results[row].alert_latched = latched ? 1u : 0u;
        }
        if (state.backend_enabled) {
            for (const auto &entry:working)
                if (!state.backend.save(state.backend.context,entry.first,
                        entry.second.maxima.data(),entry.second.alert_latched?1u:0u))
                    throw std::runtime_error("persistent state save failed");
            if (!state.backend.commit(state.backend.context,
                    requests[request_count-1u].sequence))
                throw std::runtime_error("persistent state commit failed");
            backend_transaction=false;
        } else commit_event_states(state, working);
        state.last_sequence = std::max(state.last_sequence, requests[request_count - 1u].sequence);
        state.has_sequence = true;
        const uint64_t t5=now_ns();
        ++state.profile.batches; state.profile.rows+=request_count;
        const uint64_t times[]={t0,t1,t2,t3,t4,t5};
        for(size_t i=0;i<5;++i)state.profile.phase_ns[i]+=times[i+1]-times[i];
        for(size_t t=0;t<threads;++t)for(size_t h=0;h<7;++h)
            state.profile.head_thread_ns[h]+=head_times[t][h];
        return true;
    } catch (const std::exception &exception) {
        if (backend_transaction) state.backend.rollback(state.backend.context);
        set_error(error, error_capacity,
                  std::string("native fusion batch failed: ") + exception.what());
        return false;
    } catch (...) {
        if (backend_transaction) state.backend.rollback(state.backend.context);
        set_error(error, error_capacity, "native fusion batch failed");
        return false;
    }
}

}  // extern "C"
