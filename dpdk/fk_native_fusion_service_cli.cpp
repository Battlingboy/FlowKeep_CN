#include "fk_native_fusion_engine_scorer.h"
#include "fk_target_demand_audit.h"
#include "fk_native_fusion_event_router.h"
#include "fk_native_fusion_jsonl_ledger.h"
#include "fk_native_fusion_service.h"
#include "fk_native_coverage_source.h"
#include "fk_versioned_observation_source.h"
#include "fk_cpu_model.h"
#include "fk_native_rocksdb_state.h"
#include "fk_final_scored_evidence_selector.h"
#include <filesystem>

#include <algorithm>
#include <array>
#include <cerrno>
#include <chrono>
#include <cmath>
#include <cstdio>
#include <ctime>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <fstream>
#include <jansson.h>
#include <map>
#include <memory>
#include <openssl/evp.h>
#include <sched.h>
#include <set>
#include <sys/stat.h>
#include <sys/resource.h>
#include <thread>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

#include <unistd.h>

namespace {

constexpr uint32_t kFlowOpenFeatureCount = 23u;

std::string selected_environment(const char *name,const char *fallback) {
    const char *value=std::getenv(name);return value?value:fallback;
}
size_t selected_environment_size(const char *name,size_t fallback,size_t maximum) {
    const char *value=std::getenv(name);if(!value)return fallback;
    const std::string input(value);
    if(input.empty() || !std::all_of(input.begin(),input.end(),[](char c){return c>='0' && c<='9';}))
        throw std::invalid_argument(std::string("invalid ")+name);
    size_t end=0;const auto number=std::stoull(input,&end);
    if(end!=input.size() || !number || number>maximum)
        throw std::invalid_argument(std::string("out-of-range ")+name);
    return static_cast<size_t>(number);
}

class CpuFlowOpenScorer final
        : public flowkeep::NativeFusionFlowOpenScorer {
public:
    explicit CpuFlowOpenScorer(const fk_cpu_model *model) noexcept
        : model_(model) {}

    bool ScoreFlowOpen(
            const fk_flow_key &key,
            double *score,
            std::string *error) noexcept override {
        if (model_ == nullptr || score == nullptr ||
            (key.ip_version != 4u && key.ip_version != 6u)) {
            if (error != nullptr)
                *error = "flow-open scorer input is invalid";
            return false;
        }
        const uint16_t low = key.low_port;
        const uint16_t high = key.high_port;
        const auto either = [low, high](uint16_t port) {
            return low == port || high == port;
        };
        const float normalizer = static_cast<float>(std::log1p(65535.0));
        const bool one_well_known_one_ephemeral =
            (low <= 1023u && high >= 49152u) ||
            (high <= 1023u && low >= 49152u);
        const bool either_ephemeral = low >= 49152u || high >= 49152u;
        const bool either_registered =
            (low >= 1024u && low < 49152u) ||
            (high >= 1024u && high < 49152u);
        const float features[kFlowOpenFeatureCount] = {
            static_cast<float>(key.ip_version == 4u),
            static_cast<float>(key.ip_version == 6u),
            static_cast<float>(key.protocol == 1u),
            static_cast<float>(key.protocol == 6u),
            static_cast<float>(key.protocol == 17u),
            static_cast<float>(std::log1p(static_cast<double>(low))) /
                normalizer,
            static_cast<float>(std::log1p(static_cast<double>(high))) /
                normalizer,
            static_cast<float>(low <= 1023u),
            static_cast<float>(high <= 1023u),
            static_cast<float>(low == high),
            static_cast<float>(either(53u)),
            static_cast<float>(either(80u)),
            static_cast<float>(either(443u)),
            static_cast<float>(either(22u)),
            static_cast<float>(either(123u)),
            static_cast<float>(either(5353u)),
            static_cast<float>(either(137u)),
            static_cast<float>(either(67u) || either(68u)),
            static_cast<float>(either(445u)),
            static_cast<float>(either(3389u)),
            static_cast<float>(either_ephemeral),
            static_cast<float>(either_registered),
            static_cast<float>(one_well_known_one_ephemeral),
        };
        float output = 0.0f;
        if (!fk_cpu_model_predict(model_, features, kFlowOpenFeatureCount,
                &output, 1u) || !std::isfinite(output) ||
            output < 0.0f || output > 1.0f) {
            if (error != nullptr)
                *error = "flow-open CPU model prediction failed";
            return false;
        }
        *score = static_cast<double>(output);
        return true;
    }

private:
    const fk_cpu_model *model_;
};

bool flow_open_head_enabled(
        const std::unordered_map<std::string, std::string> &options) {
    return options.find("flow-open-model") != options.end();
}

const char *service_protocol(
        const std::unordered_map<std::string, std::string> &options) {
    if (options.count("terminal-coverage"))
        return "flowkeep-live-seven-state-fusion-service-v6";
    return flow_open_head_enabled(options)
        ? "flowkeep-live-seven-state-fusion-service-v5"
        : "flowkeep-live-seven-state-fusion-service-v4";
}

uint64_t process_cpu_ns() {
    struct timespec value{};
    if (clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &value) != 0)
        return 0u;
    return static_cast<uint64_t>(value.tv_sec) * UINT64_C(1000000000) +
        static_cast<uint64_t>(value.tv_nsec);
}

uint64_t monotonic_ns() noexcept {
    struct timespec value{};
    if (clock_gettime(CLOCK_MONOTONIC, &value) != 0)
        return 0u;
    return static_cast<uint64_t>(value.tv_sec) * UINT64_C(1000000000) +
        static_cast<uint64_t>(value.tv_nsec);
}

/*
 * Explicit no-persistence experiment path. Decisions are retained only so
 * the frozen Test evaluator can be fed after the timed service has stopped.
 * No serialization, compression, filesystem write, fsync, or directory
 * publication occurs in CommitConsecutive().
 */
class BufferedEvaluationCommitter final
        : public flowkeep::NativeFusionCommitter {
public:
    explicit BufferedEvaluationCommitter(size_t reserve_rows) {
        decisions_.reserve(reserve_rows);
    }

    bool CommitConsecutive(
            const flowkeep::NativeFusionDecision *decisions,
            size_t count,
            flowkeep::NativeFusionCommitResult *result,
            std::string *error) noexcept override {
        if (decisions == nullptr || count == 0u || result == nullptr) {
            if (error != nullptr)
                *error = "in-memory evaluation commit arguments are invalid";
            return false;
        }
        if (!decisions_.empty() &&
            decisions[0].sequence != decisions_.back().sequence + 1u) {
            if (error != nullptr)
                *error = "in-memory evaluation prefix is not consecutive";
            return false;
        }
        for (size_t index = 1u; index < count; ++index) {
            if (decisions[index].sequence !=
                    decisions[index - 1u].sequence + 1u) {
                if (error != nullptr)
                    *error = "in-memory evaluation batch is not consecutive";
                return false;
            }
        }
        try {
            decisions_.insert(decisions_.end(), decisions, decisions + count);
        } catch (...) {
            if (error != nullptr)
                *error = "in-memory evaluation buffer allocation failed";
            return false;
        }
        const uint64_t completed = monotonic_ns();
        if (completed == 0u) {
            if (error != nullptr)
                *error = "in-memory evaluation completion clock failed";
            return false;
        }
        *result = {};
        result->completed_monotonic_ns = completed;
        result->durability =
            flowkeep::NativeFusionDurability::TestOnlyMemory;
        return true;
    }

    const std::vector<flowkeep::NativeFusionDecision> &decisions() const {
        return decisions_;
    }

private:
    std::vector<flowkeep::NativeFusionDecision> decisions_;
};

bool parse_cpu_set(const std::string &text, std::set<uint32_t> *cpus);
using CpuPair = std::pair<uint32_t, uint32_t>;
bool parse_cpu_pair_set(
    const std::string &text,
    std::set<CpuPair> *pairs);

struct CpuTopologySummary {
    uint64_t logical_cpu_count = 0u;
    uint64_t physical_core_count = 0u;
    uint64_t maximum_threads_per_core = 0u;
    bool consumer_smt_active = false;
};

bool summarize_cpu_topology(
    const std::set<uint32_t> &cpus,
    CpuTopologySummary *summary);

enum class ControlledServiceCpuLayoutKind {
    Invalid = 0,
    LegacySharedCoordinatorCommitterCore = 1,
    PhysicalCoreIsolated = 2,
};

const char *controlled_service_cpu_layout_kind_name(
    ControlledServiceCpuLayoutKind kind);

ControlledServiceCpuLayoutKind controlled_service_cpu_layout(
    const std::set<uint32_t> &consumers,
    uint64_t service_workers,
    std::vector<uint32_t> *coordinator_cpu_set,
    std::vector<uint32_t> *committer_cpu_set,
    std::vector<std::vector<uint32_t>> *worker_cpu_sets);

bool physical_cpu_sets_disjoint(
    const std::vector<uint32_t> &left,
    const std::vector<uint32_t> &right);

constexpr const char *kUsage =
    "usage: fk_native_fusion_service_cli [required options]\n"
    "       fk_native_fusion_service_cli --inspect-cpu-layout "
    "CPU[,CPU...] WORKERS\n"
    "\n"
    "Required immutable bindings:\n"
    "  --shm-name NAME\n"
    "  --expected-run-epoch U64\n"
    "  --wait-seconds SECONDS\n"
    "  --model PATH\n"
    "  --model-sha256 HEX64\n"
    "  --dataset-id ID\n"
    "  --model-source-dataset-id ID\n"
    "  --cross-dataset-partial-diagnostic true|false\n"
    "  --bundle PATH\n"
    "  --bundle-sha256 HEX64\n"
    "  --bundle-receipt PATH\n"
    "  --bundle-receipt-sha256 HEX64\n"
    "  --source-model-sha256 HEX64\n"
    "  --flow-open-model PATH\n"
    "  --flow-open-model-sha256 HEX64\n"
    "  --flow-open-schema-sha256 HEX64\n"
    "  --flow-open-threshold PROBABILITY\n"
    "  --event-unit scenario|five_tuple\n"
    "  --event-map PATH\n"
    "  --event-map-sha256 HEX64\n"
    "  --event-assets-receipt PATH\n"
    "  --event-assets-receipt-sha256 HEX64\n"
    "  --event-assets-address-mode "
    "compact_disjoint_blocks|original_addresses_partial_diagnostic\n"
    "  --event-universe PATH\n"
    "  --event-universe-sha256 HEX64\n"
    "  --output-dir DIR\n"
    "  --retention-policy NAME\n"
    "  --retention-detector-coupling decoupled\n"
    "  --detector-schedule batch_fifo|deadline_guard_batch_fifo\n"
    "  --detector-deadline-us U64\n"
    "  --deadline-miss-policy enforce|record_only\n"
    "  --durable-commit-max-wait-age-anchor physical_enqueue|consumer_receive|first_durable_candidate\n"
    "     first_durable_candidate requires --durable-commit-max-wait-us 1..20000\n"
    "  --expected-run-uuid-hex HEX32\n"
    "  --expected-config-sha256 HEX64\n"
    "  --consumer-cpus CPU[,CPU...]\n"
    "  --reserved-dpdk-cpus CPU[,CPU...]\n"
    "  --reserved-dpdk-state-smt-pairs CPU:CPU[,CPU:CPU...]\n"
    "  --consumer-smt disabled|enabled\n"
    "  --consumer-oversubscription disabled|enabled\n"
    "\n"
    "Formal runtime settings (defaults shown):\n"
    "  --service-workers 1  (supported: 1,2,4,8)\n"
    "  --engine-threads 16\n"
    "  --batch-size 512\n"
    "  --durable-commit-batch-size BATCH_SIZE\n"
    "  --durable-commit-max-wait-us 25000\n"
    "  --batch-wait-us 5000\n"
    "  --max-inflight 1024\n"
    "  --flow-state-capacity MAX_INFLIGHT\n"
    "  --route-quantum MAX_INFLIGHT\n"
    "  --poll-sleep-us 50\n"
    "  --adaptive-history-meta PATH --adaptive-history-meta-sha256 HEX64\n"
    "  --adaptive-threshold P --adaptive-watch-ratio R\n"
    "  --adaptive-first-packet 4 --adaptive-near-gap N "
    "--adaptive-far-gap N --adaptive-horizon-packet 20\n"
    "  --adaptive-action-risk PATH --adaptive-action-risk-sha256 HEX64\n"
    "  --adaptive-marginal-table PATH --adaptive-marginal-table-sha256 HEX64\n"
    "  --adaptive-fixed-checkpoints comma-separated increasing points ending in 20 (at most four)\n"
    "  --adaptive-event-frontiers true (in-memory history, causal event batching)\n"
    "  --adaptive-trained-policy PATH --adaptive-trained-policy-sha256 HEX\n"
    "\n"
    "consumer-cpus must contain engine-threads+1 logical CPUs normally, or\n"
    "engine-threads+2 when consumer SMT is enabled. A formal SMT layout has\n"
    "two singleton physical cores for the coordinator and committer, then\n"
    "an equal positive number of complete SMT pairs per service worker.\n"
    "Legacy layouts that split one SMT pair between coordinator and committer\n"
    "remain executable for evidence readability but are never formal-ready.\n"
    "Consumer SMT is disabled by default. When\n"
    "enabled, siblings may only coexist inside the consumer set; every\n"
    "consumer physical core remains disjoint from reserved-dpdk-cpus.\n"
    "Reserved DPDK SMT sharing is rejected except for the exact closed\n"
    "state-worker sibling-pair whitelist supplied above.\n"
    "Controlled oversubscription is disabled by default and must be enabled\n"
    "explicitly when service-thread-count exceeds the consumer CPU count;\n"
    "explicit mode permits at most four service threads per logical CPU.\n";

const char *const kRequired[] = {
    "shm-name", "expected-run-epoch", "wait-seconds", "model",
    "model-sha256", "dataset-id", "bundle", "bundle-sha256",
    "bundle-receipt", "bundle-receipt-sha256",
    "source-model-sha256", "event-unit", "event-map",
    "event-map-sha256", "event-assets-receipt",
    "event-assets-receipt-sha256", "event-universe",
    "event-universe-sha256", "output-dir", "retention-policy",
    "retention-detector-coupling", "detector-schedule",
    "detector-deadline-us",
    "expected-run-uuid-hex", "expected-config-sha256", "consumer-cpus",
    "reserved-dpdk-cpus",
};

bool parse_u64(const std::string &text, uint64_t *value) {
    if (text.empty() || value == nullptr || text[0] == '-')
        return false;
    char *end = nullptr;
    errno = 0;
    const unsigned long long parsed = std::strtoull(text.c_str(), &end, 10);
    if (errno != 0 || end == text.c_str() || *end != '\0')
        return false;
    *value = static_cast<uint64_t>(parsed);
    return true;
}

uint64_t configured_commit_depth(const std::unordered_map<std::string,std::string> &options) {
    uint64_t depth=2u;
    const auto found=options.find("durable-commit-depth");
    if(found!=options.end() && !parse_u64(found->second,&depth))return 0u;
    return depth;
}

bool load_marginal_table(
        const std::string &path,
        fk_marginal_checkpoint_config *config,
        std::string *error) {
    const bool ok = fk_marginal_checkpoint_load(path.c_str(), config);
    if (!ok && error) *error = "marginal checkpoint table is malformed";
    return ok;
}

flowkeep::NativeFusionDurableAgeAnchor parse_age_anchor(
        const std::string &text) {
    if (text == "consumer_receive_monotonic_ns" ||
        text == "consumer_receive")
        return flowkeep::NativeFusionDurableAgeAnchor::ConsumerReceive;
    if (text == "first_durable_candidate_monotonic_ns" ||
        text == "first_durable_candidate")
        return flowkeep::NativeFusionDurableAgeAnchor::FirstDurableCandidate;
    return flowkeep::NativeFusionDurableAgeAnchor::PhysicalEnqueue;
}

bool exact_hex(const std::string &text, size_t length) {
    if (text.size() != length)
        return false;
    for (char value : text) {
        if (!((value >= '0' && value <= '9') ||
              (value >= 'a' && value <= 'f'))) {
            return false;
        }
    }
    return true;
}

bool parse_detector_schedule(
        const std::string &text,
        flowkeep::NativeFusionDetectorSchedule *schedule) {
    if (schedule == nullptr)
        return false;
    if (text == "batch_fifo") {
        *schedule = flowkeep::NativeFusionDetectorSchedule::BatchFifo;
        return true;
    }
    if (text == "deadline_guard_batch_fifo") {
        *schedule = flowkeep::NativeFusionDetectorSchedule::
            DeadlineGuardBatchFifo;
        return true;
    }
    return false;
}

bool valid_policy_name(const std::string &text) {
    if (text.empty() || text.size() > 64u)
        return false;
    return std::all_of(text.begin(), text.end(), [](unsigned char value) {
        return (value >= 'a' && value <= 'z') ||
            (value >= '0' && value <= '9') || value == '_';
    });
}

bool parse_sha256(const std::string &text, uint8_t output[32]) {
    if (!exact_hex(text, 64u) || output == nullptr)
        return false;
    const auto digit = [](char value) -> uint8_t {
        return value <= '9' ? static_cast<uint8_t>(value - '0') :
            static_cast<uint8_t>(value - 'a' + 10);
    };
    for (size_t index = 0u; index < 32u; ++index) {
        output[index] = static_cast<uint8_t>(
            (digit(text[index * 2u]) << 4u) |
            digit(text[index * 2u + 1u]));
    }
    return true;
}

bool file_sha256(const std::string &path, std::string *hex) {
    const int fd = ::open(path.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0)
        return false;
    struct stat status{};
    if (::fstat(fd, &status) != 0 || !S_ISREG(status.st_mode)) {
        (void)::close(fd);
        return false;
    }
    EVP_MD_CTX *context = EVP_MD_CTX_new();
    if (context == nullptr) {
        (void)::close(fd);
        return false;
    }
    bool success = EVP_DigestInit_ex(context, EVP_sha256(), nullptr) == 1;
    std::array<unsigned char, 1u << 16u> buffer{};
    while (success) {
        const ssize_t count = ::read(fd, buffer.data(), buffer.size());
        if (count < 0 && errno == EINTR)
            continue;
        if (count < 0) {
            success = false;
            break;
        }
        if (count == 0)
            break;
        success = EVP_DigestUpdate(
            context, buffer.data(), static_cast<size_t>(count)) == 1;
    }
    unsigned char digest[EVP_MAX_MD_SIZE]{};
    unsigned int bytes = 0u;
    success = success &&
        EVP_DigestFinal_ex(context, digest, &bytes) == 1 && bytes == 32u;
    EVP_MD_CTX_free(context);
    success = (::close(fd) == 0) && success;
    if (!success)
        return false;
    static const char alphabet[] = "0123456789abcdef";
    try {
        hex->resize(64u);
    } catch (...) {
        return false;
    }
    for (size_t index = 0u; index < 32u; ++index) {
        (*hex)[index * 2u] = alphabet[digest[index] >> 4u];
        (*hex)[index * 2u + 1u] = alphabet[digest[index] & 0x0fu];
    }
    return true;
}

std::string canonical_existing_path(const std::string &path) {
    char *resolved = ::realpath(path.c_str(), nullptr);
    if (resolved == nullptr)
        return {};
    std::string result;
    try {
        result = resolved;
    } catch (...) {
    }
    std::free(resolved);
    return result;
}

bool verify_file_binding(
        const std::string &path,
        const std::string &expected,
        std::string *canonical,
        std::string *error) {
    *canonical = canonical_existing_path(path);
    std::string actual;
    if (canonical->empty() || !file_sha256(*canonical, &actual) ||
        actual != expected) {
        *error = "file SHA-256 binding failed: " + path;
        return false;
    }
    return true;
}

bool apply_affinity(
        const std::set<uint32_t> &cpus,
        std::string *error) {
    cpu_set_t requested;
    CPU_ZERO(&requested);
    for (uint32_t cpu : cpus)
        CPU_SET(cpu, &requested);
    if (::sched_setaffinity(0, sizeof(requested), &requested) != 0) {
        *error = "sched_setaffinity for consumer cpuset failed";
        return false;
    }
    cpu_set_t observed;
    CPU_ZERO(&observed);
    if (::sched_getaffinity(0, sizeof(observed), &observed) != 0) {
        *error = "sched_getaffinity for consumer cpuset failed";
        return false;
    }
    for (size_t cpu = 0u; cpu < CPU_SETSIZE; ++cpu) {
        if (CPU_ISSET(cpu, &requested) != CPU_ISSET(cpu, &observed)) {
            *error = "actual consumer affinity differs from requested cpuset";
            return false;
        }
    }
    return true;
}

std::unique_ptr<flowkeep::NativeFusionRequestSource> wait_for_source(
        const std::string &name,
        uint64_t epoch,
        double seconds,
        std::string *error) {
    const auto deadline = std::chrono::steady_clock::now() +
        std::chrono::duration<double>(seconds);
    do {
        std::unique_ptr<flowkeep::NativeFusionRequestSource> source =
            flowkeep::OpenNativeFusionShmSource(name, epoch, error);
        if (source)
            return source;
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    } while (std::chrono::steady_clock::now() < deadline);
    *error = "timed out waiting for clean detector SHM producer";
    return nullptr;
}

bool write_all(int fd, const char *data, size_t bytes) {
    size_t offset = 0u;
    while (offset < bytes) {
        const ssize_t count = ::write(fd, data + offset, bytes - offset);
        if (count < 0 && errno == EINTR)
            continue;
        if (count <= 0)
            return false;
        offset += static_cast<size_t>(count);
    }
    return true;
}

bool atomic_write_json(
        const std::string &path,
        const json_t *document,
        std::string *error) {
    char *payload = json_dumps(document,
        JSON_INDENT(2) | JSON_SORT_KEYS | JSON_ENSURE_ASCII);
    if (payload == nullptr) {
        *error = "receipt JSON serialization failed";
        return false;
    }
    const std::string temporary = path + ".tmp." +
        std::to_string(static_cast<unsigned long long>(::getpid()));
    const int fd = ::open(temporary.c_str(),
        O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
    bool success = fd >= 0;
    if (success) {
        success = write_all(fd, payload, std::strlen(payload)) &&
            write_all(fd, "\n", 1u) && ::fsync(fd) == 0;
        if (::close(fd) != 0)
            success = false;
    }
    if (success)
        success = ::rename(temporary.c_str(), path.c_str()) == 0;
    if (success) {
        const size_t slash = path.find_last_of('/');
        const std::string parent = slash == 0u ? "/" :
            path.substr(0u, slash);
        const int directory = ::open(parent.c_str(),
            O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
        success = directory >= 0 && ::fsync(directory) == 0;
        if (directory >= 0 && ::close(directory) != 0)
            success = false;
    }
    if (!success) {
        (void)::unlink(temporary.c_str());
        *error = "receipt atomic durable publication failed";
    }
    std::free(payload);
    return success;
}

void object_string(json_t *object, const char *name, const std::string &value) {
    json_object_set_new(object, name, json_stringn(value.data(), value.size()));
}

void object_u64(json_t *object, const char *name, uint64_t value) {
    json_object_set_new(object, name,
        json_integer(static_cast<json_int_t>(value)));
}

void object_bool(json_t *object, const char *name, bool value) {
    json_object_set_new(object, name, value ? json_true() : json_false());
}

json_t *cpu_array(const std::set<uint32_t> &cpus) {
    json_t *array = json_array();
    for (uint32_t cpu : cpus)
        json_array_append_new(array, json_integer(cpu));
    return array;
}

json_t *cpu_array(const std::vector<uint32_t> &cpus) {
    json_t *array = json_array();
    for (uint32_t cpu : cpus)
        json_array_append_new(array, json_integer(cpu));
    return array;
}

ControlledServiceCpuLayoutKind attach_service_cpu_layout(
        json_t *scheduling,
        const std::unordered_map<std::string, std::string> &options,
        uint64_t engine_threads,
        uint64_t service_workers) {
    std::set<uint32_t> cpus;
    const bool cpus_valid =
        parse_cpu_set(options.at("consumer-cpus"), &cpus);
    CpuTopologySummary topology{};
    const bool topology_valid = cpus_valid &&
        summarize_cpu_topology(cpus, &topology);
    std::vector<uint32_t> coordinator_cpus;
    std::vector<uint32_t> committer_cpus;
    std::vector<std::vector<uint32_t>> worker_cpu_sets;
    const ControlledServiceCpuLayoutKind layout = topology_valid ?
        controlled_service_cpu_layout(cpus, service_workers,
            &coordinator_cpus, &committer_cpus, &worker_cpu_sets) :
        ControlledServiceCpuLayoutKind::Invalid;
    const bool isolated =
        layout == ControlledServiceCpuLayoutKind::PhysicalCoreIsolated;
    const bool legacy_shared = layout == ControlledServiceCpuLayoutKind::
        LegacySharedCoordinatorCommitterCore;

    json_object_set_new(scheduling, "consumer_cpus", cpu_array(cpus));
    object_string(scheduling, "affinity_layout_kind",
        controlled_service_cpu_layout_kind_name(layout));
    object_bool(scheduling, "affinity_layout_compatible",
        layout != ControlledServiceCpuLayoutKind::Invalid);
    object_bool(scheduling, "legacy_affinity_layout_compatible",
        legacy_shared);
    object_bool(scheduling, "dedicated_affinity_layout_resolved", isolated);
    object_bool(scheduling,
        "coordinator_committer_physical_core_disjoint", isolated);
    object_bool(scheduling, "service_role_physical_core_disjoint", isolated);
    object_bool(scheduling, "coordinator_committer_intentional_timeshare",
        legacy_shared);
    object_bool(scheduling, "cross_role_smt_overlap", !isolated);
    object_bool(scheduling, "smt_overlap", !isolated);
    object_u64(scheduling, "service_thread_count", engine_threads + 3u +
        (options.count("persistent-state-dir") ? service_workers : 0u));
    object_u64(scheduling, "service_compute_thread_count", engine_threads + 2u);
    object_string(scheduling, "consumer_oversubscription_flag_scope", "compute_pool_only_io_threads_explicitly_timeshare");
    object_bool(scheduling, "io_threads_share_existing_cpu_affinity", true);
    object_u64(scheduling, "prepare_publish_pipeline_depth", configured_commit_depth(options));
    object_u64(scheduling, "prepared_payload_limit_per_batch_bytes",
        options.count("terminal-coverage") ? (16u << 20) : (8u << 20));
    object_string(scheduling,"drain_preparation_cpu_role",
        options.count("ledger-overlap-compression")?"idle_existing_inference_pool_after_verified_input_fence":"committer");
    object_string(scheduling,"drain_preparation_scheduler",
        options.count("ledger-overlap-compression")?"SCHED_IDLE":"unchanged");
    object_u64(scheduling, "prepared_compressed_limit_per_batch_bytes", 9u << 20);
    object_u64(scheduling, "prepared_maximum_rows", 5120u);
    object_string(scheduling, "pipeline_memory_scope", "bounded_service_scratch_not_retained_flow_64MiB_budget");
    object_bool(scheduling, "consumer_thread_oversubscription_enabled",
        options.at("consumer-oversubscription") == "enabled");
    object_bool(scheduling, "consumer_thread_oversubscription_active",
        engine_threads + 2u > topology.logical_cpu_count);
    object_u64(scheduling, "service_threads_per_logical_cpu_numerator",
        engine_threads + 2u);
    object_u64(scheduling, "service_threads_per_logical_cpu_denominator",
        topology.logical_cpu_count);
    object_u64(scheduling, "service_cpuset_logical_cpu_count",
        topology.logical_cpu_count);
    object_u64(scheduling, "service_cpuset_physical_core_count",
        topology.physical_core_count);
    object_u64(scheduling, "service_process_cpuset_physical_cores",
        topology.physical_core_count);
    object_u64(scheduling, "consumer_maximum_threads_per_core",
        topology.maximum_threads_per_core);
    object_bool(scheduling, "consumer_smt_enabled",
        options.at("consumer-smt") == "enabled");
    object_bool(scheduling, "consumer_smt_active",
        topology.consumer_smt_active);
    object_string(scheduling, "reserved_dpdk_state_smt_pairs",
        options.at("reserved-dpdk-state-smt-pairs"));
    object_bool(scheduling, "dpdk_cpu_overlap", false);
    json_object_set_new(scheduling, "coordinator_cpus",
        cpu_array(coordinator_cpus));
    json_object_set_new(scheduling, "committer_cpus",
        cpu_array(committer_cpus));
    json_t *worker_plan = json_array();
    for (const std::vector<uint32_t> &worker_cpus : worker_cpu_sets)
        json_array_append_new(worker_plan, cpu_array(worker_cpus));
    json_object_set_new(scheduling, "worker_cpu_sets", worker_plan);
    return layout;
}

void attach_model_residency(
        json_t *root,
        const fk_native_fusion_metadata &metadata) {
    json_t *residency = json_object();
    object_string(residency, "method", "mlock");
    object_u64(residency, "requested_bytes", metadata.model_bytes);
    object_u64(residency, "locked_bytes", metadata.locked_bytes);
    object_bool(residency, "success",
        metadata.mlock_succeeded == 1u && metadata.model_bytes > 0u &&
        metadata.locked_bytes == metadata.model_bytes);
    json_object_set_new(root, "model_residency", residency);
}

void attach_retention_detector_contract(
        json_t *root,
        const std::unordered_map<std::string, std::string> &options) {
    json_t *contract = json_object();
    object_string(contract, "retention_policy",
        options.at("retention-policy"));
    object_string(contract, "detector_schedule",
        options.at("detector-schedule"));
    object_string(contract, "coupling_mode",
        options.at("retention-detector-coupling"));
    object_bool(contract, "coupled", false);
    object_bool(contract, "retention_signal_used_for_scheduling", false);
    object_bool(contract, "detector_output_used_for_retention", false);
    object_bool(contract, "truth_or_future_fields_used", false);
    object_string(contract, "priority_input",
        "physical_enqueue_monotonic_ns_plus_uniform_slo_only");
    json_object_set_new(root, "retention_detector_contract", contract);
}

json_t *minimal_running_receipt(
        const std::unordered_map<std::string, std::string> &options,
        const flowkeep::NativeFusionJsonlLedgerAudit &ledger,
        const flowkeep::NativeFusionSourceSnapshot &initial,
        const fk_native_fusion_metadata &metadata) {
    uint64_t deadline_us = 0u;
    uint64_t batch = 0u;
    uint64_t durable_commit_batch = 0u;
    uint64_t durable_commit_max_wait_us = 0u;
    uint64_t batch_wait_us = 0u;
    uint64_t max_inflight = 0u;
    uint64_t flow_state_capacity = 0u;
    uint64_t route_quantum = 0u;
    uint64_t engine_threads = 0u;
    uint64_t service_workers = 0u;
    (void)parse_u64(options.at("detector-deadline-us"), &deadline_us);
    (void)parse_u64(options.at("batch-size"), &batch);
    (void)parse_u64(options.at("durable-commit-batch-size"),
        &durable_commit_batch);
    (void)parse_u64(options.at("durable-commit-max-wait-us"),
        &durable_commit_max_wait_us);
    const auto age_anchor = parse_age_anchor(
        options.find("durable-commit-max-wait-age-anchor") == options.end()
        ? "physical_enqueue_monotonic_ns"
        : options.at("durable-commit-max-wait-age-anchor"));
    (void)parse_u64(options.at("batch-wait-us"), &batch_wait_us);
    (void)parse_u64(options.at("max-inflight"), &max_inflight);
    (void)parse_u64(options.at("flow-state-capacity"),
        &flow_state_capacity);
    (void)parse_u64(options.at("route-quantum"), &route_quantum);
    (void)parse_u64(options.at("engine-threads"), &engine_threads);
    (void)parse_u64(options.at("service-workers"), &service_workers);
    json_t *root = json_object();
    object_string(root, "protocol", service_protocol(options));
    object_string(root, "status", "RUNNING");
    object_bool(root, "formal_ready", false);
    object_bool(root, "production_service_ready", false);
    object_u64(root, "durable_sequence", ledger.last_sequence);
    object_u64(root, "acked_sequence", 0u);
    json_object_set_new(root, "failure", json_null());
    object_bool(root, "interrupted", false);
    object_bool(root, "final_flush_complete", false);
    object_string(root, "routing_mode", "flow_key_event_assets_v1");
    attach_model_residency(root, metadata);

    json_t *transport = json_object();
    object_string(transport, "consumer_mode", "formal_ack_consumer");
    object_string(transport, "mapping_access", "read-write-ack-only");
    object_u64(transport, "run_epoch", initial.run_epoch);
    object_bool(transport, "producer_done", false);
    object_bool(transport, "formal_transport_clean", true);
    object_u64(transport, "records_popped", initial.records_peeked);
    object_u64(transport, "records_acked", initial.records_acked);
    object_u64(transport, "producer_overflow_failures",
        initial.producer_overruns);
    object_u64(transport, "producer_drops", initial.producer_drops);
    object_u64(transport, "overruns", initial.producer_overruns);
    object_u64(transport, "sequence_errors", initial.sequence_gaps);
    object_u64(transport, "corrupt_records",
        initial.consumer_validation_failures);
    object_u64(transport, "consumer_fault", initial.consumer_fault);
    json_object_set_new(root, "transport", transport);

    json_t *scheduling = json_object();
    object_string(scheduling, "mode", options.at("detector-schedule"));
    object_string(scheduling, "retention_policy",
        options.at("retention-policy"));
    object_string(scheduling, "retention_detector_coupling",
        options.at("retention-detector-coupling"));
    object_bool(scheduling, "retention_detector_coupled", false);
    object_bool(scheduling, "retention_signal_used_for_scheduling", false);
    object_string(scheduling, "retention_commit_mode",
        "bounded_prepare_publish_v1");
    object_string(scheduling, "durable_commit_durability",
        (ledger.synchronous_wal_segments?"synchronous_rocksdb_wal_segments":"fsync_recoverable_segment_and_directory"));
    object_u64(scheduling, "durable_commit_queue_depth", configured_commit_depth(options));
    object_bool(scheduling,
        "detector_ingest_decoupled_from_durable_fsync", true);
    object_bool(scheduling, "ack_after_durable_only", true);
    object_u64(scheduling, "configured_deadline_us", deadline_us);
    object_u64(scheduling, "configured_deadline_ns", deadline_us * 1000u);
    object_string(scheduling, "deadline_miss_policy",
        options.at("deadline-miss-policy"));
    object_bool(scheduling, "deadline_gate_enforced",
        options.at("deadline-miss-policy") == "enforce");
    const bool deadline_guard = options.at("detector-schedule") ==
        "deadline_guard_batch_fifo";
    object_bool(scheduling, "deadline_guard_enabled", deadline_guard);
    object_u64(scheduling, "dispatch_guard_ns",
        deadline_guard ? deadline_us * 1000u / 2u : 0u);
    object_string(scheduling, "deadline_rule",
        "decision_monotonic_ns <= physical_enqueue_monotonic_ns + "
        "configured_deadline_ns");
    if (deadline_guard) {
        object_string(scheduling, "latest_start_rule",
            "oldest_physical_enqueue_monotonic_ns + "
            "configured_deadline_ns - dispatch_guard_ns");
    } else {
        json_object_set_new(scheduling, "latest_start_rule", json_null());
    }
    object_u64(scheduling, "batch_capacity", batch);
    object_u64(scheduling, "inference_batch_capacity", batch);
    object_u64(scheduling, "durable_commit_batch_capacity",
        durable_commit_batch);
    object_u64(scheduling, "durable_commit_max_wait_us",
        durable_commit_max_wait_us);
    object_u64(scheduling, "durable_commit_max_wait_ns",
        durable_commit_max_wait_us * 1000u);
    object_string(scheduling, "durable_commit_max_wait_rule",
        "ordered_head_submit_guard_while_durable_committer_idle");
    object_string(scheduling, "durable_commit_max_wait_age_anchor",
        flowkeep::NativeFusionDurableAgeAnchorName(age_anchor));
    object_bool(scheduling, "durable_commit_candidate_coalescing_enabled",
        age_anchor == flowkeep::NativeFusionDurableAgeAnchor::FirstDurableCandidate);
    object_string(scheduling, "detection_deadline_clock_unmodified",
        "physical_enqueue_monotonic_ns");
    object_bool(scheduling, "durable_commit_max_wait_is_ack_bound", false);
    object_bool(scheduling,
        "durable_commit_busy_time_may_exceed_max_wait", true);
    object_u64(scheduling, "durable_commit_submissions", 0u);
    object_u64(scheduling, "durable_commit_successful_calls", 0u);
    object_u64(scheduling, "durable_commit_failed_calls", 0u);
    object_u64(scheduling, "fsync_attested_commit_calls", 0u);
    object_u64(scheduling, "ack_calls", 0u);
    object_u64(scheduling, "requests_persisted", 0u);
    json_t *durable_triggers = json_object();
    object_u64(durable_triggers, "capacity", 0u);
    object_u64(durable_triggers, "terminal", 0u);
    object_u64(durable_triggers, "max_wait", 0u);
    object_u64(durable_triggers, "quiescent_feedback_subset_of_terminal",0u);
    object_u64(durable_triggers, "drain_wait_subset_of_max_wait",0u);
    object_u64(scheduling,"drain_commit_max_wait_ns",0u);
    json_object_set_new(scheduling, "durable_commit_triggers",
        durable_triggers);
    json_t *durable_rows = json_object();
    object_u64(durable_rows, "minimum", 0u);
    object_u64(durable_rows, "maximum", 0u);
    json_object_set_new(scheduling, "durable_commit_batch_rows",
        durable_rows);
    object_u64(scheduling, "maximum_durable_commit_batch_wait_ns", 0u);
    object_u64(scheduling, "durable_commit_total_ns", 0u);
    object_u64(scheduling, "maximum_durable_commit_ns", 0u);
    object_u64(scheduling, "durable_commit_elapsed_ns_sum", 0u);
    object_u64(scheduling, "maximum_durable_commit_elapsed_ns", 0u);
    object_u64(scheduling,
        "first_durable_commit_submit_monotonic_ns", 0u);
    object_u64(scheduling,
        "last_durable_commit_completion_monotonic_ns", 0u);
    object_u64(scheduling, "durable_commit_active_span_ns", 0u);
    object_u64(scheduling, "maximum_decision_to_durable_ns", 0u);
    object_u64(scheduling,
        "maximum_physical_enqueue_to_durable_ns", 0u);
    object_u64(scheduling, "maximum_decision_to_ack_ns", 0u);
    object_u64(scheduling,
        "maximum_physical_enqueue_to_ack_ns", 0u);
    object_string(scheduling, "ack_timing_point",
        "immediately_after_successful_source_ack_call_return");
    object_bool(scheduling, "durable_trigger_count_match", true);
    object_bool(scheduling, "durable_call_count_match", true);
    object_u64(scheduling, "batch_wait_us", batch_wait_us);
    object_u64(scheduling, "max_inflight", max_inflight);
    object_u64(scheduling, "flow_state_capacity", flow_state_capacity);
    object_u64(scheduling, "route_quantum", route_quantum);
    object_u64(scheduling, "engine_threads", engine_threads);
    object_u64(scheduling, "service_workers", service_workers);
    (void)attach_service_cpu_layout(
        scheduling, options, engine_threads, service_workers);
    attach_retention_detector_contract(root, options);
    json_object_set_new(root, "detector_scheduling", scheduling);

    json_t *evidence = json_object();
    object_string(evidence, "run_uuid_hex",
        options.at("expected-run-uuid-hex"));
    object_string(evidence, "config_sha256",
        options.at("expected-config-sha256"));
    object_bool(evidence, "complete", true);
    json_object_set_new(root, "evidence_binding", evidence);
    json_error_t json_error{};
    json_t *manifest = json_loads(
        ledger.manifest_json.c_str(), JSON_REJECT_DUPLICATES, &json_error);
    if (manifest == nullptr)
        manifest = json_null();
    json_object_set_new(root, "decision_ledger", manifest);
    return root;
}

uint64_t file_size(const std::string &path) {
    struct stat status{};
    return ::stat(path.c_str(), &status) == 0 && status.st_size >= 0 ?
        static_cast<uint64_t>(status.st_size) : 0u;
}

json_t *final_receipt(
        const std::unordered_map<std::string, std::string> &options,
        const flowkeep::NativeFusionServiceReceipt &service,
        const flowkeep::NativeFusionJsonlLedgerAudit &ledger,
        const fk_native_fusion_metadata &metadata,
        const std::string &model_path,
        const std::string &bundle_path,
        const std::string &bundle_receipt_path,
        const std::string &event_map_path,
        const std::string &event_universe_path,
        const std::string &assets_receipt_path,
        uint64_t route_count,
        uint64_t event_count,
        uint64_t service_process_cpu_ns,
        uint64_t service_timed_peak_rss_kib,
        bool run_success,
        const std::string &failure) {
    const bool online_persistence_disabled =
        options.at("online-persistence") == "disabled";
    uint64_t expected_epoch = 0u;
    uint64_t expected_durable_commit_batch = 0u;
    uint64_t expected_durable_commit_max_wait_us = 0u;
    uint64_t expected_route_quantum = 0u;
    uint64_t expected_flow_state_capacity = 0u;
    uint64_t engine_threads = 0u;
    uint64_t service_workers = 0u;
    flowkeep::NativeFusionDetectorSchedule expected_schedule{};
    (void)parse_u64(options.at("expected-run-epoch"), &expected_epoch);
    (void)parse_u64(options.at("durable-commit-batch-size"),
        &expected_durable_commit_batch);
    (void)parse_u64(options.at("durable-commit-max-wait-us"),
        &expected_durable_commit_max_wait_us);
    (void)parse_u64(options.at("route-quantum"),
        &expected_route_quantum);
    (void)parse_u64(options.at("flow-state-capacity"),
        &expected_flow_state_capacity);
    (void)parse_u64(options.at("engine-threads"), &engine_threads);
    (void)parse_u64(options.at("service-workers"), &service_workers);
    (void)parse_detector_schedule(
        options.at("detector-schedule"), &expected_schedule);
    std::set<uint32_t> receipt_cpus;
    const bool receipt_cpus_valid =
        parse_cpu_set(options.at("consumer-cpus"), &receipt_cpus);
    std::vector<uint32_t> receipt_coordinator_cpus;
    std::vector<uint32_t> receipt_committer_cpus;
    std::vector<std::vector<uint32_t>> receipt_worker_cpus;
    const ControlledServiceCpuLayoutKind receipt_layout =
        receipt_cpus_valid ? controlled_service_cpu_layout(
            receipt_cpus, service_workers, &receipt_coordinator_cpus,
            &receipt_committer_cpus, &receipt_worker_cpus) :
        ControlledServiceCpuLayoutKind::Invalid;
    const bool physical_affinity_layout_ready =
        receipt_layout ==
            ControlledServiceCpuLayoutKind::PhysicalCoreIsolated &&
        options.at("consumer-smt") == "enabled" &&
        physical_cpu_sets_disjoint(
            receipt_coordinator_cpus, receipt_committer_cpus) &&
        service.coordinator_affinity_requested == 1u &&
        service.coordinator_affinity_attested == 1u &&
        service.committer_affinity_requested == 1u &&
        service.committer_affinity_attested == 1u &&
        service.worker_affinity_plan_requested == 1u &&
        service.worker_affinity_plan_attested == 1u;
    const bool route_cache_closed =
        service.route_cache_hits <=
            UINT64_MAX - service.route_cache_misses &&
        service.route_cache_hits + service.route_cache_misses ==
            service.route_bindings_validated &&
        service.route_bindings_validated == service.requests_routed &&
        service.route_cache_misses == service.frozen_flow_routes;
    const bool model_residency_ready = metadata.mlock_succeeded == 1u &&
        metadata.model_bytes > 0u &&
        metadata.locked_bytes == metadata.model_bytes;
    const bool durable_trigger_count_valid =
        service.durable_commit_trigger_capacity <=
            UINT64_MAX - service.durable_commit_trigger_terminal &&
        service.durable_commit_trigger_capacity +
                service.durable_commit_trigger_terminal <=
            UINT64_MAX - service.durable_commit_trigger_max_wait;
    const uint64_t durable_trigger_count = durable_trigger_count_valid ?
        service.durable_commit_trigger_capacity +
            service.durable_commit_trigger_terminal +
            service.durable_commit_trigger_max_wait : 0u;
    const bool durable_call_count_valid =
        service.durable_commit_calls <=
            UINT64_MAX - service.durable_commit_failed_calls;
    const uint64_t durable_call_count = durable_call_count_valid ?
        service.durable_commit_calls +
            service.durable_commit_failed_calls : 0u;
    const bool durable_metrics_ready = durable_trigger_count_valid &&
        durable_call_count_valid &&
        expected_durable_commit_max_wait_us != 0u &&
        expected_durable_commit_max_wait_us <= UINT64_MAX / 1000u &&
        service.durable_commit_max_wait_ns ==
            expected_durable_commit_max_wait_us * 1000u &&
        service.durable_commit_submissions != 0u &&
        service.durable_commit_submissions == durable_trigger_count &&
        service.durable_commit_submissions == durable_call_count &&
        service.durable_commit_failed_calls == 0u &&
        service.durable_commit_calls == service.ack_calls &&
        (online_persistence_disabled ?
            service.fsync_attested_commit_calls == 0u :
            service.durable_commit_calls ==
                (ledger.synchronous_wal_segments?service.sync_wal_attested_commit_calls:service.fsync_attested_commit_calls)) &&
        service.minimum_durable_commit_batch_rows != 0u &&
        service.minimum_durable_commit_batch_rows <=
            service.maximum_durable_commit_batch_rows &&
        service.maximum_durable_commit_batch_rows <=
            service.durable_commit_batch_capacity &&
        service.durable_commit_total_ns >=
            service.maximum_durable_commit_ns &&
        service.durable_commit_elapsed_ns_sum >=
            service.maximum_durable_commit_elapsed_ns &&
        service.first_durable_commit_submit_monotonic_ns != 0u &&
        service.last_durable_commit_completion_monotonic_ns >=
            service.first_durable_commit_submit_monotonic_ns &&
        service.durable_commit_active_span_ns ==
            service.last_durable_commit_completion_monotonic_ns -
                service.first_durable_commit_submit_monotonic_ns;
    const auto flow_state_map_ready =
        [expected_flow_state_capacity](
                const flowkeep::NativeFusionFlowStateMapMetrics &map) {
            return map.post_reserve_bucket_count != 0u &&
                map.terminal_bucket_count ==
                    map.post_reserve_bucket_count &&
                map.terminal_entries <= map.peak_entries &&
                map.peak_entries <= expected_flow_state_capacity;
        };
    const bool flow_state_ready =
        expected_flow_state_capacity != 0u &&
        service.flow_state_capacity == expected_flow_state_capacity &&
        service.flow_state_capacity_failures == 0u &&
        service.flow_state_runtime_rehashes == 0u &&
        service.flow_state_capacity_closed == 1u &&
        service.flow_state_no_runtime_rehash == 1u &&
        flow_state_map_ready(service.stable_flow_routes_map) &&
        flow_state_map_ready(service.flow_coverage_map) &&
        flow_state_map_ready(service.active_semantic_generations_map) &&
        flow_state_map_ready(service.event_coverage_map);
    const bool service_complete = run_success && model_residency_ready &&
        physical_affinity_layout_ready &&
        (online_persistence_disabled ? service.completed == 1u :
            service.production_service_ready == 1u) &&
        service.flow_open_coverage_closed == 1u &&
        service.durable_sequence_equals_acked_sequence == 1u &&
        ledger.faulted == 0u && ledger.last_sequence > 0u &&
        ledger.last_sequence == service.last_acked_sequence &&
        service.final_source.run_epoch == expected_epoch &&
        service.final_source.producer_done == 1u &&
        service.final_source.consumer_fault == 0u &&
        service.durable_commit_queue_depth ==
            (online_persistence_disabled ? 1u :
                configured_commit_depth(options)) &&
        service.durable_commit_batch_capacity ==
            expected_durable_commit_batch &&
        durable_metrics_ready &&
        service.route_quantum == expected_route_quantum &&
        flow_state_ready &&
        route_cache_closed &&
        service.detector_schedule == expected_schedule &&
        service.retention_detector_coupling ==
            flowkeep::NativeFusionRetentionDetectorCoupling::Decoupled &&
        service.detector_schedule_uses_retention_signal == 0u &&
        service.detector_ingest_decoupled_from_durable_fsync == 1u &&
        service.ack_after_durable_only == 1u;
    const bool transport_clean =
        service.final_source.run_epoch == expected_epoch &&
        service.final_source.producer_done == 1u &&
        service.final_source.consumer_fault == 0u &&
        service.final_source.producer_overruns == 0u &&
        service.final_source.producer_drops == 0u &&
        service.final_source.sequence_gaps == 0u &&
        service.final_source.consumer_validation_failures == 0u &&
        service.requests_peeked > 0u &&
        service.requests_peeked == service.requests_acked;
    const bool deadline_slo_passed = service.deadline_misses == 0u;
    const bool record_only_deadline =
        options.at("deadline-miss-policy") == "record_only";
    const bool accepted = service_complete &&
        (deadline_slo_passed || record_only_deadline);
    const bool diagnostic_original_addresses =
        options.at("event-assets-address-mode") ==
            "original_addresses_partial_diagnostic";
    const bool formal_ready = service_complete && deadline_slo_passed &&
        !diagnostic_original_addresses;
    json_t *root = json_object();
    object_string(root, "protocol", service_protocol(options));
    object_string(root, "status", accepted ? "COMPLETE" : "FAILED");
    object_bool(root, "formal_ready", formal_ready);
    object_bool(root, "production_service_ready", service_complete);
    object_bool(root, "online_persistence_enabled",
        !online_persistence_disabled);
    object_bool(root, "post_timing_evaluation_export",
        online_persistence_disabled);
    object_string(root, "online_commit_boundary",
        online_persistence_disabled ? "in_memory_only" :
            (ledger.synchronous_wal_segments?"synchronous_rocksdb_wal_segments":"fsync_recoverable_segment_directory"));
    object_u64(root, "durable_sequence", ledger.last_sequence);
    object_u64(root, "acked_sequence", service.last_acked_sequence);
    if (!failure.empty()) {
        object_string(root, "failure", failure);
    } else if (!physical_affinity_layout_ready) {
        object_string(root, "failure",
            "service CPU roles are not physical-core isolated");
    } else if (!flow_state_ready) {
        object_string(root, "failure",
            "run-wide flow state capacity/rehash evidence is not closed");
    } else if (!deadline_slo_passed && !record_only_deadline) {
        object_string(root, "failure",
            "detector deadline SLO missed under enforce policy");
    } else {
        json_object_set_new(root, "failure", json_null());
    }
    object_u64(root, "started_monotonic_ns", service.started_monotonic_ns);
    object_u64(root, "stopped_monotonic_ns", service.stopped_monotonic_ns);
    object_u64(root, "service_process_cpu_ns", service_process_cpu_ns);
    object_u64(root,"service_timed_peak_rss_kib",service_timed_peak_rss_kib);
    object_string(root,"service_timed_peak_rss_scope","process maximum through online drain; includes initialization; sampled before audit export and fresh DB readback");
    object_string(root,"service_process_peak_rss_scope","process maximum at final receipt after audit export and DB readback; not the timed service memory boundary");
    struct rusage resource_usage{};
    if (getrusage(RUSAGE_SELF,&resource_usage)==0)
        object_u64(root,"service_process_peak_rss_kib",static_cast<uint64_t>(resource_usage.ru_maxrss));
    if (options.count("persistent-state-dir")) {
        object_string(root,"persistent_state_backend","rocksdb");
        object_bool(root,"persistent_state_sync",true);
        object_bool(root,"persistent_state_wal",true);
        object_string(root,"persistent_state_directory",options.at("persistent-state-dir"));
        object_bool(root,"persistent_state_online_resume_supported",false);
        object_bool(root,"persistent_state_in_rx_64mib_budget",false);
        object_u64(root,"persistent_shared_block_cache_capacity_bytes",4u<<20);
        object_u64(root,"persistent_shared_write_buffer_flush_threshold_bytes",8u<<20);
        object_bool(root,"persistent_memory_is_hard_rss_limit",false);
        object_u64(root,"persistent_history_idle_ttl_ns",90ull*86400ull*1000000000ull);
        object_string(root,"persistent_history_clock","semantic_event_time");
        object_u64(root,"persistent_expiry_index_scan_limit_per_commit",256);
        object_bool(root,"persistent_physical_disk_quota_enforced",false);
        object_bool(root,"persistent_full_three_tier_retention",false);
    }

    json_object_set_new(
        root,
        "service_process_cpu_ns_per_input_record",
        json_real(service.requests_peeked == 0u ? 0.0 :
            static_cast<double>(service_process_cpu_ns) /
                static_cast<double>(service.requests_peeked)));
    object_string(
        root,
        "service_cpu_scope",
        "native_fusion_service_process_all_threads_run_only_excludes_model_load_and_receiver");
    object_bool(root, "interrupted", false);
    object_bool(root, "final_flush_complete", service_complete);
    object_string(root, "routing_mode", "flow_key_event_assets_v1");
    attach_model_residency(root, metadata);

    json_t *evidence = json_object();
    object_string(evidence, "run_uuid_hex",
        options.at("expected-run-uuid-hex"));
    object_string(evidence, "config_sha256",
        options.at("expected-config-sha256"));
    object_bool(evidence, "complete", true);
    json_object_set_new(root, "evidence_binding", evidence);

    json_t *checks = json_object();
    const char *const boolean_checks[] = {
        "route_provenance_ready", "production_flow_key_routing",
        "transport_required_fields_present", "transport_counts_clean",
        "fusion_service_count_match", "service_ledger_count_match",
        "nonempty_scored_stream", "evidence_binding_ready",
        "detector_scheduling_ready",
    };
    for (const char *name : boolean_checks)
        object_bool(checks, name, service_complete);
    object_u64(checks, "sequence_token_bindings_validated",
        service.route_bindings_validated);
    object_u64(checks, "last_routed_sequence",
        service.last_acked_sequence);
    object_bool(checks, "flow_open_coverage_closed",
        service.flow_open_coverage_closed == 1u);
    object_bool(checks, "run_wide_flow_state_closed", flow_state_ready);
    object_bool(checks, "flow_continue_coverage_closed",
        service.capacity_continuation_rebindings ==
            service.flow_continue_records);
    object_bool(checks, "active_generation_residency_closed",
        service.superseded_generation_retirements +
                service.flow_coverage_map.terminal_entries ==
            service.flow_open_records + service.flow_continue_records &&
        service.flow_coverage_map.terminal_entries >=
            service.active_semantic_generations_map.terminal_entries);
    object_bool(checks, "model_residency_ready", model_residency_ready);
    json_object_set_new(root, "closure_checks", checks);

    json_t *route = json_object();
    object_string(route, "routing_mode", "flow_key_event_assets_v1");
    object_bool(route, "provenance_verified", true);
    object_bool(route, "hash_closure_complete", true);
    object_bool(route, "label_blind_output_columns_verified", true);
    object_bool(route, "event_semantics_verified", true);
    object_string(route, "event_unit", options.at("event-unit"));
    object_string(route, "address_mode",
        options.at("event-assets-address-mode"));
    object_bool(route, "formal_address_namespace",
        !diagnostic_original_addresses);
    object_u64(route, "entries", route_count);
    object_string(route, "event_universe_sha256",
        options.at("event-universe-sha256"));
    json_t *map_node = json_object();
    object_string(map_node, "path", event_map_path);
    object_string(map_node, "sha256", options.at("event-map-sha256"));
    object_u64(map_node, "size_bytes", file_size(event_map_path));
    object_u64(map_node, "rows", route_count);
    json_t *columns = json_array();
    json_array_append_new(columns, json_string("flow_key"));
    json_array_append_new(columns, json_string("event_id"));
    json_object_set_new(map_node, "columns", columns);
    json_object_set_new(route, "event_map", map_node);
    json_t *universe_node = json_object();
    object_string(universe_node, "path", event_universe_path);
    object_string(universe_node, "sha256",
        options.at("event-universe-sha256"));
    object_u64(universe_node, "size_bytes", file_size(event_universe_path));
    object_u64(universe_node, "rows", event_count);
    columns = json_array();
    json_array_append_new(columns, json_string("event_id"));
    json_object_set_new(universe_node, "columns", columns);
    json_object_set_new(route, "event_universe", universe_node);
    json_t *receipt_node = json_object();
    object_string(receipt_node, "path", assets_receipt_path);
    object_string(receipt_node, "sha256",
        options.at("event-assets-receipt-sha256"));
    object_u64(receipt_node, "size_bytes", file_size(assets_receipt_path));
    object_string(receipt_node, "protocol",
        "flowkeep-label-blind-replay-online-event-assets-v1");
    json_object_set_new(route, "event_assets_receipt", receipt_node);
    json_object_set_new(root, "event_route_map", route);

    json_t *fusion = json_object();
    object_string(fusion, "protocol",
        "flowkeep-live-seven-state-fusion-v1");
    json_t *semantics = json_object();
    object_u64(semantics, "state_heads", 7u);
    object_u64(semantics, "meta_models",
        options.count("adaptive-history-meta") ? 1u : 3u);
    json_object_set_new(semantics, "threshold",
        json_real(metadata.threshold));
    object_bool(semantics, "cross_dataset_scoring", false);
    object_string(semantics, "batch_commit", "atomic");
    if (options.count("adaptive-history-meta") ||
        options.count("adaptive-action-risk")) {
        json_t *adaptive = json_object();
        if (options.count("adaptive-history-meta")) {
        object_string(adaptive, "history_meta_path",
            options.at("adaptive-history-meta"));
        object_string(adaptive, "history_meta_sha256",
            options.at("adaptive-history-meta-sha256"));
        }
        if (options.count("adaptive-action-risk")) {
            object_string(adaptive, "scheduler",
                options.count("adaptive-fixed-checkpoints") ?
                "fixed_points_matched_control" : options.count("adaptive-trained-policy") ?
                "train_fitted_validation_selected_error_reduction" :
                "actual_score_feedback_marginal_evidence_next_or_stop");
            object_bool(adaptive, "event_frontier_batching", options.count("adaptive-event-frontiers") != 0);
            if (options.count("adaptive-fixed-checkpoints"))
                object_string(adaptive, "fixed_points", options.at("adaptive-fixed-checkpoints"));
            if (options.count("adaptive-trained-policy"))
                object_string(adaptive, "trained_policy_sha256", options.at("adaptive-trained-policy-sha256"));
            object_string(adaptive, "action_risk_path",
                options.at("adaptive-action-risk"));
            object_string(adaptive, "action_risk_sha256",
                options.at("adaptive-action-risk-sha256"));
            object_string(adaptive, "marginal_table_path",
                options.at("adaptive-marginal-table"));
            object_string(adaptive, "marginal_table_sha256",
                options.at("adaptive-marginal-table-sha256"));
            object_string(adaptive, "first_observation",
                options.count("adaptive-fixed-checkpoints") ?
                "first_configured_control_point" : "predicted_not_fixed");
            object_string(adaptive, "successor_observation",
                options.count("adaptive-fixed-checkpoints") ?
                "next_configured_control_point" : "actual_score_then_next_or_stop");
        } else {
            object_string(adaptive, "first_packet",
                options.at("adaptive-first-packet"));
            object_string(adaptive, "near_gap",
                options.at("adaptive-near-gap"));
            object_string(adaptive, "far_gap",
                options.at("adaptive-far-gap"));
            object_string(adaptive, "watch_ratio",
                options.at("adaptive-watch-ratio"));
            object_string(adaptive, "horizon_packet",
                options.at("adaptive-horizon-packet"));
        }
        object_string(adaptive, "candidate_contract",
            "speculative_snapshots_actual_model_calls_only_when_due");
        json_object_set_new(semantics, "adaptive_checkpoint", adaptive);
    }
    json_object_set_new(fusion, "semantics", semantics);
    json_t *model = json_object();
    object_string(model, "path", model_path);
    object_string(model, "sha256", options.at("model-sha256"));
    json_t *scope = json_object();
    object_string(scope, "requested_dataset_id", options.at("dataset-id"));
    object_string(scope, "model_source_dataset_id",
        options.at("model-source-dataset-id"));
    object_string(scope, "requested_event_unit", options.at("event-unit"));
    object_bool(scope, "cross_dataset_scoring",
        options.at("cross-dataset-partial-diagnostic") == "true");
    object_bool(scope, "partial_diagnostic_only",
        options.at("cross-dataset-partial-diagnostic") == "true");
    json_object_set_new(model, "scope", scope);
    json_t *native_bundle = json_object();
    object_string(native_bundle, "path", bundle_path);
    object_string(native_bundle, "sha256", options.at("bundle-sha256"));
    object_string(native_bundle, "source_model_sha256",
        options.at("source-model-sha256"));
    object_string(native_bundle, "receipt_path", bundle_receipt_path);
    object_string(native_bundle, "receipt_sha256",
        options.at("bundle-receipt-sha256"));
    json_object_set_new(fusion, "native_bundle", native_bundle);
    json_object_set_new(model, "source_bindings", json_object());
    json_object_set_new(fusion, "model", model);
    if (flow_open_head_enabled(options)) {
        char *end = nullptr;
        const double flow_open_threshold = std::strtod(
            options.at("flow-open-threshold").c_str(), &end);
        (void)end;
        json_t *flow_open_head = json_object();
        object_string(flow_open_head, "path",
            canonical_existing_path(options.at("flow-open-model")));
        object_string(flow_open_head, "sha256",
            options.at("flow-open-model-sha256"));
        object_string(flow_open_head, "feature_schema_sha256",
            options.at("flow-open-schema-sha256"));
        object_u64(flow_open_head, "feature_count", kFlowOpenFeatureCount);
        json_object_set_new(flow_open_head, "threshold",
            json_real(flow_open_threshold));
        object_string(flow_open_head, "decision_semantics",
            "provisional_at_flow_open_checkpoint_supersedes_short_flow_terminal");
        object_bool(flow_open_head, "train_only_threshold_selection", true);
        object_bool(flow_open_head, "address_namespace_invariant", true);
        json_object_set_new(fusion, "flow_open_head", flow_open_head);
    }
    json_t *fusion_state = json_object();
    object_string(fusion_state, "event_unit", options.at("event-unit"));
    object_u64(fusion_state, "unique_events", event_count);
    object_u64(fusion_state, "unique_flows", route_count);
    object_u64(fusion_state, "last_sequence", service.last_acked_sequence);
    json_object_set_new(fusion, "state", fusion_state);
    json_t *counters = json_object();
    object_u64(counters, "records_received", service.requests_peeked);
    object_u64(counters, "flow_open_records", service.flow_open_records);
    object_u64(counters, "flow_open_records_scored",
        service.flow_open_records_scored);
    object_u64(counters, "flow_continue_records",
        service.flow_continue_records);
    object_u64(counters, "checkpoints_received", service.checkpoint_records);
    object_u64(counters, "checkpoints_scored", service.requests_scored);
    object_u64(counters, "flow_open_only_event_terminals",
        service.flow_open_only_event_terminals);
    object_u64(counters, "checkpoints_rejected", 0u);
    object_u64(counters, "batches_scored", service.scorer_batches);
    json_object_set_new(fusion, "counters", counters);
    json_object_set_new(root, "fusion", fusion);

    uint64_t deadline_us = 0u;
    uint64_t batch = 0u;
    uint64_t durable_commit_batch = 0u;
    uint64_t durable_commit_max_wait_us = 0u;
    uint64_t batch_wait_us = 0u;
    uint64_t max_inflight = 0u;
    uint64_t flow_state_capacity = 0u;
    uint64_t route_quantum = 0u;
    (void)parse_u64(options.at("detector-deadline-us"), &deadline_us);
    (void)parse_u64(options.at("batch-size"), &batch);
    (void)parse_u64(options.at("durable-commit-batch-size"),
        &durable_commit_batch);
    (void)parse_u64(options.at("durable-commit-max-wait-us"),
        &durable_commit_max_wait_us);
    const auto age_anchor = parse_age_anchor(
        options.find("durable-commit-max-wait-age-anchor") == options.end()
        ? "physical_enqueue_monotonic_ns"
        : options.at("durable-commit-max-wait-age-anchor"));
    (void)parse_u64(options.at("batch-wait-us"), &batch_wait_us);
    (void)parse_u64(options.at("max-inflight"), &max_inflight);
    (void)parse_u64(options.at("flow-state-capacity"),
        &flow_state_capacity);
    (void)parse_u64(options.at("route-quantum"), &route_quantum);
    json_t *scheduling = json_object();
    object_string(scheduling, "mode",
        flowkeep::NativeFusionDetectorScheduleName(
            service.detector_schedule));
    object_string(scheduling, "retention_policy",
        options.at("retention-policy"));
    object_string(scheduling, "retention_detector_coupling",
        options.at("retention-detector-coupling"));
    object_bool(scheduling, "retention_detector_coupled", false);
    object_bool(scheduling, "retention_signal_used_for_scheduling",
        service.detector_schedule_uses_retention_signal != 0u);
    object_string(scheduling, "retention_commit_mode",
        online_persistence_disabled ? "in_memory_evaluation_buffer_v1" :
            "bounded_prepare_publish_v1");
    object_string(scheduling, "durable_commit_durability",
        online_persistence_disabled ? "none_in_memory_only" :
            (ledger.synchronous_wal_segments?"synchronous_rocksdb_wal_segments":"fsync_recoverable_segment_and_directory"));
    object_u64(scheduling, "durable_commit_queue_depth",
        service.durable_commit_queue_depth);
    object_u64(scheduling, "durable_commit_peak_depth",service.durable_commit_peak_depth);
    object_bool(scheduling,"drain_preparation_overlap",service.drain_preparation_overlap);
    object_u64(scheduling,"drain_preparation_batches",service.drain_preparation_batches);
    object_bool(scheduling,"drain_preparation_idle_attested",service.drain_preparation_idle_attested);
    object_bool(scheduling,
        "detector_ingest_decoupled_from_durable_fsync",
        service.detector_ingest_decoupled_from_durable_fsync == 1u);
    object_bool(scheduling, "ack_after_durable_only",
        service.ack_after_durable_only == 1u);
    object_u64(scheduling, "configured_deadline_us", deadline_us);
    object_u64(scheduling, "configured_deadline_ns", deadline_us * 1000u);
    object_string(scheduling, "deadline_miss_policy",
        options.at("deadline-miss-policy"));
    object_bool(scheduling, "deadline_gate_enforced",
        !record_only_deadline);
    const bool deadline_guard = service.detector_schedule ==
        flowkeep::NativeFusionDetectorSchedule::DeadlineGuardBatchFifo;
    object_bool(scheduling, "deadline_guard_enabled", deadline_guard);
    object_u64(scheduling, "dispatch_guard_ns",
        service.detector_dispatch_guard_ns);
    object_string(scheduling, "deadline_rule",
        "decision_monotonic_ns <= physical_enqueue_monotonic_ns + "
        "configured_deadline_ns");
    if (deadline_guard) {
        object_string(scheduling, "latest_start_rule",
            "oldest_physical_enqueue_monotonic_ns + "
            "configured_deadline_ns - dispatch_guard_ns");
    } else {
        json_object_set_new(scheduling, "latest_start_rule", json_null());
    }
    object_u64(scheduling, "batch_capacity", batch);
    object_u64(scheduling, "inference_batch_capacity", batch);
    object_u64(scheduling, "durable_commit_batch_capacity",
        durable_commit_batch);
    object_u64(scheduling, "durable_commit_max_wait_us",
        durable_commit_max_wait_us);
    object_u64(scheduling, "durable_commit_max_wait_ns",
        service.durable_commit_max_wait_ns);
    object_string(scheduling, "durable_commit_max_wait_rule",
        "ordered_head_submit_guard_while_durable_committer_idle");
    object_string(scheduling, "durable_commit_max_wait_age_anchor",
        flowkeep::NativeFusionDurableAgeAnchorName(age_anchor));
    object_bool(scheduling, "durable_commit_candidate_coalescing_enabled",
        age_anchor == flowkeep::NativeFusionDurableAgeAnchor::FirstDurableCandidate);
    object_string(scheduling, "detection_deadline_clock_unmodified",
        "physical_enqueue_monotonic_ns");
    object_bool(scheduling, "durable_commit_max_wait_is_ack_bound", false);
    object_bool(scheduling,
        "durable_commit_busy_time_may_exceed_max_wait", true);
    object_u64(scheduling, "durable_commit_submissions",
        service.durable_commit_submissions);
    object_u64(scheduling, "durable_commit_successful_calls",
        service.durable_commit_calls);
    object_u64(scheduling, "durable_commit_failed_calls",
        service.durable_commit_failed_calls);
    object_u64(scheduling, "fsync_attested_commit_calls",
        service.fsync_attested_commit_calls);
    object_u64(scheduling, "ack_calls", service.ack_calls);
    object_u64(scheduling, "requests_persisted",
        service.requests_persisted);
    json_t *durable_triggers = json_object();
    object_u64(durable_triggers, "capacity",
        service.durable_commit_trigger_capacity);
    object_u64(durable_triggers, "terminal",
        service.durable_commit_trigger_terminal);
    object_u64(durable_triggers, "max_wait",
        service.durable_commit_trigger_max_wait);
    object_u64(durable_triggers, "quiescent_feedback_subset_of_terminal",
        service.durable_commit_trigger_quiescent_feedback);
    object_u64(durable_triggers, "drain_wait_subset_of_max_wait",service.durable_commit_trigger_drain_wait);
    object_u64(scheduling,"drain_commit_max_wait_ns",service.drain_commit_max_wait_ns);
    json_object_set_new(scheduling, "durable_commit_triggers",
        durable_triggers);
    json_t *durable_rows = json_object();
    object_u64(durable_rows, "minimum",
        service.minimum_durable_commit_batch_rows);
    object_u64(durable_rows, "maximum",
        service.maximum_durable_commit_batch_rows);
    json_object_set_new(scheduling, "durable_commit_batch_rows",
        durable_rows);
    object_u64(scheduling, "maximum_durable_commit_batch_wait_ns",
        service.maximum_durable_commit_batch_wait_ns);
    object_string(scheduling,"durable_commit_total_scope","history_wait_and_publication_excludes_overlapped_preparation");
    object_bool(scheduling,"preparation_and_publication_phase_sums_are_wall_time",false);
    object_u64(scheduling, "durable_commit_total_ns",
        service.durable_commit_total_ns);
    object_u64(scheduling, "maximum_durable_commit_ns",
        service.maximum_durable_commit_ns);
    object_u64(scheduling, "durable_commit_elapsed_ns_sum",
        service.durable_commit_elapsed_ns_sum);
    object_u64(scheduling, "maximum_durable_commit_elapsed_ns",
        service.maximum_durable_commit_elapsed_ns);
    object_u64(scheduling,
        "first_durable_commit_submit_monotonic_ns",
        service.first_durable_commit_submit_monotonic_ns);
    object_u64(scheduling,
        "last_durable_commit_completion_monotonic_ns",
        service.last_durable_commit_completion_monotonic_ns);
    object_u64(scheduling, "durable_commit_active_span_ns",
        service.durable_commit_active_span_ns);
    object_u64(scheduling, "maximum_decision_to_durable_ns",
        service.maximum_decision_to_durable_ns);
    object_u64(scheduling, "maximum_physical_enqueue_to_durable_ns",
        service.maximum_physical_enqueue_to_durable_ns);
    object_u64(scheduling, "maximum_decision_to_ack_ns",
        service.maximum_decision_to_ack_ns);
    object_u64(scheduling, "maximum_physical_enqueue_to_ack_ns",
        service.maximum_physical_enqueue_to_ack_ns);
    object_string(scheduling, "ack_timing_point",
        "immediately_after_successful_source_ack_call_return");
    object_bool(scheduling, "durable_trigger_count_match",
        durable_trigger_count_valid &&
            durable_trigger_count == service.durable_commit_submissions);
    object_bool(scheduling, "durable_call_count_match",
        durable_call_count_valid &&
            durable_call_count == service.durable_commit_submissions);
    object_u64(scheduling, "batch_wait_us", batch_wait_us);
    object_u64(scheduling, "max_inflight", max_inflight);
    object_u64(scheduling, "flow_state_capacity", flow_state_capacity);
    object_u64(scheduling, "route_quantum", route_quantum);
    object_u64(scheduling, "route_quantum_yields",
        service.route_quantum_yields);
    object_u64(scheduling, "effective_route_slice_capacity",
        service.effective_route_slice_capacity);
    object_u64(scheduling, "route_slice_yields",
        service.route_slice_yields);
    object_u64(scheduling, "peak_inflight", service.peak_inflight);
    object_bool(scheduling, "pending_capacity_bounded",
        service.peak_inflight <= max_inflight);
    object_u64(scheduling, "engine_threads", engine_threads);
    object_u64(scheduling, "service_workers", service_workers);
    (void)attach_service_cpu_layout(
        scheduling, options, engine_threads, service_workers);
    object_bool(scheduling, "coordinator_affinity_requested",
        service.coordinator_affinity_requested == 1u);
    object_bool(scheduling, "coordinator_affinity_attested",
        service.coordinator_affinity_attested == 1u);
    object_bool(scheduling, "committer_affinity_requested",
        service.committer_affinity_requested == 1u);
    object_bool(scheduling, "committer_affinity_attested",
        service.committer_affinity_attested == 1u);
    object_bool(scheduling, "worker_affinity_plan_requested",
        service.worker_affinity_plan_requested == 1u);
    object_bool(scheduling, "worker_affinity_plan_attested",
        service.worker_affinity_plan_attested == 1u);
    object_bool(scheduling, "source_delivers_validated_items",
        service.source_delivers_validated_items == 1u);
    object_u64(scheduling, "decisions_checked", service.requests_scored);
    object_u64(scheduling, "control_records_checked",
        service.flow_open_records + service.flow_continue_records);
    object_u64(scheduling, "deadline_misses", service.deadline_misses);
    const flowkeep::NativeFusionFirstDeadlineMissMetrics &first_miss =
        service.first_deadline_miss;
    json_t *first_deadline_miss = json_object();
    object_bool(first_deadline_miss, "present", first_miss.present == 1u);
    object_u64(first_deadline_miss, "observed_miss_count",
        service.deadline_misses);
    object_u64(first_deadline_miss, "sequence", first_miss.sequence);
    object_u64(first_deadline_miss, "event_routing_token",
        first_miss.event_routing_token);
    object_bool(first_deadline_miss,
        "sequence_event_routing_token_match",
        first_miss.present == 0u ||
            first_miss.sequence == first_miss.event_routing_token);
    object_u64(first_deadline_miss, "worker_shard",
        first_miss.worker_shard);
    object_u64(first_deadline_miss, "physical_enqueue_monotonic_ns",
        first_miss.physical_enqueue_monotonic_ns);
    object_u64(first_deadline_miss, "consumer_receive_monotonic_ns",
        first_miss.consumer_receive_monotonic_ns);
    object_u64(first_deadline_miss, "inference_start_monotonic_ns",
        first_miss.inference_start_monotonic_ns);
    object_u64(first_deadline_miss, "decision_monotonic_ns",
        first_miss.decision_monotonic_ns);
    object_u64(first_deadline_miss, "transport_queue_wait_ns",
        first_miss.transport_queue_wait_ns);
    object_u64(first_deadline_miss, "worker_queue_wait_ns",
        first_miss.worker_queue_wait_ns);
    object_u64(first_deadline_miss, "inference_ns",
        first_miss.inference_ns);
    object_u64(first_deadline_miss, "end_to_end_ns",
        first_miss.end_to_end_ns);
    json_object_set_new(scheduling, "first_deadline_miss",
        first_deadline_miss);
    object_u64(scheduling, "max_queue_wait_ns",
        service.maximum_queue_wait_ns);
    object_u64(scheduling, "max_end_to_end_ns",
        service.maximum_end_to_end_ns);
    json_t *batch_triggers = json_object();
    object_u64(batch_triggers,"input_fence",service.batch_trigger_input_fence);
    object_u64(batch_triggers, "capacity",
        service.batch_trigger_capacity);
    object_u64(batch_triggers, "fixed_wait_timeout",
        service.batch_trigger_wait_timeout);
    object_u64(batch_triggers, "deadline_guard",
        service.batch_trigger_deadline_guard);
    object_u64(batch_triggers, "close",
        service.batch_trigger_close);
    json_object_set_new(scheduling, "batch_triggers", batch_triggers);
    const uint64_t trigger_total = service.batch_trigger_capacity +
        service.batch_trigger_wait_timeout +
        service.batch_trigger_deadline_guard + service.batch_trigger_close +
        service.batch_trigger_input_fence;
    object_bool(scheduling, "batch_trigger_count_match",
        trigger_total == service.scorer_batches);
    uint64_t maximum_worker_queue_wait_ns = 0u;
    uint64_t maximum_batch_inference_ns = 0u;
    json_t *worker_metrics = json_array();
    for (const flowkeep::NativeFusionWorkerMetrics &worker :
            service.worker_metrics) {
        maximum_worker_queue_wait_ns = std::max(
            maximum_worker_queue_wait_ns,
            worker.maximum_worker_queue_wait_ns);
        maximum_batch_inference_ns = std::max(
            maximum_batch_inference_ns, worker.maximum_inference_ns);
        json_t *item = json_object();
        object_u64(item, "worker_shard", worker.worker_shard);
        object_u64(item, "records_popped", worker.requests_routed);
        object_u64(item, "records_dequeued", worker.requests_dequeued);
        object_u64(item, "records_scored", worker.requests_scored);
        object_u64(item, "batches_started", worker.batches_started);
        object_u64(item, "batches_scored", worker.batches_scored);
        object_u64(item, "max_batch_rows", worker.maximum_batch_rows);
        object_u64(item, "peak_queue_depth", worker.peak_queue_depth);
        object_u64(item, "terminal_queue_depth",
            worker.terminal_queue_depth);
        object_u64(item, "max_transport_queue_wait_ns",
            worker.maximum_transport_queue_wait_ns);
        object_u64(item, "max_worker_queue_wait_ns",
            worker.maximum_worker_queue_wait_ns);
        object_u64(item, "max_inference_ns",
            worker.maximum_inference_ns);
        object_u64(item, "max_end_to_end_ns",
            worker.maximum_end_to_end_ns);
        object_u64(item, "batch_trigger_capacity",
            worker.batch_trigger_capacity);
        object_u64(item,"active_batch_wait_ns",worker.active_batch_wait_ns);
        object_u64(item,"drain_batch_wait_ns",worker.drain_batch_wait_ns);
        object_u64(item,"input_fence_transitions",worker.input_fence_transitions);
        object_u64(item,"batch_trigger_input_fence",worker.batch_trigger_input_fence);
        object_u64(item,"active_phase_batches",worker.active_phase_batches);
        object_u64(item,"drain_phase_batches",worker.drain_phase_batches);
        object_u64(item,"active_phase_rows",worker.active_phase_rows);
        object_u64(item,"drain_phase_rows",worker.drain_phase_rows);
        object_u64(item, "batch_trigger_wait_timeout",
            worker.batch_trigger_wait_timeout);
        object_u64(item, "batch_trigger_deadline_guard",
            worker.batch_trigger_deadline_guard);
        object_u64(item, "batch_trigger_close",
            worker.batch_trigger_close);
        object_u64(item, "affinity_cpu_count",
            worker.affinity_cpu_count);
        object_bool(item, "affinity_requested",
            worker.affinity_requested == 1u);
        object_bool(item, "affinity_attested",
            worker.affinity_attested == 1u);
        json_array_append_new(worker_metrics, item);
    }
    object_u64(scheduling, "max_worker_queue_wait_ns",
        maximum_worker_queue_wait_ns);
    object_u64(scheduling, "max_batch_inference_ns",
        maximum_batch_inference_ns);
    json_object_set_new(scheduling, "worker_metrics", worker_metrics);
    object_bool(scheduling, "all_decisions_within_deadline",
        deadline_slo_passed);
    object_bool(scheduling, "deadline_slo_passed", deadline_slo_passed);
    object_bool(scheduling, "deadline_misses_recorded", true);
    object_bool(scheduling, "experiment_continuation_allowed",
        deadline_slo_passed || record_only_deadline);
    object_bool(scheduling, "formal_ready", formal_ready);
    json_object_set_new(root, "detector_scheduling", scheduling);
    attach_retention_detector_contract(root, options);

    json_t *counts = json_object();
    object_u64(counts,"source_maintenance_progress_turns",service.source_maintenance_progress_turns);
    object_u64(counts, "records_popped", service.requests_peeked);
    object_u64(counts, "records_scored", service.requests_scored);
    object_u64(counts, "flow_open_records", service.flow_open_records);
    object_u64(counts, "flow_open_records_scored",
        service.flow_open_records_scored);
    object_u64(counts, "flow_continue_records",
        service.flow_continue_records);
    object_u64(counts, "capacity_continuation_rebindings",
        service.capacity_continuation_rebindings);
    object_u64(counts, "superseded_generation_retirements",
        service.superseded_generation_retirements);
    object_u64(counts, "checkpoint_records", service.checkpoint_records);
    object_u64(counts, "flow_open_only_event_terminals",
        service.flow_open_only_event_terminals);
    object_bool(counts, "flow_open_coverage_closed",
        service.flow_open_coverage_closed == 1u);
    object_u64(counts, "chunks_scored", service.scorer_batches);
    object_u64(counts, "route_failures", service.route_failures);
    object_u64(counts, "route_cache_hits", service.route_cache_hits);
    object_u64(counts, "route_cache_misses", service.route_cache_misses);
    object_u64(counts, "route_bindings_validated",
        service.route_bindings_validated);
    object_u64(counts, "frozen_flow_routes", service.frozen_flow_routes);
    object_bool(counts,"paged_reorder",service.paged_reorder);
    object_u64(counts,"reorder_peak_payload_bytes",service.reorder_peak_payload_bytes);
    object_u64(counts,"reorder_allocated_bytes_at_end",service.reorder_allocated_bytes_at_end);
    object_u64(counts,"reorder_page_reuses",service.reorder_page_reuses);
    json_object_set_new(root, "service_counts", counts);

    json_t *flow_state = json_object();
    object_string(flow_state, "capacity_source", "explicit_cli_per_map");
    object_string(flow_state, "flow_coverage_residency",
        "exact_open_generations_until_original_eof_closure");
    object_u64(flow_state, "capacity_per_map",
        service.flow_state_capacity);
    object_u64(flow_state, "capacity_failures",
        service.flow_state_capacity_failures);
    object_u64(flow_state, "runtime_rehashes",
        service.flow_state_runtime_rehashes);
    object_bool(flow_state, "capacity_closed",
        service.flow_state_capacity_closed == 1u);
    object_bool(flow_state, "no_runtime_rehash_after_reserve",
        service.flow_state_no_runtime_rehash == 1u);
    const auto append_flow_state_map = [flow_state](const char *name,
            const flowkeep::NativeFusionFlowStateMapMetrics &metrics) {
        json_t *item = json_object();
        object_u64(item, "peak_entries", metrics.peak_entries);
        object_u64(item, "terminal_entries", metrics.terminal_entries);
        object_u64(item, "post_reserve_bucket_count",
            metrics.post_reserve_bucket_count);
        object_u64(item, "terminal_bucket_count",
            metrics.terminal_bucket_count);
        json_object_set_new(flow_state, name, item);
    };
    append_flow_state_map("stable_flow_routes",
        service.stable_flow_routes_map);
    append_flow_state_map("flow_coverage", service.flow_coverage_map);
    append_flow_state_map("active_semantic_generations",
        service.active_semantic_generations_map);
    append_flow_state_map("event_coverage", service.event_coverage_map);
    json_object_set_new(root, "run_wide_flow_state", flow_state);

    json_t *transport = json_object();
    object_string(transport, "consumer_mode", "formal_ack_consumer");
    object_string(transport, "mapping_access", "read-write-ack-only");
    object_u64(transport, "run_epoch", service.final_source.run_epoch);
    object_bool(transport, "producer_done",
        service.final_source.producer_done == 1u);
    object_u64(transport, "producer_stop_monotonic_ns",
        service.final_source.producer_stop_monotonic_ns);
    object_u64(transport, "consumer_fault",
        service.final_source.consumer_fault);
    object_bool(transport, "formal_transport_clean", transport_clean);
    object_u64(transport, "records_popped", service.requests_peeked);
    object_u64(transport, "records_acked", service.requests_acked);
    object_u64(transport, "producer_overflow_failures",
        service.final_source.producer_overruns);
    object_u64(transport, "producer_drops",
        service.final_source.producer_drops);
    object_u64(transport, "overruns",
        service.final_source.producer_overruns);
    object_u64(transport, "sequence_errors",
        service.final_source.sequence_gaps);
    object_u64(transport, "corrupt_records",
        service.final_source.consumer_validation_failures);
    json_object_set_new(root, "transport", transport);

    json_t *commit_phases = json_object();
    object_string(commit_phases, "protocol",
        "flowkeep-durable-commit-phase-timing-v1");
    object_bool(commit_phases, "segment_directory_fd_reused", true);
    object_bool(commit_phases, "payload_buffer_reuse_enabled", ledger.payload_buffer_reuse_enabled);
    object_u64(commit_phases, "payload_buffer_moves", ledger.payload_buffer_moves);
    object_u64(commit_phases, "payload_buffer_moved_bytes", ledger.payload_buffer_moved_bytes);
    object_u64(commit_phases, "payload_buffer_reuse_hits", ledger.payload_buffer_reuse_hits);
    const auto append_phase = [commit_phases](const char *name,
            uint64_t total_ns, uint64_t maximum_ns) {
        json_t *phase = json_object();
        object_u64(phase, "total_ns", total_ns);
        object_u64(phase, "maximum_ns", maximum_ns);
        json_object_set_new(commit_phases, name, phase);
    };
    append_phase("validate_serialize", ledger.validate_serialize_total_ns,
        ledger.validate_serialize_max_ns);
    append_phase("compression", ledger.compression_total_ns,
        ledger.compression_max_ns);
    append_phase("prepare_state", ledger.prepare_state_total_ns,
        ledger.prepare_state_max_ns);
    append_phase("segment_open", ledger.segment_open_total_ns,
        ledger.segment_open_max_ns);
    append_phase("segment_write", ledger.segment_write_total_ns,
        ledger.segment_write_max_ns);
    append_phase("segment_file_fsync", ledger.segment_file_fsync_total_ns,
        ledger.segment_file_fsync_max_ns);
    append_phase("segment_publish", ledger.segment_publish_total_ns,
        ledger.segment_publish_max_ns);
    append_phase("segment_directory_fsync",
        ledger.segment_directory_fsync_total_ns,
        ledger.segment_directory_fsync_max_ns);
    append_phase("state_apply", ledger.state_apply_total_ns,
        ledger.state_apply_max_ns);
    json_t *slowest_commit = json_object();
    object_u64(slowest_commit, "total_ns",
        ledger.slowest_commit_total_ns);
    object_u64(slowest_commit, "segment_index",
        ledger.slowest_commit_segment_index);
    object_u64(slowest_commit, "decisions",
        ledger.slowest_commit_decisions);
    object_u64(slowest_commit, "validate_serialize_ns",
        ledger.slowest_commit_validate_serialize_ns);
    object_u64(slowest_commit, "compression_ns",
        ledger.slowest_commit_compression_ns);
    object_u64(slowest_commit, "prepare_state_ns",
        ledger.slowest_commit_prepare_state_ns);
    object_u64(slowest_commit, "segment_open_ns",
        ledger.slowest_commit_segment_open_ns);
    object_u64(slowest_commit, "segment_write_ns",
        ledger.slowest_commit_segment_write_ns);
    object_u64(slowest_commit, "segment_file_fsync_ns",
        ledger.slowest_commit_segment_file_fsync_ns);
    object_u64(slowest_commit, "segment_publish_ns",
        ledger.slowest_commit_segment_publish_ns);
    object_u64(slowest_commit, "segment_directory_fsync_ns",
        ledger.slowest_commit_segment_directory_fsync_ns);
    object_u64(slowest_commit, "state_apply_ns",
        ledger.slowest_commit_state_apply_ns);
    json_object_set_new(commit_phases, "slowest_commit", slowest_commit);
    json_object_set_new(root, "durable_commit_phase_timing", commit_phases);

    json_error_t json_error{};
    json_t *manifest = json_loads(
        ledger.manifest_json.c_str(), JSON_REJECT_DUPLICATES, &json_error);
    if (manifest == nullptr)
        manifest = json_null();
    json_object_set_new(root, "decision_ledger", manifest);
    return root;
}

bool json_string_equals(json_t *object, const char *name,
        const std::string &expected) {
    json_t *value = json_object_get(object, name);
    return json_is_string(value) && expected == json_string_value(value);
}

bool json_true_field(json_t *object, const char *name) {
    return json_is_true(json_object_get(object, name));
}

bool json_false_field(json_t *object, const char *name) {
    return json_is_false(json_object_get(object, name));
}

bool json_null_field(json_t *object, const char *name) {
    return json_is_null(json_object_get(object, name));
}

bool json_zero_field(json_t *object, const char *name) {
    json_t *value = json_object_get(object, name);
    return json_is_integer(value) && json_integer_value(value) == 0;
}

bool no_checkpoint_policy_valid(json_t *scope) {
    json_t *policy = json_object_get(
        scope, "no_checkpoint_decision_policy");
    const char *const extension_fields[] = {
        "no_checkpoint_decision_policy_declared",
        "no_checkpoint_decision_policy_source",
        "no_checkpoint_numeric_score",
        "no_checkpoint_fixed_prediction",
        "no_checkpoint_fusion_invoked",
    };
    if (policy == nullptr) {
        // Frozen v1 receipts predate this extension and retain the historical
        // seven-zero-state meta/rank behavior.  A partial extension is invalid.
        for (const char *field : extension_fields) {
            if (json_object_get(scope, field) != nullptr)
                return false;
        }
        return true;
    }
    if (json_string_equals(scope, "no_checkpoint_decision_policy",
            "explicit_negative_without_numeric_score")) {
        return json_string_equals(scope,
                "no_checkpoint_decision_policy_declared",
                "explicit_negative_without_numeric_score") &&
            json_string_equals(scope,
                "no_checkpoint_decision_policy_source", "artifact_explicit") &&
            json_false_field(scope, "no_checkpoint_numeric_score") &&
            json_zero_field(scope, "no_checkpoint_fixed_prediction") &&
            json_false_field(scope, "no_checkpoint_fusion_invoked");
    }
    if (json_string_equals(scope, "no_checkpoint_decision_policy",
            "seven_zero_state_meta_rank_baseline")) {
        const bool explicit_declaration = json_string_equals(scope,
                "no_checkpoint_decision_policy_declared",
                "seven_zero_state_meta_rank_baseline") &&
            json_string_equals(scope,
                "no_checkpoint_decision_policy_source", "artifact_explicit");
        const bool missing_key_compatibility = json_null_field(scope,
                "no_checkpoint_decision_policy_declared") &&
            json_string_equals(scope,
                "no_checkpoint_decision_policy_source",
                "artifact_key_absent_legacy_compatibility");
        return (explicit_declaration || missing_key_compatibility) &&
            json_true_field(scope, "no_checkpoint_numeric_score") &&
            json_null_field(scope, "no_checkpoint_fixed_prediction") &&
            json_true_field(scope, "no_checkpoint_fusion_invoked");
    }
    return false;
}

bool validate_bundle_receipt(
        const std::string &path,
        const std::string &bundle_path,
        const std::unordered_map<std::string, std::string> &options,
        std::string *error) {
    json_error_t parse_error{};
    json_t *root = json_load_file(
        path.c_str(), JSON_REJECT_DUPLICATES, &parse_error);
    if (!json_is_object(root)) {
        if (root != nullptr)
            json_decref(root);
        *error = "native bundle receipt is invalid JSON";
        return false;
    }
    json_t *bundle = json_object_get(root, "bundle");
    json_t *source = json_object_get(root, "source_model");
    json_t *scope = json_object_get(root, "scope");
    const std::string expected_bundle_event_unit =
        options.at("event-unit") == "five_tuple" ?
            "canonical_bidirectional_five_tuple_within_capture" :
            options.at("event-unit");
    const bool cross_dataset_diagnostic =
        options.at("cross-dataset-partial-diagnostic") == "true";
    const bool valid =
        json_string_equals(root, "protocol",
            "flowkeep-native-seven-state-fusion-bundle-receipt-v1") &&
        json_string_equals(root, "status", "COMPLETE") &&
        json_false_field(root, "temporary_files_are_formal_inputs") &&
        json_is_object(bundle) && json_is_object(source) &&
        json_is_object(scope) &&
        json_string_equals(bundle, "path", bundle_path) &&
        json_string_equals(bundle, "sha256", options.at("bundle-sha256")) &&
        json_string_equals(source, "sha256",
            options.at("source-model-sha256")) &&
        json_string_equals(scope, "dataset_id",
            options.at("model-source-dataset-id")) &&
        json_string_equals(scope, "event_unit", expected_bundle_event_unit) &&
        json_false_field(scope, "cross_dataset_scoring") &&
        (!cross_dataset_diagnostic ||
            options.at("dataset-id") !=
                options.at("model-source-dataset-id")) &&
        no_checkpoint_policy_valid(scope);
    json_decref(root);
    if (!valid)
        *error = "native bundle provenance receipt binding differs";
    return valid;
}

bool artifact_binding_valid(
        json_t *artifact,
        const std::string &path,
        const std::string &sha) {
    json_t *bytes = json_object_get(artifact, "size_bytes");
    return json_is_object(artifact) &&
        json_string_equals(artifact, "path", path) &&
        json_string_equals(artifact, "sha256", sha) &&
        json_is_integer(bytes) && json_integer_value(bytes) >= 0 &&
        static_cast<uint64_t>(json_integer_value(bytes)) == file_size(path);
}

bool json_integer_equals(
        json_t *object,
        const char *name,
        uint64_t expected) {
    json_t *value = json_object_get(object, name);
    return json_is_integer(value) && json_integer_value(value) >= 0 &&
        static_cast<uint64_t>(json_integer_value(value)) == expected;
}

bool validate_event_assets_receipt(
        const std::string &path,
        const std::string &event_map_path,
        const std::string &event_universe_path,
        const std::unordered_map<std::string, std::string> &options,
        uint64_t route_count,
        uint64_t event_count,
        std::string *error) {
    json_error_t parse_error{};
    json_t *root = json_load_file(
        path.c_str(), JSON_REJECT_DUPLICATES, &parse_error);
    if (!json_is_object(root)) {
        if (root != nullptr)
            json_decref(root);
        *error = "event-assets receipt is invalid JSON";
        return false;
    }
    json_t *outputs = json_object_get(root, "outputs");
    json_t *labels = json_object_get(root, "label_blind_contract");
    json_t *closure = json_object_get(root, "closure_audit");
    json_t *namespace_node = json_object_get(root, "namespace_contract");
    json_t *short_frames = json_object_get(root, "short_frame_contract");
    const bool scenario = options.at("event-unit") == "scenario";
    const bool valid =
        json_string_equals(root, "protocol",
            "flowkeep-label-blind-replay-online-event-assets-v1") &&
        json_string_equals(root, "status", "COMPLETE") &&
        json_string_equals(root, "event_unit", options.at("event-unit")) &&
        json_is_object(outputs) && json_object_size(outputs) == 2u &&
        artifact_binding_valid(json_object_get(outputs, "event_map"),
            event_map_path, options.at("event-map-sha256")) &&
        artifact_binding_valid(json_object_get(outputs, "event_universe"),
            event_universe_path, options.at("event-universe-sha256")) &&
        json_is_object(labels) &&
        json_false_field(labels, "truth_input_supported") &&
        json_false_field(labels, "labels_in_online_outputs") &&
        json_is_object(namespace_node) &&
        json_string_equals(namespace_node, "mode",
            options.at("event-assets-address-mode")) &&
        json_true_field(namespace_node, "canonical_endpoint_order_preserved") &&
        json_is_object(short_frames) && json_true_field(short_frames, "validated") &&
        json_is_object(closure) &&
        json_true_field(closure, "packet_conservation") &&
        json_true_field(closure, "flow_collision_free") &&
        json_true_field(closure, "event_map_closed_by_universe") &&
        json_integer_equals(closure, "flow_collision_count", 0u) &&
        json_integer_equals(closure, "cross_namespace_packets", 0u) &&
        json_integer_equals(closure, "event_map_rows", route_count) &&
        json_integer_equals(closure, "event_universe_rows", event_count) &&
        (scenario ?
            (json_true_field(closure,
                 "scenario_universe_includes_all_mapping_captures") &&
             json_false_field(closure,
                 "five_tuple_universe_equals_observed_tuples")) :
            (json_false_field(closure,
                 "scenario_universe_includes_all_mapping_captures") &&
             json_true_field(closure,
                 "five_tuple_universe_equals_observed_tuples")));
    json_decref(root);
    if (!valid)
        *error = "event-assets receipt closure differs";
    return valid;
}

bool load_event_universe_count(
        const std::string &path,
        const std::string &event_unit,
        uint64_t *count,
        std::string *error) {
    std::ifstream input(path);
    std::string line;
    if (!input || !std::getline(input, line) || line != "event_id") {
        *error = "event universe exact CSV header differs";
        return false;
    }
    std::set<std::string> events;
    while (std::getline(input, line)) {
        if (!line.empty() && line.back() == '\r')
            line.pop_back();
        if (line.empty() || line.find('\0') != std::string::npos ||
            line.find(',') != std::string::npos ||
            !events.insert(line).second ||
            (event_unit == "scenario" && line.find("||") !=
                std::string::npos) ||
            (event_unit == "five_tuple" && line.find("||") ==
                std::string::npos)) {
            *error = "event universe row is unsafe/duplicate/noncanonical";
            return false;
        }
    }
    if (!input.eof() || events.empty()) {
        *error = "event universe is empty or unreadable";
        return false;
    }
    *count = events.size();
    return true;
}

bool initial_source_ready(
        const flowkeep::NativeFusionSourceSnapshot &snapshot,
        uint64_t expected_epoch) {
    return snapshot.run_epoch == expected_epoch &&
        snapshot.write_sequence == 0u && snapshot.published == 0u &&
        snapshot.producer_drops == 0u && snapshot.producer_overruns == 0u &&
        snapshot.producer_fail_closed == 0u &&
        snapshot.producer_validation_failures == 0u &&
        snapshot.producer_integrity_failures == 0u &&
        snapshot.read_sequence == 0u && snapshot.records_peeked == 0u &&
        snapshot.records_acked == 0u && snapshot.sequence_gaps == 0u &&
        snapshot.consumer_validation_failures == 0u &&
        snapshot.ack_rejections == 0u && snapshot.consumer_fault == 0u &&
        snapshot.consumer_open_count == 1u &&
        snapshot.consumer_close_count == 0u &&
        snapshot.consumer_claim_token != 0u;
}

bool parse_cpu_set(const std::string &text, std::set<uint32_t> *cpus) {
    if (text.empty() || cpus == nullptr)
        return false;
    cpus->clear();
    size_t begin = 0u;
    while (begin < text.size()) {
        const size_t comma = text.find(',', begin);
        const std::string field = text.substr(begin,
            comma == std::string::npos ? std::string::npos : comma - begin);
        uint64_t cpu = 0u;
        if (!parse_u64(field, &cpu) || cpu >= CPU_SETSIZE ||
            !cpus->insert(static_cast<uint32_t>(cpu)).second) {
            return false;
        }
        if (comma == std::string::npos)
            break;
        begin = comma + 1u;
    }
    return true;
}

bool parse_cpu_pair_set(
        const std::string &text,
        std::set<CpuPair> *pairs) {
    if (pairs == nullptr)
        return false;
    pairs->clear();
    if (text.empty())
        return true;
    std::set<uint32_t> endpoints;
    size_t begin = 0u;
    while (begin < text.size()) {
        const size_t comma = text.find(',', begin);
        const std::string field = text.substr(
            begin,
            comma == std::string::npos
                ? std::string::npos : comma - begin);
        const size_t colon = field.find(':');
        uint64_t first = 0u;
        uint64_t second = 0u;
        if (colon == std::string::npos ||
            field.find(':', colon + 1u) != std::string::npos ||
            !parse_u64(field.substr(0u, colon), &first) ||
            !parse_u64(field.substr(colon + 1u), &second) ||
            first >= CPU_SETSIZE || second >= CPU_SETSIZE ||
            first >= second) {
            return false;
        }
        const CpuPair pair{
            static_cast<uint32_t>(first), static_cast<uint32_t>(second)};
        if ((!pairs->empty() && pair <= *pairs->rbegin()) ||
            !endpoints.insert(static_cast<uint32_t>(first)).second ||
            !endpoints.insert(static_cast<uint32_t>(second)).second ||
            !pairs->insert(pair).second) {
            return false;
        }
        if (comma == std::string::npos)
            break;
        begin = comma + 1u;
        if (begin == text.size())
            return false;
    }
    return true;
}

bool read_cpu_topology_value(
        uint32_t cpu,
        const char *field,
        uint64_t *value) {
    const std::string path = "/sys/devices/system/cpu/cpu" +
        std::to_string(cpu) + "/topology/" + field;
    std::ifstream input(path);
    std::string text;
    if (!input || !(input >> text) || !parse_u64(text, value))
        return false;
    input >> std::ws;
    return input.eof();
}

bool summarize_cpu_topology(
        const std::set<uint32_t> &cpus,
        CpuTopologySummary *summary) {
    if (cpus.empty() || summary == nullptr)
        return false;
    using PhysicalCore = std::pair<uint64_t, uint64_t>;
    std::map<PhysicalCore, uint64_t> counts;
    for (uint32_t cpu : cpus) {
        uint64_t package = 0u;
        uint64_t core = 0u;
        if (!read_cpu_topology_value(
                cpu, "physical_package_id", &package) ||
            !read_cpu_topology_value(cpu, "core_id", &core)) {
            return false;
        }
        ++counts[{package, core}];
    }
    *summary = {};
    summary->logical_cpu_count = cpus.size();
    summary->physical_core_count = counts.size();
    for (const auto &item : counts) {
        summary->maximum_threads_per_core = std::max(
            summary->maximum_threads_per_core, item.second);
    }
    summary->consumer_smt_active =
        summary->logical_cpu_count > summary->physical_core_count;
    return true;
}

bool physical_cpu_contract_valid(
        const std::set<uint32_t> &consumers,
        const std::set<uint32_t> &reserved,
        const std::set<CpuPair> &allowed_reserved_smt_pairs,
        bool allow_consumer_smt) {
    using PhysicalCore = std::pair<uint64_t, uint64_t>;
    CpuTopologySummary consumer_topology{};
    if (!summarize_cpu_topology(consumers, &consumer_topology) ||
        (!allow_consumer_smt && consumer_topology.consumer_smt_active)) {
        return false;
    }
    std::set<PhysicalCore> consumer_cores;
    std::map<PhysicalCore, std::vector<uint32_t>> reserved_cores;
    for (uint32_t cpu : consumers) {
        uint64_t package = 0u;
        uint64_t core = 0u;
        if (!read_cpu_topology_value(
                cpu, "physical_package_id", &package) ||
            !read_cpu_topology_value(cpu, "core_id", &core)) {
            return false;
        }
        consumer_cores.emplace(package, core);
    }
    for (uint32_t cpu : reserved) {
        uint64_t package = 0u;
        uint64_t core = 0u;
        if (!read_cpu_topology_value(
                cpu, "physical_package_id", &package) ||
            !read_cpu_topology_value(cpu, "core_id", &core) ||
            consumer_cores.find({package, core}) != consumer_cores.end()) {
            return false;
        }
        reserved_cores[{package, core}].push_back(cpu);
    }
    size_t observed_allowed_pairs = 0u;
    for (auto &item : reserved_cores) {
        std::vector<uint32_t> &siblings = item.second;
        std::sort(siblings.begin(), siblings.end());
        if (siblings.size() == 1u)
            continue;
        if (siblings.size() != 2u ||
            allowed_reserved_smt_pairs.find(
                {siblings[0u], siblings[1u]}) ==
                allowed_reserved_smt_pairs.end()) {
            return false;
        }
        ++observed_allowed_pairs;
    }
    if (observed_allowed_pairs != allowed_reserved_smt_pairs.size())
        return false;
    for (const CpuPair &pair : allowed_reserved_smt_pairs) {
        if (reserved.find(pair.first) == reserved.end() ||
            reserved.find(pair.second) == reserved.end()) {
            return false;
        }
        uint64_t first_package = 0u;
        uint64_t first_core = 0u;
        uint64_t second_package = 0u;
        uint64_t second_core = 0u;
        if (!read_cpu_topology_value(
                pair.first, "physical_package_id", &first_package) ||
            !read_cpu_topology_value(
                pair.first, "core_id", &first_core) ||
            !read_cpu_topology_value(
                pair.second, "physical_package_id", &second_package) ||
            !read_cpu_topology_value(
                pair.second, "core_id", &second_core) ||
            first_package != second_package || first_core != second_core) {
            return false;
        }
    }
    return true;
}

bool parse_options(
        int argc,
        char **argv,
        std::unordered_map<std::string, std::string> *options,
        std::string *error) {
    for (int index = 1; index < argc; ++index) {
        const std::string argument(argv[index]);
        if (argument == "--help" || argument == "-h")
            return false;
        if (argument.size() <= 2u || argument.compare(0u, 2u, "--") != 0 ||
            index + 1 >= argc) {
            *error = "each option must be --name VALUE";
            return false;
        }
        const std::string name = argument.substr(2u);
        if (options->find(name) != options->end()) {
            *error = "duplicate option: --" + name;
            return false;
        }
        options->emplace(name, argv[++index]);
    }
    const std::set<std::string> allowed = {
        "terminal-coverage", "ledger-overlap-compression", "ledger-buffer-reuse",
        "online-persistence",
        "persistent-state-dir",
        "shm-name", "expected-run-epoch", "wait-seconds", "model",
        "model-sha256", "dataset-id", "bundle", "bundle-sha256",
        "model-source-dataset-id", "cross-dataset-partial-diagnostic",
        "bundle-receipt", "bundle-receipt-sha256",
        "source-model-sha256", "event-unit", "event-map",
        "event-map-sha256", "event-assets-receipt",
        "event-assets-address-mode",
        "event-assets-receipt-sha256", "event-universe",
        "event-universe-sha256", "output-dir", "retention-policy",
        "retention-detector-coupling", "detector-schedule",
        "detector-deadline-us", "deadline-miss-policy",
        "expected-run-uuid-hex", "expected-config-sha256", "consumer-cpus",
        "reserved-dpdk-cpus", "reserved-dpdk-state-smt-pairs",
        "consumer-smt", "consumer-oversubscription",
        "service-workers", "engine-threads",
        "batch-size", "durable-commit-batch-size", "durable-commit-depth",
        "durable-commit-max-wait-us", "batch-wait-us",
        "durable-commit-max-wait-age-anchor",
        "max-inflight", "flow-state-capacity", "route-quantum",
        "poll-sleep-us", "flow-open-model", "flow-open-model-sha256",
        "flow-open-schema-sha256", "flow-open-threshold",
        "adaptive-history-meta", "adaptive-history-meta-sha256",
        "adaptive-threshold", "adaptive-watch-ratio",
        "adaptive-first-packet", "adaptive-near-gap",
        "adaptive-far-gap", "adaptive-horizon-packet",
        "adaptive-action-risk", "adaptive-action-risk-sha256",
        "adaptive-marginal-table", "adaptive-marginal-table-sha256",
        "adaptive-fixed-checkpoints",
        "adaptive-event-frontiers", "adaptive-trained-policy", "adaptive-trained-policy-sha256",
        "joint-evidence-scheduling", "sparse-prefixes", "versioned-prefixes",
    };
    for (const auto &item : *options) {
        if (allowed.find(item.first) == allowed.end()) {
            *error = "unknown option: --" + item.first;
            return false;
        }
    }
    for (const char *name : kRequired) {
        if (options->find(name) == options->end()) {
            *error = std::string("missing required option: --") + name;
            return false;
        }
    }
    const char *const flow_open_names[] = {
        "flow-open-model", "flow-open-model-sha256",
        "flow-open-schema-sha256", "flow-open-threshold",
    };
    size_t flow_open_options = 0u;
    for (const char *name : flow_open_names)
        flow_open_options += options->find(name) != options->end() ? 1u : 0u;
    if (flow_open_options != 0u &&
        flow_open_options != sizeof(flow_open_names) / sizeof(flow_open_names[0])) {
        *error = "flow-open model options must be supplied as one complete set";
        return false;
    }
    const char *const adaptive_legacy_names[] = {
        "adaptive-history-meta", "adaptive-history-meta-sha256",
        "adaptive-threshold", "adaptive-watch-ratio",
        "adaptive-first-packet", "adaptive-near-gap",
        "adaptive-far-gap", "adaptive-horizon-packet",
    };
    const char *const adaptive_marginal_names[] = {
        "adaptive-action-risk",
        "adaptive-action-risk-sha256", "adaptive-marginal-table",
        "adaptive-marginal-table-sha256",
    };
    size_t legacy_options = 0u, marginal_options = 0u;
    for (const char *name : adaptive_legacy_names)
        legacy_options += options->find(name) != options->end() ? 1u : 0u;
    for (const char *name : adaptive_marginal_names)
        marginal_options += options->find(name) != options->end() ? 1u : 0u;
    const bool complete_legacy = legacy_options ==
        sizeof(adaptive_legacy_names) / sizeof(adaptive_legacy_names[0]);
    const bool complete_marginal = marginal_options ==
        sizeof(adaptive_marginal_names) / sizeof(adaptive_marginal_names[0]);
    if ((legacy_options != 0u || marginal_options != 0u) &&
        complete_legacy == complete_marginal) {
        *error = "select exactly one complete legacy or marginal adaptive option set";
        return false;
    }
    const bool has_meta = options->count("adaptive-history-meta") != 0u;
    if (has_meta != (options->count("adaptive-history-meta-sha256") != 0u) ||
        has_meta != (options->count("adaptive-threshold") != 0u)) {
        *error = "history-meta override requires path, hash and threshold together";
        return false;
    }
    if (options->count("adaptive-fixed-checkpoints") &&
        !complete_marginal) {
        *error = "fixed checkpoint control requires marginal mode";
        return false;
    }
    if ((options->count("adaptive-trained-policy") != options->count("adaptive-trained-policy-sha256")) ||
        (options->count("adaptive-trained-policy") && !complete_marginal) ||
        (options->count("adaptive-event-frontiers") &&
            (!complete_marginal || options->at("adaptive-event-frontiers") != "true"))) {
        *error = "trained policy/frontier flags require marginal mode and complete bindings";
        return false;
    }
    if ((complete_legacy || complete_marginal) &&
        options->count("persistent-state-dir")) {
        *error = "adaptive speculative candidates do not support persistent history resume";
        return false;
    }
    options->emplace("service-workers", "1");
    options->emplace("event-assets-address-mode", "compact_disjoint_blocks");
    options->emplace("model-source-dataset-id", options->at("dataset-id"));
    options->emplace("cross-dataset-partial-diagnostic", "false");
    options->emplace("deadline-miss-policy", "enforce");
    options->emplace("consumer-smt", "disabled");
    options->emplace("consumer-oversubscription", "disabled");
    options->emplace("reserved-dpdk-state-smt-pairs", "");
    options->emplace("engine-threads", "16");
    options->emplace("batch-size", "512");
    options->emplace("batch-wait-us", "5000");
    options->emplace("max-inflight", "1024");
    options->emplace("flow-state-capacity", options->at("max-inflight"));
    options->emplace("durable-commit-batch-size",
        options->at("batch-size"));
    options->emplace("durable-commit-max-wait-us", "25000");
    options->emplace("durable-commit-depth", "2");
    options->emplace("online-persistence", "durable");
    options->emplace("route-quantum", options->at("max-inflight"));
    options->emplace("poll-sleep-us", "50");
    if (options->at("online-persistence") != "durable" &&
        options->at("online-persistence") != "disabled") {
        *error = "--online-persistence must be durable or disabled";
        return false;
    }
    if (options->at("online-persistence") == "disabled" &&
        (options->count("ledger-overlap-compression") != 0u ||
         options->count("ledger-buffer-reuse") != 0u ||
         options->count("persistent-state-dir") != 0u)) {
        *error = "disabled online persistence conflicts with persistence options";
        return false;
    }
    return true;
}

const char *controlled_service_cpu_layout_kind_name(
        ControlledServiceCpuLayoutKind kind) {
    switch (kind) {
    case ControlledServiceCpuLayoutKind::PhysicalCoreIsolated:
        return "physical_core_isolated";
    case ControlledServiceCpuLayoutKind::
            LegacySharedCoordinatorCommitterCore:
        return "legacy_shared_coordinator_committer_core";
    case ControlledServiceCpuLayoutKind::Invalid:
        break;
    }
    return "invalid";
}

bool physical_cpu_sets_disjoint(
        const std::vector<uint32_t> &left,
        const std::vector<uint32_t> &right) {
    using PhysicalCore = std::pair<uint64_t, uint64_t>;
    if (left.empty() || right.empty())
        return false;
    std::set<PhysicalCore> left_cores;
    for (uint32_t cpu : left) {
        uint64_t package = 0u;
        uint64_t core = 0u;
        if (!read_cpu_topology_value(
                cpu, "physical_package_id", &package) ||
            !read_cpu_topology_value(cpu, "core_id", &core)) {
            return false;
        }
        left_cores.emplace(package, core);
    }
    for (uint32_t cpu : right) {
        uint64_t package = 0u;
        uint64_t core = 0u;
        if (!read_cpu_topology_value(
                cpu, "physical_package_id", &package) ||
            !read_cpu_topology_value(cpu, "core_id", &core) ||
            left_cores.find({package, core}) != left_cores.end()) {
            return false;
        }
    }
    return true;
}

ControlledServiceCpuLayoutKind controlled_service_cpu_layout(
        const std::set<uint32_t> &consumers,
        uint64_t service_workers,
        std::vector<uint32_t> *coordinator_cpu_set,
        std::vector<uint32_t> *committer_cpu_set,
        std::vector<std::vector<uint32_t>> *worker_cpu_sets) {
    if (service_workers == 0u || coordinator_cpu_set == nullptr ||
        committer_cpu_set == nullptr || worker_cpu_sets == nullptr) {
        return ControlledServiceCpuLayoutKind::Invalid;
    }
    coordinator_cpu_set->clear();
    committer_cpu_set->clear();
    worker_cpu_sets->clear();
    using PhysicalCore = std::pair<uint64_t, uint64_t>;
    std::map<PhysicalCore, std::vector<uint32_t>> groups;
    for (uint32_t cpu : consumers) {
        uint64_t package = 0u;
        uint64_t core = 0u;
        if (!read_cpu_topology_value(
                cpu, "physical_package_id", &package) ||
            !read_cpu_topology_value(cpu, "core_id", &core)) {
            return ControlledServiceCpuLayoutKind::Invalid;
        }
        groups[{package, core}].push_back(cpu);
    }
    std::vector<std::vector<uint32_t>> singleton_groups;
    std::vector<std::vector<uint32_t>> complete_smt_pairs;
    singleton_groups.reserve(2u);
    complete_smt_pairs.reserve(groups.size());
    for (auto &item : groups) {
        std::sort(item.second.begin(), item.second.end());
        if (item.second.size() == 1u) {
            singleton_groups.push_back(item.second);
        } else if (item.second.size() == 2u) {
            complete_smt_pairs.push_back(item.second);
        } else {
            return ControlledServiceCpuLayoutKind::Invalid;
        }
    }
    const auto order_by_first_cpu =
        [](const std::vector<uint32_t> &left,
           const std::vector<uint32_t> &right) {
            return left.front() < right.front();
        };
    std::sort(singleton_groups.begin(), singleton_groups.end(),
        order_by_first_cpu);
    std::sort(complete_smt_pairs.begin(), complete_smt_pairs.end(),
        order_by_first_cpu);

    const auto assign_workers = [&](size_t first_pair) {
        if (complete_smt_pairs.size() <= first_pair ||
            (complete_smt_pairs.size() - first_pair) % service_workers !=
                0u) {
            return false;
        }
        const size_t pairs_per_worker =
            (complete_smt_pairs.size() - first_pair) /
                static_cast<size_t>(service_workers);
        if (pairs_per_worker == 0u)
            return false;
        worker_cpu_sets->clear();
        worker_cpu_sets->reserve(static_cast<size_t>(service_workers));
        size_t pair_index = first_pair;
        for (size_t worker = 0u;
             worker < static_cast<size_t>(service_workers); ++worker) {
            std::vector<uint32_t> worker_cpus;
            worker_cpus.reserve(pairs_per_worker * 2u);
            for (size_t pair = 0u; pair < pairs_per_worker;
                 ++pair, ++pair_index) {
                worker_cpus.insert(worker_cpus.end(),
                    complete_smt_pairs[pair_index].begin(),
                    complete_smt_pairs[pair_index].end());
            }
            std::sort(worker_cpus.begin(), worker_cpus.end());
            worker_cpu_sets->push_back(std::move(worker_cpus));
        }
        return pair_index == complete_smt_pairs.size() &&
            worker_cpu_sets->size() == service_workers;
    };

    /* Formal layout: coordinator and committer occupy distinct singleton
     * physical cores.  Every worker owns one or more whole SMT pairs and no
     * physical core is shared across roles. */
    if (singleton_groups.size() == 2u &&
        complete_smt_pairs.size() >= service_workers &&
        complete_smt_pairs.size() % service_workers == 0u) {
        coordinator_cpu_set->assign(1u, singleton_groups[0u][0u]);
        committer_cpu_set->assign(1u, singleton_groups[1u][0u]);
        if (assign_workers(0u) && physical_cpu_sets_disjoint(
                *coordinator_cpu_set, *committer_cpu_set)) {
            return ControlledServiceCpuLayoutKind::PhysicalCoreIsolated;
        }
        coordinator_cpu_set->clear();
        committer_cpu_set->clear();
        worker_cpu_sets->clear();
        return ControlledServiceCpuLayoutKind::Invalid;
    }

    /* Historical receipts used complete SMT pairs everywhere and split the
     * first pair between coordinator and committer.  Preserve execution and
     * receipt readability, but classify it explicitly as non-formal. */
    if (singleton_groups.empty() && complete_smt_pairs.size() > 1u &&
        (complete_smt_pairs.size() - 1u) % service_workers == 0u) {
        coordinator_cpu_set->assign(1u, complete_smt_pairs[0u][0u]);
        committer_cpu_set->assign(1u, complete_smt_pairs[0u][1u]);
        if (assign_workers(1u) && !physical_cpu_sets_disjoint(
                *coordinator_cpu_set, *committer_cpu_set)) {
            return ControlledServiceCpuLayoutKind::
                LegacySharedCoordinatorCommitterCore;
        }
    }
    coordinator_cpu_set->clear();
    committer_cpu_set->clear();
    worker_cpu_sets->clear();
    return ControlledServiceCpuLayoutKind::Invalid;
}

int inspect_cpu_layout(const char *cpu_text, const char *worker_text) {
    uint64_t service_workers = 0u;
    std::set<uint32_t> consumers;
    const bool input_valid = cpu_text != nullptr && worker_text != nullptr &&
        parse_u64(worker_text, &service_workers) && service_workers != 0u &&
        parse_cpu_set(cpu_text, &consumers);
    CpuTopologySummary topology{};
    const bool topology_valid = input_valid &&
        summarize_cpu_topology(consumers, &topology);
    std::vector<uint32_t> coordinator_cpus;
    std::vector<uint32_t> committer_cpus;
    std::vector<std::vector<uint32_t>> worker_cpu_sets;
    const ControlledServiceCpuLayoutKind layout = topology_valid ?
        controlled_service_cpu_layout(consumers, service_workers,
            &coordinator_cpus, &committer_cpus, &worker_cpu_sets) :
        ControlledServiceCpuLayoutKind::Invalid;
    const bool isolated =
        layout == ControlledServiceCpuLayoutKind::PhysicalCoreIsolated;
    const bool compatible =
        layout != ControlledServiceCpuLayoutKind::Invalid;

    json_t *root = json_object();
    object_string(root, "protocol",
        "flowkeep-service-cpu-layout-inspection-v1");
    object_string(root, "status",
        isolated ? "PASS" : (compatible ? "LEGACY" : "INVALID"));
    object_string(root, "affinity_layout_kind",
        controlled_service_cpu_layout_kind_name(layout));
    object_bool(root, "affinity_layout_compatible", compatible);
    object_bool(root, "formal_ready", isolated);
    object_bool(root, "coordinator_committer_physical_core_disjoint",
        isolated && physical_cpu_sets_disjoint(
            coordinator_cpus, committer_cpus));
    object_u64(root, "service_workers", service_workers);
    object_u64(root, "logical_cpu_count", topology.logical_cpu_count);
    object_u64(root, "physical_core_count", topology.physical_core_count);
    object_u64(root, "maximum_threads_per_core",
        topology.maximum_threads_per_core);
    json_object_set_new(root, "consumer_cpus", cpu_array(consumers));
    json_object_set_new(root, "coordinator_cpus",
        cpu_array(coordinator_cpus));
    json_object_set_new(root, "committer_cpus",
        cpu_array(committer_cpus));
    json_t *worker_plan = json_array();
    for (const std::vector<uint32_t> &worker_cpus : worker_cpu_sets)
        json_array_append_new(worker_plan, cpu_array(worker_cpus));
    json_object_set_new(root, "worker_cpu_sets", worker_plan);
    if (!input_valid) {
        object_string(root, "failure", "invalid CPU set or worker count");
    } else if (!topology_valid) {
        object_string(root, "failure", "CPU topology could not be resolved");
    } else if (!compatible) {
        object_string(root, "failure",
            "layout is neither physical-core-isolated nor legacy-compatible");
    } else if (!isolated) {
        object_string(root, "failure",
            "coordinator and committer share one physical core");
    } else {
        json_object_set_new(root, "failure", json_null());
    }
    char *rendered = json_dumps(root, JSON_COMPACT | JSON_SORT_KEYS);
    const bool serialized = rendered != nullptr;
    if (serialized) {
        std::printf("%s\n", rendered);
        std::free(rendered);
    }
    json_decref(root);
    if (!serialized)
        return 2;
    return isolated ? 0 : (compatible ? 3 : 2);
}

bool validate_contract(
        const std::unordered_map<std::string, std::string> &options,
        std::string *error) {
    if(configured_commit_depth(options)!=2u && configured_commit_depth(options)!=4u) {
        *error="--durable-commit-depth must be 2 or 4";return false;
    }
    const char *const numeric_names[] = {
        "expected-run-epoch", "detector-deadline-us", "service-workers",
        "engine-threads", "batch-size", "durable-commit-batch-size",
        "durable-commit-max-wait-us", "batch-wait-us", "max-inflight",
        "flow-state-capacity", "route-quantum", "poll-sleep-us",
    };
    std::unordered_map<std::string, uint64_t> numeric;
    for (const char *name : numeric_names) {
        uint64_t value = 0u;
        if (!parse_u64(options.at(name), &value) || value == 0u) {
            *error = std::string("invalid positive integer: --") + name;
            return false;
        }
        numeric.emplace(name, value);
    }
    char *wait_end = nullptr;
    errno = 0;
    const double wait = std::strtod(options.at("wait-seconds").c_str(),
        &wait_end);
    if (errno != 0 || wait_end == options.at("wait-seconds").c_str() ||
        *wait_end != '\0' || !(wait > 0.0 && wait <= 3600.0)) {
        *error = "--wait-seconds is invalid";
        return false;
    }
    if (options.at("event-unit") != "scenario" &&
        options.at("event-unit") != "five_tuple") {
        *error = "--event-unit must be scenario or five_tuple";
        return false;
    }
    if (options.at("event-assets-address-mode") !=
            "compact_disjoint_blocks" &&
        options.at("event-assets-address-mode") !=
            "original_addresses_partial_diagnostic") {
        *error = "--event-assets-address-mode must be "
            "compact_disjoint_blocks or "
            "original_addresses_partial_diagnostic";
        return false;
    }
    if (options.at("cross-dataset-partial-diagnostic") != "true" &&
        options.at("cross-dataset-partial-diagnostic") != "false") {
        *error = "--cross-dataset-partial-diagnostic must be true or false";
        return false;
    }
    if (options.at("cross-dataset-partial-diagnostic") == "true" &&
        options.at("event-assets-address-mode") !=
            "original_addresses_partial_diagnostic") {
        *error = "cross-dataset diagnostic requires original-address "
            "partial-diagnostic assets";
        return false;
    }
    flowkeep::NativeFusionDetectorSchedule detector_schedule{};
    if (!parse_detector_schedule(
            options.at("detector-schedule"), &detector_schedule)) {
        *error = "--detector-schedule must be batch_fifo or "
            "deadline_guard_batch_fifo";
        return false;
    }
    if (options.at("retention-detector-coupling") != "decoupled") {
        *error = "only causally decoupled retention/detector scheduling is "
            "implemented";
        return false;
    }
    if (options.at("deadline-miss-policy") != "enforce" &&
        options.at("deadline-miss-policy") != "record_only") {
        *error = "--deadline-miss-policy must be enforce or record_only";
        return false;
    }
    const auto durable_anchor_option = options.find("durable-commit-max-wait-age-anchor");
    if (durable_anchor_option != options.end()) {
        const auto &anchor = durable_anchor_option->second;
        if (anchor != "physical_enqueue" && anchor != "physical_enqueue_monotonic_ns" &&
            anchor != "consumer_receive" && anchor != "consumer_receive_monotonic_ns" &&
            anchor != "first_durable_candidate" && anchor != "first_durable_candidate_monotonic_ns") {
            *error = "invalid --durable-commit-max-wait-age-anchor";
            return false;
        }
        if (parse_age_anchor(anchor) == flowkeep::NativeFusionDurableAgeAnchor::FirstDurableCandidate &&
            numeric.at("durable-commit-max-wait-us") > 20000u) {
            *error = "first_durable_candidate requires --durable-commit-max-wait-us in 1..20000";
            return false;
        }
    }
    if (!valid_policy_name(options.at("retention-policy"))) {
        *error = "--retention-policy must be a lowercase identifier";
        return false;
    }
    const char *const sha_names[] = {
        "model-sha256", "bundle-sha256", "bundle-receipt-sha256",
        "source-model-sha256",
        "event-map-sha256", "event-assets-receipt-sha256",
        "event-universe-sha256", "expected-config-sha256",
    };
    for (const char *name : sha_names) {
        if (!exact_hex(options.at(name), 64u)) {
            *error = std::string("invalid lowercase SHA-256: --") + name;
            return false;
        }
    }
    if (flow_open_head_enabled(options)) {
        if (!exact_hex(options.at("flow-open-model-sha256"), 64u) ||
            !exact_hex(options.at("flow-open-schema-sha256"), 64u)) {
            *error = "flow-open model/schema SHA-256 is invalid";
            return false;
        }
        char *threshold_end = nullptr;
        errno = 0;
        const double threshold = std::strtod(
            options.at("flow-open-threshold").c_str(), &threshold_end);
        if (errno != 0 ||
            threshold_end == options.at("flow-open-threshold").c_str() ||
            *threshold_end != '\0' || !std::isfinite(threshold) ||
            threshold < 0.0 || threshold > 1.0) {
            *error = "--flow-open-threshold is invalid";
            return false;
        }
    }
    if (options.count("adaptive-history-meta") || options.count("adaptive-action-risk")) {
        if (options.count("adaptive-history-meta") &&
            !exact_hex(options.at("adaptive-history-meta-sha256"), 64u)) {
            *error = "adaptive history meta SHA-256 is invalid";
            return false;
        }
        if (options.count("adaptive-action-risk")) {
            if (!exact_hex(options.at("adaptive-action-risk-sha256"), 64u) ||
                !exact_hex(options.at("adaptive-marginal-table-sha256"), 64u)) {
                *error = "adaptive marginal artifact SHA-256 is invalid";
                return false;
            }
            if (options.count("adaptive-threshold")) {
            char *end = nullptr;
            errno = 0;
            const double threshold = std::strtod(
                options.at("adaptive-threshold").c_str(), &end);
            if (errno != 0 || end == options.at("adaptive-threshold").c_str() ||
                *end != '\0' || !std::isfinite(threshold) ||
                threshold < 0.0 || threshold > 1.0) {
                *error = "invalid marginal detector threshold";
                return false;
            }
            }
        } else {
        uint64_t first = 0u, near_gap = 0u, far_gap = 0u, horizon = 0u;
        if (!parse_u64(options.at("adaptive-first-packet"), &first) ||
            !parse_u64(options.at("adaptive-near-gap"), &near_gap) ||
            !parse_u64(options.at("adaptive-far-gap"), &far_gap) ||
            !parse_u64(options.at("adaptive-horizon-packet"), &horizon) ||
            first != 4u || near_gap == 0u || far_gap == 0u ||
            horizon != 20u || near_gap > horizon || far_gap > horizon) {
            *error = "adaptive checkpoint integers are invalid";
            return false;
        }
        for (const char *name : {"adaptive-threshold",
                                 "adaptive-watch-ratio"}) {
            char *end = nullptr;
            errno = 0;
            const double value = std::strtod(options.at(name).c_str(), &end);
            if (errno != 0 || end == options.at(name).c_str() ||
                *end != '\0' || !std::isfinite(value) ||
                value < 0.0 || value > 1.0) {
                *error = std::string("invalid probability: --") + name;
                return false;
            }
        }
        }
    }
    if (!exact_hex(options.at("expected-run-uuid-hex"), 32u) ||
        options.at("model-sha256") != options.at("source-model-sha256")) {
        *error = "run UUID or source-model SHA binding is invalid";
        return false;
    }
    const uint64_t batch_size = numeric["batch-size"];
    // Keep the production microbatch allow-list closed.  The 64-row point is
    // qualified for the latency-safe online schedule; 512 and larger remain
    // the frozen Development upper-envelope points.
    const bool supported_batch = batch_size == 64u || batch_size == 512u ||
        batch_size == 1024u || batch_size == 2048u ||
        batch_size == 4096u;
    const uint64_t service_workers = numeric["service-workers"];
    const bool supported_workers = service_workers == 1u ||
        service_workers == 2u || service_workers == 4u ||
        service_workers == 8u;
    if (!supported_workers ||
        numeric["engine-threads"] > 64u ||
        numeric["engine-threads"] % service_workers != 0u ||
        !supported_batch ||
        numeric["max-inflight"] < numeric["batch-size"] ||
        numeric["max-inflight"] > 262144u ||
        numeric["flow-state-capacity"] < numeric["max-inflight"] ||
        numeric["flow-state-capacity"] > 1048576u ||
        numeric["durable-commit-batch-size"] > 65536u ||
        numeric["durable-commit-batch-size"] > numeric["max-inflight"] ||
        numeric["durable-commit-max-wait-us"] >
            numeric["detector-deadline-us"] ||
        numeric["route-quantum"] > numeric["max-inflight"] ||
        numeric["batch-wait-us"] > 1000000u ||
        numeric["poll-sleep-us"] > 1000000u ||
        numeric["detector-deadline-us"] > 3600000000u) {
        *error = "formal worker/batch/inflight settings differ";
        return false;
    }
    std::set<uint32_t> consumers;
    std::set<uint32_t> reserved;
    std::set<CpuPair> allowed_reserved_smt_pairs;
    const std::string &consumer_smt = options.at("consumer-smt");
    const std::string &consumer_oversubscription =
        options.at("consumer-oversubscription");
    if ((consumer_smt != "disabled" && consumer_smt != "enabled") ||
        (consumer_oversubscription != "disabled" &&
         consumer_oversubscription != "enabled")) {
        *error = "consumer SMT/oversubscription mode is invalid";
        return false;
    }
    const bool consumer_smt_enabled = consumer_smt == "enabled";
    const bool oversubscription_enabled =
        consumer_oversubscription == "enabled";
    const uint64_t service_thread_count = numeric["engine-threads"] + 2u;
    if (!parse_cpu_set(options.at("consumer-cpus"), &consumers) ||
        !parse_cpu_set(options.at("reserved-dpdk-cpus"), &reserved) ||
        !parse_cpu_pair_set(
            options.at("reserved-dpdk-state-smt-pairs"),
            &allowed_reserved_smt_pairs)) {
        *error = "consumer/reserved CPU set or DPDK SMT whitelist is invalid";
        return false;
    }
    const uint64_t normal_consumer_cpus = numeric["engine-threads"] +
        (consumer_smt_enabled ? 2u : 1u);
    if ((!oversubscription_enabled &&
         consumers.size() != normal_consumer_cpus) ||
        (oversubscription_enabled &&
         (!consumer_smt_enabled || consumers.size() >= service_thread_count ||
          service_thread_count > consumers.size() * 4u ||
          consumers.size() < service_workers + 2u))) {
        *error = "consumer CPU set violates controlled oversubscription";
        return false;
    }
    for (uint32_t cpu : consumers) {
        if (reserved.find(cpu) != reserved.end()) {
            *error = "consumer and reserved DPDK CPU sets overlap";
            return false;
        }
    }
    if (!physical_cpu_contract_valid(
            consumers,
            reserved,
            allowed_reserved_smt_pairs,
            consumer_smt_enabled)) {
        *error = "consumer/DPDK physical cores or SMT siblings overlap";
        return false;
    }
    CpuTopologySummary consumer_topology{};
    if (!summarize_cpu_topology(consumers, &consumer_topology) ||
        (oversubscription_enabled &&
         (consumer_topology.maximum_threads_per_core != 2u ||
          consumer_topology.logical_cpu_count !=
              consumer_topology.physical_core_count * 2u))) {
        *error = "controlled oversubscription requires complete SMT pairs";
        return false;
    }
    return true;
}

}  // namespace

int main(int argc, char **argv) {
    if (argc >= 2 &&
        std::strcmp(argv[1], "--inspect-cpu-layout") == 0) {
        if (argc != 4) {
            std::fputs(kUsage, stderr);
            return 2;
        }
        return inspect_cpu_layout(argv[2], argv[3]);
    }
    if (argc == 2 && (std::strcmp(argv[1], "--help") == 0 ||
                     std::strcmp(argv[1], "-h") == 0)) {
        std::fputs(kUsage, stdout);
        return 0;
    }
    std::unordered_map<std::string, std::string> options;
    std::string error;
    if (!parse_options(argc, argv, &options, &error) ||
        !validate_contract(options, &error)) {
        std::fprintf(stderr, "%s\n%s", error.c_str(), kUsage);
        return 2;
    }

    uint64_t epoch = 0u;
    uint64_t service_workers = 0u;
    uint64_t engine_threads = 0u;
    uint64_t batch_size = 0u;
    uint64_t durable_commit_batch_size = 0u;
    uint64_t durable_commit_max_wait_us = 0u;
    uint64_t batch_wait_us = 0u;
    uint64_t max_inflight = 0u;
    uint64_t flow_state_capacity = 0u;
    uint64_t route_quantum = 0u;
    uint64_t poll_us = 0u;
    uint64_t deadline_us = 0u;
    flowkeep::NativeFusionDetectorSchedule detector_schedule{};
    (void)parse_u64(options.at("expected-run-epoch"), &epoch);
    (void)parse_u64(options.at("service-workers"), &service_workers);
    (void)parse_u64(options.at("engine-threads"), &engine_threads);
    (void)parse_u64(options.at("batch-size"), &batch_size);
    (void)parse_u64(options.at("durable-commit-batch-size"),
        &durable_commit_batch_size);
    (void)parse_u64(options.at("durable-commit-max-wait-us"),
        &durable_commit_max_wait_us);
    (void)parse_u64(options.at("batch-wait-us"), &batch_wait_us);
    (void)parse_u64(options.at("max-inflight"), &max_inflight);
    (void)parse_u64(options.at("flow-state-capacity"),
        &flow_state_capacity);
    (void)parse_u64(options.at("route-quantum"), &route_quantum);
    (void)parse_u64(options.at("poll-sleep-us"), &poll_us);
    (void)parse_u64(options.at("detector-deadline-us"), &deadline_us);
    (void)parse_detector_schedule(
        options.at("detector-schedule"), &detector_schedule);
    char *wait_end = nullptr;
    const double wait_seconds = std::strtod(
        options.at("wait-seconds").c_str(), &wait_end);
    (void)wait_end;
    const bool adaptive_enabled =
        options.count("adaptive-history-meta") != 0u ||
        options.count("adaptive-action-risk") != 0u;
    const bool marginal_enabled =
        options.count("adaptive-action-risk") != 0u;
    if(options.count("joint-evidence-scheduling") &&
       (!marginal_enabled || options.at("joint-evidence-scheduling")!="true")) {
        std::fputs("joint evidence scheduling requires marginal mode and true\n",stderr);
        return 2;
    }
    if(options.count("versioned-prefixes") &&
       (options.at("versioned-prefixes")!="true" || options.count("sparse-prefixes") ||
        !marginal_enabled || !options.count("terminal-coverage") || !options.count("adaptive-history-meta") ||
        options.count("adaptive-fixed-checkpoints"))) {
        std::fputs("versioned prefixes require the history-meta marginal policy and terminal coverage\n",stderr);return 2;
    }
    if(options.count("sparse-prefixes") &&
       (!marginal_enabled || !options.count("terminal-coverage") || options.at("sparse-prefixes")!="true" ||
        options.count("adaptive-trained-policy") || options.count("adaptive-fixed-checkpoints") ||
        !options.count("adaptive-history-meta"))) {
        std::fputs("sparse prefixes require the history-meta marginal policy and terminal coverage\n",stderr);
        return 2;
    }
    flowkeep::AdaptiveCheckpointScorerConfig adaptive_config{};
    if (adaptive_enabled) {
        if (options.count("adaptive-threshold"))
            adaptive_config.threshold = std::strtod(
                options.at("adaptive-threshold").c_str(), nullptr);
        adaptive_config.fixed_checkpoint_control =
            options.count("adaptive-fixed-checkpoints") != 0u;
        adaptive_config.event_frontier_batching = options.count("adaptive-event-frontiers") != 0;
        if (adaptive_config.fixed_checkpoint_control) {
            adaptive_config.fixed_points.clear();
            const std::string &list = options.at("adaptive-fixed-checkpoints");
            size_t start = 0;
            while (start < list.size()) {
                const auto end = list.find(',', start);
                uint64_t point = 0;
                if (!parse_u64(list.substr(start, end == std::string::npos ? end : end - start), &point) ||
                    point == 0 || point > 20 || adaptive_config.fixed_points.size() >= 4 ||
                    (!adaptive_config.fixed_points.empty() && point <= adaptive_config.fixed_points.back())) {
                    std::fputs("invalid fixed checkpoint list\n", stderr); return 2;
                }
                adaptive_config.fixed_points.push_back(static_cast<uint8_t>(point));
                if (end == std::string::npos) break;
                start = end + 1;
            }
            if (list.empty() || list.back() == ',' || adaptive_config.fixed_points.empty() || adaptive_config.fixed_points.back() != 20) {
                std::fputs("fixed checkpoint list must end in 20\n", stderr); return 2;
            }
        }
        if (marginal_enabled) {
            adaptive_config.marginal_enabled = true;
            adaptive_config.action_risk_model_path =
                options.at("adaptive-action-risk");
            if (!load_marginal_table(
                    options.at("adaptive-marginal-table"),
                    &adaptive_config.marginal, &error)) {
                std::fprintf(stderr, "%s\n", error.c_str());
                return 2;
            }
            if (adaptive_config.marginal.horizon_packet < 20u) {
                std::fputs("marginal checkpoint table does not cover packet 20\n",
                    stderr);
                return 2;
            }
            /* R16 retains no exact cumulative packet state after packet 20.
             * Keep NEXT, STOP and dirty-EOF in that same executable domain. */
            adaptive_config.marginal.horizon_packet = 20u;
        } else {
            uint64_t value = 0u;
            (void)parse_u64(options.at("adaptive-first-packet"), &value);
            adaptive_config.first_packet = static_cast<uint32_t>(value);
            (void)parse_u64(options.at("adaptive-near-gap"), &value);
            adaptive_config.near_gap = static_cast<uint32_t>(value);
            (void)parse_u64(options.at("adaptive-far-gap"), &value);
            adaptive_config.far_gap = static_cast<uint32_t>(value);
            (void)parse_u64(options.at("adaptive-horizon-packet"), &value);
            adaptive_config.horizon_packet = static_cast<uint32_t>(value);
            adaptive_config.watch_ratio = std::strtod(
                options.at("adaptive-watch-ratio").c_str(), nullptr);
        }
    }

    std::set<uint32_t> consumer_cpus;
    std::set<uint32_t> reserved_cpus;
    (void)parse_cpu_set(options.at("consumer-cpus"), &consumer_cpus);
    (void)parse_cpu_set(options.at("reserved-dpdk-cpus"), &reserved_cpus);
    if (!apply_affinity(consumer_cpus, &error)) {
        std::fprintf(stderr, "%s\n", error.c_str());
        return 2;
    }
    const bool dedicated_affinity =
        options.at("consumer-smt") == "enabled";
    std::vector<uint32_t> coordinator_cpu_set;
    std::vector<uint32_t> committer_cpu_set;
    std::vector<std::vector<uint32_t>> worker_cpu_sets;
    if (dedicated_affinity) {
        const ControlledServiceCpuLayoutKind layout =
            controlled_service_cpu_layout(
                consumer_cpus, service_workers, &coordinator_cpu_set,
                &committer_cpu_set, &worker_cpu_sets);
        if (layout == ControlledServiceCpuLayoutKind::Invalid) {
            std::fputs(
                "controlled service CPU layout requires either two singleton "
                "physical cores plus an equal positive number of complete SMT "
                "pairs per worker, or the executable legacy split-pair "
                "layout\n", stderr);
            return 2;
        }
    }

    std::string model_path;
    std::string bundle_path;
    std::string bundle_receipt_path;
    std::string event_map_path;
    std::string assets_receipt_path;
    std::string event_universe_path;
    std::string flow_open_model_path;
    std::string adaptive_history_meta_path;
    std::string adaptive_action_risk_path;
    std::string adaptive_marginal_table_path;
    if (!verify_file_binding(options.at("model"),
            options.at("model-sha256"), &model_path, &error) ||
        !verify_file_binding(options.at("bundle"),
            options.at("bundle-sha256"), &bundle_path, &error) ||
        !verify_file_binding(options.at("bundle-receipt"),
            options.at("bundle-receipt-sha256"),
            &bundle_receipt_path, &error) ||
        !verify_file_binding(options.at("event-map"),
            options.at("event-map-sha256"), &event_map_path, &error) ||
        !verify_file_binding(options.at("event-assets-receipt"),
            options.at("event-assets-receipt-sha256"),
            &assets_receipt_path, &error) ||
        !verify_file_binding(options.at("event-universe"),
            options.at("event-universe-sha256"),
            &event_universe_path, &error)) {
        std::fprintf(stderr, "%s\n", error.c_str());
        return 2;
    }
    if (flow_open_head_enabled(options) &&
        !verify_file_binding(options.at("flow-open-model"),
            options.at("flow-open-model-sha256"),
            &flow_open_model_path, &error)) {
        std::fprintf(stderr, "%s\n", error.c_str());
        return 2;
    }
    if (options.count("adaptive-history-meta") &&
        !verify_file_binding(options.at("adaptive-history-meta"),
            options.at("adaptive-history-meta-sha256"),
            &adaptive_history_meta_path, &error)) {
        std::fprintf(stderr, "%s\n", error.c_str());
        return 2;
    }
    if (marginal_enabled &&
        (!verify_file_binding(options.at("adaptive-action-risk"),
            options.at("adaptive-action-risk-sha256"),
            &adaptive_action_risk_path, &error) ||
         !verify_file_binding(options.at("adaptive-marginal-table"),
            options.at("adaptive-marginal-table-sha256"),
            &adaptive_marginal_table_path, &error))) {
        std::fprintf(stderr, "%s\n", error.c_str());
        return 2;
    }
    if (marginal_enabled)
        adaptive_config.action_risk_model_path = adaptive_action_risk_path;
    if (options.count("adaptive-trained-policy")) {
        std::string policy_path;
        if (!verify_file_binding(options.at("adaptive-trained-policy"),
            options.at("adaptive-trained-policy-sha256"), &policy_path, &error)) {
            std::fprintf(stderr, "%s\n", error.c_str()); return 2;
        }
        adaptive_config.trained_policy = flowkeep::TrainedCheckpointPolicy::Load(policy_path.c_str());
        if (!adaptive_config.trained_policy) {
            std::fputs("invalid trained checkpoint policy\n", stderr); return 2;
        }
        char action_hex[65]{};
        for (size_t i = 0; i < 32; ++i)
            std::snprintf(action_hex + i * 2, 3, "%02x", adaptive_config.trained_policy->action_sha[i]);
        if (options.at("adaptive-action-risk-sha256") != action_hex) {
            std::fputs("trained policy admission model mismatch\n", stderr); return 2;
        }
    }
    if (!validate_bundle_receipt(bundle_receipt_path, bundle_path,
            options, &error)) {
        std::fprintf(stderr, "%s\n", error.c_str());
        return 2;
    }

    std::unique_ptr<flowkeep::NativeFusionCsvEventRouter> router =
        flowkeep::NativeFusionCsvEventRouter::Load(event_map_path,
            options.at("event-map-sha256"), options.at("event-unit"),
            &error);
    if (!router) {
        std::fprintf(stderr, "%s\n", error.c_str());
        return 2;
    }
    flowkeep::NativeFusionEventRouterAudit router_audit{};
    uint64_t event_count = 0u;
    if (!router->Audit(&router_audit, &error) ||
        !load_event_universe_count(event_universe_path,
            options.at("event-unit"), &event_count, &error) ||
        !validate_event_assets_receipt(assets_receipt_path,
            event_map_path, event_universe_path, options,
            router_audit.entries, event_count, &error)) {
        std::fprintf(stderr, "%s\n", error.c_str());
        return 2;
    }

    uint8_t bundle_sha[32]{};
    uint8_t model_sha[32]{};
    (void)parse_sha256(options.at("bundle-sha256"), bundle_sha);
    (void)parse_sha256(options.at("source-model-sha256"), model_sha);
    std::array<char, 1024u> native_error{};
    using NativeModelPtr = std::unique_ptr<
        fk_native_fusion_model, decltype(&fk_native_fusion_model_destroy)>;
    NativeModelPtr model(fk_native_fusion_model_load(
        bundle_path.c_str(), bundle_sha, model_sha,
        native_error.data(), native_error.size()),
        &fk_native_fusion_model_destroy);
    if (!model) {
        std::fprintf(stderr, "%s\n", native_error.data());
        return 2;
    }
    using CpuModelPtr = std::unique_ptr<
        fk_cpu_model, decltype(&fk_cpu_model_destroy)>;
    CpuModelPtr flow_open_model(nullptr, &fk_cpu_model_destroy);
    std::unique_ptr<CpuFlowOpenScorer> flow_open_scorer;
    double flow_open_threshold = 0.0;
    if (flow_open_head_enabled(options)) {
        std::array<char, 1024u> flow_open_error{};
        flow_open_model.reset(fk_cpu_model_load_verified(
            flow_open_model_path.c_str(),
            options.at("flow-open-model-sha256").c_str(),
            flow_open_error.data(), flow_open_error.size()));
        fk_cpu_model_metadata flow_open_metadata{};
        char *threshold_end = nullptr;
        flow_open_threshold = std::strtod(
            options.at("flow-open-threshold").c_str(), &threshold_end);
        (void)threshold_end;
        if (!flow_open_model ||
            !fk_cpu_model_get_metadata(
                flow_open_model.get(), &flow_open_metadata) ||
            flow_open_metadata.role != FK_CPU_MODEL_DETECTOR ||
            flow_open_metadata.feature_count != kFlowOpenFeatureCount ||
            flow_open_metadata.output_count != 1u ||
            options.at("flow-open-schema-sha256") !=
                flow_open_metadata.feature_schema_sha256) {
            std::fprintf(stderr, "%s\n",
                flow_open_error[0] == '\0'
                    ? "flow-open CPU model metadata/schema differs"
                    : flow_open_error.data());
            return 2;
        }
        flow_open_scorer = std::make_unique<CpuFlowOpenScorer>(
            flow_open_model.get());
    }
    const uint64_t threads_per_worker = engine_threads / service_workers;
    fk_native_fusion_metadata metadata{};
    if (!fk_native_fusion_model_get_metadata(model.get(), &metadata) ||
        metadata.model_bytes == 0u ||
        threads_per_worker > metadata.maximum_threads) {
        std::fprintf(stderr, "native fusion model metadata/thread bound differs\n");
        return 2;
    }
    uint64_t locked_model_bytes = 0u;
    if (!fk_native_fusion_model_mlock(
            model.get(), &locked_model_bytes,
            native_error.data(), native_error.size())) {
        std::fprintf(stderr, "%s\n", native_error.data());
        return 2;
    }
    if (!fk_native_fusion_model_get_metadata(model.get(), &metadata) ||
        metadata.mlock_succeeded != 1u ||
        locked_model_bytes != metadata.model_bytes ||
        metadata.locked_bytes != metadata.model_bytes) {
        std::fprintf(stderr,
            "native fusion model residency verification failed\n");
        return 2;
    }
    if (options.count("adaptive-history-meta"))
        metadata.threshold = adaptive_config.threshold;
    else if (adaptive_enabled)
        adaptive_config.threshold = metadata.threshold;
    if (marginal_enabled && adaptive_config.marginal.detector_score_prior &&
        (options.count("adaptive-history-meta") ||
         adaptive_config.marginal.alert_threshold != metadata.threshold ||
         std::memcmp(adaptive_config.marginal.source_model_sha256,
             metadata.source_model_sha256, 32) != 0)) {
        std::fprintf(stderr, "marginal prior does not match the frozen detector/threshold\n");
        return 2;
    }
    if (marginal_enabled)
        adaptive_config.marginal.alert_threshold = adaptive_config.threshold;
    if (adaptive_config.trained_policy &&
        (adaptive_config.trained_policy->threshold != metadata.threshold ||
         std::memcmp(adaptive_config.trained_policy->model_sha.data(), metadata.source_model_sha256, 32) != 0)) {
        std::fputs("trained policy detector/threshold mismatch\n", stderr); return 2;
    }
    if(adaptive_config.trained_policy) {
        const auto &policy=*adaptive_config.trained_policy;
        char meta_hex[65]{};
        for(size_t i=0;i<32;++i)std::snprintf(meta_hex+i*2,3,"%02x",policy.history_meta_sha[i]);
        if(policy.utility_stop != bool(options.count("adaptive-history-meta")) ||
           (policy.utility_stop && options.at("adaptive-history-meta-sha256")!=meta_hex)) {
            std::fputs("trained policy history-meta binding mismatch\n",stderr);return 2;
        }
    }
    std::shared_ptr<flowkeep::AdaptiveTerminalRegistry>
        adaptive_terminal_registry;
    std::shared_ptr<flowkeep::SparsePrefixChannel> sparse_prefixes;
    if(options.count("versioned-prefixes")) {
        try {
            adaptive_config.prefix_versions=std::make_shared<flowkeep::PrefixVersionStore>(options.at("shm-name"),epoch);
            if(!adaptive_config.prefix_versions->BindRecycling(true) ||
               !adaptive_config.prefix_versions->BindBulkRecycling(true))
                throw std::runtime_error("H7 recycling mode mismatch");
            if(!adaptive_config.prefix_versions->BindThreshold(adaptive_config.threshold))
                throw std::runtime_error("versioned RX/service threshold mismatch");
        }catch(const std::exception &e){std::fprintf(stderr,"versioned prefix channel: %s\n",e.what());return 2;}
    }
    if(options.count("sparse-prefixes")) {
        try {
            sparse_prefixes=std::make_shared<flowkeep::SparsePrefixChannel>(options.at("shm-name"),epoch);
            if(!sparse_prefixes->BindThreshold(adaptive_config.threshold))
                throw std::runtime_error("sparse RX/service threshold mismatch");
        }catch(const std::exception &e){std::fprintf(stderr,"sparse prefix channel: %s\n",e.what());return 2;}
    }
    if (marginal_enabled) {
        adaptive_terminal_registry =
            std::make_shared<flowkeep::AdaptiveTerminalRegistry>(sparse_prefixes);
    if(adaptive_terminal_registry)adaptive_terminal_registry->SetNaturalAuditVersions(adaptive_config.prefix_versions);
        adaptive_config.terminal_registry = adaptive_terminal_registry;
        if(options.count("joint-evidence-scheduling")) {
            try {
                adaptive_config.evidence_feedback=std::make_shared<flowkeep::EvidenceGainChannel>(
                    options.at("shm-name"),epoch);
            } catch(const std::exception &e) {
                std::fprintf(stderr,"evidence gain channel: %s\n",e.what());return 2;
            }
        }
    }
    std::shared_ptr<flowkeep::FinalScoredEvidenceSelector> selected_evidence;
    const std::string selected_evidence_mode=selected_environment("FK_SELECTED_EVIDENCE_MODE","off");
    if(selected_evidence_mode!="off") {
        try {
            if((selected_evidence_mode!="baseline" && selected_evidence_mode!="flowkeep") ||
               !adaptive_config.prefix_versions || !adaptive_terminal_registry ||
               options.at("online-persistence")!="durable")
                throw std::invalid_argument("selected evidence requires versioned adaptive online persistence");
            flowkeep::SelectedEvidenceStoreConfig config;
            config.mode=selected_evidence_mode;
            config.version_submission_guard=true;
            config.wal_group_batches=4;
            config.compress_values=true;
            config.prepare_pipeline=selected_environment("FK_SELECTED_PREPARE_PIPELINE","1")=="1";
            config.directory=options.at("output-dir")+"/selected_evidence";
            config.model_sha256=options.at("source-model-sha256");
            config.policy_sha256=options.count("adaptive-trained-policy-sha256")?
                options.at("adaptive-trained-policy-sha256"):options.at("expected-config-sha256");
            config.run_uuid=options.at("expected-run-uuid-hex");
            config.capacity_records=selected_environment_size("FK_SELECTED_EVIDENCE_CAPACITY_RECORDS",4096,65536);
            config.capacity_bytes=selected_environment_size("FK_SELECTED_EVIDENCE_CAPACITY_BYTES",8u<<20,256u<<20);
            config.batch_size=selected_environment_size("FK_SELECTED_EVIDENCE_BATCH_SIZE",512,1024);
            config.coalesce_us=selected_environment_size("FK_SELECTED_EVIDENCE_COALESCE_US",2000,5000);
            config.writer_cpu=selected_environment_size("FK_SELECTED_EVIDENCE_WRITER_CPU",31,CPU_SETSIZE-1);
            config.full_wait_ms=selected_environment_size("FK_SELECTED_EVIDENCE_FULL_WAIT_MS",30000,30000);
            auto storage=std::make_shared<flowkeep::SelectedEvidenceStore>(config);
            selected_evidence=std::make_shared<flowkeep::FinalScoredEvidenceSelector>(
                adaptive_config.prefix_versions,adaptive_config.evidence_feedback,storage,
                static_cast<size_t>(flow_state_capacity),static_cast<size_t>(max_inflight));
            adaptive_config.selected_evidence_observer=selected_evidence;
        }catch(const std::exception &e){std::fprintf(stderr,"selected evidence setup: %s\n",e.what());return 2;}
    }
    using NativeSessionPtr = std::unique_ptr<
        fk_native_fusion_session, decltype(&fk_native_fusion_session_destroy)>;
    std::shared_ptr<flowkeep::NativeRocksDbResources> persistent_resources;
    if (options.count("persistent-state-dir"))
        persistent_resources=std::make_shared<flowkeep::NativeRocksDbResources>();
    std::vector<std::unique_ptr<flowkeep::NativeRocksDbState>> persistent_stores;
    std::vector<NativeSessionPtr> sessions;
    std::vector<std::unique_ptr<flowkeep::NativeFusionBatchScorer>>
        scorer_storage;
    std::vector<flowkeep::NativeFusionBatchScorer *> scorers;
    try {
        sessions.reserve(service_workers);
        scorer_storage.reserve(service_workers);
        scorers.reserve(service_workers);
        for (uint64_t worker = 0u; worker < service_workers; ++worker) {
            if (dedicated_affinity) {
                const std::set<uint32_t> worker_affinity(
                    worker_cpu_sets[static_cast<size_t>(worker)].begin(),
                    worker_cpu_sets[static_cast<size_t>(worker)].end());
                if (!apply_affinity(worker_affinity, &error)) {
                    std::fprintf(stderr,
                        "native session pool affinity failed: %s\n",
                        error.c_str());
                    return 2;
                }
            }
            NativeSessionPtr session(fk_native_fusion_session_create(
                model.get(), static_cast<uint32_t>(threads_per_worker),
                native_error.data(), native_error.size()),
                &fk_native_fusion_session_destroy);
            if (!session) {
                std::fprintf(stderr, "%s\n", native_error.data());
                return 2;
            }
            if (options.count("adaptive-history-meta") &&
                !fk_native_fusion_session_attach_history_meta(
                    session.get(), adaptive_history_meta_path.c_str(),
                    adaptive_config.threshold,
                    native_error.data(), native_error.size())) {
                std::fprintf(stderr, "%s\n", native_error.data());
                return 2;
            }
            if (options.count("persistent-state-dir")) {
                const std::filesystem::path directory(options.at("persistent-state-dir"));
                std::filesystem::create_directories(directory);
                const std::string path=(directory/("worker_"+std::to_string(worker))).string();
                // Resume requires coordination with the durable output ledger.
                // A fresh experiment must never silently reuse scored state.
                if (std::filesystem::exists(path))
                    throw std::runtime_error("persistent worker directory already exists; online resume not implemented");
                const std::string binding=options.at("bundle-sha256")+":"+
                    options.at("event-map-sha256")+":"+options.at("retention-policy")+":"+
                    std::to_string(service_workers)+":"+std::to_string(worker);
                auto store=std::make_unique<flowkeep::NativeRocksDbState>(path,binding,persistent_resources);
                store->EnableAsync();
                auto callbacks=store->submission_callbacks();
                if (!fk_native_fusion_session_attach_submitted_backend(session.get(),&callbacks,
                        native_error.data(),native_error.size()))
                    throw std::runtime_error(native_error.data());
                persistent_stores.push_back(std::move(store));
                std::fprintf(stdout,"FLOWKEEP_PERSISTENT_STATE worker=%llu backend=rocksdb sync=true wal=true path=%s\n",
                    static_cast<unsigned long long>(worker),path.c_str());
                std::fflush(stdout);
            }
            std::unique_ptr<flowkeep::NativeFusionBatchScorer> scorer;
            if (adaptive_enabled) {
                auto adaptive = std::make_unique<
                    flowkeep::AdaptiveCheckpointEngineScorer>(
                        session.get(),
                        static_cast<uint32_t>(threads_per_worker),
                        adaptive_config);
                if (!adaptive->valid())
                    throw std::runtime_error(
                        "adaptive checkpoint scorer configuration invalid");
                if (persistent_resources)
                    adaptive->SetContextSink(persistent_stores.back().get());
                scorer = std::move(adaptive);
            } else {
                auto frozen = std::make_unique<
                    flowkeep::NativeFusionEngineScorer>(
                        session.get(),
                        static_cast<uint32_t>(threads_per_worker));
                if (persistent_resources)
                    frozen->SetContextSink(persistent_stores.back().get());
                scorer = std::move(frozen);
            }
            scorers.push_back(scorer.get());
            sessions.push_back(std::move(session));
            scorer_storage.push_back(std::move(scorer));
        }
        if (dedicated_affinity) {
            const std::set<uint32_t> coordinator_affinity(
                coordinator_cpu_set.begin(), coordinator_cpu_set.end());
            if (!apply_affinity(coordinator_affinity, &error)) {
                std::fprintf(stderr, "coordinator affinity failed: %s\n",
                    error.c_str());
                return 2;
            }
        }
    } catch (const std::exception &exception) {
        std::fprintf(stderr, "native scorer allocation failed: %s\n",
            exception.what());
        return 2;
    } catch (...) {
        std::fputs("native scorer allocation failed\n", stderr);
        return 2;
    }

    flowkeep::NativeFusionJsonlLedgerConfig ledger_config{};
    const bool terminal_coverage = options.count("terminal-coverage") != 0;
    if (terminal_coverage && (options.at("terminal-coverage") != "true" ||
        options.at("event-unit") != "five_tuple" || flow_open_scorer != nullptr ||
        router_audit.entries != event_count)) {
        std::fputs("terminal coverage requires one-to-one five_tuple events and no flow-open model\n", stderr);
        return 2;
    }
    ledger_config.terminal_coverage = terminal_coverage;
    ledger_config.synchronous_wal_segments=true;
    ledger_config.group_wal_publication=true;
    ledger_config.prepared_commit_capacity=static_cast<uint32_t>(configured_commit_depth(options));
    if(options.count("ledger-buffer-reuse")) {
        if(options.at("ledger-buffer-reuse")!="true") {
            std::fputs("ledger buffer reuse requires true\n",stderr);return 2;
        }
        ledger_config.reuse_payload_buffers=true;
    }
    if(options.count("ledger-overlap-compression")) {
        if(options.at("ledger-overlap-compression")!="true" || !dedicated_affinity) {
            std::fputs("ledger overlap requires true and dedicated affinity\n",stderr);return 2;
        }
        ledger_config.defer_compression_to_publish=true;
    }
    ledger_config.output_directory = options.at("output-dir");
    ledger_config.run_uuid_hex = options.at("expected-run-uuid-hex");
    ledger_config.threshold = metadata.threshold;
    if (deadline_us > UINT64_MAX / 1000u) {
        std::fprintf(stderr, "detector deadline overflows nanoseconds\n");
        return 2;
    }
    ledger_config.detector_deadline_ns = deadline_us * 1000u;
    /* Tuple routes can contain multiple physical epochs. Bound the exact
     * durable epoch index by the same explicit run-wide service capacity. */
    ledger_config.expected_semantic_chains = flow_state_capacity;
    ledger_config.expected_event_states = event_count;
    ledger_config.provisional_flow_open_scores =
        flow_open_scorer != nullptr;
    const bool online_persistence_disabled =
        options.at("online-persistence") == "disabled";
    std::unique_ptr<flowkeep::NativeFusionJsonlLedger> ledger;
    std::unique_ptr<BufferedEvaluationCommitter> memory_committer;
    flowkeep::NativeFusionCommitter *online_committer = nullptr;
    if (online_persistence_disabled) {
        try {
            const size_t reserve_rows = event_count > SIZE_MAX / 2u ?
                static_cast<size_t>(event_count) :
                static_cast<size_t>(event_count * 2u);
            memory_committer =
                std::make_unique<BufferedEvaluationCommitter>(reserve_rows);
            online_committer = memory_committer.get();
        } catch (...) {
            std::fputs("in-memory evaluation committer allocation failed\n",
                stderr);
            return 2;
        }
    } else {
        ledger = flowkeep::NativeFusionJsonlLedger::Create(
            ledger_config, &error);
        if (!ledger) {
            std::fprintf(stderr, "%s\n", error.c_str());
            return 2;
        }
        online_committer = ledger.get();
    }

    std::unique_ptr<flowkeep::NativeFusionRequestSource> source =
        wait_for_source(options.at("shm-name"), epoch, wait_seconds, &error);
    flowkeep::NativeCoverageSource *coverage_source = nullptr;
    flowkeep::VersionedObservationSource *versioned_source = nullptr;
    if(source && terminal_coverage && adaptive_config.prefix_versions) {
        try {
            auto wrapped=std::make_unique<flowkeep::VersionedObservationSource>(std::move(source),router.get(),
                adaptive_config.prefix_versions,adaptive_terminal_registry,static_cast<size_t>(flow_state_capacity),selected_evidence);
            versioned_source=wrapped.get();source=std::move(wrapped);
        }catch(const std::exception &e){std::fprintf(stderr,"versioned source: %s\n",e.what());return 2;}
    }
    if (source && terminal_coverage && !versioned_source) {
        try {
            auto wrapped = std::make_unique<flowkeep::NativeCoverageSource>(
                std::move(source), router.get(), router_audit.entries,
                event_count, adaptive_enabled,
                static_cast<size_t>(flow_state_capacity),
                adaptive_terminal_registry,sparse_prefixes);
            coverage_source = wrapped.get(); source = std::move(wrapped);
        } catch (const std::exception &e) {
            std::fprintf(stderr, "coverage source allocation failed: %s\n", e.what());
            return 2;
        }
    }
    flowkeep::NativeFusionSourceSnapshot initial{};
    if (!source || !source->Snapshot(&initial, &error) ||
        !initial_source_ready(initial, epoch)) {
        if (error.empty())
            error = "initial formal consumer snapshot is not clean";
        std::fprintf(stderr, "%s\n", error.c_str());
        if (source) {
            std::string ignored;
            (void)source->Close(&ignored);
        }
        if (ledger) {
            std::string ignored;
            (void)ledger->Close(&ignored);
        }
        return 2;
    }
    flowkeep::NativeFusionJsonlLedgerAudit ledger_audit{};
    if (ledger && !ledger->Audit(&ledger_audit, &error)) {
        std::fprintf(stderr, "%s\n", error.c_str());
        std::string ignored;
        (void)source->Close(&ignored);
        (void)ledger->Close(&ignored);
        return 2;
    }
    const std::string receipt_path =
        options.at("output-dir") + "/receipt.json";
    if (!online_persistence_disabled) {
        json_t *running = minimal_running_receipt(
            options, ledger_audit, initial, metadata);
        const bool running_written = running != nullptr &&
            atomic_write_json(receipt_path, running, &error);
        if (running != nullptr)
            json_decref(running);
        if (!running_written) {
            std::fprintf(stderr, "%s\n", error.c_str());
            std::string ignored;
            (void)source->Close(&ignored);
            (void)ledger->Close(&ignored);
            return 2;
        }
    }

    flowkeep::NativeFusionServiceConfig service_config{};
    service_config.worker_count = static_cast<uint32_t>(service_workers);
    service_config.batch_capacity = static_cast<uint32_t>(batch_size);
    service_config.durable_commit_batch_capacity =
        static_cast<uint32_t>(durable_commit_batch_size);
    service_config.durable_commit_max_wait_ns =
        durable_commit_max_wait_us * 1000u;
    service_config.durable_commit_max_wait_age_anchor = parse_age_anchor(
        options.find("durable-commit-max-wait-age-anchor") == options.end()
        ? "physical_enqueue_monotonic_ns"
        : options.at("durable-commit-max-wait-age-anchor"));
    service_config.max_inflight = static_cast<uint32_t>(max_inflight);
    service_config.flow_state_capacity =
        static_cast<uint32_t>(flow_state_capacity);
    service_config.route_quantum = static_cast<uint32_t>(route_quantum);
    service_config.worker_batch_wait_ns = batch_wait_us * 1000u;
    service_config.idle_poll_ns = poll_us * 1000u;
    service_config.detector_deadline_ns = deadline_us * 1000u;
    service_config.detector_schedule = detector_schedule;
    service_config.retention_detector_coupling =
        flowkeep::NativeFusionRetentionDetectorCoupling::Decoupled;
    service_config.flow_open_scorer = flow_open_scorer.get();
    service_config.flow_open_threshold = flow_open_threshold;
    service_config.coordinator_cpu_set = coordinator_cpu_set;
    service_config.committer_cpu_set = committer_cpu_set;
    service_config.worker_cpu_sets = worker_cpu_sets;
    service_config.allow_test_only_durability =
        online_persistence_disabled;
    flowkeep::NativeFusionServiceReceipt service_receipt{};
    std::string run_error;
    (void)flowkeep::TargetDemandAudit::Get();
    (void)flowkeep::NaturalHistoryAudit::Get();
    const uint64_t service_process_cpu_start_ns = process_cpu_ns();
    bool run_success = flowkeep::RunNativeFusionService(
        source.get(), router.get(), scorers, online_committer, service_config,
        &service_receipt, &run_error);
    for(auto &store:persistent_stores)
        if(!store->FinishAsync()) {
            run_success=false;
            if(run_error.empty())run_error="history pipeline drain failed";
        }
    const uint64_t service_process_cpu_end_ns = process_cpu_ns();
    struct rusage timed_resource_usage{};
    if(getrusage(RUSAGE_SELF,&timed_resource_usage)!=0){std::fputs("timed RSS sampling failed\n",stderr);return 2;}
    const uint64_t service_timed_peak_rss_kib=static_cast<uint64_t>(timed_resource_usage.ru_maxrss);
    const uint64_t service_process_cpu_elapsed_ns =
        service_process_cpu_end_ns >= service_process_cpu_start_ns
        ? service_process_cpu_end_ns - service_process_cpu_start_ns : 0u;
    // All required writes completed before SHM source close. Read-only
    // verification is an evaluation step, not an early durability ACK.
    if(!flowkeep::NaturalHistoryAudit::Get().Save(options.at("output-dir")+"/natural_history.jsonl")) {
        std::fputs("natural history audit write failed\n",stderr);return 2;
    }
    if(!flowkeep::TargetDemandAudit::Get().Save(options.at("output-dir"),adaptive_config.prefix_versions.get())) {
        std::fputs("target demand audit failed\n",stderr);return 2;
    }
    bool selected_evidence_verified=true;
    std::string selected_error;
    if(selected_evidence) {
        selected_evidence_verified=selected_evidence->Verify(&selected_error);
        if(!selected_evidence_verified) {
            run_success=false;
            if(run_error.empty())run_error=selected_error;
        }
    }
    json_error_t selected_json_error{};
    json_t *selected_receipt=nullptr;
    try {
        selected_receipt=selected_evidence?
            json_loads(selected_evidence->ReceiptJson().c_str(),JSON_REJECT_DUPLICATES,&selected_json_error):
            json_pack("{s:s,s:s,s:b,s:b}","schema","flowkeep-selected-final-evidence-v1",
                "mode","off","enabled",0,"new_selected_evidence_saved",0);
    }catch(const std::exception &e){selected_error=e.what();}
    if(!selected_receipt || !atomic_write_json(options.at("output-dir")+"/selected_evidence_receipt.json",
            selected_receipt,&selected_error)) {
        run_success=false;
        if(run_error.empty())run_error=selected_error.empty()?"selected evidence receipt failed":selected_error;
    }
    if(selected_receipt)json_decref(selected_receipt);
    /* This export starts only after the timed online service and every
     * inference/history worker have stopped. It exists solely to reuse the
     * frozen accuracy evaluator and is excluded from online throughput. */
    if (online_persistence_disabled) {
        ledger = flowkeep::NativeFusionJsonlLedger::Create(
            ledger_config, &error);
        if (!ledger) {
            run_success = false;
            if (run_error.empty())
                run_error = error;
        } else {
            const auto &decisions = memory_committer->decisions();
            for (size_t offset = 0u; offset < decisions.size();) {
                const size_t count = std::min<size_t>(
                    5120u, decisions.size() - offset);
                flowkeep::NativeFusionCommitResult exported{};
                if (!ledger->CommitConsecutive(
                        decisions.data() + offset, count, &exported,
                        &error)) {
                    run_success = false;
                    if (run_error.empty())
                        run_error = error;
                    break;
                }
                offset += count;
            }
    }
    }
    std::string close_error;
    const bool ledger_closed = ledger && ledger->Close(&close_error);
    if (ledger && !ledger->Audit(&ledger_audit, &error)) {
        if (run_error.empty())
            run_error = error;
    }
    if (!ledger_closed && run_error.empty())
        run_error = ledger ? close_error :
            "post-timing evaluation ledger creation failed";

    json_t *terminal = final_receipt(options, service_receipt, ledger_audit,
        metadata, model_path, bundle_path, bundle_receipt_path,
        event_map_path, event_universe_path, assets_receipt_path,
        router_audit.entries, event_count,
        service_process_cpu_elapsed_ns,service_timed_peak_rss_kib,
        run_success && ledger_closed, run_error);
    json_t *h7=json_object();
    object_string(h7,"variant","H7_physical_NIC_integration_v1");
    object_bool(h7,"synchronous_wal_segments",ledger_audit.synchronous_wal_segments);
    object_u64(h7,"wal_segment_commits",ledger_audit.wal_segment_commits);
    object_u64(h7,"wal_write_calls",ledger_audit.wal_write_calls);
    object_u64(h7,"wal_group_writes",ledger_audit.wal_group_writes);
    object_u64(h7,"wal_max_group_segments",ledger_audit.wal_max_group_segments);
    object_u64(h7,"sync_wal_attested_commit_calls",service_receipt.sync_wal_attested_commit_calls);
    object_u64(h7,"wal_segment_bytes",ledger_audit.wal_segment_bytes);
    object_u64(h7,"wal_write_wall_ns",ledger_audit.wal_write_wall_ns);
    object_u64(h7,"wal_write_cpu_ns",ledger_audit.wal_write_cpu_ns);
    if(adaptive_config.prefix_versions) {
        const auto &v=*adaptive_config.prefix_versions;
        object_bool(h7,"recycling",v.RecyclingEnabled());
        object_bool(h7,"bulk_recycling",v.BulkRecyclingEnabled());
        object_u64(h7,"published_versions",v.Used());
        object_u64(h7,"slots_allocated",v.PayloadSlotsAllocated());
        object_u64(h7,"peak_live",v.PayloadsPeakLive());
        object_u64(h7,"live",v.PayloadsLive());
        object_u64(h7,"recycled",v.PayloadsRecycled());
        object_u64(h7,"late_discarded",v.LateDiscarded());
        object_u64(h7,"retired_identities",v.RetiredIdentities());
        object_u64(h7,"prefix_bytes",sizeof(flowkeep::PrefixVersionStore::Prefix));object_u64(h7,"identity_slots_allocated",adaptive_config.prefix_versions->IdentitySlotsAllocated());object_u64(h7,"identity_metadata_bytes_per_slot",flowkeep::PrefixVersionStore::IdentityMetadataBytesPerSlot());object_u64(h7,"pinned_metadata_bytes",flowkeep::PrefixVersionStore::PinnedMetadataBytes());
    }
    if(versioned_source) {
        object_u64(h7,"deferred_finalizations_enqueued",versioned_source->release_enqueued());
        object_u64(h7,"deferred_finalizations_completed",versioned_source->release_completed());
        object_u64(h7,"finalization_capacity_deferrals",versioned_source->release_deferrals());
        object_u64(h7,"peak_deferred_finalizations",versioned_source->release_peak());
        object_u64(h7,"finalization_coordinator_work_ns",versioned_source->release_work_ns());
        object_string(h7,"candidate_variant","H8_deferred_finalization_group4_lossless_selected_v3");
    }
    json_object_set_new(terminal,"h7_online",h7);
    const auto append_coverage_receipt = [&](const auto *coverage_source) {
        json_t *coverage = json_object();
        object_string(coverage,"protocol","flowkeep-native-eof-coverage-v2");
        if(versioned_source)object_string(coverage,"protocol","flowkeep-native-versioned-coverage-v1");
        object_string(coverage,"trigger","marginal-current-score-final-or-pending-next-dirty-eof");
        object_bool(coverage,"terminal_inference_may_overlap_physical_commit",true);
        object_string(coverage,"semantic_trigger_clock",versioned_source?
            "original_observation_clock_with_verified_input_eof_version_frontier":
            "last_emitted_request_watermark_not_last_packet_time");
        object_string(coverage,"event_scope","one tuple/event; STOP or packet20 finalizes the current score, pending NEXT ending early scores the last real prefix");
        object_bool(coverage,"formal_training_eligible",false);
        object_bool(coverage,"ordinary_checkpoints_unchanged",true);
        object_bool(coverage,"producer_visible_ack_includes_terminal_suffix",false);
        object_bool(coverage,"continuous_stream_terminal_detection_supported",false);
        object_bool(coverage,"joint_evidence_scheduling",adaptive_config.evidence_feedback!=nullptr);
        object_bool(coverage,"sparse_prefix_transport",sparse_prefixes!=nullptr);
        object_bool(coverage,"versioned_selected_observations",versioned_source!=nullptr);
        object_bool(coverage,"independent_event_clocks",versioned_source!=nullptr);
        object_u64(coverage,"prefix_version_shared_bytes",adaptive_config.prefix_versions?flowkeep::PrefixVersionStore::Bytes():0);
        object_u64(coverage,"prefix_versions_used",adaptive_config.prefix_versions?adaptive_config.prefix_versions->Used():0);
        if(versioned_source)object_u64(coverage,"selected_observation_records",versioned_source->selected_records());
        if(versioned_source) {
            const auto &s=versioned_source->ready_stats();json_t *ready=json_object();
            object_string(ready,"protocol","coalesced-prefix-and-feedback-notifications-v1");
            object_bool(ready,"top_bitmap",adaptive_config.prefix_versions->ReadyTopEnabled());
            object_bool(ready,"bulk_feature_validation",flowkeep::FeatureValidationMode()==1);
            object_u64(ready,"peek_calls",s.peek_calls);object_u64(ready,"ready_checks",s.ready_checks);
            object_u64(ready,"prefix_notifications",s.prefix_notifications);
            object_u64(ready,"feedback_notifications",s.feedback_notifications);
            object_u64(ready,"notification_scratch_calls",s.notification_scratch_calls);
            object_u64(ready,"prefix_parks",s.prefix_parks);object_u64(ready,"feedback_parks",s.feedback_parks);
            object_u64(ready,"unresolved_retries",s.unresolved_retries);object_u64(ready,"empty_peeks",s.empty_peeks);
            json_object_set_new(coverage,"readiness",ready);
        }
        object_u64(coverage,"sparse_prefix_shared_bytes",sparse_prefixes?flowkeep::SparsePrefixChannel::Bytes():0);
        object_u64(coverage,"sparse_terminal_snapshots",coverage_source->sparse_terminal_snapshots());
        if(adaptive_config.evidence_feedback) {
            object_u64(coverage,"gain_feedback_publications",adaptive_config.evidence_feedback->Published());
            object_u64(coverage,"gain_feedback_shared_bytes",flowkeep::EvidenceGainChannel::Bytes());
        }
        object_u64(coverage,"physical_shm_records",coverage_source->physical_records());
        object_u64(coverage,"physical_shm_records_acked",coverage_source->physical_acked());
        object_u64(coverage,"terminal_records",coverage_source->terminal_records());
        object_u64(coverage,"terminal_records_acked",coverage_source->terminal_acked());
        object_u64(coverage,"current_score_eof_finalizations",
            coverage_source->current_score_finalizations());
        object_u64(coverage,"dirty_eof_model_calls",
            coverage_source->terminal_records());
        object_u64(coverage,"total_eof_finalizations",
            coverage_source->current_score_finalizations()+
            coverage_source->terminal_records());
        object_u64(coverage,"producer_eof_monotonic_ns",coverage_source->eof_monotonic_ns());
        object_u64(coverage,"last_request_semantic_watermark_ns",coverage_source->request_watermark_ns());
        object_u64(coverage,"preallocated_prefix_payload_bytes",coverage_source->payload_bytes());
        object_u64(coverage,"preallocated_metadata_vector_bytes",coverage_source->metadata_vector_bytes());
        object_string(coverage,"memory_scope","ordinary memory; hash/deque/allocator and in-flight shared prefix accounted by process RSS; not RX64MiB");
        const auto &stats=coverage_source->stats();
        object_u64(coverage,"deposits",stats.reserved);
        object_u64(coverage,"primary_superseded",stats.superseded);
        object_u64(coverage,"coverage_persisted",stats.coverage_committed);
        object_u64(coverage,"released_after_ack",stats.released);
        object_u64(coverage,"peak_live_prefixes",stats.peak_live);
        object_u64(coverage,"live_prefixes_at_close",stats.live);
        object_u64(coverage,"rejections",stats.rejected);
        json_object_set_new(terminal,"terminal_coverage",coverage);
        object_bool(terminal,"formal_training_eligible",false);
    };
    if(terminal && coverage_source)append_coverage_receipt(coverage_source);
    if(terminal && versioned_source)append_coverage_receipt(versioned_source);
    if(terminal && !persistent_stores.empty()) {
        json_t *profile=json_object(),*workers=json_array();
        object_string(profile,"scope","history_sync_write_background_or_gc_fence_excludes_open_prefetch_preparation");
        object_bool(profile,"included_in_batch_inference_latency",false);
        object_bool(profile,"bounded_submission_and_gc_fence_included_in_inference_latency",true);
        object_string(profile,"submission_contract","bounded_async_sync_wal_history_fence_v1");
        object_bool(profile,"ack_requires_history_fence",true);
        object_bool(profile,"writer_inherits_worker_cpu_affinity",true);
        object_string(profile,"memory_accounting","per_worker_charged_payload_overlay_allowance_cap; merge_and_submission_scratch_bounded_separately; not_process_RSS_cap");
        object_bool(profile,"worker_durations_overlap",true);
        object_bool(profile,"sync_wal_unchanged",true);
        for(size_t index=0;index<persistent_stores.size();++index) {
            const auto &store=*persistent_stores[index];json_t *row=json_object();
            object_u64(row,"worker",index);
            object_u64(row,"write_calls",store.commit_write_calls());
            object_u64(row,"write_failures",store.commit_write_failures());
            object_u64(row,"write_ns",store.commit_write_ns());
            object_u64(row,"maximum_write_ns",store.maximum_commit_write_ns());
            object_u64(row,"submitted_batches",store.submitted_batches());
            object_u64(row,"maximum_merged_batches",store.maximum_merged_batches());
            object_u64(row,"maximum_outstanding_charge_bytes",store.maximum_outstanding_charge_bytes());
            object_u64(row,"maximum_outstanding_batches",store.maximum_outstanding_batches());
            object_u64(row,"maximum_charge_bytes",store.maximum_charge_bytes());
            object_u64(row,"maximum_batches",store.maximum_batches());
            object_u64(row,"submission_wait_ns",store.submission_wait_ns());
            object_u64(row,"gc_fenced_batches",store.gc_fenced_batches());
            object_u64(row,"wal_write_ns_includes_sync",store.wal_write_ns());
            object_u64(row,"io_fsync_ns_nested_in_wal",store.io_fsync_ns());
            object_u64(row,"memtable_write_ns",store.memtable_write_ns());
            object_u64(row,"write_delay_ns",store.write_delay_ns());
            object_u64(row,"write_thread_wait_ns",store.write_thread_wait_ns());
            json_array_append_new(workers,row);
        }
        json_object_set_new(profile,"workers",workers);
        json_object_set_new(terminal,"persistent_history_write_profile",profile);
    }
    if (terminal) {
        json_t *trace=json_object(),*rows=json_array(),*score_profile=json_array();
        object_string(trace,"protocol","flowkeep-prepare-publish-trace-v1");
        object_u64(trace,"capacity",4096u);
        object_u64(trace,"dropped",service_receipt.commit_trace_dropped);
        object_string(trace,"phase_cost_protocol","thread-cpu-offcpu-v1");
        object_string(trace,"off_cpu_scope","blocking_plus_runnable_wait_not_disk_latency");
        const auto cost=[](const flowkeep::ThreadPhaseTiming &p) {
            json_t *v=json_object();object_bool(v,"valid",p.valid);
            object_u64(v,"started_ns",p.started_ns);object_u64(v,"finished_ns",p.finished_ns);
            object_u64(v,"cpu_ns",p.cpu_ns);object_u64(v,"off_cpu_ns",p.off_cpu_ns);
            object_u64(v,"voluntary_switches",p.voluntary_switches);
            object_u64(v,"involuntary_switches",p.involuntary_switches);return v;
        };
        json_object_set_new(trace,"coordinator_fence_to_source_done",cost(service_receipt.coordinator_fence_to_source_done));
        json_object_set_new(trace,"coordinator_source_done_to_drained",cost(service_receipt.coordinator_source_done_to_drained));
        json_t *waits=json_object();
        object_string(waits,"scope","exclusive_state_at_wait_entry_not_causal_offcpu_attribution");
        const char *reasons[]={"source_readiness","scorer_outstanding","commit_slots_full","batch_coalescing","durable_drain"};
        for(unsigned i=0;i<5;++i) {
            json_t *row=json_object();object_u64(row,"calls",service_receipt.coordinator_wait_calls[i]);
            object_u64(row,"wall_ns",service_receipt.coordinator_wait_ns[i]);
            object_u64(row,"fence_to_source_done_wall_ns",service_receipt.coordinator_fence_wait_ns[i]);
            json_object_set_new(waits,reasons[i],row);
        }
        object_u64(waits,"notified_wakes",service_receipt.coordinator_notified_wakes);
        object_u64(waits,"timeout_wakes",service_receipt.coordinator_timeout_wakes);
        json_object_set_new(trace,"coordinator_wait_states",waits);
        const auto trace_row=[&cost](const flowkeep::NativeFusionCommitTrace &t) {
            json_t *row=json_object();
            object_u64(row,"first_sequence",t.first_sequence);
            object_u64(row,"last_sequence",t.last_sequence);
            object_u64(row,"oldest_sequence",t.oldest_sequence);
            object_u64(row,"oldest_enqueue_ns",t.oldest_enqueue_ns);
            object_u64(row,"oldest_decision_ns",t.oldest_decision_ns);
            object_u64(row,"last_decision_ns",t.last_decision_ns);
            object_u64(row,"submitted_ns",t.submitted_ns);
            object_u64(row,"prepare_started_ns",t.prepare_started_ns);
            object_u64(row,"prepare_finished_ns",t.prepare_finished_ns);
            object_u64(row,"history_started_ns",t.history_started_ns);
            object_u64(row,"history_finished_ns",t.history_finished_ns);
            object_u64(row,"publish_started_ns",t.publish_started_ns);
            object_u64(row,"publish_finished_ns",t.publish_finished_ns);
            object_u64(row,"ack_ns",t.ack_ns);
            json_t *costs=json_object();
            json_object_set_new(costs,"prepare",cost(t.prepare_cost));
            json_object_set_new(costs,"history",cost(t.history_cost));
            json_object_set_new(costs,"publish",cost(t.publish_cost));
            json_object_set_new(costs,"serialize",cost(t.serialize_cost));
            json_object_set_new(costs,"compression",cost(t.compression_cost));
            json_object_set_new(costs,"state",cost(t.state_cost));
            json_object_set_new(costs,"file_sync",cost(t.file_sync_cost));
            json_object_set_new(costs,"directory_sync",cost(t.directory_sync_cost));
            json_object_set_new(row,"phase_costs",costs);
            return row;
        };
        for(const auto &t:service_receipt.commit_trace)json_array_append_new(rows,trace_row(t));
        json_object_set_new(trace,"batches",rows);
        json_object_set_new(trace,"slowest_ack",trace_row(service_receipt.slowest_ack_trace));
        json_object_set_new(terminal,"commit_pipeline_trace",trace);
        const char *names[]={"validate_resize_ns","seven_head_wall_ns","history_fold_ns","meta_fusion_ns","history_submit_and_latch_ns"};
        for(size_t i=0;i<scorer_storage.size();++i) {
            fk_native_fusion_phase_profile p{};json_t *row=json_object(),*heads=json_array();
            object_u64(row,"worker",i);
            object_bool(row,"profile_valid",scorer_storage[i]->PhaseProfile(&p));
            object_u64(row,"batches",p.batches);object_u64(row,"rows",p.rows);
            object_u64(row,"context_prepare_ns",scorer_storage[i]->ContextPrepareNs());
            object_u64(row,"context_clear_ns",scorer_storage[i]->ContextClearNs());
            object_u64(row,"candidate_rows",scorer_storage[i]->CandidateRows());
            object_u64(row,"actual_model_calls",scorer_storage[i]->ActualModelCalls());
            object_u64(row,"synthetic_candidate_rows",scorer_storage[i]->SyntheticRows());
            for(size_t k=0;k<5;++k)object_u64(row,names[k],p.phase_ns[k]);
            for(auto ns:p.head_thread_ns)json_array_append_new(heads,json_integer(ns));
            json_object_set_new(row,"head_thread_wall_ns_sum_nonadditive",heads);
            object_u64(row,"meta_cache_hits",p.meta_cache_hits);
            object_u64(row,"meta_cache_misses",p.meta_cache_misses);
            json_array_append_new(score_profile,row);
        }
        json_object_set_new(terminal,"scoring_phase_profile",score_profile);
    }
    bool terminal_written = terminal != nullptr &&
        atomic_write_json(receipt_path, terminal, &error);
    bool ready = false;
    if (terminal != nullptr) {
        const json_t *status = json_object_get(terminal, "status");
        ready = json_is_string(status) &&
            std::strcmp(json_string_value(status), "COMPLETE") == 0;
        char *rendered = json_dumps(terminal, JSON_COMPACT | JSON_SORT_KEYS);
        if (rendered != nullptr) {
            std::printf("%s\n", rendered);
            std::free(rendered);
        }
        json_decref(terminal);
    }
    if (!terminal_written) {
        std::fprintf(stderr, "%s\n", error.c_str());
        return 2;
    }
    return ready ? 0 : 2;
}
