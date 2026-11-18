#include "fk_native_fusion_jsonl_ledger.h"
#include "fk_native_prefix_hex.h"

#include <algorithm>
#include <array>
#include <atomic>
#include <arpa/inet.h>
#include <charconv>
#include <cerrno>
#include <cmath>
#include <cstdio>
#include <cstring>
#include <dirent.h>
#include <fcntl.h>
#include <limits>
#include <experimental/memory_resource>
#include <experimental/unordered_map>
#include <new>
#include <mutex>
#include <openssl/evp.h>
#include <string>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
#include <unordered_map>
#include <utility>
#include <vector>
#include <zstd.h>
#include <rocksdb/db.h>
#include <rocksdb/write_batch.h>
#include <rocksdb/cache.h>
#include <rocksdb/table.h>

namespace flowkeep {
namespace {

constexpr const char *kLedgerProtocol =
    "flowkeep-atomic-decision-segment-ledger-v6";
constexpr const char *kLedgerProtocolFlowOpen =
    "flowkeep-atomic-decision-segment-ledger-v7";
constexpr const char *kDecisionProtocol =
    "flowkeep-live-seven-state-decision-v4";
constexpr const char *kDecisionProtocolFlowOpen =
    "flowkeep-live-seven-state-decision-v5";
constexpr const char *kSegmentNaming =
    "decision_segments/segment_%08d.jsonl.zst";
constexpr const char *kChainFormula =
    "sha256(previous_chain_hex || segment_sha256_hex || row_count_u64_le)";
constexpr int kZstdCompressionLevel = 1;

/*
 * Keep the durable semantic index allocation-free.  The former index used a
 * rendered "five-tuple|logical=N" std::string as both the lookup key and the
 * long-lived map key.  Real contains about 0.48M semantic presentation keys,
 * so that representation made every durable batch allocate, hash, and retain
 * another copy of text that is already rendered separately for JSONL.  This
 * fixed key preserves the exact same identity while avoiding that hot-path
 * string churn.
 */
struct SemanticKey {
    fk_flow_key flow{};
    uint64_t logical_connection_id = 0u;
    uint64_t flow_first_timestamp_ns = 0u;
};

struct SemanticKeyEqual {
    bool operator()(const SemanticKey &left,
            const SemanticKey &right) const noexcept {
        if (left.logical_connection_id != right.logical_connection_id ||
            left.flow_first_timestamp_ns !=
                right.flow_first_timestamp_ns ||
            left.flow.ip_version != right.flow.ip_version ||
            left.flow.protocol != right.flow.protocol ||
            left.flow.low_port != right.flow.low_port ||
            left.flow.high_port != right.flow.high_port) {
            return false;
        }
        const size_t address_bytes =
            left.flow.ip_version == 4u ? 4u : 16u;
        return std::memcmp(left.flow.low_addr, right.flow.low_addr,
                address_bytes) == 0 &&
            std::memcmp(left.flow.high_addr, right.flow.high_addr,
                address_bytes) == 0;
    }
};

struct SemanticKeyHash {
    size_t operator()(const SemanticKey &key) const noexcept {
        uint64_t hash = UINT64_C(1469598103934665603);
        const auto mix = [&hash](const void *data, size_t bytes) {
            const auto *input = static_cast<const uint8_t *>(data);
            for (size_t index = 0u; index < bytes; ++index) {
                hash ^= input[index];
                hash *= UINT64_C(1099511628211);
            }
        };
        mix(&key.flow.ip_version, sizeof(key.flow.ip_version));
        mix(&key.flow.protocol, sizeof(key.flow.protocol));
        const size_t address_bytes = key.flow.ip_version == 4u ? 4u : 16u;
        mix(key.flow.low_addr, address_bytes);
        mix(key.flow.high_addr, address_bytes);
        mix(&key.flow.low_port, sizeof(key.flow.low_port));
        mix(&key.flow.high_port, sizeof(key.flow.high_port));
        mix(&key.logical_connection_id, sizeof(key.logical_connection_id));
        mix(&key.flow_first_timestamp_ns,
            sizeof(key.flow_first_timestamp_ns));
        /* MurmurHash3 finalizer prevents structured address/port suffixes
         * from concentrating buckets after the byte-wise identity hash. */
        hash ^= hash >> 33u;
        hash *= UINT64_C(0xff51afd7ed558ccd);
        hash ^= hash >> 33u;
        hash *= UINT64_C(0xc4ceb9fe1a85ec53);
        hash ^= hash >> 33u;
        return static_cast<size_t>(hash);
    }
};

/* GCC 10's C++14 PMR implementation provides polymorphic allocators but not
 * monotonic_buffer_resource.  This commit-local bump resource supplies the
 * missing behavior and delegates only an unexpectedly oversized allocation
 * to the standard upstream resource. */
class PendingMemoryResource final
        : public std::experimental::pmr::memory_resource {
public:
    PendingMemoryResource(void *storage, size_t bytes) noexcept
        : current_(static_cast<unsigned char *>(storage)),
          remaining_(bytes),
          begin_(reinterpret_cast<uintptr_t>(storage)),
          end_(begin_ + bytes),
          upstream_(std::experimental::pmr::new_delete_resource()) {}

private:
    void *do_allocate(size_t bytes, size_t alignment) override {
        void *candidate = current_;
        size_t space = remaining_;
        if (std::align(alignment, bytes, candidate, space) != nullptr) {
            current_ = static_cast<unsigned char *>(candidate) + bytes;
            remaining_ = space - bytes;
            return candidate;
        }
        return upstream_->allocate(bytes, alignment);
    }

    void do_deallocate(
            void *pointer, size_t bytes, size_t alignment) override {
        const auto *value = static_cast<unsigned char *>(pointer);
        const uintptr_t address = reinterpret_cast<uintptr_t>(value);
        if (address < begin_ || address >= end_)
            upstream_->deallocate(pointer, bytes, alignment);
    }

    bool do_is_equal(
            const std::experimental::pmr::memory_resource &other)
            const noexcept override {
        return this == &other;
    }

    unsigned char *current_;
    size_t remaining_;
    uintptr_t begin_;
    uintptr_t end_;
    std::experimental::pmr::memory_resource *upstream_;
};

uint64_t monotonic_ns() {
    timespec value{};
    if (::clock_gettime(CLOCK_MONOTONIC, &value) != 0 ||
        value.tv_sec < 0 || value.tv_nsec < 0 ||
        value.tv_nsec >= 1000000000L) {
        return 0u;
    }
    return static_cast<uint64_t>(value.tv_sec) * UINT64_C(1000000000) +
        static_cast<uint64_t>(value.tv_nsec);
}

void set_error(std::string *output, const char *message) {
    if (output != nullptr) {
        try {
            *output = message;
        } catch (...) {
        }
    }
}

void set_error(std::string *output, const std::string &message) {
    if (output != nullptr) {
        try {
            *output = message;
        } catch (...) {
        }
    }
}

bool write_all(int fd, const void *payload, size_t payload_bytes) {
    const auto *bytes = static_cast<const char *>(payload);
    size_t offset = 0u;
    while (offset < payload_bytes) {
        const ssize_t written = ::write(
            fd, bytes + offset, payload_bytes - offset);
        if (written < 0) {
            if (errno == EINTR)
                continue;
            return false;
        }
        if (written == 0)
            return false;
        offset += static_cast<size_t>(written);
    }
    return true;
}

bool write_all(int fd, const std::string &payload) {
    return write_all(fd, payload.data(), payload.size());
}

std::string parent_path(const std::string &path) {
    const size_t slash = path.find_last_of('/');
    if (slash == std::string::npos)
        return ".";
    if (slash == 0u)
        return "/";
    return path.substr(0u, slash);
}

bool fsync_directory(const std::string &path) {
    const int fd = ::open(path.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC |
        O_NOFOLLOW);
    if (fd < 0)
        return false;
    const bool success = ::fsync(fd) == 0;
    const bool closed = ::close(fd) == 0;
    return success && closed;
}

uint64_t elapsed_ns(uint64_t started, uint64_t finished) {
    return started != 0u && finished >= started ? finished - started : 0u;
}

void accumulate_timing(
        uint64_t value, uint64_t &total, uint64_t &maximum) {
    total = value > UINT64_MAX - total ? UINT64_MAX : total + value;
    maximum = std::max(maximum, value);
}

bool path_absent(const std::string &path) {
    struct stat status{};
    if (::lstat(path.c_str(), &status) == 0)
        return false;
    return errno == ENOENT;
}

bool exact_directory(const std::string &path) {
    struct stat status{};
    struct stat followed{};
    return ::lstat(path.c_str(), &status) == 0 && S_ISDIR(status.st_mode) &&
        !S_ISLNK(status.st_mode) && ::stat(path.c_str(), &followed) == 0 &&
        status.st_dev == followed.st_dev && status.st_ino == followed.st_ino;
}

bool directory_empty(const std::string &path) {
    DIR *directory = ::opendir(path.c_str());
    if (directory == nullptr)
        return false;
    bool empty = true;
    errno = 0;
    while (dirent *entry = ::readdir(directory)) {
        if (std::strcmp(entry->d_name, ".") != 0 &&
            std::strcmp(entry->d_name, "..") != 0) {
            empty = false;
            break;
        }
    }
    const bool read_ok = errno == 0;
    const bool close_ok = ::closedir(directory) == 0;
    return empty && read_ok && close_ok;
}

bool lowercase_uuid(const std::string &value) {
    if (value.size() != 32u)
        return false;
    for (char character : value) {
        if (!((character >= '0' && character <= '9') ||
              (character >= 'a' && character <= 'f'))) {
            return false;
        }
    }
    return true;
}

bool safe_event_id(const std::string &value) {
    if (value.empty() || value.size() > 4096u)
        return false;
    for (unsigned char character : value) {
        if (character == 0u || character == '\n' || character == '\r')
            return false;
    }
    return true;
}

void append_json_string(std::string &output, const std::string &value) {
    static const char hex[] = "0123456789abcdef";
    output.push_back('"');
    size_t span=0;
    for (size_t i=0;i<value.size();++i) {
        const auto character=static_cast<unsigned char>(value[i]);
        if(character>=0x20u && character!='"' && character!='\\')continue;
        output.append(value.data()+span,i-span);
        span=i+1;
        switch (character) {
        case '"': output.append("\\\""); break;
        case '\\': output.append("\\\\"); break;
        case '\b': output.append("\\b"); break;
        case '\f': output.append("\\f"); break;
        case '\n': output.append("\\n"); break;
        case '\r': output.append("\\r"); break;
        case '\t': output.append("\\t"); break;
        default:
            if (character < 0x20u) {
                output.append("\\u00");
                output.push_back(hex[character >> 4u]);
                output.push_back(hex[character & 0x0fu]);
            } else {
                output.push_back(static_cast<char>(character));
            }
        }
    }
    output.append(value.data()+span,value.size()-span);
    output.push_back('"');
}

void append_u64(std::string &output, uint64_t value) {
    char buffer[32];
    const auto converted = std::to_chars(
        buffer, buffer + sizeof(buffer), value);
    if (converted.ec == std::errc{})
        output.append(buffer, static_cast<size_t>(converted.ptr - buffer));
}

void append_u32(std::string &output, uint32_t value) {
    append_u64(output, value);
}

bool append_double(std::string &output, double value) {
    if (!std::isfinite(value))
        return false;
    char buffer[64];
    const int length = std::snprintf(buffer, sizeof(buffer), "%.17g", value);
    if (length <= 0 || static_cast<size_t>(length) >= sizeof(buffer))
        return false;
    output.append(buffer, static_cast<size_t>(length));
    return true;
}

bool sha256_hex(const void *data, size_t bytes, std::string *hex) {
    if (data == nullptr || hex == nullptr)
        return false;
    EVP_MD_CTX *context = EVP_MD_CTX_new();
    if (context == nullptr)
        return false;
    unsigned char digest[EVP_MAX_MD_SIZE]{};
    unsigned int digest_bytes = 0u;
    const bool success = EVP_DigestInit_ex(
            context, EVP_sha256(), nullptr) == 1 &&
        EVP_DigestUpdate(context, data, bytes) == 1 &&
        EVP_DigestFinal_ex(context, digest, &digest_bytes) == 1 &&
        digest_bytes == 32u;
    EVP_MD_CTX_free(context);
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

bool chain_sha256(
        const std::string &previous,
        const std::string &segment,
        uint64_t rows,
        std::string *output) {
    if (previous.size() != 64u || segment.size() != 64u)
        return false;
    unsigned char count[8];
    for (size_t index = 0u; index < 8u; ++index)
        count[index] = static_cast<unsigned char>(rows >> (index * 8u));
    EVP_MD_CTX *context = EVP_MD_CTX_new();
    if (context == nullptr)
        return false;
    unsigned char digest[EVP_MAX_MD_SIZE]{};
    unsigned int digest_bytes = 0u;
    const bool success = EVP_DigestInit_ex(
            context, EVP_sha256(), nullptr) == 1 &&
        EVP_DigestUpdate(context, previous.data(), previous.size()) == 1 &&
        EVP_DigestUpdate(context, segment.data(), segment.size()) == 1 &&
        EVP_DigestUpdate(context, count, sizeof(count)) == 1 &&
        EVP_DigestFinal_ex(context, digest, &digest_bytes) == 1 &&
        digest_bytes == 32u;
    EVP_MD_CTX_free(context);
    if (!success)
        return false;
    static const char alphabet[] = "0123456789abcdef";
    try {
        output->resize(64u);
    } catch (...) {
        return false;
    }
    for (size_t index = 0u; index < 32u; ++index) {
        (*output)[index * 2u] = alphabet[digest[index] >> 4u];
        (*output)[index * 2u + 1u] = alphabet[digest[index] & 0x0fu];
    }
    return true;
}

bool zstd_level_one(
        ZSTD_CCtx *context,
        const std::string &input,
        std::vector<char> *scratch,
        size_t *compressed_bytes,
        std::string *error) {
    if (context == nullptr || scratch == nullptr ||
        compressed_bytes == nullptr) {
        set_error(error, "zstd compressor state is null");
        return false;
    }
    const bool configured =
        !::ZSTD_isError(::ZSTD_CCtx_reset(
            context, ZSTD_reset_session_only)) &&
        !::ZSTD_isError(::ZSTD_CCtx_setPledgedSrcSize(
            context, static_cast<unsigned long long>(input.size())));
    if (!configured) {
        set_error(error, "zstd deterministic frame setup failed");
        return false;
    }
    const size_t bound = ::ZSTD_compressBound(input.size());
    if (bound == 0u || ::ZSTD_isError(bound)) {
        set_error(error, "zstd output bound is invalid");
        return false;
    }
    if (scratch->size() < bound)
        scratch->resize(bound);
    const size_t compressed = ::ZSTD_compress2(
        context, scratch->data(), scratch->size(),
        input.data(), input.size());
    if (::ZSTD_isError(compressed) || compressed == 0u ||
        compressed > scratch->size()) {
        set_error(error, "zstd compression failed");
        return false;
    }
    *compressed_bytes = compressed;
    return true;
}

bool append_flow_key_json_string(
        std::string &output, const fk_flow_key &key) {
    char low[INET6_ADDRSTRLEN]{};
    char high[INET6_ADDRSTRLEN]{};
    if ((key.ip_version != 4u && key.ip_version != 6u) ||
        (key.protocol != 6u && key.protocol != 17u)) {
        return false;
    }
    if (key.ip_version == 6u &&
        (::inet_ntop(AF_INET6, key.low_addr, low, sizeof(low)) == nullptr ||
         ::inet_ntop(AF_INET6, key.high_addr, high, sizeof(high)) ==
             nullptr)) {
        return false;
    }
    output.push_back('"');
    output.append(key.protocol == 6u ? "6|" : "17|");
    if (key.ip_version == 4u) {
        for (size_t index = 0u; index < 4u; ++index) {
            if (index != 0u)
                output.push_back('.');
            append_u32(output, key.low_addr[index]);
        }
    } else {
        output.append(low);
    }
    output.push_back(':');
    append_u32(output, key.low_port);
    output.push_back('|');
    if (key.ip_version == 4u) {
        for (size_t index = 0u; index < 4u; ++index) {
            if (index != 0u)
                output.push_back('.');
            append_u32(output, key.high_addr[index]);
        }
    } else {
        output.append(high);
    }
    output.push_back(':');
    append_u32(output, key.high_port);
    output.push_back('"');
    return true;
}

}  // namespace

struct NativeFusionJsonlLedger::Implementation {
    enum class PublishKind : uint8_t {
        Segment = 1u,
        InitialManifest = 2u,
        ClosureManifest = 3u,
    };

    struct EventState {
        const std::string *event_id = nullptr;
        uint64_t flow_opens = 0u;
        uint64_t flow_continues = 0u;
        uint64_t updates = 0u;
        uint64_t last_observation_ns = 0u;
        bool has_observation = false;
        bool alert_latched = false;
    };

    struct SemanticChainState {
        uint64_t event_token = 0u;
        uint64_t flow_first_timestamp_ns = 0u;
        uint32_t flow_index = 0u;
        uint32_t flow_generation = 0u;
        uint32_t last_checkpoint_packet = 0u;
    };

    struct PublishTiming {
        uint64_t open_ns = 0u;
        uint64_t write_ns = 0u;
        uint64_t file_fsync_ns = 0u;
        uint64_t publish_ns = 0u;
        uint64_t directory_fsync_ns = 0u;
        ThreadPhaseTiming file_sync_cost,directory_sync_cost;
    };

    struct StagedAccounting {
        std::atomic<uint64_t> files{0},bytes{0},peak_files{0},peak_bytes{0};
        static void Maximum(std::atomic<uint64_t> &peak,uint64_t value) noexcept {
            auto prior=peak.load(std::memory_order_relaxed);
            while(prior<value && !peak.compare_exchange_weak(prior,value,std::memory_order_relaxed)){}
        }
        void Add(uint64_t n) noexcept {
            Maximum(peak_files,files.fetch_add(1,std::memory_order_relaxed)+1);
            Maximum(peak_bytes,bytes.fetch_add(n,std::memory_order_relaxed)+n);
        }
        void Remove(uint64_t n) noexcept {
            files.fetch_sub(1,std::memory_order_relaxed);bytes.fetch_sub(n,std::memory_order_relaxed);
        }
    };

    struct Prepared final : NativeFusionPreparedCommit {
        Implementation *owner = nullptr;
        uint64_t segment_index = 0, first = 0, last = 0, rows = 0, total_rows = 0;
        uint64_t first_ever = 0, raw_bytes = 0, last_decision_ns = 0;
        uint64_t validate_ns = 0, compression_ns = 0, prepare_ns = 0;
        ThreadPhaseTiming serialize_cost,compression_cost,state_cost;
        std::string bytes, chain, manifest, name;
        bool raw_payload=false;
        std::string staged_temporary;
        PublishTiming staged_timing;
        bool staged_ready=false;
        // Independent ownership permits a cancelled Prepared to outlive its
        // ledger without dereferencing a destroyed Implementation.
        std::shared_ptr<StagedAccounting> staged_accounting;
        uint64_t staged_charge=0;
        void ReleaseStagedAccounting() noexcept {
            if(staged_accounting){staged_accounting->Remove(staged_charge);staged_accounting.reset();}
        }
        ~Prepared() override {
            if(!staged_temporary.empty())(void)::unlink(staged_temporary.c_str());
            ReleaseStagedAccounting();
        }
    };
    // Preparation owns semantic maps and staged counters; publication owns
    // durable counters/manifest. Audit and Close require both threads joined.
    std::atomic<uint64_t> durable_segments{0};
    uint64_t durable_decisions = 0, durable_first = 0, durable_last = 0;
    std::string durable_chain = std::string(64u, '0'), durable_manifest;
    NativeFusionJsonlLedgerConfig config;
    bool compression_deferred=false; // preparation thread owns transition
    ZSTD_CCtx *zstd_context = nullptr;
    std::vector<char> zstd_scratch;
    std::string commit_payload_scratch;
    // One bounded spare, exchanged only after compression has consumed the
    // immutable raw job. Preparation and publication never share its bytes.
    std::mutex payload_spare_mutex;
    std::string payload_spare;
    uint64_t payload_buffer_moves=0, payload_buffer_moved_bytes=0;
    uint64_t payload_buffer_reuse_hits=0; // preparation-thread counters
    std::shared_ptr<StagedAccounting> staged_accounting;
    uint64_t staged_segments_prepared=0; // preparation-thread counter
    uint64_t staged_records_prepared=0,staged_payload_bytes_prepared=0;
    uint64_t staged_publish_calls=0,staged_publish_succeeded=0; // publication-thread counters
    std::vector<unsigned char> commit_pending_arena_scratch;
    std::string segment_directory;
    std::string manifest_path;
    std::string lock_path;
    int lock_fd = -1;
    std::unique_ptr<rocksdb::DB> wal_db;
    uint64_t wal_write_calls=0,wal_segment_bytes=0,wal_write_wall_ns=0,wal_write_cpu_ns=0;
    uint64_t wal_segment_commits=0,wal_group_writes=0,wal_max_group_segments=0;
    /* The segment directory never changes during a run.  Reusing this exact
     * descriptor removes an open/close pair from every durable batch while
     * preserving the same directory fsync before ACK. */
    int segment_directory_fd = -1;
    uint64_t segments = 0u;
    uint64_t decisions = 0u;
    uint64_t first_sequence = 0u;
    uint64_t last_sequence = 0u;
    uint64_t segment_fsync_calls = 0u;
    uint64_t segment_directory_fsync_calls = 0u;
    uint64_t manifest_fsync_calls = 0u;
    uint64_t initial_manifest_fsync_calls = 0u;
    uint64_t commit_manifest_fsync_calls = 0u;
    uint64_t closure_manifest_fsync_calls = 0u;
    uint64_t directory_fsync_calls = 0u;
    uint64_t bytes_committed = 0u;
    uint64_t uncompressed_bytes_committed = 0u;
    uint64_t validate_serialize_total_ns = 0u;
    uint64_t validate_serialize_max_ns = 0u;
    uint64_t compression_total_ns = 0u;
    uint64_t compression_max_ns = 0u;
    uint64_t prepare_state_total_ns = 0u;
    uint64_t prepare_state_max_ns = 0u;
    uint64_t segment_open_total_ns = 0u;
    uint64_t segment_open_max_ns = 0u;
    uint64_t segment_write_total_ns = 0u;
    uint64_t segment_write_max_ns = 0u;
    uint64_t segment_file_fsync_total_ns = 0u;
    uint64_t segment_file_fsync_max_ns = 0u;
    uint64_t segment_publish_total_ns = 0u;
    uint64_t segment_publish_max_ns = 0u;
    uint64_t segment_directory_fsync_total_ns = 0u;
    uint64_t segment_directory_fsync_max_ns = 0u;
    uint64_t state_apply_total_ns = 0u;
    uint64_t state_apply_max_ns = 0u;
    uint64_t slowest_commit_total_ns = 0u;
    uint64_t slowest_commit_segment_index = 0u;
    uint64_t slowest_commit_decisions = 0u;
    uint64_t slowest_commit_validate_serialize_ns = 0u;
    uint64_t slowest_commit_compression_ns = 0u;
    uint64_t slowest_commit_prepare_state_ns = 0u;
    uint64_t slowest_commit_segment_open_ns = 0u;
    uint64_t slowest_commit_segment_write_ns = 0u;
    uint64_t slowest_commit_segment_file_fsync_ns = 0u;
    uint64_t slowest_commit_segment_publish_ns = 0u;
    uint64_t slowest_commit_segment_directory_fsync_ns = 0u;
    uint64_t slowest_commit_state_apply_ns = 0u;
    std::string chain = std::string(64u, '0');
    std::string latest_segment_json = "null";
    std::string manifest_json;
    std::unordered_map<uint64_t, EventState> event_states;
    /* Independent durable-boundary validation. Exact physical epochs remain
     * separate because original EOF completion can refer to an older tuple
     * epoch after a later FLOW_OPEN is already durable. */
    std::unordered_map<SemanticKey, SemanticChainState,
        SemanticKeyHash, SemanticKeyEqual> semantic_chains;
    std::atomic<bool> faulted{false};
    bool closed = false;

    ~Implementation() {
        if (zstd_context != nullptr)
            (void)::ZSTD_freeCCtx(zstd_context);
        if (segment_directory_fd >= 0)
            (void)::close(segment_directory_fd);
    }

    std::string manifest_for(
            uint64_t proposed_segments,
            uint64_t proposed_decisions,
            uint64_t proposed_first,
            uint64_t proposed_last,
            const std::string &proposed_latest,
            const std::string &proposed_chain) const {
        std::string output;
        output.reserve(1024u + proposed_latest.size());
        output.append("{\n  \"chain_formula\": ");
        append_json_string(output, kChainFormula);
        output.append(",\n  \"chain_sha256\": ");
        append_json_string(output, proposed_chain);
        output.append(",\n  \"compression\": {\"format\":\"zstd\","
            "\"level\":1,\"checksum\":true,\"content_size\":true,"
            "\"dict_id\":false}");
        output.append(",\n  \"compression_library_version_number\": ");
        append_u64(output, ::ZSTD_versionNumber());
        output.append(",\n  \"decision_protocol\": ");
        append_json_string(output, config.terminal_coverage ?
            "flowkeep-live-seven-state-decision-v6" : (config.provisional_flow_open_scores ?
            kDecisionProtocolFlowOpen : kDecisionProtocol));
        output.append(",\n  \"decisions_committed\": ");
        append_u64(output, proposed_decisions);
        output.append(",\n  \"first_sequence\": ");
        if (proposed_decisions == 0u)
            output.append("null");
        else
            append_u64(output, proposed_first);
        output.append(",\n  \"last_sequence\": ");
        if (proposed_decisions == 0u)
            output.append("null");
        else
            append_u64(output, proposed_last);
        output.append(",\n  \"latest_segment\": ");
        output.append(proposed_latest);
        output.append(",\n  \"protocol\": ");
        append_json_string(output, config.synchronous_wal_segments ? "flowkeep-sync-wal-segment-ledger-v1" : config.terminal_coverage ?
            "flowkeep-atomic-decision-segment-ledger-v8" : (config.provisional_flow_open_scores ?
            kLedgerProtocolFlowOpen : kLedgerProtocol));
        output.append(",\n  \"run_uuid\": ");
        append_json_string(output, config.run_uuid_hex);
        output.append(",\n  \"segment_naming\": ");
        append_json_string(output, kSegmentNaming);
        output.append(",\n  \"segments_committed\": ");
        append_u64(output, proposed_segments);
        output.append(",\n  \"uncompressed_format\":\"jsonl\"");
        output.append("\n}\n");
        return output;
    }

    bool atomic_publish(
            const std::string &path,
            const void *payload,
            size_t payload_bytes,
            bool replace,
            PublishKind kind,
            PublishTiming *publish_timing,
            std::string *error) {
        if (publish_timing != nullptr)
            *publish_timing = {};
        const uint64_t timestamp = monotonic_ns();
        if (timestamp == 0u) {
            set_error(error, "ledger monotonic clock failed");
            return false;
        }
        char suffix[96];
        const int suffix_length = std::snprintf(suffix, sizeof(suffix),
            ".tmp.%ld.%llu", static_cast<long>(::getpid()),
            static_cast<unsigned long long>(timestamp));
        if (suffix_length <= 0 ||
            static_cast<size_t>(suffix_length) >= sizeof(suffix)) {
            set_error(error, "ledger temporary path overflow");
            return false;
        }
        const std::string directory = parent_path(path);
        const size_t slash = path.find_last_of('/');
        const std::string basename = slash == std::string::npos ? path :
            path.substr(slash + 1u);
        const std::string temporary = directory + "/." + basename + suffix;
        const uint64_t open_started = monotonic_ns();
        const int fd = ::open(temporary.c_str(),
            O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
        const uint64_t open_finished = monotonic_ns();
        if (fd < 0) {
            set_error(error, "ledger temporary file create failed");
            return false;
        }
        const uint64_t write_started = monotonic_ns();
        bool success = write_all(fd, payload, payload_bytes);
        const uint64_t write_finished = monotonic_ns();
        const uint64_t file_fsync_started = monotonic_ns();
        const auto file_sync_clock=ReadThreadPhaseStamp();
        if (success)
            success = ::fsync(fd) == 0;
        const auto file_sync_cost=ThreadPhaseBetween(file_sync_clock,ReadThreadPhaseStamp());
        const uint64_t file_fsync_finished = monotonic_ns();
        if (success) {
            if (kind == PublishKind::Segment) {
                ++segment_fsync_calls;
            } else {
                ++manifest_fsync_calls;
                if (kind == PublishKind::InitialManifest)
                    ++initial_manifest_fsync_calls;
                else
                    ++closure_manifest_fsync_calls;
            }
        }
        const uint64_t publish_started = monotonic_ns();
        if (::close(fd) != 0)
            success = false;
        if (success) {
            if (replace) {
                success = ::rename(temporary.c_str(), path.c_str()) == 0;
            } else {
                success = ::link(temporary.c_str(), path.c_str()) == 0;
                if (::unlink(temporary.c_str()) != 0)
                    success = false;
            }
        }
        const uint64_t publish_finished = monotonic_ns();
        const uint64_t directory_fsync_started = monotonic_ns();
        const auto directory_sync_clock=ReadThreadPhaseStamp();
        if (success) {
            success = kind == PublishKind::Segment &&
                    segment_directory_fd >= 0 && directory == segment_directory
                ? ::fsync(segment_directory_fd) == 0
                : fsync_directory(directory);
            if (success) {
                ++directory_fsync_calls;
                if (kind == PublishKind::Segment)
                    ++segment_directory_fsync_calls;
            }
        }
        const uint64_t directory_fsync_finished = monotonic_ns();
        const auto directory_sync_cost=ThreadPhaseBetween(directory_sync_clock,ReadThreadPhaseStamp());
        if (!success) {
            (void)::unlink(temporary.c_str());
            set_error(error, kind == PublishKind::Segment ?
                "decision segment durable publication failed" :
                "decision manifest durable publication failed");
        }
        if (success && kind == PublishKind::Segment) {
            PublishTiming observed{};
            observed.file_sync_cost=file_sync_cost;
            observed.directory_sync_cost=directory_sync_cost;
            observed.open_ns = elapsed_ns(open_started, open_finished);
            observed.write_ns = elapsed_ns(write_started, write_finished);
            observed.file_fsync_ns = elapsed_ns(
                file_fsync_started, file_fsync_finished);
            observed.publish_ns = elapsed_ns(
                publish_started, publish_finished);
            observed.directory_fsync_ns = elapsed_ns(
                directory_fsync_started, directory_fsync_finished);
            accumulate_timing(observed.open_ns,
                segment_open_total_ns, segment_open_max_ns);
            accumulate_timing(observed.write_ns,
                segment_write_total_ns, segment_write_max_ns);
            accumulate_timing(observed.file_fsync_ns,
                segment_file_fsync_total_ns, segment_file_fsync_max_ns);
            accumulate_timing(observed.publish_ns,
                segment_publish_total_ns, segment_publish_max_ns);
            accumulate_timing(observed.directory_fsync_ns,
                segment_directory_fsync_total_ns,
                segment_directory_fsync_max_ns);
            if (publish_timing != nullptr)
                *publish_timing = observed;
        }
        return success;
    }

    // Only the preparation thread calls this. No final segment is visible and
    // no durable sequence/manifest advances here. A crash leaves a temporary
    // name, which the unchanged gap-free final-segment recovery ignores.
    bool stage_segment(Prepared &p,std::string *error) {
        if(p.raw_payload || !staged_accounting || p.bytes.size()>(9u<<20)) {
            set_error(error,"invalid staged segment payload/state");return false;
        }
        const uint64_t stamp=monotonic_ns();
        if(!stamp){set_error(error,"ledger monotonic clock failed");return false;}
        char suffix[96];
        const int n=std::snprintf(suffix,sizeof(suffix),".tmp.%ld.%llu",
            static_cast<long>(::getpid()),static_cast<unsigned long long>(stamp));
        if(n<=0 || static_cast<size_t>(n)>=sizeof(suffix)){
            set_error(error,"ledger temporary path overflow");return false;
        }
        p.staged_temporary=segment_directory+"/."+p.name+suffix;
        const uint64_t open_start=monotonic_ns();
        const int fd=::open(p.staged_temporary.c_str(),O_WRONLY|O_CREAT|O_EXCL|O_CLOEXEC|O_NOFOLLOW,0600);
        const uint64_t open_end=monotonic_ns();
        if(fd<0){p.staged_temporary.clear();set_error(error,"ledger temporary file create failed");return false;}
        const uint64_t write_start=monotonic_ns();
        bool success=write_all(fd,p.bytes.data(),p.bytes.size());
        const uint64_t write_end=monotonic_ns(),sync_start=monotonic_ns();
        const auto sync_clock=ReadThreadPhaseStamp();
        if(success)success=::fsync(fd)==0;
        const auto sync_cost=ThreadPhaseBetween(sync_clock,ReadThreadPhaseStamp());
        const uint64_t sync_end=monotonic_ns();
        // Preserve the meaning of this counter: successful file fsyncs,
        // including a file whose later publication could still fail.
        if(success)++segment_fsync_calls;
        const uint64_t close_start=monotonic_ns();
        if(::close(fd)!=0)success=false;
        const uint64_t close_end=monotonic_ns();
        if(!success){set_error(error,"decision segment staging write/fsync/close failed");return false;}
        p.staged_timing.open_ns=elapsed_ns(open_start,open_end);
        p.staged_timing.write_ns=elapsed_ns(write_start,write_end);
        p.staged_timing.file_fsync_ns=elapsed_ns(sync_start,sync_end);
        p.staged_timing.file_sync_cost=sync_cost;
        // The original publish phase includes close(fd), so retain that work
        // in the same per-segment counter despite the earlier execution.
        p.staged_timing.publish_ns=elapsed_ns(close_start,close_end);
        p.staged_charge=p.bytes.size();p.staged_accounting=staged_accounting;
        p.staged_accounting->Add(p.staged_charge);p.staged_ready=true;
        ++staged_segments_prepared;staged_records_prepared+=p.rows;
        staged_payload_bytes_prepared+=p.bytes.size();return true;
    }

    // Called only by ordered publication after the service history fence.
    // Keep the original link/unlink no-replacement primitive and exactly one
    // directory fsync. Temporary file durability alone never authorizes ACK.
    bool publish_staged_segment(Prepared &p,PublishTiming *timing,std::string *error) {
        ++staged_publish_calls;
        if(!p.staged_ready || p.staged_temporary.empty() || !p.staged_accounting ||
           p.raw_payload || p.staged_charge!=p.bytes.size()) {
            set_error(error,"staged segment ownership/state is invalid");return false;
        }
        auto observed=p.staged_timing;
        const std::string final_path=segment_directory+"/"+p.name;
        const uint64_t publish_start=monotonic_ns();
        bool success=::link(p.staged_temporary.c_str(),final_path.c_str())==0;
        if(::unlink(p.staged_temporary.c_str())!=0)success=false;
        else p.staged_temporary.clear();
        const uint64_t publish_end=monotonic_ns(),sync_start=monotonic_ns();
        const auto sync_clock=ReadThreadPhaseStamp();
        if(success)success=segment_directory_fd>=0?::fsync(segment_directory_fd)==0:fsync_directory(segment_directory);
        const auto sync_cost=ThreadPhaseBetween(sync_clock,ReadThreadPhaseStamp());
        const uint64_t sync_end=monotonic_ns();
        if(success){++directory_fsync_calls;++segment_directory_fsync_calls;}
        p.staged_ready=false;
        if(p.staged_temporary.empty())p.ReleaseStagedAccounting();
        if(!success){set_error(error,"decision segment durable publication failed");return false;}
        observed.publish_ns+=elapsed_ns(publish_start,publish_end);
        observed.directory_fsync_ns=elapsed_ns(sync_start,sync_end);observed.directory_sync_cost=sync_cost;
        accumulate_timing(observed.open_ns,segment_open_total_ns,segment_open_max_ns);
        accumulate_timing(observed.write_ns,segment_write_total_ns,segment_write_max_ns);
        accumulate_timing(observed.file_fsync_ns,segment_file_fsync_total_ns,segment_file_fsync_max_ns);
        accumulate_timing(observed.publish_ns,segment_publish_total_ns,segment_publish_max_ns);
        accumulate_timing(observed.directory_fsync_ns,segment_directory_fsync_total_ns,segment_directory_fsync_max_ns);
        if(timing)*timing=observed;
        ++staged_publish_succeeded;
        return true;
    }

    bool atomic_publish(
            const std::string &path,
            const std::string &payload,
            bool replace,
            PublishKind kind,
            std::string *error) {
        return atomic_publish(path, payload.data(), payload.size(), replace,
            kind, nullptr, error);
    }

    bool publish_wal_segment(Prepared &p, PublishTiming *timing,std::string *error) {
        if(!wal_db || p.raw_payload || p.staged_ready) {
            set_error(error,"WAL publication state is invalid");return false;
        }
        rocksdb::WriteBatch batch;
        batch.Put("segment/"+p.name,p.bytes);batch.Put("meta/manifest",p.manifest);
        return write_wal_batch(batch,1,p.bytes.size(),timing,error);
    }
    bool write_wal_batch(rocksdb::WriteBatch &batch,size_t segments,uint64_t bytes,
            PublishTiming *timing,std::string *error) {
        if(config.before_wal_write_for_test && !config.before_wal_write_for_test(config.wal_test_context)) {
            set_error(error,"injected WAL write failure");return false;
        }
        rocksdb::WriteOptions options;options.sync=true;options.disableWAL=false;
        const auto clock=ReadThreadPhaseStamp();const uint64_t begin=monotonic_ns();
        const auto status=wal_db->Write(options,&batch);
        const uint64_t end=monotonic_ns();const auto cost=ThreadPhaseBetween(clock,ReadThreadPhaseStamp());
        if(!status.ok()){set_error(error,"WAL segment Write failed: "+status.ToString());return false;}
        ++wal_write_calls;wal_segment_commits+=segments;wal_group_writes+=segments>1;
        wal_max_group_segments=std::max<uint64_t>(wal_max_group_segments,segments);
        wal_segment_bytes+=bytes;wal_write_wall_ns+=elapsed_ns(begin,end);wal_write_cpu_ns+=cost.cpu_ns;
        if(timing){*timing={};timing->file_sync_cost=cost;}
        return true;
    }

    bool initialize(std::string *error) {
        if (config.output_directory.empty() ||
            (config.group_wal_publication && !config.synchronous_wal_segments) ||
            (config.synchronous_wal_segments && (config.stage_segment_file_in_prepare || config.defer_compression_to_publish)) ||
            (config.prepared_commit_capacity != 2u && config.prepared_commit_capacity != 4u) ||
            config.output_directory[0] != '/' ||
            !lowercase_uuid(config.run_uuid_hex) ||
            !std::isfinite(config.threshold) || config.threshold < 0.0 ||
            config.threshold > 1.0 || config.detector_deadline_ns == 0u ||
            config.expected_semantic_chains >
                std::numeric_limits<size_t>::max() ||
            config.expected_event_states >
                std::numeric_limits<size_t>::max()) {
            set_error(error, "JSONL ledger configuration is invalid");
            return false;
        }
        zstd_context = ::ZSTD_createCCtx();
        if (zstd_context == nullptr ||
            ::ZSTD_isError(::ZSTD_CCtx_setParameter(
                zstd_context, ZSTD_c_compressionLevel,
                kZstdCompressionLevel)) ||
            ::ZSTD_isError(::ZSTD_CCtx_setParameter(
                zstd_context, ZSTD_c_checksumFlag, 1)) ||
            ::ZSTD_isError(::ZSTD_CCtx_setParameter(
                zstd_context, ZSTD_c_contentSizeFlag, 1)) ||
            ::ZSTD_isError(::ZSTD_CCtx_setParameter(
                zstd_context, ZSTD_c_dictIDFlag, 0)) ||
            ::ZSTD_isError(::ZSTD_CCtx_setParameter(
                zstd_context, ZSTD_c_nbWorkers, 0))) {
            set_error(error, "zstd compressor initialization failed");
            return false;
        }
        try {
            if (config.expected_semantic_chains != 0u) {
                semantic_chains.reserve(static_cast<size_t>(
                    config.expected_semantic_chains));
            }
            if (config.expected_event_states != 0u) {
                event_states.reserve(static_cast<size_t>(
                    config.expected_event_states));
            }
        } catch (...) {
            set_error(error, "ledger state index reservation failed");
            return false;
        }
        struct stat status{};
        if (::lstat(config.output_directory.c_str(), &status) != 0) {
            if (errno != ENOENT ||
                ::mkdir(config.output_directory.c_str(), 0700) != 0 ||
                !fsync_directory(parent_path(config.output_directory))) {
                set_error(error, "ledger output directory create failed");
                return false;
            }
            ++directory_fsync_calls;
        }
        if (!exact_directory(config.output_directory)) {
            set_error(error, "ledger output path is not an exact directory");
            return false;
        }
        segment_directory = config.output_directory + "/decision_segments";
        manifest_path = config.output_directory + "/decisions_manifest.json";
        lock_path = config.output_directory + "/.live_service.lock";
        const std::string receipt_path =
            config.output_directory + "/receipt.json";
        if (!path_absent(manifest_path) || !path_absent(receipt_path) ||
            !path_absent(lock_path)) {
            set_error(error, "ledger output belongs to a prior service run");
            return false;
        }
        if (::lstat(segment_directory.c_str(), &status) != 0) {
            if (errno != ENOENT ||
                ::mkdir(segment_directory.c_str(), 0700) != 0 ||
                !fsync_directory(config.output_directory)) {
                set_error(error, "decision segment directory create failed");
                return false;
            }
            ++directory_fsync_calls;
        } else if (!exact_directory(segment_directory) ||
                   !directory_empty(segment_directory)) {
            set_error(error, "decision segment directory is not empty/exact");
            return false;
        }
        segment_directory_fd = ::open(segment_directory.c_str(),
            O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
        if (segment_directory_fd < 0) {
            set_error(error, "decision segment directory open failed");
            return false;
        }
        lock_fd = ::open(lock_path.c_str(),
            O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
        if (lock_fd < 0) {
            set_error(error, "ledger run lock create failed");
            return false;
        }
        std::string lock_json = "{\"pid\":";
        append_u64(lock_json, static_cast<uint64_t>(::getpid()));
        lock_json.append(",\"run_uuid\":");
        append_json_string(lock_json, config.run_uuid_hex);
        lock_json.append("}\n");
        if (!write_all(lock_fd, lock_json) || ::fsync(lock_fd) != 0 ||
            !fsync_directory(config.output_directory)) {
            set_error(error, "ledger run lock durability failed");
            return false;
        }
        ++directory_fsync_calls;
        manifest_json = manifest_for(0u, 0u, 0u, 0u, "null", chain);
        durable_manifest = manifest_json;
        if(config.synchronous_wal_segments) {
            const std::string path=config.output_directory+"/segment_wal";
            if(!path_absent(path)){set_error(error,"WAL directory already exists");return false;}
            rocksdb::Options options;options.create_if_missing=true;options.error_if_exists=true;
            options.paranoid_checks=true;options.write_buffer_size=1u<<20;
            options.max_write_buffer_number=2;options.max_background_jobs=2;options.max_open_files=64;
            // Already-compressed deterministic frames: do not compress twice.
            options.compression=rocksdb::kNoCompression;
            rocksdb::BlockBasedTableOptions table;table.block_cache=rocksdb::NewLRUCache(2u<<20,0,true);
            options.table_factory.reset(rocksdb::NewBlockBasedTableFactory(table));
            rocksdb::DB *raw=nullptr;auto status=rocksdb::DB::Open(options,path,&raw);
            if(!status.ok()){set_error(error,"WAL Open failed: "+status.ToString());return false;}
            wal_db.reset(raw);rocksdb::WriteOptions writes;writes.sync=true;writes.disableWAL=false;
            status=wal_db->Put(writes,"meta/manifest",manifest_json);
            if(!status.ok() || !fsync_directory(config.output_directory)) {
                set_error(error,"WAL initialization durability failed");return false;
            }
        }
        if (!atomic_publish(
                manifest_path, manifest_json, true,
                PublishKind::InitialManifest, error)) {
            return false;
        }
        return true;
    }
};

NativeFusionJsonlLedger::NativeFusionJsonlLedger(
        Implementation *implementation) noexcept
    : implementation_(implementation) {}

NativeFusionJsonlLedger::~NativeFusionJsonlLedger() {
    std::string ignored;
    (void)Close(&ignored);
    delete implementation_;
}

std::unique_ptr<NativeFusionJsonlLedger> NativeFusionJsonlLedger::Create(
        const NativeFusionJsonlLedgerConfig &config,
        std::string *error) {
    Implementation *implementation = new (std::nothrow) Implementation{};
    if (implementation == nullptr) {
        set_error(error, "JSONL ledger allocation failed");
        return nullptr;
    }
    try {
        implementation->config = config;
        if(config.stage_segment_file_in_prepare)
            implementation->staged_accounting=std::make_shared<Implementation::StagedAccounting>();
    } catch (...) {
        delete implementation;
        set_error(error, "JSONL ledger configuration allocation failed");
        return nullptr;
    }
    if (!implementation->initialize(error)) {
        if (implementation->lock_fd >= 0)
            (void)::close(implementation->lock_fd);
        delete implementation;
        return nullptr;
    }
    std::unique_ptr<NativeFusionJsonlLedger> result(
        new (std::nothrow) NativeFusionJsonlLedger(implementation));
    if (!result) {
        (void)::close(implementation->lock_fd);
        delete implementation;
        set_error(error, "JSONL ledger object allocation failed");
    }
    return result;
}

bool NativeFusionJsonlLedger::CommitConsecutive(
        const NativeFusionDecision *decisions, size_t decision_count,
        NativeFusionCommitResult *result, std::string *error) noexcept {
    std::unique_ptr<NativeFusionPreparedCommit> prepared;
    if (result) *result = {};
    return result && PrepareConsecutive(decisions, decision_count, &prepared, error)
        && PublishPrepared(prepared.get(), result, error);
}

bool NativeFusionJsonlLedger::SupportsDrainPreparationOverlap() const noexcept {
    return implementation_ && implementation_->config.defer_compression_to_publish;
}

void NativeFusionJsonlLedger::BeginDrainPreparationOverlap() noexcept {
    if(SupportsDrainPreparationOverlap())implementation_->compression_deferred=true;
}

uint32_t NativeFusionJsonlLedger::PreparedCommitCapacity() const noexcept {
    return implementation_ ? implementation_->config.prepared_commit_capacity : 0u;
}

bool NativeFusionJsonlLedger::PrepareConsecutive(
        const NativeFusionDecision *decisions, size_t decision_count,
        std::unique_ptr<NativeFusionPreparedCommit> *output,
        std::string *error) noexcept {
    if (output) output->reset();
    if (implementation_ == nullptr || decisions == nullptr ||
        decision_count == 0u || decision_count > 5120u || output == nullptr ||
        implementation_->segments - implementation_->durable_segments.load() >= implementation_->config.prepared_commit_capacity ||
        implementation_->faulted || implementation_->closed) {
        set_error(error, "JSONL ledger commit arguments/state are invalid");
        return false;
    }
    Implementation &state = *implementation_;
    const uint64_t commit_started = monotonic_ns();
    const auto serialize_clock=ReadThreadPhaseStamp();
    const bool defer_compression=state.compression_deferred && !state.config.stage_segment_file_in_prepare;
    struct PendingState {
        uint64_t token;
        Implementation::EventState next;
        bool new_event;
        Implementation::EventState *destination = nullptr;
    };
    struct PendingSemanticChain {
        SemanticKey key;
        Implementation::SemanticChainState next;
        bool new_chain;
        Implementation::SemanticChainState *destination = nullptr;
    };
    try {
        constexpr size_t kPayloadReserveBytesPerDecision = 1152u;
        if (decision_count >
            std::numeric_limits<size_t>::max() /
                kPayloadReserveBytesPerDecision) {
            state.faulted = true;
            set_error(error, "decision payload reserve size overflowed");
            return false;
        }
        std::string &payload = state.commit_payload_scratch;
        payload.clear();
        if (defer_compression && state.config.reuse_payload_buffers) {
            std::lock_guard<std::mutex> lock(state.payload_spare_mutex);
            if (state.payload_spare.capacity() > payload.capacity()) {
                payload.swap(state.payload_spare);
                ++state.payload_buffer_reuse_hits;
            }
        }
        const size_t payload_reserve_bytes =
            decision_count * kPayloadReserveBytesPerDecision;
        if (payload.capacity() < payload_reserve_bytes)
            payload.reserve(payload_reserve_bytes);
        std::vector<PendingState> pending;
        pending.reserve(decision_count);
        size_t new_event_states = 0u;
        size_t new_semantic_chains = 0u;
        /* Both per-commit indexes are discarded together.  A shared
         * monotonic arena turns thousands of node malloc/free operations per
         * Real batch into one bounded allocation while preserving the exact
         * unordered-map lookup semantics.  The upstream resource remains a
         * correctness fallback if an implementation has unusually large
         * node overhead. */
        constexpr size_t kPendingArenaBytesPerDecision = 256u;
        const size_t pending_arena_bytes =
            decision_count * kPendingArenaBytesPerDecision;
        if (state.commit_pending_arena_scratch.size() < pending_arena_bytes) {
            state.commit_pending_arena_scratch.resize(pending_arena_bytes);
        }
        PendingMemoryResource pending_resource(
            state.commit_pending_arena_scratch.data(), pending_arena_bytes);
        std::experimental::pmr::unordered_map<uint64_t, size_t>
            pending_indices{
            &pending_resource};
        pending_indices.reserve(decision_count);
        std::vector<PendingSemanticChain> pending_chains;
        pending_chains.reserve(decision_count);
        std::experimental::pmr::unordered_map<
            SemanticKey, size_t, SemanticKeyHash, SemanticKeyEqual>
            pending_chain_indices{&pending_resource};
        pending_chain_indices.reserve(decision_count);
        const uint64_t expected_first = state.last_sequence + 1u;
        for (size_t index = 0u; index < decision_count; ++index) {
            const NativeFusionDecision &decision = decisions[index];
            const uint64_t expected = expected_first + index;
            const bool flow_open =
                decision.kind == NativeFusionDecisionKind::FlowOpen;
            const bool flow_continue =
                decision.kind == NativeFusionDecisionKind::FlowContinue;
            const bool checkpoint =
                decision.kind == NativeFusionDecisionKind::Checkpoint;
            const bool flow_control = flow_open || flow_continue;
            const bool provisional_flow_open = flow_open &&
                state.config.provisional_flow_open_scores;
            const bool has_prefix = static_cast<bool>(decision.coverage_prefix);
            const bool deposit = flow_open && has_prefix;
            if ((!state.config.terminal_coverage && (has_prefix || decision.coverage_terminal ||
                     decision.coverage_evidence_timestamp_ns)) ||
                (state.config.terminal_coverage &&
                 ((flow_open != deposit) || provisional_flow_open ||
                  (deposit && (decision.coverage_terminal ||
                   decision.coverage_evidence_timestamp_ns != decision.flow_first_timestamp_ns)) ||
                  (decision.coverage_terminal && (!checkpoint || !has_prefix ||
                   decision.checkpoint_packet == 0u ||
                   decision.coverage_evidence_timestamp_ns <
                       decision.flow_first_timestamp_ns ||
                   decision.coverage_evidence_timestamp_ns >
                       decision.semantic_timestamp_ns)) ||
                  (!deposit && !decision.coverage_terminal && (decision.coverage_evidence_timestamp_ns || has_prefix))))) {
                state.faulted = true;
                set_error(error, "coverage deposit/terminal protocol mismatch");
                return false;
            }
            if (has_prefix) for (float v : *decision.coverage_prefix) {
                if (!std::isfinite(v)) {
                    state.faulted = true;
                    set_error(error, "nonfinite native coverage prefix");
                    return false;
                }
            }
            if (decision.sequence != expected || decision.event_token == 0u ||
                decision.event_id == nullptr ||
                !safe_event_id(*decision.event_id) ||
                decision.event_routing_token != decision.sequence ||
                decision.flow_generation == 0u ||
                decision.flow_first_timestamp_ns == 0u ||
                decision.flow_first_timestamp_ns >
                    decision.semantic_timestamp_ns ||
                (decision.logical_connection_id != 0u &&
                 decision.canonical_key.protocol != 17u) ||
                (!flow_control && !checkpoint) ||
                (flow_control &&
                 (decision.checkpoint_packet != 0u ||
                  decision.source_mask != 0u ||
                  decision.threshold_met != 0u ||
                  decision.first_alert != 0u ||
                  decision.alert_latched != 0u)) ||
                (flow_continue &&
                 (decision.score_present != 0u ||
                  decision.score != 0.0)) ||
                (flow_open &&
                 (decision.score_present !=
                      (provisional_flow_open ? 1u : 0u) ||
                  (!provisional_flow_open && decision.score != 0.0))) ||
                (flow_open &&
                 (decision.flow_first_timestamp_ns !=
                      decision.semantic_timestamp_ns ||
                  decision.predecessor_flow_index != 0u ||
                  decision.predecessor_flow_generation != 0u ||
                  decision.predecessor_checkpoint_packet != 0u)) ||
                (flow_continue &&
                 (decision.logical_connection_id != 0u ||
                  decision.predecessor_flow_generation == 0u ||
                  (decision.predecessor_flow_index == decision.flow_index &&
                   decision.predecessor_flow_generation ==
                       decision.flow_generation))) ||
                (checkpoint &&
                 (decision.score_present != 1u ||
                  decision.checkpoint_packet == 0u ||
                  decision.checkpoint_packet > UINT16_MAX ||
                  decision.predecessor_flow_index != 0u ||
                  decision.predecessor_flow_generation != 0u ||
                  decision.predecessor_checkpoint_packet != 0u)) ||
                decision.source_mask > FK_DETECTOR_REQUEST_SOURCE_MASK_ALL ||
                !std::isfinite(decision.score) || decision.score < 0.0 ||
                decision.score > 1.0 || decision.threshold_met > 1u ||
                decision.first_alert > 1u || decision.alert_latched > 1u ||
                decision.physical_enqueue_monotonic_ns == 0u ||
                !(decision.physical_enqueue_monotonic_ns <=
                      decision.consumer_receive_monotonic_ns &&
                  decision.consumer_receive_monotonic_ns <=
                      decision.inference_start_monotonic_ns &&
                  decision.inference_start_monotonic_ns <=
                      decision.decision_monotonic_ns) ||
                decision.physical_enqueue_monotonic_ns >
                    UINT64_MAX - state.config.detector_deadline_ns) {
                state.faulted = true;
                set_error(error, "decision row identity/timestamp is invalid");
                return false;
            }
            const SemanticKey semantic_key{
                decision.canonical_key, decision.logical_connection_id,
                decision.flow_first_timestamp_ns};
            size_t chain_index = 0u;
            const auto pending_chain = pending_chain_indices.find(
                semantic_key);
            if (pending_chain == pending_chain_indices.end()) {
                Implementation::SemanticChainState next{};
                bool new_chain = false;
                Implementation::SemanticChainState *destination = nullptr;
                const auto existing = state.semantic_chains.find(
                    semantic_key);
                if (existing == state.semantic_chains.end()) {
                    new_chain = true;
                    ++new_semantic_chains;
                } else {
                    next = existing->second;
                    destination = &existing->second;
                }
                chain_index = pending_chains.size();
                pending_chains.push_back({
                    semantic_key, next, new_chain, destination});
                pending_chain_indices.emplace(
                    pending_chains.back().key, chain_index);
            } else {
                chain_index = pending_chain->second;
            }
            Implementation::SemanticChainState &chain =
                pending_chains[chain_index].next;
            const bool chain_exists =
                !pending_chains[chain_index].new_chain ||
                chain.flow_generation != 0u;
            if (flow_open) {
                if (chain_exists) {
                    state.faulted = true;
                    set_error(error,
                        "FLOW_OPEN semantic epoch/route is invalid");
                    return false;
                }
                chain.event_token = decision.event_token;
                chain.flow_first_timestamp_ns =
                    decision.flow_first_timestamp_ns;
                chain.flow_index = decision.flow_index;
                chain.flow_generation = decision.flow_generation;
                chain.last_checkpoint_packet = 0u;
            } else if (flow_continue) {
                if (!chain_exists ||
                    chain.event_token != decision.event_token ||
                    chain.flow_first_timestamp_ns !=
                        decision.flow_first_timestamp_ns ||
                    chain.flow_index !=
                        decision.predecessor_flow_index ||
                    chain.flow_generation !=
                        decision.predecessor_flow_generation ||
                    chain.last_checkpoint_packet !=
                        decision.predecessor_checkpoint_packet ||
                    (chain.flow_index == decision.flow_index &&
                     chain.flow_generation == decision.flow_generation)) {
                    state.faulted = true;
                    set_error(error,
                        "FLOW_CONTINUE durable predecessor differs");
                    return false;
                }
                chain.flow_index = decision.flow_index;
                chain.flow_generation = decision.flow_generation;
            } else {
                if (!chain_exists ||
                    chain.event_token != decision.event_token ||
                    chain.flow_first_timestamp_ns !=
                        decision.flow_first_timestamp_ns ||
                    chain.flow_index != decision.flow_index ||
                    chain.flow_generation != decision.flow_generation ||
                    (!decision.coverage_terminal &&
                     decision.checkpoint_packet <=
                         chain.last_checkpoint_packet) ||
                    (decision.coverage_terminal &&
                     decision.checkpoint_packet <
                         chain.last_checkpoint_packet)) {
                    state.faulted = true;
                    set_error(error,
                        "checkpoint durable semantic chain differs");
                    return false;
                }
                chain.last_checkpoint_packet =
                    decision.checkpoint_packet;
            }
            size_t pending_index = 0u;
            const auto pending_found = pending_indices.find(
                decision.event_token);
            if (pending_found == pending_indices.end()) {
                Implementation::EventState next{};
                bool new_event = false;
                Implementation::EventState *destination = nullptr;
                const auto existing = state.event_states.find(
                    decision.event_token);
                if (existing == state.event_states.end()) {
                    next.event_id = decision.event_id;
                    new_event = true;
                    ++new_event_states;
                } else {
                    next = existing->second;
                    destination = &existing->second;
                    if (next.event_id == nullptr ||
                        *next.event_id != *decision.event_id) {
                        state.faulted = true;
                        set_error(error, "event token collided with event_id");
                        return false;
                    }
                }
                pending_index = pending.size();
                pending.push_back(
                    {decision.event_token, next, new_event, destination});
                pending_indices.emplace(decision.event_token, pending_index);
            } else {
                pending_index = pending_found->second;
            }
            Implementation::EventState &event = pending[pending_index].next;
            if (event.has_observation &&
                decision.semantic_timestamp_ns < event.last_observation_ns) {
                state.faulted = true;
                set_error(error, "event semantic timestamp regressed");
                return false;
            }
            const bool threshold_met = checkpoint &&
                decision.score >= state.config.threshold;
            const bool first_alert = checkpoint && threshold_met &&
                !event.alert_latched;
            const bool alert_latched = event.alert_latched || threshold_met;
            if ((checkpoint &&
                 ((decision.threshold_met != 0u) != threshold_met ||
                  (decision.first_alert != 0u) != first_alert ||
                  (decision.alert_latched != 0u) != alert_latched)) ||
                (checkpoint && event.updates == UINT64_MAX) ||
                (flow_open && event.flow_opens == UINT64_MAX) ||
                (flow_continue && event.flow_continues == UINT64_MAX)) {
                state.faulted = true;
                set_error(error, "decision threshold/latch semantics differ");
                return false;
            }
            if (flow_open)
                ++event.flow_opens;
            else if (flow_continue)
                ++event.flow_continues;
            else
                ++event.updates;
            event.last_observation_ns = decision.semantic_timestamp_ns;
            event.has_observation = true;
            event.alert_latched = alert_latched;
            const uint64_t queue_wait =
                decision.consumer_receive_monotonic_ns -
                decision.physical_enqueue_monotonic_ns;
            const uint64_t inference = decision.decision_monotonic_ns -
                decision.inference_start_monotonic_ns;
            const uint64_t end_to_end = decision.decision_monotonic_ns -
                decision.physical_enqueue_monotonic_ns;
            const uint64_t deadline =
                decision.physical_enqueue_monotonic_ns +
                state.config.detector_deadline_ns;
            const bool deadline_met =
                decision.decision_monotonic_ns <= deadline;

            payload.append(alert_latched ?
                "{\"alert_latched\":true,\"batch_inference_ns\":" :
                "{\"alert_latched\":false,\"batch_inference_ns\":");
            append_u64(payload, inference);
            payload.append(",\"checkpoint_packet\":");
            append_u32(payload, decision.checkpoint_packet);
            payload.append(",\"decision_monotonic_ns\":");
            append_u64(payload, decision.decision_monotonic_ns);
            payload.append(flow_open ?
                ",\"decision_kind\":\"flow_open\","
                "\"detector_deadline_met\":" :
                (flow_continue ?
                    ",\"decision_kind\":\"flow_continue\","
                    "\"detector_deadline_met\":" :
                    ",\"decision_kind\":\"checkpoint\","
                    "\"detector_deadline_met\":"));
            payload.append(deadline_met ? "true" : "false");
            payload.append(",\"detector_deadline_ns\":");
            append_u64(payload, deadline);
            payload.append(
                ",\"detector_schedule\":\"fifo_deadline\","
                "\"end_to_end_ns\":");
            append_u64(payload, end_to_end);
            payload.append(",\"event_checkpoint_updates\":");
            append_u64(payload, event.updates);
            payload.append(",\"event_flow_continues\":");
            append_u64(payload, event.flow_continues);
            payload.append(",\"event_id\":");
            append_json_string(payload, *decision.event_id);
            payload.append(",\"event_routing_token\":");
            append_u64(payload, decision.event_routing_token);
            payload.append(first_alert ?
                ",\"first_alert\":true,\"flow_generation\":" :
                ",\"first_alert\":false,\"flow_generation\":");
            append_u32(payload, decision.flow_generation);
            payload.append(",\"flow_first_timestamp_ns\":");
            append_u64(payload, decision.flow_first_timestamp_ns);
            payload.append(",\"flow_index\":");
            append_u32(payload, decision.flow_index);
            payload.append(",\"flow_key\":");
            if (!append_flow_key_json_string(
                    payload, decision.canonical_key)) {
                state.faulted = true;
                set_error(error, "decision flow key formatting failed");
                return false;
            }
            payload.append(",\"inference_start_monotonic_ns\":");
            append_u64(payload, decision.inference_start_monotonic_ns);
            payload.append(",\"logical_connection_id\":");
            append_u64(payload, decision.logical_connection_id);
            payload.append(decision.score_present == 1u ?
                ",\"model_score_present\":true,\"observation_ns\":" :
                ",\"model_score_present\":false,\"observation_ns\":");
            append_u64(payload, decision.semantic_timestamp_ns);
            payload.append(",\"physical_enqueue_monotonic_ns\":");
            append_u64(payload, decision.physical_enqueue_monotonic_ns);
            payload.append(",\"predecessor_flow_generation\":");
            append_u32(payload, decision.predecessor_flow_generation);
            payload.append(",\"predecessor_flow_index\":");
            append_u32(payload, decision.predecessor_flow_index);
            payload.append(",\"predecessor_checkpoint_packet\":");
            append_u32(payload, decision.predecessor_checkpoint_packet);
            payload.append(",\"protocol\":\"");
            payload.append(state.config.terminal_coverage ?
                "flowkeep-live-seven-state-decision-v6" : (state.config.provisional_flow_open_scores ?
                kDecisionProtocolFlowOpen : kDecisionProtocol));
            payload.append(alert_latched ?
                "\",\"predicted\":true,\"queue_wait_ns\":" :
                "\",\"predicted\":false,\"queue_wait_ns\":");
            append_u64(payload, queue_wait);
            payload.append(",\"receive_monotonic_ns\":");
            append_u64(payload, decision.consumer_receive_monotonic_ns);
            payload.append(",\"score\":");
            if (decision.score_present == 0u) {
                payload.append("null");
            } else if (!append_double(payload, decision.score)) {
                state.faulted = true;
                set_error(error, "decision score serialization failed");
                return false;
            }
            payload.append(",\"sequence\":");
            append_u64(payload, decision.sequence);
            payload.append(",\"source_mask\":");
            append_u64(payload, decision.source_mask);
            if (state.config.terminal_coverage) {
                payload.append(",\"coverage_evidence_timestamp_ns\":");
                append_u64(payload, decision.coverage_evidence_timestamp_ns);
                payload.append(",\"observation_kind\":");
                append_json_string(payload, deposit ? "prefix_deposit" :
                    (decision.coverage_terminal ? "input_eof_prefix" : "ordinary"));
                payload.append(",\"coverage_prefix_f32le_hex\":");
                if (!has_prefix) payload.append("null");
                else AppendPrefixHex(payload,*decision.coverage_prefix);
            }
            payload.append(threshold_met ?
                ",\"threshold_met\":true}\n" :
                ",\"threshold_met\":false}\n");
            if (payload.size() > (state.config.terminal_coverage ? (16u << 20) : (8u << 20))) {
                state.faulted = true;
                set_error(error, "prepared segment exceeds protocol payload bound");
                return false;
            }
        }

        const uint64_t validate_serialize_finished = monotonic_ns();
        const auto compression_clock=ReadThreadPhaseStamp();
        if (state.segments > UINT32_MAX) {
            state.faulted = true;
            set_error(error, "decision segment index overflowed");
            return false;
        }
        size_t compressed_bytes = 0u;
        if (!defer_compression && !zstd_level_one(state.zstd_context, payload,
                &state.zstd_scratch, &compressed_bytes, error)) {
            state.faulted = true;
            return false;
        }
        const uint64_t compression_finished = monotonic_ns();
        const auto state_clock=ReadThreadPhaseStamp();
        char name[64];
        const int name_length = std::snprintf(name, sizeof(name),
            "segment_%08llu.jsonl.zst",
            static_cast<unsigned long long>(state.segments));
        if (name_length <= 0 ||
            static_cast<size_t>(name_length) >= sizeof(name)) {
            state.faulted = true;
            set_error(error, "decision segment name overflowed");
            return false;
        }
        std::string segment_sha;
        if (!defer_compression && !sha256_hex(state.zstd_scratch.data(),
                compressed_bytes, &segment_sha)) {
            state.faulted = true;
            set_error(error, "decision segment SHA-256 failed");
            return false;
        }
        std::string proposed_chain;
        if (!defer_compression && !chain_sha256(state.chain, segment_sha, decision_count,
                &proposed_chain)) {
            state.faulted = true;
            set_error(error, "decision ledger chain SHA-256 failed");
            return false;
        }
        const uint64_t proposed_segments = state.segments + 1u;
        const uint64_t proposed_decisions = state.decisions + decision_count;
        const uint64_t proposed_first = state.decisions == 0u ?
            decisions[0].sequence : state.first_sequence;
        const uint64_t proposed_last = decisions[decision_count - 1u].sequence;
        std::string latest = "{\"bytes\":";
        append_u64(latest, compressed_bytes);
        latest.append(",\"first_sequence\":");
        append_u64(latest, decisions[0].sequence);
        latest.append(",\"last_sequence\":");
        append_u64(latest, proposed_last);
        latest.append(",\"path\":\"decision_segments/");
        latest.append(name, static_cast<size_t>(name_length));
        latest.append("\",\"rows\":");
        append_u64(latest, decision_count);
        latest.append(",\"sha256\":\"");
        latest.append(segment_sha);
        latest.append("\",\"uncompressed_bytes\":");
        append_u64(latest, payload.size());
        latest.append("}");
        std::string proposed_manifest = state.manifest_for(
            proposed_segments, proposed_decisions, proposed_first,
            proposed_last, latest, proposed_chain);

        /* Do not exact-reserve on every commit.  libstdc++ implements
         * reserve(size + delta) as a just-large-enough rehash; on Real that
         * repeatedly rebuilt a growing ~0.5M-entry table dozens of times.
         * Let normal insertions use the hash table's geometric growth. Resolve
         * stable value pointers before publishing so no allocation can occur
         * after the segment becomes durable. */
        const size_t expected_semantic_chains = static_cast<size_t>(
            state.config.expected_semantic_chains);
        const size_t expected_event_states = static_cast<size_t>(
            state.config.expected_event_states);
        if ((expected_semantic_chains != 0u &&
             (state.semantic_chains.size() > expected_semantic_chains ||
              new_semantic_chains > expected_semantic_chains -
                  state.semantic_chains.size())) ||
            (expected_event_states != 0u &&
             (state.event_states.size() > expected_event_states ||
              new_event_states > expected_event_states -
                  state.event_states.size()))) {
            state.faulted = true;
            set_error(error, "ledger frozen state bound exceeded");
            return false;
        }
        for (PendingState &entry : pending) {
            if (entry.new_event) {
                const auto inserted =
                    state.event_states.emplace(entry.token, entry.next);
                if (!inserted.second) {
                    state.faulted = true;
                    set_error(error,
                        "event state insertion invariant failed");
                    return false;
                }
                entry.destination = &inserted.first->second;
            } else if (entry.destination == nullptr) {
                state.faulted = true;
                set_error(error, "event state destination is missing");
                return false;
            }
        }
        for (PendingSemanticChain &entry : pending_chains) {
            if (entry.new_chain) {
                const auto inserted =
                    state.semantic_chains.emplace(entry.key, entry.next);
                if (!inserted.second) {
                    state.faulted = true;
                    set_error(error,
                        "semantic chain insertion invariant failed");
                    return false;
                }
                entry.destination = &inserted.first->second;
            } else if (entry.destination == nullptr) {
                state.faulted = true;
                set_error(error,
                    "semantic chain destination is missing");
                return false;
            }
        }
        const uint64_t prepare_state_finished = monotonic_ns();
        auto prepared = std::make_unique<Implementation::Prepared>();
        prepared->owner = &state;
        prepared->segment_index = state.segments;
        prepared->first = decisions[0].sequence;
        prepared->last = proposed_last;
        prepared->first_ever = proposed_first;
        prepared->rows = decision_count;
        prepared->total_rows = proposed_decisions;
        prepared->raw_bytes = payload.size();
        prepared->last_decision_ns = decisions[decision_count-1].decision_monotonic_ns;
        prepared->raw_payload=defer_compression;
        if(prepared->raw_payload && state.config.reuse_payload_buffers) {
            prepared->bytes.swap(payload);
            ++state.payload_buffer_moves;
            state.payload_buffer_moved_bytes+=prepared->raw_bytes;
        }
        else if(prepared->raw_payload)prepared->bytes=payload;
        else prepared->bytes.assign(state.zstd_scratch.data(), compressed_bytes);
        if (prepared->bytes.size() > (prepared->raw_payload ? (16u << 20) : (9u << 20))) {
            state.faulted = true;
            set_error(error, "prepared compressed segment exceeds bound");
            return false;
        }
        prepared->name = name;
        prepared->chain = proposed_chain;
        prepared->manifest = proposed_manifest;
        prepared->validate_ns = elapsed_ns(commit_started, validate_serialize_finished);
        prepared->compression_ns = elapsed_ns(validate_serialize_finished, compression_finished);
        prepared->prepare_ns = elapsed_ns(compression_finished, prepare_state_finished);
        prepared->serialize_cost=ThreadPhaseBetween(serialize_clock,compression_clock);
        if(!defer_compression)
            prepared->compression_cost=ThreadPhaseBetween(compression_clock,state_clock);
        // Advance only the preparation view. Nothing here is durable.
        for (const PendingState &entry : pending) *entry.destination = entry.next;
        for (const PendingSemanticChain &entry : pending_chains) *entry.destination = entry.next;
        state.segments = proposed_segments;
        state.decisions = proposed_decisions;
        state.first_sequence = proposed_first;
        state.last_sequence = proposed_last;
        if(!defer_compression) {
            state.chain.swap(proposed_chain);
            state.latest_segment_json.swap(latest);
            state.manifest_json.swap(proposed_manifest);
        }
        prepared->state_cost=ThreadPhaseBetween(state_clock,ReadThreadPhaseStamp());
        if(state.config.stage_segment_file_in_prepare && !state.stage_segment(*prepared,error)) {
            state.faulted=true;return false;
        }
        *output = std::move(prepared);
        return true;
    } catch (const std::exception &exception) {
        implementation_->faulted = true;
        set_error(error, std::string("JSONL ledger exception: ") +
            exception.what());
        return false;
    } catch (...) {
        implementation_->faulted = true;
        set_error(error, "JSONL ledger non-standard exception");
        return false;
    }
}

bool NativeFusionJsonlLedger::SupportsGroupedPublication() const noexcept {
    return implementation_ && implementation_->config.synchronous_wal_segments &&
        implementation_->config.group_wal_publication;
}

bool NativeFusionJsonlLedger::PublishPreparedGroup(NativeFusionPreparedCommit *const *items,
        size_t count,NativeFusionCommitResult *results,std::string *error) noexcept {
    if(results)for(size_t i=0;i<count&&i<4;++i)results[i]={};
    if(!SupportsGroupedPublication() || !items || !results || !count ||
       count>4 || count>PreparedCommitCapacity())return false;
    auto &s=*implementation_;
    try {
        if(s.faulted || s.closed || !s.wal_db)return false;
        std::array<Implementation::Prepared *,4> prepared{};
        uint64_t next=s.durable_last+1,bytes=0;rocksdb::WriteBatch batch;
        for(size_t i=0;i<count;++i) {
            auto *p=dynamic_cast<Implementation::Prepared*>(items[i]);
            if(!p || p->owner!=implementation_ || p->segment_index!=s.durable_segments.load()+i ||
               p->first!=next || p->raw_payload || p->staged_ready) {
                s.faulted=true;set_error(error,"group publication owner/order/state is invalid");return false;
            }
            next=p->last+1;bytes+=p->bytes.size();prepared[i]=p;
            batch.Put("segment/"+p->name,p->bytes);
        }
        batch.Put("meta/manifest",prepared[count-1]->manifest);
        Implementation::PublishTiming timing{};
        if(!s.write_wal_batch(batch,count,bytes,&timing,error)){s.faulted=true;return false;}
        // Every member is already durable. Advance observable prefix state and
        // return per-logical-batch receipts only now, in the original order.
        for(size_t i=0;i<count;++i)
            if(!PublishPreparedInternal(items[i],&results[i],error,true))return false;
        results[0].file_sync_cost=timing.file_sync_cost; // count shared I/O once
        return true;
    } catch(...) {s.faulted=true;set_error(error,"group publication exception");return false;}
}

bool NativeFusionJsonlLedger::PublishPrepared(NativeFusionPreparedCommit *opaque,
        NativeFusionCommitResult *result,std::string *error) noexcept {
    return PublishPreparedInternal(opaque,result,error,false);
}
bool NativeFusionJsonlLedger::PublishPreparedInternal(
        NativeFusionPreparedCommit *opaque, NativeFusionCommitResult *result,
        std::string *error,bool already_durable) noexcept {
    if (result) *result = {};
    auto *p = dynamic_cast<Implementation::Prepared *>(opaque);
    if (!implementation_ || !p || !result || p->owner != implementation_ ||
        implementation_->faulted || implementation_->closed ||
        p->segment_index != implementation_->durable_segments.load() ||
        p->first != implementation_->durable_last + 1u) {
        if (implementation_) implementation_->faulted = true;
        set_error(error, "prepared publication owner/order/state is invalid");
        return false;
    }
    auto &state = *implementation_;
    try {
        if(p->raw_payload) {
            const uint64_t started=monotonic_ns();size_t compressed_bytes=0;
            const auto compression_clock=ReadThreadPhaseStamp();
            if(!zstd_level_one(state.zstd_context,p->bytes,&state.zstd_scratch,&compressed_bytes,error) ||
               compressed_bytes>(9u<<20)) {
                state.faulted=true;return false;
            }
            p->compression_ns=elapsed_ns(started,monotonic_ns());
            p->compression_cost=ThreadPhaseBetween(compression_clock,ReadThreadPhaseStamp());
            const uint64_t sealed=monotonic_ns();std::string segment_sha;
            if(!sha256_hex(state.zstd_scratch.data(),compressed_bytes,&segment_sha) ||
               !chain_sha256(state.durable_chain,segment_sha,p->rows,&p->chain)) {
                state.faulted=true;set_error(error,"deferred segment/chain SHA-256 failed");return false;
            }
            std::string latest="{\"bytes\":";append_u64(latest,compressed_bytes);
            latest.append(",\"first_sequence\":");append_u64(latest,p->first);
            latest.append(",\"last_sequence\":");append_u64(latest,p->last);
            latest.append(",\"path\":\"decision_segments/");latest.append(p->name);
            latest.append("\",\"rows\":");append_u64(latest,p->rows);
            latest.append(",\"sha256\":\"");latest.append(segment_sha);
            latest.append("\",\"uncompressed_bytes\":");append_u64(latest,p->raw_bytes);latest.append("}");
            p->manifest=state.manifest_for(p->segment_index+1,p->total_rows,p->first_ever,p->last,latest,p->chain);
            if (state.config.reuse_payload_buffers) {
                // Allocate the small compressed frame before giving up raw
                // ownership; a failed allocation cannot recycle live input.
                std::string compressed(state.zstd_scratch.data(),compressed_bytes);
                p->bytes.swap(compressed);
                compressed.clear();
                {
                    std::lock_guard<std::mutex> lock(state.payload_spare_mutex);
                    if (compressed.capacity() > state.payload_spare.capacity())
                        compressed.swap(state.payload_spare);
                } // Any replaced spare is freed outside the lock.
            } else p->bytes.assign(state.zstd_scratch.data(),compressed_bytes);
            p->raw_payload=false;
            p->prepare_ns+=elapsed_ns(sealed,monotonic_ns());
        }
        // Allocate durable receipt copies before the publish/ACK boundary.
        std::string next_chain = p->chain, next_manifest = p->manifest;
        Implementation::PublishTiming timing{};
        const uint64_t start = monotonic_ns();
        const bool publication_ok=already_durable || (state.config.synchronous_wal_segments?
            state.publish_wal_segment(*p,&timing,error):state.config.stage_segment_file_in_prepare?
            state.publish_staged_segment(*p,&timing,error):
            state.atomic_publish(state.segment_directory + "/" + p->name,
                p->bytes.data(), p->bytes.size(), false,
                Implementation::PublishKind::Segment, &timing, error));
        if (!publication_ok) {
            state.faulted = true;
            return false;
        }
        const uint64_t published = monotonic_ns();
        state.durable_decisions = p->total_rows;
        state.durable_first = p->first_ever;
        state.durable_last = p->last;
        state.durable_chain.swap(next_chain);
        state.durable_manifest.swap(next_manifest);
        state.bytes_committed += p->bytes.size();
        state.uncompressed_bytes_committed += p->raw_bytes;
        state.durable_segments.store(p->segment_index + 1u);
        result->completed_monotonic_ns = monotonic_ns();
        if (result->completed_monotonic_ns < p->last_decision_ns) {
            state.faulted = true; return false;
        }
        result->durability = state.config.synchronous_wal_segments ? NativeFusionDurability::SyncWriteAheadLog : NativeFusionDurability::FsyncRecoverableSegmentDirectory;
        result->serialize_cost=p->serialize_cost;
        result->compression_cost=p->compression_cost;
        result->state_cost=p->state_cost;
        result->file_sync_cost=timing.file_sync_cost;
        result->directory_sync_cost=timing.directory_sync_cost;
        const uint64_t apply = elapsed_ns(published, result->completed_monotonic_ns);
        accumulate_timing(p->validate_ns, state.validate_serialize_total_ns, state.validate_serialize_max_ns);
        accumulate_timing(p->compression_ns, state.compression_total_ns, state.compression_max_ns);
        accumulate_timing(p->prepare_ns, state.prepare_state_total_ns, state.prepare_state_max_ns);
        accumulate_timing(apply, state.state_apply_total_ns, state.state_apply_max_ns);
        // Sum of this segment's own prepare+publish work, excluding pipeline
        // queue/history wait. Different segments can overlap in wall time.
        const uint64_t staged_work=state.config.stage_segment_file_in_prepare?
            p->staged_timing.open_ns+p->staged_timing.write_ns+p->staged_timing.file_fsync_ns+p->staged_timing.publish_ns:0;
        const uint64_t total = p->validate_ns + p->compression_ns + p->prepare_ns
            + staged_work + elapsed_ns(start, result->completed_monotonic_ns);
        if (total > state.slowest_commit_total_ns) {
            state.slowest_commit_total_ns = total;
            state.slowest_commit_segment_index = p->segment_index;
            state.slowest_commit_decisions = p->rows;
            state.slowest_commit_validate_serialize_ns = p->validate_ns;
            state.slowest_commit_compression_ns = p->compression_ns;
            state.slowest_commit_prepare_state_ns = p->prepare_ns;
            state.slowest_commit_segment_open_ns = timing.open_ns;
            state.slowest_commit_segment_write_ns = timing.write_ns;
            state.slowest_commit_segment_file_fsync_ns = timing.file_fsync_ns;
            state.slowest_commit_segment_publish_ns = timing.publish_ns;
            state.slowest_commit_segment_directory_fsync_ns = timing.directory_fsync_ns;
            state.slowest_commit_state_apply_ns = apply;
        }
        return true;
    } catch (...) {
        state.faulted = true;
        set_error(error, "prepared publication exception");
        return false;
    }
}

bool NativeFusionJsonlLedger::Audit(
        NativeFusionJsonlLedgerAudit *audit,
        std::string *error) const noexcept {
    if (implementation_ == nullptr || audit == nullptr) {
        set_error(error, "JSONL ledger audit arguments are invalid");
        return false;
    }
    try {
        *audit = {};
        audit->synchronous_wal_segments=implementation_->config.synchronous_wal_segments;
        audit->wal_test_hook_enabled=implementation_->config.before_wal_write_for_test!=nullptr;
        audit->wal_write_calls=implementation_->wal_write_calls;
        audit->wal_segment_commits=implementation_->wal_segment_commits;
        audit->wal_group_writes=implementation_->wal_group_writes;
        audit->wal_max_group_segments=implementation_->wal_max_group_segments;
        audit->wal_segment_bytes=implementation_->wal_segment_bytes;
        audit->wal_write_wall_ns=implementation_->wal_write_wall_ns;
        audit->wal_write_cpu_ns=implementation_->wal_write_cpu_ns;
        audit->segments_committed = implementation_->durable_segments.load();
        audit->decisions_committed = implementation_->durable_decisions;
        audit->first_sequence = implementation_->durable_first;
        audit->last_sequence = implementation_->durable_last;
        audit->segment_fsync_calls = implementation_->segment_fsync_calls;
        audit->segment_directory_fsync_calls =
            implementation_->segment_directory_fsync_calls;
        audit->manifest_fsync_calls = implementation_->manifest_fsync_calls;
        audit->initial_manifest_fsync_calls =
            implementation_->initial_manifest_fsync_calls;
        audit->commit_manifest_fsync_calls =
            implementation_->commit_manifest_fsync_calls;
        audit->closure_manifest_fsync_calls =
            implementation_->closure_manifest_fsync_calls;
        audit->directory_fsync_calls = implementation_->directory_fsync_calls;
        audit->bytes_committed = implementation_->bytes_committed;
        audit->uncompressed_bytes_committed =
            implementation_->uncompressed_bytes_committed;
        audit->payload_buffer_reuse_enabled=implementation_->config.reuse_payload_buffers;
        audit->payload_buffer_moves=implementation_->payload_buffer_moves;
        audit->payload_buffer_moved_bytes=implementation_->payload_buffer_moved_bytes;
        audit->payload_buffer_reuse_hits=implementation_->payload_buffer_reuse_hits;
        audit->stage_segment_file_in_prepare_enabled=implementation_->config.stage_segment_file_in_prepare;
        audit->staged_segments_prepared=implementation_->staged_segments_prepared;
        audit->staged_records_prepared=implementation_->staged_records_prepared;
        audit->staged_payload_bytes_prepared=implementation_->staged_payload_bytes_prepared;
        audit->staged_publish_calls=implementation_->staged_publish_calls;
        audit->staged_publish_succeeded=implementation_->staged_publish_succeeded;
        if(implementation_->staged_accounting){
            const auto &a=*implementation_->staged_accounting;
            audit->staged_files_outstanding=a.files.load(std::memory_order_relaxed);
            audit->staged_files_peak=a.peak_files.load(std::memory_order_relaxed);
            audit->staged_bytes_outstanding=a.bytes.load(std::memory_order_relaxed);
            audit->staged_bytes_peak=a.peak_bytes.load(std::memory_order_relaxed);
        }
        audit->validate_serialize_total_ns =
            implementation_->validate_serialize_total_ns;
        audit->validate_serialize_max_ns =
            implementation_->validate_serialize_max_ns;
        audit->compression_total_ns = implementation_->compression_total_ns;
        audit->compression_max_ns = implementation_->compression_max_ns;
        audit->prepare_state_total_ns =
            implementation_->prepare_state_total_ns;
        audit->prepare_state_max_ns = implementation_->prepare_state_max_ns;
        audit->segment_open_total_ns =
            implementation_->segment_open_total_ns;
        audit->segment_open_max_ns = implementation_->segment_open_max_ns;
        audit->segment_write_total_ns =
            implementation_->segment_write_total_ns;
        audit->segment_write_max_ns = implementation_->segment_write_max_ns;
        audit->segment_file_fsync_total_ns =
            implementation_->segment_file_fsync_total_ns;
        audit->segment_file_fsync_max_ns =
            implementation_->segment_file_fsync_max_ns;
        audit->segment_publish_total_ns =
            implementation_->segment_publish_total_ns;
        audit->segment_publish_max_ns =
            implementation_->segment_publish_max_ns;
        audit->segment_directory_fsync_total_ns =
            implementation_->segment_directory_fsync_total_ns;
        audit->segment_directory_fsync_max_ns =
            implementation_->segment_directory_fsync_max_ns;
        audit->state_apply_total_ns = implementation_->state_apply_total_ns;
        audit->state_apply_max_ns = implementation_->state_apply_max_ns;
        audit->slowest_commit_total_ns =
            implementation_->slowest_commit_total_ns;
        audit->slowest_commit_segment_index =
            implementation_->slowest_commit_segment_index;
        audit->slowest_commit_decisions =
            implementation_->slowest_commit_decisions;
        audit->slowest_commit_validate_serialize_ns =
            implementation_->slowest_commit_validate_serialize_ns;
        audit->slowest_commit_compression_ns =
            implementation_->slowest_commit_compression_ns;
        audit->slowest_commit_prepare_state_ns =
            implementation_->slowest_commit_prepare_state_ns;
        audit->slowest_commit_segment_open_ns =
            implementation_->slowest_commit_segment_open_ns;
        audit->slowest_commit_segment_write_ns =
            implementation_->slowest_commit_segment_write_ns;
        audit->slowest_commit_segment_file_fsync_ns =
            implementation_->slowest_commit_segment_file_fsync_ns;
        audit->slowest_commit_segment_publish_ns =
            implementation_->slowest_commit_segment_publish_ns;
        audit->slowest_commit_segment_directory_fsync_ns =
            implementation_->slowest_commit_segment_directory_fsync_ns;
        audit->slowest_commit_state_apply_ns =
            implementation_->slowest_commit_state_apply_ns;
        audit->chain_sha256 = implementation_->durable_chain;
        audit->manifest_json = implementation_->durable_manifest;
        audit->manifest_path = implementation_->manifest_path;
        audit->faulted = implementation_->faulted ? 1u : 0u;
        audit->closed = implementation_->closed ? 1u : 0u;
        return true;
    } catch (...) {
        set_error(error, "JSONL ledger audit allocation failed");
        return false;
    }
}

bool NativeFusionJsonlLedger::Close(std::string *error) noexcept {
    if (implementation_ == nullptr)
        return true;
    if (implementation_->closed)
        return !implementation_->faulted;
    bool success = true;
    if (implementation_->last_sequence != implementation_->durable_last)
        implementation_->faulted = true;
    if (!implementation_->faulted) {
        success = implementation_->atomic_publish(
            implementation_->manifest_path,
            implementation_->durable_manifest,
            true,
            Implementation::PublishKind::ClosureManifest,
            error);
    }
    if (implementation_->lock_fd >= 0) {
        const bool lock_closed = ::close(implementation_->lock_fd) == 0;
        success = success && lock_closed;
        implementation_->lock_fd = -1;
    }
    implementation_->wal_db.reset(); // Join database background work inside service drain.
    implementation_->closed = true;
    if (!success) {
        implementation_->faulted = true;
        if (error == nullptr || error->empty())
            set_error(error, "JSONL ledger closure durability failed");
    }
    return success && !implementation_->faulted;
}

}  // namespace flowkeep
