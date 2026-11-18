#define _POSIX_C_SOURCE 200809L

#include "fk_no_nic_pcap_runner.h"

#include "fk_actor_namespace_monitor_map.h"
#include "fk_compact_runtime.h"
#include "fk_exact_identity_sequencer.h"
#include "fk_fixed_ttl_retention_contract.h"
#include "fk_no_nic_decision_trace_csv.h"
#include "fk_no_nic_full_composition.h"
#include "fk_quic_cid_map.h"
#include "fk_quic_presentation_path_directory.h"
#include "fk_source_record_intervention_plan.h"

#include <rte_mbuf.h>
#include <rte_cycles.h>

#include <openssl/evp.h>

#include <array>
#include <cerrno>
#include <chrono>
#include <cinttypes>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <limits>
#include <memory>
#include <new>
#include <string>
#include <sys/stat.h>
#include <time.h>

namespace {

constexpr uint32_t kMaximumFrameBytes = UINT16_MAX;
constexpr uint16_t kMbufPoolCapacity = 64u;
constexpr uint16_t kBurstCapacity = 32u;
constexpr uint32_t kDefaultMaximumFlows = 45056u;
constexpr uint64_t kIdleTimeoutNs = UINT64_C(120000000000);
constexpr size_t kSha256Bytes = 32u;
constexpr const char *kDefaultOwnerHashKeyHex =
    "3132333435363738393a3b3c3d3e3f40";

uint64_t steady_monotonic_ns() {
    return static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::nanoseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count());
}

uint64_t process_cpu_ns() {
    struct timespec value{};
    if (clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &value) != 0)
        return 0u;
    return static_cast<uint64_t>(value.tv_sec) * UINT64_C(1000000000) +
        static_cast<uint64_t>(value.tv_nsec);
}

struct WholePipelineTiming {
    uint64_t wall_ns{};
    uint64_t process_cpu_ns{};
    uint64_t tsc_cycles{};
    uint64_t tsc_hz{};
    bool complete{};
};

void set_error(char *error, size_t capacity, const char *message) {
    if (error != nullptr && capacity != 0u)
        std::snprintf(error, capacity, "%s", message == nullptr ? "" : message);
}

uint16_t decode_u16(const uint8_t *bytes, bool little_endian) {
    return little_endian
        ? static_cast<uint16_t>(
              static_cast<uint16_t>(bytes[0]) |
              static_cast<uint16_t>(bytes[1]) << 8u)
        : static_cast<uint16_t>(
              static_cast<uint16_t>(bytes[0]) << 8u |
              static_cast<uint16_t>(bytes[1]));
}

uint32_t decode_u32(const uint8_t *bytes, bool little_endian) {
    if (little_endian) {
        return static_cast<uint32_t>(bytes[0]) |
            static_cast<uint32_t>(bytes[1]) << 8u |
            static_cast<uint32_t>(bytes[2]) << 16u |
            static_cast<uint32_t>(bytes[3]) << 24u;
    }
    return static_cast<uint32_t>(bytes[0]) << 24u |
        static_cast<uint32_t>(bytes[1]) << 16u |
        static_cast<uint32_t>(bytes[2]) << 8u |
        static_cast<uint32_t>(bytes[3]);
}

bool checked_add(uint64_t &value, uint64_t increment) {
    if (increment > std::numeric_limits<uint64_t>::max() - value)
        return false;
    value += increment;
    return true;
}

class Sha256Stream {
public:
    Sha256Stream() = default;
    ~Sha256Stream() {
        if (context_ != nullptr)
            EVP_MD_CTX_free(context_);
    }
    Sha256Stream(const Sha256Stream &) = delete;
    Sha256Stream &operator=(const Sha256Stream &) = delete;

    bool begin() {
        if (context_ == nullptr)
            context_ = EVP_MD_CTX_new();
        active_ = context_ != nullptr &&
            EVP_DigestInit_ex(context_, EVP_sha256(), nullptr) == 1;
        return active_;
    }

    bool update(const void *bytes, size_t length) {
        return active_ && bytes != nullptr &&
            EVP_DigestUpdate(context_, bytes, length) == 1;
    }

    bool finish(std::array<uint8_t, kSha256Bytes> &digest) {
        unsigned int length = 0u;
        if (!active_ ||
            EVP_DigestFinal_ex(context_, digest.data(), &length) != 1 ||
            length != digest.size()) {
            return false;
        }
        active_ = false;
        return true;
    }

private:
    EVP_MD_CTX *context_ = nullptr;
    bool active_ = false;
};

enum class RecordStatus : uint8_t {
    End,
    Ready,
    Error,
};

struct PcapRecord {
    uint64_t timestamp_ns = 0u;
    uint32_t captured_length = 0u;
    uint32_t wire_length = 0u;
};

struct PcapScan {
    uint64_t packets = 0u;
    uint64_t captured_bytes = 0u;
    uint64_t wire_bytes = 0u;
    uint64_t first_timestamp_ns = 0u;
    uint64_t last_timestamp_ns = 0u;
    uint64_t file_bytes = 0u;
    uint32_t snap_length = 0u;
    std::array<uint8_t, kSha256Bytes> sha256{};
    bool nanosecond_resolution = false;
    bool little_endian = true;
};

struct PcapSlot {
    alignas(RTE_CACHE_LINE_SIZE)
        std::array<uint8_t, sizeof(rte_mbuf)> mbuf_storage{};
    alignas(RTE_CACHE_LINE_SIZE)
        std::array<uint8_t, kMaximumFrameBytes> frame{};
    uint64_t sequence = 0u;
    uint64_t timestamp_ns = 0u;
    uint64_t physical_ingress_ns = 0u;
    uint32_t wire_length = 0u;
    bool in_use = false;

    rte_mbuf *mbuf() {
        return reinterpret_cast<rte_mbuf *>(mbuf_storage.data());
    }

    void initialize_mbuf(uint32_t length) {
        (void)new (mbuf_storage.data()) rte_mbuf{};
        rte_mbuf *packet = mbuf();
        packet->buf_addr = frame.data();
        packet->buf_iova = RTE_BAD_IOVA;
        packet->buf_len = static_cast<uint16_t>(length);
        packet->data_off = 0u;
        packet->data_len = static_cast<uint16_t>(length);
        packet->pkt_len = length;
        packet->nb_segs = 1u;
        packet->next = nullptr;
        rte_mbuf_refcnt_set(packet, 1u);
    }
};

class BoundedPcapSource {
public:
    BoundedPcapSource()
        : slots_(std::make_unique<PcapSlot[]>(kMbufPoolCapacity)) {}

    ~BoundedPcapSource() {
        if (stream_ != nullptr)
            std::fclose(stream_);
    }

    BoundedPcapSource(const BoundedPcapSource &) = delete;
    BoundedPcapSource &operator=(const BoundedPcapSource &) = delete;

    bool open_scan_and_rewind(
            const char *path,
            PcapScan &scan,
            char *error,
            size_t error_capacity) {
        set_error(error, error_capacity, "");
        if (path == nullptr || stream_ != nullptr) {
            set_error(error, error_capacity, "invalid PCAP source path/state");
            return false;
        }
        stream_ = std::fopen(path, "rb");
        if (stream_ == nullptr) {
            set_error(error, error_capacity, "cannot open PCAP input");
            return false;
        }
        struct stat status{};
        if (fstat(fileno(stream_), &status) != 0 || status.st_size < 0) {
            set_error(error, error_capacity, "cannot stat PCAP input");
            return false;
        }
        scan.file_bytes = static_cast<uint64_t>(status.st_size);
        uint8_t header[24]{};
        if (std::fread(header, 1u, sizeof(header), stream_) !=
            sizeof(header)) {
            set_error(error, error_capacity, "truncated classic PCAP header");
            return false;
        }
        Sha256Stream scan_digest;
        if (!scan_digest.begin() ||
            !scan_digest.update(header, sizeof(header))) {
            set_error(error, error_capacity, "cannot initialize PCAP SHA-256");
            return false;
        }
        if (header[0] == 0x0au && header[1] == 0x0du &&
            header[2] == 0x0du && header[3] == 0x0au) {
            set_error(error, error_capacity,
                "PCAPNG is unsupported; classic Ethernet PCAP is required");
            return false;
        }
        if (std::memcmp(header, "\xd4\xc3\xb2\xa1", 4u) == 0) {
            little_endian_ = true;
            nanoseconds_ = false;
        } else if (std::memcmp(header, "\xa1\xb2\xc3\xd4", 4u) == 0) {
            little_endian_ = false;
            nanoseconds_ = false;
        } else if (std::memcmp(header, "\x4d\x3c\xb2\xa1", 4u) == 0) {
            little_endian_ = true;
            nanoseconds_ = true;
        } else if (std::memcmp(header, "\xa1\xb2\x3c\x4d", 4u) == 0) {
            little_endian_ = false;
            nanoseconds_ = true;
        } else {
            set_error(error, error_capacity, "unsupported classic PCAP magic");
            return false;
        }
        const uint16_t major = decode_u16(header + 4u, little_endian_);
        const uint16_t minor = decode_u16(header + 6u, little_endian_);
        snap_length_ = decode_u32(header + 16u, little_endian_);
        const uint32_t link_type = decode_u32(header + 20u, little_endian_);
        if (major != 2u || minor != 4u) {
            set_error(error, error_capacity, "unsupported classic PCAP version");
            return false;
        }
        if (link_type != 1u) {
            set_error(error, error_capacity,
                "classic PCAP link type must be Ethernet (DLT_EN10MB=1)");
            return false;
        }
        /* The classic-PCAP global snaplen is only a declared capture bound.
         * Common libpcap writers use 262144 even for ordinary Ethernet
         * frames.  Keep the hot-path buffer bound on every record below;
         * rejecting a safe trace solely because its declared bound is wider
         * would make the exact Validation replay unnecessarily unusable. */
        if (snap_length_ < 14u) {
            set_error(error, error_capacity, "unsupported PCAP snapshot length");
            return false;
        }

        uint64_t prior_timestamp = 0u;
        bool timestamp_initialized = false;
        for (;;) {
            PcapRecord record{};
            const RecordStatus result = read_record(
                record,
                scan_scratch_.data(),
                &scan_digest,
                error,
                error_capacity);
            if (result == RecordStatus::End)
                break;
            if (result != RecordStatus::Ready)
                return false;
            if (timestamp_initialized &&
                record.timestamp_ns < prior_timestamp) {
                set_error(error, error_capacity,
                    "PCAP timestamps regress; exact semantic order rejected");
                return false;
            }
            if (scan.packets == 0u)
                scan.first_timestamp_ns = record.timestamp_ns;
            scan.last_timestamp_ns = record.timestamp_ns;
            prior_timestamp = record.timestamp_ns;
            timestamp_initialized = true;
            if (scan.packets == UINT32_MAX ||
                scan.packets + 1u >=
                    FK_EXACT_IDENTITY_SEQUENCER_MAX_PACKETS ||
                !checked_add(scan.packets, 1u) ||
                !checked_add(
                    scan.captured_bytes, record.captured_length) ||
                !checked_add(scan.wire_bytes, record.wire_length)) {
                set_error(error, error_capacity, "PCAP counter range exceeded");
                return false;
            }
        }
        if (scan.packets == 0u) {
            set_error(error, error_capacity,
                "empty PCAP cannot form a non-empty exact epoch");
            return false;
        }
        if (!scan_digest.finish(scan.sha256)) {
            set_error(error, error_capacity, "cannot finalize PCAP SHA-256");
            return false;
        }
        scan.snap_length = snap_length_;
        scan.nanosecond_resolution = nanoseconds_;
        scan.little_endian = little_endian_;
        expected_packets_ = scan.packets;
        expected_wire_bytes_ = scan.wire_bytes;
        expected_sha256_ = scan.sha256;
        router_now_ns_ = 0u;
        if (fseeko(stream_, 24, SEEK_SET) != 0) {
            set_error(error, error_capacity, "cannot rewind classic PCAP records");
            return false;
        }
        clearerr(stream_);
        if (!replay_digest_.begin() ||
            !replay_digest_.update(header, sizeof(header))) {
            set_error(error, error_capacity,
                "cannot initialize replay PCAP SHA-256");
            return false;
        }
        return true;
    }

    static bool burst_callback(
            void *context,
            uint16_t,
            uint16_t,
            rte_mbuf **packets,
            uint16_t capacity,
            uint16_t *received) {
        return context != nullptr &&
            static_cast<BoundedPcapSource *>(context)->burst(
                packets, capacity, received);
    }

    static bool clock_callback(void *context, uint64_t *timestamp_ns) {
        return context != nullptr &&
            static_cast<BoundedPcapSource *>(context)->clock(timestamp_ns);
    }

    static bool decode_callback(
            void *context,
            const rte_mbuf *packet,
            uint16_t,
            uint64_t physical_ingress_timestamp_ns,
            uint64_t *packet_sequence,
            uint64_t *semantic_timestamp_ns,
            uint32_t *wire_length) {
        return context != nullptr &&
            static_cast<BoundedPcapSource *>(context)->decode(
                packet,
                physical_ingress_timestamp_ns,
                packet_sequence,
                semantic_timestamp_ns,
                wire_length);
    }

    static bool reclaim_callback(void *context, rte_mbuf *packet) {
        return context != nullptr &&
            static_cast<BoundedPcapSource *>(context)->reclaim(packet);
    }

    static bool monotonic_now_callback(
            void *context, uint64_t *timestamp_ns) {
        if (context == nullptr || timestamp_ns == nullptr)
            return false;
        return static_cast<BoundedPcapSource *>(context)->monotonic_now(
            timestamp_ns);
    }

    static bool stats_callback(
            void *context,
            fk_no_nic_full_composition_io_stats_v1 *stats) {
        if (context == nullptr || stats == nullptr)
            return false;
        const auto &source = *static_cast<BoundedPcapSource *>(context);
        *stats = {};
        stats->acquired_packets = source.acquired_packets_;
        stats->acquired_wire_bytes = source.acquired_wire_bytes_;
        stats->reclaim_attempts = source.reclaim_attempts_;
        stats->reclaim_successes = source.reclaim_successes_;
        stats->duplicate_reclaims = source.duplicate_reclaims_;
        stats->live_mbufs = source.live_mbufs_;
        stats->forced_failure_reclaims =
            source.forced_failure_reclaims_;
        stats->bounded_source_reserved_bytes =
            static_cast<uint64_t>(kMbufPoolCapacity) * sizeof(PcapSlot);
        stats->bounded_source_peak_bytes =
            stats->bounded_source_reserved_bytes;
        stats->bounded_source_capacity = kMbufPoolCapacity;
        stats->source_exhausted =
            source.source_exhausted_ ? 1u : 0u;
        stats->source_failed = source.source_failed_ ? 1u : 0u;
        stats->accounting_conserved =
            source.source_exhausted_ && !source.source_failed_ &&
                    source.replay_digest_verified_ &&
                    source.acquired_packets_ == source.expected_packets_ &&
                    source.acquired_wire_bytes_ ==
                        source.expected_wire_bytes_ &&
                    source.reclaim_successes_ ==
                        source.acquired_packets_ &&
                    source.live_mbufs_ == 0u &&
                    source.duplicate_reclaims_ == 0u
                ? 1u : 0u;
        stats->ownership_recovered =
            source.live_mbufs_ == 0u &&
                    source.reclaim_successes_ +
                            source.forced_failure_reclaims_ ==
                        source.acquired_packets_
                ? 1u : 0u;
        stats->bounded_source_memory_exact = 1u;
        stats->bounded_source_trace_independent = 1u;
        return true;
    }

    uint64_t recover_owned_slots_after_pipeline_failure() noexcept {
        source_failed_ = true;
        uint64_t recovered = 0u;
        for (uint16_t index = 0u; index < kMbufPoolCapacity; ++index) {
            PcapSlot &slot = slots_[index];
            if (!slot.in_use)
                continue;
            slot.in_use = false;
            ++recovered;
        }
        if (recovered > live_mbufs_) {
            duplicate_reclaims_++;
            live_mbufs_ = 0u;
        } else {
            live_mbufs_ -= recovered;
        }
        forced_failure_reclaims_ += recovered;
        return recovered;
    }

private:
    RecordStatus read_record(
            PcapRecord &record,
            uint8_t *payload,
            Sha256Stream *digest,
            char *error,
            size_t error_capacity) {
        uint8_t header[16]{};
        const size_t bytes = std::fread(header, 1u, sizeof(header), stream_);
        if (bytes == 0u && std::feof(stream_))
            return RecordStatus::End;
        if (bytes != sizeof(header)) {
            set_error(error, error_capacity, "truncated classic PCAP record header");
            return RecordStatus::Error;
        }
        const uint32_t seconds = decode_u32(header, little_endian_);
        const uint32_t fraction = decode_u32(header + 4u, little_endian_);
        record.captured_length = decode_u32(header + 8u, little_endian_);
        record.wire_length = decode_u32(header + 12u, little_endian_);
        const uint32_t fraction_limit =
            nanoseconds_ ? UINT32_C(1000000000) : UINT32_C(1000000);
        if (fraction >= fraction_limit || record.captured_length < 14u ||
            record.captured_length > snap_length_ ||
            record.captured_length > kMaximumFrameBytes ||
            record.wire_length != record.captured_length) {
            set_error(error, error_capacity,
                "invalid/truncated PCAP record; exact full capture required");
            return RecordStatus::Error;
        }
        const uint64_t fraction_ns = nanoseconds_
            ? fraction : static_cast<uint64_t>(fraction) * 1000u;
        record.timestamp_ns = static_cast<uint64_t>(seconds) *
                UINT64_C(1000000000) +
            fraction_ns;
        if (record.timestamp_ns == 0u) {
            set_error(error, error_capacity, "zero PCAP timestamp rejected");
            return RecordStatus::Error;
        }
        if (std::fread(
                payload, 1u, record.captured_length, stream_) !=
            record.captured_length) {
            set_error(error, error_capacity, "truncated classic PCAP frame bytes");
            return RecordStatus::Error;
        }
        if (digest == nullptr || !digest->update(header, sizeof(header)) ||
            !digest->update(payload, record.captured_length)) {
            set_error(error, error_capacity, "PCAP SHA-256 update failed");
            return RecordStatus::Error;
        }
        return RecordStatus::Ready;
    }

    PcapSlot *free_slot() {
        for (uint16_t index = 0u; index < kMbufPoolCapacity; ++index) {
            if (!slots_[index].in_use)
                return &slots_[index];
        }
        return nullptr;
    }

    PcapSlot *find_slot(const rte_mbuf *packet) {
        for (uint16_t index = 0u; index < kMbufPoolCapacity; ++index) {
            if (slots_[index].mbuf() == packet)
                return &slots_[index];
        }
        return nullptr;
    }

    bool rollback_batch(
            off_t offset,
            uint16_t count,
            uint64_t prior_sequence,
            uint64_t prior_timestamp) {
        for (uint16_t index = 0u; index < count; ++index) {
            clock_batch_[index]->physical_ingress_ns = 0u;
            clock_batch_[index]->in_use = false;
        }
        clock_count_ = 0u;
        clock_cursor_ = 0u;
        next_sequence_ = prior_sequence;
        prior_timestamp_ns_ = prior_timestamp;
        clearerr(stream_);
        return fseeko(stream_, offset, SEEK_SET) == 0;
    }

    bool finish_replay_digest(char *error, size_t error_capacity) {
        if (replay_digest_verified_)
            return true;
        const int trailing = std::fgetc(stream_);
        if (trailing != EOF || !std::feof(stream_)) {
            set_error(error, error_capacity,
                "PCAP changed after preflight or has trailing records");
            return false;
        }
        std::array<uint8_t, kSha256Bytes> observed{};
        if (!replay_digest_.finish(observed) || observed != expected_sha256_) {
            set_error(error, error_capacity,
                "PCAP changed between preflight and bounded replay");
            return false;
        }
        replay_digest_verified_ = true;
        return true;
    }

    bool burst(
            rte_mbuf **packets,
            uint16_t capacity,
            uint16_t *received) {
        if (packets == nullptr || received == nullptr || capacity == 0u ||
            capacity > kBurstCapacity || source_failed_) {
            if (received != nullptr)
                *received = 0u;
            return false;
        }
        *received = 0u;
        if (next_sequence_ == expected_packets_) {
            if (!replay_digest_verified_) {
                source_failed_ = true;
                return false;
            }
            source_exhausted_ = true;
            return true;
        }
        if (clock_cursor_ != clock_count_) {
            source_failed_ = true;
            return false;
        }
        const off_t batch_offset = ftello(stream_);
        if (batch_offset < 0) {
            source_failed_ = true;
            return false;
        }
        const uint64_t prior_sequence = next_sequence_;
        const uint64_t prior_timestamp = prior_timestamp_ns_;
        uint16_t count = 0u;
        uint64_t batch_wire_bytes = 0u;
        char detail[160]{};
        while (count < capacity && next_sequence_ + count < expected_packets_) {
            PcapSlot *slot = free_slot();
            if (slot == nullptr)
                break;
            slot->in_use = true;
            clock_batch_[count] = slot;
            PcapRecord record{};
            const RecordStatus status = read_record(
                record,
                slot->frame.data(),
                &replay_digest_,
                detail,
                sizeof(detail));
            if (status != RecordStatus::Ready ||
                (next_sequence_ + count != 0u &&
                 record.timestamp_ns <
                     (count == 0u ? prior_timestamp_ns_
                                  : clock_batch_[count - 1u]->timestamp_ns)) ||
                !checked_add(batch_wire_bytes, record.wire_length)) {
                source_failed_ = true;
                (void)rollback_batch(
                    batch_offset,
                    static_cast<uint16_t>(count + 1u),
                    prior_sequence,
                    prior_timestamp);
                return false;
            }
            slot->sequence = next_sequence_ + count;
            slot->timestamp_ns = record.timestamp_ns;
            slot->wire_length = record.wire_length;
            slot->initialize_mbuf(record.captured_length);
            packets[count] = slot->mbuf();
            ++count;
        }
        if (count == 0u)
            return true;
        if (next_sequence_ + count == expected_packets_ &&
            !finish_replay_digest(detail, sizeof(detail))) {
            source_failed_ = true;
            (void)rollback_batch(
                batch_offset, count, prior_sequence, prior_timestamp);
            return false;
        }
        next_sequence_ += count;
        acquired_packets_ += count;
        acquired_wire_bytes_ += batch_wire_bytes;
        live_mbufs_ += count;
        prior_timestamp_ns_ = clock_batch_[count - 1u]->timestamp_ns;
        clock_count_ = count;
        clock_cursor_ = 0u;
        source_exhausted_ = next_sequence_ == expected_packets_;
        *received = count;
        return true;
    }

    bool clock(uint64_t *timestamp_ns) {
        if (timestamp_ns == nullptr || clock_cursor_ >= clock_count_)
            return false;
        PcapSlot *slot = clock_batch_[clock_cursor_++];
        if (slot == nullptr || !slot->in_use || slot->timestamp_ns == 0u)
            return false;
        uint64_t now_ns = steady_monotonic_ns();
        if (now_ns == 0u)
            return false;
        if (now_ns <= router_now_ns_)
            now_ns = router_now_ns_ + 1u;
        slot->physical_ingress_ns = now_ns;
        router_now_ns_ = now_ns;
        *timestamp_ns = now_ns;
        return true;
    }

    bool monotonic_now(uint64_t *timestamp_ns) {
        if (timestamp_ns == nullptr)
            return false;
        uint64_t now_ns = steady_monotonic_ns();
        if (now_ns == 0u)
            return false;
        if (now_ns < router_now_ns_)
            now_ns = router_now_ns_;
        router_now_ns_ = now_ns;
        *timestamp_ns = now_ns;
        return true;
    }

    bool decode(
            const rte_mbuf *packet,
            uint64_t physical_ingress_timestamp_ns,
            uint64_t *packet_sequence,
            uint64_t *semantic_timestamp_ns,
            uint32_t *wire_length) {
        if (packet == nullptr || packet_sequence == nullptr ||
            semantic_timestamp_ns == nullptr || wire_length == nullptr)
            return false;
        PcapSlot *slot = find_slot(packet);
        if (slot == nullptr || !slot->in_use ||
            physical_ingress_timestamp_ns != slot->physical_ingress_ns ||
            slot->wire_length != packet->pkt_len)
            return false;
        *packet_sequence = slot->sequence;
        *semantic_timestamp_ns = slot->timestamp_ns;
        *wire_length = slot->wire_length;
        return true;
    }

    bool reclaim(rte_mbuf *packet) {
        ++reclaim_attempts_;
        PcapSlot *slot = find_slot(packet);
        if (slot == nullptr || !slot->in_use || live_mbufs_ == 0u) {
            ++duplicate_reclaims_;
            source_failed_ = true;
            return false;
        }
        slot->in_use = false;
        slot->physical_ingress_ns = 0u;
        slot->mbuf()->ol_flags ^= UINT64_C(0x8000000000000000);
        ++reclaim_successes_;
        --live_mbufs_;
        return true;
    }

    FILE *stream_ = nullptr;
    bool little_endian_ = true;
    bool nanoseconds_ = false;
    uint32_t snap_length_ = 0u;
    std::unique_ptr<PcapSlot[]> slots_;
    std::array<PcapSlot *, kBurstCapacity> clock_batch_{};
    std::array<uint8_t, kMaximumFrameBytes> scan_scratch_{};
    Sha256Stream replay_digest_;
    std::array<uint8_t, kSha256Bytes> expected_sha256_{};
    uint16_t clock_count_ = 0u;
    uint16_t clock_cursor_ = 0u;
    uint64_t expected_packets_ = 0u;
    uint64_t expected_wire_bytes_ = 0u;
    uint64_t router_now_ns_ = 0u;
    uint64_t prior_timestamp_ns_ = 0u;
    uint64_t next_sequence_ = 0u;
    uint64_t acquired_packets_ = 0u;
    uint64_t acquired_wire_bytes_ = 0u;
    uint64_t reclaim_attempts_ = 0u;
    uint64_t reclaim_successes_ = 0u;
    uint64_t forced_failure_reclaims_ = 0u;
    uint64_t duplicate_reclaims_ = 0u;
    uint64_t live_mbufs_ = 0u;
    bool source_exhausted_ = false;
    bool source_failed_ = false;
    bool replay_digest_verified_ = false;
};

struct Options {
    const char *pcap = nullptr;
    const char *action_model = nullptr;
    const char *value_model_v3_artifact = nullptr;
    const char *value_model_v3_artifact_sha = nullptr;
    const char *value_model_v3_training_receipt_sha = nullptr;
    const char *value_model_v3_schema_sha = nullptr;
    const char *value_model_v3_action_domain_sha = nullptr;
    const char *value_model_v3_deadline_contract_sha = nullptr;
    const char *transition_value_model = nullptr;
    const char *transition_value_schema_sha = nullptr;
    const char *transition_value_model_sha = nullptr;
    enum fk_value_model_v3_role value_model_v3_role =
        static_cast<enum fk_value_model_v3_role>(0);
    const char *detector_model = nullptr;
    const char *detector_state_model_dir = nullptr;
    const char *action_schema = nullptr;
    const char *detector_schema = nullptr;
    const char *event_student_artifact = nullptr;
    const char *event_student_artifact_sha = nullptr;
    const char *event_student_feature_schema_sha = nullptr;
    const char *event_student_source_state_sha = nullptr;
    const char *aggregation_mode = nullptr;
    const char *aggregation_rule = nullptr;
    const char *aggregation_threshold_profile = nullptr;
    const char *aggregation_contract_sha = nullptr;
    const char *development_oof_receipt_sha = nullptr;
    const char *causal_event_calibrator_artifact = nullptr;
    const char *causal_event_calibrator_artifact_sha = nullptr;
    const char *causal_event_calibrator_source_npz_sha = nullptr;
    const char *causal_event_calibrator_feature_contract_sha = nullptr;
    const char *causal_event_calibrator_real_prefix_receipt_sha = nullptr;
    float aggregation_threshold = 0.0f;
    const char *monitored_cidr = nullptr;
    const char *actor_identity_contract_sha = nullptr;
    const char *actor_namespace_monitor_map = nullptr;
    const char *actor_namespace_monitor_map_sha256 = nullptr;
    const char *compact_monitored_ipv4_pool = nullptr;
    uint32_t compact_monitored_ipv4_slots_per_namespace = 0u;
    uint32_t compact_monitored_ipv4_namespace_count = 0u;
    uint32_t compact_monitored_ipv4_identity_index = 0u;
    uint64_t expected_flow_capacity_rollovers = 0u;
    const char *decision_trace = nullptr;
    const char *decision_trace_features = nullptr;
    const char *development_source_record_intervention_plan = nullptr;
    const char *development_packet_lineage = nullptr;
    uint32_t event_student_hidden = 0u;
    uint32_t event_student_identity_embedding = 0u;
    const char *output = nullptr;
    fk_no_nic_full_composition_budget_mode budget =
        FK_NO_NIC_FULL_COMPOSITION_BUDGET_16_MIB;
    uint32_t maximum_flows = kDefaultMaximumFlows;
    uint32_t actor_maximum_total_flows =
        FK_ACTOR_SESSION_DEFAULT_TOTAL_FLOWS;
    const char *owner_hash_key_hex = kDefaultOwnerHashKeyHex;
    uint32_t maximum_quic_connections = 0u;
    const char *budget_name = "16";
    fk_component_pool_weights pool_weights{};
    bool pool_weights_seen = false;
    float lambda_memory_per_byte = 0.0f;
    float lambda_queue = 0.0f;
    float lambda_deadline = 0.0f;
    float retention_discount = 0.0f;
    bool lambda_memory_seen = false;
    bool lambda_queue_seen = false;
    bool lambda_deadline_seen = false;
    bool retention_discount_seen = false;
    fk_compact_retention_policy_kind retention_policy =
        FK_COMPACT_POLICY_FLOWKEEP;
    const char *retention_policy_name = "flowkeep";
    fk_fixed_ttl_retention_binding fixed_ttl_retention{};
    uint64_t seeded_random_retention_seed = 0u;
    const char *retention_detector_coupling = nullptr;
    const char *detector_scheduling = nullptr;
    uint32_t detector_deadline_us = 0u;
    bool retention_policy_seen = false;
    bool seeded_random_retention_seed_seen = false;
    bool detector_deadline_seen = false;
    bool aggregation_threshold_seen = false;
    bool value_model_v3_role_seen = false;
    bool compact_monitored_ipv4_slots_seen = false;
    bool compact_monitored_ipv4_namespace_count_seen = false;
    bool compact_monitored_ipv4_identity_index_seen = false;
    bool expected_flow_capacity_rollovers_seen = false;
    bool owner_hash_key_seen = false;
};

struct DecisionTraceFeaturesReceipt {
    std::array<uint8_t, kSha256Bytes> sha256{};
    uint64_t rows = 0u;
    bool enabled = false;
    bool sha256_valid = false;
    bool row_conservation_valid = false;
};

struct ActorNamespaceMonitorMapInput {
    fk_actor_namespace_monitor_map_metadata metadata{};
    std::unique_ptr<uint32_t[]> indices;
    std::array<uint8_t, kSha256Bytes> whole_file_sha256{};
    uint64_t file_bytes = 0u;
    uint32_t minimum_identity_index = 0u;
    uint32_t maximum_identity_index = 0u;
    bool requested = false;
    bool loaded = false;
    bool whole_file_sha256_verified = false;
    bool actor_session_configured = false;
};

struct RetentionDetectorCompositionReceipt {
    uint64_t checkpoint_records = 0u;
    uint64_t fifo_order_violations = 0u;
    uint64_t maximum_flow_detector_latency_ns = 0u;
    uint64_t maximum_flow_detector_schedule_latency_ns = 0u;
    uint64_t detector_deadline_ns = 0u;
    bool requested = false;
    bool fifo_verified = false;
    bool deadline_verified = false;
    bool conservation_verified = false;
    bool complete = false;
};

void json_string(FILE *stream, const char *text);

const char *retention_rank_name(
        fk_compact_retention_policy_kind policy) {
    switch (policy) {
    case FK_COMPACT_POLICY_FLOWKEEP:
        return "causal_lcb_per_exact_candidate_owned_byte";
    case FK_COMPACT_POLICY_LEARNED_DETECTION_LOSS_PER_BYTE:
        return "learned_detection_loss_per_exact_candidate_owned_byte";
    case FK_COMPACT_POLICY_SEEDED_RANDOM_RETENTION:
        return "frozen_seed_hash_over_legal_whole_flow_victims";
    default:
        return "deterministic_policy_not_score_ranked";
    }
}

void write_retention_detector_composition_json(
        FILE *stream,
        const Options &options,
        const RetentionDetectorCompositionReceipt &receipt) {
    std::fputs(
        "  \"retention_detector_composition\": {\n"
        "    \"mode\": ",
        stream);
    if (options.retention_detector_coupling == nullptr)
        std::fputs("null", stream);
    else
        json_string(stream, options.retention_detector_coupling);
    std::fputs(",\n    \"orthogonal_configuration_fields\": ", stream);
    std::fputs(receipt.requested ? "true" : "false", stream);
    std::fputs(",\n    \"retention\": {\"policy\": ", stream);
    json_string(stream, options.retention_policy_name);
    std::fputs(", \"ranking\": ", stream);
    json_string(stream, retention_rank_name(options.retention_policy));
    std::fputs(", \"online_signal\": ", stream);
    if (options.retention_policy ==
            FK_COMPACT_POLICY_LEARNED_DETECTION_LOSS_PER_BYTE) {
        json_string(
            stream,
            "frozen_prefix_only_learned_detection_loss_not_live_detector_score");
    } else {
        std::fputs("null", stream);
    }
    std::fputs(", \"exact_candidate_owned_bytes\": ", stream);
    std::fputs(
        options.retention_policy ==
                FK_COMPACT_POLICY_LEARNED_DETECTION_LOSS_PER_BYTE
            ? "true" : "false",
        stream);
    std::fputs("},\n    \"detector_scheduler\": {\"discipline\": ", stream);
    if (options.detector_scheduling == nullptr)
        std::fputs("null", stream);
    else
        json_string(stream, options.detector_scheduling);
    std::fprintf(
        stream,
        ", \"deadline_us\": %u, \"checkpoint_records\": %" PRIu64
        ", \"fifo_order_violations\": %" PRIu64
        ", \"maximum_flow_detector_latency_ns\": %" PRIu64
        ", \"maximum_queue_plus_inference_latency_ns\": %" PRIu64
        ", \"implementation_scope\": "
        "\"synchronous_no_nic_causal_fifo\", "
        "\"detector_scheduling_baseline\": false, "
        "\"retention_signal_used_for_scheduling\": false, "
        "\"deadline_applicable\": false, "
        "\"fifo_verified\": %s, \"deadline_verified\": %s, "
        "\"conservation_verified\": %s},\n"
        "    \"live_detector_score_available_before_retention\": false,\n"
        "    \"native_live_service_scheduler_claim\": false,\n"
        "    \"score_per_byte_policy_available\": false,\n"
        "    \"complete\": %s\n"
        "  },\n",
        options.detector_deadline_us,
        receipt.checkpoint_records,
        receipt.fifo_order_violations,
        receipt.maximum_flow_detector_latency_ns,
        receipt.maximum_flow_detector_schedule_latency_ns,
        receipt.fifo_verified ? "true" : "false",
        receipt.deadline_verified ? "true" : "false",
        receipt.conservation_verified ? "true" : "false",
        receipt.complete ? "true" : "false");
}

const char *effective_action_model(const Options &options) {
    return options.value_model_v3_artifact != nullptr
        ? options.value_model_v3_artifact : options.action_model;
}

struct Invocation {
    const char *entrypoint;
    bool production_main_opt_in;
    bool eal_initialized_before_entry;
};

constexpr Invocation kStandaloneInvocation{
    "standalone-no-eal", false, false};
constexpr Invocation kProductionEalInvocation{
    "production-dpdk-eal-opt-in", true, true};

void usage(FILE *stream, const char *program) {
    std::fprintf(
        stream,
        "usage: %s --pcap FILE --budget 16|32|64|128|unlimited "
        "[--pool-weights STAT,SEQ,JA4_PENDING,JA4_SUMMARY] "
        "[--lambda-memory-per-byte X] [--lambda-queue X] "
        "[--lambda-deadline X] "
        "[--retention-policy flowkeep|lru|lfu|fifo|fixed_ttl|protocol_aware|"
        "protocol_deadline|handshake_only|full_state|summary_only|history_only|"
        "summary_history|summary_handshake|history_handshake|core_only|"
        "learned_detection_loss_per_byte|seeded_random_retention] "
        "[--fixed-ttl-ns POSITIVE_DECIMAL_UINT64_NS] "
        "[--seeded-random-retention-seed N] "
        "[--retention-detector-coupling decoupled "
        "--detector-scheduling batch_fifo] "
        "[--maximum-flows N] [--owner-hash-key-hex 32_HEX] "
        "--maximum-quic-connections N "
        "[--action-model FILE | "
        "--value-model-v3-artifact FILE "
        "--value-model-v3-artifact-sha SHA256 "
        "--value-model-v3-training-receipt-sha SHA256 "
        "--value-model-v3-schema-sha SHA256 "
        "--value-model-v3-action-domain-sha SHA256 "
        "--value-model-v3-deadline-contract-sha SHA256 "
        "--value-model-v3-role flowkeep|learned_immediate_risk|"
        "learned_future_risk|learned_detection_loss] "
        "[--transition-value-model FILE "
        "--transition-value-schema-sha SHA256 "
        "--transition-value-model-sha SHA256] "
        "(--detector-model FILE | --detector-state-model-dir DIR) "
        "[--action-schema SHA256] --detector-schema SHA256 "
        "(--aggregation-mode frozen_cpp_causal "
        "--aggregation-rule max|causal_event_calibrator_max "
        "--aggregation-threshold-profile NAME --aggregation-threshold P "
        "--aggregation-contract-sha256 SHA256 "
        "--development-oof-receipt-sha256 SHA256 "
        "[--causal-event-calibrator-artifact FILE "
        "--causal-event-calibrator-artifact-sha SHA256 "
        "--causal-event-calibrator-source-npz-sha SHA256 "
        "--causal-event-calibrator-feature-contract-sha SHA256 "
        "--causal-event-calibrator-real-prefix-receipt-sha SHA256] | "
        "[--monitored-cidr CIDR "
        "(--actor-namespace-monitor-map FKANM01 "
        "--actor-namespace-monitor-map-sha256 SHA256 | "
        "--compact-monitored-ipv4-pool CIDR "
        "--compact-monitored-ipv4-slots-per-namespace N "
        "--compact-monitored-ipv4-namespace-count N "
        "--compact-monitored-ipv4-identity-index N) "
        "--actor-identity-contract-sha256 SHA256 "
        "--expected-flow-capacity-rollovers N "
        "--event-student-artifact FKESV1 "
        "--event-student-artifact-sha SHA256 "
        "--event-student-feature-schema-sha SHA256 "
        "--event-student-source-state-sha SHA256 "
        "--event-student-hidden N --event-student-identity-embedding N]) "
        "[--decision-trace CSV [--decision-trace-features CSV]] "
        "[--development-source-record-intervention-plan FKSRINT1 "
        "--development-packet-lineage FKPLV1] "
        "--output JSON\n",
        program == nullptr ? "fk_no_nic_pcap_runner" : program);
}

bool parse_pool_weights(const char *text, fk_component_pool_weights &weights) {
    if (text == nullptr)
        return false;
    unsigned values[4]{};
    char tail = '\0';
    if (std::sscanf(text, "%u,%u,%u,%u%c", &values[0], &values[1],
                    &values[2], &values[3], &tail) != 4)
        return false;
    unsigned total = 0u;
    for (unsigned value : values) {
        if (value > 100u)
            return false;
        total += value;
    }
    if (total != 100u)
        return false;
    weights.stat_percent = static_cast<uint8_t>(values[0]);
    weights.seq_percent = static_cast<uint8_t>(values[1]);
    weights.ja4_pending_percent = static_cast<uint8_t>(values[2]);
    weights.ja4_summary_percent = static_cast<uint8_t>(values[3]);
    return true;
}

bool parse_u32(const char *text, uint32_t &value) {
    if (text == nullptr || *text == '\0')
        return false;
    errno = 0;
    char *end = nullptr;
    const unsigned long parsed = std::strtoul(text, &end, 10);
    if (errno != 0 || end == text || *end != '\0' || parsed == 0u ||
        parsed > UINT16_MAX)
        return false;
    value = static_cast<uint32_t>(parsed);
    return true;
}

bool parse_nonzero_u32(const char *text, uint32_t &value) {
    if (text == nullptr || *text == '\0' || *text == '-')
        return false;
    errno = 0;
    char *end = nullptr;
    const unsigned long long parsed = std::strtoull(text, &end, 10);
    if (errno != 0 || end == text || *end != '\0' || parsed == 0u ||
        parsed > UINT32_MAX) {
        return false;
    }
    value = static_cast<uint32_t>(parsed);
    return true;
}

bool parse_u64_allow_zero(const char *text, uint64_t &value) {
    if (text == nullptr || *text == '\0' || *text == '-')
        return false;
    errno = 0;
    char *end = nullptr;
    const unsigned long long parsed = std::strtoull(text, &end, 10);
    if (errno != 0 || end == text || *end != '\0')
        return false;
    value = static_cast<uint64_t>(parsed);
    return true;
}

bool parse_probability(const char *text, float &value) {
    if (text == nullptr || *text == '\0')
        return false;
    errno = 0;
    char *end = nullptr;
    const float parsed = std::strtof(text, &end);
    if (errno != 0 || end == text || *end != '\0' ||
        !std::isfinite(parsed) || parsed <= 0.0f || parsed > 1.0f) {
        return false;
    }
    value = parsed;
    return true;
}

bool parse_nonnegative_float(const char *text, float &value) {
    if (text == nullptr || *text == '\0')
        return false;
    errno = 0;
    char *end = nullptr;
    const float parsed = std::strtof(text, &end);
    if (errno != 0 || end == text || *end != '\0' ||
        !std::isfinite(parsed) || parsed < 0.0f) {
        return false;
    }
    value = parsed;
    return true;
}

bool valid_sha256(const char *text) {
    if (text == nullptr || std::strlen(text) != 64u)
        return false;
    for (size_t index = 0u; index < 64u; ++index) {
        if (!((text[index] >= '0' && text[index] <= '9') ||
              (text[index] >= 'a' && text[index] <= 'f')))
            return false;
    }
    return true;
}

bool parse_owner_hash_key(
        const char *text,
        uint8_t (&output)[FK_NO_NIC_OWNER_HASH_KEY_BYTES]) {
    if (text == nullptr ||
        std::strlen(text) != FK_NO_NIC_OWNER_HASH_KEY_BYTES * 2u) {
        return false;
    }
    auto nibble = [](char value) -> int {
        if (value >= '0' && value <= '9')
            return value - '0';
        if (value >= 'a' && value <= 'f')
            return value - 'a' + 10;
        return -1;
    };
    for (size_t index = 0u; index < FK_NO_NIC_OWNER_HASH_KEY_BYTES; ++index) {
        const int high = nibble(text[index * 2u]);
        const int low = nibble(text[index * 2u + 1u]);
        if (high < 0 || low < 0)
            return false;
        output[index] = static_cast<uint8_t>((high << 4u) | low);
    }
    return true;
}

bool set_once(const char *&target, const char *value) {
    if (target != nullptr || value == nullptr)
        return false;
    target = value;
    return true;
}

bool existing_files_alias(const char *left, const char *right) {
    if (left == nullptr || right == nullptr)
        return false;
    struct stat left_status{};
    struct stat right_status{};
    return stat(left, &left_status) == 0 && stat(right, &right_status) == 0 &&
        left_status.st_dev == right_status.st_dev &&
        left_status.st_ino == right_status.st_ino;
}

bool parse_options(int argc, char **argv, Options &options) {
    bool budget_seen = false;
    bool maximum_flows_seen = false;
    bool maximum_quic_connections_seen = false;
    bool event_hidden_seen = false;
    bool event_embedding_seen = false;
    for (int index = 1; index < argc; ++index) {
        const char *name = argv[index];
        if (std::strcmp(name, "--help") == 0)
            return false;
        if (index + 1 >= argc)
            return false;
        const char *value = argv[++index];
        if (std::strcmp(name, "--pcap") == 0) {
            if (!set_once(options.pcap, value))
                return false;
        } else if (std::strcmp(name, "--action-model") == 0) {
            if (!set_once(options.action_model, value))
                return false;
        } else if (std::strcmp(
                       name, "--value-model-v3-artifact") == 0) {
            if (!set_once(options.value_model_v3_artifact, value))
                return false;
        } else if (std::strcmp(
                       name, "--value-model-v3-artifact-sha") == 0) {
            if (!set_once(options.value_model_v3_artifact_sha, value))
                return false;
        } else if (std::strcmp(
                       name, "--value-model-v3-training-receipt-sha") == 0) {
            if (!set_once(
                    options.value_model_v3_training_receipt_sha, value)) {
                return false;
            }
        } else if (std::strcmp(
                       name, "--value-model-v3-schema-sha") == 0) {
            if (!set_once(options.value_model_v3_schema_sha, value))
                return false;
        } else if (std::strcmp(
                       name, "--value-model-v3-action-domain-sha") == 0) {
            if (!set_once(options.value_model_v3_action_domain_sha, value))
                return false;
        } else if (std::strcmp(
                       name,
                       "--value-model-v3-deadline-contract-sha") == 0) {
            if (!set_once(
                    options.value_model_v3_deadline_contract_sha, value)) {
                return false;
            }
        } else if (std::strcmp(name, "--value-model-v3-role") == 0) {
            if (options.value_model_v3_role_seen)
                return false;
            options.value_model_v3_role_seen = true;
            if (std::strcmp(value, "flowkeep") == 0) {
                options.value_model_v3_role = FK_VALUE_MODEL_V3_FLOWKEEP;
            } else if (std::strcmp(
                           value, "learned_immediate_risk") == 0) {
                options.value_model_v3_role =
                    FK_VALUE_MODEL_V3_IMMEDIATE_RISK;
            } else if (std::strcmp(
                           value, "learned_future_risk") == 0) {
                options.value_model_v3_role =
                    FK_VALUE_MODEL_V3_FUTURE_RISK;
            } else if (std::strcmp(
                           value, "learned_detection_loss") == 0) {
                options.value_model_v3_role =
                    FK_VALUE_MODEL_V3_DETECTION_LOSS;
            } else {
                return false;
            }
        } else if (std::strcmp(name, "--transition-value-model") == 0) {
            if (!set_once(options.transition_value_model, value))
                return false;
        } else if (std::strcmp(
                       name, "--transition-value-schema-sha") == 0) {
            if (!set_once(options.transition_value_schema_sha, value))
                return false;
        } else if (std::strcmp(
                       name, "--transition-value-model-sha") == 0) {
            if (!set_once(options.transition_value_model_sha, value))
                return false;
        } else if (std::strcmp(name, "--detector-model") == 0) {
            if (!set_once(options.detector_model, value))
                return false;
        } else if (std::strcmp(name, "--detector-state-model-dir") == 0) {
            if (!set_once(options.detector_state_model_dir, value))
                return false;
        } else if (std::strcmp(name, "--action-schema") == 0) {
            if (!set_once(options.action_schema, value))
                return false;
        } else if (std::strcmp(name, "--detector-schema") == 0) {
            if (!set_once(options.detector_schema, value))
                return false;
        } else if (std::strcmp(name, "--aggregation-mode") == 0) {
            if (!set_once(options.aggregation_mode, value))
                return false;
        } else if (std::strcmp(name, "--aggregation-rule") == 0) {
            if (!set_once(options.aggregation_rule, value))
                return false;
        } else if (std::strcmp(
                       name, "--aggregation-threshold-profile") == 0) {
            if (!set_once(options.aggregation_threshold_profile, value))
                return false;
        } else if (std::strcmp(name, "--aggregation-threshold") == 0) {
            if (options.aggregation_threshold_seen ||
                !parse_probability(value, options.aggregation_threshold)) {
                return false;
            }
            options.aggregation_threshold_seen = true;
        } else if (std::strcmp(
                       name, "--aggregation-contract-sha256") == 0) {
            if (!set_once(options.aggregation_contract_sha, value))
                return false;
        } else if (std::strcmp(
                       name, "--development-oof-receipt-sha256") == 0) {
            if (!set_once(options.development_oof_receipt_sha, value))
                return false;
        } else if (std::strcmp(
                       name, "--causal-event-calibrator-artifact") == 0) {
            if (!set_once(options.causal_event_calibrator_artifact, value))
                return false;
        } else if (std::strcmp(
                       name,
                       "--causal-event-calibrator-artifact-sha") == 0) {
            if (!set_once(
                    options.causal_event_calibrator_artifact_sha, value))
                return false;
        } else if (std::strcmp(
                       name,
                       "--causal-event-calibrator-source-npz-sha") == 0) {
            if (!set_once(
                    options.causal_event_calibrator_source_npz_sha, value))
                return false;
        } else if (std::strcmp(
                       name,
                       "--causal-event-calibrator-feature-contract-sha") ==
                   0) {
            if (!set_once(
                    options.causal_event_calibrator_feature_contract_sha,
                    value)) {
                return false;
            }
        } else if (std::strcmp(
                       name,
                       "--causal-event-calibrator-real-prefix-receipt-sha") ==
                   0) {
            if (!set_once(
                    options.causal_event_calibrator_real_prefix_receipt_sha,
                    value)) {
                return false;
            }
        } else if (std::strcmp(name, "--event-student-artifact") == 0) {
            if (!set_once(options.event_student_artifact, value))
                return false;
        } else if (std::strcmp(
                       name, "--event-student-artifact-sha") == 0) {
            if (!set_once(options.event_student_artifact_sha, value))
                return false;
        } else if (std::strcmp(
                       name, "--event-student-feature-schema-sha") == 0) {
            if (!set_once(
                    options.event_student_feature_schema_sha, value))
                return false;
        } else if (std::strcmp(
                       name, "--event-student-source-state-sha") == 0) {
            if (!set_once(options.event_student_source_state_sha, value))
                return false;
        } else if (std::strcmp(name, "--event-student-hidden") == 0) {
            if (event_hidden_seen ||
                !parse_u32(value, options.event_student_hidden) ||
                options.event_student_hidden >
                    FK_EVENT_STUDENT_MAX_HIDDEN)
                return false;
            event_hidden_seen = true;
        } else if (std::strcmp(
                       name, "--event-student-identity-embedding") == 0) {
            if (event_embedding_seen ||
                !parse_u32(
                    value, options.event_student_identity_embedding) ||
                options.event_student_identity_embedding >
                    FK_EVENT_STUDENT_MAX_IDENTITY_EMBEDDING)
                return false;
            event_embedding_seen = true;
        } else if (std::strcmp(name, "--monitored-cidr") == 0) {
            if (!set_once(options.monitored_cidr, value))
                return false;
        } else if (std::strcmp(
                       name, "--actor-namespace-monitor-map") == 0) {
            if (!set_once(options.actor_namespace_monitor_map, value) ||
                value[0] == '\0') {
                return false;
            }
        } else if (std::strcmp(
                       name,
                       "--actor-namespace-monitor-map-sha256") == 0) {
            if (!set_once(
                    options.actor_namespace_monitor_map_sha256, value)) {
                return false;
            }
        } else if (std::strcmp(
                       name, "--compact-monitored-ipv4-pool") == 0) {
            if (!set_once(options.compact_monitored_ipv4_pool, value))
                return false;
        } else if (std::strcmp(
                       name,
                       "--compact-monitored-ipv4-slots-per-namespace") ==
                   0) {
            if (options.compact_monitored_ipv4_slots_seen ||
                !parse_nonzero_u32(
                    value,
                    options.compact_monitored_ipv4_slots_per_namespace)) {
                return false;
            }
            options.compact_monitored_ipv4_slots_seen = true;
        } else if (std::strcmp(
                       name,
                       "--compact-monitored-ipv4-namespace-count") == 0) {
            if (options.compact_monitored_ipv4_namespace_count_seen ||
                !parse_nonzero_u32(
                    value,
                    options.compact_monitored_ipv4_namespace_count)) {
                return false;
            }
            options.compact_monitored_ipv4_namespace_count_seen = true;
        } else if (std::strcmp(
                       name,
                       "--compact-monitored-ipv4-identity-index") == 0) {
            if (options.compact_monitored_ipv4_identity_index_seen ||
                !parse_nonzero_u32(
                    value,
                    options.compact_monitored_ipv4_identity_index)) {
                return false;
            }
            options.compact_monitored_ipv4_identity_index_seen = true;
        } else if (std::strcmp(
                       name, "--actor-identity-contract-sha256") == 0) {
            if (!set_once(options.actor_identity_contract_sha, value))
                return false;
        } else if (std::strcmp(
                       name,
                       "--expected-flow-capacity-rollovers") == 0) {
            if (options.expected_flow_capacity_rollovers_seen ||
                !parse_u64_allow_zero(
                    value, options.expected_flow_capacity_rollovers)) {
                return false;
            }
            options.expected_flow_capacity_rollovers_seen = true;
        } else if (std::strcmp(name, "--output") == 0) {
            if (!set_once(options.output, value))
                return false;
        } else if (std::strcmp(name, "--decision-trace") == 0) {
            if (!set_once(options.decision_trace, value))
                return false;
        } else if (std::strcmp(
                       name, "--decision-trace-features") == 0) {
            if (!set_once(options.decision_trace_features, value))
                return false;
        } else if (std::strcmp(
                       name,
                       "--development-source-record-intervention-plan") ==
                   0) {
            if (!set_once(
                    options.development_source_record_intervention_plan,
                    value)) {
                return false;
            }
        } else if (std::strcmp(
                       name, "--development-packet-lineage") == 0) {
            if (!set_once(options.development_packet_lineage, value))
                return false;
        } else if (std::strcmp(name, "--maximum-flows") == 0) {
            if (maximum_flows_seen ||
                !parse_nonzero_u32(value, options.maximum_flows))
                return false;
            maximum_flows_seen = true;
        } else if (std::strcmp(
                       name, "--actor-maximum-total-flows") == 0) {
            if (!parse_nonzero_u32(
                    value, options.actor_maximum_total_flows))
                return false;
        } else if (std::strcmp(name, "--owner-hash-key-hex") == 0) {
            uint8_t parsed[FK_NO_NIC_OWNER_HASH_KEY_BYTES]{};
            if (options.owner_hash_key_seen ||
                !parse_owner_hash_key(value, parsed)) {
                return false;
            }
            options.owner_hash_key_seen = true;
            options.owner_hash_key_hex = value;
        } else if (std::strcmp(
                       name, "--maximum-quic-connections") == 0) {
            if (maximum_quic_connections_seen ||
                !parse_u32(value, options.maximum_quic_connections)) {
                return false;
            }
            maximum_quic_connections_seen = true;
        } else if (std::strcmp(name, "--pool-weights") == 0) {
            if (options.pool_weights_seen ||
                !parse_pool_weights(value, options.pool_weights))
                return false;
            options.pool_weights_seen = true;
        } else if (std::strcmp(name, "--lambda-memory-per-byte") == 0) {
            if (options.lambda_memory_seen ||
                !parse_nonnegative_float(
                    value, options.lambda_memory_per_byte))
                return false;
            options.lambda_memory_seen = true;
        } else if (std::strcmp(name, "--lambda-queue") == 0) {
            if (options.lambda_queue_seen ||
                !parse_nonnegative_float(value, options.lambda_queue))
                return false;
            options.lambda_queue_seen = true;
        } else if (std::strcmp(name, "--lambda-deadline") == 0) {
            if (options.lambda_deadline_seen ||
                !parse_nonnegative_float(value, options.lambda_deadline))
                return false;
            options.lambda_deadline_seen = true;
        } else if (std::strcmp(name, "--retention-discount") == 0) {
            if (options.retention_discount_seen ||
                !parse_nonnegative_float(value, options.retention_discount))
                return false;
            options.retention_discount_seen = true;
        } else if (std::strcmp(name, "--retention-policy") == 0) {
            if (options.retention_policy_seen)
                return false;
            options.retention_policy_seen = true;
            options.retention_policy_name = value;
            if (!fk_compact_retention_policy_parse(
                    value, &options.retention_policy))
                return false;
        } else if (std::strcmp(
                       name, "--fixed-ttl-ns") == 0) {
            if (!fk_fixed_ttl_retention_parse_ns_once(
                    value, &options.fixed_ttl_retention)) {
                return false;
            }
        } else if (std::strcmp(
                       name, "--seeded-random-retention-seed") == 0) {
            if (options.seeded_random_retention_seed_seen ||
                !parse_u64_allow_zero(
                    value, options.seeded_random_retention_seed)) {
                return false;
            }
            options.seeded_random_retention_seed_seen = true;
        } else if (std::strcmp(
                       name, "--retention-detector-coupling") == 0) {
            if (!set_once(options.retention_detector_coupling, value))
                return false;
        } else if (std::strcmp(name, "--detector-scheduling") == 0) {
            if (!set_once(options.detector_scheduling, value))
                return false;
        } else if (std::strcmp(name, "--detector-deadline-us") == 0) {
            if (options.detector_deadline_seen ||
                !parse_u32(value, options.detector_deadline_us)) {
                return false;
            }
            options.detector_deadline_seen = true;
        } else if (std::strcmp(name, "--budget") == 0) {
            if (budget_seen)
                return false;
            budget_seen = true;
            options.budget_name = value;
            if (std::strcmp(value, "16") == 0) {
                options.budget =
                    FK_NO_NIC_FULL_COMPOSITION_BUDGET_16_MIB;
            } else if (std::strcmp(value, "32") == 0) {
                options.budget =
                    FK_NO_NIC_FULL_COMPOSITION_BUDGET_32_MIB;
            } else if (std::strcmp(value, "64") == 0) {
                options.budget =
                    FK_NO_NIC_FULL_COMPOSITION_BUDGET_64_MIB;
            } else if (std::strcmp(value, "128") == 0) {
                options.budget =
                    FK_NO_NIC_FULL_COMPOSITION_BUDGET_128_MIB;
            } else if (std::strcmp(value, "unlimited") == 0) {
                options.budget =
                    FK_NO_NIC_FULL_COMPOSITION_BUDGET_UNLIMITED_FULL_STATE;
            } else {
                return false;
            }
        } else {
            return false;
        }
    }
    const bool no_event_student =
        options.event_student_artifact == nullptr &&
        options.event_student_artifact_sha == nullptr &&
        options.event_student_feature_schema_sha == nullptr &&
        options.event_student_source_state_sha == nullptr &&
        !event_hidden_seen && !event_embedding_seen;
    const bool complete_event_student =
        options.event_student_artifact != nullptr &&
        valid_sha256(options.event_student_artifact_sha) &&
        valid_sha256(options.event_student_feature_schema_sha) &&
        valid_sha256(options.event_student_source_state_sha) &&
        event_hidden_seen && event_embedding_seen;
    const bool no_frozen_aggregation =
        options.aggregation_mode == nullptr &&
        options.aggregation_rule == nullptr &&
        options.aggregation_threshold_profile == nullptr &&
        options.aggregation_contract_sha == nullptr &&
        options.development_oof_receipt_sha == nullptr &&
        !options.aggregation_threshold_seen;
    const bool complete_frozen_aggregation_common =
        options.aggregation_mode != nullptr &&
        std::strcmp(options.aggregation_mode, "frozen_cpp_causal") == 0 &&
        options.aggregation_rule != nullptr &&
        options.aggregation_threshold_profile != nullptr &&
        std::strlen(options.aggregation_threshold_profile) != 0u &&
        std::strlen(options.aggregation_threshold_profile) <
            FK_NO_NIC_FROZEN_CAUSAL_TEXT_BYTES &&
        options.aggregation_threshold_seen &&
        valid_sha256(options.aggregation_contract_sha) &&
        valid_sha256(options.development_oof_receipt_sha);
    const bool no_causal_calibrator =
        options.causal_event_calibrator_artifact == nullptr &&
        options.causal_event_calibrator_artifact_sha == nullptr &&
        options.causal_event_calibrator_source_npz_sha == nullptr &&
        options.causal_event_calibrator_feature_contract_sha == nullptr &&
        options.causal_event_calibrator_real_prefix_receipt_sha == nullptr;
    const bool complete_causal_calibrator =
        options.causal_event_calibrator_artifact != nullptr &&
        options.causal_event_calibrator_artifact[0] != '\0' &&
        valid_sha256(options.causal_event_calibrator_artifact_sha) &&
        valid_sha256(options.causal_event_calibrator_source_npz_sha) &&
        valid_sha256(options.causal_event_calibrator_feature_contract_sha) &&
        valid_sha256(
            options.causal_event_calibrator_real_prefix_receipt_sha);
    const bool complete_frozen_aggregation =
        complete_frozen_aggregation_common &&
        ((no_causal_calibrator &&
          std::strcmp(options.aggregation_rule, "max") == 0) ||
         (complete_causal_calibrator &&
          std::strcmp(
              options.aggregation_rule,
              "causal_event_calibrator_max") == 0));
    const bool no_value_model_v3 =
        options.value_model_v3_artifact == nullptr &&
        options.value_model_v3_artifact_sha == nullptr &&
        options.value_model_v3_training_receipt_sha == nullptr &&
        options.value_model_v3_schema_sha == nullptr &&
        options.value_model_v3_action_domain_sha == nullptr &&
        options.value_model_v3_deadline_contract_sha == nullptr &&
        !options.value_model_v3_role_seen;
    const bool legacy_action_model =
        options.action_model != nullptr && no_value_model_v3;
    const bool no_action_selector =
        options.action_model == nullptr && no_value_model_v3;
    const bool complete_value_model_v3 =
        options.action_model == nullptr &&
        options.value_model_v3_artifact != nullptr &&
        options.value_model_v3_artifact[0] != '\0' &&
        valid_sha256(options.value_model_v3_artifact_sha) &&
        valid_sha256(options.value_model_v3_training_receipt_sha) &&
        valid_sha256(options.value_model_v3_schema_sha) &&
        valid_sha256(options.value_model_v3_action_domain_sha) &&
        valid_sha256(options.value_model_v3_deadline_contract_sha) &&
        options.value_model_v3_role_seen &&
        options.action_schema != nullptr &&
        std::strcmp(
            options.value_model_v3_schema_sha, options.action_schema) == 0 &&
        std::strcmp(
            options.value_model_v3_action_domain_sha,
            FK_VALUE_MODEL_V3_REQUESTED_ACTION_DOMAIN_SHA256) == 0 &&
        std::strcmp(
            options.value_model_v3_deadline_contract_sha,
            FK_VALUE_MODEL_V3_ONLINE_DEADLINE_CONTRACT_SHA256) == 0;
    const bool no_transition_value =
        options.transition_value_model == nullptr &&
        options.transition_value_schema_sha == nullptr &&
        options.transition_value_model_sha == nullptr;
    const bool complete_transition_value =
        options.transition_value_model != nullptr &&
        options.transition_value_model[0] != '\0' &&
        valid_sha256(options.transition_value_schema_sha) &&
        valid_sha256(options.transition_value_model_sha) &&
        complete_value_model_v3 &&
        options.retention_policy == FK_COMPACT_POLICY_FLOWKEEP &&
        options.value_model_v3_role == FK_VALUE_MODEL_V3_FLOWKEEP;
    const bool no_decoupled_contract =
        options.retention_detector_coupling == nullptr &&
        options.detector_scheduling == nullptr &&
        !options.detector_deadline_seen;
    const bool decoupled_selector_contract_valid =
        (options.retention_policy ==
             FK_COMPACT_POLICY_LEARNED_DETECTION_LOSS_PER_BYTE &&
         complete_value_model_v3 &&
         options.value_model_v3_role == FK_VALUE_MODEL_V3_DETECTION_LOSS) ||
        (options.retention_policy == FK_COMPACT_POLICY_FLOWKEEP &&
         complete_value_model_v3 &&
         options.value_model_v3_role == FK_VALUE_MODEL_V3_FLOWKEEP) ||
        (options.retention_policy != FK_COMPACT_POLICY_FLOWKEEP &&
         options.retention_policy !=
             FK_COMPACT_POLICY_LEARNED_DETECTION_LOSS_PER_BYTE &&
         no_action_selector && options.action_schema == nullptr);
    const bool complete_decoupled_contract =
        options.retention_detector_coupling != nullptr &&
        std::strcmp(
            options.retention_detector_coupling, "decoupled") == 0 &&
        options.detector_scheduling != nullptr &&
        std::strcmp(options.detector_scheduling, "batch_fifo") == 0 &&
        !options.detector_deadline_seen &&
        options.decision_trace != nullptr &&
        decoupled_selector_contract_valid;
    if (!no_decoupled_contract && !complete_decoupled_contract) {
        std::fprintf(
            stderr,
            "invalid decoupled contract: coupling=%s scheduling=%s "
            "deadline_seen=%s trace=%s policy=%d value_v3=%s role=%d "
            "selector_binding=%s\n",
            options.retention_detector_coupling == nullptr
                ? "absent" : options.retention_detector_coupling,
            options.detector_scheduling == nullptr
                ? "absent" : options.detector_scheduling,
            options.detector_deadline_seen ? "true" : "false",
            options.decision_trace == nullptr ? "absent" : "present",
            static_cast<int>(options.retention_policy),
            complete_value_model_v3 ? "complete" : "incomplete",
            static_cast<int>(options.value_model_v3_role),
            decoupled_selector_contract_valid ? "valid" : "invalid");
    }
    const char *action_model = effective_action_model(options);
    fk_actor_session_config actor_check{};
    fk_actor_session_config_init(&actor_check);
    const bool no_compact_monitor =
        options.actor_namespace_monitor_map == nullptr &&
        options.actor_namespace_monitor_map_sha256 == nullptr &&
        options.compact_monitored_ipv4_pool == nullptr &&
        !options.compact_monitored_ipv4_slots_seen &&
        !options.compact_monitored_ipv4_namespace_count_seen &&
        !options.compact_monitored_ipv4_identity_index_seen &&
        options.actor_identity_contract_sha == nullptr &&
        !options.expected_flow_capacity_rollovers_seen;
    const bool complete_compact_monitor =
        options.actor_namespace_monitor_map == nullptr &&
        options.actor_namespace_monitor_map_sha256 == nullptr &&
        options.compact_monitored_ipv4_pool != nullptr &&
        options.compact_monitored_ipv4_slots_seen &&
        options.compact_monitored_ipv4_namespace_count_seen &&
        options.compact_monitored_ipv4_identity_index_seen &&
        options.monitored_cidr != nullptr &&
        valid_sha256(options.actor_identity_contract_sha) &&
        options.expected_flow_capacity_rollovers_seen;
    const bool complete_actor_namespace_monitor_map =
        options.actor_namespace_monitor_map != nullptr &&
        valid_sha256(options.actor_namespace_monitor_map_sha256) &&
        options.compact_monitored_ipv4_pool == nullptr &&
        !options.compact_monitored_ipv4_slots_seen &&
        !options.compact_monitored_ipv4_namespace_count_seen &&
        !options.compact_monitored_ipv4_identity_index_seen &&
        options.monitored_cidr != nullptr &&
        valid_sha256(options.actor_identity_contract_sha) &&
        options.expected_flow_capacity_rollovers_seen;
    bool actor_monitor_valid =
        options.monitored_cidr == nullptr ||
        fk_actor_session_config_add_cidr_text(
            &actor_check, options.monitored_cidr);
    if (actor_monitor_valid && complete_compact_monitor) {
        actor_monitor_valid =
            fk_actor_session_config_set_compact_ipv4_monitor_text(
                &actor_check,
                options.compact_monitored_ipv4_pool,
                options.compact_monitored_ipv4_slots_per_namespace,
                options.compact_monitored_ipv4_namespace_count,
                options.compact_monitored_ipv4_identity_index);
    }
    actor_monitor_valid = actor_monitor_valid &&
        (no_compact_monitor || complete_compact_monitor ||
         complete_actor_namespace_monitor_map);
    const bool selector_contract_valid =
        (legacy_action_model && valid_sha256(options.action_schema)) ||
        (complete_value_model_v3 &&
         (options.retention_policy !=
              FK_COMPACT_POLICY_LEARNED_DETECTION_LOSS_PER_BYTE ||
          options.value_model_v3_role == FK_VALUE_MODEL_V3_DETECTION_LOSS)) ||
        (no_action_selector &&
         options.action_schema == nullptr &&
         !fk_compact_retention_policy_uses_learned_selector(
             options.retention_policy));
    const bool seeded_random_contract_valid =
        options.retention_policy ==
            FK_COMPACT_POLICY_SEEDED_RANDOM_RETENTION
        ? options.seeded_random_retention_seed_seen
        : !options.seeded_random_retention_seed_seen;
    const bool no_source_record_intervention =
        options.development_source_record_intervention_plan == nullptr &&
        options.development_packet_lineage == nullptr;
    const bool complete_source_record_intervention =
        options.development_source_record_intervention_plan != nullptr &&
        options.development_packet_lineage != nullptr &&
        options.decision_trace != nullptr &&
        options.decision_trace_features != nullptr &&
        options.output != nullptr && options.pcap != nullptr &&
        options.retention_policy == FK_COMPACT_POLICY_FLOWKEEP &&
        std::strcmp(
            options.development_source_record_intervention_plan,
            options.development_packet_lineage) != 0 &&
        std::strcmp(
            options.development_source_record_intervention_plan,
            options.output) != 0 &&
        std::strcmp(
            options.development_packet_lineage, options.output) != 0 &&
        std::strcmp(
            options.development_source_record_intervention_plan,
            options.pcap) != 0 &&
        std::strcmp(
            options.development_packet_lineage, options.pcap) != 0;
    return budget_seen && maximum_quic_connections_seen &&
        options.maximum_quic_connections <= options.maximum_flows &&
        options.pcap != nullptr &&
        fk_fixed_ttl_retention_binding_valid(
            options.retention_policy,
            &options.fixed_ttl_retention) &&
        seeded_random_contract_valid &&
        selector_contract_valid &&
        (no_transition_value || complete_transition_value) &&
        (no_source_record_intervention ||
         complete_source_record_intervention) &&
        (no_decoupled_contract || complete_decoupled_contract) &&
        ((options.detector_model != nullptr) !=
         (options.detector_state_model_dir != nullptr)) &&
        options.detector_schema != nullptr && options.output != nullptr &&
        valid_sha256(options.detector_schema) &&
        std::strcmp(options.output, options.pcap) != 0 &&
        (action_model == nullptr ||
         std::strcmp(options.output, action_model) != 0) &&
        (options.transition_value_model == nullptr ||
         std::strcmp(options.output, options.transition_value_model) != 0) &&
        (options.detector_model == nullptr ||
         std::strcmp(options.output, options.detector_model) != 0) &&
        (options.decision_trace == nullptr ||
         (std::strcmp(options.decision_trace, options.output) != 0 &&
          std::strcmp(options.decision_trace, options.pcap) != 0 &&
          (action_model == nullptr ||
           std::strcmp(options.decision_trace, action_model) != 0) &&
          (options.detector_model == nullptr ||
           std::strcmp(options.decision_trace, options.detector_model) != 0))) &&
        (options.decision_trace_features == nullptr ||
         (options.decision_trace != nullptr &&
          options.decision_trace_features[0] != '\0' &&
          std::strcmp(
              options.decision_trace_features, options.decision_trace) != 0 &&
          std::strcmp(options.decision_trace_features, options.output) != 0 &&
          std::strcmp(options.decision_trace_features, options.pcap) != 0 &&
          (action_model == nullptr ||
           std::strcmp(options.decision_trace_features, action_model) != 0) &&
          (options.detector_model == nullptr ||
           std::strcmp(
               options.decision_trace_features,
               options.detector_model) != 0) &&
          (options.event_student_artifact == nullptr ||
           std::strcmp(
               options.decision_trace_features,
               options.event_student_artifact) != 0))) &&
        ((complete_frozen_aggregation && no_event_student &&
          (no_causal_calibrator || complete_causal_calibrator)) ||
         (complete_event_student && no_frozen_aggregation &&
          no_causal_calibrator)) && actor_monitor_valid &&
        (options.event_student_artifact == nullptr ||
         std::strcmp(options.output, options.event_student_artifact) != 0) &&
        (options.causal_event_calibrator_artifact == nullptr ||
         (std::strcmp(
              options.output,
              options.causal_event_calibrator_artifact) != 0 &&
          (options.decision_trace == nullptr ||
           std::strcmp(
               options.decision_trace,
               options.causal_event_calibrator_artifact) != 0) &&
          (options.decision_trace_features == nullptr ||
           std::strcmp(
               options.decision_trace_features,
               options.causal_event_calibrator_artifact) != 0)));
}

void json_string(FILE *stream, const char *text) {
    std::fputc('"', stream);
    if (text != nullptr) {
        for (const unsigned char *cursor =
                 reinterpret_cast<const unsigned char *>(text);
             *cursor != 0u;
             ++cursor) {
            const unsigned char value = *cursor;
            if (value == '"' || value == '\\') {
                std::fputc('\\', stream);
                std::fputc(value, stream);
            } else if (value == '\n') {
                std::fputs("\\n", stream);
            } else if (value == '\r') {
                std::fputs("\\r", stream);
            } else if (value == '\t') {
                std::fputs("\\t", stream);
            } else if (value < 0x20u) {
                std::fprintf(stream, "\\u%04x", value);
            } else {
                std::fputc(value, stream);
            }
        }
    }
    std::fputc('"', stream);
}

void write_sha256_hex(
        FILE *stream,
        const std::array<uint8_t, kSha256Bytes> &digest) {
    static constexpr char hex[] = "0123456789abcdef";
    for (uint8_t value : digest) {
        std::fputc(hex[value >> 4u], stream);
        std::fputc(hex[value & 0x0fu], stream);
    }
}

bool sha256_file(
        const char *path,
        std::array<uint8_t, kSha256Bytes> &digest) {
    if (path == nullptr || *path == '\0')
        return false;
    FILE *stream = std::fopen(path, "rb");
    if (stream == nullptr)
        return false;
    Sha256Stream sha;
    std::array<uint8_t, 1u << 16u> buffer{};
    bool valid = sha.begin();
    while (valid) {
        const size_t count = std::fread(
            buffer.data(), 1u, buffer.size(), stream);
        if (count != 0u && !sha.update(buffer.data(), count)) {
            valid = false;
            break;
        }
        if (count < buffer.size()) {
            valid = std::feof(stream) != 0 && std::ferror(stream) == 0;
            break;
        }
    }
    const bool closed = std::fclose(stream) == 0;
    return valid && closed && sha.finish(digest);
}

bool sha256_matches_hex(
        const std::array<uint8_t, kSha256Bytes> &digest,
        const char *expected) {
    if (!valid_sha256(expected))
        return false;
    static constexpr char kHex[] = "0123456789abcdef";
    for (size_t index = 0u; index < digest.size(); ++index) {
        if (expected[index * 2u] != kHex[digest[index] >> 4u] ||
            expected[index * 2u + 1u] !=
                kHex[digest[index] & 0x0fu]) {
            return false;
        }
    }
    return true;
}

bool load_actor_namespace_monitor_map(
        const Options &options,
        ActorNamespaceMonitorMapInput &input,
        char *error,
        size_t error_capacity) {
    set_error(error, error_capacity, "");
    input = ActorNamespaceMonitorMapInput{};
    input.requested =
        options.actor_namespace_monitor_map != nullptr ||
        options.actor_namespace_monitor_map_sha256 != nullptr;
    if (!input.requested)
        return true;
    if (options.actor_namespace_monitor_map == nullptr ||
        !valid_sha256(options.actor_namespace_monitor_map_sha256)) {
        set_error(
            error, error_capacity,
            "actor namespace monitor map path/SHA pair is incomplete");
        return false;
    }

    FILE *stream = std::fopen(options.actor_namespace_monitor_map, "rb");
    if (stream == nullptr) {
        set_error(error, error_capacity,
            "cannot open actor namespace monitor map");
        return false;
    }
    struct stat status{};
    if (fstat(fileno(stream), &status) != 0 || status.st_size <= 0 ||
        static_cast<uint64_t>(status.st_size) >
            FK_ACTOR_NAMESPACE_MONITOR_MAP_MAX_FILE_BYTES ||
        static_cast<uint64_t>(status.st_size) >
            static_cast<uint64_t>(std::numeric_limits<size_t>::max())) {
        (void)std::fclose(stream);
        set_error(error, error_capacity,
            "actor namespace monitor map size is outside bounds");
        return false;
    }
    const size_t byte_count = static_cast<size_t>(status.st_size);
    std::unique_ptr<uint8_t[]> bytes(
        new (std::nothrow) uint8_t[byte_count]);
    if (!bytes) {
        (void)std::fclose(stream);
        set_error(error, error_capacity,
            "actor namespace monitor map allocation failed");
        return false;
    }
    const size_t read_bytes =
        std::fread(bytes.get(), 1u, byte_count, stream);
    const int trailing = std::fgetc(stream);
    const bool exact_read = read_bytes == byte_count && trailing == EOF &&
        std::feof(stream) != 0 && std::ferror(stream) == 0;
    const bool closed = std::fclose(stream) == 0;
    if (!exact_read || !closed) {
        set_error(error, error_capacity,
            "actor namespace monitor map exact read failed");
        return false;
    }

    Sha256Stream sha;
    if (!sha.begin() || !sha.update(bytes.get(), byte_count) ||
        !sha.finish(input.whole_file_sha256)) {
        set_error(error, error_capacity,
            "actor namespace monitor map SHA-256 failed");
        return false;
    }
    input.whole_file_sha256_verified = sha256_matches_hex(
        input.whole_file_sha256,
        options.actor_namespace_monitor_map_sha256);
    if (!input.whole_file_sha256_verified) {
        set_error(error, error_capacity,
            "actor namespace monitor map SHA-256 mismatch");
        return false;
    }

    if (!fk_actor_namespace_monitor_map_decode(
            bytes.get(), byte_count, &input.metadata, nullptr, 0u,
            error, error_capacity)) {
        return false;
    }
    input.indices.reset(
        new (std::nothrow) uint32_t[input.metadata.namespace_count]);
    if (!input.indices) {
        set_error(error, error_capacity,
            "actor namespace monitor index allocation failed");
        return false;
    }
    if (!fk_actor_namespace_monitor_map_decode(
            bytes.get(), byte_count, &input.metadata,
            input.indices.get(), input.metadata.namespace_count,
            error, error_capacity)) {
        input.indices.reset();
        return false;
    }
    input.minimum_identity_index = input.indices[0];
    input.maximum_identity_index = input.indices[0];
    for (uint32_t index = 1u;
         index < input.metadata.namespace_count; ++index) {
        if (input.indices[index] < input.minimum_identity_index)
            input.minimum_identity_index = input.indices[index];
        if (input.indices[index] > input.maximum_identity_index)
            input.maximum_identity_index = input.indices[index];
    }
    input.file_bytes = static_cast<uint64_t>(byte_count);
    input.loaded = true;
    return true;
}

void write_decision_trace_features_json(
        FILE *stream,
        const Options &options,
        const DecisionTraceFeaturesReceipt &receipt) {
    std::fputs(
        "  \"decision_trace_features\": {\n"
        "    \"protocol\": \"flowkeep-no-nic-decision-trace-features-v1\",\n"
        "    \"enabled\": ",
        stream);
    std::fputs(receipt.enabled ? "true" : "false", stream);
    std::fputs(",\n    \"path\": ", stream);
    if (options.decision_trace_features == nullptr)
        std::fputs("null", stream);
    else
        json_string(stream, options.decision_trace_features);
    std::fputs(",\n    \"sha256\": ", stream);
    if (!receipt.sha256_valid) {
        std::fputs("null", stream);
    } else {
        std::fputc('"', stream);
        write_sha256_hex(stream, receipt.sha256);
        std::fputc('"', stream);
    }
    std::fprintf(
        stream,
        ",\n    \"rows\": %" PRIu64 ",\n"
        "    \"feature_count\": %u,\n"
        "    \"checkpoint_rows_conserved\": %s\n"
        "  },\n",
        receipt.rows,
        FK_NO_NIC_DECISION_TRACE_DETECTOR_FEATURES,
        receipt.row_conservation_valid ? "true" : "false");
}

void write_raw_sha256_hex(FILE *stream, const uint8_t digest[32]) {
    static constexpr char kHex[] = "0123456789abcdef";
    for (size_t index = 0u; index < 32u; ++index) {
        std::fputc(kHex[digest[index] >> 4u], stream);
        std::fputc(kHex[digest[index] & 0x0fu], stream);
    }
}

void write_source_record_intervention_json(
        FILE *stream,
        const Options &options,
        const fk_source_record_intervention_plan_receipt_v1 &plan,
        const fk_compact_checkpoint_intervention_receipt_v1 &runtime) {
    const bool enabled =
        options.development_source_record_intervention_plan != nullptr;
    const bool complete = enabled && plan.complete != 0u &&
        runtime.enabled == 1u && runtime.complete == 1u &&
        runtime.trace_binding_complete == 1u &&
        runtime.one_shot_disarmed == 1u &&
        runtime.applications == 1u && runtime.controller_failures == 0u &&
        runtime.identity_mismatches == 0u &&
        runtime.victim_identity_mismatches == 0u &&
        runtime.alternative_victim_releases == 0u &&
        runtime.candidate_evidence_allocations == 0u &&
        runtime.candidate_evidence_allocation_rejections == 0u;
    std::fprintf(
        stream,
        "  \"source_record_intervention\": {\n"
        "    \"protocol\": \"flowkeep-source-record-intervention-receipt-v1\",\n"
        "    \"enabled\": %s,\n"
        "    \"data_scope\": %s,\n"
        "    \"estimand\": \"controlled_one_step_allocation_intervention\",\n"
        "    \"global_optimal_closed_loop_claimed\": false,\n"
        "    \"offline_event_bag_used\": false,\n"
        "    \"independent_process_required\": true,\n"
        "    \"plan_path\": ",
        enabled ? "true" : "false",
        enabled ? "\"development\"" : "null");
    if (enabled)
        json_string(stream, options.development_source_record_intervention_plan);
    else
        std::fputs("null", stream);
    std::fputs(",\n    \"packet_lineage_path\": ", stream);
    if (enabled)
        json_string(stream, options.development_packet_lineage);
    else
        std::fputs("null", stream);
    if (!enabled) {
        std::fputs(",\n    \"complete\": true\n  },\n", stream);
        return;
    }
    std::fputs(",\n    \"plan_sha256\": \"", stream);
    write_raw_sha256_hex(stream, plan.plan_sha256);
    std::fputs("\",\n    \"pcap_sha256\": \"", stream);
    write_raw_sha256_hex(stream, plan.pcap_sha256);
    std::fputs("\",\n    \"packet_lineage_sha256\": \"", stream);
    write_raw_sha256_hex(stream, plan.packet_lineage_sha256);
    std::fputs("\",\n    \"checkpoint_sidecar_sha256\": \"", stream);
    write_raw_sha256_hex(stream, plan.checkpoint_sidecar_sha256);
    std::fputs("\",\n    \"conflict_id_sha256\": \"", stream);
    write_raw_sha256_hex(stream, plan.conflict_id_sha256);
    std::fprintf(
        stream,
        "\",\n"
        "    \"source_packet_sequence\": %" PRIu64 ",\n"
        "    \"source_record_sequence\": %" PRIu64 ",\n"
        "    \"source_index\": %u,\n"
        "    \"source_segment_index\": %u,\n"
        "    \"source_segment_count\": %u,\n"
        "    \"source_timestamp_ns\": %" PRIu64 ",\n"
        "    \"output_timestamp_ns\": %" PRIu64 ",\n"
        "    \"victim_count\": %u,\n"
        "    \"pcap_sha256_match\": %s,\n"
        "    \"packet_lineage_exact_match\": %s,\n"
        "    \"runtime\": {\n"
        "      \"abi_version\": %u,\n"
        "      \"record_bytes\": %u,\n"
        "      \"flow_index\": %u,\n"
        "      \"flow_generation\": %u,\n"
        "      \"checkpoint_packet\": %u,\n"
        "      \"victim_count\": %u,\n"
        "      \"mode\": %u,\n"
        "      \"enabled\": %s,\n"
        "      \"semantic_candidate_matches\": %" PRIu64 ",\n"
        "      \"applications\": %" PRIu64 ",\n"
        "      \"controller_failures\": %" PRIu64 ",\n"
        "      \"identity_mismatches\": %" PRIu64 ",\n"
        "      \"target_missed_before_later_timestamp\": %" PRIu64 ",\n"
        "      \"trace_checkpoint_matches\": %" PRIu64 ",\n"
        "      \"trace_binding_mismatches\": %" PRIu64 ",\n"
        "      \"victim_identity_checks\": %" PRIu64 ",\n"
        "      \"victim_identity_mismatches\": %" PRIu64 ",\n"
        "      \"alternative_victim_releases\": %" PRIu64 ",\n"
        "      \"candidate_evidence_allocations\": %" PRIu64 ",\n"
        "      \"candidate_evidence_allocation_rejections\": %" PRIu64 ",\n"
        "      \"post_intervention_original_policy_decisions\": %" PRIu64 ",\n"
        "      \"one_shot_disarmed\": %s,\n"
        "      \"expected_previous_mask\": %u,\n"
        "      \"expected_behavior_requested_mask\": %u,\n"
        "      \"expected_behavior_final_mask\": %u,\n"
        "      \"applied_previous_mask\": %u,\n"
        "      \"applied_requested_mask\": %u,\n"
        "      \"applied_final_mask\": %u,\n"
        "      \"applied_controlled_bytes_before\": %" PRIu64 ",\n"
        "      \"applied_controlled_bytes_after\": %" PRIu64 ",\n"
        "      \"trace_binding_complete\": %s,\n"
        "      \"complete\": %s\n"
        "    },\n"
        "    \"complete\": %s\n"
        "  },\n",
        plan.source_packet_sequence,
        plan.source_record_sequence,
        plan.source_index,
        plan.source_segment_index,
        plan.source_segment_count,
        plan.source_timestamp_ns,
        plan.output_timestamp_ns,
        plan.victim_count,
        plan.pcap_sha256_match ? "true" : "false",
        plan.packet_lineage_exact_match ? "true" : "false",
        runtime.abi_version,
        runtime.record_bytes,
        runtime.flow_index,
        runtime.flow_generation,
        runtime.checkpoint_packet,
        runtime.victim_count,
        static_cast<unsigned>(runtime.mode),
        runtime.enabled ? "true" : "false",
        runtime.semantic_candidate_matches,
        runtime.applications,
        runtime.controller_failures,
        runtime.identity_mismatches,
        runtime.target_missed_before_later_timestamp,
        runtime.trace_checkpoint_matches,
        runtime.trace_binding_mismatches,
        runtime.victim_identity_checks,
        runtime.victim_identity_mismatches,
        runtime.alternative_victim_releases,
        runtime.candidate_evidence_allocations,
        runtime.candidate_evidence_allocation_rejections,
        runtime.post_intervention_original_policy_decisions,
        runtime.one_shot_disarmed ? "true" : "false",
        runtime.expected_previous_mask,
        runtime.expected_behavior_requested_mask,
        runtime.expected_behavior_final_mask,
        runtime.applied_previous_mask,
        runtime.applied_requested_mask,
        runtime.applied_final_mask,
        runtime.applied_controlled_bytes_before,
        runtime.applied_controlled_bytes_after,
        runtime.trace_binding_complete ? "true" : "false",
        runtime.complete ? "true" : "false",
        complete ? "true" : "false");
}

FILE *open_output(const char *path) {
    return std::strcmp(path, "-") == 0 ? stdout : std::fopen(path, "w");
}

bool close_output(FILE *stream) {
    if (stream == nullptr)
        return false;
    if (stream == stdout)
        return std::fflush(stream) == 0;
    return std::fclose(stream) == 0;
}

void write_integration_json(
        FILE *stream,
        const Invocation &invocation,
        bool finite_pcap_preflight_verified) {
    std::fputs("  \"integration\": {\n    \"entrypoint\": ", stream);
    json_string(stream, invocation.entrypoint);
    std::fprintf(
        stream,
        ",\n    \"production_main_opt_in\": %s,\n"
        "    \"eal_initialized_before_entry\": %s,\n"
        "    \"finite_pcap_mode_requested\": true,\n"
        "    \"finite_pcap_preflight_verified\": %s,\n"
        "    \"actual_nic_rx_connected\": false,\n"
        "    \"production_capability_promoted\": false\n  },\n",
        invocation.production_main_opt_in ? "true" : "false",
        invocation.eal_initialized_before_entry ? "true" : "false",
        finite_pcap_preflight_verified ? "true" : "false");
}

uint64_t budget_bytes(fk_no_nic_full_composition_budget_mode budget);

bool write_failure_json(
        const Options &options,
        const Invocation &invocation,
        const char *stage,
        const char *message) {
    if (options.output == nullptr)
        return false;
    FILE *stream = open_output(options.output);
    if (stream == nullptr)
        return false;
    std::fputs("{\n  \"protocol\": \"flowkeep-no-nic-pcap-runner-v1\",\n", stream);
    std::fputs("  \"status\": \"failed\",\n  \"stage\": ", stream);
    json_string(stream, stage);
    std::fputs(",\n  \"error\": ", stream);
    json_string(stream, message);
    std::fputs(",\n  \"pcap\": ", stream);
    json_string(stream, options.pcap);
    std::fputs(",\n", stream);
    write_integration_json(stream, invocation, false);
    std::fputs("  \"formal_detection_result\": false,\n"
               "  \"accuracy_claim\": false\n}\n", stream);
    return close_output(stream);
}

bool write_pipeline_failure_json(
        const Options &options,
        const Invocation &invocation,
        const PcapScan &scan,
        const fk_no_nic_full_composition_io_stats_v1 &io,
        const char *message) {
    char fixed_ttl_receipt[320]{};
    if (!fk_fixed_ttl_retention_format_receipt_json(
            fixed_ttl_receipt,
            sizeof(fixed_ttl_receipt),
            options.retention_policy,
            &options.fixed_ttl_retention)) {
        return false;
    }
    FILE *stream = open_output(options.output);
    if (stream == nullptr)
        return false;
    std::fputs("{\n  \"protocol\": \"flowkeep-no-nic-pcap-runner-v1\",\n"
               "  \"status\": \"failed\",\n"
               "  \"stage\": \"pipeline\",\n"
               "  \"error\": ", stream);
    json_string(stream, message);
    std::fputs(",\n  \"input\": {\n    \"pcap\": ", stream);
    json_string(stream, options.pcap);
    std::fprintf(
        stream,
        ",\n    \"format\": \"classic-pcap\",\n"
        "    \"file_bytes\": %" PRIu64 ",\n"
        "    \"expected_packets\": %" PRIu64 ",\n"
        "    \"expected_captured_bytes\": %" PRIu64 ",\n"
        "    \"expected_wire_bytes\": %" PRIu64 ",\n"
        "    \"sha256\": \"",
        scan.file_bytes,
        scan.packets,
        scan.captured_bytes,
        scan.wire_bytes);
    write_sha256_hex(stream, scan.sha256);
    std::fprintf(
        stream,
        "\",\n"
        "    \"acquired_packets\": %" PRIu64 ",\n"
        "    \"acquired_wire_bytes\": %" PRIu64 "\n  },\n",
        io.acquired_packets,
        io.acquired_wire_bytes);
    std::fputs("  \"configuration\": {\n    \"budget\": ", stream);
    json_string(stream, options.budget_name);
    std::fprintf(
        stream,
        ",\n    \"controlled_budget_bytes\": %" PRIu64 ",\n"
        "    \"maximum_flows\": %u,\n"
        "    \"owner_hash_key_hex\": \"%s\",\n"
        "    \"maximum_quic_connections\": %u,\n"
        "    \"retention_policy\": \"%s\",\n"
        "    \"fixed_ttl_retention_receipt\": %s,\n"
        "    \"seeded_random_retention_seed\": %" PRIu64 ",\n"
        "    \"seeded_random_retention_seed_precommitted\": %s,\n"
        "    \"lambda_memory_per_byte\": %.9g,\n"
        "    \"lambda_queue\": %.9g,\n"
        "    \"lambda_deadline\": %.9g,\n"
        "    \"pool_weights\": [%u, %u, %u, %u],\n"
        "    \"retention_detector_coupling\": ",
        budget_bytes(options.budget),
        options.maximum_flows,
        options.owner_hash_key_hex,
        options.maximum_quic_connections,
        options.retention_policy_name,
        fixed_ttl_receipt,
        options.seeded_random_retention_seed,
        options.seeded_random_retention_seed_seen ? "true" : "false",
        static_cast<double>(options.lambda_memory_per_byte),
        static_cast<double>(options.lambda_queue),
        static_cast<double>(options.lambda_deadline),
        options.pool_weights.stat_percent,
        options.pool_weights.seq_percent,
        options.pool_weights.ja4_pending_percent,
        options.pool_weights.ja4_summary_percent);
    if (options.retention_detector_coupling == nullptr)
        std::fputs("null", stream);
    else
        json_string(stream, options.retention_detector_coupling);
    std::fputs(",\n    \"detector_scheduling\": ", stream);
    if (options.detector_scheduling == nullptr)
        std::fputs("null", stream);
    else
        json_string(stream, options.detector_scheduling);
    std::fprintf(
        stream,
        ",\n    \"detector_deadline_us\": %u\n  },\n",
        options.detector_deadline_us);
    std::fputs(
        "  \"drops_rejects\": {\n"
        "    \"available\": false,\n"
        "    \"reason\": \"pipeline did not reach an auditable terminal snapshot\"\n"
        "  },\n",
        stream);
    std::fprintf(
        stream,
        "  \"ownership\": {\n"
        "    \"exact_callback_reclaims\": %" PRIu64 ",\n"
        "    \"forced_failure_reclaims\": %" PRIu64 ",\n"
        "    \"duplicate_reclaims\": %" PRIu64 ",\n"
        "    \"live_mbufs_at_end\": %" PRIu64 ",\n"
        "    \"source_storage_recovered\": %s,\n"
        "    \"exact_pipeline_conservation\": false\n  },\n",
        io.reclaim_successes,
        io.forced_failure_reclaims,
        io.duplicate_reclaims,
        io.live_mbufs,
        io.ownership_recovered ? "true" : "false");
    std::fprintf(
        stream,
        "  \"controlled_state\": {\n"
        "    \"available\": false,\n"
        "    \"ceiling_bytes\": %" PRIu64 ",\n"
        "    \"hard_budget_violations\": null,\n"
        "    \"accounting_valid\": false\n  },\n",
        budget_bytes(options.budget));
    std::fprintf(
        stream,
        "  \"terminal\": {\n"
        "    \"state\": \"pipeline_failed_source_recovered\",\n"
        "    \"source_exhausted\": %s,\n"
        "    \"source_failed\": true,\n"
        "    \"normal_complete\": false\n  },\n",
        io.source_exhausted ? "true" : "false");
    write_integration_json(stream, invocation, true);
    std::fputs(
        "  \"formal_detection_result\": false,\n"
        "  \"accuracy_claim\": false\n}\n",
        stream);
    return close_output(stream);
}

uint64_t budget_bytes(fk_no_nic_full_composition_budget_mode budget) {
    switch (budget) {
    case FK_NO_NIC_FULL_COMPOSITION_BUDGET_16_MIB:
        return UINT64_C(16) * 1024u * 1024u;
    case FK_NO_NIC_FULL_COMPOSITION_BUDGET_32_MIB:
        return UINT64_C(32) * 1024u * 1024u;
    case FK_NO_NIC_FULL_COMPOSITION_BUDGET_64_MIB:
        return UINT64_C(64) * 1024u * 1024u;
    case FK_NO_NIC_FULL_COMPOSITION_BUDGET_128_MIB:
        return UINT64_C(128) * 1024u * 1024u;
    case FK_NO_NIC_FULL_COMPOSITION_BUDGET_UNLIMITED_FULL_STATE:
        return 0u;
    }
    return 0u;
}

void write_optional_pool_json(
        FILE *stream,
        const char *name,
        const fk_no_nic_optional_pool_result_v1 &pool,
        bool trailing_comma) {
    const uint64_t current_bytes =
        static_cast<uint64_t>(pool.block_bytes) * pool.current_in_use;
    const uint64_t peak_bytes =
        static_cast<uint64_t>(pool.block_bytes) * pool.peak_in_use;
    std::fputs("      ", stream);
    json_string(stream, name);
    std::fprintf(
        stream,
        ": {\"block_bytes\": %u, \"capacity\": %u, "
        "\"current_in_use\": %u, \"peak_in_use\": %u, "
        "\"current_usage_bytes\": %" PRIu64
        ", \"peak_usage_bytes\": %" PRIu64
        ", \"allocations\": %" PRIu64
        ", \"allocation_rejects\": %" PRIu64 "}%s\n",
        pool.block_bytes,
        pool.capacity,
        pool.current_in_use,
        pool.peak_in_use,
        current_bytes,
        peak_bytes,
        pool.allocations,
        pool.allocation_rejects,
        trailing_comma ? "," : "");
}

void write_service_memory_component_json(
        FILE *stream,
        const char *name,
        const fk_no_nic_service_memory_component_receipt_v1 &component,
        bool trailing_comma) {
    std::fputs("      {\"name\": ", stream);
    json_string(stream, name);
    std::fputs(", \"disposition\": ", stream);
    json_string(
        stream,
        fk_no_nic_service_memory_disposition_name_v1(
            component.disposition));
    std::fprintf(
        stream,
        ", \"configured_reserved_bytes\": %" PRIu64
        ", \"observed_reserved_bytes\": %" PRIu64
        ", \"peak_bytes\": %" PRIu64
        ", \"reservation_exact\": %s"
        ", \"trace_independent\": %s"
        ", \"bounded_window\": %s"
        ", \"hash_bound\": %s}%s\n",
        component.configured_reserved_bytes,
        component.observed_reserved_bytes,
        component.peak_bytes,
        component.reservation_exact ? "true" : "false",
        component.trace_independent ? "true" : "false",
        component.bounded_window ? "true" : "false",
        component.hash_bound ? "true" : "false",
        trailing_comma ? "," : "");
}

void write_service_memory_json(
        FILE *stream,
        const fk_no_nic_service_memory_receipt_v1 &receipt) {
    std::fputs(
        "  \"service_memory\": {\n"
        "    \"receipt_abi\": \"flowkeep.no_nic.service_memory.receipt.v1\",\n"
        "    \"receipt_sha256\": \"",
        stream);
    static constexpr char hex[] = "0123456789abcdef";
    for (uint8_t value : receipt.receipt_sha256) {
        std::fputc(hex[value >> 4u], stream);
        std::fputc(hex[value & 0x0fu], stream);
    }
    std::fprintf(
        stream,
        "\",\n"
        "    \"receipt_hash_valid\": %s,\n"
        "    \"component_count\": %u,\n"
        "    \"auxiliary_component_count\": %u,\n"
        "    \"trace_packet_count\": %" PRIu64 ",\n"
        "    \"bridge_epoch_packet_limit\": %" PRIu64 ",\n"
        "    \"completion_window_capacity\": %u,\n"
        "    \"checkpoint_payload_capacity\": %u,\n"
        "    \"configured_reserved_bytes\": %" PRIu64 ",\n"
        "    \"observed_reserved_bytes\": %" PRIu64 ",\n"
        "    \"peak_bytes\": %" PRIu64 ",\n"
        "    \"trace_sized_active_reserved_bytes\": %" PRIu64 ",\n"
        "    \"separate_from_controlled_state\": %s,\n"
        "    \"component_accounting_exact\": %s,\n"
        "    \"auxiliary_accounting_exact\": %s,\n"
        "    \"active_reservations_trace_independent\": %s,\n"
        "    \"completion_transport_window_bounded\": %s,\n"
        "    \"external_source_window_bounded\": %s,\n"
        "    \"finite_epoch_handoff_required\": %s,\n"
        "    \"formal_14_component_complete\": %s,\n"
        "    \"formal_non_active_component_mask\": %u,\n"
        "    \"components\": [\n",
        fk_no_nic_service_memory_receipt_verify_v1(&receipt)
            ? "true" : "false",
        receipt.component_count,
        receipt.auxiliary_component_count,
        receipt.trace_packet_count,
        receipt.bridge_epoch_packet_limit,
        receipt.completion_window_capacity,
        receipt.checkpoint_payload_capacity,
        receipt.total_configured_reserved_bytes,
        receipt.total_observed_reserved_bytes,
        receipt.total_peak_bytes,
        receipt.trace_sized_active_reserved_bytes,
        receipt.service_memory_separate_from_controlled_state
            ? "true" : "false",
        receipt.component_accounting_exact ? "true" : "false",
        receipt.auxiliary_accounting_exact ? "true" : "false",
        receipt.active_reservations_trace_independent ? "true" : "false",
        receipt.completion_transport_window_bounded ? "true" : "false",
        receipt.external_source_window_bounded ? "true" : "false",
        receipt.finite_epoch_handoff_required ? "true" : "false",
        receipt.formal_14_component_complete ? "true" : "false",
        receipt.formal_non_active_component_mask);
    for (uint32_t index = 0u;
         index < FK_IDENTITY_SERVICE_COMPONENT_COUNT; ++index) {
        write_service_memory_component_json(
            stream,
            fk_identity_pipeline_service_component_name(
                static_cast<fk_identity_pipeline_service_component>(index)),
            receipt.components[index],
            index + 1u != FK_IDENTITY_SERVICE_COMPONENT_COUNT);
    }
    std::fputs("    ],\n    \"auxiliary_components\": [\n", stream);
    for (uint32_t index = 0u;
         index < FK_NO_NIC_SERVICE_MEMORY_AUXILIARY_COMPONENT_COUNT;
         ++index) {
        write_service_memory_component_json(
            stream,
            fk_no_nic_service_memory_auxiliary_component_name_v1(index),
            receipt.auxiliary_components[index],
            index + 1u !=
                FK_NO_NIC_SERVICE_MEMORY_AUXILIARY_COMPONENT_COUNT);
    }
    std::fputs("    ]\n  },\n", stream);
}

void write_trigger_receipt_json(
        FILE *stream,
        const fk_no_nic_trigger_receipt_v2 &receipt) {
    std::fprintf(
        stream,
        "  \"event_student_trigger_receipt_v2\": {\n"
        "    \"abi_version\": %u,\n"
        "    \"trigger_protocol\": %u,\n"
        "    \"ordinal_base\": %u,\n"
        "    \"worker_count\": %u,\n"
        "    \"checkpoint_trigger_messages\": %" PRIu64 ",\n"
        "    \"scheduled_periodic_ticks\": %" PRIu64 ",\n"
        "    \"empty_periodic_ticks\": %" PRIu64 ",\n"
        "    \"same_timestamp_unchanged_periodic_coalesces\": %" PRIu64 ",\n"
        "    \"checkpoint_trigger_results\": %" PRIu64 ",\n"
        "    \"periodic_trigger_results\": %" PRIu64 ",\n"
        "    \"output_results\": %" PRIu64 ",\n"
        "    \"trigger_ordinal_sum\": %" PRIu64 ",\n"
        "    \"trigger_ordinal_xor\": %" PRIu64 ",\n"
        "    \"trigger_ordinal_max\": %" PRIu64 ",\n"
        "    \"checkpoint_packet_results\": {\"4\": %" PRIu64
        ", \"8\": %" PRIu64 ", \"12\": %" PRIu64
        ", \"20\": %" PRIu64 "},\n"
        "    \"invalid_checkpoint_packet_rejections\": %" PRIu64 ",\n"
        "    \"trigger_protocol_rejections\": %" PRIu64 ",\n"
        "    \"final_watermark_ns\": %" PRIu64 ",\n"
        "    \"event_path_reserved_bytes\": %" PRIu64 ",\n"
        "    \"student_shards_reserved_bytes\": %" PRIu64 ",\n"
        "    \"student_model\": {\n"
        "      \"continuous_features\": %u,\n"
        "      \"input_features\": %u,\n"
        "      \"hidden\": %u,\n"
        "      \"identity_embedding\": %u,\n"
        "      \"event_hidden\": %u,\n"
        "      \"parameter_floats\": %u,\n"
        "      \"decision_threshold\": %.9g,\n"
        "      \"artifact_sha256\": \"%s\",\n"
        "      \"feature_schema_sha256\": \"%s\",\n"
        "      \"architecture_sha256\": \"%s\",\n"
        "      \"source_state_sha256\": \"%s\",\n"
        "      \"payload_sha256\": \"%s\"\n"
        "    },\n"
        "    \"final_flush_complete\": %s,\n"
        "    \"command_queues_empty\": %s,\n"
        "    \"result_queues_empty\": %s,\n"
        "    \"worker_failure\": %s,\n"
        "    \"conservation_valid\": %s,\n"
        "    \"deterministic_smoke_model\": %s\n"
        "  },\n",
        receipt.abi_version,
        receipt.trigger_protocol,
        receipt.ordinal_base,
        receipt.worker_count,
        receipt.checkpoint_trigger_messages,
        receipt.scheduled_periodic_ticks,
        receipt.empty_periodic_ticks,
        receipt.same_timestamp_unchanged_periodic_coalesces,
        receipt.checkpoint_trigger_results,
        receipt.periodic_trigger_results,
        receipt.output_results,
        receipt.trigger_ordinal_sum,
        receipt.trigger_ordinal_xor,
        receipt.trigger_ordinal_max,
        receipt.checkpoint_packet_4_results,
        receipt.checkpoint_packet_8_results,
        receipt.checkpoint_packet_12_results,
        receipt.checkpoint_packet_20_results,
        receipt.invalid_checkpoint_packet_rejections,
        receipt.trigger_protocol_rejections,
        receipt.final_watermark_ns,
        receipt.event_path_reserved_bytes,
        receipt.student_shards_reserved_bytes,
        receipt.student_continuous_features,
        receipt.student_input_features,
        receipt.student_hidden,
        receipt.student_identity_embedding,
        receipt.student_event_hidden,
        receipt.student_parameter_floats,
        static_cast<double>(receipt.student_decision_threshold),
        receipt.student_artifact_sha256,
        receipt.student_feature_schema_sha256,
        receipt.student_architecture_sha256,
        receipt.student_source_state_sha256,
        receipt.student_payload_sha256,
        receipt.final_flush_complete ? "true" : "false",
        receipt.command_queues_empty ? "true" : "false",
        receipt.result_queues_empty ? "true" : "false",
        receipt.worker_failure ? "true" : "false",
        receipt.conservation_valid ? "true" : "false",
        receipt.deterministic_smoke_model ? "true" : "false");
}

void write_frozen_causal_aggregation_json(
        FILE *stream,
        const fk_no_nic_frozen_causal_aggregation_receipt_v1 &receipt) {
    if (receipt.enabled == 0u) {
        std::fputs(
            "  \"frozen_causal_aggregation\": {\n"
            "    \"abi_version\": 0,\n"
            "    \"aggregation_mode\": null,\n"
            "    \"aggregation_rule\": null,\n"
            "    \"threshold_profile\": null,\n"
            "    \"threshold\": null,\n"
            "    \"aggregation_contract_sha256\": null,\n"
            "    \"development_oof_receipt_sha256\": null,\n"
            "    \"checkpoint_updates\": 0,\n"
            "    \"periodic_updates\": 0,\n"
            "    \"total_feature_updates\": 0,\n"
            "    \"initialized_event_generations\": 0,\n"
            "    \"feature_state_resets\": 0,\n"
            "    \"inference_calls\": 0,\n"
            "    \"inference_failures\": 0,\n"
            "    \"model_load_successes\": 0,\n"
            "    \"model_load_failures\": 0,\n"
            "    \"mixed_mask_triggers\": 0,\n"
            "    \"causal_records_presented\": 0,\n"
            "    \"requested_effective_mask_divergences\": 0,\n"
            "    \"protocol_action_domain_checks\": 0,\n"
            "    \"protocol_action_domain_violations\": 0,\n"
            "    \"physical_feature_mask_checks\": 0,\n"
            "    \"physical_feature_mask_mismatches\": 0,\n"
            "    \"requested_mask_or\": 0,\n"
            "    \"physical_final_mask_or\": 0,\n"
            "    \"scheduled_periodic_ticks\": 0,\n"
            "    \"empty_periodic_ticks\": 0,\n"
            "    \"same_timestamp_periodic_coalesces\": 0,\n"
            "    \"threshold_crossings\": 0,\n"
            "    \"latched_alert_outputs\": 0,\n"
            "    \"stale_handle_rejections\": 0,\n"
            "    \"reserved_bytes\": 0,\n"
            "    \"causal_event_calibrator_artifact_sha256\": null,\n"
            "    \"causal_event_calibrator_source_npz_sha256\": null,\n"
            "    \"causal_event_feature_contract_sha256\": null,\n"
            "    \"causal_event_real_prefix_receipt_sha256\": null,\n"
            "    \"enabled\": false,\n"
            "    \"calibrator_enabled\": false,\n"
            "    \"model_loaded\": false,\n"
            "    \"model_used\": false,\n"
            "    \"deterministic_smoke_model\": false,\n"
            "    \"complete\": false\n"
            "  },\n",
            stream);
        return;
    }
    std::fprintf(
        stream,
        "  \"frozen_causal_aggregation\": {\n"
        "    \"abi_version\": %u,\n"
        "    \"aggregation_mode\": \"frozen_cpp_causal\",\n"
        "    \"aggregation_rule\": \"%s\",\n"
        "    \"threshold_profile\": \"%s\",\n"
        "    \"threshold\": %.9g,\n"
        "    \"aggregation_contract_sha256\": \"%s\",\n"
        "    \"development_oof_receipt_sha256\": \"%s\",\n"
        "    \"checkpoint_updates\": %" PRIu64 ",\n"
        "    \"periodic_updates\": %" PRIu64 ",\n"
        "    \"total_feature_updates\": %" PRIu64 ",\n"
        "    \"initialized_event_generations\": %" PRIu64 ",\n"
        "    \"feature_state_resets\": %" PRIu64 ",\n"
        "    \"inference_calls\": %" PRIu64 ",\n"
        "    \"inference_failures\": %" PRIu64 ",\n"
        "    \"model_load_successes\": %" PRIu64 ",\n"
        "    \"model_load_failures\": %" PRIu64 ",\n"
        "    \"mixed_mask_triggers\": %" PRIu64 ",\n"
        "    \"causal_records_presented\": %" PRIu64 ",\n"
        "    \"requested_effective_mask_divergences\": %" PRIu64 ",\n"
        "    \"protocol_action_domain_checks\": %" PRIu64 ",\n"
        "    \"protocol_action_domain_violations\": %" PRIu64 ",\n"
        "    \"physical_feature_mask_checks\": %" PRIu64 ",\n"
        "    \"physical_feature_mask_mismatches\": %" PRIu64 ",\n"
        "    \"requested_mask_or\": %u,\n"
        "    \"physical_final_mask_or\": %u,\n"
        "    \"scheduled_periodic_ticks\": %" PRIu64 ",\n"
        "    \"empty_periodic_ticks\": %" PRIu64 ",\n"
        "    \"same_timestamp_periodic_coalesces\": %" PRIu64 ",\n"
        "    \"threshold_crossings\": %" PRIu64 ",\n"
        "    \"latched_alert_outputs\": %" PRIu64 ",\n"
        "    \"stale_handle_rejections\": %" PRIu64 ",\n"
        "    \"reserved_bytes\": %" PRIu64 ",\n",
        receipt.abi_version,
        receipt.aggregation_rule,
        receipt.threshold_profile,
        static_cast<double>(receipt.threshold),
        receipt.aggregation_contract_sha256,
        receipt.development_oof_receipt_sha256,
        receipt.checkpoint_updates,
        receipt.periodic_updates,
        receipt.total_feature_updates,
        receipt.initialized_event_generations,
        receipt.feature_state_resets,
        receipt.inference_calls,
        receipt.inference_failures,
        receipt.model_load_successes,
        receipt.model_load_failures,
        receipt.mixed_mask_triggers,
        receipt.causal_records_presented,
        receipt.requested_effective_mask_divergences,
        receipt.protocol_action_domain_checks,
        receipt.protocol_action_domain_violations,
        receipt.physical_feature_mask_checks,
        receipt.physical_feature_mask_mismatches,
        receipt.requested_mask_or,
        receipt.physical_final_mask_or,
        receipt.scheduled_periodic_ticks,
        receipt.empty_periodic_ticks,
        receipt.same_timestamp_periodic_coalesces,
        receipt.threshold_crossings,
        receipt.latched_alert_outputs,
        receipt.stale_handle_rejections,
        receipt.reserved_bytes);
    std::fputs("    \"causal_event_calibrator_artifact_sha256\": ", stream);
    if (receipt.calibrator_enabled != 0u)
        json_string(stream, receipt.causal_event_calibrator_artifact_sha256);
    else
        std::fputs("null", stream);
    std::fputs(
        ",\n    \"causal_event_calibrator_source_npz_sha256\": ", stream);
    if (receipt.calibrator_enabled != 0u)
        json_string(stream, receipt.causal_event_calibrator_source_npz_sha256);
    else
        std::fputs("null", stream);
    std::fputs(
        ",\n    \"causal_event_feature_contract_sha256\": ", stream);
    if (receipt.calibrator_enabled != 0u)
        json_string(stream, receipt.causal_event_feature_contract_sha256);
    else
        std::fputs("null", stream);
    std::fputs(
        ",\n    \"causal_event_real_prefix_receipt_sha256\": ", stream);
    if (receipt.calibrator_enabled != 0u)
        json_string(
            stream, receipt.causal_event_real_prefix_receipt_sha256);
    else
        std::fputs("null", stream);
    std::fprintf(
        stream,
        ",\n    \"enabled\": %s,\n"
        "    \"calibrator_enabled\": %s,\n"
        "    \"model_loaded\": %s,\n"
        "    \"model_used\": %s,\n"
        "    \"deterministic_smoke_model\": %s,\n"
        "    \"complete\": %s\n"
        "  },\n",
        receipt.enabled ? "true" : "false",
        receipt.calibrator_enabled ? "true" : "false",
        receipt.model_loaded ? "true" : "false",
        receipt.model_used ? "true" : "false",
        receipt.deterministic_smoke_model ? "true" : "false",
        receipt.complete ? "true" : "false");
}

const char *value_v3_role_name(enum fk_value_model_v3_role role) {
    switch (role) {
    case FK_VALUE_MODEL_V3_FLOWKEEP:
        return "flowkeep";
    case FK_VALUE_MODEL_V3_IMMEDIATE_RISK:
        return "learned_immediate_risk";
    case FK_VALUE_MODEL_V3_FUTURE_RISK:
        return "learned_future_risk";
    case FK_VALUE_MODEL_V3_DETECTION_LOSS:
        return "learned_detection_loss";
    }
    return nullptr;
}

const char *value_v3_family_name(enum fk_value_model_v3_family family) {
    switch (family) {
    case FK_VALUE_MODEL_V3_RIDGE:
        return "ridge";
    case FK_VALUE_MODEL_V3_BOUNDED_TREE:
        return "bounded_tree";
    case FK_VALUE_MODEL_V3_LIGHT_MLP:
        return "light_mlp";
    case FK_VALUE_MODEL_V3_ACTION_RIDGE:
        return "action_ridge";
    case FK_VALUE_MODEL_V3_HYBRID_GATE_FOREST:
        return "hybrid_gate_forest";
    }
    return nullptr;
}

void write_value_model_v3_json(
        FILE *stream,
        const fk_no_nic_value_model_v3_receipt_v1 &receipt) {
    std::fputs("  \"value_model_v3\": {\n", stream);
    if (receipt.enabled == 0u) {
        std::fputs(
            "    \"abi_version\": 0,\n"
            "    \"model_kind\": null,\n"
            "    \"format_version\": 0,\n"
            "    \"qualification_scope\": null,\n"
            "    \"legacy_v1_development_diagnostic_only\": false,\n"
            "    \"formal_detection_eligible\": false,\n"
            "    \"family\": null,\n"
            "    \"role\": null,\n"
            "    \"context_features\": 0,\n"
            "    \"query_features\": 0,\n"
            "    \"model_features\": 0,\n"
            "    \"learned_actions\": 0,\n"
            "    \"outputs\": 0,\n"
            "    \"conditional_equivalence_tolerance\": 0,\n"
            "    \"training_target_uses_detector_threshold\": false,\n"
            "    \"formal_event_student_counterfactual_semantics_aligned\": false,\n"
            "    \"detector_threshold_bits\": 0,\n"
            "    \"artifact_file_bytes\": 0,\n"
            "    \"model_reserved_bytes\": 0,\n"
            "    \"frozen_context_reserved_bytes\": 0,\n"
            "    \"load_attempts\": 0,\n"
            "    \"load_successes\": 0,\n"
            "    \"load_failures\": 0,\n"
            "    \"contexts_built\": 0,\n"
            "    \"context_failures\": 0,\n"
            "    \"inference_calls\": 0,\n"
            "    \"inference_failures\": 0,\n"
            "    \"core_zero_violations\": 0,\n"
            "    \"protocol_domain_violations\": 0,\n"
            "    \"artifact_sha256\": null,\n"
            "    \"training_receipt_sha256\": null,\n"
            "    \"online_context_schema_sha256\": null,\n"
            "    \"requested_action_domain_sha256\": null,\n"
            "    \"online_deadline_contract_sha256\": null,\n"
            "    \"detector_threshold_binding_sha256\": null,\n"
            "    \"detector_threshold_selection_receipt_sha256\": null,\n"
            "    \"detector_operating_point_receipt_sha256\": null,\n"
            "    \"enabled\": false,\n"
            "    \"loaded\": false,\n"
            "    \"used\": false,\n"
            "    \"complete\": false\n"
            "  },\n",
            stream);
        return;
    }
    const char *role = value_v3_role_name(receipt.role);
    const char *family = value_v3_family_name(receipt.family);
    const bool legacy_v1 = receipt.format_version == 1u;
    const char *qualification_scope = legacy_v1
        ? "development_diagnostic_only_legacy_v1"
        : "no_nic_runtime_receipt_no_accuracy_claim";
    std::fprintf(
        stream,
        "    \"abi_version\": %u,\n"
        "    \"model_kind\": \"value_v3_64d\",\n"
        "    \"format_version\": %u,\n"
        "    \"qualification_scope\": \"%s\",\n"
        "    \"legacy_v1_development_diagnostic_only\": %s,\n"
        "    \"formal_detection_eligible\": false,\n"
        "    \"family\": \"%s\",\n"
        "    \"role\": \"%s\",\n"
        "    \"context_features\": %u,\n"
        "    \"query_features\": %u,\n"
        "    \"model_features\": %u,\n"
        "    \"learned_actions\": %u,\n"
        "    \"outputs\": %u,\n"
        "    \"conditional_equivalence_tolerance\": %.9g,\n"
        "    \"training_target_uses_detector_threshold\": %s,\n"
        "    \"formal_event_student_counterfactual_semantics_aligned\": %s,\n"
        "    \"detector_threshold_bits\": %u,\n"
        "    \"core_is_learned_action\": false,\n"
        "    \"core_reference_output\": 0,\n"
        "    \"artifact_file_bytes\": %" PRIu64 ",\n"
        "    \"model_reserved_bytes\": %" PRIu64 ",\n"
        "    \"frozen_context_reserved_bytes\": %" PRIu64 ",\n"
        "    \"load_attempts\": %" PRIu64 ",\n"
        "    \"load_successes\": %" PRIu64 ",\n"
        "    \"load_failures\": %" PRIu64 ",\n"
        "    \"contexts_built\": %" PRIu64 ",\n"
        "    \"context_failures\": %" PRIu64 ",\n"
        "    \"inference_calls\": %" PRIu64 ",\n"
        "    \"inference_failures\": %" PRIu64 ",\n"
        "    \"core_zero_violations\": %" PRIu64 ",\n"
        "    \"protocol_domain_violations\": %" PRIu64 ",\n"
        "    \"artifact_sha256\": \"%s\",\n"
        "    \"training_receipt_sha256\": \"%s\",\n"
        "    \"online_context_schema_sha256\": \"%s\",\n"
        "    \"requested_action_domain_sha256\": \"%s\",\n"
        "    \"online_deadline_contract_sha256\": \"%s\",\n"
        "    \"detector_threshold_binding_sha256\": \"%s\",\n"
        "    \"detector_threshold_selection_receipt_sha256\": \"%s\",\n"
        "    \"detector_operating_point_receipt_sha256\": \"%s\",\n"
        "    \"enabled\": %s,\n"
        "    \"loaded\": %s,\n"
        "    \"used\": %s,\n"
        "    \"complete\": %s\n"
        "  },\n",
        receipt.abi_version, receipt.format_version, qualification_scope,
        legacy_v1 ? "true" : "false",
        family == nullptr ? "invalid" : family,
        role == nullptr ? "invalid" : role,
        receipt.context_features, receipt.query_features,
        receipt.model_features, receipt.learned_actions, receipt.outputs,
        static_cast<double>(receipt.conditional_equivalence_tolerance),
        receipt.training_target_uses_detector_threshold ? "true" : "false",
        receipt.formal_event_student_counterfactual_semantics_aligned
            ? "true" : "false",
        receipt.detector_threshold_bits,
        receipt.artifact_file_bytes, receipt.model_reserved_bytes,
        receipt.frozen_context_reserved_bytes, receipt.load_attempts,
        receipt.load_successes, receipt.load_failures,
        receipt.contexts_built, receipt.context_failures,
        receipt.inference_calls, receipt.inference_failures,
        receipt.core_zero_violations, receipt.protocol_domain_violations,
        receipt.artifact_sha256, receipt.training_receipt_sha256,
        receipt.online_context_schema_sha256,
        receipt.requested_action_domain_sha256,
        receipt.online_deadline_contract_sha256,
        receipt.detector_threshold_binding_sha256,
        receipt.detector_threshold_selection_receipt_sha256,
        receipt.detector_operating_point_receipt_sha256,
        receipt.enabled ? "true" : "false",
        receipt.loaded ? "true" : "false",
        receipt.used ? "true" : "false",
        receipt.complete ? "true" : "false");
}

void write_decision_observability_json(
        FILE *stream,
        const Options &options,
        const fk_no_nic_decision_observability_v1 &value) {
    std::fputs(
        "  \"decision_observability\": {\n"
        "    \"trace_path\": ",
        stream);
    if (options.decision_trace == nullptr)
        std::fputs("null", stream);
    else
        json_string(stream, options.decision_trace);
    std::fprintf(
        stream,
        ",\n    \"trace_abi\": %u,\n"
        "    \"records\": {\"all\": %" PRIu64
        ", \"checkpoint\": %" PRIu64 ", \"periodic\": %" PRIu64
        ", \"evidence_transition\": %" PRIu64
        ", \"exported\": %" PRIu64 ", \"sink_rejections\": %" PRIu64
        ", \"rolling_hash64\": \"%016" PRIx64 "\"},\n"
        "    \"trace_export_complete\": %s,\n"
        "    \"timing\": {\n"
        "      \"definition\": \"physical_steady_clock; packet_to_decision=RX_ingress_to_Event_Student_decision\",\n"
        "      \"quantile_method\": \"log2_lower_bound_histogram_64_bins\",\n"
        "      \"detection_ns\": {\"samples\": %" PRIu64
        ", \"p50\": %" PRIu64 ", \"p95\": %" PRIu64
        ", \"p99\": %" PRIu64 "},\n"
        "      \"packet_to_decision_ns\": {\"samples\": %" PRIu64
        ", \"p50\": %" PRIu64 ", \"p95\": %" PRIu64
        ", \"p99\": %" PRIu64 "},\n"
        "      \"flow_detector_ns\": {\"samples\": %" PRIu64
        ", \"p50\": %" PRIu64 ", \"p95\": %" PRIu64
        ", \"p99\": %" PRIu64 "},\n"
        "      \"timestamp_failures\": %" PRIu64
        ", \"order_failures\": %" PRIu64 ", \"complete\": %s\n"
        "    },\n"
        "    \"queue\": {\n"
        "      \"scope\": \"offered_interval_source_start_to_rx_stop\",\n"
        "      \"samples\": %" PRIu64 ", \"max_stage_peak_entries\": %" PRIu64
        ", \"ols_slope_entries_per_second\": %.17g"
        ", \"peak_positive_slope_entries_per_second\": %.17g,\n"
        "      \"stage_peaks\": {\"sequencer_ingress\": %" PRIu64
        ", \"sequencer_reorder\": %" PRIu64 ", \"dispatch\": %" PRIu64
        ", \"owner_output\": %" PRIu64 ", \"checkpoint_reorder\": %" PRIu64
        ", \"student_command\": %" PRIu64 ", \"student_result\": %" PRIu64
        "}\n    },\n"
        "    \"recovery\": {\"definition\": \"RX_normal_stop_to_all_pipeline_and_Student_queues_drained\""
        ", \"start_ns\": %" PRIu64 ", \"complete_ns\": %" PRIu64
        ", \"time_ns\": %" PRIu64 ", \"complete\": %s},\n"
        "    \"loss_accounting\": {\n"
        "      \"fatal\": {\"packet_drops\": %" PRIu64
        ", \"decision_drops\": %" PRIu64 ", \"integrity_events\": %" PRIu64
        "},\n"
        "      \"policy_reject\": {\"flows\": %" PRIu64
        ", \"state_actions\": %" PRIu64 ", \"evidence\": %" PRIu64 "},\n"
        "      \"retry_only_backpressure_events\": %" PRIu64
        ", \"complete\": %s\n"
        "    }\n"
        "  },\n",
        value.abi_version,
        value.decision_records + value.evidence_transition_records,
        value.checkpoint_records,
        value.periodic_records,
        value.evidence_transition_records,
        value.trace_sink_records,
        value.trace_sink_rejections,
        value.trace_rolling_hash64,
        value.trace_export_complete ? "true" : "false",
        value.detection_latency_samples,
        value.detection_latency_p50_ns,
        value.detection_latency_p95_ns,
        value.detection_latency_p99_ns,
        value.packet_to_decision_samples,
        value.packet_to_decision_p50_ns,
        value.packet_to_decision_p95_ns,
        value.packet_to_decision_p99_ns,
        value.flow_detector_latency_samples,
        value.flow_detector_latency_p50_ns,
        value.flow_detector_latency_p95_ns,
        value.flow_detector_latency_p99_ns,
        value.timestamp_failures,
        value.order_failures,
        value.timing_complete ? "true" : "false",
        value.queue_samples,
        value.queue_peak_entries,
        value.queue_ols_slope_entries_per_second,
        value.queue_peak_positive_slope_entries_per_second,
        value.sequencer_ingress_peak,
        value.sequencer_reorder_peak,
        value.dispatch_peak,
        value.owner_output_peak,
        value.checkpoint_reorder_peak,
        value.student_command_peak,
        value.student_result_peak,
        value.recovery_start_monotonic_ns,
        value.recovery_complete_monotonic_ns,
        value.recovery_time_ns,
        value.recovery_complete ? "true" : "false",
        value.fatal_packet_drops,
        value.fatal_decision_drops,
        value.fatal_integrity_events,
        value.policy_flow_rejects,
        value.policy_state_action_rejects,
        value.policy_evidence_rejects,
        value.transient_backpressure_events,
        value.drop_accounting_complete ? "true" : "false");
}

void write_evidence_transition_receipt_json(
        FILE *stream,
        const fk_no_nic_evidence_transition_receipt_v1 &value) {
    std::fprintf(
        stream,
        "  \"evidence_transition_receipt\": {\n"
        "    \"abi_version\": %u,\n"
        "    \"table_records_emitted\": %" PRIu64 ",\n"
        "    \"runtime_records_drained\": %" PRIu64 ",\n"
        "    \"trace_records_emitted\": %" PRIu64 ",\n"
        "    \"drain_calls\": %" PRIu64 ",\n"
        "    \"terminal_timer_scan_passes\": %" PRIu64 ",\n"
        "    \"terminal_timer_component_releases\": %" PRIu64 ",\n"
        "    \"last_transition_sequence\": %" PRIu64 ",\n"
        "    \"sequence_failures\": %" PRIu64 ",\n"
        "    \"queue_full_rejects\": %" PRIu64 ",\n"
        "    \"terminal_pending\": %u,\n"
        "    \"sequence_contiguous\": %s,\n"
        "    \"terminal_queue_empty\": %s,\n"
        "    \"complete\": %s\n"
        "  },\n",
        value.abi_version,
        value.table_records_emitted,
        value.runtime_records_drained,
        value.trace_records_emitted,
        value.drain_calls,
        value.terminal_timer_scan_passes,
        value.terminal_timer_component_releases,
        value.last_transition_sequence,
        value.sequence_failures,
        value.queue_full_rejects,
        value.terminal_pending,
        value.sequence_contiguous ? "true" : "false",
        value.terminal_queue_empty ? "true" : "false",
        value.complete ? "true" : "false");
}

void write_detection_service_capacity_json(
        FILE *stream,
        const fk_no_nic_detection_service_capacity_receipt_v1 &value) {
    std::fprintf(
        stream,
        "  \"detection_service_capacity\": {\n"
        "    \"abi_version\": %u,\n"
        "    \"budget_disposition\": \"separate_detection_service_state\",\n"
        "    \"actor_maximum_events\": %u,\n"
        "    \"actor_maximum_total_flows\": %u,\n"
        "    \"actor_maximum_flows_per_event\": %u,\n"
        "    \"window_maximum_events\": %u,\n"
        "    \"window_maximum_total_flows\": %u,\n"
        "    \"actor_active_events\": %u,\n"
        "    \"actor_peak_active_events\": %u,\n"
        "    \"actor_active_flows\": %u,\n"
        "    \"actor_peak_active_flows\": %u,\n"
        "    \"actor_event_capacity_evictions\": %" PRIu64 ",\n"
        "    \"actor_total_flow_capacity_evictions\": %" PRIu64 ",\n"
        "    \"actor_flow_capacity_rollovers\": %" PRIu64 ",\n"
        "    \"expected_flow_capacity_rollovers\": %" PRIu64 ",\n"
        "    \"flow_rollover_contract_enforced\": %s,\n"
        "    \"flow_rollover_contract_valid\": %s,\n"
        "    \"window_live_slot_reuse_conflicts\": %" PRIu64 ",\n"
        "    \"window_event_slots_reused\": %" PRIu64 ",\n"
        "    \"capacity_clean\": %s\n"
        "  },\n",
        value.abi_version,
        value.actor_maximum_events,
        value.actor_maximum_total_flows,
        value.actor_maximum_flows_per_event,
        value.window_maximum_events,
        value.window_maximum_total_flows,
        value.actor_active_events,
        value.actor_peak_active_events,
        value.actor_active_flows,
        value.actor_peak_active_flows,
        value.actor_event_capacity_evictions,
        value.actor_total_flow_capacity_evictions,
        value.actor_flow_capacity_rollovers,
        value.expected_flow_capacity_rollovers,
        value.flow_rollover_contract_enforced ? "true" : "false",
        value.flow_rollover_contract_valid ? "true" : "false",
        value.window_live_slot_reuse_conflicts,
        value.window_event_slots_reused,
        value.capacity_clean ? "true" : "false");
}

void write_packet_disposition_json(
        FILE *stream,
        const fk_no_nic_full_composition_result &result) {
    std::fprintf(
        stream,
        "    \"packet_disposition\": {"
        "\"input_packets\": %" PRIu64
        ", \"parser_ok\": %" PRIu64
        ", \"parser_rejected\": %" PRIu64
        ", \"identity_skipped\": %" PRIu64
        ", \"identity_rejected\": %" PRIu64
        ", \"runtime_frames\": %" PRIu64
        ", \"ordinary_observed\": %" PRIu64
        ", \"quic_observed\": %" PRIu64
        ", \"runtime_ignored\": %" PRIu64
        ", \"admission_rejected\": %" PRIu64
        ", \"terminal\": %" PRIu64
        ", \"conserved\": %s},\n",
        result.packets_created,
        result.router_parser_successes,
        result.router_parser_rejections,
        result.identity_skip_reclaims,
        result.identity_reject_reclaims,
        result.runtime_frames,
        result.owner_ordinary,
        result.owner_quic,
        result.owner_ignored,
        result.owner_admission_rejected,
        result.owner_terminal_results,
        result.packet_disposition_conserved ? "true" : "false");
}

const char *finite_epoch_quic_drain_reason_json_name(uint8_t reason) {
    switch (static_cast<fk_quic_cid_finite_epoch_drain_reason>(reason)) {
    case FK_QUIC_CID_FINITE_EPOCH_DRAIN_REASON_NONE:
        return "none";
    case FK_QUIC_CID_FINITE_EPOCH_DRAIN_IDLE_TIMEOUT_AFTER_EOF:
        return "idle_timeout_after_eof";
    }
    return "unknown";
}

const char *finite_epoch_quic_path_drain_reason_json_name(
        uint8_t reason) {
    switch (static_cast<
            fk_quic_presentation_path_finite_epoch_drain_reason>(reason)) {
    case FK_QUIC_PRESENTATION_PATH_FINITE_EPOCH_DRAIN_REASON_NONE:
        return "none";
    case FK_QUIC_PRESENTATION_PATH_FINITE_EPOCH_DRAIN_IDLE_TIMEOUT_AFTER_EOF:
        return "idle_timeout_after_eof";
    }
    return "unknown";
}

void write_quic_connection_capacity_json(
        FILE *stream,
        const fk_no_nic_quic_identity_observability_v1 &value) {
    std::fprintf(
        stream,
        "    \"quic_connection_capacity\": {\n"
        "      \"abi_version\": %u,\n"
        "      \"maximum_connections\": %u,\n"
        "      \"active_connections_at_end\": %u,\n"
        "      \"peak_active_connections\": %u,\n"
        "      \"admission_rejections\": %" PRIu64 ",\n"
        "      \"cid_map_admission_rejections\": %" PRIu64 ",\n"
        "      \"capacity_conserved\": %s,\n"
        "      \"terminal_active_zero\": %s,\n"
        "      \"admission_rejections_zero\": %s,\n"
        "      \"tcp_only_no_quic_activity\": %s,\n"
        "      \"finite_epoch_drain\": {\"requested\": %s, "
        "\"after_input_eof\": %s, \"reason\": \"%s\", "
        "\"terminal_semantic_timestamp_ns\": %" PRIu64
        ", \"active_connections_before\": %u, "
        "\"connections_drained\": %u, "
        "\"active_connections_after\": %u, "
        "\"presentation_path_reason\": \"%s\", "
        "\"path_active_logical_connections_before\": %u, "
        "\"paths_before\": %u, \"paths_drained\": %u, "
        "\"path_active_logical_connections_after\": %u, "
        "\"paths_after\": %u, "
        "\"path_complete\": %s, \"complete\": %s, "
        "\"before_publisher_terminal\": %s},\n"
        "      \"retirement_delivery\": {"
        "\"publisher_controls_committed\": %" PRIu64
        ", \"publisher_terminal_batches_committed\": %" PRIu64
        ", \"publisher_terminal_empty\": %" PRIu64
        ", \"publisher_marked_controls_at_end\": %u, "
        "\"dispatch_controls_enqueued\": %" PRIu64
        ", \"dispatch_controls_normal_dequeued\": %" PRIu64
        ", \"dispatch_control_depth_at_end\": %" PRIu64
        ", \"owner_controls_dequeued\": %" PRIu64
        ", \"owner_controls_acked\": %" PRIu64
        ", \"adapter_retire_calls\": %" PRIu64
        ", \"adapter_retire_acked\": %" PRIu64
        ", \"cid_ack_calls\": %" PRIu64
        ", \"cid_acks\": %" PRIu64
        ", \"cid_connections_retired_pending_owner_ack_total\": %" PRIu64
        ", \"cid_retirement_publication_marks\": %" PRIu64
        ", \"ack_failures\": %" PRIu64
        ", \"publisher_accounting_conserved\": %s, "
        "\"publisher_formal_complete\": %s, "
        "\"dispatch_observations_sealed\": %s, "
        "\"delivery_conserved\": %s, \"owner_ack_complete\": %s},\n"
        "      \"router\": {\"initial_packets\": %" PRIu64
        ", \"long_packets\": %" PRIu64
        ", \"short_packets\": %" PRIu64
        ", \"quic_data_committed\": %" PRIu64
        ", \"quic_skip_committed\": %" PRIu64
        ", \"quic_disposition_conserved\": %s},\n"
        "      \"cid_map\": {\"actual_capacity\": %u, "
        "\"active_connections_at_end\": %u, "
        "\"peak_active_connections\": %u, "
        "\"active_cids_at_end\": %u, \"peak_active_cids\": %u, "
        "\"pending_handshakes_at_end\": %u, "
        "\"peak_pending_handshakes\": %u, "
        "\"retired_pending_owner_ack_at_end\": %u, "
        "\"binding_credits_in_use_at_end\": %u, "
        "\"observations\": %" PRIu64
        ", \"connections_created\": %" PRIu64
        ", \"rejects\": {\"connection_capacity\": %" PRIu64
        ", \"fixed_owner_capacity\": %" PRIu64
        ", \"cid_capacity\": %" PRIu64
        ", \"per_connection_cid_capacity\": %" PRIu64
        ", \"pending_handshake_capacity\": %" PRIu64
        ", \"hash_chain_lookup\": %" PRIu64
        ", \"hash_chain_registration\": %" PRIu64
        ", \"hash_chain_internal\": %" PRIu64
        ", \"direction_conflicts\": %" PRIu64
        ", \"same_cid_dual_role\": %" PRIu64
        ", \"hard_integrity\": %" PRIu64
        ", \"allocator_integrity\": %" PRIu64 "}},\n"
        "      \"presentation_path\": {\"actual_capacity\": %u, "
        "\"active_connections_at_end\": %u, "
        "\"peak_active_connections\": %u, "
        "\"active_paths_at_end\": %u, \"peak_active_paths\": %u, "
        "\"classify_calls\": %" PRIu64
        ", \"register_calls\": %" PRIu64
        ", \"rejected_operations\": %" PRIu64
        ", \"rejects\": {\"global_capacity\": %" PRIu64
        ", \"per_connection_capacity\": %" PRIu64
        ", \"hash_chain_capacity\": %" PRIu64
        ", \"invalid_input\": %" PRIu64
        ", \"generation_conflict\": %" PRIu64
        ", \"internal_integrity\": %" PRIu64 "}},\n"
        "      \"owner_flow_bindings\": {\"actual_capacity\": %u, "
        "\"active_at_end\": %" PRIu64
        ", \"peak_active_sum\": %" PRIu64
        ", \"unbound_at_end\": %" PRIu64
        ", \"retired_pending_at_end\": %" PRIu64
        ", \"bind_attempts\": %" PRIu64
        ", \"created\": %" PRIu64
        ", \"idempotent\": %" PRIu64
        ", \"rejects\": {\"conflicts\": %" PRIu64
        ", \"missing\": %" PRIu64
        ", \"stale_generation\": %" PRIu64
        ", \"handle_mismatch\": %" PRIu64
        ", \"direction_mismatch\": %" PRIu64
        ", \"cid_generation_mismatch\": %" PRIu64
        ", \"fixed_owner_mismatch\": %" PRIu64
        ", \"slot_reuse\": %" PRIu64
        ", \"retire_expectation\": %" PRIu64
        ", \"slot_out_of_range\": %" PRIu64
        ", \"invalid_requests\": %" PRIu64
        ", \"state_integrity\": %" PRIu64 "}},\n"
        "      \"initial_crypto_gate\": {\"begin_attempts\": %" PRIu64
        ", \"allowed\": %" PRIu64
        ", \"deferred\": %" PRIu64
        ", \"rejected\": %" PRIu64
        ", \"rejects\": {\"pressure\": %" PRIu64
        ", \"global_token\": %" PRIu64
        ", \"prefix_credit\": %" PRIu64
        ", \"prefix_table\": %" PRIu64
        ", \"oversized\": %" PRIu64
        ", \"invalid_request\": %" PRIu64
        ", \"internal\": %" PRIu64 "}}\n"
        "    }\n",
        value.abi_version,
        value.maximum_connections,
        value.cid_active_connections_at_end,
        value.cid_peak_active_connections,
        value.admission_rejections,
        value.cid_map_admission_rejections,
        value.capacity_conserved ? "true" : "false",
        value.terminal_active_zero ? "true" : "false",
        value.admission_rejections_zero ? "true" : "false",
        value.tcp_only_no_quic_activity ? "true" : "false",
        value.finite_epoch_drain_requested ? "true" : "false",
        value.finite_epoch_drain_after_input_eof ? "true" : "false",
        finite_epoch_quic_drain_reason_json_name(
            value.finite_epoch_drain_reason),
        value.finite_epoch_drain_timestamp_ns,
        value.finite_epoch_active_before,
        value.finite_epoch_connections_drained,
        value.finite_epoch_active_after,
        finite_epoch_quic_path_drain_reason_json_name(
            value.finite_epoch_path_drain_reason),
        value.finite_epoch_path_active_connections_before,
        value.finite_epoch_paths_before,
        value.finite_epoch_paths_drained,
        value.finite_epoch_path_active_connections_after,
        value.finite_epoch_paths_after,
        value.finite_epoch_path_drain_complete ? "true" : "false",
        value.finite_epoch_drain_complete ? "true" : "false",
        value.finite_epoch_drain_before_publisher_terminal
            ? "true" : "false",
        value.publisher_controls_committed,
        value.publisher_terminal_batches_committed,
        value.publisher_terminal_empty,
        value.publisher_marked_controls_at_end,
        value.dispatch_retire_controls_enqueued,
        value.dispatch_retire_controls_normal_dequeued,
        value.dispatch_retire_control_depth_at_end,
        value.owner_retire_controls_dequeued,
        value.owner_retire_controls_acked,
        value.adapter_retire_calls,
        value.adapter_retire_acked,
        value.cid_retirement_ack_calls,
        value.cid_retirement_acks,
        value.cid_connections_retired_pending_owner_ack_total,
        value.cid_retirement_publication_marks,
        value.retirement_ack_failures,
        value.publisher_accounting_conserved ? "true" : "false",
        value.publisher_formal_complete ? "true" : "false",
        value.dispatch_observations_sealed ? "true" : "false",
        value.retirement_delivery_conserved ? "true" : "false",
        value.owner_ack_complete ? "true" : "false",
        value.router_quic_initial_packets,
        value.router_quic_long_packets,
        value.router_quic_short_packets,
        value.router_quic_data_committed_transfers,
        value.router_quic_skip_committed_reclaims,
        value.router_quic_disposition_conserved ? "true" : "false",
        value.cid_map_maximum_connections,
        value.cid_active_connections_at_end,
        value.cid_peak_active_connections,
        value.cid_active_cids_at_end,
        value.cid_peak_active_cids,
        value.cid_pending_handshakes_at_end,
        value.cid_peak_pending_handshakes,
        value.cid_retired_pending_owner_ack_at_end,
        value.cid_binding_credits_in_use_at_end,
        value.cid_observations,
        value.cid_connections_created,
        value.cid_connection_capacity_rejects,
        value.cid_fixed_owner_capacity_rejects,
        value.cid_capacity_rejects,
        value.cid_per_connection_capacity_rejects,
        value.cid_pending_handshake_capacity_rejects,
        value.cid_hash_chain_lookup_rejects,
        value.cid_hash_chain_registration_rejects,
        value.cid_hash_chain_internal_rejects,
        value.cid_direction_conflicts,
        value.cid_same_cid_dual_role_rejects,
        value.cid_hard_integrity_failures,
        value.cid_allocator_integrity_failures,
        value.path_maximum_connections,
        value.path_active_connections_at_end,
        value.path_peak_active_connections,
        value.path_active_paths_at_end,
        value.path_peak_active_paths,
        value.path_classify_calls,
        value.path_register_calls,
        value.path_rejected_operations,
        value.path_global_capacity_rejects,
        value.path_per_connection_capacity_rejects,
        value.path_hash_chain_capacity_rejects,
        value.path_invalid_input_rejects,
        value.path_generation_conflict_rejects,
        value.path_internal_integrity_rejects,
        value.binding_maximum_connections,
        value.binding_active_at_end,
        value.binding_peak_active_sum,
        value.binding_unbound_at_end,
        value.binding_retired_pending_at_end,
        value.binding_bind_attempts,
        value.binding_created,
        value.binding_idempotent,
        value.binding_conflicts,
        value.binding_missing_rejects,
        value.binding_stale_generation_rejects,
        value.binding_handle_mismatch_rejects,
        value.binding_direction_mismatch_rejects,
        value.binding_cid_generation_mismatch_rejects,
        value.binding_fixed_owner_mismatch_rejects,
        value.binding_slot_reuse_rejects,
        value.binding_retire_expectation_rejects,
        value.binding_slot_out_of_range_rejects,
        value.binding_invalid_requests,
        value.binding_state_integrity_failures,
        value.crypto_gate_begin_attempts,
        value.crypto_gate_begin_allowed,
        value.crypto_gate_begin_deferred,
        value.crypto_gate_begin_rejected,
        value.crypto_gate_pressure_rejects,
        value.crypto_gate_global_token_rejects,
        value.crypto_gate_prefix_credit_rejects,
        value.crypto_gate_prefix_table_rejects,
        value.crypto_gate_oversized_rejects,
        value.crypto_gate_invalid_request_rejects,
        value.crypto_gate_internal_rejects);
}

const char *pressure_denominator_json_name(uint8_t denominator) {
    switch (static_cast<fk_compact_pressure_denominator>(denominator)) {
    case FK_COMPACT_PRESSURE_DENOMINATOR_NONE:
        return "none";
    case FK_COMPACT_PRESSURE_DENOMINATOR_OPTIONAL_EVIDENCE_CAPACITY_BYTES:
        return "optional_evidence_capacity_bytes";
    case FK_COMPACT_PRESSURE_DENOMINATOR_MAX_OPTIONAL_TYPED_POOL_UTILIZATION:
        return "maximum_optional_typed_pool_utilization";
    }
    return "unknown";
}

bool write_success_json(
        const Options &options,
        const Invocation &invocation,
        const PcapScan &scan,
        const fk_no_nic_full_composition_result &result,
        const ActorNamespaceMonitorMapInput &actor_namespace_monitor_map,
        const DecisionTraceFeaturesReceipt &trace_features,
        const RetentionDetectorCompositionReceipt &composition,
        const WholePipelineTiming &timing,
        const fk_source_record_intervention_plan_receipt_v1
            &source_record_intervention_receipt) {
    char fixed_ttl_receipt[320]{};
    if (!fk_fixed_ttl_retention_format_receipt_json(
            fixed_ttl_receipt,
            sizeof(fixed_ttl_receipt),
            options.retention_policy,
            &options.fixed_ttl_retention)) {
        return false;
    }
    FILE *stream = open_output(options.output);
    if (stream == nullptr)
        return false;
    std::fputs("{\n  \"protocol\": \"flowkeep-no-nic-pcap-runner-v1\",\n"
               "  \"status\": \"complete\",\n"
               "  \"input\": {\n    \"pcap\": ", stream);
    json_string(stream, options.pcap);
    std::fprintf(
        stream,
        ",\n    \"format\": \"classic-pcap\",\n"
        "    \"link_type\": \"Ethernet\",\n"
        "    \"file_bytes\": %" PRIu64 ",\n"
        "    \"packets\": %" PRIu64 ",\n"
        "    \"captured_bytes\": %" PRIu64 ",\n"
        "    \"wire_bytes\": %" PRIu64 ",\n"
        "    \"declared_snapshot_length\": %u,\n"
        "    \"first_timestamp_ns\": %" PRIu64 ",\n"
        "    \"last_timestamp_ns\": %" PRIu64 ",\n"
        "    \"sha256\": \"",
        scan.file_bytes,
        scan.packets,
        scan.captured_bytes,
        scan.wire_bytes,
        scan.snap_length,
        scan.first_timestamp_ns,
        scan.last_timestamp_ns);
    write_sha256_hex(stream, scan.sha256);
    std::fputs("\"\n  },\n", stream);
    std::fputs("  \"configuration\": {\n    \"budget\": ", stream);
    json_string(stream, options.budget_name);
    std::fprintf(
        stream,
        ",\n    \"controlled_budget_bytes\": %" PRIu64 ",\n"
        "    \"maximum_flows\": %u,\n"
        "    \"owner_hash_key_hex\": \"%s\",\n"
        "    \"maximum_quic_connections\": %u,\n"
        "    \"retention_policy\": \"%s\",\n"
        "    \"fixed_ttl_retention_receipt\": %s,\n"
        "    \"seeded_random_retention_seed\": %" PRIu64 ",\n"
        "    \"seeded_random_retention_seed_precommitted\": %s,\n"
        "    \"lambda_memory_per_byte\": %.9g,\n"
        "    \"lambda_queue\": %.9g,\n"
        "    \"lambda_deadline\": %.9g,\n"
        "    \"budget_monotone_action_chain\": true,\n"
        "    \"action_rank\": \"%s\",\n"
        "    \"memory_enforcement\": \"hard_budget_not_sparse_target\",\n"
        "    \"pool_weights\": [%u, %u, %u, %u],\n"
        "    \"mbuf_pool_capacity\": %u,\n"
        "    \"rx_burst_capacity\": %u,\n"
        "    \"action_model\": ",
        budget_bytes(options.budget),
        options.maximum_flows,
        options.owner_hash_key_hex,
        options.maximum_quic_connections,
        options.retention_policy_name,
        fixed_ttl_receipt,
        options.seeded_random_retention_seed,
        options.seeded_random_retention_seed_seen ? "true" : "false",
        static_cast<double>(options.lambda_memory_per_byte),
        static_cast<double>(options.lambda_queue),
        static_cast<double>(options.lambda_deadline),
        retention_rank_name(options.retention_policy),
        options.pool_weights.stat_percent,
        options.pool_weights.seq_percent,
        options.pool_weights.ja4_pending_percent,
        options.pool_weights.ja4_summary_percent,
        kMbufPoolCapacity,
        kBurstCapacity);
    if (effective_action_model(options) == nullptr)
        std::fputs("null", stream);
    else
        json_string(stream, effective_action_model(options));
    std::fputs(",\n    \"action_model_kind\": ", stream);
    json_string(
        stream,
        options.value_model_v3_artifact != nullptr
            ? "value_v3_64d"
            : (options.action_model != nullptr ? "legacy_30d" : "none"));
    std::fputs(",\n    \"action_schema_sha256\": ", stream);
    if (options.action_schema == nullptr)
        std::fputs("null", stream);
    else
        json_string(stream, options.action_schema);
    std::fputs(",\n    \"value_model_v3_role\": ", stream);
    if (options.value_model_v3_artifact == nullptr) {
        std::fputs("null", stream);
    } else {
        json_string(stream, value_v3_role_name(options.value_model_v3_role));
    }
    std::fputs(",\n    \"value_model_v3_artifact_sha256\": ", stream);
    if (options.value_model_v3_artifact_sha == nullptr)
        std::fputs("null", stream);
    else
        json_string(stream, options.value_model_v3_artifact_sha);
    std::fputs(",\n    \"value_model_v3_training_receipt_sha256\": ", stream);
    if (options.value_model_v3_training_receipt_sha == nullptr)
        std::fputs("null", stream);
    else
        json_string(stream, options.value_model_v3_training_receipt_sha);
    std::fputs(",\n    \"value_model_v3_requested_action_domain_sha256\": ", stream);
    if (options.value_model_v3_action_domain_sha == nullptr)
        std::fputs("null", stream);
    else
        json_string(stream, options.value_model_v3_action_domain_sha);
    std::fputs(",\n    \"value_model_v3_online_deadline_contract_sha256\": ", stream);
    if (options.value_model_v3_deadline_contract_sha == nullptr)
        std::fputs("null", stream);
    else
        json_string(stream, options.value_model_v3_deadline_contract_sha);
    std::fputs(",\n    \"transition_value_model\": ", stream);
    if (options.transition_value_model == nullptr)
        std::fputs("null", stream);
    else
        json_string(stream, options.transition_value_model);
    std::fputs(",\n    \"transition_value_schema_sha256\": ", stream);
    if (options.transition_value_schema_sha == nullptr)
        std::fputs("null", stream);
    else
        json_string(stream, options.transition_value_schema_sha);
    std::fputs(",\n    \"transition_value_model_sha256\": ", stream);
    if (options.transition_value_model_sha == nullptr)
        std::fputs("null", stream);
    else
        json_string(stream, options.transition_value_model_sha);
    std::fputs(",\n    \"detector_model\": ", stream);
    if (options.detector_model == nullptr)
        std::fputs("null", stream);
    else
        json_string(stream, options.detector_model);
    std::fputs(",\n    \"detector_state_model_dir\": ", stream);
    if (options.detector_state_model_dir == nullptr)
        std::fputs("null", stream);
    else
        json_string(stream, options.detector_state_model_dir);
    std::fputs(",\n    \"detector_schema_sha256\": ", stream);
    json_string(stream, options.detector_schema);
    std::fputs(",\n    \"monitored_cidr\": ", stream);
    if (options.monitored_cidr == nullptr)
        std::fputs("null", stream);
    else
        json_string(stream, options.monitored_cidr);
    const bool fixed_compact_monitor =
        options.compact_monitored_ipv4_pool != nullptr;
    const bool mapped_compact_monitor =
        actor_namespace_monitor_map.requested;
    const bool map_binding_valid = mapped_compact_monitor &&
        actor_namespace_monitor_map.loaded &&
        actor_namespace_monitor_map.whole_file_sha256_verified &&
        actor_namespace_monitor_map.actor_session_configured &&
        actor_namespace_monitor_map.indices != nullptr &&
        actor_namespace_monitor_map.metadata.namespace_count != 0u;
    const uint32_t monitor_slots = mapped_compact_monitor
        ? actor_namespace_monitor_map.metadata.slots_per_namespace
        : options.compact_monitored_ipv4_slots_per_namespace;
    const uint32_t monitor_namespaces = mapped_compact_monitor
        ? actor_namespace_monitor_map.metadata.namespace_count
        : options.compact_monitored_ipv4_namespace_count;
    std::fputs(",\n    \"compact_monitored_ipv4\": {\n", stream);
    std::fprintf(
        stream,
        "      \"enabled\": %s,\n"
        "      \"mode\": \"%s\",\n"
        "      \"formula\": \"pool_base + (namespace_id-1)*slots_per_namespace + identity_index\",\n"
        "      \"pool\": ",
        fixed_compact_monitor || mapped_compact_monitor ? "true" : "false",
        mapped_compact_monitor
            ? "per_namespace_sidecar"
            : (fixed_compact_monitor ? "fixed_index" : "disabled"));
    if (mapped_compact_monitor) {
        std::fprintf(
            stream,
            "\"%u.%u.%u.%u/%u\"",
            static_cast<unsigned>(
                actor_namespace_monitor_map.metadata.pool_base[0]),
            static_cast<unsigned>(
                actor_namespace_monitor_map.metadata.pool_base[1]),
            static_cast<unsigned>(
                actor_namespace_monitor_map.metadata.pool_base[2]),
            static_cast<unsigned>(
                actor_namespace_monitor_map.metadata.pool_base[3]),
            static_cast<unsigned>(
                actor_namespace_monitor_map.metadata.pool_prefix_length));
    } else if (fixed_compact_monitor) {
        json_string(stream, options.compact_monitored_ipv4_pool);
    } else {
        std::fputs("null", stream);
    }
    std::fprintf(
        stream,
        ",\n      \"slots_per_namespace\": %u,\n"
        "      \"namespace_count\": %u,\n"
        "      \"monitored_identity_index\": ",
        monitor_slots,
        monitor_namespaces);
    if (fixed_compact_monitor) {
        std::fprintf(
            stream, "%u",
            options.compact_monitored_ipv4_identity_index);
    } else {
        std::fputs("null", stream);
    }
    std::fprintf(
        stream,
        ",\n      \"vector_entry_count\": %u,\n"
        "      \"actor_identity_contract_sha256\": ",
        mapped_compact_monitor ? monitor_namespaces : 0u);
    if (options.actor_identity_contract_sha == nullptr)
        std::fputs("null", stream);
    else
        json_string(stream, options.actor_identity_contract_sha);
    std::fprintf(
        stream,
        ",\n      \"expected_flow_capacity_rollovers\": %" PRIu64 ",\n"
        "      \"actor_namespace_monitor_map\": {\n"
        "        \"requested\": %s,\n"
        "        \"loaded\": %s,\n"
        "        \"binding_valid\": %s,\n"
        "        \"format\": ",
        options.expected_flow_capacity_rollovers,
        mapped_compact_monitor ? "true" : "false",
        actor_namespace_monitor_map.loaded ? "true" : "false",
        map_binding_valid ? "true" : "false");
    if (mapped_compact_monitor)
        json_string(stream, "FKANM01");
    else
        std::fputs("null", stream);
    std::fputs(",\n        \"path\": ", stream);
    if (options.actor_namespace_monitor_map == nullptr)
        std::fputs("null", stream);
    else
        json_string(stream, options.actor_namespace_monitor_map);
    std::fputs(",\n        \"expected_whole_file_sha256\": ", stream);
    if (options.actor_namespace_monitor_map_sha256 == nullptr)
        std::fputs("null", stream);
    else
        json_string(stream, options.actor_namespace_monitor_map_sha256);
    std::fputs(",\n        \"observed_whole_file_sha256\": ", stream);
    if (!actor_namespace_monitor_map.loaded) {
        std::fputs("null", stream);
    } else {
        std::fputc('"', stream);
        write_sha256_hex(
            stream, actor_namespace_monitor_map.whole_file_sha256);
        std::fputc('"', stream);
    }
    std::fprintf(
        stream,
        ",\n        \"whole_file_sha256_verified\": %s,\n"
        "        \"file_bytes\": %" PRIu64 ",\n"
        "        \"entry_count\": %u,\n"
        "        \"minimum_identity_index\": ",
        actor_namespace_monitor_map.whole_file_sha256_verified
            ? "true" : "false",
        actor_namespace_monitor_map.file_bytes,
        actor_namespace_monitor_map.loaded ? monitor_namespaces : 0u);
    if (actor_namespace_monitor_map.loaded) {
        std::fprintf(
            stream, "%u",
            actor_namespace_monitor_map.minimum_identity_index);
    } else {
        std::fputs("null", stream);
    }
    std::fputs(",\n        \"maximum_identity_index\": ", stream);
    if (actor_namespace_monitor_map.loaded) {
        std::fprintf(
            stream, "%u",
            actor_namespace_monitor_map.maximum_identity_index);
    } else {
        std::fputs("null", stream);
    }
    std::fputs(",\n        \"source_mapping_sha256\": ", stream);
    if (!actor_namespace_monitor_map.loaded) {
        std::fputs("null", stream);
    } else {
        std::fputc('"', stream);
        for (uint8_t value :
             actor_namespace_monitor_map.metadata.source_mapping_sha256) {
            static constexpr char kHex[] = "0123456789abcdef";
            std::fputc(kHex[value >> 4u], stream);
            std::fputc(kHex[value & 0x0fu], stream);
        }
        std::fputc('"', stream);
    }
    std::fprintf(
        stream,
        ",\n        \"immutable_loaded_once\": %s,\n"
        "        \"labels_consumed\": false\n"
        "      }\n"
        "    }",
        map_binding_valid ? "true" : "false");
    std::fputs("\n  },\n", stream);
    write_retention_detector_composition_json(
        stream, options, composition);
    std::fprintf(
        stream,
        "  \"detection\": {\n"
        "    \"flow_open_messages\": %" PRIu64 ",\n"
        "    \"flow_continue_messages\": %" PRIu64 ",\n"
        "    \"requests\": %" PRIu64 ",\n"
        "    \"decisions\": %" PRIu64 ",\n"
        "    \"positive_decisions_at_0_5\": %" PRIu64 ",\n"
        "    \"score_valid\": %s,\n"
        "    \"score_min\": %.9g,\n"
        "    \"score_max\": %.9g,\n"
        "    \"score_sum\": %.17g,\n"
        "    \"labels_consumed\": false,\n"
        "    \"accuracy_claim\": false\n  },\n",
        result.flow_open_messages,
        result.flow_continue_messages,
        result.detection_requests,
        result.detector_executions,
        result.positive_detection_decisions,
        result.detector_executions != 0u ? "true" : "false",
        result.detection_score_min,
        result.detection_score_max,
        result.detection_score_sum);
    std::fprintf(
        stream,
        "  \"global_order\": {\n"
        "    \"input_sequence_base\": 0,\n"
        "    \"input_sequence_exclusive\": %" PRIu64 ",\n"
        "    \"packets_sequenced\": %" PRIu64 ",\n"
        "    \"input_packet_order_complete\": %s,\n"
        "    \"association_messages\": %" PRIu64 ",\n"
        "    \"last_association_input_sequence_valid\": %s,\n"
        "    \"last_association_input_sequence\": %" PRIu64 ",\n"
        "    \"strictly_increasing\": %s,\n"
        "    \"reorder_drained\": %s\n  },\n",
        scan.packets,
        result.sequencer_transferred,
        result.sequencer_transferred == scan.packets ? "true" : "false",
        result.reorder_messages,
        result.reorder_messages != 0u ? "true" : "false",
        result.last_reorder_input_sequence,
        result.global_order_conserved ? "true" : "false",
        result.reorder_drained ? "true" : "false");
    std::fprintf(
        stream,
        "  \"drops_rejects\": {\n"
        "    \"rx\": {\"callback_retries\": %" PRIu64
        ", \"shape_or_integrity_rejects\": %" PRIu64 "},\n"
        "    \"sequencer\": {\"queue_full\": %" PRIu64
        ", \"integrity\": %" PRIu64 "},\n"
        "    \"identity\": {\"skip_reclaims\": %" PRIu64
        ", \"reject_reclaims\": %" PRIu64
        ", \"backpressure\": %" PRIu64 "},\n"
        "    \"router\": {\"resolver\": %" PRIu64
        ", \"parser\": %" PRIu64 ", \"identity\": %" PRIu64
        ", \"completion_backpressure\": %" PRIu64
        ", \"completion_rejections\": %" PRIu64 "},\n"
        "    \"dispatch\": {\"ordered_skips\": %" PRIu64
        ", \"queue_full\": %" PRIu64 ", \"invalid_routes\": %" PRIu64
        "},\n"
        "    \"owner\": {\"ignored\": %" PRIu64
        ", \"admission_rejected\": %" PRIu64
        ", \"output_backpressure\": %" PRIu64
        ", \"terminal\": %" PRIu64 ", \"reclaim_failures\": %" PRIu64
        "},\n"
        "    \"bridge\": {\"reservation_backpressure\": %" PRIu64
        ", \"reorder_backpressure\": %" PRIu64
        ", \"publication_rejections\": %" PRIu64
        ", \"integrity_rejections\": %" PRIu64 "},\n"
        "    \"runtime\": {\"parse_ignored\": %" PRIu64
        ", \"flow_admission_rejected\": %" PRIu64
        ", \"state_update_failures\": %" PRIu64
        ", \"checkpoint_failures\": %" PRIu64 "},\n"
        "    \"flow_table\": {\"admission_rejected\": %" PRIu64
        ", \"evidence_allocation_failures\": %" PRIu64 "},\n"
        "    \"parser\": {\"total\": %" PRIu64
        ", \"reason_enum\": \"fk_native_parse_code_v1\", "
        "\"by_code\": {\"TRUNCATED\": %" PRIu64
        ", \"MALFORMED\": %" PRIu64
        ", \"UNSUPPORTED_L2\": %" PRIu64
        ", \"UNSUPPORTED_L3\": %" PRIu64
        ", \"UNSUPPORTED_L4\": %" PRIu64
        ", \"FRAGMENTED\": %" PRIu64
        ", \"CAP_EXCEEDED\": %" PRIu64
        "}, \"conserved\": %s}\n  },\n",
        result.rx_callback_retries,
        result.rx_shape_rejections,
        result.sequencer_queue_full_rejections,
        result.sequencer_integrity_rejections,
        result.identity_skip_reclaims,
        result.identity_reject_reclaims,
        result.identity_backpressure,
        result.router_resolver_rejections,
        result.router_parser_rejections,
        result.router_identity_rejections,
        result.router_completion_backpressure,
        result.router_completion_rejections,
        result.dispatch_ordered_skips,
        result.dispatch_queue_full,
        result.dispatch_invalid_routes,
        result.owner_ignored,
        result.owner_admission_rejected,
        result.owner_output_backpressure,
        result.owner_terminal_results,
        result.owner_reclaim_failures,
        result.bridge_reservation_backpressure,
        result.bridge_reorder_backpressure,
        result.bridge_publication_rejections,
        result.bridge_integrity_rejections,
        result.runtime_parse_ignored,
        result.runtime_flow_admission_rejects,
        result.runtime_state_update_failures,
        result.runtime_checkpoint_failures,
        result.table_admission_rejects,
        result.table_evidence_allocation_failures,
        result.router_parser_rejections,
        result.router_parser_rejections_by_code[FK_PARSE_TRUNCATED],
        result.router_parser_rejections_by_code[FK_PARSE_MALFORMED],
        result.router_parser_rejections_by_code[FK_PARSE_UNSUPPORTED_L2],
        result.router_parser_rejections_by_code[FK_PARSE_UNSUPPORTED_L3],
        result.router_parser_rejections_by_code[FK_PARSE_UNSUPPORTED_L4],
        result.router_parser_rejections_by_code[FK_PARSE_FRAGMENTED],
        result.router_parser_rejections_by_code[FK_PARSE_CAP_EXCEEDED],
        result.router_parser_reason_conserved ? "true" : "false");
    const bool optional_state_competition_observed =
        result.action_pool_unavailable_records != 0u ||
        result.action_budget_rejections != 0u ||
        result.stat_pool.allocation_rejects != 0u ||
        result.seq_pool.allocation_rejects != 0u ||
        result.ja4_pending_pool.allocation_rejects != 0u ||
        result.ja4_summary_pool.allocation_rejects != 0u;
    std::fprintf(
        stream,
        "  \"retention_diagnostics\": {\n"
        "    \"runtime_frames\": %" PRIu64 ",\n"
        "    \"runtime_post_final_checkpoint_tail_packets\": %" PRIu64 ",\n"
        "    \"runtime_bound_final_tail_fast_path_packets\": %" PRIu64 ",\n"
        "    \"runtime_parse_ignored\": %" PRIu64 ",\n"
        "    \"exact_runtime_disposition_conserved\": %s,\n"
        "    \"flows_created\": %" PRIu64 ",\n"
        "    \"flows_released\": %" PRIu64 ",\n"
        "    \"active_flows_at_end\": %" PRIu64 ",\n"
        "    \"peak_active_flows\": %" PRIu64 ",\n"
        "    \"runtime_optional_timer_exact_boundaries\": %" PRIu64 ",\n"
        "    \"runtime_optional_timer_boundary_stalls\": %" PRIu64 ",\n"
        "    \"runtime_timer_deadline_queries\": %" PRIu64 ",\n"
        "    \"runtime_timer_deadline_rebuilds\": %" PRIu64 ",\n"
        "    \"runtime_timer_deadline_probes\": %" PRIu64 ",\n"
        "    \"runtime_idle_scan_calls\": %" PRIu64 ",\n"
        "    \"runtime_idle_scan_probes\": %" PRIu64 ",\n"
        "    \"runtime_idle_scan_gated_calls\": %" PRIu64 ",\n"
        "    \"runtime_idle_scan_completed_cycles\": %" PRIu64 ",\n"
        "    \"semantic_timer_retry\": {\n"
        "      \"owner_data_drain_retries\": %" PRIu64 ",\n"
        "      \"owner_retire_drain_retries\": %" PRIu64 ",\n"
        "      \"adapter_data_step_calls\": %" PRIu64 ",\n"
        "      \"adapter_data_step_completions\": %" PRIu64 ",\n"
        "      \"adapter_data_drain_required\": %" PRIu64 ",\n"
        "      \"adapter_data_step_failures\": %" PRIu64 ",\n"
        "      \"adapter_retire_step_calls\": %" PRIu64 ",\n"
        "      \"adapter_retire_step_completions\": %" PRIu64 ",\n"
        "      \"adapter_retire_drain_required\": %" PRIu64 ",\n"
        "      \"adapter_retire_step_failures\": %" PRIu64 "\n"
        "    },\n"
        "    \"checkpoint_decisions\": %" PRIu64 ",\n"
        "    \"value_model_calls\": %" PRIu64 ",\n"
        "    \"value_model_failures\": %" PRIu64 ",\n"
        "    \"value_inference_failures\": %" PRIu64 ",\n"
        "    \"value_transition_failures\": %" PRIu64 ",\n"
        "    \"value_inference_ns\": %" PRIu64 ",\n"
        "    \"detector_inference_ns\": %" PRIu64 ",\n"
        "    \"value_v3_cache_hits\": %" PRIu64 ",\n"
        "    \"value_v3_cache_misses\": %" PRIu64 ",\n"
        "    \"value_v3_inferences_avoided\": %" PRIu64 ",\n"
        "    \"transition_value_calls\": %" PRIu64 ",\n"
        "    \"transition_value_failures\": %" PRIu64 ",\n"
        "    \"transition_value_inference_ns\": %" PRIu64 ",\n"
        "    \"selected_mask_counts\": [",
        result.runtime_frames,
        result.runtime_post_final_checkpoint_tail_packets,
        result.runtime_bound_final_tail_fast_path_packets,
        result.runtime_parse_ignored,
        result.packet_disposition_conserved ? "true" : "false",
        result.flows_created,
        result.flows_released,
        result.active_flows,
        result.peak_active_flows,
        result.runtime_optional_timer_exact_boundaries,
        result.runtime_optional_timer_boundary_stalls,
        result.runtime_timer_deadline_queries,
        result.runtime_timer_deadline_rebuilds,
        result.runtime_timer_deadline_probes,
        result.runtime_idle_scan_calls,
        result.runtime_idle_scan_probes,
        result.runtime_idle_scan_gated_calls,
        result.runtime_idle_scan_completed_cycles,
        result.owner_data_semantic_drain_retries,
        result.owner_retire_semantic_drain_retries,
        result.adapter_semantic_data_step_calls,
        result.adapter_semantic_data_step_completions,
        result.adapter_semantic_data_drain_required,
        result.adapter_semantic_data_step_failures,
        result.adapter_semantic_retire_step_calls,
        result.adapter_semantic_retire_step_completions,
        result.adapter_semantic_retire_drain_required,
        result.adapter_semantic_retire_step_failures,
        result.checkpoint_decisions,
        result.value_model_calls,
        result.value_model_failures,
        result.value_inference_failures,
        result.value_transition_failures,
        result.value_inference_ns,
        result.detector_inference_ns,
        result.value_v3_cache_hits,
        result.value_v3_cache_misses,
        result.value_v3_inferences_avoided,
        result.transition_value_calls,
        result.transition_value_failures,
        result.transition_value_inference_ns);
    for (size_t index = 0u; index < 8u; ++index) {
        std::fprintf(
            stream,
            "%s%" PRIu64,
            index == 0u ? "" : ", ",
            result.action_selected_mask_counts[index]);
    }
    std::fputs("],\n    \"pool_unavailable_records\": ", stream);
    std::fprintf(stream, "%" PRIu64, result.action_pool_unavailable_records);
    std::fputs(
        ",\n    \"pool_unavailable_component_counts\": {\"stat\": ",
        stream);
    std::fprintf(
        stream,
        "%" PRIu64 ", \"seq\": %" PRIu64 ", \"ja4\": %" PRIu64
        "},\n    \"budget_rejections\": %" PRIu64
        ",\n    \"lru_victims_released\": %" PRIu64
        ",\n    \"lfu_victims_released\": %" PRIu64
        ",\n    \"fifo_victims_released\": %" PRIu64
        ",\n    \"seeded_random_victims_released\": %" PRIu64
        ",\n    \"automatic_pressure_transitions\": %" PRIu64
        ",\n    \"automatic_overload_transitions\": %" PRIu64
        ",\n    \"automatic_recovery_transitions\": %" PRIu64
        ",\n    \"transition_failure_counts_by_result\": [",
        result.action_pool_unavailable_component_counts[0],
        result.action_pool_unavailable_component_counts[1],
        result.action_pool_unavailable_component_counts[2],
        result.action_budget_rejections,
        result.baseline_lru_victims_released,
        result.baseline_lfu_victims_released,
        result.baseline_fifo_victims_released,
        result.baseline_seeded_random_victims_released,
        result.automatic_pressure_transitions,
        result.automatic_overload_transitions,
        result.automatic_recovery_transitions);
    for (size_t index = 0u; index < 7u; ++index) {
        std::fprintf(
            stream,
            "%s%" PRIu64,
            index == 0u ? "" : ", ",
            result.action_transition_failure_counts[index]);
    }
    std::fprintf(
        stream,
        "],\n    \"optional_state_competition_observed\": %s,\n"
        "    \"optional_state_pools\": {\n",
        optional_state_competition_observed ? "true" : "false");
    write_optional_pool_json(stream, "stat", result.stat_pool, true);
    write_optional_pool_json(stream, "seq", result.seq_pool, true);
    write_optional_pool_json(
        stream, "ja4_pending", result.ja4_pending_pool, true);
    write_optional_pool_json(
        stream, "ja4_summary", result.ja4_summary_pool, false);
    std::fputs("    },\n", stream);
    write_packet_disposition_json(stream, result);
    write_quic_connection_capacity_json(stream, result.quic_identity);
    std::fputs("  },\n", stream);
    std::fprintf(
        stream,
        "  \"ownership\": {\n"
        "    \"rx_received\": %" PRIu64 ",\n"
        "    \"sequencer_transferred\": %" PRIu64 ",\n"
        "    \"identity_data_transfers\": %" PRIu64 ",\n"
        "    \"owner_packets_completed\": %" PRIu64 ",\n"
        "    \"exact_reclaims\": %" PRIu64 ",\n"
        "    \"forced_failure_reclaims\": %" PRIu64 ",\n"
        "    \"duplicate_reclaims\": %" PRIu64 ",\n"
        "    \"live_mbufs_at_end\": %" PRIu64 ",\n"
        "    \"conserved\": %s\n  },\n",
        result.rx_received,
        result.sequencer_transferred,
        result.identity_data_transfers,
        result.owner_packets_completed,
        result.mbufs_reclaimed,
        result.io_forced_failure_reclaims,
        result.io_duplicate_reclaims,
        result.io_live_mbufs,
        result.mbuf_ownership_conserved ? "true" : "false");
    std::fprintf(
        stream,
        "  \"controlled_state\": {\n"
        "    \"scope\": \"FlowTable_BOOTSTRAP_Summary_History_TLS_JA4_lease_QUIC_CID_map_QUIC_presentation_path_owner_flow_bindings\",\n"
        "    \"actor_session_present\": true,\n"
        "    \"ceiling_bytes\": %" PRIu64 ",\n"
        "    \"reserved_bytes\": %" PRIu64 ",\n"
        "    \"unassigned_bytes\": %" PRIu64 ",\n"
        "    \"current_bytes\": %" PRIu64 ",\n"
        "    \"peak_bytes\": %" PRIu64 ",\n"
        "    \"peak_evidence_bytes\": %" PRIu64 ",\n"
        "    \"mandatory_floor_bytes\": %" PRIu64 ",\n"
        "    \"optional_evidence_capacity_bytes\": %" PRIu64 ",\n"
        "    \"optional_evidence_current_bytes\": %" PRIu64 ",\n"
        "    \"optional_evidence_peak_bytes\": %" PRIu64 ",\n"
        "    \"pressure_contract\": {\"denominator\": \"%s\", "
        "\"denominator_enum\": %u, \"semantics\": "
        "\"automatic_state_selection_uses_the_maximum_current_in_use_over_capacity_ratio_across_stat_seq_ja4_pending_and_ja4_summary_typed_pools\", "
        "\"automatic_enabled\": %s, \"enter_percent\": %u, "
        "\"exit_percent\": %u, \"overload_enter_percent\": %u, "
        "\"overload_exit_percent\": %u},\n"
        "    \"resolved_policy\": {\"pressure_mode_order\": [\"normal\", \"pressure\", \"overload\"], "
        "\"maximum_components\": [%u, %u, %u], "
        "\"minimum_utility\": [%.9g, %.9g, %.9g], "
        "\"preserve_full_state_in_normal\": %s},\n"
        "    \"pressure_accounting_failures\": %" PRIu64 ",\n"
        "    \"hard_budget_violations\": %" PRIu64 ",\n"
        "    \"state_byte_seconds\": %.17g,\n"
        "    \"state_byte_seconds_complete\": %s,\n"
        "    \"state_byte_seconds_by_component\": [%.17g, %.17g, %.17g, %.17g, %.17g, %.17g, %.17g, %.17g],\n"
        "    \"accounting_valid\": %s,\n"
        "    \"components\": {\n"
        "      \"flow_table\": {\"reserved_bytes\": %" PRIu64
        ", \"current_bytes\": %" PRIu64 ", \"peak_bytes\": %" PRIu64 "},\n"
        "      \"quic_cid_map\": {\"configured_capacity\": %u, "
        "\"actual_capacity\": %u, \"reserved_bytes\": %" PRIu64
        ", \"current_bytes\": %" PRIu64 ", \"peak_bytes\": %" PRIu64 "},\n"
        "      \"quic_presentation_path\": {\"configured_capacity\": %u, "
        "\"actual_capacity\": %u, \"reserved_bytes\": %" PRIu64
        ", \"current_bytes\": %" PRIu64 ", \"peak_bytes\": %" PRIu64 "},\n"
        "      \"owner_flow_bindings\": {\"configured_capacity\": %u, "
        "\"actual_capacity\": %u, \"reserved_bytes\": %" PRIu64
        ", \"current_bytes\": %" PRIu64 ", \"peak_bytes\": %" PRIu64 "}\n"
        "    }\n  },\n",
        result.controlled_state_ceiling_bytes,
        result.controlled_allocation_bytes,
        result.controlled_state_unassigned_bytes,
        result.controlled_state_current_bytes,
        result.controlled_state_peak_bytes,
        result.peak_evidence_storage_bytes,
        result.mandatory_floor_bytes,
        result.optional_evidence_capacity_bytes,
        result.optional_evidence_current_bytes,
        result.optional_evidence_peak_bytes,
        pressure_denominator_json_name(result.pressure_denominator),
        static_cast<unsigned>(result.pressure_denominator),
        result.automatic_pressure_enabled ? "true" : "false",
        static_cast<unsigned>(result.pressure_enter_percent),
        static_cast<unsigned>(result.pressure_exit_percent),
        static_cast<unsigned>(result.overload_enter_percent),
        static_cast<unsigned>(result.overload_exit_percent),
        static_cast<unsigned>(result.resolved_policy_maximum_components[0]),
        static_cast<unsigned>(result.resolved_policy_maximum_components[1]),
        static_cast<unsigned>(result.resolved_policy_maximum_components[2]),
        result.resolved_policy_minimum_utility[0],
        result.resolved_policy_minimum_utility[1],
        result.resolved_policy_minimum_utility[2],
        result.resolved_policy_preserve_full_state_in_normal
            ? "true" : "false",
        result.pressure_accounting_failures,
        result.controlled_state_hard_budget_violations,
        result.controlled_state_byte_seconds,
        result.state_byte_seconds_complete ? "true" : "false",
        result.state_byte_seconds_by_component[0],
        result.state_byte_seconds_by_component[1],
        result.state_byte_seconds_by_component[2],
        result.state_byte_seconds_by_component[3],
        result.state_byte_seconds_by_component[4],
        result.state_byte_seconds_by_component[5],
        result.state_byte_seconds_by_component[6],
        result.state_byte_seconds_by_component[7],
        result.controlled_state_accounting_valid ? "true" : "false",
        result.flow_table_reserved_bytes,
        result.flow_table_current_bytes,
        result.flow_table_peak_bytes,
        result.maximum_quic_connections_configured,
        result.quic_cid_connection_capacity,
        result.quic_cid_reserved_bytes,
        result.quic_cid_current_bytes,
        result.quic_cid_peak_bytes,
        result.maximum_quic_connections_configured,
        result.quic_path_connection_capacity,
        result.quic_path_reserved_bytes,
        result.quic_path_current_bytes,
        result.quic_path_peak_bytes,
        result.maximum_quic_connections_configured,
        result.owner_binding_connection_capacity,
        result.owner_binding_reserved_bytes,
        result.owner_binding_current_bytes,
        result.owner_binding_peak_bytes);
    write_trigger_receipt_json(stream, result.trigger_receipt);
    write_frozen_causal_aggregation_json(
        stream, result.frozen_causal_aggregation);
    write_value_model_v3_json(stream, result.value_model_v3);
    write_evidence_transition_receipt_json(
        stream, result.evidence_transitions);
    write_detection_service_capacity_json(
        stream, result.detection_service_capacity);
    write_decision_trace_features_json(stream, options, trace_features);
    write_source_record_intervention_json(
        stream, options, source_record_intervention_receipt,
        result.checkpoint_intervention);
    write_decision_observability_json(
        stream, options, result.observability);
    write_service_memory_json(stream, result.service_memory);
    const double packets = static_cast<double>(scan.packets);
    std::fprintf(
        stream,
        "  \"whole_pipeline_performance\": {\n"
        "    \"scope\": \"full_composition_run_including_model_load_input_processing_and_semantic_drain\",\n"
        "    \"wall_ns\": %" PRIu64 ",\n"
        "    \"process_cpu_ns\": %" PRIu64 ",\n"
        "    \"tsc_cycles\": %" PRIu64 ",\n"
        "    \"tsc_hz\": %" PRIu64 ",\n"
        "    \"tsc_hz_available\": %s,\n"
        "    \"packets\": %" PRIu64 ",\n"
        "    \"wall_ns_per_packet\": %.9g,\n"
        "    \"process_cpu_ns_per_packet\": %.9g,\n"
        "    \"tsc_cycles_per_packet\": %.9g,\n"
        "    \"hardware_pmu_cycles_per_packet\": null,\n"
        "    \"hardware_pmu_cycles_blocker\": \"not_collected_by_in_process_runner\",\n"
        "    \"complete\": %s\n"
        "  },\n",
        timing.wall_ns,
        timing.process_cpu_ns,
        timing.tsc_cycles,
        timing.tsc_hz,
        timing.tsc_hz != 0u ? "true" : "false",
        scan.packets,
        packets == 0.0 ? 0.0 : static_cast<double>(timing.wall_ns) / packets,
        packets == 0.0 ? 0.0 :
            static_cast<double>(timing.process_cpu_ns) / packets,
        packets == 0.0 ? 0.0 :
            static_cast<double>(timing.tsc_cycles) / packets,
        timing.complete ? "true" : "false");
    std::fprintf(
        stream,
        "  \"terminal\": {\n"
        "    \"state\": \"normal_complete\",\n"
        "    \"source_exhausted\": %s,\n"
        "    \"source_failed\": %s,\n"
        "    \"partial_epoch_closed\": %s,\n"
        "    \"bridge_sealed\": %s,\n"
        "    \"reorder_drained\": %s,\n"
        "    \"end_barrier_reached\": %s,\n"
        "    \"normal_complete\": %s\n  },\n",
        result.source_exhausted ? "true" : "false",
        result.source_failed ? "true" : "false",
        result.partial_epoch_closed ? "true" : "false",
        result.bridge_sealed ? "true" : "false",
        result.reorder_drained ? "true" : "false",
        result.source_exhausted && !result.source_failed &&
                result.partial_epoch_closed && result.bridge_sealed &&
                result.reorder_drained && result.normal_complete
            ? "true" : "false",
        result.normal_complete ? "true" : "false");
    write_integration_json(stream, invocation, true);
    std::fputs(
        "  \"formal_detection_result\": false,\n"
        "  \"accuracy_claim\": false,\n"
        "  \"model_status\": \"caller-supplied-unlabeled-system-smoke\"\n"
        "}\n",
        stream);
    return close_output(stream);
}

int runner_entry_impl(
        int argc,
        char **argv,
        const Invocation &invocation) {
    if (argc == 2 && argv != nullptr && argv[1] != nullptr &&
        std::strcmp(argv[1], "--help") == 0) {
        usage(stdout, argc > 0 ? argv[0] : nullptr);
        return 0;
    }
    Options options{};
    if (!parse_options(argc, argv, options)) {
        usage(stderr, argc > 0 ? argv[0] : nullptr);
        return 2;
    }
    if (invocation.production_main_opt_in &&
        std::strcmp(options.output, "-") == 0) {
        std::fputs(
            "production EAL no-NIC mode requires a JSON output file; "
            "stdout can contain EAL diagnostics\n",
            stderr);
        return 2;
    }
    const char *action_model = effective_action_model(options);
    if (std::strcmp(options.output, "-") != 0 &&
        (existing_files_alias(options.output, options.pcap) ||
         existing_files_alias(options.output, action_model) ||
         existing_files_alias(options.output, options.detector_model) ||
         existing_files_alias(
             options.output, options.actor_namespace_monitor_map) ||
         (options.event_student_artifact != nullptr &&
          existing_files_alias(
              options.output, options.event_student_artifact)) ||
         (options.causal_event_calibrator_artifact != nullptr &&
          existing_files_alias(
              options.output,
              options.causal_event_calibrator_artifact)))) {
        std::fputs("output aliases an immutable input\n", stderr);
        return 2;
    }
    if (options.decision_trace != nullptr &&
        (existing_files_alias(options.decision_trace, options.pcap) ||
         existing_files_alias(options.decision_trace, action_model) ||
         (options.detector_model != nullptr &&
          existing_files_alias(
              options.decision_trace, options.detector_model)) ||
         existing_files_alias(
             options.decision_trace,
             options.actor_namespace_monitor_map) ||
         (options.causal_event_calibrator_artifact != nullptr &&
          existing_files_alias(
              options.decision_trace,
              options.causal_event_calibrator_artifact)))) {
        std::fputs("decision trace aliases an immutable input\n", stderr);
        return 2;
    }
    if (options.decision_trace_features != nullptr &&
        (existing_files_alias(
             options.decision_trace_features, options.decision_trace) ||
         existing_files_alias(options.decision_trace_features, options.pcap) ||
         existing_files_alias(options.decision_trace_features, action_model) ||
         (options.detector_model != nullptr &&
          existing_files_alias(
              options.decision_trace_features, options.detector_model)) ||
         existing_files_alias(
             options.decision_trace_features,
             options.actor_namespace_monitor_map) ||
         (options.event_student_artifact != nullptr &&
          existing_files_alias(
              options.decision_trace_features,
              options.event_student_artifact)) ||
         (options.causal_event_calibrator_artifact != nullptr &&
          existing_files_alias(
              options.decision_trace_features,
              options.causal_event_calibrator_artifact)))) {
        std::fputs(
            "decision trace features alias another output or immutable input\n",
            stderr);
        return 2;
    }
    if (options.development_source_record_intervention_plan != nullptr &&
        (existing_files_alias(
             options.development_source_record_intervention_plan,
             options.development_packet_lineage) ||
         existing_files_alias(
             options.development_source_record_intervention_plan,
             options.output) ||
         existing_files_alias(
             options.development_source_record_intervention_plan,
             options.decision_trace) ||
         existing_files_alias(
             options.development_source_record_intervention_plan,
             options.decision_trace_features) ||
         existing_files_alias(
             options.development_packet_lineage, options.output) ||
         existing_files_alias(
             options.development_packet_lineage, options.decision_trace) ||
         existing_files_alias(
             options.development_packet_lineage,
             options.decision_trace_features))) {
        std::fputs(
            "source-record intervention input aliases an output\n", stderr);
        return 2;
    }

    ActorNamespaceMonitorMapInput actor_namespace_monitor_map;
    char error[2048]{};
    if (!load_actor_namespace_monitor_map(
            options, actor_namespace_monitor_map,
            error, sizeof(error))) {
        std::fprintf(stderr, "%s\n", error);
        (void)write_failure_json(
            options, invocation,
            "actor_namespace_monitor_map_preflight", error);
        return 2;
    }

    BoundedPcapSource source;
    fk_no_nic_decision_trace_csv_writer trace_writer;
    std::unique_ptr<fk_no_nic_detector_request_trace_csv_writer>
        trace_features_writer;
    PcapScan scan{};
    if (!source.open_scan_and_rewind(
            options.pcap, scan, error, sizeof(error))) {
        std::fprintf(stderr, "%s\n", error);
        (void)write_failure_json(
            options, invocation, "pcap_preflight", error);
        return 2;
    }
    if (scan.last_timestamp_ns >
        std::numeric_limits<uint64_t>::max() - kIdleTimeoutNs - 1u) {
        set_error(error, sizeof(error), "terminal semantic watermark overflow");
        (void)write_failure_json(
            options, invocation, "pcap_preflight", error);
        return 2;
    }
    fk_compact_checkpoint_intervention_v1 checkpoint_intervention{};
    fk_source_record_intervention_plan_receipt_v1
        source_record_intervention_receipt{};
    if (options.development_source_record_intervention_plan != nullptr &&
        !fk_source_record_intervention_plan_load(
            options.development_source_record_intervention_plan,
            options.development_packet_lineage,
            scan.sha256.data(), scan.packets,
            &checkpoint_intervention,
            &source_record_intervention_receipt,
            error, sizeof(error))) {
        std::fprintf(stderr, "%s\n", error);
        (void)write_failure_json(
            options, invocation,
            "development_source_record_intervention_preflight", error);
        return 2;
    }

    fk_no_nic_full_composition_config config{};
    fk_no_nic_full_composition_default_config_init(&config);
    config.budget_mode = options.budget;
    config.packet_count = static_cast<uint32_t>(scan.packets);
    config.bridge_epoch_packet_limit =
        config.packet_count <= UINT32_MAX - 64u
            ? config.packet_count + 64u : config.packet_count;
    config.completion_window_capacity = 64u;
    config.sequencer_ingress_capacity = 64u;
    config.rx_burst_capacity = kBurstCapacity;
    config.maximum_flows = options.maximum_flows;
    if (!parse_owner_hash_key(
            options.owner_hash_key_hex, config.owner_hash_key)) {
        set_error(error, sizeof(error), "owner hash key is invalid");
        (void)write_failure_json(
            options, invocation, "configuration", error);
        return 2;
    }
    config.owner_hash_key_precommitted = 1u;
    config.maximum_quic_connections = options.maximum_quic_connections;
    config.pool_weights = options.pool_weights;
    config.lambda_memory_per_byte = options.lambda_memory_per_byte;
    config.lambda_queue = options.lambda_queue;
    config.lambda_deadline = options.lambda_deadline;
    config.retention_discount = options.retention_discount;
    config.baseline_policy.kind = options.retention_policy;
    config.checkpoint_intervention = checkpoint_intervention;
    config.baseline_policy.maximum_lru_victims_per_decision = 64u;
    if (!fk_fixed_ttl_retention_bind_baseline(
            options.retention_policy,
            &options.fixed_ttl_retention,
            &config.baseline_policy)) {
        set_error(
            error, sizeof(error),
            "invalid fixed-TTL nanosecond binding");
        (void)write_failure_json(
            options, invocation, "configuration", error);
        return 2;
    }
    config.baseline_policy.seeded_random_seed =
        options.seeded_random_retention_seed;
    config.baseline_policy.seeded_random_seed_precommitted =
        options.seeded_random_retention_seed_seen ? 1u : 0u;
    config.idle_timeout_ns = kIdleTimeoutNs;
    config.terminal_semantic_timestamp_ns =
        scan.last_timestamp_ns + kIdleTimeoutNs + 1u;
    config.action_value_model_path = action_model;
    config.detector_model_path = options.detector_model;
    std::array<std::string, 8> detector_state_models{};
    if (options.detector_state_model_dir != nullptr) {
        for (uint8_t mask = 0u; mask < 8u; ++mask) {
            detector_state_models[mask] =
                std::string(options.detector_state_model_dir) +
                "/state_" + std::to_string(mask) + ".fkmodel";
            config.detector_state_model_paths[mask] =
                detector_state_models[mask].c_str();
        }
    }
    config.action_schema_sha256 = options.action_schema;
    config.detector_schema_sha256 = options.detector_schema;
    config.transition_value_model_path = options.transition_value_model;
    config.transition_value_schema_sha256 =
        options.transition_value_schema_sha;
    config.transition_value_model_sha256 = options.transition_value_model_sha;
    if (options.value_model_v3_artifact != nullptr) {
        config.value_model_v3.artifact_path =
            options.value_model_v3_artifact;
        config.value_model_v3.artifact_sha256 =
            options.value_model_v3_artifact_sha;
        config.value_model_v3.training_receipt_sha256 =
            options.value_model_v3_training_receipt_sha;
        config.value_model_v3.online_context_schema_sha256 =
            options.value_model_v3_schema_sha;
        config.value_model_v3.requested_action_domain_sha256 =
            options.value_model_v3_action_domain_sha;
        config.value_model_v3.online_deadline_contract_sha256 =
            options.value_model_v3_deadline_contract_sha;
        config.value_model_v3.expected_role = options.value_model_v3_role;
    }
    if (options.aggregation_mode != nullptr) {
        config.frozen_causal_aggregation.mode =
            FK_NO_NIC_EVENT_AGGREGATION_FROZEN_CPP_CAUSAL;
        config.frozen_causal_aggregation.threshold =
            options.aggregation_threshold;
        config.frozen_causal_aggregation.threshold_profile =
            options.aggregation_threshold_profile;
        config.frozen_causal_aggregation.aggregation_contract_sha256 =
            options.aggregation_contract_sha;
        config.frozen_causal_aggregation.development_oof_receipt_sha256 =
            options.development_oof_receipt_sha;
        config.frozen_causal_aggregation
            .causal_event_calibrator_artifact_path =
            options.causal_event_calibrator_artifact;
        config.frozen_causal_aggregation
            .causal_event_calibrator_artifact_sha256 =
            options.causal_event_calibrator_artifact_sha;
        config.frozen_causal_aggregation
            .causal_event_calibrator_source_npz_sha256 =
            options.causal_event_calibrator_source_npz_sha;
        config.frozen_causal_aggregation
            .causal_event_feature_contract_sha256 =
            options.causal_event_calibrator_feature_contract_sha;
        config.frozen_causal_aggregation
            .causal_event_real_prefix_receipt_sha256 =
            options.causal_event_calibrator_real_prefix_receipt_sha;
    }
    if (options.event_student_artifact != nullptr) {
        config.event_student_artifact_path =
            options.event_student_artifact;
        config.event_student_load_config.expected_artifact_sha256 =
            options.event_student_artifact_sha;
        config.event_student_load_config.expected_feature_schema_sha256 =
            options.event_student_feature_schema_sha;
        config.event_student_load_config.expected_source_state_sha256 =
            options.event_student_source_state_sha;
        config.event_student_load_config.expected_hidden =
            options.event_student_hidden;
        config.event_student_load_config.expected_identity_embedding =
            options.event_student_identity_embedding;
    }
    if (options.monitored_cidr != nullptr) {
        fk_actor_session_config_init(&config.actor_session);
        if (!fk_actor_session_config_add_cidr_text(
                &config.actor_session, options.monitored_cidr)) {
            set_error(error, sizeof(error), "invalid monitored CIDR");
            (void)write_failure_json(
                options, invocation, "actor_session_config", error);
            return 2;
        }
    }
    const bool fixed_compact_monitor_requested =
        options.compact_monitored_ipv4_pool != nullptr;
    const bool map_compact_monitor_requested =
        actor_namespace_monitor_map.requested;
    bool compact_monitor_configured = true;
    if (fixed_compact_monitor_requested) {
        compact_monitor_configured =
            fk_actor_session_config_set_compact_ipv4_monitor_text(
                &config.actor_session,
                options.compact_monitored_ipv4_pool,
                options.compact_monitored_ipv4_slots_per_namespace,
                options.compact_monitored_ipv4_namespace_count,
                options.compact_monitored_ipv4_identity_index);
    } else if (map_compact_monitor_requested) {
        compact_monitor_configured =
            actor_namespace_monitor_map.loaded &&
            actor_namespace_monitor_map.indices != nullptr &&
            fk_actor_session_config_set_compact_ipv4_monitor_map(
                &config.actor_session,
                actor_namespace_monitor_map.metadata.pool_base,
                actor_namespace_monitor_map.metadata.pool_prefix_length,
                actor_namespace_monitor_map.metadata.slots_per_namespace,
                actor_namespace_monitor_map.metadata.namespace_count,
                actor_namespace_monitor_map.indices.get(),
                actor_namespace_monitor_map.metadata.namespace_count);
        actor_namespace_monitor_map.actor_session_configured =
            compact_monitor_configured &&
            fk_actor_session_config_valid(&config.actor_session);
        compact_monitor_configured =
            actor_namespace_monitor_map.actor_session_configured;
    }
    if (!compact_monitor_configured) {
        set_error(
            error, sizeof(error),
            "invalid compact monitored IPv4 identity contract");
        (void)write_failure_json(
            options, invocation, "actor_session_config", error);
        return 2;
    }
    if (options.expected_flow_capacity_rollovers_seen) {
        config.enforce_flow_rollover_contract = 1u;
        config.expected_flow_capacity_rollovers =
            options.expected_flow_capacity_rollovers;
    }
    /* A formal finite replay must not silently lose event evidence because
     * the detector service inherited the 4K compact-test default.  Use the
     * structural one-event-per-retained-flow upper bound, common to every
     * retention treatment.  This preallocated service memory is measured in
     * the result but is outside the controlled FlowKeep state budget. */
    config.actor_session.maximum_events = FK_ACTOR_SESSION_MAX_EVENTS;
    config.actor_session.maximum_total_flows =
        options.actor_maximum_total_flows;
    config.preserve_actor_session_capacities = 1u;
    config.burst_context = &source;
    config.burst = BoundedPcapSource::burst_callback;
    config.clock_context = &source;
    config.clock = BoundedPcapSource::clock_callback;
    config.decode_context = &source;
    config.decode = BoundedPcapSource::decode_callback;
    config.reclaim_context = &source;
    config.reclaim = BoundedPcapSource::reclaim_callback;
    config.monotonic_clock_context = &source;
    config.monotonic_now_ns = BoundedPcapSource::monotonic_now_callback;
    config.io_stats_context = &source;
    config.io_stats = BoundedPcapSource::stats_callback;
    if (options.decision_trace != nullptr) {
        if (!trace_writer.open_exclusive(options.decision_trace)) {
            std::fputs("cannot create decision trace output exclusively\n", stderr);
            return 2;
        }
        if (options.decision_trace_features != nullptr) {
            trace_features_writer.reset(
                new (std::nothrow)
                    fk_no_nic_detector_request_trace_csv_writer());
            if (trace_features_writer == nullptr ||
                !trace_features_writer->open_exclusive(
                    options.decision_trace_features)) {
                std::fputs(
                    "cannot create decision trace features output exclusively\n",
                    stderr);
                return 2;
            }
        }
        config.decision_trace_context = &trace_writer;
        config.decision_trace_sink =
            fk_no_nic_decision_trace_csv_writer::sink;
        if (options.decision_trace_features != nullptr) {
            config.decision_trace_features_context =
                trace_features_writer.get();
            config.decision_trace_features_sink =
                fk_no_nic_detector_request_trace_csv_writer::sink;
        }
    }
    config.external_io = 1u;

    fk_no_nic_full_composition_result result{};
    const uint64_t wall_begin_ns = steady_monotonic_ns();
    const uint64_t cpu_begin_ns = process_cpu_ns();
    const uint64_t tsc_begin = rte_rdtsc_precise();
    const bool run_ok = fk_no_nic_full_composition_run(
        &config, &result, error, sizeof(error));
    const uint64_t tsc_end = rte_rdtsc_precise();
    const uint64_t cpu_end_ns = process_cpu_ns();
    const uint64_t wall_end_ns = steady_monotonic_ns();
    WholePipelineTiming whole_pipeline_timing{};
    whole_pipeline_timing.wall_ns = wall_end_ns >= wall_begin_ns
        ? wall_end_ns - wall_begin_ns : 0u;
    whole_pipeline_timing.process_cpu_ns = cpu_end_ns >= cpu_begin_ns
        ? cpu_end_ns - cpu_begin_ns : 0u;
    whole_pipeline_timing.tsc_cycles = tsc_end >= tsc_begin
        ? tsc_end - tsc_begin : 0u;
    whole_pipeline_timing.tsc_hz = rte_get_tsc_hz();
    whole_pipeline_timing.complete =
        whole_pipeline_timing.wall_ns != 0u &&
        whole_pipeline_timing.process_cpu_ns != 0u &&
        whole_pipeline_timing.tsc_cycles != 0u;
    if (!run_ok) {
        std::fprintf(stderr, "%s\n", error);
        (void)source.recover_owned_slots_after_pipeline_failure();
        (void)trace_writer.finish();
        if (trace_features_writer != nullptr)
            (void)trace_features_writer->finish();
        fk_no_nic_full_composition_io_stats_v1 io{};
        (void)BoundedPcapSource::stats_callback(&source, &io);
        (void)write_pipeline_failure_json(
            options, invocation, scan, io, error);
        return 1;
    }
    DecisionTraceFeaturesReceipt trace_features{};
    trace_features.enabled = options.decision_trace_features != nullptr;
    const bool main_trace_finished = trace_writer.finish();
    const bool feature_trace_finished = trace_features_writer == nullptr ||
        trace_features_writer->finish();
    const bool trace_finished =
        main_trace_finished && feature_trace_finished;
    trace_features.rows = trace_features_writer == nullptr
        ? 0u : trace_features_writer->records();
    trace_features.row_conservation_valid = !trace_features.enabled ||
        trace_features.rows == result.observability.checkpoint_records;
    if (trace_features.enabled && trace_finished) {
        trace_features.sha256_valid = sha256_file(
            options.decision_trace_features, trace_features.sha256);
    }
    if (!trace_finished ||
        (options.decision_trace != nullptr &&
         trace_writer.records() !=
             result.observability.decision_records +
                 result.observability.evidence_transition_records) ||
        !trace_features.row_conservation_valid ||
        (trace_features.enabled && !trace_features.sha256_valid)) {
        std::fprintf(stderr, "decision trace finalization/conservation failed\n");
        return 1;
    }
    RetentionDetectorCompositionReceipt composition{};
    composition.requested =
        options.retention_detector_coupling != nullptr;
    if (composition.requested) {
        composition.checkpoint_records = trace_writer.checkpoint_records();
        composition.fifo_order_violations =
            trace_writer.checkpoint_fifo_order_violations();
        composition.maximum_flow_detector_latency_ns =
            trace_writer.maximum_flow_detector_latency_ns();
        composition.maximum_flow_detector_schedule_latency_ns =
            trace_writer.maximum_flow_detector_schedule_latency_ns();
        composition.detector_deadline_ns =
            static_cast<uint64_t>(options.detector_deadline_us) * 1000u;
        composition.fifo_verified =
            composition.checkpoint_records != 0u &&
            composition.checkpoint_records ==
                result.observability.checkpoint_records &&
            composition.fifo_order_violations == 0u &&
            result.global_order_conserved != 0u;
        /* batch_fifo is an in-thread, synchronous causal execution contract.
         * It has no native queue/deadline guard to verify or claim. */
        composition.deadline_verified =
            !options.detector_deadline_seen &&
            composition.detector_deadline_ns == 0u;
        composition.conservation_verified =
            result.source_exhausted != 0u && result.source_failed == 0u &&
            result.normal_complete != 0u &&
            result.global_order_conserved != 0u &&
            result.mbuf_ownership_conserved != 0u &&
            result.packet_disposition_conserved != 0u;
        composition.complete = composition.fifo_verified &&
            composition.deadline_verified &&
            composition.conservation_verified;
        if (!composition.complete) {
            std::snprintf(
                error, sizeof(error),
                "decoupled retention/detector contract failed closed");
            std::fprintf(stderr, "%s\n", error);
            fk_no_nic_full_composition_io_stats_v1 io{};
            (void)BoundedPcapSource::stats_callback(&source, &io);
            (void)write_pipeline_failure_json(
                options, invocation, scan, io, error);
            return 1;
        }
    }
    if (!fk_no_nic_service_memory_receipt_verify_v1(
            &result.service_memory)) {
        std::snprintf(
            error, sizeof(error),
            "service-memory result receipt failed verification");
        std::fprintf(stderr, "%s\n", error);
        fk_no_nic_full_composition_io_stats_v1 io{};
        (void)BoundedPcapSource::stats_callback(&source, &io);
        (void)write_pipeline_failure_json(
            options, invocation, scan, io, error);
        return 1;
    }
    const auto &value_v3 = result.value_model_v3;
    const bool value_v3_requested =
        options.value_model_v3_artifact != nullptr;
    const bool value_v3_supported_format =
        value_v3.format_version == 1u || value_v3.format_version == 2u;
    const bool value_v3_threshold_metadata_valid =
        (value_v3.training_target_uses_detector_threshold == 0u &&
         value_v3.detector_threshold_bits == 0u &&
         std::strcmp(
             value_v3.detector_threshold_binding_sha256, "none") == 0 &&
         std::strcmp(
             value_v3.detector_threshold_selection_receipt_sha256,
             "none") == 0 &&
         std::strcmp(
             value_v3.detector_operating_point_receipt_sha256,
             "none") == 0) ||
        (value_v3.training_target_uses_detector_threshold == 1u &&
         value_v3.detector_threshold_bits != 0u &&
         std::strlen(
             value_v3.detector_threshold_binding_sha256) == 64u &&
         std::strlen(
             value_v3.detector_threshold_selection_receipt_sha256) == 64u &&
         std::strlen(
             value_v3.detector_operating_point_receipt_sha256) == 64u);
    /* Legacy FKVM3/1 has no threshold/formal provenance fields.  It is
     * accepted here only as a development/diagnostic no-NIC receipt and must
     * retain the loader's threshold-independent defaults.  This runner never
     * emits a formal detection result or accuracy claim for either version. */
    const bool value_v3_legacy_v1_defaults_valid =
        value_v3.format_version != 1u ||
        (value_v3.training_target_uses_detector_threshold == 0u &&
         value_v3.formal_event_student_counterfactual_semantics_aligned == 0u &&
         value_v3.detector_threshold_bits == 0u &&
         std::strcmp(
             value_v3.detector_threshold_binding_sha256, "none") == 0 &&
         std::strcmp(
             value_v3.detector_threshold_selection_receipt_sha256,
             "none") == 0 &&
         std::strcmp(
             value_v3.detector_operating_point_receipt_sha256,
             "none") == 0);
    const bool value_v3_contract_valid = value_v3_requested
        ? value_v3.abi_version ==
                FK_NO_NIC_VALUE_MODEL_V3_RECEIPT_ABI_VERSION &&
            value_v3_supported_format &&
            value_v3_legacy_v1_defaults_valid &&
            value_v3.role == options.value_model_v3_role &&
            value_v3.context_features ==
                FK_VALUE_MODEL_V3_CONTEXT_FEATURES &&
            value_v3.query_features == FK_VALUE_MODEL_V3_QUERY_FEATURES &&
            value_v3.model_features == FK_VALUE_MODEL_V3_MODEL_FEATURES &&
            value_v3.learned_actions == FK_VALUE_MODEL_V3_ACTIONS &&
            value_v3.outputs == FK_VALUE_MODEL_V3_OUTPUTS &&
            std::isfinite(value_v3.conditional_equivalence_tolerance) &&
            value_v3.conditional_equivalence_tolerance >= 0.0f &&
            value_v3.conditional_equivalence_tolerance < 1.0f &&
            (value_v3.family == FK_VALUE_MODEL_V3_HYBRID_GATE_FOREST ||
             value_v3.conditional_equivalence_tolerance == 0.0f) &&
            value_v3.training_target_uses_detector_threshold <= 1u &&
            value_v3.formal_event_student_counterfactual_semantics_aligned <= 1u &&
            value_v3_threshold_metadata_valid &&
            value_v3.artifact_file_bytes != 0u &&
            value_v3.model_reserved_bytes != 0u &&
            value_v3.frozen_context_reserved_bytes == 0u &&
            value_v3.load_attempts == 1u &&
            value_v3.load_successes == 1u &&
            value_v3.load_failures == 0u &&
            value_v3.contexts_built != 0u &&
            value_v3.context_failures == 0u &&
            value_v3.inference_calls == value_v3.contexts_built &&
            value_v3.inference_failures == 0u &&
            value_v3.core_zero_violations == 0u &&
            value_v3.protocol_domain_violations == 0u &&
            value_v3.enabled == 1u && value_v3.loaded == 1u &&
            value_v3.used == 1u && value_v3.complete == 1u &&
            std::strcmp(
                value_v3.artifact_sha256,
                options.value_model_v3_artifact_sha) == 0 &&
            std::strcmp(
                value_v3.training_receipt_sha256,
                options.value_model_v3_training_receipt_sha) == 0 &&
            std::strcmp(
                value_v3.online_context_schema_sha256,
                options.value_model_v3_schema_sha) == 0 &&
            std::strcmp(
                value_v3.requested_action_domain_sha256,
                options.value_model_v3_action_domain_sha) == 0 &&
            std::strcmp(
                value_v3.online_deadline_contract_sha256,
                options.value_model_v3_deadline_contract_sha) == 0
        : value_v3.enabled == 0u && value_v3.loaded == 0u &&
            value_v3.used == 0u && value_v3.complete == 0u &&
            value_v3.load_attempts == 0u &&
            value_v3.inference_calls == 0u;
    const bool no_selector_contract_valid = action_model != nullptr ||
        (result.value_model_calls == 0u &&
         result.value_model_failures == 0u &&
         result.value_inference_failures == 0u &&
         result.value_transition_failures == 0u);
    const bool transition_value_contract_valid =
        options.transition_value_model != nullptr
        ? result.transition_value_calls != 0u &&
            result.transition_value_failures == 0u &&
            result.transition_value_inference_ns != 0u
        : result.transition_value_calls == 0u &&
            result.transition_value_failures == 0u &&
            result.transition_value_inference_ns == 0u;
    const bool decoupled_policy_model_valid = !composition.requested ||
        (options.retention_policy ==
             FK_COMPACT_POLICY_LEARNED_DETECTION_LOSS_PER_BYTE &&
         value_v3_requested && value_v3.format_version == 2u &&
         value_v3.role == FK_VALUE_MODEL_V3_DETECTION_LOSS) ||
        (options.retention_policy == FK_COMPACT_POLICY_FLOWKEEP &&
         value_v3_requested && value_v3_supported_format &&
         value_v3.role == FK_VALUE_MODEL_V3_FLOWKEEP) ||
        (options.retention_policy != FK_COMPACT_POLICY_FLOWKEEP &&
         options.retention_policy !=
             FK_COMPACT_POLICY_LEARNED_DETECTION_LOSS_PER_BYTE &&
         !value_v3_requested && options.action_model == nullptr);
    if (!value_v3_contract_valid || !no_selector_contract_valid ||
        !transition_value_contract_valid ||
        !decoupled_policy_model_valid) {
        std::snprintf(
            error, sizeof(error),
            "V3 action-model result contract failed closed");
        std::fprintf(stderr, "%s\n", error);
        fk_no_nic_full_composition_io_stats_v1 io{};
        (void)BoundedPcapSource::stats_callback(&source, &io);
        (void)write_pipeline_failure_json(
            options, invocation, scan, io, error);
        return 1;
    }
    const auto &frozen = result.frozen_causal_aggregation;
    const bool causal_calibrator_requested =
        options.causal_event_calibrator_artifact != nullptr;
    const bool frozen_common_contract_valid =
        frozen.abi_version ==
            FK_NO_NIC_FROZEN_CAUSAL_AGGREGATION_RECEIPT_ABI_VERSION &&
        frozen.enabled == 1u && frozen.complete == 1u &&
        frozen.deterministic_smoke_model == 0u &&
        result.trigger_receipt.deterministic_smoke_model == 0u &&
        std::strcmp(
            frozen.aggregation_rule, options.aggregation_rule) == 0 &&
        std::strcmp(
            frozen.threshold_profile,
            options.aggregation_threshold_profile) == 0 &&
        frozen.threshold == options.aggregation_threshold &&
        std::strcmp(
            frozen.aggregation_contract_sha256,
            options.aggregation_contract_sha) == 0 &&
        std::strcmp(
            frozen.development_oof_receipt_sha256,
            options.development_oof_receipt_sha) == 0;
    const bool frozen_base_max_contract_valid =
        !causal_calibrator_requested && frozen.calibrator_enabled == 0u &&
        frozen.model_loaded == 0u && frozen.model_used == 0u &&
        frozen.model_load_successes == 0u &&
        frozen.model_load_failures == 0u && frozen.inference_calls == 0u &&
        frozen.inference_failures == 0u &&
        frozen.total_feature_updates == 0u && frozen.periodic_updates == 0u &&
        frozen.requested_effective_mask_divergences == 0u &&
        frozen.protocol_action_domain_checks == 0u &&
        frozen.protocol_action_domain_violations == 0u &&
        frozen.physical_feature_mask_checks == 0u &&
        frozen.physical_feature_mask_mismatches == 0u &&
        frozen.requested_mask_or == 0u &&
        frozen.physical_final_mask_or == 0u &&
        frozen.causal_event_calibrator_artifact_sha256[0] == '\0' &&
        frozen.causal_event_calibrator_source_npz_sha256[0] == '\0' &&
        frozen.causal_event_feature_contract_sha256[0] == '\0' &&
        frozen.causal_event_real_prefix_receipt_sha256[0] == '\0';
    uint64_t feature_update_partition = frozen.checkpoint_updates;
    const bool feature_update_conserved =
        checked_add(feature_update_partition, frozen.periodic_updates) &&
        feature_update_partition == frozen.total_feature_updates;
    uint64_t periodic_tick_partition = frozen.periodic_updates;
    const bool periodic_schedule_conserved =
        checked_add(periodic_tick_partition, frozen.empty_periodic_ticks) &&
        checked_add(
            periodic_tick_partition,
            frozen.same_timestamp_periodic_coalesces) &&
        periodic_tick_partition == frozen.scheduled_periodic_ticks;
    const bool frozen_calibrator_contract_valid =
        causal_calibrator_requested && frozen.calibrator_enabled == 1u &&
        std::strcmp(
            frozen.aggregation_rule,
            "causal_event_calibrator_max") == 0 &&
        frozen.model_loaded == 1u && frozen.model_used == 1u &&
        frozen.model_load_successes == 1u &&
        frozen.model_load_failures == 0u && frozen.inference_calls > 0u &&
        frozen.inference_failures == 0u &&
        frozen.inference_calls == frozen.total_feature_updates &&
        feature_update_conserved && periodic_schedule_conserved &&
        frozen.feature_state_resets ==
            frozen.initialized_event_generations &&
        frozen.causal_records_presented >= frozen.inference_calls &&
        frozen.protocol_action_domain_checks == frozen.checkpoint_updates &&
        frozen.protocol_action_domain_violations == 0u &&
        frozen.physical_feature_mask_checks == frozen.checkpoint_updates &&
        frozen.physical_feature_mask_mismatches == 0u &&
        frozen.requested_mask_or <= FK_COMPONENT_FULL &&
        frozen.physical_final_mask_or <= FK_COMPONENT_FULL &&
        std::strcmp(
            frozen.causal_event_calibrator_artifact_sha256,
            options.causal_event_calibrator_artifact_sha) == 0 &&
        std::strcmp(
            frozen.causal_event_calibrator_source_npz_sha256,
            options.causal_event_calibrator_source_npz_sha) == 0 &&
        std::strcmp(
            frozen.causal_event_feature_contract_sha256,
            options.causal_event_calibrator_feature_contract_sha) == 0 &&
        std::strcmp(
            frozen.causal_event_real_prefix_receipt_sha256,
            options.causal_event_calibrator_real_prefix_receipt_sha) == 0;
    const bool frozen_contract_valid = options.aggregation_mode == nullptr ||
        (frozen_common_contract_valid &&
         ((causal_calibrator_requested &&
           frozen_calibrator_contract_valid) ||
          (!causal_calibrator_requested &&
           std::strcmp(frozen.aggregation_rule, "max") == 0 &&
           frozen_base_max_contract_valid)));
    const bool event_student_contract_valid =
        options.event_student_artifact == nullptr ||
        (result.trigger_receipt.deterministic_smoke_model == 0u &&
         result.frozen_causal_aggregation.enabled == 0u);
    const auto &capacity = result.detection_service_capacity;
    const bool quic_identity_capacity_valid =
        result.maximum_quic_connections_configured ==
            options.maximum_quic_connections &&
        result.quic_cid_connection_capacity ==
            options.maximum_quic_connections &&
        result.quic_path_connection_capacity ==
            options.maximum_quic_connections &&
        result.owner_binding_connection_capacity ==
            options.maximum_quic_connections;
    const bool formal_audit_valid =
        result.router_parser_reason_conserved != 0u &&
        result.packet_disposition_conserved != 0u &&
        result.quic_identity.abi_version ==
            FK_NO_NIC_QUIC_IDENTITY_OBSERVABILITY_ABI_VERSION &&
        result.quic_identity.capacity_conserved != 0u &&
        result.quic_identity.router_quic_disposition_conserved != 0u &&
        result.quic_identity.terminal_active_zero != 0u &&
        result.quic_identity.finite_epoch_drain_requested == 1u &&
        result.quic_identity.finite_epoch_drain_after_input_eof == 1u &&
        result.quic_identity.finite_epoch_drain_complete == 1u &&
        result.quic_identity
                .finite_epoch_drain_before_publisher_terminal == 1u &&
        result.quic_identity.finite_epoch_drain_reason ==
            FK_QUIC_CID_FINITE_EPOCH_DRAIN_IDLE_TIMEOUT_AFTER_EOF &&
        result.quic_identity.finite_epoch_drain_timestamp_ns ==
            config.terminal_semantic_timestamp_ns &&
        result.quic_identity.finite_epoch_active_after == 0u &&
        result.quic_identity.finite_epoch_connections_drained ==
            result.quic_identity.finite_epoch_active_before &&
        result.quic_identity.finite_epoch_path_drain_complete == 1u &&
        result.quic_identity.finite_epoch_path_drain_reason ==
            FK_QUIC_PRESENTATION_PATH_FINITE_EPOCH_DRAIN_IDLE_TIMEOUT_AFTER_EOF &&
        result.quic_identity.finite_epoch_path_active_connections_after ==
            0u &&
        result.quic_identity.finite_epoch_paths_after == 0u &&
        result.quic_identity.finite_epoch_paths_drained ==
            result.quic_identity.finite_epoch_paths_before &&
        result.quic_identity.publisher_accounting_conserved == 1u &&
        result.quic_identity.publisher_formal_complete == 1u &&
        result.quic_identity.dispatch_observations_sealed == 1u &&
        result.quic_identity.publisher_marked_controls_at_end == 0u &&
        result.quic_identity.dispatch_retire_control_depth_at_end == 0u &&
        result.quic_identity.cid_retired_pending_owner_ack_at_end == 0u &&
        result.quic_identity.cid_binding_credits_in_use_at_end == 0u &&
        result.quic_identity.retirement_delivery_conserved == 1u &&
        result.quic_identity.owner_ack_complete == 1u &&
        result.quic_identity.retirement_ack_failures == 0u;
    const bool detection_service_capacity_valid =
        capacity.abi_version ==
            FK_NO_NIC_DETECTION_SERVICE_CAPACITY_RECEIPT_ABI_VERSION &&
        capacity.actor_maximum_events == FK_ACTOR_SESSION_MAX_EVENTS &&
        capacity.actor_maximum_total_flows ==
            options.actor_maximum_total_flows &&
        capacity.actor_maximum_flows_per_event ==
            FK_ACTOR_SESSION_MAX_FLOWS_PER_EVENT &&
        capacity.actor_event_capacity_evictions == 0u &&
        capacity.actor_total_flow_capacity_evictions == 0u &&
        capacity.expected_flow_capacity_rollovers ==
            options.expected_flow_capacity_rollovers &&
        capacity.flow_rollover_contract_enforced ==
            (options.expected_flow_capacity_rollovers_seen ? 1u : 0u) &&
        capacity.flow_rollover_contract_valid != 0u &&
        capacity.window_live_slot_reuse_conflicts == 0u &&
        capacity.capacity_clean != 0u;
    if (!frozen_contract_valid || !event_student_contract_valid ||
        !quic_identity_capacity_valid ||
        !formal_audit_valid ||
        !detection_service_capacity_valid ||
        result.runtime_optional_timer_boundary_stalls != 0u ||
        result.state_byte_seconds_complete == 0u ||
        result.evidence_transitions.complete == 0u) {
        std::snprintf(
            error, sizeof(error),
            "aggregation/state-residency result contract failed closed");
        std::fprintf(stderr, "%s\n", error);
        fk_no_nic_full_composition_io_stats_v1 io{};
        (void)BoundedPcapSource::stats_callback(&source, &io);
        (void)write_pipeline_failure_json(
            options, invocation, scan, io, error);
        return 1;
    }
    if (!write_success_json(
            options, invocation, scan, result,
            actor_namespace_monitor_map, trace_features, composition,
            whole_pipeline_timing,
            source_record_intervention_receipt)) {
        std::fprintf(stderr, "failed to write JSON output\n");
        return 1;
    }
    return 0;
}

const char *argument_value(int argc, char **argv, const char *name) {
    if (argv == nullptr || name == nullptr)
        return nullptr;
    for (int index = 1; index + 1 < argc; ++index) {
        if (argv[index] != nullptr && std::strcmp(argv[index], name) == 0)
            return argv[index + 1];
    }
    return nullptr;
}

int guarded_runner_entry(
        int argc,
        char **argv,
        const Invocation &invocation) {
    try {
        return runner_entry_impl(argc, argv, invocation);
    } catch (const std::bad_alloc &) {
        Options failure{};
        failure.output = argument_value(argc, argv, "--output");
        failure.pcap = argument_value(argc, argv, "--pcap");
        std::fputs("runner allocation failed\n", stderr);
        (void)write_failure_json(
            failure,
            invocation,
            "runner_allocation",
            "runner allocation failed");
        return 1;
    } catch (...) {
        Options failure{};
        failure.output = argument_value(argc, argv, "--output");
        failure.pcap = argument_value(argc, argv, "--pcap");
        std::fputs("runner internal exception\n", stderr);
        (void)write_failure_json(
            failure,
            invocation,
            "runner_exception",
            "runner internal exception");
        return 1;
    }
}

}  // namespace

extern "C" int fk_no_nic_pcap_runner_entry(int argc, char **argv) {
    return guarded_runner_entry(argc, argv, kStandaloneInvocation);
}

extern "C" int fk_no_nic_pcap_runner_entry_after_eal(
        int argc,
        char **argv) {
    return guarded_runner_entry(argc, argv, kProductionEalInvocation);
}
