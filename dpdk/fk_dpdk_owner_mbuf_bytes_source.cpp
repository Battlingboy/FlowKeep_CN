#include "fk_dpdk_owner_mbuf_bytes_source.h"

#include "fk_owner_runtime_adapter.h"

#include <rte_mbuf.h>

#include <atomic>
#include <cstddef>
#include <cstring>
#include <limits>
#include <new>

namespace {

struct SourceImpl {
    fk_dpdk_owner_mbuf_bytes_source_config config{};
    std::atomic<uint64_t> owner_thread_token{0u};
    std::atomic<uint64_t> owner_claim_attempts{0u};
    std::atomic<uint64_t> owner_claim_successes{0u};
    std::atomic<uint64_t> owner_claim_rejections{0u};
    std::atomic<uint64_t> owner_thread_rejections{0u};

    fk_dpdk_owner_mbuf_bytes_source_stats counters{};
    uintptr_t active_packet_handle = 0u;
    const uint8_t *active_data = nullptr;
    void *active_buf_addr = nullptr;
    uint32_t active_captured_length = 0u;
    uint32_t active_wire_length = 0u;
    uint32_t active_pkt_len = 0u;
    uint64_t active_ol_flags = 0u;
    uint16_t active_data_len = 0u;
    uint16_t active_data_off = 0u;
    uint16_t active_buf_len = 0u;
    uint16_t active_refcnt = 0u;
    uint8_t initialized = 0u;
    uint8_t active_claim = 0u;
    uint8_t reserved[6]{};
};

static_assert(alignof(SourceImpl) <= alignof(max_align_t),
    "mbuf byte source must fit max_align_t placement storage");
static_assert(sizeof(fk_dpdk_owner_mbuf_bytes_source_config) == 16u,
    "mbuf byte source config ABI changed");

std::atomic<uint64_t> g_next_owner_thread_token{1u};

SourceImpl *implementation(fk_dpdk_owner_mbuf_bytes_source *source) {
    return reinterpret_cast<SourceImpl *>(source);
}

const SourceImpl *implementation(
        const fk_dpdk_owner_mbuf_bytes_source *source) {
    return reinterpret_cast<const SourceImpl *>(source);
}

bool reserved_zero(const fk_dpdk_owner_mbuf_bytes_source_config &config) {
    for (const uint8_t value : config.reserved) {
        if (value != 0u)
            return false;
    }
    return true;
}

bool config_valid(const fk_dpdk_owner_mbuf_bytes_source_config *config) {
    return config != nullptr &&
        config->abi_version == FK_DPDK_OWNER_MBUF_BYTES_SOURCE_ABI_VERSION &&
        config->owner_count != 0u &&
        config->fixed_owner < config->owner_count &&
        reserved_zero(*config);
}

uint64_t allocate_owner_thread_token() {
    uint64_t candidate =
        g_next_owner_thread_token.load(std::memory_order_relaxed);
    while (candidate != 0u) {
        const uint64_t successor =
            candidate == std::numeric_limits<uint64_t>::max()
                ? 0u : candidate + 1u;
        if (g_next_owner_thread_token.compare_exchange_weak(
                candidate,
                successor,
                std::memory_order_relaxed,
                std::memory_order_relaxed)) {
            return candidate;
        }
    }
    return 0u;
}

uint64_t current_thread_token() {
    static thread_local const uint64_t token = allocate_owner_thread_token();
    return token;
}

bool owner_thread(SourceImpl &source) {
    const uint64_t current = current_thread_token();
    const uint64_t claimed =
        source.owner_thread_token.load(std::memory_order_acquire);
    if (current != 0u && claimed != 0u && current == claimed)
        return true;
    source.owner_thread_rejections.fetch_add(1u, std::memory_order_relaxed);
    return false;
}

bool descriptor_shape_valid(
        const SourceImpl &source,
        const fk_owner_packet &packet) {
    return packet.packet_handle != 0u &&
        packet.owner_worker == source.config.fixed_owner &&
        packet.captured_length != 0u && packet.wire_length != 0u &&
        packet.captured_length == packet.wire_length;
}

bool mbuf_shape_valid(
        const rte_mbuf &mbuf,
        uint32_t captured_length,
        uint32_t wire_length,
        const uint8_t **data) {
    if (data != nullptr)
        *data = nullptr;
    if (captured_length == 0u || captured_length != wire_length ||
        mbuf.buf_addr == nullptr || mbuf.nb_segs != 1u ||
        mbuf.next != nullptr || mbuf.pkt_len == 0u ||
        mbuf.data_len == 0u || mbuf.pkt_len != mbuf.data_len ||
        mbuf.pkt_len != captured_length ||
        !RTE_MBUF_DIRECT(&mbuf) || rte_mbuf_refcnt_read(&mbuf) != 1u ||
        mbuf.data_off > mbuf.buf_len ||
        mbuf.data_len >
            static_cast<uint32_t>(mbuf.buf_len - mbuf.data_off)) {
        return false;
    }
    const auto *bytes = rte_pktmbuf_mtod(&mbuf, const uint8_t *);
    if (bytes == nullptr)
        return false;
    if (data != nullptr)
        *data = bytes;
    return true;
}

bool active_mbuf_unchanged(const SourceImpl &source, const rte_mbuf &mbuf) {
    const uint8_t *data = nullptr;
    return mbuf_shape_valid(
            mbuf,
            source.active_captured_length,
            source.active_wire_length,
            &data) &&
        data == source.active_data &&
        mbuf.buf_addr == source.active_buf_addr &&
        mbuf.pkt_len == source.active_pkt_len &&
        mbuf.ol_flags == source.active_ol_flags &&
        mbuf.data_len == source.active_data_len &&
        mbuf.data_off == source.active_data_off &&
        mbuf.buf_len == source.active_buf_len &&
        rte_mbuf_refcnt_read(&mbuf) == source.active_refcnt;
}

void clear_active(SourceImpl &source) {
    source.active_packet_handle = 0u;
    source.active_data = nullptr;
    source.active_buf_addr = nullptr;
    source.active_captured_length = 0u;
    source.active_wire_length = 0u;
    source.active_pkt_len = 0u;
    source.active_ol_flags = 0u;
    source.active_data_len = 0u;
    source.active_data_off = 0u;
    source.active_buf_len = 0u;
    source.active_refcnt = 0u;
    source.active_claim = 0u;
}

bool resolve_exact_mbuf(
        void *context,
        uintptr_t packet_handle,
        const uint8_t **frame,
        size_t *captured_length,
        uint32_t *wire_length) {
    if (frame != nullptr)
        *frame = nullptr;
    if (captured_length != nullptr)
        *captured_length = 0u;
    if (wire_length != nullptr)
        *wire_length = 0u;
    if (context == nullptr || frame == nullptr ||
        captured_length == nullptr || wire_length == nullptr)
        return false;
    SourceImpl &source = *static_cast<SourceImpl *>(context);
    if (source.initialized == 0u || !owner_thread(source))
        return false;
    source.counters.resolver_calls++;
    if (source.active_claim == 0u) {
        source.counters.resolver_no_active_rejections++;
        return false;
    }
    if (packet_handle == 0u ||
        packet_handle != source.active_packet_handle) {
        source.counters.resolver_handle_mismatch_rejections++;
        return false;
    }
    const auto *mbuf = reinterpret_cast<const rte_mbuf *>(packet_handle);
    if (!active_mbuf_unchanged(source, *mbuf)) {
        source.counters.resolver_mbuf_mutation_rejections++;
        return false;
    }
    *frame = source.active_data;
    *captured_length = source.active_captured_length;
    *wire_length = source.active_wire_length;
    source.counters.resolver_successes++;
    return true;
}

bool sum_equals(uint64_t expected, uint64_t left, uint64_t right) {
    return left <= std::numeric_limits<uint64_t>::max() - right &&
        expected == left + right;
}

bool sum_equals(
        uint64_t expected,
        uint64_t first,
        uint64_t second,
        uint64_t third,
        uint64_t fourth) {
    uint64_t sum = 0u;
    const uint64_t values[]{first, second, third, fourth};
    for (const uint64_t value : values) {
        if (value > std::numeric_limits<uint64_t>::max() - sum)
            return false;
        sum += value;
    }
    return sum == expected;
}

bool accounting_conserved(const SourceImpl &source) {
    const fk_dpdk_owner_mbuf_bytes_source_stats &stats = source.counters;
    const uint64_t active = source.active_claim != 0u ? 1u : 0u;
    return source.initialized == 1u &&
        source.active_claim <= 1u &&
        sum_equals(
            source.owner_claim_attempts.load(std::memory_order_relaxed),
            source.owner_claim_successes.load(std::memory_order_relaxed),
            source.owner_claim_rejections.load(std::memory_order_relaxed)) &&
        source.owner_claim_successes.load(std::memory_order_relaxed) <= 1u &&
        sum_equals(stats.packet_claim_attempts,
            stats.packet_claim_successes,
            stats.double_claim_rejections,
            stats.descriptor_rejections,
            stats.mbuf_shape_rejections) &&
        sum_equals(stats.resolver_calls,
            stats.resolver_successes,
            stats.resolver_no_active_rejections,
            stats.resolver_handle_mismatch_rejections,
            stats.resolver_mbuf_mutation_rejections) &&
        sum_equals(stats.release_attempts,
            stats.release_successes,
            stats.release_no_active_rejections,
            stats.release_handle_mismatch_rejections,
            0u) &&
        sum_equals(stats.packet_claim_successes,
            stats.release_successes, active) &&
        ((active == 0u && source.active_packet_handle == 0u &&
          source.active_data == nullptr &&
          source.active_captured_length == 0u &&
          source.active_wire_length == 0u) ||
         (active == 1u && source.active_packet_handle != 0u &&
          source.active_data != nullptr &&
          source.active_captured_length != 0u &&
          source.active_captured_length == source.active_wire_length));
}

}  // namespace

extern "C" {

void fk_dpdk_owner_mbuf_bytes_source_default_config_init(
        fk_dpdk_owner_mbuf_bytes_source_config *config) {
    if (config == nullptr)
        return;
    *config = {};
    config->abi_version = FK_DPDK_OWNER_MBUF_BYTES_SOURCE_ABI_VERSION;
    config->fixed_owner = 0u;
    config->owner_count = 1u;
}

bool fk_dpdk_owner_mbuf_bytes_source_config_valid(
        const fk_dpdk_owner_mbuf_bytes_source_config *config) {
    return config_valid(config);
}

size_t fk_dpdk_owner_mbuf_bytes_source_storage_bytes(
        const fk_dpdk_owner_mbuf_bytes_source_config *config) {
    return config_valid(config) ? sizeof(SourceImpl) : 0u;
}

fk_dpdk_owner_mbuf_bytes_source *
fk_dpdk_owner_mbuf_bytes_source_initialize(
        void *storage,
        size_t storage_bytes,
        const fk_dpdk_owner_mbuf_bytes_source_config *config) {
    if (storage == nullptr || !config_valid(config) ||
        storage_bytes < sizeof(SourceImpl) ||
        reinterpret_cast<uintptr_t>(storage) % alignof(max_align_t) != 0u)
        return nullptr;
    auto *source = new (storage) SourceImpl{};
    source->config = *config;
    source->counters.abi_version =
        FK_DPDK_OWNER_MBUF_BYTES_SOURCE_ABI_VERSION;
    source->counters.fixed_owner = config->fixed_owner;
    source->counters.owner_count = config->owner_count;
    source->counters.initialized = 1u;
    source->initialized = 1u;
    return reinterpret_cast<fk_dpdk_owner_mbuf_bytes_source *>(source);
}

bool fk_dpdk_owner_mbuf_bytes_source_claim_owner(
        fk_dpdk_owner_mbuf_bytes_source *source_ptr) {
    if (source_ptr == nullptr)
        return false;
    SourceImpl &source = *implementation(source_ptr);
    if (source.initialized == 0u)
        return false;
    source.owner_claim_attempts.fetch_add(1u, std::memory_order_relaxed);
    const uint64_t token = current_thread_token();
    uint64_t expected = 0u;
    if (token != 0u && source.owner_thread_token.compare_exchange_strong(
            expected,
            token,
            std::memory_order_acq_rel,
            std::memory_order_acquire)) {
        source.owner_claim_successes.fetch_add(1u, std::memory_order_relaxed);
        source.counters.owner_claimed = 1u;
        return true;
    }
    source.owner_claim_rejections.fetch_add(1u, std::memory_order_relaxed);
    source.owner_thread_rejections.fetch_add(1u, std::memory_order_relaxed);
    return false;
}

bool fk_dpdk_owner_mbuf_bytes_source_get_adapter_source(
        fk_dpdk_owner_mbuf_bytes_source *source_ptr,
        fk_owner_packet_bytes_source *adapter_source) {
    if (adapter_source != nullptr)
        *adapter_source = {};
    if (source_ptr == nullptr || adapter_source == nullptr)
        return false;
    SourceImpl &source = *implementation(source_ptr);
    if (source.initialized == 0u)
        return false;
    adapter_source->abi_version = FK_OWNER_PACKET_BYTES_SOURCE_ABI_VERSION;
    adapter_source->exact_handle_binding = 1u;
    adapter_source->immutable_while_owned = 1u;
    adapter_source->contiguous_frame = 1u;
    adapter_source->context = &source;
    adapter_source->resolve = resolve_exact_mbuf;
    return true;
}

fk_dpdk_owner_mbuf_claim_result
fk_dpdk_owner_mbuf_bytes_source_claim_dequeued(
        fk_dpdk_owner_mbuf_bytes_source *source_ptr,
        const fk_owner_packet *packet) {
    if (source_ptr == nullptr)
        return FK_DPDK_OWNER_MBUF_CLAIM_INVALID;
    SourceImpl &source = *implementation(source_ptr);
    if (source.initialized == 0u)
        return FK_DPDK_OWNER_MBUF_CLAIM_INVALID;
    if (!owner_thread(source))
        return FK_DPDK_OWNER_MBUF_CLAIM_NOT_OWNER;
    source.counters.packet_claim_attempts++;
    if (source.active_claim != 0u) {
        source.counters.double_claim_rejections++;
        return FK_DPDK_OWNER_MBUF_CLAIM_BUSY;
    }
    if (packet == nullptr || !descriptor_shape_valid(source, *packet)) {
        source.counters.descriptor_rejections++;
        return FK_DPDK_OWNER_MBUF_CLAIM_DESCRIPTOR_REJECTED;
    }
    const auto *mbuf =
        reinterpret_cast<const rte_mbuf *>(packet->packet_handle);
    const uint8_t *data = nullptr;
    if (!mbuf_shape_valid(
            *mbuf, packet->captured_length, packet->wire_length, &data)) {
        source.counters.mbuf_shape_rejections++;
        return FK_DPDK_OWNER_MBUF_CLAIM_SHAPE_REJECTED;
    }
    source.active_packet_handle = packet->packet_handle;
    source.active_data = data;
    source.active_buf_addr = mbuf->buf_addr;
    source.active_captured_length = packet->captured_length;
    source.active_wire_length = packet->wire_length;
    source.active_pkt_len = mbuf->pkt_len;
    source.active_ol_flags = mbuf->ol_flags;
    source.active_data_len = mbuf->data_len;
    source.active_data_off = mbuf->data_off;
    source.active_buf_len = mbuf->buf_len;
    source.active_refcnt = rte_mbuf_refcnt_read(mbuf);
    source.active_claim = 1u;
    source.counters.packet_claim_successes++;
    return FK_DPDK_OWNER_MBUF_CLAIMED;
}

fk_dpdk_owner_mbuf_release_result
fk_dpdk_owner_mbuf_bytes_source_release_consumed(
        fk_dpdk_owner_mbuf_bytes_source *source_ptr,
        uintptr_t exact_packet_handle) {
    if (source_ptr == nullptr)
        return FK_DPDK_OWNER_MBUF_RELEASE_INVALID;
    SourceImpl &source = *implementation(source_ptr);
    if (source.initialized == 0u)
        return FK_DPDK_OWNER_MBUF_RELEASE_INVALID;
    if (!owner_thread(source))
        return FK_DPDK_OWNER_MBUF_RELEASE_NOT_OWNER;
    source.counters.release_attempts++;
    if (source.active_claim == 0u) {
        source.counters.release_no_active_rejections++;
        return FK_DPDK_OWNER_MBUF_RELEASE_NO_ACTIVE_CLAIM;
    }
    if (exact_packet_handle == 0u ||
        exact_packet_handle != source.active_packet_handle) {
        source.counters.release_handle_mismatch_rejections++;
        return FK_DPDK_OWNER_MBUF_RELEASE_HANDLE_MISMATCH;
    }
    clear_active(source);
    source.counters.release_successes++;
    return FK_DPDK_OWNER_MBUF_RELEASED;
}

bool fk_dpdk_owner_mbuf_bytes_source_get_stats(
        const fk_dpdk_owner_mbuf_bytes_source *source_ptr,
        fk_dpdk_owner_mbuf_bytes_source_stats *stats) {
    if (stats != nullptr)
        *stats = {};
    if (source_ptr == nullptr || stats == nullptr)
        return false;
    const SourceImpl &source = *implementation(source_ptr);
    if (source.initialized == 0u)
        return false;
    *stats = source.counters;
    stats->owner_claim_attempts =
        source.owner_claim_attempts.load(std::memory_order_relaxed);
    stats->owner_claim_successes =
        source.owner_claim_successes.load(std::memory_order_relaxed);
    stats->owner_claim_rejections =
        source.owner_claim_rejections.load(std::memory_order_relaxed);
    stats->owner_thread_rejections =
        source.owner_thread_rejections.load(std::memory_order_relaxed);
    stats->active_packet_handle = source.active_packet_handle;
    stats->active_captured_length = source.active_captured_length;
    stats->active_wire_length = source.active_wire_length;
    stats->active_claim = source.active_claim;
    stats->accounting_conserved = accounting_conserved(source) ? 1u : 0u;
    return true;
}

bool fk_dpdk_owner_mbuf_bytes_source_accounting_conserved(
        const fk_dpdk_owner_mbuf_bytes_source *source_ptr) {
    return source_ptr != nullptr &&
        accounting_conserved(*implementation(source_ptr));
}

bool fk_dpdk_owner_mbuf_bytes_source_destroy_checked(
        fk_dpdk_owner_mbuf_bytes_source *source_ptr) {
    if (source_ptr == nullptr)
        return false;
    SourceImpl &source = *implementation(source_ptr);
    if (source.initialized == 0u)
        return false;
    if (source.active_claim != 0u) {
        source.counters.destroy_live_claim_rejections++;
        return false;
    }
    source.initialized = 0u;
    source.~SourceImpl();
    return true;
}

const char *fk_dpdk_owner_mbuf_claim_result_name(
        fk_dpdk_owner_mbuf_claim_result result) {
    switch (result) {
    case FK_DPDK_OWNER_MBUF_CLAIM_INVALID: return "invalid";
    case FK_DPDK_OWNER_MBUF_CLAIM_NOT_OWNER: return "not_owner";
    case FK_DPDK_OWNER_MBUF_CLAIMED: return "claimed";
    case FK_DPDK_OWNER_MBUF_CLAIM_BUSY: return "busy";
    case FK_DPDK_OWNER_MBUF_CLAIM_DESCRIPTOR_REJECTED:
        return "descriptor_rejected";
    case FK_DPDK_OWNER_MBUF_CLAIM_SHAPE_REJECTED:
        return "mbuf_shape_rejected";
    }
    return "unknown";
}

const char *fk_dpdk_owner_mbuf_release_result_name(
        fk_dpdk_owner_mbuf_release_result result) {
    switch (result) {
    case FK_DPDK_OWNER_MBUF_RELEASE_INVALID: return "invalid";
    case FK_DPDK_OWNER_MBUF_RELEASE_NOT_OWNER: return "not_owner";
    case FK_DPDK_OWNER_MBUF_RELEASED: return "released";
    case FK_DPDK_OWNER_MBUF_RELEASE_NO_ACTIVE_CLAIM:
        return "no_active_claim";
    case FK_DPDK_OWNER_MBUF_RELEASE_HANDLE_MISMATCH:
        return "handle_mismatch";
    }
    return "unknown";
}

}  // extern "C"
