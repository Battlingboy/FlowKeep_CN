#include "fk_dpdk_exact_identity_mbuf_source.h"

#include <rte_mbuf.h>

#include <atomic>
#include <cstddef>
#include <cstring>
#include <limits>
#include <new>

namespace {

struct SourceImpl {
    fk_dpdk_exact_identity_mbuf_source_config config{};
    std::atomic<uint64_t> identity_thread_token{0u};
    std::atomic<uint64_t> identity_thread_claim_attempts{0u};
    std::atomic<uint64_t> identity_thread_claim_successes{0u};
    std::atomic<uint64_t> identity_thread_claim_rejections{0u};
    std::atomic<uint64_t> identity_thread_rejections{0u};
    fk_dpdk_exact_identity_mbuf_source_stats counters{};
    fk_exact_identity_packet active_packet{};
    const uint8_t *active_data = nullptr;
    void *active_buf_addr = nullptr;
    uint64_t active_ol_flags = 0u;
    uint32_t active_pkt_len = 0u;
    uint16_t active_data_len = 0u;
    uint16_t active_data_off = 0u;
    uint16_t active_buf_len = 0u;
    uint16_t active_refcnt = 0u;
    uint8_t initialized = 0u;
    uint8_t active_claim = 0u;
    uint8_t reserved[6]{};
};

static_assert(sizeof(fk_dpdk_exact_identity_mbuf_source_config) == 16u,
    "exact identity mbuf source config ABI changed");
static_assert(alignof(SourceImpl) <= alignof(max_align_t),
    "exact identity mbuf source must fit max_align_t placement storage");

std::atomic<uint64_t> g_next_identity_thread_token{1u};

SourceImpl *implementation(fk_dpdk_exact_identity_mbuf_source *source) {
    return reinterpret_cast<SourceImpl *>(source);
}

const SourceImpl *implementation(
        const fk_dpdk_exact_identity_mbuf_source *source) {
    return reinterpret_cast<const SourceImpl *>(source);
}

bool reserved_zero(const fk_dpdk_exact_identity_mbuf_source_config &config) {
    for (const uint8_t value : config.reserved) {
        if (value != 0u)
            return false;
    }
    return true;
}

bool config_valid(const fk_dpdk_exact_identity_mbuf_source_config *config) {
    return config != nullptr &&
        config->abi_version ==
            FK_DPDK_EXACT_IDENTITY_MBUF_SOURCE_ABI_VERSION &&
        config->producer_count != 0u &&
        config->producer_count <= FK_EXACT_IDENTITY_SEQUENCER_MAX_PRODUCERS &&
        reserved_zero(*config);
}

uint64_t allocate_identity_thread_token() {
    uint64_t candidate =
        g_next_identity_thread_token.load(std::memory_order_relaxed);
    while (candidate != 0u) {
        const uint64_t successor =
            candidate == std::numeric_limits<uint64_t>::max()
                ? 0u : candidate + 1u;
        if (g_next_identity_thread_token.compare_exchange_weak(
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
    static thread_local const uint64_t token =
        allocate_identity_thread_token();
    return token;
}

bool identity_thread(SourceImpl &source) {
    const uint64_t current = current_thread_token();
    const uint64_t claimed =
        source.identity_thread_token.load(std::memory_order_acquire);
    if (current != 0u && claimed != 0u && current == claimed)
        return true;
    source.identity_thread_rejections.fetch_add(
        1u, std::memory_order_relaxed);
    return false;
}

bool packet_valid(
        const SourceImpl &source,
        const fk_exact_identity_packet &packet) {
    return packet.packet_handle != 0u &&
        packet.packet_sequence < FK_EXACT_IDENTITY_SEQUENCER_MAX_PACKETS &&
        packet.physical_ingress_timestamp_ns != 0u &&
        packet.captured_length != 0u &&
        packet.wire_length >= packet.captured_length &&
        packet.ingress_worker < source.config.producer_count &&
        packet.reserved == 0u;
}

bool exact_packet_equal(
        const fk_exact_identity_packet &left,
        const fk_exact_identity_packet &right) {
    return left.packet_handle == right.packet_handle &&
        left.packet_sequence == right.packet_sequence &&
        left.semantic_timestamp_ns == right.semantic_timestamp_ns &&
        left.physical_ingress_timestamp_ns ==
            right.physical_ingress_timestamp_ns &&
        left.captured_length == right.captured_length &&
        left.wire_length == right.wire_length &&
        left.ingress_worker == right.ingress_worker &&
        left.reserved == right.reserved;
}

bool mbuf_valid(
        const rte_mbuf &mbuf,
        uint32_t captured_length,
        const uint8_t **data) {
    if (data != nullptr)
        *data = nullptr;
    if (captured_length == 0u || mbuf.buf_addr == nullptr ||
        mbuf.nb_segs != 1u || mbuf.next != nullptr ||
        mbuf.pkt_len == 0u || mbuf.data_len == 0u ||
        mbuf.pkt_len != mbuf.data_len || mbuf.pkt_len != captured_length ||
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

bool active_mbuf_unchanged(const SourceImpl &source) {
    if (source.active_claim == 0u ||
        source.active_packet.packet_handle == 0u)
        return false;
    const auto *mbuf = reinterpret_cast<const rte_mbuf *>(
        source.active_packet.packet_handle);
    const uint8_t *data = nullptr;
    return mbuf_valid(*mbuf, source.active_packet.captured_length, &data) &&
        data == source.active_data &&
        mbuf->buf_addr == source.active_buf_addr &&
        mbuf->ol_flags == source.active_ol_flags &&
        mbuf->pkt_len == source.active_pkt_len &&
        mbuf->data_len == source.active_data_len &&
        mbuf->data_off == source.active_data_off &&
        mbuf->buf_len == source.active_buf_len &&
        rte_mbuf_refcnt_read(mbuf) == source.active_refcnt;
}

void clear_active(SourceImpl &source) {
    source.active_packet = {};
    source.active_data = nullptr;
    source.active_buf_addr = nullptr;
    source.active_ol_flags = 0u;
    source.active_pkt_len = 0u;
    source.active_data_len = 0u;
    source.active_data_off = 0u;
    source.active_buf_len = 0u;
    source.active_refcnt = 0u;
    source.active_claim = 0u;
}

bool resolve_active(
        void *context,
        uintptr_t exact_packet_handle,
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
    if (source.initialized == 0u || !identity_thread(source))
        return false;
    source.counters.resolver_calls++;
    if (source.active_claim == 0u) {
        source.counters.resolver_no_active_rejections++;
        return false;
    }
    if (exact_packet_handle == 0u ||
        exact_packet_handle != source.active_packet.packet_handle) {
        source.counters.resolver_handle_mismatch_rejections++;
        return false;
    }
    if (!active_mbuf_unchanged(source)) {
        source.counters.resolver_mbuf_mutation_rejections++;
        return false;
    }
    *frame = source.active_data;
    *captured_length = source.active_packet.captured_length;
    *wire_length = source.active_packet.wire_length;
    source.counters.resolver_successes++;
    return true;
}

bool checked_sum_equals(
        uint64_t expected,
        const uint64_t *values,
        size_t count) {
    uint64_t sum = 0u;
    for (size_t index = 0u; index < count; ++index) {
        if (values[index] > std::numeric_limits<uint64_t>::max() - sum)
            return false;
        sum += values[index];
    }
    return sum == expected;
}

bool accounting_conserved(const SourceImpl &source) {
    const auto &s = source.counters;
    const uint64_t active = source.active_claim != 0u ? 1u : 0u;
    const uint64_t thread_partition[]{
        source.identity_thread_claim_successes.load(
            std::memory_order_relaxed),
        source.identity_thread_claim_rejections.load(
            std::memory_order_relaxed),
    };
    const uint64_t claim_partition[]{
        s.released_claim_successes,
        s.double_claim_rejections,
        s.descriptor_rejections,
        s.mbuf_shape_rejections,
    };
    const uint64_t resolver_partition[]{
        s.resolver_successes,
        s.resolver_no_active_rejections,
        s.resolver_handle_mismatch_rejections,
        s.resolver_mbuf_mutation_rejections,
    };
    const uint64_t retain_partition[]{
        s.backpressure_retentions,
        s.backpressure_no_active_rejections,
        s.backpressure_descriptor_mismatch_rejections,
        s.backpressure_mbuf_mutation_rejections,
    };
    const uint64_t clear_attempts[]{
        s.transfer_clear_attempts,
        s.skip_reclaim_clear_attempts,
        s.reject_reclaim_clear_attempts,
    };
    const uint64_t clear_partition[]{
        s.transfer_clears,
        s.skip_reclaim_clears,
        s.reject_reclaim_clears,
        s.clear_no_active_rejections,
        s.clear_descriptor_mismatch_rejections,
        s.clear_mbuf_mutation_rejections,
    };
    const uint64_t ownership_partition[]{
        s.transfer_clears,
        s.skip_reclaim_clears,
        s.reject_reclaim_clears,
        active,
    };
    uint64_t total_clear_attempts = 0u;
    if (!checked_sum_equals(
            source.identity_thread_claim_attempts.load(
                std::memory_order_relaxed),
            thread_partition,
            sizeof(thread_partition) / sizeof(thread_partition[0])) ||
        source.identity_thread_claim_successes.load(
            std::memory_order_relaxed) > 1u ||
        !checked_sum_equals(s.released_claim_attempts,
            claim_partition,
            sizeof(claim_partition) / sizeof(claim_partition[0])) ||
        !checked_sum_equals(s.resolver_calls,
            resolver_partition,
            sizeof(resolver_partition) / sizeof(resolver_partition[0])) ||
        !checked_sum_equals(s.backpressure_retain_attempts,
            retain_partition,
            sizeof(retain_partition) / sizeof(retain_partition[0]))) {
        return false;
    }
    for (const uint64_t value : clear_attempts) {
        if (value > std::numeric_limits<uint64_t>::max() -
                total_clear_attempts)
            return false;
        total_clear_attempts += value;
    }
    return source.initialized == 1u && source.active_claim <= 1u &&
        checked_sum_equals(total_clear_attempts,
            clear_partition,
            sizeof(clear_partition) / sizeof(clear_partition[0])) &&
        checked_sum_equals(s.released_claim_successes,
            ownership_partition,
            sizeof(ownership_partition) / sizeof(ownership_partition[0])) &&
        ((active == 0u && source.active_packet.packet_handle == 0u &&
          source.active_data == nullptr) ||
         (active == 1u && source.active_packet.packet_handle != 0u &&
          source.active_data != nullptr));
}

enum class ClearKind { Transfer, SkipReclaim, RejectReclaim };

fk_dpdk_exact_identity_mbuf_clear_result clear_exact(
        SourceImpl &source,
        const fk_exact_identity_packet *packet,
        ClearKind kind) {
    switch (kind) {
    case ClearKind::Transfer: source.counters.transfer_clear_attempts++; break;
    case ClearKind::SkipReclaim:
        source.counters.skip_reclaim_clear_attempts++;
        break;
    case ClearKind::RejectReclaim:
        source.counters.reject_reclaim_clear_attempts++;
        break;
    }
    if (source.active_claim == 0u) {
        source.counters.clear_no_active_rejections++;
        return FK_DPDK_EXACT_IDENTITY_MBUF_CLEAR_NO_ACTIVE_CLAIM;
    }
    if (packet == nullptr ||
        !exact_packet_equal(*packet, source.active_packet)) {
        source.counters.clear_descriptor_mismatch_rejections++;
        return FK_DPDK_EXACT_IDENTITY_MBUF_CLEAR_DESCRIPTOR_MISMATCH;
    }
    /* DATA_COMMITTED made the descriptor visible to the fixed owner.  That
     * owner may already have consumed and freed the mbuf, so the transfer
     * transition must never dereference it again.  The router resolved and
     * validated these immutable bytes before commit; the complete frozen
     * descriptor is the only safe post-commit close token.  SKIP/REJECT keep
     * caller ownership and therefore still validate before reclamation. */
    if (kind != ClearKind::Transfer && !active_mbuf_unchanged(source)) {
        source.counters.clear_mbuf_mutation_rejections++;
        return FK_DPDK_EXACT_IDENTITY_MBUF_CLEAR_MBUF_MUTATED;
    }
    clear_active(source);
    switch (kind) {
    case ClearKind::Transfer: source.counters.transfer_clears++; break;
    case ClearKind::SkipReclaim: source.counters.skip_reclaim_clears++; break;
    case ClearKind::RejectReclaim:
        source.counters.reject_reclaim_clears++;
        break;
    }
    return FK_DPDK_EXACT_IDENTITY_MBUF_CLEARED;
}

}  // namespace

extern "C" {

void fk_dpdk_exact_identity_mbuf_source_default_config_init(
        fk_dpdk_exact_identity_mbuf_source_config *config) {
    if (config == nullptr)
        return;
    *config = {};
    config->abi_version = FK_DPDK_EXACT_IDENTITY_MBUF_SOURCE_ABI_VERSION;
    config->producer_count = 1u;
}

bool fk_dpdk_exact_identity_mbuf_source_config_valid(
        const fk_dpdk_exact_identity_mbuf_source_config *config) {
    return config_valid(config);
}

size_t fk_dpdk_exact_identity_mbuf_source_storage_bytes(
        const fk_dpdk_exact_identity_mbuf_source_config *config) {
    return config_valid(config) ? sizeof(SourceImpl) : 0u;
}

fk_dpdk_exact_identity_mbuf_source *
fk_dpdk_exact_identity_mbuf_source_initialize(
        void *storage,
        size_t storage_bytes,
        const fk_dpdk_exact_identity_mbuf_source_config *config) {
    if (storage == nullptr || !config_valid(config) ||
        storage_bytes < sizeof(SourceImpl) ||
        reinterpret_cast<uintptr_t>(storage) % alignof(max_align_t) != 0u)
        return nullptr;
    auto *source = new (storage) SourceImpl{};
    source->config = *config;
    source->counters.abi_version =
        FK_DPDK_EXACT_IDENTITY_MBUF_SOURCE_ABI_VERSION;
    source->counters.producer_count = config->producer_count;
    source->counters.initialized = 1u;
    source->initialized = 1u;
    return reinterpret_cast<fk_dpdk_exact_identity_mbuf_source *>(source);
}

bool fk_dpdk_exact_identity_mbuf_source_claim_identity_thread(
        fk_dpdk_exact_identity_mbuf_source *source_ptr) {
    if (source_ptr == nullptr)
        return false;
    SourceImpl &source = *implementation(source_ptr);
    if (source.initialized == 0u)
        return false;
    source.identity_thread_claim_attempts.fetch_add(
        1u, std::memory_order_relaxed);
    const uint64_t token = current_thread_token();
    uint64_t expected = 0u;
    if (token != 0u && source.identity_thread_token.compare_exchange_strong(
            expected,
            token,
            std::memory_order_acq_rel,
            std::memory_order_acquire)) {
        source.identity_thread_claim_successes.fetch_add(
            1u, std::memory_order_relaxed);
        source.counters.identity_thread_claimed = 1u;
        return true;
    }
    source.identity_thread_claim_rejections.fetch_add(
        1u, std::memory_order_relaxed);
    source.identity_thread_rejections.fetch_add(
        1u, std::memory_order_relaxed);
    return false;
}

bool fk_dpdk_exact_identity_mbuf_source_get_resolver(
        fk_dpdk_exact_identity_mbuf_source *source_ptr,
        fk_exact_identity_packet_bytes_resolver *resolver) {
    if (resolver != nullptr)
        *resolver = {};
    if (source_ptr == nullptr || resolver == nullptr)
        return false;
    SourceImpl &source = *implementation(source_ptr);
    if (source.initialized == 0u)
        return false;
    resolver->abi_version = FK_EXACT_IDENTITY_PACKET_BYTES_RESOLVER_ABI_VERSION;
    resolver->exact_handle_binding = 1u;
    resolver->immutable_while_claimed = 1u;
    resolver->contiguous_frame = 1u;
    resolver->context = &source;
    resolver->resolve = resolve_active;
    return true;
}

fk_dpdk_exact_identity_mbuf_claim_result
fk_dpdk_exact_identity_mbuf_source_claim_released(
        fk_dpdk_exact_identity_mbuf_source *source_ptr,
        const fk_exact_identity_packet *packet) {
    if (source_ptr == nullptr)
        return FK_DPDK_EXACT_IDENTITY_MBUF_CLAIM_INVALID;
    SourceImpl &source = *implementation(source_ptr);
    if (source.initialized == 0u)
        return FK_DPDK_EXACT_IDENTITY_MBUF_CLAIM_INVALID;
    if (!identity_thread(source))
        return FK_DPDK_EXACT_IDENTITY_MBUF_CLAIM_NOT_IDENTITY_THREAD;
    source.counters.released_claim_attempts++;
    if (source.active_claim != 0u) {
        source.counters.double_claim_rejections++;
        return FK_DPDK_EXACT_IDENTITY_MBUF_CLAIM_BUSY;
    }
    if (packet == nullptr || !packet_valid(source, *packet)) {
        source.counters.descriptor_rejections++;
        return FK_DPDK_EXACT_IDENTITY_MBUF_CLAIM_DESCRIPTOR_REJECTED;
    }
    const auto *mbuf =
        reinterpret_cast<const rte_mbuf *>(packet->packet_handle);
    const uint8_t *data = nullptr;
    if (!mbuf_valid(*mbuf, packet->captured_length, &data)) {
        source.counters.mbuf_shape_rejections++;
        return FK_DPDK_EXACT_IDENTITY_MBUF_CLAIM_SHAPE_REJECTED;
    }
    source.active_packet = *packet;
    source.active_data = data;
    source.active_buf_addr = mbuf->buf_addr;
    source.active_ol_flags = mbuf->ol_flags;
    source.active_pkt_len = mbuf->pkt_len;
    source.active_data_len = mbuf->data_len;
    source.active_data_off = mbuf->data_off;
    source.active_buf_len = mbuf->buf_len;
    source.active_refcnt = rte_mbuf_refcnt_read(mbuf);
    source.active_claim = 1u;
    source.counters.released_claim_successes++;
    return FK_DPDK_EXACT_IDENTITY_MBUF_CLAIMED;
}

fk_dpdk_exact_identity_mbuf_retain_result
fk_dpdk_exact_identity_mbuf_source_retain_backpressure(
        fk_dpdk_exact_identity_mbuf_source *source_ptr,
        const fk_exact_identity_packet *packet) {
    if (source_ptr == nullptr)
        return FK_DPDK_EXACT_IDENTITY_MBUF_RETAIN_INVALID;
    SourceImpl &source = *implementation(source_ptr);
    if (source.initialized == 0u)
        return FK_DPDK_EXACT_IDENTITY_MBUF_RETAIN_INVALID;
    if (!identity_thread(source))
        return FK_DPDK_EXACT_IDENTITY_MBUF_RETAIN_NOT_IDENTITY_THREAD;
    source.counters.backpressure_retain_attempts++;
    if (source.active_claim == 0u) {
        source.counters.backpressure_no_active_rejections++;
        return FK_DPDK_EXACT_IDENTITY_MBUF_RETAIN_NO_ACTIVE_CLAIM;
    }
    if (packet == nullptr ||
        !exact_packet_equal(*packet, source.active_packet)) {
        source.counters.backpressure_descriptor_mismatch_rejections++;
        return FK_DPDK_EXACT_IDENTITY_MBUF_RETAIN_DESCRIPTOR_MISMATCH;
    }
    if (!active_mbuf_unchanged(source)) {
        source.counters.backpressure_mbuf_mutation_rejections++;
        return FK_DPDK_EXACT_IDENTITY_MBUF_RETAIN_MBUF_MUTATED;
    }
    source.counters.backpressure_retentions++;
    return FK_DPDK_EXACT_IDENTITY_MBUF_RETAINED;
}

fk_dpdk_exact_identity_mbuf_clear_result
fk_dpdk_exact_identity_mbuf_source_transfer_data_committed(
        fk_dpdk_exact_identity_mbuf_source *source_ptr,
        const fk_exact_identity_packet *packet) {
    if (source_ptr == nullptr)
        return FK_DPDK_EXACT_IDENTITY_MBUF_CLEAR_INVALID;
    SourceImpl &source = *implementation(source_ptr);
    if (source.initialized == 0u)
        return FK_DPDK_EXACT_IDENTITY_MBUF_CLEAR_INVALID;
    if (!identity_thread(source))
        return FK_DPDK_EXACT_IDENTITY_MBUF_CLEAR_NOT_IDENTITY_THREAD;
    return clear_exact(source, packet, ClearKind::Transfer);
}

fk_dpdk_exact_identity_mbuf_clear_result
fk_dpdk_exact_identity_mbuf_source_clear_skip_for_reclaim(
        fk_dpdk_exact_identity_mbuf_source *source_ptr,
        const fk_exact_identity_packet *packet) {
    if (source_ptr == nullptr)
        return FK_DPDK_EXACT_IDENTITY_MBUF_CLEAR_INVALID;
    SourceImpl &source = *implementation(source_ptr);
    if (source.initialized == 0u)
        return FK_DPDK_EXACT_IDENTITY_MBUF_CLEAR_INVALID;
    if (!identity_thread(source))
        return FK_DPDK_EXACT_IDENTITY_MBUF_CLEAR_NOT_IDENTITY_THREAD;
    return clear_exact(source, packet, ClearKind::SkipReclaim);
}

fk_dpdk_exact_identity_mbuf_clear_result
fk_dpdk_exact_identity_mbuf_source_clear_reject_for_reclaim(
        fk_dpdk_exact_identity_mbuf_source *source_ptr,
        const fk_exact_identity_packet *packet) {
    if (source_ptr == nullptr)
        return FK_DPDK_EXACT_IDENTITY_MBUF_CLEAR_INVALID;
    SourceImpl &source = *implementation(source_ptr);
    if (source.initialized == 0u)
        return FK_DPDK_EXACT_IDENTITY_MBUF_CLEAR_INVALID;
    if (!identity_thread(source))
        return FK_DPDK_EXACT_IDENTITY_MBUF_CLEAR_NOT_IDENTITY_THREAD;
    return clear_exact(source, packet, ClearKind::RejectReclaim);
}

bool fk_dpdk_exact_identity_mbuf_source_get_stats(
        const fk_dpdk_exact_identity_mbuf_source *source_ptr,
        fk_dpdk_exact_identity_mbuf_source_stats *stats) {
    if (stats != nullptr)
        *stats = {};
    if (source_ptr == nullptr || stats == nullptr)
        return false;
    const SourceImpl &source = *implementation(source_ptr);
    if (source.initialized == 0u)
        return false;
    *stats = source.counters;
    stats->identity_thread_claim_attempts =
        source.identity_thread_claim_attempts.load(std::memory_order_relaxed);
    stats->identity_thread_claim_successes =
        source.identity_thread_claim_successes.load(
            std::memory_order_relaxed);
    stats->identity_thread_claim_rejections =
        source.identity_thread_claim_rejections.load(
            std::memory_order_relaxed);
    stats->identity_thread_rejections =
        source.identity_thread_rejections.load(std::memory_order_relaxed);
    stats->active_packet_handle = source.active_packet.packet_handle;
    stats->active_packet_sequence = source.active_packet.packet_sequence;
    stats->active_captured_length = source.active_packet.captured_length;
    stats->active_wire_length = source.active_packet.wire_length;
    stats->active_claim = source.active_claim;
    stats->accounting_conserved = accounting_conserved(source) ? 1u : 0u;
    return true;
}

bool fk_dpdk_exact_identity_mbuf_source_accounting_conserved(
        const fk_dpdk_exact_identity_mbuf_source *source_ptr) {
    return source_ptr != nullptr &&
        accounting_conserved(*implementation(source_ptr));
}

bool fk_dpdk_exact_identity_mbuf_source_destroy_checked(
        fk_dpdk_exact_identity_mbuf_source *source_ptr) {
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

}  // extern "C"
