#include "fk_exact_identity_router.h"

#include "fk_quic_initial_admission_bridge.h"

#include <atomic>
#include <cstddef>
#include <cstdio>
#include <cstring>
#include <limits>
#include <new>

namespace {

constexpr uint64_t kMagic = UINT64_C(0x464b455852545231);  // "FKEXRTR1"

enum class PreparedKind : uint8_t {
    None = 0u,
    Data = 1u,
    Skip = 2u,
};

enum class PreparedClearDisposition : uint8_t {
    Normal = 0u,
    DirectAbort = 1u,
    DetachedGlobalAbort = 2u,
};

struct RouterImpl {
    uint64_t magic = 0u;
    fk_exact_identity_router_config config{};
    fk_exact_identity_packet_bytes_resolver resolver{};
    fk_quic_cid_map *cid_map = nullptr;
    fk_quic_presentation_path_directory *path_directory = nullptr;
    fk_owner_dispatch *dispatch = nullptr;
    fk_quic_route_receipt_state *route_receipts = nullptr;
    fk_quic_retirement_publisher *retirement_publisher = nullptr;
    fk_owner_output_sequence_bridge *completion_bridge = nullptr;
    fk_quic_initial_crypto_admission_gate *initial_crypto_gate = nullptr;
    void *monotonic_clock_context = nullptr;
    fk_exact_identity_router_monotonic_now_ns_callback monotonic_now_ns =
        nullptr;
    std::atomic<uint64_t> identity_thread_token{0u};
    std::atomic<uint64_t> identity_thread_claim_attempts{0u};
    std::atomic<uint64_t> identity_thread_claim_successes{0u};
    std::atomic<uint64_t> identity_thread_claim_rejections{0u};
    std::atomic<uint64_t> identity_thread_call_rejections{0u};
    std::atomic<uint64_t> abort_pending_wrong_thread_calls{0u};
    std::atomic<uint64_t> detach_pending_wrong_thread_calls{0u};
    fk_exact_identity_router_stats counters{};
    fk_exact_identity_packet reserved_packet{};
    fk_owner_packet prepared_data_packet{};
    fk_exact_identity_router_result prepared_result{};
    fk_exact_identity_router_result terminal_pending_result{};
    fk_exact_identity_packet last_aborted_packet{};
    fk_exact_identity_router_detach_receipt_v1 detached_receipt{};
    fk_quic_initial_crypto_admission_receipt_v1 active_crypto_receipt{};
    /* The identity stage has one immutable owner-hash key and one claimed
     * thread.  Consecutive packets of an elephant flow therefore need only a
     * 38-byte exact-key comparison; repeating identity materialization and
     * SipHash cannot change the selected owner. */
    fk_flow_key cached_flow_owner_key{};
    uint16_t cached_flow_owner = UINT16_MAX;
    uint8_t cached_flow_owner_valid = 0u;
    fk_owner_observation_skip_reason prepared_skip_reason =
        FK_OWNER_OBSERVATION_SKIP_FILTERED;
    PreparedKind prepared_kind = PreparedKind::None;
    uint8_t reservation_live = 0u;
    uint8_t prepared_terminal_after_commit = 0u;
    uint8_t last_abort_valid = 0u;
    uint8_t detached_global_abort = 0u;
    uint8_t terminal_pending_global_abort = 0u;
    uint8_t active_crypto_receipt_live = 0u;
    uint8_t sticky_failure = 0u;
    uint8_t initialized = 0u;
};

static_assert(sizeof(fk_exact_identity_router_config) == 16u,
    "exact identity router config ABI changed");
static_assert(alignof(RouterImpl) <= alignof(max_align_t),
    "exact identity router placement alignment changed");

std::atomic<uint64_t> g_next_identity_thread_token{1u};

RouterImpl *implementation(fk_exact_identity_router *router) {
    return reinterpret_cast<RouterImpl *>(router);
}

const RouterImpl *implementation(const fk_exact_identity_router *router) {
    return reinterpret_cast<const RouterImpl *>(router);
}

void set_error(char *error, size_t capacity, const char *message) {
    if (error == nullptr || capacity == 0u)
        return;
    std::snprintf(error, capacity, "%s", message == nullptr ? "" : message);
}

bool all_zero(const uint8_t *bytes, size_t count) {
    if (bytes == nullptr)
        return false;
    uint8_t combined = 0u;
    for (size_t index = 0u; index < count; ++index)
        combined = static_cast<uint8_t>(combined | bytes[index]);
    return combined == 0u;
}

bool config_valid(const fk_exact_identity_router_config *config) {
    return config != nullptr &&
        config->abi_version == FK_EXACT_IDENTITY_ROUTER_ABI_VERSION &&
        config->owner_count != 0u &&
        config->owner_count <= FK_QUIC_ROUTE_RECEIPT_MAX_OWNERS &&
        (config->owner_count & (config->owner_count - 1u)) == 0u &&
        all_zero(config->reserved, sizeof(config->reserved));
}

bool resolver_valid(
        const fk_exact_identity_packet_bytes_resolver *resolver) {
    return resolver != nullptr &&
        resolver->abi_version ==
            FK_EXACT_IDENTITY_PACKET_BYTES_RESOLVER_ABI_VERSION &&
        resolver->exact_handle_binding == 1u &&
        resolver->immutable_while_claimed == 1u &&
        resolver->contiguous_frame == 1u &&
        resolver->reserved0 == 0u &&
        resolver->context != nullptr && resolver->resolve != nullptr;
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

bool identity_thread(RouterImpl &state) {
    const uint64_t current = current_thread_token();
    const uint64_t claimed =
        state.identity_thread_token.load(std::memory_order_acquire);
    if (current != 0u && claimed != 0u && current == claimed)
        return true;
    state.identity_thread_call_rejections.fetch_add(
        1u, std::memory_order_relaxed);
    return false;
}

bool checked_add(RouterImpl &state, uint64_t &counter, uint64_t value = 1u) {
    if (value > std::numeric_limits<uint64_t>::max() - counter) {
        state.sticky_failure = 1u;
        return false;
    }
    counter += value;
    return true;
}

bool record_parser_rejection(
        RouterImpl &state, fk_native_parse_code code) {
    if (code <= FK_PARSE_OK || code > FK_PARSE_CAP_EXCEEDED) {
        state.sticky_failure = 1u;
        return false;
    }
    return checked_add(state, state.counters.parser_rejections) &&
        checked_add(
            state,
            state.counters.parser_rejections_by_code[
                static_cast<unsigned>(code)]);
}

bool parser_reason_partition_conserved(
        const fk_exact_identity_router_stats &stats) {
    if (stats.parser_rejections_by_code[FK_PARSE_OK] != 0u)
        return false;
    uint64_t total = 0u;
    for (unsigned code = FK_PARSE_TRUNCATED;
         code <= FK_PARSE_CAP_EXCEEDED; ++code) {
        const uint64_t count = stats.parser_rejections_by_code[code];
        if (count > std::numeric_limits<uint64_t>::max() - total)
            return false;
        total += count;
    }
    return total == stats.parser_rejections;
}

bool resolve_active_crypto_receipt(
        RouterImpl &state,
        fk_quic_initial_crypto_completion_outcome outcome) {
    if (state.active_crypto_receipt_live == 0u)
        return true;
    const bool counter_ok = checked_add(
        state, state.counters.initial_crypto_gate_completion_attempts);
    const fk_quic_initial_crypto_completion_result completed =
        fk_quic_initial_crypto_admission_gate_complete(
            state.initial_crypto_gate,
            &state.active_crypto_receipt,
            outcome);
    if (completed == FK_QUIC_INITIAL_CRYPTO_COMPLETED ||
        completed == FK_QUIC_INITIAL_CRYPTO_COMPLETE_ALREADY_COMPLETED) {
        state.active_crypto_receipt = {};
        state.active_crypto_receipt_live = 0u;
        const bool completion_counter_ok = checked_add(
            state, state.counters.initial_crypto_gate_completions);
        return counter_ok && completion_counter_ok;
    }
    (void)checked_add(
        state, state.counters.initial_crypto_gate_completion_rejections);
    /* A failed completion is already a formal integrity failure.  Abort-seal
     * is the only no-refund fallback which can abandon an otherwise live
     * receipt before the router becomes terminal. */
    if (fk_quic_initial_crypto_admission_gate_seal_abort(
            state.initial_crypto_gate)) {
        state.active_crypto_receipt = {};
        state.active_crypto_receipt_live = 0u;
    }
    return false;
}

bool gate_rejection_is_terminal(
        fk_quic_initial_crypto_admission_reason reason) {
    switch (reason) {
    case FK_QUIC_INITIAL_CRYPTO_REASON_GLOBAL_TOKENS_EXHAUSTED:
    case FK_QUIC_INITIAL_CRYPTO_REASON_PREFIX_CREDITS_EXHAUSTED:
    case FK_QUIC_INITIAL_CRYPTO_REASON_PREFIX_TABLE_PRESSURE:
    case FK_QUIC_INITIAL_CRYPTO_REASON_CRYPTO_INPUT_TOO_LARGE:
        return false;
    case FK_QUIC_INITIAL_CRYPTO_REASON_NONE:
    case FK_QUIC_INITIAL_CRYPTO_REASON_CHARGED_PREFIX_CRYPTO:
    case FK_QUIC_INITIAL_CRYPTO_REASON_IDEMPOTENT_ACTIVE_RETRY:
    case FK_QUIC_INITIAL_CRYPTO_REASON_INVALID_REQUEST:
    case FK_QUIC_INITIAL_CRYPTO_REASON_ACTIVE_DESCRIPTOR_MISMATCH:
    case FK_QUIC_INITIAL_CRYPTO_REASON_SEQUENCE_REPLAY:
    case FK_QUIC_INITIAL_CRYPTO_REASON_COMPLETED_DESCRIPTOR_REPLAY:
    case FK_QUIC_INITIAL_CRYPTO_REASON_CLOCK_REGRESSION:
    case FK_QUIC_INITIAL_CRYPTO_REASON_STOPPED:
    case FK_QUIC_INITIAL_CRYPTO_REASON_TERMINAL:
    case FK_QUIC_INITIAL_CRYPTO_REASON_COUNTER_OVERFLOW:
    case FK_QUIC_INITIAL_CRYPTO_REASON_INTERNAL_FAILURE:
    case FK_QUIC_INITIAL_CRYPTO_REASON_COUNT:
        return true;
    }
    return true;
}

void reset_result(fk_exact_identity_router_result *result) {
    if (result != nullptr)
        *result = {};
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

bool exact_packet_valid(
        const RouterImpl &state,
        const fk_exact_identity_packet *packet) {
    return packet != nullptr && packet->packet_handle != 0u &&
        packet->packet_sequence < FK_EXACT_IDENTITY_SEQUENCER_MAX_PACKETS &&
        packet->physical_ingress_timestamp_ns != 0u &&
        packet->captured_length != 0u &&
        packet->wire_length >= packet->captured_length &&
        packet->ingress_worker < state.config.owner_count &&
        packet->reserved == 0u;
}

void mark_sticky(RouterImpl &state) {
    state.sticky_failure = 1u;
}

fk_exact_identity_router_outcome finish_outcome(
        RouterImpl &state,
        fk_exact_identity_router_outcome outcome,
        fk_exact_identity_router_result *result) {
    uint64_t *counter = nullptr;
    switch (outcome) {
    case FK_EXACT_IDENTITY_ROUTER_DATA_COMMITTED_TRANSFER:
        counter = &state.counters.data_committed_transfers;
        break;
    case FK_EXACT_IDENTITY_ROUTER_SKIP_COMMITTED_RECLAIM:
        counter = &state.counters.skip_committed_reclaims;
        break;
    case FK_EXACT_IDENTITY_ROUTER_BACKPRESSURE_RETAIN:
        counter = &state.counters.backpressure_retentions;
        break;
    case FK_EXACT_IDENTITY_ROUTER_TERMINAL_RECLAIM_ABORT:
        counter = &state.counters.terminal_reclaim_aborts;
        break;
    case FK_EXACT_IDENTITY_ROUTER_TERMINAL_PENDING_GLOBAL_ABORT:
        counter = &state.counters.terminal_pending_global_aborts;
        break;
    case FK_EXACT_IDENTITY_ROUTER_INVALID:
    case FK_EXACT_IDENTITY_ROUTER_NOT_IDENTITY_THREAD:
        break;
    }
    if (counter != nullptr)
        (void)checked_add(state, *counter);
    if (result != nullptr)
        result->outcome = outcome;
    return outcome;
}

bool topology_matches(
        const fk_exact_identity_router_config &config,
        fk_quic_cid_map *cid_map,
        fk_owner_dispatch *dispatch,
        fk_quic_route_receipt_state *route_receipts,
        fk_quic_retirement_publisher *publisher,
        fk_owner_output_sequence_bridge *completion_bridge) {
    fk_quic_cid_map_topology_receipt cid_topology{};
    fk_owner_dispatch_stats dispatch_stats{};
    fk_quic_route_receipt_stats receipt_stats{};
    fk_quic_retirement_publisher_stats publisher_stats{};
    fk_owner_output_sequence_bridge_stats completion_stats{};
    return fk_quic_cid_map_get_topology_receipt(cid_map, &cid_topology) &&
        fk_owner_dispatch_get_stats(dispatch, &dispatch_stats) &&
        fk_quic_route_receipt_get_stats(route_receipts, &receipt_stats) &&
        fk_quic_retirement_publisher_get_stats(
            publisher, &publisher_stats) &&
        fk_owner_output_sequence_bridge_get_stats(
            completion_bridge, &completion_stats) &&
        cid_topology.fixed_owner_count == config.owner_count &&
        dispatch_stats.worker_count == config.owner_count &&
        receipt_stats.owner_count == config.owner_count &&
        publisher_stats.owner_count == config.owner_count &&
        completion_stats.owner_count == config.owner_count;
}

bool build_owner_packet(
        const fk_exact_identity_packet &exact,
        uint16_t owner_worker,
        uint8_t identity_kind,
        uint64_t logical_connection_id,
        uint8_t feature_direction,
        uint8_t feature_direction_known,
        fk_owner_packet &packet) {
    if (owner_worker == UINT16_MAX)
        return false;
    packet = {};
    packet.packet_handle = exact.packet_handle;
    packet.logical_connection_id = logical_connection_id;
    packet.packet_sequence = exact.packet_sequence;
    packet.physical_ingress_timestamp_ns =
        exact.physical_ingress_timestamp_ns;
    packet.semantic_timestamp_ns = exact.semantic_timestamp_ns;
    packet.captured_length = exact.captured_length;
    packet.wire_length = exact.wire_length;
    packet.ingress_worker = exact.ingress_worker;
    packet.owner_worker = owner_worker;
    packet.identity_kind = identity_kind;
    packet.feature_direction = feature_direction;
    packet.feature_direction_known = feature_direction_known;
    return true;
}

bool quic_packet_kind(fk_exact_identity_router_packet_kind kind) {
    return kind == FK_EXACT_IDENTITY_ROUTER_PACKET_QUIC_INITIAL ||
        kind == FK_EXACT_IDENTITY_ROUTER_PACKET_QUIC_LONG ||
        kind == FK_EXACT_IDENTITY_ROUTER_PACKET_QUIC_SHORT;
}

fk_exact_identity_router_outcome abort_terminal(
    RouterImpl &state,
    const fk_exact_identity_packet *packet,
    fk_exact_identity_router_result *result);

fk_exact_identity_router_outcome reserve_completion_credit(
    RouterImpl &state,
    const fk_exact_identity_packet &packet,
    fk_exact_identity_router_result *result,
    bool &ready);

fk_exact_identity_router_outcome publish_skip(
    RouterImpl &state,
    const fk_exact_identity_packet &packet,
    fk_owner_observation_skip_reason reason,
    bool terminal_after_commit,
    fk_exact_identity_router_result *result);

fk_exact_identity_router_outcome publish_data(
    RouterImpl &state,
    const fk_exact_identity_packet &exact,
    fk_owner_packet &packet,
    fk_exact_identity_router_result *result);

fk_exact_identity_router_outcome publish_prepared(
    RouterImpl &state,
    fk_exact_identity_router_result *result);

void clear_prepared(
    RouterImpl &state,
    PreparedClearDisposition disposition);

bool select_flow_owner(
    RouterImpl &state,
    const fk_flow_key &key,
    uint16_t &owner);

bool select_initial_owner(
    RouterImpl &state,
    const uint8_t *dcid,
    uint8_t dcid_length,
    uint16_t &owner);

void record_cid_result(
    RouterImpl &state,
    fk_quic_cid_result_code code);

bool cid_success(const fk_quic_cid_resolution &resolution);

bool cid_internal_failure(const fk_quic_cid_resolution &resolution);

}  // namespace

extern "C" {

fk_exact_identity_router_outcome fk_exact_identity_router_process(
        fk_exact_identity_router *router,
        const fk_exact_identity_packet *exact_packet,
        fk_exact_identity_router_result *result) {
    reset_result(result);
    if (router == nullptr || result == nullptr)
        return FK_EXACT_IDENTITY_ROUTER_INVALID;
    RouterImpl &state = *implementation(router);
    if (state.magic != kMagic || state.initialized == 0u)
        return FK_EXACT_IDENTITY_ROUTER_INVALID;
    if (!identity_thread(state)) {
        result->outcome = FK_EXACT_IDENTITY_ROUTER_NOT_IDENTITY_THREAD;
        return result->outcome;
    }
    if (!checked_add(state, state.counters.process_attempts))
        return abort_terminal(state, exact_packet, result);
    if (state.terminal_pending_global_abort != 0u) {
        if (exact_packet != nullptr && exact_packet_equal(
                state.reserved_packet, *exact_packet)) {
            (void)checked_add(
                state, state.counters.terminal_pending_exact_replays);
            *result = state.terminal_pending_result;
            return finish_outcome(
                state,
                FK_EXACT_IDENTITY_ROUTER_TERMINAL_PENDING_GLOBAL_ABORT,
                result);
        }
        (void)checked_add(
            state,
            state.counters.terminal_pending_descriptor_mismatches);
        return finish_outcome(
            state,
            FK_EXACT_IDENTITY_ROUTER_TERMINAL_RECLAIM_ABORT,
            result);
    }
    if (!exact_packet_valid(state, exact_packet))
        return abort_terminal(state, exact_packet, result);
    const fk_exact_identity_packet &exact = *exact_packet;
    if (state.sticky_failure != 0u)
        return abort_terminal(state, &exact, result);

    /* A publisher-full transaction is already completely prepared and owns
     * a bound completion reservation.  Exact retry deliberately bypasses the
     * resolver, parser, authenticator, CID/path mutation, and receipt issue:
     * backpressure cannot change the packet's security evidence. */
    if (state.prepared_kind != PreparedKind::None) {
        bool reservation_ready = false;
        const fk_exact_identity_router_outcome reservation_outcome =
            reserve_completion_credit(
                state, exact, result, reservation_ready);
        if (!reservation_ready)
            return reservation_outcome;
        if (!checked_add(
                state, state.counters.prepared_retry_attempts) ||
            !checked_add(
                state,
                state.counters.prepared_retry_resolver_bypasses)) {
            return abort_terminal(state, &exact, result);
        }
        if (state.prepared_kind == PreparedKind::Data) {
            if (!checked_add(
                    state, state.counters.prepared_data_retries)) {
                return abort_terminal(state, &exact, result);
            }
        } else if (!checked_add(
                state, state.counters.prepared_skip_retries)) {
            return abort_terminal(state, &exact, result);
        }
        *result = state.prepared_result;
        return publish_prepared(state, result);
    }

    const uint8_t *frame = nullptr;
    size_t captured_length = 0u;
    uint32_t wire_length = 0u;
    (void)checked_add(state, state.counters.resolver_attempts);
    if (!state.resolver.resolve(
            state.resolver.context,
            exact.packet_handle,
            &frame,
            &captured_length,
            &wire_length) ||
        frame == nullptr || captured_length != exact.captured_length ||
        wire_length != exact.wire_length || captured_length == 0u ||
        captured_length > std::numeric_limits<uint32_t>::max()) {
        (void)checked_add(state, state.counters.resolver_rejections);
        return abort_terminal(state, &exact, result);
    }
    (void)checked_add(state, state.counters.resolver_successes);

    bool reservation_ready = false;
    const fk_exact_identity_router_outcome reservation_outcome =
        reserve_completion_credit(
            state, exact, result, reservation_ready);
    if (!reservation_ready)
        return reservation_outcome;

    if (captured_length < wire_length) {
        result->parse_code = FK_PARSE_TRUNCATED;
        if (!record_parser_rejection(state, FK_PARSE_TRUNCATED))
            return abort_terminal(state, &exact, result);
        return publish_skip(
            state,
            exact,
            FK_OWNER_OBSERVATION_SKIP_CAPTURE_TRUNCATED,
            false,
            result);
    }

    fk_packet_view view{};
    const fk_native_parse_code parse_code = fk_native_parse_ethernet(
        frame, captured_length, wire_length, &view);
    result->parse_code = parse_code;
    if (parse_code != FK_PARSE_OK) {
        if (!record_parser_rejection(state, parse_code))
            return abort_terminal(state, &exact, result);
        const fk_owner_observation_skip_reason reason =
            parse_code == FK_PARSE_UNSUPPORTED_L2 ||
                parse_code == FK_PARSE_UNSUPPORTED_L3 ||
                parse_code == FK_PARSE_UNSUPPORTED_L4
            ? FK_OWNER_OBSERVATION_SKIP_UNSUPPORTED_PACKET
            : FK_OWNER_OBSERVATION_SKIP_PARSE_REJECTED;
        return publish_skip(state, exact, reason, false, result);
    }
    (void)checked_add(state, state.counters.parser_successes);

    fk_flow_key flow_key{};
    uint8_t canonical_direction = 0u;
    const fk_native_parse_code flow_key_code = fk_native_flow_key(
        &view, &flow_key, &canonical_direction);
    if (flow_key_code != FK_PARSE_OK) {
        result->parse_code = flow_key_code;
        if (!record_parser_rejection(state, flow_key_code))
            return abort_terminal(state, &exact, result);
        return publish_skip(
            state,
            exact,
            FK_OWNER_OBSERVATION_SKIP_UNSUPPORTED_PACKET,
            false,
            result);
    }
    (void)canonical_direction;

    if (view.l4_protocol == 6u) {
        result->packet_kind =
            FK_EXACT_IDENTITY_ROUTER_PACKET_FLOW_KEY_TCP;
        (void)checked_add(state, state.counters.flow_key_tcp_packets);
        uint16_t owner = UINT16_MAX;
        if (!select_flow_owner(state, flow_key, owner)) {
            return publish_skip(
                state,
                exact,
                FK_OWNER_OBSERVATION_SKIP_UNRESOLVED_IDENTITY,
                true,
                result);
        }
        fk_owner_packet packet{};
        if (!build_owner_packet(
                exact,
                owner,
                FK_OWNER_IDENTITY_FLOW_KEY,
                0u,
                0u,
                0u,
                packet)) {
            return publish_skip(
                state,
                exact,
                FK_OWNER_OBSERVATION_SKIP_UNRESOLVED_IDENTITY,
                true,
                result);
        }
        result->owner_worker = owner;
        return publish_data(state, exact, packet, result);
    }
    if (view.l4_protocol != 17u || view.payload == nullptr ||
        view.payload_size == 0u) {
        return publish_skip(
            state,
            exact,
            FK_OWNER_OBSERVATION_SKIP_UNSUPPORTED_PACKET,
            false,
            result);
    }

    (void)checked_add(state, state.counters.path_classify_calls);
    fk_quic_presentation_path_classification path_classification{};
    const fk_quic_presentation_path_code path_code =
        fk_quic_presentation_path_directory_classify(
            state.path_directory,
            &flow_key,
            exact.semantic_timestamp_ns,
            &path_classification);
    if (path_code == FK_QUIC_PRESENTATION_PATH_REJECTED) {
        return publish_skip(
            state,
            exact,
            FK_OWNER_OBSERVATION_SKIP_UNRESOLVED_IDENTITY,
            true,
            result);
    }
    const bool known_quic_path =
        path_code == FK_QUIC_PRESENTATION_PATH_KNOWN_QUIC_PATH ||
        path_code == FK_QUIC_PRESENTATION_PATH_AMBIGUOUS;

    fk_quic_header_observation header{};
    const fk_native_parse_code inspect_code =
        fk_native_inspect_quic_header(&view, &header);
    const bool visible_long_header = inspect_code == FK_PARSE_OK &&
        (header.status == FK_QUIC_LONG_HEADER_PARTIAL ||
         header.status == FK_QUIC_VERSION_NEGOTIATION_PARTIAL);

    fk_quic_cid_resolution resolution{};
    fk_quic_initial_auth_result authenticated_initial{};
    const fk_quic_initial_auth_result *receipt_authentication = nullptr;
    fk_quic_route_evidence_kind evidence_kind =
        FK_QUIC_ROUTE_EVIDENCE_EXACT_SHORT_HEADER_DCID;
    fk_quic_route_placement_context placement_context =
        FK_QUIC_ROUTE_PLACEMENT_EXACT_CID_RESOLUTION;

    if (visible_long_header) {
        const bool supported_initial =
            header.long_packet_type == FK_QUIC_LONG_PACKET_INITIAL &&
            (header.version == FK_QUIC_INITIAL_AUTH_VERSION_V1 ||
             header.version == FK_QUIC_INITIAL_AUTH_VERSION_V2);
        /* Resolve an already authenticated DCID before attempting client
         * Initial decryption.  This routes server-sent Initial packets and
         * repeated client packets as exact known long-header evidence, and
         * avoids falsely counting them as client-auth failures. */
        const fk_quic_cid_result_code prelookup_code =
            fk_quic_cid_map_observe_long_header(
                state.cid_map,
                &header,
                exact.semantic_timestamp_ns,
                exact.ingress_worker,
                0u,
                &resolution);
        if (prelookup_code == FK_QUIC_CID_RESOLVED) {
            result->packet_kind =
                FK_EXACT_IDENTITY_ROUTER_PACKET_QUIC_LONG;
            (void)checked_add(state, state.counters.quic_long_packets);
            (void)checked_add(
                state, state.counters.exact_cid_no_crypto_routes);
            record_cid_result(state, prelookup_code);
            evidence_kind = FK_QUIC_ROUTE_EVIDENCE_EXACT_LONG_HEADER_DCID;
        } else if (supported_initial &&
                prelookup_code == FK_QUIC_CID_REJECTED &&
                resolution.reason ==
                    FK_QUIC_CID_REJECT_INITIAL_AUTH_REQUIRED) {
            result->packet_kind =
                FK_EXACT_IDENTITY_ROUTER_PACKET_QUIC_INITIAL;
            (void)checked_add(state, state.counters.quic_initial_packets);
            (void)checked_add(
                state, state.counters.initial_clear_bounds_inspections);
            fk_quic_initial_clear_bounds_v1 clear_bounds{};
            if (fk_quic_initial_inspect_client_clear_bounds(
                    view.payload,
                    view.payload_size,
                    &clear_bounds) !=
                    FK_QUIC_INITIAL_CLEAR_CRYPTO_CANDIDATE) {
                (void)checked_add(
                    state,
                    state.counters.initial_clear_bounds_rejections);
                result->initial_auth_reason = clear_bounds.reason;
                return publish_skip(
                    state,
                    exact,
                    FK_OWNER_OBSERVATION_SKIP_UNRESOLVED_IDENTITY,
                    false,
                    result);
            }
            (void)checked_add(
                state, state.counters.initial_clear_bounds_candidates);

            uint64_t physical_now_ns = 0u;
            if (!state.monotonic_now_ns(
                    state.monotonic_clock_context,
                    &physical_now_ns)) {
                result->initial_crypto_admission_decision =
                    FK_QUIC_INITIAL_CRYPTO_ADMISSION_REJECT;
                result->initial_crypto_admission_reason =
                    FK_QUIC_INITIAL_CRYPTO_REASON_INTERNAL_FAILURE;
                return publish_skip(
                    state,
                    exact,
                    FK_OWNER_OBSERVATION_SKIP_FILTERED,
                    true,
                    result);
            }
            fk_quic_initial_crypto_admission_request_v1 gate_request{};
            gate_request.abi_version =
                FK_QUIC_INITIAL_CRYPTO_ADMISSION_GATE_ABI_VERSION;
            gate_request.crypto_input_bytes = clear_bounds.packet_end_bytes;
            gate_request.ip_version = view.ip_version;
            gate_request.packet_sequence = exact.packet_sequence;
            gate_request.packet_handle = exact.packet_handle;
            gate_request.physical_ingress_timestamp_ns =
                exact.physical_ingress_timestamp_ns;
            gate_request.physical_now_ns = physical_now_ns;
            const size_t source_address_bytes =
                view.ip_version == 4u ? 4u : 16u;
            std::memcpy(
                gate_request.source_address,
                view.src_addr,
                source_address_bytes);
            if (!checked_add(
                    state,
                    state.counters.initial_crypto_gate_begin_attempts)) {
                return abort_terminal(state, &exact, result);
            }
            fk_quic_initial_crypto_admission_begin_result_v1 gate_begin{};
            const fk_quic_initial_crypto_admission_decision gate_decision =
                fk_quic_initial_crypto_admission_gate_begin(
                    state.initial_crypto_gate,
                    &gate_request,
                    &gate_begin);
            result->initial_crypto_admission_decision = gate_decision;
            result->initial_crypto_admission_reason = gate_begin.reason;
            if (gate_decision != FK_QUIC_INITIAL_CRYPTO_ADMISSION_ALLOW) {
                const bool rejection_counter_ok = checked_add(
                    state,
                    state.counters.initial_crypto_gate_rejections);
                return publish_skip(
                    state,
                    exact,
                    FK_OWNER_OBSERVATION_SKIP_FILTERED,
                    !rejection_counter_ok ||
                        gate_decision !=
                            FK_QUIC_INITIAL_CRYPTO_ADMISSION_REJECT ||
                        gate_rejection_is_terminal(gate_begin.reason),
                    result);
            }
            state.active_crypto_receipt = gate_begin.receipt;
            state.active_crypto_receipt_live = 1u;
            if (!checked_add(
                    state,
                    state.counters.initial_crypto_gate_allows) ||
                gate_begin.receipt.crypto_input_bytes !=
                    clear_bounds.packet_end_bytes ||
                gate_begin.receipt.packet_sequence != exact.packet_sequence ||
                gate_begin.receipt.packet_handle != exact.packet_handle ||
                !checked_add(
                    state, state.counters.initial_auth_attempts)) {
                return abort_terminal(state, &exact, result);
            }
            if (fk_quic_initial_authenticate_client(
                    view.payload,
                    view.payload_size,
                    &authenticated_initial,
                    nullptr) != FK_QUIC_INITIAL_AUTHENTICATED) {
                (void)checked_add(
                    state, state.counters.initial_auth_rejections);
                result->initial_auth_reason = authenticated_initial.reason;
                const fk_quic_initial_crypto_completion_outcome
                    completion_outcome =
                    authenticated_initial.reason ==
                            FK_QUIC_INITIAL_AUTH_REASON_CRYPTO_FAILURE
                        ? FK_QUIC_INITIAL_CRYPTO_COMPLETION_CRYPTO_FAILURE
                        : FK_QUIC_INITIAL_CRYPTO_COMPLETION_INVALID_AUTH;
                if (!resolve_active_crypto_receipt(
                        state, completion_outcome)) {
                    return abort_terminal(state, &exact, result);
                }
                return publish_skip(
                    state,
                    exact,
                    FK_OWNER_OBSERVATION_SKIP_UNRESOLVED_IDENTITY,
                    false,
                    result);
            }
            if (authenticated_initial.datagram_bytes !=
                    clear_bounds.datagram_bytes ||
                authenticated_initial.authenticated_packet_bytes !=
                    clear_bounds.packet_end_bytes ||
                authenticated_initial.trailing_coalesced_bytes !=
                    clear_bounds.trailing_coalesced_bytes ||
                authenticated_initial.authenticated_packet_bytes !=
                    state.active_crypto_receipt.crypto_input_bytes) {
                (void)checked_add(
                    state, state.counters.initial_auth_rejections);
                result->initial_auth_reason =
                    FK_QUIC_INITIAL_AUTH_REASON_PACKET_LENGTH_INVALID;
                if (!resolve_active_crypto_receipt(
                        state,
                        FK_QUIC_INITIAL_CRYPTO_COMPLETION_DOWNSTREAM_ABORTED)) {
                    return abort_terminal(state, &exact, result);
                }
                return publish_skip(
                    state,
                    exact,
                    FK_OWNER_OBSERVATION_SKIP_UNRESOLVED_IDENTITY,
                    true,
                    result);
            }
            if (!resolve_active_crypto_receipt(
                    state,
                    FK_QUIC_INITIAL_CRYPTO_COMPLETION_AUTHENTICATED)) {
                return abort_terminal(state, &exact, result);
            }
            (void)checked_add(
                state, state.counters.initial_auth_successes);
            fk_quic_header_observation admitted_header{};
            fk_quic_cid_initial_admission_proof proof{};
            uint16_t proposed_owner = UINT16_MAX;
            if (!fk_quic_initial_auth_to_cid_admission(
                    &authenticated_initial,
                    &admitted_header,
                    &proof) ||
                !select_initial_owner(
                    state,
                    authenticated_initial.destination_cid,
                    authenticated_initial.destination_cid_length,
                    proposed_owner)) {
                return publish_skip(
                    state,
                    exact,
                    FK_OWNER_OBSERVATION_SKIP_UNRESOLVED_IDENTITY,
                    true,
                    result);
            }
            const fk_quic_cid_result_code cid_code =
                fk_quic_cid_map_observe_authenticated_initial(
                    state.cid_map,
                    &admitted_header,
                    &proof,
                    exact.semantic_timestamp_ns,
                    exact.ingress_worker,
                    proposed_owner,
                    &resolution);
            record_cid_result(state, cid_code);
            evidence_kind =
                FK_QUIC_ROUTE_EVIDENCE_AUTHENTICATED_INITIAL_DCID;
            placement_context =
                FK_QUIC_ROUTE_PLACEMENT_AUTHENTICATED_REGISTRATION;
            receipt_authentication = &authenticated_initial;
        } else {
            result->packet_kind =
                FK_EXACT_IDENTITY_ROUTER_PACKET_QUIC_LONG;
            (void)checked_add(state, state.counters.quic_long_packets);
            record_cid_result(state, prelookup_code);
            evidence_kind = FK_QUIC_ROUTE_EVIDENCE_EXACT_LONG_HEADER_DCID;
        }
    } else {
        /* Short headers have no self-describing CID boundary.  Probe the
         * bounded active-length index even on a new tuple so a migrated
         * connection can be recognized.  Only a clean UNRESOLVED result on
         * a path never known as QUIC may fall back to ordinary UDP. */
        const fk_quic_cid_result_code cid_code =
            fk_quic_cid_map_resolve_known_short_header(
                state.cid_map,
                view.payload,
                view.payload_size,
                exact.semantic_timestamp_ns,
                exact.ingress_worker,
                &resolution);
        record_cid_result(state, cid_code);
        result->cid_code = resolution.code;
        result->cid_reason = resolution.reason;
        result->resolved_destination_cid_length =
            resolution.resolved_destination_cid_length;
        if (cid_code == FK_QUIC_CID_RESOLVED) {
            result->packet_kind =
                FK_EXACT_IDENTITY_ROUTER_PACKET_QUIC_SHORT;
            (void)checked_add(state, state.counters.quic_short_packets);
            evidence_kind =
                FK_QUIC_ROUTE_EVIDENCE_EXACT_SHORT_HEADER_DCID;
        } else if ((cid_code == FK_QUIC_CID_UNRESOLVED ||
                    cid_code == FK_QUIC_CID_NOT_QUIC) &&
                !known_quic_path) {
            const bool recognizable_supported_long =
                view.payload_size >= 5u &&
                (view.payload[0] & 0xc0u) == 0xc0u &&
                (((static_cast<uint32_t>(view.payload[1]) << 24u) |
                  (static_cast<uint32_t>(view.payload[2]) << 16u) |
                  (static_cast<uint32_t>(view.payload[3]) << 8u) |
                  static_cast<uint32_t>(view.payload[4])) ==
                    FK_QUIC_INITIAL_AUTH_VERSION_V1 ||
                 ((static_cast<uint32_t>(view.payload[1]) << 24u) |
                  (static_cast<uint32_t>(view.payload[2]) << 16u) |
                  (static_cast<uint32_t>(view.payload[3]) << 8u) |
                  static_cast<uint32_t>(view.payload[4])) ==
                    FK_QUIC_INITIAL_AUTH_VERSION_V2);
            if (inspect_code != FK_PARSE_OK &&
                recognizable_supported_long) {
                return publish_skip(
                    state,
                    exact,
                    FK_OWNER_OBSERVATION_SKIP_PARSE_REJECTED,
                    false,
                    result);
            }
            result->packet_kind =
                FK_EXACT_IDENTITY_ROUTER_PACKET_FLOW_KEY_UDP;
            (void)checked_add(state, state.counters.flow_key_udp_packets);
            uint16_t owner = UINT16_MAX;
            if (!select_flow_owner(state, flow_key, owner)) {
                return publish_skip(
                    state,
                    exact,
                    FK_OWNER_OBSERVATION_SKIP_UNRESOLVED_IDENTITY,
                    true,
                    result);
            }
            fk_owner_packet packet{};
            if (!build_owner_packet(
                    exact,
                    owner,
                    FK_OWNER_IDENTITY_FLOW_KEY,
                    0u,
                    0u,
                    0u,
                    packet)) {
                return publish_skip(
                    state,
                    exact,
                    FK_OWNER_OBSERVATION_SKIP_UNRESOLVED_IDENTITY,
                    true,
                    result);
            }
            result->owner_worker = owner;
            return publish_data(state, exact, packet, result);
        } else {
            return publish_skip(
                state,
                exact,
                FK_OWNER_OBSERVATION_SKIP_UNRESOLVED_IDENTITY,
                cid_internal_failure(resolution),
                result);
        }
    }

    result->cid_code = resolution.code;
    result->cid_reason = resolution.reason;
    result->resolved_destination_cid_length =
        resolution.resolved_destination_cid_length;
    if (!cid_success(resolution) ||
        resolution.fixed_owner >= state.config.owner_count) {
        return publish_skip(
            state,
            exact,
            FK_OWNER_OBSERVATION_SKIP_UNRESOLVED_IDENTITY,
            cid_internal_failure(resolution),
            result);
    }

    /* Despite the legacy function name, only AUTHENTICATED_INITIAL may
     * refresh a path.  An EXACT_CID resolution can create one conservative
     * known-QUIC guard on a previously unknown tuple (needed for migration),
     * but an existing guard is deliberately left unrefreshed: a CID match is
     * not endpoint authentication. */
    const bool authenticated_path = placement_context ==
        FK_QUIC_ROUTE_PLACEMENT_AUTHENTICATED_REGISTRATION;
    const bool register_path = authenticated_path ||
        path_code == FK_QUIC_PRESENTATION_PATH_NOT_KNOWN;
    if (register_path) {
        (void)checked_add(state, state.counters.path_register_calls);
        fk_quic_presentation_path_classification registered_path{};
        const fk_quic_presentation_path_code registered =
            fk_quic_presentation_path_directory_register_authenticated(
                state.path_directory,
                resolution.logical_connection_id,
                &flow_key,
                exact.semantic_timestamp_ns,
                &registered_path);
        const bool registration_shape =
            registered_path.registration_created +
                registered_path.registration_refreshed == 1u;
        if (registered == FK_QUIC_PRESENTATION_PATH_REJECTED ||
            registered == FK_QUIC_PRESENTATION_PATH_NOT_KNOWN ||
            !registration_shape ||
            (!authenticated_path &&
             registered_path.registration_created != 1u)) {
            (void)checked_add(
                state, state.counters.path_register_rejections);
            return publish_skip(
                state,
                exact,
                FK_OWNER_OBSERVATION_SKIP_UNRESOLVED_IDENTITY,
                true,
                result);
        }
        if (registered_path.registration_created != 0u) {
            (void)checked_add(
                state, state.counters.path_registrations_created);
        } else {
            (void)checked_add(
                state, state.counters.path_registrations_refreshed);
        }
        if (authenticated_path) {
            (void)checked_add(
                state,
                state.counters.authenticated_initial_path_registrations);
        } else {
            (void)checked_add(
                state, state.counters.exact_cid_guard_registrations);
        }
    } else {
        (void)checked_add(
            state, state.counters.path_registration_skipped_existing);
    }

    fk_owner_packet packet{};
    if (!build_owner_packet(
            exact,
            resolution.fixed_owner,
            FK_OWNER_IDENTITY_QUIC_LOGICAL,
            resolution.logical_connection_id,
            resolution.feature_direction,
            resolution.feature_direction_known,
            packet)) {
        return publish_skip(
            state,
            exact,
            FK_OWNER_OBSERVATION_SKIP_UNRESOLVED_IDENTITY,
            true,
            result);
    }
    fk_quic_route_receipt_bridge_request request{};
    request.packet = &packet;
    request.packet_view = &view;
    request.authenticated_initial = receipt_authentication;
    request.evidence_kind = evidence_kind;
    request.placement_context = placement_context;
    request.fixed_owner_context = resolution.code == FK_QUIC_CID_CREATED
        ? FK_QUIC_ROUTE_FIXED_OWNER_CREATED
        : FK_QUIC_ROUTE_FIXED_OWNER_ACTIVE;
    request.resolved_short_dcid_length =
        evidence_kind == FK_QUIC_ROUTE_EVIDENCE_EXACT_SHORT_HEADER_DCID
        ? resolution.resolved_destination_cid_length : 0u;
    (void)checked_add(
        state, state.counters.route_receipt_issue_attempts);
    const fk_quic_route_receipt_result receipt_result =
        fk_quic_route_receipt_bridge_issue(
            state.route_receipts,
            &request,
            &packet.route_receipt);
    if (receipt_result != FK_QUIC_ROUTE_RECEIPT_ACCEPTED) {
        (void)checked_add(
            state, state.counters.route_receipt_rejections);
        return publish_skip(
            state,
            exact,
            FK_OWNER_OBSERVATION_SKIP_UNRESOLVED_IDENTITY,
            true,
            result);
    }
    (void)checked_add(state, state.counters.route_receipts_issued);
    result->logical_connection_id = resolution.logical_connection_id;
    result->owner_worker = resolution.fixed_owner;
    result->feature_direction = resolution.feature_direction;
    result->feature_direction_known =
        resolution.feature_direction_known;
    result->route_evidence_kind = static_cast<uint8_t>(evidence_kind);
    result->route_placement_context =
        static_cast<uint8_t>(placement_context);
    return publish_data(state, exact, packet, result);
}

fk_exact_identity_router_abort_pending_result
fk_exact_identity_router_abort_pending(
        fk_exact_identity_router *router,
        const fk_exact_identity_packet *exact_packet) {
    if (router == nullptr || exact_packet == nullptr)
        return FK_EXACT_IDENTITY_ROUTER_ABORT_PENDING_INVALID;
    RouterImpl &state = *implementation(router);
    if (state.magic != kMagic || state.initialized == 0u)
        return FK_EXACT_IDENTITY_ROUTER_ABORT_PENDING_INVALID;
    if (!identity_thread(state)) {
        state.abort_pending_wrong_thread_calls.fetch_add(
            1u, std::memory_order_relaxed);
        return FK_EXACT_IDENTITY_ROUTER_ABORT_PENDING_NOT_IDENTITY_THREAD;
    }
    if (!exact_packet_valid(state, exact_packet))
        return FK_EXACT_IDENTITY_ROUTER_ABORT_PENDING_INVALID;
    (void)checked_add(state, state.counters.abort_pending_attempts);
    if (state.last_abort_valid != 0u &&
        exact_packet_equal(state.last_aborted_packet, *exact_packet)) {
        (void)checked_add(
            state, state.counters.abort_pending_already_recorded);
        return FK_EXACT_IDENTITY_ROUTER_ABORT_PENDING_ALREADY_RECORDED;
    }
    if (state.reservation_live == 0u ||
        (state.prepared_kind == PreparedKind::None &&
         state.terminal_pending_global_abort == 0u)) {
        (void)checked_add(state, state.counters.abort_pending_none);
        return FK_EXACT_IDENTITY_ROUTER_ABORT_PENDING_NONE;
    }
    if (!exact_packet_equal(state.reserved_packet, *exact_packet)) {
        mark_sticky(state);
        (void)checked_add(
            state, state.counters.abort_pending_descriptor_mismatches);
        return FK_EXACT_IDENTITY_ROUTER_ABORT_PENDING_DESCRIPTOR_MISMATCH;
    }

    (void)checked_add(state, state.counters.completion_abort_attempts);
    const fk_owner_reserved_abort_result aborted =
        fk_owner_output_sequence_bridge_abort_reserved(
            state.completion_bridge,
            exact_packet->packet_sequence,
            FK_OWNER_RESERVED_ABORT_ROUTER_TERMINAL);
    if (aborted != FK_OWNER_RESERVED_ABORT_RECORDED &&
        aborted != FK_OWNER_RESERVED_ABORT_ALREADY_RECORDED) {
        mark_sticky(state);
        (void)checked_add(
            state, state.counters.completion_abort_rejections);
        (void)checked_add(
            state, state.counters.abort_pending_bridge_rejections);
        return FK_EXACT_IDENTITY_ROUTER_ABORT_PENDING_BRIDGE_REJECTED;
    }
    (void)checked_add(state, state.counters.completion_aborts_recorded);
    state.last_aborted_packet = state.reserved_packet;
    state.last_abort_valid = 1u;
    state.reservation_live = 0u;
    state.reserved_packet = {};
    state.terminal_pending_result = {};
    state.terminal_pending_global_abort = 0u;
    clear_prepared(state, PreparedClearDisposition::DirectAbort);
    mark_sticky(state);
    if (aborted == FK_OWNER_RESERVED_ABORT_ALREADY_RECORDED) {
        (void)checked_add(
            state, state.counters.abort_pending_already_recorded);
        return FK_EXACT_IDENTITY_ROUTER_ABORT_PENDING_ALREADY_RECORDED;
    }
    (void)checked_add(state, state.counters.abort_pending_recorded);
    return FK_EXACT_IDENTITY_ROUTER_ABORT_PENDING_RECORDED;
}

fk_exact_identity_router_detach_pending_result
fk_exact_identity_router_detach_pending_for_global_abort(
        fk_exact_identity_router *router,
        const fk_exact_identity_packet *exact_packet,
        fk_exact_identity_router_detach_receipt_v1 *receipt) {
    if (receipt != nullptr)
        *receipt = {};
    if (router == nullptr || exact_packet == nullptr || receipt == nullptr)
        return FK_EXACT_IDENTITY_ROUTER_DETACH_PENDING_INVALID;
    RouterImpl &state = *implementation(router);
    if (state.magic != kMagic || state.initialized == 0u)
        return FK_EXACT_IDENTITY_ROUTER_DETACH_PENDING_INVALID;
    if (!identity_thread(state)) {
        state.detach_pending_wrong_thread_calls.fetch_add(
            1u, std::memory_order_relaxed);
        return
            FK_EXACT_IDENTITY_ROUTER_DETACH_PENDING_NOT_IDENTITY_THREAD;
    }
    if (!exact_packet_valid(state, exact_packet))
        return FK_EXACT_IDENTITY_ROUTER_DETACH_PENDING_INVALID;
    (void)checked_add(state, state.counters.detach_pending_attempts);

    if (state.detached_global_abort != 0u) {
        if (!exact_packet_equal(
                state.detached_receipt.descriptor, *exact_packet)) {
            mark_sticky(state);
            (void)checked_add(
                state,
                state.counters.detach_pending_descriptor_mismatches);
            return FK_EXACT_IDENTITY_ROUTER_DETACH_PENDING_DESCRIPTOR_MISMATCH;
        }
        *receipt = state.detached_receipt;
        (void)checked_add(
            state, state.counters.detach_pending_already_detached);
        return FK_EXACT_IDENTITY_ROUTER_DETACH_PENDING_ALREADY_DETACHED;
    }
    if (state.reservation_live == 0u ||
        (state.prepared_kind == PreparedKind::None &&
         state.terminal_pending_global_abort == 0u)) {
        /* A one-sided prepared/reservation state is an integrity failure, but
         * there is still no safe candidate that this API may detach. */
        if ((state.reservation_live != 0u) !=
            (state.prepared_kind != PreparedKind::None ||
             state.terminal_pending_global_abort != 0u)) {
            mark_sticky(state);
        }
        (void)checked_add(state, state.counters.detach_pending_none);
        return FK_EXACT_IDENTITY_ROUTER_DETACH_PENDING_NONE;
    }
    if (!exact_packet_equal(state.reserved_packet, *exact_packet)) {
        mark_sticky(state);
        (void)checked_add(
            state,
            state.counters.detach_pending_descriptor_mismatches);
        return FK_EXACT_IDENTITY_ROUTER_DETACH_PENDING_DESCRIPTOR_MISMATCH;
    }

    fk_exact_identity_router_detach_receipt_v1 frozen{};
    frozen.abi_version =
        FK_EXACT_IDENTITY_ROUTER_DETACH_RECEIPT_ABI_VERSION;
    frozen.prepared_kind = state.terminal_pending_global_abort != 0u
        ? static_cast<uint32_t>(
              FK_EXACT_IDENTITY_ROUTER_DETACH_KIND_TERMINAL_PENDING)
        : static_cast<uint32_t>(state.prepared_kind);
    frozen.receipt_ordinal = 1u;
    frozen.descriptor = state.reserved_packet;
    frozen.bridge_reservation_left_active = 1u;
    state.detached_receipt = frozen;
    state.detached_global_abort = 1u;
    state.reservation_live = 0u;
    state.reserved_packet = {};
    state.terminal_pending_result = {};
    state.terminal_pending_global_abort = 0u;
    clear_prepared(
        state, PreparedClearDisposition::DetachedGlobalAbort);
    mark_sticky(state);
    (void)checked_add(state, state.counters.detach_pending_detached);
    *receipt = frozen;
    return FK_EXACT_IDENTITY_ROUTER_DETACH_PENDING_DETACHED;
}

bool fk_exact_identity_router_accounting_conserved(
        const fk_exact_identity_router *router) {
    if (router == nullptr)
        return false;
    const RouterImpl &state = *implementation(router);
    if (state.magic != kMagic || state.initialized == 0u)
        return false;
    const auto &s = state.counters;
    const auto sum_equals = [](uint64_t expected,
                               const uint64_t *values,
                               size_t count) {
        uint64_t sum = 0u;
        for (size_t index = 0u; index < count; ++index) {
            if (values[index] >
                std::numeric_limits<uint64_t>::max() - sum) {
                return false;
            }
            sum += values[index];
        }
        return sum == expected;
    };
    const uint64_t outcomes[]{
        s.data_committed_transfers,
        s.skip_committed_reclaims,
        s.backpressure_retentions,
        s.terminal_reclaim_aborts,
        s.terminal_pending_global_aborts,
    };
    const uint64_t resolver_partition[]{
        s.resolver_successes,
        s.resolver_rejections,
    };
    const uint64_t authentication_partition[]{
        s.initial_auth_successes,
        s.initial_auth_rejections,
    };
    const uint64_t clear_bounds_partition[]{
        s.initial_clear_bounds_candidates,
        s.initial_clear_bounds_rejections,
    };
    const uint64_t crypto_gate_begin_partition[]{
        s.initial_crypto_gate_allows,
        s.initial_crypto_gate_rejections,
    };
    const uint64_t crypto_gate_completion_partition[]{
        s.initial_crypto_gate_completions,
        s.initial_crypto_gate_completion_rejections,
    };
    const uint64_t receipt_partition[]{
        s.route_receipts_issued,
        s.route_receipt_rejections,
    };
    const uint64_t reservation_partition[]{
        s.completion_reservations,
        s.completion_idempotent_reservations,
        s.completion_reservation_backpressure,
        s.completion_reservation_rejections,
    };
    const uint64_t route_bind_partition[]{
        s.completion_routes_bound,
        s.completion_route_idempotent_bindings,
        s.completion_route_bind_rejections,
    };
    const uint64_t skip_completion_partition[]{
        s.skip_completions_published,
        s.skip_completion_publish_rejections,
    };
    const uint64_t claim_partition[]{
        state.identity_thread_claim_successes.load(
            std::memory_order_acquire),
        state.identity_thread_claim_rejections.load(
            std::memory_order_acquire),
    };
    const uint64_t prepared_partition[]{
        s.prepared_data_transactions,
        s.prepared_skip_transactions,
    };
    const uint64_t prepared_retry_partition[]{
        s.prepared_data_retries,
        s.prepared_skip_retries,
    };
    const uint64_t abort_pending_partition[]{
        s.abort_pending_recorded,
        s.abort_pending_already_recorded,
        s.abort_pending_none,
        s.abort_pending_descriptor_mismatches,
        s.abort_pending_bridge_rejections,
    };
    const uint64_t prepared_live =
        state.prepared_kind == PreparedKind::None ? 0u : 1u;
    const uint64_t prepared_lifetime_partition[]{
        s.prepared_transactions_cleared,
        prepared_live,
    };
    const uint64_t prepared_clear_partition[]{
        s.prepared_transactions_normal_cleared,
        s.prepared_transactions_abort_pending_cleared,
        s.prepared_transactions_detached_global,
    };
    const uint64_t detach_pending_partition[]{
        s.detach_pending_detached,
        s.detach_pending_already_detached,
        s.detach_pending_none,
        s.detach_pending_descriptor_mismatches,
    };
    return parser_reason_partition_conserved(s) &&
        sum_equals(
            s.process_attempts,
            outcomes,
            sizeof(outcomes) / sizeof(outcomes[0])) &&
        sum_equals(
            s.resolver_attempts,
            resolver_partition,
            sizeof(resolver_partition) / sizeof(resolver_partition[0])) &&
        sum_equals(
            s.initial_auth_attempts,
            authentication_partition,
            sizeof(authentication_partition) /
                sizeof(authentication_partition[0])) &&
        sum_equals(
            s.initial_clear_bounds_inspections,
            clear_bounds_partition,
            sizeof(clear_bounds_partition) /
                sizeof(clear_bounds_partition[0])) &&
        sum_equals(
            s.initial_crypto_gate_begin_attempts,
            crypto_gate_begin_partition,
            sizeof(crypto_gate_begin_partition) /
                sizeof(crypto_gate_begin_partition[0])) &&
        sum_equals(
            s.initial_crypto_gate_completion_attempts,
            crypto_gate_completion_partition,
            sizeof(crypto_gate_completion_partition) /
                sizeof(crypto_gate_completion_partition[0])) &&
        s.initial_crypto_gate_allows == s.initial_auth_attempts &&
        s.initial_crypto_gate_allows ==
            s.initial_crypto_gate_completion_attempts &&
        sum_equals(
            s.route_receipt_issue_attempts,
            receipt_partition,
            sizeof(receipt_partition) / sizeof(receipt_partition[0])) &&
        sum_equals(
            s.completion_reservation_attempts,
            reservation_partition,
            sizeof(reservation_partition) /
                sizeof(reservation_partition[0])) &&
        sum_equals(
            s.completion_route_bind_attempts,
            route_bind_partition,
            sizeof(route_bind_partition) / sizeof(route_bind_partition[0])) &&
        sum_equals(
            s.skip_completion_publish_attempts,
            skip_completion_partition,
            sizeof(skip_completion_partition) /
                sizeof(skip_completion_partition[0])) &&
        sum_equals(
            state.identity_thread_claim_attempts.load(
                std::memory_order_acquire),
            claim_partition,
            sizeof(claim_partition) / sizeof(claim_partition[0])) &&
        sum_equals(
            s.prepared_transactions,
            prepared_partition,
            sizeof(prepared_partition) / sizeof(prepared_partition[0])) &&
        sum_equals(
            s.prepared_retry_attempts,
            prepared_retry_partition,
            sizeof(prepared_retry_partition) /
                sizeof(prepared_retry_partition[0])) &&
        s.prepared_retry_resolver_bypasses ==
            s.prepared_retry_attempts &&
        sum_equals(
            s.abort_pending_attempts,
            abort_pending_partition,
            sizeof(abort_pending_partition) /
                sizeof(abort_pending_partition[0])) &&
        sum_equals(
            s.prepared_transactions,
            prepared_lifetime_partition,
            sizeof(prepared_lifetime_partition) /
                sizeof(prepared_lifetime_partition[0])) &&
        sum_equals(
            s.prepared_transactions_cleared,
            prepared_clear_partition,
            sizeof(prepared_clear_partition) /
                sizeof(prepared_clear_partition[0])) &&
        sum_equals(
            s.detach_pending_attempts,
            detach_pending_partition,
            sizeof(detach_pending_partition) /
                sizeof(detach_pending_partition[0])) &&
        s.prepared_transactions_detached_global <=
            s.detach_pending_detached &&
        (state.detached_global_abort == 0u ||
         (state.detached_receipt.abi_version ==
              FK_EXACT_IDENTITY_ROUTER_DETACH_RECEIPT_ABI_VERSION &&
          state.detached_receipt.bridge_reservation_left_active == 1u)) &&
        (state.terminal_pending_global_abort == 0u ||
         (state.reservation_live != 0u &&
          state.terminal_pending_result.outcome ==
              FK_EXACT_IDENTITY_ROUTER_TERMINAL_PENDING_GLOBAL_ABORT)) &&
        (state.reservation_live == 0u ||
         state.prepared_kind != PreparedKind::None ||
         state.terminal_pending_global_abort != 0u) &&
        state.active_crypto_receipt_live == 0u &&
        s.path_register_calls ==
            s.authenticated_initial_path_registrations +
            s.exact_cid_guard_registrations +
            s.path_register_rejections &&
        s.path_registrations_created +
            s.path_registrations_refreshed ==
            s.authenticated_initial_path_registrations +
            s.exact_cid_guard_registrations &&
        s.completion_aborts_recorded +
            s.completion_abort_rejections ==
            s.completion_abort_attempts &&
        state.identity_thread_claim_successes.load(
            std::memory_order_acquire) <= 1u &&
        s.reserved_bytes == sizeof(RouterImpl);
}

bool fk_exact_identity_router_get_stats(
        const fk_exact_identity_router *router,
        fk_exact_identity_router_stats *stats) {
    if (router == nullptr || stats == nullptr)
        return false;
    const RouterImpl &state = *implementation(router);
    if (state.magic != kMagic || state.initialized == 0u)
        return false;
    *stats = state.counters;
    stats->reserved_bytes = sizeof(RouterImpl);
    stats->identity_thread_claim_attempts =
        state.identity_thread_claim_attempts.load(std::memory_order_acquire);
    stats->identity_thread_claim_successes =
        state.identity_thread_claim_successes.load(std::memory_order_acquire);
    stats->identity_thread_claim_rejections =
        state.identity_thread_claim_rejections.load(std::memory_order_acquire);
    stats->identity_thread_call_rejections =
        state.identity_thread_call_rejections.load(std::memory_order_acquire);
    stats->abort_pending_wrong_thread =
        state.abort_pending_wrong_thread_calls.load(
            std::memory_order_acquire);
    stats->detach_pending_wrong_thread =
        state.detach_pending_wrong_thread_calls.load(
            std::memory_order_acquire);
    stats->abi_version = FK_EXACT_IDENTITY_ROUTER_ABI_VERSION;
    stats->owner_count = state.config.owner_count;
    stats->initialized = state.initialized;
    stats->identity_thread_claimed =
        state.identity_thread_token.load(std::memory_order_acquire) != 0u
        ? 1u : 0u;
    stats->sticky_failure = state.sticky_failure;
    stats->prepared_transaction =
        state.prepared_kind == PreparedKind::None ? 0u : 1u;
    stats->detached_global_abort = state.detached_global_abort;
    stats->terminal_pending_global_abort =
        state.terminal_pending_global_abort;
    stats->parser_reason_conserved =
        parser_reason_partition_conserved(*stats) ? 1u : 0u;
    stats->accounting_conserved =
        fk_exact_identity_router_accounting_conserved(router) ? 1u : 0u;
    return true;
}

bool fk_exact_identity_router_destroy_checked(
        fk_exact_identity_router *router) {
    if (router == nullptr)
        return false;
    RouterImpl &state = *implementation(router);
    if (state.magic != kMagic || state.initialized == 0u ||
        state.reservation_live != 0u ||
        state.prepared_kind != PreparedKind::None ||
        state.terminal_pending_global_abort != 0u ||
        state.active_crypto_receipt_live != 0u)
        return false;
    if (state.detached_global_abort != 0u) {
        fk_owner_output_sequence_bridge_stats bridge_stats{};
        fk_owner_reserved_abort_receipt_v1 bridge_receipt{};
        if (!fk_owner_output_sequence_bridge_get_stats(
                state.completion_bridge, &bridge_stats) ||
            !fk_owner_output_sequence_bridge_get_abort_receipt(
                state.completion_bridge, &bridge_receipt) ||
            !bridge_stats.terminal_failure ||
            !bridge_stats.abort_receipt_present ||
            !bridge_stats.abort_cleanup_done ||
            bridge_stats.active_reservations != 0u) {
            (void)checked_add(
                state,
                state.counters
                    .detached_destroy_bridge_not_clean_rejections);
            return false;
        }
    }
    state.initialized = 0u;
    state.magic = 0u;
    state.~RouterImpl();
    return true;
}

}  // extern "C"

extern "C" {

void fk_exact_identity_router_default_config_init(
        fk_exact_identity_router_config *config) {
    if (config == nullptr)
        return;
    *config = {};
    config->abi_version = FK_EXACT_IDENTITY_ROUTER_ABI_VERSION;
    config->owner_count = 8u;
}

bool fk_exact_identity_router_config_valid(
        const fk_exact_identity_router_config *config) {
    return config_valid(config);
}

size_t fk_exact_identity_router_storage_bytes(
        const fk_exact_identity_router_config *config) {
    return config_valid(config) ? sizeof(RouterImpl) : 0u;
}

fk_exact_identity_router *fk_exact_identity_router_initialize(
        void *storage,
        size_t storage_bytes,
        const fk_exact_identity_router_config *config,
        const fk_exact_identity_packet_bytes_resolver *resolver,
        fk_quic_cid_map *cid_map,
        fk_quic_presentation_path_directory *path_directory,
        fk_owner_dispatch *dispatch,
        fk_quic_route_receipt_state *route_receipts,
        fk_quic_retirement_publisher *retirement_publisher,
        fk_owner_output_sequence_bridge *completion_bridge,
        fk_quic_initial_crypto_admission_gate *initial_crypto_gate,
        void *monotonic_clock_context,
        fk_exact_identity_router_monotonic_now_ns_callback monotonic_now_ns,
        char *error,
        size_t error_capacity) {
    set_error(error, error_capacity, "");
    if (storage == nullptr || storage_bytes < sizeof(RouterImpl) ||
        reinterpret_cast<uintptr_t>(storage) % alignof(max_align_t) != 0u ||
        !config_valid(config) || !resolver_valid(resolver) ||
        cid_map == nullptr || path_directory == nullptr ||
        dispatch == nullptr || route_receipts == nullptr ||
        retirement_publisher == nullptr || completion_bridge == nullptr) {
        set_error(error, error_capacity,
            "invalid exact identity router placement or dependency");
        return nullptr;
    }
    if (initial_crypto_gate == nullptr) {
        set_error(error, error_capacity,
            "missing exact identity router Initial crypto gate");
        return nullptr;
    }
    if (monotonic_now_ns == nullptr) {
        set_error(error, error_capacity,
            "missing exact identity router monotonic clock callback");
        return nullptr;
    }
    if (!topology_matches(
            *config,
            cid_map,
            dispatch,
            route_receipts,
            retirement_publisher,
            completion_bridge)) {
        set_error(error, error_capacity,
            "exact identity router owner topology mismatch");
        return nullptr;
    }
    auto *state = new (storage) RouterImpl{};
    state->magic = kMagic;
    state->config = *config;
    state->resolver = *resolver;
    state->cid_map = cid_map;
    state->path_directory = path_directory;
    state->dispatch = dispatch;
    state->route_receipts = route_receipts;
    state->retirement_publisher = retirement_publisher;
    state->completion_bridge = completion_bridge;
    state->initial_crypto_gate = initial_crypto_gate;
    state->monotonic_clock_context = monotonic_clock_context;
    state->monotonic_now_ns = monotonic_now_ns;
    state->counters.reserved_bytes = sizeof(RouterImpl);
    state->counters.abi_version = FK_EXACT_IDENTITY_ROUTER_ABI_VERSION;
    state->counters.owner_count = config->owner_count;
    state->initialized = 1u;
    return reinterpret_cast<fk_exact_identity_router *>(state);
}

bool fk_exact_identity_router_claim_identity_thread(
        fk_exact_identity_router *router) {
    if (router == nullptr)
        return false;
    RouterImpl &state = *implementation(router);
    state.identity_thread_claim_attempts.fetch_add(
        1u, std::memory_order_relaxed);
    if (state.magic != kMagic || state.initialized == 0u) {
        state.identity_thread_claim_rejections.fetch_add(
            1u, std::memory_order_relaxed);
        return false;
    }
    const uint64_t token = current_thread_token();
    uint64_t expected = 0u;
    if (token == 0u || !state.identity_thread_token.compare_exchange_strong(
            expected,
            token,
            std::memory_order_acq_rel,
            std::memory_order_acquire)) {
        state.identity_thread_claim_rejections.fetch_add(
            1u, std::memory_order_relaxed);
        return false;
    }
    if (!fk_quic_initial_crypto_admission_gate_claim_owner(
            state.initial_crypto_gate)) {
        mark_sticky(state);
        state.identity_thread_claim_rejections.fetch_add(
            1u, std::memory_order_relaxed);
        return false;
    }
    state.identity_thread_claim_successes.fetch_add(
        1u, std::memory_order_relaxed);
    return true;
}

}  // extern "C"

namespace {

fk_exact_identity_router_outcome abort_terminal(
        RouterImpl &state,
        const fk_exact_identity_packet *packet,
    fk_exact_identity_router_result *result) {
    if (state.active_crypto_receipt_live != 0u) {
        (void)resolve_active_crypto_receipt(
            state,
            FK_QUIC_INITIAL_CRYPTO_COMPLETION_DOWNSTREAM_ABORTED);
    }
    mark_sticky(state);
    if (state.terminal_pending_global_abort != 0u) {
        if (packet != nullptr &&
            exact_packet_equal(state.reserved_packet, *packet)) {
            if (result != nullptr)
                *result = state.terminal_pending_result;
            return finish_outcome(
                state,
                FK_EXACT_IDENTITY_ROUTER_TERMINAL_PENDING_GLOBAL_ABORT,
                result);
        }
        return finish_outcome(
            state,
            FK_EXACT_IDENTITY_ROUTER_TERMINAL_RECLAIM_ABORT,
            result);
    }
    if (state.reservation_live != 0u) {
        /* Multi-owner phase one: freezing a candidate is intentionally not
         * a bridge abort.  The global coordinator is the sole component that
         * may create the first-loss receipt and clean every participant. */
        state.terminal_pending_global_abort = 1u;
        const fk_exact_identity_router_outcome outcome = finish_outcome(
            state,
            FK_EXACT_IDENTITY_ROUTER_TERMINAL_PENDING_GLOBAL_ABORT,
            result);
        state.terminal_pending_result = result != nullptr
            ? *result : fk_exact_identity_router_result{};
        state.terminal_pending_result.outcome = outcome;
        return outcome;
    } else if (packet != nullptr) {
        /* No credit was acquired, so there is deliberately no synthetic
         * abort receipt to create for this packet. */
        (void)packet;
    }
    clear_prepared(state, PreparedClearDisposition::DirectAbort);
    return finish_outcome(
        state,
        FK_EXACT_IDENTITY_ROUTER_TERMINAL_RECLAIM_ABORT,
        result);
}

fk_exact_identity_router_outcome reserve_completion_credit(
        RouterImpl &state,
        const fk_exact_identity_packet &packet,
        fk_exact_identity_router_result *result,
        bool &ready) {
    ready = false;
    if (!checked_add(
            state, state.counters.completion_reservation_attempts))
        return abort_terminal(state, &packet, result);
    const fk_owner_packet_reservation_result reserved =
        fk_owner_output_sequence_bridge_reserve_next(
            state.completion_bridge, packet.packet_sequence);
    if (reserved == FK_OWNER_PACKET_RESERVATION_FULL) {
        (void)checked_add(
            state, state.counters.completion_reservation_backpressure);
        return finish_outcome(
            state,
            FK_EXACT_IDENTITY_ROUTER_BACKPRESSURE_RETAIN,
            result);
    }
    if (reserved == FK_OWNER_PACKET_RESERVED) {
        if (state.reservation_live != 0u)
            return abort_terminal(state, &packet, result);
        state.reserved_packet = packet;
        state.reservation_live = 1u;
        (void)checked_add(state, state.counters.completion_reservations);
        ready = true;
        return FK_EXACT_IDENTITY_ROUTER_INVALID;
    }
    if (reserved == FK_OWNER_PACKET_ALREADY_RESERVED) {
        (void)checked_add(
            state, state.counters.completion_idempotent_reservations);
        if (state.reservation_live == 0u ||
            !exact_packet_equal(state.reserved_packet, packet)) {
            return abort_terminal(state, &packet, result);
        }
        ready = true;
        return FK_EXACT_IDENTITY_ROUTER_INVALID;
    }
    (void)checked_add(
        state, state.counters.completion_reservation_rejections);
    return abort_terminal(state, &packet, result);
}

bool bind_reserved_route(
        RouterImpl &state,
        uint64_t packet_sequence,
        uint16_t expected_owner,
        fk_owner_reserved_route_kind route_kind) {
    fk_owner_reserved_route_v1 route{};
    route.packet_sequence = packet_sequence;
    route.expected_owner = expected_owner;
    route.route_kind = static_cast<uint8_t>(route_kind);
    if (!checked_add(
            state, state.counters.completion_route_bind_attempts))
        return false;
    const fk_owner_reserved_route_bind_result bound =
        fk_owner_output_sequence_bridge_bind_reserved_route(
            state.completion_bridge, &route);
    if (bound == FK_OWNER_RESERVED_ROUTE_BOUND) {
        (void)checked_add(state, state.counters.completion_routes_bound);
        return true;
    }
    if (bound == FK_OWNER_RESERVED_ROUTE_ALREADY_BOUND) {
        (void)checked_add(
            state, state.counters.completion_route_idempotent_bindings);
        return true;
    }
    (void)checked_add(
        state, state.counters.completion_route_bind_rejections);
    return false;
}

bool publish_skip_completion(
        RouterImpl &state,
        uint64_t packet_sequence) {
    fk_owner_packet_completion_v1 completion{};
    completion.packet_sequence = packet_sequence;
    completion.fixed_owner = FK_OWNER_OUTPUT_SEQUENCE_BRIDGE_SKIP_OWNER;
    completion.completion_kind = FK_OWNER_PACKET_COMPLETION_ORDERED_SKIP;
    if (!checked_add(
            state, state.counters.skip_completion_publish_attempts))
        return false;
    const fk_owner_packet_completion_publish_result published =
        fk_owner_output_sequence_bridge_publish_completion_after_commit_ack(
            state.completion_bridge, &completion);
    if (published != FK_OWNER_PACKET_COMPLETION_PUBLISHED) {
        (void)checked_add(
            state, state.counters.skip_completion_publish_rejections);
        return false;
    }
    (void)checked_add(state, state.counters.skip_completions_published);
    state.reservation_live = 0u;
    state.reserved_packet = {};
    return true;
}

void clear_prepared(
        RouterImpl &state,
        PreparedClearDisposition disposition) {
    if (state.prepared_kind == PreparedKind::None)
        return;
    (void)checked_add(
        state, state.counters.prepared_transactions_cleared);
    switch (disposition) {
    case PreparedClearDisposition::Normal:
        (void)checked_add(
            state,
            state.counters.prepared_transactions_normal_cleared);
        break;
    case PreparedClearDisposition::DirectAbort:
        (void)checked_add(
            state,
            state.counters.prepared_transactions_abort_pending_cleared);
        break;
    case PreparedClearDisposition::DetachedGlobalAbort:
        (void)checked_add(
            state,
            state.counters.prepared_transactions_detached_global);
        break;
    }
    state.prepared_data_packet = {};
    state.prepared_result = {};
    state.prepared_skip_reason = FK_OWNER_OBSERVATION_SKIP_FILTERED;
    state.prepared_kind = PreparedKind::None;
    state.prepared_terminal_after_commit = 0u;
}

bool prepare_data(
        RouterImpl &state,
        const fk_owner_packet &packet,
        const fk_exact_identity_router_result *result) {
    if (state.prepared_kind != PreparedKind::None || result == nullptr)
        return false;
    if (!checked_add(state, state.counters.prepared_transactions) ||
        !checked_add(state, state.counters.prepared_data_transactions)) {
        return false;
    }
    state.prepared_data_packet = packet;
    state.prepared_result = *result;
    state.prepared_result.outcome = FK_EXACT_IDENTITY_ROUTER_INVALID;
    state.prepared_result.publisher_result =
        FK_QUIC_RETIREMENT_PUBLISHER_INVALID;
    state.prepared_kind = PreparedKind::Data;
    return true;
}

bool prepare_skip(
        RouterImpl &state,
        fk_owner_observation_skip_reason reason,
        bool terminal_after_commit,
        const fk_exact_identity_router_result *result) {
    if (state.prepared_kind != PreparedKind::None || result == nullptr)
        return false;
    if (!checked_add(state, state.counters.prepared_transactions) ||
        !checked_add(state, state.counters.prepared_skip_transactions)) {
        return false;
    }
    state.prepared_result = *result;
    state.prepared_result.outcome = FK_EXACT_IDENTITY_ROUTER_INVALID;
    state.prepared_result.publisher_result =
        FK_QUIC_RETIREMENT_PUBLISHER_INVALID;
    state.prepared_skip_reason = reason;
    state.prepared_terminal_after_commit =
        terminal_after_commit ? 1u : 0u;
    state.prepared_kind = PreparedKind::Skip;
    return true;
}

fk_exact_identity_router_outcome publish_prepared(
        RouterImpl &state,
        fk_exact_identity_router_result *result) {
    if (result == nullptr || state.prepared_kind == PreparedKind::None)
        return abort_terminal(state, &state.reserved_packet, result);

    if (state.prepared_kind == PreparedKind::Data) {
        fk_owner_dispatch_owner_stats owner_stats{};
        if (!fk_owner_dispatch_get_owner_stats(
                state.dispatch,
                state.prepared_data_packet.owner_worker,
                &owner_stats)) {
            return abort_terminal(state, &state.reserved_packet, result);
        }
        /* Avoid invoking the retirement transaction when the DATA queue is
         * observably full. Besides saving work, this prevents repeated
         * retirement peek/rollback bookkeeping from making CID evidence
         * depend on how many times the same packet encountered pressure. */
        if (owner_stats.depth >= owner_stats.queue_capacity) {
            (void)checked_add(
                state,
                state.counters
                    .prepared_data_queue_preflight_backpressure);
            result->publisher_result =
                FK_QUIC_RETIREMENT_PUBLISHER_DISPATCH_QUEUE_FULL;
            return finish_outcome(
                state,
                FK_EXACT_IDENTITY_ROUTER_BACKPRESSURE_RETAIN,
                result);
        }
        (void)checked_add(state, state.counters.publisher_data_calls);
        const fk_quic_retirement_publisher_result published =
            fk_quic_retirement_publisher_submit_data_observation(
                state.retirement_publisher,
                state.prepared_data_packet.ingress_worker,
                state.prepared_data_packet.owner_worker,
                &state.prepared_data_packet);
        result->publisher_result = published;
        if (published == FK_QUIC_RETIREMENT_PUBLISHER_DATA_COMMITTED) {
            if (quic_packet_kind(state.prepared_result.packet_kind)) {
                (void)checked_add(
                    state,
                    state.counters.quic_data_committed_transfers);
            }
            /* The bridge credit remains live for the fixed owner. Only the
             * router retry binding and immutable prepared copy are cleared. */
            state.reservation_live = 0u;
            state.reserved_packet = {};
            clear_prepared(state, PreparedClearDisposition::Normal);
            return finish_outcome(
                state,
                FK_EXACT_IDENTITY_ROUTER_DATA_COMMITTED_TRANSFER,
                result);
        }
        if (published == FK_QUIC_RETIREMENT_PUBLISHER_DISPATCH_QUEUE_FULL) {
            return finish_outcome(
                state,
                FK_EXACT_IDENTITY_ROUTER_BACKPRESSURE_RETAIN,
                result);
        }
        return abort_terminal(state, &state.reserved_packet, result);
    }

    (void)checked_add(state, state.counters.publisher_skip_calls);
    const fk_quic_retirement_publisher_result published =
        fk_quic_retirement_publisher_submit_skipped_observation(
            state.retirement_publisher,
            state.reserved_packet.packet_sequence,
            state.prepared_skip_reason);
    result->publisher_result = published;
    if (published == FK_QUIC_RETIREMENT_PUBLISHER_DISPATCH_QUEUE_FULL) {
        return finish_outcome(
            state,
            FK_EXACT_IDENTITY_ROUTER_BACKPRESSURE_RETAIN,
            result);
    }
    if (published != FK_QUIC_RETIREMENT_PUBLISHER_SKIP_COMMITTED)
        return abort_terminal(state, &state.reserved_packet, result);
    const bool terminal_after_commit =
        state.prepared_terminal_after_commit != 0u;
    const fk_exact_identity_packet exact = state.reserved_packet;
    if (!publish_skip_completion(state, exact.packet_sequence))
        return abort_terminal(state, &exact, result);
    if (quic_packet_kind(state.prepared_result.packet_kind)) {
        (void)checked_add(
            state,
            state.counters.quic_skip_committed_reclaims);
    }
    clear_prepared(state, PreparedClearDisposition::Normal);
    if (terminal_after_commit)
        return abort_terminal(state, &exact, result);
    return finish_outcome(
        state,
        FK_EXACT_IDENTITY_ROUTER_SKIP_COMMITTED_RECLAIM,
        result);
}

fk_exact_identity_router_outcome publish_skip(
        RouterImpl &state,
        const fk_exact_identity_packet &packet,
        fk_owner_observation_skip_reason reason,
    bool terminal_after_commit,
    fk_exact_identity_router_result *result) {
    if (result != nullptr) {
        if (result->packet_kind == FK_EXACT_IDENTITY_ROUTER_PACKET_NONE)
            result->packet_kind = FK_EXACT_IDENTITY_ROUTER_PACKET_SKIPPED;
        result->skip_reason = reason;
    }
    if (!bind_reserved_route(
            state,
            packet.packet_sequence,
            FK_OWNER_OUTPUT_SEQUENCE_BRIDGE_SKIP_OWNER,
            FK_OWNER_RESERVED_ROUTE_SKIP)) {
        return abort_terminal(state, &packet, result);
    }
    if (!prepare_skip(
            state, reason, terminal_after_commit, result)) {
        return abort_terminal(state, &packet, result);
    }
    return publish_prepared(state, result);
}

fk_exact_identity_router_outcome publish_data(
        RouterImpl &state,
        const fk_exact_identity_packet &exact,
        fk_owner_packet &packet,
        fk_exact_identity_router_result *result) {
    if (!bind_reserved_route(
            state,
            exact.packet_sequence,
            packet.owner_worker,
            FK_OWNER_RESERVED_ROUTE_DATA)) {
        return abort_terminal(state, &exact, result);
    }
    if (!prepare_data(state, packet, result))
        return abort_terminal(state, &exact, result);
    return publish_prepared(state, result);
}

bool select_flow_owner(
        RouterImpl &state,
        const fk_flow_key &key,
        uint16_t &owner) {
    if (state.cached_flow_owner_valid != 0u &&
        fk_flow_key_equal(&state.cached_flow_owner_key, &key)) {
        owner = state.cached_flow_owner;
        return owner < state.config.owner_count;
    }
    fk_owner_identity identity{};
    bool formal_owner = false;
    const bool selected = fk_owner_identity_from_flow_key(&key, &identity) &&
        fk_owner_dispatch_select_owner(
            state.dispatch, &identity, &owner, &formal_owner) &&
        formal_owner && owner < state.config.owner_count;
    if (selected) {
        state.cached_flow_owner_key = key;
        state.cached_flow_owner = owner;
        state.cached_flow_owner_valid = 1u;
    }
    return selected;
}

bool select_initial_owner(
        RouterImpl &state,
        const uint8_t *dcid,
        uint8_t dcid_length,
        uint16_t &owner) {
    if (dcid == nullptr || dcid_length == 0u || dcid_length > 20u)
        return false;
    fk_owner_identity identity{};
    identity.kind = FK_OWNER_IDENTITY_QUIC_INITIAL_CID;
    identity.length = dcid_length;
    std::memcpy(identity.bytes, dcid, dcid_length);
    bool formal_owner = false;
    return fk_owner_dispatch_select_owner(
            state.dispatch, &identity, &owner, &formal_owner) &&
        formal_owner && owner < state.config.owner_count;
}

void record_cid_result(
        RouterImpl &state,
        fk_quic_cid_result_code code) {
    uint64_t *counter = nullptr;
    switch (code) {
    case FK_QUIC_CID_CREATED:
        counter = &state.counters.cid_created;
        break;
    case FK_QUIC_CID_RESOLVED:
        counter = &state.counters.cid_resolved;
        break;
    case FK_QUIC_CID_UNRESOLVED:
    case FK_QUIC_CID_NOT_QUIC:
    case FK_QUIC_CID_INVALID:
        counter = &state.counters.cid_unresolved;
        break;
    case FK_QUIC_CID_AMBIGUOUS:
        counter = &state.counters.cid_ambiguous;
        break;
    case FK_QUIC_CID_REJECTED:
        counter = &state.counters.cid_rejected;
        break;
    }
    if (counter != nullptr)
        (void)checked_add(state, *counter);
}

bool cid_success(const fk_quic_cid_resolution &resolution) {
    return (resolution.code == FK_QUIC_CID_CREATED ||
            resolution.code == FK_QUIC_CID_RESOLVED) &&
        resolution.logical_connection_id != 0u &&
        resolution.feature_direction_known == 1u &&
        resolution.feature_direction <= 1u &&
        resolution.resolved_destination_cid_length != 0u &&
        resolution.resolved_destination_cid_length <= 20u;
}

bool cid_internal_failure(const fk_quic_cid_resolution &resolution) {
    return resolution.reason == FK_QUIC_CID_REJECT_INTERNAL_INTEGRITY ||
        resolution.reason == FK_QUIC_CID_REJECT_TIME_REGRESSION;
}

}  // namespace
