#define _POSIX_C_SOURCE 200809L
#include "fk_native_runtime.h"

#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define FK_TCP_PROTOCOL 6u
#define FK_UDP_PROTOCOL 17u
#define FK_NATIVE_RUNTIME_MAX_FLOWS 65536u
#define FK_NATIVE_PARSER_PACKET_LEASE 16u
#define FK_NATIVE_LATENCY_SAMPLE_INTERVAL 1024u

struct runtime_flow {
    bool used;
    bool terminal_reported[2];
    bool fingerprint_complete;
    bool client_hello_seen;
    bool server_hello_seen;
    uint32_t parser_packets;
    struct fk_flow_key key;
    struct fk_tcp_tls_flow *parser;
};

struct fk_native_runtime {
    struct runtime_flow *flows;
    size_t capacity;
    uint32_t maximum_flows;
    uint32_t allocated_flows;
    enum fk_native_state_method state_method;
    struct fk_native_flowkeep *flowkeep;
    uint64_t controlled_budget_bytes;
    uint64_t state_accounting_timestamp_ns;
    long double controlled_state_byte_ns;
    bool window_ready;
    uint64_t window_packet_sequence;
    uint32_t window_emission_reason;
    bool window_observation_complete;
    struct fk_native_flow_snapshot window_snapshot;
    struct fk_native_runtime_stats stats;
};

static void account_controlled_state_time(
        struct fk_native_runtime *runtime,
        uint64_t timestamp_ns) {
    if (runtime == NULL)
        return;
    if (runtime->state_accounting_timestamp_ns != 0u &&
        timestamp_ns >= runtime->state_accounting_timestamp_ns) {
        uint64_t elapsed =
            timestamp_ns - runtime->state_accounting_timestamp_ns;
        runtime->controlled_state_byte_ns +=
            (long double)fk_native_runtime_owned_bytes(runtime) *
            (long double)elapsed;
        runtime->stats.controlled_state_byte_seconds =
            (double)(runtime->controlled_state_byte_ns / 1000000000.0L);
    }
    runtime->state_accounting_timestamp_ns = timestamp_ns;
}

static uint64_t runtime_external_owned_bytes(
        const struct fk_native_runtime *runtime) {
    if (runtime == NULL)
        return 0u;
    return sizeof(*runtime) +
        (uint64_t)runtime->capacity * sizeof(*runtime->flows) +
        (uint64_t)runtime->allocated_flows *
            sizeof(struct fk_tcp_tls_flow);
}

static bool parser_budget_available(
        struct fk_native_runtime *runtime) {
    if (runtime->controlled_budget_bytes == 0u)
        return true;
    uint64_t state_bytes =
        fk_native_flowkeep_owned_bytes(runtime->flowkeep);
    uint64_t external = runtime_external_owned_bytes(runtime);
    bool available =
        external <= runtime->controlled_budget_bytes &&
        state_bytes <= runtime->controlled_budget_bytes - external &&
        sizeof(struct fk_tcp_tls_flow) <=
            runtime->controlled_budget_bytes - external - state_bytes;
    if (!available)
        runtime->stats.parser_budget_rejects++;
    return available;
}

static void audit_controlled_budget(
        struct fk_native_runtime *runtime) {
    if (runtime == NULL || runtime->controlled_budget_bytes == 0u)
        return;
    uint64_t external = runtime_external_owned_bytes(runtime);
    uint64_t state_bytes =
        fk_native_flowkeep_owned_bytes(runtime->flowkeep);
    if (external > runtime->controlled_budget_bytes ||
        state_bytes > runtime->controlled_budget_bytes - external)
        runtime->stats.controlled_budget_violations++;
}

struct hello_context {
    struct fk_native_runtime *runtime;
    struct runtime_flow *flow;
    uint64_t packet_sequence;
    uint8_t direction;
    fk_native_event_callback callback;
    void *user;
};

static bool known_tls_port(uint16_t port) {
    switch (port) {
    case 443u:
    case 465u:
    case 636u:
    case 853u:
    case 989u:
    case 990u:
    case 993u:
    case 995u:
    case 5061u:
    case 8443u:
    case 9443u:
        return true;
    default:
        return false;
    }
}

static uint64_t monotonic_ns(void) {
    struct timespec value;
    if (clock_gettime(CLOCK_MONOTONIC, &value) != 0)
        return 0u;
    return (uint64_t)value.tv_sec * 1000000000ull +
           (uint64_t)value.tv_nsec;
}

static void observe_state_latency(
        struct fk_native_runtime *runtime,
        uint64_t elapsed_ns) {
    runtime->stats.state_latency_samples++;
    runtime->stats.state_latency_total_ns += elapsed_ns;
    if (elapsed_ns > runtime->stats.state_latency_max_ns)
        runtime->stats.state_latency_max_ns = elapsed_ns;
    uint32_t bucket = 0u;
    uint64_t value = elapsed_ns;
    while (value > 1u && bucket < 31u) {
        value >>= 1u;
        bucket++;
    }
    runtime->stats.state_latency_log2_ns[bucket]++;
}

static bool resembles_tls_record(
        const uint8_t *payload,
        size_t payload_length) {
    if (payload == NULL)
        return false;
    if (payload_length >= 3u && (payload[0] & 0x80u) != 0u) {
        uint16_t record_length =
            (uint16_t)(
                ((uint16_t)(payload[0] & 0x7fu) << 8) |
                payload[1]);
        if (record_length >= 9u &&
            record_length <= FK_TLS_HANDSHAKE_BODY_CAP &&
            payload[2] == FK_TLS_CLIENT_HELLO)
            return true;
    }
    if (payload_length < 5u)
        return false;
    uint8_t content_type = payload[0];
    uint16_t record_length =
        (uint16_t)(((uint16_t)payload[3] << 8) | payload[4]);
    return content_type >= 20u && content_type <= 24u &&
           payload[1] == 3u &&
           record_length <= FK_TLS_RECORD_PLAINTEXT_MAX;
}

static struct runtime_flow *find_flow(
        struct fk_native_runtime *runtime,
        const struct fk_flow_key *key) {
    size_t mask = runtime->capacity - 1u;
    size_t start = (size_t)fk_flow_key_hash(key) & mask;
    for (size_t probe = 0u; probe < runtime->capacity; ++probe) {
        struct runtime_flow *flow =
            &runtime->flows[(start + probe) & mask];
        if (!flow->used)
            return NULL;
        if (fk_flow_key_equal(&flow->key, key))
            return flow;
    }
    return NULL;
}

static struct runtime_flow *create_flow(
        struct fk_native_runtime *runtime,
        const struct fk_flow_key *key) {
    if (runtime->allocated_flows >= runtime->maximum_flows)
        return NULL;
    size_t mask = runtime->capacity - 1u;
    size_t start = (size_t)fk_flow_key_hash(key) & mask;
    for (size_t probe = 0u; probe < runtime->capacity; ++probe) {
        struct runtime_flow *flow =
            &runtime->flows[(start + probe) & mask];
        if (flow->used) {
            if (fk_flow_key_equal(&flow->key, key))
                return flow;
            continue;
        }
        if (!parser_budget_available(runtime))
            return NULL;
        struct fk_tcp_tls_flow *parser = malloc(sizeof(*parser));
        if (parser == NULL)
            return NULL;
        fk_tcp_tls_flow_init(parser);
        flow->used = true;
        flow->key = *key;
        flow->parser = parser;
        runtime->allocated_flows++;
        if (runtime->allocated_flows >
            runtime->stats.peak_allocated_tls_flows)
            runtime->stats.peak_allocated_tls_flows =
                runtime->allocated_flows;
        return flow;
    }
    return NULL;
}

static void release_flow_parser(
        struct fk_native_runtime *runtime,
        struct runtime_flow *flow,
        bool fingerprint_complete) {
    if (runtime == NULL || flow == NULL)
        return;
    if (flow->parser != NULL) {
        free(flow->parser);
        flow->parser = NULL;
        if (runtime->allocated_flows > 0u)
            runtime->allocated_flows--;
    }
    flow->parser_packets = 0u;
    if (fingerprint_complete)
        flow->fingerprint_complete = true;
}

static void initialize_event(
        struct fk_native_event *event,
        uint64_t packet_sequence,
        uint32_t event_type,
        enum fk_native_parse_code parse_code,
        enum fk_protocol_completeness completeness,
        const struct fk_flow_key *key,
        uint8_t direction) {
    memset(event, 0, sizeof(*event));
    event->packet_sequence = packet_sequence;
    event->event_type = event_type;
    event->parse_code = (uint32_t)parse_code;
    event->completeness = (uint32_t)completeness;
    event->ip_version = key->ip_version;
    event->protocol = key->protocol;
    event->direction = direction;
    memcpy(event->low_addr, key->low_addr, sizeof(event->low_addr));
    memcpy(event->high_addr, key->high_addr, sizeof(event->high_addr));
    event->low_port = key->low_port;
    event->high_port = key->high_port;
}

static bool deliver_event(
        struct fk_native_runtime *runtime,
        struct fk_native_event *event,
        fk_native_event_callback callback,
        void *user) {
    runtime->stats.events_generated++;
    if (callback == NULL || !callback(event, user)) {
        runtime->stats.event_delivery_failures++;
        return false;
    }
    return true;
}

static size_t bounded_string_length(
        const char *value,
        size_t capacity) {
    size_t length = 0u;
    while (length < capacity && value[length] != '\0')
        length++;
    return length;
}

static void hello_observed(
        const struct fk_tls_hello *hello,
        void *user) {
    struct hello_context *context = user;
    struct fk_native_event event;
    initialize_event(
        &event,
        context->packet_sequence,
        FK_NATIVE_EVENT_TLS_HELLO,
        FK_PARSE_OK,
        hello->completeness,
        &context->flow->key,
        context->direction);
    event.framing = (uint8_t)hello->framing;
    event.hello_kind = (uint8_t)hello->kind;
    event.hello_retry_request = hello->hello_retry_request ? 1u : 0u;
    event.legacy_version = hello->legacy_version;
    event.selected_cipher = hello->selected_cipher;
    event.cipher_count = hello->cipher_count;
    event.extension_count = hello->extension_count;
    event.supported_version_count = hello->supported_version_count;
    event.signature_algorithm_count =
        hello->signature_algorithm_count;
    memcpy(
        event.ciphers,
        hello->ciphers,
        (size_t)hello->cipher_count * sizeof(hello->ciphers[0]));
    memcpy(
        event.extensions,
        hello->extensions,
        (size_t)hello->extension_count *
            sizeof(hello->extensions[0]));
    memcpy(
        event.supported_versions,
        hello->supported_versions,
        (size_t)hello->supported_version_count *
            sizeof(hello->supported_versions[0]));
    memcpy(
        event.signature_algorithms,
        hello->signature_algorithms,
        (size_t)hello->signature_algorithm_count *
            sizeof(hello->signature_algorithms[0]));
    size_t server_name_length = bounded_string_length(
        hello->server_name,
        sizeof(hello->server_name));
    size_t alpn_length = bounded_string_length(
        hello->alpn,
        sizeof(hello->alpn));
    event.server_name_length = (uint16_t)server_name_length;
    event.alpn_length = (uint16_t)alpn_length;
    memcpy(event.server_name, hello->server_name, server_name_length);
    memcpy(event.alpn, hello->alpn, alpn_length);

    context->runtime->stats.tls_hello_events++;
    if (hello->kind == FK_TLS_CLIENT_HELLO)
        context->runtime->stats.tls_client_hello_events++;
    else if (hello->kind == FK_TLS_SERVER_HELLO)
        context->runtime->stats.tls_server_hello_events++;
    if (hello->completeness != FK_COMPLETENESS_COMPLETE)
        context->runtime->stats.tls_partial_hello_events++;
    else {
        if (hello->kind == FK_TLS_CLIENT_HELLO)
            context->flow->client_hello_seen = true;
        else if (hello->kind == FK_TLS_SERVER_HELLO)
            context->flow->server_hello_seen = true;
        context->flow->fingerprint_complete =
            context->flow->client_hello_seen &&
            context->flow->server_hello_seen;
    }
    (void)deliver_event(
        context->runtime,
        &event,
        context->callback,
        context->user);
}

static void emit_tls_status(
        struct fk_native_runtime *runtime,
        const struct runtime_flow *flow,
        uint64_t packet_sequence,
        uint8_t direction,
        enum fk_protocol_completeness completeness,
        fk_native_event_callback callback,
        void *user) {
    struct fk_native_event event;
    initialize_event(
        &event,
        packet_sequence,
        FK_NATIVE_EVENT_TLS_STATUS,
        FK_PARSE_OK,
        completeness,
        &flow->key,
        direction);
    runtime->stats.tls_terminal_status_events++;
    (void)deliver_event(runtime, &event, callback, user);
}

struct fk_native_runtime *fk_native_runtime_create(
        uint32_t maximum_tls_flows) {
    return fk_native_runtime_create_with_state(
        maximum_tls_flows, 0, 0u, 0u);
}

struct fk_native_runtime *fk_native_runtime_create_with_state(
        uint32_t maximum_tls_flows,
        enum fk_native_state_method state_method,
        uint32_t maximum_state_flows,
        uint64_t idle_timeout_ns) {
    if (maximum_tls_flows == 0u ||
        maximum_tls_flows > FK_NATIVE_RUNTIME_MAX_FLOWS)
        return NULL;
    struct fk_native_runtime *runtime = calloc(1u, sizeof(*runtime));
    if (runtime == NULL)
        return NULL;
    /*
     * The compact identity table is independent of the expensive concurrent
     * parser lease limit.  Completed identities remain as small suppression
     * records so later application data cannot recreate a parser.
     */
    size_t target = (size_t)FK_NATIVE_RUNTIME_MAX_FLOWS * 2u;
    size_t capacity = 2u;
    while (capacity < target)
        capacity *= 2u;
    runtime->flows = calloc(capacity, sizeof(*runtime->flows));
    if (runtime->flows == NULL) {
        free(runtime);
        return NULL;
    }
    runtime->capacity = capacity;
    runtime->maximum_flows = maximum_tls_flows;
    runtime->state_method = state_method;
    runtime->stats.state_latency_sample_interval_packets =
        FK_NATIVE_LATENCY_SAMPLE_INTERVAL;
    if (state_method != 0) {
        runtime->flowkeep = fk_native_flowkeep_create(
            state_method, maximum_state_flows, idle_timeout_ns);
        if (runtime->flowkeep == NULL) {
            free(runtime->flows);
            free(runtime);
            return NULL;
        }
    }
    return runtime;
}

bool fk_native_runtime_configure_value_policy(
        struct fk_native_runtime *runtime,
        const struct fk_native_value_model *model,
        uint64_t controlled_budget_bytes,
        uint32_t replacement_candidates) {
    if (runtime == NULL || controlled_budget_bytes == 0u)
        return false;
    runtime->controlled_budget_bytes = controlled_budget_bytes;
    fk_native_flowkeep_set_external_owned_bytes(
        runtime->flowkeep,
        runtime_external_owned_bytes(runtime));
    bool configured = fk_native_flowkeep_configure_value_policy(
        runtime->flowkeep,
        model,
        controlled_budget_bytes,
        replacement_candidates);
    if (!configured)
        runtime->controlled_budget_bytes = 0u;
    return configured;
}

bool fk_native_runtime_configure_budget_policy(
        struct fk_native_runtime *runtime,
        uint64_t controlled_budget_bytes,
        uint32_t replacement_candidates,
        uint64_t fixed_ttl_ns) {
    if (runtime == NULL || controlled_budget_bytes == 0u)
        return false;
    runtime->controlled_budget_bytes = controlled_budget_bytes;
    fk_native_flowkeep_set_external_owned_bytes(
        runtime->flowkeep,
        runtime_external_owned_bytes(runtime));
    bool configured = fk_native_flowkeep_configure_budget_policy(
        runtime->flowkeep,
        controlled_budget_bytes,
        replacement_candidates,
        fixed_ttl_ns);
    if (!configured)
        runtime->controlled_budget_bytes = 0u;
    return configured;
}

void fk_native_runtime_destroy(struct fk_native_runtime *runtime) {
    if (runtime == NULL)
        return;
    for (size_t index = 0u; index < runtime->capacity; ++index)
        free(runtime->flows[index].parser);
    fk_native_flowkeep_destroy(runtime->flowkeep);
    free(runtime->flows);
    free(runtime);
}

void fk_native_runtime_process_frame(
        struct fk_native_runtime *runtime,
        uint64_t packet_sequence,
        const uint8_t *frame,
        size_t captured_length,
        uint32_t wire_length,
        fk_native_event_callback callback,
        void *user) {
    fk_native_runtime_process_frame_at(
        runtime,
        packet_sequence,
        packet_sequence,
        frame,
        captured_length,
        wire_length,
        callback,
        user);
}

void fk_native_runtime_process_frame_at(
        struct fk_native_runtime *runtime,
        uint64_t packet_sequence,
        uint64_t timestamp_ns,
        const uint8_t *frame,
        size_t captured_length,
        uint32_t wire_length,
        fk_native_event_callback callback,
        void *user) {
    if (runtime == NULL)
        return;
    account_controlled_state_time(runtime, timestamp_ns);
    runtime->stats.frames_processed++;
    runtime->stats.captured_bytes_processed += captured_length;
    struct fk_packet_view view;
    enum fk_native_parse_code code = fk_native_parse_ethernet(
        frame,
        captured_length,
        wire_length,
        &view);
    if ((unsigned)code <= FK_PARSE_CAP_EXCEEDED)
        runtime->stats.parse_codes[code]++;
    if (code != FK_PARSE_OK)
        return;
    bool fingerprint_retained = true;
    if (runtime->flowkeep != NULL) {
        fk_native_flowkeep_set_external_owned_bytes(
            runtime->flowkeep,
            runtime_external_owned_bytes(runtime));
        bool sample_latency =
            packet_sequence % FK_NATIVE_LATENCY_SAMPLE_INTERVAL == 0u;
        uint64_t state_start_ns =
            sample_latency ? monotonic_ns() : 0u;
        struct fk_native_flow_snapshot snapshot;
        bool state_retained = fk_native_flowkeep_process(
            runtime->flowkeep, timestamp_ns, &view, &snapshot);
        uint64_t state_end_ns =
            sample_latency ? monotonic_ns() : 0u;
        if (sample_latency && state_end_ns >= state_start_ns)
            observe_state_latency(
                runtime, state_end_ns - state_start_ns);
        if (state_retained) {
            if (runtime->state_method == FK_NATIVE_STATE_FLOWKEEP ||
                runtime->state_method ==
                    FK_NATIVE_STATE_FLOWKEEP_HEURISTIC ||
                runtime->state_method == FK_NATIVE_STATE_LRU ||
                runtime->state_method == FK_NATIVE_STATE_FIXED_TTL ||
                runtime->state_method ==
                    FK_NATIVE_STATE_PROTOCOL_AWARE ||
                runtime->state_method ==
                    FK_NATIVE_STATE_PROTOCOL_DEADLINE ||
                runtime->state_method ==
                    FK_NATIVE_STATE_HANDSHAKE_ONLY) {
                fingerprint_retained =
                    (snapshot.lifecycle == FK_NATIVE_BOOTSTRAP &&
                     view.l4_protocol == FK_UDP_PROTOCOL) ||
                    snapshot.lifecycle == FK_NATIVE_HS ||
                    snapshot.lifecycle == FK_NATIVE_FULL;
            }
            bool terminal =
                view.l4_protocol == FK_TCP_PROTOCOL &&
                (view.tcp_flags &
                 (FK_TCP_FLAG_RST | FK_TCP_FLAG_FIN)) != 0u;
            /*
             * The detector ABI has one irrevocable decision per flow:
             * packet 20, or an earlier transport-terminal observation.
             * Packet-1/4 lifecycle changes and later pressure reviews are
             * controller audit events, not inference requests. Publishing
             * them here used to make the pressure controller count work that
             * the consumer would reject or deduplicate.
             */
            uint32_t reason =
                snapshot.packets == FK_NATIVE_HISTORY_PACKETS ? 3u :
                terminal &&
                snapshot.packets < FK_NATIVE_HISTORY_PACKETS ? 4u : 0u;
            if (reason != 0u) {
            runtime->window_ready = true;
            runtime->window_packet_sequence = packet_sequence;
            runtime->window_emission_reason = reason;
            runtime->window_observation_complete = terminal;
            runtime->window_snapshot = snapshot;
            }
        }
    }

    /*
     * SUMMARY and HISTORY retention never expose handshake fingerprints to
     * their detector.  Parsing TCP/TLS or QUIC after the state update wastes
     * the RX budget and can starve the NIC descriptor ring under burst load.
     * The caller still advances the sparse-event watermark for every frame,
     * so consumers retain the same lossless ordering guarantee.
     */
    if (runtime->state_method == FK_NATIVE_STATE_SUMMARY ||
        runtime->state_method == FK_NATIVE_STATE_HISTORY ||
        runtime->state_method == FK_NATIVE_STATE_NETBEACON ||
        runtime->state_method == FK_NATIVE_STATE_SPLIDT ||
        runtime->state_method == FK_NATIVE_STATE_OCTOSKETCH ||
        runtime->state_method == FK_NATIVE_STATE_FLM ||
        !fingerprint_retained)
        return;

    if (view.l4_protocol == FK_UDP_PROTOCOL) {
        runtime->stats.udp_packets++;
        struct fk_quic_header_observation observation;
        enum fk_native_parse_code quic_code =
            fk_native_inspect_quic_header(&view, &observation);
        if (observation.status == FK_QUIC_NOT_DETECTED)
            return;
        struct fk_flow_key key;
        uint8_t direction = 0u;
        if (fk_native_flow_key(&view, &key, &direction) != FK_PARSE_OK)
            return;
        struct fk_native_event event;
        initialize_event(
            &event,
            packet_sequence,
            FK_NATIVE_EVENT_QUIC_PARTIAL,
            quic_code,
            FK_COMPLETENESS_PARTIAL,
            &key,
            direction);
        runtime->stats.quic_partial_events++;
        (void)deliver_event(runtime, &event, callback, user);
        return;
    }
    if (view.l4_protocol != FK_TCP_PROTOCOL)
        return;
    runtime->stats.tcp_packets++;

    struct fk_flow_key key;
    uint8_t direction = 0u;
    if (fk_native_flow_key(&view, &key, &direction) != FK_PARSE_OK)
        return;
    struct runtime_flow *flow = find_flow(runtime, &key);
    bool candidate =
        resembles_tls_record(view.payload, view.payload_size) ||
        (((view.tcp_flags & FK_TCP_FLAG_SYN) != 0u) &&
         (known_tls_port(view.src_port) ||
          known_tls_port(view.dst_port)));
    if (flow == NULL && candidate) {
        flow = create_flow(runtime, &key);
        if (flow == NULL) {
            runtime->stats.tls_flow_table_full++;
            return;
        }
        runtime->stats.tls_candidate_flows++;
    }
    if (flow == NULL)
        return;

    bool new_connection =
        (view.tcp_flags & (FK_TCP_FLAG_SYN | FK_TCP_FLAG_ACK)) ==
        FK_TCP_FLAG_SYN;
    if (flow->parser == NULL) {
        if (!new_connection || runtime->allocated_flows >=
                runtime->maximum_flows)
            return;
        if (!parser_budget_available(runtime))
            return;
        flow->parser = malloc(sizeof(*flow->parser));
        if (flow->parser == NULL)
            return;
        fk_tcp_tls_flow_init(flow->parser);
        flow->fingerprint_complete = false;
        flow->client_hello_seen = false;
        flow->server_hello_seen = false;
        flow->parser_packets = 0u;
        memset(flow->terminal_reported, 0, sizeof(flow->terminal_reported));
        runtime->allocated_flows++;
        if (runtime->allocated_flows >
            runtime->stats.peak_allocated_tls_flows)
            runtime->stats.peak_allocated_tls_flows =
                runtime->allocated_flows;
    }

    if (new_connection) {
        bool had_sequence =
            flow->parser->direction[0].sequence_initialized ||
            flow->parser->direction[1].sequence_initialized;
        if (had_sequence) {
            fk_tcp_tls_flow_init(flow->parser);
            flow->fingerprint_complete = false;
            flow->client_hello_seen = false;
            flow->server_hello_seen = false;
            flow->parser_packets = 0u;
            memset(
                flow->terminal_reported,
                0,
                sizeof(flow->terminal_reported));
            runtime->stats.tls_connection_resets++;
        }
    }

    bool was_desynchronized =
        flow->parser->direction[direction].desynchronized;
    struct hello_context context = {
        .runtime = runtime,
        .flow = flow,
        .packet_sequence = packet_sequence,
        .direction = direction,
        .callback = callback,
        .user = user,
    };
    enum fk_protocol_completeness completeness =
        fk_tcp_tls_flow_feed(
            flow->parser,
            direction,
            view.tcp_sequence,
            view.tcp_flags,
            view.payload,
            view.payload_size,
            hello_observed,
            &context);
    flow->parser_packets++;
    bool terminal =
        completeness == FK_COMPLETENESS_MALFORMED ||
        completeness == FK_COMPLETENESS_CAP_EXCEEDED ||
        (!was_desynchronized &&
         flow->parser->direction[direction].desynchronized);
    if (terminal && !flow->terminal_reported[direction]) {
        flow->terminal_reported[direction] = true;
        emit_tls_status(
            runtime,
            flow,
            packet_sequence,
            direction,
            completeness,
            callback,
            user);
    }
    bool transport_terminal =
        (view.tcp_flags & (FK_TCP_FLAG_FIN | FK_TCP_FLAG_RST)) != 0u;
    if (flow->fingerprint_complete || transport_terminal ||
        flow->parser_packets >= FK_NATIVE_PARSER_PACKET_LEASE) {
        release_flow_parser(
            runtime, flow,
            flow->fingerprint_complete || transport_terminal);
    }
    fk_native_flowkeep_set_external_owned_bytes(
        runtime->flowkeep,
        runtime_external_owned_bytes(runtime));
    audit_controlled_budget(runtime);
}

const struct fk_native_runtime_stats *fk_native_runtime_get_stats(
        const struct fk_native_runtime *runtime) {
    return runtime == NULL ? NULL : &runtime->stats;
}

uint64_t fk_native_runtime_owned_bytes(
        const struct fk_native_runtime *runtime) {
    if (runtime == NULL)
        return 0u;
    return sizeof(*runtime) +
           (uint64_t)runtime->capacity * sizeof(*runtime->flows) +
           (uint64_t)runtime->allocated_flows *
               sizeof(struct fk_tcp_tls_flow) +
           fk_native_flowkeep_owned_bytes(runtime->flowkeep);
}

uint64_t fk_native_runtime_peak_owned_bytes(
        const struct fk_native_runtime *runtime) {
    if (runtime == NULL)
        return 0u;
    const struct fk_native_flowkeep_stats *state =
        fk_native_flowkeep_get_stats(runtime->flowkeep);
    return sizeof(*runtime) +
           (uint64_t)runtime->capacity * sizeof(*runtime->flows) +
           runtime->stats.peak_allocated_tls_flows *
               sizeof(struct fk_tcp_tls_flow) +
           (state == NULL ? 0u : state->peak_owned_bytes);
}

uint32_t fk_native_runtime_maximum_tls_flows(
        const struct fk_native_runtime *runtime) {
    return runtime == NULL ? 0u : runtime->maximum_flows;
}

uint32_t fk_native_runtime_allocated_tls_flows(
        const struct fk_native_runtime *runtime) {
    return runtime == NULL ? 0u : runtime->allocated_flows;
}

const struct fk_native_flowkeep_stats *
fk_native_runtime_get_flowkeep_stats(
        const struct fk_native_runtime *runtime) {
    return runtime == NULL
        ? NULL : fk_native_flowkeep_get_stats(runtime->flowkeep);
}

enum fk_native_state_method fk_native_runtime_state_method(
        const struct fk_native_runtime *runtime) {
    return runtime == NULL ? 0 : runtime->state_method;
}

void fk_native_runtime_set_q4_policy(
        struct fk_native_runtime *runtime,
        bool impact_enabled,
        bool lease_enabled) {
    if (runtime == NULL)
        return;
    fk_native_flowkeep_set_q4_policy(
        runtime->flowkeep, impact_enabled, lease_enabled);
}

void fk_native_runtime_set_pressure(
        struct fk_native_runtime *runtime,
        uint32_t pressure_level) {
    if (runtime == NULL)
        return;
    fk_native_flowkeep_set_pressure(runtime->flowkeep, pressure_level);
}

bool fk_native_runtime_take_window(
        struct fk_native_runtime *runtime,
        uint64_t *packet_sequence,
        struct fk_native_flow_snapshot *snapshot,
        uint32_t *emission_reason,
        bool *observation_complete) {
    if (runtime == NULL || !runtime->window_ready ||
        packet_sequence == NULL || snapshot == NULL ||
        emission_reason == NULL || observation_complete == NULL)
        return false;
    *packet_sequence = runtime->window_packet_sequence;
    *snapshot = runtime->window_snapshot;
    *emission_reason = runtime->window_emission_reason;
    *observation_complete = runtime->window_observation_complete;
    runtime->window_ready = false;
    return true;
}

uint64_t fk_native_runtime_state_latency_percentile_ns(
        const struct fk_native_runtime *runtime,
        uint32_t numerator,
        uint32_t denominator) {
    if (runtime == NULL || denominator == 0u ||
        numerator > denominator ||
        runtime->stats.state_latency_samples == 0u)
        return 0u;
    uint64_t target =
        (runtime->stats.state_latency_samples * numerator +
         denominator - 1u) / denominator;
    if (target == 0u)
        target = 1u;
    uint64_t cumulative = 0u;
    for (uint32_t bucket = 0u; bucket < 32u; ++bucket) {
        cumulative += runtime->stats.state_latency_log2_ns[bucket];
        if (cumulative >= target)
            return bucket == 31u
                ? UINT32_MAX : 1ull << (bucket + 1u);
    }
    return runtime->stats.state_latency_max_ns;
}
