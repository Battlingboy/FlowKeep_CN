#include "fk_quic_route_receipt.h"

#include <atomic>
#include <cstddef>
#include <cstring>
#include <limits>
#include <new>

namespace {

constexpr uint32_t kQuicAeadTagBytes = 16u;

struct ReplaySlot {
    std::atomic_flag lock = ATOMIC_FLAG_INIT;
    uint64_t last_packet_sequence;
    uint8_t initialized;
    uint8_t reserved[7];
};

struct ReceiptState {
    fk_quic_route_receipt_config config;
    ReplaySlot *replay_slots;
    size_t reserved_bytes;
    std::atomic<uint64_t> issue_attempts;
    std::atomic<uint64_t> issued;
    std::atomic<uint64_t> issue_rejections;
    std::atomic<uint64_t> verify_attempts;
    std::atomic<uint64_t> verified;
    std::atomic<uint64_t> invalid_rejections;
    std::atomic<uint64_t> tag_mismatch_rejections;
    std::atomic<uint64_t> replay_or_reorder_rejections;
    std::atomic<uint64_t> internal_integrity_rejections;
};

struct WireMaterial {
    fk_flow_key canonical_udp_key;
    uint32_t datagram_bytes;
    uint32_t authenticated_packet_bytes;
    uint32_t trailing_coalesced_bytes;
    uint8_t cid[20];
    uint8_t cid_length;
    uint8_t first_wire_byte;
};

struct ByteWriter {
    uint8_t *bytes;
    size_t capacity;
    size_t size;

    bool append_u8(uint8_t value) {
        if (size >= capacity)
            return false;
        bytes[size++] = value;
        return true;
    }

    bool append_u16_le(uint16_t value) {
        return append_u8(static_cast<uint8_t>(value)) &&
            append_u8(static_cast<uint8_t>(value >> 8u));
    }

    bool append_u32_le(uint32_t value) {
        for (unsigned shift = 0u; shift < 32u; shift += 8u) {
            if (!append_u8(static_cast<uint8_t>(value >> shift)))
                return false;
        }
        return true;
    }

    bool append_u64_le(uint64_t value) {
        for (unsigned shift = 0u; shift < 64u; shift += 8u) {
            if (!append_u8(static_cast<uint8_t>(value >> shift)))
                return false;
        }
        return true;
    }

    bool append_bytes(const uint8_t *source, size_t length) {
        if ((length != 0u && source == nullptr) ||
            length > capacity - size)
            return false;
        if (length != 0u)
            std::memcpy(bytes + size, source, length);
        size += length;
        return true;
    }
};

static_assert(
    sizeof(fk_quic_route_receipt) == FK_QUIC_ROUTE_RECEIPT_BYTES,
    "QUIC route receipt transport ABI changed");
static_assert(
    alignof(ReceiptState) <= alignof(max_align_t),
    "receipt state exceeds caller placement alignment");
static_assert(
    alignof(ReplaySlot) <= alignof(max_align_t),
    "replay slot exceeds caller placement alignment");
static_assert(
    sizeof(uintptr_t) <= sizeof(uint64_t),
    "packet handle does not fit the frozen receipt message ABI");
static_assert(sizeof(ReplaySlot) == 24u, "replay slot ABI changed");
static_assert(sizeof(ReceiptState) == 136u, "receipt state ABI changed");

bool checked_add(size_t &value, size_t addend) {
    if (addend > std::numeric_limits<size_t>::max() - value)
        return false;
    value += addend;
    return true;
}

bool align_size(size_t &value, size_t alignment) {
    const size_t remainder = value % alignment;
    return remainder == 0u || checked_add(value, alignment - remainder);
}

bool power_of_two(uint16_t value) {
    return value != 0u && (value & (value - 1u)) == 0u;
}

bool all_zero(const uint8_t *bytes, size_t length) {
    uint8_t combined = 0u;
    for (size_t index = 0u; index < length; ++index)
        combined = static_cast<uint8_t>(combined | bytes[index]);
    return combined == 0u;
}

bool independent_keys(const fk_quic_route_receipt_config &config) {
    uint8_t difference = 0u;
    for (size_t index = 0u; index < FK_QUIC_ROUTE_RECEIPT_KEY_BYTES;
         ++index) {
        difference = static_cast<uint8_t>(difference |
            (config.authentication_key_0[index] ^
             config.authentication_key_1[index]));
    }
    return difference != 0u &&
        !all_zero(config.authentication_key_0,
            FK_QUIC_ROUTE_RECEIPT_KEY_BYTES) &&
        !all_zero(config.authentication_key_1,
            FK_QUIC_ROUTE_RECEIPT_KEY_BYTES);
}

size_t required_bytes(const fk_quic_route_receipt_config *config) {
    if (config == nullptr || config->run_epoch == 0u ||
        !power_of_two(config->owner_count) ||
        config->owner_count > FK_QUIC_ROUTE_RECEIPT_MAX_OWNERS ||
        config->keys_precommitted != 1u ||
        !all_zero(config->reserved, sizeof(config->reserved)) ||
        !independent_keys(*config))
        return 0u;
    size_t bytes = sizeof(ReceiptState);
    if (!align_size(bytes, alignof(ReplaySlot)))
        return 0u;
    const size_t count = config->owner_count;
    if (count > std::numeric_limits<size_t>::max() / sizeof(ReplaySlot) ||
        !checked_add(bytes, count * sizeof(ReplaySlot)))
        return 0u;
    return bytes;
}

uint64_t rotate_left(uint64_t value, unsigned shift) {
    return (value << shift) | (value >> (64u - shift));
}

uint64_t load_u64_le(const uint8_t *bytes) {
    uint64_t result = 0u;
    for (unsigned index = 0u; index < 8u; ++index)
        result |= static_cast<uint64_t>(bytes[index]) << (index * 8u);
    return result;
}

void store_u64_le(uint64_t value, uint8_t *bytes) {
    for (unsigned index = 0u; index < 8u; ++index)
        bytes[index] = static_cast<uint8_t>(value >> (index * 8u));
}

void sip_round(uint64_t &v0, uint64_t &v1, uint64_t &v2, uint64_t &v3) {
    v0 += v1;
    v1 = rotate_left(v1, 13u);
    v1 ^= v0;
    v0 = rotate_left(v0, 32u);
    v2 += v3;
    v3 = rotate_left(v3, 16u);
    v3 ^= v2;
    v0 += v3;
    v3 = rotate_left(v3, 21u);
    v3 ^= v0;
    v2 += v1;
    v1 = rotate_left(v1, 17u);
    v1 ^= v2;
    v2 = rotate_left(v2, 32u);
}

uint64_t siphash24(
        const uint8_t key[FK_QUIC_ROUTE_RECEIPT_KEY_BYTES],
        const uint8_t *message,
        size_t length) {
    const uint64_t k0 = load_u64_le(key);
    const uint64_t k1 = load_u64_le(key + 8u);
    uint64_t v0 = UINT64_C(0x736f6d6570736575) ^ k0;
    uint64_t v1 = UINT64_C(0x646f72616e646f6d) ^ k1;
    uint64_t v2 = UINT64_C(0x6c7967656e657261) ^ k0;
    uint64_t v3 = UINT64_C(0x7465646279746573) ^ k1;
    const size_t blocks = length / 8u;
    for (size_t index = 0u; index < blocks; ++index) {
        const uint64_t word = load_u64_le(message + index * 8u);
        v3 ^= word;
        sip_round(v0, v1, v2, v3);
        sip_round(v0, v1, v2, v3);
        v0 ^= word;
    }
    uint64_t tail = static_cast<uint64_t>(length) << 56u;
    const size_t offset = blocks * 8u;
    for (size_t index = 0u; index < length - offset; ++index)
        tail |= static_cast<uint64_t>(message[offset + index]) <<
            (index * 8u);
    v3 ^= tail;
    sip_round(v0, v1, v2, v3);
    sip_round(v0, v1, v2, v3);
    v0 ^= tail;
    v2 ^= 0xffu;
    for (unsigned index = 0u; index < 4u; ++index)
        sip_round(v0, v1, v2, v3);
    return v0 ^ v1 ^ v2 ^ v3;
}

bool packet_descriptor_valid(
        const ReceiptState &state,
        const fk_owner_packet *packet,
        const fk_packet_view *view,
        bool issuing) {
    if (packet == nullptr || view == nullptr ||
        packet->packet_handle == 0u ||
        packet->logical_connection_id == 0u ||
        packet->packet_sequence == UINT64_MAX ||
        packet->physical_ingress_timestamp_ns == 0u ||
        packet->captured_length == 0u ||
        packet->wire_length < packet->captured_length ||
        packet->ingress_worker >= state.config.owner_count ||
        packet->owner_worker >= state.config.owner_count ||
        packet->identity_kind != FK_OWNER_IDENTITY_QUIC_LOGICAL ||
        packet->feature_direction_known != 1u ||
        packet->feature_direction > 1u ||
        view->code != FK_PARSE_OK || view->l4_protocol != 17u ||
        (view->ip_version != 4u && view->ip_version != 6u) ||
        view->payload == nullptr || view->payload_size == 0u ||
        packet->captured_length != view->captured_size ||
        packet->wire_length != view->wire_size)
        return false;
    for (uint8_t byte : packet->reserved) {
        if (byte != 0u)
            return false;
    }
    return issuing ? fk_quic_route_receipt_is_zero(&packet->route_receipt) :
        fk_quic_route_receipt_shape_valid(&packet->route_receipt);
}

bool initial_result_matches_wire(
        const fk_packet_view &view,
        const fk_quic_initial_auth_result *authenticated,
        WireMaterial &material) {
    const bool supported_version = authenticated != nullptr &&
        (authenticated->version == FK_QUIC_INITIAL_AUTH_VERSION_V1 ||
         authenticated->version == FK_QUIC_INITIAL_AUTH_VERSION_V2);
    const uint8_t expected_type_bits = authenticated != nullptr &&
            authenticated->version == FK_QUIC_INITIAL_AUTH_VERSION_V2 ?
        1u : 0u;
    fk_quic_initial_clear_bounds_v1 clear_bounds{};
    const bool clear_candidate =
        fk_quic_initial_inspect_client_clear_bounds(
            view.payload, view.payload_size, &clear_bounds) ==
        FK_QUIC_INITIAL_CLEAR_CRYPTO_CANDIDATE;
    if (authenticated == nullptr ||
        !clear_candidate ||
        clear_bounds.abi_version !=
            FK_QUIC_INITIAL_CLEAR_BOUNDS_ABI_VERSION ||
        clear_bounds.reason != FK_QUIC_INITIAL_AUTH_REASON_NONE ||
        authenticated->abi_version != FK_QUIC_INITIAL_AUTH_ABI_VERSION ||
        authenticated->decision != FK_QUIC_INITIAL_AUTHENTICATED ||
        authenticated->reason != FK_QUIC_INITIAL_AUTH_REASON_NONE ||
        !supported_version ||
        authenticated->fixed_bit_verified != 1u ||
        authenticated->long_packet_type_bits != expected_type_bits ||
        authenticated->packet_number_bytes == 0u ||
        authenticated->packet_number_bytes > 4u ||
        authenticated->destination_cid_length == 0u ||
        authenticated->destination_cid_length > sizeof(material.cid) ||
        authenticated->source_cid_length > sizeof(material.cid) ||
        clear_bounds.version != authenticated->version ||
        clear_bounds.datagram_bytes != authenticated->datagram_bytes ||
        clear_bounds.packet_end_bytes !=
            authenticated->authenticated_packet_bytes ||
        clear_bounds.trailing_coalesced_bytes !=
            authenticated->trailing_coalesced_bytes ||
        clear_bounds.packet_number_offset +
                authenticated->packet_number_bytes !=
            authenticated->authenticated_header_bytes ||
        clear_bounds.token_bytes != authenticated->token_bytes ||
        clear_bounds.fixed_bit_verified !=
            authenticated->fixed_bit_verified ||
        clear_bounds.long_packet_type_bits !=
            authenticated->long_packet_type_bits ||
        clear_bounds.destination_cid_length !=
            authenticated->destination_cid_length ||
        clear_bounds.source_cid_length !=
            authenticated->source_cid_length ||
        authenticated->datagram_bytes != view.payload_size ||
        authenticated->datagram_bytes <
            FK_QUIC_INITIAL_AUTH_MIN_DATAGRAM_BYTES ||
        authenticated->datagram_bytes >
            FK_QUIC_INITIAL_AUTH_MAX_DATAGRAM_BYTES ||
        authenticated->authenticated_packet_bytes == 0u ||
        authenticated->authenticated_packet_bytes > view.payload_size ||
        authenticated->trailing_coalesced_bytes !=
            authenticated->datagram_bytes -
                authenticated->authenticated_packet_bytes ||
        authenticated->authenticated_header_bytes == 0u ||
        authenticated->authenticated_ciphertext_bytes < 16u ||
        authenticated->authenticated_header_bytes >
            authenticated->authenticated_packet_bytes ||
        authenticated->authenticated_packet_bytes -
                authenticated->authenticated_header_bytes <
            kQuicAeadTagBytes ||
        authenticated->authenticated_ciphertext_bytes !=
            authenticated->authenticated_packet_bytes -
                authenticated->authenticated_header_bytes -
                kQuicAeadTagBytes ||
        authenticated->authenticated_packet_bytes < 6u ||
        (view.payload[0] & 0xc0u) != 0xc0u ||
        static_cast<uint8_t>((view.payload[0] >> 4u) & 0x03u) !=
            expected_type_bits ||
        view.payload[5] != authenticated->destination_cid_length ||
        static_cast<size_t>(7u + authenticated->destination_cid_length +
            authenticated->source_cid_length) >
            authenticated->authenticated_packet_bytes ||
        view.payload[6u + authenticated->destination_cid_length] !=
            authenticated->source_cid_length ||
        std::memcmp(
            view.payload + 6u,
            authenticated->destination_cid,
            authenticated->destination_cid_length) != 0 ||
        std::memcmp(
            view.payload + 7u + authenticated->destination_cid_length,
            authenticated->source_cid,
            authenticated->source_cid_length) != 0 ||
        std::memcmp(
            clear_bounds.destination_cid,
            authenticated->destination_cid,
            authenticated->destination_cid_length) != 0 ||
        std::memcmp(
            clear_bounds.source_cid,
            authenticated->source_cid,
            authenticated->source_cid_length) != 0 ||
        !all_zero(authenticated->reserved0,
            sizeof(authenticated->reserved0)))
        return false;
    const uint32_t wire_version =
        (static_cast<uint32_t>(view.payload[1]) << 24u) |
        (static_cast<uint32_t>(view.payload[2]) << 16u) |
        (static_cast<uint32_t>(view.payload[3]) << 8u) |
        static_cast<uint32_t>(view.payload[4]);
    if (wire_version != authenticated->version)
        return false;
    material.cid_length = authenticated->destination_cid_length;
    material.first_wire_byte = view.payload[0];
    material.datagram_bytes = authenticated->datagram_bytes;
    material.authenticated_packet_bytes =
        authenticated->authenticated_packet_bytes;
    material.trailing_coalesced_bytes =
        authenticated->trailing_coalesced_bytes;
    std::memcpy(material.cid, view.payload + 6u, material.cid_length);
    return true;
}

bool extract_wire_material(
        const ReceiptState &state,
        const fk_owner_packet *packet,
        const fk_packet_view *view,
        const fk_quic_initial_auth_result *authenticated_initial,
        uint8_t evidence_kind,
        uint8_t placement_context,
        uint8_t fixed_owner_context,
        uint8_t short_dcid_length,
        bool issuing,
        WireMaterial &material) {
    std::memset(&material, 0, sizeof(material));
    if (!packet_descriptor_valid(state, packet, view, issuing))
        return false;
    fk_quic_route_receipt shape{};
    shape.abi_version = FK_QUIC_ROUTE_RECEIPT_ABI_VERSION;
    shape.evidence_kind = evidence_kind;
    shape.placement_context = placement_context;
    shape.fixed_owner_context = fixed_owner_context;
    shape.cid_length = evidence_kind ==
            FK_QUIC_ROUTE_EVIDENCE_EXACT_SHORT_HEADER_DCID ?
        short_dcid_length : 1u;
    uint8_t canonical_direction = 0u;
    if (!fk_quic_route_receipt_shape_valid(&shape) ||
        fk_native_flow_key(
            view, &material.canonical_udp_key,
            &canonical_direction) != FK_PARSE_OK ||
        material.canonical_udp_key.protocol != 17u)
        return false;
    material.datagram_bytes = static_cast<uint32_t>(view->payload_size);

    if (evidence_kind ==
            FK_QUIC_ROUTE_EVIDENCE_AUTHENTICATED_INITIAL_DCID)
        return initial_result_matches_wire(
            *view, authenticated_initial, material);

    if (authenticated_initial != nullptr)
        return false;
    if (evidence_kind ==
            FK_QUIC_ROUTE_EVIDENCE_EXACT_LONG_HEADER_DCID) {
        fk_quic_header_observation observation{};
        if (fk_native_inspect_quic_header(view, &observation) != FK_PARSE_OK ||
            observation.status != FK_QUIC_LONG_HEADER_PARTIAL ||
            (view->payload[0] & 0x40u) == 0u ||
            (observation.version != FK_QUIC_INITIAL_AUTH_VERSION_V1 &&
             observation.version != FK_QUIC_INITIAL_AUTH_VERSION_V2) ||
            observation.destination_cid_length == 0u)
            return false;
        material.cid_length = observation.destination_cid_length;
        material.first_wire_byte = view->payload[0];
        std::memcpy(
            material.cid,
            observation.destination_cid,
            material.cid_length);
        return true;
    }
    if (evidence_kind !=
            FK_QUIC_ROUTE_EVIDENCE_EXACT_SHORT_HEADER_DCID ||
        short_dcid_length == 0u || short_dcid_length > sizeof(material.cid) ||
        (view->payload[0] & 0x80u) != 0u ||
        static_cast<size_t>(short_dcid_length) > view->payload_size - 1u)
        return false;
    material.cid_length = short_dcid_length;
    material.first_wire_byte = view->payload[0];
    std::memcpy(material.cid, view->payload + 1u, material.cid_length);
    return true;
}

bool serialize_message(
        const ReceiptState &state,
        const fk_owner_packet &packet,
        const fk_quic_route_receipt &receipt,
        const WireMaterial &material,
        uint8_t *message,
        size_t capacity,
        size_t &message_bytes) {
    ByteWriter writer{message, capacity, 0u};
    static const uint8_t domain[8]{
        'F', 'K', 'Q', 'R', 'T', 'E', 'V', '1'};
    const bool written =
        writer.append_bytes(domain, sizeof(domain)) &&
        writer.append_u32_le(FK_QUIC_ROUTE_RECEIPT_ABI_VERSION) &&
        writer.append_u64_le(state.config.run_epoch) &&
        writer.append_u64_le(static_cast<uint64_t>(packet.packet_handle)) &&
        writer.append_u64_le(packet.logical_connection_id) &&
        writer.append_u64_le(packet.packet_sequence) &&
        writer.append_u64_le(packet.physical_ingress_timestamp_ns) &&
        writer.append_u64_le(packet.semantic_timestamp_ns) &&
        writer.append_u32_le(packet.captured_length) &&
        writer.append_u32_le(packet.wire_length) &&
        writer.append_u16_le(packet.ingress_worker) &&
        writer.append_u16_le(packet.owner_worker) &&
        writer.append_u8(packet.identity_kind) &&
        writer.append_u8(packet.feature_direction) &&
        writer.append_u8(packet.feature_direction_known) &&
        writer.append_bytes(packet.reserved, sizeof(packet.reserved)) &&
        writer.append_u8(receipt.evidence_kind) &&
        writer.append_u8(receipt.placement_context) &&
        writer.append_u8(receipt.fixed_owner_context) &&
        writer.append_u8(material.cid_length) &&
        writer.append_u8(material.first_wire_byte) &&
        writer.append_u32_le(material.datagram_bytes) &&
        writer.append_u32_le(material.authenticated_packet_bytes) &&
        writer.append_u32_le(material.trailing_coalesced_bytes) &&
        writer.append_u8(material.canonical_udp_key.ip_version) &&
        writer.append_u8(material.canonical_udp_key.protocol) &&
        writer.append_bytes(material.canonical_udp_key.low_addr, 16u) &&
        writer.append_bytes(material.canonical_udp_key.high_addr, 16u) &&
        writer.append_u16_le(material.canonical_udp_key.low_port) &&
        writer.append_u16_le(material.canonical_udp_key.high_port) &&
        writer.append_bytes(material.cid, material.cid_length);
    if (!written)
        return false;
    message_bytes = writer.size;
    return true;
}

bool calculate_tag(
        const ReceiptState &state,
        const fk_owner_packet &packet,
        const fk_quic_route_receipt &receipt,
        const WireMaterial &material,
        uint8_t tag[FK_QUIC_ROUTE_RECEIPT_TAG_BYTES]) {
    uint8_t message[192]{};
    size_t message_bytes = 0u;
    if (!serialize_message(
            state, packet, receipt, material,
            message, sizeof(message), message_bytes))
        return false;
    const uint64_t first = siphash24(
        state.config.authentication_key_0, message, message_bytes);
    const uint64_t second = siphash24(
        state.config.authentication_key_1, message, message_bytes);
    store_u64_le(first, tag);
    store_u64_le(second, tag + 8u);
    return true;
}

bool constant_time_tag_equal(
        const uint8_t left[FK_QUIC_ROUTE_RECEIPT_TAG_BYTES],
        const uint8_t right[FK_QUIC_ROUTE_RECEIPT_TAG_BYTES]) {
    uint32_t difference = 0u;
    for (size_t index = 0u; index < FK_QUIC_ROUTE_RECEIPT_TAG_BYTES;
         ++index)
        difference |= static_cast<uint32_t>(left[index] ^ right[index]);
    return difference == 0u;
}

ReceiptState *implementation(fk_quic_route_receipt_state *state) {
    return reinterpret_cast<ReceiptState *>(state);
}

const ReceiptState *implementation(const fk_quic_route_receipt_state *state) {
    return reinterpret_cast<const ReceiptState *>(state);
}

void lock_slot(ReplaySlot &slot) {
    while (slot.lock.test_and_set(std::memory_order_acquire))
        std::atomic_signal_fence(std::memory_order_seq_cst);
}

void unlock_slot(ReplaySlot &slot) {
    slot.lock.clear(std::memory_order_release);
}

}  // namespace

extern "C" {

void fk_quic_route_receipt_default_config_init(
        fk_quic_route_receipt_config *config) {
    if (config == nullptr)
        return;
    std::memset(config, 0, sizeof(*config));
    config->owner_count = 8u;
    for (size_t index = 0u; index < FK_QUIC_ROUTE_RECEIPT_KEY_BYTES;
         ++index) {
        config->authentication_key_0[index] =
            static_cast<uint8_t>(index + 1u);
        config->authentication_key_1[index] =
            static_cast<uint8_t>(0xa1u + index);
    }
    /* Callers must bind a nonzero run epoch and precommit both keys. */
}

bool fk_quic_route_receipt_config_valid(
        const fk_quic_route_receipt_config *config) {
    return required_bytes(config) != 0u;
}

size_t fk_quic_route_receipt_storage_bytes(
        const fk_quic_route_receipt_config *config) {
    return required_bytes(config);
}

fk_quic_route_receipt_state *fk_quic_route_receipt_initialize(
        void *storage,
        size_t storage_bytes,
        const fk_quic_route_receipt_config *config) {
    const size_t required = required_bytes(config);
    if (storage == nullptr || required == 0u || storage_bytes < required ||
        reinterpret_cast<uintptr_t>(storage) % alignof(max_align_t) != 0u)
        return nullptr;
    uint8_t *base = static_cast<uint8_t *>(storage);
    auto *state = new (base) ReceiptState{};
    state->config = *config;
    state->reserved_bytes = required;
    size_t offset = sizeof(ReceiptState);
    (void)align_size(offset, alignof(ReplaySlot));
    state->replay_slots = reinterpret_cast<ReplaySlot *>(base + offset);
    for (uint16_t owner = 0u; owner < config->owner_count; ++owner) {
        auto *slot = new (&state->replay_slots[owner]) ReplaySlot{};
        slot->lock.clear(std::memory_order_relaxed);
    }
    return reinterpret_cast<fk_quic_route_receipt_state *>(state);
}

void fk_quic_route_receipt_destroy(fk_quic_route_receipt_state *state) {
    if (state == nullptr)
        return;
    ReceiptState *impl = implementation(state);
    for (uint16_t owner = 0u; owner < impl->config.owner_count; ++owner)
        impl->replay_slots[owner].~ReplaySlot();
    impl->~ReceiptState();
}

fk_quic_route_receipt_result fk_quic_route_receipt_bridge_issue(
        fk_quic_route_receipt_state *state,
        const fk_quic_route_receipt_bridge_request *request,
        fk_quic_route_receipt *receipt) {
    if (receipt != nullptr)
        std::memset(receipt, 0, sizeof(*receipt));
    if (state == nullptr || receipt == nullptr)
        return FK_QUIC_ROUTE_RECEIPT_INVALID;
    ReceiptState &impl = *implementation(state);
    impl.issue_attempts.fetch_add(1u, std::memory_order_relaxed);
    if (request == nullptr ||
        !all_zero(request->reserved, sizeof(request->reserved))) {
        impl.issue_rejections.fetch_add(1u, std::memory_order_relaxed);
        return FK_QUIC_ROUTE_RECEIPT_INVALID;
    }
    WireMaterial material{};
    if (!extract_wire_material(
            impl,
            request->packet,
            request->packet_view,
            request->authenticated_initial,
            static_cast<uint8_t>(request->evidence_kind),
            static_cast<uint8_t>(request->placement_context),
            static_cast<uint8_t>(request->fixed_owner_context),
            request->resolved_short_dcid_length,
            true,
            material)) {
        impl.issue_rejections.fetch_add(1u, std::memory_order_relaxed);
        return FK_QUIC_ROUTE_RECEIPT_INVALID;
    }
    receipt->abi_version = FK_QUIC_ROUTE_RECEIPT_ABI_VERSION;
    receipt->evidence_kind = static_cast<uint8_t>(request->evidence_kind);
    receipt->placement_context =
        static_cast<uint8_t>(request->placement_context);
    receipt->fixed_owner_context =
        static_cast<uint8_t>(request->fixed_owner_context);
    receipt->cid_length = material.cid_length;
    if (!calculate_tag(
            impl, *request->packet, *receipt, material, receipt->tag)) {
        std::memset(receipt, 0, sizeof(*receipt));
        impl.issue_rejections.fetch_add(1u, std::memory_order_relaxed);
        return FK_QUIC_ROUTE_RECEIPT_INTERNAL_INTEGRITY;
    }
    impl.issued.fetch_add(1u, std::memory_order_relaxed);
    return FK_QUIC_ROUTE_RECEIPT_ACCEPTED;
}

fk_quic_route_receipt_result fk_quic_route_receipt_verify_and_consume(
        fk_quic_route_receipt_state *state,
        const fk_owner_packet *packet,
        const fk_packet_view *packet_view,
        const fk_quic_initial_auth_result *authenticated_initial) {
    if (state == nullptr)
        return FK_QUIC_ROUTE_RECEIPT_INVALID;
    ReceiptState &impl = *implementation(state);
    impl.verify_attempts.fetch_add(1u, std::memory_order_relaxed);
    if (packet == nullptr ||
        !fk_quic_route_receipt_shape_valid(&packet->route_receipt)) {
        impl.invalid_rejections.fetch_add(1u, std::memory_order_relaxed);
        return FK_QUIC_ROUTE_RECEIPT_INVALID;
    }
    const fk_quic_route_receipt &receipt = packet->route_receipt;
    WireMaterial material{};
    if (!extract_wire_material(
            impl,
            packet,
            packet_view,
            authenticated_initial,
            receipt.evidence_kind,
            receipt.placement_context,
            receipt.fixed_owner_context,
            receipt.cid_length,
            false,
            material) || material.cid_length != receipt.cid_length) {
        impl.invalid_rejections.fetch_add(1u, std::memory_order_relaxed);
        return FK_QUIC_ROUTE_RECEIPT_INVALID;
    }
    uint8_t expected[FK_QUIC_ROUTE_RECEIPT_TAG_BYTES]{};
    if (!calculate_tag(impl, *packet, receipt, material, expected)) {
        impl.internal_integrity_rejections.fetch_add(
            1u, std::memory_order_relaxed);
        return FK_QUIC_ROUTE_RECEIPT_INTERNAL_INTEGRITY;
    }
    if (!constant_time_tag_equal(expected, receipt.tag)) {
        impl.tag_mismatch_rejections.fetch_add(
            1u, std::memory_order_relaxed);
        return FK_QUIC_ROUTE_RECEIPT_TAG_MISMATCH;
    }
    ReplaySlot &slot = impl.replay_slots[packet->owner_worker];
    lock_slot(slot);
    if (slot.initialized != 0u &&
        packet->packet_sequence <= slot.last_packet_sequence) {
        unlock_slot(slot);
        impl.replay_or_reorder_rejections.fetch_add(
            1u, std::memory_order_relaxed);
        return FK_QUIC_ROUTE_RECEIPT_REPLAY_OR_REORDER;
    }
    slot.last_packet_sequence = packet->packet_sequence;
    slot.initialized = 1u;
    unlock_slot(slot);
    impl.verified.fetch_add(1u, std::memory_order_relaxed);
    return FK_QUIC_ROUTE_RECEIPT_ACCEPTED;
}

bool fk_quic_route_receipt_get_stats(
        const fk_quic_route_receipt_state *state,
        fk_quic_route_receipt_stats *stats) {
    if (state == nullptr || stats == nullptr)
        return false;
    const ReceiptState &impl = *implementation(state);
    std::memset(stats, 0, sizeof(*stats));
    stats->issue_attempts = impl.issue_attempts.load(
        std::memory_order_relaxed);
    stats->issued = impl.issued.load(std::memory_order_relaxed);
    stats->issue_rejections = impl.issue_rejections.load(
        std::memory_order_relaxed);
    stats->verify_attempts = impl.verify_attempts.load(
        std::memory_order_relaxed);
    stats->verified = impl.verified.load(std::memory_order_relaxed);
    stats->invalid_rejections = impl.invalid_rejections.load(
        std::memory_order_relaxed);
    stats->tag_mismatch_rejections = impl.tag_mismatch_rejections.load(
        std::memory_order_relaxed);
    stats->replay_or_reorder_rejections =
        impl.replay_or_reorder_rejections.load(std::memory_order_relaxed);
    stats->internal_integrity_rejections =
        impl.internal_integrity_rejections.load(std::memory_order_relaxed);
    stats->reserved_bytes = impl.reserved_bytes;
    stats->run_epoch = impl.config.run_epoch;
    stats->owner_count = impl.config.owner_count;
    stats->keys_precommitted = impl.config.keys_precommitted;
    stats->production_formal_issuance_capable = 0u;
    return fk_quic_route_receipt_stats_accounting_conserved(stats);
}

bool fk_quic_route_receipt_stats_accounting_conserved(
        const fk_quic_route_receipt_stats *stats) {
    if (stats == nullptr)
        return false;
    uint64_t issue_partition = stats->issued;
    if (stats->issue_rejections >
            std::numeric_limits<uint64_t>::max() - issue_partition)
        return false;
    issue_partition += stats->issue_rejections;

    uint64_t verify_partition = stats->verified;
    const uint64_t verify_parts[]{
        stats->invalid_rejections,
        stats->tag_mismatch_rejections,
        stats->replay_or_reorder_rejections,
        stats->internal_integrity_rejections,
    };
    for (const uint64_t part : verify_parts) {
        if (part >
                std::numeric_limits<uint64_t>::max() - verify_partition)
            return false;
        verify_partition += part;
    }
    return issue_partition == stats->issue_attempts &&
        verify_partition == stats->verify_attempts;
}

bool fk_quic_route_receipt_production_formal_issuance_capable(
        const fk_quic_route_receipt_state *state) {
    (void)state;
    return false;
}

}  // extern "C"
