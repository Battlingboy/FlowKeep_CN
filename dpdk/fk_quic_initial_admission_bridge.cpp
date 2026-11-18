#include "fk_quic_initial_admission_bridge.h"

#include <cstring>
#include <type_traits>

namespace {

template <typename Enum>
typename std::underlying_type<Enum>::type enum_representation(
        const Enum &value) {
    using Underlying = typename std::underlying_type<Enum>::type;
    static_assert(
        sizeof(Underlying) == sizeof(Enum),
        "enum representation size changed");
    Underlying raw{};
    std::memcpy(&raw, &value, sizeof(raw));
    return raw;
}

bool reserved_zero(const fk_quic_initial_auth_result &result) {
    for (uint8_t byte : result.reserved0) {
        if (byte != 0u)
            return false;
    }
    return true;
}

}  // namespace

bool fk_quic_initial_auth_to_cid_admission(
        const fk_quic_initial_auth_result *authenticated,
        fk_quic_header_observation *observation,
        fk_quic_cid_initial_admission_proof *proof) {
    if (observation != nullptr)
        std::memset(observation, 0, sizeof(*observation));
    if (proof != nullptr)
        std::memset(proof, 0, sizeof(*proof));
    if (authenticated == nullptr || observation == nullptr ||
        proof == nullptr)
        return false;

    const auto decision = enum_representation(authenticated->decision);
    const auto reason = enum_representation(authenticated->reason);
    const bool v1 = authenticated->version ==
        FK_QUIC_INITIAL_AUTH_VERSION_V1;
    const bool v2 = authenticated->version ==
        FK_QUIC_INITIAL_AUTH_VERSION_V2;
    const uint8_t expected_type_bits = v1 ? 0u : 1u;
    if (authenticated->abi_version != FK_QUIC_INITIAL_AUTH_ABI_VERSION ||
        decision != FK_QUIC_INITIAL_AUTHENTICATED ||
        reason != FK_QUIC_INITIAL_AUTH_REASON_NONE || (!v1 && !v2) ||
        authenticated->fixed_bit_verified != 1u ||
        authenticated->long_packet_type_bits != expected_type_bits ||
        authenticated->destination_cid_length <
            FK_QUIC_INITIAL_AUTH_MIN_CLIENT_DCID_BYTES ||
        authenticated->destination_cid_length > FK_QUIC_CID_MAX_BYTES ||
        authenticated->source_cid_length > FK_QUIC_CID_MAX_BYTES ||
        authenticated->datagram_bytes <
            FK_QUIC_INITIAL_AUTH_MIN_DATAGRAM_BYTES ||
        authenticated->datagram_bytes >
            FK_QUIC_INITIAL_AUTH_MAX_DATAGRAM_BYTES ||
        authenticated->authenticated_packet_bytes == 0u ||
        authenticated->authenticated_packet_bytes >
            authenticated->datagram_bytes ||
        authenticated->trailing_coalesced_bytes !=
            authenticated->datagram_bytes -
                authenticated->authenticated_packet_bytes ||
        authenticated->authenticated_header_bytes == 0u ||
        authenticated->authenticated_ciphertext_bytes < 16u ||
        authenticated->authenticated_header_bytes >
            authenticated->authenticated_packet_bytes ||
        authenticated->authenticated_packet_bytes -
                authenticated->authenticated_header_bytes < 16u ||
        authenticated->authenticated_ciphertext_bytes !=
            authenticated->authenticated_packet_bytes -
                authenticated->authenticated_header_bytes - 16u ||
        authenticated->packet_number_bytes == 0u ||
        authenticated->packet_number_bytes > 4u ||
        !reserved_zero(*authenticated)) {
        return false;
    }

    observation->status = FK_QUIC_LONG_HEADER_PARTIAL;
    observation->completeness = FK_COMPLETENESS_PARTIAL;
    observation->long_packet_type = FK_QUIC_LONG_PACKET_INITIAL;
    observation->version = authenticated->version;
    observation->long_packet_type_bits =
        authenticated->long_packet_type_bits;
    observation->destination_cid_length =
        authenticated->destination_cid_length;
    observation->source_cid_length = authenticated->source_cid_length;
    std::memcpy(
        observation->destination_cid,
        authenticated->destination_cid,
        authenticated->destination_cid_length);
    std::memcpy(
        observation->source_cid,
        authenticated->source_cid,
        authenticated->source_cid_length);

    proof->abi_version =
        FK_QUIC_CID_INITIAL_ADMISSION_PROOF_ABI_VERSION;
    proof->authentication_method =
        FK_QUIC_CID_INITIAL_AUTH_AEAD_VERIFIED;
    proof->version = authenticated->version;
    proof->fixed_bit = 1u;
    proof->long_packet_type_bits =
        authenticated->long_packet_type_bits;
    proof->destination_cid_length =
        authenticated->destination_cid_length;
    proof->source_cid_length = authenticated->source_cid_length;
    std::memcpy(
        proof->destination_cid,
        authenticated->destination_cid,
        authenticated->destination_cid_length);
    std::memcpy(
        proof->source_cid,
        authenticated->source_cid,
        authenticated->source_cid_length);
    return true;
}
