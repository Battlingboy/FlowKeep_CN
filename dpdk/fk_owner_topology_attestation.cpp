#include "fk_owner_topology_attestation.h"

#include <cinttypes>
#include <cstddef>
#include <cstdio>

namespace {

constexpr uint64_t kFnvOffset = UINT64_C(14695981039346656037);
constexpr uint64_t kFnvPrime = UINT64_C(1099511628211);

static_assert(sizeof(fk_owner_topology_attestation) == 88u,
    "owner-topology attestation ABI changed");
static_assert(offsetof(fk_owner_topology_attestation,
        canonical_config_hash) == 16u &&
    offsetof(fk_owner_topology_attestation, cid_receipt) == 24u &&
    offsetof(fk_owner_topology_attestation, binding_receipt) == 56u,
    "owner-topology attestation layout changed");

void hash_byte(uint64_t &hash, uint8_t value) {
    hash ^= value;
    hash *= kFnvPrime;
}

void hash_u16(uint64_t &hash, uint16_t value) {
    hash_byte(hash, static_cast<uint8_t>(value));
    hash_byte(hash, static_cast<uint8_t>(value >> 8u));
}

void hash_u32(uint64_t &hash, uint32_t value) {
    hash_u16(hash, static_cast<uint16_t>(value));
    hash_u16(hash, static_cast<uint16_t>(value >> 16u));
}

uint64_t canonical_hash(
        const fk_quic_cid_map_topology_receipt &receipt) {
    static constexpr char kDomain[] = "FLOWKEEP_OWNER_TOPOLOGY_V1";
    uint64_t hash = kFnvOffset;
    for (size_t index = 0u; index + 1u < sizeof(kDomain); ++index)
        hash_byte(hash, static_cast<uint8_t>(kDomain[index]));
    hash_u32(hash, receipt.receipt_abi_version);
    hash_u16(hash, receipt.logical_id_abi_version);
    hash_byte(hash, receipt.logical_id_bits);
    hash_byte(hash, receipt.logical_id_generation_bits);
    hash_byte(hash, receipt.logical_id_encoded_slot_bits);
    hash_byte(hash, receipt.logical_id_full_width);
    hash_byte(hash, receipt.retire_ack_required);
    hash_u16(hash, receipt.fixed_owner_count);
    hash_u32(hash, receipt.maximum_connection_slots);
    return hash;
}

void set_error(
        char *error,
        size_t error_capacity,
        uint32_t failure_flags) {
    if (error == nullptr || error_capacity == 0u)
        return;
    if (failure_flags == 0u) {
        error[0] = '\0';
        return;
    }
    std::snprintf(
        error,
        error_capacity,
        "owner topology attestation rejected: failure_flags=0x%08" PRIx32,
        failure_flags);
}

}  // namespace

bool fk_owner_topology_attest_receipts(
        const fk_quic_cid_map_topology_receipt *cid_receipt,
        const fk_owner_flow_bindings_topology_receipt *binding_receipt,
        fk_owner_topology_attestation *attestation,
        char *error,
        size_t error_capacity) {
    if (attestation != nullptr)
        *attestation = {};
    if (error != nullptr && error_capacity != 0u)
        error[0] = '\0';
    if (attestation == nullptr) {
        set_error(
            error, error_capacity,
            FK_OWNER_TOPOLOGY_ATTESTATION_FAILURE_INVALID_ARGUMENT);
        return false;
    }

    attestation->attestation_abi_version =
        FK_OWNER_TOPOLOGY_ATTESTATION_ABI_VERSION;
    if (cid_receipt == nullptr || binding_receipt == nullptr) {
        attestation->failure_flags =
            FK_OWNER_TOPOLOGY_ATTESTATION_FAILURE_INVALID_ARGUMENT;
        set_error(error, error_capacity, attestation->failure_flags);
        return false;
    }

    attestation->cid_receipt = *cid_receipt;
    attestation->binding_receipt = *binding_receipt;
    attestation->canonical_config_hash = canonical_hash(*cid_receipt);

    uint32_t failures = 0u;
    if (cid_receipt->receipt_abi_version !=
            FK_QUIC_CID_MAP_TOPOLOGY_RECEIPT_ABI_VERSION ||
        binding_receipt->receipt_abi_version !=
            FK_OWNER_FLOW_BINDINGS_TOPOLOGY_RECEIPT_ABI_VERSION ||
        cid_receipt->receipt_abi_version !=
            binding_receipt->receipt_abi_version) {
        failures |= FK_OWNER_TOPOLOGY_ATTESTATION_FAILURE_RECEIPT_ABI;
    }
    if (cid_receipt->logical_id_abi_version !=
            FK_QUIC_LOGICAL_ID_ABI_VERSION ||
        binding_receipt->logical_id_abi_version !=
            FK_QUIC_LOGICAL_ID_ABI_VERSION ||
        cid_receipt->logical_id_abi_version !=
            binding_receipt->logical_id_abi_version) {
        failures |= FK_OWNER_TOPOLOGY_ATTESTATION_FAILURE_LOGICAL_ID_ABI;
    }
    if (cid_receipt->logical_id_bits !=
            FK_QUIC_LOGICAL_ID_FULL_WIDTH_BITS ||
        binding_receipt->logical_id_bits !=
            FK_QUIC_LOGICAL_ID_FULL_WIDTH_BITS ||
        cid_receipt->logical_id_bits != binding_receipt->logical_id_bits) {
        failures |= FK_OWNER_TOPOLOGY_ATTESTATION_FAILURE_LOGICAL_ID_BITS;
    }
    if (cid_receipt->logical_id_full_width != 1u ||
        binding_receipt->logical_id_full_width != 1u ||
        cid_receipt->logical_id_full_width !=
            binding_receipt->logical_id_full_width) {
        failures |= FK_OWNER_TOPOLOGY_ATTESTATION_FAILURE_FULL_WIDTH;
    }
    if (cid_receipt->logical_id_generation_bits !=
            FK_QUIC_LOGICAL_ID_GENERATION_BITS ||
        binding_receipt->logical_id_generation_bits !=
            FK_QUIC_LOGICAL_ID_GENERATION_BITS ||
        cid_receipt->logical_id_generation_bits !=
            binding_receipt->logical_id_generation_bits) {
        failures |= FK_OWNER_TOPOLOGY_ATTESTATION_FAILURE_GENERATION_BITS;
    }
    if (cid_receipt->logical_id_encoded_slot_bits !=
            FK_QUIC_LOGICAL_ID_ENCODED_SLOT_BITS ||
        binding_receipt->logical_id_encoded_slot_bits !=
            FK_QUIC_LOGICAL_ID_ENCODED_SLOT_BITS ||
        cid_receipt->logical_id_encoded_slot_bits !=
            binding_receipt->logical_id_encoded_slot_bits) {
        failures |=
            FK_OWNER_TOPOLOGY_ATTESTATION_FAILURE_ENCODED_SLOT_BITS;
    }
    if (cid_receipt->retire_ack_required != 1u ||
        binding_receipt->retire_ack_required != 1u ||
        cid_receipt->retire_ack_required !=
            binding_receipt->retire_ack_required) {
        failures |= FK_OWNER_TOPOLOGY_ATTESTATION_FAILURE_RETIRE_ACK;
    }
    if (cid_receipt->fixed_owner_count == 0u ||
        binding_receipt->fixed_owner_count == 0u ||
        cid_receipt->fixed_owner_count !=
            binding_receipt->fixed_owner_count) {
        failures |=
            FK_OWNER_TOPOLOGY_ATTESTATION_FAILURE_FIXED_OWNER_COUNT;
    }
    if (cid_receipt->maximum_connection_slots == 0u ||
        binding_receipt->maximum_connection_slots == 0u ||
        cid_receipt->maximum_connection_slots !=
            binding_receipt->maximum_connection_slots) {
        failures |= FK_OWNER_TOPOLOGY_ATTESTATION_FAILURE_CONNECTION_SLOTS;
    }
    if (cid_receipt->reserved0 != 0u || cid_receipt->reserved1 != 0u ||
        cid_receipt->reserved2 != 0u ||
        binding_receipt->reserved0 != 0u ||
        binding_receipt->reserved1 != 0u ||
        binding_receipt->reserved2 != 0u) {
        failures |= FK_OWNER_TOPOLOGY_ATTESTATION_FAILURE_RESERVED_FIELD;
    }
    if (cid_receipt->topology_config_hash == 0u ||
        cid_receipt->topology_config_hash !=
            binding_receipt->topology_config_hash) {
        failures |=
            FK_OWNER_TOPOLOGY_ATTESTATION_FAILURE_RECEIPT_HASH_MISMATCH;
    }
    if (cid_receipt->topology_config_hash !=
        attestation->canonical_config_hash) {
        failures |=
            FK_OWNER_TOPOLOGY_ATTESTATION_FAILURE_CID_CANONICAL_HASH;
    }
    if (binding_receipt->topology_config_hash !=
        attestation->canonical_config_hash) {
        failures |=
            FK_OWNER_TOPOLOGY_ATTESTATION_FAILURE_BINDING_CANONICAL_HASH;
    }

    attestation->failure_flags = failures;
    attestation->passed = failures == 0u ? 1u : 0u;
    set_error(error, error_capacity, failures);
    return failures == 0u;
}
