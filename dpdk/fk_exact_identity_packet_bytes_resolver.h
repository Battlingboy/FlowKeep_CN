#ifndef FLOWKEEP_FK_EXACT_IDENTITY_PACKET_BYTES_RESOLVER_H
#define FLOWKEEP_FK_EXACT_IDENTITY_PACKET_BYTES_RESOLVER_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define FK_EXACT_IDENTITY_PACKET_BYTES_RESOLVER_ABI_VERSION 1u

typedef bool (*fk_exact_identity_packet_bytes_resolve_callback)(
    void *context,
    uintptr_t exact_packet_handle,
    const uint8_t **frame,
    size_t *captured_length,
    uint32_t *wire_length);

/* DPDK-independent, exact-handle byte resolver used only while the identity
 * stage owns an immutable packet claim.  Callers must reject any resolver
 * that cannot prove all three capability flags. */
struct fk_exact_identity_packet_bytes_resolver {
    uint32_t abi_version;
    uint8_t exact_handle_binding;
    uint8_t immutable_while_claimed;
    uint8_t contiguous_frame;
    uint8_t reserved0;
    void *context;
    fk_exact_identity_packet_bytes_resolve_callback resolve;
};

#ifdef __cplusplus
}
#endif

#endif
