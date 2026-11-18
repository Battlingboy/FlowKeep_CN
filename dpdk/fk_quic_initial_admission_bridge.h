#ifndef FLOWKEEP_FK_QUIC_INITIAL_ADMISSION_BRIDGE_H
#define FLOWKEEP_FK_QUIC_INITIAL_ADMISSION_BRIDGE_H

#include <stdbool.h>

#include "fk_quic_cid_map.h"
#include "fk_quic_initial_auth.h"

#ifdef __cplusplus
extern "C" {
#endif

#define FK_QUIC_INITIAL_ADMISSION_BRIDGE_ABI_VERSION 1u

/* Convert only a successful cryptographic authenticator result into the
 * clear observation and exact 60-byte proof consumed by the CID map. Outputs
 * are cleared on failure. This value-only adapter performs no allocation. */
bool fk_quic_initial_auth_to_cid_admission(
    const struct fk_quic_initial_auth_result *authenticated,
    struct fk_quic_header_observation *observation,
    struct fk_quic_cid_initial_admission_proof *proof);

#ifdef __cplusplus
}
#endif

#endif
