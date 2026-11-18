#ifndef FLOWKEEP_FK_FORMAL_RUN_CONTRACT_H
#define FLOWKEEP_FK_FORMAL_RUN_CONTRACT_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "fk_event_result_log.h"

#ifdef __cplusplus
extern "C" {
#endif

#define FK_FORMAL_RUN_CONTRACT_VERSION 1u
#define FK_FORMAL_RUN_CONTRACT_BYTES 320u
#define FK_FORMAL_RUN_CONTRACT_ENDIAN_TAG UINT32_C(0x01020304)
#define FK_FORMAL_RUN_CONTRACT_FORMAL_DATACON UINT32_C(0x00000001)

struct fk_formal_run_contract {
    struct fk_event_result_log_header_binding header;
    uint8_t file_sha256[FK_EVENT_RESULT_LOG_SHA256_BYTES];
};

/* Unique FKRCV1 encoding. file_sha256 is not serialized (self-reference is
 * forbidden); it is SHA-256 of the returned 320 bytes. */
bool fk_formal_run_contract_encode(
    const struct fk_event_result_log_header_binding *header,
    uint8_t output[FK_FORMAL_RUN_CONTRACT_BYTES],
    char *error,
    size_t error_capacity);

/* Reads one immutable, fixed-width FKRCV1 file and verifies its separately
 * supplied lowercase SHA-256 before parsing any field. */
bool fk_formal_run_contract_load(
    const char *path,
    const char *expected_file_sha256,
    struct fk_formal_run_contract *contract,
    char *error,
    size_t error_capacity);

/* Exact byte/bit comparison against the locally computed FKERES header. */
bool fk_formal_run_contract_matches_header(
    const struct fk_formal_run_contract *contract,
    const struct fk_event_result_log_header_binding *header,
    char *error,
    size_t error_capacity);

#ifdef __cplusplus
}
#endif

#endif
