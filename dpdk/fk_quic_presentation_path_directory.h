#ifndef FLOWKEEP_FK_QUIC_PRESENTATION_PATH_DIRECTORY_H
#define FLOWKEEP_FK_QUIC_PRESENTATION_PATH_DIRECTORY_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "fk_native_parser.h"
#include "fk_quic_logical_id.h"

#ifdef __cplusplus
extern "C" {
#endif

#define FK_QUIC_PRESENTATION_PATH_DIRECTORY_ABI_VERSION 1u
#define FK_QUIC_PRESENTATION_PATH_ENTRY_BYTES 88u
#define FK_QUIC_PRESENTATION_PATH_CONNECTION_ENTRY_BYTES 16u

/*
 * This is a conservative QUIC/non-QUIC classification directory, not a CID
 * resolver.  A five tuple can prove only that a presentation path has
 * previously carried authenticated QUIC.  It can never prove which logical
 * connection owns a packet with an unknown or rotated short-header CID.
 * Consequently classify() deliberately returns no logical connection id.
 *
 * Every byte is caller-provided placement storage.  Calls are serialized by
 * the single identity stage; this module performs no allocation or locking.
 */
struct fk_quic_presentation_path_directory_config {
    uint32_t maximum_logical_connections;
    uint32_t maximum_paths;
    uint16_t maximum_paths_per_connection;
    uint16_t reserved0;
    uint32_t maximum_hash_chain;
    uint32_t expiration_scan_per_operation;
    uint32_t reserved1;
    uint64_t path_ttl_ns;
    uint8_t siphash_key[16];
    uint8_t siphash_key_precommitted;
    uint8_t reserved[7];
};

enum fk_quic_presentation_path_code {
    FK_QUIC_PRESENTATION_PATH_NOT_KNOWN = 0,
    FK_QUIC_PRESENTATION_PATH_KNOWN_QUIC_PATH = 1,
    FK_QUIC_PRESENTATION_PATH_AMBIGUOUS = 2,
    FK_QUIC_PRESENTATION_PATH_REJECTED = 3,
};

enum fk_quic_presentation_path_reject_reason {
    FK_QUIC_PRESENTATION_PATH_REJECT_NONE = 0,
    FK_QUIC_PRESENTATION_PATH_REJECT_INVALID_INPUT = 1,
    FK_QUIC_PRESENTATION_PATH_REJECT_TIME_REGRESSION = 2,
    FK_QUIC_PRESENTATION_PATH_REJECT_GLOBAL_CAPACITY = 3,
    FK_QUIC_PRESENTATION_PATH_REJECT_PER_CONNECTION_CAPACITY = 4,
    FK_QUIC_PRESENTATION_PATH_REJECT_HASH_CHAIN_CAPACITY = 5,
    FK_QUIC_PRESENTATION_PATH_REJECT_LOGICAL_GENERATION_CONFLICT = 6,
    FK_QUIC_PRESENTATION_PATH_REJECT_BYTE_TIME_OVERFLOW = 7,
    FK_QUIC_PRESENTATION_PATH_REJECT_INTERNAL_INTEGRITY = 8,
};

/* Intentionally contains classification and cardinality only--never an id. */
struct fk_quic_presentation_path_classification {
    enum fk_quic_presentation_path_code code;
    enum fk_quic_presentation_path_reject_reason reason;
    uint32_t matching_logical_connections;
    uint8_t registration_created;
    uint8_t registration_refreshed;
    uint8_t reserved[2];
};

enum fk_quic_presentation_path_release_result {
    FK_QUIC_PRESENTATION_PATH_RELEASE_INVALID = 0,
    FK_QUIC_PRESENTATION_PATH_RELEASE_NOT_FOUND = 1,
    FK_QUIC_PRESENTATION_PATH_RELEASED = 2,
    FK_QUIC_PRESENTATION_PATH_RELEASE_REJECTED = 3,
};

struct fk_quic_presentation_path_directory_stats {
    uint64_t classify_calls;
    uint64_t authenticated_register_calls;
    uint64_t release_calls;
    uint64_t known_classifications;
    uint64_t not_known_classifications;
    uint64_t ambiguous_classifications;
    uint64_t rejected_operations;
    uint64_t paths_registered;
    uint64_t paths_refreshed;
    uint64_t paths_released;
    uint64_t paths_expired;
    uint64_t logical_connections_released;
    uint64_t expiration_scan_calls;
    uint64_t expiration_slots_scanned;
    uint64_t invalid_input_rejects;
    uint64_t time_regression_rejects;
    uint64_t global_capacity_rejects;
    uint64_t per_connection_capacity_rejects;
    uint64_t hash_chain_capacity_rejects;
    uint64_t logical_generation_conflict_rejects;
    uint64_t byte_time_overflow_rejects;
    uint64_t internal_integrity_rejects;
    uint64_t accounting_failures;

    uint64_t reserved_bytes;
    uint64_t fixed_bytes;
    uint64_t used_bytes;
    uint64_t peak_used_bytes;
    /* Exact unsigned 128-bit integral of used_bytes over semantic ns. */
    uint64_t state_byte_nanoseconds_low;
    uint64_t state_byte_nanoseconds_high;
    uint64_t last_semantic_timestamp_ns;

    uint32_t active_logical_connections;
    uint32_t peak_active_logical_connections;
    uint32_t active_paths;
    uint32_t peak_active_paths;
    uint32_t maximum_logical_connections;
    uint32_t maximum_paths;
    uint32_t hash_bucket_count;
    uint16_t maximum_paths_per_connection;
    uint16_t path_entry_bytes;
    uint16_t connection_entry_bytes;
    uint8_t semantic_timestamp_set;
    uint8_t siphash_key_precommitted;
};

#define FK_QUIC_PRESENTATION_PATH_FINITE_EPOCH_DRAIN_RECEIPT_ABI_VERSION 1u

enum fk_quic_presentation_path_finite_epoch_drain_reason {
    FK_QUIC_PRESENTATION_PATH_FINITE_EPOCH_DRAIN_REASON_NONE = 0,
    FK_QUIC_PRESENTATION_PATH_FINITE_EPOCH_DRAIN_IDLE_TIMEOUT_AFTER_EOF = 1,
};

/* Value-only proof that a quiescent finite input epoch expired every
 * remaining authenticated presentation path at its preregistered terminal
 * watermark.  The caller must first stop/join packet producers and identity
 * processing; this API never decides that EOF has occurred. */
struct fk_quic_presentation_path_finite_epoch_drain_receipt_v1 {
    uint32_t abi_version;
    enum fk_quic_presentation_path_finite_epoch_drain_reason reason;
    uint64_t terminal_semantic_timestamp_ns;
    uint32_t active_logical_connections_before;
    uint32_t active_paths_before;
    uint32_t paths_drained;
    uint32_t active_logical_connections_after;
    uint32_t active_paths_after;
    uint8_t complete;
    uint8_t reserved[3];
};

struct fk_quic_presentation_path_directory;

void fk_quic_presentation_path_directory_default_config_init(
    struct fk_quic_presentation_path_directory_config *config);

bool fk_quic_presentation_path_directory_config_valid(
    const struct fk_quic_presentation_path_directory_config *config);

/* Exact reservation, including metadata, buckets, entries and alignment. */
size_t fk_quic_presentation_path_directory_storage_bytes(
    const struct fk_quic_presentation_path_directory_config *config);

struct fk_quic_presentation_path_directory *
fk_quic_presentation_path_directory_initialize(
    void *storage,
    size_t storage_bytes,
    const struct fk_quic_presentation_path_directory_config *config,
    char *error,
    size_t error_capacity);

void fk_quic_presentation_path_directory_destroy(
    struct fk_quic_presentation_path_directory *directory);

/*
 * Placement-path lookup only.  KNOWN means "do not downgrade this packet to
 * ordinary UDP"; it never authorizes association to any logical connection.
 * An unauthenticated lookup does not refresh TTL.
 */
enum fk_quic_presentation_path_code
fk_quic_presentation_path_directory_classify(
    struct fk_quic_presentation_path_directory *directory,
    const struct fk_flow_key *canonical_udp_key,
    uint64_t semantic_timestamp_ns,
    struct fk_quic_presentation_path_classification *classification);

/*
 * The only mutation-capable admission API.  The caller must have obtained
 * the nonzero full-width logical id from an authenticated Initial or an exact
 * CID-directory resolution for this packet.  The directory cannot create or
 * infer logical identities itself.
 */
enum fk_quic_presentation_path_code
fk_quic_presentation_path_directory_register_authenticated(
    struct fk_quic_presentation_path_directory *directory,
    uint64_t cid_directory_logical_connection_id,
    const struct fk_flow_key *canonical_udp_key,
    uint64_t semantic_timestamp_ns,
    struct fk_quic_presentation_path_classification *classification);

/* Removes every path for the exact logical-id generation. */
enum fk_quic_presentation_path_release_result
fk_quic_presentation_path_directory_release_logical_connection(
    struct fk_quic_presentation_path_directory *directory,
    uint64_t logical_connection_id,
    uint64_t semantic_timestamp_ns,
    uint32_t *released_paths);

/* Quiescent finite-epoch drain.  A timestamp earlier than any active path's
 * frozen idle expiry fails before lifecycle mutation.  Successful removals
 * are accounted as formal expirations, never capacity eviction or drop. */
bool fk_quic_presentation_path_directory_drain_finite_epoch(
    struct fk_quic_presentation_path_directory *directory,
    uint64_t terminal_semantic_timestamp_ns,
    struct fk_quic_presentation_path_finite_epoch_drain_receipt_v1 *receipt);

bool fk_quic_presentation_path_directory_get_stats(
    const struct fk_quic_presentation_path_directory *directory,
    struct fk_quic_presentation_path_directory_stats *stats);

/* Full cold-path invariant audit; performs no allocation. */
bool fk_quic_presentation_path_directory_accounting_conserved(
    struct fk_quic_presentation_path_directory *directory);

#ifdef __cplusplus
}
#endif

#endif
