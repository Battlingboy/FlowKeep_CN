#ifndef FLOWKEEP_FK_SOURCE_RECORD_INTERVENTION_PLAN_H
#define FLOWKEEP_FK_SOURCE_RECORD_INTERVENTION_PLAN_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "fk_compact_runtime.h"

#ifdef __cplusplus
extern "C" {
#endif

#define FK_SOURCE_RECORD_INTERVENTION_PLAN_ABI_VERSION 1u
#define FK_SOURCE_RECORD_INTERVENTION_PLAN_HEADER_BYTES 320u
#define FK_SOURCE_RECORD_INTERVENTION_PLAN_VICTIM_BYTES 80u
#define FK_SOURCE_RECORD_INTERVENTION_SHA256_BYTES 32u

/* Load-time receipt for the immutable Development-only source binding.  The
 * runtime receipt separately proves the semantic checkpoint transaction. */
struct fk_source_record_intervention_plan_receipt_v1 {
    uint32_t abi_version;
    uint32_t record_bytes;
    uint64_t plan_file_bytes;
    uint64_t packet_lineage_file_bytes;
    uint64_t packet_lineage_record_count;
    uint64_t source_packet_sequence;
    uint64_t source_record_sequence;
    uint64_t source_timestamp_ns;
    uint64_t output_timestamp_ns;
    uint32_t source_index;
    uint32_t source_segment_index;
    uint32_t source_segment_count;
    uint32_t victim_count;
    uint8_t plan_sha256[FK_SOURCE_RECORD_INTERVENTION_SHA256_BYTES];
    uint8_t pcap_sha256[FK_SOURCE_RECORD_INTERVENTION_SHA256_BYTES];
    uint8_t packet_lineage_sha256[
        FK_SOURCE_RECORD_INTERVENTION_SHA256_BYTES];
    uint8_t checkpoint_sidecar_sha256[
        FK_SOURCE_RECORD_INTERVENTION_SHA256_BYTES];
    uint8_t conflict_id_sha256[
        FK_SOURCE_RECORD_INTERVENTION_SHA256_BYTES];
    uint8_t development_scope;
    uint8_t official_test_accessed;
    uint8_t primary_validation_accessed;
    uint8_t offline_event_bag_used;
    uint8_t global_optimal_closed_loop_claimed;
    uint8_t packet_lineage_exact_match;
    uint8_t pcap_sha256_match;
    uint8_t independent_process_required;
    uint8_t controlled_one_step_intervention;
    uint8_t complete;
    uint8_t reserved[6];
};

/* Decode a fixed little-endian FKSRINT1 plan and prove its exact FKPLV1
 * output-packet -> source-record binding.  Both files are read and SHA-256
 * verified before any runtime state exists. */
bool fk_source_record_intervention_plan_load(
    const char *plan_path,
    const char *packet_lineage_path,
    const uint8_t observed_pcap_sha256[
        FK_SOURCE_RECORD_INTERVENTION_SHA256_BYTES],
    uint64_t observed_pcap_packet_count,
    struct fk_compact_checkpoint_intervention_v1 *intervention,
    struct fk_source_record_intervention_plan_receipt_v1 *receipt,
    char *error,
    size_t error_capacity);

#ifdef __cplusplus
}
#endif

#endif
