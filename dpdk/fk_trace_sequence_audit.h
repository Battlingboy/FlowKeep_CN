#ifndef FLOWKEEP_FK_TRACE_SEQUENCE_AUDIT_H
#define FLOWKEEP_FK_TRACE_SEQUENCE_AUDIT_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Concurrent, allocation-free audit of the exact FKTSV1 packet sequence.
 *
 * The caller allocates the storage once at startup.  RX workers may then call
 * observe() concurrently.  The bitmap is experimental provenance metadata,
 * not retained flow evidence, so callers must account for it separately from
 * the controlled FLOWKEEP state budget.
 */
struct fk_trace_sequence_audit;

struct fk_trace_sequence_audit_stats {
    uint64_t expected_sequences;
    uint64_t unique_sequences;
    uint64_t duplicate_sequences;
    uint64_t out_of_range_sequences;
    uint64_t contiguous_prefix_sequences;
    uint64_t lowest_sequence;
    uint64_t highest_sequence;
    uint64_t internal_gaps_through_highest;
    uint64_t total_missing_sequences;
    uint64_t bitmap_bytes;
    uint64_t reserved_bytes;
    bool has_observation;
    bool complete;
    bool integrity_passed;
};

size_t fk_trace_sequence_audit_storage_bytes(
    uint64_t expected_sequences);

struct fk_trace_sequence_audit *fk_trace_sequence_audit_init(
    void *storage,
    size_t storage_bytes,
    uint64_t expected_sequences,
    char *error,
    size_t error_capacity);

/*
 * Returns true exactly once for each in-range sequence.  The RX worker must
 * call this only after it has finished parsing the packet and publishing all
 * FLOW_OPEN/checkpoint messages derived from it.  Duplicate and out-of-range
 * inputs return false and are counted independently.
 */
bool fk_trace_sequence_audit_observe(
    struct fk_trace_sequence_audit *audit,
    uint64_t sequence);

/* Vector form for one strictly increasing owner-local release batch.  It
 * preserves the exact bitmap/duplicate evidence while issuing at most one
 * atomic OR per 64 packet sequences. */
bool fk_trace_sequence_audit_observe_batch(
    struct fk_trace_sequence_audit *audit,
    const uint64_t *sequences,
    uint32_t count);

/*
 * Advance the exact zero-based contiguous prefix visible in the bitmap.
 * Exactly one non-RX owner (the global association aggregator) may call this
 * function.  A returned value N proves that every sequence in [0,N) has
 * fully processed and published, so messages sourced from sequence < N can
 * be released without a guessed wall-clock reorder delay.
 */
bool fk_trace_sequence_audit_advance_contiguous(
    struct fk_trace_sequence_audit *audit,
    uint64_t *contiguous_prefix_sequences);

/* Scheduling only: advance the caller-owned cursor through observations OR
 * explicitly recorded losses. Neither input bitmap is changed; the ordinary
 * completeness/duplicate audit remains authoritative. */
bool fk_trace_sequence_audit_advance_resolved(
    const struct fk_trace_sequence_audit *audit,
    const struct fk_trace_sequence_audit *losses,
    uint64_t *resolved_prefix);

/* Acquired bitmap word for a controller which has an independent producer
 * frontier proof. A missing bit alone is never permission to declare loss. */
bool fk_trace_sequence_audit_load_word(
    const struct fk_trace_sequence_audit *audit,
    uint64_t word_index, uint64_t *word);

/*
 * Take a snapshot after RX workers have stopped.  A concurrent snapshot is
 * memory-safe but may be internally transient and is not a formal receipt.
 */
bool fk_trace_sequence_audit_get_stats(
    const struct fk_trace_sequence_audit *audit,
    struct fk_trace_sequence_audit_stats *stats);

#ifdef __cplusplus
}
#endif

#endif
