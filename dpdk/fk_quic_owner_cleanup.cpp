#include "fk_quic_owner_cleanup.h"

#include "fk_compact_runtime.h"

#include <cstring>
#include <initializer_list>
#include <limits>

namespace {

bool byte_flags_valid(const fk_quic_cid_retirement &retirement) {
    return retirement.packet_sequence_known <= 1u &&
        retirement.expired <= 1u &&
        retirement.binding_expected <= 1u &&
        retirement.retirement_timestamp_known <= 1u &&
        retirement.retirement_timestamp_formal <= 1u &&
        retirement.reserved[0] == 0u;
}

bool retirement_shape_valid(
        const fk_quic_owner_cleanup_adapter &adapter,
        const fk_quic_cid_retirement &retirement) {
    if (!byte_flags_valid(retirement) ||
        retirement.fixed_owner != adapter.fixed_owner ||
        retirement.retirement_ordinal == 0u ||
        (retirement.retirement_timestamp_formal != 0u &&
         retirement.retirement_timestamp_known == 0u) ||
        (retirement.expired != 0u &&
         (retirement.retirement_timestamp_known == 0u ||
          retirement.retirement_timestamp_formal == 0u)) ||
        (retirement.retirement_timestamp_known == 0u &&
         retirement.retirement_timestamp_ns != 0u) ||
        (retirement.packet_sequence_known == 0u &&
         retirement.packet_sequence != 0u)) {
        return false;
    }
    uint32_t slot = 0u;
    uint32_t generation = 0u;
    return fk_quic_logical_id_decode(
        retirement.logical_connection_id,
        adapter.maximum_connection_slots,
        &slot,
        &generation);
}

bool immutable_snapshot_matches(
        const fk_quic_cid_retirement &expected,
        const fk_quic_cid_retirement &current) {
    return expected.logical_connection_id ==
            current.logical_connection_id &&
        expected.retirement_ordinal == current.retirement_ordinal &&
        expected.packet_sequence == current.packet_sequence &&
        expected.retirement_timestamp_ns ==
            current.retirement_timestamp_ns &&
        expected.fixed_owner == current.fixed_owner &&
        expected.packet_sequence_known == current.packet_sequence_known &&
        expected.expired == current.expired &&
        expected.retirement_timestamp_known ==
            current.retirement_timestamp_known &&
        expected.retirement_timestamp_formal ==
            current.retirement_timestamp_formal &&
        /* CID may learn that an earlier queued DATA envelope established a
         * binding after peek.  That transition is monotonic: 0 -> 1 is the
         * only permitted mismatch; 1 -> 0 would erase established truth. */
        (expected.binding_expected == 0u ||
         current.binding_expected == 1u);
}

bool retained_binding_valid(
        const fk_quic_owner_cleanup_context &context,
        const fk_owner_flow_binding &binding) {
    if (binding.logical_connection_id !=
            context.expected_retirement.logical_connection_id ||
        binding.logical_feature_to_presentation_direction_xor > 1u) {
        return false;
    }
    for (uint8_t byte : binding.reserved) {
        if (byte != 0u)
            return false;
    }
    if (binding.handle.generation == 0u)
        return binding.handle.index == 0u;
    return binding.handle.index <= FK_OWNER_FLOW_BINDINGS_MAX_FLOW_INDEX;
}

bool counter_partition_conserved(
        uint64_t expected,
        std::initializer_list<uint64_t> parts) {
    uint64_t observed = 0u;
    for (const uint64_t part : parts) {
        if (part > std::numeric_limits<uint64_t>::max() - observed)
            return false;
        observed += part;
    }
    return observed == expected;
}

bool counters_conserved(const fk_quic_owner_cleanup_stats &stats) {
    return counter_partition_conserved(
            stats.context_prepare_attempts,
            {stats.contexts_prepared,
             stats.context_prepare_rejects}) &&
        counter_partition_conserved(
            stats.callback_calls,
            {stats.callback_successes,
             stats.callback_failures}) &&
        counter_partition_conserved(
            stats.callback_calls,
            {stats.invalid_callback_rejects,
             stats.stale_context_rejects,
             stats.reentrant_callback_rejects,
             stats.retirement_snapshot_mismatches,
             stats.retirement_snapshot_matches}) &&
        counter_partition_conserved(
            stats.retirement_snapshot_matches,
            {stats.timestamp_known_calls,
             stats.timestamp_unknown_rejects}) &&
        counter_partition_conserved(
            stats.timestamp_known_calls,
            {stats.timestamp_formal_calls,
             stats.timestamp_nonformal_calls}) &&
        counter_partition_conserved(
            stats.binding_prepare_attempts,
            {stats.binding_prepare_fresh,
             stats.binding_prepare_idempotent,
             stats.binding_prepare_failures}) &&
        counter_partition_conserved(
            stats.flow_release_attempts,
            {stats.flow_release_released,
             stats.flow_release_already_absent,
             stats.flow_release_time_regressions,
             stats.flow_release_failures,
             stats.flow_release_contract_violations}) &&
        counter_partition_conserved(
            stats.binding_finalize_attempts,
            {stats.binding_finalize_successes,
             stats.binding_finalize_failures}) &&
        stats.callback_successes == stats.binding_finalize_successes &&
        counter_partition_conserved(
            stats.callback_successes,
            {stats.successful_formal_cleanups,
             stats.successful_nonformal_cleanups});
}

bool formal_ready_impl(
        const fk_quic_owner_cleanup_adapter &adapter) {
    const fk_quic_owner_cleanup_stats &stats = adapter.stats;
    return adapter.initialized != 0u &&
        adapter.callback_active == 0u &&
        counters_conserved(stats) &&
        stats.context_prepare_rejects == 0u &&
        stats.contexts_prepared == stats.callback_successes &&
        stats.latest_context_epoch == stats.contexts_prepared &&
        stats.callback_failures == 0u &&
        stats.invalid_callback_rejects == 0u &&
        stats.stale_context_rejects == 0u &&
        stats.reentrant_callback_rejects == 0u &&
        stats.retirement_snapshot_mismatches == 0u &&
        stats.timestamp_nonformal_calls == 0u &&
        stats.timestamp_unknown_rejects == 0u &&
        stats.timestamp_regression_rejects == 0u &&
        stats.binding_prepare_failures == 0u &&
        stats.binding_prepare_idempotent == 0u &&
        stats.retired_binding_contract_failures == 0u &&
        stats.flow_release_time_regressions == 0u &&
        stats.flow_release_failures == 0u &&
        stats.flow_release_contract_violations == 0u &&
        stats.binding_finalize_failures == 0u &&
        ((stats.callback_successes == 0u &&
          adapter.timestamp_watermark_valid == 0u) ||
         (stats.callback_successes != 0u &&
          adapter.timestamp_watermark_valid == 1u)) &&
        stats.callback_successes == stats.successful_formal_cleanups;
}

}  // namespace

bool fk_quic_owner_cleanup_adapter_initialize(
        fk_quic_owner_cleanup_adapter *adapter,
        fk_owner_flow_bindings *bindings,
        uint16_t fixed_owner,
        fk_quic_owner_flow_release_callback release_callback,
        void *release_user) {
    if (adapter == nullptr)
        return false;
    std::memset(adapter, 0, sizeof(*adapter));
    if (bindings == nullptr || release_callback == nullptr)
        return false;
    fk_owner_flow_bindings_stats binding_stats{};
    if (!fk_owner_flow_bindings_get_stats(bindings, &binding_stats) ||
        binding_stats.logical_id_abi_version !=
            FK_QUIC_LOGICAL_ID_ABI_VERSION ||
        binding_stats.retire_ack_required == 0u ||
        binding_stats.maximum_connection_slots == 0u ||
        fixed_owner >= binding_stats.owner_count) {
        return false;
    }
    adapter->bindings = bindings;
    adapter->release_callback = release_callback;
    adapter->release_user = release_user;
    adapter->maximum_connection_slots =
        binding_stats.maximum_connection_slots;
    adapter->fixed_owner = fixed_owner;
    adapter->stats.fixed_owner = fixed_owner;
    adapter->initialized = 1u;
    return true;
}

bool fk_quic_owner_cleanup_context_prepare(
        fk_quic_owner_cleanup_adapter *adapter,
        const fk_quic_cid_retirement *latest_retirement,
        fk_quic_owner_cleanup_context *context) {
    if (context != nullptr)
        std::memset(context, 0, sizeof(*context));
    if (adapter == nullptr || adapter->initialized == 0u ||
        context == nullptr) {
        return false;
    }
    adapter->stats.context_prepare_attempts++;
    if (latest_retirement == nullptr ||
        !retirement_shape_valid(*adapter, *latest_retirement) ||
        adapter->latest_context_epoch ==
            std::numeric_limits<uint64_t>::max()) {
        adapter->stats.context_prepare_rejects++;
        return false;
    }
    adapter->latest_context_epoch++;
    adapter->stats.latest_context_epoch = adapter->latest_context_epoch;
    context->adapter = adapter;
    context->expected_retirement = *latest_retirement;
    context->epoch = adapter->latest_context_epoch;
    context->ready = 1u;
    adapter->stats.contexts_prepared++;
    return true;
}

bool fk_quic_owner_cleanup_callback(
        void *user,
        const fk_quic_cid_retirement *current_retirement) {
    auto *context = static_cast<fk_quic_owner_cleanup_context *>(user);
    if (context == nullptr || context->adapter == nullptr)
        return false;
    fk_quic_owner_cleanup_adapter &adapter = *context->adapter;
    fk_quic_owner_cleanup_stats &stats = adapter.stats;
    stats.callback_calls++;
    if (adapter.callback_active != 0u) {
        stats.reentrant_callback_rejects++;
        stats.callback_failures++;
        return false;
    }
    adapter.callback_active = 1u;
    const auto fail = [&adapter, &stats]() {
        stats.callback_failures++;
        adapter.callback_active = 0u;
        return false;
    };
    if (adapter.initialized == 0u || adapter.bindings == nullptr ||
        adapter.release_callback == nullptr || current_retirement == nullptr ||
        context->ready == 0u) {
        stats.invalid_callback_rejects++;
        return fail();
    }
    if (context->completed != 0u ||
        context->epoch != adapter.latest_context_epoch) {
        stats.stale_context_rejects++;
        return fail();
    }
    if (!retirement_shape_valid(adapter, *current_retirement) ||
        !immutable_snapshot_matches(
            context->expected_retirement, *current_retirement)) {
        stats.retirement_snapshot_mismatches++;
        return fail();
    }
    stats.retirement_snapshot_matches++;
    if (current_retirement->retirement_timestamp_known == 0u) {
        stats.timestamp_unknown_rejects++;
        return fail();
    }
    stats.timestamp_known_calls++;
    if (current_retirement->retirement_timestamp_formal != 0u)
        stats.timestamp_formal_calls++;
    else
        stats.timestamp_nonformal_calls++;
    if (adapter.timestamp_watermark_valid != 0u &&
        current_retirement->retirement_timestamp_ns <
            adapter.timestamp_watermark_ns) {
        stats.timestamp_regression_rejects++;
        return fail();
    }

    fk_owner_flow_binding retired_binding{};
    stats.binding_prepare_attempts++;
    const fk_owner_flow_binding_result prepare =
        fk_owner_flow_bindings_retire_connection(
            adapter.bindings,
            adapter.fixed_owner,
            current_retirement->logical_connection_id,
            current_retirement->binding_expected != 0u,
            &retired_binding);
    if (prepare == FK_OWNER_FLOW_BINDING_RETIRE_PREPARED) {
        stats.binding_prepare_fresh++;
    } else if (prepare ==
            FK_OWNER_FLOW_BINDING_RETIRE_PREPARE_IDEMPOTENT) {
        stats.binding_prepare_idempotent++;
    } else {
        stats.binding_prepare_failures++;
        return fail();
    }
    if (!retained_binding_valid(*context, retired_binding)) {
        stats.retired_binding_contract_failures++;
        return fail();
    }

    stats.flow_release_attempts++;
    const fk_quic_owner_flow_release_result released =
        adapter.release_callback(
            adapter.release_user,
            retired_binding.handle,
            current_retirement->retirement_timestamp_ns);
    bool release_accepted = false;
    if (retired_binding.handle.generation == 0u) {
        if (released == FK_QUIC_OWNER_FLOW_RELEASE_ALREADY_ABSENT) {
            stats.flow_release_already_absent++;
            release_accepted = true;
        } else if (released == FK_QUIC_OWNER_FLOW_RELEASE_TIME_REGRESSION) {
            stats.flow_release_time_regressions++;
        } else if (released == FK_QUIC_OWNER_FLOW_RELEASE_INVALID ||
                   released == FK_QUIC_OWNER_FLOW_RELEASE_FAILED) {
            stats.flow_release_failures++;
        } else {
            /* RELEASED for a zero handle fabricates a FlowTable release. */
            stats.flow_release_contract_violations++;
        }
    } else if (released == FK_QUIC_OWNER_FLOW_RELEASE_RELEASED) {
        stats.flow_release_released++;
        release_accepted = true;
    } else if (released == FK_QUIC_OWNER_FLOW_RELEASE_ALREADY_ABSENT) {
        stats.flow_release_already_absent++;
        release_accepted = true;
    } else if (released == FK_QUIC_OWNER_FLOW_RELEASE_TIME_REGRESSION) {
        stats.flow_release_time_regressions++;
    } else if (released == FK_QUIC_OWNER_FLOW_RELEASE_INVALID ||
               released == FK_QUIC_OWNER_FLOW_RELEASE_FAILED) {
        stats.flow_release_failures++;
    } else {
        stats.flow_release_contract_violations++;
    }
    if (!release_accepted)
        return fail();

    adapter.timestamp_watermark_ns =
        current_retirement->retirement_timestamp_ns;
    adapter.timestamp_watermark_valid = 1u;
    stats.timestamp_watermark_ns = adapter.timestamp_watermark_ns;
    stats.timestamp_watermark_valid = 1u;

    stats.binding_finalize_attempts++;
    if (fk_owner_flow_bindings_finalize_retire_exact(
            adapter.bindings,
            adapter.fixed_owner,
            current_retirement->logical_connection_id) !=
            FK_OWNER_FLOW_BINDING_RETIRE_FINALIZED) {
        stats.binding_finalize_failures++;
        return fail();
    }
    stats.binding_finalize_successes++;
    stats.callback_successes++;
    if (current_retirement->retirement_timestamp_formal != 0u)
        stats.successful_formal_cleanups++;
    else
        stats.successful_nonformal_cleanups++;
    context->completed = 1u;
    adapter.callback_active = 0u;
    return true;
}

bool fk_quic_owner_cleanup_get_stats(
        const fk_quic_owner_cleanup_adapter *adapter,
        fk_quic_owner_cleanup_stats *stats) {
    if (adapter == nullptr || stats == nullptr ||
        adapter->initialized == 0u) {
        return false;
    }
    *stats = adapter->stats;
    stats->fixed_owner = adapter->fixed_owner;
    stats->timestamp_watermark_ns = adapter->timestamp_watermark_ns;
    stats->latest_context_epoch = adapter->latest_context_epoch;
    stats->timestamp_watermark_valid =
        adapter->timestamp_watermark_valid;
    stats->formal_replay_ready = formal_ready_impl(*adapter) ? 1u : 0u;
    return true;
}

bool fk_quic_owner_cleanup_accounting_conserved(
        const fk_quic_owner_cleanup_adapter *adapter) {
    return adapter != nullptr && adapter->initialized != 0u &&
        adapter->stats.fixed_owner == adapter->fixed_owner &&
        adapter->stats.latest_context_epoch ==
            adapter->latest_context_epoch &&
        adapter->stats.timestamp_watermark_valid ==
            adapter->timestamp_watermark_valid &&
        (adapter->timestamp_watermark_valid == 0u ||
         adapter->stats.timestamp_watermark_ns ==
            adapter->timestamp_watermark_ns) &&
        counters_conserved(adapter->stats);
}

bool fk_quic_owner_cleanup_formal_replay_ready(
        const fk_quic_owner_cleanup_adapter *adapter) {
    return adapter != nullptr && formal_ready_impl(*adapter) &&
        fk_quic_owner_cleanup_accounting_conserved(adapter);
}

fk_quic_owner_flow_release_result
fk_quic_owner_cleanup_compact_runtime_release(
        void *runtime_user,
        fk_owner_flow_handle handle,
        uint64_t retirement_timestamp_ns) {
    auto *runtime = static_cast<fk_compact_runtime *>(runtime_user);
    fk_compact_flow_handle compact_handle{};
    compact_handle.index = handle.index;
    compact_handle.generation = handle.generation;
    switch (fk_compact_runtime_release_bound_flow(
            runtime, compact_handle, retirement_timestamp_ns)) {
    case FK_COMPACT_RUNTIME_FLOW_RELEASE_RELEASED:
        return FK_QUIC_OWNER_FLOW_RELEASE_RELEASED;
    case FK_COMPACT_RUNTIME_FLOW_RELEASE_ALREADY_ABSENT:
        return FK_QUIC_OWNER_FLOW_RELEASE_ALREADY_ABSENT;
    case FK_COMPACT_RUNTIME_FLOW_RELEASE_TIME_REGRESSION:
        return FK_QUIC_OWNER_FLOW_RELEASE_TIME_REGRESSION;
    case FK_COMPACT_RUNTIME_FLOW_RELEASE_FAILED:
        return FK_QUIC_OWNER_FLOW_RELEASE_FAILED;
    case FK_COMPACT_RUNTIME_FLOW_RELEASE_INVALID:
    default:
        return FK_QUIC_OWNER_FLOW_RELEASE_INVALID;
    }
}

const char *fk_quic_owner_flow_release_result_name(
        fk_quic_owner_flow_release_result result) {
    switch (result) {
    case FK_QUIC_OWNER_FLOW_RELEASE_INVALID:
        return "invalid";
    case FK_QUIC_OWNER_FLOW_RELEASE_RELEASED:
        return "released";
    case FK_QUIC_OWNER_FLOW_RELEASE_ALREADY_ABSENT:
        return "already_absent";
    case FK_QUIC_OWNER_FLOW_RELEASE_TIME_REGRESSION:
        return "time_regression";
    case FK_QUIC_OWNER_FLOW_RELEASE_FAILED:
        return "failed";
    default:
        return "unknown";
    }
}
