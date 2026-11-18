cc = meson.get_compiler('c')

rt_dep = cc.find_library('rt', required: true)

m_dep = cc.find_library('m', required: true)

crypto_dep = cc.find_library('crypto', required: true)

jansson_dep = cc.find_library('jansson', required: true)

zstd_dep = dependency('libzstd', required: true)

threads_dep = dependency('threads')

prewritten_wal_native_dep = cc.find_library('rocksdb', required: true)

prewritten_wal_env_lib = static_library('fk_prewritten_wal_env',
  ['fk_prewritten_wal_env.cpp', 'fk_history_write_batch.cpp'],
  dependencies: [prewritten_wal_native_dep, threads_dep],
  cpp_args: ['-Wall', '-Wextra', '-Wpedantic', '-Werror', '-fno-rtti'])

prewritten_wal_rocksdb_dep = declare_dependency(
  dependencies: prewritten_wal_native_dep,
  link_with: prewritten_wal_env_lib)

dpdk_dep = dependency('libdpdk', method: 'pkg-config', required: true)

isal_dep = dependency('libisal', method: 'pkg-config', required: true)

native_parser_lib = static_library(
  'fk_native_parser',
  [
    'fk_native_parser.c',
    'fk_native_runtime.c',
    'fk_native_flowkeep.c',
    'fk_native_event_ring.c',
    'fk_native_window_ring.c',
  ],
  dependencies: [m_dep],
)

trace_sidecar_lib = static_library(
  'fk_trace_sidecar',
  ['fk_trace_sidecar.c'],
  dependencies: [crypto_dep],
)

trace_transport_shim_lib = static_library(
  'fk_trace_transport_shim',
  ['fk_trace_transport_shim.c'],
  dependencies: [isal_dep],
  c_args: ['-Wall', '-Wextra', '-Wpedantic', '-Werror'],
)

trace_sequence_audit_lib = static_library(
  'fk_trace_sequence_audit',
  ['fk_trace_sequence_audit.cpp'],
)

trace_message_barrier_lib = static_library(
  'fk_trace_message_barrier',
  ['fk_trace_message_barrier.cpp'],
)

actor_session_lib = static_library(
  'fk_actor_session',
  ['fk_actor_session.cpp'],
)

actor_namespace_monitor_map_lib = static_library(
  'fk_actor_namespace_monitor_map',
  ['fk_actor_namespace_monitor_map.cpp'],
  cpp_args: ['-Wall', '-Wextra', '-Wpedantic', '-Werror'],
)

quic_cid_map_lib = static_library(
  'fk_quic_cid_map',
  ['fk_quic_cid_map.cpp'],
)

quic_initial_auth_lib = static_library(
  'fk_quic_initial_auth',
  ['fk_quic_initial_auth.cpp'],
  dependencies: [crypto_dep],
  cpp_args: [
    '-Wall',
    '-Wextra',
    '-Wpedantic',
    '-Werror',
  ],
)

quic_initial_admission_bridge_lib = static_library(
  'fk_quic_initial_admission_bridge',
  ['fk_quic_initial_admission_bridge.cpp'],
  cpp_args: ['-Wall', '-Wextra', '-Wpedantic', '-Werror'],
)

quic_initial_crypto_admission_gate_lib = static_library(
  'fk_quic_initial_crypto_admission_gate',
  ['fk_quic_initial_crypto_admission_gate.cpp'],
  cpp_args: ['-Wall', '-Wextra', '-Wpedantic', '-Werror'],
)

detection_event_path_lib = static_library(
  'fk_detection_event_path',
  ['fk_detection_event_path.cpp'],
)

checkpoint_reorder_lib = static_library(
  'fk_checkpoint_reorder',
  ['fk_checkpoint_reorder.cpp'],
)

component_state_lib = static_library(
  'fk_component_state',
  ['fk_component_state.cpp'],
)

marginal_checkpoint_scheduler_lib = static_library(
  'fk_marginal_checkpoint_scheduler',
  ['fk_marginal_checkpoint_scheduler.cpp'],
  cpp_args: ['-Wall', '-Wextra', '-Wpedantic', '-Werror'],
)

marginal_checkpoint_scheduler_test = executable(
  'test_fk_marginal_checkpoint_scheduler',
  ['test_fk_marginal_checkpoint_scheduler.cpp'],
  link_with: marginal_checkpoint_scheduler_lib,
  cpp_args: ['-Wall', '-Wextra', '-Wpedantic', '-Werror'],
)

portable_hgb_lib = static_library(
  'fk_portable_hgb',
  ['fk_portable_hgb.cpp'],
  cpp_args: ['-Wall', '-Wextra', '-Wpedantic', '-Werror'],
)

portable_hgb_test = executable(
  'test_fk_portable_hgb',
  ['test_fk_portable_hgb.cpp'],
  link_with: portable_hgb_lib,
  cpp_args: ['-Wall', '-Wextra', '-Wpedantic', '-Werror'],
)

cpu_model_lib = static_library(
  'fk_cpu_model',
  ['fk_cpu_model.cpp'],
  dependencies: [crypto_dep],
)

native_seven_state_fusion_lib = static_library(
  'fk_native_seven_state_fusion',
  ['fk_native_seven_state_fusion.cpp'],
  dependencies: [crypto_dep, threads_dep],
  cpp_args: ['-Wall', '-Wextra', '-Wpedantic', '-Werror'],
)

value_model_v3_lib = static_library(
  'fk_value_model_v3',
  ['fk_value_model_v3.cpp'],
  dependencies: [crypto_dep],
  cpp_args: ['-Wall', '-Wextra', '-Wpedantic', '-Werror'],
)

value_model_v3_context_lib = static_library(
  'fk_value_model_v3_context',
  ['fk_value_model_v3_context.cpp'],
  dependencies: [m_dep],
  cpp_args: ['-Wall', '-Wextra', '-Wpedantic', '-Werror'],
)

causal_event_calibrator_lib = static_library(
  'fk_causal_event_calibrator',
  ['fk_causal_event_calibrator.cpp', 'fk_causal_event_features.cpp'],
  cpp_args: ['-Wall', '-Wextra', '-Wpedantic', '-Werror'],
)

event_student_lib = static_library(
  'fk_event_student',
  ['fk_event_student.cpp'],
  dependencies: [crypto_dep],
)

event_student_manifest_lib = static_library(
  'fk_event_student_manifest',
  ['fk_event_student_manifest.cpp'],
  dependencies: [crypto_dep],
)

online_event_windows_lib = static_library(
  'fk_online_event_windows',
  ['fk_online_event_windows.cpp', 'fk_stage_aware_aggregator.cpp'],
)

student_shards_lib = static_library(
  'fk_student_shards',
  ['fk_student_shards.cpp'],
)

event_result_log_lib = static_library(
  'fk_event_result_log',
  ['fk_event_result_log.cpp'],
)

formal_run_contract_lib = static_library(
  'fk_formal_run_contract',
  ['fk_formal_run_contract.cpp'],
  dependencies: [crypto_dep],
)

frozen_artifact_lib = static_library(
  'fk_frozen_artifact',
  ['fk_frozen_artifact.cpp'],
  dependencies: [crypto_dep],
)

formal_gate_lib = static_library(
  'fk_formal_gate',
  ['fk_formal_gate.cpp'],
)

identity_pipeline_contract_lib = static_library(
  'fk_identity_pipeline_contract',
  ['fk_identity_pipeline_contract.cpp'],
  cpp_args: ['-Wall', '-Wextra', '-Wpedantic', '-Werror'],
)

controlled_budget_plan_lib = static_library(
  'fk_controlled_budget_plan',
  ['fk_controlled_budget_plan.cpp'],
)

owner_dispatch_lib = static_library(
  'fk_owner_dispatch',
  ['fk_owner_dispatch.cpp'],
  cpp_args: [
    '-Wall',
    '-Wextra',
    '-Wpedantic',
    '-Werror',
  ],
)

dpdk_owner_mbuf_bytes_source_lib = static_library(
  'fk_dpdk_owner_mbuf_bytes_source',
  ['fk_dpdk_owner_mbuf_bytes_source.cpp'],
  dependencies: [dpdk_dep],
  cpp_args: [
    '-Wall',
    '-Wextra',
    '-Wpedantic',
    '-Werror',
  ],
)

dpdk_exact_identity_mbuf_source_lib = static_library(
  'fk_dpdk_exact_identity_mbuf_source',
  ['fk_dpdk_exact_identity_mbuf_source.cpp'],
  dependencies: [dpdk_dep],
  cpp_args: [
    '-Wall',
    '-Wextra',
    '-Wpedantic',
    '-Werror',
  ],
)

quic_route_receipt_lib = static_library(
  'fk_quic_route_receipt',
  ['fk_quic_route_receipt.cpp'],
  cpp_args: [
    '-Wall',
    '-Wextra',
    '-Wpedantic',
    '-Werror',
  ],
)

owner_flow_bindings_lib = static_library(
  'fk_owner_flow_bindings',
  ['fk_owner_flow_bindings.cpp'],
  cpp_args: [
    '-Wall',
    '-Wextra',
    '-Wpedantic',
    '-Werror',
  ],
)

owner_topology_attestation_lib = static_library(
  'fk_owner_topology_attestation',
  ['fk_owner_topology_attestation.cpp'],
  cpp_args: ['-Wall', '-Wextra', '-Wpedantic', '-Werror'],
)

quic_presentation_path_directory_lib = static_library(
  'fk_quic_presentation_path_directory',
  ['fk_quic_presentation_path_directory.cpp'],
  cpp_args: [
    '-Wall',
    '-Wextra',
    '-Wpedantic',
    '-Werror',
  ],
)

exact_identity_sequencer_lib = static_library(
  'fk_exact_identity_sequencer',
  ['fk_exact_identity_sequencer.cpp'],
  cpp_args: ['-Wall', '-Wextra', '-Wpedantic', '-Werror'],
)

dpdk_exact_rx_producer_pump_lib = static_library(
  'fk_dpdk_exact_rx_producer_pump',
  ['fk_dpdk_exact_rx_producer_pump.cpp'],
  dependencies: [dpdk_dep],
  cpp_args: ['-Wall', '-Wextra', '-Wpedantic', '-Werror'],
)

run_artifact_lib = static_library(
  'fk_run_artifact',
  ['fk_run_artifact.cpp'],
)

cpu_pipeline_lib = static_library(
  'fk_cpu_pipeline',
  ['fk_cpu_pipeline.cpp'],
  dependencies: [crypto_dep],
  link_with: [cpu_model_lib, value_model_v3_lib],
)

compact_flow_table_lib = static_library(
  'fk_compact_flow_table',
  ['fk_compact_flow_table.cpp', 'fk_evidence_archive.cpp'],
  dependencies: [prewritten_wal_rocksdb_dep, crypto_dep, jansson_dep, threads_dep],
)

compact_tls_lib = static_library(
  'fk_compact_tls',
  ['fk_compact_tls.cpp'],
)

compact_controller_lib = static_library(
  'fk_compact_controller',
  ['fk_compact_controller.cpp'],
)

compact_runtime_lib = static_library(
  'fk_compact_runtime',
  [
    'fk_compact_runtime.cpp',
    'fk_ja4_identity_features.cpp',
  ],
  link_with: value_model_v3_context_lib,
)

quic_owner_cleanup_lib = static_library(
  'fk_quic_owner_cleanup',
  ['fk_quic_owner_cleanup.cpp'],
  cpp_args: ['-Wall', '-Wextra', '-Wpedantic', '-Werror'],
)

owner_runtime_adapter_lib = static_library(
  'fk_owner_runtime_adapter',
  ['fk_owner_runtime_adapter.cpp'],
  cpp_args: ['-Wall', '-Wextra', '-Wpedantic', '-Werror'],
)

owner_output_batch_ring_lib = static_library(
  'fk_owner_output_batch_ring',
  ['fk_owner_output_batch_ring.cpp'],
  cpp_args: ['-Wall', '-Wextra', '-Wpedantic', '-Werror'],
)

detector_request_ring_lib = static_library(
  'fk_detector_request_ring',
  ['fk_detector_request_ring.cpp'],
  cpp_args: ['-Wall', '-Wextra', '-Wpedantic', '-Werror'],
)

detector_request_shm_lib = static_library(
  'fk_detector_request_shm_abi',
  ['fk_detector_request_shm_abi.cpp'],
  dependencies: [rt_dep],
  link_with: detector_request_ring_lib,
  cpp_args: ['-Wall', '-Wextra', '-Wpedantic', '-Werror'],
)

native_fusion_service_lib = static_library(
  'fk_native_fusion_service',
  ['fk_native_fusion_service.cpp'],
  dependencies: [threads_dep],
  link_with: [detector_request_shm_lib, detector_request_ring_lib],
  cpp_args: ['-Wall', '-Wextra', '-Wpedantic', '-Werror'],
)

native_fusion_engine_scorer_lib = static_library(
  'fk_native_fusion_engine_scorer',
  ['fk_native_fusion_engine_scorer.cpp'],
  dependencies: [threads_dep],
  link_with: [native_seven_state_fusion_lib, native_fusion_service_lib,
              portable_hgb_lib, marginal_checkpoint_scheduler_lib],
  cpp_args: ['-Wall', '-Wextra', '-Wpedantic', '-Werror'],
)

native_fusion_jsonl_ledger_lib = static_library(
  'fk_native_fusion_jsonl_ledger',
  ['fk_native_fusion_jsonl_ledger.cpp'],
  dependencies: [crypto_dep, zstd_dep],
  link_with: native_fusion_service_lib,
  cpp_args: ['-Wall', '-Wextra', '-Wpedantic', '-Werror'],
)

native_fusion_event_router_lib = static_library(
  'fk_native_fusion_event_router',
  ['fk_native_fusion_event_router.cpp'],
  dependencies: [crypto_dep],
  link_with: native_fusion_service_lib,
  cpp_args: ['-Wall', '-Wextra', '-Wpedantic', '-Werror'],
)

selected_evidence_lib = static_library(
  'fk_selected_evidence',
  ['fk_selected_evidence_store.cpp', 'fk_final_scored_evidence_selector.cpp'],
  dependencies: [zstd_dep, crypto_dep, jansson_dep, rt_dep, threads_dep, prewritten_wal_rocksdb_dep],
  link_with: [native_fusion_service_lib, detector_request_ring_lib],
  cpp_args: ['-Wall', '-Wextra', '-Wpedantic', '-Werror'],
)

foreach selected_test : ['test_fk_selected_evidence_store', 'test_fk_selected_source_hooks', 'test_fk_final_scored_evidence_selector']
  selected_executable = executable(selected_test, [selected_test + '.cpp'],
    dependencies: [crypto_dep, jansson_dep, rt_dep, threads_dep, prewritten_wal_rocksdb_dep],
    link_with: [selected_evidence_lib, native_fusion_service_lib, detector_request_ring_lib],
    cpp_args: ['-Wall', '-Wextra', '-Wpedantic', '-Werror'])
  test(selected_test, selected_executable, timeout: 60)
endforeach

native_fusion_service_cli = executable(
  'fk_native_fusion_service_cli',
  ['fk_native_fusion_service_cli.cpp'],
  dependencies: [crypto_dep, jansson_dep, rt_dep, threads_dep, zstd_dep, prewritten_wal_rocksdb_dep],
  link_with: [
    selected_evidence_lib,
    native_fusion_engine_scorer_lib,
    native_fusion_event_router_lib,
    native_fusion_jsonl_ledger_lib,
    native_fusion_service_lib,
    native_seven_state_fusion_lib,
    cpu_model_lib,
    detector_request_shm_lib,
    detector_request_ring_lib,
  ],
  cpp_args: ['-Wall', '-Wextra', '-Wpedantic', '-Werror'],
)

compact_detector_request_adapter_lib = static_library(
  'fk_compact_detector_request_adapter',
  ['fk_compact_detector_request_adapter.cpp'],
  link_with: detector_request_ring_lib,
  cpp_args: ['-Wall', '-Wextra', '-Wpedantic', '-Werror'],
)

owner_output_sequence_bridge_lib = static_library(
  'fk_owner_output_sequence_bridge',
  ['fk_owner_output_sequence_bridge.cpp'],
  cpp_args: ['-Wall', '-Wextra', '-Wpedantic', '-Werror'],
)

quic_retirement_publisher_lib = static_library(
  'fk_quic_retirement_publisher',
  ['fk_quic_retirement_publisher.cpp'],
  cpp_args: ['-Wall', '-Wextra', '-Wpedantic', '-Werror'],
)

exact_identity_router_lib = static_library(
  'fk_exact_identity_router',
  ['fk_exact_identity_router.cpp'],
  cpp_args: ['-Wall', '-Wextra', '-Wpedantic', '-Werror'],
)

exact_identity_rx_worker_pump_lib = static_library(
  'fk_exact_identity_rx_worker_pump',
  ['fk_exact_identity_rx_worker_pump.cpp'],
  dependencies: [dpdk_dep],
  cpp_args: ['-Wall', '-Wextra', '-Wpedantic', '-Werror'],
)

fixed_owner_worker_pump_lib = static_library(
  'fk_fixed_owner_worker_pump',
  ['fk_fixed_owner_worker_pump.cpp'],
  cpp_args: ['-Wall', '-Wextra', '-Wpedantic', '-Werror'],
)

owner_pipeline_abort_coordinator_lib = static_library(
  'fk_owner_pipeline_abort_coordinator',
  ['fk_owner_pipeline_abort_coordinator.cpp'],
  cpp_args: ['-Wall', '-Wextra', '-Wpedantic', '-Werror'],
)

slab_pool_lib = static_library(
  'fk_slab_pool',
  ['fk_slab_pool.cpp'],
)

no_nic_controlled_state_sizing_lib = static_library(
  'fk_no_nic_controlled_state_sizing',
  ['fk_no_nic_controlled_state_sizing.cpp'],
  cpp_args: ['-Wall', '-Wextra', '-Wpedantic', '-Werror'],
)

no_nic_full_composition_lib = static_library(
  'fk_no_nic_full_composition',
  ['fk_no_nic_full_composition.cpp'],
  dependencies: [dpdk_dep, crypto_dep],
  cpp_args: ['-Wall', '-Wextra', '-Wpedantic', '-Werror'],
)

source_record_intervention_plan_lib = static_library(
  'fk_source_record_intervention_plan',
  ['fk_source_record_intervention_plan.cpp'],
  dependencies: [crypto_dep],
  cpp_args: ['-Wall', '-Wextra', '-Wpedantic', '-Werror'],
)

no_nic_pcap_runner_lib = static_library(
  'fk_no_nic_pcap_runner_core',
  ['fk_no_nic_pcap_runner.cpp'],
  dependencies: [dpdk_dep, crypto_dep],
  cpp_args: ['-Wall', '-Wextra', '-Wpedantic', '-Werror'],
)

finite_live_quic_correctness_gate_lib = static_library(
  'fk_finite_live_quic_correctness_gate',
  ['fk_finite_live_quic_correctness_gate.cpp'],
  cpp_args: ['-Wall', '-Wextra', '-Wpedantic', '-Werror'],
)

dpdk_finite_live_runner_lib = static_library(
  'fk_dpdk_finite_live_runner',
  ['fk_dpdk_finite_live_runner.cpp'],
  dependencies: [dpdk_dep],
  link_with: finite_live_quic_correctness_gate_lib,
  cpp_args: ['-Wall', '-Wextra', '-Wpedantic', '-Werror'],
)

native_fusion_service_test = executable(
  'test_fk_native_fusion_service',
  ['test_fk_native_fusion_service.cpp'],
  dependencies: [rt_dep, threads_dep],
  link_with: [
    native_fusion_service_lib,
    detector_request_shm_lib,
    detector_request_ring_lib,
  ],
  cpp_args: ['-Wall', '-Wextra', '-Wpedantic', '-Werror'],
)

executable(
  'fk_dpdk_compact_rx',
  ['fk_dpdk_compact_rx.cpp'],
  dependencies: [dpdk_dep, rt_dep, m_dep, crypto_dep, threads_dep, isal_dep, prewritten_wal_rocksdb_dep],
  link_with: [
    no_nic_pcap_runner_lib,
    source_record_intervention_plan_lib,
    dpdk_finite_live_runner_lib,
    no_nic_full_composition_lib,
    no_nic_controlled_state_sizing_lib,
    identity_pipeline_contract_lib,
    dpdk_exact_rx_producer_pump_lib,
    dpdk_exact_identity_mbuf_source_lib,
    dpdk_owner_mbuf_bytes_source_lib,
    exact_identity_router_lib,
    exact_identity_rx_worker_pump_lib,
    fixed_owner_worker_pump_lib,
    owner_pipeline_abort_coordinator_lib,
    owner_output_sequence_bridge_lib,
    quic_initial_admission_bridge_lib,
    quic_initial_crypto_admission_gate_lib,
    run_artifact_lib,
    formal_gate_lib,
    controlled_budget_plan_lib,
    frozen_artifact_lib,
    event_result_log_lib,
    formal_run_contract_lib,
    event_student_lib,
    event_student_manifest_lib,
    online_event_windows_lib,
    student_shards_lib,
    trace_sidecar_lib,
    trace_transport_shim_lib,
    trace_sequence_audit_lib,
    trace_message_barrier_lib,
    checkpoint_reorder_lib,
    detection_event_path_lib,
    actor_session_lib,
    actor_namespace_monitor_map_lib,
    exact_identity_sequencer_lib,
    owner_dispatch_lib,
    quic_cid_map_lib,
    quic_presentation_path_directory_lib,
    owner_flow_bindings_lib,
    owner_topology_attestation_lib,
    quic_owner_cleanup_lib,
    owner_runtime_adapter_lib,
    owner_output_batch_ring_lib,
    quic_route_receipt_lib,
    quic_initial_auth_lib,
    quic_retirement_publisher_lib,
    causal_event_calibrator_lib,
    compact_detector_request_adapter_lib,
    detector_request_shm_lib,
    detector_request_ring_lib,
    compact_runtime_lib,
    marginal_checkpoint_scheduler_lib,
    portable_hgb_lib,
    compact_controller_lib,
    compact_flow_table_lib,
    compact_tls_lib,
    slab_pool_lib,
    cpu_pipeline_lib,
    cpu_model_lib,
    component_state_lib,
    native_parser_lib,
  ],
  install: true,
)

test('fk_marginal_checkpoint_scheduler', marginal_checkpoint_scheduler_test, is_parallel: false, timeout: 120)

test('fk_portable_hgb', portable_hgb_test, is_parallel: false, timeout: 120)

test('fk_native_fusion_service', native_fusion_service_test, is_parallel: false, timeout: 120)
