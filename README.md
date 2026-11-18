# FlowKeep

FlowKeep combines adaptive traffic observation, version-bound asynchronous inference, and decision-aligned evidence retention.

## Build

The implementation uses C11 and C++17. Install Meson, Ninja, pkg-config, DPDK, ISA-L, OpenSSL, Jansson, Zstandard, and RocksDB development packages.

```sh
meson setup build --buildtype=release
meson compile -C build
meson test -C build --print-errorlogs --num-processes 1
```

The two executables are `build/dpdk/fk_dpdk_compact_rx` and `build/dpdk/fk_native_fusion_service_cli`. Runtime configuration and trained model files are supplied through their command-line options.

## Implementation

| Component | Main files in `dpdk/` |
| --- | --- |
| Packet reception and feature updates | `fk_dpdk_compact_rx.cpp`, `fk_compact_runtime.cpp` |
| Adaptive observation | `fk_marginal_checkpoint_scheduler.cpp`, `fk_trained_checkpoint_policy.h` |
| Immutable feature versions and request binding | `fk_prefix_version_store.h`, `fk_versioned_observation_source.h` |
| Asynchronous inference and history updates | `fk_native_fusion_service.cpp`, `fk_native_fusion_engine_scorer.cpp`, `fk_native_seven_state_fusion.cpp` |
| Final-request evidence selection and persistence | `fk_final_scored_evidence_selector.cpp`, `fk_selected_evidence_store.cpp` |

`SOURCE_MANIFEST.json` records the source hashes and the bundled-header include adjustment. The tests cover scheduling, model evaluation, asynchronous service behavior, evidence persistence, source callbacks, and final-request selection.
