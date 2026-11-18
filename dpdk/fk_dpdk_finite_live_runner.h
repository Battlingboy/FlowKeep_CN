#ifndef FLOWKEEP_FK_DPDK_FINITE_LIVE_RUNNER_H
#define FLOWKEEP_FK_DPDK_FINITE_LIVE_RUNNER_H

#ifdef __cplusplus
extern "C" {
#endif

/* Opt-in, single-RX-queue/single-fixed-owner finite-input actual-NIC mode.
 * The caller must have completed rte_eal_init().  With the explicit
 * --require-quic-identity-proof flag it may issue the narrowly scoped QUIC
 * correctness receipt defined by fk_finite_live_quic_correctness_gate.  It
 * never promotes the default multi-queue production path and is not a
 * throughput benchmark. */
int fk_dpdk_finite_live_runner_entry_after_eal(int argc, char **argv);

#ifdef __cplusplus
}
#endif

#endif
