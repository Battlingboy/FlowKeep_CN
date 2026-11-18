#ifndef FLOWKEEP_FK_NO_NIC_PCAP_RUNNER_H
#define FLOWKEEP_FK_NO_NIC_PCAP_RUNNER_H

#ifdef __cplusplus
extern "C" {
#endif

/* Kept callable so the focused test can exercise argument and malformed-input
 * paths without spawning a shell. */
int fk_no_nic_pcap_runner_entry(int argc, char **argv);

/* Production-main-only entry.  The caller must invoke this only after a
 * successful rte_eal_init().  It records that narrow integration fact while
 * continuing to report actual NIC RX and every formal capability as false. */
int fk_no_nic_pcap_runner_entry_after_eal(int argc, char **argv);

#ifdef __cplusplus
}
#endif

#endif
