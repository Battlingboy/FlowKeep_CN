#ifndef FK_RX_QUEUE_TOPOLOGY_H
#define FK_RX_QUEUE_TOPOLOGY_H

#include <cstdint>
#include <limits>

namespace fk_rx_queue_topology {

constexpr uint16_t kInvalidOwner = std::numeric_limits<uint16_t>::max();
constexpr uint16_t kMaximumRxQueues = 64u;

/* Direct RX workers consume queue[index], so that mode requires an exact
 * queue/worker correspondence.  Dedicated RX pumps perform software owner
 * dispatch and may therefore fan more hardware queues into fewer workers. */
static inline bool valid(
        uint16_t workers,
        uint16_t rx_queues,
        uint16_t rx_pump_workers,
        bool software_owner_dispatch) {
    if (workers == 0u || rx_queues == 0u ||
        rx_queues > kMaximumRxQueues)
        return false;
    if (rx_pump_workers == 0u) {
        return !software_owner_dispatch && rx_queues == workers;
    }
    /* Pumps terminate hardware queues and software-dispatch to owners; they
     * are producers, not owner shards.  Requiring pump_count <= workers
     * unnecessarily prevents one-pump-per-RX-queue layouts on machines that
     * have fewer state shards than NIC queues. */
    return software_owner_dispatch && rx_pump_workers <= rx_queues;
}

static inline bool owner_is_valid(uint16_t owner, uint16_t workers) {
    return workers != 0u && owner < workers;
}

/* Owner parsing is fail-closed for formal classification, but diagnostic and
 * malformed traffic still follows the legacy fallback path.  Keep that path
 * inside the worker array even when rx_queues > workers. */
static inline uint16_t fallback_owner_for_queue(
        uint16_t rx_queue,
        uint16_t workers) {
    return workers == 0u
        ? kInvalidOwner
        : static_cast<uint16_t>(rx_queue % workers);
}

}  // namespace fk_rx_queue_topology

#endif
