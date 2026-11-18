#ifndef FK_ADAPTIVE_OWNER_ROUTE_H
#define FK_ADAPTIVE_OWNER_ROUTE_H

#include <cstdint>

namespace fk_adaptive_owner_route {

struct Decision {
    uint16_t owner = 0u;
    bool rebalanced = false;
};

/* Keep the frozen hash placement while its queue is close to the least
 * loaded owner.  Once the excess crosses the threshold, bind this new
 * bidirectional flow to one of the least loaded owners.  The caller stores
 * the decision for the lifetime of that flow; this function never migrates
 * an existing flow. */
inline Decision Choose(
        uint16_t hash_owner,
        const uint64_t *depths,
        uint16_t owner_count,
        uint64_t overload_threshold,
        uint64_t tie_ticket) {
    Decision result{hash_owner, false};
    if (depths == nullptr || owner_count == 0u ||
        hash_owner >= owner_count)
        return result;
    uint64_t minimum = depths[0u];
    for (uint16_t owner = 1u; owner < owner_count; ++owner)
        if (depths[owner] < minimum)
            minimum = depths[owner];
    if (depths[hash_owner] <= minimum ||
        depths[hash_owner] - minimum <= overload_threshold)
        return result;
    uint16_t minimum_count = 0u;
    for (uint16_t owner = 0u; owner < owner_count; ++owner)
        minimum_count += depths[owner] == minimum;
    uint16_t selected = static_cast<uint16_t>(
        tie_ticket % minimum_count);
    for (uint16_t owner = 0u; owner < owner_count; ++owner) {
        if (depths[owner] != minimum)
            continue;
        if (selected-- == 0u) {
            result.owner = owner;
            result.rebalanced = owner != hash_owner;
            return result;
        }
    }
    return result;
}

}  // namespace fk_adaptive_owner_route

#endif
