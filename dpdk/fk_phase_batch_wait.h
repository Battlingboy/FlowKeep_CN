#ifndef FK_PHASE_BATCH_WAIT_H
#define FK_PHASE_BATCH_WAIT_H
#include <cstdint>
#include <cstdlib>
#include <stdexcept>
namespace flowkeep {
// Worker-mutex protected. A clean input fence changes batching delay only;
// it does not close the worker, authorize feedback, or settle evidence.
struct PhaseBatchWait {
    uint64_t active_ns=0,drain_ns=0;
    bool switch_enabled=false,draining=false;
    explicit PhaseBatchWait(uint64_t configured_ns) {
        const auto parse=[](const char *name) -> uint64_t {
            const char *v=std::getenv(name);if(!v)return 0;
            char *end=nullptr;const long n=std::strtol(v,&end,10);
            if(!*v || *end || n<0 || n>20000)throw std::invalid_argument(name);
            return static_cast<uint64_t>(n)*1000;
        };
        const auto active=parse("FK_PHASE_BATCH_ACTIVE_US");
        const auto drain=parse("FK_PHASE_BATCH_DRAIN_US");
        if(drain && (!active || drain>active))
            throw std::invalid_argument("phase batch drain requires active >= drain");
        active_ns=active?active:configured_ns;drain_ns=drain?drain:active_ns;
        switch_enabled=drain && drain<active_ns;
    }
    uint64_t WaitNs() const noexcept {return draining?drain_ns:active_ns;}
    bool InputFence() noexcept {
        if(!switch_enabled || draining)return false;
        draining=true;return true;
    }
};
}
#endif
