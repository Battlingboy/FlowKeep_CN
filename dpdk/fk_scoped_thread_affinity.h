#ifndef FK_SCOPED_THREAD_AFFINITY_H
#define FK_SCOPED_THREAD_AFFINITY_H
#include <pthread.h>
#include <sched.h>
#include <stdexcept>
#include <exception>
namespace flowkeep {
// Change only the constructing thread while it creates database workers.
// New workers inherit this CPU set; restore the DPDK creator before READY.
class ScopedThreadAffinity {
public:
    explicit ScopedThreadAffinity(const cpu_set_t &requested) {
        if(CPU_COUNT(&requested)==0)
            throw std::invalid_argument("empty database creator CPU set");
        if(pthread_getaffinity_np(pthread_self(),sizeof(original_),&original_)!=0)
            throw std::runtime_error("cannot read database creator affinity");
        if(pthread_setaffinity_np(pthread_self(),sizeof(requested),&requested)!=0)
            throw std::runtime_error("cannot set database creator affinity");
        active_=true;
        cpu_set_t observed;CPU_ZERO(&observed);
        if(pthread_getaffinity_np(pthread_self(),sizeof(observed),&observed)!=0 ||
           !CPU_EQUAL(&observed,&requested)) {
            if(!Restore())std::terminate();
            throw std::runtime_error("database creator affinity differs from requested set");
        }
    }
    ScopedThreadAffinity(const ScopedThreadAffinity &)=delete;
    ScopedThreadAffinity &operator=(const ScopedThreadAffinity &)=delete;
    ~ScopedThreadAffinity() noexcept {if(!Restore())std::terminate();}
    bool Restore() noexcept {
        if(!active_)return true;
        if(pthread_setaffinity_np(pthread_self(),sizeof(original_),&original_)!=0)return false;
        cpu_set_t observed;CPU_ZERO(&observed);
        if(pthread_getaffinity_np(pthread_self(),sizeof(observed),&observed)!=0 ||
           !CPU_EQUAL(&observed,&original_))return false;
        active_=false;return true;
    }
private:
    cpu_set_t original_{};bool active_=false;
};
}
#endif
