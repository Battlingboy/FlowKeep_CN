#ifndef FLOWKEEP_FK_THREAD_PHASE_CLOCK_H
#define FLOWKEEP_FK_THREAD_PHASE_CLOCK_H

#include <cstdint>
#include <pthread.h>
#include <sys/resource.h>
#include <time.h>

namespace flowkeep {
// Diagnostic only: off-CPU time includes both blocking and runnable waiting.
// Context-switch counts are supporting evidence, not a duration attribution.
struct ThreadPhaseTiming {
    uint64_t started_ns=0, finished_ns=0, cpu_ns=0, off_cpu_ns=0;
    uint64_t voluntary_switches=0, involuntary_switches=0;
    bool valid=false;
};
struct ThreadPhaseStamp {
    uint64_t wall_ns=0, cpu_ns=0;
    rusage usage{};
    pthread_t thread{};
    bool valid=false;
};
inline ThreadPhaseStamp ReadThreadPhaseStamp() noexcept {
    ThreadPhaseStamp s;
    timespec wall{},cpu{};
    s.thread=::pthread_self();
    s.valid=::clock_gettime(CLOCK_MONOTONIC,&wall)==0 &&
        ::clock_gettime(CLOCK_THREAD_CPUTIME_ID,&cpu)==0 &&
        ::getrusage(RUSAGE_THREAD,&s.usage)==0;
    if(s.valid) {
        s.wall_ns=uint64_t(wall.tv_sec)*1000000000u+wall.tv_nsec;
        s.cpu_ns=uint64_t(cpu.tv_sec)*1000000000u+cpu.tv_nsec;
    }
    return s;
}
inline ThreadPhaseTiming ThreadPhaseBetween(
        const ThreadPhaseStamp &a,const ThreadPhaseStamp &b) noexcept {
    ThreadPhaseTiming t;
    if(!a.valid || !b.valid || !::pthread_equal(a.thread,b.thread) ||
       b.wall_ns<a.wall_ns || b.cpu_ns<a.cpu_ns ||
       b.usage.ru_nvcsw<a.usage.ru_nvcsw || b.usage.ru_nivcsw<a.usage.ru_nivcsw)
        return t;
    t.valid=true;t.started_ns=a.wall_ns;t.finished_ns=b.wall_ns;
    t.cpu_ns=b.cpu_ns-a.cpu_ns;
    const uint64_t wall=b.wall_ns-a.wall_ns;
    t.off_cpu_ns=wall>t.cpu_ns?wall-t.cpu_ns:0;
    t.voluntary_switches=b.usage.ru_nvcsw-a.usage.ru_nvcsw;
    t.involuntary_switches=b.usage.ru_nivcsw-a.usage.ru_nivcsw;
    return t;
}
}
#endif
