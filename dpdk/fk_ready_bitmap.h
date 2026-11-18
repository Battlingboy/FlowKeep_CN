#ifndef FK_READY_BITMAP_H
#define FK_READY_BITMAP_H
#include <atomic>
#include <cstdint>

namespace flowkeep {
// Coalescing MPSC notifications, one consumer. No evidence lives here.
// Clearing a summary precedes clearing its leaves: a concurrent producer
// either joins the consumed leaf or publishes a new summary notification.
template<uint32_t Count> struct ReadyBitmap {
    static_assert(Count % 4096u == 0u, "complete two-level bitmap");
    static_assert(Count / 4096u <= 64u, "top bitmap covers all summaries");
    std::atomic<uint64_t> leaves[Count / 64u]{};
    std::atomic<uint64_t> summaries[Count / 4096u]{};
    std::atomic<uint64_t> top{0};
    void Notify(uint32_t index) noexcept {
        const uint32_t word=index/64u;
        if(leaves[word].fetch_or(UINT64_C(1)<<(index%64u),std::memory_order_release)==0)
            if(summaries[word/64u].fetch_or(UINT64_C(1)<<(word%64u),std::memory_order_release)==0)
                top.fetch_or(UINT64_C(1)<<(word/64u),std::memory_order_release);
    }
    struct Cursor {uint32_t next_summary=0,summary=0,word=0;uint64_t words=0,bits=0;};
    bool Take(Cursor &cursor,uint32_t *index) noexcept {
        for(uint32_t scanned=0;;) {
            if(cursor.bits) {
                const unsigned bit=__builtin_ctzll(cursor.bits);cursor.bits&=cursor.bits-1;
                *index=cursor.word*64u+bit;return true;
            }
            if(cursor.words) {
                const unsigned bit=__builtin_ctzll(cursor.words);cursor.words&=cursor.words-1;
                cursor.word=cursor.summary*64u+bit;
                cursor.bits=leaves[cursor.word].exchange(0,std::memory_order_acquire);
                continue;
            }
            if(scanned++==Count/4096u)return false;
            cursor.summary=cursor.next_summary;
            cursor.next_summary=(cursor.next_summary+1)%(Count/4096u);
            // Avoid an RMW on empty summary cache lines.
            if(summaries[cursor.summary].load(std::memory_order_acquire))
                cursor.words=summaries[cursor.summary].exchange(0,std::memory_order_acquire);
        }
    }
    // Clear a parent before consuming its children at every level. A racing
    // producer is either covered by the consumer's already-owned child bit,
    // or republishes that bit and its ancestors. Only one consumer may drain.
    // The top bit is a wake-up hint, never ownership of an evidence version.
    bool TakeTop(Cursor &cursor,uint32_t *index) noexcept {
        for(;;) {
            if(cursor.bits) {
                const unsigned bit=__builtin_ctzll(cursor.bits);cursor.bits&=cursor.bits-1;
                *index=cursor.word*64u+bit;return true;
            }
            if(cursor.words) {
                const unsigned bit=__builtin_ctzll(cursor.words);cursor.words&=cursor.words-1;
                cursor.word=cursor.summary*64u+bit;
                cursor.bits=leaves[cursor.word].exchange(0,std::memory_order_acquire);
                continue;
            }
            const uint64_t pending=top.load(std::memory_order_acquire);
            if(!pending)return false;
            const uint64_t after=pending & (~UINT64_C(0)<<cursor.next_summary);
            cursor.summary=__builtin_ctzll(after?after:pending);
            cursor.next_summary=(cursor.summary+1)%(Count/4096u);
            top.fetch_and(~(UINT64_C(1)<<cursor.summary),std::memory_order_acquire);
            cursor.words=summaries[cursor.summary].exchange(0,std::memory_order_acquire);
        }
    }
};
}
#endif
