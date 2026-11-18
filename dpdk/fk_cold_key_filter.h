#ifndef FK_COLD_KEY_FILTER_H
#define FK_COLD_KEY_FILTER_H
#include <cstdint>
#include <memory>
#include <stdexcept>
#include <string_view>

namespace flowkeep {
// Fixed-size, insert-only membership filter over ALL keys in the exclusively
// owned DB. A negative proves absence; a positive ALWAYS falls through to the
// exact DB/cache lookup. Deletes never clear bits. Reopen rebuilds from the
// actual recovered DB before serving a request. Saturation only costs speed.
// The caller holds the store writer mutex and publishes additions only after
// a successful synced write; an uncertain write must fail closed until reopen.
class ColdKeyFilter {
    std::unique_ptr<uint64_t[]> words_;
    size_t count_=0;
    uint64_t set_bits_=0;
    static uint64_t Mix(uint64_t x) noexcept {
        x^=x>>30;x*=0xbf58476d1ce4e5b9ull;
        x^=x>>27;x*=0x94d049bb133111ebull;return x^(x>>31);
    }
    static uint64_t Hash(std::string_view key) noexcept {
        uint64_t h=1469598103934665603ull;
        for(unsigned char c:key){h^=c;h*=1099511628211ull;}
        return Mix(h);
    }
public:
    void Configure(size_t bytes) {
        if(words_ || bytes>(512u<<10))throw std::invalid_argument("invalid cold key filter capacity");
        count_=bytes/sizeof(uint64_t);
        if(count_)words_=std::make_unique<uint64_t[]>(count_);
    }
    size_t AllocatedBytes() const noexcept {return count_*sizeof(uint64_t);}
    uint64_t SetBits() const noexcept {return set_bits_;}
    bool MayContain(std::string_view key) const noexcept {
        if(!count_)return true;
        uint64_t h=Hash(key);const uint64_t step=Mix(h^0x9e3779b97f4a7c15ull)|1ull;
        for(unsigned i=0;i<6;++i,h+=step) {
            const uint64_t bit=h%(count_*64);
            if(!(words_[bit/64]&(1ull<<(bit%64))))return false;
        }
        return true;
    }
    void Add(std::string_view key) noexcept {
        if(!count_)return;
        uint64_t h=Hash(key);const uint64_t step=Mix(h^0x9e3779b97f4a7c15ull)|1ull;
        for(unsigned i=0;i<6;++i,h+=step) {
            const uint64_t bit=h%(count_*64),mask=1ull<<(bit%64);
            auto &word=words_[bit/64];set_bits_+=!(word&mask);word|=mask;
        }
    }
};
}
#endif
