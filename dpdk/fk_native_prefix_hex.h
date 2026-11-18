#ifndef FK_NATIVE_PREFIX_HEX_H
#define FK_NATIVE_PREFIX_HEX_H
#include <array>
#include <cstdint>
#include <cstring>
#include <string>

namespace flowkeep {
// Identical quoted IEEE754 little-endian hex, emitted in one append instead
// of two string-capacity checks for each evidence byte. Validation stays at
// the ledger boundary; this encoder deliberately preserves every input bit.
template<size_t N>
inline void AppendPrefixHex(std::string &output,const std::array<float,N> &prefix) {
    static_assert(sizeof(float)==4,"coverage wire format requires float32");
    constexpr char hex[]="0123456789abcdef";
    std::array<char,N*8+2> encoded;
    char *dst=encoded.data();*dst++='"';
    for(float value:prefix) {
        uint32_t bits;std::memcpy(&bits,&value,4);
        for(unsigned byte=0;byte<4;++byte) {
            const auto v=static_cast<uint8_t>(bits>>(byte*8));
            *dst++=hex[v>>4];*dst++=hex[v&15];
        }
    }
    *dst='"';output.append(encoded.data(),encoded.size());
}
}
#endif
