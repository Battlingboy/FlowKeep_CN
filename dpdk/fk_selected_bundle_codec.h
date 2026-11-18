#ifndef FK_SELECTED_BUNDLE_CODEC_H
#define FK_SELECTED_BUNDLE_CODEC_H
#include <rocksdb/db.h>
#include <openssl/sha.h>
#include <zstd.h>
#include <cstdint>
#include <cstring>
#include <map>
#include <stdexcept>
#include <string>

namespace flowkeep {
// Physical packaging only: every row retains its original 808-byte portable
// encoding. V1 also stores its 64-byte SHA256 envelope; V2 authenticates the
// complete immutable group and reconstructs legacy envelopes on readback.
// Both formats already have group-level compression/corruption granularity.
// The identity index and its bundle are
// placed in the SAME synchronous WriteBatch. No reference can be acknowledged
// independently of its payload. Fresh DB + one encoder owns the bundle IDs.
struct SelectedBundleCodec {
    static constexpr size_t row_bytes=872, max_rows=256, reference_bytes=18;
    static constexpr size_t compact_row_bytes=808;
    static void Append(std::string &out,uint64_t value,unsigned bytes) {
        for(unsigned i=0;i<bytes;++i)out.push_back(char((value>>(8*i))&255));
    }
    static uint64_t Read(const std::string &s,size_t at,unsigned bytes) {
        if(at>s.size() || bytes>s.size()-at)throw std::runtime_error("selected bundle truncated integer");
        uint64_t n=0;
        for(unsigned i=0;i<bytes;++i)n|=uint64_t(uint8_t(s[at+i]))<<(8*i);
        return n;
    }
    static std::string Key(uint64_t id) {
        if(!id)throw std::runtime_error("selected bundle zero ID");
        return "bundle/"+std::to_string(id);
    }
    static std::string Reference(uint64_t id,uint32_t index) {
        if(!id || index>=max_rows)throw std::runtime_error("invalid selected bundle reference");
        std::string out="FKREF1";Append(out,id,8);Append(out,index,4);return out;
    }
    static std::string Encode(ZSTD_CCtx *context,const std::string &raw,size_t rows,bool compact=false) {
        const size_t bytes=compact?compact_row_bytes:row_bytes;
        if(!context || !rows || rows>max_rows || raw.size()!=rows*bytes)
            throw std::runtime_error("invalid selected bundle raw size");
        unsigned char hash[SHA256_DIGEST_LENGTH];
        SHA256(reinterpret_cast<const unsigned char*>(raw.data()),raw.size(),hash);
        std::string out=compact?"FKZSB2":"FKZSB1";Append(out,rows,4);
        out.append(reinterpret_cast<const char*>(hash),sizeof(hash));
        const auto header=out.size();out.resize(header+ZSTD_compressBound(raw.size()));
        const size_t n=ZSTD_compressCCtx(context,out.data()+header,out.size()-header,raw.data(),raw.size(),1);
        if(ZSTD_isError(n))throw std::runtime_error("selected bundle compression failed");
        out.resize(header+n);return out;
    }
    static std::string Decode(const std::string &value) {
        constexpr size_t header=10+SHA256_DIGEST_LENGTH;
        const bool compact=value.compare(0,6,"FKZSB2")==0;
        if(value.size()<=header || (!compact && value.compare(0,6,"FKZSB1")))
            throw std::runtime_error("selected bundle header invalid");
        const auto rows=Read(value,6,4);
        if(!rows || rows>max_rows)throw std::runtime_error("selected bundle row count invalid");
        std::string raw(rows*(compact?compact_row_bytes:row_bytes),'\0');
        const size_t decoded=ZSTD_decompress(raw.data(),raw.size(),value.data()+header,value.size()-header);
        if(ZSTD_isError(decoded) || decoded!=raw.size())
            throw std::runtime_error("selected bundle decoded size invalid");
        unsigned char hash[SHA256_DIGEST_LENGTH];
        SHA256(reinterpret_cast<const unsigned char*>(raw.data()),raw.size(),hash);
        if(std::memcmp(hash,value.data()+10,sizeof(hash)))
            throw std::runtime_error("selected bundle checksum mismatch");
        if(compact) {
            // Verify the stored group before synthesizing compatibility fields.
            // These bytes are an export envelope, not a second stored checksum.
            constexpr char hex[]="0123456789abcdef";
            std::string legacy(rows*row_bytes,'\0');
            for(size_t i=0;i<rows;++i) {
                const auto *body=raw.data()+i*compact_row_bytes;
                auto *destination=legacy.data()+i*row_bytes;
                std::memcpy(destination,body,compact_row_bytes);
                SHA256(reinterpret_cast<const unsigned char*>(body),compact_row_bytes,hash);
                for(size_t j=0;j<sizeof(hash);++j) {
                    destination[compact_row_bytes+2*j]=hex[hash[j]>>4];
                    destination[compact_row_bytes+2*j+1]=hex[hash[j]&15];
                }
            }
            return legacy;
        }
        return raw;
    }
};

// Verification/readback only. Bounded scratch: at most eight decoded groups;
// the online writer never creates this cache. Original per-identity lookup
// remains possible, with one additional lookup and group decompression.
struct SelectedBundleReader {
    std::map<std::string,std::string> cache;
    std::string Resolve(rocksdb::DB &db,const std::string &value) {
        if(value.compare(0,6,"FKREF1"))return value;
        if(value.size()!=SelectedBundleCodec::reference_bytes)
            throw std::runtime_error("selected bundle reference size invalid");
        const auto key=SelectedBundleCodec::Key(SelectedBundleCodec::Read(value,6,8));
        const auto index=SelectedBundleCodec::Read(value,14,4);
        auto found=cache.find(key);
        if(found==cache.end()) {
            std::string encoded;const auto status=db.Get(rocksdb::ReadOptions(),key,&encoded);
            if(!status.ok())throw std::runtime_error("selected bundle missing: "+status.ToString());
            auto raw=SelectedBundleCodec::Decode(encoded);
            if(cache.size()>=8)cache.clear();
            found=cache.emplace(key,std::move(raw)).first;
        }
        const auto &raw=found->second;
        if(index>=raw.size()/SelectedBundleCodec::row_bytes)
            throw std::runtime_error("selected bundle reference out of range");
        return raw.substr(index*SelectedBundleCodec::row_bytes,SelectedBundleCodec::row_bytes);
    }
};
}
#endif
