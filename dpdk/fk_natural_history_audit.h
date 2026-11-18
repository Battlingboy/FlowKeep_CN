#ifndef FK_NATURAL_HISTORY_AUDIT_H
#define FK_NATURAL_HISTORY_AUDIT_H
#include "fk_detector_request_shm_abi.h"
#include <array>
#include <cstdio>
#include <cstring>
#include <mutex>
#include <string>
#include <vector>
#include <openssl/sha.h>
namespace flowkeep {
// Observation only: no waits, forced targets, changes to dispatch or model input.
// Rows are buffered in process memory and written after the service ends.
class NaturalHistoryAudit {
    struct Row {
        uint64_t seq=0,authseq=0,first=0,logical=0;
        uint32_t payload_index=0,packet=0,authlatest=0,bindlatest=0,mask=0,kind=0,lookup_before=0,lookup_after=0;
        bool terminal=false,actual=false;
        double score=0;
        std::array<unsigned char,sizeof(fk_flow_key)> key{};
        std::array<unsigned char,SHA256_DIGEST_LENGTH> feature_sha{};
    };
    std::mutex mutex_;
    std::vector<Row> rows_;
    std::vector<std::array<float,159>> bound_inputs_;
    NaturalHistoryAudit(){rows_.reserve(300000);bound_inputs_.reserve(300000);}
    static std::string Hex(const unsigned char *p,size_t n) {
        static const char h[]="0123456789abcdef";
        std::string out;out.reserve(n*2);
        for(size_t i=0;i<n;++i){out.push_back(h[p[i]>>4]);out.push_back(h[p[i]&15]);}
        return out;
    }
public:
    static NaturalHistoryAudit &Get(){static NaturalHistoryAudit a;return a;}
    void Bind(const fk_detector_request_v1 &r,uint64_t seq,uint64_t authseq,
              uint32_t authlatest,uint32_t bindlatest,bool terminal,uint32_t before,uint32_t after) {
        Row x{};x.kind=0;x.seq=seq;x.authseq=authseq;x.first=r.flow_first_timestamp_ns;
        x.logical=r.logical_connection_id;x.packet=r.checkpoint_packet;x.authlatest=authlatest;
        x.bindlatest=bindlatest;x.mask=r.source_mask;x.terminal=terminal;
        x.lookup_before=before;x.lookup_after=after;
        std::memcpy(x.key.data(),&r.canonical_key,sizeof(r.canonical_key));
        SHA256(reinterpret_cast<const unsigned char*>(r.features),sizeof(r.features),x.feature_sha.data());
        std::array<float,159> input{};std::memcpy(input.data(),r.features,sizeof(r.features));
        std::lock_guard<std::mutex> lock(mutex_);x.payload_index=bound_inputs_.size();bound_inputs_.push_back(input);rows_.push_back(x);
    }
    void Score(uint64_t seq,bool actual,double score) {
        Row x{};x.kind=1;x.seq=seq;x.actual=actual;x.score=score;
        std::lock_guard<std::mutex> lock(mutex_);rows_.push_back(x);
    }
    void Finalize(uint64_t seq,uint32_t packet,uint32_t latest) {
        Row x{};x.kind=2;x.seq=seq;x.packet=packet;x.bindlatest=latest;
        std::lock_guard<std::mutex> lock(mutex_);rows_.push_back(x);
    }
    bool Save(const std::string &path) {
        std::lock_guard<std::mutex> lock(mutex_);
        FILE *f=std::fopen(path.c_str(),"wx");if(!f)return false;
        bool ok=true;
        for(const auto &x:rows_) {
            int n=0;
            if(x.kind==0)n=std::fprintf(f,
                "{\"kind\":\"bind\",\"sequence\":%llu,\"authorization_sequence\":%llu,"
                "\"key\":\"%s\",\"first\":%llu,\"logical\":%llu,\"packet\":%u,"
                "\"authorization_latest\":%u,\"bind_latest\":%u,\"terminal\":%s,"
                "\"mask\":%u,\"features_sha256\":\"%s\",\"features_hex\":\"%s\",\"lookup_latest_before\":%u,\"lookup_latest_after\":%u}\n",
                (unsigned long long)x.seq,(unsigned long long)x.authseq,Hex(x.key.data(),x.key.size()).c_str(),
                (unsigned long long)x.first,(unsigned long long)x.logical,x.packet,x.authlatest,x.bindlatest,
                x.terminal?"true":"false",x.mask,Hex(x.feature_sha.data(),x.feature_sha.size()).c_str(),Hex(reinterpret_cast<const unsigned char*>(bound_inputs_[x.payload_index].data()),636).c_str(),x.lookup_before,x.lookup_after);
            else if(x.kind==1)n=std::fprintf(f,"{\"kind\":\"score\",\"sequence\":%llu,\"actual\":%s,\"score\":%.17g}\n",
                (unsigned long long)x.seq,x.actual?"true":"false",x.score);
            else n=std::fprintf(f,"{\"kind\":\"finalize\",\"sequence\":%llu,\"packet\":%u,\"latest\":%u}\n",
                (unsigned long long)x.seq,x.packet,x.bindlatest);
            if(n<0){ok=false;break;}
        }
        if(std::fclose(f)!=0)ok=false;
        return ok;
    }
};
}
#endif
