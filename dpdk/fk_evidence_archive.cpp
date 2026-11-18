#include "fk_evidence_archive.h"
#include <rocksdb/db.h>
#include <rocksdb/cache.h>
#include <rocksdb/table.h>
#include <rocksdb/write_batch.h>
#include <rocksdb/write_buffer_manager.h>
#include <jansson.h>
#include <openssl/sha.h>
#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdlib>
#include <cstring>
#include <deque>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <memory>
#include <mutex>
#include <sstream>
#include <stdexcept>
#include <thread>
#include <utility>
#include <vector>
#include <pthread.h>
#include <sched.h>

namespace flowkeep {
namespace {
constexpr size_t kMaxBatch=1024;
constexpr size_t kEncodedLimit=2048;
constexpr size_t kWaitBuckets=48;
constexpr const char *kSchema="flowkeep-selected-evidence-v1";
uint64_t steady_ns() noexcept {
    return static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::nanoseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count());
}
constexpr std::array<uint64_t,kWaitBuckets> kWaitUpperUs{{
    1,2,3,4,5,7,10,15,20,30,40,50,75,100,150,200,
    300,400,500,750,1000,1500,2000,3000,4000,5000,7500,10000,
    15000,20000,30000,40000,50000,75000,100000,150000,
    200000,300000,400000,500000,750000,1000000,2000000,5000000,
    10000000,20000000,50000000,UINT64_MAX}};
struct WaitHistogram {
    std::array<std::atomic<uint64_t>,kWaitBuckets> total{},period{};
    void observe(uint64_t nanoseconds) noexcept {
        const uint64_t us=nanoseconds/1000;
        const size_t bucket=static_cast<size_t>(std::lower_bound(kWaitUpperUs.begin(),kWaitUpperUs.end(),us)-kWaitUpperUs.begin());
        total[bucket].fetch_add(1,std::memory_order_relaxed);
        period[bucket].fetch_add(1,std::memory_order_relaxed);
    }
    std::pair<uint64_t,uint64_t> take_period_p99() noexcept {
        uint64_t samples=0;std::array<uint64_t,kWaitBuckets> counts{};
        for(size_t i=0;i<kWaitBuckets;++i){counts[i]=period[i].exchange(0,std::memory_order_relaxed);samples+=counts[i];}
        if(!samples)return {0,0};
        const uint64_t target=(99*samples+99)/100;uint64_t seen=0;
        for(size_t i=0;i<kWaitBuckets;++i){seen+=counts[i];if(seen>=target)return {kWaitUpperUs[i],samples};}
        return {kWaitUpperUs.back(),samples};
    }
    std::pair<uint64_t,uint64_t> total_p99() const noexcept {
        uint64_t samples=0;for(const auto &v:total)samples+=v.load(std::memory_order_relaxed);
        if(!samples)return {0,0};
        const uint64_t target=(99*samples+99)/100;uint64_t seen=0;
        for(size_t i=0;i<kWaitBuckets;++i){seen+=total[i].load(std::memory_order_relaxed);
            if(seen>=target)return {kWaitUpperUs[i],samples};}
        return {kWaitUpperUs.back(),samples};
    }
};
uint64_t number(const char *name,uint64_t fallback) {
    const char *v=std::getenv(name); if(!v)return fallback;
    size_t n=0; auto x=std::stoull(v,&n);
    if(n!=std::strlen(v))throw std::runtime_error(std::string("invalid ")+name);
    return x;
}
std::string env(const char *name,const char *fallback="") {
    const char *p=std::getenv(name);return p?p:fallback;
}
std::string digest(const std::string &v) {
    unsigned char h[32];SHA256(reinterpret_cast<const unsigned char*>(v.data()),v.size(),h);
    static const char hex[]="0123456789abcdef";std::string s(64,'0');
    for(size_t i=0;i<32;++i){s[2*i]=hex[h[i]>>4];s[2*i+1]=hex[h[i]&15];}return s;
}
std::string dump(json_t *v) {
    char *p=json_dumps(v,JSON_COMPACT|JSON_SORT_KEYS);
    if(!p)throw std::runtime_error("JSON encoding failed");
    std::string s(p);std::free(p);return s;
}
void put(json_t *o,const char *k,uint64_t n) {
    // Saturating R16 accumulators can contain UINT64_MAX. Preserve all bits.
    json_object_set_new(o,k,n<=INT64_MAX?json_integer(static_cast<json_int_t>(n)):
                        json_string(std::to_string(n).c_str()));
}
void str(json_t *o,const char *k,const std::string &s){json_object_set_new(o,k,json_string(s.c_str()));}
void flag(json_t *o,const char *k,bool b){json_object_set_new(o,k,json_boolean(b));}
template<class T,size_t N> void arr(json_t *o,const char *k,const T(&v)[N]) {
    auto *a=json_array();for(auto n:v)json_array_append_new(a,static_cast<uint64_t>(n)<=INT64_MAX?
        json_integer(static_cast<json_int_t>(n)):json_string(std::to_string(n).c_str()));
    json_object_set_new(o,k,a);
}
std::string hexbytes(const void *p,size_t n) {
    const auto *b=static_cast<const unsigned char*>(p);static const char h[]="0123456789abcdef";
    std::string s(2*n,'0');for(size_t i=0;i<n;++i){s[2*i]=h[b[i]>>4];s[2*i+1]=h[b[i]&15];}return s;
}
std::string hex64(uint64_t n){std::ostringstream s;s<<std::hex<<std::setw(16)<<std::setfill('0')<<n;return s.str();}
struct Range {uint64_t first_packet=0,last_packet=0,first_ns=0,last_ns=0;};
struct Progress {
    uint64_t bytes_seen=0,gap_events=0,retransmitted_bytes=0;
    uint32_t retained_body_bytes=0,handshake_remaining=0;
    uint8_t completeness=0,desynchronized=0,closed=0;
};
struct Snapshot {
    uint64_t sequence=0,logical_id=0,flow_first_ns=0,trigger_ns=0,trigger_packet=0;
    // In-memory telemetry only. The portable RocksDB encoding below omits it.
    uint64_t enqueue_steady_ns=0;
    fk_flow_key key{};uint32_t owner=0,index=0,generation=0,trigger=0,release_reason=0;
    uint8_t component=0,first_direction=0,terminal_observed=0,range_known=0,parser_progress_available=0;
    Range range{};
    fk_compact_stat_state stat{};
    fk_compact_seq_state seq{};
    fk_compact_fingerprint_observation client{},server{};
    Progress progress[2]{};
};
struct Track {
    uint32_t generation=0;uint8_t fingerprint_bits=0,saved_mask=0;
    Range range[3]{};
    uint64_t saved_packet[3]{};
};
struct Tail {
    Snapshot base{};
    fk_compact_tls_flow tls{};
    fk_flow_key key{};
    uint64_t deadline_ns=0;
    uint32_t packets=0;
    uint8_t active=0,last_quality=0,saw_future=0,completion_seen=0;
};
// Explicit little-endian portable encoding. Neither pointers nor C++ struct
// padding enter the database. Only the selected component is serialized.
struct Wire {
    std::string bytes;size_t offset=0;bool reading=false;
    template<class T>void f(T &x){
        if(reading){if(bytes.size()-offset<sizeof(T))throw std::runtime_error("truncated evidence");
            uint64_t n=0;for(size_t i=0;i<sizeof(T);++i)n|=uint64_t(static_cast<unsigned char>(bytes[offset++]))<<(8*i);x=static_cast<T>(n);
        }else for(size_t i=0;i<sizeof(T);++i)bytes.push_back(static_cast<char>((uint64_t(x)>>(8*i))&255));
    }
    template<class T,size_t N>void a(T(&x)[N]){for(auto &v:x)f(v);}
};
void codec(Wire &w,Snapshot &s){
    w.f(s.sequence);w.f(s.logical_id);w.f(s.flow_first_ns);w.f(s.trigger_ns);w.f(s.trigger_packet);
    w.f(s.key.ip_version);w.f(s.key.protocol);w.a(s.key.low_addr);w.a(s.key.high_addr);w.f(s.key.low_port);w.f(s.key.high_port);
    w.f(s.owner);w.f(s.index);w.f(s.generation);w.f(s.trigger);w.f(s.release_reason);
    w.f(s.component);w.f(s.first_direction);w.f(s.terminal_observed);w.f(s.range_known);w.f(s.parser_progress_available);
    w.f(s.range.first_packet);w.f(s.range.last_packet);w.f(s.range.first_ns);w.f(s.range.last_ns);
    if(s.component==1){auto &v=s.stat;w.a(v.direction_packets);w.a(v.direction_bytes);w.a(v.payload_bytes);
        w.a(v.interarrival_sum_ns);w.a(v.interarrival_squared_sum_ns);w.f(v.minimum_wire_size);w.f(v.maximum_wire_size);w.a(v.tcp_flag_counts);
    }else if(s.component==2){auto &v=s.seq;w.f(v.count);w.f(v.next);
        for(auto &p:v.packets){w.f(p.delta_time_us);w.f(p.wire_size);w.f(p.direction);}
        if(v.count>20 || v.next>=20)throw std::runtime_error("invalid sequence length");
    }else if(s.component==4){
        for(auto *p:{&s.client,&s.server}){w.f(p->cipher_set_hash);w.f(p->extension_set_hash);w.f(p->signature_set_hash);
            w.f(p->server_name_hash);w.f(p->alpn_hash);w.f(p->legacy_version);w.f(p->selected_cipher);w.f(p->cipher_count);
            w.f(p->extension_count);w.f(p->signature_algorithm_count);w.f(p->present);w.f(p->hello_retry_request);w.f(p->completeness);w.f(p->framing);}
        for(auto &v:s.progress){w.f(v.bytes_seen);w.f(v.gap_events);w.f(v.retransmitted_bytes);w.f(v.retained_body_bytes);
            w.f(v.handshake_remaining);w.f(v.completeness);w.f(v.desynchronized);w.f(v.closed);}
    }else throw std::runtime_error("invalid evidence component");
    if(!s.sequence || !s.generation || s.first_direction>1 || s.range_known>1 || s.terminal_observed>1 ||
       s.range.last_packet>s.trigger_packet || s.range.first_packet>s.range.last_packet ||
       s.range.last_ns>s.trigger_ns || (s.range_known && !s.range.first_packet))throw std::runtime_error("invalid evidence bounds");
}
std::string binary(const Snapshot &snapshot){Snapshot s=snapshot;Wire w;w.bytes.reserve(512);w.bytes="FKSE1";codec(w,s);return w.bytes;}
Snapshot decode(const std::string &body){if(body.size()<5 || body.compare(0,5,"FKSE1"))throw std::runtime_error("invalid evidence encoding");
    Wire w;w.bytes=body;w.offset=5;w.reading=true;Snapshot s{};codec(w,s);
    if(w.offset!=body.size())throw std::runtime_error("trailing evidence bytes");
    return s;}
const char *component_name(uint8_t c){return c==1?"STAT":c==2?"SEQ":"JA4";}
std::string tuple(const fk_flow_key &k) {
    return std::to_string(k.ip_version)+":"+std::to_string(k.protocol)+":"+
        hexbytes(k.low_addr,16)+":"+std::to_string(k.low_port)+":"+
        hexbytes(k.high_addr,16)+":"+std::to_string(k.high_port);
}
std::string record_key(uint64_t n){std::ostringstream s;s<<"evidence/"<<std::setw(20)<<std::setfill('0')<<n;return s.str();}
std::string flow_id(const Snapshot &s,const std::string &run) {
    return digest(run+"|"+tuple(s.key)+"|"+std::to_string(s.flow_first_ns)+"|"+
                  std::to_string(s.logical_id)+"|"+std::to_string(s.owner)+"|"+
                  std::to_string(s.index)+"|"+std::to_string(s.generation));
}
json_t *fingerprint(const fk_compact_fingerprint_observation &f) {
    auto *o=json_object();
    str(o,"cipher_set_hash",hex64(f.cipher_set_hash));str(o,"extension_set_hash",hex64(f.extension_set_hash));
    str(o,"signature_set_hash",hex64(f.signature_set_hash));str(o,"server_name_hash",hex64(f.server_name_hash));
    str(o,"alpn_hash",hex64(f.alpn_hash));put(o,"legacy_version",f.legacy_version);
    put(o,"selected_cipher",f.selected_cipher);put(o,"cipher_count",f.cipher_count);
    put(o,"extension_count",f.extension_count);put(o,"signature_algorithm_count",f.signature_algorithm_count);
    put(o,"present",f.present);put(o,"hello_retry_request",f.hello_retry_request);
    put(o,"completeness",f.completeness);put(o,"framing",f.framing);return o;
}
json_t *encode(const Snapshot &s,const std::string &run) {
    auto *o=json_object();str(o,"schema",kSchema);str(o,"run_id",run);
    put(o,"sequence",s.sequence);str(o,"flow_id",flow_id(s,run));str(o,"canonical_tuple",tuple(s.key));
    put(o,"flow_first_ns",s.flow_first_ns);put(o,"logical_connection_id",s.logical_id);
    put(o,"owner",s.owner);put(o,"flow_index",s.index);put(o,"flow_generation",s.generation);
    put(o,"first_direction",s.first_direction);str(o,"component",component_name(s.component));
    put(o,"trigger",s.trigger);put(o,"release_reason",s.release_reason);
    put(o,"trigger_packet",s.trigger_packet);put(o,"trigger_ns",s.trigger_ns);
    put(o,"observed_first_packet",s.range.first_packet);put(o,"observed_last_packet",s.range.last_packet);
    put(o,"observed_first_ns",s.range.first_ns);put(o,"observed_last_ns",s.range.last_ns);
    flag(o,"range_known",s.range_known);flag(o,"full_flow_evidence",false);
    str(o,"observation_scope",s.range_known?"resident_component_interval":"no_verified_observation_interval");
    str(o,"stop_reason",s.trigger==EvidenceContinuation?"independent_ja4_continuation":
        s.trigger==EvidenceObservation?"selected_observation_point":
        s.trigger==EvidenceBeforeRelease?"original_component_release":
        s.trigger==EvidenceBeforeCompaction?"original_tls_compaction":"original_lifecycle_boundary");
    flag(o,"transport_terminal_observed",s.terminal_observed);
    str(o,"requirement","resident_stat_seq_at_4_8_12_20_or_release;ja4_on_hello_or_release;optional_bounded_ja4_tail");
    auto *p=json_object();json_object_set_new(o,"payload",p);
    if(s.component==1) {
        arr(p,"direction_packets",s.stat.direction_packets);arr(p,"direction_bytes",s.stat.direction_bytes);
        arr(p,"payload_bytes",s.stat.payload_bytes);arr(p,"interarrival_sum_ns",s.stat.interarrival_sum_ns);
        arr(p,"interarrival_squared_sum_ns",s.stat.interarrival_squared_sum_ns);
        put(p,"minimum_wire_size",s.stat.minimum_wire_size);put(p,"maximum_wire_size",s.stat.maximum_wire_size);
        arr(p,"tcp_flag_counts",s.stat.tcp_flag_counts);
        flag(o,"payload_observed",s.stat.direction_packets[0]+s.stat.direction_packets[1]>0);
    } else if(s.component==2) {
        put(p,"count",s.seq.count);put(p,"next",s.seq.next);
        auto *a=json_array();json_object_set_new(p,"packets_chronological",a);
        for(uint32_t i=0;i<s.seq.count;++i) {
            const auto &v=s.seq.packets[(s.seq.next+FK_COMPACT_SEQ_PACKETS-s.seq.count+i)%FK_COMPACT_SEQ_PACKETS];
            auto *r=json_array();json_array_append_new(r,json_integer(v.wire_size));
            json_array_append_new(r,json_integer(v.direction));json_array_append_new(r,json_integer(v.delta_time_us));
            json_array_append_new(a,r);
        }
        flag(o,"payload_observed",s.seq.count>0);
    } else {
        json_object_set_new(p,"client",fingerprint(s.client));json_object_set_new(p,"server",fingerprint(s.server));
        flag(p,"raw_handshake_body_saved",false);flag(p,"ja4_text_saved",false);
        flag(p,"parser_progress_available",s.parser_progress_available);
        flag(p,"client_hello_complete",s.client.present && s.client.completeness==FK_COMPLETENESS_COMPLETE);
        flag(p,"server_hello_complete",s.server.present && s.server.completeness==FK_COMPLETENESS_COMPLETE);
        auto *a=json_array();json_object_set_new(p,"parser_progress",a);
        for(const auto &v:s.progress){auto *r=json_object();put(r,"bytes_seen",v.bytes_seen);
            put(r,"gap_events",v.gap_events);put(r,"retransmitted_bytes",v.retransmitted_bytes);
            put(r,"retained_body_bytes_in_original_state",v.retained_body_bytes);
            put(r,"handshake_remaining",v.handshake_remaining);put(r,"completeness",v.completeness);
            flag(r,"desynchronized",v.desynchronized);flag(r,"closed",v.closed);json_array_append_new(a,r);}
        flag(o,"payload_observed",s.range_known);
        flag(o,"client_hello_present",s.client.present);flag(o,"server_hello_present",s.server.present);
    }
    return o;
}
unsigned evidence_quality(const Snapshot &s) noexcept {
    if(!s.range_known)return 0;
    if(s.component==1)return s.stat.direction_packets[0]+s.stat.direction_packets[1]>=4?2:1;
    if(s.component==2)return s.seq.count>=8?3:(s.seq.count?1:0);
    if(s.component==4){
        const bool client=s.client.present && s.client.completeness==FK_COMPLETENESS_COMPLETE;
        const bool server=s.server.present && s.server.completeness==FK_COMPLETENESS_COMPLETE;
        return client && server?5:client?4:(s.client.present || s.server.present?1:0);
    }
    return 0;
}
unsigned fixed_investigation_points(const Snapshot &s) noexcept {
    // The pre-Test requirements are fixed in evidence_policy_v1.json. No label,
    // detector score, future packets or value model enter admission.
    if(!s.range_known)return 0;
    if(s.component==1)return s.stat.direction_packets[0]+s.stat.direction_packets[1]>=4?1:0;
    if(s.component==2)return s.seq.count>=8?1:0;
    if(s.component==4){const bool client=s.client.present &&
        s.client.completeness==FK_COMPLETENESS_COMPLETE;
        const bool server=s.server.present &&
        s.server.completeness==FK_COMPLETENESS_COMPLETE;
        return client?2+static_cast<unsigned>(server):0;}
    return 0;
}
uint64_t fingerprint_set(const uint16_t *values,uint16_t count) noexcept {
    uint16_t retained[FK_TLS_CIPHER_CAP]{};size_t n=0;
    for(uint16_t i=0;i<count && n<FK_TLS_CIPHER_CAP;++i)
        if((values[i]&0x0f0fu)!=0x0a0au)retained[n++]=values[i];
    std::sort(retained,retained+n);uint64_t hash=1469598103934665603ull;
    for(size_t i=0;i<n;++i){hash^=static_cast<uint8_t>(retained[i]>>8u);hash*=1099511628211ull;
        hash^=static_cast<uint8_t>(retained[i]);hash*=1099511628211ull;}
    return hash;
}
uint64_t fingerprint_text(const char *s,size_t cap) noexcept {
    if(!s || !cap || !s[0])return 0;
    uint64_t hash=1469598103934665603ull;
    for(size_t i=0;i<cap && s[i];++i){hash^=static_cast<uint8_t>(s[i]);hash*=1099511628211ull;}
    return hash;
}
void tail_hello(const fk_tls_hello *hello,void *user) noexcept {
    auto *tail=static_cast<Tail*>(user);auto &f=hello->kind==FK_TLS_CLIENT_HELLO?
        tail->base.client:tail->base.server;f={};
    f.cipher_set_hash=fingerprint_set(hello->ciphers,hello->cipher_count);
    f.extension_set_hash=fingerprint_set(hello->extensions,hello->extension_count);
    f.signature_set_hash=fingerprint_set(hello->signature_algorithms,hello->signature_algorithm_count);
    f.server_name_hash=fingerprint_text(hello->server_name,FK_TLS_SNI_CAP);
    f.alpn_hash=fingerprint_text(hello->alpn,FK_TLS_ALPN_CAP);
    f.legacy_version=hello->legacy_version;f.selected_cipher=hello->selected_cipher;
    f.cipher_count=hello->cipher_count;f.extension_count=hello->extension_count;
    f.signature_algorithm_count=hello->signature_algorithm_count;f.present=1;
    f.hello_retry_request=hello->hello_retry_request?1:0;
    f.completeness=static_cast<uint8_t>(hello->completeness);
    f.framing=static_cast<uint8_t>(hello->framing);
}
void copy_tail_progress(Snapshot &s,const fk_compact_tls_flow &tls) noexcept {
    s.parser_progress_available=1;
    for(unsigned d=0;d<2;++d){const auto &v=tls.direction[d];auto &dst=s.progress[d];
        dst.bytes_seen=v.tls.bytes_seen;dst.gap_events=v.gap_events;
        dst.retransmitted_bytes=v.retransmitted_bytes;
        dst.retained_body_bytes=v.tls.retained_body_bytes;
        dst.handshake_remaining=v.tls.handshake_remaining;
        dst.completeness=v.tls.completeness;dst.desynchronized=v.desynchronized;
        dst.closed=v.closed;}
}
class Archive {
public:
    std::string mode,run,path,selection;bool enabled=false;
    std::atomic<uint64_t> selected{0},accepted{0},durable{0},full{0},busy{0},failed{0},capture_failed{0},unchanged{0};
    std::atomic<uint64_t> policy_suppressed{0},policy_pressure_suppressed{0};
    std::atomic<uint64_t> late_only_candidates{0},late_only_candidate_bytes{0};
    std::atomic<uint64_t> pressure_zero_suppressed{0},pressure_ratio_suppressed{0};
    std::atomic<uint64_t> rejected_db_budget{0},db_reserved_records{0},db_reserved_logical_bytes{0};
    std::atomic<uint64_t> tail_bytes{0},tail_peak_bytes{0},tail_armed{0},tail_rejected_full{0};
    std::atomic<uint64_t> tail_future_packets{0},tail_completed{0},tail_saved{0},tail_expired{0},tail_no_future{0};
    std::atomic<uint64_t> tracker_bytes{0},tracker_peak{0};
    std::atomic<uint64_t> copied_bytes{0},peak_inflight{0},encoded_bytes{0};
    std::atomic<uint64_t> selected_logical_bytes{0},accepted_logical_bytes{0};
    std::atomic<uint64_t> dequeued{0},dequeued_logical_bytes{0},durable_logical_bytes{0},db_write_busy_ns{0};
    WaitHistogram queue_wait_,durable_wait_,db_write_wait_;
    std::atomic<bool> disk_failed{false};
    uint64_t tracker_limit=0;uint32_t next_owner=0;
    Archive() {
        mode=env("FK_EVIDENCE_MODE","off");if(mode=="off")return;
        if(mode!="bounded" && mode!="async_baseline")throw std::runtime_error("invalid FK_EVIDENCE_MODE");
        selection=env("FK_EVIDENCE_SELECTION","all");
        if(selection!="all" && selection!="quality_first" && selection!="late_only" &&
            selection!="late_only_pressure")
            throw std::runtime_error("invalid FK_EVIDENCE_SELECTION");
        path=env("FK_EVIDENCE_DB");run=env("FK_EVIDENCE_RUN_ID");
        if(path.empty() || run.empty() || run.size()>128)throw std::runtime_error("evidence DB/run ID required");
        limit_bytes_=number("FK_EVIDENCE_QUEUE_BYTES",2u<<20);
        capacity_=std::min<uint64_t>(number("FK_EVIDENCE_QUEUE_RECORDS",2048),limit_bytes_/sizeof(Snapshot));
        batch_size_=number("FK_EVIDENCE_WRITE_BATCH_RECORDS",256);
        coalesce_us_=number("FK_EVIDENCE_COALESCE_US",1000);
        if((batch_size_!=64 && batch_size_!=128 && batch_size_!=256 &&
            batch_size_!=512 && batch_size_!=1024) || coalesce_us_>5000)
            throw std::runtime_error("invalid evidence batch or coalesce setting");
        db_limit_records_=number("FK_EVIDENCE_DB_MAX_RECORDS",UINT64_MAX);
        db_limit_logical_bytes_=number("FK_EVIDENCE_DB_LOGICAL_BYTES",UINT64_MAX);
        pressure_low_pct_=number("FK_EVIDENCE_PRESSURE_LOW_PCT",50);
        pressure_high_pct_=number("FK_EVIDENCE_PRESSURE_HIGH_PCT",90);
        if(!pressure_low_pct_ || pressure_low_pct_>=pressure_high_pct_ || pressure_high_pct_>100)
            throw std::runtime_error("invalid evidence pressure thresholds");
        tracker_limit=number("FK_EVIDENCE_TRACKER_BYTES",16u<<20);
        tail_slots_per_owner_=number("FK_EVIDENCE_TAIL_SLOTS_PER_OWNER",0);
        tail_limit_bytes_=number("FK_EVIDENCE_TAIL_BYTES",4u<<20);
        tail_timeout_ns_=number("FK_EVIDENCE_TAIL_TIMEOUT_NS",5'000'000'000ull);
        tail_max_packets_=number("FK_EVIDENCE_TAIL_MAX_PACKETS",12);
        delay_us_=number("FK_EVIDENCE_TEST_WRITER_DELAY_US",0);
        writer_cpu_=number("FK_EVIDENCE_WRITER_CPU",UINT64_MAX);
        if(writer_cpu_!=UINT64_MAX && writer_cpu_>=CPU_SETSIZE)throw std::runtime_error("invalid evidence writer CPU");
        telemetry_report_=env("FK_EVIDENCE_TELEMETRY_REPORT");telemetry_enabled_=!telemetry_report_.empty();
        telemetry_cpu_=number("FK_EVIDENCE_TELEMETRY_CPU",UINT64_MAX);
        telemetry_interval_ms_=number("FK_EVIDENCE_TELEMETRY_INTERVAL_MS",100);
        if(telemetry_enabled_ && (telemetry_interval_ms_<20 || telemetry_interval_ms_>1000 ||
            (telemetry_cpu_!=UINT64_MAX && telemetry_cpu_>=CPU_SETSIZE) ||
            (telemetry_cpu_!=UINT64_MAX && telemetry_cpu_==writer_cpu_)))
            throw std::runtime_error("invalid evidence telemetry period or CPU");
        fail_after_=number("FK_EVIDENCE_TEST_FAIL_AFTER_BATCHES",UINT64_MAX);
        oracle_path_=env("FK_EVIDENCE_ORACLE");report_path_=env("FK_EVIDENCE_REPORT",(path+".receipt.json").c_str());
        if(!capacity_ || capacity_>65536 || tracker_limit>(256u<<20) || tail_slots_per_owner_>128 ||
           tail_limit_bytes_>(64u<<20) || !tail_timeout_ns_ || !tail_max_packets_ || tail_max_packets_>64)
            throw std::runtime_error("invalid evidence limits");
        for(size_t i=0;i<3;++i){Snapshot test{};test.component=1u<<i;test.sequence=1;test.generation=1;
            logical_charge_[i]=binary(test).size()+32+128;}
        if(std::filesystem::exists(path))throw std::runtime_error("evidence DB must be new");
        std::filesystem::create_directories(path);
        if(!oracle_path_.empty()){oracle_.open(oracle_path_);if(!oracle_)throw std::runtime_error("cannot create oracle");}
        if(mode=="bounded"){
            slots_.resize(capacity_);slot_sequence_=std::make_unique<std::atomic<uint64_t>[]>(capacity_);
            for(uint64_t i=0;i<capacity_;++i)slot_sequence_[i].store(i,std::memory_order_relaxed);
        }
        // No on-ingress payload allocations for the bounded queue. Writing slots
        // remain charged and cannot be overwritten until the sync write returns.
        rocksdb::Options op;op.create_if_missing=true;op.paranoid_checks=true;
        op.write_buffer_size=1u<<20;op.max_write_buffer_number=2;op.max_background_jobs=2;op.max_open_files=64;
        cache_=rocksdb::NewLRUCache(2u<<20,0,true);
        buffers_=std::make_shared<rocksdb::WriteBufferManager>(4u<<20);op.write_buffer_manager=buffers_;
        rocksdb::BlockBasedTableOptions table;table.block_cache=cache_;table.cache_index_and_filter_blocks=true;
        table.index_type=rocksdb::BlockBasedTableOptions::kTwoLevelIndexSearch;table.metadata_block_size=4096;
        table.pin_top_level_index_and_filter=false;
        op.table_factory.reset(rocksdb::NewBlockBasedTableFactory(table));
        rocksdb::DB *raw=nullptr;check(rocksdb::DB::Open(op,path,&raw));db_.reset(raw);
        write_.sync=true;write_.disableWAL=false;
        rocksdb::WriteBatch b;b.Put("meta/schema",kSchema);b.Put("meta/run_id",run);check(db_->Write(write_,&b));
        enabled=true;writer_=std::thread(&Archive::worker,this);
        if(telemetry_enabled_){start_steady_ns_=steady_ns();samples_.reserve(20000);
            sample_now();telemetry_thread_=std::thread(&Archive::sampler,this);}
    }
    ~Archive(){finish();}
    bool submit(Snapshot &s) {
        ++selected;
        if(stopping_ || disk_failed){++failed;return false;}
        const uint64_t charge=logical_charge_[s.component==1?0:s.component==2?1:2];
        if(telemetry_enabled_)selected_logical_bytes.fetch_add(charge,std::memory_order_relaxed);
        const auto reserved=db_reserved_records.fetch_add(1,std::memory_order_acq_rel);
        if(reserved>=db_limit_records_){db_reserved_records.fetch_sub(1);++rejected_db_budget;return false;}
        const auto bytes=db_reserved_logical_bytes.fetch_add(charge,std::memory_order_acq_rel);
        if(charge>db_limit_logical_bytes_ || bytes>db_limit_logical_bytes_-charge){
            db_reserved_logical_bytes.fetch_sub(charge);db_reserved_records.fetch_sub(1);
            ++rejected_db_budget;return false;
        }
        const auto rollback=[&]{db_reserved_logical_bytes.fetch_sub(charge);db_reserved_records.fetch_sub(1);};
        uint64_t occupancy=0;
        if(mode=="bounded"){
            // Bounded MPSC sequence ring; no allocation, capacity wait or disk
            // wait in the producer. A writing slot is unavailable until durable.
            uint64_t pos=producer_.load(std::memory_order_relaxed);bool claimed=false;
            for(unsigned attempt=0;attempt<32;++attempt){
                if(pos-consumed_.load(std::memory_order_acquire)>=capacity_){rollback();++full;return false;}
                const auto available=slot_sequence_[pos%capacity_].load(std::memory_order_acquire);
                const auto diff=static_cast<int64_t>(available)-static_cast<int64_t>(pos);
                if(diff==0){if(producer_.compare_exchange_weak(pos,pos+1,std::memory_order_relaxed)){claimed=true;break;}}
                else if(diff<0){rollback();++full;return false;}
                else pos=producer_.load(std::memory_order_relaxed);
            }
            if(!claimed){rollback();++busy;return false;}
            s.sequence=pos+1;if(telemetry_enabled_)s.enqueue_steady_ns=steady_ns();
            slots_[pos%capacity_]=s;++accepted;
            occupancy=std::min<uint64_t>(capacity_,pos+1-consumed_.load(std::memory_order_acquire));
            slot_sequence_[pos%capacity_].store(pos+1,std::memory_order_release);
        }else{
            // Deliberately simple asynchronous archive baseline: short mutex
            // handoff and deque copy. Never waits for queue space or disk I/O.
            std::lock_guard<std::mutex> lock(mu_);
            if(outstanding_==capacity_){rollback();++full;return false;}
            s.sequence=accepted.load()+1;if(telemetry_enabled_)s.enqueue_steady_ns=steady_ns();
            simple_.push_back(s);
            ++queued_;++outstanding_;++accepted;occupancy=outstanding_;
        }
        copied_bytes+=sizeof(Snapshot);
        if(telemetry_enabled_)accepted_logical_bytes.fetch_add(charge,std::memory_order_relaxed);
        uint64_t peak=peak_inflight.load();const uint64_t queue_charge=occupancy*sizeof(Snapshot);
        while(peak<queue_charge && !peak_inflight.compare_exchange_weak(peak,queue_charge)){}
        if(oracle_.is_open()){std::lock_guard<std::mutex> lock(oracle_mutex_);
            const auto value=binary(s);
            oracle_<<record_key(s.sequence)<<' '<<digest(value)<<'\n';
            if(!oracle_)throw std::runtime_error("oracle write failure");}
        ready_.notify_one();return true;
    }
    bool should_submit(const Snapshot &s) noexcept {
        if((selection=="late_only" || selection=="late_only_pressure") &&
            s.trigger==EvidenceObservation){++policy_suppressed;return false;}
        ++late_only_candidates;
        if(telemetry_enabled_)late_only_candidate_bytes.fetch_add(
            logical_charge_[s.component==1?0:s.component==2?1:2],std::memory_order_relaxed);
        if(selection=="late_only_pressure"){
            const uint64_t accepted_now=accepted.load(std::memory_order_relaxed);
            const uint64_t durable_now=durable.load(std::memory_order_relaxed);
            const uint64_t pending=accepted_now>durable_now?accepted_now-durable_now:0;
            const unsigned points=fixed_investigation_points(s);
            if(pending*100>=capacity_*pressure_low_pct_ && !points){
                ++policy_suppressed;++policy_pressure_suppressed;++pressure_zero_suppressed;return false;}
            const uint64_t charge=logical_charge_[s.component==1?0:s.component==2?1:2];
            if(pending*100>=capacity_*pressure_high_pct_ &&
                static_cast<uint64_t>(points)*logical_charge_[0]<charge){
                ++policy_suppressed;++policy_pressure_suppressed;++pressure_ratio_suppressed;return false;}
        }
        if(selection=="quality_first"){
            // Causal queue occupancy; neither labels nor future alert outcomes
            // enter this fixed rule. Preserve partial evidence when not busy.
            const uint64_t pending=accepted.load(std::memory_order_relaxed)-durable.load(std::memory_order_relaxed);
            const unsigned quality=evidence_quality(s);
            if((pending*10>=capacity_*8 && quality<=1) ||
               (pending*10>=capacity_*5 && quality==0)){
                ++policy_suppressed;++policy_pressure_suppressed;return false;
            }
        }
        return true;
    }
    size_t tail_slots_per_owner() const noexcept {return tail_slots_per_owner_;}
    uint64_t tail_limit_bytes() const noexcept {return tail_limit_bytes_;}
    uint64_t tail_timeout_ns() const noexcept {return tail_timeout_ns_;}
    uint32_t tail_max_packets() const noexcept {return static_cast<uint32_t>(tail_max_packets_);}
    bool finish() noexcept {
        if(!enabled || finished_)return !disk_failed;
        {std::lock_guard<std::mutex> lock(mu_);stopping_=true;}ready_.notify_one();
        if(writer_.joinable())writer_.join();
        if(telemetry_enabled_){telemetry_stop_.store(true,std::memory_order_release);
            if(telemetry_thread_.joinable())telemetry_thread_.join();
            if(samples_.size()<20000)sample_now();
            telemetry_write_failed_=telemetry_write_failed_ || !write_telemetry();}
        oracle_.close();finished_=true;
        try {
            auto *o=json_object();str(o,"mode",mode);str(o,"database",path);str(o,"run_id",run);
            flag(o,"sync",true);flag(o,"wal",true);flag(o,"enqueue_is_durable",false);
            flag(o,"release_waits_for_archive",false);flag(o,"independent_continuation_enabled",tail_slots_per_owner_>0);
            str(o,"selection",selection);put(o,"selected",selected);put(o,"accepted",accepted);
            put(o,"late_only_candidates",late_only_candidates);
            put(o,"late_only_candidate_logical_bytes",late_only_candidate_bytes);
            put(o,"policy_suppressed",policy_suppressed);put(o,"policy_pressure_suppressed",policy_pressure_suppressed);
            put(o,"pressure_zero_suppressed",pressure_zero_suppressed);
            put(o,"pressure_ratio_suppressed",pressure_ratio_suppressed);
            put(o,"pressure_low_pct",pressure_low_pct_);put(o,"pressure_high_pct",pressure_high_pct_);
            put(o,"logical_charge_stat",logical_charge_[0]);put(o,"logical_charge_seq",logical_charge_[1]);
            put(o,"logical_charge_ja4",logical_charge_[2]);
            put(o,"rejected_db_budget",rejected_db_budget);
            put(o,"db_reserved_records",db_reserved_records);put(o,"db_reserved_logical_bytes",db_reserved_logical_bytes);
            put(o,"db_limit_records",db_limit_records_);put(o,"db_limit_logical_bytes",db_limit_logical_bytes_);
            str(o,"db_budget_scope","snapshot_value_sha_index_logical_charge;not_physical_rocksdb_directory_size");
            put(o,"tail_slots_per_owner",tail_slots_per_owner_);put(o,"tail_limit_bytes",tail_limit_bytes_);
            put(o,"tail_timeout_ns",tail_timeout_ns_);put(o,"tail_max_packets",tail_max_packets_);
            put(o,"tail_peak_bytes",tail_peak_bytes);put(o,"tail_armed",tail_armed);
            put(o,"tail_rejected_full",tail_rejected_full);put(o,"tail_future_packets",tail_future_packets);
            put(o,"tail_completed",tail_completed);put(o,"tail_saved",tail_saved);
            put(o,"tail_expired",tail_expired);put(o,"tail_no_future",tail_no_future);
            put(o,"unchanged_snapshots_skipped",unchanged);
            flag(o,"all_selected_persisted",selected==durable && capture_failed==0);
            put(o,"durable",durable);put(o,"rejected_full",full);put(o,"rejected_busy",busy);
            put(o,"rejected_failed_or_stopping",failed);put(o,"capture_failures",capture_failed);
            put(o,"accepted_but_not_durable",accepted-durable);flag(o,"write_failed",disk_failed);
            put(o,"snapshot_object_bytes",sizeof(Snapshot));put(o,"queue_capacity_records",capacity_);
            put(o,"queue_payload_limit_bytes",limit_bytes_);put(o,"queue_preallocated_payload_bytes",slots_.capacity()*sizeof(Snapshot));
            put(o,"queue_sequence_metadata_bytes",mode=="bounded"?capacity_*sizeof(std::atomic<uint64_t>):0);
            put(o,"tracker_registry_static_bytes",128*(sizeof(void*)*2));
            put(o,"queue_peak_outstanding_payload_bytes",peak_inflight);put(o,"tracker_peak_bytes",tracker_peak);
            put(o,"baseline_writer_copy_bytes",mode=="async_baseline"?batch_size_*sizeof(Snapshot):0);
            put(o,"writer_encoded_batch_bound_bytes",batch_size_*(2*kEncodedLimit+512));
            put(o,"rocksdb_cache_capacity_bytes",2u<<20);put(o,"rocksdb_write_buffer_manager_threshold_bytes",4u<<20);
            put(o,"rocksdb_cache_usage_at_close",cache_->GetUsage());put(o,"rocksdb_memtables_at_close",buffers_->memory_usage());
            flag(o,"rocksdb_threshold_is_process_rss_cap",false);flag(o,"oracle_enabled",!oracle_path_.empty());
            put(o,"successful_batches",batches_);put(o,"encoded_bytes_written",encoded_bytes);
            flag(o,"telemetry_enabled",telemetry_enabled_);flag(o,"telemetry_write_failed",telemetry_write_failed_);
            if(telemetry_enabled_){str(o,"telemetry_report",telemetry_report_);
                put(o,"selected_logical_bytes",selected_logical_bytes);
                put(o,"accepted_logical_bytes",accepted_logical_bytes);
                put(o,"writer_dequeued",dequeued);put(o,"writer_dequeued_logical_bytes",dequeued_logical_bytes);
                put(o,"durable_logical_bytes",durable_logical_bytes);
                put(o,"db_write_busy_ns",db_write_busy_ns);
                const auto q=queue_wait_.total_p99(),d=durable_wait_.total_p99(),w=db_write_wait_.total_p99();
                put(o,"queue_wait_p99_upper_us",q.first);put(o,"queue_wait_samples",q.second);
                put(o,"durable_wait_p99_upper_us",d.first);put(o,"durable_wait_samples",d.second);
                put(o,"sync_write_batch_p99_upper_us",w.first);put(o,"sync_write_batch_samples",w.second);
                str(o,"wait_p99_scope","histogram_upper_bound_for_accepted_records_or_completed_sync_batches");
                put(o,"telemetry_period_ms",telemetry_interval_ms_);put(o,"telemetry_samples",samples_.size());}
            put(o,"maximum_write_batch_records",batch_size_);put(o,"maximum_coalesce_us",coalesce_us_);
            if(writer_cpu_!=UINT64_MAX)put(o,"writer_cpu",writer_cpu_);
            put(o,"outstanding_at_close",accepted-durable);str(o,"last_error",error_);
            std::ofstream out(report_path_);out<<dump(o)<<'\n';json_decref(o);
            if(!out)return false;
        }catch(...){return false;}
        return !disk_failed && !telemetry_write_failed_ && accepted==durable;
    }
private:
    struct Sample {
        uint64_t steady_time_ns=0,unix_time_ns=0,candidates=0,candidate_bytes=0,selected=0,selected_bytes=0;
        uint64_t accepted=0,accepted_bytes=0,dequeued=0,dequeued_bytes=0;
        uint64_t durable=0,durable_bytes=0,durable_logical_bytes=0;
        uint64_t rejected_full=0,rejected_busy=0,rejected_db_budget=0;
        uint64_t pending_slots=0,ready_records=0,writing_records=0,db_write_busy_ns=0;
        uint64_t queue_wait_p99_upper_us=0,queue_wait_samples=0;
        uint64_t durable_wait_p99_upper_us=0,durable_wait_samples=0;
        uint64_t sync_write_p99_upper_us=0,sync_write_samples=0;
    };
    std::string telemetry_report_;
    bool telemetry_enabled_=false,telemetry_write_failed_=false;
    uint64_t telemetry_cpu_=UINT64_MAX,telemetry_interval_ms_=100,start_steady_ns_=0;
    std::atomic<bool> telemetry_stop_{false};std::thread telemetry_thread_;
    std::vector<Sample> samples_;
    void sample_now() noexcept {
        Sample s{};s.steady_time_ns=steady_ns()-start_steady_ns_;
        s.unix_time_ns=static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::nanoseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count());
        s.candidates=late_only_candidates.load();s.candidate_bytes=late_only_candidate_bytes.load();
        s.selected=selected.load();s.selected_bytes=selected_logical_bytes.load();
        s.accepted=accepted.load();s.accepted_bytes=accepted_logical_bytes.load();
        s.dequeued=dequeued.load();s.dequeued_bytes=dequeued_logical_bytes.load();
        s.durable=durable.load();s.durable_bytes=encoded_bytes.load();
        s.durable_logical_bytes=durable_logical_bytes.load();
        s.rejected_full=full.load();s.rejected_busy=busy.load();s.rejected_db_budget=rejected_db_budget.load();
        s.pending_slots=s.accepted>s.durable?s.accepted-s.durable:0;
        s.ready_records=s.accepted>s.dequeued?s.accepted-s.dequeued:0;
        s.writing_records=s.dequeued>s.durable?s.dequeued-s.durable:0;
        s.db_write_busy_ns=db_write_busy_ns.load();
        const auto q=queue_wait_.take_period_p99(),d=durable_wait_.take_period_p99(),w=db_write_wait_.take_period_p99();
        s.queue_wait_p99_upper_us=q.first;s.queue_wait_samples=q.second;
        s.durable_wait_p99_upper_us=d.first;s.durable_wait_samples=d.second;
        s.sync_write_p99_upper_us=w.first;s.sync_write_samples=w.second;
        samples_.push_back(s);
    }
    void sampler() noexcept {
        if(telemetry_cpu_!=UINT64_MAX){cpu_set_t set;CPU_ZERO(&set);CPU_SET(telemetry_cpu_,&set);
            if(pthread_setaffinity_np(pthread_self(),sizeof(set),&set)!=0){telemetry_write_failed_=true;return;}}
        while(!telemetry_stop_.load(std::memory_order_acquire)){
            std::this_thread::sleep_for(std::chrono::milliseconds(telemetry_interval_ms_));
            if(samples_.size()<20000)sample_now();
        }
    }
    bool write_telemetry() noexcept {
        try {
            std::ofstream output(telemetry_report_);if(!output)return false;
            output<<"{\"schema\":\"flowkeep-evidence-window-rates-v1\",\"period_ms\":"<<telemetry_interval_ms_
                  <<",\"p99_is_histogram_upper_bound\":true,\"samples\":[";
            for(size_t i=0;i<samples_.size();++i){const auto &s=samples_[i];
                if(i)output<<',';
                auto *o=json_object();
                put(o,"steady_time_ns",s.steady_time_ns);put(o,"unix_time_ns",s.unix_time_ns);
                put(o,"candidates",s.candidates);put(o,"candidate_bytes",s.candidate_bytes);
                put(o,"selected",s.selected);put(o,"selected_bytes",s.selected_bytes);
                put(o,"accepted",s.accepted);put(o,"accepted_bytes",s.accepted_bytes);
                put(o,"dequeued",s.dequeued);put(o,"dequeued_bytes",s.dequeued_bytes);
                put(o,"durable",s.durable);put(o,"durable_bytes",s.durable_bytes);
                put(o,"durable_logical_bytes",s.durable_logical_bytes);
                put(o,"rejected_full",s.rejected_full);put(o,"rejected_busy",s.rejected_busy);
                put(o,"rejected_db_budget",s.rejected_db_budget);
                put(o,"pending_slots",s.pending_slots);put(o,"ready_records",s.ready_records);
                put(o,"writing_records",s.writing_records);put(o,"db_write_busy_ns",s.db_write_busy_ns);
                put(o,"queue_wait_p99_upper_us",s.queue_wait_p99_upper_us);
                put(o,"queue_wait_samples",s.queue_wait_samples);
                put(o,"durable_wait_p99_upper_us",s.durable_wait_p99_upper_us);
                put(o,"durable_wait_samples",s.durable_wait_samples);
                put(o,"sync_write_p99_upper_us",s.sync_write_p99_upper_us);
                put(o,"sync_write_samples",s.sync_write_samples);
                output<<dump(o);json_decref(o);
            }
            output<<"]}\n";return static_cast<bool>(output);
        }catch(...){return false;}
    }
    void check(const rocksdb::Status &s){if(!s.ok())throw std::runtime_error(s.ToString());}
    uint64_t limit_bytes_=0,capacity_=0,delay_us_=0,fail_after_=0,batches_=0,writer_cpu_=UINT64_MAX;
    uint64_t batch_size_=256,coalesce_us_=1000;
    uint64_t db_limit_records_=UINT64_MAX,db_limit_logical_bytes_=UINT64_MAX;
    uint64_t pressure_low_pct_=50,pressure_high_pct_=90;
    uint64_t tail_slots_per_owner_=0,tail_limit_bytes_=0,tail_timeout_ns_=0,tail_max_packets_=0;
    std::array<uint64_t,3> logical_charge_{};
    size_t queued_=0,outstanding_=0;std::atomic<bool> stopping_{false};bool finished_=false;
    std::atomic<uint64_t> producer_{0},consumed_{0};
    std::unique_ptr<std::atomic<uint64_t>[]> slot_sequence_;
    std::string oracle_path_,report_path_,error_;std::ofstream oracle_;
    std::vector<Snapshot> slots_;std::deque<Snapshot> simple_;
    std::mutex mu_,oracle_mutex_;std::condition_variable ready_;std::thread writer_;
    std::shared_ptr<rocksdb::Cache> cache_;std::shared_ptr<rocksdb::WriteBufferManager> buffers_;
    std::unique_ptr<rocksdb::DB> db_;rocksdb::WriteOptions write_;
    void worker() noexcept {
        try {
            if(writer_cpu_!=UINT64_MAX){cpu_set_t set;CPU_ZERO(&set);CPU_SET(writer_cpu_,&set);
                if(pthread_setaffinity_np(pthread_self(),sizeof(set),&set)!=0)throw std::runtime_error("cannot bind evidence writer CPU");}
            std::vector<Snapshot> copy;if(mode=="async_baseline")copy.reserve(batch_size_);
            std::array<const Snapshot*,kMaxBatch> batch{};
            for(;;) {
                size_t count=0;
                uint64_t position=consumed_.load(std::memory_order_relaxed);
                if(mode=="bounded"){
                    if(!stopping_ && producer_.load(std::memory_order_acquire)-position<std::min<uint64_t>(batch_size_,capacity_)){
                        std::unique_lock<std::mutex> lock(mu_);
                        ready_.wait_for(lock,std::chrono::microseconds(coalesce_us_),[&]{return stopping_ ||
                            producer_.load(std::memory_order_acquire)-position>=std::min<uint64_t>(batch_size_,capacity_);});
                    }
                    while(count<batch_size_ && count<capacity_ &&
                        slot_sequence_[(position+count)%capacity_].load(std::memory_order_acquire)==position+count+1){
                        batch[count]=&slots_[(position+count)%capacity_];++count;
                    }
                    if(!count){
                        if(stopping_ && position==producer_.load(std::memory_order_acquire))break;
                        std::unique_lock<std::mutex> lock(mu_);
                        ready_.wait_for(lock,std::chrono::milliseconds(1),[&]{return stopping_ ||
                            slot_sequence_[position%capacity_].load(std::memory_order_acquire)==position+1;});
                        continue;
                    }
                }else{std::unique_lock<std::mutex> lock(mu_);ready_.wait(lock,[&]{return stopping_ || queued_;});
                    if(!queued_ && stopping_)break;
                    if(!stopping_ && queued_<std::min<uint64_t>(batch_size_,capacity_))
                        ready_.wait_for(lock,std::chrono::microseconds(coalesce_us_),[&]{return stopping_ || queued_>=std::min<uint64_t>(batch_size_,capacity_);});
                    count=std::min(batch_size_,queued_);copy.clear();
                    for(size_t i=0;i<count;++i){
                        copy.push_back(simple_.front());simple_.pop_front();batch[i]=&copy.back();
                    }
                    queued_-=count;
                }
                uint64_t batch_logical_bytes=0;
                if(telemetry_enabled_){const uint64_t now=steady_ns();
                    for(size_t i=0;i<count;++i){const auto &s=*batch[i];
                        batch_logical_bytes+=logical_charge_[s.component==1?0:s.component==2?1:2];
                        if(s.enqueue_steady_ns && now>=s.enqueue_steady_ns)
                            queue_wait_.observe(now-s.enqueue_steady_ns);}
                    dequeued_logical_bytes.fetch_add(batch_logical_bytes,std::memory_order_relaxed);
                    dequeued.fetch_add(count,std::memory_order_release);}
                if(delay_us_)std::this_thread::sleep_for(std::chrono::microseconds(delay_us_));
                if(batches_>=fail_after_)throw std::runtime_error("injected archive write failure");
                rocksdb::WriteBatch write_batch;uint64_t bytes=0;
                for(size_t i=0;i<count;++i){const auto &s=*batch[i];
                    const std::string body=binary(s);
                    if(body.size()>kEncodedLimit)throw std::runtime_error("snapshot encoding exceeds bound");
                    const auto encoded=body+digest(body);
                    const auto key=record_key(s.sequence);write_batch.Put(key,encoded);
                    write_batch.Put("flow/"+flow_id(s,run)+"/"+component_name(s.component)+"/"+key.substr(9),key);
                    bytes+=encoded.size();
                }
                write_batch.Put("meta/durable_sequence",std::to_string(batch[count-1]->sequence));
                const uint64_t write_start=telemetry_enabled_?steady_ns():0;
                check(db_->Write(write_,&write_batch)); // durable only after synced WAL success
                if(telemetry_enabled_){const uint64_t now=steady_ns();
                    const uint64_t elapsed=now>=write_start?now-write_start:0;
                    db_write_busy_ns.fetch_add(elapsed,std::memory_order_relaxed);
                    durable_logical_bytes.fetch_add(batch_logical_bytes,std::memory_order_relaxed);
                    db_write_wait_.observe(elapsed);
                    for(size_t i=0;i<count;++i){const auto &s=*batch[i];
                        if(s.enqueue_steady_ns && now>=s.enqueue_steady_ns)
                            durable_wait_.observe(now-s.enqueue_steady_ns);}}
                durable+=count;++batches_;encoded_bytes+=bytes;
                if(mode=="bounded"){
                    for(size_t i=0;i<count;++i)slot_sequence_[(position+i)%capacity_].store(position+i+capacity_,std::memory_order_release);
                    consumed_.store(position+count,std::memory_order_release);
                }else{std::lock_guard<std::mutex> lock(mu_);outstanding_-=count;}
            }
        }catch(const std::exception &e){std::lock_guard<std::mutex> lock(mu_);error_=e.what();disk_failed=true;}
        catch(...){std::lock_guard<std::mutex> lock(mu_);error_="unknown archive writer failure";disk_failed=true;}
    }
};
Archive &archive(){static Archive a;return a;}
}
struct EvidenceTracker {
    fk_compact_flow_table *table=nullptr;uint32_t owner=0;
    std::vector<Track> slots;std::vector<Tail> tails;uint32_t tail_active=0;
};
namespace {
struct TrackerEntry {std::atomic<fk_compact_flow_table*> table{nullptr};std::atomic<EvidenceTracker*> tracker{nullptr};};
std::array<TrackerEntry,128> trackers{};std::mutex attach_mutex;std::atomic<size_t> tracker_count{0};
}
EvidenceTracker *EvidenceFor(fk_compact_flow_table *table) noexcept {
    for(size_t i=0;i<tracker_count.load(std::memory_order_acquire);++i){
        if(trackers[i].table.load(std::memory_order_acquire)==table)
            return trackers[i].tracker.load(std::memory_order_acquire);
    }return nullptr;
}
EvidenceTracker *EvidenceAttach(fk_compact_flow_table *table,uint32_t capacity) {
    auto &a=archive();if(!a.enabled)return nullptr;
    std::lock_guard<std::mutex> lock(attach_mutex);
    const uint64_t bytes=sizeof(EvidenceTracker)+capacity*sizeof(Track);
    const uint64_t tail_bytes=a.tail_slots_per_owner()*sizeof(Tail);
    if(bytes>a.tracker_limit || a.tracker_bytes> a.tracker_limit-bytes)throw std::runtime_error("evidence tracker budget exhausted");
    if(tail_bytes>a.tail_limit_bytes() || a.tail_bytes>a.tail_limit_bytes()-tail_bytes)
        throw std::runtime_error("evidence tail budget exhausted");
    size_t slot=0;while(slot<trackers.size() && trackers[slot].table.load())++slot;
    if(slot==trackers.size())throw std::runtime_error("too many evidence owners");
    auto p=std::make_unique<EvidenceTracker>();p->table=table;p->owner=a.next_owner++;p->slots.resize(capacity);
    p->tails.resize(a.tail_slots_per_owner());
    a.tracker_bytes+=bytes;a.tracker_peak=std::max<uint64_t>(a.tracker_peak,a.tracker_bytes);
    a.tail_bytes+=tail_bytes;a.tail_peak_bytes=std::max<uint64_t>(a.tail_peak_bytes,a.tail_bytes);
    trackers[slot].tracker.store(p.get(),std::memory_order_release);
    trackers[slot].table.store(table,std::memory_order_release);
    tracker_count.store(std::max(tracker_count.load(),slot+1),std::memory_order_release);
    return p.release();
}
void EvidenceDetach(EvidenceTracker *p) noexcept {
    if(!p)return;
    std::lock_guard<std::mutex> lock(attach_mutex);
    for(auto &slot:trackers)if(slot.tracker.load()==p){slot.table.store(nullptr,std::memory_order_release);slot.tracker.store(nullptr);}
    auto &a=archive();a.tracker_bytes-=sizeof(EvidenceTracker)+p->slots.capacity()*sizeof(Track);
    for(const auto &tail:p->tails)if(tail.active && !tail.saw_future)++a.tail_no_future;
    a.tail_bytes-=p->tails.capacity()*sizeof(Tail);delete p;
}
namespace {
void arm_tail(EvidenceTracker *p,fk_compact_flow_table *table,fk_compact_flow_handle h,
              const fk_compact_flow_snapshot &flow,const fk_compact_core_state &core,
              const Range &range,uint32_t reason) noexcept {
    auto &a=archive();if(p->tails.empty() || core.terminal_observed || !range.first_packet)return;
    bool full=false;const auto *ja4=fk_compact_flow_table_resident_ja4(table,h,&full);
    if(!ja4 || !full)return; // summary lacks the parser; cannot be rehydrated
    const bool both_complete=ja4->client.present && ja4->server.present &&
        ja4->client.completeness==FK_COMPLETENESS_COMPLETE &&
        ja4->server.completeness==FK_COMPLETENESS_COMPLETE;
    if(both_complete || ja4->tls.direction[0].desynchronized || ja4->tls.direction[1].desynchronized)
        return;
    for(auto &tail:p->tails)if(tail.active && tail.base.index==h.index &&
        tail.base.generation==h.generation)return;
    Tail *chosen=nullptr;for(auto &tail:p->tails)if(!tail.active){chosen=&tail;break;}
    if(!chosen){++a.tail_rejected_full;return;}
    auto &tail=*chosen;tail={};tail.active=1;tail.key=flow.key;tail.tls=ja4->tls;
    tail.base.key=flow.key;tail.base.logical_id=core.logical_connection_id;
    tail.base.flow_first_ns=flow.first_timestamp_ns;tail.base.trigger_ns=flow.last_timestamp_ns;
    tail.base.trigger_packet=flow.packets;tail.base.owner=p->owner;tail.base.index=h.index;
    tail.base.generation=h.generation;tail.base.component=4;tail.base.trigger=EvidenceBeforeRelease;
    tail.base.release_reason=reason;tail.base.first_direction=flow.first_direction;
    tail.base.range=range;tail.base.range_known=1;tail.base.client=ja4->client;
    tail.base.server=ja4->server;copy_tail_progress(tail.base,tail.tls);
    tail.last_quality=evidence_quality(tail.base);
    const auto timeout=a.tail_timeout_ns();tail.deadline_ns=flow.last_timestamp_ns>UINT64_MAX-timeout?
        UINT64_MAX:flow.last_timestamp_ns+timeout;
    ++p->tail_active;++a.tail_armed;
}
}
void EvidenceCapture(EvidenceTracker *p,fk_compact_flow_table *table,fk_compact_flow_handle h,
                     uint8_t mask,EvidenceTrigger trigger,uint32_t reason) noexcept {
    if(!p || h.index>=p->slots.size())return;
    try {
        auto &a=archive();auto &t=p->slots[h.index];
        if(t.generation!=h.generation){t={};t.generation=h.generation;}
        fk_compact_flow_snapshot flow{};fk_compact_core_state core{};
        if(!fk_compact_flow_table_snapshot(table,h,&flow) || !fk_compact_flow_table_capture_core(table,h,&core)){
            ++a.capture_failed;return;}
        if(trigger==EvidenceBeforeRelease && (mask&4))
            arm_tail(p,table,h,flow,core,t.range[2],reason);
        struct Candidate {unsigned component_index;Snapshot snapshot;};
        std::array<Candidate,3> candidates{};size_t candidate_count=0;
        for(unsigned i=0;i<3;++i){const uint8_t c=1u<<i;if(!(mask&c))continue;
            // Fixed requirement is to preserve each distinct observed version.
            // A release with no intervening observation does not need another
            // copy. The prior immutable copy remains charged until sync. Failed
            // admission is never marked saved, so a later boundary may retry.
            if((t.saved_mask&c) && t.saved_packet[i]==t.range[i].last_packet && t.range[i].last_packet){++a.unchanged;continue;}
            Snapshot s{};s.key=flow.key;s.logical_id=core.logical_connection_id;s.flow_first_ns=flow.first_timestamp_ns;
            s.trigger_ns=flow.last_timestamp_ns;s.trigger_packet=flow.packets;s.owner=p->owner;
            s.index=h.index;s.generation=h.generation;s.component=c;s.trigger=trigger;s.release_reason=reason;
            s.first_direction=flow.first_direction;s.terminal_observed=core.terminal_observed;
            s.range=t.range[i];s.range_known=s.range.first_packet!=0;
            if(c==1){auto *v=fk_compact_flow_table_stat(table,h);if(!v)continue;s.stat=*v;}
            else if(c==2){auto *v=fk_compact_flow_table_seq(table,h);if(!v)continue;s.seq=*v;
                if(v->count>FK_COMPACT_SEQ_PACKETS || v->next>=FK_COMPACT_SEQ_PACKETS){++a.capture_failed;continue;}
                if(s.range_known && s.range.last_packet-s.range.first_packet+1>v->count){
                    s.range.first_packet=s.range.last_packet-v->count+1;
                    // A bounded sequence can roll. We do not invent a timestamp for its new head.
                    s.range.first_ns=0;
                }
            }else{bool full=false;auto *v=fk_compact_flow_table_resident_ja4(table,h,&full);if(!v)continue;
                s.client=v->client;s.server=v->server;s.parser_progress_available=full;
                if(full)for(unsigned d=0;d<2;++d){const auto &vdir=v->tls.direction[d];auto &dst=s.progress[d];
                    dst.bytes_seen=vdir.tls.bytes_seen;dst.gap_events=vdir.gap_events;dst.retransmitted_bytes=vdir.retransmitted_bytes;
                    dst.retained_body_bytes=vdir.tls.retained_body_bytes;dst.handshake_remaining=vdir.tls.handshake_remaining;
                    dst.completeness=vdir.tls.completeness;dst.desynchronized=vdir.desynchronized;dst.closed=vdir.closed;}
            }
            candidates[candidate_count++]={i,s};
        }
        if(a.selection=="quality_first"){
            std::stable_sort(candidates.begin(),candidates.begin()+candidate_count,
                [](const Candidate &left,const Candidate &right){
                    return evidence_quality(left.snapshot)>evidence_quality(right.snapshot);});
        }
        for(size_t n=0;n<candidate_count;++n){
            auto &candidate=candidates[n];auto &s=candidate.snapshot;
            if(a.should_submit(s) && a.submit(s)){
                const unsigned i=candidate.component_index;
                t.saved_mask|=1u<<i;t.saved_packet[i]=t.range[i].last_packet;
            }
        }
    }catch(...){++archive().capture_failed;}
}
void EvidenceObserve(EvidenceTracker *p,fk_compact_flow_table *table,fk_compact_flow_handle h,uint8_t updated) noexcept {
    if(!p || !updated || h.index>=p->slots.size())return;
    try {
        fk_compact_flow_snapshot s{};if(!fk_compact_flow_table_snapshot(table,h,&s)){++archive().capture_failed;return;}
        auto &t=p->slots[h.index];if(t.generation!=h.generation){t={};t.generation=h.generation;}
        for(unsigned i=0;i<3;++i)if(updated&(1u<<i)){
            auto &r=t.range[i];if(!r.first_packet){r.first_packet=s.packets;r.first_ns=s.last_timestamp_ns;}
            r.last_packet=s.packets;r.last_ns=s.last_timestamp_ns;
        }
        uint8_t capture=0;
        if(s.packets==4 || s.packets==8 || s.packets==12 || s.packets==20)capture=updated&3;
        if(updated&4){bool full=false;auto *j=fk_compact_flow_table_resident_ja4(table,h,&full);
            if(j){uint8_t bits=(j->client.present?1:0)|(j->server.present?2:0);
                if(bits!=t.fingerprint_bits){capture|=4;t.fingerprint_bits=bits;}}}
        if(capture)EvidenceCapture(p,table,h,capture,EvidenceObservation);
    }catch(...){++archive().capture_failed;}
}
void EvidenceContinue(EvidenceTracker *p,const fk_flow_key *key,uint8_t direction,
                      const fk_packet_view *view,uint64_t timestamp_ns) noexcept {
    if(!p || !p->tail_active || !key || !view || direction>1 || view->l4_protocol!=6)return;
    try {
        auto &a=archive();const bool new_epoch=(view->tcp_flags&FK_TCP_FLAG_SYN) &&
            !(view->tcp_flags&FK_TCP_FLAG_ACK);
        for(auto &tail:p->tails){
            if(!tail.active)continue;
            if(timestamp_ns>tail.deadline_ns){tail.active=0;--p->tail_active;++a.tail_expired;continue;}
            if(!fk_flow_key_equal(&tail.key,key))continue;
            if(new_epoch){tail.active=0;--p->tail_active;++a.tail_expired;continue;}
            if(timestamp_ns<tail.base.trigger_ns)continue;
            tail.saw_future=1;++tail.packets;++a.tail_future_packets;
            if(view->payload && view->payload_size && !view->payload_truncated){
                fk_compact_tls_flow_feed(&tail.tls,direction,view->tcp_sequence,
                    view->tcp_flags,view->payload,view->payload_size,tail_hello,&tail);
                tail.base.range.last_packet=tail.base.trigger_packet+tail.packets;
                tail.base.range.last_ns=timestamp_ns;
                const unsigned quality=evidence_quality(tail.base);
                if(quality>=4 && quality>tail.last_quality){
                    if(!tail.completion_seen){++a.tail_completed;tail.completion_seen=1;}
                    Snapshot s=tail.base;s.trigger=EvidenceContinuation;
                    s.trigger_packet=tail.base.trigger_packet+tail.packets;s.trigger_ns=timestamp_ns;
                    copy_tail_progress(s,tail.tls);
                    if(a.should_submit(s) && a.submit(s)){
                        ++a.tail_saved;tail.last_quality=quality;
                        if(quality>=5){tail.active=0;--p->tail_active;}
                    }
                }
            }
            if(tail.active && tail.packets>=a.tail_max_packets()){
                tail.active=0;--p->tail_active;++a.tail_expired;
            }
        }
    }catch(...){++archive().capture_failed;}
}
bool EvidenceFinish() noexcept {try{return archive().finish();}catch(...){return false;}}
uint64_t EvidencePendingRecords() noexcept {try{auto &a=archive();return a.accepted-a.durable;}catch(...){return 0;}}
int EvidenceRead(const std::string &path,const std::string &oracle_path,const std::string &output,
                 const std::string &filter,size_t limit) {
    try {
        rocksdb::Options op;rocksdb::DB *raw=nullptr;auto status=rocksdb::DB::OpenForReadOnly(op,path,&raw);
        if(!status.ok())throw std::runtime_error(status.ToString());
        std::unique_ptr<rocksdb::DB> db(raw);
        std::string schema,run;status=db->Get(rocksdb::ReadOptions(),"meta/schema",&schema);
        if(!status.ok() || schema!=kSchema)throw std::runtime_error("invalid evidence schema");
        status=db->Get(rocksdb::ReadOptions(),"meta/run_id",&run);if(!status.ok())throw std::runtime_error("missing run identity");
        std::ifstream oracle;if(!oracle_path.empty()){oracle.open(oracle_path);if(!oracle)throw std::runtime_error("cannot open oracle");}
        std::ofstream out;if(!output.empty()){out.open(output);if(!out)throw std::runtime_error("cannot open query output");}
        uint64_t count=0,emitted=0;std::array<uint64_t,3> types{};std::string chain(64,'0');
        std::unique_ptr<rocksdb::Iterator> it(db->NewIterator(rocksdb::ReadOptions()));
        for(it->Seek("evidence/");it->Valid() && it->key().starts_with("evidence/");it->Next()){
            const auto key=it->key().ToString(),value=it->value().ToString();
            if(value.size()<69)throw std::runtime_error("truncated evidence envelope");
            const auto body=value.substr(0,value.size()-64),hash=value.substr(value.size()-64);
            if(digest(body)!=hash)throw std::runtime_error("evidence digest mismatch");
            const Snapshot s=decode(body);const std::string fid=flow_id(s,run),type=component_name(s.component);
            const uint64_t sequence=s.sequence;
            if(key!=record_key(sequence) || sequence!=count+1)throw std::runtime_error("evidence sequence gap");
            std::string indexed;status=db->Get(rocksdb::ReadOptions(),std::string("flow/")+fid+"/"+type+"/"+key.substr(9),&indexed);
            if(!status.ok() || indexed!=key)throw std::runtime_error("query index mismatch");
            if(oracle.is_open()){std::string expected_key,expected_hash;if(!(oracle>>expected_key>>expected_hash) ||
                expected_key!=key || expected_hash!=hash)throw std::runtime_error("copied snapshot differs from owner oracle");}
            chain=digest(chain+key+hash);++count;++types[type=="STAT"?0:type=="SEQ"?1:2];
            if(out && (filter.empty() || filter==fid) && (!limit || emitted<limit)){
                auto *o=encode(s,run);out<<dump(o)<<'\n';json_decref(o);++emitted;}
        }
        if(!it->status().ok())throw std::runtime_error(it->status().ToString());
        if(oracle.is_open()){std::string extra;if(oracle>>extra)throw std::runtime_error("accepted evidence missing from database");}
        std::string water;status=db->Get(rocksdb::ReadOptions(),"meta/durable_sequence",&water);
        if(count ? (!status.ok() || std::stoull(water)!=count) : !status.IsNotFound())throw std::runtime_error("durable watermark mismatch");
        auto *receipt=json_object();put(receipt,"verified_records",count);put(receipt,"stat",types[0]);
        put(receipt,"seq",types[1]);put(receipt,"ja4",types[2]);put(receipt,"exported_records",emitted);
        flag(receipt,"oracle_matched",!oracle_path.empty());flag(receipt,"database_only_reader",true);
        str(receipt,"database",path);str(receipt,"content_sha256",chain);
        std::cout<<dump(receipt)<<'\n';json_decref(receipt);return 0;
    }catch(const std::exception &e){std::cerr<<"evidence verification: "<<e.what()<<'\n';return 1;}
}
}
