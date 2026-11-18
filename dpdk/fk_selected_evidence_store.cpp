#include "fk_selected_evidence_store.h"
#include <atomic>
#include "fk_prefix_version_store.h"
#include "fk_thread_phase_clock.h"
#include "fk_evidence_persistence_schedule.h"
#include <rocksdb/cache.h>
#include <rocksdb/db.h>
#include <rocksdb/table.h>
#include <rocksdb/write_batch.h>
#include <rocksdb/write_buffer_manager.h>
#include <openssl/sha.h>
#include <zstd.h>
#include <algorithm>
#include <array>
#include <chrono>
#include <cmath>
#include <condition_variable>
#include <cstring>
#include <cstdlib>
#include "fk_history_write_batch.h"
#include "fk_selected_bundle_codec.h"
#include <deque>
#include <filesystem>
#include <limits>
#include <map>
#include <mutex>
#include <set>
#include <sstream>
#include <stdexcept>
#include <thread>
#include <type_traits>
#include <pthread.h>
#include <sched.h>
#include <time.h>

namespace flowkeep {
namespace {
constexpr const char *kSchema="flowkeep-selected-final-evidence-v1";
constexpr const char *kMagic="FKSEF1";
constexpr const char *kPrefix="selected/";
constexpr size_t kEncodedBytes=6+FK_DETECTOR_REQUEST_RECORD_BYTES+3*sizeof(uint64_t)+sizeof(double)+2;
std::string unwrap_selected_value(const std::string &value) {
    if(value.compare(0,6,"FKZSE1")!=0)return value;
    if(value.size()<10)throw std::runtime_error("compressed selected header truncated");
    uint32_t size=0;for(unsigned i=0;i<4;++i)size|=uint32_t(uint8_t(value[6+i]))<<(8*i);
    if(size!=kEncodedBytes+64)throw std::runtime_error("compressed selected decoded size invalid");
    std::string raw(size,'\0');
    const size_t decoded=ZSTD_decompress(&raw[0],raw.size(),value.data()+10,value.size()-10);
    if(ZSTD_isError(decoded)||decoded!=size)throw std::runtime_error("compressed selected decode failed");
    return raw;
}

uint64_t monotonic_ns() {
    timespec ts{};
    if(clock_gettime(CLOCK_MONOTONIC,&ts))throw std::runtime_error("selected evidence monotonic clock failed");
    return uint64_t(ts.tv_sec)*1000000000ull+uint64_t(ts.tv_nsec);
}
std::string hex(const std::string &bytes) {
    static const char digits[]="0123456789abcdef";
    std::string result(bytes.size()*2,'0');
    for(size_t i=0;i<bytes.size();++i){const auto b=static_cast<unsigned char>(bytes[i]);result[2*i]=digits[b>>4];result[2*i+1]=digits[b&15];}
    return result;
}
std::string sha256(const std::string &bytes) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char*>(bytes.data()),bytes.size(),hash);
    return hex(std::string(reinterpret_cast<const char*>(hash),sizeof(hash)));
}
std::string quote(const std::string &value) {
    static const char digits[]="0123456789abcdef";
    std::string result="\"";
    for(unsigned char c:value){
        if(c=='"' || c=='\\'){result+='\\';result+=char(c);}
        else if(c<32){result+="\\u00";result+=digits[c>>4];result+=digits[c&15];}
        else result+=char(c);
    }
    return result+'"';
}
bool hash_valid(const std::string &hash) {
    return hash.size()==64 && std::all_of(hash.begin(),hash.end(),[](char c){return (c>='0'&&c<='9')||(c>='a'&&c<='f');});
}
struct Wire {
    std::string bytes;size_t position=0;bool reading=false;
    template<class T> void field(T &value) {
        static_assert(std::is_integral<T>::value && std::is_unsigned<T>::value,"unsigned portable field");
        if(reading){
            if(position>bytes.size() || bytes.size()-position<sizeof(T))throw std::runtime_error("truncated selected evidence");
            uint64_t n=0;for(size_t i=0;i<sizeof(T);++i)n|=uint64_t(static_cast<unsigned char>(bytes[position++]))<<(8*i);
            value=static_cast<T>(n);
        }else for(size_t i=0;i<sizeof(T);++i)bytes+=char((uint64_t(value)>>(8*i))&255);
    }
    template<class T,size_t N> void array(T (&values)[N]){for(auto &value:values)field(value);}
    void single(float &value){uint32_t bits=0;if(!reading)std::memcpy(&bits,&value,4);field(bits);if(reading)std::memcpy(&value,&bits,4);}
    void real(double &value){uint64_t bits=0;if(!reading)std::memcpy(&bits,&value,8);field(bits);if(reading)std::memcpy(&value,&bits,8);}
};
// The encoder owns exactly one final-sized output, writes each declared wire
// field once, and never copies the 840-byte record just to serialize it. The
// existing reader remains separate so its truncation/trailing-byte checks do
// not change. Little-endian machines may copy each scalar's representation;
// other machines retain explicit little-endian emission.
struct FixedWire {
    std::string bytes=std::string(kEncodedBytes,'\0');size_t position=6;
    FixedWire(){std::memcpy(bytes.data(),kMagic,6);}
    template<class T> void field(const T &value) {
        static_assert(std::is_integral<T>::value && std::is_unsigned<T>::value,"unsigned portable field");
        if(position>bytes.size() || bytes.size()-position<sizeof(T))
            throw std::logic_error("selected evidence explicit wire size overflow");
#if defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
        std::memcpy(bytes.data()+position,&value,sizeof(T));position+=sizeof(T);
#else
        for(size_t i=0;i<sizeof(T);++i)bytes[position++]=char((uint64_t(value)>>(8*i))&255);
#endif
    }
    template<class T,size_t N> void array(const T (&values)[N]){for(const auto &value:values)field(value);}
    void single(const float &value){uint32_t bits;std::memcpy(&bits,&value,sizeof(bits));field(bits);}
    void real(const double &value){uint64_t bits;std::memcpy(&bits,&value,sizeof(bits));field(bits);}
};
template<class W,class K> void key_wire(W &w,K &key) {
    w.field(key.ip_version);w.field(key.protocol);w.array(key.low_addr);w.array(key.high_addr);w.field(key.low_port);w.field(key.high_port);
}
template<class W,class R> void payload(W &w,R &record) {
    auto &r=record.request;
    w.field(r.magic);w.field(r.abi_version);w.field(r.header_bytes);w.field(r.record_bytes);w.field(r.feature_count);
    key_wire(w,r.canonical_key);w.field(r.reserved_key_alignment);
    w.field(r.flow_index);w.field(r.flow_generation);w.field(r.checkpoint_packet);w.field(r.source_mask);w.field(r.flags);w.array(r.reserved0);
    w.field(r.semantic_timestamp_ns);w.field(r.physical_timestamp_ns);w.field(r.event_routing_token);w.field(r.logical_connection_id);w.field(r.flow_first_timestamp_ns);
    w.field(r.predecessor_flow_index);w.field(r.predecessor_flow_generation);w.field(r.predecessor_checkpoint_packet);w.array(r.reserved_header);
    for(auto &value:r.features)w.single(value);
    w.array(r.reserved_tail);
    w.field(record.decision_sequence);w.field(record.event_token);w.field(record.evidence_timestamp_ns);
    w.real(record.score);w.field(record.threshold_met);w.field(record.alert_latched);
}
std::string encode_unchecked(const SelectedEvidenceRecord &record) {
    FixedWire w;payload(w,record);
    if(w.position!=kEncodedBytes)throw std::logic_error("selected evidence explicit wire size mismatch");
    return std::move(w.bytes);
}
// Every byte of these two C ABI objects is an explicitly encoded field. These
// assertions deliberately fail compilation if an ABI change introduces padding
// or a new field: only under this complete layout proof is request memcmp the
// same relation as comparing its field-wise wire encoding. No bytes outside
// request (in particular SelectedEvidenceRecord padding/hints) are compared.
static_assert(std::is_standard_layout<fk_flow_key>::value && sizeof(fk_flow_key)==38,"encoded key ABI");
#define FK_ENCODED_OFFSET(Type,Field,Offset,Bytes) \
    static_assert(offsetof(Type,Field)==Offset && sizeof(((Type*)nullptr)->Field)==Bytes,"encoded field ABI: " #Field)
FK_ENCODED_OFFSET(fk_flow_key,ip_version,0,1);
FK_ENCODED_OFFSET(fk_flow_key,protocol,1,1);
FK_ENCODED_OFFSET(fk_flow_key,low_addr,2,16);
FK_ENCODED_OFFSET(fk_flow_key,high_addr,18,16);
FK_ENCODED_OFFSET(fk_flow_key,low_port,34,2);
FK_ENCODED_OFFSET(fk_flow_key,high_port,36,2);
static_assert(std::is_standard_layout<fk_detector_request_v1>::value && sizeof(fk_detector_request_v1)==768,"encoded request ABI");
FK_ENCODED_OFFSET(fk_detector_request_v1,magic,0,8);
FK_ENCODED_OFFSET(fk_detector_request_v1,abi_version,8,2);
FK_ENCODED_OFFSET(fk_detector_request_v1,header_bytes,10,2);
FK_ENCODED_OFFSET(fk_detector_request_v1,record_bytes,12,2);
FK_ENCODED_OFFSET(fk_detector_request_v1,feature_count,14,2);
FK_ENCODED_OFFSET(fk_detector_request_v1,canonical_key,16,38);
FK_ENCODED_OFFSET(fk_detector_request_v1,reserved_key_alignment,54,2);
FK_ENCODED_OFFSET(fk_detector_request_v1,flow_index,56,4);
FK_ENCODED_OFFSET(fk_detector_request_v1,flow_generation,60,4);
FK_ENCODED_OFFSET(fk_detector_request_v1,checkpoint_packet,64,4);
FK_ENCODED_OFFSET(fk_detector_request_v1,source_mask,68,1);
FK_ENCODED_OFFSET(fk_detector_request_v1,flags,69,1);
FK_ENCODED_OFFSET(fk_detector_request_v1,reserved0,70,2);
FK_ENCODED_OFFSET(fk_detector_request_v1,semantic_timestamp_ns,72,8);
FK_ENCODED_OFFSET(fk_detector_request_v1,physical_timestamp_ns,80,8);
FK_ENCODED_OFFSET(fk_detector_request_v1,event_routing_token,88,8);
FK_ENCODED_OFFSET(fk_detector_request_v1,logical_connection_id,96,8);
FK_ENCODED_OFFSET(fk_detector_request_v1,flow_first_timestamp_ns,104,8);
FK_ENCODED_OFFSET(fk_detector_request_v1,predecessor_flow_index,112,4);
FK_ENCODED_OFFSET(fk_detector_request_v1,predecessor_flow_generation,116,4);
FK_ENCODED_OFFSET(fk_detector_request_v1,predecessor_checkpoint_packet,120,4);
FK_ENCODED_OFFSET(fk_detector_request_v1,reserved_header,124,4);
FK_ENCODED_OFFSET(fk_detector_request_v1,features,128,636);
FK_ENCODED_OFFSET(fk_detector_request_v1,reserved_tail,764,4);
#undef FK_ENCODED_OFFSET
void validate(const SelectedEvidenceRecord &record) {
    static_assert(sizeof(float)==4 && std::numeric_limits<float>::is_iec559,"IEEE binary32 required");
    static_assert(sizeof(double)==8 && std::numeric_limits<double>::is_iec559,"IEEE binary64 required");
    const auto &r=record.request;
    if(r.magic!=FK_DETECTOR_REQUEST_MAGIC || r.abi_version!=FK_DETECTOR_REQUEST_ABI_VERSION ||
       r.header_bytes!=FK_DETECTOR_REQUEST_HEADER_BYTES || r.record_bytes!=FK_DETECTOR_REQUEST_RECORD_BYTES ||
       r.feature_count!=FK_DETECTOR_REQUEST_FEATURE_COUNT || (r.canonical_key.ip_version!=4 && r.canonical_key.ip_version!=6) ||
       !r.flow_generation || !r.flow_first_timestamp_ns || r.semantic_timestamp_ns<r.flow_first_timestamp_ns ||
       !r.physical_timestamp_ns || !r.event_routing_token || r.checkpoint_packet<1 || r.checkpoint_packet>20 ||
       r.source_mask>FK_DETECTOR_REQUEST_SOURCE_MASK_ALL || (r.flags!=0 && r.flags!=FK_DETECTOR_REQUEST_FLAG_COVERAGE_TERMINAL) ||
       !record.decision_sequence || !record.event_token || record.evidence_timestamp_ns<r.flow_first_timestamp_ns ||
       record.evidence_timestamp_ns>r.semantic_timestamp_ns || !std::isfinite(record.score) || record.score<0 || record.score>1 ||
       record.threshold_met>1 || record.alert_latched>1)
        throw std::invalid_argument("invalid selected final scoring record");
    if(!FeatureValuesValid(r.features,FK_DETECTOR_REQUEST_FEATURE_COUNT))
        throw std::invalid_argument("nonfinite selected scoring feature");
    if(record.gain_known && (!std::isfinite(record.marginal_gain) || record.marginal_gain<0))
        throw std::invalid_argument("invalid known selected evidence gain");
    if(r.flags==FK_DETECTOR_REQUEST_FLAG_COVERAGE_TERMINAL && fk_detector_coverage_evidence_ns(&r)!=record.evidence_timestamp_ns)
        throw std::invalid_argument("selected EOF evidence timestamp differs");
    if(r.flags==0 && record.evidence_timestamp_ns!=r.semantic_timestamp_ns)
        throw std::invalid_argument("ordinary selected evidence timestamp differs");
}
// The ABI layout assertions above prove that every request byte is an explicit
// wire field. Other record fields are copied individually, never record padding.
// Keep Encode/Decode unchanged as independent field-wise verification paths.
void append_packed_row(std::string &raw,const SelectedEvidenceRecord &record,bool compact=false) {
    validate(record);
    const size_t begin=raw.size();raw.resize(begin+kEncodedBytes+(compact?0:64));
    char *const body=raw.data()+begin;
#if defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    char *dest=body;
    std::memcpy(dest,kMagic,6);dest+=6;
    std::memcpy(dest,&record.request,sizeof(record.request));dest+=sizeof(record.request);
    const auto field=[&](const auto &value){std::memcpy(dest,&value,sizeof(value));dest+=sizeof(value);};
    field(record.decision_sequence);field(record.event_token);field(record.evidence_timestamp_ns);
    field(record.score);field(record.threshold_met);field(record.alert_latched);
    if(size_t(dest-body)!=kEncodedBytes)throw std::logic_error("packed wire size differs");
#else
    const auto encoded=encode_unchecked(record);std::memcpy(body,encoded.data(),encoded.size());
#endif
    if(compact)return;
    unsigned char digest[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char*>(body),kEncodedBytes,digest);
    static constexpr char digits[]="0123456789abcdef";
    for(size_t i=0;i<sizeof(digest);++i) {
        body[kEncodedBytes+2*i]=digits[digest[i]>>4];
        body[kEncodedBytes+2*i+1]=digits[digest[i]&15];
    }
}
std::string fixed_identity_key(const SelectedEvidenceRecord &record) {
#if defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    unsigned char raw[sizeof(fk_flow_key)+2*sizeof(uint64_t)];
    std::memcpy(raw,&record.request.canonical_key,sizeof(fk_flow_key));
    std::memcpy(raw+sizeof(fk_flow_key),&record.request.flow_first_timestamp_ns,8);
    std::memcpy(raw+sizeof(fk_flow_key)+8,&record.request.logical_connection_id,8);
    static constexpr char digits[]="0123456789abcdef";
    std::string out(sizeof(raw)*2,'\0');
    for(size_t i=0;i<sizeof(raw);++i){out[2*i]=digits[raw[i]>>4];out[2*i+1]=digits[raw[i]&15];}
    return out;
#else
    return SelectedEvidenceStore::IdentityKey(record);
#endif
}
void require(const rocksdb::Status &status){if(!status.ok())throw std::runtime_error(status.ToString());}
std::string map_digest(const std::map<std::string,std::string> &records) {
    SHA256_CTX ctx;SHA256_Init(&ctx);
    for(const auto &entry:records){
        Wire lengths;uint64_t key_size=entry.first.size(),value_size=entry.second.size();lengths.field(key_size);lengths.field(value_size);
        SHA256_Update(&ctx,lengths.bytes.data(),lengths.bytes.size());
        SHA256_Update(&ctx,entry.first.data(),entry.first.size());SHA256_Update(&ctx,entry.second.data(),entry.second.size());
    }
    unsigned char hash[SHA256_DIGEST_LENGTH];SHA256_Final(hash,&ctx);
    return hex(std::string(reinterpret_cast<const char*>(hash),sizeof(hash)));
}
}

std::string SelectedEvidenceStore::Encode(const SelectedEvidenceRecord &record){
    validate(record);auto result=encode_unchecked(record);
    if(result.size()!=kEncodedBytes)throw std::logic_error("selected evidence explicit wire size mismatch");
    return result;
}
bool SelectedEvidenceStore::SameEncodedPayload(const SelectedEvidenceRecord &a,const SelectedEvidenceRecord &b) {
    validate(a);validate(b);
    return std::memcmp(&a.request,&b.request,sizeof(a.request))==0 &&
        a.decision_sequence==b.decision_sequence && a.event_token==b.event_token &&
        a.evidence_timestamp_ns==b.evidence_timestamp_ns &&
        std::memcmp(&a.score,&b.score,sizeof(a.score))==0 &&
        a.threshold_met==b.threshold_met && a.alert_latched==b.alert_latched;
}
SelectedEvidenceRecord SelectedEvidenceStore::Decode(const std::string &bytes) {
    if(bytes.size()<6 || bytes.compare(0,6,kMagic))throw std::runtime_error("selected evidence wire schema mismatch");
    Wire w;w.bytes=bytes;w.position=6;w.reading=true;SelectedEvidenceRecord record;payload(w,record);
    if(w.position!=bytes.size())throw std::runtime_error("selected evidence trailing bytes");
    validate(record);return record;
}
std::string SelectedEvidenceStore::IdentityKey(const SelectedEvidenceRecord &record) {
    Wire w;auto key=record.request.canonical_key;key_wire(w,key);
    auto first=record.request.flow_first_timestamp_ns,logical=record.request.logical_connection_id;
    w.field(first);w.field(logical);return hex(w.bytes);
}
std::string SelectedEvidenceStore::ContentKey(const SelectedEvidenceRecord &record) {
    validate(record);auto copy=record;copy.decision_sequence=0;copy.event_token=0;
    copy.request.physical_timestamp_ns=0;copy.request.event_routing_token=0;
    copy.request.flow_index=0;copy.request.flow_generation=0;
    copy.request.predecessor_flow_index=0;copy.request.predecessor_flow_generation=0;
    return encode_unchecked(copy);
}
std::string SelectedEvidenceStore::ContentDigest(const SelectedEvidenceRecord &record){return sha256(ContentKey(record));}
std::string SelectedEvidenceStore::ContentDigest(const std::vector<SelectedEvidenceRecord> &records) {
    std::map<std::string,std::string> ordered;
    for(const auto &record:records)if(!ordered.emplace(IdentityKey(record),ContentKey(record)).second)
        throw std::invalid_argument("duplicate semantic identity in selected evidence oracle");
    return map_digest(ordered);
}

struct SelectedEvidenceStore::Impl {
    Config config;
    mutable std::mutex mutex;std::mutex finish_mutex;
    std::condition_variable ready,space,encode_ready;
    std::thread writer;
    struct WriteTrace {
        uint64_t records=0,queued_before=0,outstanding_before=0,dequeued_ns=0,prepared_ns=0,retired_ns=0;
        ThreadPhaseTiming prepare{},sync{};
        uint64_t sync_group_id=0;
    };
    struct PreparedWrite {
        std::vector<size_t> indices;
        std::vector<const SelectedEvidenceRecord*> records;
        rocksdb::WriteBatch batch;
        WriteTrace trace;
    };
    std::deque<std::unique_ptr<PreparedWrite>> prepared_writes;
    std::vector<WriteTrace> write_trace;
    uint64_t write_trace_dropped=0,prepared_queue_peak=0;
    bool encoder_ready=false,encoder_done=false;
    bool merge_prepared=false,bundle_codec=false,packed_append=false,fixed_identity=false,compact_bundle=false;
    std::atomic<uint64_t> bundle_raw_bytes{0},row_checksum_bytes_omitted{0};
    std::atomic<uint64_t> packed_append_records{0},fixed_identity_keys{0};
    std::atomic<uint64_t> bundle_groups{0},bundle_records{0},bundle_reference_bytes{0},bundle_payload_bytes{0};
    uint64_t next_bundle_id=0; // Single encoder, fresh database; no reuse.

    std::atomic<uint64_t> merged_prepared_jobs{0},merged_prepared_records{0},merge_copy_bytes{0};

    int actual_encoder_cpu=-1;
    std::unique_ptr<rocksdb::DB> db;
    std::shared_ptr<rocksdb::Cache> cache;
    std::shared_ptr<rocksdb::WriteBufferManager> buffers;
    rocksdb::WriteOptions writes;
    std::deque<SelectedEvidenceRecord> baseline;
    std::vector<SelectedEvidenceRecord> slots;
    // Keys are immutable while a slot is queued/writing; the slot and its key
    // are reused only after the unchanged synchronous DB acknowledgement.
    std::vector<std::string> slot_identity_keys;
    std::vector<PrefixVersionStore::ReadHandle> slot_version_handles;
    uint64_t bound_version_submissions=0,bound_version_retirements=0;
    uint64_t batch_submit_calls=0,batch_submit_records=0,batch_submit_max_records=0,submit_notifications=0;
    std::vector<size_t> fifo,free_slots;
    std::vector<EvidencePersistenceCandidate> order_candidates;
    std::vector<size_t> order_indices;
    size_t effective_capacity=0,head=0,queued=0,writing=0,outstanding=0;
    bool stopping=false,failed=false,finished=false,verified=false,writer_ready=false,drain_complete=false;
    std::string error,manifest,target_digest,expected_target_digest,full_digest;
    uint64_t submitted=0,durable=0,readback=0,write_failed=0,duplicate_failures=0;
    std::shared_ptr<PrefixVersionStore> retire_versions;
    uint64_t retired_after_sync=0;
    uint64_t submission_claims=0,submission_claim_rejections=0;
    std::atomic<uint64_t> uniqueness_get_calls{0},guarded_records_prepared{0};
    std::atomic<uint64_t> raw_value_bytes{0},stored_value_bytes{0},compressed_values{0},codec_wall_ns{0};
    uint64_t batches=0,maximum_batch=0,blocked_calls=0,blocked_ns=0,blocked_max_ns=0,timeouts=0;
    uint64_t peak_records=0,peak_bytes=0,enqueue_copies=0,dequeue_copies=0;
    uint64_t competitions=0,reorders=0,known_gain_candidates=0,zero_gain_candidates=0,unknown_gain_candidates=0,deadline_candidates=0;
    uint64_t last_durable_completion_ns=0,finish_ns=0,write_ns=0,last_submit_ns=0;
    int actual_writer_cpu=-1;

    explicit Impl(const Config &c):config(c) {
        if(config.mode!="off" && config.mode!="baseline" && config.mode!="flowkeep")throw std::invalid_argument("invalid selected evidence mode");
        if(config.compress_values && config.mode!="flowkeep")
            throw std::invalid_argument("selected compression is FlowKeep-only experiment");
        if(config.wal_group_batches<1 || config.wal_group_batches>4 ||
           (config.mode!="flowkeep" && config.wal_group_batches!=1))
            throw std::invalid_argument("invalid selected WAL grouping");
        if(config.version_submission_guard && config.mode!="flowkeep")
            throw std::invalid_argument("submission guard requires FlowKeep's exact identity directory");
        if(config.prepare_pipeline && config.mode!="flowkeep")throw std::invalid_argument("prepared selected pipeline requires FlowKeep mode");
        if(const char *v=std::getenv("FK_MERGE_PREPARED_WRITES")) {
            if(std::strcmp(v,"0") && std::strcmp(v,"1"))
                throw std::invalid_argument("FK_MERGE_PREPARED_WRITES must be 0 or 1");
            merge_prepared=std::strcmp(v,"1")==0 && config.prepare_pipeline && config.mode=="flowkeep";
        }
        if(const char *v=std::getenv("FK_SELECTED_BUNDLE_CODEC")) {
            if(std::strcmp(v,"0") && std::strcmp(v,"1"))
                throw std::invalid_argument("FK_SELECTED_BUNDLE_CODEC must be 0 or 1");
            bundle_codec=std::strcmp(v,"1")==0 && config.prepare_pipeline &&
                config.compress_values && config.mode=="flowkeep";
        }
        const auto toggle=[](const char *name) {
            const char *v=std::getenv(name);if(!v)return false;
            if(std::strcmp(v,"0") && std::strcmp(v,"1"))throw std::invalid_argument(name);
            return std::strcmp(v,"1")==0;
        };
        packed_append=toggle("FK_SELECTED_PACKED_APPEND") && bundle_codec;
        fixed_identity=toggle("FK_SELECTED_FIXED_IDENTITY_KEY") && config.mode=="flowkeep";
        compact_bundle=toggle("FK_SELECTED_COMPACT_BUNDLE") && bundle_codec;
        write_trace.reserve(4096);
        if(config.mode=="off"){finished=true;drain_complete=true;return;}
        if(config.directory.empty() || !hash_valid(config.model_sha256) || !hash_valid(config.policy_sha256) || config.run_uuid.empty() ||
           config.run_uuid.size()>128 || config.run_uuid.find('\0')!=std::string::npos || !config.capacity_records ||
           config.capacity_bytes<RecordChargeBytes() || !config.batch_size || !config.full_wait_ms ||
           config.coalesce_us>20000 || config.writer_cpu>=CPU_SETSIZE)
            throw std::invalid_argument("invalid selected evidence storage configuration");
        effective_capacity=std::min(config.capacity_records,config.capacity_bytes/RecordChargeBytes());
        if(effective_capacity>1048576)throw std::invalid_argument("selected evidence capacity exceeds implementation limit");
        if(std::filesystem::exists(config.directory))throw std::invalid_argument("selected evidence directory must be fresh");
        const auto parent=std::filesystem::path(config.directory).parent_path();
        if(!parent.empty())std::filesystem::create_directories(parent);
        if(config.mode=="flowkeep"){
            slots.resize(effective_capacity);fifo.resize(effective_capacity);free_slots.reserve(effective_capacity);
            slot_identity_keys.resize(effective_capacity);slot_version_handles.resize(effective_capacity);order_candidates.reserve(effective_capacity);order_indices.reserve(effective_capacity);
            for(size_t i=effective_capacity;i-- >0;)free_slots.push_back(i);
        }
        rocksdb::Options options;options.create_if_missing=true;options.paranoid_checks=true;
        // Enforce freshness inside DB::Open, not merely with the earlier path
        // existence observation. RocksDB also holds the exclusive writer lock.
        options.error_if_exists=config.version_submission_guard;
        options.write_buffer_size=1u<<20;options.max_write_buffer_number=2;options.max_background_jobs=2;options.max_open_files=64;
        cache=rocksdb::NewLRUCache(2u<<20,0,true);buffers=std::make_shared<rocksdb::WriteBufferManager>(4u<<20);options.write_buffer_manager=buffers;
        rocksdb::BlockBasedTableOptions table;table.block_cache=cache;table.cache_index_and_filter_blocks=true;
        table.index_type=rocksdb::BlockBasedTableOptions::kTwoLevelIndexSearch;table.metadata_block_size=4096;table.pin_top_level_index_and_filter=false;
        options.table_factory.reset(rocksdb::NewBlockBasedTableFactory(table));
        rocksdb::DB *raw=nullptr;require(rocksdb::DB::Open(options,config.directory,&raw));db.reset(raw);
        writes.sync=true;writes.disableWAL=false;
        manifest=Manifest();rocksdb::WriteBatch metadata;metadata.Put("meta/manifest",manifest);metadata.Put("meta/durable_records","0");require(db->Write(writes,&metadata));
        writer=std::thread([this]{Run();});
        std::unique_lock<std::mutex> lock(mutex);ready.wait(lock,[this]{return writer_ready;});
        if(failed){lock.unlock();writer.join();throw std::runtime_error(error);}
    }
    ~Impl(){std::string ignored;Finish(&ignored);}
    std::string Manifest() const {
        std::ostringstream out;
        out<<"{\"schema\":"<<quote(kSchema)<<",\"mode\":"<<quote(config.mode)<<",\"model_sha256\":"<<quote(config.model_sha256)
           <<",\"policy_sha256\":"<<quote(config.policy_sha256)<<",\"run_uuid\":"<<quote(config.run_uuid)
           <<",\"feature_count\":159,\"wire_encoding\":\"explicit_little_endian_ieee754_v1\",\"target\":\"last_actual_scored_request_per_semantic_identity\""
           <<",\"capacity_records\":"<<config.capacity_records<<",\"capacity_bytes\":"<<config.capacity_bytes
           <<",\"record_charge_bytes\":"<<RecordChargeBytes()<<",\"effective_capacity_records\":"<<effective_capacity
           <<",\"capacity_scope\":\"logical_record_payload_queued_plus_writing_excludes_container_DB_and_oracle_memory\""
           <<",\"batch_size\":"<<config.batch_size<<",\"coalesce_us\":"<<config.coalesce_us<<",\"writer_cpu\":"<<config.writer_cpu
           <<",\"full_wait_ms\":"<<config.full_wait_ms<<",\"full_policy\":\"block_until_space_or_timeout_fail_closed\""
           <<",\"value_envelope\":"<<quote(compact_bundle?"FKREF1_atomic_FKZSB2_compact_groups_v1":bundle_codec?"FKREF1_atomic_FKZSB1_indexed_groups_v1":config.compress_values?"FKZSE1_le32_zstd_or_raw_v1":"raw_sha256_v1")
           <<",\"raw_value_bytes\":"<<raw_value_bytes.load()<<",\"stored_value_bytes\":"<<stored_value_bytes.load()
           <<",\"compressed_values\":"<<compressed_values.load()<<",\"codec_wall_ns\":"<<codec_wall_ns.load()
           <<",\"prepare_pipeline\":"<<(config.prepare_pipeline?"true":"false")
           <<",\"wal_group_batches\":"<<config.wal_group_batches
           <<",\"version_submission_guard\":"<<(config.version_submission_guard?"true":"false")
           <<",\"error_if_database_exists\":"<<(config.version_submission_guard?"true":"false")
           <<",\"wal_enabled\":true,\"sync_each_batch\":true,\"use_fsync\":false"
           <<",\"test_hooks_enabled\":"<<(config.before_write_for_test?"true":"false")<<"}";
        return out.str();
    }
    bool FailLocked(const std::string &message,std::string *out=nullptr) {
        if(!failed)error=message;
        failed=true;stopping=true;verified=false;ready.notify_all();space.notify_all();encode_ready.notify_all();
        if(out)*out=error;
        return false;
    }
    bool ResultLocked(std::string *out) const {if(failed && out)*out=error;return !failed;}
    bool Submit(const SelectedEvidenceRecord &record,std::string *out,const PrefixVersionStore::ReadHandle *bound=nullptr) {
        std::string identity;
        try{validate(record);if(config.mode=="flowkeep"){
            identity=fixed_identity?fixed_identity_key(record):IdentityKey(record);
            if(fixed_identity)++fixed_identity_keys;
        }}
        catch(const std::exception &e){std::lock_guard<std::mutex> lock(mutex);return FailLocked(e.what(),out);}
        std::unique_lock<std::mutex> lock(mutex);
        if(config.mode=="off")return FailLocked("selected evidence Submit called in off mode",out);
        if(failed)return ResultLocked(out);
        if(stopping || finished)return FailLocked("selected evidence Submit after Finish",out);
        if(outstanding>=effective_capacity){
            ++blocked_calls;const uint64_t start=monotonic_ns();
            const auto deadline=std::chrono::steady_clock::now()+std::chrono::milliseconds(config.full_wait_ms);
            const bool woke=space.wait_until(lock,deadline,[this]{return failed || stopping || outstanding<effective_capacity;});
            const uint64_t elapsed=monotonic_ns()-start;blocked_ns+=elapsed;blocked_max_ns=std::max(blocked_max_ns,elapsed);
            if(!woke){++timeouts;return FailLocked("selected evidence bounded queue timeout",out);}
            if(failed)return ResultLocked(out);
            if(stopping)return FailLocked("selected evidence closed during Submit",out);
        }
        if(bound && (config.mode!="flowkeep" || !retire_versions ||
             !retire_versions->Matches(*bound,{record.request.canonical_key,record.request.flow_first_timestamp_ns,record.request.logical_connection_id})))
            return FailLocked("selected evidence mismatched lifecycle binding",out);
        if(config.version_submission_guard) {
            const auto &r=record.request;
            if(!retire_versions || !(bound?retire_versions->ClaimFinalEvidenceSubmission(
                    {r.canonical_key,r.flow_first_timestamp_ns,r.logical_connection_id},*bound):
                    retire_versions->ClaimFinalEvidenceSubmission({r.canonical_key,r.flow_first_timestamp_ns,r.logical_connection_id}))) {
                ++submission_claim_rejections;
                return FailLocked("selected evidence sealed submission claim rejected",out);
            }
            ++submission_claims;
        }
        try{
            if(config.mode=="baseline")baseline.push_back(record);
            else {const size_t index=free_slots.back();free_slots.pop_back();slots[index]=record;
                slot_identity_keys[index]=std::move(identity);slot_version_handles[index]=bound?*bound:PrefixVersionStore::ReadHandle{};
                if(bound){++bound_version_submissions;}fifo[(head+queued)%effective_capacity]=index;}
            ++queued;++outstanding;++submitted;++enqueue_copies;
            last_submit_ns=monotonic_ns();peak_records=std::max<uint64_t>(peak_records,outstanding);
            peak_bytes=std::max<uint64_t>(peak_bytes,outstanding*RecordChargeBytes());++submit_notifications;if(config.prepare_pipeline)encode_ready.notify_one();else ready.notify_one();return true;
        }catch(const std::exception &e){return FailLocked(e.what(),out);}
    }
    bool SubmitBatch(const SelectedEvidenceRecord *const *records,size_t count,
                     const PrefixVersionStore::ReadHandle *bindings,std::string *out) {
        if(!records || !count || count>16 || count>effective_capacity) {
            std::lock_guard<std::mutex> lock(mutex);
            return FailLocked("selected evidence batch exceeds bounded admission",out);
        }
        std::array<std::string,16> identities;
        try {
            for(size_t i=0;i<count;++i) {
                if(!records[i])throw std::invalid_argument("null selected batch record");
                validate(*records[i]);identities[i]=fixed_identity?
                    fixed_identity_key(*records[i]):IdentityKey(*records[i]);
                if(fixed_identity)++fixed_identity_keys;
            }
        }catch(const std::exception &e){std::lock_guard<std::mutex> lock(mutex);return FailLocked(e.what(),out);}
        std::unique_lock<std::mutex> lock(mutex);
        if(config.mode!="flowkeep")return FailLocked("selected batch requires FlowKeep slots",out);
        if(failed)return ResultLocked(out);
        if(stopping || finished)return FailLocked("selected batch after Finish",out);
        if(effective_capacity-outstanding<count) {
            ++blocked_calls;const uint64_t start=monotonic_ns();
            const auto deadline=std::chrono::steady_clock::now()+std::chrono::milliseconds(config.full_wait_ms);
            const bool woke=space.wait_until(lock,deadline,[&]{return failed || stopping || effective_capacity-outstanding>=count;});
            const auto elapsed=monotonic_ns()-start;blocked_ns+=elapsed;blocked_max_ns=std::max(blocked_max_ns,elapsed);
            if(!woke){++timeouts;return FailLocked("selected evidence bounded batch timeout",out);}
            if(failed)return ResultLocked(out);
            if(stopping)return FailLocked("selected evidence closed during batch",out);
        }
        // Reject every bad binding before consuming any seal. On a later
        // claim failure the entire run fails closed; no slot is published.
        for(size_t i=0;i<count;++i)if(bindings && (!retire_versions ||
            !retire_versions->Matches(bindings[i],{records[i]->request.canonical_key,
                records[i]->request.flow_first_timestamp_ns,records[i]->request.logical_connection_id})))
            return FailLocked("selected evidence mismatched batch lifecycle binding",out);
        if(config.version_submission_guard)for(size_t i=0;i<count;++i) {
            const auto &r=records[i]->request;
            const PrefixVersionStore::Identity id{r.canonical_key,r.flow_first_timestamp_ns,r.logical_connection_id};
            if(!retire_versions || !(bindings?retire_versions->ClaimFinalEvidenceSubmission(id,bindings[i]):
                    retire_versions->ClaimFinalEvidenceSubmission(id))) {
                ++submission_claim_rejections;return FailLocked("selected evidence batch seal claim rejected",out);
            }
            ++submission_claims;
        }
        // Slots and queued counts become visible together on mutex release.
        // The existing writer remains the only sync/retirement authority.
        for(size_t i=0;i<count;++i) {
            const size_t index=free_slots.back();free_slots.pop_back();
            slots[index]=*records[i];slot_identity_keys[index]=std::move(identities[i]);
            slot_version_handles[index]=bindings?bindings[i]:PrefixVersionStore::ReadHandle{};
            if(bindings)++bound_version_submissions;
            fifo[(head+queued)%effective_capacity]=index;
            ++queued;++outstanding;++submitted;++enqueue_copies;
        }
        ++batch_submit_calls;batch_submit_records+=count;batch_submit_max_records=std::max<uint64_t>(batch_submit_max_records,count);
        last_submit_ns=monotonic_ns();peak_records=std::max<uint64_t>(peak_records,outstanding);
        peak_bytes=std::max<uint64_t>(peak_bytes,outstanding*RecordChargeBytes());++submit_notifications;
        if(config.prepare_pipeline)encode_ready.notify_one();else ready.notify_one();
        return true;
    }
    void OrderLocked() {
        if(config.mode!="flowkeep" || queued<=config.batch_size)return;
        ++competitions;order_candidates.resize(queued);order_indices.resize(queued);uint64_t watermark=0;
        for(size_t i=0;i<queued;++i){
            const size_t index=fifo[(head+i)%effective_capacity];order_indices[i]=index;const auto &r=slots[index];
            auto &c=order_candidates[i];c.chain=slot_identity_keys[index];c.recoverability_deadline_ns=r.recoverability_deadline_ns;
            // The shared codec is fixed-size. Do not serialize 159 features
            // again merely to determine a candidate's exact logical charge.
            c.estimated_write_bytes=kEncodedBytes+64+c.chain.size()+std::strlen(kPrefix);
            c.gain_known=r.gain_known;c.marginal_gain=r.marginal_gain;
            if(c.gain_known){++known_gain_candidates;if(c.marginal_gain==0)++zero_gain_candidates;}else ++unknown_gain_candidates;
            if(c.recoverability_deadline_ns)++deadline_candidates;
            watermark=std::max(watermark,r.semantic_watermark_ns);
        }
        const auto order=EvidencePersistenceOrder(order_candidates,config.batch_size,watermark,true);
        for(size_t i=0;i<order.size();++i){if(order[i]!=i)++reorders;fifo[(head+i)%effective_capacity]=order_indices[order[i]];}
    }
    void PinSelectedThread() {
        cpu_set_t wanted;CPU_ZERO(&wanted);CPU_SET(config.writer_cpu,&wanted);
        if(pthread_setaffinity_np(pthread_self(),sizeof(wanted),&wanted))throw std::runtime_error("selected pipeline affinity failed");
        cpu_set_t observed;CPU_ZERO(&observed);
        if(pthread_getaffinity_np(pthread_self(),sizeof(observed),&observed) || !CPU_EQUAL(&wanted,&observed))
            throw std::runtime_error("selected pipeline affinity mismatch");
    }
    void PrepareSelectedLoop() noexcept {
        try {
            PinSelectedThread();
            {std::lock_guard<std::mutex> lock(mutex);actual_encoder_cpu=sched_getcpu();encoder_ready=true;ready.notify_all();}
            const size_t maximum=std::min(config.batch_size*config.wal_group_batches,effective_capacity);
            const size_t target=std::min(config.batch_size,effective_capacity);
            std::unique_ptr<ZSTD_CCtx,decltype(&ZSTD_freeCCtx)> codec(config.compress_values?ZSTD_createCCtx():nullptr,ZSTD_freeCCtx);
            if(config.compress_values&&!codec)throw std::runtime_error("selected pipeline codec allocation");
            std::string compressed(ZSTD_compressBound(kEncodedBytes+64)+10,'\0');
            for(;;) {
                auto job=std::make_unique<PreparedWrite>();
                {
                    std::unique_lock<std::mutex> lock(mutex);
                    encode_ready.wait(lock,[&]{return failed || (queued && prepared_writes.size()<2) || (stopping && !queued);});
                    if(failed || (stopping && !queued))break;
                    if(!stopping && queued<target && outstanding<effective_capacity && config.coalesce_us)
                        encode_ready.wait_for(lock,std::chrono::microseconds(config.coalesce_us),[&]{return failed || stopping || queued>=target || outstanding>=effective_capacity;});
                    if(failed)break;
                    OrderLocked();const size_t count=std::min(maximum,queued);
                    job->trace.records=count;job->trace.queued_before=queued;job->trace.outstanding_before=outstanding;job->trace.dequeued_ns=monotonic_ns();
                    job->indices.reserve(count);job->records.reserve(count);
                    for(size_t i=0;i<count;++i){const size_t index=fifo[head];head=(head+1)%effective_capacity;job->indices.push_back(index);job->records.push_back(&slots[index]);}
                    queued-=count;writing+=count;
                }
                const auto stamp=ReadThreadPhaseStamp();
                if(bundle_codec) {
                    for(size_t first=0;first<job->records.size();first+=SelectedBundleCodec::max_rows) {
                        const size_t count=std::min(SelectedBundleCodec::max_rows,job->records.size()-first);
                        if(next_bundle_id==UINT64_MAX)throw std::runtime_error("selected bundle ID overflow");
                        const uint64_t id=++next_bundle_id;
                        std::string raw;raw.reserve(count*(compact_bundle?SelectedBundleCodec::compact_row_bytes:SelectedBundleCodec::row_bytes));
                        for(size_t j=0;j<count;++j) {
                            const size_t i=first+j;
                            if(packed_append)append_packed_row(raw,*job->records[i],compact_bundle);
                            else {const auto body=Encode(*job->records[i]);raw+=body;if(!compact_bundle)raw+=sha256(body);}
                            const auto key=std::string(kPrefix)+slot_identity_keys[job->indices[i]];
                            const auto ref=SelectedBundleCodec::Reference(id,uint32_t(j));
                            require(job->batch.Put(key,ref));
                            bundle_reference_bytes+=ref.size();stored_value_bytes+=ref.size();
                        }
                        const uint64_t started=monotonic_ns();
                        if(packed_append)packed_append_records+=count;
                        const auto encoded=SelectedBundleCodec::Encode(codec.get(),raw,count,compact_bundle);
                        codec_wall_ns+=monotonic_ns()-started;
                        require(job->batch.Put(SelectedBundleCodec::Key(id),encoded));
                        // Keep the logical legacy export size comparable.
                        raw_value_bytes+=count*SelectedBundleCodec::row_bytes;
                        bundle_raw_bytes+=raw.size();
                        if(compact_bundle)row_checksum_bytes_omitted+=count*64;
                        stored_value_bytes+=encoded.size();
                        bundle_payload_bytes+=encoded.size();++bundle_groups;bundle_records+=count;compressed_values+=count;
                    }
                } else for(size_t i=0;i<job->records.size();++i) {
                    const auto *record=job->records[i];const auto key=std::string(kPrefix)+slot_identity_keys[job->indices[i]];
                    const auto body=Encode(*record);const auto raw=body+sha256(body);raw_value_bytes.fetch_add(raw.size(),std::memory_order_relaxed);
                    if(codec) {
                        const uint64_t started=monotonic_ns();
                        const size_t count=ZSTD_compressCCtx(codec.get(),&compressed[10],compressed.size()-10,raw.data(),raw.size(),1);
                        if(ZSTD_isError(count))throw std::runtime_error("selected pipeline compression failed");
                        codec_wall_ns.fetch_add(monotonic_ns()-started,std::memory_order_relaxed);
                        if(count+10<raw.size()) {
                            std::memcpy(&compressed[0],"FKZSE1",6);for(unsigned n=0;n<4;++n)compressed[6+n]=char((raw.size()>>(8*n))&255);
                            job->batch.Put(key,rocksdb::Slice(compressed.data(),count+10));stored_value_bytes.fetch_add(count+10,std::memory_order_relaxed);++compressed_values;
                        }else {job->batch.Put(key,raw);stored_value_bytes.fetch_add(raw.size(),std::memory_order_relaxed);}
                    }else {job->batch.Put(key,raw);stored_value_bytes.fetch_add(raw.size(),std::memory_order_relaxed);}
                }
                job->trace.prepare=ThreadPhaseBetween(stamp,ReadThreadPhaseStamp());job->trace.prepared_ns=monotonic_ns();
                {std::lock_guard<std::mutex> lock(mutex);prepared_writes.push_back(std::move(job));prepared_queue_peak=std::max<uint64_t>(prepared_queue_peak,prepared_writes.size());}
                ready.notify_all();
            }
        }catch(const std::exception&e){std::lock_guard<std::mutex> lock(mutex);++write_failed;encoder_ready=true;FailLocked(e.what());}
         catch(...){std::lock_guard<std::mutex> lock(mutex);++write_failed;encoder_ready=true;FailLocked("selected prepare stage failure");}
        {std::lock_guard<std::mutex> lock(mutex);encoder_done=true;}ready.notify_all();space.notify_all();
    }
    void RunPipelined() noexcept {
        std::thread encoder;
        try {
            PinSelectedThread();actual_writer_cpu=sched_getcpu();encoder=std::thread([this]{PrepareSelectedLoop();});
            {std::unique_lock<std::mutex> lock(mutex);ready.wait(lock,[&]{return encoder_ready || failed;});writer_ready=true;ready.notify_all();}
            for(;;) {
                std::unique_ptr<PreparedWrite> job;
                std::unique_ptr<PreparedWrite> extra;
                WriteTrace extra_trace{};bool have_extra=false;
                {
                    std::unique_lock<std::mutex> lock(mutex);ready.wait(lock,[&]{return failed || !prepared_writes.empty() || encoder_done;});
                    if(failed || (encoder_done && prepared_writes.empty()))break;
                    job=std::move(prepared_writes.front());prepared_writes.pop_front();
                    const size_t maximum=std::min(config.batch_size*config.wal_group_batches,effective_capacity);
                    // No extra wait: merge only a job already prepared, and
                    // retain the previous per-write and outstanding limits.
                    if(merge_prepared && !prepared_writes.empty() &&
                       job->records.size()+prepared_writes.front()->records.size()<=maximum) {
                        extra=std::move(prepared_writes.front());prepared_writes.pop_front();
                    }
                    encode_ready.notify_one();
                }
                if(extra) {
                    // Public RocksDB API; never concatenate private batch wire
                    // formats. The producer emits only default-CF evidence Put.
                    uint64_t append_rows=0,append_bytes=0;
                    require(AppendSelectedWriteBatch(extra->batch,job->batch,kPrefix,append_rows,append_bytes));
                    if(append_rows!=extra->records.size())throw std::runtime_error("prepared batch merge count mismatch");
                    job->indices.insert(job->indices.end(),extra->indices.begin(),extra->indices.end());
                    job->records.insert(job->records.end(),extra->records.begin(),extra->records.end());
                    extra_trace=extra->trace;have_extra=true;
                    ++merged_prepared_jobs;merged_prepared_records+=extra->records.size();merge_copy_bytes+=append_bytes;
                    extra.reset();
                }
                if(config.before_write_for_test && !config.before_write_for_test(job->records.data(),job->records.size()))
                    throw std::runtime_error("injected selected pipeline writer failure");
                // Only the publication thread touches DB uniqueness state and
                // durable-record metadata. It observes all prior sync writes.
                std::set<std::string> batch_keys;
                for(size_t i=0;i<job->records.size();++i) {
                    const auto key=std::string(kPrefix)+slot_identity_keys[job->indices[i]];
                    if(config.version_submission_guard)++guarded_records_prepared;
                    else {
                        ++uniqueness_get_calls;std::string prior;const auto status=db->Get(rocksdb::ReadOptions(),key,&prior);
                        if(!status.IsNotFound()) {
                            if(status.ok()){std::lock_guard<std::mutex> lock(mutex);++duplicate_failures;throw std::runtime_error("duplicate final selected semantic identity");}
                            require(status);
                        }
                        if(!batch_keys.insert(key).second){std::lock_guard<std::mutex> lock(mutex);++duplicate_failures;throw std::runtime_error("duplicate final selected semantic identity in batch");}
                    }
                }
                uint64_t next_durable=0;
                {std::lock_guard<std::mutex> lock(mutex);next_durable=durable+job->records.size();}
                job->batch.Put("meta/durable_records",std::to_string(next_durable));
                const auto stamp=ReadThreadPhaseStamp();const uint64_t started=monotonic_ns();require(db->Write(writes,&job->batch));const uint64_t ended=monotonic_ns();
                job->trace.sync=ThreadPhaseBetween(stamp,ReadThreadPhaseStamp());
                // Slots, immutable snapshots and selected keys remain owned
                // throughout both stages. Sync success is the sole release gate.
                if(retire_versions)for(size_t i=0;i<job->records.size();++i){const auto&r=job->records[i]->request;
                    const auto &binding=slot_version_handles[job->indices[i]];
                    const PrefixVersionStore::Identity id{r.canonical_key,r.flow_first_timestamp_ns,r.logical_connection_id};
                    if(!(binding.Bound()?retire_versions->RetireFinalized(id,binding):retire_versions->RetireFinalized(id)))
                        throw std::runtime_error("selected pipeline durable retirement failed");
                    if(binding.Bound())++bound_version_retirements;
                }
                {
                    std::lock_guard<std::mutex> lock(mutex);durable=next_durable;++batches;
                    if(retire_versions)retired_after_sync+=job->records.size();
                    maximum_batch=std::max<uint64_t>(maximum_batch,job->records.size());write_ns+=ended-started;last_durable_completion_ns=ended;
                    outstanding-=job->records.size();writing-=job->records.size();for(size_t index:job->indices)free_slots.push_back(index);
                    job->trace.retired_ns=monotonic_ns();job->trace.sync_group_id=batches;
                    if(write_trace.size()<4096)write_trace.push_back(job->trace);else ++write_trace_dropped;
                    if(have_extra) {
                        // Keep each encoder interval intact. Shared sync
                        // intervals must be unioned, never added twice.
                        extra_trace.sync=job->trace.sync;extra_trace.retired_ns=job->trace.retired_ns;
                        extra_trace.sync_group_id=batches;
                        if(write_trace.size()<4096)write_trace.push_back(extra_trace);else ++write_trace_dropped;
                    }
                }
                space.notify_all();ready.notify_all();
            }
        }catch(const std::exception&e){std::lock_guard<std::mutex> lock(mutex);++write_failed;writer_ready=true;FailLocked(e.what());}
         catch(...){std::lock_guard<std::mutex> lock(mutex);++write_failed;writer_ready=true;FailLocked("selected publication stage failure");}
        if(encoder.joinable()){encoder.join();}
        ready.notify_all();space.notify_all();
    }

    void Run() noexcept {
        if(config.prepare_pipeline){RunPipelined();return;}
        try{
            cpu_set_t selected;CPU_ZERO(&selected);CPU_SET(config.writer_cpu,&selected);
            if(pthread_setaffinity_np(pthread_self(),sizeof(selected),&selected))throw std::runtime_error("selected evidence writer affinity failed");
            cpu_set_t observed;CPU_ZERO(&observed);
            if(pthread_getaffinity_np(pthread_self(),sizeof(observed),&observed) ||
               !CPU_EQUAL(&selected,&observed))throw std::runtime_error("selected evidence writer affinity mismatch");
            {std::lock_guard<std::mutex> lock(mutex);actual_writer_cpu=sched_getcpu();writer_ready=true;ready.notify_all();}
            const size_t maximum=std::min(config.batch_size*config.wal_group_batches,effective_capacity);
            const size_t coalesce_target=std::min(config.batch_size,effective_capacity);
            std::vector<SelectedEvidenceRecord> copied;if(config.mode=="baseline")copied.reserve(maximum);
            std::vector<size_t> indices;indices.reserve(maximum);
            std::vector<const SelectedEvidenceRecord*> records;records.reserve(maximum);
            std::unique_ptr<ZSTD_CCtx,decltype(&ZSTD_freeCCtx)> codec(
                config.compress_values?ZSTD_createCCtx():nullptr,ZSTD_freeCCtx);
            if(config.compress_values&&!codec)throw std::runtime_error("selected codec allocation");
            std::string compressed(ZSTD_compressBound(kEncodedBytes+64)+10,'\0');
            for(;;){
                WriteTrace trace;
                {
                    std::unique_lock<std::mutex> lock(mutex);ready.wait(lock,[this]{return failed || stopping || queued;});
                    if(failed || (stopping && !queued))break;
                    if(!stopping && queued<coalesce_target && outstanding<effective_capacity && config.coalesce_us)
                        ready.wait_for(lock,std::chrono::microseconds(config.coalesce_us),[this,coalesce_target]{return failed || stopping || queued>=coalesce_target || outstanding>=effective_capacity;});
                    if(failed)break;
                    OrderLocked();records.clear();indices.clear();copied.clear();
                    const size_t count=std::min(maximum,queued);
                    trace.records=count;trace.queued_before=queued;trace.outstanding_before=outstanding;trace.dequeued_ns=monotonic_ns();
                    for(size_t i=0;i<count;++i){
                        if(config.mode=="baseline"){
                            copied.push_back(baseline.front());baseline.pop_front();records.push_back(&copied.back());++dequeue_copies;
                        }else{
                            const size_t index=fifo[head];head=(head+1)%effective_capacity;indices.push_back(index);records.push_back(&slots[index]);
                        }
                    }
                    queued-=count;writing=count;
                }
                const auto prepare_stamp=ReadThreadPhaseStamp();
                if(config.before_write_for_test && !config.before_write_for_test(records.data(),records.size()))
                    throw std::runtime_error("injected selected evidence writer failure");
                rocksdb::WriteBatch batch;std::set<std::string> batch_keys;
                for(size_t i=0;i<records.size();++i){
                    const auto *record=records[i];
                    const auto key=std::string(kPrefix)+(config.mode=="flowkeep"?slot_identity_keys[indices[i]]:IdentityKey(*record));std::string prior;
                    if(config.version_submission_guard) {
                        // Fresh DB + sole writer + injective exact identity key
                        // + a single consumed directory claim prove uniqueness.
                        // Payload encoding/validation and sync WAL are unchanged.
                        guarded_records_prepared.fetch_add(1u,std::memory_order_relaxed);
                    } else {
                        uniqueness_get_calls.fetch_add(1u,std::memory_order_relaxed);
                        const auto status=db->Get(rocksdb::ReadOptions(),key,&prior);
                        if(!status.IsNotFound()){if(status.ok()){std::lock_guard<std::mutex> lock(mutex);++duplicate_failures;throw std::runtime_error("duplicate final selected semantic identity");}require(status);}
                        if(!batch_keys.insert(key).second){std::lock_guard<std::mutex> lock(mutex);++duplicate_failures;throw std::runtime_error("duplicate final selected semantic identity in batch");}
                    }
                    const auto body=Encode(*record);const auto raw=body+sha256(body);
                    raw_value_bytes.fetch_add(raw.size(),std::memory_order_relaxed);
                    if(codec) {
                        const uint64_t codec_begin=monotonic_ns();
                        const size_t count=ZSTD_compressCCtx(codec.get(),&compressed[10],compressed.size()-10,
                            raw.data(),raw.size(),1);
                        if(ZSTD_isError(count))throw std::runtime_error("selected compression failed");
                        codec_wall_ns.fetch_add(monotonic_ns()-codec_begin,std::memory_order_relaxed);
                        if(count+10<raw.size()) {
                            std::memcpy(&compressed[0],"FKZSE1",6);
                            for(unsigned n=0;n<4;++n)compressed[6+n]=char((raw.size()>>(8*n))&255);
                            batch.Put(key,rocksdb::Slice(compressed.data(),count+10));
                            stored_value_bytes.fetch_add(count+10,std::memory_order_relaxed);++compressed_values;
                        }else {batch.Put(key,raw);stored_value_bytes.fetch_add(raw.size(),std::memory_order_relaxed);}
                    }else {batch.Put(key,raw);stored_value_bytes.fetch_add(raw.size(),std::memory_order_relaxed);}
                }
                trace.prepare=ThreadPhaseBetween(prepare_stamp,ReadThreadPhaseStamp());trace.prepared_ns=monotonic_ns();
                batch.Put("meta/durable_records",std::to_string(durable+records.size()));
                const auto sync_stamp=ReadThreadPhaseStamp();
                const uint64_t start=monotonic_ns();require(db->Write(writes,&batch));const uint64_t end=monotonic_ns();
                trace.sync=ThreadPhaseBetween(sync_stamp,ReadThreadPhaseStamp());
                if(retire_versions)for(size_t i=0;i<records.size();++i) {
                    const auto &r=records[i]->request;
                    const auto binding=config.mode=="flowkeep"?slot_version_handles[indices[i]]:PrefixVersionStore::ReadHandle{};
                    const PrefixVersionStore::Identity id{r.canonical_key,r.flow_first_timestamp_ns,r.logical_connection_id};
                    if(!(binding.Bound()?retire_versions->RetireFinalized(id,binding):retire_versions->RetireFinalized(id)))
                        throw std::runtime_error("selected durable evidence retirement failed");
                    if(binding.Bound())++bound_version_retirements;
                }
                {
                    std::lock_guard<std::mutex> lock(mutex);durable+=records.size();++batches;
                    trace.retired_ns=monotonic_ns();if(write_trace.size()<4096)write_trace.push_back(trace);else ++write_trace_dropped;
                    if(retire_versions)retired_after_sync+=records.size();
                    maximum_batch=std::max<uint64_t>(maximum_batch,records.size());write_ns+=end-start;last_durable_completion_ns=end;
                    outstanding-=records.size();writing=0;
                    if(config.mode=="flowkeep")for(size_t index:indices)free_slots.push_back(index);
                    space.notify_all();
                }
            }
        }catch(const std::exception &e){std::lock_guard<std::mutex> lock(mutex);++write_failed;writer_ready=true;FailLocked(e.what());}
        catch(...){std::lock_guard<std::mutex> lock(mutex);++write_failed;writer_ready=true;FailLocked("unknown selected evidence writer failure");}
        ready.notify_all();space.notify_all();
    }
    bool Finish(std::string *out) {
        std::lock_guard<std::mutex> lifecycle(finish_mutex);
        {std::lock_guard<std::mutex> lock(mutex);if(drain_complete)return ResultLocked(out);stopping=true;ready.notify_all();space.notify_all();encode_ready.notify_all();}
        if(writer.joinable())writer.join();
        db.reset();
        std::lock_guard<std::mutex> lock(mutex);finish_ns=monotonic_ns();drain_complete=true;
        if(outstanding || submitted!=durable)FailLocked("selected evidence incomplete drain");
        finished=!failed;return ResultLocked(out);
    }
    bool Verify(const std::vector<SelectedEvidenceRecord> &expected,std::string *out) {
        std::lock_guard<std::mutex> lifecycle(finish_mutex);
        {std::lock_guard<std::mutex> lock(mutex);
            if(failed)return ResultLocked(out);
            if(!finished)return FailLocked("selected evidence verification requires Finish",out);
            if(config.mode=="off"){if(!expected.empty())return FailLocked("off mode has selected evidence oracle",out);verified=true;return true;}
        }
        try{
            std::map<std::string,std::string> full_expected,normalized;
            for(const auto &record:expected){
                const auto key=IdentityKey(record);
                if(!full_expected.emplace(key,Encode(record)).second)throw std::runtime_error("duplicate semantic identity in selected evidence oracle");
                normalized.emplace(key,ContentKey(record));
            }
            rocksdb::Options options;options.paranoid_checks=true;rocksdb::DB *raw=nullptr;
            require(rocksdb::DB::OpenForReadOnly(options,config.directory,&raw));std::unique_ptr<rocksdb::DB> read_only(raw);
            std::string binding;require(read_only->Get(rocksdb::ReadOptions(),"meta/manifest",&binding));
            if(binding!=manifest)throw std::runtime_error("selected evidence manifest binding mismatch");
            std::string count;require(read_only->Get(rocksdb::ReadOptions(),"meta/durable_records",&count));
            if(count!=std::to_string(submitted))throw std::runtime_error("selected evidence durable count mismatch");
            std::map<std::string,std::string> full_actual,content;
            SelectedBundleReader bundle_reader;
            std::unique_ptr<rocksdb::Iterator> it(read_only->NewIterator(rocksdb::ReadOptions()));
            for(it->Seek(kPrefix);it->Valid() && it->key().starts_with(kPrefix);it->Next()){
                const std::string key=it->key().ToString().substr(std::strlen(kPrefix)),value=unwrap_selected_value(bundle_reader.Resolve(*read_only,it->value().ToString()));
                if(value.size()<64)throw std::runtime_error("selected evidence truncated digest envelope");
                const auto body=value.substr(0,value.size()-64);
                if(sha256(body)!=value.substr(value.size()-64))throw std::runtime_error("selected evidence payload checksum mismatch");
                const auto record=Decode(body);
                if(IdentityKey(record)!=key)throw std::runtime_error("selected evidence semantic key mismatch");
                const auto found=full_expected.find(key);
                if(found==full_expected.end() || found->second!=body)throw std::runtime_error("selected evidence differs from independent scoring request oracle");
                full_actual.emplace(key,body);content.emplace(key,ContentKey(record));
            }
            require(it->status());
            if(full_actual.size()!=expected.size() || full_actual.size()!=submitted)throw std::runtime_error("selected evidence missing or extra semantic identities");
            const auto actual_digest=map_digest(content),expected_digest=map_digest(normalized);
            if(actual_digest!=expected_digest)throw std::runtime_error("selected evidence target content digest mismatch");
            std::lock_guard<std::mutex> lock(mutex);readback=full_actual.size();target_digest=actual_digest;expected_target_digest=expected_digest;full_digest=map_digest(full_actual);verified=true;return true;
        }catch(const std::exception &e){std::lock_guard<std::mutex> lock(mutex);return FailLocked(e.what(),out);}
    }
    std::string Receipt() const {
        std::lock_guard<std::mutex> lock(mutex);std::ostringstream out;
        out<<"{\"schema\":"<<quote(kSchema)<<",\"mode\":"<<quote(config.mode)<<",\"enabled\":"<<(config.mode=="off"?"false":"true")<<",\"directory\":"<<quote(config.directory)
           <<",\"manifest\":"<<(manifest.empty()?"null":manifest)<<",\"finished\":"<<(finished&&!failed?"true":"false")
           <<",\"failed\":"<<(failed?"true":"false")<<",\"readback_verified\":"<<(verified?"true":"false")
           <<",\"passed\":"<<(finished&&!failed&&verified?"true":"false")<<",\"error\":"<<quote(error)
           <<",\"submitted_records\":"<<submitted<<",\"durable_records\":"<<durable<<",\"readback_records\":"<<readback
           <<",\"version_retirement_enabled\":"<<(retire_versions?"true":"false")
           <<",\"versions_retired_after_sync_records\":"<<retired_after_sync
           <<",\"bound_version_submissions\":"<<bound_version_submissions<<",\"bound_version_retirements\":"<<bound_version_retirements
           <<",\"slot_version_handle_bytes\":"<<slot_version_handles.capacity()*sizeof(PrefixVersionStore::ReadHandle)
           <<",\"value_envelope\":"<<quote(compact_bundle?"FKREF1_atomic_FKZSB2_compact_groups_v1":bundle_codec?"FKREF1_atomic_FKZSB1_indexed_groups_v1":config.compress_values?"FKZSE1_le32_zstd_or_raw_v1":"raw_sha256_v1")
           <<",\"raw_value_bytes\":"<<raw_value_bytes.load()<<",\"stored_value_bytes\":"<<stored_value_bytes.load()
           <<",\"compressed_values\":"<<compressed_values.load()<<",\"codec_wall_ns\":"<<codec_wall_ns.load()
           <<",\"prepare_pipeline\":"<<(config.prepare_pipeline?"true":"false")
           <<",\"wal_group_batches\":"<<config.wal_group_batches
           <<",\"version_submission_guard\":"<<(config.version_submission_guard?"true":"false")
           <<",\"version_submission_claims\":"<<submission_claims
           <<",\"version_submission_claim_rejections\":"<<submission_claim_rejections
           <<",\"uniqueness_get_calls\":"<<uniqueness_get_calls.load(std::memory_order_relaxed)
           <<",\"guarded_records_prepared\":"<<guarded_records_prepared.load(std::memory_order_relaxed)
           <<",\"outstanding_records\":"<<outstanding<<",\"queued_records\":"<<queued<<",\"writing_records\":"<<writing
           <<",\"write_failed\":"<<write_failed<<",\"duplicate_identity_failures\":"<<duplicate_failures<<",\"dropped\":0"
           <<",\"peak_outstanding_records\":"<<peak_records<<",\"peak_outstanding_bytes\":"<<peak_bytes
           <<",\"capacity_records\":"<<config.capacity_records<<",\"capacity_bytes\":"<<config.capacity_bytes
           <<",\"effective_capacity_records\":"<<effective_capacity<<",\"record_charge_bytes\":"<<RecordChargeBytes()
           <<",\"batch_size\":"<<config.batch_size<<",\"coalesce_us\":"<<config.coalesce_us<<",\"writer_cpu\":"<<config.writer_cpu
           <<",\"actual_writer_cpu\":"<<actual_writer_cpu<<",\"full_wait_ms\":"<<config.full_wait_ms
           <<",\"wal_enabled\":"<<(config.mode=="off"?"false":"true")<<",\"sync_each_batch\":"<<(config.mode=="off"?"false":"true")
           <<",\"write_batches\":"<<batches<<",\"maximum_write_batch_records\":"<<maximum_batch<<",\"sync_write_ns\":"<<write_ns
           <<",\"blocked_calls\":"<<blocked_calls<<",\"blocked_ns\":"<<blocked_ns<<",\"blocked_max_ns\":"<<blocked_max_ns
           <<",\"queue_timeouts\":"<<timeouts<<",\"enqueue_record_copies\":"<<enqueue_copies<<",\"dequeue_record_copies\":"<<dequeue_copies
           <<",\"utility_competitions\":"<<competitions<<",\"utility_reorders\":"<<reorders
           <<",\"known_gain_candidates\":"<<known_gain_candidates<<",\"zero_gain_candidates\":"<<zero_gain_candidates<<",\"unknown_gain_candidates\":"<<unknown_gain_candidates
           <<",\"known_deadline_candidates\":"<<deadline_candidates
           <<",\"last_submit_monotonic_ns\":"<<last_submit_ns<<",\"last_durable_completion_ns\":"<<last_durable_completion_ns
           <<",\"finish_monotonic_ns\":"<<finish_ns<<",\"drain_complete_monotonic_ns\":"<<finish_ns<<",\"completion_clock\":\"CLOCK_MONOTONIC\",\"clock\":\"CLOCK_MONOTONIC\""
           <<",\"target_content_sha256\":"<<quote(target_digest)<<",\"readback_content_sha256\":"<<quote(target_digest)
           <<",\"expected_target_content_sha256\":"<<quote(expected_target_digest)<<",\"full_wire_content_sha256\":"<<quote(full_digest)
           <<",\"target_digest_scope\":\"sorted_semantic_identity_normalized_scoring_payload_excludes_run_sequence_routing_physical_time_and_slot_incarnation\""
           <<",\"independent_full_request_oracle_verified\":"<<(verified?"true":"false")
           <<",\"test_hooks_enabled\":"<<(config.before_write_for_test?"true":"false");
        out<<",\"compact_bundle_enabled\":"<<(compact_bundle?"true":"false")
           <<",\"bundle_raw_bytes\":"<<bundle_raw_bytes.load()<<",\"row_checksum_bytes_omitted\":"<<row_checksum_bytes_omitted.load()
           <<",\"bundle_codec_enabled\":"<<(bundle_codec?"true":"false")
           <<",\"bulk_feature_validation_enabled\":"<<(FeatureValidationMode()==1?"true":"false")
           <<",\"packed_append_enabled\":"<<(packed_append?"true":"false")
           <<",\"packed_append_records\":"<<packed_append_records
           <<",\"fixed_identity_enabled\":"<<(fixed_identity?"true":"false")
           <<",\"fixed_identity_keys\":"<<fixed_identity_keys
           <<",\"bundle_groups\":"<<bundle_groups<<",\"bundle_records\":"<<bundle_records
           <<",\"bundle_reference_bytes\":"<<bundle_reference_bytes<<",\"bundle_payload_bytes\":"<<bundle_payload_bytes
           <<",\"bundle_max_rows\":"<<SelectedBundleCodec::max_rows;
        out<<",\"merge_prepared_enabled\":"<<(merge_prepared?"true":"false")
           <<",\"merged_prepared_jobs\":"<<merged_prepared_jobs
           <<",\"merged_prepared_records\":"<<merged_prepared_records
           <<",\"merge_copy_bytes\":"<<merge_copy_bytes;
        out<<",\"batch_submit_calls\":"<<batch_submit_calls
           <<",\"batch_submit_records\":"<<batch_submit_records
           <<",\"batch_submit_max_records\":"<<batch_submit_max_records
           <<",\"submit_notifications\":"<<submit_notifications;
        out<<",\"actual_encoder_cpu\":"<<actual_encoder_cpu<<",\"prepared_queue_peak\":"<<prepared_queue_peak;
        out<<",\"write_trace\":{\"scope\":\"CLOCK_MONOTONIC intervals, per-stage thread CPU; overlapping stages must not be summed as end-to-end time\",\"dropped\":"<<write_trace_dropped<<",\"batches\":[";
        for(size_t i=0;i<write_trace.size();++i){if(i)out<<',';const auto&t=write_trace[i];
            out<<"{\"records\":"<<t.records<<",\"queued_before\":"<<t.queued_before<<",\"outstanding_before\":"<<t.outstanding_before
               <<",\"dequeued_ns\":"<<t.dequeued_ns<<",\"prepared_ns\":"<<t.prepared_ns<<",\"retired_ns\":"<<t.retired_ns
               <<",\"prepare_started_ns\":"<<t.prepare.started_ns<<",\"prepare_finished_ns\":"<<t.prepare.finished_ns<<",\"prepare_cpu_ns\":"<<t.prepare.cpu_ns<<",\"prepare_off_cpu_ns\":"<<t.prepare.off_cpu_ns
               <<",\"sync_group_id\":"<<t.sync_group_id<<",\"sync_started_ns\":"<<t.sync.started_ns<<",\"sync_finished_ns\":"<<t.sync.finished_ns<<",\"sync_cpu_ns\":"<<t.sync.cpu_ns<<",\"sync_off_cpu_ns\":"<<t.sync.off_cpu_ns<<"}";
        }
        out<<"]}}";
        return out.str();
    }
};

SelectedEvidenceStore::SelectedEvidenceStore(const Config &config):impl_(new Impl(config)){}
SelectedEvidenceStore::~SelectedEvidenceStore()=default;
uint32_t SelectedEvidenceStore::WriterCpu() const noexcept{return impl_->config.writer_cpu;}
uint32_t SelectedEvidenceStore::FullWaitMs() const noexcept{return impl_->config.full_wait_ms;}
size_t SelectedEvidenceStore::CapacityRecords() const noexcept{return impl_->effective_capacity;}
bool SelectedEvidenceStore::AdmissionReady() const {
    std::lock_guard<std::mutex> lock(impl_->mutex);
    return impl_->failed || impl_->stopping || impl_->finished ||
        impl_->outstanding < impl_->effective_capacity;
}
size_t SelectedEvidenceStore::AdmissionAvailable(size_t maximum) const {
    std::lock_guard<std::mutex> lock(impl_->mutex);
    if(!maximum)return 0;
    if(impl_->failed || impl_->stopping || impl_->finished)return 1;
    return std::min(maximum,impl_->effective_capacity-impl_->outstanding);
}
bool SelectedEvidenceStore::SubmitBatch(const SelectedEvidenceRecord *const *rows,size_t count,
        const PrefixVersionStore::ReadHandle *bindings,std::string *error) {
    return impl_->SubmitBatch(rows,count,bindings,error);
}
bool SelectedEvidenceStore::Submit(const SelectedEvidenceRecord &record,std::string *error){return impl_->Submit(record,error);}
bool SelectedEvidenceStore::SubmitBound(const SelectedEvidenceRecord &record,const PrefixVersionStore::ReadHandle &binding,std::string *error){return impl_->Submit(record,error,&binding);}
bool SelectedEvidenceStore::SupportsBoundSubmission() const{return impl_->config.mode=="flowkeep";}
bool SelectedEvidenceStore::BindVersionRetirement(std::shared_ptr<PrefixVersionStore> versions,std::string *error){
    std::lock_guard<std::mutex> lock(impl_->mutex);
    if(!versions || !versions->RecyclingEnabled() || impl_->submitted || impl_->stopping ||
            impl_->failed || impl_->retire_versions || impl_->config.mode=="off")
        return impl_->FailLocked("invalid selected version-retirement binding",error);
    impl_->retire_versions=std::move(versions);return true;
}
bool SelectedEvidenceStore::Finish(std::string *error){return impl_->Finish(error);}
bool SelectedEvidenceStore::Verify(const std::vector<SelectedEvidenceRecord> &expected,std::string *error){return impl_->Verify(expected,error);}
std::string SelectedEvidenceStore::ReceiptJson() const{return impl_->Receipt();}
}
