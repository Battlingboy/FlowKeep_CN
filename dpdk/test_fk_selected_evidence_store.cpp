#include "fk_selected_evidence_store.h"
#include <rocksdb/db.h>
#include <jansson.h>
#include <atomic>
#include <chrono>
#include <cmath>
#include <condition_variable>
#include <cstring>
#include <filesystem>
#include <future>
#include <iostream>
#include <limits>
#include <memory>
#include <mutex>
#include <stdexcept>
#include <thread>
#include <vector>
#include <sched.h>
#include <unistd.h>

using flowkeep::SelectedEvidenceRecord;
using flowkeep::SelectedEvidenceStore;
using flowkeep::SelectedEvidenceStoreConfig;
#define CHECK(value) do{if(!(value))throw std::runtime_error(std::string("line ")+std::to_string(__LINE__)+": " #value);}while(false)

struct Temporary {
    std::filesystem::path path;
    Temporary(){char name[]="/tmp/fk_selected_evidence_fixture_XXXXXX";const char *p=mkdtemp(name);if(!p)throw std::runtime_error("mkdtemp");path=p;}
    ~Temporary(){std::error_code ignored;std::filesystem::remove_all(path,ignored);}
};
using Json=std::unique_ptr<json_t,decltype(&json_decref)>;
Json receipt(const SelectedEvidenceStore &store){json_error_t error{};Json result(json_loads(store.ReceiptJson().c_str(),0,&error),json_decref);CHECK(result);return result;}
uint64_t number(const SelectedEvidenceStore &store,const char *key){auto json=receipt(store);auto *field=json_object_get(json.get(),key);CHECK(json_is_integer(field));return uint64_t(json_integer_value(field));}
bool boolean(const SelectedEvidenceStore &store,const char *key){auto json=receipt(store);auto *field=json_object_get(json.get(),key);CHECK(json_is_boolean(field));return json_is_true(field);}
std::string string(const SelectedEvidenceStore &store,const char *key){auto json=receipt(store);const char *value=json_string_value(json_object_get(json.get(),key));CHECK(value);return value;}

SelectedEvidenceRecord record(uint64_t identity,uint32_t packet=8) {
    SelectedEvidenceRecord value;auto &r=value.request;
    r.magic=FK_DETECTOR_REQUEST_MAGIC;r.abi_version=FK_DETECTOR_REQUEST_ABI_VERSION;
    r.header_bytes=FK_DETECTOR_REQUEST_HEADER_BYTES;r.record_bytes=FK_DETECTOR_REQUEST_RECORD_BYTES;r.feature_count=FK_DETECTOR_REQUEST_FEATURE_COUNT;
    r.canonical_key.ip_version=4;r.canonical_key.protocol=6;r.canonical_key.low_addr[0]=10;r.canonical_key.high_addr[0]=20;
    r.canonical_key.low_port=1234;r.canonical_key.high_port=443;
    r.flow_index=uint32_t(identity);r.flow_generation=1;r.checkpoint_packet=packet;r.source_mask=7;
    r.flow_first_timestamp_ns=1000000+identity;r.logical_connection_id=identity;
    r.semantic_timestamp_ns=r.flow_first_timestamp_ns+packet;r.physical_timestamp_ns=9000000+identity;r.event_routing_token=identity;
    for(size_t i=0;i<FK_DETECTOR_REQUEST_FEATURE_COUNT;++i)r.features[i]=float(i)/7+float(identity);
    r.features[0]=-0.0f;r.features[1]=std::numeric_limits<float>::denorm_min();r.features[158]=std::numeric_limits<float>::max();
    value.decision_sequence=identity;value.event_token=identity;value.evidence_timestamp_ns=r.semantic_timestamp_ns;
    value.score=.75;value.threshold_met=1;value.alert_latched=1;return value;
}
SelectedEvidenceStoreConfig config(const Temporary &tmp,const std::string &name,const std::string &mode) {
    SelectedEvidenceStoreConfig c;c.mode=mode;c.directory=(tmp.path/name).string();c.model_sha256=std::string(64,'a');c.policy_sha256=std::string(64,'b');c.run_uuid="local-fixture";
    c.capacity_records=8;c.capacity_bytes=8*SelectedEvidenceStore::RecordChargeBytes();c.batch_size=4;c.coalesce_us=1000;c.full_wait_ms=500;
    cpu_set_t allowed;CPU_ZERO(&allowed);CHECK(sched_getaffinity(0,sizeof(allowed),&allowed)==0);
    for(unsigned i=0;i<CPU_SETSIZE;++i)if(CPU_ISSET(i,&allowed)){c.writer_cpu=i;return c;}
    throw std::runtime_error("no allowed CPU");
}
struct Gate {
    std::mutex mutex;std::condition_variable condition;bool entered=false,open=false;
    std::vector<uint64_t> order;
    bool Before(const SelectedEvidenceRecord *const *rows,size_t count){
        std::unique_lock<std::mutex> lock(mutex);entered=true;condition.notify_all();condition.wait(lock,[this]{return open;});
        for(size_t i=0;i<count;++i)order.push_back(rows[i]->request.logical_connection_id);
        return true;
    }
    void Wait(){std::unique_lock<std::mutex> lock(mutex);CHECK(condition.wait_for(lock,std::chrono::seconds(3),[this]{return entered;}));}
    void Open(){std::lock_guard<std::mutex> lock(mutex);open=true;condition.notify_all();}
};
struct OpenOnExit {Gate &gate;~OpenOnExit(){gate.Open();}};

void codec_and_normalization() {
    const auto original=record(1);const auto encoded=SelectedEvidenceStore::Encode(original);
    const auto decoded=SelectedEvidenceStore::Decode(encoded);
    CHECK(SelectedEvidenceStore::Encode(decoded)==encoded);
    CHECK(std::memcmp(original.request.features,decoded.request.features,sizeof(original.request.features))==0);
    CHECK(std::signbit(decoded.request.features[0]));
    SelectedEvidenceRecord partial;partial.request.canonical_key=original.request.canonical_key;
    partial.request.flow_first_timestamp_ns=original.request.flow_first_timestamp_ns;partial.request.logical_connection_id=original.request.logical_connection_id;
    CHECK(SelectedEvidenceStore::IdentityKey(partial)==SelectedEvidenceStore::IdentityKey(original));
    auto changed=original;changed.decision_sequence=999;changed.event_token=888;changed.request.event_routing_token=777;
    changed.request.physical_timestamp_ns+=123;changed.request.flow_index+=11;changed.request.flow_generation+=22;
    changed.recoverability_deadline_ns=123;changed.semantic_watermark_ns=999;changed.gain_known=true;changed.marginal_gain=9;
    CHECK(SelectedEvidenceStore::Encode(changed)!=encoded);
    CHECK(SelectedEvidenceStore::ContentDigest(changed)==SelectedEvidenceStore::ContentDigest(original));
    changed.request.features[80]+=1;CHECK(SelectedEvidenceStore::ContentDigest(changed)!=SelectedEvidenceStore::ContentDigest(original));
    auto terminal=original;terminal.request.flags=FK_DETECTOR_REQUEST_FLAG_COVERAGE_TERMINAL;terminal.request.semantic_timestamp_ns+=100;
    fk_detector_coverage_set_evidence_ns(&terminal.request,terminal.evidence_timestamp_ns);
    CHECK(SelectedEvidenceStore::Encode(SelectedEvidenceStore::Decode(SelectedEvidenceStore::Encode(terminal)))==SelectedEvidenceStore::Encode(terminal));
    for(const auto &broken:{encoded.substr(0,encoded.size()-1),encoded+"extra",std::string("wrong")} ){
        bool threw=false;try{SelectedEvidenceStore::Decode(broken);}catch(const std::exception&){threw=true;}CHECK(threw);
    }
}

void basic_equivalence_and_immutable_copy() {
    Temporary tmp;std::vector<SelectedEvidenceRecord> oracle;for(uint64_t i=1;i<=7;++i)oracle.push_back(record(i));
    std::string baseline_digest;
    for(const std::string mode:{"baseline","flowkeep"}){
        auto c=config(tmp,mode,mode);SelectedEvidenceStore store(c);std::string error;
        for(const auto &saved:oracle){auto reused=saved;CHECK(store.Submit(reused,&error));reused.request.features[22]=-99;reused.request.flow_generation=900;}
        CHECK(store.Finish(&error));const auto finish=number(store,"finish_monotonic_ns");CHECK(store.Finish(&error));CHECK(number(store,"finish_monotonic_ns")==finish);
        CHECK(store.Verify(oracle,&error));CHECK(boolean(store,"passed"));CHECK(number(store,"submitted_records")==7);CHECK(number(store,"durable_records")==7);CHECK(number(store,"readback_records")==7);
        CHECK(number(store,"outstanding_records")==0);CHECK(number(store,"write_failed")==0);CHECK(number(store,"dropped")==0);
        CHECK(number(store,"last_durable_completion_ns")>0);CHECK(number(store,"last_durable_completion_ns")<=number(store,"drain_complete_monotonic_ns"));
        CHECK(number(store,"peak_outstanding_bytes")<=c.capacity_bytes);CHECK(number(store,"maximum_write_batch_records")>1);
        CHECK(number(store,"actual_writer_cpu")==c.writer_cpu);
        CHECK(number(store,"dequeue_record_copies")== (mode=="baseline"?7:0));
        CHECK(string(store,"target_content_sha256")==SelectedEvidenceStore::ContentDigest(oracle));
        if(mode=="baseline")baseline_digest=string(store,"target_content_sha256");else CHECK(string(store,"target_content_sha256")==baseline_digest);
    }
}

void writing_charge_and_backpressure() {
    Temporary tmp;
    for(const std::string mode:{"baseline","flowkeep"}){
        Gate gate;auto c=config(tmp,mode,mode);c.capacity_records=8;c.capacity_bytes=2*SelectedEvidenceStore::RecordChargeBytes();c.batch_size=1;c.coalesce_us=0;
        c.before_write_for_test=[&](const SelectedEvidenceRecord *const *r,size_t n){return gate.Before(r,n);};
        SelectedEvidenceStore store(c);OpenOnExit guard{gate};std::string error;
        CHECK(store.Submit(record(1),&error));gate.Wait();CHECK(number(store,"writing_records")==1);
        CHECK(store.Submit(record(2),&error));CHECK(number(store,"outstanding_records")==2);
        auto third=std::async(std::launch::async,[&]{std::string e;return store.Submit(record(3),&e);});
        CHECK(third.wait_for(std::chrono::milliseconds(20))==std::future_status::timeout);
        gate.Open();CHECK(third.get());CHECK(store.Finish(&error));CHECK(store.Verify({record(1),record(2),record(3)},&error));
        CHECK(number(store,"effective_capacity_records")==2);CHECK(number(store,"peak_outstanding_records")==2);
        CHECK(number(store,"blocked_calls")==1);CHECK(number(store,"blocked_ns")>0);
    }
}

void timeout_sticky_and_no_drop() {
    Temporary tmp;
    for(const std::string mode:{"baseline","flowkeep"}){
        Gate gate;auto c=config(tmp,mode,mode);c.capacity_records=1;c.capacity_bytes=SelectedEvidenceStore::RecordChargeBytes();c.batch_size=1;c.coalesce_us=0;c.full_wait_ms=20;
        c.before_write_for_test=[&](const SelectedEvidenceRecord *const *r,size_t n){return gate.Before(r,n);};
        SelectedEvidenceStore store(c);OpenOnExit guard{gate};std::string error;
        CHECK(store.Submit(record(1),&error));gate.Wait();CHECK(!store.Submit(record(2),&error));CHECK(error.find("timeout")!=std::string::npos);
        CHECK(!store.Submit(record(3),&error));gate.Open();CHECK(!store.Finish(&error));const auto previous=store.ReceiptJson();CHECK(!store.Finish(&error));CHECK(store.ReceiptJson()==previous);
        CHECK(number(store,"queue_timeouts")==1);CHECK(number(store,"submitted_records")==1);CHECK(number(store,"dropped")==0);CHECK(boolean(store,"failed"));CHECK(!boolean(store,"finished"));
    }
}

void writer_failure_sticky() {
    Temporary tmp;
    for(const std::string mode:{"baseline","flowkeep"}){
        auto c=config(tmp,mode,mode);c.before_write_for_test=[](const SelectedEvidenceRecord *const *,size_t){return false;};
        SelectedEvidenceStore store(c);std::string error;CHECK(store.Submit(record(1),&error));CHECK(!store.Finish(&error));const auto prior=store.ReceiptJson();CHECK(!store.Finish(&error));CHECK(store.ReceiptJson()==prior);
        CHECK(!store.Submit(record(2),&error));CHECK(number(store,"write_failed")==1);CHECK(number(store,"outstanding_records")==1);CHECK(number(store,"dropped")==0);
        CHECK(!store.Verify({record(1)},&error));
    }
}

void correct_scheduler_only_changes_order() {
    Temporary tmp;std::string target;
    std::vector<SelectedEvidenceRecord> oracle;for(uint64_t i=1;i<=5;++i)oracle.push_back(record(i));
    oracle[1].gain_known=true;oracle[1].marginal_gain=0;
    oracle[2].gain_known=true;oracle[2].marginal_gain=9;oracle[2].recoverability_deadline_ns=5;oracle[2].semantic_watermark_ns=10;
    oracle[3].gain_known=true;oracle[3].marginal_gain=1;
    for(const std::string mode:{"baseline","flowkeep"}){
        Gate gate;auto c=config(tmp,mode,mode);c.capacity_records=5;c.capacity_bytes=5*SelectedEvidenceStore::RecordChargeBytes();c.batch_size=2;c.coalesce_us=0;
        c.before_write_for_test=[&](const SelectedEvidenceRecord *const *r,size_t n){return gate.Before(r,n);};
        SelectedEvidenceStore store(c);OpenOnExit guard{gate};std::string error;
        CHECK(store.Submit(oracle[0],&error));gate.Wait();for(size_t i=1;i<oracle.size();++i)CHECK(store.Submit(oracle[i],&error));
        gate.Open();CHECK(store.Finish(&error));CHECK(store.Verify(oracle,&error));
        if(mode=="baseline"){
            CHECK(gate.order==std::vector<uint64_t>({1,2,3,4,5}));CHECK(number(store,"utility_competitions")==0);target=string(store,"target_content_sha256");
        }else{
            // The scheduler ranks only the contended next batch; once two
            // records remain they fit one batch and retain their FIFO order.
            CHECK(gate.order==std::vector<uint64_t>({1,3,5,2,4}));CHECK(number(store,"utility_competitions")>0);CHECK(number(store,"utility_reorders")>0);
            CHECK(number(store,"unknown_gain_candidates")>0);CHECK(number(store,"zero_gain_candidates")>0);CHECK(number(store,"known_deadline_candidates")>0);
            CHECK(string(store,"target_content_sha256")==target);
        }
    }
}

void duplicate_identity_fails_not_overwrites() {
    Temporary tmp;
    for(const std::string mode:{"baseline","flowkeep"}){
        auto c=config(tmp,mode,mode);SelectedEvidenceStore store(c);std::string error;auto second=record(1,12);second.decision_sequence=2;
        CHECK(store.Submit(record(1),&error));(void)store.Submit(second,&error);CHECK(!store.Finish(&error));CHECK(number(store,"duplicate_identity_failures")==1);CHECK(boolean(store,"failed"));
    }
}

void independent_oracle_rejects_wrong_request() {
    Temporary tmp;
    for(const std::string mode:{"baseline","flowkeep"}){
        auto c=config(tmp,mode,mode);SelectedEvidenceStore store(c);std::string error;CHECK(store.Submit(record(1),&error));CHECK(store.Finish(&error));
        auto wrong=record(1);++wrong.request.flow_index;
        CHECK(SelectedEvidenceStore::ContentDigest(wrong)==SelectedEvidenceStore::ContentDigest(record(1)));
        CHECK(!store.Verify({wrong},&error));CHECK(error.find("oracle")!=std::string::npos);CHECK(!boolean(store,"readback_verified"));CHECK(!store.Finish(&error));
    }
}

void corrupted_database_rejected() {
    Temporary tmp;auto c=config(tmp,"corrupt","flowkeep");SelectedEvidenceStore store(c);std::string error;
    CHECK(store.Submit(record(1),&error));CHECK(store.Finish(&error));
    rocksdb::Options options;rocksdb::DB *raw=nullptr;CHECK(rocksdb::DB::Open(options,c.directory,&raw).ok());
    {std::unique_ptr<rocksdb::DB> db(raw);rocksdb::WriteOptions writes;writes.sync=true;
        CHECK(db->Put(writes,"selected/"+SelectedEvidenceStore::IdentityKey(record(1)),"damaged").ok());}
    CHECK(!store.Verify({record(1)},&error));CHECK(boolean(store,"failed"));
}

void empty_off_and_invalid_configuration() {
    Temporary tmp;std::string error;
    for(const std::string mode:{"baseline","flowkeep"}){
        auto c=config(tmp,mode,mode);SelectedEvidenceStore store(c);CHECK(store.Finish(&error));CHECK(store.Verify({},&error));
        CHECK(number(store,"last_durable_completion_ns")==0);CHECK(number(store,"write_batches")==0);CHECK(boolean(store,"passed"));
        bool rejected=false;try{SelectedEvidenceStore duplicate(c);}catch(const std::exception&){rejected=true;}CHECK(rejected);
    }
    SelectedEvidenceStoreConfig off;off.mode="off";off.directory=(tmp.path/"off").string();SelectedEvidenceStore disabled(off);
    CHECK(disabled.Finish(&error));CHECK(disabled.Verify({},&error));CHECK(!std::filesystem::exists(off.directory));
    auto bad=config(tmp,"invalid","flowkeep");bad.writer_cpu=CPU_SETSIZE;bool rejected=false;
    try{SelectedEvidenceStore invalid(bad);}catch(const std::exception&){rejected=true;}CHECK(rejected);CHECK(!std::filesystem::exists(bad.directory));
    bad=config(tmp,"bad-bytes","baseline");bad.capacity_bytes=1;rejected=false;
    try{SelectedEvidenceStore invalid(bad);}catch(const std::exception&){rejected=true;}CHECK(rejected);
}

void concurrent_submitters_are_bounded() {
    Temporary tmp;
    for(const std::string mode:{"baseline","flowkeep"}){
        auto c=config(tmp,mode,mode);c.full_wait_ms=3000;c.coalesce_us=0;SelectedEvidenceStore store(c);
        std::atomic<bool> ok{true};std::vector<std::thread> producers;
        for(uint64_t worker=0;worker<4;++worker)producers.emplace_back([&,worker]{for(uint64_t i=1;i<=12;++i){std::string e;if(!store.Submit(record(worker*12+i),&e))ok=false;}});
        for(auto &thread:producers)thread.join();CHECK(ok.load());std::string error;CHECK(store.Finish(&error));
        std::vector<SelectedEvidenceRecord> oracle;for(uint64_t i=1;i<=48;++i)oracle.push_back(record(i));CHECK(store.Verify(oracle,&error));
        CHECK(number(store,"peak_outstanding_records")<=c.capacity_records);CHECK(number(store,"peak_outstanding_bytes")<=c.capacity_bytes);
    }
}

int main() {
    struct Test {const char *name;void (*run)();};
    const Test tests[]={
        {"codec_and_normalization",codec_and_normalization},
        {"basic_equivalence_and_immutable_copy",basic_equivalence_and_immutable_copy},
        {"writing_charge_and_backpressure",writing_charge_and_backpressure},
        {"timeout_sticky_and_no_drop",timeout_sticky_and_no_drop},
        {"writer_failure_sticky",writer_failure_sticky},
        {"correct_scheduler_only_changes_order",correct_scheduler_only_changes_order},
        {"duplicate_identity_fails_not_overwrites",duplicate_identity_fails_not_overwrites},
        {"independent_oracle_rejects_wrong_request",independent_oracle_rejects_wrong_request},
        {"corrupted_database_rejected",corrupted_database_rejected},
        {"empty_off_and_invalid_configuration",empty_off_and_invalid_configuration},
        {"concurrent_submitters_are_bounded",concurrent_submitters_are_bounded},
    };
    size_t passed=0;
    for(const auto &test:tests){try{test.run();++passed;std::cout<<"PASS "<<test.name<<'\n';}
        catch(const std::exception &e){std::cerr<<"FAIL "<<test.name<<": "<<e.what()<<'\n';return 1;}}
    std::cout<<"PASS selected evidence fixtures "<<passed<<'/'<<sizeof(tests)/sizeof(tests[0])<<'\n';return 0;
}
