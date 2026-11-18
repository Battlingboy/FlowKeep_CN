#ifndef FK_ONLINE_COLD_MANIFEST_H
#define FK_ONLINE_COLD_MANIFEST_H
#include "fk_online_cold_checkpoint.h"
#include <atomic>
#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <limits>
#include <sstream>
#include <string_view>
#include <sys/stat.h>
#include <unistd.h>
#include <unordered_set>
namespace flowkeep {
namespace online_cold_manifest {
inline bool IsDigest(const std::string &value) {
    if(value.size()!=64)return false;
    for(unsigned char c:value)if(!((c>='0' && c<='9') || (c>='a' && c<='f')))return false;
    return true;
}
inline void JsonString(std::ostream &out,const std::string &value) {
    constexpr char hex[]="0123456789abcdef";out.put('"');
    for(unsigned char c:value) {
        if(c=='"' || c=='\\'){out.put('\\');out.put(static_cast<char>(c));}
        else if(c<32){out<<"\\u00";out.put(hex[c>>4]);out.put(hex[c&15]);}
        else out.put(static_cast<char>(c));
    }
    out.put('"');
}
inline void Require(bool condition,const char *message) {
    if(!condition)throw std::runtime_error(message);
}
inline void RequireCompleteRecords(const ColdMigrationStats &stats,bool async_handoff,uint64_t confirmed) {
    Require(stats.outstanding==0 && stats.write_failed==0 && stats.stale==0 &&
        !stats.write_failure && stats.detached_failed==0 && stats.detached_outstanding==0 &&
        stats.accepted==stats.written && stats.written==confirmed,
        "cold backend is not completely confirmed");
    if(async_handoff)
        Require(stats.detached_only && stats.validated==0 &&
            stats.detached_accepted==confirmed && stats.detached_written==confirmed,
            "asynchronous cold handoffs are not completely durable");
    else
        Require(!stats.detached_only && stats.validated==confirmed &&
            stats.detached_accepted==0 && stats.detached_written==0,
            "cold release validations are not completely confirmed");
}
inline void SystemFailure(const char *operation) {
    const int saved=errno;throw std::runtime_error(std::string(operation)+": "+std::strerror(saved));
}
inline void Sync(int fd,const char *operation) {
    for(;;){if(::fsync(fd)==0)return;if(errno!=EINTR)SystemFailure(operation);}
}
// Own only descriptors and the unique temporary name created by this call.
// If rename succeeded but directory fsync failed, leave the visible manifest
// for audit and report failure; never claim that its commit is durable.
struct AtomicFile {
    int directory=-1,file=-1;std::string temporary;bool temporary_owned=false,renamed=false;
    ~AtomicFile() {
        if(file>=0)::close(file);
        if(directory>=0) {
            if(temporary_owned && !renamed)::unlinkat(directory,temporary.c_str(),0);
            ::close(directory);
        }
    }
};
inline void Commit(const std::string &path,const std::string &contents) {
    Require(!path.empty() && path.find('\0')==std::string::npos,"invalid cold manifest path");
    const std::filesystem::path target(path);const std::string name=target.filename().string();
    Require(!name.empty() && name!="." && name!="..","invalid cold manifest filename");
    const std::string parent=target.has_parent_path()?target.parent_path().string():".";
    AtomicFile output;
    output.directory=::open(parent.c_str(),O_RDONLY|O_DIRECTORY|O_CLOEXEC|O_NOFOLLOW);
    if(output.directory<0)SystemFailure("open cold manifest directory");
    struct stat previous{};
    if(::fstatat(output.directory,name.c_str(),&previous,AT_SYMLINK_NOFOLLOW)==0)
        Require(S_ISREG(previous.st_mode),"existing cold manifest is not a regular file");
    else if(errno!=ENOENT)SystemFailure("stat cold manifest target");
    static std::atomic<uint64_t> sequence{0};
    for(unsigned attempt=0;attempt<32;++attempt) {
        output.temporary="."+name+".tmp."+std::to_string(static_cast<unsigned long>(::getpid()))+
            "."+std::to_string(sequence.fetch_add(1,std::memory_order_relaxed));
        output.file=::openat(output.directory,output.temporary.c_str(),
            O_WRONLY|O_CREAT|O_EXCL|O_CLOEXEC|O_NOFOLLOW,0600);
        if(output.file>=0){output.temporary_owned=true;break;}
        if(errno!=EEXIST)SystemFailure("create cold manifest temporary");
        // A collision belongs to another invocation; never unlink that name.
        output.temporary.clear();
    }
    Require(output.file>=0,"cannot allocate unique cold manifest temporary");
    size_t offset=0;
    while(offset<contents.size()) {
        const ssize_t written=::write(output.file,contents.data()+offset,contents.size()-offset);
        if(written<0){if(errno==EINTR)continue;SystemFailure("write cold manifest");}
        Require(written>0,"zero-byte cold manifest write");offset+=static_cast<size_t>(written);
    }
    Sync(output.file,"sync cold manifest");
    const int close_result=::close(output.file);output.file=-1;
    if(close_result!=0)SystemFailure("close cold manifest");
    if(::renameat(output.directory,output.temporary.c_str(),output.directory,name.c_str())!=0)
        SystemFailure("rename cold manifest");
    output.renamed=true;Sync(output.directory,"sync cold manifest directory");
}
}
// Caller supplies every owner in its stable owner-index order, after joining
// those owners, sealing the common durable detector ACK and draining/stopping
// the shared backend. They must remain quiescent until this function returns.
// This is a clean-shutdown consistency root. It does not implement online
// crash replay, detector-state restoration or source-data retention.
inline bool PersistOnlineColdManifest(const std::string &path,
        const std::vector<OnlineColdCheckpoint*> &providers,
        const std::string &source_digest,const std::string &config_digest,
        std::string *error) noexcept {
    try {
        using namespace online_cold_manifest;
        if(error)error->clear();
        Require(IsDigest(source_digest) && IsDigest(config_digest),"invalid source/config SHA256");
        Require(!providers.empty() && providers.size()<=65536,"invalid cold manifest owner count");
        Require(providers.front()!=nullptr,"null cold manifest owner");
        const auto *backend=providers.front()->Backend();Require(backend!=nullptr,"null cold backend");
        // Handoff-ready owners can still have an asynchronous writer. Even
        // momentarily equal counters are not a sealed recovery boundary.
        Require(backend->Finished(),"cold backend writer is not finished");
        Require(!backend->AnyFailure(),"cold backend reports a persistence failure");
        const bool async_handoff=backend->AsyncHandoff();
        const auto &scope=providers.front()->Scope();
        Require(scope==config_digest && backend->Scope()==scope,"cold scope/config mismatch");
        const uint64_t ack=providers.front()->RecoveryAck();
        const uint64_t input=providers.front()->RecoveryInputCursor();
        const uint64_t watermark=providers.front()->RecoveryWatermark();
        std::unordered_set<const OnlineColdCheckpoint*> owners;
        std::unordered_set<std::string_view> live_ids;uint64_t confirmed=0,live_count=0;
        std::vector<std::string_view> verification_ids;
        for(const auto *provider:providers) {
            Require(provider!=nullptr && owners.insert(provider).second,"null or duplicate cold owner");
            Require(provider->Backend()==backend && provider->Scope()==scope,"mixed cold backend or scope");
            Require(provider->ShutdownReady() && provider->RecoveryBoundaryRecorded(),"unsealed cold owner");
            Require(provider->RecoveryAck()==ack && provider->RecoveryInputCursor()==input &&
                provider->RecoveryWatermark()==watermark,"inconsistent cold ACK/input/watermark");
            const auto count=provider->ConfirmedColdRecords();
            Require(count<=std::numeric_limits<uint64_t>::max()-confirmed,"cold record count overflow");
            confirmed+=count;
            for(const auto &id:provider->ShutdownLiveCoreIds()) {
                Require(IsDigest(id) && live_ids.insert(id).second,"invalid or duplicate live Core ID");
                if(!backend->WriteOnly())verification_ids.emplace_back(id);
                ++live_count;
            }
        }
        if(!backend->WriteOnly())
            Require(backend->VerifyRecoveryRoots(verification_ids),"missing or unprotected cold recovery root");
        const auto stats=backend->Stats();
        RequireCompleteRecords(stats,async_handoff,confirmed);
        std::ostringstream out;
        out<<"{\"schema\":\"flowkeep-online-cold-clean-shutdown-v1\",\"cold_record_schema\":\""<<kColdRecordSchema<<"\","
            "\"recovery_scope\":\"clean_shutdown_only\",\"online_crash_ack_recovery_supported\":false,"
            "\"source_records_sha256\":\""<<source_digest<<"\",\"config_sha256\":\""<<config_digest
            <<"\",\"cold_scope\":\""<<scope<<"\",\"backend_path\":";
        JsonString(out,backend->Path());
        out<<",\"async_handoff\":"<<(async_handoff?"true":"false")
            <<",\"cold_retention_contract\":\""<<backend->RetentionContract()<<"\""
            <<",\"snapshot_gc_enabled\":"<<(backend->SnapshotGcEnabled()?"true":"false")
            <<",\"recovery_roots_readback_verified\":"<<(backend->WriteOnly()?"false":"true")
            <<",\"records_validated\":"<<stats.validated
            <<",\"records_detached_written\":"<<stats.detached_written
            <<",\"owner_count\":"<<providers.size()<<",\"ack_sequence\":"<<ack
            <<",\"input_packet_cursor\":"<<input<<",\"semantic_watermark_ns\":"<<watermark
            <<",\"live_core_count\":"<<live_count<<",\"confirmed_cold_records\":"<<confirmed
            <<",\"owners\":[";
        for(size_t owner=0;owner<providers.size();++owner) {
            if(owner)out<<',';
            out<<"{\"owner_index\":"<<owner<<",\"live_core_ids\":[";
            const auto &ids=providers[owner]->ShutdownLiveCoreIds();
            for(size_t i=0;i<ids.size();++i){if(i)out<<',';out<<'"'<<ids[i]<<'"';}
            out<<"]}";
        }
        out<<"]}\n";Require(out.good(),"cannot encode cold manifest");
        Commit(path,out.str());return true;
    }catch(const std::exception &e){if(error){try{*error=e.what();}catch(...){}}return false;}
    catch(...){if(error){try{*error="unknown cold manifest failure";}catch(...){}}return false;}
}
// Explicit topology prevents an empty or omitted owner/backend from silently
// disappearing from the clean-shutdown root. All groups use one resource
// manager and split, rather than multiply, the original queue/disk budgets.
inline bool PersistOnlineColdManifest(const std::string &path,
        const std::vector<OnlineColdCheckpoint*> &providers,
        const std::vector<const OnlineColdBackend*> &backends,
        size_t expected_owner_count,
        const std::string &source_digest,const std::string &config_digest,
        std::string *error) noexcept {
    try {
        using namespace online_cold_manifest;
        if(error)error->clear();
        constexpr uint64_t kTotalLogicalQuota=256ull*1024*1024;
        constexpr size_t kTotalQueueCapacity=1024;
        Require(IsDigest(source_digest) && IsDigest(config_digest),"invalid source/config SHA256");
        Require(expected_owner_count!=0 && expected_owner_count<=65536 &&
            providers.size()==expected_owner_count,"missing or unexpected cold owner");
        Require(backends.size()==1 || backends.size()==2 || backends.size()==4,
            "unsupported cold backend topology");
        Require(expected_owner_count>=backends.size(),"cold backend has no configured owner");
        const size_t groups=backends.size();
        bool async_handoff=false;
        std::array<ColdMigrationStats,4> statistics{};
        std::array<uint64_t,4> confirmed{},live_count{},logical_bytes{};
        std::array<size_t,4> owner_counts{};
        std::unordered_set<const OnlineColdBackend*> unique_backends;
        std::unordered_set<std::string> backend_paths;
        const NativeRocksDbResources *resources=nullptr;
        for(size_t group=0;group<groups;++group) {
            const auto *backend=backends[group];
            Require(backend && unique_backends.insert(backend).second,"null or duplicate cold backend");
            Require(!backend->Path().empty() && backend_paths.insert(backend->Path()).second,
                "empty or duplicate cold backend path");
            Require(backend->Scope()==config_digest,"cold backend scope/config mismatch");
            Require(backend->Finished(),"cold backend writer is not finished");
            Require(!backend->AnyFailure(),"cold backend reports a persistence failure");
            if(group==0)async_handoff=backend->AsyncHandoff();
            Require(backend->AsyncHandoff()==async_handoff,"mixed cold handoff modes");
            Require(backend->SnapshotGcEnabled()==backends.front()->SnapshotGcEnabled(),"mixed cold GC modes");
            Require(backend->FinalRootsOnly()==backends.front()->FinalRootsOnly(),"mixed cold retention modes");
            Require(backend->WriteOnly()==backends.front()->WriteOnly(),"mixed cold read/write modes");
            if(group==0)resources=backend->ResourceIdentity();
            Require(resources && backend->ResourceIdentity()==resources,"cold backends do not share resources");
            Require(resources->block_cache && resources->write_buffers &&
                resources->block_cache->GetCapacity()==(4u<<20) &&
                resources->write_buffers->buffer_size()==(8u<<20),"cold shared RocksDB budgets changed");
            statistics[group]=backend->Stats();
            Require(statistics[group].capacity==kTotalQueueCapacity/groups,"cold queue budget is not evenly partitioned");
            Require(backend->MaximumLogicalBytes()==kTotalLogicalQuota/groups,"cold logical quota is not evenly partitioned");
            logical_bytes[group]=backend->LogicalBytes();
            Require(logical_bytes[group]<=backend->MaximumLogicalBytes(),"cold logical quota exceeded");
        }
        Require(providers.front()!=nullptr,"null cold manifest owner");
        const uint64_t ack=providers.front()->RecoveryAck();
        const uint64_t input=providers.front()->RecoveryInputCursor();
        const uint64_t watermark=providers.front()->RecoveryWatermark();
        std::unordered_set<const OnlineColdCheckpoint*> owners;
        std::unordered_set<std::string_view> live_ids;
        std::array<std::vector<std::string_view>,4> verification_ids;
        uint64_t total_confirmed=0,total_live=0,total_logical=0;
        for(size_t owner=0;owner<providers.size();++owner) {
            const auto *provider=providers[owner];const size_t group=owner%groups;
            Require(provider && owners.insert(provider).second,"null or duplicate cold owner");
            Require(provider->Backend()==backends[group],"cold owner/backend assignment mismatch");
            Require(provider->Scope()==config_digest,"cold owner scope/config mismatch");
            Require(provider->ShutdownReady() && provider->RecoveryBoundaryRecorded(),"unsealed cold owner");
            Require(provider->RecoveryAck()==ack && provider->RecoveryInputCursor()==input &&
                provider->RecoveryWatermark()==watermark,"inconsistent cold ACK/input/watermark");
            const uint64_t count=provider->ConfirmedColdRecords();
            Require(count<=std::numeric_limits<uint64_t>::max()-confirmed[group] &&
                count<=std::numeric_limits<uint64_t>::max()-total_confirmed,"cold record count overflow");
            confirmed[group]+=count;total_confirmed+=count;++owner_counts[group];
            for(const auto &id:provider->ShutdownLiveCoreIds()) {
                Require(IsDigest(id) && live_ids.insert(id).second,"invalid or duplicate live Core ID");
                if(!backends[group]->WriteOnly())verification_ids[group].emplace_back(id);
                Require(total_live!=std::numeric_limits<uint64_t>::max(),"cold live Core count overflow");
                ++live_count[group];++total_live;
            }
        }
        for(size_t group=0;group<groups;++group) {
            Require(owner_counts[group]!=0,"cold backend has no sealed owner");
            if(!backends[group]->WriteOnly())
                Require(backends[group]->VerifyRecoveryRoots(verification_ids[group]),
                    "missing or unprotected cold recovery root");
            const auto &s=statistics[group];
            RequireCompleteRecords(s,async_handoff,confirmed[group]);
            Require(logical_bytes[group]<=kTotalLogicalQuota-total_logical,"cold aggregate logical quota exceeded");
            total_logical+=logical_bytes[group];
        }
        // Preserve the existing serialized contract for the one-group mode,
        // after enforcing the stronger explicit topology/resource checks.
        if(groups==1)return PersistOnlineColdManifest(path,providers,source_digest,config_digest,error);
        std::ostringstream out;
        out<<"{\"schema\":\"flowkeep-online-cold-clean-shutdown-v2\",\"cold_record_schema\":\""<<kColdRecordSchema<<"\","
            "\"recovery_scope\":\"clean_shutdown_only\",\"online_crash_ack_recovery_supported\":false,"
            "\"source_records_sha256\":\""<<source_digest<<"\",\"config_sha256\":\""<<config_digest
            <<"\",\"cold_scope\":\""<<config_digest<<"\",\"backend_count\":"<<groups
            <<",\"async_handoff\":"<<(async_handoff?"true":"false")
            <<",\"snapshot_gc_enabled\":"<<(backends.front()->SnapshotGcEnabled()?"true":"false")
            <<",\"cold_retention_contract\":\""<<backends.front()->RetentionContract()<<"\""
            <<",\"recovery_roots_readback_verified\":"<<(backends[0]->WriteOnly()?"false":"true")
            <<",\"backend_assignment\":\"owner_index_modulo_backend_count\",\"shared_rocksdb_resources\":true"
            <<",\"shared_rocksdb_block_cache_capacity_bytes\":"<<resources->block_cache->GetCapacity()
            <<",\"shared_rocksdb_write_buffer_budget_bytes\":"<<resources->write_buffers->buffer_size()
            <<",\"queue_capacity_total\":"<<kTotalQueueCapacity
            <<",\"maximum_logical_bytes_total\":"<<kTotalLogicalQuota
            <<",\"logical_bytes_total\":"<<total_logical
            <<",\"owner_count\":"<<providers.size()<<",\"ack_sequence\":"<<ack
            <<",\"input_packet_cursor\":"<<input<<",\"semantic_watermark_ns\":"<<watermark
            <<",\"live_core_count\":"<<total_live<<",\"confirmed_cold_records\":"<<total_confirmed
            <<",\"backends\":[";
        for(size_t group=0;group<groups;++group) {
            if(group)out<<',';
            const auto *backend=backends[group];const auto &s=statistics[group];
            out<<"{\"backend_id\":"<<group<<",\"path\":";JsonString(out,backend->Path());
            out<<",\"cold_scope\":\""<<config_digest<<"\",\"finished\":true,\"sync_wal\":true"
                <<",\"async_handoff\":"<<(async_handoff?"true":"false")
                <<",\"snapshot_gc_enabled\":"<<(backend->SnapshotGcEnabled()?"true":"false")
                <<",\"cold_retention_contract\":\""<<backend->RetentionContract()<<"\""
                <<",\"recovery_roots_readback_verified\":"<<(backend->WriteOnly()?"false":"true")
                <<",\"writer_cpu\":"<<backend->WriterCpu()<<",\"owner_count\":"<<owner_counts[group]
                <<",\"queue_capacity\":"<<s.capacity<<",\"maximum_logical_bytes\":"<<backend->MaximumLogicalBytes()
                <<",\"logical_bytes\":"<<logical_bytes[group]<<",\"live_core_count\":"<<live_count[group]
                <<",\"records_accepted\":"<<s.accepted<<",\"records_written\":"<<s.written
                <<",\"records_validated\":"<<s.validated
                <<",\"records_detached_written\":"<<s.detached_written
                <<",\"confirmed_cold_records\":"<<confirmed[group]
                <<",\"outstanding\":"<<s.outstanding<<",\"write_failed\":"<<s.write_failed<<",\"stale\":"<<s.stale<<'}';
        }
        out<<"],\"owners\":[";
        for(size_t owner=0;owner<providers.size();++owner) {
            if(owner)out<<',';
            out<<"{\"owner_index\":"<<owner<<",\"backend_id\":"<<owner%groups
                <<",\"confirmed_cold_records\":"<<providers[owner]->ConfirmedColdRecords()<<",\"live_core_ids\":[";
            const auto &ids=providers[owner]->ShutdownLiveCoreIds();
            for(size_t i=0;i<ids.size();++i){if(i)out<<',';out<<'"'<<ids[i]<<'"';}
            out<<"]}";
        }
        out<<"]}\n";Require(out.good(),"cannot encode cold manifest");
        Commit(path,out.str());return true;
    }catch(const std::exception &e){if(error){try{*error=e.what();}catch(...){}}return false;}
    catch(...){if(error){try{*error="unknown cold manifest failure";}catch(...){}}return false;}
}
}
#endif
