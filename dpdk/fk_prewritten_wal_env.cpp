#include "fk_prewritten_wal_env.h"
namespace flowkeep {
// Linux/local-buffered-Env candidate. Only newly created cold WAL files are
// materialized. The native WritableFile remains logically empty at offset zero.
// This Env must outlive the DB and its background work.
class PrewrittenWalEnv::Impl final : public rocksdb::EnvWrapper {
public:
    explicit Impl(const std::string &path)
        :rocksdb::EnvWrapper(rocksdb::Env::Default()),directory_(std::filesystem::absolute(path).lexically_normal()) {}
    PrewrittenWalStats Stats() const {std::lock_guard<std::mutex> lock(mutex_);return stats_;}
    rocksdb::Status NewWritableFile(const std::string &path,std::unique_ptr<rocksdb::WritableFile> *result,
                                   const rocksdb::EnvOptions &options) override {
        try {
            if(!IsColdWal(path))return target()->NewWritableFile(path,result,options);
        }catch(const std::exception &error){return rocksdb::Status::IOError("cold WAL path",error.what());}
        if(!result)return rocksdb::Status::InvalidArgument("null cold WAL result");
        result->reset();std::lock_guard<std::mutex> lock(mutex_);++stats_.attempts;
        const auto start=std::chrono::steady_clock::now();
        std::unique_ptr<rocksdb::WritableFile> created;int fd=-1;struct stat identity{};bool own_identity=false;
        rocksdb::Status status;
        auto fail=[&](const rocksdb::Status &error) {
            if(fd>=0){const int closing=fd;fd=-1;if(close(closing)!=0)++stats_.cleanup_failures;}
            if(created){if(!created->Close().ok())++stats_.cleanup_failures;created.reset();}
            if(own_identity) {
                struct stat current{};
                if(lstat(path.c_str(),&current)==0 && Same(identity,current)) {
                    if(unlink(path.c_str())!=0)++stats_.cleanup_failures;
                }
            }
            ++stats_.failures;FinishTime(start);return error;
        };
        try {
            if(options.use_mmap_writes || options.use_direct_writes)
                return fail(rocksdb::Status::NotSupported("cold WAL prewrite requires native buffered file"));
            struct stat before{};
            if(lstat(path.c_str(),&before)==0)return fail(rocksdb::Status::IOError("cold WAL already exists"));
            if(errno!=ENOENT)return fail(IoError("stat new cold WAL"));
            status=target()->NewWritableFile(path,&created,options);if(!status.ok())return fail(status);
            if(!created || created->GetFileSize()!=0)return fail(rocksdb::Status::IOError("new cold WAL is not logically empty"));
            if(lstat(path.c_str(),&identity)!=0)return fail(IoError("stat created cold WAL"));
            if(!S_ISREG(identity.st_mode) || identity.st_size!=0 || identity.st_nlink!=1)
                return fail(rocksdb::Status::IOError("new cold WAL identity is not an empty regular file"));
            fd=open(path.c_str(),O_RDWR|O_CLOEXEC|O_NOFOLLOW);
            if(fd<0)return fail(IoError("open cold WAL for prewrite"));
            struct stat opened{};
            if(fstat(fd,&opened)!=0)return fail(IoError("fstat cold WAL prewrite fd"));
            if(!Same(identity,opened) || opened.st_size!=0)return fail(rocksdb::Status::IOError("cold WAL replaced before prewrite"));
            // Compare native inode identities as well, tying the path to the
            // actual WritableFile rather than only comparing two path stats.
            std::array<char,64> writer_id{},reader_id{};
            const size_t writer_size=created->GetUniqueId(writer_id.data(),writer_id.size());
            std::unique_ptr<rocksdb::RandomAccessFile> reader;
            status=target()->NewRandomAccessFile(path,&reader,options);if(!status.ok())return fail(status);
            const size_t reader_size=reader->GetUniqueId(reader_id.data(),reader_id.size());
            if(!writer_size || writer_size>writer_id.size() || writer_size!=reader_size || std::memcmp(writer_id.data(),reader_id.data(),writer_size))
                return fail(rocksdb::Status::IOError("cold WAL native inode identity mismatch or unavailable"));
            own_identity=true;
            reader.reset();
            for(uint64_t offset=0;offset<PrewrittenWalStats::initial_bytes;) {
                const size_t count=static_cast<size_t>(std::min<uint64_t>(zero_.size(),PrewrittenWalStats::initial_bytes-offset));
                const ssize_t written=pwrite(fd,zero_.data(),count,static_cast<off_t>(offset));
                if(written<0 && errno==EINTR)continue;
                if(written<=0)return fail(written<0?IoError("prewrite cold WAL"):rocksdb::Status::IOError("zero-length cold WAL prewrite"));
                if(static_cast<size_t>(written)>count)return fail(rocksdb::Status::IOError("oversized cold WAL prewrite"));
                offset+=static_cast<uint64_t>(written);stats_.bytes_written+=static_cast<uint64_t>(written);
            }
            ++stats_.sync_attempts;int synced;
            do {synced=fdatasync(fd);}while(synced<0 && errno==EINTR);
            if(synced!=0){++stats_.sync_failures;return fail(IoError("sync prewritten cold WAL"));}
            ++stats_.sync_successes;
            struct stat after{},named{};
            if(fstat(fd,&after)!=0 || lstat(path.c_str(),&named)!=0)return fail(IoError("stat prewritten cold WAL"));
            if(!Same(identity,after) || !Same(identity,named) || after.st_size!=off_t(PrewrittenWalStats::initial_bytes) ||
               created->GetFileSize()!=0 || created->GetUniqueId(reader_id.data(),reader_id.size())!=writer_size ||
               std::memcmp(writer_id.data(),reader_id.data(),writer_size))
                return fail(rocksdb::Status::IOError("prewrite changed cold WAL identity or logical size"));
            const int closing=fd;fd=-1;if(close(closing)!=0)return fail(IoError("close cold WAL prewrite fd"));
            *result=std::move(created);++stats_.successes;FinishTime(start);return rocksdb::Status::OK();
        }catch(const std::exception &error){return fail(rocksdb::Status::IOError("cold WAL prewrite exception",error.what()));}
        catch(...){return fail(rocksdb::Status::IOError("unknown cold WAL prewrite exception"));}
    }
private:
    std::filesystem::path directory_;mutable std::mutex mutex_;PrewrittenWalStats stats_{};
    inline static const std::array<char,PrewrittenWalStats::zero_buffer_bytes> zero_{};
    bool IsColdWal(const std::string &path) const {
        if(path.size()<5 || path.compare(path.size()-4,4,".log"))return false;
        const auto parsed=std::filesystem::absolute(path).lexically_normal();
        const auto name=parsed.filename().string();
        if(parsed.parent_path()!=directory_ || name.size()<5)return false;
        for(size_t i=0;i<name.size()-4;++i)if(name[i]<'0' || name[i]>'9')return false;
        return true;
    }
    static bool Same(const struct stat &a,const struct stat &b) {return a.st_dev==b.st_dev && a.st_ino==b.st_ino;}
    static rocksdb::Status IoError(const char *action) {const int code=errno;return rocksdb::Status::IOError(action,std::strerror(code));}
    void FinishTime(std::chrono::steady_clock::time_point start) {
        const auto elapsed=static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::nanoseconds>(
            std::chrono::steady_clock::now()-start).count());
        stats_.total_ns+=elapsed;if(elapsed>stats_.maximum_ns)stats_.maximum_ns=elapsed;
    }
};
PrewrittenWalEnv::PrewrittenWalEnv(const std::string &path):impl_(std::make_unique<Impl>(path)) {}
PrewrittenWalEnv::~PrewrittenWalEnv()=default;
rocksdb::Env *PrewrittenWalEnv::Env() const noexcept {return impl_.get();}
PrewrittenWalStats PrewrittenWalEnv::Stats() const {return impl_->Stats();}
}
