#ifndef FK_PREWRITTEN_WAL_ENV_H
#define FK_PREWRITTEN_WAL_ENV_H
#include <rocksdb/env.h>
#include <algorithm>
#include <array>
#include <chrono>
#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <filesystem>
#include <mutex>
#include <ostream>
#include <sys/stat.h>
#include <unistd.h>
namespace flowkeep {
struct PrewrittenWalStats {
    static constexpr uint64_t initial_bytes=1u<<20,zero_buffer_bytes=64u<<10;
    bool enabled=true;
    uint64_t attempts=0,successes=0,failures=0,bytes_written=0;
    uint64_t sync_attempts=0,sync_successes=0,sync_failures=0;
    uint64_t total_ns=0,maximum_ns=0,cleanup_failures=0;
    void WriteJson(std::ostream &out) const {
        out<<"{\"enabled\":"<<(enabled?"true":"false")<<",\"scope\":\"all_new_cold_wal_files_including_db_open_and_rollover\","
            "\"native_recovery_mode_unchanged\":true,\"native_wal_format_unchanged\":true,"
            "\"zero_buffer_scope\":\"process_shared_readonly\""
           <<",\"initial_bytes\":"<<initial_bytes<<",\"zero_buffer_bytes\":"<<zero_buffer_bytes
           <<",\"attempts\":"<<attempts<<",\"successes\":"<<successes<<",\"failures\":"<<failures
           <<",\"bytes_written\":"<<bytes_written<<",\"sync_attempts\":"<<sync_attempts
           <<",\"sync_successes\":"<<sync_successes<<",\"sync_failures\":"<<sync_failures
           <<",\"total_ns\":"<<total_ns<<",\"maximum_ns\":"<<maximum_ns
           <<",\"cleanup_failures\":"<<cleanup_failures<<"}";
    }
};
// The implementation is compiled separately with -fno-rtti, matching the
// system RocksDB build. This ordinary owning controller requires no RTTI change
// in callers. It must outlive the DB and all of that DB's background work.
class PrewrittenWalEnv {
public:
    explicit PrewrittenWalEnv(const std::string &path);
    ~PrewrittenWalEnv();
    PrewrittenWalEnv(const PrewrittenWalEnv&)=delete;
    PrewrittenWalEnv &operator=(const PrewrittenWalEnv&)=delete;
    rocksdb::Env *Env() const noexcept;
    PrewrittenWalStats Stats() const;
private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};
}
#endif
