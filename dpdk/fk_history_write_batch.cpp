#include "fk_history_write_batch.h"
namespace flowkeep {
// Installed RocksDB omits Handler RTTI. Isolate this derived class in the
// existing RocksDB compatibility library compiled with -fno-rtti.
rocksdb::Status AppendHistoryWriteBatch(const rocksdb::WriteBatch &from,rocksdb::WriteBatch &to) {
    struct Append final : rocksdb::WriteBatch::Handler {
        rocksdb::WriteBatch &batch;
        explicit Append(rocksdb::WriteBatch &b):batch(b){}
        void Put(const rocksdb::Slice &k,const rocksdb::Slice &v) override {batch.Put(k,v);}
        void Delete(const rocksdb::Slice &k) override {batch.Delete(k);}
    } handler(to);
    return from.Iterate(&handler);
}
}

namespace flowkeep {
// The installed RocksDB omits Handler RTTI. This existing compatibility
// translation unit already builds with -fno-rtti; other consumers are unchanged.
rocksdb::Status AppendSelectedWriteBatch(const rocksdb::WriteBatch &from,rocksdb::WriteBatch &to,
        const rocksdb::Slice &prefix,uint64_t &rows,uint64_t &bytes) {
    struct Append final:rocksdb::WriteBatch::Handler {
        rocksdb::WriteBatch &out;rocksdb::Slice prefix;uint64_t rows=0,bytes=0;
        Append(rocksdb::WriteBatch &b,const rocksdb::Slice &p):out(b),prefix(p){}
        rocksdb::Status PutCF(uint32_t cf,const rocksdb::Slice &key,const rocksdb::Slice &value) override {
            if(cf || (!key.starts_with(prefix) && !key.starts_with("bundle/")))
                return rocksdb::Status::InvalidArgument("unexpected prepared evidence entry");
            const auto result=out.Put(key,value);
            if(result.ok()){if(key.starts_with(prefix))++rows;bytes+=key.size()+value.size();}
            return result;
        }
    } append(to,prefix);
    const auto status=from.Iterate(&append);rows=append.rows;bytes=append.bytes;return status;
}
}
