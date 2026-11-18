#ifndef FK_HISTORY_WRITE_BATCH_H
#define FK_HISTORY_WRITE_BATCH_H
#include <rocksdb/write_batch.h>
#include <cstdint>
namespace flowkeep {
rocksdb::Status AppendSelectedWriteBatch(const rocksdb::WriteBatch &,rocksdb::WriteBatch &,
                                        const rocksdb::Slice &,uint64_t &,uint64_t &);
rocksdb::Status AppendHistoryWriteBatch(const rocksdb::WriteBatch &,rocksdb::WriteBatch &);
}
#endif
