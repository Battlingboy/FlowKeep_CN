#ifndef FK_NATIVE_EVENT_CONTEXT_H
#define FK_NATIVE_EVENT_CONTEXT_H
#include <cstddef>
#include <cstdint>
#include <string>
#include "fk_native_parser.h"
namespace flowkeep {
struct NativeEventContext {
    uint64_t sequence, event_token, semantic_timestamp_ns;
    const std::string *event_id;
    fk_flow_key canonical_key{};
    uint64_t flow_first_timestamp_ns = 0u;
    uint64_t logical_connection_id = 0u;
    uint32_t checkpoint_packet = 0u;
    uint8_t request_flags = 0u;
};
class NativeEventContextSink {
public:
    virtual ~NativeEventContextSink() = default;
    virtual bool PrepareContext(const NativeEventContext *, size_t, std::string *) noexcept = 0;
    virtual void ClearContext() noexcept = 0;
    virtual const uint8_t *HistoryResetRows() const noexcept = 0;
    // A computed result is provisional until its history dependency is durable.
    virtual bool WaitDurable(uint64_t, std::string *) noexcept { return true; }
};
}
#endif
