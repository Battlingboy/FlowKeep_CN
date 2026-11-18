#ifndef FK_COLD_EVIDENCE_H
#define FK_COLD_EVIDENCE_H
#include "fk_compact_flow_table.h"
#include <openssl/sha.h>
#include <cstring>
#include <stdexcept>
#include <string>
#include <type_traits>
namespace flowkeep {
#if defined(FK_COLD_COMPACT_ZERO_TAIL) && FK_COLD_COMPACT_ZERO_TAIL
inline constexpr bool kCompactColdRecord=true;
inline constexpr const char *kColdRecordSchema="FKCE4";
#else
inline constexpr bool kCompactColdRecord=false;
inline constexpr const char *kColdRecordSchema="FKCE3";
#endif
// Evidence payload only: core admission, budgets, policy and ACK/replay remain
// the caller's responsibility. Restore never allocates or fills missing packets.
struct ColdEvidence {
    std::string scope;
    fk_compact_flow_handle handle{};
    fk_compact_flow_snapshot snapshot{};
    fk_compact_core_state core{};
    uint8_t resident_mask=0,full_tls=0;
    fk_compact_stat_state stat{};
    fk_compact_seq_state seq{};
    fk_compact_ja4_state ja4{};
};
namespace cold_codec {
struct Wire {
    std::string bytes;size_t position=0;bool reading=false;bool sslv2_state_present=true;
    bool compact_zero_tail=false;
    template<class T> void field(T &v) {
        static_assert(sizeof(T)<=8,"integer field width");
        if(reading) {
            if(position>bytes.size() || bytes.size()-position<sizeof(T))
                throw std::runtime_error("truncated cold evidence");
            uint64_t n=0;for(size_t i=0;i<sizeof(T);++i)n|=uint64_t(static_cast<unsigned char>(bytes[position++]))<<(8*i);
            v=static_cast<T>(n);
        } else for(size_t i=0;i<sizeof(T);++i)bytes.push_back(static_cast<char>((uint64_t(v)>>(8*i))&255));
    }
    template<class T,size_t N> void array(T (&v)[N]) {
        if constexpr(std::is_same<T,uint8_t>::value) {
            if constexpr(N>=64) {
                if(compact_zero_tail) {
                    // FKCE4 removes only an exactly-zero suffix, not bytes
                    // beyond a parser cursor. Nonzero stale bytes survive.
                    // N is schema-defined; reject lengths before any copy.
                    uint32_t stored=static_cast<uint32_t>(N);
                    if(!reading)while(stored && v[stored-1]==0)--stored;
                    field(stored);
                    if(stored>N)throw std::runtime_error("invalid compact array length");
                    if(reading) {
                        if(position>bytes.size() || stored>bytes.size()-position)
                            throw std::runtime_error("truncated compact array");
                        if(stored && bytes[position+stored-1]=='\0')
                            throw std::runtime_error("noncanonical compact array");
                        std::memcpy(v,bytes.data()+position,stored);
                        std::memset(v+stored,0,N-stored);position+=stored;
                    }else bytes.append(reinterpret_cast<const char*>(v),stored);
                    return;
                }
            }
            // The FKCE2 representation of an octet array is its raw bytes.
            // Multi-byte integers retain the explicit little-endian codec.
            if(reading) {
                if(position>bytes.size() || N>bytes.size()-position)
                    throw std::runtime_error("truncated cold evidence");
                std::memcpy(v,bytes.data()+position,N);position+=N;
            }else bytes.append(reinterpret_cast<const char*>(v),N);
        }else for(auto &x:v)field(x);
    }
};
inline void fingerprint(Wire &w,fk_compact_fingerprint_observation &v) {
    w.field(v.cipher_set_hash);w.field(v.extension_set_hash);w.field(v.signature_set_hash);
    w.field(v.server_name_hash);w.field(v.alpn_hash);w.field(v.legacy_version);
    w.field(v.selected_cipher);w.field(v.cipher_count);w.field(v.extension_count);
    w.field(v.signature_algorithm_count);w.field(v.present);w.field(v.hello_retry_request);
    if(w.sslv2_state_present) {
        w.field(v.completeness);w.field(v.framing);
        if(v.completeness>FK_COMPLETENESS_CAP_EXCEEDED || v.framing>FK_SSLV2_COMPATIBLE_FRAMING)
            throw std::runtime_error("invalid fingerprint provenance");
    }else if(w.reading) {v.completeness=0;v.framing=0;}
}
inline void stream(Wire &w,fk_compact_tls_direction &d) {
    auto &s=d.tls;
    w.array(s.record_header);w.array(s.handshake_header);w.field(s.record_header_bytes);
    w.field(s.handshake_header_bytes);w.field(s.record_content_type);w.field(s.handshake_type);
    w.field(s.application_data_seen);
    if(w.sslv2_state_present)w.field(s.record_is_sslv2_client_hello);
    else if(w.reading)s.record_is_sslv2_client_hello=0;
    w.field(s.record_remaining);w.field(s.handshake_length);
    w.field(s.handshake_remaining);w.field(s.retained_body_bytes);w.array(s.hello_body);
    uint32_t completeness=static_cast<uint32_t>(s.completeness);w.field(completeness);
    s.completeness=static_cast<fk_protocol_completeness>(completeness);
    w.field(s.bytes_seen);w.field(s.records_seen);w.field(s.hello_messages_emitted);
    w.field(s.cap_exceeded_messages);w.field(s.malformed_records);w.field(d.next_sequence);
    w.field(d.sequence_initialized);w.field(d.desynchronized);w.field(d.closed);
    w.field(d.retransmitted_bytes);w.field(d.gap_events);
    if(completeness>FK_COMPLETENESS_CAP_EXCEEDED || d.sequence_initialized>1 || d.desynchronized>1 || d.closed>1 || s.record_header_bytes>5 || s.handshake_header_bytes>4 || s.retained_body_bytes>FK_COMPACT_TLS_HELLO_CAP || s.record_is_sslv2_client_hello>1)
        throw std::runtime_error("invalid TLS evidence lengths");
}
inline void core(Wire &w,fk_compact_core_state &v) {
    w.field(v.logical_connection_id);auto &c=v.component;
    w.field(c.absolute_deadline_ns);
    for(float &f:c.initial_action_values) {
        uint32_t bits=0;std::memcpy(&bits,&f,4);w.field(bits);std::memcpy(&f,&bits,4);
    }
    w.field(c.owned.stat_bytes);w.field(c.owned.seq_bytes);w.field(c.owned.ja4_bytes);
    w.field(c.mask);
    uint8_t flags=c.decision_started | (c.observation_complete<<1) |
        (c.initial_action_values_valid<<2) | (c.replacement_values_physical<<3);
    w.field(flags);if(flags>15)throw std::runtime_error("invalid Core flags");
    c.decision_started=flags&1;c.observation_complete=(flags>>1)&1;
    c.initial_action_values_valid=(flags>>2)&1;c.replacement_values_physical=(flags>>3)&1;
    w.field(c.checkpoint_index);w.array(c.missing_reason);w.field(c.next_checkpoint_packet);
    w.array(c.component_start_packet);w.field(c.released_mask);
    auto &b=v.bootstrap;w.array(b.wire_size);w.array(b.payload_size);w.array(b.delta_time_us);
    w.array(b.tcp_flags);w.field(b.direction_bits);w.field(b.count);
    w.array(v.direction_packets);w.field(v.maximum_wire_size);w.field(v.first_direction);
    w.field(v.fixed_ttl_deadline);w.field(v.terminal_observed);w.field(v.lifecycle_reserved);
    if(c.mask>FK_COMPONENT_FULL || c.released_mask>FK_COMPONENT_FULL ||
        b.count>FK_COMPACT_BOOTSTRAP_PACKETS || v.first_direction>1 || v.terminal_observed>1)
        throw std::runtime_error("invalid logical Core");
}
inline void body(Wire &w,ColdEvidence &v) {
    if(!w.reading && (v.scope.empty() || v.scope.size()>256))throw std::runtime_error("invalid scope length");
    uint16_t n=static_cast<uint16_t>(v.scope.size());w.field(n);
    if(n==0 || n>256)throw std::runtime_error("invalid evidence scope");
    if(w.reading)v.scope.resize(n);
    for(char &c:v.scope)w.field(c);
    w.field(v.handle.index);w.field(v.handle.generation);
    auto &s=v.snapshot;auto &k=s.key;
    w.field(k.ip_version);w.field(k.protocol);w.array(k.low_addr);w.array(k.high_addr);
    w.field(k.low_port);w.field(k.high_port);w.field(s.first_timestamp_ns);w.field(s.last_timestamp_ns);
    w.field(s.packets);w.field(s.bytes);w.field(s.first_direction);w.field(s.component_mask);
    w.field(s.observation_complete);w.field(s.next_checkpoint_packet);
    core(w,v.core);
    w.field(v.resident_mask);w.field(v.full_tls);
    if((v.resident_mask&~FK_COMPONENT_FULL) || v.full_tls>1 ||
        (v.full_tls && !(v.resident_mask&FK_COMPONENT_JA4)) || s.last_timestamp_ns<s.first_timestamp_ns)
        throw std::runtime_error("invalid evidence envelope");
    if(v.resident_mask&FK_COMPONENT_STAT) {
        auto &t=v.stat;w.array(t.direction_packets);w.array(t.direction_bytes);w.array(t.payload_bytes);
        w.array(t.interarrival_sum_ns);w.array(t.interarrival_squared_sum_ns);
        w.field(t.minimum_wire_size);w.field(t.maximum_wire_size);w.array(t.tcp_flag_counts);
    }
    if(v.resident_mask&FK_COMPONENT_SEQ) {
        for(auto &p:v.seq.packets){w.field(p.delta_time_us);w.field(p.wire_size);w.field(p.direction);}
        w.field(v.seq.count);w.field(v.seq.next);
        if(v.seq.count>FK_COMPACT_SEQ_PACKETS || v.seq.next>=FK_COMPACT_SEQ_PACKETS)
            throw std::runtime_error("invalid sequence evidence bounds");
    }
    if(v.resident_mask&FK_COMPONENT_JA4) {
        fingerprint(w,v.ja4.client);fingerprint(w,v.ja4.server);
        if(v.full_tls) {
            for(auto &d:v.ja4.tls.direction)stream(w,d);
            uint32_t c=static_cast<uint32_t>(v.ja4.tls.completeness);w.field(c);
            if(c>FK_COMPLETENESS_CAP_EXCEEDED)throw std::runtime_error("invalid TLS completeness");
            v.ja4.tls.completeness=static_cast<fk_protocol_completeness>(c);
        }
    }
}
}
inline bool EncodeColdEvidence(const ColdEvidence &record,std::string *output,
                               bool compact=kCompactColdRecord) noexcept {
    try {
        if(!output || record.scope.empty() || record.scope.size()>256)return false;
        ColdEvidence copy=record;cold_codec::Wire w;
        // Capacity is only an allocation hint; body() still defines every
        // serialized field. Build magic/body/digest in one owned buffer.
        size_t capacity=384+copy.scope.size()+SHA256_DIGEST_LENGTH;
        if(copy.resident_mask&FK_COMPONENT_STAT)capacity+=sizeof(copy.stat);
        if(copy.resident_mask&FK_COMPONENT_SEQ)capacity+=sizeof(copy.seq);
        if(copy.resident_mask&FK_COMPONENT_JA4)
            capacity+=copy.full_tls ? sizeof(copy.ja4) : 2*sizeof(copy.ja4.client);
        w.compact_zero_tail=compact;
        w.bytes.reserve(capacity);w.bytes=compact ? "FKCE4" : "FKCE3";cold_codec::body(w,copy);
        unsigned char digest[SHA256_DIGEST_LENGTH];
        SHA256(reinterpret_cast<const unsigned char*>(w.bytes.data()),w.bytes.size(),digest);
        w.bytes.append(reinterpret_cast<const char*>(digest),sizeof(digest));
        *output=std::move(w.bytes);return true;
    }catch(...){return false;}
}
inline bool DecodeColdEvidence(const std::string &encoded,const std::string &scope,ColdEvidence *output) noexcept {
    try {
        if(!output || encoded.size()<37 || encoded.size()>16384 ||
           (encoded.compare(0,5,"FKCE2") && encoded.compare(0,5,"FKCE3") && encoded.compare(0,5,"FKCE4")))return false;
        const size_t size=encoded.size()-SHA256_DIGEST_LENGTH;
        unsigned char digest[SHA256_DIGEST_LENGTH];
        SHA256(reinterpret_cast<const unsigned char*>(encoded.data()),size,digest);
        if(std::memcmp(digest,encoded.data()+size,sizeof(digest)))return false;
        cold_codec::Wire w;w.bytes=encoded.substr(5,size-5);w.reading=true;
        w.sslv2_state_present=encoded.compare(0,5,"FKCE2")!=0;
        w.compact_zero_tail=encoded.compare(0,5,"FKCE4")==0;
        ColdEvidence decoded;cold_codec::body(w,decoded);
        if(w.position!=w.bytes.size() || decoded.scope!=scope)return false;
        *output=std::move(decoded);return true;
    }catch(...){return false;}
}
inline bool CaptureColdEvidence(fk_compact_flow_table *table,fk_compact_flow_handle handle,
                               const std::string &scope,ColdEvidence *output) noexcept {
    try {
        if(!output || scope.empty() || scope.size()>256)return false;
        ColdEvidence v;v.scope=scope;v.handle=handle;
        if(!fk_compact_flow_table_snapshot(table,handle,&v.snapshot) ||
            !fk_compact_flow_table_capture_core(table,handle,&v.core))return false;
        if(auto *p=fk_compact_flow_table_stat(table,handle)){v.stat=*p;v.resident_mask|=FK_COMPONENT_STAT;}
        if(auto *p=fk_compact_flow_table_seq(table,handle)){v.seq=*p;v.resident_mask|=FK_COMPONENT_SEQ;}
        bool full_tls=false;
        if(auto *p=fk_compact_flow_table_resident_ja4(table,handle,&full_tls)) {
            v.ja4.client=p->client;v.ja4.server=p->server;v.resident_mask|=FK_COMPONENT_JA4;
            if(full_tls){v.ja4.tls=p->tls;v.full_tls=1;}
        }
        *output=std::move(v);return true;
    }catch(...){return false;}
}
inline bool RestoreColdIntoNewGeneration(fk_compact_flow_table *table,const ColdEvidence &record,
        fk_compact_flow_handle *handle) noexcept {
    std::string validated;
    if(!EncodeColdEvidence(record,&validated))return false;
    return fk_compact_flow_table_restore_cold(table,&record.snapshot,&record.core,
        record.resident_mask&FK_COMPONENT_STAT?&record.stat:nullptr,
        record.resident_mask&FK_COMPONENT_SEQ?&record.seq:nullptr,
        record.resident_mask&FK_COMPONENT_JA4?&record.ja4:nullptr,record.full_tls!=0,handle);
}
// Caller must hold the single-owner flow-table exclusion. Requires exactly
// the same core checkpoint and preallocated resident components. No policy,
// generation, budget, evidence-validity or missing-reason fields are changed.
inline bool RestoreColdEvidence(fk_compact_flow_table *table,fk_compact_flow_handle handle,
                                const std::string &scope,const ColdEvidence &v) noexcept {
    try {
        if(v.scope!=scope || handle.index!=v.handle.index || handle.generation!=v.handle.generation)return false;
        ColdEvidence current;if(!CaptureColdEvidence(table,handle,scope,&current))return false;
        if(current.resident_mask!=v.resident_mask || current.full_tls!=v.full_tls)return false;
        ColdEvidence target_header=v,current_header=current;
        target_header.resident_mask=current_header.resident_mask=0;
        target_header.full_tls=current_header.full_tls=0;
        std::string a,b,validated;
        if(!EncodeColdEvidence(v,&validated) || !EncodeColdEvidence(target_header,&a) ||
            !EncodeColdEvidence(current_header,&b) || a!=b)return false;
        auto *stat=fk_compact_flow_table_stat(table,handle);auto *seq=fk_compact_flow_table_seq(table,handle);
        // Provisional TLS is physically resident but deliberately hidden from
        // detector accessors. Restore the validated physical slab, not a
        // nullable detector view that could turn restoration into a no-op.
        bool physical_full_tls=false;
        auto *ja4=const_cast<fk_compact_ja4_state*>(
            fk_compact_flow_table_resident_ja4(table,handle,&physical_full_tls));
        auto *tls=ja4 && physical_full_tls ? &ja4->tls : nullptr;
        if(((v.resident_mask&FK_COMPONENT_STAT) && !stat) ||
           ((v.resident_mask&FK_COMPONENT_SEQ) && !seq) ||
           ((v.resident_mask&FK_COMPONENT_JA4) && !ja4) ||
           (v.full_tls && !tls))return false;
        if(stat)*stat=v.stat;
        if(seq)*seq=v.seq;
        if(ja4){ja4->client=v.ja4.client;ja4->server=v.ja4.server;}
        if(tls)*tls=v.ja4.tls;
        return true;
    }catch(...){return false;}
}
}
#endif
