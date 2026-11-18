#include "fk_versioned_observation_source.h"

#include <array>
#include <cstdio>
#include <cstring>
#include <exception>
#include <memory>
#include <string>
#include <utility>

using namespace flowkeep;

namespace {

#define REQUIRE(condition) do { \
    if (!(condition)) { \
        std::fprintf(stderr, "line %d: %s; %s\n", __LINE__, #condition, error.c_str()); \
        return false; \
    } \
} while (false)

uint64_t Now() {
    timespec time{};
    clock_gettime(CLOCK_MONOTONIC, &time);
    return uint64_t(time.tv_sec) * 1000000000ull + time.tv_nsec;
}

enum class Call { Issued, Scored, Durable, Finalize, Finish, Close };

struct Trace {
    std::array<Call, 128> calls{};
    size_t count = 0;
    bool Add(Call call) noexcept {
        if (count == calls.size()) return false;
        calls[count++] = call;
        return true;
    }
};

// Fixed storage keeps these noexcept callbacks free of container growth.
// Failure injection returns false; deliberately throwing here would terminate.
class Observer final : public SelectedEvidenceObserver {
public:
    struct Issue {
        fk_detector_request_v1 request{};
        uint64_t sequence = 0, event = 0;
    };
    struct Score { uint64_t sequence = 0; bool actual = false; double score = 0; };
    struct Final {
        fk_flow_key key{};
        uint64_t first = 0, logical = 0, last_candidate = 0;
    };
    explicit Observer(Trace &trace) : trace_(trace) {}

    std::array<Issue, 16> issued{};
    std::array<Score, 16> scored{};
    std::array<NativeFusionDecision, 16> durable{};
    std::array<Final, 16> finalized{};
    size_t issued_count = 0, scored_count = 0, durable_count = 0;
    size_t finalize_count = 0, finish_count = 0;
    bool reject_issued = false, reject_durable = false;
    bool reject_finalize = false, reject_finish = false;
    bool admission_ready = true;
    bool FinalizeAdmissionReady() const noexcept override {return admission_ready;}

    bool Issued(const fk_detector_request_v1 &request, uint64_t sequence,
                uint64_t event, std::string *error) noexcept override {
        if (!trace_.Add(Call::Issued) || issued_count == issued.size())
            return Reject(error, "fake Issued capacity");
        issued[issued_count++] = {request, sequence, event};
        return !reject_issued || Reject(error, "injected Issued failure");
    }
    bool Scored(uint64_t sequence, bool actual, double score,
                std::string *error) noexcept override {
        if (!trace_.Add(Call::Scored) || scored_count == scored.size())
            return Reject(error, "fake Scored capacity");
        scored[scored_count++] = {sequence, actual, score};
        return true;
    }
    bool Durable(const NativeFusionDecision &decision,
                 std::string *error) noexcept override {
        if (!trace_.Add(Call::Durable) || durable_count == durable.size())
            return Reject(error, "fake Durable capacity");
        durable[durable_count++] = decision;
        return !reject_durable || Reject(error, "injected Durable failure");
    }
    bool Finalize(const fk_flow_key &key, uint64_t first, uint64_t logical,
                  uint64_t last_candidate, std::string *error) noexcept override {
        if (!trace_.Add(Call::Finalize) || finalize_count == finalized.size())
            return Reject(error, "fake Finalize capacity");
        finalized[finalize_count++] = {key, first, logical, last_candidate};
        return !reject_finalize || Reject(error, "injected Finalize failure");
    }
    bool Finish(std::string *error) noexcept override {
        ++finish_count;
        if (!trace_.Add(Call::Finish)) return Reject(error, "fake Finish capacity");
        return !reject_finish || Reject(error, "injected Finish failure");
    }

private:
    static bool Reject(std::string *error, const char *message) noexcept {
        if (error) *error = message;
        return false;
    }
    Trace &trace_;
};

class Input final : public NativeFusionRequestSource {
public:
    explicit Input(Trace &trace) : trace_(trace) {}
    fk_detector_request_v1 opening{};
    uint64_t peeked = 0, acked = 0, close_count = 0;
    bool done = false, reject_close = false;

    NativeFusionSourceResult Peek(fk_detector_request_v1 *request,
            uint64_t *sequence, std::string *) noexcept override {
        if (peeked) return done ? NativeFusionSourceResult::ProducerDone
                               : NativeFusionSourceResult::Empty;
        *request = opening;
        *sequence = ++peeked;
        return NativeFusionSourceResult::Item;
    }
    bool Ack(uint64_t sequence, std::string *) noexcept override {
        if (sequence <= acked || sequence > peeked) return false;
        acked = sequence;
        return true;
    }
    bool Snapshot(NativeFusionSourceSnapshot *snapshot,
                  std::string *) const noexcept override {
        *snapshot = {};
        snapshot->capacity = 32;
        snapshot->run_epoch = 20260925;
        snapshot->write_sequence = snapshot->published = 1;
        snapshot->read_sequence = snapshot->records_acked = acked;
        snapshot->records_peeked = peeked;
        snapshot->producer_done = done;
        snapshot->producer_stop_monotonic_ns = done ? Now() : 0;
        snapshot->consumer_open_count = 1;
        snapshot->consumer_close_count = close_count;
        snapshot->consumer_claim_token = close_count ? 0 : 1;
        return true;
    }
    bool Close(std::string *error) noexcept override {
        ++close_count;
        if (!trace_.Add(Call::Close) || reject_close) {
            if (error) *error = "injected transport Close failure";
            return false;
        }
        return true;
    }
private:
    Trace &trace_;
};

class Router final : public NativeFusionEventRouter {
public:
    bool Resolve(const fk_detector_request_v1 &, Route *route,
                 std::string *) noexcept override {
        route->event_token = 1;
        route->event_id = &event_;
        return true;
    }
private:
    std::string event_ = "shared-event";
};

struct Fixture {
    Trace trace;
    Router router;
    std::shared_ptr<PrefixVersionStore> versions;
    std::shared_ptr<AdaptiveTerminalRegistry> registry =
        std::make_shared<AdaptiveTerminalRegistry>();
    std::shared_ptr<Observer> observer = std::make_shared<Observer>(trace);
    Input *input = nullptr;
    std::unique_ptr<VersionedObservationSource> source;
    fk_detector_request_v1 opening{};
    PrefixVersionStore::Identity identity{};

    Fixture(std::shared_ptr<PrefixVersionStore> store, uint64_t ordinal)
        : versions(std::move(store)) {
        fk_detector_request_v1_prepare(&opening);
        opening.canonical_key.ip_version = 4;
        opening.canonical_key.protocol = 17;
        opening.canonical_key.low_addr[0] = 10;
        opening.canonical_key.high_addr[0] = 20;
        opening.canonical_key.low_port = 1;
        opening.canonical_key.high_port = 443;
        opening.flow_index = 9;
        opening.flow_generation = 3;
        opening.flow_first_timestamp_ns = ordinal * 100;
        opening.logical_connection_id = ordinal + 10;
        opening.flags = FK_DETECTOR_REQUEST_FLAG_COVERAGE_OPEN;
        opening.semantic_timestamp_ns = opening.flow_first_timestamp_ns;
        opening.physical_timestamp_ns = Now();
        opening.event_routing_token = 1;
        identity = {opening.canonical_key, opening.flow_first_timestamp_ns,
                    opening.logical_connection_id};
        auto transport = std::make_unique<Input>(trace);
        input = transport.get();
        input->opening = opening;
        source = std::make_unique<VersionedObservationSource>(std::move(transport),
            &router, versions, registry, 2, observer);
    }

    bool Publish(uint32_t count, uint32_t first_next) {
        for (uint32_t packet = 1; packet <= count; ++packet) {
            PrefixVersionStore::Prefix prefix{};
            prefix.physical_ns = Now();
            prefix.evidence.observation_ns = identity.first + packet - 1;
            prefix.evidence.packet = packet;
            prefix.evidence.flow_index = opening.flow_index;
            prefix.evidence.generation = opening.flow_generation;
            prefix.evidence.mask = 3;
            for (size_t i = 0; i < prefix.evidence.features.size(); ++i)
                prefix.evidence.features[i] = float(packet * 1000 + i);
            if (!versions->Publish(identity, prefix, packet == 1 ? first_next : 0))
                return false;
        }
        return true;
    }

    void Feedback(uint64_t sequence, uint32_t packet, uint32_t next, bool stop) {
        NativeEventContext context{};
        context.canonical_key = identity.key;
        context.flow_first_timestamp_ns = identity.first;
        context.logical_connection_id = identity.logical;
        context.sequence = sequence;
        context.checkpoint_packet = packet;
        fk_marginal_checkpoint_state state{};
        state.calls = 1;
        state.last_observation_packet = packet;
        state.pending_packet = next;
        state.stopped = stop;
        registry->Publish(context, state);
    }

    bool Durable(const fk_detector_request_v1 &request, uint64_t sequence,
                 std::string *error) {
        NativeFusionDecision decision{};
        decision.kind = request.flags == FK_DETECTOR_REQUEST_FLAG_COVERAGE_OPEN
            ? NativeFusionDecision::Kind::FlowOpen : NativeFusionDecision::Kind::Checkpoint;
        decision.score_present = decision.kind == NativeFusionDecision::Kind::Checkpoint;
        decision.sequence = sequence;
        decision.event_token = 1;
        decision.event_routing_token = request.event_routing_token;
        decision.canonical_key = request.canonical_key;
        decision.flow_first_timestamp_ns = request.flow_first_timestamp_ns;
        decision.logical_connection_id = request.logical_connection_id;
        decision.flow_index = request.flow_index;
        decision.flow_generation = request.flow_generation;
        decision.checkpoint_packet = request.checkpoint_packet;
        decision.source_mask = request.source_mask;
        decision.semantic_timestamp_ns = request.semantic_timestamp_ns;
        decision.physical_enqueue_monotonic_ns = request.physical_timestamp_ns;
        decision.coverage_terminal = request.flags == FK_DETECTOR_REQUEST_FLAG_COVERAGE_TERMINAL;
        if (decision.coverage_terminal)
            decision.coverage_evidence_timestamp_ns = fk_detector_coverage_evidence_ns(&request);
        return source->ObserveDurableDecision(decision, error);
    }
};

bool StopOrdering(const std::shared_ptr<PrefixVersionStore> &versions,
                  uint64_t ordinal, bool ack_first, bool reject_finalize) {
    std::string error;
    Fixture fixture(versions, ordinal);
    REQUIRE(fixture.Publish(20, 5));
    fk_detector_request_v1 opening{}, checkpoint{}, scratch{};
    uint64_t sequence = 0;
    REQUIRE(fixture.source->Peek(&opening, &sequence, &error) == NativeFusionSourceResult::Item);
    REQUIRE(sequence == 1 && fixture.observer->issued_count == 0);
    REQUIRE(fixture.source->Peek(&checkpoint, &sequence, &error) == NativeFusionSourceResult::Item);
    REQUIRE(sequence == 2 && checkpoint.checkpoint_packet == 5);
    REQUIRE(fixture.observer->issued_count == 1 && fixture.observer->issued[0].sequence == 2);
    REQUIRE(std::memcmp(&fixture.observer->issued[0].request, &checkpoint, sizeof(checkpoint)) == 0);
    REQUIRE(fixture.observer->Scored(sequence, true, .25, &error));
    REQUIRE(fixture.Durable(opening, 1, &error));
    REQUIRE(fixture.Durable(checkpoint, 2, &error));
    REQUIRE(fixture.observer->durable_count == 2 && fixture.observer->finalize_count == 0);
    fixture.observer->reject_finalize = reject_finalize;
    if (ack_first) {
        REQUIRE(fixture.source->Ack(2, &error));
        REQUIRE(fixture.observer->finalize_count == 0 && fixture.source->stats().live == 1);
        fixture.Feedback(2, 5, 0, true);
        REQUIRE(fixture.source->Peek(&scratch, &sequence, &error) == NativeFusionSourceResult::Empty);
        const auto result = fixture.source->Peek(&scratch, &sequence, &error);
        REQUIRE(result == (reject_finalize ? NativeFusionSourceResult::Fault : NativeFusionSourceResult::Empty));
    } else {
        fixture.Feedback(2, 5, 0, true);
        REQUIRE(fixture.source->Peek(&scratch, &sequence, &error) == NativeFusionSourceResult::Empty);
        REQUIRE(fixture.observer->finalize_count == 0 && fixture.source->stats().live == 1);
        REQUIRE(fixture.source->Ack(2, &error));
        // Full evidence writer: ACK and Peek remain nonblocking, while the
        // source must retain the exact identity and refuse premature EOF.
        fixture.observer->admission_ready=false;
        for(unsigned i=0;i<10;++i) {
            REQUIRE(fixture.source->Peek(&scratch, &sequence, &error) == NativeFusionSourceResult::Empty);
            REQUIRE(fixture.observer->finalize_count==0 && fixture.source->stats().live==1);
        }
        fixture.observer->admission_ready=true;
        const auto result=fixture.source->Peek(&scratch,&sequence,&error);
        REQUIRE(result==(reject_finalize?NativeFusionSourceResult::Fault:NativeFusionSourceResult::Empty));
    }
    REQUIRE(fixture.observer->finalize_count == 1);
    const auto &final = fixture.observer->finalized[0];
    REQUIRE(final.last_candidate == 2 && final.first == fixture.identity.first);
    REQUIRE(final.logical == fixture.identity.logical);
    REQUIRE(std::memcmp(&final.key, &fixture.identity.key, sizeof(final.key)) == 0);
    REQUIRE(fixture.observer->issued[0].request.checkpoint_packet == 5);
    REQUIRE(versions->Latest(fixture.identity) == 20);
    if (reject_finalize) {
        REQUIRE(error == "injected Finalize failure");
        NativeFusionSourceSnapshot snapshot{};
        REQUIRE(fixture.source->Snapshot(&snapshot, &error) && snapshot.consumer_fault == 1);
        REQUIRE(fixture.source->stats().released == 0 && fixture.source->stats().live == 1);
        REQUIRE(fixture.source->Peek(&scratch, &sequence, &error) == NativeFusionSourceResult::Fault);
        REQUIRE(fixture.observer->finalize_count == 1);
    } else {
        REQUIRE(fixture.source->stats().released == 1 && fixture.source->stats().live == 0);
        fixture.input->done = true;
        REQUIRE(fixture.source->Peek(&scratch, &sequence, &error) == NativeFusionSourceResult::ProducerDone);
        REQUIRE(fixture.source->Peek(&scratch, &sequence, &error) == NativeFusionSourceResult::ProducerDone);
        REQUIRE(fixture.observer->finalize_count == 1);
    }
    const size_t before_close = fixture.trace.count;
    REQUIRE(fixture.source->Close(&error));
    REQUIRE(fixture.trace.calls[before_close] == Call::Finish);
    REQUIRE(fixture.trace.calls[before_close + 1] == Call::Close);
    REQUIRE(fixture.source->Close(&error) == !reject_finalize);
    REQUIRE(fixture.observer->finish_count == 1 && fixture.input->close_count == 1);
    REQUIRE(fixture.observer->finalize_count == 1);
    return true;
}

bool Terminal(const std::shared_ptr<PrefixVersionStore> &versions, uint64_t ordinal,
              bool initial_checkpoint) {
    std::string error;
    Fixture fixture(versions, ordinal);
    REQUIRE(fixture.Publish(7, initial_checkpoint ? 5 : 12));
    fk_detector_request_v1 opening{}, checkpoint{}, terminal{}, scratch{};
    uint64_t sequence = 0;
    REQUIRE(fixture.source->Peek(&opening, &sequence, &error) == NativeFusionSourceResult::Item);
    REQUIRE(fixture.Durable(opening, sequence, &error));
    REQUIRE(fixture.source->Ack(sequence, &error));
    if (initial_checkpoint) {
        REQUIRE(fixture.source->Peek(&checkpoint, &sequence, &error) == NativeFusionSourceResult::Item);
        REQUIRE(sequence == 2 && checkpoint.checkpoint_packet == 5 && checkpoint.flags == 0);
        REQUIRE(fixture.observer->Scored(sequence, true, .2, &error));
        REQUIRE(fixture.Durable(checkpoint, sequence, &error));
        REQUIRE(fixture.source->Ack(sequence, &error));
        fixture.Feedback(sequence, 5, 12, false);
    }
    fixture.input->done = true;
    REQUIRE(fixture.source->Peek(&terminal, &sequence, &error) == NativeFusionSourceResult::Item);
    REQUIRE(terminal.flags == FK_DETECTOR_REQUEST_FLAG_COVERAGE_TERMINAL);
    REQUIRE(terminal.checkpoint_packet == 7 && terminal.features[0] == 7000.f);
    REQUIRE(fk_detector_coverage_evidence_ns(&terminal) == fixture.identity.first + 6);
    PrefixVersionStore::Prefix exact{};
    REQUIRE(versions->Lookup(fixture.identity, terminal.checkpoint_packet, &exact));
    REQUIRE(std::memcmp(terminal.features, exact.evidence.features.data(), sizeof(terminal.features)) == 0);
    REQUIRE(fixture.observer->issued_count == (initial_checkpoint ? 2u : 1u));
    REQUIRE(fixture.observer->Scored(sequence, true, .3, &error));
    REQUIRE(fixture.source->Peek(&scratch, &sequence, &error) == NativeFusionSourceResult::Empty);
    const uint64_t terminal_sequence = initial_checkpoint ? 3 : 2;
    REQUIRE(fixture.Durable(terminal, terminal_sequence, &error));
    REQUIRE(fixture.observer->finalize_count == 0);
    REQUIRE(fixture.source->Ack(terminal_sequence, &error));
    REQUIRE(fixture.observer->finalize_count == 0);
    REQUIRE(fixture.source->Peek(&scratch, &sequence, &error) == NativeFusionSourceResult::ProducerDone);
    REQUIRE(fixture.observer->finalize_count == 1);
    REQUIRE(fixture.observer->finalized[0].last_candidate == terminal_sequence);
    REQUIRE(fixture.observer->scored[fixture.observer->scored_count - 1].sequence == terminal_sequence);
    REQUIRE(fixture.observer->durable[terminal_sequence - 1].coverage_terminal);
    REQUIRE(fixture.source->terminal_records() == 1 && fixture.source->terminal_acked() == 1);
    REQUIRE(fixture.source->Close(&error));
    REQUIRE(fixture.source->Close(&error));
    REQUIRE(fixture.observer->finish_count == 1 && fixture.input->close_count == 1);
    return true;
}

bool CloseFailure(const std::shared_ptr<PrefixVersionStore> &versions,
                  uint64_t ordinal, bool evidence_failure, bool transport_failure) {
    std::string error;
    Fixture fixture(versions, ordinal);
    fixture.observer->reject_finish = evidence_failure;
    fixture.input->reject_close = transport_failure;
    REQUIRE(!fixture.source->Close(&error));
    REQUIRE(error == (evidence_failure ? "injected Finish failure" : "injected transport Close failure"));
    REQUIRE(fixture.trace.count == 2 && fixture.trace.calls[0] == Call::Finish);
    REQUIRE(fixture.trace.calls[1] == Call::Close);
    REQUIRE(fixture.observer->finish_count == 1 && fixture.input->close_count == 1);
    if (evidence_failure) {
        NativeFusionSourceSnapshot snapshot{};
        REQUIRE(fixture.source->Snapshot(&snapshot, &error) && snapshot.consumer_fault == 1);
    }
    REQUIRE(!fixture.source->Close(&error));
    REQUIRE(fixture.observer->finish_count == 1 && fixture.input->close_count == 1);
    return true;
}

bool AdmissionFailure(const std::shared_ptr<PrefixVersionStore> &versions,
                      uint64_t ordinal, bool issued_failure) {
    std::string error;
    Fixture fixture(versions, ordinal);
    REQUIRE(fixture.Publish(5, 5));
    fk_detector_request_v1 request{};
    uint64_t sequence = 0;
    REQUIRE(fixture.source->Peek(&request, &sequence, &error) == NativeFusionSourceResult::Item);
    if (issued_failure) {
        fixture.observer->reject_issued = true;
        REQUIRE(fixture.source->Peek(&request, &sequence, &error) == NativeFusionSourceResult::Fault);
        REQUIRE(error == "injected Issued failure" && fixture.observer->issued_count == 1);
    } else {
        fixture.observer->reject_durable = true;
        REQUIRE(!fixture.Durable(request, sequence, &error));
        REQUIRE(error == "injected Durable failure" && fixture.observer->durable_count == 1);
        REQUIRE(!fixture.source->Ack(sequence, &error));
    }
    NativeFusionSourceSnapshot snapshot{};
    REQUIRE(fixture.source->Snapshot(&snapshot, &error) && snapshot.consumer_fault == 1);
    REQUIRE(fixture.observer->finalize_count == 0);
    REQUIRE(fixture.source->Close(&error));
    return true;
}

}  // namespace

int main() {
    try {
        const std::string name = "/fk_selected_source_hooks_" + std::to_string(getpid());
        auto versions = std::make_shared<PrefixVersionStore>(name, 20260925);
        uint64_t ordinal = 0;
        for (bool reject_finalize : {false, true})
            for (bool ack_first : {false, true})
                if (!StopOrdering(versions, ++ordinal, ack_first, reject_finalize)) return 1;
        for (bool initial_checkpoint : {false, true})
            if (!Terminal(versions, ++ordinal, initial_checkpoint)) return 1;
        for (const auto &failures : {std::pair<bool, bool>{true, false},
                                    {false, true}, {true, true}})
            if (!CloseFailure(versions, ++ordinal, failures.first, failures.second)) return 1;
        for (bool issued_failure : {false, true})
            if (!AdmissionFailure(versions, ++ordinal, issued_failure)) return 1;
        std::puts("PASS: selected source hooks; ACK/STOP order; exact terminal prefix; one finalization; drain-before-close; idempotent close; callback failures");
        std::puts("SCOPE: source lifecycle hooks with explicit fake scoring callbacks; actual/synthetic selection and disk persistence are tested separately");
        return 0;
    } catch (const std::exception &exception) {
        std::fprintf(stderr, "selected source hooks exception: %s\n", exception.what());
        return 1;
    }
}
