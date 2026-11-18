#include "fk_detector_request_shm_abi.h"

#include <cerrno>
#include <cstddef>
#include <cstring>
#include <fcntl.h>
#include <limits>
#include <new>
#include <pthread.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

#if !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "detector-request SHM ABI requires a little-endian target"
#endif

struct fk_detector_request_shm {
    uint64_t handle_magic;
    int fd;
    uint8_t role;
    uint8_t reserved0[3];
    uint32_t capacity;
    size_t mapping_bytes;
    size_t slots_bytes;
    void *producer_page;
    void *consumer_page;
    void *slots_page;
    fk_detector_request_shm_producer_header_v1 *producer;
    fk_detector_request_shm_consumer_control_v1 *consumer;
    fk_detector_request_shm_slot_v1 *slots;
    uint64_t open_pid;
    uint64_t owner_tid;
    pthread_t owner_pthread;
    uint64_t run_epoch;
    uint64_t producer_pid;
    uint64_t created_mono_ns;
    uint32_t owner_uid;
    uint32_t owner_gid;
    uint64_t consumer_token;
    uint64_t next_peek_sequence;
};

namespace {

constexpr uint64_t kHandleMagic = UINT64_C(0x314c444e484b4646);
constexpr uint8_t kProducerRole = 1u;
constexpr uint8_t kConsumerRole = 2u;
constexpr uint8_t kObserverRole = 3u;

static_assert(__atomic_always_lock_free(sizeof(uint64_t), nullptr),
    "SHM ABI requires lock-free 64-bit atomics");
static_assert(sizeof(fk_detector_request_shm_config_v1) == 32u,
    "SHM config ABI changed");
static_assert(sizeof(fk_detector_request_shm_producer_header_v1) == 256u,
    "SHM producer header ABI changed");
static_assert(sizeof(fk_detector_request_shm_consumer_control_v1) == 256u,
    "SHM consumer control ABI changed");
static_assert(sizeof(fk_detector_request_shm_slot_v1) == 832u,
    "SHM slot ABI changed");
static_assert(offsetof(fk_detector_request_shm_producer_header_v1,
    producer_stop_mono_ns) == 80u, "producer mutable offset changed");
static_assert(offsetof(fk_detector_request_shm_producer_header_v1,
    write_sequence) == 88u, "write-sequence offset changed");
static_assert(offsetof(fk_detector_request_shm_producer_header_v1,
    producer_done) == 128u, "producer-done offset changed");
static_assert(offsetof(fk_detector_request_shm_consumer_control_v1,
    claim_token) == 24u, "claim-token offset changed");
static_assert(offsetof(fk_detector_request_shm_consumer_control_v1,
    read_sequence) == 56u, "read-sequence offset changed");
static_assert(offsetof(fk_detector_request_shm_slot_v1,
    publish_state) == 16u, "slot-state offset changed");
static_assert(offsetof(fk_detector_request_shm_slot_v1, request) == 64u,
    "slot-payload offset changed");
static_assert(sizeof(fk_detector_request_v1) == 768u,
    "request ABI changed");
static_assert(offsetof(fk_detector_request_v1,
    flow_first_timestamp_ns) == 104u,
    "request first timestamp offset changed");
static_assert(offsetof(fk_detector_request_v1, reserved_header) == 124u,
    "request reserved-header offset changed");
static_assert(offsetof(fk_detector_request_v1, features) == 128u,
    "request feature offset changed");
static_assert(sizeof(uid_t) <= sizeof(uint32_t), "uid ABI exceeds uint32");
static_assert(sizeof(gid_t) <= sizeof(uint32_t), "gid ABI exceeds uint32");

uint64_t atomic_load_acquire(const uint64_t *value) {
    return __atomic_load_n(value, __ATOMIC_ACQUIRE);
}

void atomic_store_release(uint64_t *value, uint64_t next) {
    __atomic_store_n(value, next, __ATOMIC_RELEASE);
}

bool atomic_compare_exchange(
        uint64_t *value, uint64_t *expected, uint64_t desired) {
    return __atomic_compare_exchange_n(value, expected, desired, false,
        __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE);
}

bool atomic_add_checked(uint64_t *value, uint64_t addend) {
    uint64_t observed = atomic_load_acquire(value);
    for (;;) {
        if (addend > UINT64_MAX - observed)
            return false;
        uint64_t expected = observed;
        if (atomic_compare_exchange(value, &expected, observed + addend))
            return true;
        observed = expected;
    }
}

bool atomic_sub_checked(uint64_t *value, uint64_t subtrahend) {
    uint64_t observed = atomic_load_acquire(value);
    for (;;) {
        if (subtrahend > observed)
            return false;
        uint64_t expected = observed;
        if (atomic_compare_exchange(
                value, &expected, observed - subtrahend)) {
            return true;
        }
        observed = expected;
    }
}

bool bytes_zero(const void *memory, size_t bytes) {
    if (memory == nullptr)
        return false;
    const auto *input = static_cast<const uint8_t *>(memory);
    uint8_t combined = 0u;
    for (size_t index = 0u; index < bytes; ++index)
        combined = static_cast<uint8_t>(combined | input[index]);
    return combined == 0u;
}

bool power_of_two(uint32_t value) {
    return value != 0u && (value & (value - 1u)) == 0u;
}

bool valid_capacity(uint32_t capacity) {
    return capacity >= FK_DETECTOR_REQUEST_SHM_MIN_CAPACITY &&
        capacity <= FK_DETECTOR_REQUEST_SHM_MAX_CAPACITY &&
        power_of_two(capacity);
}

bool checked_mapping_bytes(
        uint32_t capacity, size_t *mapping_bytes, size_t *slots_bytes) {
    if (!valid_capacity(capacity) || mapping_bytes == nullptr)
        return false;
    const size_t slot_size = sizeof(fk_detector_request_shm_slot_v1);
    if (static_cast<size_t>(capacity) >
            (std::numeric_limits<size_t>::max() -
                FK_DETECTOR_REQUEST_SHM_SLOTS_OFFSET) / slot_size) {
        return false;
    }
    const size_t slots = static_cast<size_t>(capacity) * slot_size;
    *mapping_bytes = FK_DETECTOR_REQUEST_SHM_SLOTS_OFFSET + slots;
    if (slots_bytes != nullptr)
        *slots_bytes = slots;
    return true;
}

bool valid_config(const fk_detector_request_shm_config_v1 *config) {
    size_t ignored = 0u;
    return config != nullptr &&
        config->magic == FK_DETECTOR_REQUEST_SHM_CONFIG_MAGIC &&
        config->run_epoch != 0u &&
        config->abi_version == FK_DETECTOR_REQUEST_SHM_ABI_VERSION &&
        config->config_bytes == FK_DETECTOR_REQUEST_SHM_CONFIG_BYTES &&
        bytes_zero(config->reserved, sizeof(config->reserved)) &&
        checked_mapping_bytes(config->capacity, &ignored, nullptr);
}

bool valid_name(const char *name) {
    if (name == nullptr || name[0] != '/' || name[1] == '\0')
        return false;
    size_t length = 1u;
    for (; name[length] != '\0'; ++length) {
        if (length >= FK_DETECTOR_REQUEST_SHM_MAX_NAME_BYTES)
            return false;
        const unsigned char value =
            static_cast<unsigned char>(name[length]);
        const bool safe = (value >= 'a' && value <= 'z') ||
            (value >= 'A' && value <= 'Z') ||
            (value >= '0' && value <= '9') || value == '_' ||
            value == '-' || value == '.';
        if (!safe)
            return false;
    }
    return length > 1u;
}

bool host_page_size_valid() {
    return ::sysconf(_SC_PAGESIZE) ==
        static_cast<long>(FK_DETECTOR_REQUEST_SHM_PAGE_BYTES);
}

uint64_t current_pid() {
    const pid_t value = ::getpid();
    return value > 0 ? static_cast<uint64_t>(value) : 0u;
}

uint64_t current_tid() {
    const long value = ::syscall(SYS_gettid);
    return value > 0 ? static_cast<uint64_t>(value) : 0u;
}

bool monotonic_now(uint64_t *timestamp_ns) {
    if (timestamp_ns == nullptr)
        return false;
    timespec value{};
    if (::clock_gettime(CLOCK_MONOTONIC, &value) != 0 ||
        value.tv_sec < 0 || value.tv_nsec < 0 ||
        value.tv_nsec >= 1000000000L) {
        return false;
    }
    const uint64_t seconds = static_cast<uint64_t>(value.tv_sec);
    if (seconds > (UINT64_MAX -
            static_cast<uint64_t>(value.tv_nsec)) / UINT64_C(1000000000)) {
        return false;
    }
    *timestamp_ns = seconds * UINT64_C(1000000000) +
        static_cast<uint64_t>(value.tv_nsec);
    return *timestamp_ns != 0u;
}

uint64_t mix_token(uint64_t value) {
    value += UINT64_C(0x9e3779b97f4a7c15);
    value = (value ^ (value >> 30u)) * UINT64_C(0xbf58476d1ce4e5b9);
    value = (value ^ (value >> 27u)) * UINT64_C(0x94d049bb133111eb);
    value ^= value >> 31u;
    if (value == 0u || value == UINT64_MAX)
        value = 1u;
    return value;
}

uint64_t payload_checksum(const fk_detector_request_v1 &request) {
    const auto *bytes = reinterpret_cast<const uint8_t *>(&request);
    uint64_t hash = FK_DETECTOR_REQUEST_SHM_FNV1A_OFFSET;
    for (size_t index = 0u; index < sizeof(request); ++index) {
        hash ^= bytes[index];
        hash *= FK_DETECTOR_REQUEST_SHM_FNV1A_PRIME;
    }
    return hash;
}

uint64_t writing_state(uint64_t sequence) {
    return sequence * 2u - 1u;
}

uint64_t committed_state(uint64_t sequence) {
    return sequence * 2u;
}

bool producer_static_valid(
        const fk_detector_request_shm_producer_header_v1 &header,
        const void *page) {
    size_t expected_bytes = 0u;
    return header.magic == FK_DETECTOR_REQUEST_SHM_PRODUCER_MAGIC &&
        header.abi_version == FK_DETECTOR_REQUEST_SHM_ABI_VERSION &&
        header.header_bytes ==
            FK_DETECTOR_REQUEST_SHM_PRODUCER_HEADER_BYTES &&
        header.request_bytes == FK_DETECTOR_REQUEST_RECORD_BYTES &&
        header.slot_header_bytes ==
            FK_DETECTOR_REQUEST_SHM_SLOT_HEADER_BYTES &&
        header.slot_bytes == FK_DETECTOR_REQUEST_SHM_SLOT_BYTES &&
        valid_capacity(header.capacity) &&
        header.producer_page_bytes == FK_DETECTOR_REQUEST_SHM_PAGE_BYTES &&
        header.consumer_page_bytes == FK_DETECTOR_REQUEST_SHM_PAGE_BYTES &&
        header.slots_offset == FK_DETECTOR_REQUEST_SHM_SLOTS_OFFSET &&
        checked_mapping_bytes(header.capacity, &expected_bytes, nullptr) &&
        header.mapping_bytes == expected_bytes && header.run_epoch != 0u &&
        header.producer_pid != 0u && header.created_mono_ns != 0u &&
        bytes_zero(header.reserved, sizeof(header.reserved)) &&
        page != nullptr && bytes_zero(
            static_cast<const uint8_t *>(page) + sizeof(header),
            FK_DETECTOR_REQUEST_SHM_PAGE_BYTES - sizeof(header));
}

bool consumer_static_valid(
        const fk_detector_request_shm_consumer_control_v1 &control,
        const void *page,
        uint64_t run_epoch) {
    return control.magic == FK_DETECTOR_REQUEST_SHM_CONSUMER_MAGIC &&
        control.abi_version == FK_DETECTOR_REQUEST_SHM_ABI_VERSION &&
        control.control_bytes ==
            FK_DETECTOR_REQUEST_SHM_CONSUMER_CONTROL_BYTES &&
        control.reserved0 == 0u && control.reserved1 == 0u &&
        control.run_epoch == run_epoch &&
        bytes_zero(control.reserved, sizeof(control.reserved)) &&
        page != nullptr && bytes_zero(
            static_cast<const uint8_t *>(page) + sizeof(control),
            FK_DETECTOR_REQUEST_SHM_PAGE_BYTES - sizeof(control));
}

bool file_identity_valid(
        const struct stat &status,
        const fk_detector_request_shm_producer_header_v1 &header) {
    if (!S_ISREG(status.st_mode) || status.st_uid != ::geteuid() ||
        (status.st_mode & 0777u) != FK_DETECTOR_REQUEST_SHM_REQUIRED_MODE ||
        status.st_size < 0 ||
        static_cast<uint64_t>(status.st_size) != header.mapping_bytes) {
        return false;
    }
    return static_cast<uint64_t>(header.owner_uid) ==
            static_cast<uint64_t>(status.st_uid) &&
        static_cast<uint64_t>(header.owner_gid) ==
            static_cast<uint64_t>(status.st_gid);
}

int safe_open_flags(int access) {
    int flags = access;
#ifdef O_CLOEXEC
    flags |= O_CLOEXEC;
#endif
#ifdef O_NOFOLLOW
    flags |= O_NOFOLLOW;
#endif
    return flags;
}

bool handle_basic_valid(const fk_detector_request_shm *transport) {
    return transport != nullptr && transport->handle_magic == kHandleMagic &&
        transport->fd >= 0 && transport->producer_page != nullptr &&
        transport->consumer_page != nullptr &&
        transport->slots_page != nullptr && transport->producer != nullptr &&
        transport->consumer != nullptr && transport->slots != nullptr &&
        transport->open_pid == current_pid() &&
        valid_capacity(transport->capacity);
}

bool handle_static_valid(const fk_detector_request_shm *transport) {
    return handle_basic_valid(transport) &&
        producer_static_valid(*transport->producer,
            transport->producer_page) &&
        consumer_static_valid(*transport->consumer,
            transport->consumer_page, transport->producer->run_epoch) &&
        transport->capacity == transport->producer->capacity &&
        transport->mapping_bytes == transport->producer->mapping_bytes;
}

/*
 * Per-record publish/peek validator.  open, snapshot, finish, ACK and close
 * retain handle_static_valid(), including both complete reserved-page scans.
 * This hot validator instead compares every immutable operational scalar and
 * cached mapping identity without rescanning ~8 KiB of zero padding.  Slot
 * header/state/checksum/request validation remains in read_slot(), and all
 * dynamic identity, sequence and fault checks remain in publish()/peek().
 */
bool handle_operational_valid(const fk_detector_request_shm *transport) {
    if (!handle_basic_valid(transport) ||
        transport->reserved0[0] != 0u || transport->reserved0[1] != 0u ||
        transport->reserved0[2] != 0u || transport->run_epoch == 0u ||
        transport->producer_pid == 0u ||
        transport->created_mono_ns == 0u ||
        transport->producer != transport->producer_page ||
        transport->consumer != transport->consumer_page ||
        transport->slots != transport->slots_page ||
        transport->slots_bytes != static_cast<size_t>(transport->capacity) *
            sizeof(fk_detector_request_shm_slot_v1) ||
        transport->mapping_bytes != FK_DETECTOR_REQUEST_SHM_SLOTS_OFFSET +
            transport->slots_bytes) {
        return false;
    }
    const auto &producer = *transport->producer;
    const auto &consumer = *transport->consumer;
    return producer.magic == FK_DETECTOR_REQUEST_SHM_PRODUCER_MAGIC &&
        producer.abi_version == FK_DETECTOR_REQUEST_SHM_ABI_VERSION &&
        producer.header_bytes ==
            FK_DETECTOR_REQUEST_SHM_PRODUCER_HEADER_BYTES &&
        producer.request_bytes == FK_DETECTOR_REQUEST_RECORD_BYTES &&
        producer.slot_header_bytes ==
            FK_DETECTOR_REQUEST_SHM_SLOT_HEADER_BYTES &&
        producer.slot_bytes == FK_DETECTOR_REQUEST_SHM_SLOT_BYTES &&
        producer.capacity == transport->capacity &&
        producer.producer_page_bytes ==
            FK_DETECTOR_REQUEST_SHM_PAGE_BYTES &&
        producer.consumer_page_bytes ==
            FK_DETECTOR_REQUEST_SHM_PAGE_BYTES &&
        producer.slots_offset == FK_DETECTOR_REQUEST_SHM_SLOTS_OFFSET &&
        producer.mapping_bytes == transport->mapping_bytes &&
        producer.run_epoch == transport->run_epoch &&
        producer.owner_uid == transport->owner_uid &&
        producer.owner_gid == transport->owner_gid &&
        producer.producer_pid == transport->producer_pid &&
        producer.created_mono_ns == transport->created_mono_ns &&
        consumer.magic == FK_DETECTOR_REQUEST_SHM_CONSUMER_MAGIC &&
        consumer.abi_version == FK_DETECTOR_REQUEST_SHM_ABI_VERSION &&
        consumer.control_bytes ==
            FK_DETECTOR_REQUEST_SHM_CONSUMER_CONTROL_BYTES &&
        consumer.reserved0 == 0u && consumer.reserved1 == 0u &&
        consumer.run_epoch == transport->run_epoch;
}

void producer_fail(fk_detector_request_shm_producer_header_v1 &header) {
    atomic_store_release(&header.fail_closed, 1u);
}

bool producer_add_or_fail(
        fk_detector_request_shm_producer_header_v1 &header,
        uint64_t *counter,
        uint64_t amount = 1u) {
    if (atomic_add_checked(counter, amount))
        return true;
    producer_fail(header);
    return false;
}

bool consumer_add_or_fault(
        fk_detector_request_shm_consumer_control_v1 &control,
        uint64_t *counter,
        uint64_t amount = 1u) {
    if (atomic_add_checked(counter, amount))
        return true;
    atomic_store_release(&control.consumer_fault, 1u);
    return false;
}

bool producer_identity_valid(fk_detector_request_shm &transport) {
    return transport.role == kProducerRole &&
        transport.open_pid == current_pid() &&
        ::pthread_equal(transport.owner_pthread, ::pthread_self()) != 0 &&
        transport.producer->producer_pid == current_pid();
}

bool consumer_identity_valid(const fk_detector_request_shm &transport) {
    return transport.role == kConsumerRole &&
        transport.open_pid == current_pid() &&
        ::pthread_equal(transport.owner_pthread, ::pthread_self()) != 0 &&
        transport.consumer_token != 0u &&
        atomic_load_acquire(&transport.consumer->claim_token) ==
            transport.consumer_token;
}

void clear_output(fk_detector_request_v1 *request, uint64_t *sequence) {
    if (request != nullptr)
        std::memset(request, 0, sizeof(*request));
    if (sequence != nullptr)
        *sequence = 0u;
}

enum class SlotRead { Item, NotPublished, Writing, Recycled, Corrupt };

SlotRead read_slot(
        const fk_detector_request_shm &transport,
        uint64_t sequence,
        fk_detector_request_v1 *request) {
    if (sequence == 0u ||
        sequence > FK_DETECTOR_REQUEST_SHM_MAX_SEQUENCE ||
        request == nullptr) {
        return SlotRead::Corrupt;
    }
    const size_t index = static_cast<size_t>((sequence - 1u) &
        (static_cast<uint64_t>(transport.capacity) - 1u));
    const fk_detector_request_shm_slot_v1 &slot = transport.slots[index];
    const uint64_t first = atomic_load_acquire(&slot.publish_state);
    const uint64_t expected = committed_state(sequence);
    if (first != expected) {
        if (first == 0u)
            return SlotRead::NotPublished;
        const bool writing = (first & 1u) != 0u;
        const uint64_t actual = writing ? (first + 1u) / 2u : first / 2u;
        if (actual > sequence)
            return SlotRead::Recycled;
        if (writing && actual == sequence)
            return SlotRead::Writing;
        return SlotRead::NotPublished;
    }

    fk_detector_request_shm_slot_v1 snapshot{};
    std::memcpy(&snapshot, &slot, sizeof(snapshot));
    const uint64_t second = atomic_load_acquire(&slot.publish_state);
    if (first != second || second != expected)
        return (second & 1u) != 0u ? SlotRead::Writing : SlotRead::Recycled;
    if (snapshot.magic != FK_DETECTOR_REQUEST_SHM_SLOT_MAGIC ||
        snapshot.abi_version != FK_DETECTOR_REQUEST_SHM_ABI_VERSION ||
        snapshot.slot_header_bytes !=
            FK_DETECTOR_REQUEST_SHM_SLOT_HEADER_BYTES ||
        snapshot.request_bytes != FK_DETECTOR_REQUEST_RECORD_BYTES ||
        snapshot.reserved0 != 0u || snapshot.publish_state != expected ||
        snapshot.run_epoch != transport.producer->run_epoch ||
        snapshot.slot_index != index || snapshot.reserved1 != 0u ||
        !bytes_zero(snapshot.reserved_header,
            sizeof(snapshot.reserved_header)) ||
        snapshot.payload_checksum != payload_checksum(snapshot.request) ||
        !fk_detector_request_v1_valid(&snapshot.request)) {
        return SlotRead::Corrupt;
    }
    *request = snapshot.request;
    return SlotRead::Item;
}

void copy_producer_snapshot(
        const fk_detector_request_shm_producer_header_v1 &source,
        fk_detector_request_shm_producer_header_v1 &target) {
    std::memset(&target, 0, sizeof(target));
    target.magic = source.magic;
    target.abi_version = source.abi_version;
    target.header_bytes = source.header_bytes;
    target.request_bytes = source.request_bytes;
    target.slot_header_bytes = source.slot_header_bytes;
    target.slot_bytes = source.slot_bytes;
    target.capacity = source.capacity;
    target.producer_page_bytes = source.producer_page_bytes;
    target.consumer_page_bytes = source.consumer_page_bytes;
    target.slots_offset = source.slots_offset;
    target.mapping_bytes = source.mapping_bytes;
    target.run_epoch = source.run_epoch;
    target.owner_uid = source.owner_uid;
    target.owner_gid = source.owner_gid;
    target.producer_pid = source.producer_pid;
    target.created_mono_ns = source.created_mono_ns;
#define FK_COPY_PRODUCER_ATOMIC(name) \
    target.name = atomic_load_acquire(&source.name)
    FK_COPY_PRODUCER_ATOMIC(producer_stop_mono_ns);
    FK_COPY_PRODUCER_ATOMIC(write_sequence);
    FK_COPY_PRODUCER_ATOMIC(publish_attempts);
    FK_COPY_PRODUCER_ATOMIC(published);
    FK_COPY_PRODUCER_ATOMIC(dropped);
    FK_COPY_PRODUCER_ATOMIC(overrun);
    FK_COPY_PRODUCER_ATOMIC(producer_done);
    FK_COPY_PRODUCER_ATOMIC(fail_closed);
    FK_COPY_PRODUCER_ATOMIC(request_validation_failures);
    FK_COPY_PRODUCER_ATOMIC(internal_integrity_failures);
    FK_COPY_PRODUCER_ATOMIC(finish_attempts);
    FK_COPY_PRODUCER_ATOMIC(finish_transitions);
    FK_COPY_PRODUCER_ATOMIC(done_rejections);
    FK_COPY_PRODUCER_ATOMIC(wrong_producer_rejections);
#undef FK_COPY_PRODUCER_ATOMIC
}

void copy_consumer_snapshot(
        const fk_detector_request_shm_consumer_control_v1 &source,
        fk_detector_request_shm_consumer_control_v1 &target) {
    std::memset(&target, 0, sizeof(target));
    target.magic = source.magic;
    target.abi_version = source.abi_version;
    target.control_bytes = source.control_bytes;
    target.reserved0 = source.reserved0;
    target.reserved1 = source.reserved1;
    target.run_epoch = source.run_epoch;
#define FK_COPY_CONSUMER_ATOMIC(name) \
    target.name = atomic_load_acquire(&source.name)
    FK_COPY_CONSUMER_ATOMIC(claim_token);
    FK_COPY_CONSUMER_ATOMIC(consumer_pid);
    FK_COPY_CONSUMER_ATOMIC(consumer_start_mono_ns);
    FK_COPY_CONSUMER_ATOMIC(consumer_stop_mono_ns);
    FK_COPY_CONSUMER_ATOMIC(read_sequence);
    FK_COPY_CONSUMER_ATOMIC(open_count);
    FK_COPY_CONSUMER_ATOMIC(close_count);
    FK_COPY_CONSUMER_ATOMIC(peek_attempts);
    FK_COPY_CONSUMER_ATOMIC(records_peeked);
    FK_COPY_CONSUMER_ATOMIC(ack_attempts);
    FK_COPY_CONSUMER_ATOMIC(records_acked);
    FK_COPY_CONSUMER_ATOMIC(empty_observations);
    FK_COPY_CONSUMER_ATOMIC(done_empty_observations);
    FK_COPY_CONSUMER_ATOMIC(sequence_gaps);
    FK_COPY_CONSUMER_ATOMIC(validation_failures);
    FK_COPY_CONSUMER_ATOMIC(ack_rejections);
    FK_COPY_CONSUMER_ATOMIC(unacked_on_close);
    FK_COPY_CONSUMER_ATOMIC(consumer_fault);
#undef FK_COPY_CONSUMER_ATOMIC
}

bool close_resources(fk_detector_request_shm *transport) {
    bool success = true;
    if (transport->slots_page != nullptr &&
        ::munmap(transport->slots_page, transport->slots_bytes) != 0) {
        success = false;
    }
    if (transport->consumer_page != nullptr &&
        ::munmap(transport->consumer_page,
            FK_DETECTOR_REQUEST_SHM_PAGE_BYTES) != 0) {
        success = false;
    }
    if (transport->producer_page != nullptr &&
        ::munmap(transport->producer_page,
            FK_DETECTOR_REQUEST_SHM_PAGE_BYTES) != 0) {
        success = false;
    }
    if (transport->fd >= 0 && ::close(transport->fd) != 0)
        success = false;
    transport->handle_magic = 0u;
    delete transport;
    return success;
}

void cleanup_partial(
        int fd, void *producer_page, void *consumer_page,
        void *slots_page, size_t slots_bytes) {
    if (slots_page != MAP_FAILED && slots_page != nullptr)
        (void)::munmap(slots_page, slots_bytes);
    if (consumer_page != MAP_FAILED && consumer_page != nullptr)
        (void)::munmap(consumer_page, FK_DETECTOR_REQUEST_SHM_PAGE_BYTES);
    if (producer_page != MAP_FAILED && producer_page != nullptr)
        (void)::munmap(producer_page, FK_DETECTOR_REQUEST_SHM_PAGE_BYTES);
    if (fd >= 0)
        (void)::close(fd);
}

bool open_existing(
        const char *name,
        uint64_t expected_run_epoch,
        uint8_t role,
        fk_detector_request_shm **output) {
    if (output != nullptr)
        *output = nullptr;
    if (output == nullptr || !valid_name(name) ||
        expected_run_epoch == 0u || !host_page_size_valid() ||
        (role != kConsumerRole && role != kObserverRole)) {
        return false;
    }
    const int access = role == kConsumerRole ? O_RDWR : O_RDONLY;
    const int fd = ::shm_open(name, safe_open_flags(access), 0);
    if (fd < 0)
        return false;
    struct stat status{};
    if (::fstat(fd, &status) != 0 || status.st_size <
            static_cast<off_t>(FK_DETECTOR_REQUEST_SHM_SLOTS_OFFSET)) {
        cleanup_partial(fd, nullptr, nullptr, nullptr, 0u);
        return false;
    }
    void *producer_page = ::mmap(nullptr,
        FK_DETECTOR_REQUEST_SHM_PAGE_BYTES, PROT_READ, MAP_SHARED, fd, 0);
    if (producer_page == MAP_FAILED) {
        cleanup_partial(fd, producer_page, nullptr, nullptr, 0u);
        return false;
    }
    auto *producer = static_cast<
        fk_detector_request_shm_producer_header_v1 *>(producer_page);
    if (!producer_static_valid(*producer, producer_page) ||
        producer->run_epoch != expected_run_epoch ||
        !file_identity_valid(status, *producer)) {
        cleanup_partial(fd, producer_page, nullptr, nullptr, 0u);
        return false;
    }
    size_t mapping_bytes = 0u;
    size_t slots_bytes = 0u;
    if (!checked_mapping_bytes(
            producer->capacity, &mapping_bytes, &slots_bytes)) {
        cleanup_partial(fd, producer_page, nullptr, nullptr, 0u);
        return false;
    }
    const int consumer_protection = role == kConsumerRole ?
        (PROT_READ | PROT_WRITE) : PROT_READ;
    void *consumer_page = ::mmap(nullptr,
        FK_DETECTOR_REQUEST_SHM_PAGE_BYTES, consumer_protection,
        MAP_SHARED, fd, FK_DETECTOR_REQUEST_SHM_CONSUMER_OFFSET);
    if (consumer_page == MAP_FAILED) {
        cleanup_partial(fd, producer_page, consumer_page, nullptr, 0u);
        return false;
    }
    auto *consumer = static_cast<
        fk_detector_request_shm_consumer_control_v1 *>(consumer_page);
    if (!consumer_static_valid(
            *consumer, consumer_page, expected_run_epoch)) {
        cleanup_partial(fd, producer_page, consumer_page, nullptr, 0u);
        return false;
    }
    void *slots_page = ::mmap(nullptr, slots_bytes, PROT_READ, MAP_SHARED,
        fd, FK_DETECTOR_REQUEST_SHM_SLOTS_OFFSET);
    if (slots_page == MAP_FAILED) {
        cleanup_partial(
            fd, producer_page, consumer_page, slots_page, slots_bytes);
        return false;
    }
    auto *transport = new (std::nothrow) fk_detector_request_shm{};
    if (transport == nullptr) {
        cleanup_partial(
            fd, producer_page, consumer_page, slots_page, slots_bytes);
        return false;
    }
    transport->handle_magic = kHandleMagic;
    transport->fd = fd;
    transport->role = role;
    transport->capacity = producer->capacity;
    transport->mapping_bytes = mapping_bytes;
    transport->slots_bytes = slots_bytes;
    transport->producer_page = producer_page;
    transport->consumer_page = consumer_page;
    transport->slots_page = slots_page;
    transport->producer = producer;
    transport->consumer = consumer;
    transport->slots = static_cast<fk_detector_request_shm_slot_v1 *>(
        slots_page);
    transport->open_pid = current_pid();
    transport->owner_tid = current_tid();
    transport->owner_pthread = ::pthread_self();
    transport->run_epoch = producer->run_epoch;
    transport->producer_pid = producer->producer_pid;
    transport->created_mono_ns = producer->created_mono_ns;
    transport->owner_uid = producer->owner_uid;
    transport->owner_gid = producer->owner_gid;

    if (role == kConsumerRole) {
        const uint64_t now_pid = current_pid();
        uint64_t now = 0u;
        if (now_pid == 0u || transport->owner_tid == 0u ||
            !monotonic_now(&now)) {
            (void)close_resources(transport);
            return false;
        }
        const uint64_t token = mix_token(expected_run_epoch ^ now ^
            (now_pid << 32u) ^ transport->owner_tid);
        uint64_t expected = 0u;
        if (!atomic_compare_exchange(
                &consumer->claim_token, &expected, token)) {
            (void)close_resources(transport);
            return false;
        }
        transport->consumer_token = token;
        atomic_store_release(&consumer->consumer_pid, now_pid);
        atomic_store_release(&consumer->consumer_start_mono_ns, now);
        atomic_store_release(&consumer->consumer_stop_mono_ns, 0u);
        if (!consumer_add_or_fault(*consumer, &consumer->open_count)) {
            uint64_t claimed = token;
            (void)atomic_compare_exchange(
                &consumer->claim_token, &claimed, 0u);
            (void)close_resources(transport);
            return false;
        }
        const uint64_t read = atomic_load_acquire(&consumer->read_sequence);
        const uint64_t write = atomic_load_acquire(&producer->write_sequence);
        if (read > write || read >= FK_DETECTOR_REQUEST_SHM_MAX_SEQUENCE) {
            atomic_store_release(&consumer->consumer_fault, 1u);
            uint64_t claimed = token;
            (void)atomic_compare_exchange(
                &consumer->claim_token, &claimed, 0u);
            (void)close_resources(transport);
            return false;
        }
        transport->next_peek_sequence = read + 1u;
    }
    *output = transport;
    return true;
}

}  // namespace

extern "C" {

bool fk_detector_request_shm_config_prepare(
        fk_detector_request_shm_config_v1 *config,
        uint64_t run_epoch,
        uint32_t capacity) {
    if (config == nullptr || run_epoch == 0u || !valid_capacity(capacity))
        return false;
    std::memset(config, 0, sizeof(*config));
    config->magic = FK_DETECTOR_REQUEST_SHM_CONFIG_MAGIC;
    config->run_epoch = run_epoch;
    config->capacity = capacity;
    config->abi_version = FK_DETECTOR_REQUEST_SHM_ABI_VERSION;
    config->config_bytes = FK_DETECTOR_REQUEST_SHM_CONFIG_BYTES;
    return true;
}

size_t fk_detector_request_shm_mapping_bytes(
        const fk_detector_request_shm_config_v1 *config) {
    size_t bytes = 0u;
    return valid_config(config) &&
        checked_mapping_bytes(config->capacity, &bytes, nullptr) ? bytes : 0u;
}

bool fk_detector_request_shm_create_producer(
        const char *name,
        const fk_detector_request_shm_config_v1 *config,
        fk_detector_request_shm **output) {
    if (output != nullptr)
        *output = nullptr;
    size_t mapping_bytes = 0u;
    size_t slots_bytes = 0u;
    if (output == nullptr || !valid_name(name) || !valid_config(config) ||
        !host_page_size_valid() ||
        !checked_mapping_bytes(
            config->capacity, &mapping_bytes, &slots_bytes) ||
        mapping_bytes > static_cast<uint64_t>(
            std::numeric_limits<off_t>::max())) {
        return false;
    }
    int create_flags = safe_open_flags(O_RDWR) | O_CREAT | O_EXCL;
    const int fd = ::shm_open(name, create_flags,
        static_cast<mode_t>(FK_DETECTOR_REQUEST_SHM_REQUIRED_MODE));
    if (fd < 0)
        return false;
    void *producer_page = nullptr;
    void *consumer_page = nullptr;
    void *slots_page = nullptr;
    if (::fchmod(fd,
            static_cast<mode_t>(FK_DETECTOR_REQUEST_SHM_REQUIRED_MODE)) != 0 ||
        ::ftruncate(fd, static_cast<off_t>(mapping_bytes)) != 0) {
        cleanup_partial(fd, nullptr, nullptr, nullptr, 0u);
        (void)::shm_unlink(name);
        return false;
    }
    struct stat status{};
    if (::fstat(fd, &status) != 0 || !S_ISREG(status.st_mode) ||
        status.st_uid != ::geteuid() ||
        (status.st_mode & 0777u) != FK_DETECTOR_REQUEST_SHM_REQUIRED_MODE ||
        status.st_size != static_cast<off_t>(mapping_bytes)) {
        cleanup_partial(fd, nullptr, nullptr, nullptr, 0u);
        (void)::shm_unlink(name);
        return false;
    }
    producer_page = ::mmap(nullptr, FK_DETECTOR_REQUEST_SHM_PAGE_BYTES,
        PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    consumer_page = ::mmap(nullptr, FK_DETECTOR_REQUEST_SHM_PAGE_BYTES,
        PROT_READ | PROT_WRITE, MAP_SHARED, fd,
        FK_DETECTOR_REQUEST_SHM_CONSUMER_OFFSET);
    slots_page = ::mmap(nullptr, slots_bytes, PROT_READ | PROT_WRITE,
        MAP_SHARED, fd, FK_DETECTOR_REQUEST_SHM_SLOTS_OFFSET);
    if (producer_page == MAP_FAILED || consumer_page == MAP_FAILED ||
        slots_page == MAP_FAILED) {
        cleanup_partial(
            fd, producer_page, consumer_page, slots_page, slots_bytes);
        (void)::shm_unlink(name);
        return false;
    }
    /*
     * A large audit transport must not pay first-write tmpfs faults on the
     * packet path.  Creation happens before ingress is released, so touch and
     * clear every slot here.  ftruncate already specifies zero contents; the
     * explicit clear is a performance-placement operation, not an ABI change.
     */
    std::memset(slots_page, 0, slots_bytes);
    std::memset(producer_page, 0, FK_DETECTOR_REQUEST_SHM_PAGE_BYTES);
    std::memset(consumer_page, 0, FK_DETECTOR_REQUEST_SHM_PAGE_BYTES);
    auto *producer = static_cast<
        fk_detector_request_shm_producer_header_v1 *>(producer_page);
    auto *consumer = static_cast<
        fk_detector_request_shm_consumer_control_v1 *>(consumer_page);
    uint64_t created = 0u;
    const uint64_t pid = current_pid();
    const uint64_t tid = current_tid();
    if (!monotonic_now(&created) || pid == 0u || tid == 0u) {
        cleanup_partial(
            fd, producer_page, consumer_page, slots_page, slots_bytes);
        (void)::shm_unlink(name);
        return false;
    }
    producer->magic = FK_DETECTOR_REQUEST_SHM_PRODUCER_MAGIC;
    producer->abi_version = FK_DETECTOR_REQUEST_SHM_ABI_VERSION;
    producer->header_bytes = FK_DETECTOR_REQUEST_SHM_PRODUCER_HEADER_BYTES;
    producer->request_bytes = FK_DETECTOR_REQUEST_RECORD_BYTES;
    producer->slot_header_bytes = FK_DETECTOR_REQUEST_SHM_SLOT_HEADER_BYTES;
    producer->slot_bytes = FK_DETECTOR_REQUEST_SHM_SLOT_BYTES;
    producer->capacity = config->capacity;
    producer->producer_page_bytes = FK_DETECTOR_REQUEST_SHM_PAGE_BYTES;
    producer->consumer_page_bytes = FK_DETECTOR_REQUEST_SHM_PAGE_BYTES;
    producer->slots_offset = FK_DETECTOR_REQUEST_SHM_SLOTS_OFFSET;
    producer->mapping_bytes = mapping_bytes;
    producer->run_epoch = config->run_epoch;
    producer->owner_uid = static_cast<uint32_t>(status.st_uid);
    producer->owner_gid = static_cast<uint32_t>(status.st_gid);
    producer->producer_pid = pid;
    producer->created_mono_ns = created;
    consumer->magic = FK_DETECTOR_REQUEST_SHM_CONSUMER_MAGIC;
    consumer->abi_version = FK_DETECTOR_REQUEST_SHM_ABI_VERSION;
    consumer->control_bytes = FK_DETECTOR_REQUEST_SHM_CONSUMER_CONTROL_BYTES;
    consumer->run_epoch = config->run_epoch;
    __atomic_thread_fence(__ATOMIC_RELEASE);

    if (::munmap(consumer_page, FK_DETECTOR_REQUEST_SHM_PAGE_BYTES) != 0) {
        cleanup_partial(fd, producer_page, nullptr, slots_page, slots_bytes);
        (void)::shm_unlink(name);
        return false;
    }
    consumer_page = ::mmap(nullptr, FK_DETECTOR_REQUEST_SHM_PAGE_BYTES,
        PROT_READ, MAP_SHARED, fd, FK_DETECTOR_REQUEST_SHM_CONSUMER_OFFSET);
    if (consumer_page == MAP_FAILED) {
        cleanup_partial(
            fd, producer_page, consumer_page, slots_page, slots_bytes);
        (void)::shm_unlink(name);
        return false;
    }
    consumer = static_cast<
        fk_detector_request_shm_consumer_control_v1 *>(consumer_page);
    auto *transport = new (std::nothrow) fk_detector_request_shm{};
    if (transport == nullptr) {
        cleanup_partial(
            fd, producer_page, consumer_page, slots_page, slots_bytes);
        (void)::shm_unlink(name);
        return false;
    }
    transport->handle_magic = kHandleMagic;
    transport->fd = fd;
    transport->role = kProducerRole;
    transport->capacity = config->capacity;
    transport->mapping_bytes = mapping_bytes;
    transport->slots_bytes = slots_bytes;
    transport->producer_page = producer_page;
    transport->consumer_page = consumer_page;
    transport->slots_page = slots_page;
    transport->producer = producer;
    transport->consumer = consumer;
    transport->slots = static_cast<fk_detector_request_shm_slot_v1 *>(
        slots_page);
    transport->open_pid = pid;
    transport->owner_tid = tid;
    transport->owner_pthread = ::pthread_self();
    transport->run_epoch = producer->run_epoch;
    transport->producer_pid = producer->producer_pid;
    transport->created_mono_ns = producer->created_mono_ns;
    transport->owner_uid = producer->owner_uid;
    transport->owner_gid = producer->owner_gid;
    *output = transport;
    return true;
}

bool fk_detector_request_shm_open_consumer(
        const char *name,
        uint64_t expected_run_epoch,
        fk_detector_request_shm **transport) {
    return open_existing(
        name, expected_run_epoch, kConsumerRole, transport);
}

bool fk_detector_request_shm_open_observer(
        const char *name,
        uint64_t expected_run_epoch,
        fk_detector_request_shm **transport) {
    return open_existing(
        name, expected_run_epoch, kObserverRole, transport);
}

enum fk_detector_request_shm_publish_result
fk_detector_request_shm_publish(
        fk_detector_request_shm *transport,
        const fk_detector_request_v1 *request) {
    if (transport == nullptr || request == nullptr ||
        transport->role != kProducerRole)
        return FK_DETECTOR_REQUEST_SHM_PUBLISH_INVALID_ARGUMENT;
    if (!handle_operational_valid(transport))
        return FK_DETECTOR_REQUEST_SHM_PUBLISH_INTERNAL_FAILURE;
    auto &producer = *transport->producer;
    if (!producer_add_or_fail(producer, &producer.publish_attempts))
        return FK_DETECTOR_REQUEST_SHM_PUBLISH_INTERNAL_FAILURE;
    if (!producer_identity_valid(*transport)) {
        (void)producer_add_or_fail(producer, &producer.dropped);
        (void)producer_add_or_fail(
            producer, &producer.wrong_producer_rejections);
        producer_fail(producer);
        return FK_DETECTOR_REQUEST_SHM_PUBLISH_WRONG_PRODUCER;
    }
    if (atomic_load_acquire(&producer.producer_done) != 0u) {
        (void)producer_add_or_fail(producer, &producer.dropped);
        (void)producer_add_or_fail(producer, &producer.done_rejections);
        producer_fail(producer);
        return FK_DETECTOR_REQUEST_SHM_PUBLISH_PRODUCER_DONE;
    }
    if (atomic_load_acquire(&producer.fail_closed) != 0u) {
        (void)producer_add_or_fail(producer, &producer.dropped);
        return FK_DETECTOR_REQUEST_SHM_PUBLISH_FAULTED;
    }
    if (!fk_detector_request_v1_valid(request)) {
        (void)producer_add_or_fail(producer, &producer.dropped);
        (void)producer_add_or_fail(
            producer, &producer.request_validation_failures);
        producer_fail(producer);
        return FK_DETECTOR_REQUEST_SHM_PUBLISH_REQUEST_REJECTED;
    }
    if (atomic_load_acquire(&transport->consumer->consumer_fault) != 0u) {
        (void)producer_add_or_fail(producer, &producer.dropped);
        (void)producer_add_or_fail(
            producer, &producer.internal_integrity_failures);
        producer_fail(producer);
        return FK_DETECTOR_REQUEST_SHM_PUBLISH_FAULTED;
    }
    const uint64_t write = atomic_load_acquire(&producer.write_sequence);
    const uint64_t published = atomic_load_acquire(&producer.published);
    const uint64_t read =
        atomic_load_acquire(&transport->consumer->read_sequence);
    if (write != published || read > write ||
        write > FK_DETECTOR_REQUEST_SHM_MAX_SEQUENCE ||
        write - read > transport->capacity ||
        write == FK_DETECTOR_REQUEST_SHM_MAX_SEQUENCE) {
        (void)producer_add_or_fail(producer, &producer.dropped);
        (void)producer_add_or_fail(
            producer, &producer.internal_integrity_failures);
        producer_fail(producer);
        return FK_DETECTOR_REQUEST_SHM_PUBLISH_INTERNAL_FAILURE;
    }
    if (write - read == transport->capacity) {
        (void)producer_add_or_fail(producer, &producer.dropped);
        (void)producer_add_or_fail(producer, &producer.overrun);
        producer_fail(producer);
        return FK_DETECTOR_REQUEST_SHM_PUBLISH_OVERFLOW_FAIL_CLOSED;
    }
    const uint64_t sequence = write + 1u;
    const size_t index = static_cast<size_t>((sequence - 1u) &
        (static_cast<uint64_t>(transport->capacity) - 1u));
    auto &slot = transport->slots[index];
    const uint64_t old_state = atomic_load_acquire(&slot.publish_state);
    const uint64_t required_old = sequence <= transport->capacity ? 0u :
        committed_state(sequence - transport->capacity);
    if (old_state != required_old) {
        (void)producer_add_or_fail(producer, &producer.dropped);
        (void)producer_add_or_fail(
            producer, &producer.internal_integrity_failures);
        producer_fail(producer);
        return FK_DETECTOR_REQUEST_SHM_PUBLISH_INTERNAL_FAILURE;
    }
    atomic_store_release(&slot.publish_state, writing_state(sequence));
    slot.magic = FK_DETECTOR_REQUEST_SHM_SLOT_MAGIC;
    slot.abi_version = FK_DETECTOR_REQUEST_SHM_ABI_VERSION;
    slot.slot_header_bytes = FK_DETECTOR_REQUEST_SHM_SLOT_HEADER_BYTES;
    slot.request_bytes = FK_DETECTOR_REQUEST_RECORD_BYTES;
    slot.reserved0 = 0u;
    slot.run_epoch = producer.run_epoch;
    slot.slot_index = static_cast<uint32_t>(index);
    slot.reserved1 = 0u;
    std::memset(slot.reserved_header, 0, sizeof(slot.reserved_header));
    slot.request = *request;
    slot.payload_checksum = payload_checksum(slot.request);
    atomic_store_release(&slot.publish_state, committed_state(sequence));
    atomic_store_release(&producer.published, sequence);
    atomic_store_release(&producer.write_sequence, sequence);
    return FK_DETECTOR_REQUEST_SHM_PUBLISH_COMMITTED;
}

bool fk_detector_request_shm_finish_producer(
        fk_detector_request_shm *transport,
        uint64_t stop_ns) {
    if (transport == nullptr || stop_ns == 0u ||
        transport->role != kProducerRole || !handle_static_valid(transport)) {
        return false;
    }
    auto &producer = *transport->producer;
    if (!producer_add_or_fail(producer, &producer.finish_attempts))
        return false;
    if (!producer_identity_valid(*transport)) {
        (void)producer_add_or_fail(
            producer, &producer.wrong_producer_rejections);
        producer_fail(producer);
        return false;
    }
    const uint64_t done = atomic_load_acquire(&producer.producer_done);
    const uint64_t existing_stop =
        atomic_load_acquire(&producer.producer_stop_mono_ns);
    if (done != 0u) {
        if (existing_stop == stop_ns)
            return true;
        (void)producer_add_or_fail(producer, &producer.done_rejections);
        producer_fail(producer);
        return false;
    }
    if (stop_ns < producer.created_mono_ns || existing_stop != 0u) {
        (void)producer_add_or_fail(producer, &producer.done_rejections);
        producer_fail(producer);
        return false;
    }
    atomic_store_release(&producer.producer_stop_mono_ns, stop_ns);
    if (!producer_add_or_fail(producer, &producer.finish_transitions))
        return false;
    atomic_store_release(&producer.producer_done, 1u);
    return true;
}

enum fk_detector_request_shm_peek_result
fk_detector_request_shm_consumer_peek(
        fk_detector_request_shm *transport,
        fk_detector_request_v1 *request,
        uint64_t *sequence) {
    clear_output(request, sequence);
    if (transport == nullptr || request == nullptr || sequence == nullptr ||
        transport->role != kConsumerRole ||
        !handle_operational_valid(transport)) {
        return FK_DETECTOR_REQUEST_SHM_PEEK_INVALID_ARGUMENT;
    }
    if (!consumer_identity_valid(*transport))
        return FK_DETECTOR_REQUEST_SHM_PEEK_WRONG_CONSUMER;
    auto &control = *transport->consumer;
    if (!consumer_add_or_fault(control, &control.peek_attempts))
        return FK_DETECTOR_REQUEST_SHM_PEEK_CORRUPT;
    if (atomic_load_acquire(&control.consumer_fault) != 0u)
        return FK_DETECTOR_REQUEST_SHM_PEEK_CORRUPT;
    const uint64_t expected = transport->next_peek_sequence;
    const uint64_t write =
        atomic_load_acquire(&transport->producer->write_sequence);
    if (expected > write) {
        if (!consumer_add_or_fault(control, &control.empty_observations))
            return FK_DETECTOR_REQUEST_SHM_PEEK_CORRUPT;
        const uint64_t done =
            atomic_load_acquire(&transport->producer->producer_done);
        const uint64_t confirmed_write =
            atomic_load_acquire(&transport->producer->write_sequence);
        if (done != 0u && expected > confirmed_write) {
            (void)consumer_add_or_fault(
                control, &control.done_empty_observations);
            return FK_DETECTOR_REQUEST_SHM_PEEK_PRODUCER_DONE_EMPTY;
        }
        if (atomic_load_acquire(
                &transport->producer->fail_closed) != 0u) {
            return FK_DETECTOR_REQUEST_SHM_PEEK_FAULTED_EMPTY;
        }
        return FK_DETECTOR_REQUEST_SHM_PEEK_EMPTY;
    }
    const SlotRead result = read_slot(*transport, expected, request);
    if (result != SlotRead::Item) {
        if (result != SlotRead::Writing)
            (void)consumer_add_or_fault(control, &control.sequence_gaps);
        (void)consumer_add_or_fault(control, &control.validation_failures);
        atomic_store_release(&control.consumer_fault, 1u);
        std::memset(request, 0, sizeof(*request));
        return FK_DETECTOR_REQUEST_SHM_PEEK_CORRUPT;
    }
    if (!consumer_add_or_fault(control, &control.records_peeked)) {
        std::memset(request, 0, sizeof(*request));
        return FK_DETECTOR_REQUEST_SHM_PEEK_CORRUPT;
    }
    *sequence = expected;
    transport->next_peek_sequence = expected + 1u;
    return FK_DETECTOR_REQUEST_SHM_PEEK_ITEM;
}

enum fk_detector_request_shm_ack_result
fk_detector_request_shm_consumer_ack(
        fk_detector_request_shm *transport,
        uint64_t sequence) {
    if (transport == nullptr || sequence == 0u ||
        transport->role != kConsumerRole || !handle_static_valid(transport)) {
        return FK_DETECTOR_REQUEST_SHM_ACK_INVALID_ARGUMENT;
    }
    if (!consumer_identity_valid(*transport))
        return FK_DETECTOR_REQUEST_SHM_ACK_WRONG_CONSUMER;
    auto &control = *transport->consumer;
    if (!consumer_add_or_fault(control, &control.ack_attempts))
        return FK_DETECTOR_REQUEST_SHM_ACK_CORRUPT;
    const uint64_t current = atomic_load_acquire(&control.read_sequence);
    const uint64_t last_peeked = transport->next_peek_sequence - 1u;
    if (sequence <= current || sequence > last_peeked ||
        sequence > atomic_load_acquire(
            &transport->producer->write_sequence)) {
        (void)consumer_add_or_fault(control, &control.ack_rejections);
        atomic_store_release(&control.consumer_fault, 1u);
        return FK_DETECTOR_REQUEST_SHM_ACK_OUT_OF_RANGE;
    }
    const size_t index = static_cast<size_t>((sequence - 1u) &
        (static_cast<uint64_t>(transport->capacity) - 1u));
    if (atomic_load_acquire(
            &transport->slots[index].publish_state) !=
            committed_state(sequence)) {
        (void)consumer_add_or_fault(control, &control.ack_rejections);
        atomic_store_release(&control.consumer_fault, 1u);
        return FK_DETECTOR_REQUEST_SHM_ACK_CORRUPT;
    }
    const uint64_t delta = sequence - current;
    if (!consumer_add_or_fault(control, &control.records_acked, delta))
        return FK_DETECTOR_REQUEST_SHM_ACK_CORRUPT;
    uint64_t expected = current;
    if (!atomic_compare_exchange(&control.read_sequence, &expected, sequence)) {
        (void)atomic_sub_checked(&control.records_acked, delta);
        (void)consumer_add_or_fault(control, &control.ack_rejections);
        atomic_store_release(&control.consumer_fault, 1u);
        return FK_DETECTOR_REQUEST_SHM_ACK_CORRUPT;
    }
    return FK_DETECTOR_REQUEST_SHM_ACK_COMMITTED;
}

enum fk_detector_request_shm_observe_result
fk_detector_request_shm_observer_read(
        fk_detector_request_shm *transport,
        uint64_t sequence,
        fk_detector_request_v1 *request) {
    clear_output(request, nullptr);
    if (transport == nullptr || request == nullptr || sequence == 0u ||
        transport->role != kObserverRole || !handle_static_valid(transport)) {
        return FK_DETECTOR_REQUEST_SHM_OBSERVE_INVALID_ARGUMENT;
    }
    const uint64_t write =
        atomic_load_acquire(&transport->producer->write_sequence);
    if (sequence > write) {
        return atomic_load_acquire(&transport->producer->producer_done) != 0u ?
            FK_DETECTOR_REQUEST_SHM_OBSERVE_PRODUCER_DONE_NOT_PUBLISHED :
            FK_DETECTOR_REQUEST_SHM_OBSERVE_NOT_PUBLISHED;
    }
    switch (read_slot(*transport, sequence, request)) {
    case SlotRead::Item:
        return FK_DETECTOR_REQUEST_SHM_OBSERVE_ITEM;
    case SlotRead::NotPublished:
        return FK_DETECTOR_REQUEST_SHM_OBSERVE_NOT_PUBLISHED;
    case SlotRead::Writing:
        return FK_DETECTOR_REQUEST_SHM_OBSERVE_WRITING;
    case SlotRead::Recycled:
        return FK_DETECTOR_REQUEST_SHM_OBSERVE_RECYCLED;
    case SlotRead::Corrupt:
        break;
    }
    std::memset(request, 0, sizeof(*request));
    return FK_DETECTOR_REQUEST_SHM_OBSERVE_CORRUPT;
}

bool fk_detector_request_shm_snapshot(
        const fk_detector_request_shm *transport,
        fk_detector_request_shm_producer_header_v1 *producer,
        fk_detector_request_shm_consumer_control_v1 *consumer) {
    if (producer != nullptr)
        std::memset(producer, 0, sizeof(*producer));
    if (consumer != nullptr)
        std::memset(consumer, 0, sizeof(*consumer));
    if (transport == nullptr || producer == nullptr || consumer == nullptr ||
        !handle_static_valid(transport)) {
        return false;
    }
    copy_producer_snapshot(*transport->producer, *producer);
    copy_consumer_snapshot(*transport->consumer, *consumer);
    return true;
}

bool fk_detector_request_shm_consumer_start_ready(
        const fk_detector_request_shm *transport) {
    if (transport == nullptr || transport->role != kProducerRole)
        return false;
    fk_detector_request_shm_producer_header_v1 producer{};
    fk_detector_request_shm_consumer_control_v1 consumer{};
    if (!fk_detector_request_shm_snapshot(
            transport, &producer, &consumer)) {
        return false;
    }
    return producer.producer_done == 0u &&
        producer.producer_stop_mono_ns == 0u &&
        producer.write_sequence == 0u && producer.publish_attempts == 0u &&
        producer.published == 0u && producer.dropped == 0u &&
        producer.overrun == 0u && producer.fail_closed == 0u &&
        producer.request_validation_failures == 0u &&
        producer.internal_integrity_failures == 0u &&
        producer.finish_attempts == 0u &&
        producer.finish_transitions == 0u &&
        producer.done_rejections == 0u &&
        producer.wrong_producer_rejections == 0u &&
        consumer.claim_token != 0u && consumer.claim_token != UINT64_MAX &&
        consumer.consumer_pid != 0u &&
        consumer.consumer_start_mono_ns >= producer.created_mono_ns &&
        consumer.consumer_stop_mono_ns == 0u &&
        consumer.read_sequence == 0u && consumer.open_count == 1u &&
        consumer.close_count == 0u && consumer.records_peeked == 0u &&
        consumer.ack_attempts == 0u && consumer.records_acked == 0u &&
        consumer.done_empty_observations == 0u &&
        consumer.sequence_gaps == 0u &&
        consumer.validation_failures == 0u &&
        consumer.ack_rejections == 0u &&
        consumer.unacked_on_close == 0u && consumer.consumer_fault == 0u;
}

bool fk_detector_request_shm_formal_ready(
        const fk_detector_request_shm *transport) {
    if (transport == nullptr || transport->role != kProducerRole)
        return false;
    fk_detector_request_shm_producer_header_v1 producer{};
    fk_detector_request_shm_consumer_control_v1 consumer{};
    if (!fk_detector_request_shm_snapshot(
            transport, &producer, &consumer)) {
        return false;
    }
    return producer.producer_done == 1u &&
        producer.producer_stop_mono_ns >= producer.created_mono_ns &&
        producer.fail_closed == 0u &&
        producer.write_sequence == producer.published &&
        producer.publish_attempts == producer.published &&
        producer.dropped == 0u && producer.overrun == 0u &&
        producer.request_validation_failures == 0u &&
        producer.internal_integrity_failures == 0u &&
        producer.finish_transitions == 1u &&
        producer.done_rejections == 0u &&
        producer.wrong_producer_rejections == 0u &&
        consumer.claim_token == 0u && consumer.open_count == 1u &&
        consumer.close_count == 1u && consumer.consumer_pid != 0u &&
        consumer.consumer_start_mono_ns != 0u &&
        consumer.consumer_stop_mono_ns >= consumer.consumer_start_mono_ns &&
        consumer.read_sequence == producer.write_sequence &&
        consumer.records_acked == consumer.read_sequence &&
        consumer.records_peeked == producer.published &&
        consumer.sequence_gaps == 0u &&
        consumer.validation_failures == 0u &&
        consumer.ack_rejections == 0u &&
        consumer.unacked_on_close == 0u && consumer.consumer_fault == 0u;
}

bool fk_detector_request_shm_close_checked(
        fk_detector_request_shm *transport) {
    if (!handle_static_valid(transport))
        return false;
    if (transport->role == kProducerRole) {
        if (transport->open_pid != current_pid() ||
            atomic_load_acquire(&transport->producer->producer_done) == 0u) {
            return false;
        }
    } else if (transport->role == kConsumerRole) {
        if (!consumer_identity_valid(*transport))
            return false;
        auto &control = *transport->consumer;
        const uint64_t read = atomic_load_acquire(&control.read_sequence);
        const uint64_t last_peeked = transport->next_peek_sequence - 1u;
        if (last_peeked > read && !consumer_add_or_fault(
                control, &control.unacked_on_close, last_peeked - read)) {
            return false;
        }
        uint64_t stop = 0u;
        if (!monotonic_now(&stop))
            return false;
        atomic_store_release(&control.consumer_stop_mono_ns, stop);
        if (!consumer_add_or_fault(control, &control.close_count))
            return false;
        uint64_t expected = transport->consumer_token;
        if (!atomic_compare_exchange(&control.claim_token, &expected, 0u)) {
            atomic_store_release(&control.consumer_fault, 1u);
            return false;
        }
    } else if (transport->role != kObserverRole) {
        return false;
    }
    return close_resources(transport);
}

bool fk_detector_request_shm_unlink_checked(
        const char *name,
        uint64_t expected_run_epoch) {
    if (!valid_name(name) || expected_run_epoch == 0u ||
        !host_page_size_valid()) {
        return false;
    }
    const int fd = ::shm_open(name, safe_open_flags(O_RDONLY), 0);
    if (fd < 0)
        return false;
    struct stat status{};
    if (::fstat(fd, &status) != 0 || status.st_size <
            static_cast<off_t>(FK_DETECTOR_REQUEST_SHM_SLOTS_OFFSET)) {
        cleanup_partial(fd, nullptr, nullptr, nullptr, 0u);
        return false;
    }
    void *producer_page = ::mmap(nullptr,
        FK_DETECTOR_REQUEST_SHM_PAGE_BYTES, PROT_READ, MAP_SHARED, fd, 0);
    void *consumer_page = ::mmap(nullptr,
        FK_DETECTOR_REQUEST_SHM_PAGE_BYTES, PROT_READ, MAP_SHARED, fd,
        FK_DETECTOR_REQUEST_SHM_CONSUMER_OFFSET);
    if (producer_page == MAP_FAILED || consumer_page == MAP_FAILED) {
        cleanup_partial(fd, producer_page, consumer_page, nullptr, 0u);
        return false;
    }
    const auto *producer = static_cast<const
        fk_detector_request_shm_producer_header_v1 *>(producer_page);
    const auto *consumer = static_cast<const
        fk_detector_request_shm_consumer_control_v1 *>(consumer_page);
    const bool valid = producer_static_valid(*producer, producer_page) &&
        producer->run_epoch == expected_run_epoch &&
        file_identity_valid(status, *producer) &&
        consumer_static_valid(
            *consumer, consumer_page, expected_run_epoch) &&
        atomic_load_acquire(&producer->producer_done) == 1u &&
        atomic_load_acquire(&consumer->claim_token) == 0u;
    if (!valid) {
        cleanup_partial(fd, producer_page, consumer_page, nullptr, 0u);
        return false;
    }
    const int unlink_result = ::shm_unlink(name);
    cleanup_partial(fd, producer_page, consumer_page, nullptr, 0u);
    return unlink_result == 0;
}

}  // extern "C"
