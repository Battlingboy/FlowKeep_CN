#define _GNU_SOURCE

#include "fk_trace_sidecar.h"

#include <errno.h>
#include <fcntl.h>
#include <openssl/evp.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

static const uint8_t k_magic[8] = {
    'F', 'K', 'T', 'S', 'V', '1', 0, 0,
};

enum {
    k_magic_offset = 0,
    k_version_offset = 8,
    k_header_bytes_offset = 12,
    k_record_bytes_offset = 16,
    k_flags_offset = 20,
    k_packet_count_offset = 24,
    k_pcap_file_bytes_offset = 32,
    k_first_timestamp_offset = 40,
    k_last_timestamp_offset = 48,
    k_pcap_sha256_offset = 56,
    k_records_sha256_offset = 88,
    k_reserved_offset = 120,
    k_reserved_bytes = 8,
};

static void set_error(
        char *error,
        size_t error_capacity,
        const char *format,
        ...) {
    if (error == NULL || error_capacity == 0u)
        return;
    va_list arguments;
    va_start(arguments, format);
    (void)vsnprintf(error, error_capacity, format, arguments);
    va_end(arguments);
}

static uint32_t read_le32(const uint8_t *data) {
    return
        (uint32_t)data[0] |
        ((uint32_t)data[1] << 8u) |
        ((uint32_t)data[2] << 16u) |
        ((uint32_t)data[3] << 24u);
}

static uint64_t read_le64(const uint8_t *data) {
    return
        (uint64_t)data[0] |
        ((uint64_t)data[1] << 8u) |
        ((uint64_t)data[2] << 16u) |
        ((uint64_t)data[3] << 24u) |
        ((uint64_t)data[4] << 32u) |
        ((uint64_t)data[5] << 40u) |
        ((uint64_t)data[6] << 48u) |
        ((uint64_t)data[7] << 56u);
}

static bool sha256_bytes(
        const void *data,
        size_t size,
        uint8_t digest[FK_TRACE_SIDECAR_SHA256_BYTES]) {
    bool ok = false;
    EVP_MD_CTX *context = EVP_MD_CTX_new();
    if (context == NULL)
        return false;
    unsigned int digest_bytes = 0u;
    if (EVP_DigestInit_ex(context, EVP_sha256(), NULL) == 1 &&
        EVP_DigestUpdate(context, data, size) == 1 &&
        EVP_DigestFinal_ex(context, digest, &digest_bytes) == 1 &&
        digest_bytes == FK_TRACE_SIDECAR_SHA256_BYTES)
        ok = true;
    EVP_MD_CTX_free(context);
    return ok;
}

static bool sha256_file(
        int fd,
        uint8_t digest[FK_TRACE_SIDECAR_SHA256_BYTES],
        char *error,
        size_t error_capacity) {
    if (lseek(fd, 0, SEEK_SET) < 0) {
        set_error(error, error_capacity, "cannot seek PCAP: %s",
                  strerror(errno));
        return false;
    }
    EVP_MD_CTX *context = EVP_MD_CTX_new();
    if (context == NULL) {
        set_error(error, error_capacity, "cannot allocate SHA-256 context");
        return false;
    }
    bool ok = EVP_DigestInit_ex(context, EVP_sha256(), NULL) == 1;
    uint8_t buffer[1024u * 1024u];
    while (ok) {
        ssize_t count = read(fd, buffer, sizeof(buffer));
        if (count > 0) {
            ok = EVP_DigestUpdate(
                context, buffer, (size_t)count) == 1;
            continue;
        }
        if (count == 0)
            break;
        if (errno == EINTR)
            continue;
        set_error(error, error_capacity, "cannot read PCAP: %s",
                  strerror(errno));
        ok = false;
    }
    unsigned int digest_bytes = 0u;
    if (ok)
        ok = EVP_DigestFinal_ex(
            context, digest, &digest_bytes) == 1 &&
            digest_bytes == FK_TRACE_SIDECAR_SHA256_BYTES;
    EVP_MD_CTX_free(context);
    if (!ok && error != NULL && error_capacity != 0u &&
        error[0] == '\0')
        set_error(error, error_capacity, "cannot compute PCAP SHA-256");
    return ok;
}

void fk_trace_sidecar_reset(struct fk_trace_sidecar *sidecar) {
    if (sidecar == NULL)
        return;
    memset(sidecar, 0, sizeof(*sidecar));
    sidecar->fd = -1;
}

void fk_trace_sidecar_close(struct fk_trace_sidecar *sidecar) {
    if (sidecar == NULL)
        return;
    if (sidecar->mapping != NULL &&
        sidecar->mapping != MAP_FAILED &&
        sidecar->mapping_bytes != 0u)
        (void)munmap(
            (void *)(uintptr_t)sidecar->mapping,
            sidecar->mapping_bytes);
    if (sidecar->fd >= 0)
        (void)close(sidecar->fd);
    fk_trace_sidecar_reset(sidecar);
}

bool fk_trace_sidecar_open(
        struct fk_trace_sidecar *sidecar,
        const char *path,
        char *error,
        size_t error_capacity) {
    if (error != NULL && error_capacity != 0u)
        error[0] = '\0';
    if (sidecar == NULL || path == NULL || path[0] == '\0') {
        set_error(error, error_capacity, "sidecar path is required");
        return false;
    }
    fk_trace_sidecar_reset(sidecar);
    sidecar->fd = open(path, O_RDONLY | O_CLOEXEC);
    if (sidecar->fd < 0) {
        set_error(error, error_capacity, "cannot open sidecar: %s",
                  strerror(errno));
        return false;
    }
    struct stat status;
    if (fstat(sidecar->fd, &status) != 0 ||
        status.st_size < (off_t)FK_TRACE_SIDECAR_HEADER_BYTES ||
        (uintmax_t)status.st_size > (uintmax_t)SIZE_MAX) {
        set_error(error, error_capacity, "invalid sidecar file size");
        fk_trace_sidecar_close(sidecar);
        return false;
    }
    sidecar->mapping_bytes = (size_t)status.st_size;
    void *mapping = mmap(
        NULL,
        sidecar->mapping_bytes,
        PROT_READ,
        MAP_PRIVATE,
        sidecar->fd,
        0);
    if (mapping == MAP_FAILED) {
        set_error(error, error_capacity, "cannot map sidecar: %s",
                  strerror(errno));
        sidecar->mapping = NULL;
        fk_trace_sidecar_close(sidecar);
        return false;
    }
    sidecar->mapping = mapping;
    const uint8_t *header = sidecar->mapping;
    if (memcmp(
            header + k_magic_offset,
            k_magic,
            sizeof(k_magic)) != 0 ||
        read_le32(header + k_version_offset) !=
            FK_TRACE_SIDECAR_VERSION ||
        read_le32(header + k_header_bytes_offset) !=
            FK_TRACE_SIDECAR_HEADER_BYTES ||
        read_le32(header + k_record_bytes_offset) !=
            FK_TRACE_SIDECAR_RECORD_BYTES) {
        set_error(error, error_capacity, "unsupported FKTSV1 sidecar ABI");
        fk_trace_sidecar_close(sidecar);
        return false;
    }
    sidecar->flags = read_le32(header + k_flags_offset);
    if (sidecar->flags != FK_TRACE_SIDECAR_FLAGS &&
        sidecar->flags != FK_TRACE_SIDECAR_DEVELOPMENT_REPEAT_FLAGS) {
        set_error(error, error_capacity, "unsupported FKTSV1 sidecar flags");
        fk_trace_sidecar_close(sidecar);
        return false;
    }
    for (size_t index = 0u; index < k_reserved_bytes; ++index) {
        if (header[k_reserved_offset + index] != 0u) {
            set_error(
                error, error_capacity,
                "sidecar reserved bytes are nonzero");
            fk_trace_sidecar_close(sidecar);
            return false;
        }
    }
    sidecar->packet_count =
        read_le64(header + k_packet_count_offset);
    sidecar->pcap_file_bytes =
        read_le64(header + k_pcap_file_bytes_offset);
    sidecar->first_timestamp_ns =
        read_le64(header + k_first_timestamp_offset);
    sidecar->last_timestamp_ns =
        read_le64(header + k_last_timestamp_offset);
    memcpy(
        sidecar->pcap_sha256,
        header + k_pcap_sha256_offset,
        FK_TRACE_SIDECAR_SHA256_BYTES);
    memcpy(
        sidecar->records_sha256,
        header + k_records_sha256_offset,
        FK_TRACE_SIDECAR_SHA256_BYTES);

    if (sidecar->packet_count == 0u ||
        sidecar->packet_count >= FK_TRACE_SIDECAR_MAX_PACKETS ||
        sidecar->packet_count >
            (UINT64_MAX - FK_TRACE_SIDECAR_HEADER_BYTES) /
                FK_TRACE_SIDECAR_RECORD_BYTES) {
        set_error(error, error_capacity, "invalid sidecar packet count");
        fk_trace_sidecar_close(sidecar);
        return false;
    }
    const uint64_t expected_bytes =
        FK_TRACE_SIDECAR_HEADER_BYTES +
        sidecar->packet_count * FK_TRACE_SIDECAR_RECORD_BYTES;
    if (expected_bytes != (uint64_t)sidecar->mapping_bytes) {
        set_error(error, error_capacity, "sidecar length/count mismatch");
        fk_trace_sidecar_close(sidecar);
        return false;
    }
    uint8_t observed_digest[FK_TRACE_SIDECAR_SHA256_BYTES];
    const uint8_t *records =
        sidecar->mapping + FK_TRACE_SIDECAR_HEADER_BYTES;
    const size_t record_region_bytes =
        sidecar->mapping_bytes - FK_TRACE_SIDECAR_HEADER_BYTES;
    if (!sha256_bytes(
            records, record_region_bytes, observed_digest) ||
        memcmp(
            observed_digest,
            sidecar->records_sha256,
            sizeof(observed_digest)) != 0) {
        set_error(error, error_capacity, "sidecar record SHA-256 mismatch");
        fk_trace_sidecar_close(sidecar);
        return false;
    }
    uint64_t previous = 0u;
    for (uint64_t sequence = 0u;
         sequence < sidecar->packet_count;
         ++sequence) {
        uint64_t timestamp = read_le64(
            records + sequence * FK_TRACE_SIDECAR_RECORD_BYTES);
        if (sequence != 0u && timestamp < previous) {
            set_error(
                error, error_capacity,
                "sidecar timestamps are not monotonic");
            fk_trace_sidecar_close(sidecar);
            return false;
        }
        previous = timestamp;
    }
    const uint64_t first = read_le64(records);
    const uint64_t last = read_le64(
        records +
        (sidecar->packet_count - 1u) * FK_TRACE_SIDECAR_RECORD_BYTES);
    if (first != sidecar->first_timestamp_ns ||
        last != sidecar->last_timestamp_ns) {
        set_error(error, error_capacity, "sidecar timestamp bounds mismatch");
        fk_trace_sidecar_close(sidecar);
        return false;
    }
    return true;
}

bool fk_trace_sidecar_timestamp(
        const struct fk_trace_sidecar *sidecar,
        uint64_t packet_sequence,
        uint64_t *timestamp_ns) {
    if (sidecar == NULL || timestamp_ns == NULL ||
        sidecar->mapping == NULL ||
        packet_sequence >= sidecar->packet_count)
        return false;
    const uint8_t *record =
        sidecar->mapping +
        FK_TRACE_SIDECAR_HEADER_BYTES +
        packet_sequence * FK_TRACE_SIDECAR_RECORD_BYTES;
    *timestamp_ns = read_le64(record);
    return true;
}

bool fk_trace_sidecar_safe_inclusive_watermark(
        const struct fk_trace_sidecar *sidecar,
        uint64_t ready_prefix_packets,
        bool *available,
        uint64_t *watermark_ns) {
    if (sidecar == NULL || available == NULL || watermark_ns == NULL ||
        sidecar->mapping == NULL ||
        ready_prefix_packets > sidecar->packet_count)
        return false;
    *available = false;
    *watermark_ns = 0u;
    if (ready_prefix_packets == 0u)
        return true;
    uint64_t last_ready = 0u;
    if (!fk_trace_sidecar_timestamp(
            sidecar, ready_prefix_packets - 1u, &last_ready))
        return false;
    if (ready_prefix_packets == sidecar->packet_count) {
        *available = true;
        *watermark_ns = last_ready;
        return true;
    }
    uint64_t first_unready = 0u;
    if (!fk_trace_sidecar_timestamp(
            sidecar, ready_prefix_packets, &first_unready) ||
        first_unready < last_ready)
        return false;
    if (first_unready > last_ready) {
        *available = true;
        *watermark_ns = last_ready;
        return true;
    }
    if (last_ready != 0u) {
        *available = true;
        *watermark_ns = last_ready - 1u;
    }
    return true;
}

bool fk_trace_sidecar_verify_pcap(
        const struct fk_trace_sidecar *sidecar,
        const char *pcap_path,
        char *error,
        size_t error_capacity) {
    if (error != NULL && error_capacity != 0u)
        error[0] = '\0';
    if (sidecar == NULL || sidecar->mapping == NULL ||
        pcap_path == NULL || pcap_path[0] == '\0') {
        set_error(error, error_capacity, "sidecar and PCAP are required");
        return false;
    }
    int fd = open(pcap_path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        set_error(error, error_capacity, "cannot open PCAP: %s",
                  strerror(errno));
        return false;
    }
    struct stat before;
    struct stat after;
    bool ok = fstat(fd, &before) == 0;
    if (!ok) {
        set_error(error, error_capacity, "cannot stat PCAP: %s",
                  strerror(errno));
    } else if (before.st_size < 0 ||
               (uint64_t)before.st_size != sidecar->pcap_file_bytes) {
        set_error(
            error, error_capacity,
            "sidecar PCAP byte length mismatch");
        ok = false;
    }
    uint8_t observed[FK_TRACE_SIDECAR_SHA256_BYTES];
    if (ok)
        ok = sha256_file(fd, observed, error, error_capacity);
    if (ok &&
        memcmp(
            observed,
            sidecar->pcap_sha256,
            sizeof(observed)) != 0) {
        set_error(error, error_capacity, "sidecar PCAP SHA-256 mismatch");
        ok = false;
    }
    if (ok && (fstat(fd, &after) != 0 ||
               before.st_dev != after.st_dev ||
               before.st_ino != after.st_ino ||
               before.st_size != after.st_size ||
               before.st_mtim.tv_sec != after.st_mtim.tv_sec ||
               before.st_mtim.tv_nsec != after.st_mtim.tv_nsec)) {
        set_error(error, error_capacity, "PCAP changed during verification");
        ok = false;
    }
    (void)close(fd);
    return ok;
}

bool fk_trace_sequence_encode_destination_mac(
        uint64_t packet_sequence,
        uint8_t destination_mac[6]) {
    if (destination_mac == NULL ||
        packet_sequence >= FK_TRACE_SIDECAR_MAX_PACKETS)
        return false;
    destination_mac[0] = 0x02u;
    for (unsigned index = 0u; index < 5u; ++index) {
        const unsigned shift = (4u - index) * 8u;
        destination_mac[index + 1u] =
            (uint8_t)(packet_sequence >> shift);
    }
    return true;
}

bool fk_trace_sequence_decode_destination_mac(
        const uint8_t destination_mac[6],
        uint64_t *packet_sequence) {
    if (destination_mac == NULL || packet_sequence == NULL ||
        destination_mac[0] != 0x02u)
        return false;
    uint64_t result = 0u;
    for (unsigned index = 1u; index < 6u; ++index)
        result = (result << 8u) | destination_mac[index];
    *packet_sequence = result;
    return true;
}
