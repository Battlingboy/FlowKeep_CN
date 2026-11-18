#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "fk_frozen_artifact.h"

#include <openssl/evp.h>

#include <cerrno>
#include <cstdarg>
#include <cstdio>
#include <cstring>
#include <fcntl.h>
#include <limits>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

namespace {

constexpr std::size_t kCopyBufferBytes = 64u * 1024u;

class UniqueFd final {
public:
    explicit UniqueFd(int fd = -1) noexcept : fd_(fd) {}
    ~UniqueFd() {
        if (fd_ >= 0)
            (void)::close(fd_);
    }

    UniqueFd(const UniqueFd &) = delete;
    UniqueFd &operator=(const UniqueFd &) = delete;

    int get() const noexcept { return fd_; }
    int release() noexcept {
        const int result = fd_;
        fd_ = -1;
        return result;
    }

private:
    int fd_;
};

void clear_error(char *error, std::size_t capacity) noexcept {
    if (error != nullptr && capacity != 0u)
        error[0] = '\0';
}

void set_error(
        char *error,
        std::size_t capacity,
        const char *format,
        ...) noexcept {
    if (error == nullptr || capacity == 0u)
        return;

    va_list arguments;
    va_start(arguments, format);
    (void)std::vsnprintf(error, capacity, format, arguments);
    va_end(arguments);
    error[capacity - 1u] = '\0';
}

void set_errno_error(
        char *error,
        std::size_t capacity,
        const char *operation,
        int error_number) noexcept {
    set_error(
        error,
        capacity,
        "%s: %s",
        operation,
        std::strerror(error_number));
}

bool same_source_snapshot(
        const struct stat &before,
        const struct stat &after) noexcept {
    return before.st_dev == after.st_dev &&
        before.st_ino == after.st_ino &&
        before.st_mode == after.st_mode &&
        before.st_size == after.st_size &&
        before.st_mtim.tv_sec == after.st_mtim.tv_sec &&
        before.st_mtim.tv_nsec == after.st_mtim.tv_nsec &&
        before.st_ctim.tv_sec == after.st_ctim.tv_sec &&
        before.st_ctim.tv_nsec == after.st_ctim.tv_nsec;
}

bool write_all(
        int fd,
        const std::uint8_t *data,
        std::size_t bytes,
        char *error,
        std::size_t error_capacity) noexcept {
    std::size_t offset = 0u;
    while (offset != bytes) {
        const ssize_t written = ::write(fd, data + offset, bytes - offset);
        if (written > 0) {
            offset += static_cast<std::size_t>(written);
            continue;
        }
        if (written < 0 && errno == EINTR)
            continue;

        const int failure = written == 0 ? EIO : errno;
        set_errno_error(
            error,
            error_capacity,
            "write frozen memfd",
            failure);
        return false;
    }
    return true;
}

void encode_hex(
        const std::array<std::uint8_t, fk_frozen_artifact::kSha256Bytes> &digest,
        std::array<char, fk_frozen_artifact::kSha256HexChars + 1u> *output)
        noexcept {
    static constexpr char kHex[] = "0123456789abcdef";
    for (std::size_t index = 0u; index < digest.size(); ++index) {
        (*output)[index * 2u] = kHex[digest[index] >> 4u];
        (*output)[index * 2u + 1u] = kHex[digest[index] & 0x0fu];
    }
    (*output)[fk_frozen_artifact::kSha256HexChars] = '\0';
}

}  // namespace

fk_frozen_artifact::fk_frozen_artifact() noexcept
    : fd_(-1), bytes_(0u), sha256_{}, sha256_hex_{}, proc_path_{} {}

fk_frozen_artifact::~fk_frozen_artifact() {
    reset();
}

fk_frozen_artifact::fk_frozen_artifact(fk_frozen_artifact &&other) noexcept
    : fd_(other.fd_),
      bytes_(other.bytes_),
      sha256_(other.sha256_),
      sha256_hex_(other.sha256_hex_),
      proc_path_(other.proc_path_) {
    other.fd_ = -1;
    other.bytes_ = 0u;
    other.sha256_.fill(0u);
    other.sha256_hex_.fill('\0');
    other.proc_path_.fill('\0');
}

fk_frozen_artifact &fk_frozen_artifact::operator=(
        fk_frozen_artifact &&other) noexcept {
    if (this == &other)
        return *this;

    reset();
    fd_ = other.fd_;
    bytes_ = other.bytes_;
    sha256_ = other.sha256_;
    sha256_hex_ = other.sha256_hex_;
    proc_path_ = other.proc_path_;

    other.fd_ = -1;
    other.bytes_ = 0u;
    other.sha256_.fill(0u);
    other.sha256_hex_.fill('\0');
    other.proc_path_.fill('\0');
    return *this;
}

void fk_frozen_artifact::reset() noexcept {
    if (fd_ >= 0)
        (void)::close(fd_);
    fd_ = -1;
    bytes_ = 0u;
    sha256_.fill(0u);
    sha256_hex_.fill('\0');
    proc_path_.fill('\0');
}

bool fk_frozen_artifact::open(
        const char *source_path,
        char *error,
        std::size_t error_capacity,
        std::uint64_t maximum_bytes) noexcept {
    reset();
    clear_error(error, error_capacity);

    if (source_path == nullptr || source_path[0] == '\0') {
        set_error(error, error_capacity, "source path is empty");
        return false;
    }

    UniqueFd source(::open(
        source_path,
        O_RDONLY | O_CLOEXEC | O_NONBLOCK | O_NOCTTY));
    if (source.get() < 0) {
        set_errno_error(error, error_capacity, "open source", errno);
        return false;
    }

    struct stat source_before {};
    if (::fstat(source.get(), &source_before) != 0) {
        set_errno_error(error, error_capacity, "stat source", errno);
        return false;
    }
    if (!S_ISREG(source_before.st_mode) || source_before.st_size < 0) {
        set_error(error, error_capacity, "source is not a regular file");
        return false;
    }
    if (static_cast<std::uint64_t>(source_before.st_size) > maximum_bytes) {
        set_error(
            error,
            error_capacity,
            "source exceeds the configured frozen-byte limit");
        return false;
    }

    UniqueFd frozen(::memfd_create(
        "flowkeep-frozen-artifact",
        MFD_CLOEXEC | MFD_ALLOW_SEALING));
    if (frozen.get() < 0) {
        set_errno_error(error, error_capacity, "create frozen memfd", errno);
        return false;
    }

    EVP_MD_CTX *digest_context = EVP_MD_CTX_new();
    if (digest_context == nullptr) {
        set_error(error, error_capacity, "allocate SHA-256 context failed");
        return false;
    }

    bool digest_ok = EVP_DigestInit_ex(
        digest_context, EVP_sha256(), nullptr) == 1;
    if (!digest_ok) {
        EVP_MD_CTX_free(digest_context);
        set_error(error, error_capacity, "initialize SHA-256 failed");
        return false;
    }

    std::array<std::uint8_t, kCopyBufferBytes> buffer{};
    std::uint64_t total = 0u;
    bool copied = true;
    for (;;) {
        const ssize_t count = ::read(source.get(), buffer.data(), buffer.size());
        if (count > 0) {
            const std::size_t chunk = static_cast<std::size_t>(count);
            if (total > maximum_bytes ||
                static_cast<std::uint64_t>(chunk) >
                    maximum_bytes - total) {
                set_error(
                    error,
                    error_capacity,
                    "source grew beyond the configured frozen-byte limit");
                copied = false;
                break;
            }
            if (EVP_DigestUpdate(digest_context, buffer.data(), chunk) != 1) {
                set_error(error, error_capacity, "update SHA-256 failed");
                copied = false;
                break;
            }
            if (!write_all(
                    frozen.get(),
                    buffer.data(),
                    chunk,
                    error,
                    error_capacity)) {
                copied = false;
                break;
            }
            total += chunk;
            continue;
        }
        if (count == 0)
            break;
        if (errno == EINTR)
            continue;

        set_errno_error(error, error_capacity, "read source", errno);
        copied = false;
        break;
    }

    std::array<std::uint8_t, kSha256Bytes> digest{};
    unsigned int digest_bytes = 0u;
    if (copied &&
        (EVP_DigestFinal_ex(
             digest_context, digest.data(), &digest_bytes) != 1 ||
         digest_bytes != digest.size())) {
        set_error(error, error_capacity, "finalize SHA-256 failed");
        copied = false;
    }
    EVP_MD_CTX_free(digest_context);
    if (!copied)
        return false;

    struct stat source_after {};
    if (::fstat(source.get(), &source_after) != 0) {
        set_errno_error(error, error_capacity, "restat source", errno);
        return false;
    }
    if (!same_source_snapshot(source_before, source_after) ||
        total != static_cast<std::uint64_t>(source_before.st_size)) {
        set_error(error, error_capacity, "source changed while being frozen");
        return false;
    }

    struct stat frozen_stat {};
    if (::fstat(frozen.get(), &frozen_stat) != 0) {
        set_errno_error(error, error_capacity, "stat frozen memfd", errno);
        return false;
    }
    if (frozen_stat.st_size < 0 ||
        static_cast<std::uint64_t>(frozen_stat.st_size) != total) {
        set_error(error, error_capacity, "frozen memfd size mismatch");
        return false;
    }

    if (::lseek(frozen.get(), 0, SEEK_SET) != 0) {
        set_errno_error(error, error_capacity, "rewind frozen memfd", errno);
        return false;
    }

    constexpr int kRequiredSeals =
        F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_SEAL;
    if (::fcntl(frozen.get(), F_ADD_SEALS, kRequiredSeals) != 0) {
        set_errno_error(error, error_capacity, "seal frozen memfd", errno);
        return false;
    }
    const int observed_seals = ::fcntl(frozen.get(), F_GET_SEALS);
    if (observed_seals < 0) {
        set_errno_error(error, error_capacity, "verify frozen memfd seals", errno);
        return false;
    }
    if ((observed_seals & kRequiredSeals) != kRequiredSeals) {
        set_error(error, error_capacity, "frozen memfd is not fully sealed");
        return false;
    }

    std::array<char, kProcPathCapacity> proc_path{};
    const int proc_chars = std::snprintf(
        proc_path.data(), proc_path.size(), "/proc/self/fd/%d", frozen.get());
    if (proc_chars < 0 ||
        static_cast<std::size_t>(proc_chars) >= proc_path.size()) {
        set_error(error, error_capacity, "frozen proc path is too long");
        return false;
    }

    fd_ = frozen.release();
    bytes_ = total;
    sha256_ = digest;
    encode_hex(sha256_, &sha256_hex_);
    proc_path_ = proc_path;
    return true;
}
