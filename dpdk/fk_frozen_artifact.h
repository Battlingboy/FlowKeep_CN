#ifndef FLOWKEEP_FK_FROZEN_ARTIFACT_H
#define FLOWKEEP_FK_FROZEN_ARTIFACT_H

#include <array>
#include <cstddef>
#include <cstdint>

/*
 * Startup-only, Linux-specific immutable input snapshot.
 *
 * open() reads exactly one regular source file into an anonymous memfd while
 * computing SHA-256.  A successful result has WRITE/GROW/SHRINK/SEAL seals,
 * is rewound to offset zero, and remains addressable through proc_path() until
 * this object is reset or destroyed.  No filesystem output is created.
 *
 * The object is move-only.  Calling open() always discards any older snapshot
 * first; a failed call therefore cannot leave stale input looking valid.
 */
class fk_frozen_artifact final {
public:
    static constexpr std::size_t kSha256Bytes = 32u;
    static constexpr std::size_t kSha256HexChars = 64u;

    fk_frozen_artifact() noexcept;
    ~fk_frozen_artifact();

    fk_frozen_artifact(const fk_frozen_artifact &) = delete;
    fk_frozen_artifact &operator=(const fk_frozen_artifact &) = delete;

    fk_frozen_artifact(fk_frozen_artifact &&other) noexcept;
    fk_frozen_artifact &operator=(fk_frozen_artifact &&other) noexcept;

    /*
     * Freeze source_path.  Diagnostics are optional and always NUL-terminated
     * when error/error_capacity are supplied.  The source must resolve to a
     * regular file, must not exceed maximum_bytes (checked both before and
     * during copying), and must remain unchanged for the duration of the
     * copy.
     */
    bool open(
        const char *source_path,
        char *error = nullptr,
        std::size_t error_capacity = 0u,
        std::uint64_t maximum_bytes = UINT64_MAX) noexcept;

    void reset() noexcept;

    bool valid() const noexcept { return fd_ >= 0; }
    int fd() const noexcept { return fd_; }
    std::uint64_t bytes() const noexcept { return bytes_; }
    const std::array<std::uint8_t, kSha256Bytes> &sha256() const noexcept {
        return sha256_;
    }
    const char *sha256_hex() const noexcept { return sha256_hex_.data(); }
    const char *proc_path() const noexcept { return proc_path_.data(); }

private:
    static constexpr std::size_t kProcPathCapacity = 64u;

    int fd_;
    std::uint64_t bytes_;
    std::array<std::uint8_t, kSha256Bytes> sha256_;
    std::array<char, kSha256HexChars + 1u> sha256_hex_;
    std::array<char, kProcPathCapacity> proc_path_;
};

#endif
