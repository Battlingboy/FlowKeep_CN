#include "fk_run_artifact.h"

#include <cerrno>
#include <climits>
#include <cstdint>
#include <cstring>
#include <fcntl.h>
#include <limits>
#include <sstream>
#include <string>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <utility>
#include <vector>

namespace {

constexpr char kPartialSuffix[] = ".partial";

void set_error(std::string *error, const std::string &message) {
    if (error != nullptr)
        *error = message;
}

std::string errno_message(const char *operation, const std::string &path) {
    const int saved_errno = errno;
    std::ostringstream message;
    message << operation << " '" << path << "': "
            << std::strerror(saved_errno);
    return message.str();
}

bool make_partial_path(
        const char *final_path,
        std::string &partial_path,
        std::string *error) {
    if (final_path == nullptr || final_path[0] == '\0') {
        set_error(error, "final output path is null or empty");
        return false;
    }
    const std::size_t length = std::strlen(final_path);
    if (final_path[length - 1u] == '/') {
        set_error(error, "final output path has an empty basename");
        return false;
    }
    if (length > static_cast<std::size_t>(PATH_MAX) -
            sizeof(kPartialSuffix)) {
        set_error(error, "final output path is too long");
        return false;
    }
    partial_path.assign(final_path, length);
    partial_path.append(kPartialSuffix);
    return true;
}

struct PathIdentity {
    bool inode_identity = false;
    dev_t device = 0;
    ino_t inode = 0;
    std::string normalized_path;
};

bool normalized_missing_path(
        const char *path,
        std::string &normalized,
        std::string *error) {
    if (path == nullptr || path[0] == '\0') {
        set_error(error, "cannot normalize a null or empty path");
        return false;
    }
    const std::string original(path);
    const std::size_t slash = original.find_last_of('/');
    const std::string basename = slash == std::string::npos
        ? original
        : original.substr(slash + 1u);
    if (basename.empty()) {
        set_error(error, "output/input path has an empty basename");
        return false;
    }
    const std::string parent = slash == std::string::npos
        ? "."
        : slash == 0u ? "/" : original.substr(0u, slash);
    char resolved_parent[PATH_MAX]{};
    errno = 0;
    if (::realpath(parent.c_str(), resolved_parent) == nullptr) {
        set_error(error, errno_message("realpath failed for parent", parent));
        return false;
    }
    normalized.assign(resolved_parent);
    if (normalized != "/")
        normalized.push_back('/');
    normalized.append(basename);
    return true;
}

bool identify_path(
        const char *path,
        PathIdentity &identity,
        std::string *error) {
    if (path == nullptr || path[0] == '\0') {
        set_error(error, "cannot identify a null or empty path");
        return false;
    }
    struct stat status{};
    errno = 0;
    if (::stat(path, &status) == 0) {
        identity.inode_identity = true;
        identity.device = status.st_dev;
        identity.inode = status.st_ino;
        identity.normalized_path.clear();
        return true;
    }
    const int stat_errno = errno;
    if (stat_errno != ENOENT && stat_errno != ENOTDIR) {
        set_error(error, errno_message("stat failed", path));
        return false;
    }
    struct stat link_status{};
    if (::lstat(path, &link_status) == 0) {
        set_error(error, "path exists but its target cannot be resolved");
        return false;
    }
    identity.inode_identity = false;
    identity.device = 0;
    identity.inode = 0;
    return normalized_missing_path(path, identity.normalized_path, error);
}

bool identities_alias(const PathIdentity &left, const PathIdentity &right) {
    if (left.inode_identity != right.inode_identity)
        return false;
    if (left.inode_identity) {
        return left.device == right.device && left.inode == right.inode;
    }
    return left.normalized_path == right.normalized_path;
}

bool parent_path_for(
        const std::string &path,
        std::string &parent,
        std::string *error) {
    const std::size_t slash = path.find_last_of('/');
    parent = slash == std::string::npos
        ? "."
        : slash == 0u ? "/" : path.substr(0u, slash);
    if (parent.empty()) {
        set_error(error, "cannot determine receipt parent directory");
        return false;
    }
    return true;
}

bool close_after_failed_commit(
        fk_atomic_text_receipt &receipt,
        int first_errno,
        const std::string &first_error,
        std::string *error) {
    if (receipt.file != nullptr)
        (void)std::fclose(receipt.file);
    receipt.file = nullptr;
    receipt.active = false;
    errno = first_errno;
    set_error(error, first_error);
    return false;
}

}  // namespace

bool fk_run_artifact_paths_are_safe(
        const fk_run_artifact_path_set &paths,
        std::string *error) {
    set_error(error, "");
    if (paths.required_final_output_count == 0u ||
        paths.required_final_outputs == nullptr) {
        set_error(error, "at least one required final output is needed");
        return false;
    }
    if (paths.immutable_input_count != 0u &&
        paths.immutable_inputs == nullptr) {
        set_error(error, "immutable input array is null");
        return false;
    }
    if (paths.required_final_output_count >
        std::numeric_limits<std::size_t>::max() / 2u) {
        set_error(error, "too many required final outputs");
        return false;
    }

    struct NamedIdentity {
        std::string path;
        PathIdentity identity;
    };
    std::vector<NamedIdentity> outputs;
    outputs.reserve(paths.required_final_output_count * 2u);
    for (std::size_t index = 0u;
         index < paths.required_final_output_count; ++index) {
        const char *final_path = paths.required_final_outputs[index];
        std::string partial_path;
        if (!make_partial_path(final_path, partial_path, error))
            return false;
        NamedIdentity final_identity{};
        final_identity.path = final_path;
        if (!identify_path(
                final_identity.path.c_str(), final_identity.identity, error)) {
            return false;
        }
        outputs.push_back(std::move(final_identity));
        NamedIdentity partial_identity{};
        partial_identity.path = std::move(partial_path);
        if (!identify_path(
                partial_identity.path.c_str(),
                partial_identity.identity,
                error)) {
            return false;
        }
        outputs.push_back(std::move(partial_identity));
    }

    for (std::size_t left = 0u; left < outputs.size(); ++left) {
        for (std::size_t right = left + 1u;
             right < outputs.size(); ++right) {
            if (identities_alias(
                    outputs[left].identity, outputs[right].identity)) {
                std::ostringstream message;
                message << "output path alias: '" << outputs[left].path
                        << "' and '" << outputs[right].path << "'";
                set_error(error, message.str());
                return false;
            }
        }
    }

    for (std::size_t input_index = 0u;
         input_index < paths.immutable_input_count; ++input_index) {
        const char *input_path = paths.immutable_inputs[input_index];
        if (input_path == nullptr || input_path[0] == '\0')
            continue;
        PathIdentity input_identity{};
        if (!identify_path(input_path, input_identity, error))
            return false;
        for (const NamedIdentity &output : outputs) {
            if (identities_alias(output.identity, input_identity)) {
                std::ostringstream message;
                message << "output path '" << output.path
                        << "' aliases immutable input '" << input_path
                        << "'";
                set_error(error, message.str());
                return false;
            }
        }
    }
    return true;
}

bool fk_atomic_text_receipt_begin(
        const char *final_path,
        fk_atomic_text_receipt *receipt,
        std::string *error) {
    set_error(error, "");
    if (receipt == nullptr) {
        set_error(error, "receipt is null");
        return false;
    }
    if (receipt->active || receipt->file != nullptr) {
        set_error(error, "receipt is already active");
        return false;
    }
    std::string partial_path;
    if (!make_partial_path(final_path, partial_path, error))
        return false;

    errno = 0;
    const int descriptor = ::open(
        partial_path.c_str(),
        O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW,
        0644);
    if (descriptor < 0) {
        set_error(error, errno_message("cannot create receipt partial", partial_path));
        return false;
    }
    FILE *file = ::fdopen(descriptor, "w");
    if (file == nullptr) {
        const int saved_errno = errno;
        (void)::close(descriptor);
        errno = saved_errno;
        set_error(error, errno_message("fdopen failed", partial_path));
        return false;
    }
    receipt->file = file;
    receipt->final_path = final_path;
    receipt->partial_path = std::move(partial_path);
    receipt->active = true;
    return true;
}

FILE *fk_atomic_text_receipt_stream(fk_atomic_text_receipt *receipt) {
    if (receipt == nullptr || !receipt->active)
        return nullptr;
    return receipt->file;
}

bool fk_atomic_text_receipt_commit(
        fk_atomic_text_receipt *receipt,
        std::string *error) {
    set_error(error, "");
    if (receipt == nullptr || !receipt->active || receipt->file == nullptr ||
        receipt->final_path.empty() || receipt->partial_path.empty()) {
        set_error(error, "receipt is not active or has invalid paths");
        return false;
    }

    errno = 0;
    if (std::fflush(receipt->file) != 0) {
        const int saved_errno = errno != 0 ? errno : EIO;
        const std::string message =
            errno_message("receipt fflush failed", receipt->partial_path);
        return close_after_failed_commit(
            *receipt, saved_errno, message, error);
    }
    if (std::ferror(receipt->file) != 0) {
        const int saved_errno = errno != 0 ? errno : EIO;
        errno = saved_errno;
        const std::string message =
            errno_message("receipt stream error", receipt->partial_path);
        return close_after_failed_commit(
            *receipt, saved_errno, message, error);
    }
    const int descriptor = ::fileno(receipt->file);
    if (descriptor < 0) {
        const int saved_errno = errno != 0 ? errno : EBADF;
        errno = saved_errno;
        const std::string message =
            errno_message("receipt fileno failed", receipt->partial_path);
        return close_after_failed_commit(
            *receipt, saved_errno, message, error);
    }
    errno = 0;
    if (::fsync(descriptor) != 0) {
        const int saved_errno = errno != 0 ? errno : EIO;
        const std::string message =
            errno_message("receipt fsync failed", receipt->partial_path);
        return close_after_failed_commit(
            *receipt, saved_errno, message, error);
    }
    errno = 0;
    if (std::fclose(receipt->file) != 0) {
        const int saved_errno = errno != 0 ? errno : EIO;
        receipt->file = nullptr;
        receipt->active = false;
        errno = saved_errno;
        set_error(error, errno_message("receipt fclose failed", receipt->partial_path));
        return false;
    }
    receipt->file = nullptr;
    receipt->active = false;

#if defined(SYS_renameat2)
    constexpr unsigned int kRenameNoReplace = 1u;
    errno = 0;
    if (::syscall(
            SYS_renameat2,
            AT_FDCWD,
            receipt->partial_path.c_str(),
            AT_FDCWD,
            receipt->final_path.c_str(),
            kRenameNoReplace) != 0) {
        set_error(error, errno_message(
            "atomic no-replace publish failed", receipt->final_path));
        return false;
    }
#else
    errno = ENOSYS;
    set_error(error, "renameat2(RENAME_NOREPLACE) is unavailable");
    return false;
#endif

    std::string parent;
    if (!parent_path_for(receipt->final_path, parent, error))
        return false;
    errno = 0;
    const int directory = ::open(
        parent.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (directory < 0) {
        set_error(error, errno_message("cannot open receipt parent", parent));
        return false;
    }
    errno = 0;
    const bool sync_valid = ::fsync(directory) == 0;
    const int sync_errno = errno;
    errno = 0;
    const bool close_valid = ::close(directory) == 0;
    const int close_errno = errno;
    if (!sync_valid) {
        errno = sync_errno != 0 ? sync_errno : EIO;
        set_error(error, errno_message("receipt parent fsync failed", parent));
        return false;
    }
    if (!close_valid) {
        errno = close_errno != 0 ? close_errno : EIO;
        set_error(error, errno_message("receipt parent close failed", parent));
        return false;
    }
    return true;
}

bool fk_atomic_text_receipt_abandon(
        fk_atomic_text_receipt *receipt,
        std::string *error) {
    set_error(error, "");
    if (receipt == nullptr) {
        set_error(error, "receipt is null");
        return false;
    }
    if (!receipt->active && receipt->file == nullptr)
        return true;
    if (!receipt->active || receipt->file == nullptr) {
        set_error(error, "receipt state is inconsistent");
        return false;
    }
    errno = 0;
    const bool closed = std::fclose(receipt->file) == 0;
    const int saved_errno = errno;
    receipt->file = nullptr;
    receipt->active = false;
    if (!closed) {
        errno = saved_errno != 0 ? saved_errno : EIO;
        set_error(error, errno_message("receipt abandon close failed", receipt->partial_path));
        return false;
    }
    return true;
}
