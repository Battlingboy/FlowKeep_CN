#include "fk_event_student_manifest.h"

#include <openssl/evp.h>

#include <array>
#include <cerrno>
#include <cmath>
#include <cstddef>
#include <cstdio>
#include <cstring>
#include <fcntl.h>
#include <limits>
#include <locale>
#include <new>
#include <sstream>
#include <string>
#include <sys/stat.h>
#include <unistd.h>
#include <vector>

namespace {

constexpr std::size_t kDigestBytes = 32u;
constexpr std::size_t kIoBufferBytes = 64u * 1024u;
constexpr std::size_t kMaximumPathChars = 4096u;
constexpr uint64_t kMaximumParameterFloats = 8u * 1024u * 1024u;
constexpr char kArchitectureContract[] =
    "flowkeep.strict_causal_event_student.v1;continuous=119;input=159;"
    "ja4_fields=10;ja4_tables=2;vocab=4097;normalizer=clamp10;"
    "encoder=linear-ln-gelu-linear-gelu;"
    "identity=embedding-projection-gelu;fusion=linear-ln-gelu;"
    "flow_pool=attention;window_head=linear-gelu-linear;"
    "event_pool=causal_attention;event_head=ln-linear-gelu-linear;"
    "gelu=erf;ln_eps=1e-5";
constexpr char kFormalDeploymentRequires[] =
    "exact online event-time ticks, 30s causal latest-snapshot windows, "
    "and the frozen actor-session association contract";

enum class Field : std::size_t {
    architecture_contract,
    architecture_sha256,
    artifact_path,
    artifact_sha256,
    continuous_features,
    decision_threshold,
    event_hidden,
    feature_schema_path,
    feature_schema_sha256,
    formal_evidence_eligible,
    formal_deployment_requires,
    format,
    format_version,
    header_bytes,
    hidden,
    hot_path_allocation,
    identity_embedding,
    identity_tables,
    identity_vocabulary,
    input_features,
    layer_norm_epsilon,
    locked_test_accessed,
    maximum_flows_per_window,
    parameter_floats,
    parameter_order,
    payload_bytes,
    payload_sha256,
    selection_path,
    selection_sha256,
    source_state_path,
    source_state_sha256,
    training_receipt_path,
    training_receipt_sha256,
    training_run_mode,
    count,
};

constexpr std::array<const char *, static_cast<std::size_t>(Field::count)>
    kFieldNames{{
        "architecture_contract",
        "architecture_sha256",
        "artifact_path",
        "artifact_sha256",
        "continuous_features",
        "decision_threshold",
        "event_hidden",
        "feature_schema_path",
        "feature_schema_sha256",
        "formal_evidence_eligible",
        "formal_deployment_requires",
        "format",
        "format_version",
        "header_bytes",
        "hidden",
        "hot_path_allocation",
        "identity_embedding",
        "identity_tables",
        "identity_vocabulary",
        "input_features",
        "layer_norm_epsilon",
        "locked_test_accessed",
        "maximum_flows_per_window",
        "parameter_floats",
        "parameter_order",
        "payload_bytes",
        "payload_sha256",
        "selection_path",
        "selection_sha256",
        "source_state_path",
        "source_state_sha256",
        "training_receipt_path",
        "training_receipt_sha256",
        "training_run_mode",
    }};

struct ManifestValues {
    std::array<bool, static_cast<std::size_t>(Field::count)> seen{};
    std::string artifact_sha256;
    std::string feature_schema_sha256;
    std::string source_state_sha256;
    std::string architecture_sha256;
    std::string training_receipt_sha256;
    std::string training_run_mode;
    uint64_t format_version = 0u;
    uint64_t input_features = 0u;
    uint64_t maximum_flows_per_window = 0u;
    uint64_t hidden = 0u;
    uint64_t identity_embedding = 0u;
    uint64_t event_hidden = 0u;
    uint64_t payload_bytes = 0u;
    uint64_t parameter_floats = 0u;
    double decision_threshold = 0.0;
    bool formal_evidence_eligible = false;
    uint32_t field_count = 0u;
};

static void set_error(
        char *error,
        std::size_t error_capacity,
        const std::string &message) {
    if (error == nullptr || error_capacity == 0u)
        return;
    std::snprintf(error, error_capacity, "%s", message.c_str());
}

static bool valid_digest(const char *digest) {
    if (digest == nullptr)
        return false;
    for (std::size_t index = 0u;
         index < FK_EVENT_STUDENT_SHA256_CHARS; ++index) {
        const char value = digest[index];
        if (!((value >= '0' && value <= '9') ||
              (value >= 'a' && value <= 'f')))
            return false;
    }
    return digest[FK_EVENT_STUDENT_SHA256_CHARS] == '\0';
}

static bool valid_digest(const std::string &digest) {
    return digest.size() == FK_EVENT_STUDENT_SHA256_CHARS &&
        valid_digest(digest.c_str());
}

static void digest_to_hex(
        const unsigned char digest[kDigestBytes],
        char output[FK_EVENT_STUDENT_SHA256_CHARS + 1u]) {
    constexpr char kAlphabet[] = "0123456789abcdef";
    for (std::size_t index = 0u; index < kDigestBytes; ++index) {
        output[index * 2u] = kAlphabet[digest[index] >> 4u];
        output[index * 2u + 1u] = kAlphabet[digest[index] & 0x0fu];
    }
    output[FK_EVENT_STUDENT_SHA256_CHARS] = '\0';
}

static bool sha256_bytes(
        const unsigned char *bytes,
        std::size_t size,
        char output[FK_EVENT_STUDENT_SHA256_CHARS + 1u]) {
    EVP_MD_CTX *context = EVP_MD_CTX_new();
    if (context == nullptr)
        return false;
    unsigned char digest[kDigestBytes]{};
    unsigned int digest_bytes = 0u;
    const bool ok =
        EVP_DigestInit_ex(context, EVP_sha256(), nullptr) == 1 &&
        EVP_DigestUpdate(context, bytes, size) == 1 &&
        EVP_DigestFinal_ex(context, digest, &digest_bytes) == 1 &&
        digest_bytes == kDigestBytes;
    EVP_MD_CTX_free(context);
    if (ok)
        digest_to_hex(digest, output);
    return ok;
}

static bool hash_bounded_file(
        const char *path,
        const char *label,
        uint64_t maximum_bytes,
        std::vector<unsigned char> *captured,
        char output[FK_EVENT_STUDENT_SHA256_CHARS + 1u],
        uint64_t &observed_bytes,
        std::string &reason) {
    observed_bytes = 0u;
    if (captured != nullptr)
        captured->clear();
    const int descriptor = open(path, O_RDONLY | O_CLOEXEC);
    if (descriptor < 0) {
        reason = std::string("cannot open ") + label + ": " +
            std::strerror(errno);
        return false;
    }
    struct stat before{};
    if (fstat(descriptor, &before) != 0 || !S_ISREG(before.st_mode) ||
        before.st_size <= 0 ||
        static_cast<uint64_t>(before.st_size) > maximum_bytes) {
        close(descriptor);
        reason = std::string(label) + " size/type is invalid";
        return false;
    }
    if (captured != nullptr) {
        try {
            captured->reserve(static_cast<std::size_t>(before.st_size));
        } catch (const std::bad_alloc &) {
            close(descriptor);
            reason = std::string("cannot allocate ") + label + " buffer";
            return false;
        }
    }
    EVP_MD_CTX *context = EVP_MD_CTX_new();
    if (context == nullptr) {
        close(descriptor);
        reason = "cannot allocate SHA-256 context";
        return false;
    }
    bool ok = EVP_DigestInit_ex(context, EVP_sha256(), nullptr) == 1;
    std::array<unsigned char, kIoBufferBytes> buffer{};
    while (ok) {
        const ssize_t count = read(descriptor, buffer.data(), buffer.size());
        if (count > 0) {
            const uint64_t count_u64 = static_cast<uint64_t>(count);
            if (count_u64 > maximum_bytes - observed_bytes) {
                reason = std::string(label) + " exceeds the read bound";
                ok = false;
                break;
            }
            if (EVP_DigestUpdate(
                    context, buffer.data(), static_cast<std::size_t>(count)) != 1) {
                reason = std::string("cannot hash ") + label;
                ok = false;
                break;
            }
            if (captured != nullptr) {
                try {
                    captured->insert(
                        captured->end(), buffer.begin(),
                        buffer.begin() + count);
                } catch (const std::bad_alloc &) {
                    reason = std::string("cannot allocate ") + label + " buffer";
                    ok = false;
                    break;
                }
            }
            observed_bytes += count_u64;
            continue;
        }
        if (count == 0)
            break;
        if (errno == EINTR)
            continue;
        reason = std::string("cannot read ") + label + ": " +
            std::strerror(errno);
        ok = false;
    }
    struct stat after{};
    if (ok && (fstat(descriptor, &after) != 0 ||
               after.st_size != before.st_size ||
               after.st_mtim.tv_sec != before.st_mtim.tv_sec ||
               after.st_mtim.tv_nsec != before.st_mtim.tv_nsec ||
               after.st_ctim.tv_sec != before.st_ctim.tv_sec ||
               after.st_ctim.tv_nsec != before.st_ctim.tv_nsec ||
               observed_bytes != static_cast<uint64_t>(before.st_size))) {
        reason = std::string(label) + " changed while being read";
        ok = false;
    }
    if (close(descriptor) != 0 && ok) {
        reason = std::string("cannot close ") + label + ": " +
            std::strerror(errno);
        ok = false;
    }
    unsigned char digest[kDigestBytes]{};
    unsigned int digest_bytes = 0u;
    if (ok &&
        (EVP_DigestFinal_ex(context, digest, &digest_bytes) != 1 ||
         digest_bytes != kDigestBytes)) {
        reason = std::string("cannot finalize ") + label + " SHA-256";
        ok = false;
    }
    EVP_MD_CTX_free(context);
    if (ok)
        digest_to_hex(digest, output);
    return ok;
}

static bool field_from_name(const std::string &name, Field &field) {
    for (std::size_t index = 0u; index < kFieldNames.size(); ++index) {
        if (name == kFieldNames[index]) {
            field = static_cast<Field>(index);
            return true;
        }
    }
    return false;
}

static bool append_utf8(uint32_t codepoint, std::string &output) {
    if (codepoint <= 0x7fu) {
        output.push_back(static_cast<char>(codepoint));
    } else if (codepoint <= 0x7ffu) {
        output.push_back(static_cast<char>(0xc0u | (codepoint >> 6u)));
        output.push_back(static_cast<char>(0x80u | (codepoint & 0x3fu)));
    } else if (codepoint <= 0xffffu) {
        if (codepoint >= 0xd800u && codepoint <= 0xdfffu)
            return false;
        output.push_back(static_cast<char>(0xe0u | (codepoint >> 12u)));
        output.push_back(static_cast<char>(
            0x80u | ((codepoint >> 6u) & 0x3fu)));
        output.push_back(static_cast<char>(0x80u | (codepoint & 0x3fu)));
    } else if (codepoint <= 0x10ffffu) {
        output.push_back(static_cast<char>(0xf0u | (codepoint >> 18u)));
        output.push_back(static_cast<char>(
            0x80u | ((codepoint >> 12u) & 0x3fu)));
        output.push_back(static_cast<char>(
            0x80u | ((codepoint >> 6u) & 0x3fu)));
        output.push_back(static_cast<char>(0x80u | (codepoint & 0x3fu)));
    } else {
        return false;
    }
    return true;
}

class JsonParser {
public:
    JsonParser(const unsigned char *bytes, std::size_t size)
        : bytes_(bytes), size_(size) {}

    bool parse(ManifestValues &values) {
        skip_whitespace();
        if (!consume('{'))
            return fail("manifest root is not an object");
        skip_whitespace();
        if (consume('}'))
            return fail("manifest object is empty");
        for (;;) {
            std::string name;
            bool plain_ascii = false;
            if (!parse_string(name, plain_ascii) || !plain_ascii)
                return fail("manifest field name is not canonical ASCII");
            Field field = Field::count;
            if (!field_from_name(name, field))
                return fail(std::string("unknown manifest field: ") + name);
            const std::size_t field_index = static_cast<std::size_t>(field);
            if (values.seen[field_index])
                return fail(std::string("duplicate manifest field: ") + name);
            values.seen[field_index] = true;
            ++values.field_count;
            skip_whitespace();
            if (!consume(':'))
                return fail(std::string("missing ':' after field: ") + name);
            skip_whitespace();
            if (!parse_field(field, values)) {
                if (reason_.empty())
                    reason_ = std::string("invalid manifest field: ") + name;
                return false;
            }
            skip_whitespace();
            if (consume('}'))
                break;
            if (!consume(','))
                return fail("manifest object separator is invalid");
            skip_whitespace();
            if (position_ < size_ && bytes_[position_] == '}')
                return fail("manifest has a trailing comma");
        }
        skip_whitespace();
        if (position_ != size_)
            return fail("manifest has trailing non-whitespace data");
        return validate_required(values);
    }

    const std::string &reason() const { return reason_; }

private:
    bool fail(const std::string &reason) {
        if (reason_.empty())
            reason_ = reason;
        return false;
    }

    void skip_whitespace() {
        while (position_ < size_) {
            const unsigned char value = bytes_[position_];
            if (value != ' ' && value != '\t' && value != '\n' && value != '\r')
                break;
            ++position_;
        }
    }

    bool consume(char expected) {
        if (position_ >= size_ || bytes_[position_] !=
                static_cast<unsigned char>(expected))
            return false;
        ++position_;
        return true;
    }

    static int hex_value(unsigned char value) {
        if (value >= '0' && value <= '9')
            return value - '0';
        if (value >= 'a' && value <= 'f')
            return value - 'a' + 10;
        if (value >= 'A' && value <= 'F')
            return value - 'A' + 10;
        return -1;
    }

    bool parse_hex_quad(uint32_t &value) {
        if (size_ - position_ < 4u)
            return false;
        value = 0u;
        for (std::size_t index = 0u; index < 4u; ++index) {
            const int digit = hex_value(bytes_[position_++]);
            if (digit < 0)
                return false;
            value = value * 16u + static_cast<uint32_t>(digit);
        }
        return true;
    }

    bool parse_raw_utf8(unsigned char first, std::string &output) {
        uint32_t codepoint = 0u;
        std::size_t continuation = 0u;
        uint32_t minimum = 0u;
        if (first >= 0xc2u && first <= 0xdfu) {
            codepoint = first & 0x1fu;
            continuation = 1u;
            minimum = 0x80u;
        } else if (first >= 0xe0u && first <= 0xefu) {
            codepoint = first & 0x0fu;
            continuation = 2u;
            minimum = 0x800u;
        } else if (first >= 0xf0u && first <= 0xf4u) {
            codepoint = first & 0x07u;
            continuation = 3u;
            minimum = 0x10000u;
        } else {
            return false;
        }
        if (size_ - position_ < continuation)
            return false;
        for (std::size_t index = 0u; index < continuation; ++index) {
            const unsigned char next = bytes_[position_++];
            if ((next & 0xc0u) != 0x80u)
                return false;
            codepoint = (codepoint << 6u) | (next & 0x3fu);
        }
        if (codepoint < minimum || codepoint > 0x10ffffu ||
            (codepoint >= 0xd800u && codepoint <= 0xdfffu))
            return false;
        return append_utf8(codepoint, output);
    }

    bool parse_string(std::string &output, bool &plain_ascii) {
        output.clear();
        plain_ascii = true;
        if (!consume('"'))
            return false;
        while (position_ < size_) {
            const unsigned char value = bytes_[position_++];
            if (value == '"')
                return true;
            if (value < 0x20u)
                return false;
            if (value >= 0x80u) {
                plain_ascii = false;
                if (!parse_raw_utf8(value, output))
                    return false;
                continue;
            }
            if (value != '\\') {
                output.push_back(static_cast<char>(value));
                continue;
            }
            plain_ascii = false;
            if (position_ >= size_)
                return false;
            const unsigned char escaped = bytes_[position_++];
            switch (escaped) {
            case '"': output.push_back('"'); break;
            case '\\': output.push_back('\\'); break;
            case '/': output.push_back('/'); break;
            case 'b': output.push_back('\b'); break;
            case 'f': output.push_back('\f'); break;
            case 'n': output.push_back('\n'); break;
            case 'r': output.push_back('\r'); break;
            case 't': output.push_back('\t'); break;
            case 'u': {
                uint32_t codepoint = 0u;
                if (!parse_hex_quad(codepoint))
                    return false;
                if (codepoint >= 0xd800u && codepoint <= 0xdbffu) {
                    if (size_ - position_ < 2u ||
                        bytes_[position_] != '\\' ||
                        bytes_[position_ + 1u] != 'u')
                        return false;
                    position_ += 2u;
                    uint32_t low = 0u;
                    if (!parse_hex_quad(low) || low < 0xdc00u || low > 0xdfffu)
                        return false;
                    codepoint = 0x10000u +
                        ((codepoint - 0xd800u) << 10u) + (low - 0xdc00u);
                } else if (codepoint >= 0xdc00u && codepoint <= 0xdfffu) {
                    return false;
                }
                if (!append_utf8(codepoint, output))
                    return false;
                break;
            }
            default:
                return false;
            }
            if (output.size() > FK_EVENT_STUDENT_MANIFEST_MAX_BYTES)
                return false;
        }
        return false;
    }

    bool parse_exact_string(const char *expected) {
        std::string value;
        bool plain_ascii = false;
        return parse_string(value, plain_ascii) && plain_ascii &&
            value == expected;
    }

    bool parse_digest(std::string &output) {
        bool plain_ascii = false;
        return parse_string(output, plain_ascii) && plain_ascii &&
            valid_digest(output);
    }

    bool parse_nonempty_string() {
        std::string value;
        bool plain_ascii = false;
        if (!parse_string(value, plain_ascii) || value.empty() ||
            value.size() > kMaximumPathChars)
            return false;
        for (unsigned char character : value) {
            if (character < 0x20u)
                return false;
        }
        return true;
    }

    bool parse_training_run_mode(std::string &output) {
        bool plain_ascii = false;
        return parse_string(output, plain_ascii) && plain_ascii &&
            (output == "formal" || output == "implementation-smoke");
    }

    bool parse_bool(bool &value) {
        if (size_ - position_ >= 4u &&
            std::memcmp(bytes_ + position_, "true", 4u) == 0) {
            position_ += 4u;
            value = true;
            return true;
        }
        if (size_ - position_ >= 5u &&
            std::memcmp(bytes_ + position_, "false", 5u) == 0) {
            position_ += 5u;
            value = false;
            return true;
        }
        return false;
    }

    bool parse_false() {
        bool value = true;
        return parse_bool(value) && !value;
    }

    bool parse_uint64(uint64_t &value) {
        if (position_ >= size_)
            return false;
        const std::size_t start = position_;
        if (bytes_[position_] == '0') {
            ++position_;
            if (position_ < size_ && bytes_[position_] >= '0' &&
                bytes_[position_] <= '9') {
                position_ = start;
                return false;
            }
            value = 0u;
            return true;
        }
        if (bytes_[position_] < '1' || bytes_[position_] > '9')
            return false;
        value = 0u;
        while (position_ < size_ && bytes_[position_] >= '0' &&
               bytes_[position_] <= '9') {
            const uint64_t digit = bytes_[position_] - '0';
            if (value > (std::numeric_limits<uint64_t>::max() - digit) / 10u) {
                position_ = start;
                return false;
            }
            value = value * 10u + digit;
            ++position_;
        }
        return true;
    }

    bool parse_number(double &value) {
        const std::size_t start = position_;
        if (position_ < size_ && bytes_[position_] == '-')
            ++position_;
        if (position_ >= size_)
            return false;
        if (bytes_[position_] == '0') {
            ++position_;
            if (position_ < size_ && bytes_[position_] >= '0' &&
                bytes_[position_] <= '9') {
                position_ = start;
                return false;
            }
        } else {
            if (bytes_[position_] < '1' || bytes_[position_] > '9') {
                position_ = start;
                return false;
            }
            while (position_ < size_ && bytes_[position_] >= '0' &&
                   bytes_[position_] <= '9')
                ++position_;
        }
        if (position_ < size_ && bytes_[position_] == '.') {
            ++position_;
            const std::size_t fraction = position_;
            while (position_ < size_ && bytes_[position_] >= '0' &&
                   bytes_[position_] <= '9')
                ++position_;
            if (fraction == position_) {
                position_ = start;
                return false;
            }
        }
        if (position_ < size_ &&
            (bytes_[position_] == 'e' || bytes_[position_] == 'E')) {
            ++position_;
            if (position_ < size_ &&
                (bytes_[position_] == '+' || bytes_[position_] == '-'))
                ++position_;
            const std::size_t exponent = position_;
            while (position_ < size_ && bytes_[position_] >= '0' &&
                   bytes_[position_] <= '9')
                ++position_;
            if (exponent == position_) {
                position_ = start;
                return false;
            }
        }
        const std::string token(
            reinterpret_cast<const char *>(bytes_ + start), position_ - start);
        std::istringstream stream(token);
        stream.imbue(std::locale::classic());
        stream >> value;
        if (!stream || stream.peek() != std::char_traits<char>::eof() ||
            !std::isfinite(value)) {
            position_ = start;
            return false;
        }
        return true;
    }

    static std::string expected_parameter_name(std::size_t index) {
        constexpr std::array<const char *, 8u> kPrefix{{
            "feature_mean",
            "feature_scale",
            "encoder.0.weight",
            "encoder.0.bias",
            "encoder.1.weight",
            "encoder.1.bias",
            "encoder.3.weight",
            "encoder.3.bias",
        }};
        constexpr std::array<const char *, 20u> kSuffix{{
            "identity_projection.0.weight",
            "identity_projection.0.bias",
            "feature_fusion.0.weight",
            "feature_fusion.0.bias",
            "feature_fusion.1.weight",
            "feature_fusion.1.bias",
            "flow_attention.weight",
            "flow_attention.bias",
            "window_head.0.weight",
            "window_head.0.bias",
            "window_head.2.weight",
            "window_head.2.bias",
            "event_attention.weight",
            "event_attention.bias",
            "event_head.0.weight",
            "event_head.0.bias",
            "event_head.1.weight",
            "event_head.1.bias",
            "event_head.3.weight",
            "event_head.3.bias",
        }};
        if (index < kPrefix.size())
            return kPrefix[index];
        if (index < kPrefix.size() + 20u) {
            return std::string("identity_embeddings.") +
                std::to_string(index - kPrefix.size()) + ".weight";
        }
        const std::size_t suffix_index = index - kPrefix.size() - 20u;
        return suffix_index < kSuffix.size() ? kSuffix[suffix_index] : "";
    }

    bool parse_parameter_order() {
        constexpr std::size_t kParameterTensors = 48u;
        if (!consume('['))
            return false;
        skip_whitespace();
        for (std::size_t index = 0u; index < kParameterTensors; ++index) {
            if (index != 0u) {
                if (!consume(','))
                    return false;
                skip_whitespace();
            }
            std::string name;
            bool plain_ascii = false;
            if (!parse_string(name, plain_ascii) || !plain_ascii ||
                name != expected_parameter_name(index))
                return false;
            skip_whitespace();
        }
        return consume(']');
    }

    bool parse_field(Field field, ManifestValues &values) {
        uint64_t integer = 0u;
        double number = 0.0;
        switch (field) {
        case Field::architecture_contract:
            return parse_exact_string(kArchitectureContract);
        case Field::architecture_sha256:
            return parse_digest(values.architecture_sha256);
        case Field::artifact_path:
        case Field::feature_schema_path:
        case Field::selection_path:
        case Field::source_state_path:
        case Field::training_receipt_path:
            return parse_nonempty_string();
        case Field::artifact_sha256:
            return parse_digest(values.artifact_sha256);
        case Field::continuous_features:
            return parse_uint64(integer) &&
                integer == FK_EVENT_STUDENT_CONTINUOUS_FEATURES;
        case Field::decision_threshold:
            if (!parse_number(number) || number < 0.0 || number > 1.0)
                return false;
            values.decision_threshold = number;
            return true;
        case Field::event_hidden:
            if (!parse_uint64(integer) || integer == 0u ||
                integer > FK_EVENT_STUDENT_MAX_HIDDEN / 2u)
                return false;
            values.event_hidden = integer;
            return true;
        case Field::feature_schema_sha256:
            return parse_digest(values.feature_schema_sha256);
        case Field::formal_evidence_eligible:
            return parse_bool(values.formal_evidence_eligible);
        case Field::formal_deployment_requires:
            return parse_exact_string(kFormalDeploymentRequires);
        case Field::format:
            return parse_exact_string("FKESV1");
        case Field::format_version:
            if (!parse_uint64(integer) ||
                integer != FK_EVENT_STUDENT_FORMAT_VERSION)
                return false;
            values.format_version = integer;
            return true;
        case Field::header_bytes:
            return parse_uint64(integer) && integer == 256u;
        case Field::hidden:
            if (!parse_uint64(integer) || integer == 0u ||
                integer > FK_EVENT_STUDENT_MAX_HIDDEN)
                return false;
            values.hidden = integer;
            return true;
        case Field::hot_path_allocation:
        case Field::locked_test_accessed:
            return parse_false();
        case Field::identity_embedding:
            if (!parse_uint64(integer) || integer == 0u ||
                integer > FK_EVENT_STUDENT_MAX_IDENTITY_EMBEDDING)
                return false;
            values.identity_embedding = integer;
            return true;
        case Field::identity_tables:
            return parse_uint64(integer) &&
                integer == FK_EVENT_STUDENT_JA4_FIELDS *
                    FK_EVENT_STUDENT_JA4_TABLES;
        case Field::identity_vocabulary:
            return parse_uint64(integer) &&
                integer == FK_EVENT_STUDENT_JA4_VOCABULARY;
        case Field::input_features:
            if (!parse_uint64(integer) ||
                integer != FK_EVENT_STUDENT_INPUT_FEATURES)
                return false;
            values.input_features = integer;
            return true;
        case Field::layer_norm_epsilon:
            return parse_number(number) && number == 1.0e-5;
        case Field::maximum_flows_per_window:
            if (!parse_uint64(integer) ||
                integer != FK_EVENT_STUDENT_MAX_FLOWS_PER_WINDOW)
                return false;
            values.maximum_flows_per_window = integer;
            return true;
        case Field::parameter_floats:
            if (!parse_uint64(integer) || integer == 0u ||
                integer > kMaximumParameterFloats)
                return false;
            values.parameter_floats = integer;
            return true;
        case Field::parameter_order:
            return parse_parameter_order();
        case Field::payload_bytes:
            if (!parse_uint64(integer) || integer == 0u ||
                integer > FK_EVENT_STUDENT_MANIFEST_MAX_ARTIFACT_BYTES - 256u)
                return false;
            values.payload_bytes = integer;
            return true;
        case Field::payload_sha256: {
            std::string digest;
            return parse_digest(digest);
        }
        case Field::selection_sha256: {
            std::string digest;
            return parse_digest(digest);
        }
        case Field::source_state_sha256:
            return parse_digest(values.source_state_sha256);
        case Field::training_receipt_sha256:
            return parse_digest(values.training_receipt_sha256);
        case Field::training_run_mode:
            return parse_training_run_mode(values.training_run_mode);
        case Field::count:
            return false;
        }
        return false;
    }

    bool validate_required(const ManifestValues &values) {
        constexpr std::array<Field, 15u> kRequired{{
            Field::artifact_sha256,
            Field::decision_threshold,
            Field::feature_schema_sha256,
            Field::formal_evidence_eligible,
            Field::format,
            Field::format_version,
            Field::hidden,
            Field::identity_embedding,
            Field::input_features,
            Field::locked_test_accessed,
            Field::maximum_flows_per_window,
            Field::source_state_sha256,
            Field::training_receipt_path,
            Field::training_receipt_sha256,
            Field::training_run_mode,
        }};
        for (Field field : kRequired) {
            const std::size_t index = static_cast<std::size_t>(field);
            if (!values.seen[index])
                return fail(std::string("missing manifest field: ") +
                    kFieldNames[index]);
        }
        const auto seen = [&values](Field field) {
            return values.seen[static_cast<std::size_t>(field)];
        };
        if (seen(Field::event_hidden) &&
            values.event_hidden != values.hidden / 2u)
            return fail("event_hidden does not match hidden/2");
        if (seen(Field::payload_bytes) && seen(Field::parameter_floats) &&
            (values.parameter_floats >
                 std::numeric_limits<uint64_t>::max() / 4u ||
             values.payload_bytes != values.parameter_floats * 4u))
            return fail("payload_bytes does not match parameter_floats");
        if (seen(Field::architecture_sha256)) {
            char expected[FK_EVENT_STUDENT_SHA256_CHARS + 1u]{};
            if (!sha256_bytes(
                    reinterpret_cast<const unsigned char *>(kArchitectureContract),
                    sizeof(kArchitectureContract) - 1u, expected) ||
                values.architecture_sha256 != expected)
                return fail("architecture_sha256 is not canonical");
        }
        if (values.formal_evidence_eligible !=
            (values.training_run_mode == "formal"))
            return fail(
                "training run mode/formal eligibility is inconsistent");
        return true;
    }

    const unsigned char *bytes_;
    std::size_t size_;
    std::size_t position_ = 0u;
    std::string reason_;
};

static bool path_present(const char *path) {
    return path != nullptr && path[0] != '\0';
}

static void copy_digest(
        const std::string &source,
        char destination[FK_EVENT_STUDENT_SHA256_CHARS + 1u]) {
    std::memcpy(destination, source.data(), FK_EVENT_STUDENT_SHA256_CHARS);
    destination[FK_EVENT_STUDENT_SHA256_CHARS] = '\0';
}

}  // namespace

extern "C" {

bool fk_event_student_manifest_validate(
        const fk_event_student_manifest_request *request,
        fk_event_student_manifest_receipt *receipt,
        char *error,
        std::size_t error_capacity) {
    if (error != nullptr && error_capacity != 0u)
        error[0] = '\0';
    if (receipt == nullptr) {
        set_error(error, error_capacity, "manifest receipt is required");
        return false;
    }
    std::memset(receipt, 0, sizeof(*receipt));
    if (request == nullptr || !path_present(request->artifact_path) ||
        !path_present(request->manifest_path) ||
        !path_present(request->feature_schema_path)) {
        set_error(error, error_capacity, "all deployment paths are required");
        return false;
    }
    if (!valid_digest(request->expected_manifest_sha256)) {
        set_error(error, error_capacity,
            "expected manifest SHA-256 must be lowercase 64-hex");
        return false;
    }

    std::vector<unsigned char> manifest;
    char manifest_sha256[FK_EVENT_STUDENT_SHA256_CHARS + 1u]{};
    uint64_t manifest_bytes = 0u;
    std::string reason;
    if (!hash_bounded_file(
            request->manifest_path, "manifest",
            FK_EVENT_STUDENT_MANIFEST_MAX_BYTES, &manifest,
            manifest_sha256, manifest_bytes, reason)) {
        set_error(error, error_capacity, reason);
        return false;
    }
    if (std::memcmp(manifest_sha256, request->expected_manifest_sha256,
                    FK_EVENT_STUDENT_SHA256_CHARS + 1u) != 0) {
        set_error(error, error_capacity, "manifest SHA-256 mismatch");
        return false;
    }

    ManifestValues values;
    JsonParser parser(manifest.data(), manifest.size());
    if (!parser.parse(values)) {
        set_error(error, error_capacity, parser.reason());
        return false;
    }
    if (request->require_formal_eligible &&
        !values.formal_evidence_eligible) {
        set_error(
            error,
            error_capacity,
            "formal deployment requires a formal-evidence-eligible manifest");
        return false;
    }

    char artifact_sha256[FK_EVENT_STUDENT_SHA256_CHARS + 1u]{};
    uint64_t artifact_bytes = 0u;
    if (!hash_bounded_file(
            request->artifact_path, "artifact",
            FK_EVENT_STUDENT_MANIFEST_MAX_ARTIFACT_BYTES, nullptr,
            artifact_sha256, artifact_bytes, reason)) {
        set_error(error, error_capacity, reason);
        return false;
    }
    if (values.artifact_sha256 != artifact_sha256) {
        set_error(error, error_capacity, "artifact SHA-256 mismatch");
        return false;
    }

    char schema_sha256[FK_EVENT_STUDENT_SHA256_CHARS + 1u]{};
    uint64_t schema_bytes = 0u;
    if (!hash_bounded_file(
            request->feature_schema_path, "feature schema",
            FK_EVENT_STUDENT_MANIFEST_MAX_FEATURE_SCHEMA_BYTES, nullptr,
            schema_sha256, schema_bytes, reason)) {
        set_error(error, error_capacity, reason);
        return false;
    }
    if (values.feature_schema_sha256 != schema_sha256) {
        set_error(error, error_capacity, "feature-schema SHA-256 mismatch");
        return false;
    }

    const auto seen = [&values](Field field) {
        return values.seen[static_cast<std::size_t>(field)];
    };
    if (seen(Field::payload_bytes) && artifact_bytes != values.payload_bytes + 256u) {
        set_error(error, error_capacity,
            "artifact size does not match manifest payload_bytes");
        return false;
    }

    std::memcpy(receipt->manifest_sha256, manifest_sha256,
        sizeof(receipt->manifest_sha256));
    std::memcpy(receipt->artifact_sha256, artifact_sha256,
        sizeof(receipt->artifact_sha256));
    std::memcpy(receipt->feature_schema_sha256, schema_sha256,
        sizeof(receipt->feature_schema_sha256));
    copy_digest(values.source_state_sha256, receipt->source_state_sha256);
    copy_digest(
        values.training_receipt_sha256,
        receipt->training_receipt_sha256);
    std::memcpy(receipt->format, "FKESV1", FK_EVENT_STUDENT_FORMAT_CHARS + 1u);
    std::memcpy(
        receipt->training_run_mode,
        values.training_run_mode.c_str(),
        values.training_run_mode.size() + 1u);
    receipt->manifest_bytes = manifest_bytes;
    receipt->artifact_bytes = artifact_bytes;
    receipt->feature_schema_bytes = schema_bytes;
    receipt->manifest_fields = values.field_count;
    receipt->format_version = static_cast<uint32_t>(values.format_version);
    receipt->input_features = static_cast<uint32_t>(values.input_features);
    receipt->maximum_flows_per_window =
        static_cast<uint32_t>(values.maximum_flows_per_window);
    receipt->hidden = static_cast<uint32_t>(values.hidden);
    receipt->identity_embedding =
        static_cast<uint32_t>(values.identity_embedding);
    receipt->decision_threshold =
        static_cast<float>(values.decision_threshold);
    receipt->locked_test_accessed = false;
    receipt->formal_evidence_eligible = values.formal_evidence_eligible;
    receipt->manifest_sha256_matched = true;
    receipt->artifact_sha256_matched = true;
    receipt->feature_schema_sha256_matched = true;
    receipt->load_config.expected_artifact_sha256 = receipt->artifact_sha256;
    receipt->load_config.expected_feature_schema_sha256 =
        receipt->feature_schema_sha256;
    receipt->load_config.expected_source_state_sha256 =
        receipt->source_state_sha256;
    receipt->load_config.expected_hidden = receipt->hidden;
    receipt->load_config.expected_identity_embedding =
        receipt->identity_embedding;
    return true;
}

}  // extern "C"
