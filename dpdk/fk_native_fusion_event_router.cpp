#include "fk_native_fusion_event_router.h"

#include <arpa/inet.h>
#include <fcntl.h>
#include <openssl/evp.h>
#include <sys/stat.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <exception>
#include <limits>
#include <map>
#include <new>
#include <unordered_map>
#include <utility>
#include <vector>

namespace flowkeep {
namespace {

constexpr uint64_t kMaximumEventMapBytes = UINT64_C(1073741824);
constexpr size_t kMaximumFieldBytes = 4096u;

void set_error_noexcept(std::string *error, const char *message) noexcept {
    if (error == nullptr)
        return;
    try {
        *error = message;
    } catch (...) {
    }
}

void set_error_noexcept(
        std::string *error, const std::string &message) noexcept {
    if (error == nullptr)
        return;
    try {
        *error = message;
    } catch (...) {
    }
}

void clear_error_noexcept(std::string *error) noexcept {
    if (error == nullptr)
        return;
    try {
        error->clear();
    } catch (...) {
    }
}

bool exact_lower_sha256(const std::string &value) {
    if (value.size() != 64u)
        return false;
    for (const char character : value) {
        if (!((character >= '0' && character <= '9') ||
              (character >= 'a' && character <= 'f'))) {
            return false;
        }
    }
    return true;
}

std::string hex_digest(const unsigned char *digest, size_t bytes) {
    static const char alphabet[] = "0123456789abcdef";
    std::string result(bytes * 2u, '0');
    for (size_t index = 0u; index < bytes; ++index) {
        result[index * 2u] = alphabet[digest[index] >> 4u];
        result[index * 2u + 1u] = alphabet[digest[index] & 0x0fu];
    }
    return result;
}

class ScopedFd {
public:
    explicit ScopedFd(int fd) noexcept : fd_(fd) {}
    ~ScopedFd() {
        if (fd_ >= 0)
            (void)::close(fd_);
    }
    ScopedFd(const ScopedFd &) = delete;
    ScopedFd &operator=(const ScopedFd &) = delete;
    int get() const noexcept { return fd_; }

private:
    int fd_;
};

bool read_hash_bound_file(
        const std::string &path,
        const std::string &expected_sha256,
        std::vector<unsigned char> *bytes,
        std::string *observed_sha256,
        std::string *error) {
    if (path.empty() || bytes == nullptr || observed_sha256 == nullptr ||
        !exact_lower_sha256(expected_sha256)) {
        set_error_noexcept(error, "event map path/SHA-256 binding is invalid");
        return false;
    }
    struct stat path_stat{};
    if (::lstat(path.c_str(), &path_stat) != 0 ||
        !S_ISREG(path_stat.st_mode)) {
        set_error_noexcept(error,
            "event map must be an existing regular non-symlink file");
        return false;
    }
    const int raw_fd = ::open(path.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (raw_fd < 0) {
        set_error_noexcept(error, "failed to open frozen event map");
        return false;
    }
    ScopedFd fd(raw_fd);
    struct stat opened_stat{};
    if (::fstat(fd.get(), &opened_stat) != 0 ||
        !S_ISREG(opened_stat.st_mode) || opened_stat.st_dev != path_stat.st_dev ||
        opened_stat.st_ino != path_stat.st_ino || opened_stat.st_size <= 0 ||
        static_cast<uint64_t>(opened_stat.st_size) > kMaximumEventMapBytes) {
        set_error_noexcept(error,
            "event map identity/type/size changed or is unsafe");
        return false;
    }

    EVP_MD_CTX *context = EVP_MD_CTX_new();
    if (context == nullptr ||
        EVP_DigestInit_ex(context, EVP_sha256(), nullptr) != 1) {
        EVP_MD_CTX_free(context);
        set_error_noexcept(error, "failed to initialize event map SHA-256");
        return false;
    }
    bool valid = true;
    try {
        bytes->clear();
        bytes->reserve(static_cast<size_t>(opened_stat.st_size));
        std::array<unsigned char, 65536u> buffer{};
        for (;;) {
            const ssize_t count = ::read(fd.get(), buffer.data(), buffer.size());
            if (count < 0 && errno == EINTR)
                continue;
            if (count < 0) {
                valid = false;
                break;
            }
            if (count == 0)
                break;
            const size_t chunk = static_cast<size_t>(count);
            if (bytes->size() > kMaximumEventMapBytes - chunk ||
                EVP_DigestUpdate(context, buffer.data(), chunk) != 1) {
                valid = false;
                break;
            }
            bytes->insert(bytes->end(), buffer.begin(), buffer.begin() + count);
        }
    } catch (...) {
        valid = false;
    }
    unsigned char digest[EVP_MAX_MD_SIZE]{};
    unsigned int digest_bytes = 0u;
    valid = valid && !bytes->empty() &&
        EVP_DigestFinal_ex(context, digest, &digest_bytes) == 1 &&
        digest_bytes == 32u;
    EVP_MD_CTX_free(context);
    if (!valid) {
        set_error_noexcept(error, "failed to read/hash frozen event map");
        return false;
    }
    *observed_sha256 = hex_digest(digest, digest_bytes);
    if (*observed_sha256 != expected_sha256) {
        set_error_noexcept(error, "event map SHA-256 differs from binding");
        return false;
    }
    return true;
}

bool valid_utf8(const std::vector<unsigned char> &input) {
    size_t index = 0u;
    while (index < input.size()) {
        const uint32_t first = input[index++];
        if (first <= 0x7fu)
            continue;
        uint32_t codepoint = 0u;
        size_t continuation = 0u;
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
        if (input.size() - index < continuation)
            return false;
        for (size_t count = 0u; count < continuation; ++count) {
            const uint32_t value = input[index++];
            if ((value & 0xc0u) != 0x80u)
                return false;
            codepoint = (codepoint << 6u) | (value & 0x3fu);
        }
        if (codepoint < minimum || codepoint > 0x10ffffu ||
            (codepoint >= 0xd800u && codepoint <= 0xdfffu)) {
            return false;
        }
    }
    return true;
}

using CsvRow = std::array<std::string, 2u>;

bool finish_csv_record(
        std::vector<std::string> *fields,
        std::string *field,
        std::vector<CsvRow> *rows,
        std::string *error) {
    fields->push_back(std::move(*field));
    field->clear();
    if (fields->size() != 2u) {
        set_error_noexcept(error,
            "event map CSV row does not have exactly two columns");
        return false;
    }
    rows->push_back(CsvRow{{std::move((*fields)[0]),
                            std::move((*fields)[1])}});
    fields->clear();
    return true;
}

bool parse_exact_csv(
        const std::vector<unsigned char> &bytes,
        std::vector<CsvRow> *rows,
        std::string *error) {
    if (rows == nullptr || !valid_utf8(bytes)) {
        set_error_noexcept(error, "event map is not valid UTF-8 CSV");
        return false;
    }
    rows->clear();
    std::vector<std::string> fields;
    fields.reserve(2u);
    std::string field;
    bool quoted = false;
    bool after_quote = false;
    bool field_started = false;
    for (size_t index = 0u; index < bytes.size(); ++index) {
        const char value = static_cast<char>(bytes[index]);
        if (quoted) {
            if (value == '"') {
                if (index + 1u < bytes.size() && bytes[index + 1u] == '"') {
                    field.push_back('"');
                    ++index;
                } else {
                    quoted = false;
                    after_quote = true;
                }
            } else {
                field.push_back(value);
            }
            continue;
        }
        if (after_quote) {
            if (value != ',' && value != '\r' && value != '\n') {
                set_error_noexcept(error,
                    "event map CSV has bytes after a closing quote");
                return false;
            }
        } else if (value == '"') {
            if (field_started || !field.empty()) {
                set_error_noexcept(error,
                    "event map CSV has a quote inside an unquoted field");
                return false;
            }
            quoted = true;
            field_started = true;
            continue;
        } else if (value != ',' && value != '\r' && value != '\n') {
            field.push_back(value);
            field_started = true;
            continue;
        }

        if (value == ',') {
            fields.push_back(std::move(field));
            field.clear();
            if (fields.size() >= 2u) {
                set_error_noexcept(error,
                    "event map CSV row has more than two columns");
                return false;
            }
            after_quote = false;
            field_started = false;
            continue;
        }
        if (value == '\r' && index + 1u < bytes.size() &&
            bytes[index + 1u] == '\n') {
            ++index;
        }
        if (!finish_csv_record(&fields, &field, rows, error))
            return false;
        after_quote = false;
        field_started = false;
    }
    if (quoted) {
        set_error_noexcept(error, "event map CSV has an unterminated quote");
        return false;
    }
    if (after_quote || field_started || !field.empty() || !fields.empty()) {
        if (!finish_csv_record(&fields, &field, rows, error))
            return false;
    }
    if (rows->empty() || (*rows)[0][0] != "flow_key" ||
        (*rows)[0][1] != "event_id") {
        set_error_noexcept(error,
            "event map must have exact flow_key,event_id header");
        return false;
    }
    rows->erase(rows->begin());
    if (rows->empty()) {
        set_error_noexcept(error, "event map contains no routes");
        return false;
    }
    return true;
}

struct BinaryFlowKey {
    uint8_t ip_version = 0u;
    uint8_t protocol = 0u;
    std::array<uint8_t, 16u> low_addr{};
    std::array<uint8_t, 16u> high_addr{};
    uint16_t low_port = 0u;
    uint16_t high_port = 0u;

    bool operator==(const BinaryFlowKey &other) const noexcept {
        return ip_version == other.ip_version && protocol == other.protocol &&
            low_addr == other.low_addr && high_addr == other.high_addr &&
            low_port == other.low_port && high_port == other.high_port;
    }
};

struct BinaryFlowKeyHash {
    size_t operator()(const BinaryFlowKey &key) const noexcept {
        uint64_t hash = UINT64_C(14695981039346656037);
        const auto add = [&hash](uint8_t value) {
            hash ^= value;
            hash *= UINT64_C(1099511628211);
        };
        add(key.ip_version);
        add(key.protocol);
        const size_t address_bytes = key.ip_version == 4u ? 4u : 16u;
        for (size_t index = 0u; index < address_bytes; ++index)
            add(key.low_addr[index]);
        for (size_t index = 0u; index < address_bytes; ++index)
            add(key.high_addr[index]);
        add(static_cast<uint8_t>(key.low_port >> 8u));
        add(static_cast<uint8_t>(key.low_port));
        add(static_cast<uint8_t>(key.high_port >> 8u));
        add(static_cast<uint8_t>(key.high_port));
        return static_cast<size_t>(hash);
    }
};

struct Endpoint {
    uint8_t ip_version = 0u;
    std::array<uint8_t, 16u> address{};
    uint16_t port = 0u;
};

std::string decimal_u16(uint16_t value) {
    char buffer[6]{};
    const int count = std::snprintf(buffer, sizeof(buffer), "%u",
        static_cast<unsigned int>(value));
    return count > 0 ? std::string(buffer, static_cast<size_t>(count)) :
        std::string();
}

std::string ipv4_text(const std::array<uint8_t, 16u> &address) {
    return decimal_u16(address[0]) + "." + decimal_u16(address[1]) + "." +
        decimal_u16(address[2]) + "." + decimal_u16(address[3]);
}

std::string hex_word(uint16_t value) {
    static const char alphabet[] = "0123456789abcdef";
    char reversed[4]{};
    size_t count = 0u;
    do {
        reversed[count++] = alphabet[value & 0x0fu];
        value = static_cast<uint16_t>(value >> 4u);
    } while (value != 0u);
    std::string result;
    result.reserve(count);
    while (count != 0u)
        result.push_back(reversed[--count]);
    return result;
}

std::string ipv6_text(const std::array<uint8_t, 16u> &address) {
    std::array<uint16_t, 8u> words{};
    for (size_t index = 0u; index < words.size(); ++index) {
        words[index] = static_cast<uint16_t>(
            (static_cast<uint16_t>(address[index * 2u]) << 8u) |
            address[index * 2u + 1u]);
    }
    size_t best_start = words.size();
    size_t best_length = 0u;
    for (size_t index = 0u; index < words.size();) {
        if (words[index] != 0u) {
            ++index;
            continue;
        }
        const size_t start = index;
        while (index < words.size() && words[index] == 0u)
            ++index;
        const size_t length = index - start;
        if (length >= 2u && length > best_length) {
            best_start = start;
            best_length = length;
        }
    }
    const auto join = [&words](size_t begin, size_t end) {
        std::string result;
        for (size_t index = begin; index < end; ++index) {
            if (!result.empty())
                result.push_back(':');
            result += hex_word(words[index]);
        }
        return result;
    };
    if (best_length == 0u)
        return join(0u, words.size());
    const std::string prefix = join(0u, best_start);
    const std::string suffix = join(best_start + best_length, words.size());
    if (prefix.empty() && suffix.empty())
        return "::";
    if (prefix.empty())
        return "::" + suffix;
    if (suffix.empty())
        return prefix + "::";
    return prefix + "::" + suffix;
}

std::string endpoint_text(const Endpoint &endpoint) {
    const std::string address = endpoint.ip_version == 4u ?
        ipv4_text(endpoint.address) : ipv6_text(endpoint.address);
    return address + ":" + decimal_u16(endpoint.port);
}

bool parse_port(const std::string &text, uint16_t *port) {
    if (text.empty() || port == nullptr ||
        (text.size() > 1u && text[0] == '0')) {
        return false;
    }
    uint32_t value = 0u;
    for (const char character : text) {
        if (character < '0' || character > '9')
            return false;
        value = value * 10u + static_cast<uint32_t>(character - '0');
        if (value > 65535u)
            return false;
    }
    *port = static_cast<uint16_t>(value);
    return true;
}

bool parse_endpoint(
        const std::string &text, Endpoint *endpoint, std::string *error) {
    const size_t separator = text.rfind(':');
    if (separator == std::string::npos || separator == 0u ||
        separator + 1u >= text.size() || endpoint == nullptr ||
        !parse_port(text.substr(separator + 1u), &endpoint->port)) {
        set_error_noexcept(error, "event map flow_key endpoint/port is invalid");
        return false;
    }
    const std::string address_text = text.substr(0u, separator);
    endpoint->address.fill(0u);
    if (::inet_pton(AF_INET, address_text.c_str(),
            endpoint->address.data()) == 1) {
        endpoint->ip_version = 4u;
    } else if (::inet_pton(AF_INET6, address_text.c_str(),
                   endpoint->address.data()) == 1) {
        endpoint->ip_version = 6u;
    } else {
        set_error_noexcept(error, "event map flow_key IP address is invalid");
        return false;
    }
    if (endpoint_text(*endpoint) != text) {
        set_error_noexcept(error,
            "event map flow_key endpoint is not canonical Python text");
        return false;
    }
    return true;
}

int compare_endpoints(const Endpoint &left, const Endpoint &right) {
    if (left.ip_version != right.ip_version)
        return left.ip_version < right.ip_version ? -1 : 1;
    const size_t bytes = left.ip_version == 4u ? 4u : 16u;
    const int address_order = std::memcmp(
        left.address.data(), right.address.data(), bytes);
    if (address_order != 0)
        return address_order;
    if (left.port == right.port)
        return 0;
    return left.port < right.port ? -1 : 1;
}

bool parse_flow_text(
        const std::string &text,
        BinaryFlowKey *key,
        std::string *error) {
    if (key == nullptr || text.empty() || text.size() > kMaximumFieldBytes ||
        text.find('\0') != std::string::npos ||
        text.find('\r') != std::string::npos ||
        text.find('\n') != std::string::npos) {
        set_error_noexcept(error, "event map flow_key is empty or unsafe");
        return false;
    }
    const size_t first = text.find('|');
    const size_t second = first == std::string::npos ? std::string::npos :
        text.find('|', first + 1u);
    if (first == std::string::npos || second == std::string::npos ||
        text.find('|', second + 1u) != std::string::npos ||
        (text.substr(0u, first) != "6" && text.substr(0u, first) != "17")) {
        set_error_noexcept(error,
            "event map flow_key must be canonical TCP/UDP five tuple");
        return false;
    }
    Endpoint low{};
    Endpoint high{};
    if (!parse_endpoint(text.substr(first + 1u, second - first - 1u),
            &low, error) ||
        !parse_endpoint(text.substr(second + 1u), &high, error)) {
        return false;
    }
    if (low.ip_version != high.ip_version ||
        compare_endpoints(low, high) > 0) {
        set_error_noexcept(error,
            "event map flow_key endpoints are not canonically ordered");
        return false;
    }
    *key = {};
    key->ip_version = low.ip_version;
    key->protocol = text[0] == '6' && first == 1u ? 6u : 17u;
    key->low_addr = low.address;
    key->high_addr = high.address;
    key->low_port = low.port;
    key->high_port = high.port;
    return true;
}

bool binary_flow_key(
        const fk_flow_key &input,
        BinaryFlowKey *key,
        std::string *text,
        std::string *error) {
    if (key == nullptr || (input.ip_version != 4u && input.ip_version != 6u) ||
        (input.protocol != 6u && input.protocol != 17u)) {
        set_error_noexcept(error, "native request flow_key type is invalid");
        return false;
    }
    const size_t address_bytes = input.ip_version == 4u ? 4u : 16u;
    if (input.ip_version == 4u) {
        for (size_t index = 4u; index < 16u; ++index) {
            if (input.low_addr[index] != 0u || input.high_addr[index] != 0u) {
                set_error_noexcept(error,
                    "native request IPv4 flow_key has nonzero tail bytes");
                return false;
            }
        }
    }
    const int address_order = std::memcmp(
        input.low_addr, input.high_addr, address_bytes);
    if (address_order > 0 ||
        (address_order == 0 && input.low_port > input.high_port)) {
        set_error_noexcept(error,
            "native request flow_key endpoints are not canonical");
        return false;
    }
    *key = {};
    key->ip_version = input.ip_version;
    key->protocol = input.protocol;
    std::copy(input.low_addr, input.low_addr + address_bytes,
        key->low_addr.begin());
    std::copy(input.high_addr, input.high_addr + address_bytes,
        key->high_addr.begin());
    key->low_port = input.low_port;
    key->high_port = input.high_port;
    if (text != nullptr) {
        const Endpoint low{key->ip_version, key->low_addr, key->low_port};
        const Endpoint high{key->ip_version, key->high_addr, key->high_port};
        *text = decimal_u16(key->protocol) + "|" + endpoint_text(low) + "|" +
            endpoint_text(high);
    }
    return true;
}

struct Utf8ByteLess {
    bool operator()(const std::string &left, const std::string &right) const {
        return std::lexicographical_compare(
            left.begin(), left.end(), right.begin(), right.end(),
            [](char lhs, char rhs) {
                return static_cast<unsigned char>(lhs) <
                    static_cast<unsigned char>(rhs);
            });
    }
};

bool safe_event_id(const std::string &event_id) {
    return !event_id.empty() && event_id.size() <= kMaximumFieldBytes &&
        event_id.find('\0') == std::string::npos &&
        event_id.find('\r') == std::string::npos &&
        event_id.find('\n') == std::string::npos;
}

}  // namespace

struct NativeFusionCsvEventRouter::Implementation {
    struct EventRecord {
        uint64_t token = 0u;
    };
    struct RouteRecord {
        uint64_t token = 0u;
        const std::string *event_id = nullptr;
        std::string canonical_flow_key;
    };

    NativeFusionEventUnit event_unit = NativeFusionEventUnit::Scenario;
    std::string event_map_sha256;
    std::map<std::string, EventRecord, Utf8ByteLess> events;
    std::unordered_map<BinaryFlowKey, RouteRecord, BinaryFlowKeyHash> routes;
};

NativeFusionCsvEventRouter::NativeFusionCsvEventRouter(
        Implementation *implementation) noexcept
    : implementation_(implementation) {}

NativeFusionCsvEventRouter::~NativeFusionCsvEventRouter() {
    delete implementation_;
}

std::unique_ptr<NativeFusionCsvEventRouter>
NativeFusionCsvEventRouter::Load(
        const std::string &event_map_path,
        const std::string &expected_sha256,
        const std::string &event_unit,
        std::string *error) {
    if (event_unit == "scenario") {
        return Load(event_map_path, expected_sha256,
            NativeFusionEventUnit::Scenario, error);
    }
    if (event_unit == "five_tuple") {
        return Load(event_map_path, expected_sha256,
            NativeFusionEventUnit::FiveTuple, error);
    }
    set_error_noexcept(error, "event unit must be scenario or five_tuple");
    return nullptr;
}

std::unique_ptr<NativeFusionCsvEventRouter>
NativeFusionCsvEventRouter::Load(
        const std::string &event_map_path,
        const std::string &expected_sha256,
        NativeFusionEventUnit event_unit,
        std::string *error) {
    clear_error_noexcept(error);
    try {
        if (event_unit != NativeFusionEventUnit::Scenario &&
            event_unit != NativeFusionEventUnit::FiveTuple) {
            set_error_noexcept(error,
                "event unit must be scenario or five_tuple");
            return nullptr;
        }
        std::vector<unsigned char> bytes;
        std::string observed_sha256;
        if (!read_hash_bound_file(event_map_path, expected_sha256, &bytes,
                &observed_sha256, error)) {
            return nullptr;
        }
        std::vector<CsvRow> rows;
        if (!parse_exact_csv(bytes, &rows, error))
            return nullptr;

        struct PendingRoute {
            BinaryFlowKey key;
            std::string flow_key;
            std::string event_id;
        };
        std::vector<PendingRoute> pending;
        pending.reserve(rows.size());
        std::unique_ptr<Implementation> implementation(
            new Implementation());
        implementation->event_unit = event_unit;
        implementation->event_map_sha256 = observed_sha256;

        for (const CsvRow &row : rows) {
            BinaryFlowKey key{};
            std::string row_error;
            if (!parse_flow_text(row[0], &key, &row_error)) {
                set_error_noexcept(error, row_error);
                return nullptr;
            }
            const std::string &event_id = row[1];
            if (!safe_event_id(event_id)) {
                set_error_noexcept(error, "event_id is empty or unsafe");
                return nullptr;
            }
            if (event_unit == NativeFusionEventUnit::Scenario) {
                if (event_id.find("||") != std::string::npos) {
                    set_error_noexcept(error,
                        "scenario event_id must be a capture identity");
                    return nullptr;
                }
            } else {
                const size_t separator = event_id.find("||");
                if (separator == std::string::npos || separator == 0u ||
                    event_id.find("||", separator + 2u) != std::string::npos ||
                    event_id.substr(separator + 2u) != row[0]) {
                    set_error_noexcept(error,
                        "five_tuple event_id must equal capture_id||flow_key");
                    return nullptr;
                }
                if (implementation->events.find(event_id) !=
                    implementation->events.end()) {
                    set_error_noexcept(error,
                        "five_tuple event map is not one-to-one");
                    return nullptr;
                }
            }
            implementation->events.emplace(event_id,
                Implementation::EventRecord{});
            pending.push_back(PendingRoute{key, row[0], event_id});
        }
        uint64_t token = 1u;
        for (auto &event : implementation->events)
            event.second.token = token++;

        implementation->routes.max_load_factor(0.70f);
        implementation->routes.reserve(pending.size());
        for (PendingRoute &route : pending) {
            const auto event = implementation->events.find(route.event_id);
            if (event == implementation->events.end() ||
                event->second.token == 0u) {
                set_error_noexcept(error,
                    "internal event interning/token assignment failed");
                return nullptr;
            }
            Implementation::RouteRecord record{};
            record.token = event->second.token;
            record.event_id = &event->first;
            record.canonical_flow_key = std::move(route.flow_key);
            if (!implementation->routes.emplace(route.key,
                    std::move(record)).second) {
                set_error_noexcept(error, "duplicate event map flow_key");
                return nullptr;
            }
        }
        if (implementation->routes.size() != rows.size() ||
            implementation->events.empty()) {
            set_error_noexcept(error, "event map closure is incomplete");
            return nullptr;
        }
        return std::unique_ptr<NativeFusionCsvEventRouter>(
            new NativeFusionCsvEventRouter(implementation.release()));
    } catch (const std::exception &exception) {
        set_error_noexcept(error,
            std::string("failed to load event router: ") + exception.what());
    } catch (...) {
        set_error_noexcept(error, "failed to load event router");
    }
    return nullptr;
}

bool NativeFusionCsvEventRouter::ResolveDetailed(
        const fk_detector_request_v1 &request,
        NativeFusionDetailedRoute *route,
        std::string *error) const noexcept {
    clear_error_noexcept(error);
    if (route != nullptr)
        *route = {};
    if (implementation_ == nullptr || route == nullptr) {
        set_error_noexcept(error, "event router/route output is invalid");
        return false;
    }
    BinaryFlowKey key{};
    if (!binary_flow_key(request.canonical_key, &key, nullptr, error))
        return false;
    const auto &routes = implementation_->routes;
    const auto found = routes.find(key);
    if (found == routes.end() ||
        found->second.token == 0u || found->second.event_id == nullptr ||
        found->second.event_id->empty() ||
        found->second.canonical_flow_key.empty()) {
        set_error_noexcept(error, "unknown canonical flow_key");
        return false;
    }
    route->event_token = found->second.token;
    route->event_id = found->second.event_id;
    route->canonical_flow_key = &found->second.canonical_flow_key;
    return true;
}

bool NativeFusionCsvEventRouter::Resolve(
        const fk_detector_request_v1 &request,
        Route *route,
        std::string *error) noexcept {
    if (route != nullptr)
        *route = {};
    NativeFusionDetailedRoute detailed{};
    if (route == nullptr || !ResolveDetailed(request, &detailed, error)) {
        if (route == nullptr)
            set_error_noexcept(error, "event route output is null");
        return false;
    }
    route->event_token = detailed.event_token;
    route->event_id = detailed.event_id;
    return true;
}

bool NativeFusionCsvEventRouter::Audit(
        NativeFusionEventRouterAudit *audit,
        std::string *error) const noexcept {
    clear_error_noexcept(error);
    if (audit != nullptr)
        *audit = {};
    if (implementation_ == nullptr || audit == nullptr) {
        set_error_noexcept(error, "event router audit output is invalid");
        return false;
    }
    try {
        audit->event_map_sha256 = implementation_->event_map_sha256;
        audit->event_unit = implementation_->event_unit ==
            NativeFusionEventUnit::Scenario ? "scenario" : "five_tuple";
        audit->entries = static_cast<uint64_t>(implementation_->routes.size());
        audit->unique_events =
            static_cast<uint64_t>(implementation_->events.size());
        audit->exact_header_verified = 1u;
        audit->canonical_flow_keys_verified = 1u;
        audit->event_semantics_verified = 1u;
        audit->label_blind_schema_verified = 1u;
        return true;
    } catch (...) {
        *audit = {};
        set_error_noexcept(error, "failed to copy event router audit");
        return false;
    }
}

bool NativeFusionCsvEventRouter::CanonicalFlowKeyText(
        const fk_flow_key &key,
        std::string *text,
        std::string *error) noexcept {
    clear_error_noexcept(error);
    if (text == nullptr) {
        set_error_noexcept(error, "canonical flow text output is null");
        return false;
    }
    try {
        BinaryFlowKey binary{};
        std::string output;
        if (!binary_flow_key(key, &binary, &output, error)) {
            text->clear();
            return false;
        }
        *text = std::move(output);
        return true;
    } catch (...) {
        text->clear();
        set_error_noexcept(error, "failed to format canonical flow_key");
        return false;
    }
}

}  // namespace flowkeep
