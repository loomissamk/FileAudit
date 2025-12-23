// FileAudit.cpp
// Single-binary CDS sidecar + receipt service (C++17).
// Modes:
//   --mode sender   : create *.manifest.json next to payloads in outbox
//   --mode receiver : verify payloads in inbox and write receipts/<doc_id>.receipt.json
//   --mode outbox   : sender + ship to inbox + receipt acks
//   --mode inbox    : auto-manifest + receiver for direct inbox drops
//
// No CDS changes required. Works with mounted buckets or filesystem staging.
//
// Build:
//   g++ -O2 -std=c++17 FileAudit.cpp -o file_audit -lssl -lcrypto

#include <openssl/evp.h>
#include <openssl/hmac.h>

#include <array>
#include <chrono>
#include <cctype>
#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <memory>
#include <optional>
#include <random>
#include <sstream>
#include <string>
#include <thread>
#include <vector>
#if defined(__linux__)
#include <fcntl.h>
#include <sys/inotify.h>
#include <sys/select.h>
#include <unistd.h>
#endif

namespace fs = std::filesystem;

struct Logger {
    void set_file(const fs::path& p) {
        if (p.empty()) return;
        try {
            auto parent = p.parent_path();
            if (!parent.empty()) {
                fs::create_directories(parent);
            }
        } catch (...) {
            return;
        }
        file.emplace(p, std::ios::app);
    }

    void log_line(const std::string& line) {
        std::cout << line << "\n";
        std::cout.flush();
        if (file.has_value() && file->is_open()) {
            (*file) << line << "\n";
            file->flush();
        }
    }

    std::optional<std::ofstream> file;
};

static std::optional<std::string> getenv_string(const char* key) {
    const char* v = std::getenv(key);
    if (!v || *v == '\0') return std::nullopt;
    return std::string(v);
}

static std::optional<int> getenv_int(const char* key) {
    auto v = getenv_string(key);
    if (!v) return std::nullopt;
    try {
        return std::stoi(*v);
    } catch (...) {
        return std::nullopt;
    }
}

static std::optional<size_t> getenv_size(const char* key) {
    auto v = getenv_string(key);
    if (!v) return std::nullopt;
    try {
        return static_cast<size_t>(std::stoull(*v));
    } catch (...) {
        return std::nullopt;
    }
}

static std::optional<bool> getenv_bool(const char* key) {
    auto v = getenv_string(key);
    if (!v) return std::nullopt;
    return (*v != "0");
}

static std::string now_rfc3339_utc() {
    using namespace std::chrono;
    auto now = system_clock::now();
    std::time_t t = system_clock::to_time_t(now);
    std::tm tm{};
#if defined(_WIN32)
    gmtime_s(&tm, &t);
#else
    gmtime_r(&t, &tm);
#endif
    char buf[64];
    std::snprintf(buf, sizeof(buf), "%04d-%02d-%02dT%02d:%02d:%02dZ",
                  tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
                  tm.tm_hour, tm.tm_min, tm.tm_sec);
    return std::string(buf);
}

static std::string json_escape(const std::string& s) {
    std::ostringstream o;
    for (char c : s) {
        switch (c) {
            case '\\': o << "\\\\"; break;
            case '"':  o << "\\\""; break;
            case '\b': o << "\\b";  break;
            case '\f': o << "\\f";  break;
            case '\n': o << "\\n";  break;
            case '\r': o << "\\r";  break;
            case '\t': o << "\\t";  break;
            default:
                if (static_cast<unsigned char>(c) < 0x20) {
                    o << "\\u" << std::hex << (int)c;
                } else {
                    o << c;
                }
        }
    }
    return o.str();
}

static bool ends_with(const std::string& s, const std::string& suf) {
    if (s.size() < suf.size()) return false;
    return s.compare(s.size() - suf.size(), suf.size(), suf) == 0;
}

static bool is_hex(char c) {
    return std::isdigit((unsigned char)c) ||
           (c >= 'a' && c <= 'f') ||
           (c >= 'A' && c <= 'F');
}

// Very small UUID finder: locate any 36-char UUID-like substring.
static std::optional<std::string> extract_uuid_from_filename(const std::string& name) {
    if (name.size() < 36) return std::nullopt;
    for (size_t i = 0; i + 36 <= name.size(); i++) {
        const std::string s = name.substr(i, 36);
        auto ok = [&](size_t pos, char expected) {
            return s[pos] == expected;
        };
        if (!ok(8,'-') || !ok(13,'-') || !ok(18,'-') || !ok(23,'-')) continue;
        bool allhex = true;
        for (size_t j = 0; j < 36; j++) {
            if (j==8||j==13||j==18||j==23) continue;
            if (!is_hex(s[j])) { allhex = false; break; }
        }
        if (allhex) return s;
    }
    return std::nullopt;
}

// RFC 4122 UUID v4 (random).
static std::string uuid_v4() {
    std::array<unsigned char, 16> bytes{};
    bool ok = false;
#if !defined(_WIN32)
    std::ifstream urandom("/dev/urandom", std::ios::binary);
    if (urandom) {
        urandom.read(reinterpret_cast<char*>(bytes.data()), bytes.size());
        ok = (urandom.gcount() == static_cast<std::streamsize>(bytes.size()));
    }
#endif
    if (!ok) {
        std::random_device rd;
        for (auto& b : bytes) b = static_cast<unsigned char>(rd());
    }

    bytes[6] = (bytes[6] & 0x0F) | 0x40; // version 4
    bytes[8] = (bytes[8] & 0x3F) | 0x80; // variant 1

    std::ostringstream o;
    o << std::hex << std::setfill('0');
    for (size_t i = 0; i < bytes.size(); i++) {
        o << std::setw(2) << static_cast<int>(bytes[i]);
        if (i == 3 || i == 5 || i == 7 || i == 9) o << "-";
    }
    return o.str();
}

struct HashResult {
    std::string sha256_hex;
    uint64_t size = 0;
};

static HashResult sha256_file(const fs::path& p) {
    std::ifstream f(p, std::ios::binary);
    if (!f) throw std::runtime_error("open failed: " + p.string());

    struct EvpMdCtxDeleter {
        void operator()(EVP_MD_CTX* ctx) const { EVP_MD_CTX_free(ctx); }
    };
    std::unique_ptr<EVP_MD_CTX, EvpMdCtxDeleter> ctx(EVP_MD_CTX_new());
    if (!ctx) throw std::runtime_error("EVP_MD_CTX_new failed");
    if (EVP_DigestInit_ex(ctx.get(), EVP_sha256(), nullptr) != 1) {
        throw std::runtime_error("EVP_DigestInit_ex failed");
    }

    std::vector<unsigned char> buf(1 << 20); // 1 MiB
    uint64_t total = 0;
    while (f) {
        f.read(reinterpret_cast<char*>(buf.data()), buf.size());
        std::streamsize n = f.gcount();
        if (n > 0) {
            if (EVP_DigestUpdate(ctx.get(), buf.data(), (size_t)n) != 1) {
                throw std::runtime_error("EVP_DigestUpdate failed");
            }
            total += (uint64_t)n;
        }
    }

    unsigned char out[EVP_MAX_MD_SIZE];
    unsigned int out_len = 0;
    if (EVP_DigestFinal_ex(ctx.get(), out, &out_len) != 1) {
        throw std::runtime_error("EVP_DigestFinal_ex failed");
    }

    std::ostringstream o;
    o << std::hex;
    for (unsigned int i = 0; i < out_len; i++) {
        o << "0123456789abcdef"[out[i] >> 4];
        o << "0123456789abcdef"[out[i] & 0x0F];
    }

    return { o.str(), total };
}

static std::string hex_encode(const unsigned char* data, size_t len) {
    std::ostringstream o;
    o << std::hex << std::setfill('0');
    for (size_t i = 0; i < len; i++) {
        o << std::setw(2) << static_cast<int>(data[i]);
    }
    return o.str();
}

static std::string hmac_sha256_hex(const std::string& key, const std::string& message) {
    struct HmacCtxDeleter {
        void operator()(HMAC_CTX* ctx) const { HMAC_CTX_free(ctx); }
    };
    std::unique_ptr<HMAC_CTX, HmacCtxDeleter> ctx(HMAC_CTX_new());
    if (!ctx) throw std::runtime_error("HMAC_CTX_new failed");
    if (HMAC_Init_ex(ctx.get(), key.data(), static_cast<int>(key.size()), EVP_sha256(), nullptr) != 1) {
        throw std::runtime_error("HMAC_Init_ex failed");
    }
    if (HMAC_Update(ctx.get(),
                    reinterpret_cast<const unsigned char*>(message.data()),
                    message.size()) != 1) {
        throw std::runtime_error("HMAC_Update failed");
    }
    unsigned char out[EVP_MAX_MD_SIZE];
    unsigned int out_len = 0;
    if (HMAC_Final(ctx.get(), out, &out_len) != 1) {
        throw std::runtime_error("HMAC_Final failed");
    }
    return hex_encode(out, out_len);
}

static std::string manifest_hmac_payload(const std::string& doc_id,
                                         const std::string& sha256,
                                         uint64_t size,
                                         const std::string& created_at,
                                         const std::string& filename) {
    std::ostringstream o;
    o << doc_id << "\n"
      << sha256 << "\n"
      << size << "\n"
      << created_at << "\n"
      << filename;
    return o.str();
}

static bool atomic_write_text(const fs::path& path, const std::string& content) {
    try {
        fs::path tmp = path;
        tmp += ".tmp";
        {
            std::ofstream out(tmp, std::ios::binary | std::ios::trunc);
            if (!out) return false;
            out.write(content.data(), (std::streamsize)content.size());
            out.flush();
        }
        fs::rename(tmp, path);
        return true;
    } catch (...) {
        return false;
    }
}

static bool touch_file(const fs::path& path) {
    return atomic_write_text(path, "");
}

static fs::path manifest_path_for(const fs::path& payload) {
    return payload.string() + ".manifest.json";
}

static fs::path ready_path_for(const fs::path& payload) {
    return payload.string() + ".ready";
}

static fs::path receipt_path_for(const fs::path& receipts_dir, const std::string& doc_id) {
    return receipts_dir / (doc_id + ".receipt.json");
}

static bool is_payload_file(const fs::path& p) {
    const auto name = p.filename().string();
    if (!name.empty() && name[0] == '.') return false;
    if (ends_with(name, ".manifest.json")) return false;
    if (ends_with(name, ".receipt.json")) return false;
    if (ends_with(name, ".ready")) return false;
    if (ends_with(name, ".tmp")) return false;
    return true;
}

static std::vector<fs::path> list_files(const fs::path& dir) {
    std::vector<fs::path> out;
    if (!fs::exists(dir)) return out;
    for (auto& e : fs::directory_iterator(dir)) {
        if (!e.is_regular_file()) continue;
        out.push_back(e.path());
    }
    return out;
}

static bool copy_file_atomic(const fs::path& src, const fs::path& dst) {
    try {
        fs::path tmp = dst;
        tmp += ".tmp";
        fs::copy_file(src, tmp, fs::copy_options::overwrite_existing);
        fs::rename(tmp, dst);
        return true;
    } catch (...) {
        return false;
    }
}

static bool file_is_stable(const fs::path& p, int stable_sec) {
    if (stable_sec <= 0) return true;
    try {
        auto mtime = fs::last_write_time(p);
        auto now = fs::file_time_type::clock::now();
        auto age = std::chrono::duration_cast<std::chrono::seconds>(now - mtime).count();
        return age >= stable_sec;
    } catch (...) {
        return false;
    }
}

static void mark_ready_for_stable_files(const fs::path& dir, int stable_sec, Logger& log) {
    if (stable_sec < 0) return;
    for (const auto& p : list_files(dir)) {
        if (!is_payload_file(p)) continue;
        auto ready = ready_path_for(p);
        if (fs::exists(ready)) continue;
        if (!file_is_stable(p, stable_sec)) continue;
        if (touch_file(ready)) {
            log.log_line("{\"event\":\"READY_CREATED\",\"payload\":\"" +
                         json_escape(p.filename().string()) + "\"}");
        }
    }
}

static bool write_dummy_payload(const fs::path& payload, size_t bytes) {
    std::vector<unsigned char> buf(bytes);
    std::random_device rd;
    for (auto& b : buf) b = static_cast<unsigned char>(rd());
    std::ostringstream o;
    o << std::hex << std::setfill('0');
    for (unsigned char b : buf) {
        o << std::setw(2) << static_cast<int>(b);
    }
    return atomic_write_text(payload, o.str());
}

static std::string build_manifest_json(const std::string& doc_id,
                                       const std::string& filename,
                                       const std::string& sha256,
                                       uint64_t size,
                                       const std::string& created_at,
                                       const std::optional<std::string>& hmac_sha256) {
    // Add fields later if needed.
    std::ostringstream o;
    o << "{\n"
      << "  \"doc_id\": \"" << json_escape(doc_id) << "\",\n"
      << "  \"sha256\": \"" << json_escape(sha256) << "\",\n"
      << "  \"size\": " << size << ",\n"
      << "  \"created_at\": \"" << json_escape(created_at) << "\",\n";
    if (hmac_sha256.has_value()) {
        o << "  \"hmac_sha256\": \"" << json_escape(*hmac_sha256) << "\",\n";
    }
    o << "  \"filename\": \"" << json_escape(filename) << "\"\n"
      << "}\n";
    return o.str();
}

static std::string build_receipt_json(const std::string& doc_id,
                                      const std::string& filename,
                                      const std::string& sha256,
                                      uint64_t size,
                                      const std::string& received_at,
                                      const std::string& receiver,
                                      const std::string& result) {
    std::ostringstream o;
    o << "{\n"
      << "  \"doc_id\": \"" << json_escape(doc_id) << "\",\n"
      << "  \"sha256\": \"" << json_escape(sha256) << "\",\n"
      << "  \"size\": " << size << ",\n"
      << "  \"received_at\": \"" << json_escape(received_at) << "\",\n"
      << "  \"receiver\": \"" << json_escape(receiver) << "\",\n"
      << "  \"result\": \"" << json_escape(result) << "\",\n"
      << "  \"filename\": \"" << json_escape(filename) << "\"\n"
      << "}\n";
    return o.str();
}

// Minimal JSON "parse": we only need sha256 and size and doc_id.
static std::optional<std::string> json_get_string_field(const std::string& json, const std::string& key) {
    auto k = "\"" + key + "\"";
    auto pos = json.find(k);
    if (pos == std::string::npos) return std::nullopt;
    pos = json.find(':', pos);
    if (pos == std::string::npos) return std::nullopt;
    pos = json.find('"', pos);
    if (pos == std::string::npos) return std::nullopt;
    auto end = json.find('"', pos + 1);
    if (end == std::string::npos) return std::nullopt;
    return json.substr(pos + 1, end - (pos + 1));
}

static std::optional<uint64_t> json_get_u64_field(const std::string& json, const std::string& key) {
    auto k = "\"" + key + "\"";
    auto pos = json.find(k);
    if (pos == std::string::npos) return std::nullopt;
    pos = json.find(':', pos);
    if (pos == std::string::npos) return std::nullopt;
    pos++; // after :
    while (pos < json.size() && std::isspace((unsigned char)json[pos])) pos++;
    size_t end = pos;
    while (end < json.size() && (std::isdigit((unsigned char)json[end]))) end++;
    if (end == pos) return std::nullopt;
    try {
        return (uint64_t)std::stoull(json.substr(pos, end - pos));
    } catch (...) {
        return std::nullopt;
    }
}

struct Manifest {
    std::string doc_id;
    std::string sha256;
    uint64_t size = 0;
    std::string created_at;
    std::string filename;
    std::optional<std::string> hmac_sha256;
};

static std::optional<Manifest> read_manifest(const fs::path& p) {
    std::ifstream f(p);
    if (!f) return std::nullopt;
    std::ostringstream ss;
    ss << f.rdbuf();
    auto json = ss.str();

    auto doc_id = json_get_string_field(json, "doc_id");
    auto sha = json_get_string_field(json, "sha256");
    auto sz = json_get_u64_field(json, "size");
    auto created_at = json_get_string_field(json, "created_at");
    auto filename = json_get_string_field(json, "filename");
    auto hmac = json_get_string_field(json, "hmac_sha256");
    if (!doc_id || !sha || !sz) return std::nullopt;

    Manifest man;
    man.doc_id = *doc_id;
    man.sha256 = *sha;
    man.size = *sz;
    if (created_at) man.created_at = *created_at;
    if (filename) man.filename = *filename;
    if (hmac) man.hmac_sha256 = *hmac;
    return man;
}

static bool hex_equal_case_insensitive(const std::string& a, const std::string& b) {
    if (a.size() != b.size()) return false;
    for (size_t i = 0; i < a.size(); i++) {
        char ca = a[i];
        char cb = b[i];
        if (ca >= 'A' && ca <= 'F') ca = static_cast<char>(ca - 'A' + 'a');
        if (cb >= 'A' && cb <= 'F') cb = static_cast<char>(cb - 'A' + 'a');
        if (ca != cb) return false;
    }
    return true;
}

static void sender_pass(const fs::path& outbox,
                        bool require_ready,
                        const std::string& hmac_key,
                        Logger& log) {
    for (const auto& p : list_files(outbox)) {
        if (!is_payload_file(p)) continue;
        if (require_ready && !fs::exists(ready_path_for(p))) continue;

        const auto mpath = manifest_path_for(p);
        if (fs::exists(mpath)) continue;

        try {
            auto hr = sha256_file(p);
            std::string fname = p.filename().string();
            auto uuid = extract_uuid_from_filename(fname);
            std::string doc_id = uuid.value_or(uuid_v4());

            std::string created_at = now_rfc3339_utc();
            std::optional<std::string> hmac;
            if (!hmac_key.empty()) {
                hmac = hmac_sha256_hex(
                    hmac_key,
                    manifest_hmac_payload(doc_id, hr.sha256_hex, hr.size, created_at, fname)
                );
            }

            std::string manifest_json = build_manifest_json(
                doc_id, fname, hr.sha256_hex, hr.size, created_at, hmac
            );

            if (atomic_write_text(mpath, manifest_json)) {
                log.log_line("{\"event\":\"MANIFEST_WRITTEN\",\"doc_id\":\"" +
                             json_escape(doc_id) + "\",\"payload\":\"" +
                             json_escape(p.string()) + "\",\"manifest\":\"" +
                             json_escape(mpath.string()) + "\"}");
            }
        } catch (const std::exception& e) {
            log.log_line("{\"event\":\"ERROR\",\"where\":\"sender\",\"payload\":\"" +
                         json_escape(p.string()) + "\",\"err\":\"" +
                         json_escape(e.what()) + "\"}");
        }
    }
}

static void receiver_pass(const fs::path& inbox,
                          const fs::path& receipts_out,
                          bool require_ready,
                          const std::string& hmac_key,
                          Logger& log) {
    for (const auto& p : list_files(inbox)) {
        if (!is_payload_file(p)) continue;
        if (require_ready && !fs::exists(ready_path_for(p))) continue;

        const auto mpath = manifest_path_for(p);
        if (!fs::exists(mpath)) continue;

        auto man = read_manifest(mpath);
        if (!man.has_value()) continue;

        const auto rpath = receipt_path_for(receipts_out, man->doc_id);
        if (fs::exists(rpath)) continue;

        std::string fname = p.filename().string();
        try {
            auto hr = sha256_file(p);

            bool ok = hex_equal_case_insensitive(hr.sha256_hex, man->sha256) &&
                      (hr.size == man->size);
            bool hmac_ok = true;
            if (!hmac_key.empty()) {
                if (!man->hmac_sha256.has_value() ||
                    man->created_at.empty() ||
                    man->filename.empty()) {
                    hmac_ok = false;
                } else {
                    std::string expected = hmac_sha256_hex(
                        hmac_key,
                        manifest_hmac_payload(
                            man->doc_id, man->sha256, man->size,
                            man->created_at, man->filename
                        )
                    );
                    hmac_ok = hex_equal_case_insensitive(expected, *man->hmac_sha256);
                }
            }

            std::string result = "INGESTED";
            if (!hmac_ok) result = "REJECTED_HMAC_MISMATCH";
            else if (!ok) result = "REJECTED_HASH_MISMATCH";

            std::string receipt_json = build_receipt_json(
                man->doc_id, fname, hr.sha256_hex, hr.size, now_rfc3339_utc(),
                "cds_audit_receiver", result
            );

            if (atomic_write_text(rpath, receipt_json)) {
                log.log_line("{\"event\":\"RECEIPT_WRITTEN\",\"doc_id\":\"" +
                             json_escape(man->doc_id) + "\",\"payload\":\"" +
                             json_escape(p.string()) + "\",\"receipt\":\"" +
                             json_escape(rpath.string()) + "\",\"result\":\"" +
                             json_escape(result) + "\"}");
            }
        } catch (const std::exception& e) {
            std::string receipt_json = build_receipt_json(
                man->doc_id, fname, man->sha256, man->size, now_rfc3339_utc(),
                "cds_audit_receiver", "FAILED_READ"
            );
            atomic_write_text(rpath, receipt_json);
            log.log_line("{\"event\":\"ERROR\",\"where\":\"receiver\",\"doc_id\":\"" +
                         json_escape(man->doc_id) + "\",\"payload\":\"" +
                         json_escape(p.string()) + "\",\"err\":\"" +
                         json_escape(e.what()) + "\"}");
        }
    }
}

static void outbox_pass(const fs::path& outbox,
                        const fs::path& inbox,
                        const fs::path& receipts_out,
                        bool require_ready,
                        int stable_sec,
                        const std::string& hmac_key,
                        Logger& log) {
    mark_ready_for_stable_files(outbox, stable_sec, log);
    sender_pass(outbox, require_ready, hmac_key, log);

    const fs::path sent_dir = outbox / ".sent";
    const fs::path acks_dir = outbox / ".acks";

    for (const auto& p : list_files(outbox)) {
        if (!is_payload_file(p)) continue;
        if (require_ready && !fs::exists(ready_path_for(p))) continue;

        const auto mpath = manifest_path_for(p);
        if (!fs::exists(mpath)) continue;

        const std::string base = p.filename().string();
        const fs::path marker = sent_dir / (base + ".sent");
        if (fs::exists(marker)) continue;

        fs::path dst_payload = inbox / base;
        fs::path dst_manifest = inbox / (base + ".manifest.json");
        fs::path dst_ready = inbox / (base + ".ready");

        if (copy_file_atomic(mpath, dst_manifest) &&
            copy_file_atomic(p, dst_payload) &&
            touch_file(dst_ready) &&
            touch_file(marker)) {
            log.log_line("{\"event\":\"SENT\",\"payload\":\"" +
                         json_escape(base) + "\",\"inbox\":\"" +
                         json_escape(dst_payload.string()) + "\"}");
        }
    }

    for (const auto& r : list_files(receipts_out)) {
        const auto name = r.filename().string();
        if (!ends_with(name, ".receipt.json")) continue;
        const fs::path ack = acks_dir / name;
        if (fs::exists(ack)) continue;
        if (touch_file(ack)) {
            log.log_line("{\"event\":\"RECEIPT_RECEIVED\",\"receipt\":\"" +
                         json_escape(r.string()) + "\"}");
        }
    }
}

static void inbox_pass(const fs::path& inbox,
                       const fs::path& receipts_out,
                       bool require_ready,
                       int stable_sec,
                       bool auto_manifest,
                       const std::string& hmac_key,
                       Logger& log) {
    mark_ready_for_stable_files(inbox, stable_sec, log);
    if (auto_manifest) {
        sender_pass(inbox, require_ready, hmac_key, log);
    }
    receiver_pass(inbox, receipts_out, require_ready, hmac_key, log);
}

static void wait_for_events_or_sleep(const std::vector<fs::path>& dirs,
                                     int poll_sec,
                                     bool use_inotify) {
    if (poll_sec <= 0) return;
#if defined(__linux__)
    if (use_inotify) {
        int fd = inotify_init1(IN_NONBLOCK);
        if (fd >= 0) {
            std::vector<int> wds;
            for (const auto& d : dirs) {
                if (d.empty()) continue;
                if (!fs::exists(d)) continue;
                int wd = inotify_add_watch(fd, d.c_str(),
                                           IN_CLOSE_WRITE | IN_MOVED_TO | IN_CREATE | IN_MODIFY);
                if (wd >= 0) wds.push_back(wd);
            }
            if (!wds.empty()) {
                fd_set rfds;
                FD_ZERO(&rfds);
                FD_SET(fd, &rfds);
                struct timeval tv;
                tv.tv_sec = poll_sec;
                tv.tv_usec = 0;
                int ready = select(fd + 1, &rfds, nullptr, nullptr, &tv);
                if (ready > 0 && FD_ISSET(fd, &rfds)) {
                    char buf[4096];
                    while (read(fd, buf, sizeof(buf)) > 0) {}
                }
                close(fd);
                return;
            }
            close(fd);
        }
    }
#else
    (void)dirs;
    (void)use_inotify;
#endif
    std::this_thread::sleep_for(std::chrono::seconds(poll_sec));
}

static void usage() {
    std::cerr <<
R"(cds_audit (C++17)
  --mode sender|receiver|outbox|inbox
  [--outbox ./outbox]          (sender/outbox)
  [--inbox ./inbox]            (receiver/outbox/inbox)
  [--receipts-out ./receipts]  (receiver/outbox/inbox)
  [--poll-sec 2]
  [--require-ready 1|0]
  [--stable-sec 2]
  [--inotify 1|0]
  [--log-file /path/to/log]
  [--log-dir /path/to/dir]
  [--payload-name dummy.txt]   (outbox)
  [--payload-bytes 2048]       (outbox)
  [--auto-manifest 1|0]        (inbox)
  [--hmac-key secret]          (sender/receiver/outbox/inbox)
  [--once 1|0]

Env (fallbacks):
  OUTBOX_DIR, INBOX_DIR, RECEIPTS_DIR, POLL_SEC, REQUIRE_READY, STABLE_SEC,
  INOTIFY, LOG_FILE, LOG_DIR, PAYLOAD_NAME, PAYLOAD_BYTES, INBOX_AUTOMANIFEST,
  MANIFEST_HMAC_KEY, ONCE

Sender:
  - For each payload in outbox/, write <payload>.manifest.json if missing.
Receiver:
  - For each payload in inbox/, wait for <payload>.manifest.json (and optional .ready),
    then verify sha256+size and write receipts/<doc_id>.receipt.json (idempotent).
Outbox:
  - Sender + ship payload+manifest to inbox, create .ready, and ack receipts.
Inbox:
  - Auto-manifest (optional) + receiver for direct inbox drops.
)";
}

int main(int argc, char** argv) {
    std::string mode;
    fs::path outbox = "./outbox";
    fs::path inbox = "./inbox";
    fs::path receipts_out = "./receipts";
    int poll_sec = 2;
    bool require_ready = true;
    int stable_sec = 2;
    bool use_inotify = false;
    std::string payload_name = "dummy.txt";
    size_t payload_bytes = 2048;
    bool auto_manifest = true;
    std::string log_file;
    fs::path log_dir;
    std::string hmac_key;
    bool once = false;

    if (auto v = getenv_string("OUTBOX_DIR")) outbox = *v;
    if (auto v = getenv_string("INBOX_DIR")) inbox = *v;
    if (auto v = getenv_string("RECEIPTS_DIR")) receipts_out = *v;
    if (auto v = getenv_int("POLL_SEC")) poll_sec = *v;
    if (auto v = getenv_bool("REQUIRE_READY")) require_ready = *v;
    if (auto v = getenv_int("STABLE_SEC")) stable_sec = *v;
    if (auto v = getenv_bool("INOTIFY")) use_inotify = *v;
    if (auto v = getenv_string("PAYLOAD_NAME")) payload_name = *v;
    if (auto v = getenv_size("PAYLOAD_BYTES")) payload_bytes = *v;
    if (auto v = getenv_bool("INBOX_AUTOMANIFEST")) auto_manifest = *v;
    if (auto v = getenv_string("LOG_FILE")) log_file = *v;
    if (auto v = getenv_string("LOG_DIR")) log_dir = *v;
    if (auto v = getenv_string("MANIFEST_HMAC_KEY")) hmac_key = *v;
    if (auto v = getenv_bool("ONCE")) once = *v;

    for (int i = 1; i < argc; i++) {
        std::string a = argv[i];
        auto need = [&](const char* flag) -> std::string {
            if (i + 1 >= argc) throw std::runtime_error(std::string("missing value for ") + flag);
            return argv[++i];
        };
        if (a == "--mode") mode = need("--mode");
        else if (a == "--outbox") outbox = need("--outbox");
        else if (a == "--inbox") inbox = need("--inbox");
        else if (a == "--receipts-out") receipts_out = need("--receipts-out");
        else if (a == "--poll-sec") poll_sec = std::stoi(need("--poll-sec"));
        else if (a == "--require-ready") require_ready = (need("--require-ready") != "0");
        else if (a == "--stable-sec") stable_sec = std::stoi(need("--stable-sec"));
        else if (a == "--inotify") use_inotify = (need("--inotify") != "0");
        else if (a == "--log-file") log_file = need("--log-file");
        else if (a == "--log-dir") log_dir = need("--log-dir");
        else if (a == "--payload-name") payload_name = need("--payload-name");
        else if (a == "--payload-bytes") payload_bytes = static_cast<size_t>(std::stoull(need("--payload-bytes")));
        else if (a == "--auto-manifest") auto_manifest = (need("--auto-manifest") != "0");
        else if (a == "--hmac-key") hmac_key = need("--hmac-key");
        else if (a == "--once") once = (need("--once") != "0");
        else if (a == "--help" || a == "-h") { usage(); return 0; }
        else { std::cerr << "Unknown arg: " << a << "\n"; usage(); return 2; }
    }

    if (mode != "sender" && mode != "receiver" && mode != "outbox" && mode != "inbox") {
        std::cerr << "Invalid or missing --mode\n";
        usage();
        return 2;
    }

    try {
        if (mode == "sender" || mode == "outbox") {
            fs::create_directories(outbox);
        }
        if (mode == "receiver" || mode == "outbox" || mode == "inbox") {
            fs::create_directories(inbox);
            fs::create_directories(receipts_out);
        }
        if (mode == "outbox") {
            fs::create_directories(outbox / ".sent");
            fs::create_directories(outbox / ".acks");
        }
    } catch (const std::exception& e) {
        std::cerr << "Failed to create required directories: " << e.what() << "\n";
        return 2;
    }

    Logger log;
    if (!log_file.empty()) {
        log.set_file(log_file);
    } else if (!log_dir.empty()) {
        log.set_file(log_dir / (mode + ".log"));
    }

    if (mode == "sender") {
        log.log_line("{\"service\":\"cds_audit\",\"mode\":\"sender\",\"outbox\":\"" +
                     json_escape(outbox.string()) + "\"}");
        while (true) {
            sender_pass(outbox, require_ready, hmac_key, log);
            if (once) break;
            wait_for_events_or_sleep({outbox}, poll_sec, use_inotify);
        }
    }

    if (mode == "receiver") {
        log.log_line("{\"service\":\"cds_audit\",\"mode\":\"receiver\",\"inbox\":\"" +
                     json_escape(inbox.string()) + "\",\"receipts_out\":\"" +
                     json_escape(receipts_out.string()) + "\"}");
        while (true) {
            receiver_pass(inbox, receipts_out, require_ready, hmac_key, log);
            if (once) break;
            wait_for_events_or_sleep({inbox}, poll_sec, use_inotify);
        }
    }

    if (mode == "outbox") {
        log.log_line("{\"service\":\"cds_audit\",\"mode\":\"outbox\",\"outbox\":\"" +
                     json_escape(outbox.string()) + "\",\"inbox\":\"" +
                     json_escape(inbox.string()) + "\",\"receipts_out\":\"" +
                     json_escape(receipts_out.string()) + "\"}");

        fs::path payload = outbox / payload_name;
        if (!fs::exists(payload)) {
            if (write_dummy_payload(payload, payload_bytes)) {
                touch_file(ready_path_for(payload));
                log.log_line("{\"event\":\"DUMMY_CREATED\",\"payload\":\"" +
                             json_escape(payload.string()) + "\"}");
            }
        }

        while (true) {
            outbox_pass(outbox, inbox, receipts_out, require_ready, stable_sec, hmac_key, log);
            if (once) break;
            wait_for_events_or_sleep({outbox, receipts_out}, poll_sec, use_inotify);
        }
    }

    // inbox
    log.log_line("{\"service\":\"cds_audit\",\"mode\":\"inbox\",\"inbox\":\"" +
                 json_escape(inbox.string()) + "\",\"receipts_out\":\"" +
                 json_escape(receipts_out.string()) + "\"}");
    while (true) {
        inbox_pass(inbox, receipts_out, require_ready, stable_sec, auto_manifest, hmac_key, log);
        if (once) break;
        wait_for_events_or_sleep({inbox}, poll_sec, use_inotify);
    }
}
