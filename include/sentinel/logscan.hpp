#pragma once
#include <cstddef>
#include <cstdint>
#include <functional>
#include <istream>
#include <map>
#include <memory>
#include <optional>
#include <set>
#include <span>
#include <string_view>
#include <string>
#include <vector>

#include "sentinel/result.hpp"

namespace sentinel {

enum class Severity { Info, Low, Medium, High, Critical };
const char* severity_name(Severity s);  // "info" ... "critical"

enum class LogKind { Auth, Web };

struct LogEntry {
    std::size_t line = 0;
    std::int64_t ts = 0;  // seconds since Unix epoch (UTC)
    LogKind kind = LogKind::Auth;
    std::string ip;
    std::string user;
    bool auth_failed = false;
    bool auth_success = false;
    std::string method;
    std::string path;
    int status = 0;
};

struct Finding {
    Severity severity = Severity::Info;
    std::string type;  // e.g. "brute-force", "sqli", "rate-spike"
    std::string ip;
    std::string summary;
    std::size_t line = 0;  // 0 = not tied to a single line
    std::int64_t ts = 0;
};

struct DetectorConfig {
    int bf_threshold = 5;       // failed logins from one IP ...
    int bf_window_sec = 300;    // ... within this window
    double z_threshold = 3.0;   // request-rate z-score
    int bucket_sec = 60;        // rate bucket width
    int min_spike_requests = 20;
};

// A configurable regex rule applied to URL-decoded request paths of web logs.
struct PatternRule {
    std::string id;     // unique, e.g. "sqli-union"
    std::string type;   // reported as Finding::type, e.g. "sqli"
    std::string label;  // human-readable description
    Severity severity = Severity::Medium;
    std::string regex;  // ECMAScript, matched case-insensitively
};

// Everything that tunes detection. Loaded from JSON (see rules.hpp); defaults ship with the library.
struct RulesConfig {
    DetectorConfig thresholds;
    std::vector<PatternRule> patterns;
    std::set<std::string> disabled;  // detector ids switched off: "bruteforce", "patterns", "rate-spike"
};

// Days since 1970-01-01 for a civil date (proleptic Gregorian).
std::int64_t days_from_civil(int y, int m, int d);

// Parses sshd/syslog-style auth lines and Apache/nginx combined access lines.
// default_year is used for syslog timestamps, which carry no year.
std::optional<LogEntry> parse_log_line(const std::string& line, int default_year, std::size_t line_no = 0);

std::string url_decode(const std::string& s);

// ---- detector extension point ------------------------------------------------------------
class Detector {
public:
    virtual ~Detector() = default;
    virtual std::string_view id() const = 0;
    virtual std::vector<Finding> analyze(std::span<const LogEntry> entries) const = 0;
};

// Maps detector ids to factories. Register your own detector with register_factory(); the
// built-in registry already contains "bruteforce", "patterns" and "rate-spike".
class DetectorRegistry {
public:
    using Factory = std::function<std::unique_ptr<Detector>(const RulesConfig&)>;
    void register_factory(std::string id, Factory f);
    std::vector<std::string> ids() const;
    // Builds all enabled detectors. Returns an Error (never throws) if a factory fails,
    // e.g. because a rule contains an invalid regex.
    Result<std::vector<std::unique_ptr<Detector>>> create_all(const RulesConfig& cfg) const;
    static const DetectorRegistry& builtin();

private:
    std::map<std::string, Factory> factories_;
};

// Convenience wrappers around the built-in detectors.
std::vector<Finding> detect_bruteforce(const std::vector<LogEntry>& e, const DetectorConfig& cfg);
std::vector<Finding> detect_suspicious_paths(const std::vector<LogEntry>& e);  // default pattern rules
std::vector<Finding> detect_rate_spikes(const std::vector<LogEntry>& e, const DetectorConfig& cfg);

struct LogScanResult {
    std::size_t lines_total = 0;
    std::size_t lines_parsed = 0;
    std::size_t lines_unparsed = 0;
    std::vector<Finding> findings;  // sorted: severity desc, then line
};

// Full pipeline with default rules and the given thresholds.
LogScanResult analyze_log(std::istream& in, const DetectorConfig& cfg, int default_year);
// Full pipeline with explicit rules and registry; fails only if a detector cannot be built.
Result<LogScanResult> analyze_log(std::istream& in, const RulesConfig& rules, int default_year,
                                  const DetectorRegistry& registry = DetectorRegistry::builtin());

}  // namespace sentinel
