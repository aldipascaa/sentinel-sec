#pragma once
#include <cstddef>
#include <cstdint>
#include <istream>
#include <optional>
#include <string>
#include <vector>

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

// Days since 1970-01-01 for a civil date (proleptic Gregorian).
std::int64_t days_from_civil(int y, int m, int d);

// Parses sshd/syslog-style auth lines and Apache/nginx combined access lines.
// default_year is used for syslog timestamps, which carry no year.
std::optional<LogEntry> parse_log_line(const std::string& line, int default_year, std::size_t line_no = 0);

std::string url_decode(const std::string& s);

std::vector<Finding> detect_bruteforce(const std::vector<LogEntry>& e, const DetectorConfig& cfg);
std::vector<Finding> detect_suspicious_paths(const std::vector<LogEntry>& e);
std::vector<Finding> detect_rate_spikes(const std::vector<LogEntry>& e, const DetectorConfig& cfg);

struct LogScanResult {
    std::size_t lines_total = 0;
    std::size_t lines_parsed = 0;
    std::size_t lines_unparsed = 0;
    std::vector<Finding> findings;  // sorted: severity desc, then line
};

LogScanResult analyze_log(std::istream& in, const DetectorConfig& cfg, int default_year);

}  // namespace sentinel
