#include "sentinel/logscan.hpp"

#include <algorithm>
#include <cmath>
#include <cstdio>
#include <ctime>
#include <map>
#include <regex>
#include <sstream>
#include <unordered_map>

namespace sentinel {

const char* severity_name(Severity s) {
    switch (s) {
        case Severity::Info: return "info";
        case Severity::Low: return "low";
        case Severity::Medium: return "medium";
        case Severity::High: return "high";
        case Severity::Critical: return "critical";
    }
    return "info";
}

std::int64_t days_from_civil(int y, int m, int d) {
    y -= m <= 2;
    const std::int64_t era = (y >= 0 ? y : y - 399) / 400;
    const unsigned yoe = static_cast<unsigned>(y - era * 400);
    const unsigned doy = static_cast<unsigned>((153 * (m + (m > 2 ? -3 : 9)) + 2) / 5 + d - 1);
    const unsigned doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    return era * 146097 + static_cast<std::int64_t>(doe) - 719468;
}

namespace {

int month_index(const std::string& m) {
    static const char* names[] = {"Jan", "Feb", "Mar", "Apr", "May", "Jun",
                                  "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"};
    for (int i = 0; i < 12; ++i)
        if (m == names[i]) return i + 1;
    return 0;
}

std::int64_t to_epoch(int y, int mo, int d, int h, int mi, int s) {
    return days_from_civil(y, mo, d) * 86400 + h * 3600 + mi * 60 + s;
}

const std::regex& syslog_re() {
    static const std::regex re(R"(^([A-Z][a-z]{2})\s+(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})\s+\S+\s+[^:\s]+:\s+(.*)$)");
    return re;
}
const std::regex& failed_re() {
    static const std::regex re(R"(Failed (?:password|publickey|keyboard-interactive/pam) for (?:invalid user )?(\S+) from (\S+))");
    return re;
}
const std::regex& accepted_re() {
    static const std::regex re(R"(Accepted \S+ for (\S+) from (\S+))");
    return re;
}
const std::regex& web_re() {
    static const std::regex re(R"re(^(\S+) \S+ (\S+) \[([^\]]+)\] "(\S+) (\S+)(?: [^"]*)?" (\d{3}) )re");
    return re;
}

}  // namespace

std::string url_decode(const std::string& s) {
    std::string out;
    out.reserve(s.size());
    auto hex = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    };
    for (std::size_t i = 0; i < s.size(); ++i) {
        if (s[i] == '%' && i + 2 < s.size() + 0 && hex(s[i + 1]) >= 0 && hex(s[i + 2]) >= 0) {
            out.push_back(static_cast<char>(hex(s[i + 1]) * 16 + hex(s[i + 2])));
            i += 2;
        } else if (s[i] == '+') {
            out.push_back(' ');
        } else {
            out.push_back(s[i]);
        }
    }
    return out;
}

std::optional<LogEntry> parse_log_line(const std::string& line, int default_year, std::size_t line_no) {
    std::smatch m;
    if (std::regex_search(line, m, syslog_re())) {
        const int mon = month_index(m[1].str());
        if (mon == 0) return std::nullopt;
        const std::string msg = m[6].str();
        std::smatch a;
        LogEntry e;
        e.line = line_no;
        e.kind = LogKind::Auth;
        e.ts = to_epoch(default_year, mon, std::stoi(m[2]), std::stoi(m[3]), std::stoi(m[4]), std::stoi(m[5]));
        if (std::regex_search(msg, a, failed_re())) {
            e.auth_failed = true;
        } else if (std::regex_search(msg, a, accepted_re())) {
            e.auth_success = true;
        } else {
            return std::nullopt;
        }
        e.user = a[1].str();
        e.ip = a[2].str();
        return e;
    }
    if (std::regex_search(line, m, web_re())) {
        static const std::regex ts_re(R"((\d{1,2})/([A-Za-z]{3})/(\d{4}):(\d{2}):(\d{2}):(\d{2})(?: ([+-])(\d{2})(\d{2}))?)");
        const std::string ts = m[3].str();
        std::smatch t;
        if (!std::regex_search(ts, t, ts_re)) return std::nullopt;
        const int mo = month_index(t[2].str());
        if (mo == 0) return std::nullopt;
        int off = 0;
        if (t[7].matched)
            off = (std::stoi(t[8]) * 3600 + std::stoi(t[9]) * 60) * (t[7].str() == "-" ? -1 : 1);
        const int d = std::stoi(t[1]), y = std::stoi(t[3]), h = std::stoi(t[4]), mi = std::stoi(t[5]),
                  s = std::stoi(t[6]);
        if (mo == 0) return std::nullopt;
        LogEntry e;
        e.line = line_no;
        e.kind = LogKind::Web;
        e.ip = m[1].str();
        e.user = m[2].str();
        e.method = m[4].str();
        e.path = m[5].str();
        e.status = std::stoi(m[6]);
        e.ts = to_epoch(y, mo, d, h, mi, s) - off;
        if (e.status == 401) e.auth_failed = true;
        return e;
    }
    return std::nullopt;
}

std::vector<Finding> detect_bruteforce(const std::vector<LogEntry>& entries, const DetectorConfig& cfg) {
    std::map<std::string, std::vector<const LogEntry*>> fails;
    std::map<std::string, std::vector<const LogEntry*>> successes;
    for (const auto& e : entries) {
        if (e.auth_failed) fails[e.ip].push_back(&e);
        if (e.auth_success && e.kind == LogKind::Auth) successes[e.ip].push_back(&e);
    }
    const int threshold = std::max(cfg.bf_threshold, 1);
    std::vector<Finding> out;
    for (auto& [ip, v] : fails) {
        std::sort(v.begin(), v.end(), [](auto* a, auto* b) { return a->ts < b->ts; });
        std::size_t lo = 0, best = 0, best_end = 0;
        for (std::size_t hi = 0; hi < v.size(); ++hi) {
            while (v[hi]->ts - v[lo]->ts > cfg.bf_window_sec) ++lo;
            if (hi - lo + 1 > best) {
                best = hi - lo + 1;
                best_end = hi;
            }
        }
        if (best < static_cast<std::size_t>(threshold)) continue;
        Finding f;
        f.type = "brute-force";
        f.ip = ip;
        f.severity = best >= static_cast<std::size_t>(threshold) * 4 ? Severity::Critical : Severity::High;
        f.line = v[best_end]->line;
        f.ts = v[best_end]->ts;
        f.summary = std::to_string(best) + " failed logins from " + ip + " within " +
                    std::to_string(cfg.bf_window_sec) + "s (threshold " + std::to_string(threshold) + ")";
        out.push_back(f);

        auto it = successes.find(ip);
        if (it != successes.end()) {
            for (const auto* s : it->second) {
                if (s->ts >= v.front()->ts) {
                    Finding c;
                    c.type = "brute-force-success";
                    c.ip = ip;
                    c.severity = Severity::Critical;
                    c.line = s->line;
                    c.ts = s->ts;
                    c.summary = "Successful login for '" + s->user + "' from " + ip +
                                " after a brute-force pattern - possible account compromise";
                    out.push_back(c);
                    break;
                }
            }
        }
    }
    return out;
}

namespace {

struct Pattern {
    const char* type;
    const char* label;
    Severity severity;
    std::regex re;
};

const std::vector<Pattern>& patterns() {
    static const std::vector<Pattern> p = [] {
        auto rx = [](const char* s) { return std::regex(s, std::regex::ECMAScript | std::regex::icase); };
        std::vector<Pattern> v;
        v.push_back({"sqli", "SQL injection (UNION SELECT)", Severity::High,
                     rx(R"(union(\s|/\*.*?\*/)+(all\s+)?select)")});
        v.push_back({"sqli", "SQL injection (boolean tautology)", Severity::High,
                     rx(R"((['"]\s*)?\b(or|and)\b\s+['"]?\d+['"]?\s*=\s*['"]?\d+|['"]\s*or\s*['"][^'"]*['"]\s*=\s*['"])")});
        v.push_back({"sqli", "SQL injection (time/meta functions)", Severity::High,
                     rx(R"(sleep\s*\(\s*\d+|benchmark\s*\(|information_schema|;\s*drop\s+table|xp_cmdshell)")});
        v.push_back({"xss", "Cross-site scripting", Severity::Medium,
                     rx(R"(<\s*script|javascript\s*:|\bon(error|load|mouseover|focus)\s*=|<\s*(img|svg|iframe)[^>]*>)")});
        v.push_back({"path-traversal", "Path traversal", Severity::High,
                     rx(R"(\.\.[/\\]|/etc/(passwd|shadow)|boot\.ini|win\.ini|\.\.%2f)")});
        v.push_back({"cmd-injection", "Command injection", Severity::High,
                     rx(R"((;|\||&&|`|\$\()\s*(cat|ls|id|whoami|wget|curl|nc|bash|sh|powershell|cmd)\b)")});
        v.push_back({"recon", "Sensitive file / admin probe", Severity::Low,
                     rx(R"((^|/)(\.env|\.git/|\.htpasswd|wp-login\.php|phpmyadmin|server-status|\.aws/credentials))")});
        return v;
    }();
    return p;
}

}  // namespace

std::vector<Finding> detect_suspicious_paths(const std::vector<LogEntry>& entries) {
    std::vector<Finding> out;
    for (const auto& e : entries) {
        if (e.kind != LogKind::Web) continue;
        std::string decoded = url_decode(url_decode(e.path));  // handle double encoding
        for (const auto& p : patterns()) {
            if (!std::regex_search(decoded, p.re)) continue;
            Finding f;
            f.type = p.type;
            f.ip = e.ip;
            f.line = e.line;
            f.ts = e.ts;
            f.severity = p.severity;
            // A traversal / injection that got a 200 is more worrying.
            if (e.status >= 200 && e.status < 300 && p.severity >= Severity::High) f.severity = Severity::Critical;
            std::string shown = decoded.size() > 90 ? decoded.substr(0, 87) + "..." : decoded;
            f.summary = std::string(p.label) + ": " + e.method + " " + shown + " -> " + std::to_string(e.status);
            out.push_back(f);
            break;  // one finding per request
        }
    }
    return out;
}

std::vector<Finding> detect_rate_spikes(const std::vector<LogEntry>& entries, const DetectorConfig& cfg) {
    std::vector<Finding> out;
    const int bucket = std::max(cfg.bucket_sec, 1);
    std::map<std::int64_t, std::size_t> counts;
    std::map<std::int64_t, std::unordered_map<std::string, std::size_t>> by_ip;
    for (const auto& e : entries) {
        if (e.kind != LogKind::Web) continue;
        const std::int64_t b = e.ts / bucket;
        ++counts[b];
        ++by_ip[b][e.ip];
    }
    if (counts.size() < 2) return out;
    const std::int64_t first = counts.begin()->first, last = counts.rbegin()->first;
    const std::int64_t n = last - first + 1;  // empty buckets count as zero
    if (n < 8) return out;
    double sum = 0;
    for (const auto& [b, c] : counts) sum += static_cast<double>(c);
    const double mean = sum / static_cast<double>(n);
    double var = 0;
    for (std::int64_t b = first; b <= last; ++b) {
        auto it = counts.find(b);
        const double c = it == counts.end() ? 0.0 : static_cast<double>(it->second);
        var += (c - mean) * (c - mean);
    }
    const double sd = std::sqrt(var / static_cast<double>(n));
    if (sd <= 0) return out;
    for (const auto& [b, c] : counts) {
        const double z = (static_cast<double>(c) - mean) / sd;
        if (z < cfg.z_threshold || c < static_cast<std::size_t>(cfg.min_spike_requests)) continue;
        std::string top_ip;
        std::size_t top = 0;
        for (const auto& [ip, k] : by_ip[b])
            if (k > top) top = k, top_ip = ip;
        char zb[32], mb[32];
        std::snprintf(zb, sizeof zb, "%.1f", z);
        std::snprintf(mb, sizeof mb, "%.1f", mean);
        Finding f;
        f.type = "rate-spike";
        f.ip = top_ip;
        f.ts = b * bucket;
        f.severity = z >= 6.0 ? Severity::High : Severity::Medium;
        f.summary = std::to_string(c) + " requests in " + std::to_string(bucket) + "s bucket (z=" + zb +
                    ", mean " + mb + "); top source " + top_ip + " with " + std::to_string(top);
        out.push_back(f);
    }
    return out;
}

LogScanResult analyze_log(std::istream& in, const DetectorConfig& cfg, int default_year) {
    LogScanResult r;
    std::vector<LogEntry> entries;
    std::string line;
    std::size_t no = 0;
    while (std::getline(in, line)) {
        ++no;
        if (!line.empty() && line.back() == '\r') line.pop_back();
        if (line.empty()) continue;
        ++r.lines_total;
        if (auto e = parse_log_line(line, default_year, no)) {
            entries.push_back(std::move(*e));
            ++r.lines_parsed;
        } else {
            ++r.lines_unparsed;
        }
    }
    auto add = [&](std::vector<Finding> v) { r.findings.insert(r.findings.end(), v.begin(), v.end()); };
    add(detect_bruteforce(entries, cfg));
    add(detect_suspicious_paths(entries));
    add(detect_rate_spikes(entries, cfg));
    std::stable_sort(r.findings.begin(), r.findings.end(), [](const Finding& a, const Finding& b) {
        if (a.severity != b.severity) return a.severity > b.severity;
        return a.line < b.line;
    });
    return r;
}

}  // namespace sentinel
