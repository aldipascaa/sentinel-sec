#include <algorithm>
#include <cstdio>
#include <ctime>
#include <fstream>
#include <iostream>
#include <map>
#include <set>
#include <sstream>
#include <string>
#include <vector>

#include "sentinel/logscan.hpp"
#include "sentinel/platform.hpp"
#include "sentinel/rules.hpp"
#include "sentinel/password.hpp"
#include "sentinel/portrange.hpp"
#include "sentinel/report.hpp"
#include "sentinel/scanner.hpp"
#include "sentinel/version.hpp"
#ifdef SENTINEL_HAS_SERVER
#include "sentinel/server.hpp"
#endif

using namespace sentinel;

namespace {

const char* kWarning =
    "WARNING: Only scan hosts and networks that you own or are explicitly authorized to test.\n"
    "         Unauthorized scanning may be illegal.";

void usage(std::ostream& os) {
    os << "Sentinel " << SENTINEL_VERSION << " - defensive security toolkit (for YOUR OWN systems)\n\n"
          "Usage: sentinel <command> [options]\n\n"
          "Commands:\n"
          "  scan      TCP connect port scanner (default target 127.0.0.1)\n"
          "              --host H        target host (non-loopback requires --authorized)\n"
          "              --ports SPEC    e.g. 1-1024, 22,80,443, 8000-8100, common  (default 1-1024)\n"
          "              --timeout MS    per-connection timeout (default 500)\n"
          "              --threads N     worker threads, each multiplexing many sockets (default 4)\n"
          "              --concurrency N max connection attempts in flight (default 512, max 1024)\n"
          "              --family F      auto (IPv4 preferred), 4 or 6\n"
          "              --rate N        max connection attempts/sec (default 1000, 0 = unlimited)\n"
          "              --no-banner     skip banner grabbing\n"
          "              --authorized    confirm you are authorized to scan a non-loopback host\n"
          "  logscan   Detect brute force, injection probes and request spikes in logs\n"
          "              <file>...       auth (sshd/syslog) or web (combined) logs; '-' or none = stdin\n"
          "              --rules FILE    detection rules as JSON (default: built-in rules/default_rules.json)\n"
          "              --bf-threshold N (5)  --bf-window SEC (300)  --z Z (3.0)  --year YYYY\n"
          "  audit     Password strength auditor; reads one candidate per line\n"
          "              --file F        read from file (default: stdin)   --wordlist F  extra wordlist\n"
          "  serve     Local web dashboard on 127.0.0.1\n"
          "              --port N (8787)   --max-seconds N  auto-stop after N seconds   --rules FILE\n\n"
          "Common options:\n"
          "  --json          machine-readable output\n"
          "  --no-save       do not write a report file\n"
          "  --report-dir D  report directory (default: reports)\n"
          "  --version, --help\n";
}

struct Args {
    std::map<std::string, std::string> opts;
    std::set<std::string> flags;
    std::vector<std::string> positional;
    std::string error;

    bool flag(const std::string& k) const { return flags.count(k) > 0; }
    std::string get(const std::string& k, const std::string& def) const {
        auto it = opts.find(k);
        return it == opts.end() ? def : it->second;
    }
    int get_int(const std::string& k, int def) const {
        auto it = opts.find(k);
        if (it == opts.end()) return def;
        try {
            std::size_t pos = 0;
            int v = std::stoi(it->second, &pos);
            if (pos != it->second.size()) throw std::invalid_argument("x");
            return v;
        } catch (...) {
            throw std::invalid_argument("--" + k + " expects an integer, got '" + it->second + "'");
        }
    }
    double get_double(const std::string& k, double def) const {
        auto it = opts.find(k);
        if (it == opts.end()) return def;
        try {
            return std::stod(it->second);
        } catch (...) {
            throw std::invalid_argument("--" + k + " expects a number, got '" + it->second + "'");
        }
    }
};

Args parse_args(const std::vector<std::string>& v, std::size_t from) {
    static const std::set<std::string> bool_flags = {"json", "no-save", "no-banner", "authorized", "help"};
    Args a;
    for (std::size_t i = from; i < v.size(); ++i) {
        const std::string& t = v[i];
        if (t.rfind("--", 0) == 0 && t.size() > 2) {
            std::string key = t.substr(2), val;
            auto eq = key.find('=');
            if (eq != std::string::npos) {
                val = key.substr(eq + 1);
                key = key.substr(0, eq);
                a.opts[key] = val;
            } else if (bool_flags.count(key)) {
                a.flags.insert(key);
            } else if (i + 1 < v.size()) {
                a.opts[key] = v[++i];
            } else {
                a.error = "option --" + key + " requires a value";
            }
        } else {
            a.positional.push_back(t);
        }
    }
    return a;
}

void print_table(const std::vector<std::string>& head, const std::vector<std::vector<std::string>>& rows) {
    std::vector<std::size_t> w(head.size());
    for (std::size_t i = 0; i < head.size(); ++i) w[i] = head[i].size();
    for (const auto& r : rows)
        for (std::size_t i = 0; i < r.size(); ++i) w[i] = std::max(w[i], r[i].size());
    auto line = [&](const std::vector<std::string>& r) {
        for (std::size_t i = 0; i < r.size(); ++i) {
            std::cout << r[i];
            if (i + 1 < r.size()) std::cout << std::string(w[i] - r[i].size() + 2, ' ');
        }
        std::cout << "\n";
    };
    line(head);
    std::size_t total = 0;
    for (auto x : w) total += x + 2;
    std::cout << std::string(total > 2 ? total - 2 : 0, '-') << "\n";
    for (const auto& r : rows) line(r);
}

std::string fmt1(double v) {
    char b[32];
    std::snprintf(b, sizeof b, "%.1f", v);
    return b;
}

std::string iso_time(std::int64_t ts) {
    if (ts <= 0) return "";
    const std::tm tm = platform::utc_tm(static_cast<std::time_t>(ts));
    char b[32];
    std::strftime(b, sizeof b, "%m-%d %H:%M:%S", &tm);
    return b;
}

void maybe_save(const Args& a, const json& env) {
    if (a.flag("no-save")) return;
    try {
        auto p = save_report(a.get("report-dir", "reports"), env);
        std::cerr << "Report saved: " << p.string() << "\n";
    } catch (const std::exception& e) {
        std::cerr << "warning: could not save report: " << e.what() << "\n";
    }
}

int cmd_scan(const Args& a) {
    ScanOptions o;
    o.host = a.get("host", "127.0.0.1");
    o.ports = parse_port_ranges(a.get("ports", "1-1024"));
    o.timeout_ms = a.get_int("timeout", 500);
    o.threads = a.get_int("threads", o.threads);
    o.concurrency = a.get_int("concurrency", o.concurrency);
    const std::string fam = a.get("family", "auto");
    if (fam == "4") o.family = net::Family::IPv4;
    else if (fam == "6") o.family = net::Family::IPv6;
    else if (fam != "auto") throw std::invalid_argument("--family must be auto, 4 or 6");
    o.authorized = a.flag("authorized");
    o.rate_per_sec = a.get_int("rate", 1000);
    o.grab_banner = !a.flag("no-banner");
    if (o.timeout_ms < 1 || o.threads < 1 || o.concurrency < 1 || o.rate_per_sec < 0)
        throw std::invalid_argument("invalid timeout/threads/concurrency/rate");

    std::cerr << kWarning << "\n";
    if (!is_loopback_host(o.host) && !a.flag("authorized")) {
        std::cerr << "error: '" << o.host << "' is not a loopback address. Re-run with --authorized only if you own\n"
                  << "       this host or have written permission to test it.\n";
        return 2;
    }
    const bool tty = platform::is_tty(stderr) && !a.flag("json");
    auto progress = [&](std::size_t done, std::size_t total) {
        if (tty && (done % 64 == 0 || done == total)) std::fprintf(stderr, "\rScanning... %zu/%zu", done, total);
    };
    auto scan = run_scan(o, progress);
    if (!scan) {
        std::cerr << "error: " << scan.error().message << '\n';
        return scan.error().code == Errc::Unauthorized ? 2 : 1;
    }
    const ScanSummary& s = scan.value();
    if (tty) std::fprintf(stderr, "\r%40s\r", "");

    const std::string summary = std::to_string(s.open.size()) + " open of " + std::to_string(s.scanned) +
                                " ports on " + s.address;
    json env = make_envelope("scan", summary, to_json(s));
    if (a.flag("json")) {
        std::cout << env.dump(2) << "\n";
    } else {
        std::cout << "Target: " << s.host << " (" << s.address << ")  |  " << summary << "  |  "
                  << fmt1(s.elapsed_ms) << " ms\n\n";
        if (s.open.empty()) {
            std::cout << "No open ports found.\n";
        } else {
            std::vector<std::vector<std::string>> rows;
            for (const auto& p : s.open) rows.push_back({std::to_string(p.port), p.service, fmt1(p.rtt_ms), p.banner});
            print_table({"PORT", "SERVICE", "RTT(ms)", "BANNER"}, rows);
        }
    }
    maybe_save(a, env);
    return 0;
}

int current_year() {
    return platform::local_tm(std::time(nullptr)).tm_year + 1900;
}

// Built-in rules, or the file given with --rules. Returns false (after printing) on a bad file.
bool load_rules(const Args& a, RulesConfig& out) {
    out = default_rules();
    if (!a.opts.count("rules")) return true;
    auto r = load_rules_file(a.opts.at("rules"));
    if (!r) {
        std::cerr << "error: " << r.error().message << '\n';
        return false;
    }
    out = std::move(r).value();
    return true;
}

int cmd_logscan(const Args& a) {
    RulesConfig rules;
    if (!load_rules(a, rules)) return 2;
    DetectorConfig& cfg = rules.thresholds;  // command-line flags override the rules file
    cfg.bf_threshold = a.get_int("bf-threshold", cfg.bf_threshold);
    cfg.bf_window_sec = a.get_int("bf-window", cfg.bf_window_sec);
    cfg.z_threshold = a.get_double("z", cfg.z_threshold);
    const int year = a.get_int("year", current_year());

    std::vector<std::string> files = a.positional;
    if (a.opts.count("file")) files.push_back(a.opts.at("file"));
    std::string all;
    if (files.empty() || (files.size() == 1 && files[0] == "-")) {
        std::ostringstream ss;
        ss << std::cin.rdbuf();
        all = ss.str();
    } else {
        for (const auto& f : files) {
            std::ifstream in(f, std::ios::binary);
            if (!in) {
                std::cerr << "error: cannot open '" << f << "'\n";
                return 2;
            }
            std::ostringstream ss;
            ss << in.rdbuf();
            all += ss.str();
            if (!all.empty() && all.back() != '\n') all += '\n';
        }
    }
    std::istringstream is(all);
    auto scanned = analyze_log(is, rules, year);
    if (!scanned) {
        std::cerr << "error: " << scanned.error().message << '\n';
        return 2;
    }
    const LogScanResult& r = scanned.value();
    json data = to_json(r);
    data["files"] = files;
    const std::string summary = std::to_string(r.findings.size()) + " findings in " + std::to_string(r.lines_parsed) +
                                " parsed lines";
    json env = make_envelope("logscan", summary, data);
    if (a.flag("json")) {
        std::cout << env.dump(2) << "\n";
    } else {
        std::cout << summary << " (" << r.lines_unparsed << " lines ignored)\n\n";
        if (r.findings.empty()) {
            std::cout << "No anomalies detected.\n";
        } else {
            std::vector<std::vector<std::string>> rows;
            for (const auto& f : r.findings) {
                std::string sev = severity_name(f.severity);
                std::transform(sev.begin(), sev.end(), sev.begin(), [](unsigned char c) { return static_cast<char>(std::toupper(c)); });
                rows.push_back({sev, f.type, f.ip, f.line ? std::to_string(f.line) : "-", f.summary});
            }
            print_table({"SEVERITY", "TYPE", "SOURCE IP", "LINE", "DETAIL"}, rows);
        }
    }
    maybe_save(a, env);
    return 0;
}

int cmd_audit(const Args& a) {
    std::unordered_set<std::string> extra;
    if (a.opts.count("wordlist")) {
        extra = load_wordlist(a.opts.at("wordlist"));
        if (extra.empty()) std::cerr << "warning: wordlist empty or unreadable\n";
    }
    std::vector<std::string> cands;
    std::string line;
    auto read_all = [&](std::istream& in) {
        while (std::getline(in, line)) {
            if (!line.empty() && line.back() == '\r') line.pop_back();
            if (!line.empty()) cands.push_back(line);
        }
    };
    std::string file = a.get("file", a.positional.empty() ? "" : a.positional[0]);
    if (!file.empty()) {
        std::ifstream in(file);
        if (!in) {
            std::cerr << "error: cannot open '" << file << "'\n";
            return 2;
        }
        read_all(in);
    } else {
        if (platform::is_tty(stdin)) std::cerr << "Enter candidate passwords, one per line (Ctrl+Z then Enter to finish):\n";
        read_all(std::cin);
    }

    // Passwords are scored and immediately discarded: only scores are printed or saved.
    json items = json::array();
    std::vector<std::vector<std::string>> rows;
    int weak = 0, idx = 0;
    for (auto& c : cands) {
        PasswordResult r = audit_password(c, extra.empty() ? nullptr : &extra);
        std::fill(c.begin(), c.end(), '\0');
        ++idx;
        if (r.score <= 1) ++weak;
        json j = to_json(r);
        j["index"] = idx;
        items.push_back(j);
        std::string notes;
        for (const auto& p : r.patterns) notes += (notes.empty() ? "" : "; ") + p;
        if (notes.empty() && !r.feedback.empty()) notes = r.feedback.front();
        rows.push_back({std::to_string(idx), std::to_string(r.length), fmt1(r.entropy_bits),
                        std::to_string(r.score) + "/4 " + r.label, r.crack_time, notes});
    }
    cands.clear();
    const std::string summary = std::to_string(idx) + " passwords audited, " + std::to_string(weak) + " weak";
    json env = make_envelope("audit", summary, {{"audited", idx}, {"weak", weak}, {"results", items}});
    if (a.flag("json")) {
        std::cout << env.dump(2) << "\n";
    } else {
        std::cout << summary << " (passwords are never displayed or stored)\n\n";
        if (!rows.empty()) print_table({"#", "LEN", "BITS", "SCORE", "CRACK TIME", "NOTES"}, rows);
    }
    maybe_save(a, env);
    return 0;
}

int cmd_serve(const Args& a) {
#ifdef SENTINEL_HAS_SERVER
    ServerOptions o;
    if (!load_rules(a, o.rules)) return 2;
    o.port = a.get_int("port", 8787);
    o.report_dir = a.get("report-dir", "reports");
    o.max_seconds = a.get_int("max-seconds", 0);
    if (o.port < 1 || o.port > 65535) throw std::invalid_argument("--port must be 1-65535");
    return run_server(o);
#else
    (void)a;
    std::cerr << "error: this build was configured with SENTINEL_BUILD_SERVER=OFF\n";
    return 1;
#endif
}

}  // namespace

int main(int argc, char** argv) {
    std::vector<std::string> v(argv + 1, argv + argc);
    if (v.empty()) {
        usage(std::cerr);
        return 1;
    }
    const std::string cmd = v[0];
    if (cmd == "--version" || cmd == "-V" || cmd == "version") {
        std::cout << "sentinel " << SENTINEL_VERSION << "\n";
        return 0;
    }
    if (cmd == "--help" || cmd == "-h" || cmd == "help") {
        usage(std::cout);
        return 0;
    }
    try {
        Args a = parse_args(v, 1);
        if (!a.error.empty()) {
            std::cerr << "error: " << a.error << "\n";
            return 1;
        }
        if (a.flag("help")) {
            usage(std::cout);
            return 0;
        }
        if (cmd == "scan") return cmd_scan(a);
        if (cmd == "logscan") return cmd_logscan(a);
        if (cmd == "audit") return cmd_audit(a);
        if (cmd == "serve") return cmd_serve(a);
        std::cerr << "error: unknown command '" << cmd << "'\n\n";
        usage(std::cerr);
        return 1;
    } catch (const std::exception& e) {
        std::cerr << "error: " << e.what() << "\n";
        return 1;
    }
}
