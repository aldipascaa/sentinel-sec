#include "sentinel/report.hpp"

#include <algorithm>
#include <cmath>
#include <chrono>
#include <cstdio>
#include <ctime>
#include <fstream>
#include <regex>

#include "sentinel/version.hpp"

namespace sentinel {

namespace {
double round1(double v) { return std::round(v * 10.0) / 10.0; }
}  // namespace

json to_json(const ScanSummary& s) {
    json open = json::array();
    for (const auto& p : s.open)
        open.push_back({{"port", p.port}, {"service", p.service}, {"banner", p.banner}, {"rtt_ms", round1(p.rtt_ms)}});
    return {{"host", s.host},
            {"address", s.address},
            {"ports_scanned", s.scanned},
            {"open_count", s.open.size()},
            {"elapsed_ms", round1(s.elapsed_ms)},
            {"open_ports", open}};
}

json to_json(const Finding& f) {
    return {{"severity", severity_name(f.severity)}, {"type", f.type}, {"ip", f.ip},
            {"summary", f.summary}, {"line", f.line}, {"timestamp", f.ts}};
}

json to_json(const LogScanResult& r) {
    json counts = {{"critical", 0}, {"high", 0}, {"medium", 0}, {"low", 0}, {"info", 0}};
    json findings = json::array();
    for (const auto& f : r.findings) {
        counts[severity_name(f.severity)] = counts[severity_name(f.severity)].get<int>() + 1;
        findings.push_back(to_json(f));
    }
    return {{"lines_total", r.lines_total}, {"lines_parsed", r.lines_parsed},
            {"lines_ignored", r.lines_unparsed}, {"counts", counts}, {"findings", findings}};
}

json to_json(const PasswordResult& r) {
    return {{"length", r.length},       {"entropy_bits", round1(r.entropy_bits)},
            {"raw_entropy_bits", round1(r.raw_entropy_bits)}, {"score", r.score},
            {"label", r.label},         {"common", r.common},
            {"patterns", r.patterns},   {"feedback", r.feedback},
            {"crack_time", r.crack_time}};
}

std::string utc_now_iso() {
    std::time_t t = std::time(nullptr);
    std::tm tm{};
    gmtime_s(&tm, &t);
    char b[32];
    std::strftime(b, sizeof b, "%Y-%m-%dT%H:%M:%SZ", &tm);
    return b;
}

json make_envelope(const std::string& kind, const std::string& summary, json data) {
    return {{"tool", "sentinel"}, {"version", SENTINEL_VERSION}, {"kind", kind},
            {"generated_at", utc_now_iso()}, {"summary", summary}, {"data", std::move(data)}};
}

std::filesystem::path save_report(const std::filesystem::path& dir, const json& env) {
    namespace fs = std::filesystem;
    fs::create_directories(dir);
    using namespace std::chrono;
    const auto now = system_clock::now();
    const std::time_t t = system_clock::to_time_t(now);
    const auto ms = duration_cast<milliseconds>(now.time_since_epoch()).count() % 1000;
    std::tm tm{};
    gmtime_s(&tm, &t);
    char stamp[48];
    std::strftime(stamp, sizeof stamp, "%Y%m%d-%H%M%S", &tm);
    const std::string kind = env.value("kind", "report");
    fs::path p;
    for (int i = 0;; ++i) {
        char name[128];
        std::snprintf(name, sizeof name, "%s-%s-%03d%s.json", kind.c_str(), stamp, static_cast<int>(ms),
                      i ? ("-" + std::to_string(i)).c_str() : "");
        p = dir / name;
        if (!fs::exists(p)) break;
    }
    std::ofstream f(p, std::ios::binary);
    f << env.dump(2) << "\n";
    return p;
}

std::vector<ReportInfo> list_reports(const std::filesystem::path& dir) {
    namespace fs = std::filesystem;
    std::vector<ReportInfo> out;
    std::error_code ec;
    if (!fs::is_directory(dir, ec)) return out;
    for (const auto& de : fs::directory_iterator(dir, ec)) {
        if (!de.is_regular_file() || de.path().extension() != ".json") continue;
        ReportInfo ri;
        ri.name = de.path().filename().string();
        try {
            std::ifstream f(de.path(), std::ios::binary);
            json j = json::parse(f);
            ri.kind = j.value("kind", "");
            ri.generated_at = j.value("generated_at", "");
            ri.summary = j.value("summary", "");
        } catch (...) {
            continue;
        }
        out.push_back(std::move(ri));
    }
    std::sort(out.begin(), out.end(), [](const ReportInfo& a, const ReportInfo& b) { return a.name > b.name; });
    return out;
}

std::optional<json> load_report(const std::filesystem::path& dir, const std::string& name) {
    static const std::regex ok(R"(^[a-z]+-\d{8}-\d{6}-\d{3}(-\d+)?\.json$)");
    if (!std::regex_match(name, ok)) return std::nullopt;
    std::ifstream f(dir / name, std::ios::binary);
    if (!f) return std::nullopt;
    try {
        return json::parse(f);
    } catch (...) {
        return std::nullopt;
    }
}

}  // namespace sentinel
