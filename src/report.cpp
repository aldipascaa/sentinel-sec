#include "sentinel/report.hpp"

#include <algorithm>
#include <cmath>
#include <chrono>
#include <cstdio>
#include <ctime>
#include <fstream>
#include <regex>
#include <set>
#include <stdexcept>

#include "sentinel/platform.hpp"
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

Result<ScanDiff> diff_scan(const ScanSummary& now, const std::vector<std::uint16_t>& scanned_now, const json& baseline) {
    const auto bad = [](const std::string& why) { return make_error("baseline " + why, Errc::InvalidArgument); };
    if (!baseline.is_object() || baseline.value("kind", "") != "scan") return bad("is not a sentinel scan report");
    const auto data = baseline.find("data");
    if (data == baseline.end() || !data->is_object()) return bad("has no scan data");
    const auto ports = data->find("open_ports");
    if (ports == data->end() || !ports->is_array()) return bad("has no open_ports list");
    const auto addr = data->find("address");
    if (addr == data->end() || !addr->is_string()) return bad("has no target address");
    if (addr->get<std::string>() != now.address)
        return bad("was taken against " + addr->get<std::string>() + ", not " + now.address);

    std::set<std::uint16_t> before;
    for (const auto& p : *ports) {
        const auto port = p.is_object() ? p.find("port") : p.end();
        if (!p.is_object() || port == p.end() || !port->is_number_integer()) return bad("contains a malformed port entry");
        const auto n = port->get<long long>();
        if (n < 1 || n > 65535) return bad("contains port " + std::to_string(n) + ", which is out of range");
        before.insert(static_cast<std::uint16_t>(n));
    }
    std::set<std::uint16_t> open_now;
    for (const auto& p : now.open) open_now.insert(p.port);
    const std::set<std::uint16_t> scanned(scanned_now.begin(), scanned_now.end());

    ScanDiff d;
    const auto gen = baseline.find("generated_at");
    if (gen != baseline.end() && gen->is_string()) d.baseline_generated_at = gen->get<std::string>();
    for (const auto port : open_now) {
        if (before.count(port)) ++d.unchanged;
        else d.opened.push_back(port);
    }
    for (const auto port : before)
        if (!open_now.count(port) && scanned.count(port)) d.closed.push_back(port);
    return d;
}

json to_json(const ScanDiff& d) {
    return {{"baseline_generated_at", d.baseline_generated_at}, {"opened", d.opened}, {"closed", d.closed},
            {"unchanged", d.unchanged}, {"changed", d.changed()}};
}

std::string utc_now_iso() {
    const std::tm tm = platform::utc_tm(std::time(nullptr));
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
    const std::tm tm = platform::utc_tm(t);
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
    f << env.dump(2) << '\n';
    f.flush();
    if (!f) throw std::runtime_error("cannot write report " + p.string());
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
