#pragma once
#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>
#include <vector>

#include <nlohmann/json.hpp>

#include "sentinel/logscan.hpp"
#include "sentinel/password.hpp"
#include "sentinel/result.hpp"
#include "sentinel/scanner.hpp"

namespace sentinel {

using json = nlohmann::json;

json to_json(const ScanSummary& s);
json to_json(const Finding& f);
json to_json(const LogScanResult& r);
json to_json(const PasswordResult& r);

// What changed between an earlier scan report and a new scan of the same target.
struct ScanDiff {
    std::vector<std::uint16_t> opened;   // open now, not open in the baseline
    std::vector<std::uint16_t> closed;   // open in the baseline, scanned now and no longer open
    std::size_t unchanged = 0;           // open in both
    std::string baseline_generated_at;
    bool changed() const { return !opened.empty() || !closed.empty(); }
};
// `baseline` is a saved scan report (the envelope written by save_report). `scanned_now` lists the
// ports of the new scan: a baseline port outside it counts as neither closed nor unchanged.
// Fails if the report is not a scan report or was taken against a different address.
Result<ScanDiff> diff_scan(const ScanSummary& now, const std::vector<std::uint16_t>& scanned_now, const json& baseline);
json to_json(const ScanDiff& d);

// Wraps data in the standard report envelope.
json make_envelope(const std::string& kind, const std::string& summary, json data);

// Writes <dir>/<kind>-<timestamp>.json (creating dir). Returns the file path.
std::filesystem::path save_report(const std::filesystem::path& dir, const json& envelope);

struct ReportInfo {
    std::string name;
    std::string kind;
    std::string generated_at;
    std::string summary;
};
std::vector<ReportInfo> list_reports(const std::filesystem::path& dir);  // newest first
// `name` must be a plain file name like scan-20240101-101010-123.json
std::optional<json> load_report(const std::filesystem::path& dir, const std::string& name);

std::string utc_now_iso();

}  // namespace sentinel
