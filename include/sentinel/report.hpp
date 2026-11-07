#pragma once
#include <filesystem>
#include <optional>
#include <string>
#include <vector>

#include <nlohmann/json.hpp>

#include "sentinel/logscan.hpp"
#include "sentinel/password.hpp"
#include "sentinel/scanner.hpp"

namespace sentinel {

using json = nlohmann::json;

json to_json(const ScanSummary& s);
json to_json(const Finding& f);
json to_json(const LogScanResult& r);
json to_json(const PasswordResult& r);

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
