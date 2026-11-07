#pragma once
#include <filesystem>
#include <string>
#include <string_view>

#include "sentinel/logscan.hpp"
#include "sentinel/result.hpp"

namespace sentinel {

// Rule file format (JSON). Every section is optional; omitted values keep their defaults,
// except "patterns", which - when present - replaces the default pattern list.
//
//   {
//     "version": 1,
//     "bruteforce": {"enabled": true, "threshold": 5, "window_seconds": 300},
//     "rate_spike": {"enabled": true, "z_threshold": 3.0, "bucket_seconds": 60, "min_requests": 20},
//     "patterns":   [{"id": "x", "type": "sqli", "label": "...", "severity": "high", "regex": "..."}]
//   }
//
// Validation: wrong types, unknown severities, duplicate ids and regexes that do not compile
// (or exceed kMaxRegexLength) are rejected with an Error naming the offending rule.
constexpr std::size_t kMaxRegexLength = 1000;

Result<RulesConfig> parse_rules(std::string_view json_text);
Result<RulesConfig> load_rules_file(const std::filesystem::path& file);

// The rules compiled into the binary (rules/default_rules.json). Always valid.
const RulesConfig& default_rules();
std::string_view default_rules_json();

bool parse_severity(std::string_view name, Severity& out);

}  // namespace sentinel
