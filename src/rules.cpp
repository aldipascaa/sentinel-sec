#include "sentinel/rules.hpp"

#include <fstream>
#include <regex>
#include <sstream>

#include <nlohmann/json.hpp>

#include "sentinel/embedded.hpp"

namespace sentinel {
namespace {

using json = nlohmann::json;

template <class T>
Result<T> invalid(const std::string& msg) {
    return make_error("invalid rules: " + msg, Errc::InvalidArgument);
}

// Reads an optional numeric field into `out`, enforcing [lo, hi]. Returns an error message or "".
template <class T>
std::string read_num(const json& obj, const char* section, const char* key, T lo, T hi, T& out) {
    auto it = obj.find(key);
    if (it == obj.end()) return {};
    if (!it->is_number()) return std::string(section) + "." + key + " must be a number";
    const double v = it->get<double>();
    if (v < static_cast<double>(lo) || v > static_cast<double>(hi))
        return std::string(section) + "." + key + " out of range [" + std::to_string(lo) + ", " + std::to_string(hi) + "]";
    out = static_cast<T>(v);
    return {};
}

}  // namespace

bool parse_severity(std::string_view name, Severity& out) {
    static const std::pair<std::string_view, Severity> table[] = {
        {"info", Severity::Info}, {"low", Severity::Low}, {"medium", Severity::Medium},
        {"high", Severity::High}, {"critical", Severity::Critical}};
    for (const auto& [n, s] : table)
        if (n == name) {
            out = s;
            return true;
        }
    return false;
}

std::string_view default_rules_json() {
    for (std::size_t i = 0; i < kRulesAssetsCount; ++i)
        if (std::string_view(kRulesAssets[i].name) == "default_rules.json")
            return {reinterpret_cast<const char*>(kRulesAssets[i].data), kRulesAssets[i].size};
    return {};
}

namespace {

// `base` supplies defaults for omitted sections; null while parsing the shipped defaults themselves.
Result<RulesConfig> parse_impl(std::string_view text, const RulesConfig* base) {
    json doc;
    try {
        doc = json::parse(text);
    } catch (const std::exception& e) {
        return invalid<RulesConfig>(std::string("not valid JSON: ") + e.what());
    }
    if (!doc.is_object()) return invalid<RulesConfig>("top level must be an object");

    RulesConfig cfg;
    if (base) cfg = *base;

    std::string err;
    if (auto it = doc.find("bruteforce"); it != doc.end()) {
        if (!it->is_object()) return invalid<RulesConfig>("bruteforce must be an object");
        if (it->value("enabled", true) == false) cfg.disabled.insert("bruteforce");
        else cfg.disabled.erase("bruteforce");
        if (!(err = read_num(*it, "bruteforce", "threshold", 1, 100000, cfg.thresholds.bf_threshold)).empty() ||
            !(err = read_num(*it, "bruteforce", "window_seconds", 1, 86400 * 7, cfg.thresholds.bf_window_sec)).empty())
            return invalid<RulesConfig>(err);
    }
    if (auto it = doc.find("rate_spike"); it != doc.end()) {
        if (!it->is_object()) return invalid<RulesConfig>("rate_spike must be an object");
        if (it->value("enabled", true) == false) cfg.disabled.insert("rate-spike");
        else cfg.disabled.erase("rate-spike");
        if (!(err = read_num(*it, "rate_spike", "z_threshold", 0.1, 100.0, cfg.thresholds.z_threshold)).empty() ||
            !(err = read_num(*it, "rate_spike", "bucket_seconds", 1, 86400, cfg.thresholds.bucket_sec)).empty() ||
            !(err = read_num(*it, "rate_spike", "min_requests", 1, 10000000, cfg.thresholds.min_spike_requests)).empty())
            return invalid<RulesConfig>(err);
    }

    auto pit = doc.find("patterns");
    if (pit != doc.end()) {
        cfg.patterns.clear();
        if (!pit->is_array()) return invalid<RulesConfig>("patterns must be an array");
        std::set<std::string> seen;
        for (const auto& r : *pit) {
            if (!r.is_object()) return invalid<RulesConfig>("each pattern must be an object");
            PatternRule pr;
            for (const char* key : {"id", "type", "label", "severity", "regex"}) {
                auto f = r.find(key);
                if (f == r.end() || !f->is_string() || f->get<std::string>().empty())
                    return invalid<RulesConfig>(std::string("pattern is missing string field '") + key + "'" +
                                                (r.contains("id") && r["id"].is_string() ? " (id " + r["id"].get<std::string>() + ")" : ""));
            }
            pr.id = r["id"].get<std::string>();
            pr.type = r["type"].get<std::string>();
            pr.label = r["label"].get<std::string>();
            pr.regex = r["regex"].get<std::string>();
            if (!parse_severity(r["severity"].get<std::string>(), pr.severity))
                return invalid<RulesConfig>("pattern '" + pr.id + "' has unknown severity '" + r["severity"].get<std::string>() + "'");
            if (!seen.insert(pr.id).second) return invalid<RulesConfig>("duplicate pattern id '" + pr.id + "'");
            if (pr.regex.size() > kMaxRegexLength)
                return invalid<RulesConfig>("pattern '" + pr.id + "' regex longer than " + std::to_string(kMaxRegexLength));
            try {
                std::regex probe(pr.regex, std::regex::ECMAScript | std::regex::icase);
            } catch (const std::regex_error& e) {
                return invalid<RulesConfig>("pattern '" + pr.id + "' has an invalid regex: " + e.what());
            }
            cfg.patterns.push_back(std::move(pr));
        }
    }
    return cfg;
}

}  // namespace

Result<RulesConfig> parse_rules(std::string_view text) { return parse_impl(text, &default_rules()); }

Result<RulesConfig> load_rules_file(const std::filesystem::path& file) {
    std::ifstream in(file, std::ios::binary);
    if (!in) return make_error("cannot open rules file '" + file.string() + "'", Errc::InvalidArgument);
    std::ostringstream ss;
    ss << in.rdbuf();
    if (ss.str().size() > 1024 * 1024) return make_error("rules file too large (max 1 MiB)", Errc::InvalidArgument);
    return parse_rules(ss.str());
}

const RulesConfig& default_rules() {
    static const RulesConfig cfg = [] {
        // The embedded file lists all patterns, so parsing it never recurses into default_rules().
        auto r = parse_impl(default_rules_json(), nullptr);
        return r ? std::move(r).value() : RulesConfig{};
    }();
    return cfg;
}

}  // namespace sentinel
