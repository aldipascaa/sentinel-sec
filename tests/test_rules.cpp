#include <gtest/gtest.h>

#include <filesystem>
#include <fstream>
#include <sstream>

#include "sentinel/logscan.hpp"
#include "sentinel/rules.hpp"

using namespace sentinel;

namespace {
Result<LogScanResult> run(const std::string& text, const RulesConfig& cfg) {
    std::istringstream is(text);
    return analyze_log(is, cfg, 2024);
}
std::string web(const std::string& ip, const std::string& path, int status = 404) {
    return ip + " - - [10/Oct/2023:13:00:00 +0000] \"GET " + path + " HTTP/1.1\" " + std::to_string(status) +
           " 512 \"-\" \"curl\"\n";
}
std::string fails(int n) {
    std::string s;
    for (int i = 0; i < n; ++i)
        s += "Nov  3 10:00:" + std::string(i < 10 ? "0" : "") + std::to_string(i) +
             " h sshd[1]: Failed password for root from 9.9.9.9 port 1 ssh2\n";
    return s;
}
}  // namespace

TEST(Rules, ShippedDefaultsParseAndMatchBuiltInBehaviour) {
    const RulesConfig& d = default_rules();
    EXPECT_GE(d.patterns.size(), 7u);
    EXPECT_EQ(d.thresholds.bf_threshold, 5);
    EXPECT_EQ(d.thresholds.bf_window_sec, 300);
    EXPECT_DOUBLE_EQ(d.thresholds.z_threshold, 3.0);
    EXPECT_TRUE(d.disabled.empty());
    EXPECT_FALSE(default_rules_json().empty());
}

TEST(Rules, OverridesThresholdsAndKeepsDefaultPatterns) {
    auto r = parse_rules(R"({"bruteforce": {"threshold": 3, "window_seconds": 60}})");
    ASSERT_TRUE(r) << r.error().message;
    EXPECT_EQ(r.value().thresholds.bf_threshold, 3);
    EXPECT_EQ(r.value().thresholds.bf_window_sec, 60);
    EXPECT_EQ(r.value().patterns.size(), default_rules().patterns.size());
    // ...and the lower threshold is honoured by the detector pipeline.
    auto scan = run(fails(3), r.value());
    ASSERT_TRUE(scan);
    ASSERT_EQ(scan.value().findings.size(), 1u);
    EXPECT_EQ(scan.value().findings[0].type, "brute-force");
}

TEST(Rules, CustomPatternsReplaceDefaults) {
    auto r = parse_rules(R"({"patterns":[
        {"id":"canary","type":"canary","label":"Canary URL hit","severity":"critical","regex":"/secret-canary"}]})");
    ASSERT_TRUE(r) << r.error().message;
    ASSERT_EQ(r.value().patterns.size(), 1u);
    auto scan = run(web("1.2.3.4", "/secret-canary") + web("1.2.3.4", "/a?q=union select 1"), r.value());
    ASSERT_TRUE(scan);
    ASSERT_EQ(scan.value().findings.size(), 1u);  // sqli no longer matches: it was replaced
    EXPECT_EQ(scan.value().findings[0].type, "canary");
    EXPECT_EQ(scan.value().findings[0].severity, Severity::Critical);
}

TEST(Rules, PatternsAreCaseInsensitiveAndOperateOnDecodedPaths) {
    auto r = parse_rules(R"({"patterns":[
        {"id":"x","type":"t","label":"L","severity":"low","regex":"<script"}]})");
    ASSERT_TRUE(r);
    auto scan = run(web("1.1.1.1", "/%253CSCRIPT%253E"), r.value());  // double-encoded
    ASSERT_TRUE(scan);
    EXPECT_EQ(scan.value().findings.size(), 1u);
}

TEST(Rules, RejectsInvalidInput) {
    EXPECT_FALSE(parse_rules("not json"));
    EXPECT_FALSE(parse_rules("[]"));
    EXPECT_FALSE(parse_rules(R"({"bruteforce": 5})"));
    EXPECT_FALSE(parse_rules(R"({"bruteforce": {"threshold": 0}})"));
    EXPECT_FALSE(parse_rules(R"({"bruteforce": {"threshold": "x"}})"));
    EXPECT_FALSE(parse_rules(R"({"rate_spike": {"z_threshold": -1}})"));
    EXPECT_FALSE(parse_rules(R"({"patterns": {}})"));
    // missing field
    EXPECT_FALSE(parse_rules(R"({"patterns":[{"id":"a","type":"t","label":"l","severity":"low"}]})"));
    // bad severity
    auto sev = parse_rules(R"({"patterns":[{"id":"a","type":"t","label":"l","severity":"urgent","regex":"x"}]})");
    ASSERT_FALSE(sev);
    EXPECT_NE(sev.error().message.find("severity"), std::string::npos);
    // invalid regex names the offending rule
    auto rx = parse_rules(R"({"patterns":[{"id":"broken","type":"t","label":"l","severity":"low","regex":"(["}]})");
    ASSERT_FALSE(rx);
    EXPECT_NE(rx.error().message.find("broken"), std::string::npos);
    // duplicate ids
    EXPECT_FALSE(parse_rules(R"({"patterns":[
        {"id":"a","type":"t","label":"l","severity":"low","regex":"x"},
        {"id":"a","type":"t","label":"l","severity":"low","regex":"y"}]})"));
    // oversized regex
    const std::string big(kMaxRegexLength + 1, 'a');
    EXPECT_FALSE(parse_rules(R"({"patterns":[{"id":"a","type":"t","label":"l","severity":"low","regex":")" + big + R"("}]})"));
}

TEST(Rules, DisablingDetectors) {
    auto r = parse_rules(R"({"bruteforce": {"enabled": false}})");
    ASSERT_TRUE(r);
    EXPECT_EQ(r.value().disabled.count("bruteforce"), 1u);
    auto scan = run(fails(10), r.value());
    ASSERT_TRUE(scan);
    EXPECT_TRUE(scan.value().findings.empty());
}

TEST(Rules, LoadsFromFileAndReportsMissingFile) {
    namespace fs = std::filesystem;
    const fs::path p = fs::temp_directory_path() / "sentinel_test_rules.json";
    {
        std::ofstream f(p);
        f << R"({"bruteforce": {"threshold": 2}})";
    }
    auto ok = load_rules_file(p);
    ASSERT_TRUE(ok) << ok.error().message;
    EXPECT_EQ(ok.value().thresholds.bf_threshold, 2);
    fs::remove(p);
    EXPECT_FALSE(load_rules_file(p));
}

TEST(Rules, ShippedFileOnDiskMatchesEmbeddedCopy) {
    auto disk = load_rules_file(std::filesystem::path(SENTINEL_SOURCE_DIR) / "rules" / "default_rules.json");
    ASSERT_TRUE(disk) << disk.error().message;
    EXPECT_EQ(disk.value().patterns.size(), default_rules().patterns.size());
}

// ---- detector interface + registry --------------------------------------------------------

namespace {
class CountingDetector final : public Detector {
public:
    std::string_view id() const override { return "counting"; }
    std::vector<Finding> analyze(std::span<const LogEntry> e) const override {
        Finding f;
        f.type = "count";
        f.severity = Severity::Info;
        f.summary = std::to_string(e.size()) + " entries";
        return {f};
    }
};
}  // namespace

TEST(Registry, BuiltinHasTheThreeDetectors) {
    auto ids = DetectorRegistry::builtin().ids();
    EXPECT_NE(std::find(ids.begin(), ids.end(), "bruteforce"), ids.end());
    EXPECT_NE(std::find(ids.begin(), ids.end(), "patterns"), ids.end());
    EXPECT_NE(std::find(ids.begin(), ids.end(), "rate-spike"), ids.end());
}

TEST(Registry, CustomDetectorPlugsIntoPipeline) {
    DetectorRegistry reg;
    reg.register_factory("counting", [](const RulesConfig&) { return std::make_unique<CountingDetector>(); });
    auto scan = [&] {
        std::istringstream is(web("1.1.1.1", "/a") + web("1.1.1.1", "/b"));
        return analyze_log(is, default_rules(), 2024, reg);
    }();
    ASSERT_TRUE(scan);
    ASSERT_EQ(scan.value().findings.size(), 1u);
    EXPECT_EQ(scan.value().findings[0].summary, "2 entries");
}

TEST(Registry, DisabledDetectorIsNotBuilt) {
    DetectorRegistry reg;
    reg.register_factory("counting", [](const RulesConfig&) { return std::make_unique<CountingDetector>(); });
    RulesConfig cfg = default_rules();
    cfg.disabled.insert("counting");
    auto d = reg.create_all(cfg);
    ASSERT_TRUE(d);
    EXPECT_TRUE(d.value().empty());
}

TEST(Registry, FactoryFailureBecomesError) {
    RulesConfig cfg;
    PatternRule bad;
    bad.id = "bad";
    bad.type = "t";
    bad.label = "l";
    bad.regex = "([";  // hand-built config bypassing parse_rules validation
    cfg.patterns.push_back(bad);
    std::istringstream is("");
    auto r = analyze_log(is, cfg, 2024);
    ASSERT_FALSE(r);
    EXPECT_EQ(r.error().code, Errc::InvalidArgument);
}
