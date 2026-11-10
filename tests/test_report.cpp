#include <gtest/gtest.h>

#include "sentinel/report.hpp"

using namespace sentinel;

namespace {
ScanSummary summary(std::initializer_list<std::uint16_t> open, const std::string& address = "127.0.0.1") {
    ScanSummary s;
    s.host = "localhost";
    s.address = address;
    for (const auto p : open) {
        PortResult r;
        r.port = p;
        s.open.push_back(r);
    }
    return s;
}

// A baseline exactly as `sentinel scan` saves it.
json baseline_of(std::initializer_list<std::uint16_t> open, const std::string& address = "127.0.0.1") {
    return make_envelope("scan", "baseline", to_json(summary(open, address)));
}

const std::vector<std::uint16_t> kScanned = {22, 80, 443, 8080};
}  // namespace

TEST(ScanDiff, ReportsOpenedClosedAndUnchangedPorts) {
    const auto d = diff_scan(summary({22, 443, 8080}), kScanned, baseline_of({22, 80}));
    ASSERT_TRUE(d.ok()) << d.error().message;
    EXPECT_EQ(d.value().opened, (std::vector<std::uint16_t>{443, 8080}));
    EXPECT_EQ(d.value().closed, (std::vector<std::uint16_t>{80}));
    EXPECT_EQ(d.value().unchanged, 1u);
    EXPECT_TRUE(d.value().changed());
    EXPECT_FALSE(d.value().baseline_generated_at.empty());
}

TEST(ScanDiff, IdenticalScansAreUnchanged) {
    const auto d = diff_scan(summary({22, 80}), kScanned, baseline_of({22, 80}));
    ASSERT_TRUE(d.ok());
    EXPECT_FALSE(d.value().changed());
    EXPECT_EQ(d.value().unchanged, 2u);
}

TEST(ScanDiff, BaselinePortOutsideTheNewScanIsNotReportedAsClosed) {
    // 3306 was open in the baseline but the new scan never looked at it: we cannot say it closed.
    const auto d = diff_scan(summary({22}), kScanned, baseline_of({22, 3306}));
    ASSERT_TRUE(d.ok());
    EXPECT_TRUE(d.value().closed.empty());
    EXPECT_FALSE(d.value().changed());
}

TEST(ScanDiff, RejectsABaselineForAnotherTarget) {
    const auto d = diff_scan(summary({22}), kScanned, baseline_of({22}, "10.0.0.5"));
    ASSERT_FALSE(d.ok());
    EXPECT_EQ(d.error().code, Errc::InvalidArgument);
    EXPECT_NE(d.error().message.find("10.0.0.5"), std::string::npos);
}

TEST(ScanDiff, RejectsReportsThatAreNotScans) {
    const ScanSummary now = summary({22});
    EXPECT_FALSE(diff_scan(now, kScanned, json::array()).ok());
    EXPECT_FALSE(diff_scan(now, kScanned, make_envelope("logscan", "x", json::object())).ok());
    EXPECT_FALSE(diff_scan(now, kScanned, json{{"kind", "scan"}}).ok());
    EXPECT_FALSE(diff_scan(now, kScanned, json{{"kind", "scan"}, {"data", {{"address", "127.0.0.1"}}}}).ok());

    json bad_entry = baseline_of({22});
    bad_entry["data"]["open_ports"].push_back("eighty");
    EXPECT_FALSE(diff_scan(now, kScanned, bad_entry).ok());
    json bad_port = baseline_of({22});
    bad_port["data"]["open_ports"].push_back({{"port", 70000}});
    EXPECT_FALSE(diff_scan(now, kScanned, bad_port).ok());
}

TEST(ScanDiff, SerialisesToJson) {
    const auto d = diff_scan(summary({443}), kScanned, baseline_of({80}));
    ASSERT_TRUE(d.ok());
    const json j = to_json(d.value());
    EXPECT_EQ(j["opened"], json::array({443}));
    EXPECT_EQ(j["closed"], json::array({80}));
    EXPECT_EQ(j["changed"], true);
}
