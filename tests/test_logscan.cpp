#include <gtest/gtest.h>

#include <sstream>

#include "sentinel/logscan.hpp"

using namespace sentinel;

namespace {
std::string failed(int sec, const std::string& ip) {
    char b[160];
    std::snprintf(b, sizeof b,
                  "Nov  3 10:%02d:%02d web01 sshd[100]: Failed password for root from %s port 5000 ssh2\n",
                  sec / 60, sec % 60, ip.c_str());
    return b;
}
std::string web(const std::string& ip, const std::string& path, int status = 200, int min = 0, int sec = 0) {
    char b[300];
    std::snprintf(b, sizeof b, "%s - - [10/Oct/2023:13:%02d:%02d +0000] \"GET %s HTTP/1.1\" %d 512 \"-\" \"curl\"\n",
                  ip.c_str(), min, sec, path.c_str(), status);
    return b;
}
LogScanResult run(const std::string& text, DetectorConfig cfg = {}) {
    std::istringstream is(text);
    return analyze_log(is, cfg, 2024);
}
bool has(const LogScanResult& r, const std::string& type) {
    for (auto& f : r.findings)
        if (f.type == type) return true;
    return false;
}
}  // namespace

TEST(LogParser, DaysFromCivil) {
    EXPECT_EQ(days_from_civil(1970, 1, 1), 0);
    EXPECT_EQ(days_from_civil(2000, 3, 1), 11017);
    EXPECT_EQ(days_from_civil(2024, 2, 29), 19782);
}

TEST(LogParser, SshdFailedPassword) {
    auto e = parse_log_line(
        "Nov  3 10:15:01 web01 sshd[123]: Failed password for invalid user admin from 203.0.113.5 port 22 ssh2", 2024, 7);
    ASSERT_TRUE(e);
    EXPECT_EQ(e->kind, LogKind::Auth);
    EXPECT_TRUE(e->auth_failed);
    EXPECT_EQ(e->user, "admin");
    EXPECT_EQ(e->ip, "203.0.113.5");
    EXPECT_EQ(e->line, 7u);
}

TEST(LogParser, SshdAccepted) {
    auto e = parse_log_line("Nov  3 10:16:00 web01 sshd[1]: Accepted publickey for alice from 10.0.0.2 port 4000 ssh2", 2024);
    ASSERT_TRUE(e);
    EXPECT_TRUE(e->auth_success);
    EXPECT_FALSE(e->auth_failed);
    EXPECT_EQ(e->user, "alice");
}

TEST(LogParser, SyslogTimestampUsesYear) {
    auto e = parse_log_line("Jan  1 00:00:00 h sshd[1]: Failed password for x from 1.2.3.4 port 1 ssh2", 2024);
    ASSERT_TRUE(e);
    EXPECT_EQ(e->ts, days_from_civil(2024, 1, 1) * 86400);
}

TEST(LogParser, CombinedAccessLog) {
    auto e = parse_log_line(
        R"(198.51.100.9 - bob [10/Oct/2023:13:55:36 -0700] "GET /index.html?a=1 HTTP/1.1" 404 2326 "-" "Mozilla")", 2024);
    ASSERT_TRUE(e);
    EXPECT_EQ(e->kind, LogKind::Web);
    EXPECT_EQ(e->ip, "198.51.100.9");
    EXPECT_EQ(e->method, "GET");
    EXPECT_EQ(e->path, "/index.html?a=1");
    EXPECT_EQ(e->status, 404);
    // -0700 offset: UTC time is 7h later
    EXPECT_EQ(e->ts, days_from_civil(2023, 10, 10) * 86400 + (13 + 7) * 3600 + 55 * 60 + 36);
}

TEST(LogParser, GarbageIsRejected) {
    EXPECT_FALSE(parse_log_line("", 2024));
    EXPECT_FALSE(parse_log_line("this is not a log line", 2024));
    EXPECT_FALSE(parse_log_line("Nov  3 10:15:01 host cron[1]: job finished", 2024));
}

TEST(LogParser, UrlDecode) {
    EXPECT_EQ(url_decode("%2e%2e%2fetc"), "../etc");
    EXPECT_EQ(url_decode("a+b%20c"), "a b c");
    EXPECT_EQ(url_decode("100%"), "100%");
}

TEST(BruteForce, DetectsAtThreshold) {
    std::string t;
    for (int i = 0; i < 5; ++i) t += failed(i * 10, "203.0.113.5");
    auto r = run(t);
    ASSERT_TRUE(has(r, "brute-force"));
    EXPECT_EQ(r.findings[0].severity, Severity::High);
    EXPECT_EQ(r.findings[0].ip, "203.0.113.5");
}

TEST(BruteForce, BelowThresholdIsQuiet) {
    std::string t;
    for (int i = 0; i < 4; ++i) t += failed(i * 10, "203.0.113.5");
    EXPECT_FALSE(has(run(t), "brute-force"));
}

TEST(BruteForce, WindowMatters) {
    std::string t;
    for (int i = 0; i < 6; ++i) t += failed(i * 200, "203.0.113.5");  // 200s apart, window 300s
    EXPECT_FALSE(has(run(t), "brute-force"));
    DetectorConfig wide;
    wide.bf_window_sec = 3600;
    EXPECT_TRUE(has(run(t, wide), "brute-force"));
}

TEST(BruteForce, PerIpCounting) {
    std::string t;
    for (int i = 0; i < 3; ++i) t += failed(i, "10.0.0.1") + failed(i, "10.0.0.2");
    EXPECT_FALSE(has(run(t), "brute-force"));
}

TEST(BruteForce, ManyAttemptsAreCritical) {
    std::string t;
    for (int i = 0; i < 25; ++i) t += failed(i, "203.0.113.5");
    auto r = run(t);
    ASSERT_FALSE(r.findings.empty());
    EXPECT_EQ(r.findings[0].severity, Severity::Critical);
}

TEST(BruteForce, SuccessAfterAttackIsCritical) {
    std::string t;
    for (int i = 0; i < 6; ++i) t += failed(i, "203.0.113.5");
    t += "Nov  3 10:05:00 web01 sshd[9]: Accepted password for root from 203.0.113.5 port 1 ssh2\n";
    EXPECT_TRUE(has(run(t), "brute-force-success"));
}

TEST(SuspiciousPaths, DetectsSqli) {
    auto r = run(web("1.1.1.1", "/items?id=1%20UNION%20SELECT%20username,password%20FROM%20users", 404));
    ASSERT_TRUE(has(r, "sqli"));
    EXPECT_EQ(r.findings[0].severity, Severity::High);
    EXPECT_TRUE(has(run(web("1.1.1.1", "/login?u=admin'%20OR%201=1--", 500)), "sqli"));
    EXPECT_TRUE(has(run(web("1.1.1.1", "/p?id=1;SELECT%20SLEEP(5)", 500)), "sqli"));
}

TEST(SuspiciousPaths, DetectsXss) {
    EXPECT_TRUE(has(run(web("1.1.1.1", "/search?q=%3Cscript%3Ealert(1)%3C/script%3E", 200)), "xss"));
    EXPECT_TRUE(has(run(web("1.1.1.1", "/x?y=\"onerror=alert(1)", 404)), "xss"));
}

TEST(SuspiciousPaths, DetectsTraversalIncludingEncoded) {
    EXPECT_TRUE(has(run(web("1.1.1.1", "/../../etc/passwd", 404)), "path-traversal"));
    EXPECT_TRUE(has(run(web("1.1.1.1", "/files?f=%2e%2e%2f%2e%2e%2fwindows/win.ini", 403)), "path-traversal"));
    EXPECT_TRUE(has(run(web("1.1.1.1", "/files?f=%252e%252e%252fetc", 403)), "path-traversal"));  // double-encoded
}

TEST(SuspiciousPaths, SuccessfulAttackEscalatesToCritical) {
    auto r = run(web("1.1.1.1", "/../../etc/passwd", 200));
    ASSERT_FALSE(r.findings.empty());
    EXPECT_EQ(r.findings[0].severity, Severity::Critical);
}

TEST(SuspiciousPaths, BenignRequestsAreQuiet) {
    std::string t = web("1.1.1.1", "/index.html") + web("1.1.1.1", "/products?id=42&sort=asc") +
                    web("1.1.1.1", "/static/app.js") + web("1.1.1.1", "/blog/union-station-select-seats");
    EXPECT_TRUE(run(t).findings.empty());
}

TEST(RateSpike, DetectsBurst) {
    std::string t;
    for (int m = 0; m < 30; ++m)
        for (int k = 0; k < 5; ++k) t += web("10.0.0.1", "/", 200, m % 60, k);
    for (int k = 0; k < 150; ++k) t += web("203.0.113.77", "/", 200, 40, k % 60);  // minute 40 (separate hour range ok)
    auto r = run(t);
    ASSERT_TRUE(has(r, "rate-spike"));
    for (auto& f : r.findings)
        if (f.type == "rate-spike") {
            EXPECT_EQ(f.ip, "203.0.113.77");
        }
}

TEST(RateSpike, SteadyTrafficIsQuiet) {
    std::string t;
    for (int m = 0; m < 30; ++m)
        for (int k = 0; k < 10; ++k) t += web("10.0.0.1", "/", 200, m, k);
    EXPECT_FALSE(has(run(t), "rate-spike"));
}

TEST(RateSpike, TooLittleDataIsQuiet) {
    std::string t;
    for (int k = 0; k < 100; ++k) t += web("10.0.0.1", "/", 200, 0, k % 60);
    EXPECT_FALSE(has(run(t), "rate-spike"));
}

TEST(Analyze, SortsBySeverityAndCountsLines) {
    std::string t = web("1.1.1.1", "/.env", 404) + web("1.1.1.1", "/../../etc/passwd", 200) + "garbage line\n";
    auto r = run(t);
    EXPECT_EQ(r.lines_total, 3u);
    EXPECT_EQ(r.lines_parsed, 2u);
    EXPECT_EQ(r.lines_unparsed, 1u);
    ASSERT_GE(r.findings.size(), 2u);
    EXPECT_GE(r.findings[0].severity, r.findings[1].severity);
}
