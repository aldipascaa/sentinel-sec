#include <gtest/gtest.h>

#include <atomic>
#include <chrono>
#include <filesystem>
#include <future>
#include <memory>
#include <stop_token>
#include <thread>

#include <httplib.h>

#include "sentinel/rules.hpp"
#include "sentinel/server.hpp"

using namespace sentinel;

namespace {
// Runs the real dashboard server on an ephemeral loopback port for the lifetime of the object.
class TestServer {
public:
    TestServer() {
        ServerOptions o;
        o.port = 0;
        o.quiet = true;
        o.rules = default_rules();
        o.report_dir = (std::filesystem::temp_directory_path() / "sentinel_test_reports").string();
        std::promise<int> ready;
        auto fut = ready.get_future();
        o.on_ready = [&ready](int p) { ready.set_value(p); };
        thread_ = std::jthread([o, this](std::stop_token st) { run_server(o, st); });
        if (fut.wait_for(std::chrono::seconds(5)) == std::future_status::ready) port_ = fut.get();
        // bind() happened; wait until the listener accepts connections.
        for (int i = 0; i < 50 && port_; ++i) {
            httplib::Client c("127.0.0.1", port_);
            c.set_connection_timeout(0, 200000);
            if (auto r = c.Get("/api/version")) break;
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
        }
    }
    ~TestServer() { thread_.request_stop(); }
    int port() const { return port_; }
    std::string origin() const { return "http://127.0.0.1:" + std::to_string(port_); }

private:
    int port_ = 0;
    std::jthread thread_;
};
}  // namespace

TEST(Server, ServesSplitDashboardWithStrictCsp) {
    TestServer s;
    ASSERT_GT(s.port(), 0);
    httplib::Client c("127.0.0.1", s.port());
    auto idx = c.Get("/");
    ASSERT_TRUE(idx);
    EXPECT_EQ(idx->status, 200);
    EXPECT_NE(idx->body.find("/app.js"), std::string::npos);
    EXPECT_EQ(idx->body.find("<script>"), std::string::npos);  // no inline script
    EXPECT_EQ(idx->body.find("<style>"), std::string::npos);   // no inline style block
    EXPECT_EQ(idx->body.find(" style=\""), std::string::npos); // no inline style attributes

    const std::string csp = idx->get_header_value("Content-Security-Policy");
    EXPECT_FALSE(csp.empty());
    EXPECT_EQ(csp.find("unsafe-inline"), std::string::npos);
    EXPECT_EQ(csp.find("unsafe-eval"), std::string::npos);
    EXPECT_NE(csp.find("script-src 'self'"), std::string::npos);
    EXPECT_EQ(idx->get_header_value("X-Content-Type-Options"), "nosniff");

    auto js = c.Get("/app.js");
    ASSERT_TRUE(js);
    EXPECT_EQ(js->status, 200);
    EXPECT_NE(js->get_header_value("Content-Type").find("javascript"), std::string::npos);
    auto css = c.Get("/app.css");
    ASSERT_TRUE(css);
    EXPECT_EQ(css->status, 200);
    EXPECT_NE(css->get_header_value("Content-Type").find("text/css"), std::string::npos);
}

TEST(Server, RejectsForeignHostHeader) {
    TestServer s;
    ASSERT_GT(s.port(), 0);
    httplib::Client c("127.0.0.1", s.port());
    auto r = c.Get("/api/version", httplib::Headers{{"Host", "evil.example.com"}});
    ASSERT_TRUE(r);
    EXPECT_EQ(r->status, 403);
}

TEST(Server, RejectsCrossOriginAndWrongContentTypePosts) {
    TestServer s;
    ASSERT_GT(s.port(), 0);
    httplib::Client c("127.0.0.1", s.port());
    const std::string body = R"({"password":"hunter2"})";

    auto bad_origin = c.Post("/api/audit", httplib::Headers{{"Origin", "http://evil.example.com"}}, body, "application/json");
    ASSERT_TRUE(bad_origin);
    EXPECT_EQ(bad_origin->status, 403);

    auto cross_site = c.Post("/api/audit", httplib::Headers{{"Sec-Fetch-Site", "cross-site"}}, body, "application/json");
    ASSERT_TRUE(cross_site);
    EXPECT_EQ(cross_site->status, 403);

    auto form = c.Post("/api/audit", body, "text/plain");
    ASSERT_TRUE(form);
    EXPECT_EQ(form->status, 415);

    auto ok = c.Post("/api/audit", httplib::Headers{{"Origin", s.origin()}, {"Sec-Fetch-Site", "same-origin"}}, body,
                     "application/json");
    ASSERT_TRUE(ok);
    EXPECT_EQ(ok->status, 200);
    EXPECT_EQ(ok->body.find("hunter2"), std::string::npos);  // the password is never echoed back
}

TEST(Server, LimitsRequestSize) {
    TestServer s;
    ASSERT_GT(s.port(), 0);
    httplib::Client c("127.0.0.1", s.port());
    const std::string huge(6 * 1024 * 1024, 'a');
    auto r = c.Post("/api/logscan", httplib::Headers{{"Origin", s.origin()}}, huge, "application/json");
    if (r) EXPECT_EQ(r->status, 413);  // either rejected with 413 or the connection is dropped
}

TEST(Server, LogscanUsesConfiguredRules) {
    TestServer s;
    ASSERT_GT(s.port(), 0);
    httplib::Client c("127.0.0.1", s.port());
    const std::string text =
        "1.2.3.4 - - [10/Oct/2023:13:00:00 +0000] \\\"GET /a?id=1%20union%20select%201 HTTP/1.1\\\" 404 5 \\\"-\\\" \\\"x\\\"\\n";
    auto r = c.Post("/api/logscan", httplib::Headers{{"Origin", s.origin()}}, "{\"text\":\"" + text + "\"}",
                    "application/json");
    ASSERT_TRUE(r);
    ASSERT_EQ(r->status, 200) << r->body;
    EXPECT_NE(r->body.find("sqli"), std::string::npos);
}

TEST(Server, RejectsBadReportNames) {
    TestServer s;
    ASSERT_GT(s.port(), 0);
    httplib::Client c("127.0.0.1", s.port());
    auto r = c.Get("/api/reports/..%2f..%2fsecret.json");
    ASSERT_TRUE(r);
    EXPECT_EQ(r->status, 404);
}
