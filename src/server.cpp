#include "server.hpp"

#include <atomic>
#include <chrono>
#include <iostream>
#include <mutex>
#include <sstream>
#include <thread>

#include <httplib.h>

#include "sentinel/logscan.hpp"
#include "sentinel/password.hpp"
#include "sentinel/portrange.hpp"
#include "sentinel/report.hpp"
#include "sentinel/scanner.hpp"
#include "sentinel/version.hpp"

extern const unsigned char kIndexHtml[];
extern const std::size_t kIndexHtmlSize;

namespace sentinel {
namespace {

constexpr std::size_t kMaxBody = 5 * 1024 * 1024;
constexpr std::size_t kMaxScanPorts = 10000;

void send_json(httplib::Response& res, int status, const json& j) {
    res.status = status;
    res.set_content(j.dump(), "application/json; charset=utf-8");
}

void send_error(httplib::Response& res, int status, const std::string& msg) {
    send_json(res, status, {{"error", msg}});
}

bool parse_body(const httplib::Request& req, httplib::Response& res, json& out) {
    try {
        out = json::parse(req.body.empty() ? "{}" : req.body);
        if (!out.is_object()) throw std::runtime_error("body must be a JSON object");
        return true;
    } catch (const std::exception& e) {
        send_error(res, 400, std::string("invalid JSON: ") + e.what());
        return false;
    }
}

}  // namespace

int run_server(const ServerOptions& opt) {
    httplib::Server svr;
    const std::string port_s = std::to_string(opt.port);
    const std::filesystem::path report_dir = opt.report_dir;
    std::mutex scan_mutex;  // one scan at a time

    svr.set_payload_max_length(kMaxBody);

    // DNS-rebinding / CSRF protection: only accept our own Host and Origin values.
    svr.set_pre_routing_handler([port_s](const httplib::Request& req, httplib::Response& res) {
        const std::string host = req.get_header_value("Host");
        if (host != "127.0.0.1:" + port_s && host != "localhost:" + port_s) {
            send_error(res, 403, "forbidden host");
            return httplib::Server::HandlerResponse::Handled;
        }
        if (req.method != "GET" && req.method != "HEAD") {
            const std::string origin = req.get_header_value("Origin");
            if (!origin.empty() && origin != "http://127.0.0.1:" + port_s && origin != "http://localhost:" + port_s) {
                send_error(res, 403, "forbidden origin");
                return httplib::Server::HandlerResponse::Handled;
            }
            if (req.get_header_value("Content-Type").rfind("application/json", 0) != 0) {
                send_error(res, 415, "Content-Type must be application/json");
                return httplib::Server::HandlerResponse::Handled;
            }
        }
        return httplib::Server::HandlerResponse::Unhandled;
    });
    svr.set_post_routing_handler([](const httplib::Request&, httplib::Response& res) {
        res.set_header("X-Content-Type-Options", "nosniff");
        res.set_header("X-Frame-Options", "DENY");
        res.set_header("Referrer-Policy", "no-referrer");
        res.set_header("Cache-Control", "no-store");
        res.set_header("Content-Security-Policy",
                       "default-src 'none'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; "
                       "connect-src 'self'; img-src 'self' data:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'");
    });
    svr.set_exception_handler([](const httplib::Request&, httplib::Response& res, std::exception_ptr) {
        send_error(res, 500, "internal error");
    });

    svr.Get("/", [](const httplib::Request&, httplib::Response& res) {
        res.set_content(reinterpret_cast<const char*>(kIndexHtml), kIndexHtmlSize, "text/html; charset=utf-8");
    });

    svr.Get("/api/version", [](const httplib::Request&, httplib::Response& res) {
        send_json(res, 200, {{"name", "sentinel"}, {"version", SENTINEL_VERSION}});
    });

    svr.Post("/api/scan", [&](const httplib::Request& req, httplib::Response& res) {
        json body;
        if (!parse_body(req, res, body)) return;
        ScanOptions o;
        o.host = "127.0.0.1";  // the dashboard only ever scans this machine
        try {
            o.ports = parse_port_ranges(body.value("ports", std::string("1-1024")));
            o.timeout_ms = std::clamp(body.value("timeout_ms", 400), 50, 5000);
            o.grab_banner = body.value("banner", true);
        } catch (const std::exception& e) {
            send_error(res, 400, e.what());
            return;
        }
        if (o.ports.size() > kMaxScanPorts) {
            send_error(res, 400, "too many ports (max " + std::to_string(kMaxScanPorts) + " per request)");
            return;
        }
        std::unique_lock lk(scan_mutex, std::try_to_lock);
        if (!lk.owns_lock()) {
            send_error(res, 429, "a scan is already running");
            return;
        }
        try {
            ScanSummary s = run_scan(o);
            const std::string summary = std::to_string(s.open.size()) + " open of " + std::to_string(s.scanned) +
                                        " ports on " + s.address;
            json env = make_envelope("scan", summary, to_json(s));
            try { env["report"] = save_report(report_dir, env).filename().string(); } catch (...) {}
            send_json(res, 200, env);
        } catch (const std::exception& e) {
            send_error(res, 500, e.what());
        }
    });

    svr.Post("/api/logscan", [&](const httplib::Request& req, httplib::Response& res) {
        json body;
        if (!parse_body(req, res, body)) return;
        if (!body.contains("text") || !body["text"].is_string()) {
            send_error(res, 400, "field 'text' (log contents) is required");
            return;
        }
        DetectorConfig cfg;
        cfg.bf_threshold = std::clamp(body.value("bf_threshold", cfg.bf_threshold), 1, 1000);
        cfg.bf_window_sec = std::clamp(body.value("bf_window", cfg.bf_window_sec), 1, 86400);
        cfg.z_threshold = std::clamp(body.value("z", cfg.z_threshold), 0.5, 20.0);
        std::time_t t = std::time(nullptr);
        std::tm tm{};
        localtime_s(&tm, &t);
        const int year = std::clamp(body.value("year", tm.tm_year + 1900), 1970, 2100);
        std::istringstream is(body["text"].get<std::string>());
        LogScanResult r = analyze_log(is, cfg, year);
        const std::string summary = std::to_string(r.findings.size()) + " findings in " +
                                    std::to_string(r.lines_parsed) + " parsed lines";
        json env = make_envelope("logscan", summary, to_json(r));
        try { env["report"] = save_report(report_dir, env).filename().string(); } catch (...) {}
        send_json(res, 200, env);
    });

    // Password strength: evaluated in memory and never stored, logged or echoed back.
    svr.Post("/api/audit", [&](const httplib::Request& req, httplib::Response& res) {
        json body;
        if (!parse_body(req, res, body)) return;
        if (!body.contains("password") || !body["password"].is_string()) {
            send_error(res, 400, "field 'password' is required");
            return;
        }
        std::string pw = body["password"].get<std::string>();
        if (pw.size() > 256) pw.resize(256);
        PasswordResult r = audit_password(pw);
        std::fill(pw.begin(), pw.end(), '\0');
        send_json(res, 200, to_json(r));
    });

    svr.Get("/api/reports", [&](const httplib::Request&, httplib::Response& res) {
        json arr = json::array();
        for (const auto& r : list_reports(report_dir))
            arr.push_back({{"name", r.name}, {"kind", r.kind}, {"generated_at", r.generated_at}, {"summary", r.summary}});
        send_json(res, 200, {{"reports", arr}});
    });

    svr.Get(R"(/api/reports/([A-Za-z0-9._-]+))", [&](const httplib::Request& req, httplib::Response& res) {
        auto j = load_report(report_dir, req.matches[1].str());
        if (!j) send_error(res, 404, "report not found");
        else send_json(res, 200, *j);
    });

    std::thread timer;
    std::atomic<bool> done{false};
    if (opt.max_seconds > 0) {
        timer = std::thread([&] {
            for (int i = 0; i < opt.max_seconds * 10 && !done; ++i)
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
            svr.stop();
        });
    }

    std::cout << "Sentinel dashboard: http://127.0.0.1:" << opt.port << "/  (bound to loopback only, Ctrl+C to stop)\n"
              << std::flush;
    const bool ok = svr.listen("127.0.0.1", opt.port);
    done = true;
    if (timer.joinable()) timer.join();
    if (!ok && opt.max_seconds == 0) {
        std::cerr << "error: could not listen on 127.0.0.1:" << opt.port << " (port in use?)\n";
        return 1;
    }
    return 0;
}

}  // namespace sentinel
