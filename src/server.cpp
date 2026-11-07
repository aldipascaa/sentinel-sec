#include "sentinel/server.hpp"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <functional>
#include <iostream>
#include <mutex>
#include <sstream>
#include <thread>

#include <httplib.h>

#include "sentinel/embedded.hpp"
#include "sentinel/logscan.hpp"
#include "sentinel/password.hpp"
#include "sentinel/platform.hpp"
#include "sentinel/portrange.hpp"
#include "sentinel/report.hpp"
#include "sentinel/scanner.hpp"
#include "sentinel/version.hpp"

namespace sentinel {
namespace {

constexpr std::size_t kMaxBody = 5 * 1024 * 1024;
constexpr std::size_t kMaxScanPorts = 10000;

// No 'unsafe-inline' anywhere: the dashboard is split into index.html + app.css + app.js, all same-origin.
constexpr const char* kCsp =
    "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; "
    "base-uri 'none'; form-action 'none'; frame-ancestors 'none'";

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

std::string content_type_for(const EmbeddedAsset& a) {
    std::string m = a.mime;
    if (m.rfind("text/", 0) == 0 || m == "application/javascript") m += "; charset=utf-8";
    return m;
}

}  // namespace

int run_server(const ServerOptions& opt, std::stop_token stop) {
    httplib::Server svr;
    std::string port_s;  // known after bind; read by handlers afterwards
    const std::filesystem::path report_dir = opt.report_dir;
    std::mutex scan_mutex;  // one scan at a time
    std::stop_source local_stop;

    svr.set_payload_max_length(kMaxBody);
    svr.set_read_timeout(10, 0);
    svr.set_write_timeout(10, 0);
    svr.set_keep_alive_max_count(20);

    // DNS-rebinding protection: only accept our own Host values. (Origin / Sec-Fetch-Site / Content-Type
    // checks for POSTs live in guard_post() so the request body is consumed before we answer.)
    svr.set_pre_routing_handler([&port_s](const httplib::Request& req, httplib::Response& res) {
        const std::string host = req.get_header_value("Host");
        if (host != "127.0.0.1:" + port_s && host != "localhost:" + port_s) {
            send_error(res, 403, "forbidden host");
            return httplib::Server::HandlerResponse::Handled;
        }
        return httplib::Server::HandlerResponse::Unhandled;
    });
    svr.set_post_routing_handler([](const httplib::Request&, httplib::Response& res) {
        res.set_header("X-Content-Type-Options", "nosniff");
        res.set_header("X-Frame-Options", "DENY");
        res.set_header("Referrer-Policy", "no-referrer");
        res.set_header("Cache-Control", "no-store");
        res.set_header("Cross-Origin-Resource-Policy", "same-origin");
        res.set_header("Cross-Origin-Opener-Policy", "same-origin");
        res.set_header("Content-Security-Policy", kCsp);
    });
    svr.set_exception_handler([](const httplib::Request&, httplib::Response& res, std::exception_ptr) {
        send_error(res, 500, "internal error");
    });

    // Static dashboard assets, compiled into the binary.
    for (std::size_t i = 0; i < kWebAssetsCount; ++i) {
        const EmbeddedAsset& a = kWebAssets[i];
        const std::string name = a.name;
        const std::string ctype = content_type_for(a);
        auto serve = [&a, ctype](const httplib::Request&, httplib::Response& res) {
            res.set_content(reinterpret_cast<const char*>(a.data), a.size, ctype);
        };
        svr.Get("/" + name, serve);
        if (name == "index.html") svr.Get("/", serve);
    }

    svr.Get("/api/version", [](const httplib::Request&, httplib::Response& res) {
        send_json(res, 200, {{"name", "sentinel"}, {"version", SENTINEL_VERSION}});
    });

    // CSRF protection for state-changing requests: same-origin only, JSON only.
    auto guard_post = [&port_s](const httplib::Request& req, httplib::Response& res) {
        const std::string origin = req.get_header_value("Origin");
        if (!origin.empty() && origin != "http://127.0.0.1:" + port_s && origin != "http://localhost:" + port_s) {
            send_error(res, 403, "forbidden origin");
            return false;
        }
        // Browsers send Sec-Fetch-Site; anything but same-origin (or user-initiated "none") is cross-site.
        const std::string site = req.get_header_value("Sec-Fetch-Site");
        if (!site.empty() && site != "same-origin" && site != "none") {
            send_error(res, 403, "cross-site request blocked");
            return false;
        }
        if (req.get_header_value("Content-Type").rfind("application/json", 0) != 0) {
            send_error(res, 415, "Content-Type must be application/json");
            return false;
        }
        return true;
    };
    auto post = [&](const std::string& path, std::function<void(const httplib::Request&, httplib::Response&)> h) {
        svr.Post(path, [guard_post, h = std::move(h)](const httplib::Request& req, httplib::Response& res) {
            if (guard_post(req, res)) h(req, res);
        });
    };

    post("/api/scan", [&](const httplib::Request& req, httplib::Response& res) {
        json body;
        if (!parse_body(req, res, body)) return;
        ScanOptions o;
        o.host = "127.0.0.1";  // the dashboard only ever scans this machine (authorized stays false)
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
        auto r = run_scan(o, {}, local_stop.get_token());
        if (!r) {
            send_error(res, 500, r.error().message);
            return;
        }
        const ScanSummary& s = r.value();
        const std::string summary = std::to_string(s.open.size()) + " open of " + std::to_string(s.scanned) +
                                    " ports on " + s.address;
        json env = make_envelope("scan", summary, to_json(s));
        try { env["report"] = save_report(report_dir, env).filename().string(); } catch (...) {}
        send_json(res, 200, env);
    });

    post("/api/logscan", [&](const httplib::Request& req, httplib::Response& res) {
        json body;
        if (!parse_body(req, res, body)) return;
        if (!body.contains("text") || !body["text"].is_string()) {
            send_error(res, 400, "field 'text' (log contents) is required");
            return;
        }
        RulesConfig rules = opt.rules;
        DetectorConfig& cfg = rules.thresholds;
        cfg.bf_threshold = std::clamp(body.value("bf_threshold", cfg.bf_threshold), 1, 1000);
        cfg.bf_window_sec = std::clamp(body.value("bf_window", cfg.bf_window_sec), 1, 86400);
        cfg.z_threshold = std::clamp(body.value("z", cfg.z_threshold), 0.5, 20.0);
        const int local_year = platform::local_tm(std::time(nullptr)).tm_year + 1900;
        const int year = std::clamp(body.value("year", local_year), 1970, 2100);
        std::istringstream is(body["text"].get<std::string>());
        auto r = analyze_log(is, rules, year);
        if (!r) {
            send_error(res, 500, r.error().message);
            return;
        }
        const std::string summary = std::to_string(r.value().findings.size()) + " findings in " +
                                    std::to_string(r.value().lines_parsed) + " parsed lines";
        json env = make_envelope("logscan", summary, to_json(r.value()));
        try { env["report"] = save_report(report_dir, env).filename().string(); } catch (...) {}
        send_json(res, 200, env);
    });

    // Password strength: evaluated in memory and never stored, logged or echoed back.
    post("/api/audit", [&](const httplib::Request& req, httplib::Response& res) {
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

    // ---- bind (loopback only) and serve
    int port = opt.port;
    if (opt.port == 0) {
        port = svr.bind_to_any_port("127.0.0.1");
        if (port < 0) port = 0;
    } else if (!svr.bind_to_port("127.0.0.1", opt.port)) {
        port = 0;
    }
    if (port == 0) {
        if (!opt.quiet) std::cerr << "error: could not listen on 127.0.0.1:" << opt.port << " (port in use?)\n";
        return 1;
    }
    port_s = std::to_string(port);

    std::stop_callback on_stop(stop, [&] {
        local_stop.request_stop();
        svr.stop();
    });
    std::atomic<bool> done{false};
    std::thread timer;
    if (opt.max_seconds > 0) {
        timer = std::thread([&] {
            for (int i = 0; i < opt.max_seconds * 10 && !done; ++i)
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
            local_stop.request_stop();
            svr.stop();
        });
    }

    if (!opt.quiet)
        std::cout << "Sentinel dashboard: http://127.0.0.1:" << port << "/  (bound to loopback only, Ctrl+C to stop)\n"
                  << std::flush;
    if (opt.on_ready) opt.on_ready(port);
    svr.listen_after_bind();
    done = true;
    local_stop.request_stop();
    if (timer.joinable()) timer.join();
    return 0;
}

}  // namespace sentinel
