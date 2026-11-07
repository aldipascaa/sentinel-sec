# Changelog

All notable changes to this project are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/) and the project uses [Semantic Versioning](https://semver.org/).

## [1.1.0] - 2026-11-08

Architecture review release; see [ARCHITECTURE_REVIEW.md](ARCHITECTURE_REVIEW.md) for the findings behind every item. CLI behavior and the dashboard are unchanged apart from what is listed.

### Security
- The non-loopback guard is now enforced inside `run_scan()` on the *resolved* address (new `ScanOptions::authorized`). `is_loopback_host()` no longer treats names such as `127.evil.example.com` as loopback.
- Dashboard CSP no longer contains `unsafe-inline`: the page is split into `index.html`, `app.css`, `app.js`, served same-origin.
- Dashboard POSTs also check `Sec-Fetch-Site`; checks run after the body is read; read/write timeouts added; `Cross-Origin-Resource-Policy/Opener-Policy` headers.
- Regex input is length-capped (4096 bytes per request path, 1000 characters per rule).

### Added
- Portable socket layer (`sentinel/net.hpp`): RAII `Socket`, `Address` (IPv4 and IPv6), `poll()`; Winsock and POSIX implementations behind `#ifdef`.
- IPv6 scanning: `scan --family auto|4|6`, `--host ::1`.
- `scan --concurrency N`; scans can be cancelled (`std::stop_token`), also on server shutdown.
- `Detector` interface and `DetectorRegistry`; detection rules and thresholds in `rules/default_rules.json`, overridable with `logscan --rules FILE` and `serve --rules FILE`; strict rule validation.
- `sentinel::Result<T>` error type.
- `CMakePresets.json`, `sentinel_warnings` interface target, `install()` rules with an exported `Sentinel` CMake package, options `SENTINEL_BUILD_SERVER/TESTS/INSTALL`.
- MIT `LICENSE`.
- 39 new tests (87 total): net layer, `Result`, rules and registry, scanner guard/cancellation/rate/IPv6, in-process server tests.

### Changed
- Scanner is an event loop: a few worker threads (`--threads`, default 4) each multiplex many non-blocking sockets; default in-flight connections 512. A default 1024-port loopback scan takes about 1.5 s. `--threads 200` still works (clamped to 64).
- Library API returns `Result` instead of throwing: `run_scan`, rules loading, detector construction, `analyze_log(rules)`.
- Library split into `sentinel_core` (no HTTP), `sentinel_server` and the `sentinel` CLI.
- Platform differences (time conversion, tty detection, sockets) moved behind `platform.hpp` / `net.hpp`.

### Removed
- `threadpool.hpp` (no remaining users; it also swallowed worker exceptions).

### Fixed
- `save_report` now reports write failures.

## [1.0.0] - 2026-11-07

First stable release.

### Added
- `sentinel scan`: multithreaded non-blocking TCP connect scanner with port-range parsing, timeouts, rate limiting, banner grabbing and service-name guessing. Non-loopback targets require `--authorized`.
- `sentinel logscan`: parser for sshd/syslog auth logs and Apache/nginx combined logs; detectors for brute force, suspicious request paths (SQLi, XSS, path traversal, command injection, recon) and request-rate spikes (z-score), with severities.
- `sentinel audit`: password-strength auditor (entropy estimate, pattern penalties, bundled common-password list, leetspeak handling, optional wordlist). Passwords are never stored.
- `sentinel serve`: localhost-only HTTP server and single-page dashboard (scan, log analysis, live password meter, report history), light/dark themes, responsive and accessible UI.
- `--json` output and report files in `reports/`; `sentinel --version`.
- Sample logs and password list in `samples/`.
- GoogleTest suite (port ranges, log parser, detectors, password scoring, scanner against a local listener) wired into `ctest`.
- Release builds compile cleanly with `/W4 /WX`.
