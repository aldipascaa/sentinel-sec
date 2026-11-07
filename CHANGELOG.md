# Changelog

All notable changes to this project are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/) and the project uses [Semantic Versioning](https://semver.org/).

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
