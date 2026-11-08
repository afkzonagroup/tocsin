# Changelog

All notable changes to this project are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed

- Web UI: every form was refused in real browsers. `Referrer-Policy: no-referrer` makes browsers send
  `Origin: null` on form posts, which the Origin check refuses. The UI now uses `same-origin` (still no
  referrer to other sites), and a Chromium test logs in and submits forms.

### Fixed

- Two processes recovering the same stale store lock could both enter it on
  Linux, which reuses a deleted file's inode at once. Stale-lock recovery now
  runs under a short `<store>.lock.recover` mutex, and a stale lock that is a
  symlink is never recovered.

## [0.1.0] - 2026-11-08

### Added

- Incident register with the Article 23(4) NIS2 stage machine: early warning, incident notification, intermediate reports on request, progress report, final report.
- Deadline engine: 24 h / 72 h elapsed time, 24 h notification for trust service providers, final report one calendar month after the notification, progress-report rule for ongoing incidents. UTC storage, IANA time-zone display, DST-safe.
- Significance assessment against Implementing Regulation (EU) 2024/2690 Articles 3 to 14, with article references and open questions; Article 23(3) NIS2 questions for other entities; recurring-incident check (IR Article 4).
- Report builders with exactly the Article 23(4) elements per stage; Markdown, JSON and self-contained HTML output; snapshots of submitted reports.
- Encrypted local store (AES-256-GCM per record, sealed index, scrypt or raw key, atomic writes, 0600), encrypted export and restore.
- Hash-chained audit log of every change.
- `tocsin` CLI and a local web UI (loopback, one-time token, CSRF, strict CSP, no JavaScript).
- Outbound webhooks (Slack, Microsoft Teams workflows, generic HMAC-signed) with SSRF protection.
- Importers for PagerDuty, incident.io and MISP exports (draft incidents only).
- Docker image.
