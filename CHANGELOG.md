# CHANGELOG


## v0.1.0 (2026-09-26)

### Bug Fixes

- **ci**: Pythonpath for tests, permissions and cascading failure
  ([`ec895a0`](https://github.com/well-it-wasnt-me/BAD/commit/ec895a0fde288521be7401ceb15c38d6e9a836db))

Signed-off-by: Well It Wasnt Me <15037424+well-it-wasnt-me@users.noreply.github.com>

### Chores

- Github stuff and license
  ([`5cfacd4`](https://github.com/well-it-wasnt-me/BAD/commit/5cfacd4bb86fb56a33246a40a0f30a902185eaa9))

- Project scaffolding
  ([`b26a4b0`](https://github.com/well-it-wasnt-me/BAD/commit/b26a4b0ef4254abdd8ec0200cb80c572ee5ad5a7))

- Pyproject moved to beta and readme update
  ([`de3fa5a`](https://github.com/well-it-wasnt-me/BAD/commit/de3fa5a6da59bb298c7fa9d26c1d4df687821d02))

Signed-off-by: Well It Wasnt Me <15037424+well-it-wasnt-me@users.noreply.github.com>

### Documentation

- How to test
  ([`eb2522a`](https://github.com/well-it-wasnt-me/BAD/commit/eb2522adbc492a5aafc7f3a58592b908a7f49a6c))

Signed-off-by: Well It Wasnt Me <15037424+well-it-wasnt-me@users.noreply.github.com>

### Features

- Fleet deployment templates and bad check-config
  ([`f35533a`](https://github.com/well-it-wasnt-me/BAD/commit/f35533a5d55359c477b71ca4f31196f0aef92647))

Add docs/deployment.md with per-platform prerequisites and scheduling guidance, plus deploy/
  templates: Windows PowerShell installer and Intune Win32 packaging, Linux ansible role and
  install.sh, macOS pkg recipe and install.sh. Add bad check-config so deployment tooling validates
  admin configs before a scheduled run does. Nothing installed by BAD runs persistently; schedules
  belong to the admin.

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

This file is regenerated automatically by python-semantic-release on every
release, from conventional commits. If you want different changelog entries,
write different commit messages. Honesty compounding, if you will.

## [0.1.0] - 2026-09-26

### Added

- Normalized `BehaviorEvent` schema shared by all platforms.
- Collectors: systemd journal (Linux), Security event log (Windows),
  unified log (macOS) and normalized JSONL ingestion for agents.
- Per host, per user, epoch-aligned time windowing.
- Behavioral feature extraction (counts, cardinalities, failures), plus
  optional input dynamics features: typing cadence and mouse motion
  aggregates, timing and motion only, never content.
- Admin TOML configuration (`config.example.toml`, `--config` on train,
  score and monitor) with enable/disable toggles for input dynamics,
  detection knobs and the SIEM sink. Flags override the file, the file
  overrides the defaults.
- `bad check-config`: validates an admin config file and prints the
  effective settings, for deployment tooling and pre-flight checks.
- Fleet deployment story: `docs/deployment.md` plus `deploy/` templates
  (Windows PowerShell installer and Intune Win32 packaging, Linux ansible
  role and `install.sh`, macOS pkg recipe and `install.sh`). Nothing
  installed by BAD runs persistently; schedules belong to the admin.
- Isolation Forest anomaly model with save/load persistence and registry.
- Detection engine producing typed, vendor-neutral `Alert` objects with
  severity and evidence.
- SIEM transports: HTTP webhook and syslog, plus an Elastic Common Schema
  mapping.
- CLI: `collect`, `train`, `score`, `monitor`.
- JSONL storage for events and alerts.
- Test suite, mkdocs documentation, CI, release and docs pipelines.