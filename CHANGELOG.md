# CHANGELOG


## v1.0.0 (2026-09-26)

### Features

- Bad, cross-platform behavior anomaly detection with SIEM alerting
  ([`a25894e`](https://github.com/well-it-wasnt-me/BAD/commit/a25894e44194a259407aa83fbd746c6fc35b398b))

Collectors (Linux journal, Windows event log, macOS unified log, JSONL front door), feature
  extraction with optional input dynamics (timing and motion aggregates only, never content),
  Isolation Forest baseline, typed vendor-neutral alerts, webhook and syslog sinks with ECS mapping,
  admin TOML configuration, CLI, mkdocs documentation, CI and release pipelines, and deploy
  templates for Windows, Linux and macOS fleets.

BREAKING CHANGE: first tagged release;

### Breaking Changes

- First tagged release;
