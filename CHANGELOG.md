# CHANGELOG


## v1.0.1 (2026-09-26)

### Chores

- Fix pyproject
  ([`b21aaa9`](https://github.com/well-it-wasnt-me/BAD/commit/b21aaa9d0d03b21a7f865f1492844f8e0e35c94b))

Signed-off-by: Well It Wasnt Me <15037424+well-it-wasnt-me@users.noreply.github.com>


## v1.0.0 (2026-09-26)

### Bug Fixes

- **ci**: I finally figure out how to make autopublishing on pypi... better late than never..
  ([`502e247`](https://github.com/well-it-wasnt-me/BAD/commit/502e247949cde3ab8f7f9689c15ff365fe4ef31c))

Signed-off-by: Well It Wasnt Me <15037424+well-it-wasnt-me@users.noreply.github.com>

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
