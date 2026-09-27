# CHANGELOG


## v1.1.0 (2026-09-27)

### Features

- Add continuous monitoring daemon with auto-collect, auto-train, and auto-monitor
  ([`683a018`](https://github.com/well-it-wasnt-me/BAD/commit/683a0186b74f5f5f5851e479a1bb817e8c832616))

The `bad daemon` command loops collect, train and monitor on a configurable timer. All three stages
  are enabled by default and toggleable via the [daemon] TOML section. Bootstraps its own model on
  the first cycle, scores only new events via byte-offset tracking, and shuts down gracefully on
  SIGINT/SIGTERM. Includes --once mode for cron or smoke tests.

Signed-off-by: Well It Wasnt Me <15037424+well-it-wasnt-me@users.noreply.github.com>


## v1.0.0 (2026-09-27)

### Chores

- Releasing test
  ([`827a8fd`](https://github.com/well-it-wasnt-me/BAD/commit/827a8fd6ea4a0e8ccc67a038f146ce95d6b73bbb))

Signed-off-by: Well It Wasnt Me <15037424+well-it-wasnt-me@users.noreply.github.com>

### Features

- Add continuous monitoring daemon with auto-collect, auto-train, and auto-monitor
  ([`f4323c7`](https://github.com/well-it-wasnt-me/BAD/commit/f4323c7d126afd6bc7444a6dd8542ea6208693ea))

The `bad daemon` command loops collect, train and monitor on a configurable timer. All three stages
  are enabled by default and toggleable via the [daemon] TOML section. Bootstraps its own model on
  the first cycle, scores only new events via byte-offset tracking, and shuts down gracefully on
  SIGINT/SIGTERM. Includes --once mode for cron or smoke tests.

Signed-off-by: Well It Wasnt Me <15037424+well-it-wasnt-me@users.noreply.github.com>

- Linux interactive installer
  ([`3ed9427`](https://github.com/well-it-wasnt-me/BAD/commit/3ed942782e9c60876ab5280d2463f5dbb797d4ae))

Signed-off-by: Well It Wasnt Me <15037424+well-it-wasnt-me@users.noreply.github.com>

- Mac and win interactive installer
  ([`2e031d9`](https://github.com/well-it-wasnt-me/BAD/commit/2e031d984b885721ddf7b1e561fa41be2a3ff1d6))

Signed-off-by: Well It Wasnt Me <15037424+well-it-wasnt-me@users.noreply.github.com>


## v0.0.0 (2026-09-26)

### Chores

- First release
  ([`aafc8c4`](https://github.com/well-it-wasnt-me/BAD/commit/aafc8c4ae336ab7f7e7c39751cf81f4608631750))

### Features

- Add --since CLI alias, interactive Linux installer, and highlight input dynamics
  ([`dd98361`](https://github.com/well-it-wasnt-me/BAD/commit/dd983619528227d69d6199297a0d881dde7a16ef))

- fix(cli): add --since as an alias for --source on `bad collect`, matching what the docs have
  always promised (the linux collector's journalctl time string). Backwards compatible: --source
  still works for jsonl. - docs: highlighting typing cadence and mouse movement behavioral
  biometrics as a key strength of the project. - test: add 3 CLI tests for the --since alias,
  --source backwards compat, and help output listing both option names.

Signed-off-by: Well It Wasnt Me <15037424+well-it-wasnt-me@users.noreply.github.com>
