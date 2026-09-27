# CHANGELOG


## v1.0.0 (2026-09-27)

### Chores

- Releasing test
  ([`827a8fd`](https://github.com/well-it-wasnt-me/BAD/commit/827a8fd6ea4a0e8ccc67a038f146ce95d6b73bbb))

Signed-off-by: Well It Wasnt Me <15037424+well-it-wasnt-me@users.noreply.github.com>

### Features

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
