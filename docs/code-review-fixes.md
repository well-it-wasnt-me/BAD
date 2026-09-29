# Code Review Fix Plan

Outcome of the full code review. Each phase is independently shippable and
ends with a green test suite. Findings are referenced by ID from the review
report (C=critical, H=high, M=medium, L=low, T=test).

## Phase 1 — SIEM & daemon robustness (C1, H5, H6, H8, H9, H10, H13, M5)

- **C1** `webhook.py`: assert 2xx explicitly; enable `follow_redirects=True`.
- **H13** `syslog.py`: attach a real `SysLogHandler` with a stream fallback so
  "syslog" actually means syslog (and keep the logger path testable).
- **H5** `daemon.run_loop`: build the sink once, pass it through, `close()` it
  in `finally`.
- **H6** `daemon.run_cycle`: build the sink inside the monitor `try`.
- **H8** `daemon._monitor_cycle`: per-alert send isolation; advance offset past
  scored windows regardless of send outcome; track sent count separately.
- **H9** `config.SiemConfig`: validate `endpoint` scheme via `model_validator`;
  refuse private/loopback/link-local by default with an opt-in.
- **H10** `models/persistence`: optional HMAC signature file checked on load;
  `save_model` creates the model dir with `0o700`.
- **M5** `webhook.py`: bounded retry with backoff for retryable statuses.

## Phase 2 — Collectors (H1, H2, M13, M14, M15, M16, L10, L12)

- **H1** `windows.py`: allowlist `log_name`; validate `event_ids` are ints;
  escape single quotes; build the filter via parameters.
- **H2** `linux.py`: `with Popen(...)` + `try/finally`; capture stderr for the
  error message; drop the dead `or []`.
- **M16** add a `timeout` to all `collect()` subprocess calls.
- **M13** `macos.iter_log_records`: tolerate the real non-JSON trailer.
- **M14** `macos.parse_log_record`: drop the `str(... or None) or None` bug.
- **M15** linux/macos: do not fabricate "now" for missing timestamps — raise,
  matching Windows.
- **L10/L12** windows: defensive `int()` parse; normalize naive timestamps.

## Phase 3 — Storage integrity (H3, H4, M3)

- **H3** `jsonl.iter_events`: skip-and-log corrupt lines instead of poisoning
  the whole stream.
- **H4** `alerts.write`: atomic write (temp + `os.replace`); type-check inputs.
- **M3** `jsonl.write`: `mkdir(parents=True, exist_ok=True)` like `alerts`.

## Phase 4 — Detection & features (H11, H12, M6, M7, M8, M9, M10, M11)

- **H11** `windowing.build_windows`: sort by `_epoch_seconds` so mixed
  naive/aware windows do not crash.
- **H12** `behavioral._num`: reject non-finite floats (`nan`/`inf`).
- **M6** `engine.detect`: per-window try/except; log and continue.
- **M7** `engine._summarize`: set-based dedup with early stop at the limit.
- **M8/M9** `_input_features`: sort events before span; normalize tz before
  subtraction; normalize typing velocity by active typing duration.
- **M10** rename `key_interval_stddev_ms` semantics to match the math
  (documented weighted mean of aggregate stddevs) OR pool — chosen: document
  the actual statistic in the docstring and keep the name (pooled variance
  requires per-aggregate means we do not always have; renaming later is a
  model-compat break, so we document honestly now and pool is tracked as a
  follow-up).
- **M11** weighted-mean denominator: only count keystrokes for events that
  carry the paired field.

## Phase 5 — Config & CLI (M1, M2, M4, M17, L2, L3, L4, L5)

- **M1** `SiemConfig`: `kind: Literal["syslog","webhook"]` + validator
  requiring `endpoint` for webhook; reject at load time so `check-config`
  catches it.
- **M2** `DaemonCollectConfig`: add `source` field; wire it through
  `_collect_cycle` so `jsonl` works via the daemon.
- **M4** `run_cycle`: call `should_retrain` before incrementing `state.cycle`
  (or document and align the test).
- **M17** `score`: write ECS to the `--output` file when `--ecs` is set.
- **L2** `cli.monitor`/`daemon --once`: close the webhook sink.
- **L3** `score`: skip per-alert stdout echo when `--output` is given.
- **L4** wrap `AppConfig.load` + `model_copy` overrides in clean CLI errors.
- **L5** `check-config`: drop `api_key_set` from stdout (info leak).

## Phase 6 — Models (M12)

- **M12** `isolation_forest.fit`: validate every row has exactly
  `set(self.columns)`; raise a descriptive `ValueError`.

## Phase 7 — Docs & deploy (M18, M19, M20, M21, L14, L15)

- **M18** ansible: OS-aware `audit`/`auditd` package name.
- **M19** macOS installers: robust dmg mount point parsing.
- **M20** `docs/index.md`: drop the stale "no daemon" line.
- **M21** `docs/usage.md`: fix the `sink.send(to_ecs(alert))` snippet.
- **L14/L15** dedup prose; align service user name to `badsvc`.

## Phase 8 — Tests

Strengthen existing tests and add coverage for every fix above, focusing on
the production paths the old suite patched out:

- 3xx webhook; webhook retry; syslog handler attachment.
- daemon: sink built once + closed; partial-send bookkeeping; jsonl collector
  via the daemon (un-patched); `should_retrain` cadence end-to-end.
- collectors: subprocess timeout, linux `Popen` cleanup, windows injection
  guard, macos non-JSON trailer, macos `source` field, missing-timestamp
  policy.
- storage: corrupt-line skip; atomic alert write; nested-dir mkdir.
- detection: mixed naive/aware window; per-window error isolation; evidence
  cap actually tested; unsorted input to `extract`.
- features: NaN/inf coercion; partial-metadata weighted mean; privacy test
  checks values not names.
- config: `check-config` rejects bad `kind`/missing endpoint.
- CLI: `--ecs --output` writes ECS; `score --output` is quiet; invalid flag
  gives a clean error.
- models: `fit` rejects inconsistent column sets.

## Phase 9 — Cleanup (L7, L8, L9, L13, L16, M22, L6)

- **M22** lazy heavy imports in `__init__.py` / `cli.py` (PEP 562).
- **L7** `to_ecs`: typed return; derive `event.category` from evidence.
- **L8** cap syslog/alert payload size.
- **L9** tighten linux `_FAILURE_MARKERS`.
- **L13** `AppConfig`: warn on unknown top-level keys.
- **L16** document the `_num` bool guard.
- **L6** ship `config.example.toml` in the wheel.