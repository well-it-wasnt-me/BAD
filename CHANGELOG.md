# CHANGELOG


## v2.0.1 (2026-09-29)

### Chores

- Merge from main
  ([`57ea3e2`](https://github.com/well-it-wasnt-me/BAD/commit/57ea3e29316eed9e79d405065276e9be6baca989))


## v2.0.0 (2026-09-27)

### Bug Fixes

- Address critical/high/medium review findings (phases 1-6)
  ([`8d355ed`](https://github.com/well-it-wasnt-me/BAD/commit/8d355ed98fc995516b8eb606ccc43c6a6bc51840))

SIEM & daemon: - webhook: assert 2xx explicitly, follow redirects, bounded retry with backoff (C1,
  M5) - syslog: attach a real SysLogHandler with stream fallback; cap payload size (H13, L8) -
  daemon.run_loop: build sink once, reuse across cycles, close on exit (H5) - daemon.run_cycle:
  build_sink inside monitor try; per-alert send isolation, offset advances past scored batch
  regardless of send outcome (H6, H8) - daemon._collect_cycle: wire jsonl collector source through
  (M2) - daemon.run_cycle: decide retrain before incrementing cycle (M4) - config.SiemConfig:
  validate kind (Literal-style) + endpoint scheme/SSRF guard at load time so check-config catches
  misconfiguration (H9, M1) - models.persistence: optional HMAC signature on save/load; 0o700 model
  dir (H10)

Collectors: - windows: allowlist log_name, validate event_ids, escape quotes, subprocess timeout,
  defensive int() parse, normalize naive timestamps (H1, M16, L10, L12) - linux: with-Popen +
  try/finally cleanup, capture stderr, watchdog timeout, raise on missing timestamp (skip record),
  scoped failure markers (H2, M15, M16, L9) - macos: tolerate real non-JSON log show trailer, fix
  source='None' bug, raise on missing timestamp, subprocess timeout (M13, M14, M15, M16)

Storage: - jsonl.iter_events: skip-and-log corrupt lines instead of poisoning stream (H3) -
  jsonl.write: mkdir parent dirs (M3) - alerts.write: atomic temp+os.replace write (H4)

Detection & features: - windowing: sort by epoch_seconds so mixed naive/aware windows do not crash
  (H11) - features._num: reject nan/inf (H12), document bool guard - features._input_features: sort
  events, normalize tz, typing velocity by active duration, partial-metadata-aware weighted mean
  (M8, M9, M11) - features stddev semantics documented honestly (M10) - engine.detect: per-window
  error isolation (M6) - engine._summarize: set-based dedup with early stop (M7)

Models: - isolation_forest.fit: validate every row's column set (M12)

CLI: - score: --ecs writes ECS to --output; quiet stdout when --output given (M17, L3) -
  monitor/daemon --once: close webhook sink (L2) - load_config + overrides: clean CLI errors instead
  of tracebacks (L4) - check-config: drop api_key_set info leak (L5)

- **docs,deploy**: Phase 7 docs and deploy hardening
  ([`f4dbe3e`](https://github.com/well-it-wasnt-me/BAD/commit/f4dbe3ecc388368b88863d109fdfc77e2dddbe40))

- ansible: OS-aware audit/auditd package name (M18) - macos installers: fixed -mountpoint instead of
  awk-parsed volume name, so dmgs with spaces in the volume name do not break install (M19) -
  docs/index.md: drop the stale 'no daemon' line (M20) - docs/usage.md: fix sink.send(to_ecs(alert))
  snippet to send Alert; show ECS rendering as a separate step (M21) - docs/deployment.md: remove
  duplicated paragraph (L14) - docs/daemon.md: standardize service user to badsvc (L15) -
  config.example.toml: document allow_private_endpoint and daemon source

### Build System

- Ship config.example.toml in the wheel (L6); mark plan complete
  ([`b3090b4`](https://github.com/well-it-wasnt-me/BAD/commit/b3090b41af12780ebdf7cd965d61723dd557c6e9))

### Chores

- Cclean
  ([`0b68ddd`](https://github.com/well-it-wasnt-me/BAD/commit/0b68ddd4edd1a5a8922dd0098631da0a3685c429))

Signed-off-by: Well It Wasnt Me <15037424+well-it-wasnt-me@users.noreply.github.com>

### Documentation

- Add code review fix plan
  ([`c09ec42`](https://github.com/well-it-wasnt-me/BAD/commit/c09ec423ac5bff4b0e2bdb1b9529c79d6be32853))

### Testing

- Phase 8 strengthen and extend coverage for every fix
  ([`016b053`](https://github.com/well-it-wasnt-me/BAD/commit/016b0532f67e831c0b75df95f340765a145f192e))

Focus on the production paths the old suite patched out. 128 -> 181 tests.

SIEM: 3xx redirect delivery; webhook retry-then-succeed and give-up; no-api-key header omission;
  syslog handler attachment; ECS category from evidence.

Config: invalid siem kind, webhook-without-endpoint, non-http scheme, private-IP endpoint refused,
  opt-in allowed. Collectors: real non-JSON log show trailer; macos source=None bug;
  missing-timestamp skip (linux+macos); loginuid 0 preserved; windows log_name allowlist, non-int
  event_id, non-numeric Id skip, naive-timestamp normalization, collector timeouts; linux Popen
  cleanup on parse error. Storage: corrupt-line skip; nested-dir mkdir; atomic alert write on
  serialization failure; alert store read roundtrip. Detection: evidence cap actually limits to 5;
  per-window error isolation; cross-user partitioning end-to-end; mixed naive/aware window no crash.
  Features: nan/inf coercion; unsorted input; typing velocity by active duration; partial-metadata
  weighted mean; privacy test checks values not names. Models: fit rejects inconsistent/extra
  columns; HMAC save/load roundtrip, tamper rejection, missing-signature rejection. Daemon: sink
  built once + closed; partial-send offset bookkeeping; jsonl collector un-patched via new source
  field; retrain cadence matches reported cycle. CLI: check-config rejects bad siem kind / missing
  endpoint; no api_key_set leak; --ecs --output writes ECS; --output quiet on stdout; invalid flag
  clean error; zero-threshold alert path genuinely exercised. Pipeline: input-dynamics end-to-end no
  longer vacuous (threshold 0 guarantees alerts).


## v1.2.0 (2026-09-27)

### Chores

- Release
  ([`de5913c`](https://github.com/well-it-wasnt-me/BAD/commit/de5913caba2911590dbf6d3e6edd51cadb48e3a5))

- **release**: 1.2.0
  ([`206da43`](https://github.com/well-it-wasnt-me/BAD/commit/206da43af2c18ea54db143af0a8d07d91323d42c))
