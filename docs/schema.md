# Event schema

Two shapes matter: what a user did (`BehaviorEvent`) and what we think about
what they did (`Alert`). Everything else in the package exists to turn the
first into the second.

## BehaviorEvent

One thing a user did on a machine, normalized across platforms. Collectors
produce these; features, models and detection never see raw telemetry.

| Field | Type | Required | Notes |
|---|---|---|---|
| `timestamp` | datetime | yes | When it happened |
| `host_id` | str | yes | Machine it happened on |
| `user_id` | str | yes | Who did it |
| `platform` | Platform | yes | `linux`, `windows` or `macos` |
| `event_type` | EventType | yes | See taxonomy below |
| `action` | str | yes | Free-form verb: `exec`, `login`, `sudo`, ... |
| `process_name` | str | no | Executable name, path trimmed |
| `parent_process` | str | no | Parent executable when known |
| `application` | str | no | For application usage events |
| `source` | str | no | Where telemetry came from (identifier, provider) |
| `destination` | str | no | Network peer when relevant |
| `success` | bool | no | True/False when the OS said so, None when it did not |
| `privileged` | bool | no | Whether the action required privileges |
| `metadata` | dict | no | Free-form extras: pid, event_id, and other receipts |

`success: null` is a feature, not a bug: it means "the source did not say",
and a tool that invents success rates out of silence is worse than no tool.

### Event taxonomy

| event_type | Meaning |
|---|---|
| `process` | Process execution and lifecycle |
| `auth` | Authentication attempts, success and failure |
| `session` | Login sessions and their comings and goings |
| `file` | File activity |
| `network` | Network connections |
| `shell` | Shell and terminal activity, interactive commands |
| `privilege` | Privilege changes, sudo, escalation |
| `application` | Application usage |
| `input` | Typing and mouse dynamics, aggregates only. See below |

## Input dynamics

The `input` event type carries behavioral biometrics: how a human types and
how they move the mouse. A hijacked session almost always types and mouses
differently from the legitimate owner, no matter how careful it is about
which processes it runs. Pure process and auth telemetry is deaf to that
signal.

Input events are **aggregates, never raw input**. An input sampler (an agent
feeding the jsonl front door, most commonly) reports totals over an interval,
and BAD turns them into features. Timing and motion only:

| action | metadata keys | Meaning |
|---|---|---|
| `typing` | `keystrokes`, `mean_interval_ms`, `stddev_interval_ms` | How many keys, how evenly they came |
| `mouse` | `distance_px`, `duration_ms`, `direction_changes` | How far, how fast, how twitchy the course was |

Keystroke content is not a field BAD reads. There is no schema slot for it,
no metadata key for it, and no configuration that enables it. The timing of
typing is a signature. The content of typing is a lawsuit. Privacy by
construction beats privacy by promise.

Example aggregate pair, as an agent would emit them:

```json
{"timestamp": "2026-09-26T12:00:30Z", "host_id": "web-01", "user_id": "1000",
 "platform": "linux", "event_type": "input", "action": "typing",
 "metadata": {"keystrokes": 42, "mean_interval_ms": 118, "stddev_interval_ms": 31}}
{"timestamp": "2026-09-26T12:00:30Z", "host_id": "web-01", "user_id": "1000",
 "platform": "linux", "event_type": "input", "action": "mouse",
 "metadata": {"distance_px": 1234, "duration_ms": 800, "direction_changes": 12}}
```

BAD derives eight input features from these aggregates: `input_events`,
`keystrokes`, `typing_velocity_kpm`, `mean_key_interval_ms`,
`key_interval_stddev_ms`, `mouse_distance_px`, `mouse_speed_px_s` and
`mouse_direction_changes`. Admins can turn the whole category off with one
toggle in the config file, which is worth knowing if you have models trained
before it existed: the feature vector length must match between training and
scoring.

## Alert

A vendor-neutral finding. No Splunk-isms, no Sentinel-isms. Any SIEM, XDR or
agent can consume this shape and map it to whatever schema it loves.

| Field | Type | Notes |
|---|---|---|
| `timestamp` | datetime | When the anomaly was detected, not when it happened |
| `rule` | str | `user_behavior_anomaly` |
| `score` | float | 0.0 boring, 1.0 spicy |
| `severity` | Severity | `low`, `medium`, `high` or `critical` |
| `host_id` | str | Machine where the window was seen |
| `user_id` | str | User whose behavior earned the score |
| `platform` | Platform | `linux`, `windows` or `macos` |
| `model` | str | Which model produced the score |
| `window_seconds` | int | Size of the evaluated window |
| `feature_vector` | dict | The features, for the analyst who wants receipts |
| `evidence` | list[str] | Deduplicated `type:action` summaries, capped at 5 |

### Severity mapping

Scores map to severities in exactly one place, so arguments about it have a
single venue:

| Score | Severity |
|---|---|
| >= 0.90 | critical |
| >= 0.80 | high |
| >= 0.65 | medium |
| < 0.65 | low |

### Example alert

```json
{
  "timestamp": "2026-09-26T12:05:00Z",
  "rule": "user_behavior_anomaly",
  "score": 0.91,
  "severity": "critical",
  "host_id": "web-01",
  "user_id": "1000",
  "platform": "linux",
  "model": "isolation_forest",
  "window_seconds": 300,
  "feature_vector": {
    "event_count": 42.0,
    "failed_events": 30.0,
    "unique_processes": 25.0
  },
  "evidence": [
    "process:exec",
    "auth:login",
    "shell:command",
    "privilege:sudo"
  ]
}
```

An analyst reads that and already knows what kind of morning it will be.