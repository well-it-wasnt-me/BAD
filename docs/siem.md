# SIEM integration

Alerts are typed and vendor-neutral on purpose. This package does not marry
your SIEM; it hands over a boring JSON shape and lets your stack do its thing.

## Sinks

Two transports ship with the package, both behind one interface:

| Sink | Config kind | What it does |
|---|---|---|
| `WebhookSink` | `webhook` | POST each alert as JSON to any HTTP(S) endpoint, optional Bearer token |
| `SyslogSink` | `syslog` | Log each alert through the local syslog as a WARNING with compact JSON |

```python
from behavior_anomaly.config import SiemConfig
from behavior_anomaly.siem import build_sink

sink = build_sink(SiemConfig(kind="webhook", endpoint="https://siem.example.test/hook", api_key="SECRET"))
```

A webhook without an endpoint is rejected at construction time, because a
sink that cannot sink is just wishful thinking.

The HTTP client in the webhook sink is injectable (anything `httpx` shaped),
so tests use `httpx.MockTransport` instead of needing a live endpoint. Trust,
but verify.

## ECS mapping

For the Elastic-inclined (and everyone else who finds ECS convenient),
`to_ecs()` renders an `Alert` as an ECS-flavored dict:

```python
from behavior_anomaly.siem.ecs import to_ecs
from behavior_anomaly import Alert

ecs = to_ecs(alert)
# {
#   "@timestamp": ...,
#   "event": {"kind": "alert", "category": [...], "type": ["info"], "severity": 100},
#   "user": {"id": ...},
#   "host": {"id": ...},
#   "labels": {"platform": ..., "rule": ..., "model": ..., "window_seconds": ...},
#   "behavior": {"anomaly_score": ..., "features": {...}, "evidence": [...]},
#   "rule": {"name": "user_behavior_anomaly"}
# }
```

"ECS-flavored" because we are not Elastic, we just play them on TV. Severity
names map to the `event.severity` numeric scale: low 25, medium 50, high 75,
critical 100.

The CLI can print ECS directly:

```bash
bad score --input events.jsonl --model model.joblib --ecs
```

## Wiring it up yourself

Anything that can accept an `Alert` can be a sink. Implement `send(alert)`:

```python
from behavior_anomaly.siem.base import SiemSink
from behavior_anomaly.schema import Alert

class KafkaSink(SiemSink):
    def send(self, alert: Alert) -> None:
        ...  # your infrastructure, your rules
```

Then hand it to `pipeline.monitor()` and the alerts flow. The pipeline never
learns your SIEM's name, and your SIEM never learns ours.

## The fine print

- Webhook sends raise on non-2xx responses. A lost alert is worse than a
  crashed loop, and the caller deserves the truth.
- Syslog payloads are compact JSON on a single line, prefixed `SIEM_ALERT`,
  so the receiving parser has a fighting chance instead of a regex and a
  prayer.
- Every `monitor` run returns the alerts it sent, so callers can verify what
  actually shipped instead of trusting it worked. In security, "trust" is a
  bug.