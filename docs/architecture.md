# Architecture

The package is a conveyor belt: collectors in, alerts out, and every layer
only talks to its neighbors through a contract. SOLID with a small footprint:
one interface per layer, one job per module, and nothing knows more than it
needs to.

## Layers

```text
+-----------------------------------------------------------+
|  collectors/  base.py, jsonl.py, linux.py, windows.py,     |
|               macos.py                                     |
|  Contract: Collector.collect() -> Iterator[BehaviorEvent] |
+-----------------------------------------------------------+
                        |
                        v
+-----------------------------------------------------------+
|  schema.py                                                 |
|  BehaviorEvent: one thing a user did, normalized           |
+-----------------------------------------------------------+
                        |
                        v
+-----------------------------------------------------------+
|  storage/  base.py, jsonl.py, alerts.py                    |
|  Contract: EventStore write/read/iter_events               |
+-----------------------------------------------------------+
                        |
                        v
+-----------------------------------------------------------+
|  features/  base.py, behavioral.py                         |
|  Contract: FeatureExtractor.extract(window) -> {str: f}   |
+-----------------------------------------------------------+
                        |
                        v
+-----------------------------------------------------------+
|  models/  base.py, isolation_forest.py, registry.py,       |
|           persistence.py                                  |
|  Contract: AnomalyModel.fit(rows) / .score(row)            |
+-----------------------------------------------------------+
                        |
                        v
+-----------------------------------------------------------+
|  detection/  windowing.py, engine.py                        |
|  windows -> features -> score -> Alert | None              |
+-----------------------------------------------------------+
                        |
                        v
+-----------------------------------------------------------+
|  pipeline.py  train_model / detect / monitor               |
|  The glue. The CLI is a thin skin over this module.        |
+-----------------------------------------------------------+
                        |
                        v
+-----------------------------------------------------------+
|  siem/  base.py, webhook.py, syslog.py, ecs.py             |
|  Contract: SiemSink.send(alert)                            |
+-----------------------------------------------------------+
```

## Design rules

**One schema to rule them all.** Everything downstream of the collectors sees
`BehaviorEvent` and nothing else. This is why three operating systems do not
cost three codebases.

**Pure parsers, impure plumbing.** Each OS collector splits its work into a
pure parse function (dict in, `BehaviorEvent` or None out, trivially
testable) and a thin subprocess wrapper that actually talks to the OS.
Plumbing is where bugs breed; we keep it starving.

**Windows are the unit of behavior.** Raw events are noise. The pipeline
buckets events per host, per user, per epoch-aligned time window, and a
window is what gets scored. Alice's Tuesday must not influence Bob's risk
score. Bob has enough problems.

**Models are replaceable.** `AnomalyModel` is two methods. Isolation Forest
is the baseline; when someone adds a temporal model or a per-user baseline,
the registry grows by one line and nothing else changes.

**Sinks are interchangeable.** A `SiemSink` accepts a typed `Alert`. Webhook
today, syslog today, Kafka or CEF tomorrow; the pipeline does not care.

**Alerts are vendor-neutral.** One typed JSON shape with score, severity,
evidence and the feature vector. Map it to ECS, map it to whatever your SIEM
ate for breakfast. The ECS mapper in `siem/ecs.py` is included, not required.

## Why unsupervised

Nobody labels user behavior at scale, and yesterday's "weird" is today's
"the new intern". Isolation Forest needs no labels, degrades gracefully when
normal drifts, and is explainable enough for an analyst to argue with, which
is the whole point.