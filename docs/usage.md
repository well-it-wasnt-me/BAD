# Usage

## Install

```bash
pip install -e .          # or pip install behavior-anomaly-detection from your registry
```

The CLI is `bad`, and the same pipeline is importable from
Python for agents and monitoring tools that prefer in-process to shelling
out. A CLI is a convenience, not a personality.

## Step by step

### 1. Collect events

From the local OS:

```bash
bad collect --platform linux --output events.jsonl --since "1 hour ago"
bad collect --platform windows --output events.jsonl
bad collect --platform macos --output events.jsonl
```

Or ingest events your own agent already collected and normalized:

```bash
bad collect --platform jsonl --source agent-events.jsonl --output events.jsonl
```

The `jsonl` path is the front door for agents, EDRs and monitoring stacks.
They collect and normalize, we do the math. Division of labor, people.

### 2. Train

```bash
bad train --input events.jsonl --output model.joblib
```

Options worth knowing:

| Option | Default | Meaning |
|---|---|---|
| `--config` | none | TOML config file (see below); flags override it |
| `--window-seconds` | 300 | Behavior window size |
| `--contamination` | 0.01 | Expected anomaly fraction in training data |
| `--min-events` | 5 | Minimum events per window to train on |

Windows smaller than `--min-events` are dropped. Two events is a
coincidence, not a behavioral profile.

### 3. Score

```bash
bad score --input events.jsonl --model model.joblib
bad score --input events.jsonl --model model.joblib --output alerts.jsonl
bad score --input events.jsonl --model model.joblib --ecs
```

`--ecs` prints alerts rendered as Elastic Common Schema flavored JSON, for
the Elastic-inclined.

### 4. Monitor (score and ship)

```bash
bad monitor --input events.jsonl --model model.joblib --siem syslog
bad monitor --input events.jsonl --model model.joblib \
    --siem webhook --endpoint https://siem.example.test/hook --api-key SECRET
```

Every alert that clears the threshold goes to the sink. The command prints
exactly how many were sent, because "trust" is a bug.

## The config file

Every command accepts `--config /path/to/config.toml`, and the repo ships a
commented example: `config.example.toml`. Copy it, edit it, point at it.

```toml
[detection]
window_seconds = 300
anomaly_threshold = 0.65
contamination = 0.01
min_events = 5

[siem]
kind = "syslog"          # or "webhook", with an endpoint

[input_dynamics]
enabled = true
sampler_interval_seconds = 30
```

The precedence is boring and predictable: built-in defaults lose to the
config file, the config file loses to command line flags. Every key is
optional, a missing key falls back to its default, and unknown sections are
ignored, because rejecting a config for containing the future makes admins
fear upgrades. An invalid value is still an error. Silent misconfiguration is
how "we enabled the SIEM" becomes "we thought we enabled the SIEM".

The `[input_dynamics]` section decides whether typing and mouse features
join the model. If you have models trained before input dynamics existed,
keep `enabled = false` until you retrain, because a model trained on 15
columns scored against 23 produces an error, not insight.

One more thing, in writing: input dynamics are timing and motion ONLY.
BAD consumes aggregates reported by an agent. It never records keystrokes
itself, never reads content from input metadata, and no config option turns
that on, ever. See [Event Schema](schema.md) for what input events carry.

And before the scheduler discovers your config has a typo at 3 AM:

```bash
bad check-config --config /etc/bad/config.toml
```

It validates the file and prints the effective settings: windows, threshold,
sink, input dynamics. The same command the deployment templates run, so what
your deploy log said is what your fleet will do. Fleet-wide rollout lives in
[Deployment](deployment.md).

## Python API

The CLI is a thin skin over `behavior_anomaly.pipeline`. Anything with an
interpreter can drive the same conveyor belt:

```python
from behavior_anomaly import (
    DetectionConfig, train_model, detect, to_ecs,
)
from behavior_anomaly.siem import build_sink, SiemConfig
from behavior_anomaly.storage.jsonl import JsonlStore
from behavior_anomaly.models.persistence import load_model, save_model

config = DetectionConfig(window_seconds=300)

# Train
events = JsonlStore("events.jsonl").read()
model = train_model(events, config)
save_model(model, "model.joblib")

# Score
alerts = detect(JsonlStore("new-events.jsonl").read(), load_model("model.joblib"), config)

# Ship
sink = build_sink(SiemConfig(kind="webhook", endpoint="https://siem.example.test/hook"))
for alert in alerts:
    sink.send(to_ecs(alert))
```

## Tuning advice, free of charge

- Start with the default 300 second windows. Shrink for dense telemetry,
  grow for sparse fleets. A window with two events says nothing at any size.
- `--threshold 0.65` is opinionated. Watch your alert volume and move it:
  too high and you miss the fun, too low and the SIEM learns to ignore you,
  which is the worst place a detection tool can be.
- `--contamination` should match roughly how wrong your training data is.
  Not how wrong your users are. They are always worse.