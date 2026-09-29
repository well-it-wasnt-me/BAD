# BAD: Behavior Anomaly Detection

Cross-platform user behavior analytics, anomaly detection and SIEM alerting
for **Linux, Windows and macOS**.

The idea is simple. Users are creatures of habit. So are attackers pretending
to be users. This package learns what normal looks like on your fleet, scores
new behavior against it, and when a user starts doing things they never do,
it hands a vendor-neutral alert to your SIEM and lets the humans argue.

It is a **tool, not an agent (but it can loop)**. No heartbeat, no management
console. It is the math and the glue: collectors in, alerts out, and anything
in between is your call. Run it one-shot from cron, or run `bad daemon` for
the always-on collect/score/retrain loop — your call, not a sidecar we forced
on you.

## What it does

- **Collects** native telemetry from Linux (systemd journal and auditd),
  Windows (Security event log) and macOS (unified log), or ingests events
  your own agent already collected, as normalized JSONL
- **Normalizes** everything into one schema, `BehaviorEvent`, so the rest of
  the pipeline never has to care what an operating system sounds like
- **Extracts features** per user, per host, per time window, including
  optional **typing cadence and mouse movement** behavioral biometrics:
  aggregates only, never content, because the timing of typing is a
  signature and the content is a lawsuit
- **Trains** an unsupervised model (Isolation Forest baseline) on what normal
  looks like, because nobody has time to label "Tuesday" ten thousand times
- **Detects** anomalies and emits typed, vendor-neutral `Alert` objects
- **Ships** alerts to any SIEM via HTTP webhook or syslog, with an Elastic
  Common Schema mapping included
- **Configures** from one TOML file the IT admin owns: enable input
  dynamics, tune windows and thresholds, pick the sink. Flags override the
  file, the file overrides the defaults, and that is the whole ceremony

## What it does not do

- It does not take over your endpoint. No agent behavior, no persistence
  beyond files you point it at.
- It does not marry any SIEM. Findings are open by design; transports are
  interchangeable by interface.
- It does not guess. Collectors skip telemetry they cannot identify. Silence
  beats fiction.

## The signal nobody else listens for

Process and auth telemetry tells you *what* a user did. Typing cadence and
mouse motion tell you *who* was at the keyboard. A hijacked session almost
always types and mouses differently from the legitimate owner, no matter how
careful the attacker is about which commands they run. Pure process telemetry
is deaf to that signal; BAD is not.

BAD derives behavioral biometrics from **typing cadence** (keystroke counts,
mean and stddev of inter-key intervals, typing velocity) and **mouse movement
patterns** (distance, speed, direction changes). These are aggregates only,
reported by an agent over the JSONL front door. BAD never records keystrokes,
never reads content, and there is no option to turn that on, on any platform,
ever. The timing of typing is a signature. The content of typing is a lawsuit.

This is the part that makes BAD more than a process-log counter with a
threshold: the model can flag a session where the commands look normal but
the human behind them does not. That is the difference between "something
happened" and "someone else happened".

## Pipeline

```text
OS collectors / agent JSONL
        |
        v
   BehaviorEvent
        |
        v
 feature extraction (windows)
        |
        v
  anomaly model (trainable)
        |
        v
  detection policy
        |
        v
  Alert (vendor-neutral)
        |
        v
  SIEM (webhook, syslog, ECS)
```

Start with [Architecture](architecture.md) for how the layers fit together,
or [Usage](usage.md) if you just want the thing to run.

The CLI, the distribution and the executables are all `bad`, except on PyPI,
where the distribution is `behavior-anomaly-detection` because the short name
was squatted in 2018 by an Android driver that has been dead longer than some
of its users. The import package is `behavior_anomaly`, so nobody ever has to
type `from bad import Alert` with a straight face.