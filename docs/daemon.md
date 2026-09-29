# Continuous Monitoring Daemon

The CLI commands (`collect`, `train`, `score`, `monitor`) are one-shot verbs:
run once, produce a result, exit. The daemon is the always-on half of BAD.
It loops collect -> train -> monitor on a timer, forever, or until someone
tells it to stop. This is what runs on the endpoint while you sleep.

## Starting the daemon

```bash
bad daemon                          # loop forever, Ctrl-C to stop
bad daemon --config /etc/bad/config.toml
bad daemon --once                   # single cycle, for cron or smoke tests
bad daemon --verbose                # DEBUG logging
```

Without `--once`, the daemon runs until it receives SIGINT (Ctrl-C) or
SIGTERM. The current cycle finishes, then the loop exits cleanly. No
half-written files, no orphaned model state.

## What each cycle does

Every `interval_seconds` (default 300, five minutes), the daemon runs one
cycle in this order:

1. **Collect** (if enabled): pull fresh OS telemetry and append to
   `events_file`. Auto-detects the platform from the running OS, or uses
   the explicit `platform` from config.

2. **Train** (if scheduled): retrain the model from the full event history
   in `events_file`. Retraining happens every `every_cycles` cycles (default
   12, so once an hour at the default interval). On the very first cycle
   with no model file, the daemon forces a train before it starts scoring,
   because scoring against nothing is just guessing with confidence.

3. **Monitor** (if enabled): score the events collected since the last
   cycle and ship every alert to the configured SIEM sink. The daemon
   tracks its position in `events_file` so it only scores new events, not
   the entire history every time.

If any stage fails (collector unavailable, too few events to train, model
corrupt), the daemon logs the error and continues to the next stage. A bad
cycle is a bad cycle, not a dead daemon. It tries again next time.

## Configuration

All daemon settings live under the `[daemon]` section of the TOML config.
Every key is optional with sensible defaults. The daemon is ready to run
out of the box.

```toml
[daemon]
enabled = true                    # master switch
interval_seconds = 300            # sleep between cycles
events_file = "/var/lib/bad/events.jsonl"
model_file = "/var/lib/bad/model.joblib"

[daemon.collect]
enabled = true                    # pull fresh telemetry each cycle
# platform = "linux"             # omit to auto-detect
since = "5 minutes ago"           # time window for the collector

[daemon.train]
enabled = true                    # retrain periodically
every_cycles = 12                 # retrain every N cycles (12 * 300s = 1h)

[daemon.monitor]
enabled = true                    # score and ship alerts each cycle
```

The SIEM sink is configured in the existing `[siem]` section. The daemon
uses the same sink as the `bad monitor` command. See
[SIEM Integration](siem.md).

### Disabling stages

Each stage is independently toggleable:

- **Collect only**: set `train.enabled = false` and `monitor.enabled = false`.
  The daemon becomes a scheduled collector that writes to `events_file`.
  Useful when you want BAD to gather data but score it elsewhere.

- **Monitor only**: set `collect.enabled = false` and `train.enabled = false`.
  The daemon scores events an external agent writes to `events_file`. Useful
  when you have your own collector (an EDR, a log shipper) and just want the
  math.

- **Collect + monitor, no retrain**: set `train.enabled = false`. The daemon
  uses an externally trained model and never overwrites it. Useful when
  retraining must be controlled manually.

## Running as a service

### systemd (Linux)

```ini
# /etc/systemd/system/bad-daemon.service
[Unit]
Description=BAD Behavior Anomaly Detection Daemon
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/bad daemon --config /etc/bad/config.toml
Restart=on-failure
RestartSec=30
User=badsvc
Group=badsvc

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl enable --now bad-daemon
```

The daemon needs read access to the systemd journal (for the linux
collector) and write access to `events_file` and `model_file`. A dedicated
`badsvc` user with appropriate permissions is the boring, correct answer,
and the name the deploy templates in `deploy/` use.

### cron (any platform)

For environments without a service manager, `--once` runs a single cycle
and exits:

```cron
# Every 5 minutes
*/5 * * * * bad daemon --once --config /etc/bad/config.toml >> /var/log/bad.log 2>&1
```

This is less resilient than the loop (no interruptible sleep, no signal
handling, no in-process state between cycles) but it works everywhere cron
works, which is everywhere.

## Python API

The daemon is importable for tools that want to drive it in-process:

```python
import threading
from behavior_anomaly.config import AppConfig
from behavior_anomaly.daemon import run_loop, install_signal_handlers

config = AppConfig.load("/etc/bad/config.toml")
stop_event = threading.Event()
install_signal_handlers(stop_event)
run_loop(config, stop_event=stop_event)
```

For testing or one-shot use, `run_cycle` runs a single cycle without
looping or sleeping:

```python
from behavior_anomaly.config import AppConfig
from behavior_anomaly.daemon import DaemonState, run_cycle

config = AppConfig.load("/etc/bad/config.toml")
result = run_cycle(config, DaemonState())
print(f"collected={result.collected} trained={result.trained} alerts={result.alerts}")
```
