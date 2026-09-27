"""Runtime configuration.

Small, boring, validated. The way config should be. DetectionConfig drives the
math, SiemConfig drives where the verdicts get shipped, InputDynamicsConfig
decides whether typing and mouse telemetry join the feature vector, and
AppConfig glues them together and knows how to read a TOML file, which is the
format IT admins actually edit. Nobody has ever hand-edited a YAML and felt
good about it.

The DaemonConfig section drives the continuous monitoring loop: collect fresh
telemetry, score it, retrain periodically, ship alerts, repeat until the heat
death of the universe or someone hits Ctrl-C, whichever comes first.
"""

import tomllib
from pathlib import Path

from pydantic import BaseModel, Field


class DetectionConfig(BaseModel):
    """Knobs for turning raw events into verdicts.

    window_seconds: size of each behavior window (epoch-aligned buckets)
    anomaly_threshold: minimum score for an event window to become an alert
    contamination: expected fraction of anomalies in training data
    min_events: smallest window worth scoring. Two events is a coincidence,
        not a behavior pattern.
    """

    window_seconds: int = Field(default=300, ge=1)
    anomaly_threshold: float = Field(default=0.65, ge=0.0, le=1.0)
    contamination: float = Field(default=0.01, gt=0.0, le=0.5)
    min_events: int = Field(default=5, ge=1)


class SiemConfig(BaseModel):
    """Where alerts go once we find something worth complaining about.

    kind: "syslog" (structured JSON through the local syslog, works everywhere,
        needs nothing) or "webhook" (HTTP POST, works with roughly every SIEM
        on earth, needs an endpoint). The default is syslog because a webhook
        without an endpoint is just wishful thinking.
    """

    kind: str = Field(default="syslog")
    endpoint: str | None = None
    api_key: str | None = None


class InputDynamicsConfig(BaseModel):
    """Whether typing and mouse motion join the feature vector.

    enabled: include input dynamics features in training and scoring. Off
        means the feature vector matches the classic fifteen, which matters
        if you have old models you are not ready to retrain.

    sampler_interval_seconds: hint for input samplers (agents feeding the
        jsonl front door) on how often to emit an aggregate event. BAD never
        samples input itself, it only consumes what an agent reports, so this
        is a suggestion we pass along, not a daemon we start.

    And to state the obvious, because in security the obvious is load-bearing:
    this feature is about timing and motion ONLY. Keystroke content capture is
    not an option here, and it never will be. What we never read, we never
    store, leak, or get subpoenaed over.
    """

    enabled: bool = True
    sampler_interval_seconds: int = Field(default=30, ge=1)


class DaemonCollectConfig(BaseModel):
    """Auto-collection: pull fresh OS telemetry every cycle.

    enabled: collect new events each cycle and append them to events_file.
        Off means the daemon only scores whatever an external agent already
        wrote. Useful when you have your own collector and just want the
        math.

    platform: which collector to use. Omit (None) to auto-detect from the
        running OS, which is what most people want. Set explicitly only when
        you are testing or running against a non-local source.

    since: time window passed to the collector. For the linux collector this
        becomes `journalctl --since`. Defaults to one interval back so we
        overlap slightly and never miss the boundary. Missing a few events
        is how attackers get a free minute, and we are not in the business
        of handing out free minutes.
    """

    enabled: bool = True
    platform: str | None = None
    since: str = "5 minutes ago"


class DaemonTrainConfig(BaseModel):
    """Auto-training: retrain the model from accumulated events.

    enabled: retrain periodically so the model drifts with the user instead
        of fossilizing on day one. A model that never learns is a model that
        thinks today is still the day you trained it.

    every_cycles: retrain every N daemon cycles. With a 300 second interval
        and every_cycles=12, that is once an hour. Set to 1 for paranoid
        retraining (slow), or 288 for once a day (comfy).
    """

    enabled: bool = True
    every_cycles: int = Field(default=12, ge=1)


class DaemonMonitorConfig(BaseModel):
    """Auto-monitoring: score new events and ship alerts every cycle.

    enabled: score events collected since the last cycle and send every
        alert to the configured SIEM sink. This is the whole point. If you
        turn this off you have built a very expensive event collector.
    """

    enabled: bool = True


class DaemonConfig(BaseModel):
    """The continuous monitoring loop, all knobs in one place.

    enabled: master switch. False and the daemon command refuses to start.
        One boolean to kill the whole feature, because sometimes you want
        the plumbing installed but the engine off.

    interval_seconds: how long the daemon sleeps between cycles. 300 (five
        minutes) is the default because it matches the default window size.
        Faster cycles burn CPU for diminishing returns; slower cycles give
        an attacker more runway before anyone notices.

    events_file: where collected events accumulate. Append-only, greppable,
        survives restarts. The daemon reads new events from here each cycle
        and retrains from the full history when scheduled.

    model_file: where the trained model lives. The daemon loads it for
        scoring and overwrites it when retraining. On the very first cycle
        with no model file, the daemon trains one before it starts scoring,
        because scoring against nothing is just guessing with confidence.

    collect, train, monitor: sub-sections, each independently toggleable.
        The daemon does what it is told, in that order, every cycle.
    """

    enabled: bool = True
    interval_seconds: int = Field(default=300, ge=1)
    events_file: Path = Field(default=Path("/var/lib/bad/events.jsonl"))
    model_file: Path = Field(default=Path("/var/lib/bad/model.joblib"))
    collect: DaemonCollectConfig = Field(default_factory=DaemonCollectConfig)
    train: DaemonTrainConfig = Field(default_factory=DaemonTrainConfig)
    monitor: DaemonMonitorConfig = Field(default_factory=DaemonMonitorConfig)


class AppConfig(BaseModel):
    """The whole toolbox in one object, straight from the admin's TOML file.

    Every section has defaults, so a config file can contain one line or a
    hundred. A missing key is a default, not an error. An invalid one is an
    error, because silent misconfiguration is how "we enabled the SIEM"
        becomes "we thought we enabled the SIEM".
    """

    detection: DetectionConfig = Field(default_factory=DetectionConfig)
    siem: SiemConfig = Field(default_factory=SiemConfig)
    input_dynamics: InputDynamicsConfig = Field(default_factory=InputDynamicsConfig)
    daemon: DaemonConfig = Field(default_factory=DaemonConfig)

    @classmethod
    def load(cls, path: Path | str) -> "AppConfig":
        """Load AppConfig from a TOML file.

        Missing sections and missing keys fall back to defaults, so the file
        the admin writes can grow as their confidence does. Unknown sections
        are likewise ignored, because rejecting a config for containing the
        future is a great way to make admins fear upgrades.
        """
        with Path(path).open("rb") as handle:
            data = tomllib.load(handle)
        return cls.model_validate(data)
