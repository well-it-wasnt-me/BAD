"""Runtime configuration.

Small, boring, validated. The way config should be. DetectionConfig drives the
math, SiemConfig drives where the verdicts get shipped, InputDynamicsConfig
decides whether typing and mouse telemetry join the feature vector, and
AppConfig glues them together and knows how to read a TOML file, which is the
format IT admins actually edit. Nobody has ever hand-edited a YAML and felt
good about it.
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
