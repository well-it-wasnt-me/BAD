"""Core data schemas.

Two shapes matter here: what a user did on a machine (BehaviorEvent) and what
we think about what they did (Alert). Everything else in this package exists
to turn the first into the second, ideally without paging anyone at 3 AM.
"""

from datetime import UTC, datetime
from enum import StrEnum

from pydantic import BaseModel, Field


class Platform(StrEnum):
    """The big three. BSD folks, you know where to find us."""

    LINUX = "linux"
    WINDOWS = "windows"
    MACOS = "macos"


class EventType(StrEnum):
    """Normalized event taxonomy shared by every collector."""

    PROCESS = "process"
    AUTH = "auth"
    SESSION = "session"
    FILE = "file"
    NETWORK = "network"
    SHELL = "shell"
    PRIVILEGE = "privilege"
    APPLICATION = "application"
    # Input dynamics: typing and mouse telemetry, aggregates only.
    # The timing of typing is a signature. The content of typing is a lawsuit.
    INPUT = "input"


class Severity(StrEnum):
    """How loud an alert is. SIEMs love renaming these, so we keep it boring."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @classmethod
    def from_score(cls, score: float) -> "Severity":
        """Map a 0..1 anomaly score to a severity. Cutoffs are opinionated,
        like everybody in security, but at least they are in one place."""
        if score >= 0.9:
            return cls.CRITICAL
        if score >= 0.8:
            return cls.HIGH
        if score >= 0.65:
            return cls.MEDIUM
        return cls.LOW


class BehaviorEvent(BaseModel):
    """One thing a user did, normalized across platforms.

    Collectors produce these. Features, models and detection never see raw OS
    telemetry, which is the only reason this package can support three
    operating systems without losing its mind.
    """

    timestamp: datetime
    host_id: str
    user_id: str
    platform: Platform
    event_type: EventType
    action: str
    process_name: str | None = None
    parent_process: str | None = None
    application: str | None = None
    source: str | None = None
    destination: str | None = None
    success: bool | None = None
    privileged: bool | None = None
    metadata: dict[str, str | int | float | bool | None] = Field(default_factory=dict)


class Alert(BaseModel):
    """A vendor-neutral finding: this user behaved abnormally in this window.

    No Splunk-isms, no Sentinel-isms. Any SIEM, XDR or agent can consume this
    shape, map it to their favorite schema (see siem.ecs), and get on with it.
    """

    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(UTC),
        description="When the anomaly was detected, not when it happened.",
    )
    rule: str = Field(default="user_behavior_anomaly", description="Rule that fired.")
    score: float = Field(ge=0.0, le=1.0, description="Anomaly score, 0.0 boring, 1.0 spicy.")
    severity: Severity
    host_id: str
    user_id: str
    platform: Platform
    model: str = Field(description="Name of the model that produced the score.")
    window_seconds: int = Field(ge=1, description="Size of the evaluated behavior window.")
    feature_vector: dict[str, float] = Field(
        default_factory=dict,
        description="Features of the window, for the analyst who wants receipts.",
    )
    evidence: list[str] = Field(
        default_factory=list,
        description="Short human-readable event summaries from the window.",
    )
