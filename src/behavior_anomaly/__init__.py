"""BAD: Behavior Anomaly Detection.

Collect Linux, Windows and macOS telemetry, normalize it, train on what
users normally do, and hand your SIEM a vendor-neutral alert when they stop
doing that. A tool for agents and monitoring stacks, not an agent itself.
The import package stays behavior_anomaly so nobody has to type
`from bad import Alert` with a straight face.
"""

__version__ = "1.0.0"

from behavior_anomaly.config import DetectionConfig, SiemConfig
from behavior_anomaly.detection.engine import DetectionEngine
from behavior_anomaly.detection.windowing import build_windows
from behavior_anomaly.features.behavioral import BehavioralFeatures
from behavior_anomaly.models.isolation_forest import IsolationForestModel
from behavior_anomaly.pipeline import detect, monitor, train_model
from behavior_anomaly.schema import Alert, BehaviorEvent, EventType, Platform, Severity
from behavior_anomaly.siem.ecs import to_ecs

__all__ = [
    "Alert",
    "BehaviorEvent",
    "BehavioralFeatures",
    "DetectionConfig",
    "DetectionEngine",
    "EventType",
    "IsolationForestModel",
    "Platform",
    "Severity",
    "SiemConfig",
    "build_windows",
    "detect",
    "monitor",
    "to_ecs",
    "train_model",
    "__version__",
]
