"""Pipeline orchestration.

This module glues features, models, detection and SIEM sinks into three verbs:
train, detect, monitor. The CLI is a thin skin over this file so agents and
monitoring tools can import and drive the exact same pipeline in-process,
without shelling out to a terminal like it is 1999.
"""

from collections.abc import Iterable

from behavior_anomaly.config import AppConfig, DetectionConfig
from behavior_anomaly.detection.engine import DetectionEngine
from behavior_anomaly.detection.windowing import build_windows
from behavior_anomaly.features.base import FeatureExtractor
from behavior_anomaly.features.behavioral import BehavioralFeatures
from behavior_anomaly.models.base import AnomalyModel
from behavior_anomaly.models.registry import build_model
from behavior_anomaly.schema import Alert, BehaviorEvent
from behavior_anomaly.siem.base import SiemSink


def build_features(app_config: AppConfig) -> BehavioralFeatures:
    """Build the feature extractor the admin actually configured.

    Input dynamics on or off changes the feature vector length, and models
    are picky about that: train with 23 columns, score with 15, and
    sklearn will hand you back an error shaped like a shrug. This is the one
    place that decides, so train and score go through it.
    """
    return BehavioralFeatures(include_input_dynamics=app_config.input_dynamics.enabled)


def train_model(
    events: Iterable[BehaviorEvent],
    config: DetectionConfig,
    model_name: str = "isolation_forest",
    features: FeatureExtractor | None = None,
) -> AnomalyModel:
    """Train an anomaly model over windowed behavior.

    Windows smaller than config.min_events are dropped: two events is a
    coincidence, not a behavioral profile. Training on coincidence is how
    models learn that everything is fine right up until it is not.
    """
    features = features or BehavioralFeatures()
    windows = [window for window in build_windows(events, config.window_seconds) if len(window) >= config.min_events]
    rows = [features.extract(window) for window in windows]
    model = build_model(model_name, contamination=config.contamination)
    model.fit(rows)
    return model


def detect(
    events: Iterable[BehaviorEvent],
    model: AnomalyModel,
    config: DetectionConfig,
    features: FeatureExtractor | None = None,
) -> list[Alert]:
    """Score an event stream and return every alert that cleared the bar."""
    engine = DetectionEngine(model, features or BehavioralFeatures(), config)
    return engine.detect(events)


def monitor(
    events: Iterable[BehaviorEvent],
    model: AnomalyModel,
    config: DetectionConfig,
    sink: SiemSink,
    features: FeatureExtractor | None = None,
) -> list[Alert]:
    """Detect anomalies and ship every alert to a SIEM sink.

    Returns the alerts as well, so callers (tests, CLIs, curious humans) can
    see exactly what was sent instead of trusting that it worked. In security,
    "trust" is a bug.
    """
    alerts = detect(events, model, config, features)
    for alert in alerts:
        sink.send(alert)
    return alerts
