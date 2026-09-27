"""Tests for the pipeline: train, detect, monitor, the whole conveyor belt."""

from collections.abc import Sequence

import pytest
from tests.conftest import make_event

from behavior_anomaly.config import AppConfig, DetectionConfig
from behavior_anomaly.features.behavioral import BehavioralFeatures
from behavior_anomaly.models.base import AnomalyModel
from behavior_anomaly.pipeline import build_features, detect, monitor, train_model
from behavior_anomaly.schema import Alert, EventType
from behavior_anomaly.siem.base import SiemSink


class RecordingSink(SiemSink):
    """A SIEM that writes everything down. The most compliant SIEM there is."""

    def __init__(self) -> None:
        self.received: list[Alert] = []

    def send(self, alert: Alert) -> None:
        self.received.append(alert)


class StubModel(AnomalyModel):
    name = "stub"

    def __init__(self) -> None:
        pass

    def fit(self, rows: Sequence[dict[str, float]]) -> None:
        pass

    def score(self, row: dict[str, float]) -> float:
        return 0.95


def test_train_model_produces_a_fitted_model(benign_events):
    config = DetectionConfig()
    model = train_model(benign_events, config)
    assert model.name == "isolation_forest"
    assert model.columns, "an unfitted model is a participation trophy"


def test_train_model_ignores_starved_windows():
    # Two lonely events cannot fill a min_events=5 window, so training has
    # no rows at all. That must fail loudly, not hand back a trophy model.
    events = [make_event(0), make_event(1)]
    with pytest.raises(ValueError, match="empty dataset"):
        train_model(events, DetectionConfig())


def test_detect_with_stub_model_alerts_every_window():
    events = [make_event(offset) for offset in range(0, 600, 10)]
    alerts = detect(events, StubModel(), DetectionConfig())
    assert len(alerts) == 2
    assert all(alert.score == 0.95 for alert in alerts)


def test_monitor_sends_every_alert_to_the_sink():
    events = [make_event(offset) for offset in range(0, 600, 10)]
    sink = RecordingSink()
    alerts = monitor(events, StubModel(), DetectionConfig(), sink)

    assert len(alerts) == 2
    assert sink.received == alerts  # what we say we sent is what we sent


def test_build_features_respects_the_input_dynamics_toggle():
    # On: 23 columns. Off: 15. A model trained on one scored on the other
    # produces an error, not insight, so this switch must actually switch.
    on = build_features(AppConfig())
    off_config = AppConfig.model_validate({"input_dynamics": {"enabled": False}})
    off = build_features(off_config)

    assert isinstance(on, BehavioralFeatures)
    assert len(on.names()) == 23
    assert len(off.names()) == 15


def test_input_dynamics_flow_end_to_end():
    # The whole belt with input events in the stream: train with input
    # features on, then score the same stream through the same features.
    config = DetectionConfig()
    features = BehavioralFeatures(include_input_dynamics=True)
    events = [make_event(offset) for offset in range(0, 600, 10)]
    events.append(
        make_event(
            seconds_offset=550,
            event_type=EventType.INPUT,
            action="typing",
            process_name=None,
            metadata={"keystrokes": 90, "mean_interval_ms": 120, "stddev_interval_ms": 30},
        )
    )
    model = train_model(events, config, features=features)
    alerts = detect(events, model, config, features=features)
    # StubModel is not involved here; we only prove the plumbing accepts the
    # input vector, not that IsolationForest has opinions about our typing.
    assert all("keystrokes" in alert.feature_vector for alert in alerts)
