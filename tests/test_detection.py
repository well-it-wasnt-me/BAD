"""Tests for the detection engine. Verdicts, evidence and knowing when to stay quiet."""

from collections.abc import Sequence

from tests.conftest import make_event

from behavior_anomaly.config import DetectionConfig
from behavior_anomaly.detection.engine import DetectionEngine
from behavior_anomaly.features.behavioral import BehavioralFeatures
from behavior_anomaly.models.base import AnomalyModel
from behavior_anomaly.schema import EventType, Severity


class StubModel(AnomalyModel):
    """A model with the imagination of a doorknob: always the same score."""

    name = "stub"

    def __init__(self, score: float = 0.9) -> None:
        self.fixed_score = score

    def fit(self, rows: Sequence[dict[str, float]]) -> None:
        pass

    def score(self, row: dict[str, float]) -> float:
        return self.fixed_score


def _engine(score: float, config: DetectionConfig | None = None) -> DetectionEngine:
    return DetectionEngine(StubModel(score), BehavioralFeatures(), config or DetectionConfig())


def test_small_window_is_ignored():
    # Two events is a coincidence, not a behavior pattern.
    engine = _engine(0.99)
    assert engine.evaluate([make_event(0), make_event(1)]) is None


def test_boring_score_is_ignored():
    engine = _engine(0.5)
    events = [make_event(offset) for offset in range(5)]
    assert engine.evaluate(events) is None


def test_anomalous_window_produces_typed_alert():
    events = [make_event(offset, action=f"step-{offset}") for offset in range(5)]
    alert = _engine(0.9).evaluate(events)

    assert alert is not None
    assert alert.score == 0.9
    assert alert.severity == Severity.CRITICAL
    assert alert.user_id == "alice"
    assert alert.host_id == "host-1"
    assert alert.model == "stub"
    assert alert.window_seconds == 300
    assert alert.feature_vector["event_count"] == 5.0
    assert alert.evidence  # receipts included


def test_evidence_is_deduplicated_and_capped():
    events = [make_event(offset, action="exec") for offset in range(20)]
    alert = _engine(0.9).evaluate(events)
    assert alert is not None
    assert alert.evidence == ["process:exec"]


def test_detect_walks_all_windows():
    events = [make_event(offset) for offset in range(0, 600, 10)]
    alerts = _engine(0.9).detect(events)
    # 60 events, two 300 second buckets, every window above threshold.
    assert len(alerts) == 2


def test_detect_respects_threshold():
    events = [make_event(offset) for offset in range(0, 600, 10)]
    assert _engine(0.3).detect(events) == []


def test_mixed_event_types_flow_through():
    events = [
        make_event(0, event_type=EventType.AUTH, action="login", success=False),
        make_event(1, event_type=EventType.PRIVILEGE, action="sudo", privileged=True),
        make_event(2, event_type=EventType.NETWORK, action="connect"),
        make_event(3, event_type=EventType.SHELL, action="command"),
        make_event(4, event_type=EventType.FILE, action="write"),
    ]
    alert = _engine(0.8).evaluate(events)
    assert alert is not None
    assert alert.feature_vector["failed_events"] == 1.0
    assert alert.feature_vector["privileged_events"] == 1.0
