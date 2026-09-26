"""Tests for the core schemas. If these fail, everything above them is fiction."""

from datetime import UTC, datetime

import pytest
from pydantic import ValidationError
from tests.conftest import make_event

from behavior_anomaly.schema import Alert, BehaviorEvent, EventType, Platform, Severity


def test_event_holds_the_essentials():
    event = make_event()
    assert event.platform == Platform.LINUX
    assert event.event_type == EventType.PROCESS
    assert event.action == "exec"


def test_event_requires_identity():
    # An event without a user, host and time is a rumor, not telemetry.
    with pytest.raises(ValidationError):
        BehaviorEvent(
            timestamp=datetime.now(UTC),
            platform=Platform.LINUX,
            event_type=EventType.PROCESS,
            action="exec",
        )


def test_event_json_roundtrip():
    event = make_event(metadata={"pid": "42"})
    revived = BehaviorEvent.model_validate_json(event.model_dump_json())
    assert revived == event


def test_severity_from_score():
    assert Severity.from_score(0.5) == Severity.LOW
    assert Severity.from_score(0.7) == Severity.MEDIUM
    assert Severity.from_score(0.85) == Severity.HIGH
    assert Severity.from_score(0.99) == Severity.CRITICAL


def test_alert_score_must_stay_in_range():
    with pytest.raises(ValidationError):
        Alert(
            score=7.5,
            severity=Severity.HIGH,
            host_id="host-1",
            user_id="alice",
            platform=Platform.LINUX,
            model="isolation_forest",
            window_seconds=300,
        )


def test_alert_roundtrips_through_json():
    alert = Alert(
        score=0.9,
        severity=Severity.CRITICAL,
        host_id="host-1",
        user_id="alice",
        platform=Platform.LINUX,
        model="isolation_forest",
        window_seconds=300,
        feature_vector={"event_count": 42.0},
        evidence=["process:exec"],
    )
    revived = Alert.model_validate_json(alert.model_dump_json())
    assert revived.score == 0.9
    assert revived.severity == Severity.CRITICAL
    assert revived.evidence == ["process:exec"]
