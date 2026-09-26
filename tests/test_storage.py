"""Tests for storage: events and alerts on disk."""

from tests.conftest import make_event

from behavior_anomaly.schema import Alert, Platform, Severity
from behavior_anomaly.storage.alerts import JsonlAlertStore
from behavior_anomaly.storage.jsonl import JsonlStore


def test_jsonl_write_read_roundtrip(tmp_path):
    store = JsonlStore(tmp_path / "events.jsonl")
    events = [make_event(offset) for offset in range(3)]

    store.write(events)
    assert store.read() == events


def test_jsonl_write_appends(tmp_path):
    # Event history is never overwritten. Ask any SIEM, they never forget.
    store = JsonlStore(tmp_path / "events.jsonl")
    store.write([make_event(0)])
    store.write([make_event(1)])
    assert len(store.read()) == 2


def test_jsonl_iter_events_streams(tmp_path):
    store = JsonlStore(tmp_path / "events.jsonl")
    store.write([make_event(offset) for offset in range(5)])

    stream = store.iter_events()
    assert not isinstance(stream, list)
    assert len(list(stream)) == 5


def test_jsonl_skips_blank_lines(tmp_path):
    path = tmp_path / "events.jsonl"
    path.write_text("\n" + make_event(0).model_dump_json() + "\n\n", encoding="utf-8")
    assert len(JsonlStore(path).read()) == 1


def test_alert_store_writes_one_json_line_per_alert(tmp_path):
    store = JsonlAlertStore(tmp_path / "alerts.jsonl")
    alerts = [
        Alert(
            score=0.9,
            severity=Severity.CRITICAL,
            host_id="host-1",
            user_id="alice",
            platform=Platform.LINUX,
            model="isolation_forest",
            window_seconds=300,
        ),
        Alert(
            score=0.7,
            severity=Severity.MEDIUM,
            host_id="host-2",
            user_id="bob",
            platform=Platform.WINDOWS,
            model="isolation_forest",
            window_seconds=300,
        ),
    ]
    store.write(alerts)

    lines = store.path.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 2
    assert Alert.model_validate_json(lines[1]).user_id == "bob"


def test_alert_store_overwrites_previous_run(tmp_path):
    store = JsonlAlertStore(tmp_path / "alerts.jsonl")
    alert = Alert(
        score=0.9,
        severity=Severity.CRITICAL,
        host_id="host-1",
        user_id="alice",
        platform=Platform.LINUX,
        model="isolation_forest",
        window_seconds=300,
    )
    store.write([alert])
    store.write([alert])
    # The last scoring run is the truth. History wears a trench coat.
    assert len(store.path.read_text(encoding="utf-8").strip().splitlines()) == 1
