"""Tests for the continuous monitoring daemon.

The daemon is a loop, and loops are hard to test. So we test the cycle
function (one iteration, no sleeping) thoroughly, and the loop function
lightly (does it stop when told? does it call run_cycle?). The cycle is
where the logic lives; the loop is just a while-True with manners.
"""

from __future__ import annotations

import threading
from pathlib import Path
from unittest.mock import patch

import pytest
from tests.conftest import make_event

from behavior_anomaly.config import (
    AppConfig,
    DaemonCollectConfig,
    DaemonConfig,
    DaemonMonitorConfig,
    DaemonTrainConfig,
    DetectionConfig,
)
from behavior_anomaly.daemon import (
    DaemonState,
    _read_events_since,
    detect_platform,
    run_cycle,
    run_loop,
    should_retrain,
)
from behavior_anomaly.siem.base import SiemSink
from behavior_anomaly.storage.jsonl import JsonlStore

# ----------------------------------------------------------------- helpers


class FakeSink(SiemSink):
    """A SIEM sink that collects alerts in a list instead of sending them.

    Tests need to see what was sent. A real syslog sink would throw alerts
    into the void and we would have to grep /var/log to verify them, which
    is a great way to hate testing.
    """

    def __init__(self) -> None:
        self.alerts: list = []

    def send(self, alert) -> None:
        self.alerts.append(alert)


def make_app_config(
    tmp_path: Path,
    *,
    daemon_enabled: bool = True,
    collect_enabled: bool = True,
    train_enabled: bool = True,
    monitor_enabled: bool = True,
    every_cycles: int = 12,
    interval_seconds: int = 300,
    platform: str | None = None,
    min_events: int = 5,
) -> AppConfig:
    """Build an AppConfig with the daemon pointed at temp files.

    Every test needs roughly the same config shape but with one or two knobs
    flipped. This factory keeps the boilerplate in one place so the tests
    can focus on what they are actually checking.
    """
    return AppConfig(
        detection=DetectionConfig(min_events=min_events),
        daemon=DaemonConfig(
            enabled=daemon_enabled,
            interval_seconds=interval_seconds,
            events_file=tmp_path / "events.jsonl",
            model_file=tmp_path / "model.joblib",
            collect=DaemonCollectConfig(enabled=collect_enabled, platform=platform),
            train=DaemonTrainConfig(enabled=train_enabled, every_cycles=every_cycles),
            monitor=DaemonMonitorConfig(enabled=monitor_enabled),
        ),
    )


def seed_events(path: Path, count: int, start_offset: int = 0) -> None:
    """Write `count` synthetic events to a JSONL file."""
    events = [make_event(seconds_offset=start_offset + i * 10) for i in range(count)]
    JsonlStore(path).write(events)


# ------------------------------------------------------------- detect_platform


def test_detect_platform_returns_a_known_name():
    """detect_platform must return linux, windows, or macos, never None."""
    name = detect_platform()
    assert name in ("linux", "windows", "macos")


def test_detect_platform_raises_on_unknown(monkeypatch):
    """An OS we do not recognize should raise, not silently pick a default."""
    monkeypatch.setattr("behavior_anomaly.daemon._platform_module.system", lambda: "Plan9")
    with pytest.raises(ValueError, match="Cannot auto-detect"):
        detect_platform()


# ----------------------------------------------------------- should_retrain


def test_should_retrain_on_scheduled_cycle():
    """every_cycles=12 means cycle 0, 12, 24, ... retrain."""
    config = DaemonConfig(
        model_file=Path("/tmp/model.joblib"),
        train=DaemonTrainConfig(enabled=True, every_cycles=12),
    )
    # No model file exists, so bootstrap also triggers.
    assert should_retrain(config, DaemonState(cycle=0)) is True
    assert should_retrain(config, DaemonState(cycle=12)) is True
    assert should_retrain(config, DaemonState(cycle=24)) is True


def test_should_retrain_skips_unscheduled_cycle(tmp_path):
    """Between scheduled cycles, no retrain unless bootstrapping."""
    model_file = tmp_path / "model.joblib"
    model_file.touch()  # model exists, so no bootstrap needed
    config = DaemonConfig(
        model_file=model_file,
        train=DaemonTrainConfig(enabled=True, every_cycles=12),
    )
    assert should_retrain(config, DaemonState(cycle=1)) is False
    assert should_retrain(config, DaemonState(cycle=5)) is False


def test_should_retrain_disabled():
    """Training disabled means never retrain, even on cycle 0."""
    config = DaemonConfig(
        model_file=Path("/tmp/model.joblib"),
        train=DaemonTrainConfig(enabled=False),
    )
    assert should_retrain(config, DaemonState(cycle=0)) is False


def test_should_retrain_bootstrap_when_no_model(tmp_path):
    """If monitoring is on but no model exists, force a train on cycle 0."""
    config = DaemonConfig(
        model_file=tmp_path / "ghost.joblib",  # does not exist
        train=DaemonTrainConfig(enabled=True, every_cycles=999),
        monitor=DaemonMonitorConfig(enabled=True),
    )
    # every_cycles=999 means cycle 0 is the only scheduled one, but
    # bootstrap also forces it. Either way, True.
    assert should_retrain(config, DaemonState(cycle=0)) is True
    # Cycle 1: not scheduled, and still no model (we did not actually train).
    assert should_retrain(config, DaemonState(cycle=1)) is True


def test_should_retrain_no_bootstrap_when_monitor_off(tmp_path):
    """If monitoring is off, no bootstrap train is needed."""
    config = DaemonConfig(
        model_file=tmp_path / "ghost.joblib",
        train=DaemonTrainConfig(enabled=True, every_cycles=999),
        monitor=DaemonMonitorConfig(enabled=False),
    )
    # Cycle 0 is still scheduled (0 % 999 == 0), so True.
    assert should_retrain(config, DaemonState(cycle=0)) is True
    # Cycle 1: not scheduled, monitor off, no bootstrap.
    assert should_retrain(config, DaemonState(cycle=1)) is False


# ------------------------------------------------------------- run_cycle


def test_run_cycle_disabled_daemon(tmp_path):
    """A disabled daemon reports it skipped everything and does nothing."""
    config = make_app_config(tmp_path, daemon_enabled=False)
    result = run_cycle(config, DaemonState(), sink=FakeSink())
    assert result.collected == 0
    assert result.trained is False
    assert result.scored == 0
    assert "daemon disabled" in result.skipped


def test_run_cycle_full_bootstrap(tmp_path, benign_events):
    """First cycle with no model: collect, train (bootstrap), monitor.

    This is the happy path: the daemon starts cold, collects events, trains
    a model from them, and scores them. If this works, the daemon can stand
    on its own two feet from a cold start.
    """
    config = make_app_config(tmp_path, platform="jsonl", every_cycles=1)

    # We need the collector to return events. Patch build_collector to
    # return a fake that yields our benign_events.
    fake_events = list(benign_events)

    class FakeCollector:
        def collect(self):
            return iter(fake_events)

    with patch("behavior_anomaly.daemon.build_collector", return_value=FakeCollector()):
        sink = FakeSink()
        state = DaemonState()
        result = run_cycle(config, state, sink=sink)

    assert result.cycle == 0
    assert result.collected == 60
    assert result.trained is True
    assert result.scored == 60
    # The model file should now exist.
    assert config.daemon.model_file.exists()
    # Events should be in the events file.
    assert Path(config.daemon.events_file).exists()
    # State should have advanced.
    assert state.cycle == 1
    assert state.byte_offset > 0


def test_run_cycle_collect_disabled(tmp_path):
    """Collect off means no events gathered, but the cycle still runs."""
    config = make_app_config(tmp_path, collect_enabled=False, platform="jsonl")
    result = run_cycle(config, DaemonState(), sink=FakeSink())
    assert result.collected == 0
    assert "collect disabled" in result.skipped


def test_run_cycle_train_disabled(tmp_path, benign_events):
    """Train off means no model produced, monitor has nothing to score."""
    config = make_app_config(
        tmp_path, platform="jsonl", train_enabled=False, monitor_enabled=False
    )
    fake_events = list(benign_events)

    class FakeCollector:
        def collect(self):
            return iter(fake_events)

    with patch("behavior_anomaly.daemon.build_collector", return_value=FakeCollector()):
        result = run_cycle(config, DaemonState(), sink=FakeSink())

    assert result.collected == 60
    assert result.trained is False
    assert "train disabled" not in result.skipped  # train.enabled=False, no skip msg
    assert result.scored == 0
    assert "monitor disabled" in result.skipped


def test_run_cycle_monitor_disabled(tmp_path, benign_events):
    """Monitor off means events collected and model trained, but no scoring."""
    config = make_app_config(
        tmp_path, platform="jsonl", every_cycles=1, monitor_enabled=False
    )
    fake_events = list(benign_events)

    class FakeCollector:
        def collect(self):
            return iter(fake_events)

    with patch("behavior_anomaly.daemon.build_collector", return_value=FakeCollector()):
        result = run_cycle(config, DaemonState(), sink=FakeSink())

    assert result.collected == 60
    assert result.trained is True
    assert result.scored == 0
    assert "monitor disabled" in result.skipped


def test_run_cycle_monitor_uses_existing_model(tmp_path, benign_events):
    """Second cycle: model already exists, only monitor runs (no retrain)."""
    config = make_app_config(tmp_path, platform="jsonl", every_cycles=999)

    # Pre-seed events and train a model manually.
    seed_events(config.daemon.events_file, 60)
    from behavior_anomaly.models.persistence import save_model
    from behavior_anomaly.pipeline import build_features, train_model

    model = train_model(
        JsonlStore(config.daemon.events_file).read(),
        config.detection,
        features=build_features(config),
    )
    save_model(model, config.daemon.model_file)

    # Now run a cycle that collects more events and monitors.
    # No new events from collector, so monitor reads existing events.
    # But byte_offset starts at 0, so it reads everything.
    state = DaemonState(cycle=5)  # not a retrain cycle

    class FakeCollector:
        def collect(self):
            return iter([])  # no new events

    with patch("behavior_anomaly.daemon.build_collector", return_value=FakeCollector()):
        sink = FakeSink()
        result = run_cycle(config, state, sink=sink)

    assert result.collected == 0
    assert result.trained is False
    assert "train not scheduled this cycle" in result.skipped
    assert result.scored == 60  # read from byte_offset 0
    assert state.byte_offset > 0


def test_run_cycle_collect_failure_does_not_crash(tmp_path):
    """A collector that raises should be logged, not fatal."""
    config = make_app_config(tmp_path, platform="linux")

    def fake_build_collector(kind, source=None):
        raise FileNotFoundError("journalctl not found")

    with patch("behavior_anomaly.daemon.build_collector", side_effect=fake_build_collector):
        result = run_cycle(config, DaemonState(), sink=FakeSink())

    assert result.collected == 0
    assert "collect failed" in result.skipped
    # The cycle did not crash; it continued to train/monitor.


def test_run_cycle_train_failure_does_not_crash(tmp_path, benign_events):
    """Training on too few events raises, but the daemon survives."""
    config = make_app_config(tmp_path, platform="jsonl", every_cycles=1, min_events=999)

    fake_events = [make_event(seconds_offset=0)]  # only 1 event

    class FakeCollector:
        def collect(self):
            return iter(fake_events)

    with patch("behavior_anomaly.daemon.build_collector", return_value=FakeCollector()):
        result = run_cycle(config, DaemonState(), sink=FakeSink())

    assert result.collected == 1
    assert result.trained is False
    assert "train failed" in result.skipped


# ------------------------------------------------------- _read_events_since


def test_read_events_since_returns_new_events(tmp_path, benign_events):
    """Only events after byte_offset should be returned."""
    path = tmp_path / "events.jsonl"
    seed_events(path, 30)
    first_size = path.stat().st_size

    # Read from offset 0: all 30.
    events = _read_events_since(path, 0)
    assert len(events) == 30

    # Write 30 more, read from first_size: only the new 30.
    seed_events(path, 30, start_offset=300)
    events = _read_events_since(path, first_size)
    assert len(events) == 30


def test_read_events_since_empty_file(tmp_path):
    """No file means no events, not an exception."""
    events = _read_events_since(tmp_path / "ghost.jsonl", 0)
    assert events == []


def test_read_events_since_file_shrunk(tmp_path, benign_events):
    """A file that shrank (rotated) should be read from the start."""
    path = tmp_path / "events.jsonl"
    seed_events(path, 60)
    big_offset = path.stat().st_size

    # Truncate and write fewer events (simulating log rotation).
    path.write_text("", encoding="utf-8")
    seed_events(path, 10)

    events = _read_events_since(path, big_offset)
    assert len(events) == 10  # started over, not crashed


def test_read_events_since_no_new_events(tmp_path, benign_events):
    """Offset at end of file means zero new events."""
    path = tmp_path / "events.jsonl"
    seed_events(path, 30)
    end_offset = path.stat().st_size

    events = _read_events_since(path, end_offset)
    assert events == []


# --------------------------------------------------------------- run_loop


def test_run_loop_runs_one_cycle_then_stops(tmp_path, benign_events):
    """The loop should run one cycle, then stop when the event is set during sleep."""
    config = make_app_config(tmp_path, platform="jsonl", interval_seconds=1, every_cycles=1)
    stop_event = threading.Event()

    fake_events = list(benign_events)

    class FakeCollector:
        def collect(self):
            return iter(fake_events)

    def fake_sleep(seconds):
        # Set the stop flag during sleep so the loop exits after one cycle.
        stop_event.set()

    with patch("behavior_anomaly.daemon.build_collector", return_value=FakeCollector()):
        run_loop(config, stop_event=stop_event, sleep_func=fake_sleep)

    # The events file should have been written (one cycle ran).
    assert config.daemon.events_file.exists()


def test_run_loop_disabled_daemon_does_nothing(tmp_path):
    """A disabled daemon should refuse to loop at all."""
    config = make_app_config(tmp_path, daemon_enabled=False)
    stop_event = threading.Event()
    run_loop(config, stop_event=stop_event, sleep_func=lambda s: None)
    # Nothing was written because the loop returned immediately.
    assert not config.daemon.events_file.exists()


# --------------------------------------------------- daemon hardening


def test_run_loop_builds_sink_once_and_closes_it(tmp_path, benign_events, monkeypatch):
    # The loop must build the webhook sink once (not per cycle) and close it
    # on exit. A per-cycle rebuild leaks an httpx connection pool.
    builds = {"n": 0}
    closes = {"n": 0}

    class RecordingSink(SiemSink):
        def __init__(self) -> None:
            builds["n"] += 1
            self.alerts: list = []

        def send(self, alert) -> None:  # noqa: ANN001
            self.alerts.append(alert)

        def close(self) -> None:
            closes["n"] += 1

    # Point siem at a webhook so run_loop builds a sink.
    config = make_app_config(tmp_path, platform="jsonl", interval_seconds=1, every_cycles=1)
    config = config.model_copy(
        update={"siem": config.siem.model_copy(update={"kind": "webhook", "endpoint": "https://x.test"})}
    )

    class FakeCollector:
        def collect(self):
            return iter(list(benign_events))

    monkeypatch.setattr("behavior_anomaly.daemon.build_collector", lambda *a, **kw: FakeCollector())
    # Replace build_sink so we get our RecordingSink instead of a real httpx client.
    monkeypatch.setattr("behavior_anomaly.daemon.build_sink", lambda _cfg: RecordingSink())

    stop_event = threading.Event()

    def fake_sleep(_s):
        stop_event.set()

    run_loop(config, stop_event=stop_event, sleep_func=fake_sleep)
    assert builds["n"] == 1, "sink must be built once for the whole loop"
    assert closes["n"] == 1, "sink must be closed when the loop exits"


def test_monitor_cycle_advances_offset_even_when_a_send_fails(tmp_path, benign_events):
    # If one alert's send raises, the offset must still advance past the
    # scored batch and the remaining alerts must still ship — no duplicates.
    config = make_app_config(tmp_path, platform="jsonl", every_cycles=999)

    seed_events(config.daemon.events_file, 60)
    from behavior_anomaly.models.persistence import save_model
    from behavior_anomaly.pipeline import build_features, train_model

    model = train_model(
        JsonlStore(config.daemon.events_file).read(),
        config.detection,
        features=build_features(config),
    )
    save_model(model, config.daemon.model_file)

    # A stub model that always scores above threshold, so every window alerts
    # and the partial-send path is actually exercised (the real IsolationForest
    # scores its own training data as normal and would produce zero alerts).
    from collections.abc import Sequence

    from behavior_anomaly.models.base import AnomalyModel

    class AlwaysAnomalous(AnomalyModel):
        name = "always"

        def fit(self, rows: Sequence[dict[str, float]]) -> None:
            pass

        def score(self, row: dict[str, float]) -> float:
            return 0.9

    send_calls = {"n": 0}

    class FlakySink(SiemSink):
        def __init__(self) -> None:
            self.sent: list = []

        def send(self, alert) -> None:  # noqa: ANN001
            send_calls["n"] += 1
            if send_calls["n"] == 1:
                raise RuntimeError("transient SIEM hiccup")
            self.sent.append(alert)

    class FakeCollector:
        def collect(self):
            return iter([])

    with patch("behavior_anomaly.daemon.build_collector", return_value=FakeCollector()), patch(
        "behavior_anomaly.daemon.load_model", return_value=AlwaysAnomalous()
    ):
        state = DaemonState(cycle=5)
        sink = FlakySink()
        result = run_cycle(config, state, sink=sink)

    # 60 events in two windows; both alert with the stub model.
    assert result.scored == 60
    assert result.alerts == 1  # only the second alert actually shipped
    # The offset advanced past the whole scored batch regardless of the failure.
    assert state.byte_offset > 0
    # The first send raised; the second still shipped.
    assert send_calls["n"] == 2
    assert len(sink.sent) == 1


def test_run_cycle_jsonl_collector_unpatched(tmp_path, benign_events):
    # The daemon's jsonl collector path used to be impossible to exercise
    # without patching build_collector, because there was no source field.
    # Now DaemonCollectConfig.source wires the path through.
    source = tmp_path / "agent.jsonl"
    JsonlStore(source).write(benign_events)
    config = make_app_config(tmp_path, platform="jsonl", every_cycles=1)
    config = config.model_copy(
        update={
            "daemon": config.daemon.model_copy(
                update={"collect": config.daemon.collect.model_copy(update={"source": str(source)})}
            )
        }
    )
    result = run_cycle(config, DaemonState(), sink=FakeSink())
    assert result.collected == 60
    assert Path(config.daemon.events_file).exists()


def test_run_cycle_retrain_cadence_lines_up_with_reported_cycle(tmp_path, benign_events):
    # should_retrain is decided on the cycle we are about to run, before the
    # increment, so the scheduled cadence matches the cycle number reported
    # in CycleResult. every_cycles=1 means every cycle trains.
    config = make_app_config(tmp_path, platform="jsonl", every_cycles=1)

    class FakeCollector:
        def __init__(self):
            self._events = list(benign_events)

        def collect(self):
            return iter(self._events)

    with patch("behavior_anomaly.daemon.build_collector", return_value=FakeCollector()):
        state = DaemonState(cycle=0)
        first = run_cycle(config, state, sink=FakeSink())
        assert first.cycle == 0
        assert first.trained is True  # cycle 0 % 1 == 0
        # Second cycle (no new events, model exists): scheduled retrain still fires.
        second = run_cycle(config, state, sink=FakeSink())
        assert second.cycle == 1
        assert second.trained is True  # 1 % 1 == 0


def test_run_loop_exits_on_signal_mid_sleep(tmp_path):
    """Setting stop_event during sleep should wake the loop promptly."""
    config = make_app_config(
        tmp_path,
        collect_enabled=False,
        monitor_enabled=False,
        train_enabled=False,
    )
    stop_event = threading.Event()

    def fake_sleep(seconds):
        # Simulate a signal arriving during sleep.
        stop_event.set()

    run_loop(config, stop_event=stop_event, sleep_func=fake_sleep)
    # If we got here, the loop exited. The test passing is the assertion.


# --------------------------------------------------------- config defaults


def test_daemon_config_defaults_are_sensible():
    """Out of the box, the daemon should be ready to run, not ready to sulk."""
    config = DaemonConfig()
    assert config.enabled is True
    assert config.collect.enabled is True
    assert config.train.enabled is True
    assert config.monitor.enabled is True
    assert config.interval_seconds == 300
    assert config.train.every_cycles == 12


def test_app_config_loads_daemon_section(tmp_path):
    """The [daemon] section in a TOML file should populate DaemonConfig."""
    config_file = tmp_path / "config.toml"
    config_file.write_text(
        """
[daemon]
enabled = true
interval_seconds = 60
events_file = "/tmp/bad/events.jsonl"
model_file = "/tmp/bad/model.joblib"

[daemon.collect]
enabled = true
platform = "linux"
since = "1 hour ago"

[daemon.train]
enabled = false
every_cycles = 6

[daemon.monitor]
enabled = true
""",
        encoding="utf-8",
    )
    config = AppConfig.load(config_file)
    assert config.daemon.enabled is True
    assert config.daemon.interval_seconds == 60
    assert config.daemon.collect.platform == "linux"
    assert config.daemon.collect.since == "1 hour ago"
    assert config.daemon.train.enabled is False
    assert config.daemon.train.every_cycles == 6
    assert config.daemon.monitor.enabled is True
