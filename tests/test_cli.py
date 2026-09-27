"""End to end tests for the CLI. If the CLI lies, everything above it lies too."""

import json

from typer.testing import CliRunner

from behavior_anomaly.cli import app
from behavior_anomaly.schema import BehaviorEvent
from behavior_anomaly.storage.jsonl import JsonlStore

runner = CliRunner()


def write_events(path: str, events: list[BehaviorEvent]) -> None:
    """Dump a batch of events to JSONL so the CLI has something to chew on."""
    JsonlStore(path).write(events)


def test_cli_collect_from_jsonl(tmp_path, benign_events):
    source = tmp_path / "events.jsonl"
    write_events(source, benign_events)
    output = tmp_path / "collected.jsonl"

    result = runner.invoke(
        app,
        ["collect", "--platform", "jsonl", "--source", str(source), "--output", str(output)],
    )
    assert result.exit_code == 0
    assert "Collected 60 event(s)" in result.output
    assert len(JsonlStore(output).read()) == 60


def test_cli_collect_rejects_unknown_platform(tmp_path):
    result = runner.invoke(
        app,
        ["collect", "--platform", "carrier-pigeon", "--output", str(tmp_path / "x.jsonl")],
    )
    assert result.exit_code != 0


def test_cli_train_produces_a_model_file(tmp_path, benign_events):
    events = tmp_path / "events.jsonl"
    write_events(events, benign_events)
    model = tmp_path / "model.joblib"

    result = runner.invoke(app, ["train", "--input", str(events), "--output", str(model)])
    assert result.exit_code == 0
    assert model.exists()
    assert "Trained isolation_forest" in result.output


def test_cli_train_needs_events(tmp_path):
    empty = tmp_path / "empty.jsonl"
    empty.write_text("", encoding="utf-8")
    model = tmp_path / "model.joblib"

    result = runner.invoke(app, ["train", "--input", str(empty), "--output", str(model)])
    # Training on nothing is still nothing. Fail loudly, not silently.
    assert result.exit_code != 0


def test_cli_score_runs_against_trained_model(tmp_path, benign_events):
    events = tmp_path / "events.jsonl"
    write_events(events, benign_events)
    model = tmp_path / "model.joblib"
    runner.invoke(app, ["train", "--input", str(events), "--output", str(model)])

    result = runner.invoke(app, ["score", "--input", str(events), "--model", str(model)])
    assert result.exit_code == 0
    assert "alert(s)" in result.output


def test_cli_score_writes_alerts_file(tmp_path, benign_events):
    events = tmp_path / "events.jsonl"
    write_events(events, benign_events)
    model = tmp_path / "model.joblib"
    runner.invoke(app, ["train", "--input", str(events), "--output", str(model)])

    alerts = tmp_path / "alerts.jsonl"
    result = runner.invoke(
        app,
        ["score", "--input", str(events), "--model", str(model), "--output", str(alerts)],
    )
    assert result.exit_code == 0
    written = alerts.read_text(encoding="utf-8").strip()
    for line in written.splitlines():
        # Whatever lands in the file must be a valid alert, not confetti.
        assert json.loads(line)["rule"] == "user_behavior_anomaly"


def test_cli_monitor_with_syslog_sink(tmp_path, benign_events):
    events = tmp_path / "events.jsonl"
    write_events(events, benign_events)
    model = tmp_path / "model.joblib"
    runner.invoke(app, ["train", "--input", str(events), "--output", str(model)])

    result = runner.invoke(
        app,
        [
            "monitor",
            "--input",
            str(events),
            "--model",
            str(model),
            "--siem",
            "syslog",
        ],
    )
    assert result.exit_code == 0
    assert "alert(s)" in result.output


def test_cli_monitor_rejects_webhook_without_endpoint(tmp_path, benign_events):
    events = tmp_path / "events.jsonl"
    write_events(events, benign_events)
    model = tmp_path / "model.joblib"
    runner.invoke(app, ["train", "--input", str(events), "--output", str(model)])

    result = runner.invoke(
        app,
        ["monitor", "--input", str(events), "--model", str(model), "--siem", "webhook"],
    )
    assert result.exit_code != 0


def test_cli_train_honors_config_file(tmp_path, benign_events):
    events = tmp_path / "events.jsonl"
    write_events(events, benign_events)
    config = tmp_path / "config.toml"
    config.write_text("[detection]\nwindow_seconds = 600\n", encoding="utf-8")
    model = tmp_path / "model.joblib"

    result = runner.invoke(
        app,
        ["train", "--input", str(events), "--output", str(model), "--config", str(config)],
    )
    assert result.exit_code == 0


def test_cli_flags_beat_config_file(tmp_path, benign_events):
    # Precedence: defaults < config file < flags. If both speak, the human
    # typing the flag wins. That is the only rule nobody argues with.
    events = tmp_path / "events.jsonl"
    write_events(events, benign_events)
    config = tmp_path / "config.toml"
    config.write_text("[detection]\nmin_events = 3\n", encoding="utf-8")
    model = tmp_path / "model.joblib"

    result = runner.invoke(
        app,
        [
            "train",
            "--input",
            str(events),
            "--output",
            str(model),
            "--config",
            str(config),
            "--min-events",
            "5",
        ],
    )
    assert result.exit_code == 0


def test_cli_missing_config_file_is_an_error(tmp_path, benign_events):
    # The admin pointed at a file. Pretending we honored it would be the
    # kind of lie that surfaces in an incident report.
    events = tmp_path / "events.jsonl"
    write_events(events, benign_events)

    result = runner.invoke(
        app,
        [
            "train",
            "--input",
            str(events),
            "--output",
            str(tmp_path / "model.joblib"),
            "--config",
            str(tmp_path / "ghost_town.toml"),
        ],
    )
    assert result.exit_code != 0


def test_cli_example_config_file_works(tmp_path, benign_events):
    # config.example.toml is the first thing a customer copies. If it
    # explodes, so does the first impression.
    from tests.conftest import REPO_ROOT

    events = tmp_path / "events.jsonl"
    write_events(events, benign_events)
    model = tmp_path / "model.joblib"

    result = runner.invoke(
        app,
        [
            "train",
            "--input",
            str(events),
            "--output",
            str(model),
            "--config",
            str(REPO_ROOT / "config.example.toml"),
        ],
    )
    assert result.exit_code == 0


def test_cli_check_config_prints_effective_settings(tmp_path):
    # The command deployment tooling calls before the fleet finds out.
    # If it prints garbage, the ansible handler trusts garbage.
    config = tmp_path / "config.toml"
    config.write_text(
        '[detection]\nwindow_seconds = 900\n[siem]\nkind = "webhook"\nendpoint = "https://x"\n',
        encoding="utf-8",
    )

    result = runner.invoke(app, ["check-config", "--config", str(config)])
    assert result.exit_code == 0
    assert "config OK" in result.output
    assert "window=900s" in result.output
    assert "kind=webhook" in result.output
    assert "enabled=True" in result.output


def test_cli_check_config_rejects_invalid_toml(tmp_path):
    # min_events = 0 means "train on nothing", and we do not train on nothing.
    config = tmp_path / "config.toml"
    config.write_text("[detection]\nmin_events = 0\n", encoding="utf-8")

    result = runner.invoke(app, ["check-config", "--config", str(config)])
    assert result.exit_code != 0


def test_cli_check_config_rejects_missing_file(tmp_path):
    result = runner.invoke(app, ["check-config", "--config", str(tmp_path / "nope.toml")])
    assert result.exit_code != 0


def test_cli_check_config_accepts_shipped_example():
    # The file we tell every admin to copy had better validate, or the
    # very first command in the docs is a lie.
    from tests.conftest import REPO_ROOT

    result = runner.invoke(app, ["check-config", "--config", str(REPO_ROOT / "config.example.toml")])
    assert result.exit_code == 0


# ---------------------------------------------------------------- collect --since


def test_cli_collect_since_alias_reaches_linux_collector(tmp_path, monkeypatch):
    # The docs promised `bad collect --platform linux --since "1 hour ago"`.
    # For a long time the option was named --source only, so every admin who
    # copied the docs got told there is no such option. This test makes sure
    # the promise is kept: --since is accepted and its value lands in the
    # linux collector as the `since` argument, not lost in a click error.
    captured: dict = {}

    def fake_build_collector(kind: str, source: str | None = None):
        captured["kind"] = kind
        captured["source"] = source

        class _NoOpCollector:
            def collect(self):
                return iter([])

        return _NoOpCollector()

    monkeypatch.setattr("behavior_anomaly.cli.build_collector", fake_build_collector)

    output = tmp_path / "collected.jsonl"
    result = runner.invoke(
        app,
        ["collect", "--platform", "linux", "--output", str(output), "--since", "1 hour ago"],
    )
    assert result.exit_code == 0
    assert captured["kind"] == "linux"
    assert captured["source"] == "1 hour ago"


def test_cli_collect_source_still_works_for_jsonl(tmp_path, benign_events):
    # Backwards compatibility: --source must keep working for the jsonl
    # collector. Adding --since as an alias must not break the original name.
    source = tmp_path / "events.jsonl"
    write_events(source, benign_events)
    output = tmp_path / "collected.jsonl"

    result = runner.invoke(
        app,
        ["collect", "--platform", "jsonl", "--source", str(source), "--output", str(output)],
    )
    assert result.exit_code == 0
    assert "Collected 60 event(s)" in result.output


def test_cli_collect_help_lists_both_source_and_since():
    # The help output is the first place an admin looks when an option
    # "does not exist". Both names should be visible there.
    result = runner.invoke(app, ["collect", "--help"])
    assert result.exit_code == 0
    assert "--source" in result.output
    assert "--since" in result.output
