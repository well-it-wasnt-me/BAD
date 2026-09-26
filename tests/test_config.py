"""Tests for the admin config: defaults, TOML loading, precedence, refusal."""

from pathlib import Path

import pytest

from behavior_anomaly.config import AppConfig, InputDynamicsConfig


def test_defaults_when_no_config_given():
    config = AppConfig()
    assert config.detection.window_seconds == 300
    assert config.detection.min_events == 5
    assert config.siem.kind == "syslog"  # webhook needs an endpoint it does not have
    assert config.input_dynamics.enabled is True


def test_full_toml_round_trip(tmp_path: Path):
    path = tmp_path / "config.toml"
    path.write_text(
        """
        [detection]
        window_seconds = 900
        anomaly_threshold = 0.7
        contamination = 0.02
        min_events = 3

        [siem]
        kind = "webhook"
        endpoint = "https://siem.example.com/ingest"
        api_key = "hunter2"  # yes, that is the joke

        [input_dynamics]
        enabled = false
        sampler_interval_seconds = 15
        """,
        encoding="utf-8",
    )
    config = AppConfig.load(path)

    assert config.detection.window_seconds == 900
    assert config.detection.anomaly_threshold == 0.7
    assert config.detection.contamination == 0.02
    assert config.detection.min_events == 3
    assert config.siem.kind == "webhook"
    assert config.siem.endpoint == "https://siem.example.com/ingest"
    assert config.input_dynamics.enabled is False
    assert config.input_dynamics.sampler_interval_seconds == 15


def test_partial_toml_falls_back_to_defaults(tmp_path: Path):
    # One line is a valid config. The admin's file grows as their nerve does.
    path = tmp_path / "config.toml"
    path.write_text("[input_dynamics]\nenabled = false\n", encoding="utf-8")
    config = AppConfig.load(path)

    assert config.input_dynamics.enabled is False
    assert config.detection.window_seconds == 300
    assert config.siem.kind == "syslog"


def test_empty_toml_is_all_defaults(tmp_path: Path):
    path = tmp_path / "config.toml"
    path.write_text("# a config file containing only opinions\n", encoding="utf-8")
    assert AppConfig.load(path) == AppConfig()


def test_invalid_values_are_rejected(tmp_path: Path):
    # min_events = 0 means "train on nothing", and we do not train on nothing.
    path = tmp_path / "config.toml"
    path.write_text("[detection]\nmin_events = 0\n", encoding="utf-8")
    with pytest.raises(ValueError):
        AppConfig.load(path)


def test_unknown_sections_are_ignored(tmp_path: Path):
    # Rejecting a config for containing the future makes admins fear upgrades.
    path = tmp_path / "config.toml"
    path.write_text("[teleportation]\nenabled = true\n", encoding="utf-8")
    assert AppConfig.load(path).detection.window_seconds == 300


def test_example_config_file_is_valid():
    # The file we ship is the file the admin copies. If it does not validate,
    # first contact with the tool is an error message, and first impressions
    # do not get a second chance.
    import tomllib

    from tests.conftest import REPO_ROOT

    path = REPO_ROOT / "config.example.toml"
    with path.open("rb") as handle:
        data = tomllib.load(handle)
    assert AppConfig.model_validate(data) == AppConfig()


def test_input_dynamics_config_defaults():
    config = InputDynamicsConfig()
    assert config.enabled is True
    assert config.sampler_interval_seconds == 30
