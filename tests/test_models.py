"""Tests for models: training, scoring, honesty about failure."""

import pytest
from tests.conftest import make_event

from behavior_anomaly.detection.windowing import build_windows
from behavior_anomaly.features.behavioral import BehavioralFeatures, feature_names
from behavior_anomaly.models.isolation_forest import IsolationForestModel
from behavior_anomaly.models.persistence import load_model, save_model
from behavior_anomaly.models.registry import build_model
from behavior_anomaly.schema import BehaviorEvent, EventType


def _rows(events: list[BehaviorEvent]) -> list[dict[str, float]]:
    features = BehavioralFeatures()
    return [features.extract(window) for window in build_windows(events, 300)]


def test_registry_builds_and_rejects():
    assert build_model("isolation_forest").name == "isolation_forest"
    with pytest.raises(ValueError, match="Unknown model"):
        build_model("vibes")


def test_fit_rejects_empty_dataset():
    with pytest.raises(ValueError, match="empty dataset"):
        IsolationForestModel().fit([])


def test_score_before_training_is_rejected():
    with pytest.raises(ValueError, match="untrained"):
        IsolationForestModel().score({name: 0.0 for name in feature_names()})


def test_score_rejects_missing_columns(benign_events):
    model = IsolationForestModel()
    model.fit(_rows(benign_events))
    with pytest.raises(KeyError, match="missing columns"):
        model.score({"event_count": 1.0})


def test_anomalous_row_scores_higher_than_normal():
    # Two windows are not a baseline, they are a coin flip. Give the forest a
    # fleet week: ten users, two windows each, each user differently boring.
    # Identical training rows give an Isolation Forest nothing to separate,
    # and a model that has seen one thing thinks everything is that thing.
    events = []
    for user_index in range(10):
        step = 10 + (user_index % 3) * 5
        for offset in range(0, 600, step):
            events.append(
                make_event(
                    seconds_offset=offset,
                    user_id=f"user-{user_index}",
                    process_name=f"proc-{user_index % 4}",
                    event_type=EventType.PROCESS if offset % 20 < 10 else EventType.FILE,
                    success=False if user_index % 4 == 3 and offset % 5 == 0 else None,
                )
            )

    model = IsolationForestModel()
    model.fit(_rows(events))

    features = BehavioralFeatures()
    normal_row = features.extract(events[:30])
    # The same window, except this user suddenly became very busy and
    # everything they touched failed. Legitimate Friday? Sure. But the
    # model gets a vote.
    weird_row = dict(normal_row)
    weird_row["event_count"] = 50.0
    weird_row["failed_events"] = 40.0
    weird_row["unique_processes"] = 30.0

    assert model.score(weird_row) > model.score(normal_row)


def test_save_and_load_roundtrip(tmp_path, benign_events):
    model = IsolationForestModel()
    model.fit(_rows(benign_events))
    path = tmp_path / "model.joblib"

    save_model(model, path)
    revived = load_model(path)

    row = BehavioralFeatures().extract(benign_events[:30])
    assert revived.score(row) == model.score(row)
    assert revived.name == model.name


def test_save_creates_parent_directories(tmp_path, benign_events):
    model = IsolationForestModel()
    model.fit(_rows(benign_events))
    save_model(model, tmp_path / "deep" / "nested" / "model.joblib")
    assert (tmp_path / "deep" / "nested" / "model.joblib").exists()
