"""Tests for behavioral feature extraction, input dynamics included."""

from tests.conftest import make_event

from behavior_anomaly.features.behavioral import (
    BEHAVIORAL_FEATURE_NAMES,
    INPUT_FEATURE_NAMES,
    BehavioralFeatures,
    feature_names,
)
from behavior_anomaly.schema import EventType


def test_extract_counts_by_type():
    events = [
        make_event(event_type=EventType.PROCESS, action="exec"),
        make_event(event_type=EventType.PROCESS, action="fork"),
        make_event(event_type=EventType.AUTH, action="login", success=False),
        make_event(event_type=EventType.NETWORK, action="connect", destination="10.0.0.1"),
    ]
    row = BehavioralFeatures().extract(events)

    assert row["event_count"] == 4.0
    assert row["process_events"] == 2.0
    assert row["auth_events"] == 1.0
    assert row["network_events"] == 1.0
    assert row["failed_events"] == 1.0
    assert row["unique_processes"] == 1.0
    assert row["unique_destinations"] == 1.0
    assert row["unique_actions"] == 4.0


def test_extract_privileged_and_parent_process():
    events = [
        make_event(privileged=True, process_name="sudo"),
        make_event(process_name="sudo"),
    ]
    row = BehavioralFeatures().extract(events)
    assert row["privileged_events"] == 1.0
    assert row["unique_processes"] == 1.0


def test_empty_window_returns_zeroes_not_exception():
    row = BehavioralFeatures().extract([])
    # Nothing happened is a fact, not a crash.
    assert set(row) == set(feature_names())
    assert all(value == 0.0 for value in row.values())


def test_feature_keys_stay_stable():
    # Models train on these keys. Rename one and every saved model dies.
    row = BehavioralFeatures().extract([make_event()])
    assert set(row) == set(feature_names())


def test_input_dynamics_off_drops_input_features_entirely():
    # Off means the keys are absent, not zero. A vector with silent zeros is
    # how a disabled feature sneaks back into scoring.
    row = BehavioralFeatures(include_input_dynamics=False).extract([make_event()])
    assert set(row) == set(BEHAVIORAL_FEATURE_NAMES)
    assert not set(row) & set(INPUT_FEATURE_NAMES)


def test_input_typing_features_from_aggregate_metadata():
    # One typing aggregate: 120 keystrokes, mean interval 100ms, stddev 40ms.
    events = [
        make_event(
            seconds_offset=0,
            event_type=EventType.INPUT,
            action="typing",
            process_name=None,
            metadata={"keystrokes": 120, "mean_interval_ms": 100, "stddev_interval_ms": 40},
        ),
        make_event(
            seconds_offset=60,
            event_type=EventType.INPUT,
            action="typing",
            process_name=None,
            metadata={"keystrokes": 60, "mean_interval_ms": 200, "stddev_interval_ms": 80},
        ),
    ]
    row = BehavioralFeatures().extract(events)

    assert row["input_events"] == 2.0
    assert row["keystrokes"] == 180.0
    # 180 keys in 60 seconds of window span.
    assert row["typing_velocity_kpm"] == 180.0
    # Keystroke-weighted mean: (120*100 + 60*200) / 180.
    assert row["mean_key_interval_ms"] == (120 * 100 + 60 * 200) / 180
    assert row["key_interval_stddev_ms"] == (120 * 40 + 60 * 80) / 180


def test_input_mouse_features_from_aggregate_metadata():
    events = [
        make_event(
            seconds_offset=0,
            event_type=EventType.INPUT,
            action="mouse",
            process_name=None,
            metadata={"distance_px": 1000, "duration_ms": 2000, "direction_changes": 8},
        ),
        make_event(
            seconds_offset=30,
            event_type=EventType.INPUT,
            action="mouse",
            process_name=None,
            metadata={"distance_px": 500, "duration_ms": 1000, "direction_changes": 4},
        ),
    ]
    row = BehavioralFeatures().extract(events)

    assert row["input_events"] == 2.0
    assert row["mouse_distance_px"] == 1500.0
    # 1500px over 3000ms total.
    assert row["mouse_speed_px_s"] == 500.0
    assert row["mouse_direction_changes"] == 12.0


def test_input_features_never_read_content():
    # An agent that stuffed text into metadata gets ignored, not stored,
    # not logged, not scored. Privacy by construction has a test too.
    events = [
        make_event(
            event_type=EventType.INPUT,
            action="typing",
            process_name=None,
            metadata={
                "keystrokes": "42",
                "mean_interval_ms": 110,
                "sampled_text": "hunter2",
                "keys_pressed": "h,u,n,t,e,r,2",
            },
        )
    ]
    row = BehavioralFeatures().extract(events)

    assert row["keystrokes"] == 42.0  # numeric strings are tolerated
    assert row["mean_key_interval_ms"] == 110.0
    # Only whitelisted timing keys make it out. "hunter2" died here.
    assert all("text" not in name and "keys_pressed" not in name for name in row)


def test_sloppy_metadata_coerces_to_zero():
    events = [
        make_event(
            event_type=EventType.INPUT,
            action="mouse",
            process_name=None,
            metadata={"distance_px": "a lot", "duration_ms": None},
        )
    ]
    row = BehavioralFeatures().extract(events)
    # A mouse that moved "a lot" for "a while" moved zero pixels, quietly.
    assert row["mouse_distance_px"] == 0.0
    assert row["mouse_speed_px_s"] == 0.0


# --------------------------------------------------- feature hardening


def test_nan_and_inf_metadata_coerce_to_zero():
    # float("nan")/float("inf") succeed at float() but would poison the
    # feature vector and crash sklearn. _num must reject non-finite values.
    import math

    events = [
        make_event(
            event_type=EventType.INPUT,
            action="typing",
            process_name=None,
            metadata={"keystrokes": "nan", "mean_interval_ms": "inf"},
        )
    ]
    row = BehavioralFeatures().extract(events)
    assert row["keystrokes"] == 0.0
    assert math.isfinite(row["mean_key_interval_ms"])
    assert all(math.isfinite(v) for v in row.values())


def test_extract_handles_unsorted_input():
    # The public extract API has no documented ordering precondition, but the
    # span math used to assume events[0] was earliest. Reverse-order input
    # must still produce a correct, finite velocity.
    events = [
        make_event(
            seconds_offset=60,
            event_type=EventType.INPUT,
            action="typing",
            process_name=None,
            metadata={"keystrokes": 120, "mean_interval_ms": 100},
        ),
        make_event(
            seconds_offset=0,
            event_type=EventType.INPUT,
            action="typing",
            process_name=None,
            metadata={"keystrokes": 60, "mean_interval_ms": 200},
        ),
    ]
    row = BehavioralFeatures().extract(events)
    assert row["keystrokes"] == 180.0
    # Span is 60s; 180 keys / 60s = 180 kpm.
    assert row["typing_velocity_kpm"] == 180.0


def test_typing_velocity_uses_active_duration_when_present():
    # When typing events carry duration_ms, velocity is normalized by active
    # typing time (matching mouse speed), not the full window span.
    events = [
        make_event(
            seconds_offset=0,
            event_type=EventType.INPUT,
            action="typing",
            process_name=None,
            metadata={"keystrokes": 120, "duration_ms": 2000},  # 2s of typing
        ),
        # Non-typing padding so the window span is much larger than 2s.
        make_event(seconds_offset=10, event_type=EventType.PROCESS, action="exec"),
        make_event(seconds_offset=20, event_type=EventType.PROCESS, action="exec"),
    ]
    row = BehavioralFeatures().extract(events)
    # 120 keys in 2 seconds of active typing = 3600 kpm, not the ~360 kpm
    # the old window-span normalization would have reported.
    assert row["typing_velocity_kpm"] == 3600.0


def test_partial_metadata_does_not_drag_mean_toward_zero():
    # One typing event with keystrokes but no mean_interval_ms must not
    # contribute its keystrokes to the denominator of the weighted mean.
    events = [
        make_event(
            seconds_offset=0,
            event_type=EventType.INPUT,
            action="typing",
            process_name=None,
            metadata={"keystrokes": 120, "mean_interval_ms": 100},
        ),
        make_event(
            seconds_offset=60,
            event_type=EventType.INPUT,
            action="typing",
            process_name=None,
            metadata={"keystrokes": 1000},  # no mean_interval_ms
        ),
    ]
    row = BehavioralFeatures().extract(events)
    # Only the first event carries mean_interval_ms, so the mean is exactly
    # its value — not dragged down by the 1000 keystrokes that have none.
    assert row["mean_key_interval_ms"] == 100.0


def test_input_features_never_leak_content_values():
    # The old privacy test asserted feature *names* do not contain "text",
    # which is trivially true. This one asserts the secret value never
    # appears in any output value either.
    events = [
        make_event(
            event_type=EventType.INPUT,
            action="typing",
            process_name=None,
            metadata={
                "keystrokes": "42",
                "mean_interval_ms": 110,
                "sampled_text": "hunter2",
                "keys_pressed": "h,u,n,t,e,r,2",
            },
        )
    ]
    row = BehavioralFeatures().extract(events)
    for value in row.values():
        assert "hunter2" not in str(value)
    # And the whitelisted keys are exactly the feature set.
    assert "sampled_text" not in row
    assert "keys_pressed" not in row
