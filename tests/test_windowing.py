"""Tests for time windowing. Buckets, not vibes."""

import pytest
from tests.conftest import T0, make_event

from behavior_anomaly.detection.windowing import build_windows
from behavior_anomaly.schema import Platform


def test_events_bucket_by_user():
    events = [
        make_event(0, user_id="alice"),
        make_event(1, user_id="bob"),
        make_event(2, user_id="alice"),
    ]
    windows = build_windows(events, 300)
    # Alice and Bob get separate windows even in the same bucket.
    # Alice's Tuesday must not influence Bob's risk score.
    assert len(windows) == 2
    users = {window[0].user_id for window in windows}
    assert users == {"alice", "bob"}


def test_events_bucket_by_host():
    events = [
        make_event(0, host_id="host-1"),
        make_event(1, host_id="host-2"),
    ]
    windows = build_windows(events, 300)
    assert len(windows) == 2


def test_epoch_aligned_buckets():
    # T0 sits on a 300 second boundary, so offsets 0 and 299 share a bucket
    # and offset 300 lands in the next one. Tidy on purpose.
    events = [make_event(0), make_event(299), make_event(300)]
    windows = build_windows(events, 300)
    assert len(windows) == 2
    assert [len(window) for window in windows] == [2, 1]


def test_windows_are_sorted_chronologically():
    events = [make_event(10), make_event(0), make_event(5)]
    windows = build_windows(events, 300)
    timestamps = [event.timestamp for event in windows[0]]
    assert timestamps == sorted(timestamps)


def test_invalid_window_size_rejected():
    with pytest.raises(ValueError):
        build_windows([make_event(0)], 0)


def test_naive_timestamps_tolerated():
    event = make_event(0)
    naive = event.model_copy(update={"timestamp": T0.replace(tzinfo=None)})
    windows = build_windows([naive], 300)
    assert len(windows) == 1
    assert windows[0][0].platform == Platform.LINUX
