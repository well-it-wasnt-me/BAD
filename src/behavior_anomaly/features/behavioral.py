"""Behavioral feature extraction.

Counts, cardinalities, and input dynamics over a window of events. The first
fifteen features answer "how much happened and did it fail". The input
features answer "was the human at the keyboard the usual human", which is a
question process telemetry cannot even hear, let alone answer.
"""

import math
from collections import Counter
from collections.abc import Sequence
from datetime import UTC, datetime

from behavior_anomaly.features.base import FeatureExtractor
from behavior_anomaly.schema import BehaviorEvent, EventType

BEHAVIORAL_FEATURE_NAMES: tuple[str, ...] = (
    "event_count",
    "process_events",
    "auth_events",
    "session_events",
    "file_events",
    "network_events",
    "shell_events",
    "privilege_events",
    "application_events",
    "failed_events",
    "privileged_events",
    "unique_processes",
    "unique_destinations",
    "unique_applications",
    "unique_actions",
)

# Input dynamics features. Derived exclusively from timing and motion:
# how long between keys, how far the mouse, how often it changed course.
# Never what was typed. What we never read, we never log.
INPUT_FEATURE_NAMES: tuple[str, ...] = (
    "input_events",
    "keystrokes",
    "typing_velocity_kpm",
    "mean_key_interval_ms",
    "key_interval_stddev_ms",
    "mouse_distance_px",
    "mouse_speed_px_s",
    "mouse_direction_changes",
)


def feature_names(include_input_dynamics: bool = True) -> tuple[str, ...]:
    """Full feature key set for the given configuration.

    Models train on these keys, so the set must be stable per configuration.
    Rename one and every model trained with the previous name dies quietly
    in a corner.
    """
    if include_input_dynamics:
        return BEHAVIORAL_FEATURE_NAMES + INPUT_FEATURE_NAMES
    return BEHAVIORAL_FEATURE_NAMES


class BehavioralFeatures(FeatureExtractor):
    """Baseline feature set. Deterministic, cheap, and explainable enough for
    an analyst to argue with, which is the whole point."""

    def __init__(self, include_input_dynamics: bool = True) -> None:
        # The admin config flips this switch. Off means input features are not
        # part of the vector at all, not that they silently become zeros.
        self.include_input_dynamics = include_input_dynamics

    def names(self) -> tuple[str, ...]:
        return feature_names(self.include_input_dynamics)

    def extract(self, events: Sequence[BehaviorEvent]) -> dict[str, float]:
        """Flatten one event window into a single feature row.

        Empty windows get a row of zeros instead of an exception, because the
        caller should decide what "nothing happened" means, not us.
        """
        if not events:
            return {name: 0.0 for name in self.names()}

        row = _behavioral_features(events)
        if self.include_input_dynamics:
            row.update(_input_features(events))
        return row


def _behavioral_features(events: Sequence[BehaviorEvent]) -> dict[str, float]:
    """Counts and cardinalities: how much happened, what kinds, how much
    failed, how much was privileged, how many things the user touched."""
    types = Counter(event.event_type.value for event in events)
    actions = Counter(event.action for event in events)
    processes = {event.process_name for event in events if event.process_name}
    destinations = {event.destination for event in events if event.destination}
    applications = {event.application for event in events if event.application}

    return {
        "event_count": float(len(events)),
        "process_events": float(types["process"]),
        "auth_events": float(types["auth"]),
        "session_events": float(types["session"]),
        "file_events": float(types["file"]),
        "network_events": float(types["network"]),
        "shell_events": float(types["shell"]),
        "privilege_events": float(types["privilege"]),
        "application_events": float(types["application"]),
        "failed_events": float(sum(event.success is False for event in events)),
        "privileged_events": float(sum(event.privileged is True for event in events)),
        "unique_processes": float(len(processes)),
        "unique_destinations": float(len(destinations)),
        "unique_applications": float(len(applications)),
        "unique_actions": float(len(actions)),
    }


def _input_features(events: Sequence[BehaviorEvent]) -> dict[str, float]:
    """Aggregate input dynamics over a window.

    Input events arrive as aggregates, not raw events: an input sampler (an
    agent, a future BAD sampler, whatever feeds the jsonl front door) reports
    "typing: 42 keys, mean interval 118ms" and "mouse: 1234px, 800ms,
    12 direction changes". We read ONLY those whitelisted timing and motion
    keys. Keystroke content is not a field we read, and privacy by
    construction beats privacy by promise.

    Events are sorted by timestamp here so the span math does not depend on
    the caller's ordering, and timestamps are normalized to UTC before
    subtraction so a mix of tz-aware and tz-naive input events cannot crash
    the feature extractor.
    """
    ordered = sorted(events, key=lambda event: _epoch_seconds(event.timestamp))
    typing = [event for event in ordered if event.event_type == EventType.INPUT and event.action == "typing"]
    mouse = [event for event in ordered if event.event_type == EventType.INPUT and event.action == "mouse"]
    input_total = sum(event.event_type == EventType.INPUT for event in ordered)

    keystrokes = sum(_num(event.metadata.get("keystrokes")) for event in typing)

    # Normalize typing velocity by active typing duration (the sum of per-
    # typing-event duration_ms), the same basis mouse speed uses, so the two
    # "rate" features are comparable instead of one being window-shape-
    # dependent. Fall back to the window span only when no durations exist,
    # which preserves the original semantics for agents that omit duration_ms.
    typing_duration_ms = sum(_num(event.metadata.get("duration_ms")) for event in typing)
    if typing_duration_ms > 0:
        velocity = keystrokes * 60.0 / (typing_duration_ms / 1000.0)
    else:
        span_seconds = (_epoch_seconds(ordered[-1].timestamp) - _epoch_seconds(ordered[0].timestamp))
        velocity = keystrokes * 60.0 / span_seconds if span_seconds > 0 else 0.0

    # Weighted means pair keystrokes with their per-aggregate interval stats.
    # The denominator only counts keystrokes from events that actually carry
    # the paired field, so an event reporting keystrokes without a
    # mean_interval_ms does not drag the reported mean toward zero.
    if keystrokes:
        mean_interval = _weighted_mean(typing, "mean_interval_ms", "keystrokes")
        stddev_interval = _weighted_mean(typing, "stddev_interval_ms", "keystrokes")
    else:
        mean_interval = 0.0
        stddev_interval = 0.0

    distance = sum(_num(event.metadata.get("distance_px")) for event in mouse)
    duration_ms = sum(_num(event.metadata.get("duration_ms")) for event in mouse)
    speed = distance / (duration_ms / 1000.0) if duration_ms > 0 else 0.0
    direction_changes = sum(_num(event.metadata.get("direction_changes")) for event in mouse)

    return {
        "input_events": float(input_total),
        "keystrokes": keystrokes,
        "typing_velocity_kpm": velocity,
        "mean_key_interval_ms": mean_interval,
        "key_interval_stddev_ms": stddev_interval,
        "mouse_distance_px": distance,
        "mouse_speed_px_s": speed,
        "mouse_direction_changes": direction_changes,
    }


def _weighted_mean(typing: Sequence[BehaviorEvent], value_field: str, weight_field: str) -> float:
    """Keystroke-weighted mean of a per-aggregate field, counting only events
    that carry both the value and the weight. Returns 0.0 when nothing
    qualifies.

    Note on the stddev feature: this is a weighted mean of per-aggregate
    stddev_interval_ms values, NOT a pooled standard deviation across the
    whole window. Pooling requires per-aggregate means we do not always have;
    the name is kept for model compatibility and the statistic is what it is,
    documented honestly here rather than implied to be something it is not.
    """
    numerator = 0.0
    denominator = 0.0
    for event in typing:
        if value_field not in event.metadata or weight_field not in event.metadata:
            continue
        weight = _num(event.metadata.get(weight_field))
        if weight <= 0:
            continue
        numerator += _num(event.metadata.get(value_field)) * weight
        denominator += weight
    return numerator / denominator if denominator > 0 else 0.0


def _epoch_seconds(timestamp: datetime) -> float:
    """Epoch seconds for a timestamp, tolerating naive datetimes (assume UTC).

    Mirrors windowing._epoch_seconds so subtraction across a mixed-tz window
    does not raise TypeError.
    """
    if timestamp.tzinfo is None:
        timestamp = timestamp.replace(tzinfo=UTC)
    return timestamp.timestamp()


def _num(value: str | int | float | bool | None) -> float:
    """Coerce a metadata value to a number, tolerating sloppy agents.

    Metadata is free-form by design, so agents can attach anything. We only
    ever pull numbers out of it, and anything that is not a finite number is
    a zero we ignore rather than a crash we cause. Non-finite floats
    (`float("nan")`, `float("inf")`) succeed at the `float()` call but would
    poison the feature vector and crash sklearn downstream, so they are
    rejected here too.

    `bool` is checked before `int` because `bool` is an `int` subclass in
    Python (`True == 1`); an agent that sends `"keystrokes": true` gets a
    deliberate 0.0 rather than silently becoming one keystroke.
    """
    if isinstance(value, bool):
        return 0.0
    if isinstance(value, (int, float)):
        result = float(value)
    elif isinstance(value, str):
        try:
            result = float(value)
        except ValueError:
            return 0.0
    else:
        return 0.0
    if not math.isfinite(result):
        return 0.0
    return result
