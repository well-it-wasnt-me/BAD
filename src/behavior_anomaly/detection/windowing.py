"""Time windowing.

Raw events are noise. Bucketed events are behavior. We group events per
host, per user, per time bucket, so the model gets "what did this user do
in the last N seconds" instead of "here is a pile of logs, good luck".

Buckets are aligned to the epoch: a 300 second window starts at :00, :05,
:10, and so on, not whenever the first event felt like showing up.
"""

from collections.abc import Iterable
from datetime import UTC, datetime

from behavior_anomaly.schema import BehaviorEvent


def build_windows(
    events: Iterable[BehaviorEvent],
    window_seconds: int,
) -> list[list[BehaviorEvent]]:
    """Group events into (host, user, bucket) windows.

    Returns a list of windows, each a chronologically sorted list of events.
    Events are bucketed per host AND per user, because Alice's Tuesday should
    not influence Bob's risk score. Bob has enough problems.
    """
    if window_seconds <= 0:
        raise ValueError("window_seconds must be positive. Time only flows one way, pal.")

    groups: dict[tuple[str, str, int], list[BehaviorEvent]] = {}
    for event in events:
        bucket = int(_epoch_seconds(event.timestamp) // window_seconds)
        key = (event.host_id, event.user_id, bucket)
        groups.setdefault(key, []).append(event)

    return [sorted(groups[key], key=lambda event: event.timestamp) for key in sorted(groups)]


def _epoch_seconds(timestamp: datetime) -> float:
    """Epoch seconds for a timestamp, tolerating naive datetimes.

    Schema says events can be timezone-naive if a collector was lazy. We
    generously assume UTC rather than let a ValueError ruin the whole batch.
    """
    if timestamp.tzinfo is None:
        timestamp = timestamp.replace(tzinfo=UTC)
    return timestamp.timestamp()
