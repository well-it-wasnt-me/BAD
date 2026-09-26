"""Shared test helpers. Synthetic users behaving badly, on demand."""

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from behavior_anomaly.schema import BehaviorEvent, EventType, Platform

# Repo root, for tests that read files we ship (like config.example.toml).
REPO_ROOT = Path(__file__).resolve().parents[1]

# A reference time snapped to a 300 second boundary, so windowing tests can
# pretend time is tidy. Time is never tidy, but tests get to cheat.
_RAW = datetime(2026, 9, 26, 12, 0, 0, tzinfo=UTC)
T0 = datetime.fromtimestamp(_RAW.timestamp() - (_RAW.timestamp() % 300), tz=UTC)


def make_event(
    seconds_offset: int = 0,
    action: str = "exec",
    event_type: EventType = EventType.PROCESS,
    user_id: str = "alice",
    host_id: str = "host-1",
    platform: Platform = Platform.LINUX,
    success: bool | None = None,
    privileged: bool | None = None,
    process_name: str | None = "bash",
    destination: str | None = None,
    application: str | None = None,
    metadata: dict[str, str | int | float | bool | None] | None = None,
) -> BehaviorEvent:
    """Build one synthetic event, offset from T0 by the given seconds."""
    return BehaviorEvent(
        timestamp=T0 + timedelta(seconds=seconds_offset),
        host_id=host_id,
        user_id=user_id,
        platform=platform,
        event_type=event_type,
        action=action,
        process_name=process_name,
        success=success,
        privileged=privileged,
        destination=destination,
        application=application,
        metadata=metadata or {},
    )


@pytest.fixture
def benign_events() -> list[BehaviorEvent]:
    """A boring afternoon of Alice doing Alice things.

    Two full 300 second windows of steady process and file activity. The
    behavioral equivalent of beige.
    """
    return [
        make_event(
            seconds_offset=offset,
            process_name="vim",
            event_type=EventType.PROCESS if offset % 20 < 10 else EventType.FILE,
            action="edit" if offset % 20 < 10 else "write",
        )
        for offset in range(0, 600, 10)
    ]
