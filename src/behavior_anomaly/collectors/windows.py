"""Windows collector.

Pulls Security events out of the Windows Event Log via PowerShell, because
PowerShell is the one scripting runtime guaranteed to live on every Windows
box whether we like it or not.

The property-index parsing below matches Microsoft's documented event
layouts (4624 logon, 4625 failed logon, 4688 process creation). Non-English
locales shuffle the human-readable Message text, so we read the structured
Properties array instead of the prose. Brittle? Yes. Documented brittle is
still better than localized brittle.
"""

import json
import subprocess
from collections.abc import Iterator
from datetime import datetime
from typing import Any

from behavior_anomaly.collectors.base import Collector
from behavior_anomaly.schema import BehaviorEvent, EventType, Platform

# Event ID -> (event type, action). The Security log's greatest hits.
_EVENT_MAP: dict[int, tuple[EventType, str]] = {
    4624: (EventType.AUTH, "login"),
    4625: (EventType.AUTH, "login"),
    4688: (EventType.PROCESS, "exec"),
}


class WindowsEventLogCollector(Collector):
    """Collects behavioral events from the Windows Security event log."""

    def __init__(self, log_name: str = "Security", event_ids: tuple[int, ...] = (4624, 4625, 4688)) -> None:
        self.log_name = log_name
        self.event_ids = event_ids

    def collect(self) -> Iterator[BehaviorEvent]:
        ids = ",".join(str(event_id) for event_id in self.event_ids)
        script = (
            f"Get-WinEvent -FilterHashtable @{{LogName='{self.log_name}';Id={ids}}} | ConvertTo-Json -Compress -Depth 4"
        )
        completed = subprocess.run(
            ["powershell", "-NoProfile", "-Command", script],
            capture_output=True,
            text=True,
        )
        if completed.returncode != 0:
            raise RuntimeError(f"PowerShell failed: {completed.stderr.strip()}")

        data = json.loads(completed.stdout or "null")
        if data is None:
            return
        # ConvertTo-Json returns a bare object for one event and a list for
        # many. Consistency is a gift Microsoft never gave us.
        records = data if isinstance(data, list) else [data]
        for record in records:
            event = parse_win_event(record)
            if event is not None:
                yield event


def parse_win_event(record: dict[str, Any]) -> BehaviorEvent | None:
    """Map one Get-WinEvent/ConvertTo-Json record to a BehaviorEvent.

    Pure function, no PowerShell harmed during testing.
    """
    event_id = int(record.get("Id") or 0)
    if event_id not in _EVENT_MAP:
        return None

    event_type, action = _EVENT_MAP[event_id]
    props: list[Any] = record.get("Properties") or []

    # Structured property indices per Microsoft's event layouts:
    #   4624/4625: [5] TargetUserName, [18] ProcessName
    #   4688: [1] SubjectUserName, [5] NewProcessName, [9] ParentProcessName
    user_index, process_index = (5, 18) if event_id in (4624, 4625) else (1, 5)
    success = True if event_id == 4624 else (False if event_id == 4625 else None)

    return BehaviorEvent(
        timestamp=_parse_timestamp(record.get("TimeCreated")),
        host_id=str(record.get("MachineName") or "unknown"),
        user_id=_field(props, user_index) or "unknown",
        platform=Platform.WINDOWS,
        event_type=event_type,
        action=action,
        process_name=_basename(_field(props, process_index)),
        parent_process=_field(props, 9) if event_id == 4688 else None,
        source=str(record.get("ProviderName") or "Microsoft-Windows-Security-Auditing"),
        success=success,
        metadata={"event_id": event_id},
    )


def _parse_timestamp(value: Any) -> datetime:
    """Parse a .NET timestamp string. Python 3.11+ fromisoformat tolerates
    up to 7 fractional digits, which .NET produces with pride."""
    if value is None:
        raise ValueError("Windows event is missing TimeCreated. A log entry without a time is a rumor.")
    return datetime.fromisoformat(str(value))


def _field(props: list[Any], index: int) -> str | None:
    """Best-effort read of one structured event property."""
    if index >= len(props):
        return None
    value = props[index]
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _basename(path: str | None) -> str | None:
    """Windows gives us full paths; we only care about the executable name.
    C:\\Windows\\System32\\cmd.exe is a sentence, cmd.exe is a name."""
    if path is None:
        return None
    return path.replace("\\", "/").rsplit("/", 1)[-1]
