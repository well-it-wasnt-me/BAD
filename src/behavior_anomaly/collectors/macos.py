"""macOS collector.

Reads the unified log via `log show --style ndjson`. The unified log is very
thorough and very chatty, so we only map processes we actually understand:
sshd for authentication and sudo for privilege escalation. Everything else
gets skipped rather than guessed at. Guessing is for weathermen.

Want richer telemetry on macOS? The real answer is the Endpoint Security
framework, which requires entitlements Apple does not hand out like candy.
The collector interface is the adapter point: point it at your own ES agent
output (as normalized JSONL) and this package will happily chew on that.
"""

import json
import subprocess
from collections.abc import Iterator
from datetime import UTC, datetime
from typing import Any

from behavior_anomaly.collectors.base import Collector
from behavior_anomaly.schema import BehaviorEvent, EventType, Platform


class MacOSLogCollector(Collector):
    """Collects behavioral events from the macOS unified log."""

    def __init__(self, last: str = "1h") -> None:
        self.last = last

    def collect(self) -> Iterator[BehaviorEvent]:
        command = ["log", "show", "--style", "ndjson", "--last", self.last, "--info"]
        completed = subprocess.run(command, capture_output=True, text=True)
        if completed.returncode != 0:
            raise RuntimeError(f"`log show` failed: {completed.stderr.strip()}")

        for record in iter_log_records(completed.stdout):
            event = parse_log_record(record)
            if event is not None:
                yield event


def iter_log_records(stdout: str) -> Iterator[dict[str, Any]]:
    """Parse `log show --style ndjson` stdout into records.

    Pure function: skips blank lines and the trailing "finished" sentinel,
    which is `log show`'s polite way of saying it is done talking.
    """
    for line in stdout.splitlines():
        if not line.strip():
            continue
        record = json.loads(line)
        if "finished" in record:
            continue
        yield record


def parse_log_record(record: dict[str, Any]) -> BehaviorEvent | None:
    """Map one unified log NDJSON record to a BehaviorEvent, or None to skip.

    Pure function. The unified log schema has drifted between macOS versions,
    so we accept both the known key spellings rather than bet on one.
    """
    process = str(record.get("process") or "")
    message = str(record.get("eventMessage") or record.get("message") or "")

    if process == "sshd":
        event_type, action = EventType.AUTH, "login"
    elif process == "sudo":
        event_type, action = EventType.PRIVILEGE, "sudo"
    else:
        return None

    success = None
    if process == "sshd":
        success = not ("failed" in message.lower() or "invalid user" in message.lower())

    return BehaviorEvent(
        timestamp=_parse_timestamp(record.get("timestamp")),
        host_id=str(record.get("machine") or "unknown"),
        # The unified log does not hand us a user per message. sudo/sshd tell
        # us in the prose, but parsing free text for identity is how tools
        # start blaming the wrong employee, so we stay honest.
        user_id="unknown",
        platform=Platform.MACOS,
        event_type=event_type,
        action=action,
        process_name=process or None,
        source=str(record.get("subsystem") or None) or None,
        success=success,
        metadata={"pid": record.get("pid")},
    )


def _parse_timestamp(value: Any) -> datetime:
    """Parse the unified log's ISO-ish timestamp, e.g. 2024-01-01 00:00:00.000+00:00.

    Note the space separator. Python's fromisoformat accepts it, because
    even a broken clock is right twice a day.
    """
    if value is None:
        return datetime.now(UTC)
    parsed = datetime.fromisoformat(str(value))
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed
