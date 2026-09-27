"""Linux collector.

Pulls from the systemd journal via `journalctl --output json`. auditd messages
land in the journal too, so one firehose gets us process, shell, auth and
privilege events, assuming the box actually runs auditd and systemd. If it
runs neither, the machine is a lifestyle choice and we respect that from afar.

The mapping is deliberately conservative: entries we cannot identify get
skipped instead of guessed at. A tool that hallucinates telemetry is worse
than no tool at all.
"""

import json
import shutil
import subprocess
from collections.abc import Iterator
from datetime import UTC, datetime
from typing import Any

from behavior_anomaly.collectors.base import Collector
from behavior_anomaly.schema import BehaviorEvent, EventType, Platform

# auditd record types we understand, mapped to (event_type, action).
_AUDIT_TYPE_MAP: dict[str, tuple[EventType, str]] = {
    "EXECVE": (EventType.PROCESS, "exec"),
    "USER_CMD": (EventType.SHELL, "command"),
    "USER_LOGIN": (EventType.AUTH, "login"),
    "USER_AUTH": (EventType.AUTH, "auth"),
}

# auditd writes "res=success" or "res=failed" into the message. Optimists
# read the success marker; we check for failure and let absence be success.
_FAILURE_MARKERS = ("Failed", "Invalid", "res=failed")


class LinuxJournalCollector(Collector):
    """Collects behavioral events from the systemd journal.

    Needs `journalctl` on PATH and a user allowed to read the journal, which
    is most users on most boxes and nobody on a properly paranoid one.
    """

    def __init__(self, since: str | None = None) -> None:
        self.since = since

    def collect(self) -> Iterator[BehaviorEvent]:
        command = ["journalctl", "--output=json", "--no-pager"]
        if self.since:
            command += ["--since", self.since]

        if shutil.which("journalctl") is None:
            raise FileNotFoundError("journalctl not found. It is a systemd world, we just suffer in it.")

        process = subprocess.Popen(command, stdout=subprocess.PIPE, text=True)
        for line in process.stdout or []:
            if not line.strip():
                continue
            record = json.loads(line)
            event = parse_journal_record(record)
            if event is not None:
                yield event
        exit_code = process.wait()
        if exit_code != 0:
            raise RuntimeError(f"journalctl exited with code {exit_code}")


def parse_journal_record(record: dict[str, Any]) -> BehaviorEvent | None:
    """Map one journalctl JSON record to a BehaviorEvent, or None to skip.

    Pure function: no I/O, no side effects, easy to test. All the impure
    parts of this module are plumbing, and plumbing is where bugs breed.
    """
    identifier = str(record.get("SYSLOG_IDENTIFIER") or record.get("_COMM") or "")
    audit_type = str(record.get("_AUDIT_TYPE") or "")
    message = str(record.get("MESSAGE") or "")

    event_type: EventType | None = None
    action = "observed"
    if audit_type in _AUDIT_TYPE_MAP:
        event_type, action = _AUDIT_TYPE_MAP[audit_type]
    elif identifier == "sshd":
        # sshd never structured its logs and never will. We read the tea leaves.
        event_type, action = EventType.AUTH, "login"
    elif identifier == "sudo":
        event_type, action = EventType.PRIVILEGE, "sudo"

    if event_type is None:
        return None

    return BehaviorEvent(
        timestamp=_parse_timestamp(record.get("__REALTIME_TIMESTAMP")),
        host_id=str(record.get("_HOSTNAME") or "unknown"),
        user_id=str(record.get("_AUDIT_LOGINUID") or record.get("_UID") or "unknown"),
        platform=Platform.LINUX,
        event_type=event_type,
        action=action,
        process_name=record.get("_COMM") or None,
        source=identifier or None,
        success=_guess_success(message),
        metadata={"pid": record.get("_PID")},
    )


def _parse_timestamp(value: Any) -> datetime:
    """journalctl hands us epoch microseconds as a string. Because of course."""
    if value is None:
        return datetime.now(UTC)
    return datetime.fromtimestamp(int(value) / 1_000_000, tz=UTC)


def _guess_success(message: str) -> bool | None:
    """Best-effort success/failure read from free-form log prose.

    Returns None when the message says nothing useful, which is honest at
    least. Returns True when no failure marker is present, because in this
    industry absence of failure is as good as success ever gets.
    """
    lowered = message.lower()
    if any(marker.lower() in lowered for marker in _FAILURE_MARKERS):
        return False
    return True if message else None
