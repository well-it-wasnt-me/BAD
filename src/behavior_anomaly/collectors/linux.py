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
import threading
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
# Markers are scoped to audit/sshd prose so a benign line like "Failed login
# attempts this hour: 0" is not misread as a failure event.
_FAILURE_MARKERS = ("res=failed", "failed password", "invalid user", "authentication failure")

_DEFAULT_TIMEOUT = 60.0


class LinuxJournalCollector(Collector):
    """Collects behavioral events from the systemd journal.

    Needs `journalctl` on PATH and a user allowed to read the journal, which
    is most users on most boxes and nobody on a properly paranoid one.
    """

    def __init__(self, since: str | None = None, *, timeout: float = _DEFAULT_TIMEOUT) -> None:
        self.since = since
        self.timeout = timeout

    def collect(self) -> Iterator[BehaviorEvent]:
        command = ["journalctl", "--output=json", "--no-pager"]
        if self.since:
            command += ["--since", self.since]

        if shutil.which("journalctl") is None:
            raise FileNotFoundError("journalctl not found. It is a systemd world, we just suffer in it.")

        # journalctl is streamed line-by-line, so subprocess.run's `timeout`
        # does not apply. A watchdog timer terminates the process if it runs
        # past the deadline, which the read loop observes as a closed pipe.
        timed_out = False
        stderr_text = ""

        def _watchdog() -> None:
            nonlocal timed_out
            if process.poll() is None:
                timed_out = True
                process.terminate()

        timer = threading.Timer(self.timeout, _watchdog)
        timer.start()
        try:
            with subprocess.Popen(
                command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
            ) as process:
                try:
                    for line in process.stdout or []:
                        if not line.strip():
                            continue
                        try:
                            record = json.loads(line)
                        except json.JSONDecodeError:
                            # A malformed line in the journal is not a reason
                            # to abort collection; skip it and keep going.
                            continue
                        event = parse_journal_record(record)
                        if event is not None:
                            yield event
                finally:
                    # Drain stderr before reaping so a non-zero exit can be
                    # reported with the actual error text, not just a code.
                    try:
                        stderr_text = process.stderr.read() if process.stderr else ""
                    except (ValueError, OSError):
                        stderr_text = ""
                    # Ensure the child is reaped even if the consumer stops
                    # iterating early or a parse path raises. The `with`
                    # block also closes stdout on exit.
                    if process.poll() is None:
                        process.terminate()
                    exit_code = process.wait()
        finally:
            timer.cancel()

        if timed_out:
            raise TimeoutError(f"journalctl did not finish within {self.timeout}s.")
        if exit_code != 0:
            detail = stderr_text.strip()
            detail = f": {detail}" if detail else ""
            raise RuntimeError(f"journalctl exited with code {exit_code}{detail}")


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

    try:
        timestamp = _parse_timestamp(record.get("__REALTIME_TIMESTAMP"))
    except (ValueError, TypeError):
        # A timestampless record is malformed; skip it instead of poisoning
        # epoch-aligned windowing with a fabricated "now".
        return None

    return BehaviorEvent(
        timestamp=timestamp,
        host_id=str(record.get("_HOSTNAME") or "unknown"),
        # Use explicit None checks so a legitimate loginuid of 0 (root) is not
        # lost to an `or` chain that treats 0 as falsy.
        user_id=_first(record.get("_AUDIT_LOGINUID"), record.get("_UID")) or "unknown",
        platform=Platform.LINUX,
        event_type=event_type,
        action=action,
        process_name=record.get("_COMM") or None,
        source=identifier or None,
        success=_guess_success(message),
        metadata={"pid": record.get("_PID")},
    )


def _first(*values: Any) -> str | None:
    """Return the first non-None value, as a string. Avoids the `or` chain
    falsiness trap for legitimate falsy values like the integer 0."""
    for value in values:
        if value is not None:
            return str(value)
    return None


def _parse_timestamp(value: Any) -> datetime:
    """journalctl hands us epoch microseconds as a string. Because of course.

    A record with no timestamp is malformed, not "now": substituting the
    collection time would misplace it in epoch-aligned windowing and silently
    manufacture or hide anomalies. We raise, matching the Windows collector,
    so the caller can decide to skip the record.
    """
    if value is None:
        raise ValueError("Journal record is missing __REALTIME_TIMESTAMP. A timestampless event is a rumor.")
    return datetime.fromtimestamp(int(value) / 1_000_000, tz=UTC)


def _guess_success(message: str) -> bool | None:
    """Best-effort success/failure read from free-form log prose.

    Returns None when the message says nothing useful, which is honest at
    least. Returns True when no failure marker is present, because in this
    industry absence of failure is as good as success ever gets. Markers are
    scoped to audit/sshd phrasing so a benign "Failed login attempts this
    hour: 0" is not misread as a failure.
    """
    lowered = message.lower()
    if any(marker in lowered for marker in _FAILURE_MARKERS):
        return False
    return True if message else None
