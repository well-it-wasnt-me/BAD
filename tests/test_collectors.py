"""Tests for collectors. Pure parsers plus the JSONL front door.

The OS-specific collect() methods shell out to journalctl, PowerShell and
`log show`, which only exist on their home platforms. So the parsers are pure
functions fed fixture records here, and CI can run this file on any OS
without owning a Mac, a Windows box and a time machine.
"""

from tests.conftest import make_event

from behavior_anomaly.collectors import build_collector
from behavior_anomaly.collectors.jsonl import JsonlCollector
from behavior_anomaly.collectors.linux import parse_journal_record
from behavior_anomaly.collectors.macos import iter_log_records, parse_log_record
from behavior_anomaly.collectors.windows import parse_win_event
from behavior_anomaly.schema import EventType, Platform


def write_jsonl(tmp_path, events):
    path = tmp_path / "events.jsonl"
    with path.open("w", encoding="utf-8") as fh:
        for event in events:
            fh.write(event.model_dump_json() + "\n")
    return path


# ---------------------------------------------------------------- jsonl


def test_jsonl_collector_reads_normalized_events(tmp_path):
    path = write_jsonl(tmp_path, [make_event(0), make_event(1)])
    events = list(JsonlCollector(path).collect())
    assert [event.action for event in events] == ["exec", "exec"]


def test_build_collector_jsonl_requires_source():
    import pytest

    with pytest.raises(ValueError, match="read a file from a feeling"):
        build_collector("jsonl")


def test_build_collector_rejects_unknown():
    import pytest

    with pytest.raises(ValueError, match="Unknown collector"):
        build_collector("temple-os")


# ---------------------------------------------------------------- linux


def test_journal_audit_execve():
    record = {
        "__REALTIME_TIMESTAMP": "1800000000000000",
        "_HOSTNAME": "box42",
        "_COMM": "bash",
        "_UID": "1000",
        "_AUDIT_LOGINUID": "1000",
        "_AUDIT_TYPE": "EXECVE",
        "MESSAGE": 'argc=2 a0="bash" a1="whoami"',
    }
    event = parse_journal_record(record)
    assert event is not None
    assert event.platform == Platform.LINUX
    assert event.event_type == EventType.PROCESS
    assert event.action == "exec"
    assert event.user_id == "1000"
    assert event.process_name == "bash"


def test_journal_sshd_failure_is_auth_failure():
    record = {
        "__REALTIME_TIMESTAMP": "1800000000000000",
        "_HOSTNAME": "box42",
        "SYSLOG_IDENTIFIER": "sshd",
        "MESSAGE": "Failed password for root from 10.0.0.5 port 22 ssh2",
    }
    event = parse_journal_record(record)
    assert event is not None
    assert event.event_type == EventType.AUTH
    assert event.success is False


def test_journal_sshd_success():
    record = {
        "__REALTIME_TIMESTAMP": "1800000000000000",
        "_HOSTNAME": "box42",
        "SYSLOG_IDENTIFIER": "sshd",
        "MESSAGE": "Accepted publickey for alice from 10.0.0.4 port 22 ssh2",
    }
    event = parse_journal_record(record)
    assert event is not None
    assert event.success is True


def test_journal_sudo_is_privilege():
    record = {
        "__REALTIME_TIMESTAMP": "1800000000000000",
        "_HOSTNAME": "box42",
        "SYSLOG_IDENTIFIER": "sudo",
        "MESSAGE": "alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/bin/bash",
    }
    event = parse_journal_record(record)
    assert event is not None
    assert event.event_type == EventType.PRIVILEGE
    assert event.action == "sudo"


def test_journal_unknown_identifier_skipped():
    record = {
        "__REALTIME_TIMESTAMP": "1800000000000000",
        "_HOSTNAME": "box42",
        "SYSLOG_IDENTIFIER": "gnome-shell",
        "MESSAGE": "something graphical and irrelevant",
    }
    # Silence beats fiction. Skip what we do not understand.
    assert parse_journal_record(record) is None


# ---------------------------------------------------------------- windows


def _win_record(event_id: int, properties: list) -> dict:
    return {
        "Id": event_id,
        "TimeCreated": "2026-09-26T12:00:00.1234567+00:00",
        "MachineName": "DESKTOP-42",
        "ProviderName": "Microsoft-Windows-Security-Auditing",
        "Properties": properties,
    }


def test_win_event_4688_process_creation():
    record = _win_record(
        4688,
        [
            "S-1-5-18",  # SubjectUserSid
            "alice",  # SubjectUserName
            "CORP",  # SubjectDomainName
            "0x3e7",  # SubjectLogonId
            "0x1a4",  # NewProcessId
            "C:\\Windows\\System32\\cmd.exe",  # NewProcessName
            "%%1938",  # TokenElevationType
            "0x2a8",  # ProcessId
            "whoami",  # CommandLine
            "C:\\Windows\\explorer.exe",  # ParentProcessName
        ],
    )
    event = parse_win_event(record)
    assert event is not None
    assert event.platform == Platform.WINDOWS
    assert event.event_type == EventType.PROCESS
    assert event.user_id == "alice"
    assert event.process_name == "cmd.exe"  # full path trimmed to a name
    assert event.parent_process == "C:\\Windows\\explorer.exe"


def test_win_event_4624_is_successful_login():
    properties = ["filler"] * 19
    properties[5] = "alice"  # TargetUserName
    properties[18] = "C:\\Windows\\System32\\svchost.exe"  # ProcessName
    event = parse_win_event(_win_record(4624, properties))
    assert event is not None
    assert event.event_type == EventType.AUTH
    assert event.success is True
    assert event.user_id == "alice"


def test_win_event_4625_is_failed_login():
    properties = ["filler"] * 19
    properties[5] = "root"
    event = parse_win_event(_win_record(4625, properties))
    assert event is not None
    assert event.event_type == EventType.AUTH
    assert event.success is False


def test_win_event_unknown_id_skipped():
    assert parse_win_event(_win_record(5292, ["filler"])) is None


def test_win_event_missing_timestamp_rejected():
    import pytest

    record = _win_record(4624, ["filler"] * 19)
    record["TimeCreated"] = None
    with pytest.raises(ValueError, match="rumor"):
        parse_win_event(record)


# ---------------------------------------------------------------- macos


def test_macos_sshd_failure():
    record = {
        "timestamp": "2026-09-26 12:00:00.000+00:00",
        "process": "sshd",
        "message": "Failed password for invalid user admin from 10.0.0.9",
        "pid": 123,
    }
    event = parse_log_record(record)
    assert event is not None
    assert event.platform == Platform.MACOS
    assert event.event_type == EventType.AUTH
    assert event.success is False


def test_macos_sudo_is_privilege():
    record = {
        "timestamp": "2026-09-26 12:00:00.000+00:00",
        "process": "sudo",
        "message": "alice : TTY=ttys000 ; USER=root ; COMMAND=/bin/bash",
    }
    event = parse_log_record(record)
    assert event is not None
    assert event.event_type == EventType.PRIVILEGE
    assert event.action == "sudo"


def test_macos_unknown_process_skipped():
    record = {"timestamp": "2026-09-26 12:00:00.000+00:00", "process": "Safari", "message": "hi"}
    assert parse_log_record(record) is None


def test_macos_iter_log_records_skips_sentinel():
    stdout = (
        '{"timestamp":"2026-09-26 12:00:00.000+00:00","process":"sudo","message":"hi"}\n'
        "\n"
        '{"finished":"2026-09-26 12:00:01.000+00:00"}\n'
    )
    records = list(iter_log_records(stdout))
    # One real record, one blank line, one "I am done talking" sentinel.
    assert len(records) == 1
    assert records[0]["process"] == "sudo"
