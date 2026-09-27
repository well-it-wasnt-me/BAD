"""Collectors: OS telemetry in, BehaviorEvents out."""

from behavior_anomaly.collectors.base import Collector
from behavior_anomaly.collectors.jsonl import JsonlCollector
from behavior_anomaly.collectors.linux import LinuxJournalCollector
from behavior_anomaly.collectors.macos import MacOSLogCollector
from behavior_anomaly.collectors.windows import WindowsEventLogCollector


def build_collector(kind: str, source: str | None = None) -> Collector:
    """Factory: pick a collector by name.

    kind: "jsonl" (agent-friendly, works anywhere), "linux" (journalctl),
        "windows" (event log), "macos" (unified log)
    source: path for jsonl (--source), journalctl time string for linux
        (--since). Optional elsewhere.
    """
    if kind == "jsonl":
        if source is None:
            raise ValueError("The jsonl collector needs a path. We cannot read a file from a feeling.")
        return JsonlCollector(source)
    if kind == "linux":
        return LinuxJournalCollector(since=source)
    if kind == "windows":
        return WindowsEventLogCollector()
    if kind == "macos":
        return MacOSLogCollector()
    raise ValueError(f"Unknown collector: {kind!r}. Known: jsonl, linux, windows, macos")
