"""JSONL collector: ingest events that are already normalized.

This is the front door for agents, EDRs and monitoring tools. They collect
and normalize, they hand us JSON Lines, we do the math. Division of labor,
people. It is also the reason this package can be tested on any OS: no
journal, no event log, no unified log, just a text file telling the truth.
"""

from collections.abc import Iterator
from pathlib import Path

from behavior_anomaly.collectors.base import Collector
from behavior_anomaly.schema import BehaviorEvent
from behavior_anomaly.storage.jsonl import JsonlStore


class JsonlCollector(Collector):
    """Reads normalized BehaviorEvent records from a JSON Lines file."""

    def __init__(self, path: str | Path) -> None:
        self.store = JsonlStore(path)

    def collect(self) -> Iterator[BehaviorEvent]:
        yield from self.store.iter_events()
