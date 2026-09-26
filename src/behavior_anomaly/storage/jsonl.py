"""JSONL event storage.

Boring, append-only, greppable. A text file you can inspect with less and
restore with cp. Storage as it should be, before someone invents a blockchain
for logs.
"""

from collections.abc import Iterable, Iterator
from pathlib import Path

from behavior_anomaly.schema import BehaviorEvent
from behavior_anomaly.storage.base import EventStore


class JsonlStore(EventStore):
    """Reads and writes BehaviorEvents as JSON Lines."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)

    def write(self, events: Iterable[BehaviorEvent]) -> None:
        """Append events to the file. We never overwrite event history; the
        SIEM business is built on never forgetting, right or wrong."""
        with self.path.open("a", encoding="utf-8") as fh:
            for event in events:
                fh.write(event.model_dump_json() + "\n")

    def read(self) -> list[BehaviorEvent]:
        """Load every event into memory. Fine for files, rude to exabytes."""
        return list(self.iter_events())

    def iter_events(self) -> Iterator[BehaviorEvent]:
        """Stream events one line at a time. Your RAM sends its regards."""
        with self.path.open(encoding="utf-8") as fh:
            for line in fh:
                if line.strip():
                    yield BehaviorEvent.model_validate_json(line)
