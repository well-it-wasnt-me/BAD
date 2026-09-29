"""JSONL event storage.

Boring, append-only, greppable. A text file you can inspect with less and
restore with cp. Storage as it should be, before someone invents a blockchain
for logs.
"""

import logging
from collections.abc import Iterable, Iterator
from pathlib import Path

from pydantic import ValidationError

from behavior_anomaly.schema import BehaviorEvent
from behavior_anomaly.storage.base import EventStore

logger = logging.getLogger("behavior_anomaly.storage.jsonl")


class JsonlStore(EventStore):
    """Reads and writes BehaviorEvents as JSON Lines."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)

    def write(self, events: Iterable[BehaviorEvent]) -> None:
        """Append events to the file. We never overwrite event history; the
        SIEM business is built on never forgetting, right or wrong. Parent
        directories are created so a fresh install with the default
        /var/lib/bad/events.jsonl bootstraps without a manual mkdir."""
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("a", encoding="utf-8") as fh:
            for event in events:
                fh.write(event.model_dump_json() + "\n")

    def read(self) -> list[BehaviorEvent]:
        """Load every event into memory. Fine for files, rude to exabytes."""
        return list(self.iter_events())

    def iter_events(self) -> Iterator[BehaviorEvent]:
        """Stream events one line at a time. Your RAM sends its regards.

        A single corrupt line (a truncated write, schema drift, a manual
        edit) is logged and skipped rather than aborting the whole stream:
        one bad line poisoning an entire file is the kind of bug that turns
        a minor glitch into a total outage. Corrupt lines are counted and
        logged at WARNING so they are visible without crashing the daemon.
        """
        corrupt = 0
        with self.path.open(encoding="utf-8") as fh:
            for line in fh:
                if not line.strip():
                    continue
                try:
                    yield BehaviorEvent.model_validate_json(line)
                except ValidationError:
                    corrupt += 1
                    logger.warning("Skipping corrupt line %d in %s", corrupt, self.path)
                    continue
        if corrupt:
            logger.warning("Skipped %d corrupt line(s) in %s", corrupt, self.path)
