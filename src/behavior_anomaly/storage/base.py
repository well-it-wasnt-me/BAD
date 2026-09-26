"""Event storage contract.

Where events wait between collection and scoring. Implementations can be as
dumb as a JSONL file or as fancy as a database; the pipeline does not care.
"""

from abc import ABC, abstractmethod
from collections.abc import Iterable, Iterator

from behavior_anomaly.schema import BehaviorEvent


class EventStore(ABC):
    """Reads and writes BehaviorEvents."""

    @abstractmethod
    def write(self, events: Iterable[BehaviorEvent]) -> None:
        raise NotImplementedError

    @abstractmethod
    def read(self) -> list[BehaviorEvent]:
        raise NotImplementedError

    @abstractmethod
    def iter_events(self) -> Iterator[BehaviorEvent]:
        raise NotImplementedError
