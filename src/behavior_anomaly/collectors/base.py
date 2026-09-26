"""Collector contract.

Collectors are the only layer allowed to know what an operating system
sounds like. Everything downstream sees BehaviorEvents and nothing else.
"""

from abc import ABC, abstractmethod
from collections.abc import Iterator

from behavior_anomaly.schema import BehaviorEvent


class Collector(ABC):
    """Yields normalized BehaviorEvents from some telemetry source."""

    @abstractmethod
    def collect(self) -> Iterator[BehaviorEvent]:
        raise NotImplementedError
