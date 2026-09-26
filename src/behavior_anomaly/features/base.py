"""Feature extraction contract.

Features see BehaviorEvents, never raw telemetry. That separation is what
keeps this package from becoming a shrine to any single operating system.
"""

from abc import ABC, abstractmethod
from collections.abc import Sequence

from behavior_anomaly.schema import BehaviorEvent


class FeatureExtractor(ABC):
    """Turns a window of events into one flat row of numbers."""

    @abstractmethod
    def extract(self, events: Sequence[BehaviorEvent]) -> dict[str, float]:
        raise NotImplementedError
