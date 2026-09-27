"""Anomaly model contract.

Anything that can learn what "normal" looks like and score a feature row can
sit in the pipeline. One model in, one interface out. The registry is the only
place that needs to know which concrete class exists.
"""

from abc import ABC, abstractmethod
from collections.abc import Sequence


class AnomalyModel(ABC):
    """Interface for anomaly models.

    fit() learns what normal looks like. score() says how abnormal one feature
    row is: 0.0 is a Monday morning, 1.0 is a ransomware sampler.
    """

    name: str = "unknown"

    @abstractmethod
    def fit(self, rows: Sequence[dict[str, float]]) -> None:
        raise NotImplementedError

    @abstractmethod
    def score(self, row: dict[str, float]) -> float:
        raise NotImplementedError
