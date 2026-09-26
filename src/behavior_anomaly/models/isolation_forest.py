"""Isolation Forest baseline.

Unsupervised, fast, and hard to impress: it learns the shape of normal window
features and flags windows that are hard to describe as anything but weird.
Not fancy, but it ships, and fancy models can replace it without touching a
single line outside this file. That is the interface doing its job.
"""

from collections.abc import Sequence

import numpy as np
from sklearn.ensemble import IsolationForest

from behavior_anomaly.models.base import AnomalyModel


class IsolationForestModel(AnomalyModel):
    """Sklearn Isolation Forest wrapped in the AnomalyModel contract."""

    name = "isolation_forest"

    def __init__(self, contamination: float = 0.01) -> None:
        self.model = IsolationForest(
            n_estimators=200,
            contamination=contamination,
            random_state=42,
        )
        self.columns: list[str] = []

    def fit(self, rows: Sequence[dict[str, float]]) -> None:
        """Train on feature rows. All rows must carry the same columns."""
        if not rows:
            raise ValueError("Cannot train on an empty dataset. Even Nostradamus needed data.")
        self.columns = sorted(rows[0])
        matrix = np.asarray([[row[col] for col in self.columns] for row in rows], dtype=float)
        self.model.fit(matrix)

    def score(self, row: dict[str, float]) -> float:
        """Score one row: 0.0 boring, 1.0 spicy.

        sklearn's decision_function is positive for normal points, so we flip
        it and shift it into a 0..1 range. Higher score, weirder user.
        """
        if not self.columns:
            raise ValueError("Model is untrained. Train it first, then ask questions.")
        missing = set(self.columns) - set(row)
        if missing:
            raise KeyError(f"Feature row is missing columns: {sorted(missing)}")
        matrix = np.asarray([[row[col] for col in self.columns]], dtype=float)
        raw = float(-self.model.decision_function(matrix)[0])
        return max(0.0, min(1.0, raw + 0.5))
