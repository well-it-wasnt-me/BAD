"""Model registry. Builds models by name so callers never hardcode a class.

One flavor today: vanilla. When someone adds a temporal model or a clustering
model, this is the only place that grows.
"""

from behavior_anomaly.models.base import AnomalyModel
from behavior_anomaly.models.isolation_forest import IsolationForestModel


def build_model(name: str, contamination: float = 0.01) -> AnomalyModel:
    """Return a fresh, untrained model by name."""
    if name == "isolation_forest":
        return IsolationForestModel(contamination)
    raise ValueError(f"Unknown model: {name!r}. Known models: isolation_forest")
