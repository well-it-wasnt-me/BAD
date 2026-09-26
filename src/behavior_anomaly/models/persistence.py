"""Model persistence. Save to disk, load from disk, go home.

joblib handles the numpy internals so we do not have to think about them.
Fair warning for the future: joblib files are pickles, and pickles execute
code on load. Only load models you built yourself, like only taking candy
from strangers you have known for years.
"""

from pathlib import Path

import joblib

from behavior_anomaly.models.base import AnomalyModel


def save_model(model: AnomalyModel, path: str | Path) -> None:
    """Serialize a trained model to disk, creating parent folders as needed."""
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(model, target)


def load_model(path: str | Path) -> AnomalyModel:
    """Load a model back from disk and hand it over as its interface."""
    return joblib.load(Path(path))
