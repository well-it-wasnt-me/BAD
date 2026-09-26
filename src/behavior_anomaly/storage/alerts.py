"""Alert storage.

Where findings wait for a SIEM that may or may not care. Unlike events,
alerts are written in overwrite mode: the last scoring run is the truth and
previous runs are just history wearing a trench coat.
"""

from collections.abc import Iterable
from pathlib import Path

from behavior_anomaly.schema import Alert


class JsonlAlertStore:
    """Writes alerts as JSON Lines, one alert per line."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)

    def write(self, alerts: Iterable[Alert]) -> None:
        """Write alerts to the file, replacing whatever was there before."""
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("w", encoding="utf-8") as fh:
            for alert in alerts:
                fh.write(alert.model_dump_json() + "\n")
