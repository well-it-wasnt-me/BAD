"""Alert storage.

Where findings wait for a SIEM that may or may not care. Unlike events,
alerts are written in overwrite mode: the last scoring run is the truth and
previous runs are just history wearing a trench coat.

Writes are atomic: we serialize to a temp file in the same directory and
`os.replace` it onto the target on success, so a mid-write failure (a
non-Alert slipping in, a full disk) cannot destroy the previous run's
alerts. Truncate-then-stream is how data loss happens, and data loss in a
security product is how incidents happen.
"""

from __future__ import annotations

import os
import tempfile
from collections.abc import Iterable
from pathlib import Path

from behavior_anomaly.schema import Alert


class JsonlAlertStore:
    """Writes alerts as JSON Lines, one alert per line."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)

    def write(self, alerts: Iterable[Alert]) -> None:
        """Write alerts to the file, replacing whatever was there before.

        Atomic: serialize to a sibling temp file, then `os.replace` onto the
        target. A failure partway through never leaves the previous run's
        alerts gone and the new file half-written.
        """
        self.path.parent.mkdir(parents=True, exist_ok=True)
        # Materialize so serialization errors (a non-Alert in the iterable)
        # surface before we touch the real file. The directory is the target's
        # so os.replace stays on the same filesystem (atomic on POSIX).
        serialized = [a.model_dump_json() for a in alerts]
        tmp_fd, tmp_path = tempfile.mkstemp(
            prefix=self.path.name + ".", suffix=".tmp", dir=str(self.path.parent)
        )
        try:
            with os.fdopen(tmp_fd, "w", encoding="utf-8") as fh:
                for line in serialized:
                    fh.write(line + "\n")
            os.replace(tmp_path, self.path)
        except Exception:
            # Clean up the temp file on any failure; never leave a .tmp behind.
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
            raise

    def read(self) -> list[Alert]:
        """Read every alert back. Symmetric with the event store."""
        if not self.path.exists():
            return []
        lines = self.path.read_text(encoding="utf-8").splitlines()
        return [Alert.model_validate_json(line) for line in lines if line.strip()]
