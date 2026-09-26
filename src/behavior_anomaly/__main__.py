"""Entry point so `python -m behavior_anomaly` works, and so PyInstaller has
a clean target for the standalone executables. One door, many users."""

from behavior_anomaly.cli import app

app()
