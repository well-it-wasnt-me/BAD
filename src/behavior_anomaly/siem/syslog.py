"""Syslog sink.

Ships alerts through the local syslog via the Python logging stack. Most
SIEMs on the planet happily slurp syslog off a host, and the alert rides
along as compact JSON inside the message so the receiving parser has a
fighting chance instead of a regex and a prayer.
"""

import json
import logging

from behavior_anomaly.schema import Alert
from behavior_anomaly.siem.base import SiemSink


class SyslogSink(SiemSink):
    """Logs each alert as a WARNING with a SIEM_ALERT prefix."""

    def __init__(self, logger_name: str = "behavior-anomaly") -> None:
        self.logger = logging.getLogger(logger_name)

    def send(self, alert: Alert) -> None:
        payload = json.dumps(alert.model_dump(mode="json"), separators=(",", ":"))
        self.logger.warning("SIEM_ALERT %s", payload)
