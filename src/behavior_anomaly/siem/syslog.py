"""Syslog sink.

Ships alerts through the local syslog via the Python logging stack. Most
SIEMs on the planet happily slurp syslog off a host, and the alert rides
along as compact JSON inside the message so the receiving parser has a
fighting chance instead of a regex and a prayer.

This sink attaches a real SysLogHandler to a dedicated logger when the local
syslog socket is reachable, so "syslog" actually means syslog rather than
"stderr with ambitions". When the socket is absent (containers, CI, Windows
dev boxes), we fall back to a StreamHandler so the alerts still go somewhere
instead of being dropped on the floor. Either way the SIEM_ALERT line and its
JSON payload are identical, so downstream parsers do not care which transport
fired.
"""

from __future__ import annotations

import json
import logging
from logging.handlers import SysLogHandler

from behavior_anomaly.schema import Alert
from behavior_anomaly.siem.base import SiemSink

# syslog line-length budgets are real (RFC 3164 suggests 1024, most daemons
# truncate around 2048). We cap the payload so a pathological feature vector
# cannot silently get clipped mid-JSON on its way to the SIEM.
_MAX_PAYLOAD_CHARS = 4096


class SyslogSink(SiemSink):
    """Logs each alert as a WARNING with a SIEM_ALERT prefix."""

    def __init__(self, logger_name: str = "behavior-anomaly") -> None:
        self.logger = logging.getLogger(logger_name)
        # Attach a handler exactly once per logger. A second sink reusing the
        # same logger name must not double-send every alert.
        if not getattr(self.logger, "_bad_syslog_wired", False):
            self._attach_handler()
            self.logger._bad_syslog_wired = True  # type: ignore[attr-defined]
        # Never let our alerts propagate to the root logger and get echoed to
        # stderr by basicConfig as well — that would double-log in the daemon.
        self.logger.propagate = False

    def _attach_handler(self) -> None:
        handler: logging.Handler
        # Try the local syslog socket(s) in order: Linux first, then macOS.
        # SysLogHandler accepts a Unix socket path or a (host, port) tuple;
        # a bare path is the right shape for the local datagram socket.
        for address in ("/dev/log", "/var/run/syslog"):
            try:
                handler = SysLogHandler(address=address)
                break
            except (OSError, ValueError):
                continue
        else:
            # No local syslog socket (Windows, containers, CI). Fall back to
            # stderr so the alert is never silently lost — better noisy than
            # quiet when the configured transport is "syslog".
            handler = logging.StreamHandler()
        handler.setFormatter(logging.Formatter("%(message)s"))
        self.logger.addHandler(handler)

    def send(self, alert: Alert) -> None:
        payload = json.dumps(alert.model_dump(mode="json"), separators=(",", ":"))
        if len(payload) > _MAX_PAYLOAD_CHARS:
            # Truncating mid-JSON breaks parsers, so we send a smaller but
            # still valid object: drop the feature_vector (the heaviest field)
            # and keep the analyst-actionable metadata.
            slim = alert.model_dump(mode="json")
            slim.pop("feature_vector", None)
            payload = json.dumps(slim, separators=(",", ":"))
        self.logger.warning("SIEM_ALERT %s", payload)
