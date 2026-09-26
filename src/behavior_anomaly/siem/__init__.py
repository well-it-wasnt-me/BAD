"""SIEM transports: typed alerts out, no vendor loyalty in."""

from behavior_anomaly.config import SiemConfig
from behavior_anomaly.siem.base import SiemSink
from behavior_anomaly.siem.syslog import SyslogSink
from behavior_anomaly.siem.webhook import WebhookSink


def build_sink(config: SiemConfig) -> SiemSink:
    """Factory: config -> concrete sink. The one place that knows the kinds."""
    if config.kind == "webhook":
        if not config.endpoint:
            raise ValueError("A webhook sink without an endpoint is just wishful thinking.")
        return WebhookSink(config.endpoint, api_key=config.api_key)
    if config.kind == "syslog":
        return SyslogSink()
    raise ValueError(f"Unknown SIEM sink kind: {config.kind!r}. Try 'webhook' or 'syslog'.")
