"""HTTP webhook sink.

POSTs each alert as JSON to any HTTP(S) endpoint. This is the least common
denominator of SIEM integration: Splunk HEC, Sentinel connectors, generic
SOAR webhooks, a Flask app someone in IT wrote in 2019, all of them speak
"give me a POST and I will figure it out".

The httpx.Client is injectable so tests can pass a MockTransport instead of
needing a live endpoint. Trust, but verify.
"""

import httpx

from behavior_anomaly.schema import Alert
from behavior_anomaly.siem.base import SiemSink


class WebhookSink(SiemSink):
    """Sends alerts to an HTTP endpoint, optionally with a Bearer token."""

    def __init__(
        self,
        endpoint: str,
        api_key: str | None = None,
        client: httpx.Client | None = None,
        timeout: float = 10.0,
    ) -> None:
        self.endpoint = endpoint
        self.api_key = api_key
        self._client = client or httpx.Client(timeout=timeout)

    def send(self, alert: Alert) -> None:
        """POST one alert. Non-2xx responses raise; a lost alert is worse
        than a crashed loop, and the caller deserves to know the truth."""
        headers = {"Authorization": f"Bearer {self.api_key}"} if self.api_key else {}
        response = self._client.post(self.endpoint, json=alert.model_dump(mode="json"), headers=headers)
        response.raise_for_status()

    def close(self) -> None:
        """Release the underlying connection pool."""
        self._client.close()
