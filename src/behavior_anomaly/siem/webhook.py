"""HTTP webhook sink.

POSTs each alert as JSON to any HTTP(S) endpoint. This is the least common
denominator of SIEM integration: Splunk HEC, Sentinel connectors, generic
SOAR webhooks, a Flask app someone in IT wrote in 2019, all of them speak
"give me a POST and I will figure it out".

The httpx.Client is injectable so tests can pass a MockTransport instead of
needing a live endpoint. Trust, but verify.

Delivery semantics: a lost alert is worse than a crashed loop, so we treat
anything that is not a clean 2xx as a failure and raise. 3xx redirects are
followed (capped) so a moved ingestion endpoint does not silently swallow
alerts. Transient 5xx/429 responses get bounded retry with backoff, because
SIEM ingestion endpoints are famous for momentary 503s.
"""

from __future__ import annotations

import logging
import time
from collections.abc import Callable

import httpx

from behavior_anomaly.schema import Alert
from behavior_anomaly.siem.base import SiemSink

logger = logging.getLogger("behavior_anomaly.siem.webhook")

# Retryable HTTP statuses: the SIEM is alive but asking us to try again.
_RETRYABLE_STATUS = frozenset({408, 425, 429, 500, 502, 503, 504})

# Default retry policy: a few tries with linear-ish backoff and a jitter cap.
# Keep it small: a webhook that needs 30 retries has bigger problems than ours.
DEFAULT_MAX_RETRIES = 3
DEFAULT_BACKOFF_SECONDS = 0.5


class WebhookSink(SiemSink):
    """Sends alerts to an HTTP endpoint, optionally with a Bearer token."""

    def __init__(
        self,
        endpoint: str,
        api_key: str | None = None,
        client: httpx.Client | None = None,
        timeout: float = 10.0,
        max_retries: int = DEFAULT_MAX_RETRIES,
        backoff_seconds: float = DEFAULT_BACKOFF_SECONDS,
        sleep_func: Callable[[float], None] = time.sleep,
    ) -> None:
        self.endpoint = endpoint
        self.api_key = api_key
        self._owns_client = client is None
        # follow_redirects so a moved ingestion endpoint still delivers. httpx
        # caps the hop count itself, so we do not reimplement a cap here.
        self._client = client or httpx.Client(timeout=timeout, follow_redirects=True)
        self.max_retries = max_retries
        self.backoff_seconds = backoff_seconds
        self._sleep = sleep_func

    def send(self, alert: Alert) -> None:
        """POST one alert. Non-2xx responses raise; a lost alert is worse
        than a crashed loop, and the caller deserves to know the truth."""
        headers = {"Authorization": f"Bearer {self.api_key}"} if self.api_key else {}
        body = alert.model_dump(mode="json")

        attempt = 0
        while True:
            response = self._client.post(self.endpoint, json=body, headers=headers)
            if response.is_success:
                return
            # raise_for_status handles 4xx/5xx; we only retry the transient ones.
            if response.status_code in _RETRYABLE_STATUS and attempt < self.max_retries:
                wait = self.backoff_seconds * (attempt + 1)
                logger.warning(
                    "Webhook returned %d for alert (attempt %d/%d); retrying in %.2fs",
                    response.status_code,
                    attempt + 1,
                    self.max_retries,
                    wait,
                )
                self._sleep(wait)
                attempt += 1
                continue
            response.raise_for_status()
            # raise_for_status should always raise for non-2xx, but be explicit
            # so a future httpx quirk cannot silently drop the alert.
            raise httpx.HTTPStatusError(
                f"webhook returned {response.status_code} for alert", request=response.request, response=response
            )

    def close(self) -> None:
        """Release the underlying connection pool. Only closes a client we
        created; an injected client is the caller's responsibility."""
        if self._owns_client:
            self._client.close()
