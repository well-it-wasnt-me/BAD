"""Tests for the SIEM layer: sinks, factory and the ECS translator."""

import json
import logging

import httpx
import pytest

from behavior_anomaly.config import SiemConfig
from behavior_anomaly.schema import Alert, Platform, Severity
from behavior_anomaly.siem import build_sink
from behavior_anomaly.siem.base import SiemSink
from behavior_anomaly.siem.ecs import to_ecs
from behavior_anomaly.siem.syslog import SyslogSink
from behavior_anomaly.siem.webhook import WebhookSink


def _alert() -> Alert:
    return Alert(
        score=0.9,
        severity=Severity.CRITICAL,
        host_id="host-1",
        user_id="alice",
        platform=Platform.LINUX,
        model="isolation_forest",
        window_seconds=300,
        feature_vector={"event_count": 42.0},
        evidence=["process:exec"],
    )


def test_syslog_sink_writes_structured_alert():
    # The syslog sink does not propagate to the root logger (it owns its own
    # handler so the daemon's basicConfig does not double-log every alert),
    # so we capture from the named logger directly instead of via caplog.
    records: list[logging.LogRecord] = []
    sink = SyslogSink(logger_name="behavior-anomaly.test-capture")
    sink.logger.addHandler(type("H", (logging.Handler,), {"emit": lambda self, r: records.append(r)})())
    try:
        sink.send(_alert())
    finally:
        sink.logger.handlers.clear()
    assert records, "SyslogSink must actually emit a record"
    payload = records[0].getMessage().split("SIEM_ALERT ", 1)[1]
    assert json.loads(payload)["score"] == 0.9


def test_webhook_sink_posts_the_alert():
    captured: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["url"] = str(request.url)
        captured["headers"] = dict(request.headers)
        captured["body"] = json.loads(request.content)
        return httpx.Response(200)

    sink = WebhookSink(
        "https://siem.example.test/hook",
        api_key="secret-token",
        client=httpx.Client(transport=httpx.MockTransport(handler)),
    )
    sink.send(_alert())
    sink.close()

    assert captured["url"] == "https://siem.example.test/hook"
    assert captured["headers"]["authorization"] == "Bearer secret-token"
    assert captured["body"]["score"] == 0.9
    assert captured["body"]["user_id"] == "alice"


def test_webhook_sink_raises_on_server_error():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(500)

    sink = WebhookSink(
        "https://siem.example.test/hook",
        client=httpx.Client(transport=httpx.MockTransport(handler)),
        max_retries=0,
        sleep_func=lambda _s: None,
    )
    # A lost alert is worse than a raised exception. Silence is for libraries.
    with pytest.raises(httpx.HTTPStatusError):
        sink.send(_alert())
    sink.close()


def test_build_sink_kinds():
    assert isinstance(build_sink(SiemConfig(kind="syslog")), SyslogSink)
    assert isinstance(build_sink(SiemConfig(kind="webhook", endpoint="https://x.test")), WebhookSink)


def test_build_sink_rejects_unknown_kind():
    with pytest.raises(ValueError, match="Unknown SIEM sink"):
        build_sink(SiemConfig(kind="carrier-pigeon"))


def test_build_sink_rejects_webhook_without_endpoint():
    with pytest.raises(ValueError, match="wishful thinking"):
        build_sink(SiemConfig(kind="webhook", endpoint=None))


def test_ecs_mapping_shape():
    ecs = to_ecs(_alert())
    assert ecs["@timestamp"]
    assert ecs["event"]["kind"] == "alert"
    assert ecs["event"]["severity"] == 100
    assert ecs["user"]["id"] == "alice"
    assert ecs["host"]["id"] == "host-1"
    assert ecs["labels"]["platform"] == "linux"
    assert ecs["behavior"]["anomaly_score"] == 0.9
    assert ecs["rule"]["name"] == "user_behavior_anomaly"


def test_sinks_are_interchangeable():
    # The contract is the point: any sink must accept the same Alert.
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200)

    sinks: list[SiemSink] = [
        SyslogSink(),
        WebhookSink("https://x.test", client=httpx.Client(transport=httpx.MockTransport(handler))),
    ]
    for sink in sinks:
        sink.send(_alert())  # no explosion, no translation layer needed
    sinks[1].close()


# ----------------------------------------------------- new behavior coverage


def test_webhook_sink_follows_redirect_to_success():
    # A 302 to the real ingestion path must deliver the alert, not silently
    # drop it. raise_for_status alone lets 3xx pass quietly; the explicit
    # is_success check plus follow_redirects is what keeps alerts alive.
    calls: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(str(request.url))
        if request.url.path == "/hook":
            return httpx.Response(302, headers={"Location": "https://siem.example.test/ingest"})
        return httpx.Response(200)

    sink = WebhookSink(
        "https://siem.example.test/hook",
        client=httpx.Client(transport=httpx.MockTransport(handler), follow_redirects=True),
    )
    sink.send(_alert())  # must not raise
    sink.close()
    assert "/ingest" in calls[-1]


def test_webhook_sink_retries_then_succeeds_on_transient_503():
    # A momentary 503 from the SIEM should not lose the alert for the cycle.
    attempts = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        attempts["n"] += 1
        return httpx.Response(503) if attempts["n"] < 3 else httpx.Response(200)

    sink = WebhookSink(
        "https://siem.example.test/hook",
        client=httpx.Client(transport=httpx.MockTransport(handler)),
        max_retries=3,
        backoff_seconds=0,
        sleep_func=lambda _s: None,
    )
    sink.send(_alert())  # third attempt succeeds
    sink.close()
    assert attempts["n"] == 3


def test_webhook_sink_gives_up_after_max_retries():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(503)

    sink = WebhookSink(
        "https://siem.example.test/hook",
        client=httpx.Client(transport=httpx.MockTransport(handler)),
        max_retries=2,
        backoff_seconds=0,
        sleep_func=lambda _s: None,
    )
    with pytest.raises(httpx.HTTPStatusError):
        sink.send(_alert())
    sink.close()


def test_webhook_sink_no_api_key_omits_authorization_header():
    captured: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["headers"] = dict(request.headers)
        return httpx.Response(200)

    sink = WebhookSink(
        "https://siem.example.test/hook",
        client=httpx.Client(transport=httpx.MockTransport(handler)),
    )
    sink.send(_alert())
    sink.close()
    assert "authorization" not in captured["headers"]


def test_syslog_sink_has_a_handler_attached():
    # "syslog" must actually wire up a handler, not just log into the void.
    sink = SyslogSink(logger_name="behavior-anomaly.test-syslog")
    assert sink.logger.handlers, "SyslogSink must attach a real handler"
    sink.logger.handlers.clear()  # avoid leaking handlers across tests


def test_ecs_category_derived_from_evidence():
    alert = _alert()
    alert = alert.model_copy(update={"evidence": ["auth:login", "network:connect"]})
    ecs = to_ecs(alert)
    assert ecs["event"]["category"] == ["authentication", "network"]
