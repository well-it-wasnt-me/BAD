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


def test_syslog_sink_writes_structured_alert(caplog):
    with caplog.at_level(logging.WARNING, logger="behavior-anomaly"):
        SyslogSink().send(_alert())
    assert "SIEM_ALERT" in caplog.text
    # The payload must be parseable JSON, not vibes.
    payload = caplog.records[0].getMessage().split("SIEM_ALERT ", 1)[1]
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
