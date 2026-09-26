"""Elastic Common Schema mapping.

ECS is the closest thing our industry has to a lingua franca, so we render our
vendor-neutral Alert into an ECS-flavored dict. "ECS-flavored" because we are
not Elastic, we just play them on TV. Any field we do not fill, the receiving
SIEM can enrich on its own time.
"""

from behavior_anomaly.schema import Alert, Severity

_SEVERITY_NUMBERS: dict[str, int] = {
    "low": 25,
    "medium": 50,
    "high": 75,
    "critical": 100,
}


def to_ecs(alert: Alert) -> dict:
    """Render an Alert as an ECS-shaped dict, ready for SIEM ingestion."""
    return {
        "@timestamp": alert.timestamp.isoformat(),
        "event": {
            "kind": "alert",
            "category": ["authentication", "process", "network"],
            "type": ["info"],
            "severity": _severity_number(alert.severity),
        },
        "user": {"id": alert.user_id},
        "host": {"id": alert.host_id},
        "labels": {
            "platform": alert.platform.value,
            "rule": alert.rule,
            "model": alert.model,
            "window_seconds": str(alert.window_seconds),
        },
        "behavior": {
            "anomaly_score": round(alert.score, 4),
            "features": alert.feature_vector,
            "evidence": alert.evidence,
        },
        "rule": {"name": alert.rule},
    }


def _severity_number(severity: Severity) -> int:
    """Map our severity names onto the ECS event.severity numeric scale."""
    return _SEVERITY_NUMBERS[severity.value]
