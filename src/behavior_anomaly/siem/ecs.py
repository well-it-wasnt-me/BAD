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

# Map our normalized event types onto ECS event.category values. Evidence is
# "type:action" strings, so the first token of each evidence line tells us
# what categories the window actually contained — better than a hard-coded
# list that misroutes alerts whose window was, say, only authentication.
_EVENT_TYPE_TO_ECS_CATEGORY: dict[str, str] = {
    "process": "process",
    "auth": "authentication",
    "session": "session",
    "file": "file",
    "network": "network",
    "shell": "process",
    "privilege": "authentication",
    "application": "application",
    "input": "process",
}


def to_ecs(alert: Alert) -> dict[str, object]:
    """Render an Alert as an ECS-shaped dict, ready for SIEM ingestion.

    `event.category` is derived from the alert's evidence (the event types
    actually present in the window) rather than hard-coded, so an alert whose
    window contained only auth events is categorized as authentication, not
    a fixed soup of every category. `event.type` reflects the verdict: an
    anomaly alert is an `info`-with-an-anomaly-kind, by ECS convention.
    """
    categories = _categories_from_evidence(alert.evidence)
    return {
        "@timestamp": alert.timestamp.isoformat(),
        "event": {
            "kind": "alert",
            "category": categories,
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


def _categories_from_evidence(evidence: list[str]) -> list[str]:
    """Distinct ECS categories for the event types in the evidence list."""
    seen: list[str] = []
    for item in evidence:
        event_type = item.split(":", 1)[0]
        category = _EVENT_TYPE_TO_ECS_CATEGORY.get(event_type)
        if category and category not in seen:
            seen.append(category)
    return seen or ["process"]


def _severity_number(severity: Severity) -> int:
    """Map our severity names onto the ECS event.severity numeric scale."""
    return _SEVERITY_NUMBERS[severity.value]
