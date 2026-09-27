"""The detection engine.

Features plus model plus policy equals verdict. This module takes windows of
BehaviorEvents and returns either silence (everything looked normal) or a
typed, vendor-neutral Alert that any SIEM can consume without a translator.
"""

from collections.abc import Iterable, Sequence

from behavior_anomaly.config import DetectionConfig
from behavior_anomaly.detection.windowing import build_windows
from behavior_anomaly.features.base import FeatureExtractor
from behavior_anomaly.models.base import AnomalyModel
from behavior_anomaly.schema import Alert, BehaviorEvent, Severity

EVIDENCE_LIMIT = 5


class DetectionEngine:
    """Scores event windows and turns scores into Alerts.

    The engine knows nothing about collectors, storage or SIEMs. Give it a
    model, a feature extractor and a config and it will happily judge users
    until the heat death of the universe.
    """

    def __init__(self, model: AnomalyModel, features: FeatureExtractor, config: DetectionConfig):
        self.model = model
        self.features = features
        self.config = config

    def evaluate(self, events: Sequence[BehaviorEvent]) -> Alert | None:
        """Score one window of events.

        Returns None when the window is too small to mean anything or too
        boring to deserve an alert. Not every Tuesday needs an incident.
        """
        if len(events) < self.config.min_events:
            return None

        row = self.features.extract(events)
        score = self.model.score(row)
        if score < self.config.anomaly_threshold:
            return None

        last = events[-1]
        return Alert(
            score=score,
            severity=Severity.from_score(score),
            host_id=last.host_id,
            user_id=last.user_id,
            platform=last.platform,
            model=self.model.name,
            window_seconds=self.config.window_seconds,
            feature_vector=row,
            evidence=_summarize(events),
        )

    def detect(self, events: Iterable[BehaviorEvent]) -> list[Alert]:
        """Split an event stream into windows and evaluate each one."""
        alerts: list[Alert] = []
        for window in build_windows(events, self.config.window_seconds):
            alert = self.evaluate(window)
            if alert is not None:
                alerts.append(alert)
        return alerts


def _summarize(events: Sequence[BehaviorEvent], limit: int = EVIDENCE_LIMIT) -> list[str]:
    """Deduplicated "type:action" strings for the alert's evidence field.

    Kept short on purpose: evidence is a teaser for the analyst, not a
    replacement for the event store. Give them a reason to click through.
    """
    seen: list[str] = []
    for event in events:
        summary = f"{event.event_type.value}:{event.action}"
        if summary not in seen:
            seen.append(summary)
    return seen[:limit]
