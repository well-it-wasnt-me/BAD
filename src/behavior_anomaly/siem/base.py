"""SIEM sink contract.

A sink is where alerts go to be triaged. Or ignored. We do not judge, we just
need a standard interface so webhook, syslog and whatever transport comes next
are interchangeable.
"""

from abc import ABC, abstractmethod

from behavior_anomaly.schema import Alert


class SiemSink(ABC):
    """Anything that can accept an Alert and ship it somewhere."""

    @abstractmethod
    def send(self, alert: Alert) -> None:
        raise NotImplementedError
