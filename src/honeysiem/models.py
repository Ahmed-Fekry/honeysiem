"""Core data types shared by parsers, storage, detections and reporting."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime

EVENT_TYPES = (
    "connect",
    "login_failed",
    "login_success",
    "command",
    "download",
    "disconnect",
)

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


@dataclass(frozen=True)
class Event:
    """A single normalized security event, independent of the log source."""

    timestamp: datetime  # always timezone-aware UTC
    src_ip: str
    event_type: str
    src_port: int | None = None
    username: str | None = None
    password: str | None = None
    command: str | None = None
    url: str | None = None
    session: str | None = None
    source: str = "unknown"


@dataclass(frozen=True)
class Technique:
    """A MITRE ATT&CK technique."""

    id: str
    name: str
    tactic: str

    @property
    def url(self) -> str:
        return "https://attack.mitre.org/techniques/" + self.id.replace(".", "/") + "/"


@dataclass
class Alert:
    """A detection result, aggregated per rule and source IP."""

    rule_id: str
    title: str
    severity: str
    technique: Technique
    src_ip: str
    first_seen: datetime
    last_seen: datetime
    count: int
    evidence: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "severity": self.severity,
            "technique_id": self.technique.id,
            "technique_name": self.technique.name,
            "tactic": self.technique.tactic,
            "technique_url": self.technique.url,
            "src_ip": self.src_ip,
            "first_seen": self.first_seen.isoformat(),
            "last_seen": self.last_seen.isoformat(),
            "count": self.count,
            "evidence": list(self.evidence),
        }
