from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from typing import Any


class Severity(StrEnum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass(frozen=True)
class SecurityEvent:
    timestamp: datetime
    source: str
    event_type: str
    severity: Severity
    source_ip: str | None = None
    username: str | None = None
    hostname: str | None = None
    message: str = ""
    raw_log: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.timestamp.tzinfo is None or self.timestamp.utcoffset() is None:
            raise ValueError("timestamp must be timezone-aware")
        if not self.source.strip():
            raise ValueError("source must not be empty")
        if not self.event_type.strip():
            raise ValueError("event_type must not be empty")

    def to_dict(self) -> dict[str, Any]:
        """Convert the event into a JSON-friendly dictionary."""
        return {
            "timestamp": self.timestamp.isoformat(),
            "source": self.source,
            "event_type": self.event_type,
            "severity": self.severity.value,
            "source_ip": self.source_ip,
            "username": self.username,
            "hostname": self.hostname,
            "message": self.message,
            "raw_log": self.raw_log,
            "metadata": dict(self.metadata),
        }