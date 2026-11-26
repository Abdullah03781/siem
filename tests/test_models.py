from dataclasses import FrozenInstanceError
from datetime import datetime, timezone

import pytest

from sentinel_siem.models import SecurityEvent, Severity


def test_security_event_to_dict() -> None:
    timestamp = datetime(2026, 11, 26, 20, 0, 0, tzinfo=timezone.utc)
    event = SecurityEvent(
        timestamp=timestamp,
        source="ssh",
        event_type="auth_failure",
        severity=Severity.MEDIUM,
        source_ip="192.168.1.10",
        username="admin",
        hostname="web-01",
        message="Failed password for invalid user admin",
        raw_log="Nov 26 20:00:00 web-01 sshd[123]: Failed password...",
        metadata={"port": 54322, "invalid_user": True},
    )

    data = event.to_dict()

    assert data == {
        "timestamp": "2026-11-26T20:00:00+00:00",
        "source": "ssh",
        "event_type": "auth_failure",
        "severity": "medium",
        "source_ip": "192.168.1.10",
        "username": "admin",
        "hostname": "web-01",
        "message": "Failed password for invalid user admin",
        "raw_log": "Nov 26 20:00:00 web-01 sshd[123]: Failed password...",
        "metadata": {"port": 54322, "invalid_user": True},
    }

    # Mutating the serialized copy must not mutate the original event
    data["metadata"]["port"] = 9999
    assert event.metadata["port"] == 54322


def test_security_event_is_immutable() -> None:
    event = SecurityEvent(
        timestamp=datetime(2026, 11, 26, 20, 0, 0, tzinfo=timezone.utc),
        source="ssh",
        event_type="auth_failure",
        severity=Severity.LOW,
    )

    with pytest.raises(FrozenInstanceError):
        event.severity = Severity.HIGH  # type: ignore[misc]


def test_rejects_naive_timestamp() -> None:
    naive_timestamp = datetime(2026, 11, 26, 20, 0, 0)

    with pytest.raises(ValueError, match="timezone-aware"):
        SecurityEvent(
            timestamp=naive_timestamp,
            source="ssh",
            event_type="auth_failure",
            severity=Severity.LOW,
        )


def test_rejects_blank_source_or_event_type() -> None:
    valid_ts = datetime(2026, 11, 26, 20, 0, 0, tzinfo=timezone.utc)

    with pytest.raises(ValueError, match="source"):
        SecurityEvent(
            timestamp=valid_ts,
            source="   ",
            event_type="auth_failure",
            severity=Severity.LOW,
        )

    with pytest.raises(ValueError, match="event_type"):
        SecurityEvent(
            timestamp=valid_ts,
            source="ssh",
            event_type="",
            severity=Severity.LOW,
        )
