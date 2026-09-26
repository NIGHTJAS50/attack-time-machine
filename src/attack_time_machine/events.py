from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any
from uuid import uuid4


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


@dataclass(frozen=True)
class Event:
    event_type: str
    subject: str
    object: str
    data: dict[str, Any] = field(default_factory=dict)
    parents: tuple[str, ...] = ()
    timestamp: str = field(default_factory=utc_now)
    event_id: str = field(default_factory=lambda: f"evt:{uuid4().hex}")

    def to_dict(self) -> dict[str, Any]:
        return {
            "event_id": self.event_id,
            "timestamp": self.timestamp,
            "event_type": self.event_type,
            "subject": self.subject,
            "object": self.object,
            "parents": list(self.parents),
            "data": self.data,
        }

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "Event":
        required = {"event_id", "timestamp", "event_type", "subject", "object", "parents", "data"}
        missing = required - set(value)
        if missing:
            raise ValueError(f"event missing required fields: {sorted(missing)}")
        if not isinstance(value["parents"], list):
            raise ValueError("event parents must be a list")
        if not isinstance(value["data"], dict):
            raise ValueError("event data must be an object")
        return cls(
            event_id=str(value["event_id"]),
            timestamp=str(value["timestamp"]),
            event_type=str(value["event_type"]),
            subject=str(value["subject"]),
            object=str(value["object"]),
            parents=tuple(str(parent) for parent in value["parents"]),
            data=value["data"],
        )
