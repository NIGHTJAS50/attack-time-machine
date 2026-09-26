from __future__ import annotations

import time
from datetime import datetime
from typing import Iterator

from .chain import Record


def parse_ts(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def replay_lines(records: list[Record], speed: float = 1.0, sleep: bool = True) -> Iterator[str]:
    previous = None
    for record in records:
        current = parse_ts(record.event.timestamp)
        if previous is not None and sleep:
            delay = max((current - previous).total_seconds() / speed, 0)
            time.sleep(min(delay, 5.0))
        previous = current
        yield format_record(record)


def format_record(record: Record) -> str:
    event = record.event
    parents = ",".join(event.parents) if event.parents else "-"
    return (
        f"{record.sequence:04d} {event.timestamp} {event.event_type:<16} "
        f"{event.subject} -> {event.object} parents={parents}"
    )
