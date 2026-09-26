from __future__ import annotations

from .chain import Record


def filter_records(
    records: list[Record],
    event_type: str | None = None,
    subject: str | None = None,
    object_contains: str | None = None,
) -> list[Record]:
    result: list[Record] = []
    for record in records:
        event = record.event
        if event_type and event.event_type != event_type:
            continue
        if subject and event.subject != subject:
            continue
        if object_contains and object_contains not in event.object:
            continue
        result.append(record)
    return result
