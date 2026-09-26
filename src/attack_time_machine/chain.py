from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

from .events import Event

GENESIS_HASH = "0" * 64


def canonical_json(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def sha256_hex(value: object) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def hmac_hex(key: str, record_hash: str) -> str:
    return hmac.new(key.encode("utf-8"), record_hash.encode("utf-8"), hashlib.sha256).hexdigest()


@dataclass(frozen=True)
class Record:
    sequence: int
    previous_hash: str
    event: Event
    event_hash: str
    record_hash: str
    hmac: str | None = None

    def to_dict(self) -> dict[str, object]:
        value: dict[str, object] = {
            "sequence": self.sequence,
            "previous_hash": self.previous_hash,
            "event": self.event.to_dict(),
            "event_hash": self.event_hash,
            "record_hash": self.record_hash,
        }
        if self.hmac is not None:
            value["hmac"] = self.hmac
        return value

    @classmethod
    def from_dict(cls, value: dict[str, object]) -> "Record":
        return cls(
            sequence=int(value["sequence"]),
            previous_hash=str(value["previous_hash"]),
            event=Event.from_dict(value["event"]),  # type: ignore[arg-type]
            event_hash=str(value["event_hash"]),
            record_hash=str(value["record_hash"]),
            hmac=str(value["hmac"]) if "hmac" in value else None,
        )


def build_record(sequence: int, previous_hash: str, event: Event, key: str | None = None) -> Record:
    event_hash = sha256_hex(event.to_dict())
    record_payload = {
        "sequence": sequence,
        "previous_hash": previous_hash,
        "event_hash": event_hash,
        "event": event.to_dict(),
    }
    record_hash = sha256_hex(record_payload)
    seal = hmac_hex(key, record_hash) if key else None
    return Record(sequence, previous_hash, event, event_hash, record_hash, seal)


class ChainWriter:
    def __init__(self, path: Path, key: str | None = None) -> None:
        self.path = path
        self.key = key
        self._sequence = 0
        self._previous_hash = GENESIS_HASH
        if path.exists() and path.stat().st_size:
            records = read_records(path)
            verify_records(records, key=key)
            last = records[-1]
            self._sequence = last.sequence + 1
            self._previous_hash = last.record_hash

    def append(self, event: Event) -> Record:
        record = build_record(self._sequence, self._previous_hash, event, self.key)
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(canonical_json(record.to_dict()) + "\n")
        self._sequence += 1
        self._previous_hash = record.record_hash
        return record

    def append_many(self, events: Iterable[Event]) -> list[Record]:
        return [self.append(event) for event in events]


def read_records(path: Path) -> list[Record]:
    records: list[Record] = []
    with path.open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                records.append(Record.from_dict(json.loads(line)))
            except Exception as exc:
                raise ValueError(f"invalid record on line {line_number}: {exc}") from exc
    return records


def verify_records(records: list[Record], key: str | None = None) -> None:
    previous_hash = GENESIS_HASH
    seen: set[str] = set()
    for expected_sequence, record in enumerate(records):
        if record.sequence != expected_sequence:
            raise ValueError(f"sequence mismatch at record {expected_sequence}")
        if record.previous_hash != previous_hash:
            raise ValueError(f"hash chain break at sequence {record.sequence}")
        if record.event.event_id in seen:
            raise ValueError(f"duplicate event id: {record.event.event_id}")
        seen.add(record.event.event_id)
        expected = build_record(record.sequence, record.previous_hash, record.event, key)
        if record.event_hash != expected.event_hash:
            raise ValueError(f"event hash mismatch at sequence {record.sequence}")
        if record.record_hash != expected.record_hash:
            raise ValueError(f"record hash mismatch at sequence {record.sequence}")
        if key and record.hmac != expected.hmac:
            raise ValueError(f"hmac mismatch at sequence {record.sequence}")
        previous_hash = record.record_hash
