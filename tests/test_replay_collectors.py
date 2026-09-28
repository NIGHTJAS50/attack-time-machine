import pytest

from attack_time_machine.collectors import EbpfCollectorSkeleton
from attack_time_machine.events import Event
from attack_time_machine.replay import format_record, parse_ts, replay_lines
from attack_time_machine.chain import ChainWriter, read_records


def test_replay_formats_parent_links_without_sleep(tmp_path):
    path = tmp_path / "timeline.jsonl"
    ChainWriter(path).append_many([
        Event("process_start", "proc:one", "binary", timestamp="2026-01-01T00:00:00Z"),
        Event("file_write", "proc:one", "/tmp/a", parents=("evt:one",), timestamp="2026-01-01T00:00:01Z"),
    ])

    records = read_records(path)
    lines = list(replay_lines(records, speed=10, sleep=False))

    assert len(lines) == 2
    assert "parents=-" in lines[0]
    assert "parents=evt:one" in lines[1]
    assert parse_ts("2026-01-01T00:00:00Z").year == 2026
    assert format_record(records[0]).startswith("0000 ")


def test_ebpf_boundary_is_explicitly_unimplemented():
    with pytest.raises(RuntimeError, match="not implemented"):
        list(EbpfCollectorSkeleton().collect())


def test_event_rejects_invalid_serialized_shape():
    with pytest.raises(ValueError, match="parents"):
        Event.from_dict({
            "event_id": "evt:1",
            "timestamp": "2026-01-01T00:00:00Z",
            "event_type": "alert",
            "subject": "sensor",
            "object": "host",
            "parents": "evt:0",
            "data": {},
        })