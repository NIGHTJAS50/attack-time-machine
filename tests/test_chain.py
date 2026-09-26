from pathlib import Path

import pytest

from attack_time_machine.chain import ChainWriter, read_records, verify_records
from attack_time_machine.simulator import ransomware_dry_run


def test_chain_round_trip_with_hmac(tmp_path: Path) -> None:
    path = tmp_path / "incident.jsonl"
    writer = ChainWriter(path, key="secret")
    writer.append_many(ransomware_dry_run())

    records = read_records(path)

    assert len(records) == 7
    verify_records(records, key="secret")
    assert records[0].previous_hash == "0" * 64
    assert records[-1].hmac is not None


def test_tampering_is_detected(tmp_path: Path) -> None:
    path = tmp_path / "incident.jsonl"
    ChainWriter(path, key="secret").append_many(ransomware_dry_run())
    text = path.read_text(encoding="utf-8")
    path.write_text(text.replace("workstation-7", "workstation-8", 1), encoding="utf-8")

    with pytest.raises(ValueError, match="hash|hmac"):
        verify_records(read_records(path), key="secret")


def test_wrong_hmac_key_fails(tmp_path: Path) -> None:
    path = tmp_path / "incident.jsonl"
    ChainWriter(path, key="secret").append_many(ransomware_dry_run())

    with pytest.raises(ValueError, match="hmac"):
        verify_records(read_records(path), key="wrong")
