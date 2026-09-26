from pathlib import Path

from attack_time_machine.chain import ChainWriter, read_records
from attack_time_machine.cli import main
from attack_time_machine.graph import build_graph
from attack_time_machine.query import filter_records
from attack_time_machine.simulator import incident_dry_run


def write_demo(path: Path) -> None:
    ChainWriter(path, key="secret").append_many(incident_dry_run())


def test_graph_reconstructs_roots_and_edges(tmp_path: Path) -> None:
    path = tmp_path / "incident.jsonl"
    write_demo(path)

    graph = build_graph(read_records(path))

    assert graph.roots() == ["evt:login"]
    assert ("evt:touch1", "evt:alert") in graph.edges
    assert graph.orphan_edges == []


def test_query_filters_file_writes(tmp_path: Path) -> None:
    path = tmp_path / "incident.jsonl"
    write_demo(path)

    records = filter_records(read_records(path), event_type="file_write")

    assert [record.event.event_id for record in records] == ["evt:touch1", "evt:touch2"]


def test_cli_simulate_and_verify(tmp_path: Path, capsys) -> None:
    path = tmp_path / "incident.jsonl"

    assert main(["simulate", "--out", str(path), "--key", "secret"]) == 0
    assert main(["verify", str(path), "--key", "secret"]) == 0

    out = capsys.readouterr().out
    assert "wrote 7 records" in out
    assert "verified 7 records" in out


def test_cli_graph_dot(tmp_path: Path, capsys) -> None:
    path = tmp_path / "incident.jsonl"
    write_demo(path)

    assert main(["graph", str(path), "--format", "dot"]) == 0

    assert "digraph attack_time_machine" in capsys.readouterr().out
