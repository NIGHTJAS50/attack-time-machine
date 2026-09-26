from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .chain import ChainWriter, read_records, verify_records
from .graph import build_graph
from .query import filter_records
from .replay import format_record, replay_lines
from .simulator import SCENARIOS


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="atm", description="Attack Time Machine forensic timeline CLI")
    sub = parser.add_subparsers(dest="command", required=True)

    simulate = sub.add_parser("simulate", help="write a safe demo incident timeline")
    simulate.add_argument("--scenario", choices=sorted(SCENARIOS), default="ransomware-dry-run")
    simulate.add_argument("--out", required=True, type=Path)
    simulate.add_argument("--key", help="optional HMAC key")

    verify = sub.add_parser("verify", help="verify a tamper-evident timeline")
    verify.add_argument("path", type=Path)
    verify.add_argument("--key", help="optional HMAC key")

    timeline = sub.add_parser("timeline", help="print timeline rows")
    timeline.add_argument("path", type=Path)
    timeline.add_argument("--type")
    timeline.add_argument("--subject")
    timeline.add_argument("--object-contains")

    query = sub.add_parser("query", help="filter events")
    query.add_argument("path", type=Path)
    query.add_argument("--type")
    query.add_argument("--subject")
    query.add_argument("--object-contains")

    replay = sub.add_parser("replay", help="replay timeline in event order")
    replay.add_argument("path", type=Path)
    replay.add_argument("--speed", type=float, default=1.0)
    replay.add_argument("--no-sleep", action="store_true")

    graph = sub.add_parser("graph", help="export causal graph")
    graph.add_argument("path", type=Path)
    graph.add_argument("--format", choices=["json", "dot"], default="json")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "simulate":
            writer = ChainWriter(args.out, key=args.key)
            records = writer.append_many(SCENARIOS[args.scenario]())
            print(f"wrote {len(records)} records to {args.out}")
            return 0

        if args.command == "verify":
            records = read_records(args.path)
            verify_records(records, key=args.key)
            print(f"verified {len(records)} records")
            return 0

        if args.command in {"timeline", "query"}:
            records = filter_records(read_records(args.path), args.type, args.subject, args.object_contains)
            for record in records:
                print(format_record(record))
            return 0

        if args.command == "replay":
            for line in replay_lines(read_records(args.path), speed=args.speed, sleep=not args.no_sleep):
                print(line, flush=True)
            return 0

        if args.command == "graph":
            graph = build_graph(read_records(args.path))
            print(graph.to_dot() if args.format == "dot" else graph.to_json())
            return 0
    except Exception as exc:
        print(f"atm: {exc}", file=sys.stderr)
        return 1
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
