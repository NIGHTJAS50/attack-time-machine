from __future__ import annotations

from datetime import datetime, timedelta, timezone

from .events import Event


def ts(base: datetime, seconds: int) -> str:
    return (base + timedelta(seconds=seconds)).isoformat(timespec="microseconds").replace("+00:00", "Z")


def incident_dry_run() -> list[Event]:
    base = datetime(2026, 1, 1, 12, 0, tzinfo=timezone.utc)
    e1 = Event(
        event_id="evt:login",
        timestamp=ts(base, 0),
        event_type="session_start",
        subject="user:analyst",
        object="host:workstation-7",
        data={"source": "simulator", "safe": True},
    )
    e2 = Event(
        event_id="evt:shell",
        timestamp=ts(base, 4),
        event_type="process_start",
        subject="proc:sshd:1442",
        object="proc:bash:1510",
        parents=(e1.event_id,),
        data={"cmdline": "bash", "uid": 1000},
    )
    e3 = Event(
        event_id="evt:enumerate",
        timestamp=ts(base, 9),
        event_type="process_start",
        subject="proc:bash:1510",
        object="proc:find:1519",
        parents=(e2.event_id,),
        data={"cmdline": "find /home/analyst/Documents -type f", "safe_simulation": True},
    )
    e4 = Event(
        event_id="evt:touch1",
        timestamp=ts(base, 13),
        event_type="file_write",
        subject="proc:find:1519",
        object="/home/analyst/Documents/report.docx.atm-demo",
        parents=(e3.event_id,),
        data={"bytes": 128, "operation": "simulated-marker-write"},
    )
    e5 = Event(
        event_id="evt:touch2",
        timestamp=ts(base, 15),
        event_type="file_write",
        subject="proc:find:1519",
        object="/home/analyst/Documents/budget.xlsx.atm-demo",
        parents=(e3.event_id,),
        data={"bytes": 128, "operation": "simulated-marker-write"},
    )
    e6 = Event(
        event_id="evt:beacon",
        timestamp=ts(base, 18),
        event_type="network_connect",
        subject="proc:bash:1510",
        object="tcp://203.0.113.10:443",
        parents=(e2.event_id,),
        data={"reserved_test_net": True},
    )
    e7 = Event(
        event_id="evt:alert",
        timestamp=ts(base, 19),
        event_type="alert",
        subject="detector:burst-file-writes",
        object="host:workstation-7",
        parents=(e4.event_id, e5.event_id, e6.event_id),
        data={"severity": "high", "reason": "file write burst plus unusual outbound connection"},
    )
    return [e1, e2, e3, e4, e5, e6, e7]


SCENARIOS = {"incident-dry-run": incident_dry_run}
