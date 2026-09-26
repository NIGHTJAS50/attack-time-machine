from __future__ import annotations

import json
from dataclasses import dataclass

from .chain import Record


@dataclass(frozen=True)
class CausalGraph:
    nodes: dict[str, dict[str, object]]
    edges: list[tuple[str, str]]
    orphan_edges: list[tuple[str, str]]

    def roots(self) -> list[str]:
        children = {child for _, child in self.edges}
        return [event_id for event_id in self.nodes if event_id not in children]

    def to_json(self) -> str:
        return json.dumps(
            {"nodes": self.nodes, "edges": self.edges, "orphan_edges": self.orphan_edges},
            indent=2,
            sort_keys=True,
        )

    def to_dot(self) -> str:
        lines = ["digraph attack_time_machine {", "  rankdir=LR;"]
        for event_id, node in self.nodes.items():
            label = f"{node['event_type']}\\n{node['subject']} -> {node['object']}"
            lines.append(f'  "{event_id}" [label="{label}"];')
        for parent, child in self.edges:
            lines.append(f'  "{parent}" -> "{child}";')
        for parent, child in self.orphan_edges:
            lines.append(f'  "{parent}" -> "{child}" [style=dashed,color=red,label="missing"];')
        lines.append("}")
        return "\n".join(lines)


def build_graph(records: list[Record]) -> CausalGraph:
    nodes = {
        record.event.event_id: {
            "sequence": record.sequence,
            "timestamp": record.event.timestamp,
            "event_type": record.event.event_type,
            "subject": record.event.subject,
            "object": record.event.object,
            "data": record.event.data,
        }
        for record in records
    }
    edges: list[tuple[str, str]] = []
    orphan_edges: list[tuple[str, str]] = []
    for record in records:
        child = record.event.event_id
        for parent in record.event.parents:
            if parent in nodes:
                edges.append((parent, child))
            else:
                orphan_edges.append((parent, child))
    return CausalGraph(nodes, edges, orphan_edges)
