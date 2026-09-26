from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Iterable

from .events import Event


class EventCollector(ABC):
    """Interface for safe endpoint collectors that emit normalized defensive events."""

    @abstractmethod
    def collect(self) -> Iterable[Event]:
        raise NotImplementedError


class EbpfCollectorSkeleton(EventCollector):
    """Placeholder boundary for a privileged Linux eBPF collector.

    Production implementations should keep kernel probes minimal, perform policy and
    enrichment in user space, and emit the same Event schema used by the simulator.
    """

    def collect(self) -> Iterable[Event]:
        raise RuntimeError("eBPF collection is architecture-ready but not implemented in this MVP")
