"""Canonical capability contracts used by the planner."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Protocol


@dataclass
class CapabilityContext:
    cve_id: str
    artifacts: Dict[str, Any]
    resource_hints: Dict[str, Any]


class Capability(Protocol):
    def run(self, context: CapabilityContext) -> Dict[str, Any]:
        ...


class EnvironmentProvisioner(Capability, Protocol):
    ...


class SourcePreparer(Capability, Protocol):
    ...


class ExploitExecutor(Capability, Protocol):
    ...


class Verifier(Capability, Protocol):
    ...


class FixPlanner(Capability, Protocol):
    ...
