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
    """Preferred interface for capabilities."""

    def execute(self, inputs: Dict[str, Any]) -> Dict[str, Any]:
        ...

    # Backward compatibility: some legacy implementations may expose run(context).
    # Planner executor will try execute() first, then fall back to run().
    def run(self, context: CapabilityContext) -> Dict[str, Any]:  # pragma: no cover
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
