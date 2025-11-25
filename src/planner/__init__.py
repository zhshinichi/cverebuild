"""Planner package defining classifier decisions and plan schema."""
from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional, Sequence


@dataclass
class ClassifierDecision:
    """Structured output describing the vulnerability portrait."""

    cve_id: str
    profile: str
    confidence: float
    required_capabilities: Sequence[str] = field(default_factory=tuple)
    resource_hints: Dict[str, object] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, object]:
        payload = asdict(self)
        payload["required_capabilities"] = list(self.required_capabilities)
        return payload


@dataclass
class PlanArtifact:
    name: str
    type: str
    description: Optional[str] = None


@dataclass
class PlanStep:
    id: str
    capability: str
    implementation: str
    inputs: List[str] = field(default_factory=list)
    outputs: List[str] = field(default_factory=list)
    requires: List[str] = field(default_factory=list)
    environment: Optional[str] = None
    retry: Optional[Dict[str, object]] = None
    config: Dict[str, object] = field(default_factory=dict)  # 添加 config 字段
    condition: Optional[str] = None  # 添加 condition 字段
    success_condition: Optional[str] = None
    
    # 为兼容性添加别名
    @property
    def dependencies(self) -> List[str]:
        """Alias for requires field for backward compatibility"""
        return self.requires
    
    @property
    def step_id(self) -> str:
        """Alias for id field for backward compatibility"""
        return self.id

    def to_dict(self) -> Dict[str, object]:
        data = {
            "id": self.id,
            "capability": self.capability,
            "implementation": self.implementation,
            "inputs": self.inputs,
            "outputs": self.outputs,
        }
        if self.requires:
            data["requires"] = self.requires
        if self.environment:
            data["environment"] = self.environment
        if self.retry:
            data["retry"] = self.retry
        if self.condition:
            data["if"] = self.condition
        if self.success_condition:
            data["success_condition"] = self.success_condition
        return data


@dataclass
class ExecutionPlan:
    cve_id: str
    profile: str
    schema: str = "cvegenie/plan@v0"
    artifacts: Dict[str, PlanArtifact] = field(default_factory=dict)
    steps: List[PlanStep] = field(default_factory=list)

    def register_artifact(self, artifact: PlanArtifact) -> None:
        self.artifacts[artifact.name] = artifact

    def add_step(self, step: PlanStep) -> None:
        self.steps.append(step)

    def to_dict(self) -> Dict[str, object]:
        return {
            "schema": self.schema,
            "cve_id": self.cve_id,
            "profile": self.profile,
            "artifacts": {
                name: {"type": artifact.type, "description": artifact.description}
                for name, artifact in self.artifacts.items()
            },
            "steps": [step.to_dict() for step in self.steps],
        }
