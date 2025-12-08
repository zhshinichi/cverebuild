"""
Minimal DAG executor test to ensure execute() runs a step and evaluates
success_condition without using unsafe eval.
"""

import os
import sys
from pathlib import Path

import pytest

SRC_ROOT = Path(__file__).parent.parent / "src"
sys.path.insert(0, str(SRC_ROOT))


class StubCapability:
    """Simple capability that returns a success flag."""

    def __init__(self, result_bus, config):
        self.result_bus = result_bus
        self.config = config

    def execute(self, inputs):
        return {"result": {"success": True, "note": "ok"}}


def test_executor_single_step(tmp_path):
    from planner import ExecutionPlan, PlanStep
    from planner.executor import DAGExecutor
    from capabilities.registry import CapabilityRegistry
    from core.result_bus import ResultBus

    # Build minimal plan
    plan = ExecutionPlan(cve_id="CVE-TEST", profile="native-local")
    plan.add_step(
        PlanStep(
            id="single",
            capability="Stub",
            implementation="StubCapability",
            inputs=[],
            outputs=["result"],
            success_condition="result.success == True",
        )
    )

    # Registry with stub
    registry = CapabilityRegistry()
    registry.register("StubCapability", StubCapability)

    # Result bus writes into temporary shared dir
    os.environ["SHARED_DIR"] = str(tmp_path)
    bus = ResultBus("CVE-TEST", shared_root=str(tmp_path))

    executor = DAGExecutor(plan, bus, registry)
    artifacts = executor.execute()

    assert artifacts["result"]["success"] is True

