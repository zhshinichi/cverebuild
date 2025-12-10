"""DAG 执行器：按依赖顺序调度 plan.json 中的步骤。"""
from __future__ import annotations

import json
import os
from typing import Any, Dict, List, Optional, Set

from planner import ExecutionPlan, PlanStep
from core.result_bus import ResultBus


class StepExecutionError(Exception):
    """步骤执行失败异常。"""
    pass


class DAGExecutor:
    """读取 ExecutionPlan 并按拓扑顺序执行步骤。"""

    def __init__(self, plan: ExecutionPlan, result_bus: ResultBus, capability_registry: Optional[Dict[str, Any]] = None) -> None:
        """
        Args:
            plan: 待执行的计划
            result_bus: 结果总线，用于发布事件和存储产物
            capability_registry: 能力实现映射 {implementation_name: callable}
        """
        self.plan = plan
        self.result_bus = result_bus
        self.capability_registry = capability_registry or {}
        self.artifacts: Dict[str, Any] = {}  # 运行时产物缓存
        self.completed_steps: Set[str] = set()
        self.total_cost: float = 0.0  # 累计成本

    def execute(self) -> Dict[str, Any]:
        """执行整个 DAG，返回最终产物字典。"""
        self.result_bus.publish_event("plan_start", data={"profile": self.plan.profile})
        
        try:
            ordered_steps = self._topological_sort()
            for step in ordered_steps:
                if not self._check_condition(step):
                    self.result_bus.publish_event("step_skipped", step_id=step.id, data={"reason": "条件不满足"})
                    continue

                self._execute_step(step)
                self.completed_steps.add(step.id)

            self.result_bus.publish_event("plan_complete", data={"artifacts": list(self.artifacts.keys())})
            return self.artifacts

        except Exception as exc:
            self.result_bus.publish_event("plan_failed", data={"error": str(exc)})
            raise

    def _topological_sort(self) -> List[PlanStep]:
        """拓扑排序，确保依赖关系正确。"""
        steps_dict = {step.id: step for step in self.plan.steps}
        in_degree = {step.id: len(step.requires) for step in self.plan.steps}
        queue = [step_id for step_id, degree in in_degree.items() if degree == 0]
        sorted_steps = []

        while queue:
            current_id = queue.pop(0)
            sorted_steps.append(steps_dict[current_id])

            # 减少后续节点的入度
            for step in self.plan.steps:
                if current_id in step.requires:
                    in_degree[step.id] -= 1
                    if in_degree[step.id] == 0:
                        queue.append(step.id)

        if len(sorted_steps) != len(self.plan.steps):
            raise ValueError("Plan 包含循环依赖，无法执行")

        return sorted_steps

    def _check_condition(self, step: PlanStep) -> bool:
        """检查步骤的执行条件（if 字段）。"""
        if not step.condition:
            return True

        # 简单实现：支持 "!artifacts.xxx" 语法
        if step.condition.startswith("!artifacts."):
            artifact_name = step.condition[len("!artifacts."):]
            return artifact_name not in self.artifacts

        # 未来可扩展支持更复杂的表达式
        return True

    def _execute_step(self, step: PlanStep) -> None:
        """Execute a single step."""
        self.result_bus.publish_event("step_start", step_id=step.id, data={"capability": step.capability})

        try:
            # Get capability implementation class
            capability_class = self.capability_registry.get(step.implementation)
            if not capability_class:
                raise StepExecutionError(f"Implementation not found: {step.implementation}")

            # Prepare input parameters
            inputs = {name: self.artifacts.get(name) for name in step.inputs}
            
            # Instantiate capability (pass result_bus and step config)
            capability_instance = capability_class(self.result_bus, step.config or {})

            # Execute capability (prefer execute; fallback to run for older implementations)
            if hasattr(capability_instance, "execute"):
                outputs = capability_instance.execute(inputs)
            elif hasattr(capability_instance, "run"):
                outputs = capability_instance.run(inputs)
            else:
                raise StepExecutionError(f"Capability {step.implementation} has no execute/run method")

            # Store output artifacts
            for output_name in step.outputs:
                if output_name in outputs:
                    self.artifacts[output_name] = outputs[output_name]
                    self.result_bus.store_artifact(step.id, output_name, outputs[output_name], artifact_type="json")

            # Check success condition
            if step.success_condition:
                if not self._evaluate_success_condition(step.success_condition, outputs):
                    raise StepExecutionError(f"Step {step.id} failed success condition: {step.success_condition}")

            self.result_bus.publish_event("step_complete", step_id=step.id, data={"outputs": list(outputs.keys())})

        except Exception as exc:
            self.result_bus.publish_event("step_failed", step_id=step.id, data={"error": str(exc)})
            if not step.retry or step.retry.get("max", 0) <= 0:
                raise StepExecutionError(f"Step {step.id} execution failed: {exc}") from exc

            # TODO: Implement retry logic
            raise

    def _evaluate_success_condition(self, condition: str, outputs: Dict[str, Any]) -> bool:
        """Safely evaluate a simple success condition without exposing builtins."""
        import ast
        import re

        # Normalize booleans
        condition = condition.replace(" true", " True").replace(" false", " False")
        condition = condition.replace("=true", "=True").replace("=false", "=False")

        # Convert dotted access to dict-style: verification_result.passed -> verification_result['passed']
        def dot_to_bracket(match):
            parts = match.group(0).split('.')
            result = parts[0]
            for part in parts[1:]:
                result += f"['{part}']"
            return result

        condition_expr = re.sub(r'\b(\w+(?:\.\w+)+)\b', dot_to_bracket, condition)

        allowed_nodes = (
            ast.Expression,
            ast.BoolOp,
            ast.UnaryOp,
            ast.Compare,
            ast.Name,
            ast.Load,
            ast.Subscript,
            ast.Constant,
            ast.And,
            ast.Or,
            ast.Not,
            ast.Eq,
            ast.NotEq,
            ast.Gt,
            ast.GtE,
            ast.Lt,
            ast.LtE,
            ast.In,        # allow membership checks like "x in [1, 2]"
            ast.NotIn,
            ast.List,      # allow literal containers in conditions
            ast.Tuple,
        )

        try:
            tree = ast.parse(condition_expr, mode="eval")
            for node in ast.walk(tree):
                if not isinstance(node, allowed_nodes):
                    raise ValueError(f"Unsafe expression element: {ast.dump(node)}")

            namespace = {"__builtins__": {}}
            namespace.update(outputs)
            return bool(eval(compile(tree, "<condition>", "eval"), namespace, {}))
        except Exception as exc:
            print(f"[DEBUG] Condition evaluation error: {exc}")
            return False

    @classmethod
    def from_plan_file(cls, plan_path: str, result_bus: ResultBus, capability_registry: Optional[Dict[str, Any]] = None) -> DAGExecutor:
        """从 plan.json 文件加载并创建执行器。"""
        with open(plan_path, "r", encoding="utf-8") as f:
            plan_dict = json.load(f)

        # 重建 ExecutionPlan 对象（简化版本，实际需要完整反序列化）
        from planner import ExecutionPlan, PlanStep, PlanArtifact

        plan = ExecutionPlan(
            cve_id=plan_dict["cve_id"],
            profile=plan_dict["profile"],
            schema=plan_dict.get("schema", "cvegenie/plan@v0"),
        )

        for name, artifact_dict in plan_dict.get("artifacts", {}).items():
            plan.register_artifact(PlanArtifact(
                name=name,
                type=artifact_dict["type"],
                description=artifact_dict.get("description"),
            ))

        for step_dict in plan_dict.get("steps", []):
            plan.add_step(PlanStep(
                id=step_dict["id"],
                capability=step_dict["capability"],
                implementation=step_dict["implementation"],
                inputs=step_dict.get("inputs", []),
                outputs=step_dict.get("outputs", []),
                requires=step_dict.get("requires", []),
                environment=step_dict.get("environment"),
                retry=step_dict.get("retry"),
                condition=step_dict.get("if"),
                success_condition=step_dict.get("success_condition"),
            ))

        return cls(plan, result_bus, capability_registry)
