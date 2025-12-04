"""
BrainAgent - 大脑 Agent，负责分析和规划

职责:
1. 分析漏洞类型和特点
2. 制定高层攻击策略
3. 生成具体执行计划给 FreestyleAgent
4. 分析执行失败的原因（仅一次，不重试）

设计原则:
- 不直接执行工具，只做分析和规划
- 使用更强的模型进行推理
- 输出结构化的执行计划
"""

import json
from typing import Optional, Dict, Any, List
from dataclasses import dataclass, field, asdict

from agentlib import AgentWithHistory


@dataclass
class AttackPlan:
    """攻击计划数据结构"""
    vulnerability_type: str  # 漏洞类型: xss, sqli, rce, etc.
    attack_surface: str  # 攻击面描述
    prerequisites: List[str]  # 前置条件
    exploitation_steps: List[str]  # 利用步骤
    recommended_tools: List[str]  # 推荐工具
    payload_examples: List[str]  # payload 示例
    success_indicators: List[str]  # 成功标志
    potential_obstacles: List[str]  # 可能的障碍
    
    def to_dict(self) -> dict:
        return asdict(self)
    
    def to_prompt(self) -> str:
        """转换为可以传递给 FreestyleAgent 的 prompt"""
        return f"""
## 攻击计划

### 漏洞类型
{self.vulnerability_type}

### 攻击面
{self.attack_surface}

### 前置条件（必须先完成）
{chr(10).join(f'{i+1}. {step}' for i, step in enumerate(self.prerequisites))}

### 利用步骤
{chr(10).join(f'{i+1}. {step}' for i, step in enumerate(self.exploitation_steps))}

### 推荐工具
{', '.join(self.recommended_tools)}

### Payload 示例
{chr(10).join(f'- {p}' for p in self.payload_examples)}

### 成功标志（如何判断漏洞已触发）
{chr(10).join(f'- {s}' for s in self.success_indicators)}

### 可能的障碍
{chr(10).join(f'- {o}' for o in self.potential_obstacles)}
"""


@dataclass
class FailureAnalysis:
    """失败分析数据结构"""
    failure_category: str  # environment_issue, incomplete_execution, vulnerability_not_applicable, unknown
    root_cause: str  # 根本原因
    missing_steps: List[str]  # 缺失的步骤
    is_vulnerability_disproven: bool  # 是否证明漏洞不存在
    recommendation: str  # 建议
    
    def to_dict(self) -> dict:
        return asdict(self)


class BrainAgent(AgentWithHistory[dict, str]):
    """
    大脑 Agent - 负责分析漏洞并生成执行计划
    
    不执行任何工具，只做推理和规划
    """
    
    __SYSTEM_PROMPT_TEMPLATE__ = 'brain/brain.system.j2'
    __USER_PROMPT_TEMPLATE__ = 'brain/brain.user.j2'
    __LLM_MODEL__ = 'gpt-4o'  # 使用强模型进行分析
    __MAX_TOOL_ITERATIONS__ = 1  # 不需要迭代，一次输出即可
    
    # Agent 属性
    CVE_ID: Optional[str] = None
    CVE_ENTRY: Optional[Dict[str, Any]] = None
    CVE_KNOWLEDGE: Optional[str] = None
    MODE: str = "plan"  # plan 或 analyze_failure
    EXECUTION_RESULT: Optional[Dict[str, Any]] = None  # 失败分析时需要
    
    def __init__(
        self, 
        cve_id: str = None,
        cve_entry: dict = None,
        cve_knowledge: str = None,
        mode: str = "plan",
        execution_result: dict = None,
        **kwargs
    ):
        super().__init__(**kwargs)
        
        self.CVE_ID = cve_id
        self.CVE_ENTRY = cve_entry or {}
        self.CVE_KNOWLEDGE = cve_knowledge or ""
        self.MODE = mode
        self.EXECUTION_RESULT = execution_result
    
    def get_input_vars(self, *args, **kwargs) -> dict:
        """提供模板变量"""
        vars = super().get_input_vars(*args, **kwargs)
        vars.update(
            CVE_ID=self.CVE_ID,
            CVE_ENTRY=self.CVE_ENTRY,
            CVE_KNOWLEDGE=self.CVE_KNOWLEDGE,
            CVE_ENTRY_JSON=json.dumps(self.CVE_ENTRY, indent=2, ensure_ascii=False)[:5000] if self.CVE_ENTRY else '{}',
            MODE=self.MODE,
            EXECUTION_RESULT=json.dumps(self.EXECUTION_RESULT, indent=2, ensure_ascii=False) if self.EXECUTION_RESULT else 'null',
        )
        return vars
    
    def get_available_tools(self):
        """BrainAgent 不使用工具"""
        return []
    
    def parse_plan_response(self, response: str) -> AttackPlan:
        """从 LLM 响应解析攻击计划"""
        try:
            # 尝试从 JSON 块提取
            if "```json" in response:
                json_start = response.find("```json") + 7
                json_end = response.find("```", json_start)
                json_str = response[json_start:json_end].strip()
                data = json.loads(json_str)
            elif "{" in response:
                # 尝试找到 JSON 对象
                json_start = response.find("{")
                json_end = response.rfind("}") + 1
                json_str = response[json_start:json_end]
                data = json.loads(json_str)
            else:
                raise ValueError("No JSON found in response")
            
            return AttackPlan(
                vulnerability_type=data.get("vulnerability_type", "unknown"),
                attack_surface=data.get("attack_surface", ""),
                prerequisites=data.get("prerequisites", []),
                exploitation_steps=data.get("exploitation_steps", []),
                recommended_tools=data.get("recommended_tools", []),
                payload_examples=data.get("payload_examples", []),
                success_indicators=data.get("success_indicators", []),
                potential_obstacles=data.get("potential_obstacles", []),
            )
        except Exception as e:
            # 如果解析失败，返回一个基础计划
            return AttackPlan(
                vulnerability_type="unknown",
                attack_surface="Unable to parse",
                prerequisites=["Analyze vulnerability manually"],
                exploitation_steps=["Follow CVE description"],
                recommended_tools=["run_command", "http_request"],
                payload_examples=[],
                success_indicators=["Vulnerability triggered"],
                potential_obstacles=[f"Plan parsing failed: {str(e)}"],
            )
    
    def parse_failure_response(self, response: str) -> FailureAnalysis:
        """从 LLM 响应解析失败分析"""
        try:
            if "```json" in response:
                json_start = response.find("```json") + 7
                json_end = response.find("```", json_start)
                json_str = response[json_start:json_end].strip()
                data = json.loads(json_str)
            elif "{" in response:
                json_start = response.find("{")
                json_end = response.rfind("}") + 1
                json_str = response[json_start:json_end]
                data = json.loads(json_str)
            else:
                raise ValueError("No JSON found in response")
            
            return FailureAnalysis(
                failure_category=data.get("failure_category", "unknown"),
                root_cause=data.get("root_cause", "Unknown"),
                missing_steps=data.get("missing_steps", []),
                is_vulnerability_disproven=data.get("is_vulnerability_disproven", False),
                recommendation=data.get("recommendation", ""),
            )
        except Exception as e:
            return FailureAnalysis(
                failure_category="unknown",
                root_cause=f"Analysis parsing failed: {str(e)}",
                missing_steps=[],
                is_vulnerability_disproven=False,
                recommendation="Manual review required",
            )


def create_attack_plan(cve_id: str, cve_entry: dict, cve_knowledge: str = "") -> AttackPlan:
    """
    便捷函数：创建攻击计划
    
    :param cve_id: CVE ID
    :param cve_entry: CVE 条目数据
    :param cve_knowledge: 已有的漏洞知识
    :return: AttackPlan 对象
    """
    agent = BrainAgent(
        cve_id=cve_id,
        cve_entry=cve_entry,
        cve_knowledge=cve_knowledge,
        mode="plan",
    )
    
    # 运行 agent 获取响应
    response = agent.run({})
    
    # 解析响应为 AttackPlan
    return agent.parse_plan_response(response)


def analyze_failure(
    cve_id: str, 
    cve_entry: dict, 
    execution_result: dict,
    cve_knowledge: str = ""
) -> FailureAnalysis:
    """
    便捷函数：分析执行失败原因
    
    :param cve_id: CVE ID
    :param cve_entry: CVE 条目数据
    :param execution_result: FreestyleAgent 的执行结果
    :param cve_knowledge: 已有的漏洞知识
    :return: FailureAnalysis 对象
    """
    agent = BrainAgent(
        cve_id=cve_id,
        cve_entry=cve_entry,
        cve_knowledge=cve_knowledge,
        mode="analyze_failure",
        execution_result=execution_result,
    )
    
    # 运行 agent 获取响应
    response = agent.run({})
    
    # 解析响应为 FailureAnalysis
    return agent.parse_failure_response(response)
