"""Utilities for constructing execution DAGs from classifier decisions."""
from __future__ import annotations

import os
from typing import Dict, Iterable, Optional

from planner import ClassifierDecision, ExecutionPlan, PlanArtifact, PlanStep


DEFAULT_ARTIFACTS = {
    "cve_info": PlanArtifact(name="cve_info", type="json", description="LLM summary of CVE entry"),
    "repo_state": PlanArtifact(name="repo_state", type="dir", description="Prepared vulnerable environment"),
    "exploit_log": PlanArtifact(name="exploit_log", type="text", description="Exploiter output"),
    "verification": PlanArtifact(name="verification", type="json", description="Verifier metadata"),
}


class PlanBuilder:
    """Generates an execution plan based on a classifier decision and profile defaults."""

    def __init__(self, profile_overrides: Optional[Dict[str, Dict[str, object]]] = None) -> None:
        self.profile_overrides = profile_overrides or {}

    def build(self, decision: ClassifierDecision) -> ExecutionPlan:
        plan = ExecutionPlan(cve_id=decision.cve_id, profile=decision.profile)
        for artifact in DEFAULT_ARTIFACTS.values():
            plan.register_artifact(artifact)

        for step in self._materialize_steps(decision):
            plan.add_step(step)

        return plan
    
    @classmethod
    def from_yaml(cls, profile_name: str, cve_id: str, cve_entry: dict) -> ExecutionPlan:
        """
        从 YAML 配置文件加载执行计划
        
        Args:
            profile_name: Profile 名称（如 "native-local"）
            cve_id: CVE ID
            cve_entry: CVE 数据字典
        
        Returns:
            ExecutionPlan 实例
        """
        import yaml
        
        # 查找 profile 文件
        profile_path = os.path.join(os.path.dirname(__file__), '..', '..', 'profiles', f'{profile_name}.yaml')
        
        if not os.path.exists(profile_path):
            raise FileNotFoundError(f"Profile not found: {profile_path}")
        
        with open(profile_path, 'r', encoding='utf-8') as f:
            profile_config = yaml.safe_load(f)
        
        # 创建执行计划
        plan = ExecutionPlan(cve_id=cve_id, profile=profile_name)
        
        # 注册产物
        for artifact_name in profile_config.get('artifacts', []):
            plan.register_artifact(PlanArtifact(
                name=artifact_name,
                type='auto',
                description=f"Artifact from profile: {artifact_name}"
            ))
        
        # 添加步骤
        for step_config in profile_config.get('steps', []):
            step = PlanStep(
                id=step_config['step_id'],
                capability=step_config['capability'],
                implementation=step_config.get('capability'),  # 默认用 capability 名称
                inputs=step_config.get('dependencies', []),
                outputs=step_config.get('outputs', []),
                config=step_config.get('config', {}),
                condition=None
            )
            plan.add_step(step)
        
        return plan

    # ------------------------------------------------------------------
    def _materialize_steps(self, decision: ClassifierDecision) -> Iterable[PlanStep]:
        profile = decision.profile
        overrides = self.profile_overrides.get(profile, {})
        if profile == "web-basic":
            yield from self._web_basic_steps(overrides)
        elif profile == "cloud-config":
            yield from self._cloud_steps(overrides)
        elif profile == "freestyle":
            yield from self._freestyle_steps(overrides)
        else:
            yield from self._native_steps(overrides)

    def _native_steps(self, overrides: Dict[str, object]):
        yield PlanStep(
            id="collect-info",
            capability="InfoGenerator",
            implementation=overrides.get("InfoGenerator", "CVEInfoGenerator"),
            inputs=["cve_id"],
            outputs=["cve_info"],
            environment="control",
        )
        yield PlanStep(
            id="prepare-env",
            capability="EnvironmentProvisioner",
            implementation=overrides.get("EnvironmentProvisioner", "RepoBuilder"),
            inputs=["cve_info"],
            outputs=["repo_state"],
            requires=["collect-info"],
            environment="builder",
        )
        yield PlanStep(
            id="exploit",
            capability="ExploitExecutor",
            implementation=overrides.get("ExploitExecutor", "Exploiter"),
            inputs=["repo_state", "cve_info"],
            outputs=["exploit_log"],
            requires=["prepare-env"],
            environment="target",
        )
        yield PlanStep(
            id="verify",
            capability="FlagVerifier",
            implementation=overrides.get("FlagVerifier", "CTFVerifier"),
            inputs=["exploit_log"],
            outputs=["verification"],
            requires=["exploit"],
            environment="target",
            success_condition="verification.flag_found == true",
        )

    def _web_basic_steps(self, overrides: Dict[str, object]):
        """Web 漏洞专用步骤：包含环境部署、浏览器配置和漏洞利用。"""
        yield PlanStep(
            id="collect-info",
            capability="InfoGenerator",
            implementation=overrides.get("InfoGenerator", "KnowledgeBuilder"),
            inputs=["cve_id", "cve_entry"],
            outputs=["cve_knowledge"],
            environment="control",
        )
        # 环境部署步骤：使用 PreReqBuilder 和 WebAppDeployer
        yield PlanStep(
            id="analyze-prereqs",
            capability="PreReqAnalyzer",
            implementation=overrides.get("PreReqAnalyzer", "PreReqBuilder"),
            inputs=["cve_knowledge", "cve_entry"],
            outputs=["prerequisites"],
            requires=["collect-info"],
            environment="builder",
        )
        yield PlanStep(
            id="deploy-env",
            capability="EnvironmentDeployer",
            implementation=overrides.get("EnvironmentDeployer", "WebAppDeployer"),  # 使用 WebAppDeployer 简化部署
            inputs=["cve_id", "cve_knowledge", "cve_entry", "prerequisites"],
            outputs=["build_result"],
            requires=["analyze-prereqs"],
            environment="builder",
        )
        yield PlanStep(
            id="health-check",
            capability="HealthCheck",
            implementation=overrides.get("HealthCheck", "HealthCheck"),  # 单独健康检查，阻断后续步骤
            inputs=["build_result"],
            outputs=["health_result"],
            requires=["deploy-env"],
            environment="builder",
            success_condition="health_result.http_code in [200, 301, 302, 307, 404] or health_result.healthy == True",
        )
        yield PlanStep(
            id="browser-provision",
            capability="BrowserProvisioner",
            implementation=overrides.get("BrowserProvisioner", "BrowserEnvironmentProvider"),
            inputs=["build_result"],
            outputs=["browser_config"],
            requires=["health-check"],
            environment="browser",
        )
        yield PlanStep(
            id="exploit-web",
            capability="WebExploiter",
            implementation=overrides.get("WebExploiter", "WebDriverAgent"),
            inputs=["browser_config", "cve_knowledge", "cve_id"],
            outputs=["web_exploit_result"],
            requires=["browser-provision"],
            environment="browser",
        )
        yield PlanStep(
            id="verify-web",
            capability="WebVerifier",
            implementation=overrides.get("WebVerifier", "CombinedVerifier"),
            inputs=["web_exploit_result"],
            outputs=["verification_result"],
            requires=["exploit-web"],
            environment="browser",
            success_condition="verification_result.success == True",
        )

    def _cloud_steps(self, overrides: Dict[str, object]):
        yield PlanStep(
            id="collect-info",
            capability="InfoGenerator",
            implementation=overrides.get("InfoGenerator", "CVEInfoGenerator"),
            inputs=["cve_id"],
            outputs=["cve_info"],
        )
        yield PlanStep(
            id="provision-cloud",
            capability="CloudEnvProvisioner",
            implementation=overrides.get("CloudEnvProvisioner", "RepoBuilder"),
            inputs=["cve_info"],
            outputs=["repo_state"],
            requires=["collect-info"],
            environment="cloud",
        )
        yield PlanStep(
            id="exploit-api",
            capability="ApiExploiter",
            implementation=overrides.get("ApiExploiter", "Exploiter"),
            inputs=["repo_state", "cve_info"],
            outputs=["exploit_log"],
            requires=["provision-cloud"],
            environment="cloud",
        )
        yield PlanStep(
            id="verify-log",
            capability="LogVerifier",
            implementation=overrides.get("LogVerifier", "SanityGuy"),
            inputs=["exploit_log"],
            outputs=["verification"],
            requires=["exploit-api"],
            environment="cloud",
            success_condition="verification.anomaly_detected == true",
        )

    def _freestyle_steps(self, overrides: Dict[str, object]):
        """Freestyle 自由探索模式：简化的两步流程。
        
        1. 收集 CVE 信息 + 部署策略分析
        2. FreestyleAgent 使用明确的部署策略完成复现
        """
        yield PlanStep(
            id="collect-info",
            capability="InfoGenerator",
            implementation=overrides.get("InfoGenerator", "KnowledgeBuilder"),
            inputs=["cve_id", "cve_entry"],
            outputs=["cve_knowledge", "deployment_strategy"],  # 新增 deployment_strategy 输出
            environment="control",
        )
        yield PlanStep(
            id="freestyle-explore",
            capability="FreestyleExplorer",
            implementation=overrides.get("FreestyleExplorer", "FreestyleAgent"),
            inputs=["cve_id", "cve_entry", "cve_knowledge", "deployment_strategy"],  # 新增 deployment_strategy 输入
            outputs=["freestyle_result", "verification_result"],
            requires=["collect-info"],
            environment="target",
            success_condition="verification_result.passed == true",
        )
