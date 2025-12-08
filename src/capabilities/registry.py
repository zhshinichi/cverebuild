"""
Capability Registry
集中管理所有能力适配器的注册和查找
"""

from typing import Dict, Type, Optional
from capabilities.base import Capability
from capabilities.adapters import (
    # 不需要 LLM 的纯功能性 Capability
    BrowserEnvironmentProvider,
    CVEInfoExtractor,
    SimpleValidator,
    HttpResponseVerifier,
    WebAppDeployer,
    # 需要 LLM 的 Agent 适配器
    KnowledgeBuilderAdapter,
    ConfigInferencerAdapter,
    PreReqBuilderAdapter,
    RepoBuilderAdapter,
    RepoCriticAdapter,
    ExploiterAdapter,
    ExploitCriticAdapter,
    CTFVerifierAdapter,
    SanityGuyAdapter,
    # 新的分拆 Agents
    ProjectSetupAdapter,
    ServiceStartAdapter,
    HealthCheckAdapter,
    # Freestyle 自由探索模式
    FreestyleAdapter,
)
from capabilities.verifier_adapters import (
    HttpResponseVerifierCapability,
    CookieVerifierCapability,
    FlagVerifierCapability,
    CombinedVerifierCapability,
)


class CapabilityRegistry:
    """
    能力注册表：管理能力名称到实现类的映射
    
    使用示例：
        registry = CapabilityRegistry()
        capability_cls = registry.get("collect-cve-info")
        capability = capability_cls(result_bus, config)
        result = capability.execute()
    """
    
    def __init__(self):
        self._registry: Dict[str, Type[Capability]] = {}
        self._register_defaults()
    
    def _register_defaults(self):
        """注册默认能力适配器"""
        
        # ============================================================
        # 不需要 LLM 的纯功能性 Capability
        # ============================================================
        self.register("browser-provision", BrowserEnvironmentProvider)
        self.register("BrowserEnvironmentProvider", BrowserEnvironmentProvider)
        self.register("BrowserEnvironmentCapability", BrowserEnvironmentProvider)  # distinct from orchestrator provider
        self.register("BrowserProvisioner", BrowserEnvironmentProvider)
        self.register("extract-cve-info", CVEInfoExtractor)
        self.register("CVEInfoExtractor", CVEInfoExtractor)
        self.register("simple-validate", SimpleValidator)
        self.register("SimpleValidator", SimpleValidator)
        # Canonical verifiers delegate to verification.strategies.*
        self.register("http-verify", HttpResponseVerifierCapability)
        self.register("HttpResponseVerifier", HttpResponseVerifierCapability)
        self.register("HttpVerifier", HttpResponseVerifierCapability)  # DAG 使用的名称
        self.register("CookieVerifier", CookieVerifierCapability)
        self.register("cookie-verify", CookieVerifierCapability)
        self.register("FlagVerifier", FlagVerifierCapability)
        self.register("combined-verify", CombinedVerifierCapability)
        self.register("CombinedVerifier", CombinedVerifierCapability)
        
        # Web 应用部署器（简化版）
        self.register("deploy-web-app", WebAppDeployer)
        self.register("WebAppDeployer", WebAppDeployer)
        
        # ============================================================
        # 需要 LLM 的 Agent 适配器
        # ============================================================
        
        # Native 漏洞能力（按能力名称注册）
        self.register("collect-cve-info", KnowledgeBuilderAdapter)
        self.register("analyze-prerequisites", PreReqBuilderAdapter)
        self.register("build-environment", RepoBuilderAdapter)
        self.register("critique-build", RepoCriticAdapter)
        self.register("generate-exploit", ExploiterAdapter)
        self.register("critique-exploit", ExploitCriticAdapter)
        self.register("verify-exploit", CTFVerifierAdapter)
        self.register("sanity-check", SanityGuyAdapter)
        
        # 也按实现类名注册（DAG 步骤使用 implementation 名称）
        self.register("CVEInfoGenerator", KnowledgeBuilderAdapter)
        self.register("InfoGenerator", KnowledgeBuilderAdapter)
        self.register("KnowledgeBuilder", KnowledgeBuilderAdapter)
        self.register("ConfigInferencer", ConfigInferencerAdapter)
        self.register("infer-config", ConfigInferencerAdapter)
        self.register("PreReqBuilder", PreReqBuilderAdapter)
        self.register("RepoBuilder", RepoBuilderAdapter)
        self.register("RepoCritic", RepoCriticAdapter)
        self.register("Exploiter", ExploiterAdapter)
        self.register("ExploitCritic", ExploitCriticAdapter)
        self.register("CTFVerifier", CTFVerifierAdapter)
        self.register("SanityGuy", SanityGuyAdapter)
        
        # ============================================================
        # 新的分拆 Agents (Web 环境部署流水线)
        # ============================================================
        self.register("project-setup", ProjectSetupAdapter)
        self.register("ProjectSetup", ProjectSetupAdapter)
        self.register("ProjectSetupAgent", ProjectSetupAdapter)
        
        self.register("service-start", ServiceStartAdapter)
        self.register("ServiceStart", ServiceStartAdapter)
        self.register("ServiceStartAgent", ServiceStartAdapter)
        
        self.register("health-check", HealthCheckAdapter)
        self.register("HealthCheck", HealthCheckAdapter)
        self.register("HealthCheckAgent", HealthCheckAdapter)
        
        # ============================================================
        # Freestyle 自由探索模式
        # ============================================================
        self.register("freestyle-explore", FreestyleAdapter)
        self.register("FreestyleExplorer", FreestyleAdapter)
        self.register("FreestyleAgent", FreestyleAdapter)
        
        # Web 漏洞能力（延迟导入避免循环依赖）
        try:
            from capabilities.adapters import WebDriverAdapter, WebExploitCriticAdapter
            self.register("provision-browser", BrowserEnvironmentProvider)  # 用不需要 LLM 的版本
            self.register("exploit-web-vuln", WebDriverAdapter)  # 这个需要 LLM
            self.register("verify-web-exploit", CTFVerifierAdapter)  # 先复用，后续可扩展
            self.register("critique-web-exploit", WebExploitCriticAdapter)
            # 按实现类名注册
            self.register("WebDriverAgent", WebDriverAdapter)  # 重要：DAG 使用这个名称
            self.register("WebExploiter", WebDriverAdapter)
            self.register("WebVerifier", CTFVerifierAdapter)
            self.register("HttpExploiter", WebDriverAdapter)
            self.register("HttpVerifier", CTFVerifierAdapter)
            self.register("WebExploitCritic", WebExploitCriticAdapter)
        except ImportError:
            pass  # Web 能力可选
        
        # Playwright 专用能力
        try:
            from capabilities.playwright_adapters import PlaywrightWebExploiter, PlaywrightVerifier
            self.register("exploit-web-vuln-playwright", PlaywrightWebExploiter)
            self.register("verify-web-playwright", PlaywrightVerifier)
        except ImportError:
            pass  # Playwright 可选
    
    def register(self, capability_name: str, capability_class: Type[Capability]):
        """
        注册能力实现
        
        Args:
            capability_name: 能力标识符（如 "collect-cve-info"）
            capability_class: 实现 Capability 协议的类
        """
        self._registry[capability_name] = capability_class
    
    def get(self, capability_name: str) -> Optional[Type[Capability]]:
        """
        获取能力实现类
        
        Args:
            capability_name: 能力标识符
        
        Returns:
            实现 Capability 协议的类，如果未注册则返回 None
        """
        return self._registry.get(capability_name)
    
    def list_capabilities(self) -> list[str]:
        """列出所有已注册的能力"""
        return list(self._registry.keys())
    
    def is_registered(self, capability_name: str) -> bool:
        """检查能力是否已注册"""
        return capability_name in self._registry


# 全局单例（可选）
_global_registry = None


def get_global_registry() -> CapabilityRegistry:
    """获取全局能力注册表单例"""
    global _global_registry
    if _global_registry is None:
        _global_registry = CapabilityRegistry()
    return _global_registry
