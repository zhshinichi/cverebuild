"""LLM-enhanced vulnerability classifier with better accuracy."""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Dict, Optional

from agentlib import LLMFunction
from planner import ClassifierDecision
from planner.classifier import VulnerabilityClassifier, ClassifierConfig


CLASSIFICATION_PROMPT = """你是一个专业的安全漏洞分类专家。请根据以下 CVE 信息，判断这个漏洞属于哪种类型。

## CVE 信息
- CVE ID: {{ cve_id }}
- 描述: {{ description }}
- CWE: {{ cwe }}
- 补丁内容（如果有）: {{ patch_summary }}

## 分类选项

1. **native-local**: 本地代码漏洞
   - Python/Java/C++ 等语言的库漏洞
   - 需要本地安装包并运行 PoC 脚本
   - 例如：DoS、命令注入、反序列化、路径遍历等
   - 关键特征：通过 pip/npm/maven 安装，运行 Python 脚本复现

2. **web-basic**: Web 应用漏洞
   - 需要启动完整的 Web 服务器（Flask/Django/Express/MLflow 等）
   - 通过 HTTP 请求与服务器交互来触发漏洞
   - 例如：SQL注入、认证绕过、SSRF、文件上传等
   - 关键特征：需要启动并运行一个 Web 服务

3. **freestyle**: 自由探索类漏洞 ⭐ 推荐用于复杂场景
   - JavaScript/前端库漏洞（XSS、prototype pollution、window.opener 泄露）
   - 需要创建 HTML 页面 + 浏览器测试的漏洞
   - 配置类漏洞
   - 其他不适合固定流程的漏洞
   - 关键特征：需要灵活组合多种工具，没有固定的复现模式

4. **cloud-config**: 云配置漏洞
   - 云服务 API 配置错误
   - 例如：AWS IAM 配置错误、S3 权限问题等

5. **iot-firmware**: IoT/固件漏洞
   - 需要固件仿真或硬件设备

## 分析要点

1. 看**漏洞复现方式**：
   - 如果是"安装 Python 包，运行代码触发" → native-local
   - 如果是"启动 Web 服务，发送 HTTP 请求" → web-basic
   - 如果是"创建 HTML 页面，浏览器打开测试" → freestyle
   - 如果是"npm/JS 库漏洞，需要浏览器环境" → freestyle

2. 看**受影响的组件**：
   - Python 库 → native-local
   - Web 框架应用 (Flask/Django) → web-basic  
   - JavaScript/前端库 (smartbanner.js, dompurify) → freestyle

3. 当不确定时，**优先选择 freestyle**，因为它最灵活

## 输出格式

请严格按以下格式输出：

<classification>
<profile>选择一个: native-local / web-basic / freestyle / cloud-config / iot-firmware</profile>
<confidence>0.0-1.0 之间的置信度</confidence>
<reasoning>简要说明分类理由</reasoning>
<reproduction_method>简要描述复现方法</reproduction_method>
</classification>
"""


@dataclass 
class LLMClassifierConfig(ClassifierConfig):
    """Configuration for LLM-enhanced classifier."""
    model: str = "gpt-4o-mini"  # 使用轻量级模型节省成本
    temperature: float = 0.0
    use_llm: bool = True
    fallback_to_rules: bool = True  # 如果 LLM 失败，回退到规则


class LLMVulnerabilityClassifier(VulnerabilityClassifier):
    """
    LLM 增强的漏洞分类器
    
    相比规则匹配，LLM 可以：
    1. 理解上下文（如 "KnowledgeBaseWebReader" 虽然包含 "Web" 但是是一个 Python 类）
    2. 分析补丁内容来判断漏洞类型
    3. 结合 CWE 和描述进行综合判断
    """
    
    def __init__(self, config: Optional[LLMClassifierConfig] = None) -> None:
        self.config = config or LLMClassifierConfig()
        super().__init__(self.config)
        
    def classify(self, cve_id: str, cve_entry: Dict[str, object], profile_override: Optional[str] = None) -> ClassifierDecision:
        """分类漏洞，优先使用 LLM，失败时回退到规则。"""
        
        if profile_override:
            # 如果有显式覆盖，直接使用
            return super().classify(cve_id, cve_entry, profile_override)
        
        if not self.config.use_llm:
            return super().classify(cve_id, cve_entry)
        
        try:
            return self._classify_with_llm(cve_id, cve_entry)
        except Exception as e:
            print(f"⚠️ LLM classification failed: {e}")
            if self.config.fallback_to_rules:
                print("📋 Falling back to rule-based classification")
                return super().classify(cve_id, cve_entry)
            raise
    
    def _classify_with_llm(self, cve_id: str, cve_entry: Dict[str, object]) -> ClassifierDecision:
        """使用 LLM 进行分类。"""
        
        # 准备输入
        description = cve_entry.get("description", "No description available")
        cwe_list = cve_entry.get("cwe", [])
        cwe_str = ", ".join([f"{c.get('id', '')} - {c.get('value', '')}" for c in cwe_list]) if cwe_list else "Unknown"
        
        # 提取补丁摘要
        patch_summary = self._extract_patch_summary(cve_entry)
        
        # 调用 LLM
        classifier_llm = LLMFunction.create(
            CLASSIFICATION_PROMPT,
            model=self.config.model,
            temperature=self.config.temperature
        )
        
        response = classifier_llm(
            cve_id=cve_id,
            description=description,
            cwe=cwe_str,
            patch_summary=patch_summary
        )
        
        # 解析响应
        result = self._parse_classification_response(response, cve_id, cve_entry)
        
        print(f"🎯 LLM Classification for {cve_id}:")
        print(f"   Profile: {result.profile}")
        print(f"   Confidence: {result.confidence}")
        
        return result
    
    def _extract_patch_summary(self, cve_entry: Dict[str, object]) -> str:
        """提取补丁内容摘要。"""
        patches = cve_entry.get("patch_commits", [])
        if not patches:
            return "No patch information available"
        
        summaries = []
        for patch in patches[:2]:  # 只取前 2 个补丁
            content = patch.get("content", "")
            # 提取文件名
            filenames = re.findall(r'Filename: ([^\n]+)', content)
            if filenames:
                summaries.append(f"Files changed: {', '.join(filenames[:3])}")
            # 提取前 200 字符
            if content:
                summaries.append(content[:200] + "...")
        
        return "\n".join(summaries) if summaries else "No patch content"
    
    def _parse_classification_response(self, response: str, cve_id: str, cve_entry: Dict[str, object]) -> ClassifierDecision:
        """解析 LLM 响应。"""
        
        # 提取 profile - 添加 freestyle 支持
        profile_match = re.search(r'<profile>\s*(native-local|web-basic|freestyle|cloud-config|iot-firmware)\s*</profile>', response, re.IGNORECASE)
        profile = profile_match.group(1).lower() if profile_match else self.config.default_profile
        
        # 提取 confidence
        confidence_match = re.search(r'<confidence>\s*([\d.]+)\s*</confidence>', response)
        try:
            confidence = float(confidence_match.group(1)) if confidence_match else 0.7
            confidence = min(max(confidence, 0.0), 1.0)  # 限制在 0-1 范围
        except ValueError:
            confidence = 0.7
        
        # 提取 reasoning（用于调试）
        reasoning_match = re.search(r'<reasoning>(.*?)</reasoning>', response, re.DOTALL)
        if reasoning_match:
            print(f"   Reasoning: {reasoning_match.group(1).strip()[:100]}...")
        
        # 构建决策
        capabilities = self._infer_capabilities(profile)
        hints = self._infer_resource_hints(cve_entry)
        
        # 根据 profile 调整 hints
        if profile == "native-local":
            hints["needs_browser"] = False
        elif profile == "web-basic":
            hints["needs_browser"] = True
        
        return ClassifierDecision(
            cve_id=cve_id,
            profile=profile,
            confidence=confidence,
            required_capabilities=capabilities,
            resource_hints=hints,
        )


# 便捷函数
def classify_vulnerability(cve_id: str, cve_entry: Dict[str, object], use_llm: bool = True) -> ClassifierDecision:
    """
    便捷函数：分类一个漏洞。
    
    Args:
        cve_id: CVE ID
        cve_entry: CVE 数据字典
        use_llm: 是否使用 LLM（默认 True）
    
    Returns:
        ClassifierDecision 对象
    """
    config = LLMClassifierConfig(use_llm=use_llm)
    classifier = LLMVulnerabilityClassifier(config)
    return classifier.classify(cve_id, cve_entry)
