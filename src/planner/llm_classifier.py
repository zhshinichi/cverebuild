"""LLM-enhanced vulnerability classifier with better accuracy.

增强功能：
1. 读取 CVE 原始 JSON 文件获取更多上下文（references、affected products 等）
2. 可选的网络搜索能力（GitHub API、NVD）
3. 多步推理和二次验证机制
4. 更丰富的分类提示词
"""
from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any

from agentlib import LLMFunction
from planner import ClassifierDecision
from planner.classifier import VulnerabilityClassifier, ClassifierConfig


# ============================================================
# 增强版分类提示词 - 使用更丰富的上下文信息
# ============================================================

CLASSIFICATION_PROMPT = """你是一个专业的安全漏洞分类专家。请根据以下 CVE 信息，判断这个漏洞属于哪种类型。

## CVE 基本信息
- **CVE ID**: {{ cve_id }}
- **描述**: {{ description }}
- **CWE**: {{ cwe }}

## 产品信息
- **产品名称**: {{ product_name }}
- **厂商**: {{ vendor }}
- **受影响版本**: {{ affected_versions }}

## 额外上下文（如果有）
- **源码仓库**: {{ repository_url }}
- **参考链接类型**: {{ reference_types }}
- **补丁文件**: {{ patch_files }}
- **技术指标**: {{ tech_indicators }}

## 分类选项

1. **native-local**: 本地代码漏洞
   - Python/Java/C++/.NET 等语言的**类库/包**漏洞
   - 需要本地安装包并运行 PoC 脚本
   - 例如：DoS、命令注入、反序列化、路径遍历等
   - 关键特征：通过 pip/npm/maven/nuget 安装，运行测试脚本复现
   - **重要**：如果是 NuGet/PyPI/npm 类库（不是 Web 应用），应该分类为 native-local
   - **注意**：如果是 Flask/Django/FastAPI 等 Web 框架，不是 native-local！

2. **web-basic**: Web 应用漏洞 ⭐ 最常见类型
   - 需要启动完整的 Web 服务器
   - 通过 HTTP 请求与服务器交互来触发漏洞
   - **Web 框架**：Flask、Django、Express、Next.js、FastAPI、Spring Boot、MLflow、Gradio
   - **漏洞类型**：SQL注入、认证绕过、授权绕过、SSRF、文件上传、CSRF
   - **重要**：必须是可启动的 Web 服务，如果只是类库/工具包，不是 web-basic

3. **freestyle**: 自由探索类漏洞
   - JavaScript/前端库漏洞（XSS、prototype pollution）
   - 需要创建 HTML 页面 + 浏览器测试的漏洞
   - 配置类漏洞、其他不适合固定流程的漏洞

4. **cloud-config**: 云配置漏洞
   - 云服务 API 配置错误（AWS/Azure/GCP）

5. **iot-firmware**: IoT/固件漏洞
   - 需要固件仿真或硬件设备
   - 路由器、摄像头、工业控制器等

## 🚨 特殊情况识别

### 类库项目检测（应该分类为 native-local）
- 产品名称包含：utility, utilities, helper, extension, provider, wrapper, adapter, sdk, client
- NuGet 包（.NET 类库）：产品名包含 .Utilities, .Extensions, .Helpers
- 补丁文件只有 .csproj/.sln 而没有 Controller/Startup/Program.cs
- 说明中提到 "library", "package", "NuGet", "PyPI", "npm package"

### 逻辑漏洞检测（应该分类为 native-local）
- 说明中提到：
  - "incorrect calculation"（计算错误）
  - "expiration", "expire"（过期时间问题）
  - "parameter validation"（参数验证）
  - "SAS token", "SAS URL"（共享访问签名）
  - "weak encryption"（弱加密）
- 这类漏洞**无法通过 HTTP 请求触发**，需要编写测试代码

## 关键分类规则

### 规则1：按产品类型分类
| 产品类型 | 分类 |
|---------|------|
| MLflow, Gradio, FastAPI, Flask, Django | web-basic |
| Next.js, Express, Spring Boot | web-basic |
| sqlparse, PyYAML, Pillow (纯库) | native-local |
| **NuGet/PyPI/npm 类库（非 Web 应用）** | **native-local** |
| smartbanner.js, dompurify (JS前端库) | freestyle |
| 路由器、固件、嵌入式设备 | iot-firmware |

### 规则2：按 CWE 分类
| CWE | 典型分类 |
|-----|----------|
| CWE-89 SQL注入 | web-basic |
| CWE-79 XSS | web-basic 或 freestyle |
| CWE-352 CSRF | web-basic |
| CWE-918 SSRF | web-basic |
| CWE-502 反序列化 | 取决于产品（Web框架→web-basic, 库→native-local） |
| CWE-674 递归限制 | native-local |
| **CWE-682 计算错误** | **native-local** |
| **CWE-664 资源管理** | **native-local** |

### 规则3：按仓库特征分类
- 仓库有 `docker-compose.yml` → 大概率 web-basic
- 仓库有 `app.py` / `main.py` / `server.js` → web-basic
- 仓库只有 `setup.py` / `pyproject.toml` → native-local
- **仓库名包含 .Utilities / .Extensions** → **native-local (类库)**

## 输出格式

请严格按以下 XML 格式输出：

<classification>
<profile>选择一个: native-local / web-basic / freestyle / cloud-config / iot-firmware</profile>
<execution_mode>选择一个: legacy / dag / freestyle</execution_mode>
<confidence>0.0-1.0 之间的置信度</confidence>
<reasoning>详细说明分类理由，包括：1) 产品类型判断 2) CWE 影响 3) 是否是类库项目 4) 复现方式推测</reasoning>
<reproduction_method>简要描述复现方法</reproduction_method>
</classification>
"""

# ============================================================
# 二次验证提示词 - 用于低置信度时的二次分析
# ============================================================

VERIFICATION_PROMPT = """你是一个漏洞分类审核专家。第一次分类结果需要你验证。

## 第一次分类结果
- **CVE ID**: {{ cve_id }}
- **分类**: {{ first_profile }}
- **置信度**: {{ first_confidence }}
- **理由**: {{ first_reasoning }}

## 原始信息
- **描述**: {{ description }}
- **产品**: {{ product_name }}
- **CWE**: {{ cwe }}
- **源码仓库**: {{ repository_url }}

## 你的任务

1. 检查第一次分类是否正确
2. 如果分类正确，保持不变
3. 如果分类错误，给出正确的分类

## 常见错误

- ❌ 把 Flask/Django/MLflow 分类为 native-local（应该是 web-basic）
- ❌ 把纯前端 JS 库分类为 web-basic（应该是 freestyle）
- ❌ 把 IoT/固件漏洞分类为其他类型（应该是 iot-firmware）
- 🚨 **把 NuGet/PyPI/npm 类库分类为 web-basic（应该是 native-local）**
- 🚨 **把逻辑漏洞（计算错误、参数验证、过期时间）分类为 web-basic（应该是 native-local）**

## 类库项目检测特征

以下特征表明这是一个类库项目（应该是 native-local）：
- 产品名包含: .Utilities, .Extensions, .Helpers, SDK, Client
- 说明中提到: "library", "package", "NuGet", "PyPI"
- 没有 Web 服务器入口点

## 逻辑漏洞检测特征

以下特征表明这是逻辑漏洞（应该是 native-local）：
- 说明中提到: "incorrect calculation", "expiration", "parameter validation"
- CWE-682 (计算错误), CWE-664 (资源管理)
- 无法通过 HTTP 请求触发

## 输出格式

<verification>
<is_correct>yes / no</is_correct>
<corrected_profile>如果需要修正，填写正确的 profile，否则留空</corrected_profile>
<corrected_confidence>如果需要修正，填写新的置信度，否则留空</corrected_confidence>
<correction_reason>如果需要修正，说明原因</correction_reason>
</verification>
"""


@dataclass 
class LLMClassifierConfig(ClassifierConfig):
    """Configuration for LLM-enhanced classifier."""
    model: str = "gpt-5"  # 使用轻量级模型节省成本
    temperature: float = 0.0
    use_llm: bool = True
    fallback_to_rules: bool = True  # 如果 LLM 失败，回退到规则
    enable_verification: bool = True  # 启用二次验证
    verification_threshold: float = 0.75  # 低于此置信度时触发二次验证
    load_cve_raw_data: bool = True  # 是否加载 CVE 原始数据
    cvelist_base_path: str = "/workspaces/submission/src/data/cvelist"  # CVE 数据库路径


class LLMVulnerabilityClassifier(VulnerabilityClassifier):
    """
    LLM 增强的漏洞分类器
    
    相比规则匹配，LLM 可以：
    1. 理解上下文（如 "KnowledgeBaseWebReader" 虽然包含 "Web" 但是是一个 Python 类）
    2. 分析补丁内容来判断漏洞类型
    3. 结合 CWE 和描述进行综合判断
    
    增强功能：
    4. 读取 CVE 原始 JSON 文件获取更多上下文
    5. 二次验证机制提高精确度
    6. 丰富的技术指标提取
    """
    
    # CVE 报告仓库特征 - 这些仓库只包含漏洞报告，不是实际软件源码
    CVE_REPORT_REPO_PATTERNS = [
        '/myCVE',      # f1rstb100d/myCVE, ting-06a/myCVE 等
        '/CVE-',       # CVE 报告仓库
        '/poc',        # PoC 报告仓库
        '/cve',        # CVE 报告
        '/Yu/',        # 特定的报告仓库
    ]
    
    # Web 框架/产品关键词 - 应该分类为 web-basic
    WEB_PRODUCT_KEYWORDS = [
        'flask', 'django', 'fastapi', 'express', 'next.js', 'nextjs', 'spring boot',
        'mlflow', 'gradio', 'streamlit', 'tornado', 'aiohttp', 'sanic', 'starlette',
        'rails', 'laravel', 'symfony', 'wordpress', 'drupal', 'joomla',
        'jenkins', 'gitlab', 'grafana', 'kibana', 'elasticsearch',
    ]
    
    # IoT/硬件关键词 - 应该分类为 iot-firmware
    HARDWARE_KEYWORDS = [
        'router', 'firmware', 'iot', 'embedded', 'device', 'gateway', 'modem', 
        'switch', 'camera', 'dvr', 'nvr', 'plc', 'scada', 'industrial',
    ]
    
    # 类库/包项目关键词 - 应该分类为 native-local 而非 web-basic
    LIBRARY_PROJECT_KEYWORDS = [
        # .NET 类库
        'nuget', 'classlib', 'library', '.nupkg', 'netstandard', 'class library',
        'aspnetcore.utilities', 'microsoft.extensions',
        # Python 库
        'pypi', 'pip install', 'python package', 'sdk', 'client library',
        # npm 库
        'npm package', 'node module', 'typescript library',
        # 通用类库特征
        'utility', 'utilities', 'helper', 'helpers', 'extension', 'extensions',
        'middleware', 'provider', 'handler', 'wrapper', 'adapter',
    ]
    
    # 逻辑漏洞关键词 - 这类漏洞无法通过 HTTP 请求触发，需要特殊处理
    LOGIC_VULNERABILITY_KEYWORDS = [
        # 参数/输入验证缺陷
        'parameter validation', 'input validation', 'improper validation',
        'incorrect calculation', 'time calculation', 'expiration', 'expire',
        # 加密/认证逻辑缺陷
        'weak encryption', 'insufficient entropy', 'predictable',
        # 资源管理逻辑缺陷
        'resource leak', 'memory corruption', 'race condition',
        # URL/Token 生成逻辑缺陷
        'sas token', 'sas url', 'signed url', 'presigned', 'access token',
    ]
    
    def __init__(self, config: Optional[LLMClassifierConfig] = None) -> None:
        self.config = config or LLMClassifierConfig()
        super().__init__(self.config)
        self._cve_raw_cache: Dict[str, Dict] = {}  # 缓存 CVE 原始数据
    
    def _is_cve_report_repo(self, sw_version_wget: str) -> bool:
        """检测 sw_version_wget 是否指向 CVE 报告仓库而非实际软件源码。"""
        if not sw_version_wget:
            return False
        for pattern in self.CVE_REPORT_REPO_PATTERNS:
            if pattern.lower() in sw_version_wget.lower():
                return True
        return False
    
    # ============================================================
    # CVE 原始数据加载功能
    # ============================================================
    
    def _get_cve_file_path(self, cve_id: str) -> Optional[str]:
        """根据 CVE ID 计算文件路径"""
        match = re.match(r'CVE-(\d{4})-(\d+)', cve_id, re.IGNORECASE)
        if not match:
            return None
        
        year = match.group(1)
        number = int(match.group(2))
        folder = f"{(number // 1000)}xxx"
        
        return f"{self.config.cvelist_base_path}/{year}/{folder}/{cve_id.upper()}.json"
    
    def _load_cve_raw_data(self, cve_id: str) -> Optional[Dict]:
        """加载 CVE 原始 JSON 数据（包含 references、affected products 等）"""
        if cve_id in self._cve_raw_cache:
            return self._cve_raw_cache[cve_id]
        
        file_path = self._get_cve_file_path(cve_id)
        if not file_path or not os.path.exists(file_path):
            return None
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
                self._cve_raw_cache[cve_id] = data
                return data
        except Exception as e:
            print(f"[Classifier] 加载 CVE 原始数据失败: {e}")
            return None
    
    def _extract_rich_context(self, cve_id: str, cve_entry: Dict[str, object]) -> Dict[str, Any]:
        """
        提取丰富的上下文信息，用于更精确的分类
        
        从 CVE 原始数据和 cve_entry 中提取：
        - 产品名称和厂商
        - 受影响版本
        - 源码仓库 URL
        - 参考链接类型
        - 技术指标
        - 类库项目检测
        - 逻辑漏洞检测
        """
        context = {
            'product_name': '',
            'vendor': '',
            'affected_versions': '',
            'repository_url': '',
            'reference_types': [],
            'patch_files': [],
            'tech_indicators': [],
            'is_web_product': False,
            'is_hardware': False,
            'is_library_project': False,  # 新增：是否是类库项目
            'is_logic_vulnerability': False,  # 新增：是否是逻辑漏洞
        }
        
        # 从 cve_entry 提取基本信息
        sw_version_wget = cve_entry.get('sw_version_wget', '')
        if sw_version_wget:
            context['repository_url'] = sw_version_wget
            # 提取仓库名称
            repo_match = re.search(r'github\.com/([^/]+)/([^/]+)', sw_version_wget)
            if repo_match:
                context['tech_indicators'].append(f"GitHub: {repo_match.group(1)}/{repo_match.group(2)}")
        
        # 尝试加载 CVE 原始数据
        if self.config.load_cve_raw_data:
            raw_data = self._load_cve_raw_data(cve_id)
            if raw_data:
                context = self._enrich_context_from_raw(context, raw_data)
        
        # 从补丁提取文件名
        patches = cve_entry.get('patch_commits', [])
        for patch in patches[:2]:
            content = patch.get('content', '')
            filenames = re.findall(r'Filename: ([^\n]+)', content)
            context['patch_files'].extend(filenames[:5])
        
        # 检测是否是 Web 产品
        product_lower = context['product_name'].lower()
        desc_lower = cve_entry.get('description', '').lower()
        combined = f"{product_lower} {desc_lower} {sw_version_wget.lower()}"
        
        for keyword in self.WEB_PRODUCT_KEYWORDS:
            if keyword in combined:
                context['is_web_product'] = True
                context['tech_indicators'].append(f"Web框架: {keyword}")
                break
        
        # 检测是否是硬件/IoT
        for keyword in self.HARDWARE_KEYWORDS:
            if keyword in combined:
                context['is_hardware'] = True
                context['tech_indicators'].append(f"硬件: {keyword}")
                break
        
        # 🟢 新增：检测是否是类库项目
        for keyword in self.LIBRARY_PROJECT_KEYWORDS:
            if keyword in combined:
                context['is_library_project'] = True
                context['tech_indicators'].append(f"类库项目: {keyword}")
                break
        
        # 🟢 新增：检测是否是逻辑漏洞（非 HTTP 触发）
        for keyword in self.LOGIC_VULNERABILITY_KEYWORDS:
            if keyword in combined:
                context['is_logic_vulnerability'] = True
                context['tech_indicators'].append(f"逻辑漏洞: {keyword}")
                break
        
        # 🟢 新增：从补丁文件名检测项目类型
        patch_files_str = ' '.join(context['patch_files']).lower()
        
        # .csproj 文件检测
        if '.csproj' in patch_files_str:
            # 检查是否没有 Web 相关文件
            if not any(web_file in patch_files_str for web_file in ['controller', 'startup', 'program.cs', 'webapp']):
                context['is_library_project'] = True
                context['tech_indicators'].append("补丁中无Web入口点")
        
        # Python 库检测（只有 setup.py 或 pyproject.toml，没有 app/server 文件）
        if ('setup.py' in patch_files_str or 'pyproject.toml' in patch_files_str):
            if not any(web_file in patch_files_str for web_file in ['app.py', 'server.py', 'main.py', 'wsgi', 'asgi']):
                context['is_library_project'] = True
                context['tech_indicators'].append("补丁中无Web入口文件")
        
        return context
    
    def _enrich_context_from_raw(self, context: Dict[str, Any], raw_data: Dict) -> Dict[str, Any]:
        """从 CVE 原始数据丰富上下文"""
        try:
            cna = raw_data.get('containers', {}).get('cna', {})
            
            # 提取产品和厂商信息
            affected = cna.get('affected', [])
            if affected:
                first = affected[0]
                context['product_name'] = first.get('product', '')
                context['vendor'] = first.get('vendor', '')
                
                # 提取版本信息
                versions = first.get('versions', [])
                version_strs = []
                for v in versions[:3]:
                    status = v.get('status', '')
                    version = v.get('version', '')
                    if version:
                        version_strs.append(f"{version}({status})")
                context['affected_versions'] = ', '.join(version_strs)
            
            # 提取参考链接类型
            refs = cna.get('references', [])
            for ref in refs:
                url = ref.get('url', '')
                tags = ref.get('tags', [])
                
                # 记录链接类型
                if tags:
                    context['reference_types'].extend(tags)
                
                # 提取源码仓库（排除 exploit 链接）
                if 'exploit' not in tags:
                    if any(domain in url for domain in ['github.com', 'gitlab.com', 'gitee.com']):
                        if not context['repository_url']:
                            context['repository_url'] = url
                        # 提取技术指标
                        if '/issues/' in url:
                            context['tech_indicators'].append('Has Issues')
                        if '/security/' in url or '/advisories/' in url:
                            context['tech_indicators'].append('Has Security Advisory')
            
            # 去重
            context['reference_types'] = list(set(context['reference_types']))
            
        except Exception as e:
            print(f"[Classifier] 提取原始数据失败: {e}")
        
        return context
    
    def _check_data_quality(self, cve_entry: Dict[str, object]) -> tuple[bool, str]:
        """
        检查 CVE 数据质量，判断是否可以自动复现。
        
        Returns:
            (is_deployable, reason)
        """
        sw_version_wget = cve_entry.get("sw_version_wget", "")
        github_repo = cve_entry.get("_meta", {}).get("github_repo", "")
        patch_commits = cve_entry.get("patch_commits", [])
        
        # 检查 1: patch_commits 为空 - 没有补丁信息的漏洞无法有效复现
        if not patch_commits or len(patch_commits) == 0:
            return False, "No patch_commits - cannot reproduce without vulnerability details"
        
        # 检查 2: sw_version_wget 为空
        if not sw_version_wget:
            return False, "No sw_version_wget provided - cannot auto-deploy"
        
        # 检查 3: sw_version_wget 指向 CVE 报告仓库
        if self._is_cve_report_repo(sw_version_wget):
            return False, f"sw_version_wget points to CVE report repo, not actual software"
        
        # 检查 4: github_repo 和 sw_version_wget 不匹配（可能是报告仓库）
        if github_repo and sw_version_wget:
            # 从 sw_version_wget 提取 owner/repo
            wget_match = re.search(r'github\.com/([^/]+/[^/]+)/', sw_version_wget)
            repo_match = re.search(r'github\.com/([^/]+/[^/]+)', github_repo)
            if wget_match and repo_match:
                wget_repo = wget_match.group(1).lower()
                actual_repo = repo_match.group(1).lower()
                if wget_repo != actual_repo:
                    return False, f"Mismatched repos: wget={wget_repo}, github_repo={actual_repo}"
        
        return True, "OK"
        
    def classify(self, cve_id: str, cve_entry: Dict[str, object], profile_override: Optional[str] = None) -> ClassifierDecision:
        """分类漏洞，优先使用 LLM，失败时回退到增强规则。"""
        
        if profile_override:
            # 如果有显式覆盖，直接使用
            return super().classify(cve_id, cve_entry, profile_override)
        
        if not self.config.use_llm:
            return self._classify_with_enhanced_rules(cve_id, cve_entry)
        
        try:
            return self._classify_with_llm(cve_id, cve_entry)
        except Exception as e:
            print(f"⚠️ LLM classification failed: {e}")
            if self.config.fallback_to_rules:
                print("📋 Falling back to rule-based classification")
                return self._classify_with_enhanced_rules(cve_id, cve_entry)
            raise
    
    def _classify_with_enhanced_rules(self, cve_id: str, cve_entry: Dict[str, object]) -> ClassifierDecision:
        """使用增强规则进行分类（结合上下文信息）。"""
        
        # 提取丰富上下文
        context = self._extract_rich_context(cve_id, cve_entry)
        
        # 0. 数据质量检查（优先检查，缺乏关键信息时直接跳过）
        is_deployable, quality_reason = self._check_data_quality(cve_entry)
        if not is_deployable:
            print(f"⚠️ [Rules] Data quality issue: {quality_reason}")
            print(f"   → 跳过复现 (skip_reproduction=True)")
            
            return ClassifierDecision(
                cve_id=cve_id,
                profile="freestyle",
                confidence=0.0,
                required_capabilities=[],
                resource_hints={
                    "skip_reproduction": True,
                    "data_quality_issue": quality_reason,
                    "needs_browser": False,
                },
                execution_mode="freestyle",
            )
        
        # 1. 硬件检测优先
        if context['is_hardware']:
            return ClassifierDecision(
                cve_id=cve_id,
                profile="iot-firmware",
                confidence=0.9,
                required_capabilities=self._infer_capabilities("iot-firmware"),
                resource_hints={"is_hardware": True, "needs_browser": False},
                execution_mode="freestyle",
            )
        
        # 🟢 2. 类库项目检测（优先于 Web 产品检测）
        if context['is_library_project']:
            print(f"   📚 检测到类库项目，分类为 native-local")
            return ClassifierDecision(
                cve_id=cve_id,
                profile="native-local",
                confidence=0.85,
                required_capabilities=self._infer_capabilities("native-local"),
                resource_hints={
                    "is_library_project": True, 
                    "needs_browser": False,
                    "reproduction_hint": "这是一个类库项目，需要创建测试程序或使用 dotnet test/pytest/npm test"
                },
                execution_mode="freestyle",  # 类库项目需要灵活处理
            )
        
        # 🟢 3. 逻辑漏洞检测
        if context['is_logic_vulnerability']:
            print(f"   ⚠️ 检测到逻辑漏洞，分类为 native-local")
            return ClassifierDecision(
                cve_id=cve_id,
                profile="native-local",
                confidence=0.8,
                required_capabilities=self._infer_capabilities("native-local"),
                resource_hints={
                    "is_logic_vulnerability": True, 
                    "needs_browser": False,
                    "reproduction_hint": "这是逻辑漏洞，需要编写测试代码触发漏洞，而非 HTTP 请求"
                },
                execution_mode="freestyle",
            )
        
        # 4. Web 产品检测
        if context['is_web_product']:
            return ClassifierDecision(
                cve_id=cve_id,
                profile="web-basic",
                confidence=0.85,
                required_capabilities=self._infer_capabilities("web-basic"),
                resource_hints={"needs_browser": True, "is_web_product": True},
                execution_mode="dag",
            )
        
        # 5. 回退到基础规则
        return super().classify(cve_id, cve_entry)
    
    def _classify_with_llm(self, cve_id: str, cve_entry: Dict[str, object]) -> ClassifierDecision:
        """使用 LLM 进行分类，并在低置信度时进行二次验证。"""
        
        # ===== 先提取上下文（用于硬件检测） =====
        context = self._extract_rich_context(cve_id, cve_entry)
        
        # ===== 硬件检测优先 =====
        # 如果检测到硬件/IoT 产品，直接返回 iot-firmware
        if context['is_hardware']:
            print(f"\n🔍 分类 {cve_id}...")
            print(f"   🚨 检测到硬件产品，直接分类为 iot-firmware")
            return ClassifierDecision(
                cve_id=cve_id,
                profile="iot-firmware",
                confidence=0.9,
                required_capabilities=self._infer_capabilities("iot-firmware"),
                resource_hints={"is_hardware": True, "needs_browser": False},
                execution_mode="freestyle",
            )
        
        # ===== 数据质量检查 =====
        is_deployable, quality_reason = self._check_data_quality(cve_entry)
        if not is_deployable:
            print(f"⚠️ Data quality issue: {quality_reason}")
            print(f"   → 跳过复现 (skip_reproduction=True)")
            
            return ClassifierDecision(
                cve_id=cve_id,
                profile="freestyle",
                confidence=0.0,  # 置信度设为0表示不应该复现
                required_capabilities=[],
                resource_hints={
                    "skip_reproduction": True,  # 明确标记跳过复现
                    "data_quality_issue": quality_reason,
                    "needs_browser": False,
                },
                execution_mode="freestyle",
            )
        
        # ===== 准备 LLM 输入 =====
        description = cve_entry.get("description", "No description available")
        cwe_list = cve_entry.get("cwe", [])
        cwe_str = ", ".join([f"{c.get('id', '')} - {c.get('value', '')}" for c in cwe_list]) if cwe_list else "Unknown"
        
        # 提取补丁文件
        patch_files = ', '.join(context['patch_files'][:5]) if context['patch_files'] else 'None'
        tech_indicators = ', '.join(context['tech_indicators'][:5]) if context['tech_indicators'] else 'None'
        
        # ===== 第一次 LLM 分类 =====
        print(f"\n🔍 分类 {cve_id}...")
        print(f"   产品: {context['product_name']} | 厂商: {context['vendor']}")
        print(f"   技术指标: {tech_indicators}")
        
        classifier_llm = LLMFunction.create(
            CLASSIFICATION_PROMPT,
            model=self.config.model,
            temperature=self.config.temperature
        )
        
        response = classifier_llm(
            cve_id=cve_id,
            description=description,
            cwe=cwe_str,
            product_name=context['product_name'] or 'Unknown',
            vendor=context['vendor'] or 'Unknown',
            affected_versions=context['affected_versions'] or 'Unknown',
            repository_url=context['repository_url'] or 'None',
            reference_types=', '.join(context['reference_types']) if context['reference_types'] else 'None',
            patch_files=patch_files,
            tech_indicators=tech_indicators,
        )
        
        # ===== 解析第一次分类结果 =====
        result = self._parse_classification_response(response, cve_id, cve_entry)
        
        # ===== 🟢 规则修正：类库项目不应该分类为 web-basic =====
        if context['is_library_project'] and result.profile == 'web-basic':
            print(f"   📚 规则修正: 检测到类库项目，修正 web-basic → native-local")
            result = ClassifierDecision(
                cve_id=cve_id,
                profile="native-local",
                confidence=0.85,
                required_capabilities=self._infer_capabilities("native-local"),
                resource_hints={
                    **result.resource_hints, 
                    "is_library_project": True, 
                    "needs_browser": False,
                    "rule_corrected": True,
                    "reproduction_hint": "这是一个类库项目，需要创建测试程序或使用 dotnet test/pytest/npm test"
                },
                execution_mode="freestyle",
            )
        
        # ===== 🟢 规则修正：逻辑漏洞不应该分类为 web-basic =====
        if context['is_logic_vulnerability'] and result.profile == 'web-basic':
            print(f"   ⚠️ 规则修正: 检测到逻辑漏洞，修正 web-basic → native-local")
            result = ClassifierDecision(
                cve_id=cve_id,
                profile="native-local",
                confidence=0.8,
                required_capabilities=self._infer_capabilities("native-local"),
                resource_hints={
                    **result.resource_hints, 
                    "is_logic_vulnerability": True, 
                    "needs_browser": False,
                    "rule_corrected": True,
                    "reproduction_hint": "这是逻辑漏洞，需要编写测试代码触发漏洞"
                },
                execution_mode="freestyle",
            )
        
        # ===== 规则修正：如果检测到 Web 产品但分类为 native-local（且不是类库项目/逻辑漏洞），强制修正 =====
        if context['is_web_product'] and result.profile == 'native-local' and not context['is_library_project'] and not context['is_logic_vulnerability']:
            print(f"   ⚠️ 规则修正: 检测到 Web 产品，修正 native-local → web-basic")
            result = ClassifierDecision(
                cve_id=cve_id,
                profile="web-basic",
                confidence=0.85,
                required_capabilities=self._infer_capabilities("web-basic"),
                resource_hints={**result.resource_hints, "needs_browser": True, "rule_corrected": True},
                execution_mode="dag",
            )
        
        # ===== 规则修正：如果检测到硬件但分类不是 iot-firmware =====
        if context['is_hardware'] and result.profile != 'iot-firmware':
            print(f"   ⚠️ 规则修正: 检测到硬件产品，修正 {result.profile} → iot-firmware")
            result = ClassifierDecision(
                cve_id=cve_id,
                profile="iot-firmware",
                confidence=0.9,
                required_capabilities=self._infer_capabilities("iot-firmware"),
                resource_hints={**result.resource_hints, "is_hardware": True, "rule_corrected": True},
                execution_mode="freestyle",
            )
        
        # ===== 二次验证：低置信度时触发 =====
        if self.config.enable_verification and result.confidence < self.config.verification_threshold:
            print(f"   🔄 置信度低 ({result.confidence:.2f})\uff0c触发二次验证...")
            result = self._verify_classification(result, cve_entry, context, description, cwe_str)
        
        print(f"\n🎯 最终分类结果:")
        print(f"   Profile: {result.profile}")
        print(f"   Confidence: {result.confidence:.2f}")
        
        return result
    
    def _verify_classification(
        self, 
        first_result: ClassifierDecision, 
        cve_entry: Dict[str, object],
        context: Dict[str, Any],
        description: str,
        cwe_str: str
    ) -> ClassifierDecision:
        """二次验证分类结果"""
        try:
            verifier_llm = LLMFunction.create(
                VERIFICATION_PROMPT,
                model=self.config.model,
                temperature=0.0
            )
            
            # 提取第一次分类理由
            first_reasoning = first_result.resource_hints.get('reasoning', 'No reasoning available')
            
            response = verifier_llm(
                cve_id=first_result.cve_id,
                first_profile=first_result.profile,
                first_confidence=first_result.confidence,
                first_reasoning=first_reasoning,
                description=description,
                product_name=context['product_name'] or 'Unknown',
                cwe=cwe_str,
                repository_url=context['repository_url'] or 'None',
            )
            
            # 解析验证结果
            is_correct_match = re.search(r'<is_correct>\s*(yes|no)\s*</is_correct>', response, re.IGNORECASE)
            is_correct = is_correct_match.group(1).lower() == 'yes' if is_correct_match else True
            
            if not is_correct:
                # 提取修正后的 profile
                corrected_match = re.search(r'<corrected_profile>\s*(native-local|web-basic|freestyle|cloud-config|iot-firmware)\s*</corrected_profile>', response, re.IGNORECASE)
                if corrected_match:
                    corrected_profile = corrected_match.group(1).lower()
                    
                    # 提取修正后的置信度
                    conf_match = re.search(r'<corrected_confidence>\s*([\d.]+)\s*</corrected_confidence>', response)
                    corrected_confidence = float(conf_match.group(1)) if conf_match else 0.8
                    
                    print(f"   ✅ 二次验证修正: {first_result.profile} → {corrected_profile}")
                    
                    return ClassifierDecision(
                        cve_id=first_result.cve_id,
                        profile=corrected_profile,
                        confidence=min(corrected_confidence, 0.95),
                        required_capabilities=self._infer_capabilities(corrected_profile),
                        resource_hints={**first_result.resource_hints, 'verified': True, 'corrected': True},
                        execution_mode=self._infer_execution_mode(corrected_profile, {}),
                    )
            
            # 验证通过，稍微提高置信度
            print(f"   ✅ 二次验证确认分类正确")
            return ClassifierDecision(
                cve_id=first_result.cve_id,
                profile=first_result.profile,
                confidence=min(first_result.confidence + 0.1, 0.95),
                required_capabilities=first_result.required_capabilities,
                resource_hints={**first_result.resource_hints, 'verified': True},
                execution_mode=first_result.execution_mode,
            )
            
        except Exception as e:
            print(f"   ⚠️ 二次验证失败: {e}")
            return first_result
    
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

        # 提取 execution_mode
        exec_match = re.search(r'<execution_mode>\s*(legacy|dag|freestyle)\s*</execution_mode>', response, re.IGNORECASE)
        execution_mode = exec_match.group(1).lower() if exec_match else self._infer_execution_mode(profile, {})
        
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
            execution_mode=execution_mode,
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
