# 新架构使用指南

## 概述

新架构通过**分类器 + DAG 执行器**实现不同漏洞类型的差异化处理。关键特性：

- ✅ **自动分类**：根据 CWE/描述自动选择 profile（native-local / web-basic / cloud-config）
- ✅ **环境编排**：Docker 容器、浏览器、虚拟机等按需分配
- ✅ **灵活验证**：HTTP 响应、Cookie、日志、Flag 等多种验证策略
- ✅ **事件追踪**：所有步骤产物和事件保存到 `events.jsonl`

---

## 使用流程

### 1. 生成执行计划（plan.json）

```python
from planner.classifier import VulnerabilityClassifier
from planner.dag import PlanBuilder
import json

# 加载 CVE 数据
with open("src/data/example/data.json", "r") as f:
    cve_data = json.load(f)

cve_entry = cve_data["CVE-2024-4340"]

# 分类漏洞类型
classifier = VulnerabilityClassifier()
decision = classifier.classify("CVE-2024-4340", cve_entry)

print(f"Profile: {decision.profile}")
print(f"Capabilities: {decision.required_capabilities}")

# 构建执行计划
builder = PlanBuilder()
plan = builder.build(decision)

# 保存计划
with open("/shared/CVE-2024-4340/plan.json", "w") as f:
    json.dump(plan.to_dict(), f, indent=2, ensure_ascii=False)
```

### 2. 执行 DAG 计划

```python
from planner.executor import DAGExecutor
from core.result_bus import ResultBus
from capabilities.adapters import build_capability_registry

# 初始化结果总线
result_bus = ResultBus("CVE-2024-4340")

# 构建能力注册表
registry = build_capability_registry()

# 从文件加载执行器
executor = DAGExecutor.from_plan_file(
    "/shared/CVE-2024-4340/plan.json",
    result_bus,
    registry
)

# 执行计划
artifacts = executor.execute()

# 查看事件日志
events = result_bus.get_event_log()
for event in events:
    print(f"[{event['timestamp']}] {event['event_type']} - {event.get('step_id')}")
```

---

## 不同漏洞类型的执行链对比

### Native-Local 漏洞（默认）

```
collect-info → prepare-env → exploit → verify(Flag)
```

**适用场景**：二进制、本地服务、源码构建类漏洞（如 CVE-2024-4340）

**环境需求**：Docker 容器（复用现有 devcontainer）

---

### Web-Basic 漏洞（新增）

```
collect-info → browser-provision → exploit-web → verify-web(HTTP)
```

**适用场景**：CSRF、XSS、SSRF 等 Web 应用漏洞（如 CVE-2024-2288）

**环境需求**：
- 浏览器环境（Selenium Chrome）
- 目标应用需**预先部署**（手动启动或 Docker Compose）

**关键差异**：
- ❌ **不执行** `PreReqBuilder` 和 `RepoBuilder`（无需源码构建）
- ✅ **直接启动浏览器**，访问已部署的 Web 应用
- ✅ 使用 `HttpResponseVerifier` 或 `CookieVerifier` 验证

**示例配置**：

```python
# 为 Web 漏洞指定目标 URL
decision = classifier.classify("CVE-2024-2288", cve_entry)
decision.resource_hints["target_url"] = "http://localhost:9600"

# 选择验证策略
decision.resource_hints["verification_strategies"] = ["http_200", "cookie_stolen"]
```

---

### Cloud-Config 漏洞（未来）

```
collect-info → provision-cloud → exploit-api → verify-log
```

**适用场景**：云服务配置错误、API 密钥泄露、IAM 权限提升

**环境需求**：云服务 API 凭证、Terraform/Pulumi 自动化

---

## 环境编排示例

### 选择浏览器引擎

**Selenium（默认，推荐入门）**

```python
from orchestrator import EnvironmentOrchestrator

orchestrator = EnvironmentOrchestrator()

browser_meta = orchestrator.provision_environment(
    env_name="browser",
    env_type="browser",
    config={
        "engine": "selenium",  # 默认值，可省略
        "browser": "chrome",
        "headless": True,
        "target_url": "http://localhost:9600",
    }
)

# 使用 Selenium driver
driver = browser_meta["driver"]
driver.get("http://localhost:9600")
```

**Playwright（推荐高级场景）**

```python
browser_meta = orchestrator.provision_environment(
    env_name="browser",
    env_type="browser",
    config={
        "engine": "playwright",
        "browser": "chromium",  # 或 "firefox", "webkit"
        "headless": True,
        "target_url": "http://localhost:9600",
        "proxy": None,
    }
)

# 使用 Playwright page
page = browser_meta["page"]
page.goto("http://localhost:9600")

# Playwright 独有：网络拦截
page.route("**/*", lambda route: route.continue_())
```

**何时选择 Playwright？**

- ✅ 需要拦截/修改网络请求（SSRF、请求走私）
- ✅ 需要截图、录制攻击过程
- ✅ 复杂的 JavaScript 交互（WebSocket、Service Worker）
- ✅ 多浏览器并发测试（chromium/firefox/webkit）

**何时使用 Selenium？**

- ✅ 简单的表单提交、点击操作
- ✅ 团队已有 Selenium 经验
- ✅ 需要兼容旧的自动化脚本

### 复用 Docker 容器

```python
docker_meta = orchestrator.provision_environment(
    env_name="builder",
    env_type="docker",
    config={
        "container_name": "competent_dewdney",  # 复用现有容器
    }
)

print(f"使用容器: {docker_meta['container_name']}")
```

---

## 验证策略使用

### 单一策略

```python
from verification import build_default_registry

registry = build_default_registry()

context = {
    "http_response": {
        "status_code": 200,
        "content": "<html>XSS payload executed</html>",
    }
}

result = registry.verify(
    strategy_names=["http_200"],
    context=context
)

print(f"Success: {result['success']}, Confidence: {result['confidence']}")
```

### 组合策略（提高置信度）

```python
context = {
    "http_response": {...},
    "cookies": {"session": "stolen_value"},
    "exploit_output": "Cookie: session=stolen_value",
}

# 同时使用 HTTP 和 Cookie 验证
result = registry.verify(
    strategy_names=["http_200", "cookie_stolen"],
    context=context,
    combine_mode="all"  # 所有策略都要通过
)
```

---

## 人工介入点

### 1. 目标应用部署（Web 漏洞必需）

**选项 A：手动启动**（当前推荐）

```bash
# 启动目标 Web 应用
docker run -p 9600:9600 lollms-webui:vulnerable

# 在 plan 中配置 URL
{
  "resource_hints": {
    "target_url": "http://localhost:9600"
  }
}
```

**选项 B：自动部署**（未来扩展）

```yaml
# env/web-app.yaml
version: "3.8"
services:
  target:
    image: lollms-webui:vulnerable
    ports:
      - "9600:9600"
```

### 2. Selenium/Playwright 安装（首次使用）

**Selenium（默认）**

```bash
# 在容器内安装
pip install selenium

# 安装 ChromeDriver
apt-get update && apt-get install -y chromium-chromedriver
```

**Playwright（可选，推荐高级场景）**

```bash
# 安装 Playwright
pip install playwright

# 下载浏览器二进制文件
playwright install chromium

# 或安装所有浏览器
playwright install
```

### 3. 自定义验证条件

如果默认验证器不满足需求，可扩展：

```python
from verification import VerificationStrategy

class CustomVerifier(VerificationStrategy):
    def verify(self, context):
        # 自定义逻辑
        return {
            "success": True,
            "confidence": 0.95,
            "evidence": "检测到特定攻击特征",
            "details": {},
        }

# 注册到 registry
registry.register("custom", CustomVerifier())
```

---

## 迁移路径

### 阶段 1：双模式运行（当前）

- `main.py` 保留现有逻辑（`--legacy` 模式）
- 新增 `--dag` 模式使用 plan.json 执行

### 阶段 2：逐步替换（中期）

- 默认使用 DAG 执行器
- 仅在 plan.json 缺失时回退到 legacy 模式

### 阶段 3：完全迁移（长期）

- 移除 legacy 代码
- 所有漏洞通过 classifier + planner 处理

---

## 常见问题

### Q: Playwright 能否成功复现漏洞？

**A**: 是的，Playwright 在许多场景下比 Selenium 更适合 Web 漏洞复现：

| 漏洞类型 | Selenium | Playwright | 推荐 |
|---------|----------|-----------|------|
| 简单 CSRF | ✅ 支持 | ✅ 支持 | 任意 |
| XSS（alert） | ✅ 需手动处理 | ✅ 自动捕获 | Playwright |
| SSRF | ⚠️ 需代理 | ✅ 内置拦截 | Playwright |
| Cookie 窃取 | ✅ 支持 | ✅ 支持 | 任意 |
| WebSocket 攻击 | ❌ 不支持 | ✅ 原生支持 | Playwright |
| 请求走私 | ❌ 难实现 | ✅ 可拦截修改 | Playwright |
| 多步骤攻击 | ⚠️ 需复杂脚本 | ✅ 上下文管理 | Playwright |
| 截图取证 | ✅ 支持 | ✅ 更强大 | Playwright |

**Playwright 独有优势**：
- 🎯 **网络拦截**：可以修改请求/响应，模拟中间人攻击
- 📹 **录制回放**：可以记录整个攻击过程供审计
- 🚀 **性能更好**：原生协议通信，速度快 2-3 倍
- 🔧 **调试友好**：内置 trace viewer 和 inspector

**使用建议**：
- 新项目优先选择 Playwright
- 简单场景用 Selenium 足够
- 复杂网络交互必须用 Playwright

参考示例：`examples/playwright_web_exploit.py`

### Q: Web 漏洞是否需要源码？

**A**: 不需要。Web 漏洞的 `web-basic` profile 会跳过 `RepoBuilder` 步骤，直接使用浏览器访问已部署的应用。

### Q: 如何添加新的漏洞类型？

**A**: 
1. 在 `classifier.py` 的 `_pick_profile` 中添加识别规则
2. 在 `dag.py` 中添加对应的 `_xxx_steps` 方法
3. 在 `adapters.py` 中注册新的 Capability 实现

### Q: 验证策略如何选择？

**A**: 
- Classifier 根据漏洞类型自动推荐（通过 `resource_hints["verification_strategies"]`）
- 用户可在 plan.json 中手动覆盖

### Q: 环境清理是自动的吗？

**A**: 
- 复用的 Docker 容器**不会**被清理
- 新创建的浏览器会话在执行完成后自动关闭
- 调用 `orchestrator.teardown_all()` 可手动清理所有资源

---

## 下一步计划

1. ✅ **CLI 集成**：在 `main.py` 中添加 `--dag` 模式切换
2. ⬜ **YAML 配置**：支持从 `profiles/*.yaml` 加载默认步骤定义
3. ⬜ **自动部署**：环境编排器支持 Docker Compose 自动启动目标应用
4. ⬜ **可视化**：Web UI 展示 DAG 执行流程和事件时间线
