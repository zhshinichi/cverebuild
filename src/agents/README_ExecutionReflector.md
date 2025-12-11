# ExecutionReflector Agent 使用指南

## 概述

**ExecutionReflector** 是一个元级分析 Agent，在其他 Agent（如 WebDriverAgent、FreestyleAgent）执行失败后介入，分析完整执行日志并提供策略调整建议。

### 核心能力

1. **全局视野**：分析完整执行日志，而不仅仅是最后的输出
2. **模式识别**：检测重复失败循环（如"20次都是404"）
3. **根因诊断**：识别工具误用、缺少信息、环境问题等
4. **策略建议**：提供具体的修正方案（切换工具、Agent、搜索补充信息）
5. **智能推理**：使用 GPT-4o 进行深度分析

---

## 为什么需要 ExecutionReflector？

### 问题背景

CVE-2025-54137 复现失败案例：

```
WebDriverAgent 执行过程：
1. navigate_to_url('http://localhost:8080/')       → 404
2. navigate_to_url('http://localhost:8080/login')  → 404
3. navigate_to_url('http://localhost:8080/api')    → 404
...
20. navigate_to_url('http://localhost:8080/api/v13') → 404

结果：达到最大迭代次数，判定失败
```

**根本问题**：
- WebDriverAgent 只用了 `navigate_to_url`（GET 请求）
- 但这是 **API 凭证漏洞**，需要 POST 到 `/api/login`
- Agent 有 `send_http_request` 工具但没有使用
- CVE Knowledge 缺少默认凭证、API 端点、请求方法

**人类专家分析**（AI 助手）：
- 查看完整日志 → 识别"20次都是404" → 推断"应该用POST不是GET"
- 建议使用 `send_http_request` 工具
- 建议补充默认凭证信息

**ExecutionReflector 目标**：
模拟人类专家的分析能力，自动给出这样的建议！

---

## 架构集成

### 集成点 1: WebDriverAdapter（已集成）

```python
# src/capabilities/adapters.py

class WebDriverAdapter(Capability):
    def execute(self, inputs: Dict[str, Any]) -> Dict[str, Any]:
        # ... 执行 WebDriverAgent ...
        result = agent.invoke().value
        
        # 🔍 失败后自动调用 ExecutionReflector
        if is_failure and self.config.get('enable_reflection', True):
            from agents.executionReflector import ExecutionReflector, AgentExecutionContext
            
            context = AgentExecutionContext(
                agent_name='WebDriverAgent',
                cve_id=cve_id,
                cve_knowledge=cve_knowledge,
                execution_log=execution_log,
                tool_calls=tool_calls,
                final_status='failure',
                iterations_used=20,
                max_iterations=20
            )
            
            reflector = ExecutionReflector(model='gpt-4o')
            analysis = reflector.analyze(context)
            
            # 将分析结果附加到返回值
            result['execution_analysis'] = {
                'failure_type': analysis.failure_type,
                'root_cause': analysis.root_cause,
                'suggested_agent': analysis.suggested_agent,
                'suggested_strategy': analysis.suggested_strategy,
                ...
            }
        
        return {'web_exploit_result': result}
```

### 集成点 2: DAG 执行器（已集成）

```python
# src/planner/executor.py

class DAGExecutor:
    def _execute_step(self, step: PlanStep) -> None:
        outputs = capability_instance.execute(inputs)
        
        # 🔍 检查是否有 ExecutionReflector 分析结果
        execution_analysis = outputs.get('execution_analysis')
        
        if execution_analysis:
            suggested_agent = execution_analysis.get('suggested_agent')
            
            if suggested_agent and step.config.get('auto_switch_agent'):
                # 💡 自动切换到建议的 Agent
                print(f"切换到 {suggested_agent}")
                # TODO: 实现切换逻辑
```

---

## 使用方法

### 方法 1: 通过 DAG 自动触发（推荐）

在 `plan.json` 中配置 WebDriver 步骤：

```json
{
  "id": "exploit-web",
  "capability": "WebExploit",
  "implementation": "WebDriverAdapter",
  "inputs": ["cve_id", "cve_knowledge", "browser_config"],
  "outputs": ["web_exploit_result"],
  "config": {
    "enable_reflection": true,
    "auto_switch_agent": false
  }
}
```

**配置说明**：
- `enable_reflection: true` - 启用 ExecutionReflector 分析（默认已启用）
- `auto_switch_agent: false` - 是否自动切换 Agent（暂未实现完整切换逻辑）

执行后，失败日志会自动分析，结果保存到：
```
/workspaces/submission/src/shared/{CVE_ID}/{CVE_ID}_execution_analysis.json
```

### 方法 2: 手动调用分析

```python
from agents.executionReflector import (
    ExecutionReflector, 
    AgentExecutionContext,
    create_execution_context_from_log
)

# 从日志文件创建上下文
context = create_execution_context_from_log(
    agent_name='WebDriverAgent',
    cve_id='CVE-2025-54137',
    cve_knowledge="""
    CVE-2025-54137: 使用硬编码凭证漏洞 (CWE-1392)
    默认凭证: admin / password
    API 端点: /api/login
    """,
    log_file_path='/shared/CVE-2025-54137/CVE-2025-54137_dag_log.txt',
    max_iterations=20
)

# 分析失败原因
reflector = ExecutionReflector(model='gpt-4o')
analysis = reflector.analyze(context)

# 查看分析结果
print(f"失败类型: {analysis.failure_type}")
print(f"根本原因: {analysis.root_cause}")
print(f"建议工具: {analysis.suggested_tool}")
print(f"建议 Agent: {analysis.suggested_agent}")
print(f"修正策略:\n{analysis.suggested_strategy}")
```

---

## 分析结果示例

对于 CVE-2025-54137 的分析结果：

```python
ExecutionAnalysis(
    failure_type='tool_misuse',
    root_cause='Agent 使用 navigate_to_url (GET) 访问 API 端点，但应该使用 send_http_request (POST)',
    repeated_pattern='连续20次使用 navigate_to_url，都返回 404',
    suggested_tool='send_http_request',
    suggested_agent='FreestyleAgent',  # 或保持 'none'
    suggested_strategy="""
1. 使用 send_http_request 工具发送 POST 请求到 /api/login
2. 参数：
   - method="POST"
   - url="http://localhost:8080/api/login"
   - data='{"username":"admin","password":"password"}'
   - headers='{"Content-Type":"application/json"}'
3. 期望返回：200 OK 或包含 token 的 JSON 响应
4. 验证：检查返回的 session cookie 或 authentication token
    """,
    confidence=0.95,
    requires_web_search=False
)
```

---

## 输出格式

### 保存的 JSON 文件

`/shared/{CVE_ID}/{CVE_ID}_execution_analysis.json`：

```json
{
  "failure_type": "tool_misuse",
  "root_cause": "Agent 使用 navigate_to_url (GET) 访问 API 端点，但应该使用 send_http_request (POST)",
  "repeated_pattern": "连续20次使用 navigate_to_url，都返回 404",
  "suggested_tool": "send_http_request",
  "suggested_agent": "FreestyleAgent",
  "suggested_strategy": "1. 使用 send_http_request...",
  "confidence": 0.95,
  "requires_web_search": false
}
```

### 控制台输出

```
================================================================================
🔍 ExecutionReflector: 分析 WebDriverAgent 执行失败原因...
================================================================================

⚡ 快速检测到重复模式: 连续 15 次使用 navigate_to_url，其中 15 次返回 404

================================================================================
📋 ExecutionReflector 分析结果
================================================================================

🔴 失败类型: tool_misuse
📌 根本原因: Agent 使用 navigate_to_url (GET) 访问 API 端点...
🔁 重复模式: 连续20次使用 navigate_to_url，都返回 404
🔧 建议工具: send_http_request
🤖 建议切换Agent: FreestyleAgent

💡 修正策略:
1. 使用 send_http_request 工具发送 POST 请求到 /api/login
2. 参数：method="POST", data='{"username":"admin","password":"password"}'
...

📊 置信度: 95.0%

================================================================================
```

---

## 失败类型分类

ExecutionReflector 可以识别的失败类型：

| 类型 | 描述 | 典型场景 |
|------|------|----------|
| `tool_misuse` | 工具使用不当 | 应该用 POST 但用了 GET |
| `missing_credentials` | 缺少凭证信息 | 需要默认用户名/密码 |
| `environment_issue` | 环境问题 | 服务未启动、端口错误 |
| `knowledge_gap` | 知识库不足 | CVE 知识中缺少关键信息 |
| `loop_detected` | 重复循环 | 盲目尝试相同操作 |
| `other` | 其他原因 | 未归类的失败 |

---

## 高级功能

### 1. 联网搜索建议

如果 ExecutionReflector 判断需要补充外部信息：

```python
if analysis.requires_web_search:
    print("🌐 建议搜索:")
    # analysis.search_keywords 提供搜索关键词
    # 例如: "CVE-2025-54137 default credentials, exploit PoC"
```

### 2. 快速模式检测

在调用 LLM 之前，先进行快速检测：

```python
def _quick_detect_pattern(tool_calls, log):
    # 检测相同工具的连续调用
    if tool 被调用超过 10 次 and 80% 返回 404:
        return "连续 N 次使用 X 工具，大量 404 错误"
```

### 3. 日志智能截断

对于超长日志（>1000行），保留关键部分：

```python
# 保留前 100 行 + 后 100 行
truncated_log = lines[:100] + ["... 省略 N 行 ..."] + lines[-100:]
```

---

## 配置选项

### Agent 初始化参数

```python
reflector = ExecutionReflector(
    model='gpt-4o',        # LLM 模型（需要强推理能力）
    temperature=0.0        # 温度（0.0 = 确定性分析）
)
```

### WebDriverAdapter 配置

```python
# 在 DAG step.config 中
{
    "enable_reflection": true,      # 启用/禁用 ExecutionReflector
    "auto_switch_agent": false      # 是否自动切换 Agent（实验性）
}
```

---

## 性能与成本

### LLM 调用成本

- **模型**: GPT-4o（强推理能力）
- **上下文**: 约 3000-5000 tokens（CVE知识 + 日志摘要）
- **输出**: 约 500-1000 tokens（分析结果）
- **估算成本**: 每次分析约 $0.03-0.05

### 何时触发

只在以下情况触发：
1. Agent 执行失败
2. `enable_reflection: true`（默认启用）

**不会影响成功案例的性能**。

---

## 未来改进

### 短期（已规划）

1. ✅ 集成到 WebDriverAdapter - **完成**
2. ✅ 集成到 DAG 执行器 - **完成**
3. ⏳ 实现自动 Agent 切换逻辑
4. ⏳ 集成到 FreestyleAdapter

### 长期（待讨论）

1. 支持多轮对话式修正
2. 学习成功案例，构建知识库
3. 与 DeploymentRecovery 深度集成
4. 实现轻量级联网搜索（可选）

---

## 常见问题

### Q1: ExecutionReflector 和 MidExecReflector 有什么区别？

| 特性 | MidExecReflector | ExecutionReflector |
|------|------------------|-------------------|
| 触发时机 | 执行过程中（每N次失败） | 执行完成后 |
| 视野范围 | 最近几步输出 | 完整执行日志 |
| 分析深度 | 浅（错误类型识别） | 深（根因+策略） |
| 适用场景 | 部署环境构建 | Agent 执行失败 |

**协同工作**：
- MidExecReflector：在 FreestyleAgent 执行命令时检测重复错误
- ExecutionReflector：在 WebDriverAgent 完成后分析整体失败原因

### Q2: 为什么使用 GPT-4o 而不是 gpt-4o-mini？

ExecutionReflector 需要**强推理能力**：
- 分析复杂的执行轨迹
- 识别隐含的工具误用
- 给出可行的修正策略

实验表明，gpt-4o-mini 在这类任务上准确率显著低于 GPT-4o。

### Q3: 如何禁用 ExecutionReflector？

在 DAG step.config 中：

```json
{
  "enable_reflection": false
}
```

或在代码中：

```python
adapter = WebDriverAdapter(result_bus, config={'enable_reflection': False})
```

---

## 示例：完整执行流程

```
1. DAG 执行 WebDriver 步骤
   └─ WebDriverAgent 尝试复现 CVE-2025-54137
      ├─ navigate_to_url('/') → 404
      ├─ navigate_to_url('/login') → 404
      └─ ... (重复 18 次) → 达到最大迭代
   
2. WebDriverAdapter 检测失败
   └─ 调用 ExecutionReflector.analyze()
      ├─ 快速检测: "连续15次404"
      ├─ LLM 分析完整日志
      └─ 生成分析结果
   
3. ExecutionReflector 输出
   ├─ failure_type: tool_misuse
   ├─ suggested_tool: send_http_request
   ├─ suggested_agent: FreestyleAgent (可选)
   └─ suggested_strategy: "使用 POST 到 /api/login..."
   
4. DAG 执行器处理分析结果
   ├─ 保存到 execution_analysis.json
   ├─ 打印建议到控制台
   └─ (可选) 自动切换 Agent 重试
```

---

## 总结

ExecutionReflector 填补了系统的关键能力缺失：

**之前**：Agent 失败 → 报告失败 → 结束
**现在**：Agent 失败 → ExecutionReflector 分析 → 提供改进建议 → (可选) 自动重试

这使得系统能够像人类专家一样：
- 🔍 查看完整日志
- 🧠 分析根本原因
- 💡 提出修正方案
- 🔄 指导下一次尝试

**立即可用**，已集成到 WebDriverAdapter 和 DAGExecutor！
