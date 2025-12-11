"""
ExecutionReflector Agent - 执行后反思 Agent

当 WebDriverAgent、FreestyleAgent 等执行失败后介入，分析完整日志并提供策略调整建议。
这是一个元级分析 Agent，具有全局视野，能识别重复失败模式并建议修正方案。

设计理念：
- 模拟人类专家的日志分析能力
- 识别工具使用不当（如应该用 POST 但用了 GET）
- 检测重复失败循环
- 建议切换 Agent 或工具集
- 可选：联网搜索 PoC 和 Exploit
"""

import re
import json
from typing import Optional, Dict, Any, List
from dataclasses import dataclass
from agentlib import LLMFunction


@dataclass
class ExecutionAnalysis:
    """执行分析结果"""
    failure_type: str  # tool_misuse, missing_credentials, environment_issue, etc.
    root_cause: str  # 根本原因描述
    repeated_pattern: Optional[str] = None  # 重复失败模式（如"20次都是404"）
    suggested_tool: Optional[str] = None  # 建议使用的工具
    suggested_agent: Optional[str] = None  # 建议切换的 Agent
    suggested_strategy: str = ""  # 具体执行策略
    confidence: float = 0.0  # 置信度 0.0-1.0
    requires_web_search: bool = False  # 是否需要联网搜索


@dataclass
class AgentExecutionContext:
    """Agent 执行上下文"""
    agent_name: str  # WebDriverAgent, FreestyleAgent, etc.
    cve_id: str
    cve_knowledge: str
    execution_log: str  # 完整执行日志
    tool_calls: List[Dict[str, Any]]  # 工具调用历史
    final_status: str  # success, failure, timeout, etc.
    iterations_used: int  # 使用的迭代次数
    max_iterations: int  # 最大迭代次数


class ExecutionReflector:
    """
    执行反思 Agent - 在 Agent 执行失败后分析日志并提供改进建议
    
    核心能力：
    1. 分析完整执行日志（不仅仅是最后输出）
    2. 识别重复失败模式
    3. 诊断根本原因（工具误用、缺少信息、环境问题等）
    4. 建议新的执行策略
    5. 决定是否需要切换 Agent
    6. 可选：联网搜索更多信息
    """
    
    ANALYSIS_PROMPT = """你是一个高级漏洞复现专家和执行分析专家。一个 Agent 执行失败了，你需要分析完整的执行日志，找出根本原因并提供改进建议。

## Agent 信息
- **Agent 类型**: {{ agent_name }}
- **CVE ID**: {{ cve_id }}
- **迭代次数**: {{ iterations_used }}/{{ max_iterations }}
- **最终状态**: {{ final_status }}

## CVE 知识库
{{ cve_knowledge }}

## 完整执行日志
{{ execution_log }}

## 工具调用历史（最近20次）
{{ tool_calls_summary }}

---

## 分析任务

请深入分析以上信息，回答以下问题：

### 1. Agent 在做什么？
识别 Agent 的执行模式：
- 是否在重复相同的操作？
- 是否尝试了多种策略？
- 使用了哪些工具？

### 2. 为什么失败？
诊断根本原因：
- **工具误用**：例如应该用 `send_http_request(POST)` 但用了 `navigate_to_url(GET)`
- **缺少信息**：例如缺少默认凭证、API 端点、请求方法
- **环境问题**：服务未启动、端口错误、网络不通
- **策略错误**：盲目尝试、没有分析错误消息
- **CVE 知识不足**：知识库中缺少关键信息

### 3. 应该怎么改？
提供具体的修正建议：
- **工具切换**：建议使用哪个工具，如何使用
- **Agent 切换**：是否应该切换到其他 Agent（如 WebDriver → Freestyle）
- **补充信息**：需要搜索哪些额外信息（默认凭证、PoC、API 文档）
- **执行策略**：具体的步骤调整

### 4. 是否需要联网搜索？
判断是否需要搜索外部资源：
- 搜索默认凭证
- 搜索 PoC 代码
- 搜索 API 文档

---

## 输出格式

请严格按以下 XML 格式输出：

<failure_type>
[failure_type: tool_misuse | missing_credentials | environment_issue | knowledge_gap | loop_detected | other]
</failure_type>

<root_cause>
[根本原因的简洁描述，1-2句话]
</root_cause>

<repeated_pattern>
[如果检测到重复失败模式，描述它。例如："连续20次使用 navigate_to_url 访问不同URL，都返回404"。如果没有重复模式，填 "none"]
</repeated_pattern>

<suggested_tool>
[建议使用的工具名称，如 "send_http_request"。如果不需要切换工具，填 "none"]
</suggested_tool>

<suggested_agent>
[建议切换的 Agent 名称，如 "FreestyleAgent"。如果不需要切换，填 "none"]
</suggested_agent>

<suggested_strategy>
[具体的执行策略，包括：
1. 应该使用什么工具
2. 具体的参数（如 URL、method、data）
3. 期望的结果
4. 验证方法

例如：
1. 使用 send_http_request 工具发送 POST 请求到 /api/login
2. 参数：method="POST", data='{"username":"admin","password":"password"}', headers='{"Content-Type":"application/json"}'
3. 期望返回：200 OK 或登录成功的 JSON 响应
4. 验证：检查返回的 token 或 session cookie
]
</suggested_strategy>

<confidence>
[置信度 0.0-1.0]
</confidence>

<requires_web_search>
[是否需要联网搜索: true | false]
</requires_web_search>

<search_keywords>
[如果需要搜索，提供关键词，用逗号分隔。例如："CVE-2025-54137 default credentials,CVE-2025-54137 exploit PoC,API authentication bypass"。如果不需要搜索，填 "none"]
</search_keywords>
"""

    def __init__(self, model: str = 'gpt-4o', temperature: float = 0.0):
        """
        初始化 ExecutionReflector
        
        Args:
            model: LLM 模型（默认 gpt-4o，需要强推理能力）
            temperature: 温度（0.0 = 确定性分析）
        """
        self.model = model
        self.temperature = temperature
        self._reflector_llm = None
    
    def analyze(self, context: AgentExecutionContext) -> ExecutionAnalysis:
        """
        分析 Agent 执行失败的原因并提供改进建议
        
        Args:
            context: Agent 执行上下文
        
        Returns:
            ExecutionAnalysis: 分析结果
        """
        print(f"\n{'='*80}")
        print(f"🔍 ExecutionReflector: 分析 {context.agent_name} 执行失败原因...")
        print(f"{'='*80}\n")
        
        # 1. 预处理工具调用历史
        tool_calls_summary = self._format_tool_calls(context.tool_calls)
        
        # 2. 检测重复模式（快速检测）
        quick_pattern = self._quick_detect_pattern(context.tool_calls, context.execution_log)
        if quick_pattern:
            print(f"⚡ 快速检测到重复模式: {quick_pattern}")
        
        # 3. 创建 LLM 分析函数
        if not self._reflector_llm:
            self._reflector_llm = LLMFunction.create(
                self.ANALYSIS_PROMPT,
                model=self.model,
                temperature=self.temperature
            )
        
        # 4. 调用 LLM 分析
        response = self._reflector_llm(
            agent_name=context.agent_name,
            cve_id=context.cve_id,
            cve_knowledge=context.cve_knowledge[:3000],  # 限制长度
            execution_log=self._truncate_log(context.execution_log, max_lines=200),
            tool_calls_summary=tool_calls_summary,
            iterations_used=context.iterations_used,
            max_iterations=context.max_iterations,
            final_status=context.final_status
        )
        
        # 5. 解析响应
        analysis = self._parse_response(response, quick_pattern)
        
        # 6. 打印分析结果
        self._print_analysis(analysis)
        
        return analysis
    
    def _format_tool_calls(self, tool_calls: List[Dict[str, Any]]) -> str:
        """格式化工具调用历史"""
        if not tool_calls:
            return "无工具调用记录"
        
        # 只取最近 20 次
        recent_calls = tool_calls[-20:]
        
        formatted = []
        for i, call in enumerate(recent_calls, 1):
            tool_name = call.get('tool', 'unknown')
            args = call.get('args', {})
            result = call.get('result', '')
            
            # 截断长结果
            if isinstance(result, str) and len(result) > 200:
                result = result[:200] + "..."
            
            formatted.append(f"{i}. {tool_name}({self._format_args(args)}) → {result}")
        
        return '\n'.join(formatted)
    
    def _format_args(self, args: Dict[str, Any]) -> str:
        """格式化工具参数"""
        if not args:
            return ""
        
        # 只显示关键参数
        key_params = ['url', 'method', 'path', 'command', 'username', 'password']
        formatted = []
        
        for key in key_params:
            if key in args:
                value = args[key]
                if isinstance(value, str) and len(value) > 50:
                    value = value[:50] + "..."
                formatted.append(f"{key}={repr(value)}")
        
        # 如果没有关键参数，显示前3个参数
        if not formatted:
            for key, value in list(args.items())[:3]:
                if isinstance(value, str) and len(value) > 50:
                    value = value[:50] + "..."
                formatted.append(f"{key}={repr(value)}")
        
        return ', '.join(formatted)
    
    def _quick_detect_pattern(self, tool_calls: List[Dict[str, Any]], log: str) -> Optional[str]:
        """快速检测重复失败模式"""
        if not tool_calls or len(tool_calls) < 5:
            return None
        
        # 检测相同工具的连续调用
        recent = tool_calls[-15:]
        tool_counts = {}
        
        for call in recent:
            tool = call.get('tool', '')
            tool_counts[tool] = tool_counts.get(tool, 0) + 1
        
        # 如果某个工具被调用超过 10 次
        for tool, count in tool_counts.items():
            if count >= 10:
                # 检查是否都失败
                failures = sum(1 for c in recent if c.get('tool') == tool and '404' in str(c.get('result', '')))
                if failures >= count * 0.8:  # 80% 失败率
                    return f"连续 {count} 次使用 {tool}，其中 {failures} 次返回 404"
        
        # 检测日志中的重复错误
        if log.count('404') > 15:
            return "大量404错误（可能在盲目尝试不同URL）"
        
        return None
    
    def _truncate_log(self, log: str, max_lines: int = 200) -> str:
        """截断日志，保留关键部分"""
        lines = log.split('\n')
        
        if len(lines) <= max_lines:
            return log
        
        # 保留前 100 行和后 100 行
        half = max_lines // 2
        truncated = lines[:half] + [
            "",
            f"... [省略 {len(lines) - max_lines} 行] ...",
            ""
        ] + lines[-half:]
        
        return '\n'.join(truncated)
    
    def _parse_response(self, response: str, quick_pattern: Optional[str]) -> ExecutionAnalysis:
        """解析 LLM 响应"""
        # 提取 XML 标签内容
        def extract_tag(tag_name: str, default: str = "") -> str:
            pattern = f'<{tag_name}>(.*?)</{tag_name}>'
            match = re.search(pattern, response, re.DOTALL | re.IGNORECASE)
            return match.group(1).strip() if match else default
        
        failure_type = extract_tag('failure_type', 'other')
        root_cause = extract_tag('root_cause', '未知原因')
        repeated_pattern = extract_tag('repeated_pattern', quick_pattern or 'none')
        suggested_tool = extract_tag('suggested_tool', 'none')
        suggested_agent = extract_tag('suggested_agent', 'none')
        suggested_strategy = extract_tag('suggested_strategy', '无具体建议')
        confidence_str = extract_tag('confidence', '0.5')
        requires_search_str = extract_tag('requires_web_search', 'false')
        
        # 解析置信度
        try:
            confidence = float(confidence_str)
        except ValueError:
            confidence = 0.5
        
        # 解析是否需要搜索
        requires_search = requires_search_str.lower() in ['true', 'yes', '1']
        
        return ExecutionAnalysis(
            failure_type=failure_type,
            root_cause=root_cause,
            repeated_pattern=repeated_pattern if repeated_pattern != 'none' else None,
            suggested_tool=suggested_tool if suggested_tool != 'none' else None,
            suggested_agent=suggested_agent if suggested_agent != 'none' else None,
            suggested_strategy=suggested_strategy,
            confidence=confidence,
            requires_web_search=requires_search
        )
    
    def _print_analysis(self, analysis: ExecutionAnalysis):
        """打印分析结果"""
        print(f"\n{'='*80}")
        print(f"📋 ExecutionReflector 分析结果")
        print(f"{'='*80}\n")
        
        print(f"🔴 失败类型: {analysis.failure_type}")
        print(f"📌 根本原因: {analysis.root_cause}")
        
        if analysis.repeated_pattern:
            print(f"🔁 重复模式: {analysis.repeated_pattern}")
        
        if analysis.suggested_tool:
            print(f"🔧 建议工具: {analysis.suggested_tool}")
        
        if analysis.suggested_agent:
            print(f"🤖 建议切换Agent: {analysis.suggested_agent}")
        
        print(f"\n💡 修正策略:\n{analysis.suggested_strategy}")
        
        print(f"\n📊 置信度: {analysis.confidence:.1%}")
        
        if analysis.requires_web_search:
            print(f"🌐 需要联网搜索补充信息")
        
        print(f"\n{'='*80}\n")


# ============================================================
# 工具函数：从执行日志中提取工具调用
# ============================================================

def extract_tool_calls_from_log(log: str) -> List[Dict[str, Any]]:
    """
    从执行日志中提取工具调用历史
    
    这个函数尝试从日志中解析工具调用，适用于没有结构化工具调用记录的情况。
    
    Args:
        log: 执行日志
    
    Returns:
        List[Dict]: 工具调用列表
    """
    tool_calls = []
    
    # 匹配工具调用模式（根据实际日志格式调整）
    # 示例: [Tool] navigate_to_url(url='http://...') → 404
    pattern = r'\[Tool\]\s+(\w+)\((.*?)\)\s*→\s*(.*?)(?:\n|$)'
    
    for match in re.finditer(pattern, log, re.MULTILINE):
        tool_name = match.group(1)
        args_str = match.group(2)
        result = match.group(3).strip()
        
        # 简单解析参数（更复杂的解析可能需要 AST）
        args = {}
        for arg in args_str.split(','):
            if '=' in arg:
                key, value = arg.split('=', 1)
                args[key.strip()] = value.strip().strip("'\"")
        
        tool_calls.append({
            'tool': tool_name,
            'args': args,
            'result': result
        })
    
    return tool_calls


def create_execution_context_from_log(
    agent_name: str,
    cve_id: str,
    cve_knowledge: str,
    log_file_path: str,
    max_iterations: int = 40
) -> AgentExecutionContext:
    """
    从日志文件创建执行上下文（便捷函数）
    
    Args:
        agent_name: Agent 名称
        cve_id: CVE ID
        cve_knowledge: CVE 知识库
        log_file_path: 日志文件路径
        max_iterations: 最大迭代次数
    
    Returns:
        AgentExecutionContext
    """
    # 读取日志
    with open(log_file_path, 'r', encoding='utf-8') as f:
        log = f.read()
    
    # 提取工具调用
    tool_calls = extract_tool_calls_from_log(log)
    
    # 推断最终状态
    if 'success' in log.lower() or 'passed' in log.lower():
        final_status = 'success'
    elif 'timeout' in log.lower() or 'max iteration' in log.lower():
        final_status = 'timeout'
    else:
        final_status = 'failure'
    
    # 推断使用的迭代次数
    iterations_used = len(tool_calls) if tool_calls else max_iterations
    
    return AgentExecutionContext(
        agent_name=agent_name,
        cve_id=cve_id,
        cve_knowledge=cve_knowledge,
        execution_log=log,
        tool_calls=tool_calls,
        final_status=final_status,
        iterations_used=iterations_used,
        max_iterations=max_iterations
    )


# ============================================================
# 示例用法
# ============================================================

if __name__ == '__main__':
    """
    示例：分析 CVE-2025-54137 的执行失败
    """
    # 假设我们有一个日志文件
    log_path = "/shared/CVE-2025-54137/CVE-2025-54137_dag_log.txt"
    
    # CVE 知识
    cve_knowledge = """
    CVE-2025-54137: 使用硬编码凭证漏洞 (CWE-1392)
    
    漏洞类型: API 凭证漏洞
    默认凭证: admin / password
    API 端点: /api/login
    请求方法: POST
    Content-Type: application/json
    Payload: {"username":"admin","password":"password"}
    """
    
    try:
        # 创建执行上下文
        context = create_execution_context_from_log(
            agent_name='WebDriverAgent',
            cve_id='CVE-2025-54137',
            cve_knowledge=cve_knowledge,
            log_file_path=log_path,
            max_iterations=20
        )
        
        # 分析失败原因
        reflector = ExecutionReflector(model='gpt-4o')
        analysis = reflector.analyze(context)
        
        # 根据分析结果采取行动
        if analysis.suggested_agent == 'FreestyleAgent':
            print("💡 建议：切换到 FreestyleAgent 重新尝试")
        
        if analysis.requires_web_search:
            print("🌐 建议：搜索更多 PoC 和默认凭证信息")
    
    except FileNotFoundError:
        print(f"⚠️ 日志文件不存在: {log_path}")
        print("这是一个示例代码，请替换为实际的日志文件路径")
