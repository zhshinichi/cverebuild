"""
Hallucination Guard Module
检测并阻止 Agent 幻觉式停止（说 "I will proceed" 但没有实际调用工具）

P1 优化：代码级别检测不完整信号

问题描述：
- Agent 经常返回 "I will proceed to install..." 但没有调用任何工具
- LangChain 将这种纯文本响应视为最终答案并停止执行
- 导致部署任务提前终止，没有完成所有步骤

解决方案：
- 创建 HallucinationDetector 检测不完整信号
- 扩展 AgentExecutor 来拦截幻觉响应
- 自动注入反馈强制 Agent 继续执行
"""

import re
from typing import List, Dict, Tuple, Optional
from dataclasses import dataclass, field


@dataclass
class HallucinationPattern:
    """幻觉模式定义"""
    name: str
    patterns: List[str]  # 正则表达式模式
    severity: str = "high"  # high, medium, low
    requires_tool_call: bool = True  # 是否要求后续必须有工具调用
    auto_feedback: str = ""  # 检测到时自动注入的反馈


# 预定义的幻觉模式
HALLUCINATION_PATTERNS = [
    HallucinationPattern(
        name="will_proceed",
        patterns=[
            r"i will (?:now )?proceed",
            r"i(?:'ll| will) (?:now )?(?:continue|go ahead|move on)",
            r"let(?:'s| me) proceed",
            r"proceeding to",
            r"will now (?:install|deploy|start|run|execute|build)",
        ],
        severity="high",
        requires_tool_call=True,
        auto_feedback=(
            "CRITICAL: You said you would proceed but did NOT call any tools. "
            "You MUST call a tool NOW to perform the action. "
            "Do NOT describe actions - EXECUTE them with tools."
        )
    ),
    HallucinationPattern(
        name="next_step_announcement",
        patterns=[
            r"next,? i(?:'ll| will)",
            r"the next step is to",
            r"now i need to",
            r"now i should",
            r"i(?:'ll| will) (?:then|next)",
        ],
        severity="high",
        requires_tool_call=True,
        auto_feedback=(
            "CRITICAL: You announced the next step but didn't execute it. "
            "STOP describing - START executing. Call the appropriate tool NOW."
        )
    ),
    HallucinationPattern(
        name="going_to",
        patterns=[
            r"(?:am |'m )?going to (?:install|deploy|start|run|execute|build|download|clone)",
            r"about to (?:install|deploy|start|run|execute|build)",
            r"ready to (?:install|deploy|start|run|execute|build)",
        ],
        severity="high",
        requires_tool_call=True,
        auto_feedback=(
            "CRITICAL: You said you're going to do something but didn't do it. "
            "Execute the action NOW using the appropriate tool."
        )
    ),
    HallucinationPattern(
        name="let_me",
        patterns=[
            r"let me (?:install|deploy|start|run|execute|build|download|clone|check)",
            r"allow me to",
            r"i(?:'ll| will) (?:first|now) (?:check|verify|confirm)",
        ],
        severity="medium",
        requires_tool_call=True,
        auto_feedback=(
            "You indicated you would perform an action but no tool was called. "
            "Please execute the action using the appropriate tool."
        )
    ),
    HallucinationPattern(
        name="should_do",
        patterns=[
            r"i should (?:now )?(?:install|deploy|start|run|execute)",
            r"we should (?:now )?(?:install|deploy|start|run|execute)",
            r"need to (?:install|deploy|start|run|execute)",
        ],
        severity="medium",
        requires_tool_call=True,
        auto_feedback=(
            "You identified what needs to be done but didn't execute it. "
            "Please call the appropriate tool to perform the action."
        )
    ),
]

# 表示任务已完成的模式（这些情况下不应该触发幻觉检测）
COMPLETION_PATTERNS = [
    r"deployment (?:is )?complete",
    r"successfully deployed",
    r"service is (?:now )?running",
    r"verification (?:is )?complete",
    r"all steps completed",
    r"task (?:is )?finished",
    r"\"success\":\s*\"yes\"",
    r"http://localhost:\d+",  # 返回了访问地址
]


@dataclass
class DetectionResult:
    """检测结果"""
    is_hallucination: bool = False
    patterns_matched: List[str] = field(default_factory=list)
    severity: str = "none"
    feedback: str = ""
    original_text: str = ""
    has_tool_call: bool = False
    is_completed: bool = False


class HallucinationDetector:
    """
    幻觉检测器
    
    检测 Agent 响应中的"幻觉式停止"模式：
    - Agent 说要做某事但没有调用工具
    - 使用未来时态描述动作而不是执行动作
    """
    
    def __init__(self, 
                 custom_patterns: Optional[List[HallucinationPattern]] = None,
                 strict_mode: bool = True):
        """
        初始化检测器
        
        Args:
            custom_patterns: 自定义的幻觉模式列表
            strict_mode: 严格模式下，任何匹配都会触发
        """
        self.patterns = HALLUCINATION_PATTERNS.copy()
        if custom_patterns:
            self.patterns.extend(custom_patterns)
        self.strict_mode = strict_mode
        self.completion_patterns = [re.compile(p, re.IGNORECASE) for p in COMPLETION_PATTERNS]
        
        # 预编译所有模式
        self._compiled_patterns: Dict[str, List[re.Pattern]] = {}
        for pattern in self.patterns:
            self._compiled_patterns[pattern.name] = [
                re.compile(p, re.IGNORECASE) for p in pattern.patterns
            ]
    
    def _is_task_completed(self, text: str) -> bool:
        """检查任务是否已完成"""
        text_lower = text.lower()
        for pattern in self.completion_patterns:
            if pattern.search(text_lower):
                return True
        return False
    
    def detect(self, 
               agent_response: str,
               has_tool_call: bool = False,
               tool_calls: Optional[List[dict]] = None) -> DetectionResult:
        """
        检测 Agent 响应是否为幻觉
        
        Args:
            agent_response: Agent 的文本响应
            has_tool_call: 这次响应是否包含工具调用
            tool_calls: 工具调用列表（如果有）
            
        Returns:
            DetectionResult: 检测结果
        """
        result = DetectionResult(
            original_text=agent_response,
            has_tool_call=has_tool_call
        )
        
        # 检查是否已完成
        if self._is_task_completed(agent_response):
            result.is_completed = True
            return result
        
        # 如果有工具调用，不是幻觉
        if has_tool_call and tool_calls:
            result.has_tool_call = True
            return result
        
        # 检查幻觉模式
        text_lower = agent_response.lower()
        matched_patterns = []
        max_severity = "none"
        feedback_parts = []
        
        for pattern in self.patterns:
            for compiled in self._compiled_patterns[pattern.name]:
                if compiled.search(text_lower):
                    # 如果模式要求工具调用但没有，则是幻觉
                    if pattern.requires_tool_call and not has_tool_call:
                        matched_patterns.append(pattern.name)
                        if pattern.auto_feedback:
                            feedback_parts.append(pattern.auto_feedback)
                        
                        # 更新最高严重级别
                        severity_order = {"high": 3, "medium": 2, "low": 1, "none": 0}
                        if severity_order.get(pattern.severity, 0) > severity_order.get(max_severity, 0):
                            max_severity = pattern.severity
                    break
        
        if matched_patterns:
            result.is_hallucination = True
            result.patterns_matched = matched_patterns
            result.severity = max_severity
            # 合并反馈，去重
            unique_feedback = list(dict.fromkeys(feedback_parts))
            result.feedback = " ".join(unique_feedback[:2])  # 最多取两个
        
        return result
    
    def get_continuation_prompt(self, detection_result: DetectionResult, context: str = "") -> str:
        """
        生成强制继续执行的提示
        
        Args:
            detection_result: 检测结果
            context: 额外的上下文信息（如当前部署阶段）
            
        Returns:
            强制继续执行的提示文本
        """
        if not detection_result.is_hallucination:
            return ""
        
        base_prompt = detection_result.feedback or (
            "CRITICAL: You must call a tool to execute actions. "
            "Do not describe what you will do - actually do it."
        )
        
        continuation_prompt = f"""
⚠️ HALLUCINATION DETECTED - ACTION REQUIRED ⚠️

{base_prompt}

RULES:
1. Every action statement MUST be followed by a tool call
2. Do NOT use future tense ("I will...") without immediate tool execution
3. If you say "I will install X", you MUST call execute_linux_command with the install command
4. The task is NOT complete until you verify the service is running

{f"Current context: {context}" if context else ""}

YOUR NEXT RESPONSE MUST INCLUDE A TOOL CALL.
"""
        return continuation_prompt.strip()


class HallucinationStats:
    """幻觉统计跟踪"""
    
    def __init__(self):
        self.total_checks = 0
        self.hallucinations_detected = 0
        self.hallucinations_by_pattern: Dict[str, int] = {}
        self.continuations_forced = 0
        self.successful_recoveries = 0
    
    def record_check(self, result: DetectionResult):
        """记录一次检查"""
        self.total_checks += 1
        if result.is_hallucination:
            self.hallucinations_detected += 1
            for pattern in result.patterns_matched:
                self.hallucinations_by_pattern[pattern] = \
                    self.hallucinations_by_pattern.get(pattern, 0) + 1
    
    def record_continuation(self, forced: bool = True):
        """记录强制继续"""
        if forced:
            self.continuations_forced += 1
    
    def record_recovery(self, successful: bool = True):
        """记录恢复结果"""
        if successful:
            self.successful_recoveries += 1
    
    def get_summary(self) -> dict:
        """获取统计摘要"""
        return {
            "total_checks": self.total_checks,
            "hallucinations_detected": self.hallucinations_detected,
            "detection_rate": (
                self.hallucinations_detected / self.total_checks 
                if self.total_checks > 0 else 0
            ),
            "patterns_breakdown": self.hallucinations_by_pattern,
            "continuations_forced": self.continuations_forced,
            "successful_recoveries": self.successful_recoveries,
            "recovery_rate": (
                self.successful_recoveries / self.continuations_forced 
                if self.continuations_forced > 0 else 0
            )
        }


# 全局检测器实例（可被导入使用）
default_detector = HallucinationDetector()


def detect_hallucination(text: str, has_tool_call: bool = False) -> DetectionResult:
    """便捷函数：检测文本是否为幻觉"""
    return default_detector.detect(text, has_tool_call)


def get_continuation_feedback(text: str, context: str = "") -> Optional[str]:
    """
    便捷函数：如果检测到幻觉，返回继续执行的反馈
    
    Args:
        text: Agent 响应文本
        context: 上下文（如 "deploying Symfony project"）
        
    Returns:
        如果是幻觉返回反馈文本，否则返回 None
    """
    result = detect_hallucination(text, has_tool_call=False)
    if result.is_hallucination:
        return default_detector.get_continuation_prompt(result, context)
    return None


# 测试代码
if __name__ == "__main__":
    detector = HallucinationDetector()
    
    # 测试案例
    test_cases = [
        ("I will proceed to install the dependencies using Composer.", False),
        ("Let me install the packages now.", False),
        ("The next step is to start the service.", False),
        ("Now I need to run npm install.", False),
        ("Deployment is complete. The service is running at http://localhost:8080", False),
        ("Installing dependencies...", True),  # 有工具调用，不是幻觉
        ('{"success": "yes", "access": "http://localhost:9600"}', False),
    ]
    
    print("=" * 60)
    print("Hallucination Detector Test")
    print("=" * 60)
    
    for text, has_tool in test_cases:
        result = detector.detect(text, has_tool_call=has_tool)
        status = "🔴 HALLUCINATION" if result.is_hallucination else (
            "✅ COMPLETED" if result.is_completed else "⚪ NORMAL"
        )
        print(f"\n{status}: {text[:60]}...")
        if result.is_hallucination:
            print(f"   Patterns: {result.patterns_matched}")
            print(f"   Severity: {result.severity}")
