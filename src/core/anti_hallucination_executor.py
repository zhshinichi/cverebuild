"""
Anti-Hallucination Agent Executor
扩展 LangChain AgentExecutor，集成幻觉检测和自动恢复

这个模块解决了 Agent "说但不做" 的问题：
- Agent 说 "I will proceed to install..." 但没有调用工具
- LangChain 将这种纯文本响应视为最终答案
- 我们拦截这种情况，注入反馈强制 Agent 继续

核心机制：
1. 在每次 Agent 返回时检查是否有工具调用
2. 如果是纯文本且匹配幻觉模式，注入强制继续的消息
3. 将 Agent 响应重新包装为中间状态，而不是最终状态
4. 跟踪连续幻觉次数，避免无限循环
"""

from typing import Any, Dict, List, Optional, Sequence, Tuple, Union
from langchain.agents import AgentExecutor
from langchain_core.agents import AgentAction, AgentFinish, AgentStep
from langchain_core.callbacks import CallbackManagerForChainRun
from langchain_core.tools import BaseTool
from langchain_core.messages import AIMessage, HumanMessage

import logging

from core.hallucination_guard import (
    HallucinationDetector,
    HallucinationStats,
    DetectionResult,
    default_detector
)

logger = logging.getLogger(__name__)


class AntiHallucinationAgentExecutor(AgentExecutor):
    """
    带幻觉检测的 Agent 执行器
    
    当检测到 Agent 返回"幻觉式响应"（说要做某事但没有调用工具）时，
    自动注入反馈消息强制 Agent 继续执行。
    
    使用方式：
        executor = AntiHallucinationAgentExecutor(
            agent=agent,
            tools=tools,
            enable_hallucination_guard=True,
            max_hallucination_retries=3
        )
    """
    
    # 配置参数
    enable_hallucination_guard: bool = True
    max_hallucination_retries: int = 3
    hallucination_detector: Optional[HallucinationDetector] = None
    hallucination_stats: Optional[HallucinationStats] = None
    deployment_context: str = ""  # 如 "PHP/Symfony project"
    
    # 运行时状态
    _consecutive_hallucinations: int = 0
    _total_hallucinations: int = 0
    
    def __init__(self, **kwargs):
        # 提取自定义参数
        enable_guard = kwargs.pop('enable_hallucination_guard', True)
        max_retries = kwargs.pop('max_hallucination_retries', 3)
        detector = kwargs.pop('hallucination_detector', None)
        context = kwargs.pop('deployment_context', '')
        
        super().__init__(**kwargs)
        
        self.enable_hallucination_guard = enable_guard
        self.max_hallucination_retries = max_retries
        self.hallucination_detector = detector or default_detector
        self.hallucination_stats = HallucinationStats()
        self.deployment_context = context
        self._consecutive_hallucinations = 0
        self._total_hallucinations = 0
    
    def _check_for_hallucination(
        self, 
        output: Union[AgentAction, AgentFinish, List[AgentAction]],
        intermediate_steps: List[Tuple[AgentAction, str]]
    ) -> Tuple[bool, Optional[str]]:
        """
        检查 Agent 输出是否为幻觉
        
        Args:
            output: Agent 的输出（可能是 AgentFinish 或 AgentAction）
            intermediate_steps: 中间步骤
            
        Returns:
            (is_hallucination, feedback_message)
        """
        if not self.enable_hallucination_guard:
            return False, None
        
        # 只检查 AgentFinish（没有工具调用的最终响应）
        if not isinstance(output, AgentFinish):
            # 有工具调用，不是幻觉
            self._consecutive_hallucinations = 0
            return False, None
        
        # 提取响应文本
        response_text = output.return_values.get('output', '')
        if isinstance(response_text, list):
            response_text = ' '.join(str(x) for x in response_text)
        response_text = str(response_text)
        
        # 检测幻觉
        result = self.hallucination_detector.detect(
            response_text, 
            has_tool_call=False
        )
        self.hallucination_stats.record_check(result)
        
        if result.is_hallucination:
            self._consecutive_hallucinations += 1
            self._total_hallucinations += 1
            
            # 检查是否超过重试限制
            if self._consecutive_hallucinations > self.max_hallucination_retries:
                logger.warning(
                    f"[AntiHallucinationExecutor] Max retries ({self.max_hallucination_retries}) "
                    f"exceeded. Allowing termination."
                )
                return False, None
            
            # 生成反馈消息
            feedback = self.hallucination_detector.get_continuation_prompt(
                result, 
                context=self.deployment_context
            )
            
            logger.warning(
                f"[AntiHallucinationExecutor] 🔴 Hallucination detected! "
                f"Patterns: {result.patterns_matched}, "
                f"Consecutive: {self._consecutive_hallucinations}/{self.max_hallucination_retries}"
            )
            
            return True, feedback
        
        # 检查是否为真正的完成
        if result.is_completed:
            self._consecutive_hallucinations = 0
            logger.info("[AntiHallucinationExecutor] ✅ Task completion detected")
        
        return False, None
    
    def _iter(
        self,
        inputs: Dict[str, str],
        run_manager: Optional[CallbackManagerForChainRun] = None,
    ):
        """
        重写迭代方法，注入幻觉检测
        
        注意：这是核心拦截点。当 Agent 返回 AgentFinish 时，
        我们检查是否为幻觉，如果是则注入反馈并继续迭代。
        """
        # 初始化状态
        intermediate_steps: List[Tuple[AgentAction, str]] = []
        iterations = 0
        self._consecutive_hallucinations = 0
        
        # 名称到工具的映射
        name_to_tool_map = {tool.name: tool for tool in self.tools}
        color_mapping = {}  # 简化，不需要颜色
        
        while self._should_continue(iterations, intermediate_steps):
            try:
                # 调用 Agent 获取下一步动作
                next_step_output = self._take_next_step(
                    name_to_tool_map,
                    color_mapping,
                    inputs,
                    intermediate_steps,
                    run_manager=run_manager,
                )
                
                # 处理输出
                if isinstance(next_step_output, AgentFinish):
                    # 检查幻觉
                    is_hallucination, feedback = self._check_for_hallucination(
                        next_step_output, intermediate_steps
                    )
                    
                    if is_hallucination and feedback:
                        # 🔴 幻觉检测触发：注入反馈并继续
                        logger.warning(
                            f"[AntiHallucinationExecutor] Injecting feedback and continuing..."
                        )
                        self.hallucination_stats.record_continuation()
                        
                        # 将幻觉响应转换为中间步骤
                        # 创建一个虚拟的 AgentAction 来记录这次"失败"的响应
                        hallucination_action = AgentAction(
                            tool="_hallucination_detected",
                            tool_input={"response": next_step_output.return_values.get('output', '')[:200]},
                            log=f"Agent response was detected as hallucination (attempt {self._consecutive_hallucinations})"
                        )
                        intermediate_steps.append((hallucination_action, feedback))
                        
                        # 继续下一次迭代（Agent 会看到反馈）
                        iterations += 1
                        continue
                    
                    # 真正的完成
                    return self._return(
                        next_step_output, intermediate_steps, run_manager=run_manager
                    )
                
                # 不是 AgentFinish，继续正常处理
                intermediate_steps.extend(next_step_output)
                iterations += 1
                
                # 检查工具调用后是否恢复正常
                if self._consecutive_hallucinations > 0:
                    logger.info(
                        "[AntiHallucinationExecutor] ✅ Agent recovered - tool call executed"
                    )
                    self.hallucination_stats.record_recovery()
                    self._consecutive_hallucinations = 0
                
            except Exception as e:
                logger.error(f"[AntiHallucinationExecutor] Error in iteration: {e}")
                raise
        
        # 达到最大迭代次数
        output = self.agent.return_stopped_response(
            self.early_stopping_method, intermediate_steps, **inputs
        )
        return self._return(output, intermediate_steps, run_manager=run_manager)
    
    def get_hallucination_stats(self) -> dict:
        """获取幻觉检测统计"""
        return {
            **self.hallucination_stats.get_summary(),
            "total_hallucinations_this_run": self._total_hallucinations,
        }


def create_anti_hallucination_executor(
    agent,
    tools: Sequence[BaseTool],
    max_iterations: int = 40,
    max_hallucination_retries: int = 3,
    deployment_context: str = "",
    **kwargs
) -> AntiHallucinationAgentExecutor:
    """
    便捷函数：创建带幻觉防护的 Agent 执行器
    
    Args:
        agent: LangChain Agent
        tools: 工具列表
        max_iterations: 最大迭代次数
        max_hallucination_retries: 幻觉检测后的最大重试次数
        deployment_context: 部署上下文（用于生成更好的反馈）
        **kwargs: 其他 AgentExecutor 参数
        
    Returns:
        AntiHallucinationAgentExecutor 实例
    """
    return AntiHallucinationAgentExecutor(
        agent=agent,
        tools=tools,
        max_iterations=max_iterations,
        max_hallucination_retries=max_hallucination_retries,
        deployment_context=deployment_context,
        enable_hallucination_guard=True,
        verbose=kwargs.get('verbose', True),
        handle_parsing_errors=kwargs.get('handle_parsing_errors', True),
        **kwargs
    )


# 为了向后兼容，提供一个包装器
class HallucinationGuardMixin:
    """
    Mixin 类，可以添加到现有的 AgentExecutor 子类中
    
    使用方式：
        class MyExecutor(HallucinationGuardMixin, ExceptionHandlingAgentExecutor):
            pass
    """
    
    enable_hallucination_guard: bool = True
    max_hallucination_retries: int = 3
    _consecutive_hallucinations: int = 0
    
    def check_and_handle_hallucination(
        self, 
        response_text: str,
        has_tool_call: bool = False
    ) -> Tuple[bool, Optional[str]]:
        """
        检查并处理幻觉
        
        Returns:
            (should_continue, feedback_to_inject)
        """
        if not self.enable_hallucination_guard:
            return False, None
        
        if has_tool_call:
            self._consecutive_hallucinations = 0
            return False, None
        
        result = default_detector.detect(response_text, has_tool_call=False)
        
        if result.is_hallucination:
            self._consecutive_hallucinations += 1
            
            if self._consecutive_hallucinations > self.max_hallucination_retries:
                return False, None
            
            feedback = default_detector.get_continuation_prompt(result)
            return True, feedback
        
        return False, None
