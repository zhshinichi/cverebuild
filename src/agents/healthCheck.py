"""
HealthCheckAgent - 负责验证服务状态

职责：
1. HTTP 健康检查
2. 日志分析
3. 诊断问题并建议修复

输入：service_result (包含 port, log_file)
输出：health_result (包含 healthy, http_code, diagnosis)
"""

import os
from typing import Optional
from agentlib import AgentWithHistory
from toolbox.command_ops import (
    execute_command_foreground,
)
from toolbox.web_service_tools import (
    diagnose_service_failure,
)


class HealthCheckAgent(AgentWithHistory):
    """健康检查 Agent"""
    
    # 类属性 - 指向模板文件
    __SYSTEM_PROMPT_TEMPLATE__ = 'healthCheck/healthCheck.system.j2'
    __USER_PROMPT_TEMPLATE__ = 'healthCheck/healthCheck.user.j2'
    __LLM_MODEL__ = 'gpt-4o-mini'
    __MAX_TOOL_ITERATIONS__ = 8
    
    # Pydantic 字段
    service_result: Optional[str] = None
    port: Optional[int] = None
    
    @classmethod
    def configure(cls, max_iterations: int = None):
        """动态配置 Agent 参数"""
        if max_iterations is not None:
            cls.__MAX_TOOL_ITERATIONS__ = max_iterations
    
    def __init__(self, service_result: str = None, port: int = None, target_url: str = None, **kwargs):
        # 工具集：扩展诊断能力
        from toolbox.tools import TOOLS
        
        tools = [
            execute_command_foreground,
            diagnose_service_failure,
            TOOLS.get('get_file'),  # 读取日志文件
            TOOLS.get('execute_linux_command'),  # 运行 netstat/ps 等命令
        ]
        # 过滤掉 None 值
        tools = [t for t in tools if t is not None]
        
        super().__init__(tools=tools, **kwargs)
        self.service_result = service_result
        self.port = port
        self.target_url = target_url or f"http://localhost:{port}" if port else "http://localhost:8080"
        self.cost = 0
    
    def get_input_vars(self, *args, **kwargs) -> dict:
        """提供模板渲染所需的变量"""
        vars = super().get_input_vars(*args, **kwargs)
        vars.update(
            service_result=self.service_result,
            port=self.port,
            target_url=self.target_url
        )
        return vars
    
    def run(self):
        result = self.invoke({"input": "开始健康检查"})
        self.cost = self.get_total_cost() if hasattr(self, 'get_total_cost') else 0
        return result.value
