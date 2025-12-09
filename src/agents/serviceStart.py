"""
ServiceStartAgent - 负责启动 Web 服务

职责：
1. 清理旧进程
2. 根据 setup_result 中的信息启动服务
3. 后台运行服务

输入：setup_result (包含 framework, start_cmd, venv_path 等)
输出：service_result (包含 pid, port, log_file)
"""

import os
from typing import Optional
from agentlib import AgentWithHistory
from toolbox.command_ops import (
    execute_command_foreground,
    execute_command_background
)
from toolbox.web_service_tools import (
    cleanup_and_start_service,
    diagnose_service_failure,
)


class ServiceStartAgent(AgentWithHistory):
    """服务启动 Agent"""
    
    # 类属性 - 指向模板文件
    __SYSTEM_PROMPT_TEMPLATE__ = 'serviceStart/serviceStart.system.j2'
    __USER_PROMPT_TEMPLATE__ = 'serviceStart/serviceStart.user.j2'
    __MAX_TOOL_ITERATIONS__ = 10
    
    # Pydantic 字段
    setup_result: Optional[str] = None
    port: Optional[int] = None
    
    @classmethod
    def configure(cls, max_iterations: int = None):
        """动态配置 Agent 参数"""
        if max_iterations is not None:
            cls.__MAX_TOOL_ITERATIONS__ = max_iterations
    
    def __init__(self, setup_result: str = None, port: int = None, **kwargs):
        # 工具集：只包含服务启动相关的工具
        tools = [
            execute_command_foreground,
            execute_command_background,
            cleanup_and_start_service,
            diagnose_service_failure,
        ]
        
        super().__init__(tools=tools, **kwargs)
        self.setup_result = setup_result
        self.port = port
        self.cost = 0
    
    def get_input_vars(self, *args, **kwargs) -> dict:
        """提供模板渲染所需的变量"""
        vars = super().get_input_vars(*args, **kwargs)
        vars.update(
            setup_result=self.setup_result,
            port=self.port
        )
        return vars
    
    def run(self):
        result = self.invoke({"input": "开始启动服务"})
        self.cost = self.get_total_cost() if hasattr(self, 'get_total_cost') else 0
        return result.value if hasattr(result, 'value') else str(result)
