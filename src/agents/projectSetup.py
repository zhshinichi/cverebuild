"""
ProjectSetupAgent - 负责项目环境准备

职责：
1. 发现工作目录和项目结构
2. 检测框架类型 (Flask/Django/FastAPI/MLflow...)
3. 创建虚拟环境并安装依赖
4. 处理特殊情况 (git submodules, 版本冲突)

输入：cve_entry, cve_knowledge
输出：setup_result (包含 venv_path, framework, start_cmd 等)
"""

import os
from typing import ClassVar, Optional
from agentlib import AgentWithHistory
from toolbox.command_ops import (
    execute_command_foreground,
    execute_command_background
)
from toolbox.web_service_tools import (
    get_project_workspace,
    detect_web_framework,
    install_web_project,
)


class ProjectSetupAgent(AgentWithHistory):
    """项目环境准备 Agent"""
    
    # 类属性 - 指向模板文件
    __SYSTEM_PROMPT_TEMPLATE__ = 'projectSetup/projectSetup.system.j2'
    __USER_PROMPT_TEMPLATE__ = 'projectSetup/projectSetup.user.j2'
    __LLM_MODEL__ = 'gpt-4o-mini'  # 使用轻量级模型
    __MAX_TOOL_ITERATIONS__ = 15
    
    # Pydantic 字段
    cve_id: Optional[str] = None
    sw_name: Optional[str] = None
    sw_version: Optional[str] = None
    cve_knowledge: Optional[str] = None
    
    @classmethod
    def configure(cls, max_iterations: int = None):
        """动态配置 Agent 参数"""
        if max_iterations is not None:
            cls.__MAX_TOOL_ITERATIONS__ = max_iterations
    
    def __init__(self, cve_id: str = None, sw_name: str = None, 
                 sw_version: str = None, cve_knowledge: str = None, **kwargs):
        # 工具集：只包含环境准备相关的工具
        tools = [
            execute_command_foreground,
            execute_command_background,
            get_project_workspace,
            detect_web_framework,
            install_web_project,
        ]
        
        super().__init__(tools=tools, **kwargs)
        self.cve_id = cve_id
        self.sw_name = sw_name
        self.sw_version = sw_version
        self.cve_knowledge = cve_knowledge[:2000] if cve_knowledge else ''
        self.cost = 0
    
    def get_input_vars(self, *args, **kwargs) -> dict:
        """提供模板渲染所需的变量"""
        vars = super().get_input_vars(*args, **kwargs)
        vars.update(
            cve_id=self.cve_id,
            sw_name=self.sw_name,
            sw_version=self.sw_version,
            cve_knowledge=self.cve_knowledge
        )
        return vars
    
    def run(self):
        result = self.invoke({"input": "开始项目环境准备"})
        self.cost = self.get_total_cost() if hasattr(self, 'get_total_cost') else 0
        # 修复: AgentResponse 没有 .get() 方法，使用 .value 属性
        return result.value if hasattr(result, 'value') and result.value else ''
