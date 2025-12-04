"""
WebEnvBuilder Agent
专门用于 Web 漏洞的环境部署

与 RepoBuilder 的区别：
- RepoBuilder: 需要 dir_tree，适合需要从源码编译的本地漏洞
- WebEnvBuilder: 不需要 dir_tree，专门处理 Web 应用部署
  - 支持从 sw_version_wget 下载源码
  - 支持 docker-compose 部署
  - 支持 pip/npm 依赖安装
  - 自动启动 Web 服务并返回访问地址
"""

import re
import os

from agentlib import AgentWithHistory, LLMFunction
from agentlib.lib.common.parsers import BaseParser
from typing import Optional

from toolbox.tools import TOOLS
from toolbox.web_service_tools import WEB_SERVICE_TOOLS


OUTPUT_DESCRIPTION = '''
After completing the deployment, you MUST output the result in JSON format:

```json
{
    "success": "yes" or "no",
    "access": "http://localhost:9600",
    "method": "docker-compose" or "dockerfile" or "pip" or "npm" or "pre-deployed",
    "notes": "Deployment notes or error message"
}
```
'''


class WebEnvBuilderParser(BaseParser):
    """解析 WebEnvBuilder 的 JSON 输出"""
    MAX_FIX_FORMAT_TRIES = 3

    def get_format_instructions(self) -> str:
        return OUTPUT_DESCRIPTION

    def invoke(self, msg, *args, **kwargs) -> dict | str:
        response = msg['output']
        if isinstance(response, list):
            response = ' '.join(response)
        if response == 'Agent stopped due to max iterations.':
            return {'success': 'no', 'access': '', 'method': 'none', 'notes': response}
        return self.parse(response)

    def fix_format(self, text: str) -> str:
        fix_llm = LLMFunction.create(
            'Extract the deployment result from the text and format as JSON.\n\n# TEXT\n{{ info.text }}\n\n# OUTPUT FORMAT\n{{ info.output_format }}',
            model='gpt-4o-mini',
            temperature=0.0
        )
        fixed_text = fix_llm(
            info=dict(
                text=text,
                output_format=self.get_format_instructions()
            )
        )
        return fixed_text

    def parse(self, text: str) -> dict:
        import json
        
        # 尝试直接解析 JSON
        try:
            # 查找 JSON 块
            json_match = re.search(r'```json\s*(\{.*?\})\s*```', text, re.DOTALL)
            if json_match:
                return json.loads(json_match.group(1))
            
            # 查找裸 JSON
            json_match = re.search(r'\{[^{}]*"success"[^{}]*\}', text, re.DOTALL)
            if json_match:
                return json.loads(json_match.group(0))
        except json.JSONDecodeError:
            pass
        
        # 尝试修复格式
        try_itr = 1
        while try_itr <= self.MAX_FIX_FORMAT_TRIES:
            try:
                fixed = self.fix_format(text)
                json_match = re.search(r'\{.*?\}', fixed, re.DOTALL)
                if json_match:
                    return json.loads(json_match.group(0))
            except:
                pass
            try_itr += 1
        
        # 返回默认失败结果
        return {
            'success': 'no',
            'access': '',
            'method': 'none',
            'notes': f'Failed to parse output: {text[:200]}'
        }


class WebEnvBuilder(AgentWithHistory[dict, dict]):
    """
    Web 环境构建 Agent
    
    负责部署 Web 漏洞的目标环境，支持多种部署方式：
    1. Docker Compose 部署（如果存在 docker-compose.yml）
    2. Dockerfile 构建
    3. 从 GitHub 下载并安装依赖 (pip/npm)
    4. 直接使用已知的服务 URL
    
    v2: 使用智能工具而不是冗长的 prompt
    - detect_web_framework: 自动检测框架和启动方式
    - install_web_project: 智能安装（PyPI 优先）
    - cleanup_and_start_service: 清理+启动+健康检查
    - diagnose_service_failure: 错误诊断
    """
    
    __LLM_MODEL__ = 'gpt-4o-mini'
    # 使用简化版 prompt（v2 版本依赖智能工具，prompt 更短）
    __SYSTEM_PROMPT_TEMPLATE__ = 'webEnvBuilder/webEnvBuilder.system.v2.j2'
    __USER_PROMPT_TEMPLATE__ = 'webEnvBuilder/webEnvBuilder.user.v2.j2'
    __OUTPUT_PARSER__ = WebEnvBuilderParser
    __MAX_TOOL_ITERATIONS__ = 40
    
    CVE_KNOWLEDGE: Optional[str]
    SW_VERSION_WGET: Optional[str]
    SW_VERSION: Optional[str]
    PREREQUISITES: Optional[dict]
    FEEDBACK: Optional[str]
    
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.CVE_KNOWLEDGE = kwargs.get('cve_knowledge', '')
        self.SW_VERSION_WGET = kwargs.get('sw_version_wget', '')
        self.SW_VERSION = kwargs.get('sw_version', '')
        self.PREREQUISITES = kwargs.get('prerequisites', {})
        self.FEEDBACK = kwargs.get('feedback', '')
    
    def get_input_vars(self, *args, **kwargs) -> dict:
        vars = super().get_input_vars(*args, **kwargs)
        vars.update(
            cve_knowledge=self.CVE_KNOWLEDGE,
            sw_version_wget=self.SW_VERSION_WGET,
            sw_version=self.SW_VERSION,
            prerequisites=self.PREREQUISITES,
            feedback=self.FEEDBACK,
        )
        return vars
    
    def get_available_tools(self):
        """
        返回可用工具
        
        包含两类工具：
        1. 基础工具：文件操作、命令执行
        2. 智能工具：框架检测、服务管理（封装复杂逻辑，减少 prompt 负担）
        """
        # 基础工具
        base_tools = [
            'get_file',
            'write_to_file',
            'execute_ls_command',
            'execute_linux_command',
            'set_environment_variable'
        ]
        tools_list = [TOOLS[name] for name in base_tools if name in TOOLS]
        
        # 添加智能 Web 服务工具
        # 这些工具封装了复杂逻辑，让 Agent 按需调用而不是记忆冗长的规则
        for tool in WEB_SERVICE_TOOLS.values():
            tools_list.append(tool)
        
        return tools_list
    
    def get_cost(self, *args, **kw) -> float:
        total_cost = 0
        for model_name, token_usage in self.token_usage.items():
            total_cost += token_usage.get_costs(model_name)['total_cost']
        return total_cost


# 测试代码
if __name__ == "__main__":
    test_knowledge = """
    CVE-2024-2288 is a CSRF vulnerability in lollms-webui.
    The vulnerable endpoint is the profile picture upload functionality.
    """
    
    agent = WebEnvBuilder(
        cve_knowledge=test_knowledge,
        sw_version_wget="https://github.com/parisneo/lollms-webui/archive/refs/tags/v9.2.zip",
        sw_version="v9.2",
    )
    
    print("WebEnvBuilder Agent initialized successfully")
