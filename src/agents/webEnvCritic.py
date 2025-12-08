"""
WebEnvCritic - Web 环境部署评审 Agent

功能：
- 分析 WebEnvBuilder/WebAppDeployer 的部署日志
- 识别部署失败的根本原因
- 提供具体的改进建议（feedback）
- 决定是否值得重试

类似 RepoCritic，但专注于 Web 应用部署场景
"""

import re
from agentlib import AgentWithHistory
from agentlib.lib.common.parsers import BaseParser
from typing import Optional

OUTPUT_DESCRIPTION = '''
After analyzing the deployment logs, you MUST output in the following format:

```
<report>
<analysis>...</analysis>
<decision>...</decision>
<possible>...</possible>
<feedback>...</feedback>
</report>
```

Within <analysis></analysis>: Analyze what went wrong in the deployment
Within <decision></decision>: "yes" if deployment succeeded, "no" if failed
Within <possible></possible>: "yes" if fixable, "no" if not (use "n/a" if succeeded)
Within <feedback></feedback>: Specific actionable feedback (use "n/a" if succeeded or unfixable)

IMPORTANT: Provide CONCRETE feedback with exact commands/fixes, not generic advice.
'''


class WebEnvCriticParser(BaseParser):
    MAX_FIX_FORMAT_TRIES = 3

    def get_format_instructions(self) -> str:
        return OUTPUT_DESCRIPTION

    def invoke(self, msg, *args, **kwargs) -> dict:
        response = msg.content if hasattr(msg, 'content') else str(msg)
        if isinstance(response, list):
            response = ' '.join(response)
        return self.parse(response)
    
    def fix_format(self, text: str) -> str:
        from agentlib import LLMFunction
        fix_llm = LLMFunction.create(
            'Fix the format according to instructions.\n\n# CURRENT REPORT\n{{ info.current_report }}\n\n# OUTPUT FORMAT\n{{ info.output_format }}',
            model='gpt-4o-mini',
            temperature=0.0
        )
        return fix_llm(info=dict(current_report=text, output_format=self.get_format_instructions()))
    
    def parse(self, text: str) -> dict:
        # 尝试直接解析
        analysis_match = re.search(r'<analysis>(.*?)</analysis>', text, re.DOTALL)
        decision_match = re.search(r'<decision>(.*?)</decision>', text, re.DOTALL)
        possible_match = re.search(r'<possible>(.*?)</possible>', text, re.DOTALL)
        feedback_match = re.search(r'<feedback>(.*?)</feedback>', text, re.DOTALL)
        
        if all([analysis_match, decision_match, possible_match, feedback_match]):
            return {
                'analysis': analysis_match.group(1).strip(),
                'decision': decision_match.group(1).strip(),
                'possible': possible_match.group(1).strip(),
                'feedback': feedback_match.group(1).strip()
            }
        
        # 尝试修复格式
        for _ in range(self.MAX_FIX_FORMAT_TRIES):
            try:
                fixed = self.fix_format(text)
                analysis_match = re.search(r'<analysis>(.*?)</analysis>', fixed, re.DOTALL)
                decision_match = re.search(r'<decision>(.*?)</decision>', fixed, re.DOTALL)
                possible_match = re.search(r'<possible>(.*?)</possible>', fixed, re.DOTALL)
                feedback_match = re.search(r'<feedback>(.*?)</feedback>', fixed, re.DOTALL)
                
                if all([analysis_match, decision_match, possible_match, feedback_match]):
                    return {
                        'analysis': analysis_match.group(1).strip(),
                        'decision': decision_match.group(1).strip(),
                        'possible': possible_match.group(1).strip(),
                        'feedback': feedback_match.group(1).strip()
                    }
            except:
                continue
        
        # 返回默认失败结果
        return {
            'analysis': 'Failed to parse critic output',
            'decision': 'no',
            'possible': 'no',
            'feedback': f'Parser error: {text[:200]}'
        }


class WebEnvCritic(AgentWithHistory[dict, str]):
    """
    Web 环境部署评审 Agent
    
    输入：部署日志 (deployment_logs)
    输出：
    - analysis: 失败原因分析
    - decision: yes/no (部署是否成功)
    - possible: yes/no (是否可以修复)
    - feedback: 具体改进建议
    """
    
    __LLM_MODEL__ = 'gpt-4o-mini'
    __SYSTEM_PROMPT_TEMPLATE__ = 'webEnvCritic/webEnvCritic.system.j2'
    __USER_PROMPT_TEMPLATE__ = 'webEnvCritic/webEnvCritic.user.j2'
    __OUTPUT_PARSER__ = WebEnvCriticParser
    __MAX_TOOL_ITERATIONS__ = 1  # Critic 不需要工具，只需要一次分析
    
    deployment_logs: Optional[str] = None
    
    def __init__(self, deployment_logs: str = None, **kwargs):
        super().__init__(**kwargs)
        self.deployment_logs = deployment_logs or ""
    
    def get_input_vars(self, *args, **kwargs) -> dict:
        vars = super().get_input_vars(*args, **kwargs)
        vars.update(deployment_logs=self.deployment_logs)
        return vars
    
    def get_available_tools(self):
        # Critic 不需要工具
        return []
