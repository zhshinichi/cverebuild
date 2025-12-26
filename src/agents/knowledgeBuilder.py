import os
from agentlib import Agent
from typing import Optional

# 🔧 修复 CVE-2024-3651: 防止超长输入导致 token 超限
MAX_SECURITY_ADVISORY_LENGTH = 8000  # 约 2000 tokens
MAX_PATCH_LENGTH = 6000  # 约 1500 tokens

def _truncate_content(content: str, max_length: int, label: str = "content") -> str:
    """截断过长的内容，保留关键信息"""
    if not content or len(content) <= max_length:
        return content
    
    # 尝试在合理位置截断（段落或代码块边界）
    truncated = content[:max_length]
    for delimiter in ['\n```\n', '\n\n', '\n', '. ']:
        last_pos = truncated.rfind(delimiter)
        if last_pos > max_length * 0.7:
            truncated = truncated[:last_pos + len(delimiter)]
            break
    
    return truncated.strip() + f"\n\n[... {label} truncated, {len(content) - len(truncated)} chars omitted to prevent token overflow ...]"


class KnowledgeBuilder(Agent[dict, str]):
    __LLM_MODEL__ = 'gpt-4o-mini'
    __SYSTEM_PROMPT_TEMPLATE__ = 'knowledgeBuilder/knowledgeBuilder.system.j2'
    __USER_PROMPT_TEMPLATE__ = 'knowledgeBuilder/knowledgeBuilder.user.j2'

    ID: Optional[str]
    DESCRIPTION: Optional[str]
    CWE: Optional[str]
    PROJECT_NAME: Optional[str]
    AFFECTED_VERSION: Optional[str]
    SECURITY_ADVISORY: Optional[str]
    PATCH: Optional[str]

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.ID = kwargs.get('id')
        self.DESCRIPTION = kwargs.get('description')
        self.CWE = kwargs.get('cwe')
        self.PROJECT_NAME = kwargs.get('project_name')
        self.AFFECTED_VERSION = kwargs.get('affected_version')
        # 🔧 截断过长的输入
        self.SECURITY_ADVISORY = _truncate_content(
            kwargs.get('security_advisory', ''), 
            MAX_SECURITY_ADVISORY_LENGTH, 
            "security advisory"
        )
        self.PATCH = _truncate_content(
            kwargs.get('patch', ''), 
            MAX_PATCH_LENGTH, 
            "patch"
        )
    
    def get_input_vars(self, *args, **kwargs) -> dict:
        vars = super().get_input_vars(*args, **kwargs)
        vars.update(
            ID = self.ID,
            DESCRIPTION = self.DESCRIPTION,
            CWE = self.CWE,
            PROJECT_NAME = self.PROJECT_NAME,
            AFFECTED_VERSION = self.AFFECTED_VERSION,
            SECURITY_ADVISORY = self.SECURITY_ADVISORY,
            PATCH = self.PATCH
        )
        return vars
    
    def get_cost(self, *args, **kw) -> float:
        total_cost = 0
        # We have to sum up all the costs of the LLM used by the agent
        for model_name, token_usage in self.token_usage.items():
            total_cost += token_usage.get_costs(model_name)['total_cost']
        return total_cost
