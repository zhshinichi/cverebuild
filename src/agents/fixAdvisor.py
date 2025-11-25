import os
from agentlib import Agent
from typing import Optional

class FixAdvisor(Agent[dict, str]):
    """
    Agent for generating vulnerability fix recommendations based on:
    1. Vulnerability analysis (type, mechanism, root cause)
    2. Official patches (if available)
    3. Security best practices
    4. Code examples
    """
    __LLM_MODEL__ = 'gpt-5'
    __SYSTEM_PROMPT_TEMPLATE__ = 'fixAdvisor/fixAdvisor.system.j2'
    __USER_PROMPT_TEMPLATE__ = 'fixAdvisor/fixAdvisor.user.j2'

    CVE_ID: Optional[str]
    VULNERABILITY_TYPE: Optional[str]
    CWE: Optional[str]
    DESCRIPTION: Optional[str]
    VULNERABLE_CODE: Optional[str]
    PATCH_CONTENT: Optional[str]
    REPRODUCTION_SUCCESS: Optional[bool]

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.CVE_ID = kwargs.get('cve_id')
        self.VULNERABILITY_TYPE = kwargs.get('vulnerability_type')
        self.CWE = kwargs.get('cwe')
        self.DESCRIPTION = kwargs.get('description')
        self.VULNERABLE_CODE = kwargs.get('vulnerable_code', 'Not available')
        self.PATCH_CONTENT = kwargs.get('patch_content', 'No official patch available')
        self.REPRODUCTION_SUCCESS = kwargs.get('reproduction_success', False)
    
    def get_input_vars(self, *args, **kwargs) -> dict:
        vars = super().get_input_vars(*args, **kwargs)
        vars.update(
            CVE_ID = self.CVE_ID,
            VULNERABILITY_TYPE = self.VULNERABILITY_TYPE,
            CWE = self.CWE,
            DESCRIPTION = self.DESCRIPTION,
            VULNERABLE_CODE = self.VULNERABLE_CODE,
            PATCH_CONTENT = self.PATCH_CONTENT,
            REPRODUCTION_SUCCESS = self.REPRODUCTION_SUCCESS
        )
        return vars
    
    def get_cost(self, *args, **kw) -> float:
        total_cost = 0
        for model_name, token_usage in self.token_usage.items():
            total_cost += token_usage.get_costs(model_name)['total_cost']
        return total_cost
