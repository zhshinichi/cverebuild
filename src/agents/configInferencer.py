"""
ConfigInferencer Agent

专门负责从 CVE Knowledge 中推理出完整的环境配置需求。

这个 Agent 解决的问题：
1. CVE Advisory 可能没有明确说明所有启动参数
2. 某些 API 端点需要特殊模式才能启用（如 MLflow 的 basic-auth）
3. 需要根据 PoC 中的端点推理出正确的启动命令

工作流程：
1. 接收 CVE Knowledge 和 PoC 代码
2. 分析 PoC 中的目标端点
3. 查询框架知识库
4. 推理出完整的 Startup Command
5. 返回增强后的环境配置
"""

import os
import re
from agentlib import Agent
from typing import Optional, Dict, Any


# 框架知识库：用于推理特殊配置需求
FRAMEWORK_KNOWLEDGE = {
    'mlflow': {
        'name': 'MLflow',
        'default_cmd': 'mlflow server --host 0.0.0.0 --port {port}',
        'special_modes': [
            {
                'name': 'basic-auth',
                'description': 'MLflow 用户管理功能需要启用 basic-auth 模式',
                'trigger_endpoints': [
                    r'/api/2\.0/mlflow/users/',
                    r'/api/2\.0/mlflow/users/create',
                    r'/api/2\.0/mlflow/users/update-password',
                    r'/api/2\.0/mlflow/users/delete',
                    r'/signup',
                    r'/login',
                ],
                'startup_cmd': 'mlflow server --app-name basic-auth --host 0.0.0.0 --port {port}',
            },
        ],
    },
    'django': {
        'name': 'Django',
        'default_cmd': 'python manage.py runserver 0.0.0.0:{port}',
        'special_modes': [
            {
                'name': 'debug',
                'description': 'Django 调试模式',
                'trigger_endpoints': [r'/admin/', r'/__debug__/'],
                'env_vars': {'DEBUG': 'True'},
                'startup_cmd': 'python manage.py runserver 0.0.0.0:{port}',
            },
        ],
    },
    'flask': {
        'name': 'Flask',
        'default_cmd': 'flask run --host 0.0.0.0 --port {port}',
        'special_modes': [
            {
                'name': 'debug',
                'description': 'Flask 调试模式',
                'trigger_endpoints': [],
                'env_vars': {'FLASK_DEBUG': '1'},
                'startup_cmd': 'FLASK_DEBUG=1 flask run --host 0.0.0.0 --port {port}',
            },
        ],
    },
    'fastapi': {
        'name': 'FastAPI',
        'default_cmd': 'uvicorn main:app --host 0.0.0.0 --port {port}',
        'special_modes': [],
    },
}


class ConfigInferencer(Agent[dict, dict]):
    """
    配置推理 Agent：分析 CVE Knowledge 并推理出完整的环境配置。
    
    输入：
        - cve_knowledge: CVE 知识（来自 KnowledgeBuilder）
        - framework: 可选的框架提示
        
    输出：
        - port: 端口号
        - startup_cmd: 完整的启动命令（包含所有必要参数）
        - target_endpoint: 目标端点
        - special_mode: 特殊模式名称（如果有）
        - notes: 推理说明
    """
    
    __LLM_MODEL__ = 'gpt-5'
    __SYSTEM_PROMPT_TEMPLATE__ = 'configInferencer/configInferencer.system.j2'
    __USER_PROMPT_TEMPLATE__ = 'configInferencer/configInferencer.user.j2'
    
    cve_knowledge: str
    framework_hint: Optional[str]
    
    def __init__(self, cve_knowledge: str, framework_hint: str = None, **kwargs):
        super().__init__(**kwargs)
        self.cve_knowledge = cve_knowledge
        self.framework_hint = framework_hint
    
    def get_input_vars(self, *args, **kwargs) -> dict:
        vars = super().get_input_vars(*args, **kwargs)
        vars.update(
            cve_knowledge=self.cve_knowledge,
            framework_hint=self.framework_hint,
            framework_knowledge=FRAMEWORK_KNOWLEDGE,
        )
        return vars
    
    @classmethod
    def infer_config_locally(cls, cve_knowledge: str, port: int = 5000) -> Dict[str, Any]:
        """
        本地推理配置（不使用 LLM，基于规则）。
        当不需要 LLM 时可以直接调用此方法。
        
        :param cve_knowledge: CVE 知识文本
        :param port: 默认端口
        :return: 推理出的配置
        """
        result = {
            'port': port,
            'startup_cmd': None,
            'target_endpoint': None,
            'special_mode': None,
            'framework': None,
            'notes': [],
        }
        
        # 1. 提取端口号
        port_match = re.search(r'(?:localhost|127\.0\.0\.1):(\d+)', cve_knowledge)
        if port_match:
            result['port'] = int(port_match.group(1))
            result['notes'].append(f"从 PoC URL 中提取端口: {result['port']}")
        
        # 2. 提取目标端点
        endpoint_match = re.search(r'(?:localhost|127\.0\.0\.1):\d+(/[^\s"\'<>]+)', cve_knowledge)
        if endpoint_match:
            result['target_endpoint'] = endpoint_match.group(1)
            result['notes'].append(f"从 PoC URL 中提取端点: {result['target_endpoint']}")
        
        # 3. 检测框架
        for fw_name, fw_config in FRAMEWORK_KNOWLEDGE.items():
            if fw_name.lower() in cve_knowledge.lower():
                result['framework'] = fw_name
                result['startup_cmd'] = fw_config['default_cmd'].format(port=result['port'])
                result['notes'].append(f"检测到框架: {fw_config['name']}")
                
                # 4. 检查是否需要特殊模式
                if result['target_endpoint']:
                    for mode in fw_config.get('special_modes', []):
                        for pattern in mode.get('trigger_endpoints', []):
                            if re.search(pattern, result['target_endpoint'], re.IGNORECASE):
                                result['special_mode'] = mode['name']
                                result['startup_cmd'] = mode['startup_cmd'].format(port=result['port'])
                                result['notes'].append(
                                    f"端点 {result['target_endpoint']} 需要 {mode['name']} 模式: {mode['description']}"
                                )
                                break
                        if result['special_mode']:
                            break
                break
        
        return result
    
    def get_cost(self, *args, **kw) -> float:
        total_cost = 0
        for model_name, token_usage in self.token_usage.items():
            total_cost += token_usage.get_costs(model_name)['total_cost']
        return total_cost
