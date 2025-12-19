"""
DeploymentStrategyAnalyzer - 部署策略分析器

功能：
- 分析 CVE 数据（描述、软件名称、版本、仓库信息）
- 智能决策最佳部署策略
- 生成具体的部署指令

输出：
- strategy: docker_hub / source_build / manual_setup / not_feasible
- instructions: 具体的部署步骤
- confidence: 策略可行性评分
"""

import re
from typing import Dict, Any, Optional, List
from agentlib import Agent


class DeploymentStrategyAnalyzer(Agent[dict, dict]):
    """
    部署策略分析器 - 不需要工具，纯分析
    
    输入：
    - cve_id: CVE 编号
    - cve_description: 漏洞描述
    - sw_name: 软件名称
    - sw_version: 软件版本
    - sw_version_wget: 下载链接（如果有）
    - patch_commits: 补丁提交（如果有）
    
    输出：
    - strategy: 部署策略类型
    - docker_image: Docker 镜像名（如果适用）
    - source_repo: 源码仓库 URL
    - build_commands: 构建命令列表
    - start_command: 启动命令
    - port: 默认端口
    - confidence: 0.0-1.0 可行性评分
    - reasoning: 策略选择的理由
    """
    
    __LLM_MODEL__ = 'gpt-4o-mini'
    __SYSTEM_PROMPT_TEMPLATE__ = 'deploymentAnalyzer/deploymentAnalyzer.system.j2'
    __USER_PROMPT_TEMPLATE__ = 'deploymentAnalyzer/deploymentAnalyzer.user.j2'
    __MAX_TOOL_ITERATIONS__ = 1  # 纯分析，不需要工具
    
    cve_id: Optional[str] = None
    cve_description: Optional[str] = None
    sw_name: Optional[str] = None
    sw_version: Optional[str] = None
    sw_version_wget: Optional[str] = None
    patch_commits: Optional[List[Dict]] = None
    
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.cve_id = kwargs.get('cve_id', '')
        self.cve_description = kwargs.get('cve_description', '')
        self.sw_name = kwargs.get('sw_name', '')
        self.sw_version = kwargs.get('sw_version', '')
        self.sw_version_wget = kwargs.get('sw_version_wget', '')
        self.patch_commits = kwargs.get('patch_commits', [])
    
    def get_input_vars(self, *args, **kwargs) -> dict:
        vars = super().get_input_vars(*args, **kwargs)
        vars.update(
            cve_id=self.cve_id,
            cve_description=self.cve_description,
            sw_name=self.sw_name,
            sw_version=self.sw_version,
            sw_version_wget=self.sw_version_wget,
            patch_commits=self.patch_commits,
        )
        return vars
    
    def get_available_tools(self):
        # 纯分析，不需要工具
        return []


# ============================================================
# 规则引擎 - 快速预判（不需要 LLM）
# ============================================================

class DeploymentRuleEngine:
    """
    基于规则的快速部署策略判断
    用于明显的情况，避免每次都调用 LLM
    """
    
    # 已知有 Docker 镜像的软件
    KNOWN_DOCKER_IMAGES = {
        # 常见 Web 应用
        'mlflow': 'ghcr.io/mlflow/mlflow:{version}',
        'gitlab': 'gitlab/gitlab-ce:{version}',
        'jenkins': 'jenkins/jenkins:{version}',
        'wordpress': 'wordpress:{version}',
        'n8n': 'n8nio/n8n:{version}',
        'grafana': 'grafana/grafana:{version}',
        'nginx': 'nginx:{version}',
        'apache': 'httpd:{version}',
        
        # 数据库
        'mysql': 'mysql:{version}',
        'postgresql': 'postgres:{version}',
        'redis': 'redis:{version}',
        
        # 流行的 AI/Chat 应用
        'lobe-chat': 'lobehub/lobe-chat:{version}',
        'lobechat': 'lobehub/lobe-chat:{version}',
        'open-webui': 'ghcr.io/open-webui/open-webui:{version}',
        'ollama': 'ollama/ollama:{version}',
        
        # 其他常见应用
        'gitea': 'gitea/gitea:{version}',
        'drone': 'drone/drone:{version}',
        'minio': 'minio/minio:{version}',
        'keycloak': 'quay.io/keycloak/keycloak:{version}',
        'nextcloud': 'nextcloud:{version}',
        'vaultwarden': 'vaultwarden/server:{version}',
        
        # 需要源码构建的（无官方镜像）
        'django': None,
        'flask': None,
        'fastapi': None,
    }
    
    # IoT/硬件设备（通常无法复现）
    IOT_KEYWORDS = [
        'router', 'netcore', 'netis', 'tp-link', 'd-link',
        'iot', 'firmware', 'embedded', 'gateway', 'modem',
        'camera', 'dvr', 'nvr', 'switch', 'access point'
    ]
    
    # 企业内部系统（通常无公开镜像/源码）
    ENTERPRISE_KEYWORDS = [
        'oa', '办公', 'erp', 'crm', 'ywoa', 
        '金蝶', '用友', 'sap', 'oracle'
    ]
    
    @staticmethod
    def quick_analyze(cve_entry: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        快速规则判断，返回策略或 None（需要 LLM 分析）
        """
        sw_name = cve_entry.get('sw_name', '').lower()
        sw_version = cve_entry.get('sw_version', '')
        description = cve_entry.get('description', '').lower()
        sw_version_wget = cve_entry.get('sw_version_wget', '')
        
        # 规则 1: IoT/硬件设备 → 不可行
        if any(keyword in description or keyword in sw_name 
               for keyword in DeploymentRuleEngine.IOT_KEYWORDS):
            return {
                'strategy': 'not_feasible',
                'reasoning': 'IoT/firmware vulnerability requires physical hardware or specialized emulation',
                'confidence': 0.9
            }
        
        # 规则 2: 企业内部系统 → 需要源码（通常没有）
        if any(keyword in description or keyword in sw_name 
               for keyword in DeploymentRuleEngine.ENTERPRISE_KEYWORDS):
            # 检查是否有 GitHub 链接
            if 'github.com' in sw_version_wget or 'gitlab.com' in sw_version_wget:
                return {
                    'strategy': 'source_build',
                    'source_repo': sw_version_wget,
                    'reasoning': 'Enterprise application with public source code available',
                    'confidence': 0.7
                }
            return {
                'strategy': 'not_feasible',
                'reasoning': 'Enterprise internal system without public source code',
                'confidence': 0.8
            }
        
        # 规则 3: 已知的 Docker Hub 应用
        for app_name, image_template in DeploymentRuleEngine.KNOWN_DOCKER_IMAGES.items():
            if app_name in sw_name:
                if image_template:
                    version_clean = sw_version.lstrip('v').split('-')[0]
                    return {
                        'strategy': 'docker_hub',
                        'docker_image': image_template.format(version=version_clean),
                        'reasoning': f'Well-known application with official Docker image',
                        'confidence': 0.95
                    }
                else:
                    return {
                        'strategy': 'source_build',
                        'reasoning': f'{app_name} typically requires source build',
                        'confidence': 0.8
                    }
        
        # 规则 4: 有 GitHub 下载链接 → 源码构建
        if 'github.com' in sw_version_wget or 'gitlab.com' in sw_version_wget:
            # 提取仓库信息
            repo_match = re.search(r'(github\.com|gitlab\.com)/([^/]+)/([^/]+)', sw_version_wget)
            if repo_match:
                return {
                    'strategy': 'source_build',
                    'source_repo': f'https://{repo_match.group(1)}/{repo_match.group(2)}/{repo_match.group(3)}',
                    'reasoning': 'Source code available on GitHub/GitLab',
                    'confidence': 0.85
                }
        
        # 需要 LLM 进一步分析
        return None
