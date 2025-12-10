"""Web Fingerprint Capability: Web技术栈指纹识别

功能：
1. WhatWeb - 识别Web技术栈、框架、CMS、版本
2. 自动判断技术栈类型，为后续工具选择提供依据

设计原则：
- 优先使用WhatWeb进行指纹识别
- 输出标准化的技术栈信息
- 支持批量URL扫描
"""

import subprocess
import json
import re
from typing import Dict, Any, List
from capabilities.base import Capability
from core.result_bus import ResultBus


class WebFingerprintCapability(Capability):
    """Web指纹识别能力"""
    
    def __init__(self, result_bus: ResultBus, config: dict):
        self.result_bus = result_bus
        self.config = config
        self.timeout = config.get('fingerprint_timeout', 60)
        
    def execute(self, inputs: Dict[str, Any]) -> Dict[str, Any]:
        """执行指纹识别
        
        Args:
            inputs: {
                'target_url': str,     # 必需：目标URL
                'aggressive': bool     # 可选：是否使用激进模式
            }
        
        Returns:
            {
                'success': bool,
                'technologies': List[dict],  # 识别的技术栈
                'cms': str,                  # CMS类型 (WordPress/Joomla等)
                'framework': str,            # 框架 (Laravel/Django等)
                'server': str,               # Web服务器
                'language': str,             # 编程语言
                'database': str,             # 数据库 (推测)
                'raw_output': str
            }
        """
        target_url = inputs.get('target_url')
        if not target_url:
            return {
                'success': False,
                'error': 'target_url is required'
            }
        
        aggressive = inputs.get('aggressive', False)
        return self._run_whatweb(target_url, aggressive)
    
    def _run_whatweb(self, target_url: str, aggressive: bool = False) -> Dict[str, Any]:
        """运行WhatWeb进行指纹识别"""
        cmd = [
            'docker', 'run', '--rm',
            '--network', 'host',
            'ilyaglow/whatweb'
        ]
        
        # 激进模式 (更详细但可能触发WAF)
        if aggressive:
            cmd.append('-a')
            cmd.append('3')  # 激进级别3
        else:
            cmd.append('-a')
            cmd.append('1')  # 被动模式
        
        # JSON输出
        cmd.extend(['--log-json=-', target_url])
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout
            )
            
            output = result.stdout
            fingerprint = self._parse_whatweb_output(output)
            
            return {
                'success': True,
                'technologies': fingerprint.get('technologies', []),
                'cms': fingerprint.get('cms'),
                'framework': fingerprint.get('framework'),
                'server': fingerprint.get('server'),
                'language': fingerprint.get('language'),
                'database': fingerprint.get('database'),
                'raw_output': output,
                'summary': self._generate_summary(fingerprint)
            }
            
        except subprocess.TimeoutExpired:
            return {
                'success': False,
                'error': f'WhatWeb timeout after {self.timeout}s'
            }
        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }
    
    def _parse_whatweb_output(self, output: str) -> Dict[str, Any]:
        """解析WhatWeb JSON输出"""
        fingerprint = {
            'technologies': [],
            'cms': None,
            'framework': None,
            'server': None,
            'language': None,
            'database': None
        }
        
        try:
            # WhatWeb输出每行一个JSON对象
            for line in output.strip().split('\n'):
                if not line.strip():
                    continue
                    
                data = json.loads(line)
                plugins = data.get('plugins', {})
                
                # 遍历所有检测到的插件/技术
                for tech_name, tech_info in plugins.items():
                    tech_data = {
                        'name': tech_name,
                        'version': self._extract_version(tech_info),
                        'confidence': 'high'  # WhatWeb检测一般可信度高
                    }
                    
                    fingerprint['technologies'].append(tech_data)
                    
                    # 分类技术栈
                    self._categorize_technology(tech_name, tech_data, fingerprint)
                    
        except json.JSONDecodeError:
            # JSON解析失败，尝试文本模式解析
            fingerprint['technologies'] = self._parse_text_output(output)
        
        return fingerprint
    
    def _extract_version(self, tech_info: dict) -> str:
        """从技术信息中提取版本号"""
        if isinstance(tech_info, dict):
            version = tech_info.get('version', [])
            if isinstance(version, list) and version:
                return version[0]
            elif isinstance(version, str):
                return version
        elif isinstance(tech_info, str):
            # 简单的版本号提取
            version_match = re.search(r'\d+\.\d+(?:\.\d+)?', tech_info)
            if version_match:
                return version_match.group(0)
        return None
    
    def _categorize_technology(self, tech_name: str, tech_data: dict, fingerprint: dict):
        """根据技术名称分类"""
        tech_lower = tech_name.lower()
        
        # CMS识别
        cms_map = {
            'wordpress': 'WordPress',
            'joomla': 'Joomla',
            'drupal': 'Drupal',
            'magento': 'Magento',
            'prestashop': 'PrestaShop',
            'opencart': 'OpenCart',
            'shopify': 'Shopify',
            'wix': 'Wix'
        }
        for key, value in cms_map.items():
            if key in tech_lower:
                fingerprint['cms'] = value
                break
        
        # 框架识别
        framework_map = {
            'laravel': 'Laravel',
            'django': 'Django',
            'flask': 'Flask',
            'spring': 'Spring',
            'struts': 'Struts',
            'rails': 'Ruby on Rails',
            'express': 'Express.js',
            'nextjs': 'Next.js',
            'nuxt': 'Nuxt.js',
            'angular': 'Angular',
            'react': 'React',
            'vue': 'Vue.js'
        }
        for key, value in framework_map.items():
            if key in tech_lower:
                fingerprint['framework'] = value
                break
        
        # Web服务器
        server_map = {
            'apache': 'Apache',
            'nginx': 'Nginx',
            'iis': 'IIS',
            'tomcat': 'Tomcat',
            'jetty': 'Jetty',
            'lighttpd': 'Lighttpd'
        }
        for key, value in server_map.items():
            if key in tech_lower:
                fingerprint['server'] = value
                break
        
        # 编程语言
        language_map = {
            'php': 'PHP',
            'python': 'Python',
            'java': 'Java',
            'ruby': 'Ruby',
            'nodejs': 'Node.js',
            'asp.net': 'ASP.NET',
            'asp': 'ASP'
        }
        for key, value in language_map.items():
            if key in tech_lower:
                fingerprint['language'] = value
                break
        
        # 数据库推测
        database_map = {
            'mysql': 'MySQL',
            'mariadb': 'MariaDB',
            'postgresql': 'PostgreSQL',
            'mongodb': 'MongoDB',
            'redis': 'Redis',
            'mssql': 'MS SQL Server',
            'oracle': 'Oracle'
        }
        for key, value in database_map.items():
            if key in tech_lower:
                fingerprint['database'] = value
                break
    
    def _parse_text_output(self, output: str) -> List[Dict[str, Any]]:
        """解析文本格式输出（备用方案）"""
        technologies = []
        
        # 简单的正则提取技术名称
        tech_pattern = r'\[([^\]]+)\]'
        matches = re.findall(tech_pattern, output)
        
        for match in matches:
            technologies.append({
                'name': match,
                'version': None,
                'confidence': 'medium'
            })
        
        return technologies
    
    def _generate_summary(self, fingerprint: dict) -> str:
        """生成技术栈摘要"""
        parts = []
        
        if fingerprint.get('cms'):
            parts.append(f"CMS: {fingerprint['cms']}")
        
        if fingerprint.get('framework'):
            parts.append(f"Framework: {fingerprint['framework']}")
        
        if fingerprint.get('language'):
            parts.append(f"Language: {fingerprint['language']}")
        
        if fingerprint.get('server'):
            parts.append(f"Server: {fingerprint['server']}")
        
        if fingerprint.get('database'):
            parts.append(f"Database: {fingerprint['database']}")
        
        if not parts:
            tech_count = len(fingerprint.get('technologies', []))
            parts.append(f"Detected {tech_count} technologies")
        
        return ' | '.join(parts)


def identify_stack(target_url: str, result_bus: ResultBus = None, aggressive: bool = False) -> Dict[str, Any]:
    """快捷方式：识别Web技术栈"""
    fingerprint = WebFingerprintCapability(result_bus or ResultBus(), {'fingerprint_timeout': 60})
    return fingerprint.execute({
        'target_url': target_url,
        'aggressive': aggressive
    })


def recommend_scanner(fingerprint_result: Dict[str, Any]) -> List[str]:
    """根据指纹识别结果推荐扫描工具
    
    Returns:
        List[str]: 推荐的工具列表 ['sqlmap', 'wpscan', 'nikto']
    """
    recommendations = []
    
    cms = fingerprint_result.get('cms', '').lower()
    framework = fingerprint_result.get('framework', '').lower()
    language = fingerprint_result.get('language', '').lower()
    
    # WordPress相关
    if 'wordpress' in cms:
        recommendations.append('wpscan')
        recommendations.append('sqlmap')  # WP常有SQL注入
    
    # PHP应用
    elif 'php' in language:
        recommendations.append('sqlmap')
        recommendations.append('nikto')
    
    # Java应用
    elif 'java' in language or 'struts' in framework or 'spring' in framework:
        recommendations.append('nikto')
    
    # 其他CMS
    elif cms:
        recommendations.append('sqlmap')
        recommendations.append('nikto')
    
    # 通用推荐
    else:
        recommendations.append('nikto')
        recommendations.append('sqlmap')
    
    return recommendations
