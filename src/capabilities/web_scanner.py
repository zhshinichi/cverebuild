"""Web Scanner Capability: 集成SQLmap/WPScan/Nikto等安全扫描工具

功能：
1. SQLmap - SQL注入自动化利用
2. WPScan - WordPress漏洞扫描
3. Nikto - 通用Web漏洞扫描

设计原则：
- 工具以Docker容器方式运行，隔离环境
- 自动解析工具输出，提取关键信息
- 失败时提供详细诊断信息
"""

import subprocess
import json
import re
from typing import Dict, Any, List, Optional
from capabilities.base import Capability
from core.result_bus import ResultBus


class WebScannerCapability(Capability):
    """Web安全扫描工具集成"""
    
    def __init__(self, result_bus: ResultBus, config: dict):
        self.result_bus = result_bus
        self.config = config
        self.timeout = config.get('scanner_timeout', 300)  # 默认5分钟超时
        
    def execute(self, inputs: Dict[str, Any]) -> Dict[str, Any]:
        """执行Web扫描
        
        Args:
            inputs: {
                'target_url': str,  # 必需：目标URL
                'tool': str,        # 必需：工具名称 (sqlmap/wpscan/nikto)
                'params': dict      # 可选：工具特定参数
            }
        
        Returns:
            {
                'success': bool,
                'tool': str,
                'findings': List[dict],  # 发现的漏洞/问题
                'raw_output': str,       # 工具原始输出
                'error': str            # 错误信息(如果失败)
            }
        """
        target_url = inputs.get('target_url')
        tool = inputs.get('tool', 'sqlmap').lower()
        params = inputs.get('params', {})
        
        if not target_url:
            return {
                'success': False,
                'error': 'target_url is required'
            }
        
        # 根据工具类型调用对应方法
        if tool == 'sqlmap':
            return self._run_sqlmap(target_url, params)
        elif tool == 'wpscan':
            return self._run_wpscan(target_url, params)
        elif tool == 'nikto':
            return self._run_nikto(target_url, params)
        else:
            return {
                'success': False,
                'error': f'Unknown tool: {tool}. Supported: sqlmap, wpscan, nikto'
            }
    
    def _run_sqlmap(self, target_url: str, params: dict) -> Dict[str, Any]:
        """运行SQLmap进行SQL注入测试
        
        参数选项:
            - dbms: 数据库类型 (mysql/postgresql/mssql等)
            - level: 测试级别 1-5 (默认1)
            - risk: 风险级别 1-3 (默认1)
            - technique: 注入技术 (B/E/U/S/T/Q)
            - data: POST数据
            - cookie: Cookie值
        """
        cmd = [
            'docker', 'run', '--rm',
            '--network', 'host',
            'parrotsec/sqlmap'
        ]
        
        # 基础参数
        cmd.extend(['-u', target_url, '--batch'])
        
        # 可选参数
        if params.get('dbms'):
            cmd.extend(['--dbms', params['dbms']])
        
        level = params.get('level', 1)
        risk = params.get('risk', 1)
        cmd.extend(['--level', str(level), '--risk', str(risk)])
        
        if params.get('technique'):
            cmd.extend(['--technique', params['technique']])
        
        if params.get('data'):
            cmd.extend(['--data', params['data']])
        
        if params.get('cookie'):
            cmd.extend(['--cookie', params['cookie']])
        
        # 执行命令
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout
            )
            
            output = result.stdout + result.stderr
            findings = self._parse_sqlmap_output(output)
            
            return {
                'success': len(findings) > 0 or 'no injection' in output.lower(),
                'tool': 'sqlmap',
                'findings': findings,
                'raw_output': output,
                'vulnerable': len(findings) > 0
            }
            
        except subprocess.TimeoutExpired:
            return {
                'success': False,
                'tool': 'sqlmap',
                'error': f'SQLmap timeout after {self.timeout}s'
            }
        except Exception as e:
            return {
                'success': False,
                'tool': 'sqlmap',
                'error': str(e)
            }
    
    def _run_wpscan(self, target_url: str, params: dict) -> Dict[str, Any]:
        """运行WPScan扫描WordPress站点
        
        参数选项:
            - enumerate: 枚举类型 (p=插件, t=主题, u=用户)
            - api_token: WPScan API Token (提高准确率)
            - detection_mode: 检测模式 (mixed/passive/aggressive)
        """
        cmd = [
            'docker', 'run', '--rm',
            '--network', 'host',
            'wpscanteam/wpscan',
            '--url', target_url
        ]
        
        # 枚举选项
        enumerate = params.get('enumerate', 'vp,vt,u')  # 默认：漏洞插件、主题、用户
        cmd.extend(['--enumerate', enumerate])
        
        # API Token
        if params.get('api_token'):
            cmd.extend(['--api-token', params['api_token']])
        
        # 检测模式
        detection_mode = params.get('detection_mode', 'mixed')
        cmd.extend(['--detection-mode', detection_mode])
        
        # 输出JSON格式便于解析
        cmd.extend(['--format', 'json'])
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout
            )
            
            output = result.stdout
            findings = self._parse_wpscan_output(output)
            
            return {
                'success': True,
                'tool': 'wpscan',
                'findings': findings,
                'raw_output': output,
                'vulnerable': any(f.get('severity') in ['high', 'critical'] for f in findings)
            }
            
        except subprocess.TimeoutExpired:
            return {
                'success': False,
                'tool': 'wpscan',
                'error': f'WPScan timeout after {self.timeout}s'
            }
        except Exception as e:
            return {
                'success': False,
                'tool': 'wpscan',
                'error': str(e)
            }
    
    def _run_nikto(self, target_url: str, params: dict) -> Dict[str, Any]:
        """运行Nikto通用Web漏洞扫描
        
        参数选项:
            - tuning: 扫描类型调优 (1-9)
            - plugins: 插件列表
        """
        # 从URL提取host和port
        import urllib.parse
        parsed = urllib.parse.urlparse(target_url)
        host = parsed.hostname or 'localhost'
        port = parsed.port or (443 if parsed.scheme == 'https' else 80)
        
        cmd = [
            'docker', 'run', '--rm',
            '--network', 'host',
            'securecodebox/scanner-nikto',
            '-h', f'{host}:{port}'
        ]
        
        # 可选参数
        if params.get('tuning'):
            cmd.extend(['-Tuning', str(params['tuning'])])
        
        # 输出格式
        cmd.extend(['-Format', 'json'])
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout
            )
            
            output = result.stdout
            findings = self._parse_nikto_output(output)
            
            return {
                'success': True,
                'tool': 'nikto',
                'findings': findings,
                'raw_output': output,
                'vulnerable': len(findings) > 0
            }
            
        except subprocess.TimeoutExpired:
            return {
                'success': False,
                'tool': 'nikto',
                'error': f'Nikto timeout after {self.timeout}s'
            }
        except Exception as e:
            return {
                'success': False,
                'tool': 'nikto',
                'error': str(e)
            }
    
    def _parse_sqlmap_output(self, output: str) -> List[Dict[str, Any]]:
        """解析SQLmap输出，提取注入点和数据库信息"""
        findings = []
        
        # 检测注入点
        if 'parameter' in output.lower() and 'is vulnerable' in output.lower():
            # 提取参数名
            param_match = re.search(r"Parameter: (.+?) \(", output)
            if param_match:
                param_name = param_match.group(1)
                
                # 提取注入类型
                injection_type = 'unknown'
                if 'boolean-based blind' in output.lower():
                    injection_type = 'boolean-based blind'
                elif 'time-based blind' in output.lower():
                    injection_type = 'time-based blind'
                elif 'error-based' in output.lower():
                    injection_type = 'error-based'
                elif 'union query' in output.lower():
                    injection_type = 'UNION query'
                
                findings.append({
                    'type': 'sql_injection',
                    'parameter': param_name,
                    'injection_type': injection_type,
                    'severity': 'critical'
                })
        
        # 提取数据库信息
        db_match = re.search(r"back-end DBMS: (.+?)(\n|$)", output)
        if db_match:
            findings.append({
                'type': 'database_info',
                'dbms': db_match.group(1).strip(),
                'severity': 'info'
            })
        
        return findings
    
    def _parse_wpscan_output(self, output: str) -> List[Dict[str, Any]]:
        """解析WPScan JSON输出"""
        findings = []
        
        try:
            data = json.loads(output)
            
            # 解析插件漏洞
            plugins = data.get('plugins', {})
            for plugin_name, plugin_data in plugins.items():
                vulnerabilities = plugin_data.get('vulnerabilities', [])
                for vuln in vulnerabilities:
                    findings.append({
                        'type': 'wordpress_plugin_vulnerability',
                        'plugin': plugin_name,
                        'title': vuln.get('title'),
                        'severity': self._map_wpscan_severity(vuln),
                        'references': vuln.get('references', {})
                    })
            
            # 解析主题漏洞
            themes = data.get('themes', {})
            for theme_name, theme_data in themes.items():
                vulnerabilities = theme_data.get('vulnerabilities', [])
                for vuln in vulnerabilities:
                    findings.append({
                        'type': 'wordpress_theme_vulnerability',
                        'theme': theme_name,
                        'title': vuln.get('title'),
                        'severity': self._map_wpscan_severity(vuln),
                        'references': vuln.get('references', {})
                    })
            
            # 解析发现的用户
            users = data.get('users', {})
            for username, user_data in users.items():
                findings.append({
                    'type': 'wordpress_user',
                    'username': username,
                    'severity': 'info'
                })
                
        except json.JSONDecodeError:
            # JSON解析失败，尝试文本解析
            if 'vulnerabilities identified' in output.lower():
                findings.append({
                    'type': 'wpscan_raw',
                    'message': 'Vulnerabilities found (see raw output)',
                    'severity': 'medium'
                })
        
        return findings
    
    def _parse_nikto_output(self, output: str) -> List[Dict[str, Any]]:
        """解析Nikto输出"""
        findings = []
        
        try:
            data = json.loads(output)
            vulnerabilities = data.get('vulnerabilities', [])
            
            for vuln in vulnerabilities:
                findings.append({
                    'type': 'web_vulnerability',
                    'id': vuln.get('id'),
                    'message': vuln.get('msg'),
                    'severity': self._map_nikto_severity(vuln.get('OSVDB', 0))
                })
                
        except json.JSONDecodeError:
            # 文本格式解析
            lines = output.split('\n')
            for line in lines:
                if '+' in line and 'OSVDB' in line:
                    findings.append({
                        'type': 'web_vulnerability',
                        'message': line.strip(),
                        'severity': 'medium'
                    })
        
        return findings
    
    def _map_wpscan_severity(self, vuln: dict) -> str:
        """映射WPScan漏洞严重性"""
        # WPScan没有直接的severity字段，根据CVE和类型推断
        if 'rce' in str(vuln).lower() or 'remote code' in str(vuln).lower():
            return 'critical'
        elif 'sqli' in str(vuln).lower() or 'sql injection' in str(vuln).lower():
            return 'high'
        elif 'xss' in str(vuln).lower():
            return 'medium'
        else:
            return 'low'
    
    def _map_nikto_severity(self, osvdb_id: int) -> str:
        """根据OSVDB ID范围映射严重性（简化版）"""
        if osvdb_id > 10000:
            return 'medium'
        elif osvdb_id > 5000:
            return 'high'
        else:
            return 'low'


# 为了方便调用，提供快捷函数
def run_sqlmap(target_url: str, result_bus: ResultBus = None, **kwargs) -> Dict[str, Any]:
    """快捷方式：运行SQLmap扫描"""
    scanner = WebScannerCapability(result_bus or ResultBus(), {'scanner_timeout': 300})
    return scanner.execute({
        'target_url': target_url,
        'tool': 'sqlmap',
        'params': kwargs
    })


def run_wpscan(target_url: str, result_bus: ResultBus = None, **kwargs) -> Dict[str, Any]:
    """快捷方式：运行WPScan扫描"""
    scanner = WebScannerCapability(result_bus or ResultBus(), {'scanner_timeout': 300})
    return scanner.execute({
        'target_url': target_url,
        'tool': 'wpscan',
        'params': kwargs
    })


def run_nikto(target_url: str, result_bus: ResultBus = None, **kwargs) -> Dict[str, Any]:
    """快捷方式：运行Nikto扫描"""
    scanner = WebScannerCapability(result_bus or ResultBus(), {'scanner_timeout': 300})
    return scanner.execute({
        'target_url': target_url,
        'tool': 'nikto',
        'params': kwargs
    })
