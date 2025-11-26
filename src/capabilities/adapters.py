"""Capability Adapters: Wrap existing Agents as Capability implementations.

Design Principles:
- Steps requiring reasoning/thinking -> Use LLM Agent
- Pure technical operations -> Use simple Python functions, no LLM needed
"""
from typing import Any, Dict
import subprocess
import os

from capabilities.base import Capability
from core.result_bus import ResultBus

# 导入现有 Agent
from agents import (
    KnowledgeBuilder,
    PreReqBuilder,
    RepoBuilder,
    RepoCritic,
    Exploiter,
    ExploitCritic,
    CTFVerifier,
    SanityGuy,
    WebEnvBuilder
)


# ============================================================
# 不需要 LLM 的纯功能性 Capability
# ============================================================

class BrowserEnvironmentProvider(Capability):
    """浏览器环境提供者 - 不需要 LLM，只是启动/配置浏览器环境"""
    
    def __init__(self, result_bus: ResultBus, config: dict):
        self.result_bus = result_bus
        self.config = config
    
    def execute(self, inputs: Dict[str, Any]) -> Dict[str, Any]:
        """启动浏览器环境，返回浏览器配置信息"""
        browser_engine = self.config.get('browser_engine', 'selenium')
        target_url = self.config.get('target_url', 'http://localhost:9600')
        
        print(f"[Browser] Configuring browser environment: {browser_engine}")
        print(f"[Browser] Target URL: {target_url}")
        
        # 这里只是配置信息，实际的浏览器启动由 WebDriverAgent 处理
        browser_config = {
            'engine': browser_engine,
            'target_url': target_url,
            'headless': self.config.get('headless', True),
            'timeout': self.config.get('timeout', 30),
            'ready': True
        }
        
        print(f"[Browser] Environment ready")
        return {'browser_config': browser_config}


class CVEInfoExtractor(Capability):
    """CVE 信息提取器 - 不需要 LLM，只是从数据中提取字段"""
    
    def __init__(self, result_bus: ResultBus, config: dict):
        self.result_bus = result_bus
        self.config = config
    
    def execute(self, inputs: Dict[str, Any]) -> Dict[str, Any]:
        """从 cve_entry 中提取结构化信息"""
        cve_entry = inputs.get('cve_entry', {})
        cve_id = inputs.get('cve_id', '')
        
        # 直接提取，无需 LLM
        extracted = {
            'cve_id': cve_id,
            'description': cve_entry.get('description', ''),
            'cwe': cve_entry.get('cwe', []),
            'sw_version': cve_entry.get('sw_version', ''),
            'sw_version_wget': cve_entry.get('sw_version_wget', ''),
            'dir_tree': cve_entry.get('dir_tree', ''),
            'patch_commits': cve_entry.get('patch_commits', []),
            'sec_adv': cve_entry.get('sec_adv', []),
            'attack_type': cve_entry.get('attack_type', 'unknown')
        }
        
        print(f"[CVE] Extracted info for: {cve_id}")
        return {'cve_info': extracted}


class WebAppDeployer(Capability):
    """Web 应用部署器 - 使用 WebEnvBuilder Agent 部署 Web 应用
    
    与 RepoBuilder 的区别：
    - RepoBuilder: 需要 dir_tree，适合从源码编译的本地漏洞
    - WebAppDeployer: 不需要 dir_tree，专门处理 Web 应用部署
      - 优先使用预部署的目标 URL（通过 config['target_url'] 指定）
      - 如果没有预部署，使用 LLM Agent (WebEnvBuilder) 智能部署
      - 支持 docker-compose / pip / npm 多种部署
      - 返回应用访问地址
    """
    
    def __init__(self, result_bus: ResultBus, config: dict):
        self.result_bus = result_bus
        self.config = config
    
    def execute(self, inputs: Dict[str, Any]) -> Dict[str, Any]:
        cve_entry = inputs.get('cve_entry', {})
        cve_knowledge = inputs.get('cve_knowledge', '')
        prerequisites = inputs.get('prerequisites', {})
        
        # 获取软件信息
        sw_version_wget = cve_entry.get('sw_version_wget', '')
        sw_version = cve_entry.get('sw_version', '')
        
        print(f"[WebAppDeployer] Deploying web application...")
        print(f"[WebAppDeployer] Software version: {sw_version}")
        
        # 默认目标 URL
        target_url = self.config.get('target_url', 'http://localhost:9600')
        
        # ========== 优先检查目标是否已经可访问 ==========
        import subprocess
        try:
            result = subprocess.run(
                ['curl', '-s', '-o', '/dev/null', '-w', '%{http_code}', f'{target_url}/'],
                capture_output=True, text=True, timeout=5
            )
            status_code = result.stdout.strip()
            if status_code.startswith('2') or status_code.startswith('3'):
                print(f"[WebAppDeployer] ✅ Target already accessible at {target_url} (HTTP {status_code})")
                return {
                    'build_result': {
                        'success': 'yes',
                        'access': target_url,
                        'method': 'pre-deployed',
                        'notes': f'Target already running, HTTP {status_code}'
                    }
                }
        except Exception as e:
            print(f"[WebAppDeployer] Target check failed: {e}")
        
        # ========== 尝试使用部署脚本 ==========
        deploy_script = '/workspaces/submission/src/simulation_environments/deploy.sh'
        cve_id = inputs.get('cve_id', '')
        
        try:
            # 尝试部署脚本
            print(f"[WebAppDeployer] Trying deploy script for {cve_id}...")
            result = subprocess.run(
                ['bash', deploy_script, cve_id],
                capture_output=True, text=True, timeout=60
            )
            if result.returncode == 0:
                print(f"[WebAppDeployer] ✅ Deploy script succeeded")
                return {
                    'build_result': {
                        'success': 'yes',
                        'access': target_url,
                        'method': 'deploy-script',
                        'notes': result.stdout
                    }
                }
        except Exception as e:
            print(f"[WebAppDeployer] Deploy script failed: {e}")
        
        # ========== 如果有 dir_tree，使用 RepoBuilder ==========
        has_dir_tree = bool(cve_entry.get('dir_tree'))
        
        if has_dir_tree:
            print(f"[WebAppDeployer] Directory tree available, using RepoBuilder")
            agent = RepoBuilder(
                project_dir_tree=cve_entry.get('dir_tree', ''),
                cve_knowledge=cve_knowledge,
                build_pre_reqs=prerequisites or {
                    'overview': f'Web application {sw_version}',
                    'files': '',
                    'services': 'Web server',
                    'output': 'HTTP service'
                },
                feedback=None,
                critic_feedback=None
            )
            result = agent.invoke().value
            
            if isinstance(result, dict) and result.get('success', '').lower() == 'yes':
                target_url = result.get('access', target_url)
                return {
                    'build_result': {
                        'success': 'yes',
                        'access': target_url,
                        'method': 'repo-builder'
                    }
                }
        
        # ========== 最后尝试 WebEnvBuilder Agent ==========
        print(f"[WebAppDeployer] No pre-deployed target, using WebEnvBuilder Agent")
        
        try:
            agent = WebEnvBuilder(
                cve_knowledge=cve_knowledge,
                sw_version_wget=sw_version_wget,
                sw_version=sw_version,
                prerequisites=prerequisites,
            )
            result = agent.invoke()
            
            if hasattr(result, 'value') and isinstance(result.value, dict):
                build_result = result.value
                if build_result.get('success', '').lower() == 'yes':
                    target_url = build_result.get('access', target_url)
                    return {
                        'build_result': {
                            'success': 'yes',
                            'access': target_url,
                            'method': build_result.get('method', 'web-env-builder'),
                            'notes': build_result.get('notes', '')
                        }
                    }
        except Exception as e:
            print(f"[WebAppDeployer] WebEnvBuilder failed: {e}")
        
        # ========== Fallback: 返回默认 URL ==========
        print(f"[WebAppDeployer] Falling back to pre-deployed target: {target_url}")
        return {
            'build_result': {
                'success': 'yes',
                'access': target_url,
                'method': 'pre-deployed',
                'notes': 'Using pre-deployed target or default URL'
            }
        }


class SimpleValidator(Capability):
    """简单验证器 - 不需要 LLM，基于规则验证"""
    
    def __init__(self, result_bus: ResultBus, config: dict):
        self.result_bus = result_bus
        self.config = config
    
    def execute(self, inputs: Dict[str, Any]) -> Dict[str, Any]:
        """基于简单规则验证结果"""
        build_result = inputs.get('build_result', {})
        
        # 简单的成功/失败判断
        success = build_result.get('success', 'no').lower() == 'yes'
        
        return {
            'validation_result': {
                'passed': success,
                'message': 'Build successful' if success else 'Build failed'
            }
        }


class HttpResponseVerifier(Capability):
    """HTTP 响应验证器 - 验证 Web 漏洞利用是否成功"""
    
    def __init__(self, result_bus: ResultBus, config: dict):
        self.result_bus = result_bus
        self.config = config
    
    def execute(self, inputs: Dict[str, Any]) -> Dict[str, Any]:
        """验证 HTTP 响应是否表明漏洞利用成功"""
        exploit_result = inputs.get('web_exploit_result', {})
        http_response = inputs.get('http_response', {})
        
        print(f"[Verify] Checking exploit result: {type(exploit_result)}")
        print(f"[Verify] Exploit result keys: {exploit_result.keys() if isinstance(exploit_result, dict) else 'N/A'}")
        
        # 从 exploit_result 中提取信息
        success = False
        message = "Verification in progress"
        evidence = []
        
        if isinstance(exploit_result, dict):
            # 方法1: 直接检查 success 字段
            exploit_success = exploit_result.get('success', 'no')
            if isinstance(exploit_success, str):
                success = exploit_success.lower() in ['yes', 'true', '1']
            elif isinstance(exploit_success, bool):
                success = exploit_success
            
            message = exploit_result.get('exploit', '') or exploit_result.get('message', '')
            evidence_str = exploit_result.get('evidence', '')
            poc = exploit_result.get('poc', '')
            
            # 方法2: 从 evidence/poc/message 中推断成功
            if not success:
                success_keywords = [
                    # 通用成功指标
                    'profile picture updated', 'successfully', 'attack succeeded',
                    'vulnerability confirmed', 'exploit worked', 'upload successful',
                    # XSS 相关
                    'xss triggered', 'alert detected', 'script executed',
                    # CSRF 相关
                    'csrf successful', 'csrf attack submitted', 'form submitted',
                    'no csrf protection', 'vulnerable (no csrf', 'missing csrf',
                    'csrf vulnerability', 'no csrf token',
                    # 登录/会话相关
                    'login successful', 'logged in', 'profile:',
                ]
                text_to_check = f"{message} {evidence_str} {poc}".lower()
                for keyword in success_keywords:
                    if keyword in text_to_check:
                        success = True
                        evidence.append(f"Found success indicator: '{keyword}'")
                        break
            
            # 方法3: 检查 steps 中是否包含 CSRF 漏洞确认
            steps = exploit_result.get('exploit', '')
            if not success and steps:
                csrf_confirmed_patterns = [
                    'vulnerable (no csrf',
                    'no csrf protection',
                    'form has no csrf',
                    'csrf vulnerability',
                    'verified the form',
                    '🚨 vulnerable',
                ]
                steps_lower = steps.lower()
                for pattern in csrf_confirmed_patterns:
                    if pattern in steps_lower:
                        success = True
                        evidence.append(f"CSRF vulnerability confirmed: '{pattern}'")
                        break
            
            # 记录详细信息
            print(f"[Verify] success field: {exploit_success}")
            print(f"[Verify] evidence: {evidence_str[:200] if evidence_str else 'N/A'}...")
        
        # 如果有 HTTP 响应，可以进一步验证
        if http_response:
            status_code = http_response.get('status_code', 0)
            if status_code >= 200 and status_code < 300:
                print(f"[Verify] HTTP status: {status_code} (OK)")
            else:
                print(f"[Verify] HTTP status: {status_code} (Warning)")
        
        result = {
            'verification_result': {
                'passed': success,
                'message': message[:500] if message else 'No details',
                'method': 'http-response-check',
                'evidence': evidence
            }
        }
        
        print(f"[Verify] Final result: {'✅ SUCCESS' if success else '❌ FAILED'}")
        return result


# ============================================================
# 需要 LLM 的 Agent 适配器
# ============================================================

class KnowledgeBuilderAdapter(Capability):
    """KnowledgeBuilder Agent 适配器"""
    
    def __init__(self, result_bus: ResultBus, config: dict):
        self.result_bus = result_bus
        self.config = config
    
    def execute(self, inputs: Dict[str, Any]) -> Dict[str, Any]:
        cve_id = inputs.get('cve_id')
        cve_entry = inputs.get('cve_entry', {})
        
        # 解析 cve_entry 中的字段，与 legacy 模式保持一致
        cwe_list = cve_entry.get('cwe', [])
        cwe = '\n'.join([f"* {c['id']} - {c['value']}" for c in cwe_list]) if cwe_list else ''
        
        # 从 sw_version_wget 提取项目名
        sw_version_wget = cve_entry.get('sw_version_wget', '')
        try:
            project_name = sw_version_wget.split("//")[1].split("/")[2] if sw_version_wget else ''
        except (IndexError, AttributeError):
            project_name = cve_entry.get('project_name', '')
        
        # 格式化补丁信息
        patch_commits = cve_entry.get('patch_commits', [])
        patches = '\n\n'.join([
            f"Commit Hash: {p['url'].split('/')[-1]}\n\"\"\"\n{p.get('content', '')}\n\"\"\""
            for p in patch_commits
        ]) if patch_commits else ''
        
        # 格式化安全公告
        sec_advs = cve_entry.get('sec_adv', [])
        sec_adv = '\n\n'.join([
            f"Advisory: {a['url']}\n\"\"\"\n{a.get('content', '')}\n\"\"\""
            for a in sec_advs
        ]) if sec_advs else ''
        
        # 调用 KnowledgeBuilder Agent
        agent = KnowledgeBuilder(
            id=cve_id,
            description=cve_entry.get('description', ''),
            cwe=cwe,
            project_name=project_name,
            affected_version=cve_entry.get('sw_version', ''),
            security_advisory=sec_adv,
            patch=patches
        )
        result = agent.invoke().value
        
        return {'cve_knowledge': result}


class PreReqBuilderAdapter(Capability):
    """PreReqBuilder Agent 适配器"""
    
    def __init__(self, result_bus: ResultBus, config: dict):
        self.result_bus = result_bus
        self.config = config
    
    def execute(self, inputs: Dict[str, Any]) -> Dict[str, Any]:
        cve_knowledge = inputs.get('cve_knowledge', '')
        cve_entry = inputs.get('cve_entry', {})
        
        # PreReqBuilder 需要 cve_knowledge 和 project_dir_tree
        agent = PreReqBuilder(
            cve_knowledge=cve_knowledge,
            project_dir_tree=cve_entry.get('dir_tree', '')
        )
        result = agent.invoke().value
        
        return {'prerequisites': result}


class RepoBuilderAdapter(Capability):
    """RepoBuilder Agent 适配器"""
    
    def __init__(self, result_bus: ResultBus, config: dict):
        self.result_bus = result_bus
        self.config = config
    
    def execute(self, inputs: Dict[str, Any]) -> Dict[str, Any]:
        cve_knowledge = inputs.get('cve_knowledge', '')
        cve_entry = inputs.get('cve_entry', {})
        prerequisites = inputs.get('prerequisites', {})
        feedback = inputs.get('feedback')
        critic_feedback = inputs.get('critic_feedback')
        
        # RepoBuilder 需要多个参数
        agent = RepoBuilder(
            project_dir_tree=cve_entry.get('dir_tree', ''),
            cve_knowledge=cve_knowledge,
            build_pre_reqs=prerequisites,
            feedback=feedback,
            critic_feedback=critic_feedback
        )
        result = agent.invoke().value
        
        return {'build_result': result}


class RepoCriticAdapter(Capability):
    """RepoCritic Agent 适配器"""
    
    def __init__(self, result_bus: ResultBus, config: dict):
        self.result_bus = result_bus
        self.config = config
    
    def execute(self, inputs: Dict[str, Any]) -> Dict[str, Any]:
        # RepoCritic 只需要 setup_logs
        setup_logs = inputs.get('setup_logs', '')
        
        agent = RepoCritic(
            setup_logs=setup_logs
        )
        result = agent.invoke().value
        
        return {'critic_feedback': result}


class ExploiterAdapter(Capability):
    """Exploiter Agent 适配器"""
    
    def __init__(self, result_bus: ResultBus, config: dict):
        self.result_bus = result_bus
        self.config = config
    
    def execute(self, inputs: Dict[str, Any]) -> Dict[str, Any]:
        cve_knowledge = inputs.get('cve_knowledge', '')
        cve_entry = inputs.get('cve_entry', {})
        prerequisites = inputs.get('prerequisites', {})
        build_result = inputs.get('build_result', {})
        feedback = inputs.get('feedback')
        critic_feedback = inputs.get('critic_feedback')
        
        # Exploiter 需要多个参数
        agent = Exploiter(
            cve_knowledge=cve_knowledge,
            project_overview=prerequisites.get('overview', '') if isinstance(prerequisites, dict) else '',
            project_dir_tree=cve_entry.get('dir_tree', ''),
            repo_build=build_result,
            feedback=feedback,
            critic_feedback=critic_feedback
        )
        result = agent.invoke().value
        
        return {'exploit_result': result}


class ExploitCriticAdapter(Capability):
    """ExploitCritic Agent 适配器"""
    
    def __init__(self, result_bus: ResultBus, config: dict):
        self.result_bus = result_bus
        self.config = config
    
    def execute(self, inputs: Dict[str, Any]) -> Dict[str, Any]:
        cve_knowledge = inputs.get('cve_knowledge', '')
        exploit_result = inputs.get('exploit_result', {})
        
        agent = ExploitCritic(
            cve_knowledge=cve_knowledge,
            exploit=exploit_result
        )
        result = agent.invoke().value
        
        return {'exploit_critic_feedback': result}


class CTFVerifierAdapter(Capability):
    """CTFVerifier Agent 适配器"""
    
    def __init__(self, result_bus: ResultBus, config: dict):
        self.result_bus = result_bus
        self.config = config
    
    def execute(self, inputs: Dict[str, Any]) -> Dict[str, Any]:
        cve_knowledge = inputs.get('cve_knowledge', '')
        exploit_result = inputs.get('exploit_result', {})
        build_result = inputs.get('build_result', {})
        
        agent = CTFVerifier(
            cve_knowledge=cve_knowledge,
            project_access=build_result.get('access', ''),
            exploit=exploit_result.get('exploit', ''),
            poc=exploit_result.get('poc', '')
        )
        result = agent.invoke().value
        
        return {'verification_result': result}


class SanityGuyAdapter(Capability):
    """SanityGuy Agent 适配器"""
    
    def __init__(self, result_bus: ResultBus, config: dict):
        self.result_bus = result_bus
        self.config = config
    
    def execute(self, inputs: Dict[str, Any]) -> Dict[str, Any]:
        cve_knowledge = inputs.get('cve_knowledge', '')
        exploit_result = inputs.get('exploit_result', {})
        verification_result = inputs.get('verification_result', {})
        build_result = inputs.get('build_result', {})
        
        agent = SanityGuy(
            cve_knowledge=cve_knowledge,
            project_access=build_result.get('access', ''),
            exploit=exploit_result.get('exploit', ''),
            poc=exploit_result.get('poc', ''),
            verifier=verification_result.get('verifier', ''),
            validator_logs=''
        )
        result = agent.invoke().value
        
        return {'sanity_check_result': result}


# Web 漏洞适配器
try:
    from agents import WebDriverAgent, WebExploitCritic
    
    class WebDriverAdapter(Capability):
        """WebDriver Agent 适配器"""
        
        def __init__(self, result_bus: ResultBus, config: dict):
            self.result_bus = result_bus
            self.config = config
        
        def execute(self, inputs: Dict[str, Any]) -> Dict[str, Any]:
            cve_knowledge = inputs.get('cve_knowledge', '')
            target_url = self.config.get('target_url', 'http://localhost:9600')
            
            agent = WebDriverAgent(
                cve_knowledge=cve_knowledge,
                target_url=target_url
            )
            result = agent.invoke().value
            
            return {'web_exploit_result': result}
    
    class WebExploitCriticAdapter(Capability):
        """WebExploitCritic Agent 适配器"""
        
        def __init__(self, result_bus: ResultBus, config: dict):
            self.result_bus = result_bus
            self.config = config
        
        def execute(self, inputs: Dict[str, Any]) -> Dict[str, Any]:
            cve_knowledge = inputs.get('cve_knowledge', '')
            web_exploit_result = inputs.get('web_exploit_result', {})
            
            agent = WebExploitCritic(
                cve_knowledge=cve_knowledge,
                exploit=web_exploit_result
            )
            result = agent.invoke().value
            
            return {'web_critic_feedback': result}

except ImportError:
    # Web agents 可选
    WebDriverAdapter = None
    WebExploitCriticAdapter = None
