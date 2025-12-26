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

# P1 优化：幻觉检测
from core.hallucination_guard import (
    HallucinationDetector,
    HallucinationStats,
    detect_hallucination,
    get_continuation_feedback
)

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
    WebEnvBuilder,
    WebEnvCritic
)
from agents.configInferencer import ConfigInferencer


# ============================================================
# 不需要 LLM 的纯功能性 Capability
# ============================================================

class BrowserEnvironmentProvider(Capability):
    """浏览器环境提供者 - 不需要 LLM，只是启动/配置浏览器环境
    
    重要: 
    1. 优先从 build_result.access 获取目标 URL
    2. 如果没有 access，使用 build_result.port 构建 URL
    3. 在配置浏览器前，等待服务完全就绪（Health Check）
    """
    
    def __init__(self, result_bus: ResultBus, config: dict):
        self.result_bus = result_bus
        self.config = config
    
    def execute(self, inputs: Dict[str, Any]) -> Dict[str, Any]:
        """启动浏览器环境，返回浏览器配置信息"""
        browser_engine = self.config.get('browser_engine', 'selenium')
        
        # ========== 从 build_result 动态获取 target_url ==========
        build_result = inputs.get('build_result', {})
        target_url = None
        
        if isinstance(build_result, dict):
            # 1. 优先使用 access URL
            deployed_url = build_result.get('access', '')
            if deployed_url:
                target_url = deployed_url
                print(f"[Browser] ✅ Using deployed URL from build_result: {target_url}")
            else:
                # 2. 使用 build_result 中的 port 构建 URL (Docker容器内使用 host.docker.internal)
                port = build_result.get('port', 0)
                if port:
                    target_url = f'http://host.docker.internal:{port}'
                    print(f"[Browser] ✅ Using port from build_result: {target_url}")
        
        # 3. 回退到 config
        if not target_url:
            target_url = self.config.get('target_url', 'http://host.docker.internal:9600')
            print(f"[Browser] ⚠️ No URL/port in build_result, using config/default: {target_url}")
        
        # ========== 关键: 等待服务就绪（Health Check）==========
        # 在配置浏览器前，确保 Web 服务已完全启动
        # 这避免了 "ERR_CONNECTION_REFUSED" 的问题
        try:
            from toolbox.command_ops import wait_for_service
            health_result = wait_for_service(target_url, timeout=60, interval=3)
            
            if not health_result['ready']:
                print(f"[Browser] ⚠️ Service may not be fully ready: {health_result['message']}")
                # 不阻止执行，但记录警告
        except Exception as e:
            print(f"[Browser] ⚠️ Health check failed: {e}")
        
        print(f"[Browser] Configuring browser environment: {browser_engine}")
        print(f"[Browser] Target URL: {target_url}")
        
        browser_config = {
            'engine': browser_engine,
            'target_url': target_url,
            'headless': self.config.get('headless', True),
            'timeout': self.config.get('timeout', 30),
            'ready': True,
            'build_info': build_result
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
    """Web 应用部署器 - 使用分拆的 3 个 Agent 部署 Web 应用
    
    部署流程：
    1. ProjectSetupAgent: 准备环境（检测框架、安装依赖）
    2. ServiceStartAgent: 启动服务
    3. HealthCheckAgent: 验证服务（可选）
    
    这种分拆方式让每个 Agent 专注于单一职责，减少 token 消耗。
    """
    
    # 框架默认端口映射
    FRAMEWORK_DEFAULT_PORTS = {
        'open-webui': 8080,
        'mlflow': 5000,
        'flask': 5000,
        'django': 8000,
        'fastapi': 8000,
        'streamlit': 8501,
        'gradio': 7860,
    }
    
    def __init__(self, result_bus: ResultBus, config: dict):
        self.result_bus = result_bus
        self.config = config
    
    def _extract_port_from_knowledge(self, cve_knowledge: str) -> int:
        """从 CVE Knowledge 中提取端口号"""
        import re
        # 尝试匹配常见的端口模式
        patterns = [
            r'port[:\s]+(\d{4,5})',           # port: 8080 or port 8080
            r'localhost:(\d{4,5})',            # localhost:8080
            r'0\.0\.0\.0:(\d{4,5})',           # 0.0.0.0:8080
            r'--port[=\s]+(\d{4,5})',          # --port=8080 or --port 8080
            r'-p[=\s]+(\d{4,5})',              # -p 8080
            r'default port.*?(\d{4,5})',       # default port is 8080
            r'runs on port (\d{4,5})',         # runs on port 8080
        ]
        
        for pattern in patterns:
            match = re.search(pattern, cve_knowledge, re.IGNORECASE)
            if match:
                port = int(match.group(1))
                if 1024 <= port <= 65535:  # 有效端口范围
                    return port
        return 0  # 未找到
    
    def _detect_framework_from_knowledge(self, cve_knowledge: str) -> str:
        """从 CVE Knowledge 中检测框架类型"""
        knowledge_lower = cve_knowledge.lower()
        for framework in self.FRAMEWORK_DEFAULT_PORTS.keys():
            if framework.replace('-', '') in knowledge_lower.replace('-', ''):
                return framework
        return ''
    
    def _check_agent_hallucination(self, agent, build_result: dict, sw_version: str = "") -> tuple:
        """
        P1 优化：检查 Agent 是否发生幻觉式停止
        
        检测 Agent 说 "I will proceed..." 但没有实际执行工具的情况
        
        Args:
            agent: WebEnvBuilder agent 实例
            build_result: Parser 解析的结果
            sw_version: 软件版本（用于生成上下文反馈）
            
        Returns:
            (is_hallucination, feedback): 是否幻觉及建议的反馈
        """
        # 如果 Parser 已经检测到 "continue" 状态，直接返回
        if build_result.get('success') == 'continue':
            return True, None  # 已经有处理，不需要额外反馈
        
        # 检查 chat_history 中最后一条 AI 消息
        if not hasattr(agent, 'chat_history') or not agent.chat_history:
            return False, None
        
        # 获取最后一条 AI 消息
        last_ai_response = ""
        for msg in reversed(agent.chat_history):
            if hasattr(msg, 'type') and msg.type == 'ai':
                last_ai_response = msg.content if hasattr(msg, 'content') else str(msg)
                break
            elif isinstance(msg, dict) and msg.get('role') == 'assistant':
                last_ai_response = msg.get('content', '')
                break
        
        if not last_ai_response:
            return False, None
        
        # 检查是否有工具调用
        has_tool_call = False
        if hasattr(agent, 'executor') and hasattr(agent.executor, 'toolcall_metadata'):
            # 检查最近是否有成功的工具调用
            metadata = agent.executor.toolcall_metadata
            for tool_name, tool_meta in metadata.items():
                if tool_meta.get('num_successful_tool_calls', 0) > 0:
                    has_tool_call = True
                    break
        
        # 使用幻觉检测器
        result = detect_hallucination(last_ai_response, has_tool_call=has_tool_call)
        
        if result.is_hallucination:
            print(f"[WebAppDeployer] 🔴 Hallucination detected! Patterns: {result.patterns_matched}")
            # 生成针对性的反馈
            context = f"deploying {sw_version}" if sw_version else "web deployment"
            feedback = get_continuation_feedback(last_ai_response, context)
            return True, feedback
        
        return False, None

    def execute(self, inputs: Dict[str, Any]) -> Dict[str, Any]:
        cve_entry = inputs.get('cve_entry', {})
        cve_knowledge = inputs.get('cve_knowledge', '')
        cve_id = inputs.get('cve_id', '')
        deployment_strategy = inputs.get('deployment_strategy', {})
        
        # ========== 检查是否为硬件漏洞 ==========
        if deployment_strategy.get('is_hardware'):
            print(f"[WebAppDeployer] ⚠️ Hardware vulnerability detected - cannot deploy with software")
            print(f"[WebAppDeployer] ℹ️ Notes: {deployment_strategy.get('deployment_notes', 'Hardware vulnerability')}")
            return {
                'build_result': {
                    'success': 'no',
                    'access': 'N/A',
                    'method': 'hardware-skip',
                    'notes': f"Hardware vulnerability: {deployment_strategy.get('deployment_notes', 'Cannot reproduce with software')}"
                }
            }
        
        # 获取软件信息
        sw_version_wget = cve_entry.get('sw_version_wget', '')
        sw_version = cve_entry.get('sw_version', '')
        
        print(f"[WebAppDeployer] Deploying web application...")
        print(f"[WebAppDeployer] Software version: {sw_version}")
        
        # 🎯 优先检查Vulhub/Vulfocus预构建环境
        prebuilt_deployed = False
        try:
            from toolbox.vuln_env_sources import VulnEnvManager
            
            print(f"\n[WebAppDeployer] 🔍 Checking Vulhub/Vulfocus for pre-built environment...")
            manager = VulnEnvManager()
            
            env_result = manager.find_env(cve_id)
            
            if env_result:
                source, env_info = env_result
                print(f"[WebAppDeployer] ✨ Found pre-built environment in {env_info['source']}!")
                print(f"[WebAppDeployer] 📦 Deploying from {env_info['source']}...\n")
                
                deploy_result = manager.deploy_env(cve_id)
                
                if deploy_result.get('success'):
                    prebuilt_deployed = True
                    print(f"\n[WebAppDeployer] 🎉 Pre-built environment deployed successfully!")
                    print(f"   Source: {deploy_result['source']}")
                    print(f"   Method: {deploy_result['deployment_method']}")
                    
                    # 优先使用返回的 target_url
                    if 'target_url' in deploy_result and deploy_result['target_url']:
                        target_url = deploy_result['target_url']
                    # 或使用 port 构造 URL (Docker容器内使用 host.docker.internal)
                    elif 'port' in deploy_result and deploy_result['port']:
                        target_url = f"http://host.docker.internal:{deploy_result['port']}"
                    # 提取端口信息 (兼容旧格式)
                    elif 'ports' in deploy_result:
                        port_info = deploy_result.get('ports', '')
                        if ':' in str(port_info):
                            # 从 "0.0.0.0:8080->8080/tcp" 提取主机端口
                            import re
                            match = re.search(r':(\d+)->', str(port_info))
                            if match:
                                target_url = f"http://host.docker.internal:{match.group(1)}"
                            else:
                                target_url = "http://host.docker.internal:8080"  # fallback
                        else:
                            target_url = "http://host.docker.internal:8080"  # fallback
                    else:
                        target_url = "http://host.docker.internal:8080"  # fallback
                    
                    print(f"[WebAppDeployer] 🌐 Target URL: {target_url}")
                    
                    # 从 target_url 提取端口
                    port = None
                    import re
                    match = re.search(r':(\d+)', target_url)
                    if match:
                        port = int(match.group(1))
                    
                    # 返回成功结果 (注意: 必须包在 build_result 里,符合 DAG 约定)
                    return {
                        'build_result': {
                            'success': 'yes',
                            'access': target_url,
                            'port': port,
                            'method': 'prebuilt',
                            'source': deploy_result['source'],
                            'deployment_info': deploy_result
                        }
                    }
                else:
                    print(f"\n[WebAppDeployer] ⚠️ Pre-built deployment failed: {deploy_result.get('error')}")
                    print(f"   Falling back to custom deployment...\n")
            else:
                print(f"[WebAppDeployer] ℹ️ No pre-built environment found, using custom deployment\n")
        
        except Exception as e:
            print(f"[WebAppDeployer] ⚠️ Vuln source check failed: {e}")
            print(f"   Falling back to custom deployment...\n")
        
        # 如果预构建部署失败或未找到，继续原有流程
        explicit_target_url = self.config.get('target_url')
        
        # ========== 智能端口检测 ==========
        # 优先级: 1. CVE Knowledge 中明确指定 > 2. 框架默认端口 > 3. config 配置 > 4. 全局默认 9600
        
        # 1. 从 CVE Knowledge 提取端口
        knowledge_port = self._extract_port_from_knowledge(cve_knowledge)
        
        # 2. 从框架检测获取默认端口
        detected_framework = self._detect_framework_from_knowledge(cve_knowledge)
        framework_port = self.FRAMEWORK_DEFAULT_PORTS.get(detected_framework, 0)
        
        # 3. 确定最终使用的端口
        if knowledge_port:
            port = knowledge_port
            print(f"[WebAppDeployer] 📍 Port from CVE knowledge: {port}")
        elif framework_port:
            port = framework_port
            print(f"[WebAppDeployer] 📍 Port from framework default ({detected_framework}): {port}")
        else:
            port = self.config.get('port', 9600)
            print(f"[WebAppDeployer] 📍 Using config/default port: {port}")
        
        target_url = f'http://localhost:{port}'
        print(f"[WebAppDeployer] 🎯 Target URL: {target_url}")
        
        # 如果外部显式提供 target_url，直接使用并跳过自动启动
        if explicit_target_url:
            print(f"[WebAppDeployer] 🛠 Using provided target URL (skip auto-start): {explicit_target_url}")
            import subprocess as sp_check
            try:
                check_result = sp_check.run(
                    ['curl', '-s', '-o', '/dev/null', '-w', '%{http_code}', f'{explicit_target_url}/'],
                    capture_output=True, text=True, timeout=10
                )
                status_code = check_result.stdout.strip()
                if status_code and not status_code.startswith('0'):
                    return {
                        'build_result': {
                            'success': 'yes',
                            'access': explicit_target_url,
                            'method': 'pre-deployed',
                            'notes': f'User-provided target reachable, HTTP {status_code}'
                        }
                    }
            except Exception as e:
                print(f"[WebAppDeployer] Provided target unreachable: {e}")
            return {
                'build_result': {
                    'success': 'no',
                    'access': explicit_target_url,
                    'method': 'pre-deployed',
                    'notes': 'Provided target_url is not reachable; auto-start skipped as requested.'
                }
            }
        
        # ========== 1. 优先检查目标是否已经可访问 ==========
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
        
        # ========== 2. 使用分拆的 Agent 流水线 ==========
        try:
            sw_name = sw_version_wget.split('/')[-1] if sw_version_wget else 'unknown'
            
            # ========== Stage 1: ProjectSetupAgent ==========
            print(f"[WebAppDeployer] Stage 1: Project Setup")
            
            from agents.projectSetup import ProjectSetupAgent
            setup_agent = ProjectSetupAgent(
                cve_id=cve_id,
                sw_name=sw_name,
                sw_version=sw_version,
                cve_knowledge=cve_knowledge
            )
            setup_result_raw = setup_agent.run()
            
            # 解析结果
            import json
            try:
                setup_result = json.loads(setup_result_raw) if isinstance(setup_result_raw, str) else setup_result_raw
            except:
                setup_result = {'raw_output': setup_result_raw, 'success': False}
            
            print(f"[WebAppDeployer] Stage 1 Result: {setup_result.get('success', False)}")
            
            if not setup_result.get('success', False):
                # 如果环境准备失败，尝试 fallback
                print(f"[WebAppDeployer] ⚠️ Project setup failed, trying fallback...")
            
            # ========== Stage 2: ServiceStartAgent ==========
            print(f"[WebAppDeployer] Stage 2: Service Start")
            
            from agents.serviceStart import ServiceStartAgent
            start_agent = ServiceStartAgent(
                setup_result=json.dumps(setup_result, indent=2),
                port=port
            )
            service_result_raw = start_agent.run()
            
            try:
                service_result = json.loads(service_result_raw) if isinstance(service_result_raw, str) else service_result_raw
            except:
                service_result = {'raw_output': service_result_raw, 'success': False}
            
            print(f"[WebAppDeployer] Stage 2 Result: {service_result.get('success', False)}")
            
            # ========== Stage 3: Health Check (Optional) ==========
            # 简化为直接 HTTP 检查，不需要额外 Agent
            access_url = service_result.get('access_url', target_url)
            
            try:
                check_result = subprocess.run(
                    ['curl', '-s', '-o', '/dev/null', '-w', '%{http_code}', f'{access_url}/'],
                    capture_output=True, text=True, timeout=10
                )
                status_code = check_result.stdout.strip()
                if status_code and not status_code.startswith('0'):
                    print(f"[WebAppDeployer] ✅ Service is responding (HTTP {status_code})")
                    return {
                        'build_result': {
                            'success': 'yes',
                            'access': access_url,
                            'method': 'agent-pipeline',
                            'notes': f'Deployed via 3-agent pipeline, HTTP {status_code}'
                        }
                    }
            except Exception as e:
                print(f"[WebAppDeployer] Health check failed: {e}")
            
            # 即使健康检查失败，如果服务启动了，也返回成功
            if service_result.get('success'):
                return {
                    'build_result': {
                        'success': 'yes',
                        'access': access_url,
                        'method': 'agent-pipeline',
                        'notes': service_result.get('notes', '')
                    }
                }
                
        except Exception as e:
            print(f"[WebAppDeployer] Agent pipeline failed: {e}")
            import traceback
            traceback.print_exc()
        
        # ========== 3. Fallback: WebEnvBuilder with Critic Loop ==========
        print(f"[WebAppDeployer] Trying WebEnvBuilder with feedback loop...")
        
        web_env_done = False
        feedback = None
        critic_feedback = None
        max_tries = 3
        attempt = 1
        
        while not web_env_done and attempt <= max_tries:
            try:
                if feedback or critic_feedback:
                    print(f"\n[WebAppDeployer] 🔄 Retry #{attempt} with feedback")
                
                # 执行 WebEnvBuilder
                agent = WebEnvBuilder(
                    cve_knowledge=cve_knowledge,
                    sw_version_wget=sw_version_wget,
                    sw_version=sw_version,
                    prerequisites={},
                    feedback=critic_feedback or feedback,
                )
                result = agent.invoke()
                
                if hasattr(result, 'value') and isinstance(result.value, dict):
                    build_result = result.value
                    
                    # 🔴 P1 优化：双重幻觉检测
                    # 检测方式1: Parser 层检测 (success == 'continue')
                    # 检测方式2: 响应文本层检测 (chat_history 分析)
                    
                    is_parser_hallucination = build_result.get('success') == 'continue' or build_result.get('method') == 'in_progress'
                    is_text_hallucination, hallucination_feedback = self._check_agent_hallucination(
                        agent, build_result, sw_version
                    )
                    
                    if is_parser_hallucination or is_text_hallucination:
                        print(f"[WebAppDeployer] ⚠️ Agent stopped early (did not complete all steps)")
                        print(f"[WebAppDeployer] Detection: Parser={is_parser_hallucination}, Text={is_text_hallucination}")
                        if build_result.get('notes'):
                            print(f"[WebAppDeployer] Notes: {build_result.get('notes', 'Unknown')[:200]}")
                        
                        # 使用幻觉检测器生成的反馈（如果有），否则用默认反馈
                        if hallucination_feedback:
                            critic_feedback = hallucination_feedback
                        else:
                            critic_feedback = (
                                "CRITICAL: You stopped before completing all deployment steps. "
                                "You MUST continue the deployment workflow: "
                                f"1) If repo was cloned, checkout the correct version (git checkout {sw_version}). "
                                "2) Install dependencies (composer install / npm install / pip install). "
                                "3) Start the service on the correct port. "
                                "4) Verify the service with curl. "
                                "5) Only output JSON after verification succeeds. "
                                "DO NOT describe what you will do - EXECUTE IT NOW."
                            )
                        attempt += 1
                        continue
                    
                    deployed_url = build_result.get('access', '')
                    if deployed_url:
                        target_url = deployed_url
                    
                    # 统一端口来源：先用返回的 port，再从 URL 提取，最后回落到已推断的 port
                    port_from_build = build_result.get('port')
                    port_from_access = None
                    if deployed_url:
                        try:
                            import re
                            match = re.search(r':(\d+)', deployed_url)
                            if match:
                                port_from_access = int(match.group(1))
                        except Exception:
                            port_from_access = None
                    # 优先使用已知/推断端口，其次才信任 builder 输出的 URL 里的端口，避免错回落到 9600
                    port_final = port_from_build or port or port_from_access
                    if port_final:
                        target_url = f"http://localhost:{port_final}"
                        port = port_final  # keep downstream health/check consistent
                    
                    success = build_result.get('success', '').lower() == 'yes'
                    
                    # Guardrail: verify service is really up before accepting success
                    if success and port_final:
                        try:
                            check_url = target_url or f"http://localhost:{port_final}"
                            curl_result = subprocess.run(
                                ["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}", check_url, "--max-time", "10"],
                                capture_output=True,
                                text=True,
                                timeout=15
                            )
                            http_code = int(curl_result.stdout.strip()) if curl_result.stdout.strip().isdigit() else 0
                            if not ((200 <= http_code < 400) or http_code == 404):
                                success = False
                                build_result['success'] = 'no'
                                build_result['notes'] = f"Builder reported success but service not reachable (HTTP {http_code})"
                        except Exception as e:
                            success = False
                            build_result['success'] = 'no'
                            build_result['notes'] = f"Builder reported success but health check failed: {e}"
                    
                    # 提取部署日志
                    from toolbox import helper
                    deployment_logs = helper.parse_chat_messages(agent.chat_history, include_human=True)
                    
                    if success:
                        print(f"[WebAppDeployer] ✅ Deployment succeeded on attempt #{attempt}")
                        return {
                            'build_result': {
                                'success': 'yes',
                                'access': target_url,
                                'port': port_final,
                                'method': f'web-env-builder-retry-{attempt}',
                                'notes': build_result.get('notes', '')
                            }
                        }
                    
                    # 失败 - 调用 Critic
                    print(f"[WebAppDeployer] 👀 Deployment failed, invoking WebEnvCritic...")
                    
                    from agents.webEnvCritic import WebEnvCritic
                    critic = WebEnvCritic(deployment_logs=deployment_logs)
                    critic_result = critic.invoke()
                    
                    if hasattr(critic_result, 'value'):
                        critic_result = critic_result.value
                    
                    print(f"[WebAppDeployer] Critic Decision: {critic_result.get('decision', 'unknown')}")
                    print(f"[WebAppDeployer] Fixable: {critic_result.get('possible', 'unknown')}")
                    
                    # 保存 critic 分析
                    try:
                        helper.save_response(cve_id, critic_result, f"web_env_critic_attempt_{attempt}", struct=True)
                    except:
                        pass
                    
                    if critic_result.get('decision', '').lower() == 'yes':
                        # Critic 认为实际上成功了（可能是误判）
                        print(f"[WebAppDeployer] ✅ Critic says deployment actually succeeded")
                        web_env_done = True
                        return {
                            'build_result': {
                                'success': 'yes',
                                'access': target_url,
                                'port': port_final,
                                'method': f'web-env-builder-retry-{attempt}',
                                'notes': 'Critic confirmed success'
                            }
                        }
                    elif critic_result.get('possible', '').lower() == 'no':
                        # 无法修复，停止重试
                        print(f"[WebAppDeployer] ❌ Critic says issue is not fixable")
                        break
                    else:
                        # 可以修复，获取反馈并重试
                        critic_feedback = critic_result.get('feedback', '')
                        if not critic_feedback or critic_feedback.lower() == 'n/a':
                            print(f"[WebAppDeployer] ⚠️ No actionable feedback from critic")
                            break
                        
                        print(f"[WebAppDeployer] 📋 Feedback: {critic_feedback[:200]}...")
                        feedback = None  # 清除旧 feedback
                        attempt += 1
                        continue
                
                # 如果没有返回有效结果，停止
                break
                
            except Exception as e:
                print(f"[WebAppDeployer] WebEnvBuilder attempt #{attempt} failed: {e}")
                import traceback
                traceback.print_exc()
                break
        
        # ========== 4. Final Fallback ==========
        # 注意：即使部署失败，也保持使用正确检测到的端口，不要回退到其他端口
        # 因为项目本身需要特定端口才能正常工作
        print(f"[WebAppDeployer] ⚠️ All deployment attempts failed")
        # 若 URL 与当前端口不一致，统一到当前端口
        if port:
            target_url = f"http://localhost:{port}"
        print(f"[WebAppDeployer] 📍 Keeping target URL: {target_url} (port {port})")
        print(f"[WebAppDeployer] 💡 The service may need manual intervention to start")
        return {
            'build_result': {
                'success': 'no',  # 标记为失败，不要假装成功
                'access': target_url,
                'port': port,
                'method': 'fallback',
                'notes': f'Deployment failed. Target should be {target_url} but service is not running.'
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
                    'xss vulnerability', 'reflected xss', 'stored xss',
                    # CSRF 相关
                    'csrf successful', 'csrf attack submitted', 'form submitted',
                    'no csrf protection', 'vulnerable (no csrf', 'missing csrf',
                    'csrf vulnerability', 'no csrf token',
                    # LFI/路径遍历 相关
                    'lfi detected', 'lfi vulnerability', 'path traversal',
                    'root:', '/bin/bash', 'etc/passwd', 'win.ini',
                    'file inclusion', 'directory traversal',
                    # SQL 注入相关
                    'sql injection', 'sqli', 'database error', 'syntax error',
                    'union select', 'or 1=1',
                    # SSRF 相关
                    'ssrf', 'server-side request', 'internal service',
                    # 文件上传相关
                    'file uploaded', 'upload success', 'shell uploaded',
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
    """KnowledgeBuilder Agent 适配器（增强版：集成部署策略分析）"""
    
    def __init__(self, result_bus: ResultBus, config: dict):
        self.result_bus = result_bus
        self.config = config
    
    def execute(self, inputs: Dict[str, Any]) -> Dict[str, Any]:
        cve_id = inputs.get('cve_id')
        cve_entry = inputs.get('cve_entry', {})
        
        # ========== 1. 调用部署策略分析器（新增）==========
        print(f"[KnowledgeBuilder] 🔍 Analyzing deployment strategy...")
        deployment_strategy = None
        
        try:
            # 获取 CVE 描述
            description = cve_entry.get('description', '')
            
            # 动态导入避免循环依赖
            import sys
            import os
            sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'agents'))
            from deploymentStrategyAnalyzer import DeploymentStrategyAnalyzer
            
            analyzer = DeploymentStrategyAnalyzer(cve_id=cve_id, cve_description=description)
            deployment_strategy = analyzer.invoke()
            
            if deployment_strategy:
                print(f"[KnowledgeBuilder] ✅ Deployment strategy: {deployment_strategy['strategy_type']}")
                print(f"[KnowledgeBuilder] 📦 Repository: {deployment_strategy.get('repository_url', 'N/A')}")
                
                # 如果是硬件漏洞，直接返回错误
                if deployment_strategy.get('is_hardware'):
                    print(f"[KnowledgeBuilder] ⚠️ Hardware vulnerability detected - skipping")
                    return {
                        'cve_knowledge': f"## Hardware Vulnerability\n\n{deployment_strategy['deployment_notes']}",
                        'deployment_strategy': deployment_strategy
                    }
        except Exception as e:
            print(f"[KnowledgeBuilder] ⚠️ Deployment strategy analysis failed: {e}")
            import traceback
            traceback.print_exc()
        
        # ========== 2. 原有的 KnowledgeBuilder 逻辑 ==========
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
        
        # ========== 调用 ConfigInferencer 推理完整配置 ==========
        # 使用本地规则推理（快速，不消耗 LLM token）
        inferred_config = ConfigInferencer.infer_config_locally(result)
        
        # 如果推理出了启动命令，将其附加到 cve_knowledge 中
        if inferred_config.get('startup_cmd'):
            config_section = f"""

## Inferred Environment Configuration
- Port: {inferred_config.get('port', 'N/A')}
- Startup Command: {inferred_config.get('startup_cmd', 'N/A')}
- Target Endpoint: {inferred_config.get('target_endpoint', 'N/A')}
- Framework: {inferred_config.get('framework', 'N/A')}
- Special Mode: {inferred_config.get('special_mode', 'None')}
- Reasoning: {'; '.join(inferred_config.get('notes', []))}
"""
            result = result + config_section
            print(f"[ConfigInferencer] ✅ Inferred startup: {inferred_config.get('startup_cmd')}")
        
        # ========== 3. 附加部署策略信息到 cve_knowledge（新增）==========
        if deployment_strategy and deployment_strategy.get('repository_url'):
            strategy_section = f"""

## 🚀 DEPLOYMENT STRATEGY (USE THIS - DO NOT GUESS!)

**Repository URL**: {deployment_strategy['repository_url']}
**Platform**: {deployment_strategy.get('platform', 'N/A')}
**Language**: {deployment_strategy.get('language', 'Unknown')}
**Build Tool**: {deployment_strategy.get('build_tool', 'Unknown')}

### Build Commands:
```bash
{chr(10).join(deployment_strategy.get('build_commands', ['# No specific build commands']))}
```

### Start Commands:
```bash
{chr(10).join(deployment_strategy.get('start_commands', ['# No specific start commands']))}
```

### Deployment Notes:
{deployment_strategy.get('deployment_notes', 'N/A')}

⚠️ **CRITICAL INSTRUCTIONS**:
1. DO NOT try to find Docker images or guess repository URLs
2. USE THE REPOSITORY URL PROVIDED ABOVE
3. Clone from the specified repository and follow build/start commands
4. If build commands fail, analyze error and adapt (but keep using the same repo)
"""
            result = result + strategy_section
            print(f"[KnowledgeBuilder] ✅ Deployment strategy appended to cve_knowledge")
        
        return {
            'cve_knowledge': result,
            'deployment_strategy': deployment_strategy or {}
        }


class ConfigInferencerAdapter(Capability):
    """
    ConfigInferencer Adapter: 可独立使用的配置推理能力
    
    通常不需要单独调用，KnowledgeBuilderAdapter 已集成本地推理。
    此 Adapter 用于需要 LLM 进行复杂推理的场景。
    """
    
    def __init__(self, result_bus: ResultBus, config: dict):
        self.result_bus = result_bus
        self.config = config
    
    def execute(self, inputs: Dict[str, Any]) -> Dict[str, Any]:
        cve_knowledge = inputs.get('cve_knowledge', '')
        framework_hint = inputs.get('framework_hint', '')
        
        # 优先使用本地推理（快速且免费）
        if self.config.get('use_local_inference', True):
            result = ConfigInferencer.infer_config_locally(cve_knowledge)
            return {'inferred_config': result}
        
        # 使用 LLM 推理（更智能但消耗 token）
        agent = ConfigInferencer(
            cve_knowledge=cve_knowledge,
            framework_hint=framework_hint
        )
        result = agent.invoke().value
        return {'inferred_config': result}


class PreReqBuilderAdapter(Capability):
    """PreReqBuilder Agent 适配器
    
    对于 Web CVE，dir_tree 通常为空。在这种情况下，我们使用基于 CVE 知识的
    智能推断，而不是让 Agent 在空目录中探索。
    """
    
    def __init__(self, result_bus: ResultBus, config: dict):
        self.result_bus = result_bus
        self.config = config
    
    def execute(self, inputs: Dict[str, Any]) -> Dict[str, Any]:
        cve_knowledge = inputs.get('cve_knowledge', '')
        cve_entry = inputs.get('cve_entry', {})
        deployment_strategy = inputs.get('deployment_strategy', {})
        dir_tree = cve_entry.get('dir_tree', '')
        sw_version = cve_entry.get('sw_version', '')
        
        # ========== 检查是否为硬件漏洞 ==========
        if deployment_strategy.get('is_hardware'):
            print(f"[PreReqBuilder] ⚠️ Hardware vulnerability detected - skipping prerequisite analysis")
            return {
                'prerequisites': {
                    'overview': 'Hardware vulnerability - cannot analyze prerequisites',
                    'is_hardware': True
                }
            }
        
        # ========== 关键优化: 当 dir_tree 为空时，使用智能推断 ==========
        # 这避免了 PreReqBuilder 在空目录中无限循环执行 ls 命令
        if not dir_tree or not dir_tree.strip():
            print(f"[PreReqBuilder] No dir_tree available, using smart inference")
            
            # 基于 CVE 知识推断基本需求
            prerequisites = self._infer_prerequisites_from_knowledge(cve_knowledge, sw_version)
            print(f"[PreReqBuilder] Inferred prerequisites: {prerequisites['overview'][:100]}...")
            
            return {'prerequisites': prerequisites}
        
        # 有 dir_tree 时，使用传统的 PreReqBuilder Agent 分析
        print(f"[PreReqBuilder] Analyzing project with dir_tree...")
        agent = PreReqBuilder(
            cve_knowledge=cve_knowledge,
            project_dir_tree=dir_tree
        )
        result = agent.invoke().value
        
        return {'prerequisites': result}
    
    def _infer_prerequisites_from_knowledge(self, cve_knowledge: str, sw_version: str) -> dict:
        """从 CVE 知识中智能推断项目需求
        
        当没有 dir_tree 时（常见于 Web CVE），我们使用启发式方法推断需求。
        """
        knowledge_lower = cve_knowledge.lower()
        
        # 检测框架类型
        framework = "unknown"
        services = "Web server"
        output = "HTTP service on specified port"
        
        if 'mlflow' in knowledge_lower:
            framework = "MLflow"
            services = "MLflow tracking server with authentication if required"
            if 'basic-auth' in knowledge_lower or 'authentication' in knowledge_lower:
                services += " (requires --app-name basic-auth for authentication features)"
            output = "MLflow server running on port 5000"
        elif 'django' in knowledge_lower:
            framework = "Django"
            services = "Django development server (manage.py runserver)"
            output = "Django server running on port 8000"
        elif 'flask' in knowledge_lower:
            framework = "Flask"
            services = "Flask development server"
            output = "Flask server running on port 5000"
        elif 'fastapi' in knowledge_lower:
            framework = "FastAPI"
            services = "Uvicorn ASGI server"
            output = "FastAPI server running on port 8000"
        
        overview = f"""Web application vulnerability in {sw_version or framework}.
This is a web-based CVE that requires deploying a web application.
The vulnerable software should be installed via pip or downloaded from source.
Key focus areas based on CVE knowledge: Authentication, Authorization, CSRF, XSS, or API vulnerabilities."""
        
        files = f"""No local source directory available.
Install from PyPI: pip install {sw_version.replace('v', '').replace('V', '') if sw_version else framework.lower()}
Or download from GitHub and follow installation instructions."""
        
        return {
            'overview': overview,
            'files': files,
            'services': services,
            'output': output
        }


class RepoBuilderAdapter(Capability):
    """RepoBuilder Agent 适配器"""
    
    def __init__(self, result_bus: ResultBus, config: dict):
        self.result_bus = result_bus
        self.config = config
    
    def execute(self, inputs: Dict[str, Any]) -> Dict[str, Any]:
        # ========== 处理 native-local 流程的特殊情况 ==========
        # native-local 流程的 inputs 只有 cve_info，需要解包
        cve_info = inputs.get('cve_info', {})
        if cve_info and isinstance(cve_info, dict):
            # 从 cve_info 中提取 cve_knowledge
            cve_knowledge = cve_info.get('cve_knowledge', inputs.get('cve_knowledge', ''))
            deployment_strategy = cve_info.get('deployment_strategy', {})
        else:
            cve_knowledge = inputs.get('cve_knowledge', '')
            deployment_strategy = {}
        
        cve_entry = inputs.get('cve_entry', {})
        prerequisites = inputs.get('prerequisites', {})
        feedback = inputs.get('feedback')
        critic_feedback = inputs.get('critic_feedback')
        
        # ========== 当 prerequisites 为空时，从 cve_knowledge 推断 ==========
        if not prerequisites or not prerequisites.get('overview'):
            print(f"[RepoBuilderAdapter] ⚠️ No prerequisites provided, inferring from cve_knowledge...")
            prerequisites = self._infer_prerequisites(cve_knowledge, deployment_strategy)
            print(f"[RepoBuilderAdapter] ✅ Inferred prerequisites: {prerequisites.get('overview', '')[:100]}...")
        
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
    
    def _infer_prerequisites(self, cve_knowledge: str, deployment_strategy: dict) -> dict:
        """从 CVE 知识中推断项目需求（当没有单独的 PreReqBuilder 步骤时）"""
        knowledge_lower = cve_knowledge.lower()
        
        # 尝试从 deployment_strategy 获取信息
        repo_url = deployment_strategy.get('repository_url', '')
        language = deployment_strategy.get('language', 'Unknown')
        build_tool = deployment_strategy.get('build_tool', 'Unknown')
        build_commands = deployment_strategy.get('build_commands', [])
        start_commands = deployment_strategy.get('start_commands', [])
        
        # 检测框架类型
        framework = "unknown"
        services = "Application server"
        output = "Service running on specified port"
        
        if 'symfony' in knowledge_lower:
            framework = "Symfony (PHP)"
            services = "PHP development server or Apache/Nginx"
            output = "Symfony application running"
        elif 'laravel' in knowledge_lower:
            framework = "Laravel (PHP)"
            services = "PHP artisan serve"
            output = "Laravel application running"
        elif 'django' in knowledge_lower:
            framework = "Django (Python)"
            services = "Django development server"
            output = "Django server running on port 8000"
        elif 'flask' in knowledge_lower:
            framework = "Flask (Python)"
            services = "Flask development server"
            output = "Flask server running on port 5000"
        elif 'express' in knowledge_lower or 'node' in knowledge_lower:
            framework = "Express/Node.js"
            services = "Node.js server"
            output = "Node.js server running"
        elif 'spring' in knowledge_lower:
            framework = "Spring (Java)"
            services = "Spring Boot application"
            output = "Spring application running"
        
        overview = f"""Project Analysis for CVE vulnerability.
Framework: {framework}
Repository: {repo_url if repo_url else 'Not specified - check CVE knowledge for details'}
Language: {language}
Build Tool: {build_tool}

This vulnerability requires setting up the vulnerable software version and exploiting it.
Follow the build/start commands from the CVE knowledge if available."""
        
        files = f"""Source code should be obtained from the repository.
Build commands: {'; '.join(build_commands) if build_commands else 'Check CVE knowledge'}
Start commands: {'; '.join(start_commands) if start_commands else 'Check CVE knowledge'}"""
        
        return {
            'overview': overview,
            'files': files,
            'services': services,
            'output': output
        }


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
    """ExploitCritic Agent 适配器
    
    增强功能：
    1. 读取 Docker 容器日志，提供给 Critic 更多上下文
    2. 分析 HTTP 响应和服务端错误
    """
    
    def __init__(self, result_bus: ResultBus, config: dict):
        self.result_bus = result_bus
        self.config = config
    
    def execute(self, inputs: Dict[str, Any]) -> Dict[str, Any]:
        cve_knowledge = inputs.get('cve_knowledge', '')
        exploit_result = inputs.get('exploit_result', {})
        build_result = inputs.get('build_result', {})
        
        # ========== P2: 获取 Docker 容器日志 ==========
        container_logs = self._get_container_logs(build_result)
        
        # 合并 exploit 结果和容器日志
        exploit_logs = self._format_exploit_logs(exploit_result, container_logs)
        
        agent = ExploitCritic(
            cve_knowledge=cve_knowledge,
            exploit=exploit_result,
            exploit_logs=exploit_logs
        )
        result = agent.invoke().value
        
        # 将容器日志信息附加到结果中
        if container_logs:
            result['container_logs_analyzed'] = True
            result['container_log_snippet'] = container_logs[:500] if len(container_logs) > 500 else container_logs
        
        return {'exploit_critic_feedback': result}
    
    def _get_container_logs(self, build_result: dict) -> str:
        """获取 Docker 容器的日志"""
        if not build_result:
            return ""
        
        # 获取容器名称
        container_name = (
            build_result.get('container_name') or
            build_result.get('deployment_info', {}).get('container_name') or
            build_result.get('deployment_info', {}).get('container_id')
        )
        
        if not container_name:
            # 尝试从部署方法推断
            method = build_result.get('method', '').lower()
            if 'docker' not in method and 'vulhub' not in method and 'prebuilt' not in method:
                return ""  # 非 Docker 部署
            
            # 尝试列出最近的容器
            try:
                import subprocess
                result = subprocess.run(
                    ["docker", "ps", "-q", "--latest"],
                    capture_output=True,
                    text=True,
                    timeout=10
                )
                if result.returncode == 0 and result.stdout.strip():
                    container_name = result.stdout.strip()
            except:
                return ""
        
        if not container_name:
            return ""
        
        # 获取容器日志
        try:
            import subprocess
            result = subprocess.run(
                ["docker", "logs", "--tail", "100", container_name],
                capture_output=True,
                text=True,
                timeout=15
            )
            
            logs = ""
            if result.stdout:
                logs += f"=== STDOUT ===\n{result.stdout}\n"
            if result.stderr:
                logs += f"=== STDERR ===\n{result.stderr}\n"
            
            print(f"[ExploitCritic] 📋 Retrieved {len(logs)} chars of container logs from {container_name}")
            return logs
            
        except subprocess.TimeoutExpired:
            print(f"[ExploitCritic] ⚠️ Timeout getting logs from {container_name}")
            return ""
        except Exception as e:
            print(f"[ExploitCritic] ⚠️ Failed to get container logs: {e}")
            return ""
    
    def _format_exploit_logs(self, exploit_result: dict, container_logs: str) -> str:
        """格式化 exploit 日志，供 Critic 分析"""
        import re
        logs_parts = []
        
        # 1. Exploit 执行结果
        if isinstance(exploit_result, dict):
            if exploit_result.get('exploit'):
                logs_parts.append(f"=== EXPLOIT CODE ===\n{exploit_result['exploit'][:2000]}")
            if exploit_result.get('poc'):
                logs_parts.append(f"=== POC ===\n{exploit_result['poc'][:1000]}")
            if exploit_result.get('output'):
                logs_parts.append(f"=== EXPLOIT OUTPUT ===\n{exploit_result['output'][:1500]}")
            if exploit_result.get('response'):
                logs_parts.append(f"=== HTTP RESPONSE ===\n{exploit_result['response'][:1500]}")
            if exploit_result.get('error'):
                logs_parts.append(f"=== ERROR ===\n{exploit_result['error']}")
        
        # 2. 容器日志（重点关注错误）
        if container_logs:
            # 提取关键错误信息
            error_patterns = [
                r'(?i)(error|exception|traceback|fatal|failed|denied|refused).*',
                r'(?i)(500|502|503|504)\s+.*',
                r'(?i)(sql.*error|mysql.*error|pg.*error).*',
                r'(?i)(permission.*denied|access.*denied).*',
                r'(?i)(null.*pointer|segfault|core.*dump).*',
            ]
            
            important_lines = []
            for line in container_logs.split('\n'):
                for pattern in error_patterns:
                    if re.search(pattern, line):
                        important_lines.append(line.strip())
                        break
            
            if important_lines:
                logs_parts.append(f"=== CONTAINER ERRORS (extracted) ===\n" + '\n'.join(important_lines[:30]))
            
            # 也包含最后几行日志
            recent_lines = container_logs.strip().split('\n')[-20:]
            logs_parts.append(f"=== CONTAINER LOGS (recent) ===\n" + '\n'.join(recent_lines))
        
        return '\n\n'.join(logs_parts)


class CTFVerifierAdapter(Capability):
    """CTFVerifier Agent 适配器
    
    增强功能：
    1. 调用 LLM 生成 verifier 脚本
    2. 使用 HardenedVerifier 进行客观验证（金丝雀检测）
    3. 两者结果必须一致才算真正成功
    """
    
    def __init__(self, result_bus: ResultBus, config: dict):
        self.result_bus = result_bus
        self.config = config
    
    def execute(self, inputs: Dict[str, Any]) -> Dict[str, Any]:
        cve_knowledge = inputs.get('cve_knowledge', '')
        exploit_result = inputs.get('exploit_result', {})
        build_result = inputs.get('build_result', {})
        
        # 1. 调用 LLM 生成 verifier 脚本
        agent = CTFVerifier(
            cve_knowledge=cve_knowledge,
            project_access=build_result.get('access', ''),
            exploit=exploit_result.get('exploit', ''),
            poc=exploit_result.get('poc', '')
        )
        llm_result = agent.invoke().value
        
        # 2. 尝试使用 HardenedVerifier 进行客观验证
        hardened_result = None
        if self.config.get('enable_hardened_verification', True):
            hardened_result = self._run_hardened_verification(
                cve_knowledge=cve_knowledge,
                exploit_result=exploit_result,
                build_result=build_result
            )
        
        # 3. 合并结果
        final_result = {
            'verifier': llm_result.get('verifier', '') if isinstance(llm_result, dict) else llm_result,
            'llm_verification': llm_result,
            'hardened_verification': hardened_result,
        }
        
        # 如果启用了强化验证，两者必须一致
        if hardened_result:
            final_result['hardened_passed'] = hardened_result.get('verified', False)
            if not hardened_result.get('verified', False):
                print(f"[CTFVerifier] ⚠️ 强化验证失败: {hardened_result.get('failure_reason', 'unknown')}")
                final_result['verification_warning'] = 'Hardened verification failed - LLM result may be unreliable'
        
        return {'verification_result': final_result}
    
    def _run_hardened_verification(
        self, 
        cve_knowledge: str, 
        exploit_result: dict, 
        build_result: dict
    ) -> dict:
        """使用 HardenedVerifier 进行客观验证"""
        try:
            from verification.hardened_verifier import HardenedVerifier, VulnType
            from core.failure_codes import FailureCode
            
            # 从 CVE knowledge 推断漏洞类型
            vuln_type = self._infer_vuln_type(cve_knowledge)
            if not vuln_type:
                return {
                    'verified': None,
                    'skipped': True,
                    'reason': 'Could not infer vulnerability type from CVE knowledge'
                }
            
            print(f"[CTFVerifier] 🔍 使用 HardenedVerifier 验证 {vuln_type.value} 漏洞...")
            
            # 获取目标 URL
            target_url = build_result.get('access') or build_result.get('target_url') or 'http://localhost:9600'
            
            # 创建验证器
            verifier = HardenedVerifier(
                target_url=target_url,
                vuln_type=vuln_type,
                timeout=30.0
            )
            
            # 获取金丝雀数据和 payload
            oracle, canary_data = verifier.create_oracle(vuln_type)
            
            # 从 exploit_result 获取 exploit payload
            exploit_payload = exploit_result.get('poc', '') or exploit_result.get('exploit', '')
            
            # 执行验证
            result = verifier.verify(
                exploit_payload=exploit_payload,
                response_text=exploit_result.get('response', ''),
                response_headers=exploit_result.get('headers', {}),
                check_callback=None  # 可选的回调检测
            )
            
            return {
                'verified': result.verified,
                'vuln_type': vuln_type.value,
                'confidence': result.confidence,
                'evidence': result.evidence,
                'failure_reason': result.failure_reason,
                'failure_code': result.failure_code.value if result.failure_code else None,
                'canary_data': canary_data
            }
            
        except ImportError as e:
            print(f"[CTFVerifier] ⚠️ HardenedVerifier 模块不可用: {e}")
            return {
                'verified': None,
                'skipped': True,
                'reason': f'HardenedVerifier module not available: {e}'
            }
        except Exception as e:
            print(f"[CTFVerifier] ⚠️ HardenedVerifier 执行失败: {e}")
            import traceback
            traceback.print_exc()
            return {
                'verified': None,
                'error': str(e),
                'reason': f'HardenedVerifier execution failed: {e}'
            }
    
    def _infer_vuln_type(self, cve_knowledge: str) -> 'VulnType':
        """从 CVE knowledge 推断漏洞类型"""
        try:
            from verification.hardened_verifier import VulnType
        except ImportError:
            return None
            
        knowledge_lower = cve_knowledge.lower()
        
        # 按优先级匹配
        patterns = [
            (VulnType.RCE, ['remote code execution', 'rce', 'command injection', 'code execution', 'os command']),
            (VulnType.SQLI, ['sql injection', 'sqli', 'blind sql', 'union select']),
            (VulnType.XSS, ['cross-site scripting', 'xss', 'script injection', 'reflected xss', 'stored xss']),
            (VulnType.SSRF, ['server-side request forgery', 'ssrf', 'url injection']),
            (VulnType.LFI, ['local file inclusion', 'lfi', 'file read', 'arbitrary file']),
            (VulnType.PATH_TRAVERSAL, ['path traversal', 'directory traversal', '../', '..\\', 'dot dot']),
            (VulnType.AUTH_BYPASS, ['authentication bypass', 'auth bypass', 'access control']),
            (VulnType.INFO_LEAK, ['information disclosure', 'info leak', 'sensitive data', 'data exposure']),
        ]
        
        for vuln_type, keywords in patterns:
            for keyword in keywords:
                if keyword in knowledge_lower:
                    return vuln_type
        
        return None


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
            cve_id = inputs.get('cve_id', 'UNKNOWN')
            
            # ========== 关键修复: 从 browser_config 获取 target_url ==========
            # browser_config 由 BrowserEnvironmentProvider 设置，包含实际部署的 URL
            browser_config = inputs.get('browser_config', {})
            if isinstance(browser_config, dict) and browser_config.get('target_url'):
                target_url = browser_config['target_url']
                print(f"[WebDriverAdapter] ✅ Using target_url from browser_config: {target_url}")
            else:
                target_url = self.config.get('target_url', 'http://localhost:9600')
                print(f"[WebDriverAdapter] ⚠️ No browser_config, using config/default: {target_url}")
            
            agent = WebDriverAgent(
                cve_knowledge=cve_knowledge,
                target_url=target_url
            )
            
            # 执行 Agent
            result = agent.invoke().value
            
            # ========== 集成 ExecutionReflector：失败后分析 ==========
            is_failure = False
            if isinstance(result, dict):
                is_failure = result.get('success') in ['no', False, 0, '0'] or not result.get('success')
            elif isinstance(result, str):
                is_failure = 'failed' in result.lower() or 'error' in result.lower()
            
            if is_failure and self.config.get('enable_reflection', True):
                print(f"\n[WebDriverAdapter] 🔍 检测到失败，调用 ExecutionReflector 分析...")
                
                try:
                    from agents.executionReflector import ExecutionReflector, AgentExecutionContext
                    
                    # 获取 Agent 的工具调用历史
                    tool_calls = []
                    if hasattr(agent, 'toolcall_metadata'):
                        # agentlib 的工具调用元数据
                        for tool_name, metadata in agent.toolcall_metadata.items():
                            tool_calls.append({
                                'tool': tool_name,
                                'args': {},  # 简化版本
                                'result': str(metadata)
                            })
                    
                    # 获取执行日志（如果可用）
                    execution_log = ""
                    log_path = f"/workspaces/submission/src/shared/{cve_id}/{cve_id}_webdriver_log.txt"
                    if os.path.exists(log_path):
                        with open(log_path, 'r', encoding='utf-8') as f:
                            execution_log = f.read()
                    else:
                        # 使用 result 作为日志
                        execution_log = str(result)
                    
                    # 创建执行上下文
                    context = AgentExecutionContext(
                        agent_name='WebDriverAgent',
                        cve_id=cve_id,
                        cve_knowledge=cve_knowledge,
                        execution_log=execution_log,
                        tool_calls=tool_calls,
                        final_status='failure',
                        iterations_used=getattr(agent, '__MAX_TOOL_ITERATIONS__', 20),
                        max_iterations=getattr(agent, '__MAX_TOOL_ITERATIONS__', 20)
                    )
                    
                    # 分析失败原因
                    reflector = ExecutionReflector(model='gpt-4o')
                    analysis = reflector.analyze(context)
                    
                    # 将分析结果附加到返回值
                    if isinstance(result, dict):
                        result['execution_analysis'] = {
                            'failure_type': analysis.failure_type,
                            'root_cause': analysis.root_cause,
                            'repeated_pattern': analysis.repeated_pattern,
                            'suggested_tool': analysis.suggested_tool,
                            'suggested_agent': analysis.suggested_agent,
                            'suggested_strategy': analysis.suggested_strategy,
                            'confidence': analysis.confidence,
                            'requires_web_search': analysis.requires_web_search
                        }
                    
                    # 如果建议切换 Agent，记录建议
                    if analysis.suggested_agent:
                        print(f"\n💡 [ExecutionReflector] 建议切换到 {analysis.suggested_agent}")
                        print(f"   原因: {analysis.root_cause}")
                        print(f"   策略: {analysis.suggested_strategy[:200]}...")
                        
                        # 保存分析结果到文件
                        analysis_path = f"/workspaces/submission/src/shared/{cve_id}/{cve_id}_execution_analysis.json"
                        os.makedirs(os.path.dirname(analysis_path), exist_ok=True)
                        import json
                        with open(analysis_path, 'w', encoding='utf-8') as f:
                            json.dump(result.get('execution_analysis', {}), f, indent=2, ensure_ascii=False)
                        print(f"   分析结果已保存: {analysis_path}")
                
                except Exception as e:
                    print(f"[WebDriverAdapter] ⚠️ ExecutionReflector 调用失败: {e}")
                    import traceback
                    traceback.print_exc()
            
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


# ============================================================
# 新的分拆 Agents: ProjectSetup, ServiceStart, HealthCheck
# ============================================================

class ProjectSetupAdapter(Capability):
    """ProjectSetupAgent 适配器 - 环境准备
    
    负责：
    1. 发现工作目录
    2. 检测框架类型
    3. 安装依赖
    """
    
    def __init__(self, result_bus: ResultBus, config: dict):
        self.result_bus = result_bus
        self.config = config
    
    def execute(self, inputs: Dict[str, Any]) -> Dict[str, Any]:
        from agents.projectSetup import ProjectSetupAgent
        
        cve_entry = inputs.get('cve_entry', {})
        cve_knowledge = inputs.get('cve_knowledge', '')
        cve_id = inputs.get('cve_id', '')
        
        sw_name = cve_entry.get('sw_version_wget', '').split('/')[-1] if cve_entry.get('sw_version_wget') else 'unknown'
        sw_version = cve_entry.get('sw_version', '')
        
        print(f"[ProjectSetup] Setting up: {sw_name} {sw_version}")
        
        agent = ProjectSetupAgent(
            cve_id=cve_id,
            sw_name=sw_name,
            sw_version=sw_version,
            cve_knowledge=cve_knowledge
        )
        result = agent.run()
        
        # 解析 JSON 结果
        import json
        try:
            setup_result = json.loads(result) if isinstance(result, str) else result
        except:
            setup_result = {'raw_output': result, 'success': False}
        
        print(f"[ProjectSetup] Result: {setup_result.get('success', False)}")
        return {'setup_result': setup_result}


class ServiceStartAdapter(Capability):
    """ServiceStartAgent 适配器 - 服务启动
    
    负责：
    1. 清理旧进程
    2. 启动服务
    """
    
    def __init__(self, result_bus: ResultBus, config: dict):
        self.result_bus = result_bus
        self.config = config
    
    def execute(self, inputs: Dict[str, Any]) -> Dict[str, Any]:
        from agents.serviceStart import ServiceStartAgent
        import json
        
        setup_result = inputs.get('setup_result', {})
        port = self.config.get('port', 9600)
        
        print(f"[ServiceStart] Starting service on port {port}")
        
        agent = ServiceStartAgent(
            setup_result=json.dumps(setup_result, indent=2) if isinstance(setup_result, dict) else str(setup_result),
            port=port
        )
        result = agent.run()
        
        # 解析 JSON 结果
        import json
        try:
            service_result = json.loads(result) if isinstance(result, str) else result
        except:
            service_result = {'raw_output': result, 'success': False}
        
        # 构建 build_result 以兼容后续步骤
        target_url = f"http://localhost:{port}"
        build_result = {
            'success': 'yes' if service_result.get('success') else 'no',
            'access': service_result.get('access_url', target_url),
            'method': 'venv',
            'notes': service_result.get('notes', '')
        }
        
        print(f"[ServiceStart] Result: {service_result.get('success', False)}")
        return {'service_result': service_result, 'build_result': build_result}


class HealthCheckAdapter(Capability):
    """HealthCheckAgent 适配器 - 增强的健康检查
    
    使用 EnhancedHealthCheck 进行多维度检查：
    1. 端口监听
    2. HTTP 可达性（带重试）
    3. 框架特定端点
    4. 响应内容检查
    5. 结构化失败原因码
    """
    
    
    def __init__(self, result_bus: ResultBus, config: dict):
        self.result_bus = result_bus
        self.config = config
    
    def execute(self, inputs: Dict[str, Any]) -> Dict[str, Any]:
        import json, re
        
        build_result = inputs.get('build_result')
        
        # 处理 build_result 为 None 的情况
        if build_result is None:
            print(f"[HealthCheck] ⚠️ No build_result available, using default port")
            build_result = {}
        
        # 从 build_result 提取端口 (优先使用 port 字段)
        port = build_result.get('port') if build_result else None
        
        # 如果没有 port 字段,尝试从 access/target_url 提取
        if not port and build_result:
            url = build_result.get('access') or build_result.get('target_url')
            if url:
                match = re.search(r':(\d+)', url)
                if match:
                    port = int(match.group(1))
        
        if not port:
            port = self.config.get('port', 9600)  # fallback
        
        # 根据部署方式决定使用哪个主机名
        deployment_method = build_result.get('method', '').lower()
        docker_based_methods = ['vulhub', 'vulfocus', 'docker-compose', 'docker', 'prebuilt']
        
        if any(m in deployment_method for m in docker_based_methods):
            target_host = "host.docker.internal"
        else:
            target_host = "localhost"
        
        # 检测框架类型
        framework = self._detect_framework(build_result, inputs.get('cve_knowledge', ''))
        
        print(f"[HealthCheck] Checking service on {target_host}:{port}")
        print(f"[HealthCheck] Deployment method: {deployment_method}, Framework: {framework}")
        
        # 构造访问URL
        check_url = f"http://{target_host}:{port}"
        
        # === 使用增强的健康检查 ===
        try:
            from verification.enhanced_healthcheck import EnhancedHealthCheck, check_service_health
            from core.failure_codes import FailureCode, FailureAnalyzer
            
            checker = EnhancedHealthCheck(
                target_url=check_url,
                framework=framework,
                timeout_seconds=15,
                retry_count=3,
                retry_delay=2.0
            )
            
            # 获取 Docker 容器名（如果有）
            docker_container = build_result.get('container_name') or build_result.get('deployment_info', {}).get('container_name')
            
            # 执行增强健康检查
            report = checker.check(docker_container=docker_container)
            
            print(f"[HealthCheck] {report.summary}")
            
            # 如果主检查失败，尝试 fallback 到 localhost
            if not report.healthy and target_host == "host.docker.internal":
                print(f"[HealthCheck] Trying fallback to localhost...")
                fallback_url = f"http://localhost:{port}"
                fallback_checker = EnhancedHealthCheck(
                    target_url=fallback_url,
                    framework=framework,
                    timeout_seconds=10,
                    retry_count=2,
                    retry_delay=1.0
                )
                fallback_report = fallback_checker.check()
                
                if fallback_report.healthy:
                    print(f"[HealthCheck] Fallback succeeded!")
                    report = fallback_report
                    check_url = fallback_url
            
            # 构建返回结果
            http_code = 0
            for check in report.checks:
                if check.name == 'http_reachable' and 'status_code' in check.details:
                    http_code = check.details['status_code']
                    break
            
            health_result = {
                'healthy': report.healthy,
                'http_code': http_code,
                'access_url': check_url,
                'diagnosis': report.summary,
                'failure_code': report.failure_code.value if report.failure_code else None,
                'checks': report.to_dict()['checks'],
                'total_duration_ms': report.total_duration_ms
            }
            
        except ImportError:
            # Fallback 到原有逻辑
            print(f"[HealthCheck] Using legacy health check (enhanced module not available)")
            health_result = self._legacy_health_check(check_url, target_host, port)
        except Exception as e:
            print(f"[HealthCheck] Enhanced check failed: {e}, using legacy")
            health_result = self._legacy_health_check(check_url, target_host, port)
        
        print(f"[HealthCheck] HTTP {health_result.get('http_code', 0)} -> Healthy: {health_result['healthy']}")
        return {'health_result': health_result}
    
    def _detect_framework(self, build_result: dict, cve_knowledge: str) -> str:
        """从构建结果和 CVE knowledge 中检测框架类型"""
        # 从 build_result 获取
        framework = build_result.get('framework', '')
        if framework:
            return framework.lower()
        
        # 从 CVE knowledge 推断
        knowledge_lower = cve_knowledge.lower()
        framework_keywords = {
            'django': 'django',
            'flask': 'flask',
            'fastapi': 'fastapi',
            'spring': 'spring',
            'express': 'express',
            'laravel': 'laravel',
            'symfony': 'symfony',
            'rails': 'rails',
            'nextjs': 'next.js',
        }
        
        for fw, keyword in framework_keywords.items():
            if keyword in knowledge_lower:
                return fw
        
        return 'generic'
    
    def _legacy_health_check(self, check_url: str, target_host: str, port: int) -> dict:
        """原有的健康检查逻辑（作为 fallback）"""
        import subprocess
        
        http_code = 0
        diagnosis = ""
        is_healthy = False
        
        try:
            subprocess.run(["sleep", "3"], capture_output=True)
            
            curl_result = subprocess.run(
                ["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}", check_url, "--max-time", "10"],
                capture_output=True,
                text=True,
                timeout=15
            )
            http_code = int(curl_result.stdout.strip()) if curl_result.stdout.strip().isdigit() else 0
            is_healthy = (200 <= http_code < 400) or http_code == 404
            
            if not is_healthy:
                diagnosis = f"Service returned HTTP {http_code}"
                if http_code == 0:
                    diagnosis = "Connection failed - service may not be running"
                    if target_host == "host.docker.internal":
                        fallback_url = f"http://localhost:{port}"
                        try:
                            fallback_result = subprocess.run(
                                ["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}", fallback_url, "--max-time", "5"],
                                capture_output=True,
                                text=True,
                                timeout=10
                            )
                            fallback_code = int(fallback_result.stdout.strip()) if fallback_result.stdout.strip().isdigit() else 0
                            if 200 <= fallback_code < 400:
                                http_code = fallback_code
                                is_healthy = True
                                check_url = fallback_url
                                diagnosis = "Accessible via localhost (fallback)"
                        except:
                            pass
        except subprocess.TimeoutExpired:
            diagnosis = "Connection timeout"
        except Exception as e:
            diagnosis = f"Health check failed: {str(e)}"
        
        return {
            'healthy': is_healthy,
            'http_code': http_code,
            'access_url': check_url,
            'diagnosis': diagnosis
        }


# ============================================================
# Freestyle Agent 适配器 - 自由探索模式
# ============================================================

class FreestyleAdapter(Capability):
    """FreestyleAgent 适配器 - 自由探索模式
    
    用于处理不适合固定流程的漏洞:
    - JavaScript/前端库漏洞
    - 配置类漏洞
    - 复杂的多步骤漏洞
    """
    
    def __init__(self, result_bus: ResultBus, config: dict):
        self.result_bus = result_bus
        self.config = config
    
    def _parse_structured_result(self, output: str) -> dict:
        """从 Agent 输出中解析结构化的 verification_result"""
        import json
        import re
        
        # 尝试提取 JSON 块
        json_patterns = [
            r'```json\s*(\{.*?"verification_result".*?\})\s*```',
            r'"verification_result"\s*:\s*(\{[^}]+\})',
            r'\{[^{]*"env_ready"[^}]*"poc_executed"[^}]*"passed"[^}]*\}',
        ]
        
        for pattern in json_patterns:
            matches = re.findall(pattern, output, re.DOTALL | re.IGNORECASE)
            for match in matches:
                try:
                    # 尝试解析匹配的 JSON
                    if '"verification_result"' in match:
                        data = json.loads(match)
                        return data.get('verification_result', {})
                    else:
                        return json.loads(match)
                except json.JSONDecodeError:
                    continue
        
        return {}
    
    def execute(self, inputs: Dict[str, Any]) -> Dict[str, Any]:
        from agents.freestyleAgent import FreestyleAgent
        from agents.brainAgent import BrainAgent, create_attack_plan, analyze_failure
        
        cve_entry = inputs.get('cve_entry', {})
        cve_knowledge = inputs.get('cve_knowledge', '')
        cve_id = inputs.get('cve_id', '')
        deployment_strategy = inputs.get('deployment_strategy', {})  # 新增：获取部署策略
        
        print(f"[FreestyleAgent] 🚀 Starting freestyle exploration for {cve_id}")
        print(f"[FreestyleAgent] Description: {cve_entry.get('description', '')[:200]}...")
        
        # 检查是否是硬件漏洞（提前退出）
        if deployment_strategy.get('is_hardware'):
            print(f"[FreestyleAgent] ⚠️ Hardware vulnerability detected - skipping reproduction")
            return {
                'freestyle_result': {
                    'success': False,
                    'output': 'Hardware vulnerability - cannot reproduce with software',
                },
                'verification_result': {
                    'passed': False,
                    'env_ready': False,
                    'poc_executed': False,
                    'error_message': deployment_strategy.get('deployment_notes', 'Hardware vulnerability'),
                }
            }
        
        # 显示部署策略信息
        if deployment_strategy.get('repository_url'):
            print(f"[FreestyleAgent] 📦 Deployment Strategy:")
            print(f"  - Repository: {deployment_strategy['repository_url']}")
            print(f"  - Language: {deployment_strategy.get('language', 'Unknown')}")
            print(f"  - Strategy: {deployment_strategy.get('strategy_type', 'Unknown')}")
        
        # ============================================================
        # 阶段 1: BrainAgent 分析和规划
        # ============================================================
        print(f"[BrainAgent] 🧠 Analyzing vulnerability and creating attack plan...")
        
        attack_plan = None
        attack_plan_text = None
        try:
            brain_agent = BrainAgent(
                cve_id=cve_id,
                cve_entry=cve_entry,
                cve_knowledge=cve_knowledge,
                mode="plan",
            )
            brain_result = brain_agent.invoke().value
            attack_plan = brain_agent.parse_plan_response(brain_result)
            attack_plan_text = attack_plan.to_prompt()
            
            print(f"[BrainAgent] ✅ Attack plan created:")
            print(f"  - Type: {attack_plan.vulnerability_type}")
            print(f"  - Prerequisites: {len(attack_plan.prerequisites)} steps")
            print(f"  - Exploitation: {len(attack_plan.exploitation_steps)} steps")
            print(f"  - Tools: {', '.join(attack_plan.recommended_tools[:3])}")
        except Exception as e:
            print(f"[BrainAgent] ⚠️ Failed to create attack plan: {e}")
            print(f"[BrainAgent] Proceeding without attack plan...")
        
        # ============================================================
        # 阶段 2.5: DeploymentAdvisor生成部署指南
        # ============================================================
        if deployment_strategy and deployment_strategy.get('repository_url'):
            try:
                from agents.deploymentAdvisor import DeploymentAdvisor
                advisor = DeploymentAdvisor(deployment_strategy)
                deployment_guide = advisor.generate_deployment_guide()
                
                # 将部署指南注入到cve_knowledge中，让LLM看到防错建议
                if deployment_guide:
                    cve_knowledge = cve_knowledge + "\n\n" + deployment_guide
                    print("[DeploymentAdvisor] ✅ Deployment guide injected into knowledge")
            except Exception as e:
                print(f"[DeploymentAdvisor] ⚠️ Failed to generate guide: {e}")
        
        # ============================================================
        # 阶段 3: FreestyleAgent 执行
        # ============================================================
        print(f"[FreestyleAgent] 🔧 Executing attack plan...")
        
        agent = FreestyleAgent(
            cve_id=cve_id,
            cve_entry=cve_entry,
            cve_knowledge=cve_knowledge,  # 包含部署指南
            attack_plan=attack_plan_text,  # 传递攻击计划
            deployment_strategy=deployment_strategy,  # 新增：传递部署策略
        )
        
        # 使用标准的 invoke() 调用方式
        try:
            result = agent.invoke().value
            output = result if isinstance(result, str) else str(result)
            
            # 检查是否实际调用了工具（防止幻觉回答）
            # 使用 agentlib 的 toolcall_metadata 属性获取工具调用统计
            tool_stats = getattr(agent, 'toolcall_metadata', None)
            if tool_stats is None:
                # 备用方案：尝试其他属性名
                tool_stats = getattr(agent, 'tool_stats', None)
                if tool_stats is None:
                    tool_stats = getattr(agent, '_tool_stats', {})
            if not tool_stats:
                # 从 agent 的 executor 中获取
                executor = getattr(agent, 'executor', None)
                if executor:
                    tool_stats = getattr(executor, 'toolcall_metadata', {})
                    if not tool_stats:
                        tool_stats = getattr(executor, 'tool_stats', {})
            
            # 调试：打印获取到的 tool_stats
            print(f"[DEBUG] Raw tool_stats: {tool_stats}")
            
            total_tool_calls = sum(
                stat.get('num_tool_calls', 0) 
                for stat in tool_stats.values()
                if isinstance(stat, dict)  # 过滤掉非字典值（如 __ended_due_to_... 等特殊键）
            ) if tool_stats else 0
            
            print(f"[DEBUG] Calculated total_tool_calls: {total_tool_calls}")
            
            # 如果还是 0，从输出内容判断是否有工具调用的痕迹
            if total_tool_calls == 0:
                # 检查输出中是否有工具调用的关键词
                tool_call_indicators = [
                    'Invoking:', 'SUCCESS:', 'ERROR:', 'TIMEOUT:',
                    '容器', 'docker', 'http://', 'localhost',
                    '服务已就绪', '服务已启动', 'Page Title:'
                ]
                for indicator in tool_call_indicators:
                    if indicator in output:
                        # 有工具调用痕迹，不是幻觉
                        total_tool_calls = 1  # 至少有 1 次
                        break
            
            # 1. 首先尝试解析结构化结果
            structured_result = self._parse_structured_result(output)
            
            if structured_result:
                # 使用结构化结果
                env_ready = structured_result.get('env_ready', True)
                poc_executed = structured_result.get('poc_executed', True)
                passed = structured_result.get('passed', False)
                evidence = structured_result.get('evidence', '')
                error_message = structured_result.get('error_message', '')
                
                print(f"[FreestyleAgent] 📊 Structured result: env_ready={env_ready}, poc_executed={poc_executed}, passed={passed}")
                
                if not env_ready:
                    print(f"[FreestyleAgent] ⚠️ Environment setup failed - this is NOT a vulnerability verification failure")
                    is_success = False
                    final_evidence = f"环境搭建失败: {error_message or evidence}"
                elif not poc_executed:
                    print(f"[FreestyleAgent] ⚠️ POC was not executed - cannot determine vulnerability status")
                    is_success = False
                    final_evidence = f"POC 未执行: {error_message or evidence}"
                else:
                    is_success = passed
                    final_evidence = evidence
                    
            elif total_tool_calls == 0:
                # 2. 没有调用任何工具 - 幻觉回答
                print(f"[FreestyleAgent] ⚠️ No tools were actually called - this is likely a hallucinated response")
                is_success = False
                final_evidence = "警告: Agent 未调用任何工具就声称完成，这是无效的响应"
                env_ready = False
                poc_executed = False
                
            else:
                # 3. 回退到关键词匹配（兼容旧格式）
                success_indicators = ['成功', 'success', 'verified', '触发', 'exploited', 'confirmed', 'vulnerable', 'vulnerability confirmed', 'VULNERABLE']
                failure_indicators = ['失败', 'failed', 'error', '无法', 'cannot', 'not vulnerable', 'unable', 'TIMEOUT', 'ERROR']
                env_failure_indicators = ['connection refused', '连接被拒绝', 'service not ready', '服务未就绪', 'docker', 'container']
                
                success_score = sum(1 for ind in success_indicators if ind.lower() in output.lower())
                failure_score = sum(1 for ind in failure_indicators if ind.lower() in output.lower())
                env_failure_score = sum(1 for ind in env_failure_indicators if ind.lower() in output.lower())
                
                # 判断是环境问题还是验证结果
                if env_failure_score > 2 and failure_score > success_score:
                    env_ready = False
                    poc_executed = False
                    is_success = False
                    print(f"[FreestyleAgent] ⚠️ Likely environment issue detected")
                else:
                    env_ready = True
                    poc_executed = True
                    is_success = success_score > failure_score
                    
                final_evidence = output[-1000:] if len(output) > 1000 else output
            
            print(f"[FreestyleAgent] Result: success={is_success}, tool_calls={total_tool_calls}")
            
            # ============================================================
            # 阶段 3: 如果失败，BrainAgent 分析原因（仅一次）
            # ============================================================
            failure_analysis = None
            if not is_success and attack_plan:
                print(f"[BrainAgent] 🔍 Analyzing failure reason...")
                try:
                    execution_result = {
                        'output': output[-2000:],  # 最后 2000 字符
                        'env_ready': env_ready if 'env_ready' in dir() else True,
                        'poc_executed': poc_executed if 'poc_executed' in dir() else True,
                        'passed': is_success,
                        'evidence': final_evidence if 'final_evidence' in dir() else '',
                        'tool_calls': total_tool_calls,
                    }
                    
                    failure_brain = BrainAgent(
                        cve_id=cve_id,
                        cve_entry=cve_entry,
                        cve_knowledge=cve_knowledge,
                        mode="analyze_failure",
                        execution_result=execution_result,
                    )
                    failure_result = failure_brain.invoke().value
                    failure_analysis = failure_brain.parse_failure_response(failure_result)
                    
                    print(f"[BrainAgent] 📋 Failure Analysis:")
                    print(f"  - Category: {failure_analysis.failure_category}")
                    print(f"  - Root Cause: {failure_analysis.root_cause[:100]}...")
                    print(f"  - Vulnerability Disproven: {failure_analysis.is_vulnerability_disproven}")
                    
                    # 将分析结果添加到证据中
                    final_evidence = f"{final_evidence}\n\n[BrainAgent 失败分析]\n类别: {failure_analysis.failure_category}\n原因: {failure_analysis.root_cause}\n建议: {failure_analysis.recommendation}"
                    
                except Exception as e:
                    print(f"[BrainAgent] ⚠️ Failure analysis failed: {e}")
            
            return {
                'freestyle_result': {
                    'output': output, 
                    'success': is_success, 
                    'tool_calls': total_tool_calls,
                    'env_ready': env_ready if 'env_ready' in dir() else True,
                    'poc_executed': poc_executed if 'poc_executed' in dir() else True,
                    'attack_plan': attack_plan.to_dict() if attack_plan else None,
                    'failure_analysis': failure_analysis.to_dict() if failure_analysis else None,
                },
                'verification_result': {
                    'passed': is_success,
                    'env_ready': env_ready if 'env_ready' in dir() else True,
                    'poc_executed': poc_executed if 'poc_executed' in dir() else True,
                    'evidence': final_evidence if 'final_evidence' in dir() else output[-1000:],
                    'mode': 'freestyle',
                    'tool_calls': total_tool_calls
                }
            }
        except Exception as e:
            print(f"[FreestyleAgent] ❌ Error: {e}")
            import traceback
            traceback.print_exc()
            return {
                'freestyle_result': {'output': str(e), 'success': False, 'env_ready': False, 'poc_executed': False},
                'verification_result': {
                    'passed': False,
                    'env_ready': False,
                    'poc_executed': False,
                    'evidence': str(e),
                    'mode': 'freestyle'
                }
            }
