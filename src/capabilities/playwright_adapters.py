"""Playwright 特定的能力适配器（支持高级 Web 交互）。"""
from typing import Any, Dict


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
