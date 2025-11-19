import os
from agentlib import AgentWithHistory
from agentlib.lib.common.parsers import BaseParser
from agentlib.lib.tools import tool
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
    
    def parse(self, text: str, **kwargs) -> dict:
        """Parse XML report format from WebDriverAgent"""
        try_itr = 0
        while try_itr < 3:
            try:
                # Extract XML tags
                success_match = re.search(r'<success>(.*?)</success>', text, re.DOTALL)
                steps_match = re.search(r'<steps>(.*?)</steps>', text, re.DOTALL)
                evidence_match = re.search(r'<evidence>(.*?)</evidence>', text, re.DOTALL)
                poc_match = re.search(r'<poc>(.*?)</poc>', text, re.DOTALL)
                
                if not success_match:
                    raise ValueError("Missing <success> tag")
                
                success = success_match.group(1).strip()
                steps = steps_match.group(1).strip() if steps_match else "No steps provided"
                evidence = evidence_match.group(1).strip() if evidence_match else "No evidence"
                poc = poc_match.group(1).strip() if poc_match else "No PoC"
                
                print(f'✅ Successfully parsed WebDriver output!')
                return dict(
                    success=success,
                    exploit=steps,
                    poc=poc,
                    evidence=evidence
                )
            except Exception as e:
                print(f'🤡 Parse Error: {e}')
                print(f'🤡 Attempt {try_itr + 1}/3 to fix format...')
                try_itr += 1
                
                # 如果解析失败,返回默认结构
                if try_itr >= 3:
                    return dict(
                        success="no",
                        exploit="Failed to parse agent output",
                        poc=text[:500],  # 返回前500字符作为原始输出
                        evidence="Parse error"
                    )

class WebDriverAgent(AgentWithHistory[dict, str]):
    """
    Agent for performing browser-based vulnerability exploitation
    Handles CSRF, XSS, and other web-based attacks that require browser interaction
    """
    __LLM_MODEL__ = 'gpt-4o'
    __SYSTEM_PROMPT_TEMPLATE__ = 'webDriverAgent/webDriverAgent.system.j2'
    __USER_PROMPT_TEMPLATE__ = 'webDriverAgent/webDriverAgent.user.j2'
    __OUTPUT_PARSER__ = WebDriverOutputParser
    __MAX_TOOL_ITERATIONS__ = 40
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
        chrome_options = Options()
        if headless:
            chrome_options.add_argument('--headless')
        chrome_options.add_argument('--no-sandbox')
        chrome_options.add_argument('--disable-dev-shm-usage')
        chrome_options.add_argument('--disable-gpu')
        chrome_options.add_argument('--window-size=1920,1080')
        
        self.driver = webdriver.Chrome(options=chrome_options)
        return "WebDriver initialized successfully"
    
    def cleanup_driver(self):
        """Close and cleanup WebDriver"""
        if self.driver:
            self.driver.quit()
            self.driver = None
        return "WebDriver cleaned up"
    
    @tool
    def navigate_to_url(self, url: str) -> str:
        """
        Navigate to a specific URL
        
        Args:
            url: The target URL to visit
            
        Returns:
            Success message with current URL
        """
        if not self.driver:
            self.setup_driver()
        
        self.driver.get(url)
        time.sleep(2)  # Wait for page load
        return f"Navigated to {self.driver.current_url}, Page title: {self.driver.title}"
    
    @tool
    def find_element(self, selector: str, by: str = "css") -> str:
        """
        Find an element on the page
        
        Args:
            selector: CSS selector or XPath
            by: 'css' or 'xpath'
            
        Returns:
            Element information or error message
        """
        if not self.driver:
            return "Error: WebDriver not initialized"
        
        try:
            by_type = By.CSS_SELECTOR if by == "css" else By.XPATH
            element = WebDriverWait(self.driver, 10).until(
                EC.presence_of_element_located((by_type, selector))
            )
            return f"Found element: {element.tag_name}, text: {element.text[:100]}"
        except TimeoutException:
            return f"Element not found: {selector}"
        except Exception as e:
            return f"Error finding element: {str(e)}"
    
    @tool
    def click_element(self, selector: str, by: str = "css") -> str:
        """
        Click an element on the page
        
        Args:
            selector: CSS selector or XPath
            by: 'css' or 'xpath'
            
        Returns:
            Success or error message
        """
        if not self.driver:
            return "Error: WebDriver not initialized"
        
        try:
            by_type = By.CSS_SELECTOR if by == "css" else By.XPATH
            element = WebDriverWait(self.driver, 10).until(
                EC.element_to_be_clickable((by_type, selector))
            )
            element.click()
            time.sleep(1)
            return f"Clicked element: {selector}"
        except Exception as e:
            return f"Error clicking element: {str(e)}"
    
    @tool
    def input_text(self, selector: str, text: str, by: str = "css") -> str:
        """
        Input text into a form field
        
        Args:
            selector: CSS selector or XPath
            text: Text to input
            by: 'css' or 'xpath'
            
        Returns:
            Success or error message
        """
        if not self.driver:
            return "Error: WebDriver not initialized"
        
        try:
            by_type = By.CSS_SELECTOR if by == "css" else By.XPATH
            element = WebDriverWait(self.driver, 10).until(
                EC.presence_of_element_located((by_type, selector))
            )
            element.clear()
            element.send_keys(text)
            return f"Input text into {selector}"
        except Exception as e:
            return f"Error inputting text: {str(e)}"
    
    @tool
    def execute_javascript(self, script: str) -> str:
        """
        Execute JavaScript in the browser context
        
        Args:
            script: JavaScript code to execute
            
        Returns:
            Script result or error message
        """
        if not self.driver:
            return "Error: WebDriver not initialized"
        
        try:
            result = self.driver.execute_script(script)
            return f"JavaScript executed. Result: {str(result)[:200]}"
        except Exception as e:
            return f"Error executing JavaScript: {str(e)}"
    
    @tool
    def get_page_source(self) -> str:
        """
        Get the current page HTML source
        
        Returns:
            Page source (truncated)
        """
        if not self.driver:
            return "Error: WebDriver not initialized"
        
        source = self.driver.page_source
        return f"Page source (first 500 chars):\n{source[:500]}"
    
    @tool
    def check_alert(self) -> str:
        """
        Check if an alert dialog is present (useful for XSS detection)
        
        Returns:
            Alert text or "No alert present"
        """
        if not self.driver:
            return "Error: WebDriver not initialized"
        
        try:
            alert = self.driver.switch_to.alert
            alert_text = alert.text
            alert.accept()
            return f"Alert detected! Text: {alert_text}"
        except:
            return "No alert present"
    
    @tool
    def take_screenshot(self, filename: str) -> str:
        """
        Take a screenshot of the current page
        
        Args:
            filename: Screenshot filename (will be saved in /shared/{cve_id}/)
            
        Returns:
            Screenshot file path
        """
        if not self.driver:
            return "Error: WebDriver not initialized"
        
        try:
            filepath = f"/shared/{filename}"
            self.driver.save_screenshot(filepath)
            return f"Screenshot saved to {filepath}"
        except Exception as e:
            return f"Error taking screenshot: {str(e)}"
    
    @tool
    def create_csrf_page(self, html_content: str, filename: str = "csrf_exploit.html") -> str:
        """
        Create a malicious HTML page for CSRF attack
        
        Args:
            html_content: HTML content for the attack page
            filename: Output filename
            
        Returns:
            File path of created page
        """
        try:
            filepath = f"/shared/{filename}"
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(html_content)
            return f"CSRF page created at {filepath}"
        except Exception as e:
            return f"Error creating CSRF page: {str(e)}"
    
    def get_cost(self, *args, **kw) -> float:
        total_cost = 0
        for model_name, token_usage in self.token_usage.items():
            total_cost += token_usage.get_costs(model_name)['total_cost']
        return total_cost
    
    def __del__(self):
        """Cleanup on deletion"""
        self.cleanup_driver()
