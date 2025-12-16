"""
专业安全测试工具封装
用于 Exploiter Agent 调用 SQLMap、Commix、Nuclei、XSStrike 等工具
"""

import subprocess
import shutil
import os
from agentlib.lib import tools


# ============================================================
# 工具安装检查函数
# ============================================================

def _ensure_tool_installed(tool_name: str, install_commands: list) -> tuple:
    """通用工具安装检查"""
    if shutil.which(tool_name):
        return True, f"{tool_name} 已安装"
    
    for cmd in install_commands:
        try:
            result = subprocess.run(cmd, shell=True, capture_output=True, timeout=120)
            if result.returncode == 0 and shutil.which(tool_name):
                return True, f"{tool_name} 安装成功"
        except:
            continue
    
    return False, f"{tool_name} 安装失败"


def _install_sqlmap() -> tuple:
    """安装 SQLMap"""
    return _ensure_tool_installed("sqlmap", [
        "pip3 install sqlmap",
        "pip install sqlmap",
        "apt-get install -y sqlmap",
    ])


def _install_commix() -> tuple:
    """安装 Commix"""
    if shutil.which("commix") or shutil.which("commix.py") or os.path.exists("/opt/commix/commix.py"):
        return True, "commix 已安装"
    
    try:
        cmds = [
            "git clone --depth 1 https://github.com/commixproject/commix.git /opt/commix",
            "ln -sf /opt/commix/commix.py /usr/local/bin/commix",
            "chmod +x /opt/commix/commix.py",
        ]
        for cmd in cmds:
            subprocess.run(cmd, shell=True, capture_output=True, timeout=120)
        
        if os.path.exists("/opt/commix/commix.py"):
            return True, "commix 安装成功"
    except:
        pass
    
    return False, "commix 安装失败"


def _install_xsstrike() -> tuple:
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
    except:
        pass
    
    return False, "xsstrike 安装失败"


# ============================================================
# 专业安全工具
# ============================================================

@tools.tool
def run_sqlmap(
    target_url: str,
    method: str = "GET",
    data: str = None,
    parameter: str = None,
    level: int = 1,
    risk: int = 1,
    technique: str = None,
    dbms: str = None,
    dump: bool = False,
    batch: bool = True,
    timeout: int = 120,
) -> str:
    """
    运行 SQLMap 进行 SQL 注入自动化测试。
    
    SQLMap 是最强大的 SQL 注入自动化工具，支持多种数据库和注入技术。
    
    参数:
    - target_url: 目标URL (必须包含参数, 如 http://target.com/page?id=1)
    - method: HTTP方法 GET 或 POST
    - data: POST数据 (可选)
    - parameter: 指定测试的参数名 (可选)
    - level: 测试级别 1-5 (默认1)
    - risk: 风险级别 1-3 (默认1)
    - technique: 注入技术 B=布尔盲注, T=时间盲注, E=报错注入, U=联合查询
    - dbms: 指定数据库类型 mysql, postgresql, mssql, oracle, sqlite
    - dump: 是否导出数据
    - batch: 非交互模式
    - timeout: 超时秒数
    
    示例:
    - run_sqlmap(target_url="http://target.com/page?id=1")
    - run_sqlmap(target_url="http://target.com/login", method="POST", data="user=admin&pass=test")
    """
    try:
        installed, msg = _install_sqlmap()
        if not installed:
            return f"ERROR: {msg}. 请改用 execute_linux_command 手动执行或编写 Python 脚本。"
        
        cmd = ["sqlmap", "-u", target_url]
        
        if method.upper() == "POST" and data:
            cmd.extend(["--method", "POST", "--data", data])
        
        if parameter:
            cmd.extend(["-p", parameter])
        
        cmd.extend(["--level", str(level), "--risk", str(risk)])
        
        if technique:
            cmd.extend(["--technique", technique])
        
        if dbms:
            cmd.extend(["--dbms", dbms])
        
        if dump:
            cmd.append("--dump")
        
        if batch:
            cmd.append("--batch")
        
        cmd.extend(["--random-agent", "--threads", "4", "--output-dir", "/tmp/sqlmap_output"])
        
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        output = result.stdout + result.stderr
        
        if "is vulnerable" in output or "injectable" in output.lower():
            return f"VULNERABLE: SQLMap 发现 SQL 注入漏洞!\n\n{output[-3000:]}"
        elif "all tested parameters do not appear to be injectable" in output:
            return f"NOT_VULNERABLE: SQLMap 未发现 SQL 注入漏洞\n\n{output[-2000:]}"
        else:
            return f"RESULT:\n{output[-3000:]}"
            
    except subprocess.TimeoutExpired:
        return f"TIMEOUT: SQLMap 运行超时 ({timeout}秒). 请尝试编写自定义 Python 脚本。"
    except Exception as e:
        return f"ERROR: SQLMap 运行失败: {str(e)}. 请改用 execute_linux_command 或编写 Python 脚本。"


@tools.tool
def run_commix(
    target_url: str,
    data: str = None,
    cookie: str = None,
    parameter: str = None,
    technique: str = None,
    os_cmd: str = None,
    batch: bool = True,
    timeout: int = 120,
) -> str:
    """
    运行 Commix 进行命令注入自动化测试。
    
    参数:
    - target_url: 目标URL
    - data: POST数据 (可选)
    - cookie: Cookie 值 (可选)
    - parameter: 指定测试的参数名
    - technique: 注入技术 classic, eval-based, time-based, file-based
    - os_cmd: 成功注入后执行的OS命令 (可选)
    - batch: 非交互模式
    - timeout: 超时秒数
    
    示例:
    - run_commix(target_url="http://target.com/ping?ip=127.0.0.1")
    - run_commix(target_url="http://target.com/exec", data="cmd=ls")
    """
    try:
        installed, msg = _install_commix()
        if not installed:
            return f"ERROR: {msg}. 请改用 execute_linux_command 或编写 Python 脚本。"
        
        use_shell = False
        if shutil.which("commix"):
            commix_cmd = "commix"
        elif os.path.exists("/opt/commix/commix.py"):
            commix_cmd = "python3 /opt/commix/commix.py"
            use_shell = True
        else:
            return "ERROR: Commix 未找到. 请改用 execute_linux_command 或编写 Python 脚本。"
        
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
        
        cmd = " ".join(cmd_parts) if use_shell else cmd_parts
        
        result = subprocess.run(cmd, shell=use_shell, capture_output=True, text=True, timeout=timeout)
        output = result.stdout + result.stderr
        
        if "is vulnerable" in output.lower() or "command injection" in output.lower():
            return f"VULNERABLE: Commix 发现命令注入漏洞!\n\n{output[-3000:]}"
        elif "not appear to be injectable" in output:
            return f"NOT_VULNERABLE: Commix 未发现命令注入漏洞\n\n{output[-2000:]}"
        else:
            return f"RESULT:\n{output[-3000:]}"
            
    except subprocess.TimeoutExpired:
        return f"TIMEOUT: Commix 运行超时 ({timeout}秒). 请尝试编写自定义 Python 脚本。"
    except Exception as e:
        return f"ERROR: Commix 运行失败: {str(e)}. 请改用 execute_linux_command 或编写 Python 脚本。"


@tools.tool
def run_nuclei(
    target_url: str,
    template_content: str = None,
    template_file: str = None,
    tags: str = None,
    severity: str = None,
    timeout: int = 120,
) -> str:
    """
    运行 Nuclei 进行基于模板的漏洞扫描。
    
    Nuclei 使用 YAML 模板定义漏洞检测规则，比编写 Python 脚本更可靠。
    
    参数:
    - target_url: 目标URL
    - template_content: YAML 模板内容 (直接传入模板字符串)
    - template_file: 模板文件路径 (已存在的模板)
    - tags: 模板标签过滤 (如 "cve,rce")
    - severity: 严重程度过滤 (如 "critical,high")
    - timeout: 超时秒数
    
    YAML 模板示例:
    ```yaml
    id: cve-xxxx-xxxx
    info:
      name: CVE-XXXX Description
      severity: high
    http:
      - method: GET
        path:
          - "{{BaseURL}}/vulnerable/path"
        matchers:
          - type: word
            words:
              - "success indicator"
    ```
    
    示例:
    - run_nuclei(target_url="http://target.com", template_file="/tmp/cve.yaml")
    - run_nuclei(target_url="http://target.com", template_content="id: test\\n...")
    """
    try:
        # 检查 nuclei 是否安装
        if not shutil.which("nuclei"):
            return "ERROR: Nuclei 未安装. 请改用 execute_linux_command 或编写 Python 脚本。"
        
        # 如果提供了模板内容，先保存到临时文件
        temp_template = None
        if template_content:
            temp_template = "/tmp/nuclei_custom_template.yaml"
            with open(temp_template, 'w') as f:
                f.write(template_content)
            template_file = temp_template
        
        if not template_file:
            return "ERROR: 必须提供 template_content 或 template_file 参数"
        
        cmd = ["nuclei", "-u", target_url, "-t", template_file, "-no-update-templates"]
        
        if tags:
            cmd.extend(["-tags", tags])
        
        if severity:
            cmd.extend(["-severity", severity])
        
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        output = result.stdout + result.stderr
        
        # 清理临时文件
        if temp_template and os.path.exists(temp_template):
            os.remove(temp_template)
        
        if "[" in output and "]" in output:  # Nuclei 发现匹配
            return f"VULNERABLE: Nuclei 发现漏洞匹配!\n\n{output}"
        elif "no results" in output.lower() or not output.strip():
            return f"NOT_VULNERABLE: Nuclei 未发现漏洞\n\nTemplate: {template_file}"
        else:
            return f"RESULT:\n{output[-3000:]}"
            
    except subprocess.TimeoutExpired:
        return f"TIMEOUT: Nuclei 运行超时 ({timeout}秒). 请尝试编写自定义 Python 脚本。"
    except Exception as e:
        return f"ERROR: Nuclei 运行失败: {str(e)}. 请改用 execute_linux_command 或编写 Python 脚本。"


@tools.tool
def run_xss_scanner(
    target_url: str,
    crawl: bool = False,
    blind: bool = False,
    timeout: int = 120,
) -> str:
    """
    运行 XSS 漏洞扫描器 (XSStrike)。
    
    XSStrike 是最强大的开源 XSS 扫描器，支持智能 payload 生成和 WAF 绕过。
    
    参数:
    - target_url: 目标URL (应包含参数, 如 http://target.com/search?q=test)
    - crawl: 是否爬取页面发现更多注入点
    - blind: 是否使用盲 XSS 检测
    - timeout: 超时秒数
    
    示例:
    - run_xss_scanner(target_url="http://target.com/search?q=test")
    - run_xss_scanner(target_url="http://target.com/", crawl=True)
    """
    try:
        installed, msg = _install_xsstrike()
        if not installed:
            return f"ERROR: {msg}. 请改用 execute_linux_command 或编写 Python 脚本。"
        
        use_shell = False
        if shutil.which("xsstrike"):
            xss_cmd = "xsstrike"
        elif os.path.exists("/opt/xsstrike/xsstrike.py"):
            xss_cmd = "python3 /opt/xsstrike/xsstrike.py"
            use_shell = True
        else:
            # 回退到简单的 XSS 测试
            return _fallback_xss_scan(target_url)
        
        cmd_parts = [xss_cmd, "-u", target_url, "--skip"]
        
        if crawl:
            cmd_parts.append("--crawl")
        if blind:
            cmd_parts.append("--blind")
        
        cmd = " ".join(cmd_parts) if use_shell else cmd_parts
        
        result = subprocess.run(cmd, shell=use_shell, capture_output=True, text=True, timeout=timeout)
        output = result.stdout + result.stderr
        
        if "Vulnerable" in output or "payload" in output.lower():
            return f"VULNERABLE: XSStrike 发现 XSS 漏洞!\n\n{output[-3000:]}"
        elif "No parameter" in output:
            return f"NO_PARAMS: 未找到可测试的参数\n\n{output[-2000:]}"
        else:
            return f"RESULT:\n{output[-3000:]}"
            
    except subprocess.TimeoutExpired:
        return f"TIMEOUT: XSStrike 扫描超时 ({timeout}秒). 请尝试编写自定义 Python 脚本。"
    except Exception as e:
        # 回退到简单测试
        return _fallback_xss_scan(target_url)


def _fallback_xss_scan(target_url: str) -> str:
    """简单的 XSS 测试回退方案"""
    try:
        import requests
        
        payloads = [
            '<script>alert("XSS")</script>',
            '<img src=x onerror=alert("XSS")>',
            '"><script>alert("XSS")</script>',
        ]
        
        results = []
        for payload in payloads:
            try:
                if "?" in target_url:
                    test_url = target_url + payload
                else:
                    test_url = target_url + "?test=" + payload
                
                resp = requests.get(test_url, timeout=10, verify=False)
                if payload in resp.text:
                    results.append(f"可能存在 XSS: payload 被反射回响应中\nPayload: {payload}")
            except:
                continue
        
        if results:
            return f"POSSIBLE_XSS: 发现可能的 XSS 漏洞\n\n" + "\n".join(results)
        else:
            return "NOT_VULNERABLE: 简单 XSS 测试未发现漏洞. 建议编写更复杂的测试脚本。"
    except Exception as e:
        return f"ERROR: XSS 扫描失败: {str(e)}. 请编写自定义 Python 脚本进行测试。"


# ============================================================
# 导出所有工具
# ============================================================

SECURITY_TOOLS = {
    'run_sqlmap': run_sqlmap,
    'run_commix': run_commix,
    'run_nuclei': run_nuclei,
    'run_xss_scanner': run_xss_scanner,
}
