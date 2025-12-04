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
from typing import Optional, Dict, Any

from agentlib import AgentWithHistory
from agentlib.lib import tools

# 导入已有的工具
from toolbox.tools import TOOLS


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
def run_browser_test(url: str, javascript_code: str = "") -> str:
    """
    使用 Selenium 运行浏览器测试，验证漏洞
    
    :param url: 要访问的 URL
    :param javascript_code: 要执行的 JavaScript 代码（可选）
    :return: 测试结果
    """
    try:
        from selenium import webdriver
        from selenium.webdriver.chrome.options import Options
        
        options = Options()
        options.add_argument('--headless')
        options.add_argument('--no-sandbox')
        options.add_argument('--disable-dev-shm-usage')
        options.add_argument('--disable-web-security')
        
        driver = webdriver.Chrome(options=options)
        driver.set_page_load_timeout(30)
        
        driver.get(url)
        time.sleep(2)
        
        result_parts = [
            f"Page Title: {driver.title}",
            f"Current URL: {driver.current_url}",
            f"Page Source Preview: {driver.page_source[:1500] if driver.page_source else 'N/A'}",
        ]
        
        # 如果有自定义 JavaScript
        if javascript_code:
            try:
                js_result = driver.execute_script(javascript_code)
                result_parts.append(f"JS Result: {str(js_result) if js_result is not None else 'null'}")
            except Exception as js_err:
                result_parts.append(f"JS Error: {str(js_err)}")
        
        # 获取控制台日志
        try:
            logs = driver.get_log('browser')
            if logs:
                result_parts.append(f"Console Logs: {[log['message'] for log in logs[:5]]}")
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


# 将自定义工具添加到 FREESTYLE_TOOLS
FREESTYLE_TOOLS = {
    **TOOLS,  # 继承所有基础工具
    'create_html_test_page': create_html_test_page,
    'start_http_server': start_http_server,
    'run_browser_test': run_browser_test,
    'verify_window_opener_vulnerability': verify_window_opener_vulnerability,
    'install_npm_package': install_npm_package,
    'get_docker_container_ip': get_docker_container_ip,
    'run_docker_container': run_docker_container,
    'wait_for_service': wait_for_service,
    'diagnose_docker_network': diagnose_docker_network,
    'stop_docker_container': stop_docker_container,
}


# ============================================================
# FreestyleAgent 类
# ============================================================

class FreestyleAgent(AgentWithHistory[dict, str]):
    """
    自由探索 Agent - 自主决定如何复现漏洞
    
    特点:
    1. 拥有完整的工具集 - 命令执行、文件操作、浏览器测试等
    2. 自主规划 - 根据漏洞类型决定复现步骤
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
    WORK_DIR: str = "/workspaces/submission/src/simulation_environments"
    
    def __init__(
        self, 
        cve_id: str = None,
        cve_entry: dict = None,
        cve_knowledge: str = None,
        work_dir: str = None,
        **kwargs
    ):
        super().__init__(**kwargs)
        
        self.CVE_ID = cve_id
        self.CVE_ENTRY = cve_entry or {}
        self.CVE_KNOWLEDGE = cve_knowledge or ""
        if work_dir:
            self.WORK_DIR = work_dir
    
    def get_input_vars(self, *args, **kwargs) -> dict:
        """提供模板变量"""
        vars = super().get_input_vars(*args, **kwargs)
        vars.update(
            CVE_ID=self.CVE_ID,
            CVE_ENTRY=self.CVE_ENTRY,
            CVE_KNOWLEDGE=self.CVE_KNOWLEDGE,
            WORK_DIR=self.WORK_DIR,
            CVE_ENTRY_JSON=json.dumps(self.CVE_ENTRY, indent=2, ensure_ascii=False)[:3000] if self.CVE_ENTRY else '{}',
        )
        return vars
    
    def get_available_tools(self):
        """返回可用工具集 - 使用 FREESTYLE_TOOLS.values()"""
        return FREESTYLE_TOOLS.values()
