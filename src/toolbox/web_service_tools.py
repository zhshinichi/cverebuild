"""
Web Service 智能工具模块

这个模块提供了一组智能工具，让 Agent 在运行时动态获取所需知识，
而不是通过冗长的 prompt 来传递所有可能的信息。

核心理念：
- 工具比 Prompt 更可靠：工具返回的是确定性结果
- 按需获取：只有在需要时才获取信息
- 封装复杂逻辑：把端口清理、健康检查等逻辑封装起来
"""

import os
import re
import subprocess
import time
from typing import Dict, Optional, Tuple, List
from dataclasses import dataclass
from agentlib.lib import tools

# ==================== 路径处理 ====================
SIMULATION_ENV_DIR = "/workspaces/submission/src/simulation_environments"


def resolve_project_path(project_path: str) -> str:
    """
    智能解析项目路径，处理相对路径。
    
    Agent 通常传入相对路径如 'open-webui-0.6.5'，需要转换为
    simulation_environments 下的绝对路径。
    
    :param project_path: 可能是相对路径或绝对路径
    :return: 绝对路径
    """
    if not project_path:
        return SIMULATION_ENV_DIR
    
    # 如果已经是绝对路径且存在，直接返回
    if os.path.isabs(project_path) and os.path.exists(project_path):
        return project_path
    
    # 尝试在 simulation_environments 下找
    candidate = os.path.join(SIMULATION_ENV_DIR, project_path)
    if os.path.exists(candidate):
        return candidate
    
    # 如果是绝对路径但不存在，检查是否可能在 sim env 下
    if os.path.isabs(project_path):
        basename = os.path.basename(project_path)
        candidate = os.path.join(SIMULATION_ENV_DIR, basename)
        if os.path.exists(candidate):
            return candidate
    
    # 返回 sim env 下的路径（即使不存在，让调用者处理错误）
    return candidate

# ==================== 数据结构 ====================

@dataclass
class FrameworkInfo:
    """Web 框架信息"""
    framework: str           # 框架名称: mlflow, django, flask, fastapi, etc.
    version: str            # 版本号
    install_method: str     # 安装方式: pypi, source, requirements
    install_cmd: str        # 具体安装命令
    start_cmd: str          # 启动命令
    confidence: float       # 置信度 0-1
    notes: List[str]        # 额外注意事项


@dataclass
class ServiceStatus:
    """服务状态信息"""
    running: bool           # 是否运行中
    healthy: bool           # 是否健康
    pid: Optional[int]      # 进程 ID
    port: int               # 监听端口
    http_code: Optional[int]  # HTTP 响应码
    error_message: str      # 错误信息
    suggested_fix: str      # 建议的修复方法


# ==================== 框架检测知识库 ====================

FRAMEWORK_PATTERNS = {
    'mlflow': {
        'indicators': [
            ('pyproject.toml', r'name\s*=\s*["\']mlflow'),
            ('setup.py', r'mlflow'),
            ('*.py', r'from\s+mlflow|import\s+mlflow'),
        ],
        'start_cmd': 'mlflow server --host 0.0.0.0 --port {port}',
        'install_cmd': 'pip install mlflow=={version}',  # 优先 PyPI
        'pypi_name': 'mlflow',
        'notes': ['MLflow 必须用 `mlflow server` 启动，不能用 gunicorn'],
    },
    'django': {
        'indicators': [
            ('manage.py', r'django'),
            ('settings.py', r'DJANGO_SETTINGS_MODULE'),
            ('*.py', r'from\s+django|import\s+django'),
        ],
        'start_cmd': 'python manage.py runserver 0.0.0.0:{port}',
        'install_cmd': 'pip install -r requirements.txt',
        'pypi_name': 'django',
        'notes': ['使用 manage.py runserver，生产环境可用 gunicorn'],
    },
    'flask': {
        'indicators': [
            ('*.py', r'from\s+flask\s+import\s+Flask'),
            ('*.py', r'Flask\s*\('),
            ('app.py', r'flask'),
        ],
        'start_cmd': 'flask run --host 0.0.0.0 --port {port}',
        'alt_start_cmd': 'python app.py',
        'install_cmd': 'pip install -r requirements.txt',
        'pypi_name': 'flask',
        'notes': ['设置 FLASK_APP 环境变量，或直接 python app.py'],
    },
    'fastapi': {
        'indicators': [
            ('*.py', r'from\s+fastapi\s+import\s+FastAPI'),
            ('*.py', r'FastAPI\s*\('),
            ('main.py', r'fastapi'),
        ],
        'start_cmd': 'uvicorn main:app --host 0.0.0.0 --port {port}',
        'install_cmd': 'pip install -r requirements.txt',
        'pypi_name': 'fastapi',
        'notes': ['FastAPI 需要 uvicorn 或 hypercorn 作为 ASGI 服务器'],
    },
    'streamlit': {
        'indicators': [
            ('*.py', r'import\s+streamlit'),
            ('*.py', r'st\.'),
        ],
        'start_cmd': 'streamlit run app.py --server.port {port} --server.address 0.0.0.0',
        'install_cmd': 'pip install streamlit',
        'pypi_name': 'streamlit',
        'notes': ['Streamlit 有自己的服务器'],
    },
    'gradio': {
        'indicators': [
            ('*.py', r'import\s+gradio'),
            ('*.py', r'gr\.'),
        ],
        'start_cmd': 'python app.py',  # Gradio 内置服务器
        'install_cmd': 'pip install gradio',
        'pypi_name': 'gradio',
        'notes': ['Gradio 应用通过 launch() 启动'],
    },
    'lollms': {
        'indicators': [
            ('*.py', r'lollms'),
            ('pyproject.toml', r'lollms'),
        ],
        'start_cmd': 'python app.py --host 0.0.0.0 --port {port}',
        'install_cmd': 'pip install -e .',
        'pypi_name': 'lollms',
        'notes': ['lollms 通常需要从源码安装'],
    },
    'open-webui': {
        'indicators': [
            ('pyproject.toml', r'name\s*=\s*["\']open-webui'),
            ('backend/start.sh', r'uvicorn'),
            ('backend/open_webui', r''),  # 目录存在即可
        ],
        'start_cmd': 'cd backend && bash start.sh',
        'install_cmd': 'cd backend && pip install -r requirements.txt',
        'pypi_name': None,  # 不是 PyPI 包，必须从源码安装
        'project_subdir': 'backend',  # 启动时需要进入的子目录
        'notes': [
            'Open-WebUI 使用 uvicorn 启动',
            '必须在 backend/ 目录下运行 start.sh',
            '默认端口是 8080，不是 9600',
            '需要设置 WEBUI_SECRET_KEY 环境变量'
        ],
    },
}

# 启动失败错误诊断知识库
ERROR_DIAGNOSIS = {
    r'Worker failed to boot': {
        'cause': 'Gunicorn Worker 无法启动，通常是 WSGI 入口点错误',
        'fix': '不要用 gunicorn，使用框架自带的启动命令',
    },
    r'Address already in use': {
        'cause': '端口被占用',
        'fix': '运行 `fuser -k {port}/tcp` 或 `kill $(lsof -t -i:{port})`',
    },
    r"cannot import name.*from partially initialized module": {
        'cause': '循环导入错误，通常是 pip install -e . 导致',
        'fix': '使用 `pip install <package>==<version>` 从 PyPI 安装，而不是 -e .',
    },
    r'ImportError.*No module named': {
        'cause': '缺少依赖',
        'fix': '运行 `pip install -r requirements.txt` 或 `pip install -e .`',
    },
    r'ModuleNotFoundError': {
        'cause': '模块未安装',
        'fix': '检查依赖是否安装完整',
    },
    r'Connection refused': {
        'cause': '服务未运行或未监听该端口',
        'fix': '检查服务是否启动成功，查看日志',
    },
}


# ==================== 智能工具实现 ====================

@tools.tool
def detect_web_framework(project_path: str, sw_version: str = "") -> str:
    """
    智能检测 Web 项目的框架类型，并返回正确的安装和启动方法。
    
    这个工具会分析项目结构，自动识别：
    - 框架类型 (MLflow, Django, Flask, FastAPI, etc.)
    - 推荐的安装方式 (PyPI 优先于源码)
    - 正确的启动命令
    
    :param project_path: 项目根目录路径（可以是相对路径，会自动解析到 simulation_environments）
    :param sw_version: 软件版本号，如 "v2.20.1" 或 "2.20.1"
    :return: 框架信息的 JSON 字符串
    """
    import json
    
    # 智能解析路径（处理相对路径）
    resolved_path = resolve_project_path(project_path)
    
    # 解析版本号
    version = re.sub(r'^v', '', sw_version) if sw_version else ""
    
    result = {
        'framework': 'unknown',
        'install_method': 'source',
        'install_cmd': 'pip install -e .',
        'start_cmd': 'python app.py',
        'notes': [],
        'confidence': 0.0,
        'resolved_path': resolved_path,  # 告诉 Agent 实际路径
    }
    
    if not os.path.isdir(resolved_path):
        result['notes'].append(f"Warning: {resolved_path} is not a directory (original: {project_path})")
        return json.dumps(result, indent=2)
    
    # 检测框架
    for framework, config in FRAMEWORK_PATTERNS.items():
        score = 0
        for file_pattern, regex in config['indicators']:
            # 查找匹配的文件
            if '*' in file_pattern:
                # 通配符匹配
                for root, dirs, files in os.walk(resolved_path):
                    for f in files:
                        if f.endswith('.py'):
                            try:
                                with open(os.path.join(root, f), 'r', errors='ignore') as fp:
                                    content = fp.read()[:5000]  # 只读前5000字符
                                    if re.search(regex, content, re.IGNORECASE):
                                        score += 1
                                        break
                            except:
                                pass
                    break  # 只查第一层
            else:
                # 精确文件名
                target = os.path.join(resolved_path, file_pattern)
                if os.path.exists(target):
                    try:
                        with open(target, 'r', errors='ignore') as fp:
                            content = fp.read()
                            if re.search(regex, content, re.IGNORECASE):
                                score += 2  # 精确匹配权重更高
                    except:
                        pass
        
        if score > result['confidence'] * 3:
            result['framework'] = framework
            result['confidence'] = min(1.0, score / 3)
            result['start_cmd'] = config['start_cmd'].format(port=9600)
            result['notes'] = config['notes'].copy()
            
            # 确定安装方式
            if config.get('pypi_name') and version:
                result['install_method'] = 'pypi'
                result['install_cmd'] = f"pip install {config['pypi_name']}=={version}"
                result['notes'].insert(0, f"推荐从 PyPI 安装: {result['install_cmd']}")
            else:
                result['install_method'] = 'source'
                result['install_cmd'] = config.get('install_cmd', 'pip install -e .')
    
    # 如果没检测到，尝试从 pyproject.toml 或 setup.py 获取名称
    if result['framework'] == 'unknown':
        pyproject = os.path.join(resolved_path, 'pyproject.toml')
        if os.path.exists(pyproject):
            try:
                with open(pyproject, 'r') as fp:
                    content = fp.read()
                    m = re.search(r'name\s*=\s*["\']([^"\']+)["\']', content)
                    if m:
                        pkg_name = m.group(1)
                        result['framework'] = pkg_name
                        result['notes'].append(f"从 pyproject.toml 检测到包名: {pkg_name}")
                        if version:
                            result['install_cmd'] = f"pip install {pkg_name}=={version}"
                            result['install_method'] = 'pypi'
            except:
                pass
    
    return json.dumps(result, indent=2)


@tools.tool
def cleanup_and_start_service(
    framework: str,
    port: int = 9600,
    custom_cmd: str = "",
    project_path: str = "",
    env_path: str = "/tmp/venv"
) -> str:
    """
    清理旧进程并启动 Web 服务。封装了端口清理、进程管理等复杂逻辑。
    
    这个工具会：
    1. 杀掉占用目标端口的旧进程
    2. 使用正确的启动命令启动服务（优先使用 custom_cmd）
    3. 等待服务就绪并进行健康检查
    
    :param framework: 框架类型 (mlflow, django, flask, fastapi, etc.)
    :param port: 服务端口，默认 9600
    :param custom_cmd: 自定义启动命令（可选，优先使用，应来自 CVE Knowledge 中的 Startup Command）
    :param project_path: 项目路径（可以是相对路径，会自动解析到 simulation_environments）
    :param env_path: 虚拟环境路径
    :return: 启动结果信息
    """
    import json
    
    # 智能解析项目路径
    # 1. 如果提供了 project_path，使用它
    # 2. 否则，尝试从环境变量 REPO_PATH 获取
    # 3. 最后才回退到 SIMULATION_ENV_DIR
    if project_path:
        resolved_project_path = resolve_project_path(project_path)
    elif os.environ.get('REPO_PATH'):
        repo_path = os.environ['REPO_PATH'].rstrip('/')
        resolved_project_path = os.path.join(SIMULATION_ENV_DIR, repo_path)
    else:
        resolved_project_path = SIMULATION_ENV_DIR
    
    print(f"[cleanup_and_start_service] Using project directory: {resolved_project_path}")
    
    result = {
        'success': False,
        'message': '',
        'pid': None,
        'port': port,
        'cmd_used': '',
        'resolved_path': resolved_project_path,  # 告诉 Agent 实际使用的路径
    }
    
    # Step 1: 清理旧进程和旧日志
    cleanup_commands = [
        f"fuser -k {port}/tcp 2>/dev/null || true",
        f"pkill -9 -f 'gunicorn|mlflow|flask|uvicorn|django|streamlit' 2>/dev/null || true",
        "rm -f /tmp/web_service.log 2>/dev/null || true",  # 清理旧日志文件
        "sleep 2",
    ]
    
    for cmd in cleanup_commands:
        subprocess.run(cmd, shell=True, capture_output=True)
    
    # Step 2: 确定启动命令
    # 优先使用 custom_cmd（应来自 CVE Knowledge 中推理出的完整启动命令）
    if custom_cmd:
        start_cmd = custom_cmd
    elif framework.lower() in FRAMEWORK_PATTERNS:
        start_cmd = FRAMEWORK_PATTERNS[framework.lower()]['start_cmd'].format(port=port)
    else:
        start_cmd = f"python app.py --port {port}"
    
    result['cmd_used'] = start_cmd
    
    # Step 3: 构建完整的启动命令（激活虚拟环境）
    # 使用带时间戳的日志文件名，避免读取旧日志
    # 使用 bash -c 确保 source 命令可用
    import datetime
    log_file = f"/tmp/web_service_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
    result['log_file'] = log_file
    
    # ========== 关键修复: 智能判断工作目录 ==========
    # 如果是 PyPI 安装（mlflow, django 等）或框架自带命令（如 mlflow server），
    # 不需要 cd 到源码目录，直接在 /tmp 运行更安全，避免 Python 从当前目录导入
    # 只有需要从源码运行时（如 python app.py 或 bash start.sh）才需要 cd 到项目目录
    
    is_framework_cmd = any(fw in start_cmd.lower() for fw in ['mlflow', 'django', 'flask', 'uvicorn', 'streamlit'])
    is_pip_installed = framework.lower() in FRAMEWORK_PATTERNS and FRAMEWORK_PATTERNS[framework.lower()].get('pypi_name')
    
    # 检查命令是否需要项目目录（如 bash xxx.sh, python app.py 等）
    needs_project_dir = any(pattern in start_cmd.lower() for pattern in [
        'bash ', 'sh ', 'python ', './', '/'
    ]) and not is_framework_cmd
    
    if is_framework_cmd or is_pip_installed:
        # 框架命令或 PyPI 安装的包，在干净目录运行
        work_dir = "/tmp"
        print(f"[cleanup_and_start_service] Using clean directory: {work_dir} (framework command or PyPI install)")
    elif needs_project_dir or os.path.isdir(resolved_project_path):
        # 需要源码的项目，cd 到项目目录
        work_dir = resolved_project_path
        print(f"[cleanup_and_start_service] Using project directory: {work_dir}")
    else:
        # 如果路径不存在，使用 simulation_environments
        work_dir = SIMULATION_ENV_DIR
        print(f"[cleanup_and_start_service] Path not found, using simulation_environments: {work_dir}")
    
    result['work_dir'] = work_dir
    
    full_cmd = f"""bash -c 'cd {work_dir} && source {env_path}/bin/activate && nohup {start_cmd} > {log_file} 2>&1 & echo $!'"""
    
    try:
        proc = subprocess.run(
            full_cmd, 
            shell=True, 
            capture_output=True, 
            text=True,
            timeout=30
        )
        
        # 获取 PID
        pid_str = proc.stdout.strip()
        if pid_str.isdigit():
            result['pid'] = int(pid_str)
        
        # Step 4: 等待并检查健康状态
        time.sleep(5)
        
        # 检查进程是否还在
        check_proc = subprocess.run(
            f"ps -p {result['pid']} 2>/dev/null",
            shell=True,
            capture_output=True
        )
        
        if check_proc.returncode != 0:
            # 进程已退出，读取当前日志
            log_proc = subprocess.run(
                f"tail -50 {log_file}",
                shell=True,
                capture_output=True,
                text=True
            )
            result['message'] = f"进程启动后立即退出。日志:\n{log_proc.stdout}"
            
            # 诊断错误
            for pattern, diagnosis in ERROR_DIAGNOSIS.items():
                if re.search(pattern, log_proc.stdout, re.IGNORECASE):
                    result['message'] += f"\n\n诊断: {diagnosis['cause']}\n建议: {diagnosis['fix']}"
                    break
            
            return json.dumps(result, indent=2, ensure_ascii=False)
        
        # Step 5: HTTP 健康检查
        curl_cmd = f"curl -s -o /dev/null -w '%{{http_code}}' http://localhost:{port}/ --connect-timeout 5"
        curl_proc = subprocess.run(curl_cmd, shell=True, capture_output=True, text=True)
        http_code = curl_proc.stdout.strip()
        
        if http_code in ['200', '302', '301', '401', '403']:
            result['success'] = True
            result['message'] = f"服务启动成功! HTTP 状态码: {http_code}"
        elif http_code == '000':
            result['message'] = f"服务可能还在启动中，HTTP 请求超时。建议等待更长时间后重试 curl。"
        else:
            result['message'] = f"服务可能有问题，HTTP 状态码: {http_code}"
            
    except subprocess.TimeoutExpired:
        result['message'] = "启动命令超时"
    except Exception as e:
        result['message'] = f"启动失败: {str(e)}"
    
    return json.dumps(result, indent=2, ensure_ascii=False)


@tools.tool
def diagnose_service_failure(port: int = 9600, log_file: str = "") -> str:
    """
    诊断 Web 服务启动失败的原因，并给出修复建议。
    
    这个工具会：
    1. 检查端口占用情况
    2. 分析日志中的错误（优先读取最新日志）
    3. 给出具体的修复建议
    
    :param port: 服务端口
    :param log_file: 日志文件路径（可选，不传则自动查找最新日志）
    :return: 诊断结果和修复建议
    """
    import json
    import glob
    
    result = {
        'issues': [],
        'suggestions': [],
        'log_excerpt': '',
    }
    
    # 如果没有指定日志文件，自动查找最新的日志
    if not log_file:
        log_files = glob.glob('/tmp/web_service_*.log')
        if log_files:
            log_file = max(log_files, key=os.path.getmtime)  # 最新的日志
        else:
            log_file = '/tmp/web_service.log'  # 回退到旧路径
    
    # 检查端口占用
    port_check = subprocess.run(
        f"lsof -i :{port} 2>/dev/null | head -5",
        shell=True,
        capture_output=True,
        text=True
    )
    if port_check.stdout.strip():
        result['issues'].append(f"端口 {port} 被占用")
        result['suggestions'].append(f"运行: fuser -k {port}/tcp")
    
    # 读取日志
    if os.path.exists(log_file):
        try:
            with open(log_file, 'r', errors='ignore') as fp:
                log_content = fp.read()[-5000:]  # 最后5000字符
                result['log_excerpt'] = log_content[-1000:]
                result['log_file'] = log_file  # 返回使用的日志文件路径
                
                # 诊断错误
                for pattern, diagnosis in ERROR_DIAGNOSIS.items():
                    if re.search(pattern, log_content, re.IGNORECASE):
                        result['issues'].append(diagnosis['cause'])
                        result['suggestions'].append(diagnosis['fix'].format(port=port))
        except:
            result['issues'].append("无法读取日志文件")
    else:
        result['issues'].append(f"日志文件 {log_file} 不存在")
        result['suggestions'].append("检查服务是否成功启动，或日志路径是否正确")
    
    # 检查常见进程
    ps_check = subprocess.run(
        "ps aux | grep -E 'mlflow|gunicorn|flask|uvicorn|django|python.*app' | grep -v grep | head -5",
        shell=True,
        capture_output=True,
        text=True
    )
    if ps_check.stdout.strip():
        result['issues'].append("有相关进程在运行，但可能不健康")
        result['suggestions'].append("检查进程状态: " + ps_check.stdout.strip().split('\n')[0][:100])
    
    if not result['issues']:
        result['issues'].append("未发现明显问题")
        result['suggestions'].append("服务可能需要更长时间启动，或检查应用配置")
    
    return json.dumps(result, indent=2, ensure_ascii=False)


@tools.tool  
def install_web_project(
    project_path: str,
    sw_version: str,
    framework: str = "",
    env_path: str = "/tmp/venv"
) -> str:
    """
    智能安装 Web 项目依赖。
    
    优先使用 PyPI 安装（更稳定），避免源码安装的循环导入问题。
    
    :param project_path: 项目路径（可以是相对路径，会自动解析到 simulation_environments）
    :param sw_version: 版本号，如 "v2.20.1"
    :param framework: 框架类型（可选，会自动检测）
    :param env_path: 虚拟环境路径
    :return: 安装结果
    """
    import json
    
    # 智能解析项目路径
    resolved_path = resolve_project_path(project_path)
    
    result = {
        'success': False,
        'install_method': '',
        'command_used': '',
        'output': '',
        'resolved_path': resolved_path,
    }
    
    # 解析版本号
    version = re.sub(r'^v', '', sw_version)
    
    # 自动检测框架
    if not framework:
        detect_result = json.loads(detect_web_framework(project_path, sw_version))
        framework = detect_result.get('framework', 'unknown')
    
    # 确定安装命令
    if framework.lower() in FRAMEWORK_PATTERNS:
        config = FRAMEWORK_PATTERNS[framework.lower()]
        if config.get('pypi_name') and version:
            # 优先 PyPI
            install_cmd = f"pip install {config['pypi_name']}=={version}"
            result['install_method'] = 'pypi'
        else:
            install_cmd = config.get('install_cmd', 'pip install -e .')
            result['install_method'] = 'source'
    else:
        # 检查是否有 requirements.txt
        if os.path.exists(os.path.join(resolved_path, 'requirements.txt')):
            install_cmd = "pip install -r requirements.txt"
            result['install_method'] = 'requirements'
        elif os.path.exists(os.path.join(resolved_path, 'pyproject.toml')):
            install_cmd = "pip install ."  # 不用 -e 避免循环导入
            result['install_method'] = 'source'
        else:
            install_cmd = "pip install ."
            result['install_method'] = 'source'
    
    result['command_used'] = install_cmd
    
    # 执行安装 - 使用 bash -c 确保 source 命令可用
    # 不能用 `. ` 因为需要完整的 shell 功能
    full_cmd = f"""bash -c 'cd {resolved_path} && source {env_path}/bin/activate && {install_cmd}'"""
    
    try:
        proc = subprocess.run(
            full_cmd,
            shell=True,
            capture_output=True,
            text=True,
            timeout=600  # 10分钟超时
        )
        
        result['output'] = proc.stdout[-2000:] + "\n" + proc.stderr[-2000:]
        result['success'] = proc.returncode == 0
        
        if not result['success']:
            result['output'] += "\n\n建议: 检查依赖是否兼容，或尝试 pip install --upgrade pip 后重试"
            
    except subprocess.TimeoutExpired:
        result['output'] = "安装超时（10分钟）"
    except Exception as e:
        result['output'] = f"安装出错: {str(e)}"
    
    return json.dumps(result, indent=2, ensure_ascii=False)


@tools.tool
def get_project_workspace(project_name: str = "") -> str:
    """
    获取项目的实际工作目录。这是 Agent 在执行任何操作前应该调用的工具。
    
    返回信息包括：
    - simulation_environments 目录的绝对路径
    - 该目录下的所有项目/文件列表
    - 如果提供了 project_name，返回匹配的完整路径
    
    这个工具帮助 Agent 理解：
    1. 下载的源码在哪里
    2. 应该在哪个目录执行命令
    3. 如何正确引用项目路径
    
    :param project_name: 可选的项目名称（如 'open-webui-0.6.5'），用于查找特定项目
    :return: 工作目录信息的 JSON 字符串
    """
    import json
    
    result = {
        'simulation_env_dir': SIMULATION_ENV_DIR,
        'contents': [],
        'matched_project': None,
        'matched_path': None,
        'tip': '所有下载的源码都在 simulation_environments 目录下。使用完整路径调用其他工具。'
    }
    
    # 列出 simulation_environments 目录内容
    if os.path.exists(SIMULATION_ENV_DIR):
        try:
            for item in os.listdir(SIMULATION_ENV_DIR):
                item_path = os.path.join(SIMULATION_ENV_DIR, item)
                item_info = {
                    'name': item,
                    'path': item_path,
                    'is_dir': os.path.isdir(item_path),
                }
                if os.path.isdir(item_path):
                    # 列出子目录的一些内容
                    try:
                        sub_items = os.listdir(item_path)[:10]
                        item_info['sample_contents'] = sub_items
                    except:
                        pass
                result['contents'].append(item_info)
        except Exception as e:
            result['error'] = f"无法列出目录: {str(e)}"
    else:
        result['contents'] = []
        result['tip'] = 'simulation_environments 目录不存在，可能还没有下载项目'
    
    # 如果提供了项目名，尝试匹配
    if project_name:
        # 精确匹配
        exact_path = os.path.join(SIMULATION_ENV_DIR, project_name)
        if os.path.exists(exact_path):
            result['matched_project'] = project_name
            result['matched_path'] = exact_path
        else:
            # 模糊匹配
            for item in result['contents']:
                if project_name.lower() in item['name'].lower():
                    result['matched_project'] = item['name']
                    result['matched_path'] = item['path']
                    break
        
        if result['matched_path']:
            result['tip'] = f"找到项目！使用完整路径: {result['matched_path']}"
        else:
            result['tip'] = f"未找到项目 '{project_name}'。请先下载或检查目录内容。"
    
    return json.dumps(result, indent=2, ensure_ascii=False)


# ==================== 工具注册 ====================

WEB_SERVICE_TOOLS = {
    'detect_web_framework': detect_web_framework,
    'cleanup_and_start_service': cleanup_and_start_service,
    'diagnose_service_failure': diagnose_service_failure,
    'install_web_project': install_web_project,
    'get_project_workspace': get_project_workspace,
}
