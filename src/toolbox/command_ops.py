import subprocess
import os
import time
import uuid
import signal
import re
from typing import Optional, Dict, List
from collections import defaultdict
from dataclasses import dataclass, field

from agentlib.lib import tools

# 全局反思器实例（懒加载）
_mid_exec_reflector: Optional['MidExecutionReflector'] = None
_reflection_enabled: bool = True


# ==================== 重复命令检测器 ====================
@dataclass
class CommandPattern:
    """命令模式，用于检测相似命令"""
    base_pattern: str  # 命令的基本模式（去除具体参数）
    count: int = 0
    failed_count: int = 0
    last_output: str = ""
    

class RepetitiveCommandDetector:
    """
    检测重复执行相同或相似命令的行为。
    当 Agent 多次尝试相同的失败命令时，强制干预。
    """
    
    # 最大允许的相同命令失败次数
    MAX_SAME_COMMAND_FAILURES = 3
    # 最大允许的相似命令失败次数（如不同包名的apt-get install）
    MAX_SIMILAR_PATTERN_FAILURES = 5
    # 常见错误模式及其建议
    ERROR_PATTERNS = {
        r"Unable to locate package (\S+)": "包名 '{0}' 不存在。请检查正确的包名或使用 `apt-cache search <关键词>` 搜索。",
        r"E: Package '(\S+)' has no installation candidate": "包 '{0}' 不可用。尝试 `apt-get update` 或搜索替代包。",
        r"playwright.*install-deps": "Playwright 依赖应已预安装。直接使用 `playwright install chromium` 或直接运行 Python 脚本。",
        r"pip.*install.*failed": "pip 安装失败。检查包名是否正确，或尝试 `pip install --upgrade pip` 后重试。",
        r"ModuleNotFoundError: No module named '(\S+)'": "模块 '{0}' 未安装。使用 `pip install {0}` 安装。",
        r"command not found": "命令不存在。使用 `apt-get install` 安装所需工具或检查路径。",
        r"Permission denied": "权限不足。尝试添加 `sudo` 或检查文件权限。",
        r"Connection refused|Cannot connect": "连接被拒绝。确保目标服务正在运行并监听正确的端口。",
        r"libwoff2dec1|libwoff1": "libwoff 相关依赖通过 `playwright install-deps chromium` 自动安装，不需要手动安装。",
        r"gstreamer|libavif": "多媒体库通过 `playwright install-deps chromium` 安装，直接运行该命令。",
        # === Web 应用启动失败相关错误模式 ===
        r"Failed to find attribute '(\w+)' in '(\w+)'": "模块 '{1}' 没有 '{0}' 属性。这通常意味着启动命令错误。检查 README 或 pyproject.toml 获取正确的启动方式。对于 MLflow 使用 `mlflow server`，Django 用 `python manage.py runserver`，FastAPI 用 `uvicorn`。",
        r"Worker failed to boot|Worker exited with code": "Gunicorn Worker 启动失败。可能原因：1) 模块路径错误 2) 缺少依赖 3) 应用不是 WSGI/ASGI 兼容的。尝试使用框架自带的开发服务器命令。",
        r"App failed to load": "应用加载失败。检查入口点是否正确，确保使用 `pip install -e .` 安装了项目。",
        r"No module named 'databricks'": "缺少 databricks-sdk。运行 `pip install databricks-sdk` 或 `pip install -e .` 安装所有项目依赖。",
        r"gunicorn.*mlflow.*:app": "MLflow 不使用 gunicorn 直接启动。正确命令是 `mlflow server --host 0.0.0.0 --port 9600`。",
        r"AttributeError:.*'function' object has no attribute": "错误的 WSGI 入口点。CLI 函数不能作为 WSGI app。检查项目文档获取正确的启动方式。",
        r"Address already in use|Connection in use": "端口已被占用。使用 `lsof -i :<port>` 或 `netstat -tlnp | grep <port>` 检查，然后 `kill <pid>` 终止进程。",
        r"Could not open requirements file.*No such file": "requirements.txt 不存在。检查项目结构，可能是 requirements/ 目录或 pyproject.toml。对于现代项目使用 `pip install -e .`。",
        r"ImportError:.*cannot import name": "导入错误，可能是版本不兼容或循环导入。检查依赖版本，尝试 `pip install -e .` 安装正确版本。",
        r"unzip.*Timed out": "unzip 命令超时，通常是因为等待用户输入（文件覆盖确认）。必须使用 `unzip -o -q file.zip` 参数：-o (覆盖) -q (静默模式)。",
        r"replace.*\[y\]es.*\[n\]o.*\[A\]ll": "unzip 正在等待用户输入覆盖确认。使用 `unzip -o file.zip` 自动覆盖所有文件。",
        r"Timed out.*unzip": "unzip 超时可能原因：1) 文件过大需要更长时间（尝试解压到 /tmp 而不是远程挂载目录）2) 等待交互输入（必须加 -o -q 参数）3) 目标目录权限问题。建议：cd /tmp && unzip -o -q /path/to/file.zip",
    }
    
    def __init__(self):
        self.command_history: List[Dict] = []
        self.pattern_counts: Dict[str, CommandPattern] = defaultdict(CommandPattern)
        self.total_commands = 0
        self.total_failures = 0
    
    def reset(self):
        """重置检测器状态"""
        self.command_history.clear()
        self.pattern_counts.clear()
        self.total_commands = 0
        self.total_failures = 0
    
    def _normalize_command(self, cmd: str) -> str:
        """将命令规范化为模式（去除具体参数）"""
        # 移除多余空格
        cmd = ' '.join(cmd.split())
        
        # 规范化 apt-get/apt install 命令
        if re.match(r'(sudo\s+)?(apt-get|apt)\s+install', cmd):
            # 提取包名模式
            return re.sub(r'(sudo\s+)?(apt-get|apt)\s+install\s+(-y\s+)?', 'APT_INSTALL:', cmd)
        
        # 规范化 pip install 命令
        if re.match(r'pip3?\s+install', cmd):
            return re.sub(r'pip3?\s+install\s+', 'PIP_INSTALL:', cmd)
        
        # 规范化 playwright 命令
        if 'playwright' in cmd:
            return re.sub(r'playwright\s+\S+', 'PLAYWRIGHT_CMD', cmd)
        
        # 规范化 unzip 命令
        if re.match(r'unzip\s+', cmd):
            return 'UNZIP_FILE'
        
        return cmd
    
    def _extract_error_suggestion(self, output: str) -> Optional[str]:
        """从输出中提取错误并给出建议"""
        for pattern, suggestion in self.ERROR_PATTERNS.items():
            match = re.search(pattern, output, re.IGNORECASE)
            if match:
                groups = match.groups() if match.groups() else []
                try:
                    return suggestion.format(*groups) if groups else suggestion
                except (IndexError, KeyError):
                    return suggestion
        return None
    
    def check_command(self, command: str, output: str, exit_code: int) -> Optional[str]:
        """
        检查命令执行情况，返回干预消息（如果需要）
        """
        self.total_commands += 1
        is_failure = exit_code != 0
        
        if is_failure:
            self.total_failures += 1
        
        # 规范化命令
        pattern = self._normalize_command(command)
        
        # 更新模式统计
        if pattern not in self.pattern_counts:
            self.pattern_counts[pattern] = CommandPattern(base_pattern=pattern)
        
        self.pattern_counts[pattern].count += 1
        if is_failure:
            self.pattern_counts[pattern].failed_count += 1
            self.pattern_counts[pattern].last_output = output[-500:]  # 保留最后500字符
        
        # 记录历史
        self.command_history.append({
            'command': command,
            'pattern': pattern,
            'exit_code': exit_code,
            'is_failure': is_failure
        })
        
        # 检查是否需要干预
        intervention_msg = None
        
        # 1. 检查相同命令重复失败
        if self.pattern_counts[pattern].failed_count >= self.MAX_SAME_COMMAND_FAILURES:
            error_suggestion = self._extract_error_suggestion(output)
            intervention_msg = self._generate_intervention(
                f"相同命令已失败 {self.pattern_counts[pattern].failed_count} 次",
                command,
                error_suggestion
            )
        
        # 2. 检查相似模式重复失败（如多次尝试不同的apt包名）
        elif pattern.startswith('APT_INSTALL:'):
            apt_failures = sum(
                p.failed_count for key, p in self.pattern_counts.items() 
                if key.startswith('APT_INSTALL:')
            )
            if apt_failures >= self.MAX_SIMILAR_PATTERN_FAILURES:
                error_suggestion = self._extract_error_suggestion(output)
                intervention_msg = self._generate_intervention(
                    f"apt-get install 相关命令已失败 {apt_failures} 次",
                    command,
                    error_suggestion or "考虑使用 `playwright install-deps chromium` 自动安装所有依赖，或使用 `apt-cache search` 搜索正确的包名"
                )
        
        # 3. 检查总体失败率
        if self.total_commands >= 10 and self.total_failures / self.total_commands > 0.7:
            intervention_msg = self._generate_high_failure_rate_warning()
        
        return intervention_msg
    
    def _generate_intervention(self, reason: str, command: str, suggestion: Optional[str] = None) -> str:
        """生成干预消息"""
        msg = f"""
╔══════════════════════════════════════════════════════════════════╗
║ ⚠️  重复失败检测 - 需要改变策略                                    ║
╠══════════════════════════════════════════════════════════════════╣
║ 原因: {reason[:60]:<60} ║
║ 失败命令: {command[:56]:<56} ║
╠══════════════════════════════════════════════════════════════════╣
║ 🔧 建议:                                                          ║"""
        
        if suggestion:
            # 将建议分成多行
            lines = [suggestion[i:i+60] for i in range(0, len(suggestion), 60)]
            for line in lines[:3]:  # 最多3行
                msg += f"\n║   {line:<62} ║"
        else:
            msg += "\n║   - 尝试完全不同的方法                                        ║"
            msg += "\n║   - 检查错误信息，理解根本原因                                ║"
            msg += "\n║   - 搜索正确的包名或命令语法                                  ║"
        
        msg += """
╠══════════════════════════════════════════════════════════════════╣
║ ❌ 请勿再次尝试相同或相似的命令，必须采用新策略！                ║
╚══════════════════════════════════════════════════════════════════╝"""
        return msg
    
    def _generate_high_failure_rate_warning(self) -> str:
        """生成高失败率警告"""
        return f"""
╔══════════════════════════════════════════════════════════════════╗
║ 🚨 高失败率警告                                                   ║
╠══════════════════════════════════════════════════════════════════╣
║ 已执行 {self.total_commands} 个命令，其中 {self.total_failures} 个失败 ({100*self.total_failures//self.total_commands}%)          ║
║                                                                  ║
║ 建议:                                                            ║
║ 1. 暂停执行，仔细分析之前的错误输出                              ║
║ 2. 检查环境是否正确配置                                          ║
║ 3. 考虑是否需要先安装基础依赖                                    ║
║ 4. 查看文档或搜索正确的命令用法                                  ║
╚══════════════════════════════════════════════════════════════════╝"""
    
    def get_summary(self) -> str:
        """获取命令执行摘要"""
        if not self.command_history:
            return "无命令历史记录"
        
        failed_patterns = [
            (p.base_pattern, p.failed_count) 
            for p in self.pattern_counts.values() 
            if p.failed_count > 0
        ]
        failed_patterns.sort(key=lambda x: x[1], reverse=True)
        
        summary = f"命令统计: {self.total_commands} 总计, {self.total_failures} 失败\n"
        if failed_patterns:
            summary += "失败最多的命令模式:\n"
            for pattern, count in failed_patterns[:5]:
                summary += f"  - {pattern[:50]}: {count} 次失败\n"
        return summary


# 全局重复命令检测器
_command_detector: Optional[RepetitiveCommandDetector] = None


def get_command_detector() -> RepetitiveCommandDetector:
    """获取或创建全局命令检测器"""
    global _command_detector
    if _command_detector is None:
        _command_detector = RepetitiveCommandDetector()
    return _command_detector


def reset_command_detector():
    """重置命令检测器"""
    global _command_detector
    if _command_detector:
        _command_detector.reset()


# ==================== 原有代码 ====================


def get_reflector():
    """获取或创建全局反思器实例"""
    global _mid_exec_reflector
    if _mid_exec_reflector is None:
        try:
            from agents.midExecReflector import MidExecutionReflector
            _mid_exec_reflector = MidExecutionReflector()
        except ImportError:
            pass
    return _mid_exec_reflector


def enable_reflection(enabled: bool = True, context: str = "", deployment_strategy: dict = None):
    """启用或禁用反思机制（增强：支持deployment_strategy）"""
    global _reflection_enabled, _mid_exec_reflector
    _reflection_enabled = enabled
    if enabled:
        # 如果提供了deployment_strategy,创建新的reflector实例
        if deployment_strategy:
            try:
                from agents.midExecReflector import MidExecutionReflector
                _mid_exec_reflector = MidExecutionReflector(
                    context=context, 
                    deployment_strategy=deployment_strategy
                )
                print("[command_ops] ✅ MidExecReflector initialized with DeploymentStrategy")
            except ImportError as e:
                print(f"[command_ops] ⚠️ Failed to import MidExecutionReflector: {e}")
        elif context:
            # 如果只有context,更新现有reflector
            reflector = get_reflector()
            if reflector:
                reflector.update_context(context)


def reset_reflection():
    """重置反思器状态"""
    global _mid_exec_reflector
    if _mid_exec_reflector:
        _mid_exec_reflector.reset()

@tools.tool
def execute_find_command(filename: str) -> str:
    """
    This tool runs a 'find' command in the given directory to search for a specific file.
    If no files match, it returns "No files found."
    :param filename: The filename (or part of it) to search for.
    :return: The output of the 'find' command or a message if no files are found.
    """
    
    cur_dir = os.getcwd()
    os.chdir("simulation_environments/" + os.environ['REPO_PATH'])
    # Execute the find command
    process = subprocess.run(
        f"find ./ -type f -name '*{filename}*'",
        shell=True,
        capture_output=True,
        text=True,
        timeout=10
    )
    os.chdir(cur_dir)
    
    # Check if files are found
    if process.stdout.strip():
        return f"# Files found:\n{process.stdout}"
    else:
        return "No files found."

@tools.tool
def execute_ls_command(dir: str) -> str:
    """
    This tool runs an ls command in the given directory and returns the output.
    :param dir: The directory to run the ls command in.
    :return: The output of the ls command.
    """

    # print("Trying to execute: ls on", dir, "\nProceed? y/N")
    # p = input()
    # if p!='y':
    #     return "Unable to execute, permission denied"
    
    return execute_command_foreground(f"ls -a {dir}")

# Environment variables for commands
env = {}

@tools.tool
def set_environment_variable(key: str, value: str, clear: bool) -> str:
    """
    This tool sets an environment variable that will be used by all successive commands.

    :param key: The environment variable name.
    :param value: The value to assign to the environment variable.
    :param clear: Clears all previous env variables set using this command.
    :return: Confirmation message.
    """
    
    global env

    # Check for confirmation
    # print(f"Trying to export {key}={value}, clear={clear}. \nProceed? y/N")
    # p = input()
    # if p.lower() != 'y':
    #     return "Operation cancelled by user."

    if clear:
        env = {}
    env[key] = value
    
    return f"Success, current env_list={env}."

@tools.tool
def execute_linux_command(command: str, background: bool) -> str:
    """
    Executes a shell command in the root directory of the target repository.
    
    USAGE GUIDELINES:
    - Use background=False for: installations, builds, one-time commands
    - Use background=True for: servers, daemons, long-running processes
    
    IMPORTANT NOTES:
    - Export commands won't persist across calls (use set_environment_variable instead)
    - Avoid commands requiring user input (they will hang)
    - sudo commands are supported
    - Exit code 0 = success, non-zero = error
    - Empty/null output does NOT mean failure - check exit code!
    
    EXAMPLES:
    - execute_linux_command('pip install mlflow==2.11.2', background=False)
    - execute_linux_command('mlflow ui --host 0.0.0.0 --port 5000', background=True)
    - execute_linux_command('ps aux | grep mlflow', background=False)
    - execute_linux_command('curl http://localhost:5000', background=False)

    :param command: The shell command to execute
    :param background: True for long-running processes (servers), False for normal commands
    :return: Command output with exit code and logs
    """
    print("Trying to execute: ", command)
    if background:
        return execute_command_background(command)
    else:
        return execute_command_foreground(command)


# ==================== 环境路径常量 ====================
SIMULATION_ENV_DIR = "/workspaces/submission/src/simulation_environments"

# 需要在 DAG 结束时清理的进程模式
CLEANUP_PROCESS_PATTERNS = [
    'mlflow',
    'gunicorn', 
    'flask',
    'uvicorn',
    'django',
    'streamlit',
    'node',
    'npm',
    'python.*main.py',  # 避免杀掉自己，需要排除当前进程
]


def cleanup_running_processes() -> str:
    """清理 DAG 运行后残留的后台进程
    
    在 DAG 执行完成后（无论成功失败）调用此函数，
    杀掉所有 Web 服务进程，防止 CPU/内存占满。
    
    :return: 清理结果摘要
    """
    killed = []
    current_pid = os.getpid()
    
    for pattern in CLEANUP_PROCESS_PATTERNS:
        try:
            # 使用 pkill 杀掉匹配的进程，但排除当前进程
            cmd = f"pkill -9 -f '{pattern}' 2>/dev/null || true"
            subprocess.run(cmd, shell=True, capture_output=True, timeout=10)
            killed.append(pattern)
        except Exception as e:
            print(f"⚠️ Failed to kill {pattern}: {e}")
    
    # 额外清理端口占用
    common_ports = [5000, 8000, 8080, 9600, 3000]
    for port in common_ports:
        try:
            subprocess.run(f"fuser -k {port}/tcp 2>/dev/null || true", shell=True, capture_output=True, timeout=5)
        except:
            pass
    
    result = f"🧹 Cleaned up processes: {', '.join(killed)}"
    print(result)
    return result


def wait_for_service(url: str, timeout: int = 60, interval: int = 2) -> dict:
    """等待 Web 服务就绪
    
    在 browser-provision 前调用，确保服务已完全启动。
    比 cleanup_and_start_service 中的健康检查更彻底。
    
    :param url: 服务 URL，如 http://localhost:5000
    :param timeout: 最大等待时间（秒）
    :param interval: 检查间隔（秒）
    :return: 检查结果 {ready: bool, status_code: int, elapsed: float, message: str}
    """
    import time
    
    result = {
        'ready': False,
        'status_code': 0,
        'elapsed': 0,
        'message': '',
        'url': url,
    }
    
    start_time = time.time()
    attempts = 0
    max_attempts = timeout // interval
    
    print(f"⏳ Waiting for service at {url} (timeout: {timeout}s)...")
    
    while attempts < max_attempts:
        attempts += 1
        elapsed = time.time() - start_time
        
        try:
            # 使用 curl 检查服务
            curl_cmd = f"curl -s -o /dev/null -w '%{{http_code}}' '{url}/' --connect-timeout 5 --max-time 10"
            proc = subprocess.run(curl_cmd, shell=True, capture_output=True, text=True, timeout=15)
            status_code = proc.stdout.strip()
            
            if status_code and status_code != '000':
                code = int(status_code)
                result['status_code'] = code
                result['elapsed'] = elapsed
                
                # 大多数 HTTP 响应都表示服务在运行（包括重定向）
                if code in [200, 301, 302, 303, 307, 308, 401, 403, 404, 405, 500]:
                    result['ready'] = True
                    result['message'] = f"Service ready! HTTP {code} after {elapsed:.1f}s"
                    print(f"✅ {result['message']}")
                    return result
                else:
                    print(f"  Attempt {attempts}: HTTP {code}, waiting...")
            else:
                print(f"  Attempt {attempts}: Connection refused, waiting...")
                
        except subprocess.TimeoutExpired:
            print(f"  Attempt {attempts}: Timeout, waiting...")
        except Exception as e:
            print(f"  Attempt {attempts}: Error - {e}, waiting...")
        
        time.sleep(interval)
    
    result['elapsed'] = time.time() - start_time
    result['message'] = f"Service not ready after {timeout}s ({attempts} attempts)"
    print(f"❌ {result['message']}")
    return result


def cleanup_simulation_environment(keep_current_cve: str = "") -> str:
    """清理 simulation_environments 目录和虚拟环境，只保留最近一次的环境
    
    为了节省存储空间和保护系统环境，每次运行新 CVE 前：
    1. 清理旧的项目文件
    2. 清理旧的虚拟环境
    
    :param keep_current_cve: 当前正在运行的 CVE 名称（如果有），用于保留相关文件
    :return: 清理结果摘要
    """
    import shutil
    
    # ========== 1. 清理虚拟环境 ==========
    cleanup_venv()
    
    # ========== 2. 清理 simulation_environments ==========
    if not os.path.exists(SIMULATION_ENV_DIR):
        os.makedirs(SIMULATION_ENV_DIR, exist_ok=True)
        return "Created simulation_environments directory"
    
    cleaned = []
    kept = []
    
    for item in os.listdir(SIMULATION_ENV_DIR):
        item_path = os.path.join(SIMULATION_ENV_DIR, item)
        
        # 如果指定了当前 CVE，保留相关文件
        if keep_current_cve and keep_current_cve.lower() in item.lower():
            kept.append(item)
            continue
        
        # 删除旧文件和目录
        try:
            if os.path.isdir(item_path):
                shutil.rmtree(item_path)
            else:
                os.remove(item_path)
            cleaned.append(item)
        except Exception as e:
            print(f"⚠️ Failed to remove {item}: {e}")
    
    result = f"Cleaned {len(cleaned)} items from simulation_environments"
    if kept:
        result += f", kept {len(kept)} items for current CVE"
    print(f"🧹 {result}")
    
    return result


def get_working_directory() -> str:
    """获取命令执行的工作目录
    
    工作目录优先级:
    1. REPO_PATH（传统模式，在 simulation_environments 下）
    2. WORK_DIR 环境变量（手动指定）
    3. simulation_environments 目录（始终用于下载/解压源码）
    
    注意：始终返回 simulation_environments，即使它是空的。
    这样 wget/unzip 等下载命令会把文件放到正确的位置。
    """
    # 优先使用 REPO_PATH（传统模式）
    if os.environ.get("REPO_PATH"):
        repo_dir = f"{SIMULATION_ENV_DIR}/{os.environ['REPO_PATH']}"
        if os.path.exists(repo_dir):
            return repo_dir
    
    # 其次检查 WORK_DIR 环境变量
    if os.environ.get("WORK_DIR"):
        return os.environ["WORK_DIR"]
    
    # 始终使用 simulation_environments 目录
    # 确保目录存在
    if not os.path.exists(SIMULATION_ENV_DIR):
        os.makedirs(SIMULATION_ENV_DIR, exist_ok=True)
    
    return SIMULATION_ENV_DIR


# ==================== pip 命令隔离机制 ====================
VENV_PATH = "/tmp/venv"

def is_pip_command(command: str) -> bool:
    """检测是否是 pip 安装命令"""
    pip_patterns = [
        r'^\s*pip\s+install',
        r'^\s*pip3\s+install',
        r'^\s*python\s+-m\s+pip\s+install',
        r'^\s*python3\s+-m\s+pip\s+install',
        r'&&\s*pip\s+install',
        r'&&\s*pip3\s+install',
        r';\s*pip\s+install',
        r';\s*pip3\s+install',
    ]
    for pattern in pip_patterns:
        if re.search(pattern, command, re.IGNORECASE):
            return True
    return False


def ensure_venv_exists() -> bool:
    """确保虚拟环境存在，如果不存在则创建"""
    if os.path.exists(f"{VENV_PATH}/bin/activate"):
        return True
    
    try:
        print(f"[Isolation] 🔧 Creating virtual environment at {VENV_PATH}...")
        result = subprocess.run(
            f"python3 -m venv {VENV_PATH}",
            shell=True,
            capture_output=True,
            text=True,
            timeout=60
        )
        if result.returncode == 0:
            print(f"[Isolation] ✅ Virtual environment created")
            return True
        else:
            print(f"[Isolation] ❌ Failed to create venv: {result.stderr}")
            return False
    except Exception as e:
        print(f"[Isolation] ❌ Error creating venv: {e}")
        return False


def wrap_pip_command_in_venv(command: str) -> str:
    """将 pip 命令包装在虚拟环境中执行
    
    原始命令:
        pip install flask
        cd project && pip install -r requirements.txt
    
    包装后:
        source /tmp/venv/bin/activate && pip install flask
        cd project && source /tmp/venv/bin/activate && pip install -r requirements.txt
    """
    # 如果命令已经包含 venv 激活，不需要再包装
    if '/tmp/venv/bin/activate' in command or 'source.*venv' in command:
        return command
    
    # 确保 venv 存在
    ensure_venv_exists()
    
    activate_cmd = f"source {VENV_PATH}/bin/activate"
    
    # 处理复合命令 (cd xxx && pip install)
    if '&&' in command:
        # 在第一个 pip 命令前插入激活
        parts = command.split('&&')
        new_parts = []
        activated = False
        for part in parts:
            part = part.strip()
            if not activated and ('pip install' in part.lower() or 'pip3 install' in part.lower()):
                new_parts.append(activate_cmd)
                activated = True
            new_parts.append(part)
        return ' && '.join(new_parts)
    
    # 处理简单命令
    if command.strip().startswith('pip') or command.strip().startswith('python'):
        return f"{activate_cmd} && {command}"
    
    return command


def cleanup_venv():
    """清理虚拟环境（在每次 CVE 复现开始时调用）"""
    if os.path.exists(VENV_PATH):
        try:
            import shutil
            shutil.rmtree(VENV_PATH)
            print(f"[Isolation] 🧹 Cleaned up virtual environment: {VENV_PATH}")
        except Exception as e:
            print(f"[Isolation] ⚠️ Failed to cleanup venv: {e}")


def execute_command_foreground(command: str) -> str:
    """
    This tool runs a command (in the root directory of the target repository) in the shell, waits for termination and returns the output.
    Do not spawn processes that run servers as it will hang indefinitely.

    :param command: The command to run.
    :return: The output of the command.
    """
    
    # ========== pip 命令隔离：保护系统环境 ==========
    original_command = command
    if is_pip_command(command):
        command = wrap_pip_command_in_venv(command)
        if command != original_command:
            print(f"[Isolation] 🔒 pip command isolated to venv")
            print(f"[Isolation] Original: {original_command}")
            print(f"[Isolation] Wrapped:  {command}")
    
    stdout_log = create_unique_logfile("stdout")
    stderr_log = create_unique_logfile("stderr")
    exit_code = 0
    work_dir = get_working_directory()
    timeout_occurred = False
    
    try:
        with open(stdout_log, "w", encoding='utf-8') as stdout, open(stderr_log, "w", encoding='utf-8') as stderr:
            result = subprocess.run(
                command,
                shell=True,
                executable="/bin/bash",
                cwd=work_dir,
                stdout=stdout,
                stderr=stderr,
                text=True,
                timeout=300,
                errors="ignore",
                env=os.environ.copy() | env
            )
            exit_code = result.returncode
    except subprocess.TimeoutExpired:
        exit_code = 124  # 标准的超时退出码
        timeout_occurred = True
        output = f"❌ Timed out after 300s! Command: {original_command}"
        
        # 🔄 重复命令检测（超时也算失败）
        detector = get_command_detector()
        repetition_warning = detector.check_command(original_command, output, exit_code)
        if repetition_warning:
            output = output + "\n\n" + repetition_warning
        
        return output

    # Get the last 100 lines of both log files
    tail_output = get_tail_log(stdout_log, stderr_log)
    
    # Add exit code and status indicator
    status_icon = "✅" if exit_code == 0 else "⚠️"
    
    # 如果命令被隔离，在输出中说明
    isolation_note = ""
    if command != original_command:
        isolation_note = f"\n[Isolation] ℹ️ Command was executed in isolated venv ({VENV_PATH})\n"
    
    output = (
        f"{status_icon} Command completed with exit code: {exit_code}\n"
        f"Command: {original_command}\n"
        f"{isolation_note}\n"
        f"{tail_output}\n"
        f"{'Note: Exit code 0 = success, non-zero = error' if exit_code != 0 else ''}"
    )
    
    # 🔄 重复命令检测
    detector = get_command_detector()
    repetition_warning = detector.check_command(original_command, output, exit_code)
    if repetition_warning:
        output = output + "\n\n" + repetition_warning
    
    # 🔍 中途反思检查
    if _reflection_enabled:
        reflector = get_reflector()
        if reflector:
            reflection_result = reflector.check_and_reflect(command, output)
            if reflection_result and reflection_result.should_intervene:
                # 将反思结果附加到输出，让 Agent 看到
                intervention_msg = reflector.get_intervention_message(reflection_result)
                output = output + "\n\n" + intervention_msg
    
    return output

background_process_list={}


def is_python_run_command(command: str) -> bool:
    """检测是否是 Python 运行命令（需要使用 venv 中的 Python）"""
    python_patterns = [
        r'^\s*python\s+',
        r'^\s*python3\s+',
        r'&&\s*python\s+',
        r'&&\s*python3\s+',
        r';\s*python\s+',
        r';\s*python3\s+',
        r'uvicorn\s+',
        r'gunicorn\s+',
        r'flask\s+run',
        r'streamlit\s+run',
    ]
    for pattern in python_patterns:
        if re.search(pattern, command, re.IGNORECASE):
            return True
    return False


def wrap_python_command_in_venv(command: str) -> str:
    """将 Python 运行命令包装在虚拟环境中执行"""
    # 如果命令已经包含 venv 激活，不需要再包装
    if '/tmp/venv/bin/activate' in command:
        return command
    
    # 如果 venv 不存在，不包装（可能还没安装依赖）
    if not os.path.exists(f"{VENV_PATH}/bin/activate"):
        return command
    
    activate_cmd = f"source {VENV_PATH}/bin/activate"
    
    # 处理复合命令 (cd xxx && python app.py)
    if '&&' in command:
        parts = command.split('&&')
        new_parts = []
        activated = False
        for part in parts:
            part = part.strip()
            if not activated and is_python_run_command(part):
                new_parts.append(activate_cmd)
                activated = True
            new_parts.append(part)
        return ' && '.join(new_parts)
    
    # 处理简单命令
    return f"{activate_cmd} && {command}"


def execute_command_background(command: str) -> str:
    """
    This tool runs a command in the background (in the root directory of the target repository) in the shell and returns the output.
    Use this to start servers.
    Do not spawn processes using single &.

    :param command: The command to run.
    :return: The output of the command.
    """
    
    global background_process_list

    original_command = command
    command = command.removesuffix('&')
    
    # ========== Python/pip 命令隔离：使用 venv ==========
    if is_pip_command(command):
        command = wrap_pip_command_in_venv(command)
        if command != original_command.removesuffix('&'):
            print(f"[Isolation] 🔒 pip command isolated to venv")
    elif is_python_run_command(command):
        command = wrap_python_command_in_venv(command)
        if command != original_command.removesuffix('&'):
            print(f"[Isolation] 🐍 Python command will use venv")
    
    stdout_log = create_unique_logfile("stdout")
    stderr_log = create_unique_logfile("stderr")
    work_dir = get_working_directory()

    process = subprocess.Popen(
        command,
        shell=True,
        executable="/bin/bash",
        cwd=work_dir,
        stdout=open(stdout_log, "w", encoding='utf-8'),
        stderr=open(stderr_log, "w", encoding='utf-8'),
        preexec_fn=os.setsid,
        env=os.environ.copy() | env
    )

    background_process_list[process.pid]=process

    time.sleep(5)

    # Get the last 100 lines of both log files and add process info
    tail_output = get_tail_log(stdout_log, stderr_log)
    return (
        f"✅ Background process started successfully!\n"
        f"PID: {process.pid}\n"
        f"Command: {command}\n\n"
        f"{tail_output}\n"
        f"⚠️ Note: Background processes may show minimal initial output.\n"
        f"Verify service is running with:\n"
        f"  - ps aux | grep <process_name>\n"
        f"  - ss -ltnp | grep :<port>\n"
        f"  - curl http://localhost:<port>\n"
    )

def cleanup_background_processes():
    global background_process_list
    global env

    env={}
    
    # 重置命令检测器
    reset_command_detector()

    for pid in list(background_process_list.keys()):
        try:
            # Kill the entire process group
            os.killpg(os.getpgid(pid), signal.SIGTERM)
            print(f"Terminated process group for PID {pid}")
        except:
            # print(f"Process group for PID {pid} not found (already terminated?)")
            pass
        finally:
            # Remove from the list
            del background_process_list[pid]

def create_unique_logfile(suffix: str) -> str:
    """Generate a unique log file in /tmp with a specific suffix."""
    log_filename = f"/tmp/{uuid.uuid4().hex[:5]}_{suffix}.log"
    return log_filename

def get_last_lines(file_path: str, line_count: int = 100):
    """Retrieve the last `line_count` lines from a file."""
    try:
        with open(file_path, "r", encoding='utf-8') as file:
            r=file.readlines()
            return "".join(r[-line_count:]), len(r)
    except Exception as e:
        return f"Error reading log file: {e}"
    
def get_tail_log(stdout_log: str, stderr_log: str):
    last_stdout_lines, stdout_len = get_last_lines(stdout_log, 100)
    last_stderr_lines, stderr_len = get_last_lines(stderr_log, 100)
    return (
        f"LOGS for current command\n"
        f"STDOUT Log File: {stdout_log}\nLast {min(100, stdout_len)} lines out of {stdout_len}:\n{last_stdout_lines}\n\n"
        f"STDERR Log File: {stderr_log}\nLast {min(100, stderr_len)} lines out of {stderr_len}:\n{last_stderr_lines}\n"
    )
    
# @tools.tool
# def get_background_command_logs(pid: int) -> str:
#     """
#     This tool captures any pending logs from a background process's stdout and stderr.

#     :param pid: The pid of the target process.
#     :return: String with the outputs from the process.
#     """
#     print("Trying to get logs for PID: ", pid, "\nProceed? y/N")
#     p = input()
#     if p!='y':
#         return "Unable to execute, permission denied"
#     return capture_outputs(pid, 0)

# def read_from_stream(stream):
#     read = b""
#     while True:
#         data = stream.read(1)
#         if not data:
#             break
#         read += data
#     read = read.decode(errors='ignore')
#     return read

# def capture_outputs(pid: int, timeout: int):
#     if pid not in Ps:
#         return "Process not found, PID: " + str(pid) + "\n"
    
#     p = Ps[pid]
#     reads = [p.stdout.fileno(), p.stderr.fileno()]
#     ret = select.select(reads, [], [], timeout)
#     out = f"Output for process with PID: {pid}\n"
#     for fd in ret[0]:
#         if fd == p.stdout.fileno():
#             read = read_from_stream(p.stdout)
#             out+=('stdout:\n' + read + '\n')
#         if fd == p.stderr.fileno():
#             read = read_from_stream(p.stderr)
#             out+=('stderr:\n' + read + '\n')
#         out += "###\n"
#     if not ret[0]:
#         out += "No new output on stdout/stderr\n"
#     if p.poll() is None:
#         out += "status: Process is still running, you can consider waiting.\n"
#     else:
#         out += f"status: Process exited with code {p.returncode}\n"
#         del Ps[pid]
#     return out

# @tools.tool
# def send_inputs(pid: int, inp: str) -> str:
#     """
#     This tool sends an input to the stdin of the given pid if it is still running.

#     :param pid: The pid of the target process.
#     :param inp: The input to send via stdin.
#     :return: String denoting if the write was succesful or not.
#     """

#     print(f"Trying to write {inp} to {pid}...\nProceed? y/N")
#     p = input()
#     if p!='y':
#         return "Unable to execute, permission denied"
    
#     pid = int(pid)
#     if pid not in Ps:
#         return "Process not found, PID: " + str(pid) + "\n"
#     p = Ps[pid]
#     p.stdin.write(str.encode(inp))
#     p.stdin.flush()
#     return f"###Write to stdin of PID {pid} finished###\n"

# @tools.tool
# def wait(tim: int) -> str:
#     """
#     This tool waits for the given duration in seconds.
#     Can be used when you are waiting for subsequent outputs from a process.
#     Will display outputs from all running processes after the wait.

#     :param tim: Duration in seconds.
#     :return: If wait was successful.
#     """

#     print("Trying to sleep for: ", tim, "\nProceed?")
#     p = input()
#     if p!='y':
#         return "Unable to execute, permission denied"

#     time.sleep(tim)
#     outs = ""
#     for pid in list(Ps.keys()):
#         outs += capture_outputs(pid)

#     return outs