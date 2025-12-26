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

# 导入经验库（懒加载避免循环导入）
def _get_experience_library():
    """懒加载经验库，避免循环导入"""
    from toolbox.experience_library import get_experience_library
    return get_experience_library()

# 全局反思器实例（懒加载）
_mid_exec_reflector: Optional['MidExecutionReflector'] = None
_reflection_enabled: bool = True


# ==================== 智能上下文分析器 ====================
@dataclass
class ContextualInsight:
    """上下文分析结果"""
    issue_type: str  # download_failed, file_corrupted, version_not_exist, etc.
    evidence: str  # 证据描述
    blocking: bool  # 是否应该阻止后续相关命令
    suggestion: str  # 具体建议
    related_files: List[str] = field(default_factory=list)  # 相关文件


class ContextAwareAnalyzer:
    """
    智能上下文感知分析器
    
    分析命令执行的上下文，识别深层问题：
    - curl下载只有9字节 = 下载失败
    - file xxx.zip: ASCII text = 文件不是zip
    - 404 Not Found = URL错误
    - OutputType='Library' = 类库项目，不能 dotnet run
    
    💡 记忆功能说明：
    这个分析器实现了"强制记忆"，与普通的"建议"不同：
    1. 失败模式被记录到 blocking_insights
    2. 后续相同命令会被 should_block_command 强制阻止
    3. Agent 无法绕过这个限制，必须采用新策略
    
    🔄 经验库集成：
    与 ProjectExperienceLibrary 配合，实现：
    1. 从历史任务中学习项目类型经验
    2. 自动识别项目类型并应用对应经验
    3. 跨任务共享失败模式和解决方案
    """
    
    def __init__(self):
        # 累积的上下文记忆
        self.download_history: Dict[str, Dict] = {}  # filename -> {size, type, url, status}
        self.known_bad_urls: set = set()  # 已知失败的URL
        self.known_bad_versions: set = set()  # 已知不存在的版本
        self.blocking_insights: List[ContextualInsight] = []  # 阻止性问题
        
        # 🆕 重复命令失败检测器
        self.command_failure_counts: Dict[str, int] = defaultdict(int)  # 命令模式 -> 失败次数
        self.blocked_command_patterns: set = set()  # 已被阻止的命令模式
        self.MAX_REPEATED_FAILURES = 3  # 超过此次数自动阻止
        
        # 🆕 项目类型检测状态
        self.detected_project_type: Optional[str] = None  # dotnet, python, node, java, go
        self.project_files_detected: List[str] = []  # 检测到的项目文件
        
        # 经验库集成（懒加载）
        self._experience_library = None
    
    @property
    def experience_library(self):
        """懒加载获取经验库"""
        if self._experience_library is None:
            try:
                self._experience_library = _get_experience_library()
            except Exception as e:
                print(f"⚠️ 加载经验库失败: {e}")
                self._experience_library = None
        return self._experience_library
    
    def _proactive_check_dotnet_project(self, command: str) -> Optional[str]:
        """
        主动检测 .NET 项目类型
        
        在执行 dotnet run 之前，检查 .csproj 文件确定项目类型。
        如果是类库项目，直接阻止执行。
        
        返回：阻止原因，或 None 表示允许执行
        """
        # 提取 .csproj 文件路径
        proj_match = re.search(r'--project\s+(\S+\.csproj)', command)
        if not proj_match:
            # 尝试匹配简单格式: dotnet run xxx.csproj
            proj_match = re.search(r'dotnet\s+run\s+.*?(\S+\.csproj)', command, re.IGNORECASE)
        
        if not proj_match:
            return None
        
        csproj_path = proj_match.group(1)
        
        try:
            # 读取 .csproj 文件内容
            content = None
            found_path = None
            
            # 搜索路径列表
            search_paths = [
                csproj_path,  # 原始路径
                os.path.join('/workspaces/submission/src/simulation_environments', csproj_path),
                os.path.join('/tmp', csproj_path),
                os.path.join('.', csproj_path),
            ]
            
            # 搜索包含项目名称的目录
            proj_name = os.path.basename(csproj_path).replace('.csproj', '')
            if proj_name:
                # 在模拟环境目录中搜索
                sim_env_base = '/workspaces/submission/src/simulation_environments'
                try:
                    if os.path.isdir(sim_env_base):
                        for subdir in os.listdir(sim_env_base):
                            potential_path = os.path.join(sim_env_base, subdir, csproj_path)
                            search_paths.append(potential_path)
                except:
                    pass
            
            for path in search_paths:
                if os.path.exists(path):
                    with open(path, 'r', encoding='utf-8') as f:
                        content = f.read()
                    found_path = path
                    break
            
            if content is None:
                return None  # 找不到文件，不阻止
            
            # 检查是否是类库项目
            library_indicators = [
                '<OutputType>Library</OutputType>',
                '<OutputType>library</OutputType>',
                "<OutputType>Library</OutputType>".lower(),
            ]
            
            content_lower = content.lower()
            
            # 检测类库项目
            # 关键：即使是 Web SDK，如果明确设置了 OutputType=Library，也应该阻止
            if '<outputtype>library</outputtype>' in content_lower:
                # 记录到经验库
                if self.experience_library:
                    self.experience_library.identify_project_type("OutputType is 'Library'", command)
                
                return f"""⛔ 主动检测到类库项目！

📊 项目文件分析: {found_path or csproj_path}
   检测到 <OutputType>Library</OutputType>
   这是一个 .NET 类库/NuGet 包，不是可执行程序。

✅ 推荐替代方案：
   1. dotnet test  # 运行单元测试
   2. 创建测试控制台程序引用该库

❌ 阻止执行: {command[:60]}..."""
            
            # 检测是否缺少入口点（没有 Exe 类型且不是 Web SDK）
            if '<outputtype>' not in content_lower:
                # 默认可能是类库（没有明确指定 OutputType）
                if 'microsoft.net.sdk.web' not in content_lower:
                    # 进一步检查是否有 Main 入口
                    # 如果是 classlib 模板，通常没有 OutputType
                    if 'microsoft.net.sdk' in content_lower and 'aspnetcore' not in content_lower:
                        return None  # 不确定，让它尝试
        
        except Exception as e:
            # 读取失败，不阻止
            print(f"⚠️ 主动检测失败: {e}")
            return None
        
        return None
    
    def _proactive_check_npm_project(self) -> Optional[str]:
        """
        主动检测 npm 项目类型
        
        在执行 npm start 之前，检查 package.json 是否有 start 脚本。
        如果没有 start 脚本，直接阻止执行。
        
        返回：阻止原因，或 None 表示允许执行
        """
        import json as json_module
        
        # 常见工作目录
        search_paths = ['.', '/workspaces/submission/src/simulation_environments']
        
        for base_dir in search_paths:
            package_json_path = os.path.join(base_dir, 'package.json')
            if os.path.exists(package_json_path):
                try:
                    with open(package_json_path, 'r', encoding='utf-8') as f:
                        package_data = json_module.load(f)
                    
                    scripts = package_data.get('scripts', {})
                    
                    # 检查是否有 start 脚本
                    if 'start' not in scripts:
                        # 记录到经验库
                        if self.experience_library:
                            self.experience_library.identify_project_type('Missing script: "start"', 'npm start')
                        
                        available_scripts = list(scripts.keys())[:5] if scripts else ['无']
                        
                        return f"""⛔ 主动检测到 npm 库项目！

📊 package.json 分析: {package_json_path}
   没有找到 'start' 脚本
   可用脚本: {', '.join(available_scripts)}

✅ 推荐替代方案：
   1. npm test  # 运行测试
   2. 创建测试 HTML 页面引入该库

❌ 阻止执行: npm start"""
                
                except Exception as e:
                    print(f"⚠️ npm 主动检测失败: {e}")
                    return None
                
                break
        
        return None
    
    # ==================== 🆕 重复失败检测器 ====================
    
    def record_command_failure(self, command: str, error_output: str = "") -> Optional[str]:
        """
        记录命令失败，并检测是否超过重复次数限制
        
        返回：如果超过限制，返回阻止原因；否则返回 None
        """
        # 提取命令模式（去除参数）
        pattern = self._extract_command_pattern(command)
        
        # 记录失败
        self.command_failure_counts[pattern] += 1
        count = self.command_failure_counts[pattern]
        
        print(f"📊 命令失败记录: '{pattern}' 已失败 {count} 次")
        
        # 检查是否超过限制
        if count >= self.MAX_REPEATED_FAILURES:
            self.blocked_command_patterns.add(pattern)
            return f"""⛔ 命令已被自动阻止！

📊 重复失败检测:
   命令模式: {pattern}
   已失败次数: {count}
   最后错误: {error_output[:200] if error_output else '无'}

⚠️ 同一命令反复失败 {self.MAX_REPEATED_FAILURES}+ 次，说明该方法根本不可行。
✅ 请采用完全不同的策略！"""
        
        return None
    
    def _extract_command_pattern(self, command: str) -> str:
        """
        提取命令模式（保留足够的上下文避免误判）
        
        🔧 改进：保留更多上下文，避免将不同命令误判为相同模式
        例如：cd project_a 和 cd project_b 应该是不同的模式
        """
        # 处理复合命令（&& 或 ;）
        if '&&' in command:
            # 取最后一个有意义的命令作为模式
            parts = command.split('&&')
            last_cmd = parts[-1].strip()
            if last_cmd:
                return self._extract_command_pattern(last_cmd)
        
        parts = command.strip().split()
        if not parts:
            return command
        
        base_cmd = parts[0]
        
        # 🔧 修复：cd 命令需要保留目标目录
        if base_cmd == 'cd' and len(parts) > 1:
            target = parts[1]
            # 保留最后两级目录作为模式
            if '/' in target:
                target_parts = target.rstrip('/').split('/')
                target = '/'.join(target_parts[-2:]) if len(target_parts) > 1 else target_parts[-1]
            return f"cd {target}"
        
        # 包管理器命令：保留命令 + 子命令 + 主要包名
        if base_cmd in ['npm', 'yarn', 'pnpm', 'pip', 'pip3', 'composer']:
            if len(parts) >= 3:
                # npm install package-name -> "npm install package"
                return f"{base_cmd} {parts[1]} {parts[2].split('@')[0].split('==')[0][:30]}"
            elif len(parts) >= 2:
                return f"{base_cmd} {parts[1]}"
        
        # 构建工具：保留命令 + 目标
        if base_cmd in ['mvn', 'gradle', 'make', 'cargo']:
            if len(parts) >= 2:
                return f"{base_cmd} {parts[1]}"
        
        # dotnet：保留命令 + 子命令 + 项目文件
        if base_cmd == 'dotnet' and len(parts) >= 2:
            sub_cmd = parts[1]
            if sub_cmd in ['run', 'build', 'test'] and len(parts) >= 3:
                proj = parts[2] if parts[2].endswith('.csproj') else ''
                if proj:
                    return f"dotnet {sub_cmd} {os.path.basename(proj)}"
            return f"dotnet {sub_cmd}"
        
        # curl/wget：保留完整 URL 的主机部分
        if base_cmd in ['curl', 'wget']:
            for part in parts[1:]:
                if part.startswith('http'):
                    # 提取主机名和路径开头
                    import urllib.parse
                    try:
                        parsed = urllib.parse.urlparse(part)
                        return f"{base_cmd} {parsed.netloc}{parsed.path[:30]}"
                    except:
                        pass
            if len(parts) > 1:
                return f"{base_cmd} {parts[1][:50]}"
        
        # 其他命令：保留前两个部分
        if len(parts) >= 2:
            return f"{base_cmd} {parts[1][:50]}"
        
        return base_cmd
    
    def is_command_blocked_by_repetition(self, command: str) -> Optional[str]:
        """检查命令是否因重复失败被阻止"""
        pattern = self._extract_command_pattern(command)
        
        if pattern in self.blocked_command_patterns:
            count = self.command_failure_counts.get(pattern, 0)
            return f"""⛔ 命令已被阻止（重复失败 {count} 次）

📊 命令模式: {pattern}
⚠️ 该命令已多次失败，请使用完全不同的方法！"""
        
        return None
    
    # ==================== 🆕 工具/语言匹配检测器 ====================
    
    def detect_tool_language_mismatch(self, command: str) -> Optional[str]:
        """
        检测是否使用了错误的工具处理项目
        
        例如：
        - 用 pip install 安装 .NET NuGet 包
        - 用 python 运行 .cs/.csproj 文件
        - 用 dotnet 处理 Python 项目
        - 🆕 在 dotnet 项目中使用 pip/python
        """
        cmd_lower = command.lower()
        
        # 🆕 增强：如果已检测到项目类型，检查工具是否匹配
        if self.detected_project_type == 'dotnet':
            # 在 .NET 项目中使用 Python 工具
            if 'pip install' in cmd_lower or 'pip3 install' in cmd_lower:
                return f"""⛔ 项目类型不匹配！

🔍 已检测到: 这是一个 .NET/C# 项目
   检测文件: {', '.join(self.project_files_detected[:3])}

🚨 错误: 您在尝试使用 pip (Python 包管理器)
   命令: {command[:50]}...

✅ .NET 项目的正确方法:
   1. dotnet restore  # 恢复依赖
   2. dotnet build    # 编译
   3. dotnet test     # 测试"""
            
            if ('python ' in cmd_lower or 'python3 ' in cmd_lower) and not 'python -c' in cmd_lower:
                return f"""⛔ 项目类型不匹配！

🔍 已检测到: 这是一个 .NET/C# 项目
   检测文件: {', '.join(self.project_files_detected[:3])}

🚨 错误: 您在尝试使用 Python 执行
   命令: {command[:50]}...

✅ .NET 项目的正确方法:
   1. dotnet build    # 编译
   2. dotnet run      # 运行（如果是可执行项目）
   3. dotnet test     # 运行测试"""
        
        elif self.detected_project_type == 'node':
            # 在 Node 项目中使用 dotnet
            if 'dotnet ' in cmd_lower:
                return f"""⛔ 项目类型不匹配！

🔍 已检测到: 这是一个 Node.js/JavaScript 项目
   检测文件: {', '.join(self.project_files_detected[:3])}

🚨 错误: 您在尝试使用 dotnet (.NET CLI)

✅ Node.js 项目的正确方法:
   1. npm install  # 安装依赖
   2. npm test     # 运行测试"""
        
        # 检测：用 pip 安装 .NET 包（通过命令关键词）
        if 'pip install' in cmd_lower:
            # 检查是否包含 .NET 项目关键词
            dotnet_indicators = ['aspnetcore', 'nuget', '.net', 'microsoft.', 'system.']
            for indicator in dotnet_indicators:
                if indicator in cmd_lower:
                    return f"""⛔ 工具类型错误！

🚨 检测到您在尝试用 pip 安装 .NET 包
   命令: {command[:60]}...
   问题: pip 是 Python 包管理器，不能安装 .NET NuGet 包！

✅ 正确方法:
   1. dotnet restore  # 恢复 NuGet 依赖
   2. dotnet build    # 编译项目
   3. dotnet test     # 运行测试"""
        
        # 检测：用 python 运行 .cs/.csproj 文件
        if 'python ' in cmd_lower or 'python3 ' in cmd_lower:
            if '.cs' in command or '.csproj' in command:
                return f"""⛔ 工具类型错误！

🚨 检测到您在尝试用 Python 运行 C# 文件
   命令: {command[:60]}...
   问题: .cs 是 C# 源文件，不能用 Python 执行！

✅ 正确方法:
   1. dotnet build xxx.csproj  # 编译 C# 项目
   2. dotnet test              # 运行测试
   3. dotnet run               # 运行可执行项目"""
        
        # 检测：用 npm/node 处理 .NET 项目
        if 'npm ' in cmd_lower or 'node ' in cmd_lower:
            if '.csproj' in command or 'dotnet' in cmd_lower:
                return f"""⛔ 工具类型错误！

🚨 检测到您在尝试用 Node.js 处理 .NET 项目
   命令: {command[:60]}...
   问题: npm/node 是 JavaScript 工具，不能处理 .NET 项目！

✅ 正确方法:
   1. dotnet restore && dotnet build
   2. dotnet test"""
        
        # 检测：用 dotnet 处理 Python 项目
        if 'dotnet ' in cmd_lower:
            if '.py' in command or 'setup.py' in command or 'requirements.txt' in command:
                return f"""⛔ 工具类型错误！

🚨 检测到您在尝试用 dotnet 处理 Python 项目
   命令: {command[:60]}...
   问题: dotnet 是 .NET CLI，不能处理 Python 项目！

✅ 正确方法:
   1. pip install -r requirements.txt  # 安装依赖
   2. python setup.py install          # 安装包
   3. pytest                            # 运行测试"""
        
        return None
    
    def detect_project_type_from_files(self, target_project_dir: Optional[str] = None) -> Optional[str]:
        """
        从目标项目目录的文件检测项目类型
        
        ⚠️ 重要修复 (CVE-2024-32873): 只在目标项目目录检测，排除框架自身文件！
        之前的BUG：扫描到 agentlib/setup.py 导致 Go 项目被误判为 Python 项目
        
        返回: 'dotnet', 'python', 'node', 'java', 'go' 或 None
        
        Args:
            target_project_dir: 目标项目目录（可选），如果不指定则使用 simulation_environments
        """
        # 🔴 P0修复: 只在目标项目目录下检测，不扫描框架自身目录
        # 之前的问题：'.' 会扫描到 agentlib/setup.py，导致 Go 项目被误判为 Python
        search_dirs = []
        
        # 优先使用指定的目标项目目录
        if target_project_dir and os.path.isdir(target_project_dir):
            search_dirs.append(target_project_dir)
        
        # 只搜索 simulation_environments 下的目录（目标项目所在位置）
        sim_env_base = '/workspaces/submission/src/simulation_environments'
        if os.path.isdir(sim_env_base):
            search_dirs.append(sim_env_base)
        
        # ⚠️ 不再扫描当前目录 '.'，避免扫描到框架自身的 agentlib/setup.py
        
        # 需要排除的目录（框架自身的目录）
        excluded_dirs = {
            'agentlib',
            'src/agentlib',
            '/workspaces/submission/src/agentlib',
            'toolbox',
            'agents',
            'prompts',
            'orchestrator',
            'planner',
        }
        
        # 文件类型 -> 项目类型映射
        file_type_map = {
            '.csproj': 'dotnet',
            '.sln': 'dotnet',
            '.cs': 'dotnet',
            'package.json': 'node',
            'requirements.txt': 'python',
            'setup.py': 'python',
            'pyproject.toml': 'python',
            'pom.xml': 'java',
            'build.gradle': 'java',
            'go.mod': 'go',
        }
        
        detected_files = []
        detected_type = None
        type_votes = {}  # 多数投票，解决歧义
        
        for base_dir in search_dirs:
            if not os.path.isdir(base_dir):
                continue
            
            # 🔴 检查是否在排除列表中
            normalized_base = os.path.normpath(base_dir)
            if any(excl in normalized_base for excl in excluded_dirs):
                continue
                
            try:
                # 检查根目录
                for entry in os.listdir(base_dir):
                    entry_path = os.path.join(base_dir, entry)
                    
                    # 🔴 跳过框架自身的目录
                    if entry in excluded_dirs:
                        continue
                    
                    # 直接文件检查
                    for pattern, proj_type in file_type_map.items():
                        if entry.endswith(pattern) or entry == pattern:
                            detected_files.append(entry)
                            type_votes[proj_type] = type_votes.get(proj_type, 0) + 1
                            if detected_type is None:
                                detected_type = proj_type
                    
                    # 子目录检查（只检查一层）
                    if os.path.isdir(entry_path):
                        # 🔴 跳过框架自身的子目录
                        if entry in excluded_dirs:
                            continue
                        try:
                            for sub_entry in os.listdir(entry_path):
                                for pattern, proj_type in file_type_map.items():
                                    if sub_entry.endswith(pattern) or sub_entry == pattern:
                                        detected_files.append(os.path.join(entry, sub_entry))
                                        type_votes[proj_type] = type_votes.get(proj_type, 0) + 1
                                        if detected_type is None:
                                            detected_type = proj_type
                        except:
                            pass
            except:
                pass
        
        # 🔴 使用多数投票来确定最终类型（解决歧义）
        if type_votes:
            # go.mod 优先于 setup.py（Go项目优先级更高，因为很多项目可能有setup.py但实际是其他语言）
            priority_order = ['go', 'dotnet', 'java', 'node', 'python']
            for priority_type in priority_order:
                if priority_type in type_votes:
                    detected_type = priority_type
                    break
        
        if detected_type:
            self.detected_project_type = detected_type
            self.project_files_detected = detected_files[:5]  # 只保留前5个
            print(f"🔍 自动检测到项目类型: {detected_type} (文件: {', '.join(detected_files[:3])}...)")
        
        return detected_type
    
    def analyze_curl_wget_output(self, command: str, output: str, exit_code: int) -> Optional[ContextualInsight]:
        """
        分析 curl/wget 下载命令的输出
        
        关键检测：
        - 下载大小过小（< 100 bytes 通常是错误页面）
        - 404 Not Found
        - Connection refused
        - 即使 exit_code=0 也检测文件大小！（GitHub返回的"Not Found"页面会导致curl成功但内容无效）
        """
        # 提取下载的文件名和URL
        filename = None
        url = None
        
        # curl -o filename URL 或 curl -L -o filename URL
        match = re.search(r'curl\s+.*?-o\s+(\S+)\s+(https?://\S+)', command)
        if match:
            filename = match.group(1)
            url = match.group(2)
        else:
            # wget URL 或 wget -O filename URL
            match = re.search(r'wget\s+.*?(?:-O\s+(\S+)\s+)?(https?://\S+)', command)
            if match:
                url = match.group(2)
                filename = match.group(1) or (url.split('/')[-1] if url else None)
        
        if not url:
            return None
        
        # 🔴 关键修复：即使 exit_code=0 也检测下载文件大小
        # curl 的 progress 格式：100     9  100     9 表示下载了9字节
        # 这种格式意味着 100% 完成，但只有 9 字节
        size_patterns = [
            r'100\s+(\d+)\s+100\s+\d+',  # curl 标准格式
            r'(\d+)\s+\d+%\s+\d+',       # wget 格式
        ]
        
        for pattern in size_patterns:
            size_match = re.search(pattern, output)
            if size_match:
                size = int(size_match.group(1))
                # 🔴 核心检测：任何 < 1000 字节的下载都可能是错误页面
                # GitHub 的 "Not Found" 页面通常只有 9 字节
                if size < 1000:  # 扩大阈值，任何小于1KB的zip下载几乎肯定失败
                    self.known_bad_urls.add(url)
                    
                    # 提取可能的仓库信息用于 git clone 建议
                    repo_match = re.search(r'github\.com/([^/]+/[^/]+)', url)
                    git_suggestion = ""
                    if repo_match:
                        repo_path = repo_match.group(1)
                        git_suggestion = f"\n   推荐命令: git clone https://github.com/{repo_path}.git"
                    
                    insight = ContextualInsight(
                        issue_type='download_failed',
                        evidence=f"⚠️ 下载文件 '{filename}' 只有 {size} 字节！这不是有效的文件（GitHub 返回了错误页面而非实际内容）",
                        blocking=True,
                        suggestion=f"🛑 停止下载尝试！URL 返回了错误页面而非文件。{git_suggestion}\n   或使用: git clone --depth 1 <repo_url>  然后 git checkout <version>",
                        related_files=[filename] if filename else []
                    )
                    self.blocking_insights.append(insight)
                    if filename:
                        self.download_history[filename] = {
                            'size': size, 
                            'status': 'failed', 
                            'url': url,
                            'reason': f'下载只有{size}字节，是错误页面而非实际文件'
                        }
                    return insight
                break
        
        # 检测404错误
        if '404' in output or 'Not Found' in output:
            self.known_bad_urls.add(url)
            # 尝试提取版本号
            version_match = re.search(r'v?(\d+\.\d+\.\d+)', url)
            if version_match:
                self.known_bad_versions.add(version_match.group(1))
            
            # 提取仓库信息
            repo_match = re.search(r'github\.com/([^/]+/[^/]+)', url)
            git_suggestion = ""
            if repo_match:
                git_suggestion = f" 使用 git clone https://github.com/{repo_match.group(1)}.git 替代"
            
            insight = ContextualInsight(
                issue_type='url_not_found',
                evidence=f"URL返回404错误: {url}",
                blocking=True,
                suggestion=f"该URL不存在。{git_suggestion}\n或先 git clone 仓库，再 git tag -l 查看可用版本",
                related_files=[filename] if filename else []
            )
            self.blocking_insights.append(insight)
            return insight
        
        # 下载成功，记录（但只有文件大小足够大时才认为成功）
        if exit_code == 0 and filename:
            self.download_history[filename] = {'status': 'success', 'url': url}
        
        return None
    
    def analyze_file_command_output(self, command: str, output: str) -> Optional[ContextualInsight]:
        """
        分析 file 命令的输出，检测文件类型是否正确
        并自动将无效文件记录到黑名单，阻止后续 unzip
        """
        # file xxx.zip: ASCII text
        match = re.search(r'(\S+\.zip):\s*(.*)', output)
        if match:
            filename = match.group(1)
            file_type = match.group(2).lower()
            
            # 如果zip文件不是实际的zip格式
            if 'zip' not in file_type and 'archive' not in file_type:
                # 🔴 关键：立即记录到下载历史，阻止后续 unzip
                self.download_history[filename] = {
                    'status': 'not_zip', 
                    'type': file_type,
                    'reason': f'file命令检测到实际类型是: {file_type}'
                }
                
                insight = ContextualInsight(
                    issue_type='file_corrupted',
                    evidence=f"🚨 文件 '{filename}' 不是有效的ZIP文件！\n   file命令检测到实际类型是: {file_type}",
                    blocking=True,
                    suggestion=f"🛑 立即停止！不要继续尝试 unzip '{filename}'！\n   这个文件下载失败或损坏。\n   建议：使用 git clone 克隆仓库而不是下载 zip",
                    related_files=[filename]
                )
                self.blocking_insights.append(insight)
                return insight
        
        return None
    
    def analyze_ls_output(self, command: str, output: str) -> Optional[ContextualInsight]:
        """
        分析 ls -la 输出，检测异常小的文件
        
        例如：-rw-r--r-- 1 root root 9 Dec 12 08:36 lunary.zip
        9字节的zip文件明显是无效的
        """
        # 检测 zip/tar.gz 等压缩文件的大小
        # 格式: -rw-r--r-- 1 root root   9 Dec 12 08:36 lunary.zip
        file_pattern = r'-[rwx-]+\s+\d+\s+\w+\s+\w+\s+(\d+)\s+\w+\s+\d+\s+[\d:]+\s+(\S+\.(?:zip|tar\.gz|tgz|tar|gz))'
        
        tiny_files = []
        for match in re.finditer(file_pattern, output, re.IGNORECASE):
            size = int(match.group(1))
            filename = match.group(2)
            
            # 小于 1000 字节的压缩文件几乎肯定是无效的
            if size < 1000:
                tiny_files.append((filename, size))
                # 记录到下载历史，阻止后续 unzip
                self.download_history[filename] = {
                    'status': 'failed', 
                    'size': size,
                    'reason': f'ls检测到文件只有{size}字节'
                }
        
        if tiny_files:
            file_list = ', '.join([f"'{f}'({s}字节)" for f, s in tiny_files])
            insight = ContextualInsight(
                issue_type='tiny_archive_detected',
                evidence=f"⚠️ 发现异常小的压缩文件: {file_list}\n   正常的源码压缩包应该至少有几KB",
                blocking=True,
                suggestion=f"这些文件下载失败（可能是GitHub返回的错误页面）。\n   🛑 不要尝试 unzip 这些文件！\n   建议：rm {' '.join([f[0] for f in tiny_files])} && git clone <repo_url>",
                related_files=[f[0] for f in tiny_files]
            )
            self.blocking_insights.append(insight)
            return insight
        
        return None
    
    def analyze_unzip_output(self, command: str, output: str, exit_code: int) -> Optional[ContextualInsight]:
        """
        分析 unzip 命令的输出
        """
        # 提取文件名
        match = re.search(r'unzip\s+(?:-\w+\s+)*(\S+)', command)
        if not match:
            return None
        
        filename = match.group(1)
        
        # 检查是否是已知的损坏文件
        if filename in self.download_history:
            history = self.download_history[filename]
            if history.get('status') in ['failed', 'corrupted']:
                insight = ContextualInsight(
                    issue_type='unzip_known_bad_file',
                    evidence=f"尝试解压已知无效的文件 '{filename}'（之前的下载已失败）",
                    blocking=True,
                    suggestion=f"⚠️ 停止！这个文件 '{filename}' 已被检测为无效。请：1) 删除它 (rm {filename}) 2) 使用 git clone 替代下载zip 3) 检查正确的版本号和URL",
                    related_files=[filename]
                )
                return insight
        
        # 检查 unzip 错误类型
        if 'End-of-central-directory signature not found' in output:
            insight = ContextualInsight(
                issue_type='file_not_zip',
                evidence=f"'{filename}' 不是有效的ZIP文件（缺少ZIP文件头）",
                blocking=True,
                suggestion=f"⚠️ 这个文件不是ZIP格式！可能原因：1) 下载URL返回了错误页面而非文件 2) 下载被重定向 3) 版本号不存在。解决方案：使用 git clone 直接克隆仓库",
                related_files=[filename]
            )
            self.blocking_insights.append(insight)
            self.download_history[filename] = {'status': 'not_zip'}
            return insight
        
        return None
    
    def analyze_dotnet_output(self, command: str, output: str, exit_code: int) -> Optional[ContextualInsight]:
        """
        分析 dotnet 命令输出，检测类库项目等问题
        
        通用检测：
        - OutputType='Library' 表示项目是类库，不能用 dotnet run 启动
        - 这类项目需要创建测试程序或使用 dotnet test
        
        经验库集成：
        - 自动识别项目类型并加载对应经验
        - 使用历史经验增强建议
        """
        combined = output + (command if command else '')
        
        # 检测 .NET Library 项目（无法用 dotnet run 运行）
        if "OutputType is 'Library'" in output or "The current OutputType is 'Library'" in output:
            # 从命令中提取项目路径
            proj_match = re.search(r'--project\s+(\S+\.csproj)', command)
            project_name = proj_match.group(1) if proj_match else "unknown"
            
            # 🔄 使用经验库识别项目类型并获取建议
            advice = ""
            if self.experience_library:
                self.experience_library.identify_project_type(output, command)
                advice = self.experience_library.get_current_advice() or ""
                # 记录经验到经验库
                self.experience_library.record_experience("dotnet", "library", {
                    "command": "dotnet run",
                    "success": False,
                    "error": "OutputType is 'Library'",
                    "lesson": "类库项目不能用 dotnet run 启动，应使用 dotnet test"
                })
            
            # 优先使用经验库建议，否则使用默认建议
            default_suggestion = """🛑 这是一个类库/NuGet包项目，不是 Web 应用！

   对于此类漏洞，需要采用不同的复现策略：
   1. 【推荐】使用 dotnet test 运行现有单元测试
   2. 创建一个测试控制台程序引用该库并触发漏洞
   3. 如果漏洞是逻辑问题（如参数验证缺陷），需要编写代码测试
   
   ❌ 不要继续尝试 'dotnet run' 命令
   ✅ 运行: dotnet test 或创建测试程序"""
            
            insight = ContextualInsight(
                issue_type='library_project_detected',
                evidence=f"🚨 检测到 .NET 类库项目！\n   项目 '{project_name}' 的 OutputType='Library'，不是可执行程序。\n   类库项目不能用 'dotnet run' 启动。",
                blocking=True,
                suggestion=advice if advice else default_suggestion,
                related_files=[project_name]
            )
            self.blocking_insights.append(insight)
            return insight
        
        # 检测 dotnet run 失败但没有 runnable 项目
        if 'Ensure you have a runnable project type' in output:
            insight = ContextualInsight(
                issue_type='not_runnable_project',
                evidence="项目不是可执行类型（缺少 Main 入口点或 OutputType 不是 'Exe'）",
                blocking=True,
                suggestion="""这个项目不能直接运行。可能的原因：
   1. 这是一个类库项目（需要创建测试程序）
   2. 缺少 Main 方法入口点
   3. 这是一个 NuGet 包而非 Web 应用
   
   解决方案：使用 dotnet test 或创建引用该库的测试程序""",
                related_files=[]
            )
            self.blocking_insights.append(insight)
            return insight
        
        return None
    
    def analyze_npm_yarn_output(self, command: str, output: str, exit_code: int) -> Optional[ContextualInsight]:
        """
        分析 npm/yarn 命令输出，检测库项目问题
        经验库集成：自动识别项目类型并记录经验
        """
        combined = output + (command if command else '')
        
        # 检测 npm 库项目（没有 start 脚本）
        if 'Missing script: "start"' in output or 'missing script: start' in output.lower():
            # 🔄 记录经验到经验库
            if self.experience_library:
                self.experience_library.identify_project_type(output, command)
                self.experience_library.record_experience("node", "library", {
                    "command": "npm start",
                    "success": False,
                    "error": 'Missing script: "start"',
                    "lesson": "npm 库项目没有 start 脚本，应使用 npm test"
                })
            
            advice = self.experience_library.get_current_advice() if self.experience_library else None
            default_suggestion = """这是一个 npm 库/包，不是可运行的 Web 应用！
   
   对于此类漏洞：
   1. 使用 npm test 运行现有测试
   2. 创建测试 HTML 页面引入该库并触发漏洞
   3. 查看 package.json 中的 scripts 部分找可用命令
   
   ❌ 不要继续尝试 npm start"""
            
            insight = ContextualInsight(
                issue_type='npm_library_project',
                evidence="检测到 npm 库项目：没有 'start' 脚本",
                blocking=True,
                suggestion=advice if advice else default_suggestion,
                related_files=['package.json']
            )
            self.blocking_insights.append(insight)
            return insight
        
        return None
    
    def analyze_python_output(self, command: str, output: str, exit_code: int) -> Optional[ContextualInsight]:
        """
        分析 Python 命令输出，检测库项目问题
        """
        # 检测纯 Python 库（没有 web 入口点）
        if 'No module named' in output and any(x in command.lower() for x in ['flask', 'django', 'uvicorn', 'gunicorn']):
            lib_match = re.search(r"No module named '([^']+)'", output)
            lib_name = lib_match.group(1) if lib_match else 'unknown'
            
            # 判断是否是 web 框架问题
            if lib_name in ['flask', 'django', 'uvicorn', 'gunicorn', 'starlette', 'fastapi']:
                insight = ContextualInsight(
                    issue_type='python_library_project',
                    evidence=f"缺少 Web 框架 '{lib_name}'，可能这是一个纯 Python 库而非 Web 应用",
                    blocking=False,  # 只是警告，不阻止
                    suggestion=f"""检测到可能的 Python 库项目。如果这是一个库：
   1. 使用 pytest/python -m pytest 运行测试
   2. 创建测试脚本 import 该库并触发漏洞
   3. 如果确实是 Web 应用，运行: pip install {lib_name}""",
                    related_files=[]
                )
                self.blocking_insights.append(insight)
                return insight
        
        return None
    
    def analyze_command(self, command: str, output: str, exit_code: int) -> Optional[ContextualInsight]:
        """
        分析任意命令，返回上下文洞察
        """
        cmd_lower = command.lower().strip()
        
        # curl 或 wget 下载命令
        if 'curl' in cmd_lower or 'wget' in cmd_lower:
            return self.analyze_curl_wget_output(command, output, exit_code)
        
        # file 命令
        if cmd_lower.startswith('file '):
            return self.analyze_file_command_output(command, output)
        
        # ls 命令 - 检测异常小的压缩文件
        if cmd_lower.startswith('ls '):
            return self.analyze_ls_output(command, output)
        
        # unzip 命令
        if 'unzip' in cmd_lower:
            return self.analyze_unzip_output(command, output, exit_code)
        
        # dotnet 命令 - 检测类库项目
        if 'dotnet' in cmd_lower:
            return self.analyze_dotnet_output(command, output, exit_code)
        
        # npm/yarn 命令 - 检测 npm 库项目
        if 'npm' in cmd_lower or 'yarn' in cmd_lower:
            return self.analyze_npm_yarn_output(command, output, exit_code)
        
        # python/pip 命令 - 检测 Python 库项目
        if 'python' in cmd_lower or 'pip' in cmd_lower:
            return self.analyze_python_output(command, output, exit_code)
        
        return None
    
    def should_block_command(self, command: str) -> Optional[str]:
        """
        检查是否应该阻止执行某个命令
        
        检查顺序：
        0. 🆕 自动检测项目类型（从文件系统）
        1. 工具/语言匹配：检查是否用错误工具处理项目
        2. 重复失败：同一命令失败超过N次自动阻止
        3. 主动检测：对于 dotnet run，检查 .csproj 文件确定项目类型
        4. 经验库：根据历史经验预先阻止已知会失败的命令
        5. 当前会话记忆：根据本次任务中的失败记录阻止
        
        返回阻止原因，或 None 表示允许执行
        """
        cmd_lower = command.lower()
        
        # 🆕 步骤 0：如果还没检测项目类型，主动检测（只检测一次）
        if self.detected_project_type is None:
            self.detect_project_type_from_files()
        
        # 🆕 工具/语言匹配检测（防止用 pip 安装 .NET 包等）
        mismatch_block = self.detect_tool_language_mismatch(command)
        if mismatch_block:
            return mismatch_block
        
        # 🆕 重复失败检测（同一命令失败超过N次自动阻止）
        repetition_block = self.is_command_blocked_by_repetition(command)
        if repetition_block:
            return repetition_block
        
        # 🚨 主动检测：在执行 dotnet run 前检查项目文件
        if 'dotnet run' in cmd_lower:
            proactive_block = self._proactive_check_dotnet_project(command)
            if proactive_block:
                return proactive_block
        
        # 🚨 主动检测：在执行 npm start 前检查 package.json
        if 'npm start' in cmd_lower or 'npm run start' in cmd_lower:
            proactive_block = self._proactive_check_npm_project()
            if proactive_block:
                return proactive_block
        
        # 🔄 检查经验库（跨任务的历史经验）
        if self.experience_library:
            block_reason = self.experience_library.should_block_based_on_experience(command)
            if block_reason:
                return block_reason
        
        # 检查是否尝试解压已知损坏的文件
        if 'unzip' in cmd_lower:
            match = re.search(r'unzip\s+(?:-\w+\s+)*(\S+)', command)
            if match:
                filename = match.group(1)
                if filename in self.download_history:
                    status = self.download_history[filename].get('status')
                    if status in ['failed', 'corrupted', 'not_zip']:
                        return f"⛔ 阻止执行：文件 '{filename}' 已被检测为无效（{status}）。请使用 git clone 替代下载zip方式。"
        
        # 检查是否尝试下载已知失败的URL
        for bad_url in self.known_bad_urls:
            if bad_url in command:
                return f"⛔ 阻止执行：URL '{bad_url[:50]}...' 之前下载失败。请检查正确的版本或使用其他方式获取代码。"
        
        # 检查是否已检测到类库项目，阻止继续尝试 dotnet run / npm start
        for insight in self.blocking_insights:
            if insight.issue_type == 'library_project_detected' and 'dotnet run' in cmd_lower:
                return f"⛔ 阻止执行：已检测到这是 .NET 类库项目（OutputType='Library'）\n   请改用 'dotnet test' 或创建测试程序而不是继续尝试 'dotnet run'"
            
            if insight.issue_type == 'not_runnable_project' and 'dotnet run' in cmd_lower:
                return f"⛔ 阻止执行：项目不是可执行类型\n   请改用 'dotnet test' 或创建测试程序"
            
            if insight.issue_type == 'npm_library_project' and ('npm start' in cmd_lower or 'npm run start' in cmd_lower):
                return f"⛔ 阻止执行：已检测到这是 npm 库项目（没有 start 脚本）\n   请改用 'npm test' 或创建测试页面"
        
        return None
    
    def get_accumulated_insights(self) -> str:
        """
        获取累积的上下文洞察摘要
        """
        if not self.blocking_insights:
            return ""
        
        summary = "\n📊 累积的问题分析：\n"
        for i, insight in enumerate(self.blocking_insights[-3:], 1):  # 最近3个
            summary += f"  {i}. [{insight.issue_type}] {insight.evidence[:80]}...\n"
        
        return summary
    
    def reset(self):
        """重置分析器状态"""
        self.download_history.clear()
        self.known_bad_urls.clear()
        self.known_bad_versions.clear()
        self.blocking_insights.clear()
        
        # 🆕 重置重复失败检测器
        self.command_failure_counts.clear()
        self.blocked_command_patterns.clear()
        
        # 🆕 重置项目类型检测
        self.detected_project_type = None
        self.project_files_detected.clear()
        
        # 🔄 重置经验库会话（保留持久化经验）
        if self.experience_library:
            self.experience_library.reset_current_session()


# 全局上下文分析器
_context_analyzer: Optional[ContextAwareAnalyzer] = None


def get_context_analyzer() -> ContextAwareAnalyzer:
    """获取或创建全局上下文分析器"""
    global _context_analyzer
    if _context_analyzer is None:
        _context_analyzer = ContextAwareAnalyzer()
    return _context_analyzer


def reset_context_analyzer():
    """重置上下文分析器"""
    global _context_analyzer
    if _context_analyzer:
        _context_analyzer.reset()


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
        
        增强版：集成上下文感知分析器，提供更智能的建议
        """
        self.total_commands += 1
        is_failure = exit_code != 0
        
        if is_failure:
            self.total_failures += 1
        
        # 🔍 步骤1：使用上下文分析器分析命令输出
        context_analyzer = get_context_analyzer()
        context_insight = context_analyzer.analyze_command(command, output, exit_code)
        
        # 如果发现上下文问题，生成更智能的干预消息
        if context_insight and context_insight.blocking:
            return self._generate_contextual_intervention(context_insight)
        
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
            # 🆕 尝试从上下文分析器获取更具体的建议
            accumulated_insights = context_analyzer.get_accumulated_insights()
            error_suggestion = self._extract_error_suggestion(output)
            
            # 如果有上下文洞察，优先使用
            if accumulated_insights:
                error_suggestion = accumulated_insights + "\n" + (error_suggestion or "")
            
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
    
    def _generate_contextual_intervention(self, insight: 'ContextualInsight') -> str:
        """
        根据上下文洞察生成更智能的干预消息
        """
        # 根据问题类型选择图标
        icon_map = {
            'download_failed': '⬇️',
            'url_not_found': '🔗',
            'file_corrupted': '📄',
            'file_not_zip': '📦',
            'unzip_known_bad_file': '⚠️'
        }
        icon = icon_map.get(insight.issue_type, '❗')
        
        msg = f"""
╔══════════════════════════════════════════════════════════════════╗
║ {icon} 智能上下文分析 - 检测到根本问题                             ║
╠══════════════════════════════════════════════════════════════════╣
║ 🔍 问题类型: {insight.issue_type:<52} ║
╠══════════════════════════════════════════════════════════════════╣
║ 📝 证据:                                                               ║"""
        
        # 将证据分成多行
        evidence_lines = [insight.evidence[i:i+62] for i in range(0, len(insight.evidence), 62)]
        for line in evidence_lines[:3]:
            msg += f"\n║   {line:<62} ║"
        
        msg += f"""
╠══════════════════════════════════════════════════════════════════╣
║ 💡 解决方案:                                                           ║"""
        
        # 将建议分成多行
        suggestion_lines = [insight.suggestion[i:i+62] for i in range(0, len(insight.suggestion), 62)]
        for line in suggestion_lines[:4]:
            msg += f"\n║   {line:<62} ║"
        
        msg += f"""
╠══════════════════════════════════════════════════════════════════╣
║ 🚫 不要继续尝试相同的方法！请采用上述解决方案。              ║
╚══════════════════════════════════════════════════════════════════╝"""
        
        return msg
    
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
    """重置命令检测器和上下文分析器"""
    global _command_detector
    if _command_detector:
        _command_detector.reset()
    # 同时重置上下文分析器
    reset_context_analyzer()


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
    
    # 回调超时时间 - 根据命令类型动态调整
    # npm install / yarn install / composer install 等安装命令需要更长时间
    cmd_lower = command.lower()
    if any(x in cmd_lower for x in ['npm install', 'yarn install', 'pnpm install', 'composer install', 'pip install -r', 'bundle install', 'cargo build', 'mvn install', 'gradle build']):
        # 大型项目安装可能需要 10-15 分钟
        timeout = 900  # 15 分钟
        print(f"🕒 Using extended timeout ({timeout}s) for package installation...")
    elif any(x in cmd_lower for x in ['git clone', 'docker pull', 'docker build']):
        timeout = 600  # 10 分钟
    else:
        timeout = 300  # 5 分钟（默认）
    
    # 🚫 步骤 0：检查是否应该阻止执行这个命令（基于之前的失败记忆）
    context_analyzer = get_context_analyzer()
    block_reason = context_analyzer.should_block_command(command)
    if block_reason:
        print(f"\n⛔ 命令被智能分析器阻止: {command[:50]}...")
        return f"""
╔══════════════════════════════════════════════════════════════════╗
║ ⛔ 命令已被阻止执行                                                  ║
╠══════════════════════════════════════════════════════════════════╣
║ 原因: {block_reason[:58]:<58} ║
╠══════════════════════════════════════════════════════════════════╣
║ 此命令之前已失败，并且根本原因已被识别。                      ║
║ 请采用不同的方法，不要继续尝试同样的失败操作！                  ║
╚══════════════════════════════════════════════════════════════════╝
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
                timeout=timeout,
                errors="ignore",
                env=os.environ.copy() | env
            )
            exit_code = result.returncode
    except subprocess.TimeoutExpired:
        exit_code = 124  # 标准的超时退出码
        timeout_occurred = True
        output = f"❌ Timed out after {timeout}s! Command: {original_command}"
        
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
    
    # 🆕 命令失败时，记录到 ContextAwareAnalyzer 的重复失败检测器
    if exit_code != 0:
        block_msg = context_analyzer.record_command_failure(original_command, tail_output)
        if block_msg:
            # 如果超过重复次数，返回阻止消息
            return f"""
╭──────────────────────────────────────────────────────────────────╮
│ 🛑 重复失败检测触发！同一命令已失败多次                        │
├──────────────────────────────────────────────────────────────────┤
{block_msg}
├──────────────────────────────────────────────────────────────────┤
│ ❗ 此命令已被自动阻止，后续相同命令将不再执行               │
│ ✅ 请采用完全不同的策略！                                      │
╰──────────────────────────────────────────────────────────────────╯
"""
    
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
    
    # 🆕 关键修复：即使 exit_code == 0，对于下载命令也要分析是否真正成功
    # curl/wget 可能返回 0 但下载的是错误页面（如 GitHub 404 页面）
    if exit_code == 0 and any(x in cmd_lower for x in ['curl', 'wget']):
        insight = context_analyzer.analyze_curl_wget_output(original_command, tail_output, exit_code)
        if insight and insight.blocking:
            # 下载虽然"成功"但实际是错误页面
            output = output + f"\n\n" + f"""
╔══════════════════════════════════════════════════════════════════╗
║ ⚠️ 下载验证失败 - 文件内容无效                                    ║
╠══════════════════════════════════════════════════════════════════╣
║ {insight.evidence[:60]:<60} ║
╠══════════════════════════════════════════════════════════════════╣
║ {insight.suggestion[:60]:<60} ║
╠══════════════════════════════════════════════════════════════════╣
║ 💡 后续对此文件的操作（如 unzip）将被自动阻止              ║
╚══════════════════════════════════════════════════════════════════╝
"""
    
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
    
    # 🚨 步骤 0：检查是否应该阻止执行这个命令（基于之前的失败记忆）
    context_analyzer = get_context_analyzer()
    block_reason = context_analyzer.should_block_command(command)
    if block_reason:
        print(f"\n⛔ 后台命令被智能分析器阻止: {command[:50]}...")
        return f"""
╔══════════════════════════════════════════════════════════════════╗
║ ⛔ 后台命令已被阻止执行                                              ║
╠══════════════════════════════════════════════════════════════════╣
║ 原因: {block_reason[:58]:<58} ║
╠══════════════════════════════════════════════════════════════════╣
║ 这是一个类库项目，无法用此命令启动。                          ║
║ 请改用 dotnet test 或创建测试程序来复现漏洞。                    ║
╚══════════════════════════════════════════════════════════════════╝
"""
    
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

def get_last_lines(file_path: str, line_count: int = 100, max_chars: int = 15000):
    """
    Retrieve the last `line_count` lines from a file.
    
    🔧 修复 CVE-2024-3651: 添加字符数限制防止 token 超限
    - line_count: 最多返回多少行
    - max_chars: 最多返回多少字符（约 3750 tokens）
    """
    try:
        with open(file_path, "r", encoding='utf-8') as file:
            r = file.readlines()
            lines = r[-line_count:]
            result = "".join(lines)
            
            # 🔧 字符数限制：防止超长输出导致 token 超限
            if len(result) > max_chars:
                result = result[-max_chars:]
                # 找到第一个换行符，从完整行开始
                first_newline = result.find('\n')
                if first_newline > 0:
                    result = result[first_newline + 1:]
                result = f"[... output truncated, showing last {len(result)} chars ...]\n" + result
            
            return result, len(r)
    except Exception as e:
        return f"Error reading log file: {e}", 0
    
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