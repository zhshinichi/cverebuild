"""
类型化项目经验库 (Project Experience Library)

按项目类型 (.NET, Python, Node, Java 等) 收集和应用历史复现经验。

功能：
1. 经验收集：从每次复现任务中学习成功/失败模式
2. 持久化存储：按项目类型保存经验到 JSON 文件
3. 智能应用：在新任务开始时自动加载相关经验，指导命令执行

使用方式：
    from toolbox.experience_library import get_experience_library
    
    library = get_experience_library()
    library.load_project_experience("dotnet")  # 加载 .NET 经验
    
    # 获取启动建议
    suggestion = library.get_startup_advice("dotnet", "library")
    
    # 检查命令是否应该被阻止
    block_reason = library.should_block_based_on_experience("dotnet run", "dotnet", "library")
    
    # 记录新经验
    library.record_experience("dotnet", "library", {
        "command": "dotnet run",
        "success": False,
        "error": "OutputType is 'Library'",
        "lesson": "类库项目不能用 dotnet run 启动"
    })
"""

import json
import os
from datetime import datetime
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field, asdict
from pathlib import Path


# ==================== 数据结构定义 ====================

@dataclass
class CommandExperience:
    """单条命令经验"""
    command_pattern: str  # 命令模式 (如 "dotnet run", "npm start")
    success_count: int = 0
    failure_count: int = 0
    common_errors: List[str] = field(default_factory=list)  # 常见错误消息
    solutions: List[str] = field(default_factory=list)  # 解决方案
    alternatives: List[str] = field(default_factory=list)  # 替代命令
    should_avoid: bool = False  # 是否应该避免这个命令
    avoid_reason: str = ""  # 避免原因


@dataclass
class ProjectTypeExperience:
    """单个项目类型的经验"""
    project_type: str  # dotnet, python, node, java, go
    subtype: str  # library, web_app, cli, test
    
    # 经验统计
    total_tasks: int = 0
    successful_tasks: int = 0
    
    # 命令经验
    command_experiences: Dict[str, CommandExperience] = field(default_factory=dict)
    
    # 项目特征识别
    identifying_patterns: List[str] = field(default_factory=list)  # 如 "OutputType='Library'"
    
    # 通用建议
    startup_advice: str = ""  # 启动建议
    common_pitfalls: List[str] = field(default_factory=list)  # 常见陷阱
    
    # 最近更新时间
    last_updated: str = ""


@dataclass
class ExperienceLibrary:
    """完整的经验库"""
    version: str = "1.0"
    created_at: str = ""
    updated_at: str = ""
    
    # 按 project_type -> subtype 组织的经验
    experiences: Dict[str, Dict[str, ProjectTypeExperience]] = field(default_factory=dict)


# ==================== 预设的经验知识库 ====================

# 这些是从已知模式中预先定义的经验
DEFAULT_EXPERIENCES = {
    "dotnet": {
        "library": ProjectTypeExperience(
            project_type="dotnet",
            subtype="library",
            identifying_patterns=[
                "OutputType is 'Library'",
                "The current OutputType is 'Library'",
                "OutputType='Library'",
                ".nupkg",
                "classlib",
            ],
            startup_advice="""🔬 这是 .NET 类库项目，不是可执行程序！

推荐复现策略：
1. 【首选】使用 dotnet test 运行现有单元测试
   命令: dotnet test
   
2. 如果需要验证特定功能，创建测试控制台程序：
   dotnet new console -n VulnTest
   cd VulnTest
   dotnet add reference ../path/to/library.csproj
   # 然后编写测试代码

❌ 禁止使用的命令：
- dotnet run（类库没有入口点）
- dotnet build --run（同上）""",
            common_pitfalls=[
                "尝试用 dotnet run 启动类库",
                "忽略 OutputType='Library' 错误信息",
                "没有检查项目类型就尝试启动",
            ],
            command_experiences={
                "dotnet run": CommandExperience(
                    command_pattern="dotnet run",
                    failure_count=100,  # 高失败率
                    common_errors=["OutputType is 'Library'", "Ensure you have a runnable project type"],
                    solutions=["使用 dotnet test 替代", "创建测试控制台程序"],
                    alternatives=["dotnet test", "创建控制台测试项目"],
                    should_avoid=True,
                    avoid_reason="类库项目没有入口点，无法用 dotnet run 启动"
                ),
            },
        ),
        "web_app": ProjectTypeExperience(
            project_type="dotnet",
            subtype="web_app",
            identifying_patterns=[
                "Microsoft.NET.Sdk.Web",
                "aspnetcore",
                "WebApplication",
            ],
            startup_advice="""🌐 这是 .NET Web 应用

启动命令：
- dotnet run --urls http://0.0.0.0:5000
- 或查看 launchSettings.json 中的端口配置

常用环境变量：
- ASPNETCORE_ENVIRONMENT=Development
- ASPNETCORE_URLS=http://0.0.0.0:5000""",
            common_pitfalls=[
                "忘记指定监听地址（默认只监听 localhost）",
                "端口冲突",
            ],
        ),
    },
    "node": {
        "library": ProjectTypeExperience(
            project_type="node",
            subtype="library",
            identifying_patterns=[
                'Missing script: "start"',
                'missing script: start',
                '"main":',  # 没有 bin 但有 main 说明是库
            ],
            startup_advice="""📦 这是 npm 库/包，不是可运行的 Web 应用！

推荐复现策略：
1. 【首选】运行现有测试
   npm test
   或 npm run test
   
2. 创建测试 HTML 页面引入该库：
   创建 test.html，使用 <script src="node_modules/..."> 引入

3. 创建测试脚本：
   node -e "const lib = require('./'); ..."

❌ 禁止使用的命令：
- npm start（没有 start 脚本）""",
            common_pitfalls=[
                "尝试 npm start 但没有 start 脚本",
                "忽略 'Missing script: start' 错误",
            ],
            command_experiences={
                "npm start": CommandExperience(
                    command_pattern="npm start",
                    failure_count=100,
                    common_errors=['Missing script: "start"'],
                    solutions=["使用 npm test", "创建测试页面"],
                    alternatives=["npm test", "node test.js"],
                    should_avoid=True,
                    avoid_reason="npm 库没有 start 脚本"
                ),
            },
        ),
        "web_app": ProjectTypeExperience(
            project_type="node",
            subtype="web_app",
            identifying_patterns=[
                '"start":',
                "express",
                "koa",
                "fastify",
            ],
            startup_advice="""🌐 这是 Node.js Web 应用

启动命令：
- npm start
- 或 npm run dev（开发模式）
- 或查看 package.json 中的 scripts

常用端口：3000, 8080, 5000""",
        ),
    },
    "python": {
        "library": ProjectTypeExperience(
            project_type="python",
            subtype="library",
            identifying_patterns=[
                "pypi",
                "pip install",
                "setup.py",
                "pyproject.toml",
                "No module named 'flask'",  # 缺少 web 框架暗示这是库
            ],
            startup_advice="""📦 这是 Python 库/包

推荐复现策略：
1. 【首选】运行现有测试
   pytest
   或 python -m pytest
   
2. 创建测试脚本：
   from vulnerable_lib import vulnerable_function
   vulnerable_function(malicious_input)

3. 使用 Python 交互式测试：
   python -c "from lib import ...; ..."

❌ 通常不适用的命令：
- python app.py（如果没有 app.py）
- flask run（如果不是 Flask 应用）""",
            common_pitfalls=[
                "尝试用 flask run 启动非 Flask 库",
                "没有先安装库就尝试导入",
            ],
            command_experiences={
                "flask run": CommandExperience(
                    command_pattern="flask run",
                    common_errors=["No module named 'flask'", "Could not locate a Flask application"],
                    solutions=["使用 pytest 运行测试", "创建测试脚本"],
                    alternatives=["pytest", "python -m pytest", "python test_script.py"],
                    should_avoid=True,
                    avoid_reason="纯 Python 库不是 Flask 应用"
                ),
            },
        ),
        "web_app": ProjectTypeExperience(
            project_type="python",
            subtype="web_app",
            identifying_patterns=[
                "flask",
                "django",
                "fastapi",
                "uvicorn",
            ],
            startup_advice="""🌐 这是 Python Web 应用

启动命令：
- Flask: flask run --host=0.0.0.0 --port=5000
- Django: python manage.py runserver 0.0.0.0:8000
- FastAPI: uvicorn app:app --host 0.0.0.0 --port 8000

环境变量：
- FLASK_APP=app.py
- FLASK_ENV=development""",
        ),
    },
    "java": {
        "library": ProjectTypeExperience(
            project_type="java",
            subtype="library",
            identifying_patterns=[
                "<packaging>jar</packaging>",
                "maven-shade-plugin",
                "no main manifest attribute",
            ],
            startup_advice="""📦 这是 Java 库/JAR 包

推荐复现策略：
1. 【首选】运行单元测试
   mvn test
   或 gradle test
   
2. 创建测试类引用该库

❌ 禁止使用的命令：
- java -jar library.jar（没有 Main-Class）""",
            common_pitfalls=[
                "尝试 java -jar 运行没有主类的 JAR",
            ],
            command_experiences={
                "java -jar": CommandExperience(
                    command_pattern="java -jar",
                    common_errors=["no main manifest attribute"],
                    solutions=["使用 mvn test 运行测试"],
                    alternatives=["mvn test", "gradle test"],
                    should_avoid=True,
                    avoid_reason="库 JAR 没有 Main-Class"
                ),
            },
        ),
    },
    "go": {
        "library": ProjectTypeExperience(
            project_type="go",
            subtype="library",
            identifying_patterns=[
                "package main not found",
                "go: no Go source files",
            ],
            startup_advice="""📦 这是 Go 库/包

推荐复现策略：
1. 【首选】运行测试
   go test ./...
   
2. 创建测试程序引用该库

❌ 通常不适用的命令：
- go run .（如果没有 main 包）""",
            command_experiences={
                "go run": CommandExperience(
                    command_pattern="go run",
                    common_errors=["package main not found"],
                    solutions=["使用 go test 运行测试"],
                    alternatives=["go test ./..."],
                    should_avoid=True,
                    avoid_reason="Go 库没有 main 包"
                ),
            },
        ),
    },
}


# ==================== 经验库管理器 ====================

class ProjectExperienceLibrary:
    """
    项目经验库管理器
    
    负责加载、保存、更新经验，以及根据经验提供建议
    """
    
    # 经验库文件路径
    LIBRARY_DIR = Path(__file__).parent.parent / "data" / "experience_library"
    LIBRARY_FILE = LIBRARY_DIR / "project_experiences.json"
    
    def __init__(self):
        self.library = ExperienceLibrary()
        self._ensure_library_dir()
        self._load_or_init_library()
        
        # 当前任务的项目类型识别结果
        self.current_project_type: Optional[str] = None
        self.current_subtype: Optional[str] = None
    
    def _ensure_library_dir(self):
        """确保经验库目录存在"""
        self.LIBRARY_DIR.mkdir(parents=True, exist_ok=True)
    
    def _load_or_init_library(self):
        """加载已有经验库或初始化默认库"""
        if self.LIBRARY_FILE.exists():
            try:
                with open(self.LIBRARY_FILE, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    self._deserialize_library(data)
                print(f"✅ 已加载经验库: {len(self.library.experiences)} 种项目类型")
            except Exception as e:
                print(f"⚠️ 加载经验库失败: {e}，使用默认经验")
                self._init_default_experiences()
        else:
            self._init_default_experiences()
            self.save()
    
    def _init_default_experiences(self):
        """初始化默认经验库"""
        self.library = ExperienceLibrary(
            created_at=datetime.now().isoformat(),
            updated_at=datetime.now().isoformat(),
        )
        
        # 加载预设经验
        for project_type, subtypes in DEFAULT_EXPERIENCES.items():
            if project_type not in self.library.experiences:
                self.library.experiences[project_type] = {}
            
            for subtype, experience in subtypes.items():
                experience.last_updated = datetime.now().isoformat()
                self.library.experiences[project_type][subtype] = experience
        
        print(f"📚 初始化默认经验库: {len(self.library.experiences)} 种项目类型")
    
    def _deserialize_library(self, data: Dict):
        """从 JSON 数据反序列化经验库"""
        self.library = ExperienceLibrary(
            version=data.get('version', '1.0'),
            created_at=data.get('created_at', ''),
            updated_at=data.get('updated_at', ''),
        )
        
        for project_type, subtypes in data.get('experiences', {}).items():
            self.library.experiences[project_type] = {}
            for subtype, exp_data in subtypes.items():
                # 解析命令经验
                cmd_experiences = {}
                for cmd, cmd_exp in exp_data.get('command_experiences', {}).items():
                    cmd_experiences[cmd] = CommandExperience(**cmd_exp)
                
                exp_data['command_experiences'] = cmd_experiences
                self.library.experiences[project_type][subtype] = ProjectTypeExperience(**exp_data)
    
    def _serialize_experience(self, exp: ProjectTypeExperience) -> Dict:
        """序列化单个项目经验"""
        result = {
            'project_type': exp.project_type,
            'subtype': exp.subtype,
            'total_tasks': exp.total_tasks,
            'successful_tasks': exp.successful_tasks,
            'identifying_patterns': exp.identifying_patterns,
            'startup_advice': exp.startup_advice,
            'common_pitfalls': exp.common_pitfalls,
            'last_updated': exp.last_updated,
            'command_experiences': {},
        }
        
        for cmd, cmd_exp in exp.command_experiences.items():
            result['command_experiences'][cmd] = asdict(cmd_exp)
        
        return result
    
    def save(self):
        """保存经验库到文件"""
        data = {
            'version': self.library.version,
            'created_at': self.library.created_at,
            'updated_at': datetime.now().isoformat(),
            'experiences': {},
        }
        
        for project_type, subtypes in self.library.experiences.items():
            data['experiences'][project_type] = {}
            for subtype, experience in subtypes.items():
                data['experiences'][project_type][subtype] = self._serialize_experience(experience)
        
        with open(self.LIBRARY_FILE, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        
        print(f"💾 经验库已保存: {self.LIBRARY_FILE}")
    
    # ==================== 项目类型识别 ====================
    
    def identify_project_type(self, output: str, command: str = "") -> Optional[tuple]:
        """
        根据命令输出识别项目类型和子类型
        
        返回: (project_type, subtype) 或 None
        """
        combined = (output + " " + command).lower()
        
        for project_type, subtypes in self.library.experiences.items():
            for subtype, experience in subtypes.items():
                for pattern in experience.identifying_patterns:
                    if pattern.lower() in combined:
                        self.current_project_type = project_type
                        self.current_subtype = subtype
                        print(f"🔍 识别到项目类型: {project_type}/{subtype} (匹配: {pattern})")
                        return (project_type, subtype)
        
        return None
    
    # ==================== 经验查询 ====================
    
    def get_experience(self, project_type: str, subtype: str) -> Optional[ProjectTypeExperience]:
        """获取特定项目类型的经验"""
        return self.library.experiences.get(project_type, {}).get(subtype)
    
    def get_startup_advice(self, project_type: str, subtype: str) -> Optional[str]:
        """获取启动建议"""
        exp = self.get_experience(project_type, subtype)
        if exp:
            return exp.startup_advice
        return None
    
    def get_current_advice(self) -> Optional[str]:
        """获取当前识别项目的建议"""
        if self.current_project_type and self.current_subtype:
            return self.get_startup_advice(self.current_project_type, self.current_subtype)
        return None
    
    def should_block_based_on_experience(self, command: str, project_type: str = None, subtype: str = None) -> Optional[str]:
        """
        根据经验判断是否应该阻止命令执行
        
        返回: 阻止原因，或 None 表示允许
        """
        # 使用当前识别的项目类型，或传入的参数
        pt = project_type or self.current_project_type
        st = subtype or self.current_subtype
        
        if not pt or not st:
            return None
        
        exp = self.get_experience(pt, st)
        if not exp:
            return None
        
        cmd_lower = command.lower()
        
        # 检查每个命令经验
        for cmd_pattern, cmd_exp in exp.command_experiences.items():
            if cmd_pattern.lower() in cmd_lower and cmd_exp.should_avoid:
                alternatives = ", ".join(cmd_exp.alternatives) if cmd_exp.alternatives else "查看项目文档"
                return f"""⛔ 根据历史经验阻止执行：
   命令: {command[:50]}
   项目类型: {pt}/{st}
   原因: {cmd_exp.avoid_reason}
   替代方案: {alternatives}"""
        
        return None
    
    def get_common_pitfalls(self, project_type: str, subtype: str) -> List[str]:
        """获取常见陷阱"""
        exp = self.get_experience(project_type, subtype)
        if exp:
            return exp.common_pitfalls
        return []
    
    # ==================== 经验记录 ====================
    
    def record_experience(self, project_type: str, subtype: str, experience_data: Dict):
        """
        记录新经验
        
        experience_data 格式:
        {
            "command": "命令",
            "success": True/False,
            "error": "错误信息（如果失败）",
            "lesson": "学到的教训",
            "solution": "解决方案（如果有）"
        }
        """
        # 确保项目类型存在
        if project_type not in self.library.experiences:
            self.library.experiences[project_type] = {}
        
        if subtype not in self.library.experiences[project_type]:
            # 创建新的项目类型经验
            self.library.experiences[project_type][subtype] = ProjectTypeExperience(
                project_type=project_type,
                subtype=subtype,
            )
        
        exp = self.library.experiences[project_type][subtype]
        exp.last_updated = datetime.now().isoformat()
        exp.total_tasks += 1
        
        if experience_data.get('success'):
            exp.successful_tasks += 1
        
        # 更新命令经验
        command = experience_data.get('command', '')
        if command:
            cmd_pattern = self._extract_command_pattern(command)
            
            if cmd_pattern not in exp.command_experiences:
                exp.command_experiences[cmd_pattern] = CommandExperience(command_pattern=cmd_pattern)
            
            cmd_exp = exp.command_experiences[cmd_pattern]
            
            if experience_data.get('success'):
                cmd_exp.success_count += 1
            else:
                cmd_exp.failure_count += 1
                
                # 记录错误信息
                error = experience_data.get('error', '')
                if error and error not in cmd_exp.common_errors:
                    cmd_exp.common_errors.append(error[:200])  # 限制长度
                
                # 记录解决方案
                solution = experience_data.get('solution', '')
                if solution and solution not in cmd_exp.solutions:
                    cmd_exp.solutions.append(solution)
                
                # 如果失败率过高，标记为应该避免
                if cmd_exp.failure_count > 3 and cmd_exp.success_count == 0:
                    cmd_exp.should_avoid = True
                    cmd_exp.avoid_reason = experience_data.get('lesson', '多次失败，建议使用替代方案')
        
        # 记录教训
        lesson = experience_data.get('lesson', '')
        if lesson and lesson not in exp.common_pitfalls:
            exp.common_pitfalls.append(lesson)
        
        # 自动保存
        self.save()
        print(f"📝 记录新经验: {project_type}/{subtype} - {experience_data.get('command', '')[:30]}")
    
    def _extract_command_pattern(self, command: str) -> str:
        """提取命令模式（去除具体参数）"""
        parts = command.strip().split()
        if not parts:
            return command
        
        # 常见命令模式
        if parts[0] in ['dotnet', 'npm', 'yarn', 'pip', 'pip3', 'python', 'python3', 'go', 'java', 'mvn', 'gradle']:
            if len(parts) > 1:
                return f"{parts[0]} {parts[1]}"
        
        return parts[0]
    
    # ==================== 调试和信息 ====================
    
    def get_summary(self) -> str:
        """获取经验库摘要"""
        summary = ["📚 项目经验库摘要:"]
        
        for project_type, subtypes in self.library.experiences.items():
            for subtype, exp in subtypes.items():
                success_rate = (exp.successful_tasks / exp.total_tasks * 100) if exp.total_tasks > 0 else 0
                cmd_count = len(exp.command_experiences)
                summary.append(f"  - {project_type}/{subtype}: {exp.total_tasks}次任务, {success_rate:.0f}%成功率, {cmd_count}个命令经验")
        
        return "\n".join(summary)
    
    def reset_current_session(self):
        """重置当前会话状态（不删除持久化经验）"""
        self.current_project_type = None
        self.current_subtype = None


# ==================== 全局单例 ====================

_experience_library: Optional[ProjectExperienceLibrary] = None


def get_experience_library() -> ProjectExperienceLibrary:
    """获取全局经验库实例"""
    global _experience_library
    if _experience_library is None:
        _experience_library = ProjectExperienceLibrary()
    return _experience_library


def reset_experience_session():
    """重置当前会话（保留持久化经验）"""
    if _experience_library:
        _experience_library.reset_current_session()
