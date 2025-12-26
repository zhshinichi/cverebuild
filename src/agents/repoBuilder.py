import re
import os
import json

from agentlib import AgentWithHistory, LLMFunction
from agentlib.lib.common.parsers import BaseParser
from typing import Optional, Any, Dict, List
from langchain_core.agents import AgentFinish

from toolbox.tools import TOOLS

# 构建知识库路径
BUILD_KNOWLEDGE_PATH = os.path.join(
    os.path.dirname(os.path.dirname(__file__)), 
    'data', 'build_knowledge', 'build_recipes.json'
)

def load_build_knowledge() -> Dict:
    """加载构建知识库"""
    try:
        if os.path.exists(BUILD_KNOWLEDGE_PATH):
            with open(BUILD_KNOWLEDGE_PATH, 'r', encoding='utf-8') as f:
                return json.load(f)
    except Exception as e:
        print(f"[BuildKnowledge] Warning: Failed to load knowledge base: {e}")
    return {"recipes": {}}

def match_build_recipes(context: str, knowledge: Dict) -> List[Dict]:
    """根据上下文匹配相关的构建配方"""
    matched = []
    context_lower = context.lower() if context else ""
    
    for name, recipe in knowledge.get("recipes", {}).items():
        keywords = recipe.get("keywords", [])
        for keyword in keywords:
            if keyword.lower() in context_lower:
                matched.append({
                    "name": name,
                    **recipe
                })
                break  # 每个配方只匹配一次
    
    return matched

def format_build_advice(recipes: List[Dict]) -> str:
    """格式化构建建议为 prompt 注入"""
    if not recipes:
        return ""
    
    advice_parts = ["### 🧠 BUILD KNOWLEDGE (Auto-loaded from knowledge base)"]
    
    for recipe in recipes:
        name = recipe.get("name", "unknown")
        desc = recipe.get("description", "")
        
        advice_parts.append(f"\n**📦 {name.upper()}** - {desc}")
        
        # 如果需要跳过
        if recipe.get("skip_reproduction"):
            advice_parts.append(f"⚠️ SKIP: {recipe.get('skip_reason', 'Cannot be auto-reproduced')}")
            continue
        
        # 如果是库类型，优先包管理器
        if recipe.get("is_library"):
            advice_parts.append("⭐ This is a LIBRARY - prefer package manager over source build!")
            pkg_managers = recipe.get("package_managers", {})
            if pkg_managers:
                for pm, pkg in pkg_managers.items():
                    advice_parts.append(f"  - {pm}: {pkg}")
        
        # 复杂构建警告
        if recipe.get("complex_build"):
            advice_parts.append(f"⚠️ Complex build system: {recipe.get('build_system', 'unknown')}")
        
        # 子模块警告
        if recipe.get("requires_submodules"):
            advice_parts.append("⚠️ Requires git submodules! ZIP downloads will be INCOMPLETE.")
        
        # 构建指令
        instructions = recipe.get("build_instructions", [])
        if instructions:
            advice_parts.append("**Build steps:**")
            advice_parts.append("```bash")
            advice_parts.extend(instructions[:15])  # 限制长度
            if len(instructions) > 15:
                advice_parts.append("# ... more steps in knowledge base")
            advice_parts.append("```")
        
        # 依赖
        deps = recipe.get("dependencies", [])
        if deps:
            advice_parts.append(f"**Dependencies:** `apt-get install -y {' '.join(deps)}`")
        
        # 常见错误
        errors = recipe.get("common_errors", {})
        if errors:
            advice_parts.append("**Common errors & fixes:**")
            for err, fix in list(errors.items())[:3]:
                advice_parts.append(f"  - `{err}`: {fix}")
    
    return "\n".join(advice_parts)

OUTPUT_DESCRIPTION = '''
After completing the analysis, you MUST output the project build information in the following specified format.

```
<report>
<success>...</success>
<access>...</access>
</report>
```

Within <success></success>, replace ... with the information if the setup is working or not, ONLY use "yes" or "no".
Within <access></access>, replace ... with the information on how the another agent can interact with or access the software.
'''

class MyParser(BaseParser):
    MAX_FIX_FORMAT_TRIES = 3

    def get_format_instructions(self) -> str:
        return OUTPUT_DESCRIPTION

    def invoke(self, msg, *args, **kwargs) -> dict | str:
        response = msg['output']
        if isinstance(response, list):
            response = ' '.join(response)
        if response == 'Agent stopped due to max iterations.':
            return response
        return self.parse(response)

    def fix_patch_format(self, text: str) -> str:
        fix_llm = LLMFunction.create(
            'Fix the format of the current report according to the format instructions.\n\n# CURRENT REPORT\n{{ info.current_report }}\n\n# OUTPUT FORMAT\n{{ info.output_format }}',
            model='gpt-4o-mini',
            temperature=0.0
        )
        fixed_text = fix_llm(
            info = dict(
                current_report = text,
                output_format = self.get_format_instructions()
            )
        )
        return fixed_text

    def raise_format_error(self) -> None:
        raise ValueError(f'🤡 Output format is not correct!!')

    def parse(self, text: str) -> dict:
        try_itr = 1
        while try_itr <= self.MAX_FIX_FORMAT_TRIES:
            try:
                m = re.search(r'<success>(.*?)</success>', text, re.DOTALL)
                success = m.group(1).strip() if m else self.raise_format_error()
                m = re.search(r'<access>(.*?)</access>', text, re.DOTALL)
                access = m.group(1) if m else self.raise_format_error()
                return dict(
                    success = success.strip(),
                    access = access.strip()
                )
            except ValueError:
                text = self.fix_patch_format(text)
                try_itr += 1
        
        # 🔧 修复：格式修复失败后返回默认值而不是 None
        print(f"[RepoBuilder] ⚠️ Failed to parse output after {self.MAX_FIX_FORMAT_TRIES} attempts, using fallback")
        return dict(
            success = "no",
            access = f"Build status unknown. Last output: {text[:500] if text else 'empty'}"
        )

class RepoBuilder(AgentWithHistory[dict, str]):
    # 🔼 升级模型: gpt-4o-mini 处理复杂构建任务能力不足
    # CVE-2024-32873 教训: 弱模型无法自我纠正项目类型误判
    __LLM_MODEL__ = 'gpt-4o'
    __SYSTEM_PROMPT_TEMPLATE__ = 'repoBuilder/repoBuilder.system.j2'
    __USER_PROMPT_TEMPLATE__ = 'repoBuilder/repoBuilder.user.j2'
    __OUTPUT_PARSER__ = MyParser
    __MAX_TOOL_ITERATIONS__ = 60

    # general
    PROJECT_DIR_TREE: Optional[str]

    # from knowledge builder
    CVE_KNOWLEDGE: Optional[str]

    # from pre-req builder
    PROJECT_OVERVIEW: Optional[str]
    PROJECT_FILES: Optional[str]
    PROJECT_SERVICES: Optional[str]
    PROEJCT_OUTPUT: Optional[str]
    PROJECT_VERIFIER: Optional[str]

    # feedback
    FEEDBACK: Optional[str]
    ERROR: Optional[str]
    CRITIC_FEEDBACK: Optional[str]

    # TOOL_LOGS = ""
    # CAPTURE_TOOL_OUTPUT = False

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.PROJECT_DIR_TREE = kwargs.get('project_dir_tree')
        self.CVE_KNOWLEDGE = kwargs.get('cve_knowledge')
        self.BUILD_PRE_REQS = kwargs.get('build_pre_reqs')
        self.FEEDBACK = kwargs.get('feedback')
        self.CRITIC_FEEDBACK = kwargs.get('critic_feedback')

    def get_input_vars(self, *args, **kwargs) -> dict:
        vars = super().get_input_vars(*args, **kwargs)
        
        # 动态加载构建知识
        build_advice = ""
        try:
            knowledge = load_build_knowledge()
            # 从 CVE_KNOWLEDGE 和 PROJECT_OVERVIEW 中提取上下文
            context = f"{self.CVE_KNOWLEDGE or ''} {self.BUILD_PRE_REQS.get('overview', '')}"
            matched_recipes = match_build_recipes(context, knowledge)
            if matched_recipes:
                build_advice = format_build_advice(matched_recipes)
        except Exception as e:
            build_advice = f"<!-- Build knowledge loading failed: {e} -->"
        
        vars.update(
            PROJECT_DIR_TREE = self.PROJECT_DIR_TREE,
            CVE_KNOWLEDGE = self.CVE_KNOWLEDGE,
            PROJECT_OVERVIEW = self.BUILD_PRE_REQS['overview'],
            PROJECT_FILES = self.BUILD_PRE_REQS['files'],
            PROJECT_SERVICES = self.BUILD_PRE_REQS['services'],
            PROJECT_OUTPUT = self.BUILD_PRE_REQS['output'],
            BUILD_ADVICE = build_advice,  # 动态注入的构建建议
            FEEDBACK = self.FEEDBACK,
            ERROR = None,
            CRITIC_FEEDBACK = self.CRITIC_FEEDBACK
        )
        return vars

    def get_available_tools(self):
        # Only return shell-based tools, NO Python code interpreter
        # This prevents environment isolation issues
        # 扩展工具集以支持更多构建场景
        allowed_tools = [
            'get_file',
            'write_to_file', 
            'execute_ls_command',
            'execute_linux_command',
            'set_environment_variable',
            'install_npm_package',  # NPM 包安装
            'run_command_with_timeout',  # 超时控制
            'start_http_server',  # 启动 HTTP 服务器
            'create_html_test_page',  # 创建测试页面
            'search_docker_hub',  # Docker Hub 镜像搜索（修复 CVE-2024-6984 问题）
        ]
        return [TOOLS[name] for name in allowed_tools if name in TOOLS]
    
    def get_cost(self, *args, **kw) -> float:
        total_cost = 0
        # We have to sum up all the costs of the LLM used by the agent
        for model_name, token_usage in self.token_usage.items():
            total_cost += token_usage.get_costs(model_name)['total_cost']
        return total_cost
