"""
Mid-Execution Reflector (中途反思机制)

该模块实现了在 Agent 执行过程中检测重复失败并触发反思的机制。
当检测到连续失败模式时，会暂停执行并分析错误，给出修正建议。

设计原则：
1. 轻量级 - 不需要完整的 Agent，只需要简单的 LLM 调用
2. 快速响应 - 在失败模式出现后立即介入
3. 精准分析 - 识别错误类型并给出具体修正建议
"""

import re
from typing import Optional, List, Dict, Tuple
from dataclasses import dataclass, field
from agentlib import LLMFunction


@dataclass
class FailurePattern:
    """失败模式记录"""
    pattern_type: str  # pip_install, build_error, import_error, etc.
    command: str
    error_message: str
    count: int = 1


@dataclass
class ReflectionResult:
    """反思结果"""
    should_intervene: bool
    analysis: str
    corrective_action: str
    confidence: float


class ErrorPatternDetector:
    """
    错误模式检测器
    
    检测重复失败模式，如：
    - pip install 版本不存在
    - 包名错误
    - 构建失败
    - 导入错误
    """
    
    # 触发反思的连续失败阈值
    FAILURE_THRESHOLD = 3
    
    # 错误模式正则表达式
    ERROR_PATTERNS = {
        'pip_version_not_found': [
            r'ERROR: Could not find a version that satisfies the requirement ([^\s]+)',
            r'ERROR: No matching distribution found for ([^\s]+)',
        ],
        'pip_package_not_found': [
            r"ERROR: Could not find a version.*No matching distribution found for ([^\s]+)",
        ],
        'import_error': [
            r'ModuleNotFoundError: No module named [\'"]([^\'"]+)[\'"]',
            r'ImportError: cannot import name [\'"]([^\'"]+)[\'"]',
        ],
        'build_error': [
            r'error: command [\'"]([^\'"]+)[\'"] failed',
            r'fatal error: ([^\n]+)',
        ],
        'permission_error': [
            r'PermissionError: \[Errno 13\]',
            r'Permission denied',
        ],
        'connection_error': [
            r'ConnectionRefusedError',
            r'Connection refused',
            r'Could not connect to',
        ]
    }
    
    def __init__(self):
        self.failure_history: List[FailurePattern] = []
        self.consecutive_failures = 0
        self.last_failure_type: Optional[str] = None
        self.similar_command_failures: Dict[str, int] = {}
        
    def analyze_output(self, command: str, output: str) -> Optional[FailurePattern]:
        """
        分析命令输出，检测是否为失败模式
        
        :param command: 执行的命令
        :param output: 命令输出
        :return: 如果检测到失败模式，返回 FailurePattern
        """
        # 检查是否为成功输出
        if self._is_success(output):
            self._reset_consecutive()
            return None
        
        # 检测错误类型
        for pattern_type, patterns in self.ERROR_PATTERNS.items():
            for pattern in patterns:
                match = re.search(pattern, output, re.IGNORECASE)
                if match:
                    failure = FailurePattern(
                        pattern_type=pattern_type,
                        command=command,
                        error_message=match.group(0)
                    )
                    self._record_failure(failure)
                    return failure
        
        # 检查通用失败指标
        if self._contains_failure_indicators(output):
            failure = FailurePattern(
                pattern_type='generic_error',
                command=command,
                error_message=self._extract_error_summary(output)
            )
            self._record_failure(failure)
            return failure
        
        return None
    
    def _is_success(self, output: str) -> bool:
        """检查输出是否表示成功"""
        success_indicators = [
            'exit code: 0',
            'Successfully installed',
            'Successfully built',
            '✅'
        ]
        return any(indicator in output for indicator in success_indicators)
    
    def _contains_failure_indicators(self, output: str) -> bool:
        """检查是否包含失败指标"""
        failure_indicators = [
            'ERROR:',
            'Error:',
            'FAILED',
            'failed',
            'exit code: 1',
            '❌',
            '⚠️ Command completed with exit code:',  # 非零退出码
        ]
        for indicator in failure_indicators:
            if indicator in output:
                # 排除 exit code: 0 的情况
                if 'exit code: 0' not in output:
                    return True
        return False
    
    def _extract_error_summary(self, output: str) -> str:
        """提取错误摘要"""
        lines = output.split('\n')
        error_lines = [l for l in lines if 'error' in l.lower() or 'failed' in l.lower()]
        return '\n'.join(error_lines[:3]) if error_lines else output[:200]
    
    def _record_failure(self, failure: FailurePattern):
        """记录失败"""
        self.failure_history.append(failure)
        self.consecutive_failures += 1
        
        # 跟踪相似命令的失败
        cmd_base = self._get_command_base(failure.command)
        self.similar_command_failures[cmd_base] = self.similar_command_failures.get(cmd_base, 0) + 1
        
        self.last_failure_type = failure.pattern_type
    
    def _get_command_base(self, command: str) -> str:
        """获取命令的基础部分（用于识别相似命令）"""
        # 例如 "pip install llama_index==0.3.5" -> "pip install llama_index"
        parts = command.split('==')[0].split('>=')[0].split('<=')[0]
        return parts.strip()
    
    def _reset_consecutive(self):
        """重置连续失败计数"""
        self.consecutive_failures = 0
    
    def should_trigger_reflection(self) -> Tuple[bool, str]:
        """
        判断是否应该触发反思
        
        :return: (是否触发, 原因)
        """
        # 检查连续失败次数
        if self.consecutive_failures >= self.FAILURE_THRESHOLD:
            return True, f"连续失败 {self.consecutive_failures} 次"
        
        # 检查相似命令的失败次数
        for cmd, count in self.similar_command_failures.items():
            if count >= self.FAILURE_THRESHOLD:
                return True, f"相似命令 '{cmd}' 已失败 {count} 次"
        
        return False, ""
    
    def get_failure_summary(self) -> str:
        """获取失败摘要用于反思"""
        if not self.failure_history:
            return "无失败记录"
        
        recent = self.failure_history[-5:]  # 最近 5 次失败
        summary = "### 最近失败记录:\n"
        for i, f in enumerate(recent, 1):
            summary += f"\n{i}. 类型: {f.pattern_type}\n"
            summary += f"   命令: {f.command}\n"
            summary += f"   错误: {f.error_message}\n"
        
        return summary
    
    def reset(self):
        """重置检测器状态"""
        self.failure_history.clear()
        self.consecutive_failures = 0
        self.last_failure_type = None
        self.similar_command_failures.clear()


class MidExecutionReflector:
    """
    中途执行反思器
    
    当检测到重复失败模式时，调用 LLM 分析错误并给出修正建议
    """
    
    REFLECTION_PROMPT = """你是一个专业的错误分析专家。你需要分析以下连续失败的命令执行记录，找出根本原因，并给出具体的修正建议。

## 当前任务上下文
{{ context }}

## 失败记录
{{ failure_summary }}

## 分析要求
1. 识别失败的根本原因（例如：包名错误、版本不存在、依赖冲突等）
2. 判断当前的尝试策略是否正确
3. 给出具体可行的修正建议

## 输出格式
请按以下格式输出：

<analysis>
[问题分析：简要说明失败的根本原因]
</analysis>

<root_cause>
[根本原因类型：package_name_error | version_not_exist | dependency_conflict | permission_issue | other]
</root_cause>

<corrective_action>
[具体修正建议：给出应该执行的正确命令或策略调整]
</corrective_action>

<confidence>
[置信度：0.0-1.0]
</confidence>
"""

    def __init__(self, context: str = "", deployment_strategy: dict = None):
        self.context = context
        self.detector = ErrorPatternDetector()
        self._reflection_count = 0
        self._max_reflections = 3  # 最多反思 3 次
        
        # 集成DeploymentAdvisor
        self.deployment_strategy = deployment_strategy
        self.deployment_advisor = None
        if deployment_strategy:
            try:
                # 延迟导入避免循环依赖
                from agents.deploymentAdvisor import DeploymentAdvisor
                self.deployment_advisor = DeploymentAdvisor(deployment_strategy)
                print("[MidExecReflector] 🔗 DeploymentAdvisor integrated for enhanced diagnostics")
            except Exception as e:
                print(f"[MidExecReflector] ⚠️ DeploymentAdvisor integration failed: {e}")
        
    def check_and_reflect(self, command: str, output: str) -> Optional[ReflectionResult]:
        """
        检查命令输出，如果需要则触发反思
        
        :param command: 执行的命令
        :param output: 命令输出
        :return: 如果触发反思，返回 ReflectionResult
        """
        # 记录输出
        self.detector.analyze_output(command, output)
        
        # 检查是否需要反思
        should_reflect, reason = self.detector.should_trigger_reflection()
        
        if should_reflect and self._reflection_count < self._max_reflections:
            print(f"\n🔍 检测到重复失败模式: {reason}")
            print("💭 正在进行中途反思...")
            
            result = self._perform_reflection()
            self._reflection_count += 1
            
            # 反思后重置失败计数，给修正后的尝试机会
            self.detector.consecutive_failures = 0
            
            return result
        
        return None
    
    def _perform_reflection(self) -> ReflectionResult:
        """执行反思分析（增强：集成DeploymentAdvisor诊断）"""
        failure_summary = self.detector.get_failure_summary()
        
        # 🔗 如果有DeploymentAdvisor，先进行专业诊断
        advisor_diagnosis = ""
        if self.deployment_advisor:
            advisor_diagnosis = self._get_deployment_diagnosis(failure_summary)
            if advisor_diagnosis:
                print("[MidExecReflector] 💡 DeploymentAdvisor提供专业诊断")
        
        # 增强的上下文（包含advisor诊断）
        enhanced_context = self.context
        if advisor_diagnosis:
            enhanced_context += f"\n\n## 🛡️ 部署专家诊断\n{advisor_diagnosis}"
        
        # 创建 LLM 函数进行分析
        reflector = LLMFunction.create(
            self.REFLECTION_PROMPT,
            model='gpt-4o-mini',  # 使用轻量级模型以节省成本
            temperature=0.0
        )
        
        response = reflector(
            context=enhanced_context,
            failure_summary=failure_summary
        )
        
        # 解析响应
        return self._parse_reflection_response(response)
    
    def _get_deployment_diagnosis(self, failure_summary: str) -> str:
        """从DeploymentAdvisor获取针对性诊断"""
        if not self.deployment_advisor:
            return ""
        
        diagnosis_parts = []
        
        # 检查常见部署问题
        if 'composer' in failure_summary.lower() or 'php' in failure_summary.lower():
            if self.deployment_advisor.ds.get('php_version', '').startswith('7'):
                diagnosis_parts.append("⚠️ **PHP版本冲突检测**")
                diagnosis_parts.append(f"- 该项目需要PHP {self.deployment_advisor.ds['php_version']}")
                diagnosis_parts.append("- 系统默认PHP可能是8.x版本")
                diagnosis_parts.append(f"- **修正方案**: 使用Docker容器")
                
                php_ver = self.deployment_advisor.ds['php_version']
                repo = self.deployment_advisor.repo_name
                working_dir = self.deployment_advisor.ds.get('working_directory')
                
                if working_dir:
                    diagnosis_parts.append(f"  ```bash")
                    diagnosis_parts.append(f"  docker run --rm -v $(pwd)/{repo}:/app -w /app/{working_dir} composer:{php_ver} install")
                    diagnosis_parts.append(f"  ```")
                else:
                    diagnosis_parts.append(f"  ```bash")
                    diagnosis_parts.append(f"  docker run --rm -v $(pwd)/{repo}:/app -w /app composer:{php_ver} install")
                    diagnosis_parts.append(f"  ```")
        
        # 检查工作目录问题
        if 'composer.json' in failure_summary or 'package.json' in failure_summary:
            working_dir = self.deployment_advisor.ds.get('working_directory')
            if working_dir:
                diagnosis_parts.append("\n⚠️ **工作目录问题检测**")
                diagnosis_parts.append(f"- 构建文件不在根目录，而在子目录: {working_dir}/")
                diagnosis_parts.append(f"- **修正方案**: 必须在子目录中运行构建命令")
                diagnosis_parts.append(f"  ```bash")
                diagnosis_parts.append(f"  cd {self.deployment_advisor.repo_name}/{working_dir} && composer install")
                diagnosis_parts.append(f"  ```")
        
        # 检查docker-compose推荐
        if self.deployment_advisor.ds.get('deployment_type') == 'docker-compose':
            diagnosis_parts.append("\n✅ **推荐部署方式**")
            diagnosis_parts.append("- 该项目提供官方docker-compose配置")
            docker_path = self.deployment_advisor.ds.get('docker_compose_path', 'docker-compose')
            diagnosis_parts.append(f"- **最佳方案**: 使用docker-compose")
            diagnosis_parts.append(f"  ```bash")
            diagnosis_parts.append(f"  cd {self.deployment_advisor.repo_name}/{docker_path} && docker-compose up -d")
            diagnosis_parts.append(f"  ```")
        
        return '\n'.join(diagnosis_parts) if diagnosis_parts else ""
    
    def _parse_reflection_response(self, response: str) -> ReflectionResult:
        """解析反思响应"""
        import re
        
        analysis = ""
        corrective_action = ""
        confidence = 0.5
        
        # 提取分析
        match = re.search(r'<analysis>(.*?)</analysis>', response, re.DOTALL)
        if match:
            analysis = match.group(1).strip()
        
        # 提取修正建议
        match = re.search(r'<corrective_action>(.*?)</corrective_action>', response, re.DOTALL)
        if match:
            corrective_action = match.group(1).strip()
        
        # 提取置信度
        match = re.search(r'<confidence>(.*?)</confidence>', response, re.DOTALL)
        if match:
            try:
                confidence = float(match.group(1).strip())
            except ValueError:
                confidence = 0.5
        
        print(f"\n📋 反思结果:")
        print(f"   分析: {analysis}")
        print(f"   建议: {corrective_action}")
        print(f"   置信度: {confidence}")
        
        return ReflectionResult(
            should_intervene=True,
            analysis=analysis,
            corrective_action=corrective_action,
            confidence=confidence
        )
    
    def get_intervention_message(self, result: ReflectionResult) -> str:
        """生成干预消息，注入到 Agent 上下文中"""
        return f"""
⚠️ **中途反思警告**

我检测到你正在重复执行失败的操作。请立即停止当前策略并阅读以下分析：

### 问题分析
{result.analysis}

### 修正建议
{result.corrective_action}

请根据以上建议调整你的执行策略，不要继续重复相同的失败操作。
"""

    def update_context(self, new_context: str):
        """更新任务上下文"""
        self.context = new_context
    
    def reset(self):
        """重置反思器状态"""
        self.detector.reset()
        self._reflection_count = 0
