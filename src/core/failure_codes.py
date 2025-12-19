"""
失败原因码体系 - 让系统"可诊断"

定义结构化的失败原因码，用于精确诊断漏洞复现失败的根因。
每个失败都应该有一个明确的原因码，而不是模糊的错误信息。
"""

from enum import Enum
from typing import Dict, Any, Optional
from dataclasses import dataclass


class FailureCategory(Enum):
    """失败类别"""
    ENVIRONMENT = "E"    # 环境问题
    TRIGGER = "T"        # 触发问题
    VERIFICATION = "V"   # 验证问题
    DATA = "D"           # 数据问题
    NETWORK = "N"        # 网络问题
    UNKNOWN = "U"        # 未知问题


class FailureCode(Enum):
    """
    失败原因码枚举
    
    命名规则: {类别}{序号}_{简短描述}
    """
    
    # ========== 环境类 (E) ==========
    E001_VERSION_MISMATCH = "E001"       # 版本不匹配
    E002_DEPS_MISSING = "E002"           # 依赖缺失
    E003_SERVICE_NOT_RUNNING = "E003"    # 服务未运行
    E004_CONFIG_ERROR = "E004"           # 配置错误
    E005_BUILD_FAILED = "E005"           # 构建失败
    E006_PORT_CONFLICT = "E006"          # 端口冲突
    E007_PERMISSION_DENIED = "E007"      # 权限不足
    E008_RESOURCE_EXHAUSTED = "E008"     # 资源耗尽
    E009_DOCKER_ERROR = "E009"           # Docker 错误
    E010_GIT_CLONE_FAILED = "E010"       # Git 克隆失败
    E011_CHECKOUT_FAILED = "E011"        # Git checkout 失败
    E012_INSTALL_FAILED = "E012"         # 依赖安装失败
    E013_START_TIMEOUT = "E013"           # 服务启动超时
    E014_HEALTH_CHECK_FAILED = "E014"     # 健康检查失败
    E015_ENV_NOT_FOUND = "E015"           # 环境未找到
    E016_NPM_PEER_CONFLICT = "E016"       # npm peer dependency 冲突
    E017_NODE_VERSION_MISMATCH = "E017"   # Node.js 版本不匹配
    
    # ========== 触发类 (T) ==========
    T001_PAYLOAD_REJECTED = "T001"       # Payload 被拒绝
    T002_PATH_UNREACHABLE = "T002"       # 漏洞路径不可达
    T003_AUTH_REQUIRED = "T003"          # 需要认证
    T004_ENDPOINT_NOT_FOUND = "T004"     # 端点不存在
    T005_METHOD_NOT_ALLOWED = "T005"     # HTTP 方法不允许
    T006_PARAM_VALIDATION = "T006"       # 参数验证失败
    T007_WAF_BLOCKED = "T007"            # WAF 拦截
    T008_RATE_LIMITED = "T008"           # 速率限制
    T009_PATCH_APPLIED = "T009"          # 补丁已应用
    T010_VULN_NOT_TRIGGERED = "T010"     # 漏洞未触发
    T011_PRECONDITION_FAILED = "T011"    # 前置条件不满足
    T012_SESSION_INVALID = "T012"        # 会话无效
    
    # ========== 验证类 (V) ==========
    V001_NO_EVIDENCE = "V001"            # 没有验证证据
    V002_FALSE_POSITIVE = "V002"         # 误报（看起来成功但实际没有）
    V003_ORACLE_FAILED = "V003"          # Oracle 无法判定
    V004_CANARY_NOT_FOUND = "V004"       # 金丝雀数据未找到
    V005_UNEXPECTED_RESPONSE = "V005"    # 响应不符合预期
    V006_PARTIAL_SUCCESS = "V006"        # 部分成功
    V007_TIMEOUT = "V007"                # 验证超时
    V008_SIDE_EFFECT_MISSING = "V008"    # 副作用未检测到
    
    # ========== 数据类 (D) ==========
    D001_CVE_INFO_INCOMPLETE = "D001"    # CVE 信息不完整
    D002_NO_POC = "D002"                 # 无 PoC 参考
    D003_INVALID_REPO_URL = "D003"       # 仓库 URL 无效
    D004_VERSION_NOT_FOUND = "D004"      # 版本号找不到
    D005_NO_DEPLOY_STRATEGY = "D005"     # 无部署策略
    D006_UNSUPPORTED_LANG = "D006"       # 不支持的语言/框架
    D007_HARDWARE_VULN = "D007"          # 硬件漏洞（无法软件复现）
    D008_CLOSED_SOURCE = "D008"          # 闭源软件
    
    # ========== 网络类 (N) ==========
    N001_CONNECTION_REFUSED = "N001"     # 连接被拒绝
    N002_DNS_FAILED = "N002"             # DNS 解析失败
    N003_TIMEOUT = "N003"                # 网络超时
    N004_SSL_ERROR = "N004"              # SSL/TLS 错误
    N005_PROXY_ERROR = "N005"            # 代理错误
    
    # ========== 未知类 (U) ==========
    U001_UNKNOWN = "U001"                # 未知错误
    U002_LLM_ERROR = "U002"              # LLM 调用错误
    U003_INTERNAL_ERROR = "U003"         # 内部错误


@dataclass
class FailureDetail:
    """失败详情"""
    code: FailureCode
    message: str
    context: Dict[str, Any]
    recoverable: bool = False
    suggested_action: Optional[str] = None
    root_cause: Optional[str] = None  # 根因分析
    
    @property
    def category(self) -> str:
        """从失败码推断失败类别"""
        code_name = self.code.name
        if code_name.startswith('E'):
            return FailureCategory.ENVIRONMENT.value
        elif code_name.startswith('T'):
            return FailureCategory.TRIGGER.value
        elif code_name.startswith('V'):
            return FailureCategory.VERIFICATION.value
        elif code_name.startswith('D'):
            return FailureCategory.DATA.value
        elif code_name.startswith('N'):
            return FailureCategory.NETWORK.value
        else:
            return FailureCategory.UNKNOWN.value
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "failure_code": self.code.value,
            "failure_name": self.code.name,
            "message": self.message,
            "context": self.context,
            "category": self.category,
            "recoverable": self.recoverable,
            "suggested_action": self.suggested_action,
            "root_cause": self.root_cause
        }


class FailureAnalyzer:
    """失败分析器 - 从错误信息推断失败原因码"""
    
    # 错误模式映射
    ERROR_PATTERNS = {
        # 环境类
        r"version.*mismatch|版本.*不匹配": FailureCode.E001_VERSION_MISMATCH,
        r"module.*not found|import.*error|依赖.*缺失|no module named": FailureCode.E002_DEPS_MISSING,
        r"connection refused|ECONNREFUSED|服务.*未.*运行": FailureCode.E003_SERVICE_NOT_RUNNING,
        r"config.*error|配置.*错误": FailureCode.E004_CONFIG_ERROR,
        r"build.*fail|编译.*失败|make.*error": FailureCode.E005_BUILD_FAILED,
        r"address.*in use|端口.*占用|EADDRINUSE": FailureCode.E006_PORT_CONFLICT,
        r"permission denied|权限.*拒绝|EACCES": FailureCode.E007_PERMISSION_DENIED,
        r"out of memory|资源.*耗尽|no space": FailureCode.E008_RESOURCE_EXHAUSTED,
        r"docker.*error|container.*fail": FailureCode.E009_DOCKER_ERROR,
        r"git.*clone.*fail|clone.*error": FailureCode.E010_GIT_CLONE_FAILED,
        r"checkout.*fail|git.*checkout.*error": FailureCode.E011_CHECKOUT_FAILED,
        r"npm.*install.*fail|pip.*install.*fail|composer.*install.*fail": FailureCode.E012_INSTALL_FAILED,
        r"ERESOLVE|peer.*dep|could not resolve dependency|conflicting peer": FailureCode.E016_NPM_PEER_CONFLICT,
        r"engine.*incompatible|unsupported.*engine|requires.*node": FailureCode.E017_NODE_VERSION_MISMATCH,
        r"startup.*timeout|启动.*超时|start.*timeout": FailureCode.E013_START_TIMEOUT,
        r"health.*check.*fail|healthy.*false": FailureCode.E014_HEALTH_CHECK_FAILED,
        
        # 触发类
        r"403|forbidden|payload.*reject": FailureCode.T001_PAYLOAD_REJECTED,
        r"404|not found|路径.*不存在": FailureCode.T002_PATH_UNREACHABLE,
        r"401|unauthorized|认证.*失败|auth.*require": FailureCode.T003_AUTH_REQUIRED,
        r"endpoint.*not.*exist": FailureCode.T004_ENDPOINT_NOT_FOUND,
        r"405|method.*not.*allow": FailureCode.T005_METHOD_NOT_ALLOWED,
        r"400|bad.*request|参数.*错误": FailureCode.T006_PARAM_VALIDATION,
        r"waf|firewall|blocked": FailureCode.T007_WAF_BLOCKED,
        r"429|rate.*limit|too.*many": FailureCode.T008_RATE_LIMITED,
        r"patch.*applied|已.*修复|fixed": FailureCode.T009_PATCH_APPLIED,
        
        # 验证类
        r"no.*evidence|无.*证据": FailureCode.V001_NO_EVIDENCE,
        r"false.*positive|误报": FailureCode.V002_FALSE_POSITIVE,
        r"canary.*not.*found|金丝雀.*未找到": FailureCode.V004_CANARY_NOT_FOUND,
        r"unexpected.*response|响应.*不符": FailureCode.V005_UNEXPECTED_RESPONSE,
        
        # 数据类
        r"cve.*info.*incomplete|信息.*不完整": FailureCode.D001_CVE_INFO_INCOMPLETE,
        r"no.*poc|无.*poc": FailureCode.D002_NO_POC,
        r"invalid.*url|url.*invalid": FailureCode.D003_INVALID_REPO_URL,
        r"version.*not.*found|版本.*找不到": FailureCode.D004_VERSION_NOT_FOUND,
        r"hardware|硬件": FailureCode.D007_HARDWARE_VULN,
        
        # 网络类
        r"connection.*timeout|网络.*超时": FailureCode.N003_TIMEOUT,
        r"ssl.*error|certificate": FailureCode.N004_SSL_ERROR,
    }
    
    # 失败码的建议动作
    SUGGESTED_ACTIONS = {
        FailureCode.E001_VERSION_MISMATCH: "检查 CVE 描述中的受影响版本，确保 checkout 正确的 git tag",
        FailureCode.E002_DEPS_MISSING: "运行依赖安装命令 (pip install/npm install/composer install)",
        FailureCode.E003_SERVICE_NOT_RUNNING: "检查服务启动命令，查看日志确认启动失败原因",
        FailureCode.E004_CONFIG_ERROR: "检查配置文件，确保必要的环境变量已设置",
        FailureCode.E010_GIT_CLONE_FAILED: "检查仓库 URL 是否正确，网络是否可达",
        FailureCode.E011_CHECKOUT_FAILED: "检查版本 tag 是否存在，尝试 git tag -l 列出可用 tag",
        FailureCode.E012_INSTALL_FAILED: "检查依赖版本兼容性，可能需要指定特定版本",
        FailureCode.E014_HEALTH_CHECK_FAILED: "增加等待时间，检查服务日志确认实际状态",
        FailureCode.E016_NPM_PEER_CONFLICT: "使用 npm install --legacy-peer-deps 或 npm install --force 忽略 peer dependency 冲突",
        FailureCode.E017_NODE_VERSION_MISMATCH: "使用 nvm 切换到项目要求的 Node.js 版本",
        FailureCode.T001_PAYLOAD_REJECTED: "调整 payload 格式，可能需要编码或绕过检查",
        FailureCode.T003_AUTH_REQUIRED: "提供有效的认证凭据或尝试绕过认证",
        FailureCode.T009_PATCH_APPLIED: "确认使用的是漏洞版本而非修复版本",
        FailureCode.V001_NO_EVIDENCE: "检查验证策略，可能需要更敏感的检测方法",
        FailureCode.D001_CVE_INFO_INCOMPLETE: "从 NVD/GitHub/安全公告获取更多信息",
        FailureCode.D002_NO_POC: "搜索公开的 PoC 或根据补丁逆向构造",
    }
    
    @classmethod
    def analyze(cls, error_message: str, context: Dict[str, Any] = None) -> FailureDetail:
        """
        分析错误信息，返回失败详情
        
        Args:
            error_message: 错误信息
            context: 上下文信息
            
        Returns:
            FailureDetail 对象
        """
        import re
        
        context = context or {}
        error_lower = error_message.lower()
        
        # 匹配错误模式
        matched_code = FailureCode.U001_UNKNOWN
        for pattern, code in cls.ERROR_PATTERNS.items():
            if re.search(pattern, error_lower, re.IGNORECASE):
                matched_code = code
                break
        
        # 获取建议动作
        suggested_action = cls.SUGGESTED_ACTIONS.get(matched_code)
        
        # 判断是否可恢复
        recoverable = matched_code in [
            FailureCode.E002_DEPS_MISSING,
            FailureCode.E003_SERVICE_NOT_RUNNING,
            FailureCode.E006_PORT_CONFLICT,
            FailureCode.E012_INSTALL_FAILED,
            FailureCode.E013_START_TIMEOUT,
            FailureCode.E016_NPM_PEER_CONFLICT,  # npm 冲突可以用 --legacy-peer-deps 解决
            FailureCode.E017_NODE_VERSION_MISMATCH,
            FailureCode.T001_PAYLOAD_REJECTED,
            FailureCode.T003_AUTH_REQUIRED,
            FailureCode.N003_TIMEOUT,
        ]
        
        return FailureDetail(
            code=matched_code,
            message=error_message,
            context=context,
            recoverable=recoverable,
            suggested_action=suggested_action
        )
    
    @classmethod
    def from_http_code(cls, http_code: int, context: Dict[str, Any] = None) -> FailureDetail:
        """从 HTTP 状态码推断失败原因"""
        context = context or {}
        
        code_mapping = {
            0: FailureCode.E003_SERVICE_NOT_RUNNING,
            400: FailureCode.T006_PARAM_VALIDATION,
            401: FailureCode.T003_AUTH_REQUIRED,
            403: FailureCode.T001_PAYLOAD_REJECTED,
            404: FailureCode.T002_PATH_UNREACHABLE,
            405: FailureCode.T005_METHOD_NOT_ALLOWED,
            429: FailureCode.T008_RATE_LIMITED,
            500: FailureCode.U003_INTERNAL_ERROR,
            502: FailureCode.E003_SERVICE_NOT_RUNNING,
            503: FailureCode.E003_SERVICE_NOT_RUNNING,
            504: FailureCode.N003_TIMEOUT,
        }
        
        matched_code = code_mapping.get(http_code, FailureCode.U001_UNKNOWN)
        
        return FailureDetail(
            code=matched_code,
            message=f"HTTP {http_code}",
            context={"http_code": http_code, **context},
            recoverable=http_code in [429, 502, 503, 504],
            suggested_action=cls.SUGGESTED_ACTIONS.get(matched_code)
        )


class ReproReport:
    """
    复现报告 - 标准化的复现结果记录
    """
    
    def __init__(self, cve_id: str):
        self.cve_id = cve_id
        self.stages: Dict[str, Dict[str, Any]] = {}
        self.final_result: Optional[str] = None  # success / partial / failed
        self.failure_detail: Optional[FailureDetail] = None
        self.evidence_chain: list = []
        
    def record_stage(
        self,
        stage_name: str,
        success: bool,
        duration_seconds: float,
        outputs: Dict[str, Any] = None,
        failure_detail: FailureDetail = None
    ):
        """记录某个阶段的结果"""
        self.stages[stage_name] = {
            "success": success,
            "duration_seconds": duration_seconds,
            "outputs": outputs or {},
            "failure_detail": failure_detail.to_dict() if failure_detail else None
        }
        
        if not success and failure_detail:
            self.failure_detail = failure_detail
    
    def add_evidence(self, evidence_type: str, evidence_data: Any, confidence: float = 1.0):
        """添加验证证据"""
        self.evidence_chain.append({
            "type": evidence_type,
            "data": evidence_data,
            "confidence": confidence
        })
    
    def finalize(self, result: str):
        """完成报告"""
        self.final_result = result
    
    def to_dict(self) -> Dict[str, Any]:
        """导出为字典"""
        return {
            "cve_id": self.cve_id,
            "final_result": self.final_result,
            "stages": self.stages,
            "failure_detail": self.failure_detail.to_dict() if self.failure_detail else None,
            "evidence_chain": self.evidence_chain,
            "summary": self._generate_summary()
        }
    
    def _generate_summary(self) -> str:
        """生成人类可读的摘要"""
        if self.final_result == "success":
            return f"✅ CVE-{self.cve_id} 复现成功，共 {len(self.evidence_chain)} 条证据"
        
        if self.failure_detail:
            return (
                f"❌ CVE-{self.cve_id} 复现失败\n"
                f"   失败码: {self.failure_detail.code.value} ({self.failure_detail.code.name})\n"
                f"   原因: {self.failure_detail.message}\n"
                f"   建议: {self.failure_detail.suggested_action or '无'}"
            )
        
        return f"❌ CVE-{self.cve_id} 复现失败（原因未知）"


# 便捷函数
def analyze_failure(error_message: str, context: Dict[str, Any] = None) -> FailureDetail:
    """分析失败原因的便捷函数"""
    return FailureAnalyzer.analyze(error_message, context)


def create_report(cve_id: str) -> ReproReport:
    """创建复现报告的便捷函数"""
    return ReproReport(cve_id)
