"""
强化验证器 - 不让系统"自欺欺人"

原则：
1. 验证必须与触发解耦 - Agent 可以尝试多种触发方式，但成功只能由 Oracle 判定
2. 不信任 LLM 自判断 - 必须有机器可验证的证据
3. 使用"金丝雀数据"验证 - 用可控的副作用证明漏洞触发
"""

import re
import uuid
import time
import subprocess
from abc import ABC, abstractmethod
from typing import Dict, Any, List, Optional, Tuple
from dataclasses import dataclass
from enum import Enum

from core.failure_codes import FailureCode, FailureDetail, FailureAnalyzer


class VulnType(Enum):
    """漏洞类型"""
    RCE = "rce"                  # 远程代码执行
    SQLI = "sqli"                # SQL 注入
    XSS = "xss"                  # 跨站脚本
    SSRF = "ssrf"                # 服务端请求伪造
    LFI = "lfi"                  # 本地文件包含
    RFI = "rfi"                  # 远程文件包含
    PATH_TRAVERSAL = "path_traversal"  # 路径遍历
    AUTH_BYPASS = "auth_bypass"  # 认证绕过
    IDOR = "idor"                # 不安全的直接对象引用
    INFO_LEAK = "info_leak"      # 信息泄露
    DOS = "dos"                  # 拒绝服务
    CSRF = "csrf"                # 跨站请求伪造
    DESERIALIZATION = "deser"    # 反序列化
    XXE = "xxe"                  # XML 外部实体
    SSTI = "ssti"                # 服务端模板注入
    UNKNOWN = "unknown"


@dataclass
class VerificationResult:
    """验证结果"""
    success: bool
    confidence: float           # 0.0 - 1.0
    evidence: str
    evidence_type: str          # canary, response_diff, log_pattern, side_effect
    details: Dict[str, Any]
    failure_code: Optional[FailureCode] = None
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "success": self.success,
            "confidence": self.confidence,
            "evidence": self.evidence,
            "evidence_type": self.evidence_type,
            "details": self.details,
            "failure_code": self.failure_code.value if self.failure_code else None
        }


class CanaryGenerator:
    """
    金丝雀数据生成器
    
    生成用于验证漏洞触发的可控数据：
    - RCE: 写入特定文件
    - SQLi: 插入特定记录
    - XSS: 注入特定 DOM 标记
    - SSRF: 触发到特定 URL 的请求
    - 信息泄露: 预埋敏感数据
    """
    
    @staticmethod
    def generate_file_canary() -> Tuple[str, str]:
        """
        生成文件金丝雀（用于 RCE 验证）
        
        Returns:
            (canary_path, canary_content)
        """
        canary_id = uuid.uuid4().hex[:8]
        canary_path = f"/tmp/canary_{canary_id}.txt"
        canary_content = f"VULN_TRIGGERED_{canary_id}_{int(time.time())}"
        return canary_path, canary_content
    
    @staticmethod
    def generate_db_canary() -> Tuple[str, str]:
        """
        生成数据库金丝雀（用于 SQLi 验证）
        
        Returns:
            (canary_marker, canary_value)
        """
        canary_id = uuid.uuid4().hex[:8]
        canary_marker = f"SQLI_CANARY_{canary_id}"
        canary_value = f"injected_{canary_id}"
        return canary_marker, canary_value
    
    @staticmethod
    def generate_dom_canary() -> Tuple[str, str]:
        """
        生成 DOM 金丝雀（用于 XSS 验证）
        
        Returns:
            (canary_id, canary_script)
        """
        canary_id = uuid.uuid4().hex[:8]
        # 使用无害的 DOM 标记而不是 alert
        canary_script = f'<div id="xss_canary_{canary_id}" data-triggered="true"></div>'
        return canary_id, canary_script
    
    @staticmethod
    def generate_ssrf_canary() -> Tuple[str, str]:
        """
        生成 SSRF 金丝雀
        
        Returns:
            (canary_id, canary_url) - 可以用 Burp Collaborator 或自建 webhook
        """
        canary_id = uuid.uuid4().hex[:8]
        # 使用本地可验证的 URL
        canary_url = f"http://127.0.0.1:9999/ssrf_canary_{canary_id}"
        return canary_id, canary_url
    
    @staticmethod  
    def generate_secret_canary() -> Tuple[str, str]:
        """
        生成敏感数据金丝雀（用于信息泄露验证）
        
        Returns:
            (canary_name, canary_value)
        """
        canary_id = uuid.uuid4().hex[:8]
        canary_name = f"SECRET_CANARY_{canary_id}"
        canary_value = f"LEAKED_DATA_{canary_id}_{uuid.uuid4().hex}"
        return canary_name, canary_value


class HardenedOracle(ABC):
    """
    强化 Oracle 基类
    
    所有 Oracle 必须实现 verify 方法，返回机器可验证的结果。
    不允许依赖 LLM 的主观判断。
    """
    
    @abstractmethod
    def verify(self, context: Dict[str, Any]) -> VerificationResult:
        """执行验证，返回结构化结果"""
        pass
    
    @abstractmethod
    def get_required_evidence(self) -> List[str]:
        """返回该 Oracle 需要的证据类型列表"""
        pass


class RCEOracle(HardenedOracle):
    """
    RCE 漏洞验证 Oracle
    
    验证方式：检查金丝雀文件是否被创建
    """
    
    def __init__(self, canary_path: str, canary_content: str):
        self.canary_path = canary_path
        self.canary_content = canary_content
    
    def get_required_evidence(self) -> List[str]:
        return ["file_created", "file_content_match"]
    
    def verify(self, context: Dict[str, Any]) -> VerificationResult:
        """
        验证 RCE 是否成功
        
        context 应包含:
            - target_host: 目标主机 (用于远程检查)
            - ssh_config: SSH 配置 (可选)
        """
        try:
            # 本地检查
            target_host = context.get('target_host', 'localhost')
            
            if target_host in ['localhost', '127.0.0.1']:
                # 本地文件检查
                import os
                if os.path.exists(self.canary_path):
                    with open(self.canary_path, 'r') as f:
                        content = f.read().strip()
                    
                    if self.canary_content in content:
                        # 清理金丝雀文件
                        try:
                            os.remove(self.canary_path)
                        except:
                            pass
                        
                        return VerificationResult(
                            success=True,
                            confidence=1.0,
                            evidence=f"Canary file created with expected content",
                            evidence_type="canary",
                            details={
                                "canary_path": self.canary_path,
                                "canary_content": self.canary_content,
                                "actual_content": content
                            }
                        )
                    else:
                        return VerificationResult(
                            success=False,
                            confidence=0.3,
                            evidence=f"Canary file exists but content mismatch",
                            evidence_type="canary",
                            details={
                                "canary_path": self.canary_path,
                                "expected": self.canary_content,
                                "actual": content
                            },
                            failure_code=FailureCode.V005_UNEXPECTED_RESPONSE
                        )
                else:
                    return VerificationResult(
                        success=False,
                        confidence=0.0,
                        evidence=f"Canary file not found: {self.canary_path}",
                        evidence_type="canary",
                        details={"canary_path": self.canary_path},
                        failure_code=FailureCode.V004_CANARY_NOT_FOUND
                    )
            else:
                # 远程检查 (通过 SSH 或 Docker exec)
                check_cmd = f"cat {self.canary_path} 2>/dev/null"
                
                if 'docker_container' in context:
                    container = context['docker_container']
                    result = subprocess.run(
                        ['docker', 'exec', container, 'sh', '-c', check_cmd],
                        capture_output=True, text=True, timeout=10
                    )
                else:
                    # 假设可以直接执行（容器环境）
                    result = subprocess.run(
                        ['sh', '-c', check_cmd],
                        capture_output=True, text=True, timeout=10
                    )
                
                if result.returncode == 0 and self.canary_content in result.stdout:
                    return VerificationResult(
                        success=True,
                        confidence=1.0,
                        evidence=f"Canary file created with expected content",
                        evidence_type="canary",
                        details={
                            "canary_path": self.canary_path,
                            "actual_content": result.stdout.strip()
                        }
                    )
                else:
                    return VerificationResult(
                        success=False,
                        confidence=0.0,
                        evidence=f"Canary file not found or content mismatch",
                        evidence_type="canary",
                        details={
                            "canary_path": self.canary_path,
                            "stdout": result.stdout,
                            "stderr": result.stderr
                        },
                        failure_code=FailureCode.V004_CANARY_NOT_FOUND
                    )
                    
        except Exception as e:
            return VerificationResult(
                success=False,
                confidence=0.0,
                evidence=f"Verification error: {str(e)}",
                evidence_type="error",
                details={"error": str(e)},
                failure_code=FailureCode.V003_ORACLE_FAILED
            )


class SQLiOracle(HardenedOracle):
    """
    SQL 注入漏洞验证 Oracle
    
    验证方式:
    1. 时间盲注: 检测响应时间差异
    2. 布尔盲注: 检测响应内容差异
    3. 联合注入: 检测注入数据在响应中出现
    4. 堆叠注入: 检查数据库状态变化
    """
    
    def __init__(self, technique: str = "time_based", delay_seconds: float = 5.0):
        """
        Args:
            technique: time_based, boolean, union, stacked
            delay_seconds: 时间盲注的延迟秒数
        """
        self.technique = technique
        self.delay_seconds = delay_seconds
    
    def get_required_evidence(self) -> List[str]:
        return ["response_time_diff", "response_content_diff", "injected_data"]
    
    def verify(self, context: Dict[str, Any]) -> VerificationResult:
        """
        验证 SQLi 是否成功
        
        context 应包含:
            - baseline_time: 正常请求的响应时间
            - injected_time: 注入请求的响应时间
            - baseline_response: 正常响应
            - injected_response: 注入响应
            - canary_value: 金丝雀值 (用于 union 注入)
        """
        if self.technique == "time_based":
            return self._verify_time_based(context)
        elif self.technique == "boolean":
            return self._verify_boolean(context)
        elif self.technique == "union":
            return self._verify_union(context)
        else:
            return VerificationResult(
                success=False,
                confidence=0.0,
                evidence=f"Unknown technique: {self.technique}",
                evidence_type="error",
                details={},
                failure_code=FailureCode.V003_ORACLE_FAILED
            )
    
    def _verify_time_based(self, context: Dict[str, Any]) -> VerificationResult:
        """时间盲注验证"""
        baseline_time = context.get('baseline_time', 0)
        injected_time = context.get('injected_time', 0)
        
        time_diff = injected_time - baseline_time
        
        # 统计显著性检验：注入响应应该比基线慢至少 delay_seconds * 0.8
        threshold = self.delay_seconds * 0.8
        
        if time_diff >= threshold:
            confidence = min(1.0, time_diff / self.delay_seconds)
            return VerificationResult(
                success=True,
                confidence=confidence,
                evidence=f"Time-based SQLi confirmed: {time_diff:.2f}s delay (threshold: {threshold:.2f}s)",
                evidence_type="response_time_diff",
                details={
                    "baseline_time": baseline_time,
                    "injected_time": injected_time,
                    "time_diff": time_diff,
                    "threshold": threshold
                }
            )
        else:
            return VerificationResult(
                success=False,
                confidence=0.0,
                evidence=f"No significant time delay: {time_diff:.2f}s (need >= {threshold:.2f}s)",
                evidence_type="response_time_diff",
                details={
                    "baseline_time": baseline_time,
                    "injected_time": injected_time,
                    "time_diff": time_diff
                },
                failure_code=FailureCode.V001_NO_EVIDENCE
            )
    
    def _verify_boolean(self, context: Dict[str, Any]) -> VerificationResult:
        """布尔盲注验证"""
        true_response = context.get('true_response', '')
        false_response = context.get('false_response', '')
        
        # 检查响应差异
        if true_response != false_response:
            # 计算相似度
            from difflib import SequenceMatcher
            similarity = SequenceMatcher(None, true_response, false_response).ratio()
            
            if similarity < 0.95:  # 有显著差异
                return VerificationResult(
                    success=True,
                    confidence=1.0 - similarity,
                    evidence=f"Boolean SQLi confirmed: responses differ by {(1-similarity)*100:.1f}%",
                    evidence_type="response_content_diff",
                    details={
                        "similarity": similarity,
                        "true_length": len(true_response),
                        "false_length": len(false_response)
                    }
                )
        
        return VerificationResult(
            success=False,
            confidence=0.0,
            evidence="No significant response difference",
            evidence_type="response_content_diff",
            details={},
            failure_code=FailureCode.V001_NO_EVIDENCE
        )
    
    def _verify_union(self, context: Dict[str, Any]) -> VerificationResult:
        """联合注入验证"""
        canary_value = context.get('canary_value', '')
        response = context.get('response', '')
        
        if canary_value and canary_value in response:
            return VerificationResult(
                success=True,
                confidence=1.0,
                evidence=f"Union SQLi confirmed: canary '{canary_value}' found in response",
                evidence_type="injected_data",
                details={"canary_value": canary_value}
            )
        
        return VerificationResult(
            success=False,
            confidence=0.0,
            evidence=f"Canary value not found in response",
            evidence_type="injected_data",
            details={"canary_value": canary_value},
            failure_code=FailureCode.V004_CANARY_NOT_FOUND
        )


class XSSOracle(HardenedOracle):
    """
    XSS 漏洞验证 Oracle
    
    验证方式:
    1. DOM 检测: 检查注入的 DOM 元素是否存在
    2. Script 执行: 检查 JavaScript 是否执行（通过副作用）
    3. Cookie 窃取模拟: 检查 cookie 是否可访问
    """
    
    def __init__(self, canary_id: str):
        self.canary_id = canary_id
    
    def get_required_evidence(self) -> List[str]:
        return ["dom_element", "script_executed", "alert_triggered"]
    
    def verify(self, context: Dict[str, Any]) -> VerificationResult:
        """
        验证 XSS 是否成功
        
        context 应包含:
            - page_source: 页面 HTML 源码
            - dom_snapshot: DOM 快照 (如果使用 Playwright)
            - alerts: 触发的 alert 列表
            - console_logs: 控制台日志
        """
        page_source = context.get('page_source', '')
        alerts = context.get('alerts', [])
        console_logs = context.get('console_logs', [])
        
        evidence_found = []
        confidence = 0.0
        
        # 1. 检查 DOM 金丝雀
        canary_pattern = f'id="xss_canary_{self.canary_id}"'
        if canary_pattern in page_source or f'xss_canary_{self.canary_id}' in page_source:
            evidence_found.append("DOM canary found")
            confidence = max(confidence, 0.9)
        
        # 2. 检查 alert 触发
        if alerts:
            evidence_found.append(f"Alert triggered: {alerts}")
            confidence = max(confidence, 1.0)
        
        # 3. 检查控制台日志中的金丝雀
        for log in console_logs:
            if self.canary_id in str(log):
                evidence_found.append(f"Console canary: {log}")
                confidence = max(confidence, 0.95)
        
        # 4. 检查常见 XSS payload 特征
        xss_patterns = [
            r'<script[^>]*>.*?</script>',
            r'onerror\s*=\s*["\']',
            r'onload\s*=\s*["\']',
            r'javascript:',
        ]
        
        for pattern in xss_patterns:
            if re.search(pattern, page_source, re.IGNORECASE):
                evidence_found.append(f"XSS pattern matched: {pattern}")
                confidence = max(confidence, 0.7)
        
        if evidence_found:
            return VerificationResult(
                success=True,
                confidence=confidence,
                evidence="; ".join(evidence_found),
                evidence_type="dom_element",
                details={
                    "canary_id": self.canary_id,
                    "evidence_items": evidence_found,
                    "alerts": alerts
                }
            )
        
        return VerificationResult(
            success=False,
            confidence=0.0,
            evidence="No XSS evidence found",
            evidence_type="dom_element",
            details={"canary_id": self.canary_id},
            failure_code=FailureCode.V001_NO_EVIDENCE
        )


class SSRFOracle(HardenedOracle):
    """
    SSRF 漏洞验证 Oracle
    
    验证方式: 检查是否收到来自目标服务器的请求
    """
    
    def __init__(self, canary_id: str, expected_source: str = None):
        self.canary_id = canary_id
        self.expected_source = expected_source
    
    def get_required_evidence(self) -> List[str]:
        return ["callback_received", "source_ip_match"]
    
    def verify(self, context: Dict[str, Any]) -> VerificationResult:
        """
        验证 SSRF 是否成功
        
        context 应包含:
            - callback_log: 回调服务器的请求日志
            - response: 目标服务器的响应（可能包含内网信息）
        """
        callback_log = context.get('callback_log', '')
        response = context.get('response', '')
        
        # 1. 检查回调日志中是否有金丝雀
        if self.canary_id in callback_log:
            return VerificationResult(
                success=True,
                confidence=1.0,
                evidence=f"SSRF callback received with canary: {self.canary_id}",
                evidence_type="callback_received",
                details={
                    "canary_id": self.canary_id,
                    "callback_log": callback_log[:500]
                }
            )
        
        # 2. 检查响应中是否有内网特征
        internal_patterns = [
            r'169\.254\.\d+\.\d+',           # AWS metadata
            r'127\.0\.0\.\d+',               # localhost
            r'10\.\d+\.\d+\.\d+',            # 内网 A 类
            r'172\.(1[6-9]|2\d|3[0-1])\.',   # 内网 B 类
            r'192\.168\.\d+\.\d+',           # 内网 C 类
            r'localhost',
            r'internal',
        ]
        
        for pattern in internal_patterns:
            if re.search(pattern, response, re.IGNORECASE):
                return VerificationResult(
                    success=True,
                    confidence=0.8,
                    evidence=f"SSRF detected: internal resource pattern '{pattern}' in response",
                    evidence_type="response_content",
                    details={
                        "pattern_matched": pattern,
                        "response_snippet": response[:500]
                    }
                )
        
        return VerificationResult(
            success=False,
            confidence=0.0,
            evidence="No SSRF evidence found",
            evidence_type="callback_received",
            details={"canary_id": self.canary_id},
            failure_code=FailureCode.V001_NO_EVIDENCE
        )


class InfoLeakOracle(HardenedOracle):
    """
    信息泄露验证 Oracle
    
    验证方式: 检查预埋的敏感数据是否被泄露
    """
    
    def __init__(self, canary_name: str, canary_value: str):
        self.canary_name = canary_name
        self.canary_value = canary_value
    
    def get_required_evidence(self) -> List[str]:
        return ["canary_leaked", "sensitive_pattern"]
    
    def verify(self, context: Dict[str, Any]) -> VerificationResult:
        """
        验证信息泄露是否成功
        
        context 应包含:
            - response: 响应内容
            - file_content: 读取的文件内容
        """
        response = context.get('response', '')
        file_content = context.get('file_content', '')
        
        content_to_check = response + file_content
        
        # 1. 检查金丝雀值
        if self.canary_value in content_to_check:
            return VerificationResult(
                success=True,
                confidence=1.0,
                evidence=f"Canary value '{self.canary_value}' found in response - data leaked",
                evidence_type="canary_leaked",
                details={
                    "canary_name": self.canary_name,
                    "canary_value": self.canary_value
                }
            )
        
        # 2. 检查常见敏感信息模式
        sensitive_patterns = [
            (r'password\s*[=:]\s*\S+', 'password'),
            (r'api[_-]?key\s*[=:]\s*\S+', 'api_key'),
            (r'secret\s*[=:]\s*\S+', 'secret'),
            (r'token\s*[=:]\s*[a-zA-Z0-9]+', 'token'),
            (r'-----BEGIN.*PRIVATE KEY-----', 'private_key'),
            (r'/etc/passwd', 'passwd_file'),
            (r'root:.*:0:0:', 'passwd_entry'),
        ]
        
        for pattern, pattern_name in sensitive_patterns:
            match = re.search(pattern, content_to_check, re.IGNORECASE)
            if match:
                return VerificationResult(
                    success=True,
                    confidence=0.85,
                    evidence=f"Sensitive pattern '{pattern_name}' found: {match.group(0)[:50]}...",
                    evidence_type="sensitive_pattern",
                    details={
                        "pattern_name": pattern_name,
                        "matched": match.group(0)[:100]
                    }
                )
        
        return VerificationResult(
            success=False,
            confidence=0.0,
            evidence="No information leak evidence found",
            evidence_type="canary_leaked",
            details={
                "canary_name": self.canary_name,
                "checked_length": len(content_to_check)
            },
            failure_code=FailureCode.V001_NO_EVIDENCE
        )


class HardenedVerifier:
    """
    强化验证器 - 根据漏洞类型选择合适的 Oracle
    
    不信任 LLM 自判断，强制使用结构化验证。
    """
    
    # 漏洞类型关键词映射
    VULN_TYPE_KEYWORDS = {
        VulnType.RCE: ['rce', 'remote code', 'command injection', 'code execution', 'os command'],
        VulnType.SQLI: ['sql injection', 'sqli', 'sql注入'],
        VulnType.XSS: ['xss', 'cross-site scripting', 'cross site scripting', '跨站脚本'],
        VulnType.SSRF: ['ssrf', 'server-side request', 'server side request'],
        VulnType.LFI: ['lfi', 'local file', 'file inclusion', 'file read'],
        VulnType.PATH_TRAVERSAL: ['path traversal', 'directory traversal', '../', '路径遍历'],
        VulnType.AUTH_BYPASS: ['auth bypass', 'authentication bypass', '认证绕过', 'unauthorized'],
        VulnType.INFO_LEAK: ['information disclosure', 'info leak', 'data exposure', '信息泄露'],
        VulnType.CSRF: ['csrf', 'cross-site request forgery'],
        VulnType.XXE: ['xxe', 'xml external entity'],
        VulnType.SSTI: ['ssti', 'template injection', '模板注入'],
        VulnType.DESERIALIZATION: ['deserialization', 'unserialize', '反序列化'],
    }
    
    @classmethod
    def detect_vuln_type(cls, cve_description: str) -> VulnType:
        """从 CVE 描述中检测漏洞类型"""
        desc_lower = cve_description.lower()
        
        for vuln_type, keywords in cls.VULN_TYPE_KEYWORDS.items():
            for keyword in keywords:
                if keyword in desc_lower:
                    return vuln_type
        
        return VulnType.UNKNOWN
    
    @classmethod
    def create_oracle(cls, vuln_type: VulnType) -> Tuple[HardenedOracle, Dict[str, Any]]:
        """
        根据漏洞类型创建 Oracle 和金丝雀
        
        Returns:
            (oracle, canary_info)
        """
        if vuln_type == VulnType.RCE:
            canary_path, canary_content = CanaryGenerator.generate_file_canary()
            oracle = RCEOracle(canary_path, canary_content)
            canary_info = {
                'type': 'file',
                'path': canary_path,
                'content': canary_content,
                'payload_template': f'echo "{canary_content}" > {canary_path}'
            }
            return oracle, canary_info
        
        elif vuln_type == VulnType.SQLI:
            canary_marker, canary_value = CanaryGenerator.generate_db_canary()
            oracle = SQLiOracle(technique='union')
            canary_info = {
                'type': 'db',
                'marker': canary_marker,
                'value': canary_value,
                'payload_template': f"' UNION SELECT '{canary_value}'--"
            }
            return oracle, canary_info
        
        elif vuln_type == VulnType.XSS:
            canary_id, canary_script = CanaryGenerator.generate_dom_canary()
            oracle = XSSOracle(canary_id)
            canary_info = {
                'type': 'dom',
                'id': canary_id,
                'script': canary_script,
                'payload_template': canary_script
            }
            return oracle, canary_info
        
        elif vuln_type == VulnType.SSRF:
            canary_id, canary_url = CanaryGenerator.generate_ssrf_canary()
            oracle = SSRFOracle(canary_id)
            canary_info = {
                'type': 'callback',
                'id': canary_id,
                'url': canary_url,
                'payload_template': canary_url
            }
            return oracle, canary_info
        
        elif vuln_type in [VulnType.LFI, VulnType.PATH_TRAVERSAL, VulnType.INFO_LEAK]:
            canary_name, canary_value = CanaryGenerator.generate_secret_canary()
            oracle = InfoLeakOracle(canary_name, canary_value)
            canary_info = {
                'type': 'secret',
                'name': canary_name,
                'value': canary_value,
                'note': 'Pre-plant this value in target file/env before exploit'
            }
            return oracle, canary_info
        
        else:
            # 默认使用 RCE Oracle（可以检测任何写文件的行为）
            canary_path, canary_content = CanaryGenerator.generate_file_canary()
            oracle = RCEOracle(canary_path, canary_content)
            canary_info = {
                'type': 'generic',
                'path': canary_path,
                'content': canary_content
            }
            return oracle, canary_info
    
    @classmethod
    def create_oob_oracle(cls, vuln_type: VulnType) -> Tuple['OOBEnhancedOracle', Dict[str, Any]]:
        """
        创建带 OOB 验证的 Oracle（用于无回显漏洞）
        
        Args:
            vuln_type: 漏洞类型
            
        Returns:
            (oracle, oob_info) 包含 OOB URL 等信息
        """
        try:
            from verification.oob_verifier import OOBVerifier, OOBType
            
            verifier = OOBVerifier()
            token = verifier.generate_oob_payload(
                OOBType.HTTP if vuln_type != VulnType.XXE else OOBType.HTTP
            )
            
            oracle = OOBEnhancedOracle(verifier, token, vuln_type)
            oob_info = {
                'type': 'oob',
                'vuln_type': vuln_type.value,
                'oob_url': token.http_url,
                'oob_domain': token.dns_domain,
                'token_id': token.token_id,
                'note': f'Use this URL in your {vuln_type.value} payload for OOB verification'
            }
            return oracle, oob_info
            
        except ImportError:
            print("[HardenedVerifier] Warning: OOB module not available, using standard oracle")
            return cls.create_oracle(vuln_type)
    
    def __init__(self, vuln_type: VulnType = None, cve_description: str = None):
        """
        初始化强化验证器
        
        Args:
            vuln_type: 漏洞类型（如果已知）
            cve_description: CVE 描述（用于自动检测漏洞类型）
        """
        if vuln_type:
            self.vuln_type = vuln_type
        elif cve_description:
            self.vuln_type = self.detect_vuln_type(cve_description)
        else:
            self.vuln_type = VulnType.UNKNOWN
        
        self.oracle, self.canary_info = self.create_oracle(self.vuln_type)
    
    def get_canary_payload(self) -> str:
        """获取金丝雀 payload 模板"""
        return self.canary_info.get('payload_template', '')
    
    def verify(self, context: Dict[str, Any], llm_verdict: str = None) -> VerificationResult:
        """
        执行验证
        
        Args:
            context: 验证上下文
            llm_verdict: LLM 的判断（仅用于记录，不影响结果）
        
        Returns:
            VerificationResult
        """
        # 执行 Oracle 验证
        result = self.oracle.verify(context)
        
        # 记录 LLM 判断（但不信任它）
        if llm_verdict:
            result.details['llm_verdict'] = llm_verdict
            
            # 如果 LLM 说成功但 Oracle 说失败，记录为可疑
            if 'success' in llm_verdict.lower() and not result.success:
                result.details['warning'] = 'LLM claims success but Oracle found no evidence - possible false positive'
        
        return result


class OOBEnhancedOracle(HardenedOracle):
    """
    OOB 增强的 Oracle
    
    用于验证无回显漏洞（Blind RCE, SSRF, Blind SQLi, XXE 等）
    """
    
    def __init__(self, oob_verifier: 'OOBVerifier', token: 'OOBToken', vuln_type: VulnType):
        self.oob_verifier = oob_verifier
        self.token = token
        self.vuln_type = vuln_type
    
    def get_required_evidence(self) -> List[str]:
        return ["oob_callback"]
    
    def verify(self, context: Dict[str, Any]) -> VerificationResult:
        """
        使用 OOB 验证漏洞
        
        context 应包含:
            - timeout: OOB 等待超时（默认 30 秒）
            - exploit_executed: 布尔值，表示 exploit 是否已执行
        """
        timeout = context.get('timeout', 30.0)
        
        # 检查 exploit 是否已执行
        if not context.get('exploit_executed', True):
            return VerificationResult(
                success=False,
                confidence=0.0,
                evidence="Exploit not executed yet",
                evidence_type="oob_callback",
                details={"oob_url": self.token.http_url},
                failure_code=FailureCode.T001_EXPLOIT_NOT_TRIGGERED
            )
        
        # 执行 OOB 验证
        oob_result = self.oob_verifier.verify(self.token, timeout=timeout)
        
        if oob_result.verified:
            return VerificationResult(
                success=True,
                confidence=oob_result.confidence,
                evidence=oob_result.evidence,
                evidence_type="oob_callback",
                details={
                    "oob_url": self.token.http_url,
                    "interactions": len(oob_result.interactions),
                    "vuln_type": self.vuln_type.value
                }
            )
        else:
            return VerificationResult(
                success=False,
                confidence=0.0,
                evidence="No OOB callback received",
                evidence_type="oob_callback",
                details={
                    "oob_url": self.token.http_url,
                    "timeout": timeout,
                    "failure_reason": oob_result.failure_reason
                },
                failure_code=FailureCode.V001_NO_EVIDENCE
            )
    
    def cleanup(self):
        """清理 OOB 资源"""
        if hasattr(self.oob_verifier, 'cleanup'):
            self.oob_verifier.cleanup()
