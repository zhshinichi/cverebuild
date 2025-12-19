"""
增强的健康检查 - 让系统"可重复、可回归"

不只是 HTTP 200，而是全面的环境就绪性检查：
1. HTTP 可达性
2. 框架特定端点
3. 日志特征
4. 数据库连接
5. 依赖服务状态
"""

import re
import time
import subprocess
from typing import Dict, Any, List, Optional, Tuple
from dataclasses import dataclass
from enum import Enum

from core.failure_codes import FailureCode, FailureDetail, FailureAnalyzer


class CheckStatus(Enum):
    """检查状态"""
    PASSED = "passed"
    FAILED = "failed"
    SKIPPED = "skipped"
    WARNING = "warning"


@dataclass
class CheckResult:
    """单项检查结果"""
    name: str
    status: CheckStatus
    message: str
    details: Dict[str, Any]
    duration_ms: float = 0


@dataclass
class HealthReport:
    """健康检查报告"""
    healthy: bool
    checks: List[CheckResult]
    failure_code: Optional[FailureCode]
    summary: str
    total_duration_ms: float
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "healthy": self.healthy,
            "checks": [
                {
                    "name": c.name,
                    "status": c.status.value,
                    "message": c.message,
                    "details": c.details,
                    "duration_ms": c.duration_ms
                }
                for c in self.checks
            ],
            "failure_code": self.failure_code.value if self.failure_code else None,
            "summary": self.summary,
            "total_duration_ms": self.total_duration_ms
        }


class EnhancedHealthCheck:
    """
    增强的健康检查
    
    特点：
    1. 多维度检查（HTTP、端口、日志、进程）
    2. 框架感知（Django、Flask、Spring 等有不同的检查点）
    3. 结构化报告（精确定位失败原因）
    4. 重试机制（服务启动可能需要时间）
    """
    
    # 框架特定的健康检查端点
    FRAMEWORK_CHECKS = {
        'django': {
            'endpoints': ['/', '/admin/', '/static/'],
            'expected_patterns': ['django', 'csrftoken', 'admin'],
            'log_patterns': ['Starting development server', 'Quit the server'],
        },
        'flask': {
            'endpoints': ['/', '/health', '/api'],
            'expected_patterns': ['flask', 'werkzeug'],
            'log_patterns': ['Running on http', 'Debugger is active'],
        },
        'fastapi': {
            'endpoints': ['/', '/docs', '/openapi.json', '/health'],
            'expected_patterns': ['fastapi', 'swagger', 'openapi'],
            'log_patterns': ['Uvicorn running', 'Application startup'],
        },
        'spring': {
            'endpoints': ['/', '/actuator/health', '/actuator/info'],
            'expected_patterns': ['status', 'UP', 'actuator'],
            'log_patterns': ['Started Application', 'Tomcat started'],
        },
        'express': {
            'endpoints': ['/', '/api', '/health'],
            'expected_patterns': [],
            'log_patterns': ['listening on port', 'Express server'],
        },
        'laravel': {
            'endpoints': ['/', '/api'],
            'expected_patterns': ['laravel', 'csrf'],
            'log_patterns': ['Laravel development server started'],
        },
        'symfony': {
            'endpoints': ['/', '/_profiler', '/api'],
            'expected_patterns': ['symfony'],
            'log_patterns': ['Server running', 'Web server listening'],
        },
        'rails': {
            'endpoints': ['/', '/rails/info'],
            'expected_patterns': ['rails', 'ruby'],
            'log_patterns': ['Puma starting', 'Listening on'],
        },
        'nextjs': {
            'endpoints': ['/', '/api', '/_next'],
            'expected_patterns': ['_next', '__NEXT_DATA__'],
            'log_patterns': ['ready on', 'started server'],
        },
        'generic': {
            'endpoints': ['/'],
            'expected_patterns': [],
            'log_patterns': [],
        }
    }
    
    # 常见 Web 服务器的日志模式
    SERVER_LOG_PATTERNS = {
        'nginx': r'nginx.*start|worker process',
        'apache': r'Apache.*start|httpd.*start',
        'gunicorn': r'gunicorn.*Listening|Booting worker',
        'uvicorn': r'Uvicorn running|Application startup',
        'php-fpm': r'fpm is running|ready to handle connections',
        'node': r'listening on|server started',
        'tomcat': r'Catalina.*start|Server startup',
    }
    
    def __init__(
        self,
        target_url: str,
        framework: str = 'generic',
        timeout_seconds: float = 30,
        retry_count: int = 3,
        retry_delay: float = 2.0
    ):
        """
        初始化健康检查器
        
        Args:
            target_url: 目标 URL (如 http://localhost:8080)
            framework: 框架类型
            timeout_seconds: 单次检查超时
            retry_count: 重试次数
            retry_delay: 重试间隔（秒）
        """
        self.target_url = target_url.rstrip('/')
        self.framework = framework.lower() if framework else 'generic'
        self.timeout = timeout_seconds
        self.retry_count = retry_count
        self.retry_delay = retry_delay
        
        # 提取端口
        import urllib.parse
        parsed = urllib.parse.urlparse(self.target_url)
        self.host = parsed.hostname or 'localhost'
        self.port = parsed.port or 80
    
    def check(
        self,
        expected_log_patterns: List[str] = None,
        custom_endpoints: List[str] = None,
        docker_container: str = None
    ) -> HealthReport:
        """
        执行完整的健康检查
        
        Args:
            expected_log_patterns: 期望在日志中出现的模式
            custom_endpoints: 自定义检查端点
            docker_container: Docker 容器名/ID（用于检查容器内状态）
        
        Returns:
            HealthReport
        """
        start_time = time.time()
        checks: List[CheckResult] = []
        
        # 获取框架配置
        framework_config = self.FRAMEWORK_CHECKS.get(self.framework, self.FRAMEWORK_CHECKS['generic'])
        
        # 1. 端口监听检查
        checks.append(self._check_port_listening(docker_container))
        
        # 2. HTTP 可达性检查（带重试）
        http_check = self._check_http_reachable()
        checks.append(http_check)
        
        # 3. 框架特定端点检查
        endpoints = custom_endpoints or framework_config['endpoints']
        for endpoint in endpoints[:3]:  # 最多检查 3 个端点
            checks.append(self._check_endpoint(endpoint))
        
        # 4. 响应内容检查
        if framework_config['expected_patterns']:
            checks.append(self._check_response_patterns(framework_config['expected_patterns']))
        
        # 5. 日志模式检查（如果提供）
        all_log_patterns = (expected_log_patterns or []) + framework_config.get('log_patterns', [])
        if all_log_patterns and docker_container:
            checks.append(self._check_log_patterns(all_log_patterns, docker_container))
        
        # 6. 进程状态检查（如果是 Docker）
        if docker_container:
            checks.append(self._check_container_status(docker_container))
        
        # 计算总体结果
        total_duration = (time.time() - start_time) * 1000
        
        # 判断整体健康状态
        critical_checks = ['port_listening', 'http_reachable']
        critical_passed = all(
            c.status == CheckStatus.PASSED 
            for c in checks 
            if c.name in critical_checks
        )
        
        all_passed = all(c.status in [CheckStatus.PASSED, CheckStatus.SKIPPED, CheckStatus.WARNING] for c in checks)
        
        # 确定失败原因码
        failure_code = None
        if not critical_passed:
            failed_check = next((c for c in checks if c.status == CheckStatus.FAILED), None)
            if failed_check:
                failure_code = self._determine_failure_code(failed_check)
        
        # 生成摘要
        passed_count = sum(1 for c in checks if c.status == CheckStatus.PASSED)
        total_count = len(checks)
        
        if critical_passed and all_passed:
            summary = f"✅ 服务健康 ({passed_count}/{total_count} 检查通过)"
        elif critical_passed:
            summary = f"⚠️ 服务基本可用，但有警告 ({passed_count}/{total_count} 检查通过)"
        else:
            failed_names = [c.name for c in checks if c.status == CheckStatus.FAILED]
            summary = f"❌ 服务不健康: {', '.join(failed_names)} 检查失败"
        
        return HealthReport(
            healthy=critical_passed,
            checks=checks,
            failure_code=failure_code,
            summary=summary,
            total_duration_ms=total_duration
        )
    
    def _check_port_listening(self, docker_container: str = None) -> CheckResult:
        """检查端口是否在监听"""
        start = time.time()
        
        try:
            if docker_container:
                # 在容器内检查
                result = subprocess.run(
                    ['docker', 'exec', docker_container, 'sh', '-c', 
                     f'netstat -tlnp 2>/dev/null | grep :{self.port} || ss -tlnp 2>/dev/null | grep :{self.port}'],
                    capture_output=True, text=True, timeout=5
                )
                listening = result.returncode == 0 and str(self.port) in result.stdout
            else:
                # 本地检查
                import socket
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                result = sock.connect_ex((self.host, self.port))
                sock.close()
                listening = (result == 0)
            
            duration = (time.time() - start) * 1000
            
            if listening:
                return CheckResult(
                    name="port_listening",
                    status=CheckStatus.PASSED,
                    message=f"Port {self.port} is listening",
                    details={"port": self.port, "host": self.host},
                    duration_ms=duration
                )
            else:
                return CheckResult(
                    name="port_listening",
                    status=CheckStatus.FAILED,
                    message=f"Port {self.port} is not listening",
                    details={"port": self.port, "host": self.host},
                    duration_ms=duration
                )
        except Exception as e:
            return CheckResult(
                name="port_listening",
                status=CheckStatus.FAILED,
                message=f"Port check failed: {str(e)}",
                details={"error": str(e)},
                duration_ms=(time.time() - start) * 1000
            )
    
    def _check_http_reachable(self) -> CheckResult:
        """检查 HTTP 是否可达（带重试）"""
        start = time.time()
        last_error = None
        last_status_code = 0
        
        for attempt in range(self.retry_count):
            try:
                result = subprocess.run(
                    ['curl', '-s', '-o', '/dev/null', '-w', '%{http_code}', 
                     '--max-time', str(int(self.timeout)), self.target_url],
                    capture_output=True, text=True, timeout=self.timeout + 5
                )
                
                status_code = int(result.stdout.strip()) if result.stdout.strip().isdigit() else 0
                last_status_code = status_code
                
                # 2xx, 3xx, 404 都认为服务在运行
                if status_code in range(200, 400) or status_code == 404:
                    return CheckResult(
                        name="http_reachable",
                        status=CheckStatus.PASSED,
                        message=f"HTTP {status_code} - Service is responding",
                        details={
                            "url": self.target_url,
                            "status_code": status_code,
                            "attempts": attempt + 1
                        },
                        duration_ms=(time.time() - start) * 1000
                    )
                
                # 其他状态码，继续重试
                last_error = f"HTTP {status_code}"
                
            except subprocess.TimeoutExpired:
                last_error = "Request timeout"
            except Exception as e:
                last_error = str(e)
            
            # 等待后重试
            if attempt < self.retry_count - 1:
                time.sleep(self.retry_delay)
        
        return CheckResult(
            name="http_reachable",
            status=CheckStatus.FAILED,
            message=f"Service not reachable after {self.retry_count} attempts: {last_error}",
            details={
                "url": self.target_url,
                "last_status_code": last_status_code,
                "last_error": last_error,
                "attempts": self.retry_count
            },
            duration_ms=(time.time() - start) * 1000
        )
    
    def _check_endpoint(self, endpoint: str) -> CheckResult:
        """检查特定端点"""
        start = time.time()
        url = f"{self.target_url}{endpoint}"
        
        try:
            result = subprocess.run(
                ['curl', '-s', '-o', '/dev/null', '-w', '%{http_code}', 
                 '--max-time', '5', url],
                capture_output=True, text=True, timeout=10
            )
            
            status_code = int(result.stdout.strip()) if result.stdout.strip().isdigit() else 0
            
            # 任何非 5xx 响应都认为端点存在
            if status_code > 0 and status_code < 500:
                return CheckResult(
                    name=f"endpoint_{endpoint}",
                    status=CheckStatus.PASSED,
                    message=f"Endpoint {endpoint} responds with HTTP {status_code}",
                    details={"endpoint": endpoint, "status_code": status_code},
                    duration_ms=(time.time() - start) * 1000
                )
            else:
                return CheckResult(
                    name=f"endpoint_{endpoint}",
                    status=CheckStatus.WARNING,
                    message=f"Endpoint {endpoint} returns HTTP {status_code}",
                    details={"endpoint": endpoint, "status_code": status_code},
                    duration_ms=(time.time() - start) * 1000
                )
        except Exception as e:
            return CheckResult(
                name=f"endpoint_{endpoint}",
                status=CheckStatus.WARNING,
                message=f"Endpoint check failed: {str(e)}",
                details={"endpoint": endpoint, "error": str(e)},
                duration_ms=(time.time() - start) * 1000
            )
    
    def _check_response_patterns(self, patterns: List[str]) -> CheckResult:
        """检查响应内容中的特征模式"""
        start = time.time()
        
        try:
            result = subprocess.run(
                ['curl', '-s', '--max-time', '5', self.target_url],
                capture_output=True, text=True, timeout=10
            )
            
            response = result.stdout.lower()
            matched = []
            missing = []
            
            for pattern in patterns:
                if pattern.lower() in response:
                    matched.append(pattern)
                else:
                    missing.append(pattern)
            
            if matched:
                return CheckResult(
                    name="response_patterns",
                    status=CheckStatus.PASSED if len(matched) >= len(patterns) / 2 else CheckStatus.WARNING,
                    message=f"Found {len(matched)}/{len(patterns)} expected patterns",
                    details={"matched": matched, "missing": missing},
                    duration_ms=(time.time() - start) * 1000
                )
            else:
                return CheckResult(
                    name="response_patterns",
                    status=CheckStatus.WARNING,
                    message="No expected patterns found in response",
                    details={"patterns": patterns},
                    duration_ms=(time.time() - start) * 1000
                )
        except Exception as e:
            return CheckResult(
                name="response_patterns",
                status=CheckStatus.SKIPPED,
                message=f"Pattern check skipped: {str(e)}",
                details={"error": str(e)},
                duration_ms=(time.time() - start) * 1000
            )
    
    def _check_log_patterns(self, patterns: List[str], docker_container: str) -> CheckResult:
        """检查容器日志中的模式"""
        start = time.time()
        
        try:
            result = subprocess.run(
                ['docker', 'logs', '--tail', '100', docker_container],
                capture_output=True, text=True, timeout=10
            )
            
            logs = result.stdout + result.stderr
            matched = []
            
            for pattern in patterns:
                if re.search(pattern, logs, re.IGNORECASE):
                    matched.append(pattern)
            
            if matched:
                return CheckResult(
                    name="log_patterns",
                    status=CheckStatus.PASSED,
                    message=f"Found {len(matched)}/{len(patterns)} log patterns",
                    details={"matched": matched},
                    duration_ms=(time.time() - start) * 1000
                )
            else:
                return CheckResult(
                    name="log_patterns",
                    status=CheckStatus.WARNING,
                    message="Expected log patterns not found",
                    details={"patterns": patterns, "log_snippet": logs[-500:]},
                    duration_ms=(time.time() - start) * 1000
                )
        except Exception as e:
            return CheckResult(
                name="log_patterns",
                status=CheckStatus.SKIPPED,
                message=f"Log check skipped: {str(e)}",
                details={"error": str(e)},
                duration_ms=(time.time() - start) * 1000
            )
    
    def _check_container_status(self, docker_container: str) -> CheckResult:
        """检查 Docker 容器状态"""
        start = time.time()
        
        try:
            result = subprocess.run(
                ['docker', 'inspect', '--format', '{{.State.Status}}', docker_container],
                capture_output=True, text=True, timeout=5
            )
            
            status = result.stdout.strip()
            
            if status == 'running':
                return CheckResult(
                    name="container_status",
                    status=CheckStatus.PASSED,
                    message=f"Container '{docker_container}' is running",
                    details={"container": docker_container, "status": status},
                    duration_ms=(time.time() - start) * 1000
                )
            else:
                return CheckResult(
                    name="container_status",
                    status=CheckStatus.FAILED,
                    message=f"Container '{docker_container}' status: {status}",
                    details={"container": docker_container, "status": status},
                    duration_ms=(time.time() - start) * 1000
                )
        except Exception as e:
            return CheckResult(
                name="container_status",
                status=CheckStatus.SKIPPED,
                message=f"Container check skipped: {str(e)}",
                details={"error": str(e)},
                duration_ms=(time.time() - start) * 1000
            )
    
    def _determine_failure_code(self, failed_check: CheckResult) -> FailureCode:
        """根据失败的检查确定失败原因码"""
        name = failed_check.name
        details = failed_check.details
        
        if name == "port_listening":
            return FailureCode.E003_SERVICE_NOT_RUNNING
        
        elif name == "http_reachable":
            status_code = details.get('last_status_code', 0)
            if status_code == 0:
                return FailureCode.E003_SERVICE_NOT_RUNNING
            elif status_code == 502 or status_code == 503:
                return FailureCode.E003_SERVICE_NOT_RUNNING
            elif status_code == 504:
                return FailureCode.E013_START_TIMEOUT
            else:
                return FailureCode.E014_HEALTH_CHECK_FAILED
        
        elif name == "container_status":
            return FailureCode.E009_DOCKER_ERROR
        
        else:
            return FailureCode.E014_HEALTH_CHECK_FAILED


class EnvironmentValidator:
    """
    环境验证器 - 部署前的环境检查
    
    确保环境满足漏洞复现的前置条件。
    """
    
    @staticmethod
    def validate_prerequisites(
        framework: str,
        version: str,
        docker_available: bool = True
    ) -> List[CheckResult]:
        """
        验证环境前置条件
        
        Args:
            framework: 目标框架
            version: 目标版本
            docker_available: Docker 是否可用
        
        Returns:
            检查结果列表
        """
        checks = []
        
        # 1. 检查 Docker
        if docker_available:
            try:
                result = subprocess.run(
                    ['docker', 'version', '--format', '{{.Server.Version}}'],
                    capture_output=True, text=True, timeout=5
                )
                if result.returncode == 0:
                    checks.append(CheckResult(
                        name="docker_available",
                        status=CheckStatus.PASSED,
                        message=f"Docker version: {result.stdout.strip()}",
                        details={"version": result.stdout.strip()}
                    ))
                else:
                    checks.append(CheckResult(
                        name="docker_available",
                        status=CheckStatus.FAILED,
                        message="Docker not running",
                        details={"error": result.stderr}
                    ))
            except Exception as e:
                checks.append(CheckResult(
                    name="docker_available",
                    status=CheckStatus.FAILED,
                    message=f"Docker check failed: {str(e)}",
                    details={"error": str(e)}
                ))
        
        # 2. 检查网络连通性
        try:
            result = subprocess.run(
                ['curl', '-s', '-o', '/dev/null', '-w', '%{http_code}', 
                 '--max-time', '5', 'https://github.com'],
                capture_output=True, text=True, timeout=10
            )
            status = int(result.stdout.strip()) if result.stdout.strip().isdigit() else 0
            checks.append(CheckResult(
                name="network_available",
                status=CheckStatus.PASSED if status in [200, 301, 302] else CheckStatus.WARNING,
                message=f"Network check: HTTP {status}",
                details={"status_code": status}
            ))
        except Exception as e:
            checks.append(CheckResult(
                name="network_available",
                status=CheckStatus.WARNING,
                message=f"Network check: {str(e)}",
                details={"error": str(e)}
            ))
        
        # 3. 检查磁盘空间
        try:
            result = subprocess.run(
                ['df', '-h', '/'],
                capture_output=True, text=True, timeout=5
            )
            # 简单检查是否有足够空间
            checks.append(CheckResult(
                name="disk_space",
                status=CheckStatus.PASSED,
                message="Disk space available",
                details={"df_output": result.stdout}
            ))
        except Exception:
            checks.append(CheckResult(
                name="disk_space",
                status=CheckStatus.SKIPPED,
                message="Disk check skipped",
                details={}
            ))
        
        return checks


# 便捷函数
def check_service_health(
    target_url: str,
    framework: str = 'generic',
    docker_container: str = None
) -> HealthReport:
    """
    快速健康检查
    
    Args:
        target_url: 目标 URL
        framework: 框架类型
        docker_container: Docker 容器名（可选）
    
    Returns:
        HealthReport
    """
    checker = EnhancedHealthCheck(target_url, framework)
    return checker.check(docker_container=docker_container)


def validate_environment(framework: str, version: str) -> List[CheckResult]:
    """验证环境前置条件"""
    return EnvironmentValidator.validate_prerequisites(framework, version)
