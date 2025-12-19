"""
OOB (Out-of-Band) 验证模块

用于验证无回显漏洞（Blind RCE, SSRF, Blind SQLi, XXE 等）。

支持的 OOB 服务：
1. Interactsh - ProjectDiscovery 的开源 OOB 服务
2. DNSLog.cn - 中国常用的 DNS 日志服务
3. Burp Collaborator - 如果有 Burp Suite Pro
4. 自建 HTTP/DNS Callback Server

工作原理：
1. 生成唯一的 OOB URL/域名
2. 在 exploit payload 中使用这个 URL
3. 检查 OOB 服务器是否收到了请求
4. 如果收到请求，说明漏洞存在
"""

import os
import re
import time
import uuid
import socket
import subprocess
import threading
import requests
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Optional, List, Dict, Any, Tuple
from datetime import datetime
from enum import Enum

try:
    from core.failure_codes import FailureCode
except ImportError:
    FailureCode = None


class OOBType(Enum):
    """OOB 类型"""
    DNS = "dns"
    HTTP = "http"
    HTTPS = "https"
    FTP = "ftp"
    LDAP = "ldap"
    RMI = "rmi"


@dataclass
class OOBToken:
    """OOB Token - 唯一标识符"""
    token_id: str
    full_url: str
    dns_domain: str
    http_url: str
    created_at: datetime = field(default_factory=datetime.now)
    
    def get_payload(self, oob_type: OOBType = OOBType.HTTP) -> str:
        """获取用于 exploit 的 payload"""
        if oob_type == OOBType.DNS:
            return self.dns_domain
        elif oob_type == OOBType.HTTP:
            return self.http_url
        elif oob_type == OOBType.HTTPS:
            return self.http_url.replace("http://", "https://")
        else:
            return self.full_url


@dataclass
class OOBInteraction:
    """OOB 交互记录"""
    token_id: str
    interaction_type: str  # dns, http, smtp, etc.
    remote_address: str
    timestamp: datetime
    raw_request: str = ""
    protocol: str = ""
    details: Dict[str, Any] = field(default_factory=dict)


@dataclass
class OOBVerificationResult:
    """OOB 验证结果"""
    verified: bool
    token: OOBToken
    interactions: List[OOBInteraction]
    confidence: float  # 0.0 - 1.0
    evidence: str
    failure_reason: Optional[str] = None
    failure_code: Optional['FailureCode'] = None


class OOBProvider(ABC):
    """OOB 服务提供者基类"""
    
    @abstractmethod
    def generate_token(self) -> OOBToken:
        """生成新的 OOB token"""
        pass
    
    @abstractmethod
    def poll_interactions(self, token: OOBToken, timeout: float = 30.0) -> List[OOBInteraction]:
        """轮询检查是否有交互"""
        pass
    
    @abstractmethod
    def is_available(self) -> bool:
        """检查服务是否可用"""
        pass


class InteractshProvider(OOBProvider):
    """
    Interactsh OOB 服务提供者
    
    Interactsh 是 ProjectDiscovery 的开源 OOB 服务，支持：
    - DNS
    - HTTP/HTTPS
    - SMTP
    - LDAP
    - FTP
    
    需要安装 interactsh-client 或使用 API
    """
    
    # 公共 Interactsh 服务器
    DEFAULT_SERVERS = [
        "oast.pro",
        "oast.live", 
        "oast.site",
        "oast.online",
        "oast.fun",
        "oast.me",
    ]
    
    def __init__(self, server: str = None):
        self.server = server or self.DEFAULT_SERVERS[0]
        self._client_process = None
        self._token = None
        self._interactions = []
        
    def is_available(self) -> bool:
        """检查 interactsh-client 是否安装"""
        try:
            result = subprocess.run(
                ["which", "interactsh-client"],
                capture_output=True,
                timeout=5
            )
            return result.returncode == 0
        except:
            # 回退到检查是否可以访问公共服务器
            try:
                response = requests.get(f"https://{self.server}", timeout=5)
                return True
            except:
                return False
    
    def generate_token(self) -> OOBToken:
        """生成 Interactsh token"""
        # 生成唯一 ID
        token_id = str(uuid.uuid4())[:8]
        
        # 尝试使用 interactsh-client
        if self._try_start_client():
            # 从客户端获取域名
            dns_domain = f"{token_id}.{self._get_client_domain()}"
        else:
            # 回退到简单的域名生成（需要手动验证）
            dns_domain = f"{token_id}.{self.server}"
        
        http_url = f"http://{dns_domain}"
        
        self._token = OOBToken(
            token_id=token_id,
            full_url=http_url,
            dns_domain=dns_domain,
            http_url=http_url
        )
        return self._token
    
    def _try_start_client(self) -> bool:
        """尝试启动 interactsh-client"""
        try:
            self._client_process = subprocess.Popen(
                ["interactsh-client", "-json", "-v"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            # 等待客户端启动
            time.sleep(2)
            return self._client_process.poll() is None
        except:
            return False
    
    def _get_client_domain(self) -> str:
        """从 interactsh-client 获取分配的域名"""
        if self._client_process and self._client_process.stdout:
            # 读取输出获取域名
            try:
                line = self._client_process.stdout.readline()
                if "INF" in line and "." in line:
                    # 解析域名
                    match = re.search(r'([a-z0-9]+\.[a-z]+\.[a-z]+)', line)
                    if match:
                        return match.group(1)
            except:
                pass
        return self.server
    
    def poll_interactions(self, token: OOBToken, timeout: float = 30.0) -> List[OOBInteraction]:
        """轮询检查交互"""
        interactions = []
        start_time = time.time()
        
        if self._client_process and self._client_process.stdout:
            # 从 interactsh-client 读取交互
            while time.time() - start_time < timeout:
                try:
                    # 非阻塞读取
                    import select
                    if select.select([self._client_process.stdout], [], [], 1)[0]:
                        line = self._client_process.stdout.readline()
                        if token.token_id in line:
                            interaction = self._parse_interaction(line, token)
                            if interaction:
                                interactions.append(interaction)
                except:
                    pass
                time.sleep(0.5)
        
        return interactions
    
    def _parse_interaction(self, line: str, token: OOBToken) -> Optional[OOBInteraction]:
        """解析 interactsh 输出"""
        try:
            import json
            data = json.loads(line)
            return OOBInteraction(
                token_id=token.token_id,
                interaction_type=data.get("protocol", "unknown"),
                remote_address=data.get("remote-address", ""),
                timestamp=datetime.now(),
                raw_request=data.get("raw-request", ""),
                protocol=data.get("protocol", ""),
                details=data
            )
        except:
            return None
    
    def cleanup(self):
        """清理资源"""
        if self._client_process:
            self._client_process.terminate()
            self._client_process = None


class SimpleHTTPCallbackProvider(OOBProvider):
    """
    简单的 HTTP 回调服务提供者
    
    在本地启动一个简单的 HTTP 服务器监听回调。
    适用于目标可以访问攻击机的场景。
    """
    
    def __init__(self, listen_host: str = "0.0.0.0", listen_port: int = 9999):
        self.listen_host = listen_host
        self.listen_port = listen_port
        self._server_thread = None
        self._interactions = []
        self._running = False
        self._external_ip = None
    
    def is_available(self) -> bool:
        """检查端口是否可用"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            result = sock.connect_ex((self.listen_host, self.listen_port))
            sock.close()
            return result != 0  # 端口未被占用
        except:
            return False
    
    def _get_external_ip(self) -> str:
        """获取外部 IP"""
        if self._external_ip:
            return self._external_ip
        
        # 尝试多种方式获取外部 IP
        methods = [
            lambda: requests.get("https://api.ipify.org", timeout=5).text.strip(),
            lambda: requests.get("https://ifconfig.me", timeout=5).text.strip(),
            lambda: socket.gethostbyname(socket.gethostname()),
        ]
        
        for method in methods:
            try:
                ip = method()
                if ip and re.match(r'\d+\.\d+\.\d+\.\d+', ip):
                    self._external_ip = ip
                    return ip
            except:
                continue
        
        # 回退到 localhost
        return "127.0.0.1"
    
    def generate_token(self) -> OOBToken:
        """生成 token 并启动服务器"""
        token_id = str(uuid.uuid4())[:8]
        
        # 启动回调服务器
        if not self._running:
            self._start_server()
        
        external_ip = self._get_external_ip()
        http_url = f"http://{external_ip}:{self.listen_port}/{token_id}"
        
        return OOBToken(
            token_id=token_id,
            full_url=http_url,
            dns_domain=f"{token_id}.callback.local",
            http_url=http_url
        )
    
    def _start_server(self):
        """启动 HTTP 回调服务器"""
        from http.server import HTTPServer, BaseHTTPRequestHandler
        
        provider = self
        
        class CallbackHandler(BaseHTTPRequestHandler):
            def do_GET(self):
                # 记录交互
                token_id = self.path.strip("/").split("/")[0] if "/" in self.path else self.path.strip("/")
                interaction = OOBInteraction(
                    token_id=token_id,
                    interaction_type="http",
                    remote_address=self.client_address[0],
                    timestamp=datetime.now(),
                    raw_request=f"{self.command} {self.path} HTTP/1.1\n{self.headers}",
                    protocol="http",
                    details={"method": "GET", "path": self.path, "headers": dict(self.headers)}
                )
                provider._interactions.append(interaction)
                
                # 响应
                self.send_response(200)
                self.send_header("Content-type", "text/plain")
                self.end_headers()
                self.wfile.write(b"OK")
            
            def do_POST(self):
                self.do_GET()
            
            def log_message(self, format, *args):
                pass  # 静默日志
        
        def run_server():
            server = HTTPServer((self.listen_host, self.listen_port), CallbackHandler)
            server.timeout = 1
            while self._running:
                server.handle_request()
        
        self._running = True
        self._server_thread = threading.Thread(target=run_server, daemon=True)
        self._server_thread.start()
        print(f"[OOB] HTTP callback server started on {self.listen_host}:{self.listen_port}")
    
    def poll_interactions(self, token: OOBToken, timeout: float = 30.0) -> List[OOBInteraction]:
        """轮询检查交互"""
        start_time = time.time()
        
        while time.time() - start_time < timeout:
            # 检查是否有匹配的交互
            matching = [i for i in self._interactions if i.token_id == token.token_id]
            if matching:
                return matching
            time.sleep(1)
        
        return []
    
    def cleanup(self):
        """停止服务器"""
        self._running = False
        if self._server_thread:
            self._server_thread.join(timeout=2)


class OOBVerifier:
    """
    OOB 验证器
    
    使用带外通道验证无回显漏洞。
    
    使用示例：
    ```python
    verifier = OOBVerifier()
    
    # 1. 生成 OOB payload
    token = verifier.generate_oob_payload()
    print(f"Use this URL in your exploit: {token.http_url}")
    
    # 2. 执行 exploit（外部）
    # ...
    
    # 3. 验证是否有回调
    result = verifier.verify(token, timeout=30)
    if result.verified:
        print(f"Vulnerability confirmed! Evidence: {result.evidence}")
    ```
    """
    
    def __init__(self, provider: OOBProvider = None):
        """
        初始化 OOB 验证器
        
        Args:
            provider: OOB 服务提供者，默认自动选择
        """
        if provider:
            self.provider = provider
        else:
            # 自动选择可用的 provider
            self.provider = self._auto_select_provider()
    
    def _auto_select_provider(self) -> OOBProvider:
        """自动选择可用的 OOB provider"""
        # 优先级：Interactsh > SimpleHTTPCallback
        providers = [
            InteractshProvider(),
            SimpleHTTPCallbackProvider(),
        ]
        
        for provider in providers:
            if provider.is_available():
                print(f"[OOB] Using provider: {provider.__class__.__name__}")
                return provider
        
        # 默认使用 SimpleHTTPCallback（即使可能不完全可用）
        print("[OOB] Warning: No ideal OOB provider available, using SimpleHTTPCallback")
        return SimpleHTTPCallbackProvider()
    
    def generate_oob_payload(self, oob_type: OOBType = OOBType.HTTP) -> OOBToken:
        """
        生成 OOB payload
        
        Args:
            oob_type: OOB 类型 (DNS, HTTP, etc.)
            
        Returns:
            OOBToken: 包含 payload URL 的 token
        """
        return self.provider.generate_token()
    
    def verify(self, token: OOBToken, timeout: float = 30.0) -> OOBVerificationResult:
        """
        验证是否收到 OOB 回调
        
        Args:
            token: 之前生成的 OOB token
            timeout: 等待超时时间（秒）
            
        Returns:
            OOBVerificationResult: 验证结果
        """
        print(f"[OOB] Waiting for callback to {token.http_url} (timeout: {timeout}s)...")
        
        interactions = self.provider.poll_interactions(token, timeout)
        
        if interactions:
            evidence = self._format_evidence(interactions)
            return OOBVerificationResult(
                verified=True,
                token=token,
                interactions=interactions,
                confidence=0.95,  # OOB 验证置信度很高
                evidence=evidence
            )
        else:
            return OOBVerificationResult(
                verified=False,
                token=token,
                interactions=[],
                confidence=0.0,
                evidence="",
                failure_reason="No OOB callback received within timeout",
                failure_code=FailureCode.V003_VALIDATION_FAILED if FailureCode else None
            )
    
    def _format_evidence(self, interactions: List[OOBInteraction]) -> str:
        """格式化证据"""
        evidence_lines = ["OOB Interactions Received:"]
        for i, interaction in enumerate(interactions, 1):
            evidence_lines.append(f"\n--- Interaction #{i} ---")
            evidence_lines.append(f"Type: {interaction.interaction_type}")
            evidence_lines.append(f"From: {interaction.remote_address}")
            evidence_lines.append(f"Time: {interaction.timestamp}")
            if interaction.raw_request:
                evidence_lines.append(f"Request:\n{interaction.raw_request[:500]}")
        return "\n".join(evidence_lines)
    
    def cleanup(self):
        """清理资源"""
        if hasattr(self.provider, 'cleanup'):
            self.provider.cleanup()


# ============================================================
# 便捷函数
# ============================================================

def create_oob_verifier() -> OOBVerifier:
    """创建 OOB 验证器"""
    return OOBVerifier()


def generate_ssrf_oob_payload() -> Tuple[str, OOBToken]:
    """
    生成 SSRF 检测 payload
    
    Returns:
        Tuple[str, OOBToken]: (payload URL, token)
    """
    verifier = OOBVerifier()
    token = verifier.generate_oob_payload(OOBType.HTTP)
    return token.http_url, token


def generate_blind_rce_oob_payload() -> Tuple[str, OOBToken]:
    """
    生成 Blind RCE 检测 payload
    
    常见用法：
    - curl {oob_url}
    - wget {oob_url}
    - ping -c 1 {oob_domain}
    
    Returns:
        Tuple[str, OOBToken]: (payload URL, token)
    """
    verifier = OOBVerifier()
    token = verifier.generate_oob_payload(OOBType.HTTP)
    return token.http_url, token


def generate_xxe_oob_payload() -> Tuple[str, str, OOBToken]:
    """
    生成 XXE OOB payload
    
    Returns:
        Tuple[str, str, OOBToken]: (dtd_url, xxe_payload, token)
    """
    verifier = OOBVerifier()
    token = verifier.generate_oob_payload(OOBType.HTTP)
    
    # XXE payload 模板
    xxe_payload = f'''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "{token.http_url}">
]>
<root>&xxe;</root>'''
    
    return token.http_url, xxe_payload, token


# 导出
__all__ = [
    'OOBType',
    'OOBToken',
    'OOBInteraction',
    'OOBVerificationResult',
    'OOBProvider',
    'InteractshProvider',
    'SimpleHTTPCallbackProvider',
    'OOBVerifier',
    'create_oob_verifier',
    'generate_ssrf_oob_payload',
    'generate_blind_rce_oob_payload',
    'generate_xxe_oob_payload',
]
