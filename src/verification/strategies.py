"""验证策略注册表：支持多种漏洞验证方法。"""
from __future__ import annotations

import re
from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional


class VerificationStrategy(ABC):
    """验证策略基类。"""

    @abstractmethod
    def verify(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """
        执行验证逻辑。
        
        Args:
            context: 验证上下文，包含 exploit 输出、环境元数据等
        
        Returns:
            {
                "success": bool,
                "confidence": float,  # 0.0-1.0
                "evidence": str,
                "details": dict
            }
        """
        pass


class FlagVerifier(VerificationStrategy):
    """CTF Flag 验证器（现有逻辑）。"""

    def __init__(self, flag_pattern: str = r"FLAG\{[^}]+\}"):
        self.flag_pattern = re.compile(flag_pattern)

    def verify(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """检查输出中是否包含 flag。"""
        output = context.get("exploit_output", "")
        
        match = self.flag_pattern.search(output)
        if match:
            return {
                "success": True,
                "confidence": 1.0,
                "evidence": match.group(0),
                "details": {"flag_found": True, "flag_value": match.group(0)},
            }
        
        return {
            "success": False,
            "confidence": 0.0,
            "evidence": "未找到 flag",
            "details": {"flag_found": False},
        }


class HttpResponseVerifier(VerificationStrategy):
    """HTTP 响应验证器（适用于 Web 漏洞）。"""

    def __init__(self, expected_status: Optional[int] = None, expected_keywords: Optional[List[str]] = None):
        """
        Args:
            expected_status: 期望的 HTTP 状态码（如 200, 302）
            expected_keywords: 响应内容中应包含的关键字
        """
        self.expected_status = expected_status
        self.expected_keywords = expected_keywords or []

    def verify(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """检查 HTTP 响应状态码和内容。"""
        response = context.get("http_response", {})
        status_code = response.get("status_code")
        content = response.get("content", "")
        
        success = True
        confidence = 1.0
        details = {}

        # 检查状态码
        if self.expected_status and status_code != self.expected_status:
            success = False
            confidence *= 0.5
            details["status_mismatch"] = {
                "expected": self.expected_status,
                "actual": status_code,
            }

        # 检查关键字
        missing_keywords = []
        for keyword in self.expected_keywords:
            if keyword not in content:
                missing_keywords.append(keyword)
        
        if missing_keywords:
            success = False
            confidence *= 0.7
            details["missing_keywords"] = missing_keywords

        evidence = f"状态码: {status_code}, 内容长度: {len(content)}"
        
        return {
            "success": success,
            "confidence": confidence,
            "evidence": evidence,
            "details": details,
        }


class CookieVerifier(VerificationStrategy):
    """Cookie 验证器（检测 Cookie 窃取、设置等）。"""

    def __init__(self, check_mode: str = "exists", cookie_name: Optional[str] = None):
        """
        Args:
            check_mode: "exists"（检查 Cookie 是否被设置）或 "stolen"（检查是否被窃取）
            cookie_name: 要检查的 Cookie 名称
        """
        self.check_mode = check_mode
        self.cookie_name = cookie_name

    def verify(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """检查 Cookie 相关的漏洞迹象。"""
        cookies = context.get("cookies", {})
        exploit_output = context.get("exploit_output", "")
        
        if self.check_mode == "exists":
            # 检查特定 Cookie 是否存在
            if self.cookie_name:
                exists = self.cookie_name in cookies
                return {
                    "success": exists,
                    "confidence": 1.0 if exists else 0.0,
                    "evidence": f"Cookie '{self.cookie_name}' {'存在' if exists else '不存在'}",
                    "details": {"cookie_found": exists, "cookie_value": cookies.get(self.cookie_name)},
                }
        
        elif self.check_mode == "stolen":
            # 检查 exploit 输出中是否包含 Cookie 值
            cookie_pattern = re.compile(r"(session|token|auth)=[a-zA-Z0-9]+")
            matches = cookie_pattern.findall(exploit_output)
            
            if matches:
                return {
                    "success": True,
                    "confidence": 0.9,
                    "evidence": f"发现 {len(matches)} 个可能被窃取的 Cookie",
                    "details": {"stolen_cookies": matches},
                }
        
        return {
            "success": False,
            "confidence": 0.0,
            "evidence": "未检测到 Cookie 相关迹象",
            "details": {},
        }


class LogPatternVerifier(VerificationStrategy):
    """日志模式验证器（通过日志关键字判断漏洞触发）。"""

    def __init__(self, patterns: List[str], match_mode: str = "any"):
        """
        Args:
            patterns: 正则表达式列表
            match_mode: "any"（匹配任意一个）或 "all"（匹配所有）
        """
        self.patterns = [re.compile(p) for p in patterns]
        self.match_mode = match_mode

    def verify(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """检查日志中是否包含特定模式。"""
        logs = context.get("logs", "")
        
        matches = []
        for pattern in self.patterns:
            found = pattern.search(logs)
            if found:
                matches.append(found.group(0))
        
        if self.match_mode == "any":
            success = len(matches) > 0
        else:  # "all"
            success = len(matches) == len(self.patterns)
        
        confidence = len(matches) / len(self.patterns) if self.patterns else 0.0
        
        return {
            "success": success,
            "confidence": confidence,
            "evidence": f"匹配 {len(matches)}/{len(self.patterns)} 个模式",
            "details": {"matched_patterns": matches},
        }


class DOMVerifier(VerificationStrategy):
    """DOM 变化验证器（适用于 XSS 等前端漏洞）。"""

    def __init__(self, check_alert: bool = True, check_element: Optional[str] = None):
        """
        Args:
            check_alert: 是否检查 JavaScript alert 弹窗
            check_element: 要检查的 DOM 元素选择器（如 "#malicious-script"）
        """
        self.check_alert = check_alert
        self.check_element = check_element

    def verify(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """检查 DOM 变化或 JavaScript 执行迹象。"""
        page_source = context.get("page_source", "")
        alerts_detected = context.get("alerts_detected", False)
        
        success = False
        evidence = []
        details = {}

        # 检查 alert 弹窗
        if self.check_alert and alerts_detected:
            success = True
            evidence.append("检测到 JavaScript alert 弹窗")
            details["alert_detected"] = True

        # 检查特定元素
        if self.check_element:
            if self.check_element in page_source:
                success = True
                evidence.append(f"找到元素: {self.check_element}")
                details["element_found"] = True

        # 检查常见 XSS payload 特征
        xss_patterns = [
            r"<script[^>]*>.*?</script>",
            r"onerror\s*=",
            r"javascript:",
        ]
        
        for pattern in xss_patterns:
            if re.search(pattern, page_source, re.IGNORECASE):
                success = True
                evidence.append(f"检测到 XSS 特征: {pattern}")
                details["xss_pattern_found"] = True
                break

        confidence = 1.0 if success else 0.0
        
        return {
            "success": success,
            "confidence": confidence,
            "evidence": "; ".join(evidence) if evidence else "未检测到 DOM 变化",
            "details": details,
        }


class VerificationStrategyRegistry:
    """验证策略注册表，支持组合多种验证方法。"""

    def __init__(self):
        self.strategies: Dict[str, VerificationStrategy] = {}

    def register(self, name: str, strategy: VerificationStrategy):
        """注册验证策略。"""
        self.strategies[name] = strategy

    def verify(self, strategy_names: List[str], context: Dict[str, Any], combine_mode: str = "any") -> Dict[str, Any]:
        """
        使用多个策略进行验证。
        
        Args:
            strategy_names: 要使用的策略名称列表
            context: 验证上下文
            combine_mode: "any"（任意一个成功即可）或 "all"（所有策略都要成功）
        
        Returns:
            综合验证结果
        """
        results = []
        
        for name in strategy_names:
            strategy = self.strategies.get(name)
            if not strategy:
                print(f"⚠️  未找到验证策略: {name}")
                continue
            
            result = strategy.verify(context)
            results.append({**result, "strategy": name})

        if not results:
            return {
                "success": False,
                "confidence": 0.0,
                "evidence": "无可用验证策略",
                "details": {},
            }

        # 组合结果
        if combine_mode == "any":
            success = any(r["success"] for r in results)
            confidence = max(r["confidence"] for r in results)
        else:  # "all"
            success = all(r["success"] for r in results)
            confidence = sum(r["confidence"] for r in results) / len(results)

        return {
            "success": success,
            "confidence": confidence,
            "evidence": f"验证策略: {', '.join(strategy_names)}",
            "details": {"strategy_results": results},
        }


def build_default_registry() -> VerificationStrategyRegistry:
    """构建默认验证策略注册表。"""
    registry = VerificationStrategyRegistry()
    
    # 注册默认策略
    registry.register("flag", FlagVerifier())
    registry.register("http_200", HttpResponseVerifier(expected_status=200))
    registry.register("http_redirect", HttpResponseVerifier(expected_status=302))
    registry.register("cookie_exists", CookieVerifier(check_mode="exists"))
    registry.register("cookie_stolen", CookieVerifier(check_mode="stolen"))
    registry.register("dom_xss", DOMVerifier(check_alert=True))
    
    return registry
