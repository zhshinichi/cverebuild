"""Capability wrappers that reuse the canonical verification strategies."""
from __future__ import annotations

from typing import Any, Dict

from core.result_bus import ResultBus
from verification.strategies import (
    HttpResponseVerifier as StrategyHttpResponseVerifier,
    CookieVerifier as StrategyCookieVerifier,
    FlagVerifier as StrategyFlagVerifier,
    VerificationStrategyRegistry,
    build_default_registry,
)


class HttpResponseVerifierCapability:
    """Reuse verification.strategies.HttpResponseVerifier inside a capability."""

    def __init__(self, result_bus: ResultBus, config: dict) -> None:
        self.result_bus = result_bus
        expected_status = config.get("expected_status")
        expected_keywords = config.get("expected_keywords", [])
        self._strategy = StrategyHttpResponseVerifier(
            expected_status=expected_status,
            expected_keywords=expected_keywords,
        )

    def execute(self, inputs: Dict[str, Any]) -> Dict[str, Any]:
        response = inputs.get("http_response") or inputs.get("web_exploit_result") or {}
        result = self._strategy.verify({"http_response": response})
        return {"verification_result": result}


class CookieVerifierCapability:
    """Reuse verification.strategies.CookieVerifier inside a capability."""

    def __init__(self, result_bus: ResultBus, config: dict) -> None:
        self.result_bus = result_bus
        self._strategy = StrategyCookieVerifier(
            check_mode=config.get("check_mode", "exists"),
            cookie_name=config.get("cookie_name"),
        )

    def execute(self, inputs: Dict[str, Any]) -> Dict[str, Any]:
        cookies = inputs.get("cookies", {})
        exploit_output = inputs.get("exploit_output", "")
        result = self._strategy.verify({"cookies": cookies, "exploit_output": exploit_output})
        return {"verification_result": result}


class FlagVerifierCapability:
    """Reuse verification.strategies.FlagVerifier inside a capability."""

    def __init__(self, result_bus: ResultBus, config: dict) -> None:
        self.result_bus = result_bus
        self._strategy = StrategyFlagVerifier(flag_pattern=config.get("flag_pattern", r"FLAG\{[^}]+\}"))

    def execute(self, inputs: Dict[str, Any]) -> Dict[str, Any]:
        exploit_output = inputs.get("exploit_output", "")
        result = self._strategy.verify({"exploit_output": exploit_output})
        return {"verification_result": result}


class CombinedVerifierCapability:
    """Combine multiple verification strategies; configurable via strategy_names/combine_mode."""

    def __init__(self, result_bus: ResultBus, config: dict) -> None:
        self.result_bus = result_bus
        self.strategy_names = config.get("strategy_names") or ["http_200"]
        self.combine_mode = config.get("combine_mode", "any")
        self.registry: VerificationStrategyRegistry = build_default_registry()

    def execute(self, inputs: Dict[str, Any]) -> Dict[str, Any]:
        context = {
            "http_response": inputs.get("http_response") or inputs.get("web_exploit_result") or {},
            "cookies": inputs.get("cookies", {}),
            "exploit_output": inputs.get("exploit_output", ""),
            "page_source": inputs.get("page_source", ""),
            "alerts_detected": inputs.get("alerts_detected", False),
        }
        result = self.registry.verify(self.strategy_names, context=context, combine_mode=self.combine_mode)
        return {"verification_result": result}
