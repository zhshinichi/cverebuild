"""Rule-based vulnerability classifier (MVP)."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Optional

from planner import ClassifierDecision


@dataclass
class ClassifierConfig:
    default_profile: str = "native-local"
    min_confidence: float = 0.55


class VulnerabilityClassifier:
    """Heuristic classifier that selects a plan profile and resource hints."""

    def __init__(self, config: Optional[ClassifierConfig] = None) -> None:
        self.config = config or ClassifierConfig()

    def classify(self, cve_id: str, cve_entry: Dict[str, object], profile_override: Optional[str] = None) -> ClassifierDecision:
        profile = profile_override or self._pick_profile(cve_entry)
        hints = self._infer_resource_hints(cve_entry)
        capabilities = self._infer_capabilities(profile)
        confidence = self._estimate_confidence(profile, hints)

        return ClassifierDecision(
            cve_id=cve_id,
            profile=profile,
            confidence=confidence,
            required_capabilities=capabilities,
            resource_hints=hints,
        )

    # ------------------------------------------------------------------
    # Heuristics
    # ------------------------------------------------------------------
    def _pick_profile(self, cve_entry: Dict[str, object]) -> str:
        description = (cve_entry.get("description") or "").lower()
        cwe_ids = " ".join(self._extract_cwe_ids(cve_entry))

        if any(keyword in description for keyword in ("http", "browser", "csrf", "xss")):
            return "web-basic"
        if "cloud" in description or "iam" in description:
            return "cloud-config"
        if "firmware" in description or "uart" in description:
            return "iot-firmware"
        if "CWE-352" in cwe_ids or "CWE-79" in cwe_ids:
            return "web-basic"
        if "CWE-918" in cwe_ids:
            return "cloud-config"
        return self.config.default_profile

    def _infer_resource_hints(self, cve_entry: Dict[str, object]) -> Dict[str, object]:
        description = (cve_entry.get("description") or "").lower()
        needs_browser = any(term in description for term in ("browser", "csrf", "xss", "web"))
        needs_emulation = "firmware" in description or "uart" in description

        hints: Dict[str, object] = {
            "needs_browser": needs_browser,
            "needs_emulation": needs_emulation,
            "timeout": 3600,
        }
        return hints

    def _infer_capabilities(self, profile: str):
        mapping = {
            "native-local": ("InfoGenerator", "EnvironmentProvisioner", "ExploitExecutor", "FlagVerifier"),
            "web-basic": ("InfoGenerator", "PreReqAnalyzer", "EnvironmentDeployer", "BrowserProvisioner", "WebExploiter", "WebVerifier"),
            "cloud-config": ("InfoGenerator", "CloudEnvProvisioner", "ApiExploiter", "LogVerifier"),
            "iot-firmware": ("InfoGenerator", "FirmwareProvisioner", "ExploitExecutor", "TelemetryVerifier"),
        }
        return mapping.get(profile, mapping["native-local"])

    def _estimate_confidence(self, profile: str, hints: Dict[str, object]) -> float:
        score = 0.6
        if profile != self.config.default_profile:
            score += 0.15
        if hints.get("needs_browser"):
            score += 0.1
        if hints.get("needs_emulation"):
            score += 0.1
        return min(0.95, score)

    @staticmethod
    def _extract_cwe_ids(cve_entry: Dict[str, object]):
        cwe_items = cve_entry.get("cwe") or []
        ids = []
        for item in cwe_items:
            if isinstance(item, dict) and item.get("id"):
                ids.append(item["id"])
        return ids
