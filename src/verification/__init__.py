"""__init__.py for verification package."""
from .strategies import (
    VerificationStrategy,
    FlagVerifier,
    HttpResponseVerifier,
    CookieVerifier,
    LogPatternVerifier,
    DOMVerifier,
    VerificationStrategyRegistry,
    build_default_registry,
)

from .hardened_verifier import (
    VulnType,
    VerificationResult,
    CanaryGenerator,
    HardenedOracle,
    RCEOracle,
    SQLiOracle,
    XSSOracle,
    SSRFOracle,
    InfoLeakOracle,
    HardenedVerifier,
    OOBEnhancedOracle,
)

from .enhanced_healthcheck import (
    CheckStatus,
    CheckResult,
    HealthReport,
    EnhancedHealthCheck,
    EnvironmentValidator,
    check_service_health,
    validate_environment,
)

from .oob_verifier import (
    OOBType,
    OOBToken,
    OOBInteraction,
    OOBVerificationResult,
    OOBProvider,
    InteractshProvider,
    SimpleHTTPCallbackProvider,
    OOBVerifier,
    create_oob_verifier,
    generate_ssrf_oob_payload,
    generate_blind_rce_oob_payload,
    generate_xxe_oob_payload,
)

__all__ = [
    # 原有策略
    "VerificationStrategy",
    "FlagVerifier",
    "HttpResponseVerifier",
    "CookieVerifier",
    "LogPatternVerifier",
    "DOMVerifier",
    "VerificationStrategyRegistry",
    "build_default_registry",
    # 强化验证器
    "VulnType",
    "VerificationResult",
    "CanaryGenerator",
    "HardenedOracle",
    "RCEOracle",
    "SQLiOracle",
    "XSSOracle",
    "SSRFOracle",
    "InfoLeakOracle",
    "HardenedVerifier",
    "OOBEnhancedOracle",
    # 增强健康检查
    "CheckStatus",
    "CheckResult",
    "HealthReport",
    "EnhancedHealthCheck",
    "EnvironmentValidator",
    "check_service_health",
    "validate_environment",
    # OOB 验证
    "OOBType",
    "OOBToken",
    "OOBInteraction",
    "OOBVerificationResult",
    "OOBProvider",
    "InteractshProvider",
    "SimpleHTTPCallbackProvider",
    "OOBVerifier",
    "create_oob_verifier",
    "generate_ssrf_oob_payload",
    "generate_blind_rce_oob_payload",
    "generate_xxe_oob_payload",
]

