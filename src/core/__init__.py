"""
Core 模块 - 基础设施代码

包含:
- failure_codes: 失败原因码体系
- hallucination_guard: Agent 幻觉检测与防护
- anti_hallucination_executor: 幻觉防护增强型 AgentExecutor
"""

from .failure_codes import (
    FailureCode,
    FailureCategory,
    FailureDetail,
    FailureAnalyzer,
    ReproReport,
    analyze_failure,
    create_report,
)

from .hallucination_guard import (
    HallucinationDetector,
    HallucinationPattern,
    HallucinationStats,
    DetectionResult,
    detect_hallucination,
    get_continuation_feedback,
    default_detector,
)

from .anti_hallucination_executor import (
    AntiHallucinationAgentExecutor,
    create_anti_hallucination_executor,
    HallucinationGuardMixin,
)

__all__ = [
    # failure_codes
    'FailureCode',
    'FailureCategory', 
    'FailureDetail',
    'FailureAnalyzer',
    'ReproReport',
    'analyze_failure',
    'create_report',
    # hallucination_guard
    'HallucinationDetector',
    'HallucinationPattern',
    'HallucinationStats',
    'DetectionResult',
    'detect_hallucination',
    'get_continuation_feedback',
    'default_detector',
    # anti_hallucination_executor
    'AntiHallucinationAgentExecutor',
    'create_anti_hallucination_executor',
    'HallucinationGuardMixin',
]
