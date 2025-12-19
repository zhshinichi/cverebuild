"""
Core 模块 - 基础设施代码

包含:
- failure_codes: 失败原因码体系
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

__all__ = [
    'FailureCode',
    'FailureCategory', 
    'FailureDetail',
    'FailureAnalyzer',
    'ReproReport',
    'analyze_failure',
    'create_report',
]
