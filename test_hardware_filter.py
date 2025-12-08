#!/usr/bin/env python3
"""测试硬件漏洞过滤功能"""

import sys
sys.path.insert(0, '/workspaces/submission/src/data/scripts')

from web_cve_classifier import WebCVEClassifier

# 测试数据：模拟 CVE-2025-34117（路由器后门）
test_cve_router = {
    "cve_id": "CVE-2025-34117",
    "description": "Netcore router firmware contains a backdoor accessible via UDP port 53413",
    "sw_name": "Router firmware",
    "sw_version_wget": "",
    "cwe": []
}

# 测试数据：正常的 Web 漏洞
test_cve_web = {
    "cve_id": "CVE-2025-55007",
    "description": "Knowage web application is vulnerable to SSRF",
    "sw_name": "Knowage-Server",
    "sw_version_wget": "https://github.com/KnowageLabs/Knowage-Server/archive/refs/tags/v8.1.36.tar.gz",
    "cwe": [{"id": "CWE-918", "value": "Server-Side Request Forgery"}]
}

print("=" * 60)
print("测试 1: 路由器固件漏洞（应该被过滤）")
print("=" * 60)

classifier = WebCVEClassifier()
result1 = classifier.classify("CVE-2025-34117", test_cve_router)

print(f"CVE ID: {result1.cve_id}")
print(f"Is Web: {result1.is_web}")
print(f"Is Hardware: {result1.is_hardware}")
print(f"Confidence: {result1.confidence}")
print(f"Reasons: {result1.reasons}")
print(f"Hardware Reasons: {result1.hardware_reasons}")
print(f"Data Quality Issue: {result1.data_quality_issue}")

print("\n" + "=" * 60)
print("测试 2: 正常 Web 漏洞（应该通过）")
print("=" * 60)

result2 = classifier.classify("CVE-2025-55007", test_cve_web)

print(f"CVE ID: {result2.cve_id}")
print(f"Is Web: {result2.is_web}")
print(f"Is Hardware: {result2.is_hardware}")
print(f"Confidence: {result2.confidence}")
print(f"Reasons: {result2.reasons}")
print(f"CWE Matches: {result2.cwe_matches}")

print("\n" + "=" * 60)
print("结论:")
print("=" * 60)
if result1.is_hardware and not result1.is_web:
    print("✅ 硬件漏洞过滤工作正常！")
else:
    print("❌ 硬件漏洞过滤失败！")

if result2.is_web and not result2.is_hardware:
    print("✅ Web 漏洞识别工作正常！")
else:
    print("❌ Web 漏洞识别失败！")
