#!/usr/bin/env python3
"""
测试 WebDriver 集成的简单脚本
验证自动检测功能是否正常工作
"""

import sys
import os

# 添加 src 目录到 path
src_path = os.path.join(os.path.dirname(__file__), '..', 'src')
sys.path.insert(0, src_path)

# 直接导入 web_detector 模块，避免通过 toolbox.__init__
web_detector_path = os.path.join(src_path, 'toolbox', 'web_detector.py')
import importlib.util
spec = importlib.util.spec_from_file_location("web_detector", web_detector_path)
web_detector = importlib.util.module_from_spec(spec)
spec.loader.exec_module(web_detector)

requires_web_driver = web_detector.requires_web_driver
get_attack_type = web_detector.get_attack_type

# 测试用例
test_cases = [
    {
        "name": "CVE-2024-2288 (CSRF)",
        "cve_info": {
            "cwe": [{"id": "CWE-352", "value": "Cross-Site Request Forgery (CSRF)"}],
            "description": "A Cross-Site Request Forgery (CSRF) vulnerability exists in the profile picture upload",
            "sec_adv": [{"content": "CSRF attack allows uploading arbitrary files"}]
        }
    },
    {
        "name": "CVE-2024-4340 (Non-Web)",
        "cve_info": {
            "cwe": [{"id": "CWE-674", "value": "Uncontrolled Recursion"}],
            "description": "Passing a heavily nested list to sqlparse.parse() leads to DoS",
            "sec_adv": [{"content": "Python library vulnerability causing recursion error"}]
        }
    },
    {
        "name": "Generic XSS",
        "cve_info": {
            "cwe": [{"id": "CWE-79", "value": "Cross-site Scripting"}],
            "description": "Stored XSS vulnerability in comment field",
            "sec_adv": [{"content": "JavaScript injection through unsanitized input"}]
        }
    }
]

print("=" * 60)
print("WebDriver 检测器测试")
print("=" * 60)
print()

for test in test_cases:
    print(f"测试: {test['name']}")
    print("-" * 60)
    
    needs_webdriver = requires_web_driver(test['cve_info'])
    attack_type = get_attack_type(test['cve_info']) if needs_webdriver else "N/A"
    
    print(f"  需要 WebDriver: {'✅ 是' if needs_webdriver else '❌ 否'}")
    print(f"  攻击类型: {attack_type}")
    print()

print("=" * 60)
print("✅ 测试完成")
print("=" * 60)
