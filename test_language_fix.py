#!/usr/bin/env python3
"""验证语言检测修复"""

import sys
import os
import importlib.util

# 直接加载模块文件而非通过包
spec = importlib.util.spec_from_file_location(
    "deploymentStrategyAnalyzer", 
    "/workspaces/submission/src/agents/deploymentStrategyAnalyzer.py"
)
module = importlib.util.module_from_spec(spec)
sys.modules["deploymentStrategyAnalyzer"] = module
spec.loader.exec_module(module)

DeploymentStrategyAnalyzer = module.DeploymentStrategyAnalyzer

print("="*60)
print("CVE-2024-50343 (Symfony) 修复后的识别结果:")
print("="*60)

analyzer = DeploymentStrategyAnalyzer('CVE-2024-50343', 'Symfony vulnerability in web application')
result = analyzer.invoke()

print(f"\nLanguage: {result.get('language')}")
print(f"Build Tool: {result.get('build_tool')}")
print(f"Strategy: {result.get('strategy_type')}")
print(f"Repository: {result.get('repository_url')}")

notes = result.get('deployment_notes', '')
print(f"Notes: {notes[:100] if notes else 'None'}...")

# 验证是否修复
if result.get('language') == 'php':
    print("\n[+] PASS: 正确识别为 PHP!")
elif result.get('language') == 'javascript':
    print("\n[-] FAIL: 仍然错误识别为 JavaScript!")
else:
    print(f"\n[?] 识别为: {result.get('language')}")
