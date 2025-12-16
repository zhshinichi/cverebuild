#!/usr/bin/env python3
"""
在容器中验证增强版分类器的改进效果
"""
import sys
import json
import os
os.chdir('/workspaces/submission/src')
sys.path.insert(0, '/workspaces/submission/src')
sys.path.insert(0, '/workspaces/submission/src/agentlib')

from planner.llm_classifier import LLMVulnerabilityClassifier, LLMClassifierConfig

print('='*70)
print('增强版 CVE 分类器验证')
print('='*70)

# 测试用例
test_cases = [
    {
        'cve_id': 'CVE-2024-4340',
        'cve_entry': {
            'description': 'Passing a heavily nested list to sqlparse.parse() leads to a Denial of Service due to RecursionError.',
            'cwe': [{'id': 'CWE-674', 'value': 'CWE-674 Uncontrolled Recursion'}],
            'sw_version_wget': 'https://github.com/andialbrecht/sqlparse/archive/refs/tags/0.4.4.zip',
        },
        'expected': 'native-local',  # 纯 Python 库
        'reason': 'sqlparse 是纯 Python 库，不是 Web 框架'
    },
    {
        'cve_id': 'CVE-2024-6862',
        'cve_entry': {
            'description': 'A Cross-Site Request Forgery (CSRF) vulnerability exists in lunary-ai/lunary version 1.2.34.',
            'cwe': [{'id': 'CWE-352', 'value': 'CWE-352: Cross-Site Request Forgery (CSRF)'}],
            'sw_version_wget': 'https://github.com/lunary-ai/lunary/archive/refs/tags/v1.2.34.zip',
        },
        'expected': 'web-basic',  # Web 应用
        'reason': 'lunary 是 Web 应用，CSRF 需要 HTTP 请求'
    },
    {
        'cve_id': 'CVE-2024-TEST-MLFLOW',
        'cve_entry': {
            'description': 'MLflow vulnerability allows unauthorized access to sensitive data via API endpoint.',
            'cwe': [{'id': 'CWE-918', 'value': 'CWE-918: SSRF'}],
            'sw_version_wget': 'https://github.com/mlflow/mlflow/archive/refs/tags/v2.10.0.zip',
        },
        'expected': 'web-basic',  # MLflow 是 Web 应用
        'reason': 'MLflow 是 Web 框架，应该是 web-basic'
    },
    {
        'cve_id': 'CVE-2024-TEST-ROUTER',
        'cve_entry': {
            'description': 'Router firmware backdoor vulnerability allows remote code execution.',
            'cwe': [{'id': 'CWE-78', 'value': 'CWE-78: OS Command Injection'}],
            'sw_version_wget': '',
        },
        'expected': 'iot-firmware',  # 路由器固件
        'reason': '路由器固件漏洞应该是 iot-firmware'
    },
]

# 创建分类器（禁用二次验证以加快测试）
config = LLMClassifierConfig(
    use_llm=True, 
    fallback_to_rules=True,
    enable_verification=False,  # 测试时禁用二次验证以加快速度
    load_cve_raw_data=True,
)
classifier = LLMVulnerabilityClassifier(config)

print(f'\n配置：')
print(f'  - 使用 LLM: {config.use_llm}')
print(f'  - 加载 CVE 原始数据: {config.load_cve_raw_data}')
print(f'  - 二次验证: {config.enable_verification}')

results = []

for tc in test_cases:
    print(f'\n{"-"*70}')
    print(f'测试: {tc["cve_id"]}')
    print(f'期望: {tc["expected"]} ({tc["reason"]})')
    print(f'{"-"*70}')
    
    try:
        decision = classifier.classify(tc['cve_id'], tc['cve_entry'])
        
        is_correct = decision.profile == tc['expected']
        status = '✅ 通过' if is_correct else '❌ 失败'
        
        print(f'\n结果: {status}')
        print(f'  分类: {decision.profile}')
        print(f'  置信度: {decision.confidence:.2f}')
        
        if not is_correct:
            print(f'  ❌ 期望 {tc["expected"]}，实际 {decision.profile}')
        
        results.append({
            'cve_id': tc['cve_id'],
            'expected': tc['expected'],
            'actual': decision.profile,
            'correct': is_correct,
            'confidence': decision.confidence
        })
        
    except Exception as e:
        print(f'❌ 错误: {e}')
        results.append({
            'cve_id': tc['cve_id'],
            'expected': tc['expected'],
            'actual': 'ERROR',
            'correct': False,
            'confidence': 0
        })

# 汇总结果
print(f'\n{"="*70}')
print('测试结果汇总')
print(f'{"="*70}')

passed = sum(1 for r in results if r['correct'])
total = len(results)

print(f'\n通过: {passed}/{total}')

for r in results:
    status = '✅' if r['correct'] else '❌'
    print(f"  {status} {r['cve_id']}: 期望={r['expected']}, 实际={r['actual']}, 置信度={r['confidence']:.2f}")

print(f'\n{"-"*70}')
if passed == total:
    print('🎉 所有测试通过！')
else:
    print(f'⚠️ {total - passed} 个测试失败')
print(f'{"="*70}')

# 返回退出码
sys.exit(0 if passed == total else 1)
