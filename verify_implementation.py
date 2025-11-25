"""
新架构实施验证脚本
快速检查所有关键模块是否已正确实施
"""

import os
import sys
from pathlib import Path

# 颜色输出
GREEN = '\033[92m'
RED = '\033[91m'
YELLOW = '\033[93m'
BLUE = '\033[94m'
RESET = '\033[0m'

def check(condition, message):
    """检查条件并打印结果"""
    if condition:
        print(f"{GREEN}✅{RESET} {message}")
        return True
    else:
        print(f"{RED}❌{RESET} {message}")
        return False

def warn(message):
    """打印警告"""
    print(f"{YELLOW}⚠️{RESET}  {message}")

def info(message):
    """打印信息"""
    print(f"{BLUE}ℹ️{RESET}  {message}")

def main():
    print("\n" + "="*60)
    print("     DAG 架构实施验证")
    print("="*60 + "\n")
    
    passed = 0
    failed = 0
    
    # 1. 检查核心模块文件
    print(f"{BLUE}【1】检查核心模块文件{RESET}")
    required_files = [
        'src/planner/__init__.py',
        'src/planner/classifier.py',
        'src/planner/dag.py',
        'src/planner/executor.py',
        'src/capabilities/base.py',
        'src/capabilities/adapters.py',
        'src/capabilities/registry.py',
        'src/capabilities/playwright_adapters.py',
        'src/orchestrator/environment.py',
        'src/verification/strategies.py',
        'src/core/result_bus.py',
    ]
    
    for file_path in required_files:
        if check(os.path.exists(file_path), f"文件存在: {file_path}"):
            passed += 1
        else:
            failed += 1
    
    # 2. 检查配置文件
    print(f"\n{BLUE}【2】检查 Profile 配置文件{RESET}")
    profile_files = [
        'profiles/native-local.yaml',
        'profiles/web-basic.yaml',
    ]
    
    for file_path in profile_files:
        if check(os.path.exists(file_path), f"Profile 存在: {file_path}"):
            passed += 1
        else:
            failed += 1
    
    # 3. 检查文档
    print(f"\n{BLUE}【3】检查文档{RESET}")
    doc_files = [
        'docs/planner/plan_spec.md',
        'docs/planner/migration_plan.md',
        'docs/planner/usage_guide.md',
        'docs/planner/implementation_report.md',
    ]
    
    for file_path in doc_files:
        if check(os.path.exists(file_path), f"文档存在: {file_path}"):
            passed += 1
        else:
            failed += 1
    
    # 4. 检查测试文件
    print(f"\n{BLUE}【4】检查测试文件{RESET}")
    test_files = [
        'tests/test_dag_e2e.py',
        'examples/playwright_web_exploit.py',
    ]
    
    for file_path in test_files:
        if check(os.path.exists(file_path), f"测试文件存在: {file_path}"):
            passed += 1
        else:
            failed += 1
    
    # 5. 检查 main.py CLI 集成
    print(f"\n{BLUE}【5】检查 CLI 集成{RESET}")
    with open('src/main.py', 'r', encoding='utf-8') as f:
        main_content = f.read()
    
    if check('--dag' in main_content, "CLI 参数 --dag 已添加"):
        passed += 1
    else:
        failed += 1
    
    if check('--browser-engine' in main_content, "CLI 参数 --browser-engine 已添加"):
        passed += 1
    else:
        failed += 1
    
    if check('--profile' in main_content, "CLI 参数 --profile 已添加"):
        passed += 1
    else:
        failed += 1
    
    if check('from planner.classifier import VulnerabilityClassifier' in main_content, "Classifier 已导入"):
        passed += 1
    else:
        failed += 1
    
    # 6. 检查模块可导入性
    print(f"\n{BLUE}【6】检查模块可导入性{RESET}")
    sys.path.insert(0, 'src')
    
    try:
        from planner import ClassifierDecision, ExecutionPlan, PlanStep
        check(True, "planner 数据结构可导入")
        passed += 1
    except ImportError as e:
        check(False, f"planner 数据结构导入失败: {e}")
        failed += 1
    
    try:
        from planner.classifier import VulnerabilityClassifier
        check(True, "VulnerabilityClassifier 可导入")
        passed += 1
    except ImportError as e:
        check(False, f"VulnerabilityClassifier 导入失败: {e}")
        failed += 1
    
    try:
        from planner.dag import PlanBuilder
        check(True, "PlanBuilder 可导入")
        passed += 1
    except ImportError as e:
        check(False, f"PlanBuilder 导入失败: {e}")
        failed += 1
    
    try:
        from planner.executor import DAGExecutor
        check(True, "DAGExecutor 可导入")
        passed += 1
    except ImportError as e:
        check(False, f"DAGExecutor 导入失败: {e}")
        failed += 1
    
    try:
        from capabilities.base import Capability
        check(True, "Capability 协议可导入")
        passed += 1
    except ImportError as e:
        check(False, f"Capability 导入失败: {e}")
        failed += 1
    
    try:
        from orchestrator.environment import EnvironmentOrchestrator
        check(True, "EnvironmentOrchestrator 可导入")
        passed += 1
    except ImportError as e:
        check(False, f"EnvironmentOrchestrator 导入失败: {e}")
        failed += 1
    
    try:
        from verification.strategies import VerificationStrategyRegistry
        check(True, "VerificationStrategyRegistry 可导入")
        passed += 1
    except ImportError as e:
        check(False, f"VerificationStrategyRegistry 导入失败: {e}")
        failed += 1
    
    try:
        from core.result_bus import ResultBus
        check(True, "ResultBus 可导入")
        passed += 1
    except ImportError as e:
        check(False, f"ResultBus 导入失败: {e}")
        failed += 1
    
    # 7. 运行快速功能测试
    print(f"\n{BLUE}【7】运行快速功能测试{RESET}")
    
    try:
        # 测试分类器
        classifier = VulnerabilityClassifier()
        test_cve = {
            'description': 'XSS vulnerability in web application',
            'cwe': [{'id': 'CWE-79', 'value': 'Cross-site Scripting'}]
        }
        decision = classifier.classify('CVE-TEST', test_cve)
        check(decision.profile == 'web-basic', f"分类器工作正常 (识别为 {decision.profile})")
        passed += 1
    except Exception as e:
        check(False, f"分类器测试失败: {e}")
        failed += 1
    
    try:
        # 测试 PlanBuilder
        builder = PlanBuilder()
        plan = builder.build(decision)
        check(len(plan.steps) > 0, f"PlanBuilder 工作正常 (生成 {len(plan.steps)} 步)")
        passed += 1
    except Exception as e:
        check(False, f"PlanBuilder 测试失败: {e}")
        failed += 1
    
    try:
        # 测试 YAML 加载
        yaml_plan = PlanBuilder.from_yaml('web-basic', 'CVE-TEST', {})
        check(len(yaml_plan.steps) > 0, f"YAML 加载正常 (加载 {len(yaml_plan.steps)} 步)")
        passed += 1
    except Exception as e:
        check(False, f"YAML 加载测试失败: {e}")
        failed += 1
    
    try:
        # 测试 ResultBus
        bus = ResultBus('CVE-TEST')
        bus.publish_event('test', 'started', {})
        bus.store_artifact('test', 'data', 'content')
        content = bus.load_artifact('test', 'data')
        check(content == 'content', "ResultBus 工作正常")
        passed += 1
    except Exception as e:
        check(False, f"ResultBus 测试失败: {e}")
        failed += 1
    
    # 总结
    print(f"\n{BLUE}{'='*60}{RESET}")
    print(f"{BLUE}   验证总结{RESET}")
    print(f"{BLUE}{'='*60}{RESET}")
    print(f"{GREEN}✅ 通过: {passed}{RESET}")
    print(f"{RED}❌ 失败: {failed}{RESET}")
    
    success_rate = (passed / (passed + failed)) * 100 if (passed + failed) > 0 else 0
    print(f"\n成功率: {success_rate:.1f}%")
    
    if failed == 0:
        print(f"\n{GREEN}🎉 所有检查通过！架构实施成功。{RESET}")
        print(f"\n{BLUE}下一步：{RESET}")
        print("  1. 运行完整测试: python tests/test_dag_e2e.py")
        print("  2. 使用真实 CVE 测试:")
        print("     python src/main.py --cve CVE-2024-XXXX --json data.json --dag")
    else:
        print(f"\n{YELLOW}⚠️  部分检查未通过，请检查失败项。{RESET}")
        sys.exit(1)

if __name__ == '__main__':
    main()
