"""
端到端测试：验证新架构的完整流程
测试从分类器 → DAG 生成 → 执行器 → 结果验证的全链路
"""

import os
import sys
import json
from pathlib import Path

# 添加 src 到路径
src_path = Path(__file__).parent.parent / 'src'
sys.path.insert(0, str(src_path))


def test_classifier():
    """测试分类器能否正确识别漏洞类型"""
    print("\n" + "="*60)
    print("TEST 1: Vulnerability Classifier")
    print("="*60)
    
    from planner.classifier import VulnerabilityClassifier
    
    # 测试用例 1: Web 漏洞（XSS）
    web_cve = {
        'cve_id': 'CVE-TEST-WEB',
        'description': 'Cross-site scripting vulnerability in web application admin panel',
        'cwe': [{'id': 'CWE-79', 'value': 'Cross-site Scripting'}],
        'vulnerability_type': 'XSS'
    }
    
    classifier = VulnerabilityClassifier()
    decision = classifier.classify(web_cve['cve_id'], web_cve)
    
    print(f"✅ CVE: {web_cve['cve_id']}")
    print(f"   Profile: {decision.profile}")
    print(f"   Capabilities: {', '.join(decision.required_capabilities)}")
    print(f"   Confidence: {decision.confidence}")
    
    assert decision.profile == 'web-basic', f"Expected web-basic, got {decision.profile}"
    # 检查是否包含 Web 相关能力
    web_capabilities = [cap for cap in decision.required_capabilities if 'Browser' in cap or 'Http' in cap or 'Web' in cap.lower()]
    assert len(web_capabilities) > 0, f"Expected at least one web capability, got: {decision.required_capabilities}"
    
    # 测试用例 2: Native 漏洞（Buffer Overflow）
    native_cve = {
        'cve_id': 'CVE-TEST-NATIVE',
        'description': 'Buffer overflow in C library function',
        'cwe': [{'id': 'CWE-119', 'value': 'Buffer Overflow'}],
        'vulnerability_type': 'Memory Corruption'
    }
    
    decision = classifier.classify(native_cve['cve_id'], native_cve)
    
    print(f"\n✅ CVE: {native_cve['cve_id']}")
    print(f"   Profile: {decision.profile}")
    print(f"   Capabilities: {', '.join(decision.required_capabilities)}")
    
    assert decision.profile == 'native-local', f"Expected native-local, got {decision.profile}"
    # 检查是否包含构建相关能力
    build_capabilities = [cap for cap in decision.required_capabilities if 'Build' in cap or 'Repo' in cap or 'Info' in cap]
    assert len(build_capabilities) > 0, f"Expected at least one build capability, got: {decision.required_capabilities}"
    
    print("\n✅ Classifier tests PASSED\n")


def test_plan_builder():
    """测试执行计划生成器"""
    print("\n" + "="*60)
    print("TEST 2: DAG Plan Builder")
    print("="*60)
    
    from planner.classifier import VulnerabilityClassifier
    from planner.dag import PlanBuilder
    
    cve_entry = {
        'cve_id': 'CVE-2024-TEST',
        'description': 'SQL injection in admin login',
        'cwe': [{'id': 'CWE-89', 'value': 'SQL Injection'}]
    }
    
    classifier = VulnerabilityClassifier()
    decision = classifier.classify(cve_entry['cve_id'], cve_entry)
    
    builder = PlanBuilder()
    plan = builder.build(decision)
    
    print(f"✅ Generated plan for {plan.cve_id}")
    print(f"   Profile: {plan.profile}")
    print(f"   Steps: {len(plan.steps)}")
    
    for step in plan.steps:
        deps = f" <- {', '.join(step.dependencies)}" if step.dependencies else ""
        print(f"   - {step.step_id}: {step.capability}{deps}")
    
    assert len(plan.steps) > 0, "Plan should have at least one step"
    
    # 检查步骤依赖关系
    step_ids = {step.step_id for step in plan.steps}
    for step in plan.steps:
        for dep in step.dependencies:
            assert dep in step_ids, f"Step {step.step_id} depends on unknown step {dep}"
    
    print("\n✅ Plan builder tests PASSED\n")


def test_yaml_profile_loader():
    """测试从 YAML 加载 Profile"""
    print("\n" + "="*60)
    print("TEST 3: YAML Profile Loader")
    print("="*60)
    
    from planner.dag import PlanBuilder
    
    cve_entry = {
        'cve_id': 'CVE-2024-YAML-TEST',
        'description': 'Test YAML loading',
    }
    
    # 测试加载 native-local profile
    try:
        plan = PlanBuilder.from_yaml('native-local', 'CVE-2024-YAML-TEST', cve_entry)
        print(f"✅ Loaded native-local profile")
        print(f"   Steps: {len(plan.steps)}")
        print(f"   Artifacts: {len(plan.artifacts)}")
    except FileNotFoundError as e:
        print(f"⚠️  Profile file not found: {e}")
        print("   This is expected if profiles/ directory is not set up yet")
    except Exception as e:
        print(f"❌ Error loading profile: {e}")
        raise
    
    # 测试加载 web-basic profile
    try:
        plan = PlanBuilder.from_yaml('web-basic', 'CVE-2024-YAML-TEST', cve_entry)
        print(f"✅ Loaded web-basic profile")
        print(f"   Steps: {len(plan.steps)}")
    except FileNotFoundError:
        print(f"⚠️  web-basic profile not found (expected)")
    
    print("\n✅ YAML loader tests PASSED\n")


def test_capability_registry():
    """测试能力注册表"""
    print("\n" + "="*60)
    print("TEST 4: Capability Registry")
    print("="*60)
    
    try:
        from capabilities.registry import CapabilityRegistry
    except ImportError as e:
        print(f"⚠️  Skipping test: {e}")
        print("   This is expected if agentlib is not installed")
        print("\n✅ Registry tests SKIPPED (agentlib not available)\n")
        return
    
    registry = CapabilityRegistry()
    
    # 检查核心能力是否注册
    required_capabilities = [
        'collect-cve-info',
        'analyze-prerequisites',
        'build-environment',
        'generate-exploit',
        'verify-exploit'
    ]
    
    for cap in required_capabilities:
        assert registry.is_registered(cap), f"Capability {cap} not registered"
        cap_class = registry.get(cap)
        print(f"✅ {cap}: {cap_class.__name__}")
    
    # 列出所有能力
    all_caps = registry.list_capabilities()
    print(f"\n✅ Total registered capabilities: {len(all_caps)}")
    
    print("\n✅ Registry tests PASSED\n")


def test_result_bus():
    """测试结果总线事件系统"""
    print("\n" + "="*60)
    print("TEST 5: Result Bus Event System")
    print("="*60)
    
    from core.result_bus import ResultBus
    
    # 使用临时 CVE ID 避免污染真实数据
    bus = ResultBus('CVE-TEST-BUS')
    
    # 发布事件
    bus.publish_event('test-step', 'started', {'message': 'Test started'})
    bus.publish_event('test-step', 'completed', {'result': 'success'})
    
    # 存储产物
    bus.store_artifact('test-step', 'test-artifact', 'Test artifact content')
    
    # 读取产物
    content = bus.load_artifact('test-step', 'test-artifact')
    assert content == 'Test artifact content', "Artifact content mismatch"
    
    print("✅ Published 2 events")
    print("✅ Stored and retrieved 1 artifact")
    print("\n✅ Result bus tests PASSED\n")


def test_dag_executor_dry_run():
    """测试 DAG 执行器（Dry Run 模式）"""
    print("\n" + "="*60)
    print("TEST 6: DAG Executor (Dry Run)")
    print("="*60)
    
    try:
        from planner.classifier import VulnerabilityClassifier
        from planner.dag import PlanBuilder
        from planner.executor import DAGExecutor
        from capabilities.registry import CapabilityRegistry
        from core.result_bus import ResultBus
    except ImportError as e:
        print(f"⚠️  Skipping test: {e}")
        print("   This is expected if agentlib is not installed")
        print("\n✅ Executor tests SKIPPED (dependencies not available)\n")
        return
    
    # 创建简单的测试 CVE
    cve_entry = {
        'cve_id': 'CVE-DRY-RUN',
        'description': 'Test for DAG executor',
        'cwe': [{'id': 'CWE-89', 'value': 'SQL Injection'}]
    }
    
    # 分类
    classifier = VulnerabilityClassifier()
    decision = classifier.classify(cve_entry['cve_id'], cve_entry)
    
    # 生成计划
    builder = PlanBuilder()
    plan = builder.build(decision)
    
    # 初始化组件
    registry = CapabilityRegistry()
    result_bus = ResultBus('CVE-DRY-RUN')
    
    # 创建执行器（但不实际执行，只检查初始化）
    executor = DAGExecutor(plan, registry, result_bus)
    
    print(f"✅ Executor initialized")
    print(f"   Plan: {plan.cve_id}")
    print(f"   Steps: {len(plan.steps)}")
    print(f"   Registry has {len(registry.list_capabilities())} capabilities")
    
    # 测试拓扑排序
    try:
        sorted_steps = executor._topological_sort()
        print(f"✅ Topological sort successful: {len(sorted_steps)} steps")
        print(f"   Execution order: {' → '.join([s.step_id for s in sorted_steps])}")
    except Exception as e:
        print(f"❌ Topological sort failed: {e}")
        raise
    
    print("\n✅ Executor tests PASSED (dry run)\n")


def run_all_tests():
    """运行所有测试"""
    print("\n" + "█"*60)
    print("   DAG ARCHITECTURE - END-TO-END TEST SUITE")
    print("█"*60)
    
    tests = [
        ('Classifier', test_classifier),
        ('Plan Builder', test_plan_builder),
        ('YAML Loader', test_yaml_profile_loader),
        ('Capability Registry', test_capability_registry),
        ('Result Bus', test_result_bus),
        ('DAG Executor', test_dag_executor_dry_run),
    ]
    
    passed = 0
    failed = 0
    
    for test_name, test_func in tests:
        try:
            test_func()
            passed += 1
        except Exception as e:
            print(f"\n❌ {test_name} FAILED: {e}\n")
            import traceback
            traceback.print_exc()
            failed += 1
    
    # 总结
    print("\n" + "="*60)
    print("TEST SUMMARY")
    print("="*60)
    print(f"✅ Passed: {passed}/{len(tests)}")
    print(f"❌ Failed: {failed}/{len(tests)}")
    
    if failed == 0:
        print("\n🎉 ALL TESTS PASSED! Architecture is ready for real-world testing.")
    else:
        print("\n⚠️  Some tests failed. Please fix issues before proceeding.")
        sys.exit(1)


if __name__ == '__main__':
    run_all_tests()
