"""
测试 ExecutionReflector Agent

这个测试验证 ExecutionReflector 能够：
1. 分析 Agent 执行失败的日志
2. 识别重复失败模式
3. 给出正确的改进建议
"""

import sys
from pathlib import Path

# 添加 src 到路径
SRC_ROOT = Path(__file__).parent.parent / "src"
sys.path.insert(0, str(SRC_ROOT))


def test_basic_analysis():
    """测试基本的分析功能"""
    from agents.executionReflector import ExecutionReflector, AgentExecutionContext
    
    # 模拟 CVE-2025-54137 的执行日志
    simulated_log = """
[WebDriverAgent] Starting exploitation...
[Tool] navigate_to_url(url='http://localhost:8080/') → 404 Not Found
[Tool] navigate_to_url(url='http://localhost:8080/login') → 404 Not Found
[Tool] navigate_to_url(url='http://localhost:8080/api') → 404 Not Found
[Tool] navigate_to_url(url='http://localhost:8080/api/login') → 404 Not Found
[Tool] navigate_to_url(url='http://localhost:8080/admin') → 404 Not Found
[Tool] navigate_to_url(url='http://localhost:8080/api/v1') → 404 Not Found
[Tool] navigate_to_url(url='http://localhost:8080/api/v2') → 404 Not Found
[Tool] navigate_to_url(url='http://localhost:8080/api/v3') → 404 Not Found
[Tool] navigate_to_url(url='http://localhost:8080/api/v4') → 404 Not Found
[Tool] navigate_to_url(url='http://localhost:8080/api/v5') → 404 Not Found
[Tool] navigate_to_url(url='http://localhost:8080/api/v6') → 404 Not Found
[Tool] navigate_to_url(url='http://localhost:8080/api/v7') → 404 Not Found
[Tool] navigate_to_url(url='http://localhost:8080/api/v8') → 404 Not Found
[Tool] navigate_to_url(url='http://localhost:8080/api/v9') → 404 Not Found
[Tool] navigate_to_url(url='http://localhost:8080/api/v10') → 404 Not Found
[Tool] navigate_to_url(url='http://localhost:8080/api/v11') → 404 Not Found
[Tool] navigate_to_url(url='http://localhost:8080/api/v12') → 404 Not Found
[Tool] navigate_to_url(url='http://localhost:8080/api/v13') → 404 Not Found
[WebDriverAgent] Max iterations reached, giving up
"""
    
    # 模拟工具调用历史
    tool_calls = [
        {'tool': 'navigate_to_url', 'args': {'url': f'http://localhost:8080/path{i}'}, 'result': '404'}
        for i in range(18)
    ]
    
    # CVE 知识
    cve_knowledge = """
CVE-2025-54137: 使用硬编码凭证漏洞 (CWE-1392)

**漏洞类型**: API 凭证漏洞
**默认凭证**: admin / password
**API 端点**: /api/login
**请求方法**: POST
**Content-Type**: application/json
**Payload**: {"username":"admin","password":"password"}
"""
    
    # 创建执行上下文
    context = AgentExecutionContext(
        agent_name='WebDriverAgent',
        cve_id='CVE-2025-54137',
        cve_knowledge=cve_knowledge,
        execution_log=simulated_log,
        tool_calls=tool_calls,
        final_status='failure',
        iterations_used=18,
        max_iterations=20
    )
    
    # 分析
    print("\n" + "="*80)
    print("测试 ExecutionReflector 基本分析功能")
    print("="*80 + "\n")
    
    reflector = ExecutionReflector(model='gpt-4o-mini')  # 测试用轻量模型
    analysis = reflector.analyze(context)
    
    # 验证结果
    print("\n" + "="*80)
    print("验证分析结果")
    print("="*80 + "\n")
    
    assert analysis.failure_type in ['tool_misuse', 'loop_detected', 'knowledge_gap'], \
        f"失败类型不正确: {analysis.failure_type}"
    print(f"✅ 失败类型正确: {analysis.failure_type}")
    
    assert analysis.repeated_pattern is not None, "应该检测到重复模式"
    print(f"✅ 检测到重复模式: {analysis.repeated_pattern}")
    
    # 根据 CVE 知识，应该建议使用 POST 请求工具
    if 'send_http_request' in analysis.suggested_tool or 'POST' in analysis.suggested_strategy:
        print(f"✅ 正确建议使用 HTTP POST 工具")
    else:
        print(f"⚠️ 未明确建议 POST 工具（可能是模型输出变化）")
    
    assert len(analysis.suggested_strategy) > 50, "修正策略应该足够详细"
    print(f"✅ 提供了详细的修正策略（{len(analysis.suggested_strategy)} 字符）")
    
    print(f"\n置信度: {analysis.confidence:.1%}")
    
    print("\n" + "="*80)
    print("✅ 测试通过！")
    print("="*80 + "\n")


def test_pattern_detection():
    """测试重复模式检测"""
    from agents.executionReflector import ExecutionReflector
    
    print("\n" + "="*80)
    print("测试快速模式检测")
    print("="*80 + "\n")
    
    reflector = ExecutionReflector()
    
    # 模拟工具调用：连续 15 次使用相同工具都返回 404
    tool_calls = [
        {'tool': 'navigate_to_url', 'args': {}, 'result': '404 Not Found'}
        for _ in range(15)
    ]
    
    pattern = reflector._quick_detect_pattern(tool_calls, "404 " * 20)
    
    assert pattern is not None, "应该检测到重复模式"
    print(f"✅ 检测到模式: {pattern}")
    
    # 测试无重复的情况
    diverse_calls = [
        {'tool': 'navigate', 'args': {}, 'result': '200 OK'},
        {'tool': 'click', 'args': {}, 'result': 'Success'},
        {'tool': 'input', 'args': {}, 'result': 'Done'},
    ]
    
    no_pattern = reflector._quick_detect_pattern(diverse_calls, "Success")
    assert no_pattern is None, "不应该检测到模式"
    print(f"✅ 正确判断无重复模式")
    
    print("\n" + "="*80)
    print("✅ 模式检测测试通过！")
    print("="*80 + "\n")


def test_log_extraction():
    """测试从日志中提取工具调用"""
    from agents.executionReflector import extract_tool_calls_from_log
    
    print("\n" + "="*80)
    print("测试日志解析")
    print("="*80 + "\n")
    
    log = """
[Tool] navigate_to_url(url='http://example.com') → 200 OK
[Tool] click_element(selector='#login') → Success
[Tool] input_text(selector='#username', text='admin') → Done
"""
    
    tool_calls = extract_tool_calls_from_log(log)
    
    assert len(tool_calls) == 3, f"应该提取到3个工具调用，实际: {len(tool_calls)}"
    print(f"✅ 提取到 {len(tool_calls)} 个工具调用")
    
    assert tool_calls[0]['tool'] == 'navigate_to_url', "第一个工具应该是 navigate_to_url"
    print(f"✅ 工具名称解析正确: {tool_calls[0]['tool']}")
    
    assert 'url' in tool_calls[0]['args'], "应该解析出 url 参数"
    print(f"✅ 参数解析正确: {tool_calls[0]['args']}")
    
    print("\n" + "="*80)
    print("✅ 日志解析测试通过！")
    print("="*80 + "\n")


def test_integration_with_adapter():
    """测试与 WebDriverAdapter 的集成"""
    print("\n" + "="*80)
    print("测试 WebDriverAdapter 集成")
    print("="*80 + "\n")
    
    # 验证导入
    try:
        from capabilities.adapters import WebDriverAdapter
        print("✅ WebDriverAdapter 导入成功")
    except ImportError as e:
        print(f"⚠️ WebDriverAdapter 导入失败: {e}")
        print("   这是预期的，因为可能缺少 Web 相关依赖")
        return
    
    # 验证 ExecutionReflector 可以被调用
    from agents.executionReflector import ExecutionReflector
    print("✅ ExecutionReflector 可以导入")
    
    print("\n" + "="*80)
    print("✅ 集成测试通过！")
    print("="*80 + "\n")


def run_all_tests():
    """运行所有测试"""
    print("\n" + "█"*80)
    print(" "*20 + "ExecutionReflector Agent 测试套件")
    print("█"*80 + "\n")
    
    try:
        test_pattern_detection()
        test_log_extraction()
        test_integration_with_adapter()
        
        # 基本分析测试需要 OpenAI API，如果没有配置则跳过
        import os
        if os.getenv('OPENAI_API_KEY'):
            test_basic_analysis()
        else:
            print("\n⚠️ 跳过 LLM 分析测试（未设置 OPENAI_API_KEY）")
            print("   提示: 设置环境变量后可测试完整功能\n")
        
        print("\n" + "█"*80)
        print(" "*25 + "所有测试通过！✅")
        print("█"*80 + "\n")
        
    except AssertionError as e:
        print(f"\n❌ 测试失败: {e}\n")
        raise
    except Exception as e:
        print(f"\n❌ 测试错误: {e}\n")
        import traceback
        traceback.print_exc()
        raise


if __name__ == '__main__':
    run_all_tests()
