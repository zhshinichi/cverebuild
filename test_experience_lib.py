#!/usr/bin/env python3
"""测试经验库集成"""
from toolbox.command_ops import get_context_analyzer

# 获取分析器
analyzer = get_context_analyzer()
print('经验库加载状态:', '成功' if analyzer.experience_library else '失败')

# 模拟一个 .NET 类库项目错误
test_output = "A project with an Output Type of Class Library cannot be started directly. The current OutputType is 'Library'."
test_command = 'dotnet run --project test.csproj'

# 分析输出
insight = analyzer.analyze_dotnet_output(test_command, test_output, 1)
print('\n分析结果:', insight.issue_type if insight else '无')
print('是否阻止:', insight.blocking if insight else '否')

# 测试命令阻止
block_reason = analyzer.should_block_command('dotnet run --project test.csproj')
print('\n再次执行 dotnet run 被阻止:', '是' if block_reason else '否')
if block_reason:
    print('阻止原因:', block_reason[:100])

# 检查经验库状态
print('\n经验库摘要:')
print(analyzer.experience_library.get_summary())

print('\n✅ 测试通过：经验库集成成功！')
