#!/usr/bin/env python3
"""测试主动检测功能"""
from toolbox.command_ops import get_context_analyzer

# 获取分析器
analyzer = get_context_analyzer()

print("=" * 60)
print("测试1: 主动检测 .NET 类库项目（使用已知的类库项目）")
print("=" * 60)

# 测试 dotnet run 命令阻止
test_command = "dotnet run --project src/AspNetCore.Utilities.CloudStorage/AspNetCore.Utilities.CloudStorage.csproj"

block_reason = analyzer.should_block_command(test_command)
if block_reason:
    print(f"✅ 成功阻止！原因:\n{block_reason[:200]}...")
else:
    print("❌ 未能阻止（可能是因为找不到 .csproj 文件或它不是类库）")

print("\n" + "=" * 60)
print("测试2: 检查阻止机制是否正常工作")
print("=" * 60)

# 模拟之前检测到类库项目
from toolbox.command_ops import ContextualInsight
analyzer.blocking_insights.append(ContextualInsight(
    issue_type='library_project_detected',
    evidence='测试证据',
    blocking=True,
    suggestion='使用 dotnet test'
))

block_reason = analyzer.should_block_command("dotnet run --project test.csproj")
if block_reason:
    print(f"✅ 二次阻止成功！\n原因: {block_reason[:100]}...")
else:
    print("❌ 二次阻止失败")

print("\n✅ 测试完成")
