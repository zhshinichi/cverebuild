#!/usr/bin/env python3
"""调试主动检测"""
import sys
sys.path.insert(0, '/src')
import os

csproj_path = 'src/AspNetCore.Utilities.CloudStorage/AspNetCore.Utilities.CloudStorage.csproj'
print(f'工作目录: {os.getcwd()}')
print(f'文件存在: {os.path.exists(csproj_path)}')

if os.path.exists(csproj_path):
    with open(csproj_path, 'r') as f:
        content = f.read()
    
    content_lower = content.lower()
    has_output_type = '<outputtype>library</outputtype>' in content_lower
    is_web_sdk = 'microsoft.net.sdk.web' in content_lower
    
    print(f'包含 OutputType=Library: {has_output_type}')
    print(f'是 Web SDK: {is_web_sdk}')
    print(f'应该阻止条件: has_output_type={has_output_type} AND NOT is_web_sdk={not is_web_sdk}')
    
    # 问题发现：这个项目同时有 Web SDK 和 Library OutputType
    # 需要检查实际条件

# 测试主动检测
from toolbox.command_ops import get_context_analyzer

analyzer = get_context_analyzer()
test_command = 'dotnet run --project src/AspNetCore.Utilities.CloudStorage/AspNetCore.Utilities.CloudStorage.csproj'

# 手动调用主动检测
result = analyzer._proactive_check_dotnet_project(test_command)
print(f'\n主动检测结果: {result[:100] if result else "None (未阻止)"}')
