#!/usr/bin/env python3
"""
在容器中验证 ContextAwareAnalyzer 智能反思机制改进
"""
import sys
sys.path.insert(0, '/workspaces/submission/src')
from toolbox.command_ops import ContextAwareAnalyzer, get_context_analyzer, reset_context_analyzer

print('='*60)
print('ContextAwareAnalyzer 智能反思机制验证')
print('='*60)

passed = 0
failed = 0

# 测试1: curl下载9字节检测（即使exit_code=0）
print('\n[测试1] curl下载9字节检测（关键改进）')
analyzer = ContextAwareAnalyzer()
result = analyzer.analyze_command(
    'curl -L -o lunary.zip https://github.com/lunary-ai/lunary/archive/refs/tags/v1.4.8.zip',
    '100     9  100     9    0     0     18      0 --:--:-- --:--:-- --:--:--    18',
    exit_code=0
)
if result and result.issue_type == 'download_failed':
    print('  ✅ 通过: 检测到9字节下载失败')
    print(f'     证据: {result.evidence[:60]}...')
    has_git_clone = 'git clone' in result.suggestion.lower()
    print(f'     包含git clone建议: {has_git_clone}')
    passed += 1
else:
    print('  ❌ 失败: 未检测到下载失败')
    failed += 1

# 测试2: file命令检测并记录黑名单
print('\n[测试2] file命令检测ASCII text并阻止后续unzip')
analyzer2 = ContextAwareAnalyzer()
result2 = analyzer2.analyze_command('file lunary.zip', 'lunary.zip: ASCII text, with no line terminators', exit_code=0)
if result2 and result2.issue_type == 'file_corrupted':
    print('  ✅ 通过: 检测到文件类型错误')
    # 验证是否记录到黑名单
    if 'lunary.zip' in analyzer2.download_history and analyzer2.download_history['lunary.zip']['status'] == 'not_zip':
        print('  ✅ 通过: 文件已记录到黑名单')
        # 验证阻止机制
        block = analyzer2.should_block_command('unzip lunary.zip')
        if block:
            print(f'  ✅ 通过: unzip被阻止')
            passed += 1
        else:
            print('  ❌ 失败: unzip未被阻止')
            failed += 1
    else:
        print('  ❌ 失败: 文件未记录到黑名单')
        failed += 1
else:
    print('  ❌ 失败: 未检测到文件类型错误')
    failed += 1

# 测试3: ls -la检测小文件
print('\n[测试3] ls -la检测异常小的zip文件')
analyzer3 = ContextAwareAnalyzer()
ls_output = '-rw-r--r-- 1 root root    9 Dec 12 08:36 lunary.zip'
result3 = analyzer3.analyze_command('ls -la', ls_output, exit_code=0)
if result3 and result3.issue_type == 'tiny_archive_detected':
    print('  ✅ 通过: 检测到小文件')
    print(f'     证据: {result3.evidence[:60]}...')
    passed += 1
else:
    print('  ❌ 失败: 未检测到小文件')
    failed += 1

# 测试4: URL记忆并阻止重复下载
print('\n[测试4] URL失败记忆并阻止重复下载')
analyzer4 = ContextAwareAnalyzer()
analyzer4.analyze_command(
    'curl -L -o test.zip https://github.com/user/repo/archive/refs/tags/v1.0.zip',
    '100     9  100     9    0     0     18      0',
    exit_code=0
)
if any('v1.0' in url for url in analyzer4.known_bad_urls):
    print('  ✅ 通过: URL已记录到失败列表')
    block = analyzer4.should_block_command('curl -L -o test2.zip https://github.com/user/repo/archive/refs/tags/v1.0.zip')
    if block:
        print('  ✅ 通过: 重复下载被阻止')
        passed += 1
    else:
        print('  ❌ 失败: 重复下载未被阻止')
        failed += 1
else:
    print('  ❌ 失败: URL未记录')
    failed += 1

# 测试5: unzip错误检测
print('\n[测试5] unzip错误检测')
analyzer5 = ContextAwareAnalyzer()
unzip_output = '''Archive:  lunary.zip
  End-of-central-directory signature not found.  Either this file is not
  a zipfile, or it constitutes one disk of a multi-part archive.'''
result5 = analyzer5.analyze_command('unzip lunary.zip', unzip_output, exit_code=9)
if result5 and result5.issue_type == 'file_not_zip':
    print('  ✅ 通过: 检测到无效zip文件')
    has_git_clone = 'git clone' in result5.suggestion.lower()
    print(f'     建议包含git clone: {has_git_clone}')
    passed += 1
else:
    print('  ❌ 失败: 未检测到unzip错误')
    failed += 1

print('\n' + '='*60)
print(f'验证结果: {passed} 通过, {failed} 失败')
print('='*60)

# 返回失败数作为退出码
sys.exit(failed)
