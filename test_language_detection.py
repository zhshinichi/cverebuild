#!/usr/bin/env python3
"""测试语言检测修复"""

import json
import sys
sys.path.insert(0, 'src')

from agents.preReqBuilder import PreReqBuilder

# 加载 CVE-2024-7254 数据
import os
data_path = '/workspaces/submission/src/data/cve_files/CVE-2024-7254.json' if os.path.exists('/workspaces/submission') else 'src/data/cve_files/CVE-2024-7254.json'
with open(data_path) as f:
    cve_data = json.load(f)['CVE-2024-7254']

print("=" * 70)
print("CVE-2024-7254 语言检测测试")
print("=" * 70)

# 创建 PreReqBuilder 实例
builder = PreReqBuilder(
    cve_knowledge="Protocol Buffers vulnerability",
    project_dir_tree="protobuf-28.1/",
    cve_raw_data=cve_data
)

print(f"\n✅ 检测到的语言: {builder.DETECTED_LANGUAGE}")
print(f"\n📄 Patch 文件片段:")
for patch in cve_data['patch_commits'][:1]:
    content = patch['content'][:500]
    print(content)
    print("...")

if builder.DETECTED_LANGUAGE == 'java':
    print("\n✅ 成功！正确识别为 Java 项目")
    print("   - 应该使用 Maven/Gradle")
    print("   - protobuf-java:3.28.0 而不是 pip install protobuf==28.1")
else:
    print(f"\n❌ 失败！检测为: {builder.DETECTED_LANGUAGE}")

print("=" * 70)
