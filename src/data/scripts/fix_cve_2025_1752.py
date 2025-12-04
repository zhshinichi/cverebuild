#!/usr/bin/env python3
"""
修复 CVE-2025-1752 数据文件

问题：CVE-2025-1752 的 sw_version_wget 指向了 llama_index 主仓库的 v0.3.5 标签，
但漏洞实际存在于 llama-index-readers-web pip 包的 0.3.5 版本中。

主仓库的 v0.3.5 标签是2023年2月的旧版本，那时候 llama-index-readers-web 
还是作为主仓库的一部分，使用的是 gpt_index 包名。

解决方案：
1. 添加 pip_package 字段指定正确的包名和版本
2. 保留 sw_version_wget 但标注它不适用于直接下载

这样 CVE-Genie 可以识别需要使用 pip install 而不是 wget 下载
"""

import json
import os
from datetime import datetime

def fix_cve_data():
    # 获取数据文件路径
    script_dir = os.path.dirname(os.path.abspath(__file__))
    data_file = os.path.join(script_dir, '..', 'large_scale', 'data.json')
    
    print(f"📂 Loading data from: {data_file}")
    
    with open(data_file, 'r', encoding='utf-8') as f:
        data = json.load(f)
    
    if 'CVE-2025-1752' not in data:
        print("❌ CVE-2025-1752 not found in data!")
        return
    
    cve_data = data['CVE-2025-1752']
    
    print("\n📋 Current CVE-2025-1752 data:")
    print(f"   sw_version: {cve_data.get('sw_version')}")
    print(f"   sw_version_wget: {cve_data.get('sw_version_wget')}")
    
    # 修复数据
    # 添加新字段指示这是一个 pip 包
    cve_data['pip_package'] = 'llama-index-readers-web'
    cve_data['pip_version'] = '0.3.5'
    cve_data['sw_version'] = '0.3.5'  # 不需要 v 前缀
    
    # 标注 sw_version_wget 不适用
    cve_data['sw_version_wget_note'] = (
        "NOTE: This wget URL points to the main llama_index repo v0.3.5 (Feb 2023), "
        "which does NOT contain the vulnerable KnowledgeBaseWebReader class. "
        "The vulnerability exists in the separate pip package 'llama-index-readers-web==0.3.5'. "
        "Use 'pip install llama-index-readers-web==0.3.5' instead of downloading from GitHub."
    )
    
    # 更新描述以明确受影响的包
    original_desc = cve_data.get('description', '')
    if 'llama-index-readers-web' not in original_desc:
        cve_data['description'] = (
            f"[Affected Package: llama-index-readers-web==0.3.5] "
            f"{original_desc}"
        )
    
    print("\n✅ Updated CVE-2025-1752 data:")
    print(f"   pip_package: {cve_data.get('pip_package')}")
    print(f"   pip_version: {cve_data.get('pip_version')}")
    print(f"   sw_version: {cve_data.get('sw_version')}")
    
    # 备份原始文件
    backup_file = data_file + f'.backup.{datetime.now().strftime("%Y%m%d_%H%M%S")}'
    with open(backup_file, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=4, ensure_ascii=False)
    print(f"\n📦 Backup saved to: {backup_file}")
    
    # 保存修改后的数据
    with open(data_file, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=4, ensure_ascii=False)
    print(f"💾 Updated data saved to: {data_file}")
    
    print("\n🎉 Fix complete!")
    print("\n📌 Next steps:")
    print("   1. Update repoBuilder to check for 'pip_package' field")
    print("   2. If pip_package exists, use 'pip install <pip_package>==<pip_version>'")
    print("   3. Instead of downloading and extracting from GitHub")


if __name__ == '__main__':
    fix_cve_data()
