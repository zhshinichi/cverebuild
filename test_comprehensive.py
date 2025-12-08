#!/usr/bin/env python3
"""测试真实 CVE 数据的硬件过滤和部署策略分析"""

import sys
import json
import os
import re
sys.path.insert(0, '/workspaces/submission/src/data/scripts')

# 直接导入函数，避免循环导入
def get_cve_file_path(cve_id: str) -> str:
    """根据 CVE ID 计算文件路径"""
    match = re.match(r'CVE-(\d{4})-(\d+)', cve_id, re.IGNORECASE)
    if not match:
        raise ValueError(f"Invalid CVE ID format: {cve_id}")
    
    year = match.group(1)
    number = int(match.group(2))
    folder = f"{(number // 1000)}xxx"
    
    base_dir = "/workspaces/submission/src/data/cvelist"
    file_path = f"{base_dir}/{year}/{folder}/{cve_id.upper()}.json"
    return file_path

def load_cve_data(cve_id: str):
    """加载 CVE 原始数据"""
    try:
        file_path = get_cve_file_path(cve_id)
        if not os.path.exists(file_path):
            return None
        with open(file_path, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception as e:
        print(f"Error loading {cve_id}: {e}")
        return None

from web_cve_classifier import WebCVEClassifier

# 测试 CVE 列表
test_cves = [
    ("CVE-2025-34117", "路由器固件后门"),
    ("CVE-2025-55007", "Knowage SSRF"),
    ("CVE-2025-1225", "ywoa XXE")
]

print("=" * 80)
print("综合测试：硬件过滤 + 部署策略分析")
print("=" * 80)

classifier = WebCVEClassifier()

for cve_id, description in test_cves:
    print(f"\n{'='*80}")
    print(f"测试: {cve_id} ({description})")
    print(f"{'='*80}")
    
    # 1. 加载真实 CVE 数据
    cve_data = load_cve_data(cve_id)
    if not cve_data:
        print(f"❌ 无法加载 {cve_id} 数据")
        continue
    
    # 提取描述
    try:
        desc = cve_data['containers']['cna']['descriptions'][0]['value']
        print(f"描述: {desc[:150]}...")
    except:
        desc = ""
    
    # 2. 硬件过滤检测
    # 构造分类器需要的数据格式
    cve_entry = {
        "description": desc,
        "sw_name": "",
        "sw_version_wget": "",
        "cwe": []
    }
    
    try:
        affected = cve_data['containers']['cna']['affected'][0]
        cve_entry['sw_name'] = affected.get('product', '')
    except:
        pass
    
    result = classifier.classify(cve_id, cve_entry)
    
    print(f"\n[硬件过滤]")
    print(f"  Is Hardware: {result.is_hardware}")
    if result.is_hardware:
        print(f"  ⚠️  硬件漏洞，跳过复现")
        print(f"  原因: {result.hardware_reasons}")
        continue
    else:
        print(f"  ✅ 非硬件漏洞，可以复现")
    
    # 3. 部署策略分析
    print(f"\n[部署策略分析]")
    
    # 提取 GitHub URLs
    urls = []
    try:
        refs = cve_data.get('containers', {}).get('cna', {}).get('references', [])
        for ref in refs:
            url = ref.get('url', '')
            if any(domain in url for domain in ['github.com', 'gitlab.com', 'gitee.com']):
                urls.append(url)
                print(f"  找到仓库: {url}")
    except:
        pass
    
    if urls:
        print(f"  ✅ 可从源码部署")
    else:
        print(f"  ⚠️  未找到公开仓库")
    
    print(f"  Notes: 查看 DeploymentStrategyAnalyzer 获取详细部署指令")

print("\n" + "=" * 80)
print("测试完成！")
print("=" * 80)
