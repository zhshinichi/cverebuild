#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
从 webcve_ids.txt 中随机筛选 100 个 CVE，
从 cvelist/2025 获取原始数据，
整理成统一格式保存到 webdata.json
"""

import json
import os
import random
from pathlib import Path
from typing import Dict, Any, List, Optional

# 路径配置
BASE_DIR = Path(__file__).parent.parent
WEBCVE_IDS_FILE = BASE_DIR / "large_scale" / "webcve_ids.txt"
CVELIST_2025 = BASE_DIR / "cvelist" / "2025"
OUTPUT_FILE = BASE_DIR / "large_scale" / "webdata.json"


def get_cve_file_path(cve_id: str) -> Path:
    """根据 CVE ID 获取对应的 JSON 文件路径"""
    # CVE-2025-29927 -> 29xxx/CVE-2025-29927.json
    parts = cve_id.split("-")
    if len(parts) != 3:
        return None
    year = parts[1]
    num = parts[2]
    
    # 确定子目录
    if len(num) <= 4:
        subdir = f"{num[0]}xxx"
    else:
        subdir = f"{num[:2]}xxx"
    
    return CVELIST_2025 / subdir / f"{cve_id}.json"


def extract_cwe(cve_data: Dict) -> List[Dict]:
    """从原始 CVE 数据提取 CWE 信息"""
    cwes = []
    try:
        cna = cve_data.get("containers", {}).get("cna", {})
        problem_types = cna.get("problemTypes", [])
        for pt in problem_types:
            for desc in pt.get("descriptions", []):
                if desc.get("cweId"):
                    cwes.append({
                        "id": desc["cweId"],
                        "value": f"{desc['cweId']}: {desc.get('description', '')}"
                    })
    except:
        pass
    return cwes


def extract_description(cve_data: Dict) -> str:
    """提取漏洞描述"""
    try:
        cna = cve_data.get("containers", {}).get("cna", {})
        descriptions = cna.get("descriptions", [])
        for desc in descriptions:
            if desc.get("lang") == "en":
                return desc.get("value", "")
        if descriptions:
            return descriptions[0].get("value", "")
    except:
        pass
    return ""


def extract_published_date(cve_data: Dict) -> str:
    """提取发布日期"""
    try:
        return cve_data.get("cveMetadata", {}).get("datePublished", "")
    except:
        return ""


def extract_references(cve_data: Dict) -> List[str]:
    """提取参考链接"""
    refs = []
    try:
        cna = cve_data.get("containers", {}).get("cna", {})
        for ref in cna.get("references", []):
            url = ref.get("url")
            if url:
                refs.append(url)
    except:
        pass
    return refs


def extract_affected_versions(cve_data: Dict) -> Dict:
    """提取受影响的版本信息"""
    try:
        cna = cve_data.get("containers", {}).get("cna", {})
        affected = cna.get("affected", [])
        if affected:
            first = affected[0]
            vendor = first.get("vendor", "")
            product = first.get("product", "")
            versions = first.get("versions", [])
            
            # 尝试找到第一个受影响的版本
            for v in versions:
                if v.get("status") == "affected":
                    version_str = v.get("version", "")
                    return {
                        "vendor": vendor,
                        "product": product,
                        "version": version_str
                    }
    except:
        pass
    return {}


def extract_patch_commits(cve_data: Dict) -> List[Dict]:
    """提取补丁 commit 信息"""
    commits = []
    try:
        cna = cve_data.get("containers", {}).get("cna", {})
        for ref in cna.get("references", []):
            url = ref.get("url", "")
            if "commit" in url.lower() and "github.com" in url.lower():
                commits.append({
                    "url": url,
                    "content": ""  # 需要额外爬取才能获得，暂时为空
                })
    except:
        pass
    return commits


def extract_security_advisory(cve_data: Dict) -> List[Dict]:
    """提取安全公告信息"""
    advisories = []
    try:
        cna = cve_data.get("containers", {}).get("cna", {})
        for ref in cna.get("references", []):
            url = ref.get("url", "")
            if "security/advisories" in url.lower() or "GHSA" in url:
                advisories.append({
                    "url": url,
                    "content": "",  # 需要额外爬取
                    "effective": False,
                    "effective_reason": ""
                })
    except:
        pass
    return advisories


def convert_cve_format(cve_id: str, raw_data: Dict) -> Dict:
    """将原始 CVE 数据转换为目标格式"""
    
    # 从原始数据提取
    affected = extract_affected_versions(raw_data)
    
    result = {
        "published_date": extract_published_date(raw_data),
        "patch_commits": extract_patch_commits(raw_data),
        "sw_version": affected.get("version", ""),
        "sw_version_wget": "",
        "description": extract_description(raw_data),
        "sec_adv": extract_security_advisory(raw_data),
        "cwe": extract_cwe(raw_data)
    }
    
    return result


def main():
    print("=" * 60)
    print("Web CVE 数据处理脚本")
    print("=" * 60)
    
    # 1. 从 webcve_ids.txt 加载 CVE ID 列表
    print("\n[1/4] 从 webcve_ids.txt 加载 CVE ID 列表...")
    with open(WEBCVE_IDS_FILE, "r", encoding="utf-8") as f:
        all_cve_ids = [line.strip() for line in f if line.strip()]
    print(f"  - 共 {len(all_cve_ids)} 个 CVE")
    
    # 2. 随机选择 100 个
    print("\n[2/4] 随机选择 100 个 CVE...")
    if len(all_cve_ids) > 100:
        selected_ids = random.sample(all_cve_ids, 100)
    else:
        selected_ids = all_cve_ids
        print(f"  - 注意：只有 {len(selected_ids)} 个 CVE，全部选择")
    
    selected_ids.sort()  # 排序以保持一致性
    print(f"  - 选择了 {len(selected_ids)} 个 CVE")
    
    # 3. 处理每个 CVE
    print("\n[3/4] 从 cvelist/2025 获取并处理 CVE 数据...")
    result = {}
    found_count = 0
    missing_count = 0
    
    for i, cve_id in enumerate(selected_ids):
        if (i + 1) % 20 == 0:
            print(f"  - 进度: {i + 1}/{len(selected_ids)}")
        
        # 从 cvelist 获取原始数据
        cve_file = get_cve_file_path(cve_id)
        raw_data = None
        
        if cve_file and cve_file.exists():
            try:
                with open(cve_file, "r", encoding="utf-8") as f:
                    raw_data = json.load(f)
                found_count += 1
            except Exception as e:
                print(f"  - 警告：读取 {cve_id} 失败: {e}")
        else:
            missing_count += 1
            print(f"  - 警告：找不到 {cve_id} 的原始文件: {cve_file}")
        
        # 转换格式
        if raw_data:
            converted = convert_cve_format(cve_id, raw_data)
        else:
            # 创建空的占位数据
            converted = {
                "published_date": "",
                "patch_commits": [],
                "sw_version": "",
                "sw_version_wget": "",
                "description": "",
                "sec_adv": [],
                "cwe": []
            }
        
        result[cve_id] = converted
    
    print(f"\n  - 找到原始文件: {found_count}")
    print(f"  - 缺失原始文件: {missing_count}")
    
    # 4. 保存结果
    print(f"\n[4/4] 保存到 {OUTPUT_FILE}...")
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=4, ensure_ascii=False)
    
    print(f"\n✅ 完成！共处理 {len(result)} 个 CVE")
    print(f"   输出文件: {OUTPUT_FILE}")


if __name__ == "__main__":
    main()
