#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
从 webcve_ids.txt 中筛选有 GitHub 资源的 CVE
优先选择有 patch commit 和 security advisory 的 CVE
"""

import json
import os
import re
import random
from pathlib import Path
from typing import Dict, Any, List, Optional
from datetime import datetime

# 路径配置
BASE_DIR = Path(__file__).parent.parent
WEBCVE_IDS_FILE = BASE_DIR / "large_scale" / "webcve_ids.txt"
CVELIST_2025 = BASE_DIR / "cvelist" / "2025"
OUTPUT_FILE = BASE_DIR / "large_scale" / "webdata.json"


def get_cve_file_path(cve_id: str) -> Path:
    """根据 CVE ID 获取对应的 JSON 文件路径"""
    parts = cve_id.split("-")
    if len(parts) != 3:
        return None
    num = parts[2]
    
    if len(num) <= 4:
        subdir = f"{num[0]}xxx"
    else:
        subdir = f"{num[:2]}xxx"
    
    return CVELIST_2025 / subdir / f"{cve_id}.json"


def extract_urls(cve_raw: Dict) -> List[str]:
    """提取所有 URL"""
    urls = []
    try:
        cna = cve_raw.get("containers", {}).get("cna", {})
        for ref in cna.get("references", []):
            url = ref.get("url")
            if url:
                urls.append(url)
        
        for adp in cve_raw.get("containers", {}).get("adp", []):
            for ref in adp.get("references", []):
                url = ref.get("url")
                if url:
                    urls.append(url)
    except:
        pass
    return urls


def analyze_cve_resources(cve_id: str) -> Dict:
    """分析 CVE 的资源情况"""
    cve_file = get_cve_file_path(cve_id)
    
    if not cve_file or not cve_file.exists():
        return {"exists": False}
    
    with open(cve_file, "r", encoding="utf-8") as f:
        cve_raw = json.load(f)
    
    urls = extract_urls(cve_raw)
    
    # 分析 URL 类型
    has_github_commit = False
    has_github_advisory = False
    has_github_repo = False
    
    github_info = {}
    
    for url in urls:
        if "github.com" in url:
            has_github_repo = True
            
            # 检查 commit
            commit_match = re.search(r'github\.com/([^/]+)/([^/]+)/commit/([a-f0-9]+)', url)
            if commit_match:
                has_github_commit = True
                github_info['owner'] = commit_match.group(1)
                github_info['repo'] = commit_match.group(2)
                github_info['commit_url'] = url
            
            # 检查 advisory
            if "security/advisories" in url or "GHSA-" in url:
                has_github_advisory = True
                github_info['advisory_url'] = url
                
                adv_match = re.search(r'github\.com/([^/]+)/([^/]+)/security', url)
                if adv_match:
                    github_info['owner'] = adv_match.group(1)
                    github_info['repo'] = adv_match.group(2)
    
    # 计算分数
    score = 0
    if has_github_commit:
        score += 3
    if has_github_advisory:
        score += 2
    if has_github_repo:
        score += 1
    
    return {
        "exists": True,
        "cve_id": cve_id,
        "score": score,
        "has_github_commit": has_github_commit,
        "has_github_advisory": has_github_advisory,
        "has_github_repo": has_github_repo,
        "github_info": github_info,
        "urls": urls,
        "raw": cve_raw
    }


def extract_cwe(cve_raw: Dict) -> List[Dict]:
    """提取 CWE"""
    cwes = []
    try:
        cna = cve_raw.get("containers", {}).get("cna", {})
        for pt in cna.get("problemTypes", []):
            for desc in pt.get("descriptions", []):
                if desc.get("cweId"):
                    cwes.append({
                        "id": desc["cweId"],
                        "value": f"{desc['cweId']}: {desc.get('description', '')}"
                    })
    except:
        pass
    return cwes


def extract_description(cve_raw: Dict) -> str:
    """提取描述"""
    try:
        cna = cve_raw.get("containers", {}).get("cna", {})
        for desc in cna.get("descriptions", []):
            if desc.get("lang") == "en":
                return desc.get("value", "")
        if cna.get("descriptions"):
            return cna["descriptions"][0].get("value", "")
    except:
        pass
    return ""


def extract_published_date(cve_raw: Dict) -> str:
    """提取发布日期"""
    return cve_raw.get("cveMetadata", {}).get("datePublished", "")


def extract_affected_version(cve_raw: Dict) -> str:
    """提取受影响版本"""
    try:
        cna = cve_raw.get("containers", {}).get("cna", {})
        affected = cna.get("affected", [])
        if affected:
            versions = affected[0].get("versions", [])
            for v in versions:
                if v.get("status") == "affected":
                    return v.get("version", "")
    except:
        pass
    return ""


def main():
    print("=" * 60)
    print("筛选有 GitHub 资源的 Web CVE")
    print("=" * 60)
    
    # 1. 加载 CVE ID 列表
    print("\n[1/4] 加载 webcve_ids.txt...")
    with open(WEBCVE_IDS_FILE, "r", encoding="utf-8") as f:
        all_cve_ids = [line.strip() for line in f if line.strip()]
    print(f"  - 共 {len(all_cve_ids)} 个 CVE")
    
    # 2. 分析每个 CVE 的资源情况
    print("\n[2/4] 分析 CVE 资源...")
    analyses = []
    
    for i, cve_id in enumerate(all_cve_ids):
        if (i + 1) % 50 == 0:
            print(f"  - 进度: {i + 1}/{len(all_cve_ids)}")
        
        analysis = analyze_cve_resources(cve_id)
        if analysis["exists"]:
            analyses.append(analysis)
    
    print(f"\n  资源统计:")
    with_commit = sum(1 for a in analyses if a.get("has_github_commit"))
    with_advisory = sum(1 for a in analyses if a.get("has_github_advisory"))
    with_github = sum(1 for a in analyses if a.get("has_github_repo"))
    
    print(f"  - 有 GitHub commit: {with_commit}")
    print(f"  - 有 GitHub advisory: {with_advisory}")
    print(f"  - 有 GitHub repo: {with_github}")
    
    # 3. 按分数排序并选择
    print("\n[3/4] 筛选最佳 CVE...")
    analyses.sort(key=lambda x: x["score"], reverse=True)
    
    # 优先选择高分的，不足100个则补充
    selected = []
    
    # 先选有 commit 或 advisory 的
    for a in analyses:
        if a["score"] >= 2 and len(selected) < 100:
            selected.append(a)
    
    # 如果不够，从剩余的随机补充
    remaining = [a for a in analyses if a not in selected]
    if len(selected) < 100 and remaining:
        need = 100 - len(selected)
        random.shuffle(remaining)
        selected.extend(remaining[:need])
    
    print(f"  - 选择了 {len(selected)} 个 CVE")
    print(f"  - 其中高分 (>=2): {sum(1 for s in selected if s['score'] >= 2)}")
    
    # 4. 生成最终数据
    print("\n[4/4] 生成 webdata.json...")
    result = {}
    
    for a in selected:
        cve_id = a["cve_id"]
        cve_raw = a["raw"]
        github_info = a.get("github_info", {})
        
        # 构建 patch_commits
        patch_commits = []
        if "commit_url" in github_info:
            patch_commits.append({
                "url": github_info["commit_url"],
                "content": ""  # 需要单独获取
            })
        
        # 构建 sec_adv
        sec_adv = []
        if "advisory_url" in github_info:
            sec_adv.append({
                "url": github_info["advisory_url"],
                "content": "",
                "effective": False,
                "effective_reason": ""
            })
        
        # 构建 sw_version_wget
        sw_version_wget = ""
        if github_info.get("owner") and github_info.get("repo"):
            version = extract_affected_version(cve_raw)
            if version:
                # 清理版本号
                clean_v = re.search(r'[vV]?(\d+\.\d+(?:\.\d+)?)', version)
                if clean_v:
                    sw_version_wget = f"https://github.com/{github_info['owner']}/{github_info['repo']}/archive/refs/tags/{clean_v.group(0)}.zip"
        
        result[cve_id] = {
            "published_date": extract_published_date(cve_raw),
            "patch_commits": patch_commits,
            "sw_version": extract_affected_version(cve_raw),
            "sw_version_wget": sw_version_wget,
            "description": extract_description(cve_raw),
            "sec_adv": sec_adv,
            "cwe": extract_cwe(cve_raw)
        }
    
    # 按 CVE ID 排序
    result = dict(sorted(result.items()))
    
    # 保存
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=4, ensure_ascii=False)
    
    # 统计
    final_with_commits = sum(1 for v in result.values() if v.get("patch_commits"))
    final_with_adv = sum(1 for v in result.values() if v.get("sec_adv"))
    final_with_wget = sum(1 for v in result.values() if v.get("sw_version_wget"))
    
    print(f"\n✅ 完成！")
    print(f"   输出: {OUTPUT_FILE}")
    print(f"\n  字段填充统计:")
    print(f"  - patch_commits: {final_with_commits}/100")
    print(f"  - sec_adv: {final_with_adv}/100")
    print(f"  - sw_version_wget: {final_with_wget}/100")


if __name__ == "__main__":
    main()
