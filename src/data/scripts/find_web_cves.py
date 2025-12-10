#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
从 cvelist/2024 和 cvelist/2025 中筛选 Web 相关漏洞
条件：
1. 有 GitHub 公开仓库或其他公开内容
2. Web/浏览器相关
3. 非商业软件
4. 非硬件相关
5. 找到 200 个就停止
"""

import json
import os
import re
import random
from pathlib import Path
from typing import Dict, Any, List, Optional, Generator
from openai import OpenAI

# 配置
BASE_DIR = Path(__file__).parent.parent
CVELIST_DIR = BASE_DIR / "cvelist"
OUTPUT_FILE = BASE_DIR / "large_scale" / "webdata.json"

# OpenAI 配置
OPENAI_API_KEY = "sk-ziyWDSRgl3ymsBm3MWN8C5fPJwrzxaakqdsCYsWIB0dTqHmg"
OPENAI_API_BASE = "https://api.openai-hub.com/v1"

# 目标数量
TARGET_COUNT = 200

# 商业软件关键词（排除）
COMMERCIAL_KEYWORDS = [
    'sap', 'oracle', 'microsoft', 'adobe', 'ibm', 'cisco', 'vmware', 
    'fortinet', 'paloalto', 'juniper', 'f5', 'citrix', 'salesforce',
    'workday', 'servicenow', 'splunk', 'tableau', 'qlik', 'informatica',
    'teradata', 'snowflake', 'databricks', 'cloudera', 'hortonworks',
    'enterprise', 'commercial', 'proprietary', 'licensed'
]

# 硬件相关关键词（排除）
HARDWARE_KEYWORDS = [
    'firmware', 'bios', 'uefi', 'driver', 'kernel', 'embedded',
    'router', 'switch', 'firewall', 'iot', 'plc', 'scada',
    'camera', 'printer', 'scanner', 'nas', 'san', 'ups',
    'hardware', 'device', 'chip', 'cpu', 'gpu', 'memory'
]

# Web 相关关键词（包含）
WEB_KEYWORDS = [
    'xss', 'cross-site', 'csrf', 'ssrf', 'sql injection', 'sqli',
    'path traversal', 'directory traversal', 'lfi', 'rfi',
    'authentication bypass', 'authorization bypass', 'middleware',
    'http', 'https', 'web', 'browser', 'cookie', 'session', 'jwt',
    'api', 'rest', 'graphql', 'json', 'xml', 'html', 'javascript',
    'php', 'python', 'node', 'express', 'django', 'flask', 'rails',
    'react', 'vue', 'angular', 'next.js', 'nuxt', 'laravel', 'symfony',
    'wordpress', 'drupal', 'joomla', 'magento', 'shopify',
    'upload', 'download', 'redirect', 'open redirect', 'injection',
    'deserialization', 'prototype pollution', 'template injection',
    'server-side', 'client-side', 'frontend', 'backend'
]


def iter_cve_files(years: List[int]) -> Generator[Path, None, None]:
    """遍历指定年份的所有 CVE 文件"""
    for year in years:
        year_dir = CVELIST_DIR / str(year)
        if not year_dir.exists():
            print(f"⚠️ 目录不存在: {year_dir}")
            continue
        
        # 遍历子目录 (0xxx, 1xxx, ..., 99xxx)
        for subdir in sorted(year_dir.iterdir()):
            if subdir.is_dir() and subdir.name.endswith('xxx'):
                for cve_file in sorted(subdir.glob('CVE-*.json')):
                    yield cve_file


def extract_urls(cve_data: Dict) -> List[str]:
    """提取所有 URL"""
    urls = []
    try:
        cna = cve_data.get("containers", {}).get("cna", {})
        for ref in cna.get("references", []):
            url = ref.get("url", "")
            if url:
                urls.append(url)
        
        for adp in cve_data.get("containers", {}).get("adp", []):
            for ref in adp.get("references", []):
                url = ref.get("url", "")
                if url:
                    urls.append(url)
    except:
        pass
    return urls


def extract_description(cve_data: Dict) -> str:
    """提取描述"""
    try:
        cna = cve_data.get("containers", {}).get("cna", {})
        for desc in cna.get("descriptions", []):
            if desc.get("lang") == "en":
                return desc.get("value", "")
        if cna.get("descriptions"):
            return cna["descriptions"][0].get("value", "")
    except:
        pass
    return ""


def extract_affected(cve_data: Dict) -> Dict:
    """提取受影响的软件信息"""
    try:
        cna = cve_data.get("containers", {}).get("cna", {})
        affected = cna.get("affected", [])
        if affected:
            first = affected[0]
            return {
                "vendor": first.get("vendor", ""),
                "product": first.get("product", ""),
                "versions": first.get("versions", [])
            }
    except:
        pass
    return {}


def extract_cwe(cve_data: Dict) -> List[Dict]:
    """提取 CWE"""
    cwes = []
    try:
        cna = cve_data.get("containers", {}).get("cna", {})
        for pt in cna.get("problemTypes", []):
            for desc in pt.get("descriptions", []):
                cwe_id = desc.get("cweId", "")
                cwe_desc = desc.get("description", "")
                if cwe_id:
                    cwes.append({
                        "id": cwe_id,
                        "value": f"{cwe_id}: {cwe_desc}"
                    })
    except:
        pass
    return cwes


def extract_published_date(cve_data: Dict) -> str:
    """提取发布日期"""
    return cve_data.get("cveMetadata", {}).get("datePublished", "")


def rule_based_filter(cve_data: Dict, description: str, urls: List[str], affected: Dict) -> Dict:
    """基于规则的初步筛选"""
    result = {
        "has_github": False,
        "has_public_repo": False,
        "is_web_related": False,
        "is_commercial": False,
        "is_hardware": False,
        "github_info": {},
        "score": 0
    }
    
    desc_lower = description.lower()
    vendor_lower = affected.get("vendor", "").lower()
    product_lower = affected.get("product", "").lower()
    combined_text = f"{desc_lower} {vendor_lower} {product_lower}"
    
    # 检查是否商业软件
    for kw in COMMERCIAL_KEYWORDS:
        if kw in combined_text:
            result["is_commercial"] = True
            break
    
    # 检查是否硬件相关
    for kw in HARDWARE_KEYWORDS:
        if kw in combined_text:
            result["is_hardware"] = True
            break
    
    # 检查是否 Web 相关
    for kw in WEB_KEYWORDS:
        if kw in combined_text:
            result["is_web_related"] = True
            result["score"] += 1
    
    # 检查 URL
    for url in urls:
        url_lower = url.lower()
        
        # GitHub
        if "github.com" in url_lower:
            result["has_github"] = True
            result["has_public_repo"] = True
            result["score"] += 2
            
            # 提取 GitHub 信息
            commit_match = re.search(r'github\.com/([^/]+)/([^/]+)/commit/([a-f0-9]+)', url)
            if commit_match:
                result["github_info"]["owner"] = commit_match.group(1)
                result["github_info"]["repo"] = commit_match.group(2)
                result["github_info"]["commit_url"] = url
                result["score"] += 3
            
            advisory_match = re.search(r'github\.com/([^/]+)/([^/]+)/security/advisories/(GHSA-[a-z0-9-]+)', url)
            if advisory_match:
                result["github_info"]["owner"] = advisory_match.group(1)
                result["github_info"]["repo"] = advisory_match.group(2)
                result["github_info"]["advisory_url"] = url
                result["github_info"]["ghsa_id"] = advisory_match.group(3)
                result["score"] += 3
            
            release_match = re.search(r'github\.com/([^/]+)/([^/]+)/releases/tag/([^/]+)', url)
            if release_match:
                result["github_info"]["owner"] = release_match.group(1)
                result["github_info"]["repo"] = release_match.group(2)
                result["github_info"]["tag"] = release_match.group(3)
                result["score"] += 1
        
        # GitLab
        elif "gitlab.com" in url_lower:
            result["has_public_repo"] = True
            result["score"] += 2
        
        # 其他公开仓库
        elif any(x in url_lower for x in ["bitbucket.org", "sourceforge.net", "codeberg.org"]):
            result["has_public_repo"] = True
            result["score"] += 1
    
    return result


def llm_verify(client: OpenAI, cve_id: str, description: str, affected: Dict, urls: List[str]) -> bool:
    """使用 LLM 验证是否符合条件"""
    prompt = f"""判断这个 CVE 是否符合以下所有条件：
1. 是 Web/浏览器/网页相关的漏洞（如 XSS, CSRF, SQL注入, 认证绕过等）
2. 不是商业软件（如 SAP, Oracle, Microsoft, Adobe 等）
3. 不是硬件/固件相关
4. 有公开的代码仓库或技术细节

CVE ID: {cve_id}
软件: {affected.get('vendor', 'N/A')} - {affected.get('product', 'N/A')}
描述: {description[:500]}
相关链接: {', '.join(urls[:5])}

只回答 YES 或 NO，不需要解释。"""

    try:
        response = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[{"role": "user", "content": prompt}],
            max_tokens=10,
            temperature=0
        )
        answer = response.choices[0].message.content.strip().upper()
        return "YES" in answer
    except Exception as e:
        print(f"    ⚠️ LLM error: {e}")
        return False


def format_cve_data(cve_id: str, cve_raw: Dict, rule_result: Dict) -> Dict:
    """格式化 CVE 数据为目标格式"""
    github_info = rule_result.get("github_info", {})
    
    # patch_commits
    patch_commits = []
    if "commit_url" in github_info:
        patch_commits.append({
            "url": github_info["commit_url"],
            "content": ""
        })
    
    # sec_adv
    sec_adv = []
    if "advisory_url" in github_info:
        sec_adv.append({
            "url": github_info["advisory_url"],
            "content": "",
            "effective": False,
            "effective_reason": ""
        })
    
    # sw_version_wget
    sw_version_wget = ""
    affected = extract_affected(cve_raw)
    if github_info.get("owner") and github_info.get("repo"):
        versions = affected.get("versions", [])
        for v in versions:
            if v.get("status") == "affected":
                version_str = v.get("version", "")
                version_match = re.search(r'[vV]?(\d+\.\d+(?:\.\d+)?)', version_str)
                if version_match:
                    sw_version_wget = f"https://github.com/{github_info['owner']}/{github_info['repo']}/archive/refs/tags/{version_match.group(0)}.zip"
                    break
    
    # sw_version
    sw_version = ""
    versions = affected.get("versions", [])
    for v in versions:
        if v.get("status") == "affected":
            sw_version = v.get("version", "")
            break
    
    return {
        "published_date": extract_published_date(cve_raw),
        "patch_commits": patch_commits,
        "sw_version": sw_version,
        "sw_version_wget": sw_version_wget,
        "description": extract_description(cve_raw),
        "sec_adv": sec_adv,
        "cwe": extract_cwe(cve_raw)
    }


def main():
    print("=" * 60)
    print("Web CVE 筛选器 (规则 + LLM)")
    print("=" * 60)
    
    # 初始化 OpenAI 客户端
    print("\n[1/4] 初始化 LLM 客户端...")
    client = OpenAI(
        api_key=OPENAI_API_KEY,
        base_url=OPENAI_API_BASE
    )
    print("  ✅ 客户端初始化成功")
    
    # 统计
    total_scanned = 0
    rule_passed = 0
    llm_verified = 0
    selected_cves = {}
    
    print(f"\n[2/4] 扫描 CVE 文件 (目标: {TARGET_COUNT} 个)...")
    print("  扫描 2024 和 2025 年的 CVE...")
    
    # 遍历所有 CVE 文件
    for cve_file in iter_cve_files([2024, 2025]):
        if len(selected_cves) >= TARGET_COUNT:
            break
        
        total_scanned += 1
        
        if total_scanned % 1000 == 0:
            print(f"  📊 进度: 扫描 {total_scanned}, 规则通过 {rule_passed}, LLM验证 {llm_verified}, 已选 {len(selected_cves)}")
        
        try:
            with open(cve_file, "r", encoding="utf-8") as f:
                cve_data = json.load(f)
            
            cve_id = cve_data.get("cveMetadata", {}).get("cveId", "")
            if not cve_id:
                continue
            
            # 提取信息
            description = extract_description(cve_data)
            urls = extract_urls(cve_data)
            affected = extract_affected(cve_data)
            
            # 跳过没有描述的
            if not description or len(description) < 50:
                continue
            
            # 规则筛选
            rule_result = rule_based_filter(cve_data, description, urls, affected)
            
            # 必须有公开仓库
            if not rule_result["has_public_repo"]:
                continue
            
            # 排除商业软件和硬件
            if rule_result["is_commercial"] or rule_result["is_hardware"]:
                continue
            
            # 必须 Web 相关
            if not rule_result["is_web_related"]:
                continue
            
            # 规则通过
            rule_passed += 1
            
            # 高分直接通过，低分用 LLM 验证
            if rule_result["score"] >= 5:
                llm_verified += 1
                selected_cves[cve_id] = format_cve_data(cve_id, cve_data, rule_result)
                print(f"  ✅ [{len(selected_cves)}/{TARGET_COUNT}] {cve_id} (高分通过: {rule_result['score']})")
            elif rule_result["score"] >= 2:
                # LLM 验证
                if llm_verify(client, cve_id, description, affected, urls):
                    llm_verified += 1
                    selected_cves[cve_id] = format_cve_data(cve_id, cve_data, rule_result)
                    print(f"  ✅ [{len(selected_cves)}/{TARGET_COUNT}] {cve_id} (LLM验证通过)")
        
        except Exception as e:
            continue
    
    print(f"\n[3/4] 筛选完成")
    print(f"  - 总扫描: {total_scanned}")
    print(f"  - 规则通过: {rule_passed}")
    print(f"  - LLM验证: {llm_verified}")
    print(f"  - 最终选择: {len(selected_cves)}")
    
    # 按 CVE ID 排序
    selected_cves = dict(sorted(selected_cves.items()))
    
    # 保存
    print(f"\n[4/4] 保存到 {OUTPUT_FILE}...")
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        json.dump(selected_cves, f, indent=4, ensure_ascii=False)
    
    # 统计字段填充情况
    with_commits = sum(1 for v in selected_cves.values() if v.get("patch_commits"))
    with_adv = sum(1 for v in selected_cves.values() if v.get("sec_adv"))
    with_wget = sum(1 for v in selected_cves.values() if v.get("sw_version_wget"))
    with_desc = sum(1 for v in selected_cves.values() if v.get("description"))
    with_cwe = sum(1 for v in selected_cves.values() if v.get("cwe"))
    
    print(f"\n✅ 完成！")
    print(f"   输出: {OUTPUT_FILE}")
    print(f"\n  字段填充统计:")
    print(f"  - description: {with_desc}/{len(selected_cves)}")
    print(f"  - patch_commits: {with_commits}/{len(selected_cves)}")
    print(f"  - sec_adv: {with_adv}/{len(selected_cves)}")
    print(f"  - sw_version_wget: {with_wget}/{len(selected_cves)}")
    print(f"  - cwe: {with_cwe}/{len(selected_cves)}")


if __name__ == "__main__":
    main()
