#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
增强 webdata.json 中的 CVE 数据
- 从 GitHub API 获取 patch commit 内容
- 从 GitHub Security Advisories 获取 sec_adv 内容
- 生成 sw_version_wget 链接
"""

import json
import os
import re
import time
import requests
from pathlib import Path
from typing import Dict, Any, List, Optional
from datetime import datetime

# 路径配置
BASE_DIR = Path(__file__).parent.parent
WEBDATA_FILE = BASE_DIR / "large_scale" / "webdata.json"
OUTPUT_FILE = BASE_DIR / "large_scale" / "webdata_enriched.json"
CVELIST_2025 = BASE_DIR / "cvelist" / "2025"

# GitHub Token (从环境变量读取)
GITHUB_TOKEN = os.environ.get('GITHUB_TOKEN', '')

def get_github_headers():
    """获取 GitHub API headers"""
    headers = {
        "Accept": "application/vnd.github.v3+json",
        "User-Agent": "CVE-Enricher"
    }
    if GITHUB_TOKEN:
        headers["Authorization"] = f"token {GITHUB_TOKEN}"
    return headers


def extract_github_info_from_url(url: str) -> Optional[Dict]:
    """从 GitHub URL 提取 owner/repo/commit 信息"""
    # 匹配 commit URL
    commit_pattern = r'github\.com/([^/]+)/([^/]+)/commit/([a-f0-9]+)'
    match = re.search(commit_pattern, url)
    if match:
        return {
            'owner': match.group(1),
            'repo': match.group(2),
            'commit': match.group(3),
            'type': 'commit'
        }
    
    # 匹配 security advisory URL
    advisory_pattern = r'github\.com/([^/]+)/([^/]+)/security/advisories/(GHSA-[a-z0-9-]+)'
    match = re.search(advisory_pattern, url)
    if match:
        return {
            'owner': match.group(1),
            'repo': match.group(2),
            'ghsa_id': match.group(3),
            'type': 'advisory'
        }
    
    # 匹配 release URL
    release_pattern = r'github\.com/([^/]+)/([^/]+)/releases/tag/([^/]+)'
    match = re.search(release_pattern, url)
    if match:
        return {
            'owner': match.group(1),
            'repo': match.group(2),
            'tag': match.group(3),
            'type': 'release'
        }
    
    return None


def fetch_commit_content(owner: str, repo: str, commit_hash: str) -> str:
    """从 GitHub API 获取 commit 内容"""
    url = f"https://api.github.com/repos/{owner}/{repo}/commits/{commit_hash}"
    
    try:
        response = requests.get(url, headers=get_github_headers(), timeout=30)
        
        if response.status_code == 403:
            print(f"    ⚠️ Rate limit - waiting 60s...")
            time.sleep(60)
            response = requests.get(url, headers=get_github_headers(), timeout=30)
        
        if response.status_code == 200:
            data = response.json()
            
            # 构建 commit 内容
            content_parts = [data['commit']['message']]
            
            for file in data.get('files', [])[:10]:  # 限制文件数量
                file_content = f"\nFilename: {file['filename']}:\n"
                if 'patch' in file:
                    # 只取前 2000 字符
                    patch = file['patch'][:2000]
                    file_content += f"```\n{patch}\n```"
                content_parts.append(file_content)
            
            return '\n'.join(content_parts)
        else:
            print(f"    ⚠️ Failed to fetch commit: HTTP {response.status_code}")
            return ""
    except Exception as e:
        print(f"    ⚠️ Error fetching commit: {e}")
        return ""


def fetch_advisory_content(url: str) -> str:
    """获取 security advisory 内容（简化版，使用 requests）"""
    try:
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        }
        response = requests.get(url, headers=headers, timeout=30)
        
        if response.status_code == 200:
            # 简单提取文本内容
            from html.parser import HTMLParser
            
            class TextExtractor(HTMLParser):
                def __init__(self):
                    super().__init__()
                    self.text = []
                    self.in_body = False
                    
                def handle_starttag(self, tag, attrs):
                    if tag == 'body':
                        self.in_body = True
                        
                def handle_data(self, data):
                    if self.in_body:
                        text = data.strip()
                        if text:
                            self.text.append(text)
            
            parser = TextExtractor()
            parser.feed(response.text)
            
            # 返回前 5000 字符
            return ' '.join(parser.text)[:5000]
        else:
            return ""
    except Exception as e:
        print(f"    ⚠️ Error fetching advisory: {e}")
        return ""


def get_cve_raw_data(cve_id: str) -> Optional[Dict]:
    """获取 CVE 原始数据"""
    parts = cve_id.split("-")
    if len(parts) != 3:
        return None
    
    num = parts[2]
    if len(num) <= 4:
        subdir = f"{num[0]}xxx"
    else:
        subdir = f"{num[:2]}xxx"
    
    cve_file = CVELIST_2025 / subdir / f"{cve_id}.json"
    
    if cve_file.exists():
        with open(cve_file, "r", encoding="utf-8") as f:
            return json.load(f)
    return None


def extract_all_urls(cve_raw: Dict) -> List[str]:
    """从原始 CVE 数据提取所有 URL"""
    urls = []
    try:
        cna = cve_raw.get("containers", {}).get("cna", {})
        for ref in cna.get("references", []):
            url = ref.get("url")
            if url:
                urls.append(url)
        
        # 也检查 adp 容器
        for adp in cve_raw.get("containers", {}).get("adp", []):
            for ref in adp.get("references", []):
                url = ref.get("url")
                if url:
                    urls.append(url)
    except:
        pass
    return urls


def generate_wget_url(owner: str, repo: str, version: str) -> str:
    """生成下载 URL"""
    if not version:
        return ""
    
    # 清理版本号
    clean_version = version.strip()
    if clean_version.startswith(">=") or clean_version.startswith("<="):
        clean_version = clean_version[2:].strip()
    elif clean_version.startswith(">") or clean_version.startswith("<"):
        clean_version = clean_version[1:].strip()
    
    # 提取第一个版本号
    version_match = re.search(r'[vV]?(\d+\.\d+(?:\.\d+)?)', clean_version)
    if version_match:
        clean_version = version_match.group(0)
    
    if clean_version:
        return f"https://github.com/{owner}/{repo}/archive/refs/tags/{clean_version}.zip"
    return ""


def enrich_cve_data(cve_id: str, cve_data: Dict) -> Dict:
    """增强单个 CVE 的数据"""
    print(f"  Processing {cve_id}...")
    
    # 获取原始 CVE 数据
    cve_raw = get_cve_raw_data(cve_id)
    if not cve_raw:
        print(f"    ⚠️ No raw data found")
        return cve_data
    
    # 提取所有 URL
    urls = extract_all_urls(cve_raw)
    
    owner, repo = None, None
    
    # 处理 patch commits
    if not cve_data.get("patch_commits") or all(not c.get("content") for c in cve_data.get("patch_commits", [])):
        new_commits = []
        for url in urls:
            info = extract_github_info_from_url(url)
            if info and info['type'] == 'commit':
                owner, repo = info['owner'], info['repo']
                print(f"    📥 Fetching commit {info['commit'][:8]}...")
                content = fetch_commit_content(owner, repo, info['commit'])
                new_commits.append({
                    "url": url,
                    "content": content
                })
                time.sleep(0.5)  # Rate limiting
        
        if new_commits:
            cve_data["patch_commits"] = new_commits
    
    # 处理 security advisories
    if not cve_data.get("sec_adv") or all(not a.get("content") for a in cve_data.get("sec_adv", [])):
        new_advisories = []
        for url in urls:
            if "security/advisories" in url or "GHSA" in url:
                info = extract_github_info_from_url(url)
                if info and info['type'] == 'advisory':
                    owner, repo = info['owner'], info['repo']
                
                print(f"    📥 Fetching advisory...")
                content = fetch_advisory_content(url)
                
                # 判断是否有效（包含 PoC 或详细步骤）
                content_lower = content.lower()
                has_poc = any(kw in content_lower for kw in ['poc', 'proof of concept', 'exploit', 'payload', 'curl', 'python', 'script'])
                
                new_advisories.append({
                    "url": url,
                    "content": content,
                    "effective": has_poc,
                    "effective_reason": "Contains PoC or exploit details" if has_poc else "No clear PoC found"
                })
                time.sleep(0.5)
        
        if new_advisories:
            cve_data["sec_adv"] = new_advisories
    
    # 生成 sw_version_wget
    if not cve_data.get("sw_version_wget") and owner and repo:
        version = cve_data.get("sw_version", "")
        wget_url = generate_wget_url(owner, repo, version)
        if wget_url:
            cve_data["sw_version_wget"] = wget_url
    
    return cve_data


def main():
    print("=" * 60)
    print("CVE 数据增强脚本")
    print("=" * 60)
    
    if not GITHUB_TOKEN:
        print("\n⚠️ 警告: 未设置 GITHUB_TOKEN 环境变量")
        print("   API 请求将受到严格的速率限制")
        print("   建议设置: $env:GITHUB_TOKEN='your_token'")
    
    # 加载现有数据
    print(f"\n[1/3] 加载 {WEBDATA_FILE}...")
    with open(WEBDATA_FILE, "r", encoding="utf-8") as f:
        data = json.load(f)
    print(f"  - 共 {len(data)} 个 CVE")
    
    # 统计缺失字段
    missing_commits = sum(1 for v in data.values() if not v.get("patch_commits"))
    missing_advisory = sum(1 for v in data.values() if not v.get("sec_adv"))
    missing_wget = sum(1 for v in data.values() if not v.get("sw_version_wget"))
    
    print(f"\n  缺失统计:")
    print(f"  - patch_commits: {missing_commits} 个缺失")
    print(f"  - sec_adv: {missing_advisory} 个缺失")
    print(f"  - sw_version_wget: {missing_wget} 个缺失")
    
    # 增强数据
    print(f"\n[2/3] 增强 CVE 数据...")
    enriched_count = 0
    
    for i, (cve_id, cve_data) in enumerate(data.items()):
        # 检查是否需要增强
        needs_enrichment = (
            not cve_data.get("patch_commits") or 
            not cve_data.get("sec_adv") or
            not cve_data.get("sw_version_wget")
        )
        
        if needs_enrichment:
            data[cve_id] = enrich_cve_data(cve_id, cve_data)
            enriched_count += 1
        
        # 进度报告
        if (i + 1) % 10 == 0:
            print(f"\n  进度: {i + 1}/{len(data)} (增强了 {enriched_count} 个)")
    
    # 保存结果
    print(f"\n[3/3] 保存到 {OUTPUT_FILE}...")
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=4, ensure_ascii=False)
    
    # 最终统计
    final_missing_commits = sum(1 for v in data.values() if not v.get("patch_commits"))
    final_missing_advisory = sum(1 for v in data.values() if not v.get("sec_adv"))
    final_missing_wget = sum(1 for v in data.values() if not v.get("sw_version_wget"))
    
    print(f"\n✅ 完成！")
    print(f"   增强了 {enriched_count} 个 CVE")
    print(f"\n  最终缺失统计:")
    print(f"  - patch_commits: {final_missing_commits} 个缺失 (原 {missing_commits})")
    print(f"  - sec_adv: {final_missing_advisory} 个缺失 (原 {missing_advisory})")
    print(f"  - sw_version_wget: {final_missing_wget} 个缺失 (原 {missing_wget})")


if __name__ == "__main__":
    main()
