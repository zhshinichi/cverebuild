#!/usr/bin/env python3
"""
严格筛选 Web CVE - 要求必须同时具有:
1. patch_commits (补丁提交链接)
2. sec_adv (安全公告链接)  
3. sw_version_wget (软件仓库/下载链接)

从 cvelist/2024 和 2025 目录检索
"""

import json
import os
import re
from pathlib import Path
from typing import Optional
from openai import OpenAI

# API 配置
API_KEY = "sk-ziyWDSRgl3ymsBm3MWN8C5fPJwrzxaakqdsCYsWIB0dTqHmg"
BASE_URL = "https://api.openai-hub.com/v1"

# 目标数量
TARGET_COUNT = 200

# 路径配置
SCRIPT_DIR = Path(__file__).parent
DATA_DIR = SCRIPT_DIR.parent
CVELIST_DIR = DATA_DIR / "cvelist"
OUTPUT_FILE = DATA_DIR / "large_scale" / "webdata.json"


def extract_patch_commits(cve_data: dict) -> list:
    """
    提取 patch commit 链接
    
    来源:
    - references 中带有 tags: ["patch"] 的 URL
    - URL 包含 /commit/ 或 /commits/ 的 GitHub 链接
    """
    patch_commits = []
    
    # 从 cna.references 提取
    cna = cve_data.get("containers", {}).get("cna", {})
    references = cna.get("references", [])
    
    for ref in references:
        url = ref.get("url", "")
        tags = ref.get("tags", [])
        
        # 明确标记为 patch 的
        if "patch" in tags:
            if url and url not in patch_commits:
                patch_commits.append(url)
            continue
        
        # GitHub commit 链接
        if re.search(r'github\.com/[^/]+/[^/]+/commit/[a-f0-9]+', url):
            if url not in patch_commits:
                patch_commits.append(url)
        
        # GitLab commit 链接
        if re.search(r'gitlab\.[^/]+/[^/]+/[^/]+/-/commit/[a-f0-9]+', url):
            if url not in patch_commits:
                patch_commits.append(url)
    
    # 从 adp 容器提取
    for adp in cve_data.get("containers", {}).get("adp", []):
        for ref in adp.get("references", []):
            url = ref.get("url", "")
            tags = ref.get("tags", [])
            
            if "patch" in tags or "x_transferred" not in tags:
                if re.search(r'github\.com/[^/]+/[^/]+/commit/[a-f0-9]+', url):
                    if url not in patch_commits:
                        patch_commits.append(url)
    
    return patch_commits


def extract_security_advisory(cve_data: dict) -> list:
    """
    提取 security advisory 链接
    
    来源:
    - references 中带有 tags: ["vendor-advisory"] 的 URL
    - references 中带有 tags: ["issue-tracking"] 的 URL
    - URL 包含 advisory, secadv, security-announce 等关键词
    - GitHub Security Advisory 链接
    """
    sec_advs = []
    
    # 关键词模式
    advisory_patterns = [
        r'advisory',
        r'secadv',
        r'security-announce',
        r'security/advisories',
        r'GHSA-',  # GitHub Security Advisory
        r'/security/',
        r'CVE-\d{4}-\d+',  # 包含 CVE ID 的公告链接
    ]
    
    cna = cve_data.get("containers", {}).get("cna", {})
    references = cna.get("references", [])
    
    for ref in references:
        url = ref.get("url", "")
        tags = ref.get("tags", [])
        
        # 明确标记为 vendor-advisory 或 issue-tracking
        if "vendor-advisory" in tags or "issue-tracking" in tags:
            if url and url not in sec_advs:
                sec_advs.append(url)
            continue
        
        # 通过 URL 模式识别
        for pattern in advisory_patterns:
            if re.search(pattern, url, re.IGNORECASE):
                if url not in sec_advs:
                    sec_advs.append(url)
                break
    
    # 从 adp 容器提取
    for adp in cve_data.get("containers", {}).get("adp", []):
        for ref in adp.get("references", []):
            url = ref.get("url", "")
            tags = ref.get("tags", [])
            
            if "vendor-advisory" in tags or "issue-tracking" in tags:
                if url and url not in sec_advs:
                    sec_advs.append(url)
    
    return sec_advs


def extract_sw_version_wget(cve_data: dict) -> list:
    """
    提取软件仓库/版本下载链接
    
    来源:
    - affected[].repo 字段
    - GitHub/GitLab 仓库主页链接
    - Release/download 链接
    - pypi, npm, maven 等包管理器链接
    """
    sw_links = []
    
    cna = cve_data.get("containers", {}).get("cna", {})
    
    # 从 affected.repo 提取
    for affected in cna.get("affected", []):
        repo = affected.get("repo", "")
        if repo and repo not in sw_links:
            sw_links.append(repo)
    
    # 从 references 提取仓库链接
    references = cna.get("references", [])
    
    repo_patterns = [
        r'github\.com/[^/]+/[^/]+/?$',  # GitHub 仓库主页
        r'github\.com/[^/]+/[^/]+/releases',  # GitHub releases
        r'github\.com/[^/]+/[^/]+/archive',  # GitHub archive
        r'gitlab\.[^/]+/[^/]+/[^/]+/?$',  # GitLab 仓库
        r'pypi\.org/project/',  # PyPI
        r'npmjs\.com/package/',  # npm
        r'packagist\.org/packages/',  # Composer/PHP
        r'rubygems\.org/gems/',  # Ruby Gems
        r'crates\.io/crates/',  # Rust crates
        r'mvnrepository\.com/',  # Maven
    ]
    
    for ref in references:
        url = ref.get("url", "")
        
        for pattern in repo_patterns:
            if re.search(pattern, url, re.IGNORECASE):
                # 提取仓库基础 URL
                if 'github.com' in url:
                    # 提取 github.com/owner/repo 部分
                    match = re.search(r'(https?://github\.com/[^/]+/[^/]+)', url)
                    if match:
                        base_url = match.group(1)
                        if base_url not in sw_links:
                            sw_links.append(base_url)
                elif url not in sw_links:
                    sw_links.append(url)
                break
    
    return sw_links


def extract_versions(cve_data: dict) -> list:
    """
    提取受影响的版本信息
    """
    versions = []
    
    cna = cve_data.get("containers", {}).get("cna", {})
    
    for affected in cna.get("affected", []):
        for version in affected.get("versions", []):
            ver_str = version.get("version", "")
            if ver_str and ver_str not in versions:
                versions.append(ver_str)
            
            less_than = version.get("lessThan", "")
            if less_than and less_than not in versions:
                versions.append(less_than)
    
    return versions


def extract_cwe(cve_data: dict) -> list:
    """
    提取 CWE 信息
    """
    cwes = []
    
    cna = cve_data.get("containers", {}).get("cna", {})
    
    for problem_type in cna.get("problemTypes", []):
        for desc in problem_type.get("descriptions", []):
            cwe_id = desc.get("cweId", "")
            if cwe_id and cwe_id not in cwes:
                cwes.append(cwe_id)
    
    return cwes


def is_web_related_rule(cve_data: dict) -> tuple:
    """
    规则判断是否为 Web 相关漏洞
    
    Returns:
        (is_web, score, reason)
    """
    cna = cve_data.get("containers", {}).get("cna", {})
    
    # 获取描述
    descriptions = cna.get("descriptions", [])
    desc_text = ""
    for desc in descriptions:
        if desc.get("lang", "").startswith("en"):
            desc_text = desc.get("value", "")
            break
    if not desc_text and descriptions:
        desc_text = descriptions[0].get("value", "")
    
    desc_lower = desc_text.lower()
    
    # 获取产品名称
    products = []
    for affected in cna.get("affected", []):
        products.append(affected.get("product", "").lower())
        products.append(affected.get("vendor", "").lower())
    
    products_text = " ".join(products)
    
    # 排除条件 - 商业软件/硬件
    exclude_keywords = [
        'cisco', 'juniper', 'fortinet', 'palo alto', 'checkpoint',
        'microsoft windows', 'windows server', 'microsoft office',
        'oracle database', 'sap', 'ibm', 'vmware', 'citrix',
        'android', 'ios', 'macos', 'firmware', 'bios', 'uefi',
        'router', 'switch', 'firewall', 'camera', 'printer', 'scanner',
        'nvidia driver', 'amd driver', 'intel driver',
        'antivirus', 'endpoint protection', 'mcafee', 'symantec', 'kaspersky',
        'adobe acrobat', 'adobe reader',
    ]
    
    for keyword in exclude_keywords:
        if keyword in desc_lower or keyword in products_text:
            return (False, 0, f"排除: {keyword}")
    
    # Web 相关关键词评分
    score = 0
    matched = []
    
    # 高分关键词 (Web 核心技术)
    high_score_keywords = {
        'xss': 5, 'cross-site scripting': 5, 'cross site scripting': 5,
        'sql injection': 5, 'sqli': 5,
        'csrf': 5, 'cross-site request forgery': 5,
        'ssrf': 5, 'server-side request forgery': 5,
        'rce': 4, 'remote code execution': 4,
        'command injection': 4,
        'path traversal': 4, 'directory traversal': 4,
        'local file inclusion': 4, 'lfi': 4,
        'remote file inclusion': 4, 'rfi': 4,
        'authentication bypass': 4,
        'authorization bypass': 4,
        'privilege escalation': 3,
        'insecure deserialization': 4,
        'xml external entity': 4, 'xxe': 4,
        'open redirect': 3,
        'clickjacking': 3,
        'session fixation': 3,
        'session hijacking': 3,
    }
    
    # 中分关键词 (Web 技术栈)
    medium_score_keywords = {
        'web application': 3, 'webapp': 3, 'web app': 3,
        'http': 2, 'https': 2,
        'rest api': 3, 'restful': 3, 'api endpoint': 3,
        'graphql': 3,
        'json': 2, 'xml': 2,
        'html': 2, 'javascript': 2, 'css': 2,
        'php': 2, 'python': 2, 'node.js': 2, 'nodejs': 2,
        'ruby': 2, 'rails': 2, 'django': 3, 'flask': 3,
        'express': 2, 'fastapi': 3,
        'spring': 2, 'spring boot': 3,
        'laravel': 3, 'symfony': 3,
        'react': 2, 'vue': 2, 'angular': 2,
        'nginx': 2, 'apache': 2, 'tomcat': 2,
        'wordpress': 3, 'drupal': 3, 'joomla': 3,
        'magento': 3, 'prestashop': 3, 'opencart': 3,
        'cms': 2, 'content management': 2,
        'e-commerce': 2, 'ecommerce': 2, 'online store': 2,
        'login': 2, 'authentication': 2, 'oauth': 3, 'jwt': 3,
        'cookie': 2, 'session': 2,
        'upload': 2, 'file upload': 3,
        'form': 1, 'input': 1, 'parameter': 1,
        'database': 2, 'mysql': 2, 'postgresql': 2, 'mongodb': 2,
        'redis': 2, 'memcached': 2,
    }
    
    # 产品类型关键词
    product_keywords = {
        'plugin': 2, 'extension': 2, 'addon': 2, 'module': 2,
        'theme': 1, 'template': 1,
        'dashboard': 2, 'admin panel': 3, 'control panel': 2,
        'portal': 2, 'intranet': 2,
        'blog': 2, 'forum': 2, 'wiki': 2,
        'crm': 2, 'erp': 2, 'hrm': 2,
        'booking': 2, 'reservation': 2,
        'payment': 2, 'checkout': 2,
        'newsletter': 2, 'mailing': 2,
        'contact form': 2, 'feedback': 1,
    }
    
    # 计算分数
    all_text = desc_lower + " " + products_text
    
    for keyword, points in high_score_keywords.items():
        if keyword in all_text:
            score += points
            matched.append(f"{keyword}(+{points})")
    
    for keyword, points in medium_score_keywords.items():
        if keyword in all_text:
            score += points
            matched.append(f"{keyword}(+{points})")
    
    for keyword, points in product_keywords.items():
        if keyword in all_text:
            score += points
            matched.append(f"{keyword}(+{points})")
    
    return (score >= 5, score, ", ".join(matched[:5]))


def use_llm_verify(client: OpenAI, cve_data: dict, cve_id: str) -> bool:
    """
    使用 LLM 验证是否为 Web 相关漏洞
    """
    cna = cve_data.get("containers", {}).get("cna", {})
    
    # 获取描述
    descriptions = cna.get("descriptions", [])
    desc_text = ""
    for desc in descriptions:
        if desc.get("lang", "").startswith("en"):
            desc_text = desc.get("value", "")
            break
    if not desc_text and descriptions:
        desc_text = descriptions[0].get("value", "")
    
    # 获取产品信息
    products = []
    for affected in cna.get("affected", []):
        products.append(f"{affected.get('vendor', '')} {affected.get('product', '')}")
    
    prompt = f"""判断这个 CVE 是否是 Web 相关漏洞。

CVE ID: {cve_id}
产品: {', '.join(products)}
描述: {desc_text[:500]}

Web 相关漏洞的定义:
1. 影响 Web 应用程序、Web 框架、CMS、Web 服务器等
2. 涉及 HTTP/HTTPS 协议、Web API、浏览器等
3. 漏洞类型包括: XSS, SQL注入, CSRF, SSRF, RCE, 认证绕过等
4. 必须是开源软件或有公开仓库的软件

排除条件:
- 商业软件 (Microsoft, Oracle, SAP, IBM, Cisco 等)
- 硬件设备 (路由器, 防火墙, 摄像头等)
- 移动操作系统 (Android, iOS)
- 桌面软件 (非 Web 相关)

只回答 YES 或 NO"""

    try:
        response = client.chat.completions.create(
            model="gpt-5",
            messages=[{"role": "user", "content": prompt}],
            max_tokens=10,
            temperature=0
        )
        answer = response.choices[0].message.content.strip().upper()
        return "YES" in answer
    except Exception as e:
        print(f"    ⚠️ LLM 错误: {e}")
        return False


def convert_to_output_format(cve_data: dict, cve_id: str, 
                              patch_commits: list, sec_advs: list, 
                              sw_versions: list) -> dict:
    """
    转换为输出格式
    """
    cna = cve_data.get("containers", {}).get("cna", {})
    metadata = cve_data.get("cveMetadata", {})
    
    # 获取描述
    descriptions = cna.get("descriptions", [])
    desc_text = ""
    for desc in descriptions:
        if desc.get("lang", "").startswith("en"):
            desc_text = desc.get("value", "")
            break
    if not desc_text and descriptions:
        desc_text = descriptions[0].get("value", "")
    
    # 获取版本
    versions = extract_versions(cve_data)
    
    # 获取 CWE
    cwes = extract_cwe(cve_data)
    
    return {
        "cve_id": cve_id,
        "published_date": metadata.get("datePublished", ""),
        "patch_commits": patch_commits,
        "sw_version": versions,
        "sw_version_wget": sw_versions,
        "description": desc_text,
        "sec_adv": sec_advs,
        "cwe": cwes
    }


def scan_cve_files():
    """
    扫描所有 CVE 文件
    """
    cve_files = []
    
    for year in ["2024", "2025"]:
        year_dir = CVELIST_DIR / year
        if not year_dir.exists():
            continue
        
        for subdir in sorted(year_dir.iterdir()):
            if not subdir.is_dir():
                continue
            
            for json_file in sorted(subdir.glob("CVE-*.json")):
                cve_files.append(json_file)
    
    return cve_files


def main():
    print("=" * 60)
    print("严格 Web CVE 筛选器")
    print("要求: patch_commits + sec_adv + sw_version_wget 都必须有")
    print("=" * 60)
    print()
    
    # 初始化 LLM 客户端
    print("[1/4] 初始化 LLM 客户端...")
    client = OpenAI(api_key=API_KEY, base_url=BASE_URL)
    
    # 测试连接
    try:
        client.models.list()
        print("  ✅ 客户端初始化成功")
    except Exception as e:
        print(f"  ❌ 客户端初始化失败: {e}")
        return
    
    print()
    print(f"[2/4] 扫描 CVE 文件 (目标: {TARGET_COUNT} 个)...")
    
    cve_files = scan_cve_files()
    print(f"  找到 {len(cve_files)} 个 CVE 文件")
    
    selected_cves = []
    stats = {
        "total_scanned": 0,
        "has_all_fields": 0,
        "rule_passed": 0,
        "llm_verified": 0,
    }
    
    for json_file in cve_files:
        if len(selected_cves) >= TARGET_COUNT:
            break
        
        stats["total_scanned"] += 1
        
        try:
            with open(json_file, 'r', encoding='utf-8') as f:
                cve_data = json.load(f)
        except Exception as e:
            continue
        
        cve_id = cve_data.get("cveMetadata", {}).get("cveId", "")
        if not cve_id:
            continue
        
        # 提取三个关键字段
        patch_commits = extract_patch_commits(cve_data)
        sec_advs = extract_security_advisory(cve_data)
        sw_versions = extract_sw_version_wget(cve_data)
        
        # 严格要求: 三个字段都必须有
        if not patch_commits or not sec_advs or not sw_versions:
            continue
        
        stats["has_all_fields"] += 1
        
        # 规则判断是否 Web 相关
        is_web, score, reason = is_web_related_rule(cve_data)
        
        if not is_web:
            # 如果规则不通过但分数 > 3，使用 LLM 验证
            if score >= 3:
                stats["rule_passed"] += 1
                if not use_llm_verify(client, cve_data, cve_id):
                    continue
                stats["llm_verified"] += 1
            else:
                continue
        else:
            stats["rule_passed"] += 1
            stats["llm_verified"] += 1
        
        # 转换为输出格式
        cve_entry = convert_to_output_format(
            cve_data, cve_id, patch_commits, sec_advs, sw_versions
        )
        
        selected_cves.append(cve_entry)
        
        print(f"  ✅ [{len(selected_cves)}/{TARGET_COUNT}] {cve_id}")
        print(f"      patch: {len(patch_commits)}, adv: {len(sec_advs)}, repo: {len(sw_versions)}")
        
        # 进度报告
        if stats["total_scanned"] % 1000 == 0:
            print(f"  📊 进度: 扫描 {stats['total_scanned']}, "
                  f"有字段 {stats['has_all_fields']}, "
                  f"已选 {len(selected_cves)}")
    
    print()
    print("[3/4] 筛选完成")
    print(f"  - 总扫描: {stats['total_scanned']}")
    print(f"  - 有全部字段: {stats['has_all_fields']}")
    print(f"  - 规则通过: {stats['rule_passed']}")
    print(f"  - 最终选择: {len(selected_cves)}")
    
    # 保存结果
    print()
    print(f"[4/4] 保存到 {OUTPUT_FILE}...")
    
    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)
    
    with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
        json.dump(selected_cves, f, indent=2, ensure_ascii=False)
    
    print()
    print("✅ 完成！")
    print(f"   输出: {OUTPUT_FILE}")
    print()
    
    # 统计字段填充率
    print("  字段填充统计:")
    fields = ["description", "patch_commits", "sec_adv", "sw_version_wget", "cwe"]
    for field in fields:
        count = sum(1 for cve in selected_cves if cve.get(field))
        print(f"  - {field}: {count}/{len(selected_cves)}")


if __name__ == "__main__":
    main()
