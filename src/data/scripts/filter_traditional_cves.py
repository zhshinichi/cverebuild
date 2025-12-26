#!/usr/bin/env python3
"""
从 data.json 中筛选出传统类型的漏洞（非 Web 漏洞）

传统漏洞特征：
- 不涉及 HTTP/HTTPS 交互
- 不涉及 Web 服务器/浏览器
- 通常是本地漏洞、内存漏洞、文件处理漏洞等

Web 漏洞特征（排除这些）：
- XSS, CSRF, SSRF, SQLi, LFI/RFI (通过 Web 访问)
- CWE 中包含 web 相关关键词
- 描述中涉及 HTTP、API、endpoint、server、browser 等
"""

import json
import re
from pathlib import Path

# Web 相关的 CWE ID
WEB_RELATED_CWES = {
    # XSS
    'CWE-79', 'CWE-80', 'CWE-81', 'CWE-83', 'CWE-84', 'CWE-85', 'CWE-86', 'CWE-87',
    # CSRF
    'CWE-352',
    # SSRF
    'CWE-918',
    # SQL Injection
    'CWE-89', 'CWE-564',
    # Command Injection (when via web)
    'CWE-77', 'CWE-78',
    # Path Traversal (when via web endpoint)
    'CWE-22', 'CWE-23', 'CWE-24', 'CWE-25', 'CWE-26', 'CWE-27', 'CWE-28', 'CWE-29', 'CWE-35', 'CWE-36',
    # Open Redirect
    'CWE-601',
    # Session/Auth issues
    'CWE-287', 'CWE-288', 'CWE-306', 'CWE-307', 'CWE-308', 'CWE-384', 'CWE-613',
    # HTTP related
    'CWE-113', 'CWE-444',
    # File Upload
    'CWE-434',
    # Information Disclosure (web context)
    'CWE-200', 'CWE-209',
    # Injection
    'CWE-94', 'CWE-95', 'CWE-96',
    # Template Injection
    'CWE-1336',
    # XML External Entity
    'CWE-611',
    # Deserialization
    'CWE-502',
}

# Web 相关关键词（在描述中检测）
WEB_KEYWORDS = [
    # 协议/服务
    r'\bhttp\b', r'\bhttps\b', r'\bweb\s*(server|service|app|application|ui|interface)',
    r'\brest\s*api\b', r'\bapi\s*endpoint', r'\bendpoint\b',
    r'\bweb\s*browser', r'\bbrowser\b',
    # 框架
    r'\bflask\b', r'\bdjango\b', r'\bfastapi\b', r'\bexpress\b', r'\bspring\b',
    r'\buvicorn\b', r'\bgunicorn\b', r'\bnginx\b', r'\bapache\b',
    # Web 漏洞类型
    r'\bxss\b', r'\bcross.site.script', r'\bcsrf\b', r'\bssrf\b',
    r'\bsql\s*injection', r'\bsqli\b',
    r'\bopen\s*redirect', r'\burl\s*redirect',
    r'\bremote\s*code\s*execution.*web', r'\brce.*api\b',
    # Web 组件
    r'\bcookie\b', r'\bsession\b', r'\bauth.*token\b',
    r'\bform\s*upload', r'\bfile\s*upload.*web',
    r'\bhtml\b', r'\bjavascript\b', r'\bjson\s*api',
    # 网络请求
    r'\bcurl\b.*localhost', r'\bpost\s*request', r'\bget\s*request',
    r'localhost:\d+', r'127\.0\.0\.1:\d+',
]

# 传统漏洞类型的 CWE
TRADITIONAL_CWES = {
    # Buffer Overflow
    'CWE-119', 'CWE-120', 'CWE-121', 'CWE-122', 'CWE-124', 'CWE-125', 'CWE-126', 'CWE-127',
    'CWE-787', 'CWE-788',
    # Use After Free / Double Free
    'CWE-415', 'CWE-416', 'CWE-825',
    # Integer Overflow
    'CWE-190', 'CWE-191',
    # Format String
    'CWE-134',
    # Race Condition
    'CWE-362', 'CWE-366', 'CWE-367',
    # Null Pointer
    'CWE-476',
    # Memory Leak
    'CWE-401', 'CWE-772',
    # Cryptographic Issues
    'CWE-310', 'CWE-311', 'CWE-312', 'CWE-319', 'CWE-320', 'CWE-326', 'CWE-327', 'CWE-328', 'CWE-329',
    # Privilege Escalation
    'CWE-269', 'CWE-250', 'CWE-266',
}


def is_web_vulnerability(cve_data: dict) -> bool:
    """判断是否是 Web 相关漏洞"""
    
    # 1. 检查 CWE
    cwes = cve_data.get('cwe', [])
    for cwe in cwes:
        cwe_id = cwe.get('id', '')
        if cwe_id in WEB_RELATED_CWES:
            return True
    
    # 2. 检查描述
    description = cve_data.get('description', '').lower()
    for pattern in WEB_KEYWORDS:
        if re.search(pattern, description, re.IGNORECASE):
            return True
    
    # 3. 检查安全公告内容
    sec_advs = cve_data.get('sec_adv', [])
    for adv in sec_advs:
        content = adv.get('content', '').lower()
        # 检查 PoC 中是否有 Web 请求
        if re.search(r'curl.*localhost|http.*request|post.*endpoint|get\s+/\w+', content, re.IGNORECASE):
            return True
        # 检查是否启动 Web 服务器
        if re.search(r'start.*server|run.*server|flask run|uvicorn|gunicorn', content, re.IGNORECASE):
            return True
    
    # 4. 检查补丁内容（看是否涉及 Web 相关文件）
    patches = cve_data.get('patch_commits', [])
    for patch in patches:
        content = patch.get('content', '').lower()
        # 检查文件名
        if re.search(r'(server|endpoint|route|api|handler|view|controller)\.(py|js|ts|java|go)', content, re.IGNORECASE):
            return True
        # 检查内容
        if re.search(r'@(app\.|router\.|api)|(route|endpoint|request|response)', content, re.IGNORECASE):
            return True
    
    return False


def is_traditional_vulnerability(cve_data: dict) -> bool:
    """判断是否是传统类型漏洞"""
    
    # 首先排除 Web 漏洞
    if is_web_vulnerability(cve_data):
        return False
    
    # 检查 CWE 是否是传统类型
    cwes = cve_data.get('cwe', [])
    for cwe in cwes:
        cwe_id = cwe.get('id', '')
        if cwe_id in TRADITIONAL_CWES:
            return True
    
    # 检查描述中是否有传统漏洞特征
    description = cve_data.get('description', '').lower()
    traditional_patterns = [
        r'buffer\s*overflow', r'stack\s*overflow', r'heap\s*overflow',
        r'use.after.free', r'double.free', r'memory\s*corruption',
        r'integer\s*overflow', r'format\s*string',
        r'null\s*pointer', r'dereference',
        r'race\s*condition', r'toctou',
        r'privilege\s*escalation', r'local\s*privilege',
        r'arbitrary\s*code\s*execution(?!.*web)',
        r'denial\s*of\s*service(?!.*web)',
    ]
    
    for pattern in traditional_patterns:
        if re.search(pattern, description, re.IGNORECASE):
            return True
    
    return False


def main():
    # 读取数据
    data_path = Path('/workspaces/submission/src/data/large_scale/data.json')
    
    with open(data_path, 'r', encoding='utf-8') as f:
        data = json.load(f)
    
    print(f"总 CVE 数量: {len(data)}")
    print("=" * 60)
    
    # 分类统计
    web_cves = []
    traditional_cves = []
    uncertain_cves = []
    
    for cve_id, cve_data in data.items():
        if is_web_vulnerability(cve_data):
            web_cves.append(cve_id)
        elif is_traditional_vulnerability(cve_data):
            traditional_cves.append(cve_id)
        else:
            # 既不是明确的 Web 漏洞也不是明确的传统漏洞
            uncertain_cves.append(cve_id)
    
    print(f"\n📊 分类结果:")
    print(f"   Web 漏洞: {len(web_cves)}")
    print(f"   传统漏洞: {len(traditional_cves)}")
    print(f"   不确定:   {len(uncertain_cves)}")
    
    # 输出传统漏洞列表
    print("\n" + "=" * 60)
    print("🔧 传统类型漏洞列表 (非 Web):")
    print("=" * 60)
    
    for cve_id in sorted(traditional_cves):
        cve_data = data[cve_id]
        cwes = [c.get('id', '') for c in cve_data.get('cwe', [])]
        desc = cve_data.get('description', '')[:100] + '...'
        print(f"\n{cve_id}")
        print(f"   CWE: {', '.join(cwes) if cwes else 'N/A'}")
        print(f"   描述: {desc}")
    
    # 保存结果
    output = {
        'traditional_cves': sorted(traditional_cves),
        'web_cves': sorted(web_cves),
        'uncertain_cves': sorted(uncertain_cves),
        'stats': {
            'total': len(data),
            'web': len(web_cves),
            'traditional': len(traditional_cves),
            'uncertain': len(uncertain_cves),
        }
    }
    
    output_path = Path('/workspaces/submission/src/data/large_scale/cve_classification.json')
    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(output, f, indent=2, ensure_ascii=False)
    
    print(f"\n\n✅ 结果已保存到: {output_path}")
    
    # 单独输出 CVE ID 列表（方便复制）
    print("\n" + "=" * 60)
    print("📋 传统漏洞 CVE ID 列表 (可直接复制):")
    print("=" * 60)
    print(json.dumps(sorted(traditional_cves), indent=2))


if __name__ == '__main__':
    main()
