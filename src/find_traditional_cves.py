#!/usr/bin/env python3
"""
从 large_scale/data.json 中筛选出传统类型漏洞（非 Web 类）

传统类型漏洞特征：
- 不涉及 Web 应用/服务器/API
- 通常是命令行工具、库、系统组件
- 漏洞类型：缓冲区溢出、命令注入、本地提权等
"""

import json
from pathlib import Path
from collections import Counter

# Web 相关关键词（用于排除）
WEB_KEYWORDS = [
    # 框架/服务器
    'web', 'http', 'https', 'api', 'rest', 'graphql',
    'flask', 'django', 'fastapi', 'express', 'node.js', 'nodejs',
    'spring', 'springboot', 'tomcat', 'nginx', 'apache',
    'php', 'laravel', 'symfony', 'wordpress', 'drupal', 'joomla',
    'ruby on rails', 'rails', 'sinatra',
    # 前端
    'javascript', 'react', 'vue', 'angular', 'frontend',
    'browser', 'html', 'css', 'dom', 'xss', 'csrf',
    # Web 漏洞类型
    'sql injection', 'sqli', 'cross-site', 'ssrf', 'ssti',
    'open redirect', 'path traversal', 'directory traversal',
    'authentication bypass', 'session', 'cookie',
    'upload', 'file inclusion', 'lfi', 'rfi',
    # Web 服务
    'webui', 'web ui', 'web interface', 'dashboard',
    'admin panel', 'login', 'oauth', 'jwt',
    # 协议
    'websocket', 'ajax', 'json', 'xml',
]

# 传统漏洞关键词（用于包含）
TRADITIONAL_KEYWORDS = [
    # 内存安全
    'buffer overflow', 'stack overflow', 'heap overflow',
    'use after free', 'double free', 'memory corruption',
    'out of bounds', 'integer overflow', 'null pointer',
    # 命令/代码执行
    'command injection', 'code execution', 'rce',
    'arbitrary code', 'shell injection',
    # 本地漏洞
    'local privilege', 'privilege escalation', 'lpe',
    'symlink', 'race condition', 'toctou',
    # 文件系统
    'arbitrary file', 'file write', 'file read',
    # 解析器漏洞
    'parser', 'deserialize', 'pickle', 'yaml.load',
    # 加密相关
    'cryptographic', 'weak encryption',
    # 拒绝服务
    'denial of service', 'dos', 'crash', 'segfault',
]

def load_data():
    """加载 CVE 数据"""
    data_path = Path('/workspaces/submission/src/data/large_scale/data.json')
    with open(data_path, 'r', encoding='utf-8') as f:
        return json.load(f)

def is_web_related(cve_entry: dict) -> bool:
    """判断是否是 Web 相关漏洞"""
    # 检查所有文本字段
    text_fields = [
        cve_entry.get('description', ''),
        cve_entry.get('vulnerability_type', ''),
        cve_entry.get('software_name', ''),
        cve_entry.get('repo_url', ''),
        str(cve_entry.get('tags', [])),
    ]
    
    combined_text = ' '.join(text_fields).lower()
    
    # 检查是否包含 Web 关键词
    for keyword in WEB_KEYWORDS:
        if keyword in combined_text:
            return True
    
    return False

def is_traditional_vuln(cve_entry: dict) -> bool:
    """判断是否是传统类型漏洞"""
    text_fields = [
        cve_entry.get('description', ''),
        cve_entry.get('vulnerability_type', ''),
    ]
    
    combined_text = ' '.join(text_fields).lower()
    
    # 检查是否包含传统漏洞关键词
    for keyword in TRADITIONAL_KEYWORDS:
        if keyword in combined_text:
            return True
    
    return False

def analyze_cves():
    """分析并筛选传统类型漏洞"""
    data = load_data()
    
    traditional_cves = []
    web_cves = []
    uncertain_cves = []
    
    vuln_types = Counter()
    
    # data 是 dict，key 是 CVE ID，value 是详情
    for cve_id, cve_entry in data.items():
        is_web = is_web_related(cve_entry)
        is_trad = is_traditional_vuln(cve_entry)
        
        # 从 CWE 提取漏洞类型
        cwe_list = cve_entry.get('cwe', [])
        vuln_type = cwe_list[0].get('value', 'Unknown') if cwe_list else 'Unknown'
        vuln_types[vuln_type] += 1
        
        if not is_web and is_trad:
            # 明确的传统漏洞
            traditional_cves.append({
                'cve_id': cve_id,
                'software': cve_entry.get('sw_version', ''),
                'vuln_type': vuln_type,
                'description': cve_entry.get('description', '')[:100],
            })
        elif not is_web:
            # 不是 Web，但也不确定是否是传统漏洞
            uncertain_cves.append({
                'cve_id': cve_id,
                'software': cve_entry.get('sw_version', ''),
                'vuln_type': vuln_type,
                'description': cve_entry.get('description', '')[:100],
            })
        else:
            web_cves.append(cve_id)
    
    return traditional_cves, uncertain_cves, web_cves, vuln_types

def main():
    print("=" * 60)
    print("从 large_scale/data.json 筛选传统类型漏洞")
    print("=" * 60)
    
    traditional, uncertain, web, vuln_types = analyze_cves()
    
    print(f"\n📊 统计结果:")
    print(f"   - 总 CVE 数量: {len(traditional) + len(uncertain) + len(web)}")
    print(f"   - Web 相关漏洞: {len(web)}")
    print(f"   - 传统类型漏洞: {len(traditional)}")
    print(f"   - 待确认漏洞: {len(uncertain)}")
    
    print(f"\n📋 漏洞类型分布:")
    for vtype, count in vuln_types.most_common(15):
        print(f"   - {vtype}: {count}")
    
    # ========== 保存结果到文件 ==========
    output_dir = Path('/workspaces/submission/src/data/large_scale')
    
    # 1. 保存传统漏洞 CVE ID 列表
    traditional_cve_ids = [cve['cve_id'] for cve in traditional]
    traditional_file = output_dir / 'traditional_cves.txt'
    with open(traditional_file, 'w') as f:
        f.write('\n'.join(traditional_cve_ids))
    print(f"\n✅ 传统漏洞列表已保存到: {traditional_file}")
    print(f"   共 {len(traditional_cve_ids)} 个 CVE")
    
    # 2. 保存待确认漏洞 CVE ID 列表
    uncertain_cve_ids = [cve['cve_id'] for cve in uncertain]
    uncertain_file = output_dir / 'uncertain_cves.txt'
    with open(uncertain_file, 'w') as f:
        f.write('\n'.join(uncertain_cve_ids))
    print(f"\n✅ 待确认漏洞列表已保存到: {uncertain_file}")
    print(f"   共 {len(uncertain_cve_ids)} 个 CVE")
    
    # 3. 保存详细 JSON 报告
    report = {
        'summary': {
            'total': len(traditional) + len(uncertain) + len(web),
            'traditional': len(traditional),
            'uncertain': len(uncertain),
            'web': len(web),
        },
        'traditional_cves': traditional,
        'uncertain_cves': uncertain,
        'web_cve_ids': web,
    }
    report_file = output_dir / 'cve_classification_report.json'
    with open(report_file, 'w', encoding='utf-8') as f:
        json.dump(report, f, indent=2, ensure_ascii=False)
    print(f"\n✅ 详细报告已保存到: {report_file}")
    
    print("\n" + "=" * 60)
    print("🔧 传统类型漏洞列表 (非 Web)")
    print("=" * 60)
    
    if traditional:
        print("\n### 明确的传统漏洞:")
        for i, cve in enumerate(traditional, 1):
            print(f"\n{i}. {cve['cve_id']}")
            print(f"   软件: {cve['software']}")
            print(f"   类型: {cve['vuln_type']}")
            print(f"   描述: {cve['description']}...")
        
        print("\n" + "-" * 60)
        print("传统漏洞 CVE ID 列表 (可复制):")
        print("-" * 60)
        for cve in traditional:
            print(cve['cve_id'])
    
    if uncertain:
        print("\n" + "=" * 60)
        print("❓ 待确认漏洞 (非 Web 但类型不明确)")
        print("=" * 60)
        for i, cve in enumerate(uncertain, 1):
            print(f"\n{i}. {cve['cve_id']}")
            print(f"   软件: {cve['software']}")
            print(f"   类型: {cve['vuln_type']}")
            print(f"   描述: {cve['description']}...")
        
        print("\n" + "-" * 60)
        print("待确认 CVE ID 列表:")
        print("-" * 60)
        for cve in uncertain:
            print(cve['cve_id'])

if __name__ == '__main__':
    main()
