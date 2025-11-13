#!/usr/bin/env python3
"""
分析data.json中的CVE,筛选出安全且容易复现的CVE
"""
import json
import sys
from pathlib import Path

# 危险的CWE类型 (会导致RCE或系统破坏)
DANGEROUS_CWES = {
    'CWE-94',   # 代码注入
    'CWE-78',   # OS命令注入
    'CWE-77',   # 命令注入
    'CWE-502',  # 不安全的反序列化
    'CWE-434',  # 不受限制的文件上传
    'CWE-918',  # SSRF
    'CWE-611',  # XXE
}

# 相对安全的CWE类型 (适合复现)
SAFE_CWES = {
    'CWE-89',   # SQL注入
    'CWE-79',   # XSS
    'CWE-352',  # CSRF
    'CWE-22',   # 路径遍历
    'CWE-36',   # 绝对路径遍历
    'CWE-20',   # 输入验证不当
    'CWE-269',  # 权限管理不当
    'CWE-287',  # 认证绕过
    'CWE-639',  # 授权缺陷
}

# 危险关键词
DANGEROUS_KEYWORDS = [
    'rce', 'remote code execution', 'arbitrary code',
    'system takeover', 'full control', 'privilege escalation',
    'container escape', 'docker escape',
    'binary', 'executable', 'compile',
]

# 复杂环境关键词
COMPLEX_KEYWORDS = [
    'docker-compose', 'kubernetes', 'microservice',
    'database', 'redis', 'mongodb', 'postgresql',
    'oauth', 'saml', 'jwt signature',
]

# 简单库类型
SIMPLE_REGISTRIES = ['pypi', 'npm', 'packagist', 'rubygems']

def analyze_cve(cve_id, cve_data):
    """分析单个CVE的安全性和复现难度"""
    score = 100  # 基础分数,越高越安全且容易
    reasons = []
    warnings = []
    
    # 1. 检查CWE
    cwes = cve_data.get('cwe', [])
    cwe_ids = [cwe.get('id', '') for cwe in cwes]
    
    for cwe_id in cwe_ids:
        if cwe_id in DANGEROUS_CWES:
            score -= 40
            warnings.append(f"危险CWE: {cwe_id}")
        elif cwe_id in SAFE_CWES:
            score += 10
            reasons.append(f"安全CWE: {cwe_id}")
    
    # 2. 检查描述中的危险关键词
    description = cve_data.get('description', '').lower()
    for keyword in DANGEROUS_KEYWORDS:
        if keyword in description:
            score -= 30
            warnings.append(f"危险关键词: {keyword}")
            break
    
    # 3. 检查是否需要复杂环境
    for keyword in COMPLEX_KEYWORDS:
        if keyword in description:
            score -= 15
            warnings.append(f"复杂环境: {keyword}")
            break
    
    # 4. 检查是否需要浏览器 (新增)
    browser_cwes = ['CWE-79', 'CWE-352', 'CWE-1021']  # XSS, CSRF, Clickjacking
    browser_keywords = ['xss', 'cross-site scripting', 'csrf', 'cross-site request forgery', 'clickjacking', 'dom-based']
    needs_browser = False
    
    for cwe_id in cwe_ids:
        if cwe_id in browser_cwes:
            score -= 25
            warnings.append(f"需要浏览器: {cwe_id}")
            needs_browser = True
            break
    
    for keyword in browser_keywords:
        if keyword in description:
            score -= 25
            warnings.append(f"需要浏览器: {keyword}")
            needs_browser = True
            break
    
    # 5. 检查安全公告
    sec_adv = cve_data.get('sec_adv', [])
    if sec_adv:
        total_size = sum(len(adv.get('content', '')) for adv in sec_adv)
        if total_size > 10000:  # 超过10KB
            score -= 20
            warnings.append(f"sec_adv过大: {total_size} bytes")
        elif total_size < 3000:
            score += 10
            reasons.append("sec_adv简洁")
    
    # 6. 检查是否有patch
    patches = cve_data.get('patch_commits', [])
    if not patches:
        score -= 15
        warnings.append("无patch信息")
    else:
        reasons.append(f"有{len(patches)}个patch")
    
    # 6. 检查是否是简单的库漏洞
    # (通过检查是否有registry字段判断)
    # 实际data.json中可能没有这个字段,我们通过其他方式判断
    if 'sw_version' in cve_data and 'sw_version_wget' in cve_data:
        wget_url = cve_data.get('sw_version_wget', '')
        if 'pypi' in wget_url or 'npm' in wget_url:
            score += 20
            reasons.append("简单的包管理器库")
    
    # 7. 检查CVSS分数(如果有)
    # 这里我们根据描述推断
    if 'critical' in description:
        score -= 25
        warnings.append("Critical级别")
    elif 'high' in description:
        score -= 10
        warnings.append("High级别")
    
    return score, reasons, warnings

def main():
    data_file = Path('src/data/large_scale/data.json')
    
    if not data_file.exists():
        print(f"❌ 文件不存在: {data_file}")
        sys.exit(1)
    
    with open(data_file, 'r', encoding='utf-8') as f:
        data = json.load(f)
    
    print(f"📊 总共 {len(data)} 个CVE")
    print("="*80)
    
    results = []
    
    for cve_id, cve_data in data.items():
        score, reasons, warnings = analyze_cve(cve_id, cve_data)
        
        results.append({
            'cve_id': cve_id,
            'score': score,
            'reasons': reasons,
            'warnings': warnings,
            'description': cve_data.get('description', '')[:100] + '...',
            'cwe': [cwe.get('id', '') for cwe in cve_data.get('cwe', [])],
            'sw_version': cve_data.get('sw_version', 'N/A'),
        })
    
    # 按分数排序
    results.sort(key=lambda x: x['score'], reverse=True)
    
    # 输出Top 20安全的CVE
    print("\n🎯 Top 20 最安全且容易复现的CVE:\n")
    
    for i, result in enumerate(results[:20], 1):
        print(f"{i}. {result['cve_id']} (评分: {result['score']})")
        print(f"   版本: {result['sw_version']}")
        print(f"   CWE: {', '.join(result['cwe'])}")
        print(f"   描述: {result['description']}")
        
        if result['reasons']:
            print(f"   ✅ 优点: {'; '.join(result['reasons'][:3])}")
        if result['warnings']:
            print(f"   ⚠️  注意: {'; '.join(result['warnings'][:3])}")
        print()
    
    # 输出统计信息
    print("="*80)
    safe_cves = [r for r in results if r['score'] >= 80]
    medium_cves = [r for r in results if 50 <= r['score'] < 80]
    dangerous_cves = [r for r in results if r['score'] < 50]
    
    print(f"\n📈 统计:")
    print(f"   🟢 安全 (评分≥80): {len(safe_cves)} 个")
    print(f"   🟡 中等 (评分50-79): {len(medium_cves)} 个")
    print(f"   🔴 危险 (评分<50): {len(dangerous_cves)} 个")
    
    # 保存结果
    output_file = Path('src/data/safe_cves.json')
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump({
            'top_20': results[:20],
            'statistics': {
                'total': len(results),
                'safe': len(safe_cves),
                'medium': len(medium_cves),
                'dangerous': len(dangerous_cves)
            }
        }, f, indent=2, ensure_ascii=False)
    
    print(f"\n✅ 结果已保存到: {output_file}")

if __name__ == '__main__':
    main()
