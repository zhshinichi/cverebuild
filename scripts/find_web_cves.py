#!/usr/bin/env python3
"""查找数据集中的 Web 相关漏洞"""

import json

DATA_FILE = '/workspaces/submission/src/data/large_scale/data.json'

def main():
    with open(DATA_FILE, 'r') as f:
        data = json.load(f)

    # 查找有有效 PoC 的 Web CVE
    good_candidates = []
    
    web_cwes = ['CWE-79', 'CWE-89', 'CWE-22', 'CWE-352', 'CWE-918', 'CWE-94', 'CWE-78']

    for cve_id, entry in data.items():
        cwes = entry.get('cwe', [])
        sec_adv = entry.get('sec_adv', [])
        desc = entry.get('description', '').lower()
        
        cwe_ids = [c.get('id', '') for c in cwes] if isinstance(cwes, list) else []
        
        # 检查是否有有效的 sec_adv (有 PoC)
        has_effective_adv = False
        for adv in sec_adv:
            if adv.get('effective', False):
                has_effective_adv = True
                break
        
        is_web = any(wc in str(cwe_ids) for wc in web_cwes)
        
        # Python Web 框架相关
        python_keywords = ['python', 'flask', 'django', 'fastapi', 'mlflow', 'localai', 'lollms', 'gradio']
        is_python = any(kw in desc for kw in python_keywords)
        
        if is_web and has_effective_adv:
            good_candidates.append({
                'id': cve_id,
                'cwe': cwe_ids[0] if cwe_ids else 'N/A',
                'python': is_python,
                'version': entry.get('sw_version', 'N/A'),
                'desc': desc[:150]
            })

    print('=' * 80)
    print(f'Web CVEs with effective PoC (Total: {len(good_candidates)})')
    print('=' * 80)
    
    # 分类
    python_ones = [c for c in good_candidates if c['python']]
    others = [c for c in good_candidates if not c['python']]
    
    print(f'\n[RECOMMENDED - Python-based Web Apps: {len(python_ones)}]')
    print('-' * 80)
    for c in python_ones[:15]:
        print(f"  {c['id']} | {c['cwe']} | {c['version']}")
    
    print(f'\n[Other Web Apps: {len(others)}]')
    print('-' * 80)
    for c in others[:20]:
        print(f"  {c['id']} | {c['cwe']} | {c['version']}")


if __name__ == '__main__':
    main()
