#!/usr/bin/env python3
"""查看推荐的 Python Web CVE 详细信息"""

import json

DATA_FILE = '/workspaces/submission/src/data/large_scale/data.json'

# 推荐的 Python Web CVEs
RECOMMENDED = [
    'CVE-2024-2288',   # CSRF - lollms
    'CVE-2024-6983',   # RCE - localai  
    'CVE-2024-3322',   # Path Traversal
    'CVE-2024-5182',   # Path Traversal - gradio
    'CVE-2025-46719',  # XSS
    'CVE-2025-1473',   # CSRF
    'CVE-2024-4343',   # Command Injection
    'CVE-2024-5181',   # Command Injection
]

def main():
    with open(DATA_FILE, 'r') as f:
        data = json.load(f)

    for cve_id in RECOMMENDED:
        entry = data.get(cve_id, {})
        if not entry:
            print(f'{cve_id}: NOT FOUND')
            continue
            
        cwes = entry.get('cwe', [])
        cwe_str = cwes[0].get('id', 'N/A') if cwes else 'N/A'
        
        print('=' * 80)
        print(f'CVE: {cve_id}')
        print(f'Type: {cwe_str}')
        print(f'Version: {entry.get("sw_version", "N/A")}')
        print(f'Description: {entry.get("description", "")[:250]}...')
        
        # 检查 sec_adv
        sec_adv = entry.get('sec_adv', [])
        has_poc = any(adv.get('effective', False) for adv in sec_adv)
        print(f'PoC Available: {"YES" if has_poc else "NO"}')
        print()


if __name__ == '__main__':
    main()
