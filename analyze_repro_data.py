import json

with open('src/data/large_scale/repro_data.json', 'r', encoding='utf-8') as f:
    data = json.load(f)

print(f'总共 {len(data)} 个 CVE 条目\n')

# 分析字段
fields = ['description', 'cwe', 'sw_version', 'sw_version_wget', 'patch_commits', 'sec_adv', 'published_date']
field_stats = {f: {'has': 0, 'empty': 0, 'missing': 0} for f in fields}

# 统计每个字段的情况
for cve_id, entry in data.items():
    for field in fields:
        if field not in entry:
            field_stats[field]['missing'] += 1
        elif entry[field] is None or entry[field] == '' or entry[field] == []:
            field_stats[field]['empty'] += 1
        elif field == 'patch_commits' and (entry[field] == [] or len(entry[field]) == 0):
            field_stats[field]['empty'] += 1
        else:
            field_stats[field]['has'] += 1

print('=' * 60)
print('字段完整性统计:')
print('=' * 60)
total = len(data)
for field, stats in field_stats.items():
    has_pct = stats['has'] / total * 100
    print(f'{field:20} | 有值: {stats["has"]:3} ({has_pct:5.1f}%) | 空: {stats["empty"]:3} | 缺失: {stats["missing"]:3}')

# 关键字段统计
print('\n' + '=' * 60)
print('关键字段分析 (复现所需):')
print('=' * 60)

has_wget = sum(1 for e in data.values() if e.get('sw_version_wget'))
has_patch = sum(1 for e in data.values() if e.get('patch_commits') and len(e.get('patch_commits', [])) > 0)
has_both = sum(1 for e in data.values() if e.get('sw_version_wget') and e.get('patch_commits') and len(e.get('patch_commits', [])) > 0)

print(f'有源码下载链接 (sw_version_wget): {has_wget}/{total} ({has_wget/total*100:.1f}%)')
print(f'有补丁提交 (patch_commits): {has_patch}/{total} ({has_patch/total*100:.1f}%)')
print(f'两者都有: {has_both}/{total} ({has_both/total*100:.1f}%)')

# 查看几个具体的CVE内容
print('\n' + '=' * 60)
print('示例 CVE 条目 (前3个):')
print('=' * 60)
for i, (cve_id, entry) in enumerate(list(data.items())[:3]):
    print(f'\n{i+1}. {cve_id}')
    desc = entry.get("description", "N/A")
    print(f'   description: {desc[:80]}...' if len(desc) > 80 else f'   description: {desc}')
    print(f'   cwe: {entry.get("cwe", "N/A")}')
    print(f'   sw_version: {entry.get("sw_version", "N/A")}')
    wget = entry.get("sw_version_wget", "N/A")
    print(f'   sw_version_wget: {wget[:60]}...' if wget and len(wget) > 60 else f'   sw_version_wget: {wget}')
    patch = entry.get('patch_commits', [])
    print(f'   patch_commits: {len(patch) if isinstance(patch, list) else patch} 个')
    sec = entry.get('sec_adv', [])
    print(f'   sec_adv: {len(sec) if isinstance(sec, list) else sec} 个')

# 检查sec_adv的内容质量
print('\n' + '=' * 60)
print('sec_adv 内容质量分析:')
print('=' * 60)
html_content_count = 0
clean_content_count = 0
for cve_id, entry in data.items():
    sec_adv = entry.get('sec_adv', [])
    if sec_adv:
        for adv in sec_adv:
            content = adv.get('content', '')
            if '<html' in content.lower() or '<!doctype' in content.lower():
                html_content_count += 1
            elif content and len(content) > 50:
                clean_content_count += 1
                
print(f'包含 HTML 页面内容的 sec_adv: {html_content_count}')
print(f'干净的文本内容 sec_adv: {clean_content_count}')

# 与项目所需字段对比
print('\n' + '=' * 60)
print('项目复现所需字段评估:')
print('=' * 60)
print('''
项目需要的关键字段:
  ✓ cve_id - 从 key 获取
  ✓ description - 漏洞描述
  ✓ cwe - 漏洞类型分类
  ✓ sw_version - 漏洞版本
  ✓ sw_version_wget - 源码下载链接 (关键!)
  ? patch_commits - 补丁提交 (用于分析漏洞位置)
  ? sec_adv - 安全公告 (辅助信息)
''')
