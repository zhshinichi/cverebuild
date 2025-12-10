"""快速检查CVE环境可用性"""
import sys
import os
sys.path.insert(0, 'src')

# 动态导入避免依赖问题
import importlib.util

def load_module_from_path(module_name, file_path):
    spec = importlib.util.spec_from_file_location(module_name, file_path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

vuln_env_path = os.path.join('src', 'toolbox', 'vuln_env_sources.py')
vuln_env_module = load_module_from_path('vuln_env_sources', vuln_env_path)
VulnEnvManager = vuln_env_module.VulnEnvManager

# 要检查的CVE列表
cves = [
    'CVE-2025-0001',
    'CVE-2025-0049',
    'CVE-2025-0050',
    'CVE-2025-0053',
    'CVE-2025-0054',
    'CVE-2025-0057',
    'CVE-2025-0058',
    'CVE-2025-0059',
    'CVE-2025-0060',
    'CVE-2025-0061'
]

print("=" * 60)
print("检查CVE预构建环境可用性")
print("=" * 60)
print()

manager = VulnEnvManager()

found_count = 0
not_found_count = 0

for cve in cves:
    result = manager.find_env(cve)
    if result:
        source, info = result
        print(f"✅ {cve}: 找到于 {source.name}")
        found_count += 1
    else:
        print(f"❌ {cve}: 未找到预构建环境")
        not_found_count += 1
    print()

print("=" * 60)
print(f"统计: ✅ {found_count}个有环境 | ❌ {not_found_count}个需要自建")
print("=" * 60)
