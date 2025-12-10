#!/usr/bin/env python3
"""快速检查单个CVE是否有预设环境"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from toolbox.docker_vuln_registry import DockerVulnRegistry
from toolbox.vuln_env_sources import VulhubSource, VulfocusSource

cve_id = 'CVE-2025-29927'

print(f"检查 {cve_id} 的环境可用性:")
print("=" * 60)

# 1. 检查 DockerVulnRegistry
registry = DockerVulnRegistry()
result = registry.find_by_cve(cve_id)
if result:
    print(f"✅ DockerRegistry: 找到")
    print(f"   镜像: {result['image']}")
    print(f"   名称: {result['name']}")
else:
    print(f"❌ DockerRegistry: 未找到")

# 2. 检查 Vulhub
print("\n检查 Vulhub...")
vulhub = VulhubSource()
vulhub_result = vulhub.get_env_info(cve_id)
if vulhub_result:
    print(f"✅ Vulhub: 找到")
    print(f"   路径: {vulhub_result.get('path')}")
else:
    print(f"❌ Vulhub: 未找到")

# 3. 检查 Vulfocus
print("\n检查 Vulfocus...")
vulfocus = VulfocusSource()
vulfocus_result = vulfocus.get_env_info(cve_id)
if vulfocus_result:
    print(f"✅ Vulfocus: 找到")
    print(f"   镜像: {vulfocus_result.get('image')}")
else:
    print(f"❌ Vulfocus: 未找到")

print("\n" + "=" * 60)
if result or vulhub_result or vulfocus_result:
    print("✅ 该 CVE 有预设环境可用")
else:
    print("❌ 该 CVE 没有预设环境,需要使用 RepoBuilder 自定义构建")
