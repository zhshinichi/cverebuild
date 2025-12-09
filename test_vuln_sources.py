"""
测试Vulhub/Vulfocus集成

快速验证环境源查找和部署功能
"""

import sys
sys.path.insert(0, 'src')

from toolbox.vuln_env_sources import VulnEnvManager
import json


def test_env_sources():
    """测试环境源"""
    print("="*70)
    print("🧪 Testing Vulhub/Vulfocus Integration")
    print("="*70)
    
    manager = VulnEnvManager()
    
    # 测试CVE列表
    test_cases = [
        ("CVE-2017-12615", "Tomcat PUT漏洞", True),
        ("CVE-2018-1273", "Spring Data Commons RCE", True),
        ("CVE-2021-44228", "Log4Shell", True),
        ("CVE-2024-4340", "sqlparse DoS", False),
        ("CVE-2025-10390", "CRMEB", False),
    ]
    
    results = []
    
    for cve_id, description, expected_found in test_cases:
        print(f"\n{'─'*70}")
        print(f"🔍 Testing: {cve_id} - {description}")
        print(f"{'─'*70}")
        
        result = manager.find_env(cve_id)
        
        if result:
            source, env_info = result
            status = "✅ FOUND"
            print(f"{status} in {env_info['source']}")
            print(f"   Details: {json.dumps(env_info, indent=6, ensure_ascii=False)[:300]}...")
            
            results.append({
                'cve_id': cve_id,
                'found': True,
                'source': env_info['source'],
                'expected': expected_found,
                'match': True
            })
        else:
            status = "❌ NOT FOUND"
            print(f"{status} - Will use custom RepoBuilder")
            
            results.append({
                'cve_id': cve_id,
                'found': False,
                'source': None,
                'expected': expected_found,
                'match': not expected_found
            })
    
    # 统计
    print(f"\n{'='*70}")
    print("📊 Statistics")
    print(f"{'='*70}")
    
    stats = manager.get_statistics()
    for source_name, source_stats in stats.items():
        print(f"\n{source_name}:")
        for key, value in source_stats.items():
            print(f"  - {key}: {value}")
    
    # 结果汇总
    print(f"\n{'='*70}")
    print("📋 Test Results Summary")
    print(f"{'='*70}")
    
    found_count = sum(1 for r in results if r['found'])
    expected_count = sum(1 for r in results if r['expected'])
    
    print(f"\nTotal CVEs tested: {len(results)}")
    print(f"Found in sources: {found_count}")
    print(f"Expected to find: {expected_count}")
    
    print(f"\n{'CVE ID':<20} {'Found':<10} {'Source':<15} {'Expected':<10} {'Match':<8}")
    print("─"*70)
    for r in results:
        found_icon = "✅" if r['found'] else "❌"
        match_icon = "✓" if r['match'] else "✗"
        source_name = r['source'] or "N/A"
        expected_icon = "Yes" if r['expected'] else "No"
        
        print(f"{r['cve_id']:<20} {found_icon:<10} {source_name:<15} {expected_icon:<10} {match_icon:<8}")
    
    print(f"\n{'='*70}")
    print("✅ Test completed!")
    print(f"{'='*70}")


if __name__ == "__main__":
    test_env_sources()
