"""
Environment Search Engine - 智能环境搜索引擎

功能:
1. 搜索GitHub上的PoC仓库和环境配置
2. 搜索Docker Hub上的相似镜像
3. 评估是否能创建模拟环境
4. 为DeploymentAnalyzer和FreestyleAgent提供降级策略
"""

import subprocess
import requests
import re
from typing import Dict, List, Optional, Tuple
from pathlib import Path
import json


class EnvironmentSearchEngine:
    """环境搜索引擎"""
    
    GITHUB_API = "https://api.github.com/search/repositories"
    GITHUB_SEARCH_URL = "https://github.com/search"
    
    def __init__(self):
        self.cache_dir = Path.home() / ".cache" / "vuln_env_search"
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.github_token = None  # 可选：提高API速率限制
    
    def search_all(self, cve_id: str, product: str = None, version: str = None) -> Dict:
        """综合搜索所有可能的环境来源
        
        Returns:
            {
                'poc_repos': List[dict],        # GitHub PoC仓库
                'docker_images': List[dict],    # Docker Hub镜像
                'similar_cves': List[str],      # 类似CVE
                'can_mock': bool,               # 是否能创建模拟环境
                'mock_strategy': str            # 模拟策略
            }
        """
        results = {
            'poc_repos': [],
            'docker_images': [],
            'similar_cves': [],
            'can_mock': False,
            'mock_strategy': None
        }
        
        # 1. 搜索GitHub PoC
        print(f"[EnvSearch] 🔍 搜索 GitHub PoC for {cve_id}...")
        results['poc_repos'] = self.search_github_poc(cve_id)
        
        # 2. 搜索Docker镜像
        if product:
            print(f"[EnvSearch] 🔍 搜索 Docker Hub for {product}...")
            results['docker_images'] = self.search_docker_hub(product)
        
        # 3. 评估模拟环境可行性
        results['can_mock'], results['mock_strategy'] = self.evaluate_mock_feasibility(
            cve_id, product, version
        )
        
        return results
    
    def search_github_poc(self, cve_id: str) -> List[Dict]:
        """搜索GitHub上的PoC仓库"""
        poc_repos = []
        
        # 搜索关键词组合
        search_queries = [
            f"{cve_id} poc",
            f"{cve_id} exploit",
            f"{cve_id} docker",
            f"{cve_id} environment"
        ]
        
        for query in search_queries:
            try:
                # GitHub API搜索
                headers = {}
                if self.github_token:
                    headers['Authorization'] = f'token {self.github_token}'
                
                params = {
                    'q': query,
                    'sort': 'stars',
                    'order': 'desc',
                    'per_page': 5
                }
                
                response = requests.get(
                    self.GITHUB_API,
                    params=params,
                    headers=headers,
                    timeout=10
                )
                
                if response.status_code == 200:
                    data = response.json()
                    for repo in data.get('items', []):
                        repo_info = {
                            'name': repo['full_name'],
                            'url': repo['html_url'],
                            'description': repo.get('description', ''),
                            'stars': repo.get('stargazers_count', 0),
                            'has_docker': self._check_has_dockerfile(repo['html_url']),
                            'query': query
                        }
                        
                        # 去重
                        if not any(r['url'] == repo_info['url'] for r in poc_repos):
                            poc_repos.append(repo_info)
                            print(f"  ✅ 找到: {repo['full_name']} ({repo_info['stars']} ⭐)")
                
            except Exception as e:
                print(f"  ⚠️ GitHub搜索失败 ({query}): {e}")
                continue
        
        # 如果API失败，提供搜索链接
        if not poc_repos:
            search_url = f"{self.GITHUB_SEARCH_URL}?q={cve_id}+poc"
            poc_repos.append({
                'name': 'Manual Search Required',
                'url': search_url,
                'description': f'手动搜索: {search_url}',
                'stars': 0,
                'has_docker': False
            })
        
        return poc_repos
    
    def search_docker_hub(self, product: str) -> List[Dict]:
        """搜索Docker Hub上的相关镜像"""
        images = []
        
        try:
            # 使用docker search命令
            cmd = ['docker', 'search', product, '--limit', '10', '--format', 'json']
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode == 0:
                # 解析JSON输出（每行一个JSON对象）
                for line in result.stdout.strip().split('\n'):
                    if line:
                        try:
                            img = json.loads(line)
                            images.append({
                                'name': img.get('Name', ''),
                                'description': img.get('Description', ''),
                                'stars': img.get('StarCount', 0),
                                'official': img.get('IsOfficial', False)
                            })
                            print(f"  ✅ 找到镜像: {img.get('Name')} ({img.get('StarCount', 0)} ⭐)")
                        except json.JSONDecodeError:
                            continue
            else:
                print(f"  ⚠️ docker search失败: {result.stderr}")
                
        except subprocess.TimeoutExpired:
            print(f"  ⚠️ docker search超时")
        except Exception as e:
            print(f"  ⚠️ Docker Hub搜索失败: {e}")
        
        return images
    
    def evaluate_mock_feasibility(self, cve_id: str, product: str, version: str) -> Tuple[bool, Optional[str]]:
        """评估是否能创建模拟环境
        
        Returns:
            (can_mock: bool, strategy: str)
        """
        # 从CVE ID提取信息
        cve_upper = cve_id.upper()
        
        # 简单Web漏洞模式
        simple_web_patterns = [
            'auth_bypass',
            'authentication bypass',
            'missing authentication',
            'unauthorized access',
            'sql injection',
            'xss',
            'path traversal',
            'file inclusion'
        ]
        
        # 检查产品类型
        web_products = ['nginx', 'apache', 'tomcat', 'iis', 'flask', 'django', 'php', 'wordpress']
        
        if product:
            product_lower = product.lower()
            
            # Web服务器/框架
            if any(wp in product_lower for wp in web_products):
                return True, 'web_framework'
            
            # API服务
            if 'api' in product_lower or 'rest' in product_lower:
                return True, 'api_service'
        
        # 默认不创建模拟环境（避免误判）
        return False, None
    
    def _check_has_dockerfile(self, repo_url: str) -> bool:
        """检查仓库是否包含Dockerfile"""
        try:
            # 尝试访问 Dockerfile
            raw_url = repo_url.replace('github.com', 'raw.githubusercontent.com')
            raw_url = raw_url + '/main/Dockerfile'  # 或 master
            
            response = requests.head(raw_url, timeout=5)
            return response.status_code == 200
        except:
            return False
    
    def recommend_action(self, search_results: Dict, confidence: float) -> Dict:
        """根据搜索结果推荐行动方案
        
        Args:
            search_results: search_all()的返回结果
            confidence: DeploymentAnalyzer的信心度
        
        Returns:
            {
                'action': str,  # 'use_poc' / 'use_similar_image' / 'create_mock' / 'manual_setup'
                'details': dict,
                'priority': int
            }
        """
        recommendations = []
        
        # 优先级1: 有Docker的PoC仓库
        docker_pocs = [p for p in search_results['poc_repos'] if p.get('has_docker')]
        if docker_pocs:
            recommendations.append({
                'action': 'use_poc',
                'details': docker_pocs[0],  # 选择星星最多的
                'priority': 1,
                'description': f"Found PoC repository with Dockerfile: {docker_pocs[0]['url']}"
            })
        
        # 优先级2: 有相关Docker镜像
        official_images = [img for img in search_results['docker_images'] if img.get('official')]
        if official_images:
            recommendations.append({
                'action': 'use_similar_image',
                'details': official_images[0],
                'priority': 2,
                'description': f"Found official Docker image: {official_images[0]['name']}"
            })
        elif search_results['docker_images']:
            recommendations.append({
                'action': 'use_similar_image',
                'details': search_results['docker_images'][0],
                'priority': 3,
                'description': f"Found community Docker image: {search_results['docker_images'][0]['name']}"
            })
        
        # 优先级3: 普通PoC仓库
        if search_results['poc_repos'] and not docker_pocs:
            recommendations.append({
                'action': 'use_poc',
                'details': search_results['poc_repos'][0],
                'priority': 4,
                'description': f"Found PoC repository (manual setup): {search_results['poc_repos'][0]['url']}"
            })
        
        # 优先级4: 创建模拟环境
        if search_results['can_mock'] and confidence < 0.5:
            recommendations.append({
                'action': 'create_mock',
                'details': {'strategy': search_results['mock_strategy']},
                'priority': 5,
                'description': f"Can create mock environment using {search_results['mock_strategy']} strategy"
            })
        
        # 优先级5: 手动设置
        recommendations.append({
            'action': 'manual_setup',
            'details': {},
            'priority': 6,
            'description': 'No automated solution found. Manual setup required from vendor documentation.'
        })
        
        # 按优先级排序，返回最佳方案
        recommendations.sort(key=lambda x: x['priority'])
        return recommendations[0] if recommendations else recommendations[-1]


# 快捷函数
def search_environment(cve_id: str, product: str = None) -> Dict:
    """快捷搜索函数"""
    engine = EnvironmentSearchEngine()
    return engine.search_all(cve_id, product)


def get_recommendation(cve_id: str, product: str, confidence: float) -> Dict:
    """获取环境部署推荐"""
    engine = EnvironmentSearchEngine()
    results = engine.search_all(cve_id, product)
    return engine.recommend_action(results, confidence)


# 测试代码
if __name__ == '__main__':
    print("=" * 60)
    print("环境搜索引擎测试")
    print("=" * 60)
    
    # 测试CVE-2025-26345
    results = search_environment('CVE-2025-26345', 'MaxTime')
    
    print("\n搜索结果:")
    print(f"  PoC仓库: {len(results['poc_repos'])}")
    print(f"  Docker镜像: {len(results['docker_images'])}")
    print(f"  可创建模拟: {results['can_mock']}")
    
    recommendation = get_recommendation('CVE-2025-26345', 'MaxTime', 0.3)
    print(f"\n推荐方案: {recommendation['action']}")
    print(f"  原因: {recommendation['reason']}")
