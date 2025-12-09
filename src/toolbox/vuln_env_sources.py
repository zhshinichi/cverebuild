"""
漏洞环境源集成 - Vulhub & Vulfocus

功能:
1. 检查Vulhub/Vulfocus是否有对应CVE的环境
2. 自动拉取并部署已有环境
3. 显著降低RepoBuilder失败率

优先级: Vulhub > Vulfocus > 自建环境
"""

import os
import json
import subprocess
import requests
from typing import Dict, Optional, List, Tuple
from pathlib import Path
import re


class VulnEnvSource:
    """漏洞环境源基类"""
    
    def __init__(self):
        self.name = "BaseSource"
        self.cache_dir = Path("/workspace/vuln_sources_cache")
        self.cache_dir.mkdir(parents=True, exist_ok=True)
    
    def has_env(self, cve_id: str) -> bool:
        """检查是否有该CVE的环境"""
        raise NotImplementedError
    
    def get_env_info(self, cve_id: str) -> Optional[Dict]:
        """获取环境信息"""
        raise NotImplementedError
    
    def deploy_env(self, cve_id: str, work_dir: str = "/tmp/vuln_env") -> Dict:
        """部署环境,返回部署结果"""
        raise NotImplementedError


class VulhubSource(VulnEnvSource):
    """
    Vulhub源 - https://github.com/vulhub/vulhub
    
    特点:
    - 400+ 漏洞环境
    - docker-compose一键部署
    - 社区维护,质量高
    """
    
    VULHUB_REPO = "https://github.com/vulhub/vulhub.git"
    VULHUB_API = "https://api.github.com/repos/vulhub/vulhub/contents"
    
    def __init__(self):
        super().__init__()
        self.name = "Vulhub"
        self.local_repo = self.cache_dir / "vulhub"
        self.index_cache = self.cache_dir / "vulhub_index.json"
        self._index = None
    
    def _ensure_repo_cloned(self) -> bool:
        """确保Vulhub仓库已克隆"""
        if self.local_repo.exists():
            print(f"[Vulhub] Repository already exists at {self.local_repo}")
            return True
        
        try:
            print(f"[Vulhub] Cloning repository...")
            subprocess.run(
                ["git", "clone", "--depth", "1", self.VULHUB_REPO, str(self.local_repo)],
                capture_output=True,
                text=True,
                check=True,
                timeout=300
            )
            print(f"[Vulhub] ✅ Repository cloned successfully")
            return True
        except Exception as e:
            print(f"[Vulhub] ❌ Failed to clone repository: {e}")
            return False
    
    def _build_index(self) -> Dict[str, List[str]]:
        """构建CVE到路径的索引"""
        if self._index:
            return self._index
        
        # 尝试从缓存加载
        if self.index_cache.exists():
            try:
                with open(self.index_cache, 'r') as f:
                    self._index = json.load(f)
                    print(f"[Vulhub] Loaded index with {len(self._index)} CVEs")
                    return self._index
            except:
                pass
        
        # 构建新索引
        if not self._ensure_repo_cloned():
            return {}
        
        print(f"[Vulhub] Building CVE index...")
        index = {}
        
        # 遍历vulhub目录结构
        for product_dir in self.local_repo.iterdir():
            if not product_dir.is_dir() or product_dir.name.startswith('.'):
                continue
            
            for vuln_dir in product_dir.iterdir():
                if not vuln_dir.is_dir():
                    continue
                
                # 检查是否有docker-compose.yml
                if (vuln_dir / "docker-compose.yml").exists():
                    # 从目录名或README提取CVE
                    cves = self._extract_cves_from_path(vuln_dir)
                    
                    relative_path = vuln_dir.relative_to(self.local_repo)
                    for cve in cves:
                        if cve not in index:
                            index[cve] = []
                        index[cve].append(str(relative_path))
        
        # 保存缓存
        with open(self.index_cache, 'w') as f:
            json.dump(index, f, indent=2)
        
        self._index = index
        print(f"[Vulhub] ✅ Index built: {len(index)} CVEs")
        return index
    
    def _extract_cves_from_path(self, vuln_dir: Path) -> List[str]:
        """从路径和README中提取CVE编号"""
        cves = []
        
        # 1. 从目录名提取
        dir_name = vuln_dir.name
        cve_pattern = r'CVE-\d{4}-\d+|cve-\d{4}-\d+'
        matches = re.findall(cve_pattern, dir_name, re.IGNORECASE)
        cves.extend([m.upper() for m in matches])
        
        # 2. 从README提取
        readme_files = ['README.md', 'README.zh-cn.md', 'readme.md']
        for readme_name in readme_files:
            readme_path = vuln_dir / readme_name
            if readme_path.exists():
                try:
                    content = readme_path.read_text(encoding='utf-8')
                    matches = re.findall(cve_pattern, content, re.IGNORECASE)
                    cves.extend([m.upper() for m in matches])
                except:
                    pass
        
        return list(set(cves))  # 去重
    
    def has_env(self, cve_id: str) -> bool:
        """检查Vulhub是否有该CVE"""
        index = self._build_index()
        return cve_id.upper() in index
    
    def get_env_info(self, cve_id: str) -> Optional[Dict]:
        """获取Vulhub环境信息"""
        index = self._build_index()
        cve_id = cve_id.upper()
        
        if cve_id not in index:
            return None
        
        paths = index[cve_id]
        primary_path = paths[0]  # 使用第一个匹配
        
        full_path = self.local_repo / primary_path
        
        return {
            'source': 'Vulhub',
            'cve_id': cve_id,
            'path': str(full_path),
            'relative_path': primary_path,
            'docker_compose': str(full_path / "docker-compose.yml"),
            'has_readme': (full_path / "README.md").exists(),
            'alternative_paths': paths[1:] if len(paths) > 1 else []
        }
    
    def deploy_env(self, cve_id: str, work_dir: str = "/tmp/vuln_env") -> Dict:
        """部署Vulhub环境"""
        env_info = self.get_env_info(cve_id)
        if not env_info:
            return {'success': False, 'error': 'Environment not found'}
        
        try:
            compose_file = env_info['docker_compose']
            env_path = env_info['path']
            
            print(f"[Vulhub] 🚀 Deploying {cve_id} from {env_info['relative_path']}")
            
            # 1. 切换到环境目录
            os.chdir(env_path)
            
            # 2. 拉取镜像
            print(f"[Vulhub] 📦 Pulling Docker images...")
            subprocess.run(
                ["docker-compose", "pull"],
                capture_output=True,
                text=True,
                timeout=600
            )
            
            # 3. 启动环境
            print(f"[Vulhub] 🔧 Starting containers...")
            result = subprocess.run(
                ["docker-compose", "up", "-d"],
                capture_output=True,
                text=True,
                check=True,
                timeout=300
            )
            
            # 4. 获取容器信息
            containers = subprocess.run(
                ["docker-compose", "ps", "--format", "json"],
                capture_output=True,
                text=True
            )
            
            print(f"[Vulhub] ✅ Environment deployed successfully!")
            
            return {
                'success': True,
                'source': 'Vulhub',
                'cve_id': cve_id,
                'env_path': env_path,
                'containers': containers.stdout,
                'deployment_method': 'docker-compose',
                'readme_path': str(Path(env_path) / "README.md") if env_info['has_readme'] else None
            }
            
        except subprocess.TimeoutExpired:
            return {'success': False, 'error': 'Deployment timeout'}
        except subprocess.CalledProcessError as e:
            return {'success': False, 'error': f'Docker compose failed: {e.stderr}'}
        except Exception as e:
            return {'success': False, 'error': str(e)}


class VulfocusSource(VulnEnvSource):
    """
    Vulfocus源 - https://github.com/fofapro/vulfocus
    
    特点:
    - 中文社区维护
    - 最新CVE覆盖快
    - Docker镜像形式
    """
    
    VULFOCUS_IMAGES_API = "https://registry.hub.docker.com/v2/repositories/vulfocus/*/tags"
    VULFOCUS_REGISTRY = "docker.io/vulfocus"
    
    # 已知的Vulfocus镜像前缀
    KNOWN_PREFIXES = [
        "vulfocus",
        "vulhub"  # Vulfocus也包含vulhub镜像
    ]
    
    def __init__(self):
        super().__init__()
        self.name = "Vulfocus"
        self.index_cache = self.cache_dir / "vulfocus_index.json"
        self._index = None
    
    def _build_index(self) -> Dict[str, Dict]:
        """构建Vulfocus镜像索引"""
        if self._index:
            return self._index
        
        # 尝试从缓存加载
        if self.index_cache.exists():
            try:
                with open(self.index_cache, 'r') as f:
                    self._index = json.load(f)
                    print(f"[Vulfocus] Loaded index with {len(self._index)} images")
                    return self._index
            except:
                pass
        
        print(f"[Vulfocus] Building image index from Docker Hub...")
        index = {}
        
        try:
            # 查询vulfocus组织的镜像
            response = requests.get(
                "https://hub.docker.com/v2/repositories/vulfocus/",
                params={'page_size': 100},
                timeout=30
            )
            
            if response.status_code == 200:
                data = response.json()
                for repo in data.get('results', []):
                    repo_name = repo['name']
                    
                    # 尝试从镜像名提取CVE
                    cve_pattern = r'cve[-_](\d{4})[-_](\d+)'
                    match = re.search(cve_pattern, repo_name, re.IGNORECASE)
                    
                    if match:
                        cve_id = f"CVE-{match.group(1)}-{match.group(2)}"
                        index[cve_id] = {
                            'image': f"vulfocus/{repo_name}",
                            'name': repo_name,
                            'description': repo.get('description', ''),
                            'stars': repo.get('star_count', 0)
                        }
        except Exception as e:
            print(f"[Vulfocus] ⚠️ Failed to fetch from Docker Hub: {e}")
        
        # 保存缓存
        if index:
            with open(self.index_cache, 'w') as f:
                json.dump(index, f, indent=2)
            self._index = index
            print(f"[Vulfocus] ✅ Index built: {len(index)} images")
        
        return index or {}
    
    def has_env(self, cve_id: str) -> bool:
        """检查Vulfocus是否有该CVE镜像"""
        index = self._build_index()
        return cve_id.upper() in index
    
    def get_env_info(self, cve_id: str) -> Optional[Dict]:
        """获取Vulfocus镜像信息"""
        index = self._build_index()
        cve_id = cve_id.upper()
        
        if cve_id not in index:
            return None
        
        image_info = index[cve_id]
        return {
            'source': 'Vulfocus',
            'cve_id': cve_id,
            'image': image_info['image'],
            'description': image_info.get('description', ''),
            'stars': image_info.get('stars', 0)
        }
    
    def deploy_env(self, cve_id: str, work_dir: str = "/tmp/vuln_env") -> Dict:
        """部署Vulfocus镜像"""
        env_info = self.get_env_info(cve_id)
        if not env_info:
            return {'success': False, 'error': 'Image not found'}
        
        try:
            image_name = env_info['image']
            
            print(f"[Vulfocus] 🚀 Deploying {cve_id} from {image_name}")
            
            # 1. 拉取镜像
            print(f"[Vulfocus] 📦 Pulling Docker image...")
            subprocess.run(
                ["docker", "pull", image_name],
                capture_output=True,
                text=True,
                check=True,
                timeout=600
            )
            
            # 2. 启动容器
            print(f"[Vulfocus] 🔧 Starting container...")
            container_name = f"vulfocus_{cve_id.lower().replace('-', '_')}"
            
            result = subprocess.run(
                ["docker", "run", "-d", "--name", container_name, 
                 "-P",  # 自动映射所有暴露端口
                 image_name],
                capture_output=True,
                text=True,
                check=True
            )
            
            container_id = result.stdout.strip()
            
            # 3. 获取端口映射
            port_info = subprocess.run(
                ["docker", "port", container_id],
                capture_output=True,
                text=True
            )
            
            print(f"[Vulfocus] ✅ Container started: {container_id[:12]}")
            print(f"[Vulfocus] 🌐 Port mappings:\n{port_info.stdout}")
            
            return {
                'success': True,
                'source': 'Vulfocus',
                'cve_id': cve_id,
                'image': image_name,
                'container_id': container_id,
                'container_name': container_name,
                'ports': port_info.stdout,
                'deployment_method': 'docker-run'
            }
            
        except subprocess.TimeoutExpired:
            return {'success': False, 'error': 'Deployment timeout'}
        except subprocess.CalledProcessError as e:
            return {'success': False, 'error': f'Docker failed: {e.stderr}'}
        except Exception as e:
            return {'success': False, 'error': str(e)}


class VulnEnvManager:
    """漏洞环境管理器 - 统一接口"""
    
    def __init__(self):
        self.sources = [
            VulhubSource(),
            VulfocusSource()
        ]
    
    def find_env(self, cve_id: str) -> Optional[Tuple[VulnEnvSource, Dict]]:
        """
        查找CVE环境
        
        返回: (源对象, 环境信息) 或 None
        """
        cve_id = cve_id.upper()
        
        for source in self.sources:
            if source.has_env(cve_id):
                env_info = source.get_env_info(cve_id)
                if env_info:
                    print(f"[VulnEnvManager] ✅ Found {cve_id} in {source.name}")
                    return source, env_info
        
        print(f"[VulnEnvManager] ❌ {cve_id} not found in any source")
        return None
    
    def deploy_env(self, cve_id: str, work_dir: str = "/tmp/vuln_env") -> Dict:
        """
        自动部署CVE环境
        
        返回部署结果字典
        """
        result = self.find_env(cve_id)
        
        if not result:
            return {
                'success': False,
                'error': 'No pre-built environment found',
                'fallback_to_custom': True
            }
        
        source, env_info = result
        
        print(f"\n{'='*60}")
        print(f"🎯 Using {env_info['source']} for {cve_id}")
        print(f"{'='*60}\n")
        
        return source.deploy_env(cve_id, work_dir)
    
    def get_statistics(self) -> Dict:
        """获取各源的统计信息"""
        stats = {}
        
        for source in self.sources:
            if hasattr(source, '_build_index'):
                index = source._build_index()
                stats[source.name] = {
                    'available_cves': len(index),
                    'source_type': source.__class__.__name__
                }
        
        return stats


# 测试代码
if __name__ == "__main__":
    print("=== Vuln Environment Sources Integration Test ===\n")
    
    manager = VulnEnvManager()
    
    # 测试CVE
    test_cves = [
        "CVE-2017-12615",  # Tomcat - 应该在Vulhub
        "CVE-2021-44228",  # Log4j - 应该在两个源都有
        "CVE-2025-10390",  # CRMEB - 可能没有
    ]
    
    for cve in test_cves:
        print(f"\n[Test] Checking {cve}...")
        result = manager.find_env(cve)
        if result:
            source, info = result
            print(f"  ✅ Found in {source.name}")
            print(f"  Info: {json.dumps(info, indent=4, ensure_ascii=False)}")
        else:
            print(f"  ❌ Not found - will use custom RepoBuilder")
    
    # 统计信息
    print("\n" + "="*60)
    print("Statistics:")
    stats = manager.get_statistics()
    print(json.dumps(stats, indent=2, ensure_ascii=False))
    print("="*60)
