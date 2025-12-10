"""Docker Vulnerability Registry: 扩展VulnEnvManager支持更多预构建环境

功能：
1. DVWA (Damn Vulnerable Web Application)
2. WebGoat
3. 按CVE命名的镜像 (hmlio/vaas-cve-*)
4. 经典漏洞靶机镜像

数据来源：
- Awesome-Pentest Docker for Penetration Testing
- HMLIO CVE镜像集合
- OWASP教学靶场
"""

from typing import Dict, Optional, List
import json
import os


class DockerVulnRegistry:
    """Docker漏洞环境注册表"""
    
    # 静态CVE到镜像映射表
    CVE_IMAGE_MAP = {
        # Shellshock
        'CVE-2014-6271': {
            'image': 'hmlio/vaas-cve-2014-6271',
            'name': 'Shellshock Bash RCE',
            'ports': {'80/tcp': 8080}
        },
        # Heartbleed
        'CVE-2014-0160': {
            'image': 'hmlio/vaas-cve-2014-0160',
            'name': 'Heartbleed OpenSSL',
            'ports': {'443/tcp': 8443}
        },
        # Struts2
        'CVE-2017-5638': {
            'image': 'piesecurity/apache-struts2-cve-2017-5638',
            'name': 'Apache Struts2 RCE',
            'ports': {'8080/tcp': 8080}
        },
        # ImageTragick
        'CVE-2016-3714': {
            'image': 'vulhub/imagemagick:7.0.1-0',
            'name': 'ImageMagick RCE',
            'ports': {'80/tcp': 8080}
        },
        # Spring4Shell
        'CVE-2022-22965': {
            'image': 'vulfocus/spring-core-rce-2022-22965',
            'name': 'Spring4Shell RCE',
            'ports': {'8080/tcp': 8080}
        },
        # Log4Shell
        'CVE-2021-44228': {
            'image': 'vulfocus/log4j2-rce',
            'name': 'Log4Shell RCE',
            'ports': {'8080/tcp': 8080}
        },
        # Tomcat PUT上传
        'CVE-2017-12615': {
            'image': 'vulhub/tomcat:8.5.19',
            'name': 'Tomcat PUT Upload',
            'ports': {'8080/tcp': 8080}
        },
        # Redis未授权
        'CVE-2015-8545': {
            'image': 'vulhub/redis:4.0.14',
            'name': 'Redis Unauth Access',
            'ports': {'6379/tcp': 6379}
        },
    }
    
    # 教学靶场映射（用于学习和测试）
    TRAINING_LABS = {
        'DVWA': {
            'image': 'vulnerables/web-dvwa',
            'name': 'Damn Vulnerable Web Application',
            'ports': {'80/tcp': 8080},
            'env': {'MYSQL_PASS': 'dvwa'}
        },
        'WebGoat': {
            'image': 'webgoat/webgoat-8.0',
            'name': 'OWASP WebGoat',
            'ports': {'8080/tcp': 8080, '9090/tcp': 9090}
        },
        'Mutillidae': {
            'image': 'citizenstig/nowasp',
            'name': 'Mutillidae II',
            'ports': {'80/tcp': 8080}
        },
        'bWAPP': {
            'image': 'raesene/bwapp',
            'name': 'buggy Web Application',
            'ports': {'80/tcp': 8080}
        },
        'VulnerableWordPress': {
            'image': 'wpscanteam/vulnerablewordpress',
            'name': 'Vulnerable WordPress',
            'ports': {'80/tcp': 8080, '3306/tcp': 3306}
        }
    }
    
    def __init__(self):
        self.cache_dir = os.path.join(os.getcwd(), 'vuln_sources_cache', 'docker_registry')
        os.makedirs(self.cache_dir, exist_ok=True)
    
    def find_by_cve(self, cve_id: str) -> Optional[Dict]:
        """根据CVE ID查找预构建镜像
        
        Returns:
            {
                'source': 'docker_registry',
                'image': str,
                'name': str,
                'ports': dict,
                'env': dict (optional)
            }
        """
        cve_upper = cve_id.upper()
        
        if cve_upper in self.CVE_IMAGE_MAP:
            env_info = self.CVE_IMAGE_MAP[cve_upper].copy()
            env_info['source'] = 'docker_registry'
            env_info['cve_id'] = cve_upper
            return env_info
        
        return None
    
    def find_by_name(self, name: str) -> Optional[Dict]:
        """根据靶场名称查找
        
        Args:
            name: 'DVWA', 'WebGoat', 'Mutillidae' 等
        """
        name_upper = name.upper()
        
        if name_upper in self.TRAINING_LABS:
            env_info = self.TRAINING_LABS[name_upper].copy()
            env_info['source'] = 'docker_registry'
            return env_info
        
        return None
    
    def list_available_cves(self) -> List[str]:
        """列出所有可用的CVE"""
        return list(self.CVE_IMAGE_MAP.keys())
    
    def list_training_labs(self) -> List[str]:
        """列出所有教学靶场"""
        return list(self.TRAINING_LABS.keys())
    
    def deploy(self, env_info: Dict) -> Dict:
        """部署Docker镜像
        
        Args:
            env_info: find_by_cve() 或 find_by_name() 返回的信息
        
        Returns:
            {
                'success': bool,
                'container_id': str,
                'container_name': str,
                'ports': dict,
                'access_url': str
            }
        """
        import subprocess
        import random
        
        image = env_info['image']
        ports_map = env_info.get('ports', {})
        env_vars = env_info.get('env', {})
        
        # 生成容器名
        container_name = f"vuln_{env_info.get('cve_id', 'lab')}_{random.randint(1000, 9999)}"
        
        # 构建docker run命令
        cmd = ['docker', 'run', '-d', '--name', container_name]
        
        # 添加端口映射
        for container_port, host_port in ports_map.items():
            cmd.extend(['-p', f'{host_port}:{container_port.split("/")[0]}'])
        
        # 添加环境变量
        for key, value in env_vars.items():
            cmd.extend(['-e', f'{key}={value}'])
        
        # 镜像名
        cmd.append(image)
        
        try:
            # 先尝试拉取镜像
            print(f"[DockerRegistry] Pulling image: {image}")
            pull_result = subprocess.run(
                ['docker', 'pull', image],
                capture_output=True,
                text=True,
                timeout=300
            )
            
            if pull_result.returncode != 0:
                return {
                    'success': False,
                    'error': f'Failed to pull image: {pull_result.stderr}'
                }
            
            # 运行容器
            print(f"[DockerRegistry] Starting container: {container_name}")
            run_result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if run_result.returncode != 0:
                return {
                    'success': False,
                    'error': f'Failed to start container: {run_result.stderr}'
                }
            
            container_id = run_result.stdout.strip()
            
            # 获取主要访问端口
            main_port = list(ports_map.values())[0] if ports_map else 8080
            access_url = f"http://localhost:{main_port}"
            
            return {
                'success': True,
                'container_id': container_id,
                'container_name': container_name,
                'ports': ports_map,
                'access_url': access_url,
                'image': image
            }
            
        except subprocess.TimeoutExpired:
            return {
                'success': False,
                'error': 'Docker operation timeout'
            }
        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }
    
    def stop(self, container_name: str) -> bool:
        """停止并删除容器"""
        import subprocess
        
        try:
            subprocess.run(['docker', 'stop', container_name], timeout=30)
            subprocess.run(['docker', 'rm', container_name], timeout=30)
            return True
        except:
            return False
    
    def get_stats(self) -> Dict:
        """获取统计信息"""
        return {
            'cve_count': len(self.CVE_IMAGE_MAP),
            'training_labs_count': len(self.TRAINING_LABS),
            'total_environments': len(self.CVE_IMAGE_MAP) + len(self.TRAINING_LABS)
        }


# 测试代码
if __name__ == '__main__':
    registry = DockerVulnRegistry()
    
    print("📦 Docker Vulnerability Registry")
    print("=" * 50)
    
    stats = registry.get_stats()
    print(f"Available CVEs: {stats['cve_count']}")
    print(f"Training Labs: {stats['training_labs_count']}")
    print()
    
    print("CVE Environments:")
    for cve in registry.list_available_cves()[:5]:
        print(f"  - {cve}")
    print()
    
    print("Training Labs:")
    for lab in registry.list_training_labs():
        print(f"  - {lab}")
    print()
    
    # 测试查找
    test_cve = 'CVE-2014-6271'
    result = registry.find_by_cve(test_cve)
    if result:
        print(f"✅ Found {test_cve}: {result['name']}")
        print(f"   Image: {result['image']}")
