"""
DeploymentStrategyAnalyzer - 部署策略分析器

功能：
1. 读取 CVE 原始数据（从 cvelist/ 目录）
2. 分析软件类型和部署方式
3. 提取 GitHub/源码仓库信息
4. 生成具体的部署指南

输出：deployment_strategy 字典，包含：
- strategy_type: "source_code" | "docker_image" | "package_manager" | "hardware" | "unknown"
- confidence: 0.0-1.0
- repository_url: GitHub/GitLab URL（如果有）
- build_commands: 构建命令列表
- start_commands: 启动命令列表
- deployment_notes: 具体部署注意事项
"""

import json
import os
import re
from typing import Dict, Any, Optional, List
import sys

# 导入产品仓库映射表
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from toolbox.product_repository_mapping import get_repository_by_product


def get_cve_file_path(cve_id: str) -> str:
    """
    根据 CVE ID 计算文件路径
    
    例如：
    - CVE-2025-55007 → src/data/cvelist/2025/55xxx/CVE-2025-55007.json
    - CVE-2025-1225 → src/data/cvelist/2025/1xxx/CVE-2025-1225.json
    - CVE-2024-34117 → src/data/cvelist/2024/34xxx/CVE-2024-34117.json
    """
    match = re.match(r'CVE-(\d{4})-(\d+)', cve_id, re.IGNORECASE)
    if not match:
        raise ValueError(f"Invalid CVE ID format: {cve_id}")
    
    year = match.group(1)
    number = int(match.group(2))
    
    # 计算目录（按千位分组）
    folder = f"{(number // 1000)}xxx"
    
    base_dir = "/workspaces/submission/src/data/cvelist"
    # 使用正斜杠拼接（Linux 容器环境）
    file_path = f"{base_dir}/{year}/{folder}/{cve_id.upper()}.json"
    
    return file_path


def load_cve_data(cve_id: str) -> Optional[Dict]:
    """加载 CVE 原始数据"""
    try:
        file_path = get_cve_file_path(cve_id)
        if not os.path.exists(file_path):
            print(f"[DeploymentAnalyzer] CVE file not found: {file_path}")
            return None
        
        with open(file_path, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception as e:
        print(f"[DeploymentAnalyzer] Error loading CVE data: {e}")
        return None


def extract_github_urls(cve_data: Dict) -> List[str]:
    """从 CVE 数据中提取所有 GitHub/GitLab/Gitee URL（排除exploit链接）"""
    urls = []
    
    # 从 references 中提取
    try:
        refs = cve_data.get('containers', {}).get('cna', {}).get('references', [])
        for ref in refs:
            url = ref.get('url', '')
            tags = ref.get('tags', [])
            
            # ✅ 过滤掉 exploit POC 链接
            if 'exploit' in tags:
                continue
            
            if any(domain in url for domain in ['github.com', 'gitlab.com', 'gitee.com']):
                urls.append(url)
    except:
        pass
    
    # 从 affected 中提取（有时 vendor 字段包含 URL）
    try:
        affected = cve_data.get('containers', {}).get('cna', {}).get('affected', [])
        for item in affected:
            vendor = item.get('vendor', '')
            if any(domain in vendor for domain in ['github.com', 'gitlab.com', 'gitee.com']):
                urls.append(vendor)
    except:
        pass
    
    return urls


def infer_repository_from_github_urls(github_urls: List[str]) -> Optional[str]:
    """从 GitHub/GitLab/Gitee URL 推断源码仓库"""
    for url in github_urls:
        # 匹配 github.com/owner/repo 格式
        match = re.search(r'(github|gitlab|gitee)\.com/([^/]+)/([^/]+)', url)
        if match:
            platform, owner, repo = match.groups()
            # 移除可能的 .git 后缀
            repo = repo.replace('.git', '')
            # 如果是 security advisory，提取真实仓库名
            if 'security/advisories' in url:
                return f"https://{platform}.com/{owner}/{repo}"
            # 如果是 issues/pull/commit，也是有效的仓库
            if any(x in url for x in ['/issues/', '/pull/', '/commit/', '/releases/', '/archive/', '/blob/', '/tree/']):
                return f"https://{platform}.com/{owner}/{repo}"
    
    return None


def infer_deployment_strategy(cve_data: Dict, cve_description: str) -> Dict[str, Any]:
    """
    分析 CVE 数据，推断部署策略
    
    返回：
    {
        "strategy_type": "source_code" | "docker_image" | "hardware" | "unknown",
        "confidence": 0.0-1.0,
        "repository_url": "https://github.com/...",
        "product_name": "mlflow",
        "vendor": "MLFlow Project",
        "language": "python" | "java" | "javascript" | "go" | ...,
        "build_tool": "maven" | "npm" | "pip" | "go" | ...,
        "build_commands": ["mvn clean package", ...],
        "start_commands": ["java -jar target/app.jar", ...],
        "deployment_notes": "...",
        "is_hardware": false,
        "hardware_type": "" | "router" | "iot" | ...
    }
    """
    
    result = {
        "strategy_type": "unknown",
        "confidence": 0.0,
        "repository_url": None,
        "product_name": None,
        "vendor": None,
        "language": None,
        "build_tool": None,
        "build_commands": [],
        "start_commands": [],
        "deployment_notes": "",
        "is_hardware": False,
        "hardware_type": ""
    }
    
    # 提取基本信息
    try:
        cna = cve_data.get('containers', {}).get('cna', {})
        affected = cna.get('affected', [])
        if affected:
            result['product_name'] = affected[0].get('product', '')
            result['vendor'] = affected[0].get('vendor', '')
    except:
        pass
    
    # 1. 检查是否是硬件设备
    hardware_keywords = ['router', 'firmware', 'iot', 'embedded', 'device', 'gateway', 'modem', 'switch']
    desc_lower = cve_description.lower()
    
    for keyword in hardware_keywords:
        if keyword in desc_lower or (result['product_name'] and keyword in result['product_name'].lower()):
            result['is_hardware'] = True
            result['hardware_type'] = keyword
            result['strategy_type'] = 'hardware'
            result['confidence'] = 0.9
            result['deployment_notes'] = f"这是硬件设备漏洞（{keyword}），无法使用 Docker 或源码部署模拟。需要 QEMU 固件模拟或真实硬件。"
            return result
    
    # 2. 提取 GitHub/GitLab/Gitee 仓库
    github_urls = extract_github_urls(cve_data)
    repo_url = infer_repository_from_github_urls(github_urls)
    
    # 【关键改进】如果 references 中没有源码仓库，尝试通过产品名映射查找
    if not repo_url and result['product_name']:
        print(f"[DeploymentAnalyzer] No repo in references, trying product mapping for '{result['product_name']}'...")
        mapping = get_repository_by_product(result['product_name'])
        if mapping:
            repo_url = mapping['repo_url']
            result['language'] = mapping.get('language')
            result['build_tool'] = mapping.get('build_tool')
            result['php_version'] = mapping.get('php_version')
            result['required_extensions'] = mapping.get('required_extensions', [])
            result['working_directory'] = mapping.get('working_directory')
            result['deployment_type'] = mapping.get('deployment_type', 'source_code')
            result['docker_compose_path'] = mapping.get('docker_compose_path')
            default_port = mapping.get('default_port')
            print(f"[DeploymentAnalyzer] ✅ Found mapping: {repo_url}")
            
            # 构建详细的部署说明
            notes = []
            if result['deployment_type'] == 'docker-compose':
                notes.append(f"⚠️ 推荐使用官方 docker-compose 部署（路径: {result['docker_compose_path']}）")
            if result['php_version']:
                notes.append(f"需要 PHP {result['php_version']}（不兼容 PHP 8+）")
            if result['working_directory']:
                notes.append(f"工作目录: {result['working_directory']}/（composer.json 在子目录）")
            if result['required_extensions']:
                notes.append(f"必需扩展: {', '.join(result['required_extensions'][:5])}")
            if default_port:
                notes.append(f"默认端口: {default_port}")
            
            result['deployment_notes'] = ' | '.join(notes) if notes else f"从产品映射表获取仓库"
        else:
            print(f"[DeploymentAnalyzer] ⚠️ No mapping found for '{result['product_name']}'")
    
    if repo_url:
        result['repository_url'] = repo_url
        result['strategy_type'] = 'source_code'
        result['confidence'] = 0.8
        
        # 3. 推断编程语言和构建工具
        # 从文件路径推断（如果CVE描述中包含）
        product_lower = (result['product_name'] or '').lower()
        
        if '.java' in cve_description or 'maven' in desc_lower or 'spring' in desc_lower or \
           '.jar' in cve_description or 'pom.xml' in cve_description:
            result['language'] = 'java'
            result['build_tool'] = 'maven'
            result['build_commands'] = [
                f"git clone {repo_url}",
                f"cd $(basename {repo_url})",
                "mvn clean package -DskipTests"
            ]
            result['start_commands'] = [
                "java -jar target/*.jar --server.port=8080"
            ]
        
        elif '.py' in cve_description or 'python' in desc_lower or 'flask' in desc_lower or \
             'django' in desc_lower or 'pip' in cve_description or 'requirements.txt' in cve_description or \
             any(fw in product_lower for fw in ['mlflow', 'lollms', 'streamlit', 'gradio', 'fastapi']):
            result['language'] = 'python'
            result['build_tool'] = 'pip'
            result['build_commands'] = [
                f"git clone {repo_url}",
                f"cd $(basename {repo_url})",
                "pip install -r requirements.txt || pip install -e ."
            ]
            # 根据产品类型推断启动命令
            if 'mlflow' in product_lower:
                result['start_commands'] = ["mlflow server --host 0.0.0.0 --port 5000"]
            elif 'streamlit' in product_lower:
                result['start_commands'] = ["streamlit run app.py --server.port 8501"]
            elif 'gradio' in product_lower:
                result['start_commands'] = ["python app.py"]
            elif 'django' in desc_lower:
                result['start_commands'] = ["python manage.py runserver 0.0.0.0:8000"]
            elif 'flask' in desc_lower:
                result['start_commands'] = ["flask run --host=0.0.0.0 --port=5000"]
            else:
                result['start_commands'] = ["python app.py  # 或 flask run / python manage.py runserver"]
        
        elif '.js' in cve_description or 'node' in desc_lower or 'npm' in desc_lower or \
             'javascript' in desc_lower or 'package.json' in cve_description or 'express' in desc_lower:
            result['language'] = 'javascript'
            result['build_tool'] = 'npm'
            result['build_commands'] = [
                f"git clone {repo_url}",
                f"cd $(basename {repo_url})",
                "npm install"
            ]
            result['start_commands'] = [
                "npm start  # 或 node server.js / node index.js"
            ]
        
        elif '.go' in cve_description or 'golang' in desc_lower or 'go.mod' in cve_description:
            result['language'] = 'go'
            result['build_tool'] = 'go'
            result['build_commands'] = [
                f"git clone {repo_url}",
                f"cd $(basename {repo_url})",
                "go build -o app ."
            ]
            result['start_commands'] = [
                "./app"
            ]
        
        elif '.php' in cve_description or 'php' in desc_lower or 'composer' in desc_lower:
            result['language'] = result.get('language') or 'php'
            result['build_tool'] = result.get('build_tool') or 'composer'
            
            # 检查是否有工作目录配置（如CRMEB）
            working_dir = result.get('working_directory')
            repo_name = "$(basename {})".format(repo_url)
            
            if working_dir:
                # composer.json在子目录
                result['build_commands'] = [
                    f"git clone {repo_url}",
                    f"cd {repo_name}/{working_dir}",
                    "composer install"
                ]
            else:
                # 标准结构
                result['build_commands'] = [
                    f"git clone {repo_url}",
                    f"cd {repo_name}",
                    "composer install"
                ]
            
            # 检查是否建议docker-compose
            if result.get('deployment_type') == 'docker-compose':
                docker_path = result.get('docker_compose_path', 'docker-compose')
                result['start_commands'] = [
                    f"# 推荐: cd {repo_name}/{docker_path} && docker-compose up -d",
                    f"# 或手动: php -S 0.0.0.0:8000 -t public"
                ]
            else:
                result['start_commands'] = [
                    "php -S 0.0.0.0:8000 -t public  # 或使用 Apache/Nginx"
                ]
        
        # 只有在deployment_notes为空时才设置默认值（避免覆盖产品映射的详细说明）
        if not result.get('deployment_notes'):
            result['deployment_notes'] = f"从 {'GitHub/GitLab/Gitee' if any(x in repo_url for x in ['gitlab', 'gitee']) else 'GitHub'} 源码部署。语言: {result['language'] or '未知'}, 构建工具: {result['build_tool'] or '未知'}"
        
    else:
        # 没有找到 GitHub 仓库
        result['confidence'] = 0.3
        result['deployment_notes'] = "未找到公开的源码仓库。可能需要从软件官网下载或使用 Docker Hub 镜像（如果存在）。"
    
    return result


class DeploymentStrategyAnalyzer:
    """
    部署策略分析器 - 不使用 LLM，纯规则推断
    
    输入：
    - cve_id: CVE ID
    - cve_description: CVE 描述（可选）
    
    输出：
    - deployment_strategy: 部署策略字典
    """
    
    def __init__(self, cve_id: str, cve_description: str = "", **kwargs):
        self.cve_id = cve_id
        self.cve_description = cve_description
    
    def invoke(self, *args, **kwargs) -> dict:
        """执行分析"""
        print(f"[DeploymentAnalyzer] Analyzing {self.cve_id}...")
        
        # 1. 加载 CVE 原始数据
        cve_data = load_cve_data(self.cve_id)
        if not cve_data:
            return {
                "strategy_type": "unknown",
                "confidence": 0.0,
                "deployment_notes": f"无法加载 CVE 数据文件"
            }
        
        # 2. 推断部署策略
        strategy = infer_deployment_strategy(cve_data, self.cve_description)
        
        print(f"[DeploymentAnalyzer] Strategy: {strategy['strategy_type']} (confidence: {strategy['confidence']})")
        if strategy['repository_url']:
            print(f"[DeploymentAnalyzer] Repository: {strategy['repository_url']}")
        print(f"[DeploymentAnalyzer] Notes: {strategy['deployment_notes']}")
        
        return strategy


# 测试代码
if __name__ == "__main__":
    # 测试 CVE-2025-55007 (Knowage-Server - 应该找到 GitHub 仓库)
    analyzer1 = DeploymentStrategyAnalyzer(
        cve_id="CVE-2025-55007",
        cve_description="Knowage is an open source analytics suite vulnerable to SSRF"
    )
    result1 = analyzer1.invoke()
    print(json.dumps(result1, indent=2))
    
    print("\n" + "="*60 + "\n")
    
    # 测试 CVE-2025-1225 (ywoa - Java XXE)
    analyzer2 = DeploymentStrategyAnalyzer(
        cve_id="CVE-2025-1225",
        cve_description="ywoa XXE in c-main/src/main/java/com/redmoon/weixin/aes/XMLParse.java"
    )
    result2 = analyzer2.invoke()
    print(json.dumps(result2, indent=2))
