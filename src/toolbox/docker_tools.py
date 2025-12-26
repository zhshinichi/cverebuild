"""
Docker镜像查询工具
用于在RepoBuilder中优先查找官方Docker镜像，避免从源码编译
"""
import subprocess
import json
import re
from typing import Optional, List, Dict
from agentlib.lib import tools


@tools.tool
def search_docker_hub(project_name: str, version: str = None) -> str:
    """
    Search Docker Hub for official or community images of a project.
    
    **When to use:**
    - BEFORE attempting to build from source
    - For well-known projects (Qdrant, Redis, Jenkins, PostgreSQL, etc.)
    - When CVE specifies a version number
    
    **Priority:**
    1. Official images (e.g., `qdrant/qdrant`, `jenkins/jenkins`)
    2. Community images with high star count
    3. If not found, proceed to source build
    
    **Example:**
    - search_docker_hub("qdrant", "v1.8.4") → "qdrant/qdrant:v1.8.4"
    - search_docker_hub("jenkins", "2.441") → "jenkins/jenkins:2.441"
    
    :param project_name: Name of the project (e.g., 'qdrant', 'jenkins', 'redis')
    :param version: Specific version to look for (optional)
    :return: Detailed information about available images or guidance
    """
    try:
        # 标准化项目名称
        normalized_name = project_name.lower().strip()
        
        # 常见官方镜像映射
        OFFICIAL_IMAGE_MAP = {
            'qdrant': 'qdrant/qdrant',
            'jenkins': 'jenkins/jenkins',
            'redis': 'redis',
            'postgresql': 'postgres',
            'mysql': 'mysql',
            'nginx': 'nginx',
            'mongodb': 'mongo',
            'elasticsearch': 'elasticsearch',
            'rabbitmq': 'rabbitmq',
            'tomcat': 'tomcat',
            'wordpress': 'wordpress',
            'gitlab': 'gitlab/gitlab-ce',
            'nexus': 'sonatype/nexus3',
            'sonarqube': 'sonarqube',
            'minio': 'minio/minio',
            'grafana': 'grafana/grafana',
            'prometheus': 'prom/prometheus',
            'vault': 'vault',
            'consul': 'consul',
            'traefik': 'traefik',
            'caddy': 'caddy',
            'git': 'bitnami/git',
            'httpd': 'httpd',
            'apache': 'httpd',
            'php': 'php',
            'python': 'python',
            'node': 'node',
        }
        
        # 查找官方镜像
        official_image = OFFICIAL_IMAGE_MAP.get(normalized_name)
        
        if official_image:
            # 尝试验证镜像是否存在
            result = _verify_image_exists(official_image, version)
            if result:
                return result
        
        # 如果没有官方镜像，尝试搜索
        search_result = _docker_search(normalized_name, version)
        if search_result:
            return search_result
        
        # 未找到任何镜像
        return f"""❌ No Docker images found for '{project_name}'.

**Next Steps:**
1. Double-check project name spelling
2. Try searching Docker Hub manually: https://hub.docker.com/search?q={normalized_name}
3. If no official image exists, proceed with source code build

**Fallback Strategy:**
- Check if project has official container registry (e.g., quay.io, gcr.io)
- Look for `Dockerfile` in project repository
- Build from source as last resort
"""
    
    except Exception as e:
        return f"⚠️ Error searching Docker Hub: {str(e)}\n\nProceed with source build if necessary."


def _verify_image_exists(image_name: str, version: Optional[str] = None) -> Optional[str]:
    """验证Docker镜像是否存在"""
    try:
        # 构建完整镜像名称
        full_image = f"{image_name}:{version}" if version else image_name
        
        # 尝试拉取镜像信息（不实际下载）
        result = subprocess.run(
            ['docker', 'manifest', 'inspect', full_image],
            capture_output=True,
            text=True,
            timeout=10
        )
        
        if result.returncode == 0:
            return f"""✅ **Official Docker Image Found!**

Image: `{full_image}`
Status: **Verified and Available**

**Recommended Action:**
```bash
docker pull {full_image}
docker run -d --name vuln-env {full_image}
```

**Advantages:**
- ⚡ Fast deployment (no compilation needed)
- ✅ Official build (trusted source)
- 🔧 Pre-configured environment

**Skip source build and use this image directly!**
"""
        
        # 如果指定版本不存在，尝试列出可用版本
        if version:
            # 尝试获取标签列表（使用docker hub API的替代方法）
            return f"""⚠️ Specific version `{full_image}` not found.

**Try these alternatives:**
1. List available tags manually:
   - Visit: https://hub.docker.com/r/{image_name}/tags
   - Or use: `docker search {image_name}`

2. Try common version formats:
   - `{image_name}:{version}` (current attempt)
   - `{image_name}:v{version}` (with 'v' prefix)
   - `{image_name}:{version.replace('v', '')}` (without 'v' prefix)
   - `{image_name}:latest` (latest stable)

3. If no matching version, build from source with git tag: {version}
"""
        
        return None
        
    except subprocess.TimeoutExpired:
        return "⚠️ Docker Hub connection timeout. Proceed with source build."
    except FileNotFoundError:
        return "⚠️ Docker command not available. Ensure Docker is installed."
    except Exception as e:
        return None


def _docker_search(project_name: str, version: Optional[str] = None) -> Optional[str]:
    """使用docker search命令查找镜像"""
    try:
        result = subprocess.run(
            ['docker', 'search', project_name, '--limit', '10', '--format', 'json'],
            capture_output=True,
            text=True,
            timeout=15
        )
        
        if result.returncode != 0:
            return None
        
        # 解析搜索结果
        images = []
        for line in result.stdout.strip().split('\n'):
            if line:
                try:
                    img = json.loads(line)
                    images.append(img)
                except json.JSONDecodeError:
                    continue
        
        if not images:
            return None
        
        # 按星级排序
        images.sort(key=lambda x: x.get('StarCount', 0), reverse=True)
        
        # 构建结果报告
        report = f"🔍 **Docker Hub Search Results for '{project_name}':**\n\n"
        
        for i, img in enumerate(images[:5], 1):
            stars = img.get('StarCount', 0)
            official = '⭐ OFFICIAL' if img.get('IsOfficial') else ''
            name = img.get('Name', '')
            description = img.get('Description', 'No description')[:80]
            
            report += f"{i}. `{name}` {official}\n"
            report += f"   ⭐ {stars} stars | {description}\n\n"
        
        # 推荐第一个（通常是官方或最受欢迎的）
        top_image = images[0]['Name']
        report += f"**Recommended Image:** `{top_image}`"
        
        if version:
            report += f":{version}"
        
        report += f"\n\n**Usage:**\n```bash\n"
        report += f"docker pull {top_image}"
        if version:
            report += f":{version}"
        report += f"\ndocker run -d --name vuln-env {top_image}"
        if version:
            report += f":{version}"
        report += "\n```"
        
        return report
        
    except Exception:
        return None


@tools.tool
def check_build_tool(tool_name: str) -> str:
    """
    Check if a build tool is installed, and provide installation instructions if missing.
    
    **When to use:**
    - Before attempting to build a project
    - After encountering "command not found" errors
    - To verify build environment prerequisites
    
    **Supported tools:**
    - cargo (Rust)
    - go (Golang)
    - npm/node (Node.js)
    - mvn (Maven)
    - gradle (Gradle)
    - dotnet (.NET)
    - gcc/g++ (C/C++)
    - make (Build automation)
    
    **Example:**
    - check_build_tool("cargo") → Checks Rust installation
    - check_build_tool("go") → Checks Golang installation
    
    :param tool_name: Name of the build tool to check
    :return: Installation status and instructions if missing
    """
    tool_name = tool_name.lower().strip()
    
    # 工具安装命令映射
    INSTALL_COMMANDS = {
        'cargo': {
            'check': 'cargo --version',
            'install_method_1': {
                'name': 'rustup (Recommended)',
                'commands': [
                    'curl --proto "=https" --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y',
                    'source $HOME/.cargo/env',
                    'cargo --version'
                ]
            },
            'install_method_2': {
                'name': 'apt (Faster but older version)',
                'commands': [
                    'apt-get update',
                    'apt-get install -y cargo rustc',
                    'cargo --version'
                ]
            },
            'description': 'Rust build tool and package manager'
        },
        'go': {
            'check': 'go version',
            'install_method_1': {
                'name': 'apt package manager',
                'commands': [
                    'apt-get update',
                    'apt-get install -y golang-go',
                    'go version'
                ]
            },
            'install_method_2': {
                'name': 'Official binary (latest version)',
                'commands': [
                    'wget https://go.dev/dl/go1.21.5.linux-amd64.tar.gz',
                    'rm -rf /usr/local/go && tar -C /usr/local -xzf go1.21.5.linux-amd64.tar.gz',
                    'export PATH=$PATH:/usr/local/go/bin',
                    'go version'
                ]
            },
            'description': 'Golang programming language'
        },
        'npm': {
            'check': 'npm --version',
            'install_method_1': {
                'name': 'apt (includes Node.js)',
                'commands': [
                    'apt-get update',
                    'apt-get install -y nodejs npm',
                    'npm --version'
                ]
            },
            'description': 'Node.js package manager'
        },
        'node': {
            'check': 'node --version',
            'install_method_1': {
                'name': 'apt package manager',
                'commands': [
                    'apt-get update',
                    'apt-get install -y nodejs npm',
                    'node --version'
                ]
            },
            'description': 'Node.js runtime'
        },
        'mvn': {
            'check': 'mvn --version',
            'install_method_1': {
                'name': 'apt package manager',
                'commands': [
                    'apt-get update',
                    'apt-get install -y maven',
                    'mvn --version'
                ]
            },
            'description': 'Apache Maven build tool'
        },
        'gradle': {
            'check': 'gradle --version',
            'install_method_1': {
                'name': 'apt package manager',
                'commands': [
                    'apt-get update',
                    'apt-get install -y gradle',
                    'gradle --version'
                ]
            },
            'description': 'Gradle build automation'
        },
        'dotnet': {
            'check': 'dotnet --version',
            'install_method_1': {
                'name': 'Microsoft package repository',
                'commands': [
                    'wget https://packages.microsoft.com/config/ubuntu/20.04/packages-microsoft-prod.deb -O packages-microsoft-prod.deb',
                    'dpkg -i packages-microsoft-prod.deb',
                    'apt-get update',
                    'apt-get install -y dotnet-sdk-8.0',
                    'dotnet --version'
                ]
            },
            'description': '.NET SDK'
        },
        'gcc': {
            'check': 'gcc --version',
            'install_method_1': {
                'name': 'apt (build-essential)',
                'commands': [
                    'apt-get update',
                    'apt-get install -y build-essential',
                    'gcc --version'
                ]
            },
            'description': 'GNU C Compiler'
        },
        'g++': {
            'check': 'g++ --version',
            'install_method_1': {
                'name': 'apt (build-essential)',
                'commands': [
                    'apt-get update',
                    'apt-get install -y build-essential',
                    'g++ --version'
                ]
            },
            'description': 'GNU C++ Compiler'
        },
        'make': {
            'check': 'make --version',
            'install_method_1': {
                'name': 'apt (build-essential)',
                'commands': [
                    'apt-get update',
                    'apt-get install -y build-essential',
                    'make --version'
                ]
            },
            'description': 'GNU Make build automation'
        }
    }
    
    if tool_name not in INSTALL_COMMANDS:
        available = ', '.join(INSTALL_COMMANDS.keys())
        return f"❌ Tool '{tool_name}' not recognized.\n\nSupported tools: {available}"
    
    tool_info = INSTALL_COMMANDS[tool_name]
    
    # 尝试检查工具是否已安装
    try:
        result = subprocess.run(
            tool_info['check'],
            shell=True,
            capture_output=True,
            text=True,
            timeout=5
        )
        
        if result.returncode == 0:
            version_output = result.stdout.strip() or result.stderr.strip()
            return f"""✅ **{tool_name.upper()} is already installed!**

Version Info:
```
{version_output}
```

You can proceed with building the project.
"""
    
    except Exception:
        pass
    
    # 工具未安装，提供安装指令
    report = f"❌ **{tool_name.upper()} is NOT installed.**\n\n"
    report += f"Description: {tool_info['description']}\n\n"
    report += "**Installation Options:**\n\n"
    
    for i in range(1, 10):
        method_key = f'install_method_{i}'
        if method_key in tool_info:
            method = tool_info[method_key]
            report += f"### Option {i}: {method['name']}\n\n"
            report += "```bash\n"
            report += '\n'.join(method['commands'])
            report += "\n```\n\n"
    
    report += "**⚠️ IMPORTANT: Run ONE of the installation methods above before proceeding!**"
    
    return report
