"""
产品名到源码仓库的映射表

用于解决 CVE 数据中缺少源码仓库 URL 的问题。
当 CVE JSON 的 references 只包含 exploit/报告链接时，通过产品名查找真实仓库。

维护规则：
1. key 使用小写产品名（去除空格和特殊字符）
2. value 包含：repo_url（必需）、platform（可选）、notes（可选）
3. 优先使用官方仓库，其次是 fork/镜像
"""

PRODUCT_REPOSITORY_MAPPING = {
    # ============================================================
    # C - Content Management / E-commerce
    # ============================================================
    'crmeb': {
        'repo_url': 'https://github.com/crmeb/CRMEB',
        'platform': 'github',
        'notes': 'Official CRMEB repository on GitHub (Chinese e-commerce CMS)',
        'language': 'php',
        'build_tool': 'composer',
        'default_port': 80,
        'php_version': '7.4',  # Requires PHP 7.x (not compatible with PHP 8+)
        'required_extensions': ['curl', 'bcmath', 'simplexml', 'gd', 'dom', 'zip', 'pdo_mysql'],
        'working_directory': 'crmeb',  # composer.json is in subdirectory, not root
        'deployment_type': 'docker-compose',  # Recommended: use official docker-compose
        'docker_compose_path': 'docker-compose',  # Path to docker-compose directory
        'alternative_repos': [
            'https://gitee.com/ZhongBangKeJi/crmeb'  # Gitee mirror (404 - may be removed)
        ]
    },
    
    'crmebky': {
        'repo_url': 'https://github.com/crmeb/CRMEB',
        'platform': 'github',
        'notes': 'CRMEB-KY is a variant of CRMEB, use main GitHub repo',
        'language': 'php',
        'build_tool': 'composer',
        'php_version': '7.4',
        'required_extensions': ['curl', 'bcmath', 'simplexml', 'gd', 'dom', 'zip', 'pdo_mysql'],
        'working_directory': 'crmeb',
        'deployment_type': 'docker-compose'
    },
    
    # ============================================================
    # K - Knowledge / Analytics
    # ============================================================
    'knowage': {
        'repo_url': 'https://github.com/KnowageLabs/Knowage-Server',
        'platform': 'github',
        'notes': 'Open source analytics and business intelligence suite'
    },
    
    'knowageserver': {
        'repo_url': 'https://github.com/KnowageLabs/Knowage-Server',
        'platform': 'github',
        'notes': 'Alias for Knowage'
    },
    
    # ============================================================
    # M - Machine Learning / Data Science
    # ============================================================
    'mlflow': {
        'repo_url': 'https://github.com/mlflow/mlflow',
        'platform': 'github',
        'notes': 'Machine learning lifecycle platform',
        'default_port': 5000
    },
    
    # ============================================================
    # L - LLM / AI Frameworks
    # ============================================================
    'lollms': {
        'repo_url': 'https://github.com/ParisNeo/lollms-webui',
        'platform': 'github',
        'notes': 'Large Language Model interface',
        'default_port': 9600
    },
    
    'lollmswebui': {
        'repo_url': 'https://github.com/ParisNeo/lollms-webui',
        'platform': 'github',
        'notes': 'Alias for lollms'
    },
    
    # ============================================================
    # O - Office Automation (OA)
    # ============================================================
    'ywoa': {
        'repo_url': 'https://gitee.com/r1bbit/yimioa',
        'platform': 'gitee',
        'notes': 'Chinese office automation system (易米OA)',
        'language': 'java',
        'build_tool': 'maven'
    },
    
    'yimioa': {
        'repo_url': 'https://gitee.com/r1bbit/yimioa',
        'platform': 'gitee',
        'notes': 'Alias for ywoa'
    },
    
    # ============================================================
    # S - Streaming / Web Frameworks
    # ============================================================
    'streamlit': {
        'repo_url': 'https://github.com/streamlit/streamlit',
        'platform': 'github',
        'notes': 'Python web app framework for data science',
        'default_port': 8501
    },
    
    # ============================================================
    # G - Gradio
    # ============================================================
    'gradio': {
        'repo_url': 'https://github.com/gradio-app/gradio',
        'platform': 'github',
        'notes': 'Build ML web apps easily',
        'default_port': 7860
    },
    
    # ============================================================
    # O - Open WebUI
    # ============================================================
    'openwebui': {
        'repo_url': 'https://github.com/open-webui/open-webui',
        'platform': 'github',
        'notes': 'User-friendly WebUI for LLMs',
        'default_port': 8080
    },
    
    'open-webui': {
        'repo_url': 'https://github.com/open-webui/open-webui',
        'platform': 'github',
        'notes': 'Alias for openwebui'
    },
}


def get_repository_by_product(product_name: str) -> dict:
    """
    根据产品名获取仓库信息
    
    Args:
        product_name: 产品名称（不区分大小写）
    
    Returns:
        包含 repo_url, platform, notes 的字典，如果未找到返回 None
    """
    if not product_name:
        return None
    
    # 标准化产品名：小写，移除空格和特殊字符
    normalized = product_name.lower().replace(' ', '').replace('-', '').replace('_', '')
    
    return PRODUCT_REPOSITORY_MAPPING.get(normalized)


def add_product_mapping(product_name: str, repo_url: str, platform: str = None, notes: str = None):
    """
    动态添加产品映射（用于运行时扩展）
    
    Args:
        product_name: 产品名称
        repo_url: 仓库 URL
        platform: 平台（github/gitee/gitlab）
        notes: 备注信息
    """
    normalized = product_name.lower().replace(' ', '').replace('-', '').replace('_', '')
    PRODUCT_REPOSITORY_MAPPING[normalized] = {
        'repo_url': repo_url,
        'platform': platform or 'unknown',
        'notes': notes or f'Dynamically added mapping for {product_name}'
    }


# 测试代码
if __name__ == "__main__":
    test_products = [
        'CRMEB',
        'crmeb-ky',
        'Knowage-Server',
        'mlflow',
        'ywoa',
        'Open-WebUI',
        'NonExistentProduct'
    ]
    
    print("=" * 60)
    print("Product Repository Mapping Test")
    print("=" * 60)
    
    for product in test_products:
        result = get_repository_by_product(product)
        if result:
            print(f"\n✅ {product}:")
            print(f"   Repository: {result['repo_url']}")
            print(f"   Platform: {result.get('platform', 'N/A')}")
            print(f"   Notes: {result.get('notes', 'N/A')}")
        else:
            print(f"\n❌ {product}: No mapping found")
