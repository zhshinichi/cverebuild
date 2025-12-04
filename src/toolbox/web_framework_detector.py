"""
Web Framework Detector
自动检测 Python Web 项目的框架类型和正确的启动方式
"""

import re
from typing import Optional, Dict, Tuple
from dataclasses import dataclass


@dataclass
class FrameworkInfo:
    """框架信息"""
    name: str
    start_command: str
    env_vars: Dict[str, str] = None
    notes: str = ""


# 知名 Web 框架的启动命令模板
FRAMEWORK_COMMANDS = {
    'mlflow': FrameworkInfo(
        name='MLflow',
        start_command='mlflow server --host 0.0.0.0 --port {port}',
        notes='MLflow 使用自带的 server 命令，不支持 gunicorn 直接启动'
    ),
    'django': FrameworkInfo(
        name='Django',
        start_command='python manage.py runserver 0.0.0.0:{port}',
        notes='Django 开发服务器，生产环境使用 gunicorn + wsgi.py'
    ),
    'flask': FrameworkInfo(
        name='Flask',
        start_command='flask run --host 0.0.0.0 --port {port}',
        env_vars={'FLASK_APP': 'app.py'},
        notes='Flask 开发服务器，或直接运行 python app.py'
    ),
    'fastapi': FrameworkInfo(
        name='FastAPI',
        start_command='uvicorn {module}:app --host 0.0.0.0 --port {port}',
        notes='FastAPI 使用 uvicorn 作为 ASGI 服务器'
    ),
    'streamlit': FrameworkInfo(
        name='Streamlit',
        start_command='streamlit run {entry_file} --server.port {port} --server.address 0.0.0.0',
        notes='Streamlit 使用自带的 run 命令'
    ),
    'gradio': FrameworkInfo(
        name='Gradio',
        start_command='python {entry_file}',
        notes='Gradio 应用直接运行 Python 文件'
    ),
    'lollms': FrameworkInfo(
        name='lollms-webui',
        start_command='python app.py --host 0.0.0.0 --port {port}',
        notes='lollms-webui 使用自定义启动脚本'
    ),
    'jupyter': FrameworkInfo(
        name='Jupyter',
        start_command='jupyter notebook --ip 0.0.0.0 --port {port} --no-browser',
        notes='Jupyter Notebook 服务器'
    ),
    'tornado': FrameworkInfo(
        name='Tornado',
        start_command='python {entry_file}',
        notes='Tornado 应用直接运行 Python 文件'
    ),
    'sanic': FrameworkInfo(
        name='Sanic',
        start_command='sanic {module}:app --host 0.0.0.0 --port {port}',
        notes='Sanic 使用自带的 CLI'
    ),
    'aiohttp': FrameworkInfo(
        name='aiohttp',
        start_command='python {entry_file}',
        notes='aiohttp 应用直接运行 Python 文件'
    ),
    'quart': FrameworkInfo(
        name='Quart',
        start_command='quart run --host 0.0.0.0 --port {port}',
        env_vars={'QUART_APP': 'app:app'},
        notes='Quart 是 Flask 的异步版本'
    ),
}


# 框架检测模式
FRAMEWORK_PATTERNS = {
    'mlflow': [
        r'from\s+mlflow',
        r'import\s+mlflow',
        r'"mlflow"',  # in pyproject.toml/setup.py
    ],
    'django': [
        r'from\s+django',
        r'import\s+django',
        r'DJANGO_SETTINGS_MODULE',
        r'manage\.py',
    ],
    'flask': [
        r'from\s+flask\s+import\s+Flask',
        r'Flask\(__name__\)',
        r'app\s*=\s*Flask',
    ],
    'fastapi': [
        r'from\s+fastapi\s+import\s+FastAPI',
        r'FastAPI\(\)',
        r'app\s*=\s*FastAPI',
    ],
    'streamlit': [
        r'import\s+streamlit',
        r'from\s+streamlit',
        r'st\.',
    ],
    'gradio': [
        r'import\s+gradio',
        r'from\s+gradio',
        r'gr\.',
    ],
    'lollms': [
        r'lollms',
        r'from\s+lollms',
    ],
    'tornado': [
        r'from\s+tornado',
        r'import\s+tornado',
        r'tornado\.web\.Application',
    ],
    'sanic': [
        r'from\s+sanic',
        r'import\s+sanic',
        r'Sanic\(__name__\)',
    ],
    'aiohttp': [
        r'from\s+aiohttp',
        r'import\s+aiohttp',
        r'aiohttp\.web',
    ],
    'quart': [
        r'from\s+quart',
        r'import\s+quart',
        r'Quart\(__name__\)',
    ],
}


def detect_framework_from_content(content: str) -> Optional[str]:
    """
    从文件内容检测使用的框架
    
    Args:
        content: 文件内容（Python 代码或配置文件）
    
    Returns:
        检测到的框架名称，如果未检测到返回 None
    """
    content_lower = content.lower()
    
    # 按优先级检测
    priority_order = ['mlflow', 'django', 'fastapi', 'flask', 'streamlit', 
                      'gradio', 'lollms', 'sanic', 'quart', 'tornado', 'aiohttp']
    
    for framework in priority_order:
        patterns = FRAMEWORK_PATTERNS.get(framework, [])
        for pattern in patterns:
            if re.search(pattern, content, re.IGNORECASE):
                return framework
    
    return None


def detect_entry_point(content: str) -> Optional[str]:
    """
    从 pyproject.toml 或 setup.py 检测入口点
    
    Args:
        content: pyproject.toml 或 setup.py 的内容
    
    Returns:
        入口点命令，如 "mlflow server"
    """
    # 检测 pyproject.toml 的 scripts
    scripts_match = re.search(r'\[project\.scripts\](.*?)(?=\[|\Z)', content, re.DOTALL)
    if scripts_match:
        scripts_block = scripts_match.group(1)
        # 提取 script_name = "module:function"
        for line in scripts_block.split('\n'):
            if '=' in line and '#' not in line.split('=')[0]:
                parts = line.split('=')
                if len(parts) >= 2:
                    script_name = parts[0].strip().strip('"\'')
                    return script_name
    
    # 检测 setup.py 的 console_scripts
    console_scripts_match = re.search(r'console_scripts.*?=.*?\[(.*?)\]', content, re.DOTALL)
    if console_scripts_match:
        scripts_block = console_scripts_match.group(1)
        for line in scripts_block.split(','):
            if '=' in line:
                parts = line.split('=')
                script_name = parts[0].strip().strip('"\'')
                return script_name
    
    return None


def get_startup_command(framework: str, port: int = 9600, 
                        entry_file: str = 'app.py',
                        module: str = 'main') -> Tuple[str, Dict[str, str], str]:
    """
    获取框架的启动命令
    
    Args:
        framework: 框架名称
        port: 端口号
        entry_file: 入口文件
        module: 模块名
    
    Returns:
        (启动命令, 环境变量字典, 注意事项)
    """
    info = FRAMEWORK_COMMANDS.get(framework)
    if not info:
        # 默认使用 Python 直接运行
        return f'python {entry_file}', {}, f'未识别的框架，尝试直接运行 Python 文件'
    
    command = info.start_command.format(
        port=port,
        entry_file=entry_file,
        module=module
    )
    
    return command, info.env_vars or {}, info.notes


def analyze_project_structure(file_list: list) -> dict:
    """
    分析项目结构，返回启动建议
    
    Args:
        file_list: 项目文件列表
    
    Returns:
        分析结果字典
    """
    result = {
        'has_docker_compose': False,
        'has_dockerfile': False,
        'has_pyproject': False,
        'has_setup_py': False,
        'has_requirements': False,
        'has_manage_py': False,  # Django
        'entry_candidates': [],
        'framework_hints': [],
    }
    
    for f in file_list:
        f_lower = f.lower()
        
        if 'docker-compose' in f_lower:
            result['has_docker_compose'] = True
        elif f_lower.endswith('dockerfile'):
            result['has_dockerfile'] = True
        elif f_lower == 'pyproject.toml':
            result['has_pyproject'] = True
        elif f_lower == 'setup.py':
            result['has_setup_py'] = True
        elif 'requirements' in f_lower and f_lower.endswith('.txt'):
            result['has_requirements'] = True
        elif f_lower == 'manage.py':
            result['has_manage_py'] = True
            result['framework_hints'].append('django')
        
        # 入口文件候选
        if f_lower in ['app.py', 'main.py', 'server.py', 'run.py', 'wsgi.py']:
            result['entry_candidates'].append(f)
    
    return result


def get_deployment_steps(analysis: dict) -> list:
    """
    根据项目分析结果生成部署步骤
    
    Args:
        analysis: analyze_project_structure 的结果
    
    Returns:
        部署步骤列表
    """
    steps = []
    
    # 优先使用 Docker
    if analysis['has_docker_compose']:
        steps.append('docker-compose up -d --build')
        return steps
    
    if analysis['has_dockerfile']:
        steps.append('docker build -t vuln_app . && docker run -d -p 9600:9600 vuln_app')
        return steps
    
    # Python 项目
    steps.append('python3 -m venv /tmp/venv && source /tmp/venv/bin/activate')
    
    # 安装依赖
    if analysis['has_pyproject'] or analysis['has_setup_py']:
        steps.append('pip install -e .')  # 安装项目本身
    elif analysis['has_requirements']:
        steps.append('pip install -r requirements.txt')
    
    # 启动服务
    if 'django' in analysis.get('framework_hints', []) or analysis['has_manage_py']:
        steps.append('python manage.py runserver 0.0.0.0:9600')
    elif analysis['entry_candidates']:
        entry = analysis['entry_candidates'][0]
        steps.append(f'python {entry}')
    else:
        steps.append('# 需要检测正确的入口文件')
    
    return steps


# 测试代码
if __name__ == '__main__':
    # 测试框架检测
    test_content = '''
from mlflow import MlflowClient
from mlflow.server import app
'''
    framework = detect_framework_from_content(test_content)
    print(f"Detected framework: {framework}")
    
    if framework:
        cmd, env, notes = get_startup_command(framework)
        print(f"Start command: {cmd}")
        print(f"Environment: {env}")
        print(f"Notes: {notes}")
