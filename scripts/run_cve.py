#!/usr/bin/env python3
"""
CVE 自动复现工具
只需输入 CVE ID，自动判断漏洞类型并执行对应流程

用法:
    python scripts/run_cve.py CVE-2025-1752
    python scripts/run_cve.py CVE-2024-2928
"""

import argparse
import subprocess
import sys
import os

# 配置
CONTAINER_NAME = "competent_dewdney"
CONTAINER_WORKSPACE = "/workspaces/submission"
#DATA_JSON = f"{CONTAINER_WORKSPACE}/src/data/large_scale/data.json"
DATA_JSON = f"{CONTAINER_WORKSPACE}/src/data/simple_web_cves_20.json"
MAIN_PY = f"{CONTAINER_WORKSPACE}/src/main.py"

# API 配置
OPENAI_API_KEY = os.environ.get('OPENAI_API_KEY', 'sk-ziyWDSRgl3ymsBm3MWN8C5fPJwrzxaakqdsCYsWIB0dTqHmg')
OPENAI_API_BASE = os.environ.get('OPENAI_API_BASE', 'https://api.openai-hub.com/v1')


def classify_cve(cve_id: str) -> tuple[str, bool]:
    """使用 LLM 分类器判断 CVE 类型"""
    print(f"🔍 正在分析 {cve_id} 的漏洞类型...")
    
    classify_cmd = [
        'docker', 'exec',
        '-w', f'{CONTAINER_WORKSPACE}/src',
        '-e', f'PYTHONPATH={CONTAINER_WORKSPACE}/src/agentlib',
        '-e', f'OPENAI_API_KEY={OPENAI_API_KEY}',
        '-e', f'OPENAI_API_BASE={OPENAI_API_BASE}',
        CONTAINER_NAME,
        'python3', '-c', f'''
import json
import sys
sys.path.insert(0, ".")
from planner.llm_classifier import LLMVulnerabilityClassifier, LLMClassifierConfig

with open("{DATA_JSON}") as f:
    data = json.load(f)
    
cve_entry = data.get("{cve_id}", {{}})
if not cve_entry:
    print("ERROR:CVE not found in data.json")
    sys.exit(1)

config = LLMClassifierConfig(use_llm=True, fallback_to_rules=True)
classifier = LLMVulnerabilityClassifier(config)
decision = classifier.classify("{cve_id}", cve_entry)
needs_browser = decision.resource_hints.get("needs_browser", False)
print(f"{{decision.profile}},{{needs_browser}}")
'''
    ]
    
    try:
        result = subprocess.run(
            classify_cmd, 
            capture_output=True, 
            text=True, 
            timeout=120,
            encoding='utf-8',
            errors='replace'
        )
        
        if result.returncode != 0:
            print(f"⚠️ 分类失败: {result.stderr}")
            return 'native-local', False
        
        # 解析输出 - 寻找 "Profile: xxx" 和 "Needs browser: xxx" 格式
        # 或者旧的 "profile,needs_browser" 格式
        output = result.stdout
        output_lines = output.strip().split('\n')
        
        # 方法1: 查找 LLM 分类器的输出格式
        profile = None
        needs_browser = False
        
        for line in output_lines:
            line_stripped = line.strip()
            
            # 匹配 "Profile: web-basic" 格式
            if line_stripped.startswith("Profile:"):
                profile = line_stripped.split(":", 1)[1].strip()
            # 匹配 "Needs browser: True" 格式
            elif "Needs browser:" in line_stripped:
                needs_browser = "true" in line_stripped.lower()
            # 旧格式: "web-basic,True" 等 - 添加 freestyle 支持
            elif "," in line_stripped and any(p in line_stripped.lower() for p in ['native-local', 'web-basic', 'freestyle', 'cloud-config', 'iot-firmware']):
                parts = line_stripped.split(',')
                profile = parts[0].strip()
                needs_browser = parts[1].strip().lower() == 'true' if len(parts) > 1 else False
        
        if profile is None:
            # 回退：使用最后一行
            last_line = output_lines[-1].strip()
            if last_line.startswith("ERROR:"):
                print(f"❌ {last_line}")
                sys.exit(1)
            parts = last_line.split(',')
            profile = parts[0].strip() if parts else 'native-local'
            needs_browser = parts[1].strip().lower() == 'true' if len(parts) > 1 else False
        
        return profile, needs_browser
        
    except subprocess.TimeoutExpired:
        print("⚠️ 分类超时，使用默认模式")
        return 'native-local', False
    except Exception as e:
        print(f"⚠️ 分类异常: {e}，使用默认模式")
        return 'native-local', False


def run_cve(cve_id: str, mode: str = 'auto', browser_engine: str = 'playwright'):
    """运行 CVE 复现"""
    
    # 自动模式：先分类
    if mode == 'auto':
        profile, needs_browser = classify_cve(cve_id)
        
        if profile == 'freestyle':
            print(f"🎨 检测结果: 自由探索模式 ({profile}) → 使用 DAG + FreestyleAgent 流程")
            mode = 'dag'
        elif profile == 'web-basic' and needs_browser:
            print(f"🌐 检测结果: Web 漏洞 → 使用 DAG + WebDriver 流程")
            mode = 'dag'
        else:
            print(f"🐍 检测结果: Native/Python 漏洞 ({profile}) → 使用传统流程")
            mode = 'legacy'
    else:
        profile = 'native-local'  # 默认
    
    # 构建命令
    if mode == 'dag':
        container_cmd = [
            'python3', MAIN_PY,
            '--cve', cve_id,
            '--json', DATA_JSON,
            '--dag',
            '--browser-engine', browser_engine,
            '--profile', profile  # 使用分类结果的 profile
        ]
    else:  # legacy
        container_cmd = [
            'python3', MAIN_PY,
            '--cve', cve_id,
            '--json', DATA_JSON,
            '--run-type', 'build,exploit,verify'
        ]
    
    # 构建 docker exec 命令
    cmd = [
        'docker', 'exec',
        '-w', f'{CONTAINER_WORKSPACE}/src',
        '-e', f'OPENAI_API_KEY={OPENAI_API_KEY}',
        '-e', f'OPENAI_API_BASE={OPENAI_API_BASE}',
        '-e', 'MODEL=example_run',
        '-e', f'SHARED_DIR={CONTAINER_WORKSPACE}/src/shared',
        '-e', 'PYTHONIOENCODING=utf-8',
        '-e', 'PYTHONUNBUFFERED=1',
        '-e', 'PYTHONWARNINGS=ignore',  # 忽略 Python warnings，避免 PowerShell 误报错误
        CONTAINER_NAME
    ] + container_cmd
    
    print(f"\n🚀 开始复现 {cve_id}...")
    print(f"📋 执行模式: {mode}")
    print(f"💻 命令: {' '.join(container_cmd)}\n")
    print("=" * 60)
    
    # 执行命令（实时输出，使用 UTF-8 编码）
    process = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
        encoding='utf-8',
        errors='replace'
    )
    
    # 实时打印输出
    for line in iter(process.stdout.readline, ''):
        print(line, end='')
    
    process.wait()
    
    print("=" * 60)
    if process.returncode == 0:
        print(f"✅ {cve_id} 复现完成！")
    else:
        print(f"❌ {cve_id} 复现失败 (exit code: {process.returncode})")
    
    return process.returncode


def main():
    parser = argparse.ArgumentParser(
        description='CVE 自动复现工具 - 自动识别漏洞类型并执行对应流程',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
示例:
    python scripts/run_cve.py CVE-2025-1752          # 自动识别并复现
    python scripts/run_cve.py CVE-2024-2928 --mode dag    # 强制使用 DAG 模式
    python scripts/run_cve.py CVE-2025-1752 --mode legacy # 强制使用传统模式
        '''
    )
    
    parser.add_argument('cve_id', type=str, help='CVE ID (如 CVE-2025-1752)')
    parser.add_argument('--mode', type=str, choices=['auto', 'dag', 'legacy'], 
                        default='auto', help='执行模式 (默认: auto)')
    parser.add_argument('--browser', type=str, choices=['playwright', 'selenium'],
                        default='playwright', help='浏览器引擎 (默认: playwright)')
    
    args = parser.parse_args()
    
    # 验证 CVE ID 格式
    if not args.cve_id.upper().startswith('CVE-'):
        print("❌ 错误: CVE ID 格式不正确，应该是 CVE-XXXX-XXXXX")
        sys.exit(1)
    
    cve_id = args.cve_id.upper()
    
    print(f"""
╔══════════════════════════════════════════════════════════╗
║           CVE-Genie 自动复现工具                         ║
╠══════════════════════════════════════════════════════════╣
║  CVE ID: {cve_id:<47} ║
║  模式:   {args.mode:<47} ║
╚══════════════════════════════════════════════════════════╝
    """)
    
    exit_code = run_cve(cve_id, mode=args.mode, browser_engine=args.browser)
    sys.exit(exit_code)


if __name__ == '__main__':
    main()
