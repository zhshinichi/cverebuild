"""
CVE-Genie Web UI - Flask Backend
提供 Web 界面用于提交 CVE 复现任务并实时查看进度
"""

from flask import Flask, render_template, request, jsonify, Response
from flask_cors import CORS
import subprocess
import threading
import json
import os
import time
import sqlite3
from datetime import datetime
from pathlib import Path

app = Flask(__name__)
CORS(app)

# 数据库配置
DB_PATH = Path(__file__).parent / 'tasks.db'

def init_db():
    """初始化数据库"""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS tasks (
            task_id INTEGER PRIMARY KEY,
            cve_id TEXT NOT NULL,
            mode TEXT DEFAULT 'dag',
            browser_engine TEXT DEFAULT 'selenium',
            profile TEXT DEFAULT 'web-basic',
            status TEXT DEFAULT 'pending',
            start_time TEXT,
            end_time TEXT,
            output TEXT DEFAULT '[]',
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    conn.commit()
    conn.close()

def get_db():
    """获取数据库连接"""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def save_task_to_db(task):
    """保存任务到数据库"""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('''
        INSERT OR REPLACE INTO tasks 
        (task_id, cve_id, mode, browser_engine, profile, status, start_time, end_time, output)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', (
        task.task_id,
        task.cve_id,
        task.mode,
        task.browser_engine,
        task.profile,
        task.status,
        task.start_time.isoformat() if task.start_time else None,
        task.end_time.isoformat() if task.end_time else None,
        json.dumps(task.output, ensure_ascii=False)
    ))
    conn.commit()
    conn.close()

def load_tasks_from_db():
    """从数据库加载历史任务"""
    global task_counter
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM tasks ORDER BY task_id')
    rows = cursor.fetchall()
    conn.close()
    
    loaded_tasks = {}
    max_id = 0
    for row in rows:
        task = TaskRunner(
            task_id=row['task_id'],
            cve_id=row['cve_id'],
            mode=row['mode'],
            browser_engine=row['browser_engine'],
            profile=row['profile']
        )
        task.status = row['status']
        task.start_time = datetime.fromisoformat(row['start_time']) if row['start_time'] else None
        task.end_time = datetime.fromisoformat(row['end_time']) if row['end_time'] else None
        task.output = json.loads(row['output']) if row['output'] else []
        loaded_tasks[row['task_id']] = task
        max_id = max(max_id, row['task_id'])
    
    return loaded_tasks, max_id

# 初始化数据库
init_db()

# 任务状态存储 - 稍后在 TaskRunner 类定义后初始化
tasks = {}
task_counter = 0
task_lock = threading.Lock()

# 配置 - 强制使用 Docker 容器执行模式
CONTAINER_NAME = "competent_dewdney"
RUN_IN_DOCKER = True  # Web UI 在本地，但任务在 Docker 中执行

# API 配置 - 从环境变量读取或使用默认值
OPENAI_API_KEY = os.environ.get('OPENAI_API_KEY', 'sk-ziyWDSRgl3ymsBm3MWN8C5fPJwrzxaakqdsCYsWIB0dTqHmg')
OPENAI_API_BASE = os.environ.get('OPENAI_API_BASE', 'https://api.openai-hub.com/v1')

if RUN_IN_DOCKER:
    # 任务在 Docker 容器中执行
    # 本地目录 c:\Users\shinichi\submission 挂载到容器的 /workspaces/submission
    WORKSPACE_DIR = Path(__file__).parent.parent
    SHARED_DIR = WORKSPACE_DIR / 'volumes' / 'general'
    
    # 容器内的路径配置（使用挂载路径，本地修改会自动同步）
    CONTAINER_WORKSPACE = '/workspaces/submission'
    CONTAINER_SHARED_DIR = f'{CONTAINER_WORKSPACE}/src/volumes/general'
    MAIN_PY = f'{CONTAINER_WORKSPACE}/src/main.py'
    PYTHON_CMD = 'python3'
    DATA_JSON = f'{CONTAINER_WORKSPACE}/src/data/large_scale/data.json'
else:
    # 任务在本地执行（旧模式）
    SHARED_DIR = Path('volumes')
    MAIN_PY = 'src/main.py'
    PYTHON_CMD = 'python'
    DATA_JSON = 'src/data/large_scale/data.json'  # 本地相对路径


class TaskRunner:
    """后台任务执行器"""
    
    def __init__(self, task_id, cve_id, mode='dag', browser_engine='selenium', profile='web-basic', data_json=None, target_url=None):
        self.task_id = task_id
        self.cve_id = cve_id
        self.mode = mode
        self.browser_engine = browser_engine
        self.profile = profile
        self.data_json = data_json or DATA_JSON
        self.target_url = target_url  # 可选的目标 URL
        self.status = 'pending'
        self.output = []
        self.start_time = None
        self.end_time = None
        self.process = None
        
    def run(self):
        """执行 CVE 复现任务"""
        self.status = 'running'
        self.start_time = datetime.now()
        save_task_to_db(self)  # 保存状态到数据库
        
        try:
            # 先清理可能残留的 Chrome 进程（避免资源冲突）
            if RUN_IN_DOCKER:
                self.output.append({
                    'timestamp': datetime.now().isoformat(),
                    'type': 'info',
                    'message': '🧹 Cleaning up previous Chrome processes...'
                })
                cleanup_result = subprocess.run(
                    ['docker', 'exec', CONTAINER_NAME, 'bash', '-c', 'pkill -9 chrome; pkill -9 chromedriver'],
                    capture_output=True, text=True
                )
            
            # 构建容器内执行的命令
            # 智能模式：先分类漏洞类型，再决定使用哪种流程
            if self.mode == 'auto':
                # 自动模式：先运行分类器判断漏洞类型
                self.output.append({
                    'timestamp': datetime.now().isoformat(),
                    'type': 'info',
                    'message': '🔍 Auto-detecting vulnerability type...'
                })
                
                # 运行分类器
                classify_cmd = [
                    'docker', 'exec',
                    '-w', f'{CONTAINER_WORKSPACE}/src',
                    '-e', f'PYTHONPATH={CONTAINER_WORKSPACE}/src/agentlib',
                    '-e', f'OPENAI_API_KEY={OPENAI_API_KEY}',
                    '-e', f'OPENAI_API_BASE={OPENAI_API_BASE}',
                    CONTAINER_NAME,
                    PYTHON_CMD, '-c', f'''
import json
import sys
sys.path.insert(0, ".")
from planner.llm_classifier import LLMVulnerabilityClassifier, LLMClassifierConfig

with open("{self.data_json}") as f:
    data = json.load(f)
    
cve_entry = data.get("{self.cve_id}", {{}})
config = LLMClassifierConfig(use_llm=True, fallback_to_rules=True)
classifier = LLMVulnerabilityClassifier(config)
decision = classifier.classify("{self.cve_id}", cve_entry)
# 输出 profile 和 needs_browser，用逗号分隔
needs_browser = decision.resource_hints.get("needs_browser", False)
print(f"{{decision.profile}},{{needs_browser}}")
'''
                ]
                
                try:
                    result = subprocess.run(classify_cmd, capture_output=True, text=True, timeout=60)
                    # 解析输出：格式为 "profile,needs_browser"
                    output_line = result.stdout.strip().split('\n')[-1]  # 取最后一行（跳过警告信息）
                    parts = output_line.split(',')
                    detected_profile = parts[0].strip() if parts else 'native-local'
                    needs_browser = parts[1].strip().lower() == 'true' if len(parts) > 1 else False
                    
                    self.output.append({
                        'timestamp': datetime.now().isoformat(),
                        'type': 'info',
                        'message': f'🤖 LLM Classification: profile={detected_profile}, needs_browser={needs_browser}'
                    })
                    
                    if detected_profile == 'web-basic' and needs_browser:
                        self.output.append({
                            'timestamp': datetime.now().isoformat(),
                            'type': 'info',
                            'message': '🌐 Detected: Web vulnerability → Using DAG + WebDriver flow'
                        })
                        # 继续使用 DAG 模式
                        container_cmd = [
                            PYTHON_CMD, MAIN_PY,
                            '--cve', self.cve_id,
                            '--json', self.data_json,
                            '--dag',
                            '--browser-engine', self.browser_engine,
                            '--profile', 'web-basic'
                        ]
                        if self.target_url:
                            container_cmd.extend(['--target-url', self.target_url])
                    else:
                        self.output.append({
                            'timestamp': datetime.now().isoformat(),
                            'type': 'info',
                            'message': f'🐍 Detected: Native/Python vulnerability ({detected_profile}) → Using traditional build,exploit,verify flow'
                        })
                        # 切换到传统模式
                        container_cmd = [
                            PYTHON_CMD, MAIN_PY,
                            '--cve', self.cve_id,
                            '--json', self.data_json,
                            '--run-type', 'build,exploit,verify'
                        ]
                except Exception as e:
                    self.output.append({
                        'timestamp': datetime.now().isoformat(),
                        'type': 'warning',
                        'message': f'⚠️ Classification failed: {e}, falling back to DAG mode'
                    })
                    container_cmd = [
                        PYTHON_CMD, MAIN_PY,
                        '--cve', self.cve_id,
                        '--json', self.data_json,
                        '--dag',
                        '--browser-engine', self.browser_engine,
                        '--profile', self.profile
                    ]
            elif self.mode == 'dag':
                container_cmd = [
                    PYTHON_CMD, MAIN_PY,
                    '--cve', self.cve_id,
                    '--json', self.data_json,
                    '--dag',
                    '--browser-engine', self.browser_engine,
                    '--profile', self.profile
                ]
                # 如果有目标 URL，添加参数
                if self.target_url:
                    container_cmd.extend(['--target-url', self.target_url])
            elif self.mode == 'info-only':
                container_cmd = [
                    PYTHON_CMD, MAIN_PY,
                    '--cve', self.cve_id,
                    '--json', self.data_json,
                    '--run-type', 'info'
                ]
            else:
                # legacy 模式
                container_cmd = [
                    PYTHON_CMD, MAIN_PY,
                    '--cve', self.cve_id,
                    '--json', self.data_json,
                    '--run-type', 'build,exploit,verify'
                ]
            
            self.output.append({
                'timestamp': datetime.now().isoformat(),
                'type': 'info',
                'message': f'🚀 Starting CVE reproduction: {self.cve_id}'
            })
            
            # 构建 docker exec 命令
            if RUN_IN_DOCKER:
                # 在 Docker 容器中执行
                # 包含完整的环境变量：API 密钥、基础 URL、共享目录等
                cmd = [
                    'docker', 'exec', 
                    '-w', f'{CONTAINER_WORKSPACE}/src',
                    '-e', f'OPENAI_API_KEY={OPENAI_API_KEY}',
                    '-e', f'OPENAI_API_BASE={OPENAI_API_BASE}',
                    '-e', 'MODEL=example_run', 
                    '-e', f'SHARED_DIR={CONTAINER_WORKSPACE}/src/shared',
                    '-e', 'PYTHONIOENCODING=utf-8',
                    '-e', 'PYTHONUNBUFFERED=1',  # 禁用 Python 输出缓冲，确保实时输出
                    CONTAINER_NAME
                ] + container_cmd
                
                cwd = None  # docker exec 不需要 cwd
                self.output.append({
                    'timestamp': datetime.now().isoformat(),
                    'type': 'info',
                    'message': f'📦 Running in Docker container: {CONTAINER_NAME}'
                })
            else:
                # 本地执行（旧模式）
                cmd = container_cmd
                cwd = '.'
            
            self.output.append({
                'timestamp': datetime.now().isoformat(),
                'type': 'command',
                'message': f'Command: {" ".join(cmd)}'
            })
            
            # 执行命令
            self.process = subprocess.Popen(
                cmd,
                cwd=cwd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                encoding='utf-8',
                errors='replace',  # 遇到无法解码的字符用 ? 替代
                bufsize=1
            )
            
            # 实时读取输出，并定期保存到数据库
            line_count = 0
            for line in iter(self.process.stdout.readline, ''):
                if line:
                    self.output.append({
                        'timestamp': datetime.now().isoformat(),
                        'type': 'output',
                        'message': line.rstrip()
                    })
                    line_count += 1
                    # 每50行保存一次到数据库，确保日志持久化
                    if line_count % 50 == 0:
                        save_task_to_db(self)
            
            self.process.wait()
            
            # 检查结果
            if self.process.returncode == 0:
                self.status = 'completed'
                self.output.append({
                    'timestamp': datetime.now().isoformat(),
                    'type': 'success',
                    'message': '✅ Task completed successfully'
                })
            else:
                self.status = 'failed'
                self.output.append({
                    'timestamp': datetime.now().isoformat(),
                    'type': 'error',
                    'message': f'❌ Task failed with exit code {self.process.returncode}'
                })
                
        except Exception as e:
            self.status = 'error'
            self.output.append({
                'timestamp': datetime.now().isoformat(),
                'type': 'error',
                'message': f'❌ Error: {str(e)}'
            })
        finally:
            self.end_time = datetime.now()
            save_task_to_db(self)  # 任务完成后保存到数据库
            
    def get_info(self):
        """获取任务信息"""
        duration = None
        if self.start_time:
            end = self.end_time or datetime.now()
            duration = (end - self.start_time).total_seconds()
            
        return {
            'task_id': self.task_id,
            'cve_id': self.cve_id,
            'status': self.status,
            'mode': self.mode,
            'browser_engine': self.browser_engine,
            'profile': self.profile,
            'start_time': self.start_time.isoformat() if self.start_time else None,
            'end_time': self.end_time.isoformat() if self.end_time else None,
            'duration': duration,
            'output_lines': len(self.output)
        }
    
    def stop(self):
        """停止任务"""
        if self.process and self.process.poll() is None:
            self.process.terminate()
            self.status = 'stopped'


# 在 TaskRunner 类定义后加载历史任务
tasks, task_counter = load_tasks_from_db()
print(f"📦 Loaded {len(tasks)} tasks from database")


@app.route('/')
def index():
    """主页"""
    return render_template('index.html')


@app.route('/test')
def test():
    """测试页"""
    return render_template('test.html')


@app.route('/api/tasks', methods=['GET'])
def get_tasks():
    """获取所有任务列表"""
    with task_lock:
        task_list = [task.get_info() for task in tasks.values()]
    return jsonify({'tasks': task_list})


@app.route('/api/task/<int:task_id>', methods=['GET'])
def get_task(task_id):
    """获取特定任务详情"""
    with task_lock:
        task = tasks.get(task_id)
        if not task:
            return jsonify({'error': 'Task not found'}), 404
        
        output = task.output
        
        # 如果内存中没有输出，尝试从日志文件读取
        if not output and task.cve_id:
            log_file = None
            if RUN_IN_DOCKER:
                # 从本地挂载路径读取日志
                local_log = WORKSPACE_DIR / 'src' / 'shared' / task.cve_id / f'{task.cve_id}_log.txt'
                if local_log.exists():
                    log_file = local_log
            else:
                local_log = Path(f'src/shared/{task.cve_id}/{task.cve_id}_log.txt')
                if local_log.exists():
                    log_file = local_log
            
            if log_file:
                try:
                    with open(log_file, 'r', encoding='utf-8', errors='replace') as f:
                        lines = f.readlines()
                    output = [{
                        'timestamp': datetime.now().isoformat(),
                        'type': 'output',
                        'message': line.rstrip()
                    } for line in lines]
                except Exception as e:
                    output = [{'type': 'error', 'message': f'读取日志失败: {e}'}]
        
        return jsonify({
            'task': task.get_info(),
            'output': output
        })


@app.route('/api/task/<int:task_id>/output', methods=['GET'])
def get_task_output(task_id):
    """获取任务输出（支持增量获取）"""
    with task_lock:
        task = tasks.get(task_id)
        if not task:
            return jsonify({'error': 'Task not found'}), 404
        
        # 支持从指定行开始获取
        from_line = request.args.get('from', 0, type=int)
        output = task.output[from_line:]
        
        return jsonify({
            'output': output,
            'total_lines': len(task.output),
            'status': task.status
        })


@app.route('/api/task', methods=['POST'])
def create_task():
    """创建新任务"""
    global task_counter
    
    data = request.json
    cve_id = data.get('cve_id', '').strip()
    
    if not cve_id:
        return jsonify({'error': 'CVE ID is required'}), 400
    
    # 验证 CVE ID 格式
    if not cve_id.startswith('CVE-'):
        return jsonify({'error': 'Invalid CVE ID format'}), 400
    
    # 处理任务类型：task_type = 'reproduce' 或 'info'
    # 转换为内部 mode: 'dag' 或 'info-only'
    task_type = data.get('task_type', 'reproduce')
    if task_type == 'info':
        mode = 'info-only'
    else:
        mode = data.get('mode', 'dag')
    
    with task_lock:
        task_counter += 1
        task_id = task_counter
        
        task = TaskRunner(
            task_id=task_id,
            cve_id=cve_id,
            mode=mode,
            browser_engine=data.get('browser_engine', 'selenium'),
            profile=data.get('profile', 'web-basic'),  # 默认使用 web-basic
            data_json=data.get('data_json', DATA_JSON),
            target_url=data.get('target_url')  # 可选的目标 URL
        )
        
        tasks[task_id] = task
        
        # 在后台线程中运行任务
        thread = threading.Thread(target=task.run)
        thread.daemon = True
        thread.start()
    
    return jsonify({
        'task_id': task_id,
        'message': f'Task created for {cve_id}',
        'task_type': task_type,
        'mode': mode
    }), 201


@app.route('/api/task/<int:task_id>/stop', methods=['POST'])
def stop_task(task_id):
    """停止任务"""
    with task_lock:
        task = tasks.get(task_id)
        if not task:
            return jsonify({'error': 'Task not found'}), 404
        
        task.stop()
        save_task_to_db(task)  # 保存停止状态
        return jsonify({'message': 'Task stopped'})


@app.route('/api/task/<int:task_id>', methods=['DELETE'])
def delete_task(task_id):
    """删除任务"""
    with task_lock:
        task = tasks.get(task_id)
        if not task:
            return jsonify({'error': 'Task not found'}), 404
        
        # 如果任务正在运行，先停止
        if task.status == 'running':
            task.stop()
        
        # 从内存中删除
        del tasks[task_id]
        
        # 从数据库中删除
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute('DELETE FROM tasks WHERE task_id = ?', (task_id,))
        conn.commit()
        conn.close()
        
        return jsonify({'message': 'Task deleted'})


@app.route('/api/tasks/clear', methods=['DELETE'])
def clear_tasks():
    """清空所有已完成的任务"""
    with task_lock:
        # 找出所有非运行中的任务
        to_delete = [tid for tid, task in tasks.items() if task.status != 'running']
        
        for tid in to_delete:
            del tasks[tid]
        
        # 从数据库中删除
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("DELETE FROM tasks WHERE status != 'running'")
        deleted_count = cursor.rowcount
        conn.commit()
        conn.close()
        
        return jsonify({'message': f'Cleared {deleted_count} tasks'})


@app.route('/api/results/<cve_id>', methods=['GET'])
def get_results(cve_id):
    """获取 CVE 复现结果文件列表"""
    result_dir = SHARED_DIR / cve_id
    
    if not result_dir.exists():
        return jsonify({'error': 'No results found'}), 404
    
    files = []
    for item in result_dir.iterdir():
        files.append({
            'name': item.name,
            'type': 'directory' if item.is_dir() else 'file',
            'size': item.stat().st_size if item.is_file() else None,
            'modified': datetime.fromtimestamp(item.stat().st_mtime).isoformat()
        })
    
    return jsonify({'cve_id': cve_id, 'files': files})


@app.route('/api/results/<cve_id>/file/<path:filename>', methods=['GET'])
def get_result_file(cve_id, filename):
    """下载结果文件"""
    file_path = SHARED_DIR / cve_id / filename
    
    if not file_path.exists():
        return jsonify({'error': 'File not found'}), 404
    
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
        return jsonify({'filename': filename, 'content': content})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/stream/<int:task_id>')
def stream_task(task_id):
    """SSE 流式输出任务日志"""
    def generate():
        last_line = 0
        while True:
            with task_lock:
                task = tasks.get(task_id)
                if not task:
                    yield f"data: {json.dumps({'error': 'Task not found'})}\n\n"
                    break
                
                # 发送新的输出行
                new_output = task.output[last_line:]
                if new_output:
                    for line in new_output:
                        yield f"data: {json.dumps(line)}\n\n"
                    last_line = len(task.output)
                
                # 如果任务已完成，发送完成信号
                if task.status in ['completed', 'failed', 'error', 'stopped']:
                    yield f"data: {json.dumps({'type': 'end', 'status': task.status})}\n\n"
                    break
            
            time.sleep(0.5)  # 每 0.5 秒检查一次
    
    return Response(generate(), mimetype='text/event-stream')


if __name__ == '__main__':
    print("🚀 Starting CVE-Genie Web UI...")
    print("📍 Access at: http://localhost:5001")
    print("📍 Test page: http://localhost:5001/test")
    # 使用端口 5001 避免与 VS Code 冲突，禁用 reloader
    app.run(host='0.0.0.0', port=5001, debug=True, threaded=True, use_reloader=False)
