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
from datetime import datetime
from pathlib import Path

app = Flask(__name__)
CORS(app)

# 任务状态存储
tasks = {}
task_counter = 0
task_lock = threading.Lock()

# 配置 - 强制使用 Docker 容器执行模式
CONTAINER_NAME = "competent_dewdney"
RUN_IN_DOCKER = True  # Web UI 在本地，但任务在 Docker 中执行

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
    
    def __init__(self, task_id, cve_id, mode='dag', browser_engine='selenium', profile='auto', data_json=None):
        self.task_id = task_id
        self.cve_id = cve_id
        self.mode = mode
        self.browser_engine = browser_engine
        self.profile = profile
        self.data_json = data_json or DATA_JSON
        self.status = 'pending'
        self.output = []
        self.start_time = None
        self.end_time = None
        self.process = None
        
    def run(self):
        """执行 CVE 复现任务"""
        self.status = 'running'
        self.start_time = datetime.now()
        
        try:
            # 构建容器内执行的命令
            if self.mode == 'dag':
                container_cmd = [
                    PYTHON_CMD, MAIN_PY,
                    '--cve', self.cve_id,
                    '--json', self.data_json,
                    '--dag',
                    '--browser-engine', self.browser_engine,
                    '--profile', self.profile
                ]
            elif self.mode == 'info-only':
                container_cmd = [
                    PYTHON_CMD, MAIN_PY,
                    '--cve', self.cve_id,
                    '--json', self.data_json,
                    '--run-type', 'info'
                ]
            else:
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
                # 使用挂载路径 /workspaces/submission，本地修改会自动同步
                # 工作目录设为 src 目录
                # 设置 PYTHONIOENCODING=utf-8 避免编码问题
                cmd = [
                    'docker', 'exec', 
                    '-w', f'{CONTAINER_WORKSPACE}/src',
                    '-e', 'MODEL=example_run', 
                    '-e', f'ENV_PATH={CONTAINER_WORKSPACE}/src/.env',
                    '-e', 'PYTHONIOENCODING=utf-8',
                    CONTAINER_NAME
                ] + container_cmd
                
                cwd = None  # docker exec 不需要 cwd
                self.output.append({
                    'timestamp': datetime.now().isoformat(),
                    'type': 'info',
                    'message': f'📦 Running in Docker container: {CONTAINER_NAME} (using mounted workspace)'
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
            
            # 实时读取输出
            for line in iter(self.process.stdout.readline, ''):
                if line:
                    self.output.append({
                        'timestamp': datetime.now().isoformat(),
                        'type': 'output',
                        'message': line.rstrip()
                    })
            
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
        return jsonify({
            'task': task.get_info(),
            'output': task.output
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
    
    with task_lock:
        task_counter += 1
        task_id = task_counter
        
        task = TaskRunner(
            task_id=task_id,
            cve_id=cve_id,
            mode=data.get('mode', 'dag'),
            browser_engine=data.get('browser_engine', 'selenium'),
            profile=data.get('profile', 'auto'),
            data_json=data.get('data_json', DATA_JSON)
        )
        
        tasks[task_id] = task
        
        # 在后台线程中运行任务
        thread = threading.Thread(target=task.run)
        thread.daemon = True
        thread.start()
    
    return jsonify({
        'task_id': task_id,
        'message': f'Task created for {cve_id}'
    }), 201


@app.route('/api/task/<int:task_id>/stop', methods=['POST'])
def stop_task(task_id):
    """停止任务"""
    with task_lock:
        task = tasks.get(task_id)
        if not task:
            return jsonify({'error': 'Task not found'}), 404
        
        task.stop()
        return jsonify({'message': 'Task stopped'})


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
    print("📍 Access at: http://localhost:5000")
    print("📍 Test page: http://localhost:5000/test")
    app.run(host='0.0.0.0', port=5000, debug=True, threaded=True)
