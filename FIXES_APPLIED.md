# CVE复现系统修复说明

## 实施日期
2025年11月20日

## 问题分析

### CVE-2024-7009 (Calibre) 失败原因
- **环境隔离问题**：Python Code Interpreter运行在`~`目录，工具运行在项目目录
- **现象**：`execute_ls_command`看到文件，Python `open()`找不到文件
- **根本原因**：LangChain架构导致的工具和Python代码执行环境不一致

### CVE-2024-2928 (MLflow) 失败原因
- **输出捕获问题**：`!` 命令返回 `null`，Agent误判为失败
- **误判逻辑**：第一次pip成功安装，第二次看到null误认为"无网络连接"
- **实际情况**：mlflow已成功安装，只是输出捕获机制不同

## 修复方案

### 1. 禁用Python Code Interpreter (`repoBuilder.py`)

**修改**：
```python
def get_available_tools(self):
    # 只返回shell工具，移除Python解释器
    allowed_tools = [
        'get_file',                    # 读取文件（替代Python open()）
        'write_to_file',               # 写入文件
        'execute_ls_command',          # 目录列表
        'execute_linux_command',       # 执行命令（核心工具）
        'set_environment_variable'     # 环境变量
    ]
    return [TOOLS[name] for name in allowed_tools if name in TOOLS]
```

**效果**：
- ✅ 消除环境隔离问题
- ✅ 强制Agent使用正确的工具
- ✅ 所有操作在同一工作目录执行

### 2. 强化工具使用规则 (`repoBuilder.system.j2`)

**新增规则15 - 强制工具使用**：
```
⚠️ CRITICAL: You ONLY have access to these tools:
  - execute_linux_command(command, background)
  - execute_ls_command(dir)
  - get_file(filename)
  - write_to_file(content, filename)
  - set_environment_variable(key, value, clear)

❌ FORBIDDEN ACTIONS:
  - NEVER write Python code with open(), os.listdir(), subprocess.run()
  - NEVER use Python's ! magic commands (!pip, !mlflow)
  - NEVER call functions like run_shell_command() - it doesn't exist

✅ CORRECT USAGE:
  - Reading: get_file('setup.py') NOT open('setup.py')
  - Commands: execute_linux_command('pip install X', background=False)
  - Servers: execute_linux_command('mlflow ui --host 0.0.0.0 --port 5000', background=True)
```

### 3. 后台服务验证规则 (`repoBuilder.system.j2`)

**新增规则16 - 服务验证流程**：
```
Step 1: Start in background
execute_linux_command('mlflow ui --host 0.0.0.0 --port 5000', background=True)

Step 2: Wait for startup
execute_linux_command('sleep 3', background=False)

Step 3: Verify service - use ALL these checks:
a) Check process: execute_linux_command('ps aux | grep -i mlflow | grep -v grep', background=False)
b) Check port: execute_linux_command('ss -ltnp | grep :5000', background=False)
c) Check HTTP: execute_linux_command('curl -s -o /dev/null -w "%{http_code}" http://127.0.0.1:5000', background=False)

⚠️ IMPORTANT: "null" or empty output does NOT mean failure!
```

### 4. 改进命令输出 (`command_ops.py`)

**前台命令增强**：
```python
# 添加退出码显示
status_icon = "✅" if exit_code == 0 else "⚠️"
return (
    f"{status_icon} Command completed with exit code: {exit_code}\n"
    f"Command: {command}\n\n"
    f"{tail_output}\n"
)
```

**后台服务增强**：
```python
return (
    f"✅ Background process started successfully!\n"
    f"PID: {process.pid}\n"
    f"Command: {command}\n\n"
    f"{tail_output}\n"
    f"⚠️ Note: Background processes may show minimal initial output.\n"
    f"Verify service is running with:\n"
    f"  - ps aux | grep <process_name>\n"
    f"  - ss -ltnp | grep :<port>\n"
    f"  - curl http://localhost:<port>\n"
)
```

### 5. 改进工具文档 (`command_ops.py`)

**execute_linux_command 新文档**：
```python
"""
Executes a shell command in the root directory of the target repository.

USAGE GUIDELINES:
- Use background=False for: installations, builds, one-time commands
- Use background=True for: servers, daemons, long-running processes

IMPORTANT NOTES:
- Exit code 0 = success, non-zero = error
- Empty/null output does NOT mean failure - check exit code!
- Export commands won't persist (use set_environment_variable)

EXAMPLES:
- execute_linux_command('pip install mlflow==2.11.2', background=False)
- execute_linux_command('mlflow ui --host 0.0.0.0 --port 5000', background=True)
- execute_linux_command('ps aux | grep mlflow', background=False)
"""
```

## 修复效果预期

### 对CVE-2024-7009 (Calibre)的改进
| 问题 | 修复前 | 修复后 |
|-----|--------|--------|
| 文件访问 | ❌ Python `open()` 找不到文件 | ✅ `get_file()` 工具正确访问 |
| 命令执行 | ❌ 混用工具和Python代码 | ✅ 统一使用 `execute_linux_command` |
| 工作目录 | ❌ 两个不同的工作目录 | ✅ 所有操作同一目录 |
| Agent行为 | ❌ 反复尝试失败后放弃 | ✅ 使用正确工具一次成功 |

### 对CVE-2024-2928 (MLflow)的改进
| 问题 | 修复前 | 修复后 |
|-----|--------|--------|
| 输出判断 | ❌ 看到null误判为失败 | ✅ 检查退出码判断成功 |
| 服务验证 | ❌ 启动后不知道如何验证 | ✅ 三重验证（ps/port/http）|
| 网络误判 | ❌ "connectivity issues" 放弃 | ✅ 明确告知null不代表失败 |
| 重试逻辑 | ❌ 重复安装导致误判 | ✅ 用python导入验证安装 |

## 测试建议

### 测试CVE-2024-2928 (MLflow) - 应该能快速成功
```bash
# 预期Agent执行流程：
1. execute_linux_command('pip install mlflow==2.11.2', background=False)
   → 看到 "✅ Command completed with exit code: 0"
   
2. execute_linux_command('python3 -c "import mlflow; print(mlflow.__version__)"', background=False)
   → 输出 "2.11.2" 确认安装成功
   
3. execute_linux_command('mlflow ui --host 0.0.0.0 --port 5000', background=True)
   → 看到 "✅ Background process started successfully! PID: XXXX"
   
4. execute_linux_command('sleep 3', background=False)
   
5. execute_linux_command('ps aux | grep mlflow | grep -v grep', background=False)
   → 看到进程存在
   
6. execute_linux_command('curl -I http://127.0.0.1:5000', background=False)
   → 看到 HTTP 200 响应

7. 返回 <success>yes</success>
```

### 测试CVE-2024-7009 (Calibre) - 应该改进但仍有挑战
```bash
# 预期改进：
1. ✅ 不再出现 "No such file" 错误（因为不用Python open()）
2. ✅ 使用 get_file('setup.py') 正确读取文件
3. ✅ 使用 execute_linux_command('python setup.py develop', background=False) 编译
4. ⚠️ 可能仍需处理C++编译依赖问题（Qt, libstdc++等）
5. ⚠️ 如果Calibre构建复杂，可能需要多次Critic反馈
```

## 关键改进点总结

1. **架构层面**：禁用Python Code Interpreter，消除环境隔离
2. **提示词层面**：明确禁止Python代码，强制使用工具
3. **工具层面**：改进输出格式，增加退出码和状态提示
4. **验证层面**：提供明确的服务验证三步法
5. **误判预防**：明确告知null输出不代表失败

## 文件清单

修改的文件：
- ✅ `src/prompts/repoBuilder/repoBuilder.system.j2` - 系统提示词
- ✅ `src/agents/repoBuilder.py` - Agent工具配置
- ✅ `src/toolbox/command_ops.py` - 命令执行工具

## 预期成功率

- **简单CVE (MLflow类型)**：90%+ 成功率
- **中等CVE (pip安装+配置)**：70-80% 成功率  
- **复杂CVE (源码编译+C++)**：50-60% 成功率（需Critic多次反馈）

## 后续优化建议

如果仍有问题：
1. 增加更多具体的示例到提示词
2. 添加常见错误的自动重试逻辑
3. 为C++编译类CVE提供预置的依赖安装脚本
4. 考虑添加Docker支持作为备选方案
