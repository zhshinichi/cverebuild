# CVE-Genie Web UI 使用说明

## 📖 简介

Web UI 提供了一个可视化界面，让你可以通过浏览器提交 CVE 复现任务，无需在终端输入命令。

## 🚀 快速开始

### 1. 启动 Web UI

**Windows (PowerShell):**
```powershell
.\scripts\start_web_ui.ps1
```

**Linux/Mac:**
```bash
bash scripts/start_web_ui.sh
```

### 2. 访问界面

在浏览器中打开：
```
http://localhost:5000
```

### 3. 提交任务

1. 输入 CVE ID（如 `CVE-2024-2288`）
2. 选择执行模式：
   - **DAG 模式**（推荐）：智能识别漏洞类型，选择最优流程
   - **Legacy 模式**：使用原有的固定流程
3. 如果是 DAG 模式，可以选择：
   - **浏览器引擎**：Selenium（默认）或 Playwright
   - **Profile**：自动识别、Web 漏洞、Native 漏洞
4. 点击"开始复现"

### 4. 查看进度

- 任务列表会实时更新
- 点击任务卡片查看详细日志
- 日志会实时流式显示

## 🎯 功能特性

### ✅ 任务管理
- ✨ 提交新的 CVE 复现任务
- 📋 查看所有任务列表
- 🔍 查看任务详细信息
- 📝 实时查看执行日志

### ✅ 执行模式
- **DAG 模式**：
  - 自动分类漏洞类型
  - 智能选择执行流程
  - 支持浏览器引擎切换
  - 优化的步骤链
  
- **Legacy 模式**：
  - 固定执行流程
  - 向后兼容

### ✅ 实时监控
- 🌊 SSE 流式日志输出
- 🔄 自动刷新任务状态
- ⏱️ 显示执行耗时
- 📊 任务状态指示

## 📂 文件结构

```
web_ui/
├── app.py                 # Flask 后端服务
├── templates/
│   └── index.html        # 前端页面
└── README.md             # 本文档

scripts/
├── start_web_ui.sh       # Linux/Mac 启动脚本
└── start_web_ui.ps1      # Windows 启动脚本
```

## 🔧 技术栈

### 后端
- **Flask**: Python Web 框架
- **Flask-CORS**: 跨域支持
- **SSE**: Server-Sent Events 实时推送

### 前端
- **原生 HTML/CSS/JavaScript**
- **EventSource API**: SSE 客户端
- **响应式设计**: 适配不同屏幕

## 🎨 界面预览

### 主页面
- 💜 渐变紫色主题
- 📝 简洁的表单输入
- 📋 任务列表卡片展示
- 🎯 状态徽章颜色区分

### 任务详情
- 📊 任务元信息展示
- 🖥️ 黑色终端风格日志
- 🌊 实时流式输出
- ⏱️ 执行时间统计

## 📝 API 接口

### 创建任务
```
POST /api/task
Body: {
  "cve_id": "CVE-2024-2288",
  "mode": "dag",
  "browser_engine": "selenium",
  "profile": "auto"
}
```

### 获取任务列表
```
GET /api/tasks
```

### 获取任务详情
```
GET /api/task/<task_id>
```

### 流式日志
```
GET /api/stream/<task_id>
(SSE 连接)
```

## ⚙️ 配置说明

### 修改端口

编辑 `web_ui/app.py` 最后一行：
```python
app.run(host='0.0.0.0', port=5000, debug=True)  # 改成你想要的端口
```

### 修改数据文件路径

编辑 `web_ui/app.py`：
```python
DATA_JSON = 'data/example/data.json'  # 改成你的 JSON 文件路径
```

### 容器名称

如果你的容器名不是 `competent_dewdney`，修改启动脚本中的：
```bash
CONTAINER_NAME="your_container_name"
```

## 🐛 故障排除

### 问题 1: 容器未运行
```bash
# 启动容器
docker start competent_dewdney

# 或者运行新容器
docker run -d --name competent_dewdney ...
```

### 问题 2: 端口被占用
```bash
# 检查端口占用
netstat -ano | findstr :5000  # Windows
lsof -i :5000                 # Linux/Mac

# 修改端口或停止占用进程
```

### 问题 3: Flask 未安装
```bash
# 手动安装
docker exec competent_dewdney pip3 install flask flask-cors
```

### 问题 4: 无法访问 http://localhost:5000
```bash
# 检查容器端口映射
docker port competent_dewdney

# 如果需要，添加端口映射
docker run -p 5000:5000 ...
```

## 🔐 安全提示

⚠️ **注意**: 当前版本仅用于开发和测试环境！

生产环境使用前，请考虑：
- 添加身份认证
- 使用 HTTPS
- 限制任务并发数
- 添加资源限制
- 日志脱敏

## 📈 未来计划

- [ ] 用户认证系统
- [ ] 任务队列管理
- [ ] 结果文件下载
- [ ] 任务停止/删除功能
- [ ] 批量任务提交
- [ ] 统计数据可视化
- [ ] WebSocket 双向通信
- [ ] 任务优先级设置

## 💡 使用示例

### 示例 1: 测试 Web 漏洞
1. 输入 CVE ID: `CVE-2024-2288`
2. 选择模式: `DAG 模式`
3. 浏览器引擎: `Selenium`
4. Profile: `自动识别`
5. 点击"开始复现"

系统会自动识别为 Web 漏洞，执行：
```
收集信息 → 启动浏览器 → 执行攻击 → 验证结果
```

### 示例 2: 测试 Native 漏洞
1. 输入 CVE ID: `CVE-2024-1234` (假设是缓冲区溢出)
2. 选择模式: `DAG 模式`
3. Profile: `Native 漏洞`
4. 点击"开始复现"

系统会执行：
```
收集信息 → 分析依赖 → 编译源码 → 生成Exploit → 验证Flag
```

## 📞 支持

如有问题，请：
1. 查看 Docker 容器日志
2. 查看 Flask 输出日志
3. 检查浏览器控制台错误
4. 参考主项目 README

---

**Enjoy CVE-Genie Web UI! 🎉**
