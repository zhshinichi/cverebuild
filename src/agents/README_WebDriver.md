# Web Driver Agent 模块使用指南

## 概述

Web Driver Agent 模块用于复现需要浏览器交互的 Web 漏洞，如：
- **CSRF** (跨站请求伪造) - CVE-2024-2288
- **XSS** (跨站脚本攻击)
- **Clickjacking** (点击劫持)
- **Open Redirect** (开放重定向)

## 新增模块

### 1. WebDriverAgent (`agents/webDriverAgent.py`)
浏览器自动化 Agent，提供以下工具：
- `navigate_to_url()` - 访问 URL
- `find_element()` - 查找页面元素
- `click_element()` - 点击元素
- `input_text()` - 输入文本
- `execute_javascript()` - 执行 JS
- `check_alert()` - 检测 XSS alert
- `create_csrf_page()` - 创建 CSRF 攻击页面
- `take_screenshot()` - 截图取证

### 2. WebExploitCritic (`agents/webExploitCritic.py`)
Web 漏洞验证 Agent，分析复现结果并判断成功/失败

### 3. Web Detector (`toolbox/web_detector.py`)
自动检测 CVE 是否需要 WebDriver：
- `requires_web_driver(cve_info)` - 判断是否需要浏览器
- `get_attack_type(cve_info)` - 识别攻击类型

## 依赖安装

### Docker 容器内安装

```bash
# 1. 安装 Selenium
docker exec competent_dewdney pip install selenium

# 2. 安装 Chrome 和 ChromeDriver
docker exec competent_dewdney bash -c "apt-get update && apt-get install -y wget unzip chromium-browser chromium-chromedriver"

# 或者使用官方 Chrome
docker exec competent_dewdney bash -c "
wget -q -O - https://dl-ssl.google.com/linux/linux_signing_key.pub | apt-key add - && \
echo 'deb [arch=amd64] http://dl.google.com/linux/chrome/deb/ stable main' >> /etc/apt/sources.list.d/google-chrome.list && \
apt-get update && \
apt-get install -y google-chrome-stable && \
wget https://chromedriver.storage.googleapis.com/LATEST_RELEASE && \
wget https://chromedriver.storage.googleapis.com/\$(cat LATEST_RELEASE)/chromedriver_linux64.zip && \
unzip chromedriver_linux64.zip && \
mv chromedriver /usr/local/bin/ && \
chmod +x /usr/local/bin/chromedriver
"

# 3. 验证安装
docker exec competent_dewdney python -c "from selenium import webdriver; print('Selenium OK')"
docker exec competent_dewdney chromedriver --version
```

## 使用方法

### 自动检测并使用 WebDriver

在 `main.py` 中集成（需要手动添加）：

```python
from toolbox.web_detector import requires_web_driver, get_attack_type
from agents import WebDriverAgent, WebExploitCritic

# 在 Exploiter 之前检测
if requires_web_driver(self.cve_info):
    print("\n🌐 Detected web-based vulnerability, using WebDriver...")
    attack_type = get_attack_type(self.cve_info)
    
    web_agent = WebDriverAgent(
        cve_knowledge=self.cve_knowledge,
        target_url="http://localhost:9600",  # 根据实际情况调整
        attack_type=attack_type
    )
    
    result = web_agent.invoke().value
    
    # 验证结果
    critic = WebExploitCritic(
        exploit_logs=result,
        cve_knowledge=self.cve_knowledge
    )
    
    validation = critic.invoke().value
    
    if validation['decision'] == 'yes':
        print("✅ Web vulnerability successfully exploited!")
    else:
        print(f"❌ Exploitation failed: {validation['feedback']}")
```

### 手动运行示例

```python
from agents import WebDriverAgent

# 创建 agent
agent = WebDriverAgent(
    cve_knowledge="CSRF vulnerability in avatar upload...",
    target_url="http://localhost:9600",
    attack_type="csrf"
)

# 执行复现
result = agent.invoke().value
print(result)
```

## CVE-2024-2288 复现示例

```python
# 1. 启动目标应用（Lollms WebUI）
docker exec competent_dewdney bash -c "cd /path/to/lollms-webui && python app.py &"

# 2. 运行复现
docker exec competent_dewdney bash -c "
cd /workspaces/submission/src && \
ENV_PATH=.env MODEL=gpt-4o python3 main.py \
  --cve CVE-2024-2288 \
  --json data/large_scale/data.json \
  --run-type build,exploit,verify
"
```

## 工作流程

```
┌─────────────────────────────────────────┐
│  1. CVE Data Processor                  │
│     解析 CVE 信息                        │
└──────────────┬──────────────────────────┘
               │
               ▼
┌─────────────────────────────────────────┐
│  2. Web Detector                        │
│     检测是否需要 WebDriver               │
│     ├─ requires_web_driver()            │
│     └─ get_attack_type()                │
└──────────────┬──────────────────────────┘
               │
               ▼ (如果需要)
┌─────────────────────────────────────────┐
│  3. Repo Builder                        │
│     构建漏洞环境                         │
└──────────────┬──────────────────────────┘
               │
               ▼
┌─────────────────────────────────────────┐
│  4. WebDriverAgent                      │
│     ├─ 启动浏览器                        │
│     ├─ 访问目标页面                      │
│     ├─ 构造攻击 (CSRF/XSS)              │
│     ├─ 执行攻击                         │
│     └─ 收集证据 (截图/alert)             │
└──────────────┬──────────────────────────┘
               │
               ▼
┌─────────────────────────────────────────┐
│  5. WebExploitCritic                    │
│     验证漏洞是否成功触发                  │
└─────────────────────────────────────────┘
```

## 注意事项

1. **Headless Mode**: 默认使用无头模式运行，可以通过修改 `setup_driver(headless=False)` 查看浏览器
2. **端口配置**: 确保目标应用端口正确（默认 9600）
3. **超时设置**: WebDriver 默认等待 10 秒，可根据需要调整
4. **Docker 网络**: 如果目标应用在另一个容器，需要配置 Docker 网络
5. **截图路径**: 所有截图保存在 `/shared/{CVE_ID}/` 目录

## 故障排查

### 问题：找不到 chromedriver
```bash
# 检查安装
docker exec competent_dewdney which chromedriver

# 重新安装
docker exec competent_dewdney apt-get install -y chromium-chromedriver
```

### 问题：Chrome 启动失败
```bash
# 添加必要参数
chrome_options.add_argument('--no-sandbox')
chrome_options.add_argument('--disable-dev-shm-usage')
```

### 问题：无法连接目标应用
```bash
# 检查应用是否运行
docker exec competent_dewdney curl http://localhost:9600

# 检查防火墙/网络配置
```

## 扩展开发

要支持新的 Web 漏洞类型：

1. 在 `web_detector.py` 中添加 CWE 或关键词
2. 在 `WebDriverAgent` 中添加新的工具方法
3. 在系统提示词中添加对应的工作流程
4. 测试并验证

## 相关文件

```
src/
├── agents/
│   ├── webDriverAgent.py          # 浏览器自动化 Agent
│   └── webExploitCritic.py        # Web 漏洞验证 Agent
├── prompts/
│   ├── webDriverAgent/
│   │   ├── webDriverAgent.system.j2
│   │   └── webDriverAgent.user.j2
│   └── webExploitCritic/
│       ├── webExploitCritic.system.j2
│       └── webExploitCritic.user.j2
└── toolbox/
    └── web_detector.py            # Web 漏洞检测工具
```
