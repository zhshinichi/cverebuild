# WebDriver 集成使用指南

## ✅ 已完成的集成

WebDriver 逻辑已经集成到 `main.py` 中，具备以下功能：

### 1. 自动检测
- 系统会自动检测 CVE 是否需要浏览器交互
- 基于 CWE 类型（CWE-352/79/601等）和描述关键词判断
- 自动识别攻击类型（CSRF、XSS、Clickjacking等）

### 2. 智能切换
- **Web 漏洞**：使用 `WebDriverAgent` + `WebExploitCritic`
- **非 Web 漏洞**：使用传统的 `Exploiter` + `ExploitCritic`

### 3. 配置支持
- 通过环境变量 `WEB_DRIVER_TARGET_URL` 设置目标 URL
- 默认值：`http://localhost:9600`

## 🚀 使用方法

### 方式 1: 直接运行（推荐）

```bash
# 在 Docker 容器中运行
docker exec competent_dewdney bash -c "
cd /workspaces/submission/src && 
ENV_PATH=.env 
MODEL=gpt-4o 
WEB_DRIVER_TARGET_URL=http://localhost:9600 
python3 main.py 
  --cve CVE-2024-2288 
  --json data/large_scale/data.json 
  --run-type build,exploit,verify
"
```

### 方式 2: 使用提供的脚本

**Windows (PowerShell):**
```powershell
cd C:\Users\shinichi\submission
.\scripts\run_cve_2024_2288.ps1
```

**Linux/Mac (Bash):**
```bash
cd /path/to/submission
bash scripts/run_cve_2024_2288.sh
```

### 方式 3: 测试检测功能

```bash
# 测试 WebDriver 自动检测
python scripts/test_webdriver_detection.py
```

## 📋 前置要求

在运行之前，确保已安装必要的依赖：

### 1. 安装 Selenium
```bash
docker exec competent_dewdney pip install selenium
```

### 2. 安装 ChromeDriver
```bash
docker exec competent_dewdney bash -c "apt-get update && apt-get install -y chromium-browser chromium-chromedriver"
```

### 3. 启动目标应用
对于 CVE-2024-2288，需要启动 Lollms WebUI：
```bash
docker exec competent_dewdney bash -c "
cd /path/to/lollms-webui && 
python app.py &
"
```

## 🔍 检测逻辑

系统通过以下方式判断是否使用 WebDriver：

### 触发条件
1. **CWE 类型匹配**：
   - CWE-352 (CSRF)
   - CWE-79 (XSS)
   - CWE-601 (Open Redirect)
   - CWE-1021 (Clickjacking)

2. **描述关键词**：
   - csrf, xss, clickjacking
   - browser, javascript
   - cookie, session
   - same-origin, cors

3. **安全公告内容**：
   - 包含上述关键词

### 示例输出
```
🌐 Detected web-based vulnerability (Type: csrf)
   Using WebDriver for browser automation...

🌐 Using WebDriverAgent for browser-based exploitation...
🌐 Using WebExploitCritic for browser-based validation...
```

## 🛠️ 自定义配置

### 修改目标 URL
```bash
# 方法 1: 环境变量
export WEB_DRIVER_TARGET_URL=http://192.168.1.100:8080

# 方法 2: 在命令中指定
docker exec competent_dewdney bash -c "
WEB_DRIVER_TARGET_URL=http://custom-url:port python3 main.py ...
"
```

### 修改 WebDriver 行为
编辑 `src/agents/webDriverAgent.py`：
```python
def setup_driver(self, headless: bool = True):
    chrome_options = Options()
    if headless:
        chrome_options.add_argument('--headless')  # 改为 False 显示浏览器
    # ... 其他配置
```

## 📊 代码改动总结

### main.py 改动
1. **导入新模块** (第 46-47 行)：
   ```python
   from toolbox.web_detector import requires_web_driver, get_attack_type
   from agents import ... WebDriverAgent, WebExploitCritic
   ```

2. **添加配置** (第 63 行)：
   ```python
   WEB_DRIVER_TARGET_URL = os.environ.get('WEB_DRIVER_TARGET_URL', 'http://localhost:9600')
   ```

3. **漏洞检测** (第 360-366 行)：
   ```python
   use_web_driver = requires_web_driver(self.cve_info)
   if use_web_driver:
       attack_type = get_attack_type(self.cve_info)
       print(f"🌐 Detected web-based vulnerability (Type: {attack_type})")
   ```

4. **条件分支** (第 379-393 行)：
   ```python
   if use_web_driver:
       exploiter = WebDriverAgent(...)
   else:
       exploiter = Exploiter(...)
   ```

5. **Critic 切换** (第 426-436 行)：
   ```python
   if use_web_driver:
       critic = WebExploitCritic(...)
   else:
       critic = ExploitCritic(...)
   ```

## 🐛 故障排查

### 问题 1: 找不到 chromium-chromedriver
```bash
# 解决方案
docker exec competent_dewdney apt-get update
docker exec competent_dewdney apt-get install -y chromium-chromedriver
docker exec competent_dewdney which chromium-chromedriver  # 验证
```

### 问题 2: Selenium 导入错误
```bash
# 解决方案
docker exec competent_dewdney pip install --upgrade selenium
docker exec competent_dewdney python -c "import selenium; print(selenium.__version__)"
```

### 问题 3: 目标应用无响应
```bash
# 检查应用是否运行
docker exec competent_dewdney curl -v http://localhost:9600

# 检查端口占用
docker exec competent_dewdney netstat -tuln | grep 9600
```

### 问题 4: WebDriver 超时
在 `webDriverAgent.py` 中增加等待时间：
```python
WebDriverWait(self.driver, 30)  # 从 10 改为 30 秒
```

## 📝 日志位置

- **复现日志**: `/shared/{CVE_ID}/{CVE_ID}_log.txt`
- **Exploit 日志**: `/shared/{CVE_ID}/conversations/exploiter_logs.txt`
- **截图证据**: `/shared/{CVE_ID}/*.png`
- **CSRF 攻击页面**: `/shared/{CVE_ID}/csrf_exploit.html`

## 🎯 支持的漏洞类型

- ✅ **CSRF** (CWE-352) - 如 CVE-2024-2288
- ✅ **XSS** (CWE-79) - Stored/Reflected/DOM
- ✅ **Clickjacking** (CWE-1021)
- ✅ **Open Redirect** (CWE-601)
- ⚠️ **其他 Web 漏洞** - 可能需要自定义工具

## 💡 最佳实践

1. **先测试检测**：运行 `test_webdriver_detection.py` 确认检测正常
2. **确认环境**：检查 Selenium、ChromeDriver、目标应用都已就绪
3. **监控日志**：实时查看日志了解执行进度
4. **保存证据**：WebDriver 会自动截图，注意保存
5. **清理资源**：复现完成后，WebDriver 会自动清理浏览器进程

## 🔗 相关文档

- [WebDriver Agent 详细文档](./README_WebDriver.md)
- [Web Detector 源码](../toolbox/web_detector.py)
- [CVE-2024-2288 分析](../shared/CVE-2024-2288/conversations/knowledge_builder.txt)
