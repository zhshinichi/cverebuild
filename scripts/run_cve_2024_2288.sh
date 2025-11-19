#!/bin/bash
# CVE-2024-2288 复现示例脚本
# CSRF + XSS 漏洞，需要使用 WebDriver

echo "=========================================="
echo "CVE-2024-2288 复现脚本"
echo "CSRF in Lollms WebUI Avatar Upload"
echo "=========================================="
echo ""

# 配置
CVE_ID="CVE-2024-2288"
TARGET_URL="http://localhost:9600"
JSON_FILE="data/large_scale/data.json"

# 检查 Docker 容器是否运行
echo "🔍 检查 Docker 容器..."
if ! docker ps | grep -q competent_dewdney; then
    echo "❌ 容器 competent_dewdney 未运行"
    exit 1
fi
echo "✅ 容器正在运行"
echo ""

# 检查 Selenium 是否安装
echo "🔍 检查 Selenium 安装..."
if ! docker exec competent_dewdney python -c "import selenium" 2>/dev/null; then
    echo "📦 安装 Selenium..."
    docker exec competent_dewdney pip install selenium
fi
echo "✅ Selenium 已安装"
echo ""

# 检查 ChromeDriver 是否安装
echo "🔍 检查 ChromeDriver 安装..."
if ! docker exec competent_dewdney which chromium-chromedriver >/dev/null 2>&1; then
    echo "📦 安装 ChromeDriver..."
    docker exec competent_dewdney bash -c "apt-get update && apt-get install -y chromium-browser chromium-chromedriver"
fi
echo "✅ ChromeDriver 已安装"
echo ""

# 启动目标应用（如果需要）
echo "🚀 检查目标应用..."
if ! docker exec competent_dewdney curl -s $TARGET_URL >/dev/null 2>&1; then
    echo "⚠️  目标应用未运行在 $TARGET_URL"
    echo "   请手动启动 Lollms WebUI:"
    echo "   docker exec competent_dewdney bash -c 'cd /path/to/lollms-webui && python app.py &'"
    read -p "   按回车继续..."
else
    echo "✅ 目标应用正在运行"
fi
echo ""

# 运行 CVE 复现
echo "=========================================="
echo "开始复现 $CVE_ID"
echo "=========================================="
echo ""

docker exec competent_dewdney bash -c "
cd /workspaces/submission/src && \
ENV_PATH=.env \
MODEL=gpt-4o \
WEB_DRIVER_TARGET_URL=$TARGET_URL \
python3 main.py \
  --cve $CVE_ID \
  --json $JSON_FILE \
  --run-type build,exploit,verify
"

EXIT_CODE=$?

echo ""
echo "=========================================="
if [ $EXIT_CODE -eq 0 ]; then
    echo "✅ 复现完成"
    echo "查看结果: docker exec competent_dewdney cat /shared/$CVE_ID/${CVE_ID}_log.txt"
else
    echo "❌ 复现失败 (退出码: $EXIT_CODE)"
fi
echo "=========================================="

# 同步结果到本地
echo ""
echo "📥 同步结果到本地..."
docker cp competent_dewdney:/shared/$CVE_ID/. ./src/shared/$CVE_ID/

echo "✅ 完成！"
