#!/bin/bash

# CVE-Genie Web UI 启动脚本
# 在 Docker 容器中启动 Web 界面

set -e

echo "================================================"
echo "  🚀 CVE-Genie Web UI Launcher"
echo "================================================"
echo ""

CONTAINER_NAME="competent_dewdney"

# 检查容器是否运行
echo "🔍 检查 Docker 容器..."
if ! docker ps | grep -q "$CONTAINER_NAME"; then
    echo "❌ 容器 $CONTAINER_NAME 未运行"
    echo "请先启动容器: docker start $CONTAINER_NAME"
    exit 1
fi
echo "✅ 容器正在运行"

# 安装 Flask 和依赖（如果还没安装）
echo ""
echo "📦 检查依赖..."
docker exec $CONTAINER_NAME bash -c "pip3 show flask > /dev/null 2>&1" || {
    echo "📥 安装 Flask..."
    docker exec $CONTAINER_NAME pip3 install flask flask-cors
}
echo "✅ 依赖已就绪"

# 复制 Web UI 文件到容器
echo ""
echo "📂 复制 Web UI 文件到容器..."
docker cp web_ui/app.py $CONTAINER_NAME:/src/app.py
docker cp web_ui/templates $CONTAINER_NAME:/src/templates
echo "✅ 文件已复制"

# 启动 Web 服务
echo ""
echo "🌐 启动 Web 服务..."
echo "访问地址: http://localhost:5000"
echo ""
echo "提示:"
echo "  - 在浏览器打开 http://localhost:5000"
echo "  - 输入 CVE ID (如 CVE-2024-2288)"
echo "  - 点击"开始复现"即可"
echo "  - 按 Ctrl+C 停止服务"
echo ""
echo "================================================"
echo ""

# 在容器中启动 Flask (前台运行，方便查看日志)
docker exec -it $CONTAINER_NAME python3 /src/app.py
