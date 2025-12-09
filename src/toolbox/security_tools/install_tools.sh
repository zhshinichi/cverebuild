#!/bin/bash
# 安全工具Docker镜像安装脚本 (Linux/Mac版本)
# 运行方式: chmod +x install_tools.sh && ./install_tools.sh

echo "================================="
echo "  安装渗透测试工具Docker镜像"
echo "================================="
echo ""

# 检查Docker是否运行
echo "[1/6] 检查Docker状态..."
if ! docker info > /dev/null 2>&1; then
    echo "✗ Docker未运行,请先启动Docker"
    exit 1
fi
echo "✓ Docker正在运行"

# 拉取镜像
echo ""
echo "[2/6] 拉取SQLmap镜像 (SQL注入工具)..."
docker pull parrotsec/sqlmap:latest

echo ""
echo "[3/6] 拉取WPScan镜像 (WordPress扫描)..."
docker pull wpscanteam/wpscan:latest

echo ""
echo "[4/6] 拉取WhatWeb镜像 (Web指纹识别)..."
docker pull ilyaglow/whatweb:latest

echo ""
echo "[5/6] 拉取Nikto镜像 (通用Web扫描)..."
docker pull securecodebox/scanner-nikto:latest

echo ""
echo "[6/6] 拉取OWASP ZAP镜像 (可选,较大)..."
read -p "是否安装ZAP? (y/N): " response
if [[ "$response" =~ ^[Yy]$ ]]; then
    docker pull owasp/zap2docker-stable:latest
else
    echo "跳过ZAP安装"
fi

# 验证安装
echo ""
echo "================================="
echo "  验证安装"
echo "================================="
echo ""
echo "已安装的工具镜像:"
docker images | grep -E "sqlmap|wpscan|whatweb|nikto|zap"

# 创建输出目录
echo ""
echo "创建输出目录..."
mkdir -p ./output
echo "✓ 输出目录: $(pwd)/output"

# 测试运行
echo ""
echo "================================="
echo "  测试工具运行"
echo "================================="

echo ""
echo "测试SQLmap..."
docker run --rm parrotsec/sqlmap --version

echo ""
echo "测试WPScan..."
docker run --rm wpscanteam/wpscan --version

echo ""
echo "测试WhatWeb..."
docker run --rm ilyaglow/whatweb --version

echo ""
echo "================================="
echo "  ✓ 安装完成!"
echo "================================="
echo ""
echo "使用示例:"
echo "  SQLmap:  docker run --rm --network host parrotsec/sqlmap -u 'http://target/?id=1' --batch"
echo "  WPScan:  docker run --rm --network host wpscanteam/wpscan --url http://target"
echo "  WhatWeb: docker run --rm --network host ilyaglow/whatweb http://target"
echo ""
