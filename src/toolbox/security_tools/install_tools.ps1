# 安全工具Docker镜像安装脚本
# 运行方式: .\install_tools.ps1

Write-Host "=================================" -ForegroundColor Cyan
Write-Host "  安装渗透测试工具Docker镜像" -ForegroundColor Cyan
Write-Host "=================================" -ForegroundColor Cyan
Write-Host ""

# 检查Docker是否运行
Write-Host "[1/6] 检查Docker状态..." -ForegroundColor Yellow
try {
    docker info | Out-Null
    Write-Host "✓ Docker正在运行" -ForegroundColor Green
} catch {
    Write-Host "✗ Docker未运行,请先启动Docker Desktop" -ForegroundColor Red
    exit 1
}

# 拉取镜像
Write-Host ""
Write-Host "[2/6] 拉取SQLmap镜像 (SQL注入工具)..." -ForegroundColor Yellow
docker pull parrotsec/sqlmap:latest

Write-Host ""
Write-Host "[3/6] 拉取WPScan镜像 (WordPress扫描)..." -ForegroundColor Yellow
docker pull wpscanteam/wpscan:latest

Write-Host ""
Write-Host "[4/6] 拉取WhatWeb镜像 (Web指纹识别)..." -ForegroundColor Yellow
docker pull ilyaglow/whatweb:latest

Write-Host ""
Write-Host "[5/6] 拉取Nikto镜像 (通用Web扫描)..." -ForegroundColor Yellow
docker pull securecodebox/scanner-nikto:latest

Write-Host ""
Write-Host "[6/6] 拉取OWASP ZAP镜像 (可选,较大)..." -ForegroundColor Yellow
$response = Read-Host "是否安装ZAP? (y/N)"
if ($response -eq 'y' -or $response -eq 'Y') {
    docker pull owasp/zap2docker-stable:latest
} else {
    Write-Host "跳过ZAP安装" -ForegroundColor Gray
}

# 验证安装
Write-Host ""
Write-Host "=================================" -ForegroundColor Cyan
Write-Host "  验证安装" -ForegroundColor Cyan
Write-Host "=================================" -ForegroundColor Cyan

Write-Host ""
Write-Host "已安装的工具镜像:" -ForegroundColor Green
docker images | Select-String -Pattern "sqlmap|wpscan|whatweb|nikto|zap"

# 创建输出目录
Write-Host ""
Write-Host "创建输出目录..." -ForegroundColor Yellow
New-Item -ItemType Directory -Force -Path ".\output" | Out-Null
Write-Host "✓ 输出目录: $PWD\output" -ForegroundColor Green

# 测试运行
Write-Host ""
Write-Host "=================================" -ForegroundColor Cyan
Write-Host "  测试工具运行" -ForegroundColor Cyan
Write-Host "=================================" -ForegroundColor Cyan

Write-Host ""
Write-Host "测试SQLmap..." -ForegroundColor Yellow
docker run --rm parrotsec/sqlmap --version

Write-Host ""
Write-Host "测试WPScan..." -ForegroundColor Yellow
docker run --rm wpscanteam/wpscan --version

Write-Host ""
Write-Host "测试WhatWeb..." -ForegroundColor Yellow
docker run --rm ilyaglow/whatweb --version

Write-Host ""
Write-Host "=================================" -ForegroundColor Green
Write-Host "  ✓ 安装完成!" -ForegroundColor Green
Write-Host "=================================" -ForegroundColor Green
Write-Host ""
Write-Host "使用示例:" -ForegroundColor Cyan
Write-Host "  SQLmap:  docker run --rm --network host parrotsec/sqlmap -u 'http://target/?id=1' --batch" -ForegroundColor Gray
Write-Host "  WPScan:  docker run --rm --network host wpscanteam/wpscan --url http://target" -ForegroundColor Gray
Write-Host "  WhatWeb: docker run --rm --network host ilyaglow/whatweb http://target" -ForegroundColor Gray
Write-Host ""
