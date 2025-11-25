# Docker 容器配置检查脚本
$ContainerName = "competent_dewdney"

Write-Host "检查容器配置..." -ForegroundColor Cyan

# 1. 检查容器存在
Write-Host "1. 检查容器是否存在..." -ForegroundColor Yellow
$exists = docker ps -a --format "table {{.Names}}" | Select-String $ContainerName
if ($exists) {
    Write-Host "   OK - 容器存在" -ForegroundColor Green
} else {
    Write-Host "   ERROR - 容器不存在" -ForegroundColor Red
    exit 1
}

# 2. 检查容器运行状态
Write-Host "2. 检查容器是否运行..." -ForegroundColor Yellow
$running = docker ps --format "table {{.Names}}" | Select-String $ContainerName
if ($running) {
    Write-Host "   OK - 容器正在运行" -ForegroundColor Green
} else {
    Write-Host "   WARN - 容器未运行，正在启动..." -ForegroundColor Yellow
    docker start $ContainerName
    Start-Sleep -Seconds 2
}

# 3. 检查端口映射
Write-Host "3. 检查端口映射..." -ForegroundColor Yellow
$ports = docker ps --format "{{.Ports}}" --filter "name=$ContainerName"
if ($ports -match "5000") {
    Write-Host "   OK - 端口 5000 已映射" -ForegroundColor Green
    Write-Host "   访问: http://localhost:5000" -ForegroundColor Cyan
    $hasPort = $true
} else {
    Write-Host "   WARN - 端口 5000 未映射" -ForegroundColor Yellow
    $ip = docker inspect -f "((range .NetworkSettings.Networks))(($.IPAddress))((/range))" $ContainerName
    $ip = $ip -replace '\(|\)',''
    Write-Host "   可使用容器 IP: http://${ip}:5000" -ForegroundColor Cyan
    Write-Host "   或重建容器: docker run -d -p 5000:5000 --name $ContainerName IMAGE" -ForegroundColor Gray
    $hasPort = $false
}

# 4. 检查目录
Write-Host "4. 检查必要目录..." -ForegroundColor Yellow
docker exec $ContainerName test -d /src 2>&1 | Out-Null
if ($LASTEXITCODE -eq 0) {
    Write-Host "   OK - /src 存在" -ForegroundColor Green
} else {
    Write-Host "   WARN - /src 不存在" -ForegroundColor Yellow
}

docker exec $ContainerName test -d /shared 2>&1 | Out-Null
if ($LASTEXITCODE -eq 0) {
    Write-Host "   OK - /shared 存在" -ForegroundColor Green
} else {
    Write-Host "   WARN - /shared 不存在" -ForegroundColor Yellow
}

# 5. 检查 Python
Write-Host "5. 检查 Python..." -ForegroundColor Yellow
$pyver = docker exec $ContainerName python3 --version 2>&1
if ($LASTEXITCODE -eq 0) {
    Write-Host "   OK - $pyver" -ForegroundColor Green
} else {
    Write-Host "   ERROR - Python 未安装" -ForegroundColor Red
}

Write-Host ""
Write-Host "检查完成!" -ForegroundColor Cyan
if ($hasPort) {
    Write-Host "可以运行: .\scripts\start_web_ui.ps1" -ForegroundColor Green
}
