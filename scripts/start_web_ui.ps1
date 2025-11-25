# 启动 Web UI 服务
$ContainerName = "competent_dewdney"

Write-Host "启动 CVE-Genie Web UI..." -ForegroundColor Cyan
Write-Host ""

# 1. 检查容器
$running = docker ps --format "{{.Names}}" | Select-String $ContainerName
if (-not $running) {
    Write-Host "容器未运行，正在启动..." -ForegroundColor Yellow
    docker start $ContainerName
    Start-Sleep -Seconds 2
}

# 2. 安装 Flask 依赖
Write-Host "安装依赖..." -ForegroundColor Yellow
docker exec $ContainerName pip3 install -q flask flask-cors

# 3. 复制 Web UI 文件
Write-Host "部署 Web UI 文件..." -ForegroundColor Yellow
docker cp web_ui/app.py ${ContainerName}:/src/app.py
docker cp web_ui/templates/index.html ${ContainerName}:/src/templates/index.html

# 4. 检查端口映射
$ports = docker ps --format "{{.Ports}}" --filter "name=$ContainerName"
if ($ports -match "5000") {
    Write-Host ""
    Write-Host "访问地址: http://localhost:5000" -ForegroundColor Green
} else {
    $ip = docker inspect $ContainerName | ConvertFrom-Json | Select-Object -First 1
    $containerIP = $ip[0].NetworkSettings.Networks.PSObject.Properties.Value.IPAddress | Select-Object -First 1
    Write-Host ""
    Write-Host "访问地址: http://${containerIP}:5000" -ForegroundColor Green
    Write-Host "(容器 IP，只能在本机访问)" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "正在启动服务..." -ForegroundColor Cyan
Write-Host "按 Ctrl+C 停止服务" -ForegroundColor Gray
Write-Host ""

# 5. 启动 Flask
docker exec -it $ContainerName python3 /src/app.py
