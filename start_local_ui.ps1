# 在本地启动 Web UI（不在 Docker 内运行）
Write-Host "启动本地 Web UI..." -ForegroundColor Cyan
Write-Host ""

# 检查 Flask 是否安装
$flaskInstalled = pip show flask 2>$null
if (-not $flaskInstalled) {
    Write-Host "安装 Flask..." -ForegroundColor Yellow
    pip install flask flask-cors
}

Write-Host "启动服务..." -ForegroundColor Green
Write-Host "访问地址: http://localhost:5000" -ForegroundColor Cyan
Write-Host "按 Ctrl+C 停止服务" -ForegroundColor Gray
Write-Host ""

# 启动 Flask（本地运行）
python web_ui/app.py
