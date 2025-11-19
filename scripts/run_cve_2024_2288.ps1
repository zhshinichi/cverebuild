# CVE-2024-2288 复现示例脚本 (PowerShell)
# CSRF + XSS 漏洞，需要使用 WebDriver

Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "CVE-2024-2288 复现脚本" -ForegroundColor Cyan
Write-Host "CSRF in Lollms WebUI Avatar Upload" -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host ""

# 配置
$CVE_ID = "CVE-2024-2288"
$TARGET_URL = "http://localhost:9600"
$JSON_FILE = "data/large_scale/data.json"
$CONTAINER = "competent_dewdney"

# 检查 Docker 容器是否运行
Write-Host "🔍 检查 Docker 容器..." -ForegroundColor Yellow
$containerRunning = docker ps --format "{{.Names}}" | Select-String -Pattern $CONTAINER
if (-not $containerRunning) {
    Write-Host "❌ 容器 $CONTAINER 未运行" -ForegroundColor Red
    exit 1
}
Write-Host "✅ 容器正在运行" -ForegroundColor Green
Write-Host ""

# 检查 Selenium 是否安装
Write-Host "🔍 检查 Selenium 安装..." -ForegroundColor Yellow
$seleniumInstalled = docker exec $CONTAINER python -c "import selenium" 2>&1
if ($LASTEXITCODE -ne 0) {
    Write-Host "📦 安装 Selenium..." -ForegroundColor Yellow
    docker exec $CONTAINER pip install selenium
}
Write-Host "✅ Selenium 已安装" -ForegroundColor Green
Write-Host ""

# 检查 ChromeDriver 是否安装
Write-Host "🔍 检查 ChromeDriver 安装..." -ForegroundColor Yellow
$chromeDriverInstalled = docker exec $CONTAINER which chromium-chromedriver 2>&1
if ($LASTEXITCODE -ne 0) {
    Write-Host "📦 安装 ChromeDriver..." -ForegroundColor Yellow
    docker exec $CONTAINER bash -c "apt-get update && apt-get install -y chromium-browser chromium-chromedriver"
}
Write-Host "✅ ChromeDriver 已安装" -ForegroundColor Green
Write-Host ""

# 启动目标应用（如果需要）
Write-Host "🚀 检查目标应用..." -ForegroundColor Yellow
$appRunning = docker exec $CONTAINER curl -s $TARGET_URL 2>&1
if ($LASTEXITCODE -ne 0) {
    Write-Host "⚠️  目标应用未运行在 $TARGET_URL" -ForegroundColor Yellow
    Write-Host "   请手动启动 Lollms WebUI:" -ForegroundColor Yellow
    Write-Host "   docker exec $CONTAINER bash -c 'cd /path/to/lollms-webui && python app.py &'" -ForegroundColor Yellow
    Read-Host "   按回车继续"
} else {
    Write-Host "✅ 目标应用正在运行" -ForegroundColor Green
}
Write-Host ""

# 运行 CVE 复现
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "开始复现 $CVE_ID" -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host ""

$command = @"
cd /workspaces/submission/src && 
ENV_PATH=.env 
MODEL=gpt-4o 
WEB_DRIVER_TARGET_URL=$TARGET_URL 
python3 main.py 
  --cve $CVE_ID 
  --json $JSON_FILE 
  --run-type build,exploit,verify
"@

docker exec $CONTAINER bash -c $command

$exitCode = $LASTEXITCODE

Write-Host ""
Write-Host "==========================================" -ForegroundColor Cyan
if ($exitCode -eq 0) {
    Write-Host "✅ 复现完成" -ForegroundColor Green
    Write-Host "查看结果: docker exec $CONTAINER cat /shared/$CVE_ID/${CVE_ID}_log.txt"
} else {
    Write-Host "❌ 复现失败 (退出码: $exitCode)" -ForegroundColor Red
}
Write-Host "==========================================" -ForegroundColor Cyan

# 同步结果到本地
Write-Host ""
Write-Host "📥 同步结果到本地..." -ForegroundColor Yellow
$localPath = "C:\Users\shinichi\submission\src\shared\$CVE_ID"
if (-not (Test-Path $localPath)) {
    New-Item -ItemType Directory -Path $localPath -Force | Out-Null
}
docker cp "${CONTAINER}:/shared/$CVE_ID/." $localPath

Write-Host "✅ 完成！" -ForegroundColor Green
Write-Host "本地结果路径: $localPath" -ForegroundColor Cyan
