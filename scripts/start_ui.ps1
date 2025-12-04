# Start Web UI
$ContainerName = "competent_dewdney"

Write-Host "Checking container..."
$running = docker ps --format "{{.Names}}" | Select-String $ContainerName

if (-not $running) {
    Write-Host "Starting container..."
    docker start $ContainerName
    Start-Sleep -Seconds 2
}

Write-Host "Starting Web UI at http://localhost:5001"
cd web_ui
python app.py
