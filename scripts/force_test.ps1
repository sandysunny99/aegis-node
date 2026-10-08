Write-Host "============================================="
Write-Host "PULLING LATEST & REBUILDING"
Write-Host "============================================="
git pull origin main

docker compose build --no-cache app
docker compose up -d
$exitCode = $LASTEXITCODE
if ($exitCode -ne 0) {
    Write-Error "LOCAL DOCKER START FAILED"
    exit 1
}

Write-Host "`nWaiting 10 seconds for containers to initialize..."
Start-Sleep -Seconds 10

$health = docker inspect aegis-clamav-rest --format '{{.State.Health.Status}}'
if ($health -ne "healthy") {
    Write-Error "CLAMAV REST IS NOT HEALTHY (Status: $health)"
    exit 1
}

Write-Host "`n============================================="
Write-Host "RUNNING INTERNAL EICAR TEST"
Write-Host "============================================="
.\scripts\internal_eicar_test.ps1

Write-Host "`n============================================="
Write-Host "EXTRACTING DEBUG LOG"
Write-Host "============================================="
.\scripts\debug_scan.ps1
