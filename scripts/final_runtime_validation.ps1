$ErrorActionPreference = "Stop"

Write-Host "============================================="
Write-Host "AEGIS NODE CLAMAV PIPELINE VALIDATION"
Write-Host "============================================="

if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
    throw "Docker CLI is unavailable."
}

Write-Host "`nValidating Docker Compose configuration..."
docker compose config --quiet
if ($LASTEXITCODE -ne 0) {
    throw "docker compose config failed."
}

Write-Host "`nStarting the app and its declared healthy dependencies..."
docker compose up -d --build app
if ($LASTEXITCODE -ne 0) {
    throw "Could not start the Compose app service and its dependencies."
}

docker compose ps
if ($LASTEXITCODE -ne 0) {
    throw "Could not inspect Compose service status."
}

Write-Host "`nRunning readiness-gated harmless-file and EICAR scans through Aegis..."
& (Join-Path $PSScriptRoot "internal_eicar_test.ps1")
if ($LASTEXITCODE -ne 0) {
    throw "Aegis ClamAV E2E validation failed."
}

Write-Host "`nAegis ClamAV runtime and E2E validation passed."
