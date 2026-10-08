Write-Host "============================================="
Write-Host "FORCING LATEST FIXES & REBUILD"
Write-Host "============================================="
git fetch origin
git reset --hard origin/main

docker compose build --no-cache app
docker compose up -d

Write-Host "`nWaiting 5 seconds for app to initialize..."
Start-Sleep -Seconds 5

Write-Host "`n============================================="
Write-Host "RUNNING INTERNAL EICAR TEST"
Write-Host "============================================="
.\scripts\internal_eicar_test.ps1

Write-Host "`n============================================="
Write-Host "EXTRACTING DEBUG LOG"
Write-Host "============================================="
.\scripts\debug_scan.ps1
