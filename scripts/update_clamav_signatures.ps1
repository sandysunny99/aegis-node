Write-Host "============================================="
Write-Host "AEGIS NODE CLAMAV SIGNATURE UPDATER"
Write-Host "============================================="

# 1. Check Docker
docker --version > $null
if ($LASTEXITCODE -ne 0) {
    Write-Error "Docker is not available."
    exit 1
}

# 2. Check that aegis-clamav-daemon exists and is running
$daemonStatus = docker ps --filter "name=aegis-clamav-daemon" --format "{{.Status}}"
if (-not $daemonStatus) {
    Write-Error "aegis-clamav-daemon container is not running. Please start the stack first."
    exit 1
}
Write-Host "aegis-clamav-daemon is running ($daemonStatus)"

# 3. Inspect FreshClam state
Write-Host "`n[1/4] Checking existing FreshClam logs..."
docker logs aegis-clamav-daemon | Select-String "freshclam" | Select-Object -Last 5

Write-Host "`n[2/4] Checking current database timestamps..."
docker exec aegis-clamav-daemon sh -c "ls -lah --time-style=long-iso /var/lib/clamav"

# 4. Run or allow FreshClam to update safely
Write-Host "`n[3/4] Running manual FreshClam update safely..."
Write-Host "NOTE: If it reports 'locked', the automatic updater is already running, which is fine."
docker exec aegis-clamav-daemon freshclam --verbose

# 5. Show the updated database timestamps
Write-Host "`n[4/4] Verifying updated database timestamps..."
docker exec aegis-clamav-daemon sh -c "ls -lah --time-style=long-iso /var/lib/clamav"

Write-Host "`n============================================="
Write-Host "SIGNATURE UPDATE COMPLETE"
Write-Host "============================================="
