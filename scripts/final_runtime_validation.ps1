param (
    [switch]$SkipWait
)

Write-Host "============================================="
Write-Host "AEGIS NODE FINAL LOCAL RUNTIME VALIDATION"
Write-Host "============================================="

# 1. Verify Docker
Write-Host "`n[1/5] Checking Docker..."
if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
    Write-Host "DOCKER_RUNTIME_UNAVAILABLE"
    exit 1
}

$dockerVer = docker --version
$composeVer = docker compose version
Write-Host "Found $dockerVer"
Write-Host "Found $composeVer"

# 2. Check config
Write-Host "`n[2/5] Checking Docker Compose Config..."
docker compose config > $null
if ($LASTEXITCODE -ne 0) {
    Write-Error "Docker compose config failed."
    exit 1
}
Write-Host "Config is valid."

# 3. Start stack
Write-Host "`n[3/5] Starting Local Services..."
docker compose up -d
docker compose ps

# 4. Wait for health
Write-Host "`n[4/5] Waiting for Aegis Node and ClamAV to become healthy..."
if (-not $SkipWait) {
    Write-Host "Note: A fresh ClamAV container may take 1-3 minutes to download signatures."
}
$maxAttempts = 30
$attempt = 1
$healthy = $false

while ($attempt -le $maxAttempts) {
    try {
        $health = Invoke-RestMethod -Uri "http://localhost:8000/health" -Method Get -ErrorAction Stop
        if ($health.av_available -eq $true -and $health.av_provider -eq "clamav_rest") {
            $healthy = $true
            Write-Host "`nSuccess! Aegis Node is healthy."
            Write-Host "Health Response:"
            $health | ConvertTo-Json -Depth 3 | Write-Host
            break
        } else {
            Write-Host -NoNewline "."
        }
    } catch {
        Write-Host -NoNewline "."
    }
    Start-Sleep -Seconds 5
    $attempt++
}

if (-not $healthy) {
    Write-Error "`nFailed to reach healthy state. Check logs with 'docker compose logs'."
    exit 1
}

# 5. Create EICAR test file
Write-Host "`n[5/5] Creating EICAR Test Artifact..."
$eicarPath = ".\eicar.txt"
$eicarString = 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'
Set-Content -Path $eicarPath -Value $eicarString -NoNewline
Write-Host "Created eicar.txt in repository root."

# Create Safe Synthetic dataset
$safeDatasetPath = ".\safe_dataset.csv"
$safeCsv = "id,name,role`n1,Alice,Engineer`n2,Bob,Manager"
Set-Content -Path $safeDatasetPath -Value $safeCsv
Write-Host "Created safe_dataset.csv in repository root."

Write-Host "`n============================================="
Write-Host "READY FOR MANUAL VALIDATION"
Write-Host "============================================="
Write-Host "1. Open http://localhost:8000 in your browser."
Write-Host "2. Upload 'eicar.txt' through the UI."
Write-Host "   Verify the verdict is MALICIOUS and provider is clamav_rest."
Write-Host "3. Upload 'safe_dataset.csv' through the UI."
Write-Host "   Verify the full pipeline completes."
Write-Host "`nDo NOT upload eicar.txt to public services like VirusTotal!"
Write-Host "`nTo clean up after validation:"
Write-Host "Remove-Item eicar.txt, safe_dataset.csv"
Write-Host "docker compose down"
Write-Host "============================================="


