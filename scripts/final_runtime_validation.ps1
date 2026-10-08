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
            
            $isClamAv = ($health.av_provider -eq "clamav_rest")
            $isAvAvailable = ($health.av_available -eq $true)
            $isMock = ($health.av_mock_mode -eq $true)
            $avVersion = $health.av_version

            if (-not $isClamAv -or -not $isAvAvailable -or $isMock) {
                Write-Error "CRITICAL: AV provider state is not correct! Must be clamav_rest, available, and not mocked."
                exit 1
            }

            if ($avVersion -eq "Unknown") {
                Write-Host "`nWARN: AV_VERSION_UNRESOLVED - The actual version string could not be extracted." -ForegroundColor Yellow
            } else {
                Write-Host "`nAV Version verified: $avVersion" -ForegroundColor Green
            }
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
Write-Host "READY FOR DEFINITIVE VALIDATION"
Write-Host "============================================="
Write-Host "1. IMPORTANT: Run .\scripts\update_clamav_signatures.ps1 to verify signatures."
Write-Host "2. Go to Windows Security -> Virus & threat protection -> Manage settings -> Turn OFF Real-time protection temporarily."
Write-Host "   (If you do not do this, Windows will instantly delete the eicar.txt file before you can test it!)"
Write-Host "3. Run this script again to recreate eicar.txt if Windows already deleted it."
Write-Host "4. Open http://localhost:8000 in your browser (do NOT use 5173)."
Write-Host "5. Upload 'eicar.txt' and capture the ClamAV MALICIOUS verdict."
Write-Host "6. Click 'Scan Another Dataset', upload 'safe_dataset.csv', and capture the full E2E pipeline result."
Write-Host "7. Turn Real-time protection back ON."
Write-Host "============================================="


