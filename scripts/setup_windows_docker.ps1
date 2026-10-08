Write-Host "============================================="
Write-Host "AEGIS NODE - WINDOWS DOCKER DESKTOP SETUP"
Write-Host "============================================="

# 1. Check Windows
if ($IsLinux -or $IsMacOS) {
    Write-Error "This script is intended for Windows only."
    exit 1
}

# 4 & 5. Check WSL
Write-Host "`n[1/4] Checking WSL status..."
$wslExists = Get-Command wsl -ErrorAction SilentlyContinue
if (-not $wslExists) {
    Write-Host "WSL is not installed or not in PATH."
    Write-Host "Please enable WSL 2. You can usually do this by running wsl --install as Administrator."
    exit 1
} else {
    Write-Host "WSL is available."
    wsl --version
}

# 2 & 3. Check Docker
Write-Host "`n[2/4] Checking Docker installation..."
$dockerExists = Get-Command docker -ErrorAction SilentlyContinue

if (-not $dockerExists) {
    Write-Host "DOCKER_DESKTOP_REQUIRED"
    Write-Host "Docker Desktop is not installed."
    Write-Host "Official instructions: https://docs.docker.com/desktop/setup/install/windows-install/"
    
    $wingetExists = Get-Command winget -ErrorAction SilentlyContinue
    if ($wingetExists) {
        Write-Host "`nWinget is available. You can install Docker Desktop via winget:"
        Write-Host "winget install -e --id Docker.DockerDesktop"
    }
    
    Write-Host "`nPlease install Docker Desktop manually using the official installer or winget."
    exit 1
}

Write-Host "`n[3/4] Docker executable found. Checking if Docker daemon is running..."
$dockerVersion = docker version 2>&1
if ($LASTEXITCODE -ne 0) {
    Write-Host "DOCKER_DAEMON_NOT_RUNNING"
    Write-Host "Please START Docker Desktop from your Start Menu and wait for the engine to initialize."
    
    Write-Host "`nWaiting for Docker daemon to start..."
    $maxAttempts = 30
    $attempt = 1
    $running = $false
    while ($attempt -le $maxAttempts) {
        $check = docker version 2> $null
        if ($LASTEXITCODE -eq 0) {
            $running = $true
            break
        }
        Write-Host -NoNewline "."
        Start-Sleep -Seconds 5
        $attempt++
    }
    
    if (-not $running) {
        Write-Error "`nDocker daemon did not start in time. Please start it manually and run this script again."
        exit 1
    }
    Write-Host "`nDocker daemon is running!"
} else {
    Write-Host "Docker daemon is running."
}

Write-Host "`n[4/4] Checking docker compose version..."
docker compose version
if ($LASTEXITCODE -ne 0) {
    Write-Error "docker compose is not available. Please ensure Docker Desktop is fully updated."
    exit 1
}

Write-Host "`n============================================="
Write-Host "DOCKER IS READY"
Write-Host "============================================="
Write-Host "You may now run:"
Write-Host ".\scripts\final_runtime_validation.ps1"
Write-Host "============================================="
