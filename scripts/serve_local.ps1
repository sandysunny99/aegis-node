# Build the frontend from the current branch and serve it with the API on http://127.0.0.1:<port>
# Usage (from the repo root, in PowerShell):  .\scripts\serve_local.ps1            (port 8000)
#                                             .\scripts\serve_local.ps1 -Port 8001 (if 8000 is busy)
# APP_ENV is forced to development for this process only, because .env sets production and the
# app (correctly) refuses to start in production with Cloudflare's test Turnstile keys.
param([int]$Port = 8000)
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot

$busy = Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction SilentlyContinue
if ($busy) {
  Write-Error "Port $Port is already in use (process $($busy[0].OwningProcess)). Stop it, or run with -Port 8001."
}

Push-Location (Join-Path $root "frontend")
npm run build
Pop-Location

$static = Join-Path $root "backend\static"
if (Test-Path $static) { Remove-Item -Recurse -Force $static }
Copy-Item -Recurse (Join-Path $root "frontend\dist") $static

$env:APP_ENV = "development"
Write-Host "Aegis Node: http://127.0.0.1:$Port  (app: /#/app, styleguide: /#/styleguide)"
Push-Location (Join-Path $root "backend")
& (Join-Path $root ".venv\Scripts\python.exe") -m uvicorn main:app --host 127.0.0.1 --port $Port
Pop-Location
