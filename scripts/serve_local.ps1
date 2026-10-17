# Build the frontend from the current branch and serve it with the API on http://localhost:8000
# Usage (from the repo root, in PowerShell):  .\scripts\serve_local.ps1
# APP_ENV is forced to development for this process only, because .env sets production and the
# app (correctly) refuses to start in production with Cloudflare's test Turnstile keys.
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot

Push-Location (Join-Path $root "frontend")
npm run build
Pop-Location

$static = Join-Path $root "backend\static"
if (Test-Path $static) { Remove-Item -Recurse -Force $static }
Copy-Item -Recurse (Join-Path $root "frontend\dist") $static

$env:APP_ENV = "development"
Push-Location (Join-Path $root "backend")
& (Join-Path $root ".venv\Scripts\python.exe") -m uvicorn main:app --host 127.0.0.1 --port 8000
Pop-Location
