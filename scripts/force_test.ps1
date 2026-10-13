$ErrorActionPreference = "Stop"

Write-Host "Running local Aegis ClamAV pipeline validation without changing Git state..."
& (Join-Path $PSScriptRoot "final_runtime_validation.ps1")
if ($LASTEXITCODE -ne 0) {
    throw "Aegis ClamAV pipeline validation failed."
}
