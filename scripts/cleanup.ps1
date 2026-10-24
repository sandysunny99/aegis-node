<#
Stop the local Aegis Docker stack. Safe by default: containers stop, all data is kept.

  .\scripts\cleanup.ps1                  # docker compose down; volumes (scan history, artifacts, ClamAV db) kept
  .\scripts\cleanup.ps1 -DryRun          # show what would happen and change nothing
  .\scripts\cleanup.ps1 -StopListeners   # also offer to stop local dev servers on ports 8000 and 5173,
                                         # one confirmation per process, python/uvicorn/node only
  .\scripts\cleanup.ps1 -RemoveVolumes   # ALSO delete the Aegis volumes after typing DELETE AEGIS DATA

Deleting volumes without a console (CI, an agent) is refused unless
-ConfirmDeletion "DELETE AEGIS DATA" is given. Safe to rerun.
#>
param(
    [switch]$DryRun,
    [switch]$StopListeners,
    [switch]$RemoveVolumes,
    [string]$ConfirmDeletion = ""
)
$ErrorActionPreference = "Stop"
$ConfirmPhrase = "DELETE AEGIS DATA"
$DevPorts = @(8000, 5173)
$DevProcessNames = @("python", "python3", "pythonw", "uvicorn", "node")
$Interactive = [Environment]::UserInteractive -and -not [Console]::IsInputRedirected
$root = Split-Path -Parent $PSScriptRoot

# Check the deletion confirmation before doing anything, so a refused run changes nothing.
if ($RemoveVolumes -and -not $DryRun) {
    if ($ConfirmDeletion -and $ConfirmDeletion -cne $ConfirmPhrase) {
        Write-Host "-ConfirmDeletion does not match '$ConfirmPhrase'. Nothing was changed."
        exit 3
    }
    if (-not $ConfirmDeletion -and -not $Interactive) {
        Write-Host "Refusing to delete volumes without a console. Pass -ConfirmDeletion '$ConfirmPhrase' to do it deliberately. Nothing was changed."
        exit 3
    }
}

if ($StopListeners) {
    foreach ($port in $DevPorts) {
        $connections = @(Get-NetTCPConnection -LocalPort $port -State Listen -ErrorAction SilentlyContinue)
        foreach ($conn in $connections) {
            $proc = Get-Process -Id $conn.OwningProcess -ErrorAction SilentlyContinue
            if (-not $proc) { continue }
            $label = "PID $($proc.Id) ($($proc.ProcessName)) on port $port"
            if ($DevProcessNames -notcontains $proc.ProcessName.ToLower()) {
                Write-Host "Leaving $label alone: not a known dev server."
                continue
            }
            if ($DryRun) {
                Write-Host "[dry run] Would offer to stop $label."
                continue
            }
            if (-not $Interactive) {
                Write-Host "Not stopping ${label}: that needs a confirmation at the console."
                continue
            }
            if ((Read-Host "Stop ${label}? [y/N]") -eq "y") {
                Stop-Process -Id $proc.Id
                Write-Host "Stopped $label."
            }
        }
    }
}

Push-Location $root
try {
    if ($DryRun) {
        Write-Host "[dry run] Would run: docker compose down (volumes kept)."
    } else {
        Write-Host "Stopping the Aegis containers (volumes kept)..."
        docker compose down
        if ($LASTEXITCODE -ne 0) { throw "docker compose down failed." }
    }

    if ($RemoveVolumes) {
        $config = (docker compose config --format json) -join "`n" | ConvertFrom-Json
        $declared = @()
        if ($config.volumes) {
            $declared = @($config.volumes.PSObject.Properties | ForEach-Object { $_.Value.name } | Where-Object { $_ })
        }
        $existing = @(docker volume ls --format "{{.Name}}")
        $doomed = @($declared | Where-Object { $existing -contains $_ })
        if (-not $doomed) {
            Write-Host "No Aegis volumes exist. Nothing to delete."
        } else {
            Write-Host "Compose project '$($config.name)': these volumes and everything in them will be deleted:"
            $doomed | ForEach-Object { Write-Host "  - $_" }
            if ($DryRun) {
                Write-Host "[dry run] No volumes deleted."
            } else {
                $typed = $ConfirmDeletion
                if (-not $typed) { $typed = Read-Host "Type '$ConfirmPhrase' to delete them" }
                if ($typed -cne $ConfirmPhrase) {
                    Write-Host "Confirmation did not match. No volumes deleted."
                    exit 3
                }
                docker volume rm @doomed
                if ($LASTEXITCODE -ne 0) { throw "docker volume rm failed." }
                Write-Host "Deleted $($doomed.Count) volume(s)."
            }
        }
    }
} finally {
    Pop-Location
}
Write-Host "Cleanup complete."
