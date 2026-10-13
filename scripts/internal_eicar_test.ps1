$ErrorActionPreference = "Stop"

function Get-ContainerHealth([string]$Name) {
    $status = docker inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' $Name 2>$null
    if ($LASTEXITCODE -ne 0) {
        return "missing"
    }
    return "$status".Trim()
}

function Wait-ContainerHealthy([string]$Name, [int]$TimeoutSeconds) {
    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    do {
        $status = Get-ContainerHealth $Name
        Write-Host "$Name status: $status"
        if ($status -eq "healthy") {
            return
        }
        if ($status -eq "missing" -or $status -eq "exited" -or $status -eq "dead") {
            throw "Required container $Name is $status."
        }
        Start-Sleep -Seconds 5
    } while ((Get-Date) -lt $deadline)
    throw "Timed out waiting for $Name to become healthy (last status: $status)."
}

Write-Host "Checking Docker and ClamAV REST readiness..."
docker info *> $null
if ($LASTEXITCODE -ne 0) {
    throw "Docker engine is unavailable."
}
Wait-ContainerHealthy "aegis-clamav-rest" 300

Write-Host "Waiting for Aegis health and real ClamAV availability..."
$deadline = (Get-Date).AddSeconds(120)
$health = $null
do {
    try {
        $health = Invoke-RestMethod -Uri "http://localhost:8000/health" -TimeoutSec 5
        if ($health.av_provider -eq "clamav_rest" -and $health.av_available -eq $true -and $health.av_mock_mode -eq $false) {
            break
        }
    } catch {
        $health = $null
    }
    Start-Sleep -Seconds 5
} while ((Get-Date) -lt $deadline)

if (-not $health -or $health.av_provider -ne "clamav_rest" -or $health.av_available -ne $true -or $health.av_mock_mode -ne $false) {
    throw "Aegis did not become ready with real clamav_rest. Check docker compose ps and logs."
}
$health | ConvertTo-Json -Depth 3 | Write-Host

$pythonScript = @'
import io
import json
import os
import httpx

BASE = "http://localhost:8000"
HEADERS = {}
if os.environ.get("API_KEY"):
    HEADERS["X-API-Key"] = os.environ["API_KEY"]
EICAR = r"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"

def upload_and_scan(client, name, content):
    upload = client.post(
        f"{BASE}/api/v1/datasets/upload",
        files={"file": (name, io.BytesIO(content), "text/csv")},
        headers=HEADERS,
        timeout=60,
    )
    print(f"{name} upload HTTP {upload.status_code}")
    upload.raise_for_status()
    dataset_id = upload.json().get("dataset_id")
    if not isinstance(dataset_id, int):
        raise RuntimeError("Upload response did not contain a dataset_id")
    scan = client.post(f"{BASE}/api/v1/datasets/{dataset_id}/scan", headers=HEADERS, timeout=120)
    print(f"{name} scan HTTP {scan.status_code}")
    scan.raise_for_status()
    result = scan.json()
    summary = {
        key: result.get(key)
        for key in ("dataset_id", "clamav_status", "clamav_virus_name", "verdict", "verification_limitations")
    }
    summary["clamav_finding"] = any(
        item.get("category") == "clamav" or str(item.get("rule_id", "")).startswith("CLAM-")
        for item in result.get("findings", [])
    )
    print(json.dumps(summary))
    return result, summary

with httpx.Client() as client:
    clean_result, clean_summary = upload_and_scan(
        client,
        "aegis_safe_probe.csv",
        b"name,value\nAlice,1\n",
    )
    if clean_result.get("clamav_status") != "clean":
        raise RuntimeError("Harmless-file scan did not complete as a ClamAV clean scan")

    eicar_result, eicar_summary = upload_and_scan(
        client,
        "aegis_eicar_probe.csv",
        ("test,payload\n1," + EICAR + "\n").encode("ascii"),
    )
    if eicar_result.get("clamav_status") != "infected":
        raise RuntimeError("ClamAV did not report EICAR as infected")
    if not eicar_result.get("clamav_virus_name") or "eicar" not in eicar_result["clamav_virus_name"].lower():
        raise RuntimeError("ClamAV result did not identify an EICAR signature")
    if not eicar_summary["clamav_finding"]:
        raise RuntimeError("Aegis response did not include a ClamAV-provenance finding")

print("CLAMAV_AEGIS_E2E_PASSED")
'@

$tempScript = Join-Path ([System.IO.Path]::GetTempPath()) ("aegis-clamav-e2e-{0}.py" -f [guid]::NewGuid().ToString("N"))
$containerScript = "/tmp/aegis-clamav-e2e.py"
try {
    Set-Content -Path $tempScript -Value $pythonScript -Encoding UTF8
    docker cp $tempScript "aegis-node:$containerScript"
    if ($LASTEXITCODE -ne 0) {
        throw "Could not copy the E2E runner into the running app container."
    }
    docker exec aegis-node python $containerScript
    if ($LASTEXITCODE -ne 0) {
        throw "Harmless/EICAR Aegis pipeline verification failed."
    }
} finally {
    docker exec aegis-node rm -f $containerScript 2>$null
    Remove-Item -LiteralPath $tempScript -Force -ErrorAction SilentlyContinue
}
