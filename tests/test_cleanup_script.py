"""
scripts/cleanup.ps1 must keep data by default and never kill an unrelated process.

The static checks always run. The behaviour checks run the real script under PowerShell
with docker, Get-NetTCPConnection, Get-Process, Stop-Process and Read-Host replaced by
recording stubs, so nothing is stopped or deleted. They need `pwsh` on PATH (GitHub's
Ubuntu runners have it) or PWSH_BIN; otherwise they are skipped. Stdin is redirected, so
the script sees a non-interactive session; the interactive prompts are not exercised here.
"""

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts" / "cleanup.ps1"
PWSH = os.environ.get("PWSH_BIN") or shutil.which("pwsh")
PHRASE = "DELETE AEGIS DATA"

HARNESS = r"""
param([string]$Script, [string]$Log, [string]$ArgsJson)
function Write-Call($name, $argv) {
    $line = @{ name = $name; args = @($argv | ForEach-Object { "$_" }) } | ConvertTo-Json -Compress
    Add-Content -Path $Log -Value $line
}
function docker {
    Write-Call "docker" $args
    $global:LASTEXITCODE = 0
    $joined = $args -join " "
    if ($joined -eq "compose config --format json") {
        return '{"name":"aegis-node","volumes":{"clamav_data":{"name":"aegis_clamav_data"},"aegis_db":{"name":"aegis_node_db"},"aegis_artifacts":{"name":"aegis_node_artifacts"}}}'
    }
    if ($joined -like "volume ls*") { return @($env:STUB_VOLUMES -split "," | Where-Object { $_ }) }
}
function Get-NetTCPConnection {
    param($LocalPort, $State, $ErrorAction)
    Write-Call "Get-NetTCPConnection" @($LocalPort)
    if ($LocalPort -eq 8000) { return [pscustomobject]@{ OwningProcess = 101 } }
    if ($LocalPort -eq 5173) { return [pscustomobject]@{ OwningProcess = 202 } }
}
function Get-Process {
    param($Id, $ErrorAction)
    if ($Id -eq 101) { return [pscustomobject]@{ Id = 101; ProcessName = "python" } }
    if ($Id -eq 202) { return [pscustomobject]@{ Id = 202; ProcessName = "postgres" } }
}
function Stop-Process { Write-Call "Stop-Process" $args }
function Read-Host { Write-Call "Read-Host" $args; return "y" }
$splat = @{}
($ArgsJson | ConvertFrom-Json).PSObject.Properties | ForEach-Object { $splat[$_.Name] = $_.Value }
& $Script @splat
exit $LASTEXITCODE
"""


def _run(tmp_path, volumes="aegis_node_db,aegis_node_artifacts", **params):
    harness = tmp_path / "harness.ps1"
    harness.write_text(HARNESS, encoding="utf-8")
    log = tmp_path / "calls.jsonl"
    log.write_text("", encoding="utf-8")
    args = {k: (True if v is True else v) for k, v in params.items()}
    proc = subprocess.run(
        [PWSH, "-NoProfile", "-NonInteractive", "-File", str(harness), "-Script", str(SCRIPT),
         "-Log", str(log), "-ArgsJson", json.dumps(args)],
        stdin=subprocess.PIPE, capture_output=True, text=True, timeout=60,
        env={**os.environ, "STUB_VOLUMES": volumes},
    )
    calls = [json.loads(line) for line in log.read_text(encoding="utf-8").splitlines() if line]
    return proc, calls


def _docker(calls):
    return [" ".join(c["args"]) for c in calls if c["name"] == "docker"]


# --- static checks ------------------------------------------------------------

def test_script_never_uses_compose_down_with_volumes():
    text = SCRIPT.read_text(encoding="utf-8")
    assert "down -v" not in text and "--volumes" not in text


def test_script_never_force_kills():
    text = SCRIPT.read_text(encoding="utf-8")
    assert "Stop-Process" in text
    assert "-Force" not in text


def test_script_requires_typed_phrase():
    text = SCRIPT.read_text(encoding="utf-8")
    assert f'$ConfirmPhrase = "{PHRASE}"' in text
    assert "-cne $ConfirmPhrase" in text


# --- behaviour under PowerShell with stubs -------------------------------------

needs_pwsh = pytest.mark.skipif(not PWSH, reason="pwsh not installed")


@needs_pwsh
def test_default_only_stops_containers(tmp_path):
    proc, calls = _run(tmp_path)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert _docker(calls) == ["compose down"]
    assert not [c for c in calls if c["name"] in ("Stop-Process", "Get-NetTCPConnection")]


@needs_pwsh
def test_default_is_safe_to_rerun(tmp_path):
    for _ in range(2):
        proc, calls = _run(tmp_path)
        assert proc.returncode == 0
        assert _docker(calls) == ["compose down"]


@needs_pwsh
def test_dry_run_changes_nothing(tmp_path):
    proc, calls = _run(tmp_path, DryRun=True, RemoveVolumes=True, StopListeners=True)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "compose down" not in _docker(calls)
    assert not any(d.startswith("volume rm") for d in _docker(calls))
    assert not [c for c in calls if c["name"] == "Stop-Process"]
    assert "aegis_node_db" in proc.stdout


@needs_pwsh
def test_stop_listeners_without_console_kills_nothing(tmp_path):
    proc, calls = _run(tmp_path, StopListeners=True)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert not [c for c in calls if c["name"] == "Stop-Process"]
    assert "Leaving PID 202 (postgres)" in proc.stdout
    assert "Not stopping PID 101 (python)" in proc.stdout


@needs_pwsh
def test_remove_volumes_without_console_is_refused_before_any_change(tmp_path):
    proc, calls = _run(tmp_path, RemoveVolumes=True)
    assert proc.returncode == 3
    assert calls == []


@needs_pwsh
def test_remove_volumes_with_wrong_phrase_is_refused(tmp_path):
    proc, calls = _run(tmp_path, RemoveVolumes=True, ConfirmDeletion=PHRASE.lower())
    assert proc.returncode == 3
    assert calls == []


@needs_pwsh
def test_remove_volumes_with_phrase_deletes_only_listed_aegis_volumes(tmp_path):
    proc, calls = _run(tmp_path, volumes="aegis_node_db,aegis_node_artifacts,someone_else",
                       RemoveVolumes=True, ConfirmDeletion=PHRASE)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    docker = _docker(calls)
    assert docker[0] == "compose down"
    assert docker[-1] == "volume rm aegis_node_db aegis_node_artifacts"
    assert "aegis_node_db" in proc.stdout and "aegis_node_artifacts" in proc.stdout
    assert "someone_else" not in docker[-1]


@needs_pwsh
def test_remove_volumes_when_none_exist_is_a_no_op(tmp_path):
    proc, calls = _run(tmp_path, volumes="", RemoveVolumes=True, ConfirmDeletion=PHRASE)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert not any(d.startswith("volume rm") for d in _docker(calls))
    assert "Nothing to delete" in proc.stdout


# --- scripts/verify_gateway.py: paid calls only with an explicit flag ----------

def test_verify_gateway_refuses_without_opt_in(tmp_path):
    proc = subprocess.run(
        [sys.executable, "-I", str(ROOT / "scripts" / "verify_gateway.py")],
        capture_output=True, text=True, timeout=60, cwd=tmp_path,
        env={"PATH": os.environ.get("PATH", ""), "GROQ_API_KEY": "gsk_not_a_real_key"},
    )
    assert proc.returncode == 2
    assert "Nothing was loaded or sent" in proc.stdout
    assert "gsk_not_a_real_key" not in proc.stdout + proc.stderr


def test_verify_gateway_loads_backend_only_after_opt_in(monkeypatch):
    import importlib.util

    spec = importlib.util.spec_from_file_location("verify_gateway",
                                                  ROOT / "scripts" / "verify_gateway.py")
    module = importlib.util.module_from_spec(spec)
    # scripts/ is a SkillSpector target; do not leave a __pycache__ there.
    monkeypatch.setattr(sys, "dont_write_bytecode", True)
    spec.loader.exec_module(module)
    loaded = []
    monkeypatch.setattr(module, "_load_backend", lambda: loaded.append(True))
    monkeypatch.setattr(module, "test_direct_mode", lambda: True)
    monkeypatch.setattr(module, "test_gateway_mode", lambda: True)
    assert module.main([]) == 2 and loaded == []
    assert module.main(["--confirm-paid-calls"]) == 0 and loaded == [True]
