<#
================================================================================
 AEGIS task runner (Windows / PowerShell)

 `make` is not available on this machine, so this script is the single entry
 point for every routine operation. A CI-equivalent Makefile lives alongside it
 for the Linux GitHub Actions runners (Phase 8).

 Usage:   .\aegis.ps1 <command>
 Help:    .\aegis.ps1 help
================================================================================
#>
param(
    [Parameter(Position = 0)]
    [string]$Command = "help",

    [Parameter(Position = 1, ValueFromRemainingArguments = $true)]
    [string[]]$Rest
)

$ErrorActionPreference = "Stop"
$Root    = $PSScriptRoot
$Infra   = Join-Path $Root "infra"
$EnvFile = Join-Path $Root ".env"

# ------------------------------------------------------------------------------
# Virtual environment location.
#
# Default is the conventional ./.venv, which is right on Linux and CI. But this
# repository lives inside a OneDrive-synced folder, and a venv is ~400 MB of
# thousands of small files. OneDrive would sync every one of them, burn quota,
# and can lock a .pyd mid-install and corrupt the environment.
#
# So on this machine we point AEGIS_VENV at a path outside the synced tree.
# Source code stays in OneDrive (backed up, versioned); build artefacts do not.
# Set it permanently with:
#   [Environment]::SetEnvironmentVariable("AEGIS_VENV","C:\aegis-data\venv","User")
# ------------------------------------------------------------------------------
$Venv = if ($env:AEGIS_VENV) { $env:AEGIS_VENV } else { Join-Path $Root ".venv" }
$Py   = Join-Path $Venv "Scripts\python.exe"

function Say($msg)  { Write-Host "  $msg" -ForegroundColor Cyan }
function Ok($msg)   { Write-Host "  OK  $msg" -ForegroundColor Green }
function Warn($msg) { Write-Host "  !!  $msg" -ForegroundColor Yellow }
function Die($msg)  { Write-Host "  XX  $msg" -ForegroundColor Red; exit 1 }

function Invoke-Compose {
    param([string[]]$ComposeArgs)
    Push-Location $Infra
    try { & docker compose --env-file $EnvFile @ComposeArgs }
    finally { Pop-Location }
}

function Require-Venv {
    if (-not (Test-Path $Py)) { Die "No venv found. Run: .\aegis.ps1 setup" }
}

switch ($Command.ToLower()) {

    # -- Environment ----------------------------------------------------------
    "setup" {
        Say "Creating the Python virtual environment..."
        if (-not (Test-Path $Venv)) { & python -m venv $Venv }
        Say "Upgrading pip..."
        & $Py -m pip install --upgrade pip --quiet
        Say "Installing AEGIS in editable mode (this takes a few minutes)..."
        & $Py -m pip install -e "$Root[dev]"
        if (-not (Test-Path $EnvFile)) {
            Copy-Item (Join-Path $Root ".env.example") $EnvFile
            Warn ".env created from .env.example - review the secrets in it"
        }
        Ok "Environment ready. Activate it with: .\.venv\Scripts\Activate.ps1"
    }

    # -- Infrastructure -------------------------------------------------------
    "up" {
        Say "Starting infrastructure (redpanda, minio, postgres, console)..."
        Invoke-Compose @("up", "-d")
        Ok "Up. Consoles:  Redpanda http://localhost:8080   MinIO http://localhost:9001"
    }
    "down" {
        Say "Stopping containers (data volumes are preserved)..."
        Invoke-Compose @("down")
        Ok "Stopped."
    }
    "restart" { Invoke-Compose @("restart") ; Ok "Restarted." }
    "ps"      { Invoke-Compose @("ps") }
    "logs"    { Invoke-Compose (@("logs", "-f", "--tail=100") + $Rest) }
    "stats"   { & docker stats --no-stream --format "table {{.Name}}`t{{.MemUsage}}`t{{.MemPerc}}`t{{.CPUPerc}}" }

    "nuke" {
        Warn "This DELETES every AEGIS volume: lakehouse data, Kafka log, Postgres."
        $answer = Read-Host "  Type 'yes' to confirm"
        if ($answer -ne "yes") { Say "Cancelled."; break }
        Invoke-Compose @("down", "-v")
        Ok "All volumes destroyed. Run '.\aegis.ps1 up' for a clean slate."
    }

    # -- Health ---------------------------------------------------------------
    "doctor" {
        Say "Running environment diagnostics..."
        Require-Venv
        & $Py (Join-Path $Root "scripts\doctor.py")
    }

    # -- Quality gates --------------------------------------------------------
    "lint"   { Require-Venv; & $Py -m ruff check (Join-Path $Root "src") (Join-Path $Root "tests") }
    "format" { Require-Venv; & $Py -m ruff format (Join-Path $Root "src") (Join-Path $Root "tests")
               & $Py -m ruff check --fix (Join-Path $Root "src") (Join-Path $Root "tests") }
    "types"  { Require-Venv; & $Py -m mypy (Join-Path $Root "src") }
    "test"   { Require-Venv; & $Py -m pytest (Join-Path $Root "tests") -v }
    "check"  {
        Require-Venv
        Say "lint..."  ; & $Py -m ruff check (Join-Path $Root "src") (Join-Path $Root "tests")
        Say "types..." ; & $Py -m mypy (Join-Path $Root "src")
        Say "tests..." ; & $Py -m pytest (Join-Path $Root "tests")
        Ok "All quality gates passed."
    }

    default {
        Write-Host @"

  AEGIS - Threat Intelligence Lakehouse

  ENVIRONMENT
    setup       Create the venv and install all Python dependencies
    doctor      Diagnose every dependency and connection

  INFRASTRUCTURE
    up          Start redpanda, minio, postgres, console
    down        Stop containers, keep the data
    restart     Restart every container
    ps          Show container status
    logs [svc]  Follow logs (optionally for one service)
    stats       Show live memory and CPU usage
    nuke        Destroy every volume (asks for confirmation)

  QUALITY
    lint        Ruff lint
    format      Ruff format + autofix
    types       mypy type check
    test        pytest
    check       Run lint + types + tests together

  Consoles:  Redpanda http://localhost:8080   MinIO http://localhost:9001

"@ -ForegroundColor White
    }
}
