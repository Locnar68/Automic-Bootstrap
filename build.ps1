<# build.ps1 — PowerShell task runner (Invoke-Build compatible)
Usage:
  pwsh -File .\build.ps1            # shows help
  pwsh -File .\build.ps1 Setup
  pwsh -File .\build.ps1 Preflight
  pwsh -File .\build.ps1 Lint
  pwsh -File .\build.ps1 Verify

Requires:
  - PowerShell 7+
  - (Optional) Install-Module Invoke-Build -Scope CurrentUser
    If Invoke-Build isn't installed, this script still works as a simple dispatcher.
#>

param([string[]]$Task = @("Help"))

$ErrorActionPreference = "Stop"

function Use-Venv {
  if (Test-Path .\.venv\Scripts\Activate.ps1) {
    . .\.venv\Scripts\Activate.ps1
  } else {
    Write-Warning "Virtual env not found (.venv). Run .\setup_venv.ps1 or 'make setup'."
  }
}

function Help {
@"
Tasks:
  Setup       - Create venv and install dependencies
  Preflight   - Run readiness checks (venv, AWS CLI, bundle, key, STS)
  Lint        - Run ruff/flake8 if available
  Format      - Run ruff format/black if available
  Test        - Run pytest if available
  Verify      - Run CLI 'verify' (preflight first if wired)
  Clean       - Remove caches and build artifacts

Examples:
  pwsh -File .\build.ps1 Setup
  pwsh -File .\build.ps1 Preflight
"@ | Write-Host
}

function Setup {
  & pwsh -NoProfile -Command { .\setup_venv.ps1 }
}

function Preflight {
  Use-Venv
  python .\preflight.py
}

function Lint {
  Use-Venv
  if (Get-Command ruff -ErrorAction SilentlyContinue) {
    ruff check
  } elseif (Get-Command flake8 -ErrorAction SilentlyContinue) {
    flake8
  } else {
    Write-Warning "No linter found (ruff/flake8)."
  }
}

function Format {
  Use-Venv
  if (Get-Command ruff -ErrorAction SilentlyContinue) {
    ruff format
  } elseif (Get-Command black -ErrorAction SilentlyContinue) {
    black .
  } else {
    Write-Warning "No formatter found (ruff/black)."
  }
}

function Test {
  Use-Venv
  if (Get-Command pytest -ErrorAction SilentlyContinue) {
    pytest -q
  } else {
    Write-Warning "pytest not installed."
  }
}

function Verify {
  Use-Venv
  if (Get-Command automic-bootstrap -ErrorAction SilentlyContinue) {
    automic-bootstrap preflight
    automic-bootstrap verify
  } else {
    Write-Warning "automic-bootstrap entrypoint not installed (pip install -e . or python -m automic_bootstrap)."
  }
}

function Clean {
  Remove-Item -Recurse -Force -ErrorAction SilentlyContinue .pytest_cache, .ruff_cache, dist, build
  Get-ChildItem -Recurse -Directory -Filter "__pycache__" | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
}

switch -Regex ($Task[0]) {
  "Setup"    { Setup; break }
  "Preflight"{ Preflight; break }
  "Lint"     { Lint; break }
  "Format"   { Format; break }
  "Test"     { Test; break }
  "Verify"   { Verify; break }
  "Clean"    { Clean; break }
  default    { Help; break }
}
