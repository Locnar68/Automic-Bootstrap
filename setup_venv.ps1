<# setup_venv.ps1
Creates a Python virtual environment and installs project requirements.
Run from the project root in an elevated or user PowerShell:
  PS> .\setup_venv.ps1
#>

param(
  [switch]$Force
)

$ErrorActionPreference = "Stop"

# 1) Ensure Python 3.10+
$py = Get-Command python -ErrorAction SilentlyContinue
if (-not $py) { Write-Error "Python not found in PATH. Please install Python 3.10+ from https://www.python.org and re-run."; exit 1 }
$ver = & python -c "import sys;print(sys.version.split()[0])"
Write-Host "Python version: $ver"

# 2) Create venv
$venvPath = ".venv"
if (Test-Path $venvPath -and -not $Force) {
  Write-Host "Virtual env already exists at $venvPath. Use -Force to recreate."
} else {
  if (Test-Path $venvPath) { Remove-Item -Recurse -Force $venvPath }
  & python -m venv $venvPath
}

# 3) Activate and upgrade pip
$activate = ".\.venv\Scripts\Activate.ps1"
. $activate
python -m pip install --upgrade pip wheel

# 4) Install requirements
if (Test-Path ".\requirements.txt") {
  pip install -r requirements.txt
} else {
  Write-Host "requirements.txt not found; skipping pip install."
}

# 5) External dependencies & prompts
# AWS CLI
$aws = Get-Command aws -ErrorAction SilentlyContinue
if (-not $aws) {
  Write-Warning "AWS CLI not found. Please install: https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html"
} else {
  aws --version
}

# Automic bundle
$zip = Get-ChildItem -Path . -Filter "Automic*.zip" -ErrorAction SilentlyContinue | Select-Object -First 1
if (-not $zip) {
  Write-Warning "Automic bundle not found. Please place the Automic .zip in the project root."
} else {
  Write-Host "Found Automic bundle: $($zip.Name)"
}

# Key file
if (-not $env:AUTOMIC_KEY_PATH) {
  Write-Warning "Key not specified. Set AUTOMIC_KEY_PATH to the path of your PEM/PPK. Example: `$env:AUTOMIC_KEY_PATH = 'C:\path\automic-key.pem'"
} else {
  if (Test-Path $env:AUTOMIC_KEY_PATH) {
    Write-Host "Using key at $env:AUTOMIC_KEY_PATH"
  } else {
    Write-Warning "AUTOMIC_KEY_PATH points to a file that doesn't exist."
  }
}

Write-Host "`nDone. To activate this environment later:"
Write-Host "  .\.venv\Scripts\Activate.ps1"
