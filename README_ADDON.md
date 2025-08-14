# Automic-Bootstrap Developer Add-ons

This folder contains optional developer conveniences you can drop into your repo.

## Files

- `build.ps1` — PowerShell task runner (works with or without `Invoke-Build`)
- `Taskfile.yml` — Cross-platform task runner for [`go-task`](https://taskfile.dev)
- `.github/workflows/ci.yml` — GitHub Actions: lint, test, preflight

## Quickstart

### Windows (PowerShell)
```powershell
pwsh -File .\build.ps1 Setup
pwsh -File .\build.ps1 Preflight
pwsh -File .\build.ps1 Verify
```

### Cross-platform (Taskfile)
```bash
# install go-task if needed: https://taskfile.dev/installation/
task setup
task preflight
task verify
```

### GitHub Actions
1. Copy `.github/workflows/ci.yml` into your repo.
2. Push to `main`. The workflow will:
   - Install Python deps
   - Run `ruff` and `pytest`
   - Run `preflight.py` (non-fatal)
