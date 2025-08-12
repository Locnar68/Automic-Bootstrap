# Automic Bootstrap — Updated Baseline

Modular CLI to provision AWS infra and install/configure Automic AEDB, AE Engine, and AWI.

## Quick start

```powershell
pip install -e .
automic-bootstrap --help

# Provision only (returns IPs)
automic-bootstrap --region us-east-1 provision

# Full pipeline
automic-bootstrap all `
  --automic-zip C:\path\to\Automic.Automation_24.4.1_2025-07-25.zip `
  --sm-tar C:\path\to\ucsmgrlx6.tar.gz
```
