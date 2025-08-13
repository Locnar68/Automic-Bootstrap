# Automic Bootstrap — Updated Baseline

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

## Automic AEDB Bootstrap & Verification

This project automates the provisioning, loading, and verification of an Automic Automation database (AEDB) on PostgreSQL. It includes:
- Creation of the application role (`aauser`) with privileges.
- Required PostgreSQL extensions (`pgcrypto`, `uuid-ossp`).
- Tablespaces creation and assignment (`ae_data`, `ae_index`).
- Unzipping and deploying the Automic media archive.
- Executing base schema and steps SQL scripts.
- Running a verification smoke test.

All accomplished using the art of **Vibe Coding with ChatGPT**.

### What Is Vibe Coding with ChatGPT?

Instead of a rigid spec, Vibe Coding means:
1. Describing the goal in natural language.
2. Iterating with ChatGPT to design scripts, run tests, debug.
3. Adapting instantly based on output and feedback.
4. Integrating Bash, Python, and SQL across remote systems.

### Requirements

- PostgreSQL 16
- postgresql16-contrib
- SSH access to DB server
- Automic Automation ZIP (from Broadcom/Automic portal)

### About the Automic ZIP

This repository does not contain the Automic Automation installation media. Download it from your licensed Broadcom/Automic portal and upload to:  
`/opt/automic/install/Automic.Automation_<version>.zip`

### How to Use

1. Clone repo.
2. Ensure SSH key & DB server IP.
3. Run bootstrap:
   ```bash
   python -m automic_bootstrap.components.db_load --db-host <host> --key-path /path/to/key.pem --db-name AEDB --db-user postgres --db-password <password> --remote-zip /opt/automic/install/Automic.Automation_<version>.zip
   ```
4. SSH into DB server.
5. Run:
   ```bash
   APPUSER=aauser APPPASS=Automic123 bash /tmp/aedb_smoke.sh
   ```
6. Review log output for verification.

### Credits

All development/troubleshooting completed collaboratively via Vibe Coding with ChatGPT, using SSH sessions, SQL inspection, and infrastructure scripting.

---


