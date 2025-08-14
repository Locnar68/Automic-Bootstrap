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


# Automic AEDB Bootstrap & Verification

This project automates the provisioning, installation, and verification of an Automic Automation stack on AWS, including PostgreSQL AEDB, AE Engine, AWI, Service Manager, Agents, and Analytics.

It supports **step-by-step installs** or a **full pipeline** run.

---

## Automic AEDB Bootstrap & Verification

This project automates the provisioning, loading, and verification of an Automic Automation database (AEDB) on PostgreSQL. It includes:

- Creation of the application role (`aauser`) with privileges.
- Required PostgreSQL extensions (`pgcrypto`, `uuid-ossp`).
- Tablespaces creation and assignment (`ae_data`, `ae_index`).
- Unzipping and deploying the Automic media archive.
- Executing base schema and steps SQL scripts.
- Running a verification smoke test.

All accomplished using the art of **Vibe Coding with ChatGPT**.

---

### What Is Vibe Coding with ChatGPT?

Instead of a rigid spec, Vibe Coding means:

1. Describing the goal in natural language.
2. Iterating with ChatGPT to design scripts, run tests, debug.
3. Adapting instantly based on output and feedback.
4. Integrating Bash, Python, and SQL across remote systems.

---

## Quick Start

### 1. Create & Activate a Virtual Environment
It’s strongly recommended to run inside a virtual environment to keep dependencies isolated:

```bash
# Create venv
python -m venv .venv

# Activate venv (Linux/Mac)
source .venv/bin/activate

# Activate venv (Windows PowerShell)
.venv\Scripts\Activate.ps1
2. Install in Editable Mode
bash
Copy
Edit
pip install -e .
3. View CLI Help
bash
Copy
Edit
automic-bootstrap --help
Common Commands
Provision Only (returns IPs)
bash
Copy
Edit
automic-bootstrap --region us-east-1 provision
Full Pipeline
powershell
Copy
Edit
automic-bootstrap all `
  --automic-zip C:\path\to\Automic.Automation_24.4.1_2025-07-25.zip `
  --sm-tar C:\path\to\ucsmgrlx6.tar.gz
Stage-by-Stage Install
bash
Copy
Edit
automic-bootstrap install-db
automic-bootstrap install-ae
automic-bootstrap install-awi
automic-bootstrap install-sm
automic-bootstrap install-agents --unix --windows --sql --rest
automic-bootstrap install-analytics
automic-bootstrap verify
Deprovision AWS Resources
When you’re done testing, clean up AWS infrastructure to avoid charges:

bash
Copy
Edit
# Remove EC2, security groups, and key pair
automic-bootstrap deprovision --region us-east-1

# Remove specific stack by name
automic-bootstrap deprovision --region us-east-1 --stack-name MyAutomicStack
About the Automic ZIP
This repository does not contain the Automic Automation installation media.
Download it from your licensed Broadcom/Automic portal and upload to:

swift
Copy
Edit
/opt/automic/install/Automic.Automation_<version>.zip
How to Use
Clone repo

Ensure SSH key & DB server IP

Run bootstrap

bash
Copy
Edit
python -m automic_bootstrap.components.db_load \
  --db-host <host> \
  --key-path /path/to/key.pem \
  --db-name AEDB \
  --db-user postgres \
  --db-password <password> \
  --remote-zip /opt/automic/install/Automic.Automation_<version>.zip
SSH into DB server

Run smoke test

bash
Copy
Edit
APPUSER=aauser APPPASS=Automic123 bash /tmp/aedb_smoke.sh
Review log output for verification

Architecture Overview
AWS Resource Diagram
markdown
Copy
Edit
          ┌───────────────────────────────────────┐
          │              AWS Cloud                 │
          │                                         │
          │  ┌───────────────┐   ┌───────────────┐  │
          │  │   VPC         │   │  SecurityGrp  │  │
          │  └──────┬────────┘   └──────┬────────┘  │
          │         │                   │           │
          │   ┌─────▼─────┐       ┌─────▼─────┐     │
          │   │  EC2 DB   │       │  EC2 AE   │     │
          │   │(Postgres) │       │ Engine+SM │     │
          │   └─────┬─────┘       └─────┬─────┘     │
          │         │                   │           │
          │   ┌─────▼─────┐       ┌─────▼─────┐     │
          │   │   AWI     │       │  Agents   │     │
          │   └───────────┘       └───────────┘     │
          │                                         │
          └─────────────────────────────────────────┘
CLI Workflow
pgsql
Copy
Edit
 ┌────────────┐
 │ provision  │  →  Launch AWS infra (VPC, SG, EC2) + user-data
 └─────┬──────┘
       ↓
 ┌────────────┐
 │ install-db │  →  PostgreSQL + AEDB schema + tablespaces
 └─────┬──────┘
       ↓
 ┌───────────────┐
 │ install-ae    │  →  AE Engine config + TLS + JDBC
 └─────┬─────────┘
       ↓
 ┌───────────────┐
 │ install-awi   │  →  AWI + JCP CN mapping
 └─────┬─────────┘
       ↓
 ┌───────────────┐
 │ install-sm    │  →  Service Manager + UC4 definitions
 └─────┬─────────┘
       ↓
 ┌───────────────┐
 │ install-agents│  →  Unix / Windows / SQL / REST agents
 └─────┬─────────┘
       ↓
 ┌───────────────┐
 │ install-analytics │  →  Analytics datastore + props
 └─────┬─────────┘
       ↓
 ┌────────────┐
 │ verify     │  →  Health checks, log verification
 └─────┬──────┘
       ↓
 ┌──────────────┐
 │ deprovision  │  →  Destroy AWS resources & clean up
 └──────────────┘
Credits
All development and troubleshooting completed collaboratively via Vibe Coding with ChatGPT,
using SSH sessions, SQL inspection, and AWS infrastructure scripting.