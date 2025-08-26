
# Automic Bootstrap — Updated Baseline

This project automates the **provisioning, installation, and verification** of an Automic Automation stack on AWS.  
It supports a **full pipeline run** (recommended) or infrastructure-only provisioning..

---

## Quick Start

### 1. Virtual Environment (recommended)
```bash
python -m venv .venv
source .venv/bin/activate   # Linux/Mac
.venv\Scripts\Activate.ps1  # Windows PowerShell

2. Install
pip install -e .

3. Run Full Pipeline
automic-bootstrap all `
  --automic-zip C:\path\to\Automic.Automation_24.4.1_2025-07-25.zip `
  --sm-tar C:\path\to\ucsmgrlx6.tar.gz

Command Reference

automic-bootstrap all →
Provisions AWS infra and installs AEDB, AE Engine, AWI, Service Manager, Agents, and Analytics.
✅ This is the main command you should use.

automic-bootstrap provision →
Creates AWS infra only (returns IPs).
Useful for debugging infra, but does not install Automic.

automic-bootstrap --help →
Shows all commands and options.

Architecture Overview
AWS Resource Design
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
 ┌────────────┐
 │ provision  │ → Launch AWS infra (VPC, SG, EC2) + user-data
 └─────┬──────┘
       ↓
 ┌────────────┐
 │ install-db │ → PostgreSQL + AEDB schema + tablespaces
 └─────┬──────┘
       ↓
 ┌───────────────┐
 │ install-ae    │ → AE Engine config + TLS + JDBC
 └─────┬─────────┘
       ↓
 ┌───────────────┐
 │ install-awi   │ → AWI + JCP CN mapping
 └─────┬─────────┘
       ↓
 ┌───────────────┐
 │ install-sm    │ → Service Manager + UC4 definitions
 └─────┬─────────┘
       ↓
 ┌───────────────┐
 │ install-agents│ → Unix / Windows / SQL / REST agents
 └─────┬─────────┘
       ↓
 ┌───────────────┐
 │ install-analytics │ → Analytics datastore + props
 └─────┬─────────┘
       ↓
 ┌────────────┐
 │ verify     │ → Health checks, log verification
 └─────┬──────┘
       ↓
 ┌──────────────┐
 │ deprovision  │ → Destroy AWS resources & clean up
 └──────────────┘

About the Automic ZIP

This repo does not contain Broadcom Automic installation media.
Download from your licensed Broadcom/Automic portal and upload to:

/opt/automic/install/Automic.Automation_<version>.zip

Development Method

All automation here was created through VibeCoding by Mike Pepe —
a live, iterative style of coding that adapts instantly to feedback, tests, and results.

More Details

See docs/USAGE.md
 for:

Stage-by-stage installs (install-db, install-awi, etc.)

Deprovisioning AWS resources

Smoke tests and verification

Full architecture notes


---

✅ This is **ready to copy-paste** into GitHub and will keep the formatting exactly as you see it.  

Do you want me to now **write the full `docs/USAGE.md`** (expanded commands, smoke tests, teardown, diagrams) so you have the split structure complete?
