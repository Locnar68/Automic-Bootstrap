from __future__ import annotations
import logging
from pathlib import Path
from .utils import ssh_exec

def final_verification(ae_ip: str, db_ip: str, awi_ip: str, key_path: Path):
    for ip, label in [(ae_ip, 'AE'), (awi_ip, 'AWI')]:
        cmd = "bash -lc 'tail -n 40 $(find /opt/automic -name \"*.log\" | head -n1) || true'"
        rc, out, err = ssh_exec(ip, key_path, cmd)
        logging.info(f"[{label} LOGS @ {ip}]:\n{out}")

    rc, out, err = ssh_exec(db_ip, key_path, "sudo -u postgres psql -tAc 'SELECT version();'", sudo=True)
    logging.info(f"[DB VERSION @ {db_ip}]:\n{out}")
