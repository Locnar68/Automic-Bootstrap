import logging
from pathlib import Path
from ..remote.ssh import ssh_exec

def final_verification(ae_ip: str, db_ip: str, awi_ip: str, key_path: Path):
    for ip, label in [(ae_ip, 'AE'), (awi_ip, 'AWI')]:
        rc, out, err = ssh_exec(ip, key_path, "bash -lc 'tail -n 40 $(find /opt/automic -name "*.log" | head -n1) || true'")
        logging.info(f"[{label} LOGS @ {ip}]:\n{out}")
    rc, out, err = ssh_exec(db_ip, key_path, "sudo -u postgres psql -tAc 'SELECT version();'", sudo=True)
    logging.info(f"[DB CHECK @ {db_ip}]:\n{out}")
    logging.info("Verification complete.")
