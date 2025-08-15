# automic_bootstrap/components/verify.py
from __future__ import annotations

import logging
from pathlib import Path
from typing import Tuple

import paramiko

log = logging.getLogger(__name__)

# ---------- Minimal SSH helper (inline) ----------

def ssh_exec(
    host: str,
    key_path,
    cmd: str,
    sudo: bool = False,
    username: str = "ec2-user",
    timeout: int = 60,
):
    """
    Execute a remote command over SSH using a PEM key. Returns (rc, out, err).
    """
    if sudo and not cmd.strip().startswith("sudo"):
        cmd = "sudo " + cmd
    key = paramiko.RSAKey.from_private_key_file(str(key_path))
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(hostname=host, username=username, pkey=key, timeout=timeout)
    try:
        stdin, stdout, stderr = ssh.exec_command(cmd)
        rc = stdout.channel.recv_exit_status()
        out = stdout.read().decode()
        err = stderr.read().decode()
        return rc, out, err
    finally:
        ssh.close()

# ---------- Verify helpers ----------

VERIFY_SCRIPT = "/tmp/automic_verify.sh"

def _write_remote_file(ip: str, key_path: Path, remote_path: str, content: str) -> Tuple[int, str, str]:
    """
    Create/overwrite a file on the remote host using a heredoc via SSH.
    """
    cmd = (
        "bash -lc "
        f"\"cat > {remote_path} <<'EOF'\n{content}\nEOF\nchmod +x {remote_path}\""
    )
    return ssh_exec(ip, key_path, cmd)

def deploy_and_run_verify(ip: str, key_path: Path, script_body: str, remote_path: str = VERIFY_SCRIPT) -> Tuple[int, str, str]:
    """
    Deploy a simple verification script to the remote host and run it.
    Returns (rc, stdout, stderr) from the script execution.
    """
    rc_w, out_w, err_w = _write_remote_file(ip, key_path, remote_path, script_body)
    if rc_w != 0:
        log.warning(f"[VERIFY] Failed to write script on {ip}: rc={rc_w} err={err_w}")
        return rc_w, out_w, err_w
    return ssh_exec(ip, key_path, f"bash -lc '{remote_path}'")

def _default_verify_script() -> str:
    """
    A tiny verification script for AE/AWI nodes:
    - systemd status for common Automic services (if present)
    - tail of the freshest Automic *.log
    - java/node versions (AWI sanity)
    """
    return r"""#!/usr/bin/env bash
set -u
echo "== Automic quick verify ($(hostname)) =="

if command -v systemctl >/dev/null 2>&1; then
  for svc in uc4.service uc4jwp.service uc4jcp.service uc4rest.service; do
    if systemctl list-unit-files | grep -q "^$svc"; then
      echo "--- systemctl status $svc ---"
      systemctl --no-pager -l status "$svc" || true
    fi
  done
fi

LAST_LOG="$(find /opt/automic -type f -name '*.log' -printf '%T@ %p\n' 2>/dev/null | sort -nr | head -n1 | awk '{print $2}')"
if [ -n "${LAST_LOG:-}" ] && [ -f "$LAST_LOG" ]; then
  echo "--- tail -n 80 $LAST_LOG ---"
  tail -n 80 "$LAST_LOG" || true
else
  echo "No *.log found under /opt/automic"
fi

if command -v java >/dev/null 2>&1; then
  echo "--- java -version ---"
  java -version 2>&1 || true
fi
if command -v node >/dev/null 2>&1; then
  echo "--- node --version ---"
  node --version 2>&1 || true
fi

echo "== Verify complete =="
"""

# ---------- Public entrypoint ----------

def final_verification(ae_ip: str, db_ip: str, awi_ip: str, key_path: Path) -> None:
    """
    Lightweight verification across AE host, AWI host, and DB host.
    - AE/AWI: tail latest Automic log and run an inline verify script
    - DB: print PostgreSQL version
    Logs results; warns on failures but does not raise hard exceptions.
    """

    # 1) AE and AWI: tail logs
    for ip, label in [(ae_ip, "AE"), (awi_ip, "AWI")]:
        tail_cmd = (
            "bash -lc '"
            "f=$(find /opt/automic -type f -name \"*.log\" -printf \"%T@ %p\\n\" 2>/dev/null | sort -nr | head -n1 | awk '{print $2}'); "
            "[ -n \"$f\" ] && [ -f \"$f\" ] && echo \"--- tail $f ---\" && tail -n 40 \"$f\" || echo \"No *.log found\"; "
            "true'"
        )
        rc, out, err = ssh_exec(ip, key_path, tail_cmd)
        if rc != 0:
            log.warning(f"[{label} LOGS @ {ip}] tail command rc={rc} err={err}")
        log.info(f"[{label} LOGS @ {ip}]:\n{out}")

    # 2) DB: print server version (sudo to postgres)
    rc, out, err = ssh_exec(db_ip, key_path, "sudo -u postgres psql -tAc 'SELECT version();'")
    if rc != 0:
        log.warning(f"[DB VERSION @ {db_ip}] rc={rc} err={err}")
    log.info(f"[DB VERSION @ {db_ip}]:\n{out}")

    # 3) AE/AWI: deploy & run on-the-fly verify script (best effort)
    script_body = _default_verify_script()
    for ip, label in [(ae_ip, "AE"), (awi_ip, "AWI")]:
        rc, out, err = deploy_and_run_verify(ip, key_path, script_body, VERIFY_SCRIPT)
        if rc != 0:
            log.warning(f"[{label} VERIFY @ {ip}] script rc={rc} err={err}")
        log.info(f"[{label} VERIFY @ {ip} OUTPUT]:\n{out}")
