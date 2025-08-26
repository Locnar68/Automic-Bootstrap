# automic_bootstrap/components/verify.py
from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Tuple, Optional

import paramiko

log = logging.getLogger(__name__)

# =========================
# SSH helpers (inline)
# =========================

def _load_key(key_path: Path) -> paramiko.PKey:
    # Try RSA first; fall back to Ed25519 if needed
    try:
        return paramiko.RSAKey.from_private_key_file(str(key_path))
    except Exception:
        return paramiko.Ed25519Key.from_private_key_file(str(key_path))

def ssh_exec(
    host: str,
    key_path: Path,
    cmd: str,
    *,
    username: str = "ec2-user",
    sudo: bool = False,
    timeout: int = 60,
) -> Tuple[int, str, str]:
    """
    Execute a command over SSH. Returns (rc, stdout, stderr).
    """
    if sudo and not cmd.lstrip().startswith("sudo "):
        cmd = "sudo " + cmd

    key = _load_key(key_path)
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(hostname=host, username=username, pkey=key, timeout=timeout)
    try:
        stdin, stdout, stderr = ssh.exec_command(cmd, timeout=timeout)
        rc = stdout.channel.recv_exit_status()
        out = stdout.read().decode(errors="replace")
        err = stderr.read().decode(errors="replace")
        return rc, out, err
    finally:
        ssh.close()

def ssh_put_text(
    host: str,
    key_path: Path,
    dest_path: str,
    content: str,
    *,
    username: str = "ec2-user",
    mode: int = 0o755,
) -> Tuple[int, str, str]:
    """
    Write a remote file via heredoc and chmod it. Returns (rc, out, err).
    """
    heredoc = (
        "bash -lc "
        f"\"cat > {dest_path} <<'__EOF__'\n{content}\n__EOF__\nchmod {mode:o} {dest_path}\""
    )
    return ssh_exec(host, key_path, heredoc, username=username)

# =========================
# Config dataclasses
# =========================

@dataclass
class VerifyTargets:
    ae_host: str               # AE + SM live here
    awi_host: str              # AWI launcher lives here (may equal ae_host)
    db_host: str               # PostgreSQL host

@dataclass
class VerifySettings:
    key_path: Path
    ssh_user: str = "ec2-user"
    jcp_port: int = 8443                    # AE JCP port used by AWI
    awi_url: str = "http://127.0.0.1:8080/awi/"
    ae_home: str = "/opt/automic/AutomationEngine"
    sm_bin: str = "/opt/automic/ServiceManager/bin"
    jdbc_glob: str = "postgresql-*.jar"    # JDBC jar pattern under AE bin/lib
    wait_timeout_s: int = 90               # port wait + AWI start tolerance
# =========================
# Low-level verify primitives
# =========================

def wait_for_port(
    host: str,
    key_path: Path,
    *,
    username: str,
    port: int,
    timeout_s: int = 60,
    listen_ip_regex: str = r".*",
) -> bool:
    """
    Poll 'ss -ltn' on remote host until ':<port>' is present (optionally match IP).
    """
    deadline = time.time() + timeout_s
    check_cmd = (
        "bash -lc "
        f"\"ss -ltn | awk '{{print $4}}' | egrep -q '{listen_ip_regex}:{port}$'\""
    )
    while time.time() < deadline:
        rc, _, _ = ssh_exec(host, key_path, check_cmd, username=username)
        if rc == 0:
            return True
        time.sleep(2)
    return False

def sm_get_process_list(
    host: str, key_path: Path, *, username: str, sm_bin: str, dest: str = "AUTOMIC"
) -> str:
    rc, out, err = ssh_exec(
        host, key_path, f"{sm_bin}/ucybsmgrc -n{dest} -c GET_PROCESS_LIST", username=username
    )
    if rc != 0:
        log.warning("[SM] GET_PROCESS_LIST rc=%s err=%s", rc, err.strip())
    return out

def ae_processes_present(
    host: str, key_path: Path, *, username: str
) -> bool:
    rc, out, _ = ssh_exec(
        host,
        key_path,
        r"bash -lc \"ps -ef | egrep 'ucsrv(wp|cp)|ucsrvjp\.jar' | grep -v grep\"",
        username=username,
    )
    if rc != 0:
        return False
    # minimal sanity: see at least one WP/CP/J* line
    return any(tok in out for tok in ("ucsrvwp", "ucsrvcp", "ucsrvjp.jar"))

def awi_http_ok(
    host: str, key_path: Path, *, username: str, url: str
) -> bool:
    rc, _, _ = ssh_exec(
        host, key_path, f"bash -lc \"curl -fsS {url} >/dev/null\"", username=username
    )
    return rc == 0

def jdbc_present(
    host: str, key_path: Path, *, username: str, ae_home: str, jdbc_glob: str
) -> bool:
    rc, _, _ = ssh_exec(
        host,
        key_path,
        f"bash -lc \"test -s {ae_home}/bin/lib/{jdbc_glob}\"",
        username=username,
    )
    return rc == 0

def ucsrv_ini_has_connect(
    host: str, key_path: Path, *, username: str, ae_home: str
) -> bool:
    rc, _, _ = ssh_exec(
        host,
        key_path,
        f"bash -lc \"grep -q '^sqlDriverConnect=' {ae_home}/bin/ucsrv.ini\"",
        username=username,
    )
    return rc == 0

def db_version(host: str, key_path: Path, *, username: str = "ec2-user") -> str:
    rc, out, err = ssh_exec(
        host,
        key_path,
        "sudo -u postgres psql -tAc 'SELECT version();'",
        username=username,
    )
    if rc != 0:
        log.warning("[DB] version rc=%s err=%s", rc, err.strip())
    return out.strip()

# =========================
# On-the-fly debug script (optional)
# =========================

_VERIFY_SCRIPT = "/tmp/automic_verify.sh"

def _inline_debug_script() -> str:
    return r"""#!/usr/bin/env bash
set -u
echo "== Automic quick verify ($(hostname)) =="

echo "--- Recent AE/AWI logs ---"
LAST_LOG="$(find /opt/automic -type f -name '*.log' -printf '%T@ %p\n' 2>/dev/null | sort -nr | head -n1 | awk '{print $2}')"
if [ -n "${LAST_LOG:-}" ] && [ -f "$LAST_LOG" ]; then
  tail -n 120 "$LAST_LOG" || true
else
  echo "No *.log under /opt/automic"
fi

echo "--- Java (for JWP/JCP/REST/AWI) ---"
command -v java >/dev/null 2>&1 && java -version 2>&1 || echo "java not found"

echo "--- Service Manager list ---"
if [ -x /opt/automic/ServiceManager/bin/ucybsmgrc ]; then
  /opt/automic/ServiceManager/bin/ucybsmgrc -nAUTOMIC -c GET_PROCESS_LIST || true
fi

echo "== Verify script done =="
"""

def run_inline_debug(host: str, key_path: Path, *, username: str) -> str:
    rc, _, err = ssh_put_text(host, key_path, _VERIFY_SCRIPT, _inline_debug_script(), username=username)
    if rc != 0:
        return f"[verify] failed to deploy script: {err}"
    rc2, out2, err2 = ssh_exec(host, key_path, f"bash -lc '{_VERIFY_SCRIPT}'", username=username)
    return out2 if rc2 == 0 else (out2 + "\n" + err2)
# =========================
# High-level orchestrator
# =========================

def final_verification_orchestrated(
    targets: VerifyTargets,
    settings: VerifySettings,
    *,
    sm_dest: str = "AUTOMIC",
) -> None:
    """
    Verifies the full stack:
      - DB: prints version
      - AE/SM (on ae_host): SM process list, AE processes, JDBC jar, sqlDriverConnect, JCP port open
      - AWI (on awi_host): /awi/ responds; port 8080 implied by URL
      - Emits inline debug script output for AE and AWI (best-effort)

    Logs warnings if something is off; raises RuntimeError on critical failures.
    """
    k = settings.key_path
    u = settings.ssh_user

    log.info("== DB check on %s ==", targets.db_host)
    log.info("DB version: %s", db_version(targets.db_host, k, username=u))

    log.info("== AE/SM checks on %s ==", targets.ae_host)
    plist = sm_get_process_list(targets.ae_host, k, username=u, sm_bin=settings.sm_bin, dest=sm_dest)
    log.info("Service Manager process list:\n%s", plist or "(empty)")

    if not ae_processes_present(targets.ae_host, k, username=u):
        log.warning("AE processes not detected (ucsrvwp/ucsrvcp/ucsrvjp.jar).")

    if not jdbc_present(targets.ae_host, k, username=u, ae_home=settings.ae_home, jdbc_glob=settings.jdbc_glob):
        raise RuntimeError("JDBC driver not found or empty under AE bin/lib.")

    if not ucsrv_ini_has_connect(targets.ae_host, k, username=u, ae_home=settings.ae_home):
        raise RuntimeError("AE ucsrv.ini lacks sqlDriverConnect=...")

    if not wait_for_port(targets.ae_host, k, username=u, port=settings.jcp_port, timeout_s=settings.wait_timeout_s):
        raise RuntimeError(f"JCP port {settings.jcp_port} did not open on AE host.")

    log.info("== AWI checks on %s ==", targets.awi_host)
    if not awi_http_ok(targets.awi_host, k, username=u, url=settings.awi_url):
        raise RuntimeError(f"AWI not responding at {settings.awi_url}")

    # Optional: inline debug outputs (best effort)
    log.info("== AE inline debug ==")
    ae_dbg = run_inline_debug(targets.ae_host, k, username=u)
    if ae_dbg:
        log.info(ae_dbg)

    if targets.awi_host != targets.ae_host:
        log.info("== AWI inline debug ==")
        awi_dbg = run_inline_debug(targets.awi_host, k, username=u)
        if awi_dbg:
            log.info(awi_dbg)

    log.info("Final verification passed ✓")

# =========================
# Back-compat wrapper (signature similar to your previous function)
# =========================

def final_verification(ae_ip: str, db_ip: str, awi_ip: str, key_path: Path) -> None:
    """
    Backward-compatible entrypoint. Creates sensible defaults and invokes the orchestrated verifier.
    """
    targets = VerifyTargets(ae_host=ae_ip, awi_host=awi_ip, db_host=db_ip)
    settings = VerifySettings(key_path=key_path)
    final_verification_orchestrated(targets, settings)
def wait_for_port_open(*args, **kwargs):
    return wait_for_port(*args, **kwargs)