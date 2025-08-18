# automic_bootstrap/components/ae_engine.py
from __future__ import annotations

import argparse
import logging
import os
import posixpath
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Optional, Tuple

import paramiko

log = logging.getLogger(__name__)

# ====== Data Model ======
@dataclass
class AEInstallConfig:
    ae_host: str
    key_path: str
    ssh_user: str = "ec2-user"

    # Where the Automic bundle was unzipped during DB stage
    # e.g., /opt/automic/install/Automic.Automation_24.4.1_2025-07-25
    remote_unzip_root: str = "/opt/automic/install"

    # JDBC (local path on your workstation; will be uploaded)
    jdbc_jar: Optional[str] = None  # e.g., C:\LAB\jars\postgresql-42.7.4.jar

    # DB connection
    db_host: str = "127.0.0.1"
    db_name: str = "AEDB"
    db_user: str = "aauser"
    db_password: str = "Automic123"

    # AE process ports (JCP/REST used by later stages)
    jcp_port: int = 8843
    rest_port: int = 8088

    # If you want to pre-wire TLS file paths in ucsrv.ini (keystores created later)
    enable_tls: bool = False
    tls_keystore_path: str = "/opt/automic/certs/ae_keystore.p12"
    tls_keystore_pass: str = "changeit"
    tls_truststore_path: str = "/opt/automic/certs/truststore.p12"
    tls_truststore_pass: str = "changeit"


# ====== SSH helpers (local, self-contained) ======
def _ssh(aecfg: AEInstallConfig) -> paramiko.SSHClient:
    key = paramiko.RSAKey.from_private_key_file(aecfg.key_path)
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(
        hostname=aecfg.ae_host,
        username=aecfg.ssh_user,
        pkey=key,
        timeout=30,
        banner_timeout=30,
    )
    return ssh


def _run(ssh: paramiko.SSHClient, cmd: str, check: bool = True) -> Tuple[int, str, str]:
    log.debug("RUN: %s", cmd)
    stdin, stdout, stderr = ssh.exec_command(cmd)
    rc = stdout.channel.recv_exit_status()
    out = stdout.read().decode("utf-8", errors="replace")
    err = stderr.read().decode("utf-8", errors="replace")
    if check and rc != 0:
        raise RuntimeError(f"Command failed ({rc}): {cmd}\nSTDOUT:\n{out}\nSTDERR:\n{err}")
    return rc, out, err


def _sftp_put(ssh: paramiko.SSHClient, local: str, remote: str) -> None:
    log.debug("SFTP PUT %s -> %s", local, remote)
    sftp = ssh.open_sftp()
    try:
        # ensure remote dir
        rdir = posixpath.dirname(remote)
        _run(ssh, f"mkdir -p {sh(remote=rdir)}", check=True)
        sftp.put(local, remote)
    finally:
        sftp.close()


def sh(remote: Optional[str] = None) -> str:
    """Very small POSIX shell escaper for paths/values we control."""
    if remote is None:
        return "''"
    return "'" + remote.replace("'", "'\"'\"'") + "'"


# ====== AE discovery & layout ======
def detect_automation_engine_root(ssh: paramiko.SSHClient, unzip_root: str) -> str:
    """
    Try to locate the AE binary root inside the unzipped Automic bundle.
    Typical layouts (recent versions):
      <UNZIP>/Automation.Platform/Automation.Engine
      <UNZIP>/Automation.Engine
    We pick the first match that exists and looks sane.
    """
    probe = [
        f"{unzip_root}/Automation.Platform/Automation.Engine",
        f"{unzip_root}/Automation.Engine",
    ]
    for p in probe:
        rc, out, _ = _run(ssh, f"test -d {sh(p)} && echo OK || true", check=False)
        if "OK" in out:
            # quick sanity: must have bin/ucsrv.ini and bin directory
            rc, out, _ = _run(ssh, f"test -f {sh(p + '/bin/ucsrv.ini')} && echo OK || true", check=False)
            if "OK" in out:
                log.info("Detected Automation.Engine at: %s", p)
                return p
    raise RuntimeError(
        f"Could not locate Automation.Engine under {unzip_root}. "
        "Ensure the Automic media was unzipped by the DB stage."
    )


def ensure_common_dirs(ssh: paramiko.SSHClient, ae_root: str) -> None:
    paths = [
        f"{ae_root}/bin",
        f"{ae_root}/bin/lib",
        f"{ae_root}/jars",
        "/opt/automic/certs",
    ]
    _run(ssh, " && ".join([f"mkdir -p {sh(p)}" for p in paths]))


# ====== JDBC placement ======
def install_jdbc_driver(ssh: paramiko.SSHClient, ae_root: str, jdbc_local: Optional[str]) -> Optional[str]:
    """
    Upload a JDBC jar if provided, otherwise try to reuse an existing one.
    Returns the path we will set in ucsrv.ini (inside bin/lib or jars).
    """
    if jdbc_local and Path(jdbc_local).is_file():
        # Prefer bin/lib (commonly scanned), but keep a copy in jars for clarity
        remote_binlib = f"{ae_root}/bin/lib/{Path(jdbc_local).name}"
        _sftp_put(ssh, jdbc_local, remote_binlib)
        return remote_binlib

    # Try to find an existing postgresql jar
    rc, out, _ = _run(
        ssh,
        f"ls -1 {sh(ae_root + '/bin/lib')}/postgresql-*.jar {sh(ae_root + '/jars')}/postgresql-*.jar 2>/dev/null || true",
        check=False,
    )
    candidates = [ln.strip() for ln in out.splitlines() if ln.strip()]
    if candidates:
        log.info("Reusing JDBC jar: %s", candidates[0])
        return candidates[0]
    raise RuntimeError(
        "No JDBC driver found and none provided. Supply --jdbc-jar pointing to a local postgresql-*.jar."
    )


# ====== ucsrv.ini patching ======
_KV_RE = re.compile(r"^\s*([A-Za-z0-9_.-]+)\s*=\s*(.*)\s*$")

def _set_ini_key(text: str, section: str, key: str, value: str) -> str:
    """Idempotently set a key in a given section; create section if missing."""
    lines = text.splitlines()
    out = []
    in_sec = False
    sec_header = f"[{section}]"
    found_sec = False
    replaced = False

    for i, line in enumerate(lines):
        if line.strip().startswith("[") and line.strip().endswith("]"):
            if in_sec and not replaced:
                out.append(f"{key}={value}")
            in_sec = (line.strip() == sec_header)
            if in_sec:
                found_sec = True
            out.append(line)
            continue

        if in_sec:
            m = _KV_RE.match(line)
            if m and m.group(1) == key:
                if not replaced:
                    out.append(f"{key}={value}")
                    replaced = True
                else:
                    # skip duplicate
                    pass
            else:
                out.append(line)
        else:
            out.append(line)

    # If we never saw the section, append it
    if not found_sec:
        out.append("")
        out.append(sec_header)
        out.append(f"{key}={value}")
    elif in_sec and not replaced:
        out.append(f"{key}={value}")

    return "\n".join(out) + ("\n" if not text.endswith("\n") else "")


def patch_ucsrv_ini_for_postgres(
    ssh: paramiko.SSHClient,
    ae_root: str,
    jdbc_path: str,
    db_host: str,
    db_name: str,
    db_user: str,
    db_pass: str,
    jcp_port: int,
    rest_port: int,
    enable_tls: bool,
    tls_keystore_path: str,
    tls_keystore_pass: str,
    tls_truststore_path: str,
    tls_truststore_pass: str,
) -> None:
    ini_path = f"{ae_root}/bin/ucsrv.ini"
    # pull
    sftp = ssh.open_sftp()
    try:
        with sftp.file(ini_path, "r") as f:
            content = f.read().decode("utf-8", errors="replace")
    finally:
        sftp.close()

    # patch DB section
    content = _set_ini_key(content, "DB", "Type", "POSTGRES")
    content = _set_ini_key(content, "DB", "Server", db_host)
    content = _set_ini_key(content, "DB", "Port", "5432")
    content = _set_ini_key(content, "DB", "Database", db_name)
    # SQLDriverConnect varies by version; use standard ODBC string understood by AE
    odbc = (
        "DRIVER={PostgreSQL Unicode};"
        f"Server={db_host};Port=5432;Database={db_name};"
        f"UID={db_user};PWD={db_pass};"
    )
    content = _set_ini_key(content, "DB", "SQLDriverConnect", odbc)
    # Ensure JDBC is discoverable
    content = _set_ini_key(content, "JDBC", "Jar", jdbc_path)

    # Bring up basics for JWP/JCP/REST
    content = _set_ini_key(content, "JWP", "StartMode", "AUTO")
    content = _set_ini_key(content, "JCP", "StartMode", "AUTO")
    content = _set_ini_key(content, "REST", "StartMode", "AUTO")
    content = _set_ini_key(content, "REST", "Port", str(rest_port))
    content = _set_ini_key(content, "JCP", "Port", str(jcp_port))

    if enable_tls:
        # These keys/sections are representative; exact names can vary a bit by version.
        # We wire common ones so later TLS stage can just drop keystores.
        content = _set_ini_key(content, "TLS", "Keystore", tls_keystore_path)
        content = _set_ini_key(content, "TLS", "KeystorePassword", tls_keystore_pass)
        content = _set_ini_key(content, "TLS", "Truststore", tls_truststore_path)
        content = _set_ini_key(content, "TLS", "TruststorePassword", tls_truststore_pass)
        content = _set_ini_key(content, "JCP", "UseTLS", "1")
        content = _set_ini_key(content, "REST", "UseTLS", "1")
    else:
        content = _set_ini_key(content, "JCP", "UseTLS", "0")
        content = _set_ini_key(content, "REST", "UseTLS", "0")

    # push back
    sftp = ssh.open_sftp()
    try:
        tmp = ini_path + ".tmp"
        with sftp.file(tmp, "w") as f:
            f.write(content.encode("utf-8"))
        _run(ssh, f"cp {sh(tmp)} {sh(ini_path)} && rm -f {sh(tmp)}")
    finally:
        sftp.close()
    log.info("Patched %s", ini_path)


# ====== Public entrypoint ======
def run_install_ae(cfg: AEInstallConfig) -> str:
    """
    Configures Automation.Engine in-place.
    Returns the detected AE root path.
    """
    ssh = _ssh(cfg)
    try:
        # Find unzipped media root (the DB stage created a single top-level folder)
        # Strategy: pick the newest "Automic.Automation_*" in remote_unzip_root
        rc, out, _ = _run(
            ssh,
            f"ls -1dt {sh(cfg.remote_unzip_root)}/Automic.Automation_* 2>/dev/null | head -n1 || true",
            check=False,
        )
        bundle_root = out.strip()
        if not bundle_root:
            raise RuntimeError(
                f"No Automic bundle found under {cfg.remote_unzip_root}. "
                "Expected a directory like Automic.Automation_24.4.1_YYYY-MM-DD"
            )
        log.info("Bundle root: %s", bundle_root)

        ae_root = detect_automation_engine_root(ssh, bundle_root)
        ensure_common_dirs(ssh, ae_root)
        jdbc_path = install_jdbc_driver(ssh, ae_root, cfg.jdbc_jar)
        if jdbc_path is None:
            raise RuntimeError("JDBC driver was not provided and none were found on the remote host.")

        patch_ucsrv_ini_for_postgres(
            ssh=ssh,
            ae_root=ae_root,
            jdbc_path=jdbc_path,
            db_host=cfg.db_host,
            db_name=cfg.db_name,
            db_user=cfg.db_user,
            db_pass=cfg.db_password,
            jcp_port=cfg.jcp_port,
            rest_port=cfg.rest_port,
            enable_tls=cfg.enable_tls,
            tls_keystore_path=cfg.tls_keystore_path,
            tls_keystore_pass=cfg.tls_keystore_pass,
            tls_truststore_path=cfg.tls_truststore_path,
            tls_truststore_pass=cfg.tls_truststore_pass,
        )

        # We do NOT start AE here; Service Manager will control lifecycle.
        log.info("AE configured. Next step: install Service Manager and define services.")
        return ae_root
    finally:
        ssh.close()


# ====== CLI glue (optional direct module run) ======
def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Install/Configure Automic Automation Engine (AE)")
    p.add_argument("--ae-host", required=True, help="AE host (EC2 public IP/DNS)")
    p.add_argument("--ssh-user", default="ec2-user", help="SSH user (default: ec2-user)")
    p.add_argument("--key-path", required=True, help="Path to PEM key")

    p.add_argument("--remote-unzip-root", default="/opt/automic/install", help="Where Automic zip was unzipped")
    p.add_argument("--jdbc-jar", default=None, help="Local path to postgresql-*.jar")

    p.add_argument("--db-host", required=True, help="PostgreSQL host")
    p.add_argument("--db-name", default="AEDB")
    p.add_argument("--db-user", default="aauser")
    p.add_argument("--db-password", required=True)

    p.add_argument("--jcp-port", type=int, default=8843)
    p.add_argument("--rest-port", type=int, default=8088)
    p.add_argument("--enable-tls", action="store_true")

    return p


def install_ae_from_argv(argv: Optional[list[str]] = None) -> None:
    args = _build_parser().parse_args(argv)
    cfg = AEInstallConfig(
        ae_host=args.ae_host,
        key_path=args.key_path,
        ssh_user=args.ssh_user,
        remote_unzip_root=args.remote_unzip_root,
        jdbc_jar=args.jdbc_jar,
        db_host=args.db_host,
        db_name=args.db_name,
        db_user=args.db_user,
        db_password=args.db_password,
        jcp_port=args.jcp_port,
        rest_port=args.rest_port,
        enable_tls=bool(args.enable_tls),
    )
    ae_root = run_install_ae(cfg)
    print(ae_root)


if __name__ == "__main__":
    # Allows: python -m automic_bootstrap.components.ae_engine --ae-host ... (handy for testing)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s", datefmt="%H:%M:%S")
    install_ae_from_argv()
