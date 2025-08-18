# automic_bootstrap/components/db_load.py
from __future__ import annotations

import argparse
import base64
import logging
import posixpath
import re
import shlex
import sys
from dataclasses import dataclass
from typing import Optional, Tuple, List

import paramiko

log = logging.getLogger(__name__)

# ---------- SSH wrapper ----------
class SSH:
    def __init__(self, host: str, user: str, key_path: str, port: int = 22, timeout: int = 30) -> None:
        self.host = host
        self.user = user
        self.key_path = key_path
        self.port = port
        self.timeout = timeout
        self._client: Optional[paramiko.SSHClient] = None
        self._sftp: Optional[paramiko.SFTPClient] = None

    def connect(self) -> None:
        if self._client:
            return
        key = paramiko.RSAKey.from_private_key_file(self.key_path)
        c = paramiko.SSHClient()
        c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        c.connect(
            self.host,
            username=self.user,
            pkey=key,
            port=self.port,
            timeout=self.timeout,
            banner_timeout=self.timeout,
            auth_timeout=self.timeout,
        )
        self._client = c

    def close(self) -> None:
        if self._sftp:
            self._sftp.close()
            self._sftp = None
        if self._client:
            self._client.close()
            self._client = None

    @property
    def sftp(self) -> paramiko.SFTPClient:
        if not self._client:
            self.connect()
        if not self._client:
            raise RuntimeError("SSH client not connected")
        if not self._sftp:
            self._sftp = self._client.open_sftp()
        return self._sftp

    def run(self, cmd: str) -> Tuple[int, str, str]:
        """Run as the SSH user (no sudo)."""
        if not self._client:
            self.connect()
        if not self._client:
            raise RuntimeError("SSH client not connected")
        full = f"/bin/bash -lc {shlex.quote(cmd)}"
        stdin, stdout, stderr = self._client.exec_command(full)
        rc = stdout.channel.recv_exit_status()
        out = stdout.read().decode("utf-8", "ignore")
        err = stderr.read().decode("utf-8", "ignore")
        return rc, out, err

    def check(self, cmd: str) -> Tuple[str, str]:
        rc, out, err = self.run(cmd)
        if rc != 0:
            raise RuntimeError(f"Remote command failed (rc={rc}): {cmd}\nSTDOUT:\n{out}\n\nSTDERR:\n{err}")
        return out, err

    def sudo_run(self, cmd: str) -> Tuple[int, str, str]:
        return self.run(f"sudo -n /bin/bash -lc {shlex.quote(cmd)}")

    def sudo_check(self, cmd: str) -> Tuple[str, str]:
        rc, out, err = self.sudo_run(cmd)
        if rc != 0:
            raise RuntimeError(f"Remote command failed (rc={rc}): {cmd}\nSTDOUT:\n{out}\n\nSTDERR:\n{err}")
        return out, err

    def put_text(self, remote_path: str, content: str, mode: int = 0o644) -> None:
        f = self.sftp.file(remote_path, "w")
        try:
            f.write(content)
        finally:
            f.close()
        # Safe default perms
        self.sudo_check(f"chmod {mode:o} {shlex.quote(remote_path)} && chown root:root {shlex.quote(remote_path)}")


# ---------- Tiny helpers ----------
def _mkdirs(ssh: SSH, path: str) -> None:
    ssh.sudo_check(f"mkdir -p {shlex.quote(path)}")

def _which(ssh: SSH, name: str) -> bool:
    rc, _, _ = ssh.sudo_run(f"command -v {shlex.quote(name)} >/dev/null 2>&1")
    return rc == 0
# ---- Postgres service handling ----
def ensure_postgres_running(ssh: SSH) -> None:
    """
    Accept any working path:
      - If pg_isready is OK, we're done (no matter how it started).
      - Try common systemd units; if that fails, fall back to pg_ctl.
    """
    log.info("[DB LOAD] Ensure PostgreSQL running...")

    # Already up?
    if ssh.sudo_run("sudo -u postgres /usr/bin/pg_isready -q")[0] == 0:
        log.info("  - PostgreSQL already listening on 5432")
        return

    # Ensure data dir exists & initialized (try helpers, then raw initdb)
    ssh.sudo_check("install -d -o postgres -g postgres -m 700 /var/lib/pgsql/data")
    if ssh.sudo_run("test -f /var/lib/pgsql/data/PG_VERSION")[0] != 0:
        ssh.sudo_run("/usr/pgsql-16/bin/postgresql-16-setup initdb")       # PGDG (may not exist)
        ssh.sudo_run("postgresql-setup --initdb")                           # RHEL/AL2023 (may not exist)
        ssh.sudo_check("sudo -u postgres /usr/bin/initdb -D /var/lib/pgsql/data --encoding UTF8 --locale en_US.UTF-8")

    # Socket dir (pg_ctl uses it)
    ssh.sudo_check("install -d -o postgres -g postgres -m 775 /var/run/postgresql")

    # Try systemd units if present
    for unit in ("postgresql-16", "postgresql", "postgresql@16-main"):
        rc, _, _ = ssh.sudo_run(f"systemctl list-unit-files | grep -q '^{unit}\\.service'")
        if rc == 0:
            ssh.sudo_run("systemctl daemon-reload")
            if ssh.sudo_run(f"systemctl enable --now {unit}")[0] == 0:
                if ssh.sudo_run("sudo -u postgres /usr/bin/pg_isready -q")[0] == 0:
                    log.info(f"  - PostgreSQL started via systemd unit {unit}")
                    return

    # Fallback: pg_ctl
    rc, _, _ = ssh.sudo_run("sudo -u postgres /usr/bin/pg_ctl -D /var/lib/pgsql/data -l /var/lib/pgsql/logfile status")
    if rc != 0:
        ssh.sudo_check("sudo -u postgres /usr/bin/pg_ctl -D /var/lib/pgsql/data -l /var/lib/pgsql/logfile start")

    # Wait up to ~20s for readiness
    rc, _, _ = ssh.sudo_run("for i in {1..20}; do sudo -u postgres /usr/bin/pg_isready -q && exit 0; sleep 1; done; exit 1")
    if rc == 0:
        log.info("  - PostgreSQL started via pg_ctl fallback")
        return

    ssh.sudo_run("tail -n 200 /var/lib/pgsql/logfile || true")
    raise RuntimeError("Could not ensure PostgreSQL is running")
def ensure_db_and_role(ssh: SSH, db_name: str, app_user: str, app_pass: str) -> None:
    # Safe identifiers
    ident = r"[A-Za-z_][A-Za-z0-9_]*"
    if not re.fullmatch(ident, app_user):
        raise ValueError(f"Invalid app_user: {app_user!r}")
    if not re.fullmatch(ident, db_name):
        raise ValueError(f"Invalid db_name: {db_name!r}")

    # Role: create if missing, then reset password
    role_q = f"SELECT 1 FROM pg_roles WHERE rolname='{app_user}'"
    rc, out, _ = ssh.sudo_run(f"sudo -u postgres psql -tAc {shlex.quote(role_q)}")
    if rc != 0 or "1" not in out:
        ssh.sudo_check(
            "sudo -u postgres psql -v ON_ERROR_STOP=1 -c "
            + shlex.quote(f"CREATE ROLE {app_user} LOGIN PASSWORD '{app_pass}'")
        )
    ssh.sudo_check(
        "sudo -u postgres psql -v ON_ERROR_STOP=1 -c "
        + shlex.quote(f"ALTER ROLE {app_user} WITH LOGIN PASSWORD '{app_pass}'")
    )

    # DB: create OUTSIDE a transaction if missing
    db_q = f"SELECT 1 FROM pg_database WHERE datname='{db_name}'"
    rc, out, _ = ssh.sudo_run(f"sudo -u postgres psql -tAc {shlex.quote(db_q)}")
    if rc != 0 or "1" not in out:
        ssh.sudo_check(f"sudo -u postgres createdb -O {app_user} -T template0 {db_name}")


def ensure_contrib_and_extensions(ssh: SSH, db_name: str) -> None:
    # If control file missing, install contrib
    check_cmd = "test -f /usr/pgsql-16/share/extension/pgcrypto.control || test -f /usr/share/pgsql/extension/pgcrypto.control"
    rc, _, _ = ssh.sudo_run(check_cmd)
    if rc != 0:
        log.info("==> Installing PostgreSQL contrib package (pgcrypto/uuid-ossp)")
        if _which(ssh, "dnf"):
            ssh.sudo_check("dnf -y install postgresql16-contrib || dnf -y install postgresql-contrib")
        elif _which(ssh, "yum"):
            ssh.sudo_check("yum -y install postgresql16-contrib || yum -y install postgresql-contrib")
        elif _which(ssh, "apt-get"):
            ssh.sudo_check("apt-get update -y && apt-get install -y postgresql-contrib")
        else:
            raise RuntimeError("Could not install contrib packages (no dnf/yum/apt-get).")

    # Extensions (idempotent)
    ssh.sudo_check(
        f"sudo -u postgres psql -d {shlex.quote(db_name)} -v ON_ERROR_STOP=1 "
        f"-c {shlex.quote('CREATE EXTENSION IF NOT EXISTS pgcrypto;')}"
    )
    ssh.sudo_check(
        f"sudo -u postgres psql -d {shlex.quote(db_name)} -v ON_ERROR_STOP=1 "
        f"-c {shlex.quote('CREATE EXTENSION IF NOT EXISTS \"uuid-ossp\";')}"
    )
# ---- Media handling ----
def _find_media_zip(ssh: SSH, remote_zip: Optional[str], remote_install_root: str) -> str:
    if remote_zip:
        rc, _, _ = ssh.sudo_run(f"test -f {shlex.quote(remote_zip)}")
        if rc != 0:
            raise RuntimeError(f"Automic media not found: {remote_zip}")
        return remote_zip
    cmd = f"ls -1t {shlex.quote(remote_install_root)}/Automic.Automation_*.zip 2>/dev/null | head -n1"
    out, _ = ssh.sudo_check(cmd)
    z = out.strip()
    if not z:
        raise RuntimeError(f"No Automic media zip found in {remote_install_root}")
    return z

def ensure_utils_and_unzip(ssh: SSH, remote_utils: str, remote_zip: Optional[str], remote_install_root: str) -> str:
    _mkdirs(ssh, remote_utils)
    media = _find_media_zip(ssh, remote_zip, remote_install_root)

    # Ensure unzip
    if not _which(ssh, "unzip"):
        if _which(ssh, "dnf"):
            ssh.sudo_check("dnf -y install unzip")
        elif _which(ssh, "yum"):
            ssh.sudo_check("yum -y install unzip")
        elif _which(ssh, "apt-get"):
            ssh.sudo_check("apt-get update -y && apt-get install -y unzip")
        else:
            raise RuntimeError("Cannot install unzip")

    # Unpack (idempotent: -n)
    target = posixpath.join(remote_install_root)
    _mkdirs(ssh, target)
    ssh.sudo_check(f"unzip -q -n {shlex.quote(media)} -d {shlex.quote(target)}")

    # Locate the DB dir: .../Automation.Platform/db/postgresql/<ver>
    find_cmd = (
        f"find {shlex.quote(target)} -maxdepth 5 -type d -path '*/Automation.Platform/db/postgresql/*' "
        f"| sort -V | tail -n1"
    )
    out, _ = ssh.sudo_check(find_cmd)
    dbdir = out.strip()
    if not dbdir:
        raise RuntimeError("Could not locate Automation.Platform/db/postgresql/<version> directory")
    log.info(f"  - db dir: {dbdir}")
    return dbdir
# ---- Runner deployment ----
def _runner_script_content() -> str:
    return r"""#!/usr/bin/env bash
set -euo pipefail

: "${DB:?DB required}"
: "${APPUSER:?APPUSER required}"
: "${APPPASS:?APPPASS required}"
: "${DBDIR:?DBDIR required}"
: "${ILM_ENABLED:=0}"
: "${TS_DATA:=pg_default}"
: "${TS_INDEX:=pg_default}"

echo "==> Prechecks"
psql --version || true
sudo -u postgres psql -Atqc "select version();" || true

echo "==> Ensure app role + DB (idempotent)"
sudo -u postgres psql -v ON_ERROR_STOP=1 -c "DO \$\$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='${APPUSER}') THEN
    CREATE ROLE ${APPUSER} LOGIN PASSWORD '${APPPASS}';
  ELSE
    ALTER ROLE ${APPUSER} WITH LOGIN PASSWORD '${APPPASS}';
  END IF;
END \$\$;"

sudo -u postgres psql -v ON_ERROR_STOP=1 -c "DO \$\$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_database WHERE datname='${DB}') THEN
    EXECUTE 'CREATE DATABASE ' || quote_ident('${DB}')
         || ' OWNER ' || quote_ident('${APPUSER}')
         || ' TEMPLATE template0';
  ELSE
    EXECUTE 'ALTER DATABASE ' || quote_ident('${DB}')
         || ' OWNER TO ' || quote_ident('${APPUSER}');
  END IF;
END \$\$;"

echo "==> Ensure required extensions"
# install contrib if pgcrypto.control missing
if [ ! -f /usr/pgsql-16/share/extension/pgcrypto.control ] && [ ! -f /usr/share/pgsql/extension/pgcrypto.control ]; then
  if command -v dnf >/dev/null 2>&1; then
    dnf -y install postgresql16-contrib || dnf -y install postgresql-contrib
  elif command -v yum >/dev/null 2>&1; then
    yum -y install postgresql16-contrib || yum -y install postgresql-contrib
  elif command -v apt-get >/dev/null 2>&1; then
    apt-get update -y && apt-get install -y postgresql-contrib
  fi
fi
sudo -u postgres psql -d "${DB}" -v ON_ERROR_STOP=1 -c "CREATE EXTENSION IF NOT EXISTS pgcrypto;"
sudo -u postgres psql -d "${DB}" -v ON_ERROR_STOP=1 -c "CREATE EXTENSION IF NOT EXISTS \"uuid-ossp\";"

echo "==> Run BASE schema (ordered)"
BASE_DIR="${DBDIR}/base"
if [ -d "$BASE_DIR" ]; then
  find "$BASE_DIR" -maxdepth 1 -type f -name '*.sql' | sort | while read -r f; do
    echo ">>> BASE RUN: $f"
    sudo -u postgres psql -d "$DB" -q -f "$f" || true
  done
fi

echo "==> Run STEPS (ordered)"
STEPS_DIR="${DBDIR}/steps}"
if [ -d "$STEPS_DIR" ]; then
  find "$STEPS_DIR" -type f -name '*.sql' | sort | while read -r f; do
    echo ">>> STEP: $f"
    sudo -u postgres psql -d "$DB" -q -f "$f" || true
  done
fi

echo "==> Final verification"
sudo -u postgres psql -d "$DB" -Atqc "select current_database(), current_user;"
"""

def deploy_and_run_fixed_runner(
    ssh: "SSH",
    remote_utils: str,
    db_name: str,
    app_user: str,
    app_pass: str,
    dbdir: str,
    ts_data: str,
    ts_index: str,
    ilm_enabled: int = 0,
) -> None:
    """
    Upload the fixed runner into a WRITABLE utils directory and execute it.
    Uses base64 -> sudo tee (no SFTP perms needed). Verifies the file exists.
    """
    utils_dir = remote_utils.rstrip("/")
    runner_path = f"{utils_dir}/aedb_fixed_runner.sh"

    # Ensure the utils dir exists and is owned by the ssh user (ec2-user)
    ssh.sudo_check(
        f"install -d -m 775 -o {shlex.quote(ssh.user)} -g {shlex.quote(ssh.user)} {shlex.quote(utils_dir)}"
    )

    content = _runner_script_content()
    b64 = base64.b64encode(content.encode("utf-8")).decode("ascii")

    # Write with pipefail so we fail if base64 is missing
    write_cmd = (
        "set -euo pipefail; umask 022; "
        f"printf %s {shlex.quote(b64)} | $(command -v base64) -d | "
        f"sudo tee {shlex.quote(runner_path)} >/dev/null"
    )
    rc, out, err = ssh.run(write_cmd)
    if rc != 0:
        raise RuntimeError(
            f"Failed to write runner to {runner_path}\nSTDOUT:\n{out}\nSTDERR:\n{err}"
        )

    # Verify file exists, then chmod
    rc, out, err = ssh.sudo_run(f"test -f {shlex.quote(runner_path)} && echo OK || echo MISSING")
    if rc != 0 or out.strip() != "OK":
        raise RuntimeError(
            f"Runner not present at {runner_path}\nSTDOUT:\n{out}\nSTDERR:\n{err}"
        )

    ssh.sudo_check(f"chmod 755 {shlex.quote(runner_path)}")

    # Build env and run
    env = " ".join([
        f"DB={shlex.quote(db_name)}",
        f"APPUSER={shlex.quote(app_user)}",
        f"APPPASS={shlex.quote(app_pass)}",
        f"DBDIR={shlex.quote(dbdir)}",
        f"ILM_ENABLED={int(ilm_enabled)}",
        f"TS_DATA={shlex.quote(ts_data)}",
        f"TS_INDEX={shlex.quote(ts_index)}",
    ])

    log.info("  - running %s ...", runner_path)
    ssh.sudo_check(f"/usr/bin/env {env} bash {shlex.quote(runner_path)}")
# ---- Public API ----
@dataclass
class DBLoadConfig:
    db_host: str
    key_path: str
    ssh_user: str = "ec2-user"

    db_name: str = "AEDB"
    app_user: str = "aauser"
    app_pass: str = "Automic123"

    remote_zip: Optional[str] = None
    remote_install_root: str = "/opt/automic/install"
    remote_utils: str = "/opt/automic/utils"

    with_tablespaces: bool = False
    ts_data_name: str = "ae_data"
    ts_index_name: str = "ae_index"
    ts_data_path: str = "/var/lib/pgsql/ae_data"
    ts_index_path: str = "/var/lib/pgsql/ae_index"

    ilm_enabled: int = 0
    verbosity: int = 1


def setup_logging(verbosity: int = 1) -> None:
    level = logging.INFO if verbosity <= 1 else logging.DEBUG
    fmt = "%(asctime)s [%(levelname)s] %(message)s"
    datefmt = "%H:%M:%S"
    logging.basicConfig(level=level, format=fmt, datefmt=datefmt)


def run_db_load(
    db_host: str,
    key_path: str,
    ssh_user: str = "ec2-user",
    db_name: str = "AEDB",
    app_user: str = "aauser",
    app_pass: str = "Automic123",
    remote_zip: Optional[str] = None,
    remote_install_root: str = "/opt/automic/install",
    remote_utils: str = "/opt/automic/utils",
    with_tablespaces: bool = False,
    ts_data_name: str = "ae_data",
    ts_index_name: str = "ae_index",
    ts_data_path: str = "/var/lib/pgsql/ae_data",
    ts_index_path: str = "/var/lib/pgsql/ae_index",
    ilm_enabled: int = 0,
    verbosity: int = 1,
) -> None:
    """
    Ensure PostgreSQL is up, create role & DB, ensure extensions, unpack media,
    and run the vendor schema via a safe runner in a writable path.
    """
    setup_logging(verbosity)
    log.info("== Automic AEDB DB Load ==")

    ssh = SSH(db_host, ssh_user, key_path)
    try:
        ssh.connect()

        # 1) Postgres up
        ensure_postgres_running(ssh)

        # 2) DB + role
        log.info("[DB LOAD] Ensure DB %s...", db_name)
        ensure_db_and_role(ssh, db_name, app_user, app_pass)

        # 3) Media present & unpacked, and utils dir writable
        log.info("[DB LOAD] Prepare utils dir and locate/unpack media...")
        dbdir = ensure_utils_and_unzip(ssh, remote_utils, remote_zip, remote_install_root)

        # 4) Tablespaces (optional)
        if with_tablespaces:
            log.info("[DB LOAD] Tablespaces enabled: data=%s index=%s", ts_data_name, ts_index_name)
            ssh.sudo_check(
                " ".join([
                    "mkdir -p", shlex.quote(ts_data_path), shlex.quote(ts_index_path), "&&",
                    "chown -R postgres:postgres", shlex.quote(ts_data_path), shlex.quote(ts_index_path),
                ])
            )
            ts_sql = (
                "DO $$ BEGIN "
                f"IF NOT EXISTS (SELECT 1 FROM pg_tablespace WHERE spcname='{ts_data_name}') THEN "
                f"EXECUTE 'CREATE TABLESPACE {ts_data_name} OWNER {app_user} LOCATION ' || quote_literal('{ts_data_path}'); "
                "END IF; "
                f"IF NOT EXISTS (SELECT 1 FROM pg_tablespace WHERE spcname='{ts_index_name}') THEN "
                f"EXECUTE 'CREATE TABLESPACE {ts_index_name} OWNER {app_user} LOCATION ' || quote_literal('{ts_index_path}'); "
                "END IF; "
                "END $$;"
            )
            ssh.sudo_check(f"sudo -u postgres psql -v ON_ERROR_STOP=1 -c {shlex.quote(ts_sql)}")
            ts_data, ts_index = ts_data_name, ts_index_name
        else:
            log.info("[DB LOAD] Tablespaces disabled: using TABLESPACE pg_default for all objects.")
            ts_data, ts_index = "pg_default", "pg_default"

        # 5) Contrib + required extensions
        ensure_contrib_and_extensions(ssh, db_name)

        # 6) Run the vendor schema via our fixed runner
        deploy_and_run_fixed_runner(
            ssh=ssh,
            remote_utils=remote_utils,
            db_name=db_name,
            app_user=app_user,
            app_pass=app_pass,
            dbdir=dbdir,
            ts_data=ts_data,
            ts_index=ts_index,
            ilm_enabled=ilm_enabled,
        )

        log.info("[DB LOAD] Complete.")
    finally:
        ssh.close()


# ---- CLI (for standalone testing) ----
def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Automic AEDB load helper (PostgreSQL)")
    p.add_argument("--db-host", required=True)
    p.add_argument("--ssh-user", default="ec2-user")
    p.add_argument("--key-path", required=True)

    p.add_argument("--db-name", default="AEDB")
    p.add_argument("--app-user", default="aauser")
    p.add_argument("--app-pass", default="Automic123")

    p.add_argument("--remote-zip", default=None)
    p.add_argument("--remote-install-root", default="/opt/automic/install")
    p.add_argument("--remote-utils", default="/opt/automic/utils")

    p.add_argument("--with-tablespaces", action="store_true")
    p.add_argument("--ts-data-name", default="ae_data")
    p.add_argument("--ts-index-name", default="ae_index")
    p.add_argument("--ts-data-path", default="/var/lib/pgsql/ae_data")
    p.add_argument("--ts-index-path", default="/var/lib/pgsql/ae_index")

    p.add_argument("--ilm-enabled", type=int, default=0)
    p.add_argument("--verbosity", type=int, default=1)
    return p.parse_args(argv)


def main(argv: Optional[List[str]] = None) -> int:
    ns = parse_args(argv)
    try:
        run_db_load(
            db_host=ns.db_host,
            key_path=ns.key_path,
            ssh_user=ns.ssh_user,
            db_name=ns.db_name,
            app_user=ns.app_user,
            app_pass=ns.app_pass,
            remote_zip=ns.remote_zip,
            remote_install_root=ns.remote_install_root,
            remote_utils=ns.remote_utils,
            with_tablespaces=ns.with_tablespaces,
            ts_data_name=ns.ts_data_name,
            ts_index_name=ns.ts_index_name,
            ts_data_path=ns.ts_data_path,
            ts_index_path=ns.ts_index_path,
            ilm_enabled=ns.ilm_enabled,
            verbosity=ns.verbosity,
        )
        return 0
    except Exception as e:
        log.error("Upload or AEDB load failed: %s", e)
        raise


if __name__ == "__main__":
    sys.exit(main())

