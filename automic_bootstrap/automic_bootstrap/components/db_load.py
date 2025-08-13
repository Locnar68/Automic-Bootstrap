# automic_bootstrap/components/db_load.py
from __future__ import annotations

import argparse
import logging
import posixpath
import shlex
import sys
from dataclasses import dataclass
from typing import List, Optional, Tuple

import paramiko

# ---------- Logging ----------
log = logging.getLogger(__name__)

def setup_logging(verbosity: int = 1) -> None:
    level = logging.INFO if verbosity <= 1 else logging.DEBUG
    fmt = "%(asctime)s [%(levelname)s] %(message)s"
    datefmt = "%H:%M:%S"
    logging.basicConfig(level=level, format=fmt, datefmt=datefmt)

# ---------- CLI ----------
def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Automic AEDB load helper (PostgreSQL)")

    p.add_argument("--db-host", required=True, help="DB server IP/DNS")
    p.add_argument("--ssh-user", default="ec2-user", help="SSH username (default: ec2-user)")
    p.add_argument("--key-path", required=True, help="Path to PEM key")

    p.add_argument("--db-name", default="AEDB", help="Database name (default: AEDB)")
    p.add_argument("--db-user", default="postgres", help="DB superuser on the box (default: postgres)")
    p.add_argument("--db-password", required=True, help="DB superuser password (kept for future use)")

    # App owner of AEDB
    p.add_argument("--app-user", default="aauser", help="Automic DB user to own AEDB (default: aauser)")
    p.add_argument("--app-pass", default="Automic123", help="Password for --app-user (default: Automic123)")

    p.add_argument("--remote-zip", required=True, help="Path to Automic media ZIP on remote host")
    p.add_argument("--remote-install-root", default="/opt/automic/install", help="Install root (default: /opt/automic/install)")
    p.add_argument("--remote-utils", default="/opt/automic/utils", help="Utils dir (default: /opt/automic/utils)")

    # Tablespaces
    p.add_argument("--with-tablespaces", action="store_true", help="Create and wire tablespaces before loading schema")
    p.add_argument("--ts-data-name", default="ae_data", help="Data tablespace name (default: ae_data)")
    p.add_argument("--ts-index-name", default="ae_index", help="Index tablespace name (default: ae_index)")
    p.add_argument("--ts-data-path", default="/pgdata/ts/AE_DATA", help="Path for data tablespace directory")
    p.add_argument("--ts-index-path", default="/pgdata/ts/AE_INDEX", help="Path for index tablespace directory")

    p.add_argument("--verbosity", "-v", action="count", default=1, help="Increase log verbosity (-vv for debug)")
    return p.parse_args(argv or sys.argv[1:])

# ---------- SSH wrapper ----------
@dataclass
class SSHConfig:
    host: str
    user: str = "ec2-user"
    key_path: str = ""
    port: int = 22
    timeout: int = 30

class SSH:
    def __init__(self, cfg: SSHConfig):
        self.cfg = cfg
        self.client = paramiko.SSHClient()
        self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    def __enter__(self) -> "SSH":
        pkey = paramiko.RSAKey.from_private_key_file(self.cfg.key_path)
        self.client.connect(
            hostname=self.cfg.host,
            username=self.cfg.user,
            pkey=pkey,
            port=self.cfg.port,
            timeout=self.cfg.timeout,
            banner_timeout=self.cfg.timeout,
            auth_timeout=self.cfg.timeout,
        )
        return self

    def __exit__(self, exc_type, exc, tb):
        try:
            self.client.close()
        finally:
            return False

    def run(self, cmd: str, timeout: int = 300) -> Tuple[int, str, str]:
        log.debug("RUN: %s", cmd)
        stdin, stdout, stderr = self.client.exec_command(cmd, timeout=timeout)
        out = stdout.read().decode("utf-8", "ignore")
        err = stderr.read().decode("utf-8", "ignore")
        rc = stdout.channel.recv_exit_status()
        log.debug("RC=%s\nSTDOUT:\n%s\nSTDERR:\n%s", rc, out, err)
        return rc, out, err

    def sudo(self, cmd: str, timeout: int = 300) -> Tuple[int, str, str]:
        wrapped = f"sudo bash -lc {shlex.quote(cmd)}"
        return self.run(wrapped, timeout=timeout)

    def sudo_check(self, cmd: str, timeout: int = 300) -> str:
        rc, out, err = self.sudo(cmd, timeout=timeout)
        if rc != 0:
            raise RuntimeError(f"Remote command failed (rc={rc}): {cmd}\nSTDOUT:\n{out}\nSTDERR:\n{err}")
        return out

    def put(self, local_path: str, remote_path: str) -> None:
        sftp = self.client.open_sftp()
        try:
            sftp.put(local_path, remote_path)
        finally:
            sftp.close()

    def put_text(self, content: str, remote_path: str, mode: int = 0o755) -> None:
        """Write a small text file to remote_path and chmod it."""
        sftp = self.client.open_sftp()
        try:
            with sftp.file(remote_path, "w") as f:
                f.write(content)
            sftp.chmod(remote_path, mode)
        finally:
            sftp.close()
# ---------- PostgreSQL service helpers ----------
def detect_pg_service(ssh: SSH) -> str:
    """
    Detect the correct PostgreSQL systemd unit.
    Prefer versioned units (postgresql-16, postgresql@16), fallback to 'postgresql'.
    """
    rc, out, _ = ssh.sudo("systemctl list-unit-files | awk '{print $1}'")
    units = set(out.split()) if rc == 0 else set()

    for cand in ("postgresql-16.service", "postgresql@16.service"):
        if cand in units:
            return cand.removesuffix(".service")

    if "postgresql.service" in units:
        return "postgresql"

    for u in units:
        if u.startswith("postgresql") and u.endswith(".service"):
            return u.removesuffix(".service")

    raise RuntimeError("No PostgreSQL unit found (tried postgresql-16, postgresql@16, postgresql).")

def _port_5432_listening(ssh: SSH) -> bool:
    rc, out, _ = ssh.sudo("ss -ltnp | grep -E '(:|\\.)5432\\b' || true")
    if out.strip():
        return True
    rc, out, _ = ssh.sudo("netstat -ltnp 2>/dev/null | grep -E '(:|\\.)5432\\b' || true")
    return bool(out.strip())

def ensure_pg_running(ssh: SSH, unit: str) -> None:
    """Ensure PostgreSQL is running."""
    log.info("[DB LOAD] Ensure PostgreSQL running...")

    if _port_5432_listening(ssh):
        log.info("  - PostgreSQL already listening on 5432")
        ssh.sudo_check("sudo -u postgres psql -XAtc 'SELECT version();'")
        return

    rc, _, _ = ssh.sudo(f"systemctl start {shlex.quote(unit)}")
    if rc == 0:
        ssh.sudo_check("sudo -u postgres psql -XAtc 'SELECT version();'")
        return

    log.warning("  - start failed; applying small self-heal and retrying")
    ssh.sudo("mkdir -p /run/postgresql && chown postgres:postgres /run/postgresql && chmod 775 /run/postgresql")
    ssh.sudo("rm -f /run/postgresql/.s.PGSQL.5432.lock || true")
    ssh.sudo("systemctl daemon-reload || true")
    ssh.sudo_check(f"systemctl enable --now {shlex.quote(unit)}")
    ssh.sudo_check("sudo -u postgres psql -XAtc 'SELECT version();'")
    log.info("  - PostgreSQL is up.")

# ---------- Basic DB helpers ----------
def ensure_db_exists(ssh: SSH, dbname: str, dbuser: str = "postgres") -> None:
    log.info("[DB LOAD] Ensure DB %s...", dbname)
    out = ssh.sudo_check(
        f"sudo -u {shlex.quote(dbuser)} psql -XAtc \"SELECT 1 FROM pg_database WHERE datname='{dbname}';\""
    )
    if not out.strip():
        ssh.sudo_check(f"sudo -u {shlex.quote(dbuser)} createdb {shlex.quote(dbname)}")

# ---------- Unzip media and locate db/postgresql ----------
def _ensure_tool(ssh: SSH, bin_name: str, install_cmd: str) -> None:
    rc, _, _ = ssh.sudo(f"command -v {shlex.quote(bin_name)}")
    if rc != 0:
        ssh.sudo_check(install_cmd)

def ensure_utils_and_unzip(ssh: SSH, remote_utils: str, remote_zip: str, install_root: str) -> str:
    """
    Ensures utils dir exists, tools available, and the product zip is extracted
    under install_root/<zip-stem>. Returns the path to .../Automation.Platform/db/postgresql
    """
    log.info("[DB LOAD] Prepare utils dir and unzip media...")
    ssh.sudo_check(f"mkdir -p {shlex.quote(remote_utils)}")
    ssh.sudo_check(f"chmod 755 {shlex.quote(remote_utils)}")

    _ensure_tool(ssh, "unzip", "dnf -y install unzip || yum -y install unzip || true")
    _ensure_tool(ssh, "rsync", "dnf -y install rsync || yum -y install rsync || true")

    ssh.sudo_check(f"mkdir -p {shlex.quote(install_root)}")

    base = posixpath.basename(remote_zip)
    stem = base[:-4] if base.lower().endswith(".zip") else base
    extract_dir = posixpath.join(install_root, stem)

    rc, _, _ = ssh.sudo(f"test -d {shlexquote(extract_dir)}")  # noqa: F821 (we'll fix below)
    # (fix typo) use posixpath, not shlexquote
    rc, _, _ = ssh.sudo(f"test -d {shlex.quote(extract_dir)}")
    if rc != 0:
        ssh.sudo_check(f"unzip -q -o {shlex.quote(remote_zip)} -d {shlex.quote(extract_dir)}")
        ssh.sudo_check(f"find {shlex.quote(extract_dir)} -type f -name '*.sh' -exec chmod +x {{}} +;")
        log.info("  - extracted to %s", extract_dir)
    else:
        log.info("  - archive already extracted at %s", extract_dir)

    # Find .../Automation.Platform/db/postgresql
    find_db = (
        f"find {shlex.quote(extract_dir)} -maxdepth 5 -type d "
        f"-path '*/Automation.Platform/db/postgresql' | sort | tail -n1"
    )
    rc, out, _ = ssh.sudo("sh -lc " + shlex.quote(find_db))
    db_pg_root = out.strip()
    if not db_pg_root:
        raise RuntimeError(f"Could not locate Automation.Platform/db/postgresql under {extract_dir}")
    log.info("  - db dir: %s", db_pg_root)
    return db_pg_root

def _prefer_latest_base_dir(ssh: SSH, root: str) -> Optional[str]:
    """Pick the highest version dir under .../db/postgresql (e.g., 24.4)."""
    inner = f"find {shlex.quote(root)} -mindepth 1 -maxdepth 1 -type d -printf '%f\\n' | sort -V"
    rc, out, _ = ssh.sudo("sh -lc " + shlex.quote(inner))
    if rc != 0 or not out.strip():
        return None
    ver = out.strip().splitlines()[-1].strip()
    return posixpath.join(root, ver)

# ---------- Tablespaces ----------
def ensure_tablespaces(
    ssh: SSH,
    *,
    dbname: str,
    app_user: str,
    data_ts_name: str = "ae_data",
    index_ts_name: str = "ae_index",
    data_path: str = "/pgdata/ts/AE_DATA",
    index_path: str = "/pgdata/ts/AE_INDEX",
) -> None:
    log.info("[DB LOAD] Ensuring tablespaces: %s (%s), %s (%s)", data_ts_name, data_path, index_ts_name, index_path)

    # Directories & ownership
    ssh.sudo_check(f"mkdir -p {shlex.quote(data_path)} {shlex.quote(index_path)}")
    # chown parent folder to postgres (covers both)
    parent = posixpath.dirname(data_path.rstrip("/"))
    ssh.sudo_check(f"chown -R postgres:postgres {shlex.quote(parent)}")
    ssh.sudo_check(f"chmod 700 {shlex.quote(data_path)} {shlex.quote(index_path)}")

    # Exists?
    def ts_exists(name: str) -> bool:
        rc, out, _ = ssh.sudo(f"sudo -u postgres psql -XAtc \"SELECT 1 FROM pg_tablespace WHERE spcname='{name}';\"")
        return rc == 0 and out.strip() == "1"

    # Create if missing
    if not ts_exists(data_ts_name):
        ssh.sudo_check(
            f"sudo -u postgres psql -v ON_ERROR_STOP=1 -Xc "
            f"\"CREATE TABLESPACE {data_ts_name} OWNER postgres LOCATION '{data_path}';\""
        )
    if not ts_exists(index_ts_name):
        ssh.sudo_check(
            f"sudo -u postgres psql -v ON_ERROR_STOP=1 -Xc "
            f"\"CREATE TABLESPACE {index_ts_name} OWNER postgres LOCATION '{index_path}';\""
        )

    # Grant usage to app user
    ssh.sudo_check(
        f"sudo -u postgres psql -v ON_ERROR_STOP=1 -Xc "
        f"\"GRANT CREATE, USAGE ON TABLESPACE {data_ts_name} TO \\\"{app_user}\\\";\""
    )
    ssh.sudo_check(
        f"sudo -u postgres psql -v ON_ERROR_STOP=1 -Xc "
        f"\"GRANT CREATE, USAGE ON TABLESPACE {index_ts_name} TO \\\"{app_user}\\\";\""
    )

    # Set defaults to steer new objects to data TS
    ssh.sudo_check(
        f"sudo -u postgres psql -v ON_ERROR_STOP=1 -Xc "
        f"\"ALTER DATABASE \\\"{dbname}\\\" SET default_tablespace = '{data_ts_name}';\""
    )
    ssh.sudo_check(
        f"sudo -u postgres psql -v ON_ERROR_STOP=1 -Xc "
        f"\"ALTER ROLE \\\"{app_user}\\\" IN DATABASE \\\"{dbname}\\\" SET default_tablespace = '{data_ts_name}';\""
    )

    log.info("  - tablespaces ready; defaults set to %s", data_ts_name)
# ---------- Embedded bash scripts ----------
FIX_AND_LOAD_SCRIPT = r"""#!/usr/bin/env bash
set -euo pipefail

DB="${DB:-AEDB}"
APPUSER="${APPUSER:-aauser}"
APPPASS="${APPPASS:-Automic123}"
DBDIR="${DBDIR:-/opt/automic/install/Automic.Automation_24.4.1_2025-07-25/Automation.Platform/db/postgresql/24.4}"

echo "==> Prechecks"
sudo -u postgres psql -XAtc "SELECT version();"

echo "==> Ensure app role + DB ownership + schema privileges"
sudo -u postgres psql -X -v ON_ERROR_STOP=1 -c "DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='${APPUSER}') THEN
    CREATE ROLE \"${APPUSER}\" LOGIN PASSWORD '${APPPASS}';
  ELSE
    ALTER ROLE \"${APPUSER}\" LOGIN PASSWORD '${APPPASS}';
  END IF;
END $$;"
sudo -u postgres psql -X -v ON_ERROR_STOP=1 -c "ALTER DATABASE \"${DB}\" OWNER TO \"${APPUSER}\";"
sudo -u postgres psql -X -d "${DB}" -v ON_ERROR_STOP=1 -c "ALTER SCHEMA public OWNER TO \"${APPUSER}\";"
sudo -u postgres psql -X -d "${DB}" -v ON_ERROR_STOP=1 -c "GRANT USAGE, CREATE ON SCHEMA public TO \"${APPUSER}\";"
sudo -u postgres psql -X -v ON_ERROR_STOP=1 -c "GRANT ALL PRIVILEGES ON DATABASE \"${DB}\" TO \"${APPUSER}\";"

echo "==> Ensure extensions (pgcrypto, uuid-ossp)"
sudo dnf -y install postgresql16-contrib || sudo yum -y install postgresql16-contrib || true
sudo -u postgres psql -X -d "${DB}" -v ON_ERROR_STOP=1 -c "CREATE EXTENSION IF NOT EXISTS pgcrypto;"
sudo -u postgres psql -X -d "${DB}" -v ON_ERROR_STOP=1 -c "CREATE EXTENSION IF NOT EXISTS \"uuid-ossp\";"

echo "==> Load Automic base SQLs + steps"
PSQL="sudo -u \"${APPUSER}\" psql -X -v ON_ERROR_STOP=1 -d \"${DB}\""

# Base files (safe order)
$PSQL -f "${DBDIR}/check_privileges.sql" || true
$PSQL -f "${DBDIR}/uc_ddl.sql"
$PSQL -f "${DBDIR}/after_uc_ddl.sql"
$PSQL -f "${DBDIR}/create_xevents.sql" || true
$PSQL -f "${DBDIR}/create_fk_for_E.sql" || true
$PSQL -f "${DBDIR}/upd_stat.sql" || true

# Steps
if [[ -d "${DBDIR}/steps" ]]; then
  for f in $(find "${DBDIR}/steps" -maxdepth 1 -type f -name 'step_*.sql' | sort); do
    echo " -> $(basename "$f")"
    $PSQL -f "$f"
  done
fi

# ilmswitch last
if [[ -f "${DBDIR}/ilmswitch.sql" ]]; then
  echo "==> ilmswitch.sql"
  $PSQL -f "${DBDIR}/ilmswitch.sql" || true
fi

echo "==> Done schema load."
"""

VERIFY_SCRIPT = r"""#!/usr/bin/env bash
set -u
LOG="/tmp/aedb_post_bootstrap_check.log"
DB="${DB:-AEDB}"
APPUSER="${APPUSER:-aauser}"
: > "$LOG"

say(){ echo -e "$*" | tee -a "$LOG"; }

say "=== Quick AEDB Verify ==="
sudo -u postgres psql -XAtc "SELECT datname, pg_catalog.pg_get_userbyid(datdba) FROM pg_database WHERE datname='${DB}';" | sed 's/^/DB owner: /' | tee -a "$LOG"
sudo -u postgres psql -XAtd "$DB" -c "SELECT extname, extversion FROM pg_extension ORDER BY 1;" | tee -a "$LOG"

for t in OH AH USR HOST MQSRV MQSRV2; do
  printf "%-6s : " "$t" | tee -a "$LOG"
  sudo -u "${APPUSER}" psql -XAtd "$DB" -c "SELECT COUNT(*) FROM \"$t\";" 2>>"$LOG" | tee -a "$LOG" || echo "N/A" | tee -a "$LOG"
done

echo "--- nspacl(public) ---" | tee -a "$LOG"
sudo -u postgres psql -XAtd "$DB" -c "SELECT nspname, nspowner::regrole AS owner, nspacl FROM pg_namespace WHERE nspname='public';" | tee -a "$LOG"

cat "$LOG"
"""

# ---------- Deploy helpers ----------
def _prefer_latest_base_dir(ssh: SSH, root: str) -> Optional[str]:  # re-define if split across parts
    inner = f"find {shlex.quote(root)} -mindepth 1 -maxdepth 1 -type d -printf '%f\\n' | sort -V"
    rc, out, _ = ssh.sudo("sh -lc " + shlex.quote(inner))
    if rc != 0 or not out.strip():
        return None
    ver = out.strip().splitlines()[-1].strip()
    return posixpath.join(root, ver)

def deploy_and_run_fix_and_load(ssh: SSH, *, db_name: str, app_user: str, app_pass: str, db_pg_root: str) -> None:
    base_dir = _prefer_latest_base_dir(ssh, db_pg_root)
    if not base_dir:
        raise RuntimeError(f"Could not find version dir under {db_pg_root}")
    remote_fix = "/tmp/aedb_fix_and_load.sh"
    ssh.put_text(FIX_AND_LOAD_SCRIPT, remote_fix, mode=0o755)
    log.info("  - running %s ...", remote_fix)
    env = f"DB={shlex.quote(db_name)} APPUSER={shlex.quote(app_user)} APPPASS={shlex.quote(app_pass)} DBDIR={shlex.quote(base_dir)}"
    ssh.sudo_check(f"{env} {remote_fix}")

def deploy_and_run_verify(ssh: SSH, *, db_name: str, app_user: str) -> None:
    remote_verify = "/tmp/aedb_verify_quick.sh"
    ssh.put_text(VERIFY_SCRIPT, remote_verify, mode=0o755)
    log.info("  - running %s ...", remote_verify)
    env = f"DB={shlex.quote(db_name)} APPUSER={shlex.quote(app_user)}"
    out = ssh.sudo_check(f"{env} {remote_verify}")
    for line in out.splitlines()[-30:]:
        log.info("[VERIFY] %s", line)
# ---------- Orchestrator ----------
def run_db_load(
    db_host: str,
    key_path: str,
    db_name: str,
    db_user: str,
    db_password: str,  # kept for future JDBC/remote psql
    remote_zip: str,
    ssh_user: str = "ec2-user",
    remote_install_root: str = "/opt/automic/install",
    remote_utils: str = "/opt/automic/utils",
    app_user: str = "aauser",
    app_pass: str = "Automic123",
    with_tablespaces: bool = False,
    ts_data_name: str = "ae_data",
    ts_index_name: str = "ae_index",
    ts_data_path: str = "/pgdata/ts/AE_DATA",
    ts_index_path: str = "/pgdata/ts/AE_INDEX",
) -> None:
    log.info("== Automic AEDB DB Load ==")

    ssh_cfg = SSHConfig(host=db_host, user=ssh_user, key_path=key_path)
    with SSH(ssh_cfg) as ssh:
        # 1) Ensure PG is up
        unit = detect_pg_service(ssh)
        ensure_pg_running(ssh, unit)

        # 2) Ensure AEDB exists
        ensure_db_exists(ssh, db_name, db_user)

        # 3) Unzip media and locate db/postgresql
        db_pg_root = ensure_utils_and_unzip(ssh, remote_utils, remote_zip, remote_install_root)

        # 3.5) Optional: ensure tablespaces and set defaults
        if with_tablespaces:
            ensure_tablespaces(
                ssh,
                dbname=db_name,
                app_user=app_user,
                data_ts_name=ts_data_name,
                index_ts_name=ts_index_name,
                data_path=ts_data_path,
                index_path=ts_index_path,
            )

        # 4) Upload & run on-box bash loader (roles/privs/exts + base SQL + steps + ilmswitch)
        deploy_and_run_fix_and_load(ssh, db_name=db_name, app_user=app_user, app_pass=app_pass, db_pg_root=db_pg_root)

        # 5) Quick verify + log tail
        deploy_and_run_verify(ssh, db_name=db_name, app_user=app_user)

    log.info("[DB LOAD] Done.")

# ---------- CLI entry ----------
def main(argv: Optional[List[str]] = None) -> int:
    args = parse_args(argv)
    setup_logging(args.verbosity)
    try:
        run_db_load(
            db_host=args.db_host,
            key_path=args.key_path,
            db_name=args.db_name,
            db_user=args.db_user,
            db_password=args.db_password,
            remote_zip=args.remote_zip,
            ssh_user=args.ssh_user,
            remote_install_root=args.remote_install_root,
            remote_utils=args.remote_utils,
            app_user=getattr(args, "app_user", "aauser"),
            app_pass=getattr(args, "app_pass", "Automic123"),
            with_tablespaces=getattr(args, "with_tablespaces", False),
            ts_data_name=getattr(args, "ts_data_name", "ae_data"),
            ts_index_name=getattr(args, "ts_index_name", "ae_index"),
            ts_data_path=getattr(args, "ts_data_path", "/pgdata/ts/AE_DATA"),
            ts_index_path=getattr(args, "ts_index_path", "/pgdata/ts/AE_INDEX"),
        )
        return 0
    except Exception as e:
        log.error("Upload or AEDB load failed: %s", e)
        return 2

if __name__ == "__main__":
    raise SystemExit(main())
