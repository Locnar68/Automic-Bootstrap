from __future__ import annotations

import argparse
import logging
import posixpath
from shlex import quote as shlex_quote
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Optional, Tuple

import paramiko

log = logging.getLogger(__name__)


def setup_logging(verbosity: int = 1) -> None:
    level = logging.INFO if verbosity <= 1 else logging.DEBUG
    fmt = "%(asctime)s [%(levelname)s] %(message)s"
    datefmt = "%H:%M:%S"
    logging.basicConfig(level=level, format=fmt, datefmt=datefmt)


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Automic AEDB load helper (PostgreSQL)")

    # SSH / Host
    p.add_argument("--db-host", required=True, help="DB server IP/DNS")
    p.add_argument("--ssh-user", default="ec2-user", help="SSH username (default: ec2-user)")
    p.add_argument("--key-path", required=True, help="Path to PEM key")

    # DB
    p.add_argument("--db-name", default="AEDB", help="Database name (default: AEDB)")
    p.add_argument("--db-user", default="postgres", help="DB superuser on the box (default: postgres)")
    p.add_argument("--db-password", required=True, help="DB superuser password (retained for future use)")

    # App role (Automic DB owner)
    p.add_argument("--app-user", default="aauser", help="Automic DB role to own AEDB (default: aauser)")
    p.add_argument("--app-pass", default="Automic123", help="Password for --app-user (default: Automic123)")

    # Media locations
    p.add_argument("--remote-zip", required=True, help="Path to Automic media archive (.zip/.tar.gz) on remote host")
    p.add_argument("--remote-install-root", default="/opt/automic/install", help="Install root")
    p.add_argument("--remote-utils", default="/opt/automic/utils", help="Utils dir")

    # Tablespaces (filesystem prep; DB objects are created by the loader script)
    p.add_argument("--with-tablespaces", action="store_true", help="Create TS dirs and DB tablespaces")
    p.add_argument("--ts-data-name", default="ae_data")
    p.add_argument("--ts-index-name", default="ae_index")
    p.add_argument("--ts-data-path", default="/pgdata/ts/AE_DATA")
    p.add_argument("--ts-index-path", default="/pgdata/ts/AE_INDEX")

    p.add_argument("--verbosity", "-v", action="count", default=1, help="Increase log verbosity (-vv for debug)")
    return p.parse_args(argv or sys.argv[1:])
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
        wrapped = f"sudo bash -lc {shlex_quote(cmd)}"
        return self.run(wrapped, timeout=timeout)

    def sudo_check(self, cmd: str, timeout: int = 300) -> str:
        rc, out, err = self.sudo(cmd, timeout=timeout)
        if rc != 0:
            raise RuntimeError(
                f"Remote command failed (rc={rc}): {cmd}\nSTDOUT:\n{out}\nSTDERR:\n{err}"
            )
        return out

    def put(self, local_path: str, remote_path: str) -> None:
        sftp = self.client.open_sftp()
        try:
            sftp.put(local_path, remote_path)
        finally:
            sftp.close()

    def put_text(self, content: str, remote_path: str, mode: int = 0o755) -> None:
        sftp = self.client.open_sftp()
        try:
            with sftp.file(remote_path, "w") as f:
                f.write(content)
            sftp.chmod(remote_path, mode)
        finally:
            sftp.close()
def detect_pg_service(ssh: SSH) -> str:
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
    rc, out, _ = ssh.sudo(r"ss -ltnp | grep -E '(:|\.)5432\b' || true")
    if out.strip():
        return True
    rc, out, _ = ssh.sudo(r"netstat -ltnp 2>/dev/null | grep -E '(:|\.)5432\b' || true")
    return bool(out.strip())


def ensure_pg_running(ssh: SSH, unit: str) -> None:
    log.info("[DB LOAD] Ensure PostgreSQL running...")
    if _port_5432_listening(ssh):
        log.info("  - PostgreSQL already listening on 5432")
        ssh.sudo_check("sudo -u postgres psql -XAtc 'SELECT version();'")
        return
    rc, _, _ = ssh.sudo(f"systemctl start {shlex_quote(unit)}")
    if rc == 0:
        ssh.sudo_check("sudo -u postgres psql -XAtc 'SELECT version();'")
        return
    log.warning("  - start failed; applying small self-heal and retrying")
    ssh.sudo("mkdir -p /run/postgresql && chown postgres:postgres /run/postgresql && chmod 775 /run/postgresql")
    ssh.sudo("rm -f /run/postgresql/.s.PGSQL.5432.lock || true")
    ssh.sudo("systemctl daemon-reload || true")
    ssh.sudo_check(f"systemctl enable --now {shlex_quote(unit)}")
    ssh.sudo_check("sudo -u postgres psql -XAtc 'SELECT version();'")
    log.info("  - PostgreSQL is up.")


def ensure_db_exists(ssh: SSH, dbname: str, dbuser: str = "postgres") -> None:
    log.info("[DB LOAD] Ensure DB %s...", dbname)
    out = ssh.sudo_check(
        f"sudo -u {shlex_quote(dbuser)} psql -XAtc \"SELECT 1 FROM pg_database WHERE datname='{dbname}';\""
    )
    if not out.strip():
        ssh.sudo_check(f"sudo -u {shlex_quote(dbuser)} createdb {shlex_quote(dbname)}")
def _ensure_tool(ssh: SSH, bin_name: str, install_cmd: str) -> None:
    rc, _, _ = ssh.sudo(f"command -v {shlex_quote(bin_name)} >/dev/null 2>&1")
    if rc != 0:
        ssh.sudo_check(install_cmd)


def ensure_utils_and_unzip(ssh: SSH, remote_utils: str, remote_archive: str, install_root: str) -> str:
    """
    Ensure utils dir exists, unpack Automic media into install_root if needed, and
    return the path to the <...>/Automation.Platform/db/postgresql directory.
    Works whether the archive adds a top-level versioned folder or not.
    """
    log.info("[DB LOAD] Prepare utils dir and locate/unpack media...")
    ssh.sudo_check(f"mkdir -p {shlex_quote(remote_utils)} {shlex_quote(install_root)}")
    ssh.sudo_check(f"chmod 755 {shlex_quote(remote_utils)}")

    # Amazon Linux 2/2023 friendly
    _ensure_tool(ssh, "unzip", "dnf -y install unzip || yum -y install unzip || true")
    _ensure_tool(ssh, "tar", "true")  # always present

    # Already extracted?
    find_pg = f"find {shlex_quote(install_root)} -type d -path '*/Automation.Platform/db/postgresql' -print -quit"
    existing = ssh.sudo_check(f"{find_pg} || true").strip()

    if not existing:
        # Clean previous Automic dirs to avoid stale/partial trees
        ssh.sudo_check(
            f"find {shlex_quote(install_root)} -maxdepth 1 -type d -name 'Automic.Automation_*' -exec rm -rf {{}} + || true"
        )

        # Extract directly into install_root
        low = remote_archive.lower()
        if low.endswith(".zip"):
            ssh.sudo_check(f"unzip -o {shlex_quote(remote_archive)} -d {shlex_quote(install_root)}")
        elif low.endswith(".tar.gz") or low.endswith(".tgz"):
            ssh.sudo_check(f"tar -xzf {shlex_quote(remote_archive)} -C {shlex_quote(install_root)}")
        else:
            raise RuntimeError(f"Unsupported archive type: {remote_archive}")

        # Re-check
        existing = ssh.sudo_check(f"{find_pg} || true").strip()

    if not existing:
        # Deeper search for unusual nesting
        existing = ssh.sudo_check(
            f"find {shlex_quote(install_root)} -maxdepth 7 -type d -path '*/Automation.Platform/db/postgresql' -print -quit || true"
        ).strip()

    if not existing:
        raise RuntimeError(f"Could not locate Automation.Platform/db/postgresql under {install_root}")

    log.info("  - db dir: %s", existing)
    return existing


def _prefer_latest_base_dir(ssh: SSH, root: str) -> Optional[str]:
    """
    Given .../Automation.Platform/db/postgresql, choose latest version subdir (e.g., 24.4).
    """
    inner = f"find {shlex_quote(root)} -mindepth 1 -maxdepth 1 -type d -printf '%f\\n' | sort -V"
    rc, out, _ = ssh.sudo("bash -lc " + shlex_quote(inner))
    if rc != 0 or not out.strip():
        return None
    ver = out.strip().splitlines()[-1].strip()
    return posixpath.join(root, ver)
def ensure_tablespaces_dirs(
    ssh: SSH,
    *,
    data_ts_name: str = "ae_data",
    index_ts_name: str = "ae_index",
    data_path: str = "/pgdata/ts/AE_DATA",
    index_path: str = "/pgdata/ts/AE_INDEX",
) -> None:
    """
    Prepare filesystem directories for tablespaces. We do NOT GRANT here (those are DB-level),
    and we do NOT set DB/ROLE defaults here. The SQL wiring happens inside FIX_AND_LOAD_SCRIPT.
    """
    log.info("[DB LOAD] Ensuring tablespace directories exist: %s (%s), %s (%s)",
             data_ts_name, data_path, index_ts_name, index_path)
    ssh.sudo_check(f"mkdir -p {shlex_quote(data_path)} {shlex_quote(index_path)}")
    parent = posixpath.dirname(data_path.rstrip("/"))
    ssh.sudo_check(f"chown -R postgres:postgres {shlex_quote(parent)}")
    ssh.sudo_check(f"chmod 700 {shlex_quote(data_path)} {shlex_quote(index_path)}")


FIX_AND_LOAD_SCRIPT = r"""#!/usr/bin/env bash
set -euo pipefail

# Expected env vars:
#   DB, APPUSER, APPPASS, DBDIR   (e.g., .../Automation.Platform/db/postgresql/24.4)
# Optional:
#   TS_DATA, TS_INDEX              (tablespace names; default ae_data/ae_index)
#   TS_DATA_LOC, TS_INDEX_LOC      (filesystem paths for CREATE TABLESPACE)

: "${DB:?DB not set}"
: "${APPUSER:?APPUSER not set}"
: "${APPPASS:?APPPASS not set}"
: "${DBDIR:?DBDIR not set}"

TS_DATA="${TS_DATA:-ae_data}"
TS_INDEX="${TS_INDEX:-ae_index}"
TS_DATA_LOC="${TS_DATA_LOC:-}"
TS_INDEX_LOC="${TS_INDEX_LOC:-}"

# Locate psql reliably
PSQL_BIN="$(command -v psql || true)"
if [[ -z "${PSQL_BIN}" && -x "/usr/bin/psql" ]]; then
  PSQL_BIN="/usr/bin/psql"
fi
if [[ -z "${PSQL_BIN}" ]]; then
  echo "ERROR: psql not found." >&2
  exit 3
fi

echo "==> Prechecks"
"${PSQL_BIN}" -V || true
"${PSQL_BIN}" -h localhost -U postgres -Atc "select version();" || true

PSQL="${PSQL_BIN} -v ON_ERROR_STOP=1 -h localhost -U postgres \
  -v db=${DB} -v appuser=${APPUSER} -v apppass=${APPPASS} \
  -v ts_data=${TS_DATA} -v ts_index=${TS_INDEX} \
  -v TS_DATA_LOC=${TS_DATA_LOC} -v TS_INDEX_LOC=${TS_INDEX_LOC}"

echo "==> Ensure contrib extensions (if needed)"
if ! ls /usr/share/pgsql/extension/pgcrypto.control /usr/pgsql-16/share/extension/pgcrypto.control >/dev/null 2>&1; then
  if command -v dnf >/dev/null 2>&1; then
    dnf -y install postgresql16-contrib || dnf -y install postgresql-contrib || true
  elif command -v yum >/dev/null 2>&1; then
    yum -y install postgresql16-contrib || yum -y install postgresql-contrib || true
  elif command -v apt-get >/dev/null 2>&1; then
    apt-get update -y && apt-get install -y postgresql-contrib || true
  fi
fi

echo "==> Ensure app role + DB (idempotent)"
${PSQL} <<'SQL'
\set ON_ERROR_STOP on
SELECT format('CREATE ROLE %I LOGIN PASSWORD %L', :'appuser', :'apppass')
WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = :'appuser') \gexec
SELECT format('CREATE DATABASE %I OWNER %I', :'db', :'appuser')
WHERE NOT EXISTS (SELECT 1 FROM pg_database WHERE datname = :'db') \gexec
SELECT format('ALTER DATABASE %I OWNER TO %I', :'db', :'appuser') \gexec
SQL

echo "==> Ensure required extensions"
${PSQL} -d "${DB}" -c 'CREATE EXTENSION IF NOT EXISTS pgcrypto;'
${PSQL} -d "${DB}" -c 'CREATE EXTENSION IF NOT EXISTS "uuid-ossp";'

echo "==> Ensure tablespaces exist (if requested)"
${PSQL} <<'SQL'
\set ON_ERROR_STOP on
SELECT format('CREATE TABLESPACE %I OWNER %I LOCATION %L', :'ts_data',  :'appuser', :'TS_DATA_LOC')
WHERE :'ts_data' <> 'pg_default' AND coalesce(:'TS_DATA_LOC','') <> ''
  AND NOT EXISTS (SELECT 1 FROM pg_tablespace WHERE spcname = :'ts_data') \gexec
SELECT format('CREATE TABLESPACE %I OWNER %I LOCATION %L', :'ts_index', :'appuser', :'TS_INDEX_LOC')
WHERE :'ts_index' <> 'pg_default' AND coalesce(:'TS_INDEX_LOC','') <> ''
  AND NOT EXISTS (SELECT 1 FROM pg_tablespace WHERE spcname = :'ts_index') \gexec
SQL

echo "==> Tablespace privilege & defaults (best effort)"
${PSQL} <<'SQL'
\set ON_ERROR_STOP on
SELECT format('GRANT CREATE ON TABLESPACE %I TO %I', :'ts_data',  :'appuser')
FROM   pg_tablespace WHERE spcname = :'ts_data'  AND :'ts_data'  <> 'pg_default' \gexec
SELECT format('GRANT CREATE ON TABLESPACE %I TO %I', :'ts_index', :'appuser')
FROM   pg_tablespace WHERE spcname = :'ts_index' AND :'ts_index' <> 'pg_default' \gexec
SELECT format('ALTER DATABASE %I SET default_tablespace = %L', :'db', :'ts_data')
FROM   pg_tablespace WHERE spcname = :'ts_data'  AND :'ts_data'  <> 'pg_default' \gexec
SELECT format('ALTER ROLE %I IN DATABASE %I SET default_tablespace = %L', :'appuser', :'db', :'ts_data')
FROM   pg_tablespace WHERE spcname = :'ts_data'  AND :'ts_data'  <> 'pg_default' \gexec
SQL
echo "==> Detect BASE/STEPS"
if [[ ! -d "${DBDIR}" ]]; then
  echo "ERROR: DBDIR does not exist: ${DBDIR}" >&2
  exit 2
fi

BASE_DIR="${DBDIR}"
if [[ ! -f "${BASE_DIR}/uc_ddl.sql" ]]; then
  if [[ -d "${DBDIR}/base/postgresql" ]]; then
    BASE_DIR="${DBDIR}/base/postgresql"
  elif [[ -d "${DBDIR}/base" ]]; then
    BASE_DIR="${DBDIR}/base"
  fi
fi

if [[ -d "${DBDIR}/steps/postgresql" ]]; then
  STEPS_DIR="${DBDIR}/steps/postgresql"
elif [[ -d "${DBDIR}/steps" ]]; then
  STEPS_DIR="${DBDIR}/steps"
else
  echo "ERROR: Could not find STEPS under ${DBDIR}" >&2
  (command -v tree >/dev/null && tree -L 3 "${DBDIR}" || find "${DBDIR}" -maxdepth 3 -type d | sed -n '1,80p') >&2
  exit 2
fi

echo "  - BASE_DIR detected : ${BASE_DIR}"
echo "  - STEPS_DIR detected: ${STEPS_DIR}"

echo "==> Prepare working copies + normalize"
WORK_BASE="/tmp/aedb_base_work"
WORK_STEPS="/tmp/aedb_steps_work"
rm -rf "${WORK_BASE}" "${WORK_STEPS}"
mkdir -p "${WORK_BASE}" "${WORK_STEPS}"

find "${BASE_DIR}"  -maxdepth 1 -type f -name '*.sql' -print0 | sort -z | xargs -0 -I{} cp -a "{}" "${WORK_BASE}/"
find "${STEPS_DIR}" -maxdepth 1 -type f -name '*.sql' -print0 | sort -z | xargs -0 -I{} cp -a "{}" "${WORK_STEPS}/"

normalize_one() {
  local file="$1"
  sed -i 's/\r$//' "$file"

  # Legacy AE placeholders
  if grep -q '<AE_DB_USER>' "$file"; then
    sed -i "s/<AE_DB_USER>/${APPUSER//\//\\/}/g" "$file"
  fi
  if grep -q '<AE_DB_NAME>' "$file"; then
    sed -i "s/<AE_DB_NAME>/${DB//\//\\/}/g" "$file"
  fi

  # Replace TS markers and fix spacing
  sed -i -E "s/&TS_DATA#?/${TS_DATA//\//\\/}/g"   "$file"
  sed -i -E "s/&TS_INDEX#?/${TS_INDEX//\//\\/}/g" "$file"
  sed -i -E 's/\)TABLESPACE/) TABLESPACE/g' "$file"
  sed -i -E 's/INDEXTABLESPACE/INDEX TABLESPACE/g' "$file"

  # Fill missing tablespace names
  sed -i -E "s/\)[[:space:]]*TABLESPACE[[:space:]]*;[[:space:]]*$/) TABLESPACE ${TS_DATA//\//\\/} ;/g" "$file"
  sed -i -E "s/\)[[:space:]]*TABLESPACE[[:space:]]*$/) TABLESPACE ${TS_DATA//\//\\/} ;/g" "$file"
  sed -i -E "s/USING[[:space:]]+INDEX[[:space:]]+TABLESPACE[[:space:]]*;[[:space:]]*$/USING INDEX TABLESPACE ${TS_INDEX//\//\\/} ;/g" "$file"
  sed -i -E "s/USING[[:space:]]+INDEX[[:space:]]+TABLESPACE[[:space:]]*$/USING INDEX TABLESPACE ${TS_INDEX//\//\\/}/g" "$file"

  # Safety: drop any naked TABLESPACE tokens at statement end
  sed -i -E 's/[[:space:]]+TABLESPACE[[:space:]]*;[[:space:]]*$/;/' "$file"
  sed -i -E 's/USING[[:space:]]+INDEX[[:space:]]+TABLESPACE[[:space:]]*;[[:space:]]*$/;/' "$file"

  # --- NEW: ensure a semicolon before any CREATE INDEX that starts a new statement ---
  # (a) if a closing ')' is directly followed by CREATE INDEX on next line, inject ';'
  sed -i -E ':a;N;$!ba;s/\)([[:space:]]*\n[[:space:]]*CREATE[[:space:]]+INDEX)/); \1/Ig' "$file"

  # (b) if previous non-empty line lacks trailing ';', insert one before a CREATE INDEX (safety net)
  awk '
    function rtrim(s){ sub(/[[:space:]]+$/, "", s); return s }
    {
      line=$0
      trimmed=rtrim(line)
      if (match(trimmed, /^[[:space:]]*CREATE[[:space:]]+INDEX/i)) {
        if (prev_ne != "" && prev_ne !~ /;[[:space:]]*$/) { print ";" }
      }
      print line
      if (trimmed != "" && trimmed !~ /^--/) prev_ne=trimmed
    }' "$file" > "$file.awkfix" && mv "$file.awkfix" "$file"

  # Remove lines that are just semicolons
  sed -i -E '/^[[:space:]]*;[[:space:]]*$/d' "$file"
}
export -f normalize_one

find "${WORK_BASE}"  -type f -name '*.sql' -print0 | xargs -0 -n1 bash -c 'normalize_one "$0"'
find "${WORK_STEPS}" -type f -name '*.sql' -print0 | xargs -0 -n1 bash -c 'normalize_one "$0"'

# One-off fix: stray '!' lines in create_xevents.sql
if [[ -f "${WORK_BASE}/create_xevents.sql" ]] || [[ -f "${WORK_STEPS}/create_xevents.sql" ]]; then
  sed -i -E "s/^![[:space:]]*$/-- removed stray bang/" "${WORK_BASE}/create_xevents.sql" 2>/dev/null || true
  sed -i -E "s/^![[:space:]]*$/-- removed stray bang/" "${WORK_STEPS}/create_xevents.sql" 2>/dev/null || true
fi

if [[ -f "${WORK_BASE}/uc_ddl.sql" ]]; then
  echo "==> Preview uc_ddl.sql (first 40 lines after normalization)"
  nl -ba "${WORK_BASE}/uc_ddl.sql" | sed -n '1,40p' || true
fi
echo "==> Run BASE schema (ordered)"
ORDERED_BASE_FILES=()
[[ -f "${WORK_BASE}/uc_ddl.sql" ]] && ORDERED_BASE_FILES+=("${WORK_BASE}/uc_ddl.sql")
[[ -f "${WORK_BASE}/after_uc_ddl.sql" ]] && ORDERED_BASE_FILES+=("${WORK_BASE}/after_uc_ddl.sql")
while IFS= read -r -d '' f; do
  bn="$(basename "$f")"
  case "$bn" in uc_ddl.sql|after_uc_ddl.sql|drop_all.sql) ;; * ) ORDERED_BASE_FILES+=("$f");; esac
done < <(find "${WORK_BASE}" -maxdepth 1 -type f -name '*.sql' -print0 | sort -z)

for f in "${ORDERED_BASE_FILES[@]}"; do
  echo ">>> BASE RUN: ${f}"
  ${PSQL} -d "${DB}" -f "${f}"
done

echo "==> Run STEPS (ordered; permissive subset allowed to continue)"
PERMISSIVE=("chngilm.sql" "create_xevents.sql" "ilmswitch.sql" "upd_stat.sql")
for f in $(ls -1 "${WORK_STEPS}"/*.sql 2>/dev/null | sort); do
  bn="$(basename "$f")"
  echo ">>> STEP: ${f}"
  if printf '%s\0' "${PERMISSIVE[@]}" | grep -zqx -- "$bn"; then
    ${PSQL_BIN} -h localhost -U postgres -v ON_ERROR_STOP=0 -d "${DB}" -f "${f}" || true
  else
    ${PSQL} -d "${DB}" -f "${f}"
  fi
done
echo "==> Grant default privileges to app role (future objects)"
${PSQL} <<'SQL'
DO $$
DECLARE rname text := :'appuser';
BEGIN
  EXECUTE format('ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON TABLES TO %I', rname);
  EXECUTE format('ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON SEQUENCES TO %I', rname);
END $$ LANGUAGE plpgsql;
SQL

echo "==> Done"
"""

def deploy_and_run_fix_and_load(
    ssh: SSH, *,
    db_name: str, app_user: str, app_pass: str, db_pg_root: str,
    ts_data: str = "ae_data", ts_index: str = "ae_index",
    ts_data_loc: str = "/pgdata/ts/AE_DATA", ts_index_loc: str = "/pgdata/ts/AE_INDEX",
) -> None:
    """
    Uploads a fix+load shell script and executes it with the correct environment.
    """
    base_dir = _prefer_latest_base_dir(ssh, db_pg_root)
    if not base_dir:
        raise RuntimeError(f"Could not find version dir under {db_pg_root}")

    remote_fix = "/tmp/aedb_fix_and_load.sh"
    ssh.put_text(FIX_AND_LOAD_SCRIPT, remote_fix, mode=0o755)
    log.info("  - running %s ...", remote_fix)

    env = (
        f"DB={shlex_quote(db_name)} "
        f"APPUSER={shlex_quote(app_user)} "
        f"APPPASS={shlex_quote(app_pass)} "
        f"DBDIR={shlex_quote(base_dir)} "
        f"TS_DATA={shlex_quote(ts_data)} "
        f"TS_INDEX={shlex_quote(ts_index)} "
        f"TS_DATA_LOC={shlex_quote(ts_data_loc)} "
        f"TS_INDEX_LOC={shlex_quote(ts_index_loc)}"
    )

    ssh.sudo_check(f"/usr/bin/env {env} bash {remote_fix}")


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
        unit = detect_pg_service(ssh)
        ensure_pg_running(ssh, unit)
        ensure_db_exists(ssh, db_name, db_user)

        db_pg_root = ensure_utils_and_unzip(ssh, remote_utils, remote_zip, remote_install_root)

        if with_tablespaces:
            ensure_tablespaces_dirs(
                ssh,
                data_ts_name=ts_data_name,
                index_ts_name=ts_index_name,
                data_path=ts_data_path,
                index_path=ts_index_path,
            )

        deploy_and_run_fix_and_load(
            ssh,
            db_name=db_name,
            app_user=app_user,
            app_pass=app_pass,
            db_pg_root=db_pg_root,
            ts_data=ts_data_name,
            ts_index=ts_index_name,
            ts_data_loc=ts_data_path,
            ts_index_loc=ts_index_path,
        )

    log.info("[DB LOAD] Done.")


def main(argv: list[str] | None = None) -> int:
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
            app_user=args.app_user,
            app_pass=args.app_pass,
            with_tablespaces=args.with_tablespaces,
            ts_data_name=args.ts_data_name,
            ts_index_name=args.ts_index_name,
            ts_data_path=args.ts_data_path,
            ts_index_path=args.ts_index_path,
        )
        return 0
    except Exception as e:
        log.error("Upload or AEDB load failed: %s", e)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
