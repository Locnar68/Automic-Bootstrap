from __future__ import annotations

import argparse
import logging
import socket
import time
import sys
import shlex
import posixpath
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Optional, Tuple
from shlex import quote as shlex_quote

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
    p.add_argument(
        "--db-user", default="postgres", help="DB superuser on the box (default: postgres)"
    )
    p.add_argument(
        "--db-password", required=True, help="DB superuser password (retained for future use)"
    )

    # App role (Automic DB owner)
    p.add_argument(
        "--app-user", default="aauser", help="Automic DB role to own AEDB (default: aauser)"
    )
    p.add_argument(
        "--app-pass", default="Automic123", help="Password for --app-user (default: Automic123)"
    )

    # Media locations
    p.add_argument("--remote-zip", required=True, help="Path to Automic media ZIP on remote host")
    p.add_argument("--remote-install-root", default="/opt/automic/install", help="Install root")
    p.add_argument("--remote-utils", default="/opt/automic/utils", help="Utils dir")

    # Tablespaces
    p.add_argument(
        "--with-tablespaces",
        action="store_true",
        help="Create & wire tablespaces before schema load",
    )
    p.add_argument("--ts-data-name", default="ae_data")
    p.add_argument("--ts-index-name", default="ae_index")
    p.add_argument("--ts-data-path", default="/pgdata/ts/AE_DATA")
    p.add_argument("--ts-index-path", default="/pgdata/ts/AE_INDEX")

    p.add_argument(
        "--verbosity",
        "-v",
        action="count",
        default=1,
        help="Increase log verbosity (-vv for debug)",
    )
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

    def __enter__(self) -> SSH:
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

    def run(self, cmd: str, timeout: int = 300) -> tuple[int, str, str]:
        log.debug("RUN: %s", cmd)
        stdin, stdout, stderr = self.client.exec_command(cmd, timeout=timeout)
        out = stdout.read().decode("utf-8", "ignore")
        err = stderr.read().decode("utf-8", "ignore")
        rc = stdout.channel.recv_exit_status()
        log.debug("RC=%s\nSTDOUT:\n%s\nSTDERR:\n%s", rc, out, err)
        return rc, out, err

    def sudo(self, cmd: str, timeout: int = 300) -> tuple[int, str, str]:
        wrapped = f"sudo bash -lc {shlex.quote(cmd)}"
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
    rc, out, _ = ssh.sudo("ss -ltnp | grep -E '(:|\\.)5432\\b' || true")
    if out.strip():
        return True
    rc, out, _ = ssh.sudo("netstat -ltnp 2>/dev/null | grep -E '(:|\\.)5432\\b' || true")
    return bool(out.strip())


def ensure_pg_running(ssh: SSH, unit: str) -> None:
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
    ssh.sudo(
        "mkdir -p /run/postgresql && chown postgres:postgres /run/postgresql && chmod 775 /run/postgresql"
    )
    ssh.sudo("rm -f /run/postgresql/.s.PGSQL.5432.lock || true")
    ssh.sudo("systemctl daemon-reload || true")
    ssh.sudo_check(f"systemctl enable --now {shlex.quote(unit)}")
    ssh.sudo_check("sudo -u postgres psql -XAtc 'SELECT version();'")
    log.info("  - PostgreSQL is up.")


def ensure_db_exists(ssh: SSH, dbname: str, dbuser: str = "postgres") -> None:
    log.info("[DB LOAD] Ensure DB %s...", dbname)
    out = ssh.sudo_check(
        f"sudo -u {shlex.quote(dbuser)} psql -XAtc \"SELECT 1 FROM pg_database WHERE datname='{dbname}';\""
    )
    if not out.strip():
        ssh.sudo_check(f"sudo -u {shlex.quote(dbuser)} createdb {shlex.quote(dbname)}")


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

    rc, _, _ = ssh.sudo(f"test -d {shlex.quote(extract_dir)}")
    if rc != 0:
        ssh.sudo_check(f"unzip -q -o {shlex.quote(remote_zip)} -d {shlex.quote(extract_dir)}")
        ssh.sudo_check(
            f"find {shlex.quote(extract_dir)} -type f -name '*.sh' -exec chmod +x {{}} +;"
        )
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
        raise RuntimeError(
            f"Could not locate Automation.Platform/db/postgresql under {extract_dir}"
        )
    log.info("  - db dir: %s", db_pg_root)
    return db_pg_root


def _prefer_latest_base_dir(ssh: SSH, root: str) -> str | None:
    inner = f"find {shlex.quote(root)} -mindepth 1 -maxdepth 1 -type d -printf '%f\\n' | sort -V"
    rc, out, _ = ssh.sudo("sh -lc " + shlex.quote(inner))
    if rc != 0 or not out.strip():
        return None
    ver = out.strip().splitlines()[-1].strip()
    return posixpath.join(root, ver)


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
    log.info(
        "[DB LOAD] Ensuring tablespaces: %s (%s), %s (%s)",
        data_ts_name,
        data_path,
        index_ts_name,
        index_path,
    )
    ssh.sudo_check(f"mkdir -p {shlex.quote(data_path)} {shlex.quote(index_path)}")
    parent = posixpath.dirname(data_path.rstrip("/"))
    ssh.sudo_check(f"chown -R postgres:postgres {shlex.quote(parent)}")
    ssh.sudo_check(f"chmod 700 {shlex.quote(data_path)} {shlex.quote(index_path)}")

    def ts_exists(name: str) -> bool:
        rc, out, _ = ssh.sudo(
            f"sudo -u postgres psql -XAtc \"SELECT 1 FROM pg_tablespace WHERE spcname='{name}';\""
        )
        return rc == 0 and out.strip() == "1"

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

    ssh.sudo_check(
        f"sudo -u postgres psql -v ON_ERROR_STOP=1 -Xc "
        f'"GRANT CREATE, USAGE ON TABLESPACE {data_ts_name} TO \\"{app_user}\\";"'
    )
    ssh.sudo_check(
        f"sudo -u postgres psql -v ON_ERROR_STOP=1 -Xc "
        f'"GRANT CREATE, USAGE ON TABLESPACE {index_ts_name} TO \\"{app_user}\\";"'
    )
    ssh.sudo_check(
        f"sudo -u postgres psql -v ON_ERROR_STOP=1 -Xc "
        f'"ALTER DATABASE \\"{dbname}\\" SET default_tablespace = \'{data_ts_name}\';"'
    )
    ssh.sudo_check(
        f"sudo -u postgres psql -v ON_ERROR_STOP=1 -Xc "
        f'"ALTER ROLE \\"{app_user}\\" IN DATABASE \\"{dbname}\\" SET default_tablespace = \'{data_ts_name}\';"'
    )
    log.info("  - tablespaces ready; defaults set to %s", data_ts_name)


FIX_AND_LOAD_SCRIPT = r"""#!/usr/bin/env bash
set -euo pipefail

# Expected env vars:
#   DB, APPUSER, APPPASS, DBDIR (e.g., .../Automation.Platform/db/postgresql/24.4)
# Optional:
#   TS_DATA, TS_INDEX (defaults below)

: "${DB:?DB not set}"
: "${APPUSER:?APPUSER not set}"
: "${APPPASS:?APPPASS not set}"
: "${DBDIR:?DBDIR not set}"

# === FIX: sensible defaults for AE tablespaces ===
TS_DATA="${TS_DATA:-ae_data}"
TS_INDEX="${TS_INDEX:-ae_index}"
TS_DATA_ESC="${TS_DATA//\//\\/}"
TS_INDEX_ESC="${TS_INDEX//\//\\/}"

echo "==> Prechecks"
/usr/bin/psql -V || true
/usr/bin/psql -h localhost -U postgres -Atc "select version();" || true

# psql wrapper (keep -v vars for consistency; DO blocks inject literals)
PSQL="/usr/bin/psql -v ON_ERROR_STOP=1 -h localhost -U postgres -v db=${DB} -v appuser=${APPUSER} -v apppass=${APPPASS}"

echo "==> Ensure contrib extensions are installed (pgcrypto/uuid-ossp)"
if ! ls /usr/share/pgsql/extension/pgcrypto.control /usr/pgsql-16/share/extension/pgcrypto.control >/dev/null 2>&1; then
  if command -v dnf >/dev/null 2>&1; then
    sudo dnf -y install postgresql16-contrib || sudo dnf -y install postgresql-contrib
  elif command -v yum >/dev/null 2>&1; then
    sudo yum -y install postgresql16-contrib || sudo yum -y install postgresql-contrib
  elif command -v apt-get >/dev/null 2>&1; then
    sudo apt-get update -y && sudo apt-get install -y postgresql-contrib
  else
    echo "ERROR: No supported package manager to install contrib." >&2
    exit 3
  fi
fi

echo "==> Ensure app role + DB ownership (literal injection; no psql vars in DO)"
sql_quote() { printf "%s" "$1" | sed "s/'/''/g"; }
APPUSER_LIT="$(sql_quote "$APPUSER")"
APPPASS_LIT="$(sql_quote "$APPPASS")"
DB_LIT="$(sql_quote "$DB")"

${PSQL} <<SQL
DO \$\$
DECLARE
  rname  text := '${APPUSER_LIT}';
  rpass  text := '${APPPASS_LIT}';
  dbname text := '${DB_LIT}';
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = rname) THEN
    EXECUTE format('CREATE ROLE %I LOGIN PASSWORD %L', rname, rpass);
  END IF;

  IF NOT EXISTS (SELECT 1 FROM pg_database WHERE datname = dbname) THEN
    EXECUTE format('CREATE DATABASE %I OWNER %I', dbname, rname);
  END IF;

  EXECUTE format('ALTER DATABASE %I OWNER TO %I', dbname, rname);
END \$\$ LANGUAGE plpgsql;
SQL

echo "==> Ensure required extensions"
${PSQL} -d "${DB}" -c 'CREATE EXTENSION IF NOT EXISTS pgcrypto;'
${PSQL} -d "${DB}" -c 'CREATE EXTENSION IF NOT EXISTS "uuid-ossp";'

echo "==> Ensure AE tablespaces exist (ae_data / ae_index) or fall back to pg_default when not permitted"

# Detect a sensible base dir for tablespaces on Amazon Linux/Postgres
detect_ts_base() {
  # Try PG 16 path first, then generic; both fine for user-managed EC2
  if [[ -d /var/lib/pgsql/16 ]]; then
    echo "/var/lib/pgsql/16/tablespaces"
  else
    echo "/var/lib/pgsql/tablespaces"
  fi
}

TS_BASE_DIR="${TS_BASE_DIR:-$(detect_ts_base)}"

# Create a tablespace if requested (not pg_default) and it doesn't exist yet.
ensure_ts() {
  local ts_name="$1"
  local ts_path="$2"

  [[ "${ts_name}" == "pg_default" ]] && return 0

  # Already present?
  if ${PSQL} -d "${DB}" -Atc "SELECT 1 FROM pg_tablespace WHERE spcname='${ts_name}'" | grep -q '^1$'; then
    echo "  - Tablespace ${ts_name} already exists"
    return 0
  fi

  echo "  - Creating tablespace ${ts_name} at ${ts_path}"

  # Prepare directory (OS-level); ignore if already owned/exists
  sudo mkdir -p "${ts_path}"
  sudo chown -R postgres:postgres "${ts_path}" || true

  # Try to create; if it fails (e.g., RDS/managed PG), we will fall back.
  if ! sudo -u postgres psql -v ON_ERROR_STOP=1 -c \
      "CREATE TABLESPACE ${ts_name} OWNER postgres LOCATION '${ts_path}';"; then
    echo "  ! Could not create tablespace ${ts_name}. Likely a managed PG (RDS) or insufficient privileges." >&2
    return 1
  fi
}

# Attempt to ensure both; if either fails, fall back to pg_default for both
FALLBACK_TS=0
ensure_ts "${TS_DATA}"  "${TS_BASE_DIR}/${TS_DATA}"  || FALLBACK_TS=1
ensure_ts "${TS_INDEX}" "${TS_BASE_DIR}/${TS_INDEX}" || FALLBACK_TS=1

if [[ "${FALLBACK_TS}" -eq 1 ]]; then
  echo "==> Falling back: using pg_default for both data and index tablespaces"
  TS_DATA="pg_default"
  TS_INDEX="pg_default"
  TS_DATA_ESC="${TS_DATA//\//\\/}"
  TS_INDEX_ESC="${TS_INDEX//\//\\/}"
fi
echo "==> Locate Automic SQL directories (24.4 layout + fallbacks)"
if [[ ! -d "${DBDIR}" ]]; then
  echo "ERROR: DBDIR does not exist: ${DBDIR}" >&2
  exit 2
fi

# 24.4: base SQLs directly in DBDIR; steps in DBDIR/steps
if ls -1 "${DBDIR}"/*.sql >/dev/null 2>&1; then
  BASE_DIR="${DBDIR}"
else
  if [[ -d "${DBDIR}/base/postgresql" ]]; then
    BASE_DIR="${DBDIR}/base/postgresql"
  elif [[ -d "${DBDIR}/base" ]]; then
    BASE_DIR="${DBDIR}/base"
  else
    echo "ERROR: Could not find BASE SQLs under ${DBDIR}" >&2
    (command -v tree >/dev/null && tree -L 3 "${DBDIR}" || find "${DBDIR}" -maxdepth 3 -type d | sed -n '1,80p') >&2
    exit 2
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

echo "==> Prepare working copies (idempotent substitutions)"
WORK_BASE="/tmp/aedb_base_work"
WORK_STEPS="/tmp/aedb_steps_work"
rm -rf "${WORK_BASE}" "${WORK_STEPS}"
mkdir -p "${WORK_BASE}" "${WORK_STEPS}"

# Copy with stable ordering
find "${BASE_DIR}"  -maxdepth 1 -type f -name '*.sql' -print0 | sort -z | xargs -0 -I{} cp -a "{}" "${WORK_BASE}/"
find "${STEPS_DIR}" -maxdepth 1 -type f -name '*.sql' -print0 | sort -z | xargs -0 -I{} cp -a "{}" "${WORK_STEPS}/"

subst_if_needed() {
  local file="$1"

  # 1) Normalize CRLF -> LF
  sed -i 's/\r$//' "$file"

  # 2) Legacy AE placeholders
  if grep -q '<AE_DB_USER>' "$file"; then
    sed -i "s/<AE_DB_USER>/${APPUSER//\//\\/}/g" "$file"
  fi
  if grep -q '<AE_DB_NAME>' "$file"; then
    sed -i "s/<AE_DB_NAME>/${DB//\//\\/}/g" "$file"
  fi

  # 3) Tablespace marker substitution -> configured defaults
  sed -i -E "s/&TS_DATA#?/${TS_DATA_ESC}/g"   "$file"
  sed -i -E "s/&TS_INDEX#?/${TS_INDEX_ESC}/g" "$file"

  # 4) Strip schema token prefixes like "&TOKEN#".UC_FOO or &TOKEN#.UC_FOO  -> UC_FOO
  sed -i -E 's/[[:space:]]*"&[A-Za-z0-9_]+#"[[:space:]]*\.[[:space:]]*//g' "$file"
  sed -i -E 's/[[:space:]]*&[A-Za-z0-9_]+#[[:space:]]*\.[[:space:]]*//g' "$file"

  # 5) Spacing/typo normalizations around TABLESPACE
  sed -i -E 's/\)TABLESPACE/) TABLESPACE/g'        "$file"
  sed -i -E 's/INDEXTABLESPACE/INDEX TABLESPACE/g' "$file"

  # 6) Ensure TABLESPACE names are present (both same-line and multiline cases)
  #    For table storage:
  sed -i -E "s/\)[[:space:]]*TABLESPACE[[:space:]]*;[[:space:]]*$/) TABLESPACE ${TS_DATA_ESC} ;/g" "$file"
  sed -i -E "s/\)[[:space:]]*TABLESPACE[[:space:]]*$/) TABLESPACE ${TS_DATA_ESC}/g"               "$file"
  #    For PK/idx storage:
  sed -i -E "s/USING[[:space:]]+INDEX[[:space:]]+TABLESPACE[[:space:]]*;[[:space:]]*$/USING INDEX TABLESPACE ${TS_INDEX_ESC} ;/g" "$file"
  sed -i -E "s/USING[[:space:]]+INDEX[[:space:]]+TABLESPACE[[:space:]]*$/USING INDEX TABLESPACE ${TS_INDEX_ESC}/g"                 "$file"

  # 7) Safety nets: if a naked TABLESPACE clause still ends right before ';', drop that clause
  sed -i -E 's/[[:space:]]+TABLESPACE[[:space:]]*;[[:space:]]*$/;/' "$file"
  sed -i -E 's/USING[[:space:]]+INDEX[[:space:]]+TABLESPACE[[:space:]]*;[[:space:]]*$/;/' "$file"

  # 8) Remove dangling commas immediately before ) or ;
  sed -i -E 's/,([[:space:]]*\))/\1/g' "$file"
  sed -i -E 's/,([[:space:]]*;)/\1/g' "$file"

  # 9) Remove lines that are just a semicolon (prevents "syntax error at or near ';'")
  sed -i -E '/^[[:space:]]*;[[:space:]]*$/d' "$file"

  # 10) Optional: squeeze excessive blank lines (cosmetic)
  sed -i -E ':a;N;$!ba;s/\n{3,}/\n\n/g' "$file"
}
export -f subst_if_needed

find "${WORK_BASE}"  -type f -name '*.sql' -print0 | xargs -0 -n1 bash -c 'subst_if_needed "$0"'
find "${WORK_STEPS}" -type f -name '*.sql' -print0 | xargs -0 -n1 bash -c 'subst_if_needed "$0"'

# === FIX: explicit one-off patch for uc_ddl.sql end-of-line "USING INDEX TABLESPACE" with no name ===
if [[ -f "${WORK_BASE}/uc_ddl.sql" ]]; then
  sed -E -i "s/USING[[:space:]]+INDEX[[:space:]]+TABLESPACE[[:space:]]*$/USING INDEX TABLESPACE ${TS_INDEX_ESC}/" "${WORK_BASE}/uc_ddl.sql"
  # fail fast if any broken cases remain anywhere
  if grep -RInE 'USING[[:space:]]+INDEX[[:space:]]+TABLESPACE[[:space:]]*$' "${WORK_BASE}" >/dev/null; then
    echo "ERROR: Found unresolved 'USING INDEX TABLESPACE' with no name after normalization." >&2
    grep -RInE 'USING[[:space:]]+INDEX[[:space:]]+TABLESPACE[[:space:]]*$' "${WORK_BASE}" >&2 || true
    exit 4
  fi
fi

# Debug: preview the start of uc_ddl.sql after normalization
if [[ -f "${WORK_BASE}/uc_ddl.sql" ]]; then
  echo "==> Preview uc_ddl.sql (first 40 lines after normalization)"
  nl -ba "${WORK_BASE}/uc_ddl.sql" | sed -n '1,40p' || true
fi

echo "==> Run BASE schema (enforced order: uc_ddl.sql first)"
ORDERED_BASE_FILES=()
[[ -f "${WORK_BASE}/uc_ddl.sql" ]] && ORDERED_BASE_FILES+=("${WORK_BASE}/uc_ddl.sql")
[[ -f "${WORK_BASE}/after_uc_ddl.sql" ]] && ORDERED_BASE_FILES+=("${WORK_BASE}/after_uc_ddl.sql")
while IFS= read -r -d '' f; do
  bn="$(basename "$f")"
  case "$bn" in uc_ddl.sql|after_uc_ddl.sql|drop_all.sql) ;; * ) ORDERED_BASE_FILES+=("$f");; esac
done < <(find "${WORK_BASE}" -maxdepth 1 -type f -name '*.sql' -print0 | sort -z)

echo "  - BASE execution order:"
for f in "${ORDERED_BASE_FILES[@]}"; do echo "    • $(basename "$f")"; done

for f in "${ORDERED_BASE_FILES[@]}"; do
  echo ">>> BASE RUN: ${f}"
  ${PSQL} -d "${DB}" -f "${f}"
done

echo "==> Run STEPS (ordered)"
for f in $(ls -1 "${WORK_STEPS}"/*.sql 2>/dev/null | sort); do
  echo ">>> STEP: ${f}"
  ${PSQL} -d "${DB}" -f "${f}"
done

echo "==> Grant default privileges to app role (future objects)"
${PSQL} -d "${DB}" <<SQL
DO \$\$
DECLARE rname text := '${APPUSER_LIT}';
BEGIN
  EXECUTE format('ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON TABLES TO %I', rname);
  EXECUTE format('ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON SEQUENCES TO %I', rname);
END \$\$ LANGUAGE plpgsql;
SQL

echo "==> Done"
"""


def deploy_and_run_fix_and_load(
    ssh: SSH, *, db_name: str, app_user: str, app_pass: str, db_pg_root: str
) -> None:
    """
    Uploads a fix+load shell script and executes it with the correct environment
    to ensure psql variable substitution works (-v db/appuser/apppass) and that
    dynamic identifiers (role/database names) are handled safely in SQL.
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
        f"DBDIR={shlex_quote(base_dir)}"
    )

    # Use /usr/bin/env to preserve PATH and ensure bash execution on various AMIs
    ssh.sudo_check(f"/usr/bin/env {env} bash {remote_fix}")


    remote_verify = "/tmp/aedb_verify_quick.sh"
    ssh.put_text(VERIFY_SCRIPT, remote_verify, mode=0o755)
    log.info("  - running %s ...", remote_verify)

    env = (
        f"DB={shlex_quote(db_name)} "
        f"APPUSER={shlex_quote(app_user)} "
        f"APPPASS={shlex_quote(app_pass)}"
    )

    out = ssh.sudo_check(f"/usr/bin/env {env} bash {remote_verify}")
    # Log only the last handful of lines to keep output readable
    for line in out.splitlines()[-50:]:
        log.info("[VERIFY] %s", line)


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
            ensure_tablespaces(
                ssh,
                dbname=db_name,
                app_user=app_user,
                data_ts_name=ts_data_name,
                index_ts_name=ts_index_name,
                data_path=ts_data_path,
                index_path=ts_index_path,
            )

        deploy_and_run_fix_and_load(
            ssh, db_name=db_name, app_user=app_user, app_pass=app_pass, db_pg_root=db_pg_root
        )
        deploy_and_run_verify(ssh, db_name=db_name, app_user=app_user, app_pass=app_pass)

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
