# automic_bootstrap/components/db_load.py
import logging
from pathlib import Path
import paramiko
from paramiko.ssh_exception import SSHException

log = logging.getLogger(__name__)


def run_db_load(
    db_ip: str,
    key_path: Path,
    db_name: str,
    db_user: str,
    db_pass: str,
    remote_zip_path: str,
) -> None:
    """
    On the DB host:
      - unzip the Automic bundle under /opt/automic/install
      - unpack Utility tar
      - ensure PostgreSQL client lib (libpq) is present
      - create AEDB if missing and required DB settings/tablespaces
      - write ucybdbld.ini for localhost AEDB
      - run ucybdbld with newest UC_UPD.TXT
      - run post checks and print a compact summary
    Raises RuntimeError on failure.
    """
    key_path = Path(key_path).expanduser().resolve()

    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    log.info("[DB LOAD] Connecting to %s with key %s", db_ip, key_path)
    ssh.connect(hostname=db_ip, username="ec2-user", key_filename=str(key_path), timeout=45)

    # Compose a raw bash script with placeholders replaced.
    script = r"""
set -euo pipefail

ZIP="{zip}"
INSTALL_BASE="/opt/automic/install"
UTILITY_TAR="${INSTALL_BASE}/Automation.Platform/Utility/unix/linux/x64/utillx6.tar.gz"
UTILITY_DIR="/opt/automic/Utility"

DB_NAME="{db}"
DB_USER="{user}"
DB_PASS="{pwd}"
PG_SERVICE_1="postgresql@16"
PG_SERVICE_2="postgresql-16"

echo "[DB LOAD] Unzipping bundle and preparing Utility..."

# 0) Check the zip exists
if [ ! -f "$ZIP" ]; then
  echo "ERROR: ZIP not found: $ZIP"
  exit 2
fi

# 1) Unzip the master bundle into INSTALL_BASE (idempotent)
sudo mkdir -p "$INSTALL_BASE"
sudo chown ec2-user:ec2-user "$INSTALL_BASE"
sudo unzip -o "$ZIP" -d "$INSTALL_BASE" >/dev/null

# 2) Unpack the Utility to a stable path (idempotent)
sudo mkdir -p "$UTILITY_DIR"
if [ -f "$UTILITY_TAR" ]; then
  sudo cp -f "$UTILITY_TAR" "$UTILITY_DIR/utillx6.tar.gz"
  cd "$UTILITY_DIR"
  sudo gunzip -f utillx6.tar.gz || true
  if [ -f utillx6.tar ]; then
    sudo tar -xf utillx6.tar
  fi
fi

if [ ! -x "$UTILITY_DIR/bin/ucybdbld" ]; then
  echo "ERROR: Utility missing: $UTILITY_DIR/bin/ucybdbld"
  exit 3
fi

# 3) Ensure DB scripts live under Utility (idempotent)
if [ -d "${INSTALL_BASE}/Automation.Platform/db" ]; then
  sudo cp -a "${INSTALL_BASE}/Automation.Platform/db" "$UTILITY_DIR/" || true
fi
sudo chown -R ec2-user:ec2-user "$UTILITY_DIR"

# 4) Ensure libpq is present (needed by ucupgs.so)
#    (Amazon Linux 2023: libpq from PGDG stream)
sudo dnf -y install libpq >/dev/null 2>&1 || true

# 5) Prepare PostgreSQL: set postgres password (best-effort), ensure AEDB exists, setting, tablespaces
#    If password already set, ALTER USER will succeed or be ignored depending on auth.
sudo bash -lc "sudo -u postgres psql -v ON_ERROR_STOP=1 -c \"ALTER USER postgres WITH PASSWORD '$DB_PASS';\" " || true

# Ensure service is up (name varies by AMI)
if systemctl is-enabled --quiet \"$PG_SERVICE_1\" 2>/dev/null; then
  PG_SVC=\"$PG_SERVICE_1\"
elif systemctl status \"$PG_SERVICE_1\" >/dev/null 2>&1; then
  PG_SVC=\"$PG_SERVICE_1\"
elif systemctl is-enabled --quiet \"$PG_SERVICE_2\" 2>/dev/null; then
  PG_SVC=\"$PG_SERVICE_2\"
else
  PG_SVC=\"$PG_SERVICE_2\"
fi
sudo systemctl enable --now \"$PG_SVC\" || true

# Create AEDB if missing
sudo -u postgres psql -tAc "SELECT 1 FROM pg_database WHERE datname='$DB_NAME';" | grep -q 1 || \
  sudo -u postgres createdb -E UTF8 -T template0 "$DB_NAME"

# Enforce mandatory setting
sudo -u postgres psql -v ON_ERROR_STOP=1 -d postgres -c "ALTER SYSTEM SET vacuum_cost_limit = 10000;"
sudo systemctl reload \"$PG_SVC\" || sudo systemctl restart \"$PG_SVC\" || true

# Create tablespace dirs owned by postgres, empty, mode 700 (idempotent)
sudo install -d -m 700 -o postgres -g postgres /var/lib/pgsql/tablespaces
sudo install -d -m 700 -o postgres -g postgres /var/lib/pgsql/tablespaces/AE_DATA
sudo install -d -m 700 -o postgres -g postgres /var/lib/pgsql/tablespaces/AE_INDEX

# Label for SELinux if available (ignore errors)
if command -v semanage >/dev/null 2>&1; then
  sudo semanage fcontext -a -t postgresql_db_t "/var/lib/pgsql/tablespaces(/.*)?" 2>/dev/null || true
  sudo restorecon -Rv /var/lib/pgsql/tablespaces >/dev/null 2>&1 || true
fi

# Create tablespaces if missing
sudo -u postgres psql -tAc "SELECT 1 FROM pg_tablespace WHERE spcname='ae_data';" | grep -q 1 || \
  sudo -u postgres psql -v ON_ERROR_STOP=1 -d postgres -c "CREATE TABLESPACE AE_DATA  OWNER postgres LOCATION '/var/lib/pgsql/tablespaces/AE_DATA';"
sudo -u postgres psql -tAc "SELECT 1 FROM pg_tablespace WHERE spcname='ae_index';" | grep -q 1 || \
  sudo -u postgres psql -v ON_ERROR_STOP=1 -d postgres -c "CREATE TABLESPACE AE_INDEX OWNER postgres LOCATION '/var/lib/pgsql/tablespaces/AE_INDEX';"

# 6) Write ucybdbld.ini (direct Postgres; ODBC section is read but driver used is ucupgs.so)
sudo bash -lc "cat > '$UTILITY_DIR/bin/ucybdbld.ini' <<'INI'
[ODBC]
sqlDriverConnect=ODBCVAR=NNJNIORP,host=127.0.0.1 port=5432 dbname={db} user={user} password={pwd} connect_timeout=10 client_encoding=UTF-8
[DB]
; Force working dir resolution
PATH=/opt/automic/Utility/bin
ODBC_TRACE=0
INI"

# 7) Export runtime libs and run newest UC_UPD.TXT
export UT="$UTILITY_DIR"
export LD_LIBRARY_PATH="$UT/lib:$UT/bin:${LD_LIBRARY_PATH:-}"
cd "$UT/bin"

DBTXT=$(ls -1d "$UT"/db/general/* 2>/dev/null | sort -rV | head -n1)/UC_UPD.TXT || true
if [ -z "$DBTXT" ] || [ ! -f "$DBTXT" ]; then
  echo "ERROR: UC_UPD.TXT not found under $UT/db/general/*"
  exit 4
fi

echo "Running ucybdbld with $DBTXT ..."
set +e
"$UT/bin/ucybdbld" -B -X"$DBTXT" -I"$UT/bin/ucybdbld.ini"
RC=$?
set -e
if [ $RC -ne 0 ]; then
  echo "ucybdbld returned RC=$RC"
  exit $RC
fi

# 8) Post checks and summary
echo "__POSTCHECK_BEGIN__"
sudo -u postgres psql -d "$DB_NAME" -tAc "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema='public';" | sed 's/^/TABLES=/' || true
sudo -u postgres psql -d "$DB_NAME" -tAc "SELECT versi_major||'.'||versi_minor||'.'||COALESCE(versi_patch,0)||'/'||versi_status FROM uc_versi ORDER BY versi_major DESC, versi_minor DESC LIMIT 1;" | sed 's/^/VERSION=/' || true
sudo -u postgres psql -d "$DB_NAME" -tAc "SELECT to_regclass('public.oh');" | sed 's/^/OH=/' || true
sudo -u postgres psql -d "$DB_NAME" -tAc "SELECT to_regclass('public.uc_user');" | sed 's/^/UC_USER=/' || true
sudo -u postgres psql -d "$DB_NAME" -tAc "SELECT to_regclass('public.uc_client');" | sed 's/^/UC_CLIENT=/' || true
sudo -u postgres psql -d "$DB_NAME" -tAc "SHOW vacuum_cost_limit;" | sed 's/^/VCL=/' || true
echo "__POSTCHECK_END__"
""".replace("{zip}", remote_zip_path)\
   .replace("{db}", db_name)\
   .replace("{user}", db_user)\
   .replace("{pwd}", db_pass)

    # Run the script remotely
    stdin, stdout, stderr = ssh.exec_command(script, get_pty=True, timeout=0)
    out = stdout.read().decode("utf-8", "ignore")
    err = stderr.read().decode("utf-8", "ignore")
    rc = stdout.channel.recv_exit_status()

    # Always log the outcome
    if rc != 0:
        log.error("[DB LOAD] FAILED (code %s).", rc)
        if out.strip():
            log.error("STDOUT:\n%s", out)
        if err.strip():
            log.error("STDERR:\n%s", err)
        ssh.close()
        raise RuntimeError("DB load failed")

    # Parse postcheck block for a friendly summary
    summary = {
        "TABLES": None,
        "VERSION": None,
        "OH": None,
        "UC_USER": None,
        "UC_CLIENT": None,
        "VCL": None,
    }
    in_block = False
    for line in out.splitlines():
        line = line.strip()
        if line == "__POSTCHECK_BEGIN__":
            in_block = True
            continue
        if line == "__POSTCHECK_END__":
            in_block = False
            continue
        if in_block:
            for k in list(summary.keys()):
                prefix = f"{k}="
                if line.startswith(prefix):
                    summary[k] = line[len(prefix):] or None

    # Emit a concise human log
    log.info(
        "AEDB ready: version=%s, tables=%s, oh=%s, uc_user=%s, uc_client=%s, vacuum_cost_limit=%s",
        summary["VERSION"] or "unknown",
        summary["TABLES"] or "unknown",
        summary["OH"] or "NULL",
        summary["UC_USER"] or "NULL",
        summary["UC_CLIENT"] or "NULL",
        summary["VCL"] or "unknown",
    )

    # And print a nice console summary for the user
    print("=== AEDB Load Summary ===")
    print(f" DB version         : {summary['VERSION'] or 'unknown'}")
    print(f" Public tables      : {summary['TABLES'] or 'unknown'}")
    print(f" Key tables present : OH={summary['OH']}, UC_USER={summary['UC_USER']}, UC_CLIENT={summary['UC_CLIENT']}")
    print(f" vacuum_cost_limit  : {summary['VCL'] or 'unknown'}")
    print("=========================")

    ssh.close()
