import logging
from pathlib import Path
from .utils import write_remote_file
from ..remote.ssh import ssh_exec
from ..remote.sftp import sftp_put

logger = logging.getLogger(__name__)

def _service_names():
    return ["postgresql@16", "postgresql-16"]

def ensure_pg_initialized(db_ip, key_path):
    script = r"""bash -lc '
set -euo pipefail
PGVER=16
PGDATA=/var/lib/pgsql/${PGVER}/data
install -d -o postgres -g postgres "$PGDATA"
if [ ! -f "$PGDATA/PG_VERSION" ]; then
  sudo -u postgres /usr/bin/initdb -D "$PGDATA" --encoding=UTF8 --locale=C
fi
mkdir -p /etc/systemd/system/postgresql@${PGVER}.service.d
printf "[Service]
Environment=PGDATA=%s
" "$PGDATA" > /etc/systemd/system/postgresql@${PGVER}.service.d/override.conf
if command -v getenforce >/dev/null 2>&1 && [ "$(getenforce)" != "Disabled" ]; then
  restorecon -R /var/lib/pgsql || true
fi
systemctl daemon-reload
systemctl enable postgresql@${PGVER} >/dev/null 2>&1 || true
systemctl restart postgresql@${PGVER} || systemctl restart postgresql-${PGVER}
'"""
    rc, out, err = ssh_exec(db_ip, key_path, script, sudo=True)
    if rc != 0:
        raise RuntimeError(err)

def ensure_postgres_tuning(db_ip, key_path):
    hba = "/var/lib/pgsql/16/data/pg_hba.conf"
    conf = "/var/lib/pgsql/16/data/postgresql.conf"
    cmds = [
        f"grep -q "0.0.0.0/0" {hba} || echo "host all all 0.0.0.0/0 md5" | tee -a {hba} >/dev/null",
        f"grep -q "^listen_addresses" {conf} || echo "listen_addresses = '*'" | tee -a {conf} >/dev/null",
        f"grep -q "^statement_timeout" {conf} || echo "statement_timeout = '300s'" | tee -a {conf} >/dev/null",
        f"grep -q "^idle_in_transaction_session_timeout" {conf} || echo "idle_in_transaction_session_timeout = '300s'" | tee -a {conf} >/dev/null",
    ]
    for c in cmds:
        rc, out, err = ssh_exec(db_ip, key_path, c, sudo=True)
        if rc != 0:
            raise RuntimeError(err)
    # restart to apply
    for svc in _service_names():
        rc, out, err = ssh_exec(db_ip, key_path, f"systemctl restart {svc}", sudo=True)
        if rc == 0:
            break

def wait_for_postgres_ready(db_ip, key_path, timeout=300):
    import time
    start = time.time()
    while time.time() - start < timeout:
        for svc in _service_names():
            rc, out, err = ssh_exec(db_ip, key_path, f"systemctl is-active {svc}", sudo=True)
            if out.strip() == "active":
                return True
        time.sleep(5)
    raise TimeoutError("PostgreSQL did not become active in time.")

def put_automic_zip(db_ip, key_path, local_zip: Path):
    remote_zip = "/opt/automic/install/Automic.zip"
    rc, out, err = ssh_exec(db_ip, key_path, "mkdir -p /opt/automic/install && chown -R ec2-user:ec2-user /opt/automic", sudo=True)
    if rc != 0:
        raise RuntimeError(err)
    sftp_put(db_ip, key_path, local_zip, remote_zip)
    for c in ["dnf install -y unzip || yum install -y unzip", "cd /opt/automic/install && unzip -o Automic.zip"]:
        rc, out, err = ssh_exec(db_ip, key_path, c, sudo=True)
        if rc != 0:
            raise RuntimeError(err)

def install_java_for_db_tools(db_ip, key_path):
    rc, out, err = ssh_exec(db_ip, key_path, "dnf install -y java-11-amazon-corretto || yum install -y java-11-openjdk", sudo=True)
    if rc != 0:
        raise RuntimeError(err)

def ensure_automic_objects(db_ip, key_path, db_name: str, db_pass: str):
    script = rf"""bash -lc '
set -euo pipefail
DB="{db_name}"
PASS="{db_pass}"
install -d -o postgres -g postgres /opt/db/tablespaces/ae_data
install -d -o postgres -g postgres /opt/db/tablespaces/ae_index
# user
if ! sudo -u postgres psql -tAc "SELECT 1 FROM pg_roles WHERE rolname='''aauser'''" | grep -q 1; then
  sudo -u postgres psql -c "CREATE USER aauser WITH LOGIN PASSWORD '''${{PASS}}'''"
fi
# tablespaces
if ! sudo -u postgres psql -tAc "SELECT 1 FROM pg_tablespace WHERE spcname='''ae_data'''" | grep -q 1; then
  sudo -u postgres psql -c "CREATE TABLESPACE ae_data OWNER postgres LOCATION '''/opt/db/tablespaces/ae_data'''"
  sudo -u postgres psql -c "ALTER TABLESPACE ae_data OWNER TO aauser"
fi
if ! sudo -u postgres psql -tAc "SELECT 1 FROM pg_tablespace WHERE spcname='''ae_index'''" | grep -q 1; then
  sudo -u postgres psql -c "CREATE TABLESPACE ae_index OWNER postgres LOCATION '''/opt/db/tablespaces/ae_index'''"
  sudo -u postgres psql -c "ALTER TABLESPACE ae_index OWNER TO aauser"
fi
# database
if ! sudo -u postgres psql -tAc "SELECT 1 FROM pg_database WHERE datname='''${{DB}}'''" | grep -q 1; then
  sudo -u postgres psql -c "CREATE DATABASE "${{DB}}" WITH OWNER=aauser TEMPLATE=template0 ENCODING='''UTF8''' TABLESPACE=ae_data LC_COLLATE='''C''' LC_CTYPE='''C'''"
fi
# schema + defaults
if ! sudo -u postgres psql -d "${{DB}}" -tAc "SELECT 1 FROM information_schema.schemata WHERE schema_name='''aaschema'''" | grep -q 1; then
  sudo -u postgres psql -d "${{DB}}" -c "CREATE SCHEMA aaschema AUTHORIZATION aauser"
fi
sudo -u postgres psql -d "${{DB}}" -c "ALTER ROLE aauser IN DATABASE "${{DB}}" SET search_path TO '''aaschema'''"
'"""
    rc, out, err = ssh_exec(db_ip, key_path, script, sudo=True)
    if rc != 0:
        raise RuntimeError(err)

def install_utilities_and_dbload(db_ip, key_path):
    cmds = [
        "mkdir -p /opt/automic/Utility",
        "if [ -f /opt/automic/install/Automation.Platform/Utility/unix/linux/x64/utillx6.tar.gz ]; then cp /opt/automic/install/Automation.Platform/Utility/unix/linux/x64/utillx6.tar.gz /opt/automic/Utility/; fi",
        "cd /opt/automic/Utility && if [ -f utillx6.tar.gz ]; then gunzip -f utillx6.tar.gz && tar -xf utillx6.tar; fi",
        "if [ -d /opt/automic/install/Automation.Platform/db ]; then cp -R /opt/automic/install/Automation.Platform/db /opt/automic/Utility/; fi",
        "cd /opt/automic/Utility/bin && if [ -f ucybdbld.ori.ini ]; then cp -n ucybdbld.ori.ini ucybdbld.ini; fi",
    ]
    for c in cmds:
        rc, out, err = ssh_exec(db_ip, key_path, c, sudo=True)
        if rc != 0:
            raise RuntimeError(err)

def write_dbload_ini(db_ip, key_path, db_host: str, db_name: str, db_pass: str):
    ini = f"sqlDriverConnect=ODBCVAR=NNJNIORP,host={db_host} port=5432 dbname={db_name} user=aauser password={db_pass} connect_timeout=10 client_encoding=UTF-8\n"
    write_remote_file(db_ip, key_path, "/opt/automic/Utility/bin/ucybdbld.ini", ini, sudo=True)

def run_db_load(db_ip, key_path):
    cmd = r"""bash -lc '
set -e
DBTXT=$(ls -1d /opt/automic/Utility/db/general/* 2>/dev/null | sort -rV | head -n1)/UC_UPD.TXT || true
if [ -n "$DBTXT" ] && [ -f "$DBTXT" ]; then
  /opt/automic/Utility/bin/ucybdbld -B -X"$DBTXT"
else
  echo "UC_UPD.TXT not found under /opt/automic/Utility/db/general/* (skipping DB load)" >&2
fi
'"""
    rc, out, err = ssh_exec(db_ip, key_path, cmd, sudo=True)
    if rc != 0:
        raise RuntimeError(err)

def install_aedb(db_ip: str, key_path: Path, db_name: str, db_pass: str, local_zip: Path):
    logger.info("=== AEDB: init service & start ===")
    ensure_pg_initialized(db_ip, key_path)
    logger.info("=== AEDB: apply base tuning ===")
    ensure_postgres_tuning(db_ip, key_path)
    wait_for_postgres_ready(db_ip, key_path)
    logger.info("=== AEDB: upload Automic image ===")
    put_automic_zip(db_ip, key_path, local_zip)
    logger.info("=== AEDB: Java for DB tools ===")
    install_java_for_db_tools(db_ip, key_path)
    logger.info("=== AEDB: create users, tablespaces, DB, schema ===")
    ensure_automic_objects(db_ip, key_path, db_name, db_pass)
    logger.info("=== AEDB: Utilities + DB load ===")
    install_utilities_and_dbload(db_ip, key_path)
    write_dbload_ini(db_ip, key_path, db_ip, db_name, db_pass)
    run_db_load(db_ip, key_path)
    logger.info("AEDB installation complete.")
