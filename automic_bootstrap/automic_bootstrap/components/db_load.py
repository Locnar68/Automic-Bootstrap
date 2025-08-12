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

# ---------- CLI ----------
def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Automic AEDB load helper")
    p.add_argument("--db-host", required=True, help="DB server IP/DNS")
    p.add_argument("--ssh-user", default="ec2-user", help="SSH username (default: ec2-user)")
    p.add_argument("--key-path", required=True, help="Path to PEM key")
    p.add_argument("--db-name", default="AEDB", help="Database name (default: AEDB)")
    p.add_argument("--db-user", default="postgres", help="DB superuser (default: postgres)")
    p.add_argument("--db-password", required=True, help="DB superuser password (not used by local psql calls)")
    p.add_argument("--remote-zip", required=True, help="Path to Automic media zip on remote host")
    p.add_argument("--remote-install-root", default="/opt/automic/install", help="Install root (default: /opt/automic/install)")
    p.add_argument("--remote-utils", default="/opt/automic/utils", help="Utils dir (default: /opt/automic/utils)")
    p.add_argument("--verbosity", "-v", action="count", default=1, help="Increase log verbosity (-vv for debug)")
    return p.parse_args(argv or sys.argv[1:])
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
    """
    Ensure PostgreSQL is running:
      1) If 5432 already listening → OK.
      2) Try start.
      3) On failure, self-heal: fix /run/postgresql, data perms, PGDATA env, initdb if missing; enable+start.
    """
    import shlex
    log.info("[DB LOAD] Ensure PostgreSQL running...")

    if _port_5432_listening(ssh):
        log.info("  - PostgreSQL already listening on 5432")
        ssh.sudo_check("sudo -u postgres psql -XAtc 'SELECT version();'")
        return

    rc, _, _ = ssh.sudo(f"systemctl start {shlex.quote(unit)}")
    if rc == 0:
        ssh.sudo_check("sudo -u postgres psql -XAtc 'SELECT version();'")
        return

    log.warning("  - start failed; applying self-heal and retrying")

    # Runtime socket dir
    ssh.sudo("mkdir -p /run/postgresql && chown postgres:postgres /run/postgresql && chmod 775 /run/postgresql")

    # Data dir + ownership
    ssh.sudo("mkdir -p /var/lib/pgsql/data")
    ssh.sudo("chown -R postgres:postgres /var/lib/pgsql")
    ssh.sudo("chmod 700 /var/lib/pgsql/data || true")

    # PGDATA for generic unit
    ssh.sudo("mkdir -p /etc/sysconfig/pgsql")
    ssh.sudo("bash -lc 'echo \"PGDATA=\\\"/var/lib/pgsql/data\\\"\" > /etc/sysconfig/pgsql/postgresql'")

    # Initialize cluster if missing
    rc_init, _, _ = ssh.sudo("test -f /var/lib/pgsql/data/PG_VERSION")
    if rc_init != 0:
        ssh.sudo_check("postgresql-setup --initdb")

    # Clear stale locks
    ssh.sudo("rm -f /var/lib/pgsql/data/postmaster.pid /run/postgresql/.s.PGSQL.5432.lock || true")

    # Enable + start
    ssh.sudo("systemctl daemon-reload")
    ssh.sudo_check(f"systemctl enable --now {shlex.quote(unit)}")

    # Verify
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

def set_vacuum_cost_limit(ssh: SSH, value: int = 4000, dbuser: str = "postgres") -> None:
    log.info("[DB LOAD] Set vacuum_cost_limit...")
    ssh.sudo_check(f"sudo -u {shlex.quote(dbuser)} psql -XAtc \"ALTER SYSTEM SET vacuum_cost_limit = {value};\"")
    ssh.sudo("systemctl reload postgresql-16 || systemctl reload postgresql@16 || systemctl reload postgresql || true")
# ---------- Tablespaces (no transactions) ----------
def ensure_tablespaces(
    ssh: SSH,
    *,
    data_ts_name: str = "ae_data",
    index_ts_name: str = "ae_index",
    data_path: str = "/pgdata/ts/AE_DATA",
    index_path: str = "/pgdata/ts/AE_INDEX",
    dbuser: str = "postgres",
) -> None:
    log.info("[DB LOAD] Tablespaces...")

    # Ensure directories and ownership
    ssh.sudo_check(f"mkdir -p {shlex.quote(data_path)} {shlex.quote(index_path)}")
    ssh.sudo_check("chown -R postgres:postgres /pgdata/ts")
    ssh.sudo_check(f"chmod 700 /pgdata/ts {shlex.quote(data_path)} {shlex.quote(index_path)}")

    def ts_exists(name: str) -> bool:
        rc, out, err = ssh.sudo(
            f"sudo -u {shlex.quote(dbuser)} psql -XAtc \"SELECT 1 FROM pg_tablespace WHERE spcname='{name}';\""
        )
        if rc != 0:
            raise RuntimeError(f"psql check for tablespace '{name}' failed: {err or out}")
        return bool(out.strip())

    def create_ts_if_missing(name: str, loc: str) -> None:
        if ts_exists(name):
            log.info("  - tablespace %s already present", name)
            return
        log.info("  - creating tablespace %s at %s", name, loc)
        ssh.sudo_check(
            f"sudo -u {shlex.quote(dbuser)} psql -v ON_ERROR_STOP=1 -Xc "
            f"\"CREATE TABLESPACE {name} OWNER {dbuser} LOCATION '{loc}';\""
        )

    create_ts_if_missing(data_ts_name, data_path)
    create_ts_if_missing(index_ts_name, index_path)
    log.info("  - tablespaces ensured: %s, %s", data_ts_name, index_ts_name)

# ---------- Prereqs + unzip media ----------
def _ensure_tool(ssh: SSH, bin_name: str, install_cmd: str) -> None:
    rc, _, _ = ssh.sudo(f"command -v {shlex.quote(bin_name)}")
    if rc != 0:
        ssh.sudo_check(install_cmd)

def ensure_utils_and_unzip(ssh: SSH, remote_utils: str, remote_zip: str, install_root: str) -> str:
    """
    Ensures utils dir exists, tools available, and the product zip is extracted
    under install_root/<zip-stem>. Returns the extracted dir path.
    """
    log.info("[DB LOAD] Prepare utils dir and unzip media...")
    ssh.sudo_check(f"mkdir -p {shlex.quote(remote_utils)}")
    ssh.sudo_check(f"chmod 755 {shlex.quote(remote_utils)}")

    # tools
    _ensure_tool(ssh, "unzip", "dnf -y install unzip || yum -y install unzip || true")
    _ensure_tool(ssh, "rsync", "dnf -y install rsync || yum -y install rsync || true")

    # ensure install root
    ssh.sudo_check(f"mkdir -p {shlex.quote(install_root)}")

    # compute extraction dir
    base = posixpath.basename(remote_zip)
    stem = base[:-4] if base.lower().endswith(".zip") else base
    extract_dir = posixpath.join(install_root, stem)

    # unzip only if needed
    rc, _, _ = ssh.sudo(f"test -d {shlex.quote(extract_dir)}")
    if rc != 0:
        ssh.sudo_check(f"unzip -q -o {shlex.quote(remote_zip)} -d {shlex.quote(extract_dir)}")
        ssh.sudo_check(f"find {shlex.quote(extract_dir)} -type f -name '*.sh' -exec chmod +x {{}} +;")
        log.info("  - extracted to %s", extract_dir)
    else:
        log.info("  - archive already extracted at %s", extract_dir)

    return extract_dir
# ---------- Version selection + token substitution ----------

def _prefer_latest_base_dir(ssh: SSH, root: str) -> Optional[str]:
    """
    Pick the highest version directory under .../db/postgresql (e.g., 24.4),
    NOT the root and NOT the steps subdir.
    """
    inner = f"find {shlex.quote(root)} -mindepth 1 -maxdepth 1 -type d -printf '%f\\n' | sort -V"
    rc, out, _ = ssh.sudo("sh -lc " + shlex.quote(inner))
    if rc != 0 or not out.strip():
        return None
    ver = out.strip().splitlines()[-1].strip()  # highest (last after sort -V)
    return posixpath.join(root, ver)

def _preprocess_dir(ssh: SSH, src_dir: str, dst_dir: str, db_user: str) -> str:
    """
    Copy SQLs to a temp dir and replace Automic tokens with concrete names.
    Maps all *data-ish* tokens -> ae_data, *index-ish* -> ae_index, and user/owner -> db_user.
    """
    ssh.sudo(f"rm -rf {shlex.quote(dst_dir)} && mkdir -p {shlex.quote(dst_dir)}")
    ssh.sudo(f"rsync -a {shlex.quote(src_dir)}/ {shlex.quote(dst_dir)}/")

    # Expanded token list (covers TS_* and legacy P* tokens & owner/user)
    sed = (
        r"find {dir} -type f -name '*.sql' -print0 | xargs -0 sed -i "
        r"-e 's/&TS_DATA#/{ts_data}/g' "
        r"-e 's/&TS_INDEX#/{ts_index}/g' "
        r"-e 's/&TS_USER#/{db_user}/g' "
        r"-e 's/&TS_LOB#/{ts_data}/g' "
        r"-e 's/&TS_TEMP#/{ts_data}/g' "
        r"-e 's/&PData#/{ts_data}/g' -e 's/&PDATA#/{ts_data}/g' "
        r"-e 's/&PIndex#/{ts_index}/g' -e 's/&PINDEX#/{ts_index}/g' "
        r"-e 's/&PTemp#/{ts_data}/g' -e 's/&PTEMP#/{ts_data}/g' "
        r"-e 's/&PLog#/{ts_data}/g' -e 's/&PLOG#/{ts_data}/g' "
        r"-e 's/&PMisc#/{ts_data}/g' -e 's/&PMISC#/{ts_data}/g' "
        r"-e 's/&User#/{db_user}/g' -e 's/&USER#/{db_user}/g' "
        r"-e 's/&Owner#/{db_user}/g' -e 's/&OWNER#/{db_user}/g'"
    ).format(
        dir=shlex.quote(dst_dir),
        ts_data="ae_data",
        ts_index="ae_index",
        db_user=db_user,
    )
    ssh.sudo(sed)
    return dst_dir
# ---------- Ordered base schema load + steps ----------

def _run_base_schema_ordered(ssh: SSH, base_tmp: str, dbname: str, dbuser: str) -> None:
    """
    Load base schema in a dependency-friendly order:
      A) creators for staging tables (stg_*, stgori, stg_ori_) first
      B) remaining CREATE TABLE files
      C) the rest (functions, views, grants, etc.)
      D) ilmswitch.sql LAST
    """
    def _sh(cmd: str) -> tuple[int, str, str]:
        return ssh.sudo("sh -lc " + shlex.quote(cmd))

    rc, out, err = _sh(f"grep -RIlE 'CREATE[[:space:]]+TABLE[[:space:]]+(stg_|stgori|stg_ori_)' {shlex.quote(base_tmp)} --include '*.sql' | sort || true")
    stg_files = [ln.strip() for ln in out.strip().splitlines() if ln.strip()] if rc == 0 else []

    rc, out, err = _sh(f"grep -RIl 'CREATE[[:space:]]\\+TABLE' {shlex.quote(base_tmp)} --include '*.sql' | sort || true")
    tbl_files = [ln.strip() for ln in out.strip().splitlines() if ln.strip()] if rc == 0 else []

    rc, out, err = _sh(f"find {shlex.quote(base_tmp)} -type f -name '*.sql' | sort")
    all_files = [ln.strip() for ln in out.strip().splitlines() if ln.strip()] if rc == 0 else []

    def _without_ilmswitch(paths: list[str]) -> list[str]:
        return [p for p in paths if not p.endswith("/ilmswitch.sql") and not p.endswith("ilmswitch.sql")]

    stg_files = _without_ilmswitch(stg_files)
    tbl_files = _without_ilmswitch(tbl_files)
    all_files = _without_ilmswitch(all_files)

    def _dedup(seq: list[str]) -> list[str]:
        seen = set(); out = []
        for x in seq:
            if x not in seen:
                seen.add(x); out.append(x)
        return out

    stg_files = _dedup(stg_files)
    tbl_files = _dedup(tbl_files)
    all_files = _dedup(all_files)

    # Phase A
    for f in stg_files:
        log.info(">>> STG    : %s", f)
        ssh.sudo_check(f"sudo -u {shlex.quote(dbuser)} psql -v ON_ERROR_STOP=1 -X -d {shlex.quote(dbname)} -f {shlex.quote(f)}")

    # Phase B
    stg_set = set(stg_files)
    for f in tbl_files:
        if f in stg_set:
            continue
        log.info(">>> TABLES : %s", f)
        ssh.sudo_check(f"sudo -u {shlex.quote(dbuser)} psql -v ON_ERROR_STOP=1 -X -d {shlex.quote(dbname)} -f {shlex.quote(f)}")

    # Phase C
    ran_set = set(stg_files) | set(tbl_files)
    for f in all_files:
        if f in ran_set:
            continue
        log.info(">>> OTHER  : %s", f)
        ssh.sudo_check(f"sudo -u {shlex.quote(dbuser)} psql -v ON_ERROR_STOP=1 -X -d {shlex.quote(dbname)} -f {shlex.quote(f)}")

    # Phase D
    rc, out, _ = _sh(f"find {shlex.quote(base_tmp)} -type f -name 'ilmswitch.sql' | head -n1 || true")
    ilm = out.strip()
    if ilm:
        log.info(">>> ILM    : %s", ilm)
        ssh.sudo_check(f"sudo -u {shlex.quote(dbuser)} psql -v ON_ERROR_STOP=1 -X -d {shlex.quote(dbname)} -f {shlex.quote(ilm)}")

def load_aedb(ssh: SSH, extracted_root: str, dbname: str, dbuser: str) -> None:
    log.info("[DB LOAD] Load AEDB contents...")

    # BASE: latest version dir (e.g., .../postgresql/24.4)
    base_dir = _prefer_latest_base_dir(ssh, extracted_root)
    if not base_dir:
        raise RuntimeError(f"Could not find base PostgreSQL dir under: {extracted_root}")
    log.info("  - using base dir: %s", base_dir)

    # Mirror base (exclude steps & chngilm*), substitute tokens, then run ordered
    base_tmp_root = "/tmp/aedb_base_work"
    ssh.sudo(f"rm -rf {shlex.quote(base_tmp_root)} && mkdir -p {shlex.quote(base_tmp_root)}")
    ssh.sudo(f"rsync -a --delete --exclude 'steps' --exclude 'chngilm*' {shlex.quote(base_dir)}/ {shlex.quote(base_tmp_root)}/")
    base_tmp = _preprocess_dir(ssh, base_tmp_root, base_tmp_root, db_user=dbuser)
    _run_base_schema_ordered(ssh, base_tmp, dbname, dbuser)

    # STEPS: preprocess with same token map and run step_*.sql in order
    steps_dir = posixpath.join(base_dir, "steps")
    rc, _, _ = ssh.sudo(f"test -d {shlex.quote(steps_dir)}")
    if rc == 0:
        steps_tmp_root = "/tmp/aedb_steps_work"
        ssh.sudo(f"rm -rf {shlex.quote(steps_tmp_root)} && mkdir -p {shlex.quote(steps_tmp_root)}")
        ssh.sudo(f"cp -r {shlex.quote(steps_dir)} {shlex.quote(steps_tmp_root)}/")

        steps_tmp = posixpath.join(steps_tmp_root, "steps")
        _preprocess_dir(ssh, steps_tmp, steps_tmp, db_user=dbuser)

        inner = f"find {shlex.quote(steps_tmp)} -maxdepth 1 -type f -name 'step_*.sql' | sort"
        rc, out, err = ssh.sudo("sh -lc " + shlex.quote(inner))
        if rc != 0:
            raise RuntimeError(f"Failed to enumerate steps under {steps_tmp}.\nSTDERR:\n{err}\nSTDOUT:\n{out}")
        files = [ln.strip() for ln in out.strip().splitlines() if ln.strip()]
        log.info("  - executing %d step files into %s ...", len(files), dbname)
        for f in files:
            ssh.sudo_check(
                f"sudo -u {shlex.quote(dbuser)} psql -v ON_ERROR_STOP=1 -X -d {shlex.quote(dbname)} -f {shlex.quote(f)}"
            )

    log.info("  - AEDB base + steps load completed.")
# ---------- Orchestrator ----------
def run_db_load(
    db_host: str,
    key_path: str,
    db_name: str,
    db_user: str,
    db_password: str,  # currently unused in remote psql calls, kept for future JDBC/remote psql
    remote_zip: str,
    ssh_user: str = "ec2-user",
    remote_install_root: str = "/opt/automic/install",
    remote_utils: str = "/opt/automic/utils",
) -> None:
    setup_logging()
    log.info("Complete!")  # mirror your banner

    ssh_cfg = SSHConfig(host=db_host, user=ssh_user, key_path=key_path)
    with SSH(ssh_cfg) as ssh:
        # Detect service, ensure running (port-first), then DB + tuning
        unit = detect_pg_service(ssh)
        ensure_pg_running(ssh, unit)
        ensure_db_exists(ssh, db_name, db_user)
        set_vacuum_cost_limit(ssh, 4000, db_user)

        # Ensure tablespaces (no transactions)
        ensure_tablespaces(ssh, dbuser=db_user)

        # Prepare utils & unzip media
        extracted = ensure_utils_and_unzip(ssh, remote_utils, remote_zip, remote_install_root)

        # Load AEDB: base (ordered) + steps
        load_aedb(ssh, extracted, db_name, db_user)

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
        )
        return 0
    except Exception as e:
        log.error("Upload or AEDB load failed: %s", e)
        return 2

if __name__ == "__main__":
    raise SystemExit(main())
