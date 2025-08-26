# automic_bootstrap/components/ae_lite.py
from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from pathlib import Path, PurePosixPath as P
from typing import Optional

# Reuse your remote facade (same style as awi.py)
from automic_bootstrap.remote import SSHClient, run, sudo, put_text

log = logging.getLogger(__name__)

@dataclass
class AELiteConfig:
    # Target AE host
    host: str
    ssh_user: str = "ec2-user"
    key_path: str = "~/.ssh/automic-key.pem"

    # AE filesystem layout on the AE host
    ae_home: str = "/opt/automic/AutomationEngine"

    # Where to fetch AE media from on the DB host (directory)
    db_host: Optional[str] = None
    db_media_path: str = "/opt/automic/install/Automation.Platform/AutomationEngine"

    # DB connectivity (for ini line etc.)
    db_port: int = 5432
    db_name: str = "AEDB"

    # JDBC detection/copy
    # Accepts absolute path (AE host) OR a glob to search on AE/DB
    jdbc_glob: str = "postgresql-*.jar"

    # Preferred place to stage JDBC on AE
    jdbc_dest_dir: str = "/opt/automic/jdbc"

    # Runtime knobs
    java_bin: str = "/usr/bin/java"
    jcp_port: int = 8443  # JCP (TLS) default for modern AE

# ---------------- helpers ----------------

def _file_exists(ssh: SSHClient, path: str) -> bool:
    return run(ssh, f"test -s {path}", check=False).rc == 0

def _dir_exists(ssh: SSHClient, path: str) -> bool:
    return run(ssh, f"test -d {path}", check=False).rc == 0

def _glob_one(ssh: SSHClient, pattern: str) -> str:
    """Return first match for a glob pattern on the remote host, else ''."""
    cmd = f"bash -lc \"ls -1 {pattern} 2>/dev/null | head -n1\""
    return run(ssh, cmd, check=False).out.strip()

def _read_local(path: str) -> str:
    with open(os.path.expanduser(path), "r", encoding="utf-8", errors="ignore") as f:
        return f.read()

def _ensure_dirs(ssh: SSHClient, *dirs: str, owner: Optional[str] = None, mode: int = 0o755) -> None:
    sudo(ssh, "install -d " + " ".join(f"-m {mode:o} {d}" for d in dirs))
    if owner:
        sudo(ssh, f"chown -R {owner}:{owner} " + " ".join(dirs))

def _ensure_java(ssh: SSHClient, java_bin: str) -> None:
    if run(ssh, f"{java_bin} -version", check=False).rc != 0 and run(ssh, "java -version", check=False).rc != 0:
        # Amazon Linux 2023 / RHEL-family
        run(ssh, "sudo -n dnf -y install java-17-amazon-corretto-headless || sudo -n dnf -y install java-21-amazon-corretto-headless || "
                 "sudo -n yum -y install java-17-openjdk || sudo -n yum -y install java-11-openjdk", check=False)

def _upload_temp_pem(ae: SSHClient, pem_text: str) -> str:
    run(ae, f"mkdir -p /home/{ae.user}/.ssh && chmod 700 /home/{ae.user}/.ssh", check=False)
    pem_remote = f"/home/{ae.user}/.ssh/automic-tmp.pem"
    put_text(ae, pem_text, pem_remote, mode=0o600)
    return pem_remote

def _cleanup_temp_pem(ae: SSHClient, pem_remote: str) -> None:
    run(ae, f"shred -u {pem_remote}", check=False)
def _pull_ae_from_db_to_ae(ae: SSHClient, cfg: AELiteConfig) -> None:
    """
    Copy AutomationEngine folder from DB host → AE host using the same PEM:
      - upload PEM as temp to AE host
      - scp -r from DB:<candidate_paths> into AE parent dir
      - normalize nested AutomationEngine/AutomationEngine
    """
    pem_txt = _read_local(cfg.key_path)
    pem_remote = _upload_temp_pem(ae, pem_txt)
    try:
        parent = str(P(cfg.ae_home).parent)  # /opt/automic
        _ensure_dirs(ae, parent, owner=ae.user)

        candidates = [
            cfg.db_media_path,  # hinted directory
            "/opt/automic/install/AutomationEngine",
            "/opt/automic/AutomationEngine",
            "/opt/automic/install/Automation.Platform/AutomationEngine",
            "/opt/automic/install/Automation.Platform/automationengine",
            "/opt/automic/install/Automation.Platform/Automationengine",
        ]
        seen, copied = set(), False
        for src in [p for p in candidates if not (p in seen or seen.add(p))]:
            scp_cmd = (
                f"scp -i {pem_remote} -o StrictHostKeyChecking=no -r "
                f"{cfg.ssh_user}@{cfg.db_host}:{src} {parent}/"
            )
            rc = run(ae, scp_cmd, check=False).rc
            if rc != 0:
                log.debug("AE media copy from %s failed rc=%s; trying next", src, rc)
                continue

            # Normalize any double-nesting
            run(
                ae,
                f"bash -lc \"test -d {cfg.ae_home}/AutomationEngine && "
                f"mv {cfg.ae_home}/AutomationEngine/* {cfg.ae_home}/ && rmdir {cfg.ae_home}/AutomationEngine || true\"",
                check=False,
            )
            sudo(ae, f"chown -R {ae.user}:{ae.user} {parent}")
            if _dir_exists(ae, f"{cfg.ae_home}/bin"):
                copied = True
                log.info("Copied AutomationEngine from DB host path: %s", src)
                break

        if not copied and not _dir_exists(ae, f"{cfg.ae_home}/bin"):
            log.warning(
                "AutomationEngine binaries not found under %s after copy attempts. "
                "Proceeding without Engine media; you can upload it later.",
                cfg.ae_home,
            )
    finally:
        _cleanup_temp_pem(ae, pem_remote)

def _ensure_ae_present(ae: SSHClient, cfg: AELiteConfig) -> None:
    """Ensure AutomationEngine files exist under cfg.ae_home (non-fatal if absent)."""
    have_bin = _dir_exists(ae, f"{cfg.ae_home}/bin")
    jp_jar  = _file_exists(ae, f"{cfg.ae_home}/bin/ucsrvjp.jar")
    if have_bin or jp_jar:
        return
    if not cfg.db_host:
        log.warning("AE media not present and no db_host provided; skipping media copy.")
        return
    _pull_ae_from_db_to_ae(ae, cfg)

def _try_scp_jdbc_from_db(ae: SSHClient, cfg: AELiteConfig, pem_remote: str, src_glob: str, dest_dir: str) -> bool:
    _ensure_dirs(ae, dest_dir, owner=ae.user)
    scp_cmd = (
        f"scp -i {pem_remote} -o StrictHostKeyChecking=no "
        f"{cfg.ssh_user}@{cfg.db_host}:{src_glob} {dest_dir}/"
    )
    rc = run(ae, scp_cmd, check=False).rc
    return rc == 0

def _ensure_jdbc(ae: SSHClient, cfg: AELiteConfig) -> str:
    """
    Ensure a PostgreSQL JDBC jar is present on the AE host.
    Search order:
      1) Explicit cfg.jdbc_glob if it's an absolute AE path
      2) AE host common paths (/opt/automic/jdbc, /usr/share/java, AE bin/lib)
      3) DB host common paths (scp to AE:/opt/automic/jdbc)
      4) OS package (postgresql-jdbc)
    Returns the resolved jar path (AE side) or raises.
    """
    # 0) Make staging dir for JDBC
    _ensure_dirs(ae, cfg.jdbc_dest_dir, owner=ae.user)

    # 1) Exact/absolute path provided on AE?
    if cfg.jdbc_glob.startswith("/"):
        if _file_exists(ae, cfg.jdbc_glob):
            return cfg.jdbc_glob
        # also accept a directory path that contains a single jar
        candidate = _glob_one(ae, f"{cfg.jdbc_glob.rstrip('/')}/postgresql-*.jar")
        if candidate:
            return candidate

    # 2) AE host common locations
    for pat in [
        f"{cfg.jdbc_dest_dir}/postgresql-*.jar",
        "/usr/share/java/postgresql-jdbc.jar",
        "/usr/share/java/postgresql*.jar",
        f"{cfg.ae_home}/bin/lib/postgresql-*.jar",
    ]:
        hit = _glob_one(ae, pat)
        if hit:
            return hit

    # 3) Pull from DB host if available
    if cfg.db_host:
        pem_txt = _read_local(cfg.key_path)
        pem_remote = _upload_temp_pem(ae, pem_txt)
        try:
            db_candidates = [
                "/opt/automic/install/Automation.Platform/Analytics/backend/lib/ext/postgresql-*.jar",
                "/opt/automic/install/External.Resources/postgresql/postgresql-*.jar",
                "/opt/automic/install/Automation.Platform/WebInterface/lib/postgresql-*.jar",
            ]
            for src_glob in db_candidates:
                if _try_scp_jdbc_from_db(ae, cfg, pem_remote, src_glob, cfg.jdbc_dest_dir):
                    hit = _glob_one(ae, f"{cfg.jdbc_dest_dir}/postgresql-*.jar")
                    if hit:
                        return hit
        finally:
            _cleanup_temp_pem(ae, pem_remote)

    # 4) Try OS package install
    run(ae, "sudo -n dnf -y install postgresql-jdbc || sudo -n yum -y install postgresql-jdbc", check=False)
    for pat in ["/usr/share/java/postgresql-jdbc.jar", "/usr/share/java/postgresql.jar", "/usr/share/java/postgresql/postgresql.jar"]:
        hit = _glob_one(ae, pat)
        if hit:
            # Stage a copy for consistency
            sudo(ae, f"cp -f {hit} {cfg.jdbc_dest_dir}/postgresql-jdbc.jar")
            staged = f"{cfg.jdbc_dest_dir}/postgresql-jdbc.jar"
            if _file_exists(ae, staged):
                return staged

    raise RuntimeError(
        "JDBC driver not found; checked AE:/opt/automic/jdbc, AE:/usr/share/java, AE:bin/lib, "
        "copied from DB media trees, and OS package."
    )
def _write_ini_jdbc(ae: SSHClient, cfg: AELiteConfig, jdbc_path: str) -> None:
    """
    Ensure ucsrv.ini exists and has JDBC lines:
      - sqlDriver = JDBC
      - sqlDriverConnect = jdbc:postgresql://<db_host>:<db_port>/<db_name>
      - sqlDriverClasspath = <jdbc_path>
      - sqlDriverInit = -Duser.timezone=UTC
    (Non-TLS AE-lite – ports/TLS sections are intentionally omitted here.)
    """
    ini = f"{cfg.ae_home}/bin/ucsrv.ini"
    _ensure_dirs(ae, f"{cfg.ae_home}/bin", owner=ae.user)

    connect = f"jdbc:postgresql://{cfg.db_host}:{cfg.db_port}/{cfg.db_name}"
    # Create file if missing
    run(ae, f"bash -lc \"test -f {ini} || : > {ini}\"", check=False)

    # Upsert keys
    def _upsert(key: str, value: str) -> None:
        esc = value.replace("/", r"\/").replace("&", r"\&")
        run(ae, f"bash -lc \"grep -q '^{key}=' {ini} && sed -i 's/^{key}=.*/{key}={esc}/' {ini} || echo '{key}={value}' >> {ini}\"", check=False)

    _upsert("sqlDriver", "JDBC")
    _upsert("sqlDriverConnect", connect)
    _upsert("sqlDriverClasspath", jdbc_path)
    _upsert("sqlDriverInit", "-Duser.timezone=UTC")

def _start_jwp_jcp(ae: SSHClient, cfg: AELiteConfig) -> None:
    """
    Optional helper: start JWP/JCP (jar-based) without ServiceManager.
    Not called by install_ae_lite(), but kept for future use.
    """
    binp = f"{cfg.ae_home}/bin"
    sudo(ae, f"chown -R {ae.user}:{ae.user} {cfg.ae_home}",)
    run(ae, f"chmod -R a+rX {cfg.ae_home}", check=False)
    _ensure_java(ae, cfg.java_bin)

    # stop any stragglers
    run(ae, "sudo -n pkill -f 'ucsrvjp.jar' || true", check=False)

    # start using explicit java if available, else fallback to PATH/java
    java = cfg.java_bin
    java = java if run(ae, f"command -v {java}", check=False).rc == 0 else "java"
    start_jwp = f"bash -lc 'cd {binp}; nohup {java} -jar ucsrvjp.jar -I ./ucsrv.ini -S AELAB -jwp  >> ../jwp.out 2>&1 &'"
    start_jcp = f"bash -lc 'cd {binp}; nohup {java} -jar ucsrvjp.jar -I ./ucsrv.ini -S AELAB -jcp  >> ../jcp.out 2>&1 &'"

    run(ae, start_jwp, check=False)
    run(ae, start_jcp, check=False)

def install_ae_lite(cfg: AELiteConfig) -> None:
    """
    AE-lite: make the AE host ready for a real Engine install by ensuring:
      - AE folder exists (best-effort copy from DB if provided)
      - a PostgreSQL JDBC jar is present (robust discovery/copy)
      - ucsrv.ini contains JDBC lines (connect/classpath/init)
    """
    with SSHClient(cfg.host, cfg.ssh_user, cfg.key_path) as ae:
        log.info("== AE-lite on %s ==", cfg.host)

        # Ensure structure and ownership
        _ensure_dirs(ae, cfg.ae_home, f"{cfg.ae_home}/bin", owner=ae.user)

        # Try to populate AE from DB if missing (non-fatal if not found)
        _ensure_ae_present(ae, cfg)

        # Ensure JDBC (returns AE-side jar path)
        jdbc_path = _ensure_jdbc(ae, cfg)

        # Write JDBC lines to ucsrv.ini
        _write_ini_jdbc(ae, cfg, jdbc_path)

        log.info("AE-lite finished (JDBC + ini ensured; Engine media optional).")
