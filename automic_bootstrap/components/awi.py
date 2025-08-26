# automic_bootstrap/components/awi.py
from __future__ import annotations

import logging
import os
import time
from dataclasses import dataclass
from pathlib import PurePosixPath as P
from typing import Optional
from urllib.parse import urlparse

from automic_bootstrap.remote import SSHClient, run, sudo, put_text, put_file

log = logging.getLogger(__name__)

@dataclass
class AWIConfig:
    # Primary target (AWI host)
    host: str                         # AWI host/IP (SSH)
    ssh_user: str = "ec2-user"
    key_path: str = "~/.ssh/automic-key.pem"

    # Paths & names on AWI host
    awi_root: str = "/opt/automic/WebInterface"
    tls_folder: str = "/opt/automic/tls/trust"
    java_bin: str = "/usr/bin/java"

    # Optional media passed explicitly (on AWI host): .zip or .tgz
    awi_media: Optional[str] = None

    # If media is already on AWI host as an expanded folder (fast path)
    awi_media_path: str = "/opt/automic/install/Automation.Platform/WebInterface"

    # Fallback source: pull from DB host if AWI has no media
    db_host: Optional[str] = None             # e.g., "54.81.41.251"
    db_ssh_user: str = "ec2-user"
    db_media_path: str = "/opt/automic/install/Automation.Platform/WebInterface"

    # Optional: AE public cert (local on operator machine) to trust
    ae_cert_local_path: str = ""      # local file; uploaded if provided
    ae_cert_remote_name: str = "ae.crt"

    # JCP endpoint (must match AE TLS CN and port)
    jcp_cn: str = "ae-host"
    jcp_port: int = 8443

    # System name shown in AWI connection picker
    system_name: str = "AELAB"

    # Health / URL
    awi_url: str = "http://127.0.0.1:8080/"

# ---------------- utilities ----------------

def _port_from_url(url: str, default: int = 8080) -> int:
    o = urlparse(url)
    if o.port:
        return int(o.port)
    if o.scheme == "https":
        return 443
    if o.scheme == "http":
        return default
    return default

def _wait_for_local_port(ssh: SSHClient, port: int, timeout_s: int = 240) -> None:
    """Wait until *any* local address is listening on TCP :port."""
    deadline = time.time() + timeout_s
    check = f"ss -ltn | awk '{{print $4}}' | egrep -q ':{port}$'"
    while time.time() < deadline:
        if run(ssh, f"bash -lc \"{check}\"", check=False).rc == 0:
            return
        time.sleep(2)
    raise RuntimeError(f"Port {port} did not open within {timeout_s}s")

def _file_exists(ssh: SSHClient, path: str) -> bool:
    return run(ssh, f"test -s {path}", check=False).rc == 0

def _dir_exists(ssh: SSHClient, path: str) -> bool:
    return run(ssh, f"test -d {path}", check=False).rc == 0

def _ensure_dirs(ssh: SSHClient, *dirs: str, owner: Optional[str] = None, mode: int = 0o755) -> None:
    sudo(ssh, " ".join(["install -d"] + [f"-m {mode:o} {d}" for d in dirs]))
    if owner:
        sudo(ssh, f"chown -R {owner}:{owner} " + " ".join(dirs))

def _read_local(path: str) -> str:
    with open(os.path.expanduser(path), "r", encoding="utf-8", errors="ignore") as f:
        return f.read()

def _which(ssh: SSHClient, prog: str) -> str:
    return run(ssh, f"bash -lc 'command -v {prog} || true'", check=False).out.strip()

def _resolve_java(ssh: SSHClient, preferred: str = "/usr/bin/java") -> str:
    # Try preferred, then PATH java, then /usr/bin/java
    for cand in [preferred, "java", "/usr/bin/java"]:
        if _which(ssh, cand):
            return _which(ssh, cand)
    return ""

def _ensure_java(ssh: SSHClient, java_bin: str) -> None:
    # accept either the given path or any java on PATH
    if run(ssh, f"{java_bin} -version", check=False).rc != 0:
        if run(ssh, "java -version", check=False).rc == 0:
            return
        # Try installs (17 then 11)
        rc = run(ssh, "sudo -n dnf -y install java-17-amazon-corretto-headless || "
                      "sudo -n dnf -y install java-17-openjdk || "
                      "sudo -n yum -y install java-17-openjdk", check=False).rc
        if rc != 0:
            run(ssh, "sudo -n apt-get update && sudo -n apt-get -y install openjdk-17-jre-headless", check=False)
        # final acceptance check: provided path OR any java on PATH
        if run(ssh, f"{java_bin} -version", check=False).rc != 0 and \
           run(ssh, "java -version", check=False).rc != 0:
            raise RuntimeError("Java not found on AWI host and automatic install failed.")
   
def _unpack_media(ssh: SSHClient, archive_path: str, awi_root: str) -> None:
    """Unpack a .zip or .tgz into AWI root."""
    _ensure_dirs(ssh, awi_root, owner=ssh.user)
    if archive_path.endswith(".zip"):
        # ensure unzip available
        run(ssh, "sudo -n dnf -y install unzip || sudo -n yum -y install unzip", check=False)
        run(ssh, f"sudo unzip -o {archive_path} -d {awi_root}", check=True)
    else:
        run(ssh, f"sudo tar -xzf {archive_path} -C {P(awi_root).parent}", check=True)  # should create awi_root/WebInterface/*
        # normalize if it created a nested WebInterface
        run(ssh, f"bash -lc \"test -d {awi_root}/WebInterface && "
                 f"mv {awi_root}/WebInterface/* {awi_root}/ && rmdir {awi_root}/WebInterface || true\"", check=False)
    sudo(ssh, f"chown -R {ssh.user}:{ssh.user} {P(awi_root).parent}")

def _pull_webinterface_from_db_to_awi(awi: SSHClient, cfg: AWIConfig) -> None:
    """
    Copy WebInterface folder from DB host to AWI host via scp, using the same PEM.
    """
    if not cfg.db_host:
        raise RuntimeError("DB host not set and AWI media not present; set AWIConfig.db_host or provide --awi-media.")

    pem_txt = _read_local(cfg.key_path)
    temp_pem = f"/home/{awi.user}/.ssh/automic-tmp.pem"
    run(awi, f"mkdir -p /home/{awi.user}/.ssh && chmod 700 /home/{awi.user}/.ssh", check=False)
    put_text(awi, pem_txt, temp_pem, mode=0o600)

    try:
        awi_parent = str(P(cfg.awi_root).parent)  # e.g., /opt/automic
        _ensure_dirs(awi, awi_parent, owner=awi.user)

        scp_cmd = (
            f"scp -i {temp_pem} -o StrictHostKeyChecking=no -r "
            f"{cfg.db_ssh_user}@{cfg.db_host}:{cfg.db_media_path} {awi_parent}/"
        )
        rc = run(awi, scp_cmd, check=False).rc
        if rc != 0:
            # retry once with permissive config
            run(awi, f"printf 'Host *\\n\\tStrictHostKeyChecking no\\n' >> /home/{awi.user}/.ssh/config", check=False)
            rc = run(awi, scp_cmd, check=False).rc
        if rc != 0:
            raise RuntimeError(
                f"Failed to scp WebInterface from {cfg.db_host}:{cfg.db_media_path} to {awi_parent} (rc={rc})."
            )

        # Normalize nested copy (…/WebInterface/WebInterface)
        run(
            awi,
            f"bash -lc \"test -s {cfg.awi_root}/aa-webui-launcher.jar || "
            f"(test -s {cfg.awi_root}/WebInterface/aa-webui-launcher.jar && "
            f"mv {cfg.awi_root}/WebInterface/* {cfg.awi_root}/ && rmdir {cfg.awi_root}/WebInterface) || true\"",
            check=False,
        )

        if not _file_exists(awi, f"{cfg.awi_root}/aa-webui-launcher.jar"):
            raise RuntimeError("After copy, aa-webui-launcher.jar not found under AWI root.")

        sudo(awi, f"chown -R {awi.user}:{awi.user} {awi_parent}")

    finally:
        run(awi, f"shred -u {temp_pem}", check=False)

def _ensure_webinterface_present(ssh: SSHClient, cfg: AWIConfig) -> None:
    """
    Ensure {awi_root} contains aa-webui-launcher.jar.
    Order:
      1) If cfg.awi_media provided (.zip/.tgz) → unpack
      2) If expanded media exists locally (cfg.awi_media_path) → copy in
      3) Else pull from DB host
    """
    _ensure_dirs(ssh, cfg.awi_root, owner=ssh.user)

    if _file_exists(ssh, f"{cfg.awi_root}/aa-webui-launcher.jar"):
        return

    # 1) Explicit archive on AWI host
    if cfg.awi_media and _file_exists(ssh, cfg.awi_media):
        _unpack_media(ssh, cfg.awi_media, cfg.awi_root)

    if _file_exists(ssh, f"{cfg.awi_root}/aa-webui-launcher.jar"):
        return

    # 2) Expanded media present locally on AWI host
    if _dir_exists(ssh, cfg.awi_media_path):
        run(ssh, f"cp -r {cfg.awi_media_path}/* {cfg.awi_root}/", check=False)

    if _file_exists(ssh, f"{cfg.awi_root}/aa-webui-launcher.jar"):
        return

    # 3) Fallback: pull from DB host
    _pull_webinterface_from_db_to_awi(ssh, cfg)

def _render_uc4_config_xml(*, trusted_cert_folder: str, system_name: str, jcp_cn: str, jcp_port: int) -> str:
    return f"""<?xml version="1.0" encoding="UTF-8"?>
<uc4_config>
  <connections trustedCertFolder="{trusted_cert_folder}">
    <connection name="AUTOMIC" system="{system_name}">
      <jcp ip="{jcp_cn}" port="{jcp_port}"/>
    </connection>
  </connections>
</uc4_config>
"""

def _push_ae_cert_if_any(ssh: SSHClient, cfg: AWIConfig) -> None:
    if not cfg.ae_cert_local_path:
        return
    local = os.path.expanduser(cfg.ae_cert_local_path)
    if not os.path.exists(local):
        raise RuntimeError(f"AE cert not found locally: {local}")
    tmp_remote = f"/tmp/{cfg.ae_cert_remote_name}"
    put_file(ssh, local, tmp_remote)
    _ensure_dirs(ssh, cfg.tls_folder, owner=ssh.user)
    sudo(ssh, f"mv {tmp_remote} {P(cfg.tls_folder) / cfg.ae_cert_remote_name}")
def _write_uc4_config(ssh: SSHClient, cfg: AWIConfig) -> None:
    xml = _render_uc4_config_xml(
        trusted_cert_folder=cfg.tls_folder,
        system_name=cfg.system_name,
        jcp_cn=cfg.jcp_cn,
        jcp_port=cfg.jcp_port,
    )
    put_text(ssh, xml, "/tmp/uc4.config.xml")
    _ensure_dirs(ssh, f"{P(cfg.awi_root) / 'config'}", owner=ssh.user)
    sudo(ssh, f"mv /tmp/uc4.config.xml {P(cfg.awi_root) / 'config/uc4.config.xml'}")

def _start_awi(ssh: "SSHClient", cfg: "AWIConfig", port: int = 8080) -> None:
    """
    Start the AWI launcher robustly:
      - stop any previous launcher (non-fatal)
      - ensure AWI dir + osgi-tmp are writable by the runtime user
      - resolve JAVA inside the same sudo shell (use cfg.java_bin if valid, else PATH, else /usr/bin/java)
      - use fully-qualified nohup
      - wait for the chosen port
    """
    # Stop any previous launcher (ignore if none)
    run(ssh, "sudo -n pkill -f 'aa-webui-launcher.jar' || true", check=False)

    log_path = f"{cfg.awi_root}/awi.out"

    # Ensure write access for caches/logs (fixes AccessDenied on osgi-tmp)
    sudo(ssh, f"mkdir -p {cfg.awi_root}/osgi-tmp")
    sudo(ssh, f"chown -R {ssh.user}:{ssh.user} {cfg.awi_root}")
    run(ssh, f"chmod -R u+rwX,g+rwX {cfg.awi_root}", check=False)

    # Resolve JAVA in the same shell; if cfg.java_bin isn't executable, fall back gracefully.
    start_cmd = (
        "sudo -n bash -lc '"
        f"cd {cfg.awi_root} && "
        # If cfg.java_bin exists and is executable, use it; else try PATH; else default.
        f"JBIN={cfg.java_bin!s}; "
        "if [ -x \"$JBIN\" ]; then JAVA=\"$JBIN\"; "
        "elif command -v java >/dev/null 2>&1; then JAVA=\"$(command -v java)\"; "
        "else JAVA=\"/usr/bin/java\"; fi; "
        "/usr/bin/nohup \"$JAVA\" -Dserver.port={port} -jar aa-webui-launcher.jar "
        f"> {log_path} 2>&1 &'"
    ).format(port=port)

    run(ssh, start_cmd, check=True)

    # Short delay, then ensure it’s up
    run(ssh, "sleep 1; pgrep -f 'aa-webui-launcher.jar' >/dev/null", check=True)
    _wait_for_local_port(ssh, port, timeout_s=240)
    
def install_awi(cfg: AWIConfig) -> None:
    """
    Idempotent AWI install/config/start:
      - ensure dirs
      - ensure Java present
      - ensure WebInterface exists on AWI host (local archive/dir; else scp from DB)
      - push AE cert (optional)
      - write uc4.config.xml with trustedCertFolder + JCP CN/port
      - start launcher and wait for port
    """
    with SSHClient(cfg.host, cfg.ssh_user, cfg.key_path) as ssh:
        log.info("== AWI install on %s ==", cfg.host)

        # Ensure base dirs
        _ensure_dirs(ssh, cfg.awi_root, cfg.tls_folder, owner=ssh.user)

        # Java (install if needed)
        _ensure_java(ssh, cfg.java_bin)

        # Acquire/ensure media
        _ensure_webinterface_present(ssh, cfg)

        # Optional trust, then config
        _push_ae_cert_if_any(ssh, cfg)
        _write_uc4_config(ssh, cfg)

        # Start + wait
        _start_awi(ssh, cfg)

        log.info("AWI started. If remote, browse: %s", cfg.awi_url)
