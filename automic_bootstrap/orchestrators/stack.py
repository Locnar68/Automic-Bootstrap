# automic_bootstrap/automic_bootstrap/orchestrators/stack.py
import logging
import os
import stat
import time
from pathlib import Path
from typing import Any

import boto3
import botocore
import paramiko

from ..aws.ec2 import (
    ensure_security_group,
    ensure_vpc,
    get_instance_ip,
    get_latest_ami,
    launch_ec2_instance,
    wait_for_instances,
)
from ..config import Settings

log = logging.getLogger(__name__)


def _render_postgres_user_data(db_pass: str) -> str:
    return r"""#!/bin/bash -xe
exec > >(tee /var/log/db-user-data.log | logger -t user-data -s 2>/dev/console) 2>&1
dnf update -y
dnf install -y postgresql16 postgresql16-server
mkdir -p /etc/systemd/system/postgresql@16.service.d
cat <<EOF > /etc/systemd/system/postgresql@16.service.d/override.conf
[Service]
Environment=PGDATA=/var/lib/pgsql/16/data
EOF
sudo -u postgres /usr/bin/initdb --pgdata=/var/lib/pgsql/16/data || true
systemctl daemon-reload
systemctl enable --now postgresql@16 || systemctl enable --now postgresql-16
sudo -u postgres psql -c "ALTER USER postgres WITH PASSWORD '{db_pass}';" || true
echo "host all all 0.0.0.0/0 md5" >> /var/lib/pgsql/16/data/pg_hba.conf
echo "listen_addresses='*'" >> /var/lib/pgsql/16/data/postgresql.conf
systemctl restart postgresql@16 || systemctl restart postgresql-16
""".replace("{db_pass}", db_pass)


def _render_java_node_user_data() -> str:
    return r"""#!/bin/bash -xe
exec > >(tee /var/log/java-user-data.log | logger -t user-data -s 2>/dev/console) 2>&1
dnf update -y
dnf install -y java-17-amazon-corretto unzip
JAVA_HOME=$(dirname $(dirname $(readlink -f $(which java))))
echo "export JAVA_HOME=$JAVA_HOME" > /etc/profile.d/java.sh
echo "export PATH=\$JAVA_HOME/bin:\$PATH" >> /etc/profile.d/java.sh
chmod +x /etc/profile.d/java.sh
mkdir -p /opt/automic/install
chown ec2-user:ec2-user /opt/automic/install
"""


def _safe_unlink(p: Path) -> None:
    try:
        os.remove(p)
        log.info("Removed local PEM: %s", p)
    except FileNotFoundError:
        log.debug("Local PEM not found (ok): %s", p)


def _recreate_keypair(ec2_client, key_name: str, key_dir: Path) -> Path:
    """
    Delete AWS keypair + local PEM if they exist, then create a fresh pair.
    Returns the PEM path.
    """
    # Delete AWS keypair if present
    try:
        ec2_client.delete_key_pair(KeyName=key_name)
        log.info("Deleted existing AWS key pair: %s", key_name)
    except botocore.exceptions.ClientError as e:
        if e.response.get("Error", {}).get("Code") == "InvalidKeyPair.NotFound":
            log.debug("AWS key pair did not exist (ok): %s", key_name)
        else:
            raise

    # Delete local PEM if present (quiet)
    key_dir = Path(key_dir).expanduser().resolve()
    key_dir.mkdir(parents=True, exist_ok=True)
    pem_path = key_dir / f"{key_name}.pem"
    _safe_unlink(pem_path)

    # Create new keypair + write PEM
    resp = ec2_client.create_key_pair(KeyName=key_name)
    pem_path.write_text(resp["KeyMaterial"], encoding="utf-8")

    # Tighten perms on non-Windows
    try:
        os.chmod(pem_path, stat.S_IRUSR | stat.S_IWUSR)  # 0o600
    except Exception:
        pass

    log.info("Created new keypair + PEM: %s", pem_path)
    return pem_path


def wait_for_ssh_ready(ip: str, key_path: Path, timeout: int = 300) -> None:
    start = time.time()
    last_err: Exception | None = None
    while time.time() - start < timeout:
        try:
            key = paramiko.RSAKey.from_private_key_file(str(key_path))
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect(ip, username="ec2-user", pkey=key, timeout=10)
            ssh.close()
            return
        except Exception as e:
            last_err = e
            time.sleep(5)
    raise TimeoutError(f"SSH not ready on {ip} after {timeout}s; last error: {last_err}")


def launch_automic_stack(cfg: Settings, db_user_pass: str) -> dict[str, Any]:
    """
    Provisions VPC/SG, recreates keypair+PEM idempotently, launches DB/AE/AWI,
    waits for instances + SSH, and returns a dict used by the CLI.
    """
    ec2 = boto3.client("ec2", region_name=cfg.region)

    vpc_id = ensure_vpc(ec2, cfg.vpc_id)
    sg_id = ensure_security_group(ec2, vpc_id, cfg.sg_name)

    # Fresh keypair + PEM (quiet if previously missing)
    key_path = _recreate_keypair(ec2, cfg.key_name, cfg.key_dir)
    print("Key created. Waiting for servers to initialize...")

    ami = get_latest_ami(cfg.region)

    db_ud = _render_postgres_user_data(db_user_pass)
    ae_ud = _render_java_node_user_data()
    awi_ud = _render_java_node_user_data()

    db_id = launch_ec2_instance(ec2, cfg.db_name, cfg.db_type, cfg.key_name, sg_id, ami, db_ud)
    ae_id = launch_ec2_instance(ec2, cfg.ae_name, cfg.ae_type, cfg.key_name, sg_id, ami, ae_ud)
    awi_id = launch_ec2_instance(ec2, cfg.awi_name, cfg.awi_type, cfg.key_name, sg_id, ami, awi_ud)

    wait_for_instances(ec2, [db_id, ae_id, awi_id])

    db_ip = get_instance_ip(ec2, db_id)
    ae_ip = get_instance_ip(ec2, ae_id)
    awi_ip = get_instance_ip(ec2, awi_id)

    wait_for_ssh_ready(db_ip, key_path)
    wait_for_ssh_ready(ae_ip, key_path)
    wait_for_ssh_ready(awi_ip, key_path)

    return {
        "db_ip": db_ip,
        "ae_ip": ae_ip,
        "awi_ip": awi_ip,
        "key_path": key_path,
    }
