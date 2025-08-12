import logging
from pathlib import Path
from ..remote.ssh import ssh_exec
from ..remote.sftp import sftp_put

def install_service_manager(ae_ip: str, key_path: Path, sm_tar: Path | None = None) -> None:
    if not sm_tar:
        logging.info("SM tar not provided; skipping Service Manager install.")
        return
    remote_tar = "/home/ec2-user/ucsmgrlx6.tar.gz"
    sftp_put(ae_ip, key_path, sm_tar, remote_tar)
    script = r"""bash -lc '
set -e
mkdir -p /opt/automic/ServiceManager
chown -R ec2-user:ec2-user /opt/automic/ServiceManager
tar -xzvf /home/ec2-user/ucsmgrlx6.tar.gz -C /opt/automic/ServiceManager
SM_DIR=$(find /opt/automic/ServiceManager -mindepth 1 -maxdepth 1 -type d | head -n1)
sed -i "s|^connect.server=.*|connect.server=127.0.0.1;rpc/uc4|" "$SM_DIR/config/ucylbsmgr.ini"
cd "$SM_DIR/bin" && nohup ./ucybsmgr -i db -customer Automic > sm.log 2>&1 &
'"""
    rc, out, err = ssh_exec(ae_ip, key_path, script, sudo=True)
    if rc != 0:
        raise RuntimeError(err)
