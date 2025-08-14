# automic_bootstrap/automic_bootstrap/components/transfer.py
import logging
from pathlib import Path

import paramiko

log = logging.getLogger(__name__)


def _run(ssh: paramiko.SSHClient, cmd: str) -> None:
    stdin, stdout, stderr = ssh.exec_command(cmd)
    rc = stdout.channel.recv_exit_status()
    if rc != 0:
        err = stderr.read().decode("utf-8", "ignore")
        out = stdout.read().decode("utf-8", "ignore")
        raise RuntimeError(
            f"Remote command failed (rc={rc}): {cmd}\nSTDOUT:\n{out}\nSTDERR:\n{err}"
        )


def upload_automic_archive(
    local_zip: Path,
    host,
    key_path: Path,
    *,
    username: str = "ec2-user",
    remote_dir: str = "/opt/automic/install",
) -> str:
    """
    Upload the Automic bundle to the remote host and return the remote path.
    """
    # Normalize / validate
    local_zip = Path(local_zip).expanduser().resolve()
    key_path = Path(key_path).expanduser().resolve()
    host = "" if host is None else str(host)

    if not host:
        raise ValueError("upload_automic_archive: host is empty")
    if not local_zip.exists():
        raise FileNotFoundError(f"Local archive not found: {local_zip}")
    if not key_path.exists():
        raise FileNotFoundError(f"PEM not found: {key_path}")

    # Connect
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    log.info("Connecting to %s as %s with key %s", host, username, key_path)
    ssh.connect(hostname=host, username=username, key_filename=str(key_path), timeout=30)

    # Prepare remote directory under /opt (needs sudo), then hand ownership to ec2-user
    _run(ssh, f"sudo mkdir -p {remote_dir} && sudo chown {username}:{username} {remote_dir}")

    # Upload via SFTP
    sftp = ssh.open_sftp()
    remote_path = f"{remote_dir}/{local_zip.name}"
    log.info("Uploading %s -> %s:%s", local_zip, host, remote_path)
    sftp.put(str(local_zip), remote_path)
    sftp.close()

    ssh.close()
    log.info("Upload complete: %s", remote_path)
    return remote_path
