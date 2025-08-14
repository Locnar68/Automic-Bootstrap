from pathlib import Path

import paramiko


def sftp_put(host: str, key_path, local_path: Path, remote_path: str, username: str = "ec2-user"):
    key = paramiko.RSAKey.from_private_key_file(str(key_path))
    transport = paramiko.Transport((host, 22))
    transport.connect(username=username, pkey=key)
    try:
        sftp = paramiko.SFTPClient.from_transport(transport)
        sftp.put(str(local_path), remote_path)
        sftp.close()
    finally:
        transport.close()
