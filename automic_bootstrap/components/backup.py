from pathlib import Path
from ..remote.ssh import ssh_exec
from paramiko import RSAKey, Transport, SFTPClient

def backup_db(db_ip: str, key_path: Path, db_name: str, out_file: str):
    remote_dump = f"/tmp/{db_name}.sql"
    rc, out, err = ssh_exec(db_ip, key_path, f"sudo -u postgres pg_dump -d {db_name} -Fp -c > {remote_dump}", sudo=True)
    if rc != 0:
        raise RuntimeError(err)
    key = RSAKey.from_private_key_file(str(key_path))
    t = Transport((db_ip, 22)); t.connect(username="ec2-user", pkey=key)
    s = SFTPClient.from_transport(t); s.get(remote_dump, out_file); s.close(); t.close()
