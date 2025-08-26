# automic_bootstrap/remote/commands.py
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Optional
import os

from .ssh import SSHClient

@dataclass
class Result:
    rc: int
    out: str
    err: str

 

def run(ssh: SSHClient, cmd: str, *, check: bool = True) -> Result:
    rc, out, err = ssh._exec(cmd)
    if check and rc != 0:
        raise RuntimeError(f"remote command failed rc={rc}: {cmd}\n{err or out}")
    return Result(rc, out, err)

def sudo(ssh: SSHClient, cmd: str, *, check: bool = True) -> Result:
    scmd = cmd if cmd.strip().startswith("sudo ") else f"sudo -n {cmd}"
    return run(ssh, scmd, check=check)


def put_text(ssh: SSHClient, content: str, remote_path: str, mode: int = 0o644) -> Result:
    # Safe heredoc (single-quoted EOF)
    echo = (
        "cat > {dst} <<'__EOF__'\n{body}\n__EOF__\n"
        "chmod {mode:o} {dst}"
    ).format(dst=remote_path, body=content, mode=mode)
    return run(ssh, echo)

def put_file(ssh: SSHClient, local_path: str | os.PathLike[str], remote_path: str, mode: Optional[int] = None) -> Result:
    # use SFTP for binary-safe upload
    assert ssh._ssh is not None, "SSH not connected"
    sftp = ssh._ssh.open_sftp()
    try:
        sftp.put(str(local_path), remote_path)
        if mode is not None:
            sftp.chmod(remote_path, mode)
    finally:
        sftp.close()
    return Result(0, "", "")

