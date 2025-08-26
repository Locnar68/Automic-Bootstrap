# automic_bootstrap/remote/ssh.py
from __future__ import annotations

from dataclasses import dataclass
import paramiko

@dataclass
class SSHClient:
    host: str
    user: str
    key_path: str
    timeout: int = 60

    def __post_init__(self) -> None:
        self._ssh: paramiko.SSHClient | None = None

    # Context manager
    def __enter__(self) -> "SSHClient":
        key = None
        # try RSA, fallback to Ed25519
        try:
            key = paramiko.RSAKey.from_private_key_file(self.key_path)
        except Exception:
            key = paramiko.Ed25519Key.from_private_key_file(self.key_path)
        cli = paramiko.SSHClient()
        cli.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        cli.connect(
            hostname=self.host,
            username=self.user,
            pkey=key,
            timeout=self.timeout,
            banner_timeout=self.timeout,
            auth_timeout=self.timeout,
        )
        self._ssh = cli
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        try:
            if self._ssh is not None:
                self._ssh.close()
        finally:
            self._ssh = None

    # internal: run a command
    def _exec(self, cmd: str):
        assert self._ssh is not None, "SSH not connected"
        stdin, stdout, stderr = self._ssh.exec_command(f"/bin/bash -lc '{cmd}'")
        rc = stdout.channel.recv_exit_status()
        out = stdout.read().decode("utf-8", "ignore")
        err = stderr.read().decode("utf-8", "ignore")
        return rc, out, err
