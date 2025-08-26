# automic_bootstrap/remote/__init__.py
"""
Remote utilities: thin wrappers around Paramiko + helpers for file/command ops.
Re-export the public API so editors/type-checkers can resolve symbols.
"""

from .ssh import SSHClient
from .commands import run, sudo, put_text, put_file

__all__ = [
    "SSHClient",
    "run",
    "sudo",
    "put_text",
    "put_file",
]
