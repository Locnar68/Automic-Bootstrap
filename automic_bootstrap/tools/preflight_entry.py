"""
Package entry point to run preflight checks from inside the CLI.

This delegates to the top-level preflight.py if present, but also provides
a fallback minimal check if that file is missing.
"""

from __future__ import annotations

import runpy
import sys
from pathlib import Path


def run_preflight() -> int:
    root = Path(__file__).resolve().parents[2]  # project root (…/automic_bootstrap/tools)
    top = root / "preflight.py"
    if top.exists():
        # Execute the standalone preflight.py as a module
        runpy.run_path(str(top), run_name="__main__")
        return 0

    # Fallback: minimal checks
    print("== Minimal Preflight (fallback) ==")
    print(f"Python: {sys.version.split()[0]}")
    try:
        import boto3  # noqa

        print("[OK] boto3 import")
    except Exception as e:  # pragma: no cover
        print(f"[WARN] boto3 import failed: {e}")
    return 0
