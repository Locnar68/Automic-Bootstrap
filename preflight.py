#!/usr/bin/env python3

import os
import subprocess
import sys
from pathlib import Path

OK = True


def check(cmd, name):
    global OK
    try:
        out = subprocess.check_output(cmd, stderr=subprocess.STDOUT, text=True)
        print(f"[OK] {name}: {out.strip().splitlines()[0]}")
    except Exception as e:
        print(f"[WARN] {name}: {e}")
        OK = False


def main():
    print("== Automic Bootstrap Preflight ==")
    print(f"Python: {sys.version.split()[0]}")
    # venv?
    if not (
        Path(".venv")
        / ("Scripts" if os.name == "nt" else "bin")
        / ("python.exe" if os.name == "nt" else "python")
    ).exists():
        print("[WARN] Virtual environment '.venv' not found. Run setup_venv.(ps1|sh).")
    else:
        print("[OK] Found virtual environment .venv")

    # AWS CLI
    check(["aws", "--version"], "AWS CLI")

    # Automic .zip present?
    zips = list(Path(".").glob("Automic*.zip"))
    if zips:
        print(f"[OK] Automic bundle: {zips[0].name}")
    else:
        print("[WARN] Automic bundle not found in project root. Place Automic*.zip here.")

    # Key path
    key = os.environ.get("AUTOMIC_KEY_PATH")
    if not key:
        print("[WARN] AUTOMIC_KEY_PATH not set. Set to your PEM/PPK path.")
    else:
        kp = Path(key)
        if kp.exists():
            print(f"[OK] Key path: {kp}")
        else:
            print(f"[WARN] AUTOMIC_KEY_PATH points to a missing file: {kp}")

    # Optional: boto3 credential check
    try:
        import boto3

        session = boto3.Session()
        ident = session.client("sts").get_caller_identity()
        print(f"[OK] AWS identity: {ident.get('Account')} / {ident.get('Arn')}")
    except Exception as e:
        print(f"[WARN] AWS credentials not verified via STS: {e}")

    print("\nPreflight complete.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
