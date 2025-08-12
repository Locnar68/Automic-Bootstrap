# automic_bootstrap/automic_bootstrap/cli.py
from __future__ import annotations

import sys
import argparse
import logging
from pathlib import Path

# package version for --version flag
try:
    from importlib.metadata import version as _pkg_version
    __VERSION__ = _pkg_version("automic-bootstrap")
except Exception:
    __VERSION__ = "0.0.0+dev"

from .logging_setup import setup_logging
from .config import Settings, DEF_SETTINGS
from .orchestrators.stack import launch_automic_stack

# Optional imports; capture import errors for visibility
try:
    from .components.transfer import upload_automic_archive
    _TRANSFER_IMPORT_ERROR = None
except Exception as e:
    upload_automic_archive = None  # type: ignore
    _TRANSFER_IMPORT_ERROR = e

try:
    from .components.db_load import run_db_load
    _DBLOAD_IMPORT_ERROR = None
except Exception as e:
    run_db_load = None  # type: ignore
    _DBLOAD_IMPORT_ERROR = e

try:
    from .components.verify import final_verification
    _VERIFY_IMPORT_ERROR = None
except Exception as e:
    final_verification = None  # type: ignore
    _VERIFY_IMPORT_ERROR = e

try:
    from .components.backup import backup_database
    _BACKUP_IMPORT_ERROR = None
except Exception as e:
    backup_database = None  # type: ignore
    _BACKUP_IMPORT_ERROR = e


# Default archive name (no prompt; assumed present unless --automic-zip provided)
DEFAULT_ARCHIVE_NAME = "Automic.Automation_24.4.1_2025-07-25.zip"


def _common_parent() -> argparse.ArgumentParser:
    """Options shared by all commands."""
    common = argparse.ArgumentParser(add_help=False)

    # AWS
    common.add_argument("--region", default=DEF_SETTINGS.region)
    common.add_argument("--vpc-id", default=DEF_SETTINGS.vpc_id)
    common.add_argument("--sg-name", default=DEF_SETTINGS.sg_name)
    common.add_argument("--key-name", default=DEF_SETTINGS.key_name)
    common.add_argument("--key-dir", type=Path, default=DEF_SETTINGS.key_dir)

    # Node types / names
    common.add_argument("--db-name", default=DEF_SETTINGS.db_name)
    common.add_argument("--ae-name", default=DEF_SETTINGS.ae_name)
    common.add_argument("--awi-name", default=DEF_SETTINGS.awi_name)
    common.add_argument("--db-type", default=DEF_SETTINGS.db_type)
    common.add_argument("--ae-type", default=DEF_SETTINGS.ae_type)
    common.add_argument("--awi-type", default=DEF_SETTINGS.awi_type)

    # SSH / paths
    common.add_argument("--ssh-user", default=getattr(DEF_SETTINGS, "ssh_user", "ec2-user"))
    common.add_argument("--remote-install-root", default="/opt/automic/install")
    common.add_argument("--remote-utils", default="/opt/automic/utils")

    # DB creds
    common.add_argument("--db-user", default=getattr(DEF_SETTINGS, "db_user", "postgres"))
    common.add_argument("--db-sys-pass", default=DEF_SETTINGS.db_sys_pass)

    # Logging
    common.add_argument("--log-file", default="bootstrap.log")
    return common


def _build_parser() -> argparse.ArgumentParser:
    common = _common_parent()
    p = argparse.ArgumentParser(
        prog="automic-bootstrap",
        description="Automic AWS Bootstrap (provision + install AEDB, AE, AWI)",
        parents=[common],
    )
    p.add_argument("--version", action="version", version=f"automic-bootstrap {__VERSION__}")

    sub = p.add_subparsers(dest="cmd", required=True)

    # provision: infra + upload archive + AEDB load
    prov = sub.add_parser(
        "provision", parents=[common],
        help="Provision/reuse AWS infra, upload Automic archive, and load AEDB",
    )
    prov.add_argument(
        "--automic-zip", required=False, type=Path,
        help=f"Path to Automic bundle (.zip/.tar.gz). If omitted, uses ./{DEFAULT_ARCHIVE_NAME}."
    )

    # all: currently mirrors provision, future stages can be added
    allp = sub.add_parser(
        "all", parents=[common],
        help="Provision/reuse infra, upload & load AEDB, then (optionally) install AE/AWI/SM",
    )
    allp.add_argument(
        "--automic-zip", required=False, type=Path,
        help=f"Path to Automic bundle (.zip/.tar.gz). If omitted, uses ./{DEFAULT_ARCHIVE_NAME}."
    )

    # verify
    sub.add_parser(
        "verify", parents=[common],
        help="Run verification checks (logs, versions, connectivity)",
    )

    # backup-db
    sub.add_parser(
        "backup-db", parents=[common],
        help="Backup the AEDB using pg_dump",
    )

    return p
def _settings_from_args(args: argparse.Namespace) -> Settings:
    """
    Build a Settings object from DEF_SETTINGS + CLI overrides.
    Compatible with namedtuple, dataclass, Pydantic v1/v2, or plain class.
    """
    updates = dict(
        region=args.region,
        vpc_id=args.vpc_id,
        sg_name=args.sg_name,
        key_name=args.key_name,
        key_dir=Path(args.key_dir),
        db_name=args.db_name,
        ae_name=args.ae_name,
        awi_name=args.awi_name,
        db_type=args.db_type,
        ae_type=args.ae_type,
        awi_type=args.awi_type,
        db_sys_pass=args.db_sys_pass,
        log_file=args.log_file,
        ssh_user=args.ssh_user,
        remote_install_root=args.remote_install_root,
        remote_utils=args.remote_utils,
        db_user=args.db_user,
    )

    base = DEF_SETTINGS

    # 1) namedtuple-style
    if hasattr(base, "_replace"):
        return base._replace(**updates)  # type: ignore[attr-defined]

    # 2) dataclass
    try:
        import dataclasses
        if dataclasses.is_dataclass(base):
            return dataclasses.replace(base, **updates)  # type: ignore[arg-type]
    except Exception:
        pass

    # 3) Pydantic v2
    if hasattr(base, "model_copy"):
        return base.model_copy(update=updates)  # type: ignore[attr-defined]

    # 4) Pydantic v1
    if hasattr(base, "copy"):
        try:
            return base.copy(update=updates)  # type: ignore[attr-defined]
        except TypeError:
            data = base.dict()  # type: ignore[attr-defined]
            data.update(updates)
            return Settings(**data)

    # 5) Plain class with keyword constructor — rebuild from vars()
    try:
        data = {**getattr(base, "__dict__", {}), **updates}
        return Settings(**data)
    except Exception:
        # 6) Last resort: mutate a shallow clone
        import copy
        s = copy.copy(base)
        for k, v in updates.items():
            setattr(s, k, v)
        return s


def _resolve_archive_path(p: Path | None) -> Path:
    """
    No prompt. If --automic-zip not given, assume DEFAULT in CWD.
    Fail fast if the file isn't found.
    """
    def _norm(x: Path) -> Path:
        return Path(x).expanduser().resolve()

    path = _norm(p) if p else _norm(Path(DEFAULT_ARCHIVE_NAME))
    if not path.exists():
        raise FileNotFoundError(
            f"Automic archive not found: {path} "
            f"(expected {DEFAULT_ARCHIVE_NAME} in the current directory or pass --automic-zip)"
        )
    return path
def _do_provision(args: argparse.Namespace) -> int:
    settings = _settings_from_args(args)
    setup_logging(settings.log_file)
    logging.info("=== Provision start (region=%s) ===", settings.region)

    # 1) Provision/reuse infra; return connection details & key path
    try:
        pw = getattr(settings, "db_sys_pass", None) or getattr(settings, "db_password", None)
        if not pw:
            raise RuntimeError("DB password missing in Settings (expected db_sys_pass or db_password).")

        # stack must be a dict with keys: db_ip, key_path
        stack = launch_automic_stack(settings, db_user_pass=pw)
        db_ip = str(stack.get("db_ip") or "")
        key_path = Path(stack.get("key_path") or "")

        if not db_ip:
            raise RuntimeError("launch_automic_stack did not return a DB IP address")
        if not key_path:
            raise RuntimeError("launch_automic_stack did not return a key_path")

        logging.info("Provisioned: db_ip=%s, key=%s", db_ip, key_path)
    except Exception as e:
        logging.exception("Provision failed: %s", e)
        return 2

    # 2) Resolve archive path (no prompt; fail if missing), then upload & load AEDB
    if upload_automic_archive is None:
        logging.error("transfer module failed to import: %r", _TRANSFER_IMPORT_ERROR)
        return 3
    if run_db_load is None:
        logging.error("db_load module failed to import: %r", _DBLOAD_IMPORT_ERROR)
        return 5

    try:
        # archive -> remote
        archive = _resolve_archive_path(getattr(args, "automic_zip", None))
        remote_zip = upload_automic_archive(archive, db_ip, key_path)
        logging.info("Uploaded archive to %s", remote_zip)

        # determine creds & paths
        ssh_user = getattr(settings, "ssh_user", "ec2-user")
        db_user = getattr(settings, "db_user", "postgres")
        db_pass = getattr(settings, "db_sys_pass", None) or getattr(args, "db_sys_pass", None)
        if not db_pass:
            raise ValueError("Database password missing (settings.db_sys_pass or --db-sys-pass).")

        remote_install_root = getattr(settings, "remote_install_root", "/opt/automic/install")
        remote_utils = getattr(settings, "remote_utils", "/opt/automic/utils")

        # run db load
        run_db_load(
            db_host=db_ip,
            key_path=str(key_path),  # run_db_load expects a str
            db_name=getattr(settings, "db_name", "AEDB"),
            db_user=db_user,
            db_password=db_pass,
            remote_zip=remote_zip,
            ssh_user=ssh_user,
            remote_install_root=remote_install_root,
            remote_utils=remote_utils,
        )
        logging.info("AEDB load completed.")
    except Exception as e:
        logging.exception("Upload or AEDB load failed: %s", e)
        return 6

    logging.info("=== Provision complete ===")
    print(f"DB IP: {db_ip}")
    print(f"Key:   {key_path}")
    return 0


def _do_all(args: argparse.Namespace) -> int:
    rc = _do_provision(args)
    if rc != 0:
        return rc
    logging.info("[all] AE/AWI/SM stages not wired yet in this CLI build.")
    return 0


def _do_verify(args: argparse.Namespace) -> int:
    settings = _settings_from_args(args)
    setup_logging(settings.log_file)
    if final_verification is None:
        logging.error("verify module failed to import: %r", _VERIFY_IMPORT_ERROR)
        return 10
    try:
        final_verification(settings)  # type: ignore[arg-type]
        logging.info("Verification complete.")
        return 0
    except Exception as e:
        logging.exception("Verification failed: %s", e)
        return 11


def _do_backup(args: argparse.Namespace) -> int:
    settings = _settings_from_args(args)
    setup_logging(settings.log_file)
    if backup_database is None:
        logging.error("backup module failed to import: %r", _BACKUP_IMPORT_ERROR)
        return 20
    try:
        backup_database(settings)  # type: ignore[arg-type]
        logging.info("Backup complete.")
        return 0
    except Exception as e:
        logging.exception("Backup failed: %s", e)
        return 21
def main(argv: list[str] | None = None) -> int:
    if argv is None:
        argv = sys.argv[1:]
    parser = _build_parser()
    args = parser.parse_args(argv)

    # Dispatch
    if args.cmd == "provision":
        return _do_provision(args)
    if args.cmd == "all":
        return _do_all(args)
    if args.cmd == "verify":
        return _do_verify(args)
    if args.cmd == "backup-db":
        return _do_backup(args)

    parser.print_help()
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
