# automic_bootstrap/cli.py
from __future__ import annotations

import argparse
import inspect
import logging
import sys
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, cast
from dataclasses import dataclass

# ---------------- version ----------------
try:
    from importlib.metadata import version as _pkg_version
    __VERSION__ = _pkg_version("automic-bootstrap")
except Exception:
    __VERSION__ = "0.0.0+dev"

# ---------------- optional config ----------------
try:
    # Real config, if present
    from .config import DEF_SETTINGS as _DEF_SETTINGS, Settings as ConfigSettings  # type: ignore[attr-defined]
except Exception:
    # Minimal fallback so CLI still runs (same public name: ConfigSettings)
    @dataclass
    class ConfigSettings:
        region: str = "us-east-1"
        vpc_id: str = ""
        sg_name: str = "automic-sg"
        key_name: str = "automic-key"
        key_dir: Path = Path(".")
        db_name: str = "AEDB"
        ae_name: str = "AE"
        awi_name: str = "AWI"
        db_type: str = "t3.micro"
        ae_type: str = "t3.medium"
        awi_type: str = "t3.medium"
        db_sys_pass: str = "postgres"
        ssh_user: str = "ec2-user"
        remote_install_root: str = "/opt/automic/install"
        remote_utils: str = "/opt/automic/utils"
        db_user: str = "postgres"
        log_file: str = "bootstrap.log"

    _DEF_SETTINGS = ConfigSettings()

# single canonical DEF_SETTINGS instance with stable type
DEF_SETTINGS: ConfigSettings = cast(ConfigSettings, _DEF_SETTINGS)

DEFAULT_ARCHIVE_NAME = "Automic.Automation_24.4.1_2025-07-25.zip"
# ---------------- logging (robust wrapper) ----------------
try:
    from .logging_setup import setup_logging as _external_setup_logging  # type: ignore[attr-defined]
except Exception:
    _external_setup_logging = None  # type: ignore[assignment]

def init_logging(verbosity: int = 1, log_file: str = "bootstrap.log") -> None:
    """
    Robust logging initializer:
      - If package provides logging_setup.setup_logging(verbosity, log_file), use it.
      - If it only supports (log_file), fall back gracefully.
      - If missing entirely, set up a simple basicConfig.
    """
    try:
        if _external_setup_logging is not None:
            sig = inspect.signature(_external_setup_logging)
            params = list(sig.parameters.values())
            if len(params) >= 2:
                _external_setup_logging(verbosity=verbosity, log_file=log_file)  # type: ignore[call-arg]
                return
            else:
                _external_setup_logging(log_file)  # type: ignore[misc]
                return
    except Exception:
        pass

    level = logging.INFO if int(verbosity) <= 1 else logging.DEBUG
    fmt = "%(asctime)s [%(levelname)s] %(message)s"
    datefmt = "%H:%M:%S"
    logging.basicConfig(level=level, format=fmt, datefmt=datefmt)

# ---------------- optional orchestrators/components ----------------
try:
    from .orchestrators.stack import launch_automic_stack  # type: ignore[attr-defined]
except Exception:
    launch_automic_stack = None  # type: ignore[assignment]

_TRANSFER_IMPORT_ERROR: Optional[Exception] = None
try:
    from .components.transfer import upload_automic_archive  # type: ignore[attr-defined]
except Exception as e:
    upload_automic_archive = None  # type: ignore[assignment]
    _TRANSFER_IMPORT_ERROR = e

_DBLOAD_IMPORT_ERROR: Optional[Exception] = None
try:
    from .components.db_load import run_db_load  # type: ignore[attr-defined]
except Exception as e:
    run_db_load = None  # type: ignore[assignment]
    _DBLOAD_IMPORT_ERROR = e

_VERIFY_IMPORT_ERROR: Optional[Exception] = None
try:
    from .components.verify import final_verification  # type: ignore[attr-defined]
except Exception as e:
    final_verification = None  # type: ignore[assignment]
    _VERIFY_IMPORT_ERROR = e

_BACKUP_IMPORT_ERROR: Optional[Exception] = None
try:
    from .components.backup import backup_database  # type: ignore[attr-defined]
except Exception as e:
    backup_database = None  # type: ignore[assignment]
    _BACKUP_IMPORT_ERROR = e
# ---------------- tiny SSH + psql helpers (for verify-db) ----------------
def _ssh_exec(host: str, user: str, key_path: Path, cmd: str, timeout: int = 30):
    import paramiko, shlex
    c = paramiko.SSHClient()
    c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    key = paramiko.RSAKey.from_private_key_file(str(key_path))
    c.connect(hostname=host, username=user, pkey=key, timeout=timeout, banner_timeout=timeout, auth_timeout=timeout)
    try:
        full = f"/bin/bash -lc {shlex.quote(cmd)}"
        stdin, stdout, stderr = c.exec_command(full)
        rc = stdout.channel.recv_exit_status()
        out = stdout.read().decode("utf-8", "ignore")
        err = stderr.read().decode("utf-8", "ignore")
        return rc, out, err
    finally:
        c.close()

def _psql_ok(host: str, user: str, key: Path, sql: str, db: str = "postgres"):
    import shlex
    cmd = f"sudo -u postgres psql -d {shlex.quote(db)} -Atqc {shlex.quote(sql)}"
    return _ssh_exec(host, user, key, cmd)

# ---------------- parser builders ----------------
def _common_parent() -> argparse.ArgumentParser:
    common = argparse.ArgumentParser(add_help=False)

    # AWS-ish/global
    common.add_argument("--region", default=DEF_SETTINGS.region)

    # Reused infra flags
    common.add_argument("--vpc-id", default=getattr(DEF_SETTINGS, "vpc_id", ""))
    common.add_argument("--sg-name", default=getattr(DEF_SETTINGS, "sg_name", "automic-sg"))
    common.add_argument("--key-name", default=getattr(DEF_SETTINGS, "key_name", "automic-key"))
    common.add_argument("--key-dir", type=Path, default=getattr(DEF_SETTINGS, "key_dir", Path(".")))

    # Node names / types
    common.add_argument("--db-name", default=getattr(DEF_SETTINGS, "db_name", "AEDB"))
    common.add_argument("--ae-name", default=getattr(DEF_SETTINGS, "ae_name", "AE"))
    common.add_argument("--awi-name", default=getattr(DEF_SETTINGS, "awi_name", "AWI"))
    common.add_argument("--db-type", default=getattr(DEF_SETTINGS, "db_type", "t3.micro"))
    common.add_argument("--ae-type", default=getattr(DEF_SETTINGS, "ae_type", "t3.medium"))
    common.add_argument("--awi-type", default=getattr(DEF_SETTINGS, "awi_type", "t3.medium"))

    # SSH / remote paths
    common.add_argument("--ssh-user", default=getattr(DEF_SETTINGS, "ssh_user", "ec2-user"))
    common.add_argument("--remote-install-root", default=getattr(DEF_SETTINGS, "remote_install_root", "/opt/automic/install"))
    common.add_argument("--remote-utils", default=getattr(DEF_SETTINGS, "remote_utils", "/opt/automic/utils"))

    # DB creds (for “provision” flow)
    common.add_argument("--db-user", default=getattr(DEF_SETTINGS, "db_user", "postgres"))
    common.add_argument("--db-sys-pass", default=getattr(DEF_SETTINGS, "db_sys_pass", "postgres"))

    # Logging
    common.add_argument("--log-file", default=getattr(DEF_SETTINGS, "log_file", "bootstrap.log"))
    return common


def _build_parser() -> argparse.ArgumentParser:
    common = _common_parent()
    p = argparse.ArgumentParser(
        prog="automic-bootstrap",
        description="Automic AWS Bootstrap (provision + install AEDB, AE, AWI) — plus standalone DB helpers",
        parents=[common],
    )
    p.add_argument("--version", action="version", version=f"automic-bootstrap {__VERSION__}")

    sub = p.add_subparsers(dest="cmd", required=True)

    # ---- big commands ----
    prov = sub.add_parser("provision", parents=[common],
                          help="Provision/reuse AWS infra, upload archive, load AEDB")
    prov.add_argument("--automic-zip", required=False, type=Path,
                      help=f"Path to Automic bundle (.zip/.tar.gz). Default ./{DEFAULT_ARCHIVE_NAME} if omitted.")

    allp = sub.add_parser("all", parents=[common],
                          help="Provision/reuse + load AEDB; placeholder for AE/AWI stages")
    allp.add_argument("--automic-zip", required=False, type=Path,
                      help=f"Path to Automic bundle (.zip/.tar.gz). Default ./{DEFAULT_ARCHIVE_NAME} if omitted.")

    sub.add_parser("verify", parents=[common], help="Run environment verification (logs, versions, connectivity)")
    sub.add_parser("backup-db", parents=[common], help="Backup the AEDB using pg_dump")

    deprov = sub.add_parser("deprovision", parents=[common],
                            help="Tear down AWS resources created by provision")
    deprov.add_argument("--name-prefix", action="append",
                        default=["automic-", "AEDB", "AE", "AWI"],
                        help="Instance Name tag prefixes to match (repeatable). Default: %(default)r")

    # ---- focused DB helpers ----
    inst = sub.add_parser("install-db", parents=[common],
                          help="Install/initialize AEDB schema on an existing host")
    inst.add_argument("--db-host", required=True)
    inst.add_argument("--key-path", required=True, type=Path)
    inst.add_argument("--remote-zip", default=None)
    inst.add_argument("--with-tablespaces", action="store_true")
    inst.add_argument("--ts-data-name", default="ae_data")
    inst.add_argument("--ts-index-name", default="ae_index")
    inst.add_argument("--ts-data-path", default="/var/lib/pgsql/ae_data")
    inst.add_argument("--ts-index-path", default="/var/lib/pgsql/ae_index")
    inst.add_argument("--ilm-enabled", type=int, default=0)
    inst.add_argument("--verbosity", type=int, default=1)
    inst.add_argument("--app-user", default="aauser")
    inst.add_argument("--app-pass", default="Automic123")

    ver = sub.add_parser("verify-db", parents=[common],
                         help="Quick AEDB check: version + required extensions")
    ver.add_argument("--db-host", required=True)
    ver.add_argument("--key-path", required=True, type=Path)
    # NOTE: do NOT add --db-name here; it already comes from `common`

    return p
def _settings_from_args(args: argparse.Namespace) -> ConfigSettings:
    updates: Dict[str, Any] = dict(
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

    # namedtuple-like
    if hasattr(base, "_replace"):
        return base._replace(**updates)  # type: ignore[attr-defined]

    # dataclass
    try:
        import dataclasses
        if dataclasses.is_dataclass(base):
            return dataclasses.replace(base, **updates)  # type: ignore[arg-type]
    except Exception:
        pass

    # Pydantic v2
    if hasattr(base, "model_copy"):
        return base.model_copy(update=updates)  # type: ignore[attr-defined]

    # Pydantic v1
    if hasattr(base, "copy"):
        try:
            return base.copy(update=updates)  # type: ignore[attr-defined]
        except TypeError:
            data = base.dict()  # type: ignore[attr-defined]
            data.update(updates)
            return ConfigSettings(**data)  # type: ignore[arg-type]

    # Plain class
    try:
        data = {**getattr(base, "__dict__", {}), **updates}
        return ConfigSettings(**data)  # type: ignore[arg-type]
    except Exception:
        import copy
        s = copy.copy(base)
        for k, v in updates.items():
            setattr(s, k, v)
        return cast(ConfigSettings, s)


def _resolve_archive_path(p: Path | None) -> Path:
    def _norm(x: Path) -> Path:
        return Path(x).expanduser().resolve()
    path = _norm(p) if p else _norm(Path(DEFAULT_ARCHIVE_NAME))
    if not path.exists():
        raise FileNotFoundError(
            f"Automic archive not found: {path} "
            f"(expected {DEFAULT_ARCHIVE_NAME} in the current directory or pass --automic-zip)"
        )
    return path


def _call_run_db_load_with_any_signature(**cli_kwargs) -> None:
    """Call components.db_load.run_db_load with only the kwargs it accepts."""
    if run_db_load is None:
        raise RuntimeError(f"db_load module failed to import: {_DBLOAD_IMPORT_ERROR!r}")
    sig = inspect.signature(run_db_load)
    allowed = {k: v for k, v in cli_kwargs.items() if k in sig.parameters}
    return run_db_load(**allowed)  # type: ignore[misc]
# ---------------- big commands ----------------
def _do_provision(args: argparse.Namespace) -> int:
    settings = _settings_from_args(args)
    init_logging(verbosity=1, log_file=settings.log_file)
    logging.info("=== Provision start (region=%s) ===", settings.region)

    if launch_automic_stack is None:
        logging.error("orchestrator not available in this build")
        return 2

    # 1) Launch/reuse infra
    try:
        pw = getattr(settings, "db_sys_pass", None) or getattr(settings, "db_password", None)
        if not pw:
            raise RuntimeError("DB password missing in Settings (db_sys_pass or db_password).")

        raw = launch_automic_stack(settings, db_user_pass=pw)  # type: ignore[arg-type]
        if raw is None:
            raise RuntimeError("launch_automic_stack returned None")

        if not isinstance(raw, Mapping):
            raise RuntimeError("launch_automic_stack did not return a Mapping[str, Any]")

        stack: Mapping[str, Any] = cast(Mapping[str, Any], raw)
        db_ip_val: Any = stack.get("db_ip")
        key_path_val: Any = stack.get("key_path")

        if not isinstance(db_ip_val, str) or not db_ip_val:
            raise RuntimeError("launch_automic_stack did not return a valid 'db_ip'")
        if not isinstance(key_path_val, (str, Path)):
            raise RuntimeError("launch_automic_stack did not return a valid 'key_path'")

        db_ip = db_ip_val
        key_path = Path(key_path_val)

        logging.info("Provisioned: db_ip=%s, key=%s", db_ip, key_path)
    except Exception as e:
        logging.exception("Provision failed: %s", e)
        return 2

    # 2) Upload archive + run DB load
    if upload_automic_archive is None:
        logging.error("transfer module failed to import: %r", _TRANSFER_IMPORT_ERROR)
        return 3

    try:
        archive = _resolve_archive_path(getattr(args, "automic_zip", None))
        remote_zip = upload_automic_archive(archive, db_ip, key_path)  # type: ignore[arg-type]
        logging.info("Uploaded archive to %s", remote_zip)

        _call_run_db_load_with_any_signature(
            db_host=db_ip,
            key_path=str(key_path),
            ssh_user=getattr(settings, "ssh_user", "ec2-user"),
            db_name=getattr(settings, "db_name", "AEDB"),
            app_user="aauser",
            app_pass="Automic123",
            remote_zip=str(remote_zip),
            remote_install_root=getattr(settings, "remote_install_root", "/opt/automic/install"),
            remote_utils=getattr(settings, "remote_utils", "/opt/automic/utils"),
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


def _do_deprovision(args: argparse.Namespace) -> int:
    """
    Tear down AWS resources created by the 'provision' flow.
    """
    # Lazy import keeps CLI usable without AWS libs
    try:
        import boto3
        try:
            from botocore.exceptions import ClientError  # type: ignore
        except Exception:
            class ClientError(Exception):  # fallback for type-checkers if botocore is missing
                ...
    except Exception as e:
        logging.exception("boto3/botocore are required for deprovision: %s", e)
        return 1

    import time

    settings = _settings_from_args(args)
    init_logging(verbosity=1, log_file=settings.log_file)
    logging.info("=== Deprovision start (region=%s) ===", settings.region)

    ec2 = boto3.client("ec2", region_name=settings.region)
    name_prefixes: List[str] = getattr(args, "name_prefix", None) or ["automic-", "AEDB", "AE", "AWI"]

    def _list_instances_to_terminate() -> List[str]:
        ids: List[str] = []
        paginator = ec2.get_paginator("describe_instances")
        for page in paginator.paginate(
            Filters=[{"Name": "instance-state-name",
                      "Values": ["pending", "running", "stopping", "stopped"]}]
        ):
            for res in page.get("Reservations", []) or []:
                for inst in res.get("Instances", []) or []:
                    name = None
                    for tag in inst.get("Tags", []) or []:
                        if tag.get("Key") == "Name":
                            name = str(tag.get("Value") or "")
                            break
                    if name and any(name.startswith(p) for p in name_prefixes):
                        ids.append(inst["InstanceId"])
        return ids

    def _terminate(ids: List[str]) -> None:
        if not ids:
            logging.info("No matching EC2 instances to terminate.")
            return
        logging.info("Terminating instances: %s", ids)
        try:
            ec2.terminate_instances(InstanceIds=ids)
        except ClientError as e:
            logging.warning("terminate_instances error: %s", e)
        try:
            waiter = ec2.get_waiter("instance_terminated")
            waiter.wait(InstanceIds=ids)
            logging.info("Instance termination complete.")
        except ClientError as e:
            logging.warning("Wait for termination failed (continuing): %s", e)

    def _delete_security_group(name: str, vpc_id: Optional[str]) -> None:
        filters = [{"Name": "group-name", "Values": [name]}]
        if vpc_id:
            filters.append({"Name": "vpc-id", "Values": [vpc_id]})
        try:
            resp = ec2.describe_security_groups(Filters=filters)
        except ClientError as e:
            logging.warning("describe_security_groups failed: %s", e)
            return

        groups = resp.get("SecurityGroups", []) or []
        if not groups:
            logging.info("Security group '%s' not found.", name)
            return

        sg_id = groups[0].get("GroupId")
        if not sg_id:
            logging.info("Security group '%s' has no GroupId (skipping).", name)
            return

        logging.info("Deleting security group '%s' (id=%s)...", name, sg_id)
        try:
            ec2.delete_security_group(GroupId=sg_id)
            logging.info("Security group deleted.")
        except ClientError as e:
            msg = str(e)
            logging.warning("Initial SG delete failed: %s", msg)
            if "DependencyViolation" in msg:
                logging.info("Retrying SG delete after short delay...")
                time.sleep(10)
                try:
                    ec2.delete_security_group(GroupId=sg_id)
                    logging.info("Security group deleted after retry.")
                except ClientError as e2:
                    logging.warning("Retry delete failed: %s", e2)

    def _delete_key_pair(key_name: str, pem_dir: Path) -> None:
        try:
            ec2.delete_key_pair(KeyName=key_name)
            logging.info("AWS key pair '%s' deleted.", key_name)
        except ClientError as e:
            logging.warning("Could not delete AWS key pair '%s': %s", key_name, e)

        pem_path = pem_dir / f"{key_name}.pem"
        try:
            if pem_path.exists():
                pem_path.unlink()
                logging.info("Local PEM deleted at %s.", pem_path)
            else:
                logging.info("Local PEM not found at %s (already removed).", pem_path)
        except Exception as e:
            logging.warning("Failed to delete local PEM %s: %s", pem_path, e)

    try:
        ids = _list_instances_to_terminate()
        _terminate(ids)
        _delete_security_group(settings.sg_name, getattr(settings, "vpc_id", None))
        _delete_key_pair(settings.key_name, Path(settings.key_dir))
        logging.info("=== Deprovision complete ===")
        return 0
    except Exception as e:
        logging.exception("Deprovision failed: %s", e)
        return 1


def _do_verify(args: argparse.Namespace) -> int:
    settings = _settings_from_args(args)
    init_logging(verbosity=1, log_file=settings.log_file)
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
    init_logging(verbosity=1, log_file=settings.log_file)
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
# ---------------- focused DB command handlers ----------------
def _do_install_db(args: argparse.Namespace) -> int:
    init_logging(verbosity=int(getattr(args, "verbosity", 1)), log_file=getattr(args, "log_file", "bootstrap.log"))
    try:
        _call_run_db_load_with_any_signature(
            db_host=args.db_host,
            key_path=str(args.key_path),
            ssh_user=args.ssh_user,
            db_name=args.db_name,
            app_user=args.app_user,
            app_pass=args.app_pass,
            remote_zip=args.remote_zip,
            remote_install_root=args.remote_install_root,
            remote_utils=args.remote_utils,
            with_tablespaces=args.with_tablespaces,
            ts_data_name=args.ts_data_name,
            ts_index_name=args.ts_index_name,
            ts_data_path=args.ts_data_path,
            ts_index_path=args.ts_index_path,
            ilm_enabled=args.ilm_enabled,
            verbosity=args.verbosity,
        )
        return 0
    except Exception as e:
        logging.exception("install-db failed: %s", e)
        return 1


def _do_verify_db(args: argparse.Namespace) -> int:
    init_logging(verbosity=int(getattr(args, "verbosity", 1)), log_file=getattr(args, "log_file", "bootstrap.log"))
    try:
        host, user, key = args.db_host, args.ssh_user, args.key_path

        # Version
        rc, out, err = _psql_ok(host, user, key, "select version();")
        if rc != 0:
            raise RuntimeError(err or out)
        version = out.strip()

        # Extensions
        rc, out, _ = _psql_ok(
            host, user, key,
            "select extname from pg_extension where extname in ('pgcrypto','uuid-ossp') order by 1;",
            db=args.db_name,
        )
        have = {ln.strip() for ln in out.splitlines() if ln.strip()}

        print("== AEDB check ==")
        print(f"- version: {version}")
        print(f"- pgcrypto installed: {'yes' if 'pgcrypto' in have else 'no'}")
        print(f"- uuid-ossp installed: {'yes' if 'uuid-ossp' in have else 'no'}")
        return 0
    except Exception as e:
        logging.exception("verify-db failed: %s", e)
        return 1


def main(argv: Optional[List[str]] = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    parser = _build_parser()
    if not argv:
        parser.print_help()
        return 2
    args = parser.parse_args(argv)

    dispatch = {
        "provision": _do_provision,
        "all": _do_all,
        "verify": _do_verify,
        "backup-db": _do_backup,
        "deprovision": _do_deprovision,
        "install-db": _do_install_db,
        "verify-db": _do_verify_db,
    }

    cmd_val = getattr(args, "cmd", None)
    if not isinstance(cmd_val, str):  # ensures type is str (not Optional[str])
        parser.print_help()
        return 2

    func = dispatch.get(cmd_val)  # now the key is definitely a str
    if func is None:
        parser.print_help()
        return 2

    return func(args)


if __name__ == "__main__":
    raise SystemExit(main())
