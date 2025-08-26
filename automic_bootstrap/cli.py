# automic_bootstrap/cli.py
from __future__ import annotations

import argparse
import inspect
import logging
import sys
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Tuple, cast
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
            if len(sig.parameters) >= 2:
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

# ---------------- orchestrators/components ----------------
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

_AWI_IMPORT_ERROR: Optional[Exception] = None
try:
    from .components.awi import AWIConfig, install_awi  # type: ignore[attr-defined]
except Exception as e:
    AWIConfig = None  # type: ignore
    install_awi = None  # type: ignore
    _AWI_IMPORT_ERROR = e

_VERIFY_IMPORT_ERROR: Optional[Exception] = None
try:
    from .components.verify import (
        VerifyTargets,
        VerifySettings,
        final_verification_orchestrated,
    )
except Exception as e:
    VerifyTargets = None  # type: ignore
    VerifySettings = None  # type: ignore
    final_verification_orchestrated = None  # type: ignore
    _VERIFY_IMPORT_ERROR = e

_BACKUP_IMPORT_ERROR: Optional[Exception] = None
try:
    from .components.backup import backup_database  # type: ignore[attr-defined]
except Exception as e:
    backup_database = None  # type: ignore[assignment]
    _BACKUP_IMPORT_ERROR = e

_AELITE_IMPORT_ERROR: Optional[Exception] = None
try:
    from .components.ae_lite import AELiteConfig, install_ae_lite  # type: ignore[attr-defined]
except Exception as e:
    AELiteConfig = None  # type: ignore
    install_ae_lite = None  # type: ignore
    _AELITE_IMPORT_ERROR = e

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

# ---------------- generic helpers ----------------
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

def _construct_with_signature(cls: Any, **kwargs: Any) -> Any:
    """Safely construct a dataclass/config object by filtering kwargs to its signature."""
    sig = inspect.signature(cls)
    allowed = {k: v for k, v in kwargs.items() if k in sig.parameters}
    return cls(**allowed)  # type: ignore[misc]

# ---------------- ec2 discovery helper (by Name tag) ----------------
def _discover_public_ips_by_names(region: str, names: List[str]) -> Dict[str, str]:
    ips: Dict[str, str] = {}
    try:
        import boto3
        ec2 = boto3.client("ec2", region_name=region)
        flt = [
            {"Name": "instance-state-name", "Values": ["pending", "running", "stopping", "stopped"]},
            {"Name": "tag:Name", "Values": names},
        ]
        paginator = ec2.get_paginator("describe_instances")
        for page in paginator.paginate(Filters=flt):
            for res in page.get("Reservations", []) or []:
                for inst in res.get("Instances", []) or []:
                    name = None
                    for tag in inst.get("Tags", []) or []:
                        if tag.get("Key") == "Name":
                            name = str(tag.get("Value") or "")
                            break
                    if not name:
                        continue
                    pub = inst.get("PublicIpAddress") or ""
                    if pub:
                        ips[name] = pub
    except Exception as e:
        logging.warning("EC2 discovery failed: %s", e)
    return ips
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
        description="Automic AWS Bootstrap (provision + install AEDB, AE/SM/AWI, verify, backup)",
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
                          help="Provision → install-ae-lite → install-awi → verify (best-effort)")
    allp.add_argument("--automic-zip", required=False, type=Path,
                      help=f"Path to Automic bundle (.zip/.tar.gz). Default ./{DEFAULT_ARCHIVE_NAME} if omitted.")
    allp.add_argument("--key-path", required=False, type=Path,
                      help="PEM to use for follow-on SSH steps (defaults to the provisioned PEM path).")
    allp.add_argument("--jcp-port", type=int, default=8443, help="AE JCP TLS port (default 8443).")
    allp.add_argument("--awi-url", default="http://127.0.0.1:8080/awi/")

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

    verdb = sub.add_parser("verify-db", parents=[common],
                           help="Quick AEDB check: version + required extensions")
    verdb.add_argument("--db-host", required=True)
    verdb.add_argument("--key-path", required=True, type=Path)

    # ---- AE quick bring-up (files + JDBC, minimal config) ----
    aelite = sub.add_parser(
        "install-ae-lite", parents=[common],
        help="Copy AutomationEngine from DB host if missing, ensure JDBC, add sqlDriverConnect"
    )
    aelite.add_argument("--host", required=True, help="AE host/IP")
    aelite.add_argument("--db-host", required=True, help="DB host/IP (source of media if needed)")
    aelite.add_argument("--key-path", required=True, type=Path, help="PEM path on your local machine")
    aelite.add_argument("--ae-home", default="/opt/automic/AutomationEngine")
    aelite.add_argument("--db-media-path", default="/opt/automic/install/Automation.Platform/AutomationEngine")
    aelite.add_argument("--jdbc-glob", default="postgresql-*.jar")
    # NOTE: do NOT add --db-name here (comes from common). Avoids --db-name conflict.

    # ---- AWI installer ----
    awi = sub.add_parser("install-awi", parents=[common],
                         help="Install/configure AWI; if media missing on AWI, pull from DB host and start the launcher")
    awi.add_argument("--host", required=True, help="AWI host/IP to SSH into")
    awi.add_argument("--key-path", required=True, type=Path, help="PEM path on your local machine")

    # JCP endpoint (TLS by default)
    awi.add_argument("--jcp-cn", dest="jcp_cn", required=True, help="AE JCP hostname/CN or IP")
    awi.add_argument("--jcp-port", dest="jcp_port", type=int, default=8443)
    awi.add_argument("--system", dest="system_name", default="AELAB")
    awi.add_argument("--awi-url", dest="awi_url", default="http://127.0.0.1:8080/awi/")

    # Media sourcing (either archive or expanded folder)
    awi.add_argument("--awi-media", dest="awi_media",
                     default=None,
                     help="Optional: path on the AWI host to a WebInterface archive (.zip/.tgz) to unpack")
    awi.add_argument("--awi-media-path", dest="awi_media_path",
                     default="/opt/automic/install/Automation.Platform/WebInterface",
                     help="Optional: path on the AWI host to a pre-expanded WebInterface folder to copy from")

    # TLS trust + Java
    awi.add_argument("--tls-folder", dest="tls_folder", default="/opt/automic/tls/trust",
                     help="Folder on AWI host where AE cert will be trusted (default: /opt/automic/tls/trust)")
    awi.add_argument("--java-bin", dest="java_bin", default="/usr/bin/java")

    # Optional: push AE public cert to AWI trust
    awi.add_argument("--ae-cert-local", dest="ae_cert_local_path", default="")
    awi.add_argument("--ae-cert-remote", dest="ae_cert_remote_name", default="ae.crt",
                     help="Remote filename for the AE cert inside --tls-folder (default: ae.crt)")

    # Fallback source if AWI lacks media: copy from DB host
    awi.add_argument("--db-host", dest="db_host", default=None,
                     help="DB host/IP to pull WebInterface from when missing on AWI")
    awi.add_argument("--db-media-path", dest="db_media_path",
                     default="/opt/automic/install/Automation.Platform/WebInterface",
                     help="Path on DB host where WebInterface lives")

    # ---- full-stack verify ----
    ver = sub.add_parser("verify", parents=[common],
                         help="Verify AE/SM/AWI health end-to-end")
    ver.add_argument("--ae-host", required=True)
    ver.add_argument("--awi-host", required=True)
    ver.add_argument("--db-host", required=True)
    ver.add_argument("--key-path", type=Path, required=True)
    ver.add_argument("--sm-dest", default="AUTOMIC")
    ver.add_argument("--jcp-port", type=int, default=8443)
    ver.add_argument("--awi-url", default="http://127.0.0.1:8080/awi/")
    ver.add_argument("--ae-home", default="/opt/automic/AutomationEngine")
    ver.add_argument("--sm-bin", default="/opt/automic/ServiceManager/bin")
    ver.add_argument("--wait-timeout", type=int, default=90)

    return p
# ---------------- big commands ----------------
def _do_provision(args: argparse.Namespace) -> Tuple[int, Optional[str], Optional[Path]]:
    settings = _settings_from_args(args)
    init_logging(verbosity=1, log_file=settings.log_file)
    logging.info("=== Provision start (region=%s) ===", settings.region)

    if launch_automic_stack is None:
        logging.error("orchestrator not available in this build")
        return 2, None, None

    # 1) Launch/reuse infra
    try:
        pw = getattr(settings, "db_sys_pass", None) or getattr(settings, "db_password", None)
        if not pw:
            raise RuntimeError("DB password missing in Settings (db_sys_pass or db_password).")

        raw = launch_automic_stack(settings, db_user_pass=pw)  # type: ignore[arg-type]
        if raw is None or not isinstance(raw, Mapping):
            raise RuntimeError("launch_automic_stack did not return a Mapping")
        stack: Mapping[str, Any] = cast(Mapping[str, Any], raw)

        db_ip = cast(str, stack.get("db_ip", "")) or ""
        key_path_val = cast(Any, stack.get("key_path"))
        if not db_ip:
            raise RuntimeError("launch_automic_stack missing 'db_ip'")
        if not isinstance(key_path_val, (str, Path)):
            raise RuntimeError("launch_automic_stack missing 'key_path'")
        key_path = Path(key_path_val)

        logging.info("Provisioned: db_ip=%s, key=%s", db_ip, key_path)
    except Exception as e:
        logging.exception("Provision failed: %s", e)
        return 2, None, None

    # 2) Upload archive + run DB load
    if upload_automic_archive is None:
        logging.error("transfer module failed to import: %r", _TRANSFER_IMPORT_ERROR)
        return 3, None, None

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
        return 6, None, None

    logging.info("=== Provision complete ===")
    print(f"DB IP: {db_ip}")
    print(f"Key:   {key_path}")
    return 0, db_ip, key_path


def _do_deprovision(args: argparse.Namespace) -> int:
    # Lazy import keeps CLI usable without AWS libs
    try:
        import boto3
        try:
            from botocore.exceptions import ClientError  # type: ignore
        except Exception:
            class ClientError(Exception): ...
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
# ---------------- AE lite bring-up ----------------
def _do_install_ae_lite(args: argparse.Namespace) -> int:
    init_logging(verbosity=1, log_file=getattr(args, "log_file", "bootstrap.log"))

    if install_ae_lite is None or AELiteConfig is None:
        logging.error("AE-lite component unavailable: %r", _AELITE_IMPORT_ERROR)
        return 2

    try:
        cfg = _construct_with_signature(
            AELiteConfig,
            host=args.host,
            ssh_user=args.ssh_user,
            key_path=str(args.key_path),
            ae_home=args.ae_home,
            db_host=args.db_host,
            db_media_path=args.db_media_path,
            jdbc_glob=getattr(args, "jdbc_glob", "postgresql-*.jar"),
            db_name=args.db_name,  # from common parent
        )
        install_ae_lite(cfg)
        logging.info("install-ae-lite complete.")
        return 0
    except Exception as e:
        logging.exception("install-ae-lite failed: %s", e)
        return 1


# ---------------- AWI + full-stack verify handlers ----------------
def _do_install_awi(args: argparse.Namespace) -> int:
    init_logging(verbosity=1, log_file=getattr(args, "log_file", "bootstrap.log"))

    if install_awi is None or AWIConfig is None:
        logging.error("AWI component unavailable: %r", _AWI_IMPORT_ERROR)
        return 2

    try:
        cfg = _construct_with_signature(
            AWIConfig,
            host=args.host,
            ssh_user=args.ssh_user,
            key_path=str(args.key_path),

            # Paths/Java
            awi_root="/opt/automic/WebInterface",
            tls_folder=args.tls_folder,
            java_bin=args.java_bin,

            # Media (archive or expanded folder)
            awi_media=getattr(args, "awi_media", None),
            awi_media_path=args.awi_media_path,

            # JCP / System / URL
            jcp_ip_or_cn=args.jcp_cn,
            jcp_port=args.jcp_port,
            system_name=args.system_name,
            awi_url=args.awi_url,

            # Optional cert push
            ae_cert_local_path=args.ae_cert_local_path,
            ae_cert_remote_name=args.ae_cert_remote_name,

            # Fallback pull from DB host
            db_host=args.db_host,
            db_ssh_user=args.ssh_user,
            db_media_path=args.db_media_path,
        )
        install_awi(cfg)
        logging.info("install-awi complete.")
        return 0
    except Exception as e:
        msg = str(e)
        if "aa-webui-launcher.jar" in msg and "not found" in msg:
            logging.error("install-awi failed: WebInterface not present after copy. "
                          "Recheck --awi-media / --awi-media-path or --db-host/--db-media-path.")
        logging.exception("install-awi failed: %s", e)
        return 1


def _do_verify(args: argparse.Namespace) -> int:
    # Do not depend on Settings here; use args.log_file directly
    init_logging(verbosity=1, log_file=getattr(args, "log_file", "bootstrap.log"))
    if final_verification_orchestrated is None or VerifyTargets is None or VerifySettings is None:
        logging.error("verify module unavailable: %r", _VERIFY_IMPORT_ERROR)
        return 10
    try:
        targets = VerifyTargets(ae_host=args.ae_host, awi_host=args.awi_host, db_host=args.db_host)
        vset = VerifySettings(
            key_path=args.key_path,
            ssh_user=args.ssh_user,
            jcp_port=args.jcp_port,
            awi_url=args.awi_url,
            ae_home=args.ae_home,
            sm_bin=args.sm_bin,
            wait_timeout_s=args.wait_timeout,
        )
        final_verification_orchestrated(targets, vset, sm_dest=args.sm_dest)
        logging.info("Verification complete.")
        return 0
    except Exception as e:
        logging.exception("Verification failed: %s", e)
        return 11


def _do_all(args: argparse.Namespace) -> int:
    # 1) Provision + DB load
    rc, db_ip, key_path = _do_provision(args)
    if rc != 0:
        return rc
    assert db_ip and key_path

    # 2) Discover AE/AWI IPs by Name tag
    ips = _discover_public_ips_by_names(args.region, [args.ae_name, args.awi_name])
    ae_ip = ips.get(args.ae_name)
    awi_ip = ips.get(args.awi_name)
    if not ae_ip:
        logging.warning("AE IP not found via tags.")
    if not awi_ip:
        logging.warning("AWI IP not found via tags.")

    # 3) AE-lite (best-effort; continue even if it fails)
    if ae_ip:
        ns = argparse.Namespace(
            host=ae_ip,
            db_host=db_ip,
            key_path=key_path,
            ssh_user=args.ssh_user,
            ae_home="/opt/automic/AutomationEngine",
            db_media_path="/opt/automic/install/Automation.Platform/AutomationEngine",
            jdbc_glob="postgresql-*.jar",
            db_name=args.db_name,
            log_file=args.log_file,
        )
        try:
            _do_install_ae_lite(ns)
        except Exception as e:
            logging.warning("AE-lite errored but proceeding: %s", e)
    else:
        logging.warning("Skipping install-ae-lite (AE IP unknown).")

    # 4) AWI
    if awi_ip:
        ns2 = argparse.Namespace(
            host=awi_ip,
            key_path=key_path,
            ssh_user=args.ssh_user,

            jcp_cn=ae_ip or "127.0.0.1",
            jcp_port=getattr(args, "jcp_port", 8443),
            system_name="AELAB",
            awi_url=getattr(args, "awi_url", "http://127.0.0.1:8080/awi/"),

            # Prefer trust subfolder
            tls_folder="/opt/automic/tls/trust",
            java_bin="/usr/bin/java",

            # Media options (no archive by default in all-in-one)
            awi_media=None,
            awi_media_path="/opt/automic/install/Automation.Platform/WebInterface",

            # Optional cert injection disabled by default
            ae_cert_local_path="",
            ae_cert_remote_name="ae.crt",

            # Fallback copy from DB host
            db_host=db_ip,
            db_media_path="/opt/automic/install/Automation.Platform/WebInterface",
            log_file=args.log_file,
        )
        _do_install_awi(ns2)
    else:
        logging.warning("Skipping install-awi (AWI IP unknown).")

    # 5) Verify
    if ae_ip and awi_ip:
        ns3 = argparse.Namespace(
            region=args.region,
            ae_host=ae_ip,
            awi_host=awi_ip,
            db_host=db_ip,
            key_path=key_path,
            ssh_user=args.ssh_user,
            sm_dest="AUTOMIC",
            jcp_port=getattr(args, "jcp_port", 8443),
            awi_url=getattr(args, "awi_url", "http://127.0.0.1:8080/awi/"),
            ae_home="/opt/automic/AutomationEngine",
            sm_bin="/opt/automic/ServiceManager/bin",
            wait_timeout=120,
            log_file=args.log_file,
        )
        _do_verify(ns3)
    else:
        logging.warning("Skipping verify (AE/AWI IP unknown).")

    return 0

# ---------------- entrypoint ----------------
def main(argv: Optional[List[str]] = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    parser = _build_parser()
    if not argv:
        parser.print_help()
        return 2
    args = parser.parse_args(argv)

    dispatch = {
        "provision": lambda a=args: _do_provision(a)[0],
        "all": _do_all,
        "backup-db": _do_backup,
        "deprovision": _do_deprovision,
        "install-db": _do_install_db,
        "verify-db": _do_verify_db,
        "install-ae-lite": _do_install_ae_lite,
        "install-awi": _do_install_awi,
        "verify": _do_verify,
    }

    cmd_val = getattr(args, "cmd", None)
    if not isinstance(cmd_val, str):
        parser.print_help()
        return 2

    func = dispatch.get(cmd_val)
    if func is None:
        parser.print_help()
        return 2

    return int(func(args))


if __name__ == "__main__":
    raise SystemExit(main())
