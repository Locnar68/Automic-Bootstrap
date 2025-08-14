# automic_bootstrap/orchestrators/stages.py
from __future__ import annotations

import inspect
import logging
from pathlib import Path
from typing import Any

from automic_bootstrap.components.ae_engine import configure_and_start_ae

# Components mapped 1:1 to install guide sections
from automic_bootstrap.components.aedb import install_aedb
from automic_bootstrap.components.awi import install_awi
from automic_bootstrap.components.service_manager import install_service_manager

# Optional modules; import lazily inside functions if you might exclude them:
# from automic_bootstrap.components.agents import install_agents
# from automic_bootstrap.components.analytics import install_analytics
# from automic_bootstrap.components.backup import backup_db
from automic_bootstrap.components.verify import final_verification

log = logging.getLogger(__name__)


def _filter_kwargs(func: Any, kwargs: dict[str, Any]) -> dict[str, Any]:
    """
    Keep only kwargs present in the called function's signature.
    This lets us call newer/older component versions safely.
    """
    try:
        sig = inspect.signature(func)
        allowed = set(sig.parameters.keys())
        return {k: v for k, v in kwargs.items() if k in allowed and v is not None}
    except (TypeError, ValueError):
        # If we can't introspect, pass nothing to be safe
        return {}


def _path_or_none(p: Any) -> Path | None:
    if p is None:
        return None
    try:
        pp = Path(p)
        return pp if str(pp) else None
    except Exception:
        return None


# -------------------------
# Stage wrappers
# -------------------------


def stage_install_db(args) -> None:
    """
    Database stage:
      - Postgres config
      - AEDB creation + schema load
    """
    log.info("[STAGE] install-db: start")

    kwargs = {
        "db_ip": getattr(args, "db_ip", None),
        "db_name": getattr(args, "db_name", None),
        "db_user": getattr(args, "db_user", None),
        "db_password": getattr(args, "db_pass", None) or getattr(args, "db_password", None),
        "key_path": _path_or_none(getattr(args, "key_path", None)),
        "automic_zip": _path_or_none(getattr(args, "automic_zip", None)),
    }

    filtered = _filter_kwargs(install_aedb, kwargs)
    install_aedb(**filtered)

    log.info("[STAGE] install-db: complete")


def stage_install_ae(args) -> None:
    """
    AE engine stage:
      - ucsrv.ini edits, TLS, JDBC placement
      - start JWP/JCP/REST as appropriate
    """
    log.info("[STAGE] install-ae: start")

    # Some component versions support 'local_automic_zip'; others don't.
    # We'll probe and pass only what is accepted.
    kwargs_new = {
        "ae_ip": getattr(args, "ae_ip", None),
        "db_ip": getattr(args, "db_ip", None),
        "key_path": _path_or_none(getattr(args, "key_path", None)),
        "ae_name": getattr(args, "ae_name", None),
        "db_name": getattr(args, "db_name", None),
        "local_automic_zip": _path_or_none(getattr(args, "automic_zip", None)),
    }
    kwargs_legacy = {
        "ae_ip": getattr(args, "ae_ip", None),
        "db_ip": getattr(args, "db_ip", None),
        "key_path": _path_or_none(getattr(args, "key_path", None)),
        "ae_name": getattr(args, "ae_name", None),
        "db_name": getattr(args, "db_name", None),
    }

    # Prefer the richer set; if not supported, fall back.
    filt = _filter_kwargs(configure_and_start_ae, kwargs_new)
    if not filt:
        filt = _filter_kwargs(configure_and_start_ae, kwargs_legacy)

    configure_and_start_ae(**filt)

    log.info("[STAGE] install-ae: complete")


def stage_install_awi(args) -> None:
    """
    AWI stage:
      - configure uc4.config.xml
      - trusted cert folder
      - launcher
    """
    log.info("[STAGE] install-awi: start")

    kwargs = {
        "awi_ip": getattr(args, "awi_ip", None) or getattr(args, "ae_ip", None),
        "db_ip": getattr(args, "db_ip", None),
        "db_name": getattr(args, "db_name", None),
        "db_pass": getattr(args, "db_pass", None) or getattr(args, "db_password", None),
        "key_path": _path_or_none(getattr(args, "key_path", None)),
        "automic_zip": _path_or_none(getattr(args, "automic_zip", None)),
    }
    filtered = _filter_kwargs(install_awi, kwargs)
    install_awi(**filtered)

    log.info("[STAGE] install-awi: complete")


def stage_install_service_manager(args) -> None:
    """
    Service Manager stage:
      - write uc4.smd/uc4.smc
      - start SM, apply -d64 tweak where needed
    """
    log.info("[STAGE] install-sm: start")

    kwargs = {
        "ae_ip": getattr(args, "ae_ip", None),
        "key_path": _path_or_none(getattr(args, "key_path", None)),
        "sm_tar": _path_or_none(getattr(args, "sm_tar", None)),
    }
    filtered = _filter_kwargs(install_service_manager, kwargs)
    install_service_manager(**filtered)

    log.info("[STAGE] install-sm: complete")


def stage_verify(args) -> None:  # noqa: ARG001 - args reserved for future
    """
    Quick verification:
      - systemd status checks
      - log tails / psql version checks (delegated)
    """
    log.info("[STAGE] verify: start")
    final_verification()
    log.info("[STAGE] verify: complete")


def run_all(args) -> None:
    """
    Happy-path pipeline:
      DB -> AE -> AWI -> SM -> Verify
    Any missing IPs/paths will be passed only if the target stage accepts them.
    """
    log.info("[PIPELINE] all: start")

    stage_install_db(args)
    stage_install_ae(args)
    stage_install_awi(args)
    stage_install_service_manager(args)
    stage_verify(args)

    log.info("[PIPELINE] all: complete")


# -------------------------
# Convenience dispatchers
# (These can be called from cli.py subcommands)
# -------------------------


def run_stage(name: str, args) -> None:
    """
    Dispatch a single stage by name.
    Valid names: install-db, install-ae, install-awi, install-sm, verify, all
    """
    mapping = {
        "install-db": stage_install_db,
        "install-ae": stage_install_ae,
        "install-awi": stage_install_awi,
        "install-sm": stage_install_service_manager,
        "verify": stage_verify,
        "all": run_all,
    }
    func = mapping.get(name)
    if func is None:
        valid = ", ".join(mapping.keys())
        raise ValueError(f"Unknown stage '{name}'. Valid: {valid}")
    func(args)
