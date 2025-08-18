# automic_bootstrap/logging_setup.py
from __future__ import annotations
import logging, sys

def setup_logging(verbosity: int = 1, log_file: str = "bootstrap.log") -> None:
    try:
        v = int(verbosity)
    except Exception:
        v = 1
    level = logging.INFO if v <= 1 else logging.DEBUG

    fmt = "%(asctime)s [%(levelname)s] %(message)s"
    datefmt = "%H:%M:%S"

    handlers = [logging.StreamHandler(sys.stdout)]
    if log_file:
        handlers.append(logging.FileHandler(log_file, mode="a", encoding="utf-8"))

    logging.basicConfig(level=level, format=fmt, datefmt=datefmt, handlers=handlers)