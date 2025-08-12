import logging, sys
from logging.handlers import RotatingFileHandler

def setup_logging(log_file: str | None = "bootstrap.log") -> None:
    logger = logging.getLogger()
    logger.setLevel(logging.INFO)
    for h in list(logger.handlers):
        logger.removeHandler(h)
    if log_file:
        rf = RotatingFileHandler(log_file, maxBytes=10*1024*1024, backupCount=3)
        logger.addHandler(rf)
    sh = logging.StreamHandler(sys.stdout)
    logger.addHandler(sh)
    logging.info(f"Logging to {log_file}")
