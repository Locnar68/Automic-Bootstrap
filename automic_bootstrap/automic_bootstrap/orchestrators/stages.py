import logging
from pathlib import Path
from ..components.aedb import install_aedb
from ..components.ae_engine import configure_and_start_ae
from ..components.awi import install_awi
from ..components.service_manager import install_service_manager

def run_all(db_ip: str, ae_ip: str, awi_ip: str, key_path: Path, db_name: str, ae_name: str, db_pass: str, automic_zip: Path, sm_tar: Path | None = None):
    logging.info("Running full pipeline")
    install_aedb(db_ip, key_path, db_name, db_pass, automic_zip)
    configure_and_start_ae(ae_ip, db_ip, key_path, ae_name, db_name, local_automic_zip=automic_zip)
    install_awi(awi_ip, db_ip, db_name, db_pass, key_path, automic_zip)
    install_service_manager(ae_ip, key_path, sm_tar=sm_tar)
