from __future__ import annotations
import logging

def configure_postgres(hba: str, conf: str) -> None:
    cmds = [
        f"grep -q '0.0.0.0/0' {hba} || echo 'host all all 0.0.0.0/0 md5' | tee -a {hba} >/dev/null",
        f"grep -q '^listen_addresses' {conf} || echo \"listen_addresses = '*'\" | tee -a {conf} >/dev/null",
        f"grep -q '^statement_timeout' {conf} || echo \"statement_timeout = '300s'\" | tee -a {conf} >/dev/null",
        f"grep -q '^idle_in_transaction_session_timeout' {conf} || echo \"idle_in_transaction_session_timeout = '300s'\" | tee -a {conf} >/dev/null",
    ]
    for c in cmds:
        logging.info(f"Running: {c}")
        # run SSH command here
