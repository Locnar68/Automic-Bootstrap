from __future__ import annotations
from pathlib import Path
from .utils import ssh_exec

def configure_awi(awi_ip: str, key_path: Path, db_host: str, db_name: str, db_user: str, db_pass: str) -> None:
    props = (
        f"jdbc.url=jdbc:postgresql://{db_host}/{db_name}\n"
        f"jdbc.user={db_user}\n"
        f"jdbc.password={db_pass}\n"
    )
    script = f"bash -lc 'cat > /home/ec2-user/awi_response.properties <<\"EOF\"\n{props}EOF'"
    rc, out, err = ssh_exec(awi_ip, key_path, script, sudo=False)
    if rc != 0:
        raise RuntimeError(f"Failed to configure AWI: {err}")
