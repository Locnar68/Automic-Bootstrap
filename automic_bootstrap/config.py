from dataclasses import dataclass
from pathlib import Path

@dataclass
class Settings:
    region: str = "us-east-1"
    vpc_id: str = ""
    sg_name: str = "automic-sg"
    key_name: str = "automic-key"
    key_dir: Path = Path.home()
    db_name: str = "AEDB"
    ae_name: str = "AE"
    awi_name: str = "AWI"
    db_type: str = "t3.micro"
    ae_type: str = "t3.micro"
    awi_type: str = "t3.micro"
    db_sys_pass: str = "Automic123"

DEF_SETTINGS = Settings()
