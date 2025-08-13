import logging
from pathlib import Path
from ..remote.ssh import ssh_exec
from ..remote.sftp import sftp_put

def _install_java_and_dirs(awi_ip: str, key_path: Path) -> None:
    steps = [
        "dnf install -y java-17-amazon-corretto unzip || yum install -y java-17-amazon-corretto unzip",
        "mkdir -p /opt/automic/WebInterface /opt/automic/install",
        "chown ec2-user:ec2-user /opt/automic/WebInterface /opt/automic/install",
        r"""bash -lc '
            set -e
            JAVA_HOME=$(dirname "$(dirname "$(readlink -f "$(which java)")")")
            echo "export JAVA_HOME=$JAVA_HOME" > /etc/profile.d/java.sh
            echo "export PATH=\$JAVA_HOME/bin:\$PATH" >> /etc/profile.d/java.sh
            chmod +x /etc/profile.d/java.sh
        '"""
    ]
    for cmd in steps:
        rc, out, err = ssh_exec(awi_ip, key_path, cmd, sudo=True)
        if rc != 0:
            raise RuntimeError(err)

def _upload_and_unzip(awi_ip: str, key_path: Path, local_zip: Path) -> None:
    remote_zip = "/opt/automic/install/Automic.zip"
    sftp_put(awi_ip, key_path, local_zip, remote_zip)
    rc, out, err = ssh_exec(awi_ip, key_path, "cd /opt/automic/install && unzip -o Automic.zip", sudo=True)
    if rc != 0:
        raise RuntimeError(err)

def _write_response_props(awi_ip: str, key_path: Path, db_ip: str, db_name: str, db_pass: str) -> None:
    props = (
        f"jdbc.url=jdbc:postgresql://{db_ip}:5432/{db_name}\n"
        f"jdbc.user=aauser\n"
        f"jdbc.password={db_pass}\n"
    )
    script = f"bash -lc 'cat > /home/ec2-user/awi_response.properties <<"EOF"\n{props}EOF'"
    rc, out, err = ssh_exec(awi_ip, key_path, script, sudo=False)
    if rc != 0:
        raise RuntimeError(err)

def _run_awi_installer(awi_ip: str, key_path: Path) -> None:
    cmd = r"""bash -lc '
set -e
INSTALL_DIR=$(dirname "$(find /opt/automic/install -type f -name install.sh | grep -i WebInterface | head -n1)")
if [ -z "$INSTALL_DIR" ]; then
  INSTALL_DIR=$(dirname "$(find /opt/automic/install -type f -name install.sh | head -n1)")
fi
cd "$INSTALL_DIR"
bash install.sh -silent -responseFile /home/ec2-user/awi_response.properties
'"""
    rc, out, err = ssh_exec(awi_ip, key_path, cmd, sudo=True)
    if rc != 0:
        raise RuntimeError(err)

def _launch_awi(awi_ip: str, key_path: Path) -> str:
    cmd = r"""bash -lc '
set -e
RUN_DIR=$(dirname "$(find /opt/automic -type f -name aa-webui-launcher.jar | head -n1)")
if [ -z "$RUN_DIR" ]; then
  echo "aa-webui-launcher.jar not found" >&2
  exit 1
fi
cd "$RUN_DIR"
nohup java -jar aa-webui-launcher.jar > awi.log 2>&1 &
echo "$RUN_DIR"
'"""
    rc, out, err = ssh_exec(awi_ip, key_path, cmd, sudo=False)
    if rc != 0:
        raise RuntimeError(err)
    return out.strip()

def install_awi(awi_ip: str, db_ip: str, db_name: str, db_pass: str, key_path: Path, local_zip: Path) -> str:
    logging.info("=== AWI: install Java and prepare dirs ===")
    _install_java_and_dirs(awi_ip, key_path)
    logging.info("=== AWI: upload + unzip Automic image ===")
    _upload_and_unzip(awi_ip, key_path, local_zip)
    logging.info("=== AWI: write response properties ===")
    _write_response_props(awi_ip, key_path, db_ip, db_name, db_pass)
    logging.info("=== AWI: run installer ===")
    _run_awi_installer(awi_ip, key_path)
    logging.info("=== AWI: launch ===")
    run_dir = _launch_awi(awi_ip, key_path)
    logging.info(f"AWI launched from: {run_dir}")
    return run_dir
