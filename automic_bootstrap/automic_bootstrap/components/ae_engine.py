import logging
from pathlib import Path
from ..remote.ssh import ssh_exec
from ..remote.sftp import sftp_put

JAR_URL = "https://jdbc.postgresql.org/download/postgresql-42.7.5.jar"

def _install_java_and_libs(ae_ip: str, key_path: Path) -> None:
    cmds = [
        "dnf install -y java-17-amazon-corretto unzip || yum install -y java-17-amazon-corretto unzip",
        "dnf install -y postgresql-libs || yum install -y postgresql-libs || true",
        r"""bash -lc '
            set -e
            JAVA_HOME=$(dirname "$(dirname "$(readlink -f "$(which java)")")")
            echo "export JAVA_HOME=$JAVA_HOME" > /etc/profile.d/java.sh
            echo "export PATH=\$JAVA_HOME/bin:\$PATH" >> /etc/profile.d/java.sh
            chmod +x /etc/profile.d/java.sh
        '"""
    ]
    for c in cmds:
        rc, out, err = ssh_exec(ae_ip, key_path, c, sudo=True)
        if rc != 0:
            raise RuntimeError(err)

def _put_automic_zip(ae_ip: str, key_path: Path, local_zip: Path | None) -> None:
    if not local_zip:
        return
    rc, out, err = ssh_exec(ae_ip, key_path, "mkdir -p /opt/automic/install && chown ec2-user:ec2-user /opt/automic/install", sudo=True)
    if rc != 0:
        raise RuntimeError(err)
    remote_zip = "/opt/automic/install/Automic.zip"
    sftp_put(ae_ip, key_path, local_zip, remote_zip)
    rc, out, err = ssh_exec(ae_ip, key_path, "cd /opt/automic/install && unzip -o Automic.zip", sudo=True)
    if rc != 0:
        raise RuntimeError(err)

def _find_ae_dir(ae_ip: str, key_path: Path) -> str:
    cmd = r"""bash -lc 'dirname "$(find /opt/automic -type f -name ucsrv.ini | head -n1)"'"""
    rc, out, err = ssh_exec(ae_ip, key_path, cmd, sudo=True)
    path = out.strip()
    if rc != 0 or not path:
        raise RuntimeError(err or "Unable to locate ucsrv.ini under /opt/automic")
    return path

def _ensure_jdbc_driver(ae_ip: str, key_path: Path, ae_dir: str, local_driver: Path | None) -> None:
    target = f"{ae_dir}/bin/lib/postgresql-42.7.5.jar"
    if local_driver and local_driver.exists():
        sftp_put(ae_ip, key_path, local_driver, target)
        return
    cmd = f"curl -L {JAR_URL} -o {target} || wget -O {target} {JAR_URL}"
    rc, out, err = ssh_exec(ae_ip, key_path, cmd, sudo=True)
    if rc != 0:
        raise RuntimeError(err)

def _edit_ucsvr_ini(ae_ip: str, key_path: Path, ae_dir: str, db_ip: str, db_name: str, ae_name: str, ae_host_ip: str) -> None:
    script = f"""bash -lc '
set -e
INI="{ae_dir}/config/ucsvr.ini"
set_kv() {{
  local key="$1"; shift
  local val="$1"; shift
  if grep -q "^${{key}}=" "$INI"; then
    sed -i "s|^${{key}}=.*|${{key}}=${{val}}|" "$INI"
  else
    echo "${{key}}=${{val}}" >> "$INI"
  fi
}}
set_kv "jdbc.url" "jdbc:postgresql://{db_ip}:5432/{db_name}"
set_kv "jdbc.driver.class" "org.postgresql.Driver"
set_kv "server.host" "{ae_host_ip}"
set_kv "server.system" "{ae_name}"
'"""
    rc, out, err = ssh_exec(ae_ip, key_path, script, sudo=True)
    if rc != 0:
        raise RuntimeError(err)

def _start_engine_processes(ae_ip: str, key_path: Path, ae_dir: str) -> None:
    cmd = f"""bash -lc '
set -e
cd "{ae_dir}/bin"
nohup ./ucsrvwp > ae_wp.log 2>&1 &
nohup ./ucsrvcp > ae_cp.log 2>&1 &
nohup java -jar ucsrvjp.jar > ae_jwp.log 2>&1 &
nohup java -jar ucsrvjr.jar --rest > ae_rest.log 2>&1 &
'"""
    rc, out, err = ssh_exec(ae_ip, key_path, cmd, sudo=False)
    if rc != 0:
        raise RuntimeError(err)

def configure_and_start_ae(ae_ip: str, db_ip: str, key_path: Path, ae_name: str, db_name: str, local_automic_zip: Path | None = None, local_jdbc: Path | None = None) -> str:
    logging.info("=== AE: install Java + libs ===")
    _install_java_and_libs(ae_ip, key_path)
    logging.info("=== AE: upload + unzip Automic bundle (optional) ===")
    _put_automic_zip(ae_ip, key_path, local_automic_zip)
    logging.info("=== AE: locate AE directory ===")
    ae_dir = _find_ae_dir(ae_ip, key_path)
    logging.info("=== AE: ensure JDBC driver ===")
    _ensure_jdbc_driver(ae_ip, key_path, ae_dir, local_jdbc)
    logging.info("=== AE: configure ucsvr.ini ===")
    _edit_ucsvr_ini(ae_ip, key_path, ae_dir, db_ip, db_name, ae_name, ae_ip)
    logging.info("=== AE: start processes ===")
    _start_engine_processes(ae_ip, key_path, ae_dir)
    logging.info("AE Engine configured and started.")
    return ae_dir
