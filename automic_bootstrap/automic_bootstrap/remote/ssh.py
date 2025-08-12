import paramiko

def ssh_exec(host: str, key_path, cmd: str, sudo: bool=False, username: str="ec2-user", timeout: int=60):
    if sudo and not cmd.strip().startswith("sudo"):
        cmd = "sudo " + cmd
    key = paramiko.RSAKey.from_private_key_file(str(key_path))
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(hostname=host, username=username, pkey=key, timeout=timeout)
    try:
        stdin, stdout, stderr = ssh.exec_command(cmd)
        rc = stdout.channel.recv_exit_status()
        out = stdout.read().decode()
        err = stderr.read().decode()
        return rc, out, err
    finally:
        ssh.close()
