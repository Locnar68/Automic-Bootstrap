from ..remote.ssh import ssh_exec

def write_remote_file(host: str, key_path, remote_path: str, contents: str, sudo: bool=False):
    esc = contents.replace("\\", "\\\\").replace("$", "\$")
    script = f"bash -lc 'cat > {remote_path} <<"EOF"\n{esc}\nEOF'"
    rc, out, err = ssh_exec(host, key_path, script, sudo=sudo)
    if rc != 0:
        raise RuntimeError(err)
