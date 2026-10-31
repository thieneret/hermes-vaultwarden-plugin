import os

def test_probe_umask(tmp_path):
    d = tmp_path / "open-dir"
    d.mkdir(mode=0o755)
    print("UMASK AT TEST:", oct(os.umask(0o022)))
    st = os.lstat(str(d))
    print("MODE ON DISK:", oct(st.st_mode & 0o777))
