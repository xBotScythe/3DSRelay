#!/usr/bin/env python3
# push_update.py
# uploads the built .update and .cia to a 3ds running ftpd, replacing the staged
# files on its sd card. ftpd serves the sd root, so this acts as the ftp client.

import sys
import os
import ftplib

IP_FILE = ".3ds_ip"
DEFAULT_PORT = 5000  # ftpd default listen port

# local file -> remote path on the sd card (ftpd root maps to the sd root)
UPLOADS = [
    ("3DSRelay.update", "/3ds/3DSRelay.update"),  # ota seed file the app reads
    ("3DSRelay.cia", "/cia/3DSRelay.cia"),         # for a manual reinstall via fbi
]


def get_ip():
    # explicit argument wins, else fall back to the saved address
    if len(sys.argv) > 1 and sys.argv[1].strip():
        return sys.argv[1].strip()
    if os.path.exists(IP_FILE):
        with open(IP_FILE) as f:
            ip = f.read().strip()
            if ip:
                return ip
    return None


def ensure_remote_dir(ftp, remote_path):
    # create each parent directory of remote_path, ignoring "already exists"
    parts = [p for p in os.path.dirname(remote_path).split("/") if p]
    cur = ""
    for p in parts:
        cur += "/" + p
        try:
            ftp.mkd(cur)
        except ftplib.error_perm:
            pass


def main():
    ip = get_ip()
    if not ip:
        print("no 3ds ip. pass one (make push IP=10.0.0.5) or save it in .3ds_ip")
        sys.exit(1)
    port = int(os.environ.get("FTP_PORT", DEFAULT_PORT))

    missing = [src for src, _ in UPLOADS if not os.path.exists(src)]
    if missing:
        print("missing build outputs: " + ", ".join(missing))
        print("run 'make update SIGNING_KEY=<hex>' first")
        sys.exit(1)

    print(f"connecting to ftpd at {ip}:{port} ...")
    try:
        ftp = ftplib.FTP()
        ftp.connect(ip, port, timeout=10)
        ftp.login()  # ftpd accepts anonymous login
    except Exception as e:
        print(f"error: could not connect to ftpd: {e}")
        print("hint: start ftpd on the 3ds and confirm the ip/port it shows")
        sys.exit(1)

    try:
        for src, remote in UPLOADS:
            ensure_remote_dir(ftp, remote)
            size = os.path.getsize(src)
            print(f"uploading {src} ({size} bytes) -> {remote}")
            with open(src, "rb") as fh:
                ftp.storbinary(f"STOR {remote}", fh)
    except Exception as e:
        print(f"error: upload failed: {e}")
        sys.exit(1)
    finally:
        try:
            ftp.quit()
        except Exception:
            pass

    print("done. the 3ds has the new files; restart 3dsrelay to apply the update.")


if __name__ == "__main__":
    main()
