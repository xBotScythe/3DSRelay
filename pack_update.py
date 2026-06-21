#!/usr/bin/env python3
# pack_update.py
# packages and signs 3dsrelay update binaries
#
# reads CURRENT_APP_VERSION directly from source
# so the version only needs to be set in one place (the code)
#
# usage:
#   ./pack_update.py <private_key_hex>
#   ./pack_update.py <private_key_hex> [--cia <path>] [--out <path>]
#   ./pack_update.py <input.cia> <private_key_hex> <version> <output>  (legacy)

import sys
import os
import re
import hashlib
import struct

try:
    from cryptography.hazmat.primitives.asymmetric import ed25519
except ImportError:
    print("error: python 'cryptography' library is required.")
    print("install with: pip install cryptography")
    sys.exit(1)


def extract_version(filepath, pattern):
    """extract a uint32 version constant from a C++ source file"""
    try:
        with open(filepath, "r") as f:
            for line in f:
                m = re.search(pattern + r'\s*=\s*(\d+)', line)
                if m:
                    return int(m.group(1))
    except FileNotFoundError:
        pass
    return None


def main():
    # support legacy 4-arg invocation for backwards compat
    if len(sys.argv) == 5 and not sys.argv[1].startswith("--"):
        cia_path = sys.argv[1]
        priv_key_hex = sys.argv[2]
        version = int(sys.argv[3])
        out_path = sys.argv[4]
        return run(cia_path, priv_key_hex, version, out_path)

    priv_key_hex = os.environ.get("SIGNING_KEY", "")

    if not priv_key_hex and len(sys.argv) >= 2 and sys.argv[1] not in ("-h", "--help"):
        priv_key_hex = sys.argv[1]

    if not priv_key_hex or (len(sys.argv) >= 2 and sys.argv[1] in ("-h", "--help")):
        print("usage: ./pack_update.py [private_key_hex] [--cia <path>] [--out <path>]")
        print("       SIGNING_KEY=<hex> ./pack_update.py [--cia <path>] [--out <path>]")
        print()
        print("reads CURRENT_APP_VERSION from source/version.cpp")
        print("key can be passed as first arg or SIGNING_KEY env var")
        print("defaults: --cia 3DSRelay.cia  --out 3DSRelay.update")
        sys.exit(0 if "--help" in sys.argv else 1)

    cia_path = "3DSRelay.cia"
    out_path = "3DSRelay.update"

    key_from_env = bool(os.environ.get("SIGNING_KEY", ""))
    args = sys.argv[1:] if key_from_env else sys.argv[2:]
    while args:
        if args[0] == "--cia" and len(args) > 1:
            cia_path = args[1]
            args = args[2:]
        elif args[0] == "--out" and len(args) > 1:
            out_path = args[1]
            args = args[2:]
        else:
            print(f"error: unknown argument '{args[0]}'")
            sys.exit(1)

    # auto-read version from source
    version = extract_version("source/version.cpp", r"CURRENT_APP_VERSION")
    if version is None:
        print("error: could not read CURRENT_APP_VERSION from source/version.cpp")
        sys.exit(1)

    run(cia_path, priv_key_hex, version, out_path)


def run(cia_path, priv_key_hex, version, out_path):
    if not os.path.exists(cia_path):
        print(f"error: {cia_path} not found")
        sys.exit(1)

    with open(cia_path, "rb") as f:
        cia_data = f.read()

    sha256 = hashlib.sha256(cia_data).digest()
    file_size = len(cia_data)

    # parse private key
    try:
        priv_bytes = bytes.fromhex(priv_key_hex)
        if len(priv_bytes) == 64:
            priv_bytes = priv_bytes[:32]
        priv_key = ed25519.Ed25519PrivateKey.from_private_bytes(priv_bytes)
    except Exception as e:
        print(f"error loading private key: {e}")
        sys.exit(1)

    msg = struct.pack("<II", version, file_size) + sha256
    signature = priv_key.sign(msg)

    magic = struct.pack("<I", 0x55504434)
    header = magic + struct.pack("<II", version, file_size) + sha256 + signature

    with open(out_path, "wb") as f:
        f.write(header)
        f.write(cia_data)

    print(f"packed {out_path}")
    print(f"  version:    {version}")
    print(f"  size:       {file_size} bytes")
    print(f"  sha-256:    {sha256.hex()}")


if __name__ == "__main__":
    main()
