#!/usr/bin/env python3
# send.py
# user-friendly command line tool to send messages to the 3ds relay client

import sys
import os
import socket

IP_FILE = ".3ds_ip"
PORT = 5000

def get_saved_ip():
    if os.path.exists(IP_FILE):
        with open(IP_FILE, "r") as f:
            ip = f.read().strip()
            if ip:
                return ip
    return None

def save_ip(ip):
    with open(IP_FILE, "w") as f:
        f.write(ip.strip())

def main():
    saved_ip = get_saved_ip()
    token = None

    # update saved ip address
    if len(sys.argv) > 1 and sys.argv[1] in ["--set-ip", "-s"]:
        if len(sys.argv) < 3:
            print("error: specify the ip address after the flag")
            sys.exit(1)
        new_ip = sys.argv[2]
        try:
            socket.inet_aton(new_ip)
        except socket.error:
            print(f"error: '{new_ip}' is not a valid IP address")
            sys.exit(1)
        save_ip(new_ip)
        print(f"saved 3ds ip address: {new_ip}")
        sys.exit(0)

    args = sys.argv[1:]
    if len(args) >= 2 and args[0] in ["--token", "-t"]:
        token = args[1].strip()
        args = args[2:]

    if not token:
        try:
            token = input("enter session token shown on 3ds: ").strip()
        except (KeyboardInterrupt, EOFError):
            print("\ncancelled")
            sys.exit(0)

    if len(token) != 8 or any(c not in "0123456789abcdefABCDEF" for c in token):
        print("error: session token must be 8 hex characters")
        sys.exit(1)

    # get message text
    message = ""
    if args:
        message = " ".join(args)
    else:
        # prompt user for input
        try:
            message = input("enter message: ").strip()
        except (KeyboardInterrupt, EOFError):
            print("\ncancelled")
            sys.exit(0)

    if not message:
        print("error: message content is empty")
        sys.exit(1)

    # verify target ip address is configured
    target_ip = get_saved_ip()
    if not target_ip:
        print("no saved 3ds ip address found")
        try:
            target_ip = input("enter 3ds ip address (shown on console screen): ").strip()
        except (KeyboardInterrupt, EOFError):
            print("\ncancelled")
            sys.exit(0)
        
        if not target_ip:
            print("error: ip address is required")
            sys.exit(1)
        try:
            socket.inet_aton(target_ip)
        except socket.error:
            print(f"error: '{target_ip}' is not a valid IP address")
            sys.exit(1)
        save_ip(target_ip)

    # establish TCP connection and transmit payload
    print(f"connecting to 3ds at {target_ip}:{PORT}...")
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5.0)
        s.connect((target_ip, PORT))
        payload = f"{token} {message}\n"
        s.sendall(payload.encode("utf-8"))
        s.close()
        print("message successfully staged to 3ds queue!")
    except socket.timeout:
        print("error: connection timed out. verify the 3ds is in wifi mode and on the same network.")
        sys.exit(1)
    except Exception as e:
        print(f"error: failed to transmit message: {e}")
        print("hint: run './send.py --set-ip <ip>' if the 3ds ip address has changed.")
        sys.exit(1)

if __name__ == "__main__":
    main()
