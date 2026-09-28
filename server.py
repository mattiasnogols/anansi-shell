"""Operator side: an SSH server hosting implant sessions."""

import argparse
import random
import secrets
import socket
import sys
import time

import paramiko


class ShellServer(paramiko.ServerInterface):
    """Accept user <shell>."""

    def __init__(self, password):
        self.password = password

    def check_auth_password(self, username, password):
        if username == "shell" and secrets.compare_digest(password, self.password):
            return paramiko.AUTH_SUCCESSFUL
        return paramiko.AUTH_FAILED

    def check_channel_request(self, kind, chanid):
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED


def load_host_key(path):
    try:
        return paramiko.ECDSAKey.from_private_key_file(path)
    except (FileNotFoundError, paramiko.SSHException):
        key = paramiko.ECDSAKey.generate()
        key.write_private_key_file(path)
        return key


def handle_session(channel):
    """ping the client"""
    channel.settimeout(10)
    channel.send(b"anansi-shell ready\n")
    while True:
        time.sleep(random.uniform(2.0, 5.0))
        start = time.monotonic()
        try:
            channel.send(b"ping")
            reply = channel.recv(4096)
        except (socket.timeout, OSError):
            reply = b""
        if reply != b"pong":
            print("session closed by client", flush=True)
            break
        print(f"pong {1000 * (time.monotonic() - start):.1f} ms", flush=True)


def serve(bind, port, host_key, password):
    listener = socket.create_server((bind, port))
    print(f"listening on {bind}:{port}", flush=True)
    while True:
        sock, addr = listener.accept()
        transport = paramiko.Transport(sock)
        transport.add_server_key(host_key)
        try:
            transport.start_server(server=ShellServer(password))
            channel = transport.accept(timeout=5)
            if channel is not None:
                print(f"session from {addr[0]}:{addr[1]}", flush=True)
                handle_session(channel)
        except Exception as exc:
            print(f"connection failed: {exc!r}", file=sys.stderr, flush=True)
        finally:
            transport.close()


def main():
    parser = argparse.ArgumentParser(description="anansi-shell operator server")
    parser.add_argument("--bind", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=2222)
    args = parser.parse_args()
    host_key = load_host_key("server_host_key")
    password = secrets.token_urlsafe(12)
    print(f"host key fingerprint: {host_key.fingerprint}", flush=True)
    print(f"session password: {password}", flush=True)
    serve(args.bind, args.port, host_key, password)


if __name__ == "__main__":
    main()
