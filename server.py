"""Operator side: an SSH server hosting implant sessions."""

import argparse
import base64
import os
import random
import secrets
import socket
import struct
import sys
import time

import paramiko
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305

# Inner protocol, version 1. Every message is one frame, big-endian integers:
#
#     length (4B) | version (1B) | algo (1B) | nonce (12B) | ciphertext + tag
#
# `length` counts the bytes after it, so the receiver reads exactly one frame
# even when the channel hands out data in random-sized chunks. `version` and
# `algo` travel unencrypted but authenticated: the receiver needs them to pick
# a cipher, and rewriting them breaks the tag. The plaintext is base64-encoded
# before encryption, so binary command output survives the whole stack.
PROTO_VERSION = 1
AEAD = {1: AESGCM, 2: ChaCha20Poly1305}
MAX_FRAME = 2 << 20  # room for the base64 of a 1 MiB payload


def seal_frame(key, algo, plaintext):
    """Encrypt into header + nonce + ciphertext"""
    # nonce to never repeat under the same key
    nonce = os.urandom(12)
    header = bytes((PROTO_VERSION, algo))
    # AEAD to encrypt and authenticate. header covered by the tag but stays readable.
    ciphertext = AEAD[algo](key).encrypt(nonce, base64.b64encode(plaintext), header)
    return header + nonce + ciphertext


def unseal_frame(key, body):
    """Decrypt frame body"""
    version, algo = body[0], body[1]
    if len(body) < 30 or version != PROTO_VERSION or algo not in AEAD:
        raise ValueError(f"unsupported frame header: version={version} algo={algo}")
    # Body layout: 2 header bytes, 12 nonce bytes, then ciphertext + 16 byte tag. 
    payload = AEAD[algo](key).decrypt(body[2:14], body[14:], body[:2])
    return base64.b64decode(payload, validate=True)


def read_exactly(channel, count):
    # recv() may return fewer bytes so keep looping; if empty then channel closed
    data = b""
    while len(data) < count:
        chunk = channel.recv(count - len(data))
        if not chunk:
            raise EOFError("channel closed mid-frame")
        data += chunk
    return data


def send_frame(channel, key, algo, plaintext):
    body = seal_frame(key, algo, plaintext)
    channel.sendall(struct.pack(">I", len(body)) + body)


def recv_frame(channel):
    # do not buffer arbitrary amount of memory
    (length,) = struct.unpack(">I", read_exactly(channel, 4))
    if length > MAX_FRAME:
        raise ValueError(f"frame exceeds {MAX_FRAME} bytes: {length}")
    return read_exactly(channel, length)


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
