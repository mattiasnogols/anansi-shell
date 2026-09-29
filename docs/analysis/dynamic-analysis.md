# Dynamic analysis

One session against a local server, run from a scratch copy:

    strace -f -tt -s 160 -e trace=%file,%process,connect,getrandom \
        -o strace.log .venv/bin/python client.py --host <ip> \
        --port <port> --password <pw>

## Session

    124060 20:43:53.794011 connect(3, {sin_port=htons(2382), sin_addr=inet_addr("127.0.0.1")}, 16) = 0
    124063 20:43:53.798751 getrandom("\x86\x62\xb3\xd2...", 32, 0) = 32

The getrandom draw 4 ms after connect is the handshake key related. Per-frame nonces do not show.

    124067 20:43:54.065980 execve("/bin/sh", ["/bin/sh", "-c", "head -c 200000000 /dev/urandom | sha256sum"]) = 0
    124068 20:43:54.078847 execve("/usr/bin/head", ["head", "-c", "200000000", "/dev/urandom"]) = 0
    124069 20:43:54.079153 execve("/usr/bin/sha256sum", ["sha256sum"]) = 0

Commands run in a child pipeline.

## The rewrite

After b"exit", within one second:

    124060 20:43:58.067999 openat(AT_FDCWD, "client.py", O_RDONLY|O_CLOEXEC) = 3
    124060 20:43:58.103134 openat(AT_FDCWD, "tmp10qx7jct.py", O_RDWR|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC, 0600) = 3
    124099 20:43:58.105919 execve(".venv/bin/python", ["python", "tmp10qx7jct.py", "--selfcheck"]) = 0
    124060 20:43:58.796527 openat(AT_FDCWD, "client.py", O_RDONLY|O_CLOEXEC) = 3
    124060 20:43:58.796707 openat(AT_FDCWD, "client.py.bak", O_WRONLY|O_CREAT|O_TRUNC|O_CLOEXEC, 0666) = 4
    124060 20:43:58.797853 rename("tmp10qx7jct.py", "client.py") = 0

The client reads its own source, writes to a private temp file, verifies
it with a second interpreter, copies the old file to .bak and swaps it
in with one rename(). client.py is never opened for writing, so an
interruption leaves the old generation in place.