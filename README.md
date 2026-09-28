# anansi-shell

A polymorphic SSH reverse shell. The client rewrites parts of its own source after each session
and keeps working, while traffic travels inside an SSH channel.

**This tool is created for educational purposes only. Do not point it at systems for which you do not have explicit authorization.**


## Layout

    server.py     operator side: SSH listener and command console
    client.py     target side: single-file implant, rewrites itself
    tests/        unit and integration tests

## Setup

    python3 -m venv .venv
    .venv/bin/pip install -r requirements.txt