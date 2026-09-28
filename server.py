"""Operator side: an SSH server hosting implant sessions. Accept user <shell>."""

import secrets

import paramiko


class ShellServer(paramiko.ServerInterface):

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
