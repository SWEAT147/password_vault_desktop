# client_network.py
import os
import ssl
import socket
import uuid
from protocol import send_msg, recv_msg


class NetworkClient:
    def __init__(
        self,
        host: str = "127.0.0.1",
        port: int = 5050,
        *,
        cafile: str = "certs/server.crt",
        server_hostname: str = "localhost",
        timeout_sec: float = 5.0,
        dev_insecure: bool | None = None,
    ):
        self.host = host
        self.port = port
        self.cafile = cafile
        self.server_hostname = server_hostname
        self.timeout_sec = timeout_sec

        # DEV only escape hatch (default from env)
        if dev_insecure is None:
            dev_insecure = os.getenv("DEV_INSECURE_TLS", "0") == "1"
        self.dev_insecure = dev_insecure

        self.sock: ssl.SSLSocket | None = None

    def connect(self):
        if self.sock:
            return

        raw = socket.create_connection((self.host, self.port), timeout=self.timeout_sec)

        if self.dev_insecure:
            # DEV ONLY - do not use in production
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        else:
            ctx = ssl.create_default_context(cafile=self.cafile)
            ctx.check_hostname = True
            ctx.verify_mode = ssl.CERT_REQUIRED

        # Prefer modern TLS
        try:
            ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        except Exception:
            pass

        tls = ctx.wrap_socket(raw, server_hostname=self.server_hostname)
        tls.settimeout(self.timeout_sec)
        self.sock = tls

    def close(self):
        if self.sock:
            try:
                self.sock.close()
            except Exception:
                pass
        self.sock = None

    def request(self, payload: dict) -> dict:
        self.connect()
        assert self.sock is not None

        payload = dict(payload)
        payload.setdefault("v", 1)
        payload.setdefault("request_id", uuid.uuid4().hex)

        try:
            send_msg(self.sock, payload)
            return recv_msg(self.sock)
        except (OSError, ConnectionError, ssl.SSLError):
            # Drop and let caller retry if they want
            self.close()
            raise
