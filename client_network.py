import ssl
import socket
import uuid
from protocol import send_msg, recv_msg


class NetworkClient:
    def __init__(self, host="127.0.0.1", port=5050, cafile="certs/server.crt"):
        self.host = host
        self.port = port
        self.cafile = cafile
        self.sock = None

    def connect(self):
        if self.sock:
            return

        raw = socket.create_connection((self.host, self.port), timeout=5)

        ctx = ssl.create_default_context(cafile=self.cafile)
        ctx.check_hostname = True

        self.sock = ctx.wrap_socket(raw, server_hostname="localhost")

    def close(self):
        if self.sock:
            try:
                self.sock.close()
            except Exception:
                pass
        self.sock = None

    def request(self, payload: dict) -> dict:
        try:
            self.connect()
            payload = dict(payload)
            payload.setdefault("v", 1)
            payload.setdefault("request_id", uuid.uuid4().hex)
            send_msg(self.sock, payload)
            return recv_msg(self.sock)
        except Exception:
            self.close()
            raise
