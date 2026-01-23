import json
import socket
import struct
from typing import Any, Dict

MAX_MSG = 2_000_000  # 2MB


def send_msg(sock: socket.socket, obj: Dict[str, Any]) -> None:
    data = json.dumps(obj, ensure_ascii=False).encode("utf-8")
    if len(data) > MAX_MSG:
        raise ValueError("Message too large")
    header = struct.pack("!I", len(data))
    sock.sendall(header + data)


def _recv_exact(sock: socket.socket, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("Disconnected")
        buf += chunk
    return buf


def recv_msg(sock: socket.socket) -> Dict[str, Any]:
    header = _recv_exact(sock, 4)
    (length,) = struct.unpack("!I", header)
    if length <= 0 or length > MAX_MSG:
        raise ValueError("Bad message length")
    data = _recv_exact(sock, length)
    return json.loads(data.decode("utf-8"))
