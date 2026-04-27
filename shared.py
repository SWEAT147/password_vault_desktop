# shared.py
import json
import socket
import struct
import base64
import os
from typing import Any, Dict
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

MAX_MSG = 2_000_000  # 2MB

# ================= PROTOCOL =================
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

# ================= SECURITY & CRYPTO =================
_ph = PasswordHasher()

def hash_master_password(pw: str) -> str:
    return _ph.hash(pw)

def verify_master_password(pw: str, pw_hash: str) -> bool:
    try:
        return _ph.verify(pw_hash, pw)
    except VerifyMismatchError:
        return False

def derive_fernet_from_password(password: str, salt: bytes) -> Fernet:
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=300_000)
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    return Fernet(key)

def generate_vault_key() -> str:
    return Fernet.generate_key().decode()

def encrypt_with_derived(derived: Fernet, data: bytes) -> bytes:
    return derived.encrypt(data)

def decrypt_with_derived(derived: Fernet, token: bytes) -> bytes:
    return derived.decrypt(token)

def encrypt_entry_password(vault_key: str, plaintext: str) -> bytes:
    f = Fernet(vault_key.encode())
    return f.encrypt(plaintext.encode())

def decrypt_entry_password(vault_key: str, token: bytes) -> str:
    f = Fernet(vault_key.encode())
    return f.decrypt(token).decode()

# ================= RSA KEYS =================
def generate_rsa_keypair():
    priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pub = priv.public_key()
    priv_pem = priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    pub_pem = pub.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return pub_pem, priv_pem

def rsa_encrypt(pub_pem: bytes, data: bytes) -> bytes:
    pub = serialization.load_pem_public_key(pub_pem)
    return pub.encrypt(
        data,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )

def rsa_decrypt(priv_pem: bytes, ciphertext: bytes) -> bytes:
    priv = serialization.load_pem_private_key(priv_pem, password=None)
    return priv.decrypt(
        ciphertext,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )