import os, base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

_ph = PasswordHasher()

def hash_master_password(pw: str) -> str:
    return _ph.hash(pw)

def verify_master_password(pw: str, pw_hash: str) -> bool:
    try:
        return _ph.verify(pw_hash, pw)
    except VerifyMismatchError:
        return False

def derive_fernet_from_password(password: str, salt: bytes) -> Fernet:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=200_000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode("utf-8")))
    return Fernet(key)

def generate_vault_key() -> str:
    return Fernet.generate_key().decode("utf-8")

def encrypt_with_derived(derived: Fernet, data: bytes) -> bytes:
    return derived.encrypt(data)

def decrypt_with_derived(derived: Fernet, token: bytes) -> bytes:
    return derived.decrypt(token)

def encrypt_entry_password(vault_key: str, plaintext: str) -> bytes:
    f = Fernet(vault_key.encode("utf-8"))
    return f.encrypt(plaintext.encode("utf-8"))

def decrypt_entry_password(vault_key: str, token: bytes) -> str:
    f = Fernet(vault_key.encode("utf-8"))
    return f.decrypt(token).decode("utf-8")
