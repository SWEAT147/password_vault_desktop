import secrets
from datetime import datetime, timedelta

def gen_otp() -> str:
    return f"{secrets.randbelow(10**6):06d}"

def otp_expires(minutes=5) -> str:
    return (datetime.utcnow() + timedelta(minutes=minutes)).isoformat()

def is_expired(expires_at_iso: str) -> bool:
    return datetime.utcnow() > datetime.fromisoformat(expires_at_iso)
