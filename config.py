# config.py
import os

def env_bool(name: str, default: str = "0") -> bool:
    return (os.getenv(name, default).strip().lower() in {"1", "true", "yes", "y", "on"})

EMAIL_ENABLED = env_bool("EMAIL_ENABLED", "0")

SMTP_HOST = os.getenv("SMTP_HOST", "")
SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
SMTP_USER = os.getenv("SMTP_USER", "")
SMTP_PASS = os.getenv("SMTP_PASS", "")

MAIL_FROM = os.getenv("MAIL_FROM", SMTP_USER)
