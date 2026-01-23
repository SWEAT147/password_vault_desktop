# emailer.py
import smtplib
from email.message import EmailMessage
from config import EMAIL_ENABLED, SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASS, MAIL_FROM

def send_otp_email(to_email: str, code: str) -> None:
    """
    Sends OTP code via SMTP.
    If EMAIL_ENABLED=0, raises RuntimeError (caller can fallback to console log).
    """
    if not EMAIL_ENABLED:
        raise RuntimeError("EMAIL_ENABLED=0")

    if not (SMTP_HOST and SMTP_USER and SMTP_PASS and MAIL_FROM):
        raise RuntimeError("SMTP config missing (SMTP_HOST/SMTP_USER/SMTP_PASS/MAIL_FROM)")

    msg = EmailMessage()
    msg["Subject"] = "Your Password Vault OTP Code"
    msg["From"] = MAIL_FROM
    msg["To"] = to_email
    msg.set_content(f"Your OTP code is: {code}\n\nIt expires in 5 minutes.")

    with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=10) as s:
        s.starttls()
        s.login(SMTP_USER, SMTP_PASS)
        s.send_message(msg)
