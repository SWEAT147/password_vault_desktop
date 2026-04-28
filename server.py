# server.py
import os
import ssl
import socket
import threading
import secrets
import logging
import sqlite3
import smtplib
import ipaddress
import traceback
from datetime import datetime, timedelta, timezone
from email.message import EmailMessage

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from shared import (
    send_msg, recv_msg, hash_master_password, verify_master_password,
    derive_fernet_from_password, encrypt_with_derived, generate_vault_key
)

# ================= CONFIG & CONSTANTS =================
HOST = os.getenv("VAULT_HOST", "127.0.0.1")
PORT = int(os.getenv("VAULT_PORT", "5050"))

EMAIL_ENABLED = True
SMTP_HOST = "smtp.gmail.com"
SMTP_PORT = 587

SMTP_USER = "YOUR_EMAIL_HERE@gmail.com"
SMTP_PASS = "YOUR_APP_PASSWORD_HERE"

MAIL_FROM = SMTP_USER

LOGIN_MAX_ATTEMPTS = 5
LOGIN_WINDOW_SEC = 120
LOCKOUT_MINUTES = 5
OTP_MAX_ATTEMPTS = 5
RESET_MAX_ATTEMPTS = 5
SESSION_TTL_MIN = 60


# ================= UTILS & HELPERS =================
def now_utc() -> datetime: return datetime.now(timezone.utc).replace(tzinfo=None)


def iso(dt: datetime) -> str: return dt.replace(microsecond=0).isoformat()


def parse_iso(s: str) -> datetime: return datetime.fromisoformat(s)


def get_ip(addr): return addr[0] if addr else None


def gen_otp() -> str: return f"{secrets.randbelow(10 ** 6):06d}"


def otp_expires(minutes=5) -> str: return (now_utc() + timedelta(minutes=minutes)).isoformat()


def is_expired(expires_at_iso: str) -> bool: return now_utc() > datetime.fromisoformat(expires_at_iso)


def send_otp_email(to_email: str, code: str) -> None:
    if not EMAIL_ENABLED: raise RuntimeError("EMAIL_ENABLED=0")
    if not (SMTP_HOST and SMTP_USER and SMTP_PASS and MAIL_FROM): raise RuntimeError("SMTP config missing")
    msg = EmailMessage()
    msg["Subject"] = "Your Password Vault OTP Code"
    msg["From"] = MAIL_FROM
    msg["To"] = to_email
    msg.set_content(f"Your OTP code is: {code}\n\nIt expires in 5 minutes.")
    with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=10) as s:
        s.starttls()
        s.login(SMTP_USER, SMTP_PASS)
        s.send_message(msg)


def ensure_certs(out_dir="certs"):
    os.makedirs(out_dir, exist_ok=True)
    crt_path = os.path.join(out_dir, "server.crt")
    key_path = os.path.join(out_dir, "server.key")
    if os.path.exists(crt_path) and os.path.exists(key_path): return crt_path, key_path

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "IL"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "PasswordVault"),
        x509.NameAttribute(NameOID.COMMON_NAME, "localhost"),
    ])

    current_time = now_utc()
    cert = (x509.CertificateBuilder().subject_name(subject).issuer_name(issuer).public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(current_time - timedelta(days=1))
            .not_valid_after(current_time + timedelta(days=3650))
            .add_extension(
        x509.SubjectAlternativeName([x509.DNSName("localhost"), x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]),
        critical=False)
            .sign(key, hashes.SHA256()))

    with open(key_path, "wb") as f: f.write(
        key.private_bytes(encoding=serialization.Encoding.PEM, format=serialization.PrivateFormat.TraditionalOpenSSL,
                          encryption_algorithm=serialization.NoEncryption()))
    with open(crt_path, "wb") as f: f.write(cert.public_bytes(serialization.Encoding.PEM))
    return crt_path, key_path


# ================= DATABASE =================
class DatabaseManager:
    def __init__(self, db_path="vault_server.db"):
        self.db_path = db_path
        self._lock = threading.Lock()

    def connect(self):
        conn = sqlite3.connect(self.db_path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        return conn

    def _add_col(self, db, table, coldef):
        colname = coldef.split()[0]
        cols = [r["name"] for r in db.execute(f"PRAGMA table_info({table})").fetchall()]
        if colname not in cols: db.execute(f"ALTER TABLE {table} ADD COLUMN {coldef}")

    def init_db(self):
        with self._lock:
            db = self.connect()
            db.execute(
                """CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, full_name TEXT NOT NULL, email TEXT NOT NULL UNIQUE, password_hash TEXT NOT NULL, role TEXT NOT NULL DEFAULT 'user', vault_salt TEXT NOT NULL, encrypted_vault_key TEXT NOT NULL, created_at TEXT NOT NULL DEFAULT (datetime('now')))""")
            self._add_col(db, "users", "public_key_pem TEXT")
            self._add_col(db, "users", "encrypted_private_key TEXT")
            db.execute(
                "CREATE TABLE IF NOT EXISTS otp_codes (user_id INTEGER NOT NULL, code TEXT NOT NULL, expires_at TEXT NOT NULL, attempts INTEGER NOT NULL DEFAULT 0, PRIMARY KEY(user_id))")
            db.execute(
                "CREATE TABLE IF NOT EXISTS entries (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL, title TEXT NOT NULL, username TEXT NOT NULL, encrypted_password TEXT NOT NULL, created_at TEXT NOT NULL)")
            db.execute(
                "CREATE TABLE IF NOT EXISTS audit_log (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, action TEXT NOT NULL, detail TEXT, ip TEXT, created_at TEXT NOT NULL DEFAULT (datetime('now')))")
            db.execute("CREATE TABLE IF NOT EXISTS lockouts (email TEXT PRIMARY KEY, locked_until TEXT NOT NULL)")
            db.execute(
                "CREATE TABLE IF NOT EXISTS password_resets (email TEXT PRIMARY KEY, code TEXT NOT NULL, expires_at TEXT NOT NULL, attempts INTEGER NOT NULL DEFAULT 0)")

            # טבלה חדשה לשיתוף סיסמאות ספציפיות
            db.execute("""CREATE TABLE IF NOT EXISTS shared_entries (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                sender_id INTEGER NOT NULL,
                receiver_id INTEGER NOT NULL,
                title TEXT NOT NULL,
                username TEXT NOT NULL,
                encrypted_password_rsa TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT (datetime('now'))
            )""")

            db.execute("CREATE INDEX IF NOT EXISTS idx_entries_user_id ON entries(user_id)")
            db.commit()
            db.close()

    def audit(self, db, user_id, action, detail, ip):
        db.execute("INSERT INTO audit_log(user_id,action,detail,ip) VALUES(?,?,?,?)", (user_id, action, detail, ip))


# ================= SERVER LOGIC =================
class VaultServer:
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.db = DatabaseManager()
        self.db.init_db()
        self._sessions, self._sessions_lock = {}, threading.Lock()
        self._login_attempts, self._login_lock = {}, threading.Lock()

        self.routes_public = {"signup": self.handle_signup, "login_start": self.handle_login_start,
                              "login_verify": self.handle_login_verify, "reset_start": self.handle_reset_start,
                              "reset_finish": self.handle_reset_finish}

        self.routes_auth = {
            "entries_list": self.handle_entries_list,
            "entry_create": self.handle_entry_create,
            "entry_update": self.handle_entry_update,
            "entry_delete": self.handle_entry_delete,
            "change_password": self.handle_change_password,
            "keys_set": self.handle_keys_set,
            "keys_get_public": self.handle_keys_get_public,
            "share_entry_create": self.handle_share_entry_create,
            "shared_entries_list": self.handle_shared_entries_list,
            "admin_get_users": self.handle_admin_get_users,
            "admin_set_role": self.handle_admin_set_role,
            "admin_delete_user": self.handle_admin_delete_user
        }

    def reply(self, conn, req, payload: dict):
        payload = dict(payload)
        payload.setdefault("v", 1)
        if isinstance(req, dict) and "request_id" in req: payload["request_id"] = req["request_id"]
        send_msg(conn, payload)

    def is_locked_out(self, email: str) -> bool:
        db = self.db.connect()
        row = db.execute("SELECT locked_until FROM lockouts WHERE email=?", (email,)).fetchone()
        db.close()
        return (parse_iso(row["locked_until"]) > now_utc()) if row else False

    def set_lockout(self, email: str):
        db = self.db.connect()
        db.execute(
            "INSERT INTO lockouts(email,locked_until) VALUES(?,?) ON CONFLICT(email) DO UPDATE SET locked_until=excluded.locked_until",
            (email, iso(now_utc() + timedelta(minutes=LOCKOUT_MINUTES))))
        db.commit()
        db.close()

    def rate_limit_login(self, ip: str, email: str) -> bool:
        key = f"{ip}|{email}".lower()
        t = now_utc().timestamp()
        with self._login_lock:
            arr = [x for x in self._login_attempts.get(key, []) if t - x <= LOGIN_WINDOW_SEC]
            if len(arr) >= LOGIN_MAX_ATTEMPTS:
                self._login_attempts[key] = arr
                return False
            arr.append(t)
            self._login_attempts[key] = arr
            return True

    def new_session(self, user_id: int, email: str, role: str) -> str:
        token = secrets.token_urlsafe(32)
        with self._sessions_lock:
            self._sessions[token] = {"user_id": user_id, "email": email, "role": role,
                                     "expires_at": iso(now_utc() + timedelta(minutes=SESSION_TTL_MIN))}
        return token

    def get_session(self, token: str):
        if not token: return None
        with self._sessions_lock:
            s = self._sessions.get(token)
            if s and parse_iso(s["expires_at"]) > now_utc(): return s
            self._sessions.pop(token, None)
            return None

    def drop_session(self, token: str):
        if not token: return
        with self._sessions_lock:
            self._sessions.pop(token, None)

    def _send_otp(self, email: str, code: str):
        try:
            send_otp_email(email, code)
        except Exception:
            print(f"[DEV] Email failed. OTP for {email}: {code}")

    def _is_admin(self, db, user_id: int) -> bool:
        u = db.execute("SELECT role FROM users WHERE id=?", (user_id,)).fetchone()
        return u and u["role"] == "admin"

    # --- HANDLERS ---
    def handle_signup(self, conn, req, ip):
        full_name, email, pw = (req.get("full_name") or "").strip(), (req.get("email") or "").strip().lower(), req.get(
            "password") or ""
        if not full_name or not email or not pw: return self.reply(conn, req, {"ok": False, "error": "Missing fields"})
        db = self.db.connect()
        if db.execute("SELECT 1 FROM users WHERE email=?", (email,)).fetchone():
            db.close()
            return self.reply(conn, req, {"ok": False, "error": "User already exists"})
        pw_hash, salt = hash_master_password(pw), os.urandom(16)
        derived = derive_fernet_from_password(pw, salt)
        enc_vault_key = encrypt_with_derived(derived, generate_vault_key().encode())
        db.execute(
            "INSERT INTO users(full_name,email,password_hash,role,vault_salt,encrypted_vault_key) VALUES(?,?,?,?,?,?)",
            (full_name, email, pw_hash, "user", salt.hex(), enc_vault_key.hex()))
        self.db.audit(db, None, "signup", f"email={email}", ip)
        db.commit()
        db.close()
        self.reply(conn, req, {"ok": True})

    def handle_login_start(self, conn, req, ip):
        email, pw = (req.get("email") or "").strip().lower(), req.get("password") or ""
        if not email or not pw: return self.reply(conn, req, {"ok": False, "error": "Missing email/password"})
        if self.is_locked_out(email): return self.reply(conn, req, {"ok": False, "error": "Locked. Try later."})
        if not self.rate_limit_login(ip or "unknown", email):
            self.set_lockout(email)
            return self.reply(conn, req, {"ok": False, "error": "Too many attempts. Locked."})

        db = self.db.connect()
        u = db.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
        if not u or not verify_master_password(pw, u["password_hash"]):
            self.db.audit(db, u["id"] if u else None, "login_fail", f"email={email}", ip)
            db.commit()
            db.close()
            return self.reply(conn, req, {"ok": False, "error": "Invalid login"})

        code = gen_otp()
        db.execute("DELETE FROM otp_codes WHERE user_id=?", (u["id"],))
        db.execute("INSERT INTO otp_codes(user_id,code,expires_at) VALUES(?,?,?)", (u["id"], code, otp_expires(5)))
        db.commit()
        db.close()
        self._send_otp(email, code)
        self.reply(conn, req, {"ok": True, "user_id": u["id"]})

    def handle_login_verify(self, conn, req, ip):
        uid, otp = req.get("user_id"), (req.get("otp") or "").strip()
        db = self.db.connect()
        u = db.execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()
        row = db.execute("SELECT * FROM otp_codes WHERE user_id=?", (uid,)).fetchone()
        if not u or not row or is_expired(row["expires_at"]) or row["code"] != otp or row[
            "attempts"] >= OTP_MAX_ATTEMPTS:
            if row: db.execute("UPDATE otp_codes SET attempts=attempts+1 WHERE user_id=?", (uid,))
            db.commit()
            db.close()
            return self.reply(conn, req, {"ok": False, "error": "OTP invalid/expired"})

        db.execute("DELETE FROM otp_codes WHERE user_id=?", (uid,))
        k = db.execute("SELECT public_key_pem, encrypted_private_key FROM users WHERE id=?", (u["id"],)).fetchone()
        db.commit()
        db.close()

        session_token = self.new_session(u["id"], u["email"], u["role"])
        self.reply(conn, req, {"ok": True, "email": u["email"], "role": u["role"], "session_token": session_token,
                               "vault_salt": u["vault_salt"], "encrypted_vault_key": u["encrypted_vault_key"],
                               "public_key_pem": k["public_key_pem"] if k else "",
                               "encrypted_private_key": k["encrypted_private_key"] if k else ""})

    def handle_reset_start(self, conn, req, ip):
        email = (req.get("email") or "").strip().lower()
        db = self.db.connect()
        u = db.execute("SELECT id FROM users WHERE email=?", (email,)).fetchone()
        if not u:
            db.close()
            return self.reply(conn, req, {"ok": True})
        code = str(secrets.randbelow(900000) + 100000)
        db.execute(
            "INSERT INTO password_resets(email,code,expires_at,attempts) VALUES(?,?,?,0) ON CONFLICT(email) DO UPDATE SET code=excluded.code, expires_at=excluded.expires_at, attempts=0",
            (email, code, iso(now_utc() + timedelta(minutes=5))))
        db.commit()
        db.close()
        self._send_otp(email, code)
        self.reply(conn, req, {"ok": True})

    def handle_reset_finish(self, conn, req, ip):
        email, code = (req.get("email") or "").strip().lower(), (req.get("code") or "").strip()
        new_password_hash, new_vault_salt, new_encrypted_vault_key = (req.get("new_password_hash") or "").strip(), (
                    req.get("new_vault_salt") or "").strip(), (req.get("new_encrypted_vault_key") or "").strip()
        db = self.db.connect()
        u = db.execute("SELECT id FROM users WHERE email=?", (email,)).fetchone()
        r = db.execute("SELECT * FROM password_resets WHERE email=?", (email,)).fetchone()
        if not u or not r or r["code"] != code or parse_iso(r["expires_at"]) < now_utc():
            db.close()
            return self.reply(conn, req, {"ok": False, "error": "Invalid/expired code"})
        db.execute("UPDATE users SET password_hash=?, vault_salt=?, encrypted_vault_key=? WHERE email=?",
                   (new_password_hash, new_vault_salt, new_encrypted_vault_key, email))
        db.execute("DELETE FROM entries WHERE user_id=?", (u["id"],))
        db.execute("DELETE FROM password_resets WHERE email=?", (email,))
        db.commit()
        db.close()
        self.reply(conn, req, {"ok": True})

    def handle_entries_list(self, conn, req, ip, user_id):
        db = self.db.connect()
        rows = db.execute(
            "SELECT id,title,username,encrypted_password,created_at FROM entries WHERE user_id=? ORDER BY id DESC",
            (user_id,)).fetchall()
        db.close()
        self.reply(conn, req, {"ok": True, "entries": [dict(r) for r in rows]})

    def handle_entry_create(self, conn, req, ip, user_id):
        title, username, enc_pw = (req.get("title") or "").strip(), (req.get("username") or "").strip(), (
                    req.get("encrypted_password") or "").strip()
        db = self.db.connect()
        db.execute("INSERT INTO entries(user_id,title,username,encrypted_password,created_at) VALUES(?,?,?,?,?)",
                   (user_id, title, username, enc_pw, iso(now_utc())))
        db.commit()
        db.close()
        self.reply(conn, req, {"ok": True})

    def handle_entry_update(self, conn, req, ip, user_id):
        db = self.db.connect()
        db.execute("UPDATE entries SET title=?, username=?, encrypted_password=? WHERE id=? AND user_id=?",
                   (req.get("title"), req.get("username"), req.get("encrypted_password"), req.get("id"), user_id))
        db.commit()
        db.close()
        self.reply(conn, req, {"ok": True})

    def handle_entry_delete(self, conn, req, ip, user_id):
        db = self.db.connect()
        db.execute("DELETE FROM entries WHERE id=? AND user_id=?", (req.get("id"), user_id))
        db.commit()
        db.close()
        self.reply(conn, req, {"ok": True})

    def handle_change_password(self, conn, req, ip, user_id):
        db = self.db.connect()
        db.execute("UPDATE users SET password_hash=?, vault_salt=?, encrypted_vault_key=? WHERE id=?",
                   (req.get("new_password_hash"), req.get("new_vault_salt"), req.get("new_encrypted_vault_key"),
                    user_id))
        db.commit()
        db.close()
        self.reply(conn, req, {"ok": True})

    def handle_keys_set(self, conn, req, ip, user_id):
        db = self.db.connect()
        db.execute("UPDATE users SET public_key_pem=?, encrypted_private_key=? WHERE id=?",
                   (req.get("public_key_pem"), req.get("encrypted_private_key"), user_id))
        db.commit()
        db.close()
        self.reply(conn, req, {"ok": True})

    def handle_keys_get_public(self, conn, req, ip, user_id):
        db = self.db.connect()
        u = db.execute("SELECT public_key_pem FROM users WHERE email=?", (req.get("email").strip().lower(),)).fetchone()
        db.close()
        if not u or not u["public_key_pem"]: return self.reply(conn, req,
                                                               {"ok": False, "error": "Receiver has no keys"})
        self.reply(conn, req, {"ok": True, "public_key_pem": u["public_key_pem"]})

    # --- שיטת שיתוף חדשה: סיסמה ספציפית ---
    def handle_share_entry_create(self, conn, req, ip, user_id):
        to_email, title, username, enc_rsa = req.get("to_email").strip().lower(), req.get("title"), req.get(
            "username"), req.get("encrypted_password_rsa")
        db = self.db.connect()
        receiver = db.execute("SELECT id FROM users WHERE email=?", (to_email,)).fetchone()
        if not receiver:
            db.close()
            return self.reply(conn, req, {"ok": False, "error": "No such user"})
        db.execute(
            "INSERT INTO shared_entries(sender_id, receiver_id, title, username, encrypted_password_rsa) VALUES(?,?,?,?,?)",
            (user_id, receiver["id"], title, username, enc_rsa))
        db.commit()
        db.close()
        self.reply(conn, req, {"ok": True})

    def handle_shared_entries_list(self, conn, req, ip, user_id):
        db = self.db.connect()
        rows = db.execute("""SELECT se.*, u.email AS sender_email FROM shared_entries se 
                          JOIN users u ON u.id = se.sender_id 
                          WHERE receiver_id=? ORDER BY se.id DESC""", (user_id,)).fetchall()
        db.close()
        self.reply(conn, req, {"ok": True, "shared": [dict(r) for r in rows]})

    # --- ADMIN ---
    def handle_admin_get_users(self, conn, req, ip, user_id):
        db = self.db.connect()
        if not self._is_admin(db, user_id):
            db.close()
            return self.reply(conn, req, {"ok": False, "error": "Admins Only"})
        rows = db.execute("SELECT id, full_name, email, role, created_at FROM users ORDER BY id DESC").fetchall()
        db.close()
        self.reply(conn, req, {"ok": True, "users": [dict(r) for r in rows]})

    def handle_admin_set_role(self, conn, req, ip, user_id):
        db = self.db.connect()
        if not self._is_admin(db, user_id):
            db.close()
            return self.reply(conn, req, {"ok": False, "error": "Admins Only"})
        db.execute("UPDATE users SET role=? WHERE id=?", (req.get("new_role"), req.get("target_id")))
        db.commit()
        db.close()
        self.reply(conn, req, {"ok": True})

    def handle_admin_delete_user(self, conn, req, ip, user_id):
        db = self.db.connect()
        if not self._is_admin(db, user_id):
            db.close()
            return self.reply(conn, req, {"ok": False, "error": "Admins Only"})
        tid = req.get("target_id")
        db.execute("DELETE FROM users WHERE id=?", (tid,))
        db.execute("DELETE FROM entries WHERE user_id=?", (tid,))
        db.execute("DELETE FROM shared_entries WHERE sender_id=? OR receiver_id=?", (tid, tid))
        db.commit()
        db.close()
        self.reply(conn, req, {"ok": True})

    def handle_client(self, conn: ssl.SSLSocket, addr):
        ip = get_ip(addr)
        try:
            while True:
                req = recv_msg(conn)
                action, token = req.get("action"), req.get("session_token")
                if action == "logout":
                    if token:
                        with self._sessions_lock: self._sessions.pop(token, None)
                    self.reply(conn, req, {"ok": True})
                    continue
                if action in self.routes_auth:
                    s = self.get_session(token)
                    if not s:
                        self.reply(conn, req, {"ok": False, "error": "Not authenticated"})
                    else:
                        self.routes_auth[action](conn, req, ip, s["user_id"])
                elif action in self.routes_public:
                    self.routes_public[action](conn, req, ip)
        except Exception:
            pass
        finally:
            try:
                conn.close()
            except Exception:
                pass

    def start(self):
        logging.basicConfig(filename="server.log", level=logging.INFO)
        crt, key = ensure_certs()
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(crt, key)
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((self.host, self.port))
        sock.listen(50)
        print(f"Server on {self.host}:{self.port}")
        while True:
            client_sock, addr = sock.accept()
            try:
                tls_conn = context.wrap_socket(client_sock, server_side=True)
            except Exception:
                continue
            threading.Thread(target=self.handle_client, args=(tls_conn, addr), daemon=True).start()


if __name__ == "__main__":
    VaultServer(HOST, PORT).start()