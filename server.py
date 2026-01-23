# server.py
import os
import ssl
import socket
import threading
import secrets
import logging
from datetime import datetime, timedelta

from protocol import send_msg, recv_msg
from db import init_db, connect
from security import (
    hash_master_password, verify_master_password,
    derive_fernet_from_password,
    encrypt_with_derived,
    generate_vault_key
)
from otp import gen_otp, otp_expires, is_expired
from generate_cert import ensure_certs

# Email OTP / reset
from emailer import send_otp_email
from config import EMAIL_ENABLED

HOST = os.getenv("VAULT_HOST", "127.0.0.1")
PORT = int(os.getenv("VAULT_PORT", "5050"))

# -------- security policy --------
LOGIN_MAX_ATTEMPTS = 5
LOGIN_WINDOW_SEC = 120
LOCKOUT_MINUTES = 5

OTP_MAX_ATTEMPTS = 5
RESET_MAX_ATTEMPTS = 5

SESSION_TTL_MIN = 60

# token -> dict(user_id,email,role,expires_at)
_sessions = {}
_sessions_lock = threading.Lock()

# in-memory rate limit (per ip+email)
_login_attempts = {}
_login_lock = threading.Lock()


def now_utc() -> datetime:
    return datetime.utcnow()


def iso(dt: datetime) -> str:
    return dt.replace(microsecond=0).isoformat()


def parse_iso(s: str) -> datetime:
    return datetime.fromisoformat(s)


def get_ip(addr):
    try:
        return addr[0]
    except Exception:
        return None


def audit(db, user_id, action, detail, ip):
    db.execute(
        "INSERT INTO audit_log(user_id,action,detail,ip) VALUES(?,?,?,?)",
        (user_id, action, detail, ip)
    )


def reply(conn, req, payload: dict):
    payload = dict(payload)
    payload.setdefault("v", 1)
    if isinstance(req, dict) and "request_id" in req:
        payload["request_id"] = req["request_id"]
    send_msg(conn, payload)


def is_locked_out(email: str) -> bool:
    db = connect()
    row = db.execute("SELECT locked_until FROM lockouts WHERE email=?", (email,)).fetchone()
    db.close()
    if not row:
        return False
    try:
        return parse_iso(row["locked_until"]) > now_utc()
    except Exception:
        return False


def set_lockout(email: str):
    until = iso(now_utc() + timedelta(minutes=LOCKOUT_MINUTES))
    db = connect()
    db.execute(
        "INSERT INTO lockouts(email,locked_until) VALUES(?,?) "
        "ON CONFLICT(email) DO UPDATE SET locked_until=excluded.locked_until",
        (email, until)
    )
    db.commit()
    db.close()


def rate_limit_login(ip: str, email: str) -> bool:
    """Return True if allowed, False if blocked."""
    key = f"{ip}|{email}".lower()
    t = now_utc().timestamp()
    with _login_lock:
        arr = _login_attempts.get(key, [])
        arr = [x for x in arr if t - x <= LOGIN_WINDOW_SEC]
        if len(arr) >= LOGIN_MAX_ATTEMPTS:
            _login_attempts[key] = arr
            return False
        arr.append(t)
        _login_attempts[key] = arr
        return True


def new_session(user_id: int, email: str, role: str) -> str:
    token = secrets.token_urlsafe(32)
    exp = iso(now_utc() + timedelta(minutes=SESSION_TTL_MIN))
    with _sessions_lock:
        _sessions[token] = {"user_id": user_id, "email": email, "role": role, "expires_at": exp}
    return token


def get_session(token: str):
    if not token:
        return None
    with _sessions_lock:
        s = _sessions.get(token)
        if not s:
            return None
        try:
            if parse_iso(s["expires_at"]) < now_utc():
                _sessions.pop(token, None)
                return None
        except Exception:
            _sessions.pop(token, None)
            return None
        return s


def drop_session(token: str):
    if not token:
        return
    with _sessions_lock:
        _sessions.pop(token, None)


def _send_otp(email: str, code: str):
    """
    Production behavior: send via SMTP.
    Dev fallback: if email is not enabled/configured, print to console (not returned to client).
    """
    try:
        send_otp_email(email, code)
        return
    except Exception as e:
        # Dev/local fallback only
        logging.warning("OTP_EMAIL_FAILED email=%s err=%s", email, str(e))
        print(f"[DEV] OTP for {email}: {code}")


def _send_reset(email: str, code: str):
    """
    Same policy as OTP: email when enabled, else console fallback.
    """
    # Reuse same email function but change subject/content? keep simple:
    try:
        # If you want a different email template, add send_reset_email() in emailer.py
        send_otp_email(email, code)
        return
    except Exception as e:
        logging.warning("RESET_EMAIL_FAILED email=%s err=%s", email, str(e))
        print(f"[DEV] RESET CODE for {email}: {code}")


def handle_client(conn: ssl.SSLSocket, addr):
    ip = get_ip(addr)

    try:
        while True:
            req = recv_msg(conn)
            action = req.get("action")
            token = req.get("session_token")

            # =========================
            # SIGNUP
            # =========================
            if action == "signup":
                full_name = (req.get("full_name") or "").strip()
                email = (req.get("email") or "").strip().lower()
                pw = req.get("password") or ""

                if not full_name or not email or not pw:
                    reply(conn, req, {"ok": False, "error": "Missing fields"})
                    continue

                db = connect()
                if db.execute("SELECT 1 FROM users WHERE email=?", (email,)).fetchone():
                    reply(conn, req, {"ok": False, "error": "User already exists"})
                    db.close()
                    continue

                pw_hash = hash_master_password(pw)
                salt = os.urandom(16)
                derived = derive_fernet_from_password(pw, salt)

                vault_key = generate_vault_key()
                enc_vault_key = encrypt_with_derived(derived, vault_key.encode())

                db.execute(
                    "INSERT INTO users(full_name,email,password_hash,role,vault_salt,encrypted_vault_key) "
                    "VALUES(?,?,?,?,?,?)",
                    (full_name, email, pw_hash, "user", salt.hex(), enc_vault_key.hex())
                )
                audit(db, None, "signup", f"email={email}", ip)
                db.commit()
                db.close()

                logging.info("SIGNUP ip=%s email=%s", ip, email)
                reply(conn, req, {"ok": True})

            # =========================
            # LOGIN START (rate limit + lockout)
            # =========================
            elif action == "login_start":
                email = (req.get("email") or "").strip().lower()
                pw = req.get("password") or ""

                if not email or not pw:
                    reply(conn, req, {"ok": False, "error": "Missing email/password"})
                    continue

                if is_locked_out(email):
                    reply(conn, req, {"ok": False, "error": "Locked. Try later."})
                    continue

                if not rate_limit_login(ip or "unknown", email):
                    set_lockout(email)
                    reply(conn, req, {"ok": False, "error": "Too many attempts. Locked."})
                    continue

                db = connect()
                u = db.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()

                if not u or not verify_master_password(pw, u["password_hash"]):
                    audit(db, u["id"] if u else None, "login_fail", f"email={email}", ip)
                    db.commit()
                    db.close()
                    logging.warning("LOGIN_FAIL ip=%s email=%s", ip, email)
                    reply(conn, req, {"ok": False, "error": "Invalid login"})
                    continue

                code = gen_otp()
                exp = otp_expires(5)

                db.execute("DELETE FROM otp_codes WHERE user_id=?", (u["id"],))
                db.execute(
                    "INSERT INTO otp_codes(user_id,code,expires_at,attempts) VALUES(?,?,?,0)",
                    (u["id"], code, exp)
                )
                audit(db, u["id"], "login_ok_otp_sent", None, ip)
                db.commit()
                db.close()

                logging.info("OTP_CREATED ip=%s email=%s user_id=%s", ip, email, u["id"])

                # Send OTP to email (or dev console fallback)
                _send_otp(email, code)

                # IMPORTANT: do NOT return OTP to client
                reply(conn, req, {"ok": True, "user_id": u["id"]})

            # =========================
            # LOGIN VERIFY (OTP)
            # =========================
            elif action == "login_verify":
                uid = req.get("user_id")
                otp = (req.get("otp") or "").strip()

                if not uid or not otp:
                    reply(conn, req, {"ok": False, "error": "Missing fields"})
                    continue

                db = connect()
                u = db.execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()
                row = db.execute("SELECT * FROM otp_codes WHERE user_id=?", (uid,)).fetchone()

                if not u or not row:
                    audit(db, uid, "otp_fail", "missing_row", ip)
                    db.commit()
                    db.close()
                    reply(conn, req, {"ok": False, "error": "OTP invalid/expired"})
                    continue

                if row["attempts"] >= OTP_MAX_ATTEMPTS:
                    audit(db, uid, "otp_fail", "too_many_attempts", ip)
                    db.commit()
                    db.close()
                    reply(conn, req, {"ok": False, "error": "Too many OTP attempts"})
                    continue

                if is_expired(row["expires_at"]) or row["code"] != otp:
                    db.execute("UPDATE otp_codes SET attempts=attempts+1 WHERE user_id=?", (uid,))
                    audit(db, uid, "otp_fail", "wrong_or_expired", ip)
                    db.commit()
                    db.close()
                    reply(conn, req, {"ok": False, "error": "OTP invalid/expired"})
                    continue

                db.execute("DELETE FROM otp_codes WHERE user_id=?", (uid,))
                audit(db, uid, "otp_ok_login", None, ip)

                # include sharing key material if exists
                k = db.execute(
                    "SELECT public_key_pem, encrypted_private_key FROM users WHERE id=?",
                    (u["id"],)
                ).fetchone()

                db.commit()
                db.close()

                session_token = new_session(u["id"], u["email"], u["role"])
                logging.info("LOGIN_OK ip=%s email=%s user_id=%s", ip, u["email"], u["id"])

                reply(conn, req, {
                    "ok": True,
                    "email": u["email"],
                    "role": u["role"],
                    "session_token": session_token,
                    "vault_salt": u["vault_salt"],
                    "encrypted_vault_key": u["encrypted_vault_key"],
                    "public_key_pem": (k["public_key_pem"] or "") if k else "",
                    "encrypted_private_key": (k["encrypted_private_key"] or "") if k else ""
                })

            # =========================
            # PASSWORD RESET (production-style: send code via email or dev console)
            # =========================
            elif action == "reset_start":
                email = (req.get("email") or "").strip().lower()
                if not email:
                    reply(conn, req, {"ok": False, "error": "Missing email"})
                    continue

                db = connect()
                u = db.execute("SELECT id FROM users WHERE email=?", (email,)).fetchone()
                if not u:
                    db.close()
                    # do not leak whether user exists (optional)
                    reply(conn, req, {"ok": True})
                    continue

                code = str(secrets.randbelow(900000) + 100000)  # 6 digits
                exp = iso(now_utc() + timedelta(minutes=5))

                db.execute(
                    "INSERT INTO password_resets(email,code,expires_at,attempts) VALUES(?,?,?,0) "
                    "ON CONFLICT(email) DO UPDATE SET code=excluded.code, expires_at=excluded.expires_at, attempts=0",
                    (email, code, exp)
                )
                audit(db, u["id"], "reset_start", None, ip)
                db.commit()
                db.close()

                _send_reset(email, code)

                # IMPORTANT: do NOT return reset code to client
                reply(conn, req, {"ok": True})

            elif action == "reset_finish":
                email = (req.get("email") or "").strip().lower()
                code = (req.get("code") or "").strip()
                new_password_hash = (req.get("new_password_hash") or "").strip()
                new_vault_salt = (req.get("new_vault_salt") or "").strip()
                new_encrypted_vault_key = (req.get("new_encrypted_vault_key") or "").strip()

                if not all([email, code, new_password_hash, new_vault_salt, new_encrypted_vault_key]):
                    reply(conn, req, {"ok": False, "error": "Missing fields"})
                    continue

                db = connect()
                u = db.execute("SELECT id FROM users WHERE email=?", (email,)).fetchone()
                r = db.execute("SELECT * FROM password_resets WHERE email=?", (email,)).fetchone()

                if not u or not r:
                    db.close()
                    reply(conn, req, {"ok": False, "error": "Reset not started"})
                    continue

                if r["attempts"] >= RESET_MAX_ATTEMPTS:
                    db.close()
                    reply(conn, req, {"ok": False, "error": "Too many attempts"})
                    continue

                try:
                    expired = parse_iso(r["expires_at"]) < now_utc()
                except Exception:
                    expired = True

                if expired or r["code"] != code:
                    db.execute("UPDATE password_resets SET attempts=attempts+1 WHERE email=?", (email,))
                    db.commit()
                    db.close()
                    reply(conn, req, {"ok": False, "error": "Invalid/expired code"})
                    continue

                # update user password + vault metadata
                db.execute(
                    "UPDATE users SET password_hash=?, vault_salt=?, encrypted_vault_key=? WHERE email=?",
                    (new_password_hash, new_vault_salt, new_encrypted_vault_key, email)
                )

                # IMPORTANT: cannot recover old vault -> wipe entries
                db.execute("DELETE FROM entries WHERE user_id=?", (u["id"],))

                db.execute("DELETE FROM password_resets WHERE email=?", (email,))
                audit(db, u["id"], "reset_finish", "vault_wiped", ip)
                db.commit()
                db.close()

                reply(conn, req, {"ok": True})

            # =========================
            # AUTH REQUIRED ACTIONS
            # =========================
            elif action in {
                "entries_list", "entry_create", "entry_update", "entry_delete",
                "logout", "change_password",
                "keys_set", "keys_get_public",
                "share_vault_create", "share_vault_list", "share_vault_entries"
            }:
                # logout is allowed even if token expired - just drop if exists
                if action == "logout":
                    drop_session(token)
                    reply(conn, req, {"ok": True})
                    continue

                s = get_session(token)
                if not s:
                    reply(conn, req, {"ok": False, "error": "Not authenticated"})
                    continue

                user_id = s["user_id"]

                # ----- entries_list -----
                if action == "entries_list":
                    db = connect()
                    rows = db.execute(
                        "SELECT id,title,username,encrypted_password,created_at FROM entries "
                        "WHERE user_id=? ORDER BY id DESC",
                        (user_id,)
                    ).fetchall()
                    audit(db, user_id, "entries_list", f"count={len(rows)}", ip)
                    db.commit()
                    db.close()

                    out = [dict(r) for r in rows]
                    reply(conn, req, {"ok": True, "entries": out})

                # ----- entry_create -----
                elif action == "entry_create":
                    title = (req.get("title") or "").strip()
                    username = (req.get("username") or "").strip()
                    enc_pw = (req.get("encrypted_password") or "").strip()

                    if not title or not username or not enc_pw:
                        reply(conn, req, {"ok": False, "error": "Missing fields"})
                        continue

                    if len(title) > 120 or len(username) > 200 or len(enc_pw) > 10000:
                        reply(conn, req, {"ok": False, "error": "Input too long"})
                        continue

                    db = connect()
                    db.execute(
                        "INSERT INTO entries(user_id,title,username,encrypted_password,created_at) VALUES(?,?,?,?,?)",
                        (user_id, title, username, enc_pw, iso(now_utc()))
                    )
                    audit(db, user_id, "entry_create", f"title={title}", ip)
                    db.commit()
                    db.close()

                    reply(conn, req, {"ok": True})

                # ----- entry_update -----
                elif action == "entry_update":
                    entry_id = req.get("id")
                    title = (req.get("title") or "").strip()
                    username = (req.get("username") or "").strip()
                    enc_pw = (req.get("encrypted_password") or "").strip()

                    if not entry_id or not title or not username or not enc_pw:
                        reply(conn, req, {"ok": False, "error": "Missing fields"})
                        continue

                    db = connect()
                    db.execute(
                        "UPDATE entries SET title=?, username=?, encrypted_password=? WHERE id=? AND user_id=?",
                        (title, username, enc_pw, entry_id, user_id)
                    )
                    audit(db, user_id, "entry_update", f"id={entry_id}", ip)
                    db.commit()
                    db.close()

                    reply(conn, req, {"ok": True})

                # ----- entry_delete -----
                elif action == "entry_delete":
                    entry_id = req.get("id")
                    if not entry_id:
                        reply(conn, req, {"ok": False, "error": "Missing id"})
                        continue

                    db = connect()
                    db.execute("DELETE FROM entries WHERE id=? AND user_id=?", (entry_id, user_id))
                    audit(db, user_id, "entry_delete", f"id={entry_id}", ip)
                    db.commit()
                    db.close()

                    reply(conn, req, {"ok": True})

                # ----- change_password -----
                elif action == "change_password":
                    new_password_hash = (req.get("new_password_hash") or "").strip()
                    new_vault_salt = (req.get("new_vault_salt") or "").strip()
                    new_encrypted_vault_key = (req.get("new_encrypted_vault_key") or "").strip()

                    if not all([new_password_hash, new_vault_salt, new_encrypted_vault_key]):
                        reply(conn, req, {"ok": False, "error": "Missing fields"})
                        continue

                    db = connect()
                    db.execute(
                        "UPDATE users SET password_hash=?, vault_salt=?, encrypted_vault_key=? WHERE id=?",
                        (new_password_hash, new_vault_salt, new_encrypted_vault_key, user_id)
                    )
                    audit(db, user_id, "change_password", None, ip)
                    db.commit()
                    db.close()
                    reply(conn, req, {"ok": True})

                # ----- keys_set -----
                elif action == "keys_set":
                    pub = (req.get("public_key_pem") or "")
                    enc_priv = (req.get("encrypted_private_key") or "")

                    if not pub or not enc_priv:
                        reply(conn, req, {"ok": False, "error": "Missing fields"})
                        continue

                    if len(pub) > 5000 or len(enc_priv) > 30000:
                        reply(conn, req, {"ok": False, "error": "Input too long"})
                        continue

                    db = connect()
                    db.execute(
                        "UPDATE users SET public_key_pem=?, encrypted_private_key=? WHERE id=?",
                        (pub, enc_priv, user_id)
                    )
                    audit(db, user_id, "keys_set", None, ip)
                    db.commit()
                    db.close()

                    reply(conn, req, {"ok": True})

                # ----- keys_get_public -----
                elif action == "keys_get_public":
                    email = (req.get("email") or "").strip().lower()
                    if not email:
                        reply(conn, req, {"ok": False, "error": "Missing email"})
                        continue

                    db = connect()
                    u = db.execute("SELECT public_key_pem FROM users WHERE email=?", (email,)).fetchone()
                    db.close()

                    if not u or not u["public_key_pem"]:
                        reply(conn, req, {"ok": False, "error": "User has no public key yet"})
                        continue

                    reply(conn, req, {"ok": True, "public_key_pem": u["public_key_pem"]})

                # ----- share_vault_create -----
                elif action == "share_vault_create":
                    to_email = (req.get("to_email") or "").strip().lower()
                    enc_for_receiver = (req.get("enc_vault_key_for_receiver") or "").strip()

                    if not to_email or not enc_for_receiver:
                        reply(conn, req, {"ok": False, "error": "Missing fields"})
                        continue

                    if len(enc_for_receiver) > 20000:
                        reply(conn, req, {"ok": False, "error": "Input too long"})
                        continue

                    db = connect()
                    receiver = db.execute("SELECT id FROM users WHERE email=?", (to_email,)).fetchone()
                    if not receiver:
                        db.close()
                        reply(conn, req, {"ok": False, "error": "No such user"})
                        continue

                    db.execute(
                        "INSERT INTO vault_shares(owner_id,shared_with_id,enc_vault_key_for_receiver) VALUES(?,?,?) "
                        "ON CONFLICT(owner_id,shared_with_id) DO UPDATE SET enc_vault_key_for_receiver=excluded.enc_vault_key_for_receiver",
                        (user_id, receiver["id"], enc_for_receiver)
                    )
                    audit(db, user_id, "share_vault_create", f"to={to_email}", ip)
                    db.commit()
                    db.close()

                    reply(conn, req, {"ok": True})

                # ----- share_vault_list -----
                elif action == "share_vault_list":
                    db = connect()
                    rows = db.execute(
                        "SELECT vs.owner_id, u.email AS owner_email, vs.enc_vault_key_for_receiver, vs.created_at "
                        "FROM vault_shares vs JOIN users u ON u.id = vs.owner_id "
                        "WHERE vs.shared_with_id=? ORDER BY vs.id DESC",
                        (user_id,)
                    ).fetchall()
                    db.close()

                    out = [dict(r) for r in rows]
                    reply(conn, req, {"ok": True, "shared": out})

                # ----- share_vault_entries -----
                elif action == "share_vault_entries":
                    owner_id = req.get("owner_id")
                    if not owner_id:
                        reply(conn, req, {"ok": False, "error": "Missing owner_id"})
                        continue

                    db = connect()
                    ok = db.execute(
                        "SELECT 1 FROM vault_shares WHERE owner_id=? AND shared_with_id=?",
                        (owner_id, user_id)
                    ).fetchone()
                    if not ok:
                        db.close()
                        reply(conn, req, {"ok": False, "error": "Not shared with you"})
                        continue

                    rows = db.execute(
                        "SELECT id,title,username,encrypted_password,created_at FROM entries WHERE user_id=? ORDER BY id DESC",
                        (owner_id,)
                    ).fetchall()
                    db.close()

                    out = [dict(r) for r in rows]
                    reply(conn, req, {"ok": True, "entries": out})

                else:
                    reply(conn, req, {"ok": False, "error": "Unhandled action"})

            else:
                reply(conn, req, {"ok": False, "error": f"Unknown action: {action}"})

    except Exception:
        # silent drop on disconnect / bad client
        pass
    finally:
        try:
            conn.close()
        except Exception:
            pass


def main():
    init_db()

    # Log to file (remember to .gitignore server.log)
    logging.basicConfig(
        filename="server.log",
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s"
    )

    crt, key = ensure_certs()
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(crt, key)

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((HOST, PORT))
    sock.listen(50)

    print(f"Server listening on {HOST}:{PORT}")
    if EMAIL_ENABLED:
        print("Email OTP: ENABLED")
    else:
        print("Email OTP: DISABLED (DEV fallback prints OTP to console)")

    while True:
        client_sock, addr = sock.accept()
        try:
            tls_conn = context.wrap_socket(client_sock, server_side=True)
        except Exception:
            client_sock.close()
            continue

        t = threading.Thread(target=handle_client, args=(tls_conn, addr), daemon=True)
        t.start()


if __name__ == "__main__":
    main()
