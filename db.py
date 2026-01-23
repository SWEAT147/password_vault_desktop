# db.py
import sqlite3

DB_PATH = "vault_server.db"


def connect():
    # For a threaded server, allow usage across threads.
    # Each request should still use its own connection.
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


def _add_column_if_missing(db, table: str, coldef: str):
    """
    Safely add a column to an existing table (no data loss).
    coldef example: "public_key_pem TEXT"
    """
    colname = coldef.split()[0]
    cols = [r["name"] for r in db.execute(f"PRAGMA table_info({table})").fetchall()]
    if colname not in cols:
        db.execute(f"ALTER TABLE {table} ADD COLUMN {coldef}")


def init_db():
    db = connect()

    # ---------- USERS ----------
    db.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        full_name TEXT NOT NULL,
        email TEXT NOT NULL UNIQUE,
        password_hash TEXT NOT NULL,
        role TEXT NOT NULL DEFAULT 'user',
        vault_salt TEXT NOT NULL,
        encrypted_vault_key TEXT NOT NULL,
        created_at TEXT NOT NULL DEFAULT (datetime('now'))
    )
    """)
    # sharing key columns (upgrade-safe)
    _add_column_if_missing(db, "users", "public_key_pem TEXT")
    _add_column_if_missing(db, "users", "encrypted_private_key TEXT")

    # ---------- OTP ----------
    db.execute("""
    CREATE TABLE IF NOT EXISTS otp_codes (
        user_id INTEGER NOT NULL,
        code TEXT NOT NULL,
        expires_at TEXT NOT NULL,
        attempts INTEGER NOT NULL DEFAULT 0,
        PRIMARY KEY(user_id)
    )
    """)

    # ---------- ENTRIES ----------
    db.execute("""
    CREATE TABLE IF NOT EXISTS entries (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        title TEXT NOT NULL,
        username TEXT NOT NULL,
        encrypted_password TEXT NOT NULL,
        created_at TEXT NOT NULL
    )
    """)

    # ---------- AUDIT LOG ----------
    db.execute("""
    CREATE TABLE IF NOT EXISTS audit_log (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        action TEXT NOT NULL,
        detail TEXT,
        ip TEXT,
        created_at TEXT NOT NULL DEFAULT (datetime('now'))
    )
    """)

    # ---------- LOCKOUTS ----------
    db.execute("""
    CREATE TABLE IF NOT EXISTS lockouts (
        email TEXT PRIMARY KEY,
        locked_until TEXT NOT NULL
    )
    """)

    # ---------- PASSWORD RESET ----------
    db.execute("""
    CREATE TABLE IF NOT EXISTS password_resets (
        email TEXT PRIMARY KEY,
        code TEXT NOT NULL,
        expires_at TEXT NOT NULL,
        attempts INTEGER NOT NULL DEFAULT 0
    )
    """)

    # ---------- VAULT SHARES ----------
    db.execute("""
    CREATE TABLE IF NOT EXISTS vault_shares (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        owner_id INTEGER NOT NULL,
        shared_with_id INTEGER NOT NULL,
        enc_vault_key_for_receiver TEXT NOT NULL,
        created_at TEXT NOT NULL DEFAULT (datetime('now')),
        UNIQUE(owner_id, shared_with_id)
    )
    """)

    # Helpful indexes
    db.execute("CREATE INDEX IF NOT EXISTS idx_entries_user_id ON entries(user_id)")
    db.execute("CREATE INDEX IF NOT EXISTS idx_shares_shared_with ON vault_shares(shared_with_id)")
    db.execute("CREATE INDEX IF NOT EXISTS idx_shares_owner ON vault_shares(owner_id)")

    db.commit()
    db.close()
