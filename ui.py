# ui.py
from client_network import NetworkClient
import tkinter as tk
from tkinter import messagebox, simpledialog, filedialog
import string, secrets
import json
import os

from security import (
    # auth + vault
    hash_master_password,
    derive_fernet_from_password,
    encrypt_with_derived,
    decrypt_with_derived,
    generate_vault_key,
    # e2ee entries encrypt/decrypt helpers
    encrypt_entry_password,
    decrypt_entry_password,
)

from crypto_keys import generate_rsa_keypair, rsa_encrypt, rsa_decrypt


# ===================== THEME =====================
BG = "#0b0b0c"
PANEL = "#0f1012"

TEXT = "#ffffff"
MUTED = "#a9a9b3"

ENTRY_BG = "#0b0c0f"
ENTRY_FG = "#ffffff"
PLACEHOLDER_FG = "#a9a9b3"
BORDER = "#2a2b30"
FOCUS_BORDER = "#3b82f6"

BTN_BG = "#0b0c0f"
BTN_FG = "#ffffff"
BTN_BORDER = "#2a2b30"
BTN_HOVER = "#14161c"
ACCENT_BORDER = "#3b82f6"

FONT_TITLE = ("Arial", 22, "bold")
FONT_SUB = ("Arial", 12)
FONT_ENTRY = ("Arial", 13)

FIELD_H = 52
PAD_X = 12
PAD_Y = 12

EYE_W = 46  # width for eye button area


def generate_password(n=18):
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*()-_=+[]{};:,.?"
    return "".join(secrets.choice(alphabet) for _ in range(n))


def make_button(parent, text, command=None, *, primary=False, small=False) -> tk.Button:
    border = ACCENT_BORDER if primary else BTN_BORDER
    hover = "#121826" if primary else BTN_HOVER

    btn = tk.Button(
        parent,
        text=text,
        command=command,
        bg=BTN_BG,
        fg=BTN_FG,
        activebackground=hover,
        activeforeground=BTN_FG,
        relief="flat",
        bd=0,
        highlightthickness=1,
        highlightbackground=border,
        highlightcolor=border,
        font=("Arial", 11 if small else 12),
        padx=10,
        pady=8 if not small else 6,
        cursor="hand2",
    )
    btn.bind("<Enter>", lambda e: btn.configure(bg=hover))
    btn.bind("<Leave>", lambda e: btn.configure(bg=BTN_BG))
    return btn


def make_watermark_entry(parent, placeholder: str, *, is_password: bool = False, show_toggle: bool = False):
    """
    Stable watermark entry:
    - Placeholder is a label overlay (cannot be deleted)
    - Placeholder disappears only when user types
    - Optional 👁 toggle for password fields
    """
    container = tk.Frame(
        parent,
        bg=ENTRY_BG,
        highlightthickness=1,
        highlightbackground=BORDER,
        highlightcolor=BORDER,
        bd=0,
        height=FIELD_H
    )
    container.pack_propagate(False)

    var = tk.StringVar()

    entry = tk.Entry(
        container,
        textvariable=var,
        bg=ENTRY_BG,
        fg=ENTRY_FG,
        insertbackground=ENTRY_FG,
        relief="flat",
        bd=0,
        font=FONT_ENTRY,
    )

    # password masking default
    if is_password:
        entry.config(show="*")

    # layout: entry takes full width minus padding and optional eye button
    right_pad = EYE_W if (is_password and show_toggle) else 0
    entry.place(
        x=PAD_X,
        y=PAD_Y,
        relwidth=1,
        width=-(2 * PAD_X + right_pad),
        height=FIELD_H - 2 * PAD_Y
    )

    ph = tk.Label(
        container,
        text=placeholder,
        fg=PLACEHOLDER_FG,
        bg=ENTRY_BG,
        font=FONT_ENTRY,
        anchor="w"
    )
    ph.place(x=PAD_X, y=PAD_Y, height=FIELD_H - 2 * PAD_Y)

    def refresh(*_):
        if var.get():
            ph.place_forget()
        else:
            ph.place(x=PAD_X, y=PAD_Y, height=FIELD_H - 2 * PAD_Y)

    var.trace_add("write", refresh)
    ph.bind("<Button-1>", lambda e: entry.focus_set())

    def on_focus_in(_):
        container.configure(highlightbackground=FOCUS_BORDER, highlightcolor=FOCUS_BORDER)

    def on_focus_out(_):
        container.configure(highlightbackground=BORDER, highlightcolor=BORDER)
        refresh()

    entry.bind("<FocusIn>", on_focus_in)
    entry.bind("<FocusOut>", on_focus_out)

    # eye toggle
    if is_password and show_toggle:
        state = {"shown": False}

        def toggle():
            state["shown"] = not state["shown"]
            entry.config(show="" if state["shown"] else "*")

        eye = tk.Button(
            container,
            text="👁",
            command=toggle,
            bg=ENTRY_BG,
            fg=MUTED,
            activebackground=ENTRY_BG,
            activeforeground=TEXT,
            relief="flat",
            bd=0,
            highlightthickness=0,
            cursor="hand2",
            font=("Arial", 14),
        )
        eye.place(relx=1.0, x=-EYE_W + 4, y=PAD_Y - 2, width=EYE_W - 8, height=FIELD_H - 2 * PAD_Y + 4)

    refresh()
    return container, entry, var


def make_otp_boxes(parent, digits=6):
    wrap = tk.Frame(parent, bg=parent["bg"])
    vars_ = [tk.StringVar() for _ in range(digits)]
    entries = []

    def only_digit(P):
        return P == "" or (len(P) <= 1 and P.isdigit())

    vcmd = (parent.register(only_digit), "%P")

    for i in range(digits):
        e = tk.Entry(
            wrap,
            textvariable=vars_[i],
            bg=ENTRY_BG,
            fg=ENTRY_FG,
            insertbackground=ENTRY_FG,
            relief="flat",
            bd=0,
            font=("Arial", 16, "bold"),
            justify="center",
            highlightthickness=1,
            highlightbackground=BORDER,
            highlightcolor=BORDER,
            width=2,
            validate="key",
            validatecommand=vcmd
        )
        e.grid(row=0, column=i, padx=6, ipady=10)
        entries.append(e)

        e.bind("<FocusIn>", lambda ev, idx=i: entries[idx].configure(highlightbackground=FOCUS_BORDER, highlightcolor=FOCUS_BORDER))
        e.bind("<FocusOut>", lambda ev, idx=i: entries[idx].configure(highlightbackground=BORDER, highlightcolor=BORDER))

        def on_key_release(event, idx=i):
            if event.keysym == "BackSpace":
                if vars_[idx].get() == "" and idx > 0:
                    entries[idx - 1].focus_set()
                    entries[idx - 1].icursor(tk.END)
                return
            if vars_[idx].get() and idx < digits - 1:
                entries[idx + 1].focus_set()

        e.bind("<KeyRelease>", on_key_release)

    def get_code():
        return "".join(v.get().strip() for v in vars_)

    def clear():
        for v in vars_:
            v.set("")
        entries[0].focus_set()

    wrap.get_code = get_code
    wrap.clear_code = clear
    wrap.focus_first = lambda: entries[0].focus_set()
    return wrap


class ScrollArea(tk.Frame):
    def __init__(self, parent, height=300):
        super().__init__(parent, bg=parent["bg"])
        self.canvas = tk.Canvas(self, bg=parent["bg"], highlightthickness=0, bd=0, height=height)
        self.vbar = tk.Scrollbar(self, orient="vertical", command=self.canvas.yview)
        self.canvas.configure(yscrollcommand=self.vbar.set)

        self.vbar.pack(side="right", fill="y")
        self.canvas.pack(side="left", fill="both", expand=True)

        self.inner = tk.Frame(self.canvas, bg=parent["bg"])
        self.win = self.canvas.create_window((0, 0), window=self.inner, anchor="nw")

        self.inner.bind("<Configure>", lambda e: self.canvas.configure(scrollregion=self.canvas.bbox("all")))
        self.canvas.bind("<Configure>", lambda e: self.canvas.itemconfig(self.win, width=e.width))


class App:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("Password Vault")
        self.root.geometry("820x640")
        self.root.configure(bg=BG)

        self.net = NetworkClient()

        # session
        self.session_user_id = None
        self.session_password = None  # master password (kept only while app open)
        self.session_token = None     # server token after OTP verify
        self.user_email = None
        self.user_role = None

        # E2EE
        self.vault_key = None  # decrypted locally after OTP (E2EE)

        # Sharing keys (RSA)
        self.public_key_pem = None      # bytes
        self.private_key_pem = None     # bytes (decrypted locally)

        self.frame = tk.Frame(root, bg=BG)
        self.frame.pack(fill="both", expand=True)

        self.panel = tk.Frame(self.frame, bg=PANEL, highlightthickness=1, highlightbackground="#1f2026")
        self.panel.place(relx=0.5, rely=0.5, anchor="center", width=620, height=560)

        self.show_login()

    def clear_panel(self):
        for w in self.panel.winfo_children():
            w.destroy()

    # -------------------------
    # Helpers
    # -------------------------
    def _require_authed(self):
        if not self.session_token:
            messagebox.showerror("Error", "Not authenticated.", parent=self.root)
            self.show_login()
            return False
        if not self.vault_key:
            messagebox.showerror("Error", "Vault is locked.", parent=self.root)
            self.show_login()
            return False
        return True

    def _ensure_rsa_keys(self, server_pub_str, server_enc_priv_hex):
        """
        Ensure we have an RSA keypair for vault sharing.
        - If server already has keys: decrypt private key using vault_key
        - Else: generate, encrypt private with vault_key, upload
        """
        # server already has key material
        if server_pub_str and server_enc_priv_hex:
            try:
                self.public_key_pem = server_pub_str.encode("utf-8")
                enc_priv = bytes.fromhex(server_enc_priv_hex)
                priv_pem_str = decrypt_entry_password(self.vault_key, enc_priv)
                self.private_key_pem = priv_pem_str.encode("utf-8")
                return
            except Exception:
                # fall back to regenerate keys
                pass

        # generate new keys
        pub_pem, priv_pem = generate_rsa_keypair()
        self.public_key_pem = pub_pem
        self.private_key_pem = priv_pem

        try:
            enc_priv_hex = encrypt_entry_password(self.vault_key, priv_pem.decode("utf-8")).hex()
            res = self.net.request({
                "action": "keys_set",
                "session_token": self.session_token,
                "public_key_pem": pub_pem.decode("utf-8"),
                "encrypted_private_key": enc_priv_hex
            })
            if not res.get("ok"):
                messagebox.showwarning("Warning", "Failed to upload sharing keys (sharing may not work).", parent=self.root)
        except Exception:
            messagebox.showwarning("Warning", "Failed to upload sharing keys (sharing may not work).", parent=self.root)

    # ================= LOGIN =================
    def show_login(self):
        self.clear_panel()

        tk.Label(self.panel, text="Password Manager", bg=PANEL, fg=TEXT, font=FONT_TITLE).pack(pady=(18, 6))
        tk.Label(self.panel, text="Sign in to your vault", bg=PANEL, fg=MUTED, font=FONT_SUB).pack(pady=(0, 16))

        email_box, email_entry, self.email_var = make_watermark_entry(self.panel, "Email")
        email_box.pack(pady=10, padx=30, fill="x")

        pw_box, pw_entry, self.pw_var = make_watermark_entry(self.panel, "Password", is_password=True, show_toggle=True)
        pw_box.pack(pady=10, padx=30, fill="x")

        make_button(self.panel, "Login", command=self.login_start, primary=True).pack(pady=(18, 10), padx=30, fill="x")

        row = tk.Frame(self.panel, bg=PANEL)
        row.pack(pady=(4, 0))
        make_button(row, "Sign up", command=self.show_signup, small=True).pack(side="left", padx=6)
        make_button(row, "Forgot password?", command=self.show_reset_start, small=True).pack(side="left", padx=6)

        email_entry.focus_set()

    # ================= SIGNUP =================
    def show_signup(self):
        self.clear_panel()

        tk.Label(self.panel, text="Sign Up", bg=PANEL, fg=TEXT, font=FONT_TITLE).pack(pady=(18, 6))
        tk.Label(self.panel, text="Create a new account", bg=PANEL, fg=MUTED, font=FONT_SUB).pack(pady=(0, 16))

        name_box, name_entry, self.fullname_var = make_watermark_entry(self.panel, "Full name")
        name_box.pack(pady=8, padx=30, fill="x")

        email_box, email_entry, self.email_var = make_watermark_entry(self.panel, "Email")
        email_box.pack(pady=8, padx=30, fill="x")

        pw_box, pw_entry, self.pw_var = make_watermark_entry(self.panel, "Password", is_password=True, show_toggle=True)
        pw_box.pack(pady=8, padx=30, fill="x")

        make_button(self.panel, "Create Account", command=self.signup_create, primary=True).pack(pady=(18, 10), padx=30, fill="x")
        make_button(self.panel, "Back", command=self.show_login, small=True).pack()

        name_entry.focus_set()

    def signup_create(self):
        full_name = self.fullname_var.get().strip()
        email = self.email_var.get().strip()
        pw = self.pw_var.get()

        if not full_name or not email or not pw:
            messagebox.showerror("Error", "Fill all fields.", parent=self.root)
            return

        try:
            res = self.net.request({
                "action": "signup",
                "full_name": full_name,
                "email": email,
                "password": pw
            })
        except Exception as e:
            messagebox.showerror("Network error", str(e), parent=self.root)
            return

        if not res.get("ok"):
            messagebox.showerror("Error", res.get("error", "Signup failed"), parent=self.root)
            return

        messagebox.showinfo("OK", "Account created.", parent=self.root)
        self.show_login()

    # ================= LOGIN + OTP =================
    def login_start(self):
        email = self.email_var.get().strip()
        pw = self.pw_var.get()

        if not email or not pw:
            messagebox.showerror("Error", "Enter email and password.", parent=self.root)
            return

        try:
            res = self.net.request({
                "action": "login_start",
                "email": email,
                "password": pw
            })
        except Exception as e:
            messagebox.showerror("Network error", str(e), parent=self.root)
            return

        if not res.get("ok"):
            messagebox.showerror("Error", res.get("error", "Login failed"), parent=self.root)
            return

        otp = res.get("otp")  # DEV
        self.session_user_id = res.get("user_id")
        self.session_password = pw

        messagebox.showinfo("DEV OTP", f"OTP Code: {otp}", parent=self.root)
        self.show_otp()

    def show_otp(self):
        self.clear_panel()

        tk.Label(self.panel, text="OTP Verification", bg=PANEL, fg=TEXT, font=FONT_TITLE).pack(pady=(18, 6))
        tk.Label(self.panel, text="Enter the 6-digit code", bg=PANEL, fg=MUTED, font=FONT_SUB).pack(pady=(0, 16))

        self.otp_boxes = make_otp_boxes(self.panel, digits=6)
        self.otp_boxes.pack(pady=10)
        self.otp_boxes.focus_first()

        make_button(self.panel, "Verify", command=self.verify_otp, primary=True).pack(pady=(18, 10), padx=30, fill="x")
        make_button(self.panel, "Back", command=self.show_login, small=True).pack()

    def verify_otp(self):
        otp = self.otp_boxes.get_code().strip()
        if not otp:
            messagebox.showerror("Error", "Enter OTP.", parent=self.root)
            return

        try:
            res = self.net.request({
                "action": "login_verify",
                "user_id": self.session_user_id,
                "otp": otp
            })
        except Exception as e:
            messagebox.showerror("Network error", str(e), parent=self.root)
            return

        if not res.get("ok"):
            messagebox.showerror("Error", res.get("error", "OTP failed"), parent=self.root)
            self.otp_boxes.clear_code()
            return

        self.session_token = res.get("session_token")
        self.user_email = res.get("email")
        self.user_role = res.get("role")

        # E2EE: decrypt vault_key LOCALLY
        try:
            salt = bytes.fromhex(res["vault_salt"])
            enc_vk = bytes.fromhex(res["encrypted_vault_key"])
            derived = derive_fernet_from_password(self.session_password, salt)
            self.vault_key = decrypt_with_derived(derived, enc_vk).decode()
        except Exception as e:
            messagebox.showerror("Error", f"Failed to unlock vault: {e}", parent=self.root)
            return

        # sharing keys: ensure RSA keys exist and are usable
        server_pub = res.get("public_key_pem") or ""
        server_enc_priv = res.get("encrypted_private_key") or ""
        self._ensure_rsa_keys(server_pub, server_enc_priv)

        self.show_dashboard()

    # ================= FORGOT PASSWORD (DEV) =================
    def show_reset_start(self):
        self.clear_panel()

        tk.Label(self.panel, text="Reset Password", bg=PANEL, fg=TEXT, font=FONT_TITLE).pack(pady=(18, 6))
        tk.Label(self.panel, text="DEV mode: we'll show you a reset code", bg=PANEL, fg=MUTED, font=FONT_SUB).pack(pady=(0, 16))

        email_box, email_entry, self.reset_email_var = make_watermark_entry(self.panel, "Email")
        email_box.pack(pady=10, padx=30, fill="x")

        make_button(self.panel, "Send reset code", command=self.reset_start, primary=True).pack(pady=(18, 10), padx=30, fill="x")
        make_button(self.panel, "Back", command=self.show_login, small=True).pack()

        email_entry.focus_set()

    def reset_start(self):
        email = (self.reset_email_var.get() or "").strip()
        if not email:
            messagebox.showerror("Error", "Enter email.", parent=self.root)
            return

        try:
            res = self.net.request({"action": "reset_start", "email": email})
        except Exception as e:
            messagebox.showerror("Network error", str(e), parent=self.root)
            return

        if not res.get("ok"):
            messagebox.showerror("Error", res.get("error", "Reset start failed"), parent=self.root)
            return

        code = res.get("reset_code", "")
        messagebox.showinfo("DEV reset code", f"Reset Code: {code}", parent=self.root)

        self.reset_email = email
        self.show_reset_finish()

    def show_reset_finish(self):
        self.clear_panel()

        tk.Label(self.panel, text="Set New Password", bg=PANEL, fg=TEXT, font=FONT_TITLE).pack(pady=(18, 6))
        tk.Label(self.panel, text="Note: Reset wipes old vault (E2EE cannot be recovered)", bg=PANEL, fg=MUTED, font=FONT_SUB).pack(pady=(0, 16))

        code_box, code_entry, self.reset_code_var = make_watermark_entry(self.panel, "Reset code (6 digits)")
        code_box.pack(pady=8, padx=30, fill="x")

        pw1_box, pw1_entry, self.reset_pw1_var = make_watermark_entry(self.panel, "New password", is_password=True, show_toggle=True)
        pw1_box.pack(pady=8, padx=30, fill="x")

        pw2_box, pw2_entry, self.reset_pw2_var = make_watermark_entry(self.panel, "Confirm new password", is_password=True, show_toggle=True)
        pw2_box.pack(pady=8, padx=30, fill="x")

        make_button(self.panel, "Reset (wipe old vault)", command=self.reset_finish, primary=True).pack(pady=(18, 10), padx=30, fill="x")
        make_button(self.panel, "Back", command=self.show_login, small=True).pack()

        code_entry.focus_set()


    def reset_finish(self):
        code = (self.reset_code_var.get() or "").strip()
        pw1 = self.reset_pw1_var.get()
        pw2 = self.reset_pw2_var.get()

        if not code or not pw1 or not pw2:
            messagebox.showerror("Error", "Fill all fields.", parent=self.root)
            return
        if pw1 != pw2:
            messagebox.showerror("Error", "Passwords do not match.", parent=self.root)
            return
        if len(pw1) < 6:
            messagebox.showerror("Error", "Password too short (min 6).", parent=self.root)
            return

        # Reset in E2EE: create a NEW vault_key, encrypt it with new password
        try:
            salt = os.urandom(16)
            derived = derive_fernet_from_password(pw1, salt)
            new_vk = generate_vault_key()  # new vault contents -> old vault cannot be recovered
            enc_vk = encrypt_with_derived(derived, new_vk.encode()).hex()
            pw_hash = hash_master_password(pw1)
        except Exception as e:
            messagebox.showerror("Error", f"Crypto error: {e}", parent=self.root)
            return

        try:
            res = self.net.request({
                "action": "reset_finish",
                "email": self.reset_email,
                "code": code,
                "new_password_hash": pw_hash,
                "new_vault_salt": salt.hex(),
                "new_encrypted_vault_key": enc_vk
            })
        except Exception as e:
            messagebox.showerror("Network error", str(e), parent=self.root)
            return

        if not res.get("ok"):
            messagebox.showerror("Error", res.get("error", "Reset failed"), parent=self.root)
            return

        messagebox.showinfo("OK", "Password reset. Old vault was wiped (E2EE).", parent=self.root)
        self.show_login()

    # ================= DASHBOARD =================
    def show_dashboard(self):
        self.clear_panel()

        tk.Label(self.panel, text="Vault", bg=PANEL, fg=TEXT, font=FONT_TITLE).pack(pady=(18, 6))
        subtitle = f"Signed in as {self.user_email}"
        if self.user_role:
            subtitle += f"  •  role: {self.user_role}"
        tk.Label(self.panel, text=subtitle, bg=PANEL, fg=MUTED, font=FONT_SUB).pack(pady=(0, 16))

        make_button(self.panel, "New Entry", command=self.new_entry, primary=True).pack(pady=8, padx=30, fill="x")
        make_button(self.panel, "My saved entries", command=self.show_entries).pack(pady=8, padx=30, fill="x")

        # Backup
        make_button(self.panel, "Export Vault (encrypted backup)", command=self.export_vault).pack(pady=8, padx=30, fill="x")
        make_button(self.panel, "Import Vault (encrypted backup)", command=self.import_vault).pack(pady=8, padx=30, fill="x")


        # Sharing
        make_button(self.panel, "Share my Vault", command=self.share_my_vault).pack(pady=8, padx=30, fill="x")
        make_button(self.panel, "Vaults shared with me", command=self.show_shared_vaults).pack(pady=8, padx=30, fill="x")

        make_button(self.panel, "Logout", command=self.logout, small=True).pack(pady=(14, 0))


    # ================= ENTRIES =================
    def show_entries(self):
        if not self._require_authed():
            return

        self.clear_panel()

        top = tk.Frame(self.panel, bg=PANEL)
        top.pack(fill="x", pady=(10, 8), padx=16)
        make_button(top, "← Back", command=self.show_dashboard, small=True).pack(side="left")
        tk.Label(top, text="Saved Entries", bg=PANEL, fg=TEXT, font=("Arial", 16, "bold")).pack(side="right")

        area = ScrollArea(self.panel, height=260)
        area.pack(fill="both", expand=True, padx=16, pady=(4, 10))

        try:
            res = self.net.request({"action": "entries_list", "session_token": self.session_token})
        except Exception as e:
            messagebox.showerror("Network error", str(e), parent=self.root)
            return

        if not res.get("ok"):
            messagebox.showerror("Error", res.get("error", "Failed to load entries"), parent=self.root)
            return

        entries = res.get("entries", [])

        if not entries:
            tk.Label(area.inner, text="No entries yet. Add one from Dashboard.",
                     bg=PANEL, fg=MUTED, font=FONT_SUB).pack(pady=20)
        else:
            for ent in entries:
                self._entry_row(area.inner, ent)

        make_button(self.panel, "New Entry", command=self.new_entry, primary=True).pack(pady=(8, 6), padx=16, fill="x")
        make_button(self.panel, "Logout", command=self.logout, small=True).pack()

    def _entry_row(self, parent, ent: dict):
        entry_id = ent["id"]
        title = ent["title"]
        username = ent["username"]
        enc_hex = ent["encrypted_password"]

        try:
            pw_plain = decrypt_entry_password(self.vault_key, bytes.fromhex(enc_hex))
        except Exception:
            pw_plain = "<decrypt error>"

        row = tk.Frame(parent, bg="#111216", highlightthickness=1, highlightbackground=BORDER)
        row.pack(fill="x", pady=6, padx=2)

        left = tk.Frame(row, bg="#111216")
        left.pack(side="left", fill="both", expand=True, padx=10, pady=8)

        tk.Label(left, text=title, bg="#111216", fg=TEXT, font=("Arial", 13, "bold"), anchor="w").pack(fill="x")
        tk.Label(left, text=username, bg="#111216", fg=MUTED, font=("Arial", 11), anchor="w").pack(fill="x", pady=(2, 0))

        right = tk.Frame(row, bg="#111216")
        right.pack(side="right", padx=10, pady=8)

        make_button(right, "Show",
                    command=lambda: messagebox.showinfo("Password", pw_plain, parent=self.root),
                    small=True).pack(pady=2, fill="x")

        make_button(right, "Edit",
                    command=lambda: self.edit_entry(entry_id, title, username, pw_plain),
                    small=True).pack(pady=2, fill="x")

        make_button(right, "Delete",
                    command=lambda: self.delete_entry(entry_id),
                    small=True).pack(pady=2, fill="x")

    # ================= CRUD =================
    def new_entry(self):
        if not self._require_authed():
            return

        title = simpledialog.askstring("Title", "Title:", parent=self.root)
        if not title:
            return
        username = simpledialog.askstring("Username", "Email / Username:", parent=self.root)
        if not username:
            return
        pw = simpledialog.askstring("Password", "Password (leave empty to generate):", parent=self.root)
        if not pw:
            pw = generate_password()

        try:
            enc_hex = encrypt_entry_password(self.vault_key, pw).hex()
        except Exception as e:
            messagebox.showerror("Error", f"Encryption failed: {e}", parent=self.root)
            return

        try:
            res = self.net.request({
                "action": "entry_create",
                "session_token": self.session_token,
                "title": title,
                "username": username,
                "encrypted_password": enc_hex
            })
        except Exception as e:
            messagebox.showerror("Network error", str(e), parent=self.root)
            return

        if not res.get("ok"):
            messagebox.showerror("Error", res.get("error", "Failed to save"), parent=self.root)
            return

        messagebox.showinfo("Saved", "Entry saved.", parent=self.root)

    def edit_entry(self, entry_id: int, title: str, username: str, pw_plain: str):
        if not self._require_authed():
            return

        win = tk.Toplevel(self.root)
        win.title("Edit Entry")
        win.geometry("440x380")
        win.configure(bg=BG)

        win.transient(self.root)
        win.grab_set()
        win.focus_force()
        win.lift()
        win.attributes("-topmost", True)
        win.after(200, lambda: win.attributes("-topmost", False))

        panel = tk.Frame(win, bg=PANEL, highlightthickness=1, highlightbackground="#1f2026")
        panel.place(relx=0.5, rely=0.5, anchor="center", width=400, height=330)

        tk.Label(panel, text="Edit Entry", bg=PANEL, fg=TEXT, font=("Arial", 18, "bold")).pack(pady=(16, 10))

        title_box, title_e, title_var = make_watermark_entry(panel, "Title")
        title_box.pack(pady=8, padx=20, fill="x")
        title_var.set(title)

        user_box, user_e, user_var = make_watermark_entry(panel, "Username / Email")
        user_box.pack(pady=8, padx=20, fill="x")
        user_var.set(username)

        pw_box, pw_e, pw_var = make_watermark_entry(panel, "Password", is_password=True, show_toggle=True)
        pw_box.pack(pady=8, padx=20, fill="x")
        pw_var.set(pw_plain)

        def save():
            new_title = title_var.get().strip()
            new_user = user_var.get().strip()
            new_pw = pw_var.get()

            if not new_title or not new_user or not new_pw:
                messagebox.showerror("Error", "Fill all fields.", parent=win)
                return

            try:
                enc_hex = encrypt_entry_password(self.vault_key, new_pw).hex()
            except Exception as e:
                messagebox.showerror("Error", f"Encryption failed: {e}", parent=win)
                return

            try:
                res = self.net.request({
                    "action": "entry_update",
                    "session_token": self.session_token,
                    "id": entry_id,
                    "title": new_title,
                    "username": new_user,
                    "encrypted_password": enc_hex
                })
            except Exception as e:
                messagebox.showerror("Network error", str(e), parent=win)
                return

            if not res.get("ok"):
                messagebox.showerror("Error", res.get("error", "Update failed"), parent=win)
                return

            win.destroy()
            self.show_entries()

        make_button(panel, "Save", command=save, primary=True).pack(pady=(16, 8), padx=20, fill="x")
        make_button(panel, "Cancel", command=win.destroy, small=True).pack()
        title_e.focus_set()

    def delete_entry(self, entry_id: int):
        if not self._require_authed():
            return

        if not messagebox.askyesno("Confirm", "Delete entry?", parent=self.root):
            return

        try:
            res = self.net.request({"action": "entry_delete", "session_token": self.session_token, "id": entry_id})
        except Exception as e:
            messagebox.showerror("Network error", str(e), parent=self.root)
            return

        if not res.get("ok"):
            messagebox.showerror("Error", res.get("error", "Delete failed"), parent=self.root)
            return

        self.show_entries()

    # ================= BACKUP =================
    def export_vault(self):
        if not self._require_authed():
            return

        try:
            res = self.net.request({"action": "entries_list", "session_token": self.session_token})
            if not res.get("ok"):
                messagebox.showerror("Error", res.get("error", "Failed"), parent=self.root)
                return

            entries = res.get("entries", [])
            data = {"v": 1, "exported_at": __import__("datetime").datetime.now().isoformat(), "entries": entries}
            plaintext = json.dumps(data, ensure_ascii=False).encode("utf-8")

            enc_hex = encrypt_entry_password(self.vault_key, plaintext.decode("utf-8")).hex()

            path = filedialog.asksaveasfilename(
                title="Export Vault",
                defaultextension=".vault",
                filetypes=[("Vault Backup", "*.vault")]
            )
            if not path:
                return

            with open(path, "w", encoding="utf-8") as f:
                f.write(enc_hex)

            messagebox.showinfo("OK", "Exported encrypted backup.", parent=self.root)

        except Exception as e:
            messagebox.showerror("Error", str(e), parent=self.root)

    def import_vault(self):
        if not self._require_authed():
            return

        try:
            path = filedialog.askopenfilename(
                title="Import Vault",
                filetypes=[("Vault Backup", "*.vault")]
            )
            if not path:
                return

            with open(path, "r", encoding="utf-8") as f:
                enc_hex = f.read().strip()

            if len(enc_hex) < 40:
                raise ValueError("Backup file too short / not a valid .vault")

            blob_bytes = bytes.fromhex(enc_hex)

            # decrypt backup with current user's vault_key
            plaintext = decrypt_entry_password(self.vault_key, blob_bytes)
            data = json.loads(plaintext)

            entries = data.get("entries", [])
            if not isinstance(entries, list):
                raise ValueError("Backup format invalid (missing entries list)")

            imported = 0
            failed = 0

            for ent in entries:
                try:
                    title = ent["title"]
                    username = ent["username"]
                    enc_pw = ent["encrypted_password"]
                except Exception:
                    failed += 1
                    continue

                r = self.net.request({
                    "action": "entry_create",
                    "session_token": self.session_token,
                    "title": title,
                    "username": username,
                    "encrypted_password": enc_pw
                })
                if r.get("ok"):
                    imported += 1
                else:
                    failed += 1

            messagebox.showinfo("OK", f"Imported: {imported}\nFailed: {failed}", parent=self.root)

        except Exception as e:
            messagebox.showerror("Import error", f"{type(e).__name__}: {e}", parent=self.root)

    # ================= SHARING WHOLE VAULT =================
    def share_my_vault(self):
        if not self._require_authed():
            return

        to_email = simpledialog.askstring("Share Vault", "Share with (email):", parent=self.root)
        if not to_email:
            return
        to_email = to_email.strip().lower()

        # Ensure we have our private key locally (should, after login)
        if not self.private_key_pem or not self.public_key_pem:
            messagebox.showerror("Error", "Sharing keys not available. Try logout/login.", parent=self.root)
            return

        try:
            # Fetch receiver public key
            res = self.net.request({
                "action": "keys_get_public",
                "session_token": self.session_token,
                "email": to_email
            })
        except Exception as e:
            messagebox.showerror("Network error", str(e), parent=self.root)
            return

        if not res.get("ok"):
            messagebox.showerror("Error", res.get("error", "Failed to get receiver public key"), parent=self.root)
            return

        receiver_pub_pem = res["public_key_pem"].encode("utf-8")

        # Wrap (encrypt) my vault_key for receiver using receiver's public key
        try:
            wrapped = rsa_encrypt(receiver_pub_pem, self.vault_key.encode("utf-8"))
            wrapped_hex = wrapped.hex()
        except Exception as e:
            messagebox.showerror("Error", f"RSA encrypt failed: {e}", parent=self.root)
            return

        try:
            r2 = self.net.request({
                "action": "share_vault_create",
                "session_token": self.session_token,
                "to_email": to_email,
                "enc_vault_key_for_receiver": wrapped_hex
            })
        except Exception as e:
            messagebox.showerror("Network error", str(e), parent=self.root)
            return

        if not r2.get("ok"):
            messagebox.showerror("Error", r2.get("error", "Share failed"), parent=self.root)
            return

        messagebox.showinfo("OK", f"Shared your vault with {to_email}.", parent=self.root)

    def show_shared_vaults(self):
        if not self._require_authed():
            return

        self.clear_panel()
        tk.Label(self.panel, text="Shared With Me", bg=PANEL, fg=TEXT, font=FONT_TITLE).pack(pady=(18, 6))
        tk.Label(self.panel, text="Open a shared vault to view entries (read-only).", bg=PANEL, fg=MUTED, font=FONT_SUB).pack(pady=(0, 14))

        top = tk.Frame(self.panel, bg=PANEL)
        top.pack(fill="x", padx=16, pady=(0, 6))
        make_button(top, "← Back", command=self.show_dashboard, small=True).pack(side="left")

        area = ScrollArea(self.panel, height=300)
        area.pack(fill="both", expand=True, padx=16, pady=(6, 10))

        try:
            res = self.net.request({"action": "share_vault_list", "session_token": self.session_token})
        except Exception as e:
            messagebox.showerror("Network error", str(e), parent=self.root)
            self.show_dashboard()
            return

        if not res.get("ok"):
            messagebox.showerror("Error", res.get("error", "Failed to load shares"), parent=self.root)
            self.show_dashboard()
            return

        shared = res.get("shared", [])
        if not shared:
            tk.Label(area.inner, text="No one shared a vault with you yet.",
                     bg=PANEL, fg=MUTED, font=FONT_SUB).pack(pady=20)
            return

        for item in shared:
            self._shared_vault_row(area.inner, item)

    def _shared_vault_row(self, parent, item: dict):
        owner_id = item["owner_id"]
        owner_email = item.get("owner_email", "unknown")
        enc_vault_key_for_me = item["enc_vault_key_for_receiver"]
        created_at = item.get("created_at", "")

        row = tk.Frame(parent, bg="#111216", highlightthickness=1, highlightbackground=BORDER)
        row.pack(fill="x", pady=6, padx=2)

        left = tk.Frame(row, bg="#111216")
        left.pack(side="left", fill="both", expand=True, padx=10, pady=8)

        tk.Label(left, text=f"From: {owner_email}", bg="#111216", fg=TEXT, font=("Arial", 13, "bold"), anchor="w").pack(fill="x")
        tk.Label(left, text=f"Shared at: {created_at}", bg="#111216", fg=MUTED, font=("Arial", 11), anchor="w").pack(fill="x", pady=(2, 0))

        right = tk.Frame(row, bg="#111216")
        right.pack(side="right", padx=10, pady=8)

        make_button(
            right, "Open",
            command=lambda: self.open_shared_vault(owner_id, owner_email, enc_vault_key_for_me),
            small=True
        ).pack(pady=2, fill="x")

    def open_shared_vault(self, owner_id: int, owner_email: str, enc_vault_key_hex: str):
        if not self._require_authed():
            return
        if not self.private_key_pem:
            messagebox.showerror("Error", "Missing private key for sharing. Try logout/login.", parent=self.root)
            return

        # Decrypt wrapped vault key using my private RSA key
        try:
            wrapped = bytes.fromhex(enc_vault_key_hex)
            owner_vault_key = rsa_decrypt(self.private_key_pem, wrapped).decode("utf-8")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to open shared vault: {e}", parent=self.root)
            return

        # Fetch owner's entries
        try:
            res = self.net.request({
                "action": "share_vault_entries",
                "session_token": self.session_token,
                "owner_id": owner_id
            })
        except Exception as e:
            messagebox.showerror("Network error", str(e), parent=self.root)
            return

        if not res.get("ok"):
            messagebox.showerror("Error", res.get("error", "Failed to load shared entries"), parent=self.root)
            return

        entries = res.get("entries", [])
        self.show_shared_entries(owner_email, owner_vault_key, entries)

    def show_shared_entries(self, owner_email: str, owner_vault_key: str, entries: list):
        self.clear_panel()

        top = tk.Frame(self.panel, bg=PANEL)
        top.pack(fill="x", pady=(10, 8), padx=16)
        make_button(top, "← Back", command=self.show_shared_vaults, small=True).pack(side="left")
        tk.Label(top, text=f"Shared Vault: {owner_email}", bg=PANEL, fg=TEXT, font=("Arial", 16, "bold")).pack(side="right")

        area = ScrollArea(self.panel, height=360)
        area.pack(fill="both", expand=True, padx=16, pady=(4, 10))

        if not entries:
            tk.Label(area.inner, text="No entries in this shared vault.",
                     bg=PANEL, fg=MUTED, font=FONT_SUB).pack(pady=20)
            return

        for ent in entries:
            self._shared_entry_row(area.inner, ent, owner_vault_key)

    def _shared_entry_row(self, parent, ent: dict, owner_vault_key: str):
        title = ent["title"]
        username = ent["username"]
        enc_hex = ent["encrypted_password"]

        try:
            pw_plain = decrypt_entry_password(owner_vault_key, bytes.fromhex(enc_hex))
        except Exception:
            pw_plain = "<decrypt error>"

        row = tk.Frame(parent, bg="#111216", highlightthickness=1, highlightbackground=BORDER)
        row.pack(fill="x", pady=6, padx=2)

        left = tk.Frame(row, bg="#111216")
        left.pack(side="left", fill="both", expand=True, padx=10, pady=8)

        tk.Label(left, text=title, bg="#111216", fg=TEXT, font=("Arial", 13, "bold"), anchor="w").pack(fill="x")
        tk.Label(left, text=username, bg="#111216", fg=MUTED, font=("Arial", 11), anchor="w").pack(fill="x", pady=(2, 0))

        right = tk.Frame(row, bg="#111216")
        right.pack(side="right", padx=10, pady=8)

        make_button(
            right, "Show",
            command=lambda: messagebox.showinfo("Password (shared)", pw_plain, parent=self.root),
            small=True
        ).pack(pady=2, fill="x")

    # ================= LOGOUT =================
    def logout(self):
        try:
            if self.session_token:
                self.net.request({"action": "logout", "session_token": self.session_token})
        except Exception:
            pass

        try:
            self.net.close()
        except Exception:
            pass

        self.session_user_id = None
        self.session_password = None
        self.session_token = None
        self.user_email = None
        self.user_role = None
        self.vault_key = None

        self.public_key_pem = None
        self.private_key_pem = None

        self.show_login()
