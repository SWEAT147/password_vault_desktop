# client.py
import tkinter as tk
from tkinter import filedialog
import string, secrets, json, os, threading, ssl, socket, uuid

from shared import (
    send_msg, recv_msg, hash_master_password, derive_fernet_from_password,
    encrypt_with_derived, decrypt_with_derived, generate_vault_key,
    encrypt_entry_password, decrypt_entry_password, generate_rsa_keypair,
    rsa_encrypt, rsa_decrypt
)


# ================= NETWORK CLIENT =================
class NetworkClient:
    def __init__(self, host="127.0.0.1", port=5050, cafile="certs/server.crt"):
        self.host, self.port, self.cafile, self.sock = host, port, cafile, None

    def connect(self):
        if self.sock: return
        raw = socket.create_connection((self.host, self.port), timeout=30)
        ctx = ssl.create_default_context(cafile=self.cafile)
        ctx.check_hostname = True
        self.sock = ctx.wrap_socket(raw, server_hostname="localhost")

    def close(self):
        if self.sock:
            try:
                self.sock.close()
            except Exception:
                pass
        self.sock = None

    def request(self, payload: dict) -> dict:
        try:
            self.connect()
            payload = dict(payload)
            payload.setdefault("v", 1)
            payload.setdefault("request_id", uuid.uuid4().hex)
            send_msg(self.sock, payload)
            return recv_msg(self.sock)
        except Exception:
            self.close()
            raise


# ================= THEME & UI HELPERS =================
BG, PANEL, TEXT, MUTED = "#0b0b0c", "#0f1012", "#ffffff", "#a9a9b3"
ENTRY_BG, ENTRY_FG, PLACEHOLDER_FG = "#0b0c0f", "#ffffff", "#a9a9b3"
BORDER, FOCUS_BORDER, BTN_BG, BTN_FG = "#2a2b30", "#3b82f6", "#0b0c0f", "#ffffff"
BTN_BORDER, BTN_HOVER, ACCENT_BORDER = "#2a2b30", "#14161c", "#3b82f6"

FONT_TITLE, FONT_SUB, FONT_ENTRY = ("Arial", 22, "bold"), ("Arial", 12), ("Arial", 13)
FIELD_H, PAD_X, PAD_Y, EYE_W = 52, 12, 12, 46


def generate_password(n=18):
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*()-_=+[]{};:,.?"
    return "".join(secrets.choice(alphabet) for _ in range(n))


def make_button(parent, text, command=None, *, primary=False, small=False) -> tk.Button:
    border, hover = (ACCENT_BORDER, "#121826") if primary else (BTN_BORDER, BTN_HOVER)
    btn = tk.Button(parent, text=text, command=command, bg=BTN_BG, fg=BTN_FG, activebackground=hover,
                    activeforeground=BTN_FG, relief="flat", bd=0, highlightthickness=1, highlightbackground=border,
                    highlightcolor=border, font=("Arial", 11 if small else 12), padx=10, pady=8 if not small else 6,
                    cursor="hand2")
    btn.bind("<Enter>", lambda e: btn.configure(bg=hover))
    btn.bind("<Leave>", lambda e: btn.configure(bg=BTN_BG))
    return btn


def make_watermark_entry(parent, placeholder: str, *, is_password: bool = False, show_toggle: bool = False):
    container = tk.Frame(parent, bg=ENTRY_BG, highlightthickness=1, highlightbackground=BORDER, highlightcolor=BORDER,
                         bd=0, height=FIELD_H)
    container.pack_propagate(False)
    var = tk.StringVar()
    entry = tk.Entry(container, textvariable=var, bg=ENTRY_BG, fg=ENTRY_FG, insertbackground=ENTRY_FG, relief="flat",
                     bd=0, font=FONT_ENTRY)
    if is_password: entry.config(show="*")
    entry.place(x=PAD_X, y=PAD_Y, relwidth=1, width=-(2 * PAD_X + (EYE_W if (is_password and show_toggle) else 0)),
                height=FIELD_H - 2 * PAD_Y)
    ph = tk.Label(container, text=placeholder, fg=PLACEHOLDER_FG, bg=ENTRY_BG, font=FONT_ENTRY, anchor="w")
    ph.place(x=PAD_X, y=PAD_Y, height=FIELD_H - 2 * PAD_Y)

    def refresh(*_):
        if var.get():
            ph.place_forget()
        else:
            ph.place(x=PAD_X, y=PAD_Y, height=FIELD_H - 2 * PAD_Y)

    var.trace_add("write", refresh)
    ph.bind("<Button-1>", lambda e: entry.focus_set())
    entry.bind("<FocusIn>",
               lambda _: container.configure(highlightbackground=FOCUS_BORDER, highlightcolor=FOCUS_BORDER))
    entry.bind("<FocusOut>",
               lambda _: (container.configure(highlightbackground=BORDER, highlightcolor=BORDER), refresh()))
    if is_password and show_toggle:
        state = {"shown": False}

        def toggle():
            state["shown"] = not state["shown"]
            entry.config(show="" if state["shown"] else "*")

        eye = tk.Button(container, text="👁", command=toggle, bg=ENTRY_BG, fg=MUTED, activebackground=ENTRY_BG,
                        activeforeground=TEXT, relief="flat", bd=0, highlightthickness=0, cursor="hand2",
                        font=("Arial", 14))
        eye.place(relx=1.0, x=-EYE_W + 4, y=PAD_Y - 2, width=EYE_W - 8, height=FIELD_H - 2 * PAD_Y + 4)
    refresh()
    return container, entry, var


# ================= FAST & PASTE-READY OTP BOXES =================
def make_otp_boxes(parent, digits=6):
    wrap = tk.Frame(parent, bg=parent["bg"])
    vars_ = [tk.StringVar() for _ in range(digits)]
    entries = []

    vcmd = (parent.register(lambda P: P == "" or (len(P) <= 1 and P.isdigit())), "%P")

    def make_trace(idx):
        def _trace(*args):
            if len(vars_[idx].get()) == 1 and idx < digits - 1:
                entries[idx + 1].focus_set()

        return _trace

    for i in range(digits):
        e = tk.Entry(wrap, textvariable=vars_[i], bg=ENTRY_BG, fg=ENTRY_FG, insertbackground=ENTRY_FG, relief="flat",
                     bd=0, font=("Arial", 16, "bold"), justify="center", highlightthickness=1,
                     highlightbackground=BORDER, highlightcolor=BORDER, width=2, validate="key", validatecommand=vcmd)
        e.grid(row=0, column=i, padx=6, ipady=10)
        entries.append(e)

        e.bind("<FocusIn>",
               lambda ev, idx=i: entries[idx].configure(highlightbackground=FOCUS_BORDER, highlightcolor=FOCUS_BORDER))
        e.bind("<FocusOut>",
               lambda ev, idx=i: entries[idx].configure(highlightbackground=BORDER, highlightcolor=BORDER))

        def on_key_press(event, idx=i):
            if event.keysym == "BackSpace":
                if vars_[idx].get() == "" and idx > 0:
                    entries[idx - 1].focus_set()
                    entries[idx - 1].delete(0, tk.END)
                    return "break"

        e.bind("<KeyPress>", on_key_press)

        def on_paste(event, idx=i):
            try:
                clip = wrap.clipboard_get().strip()
                if clip.isdigit():
                    for j in range(min(digits - idx, len(clip))):
                        vars_[idx + j].set(clip[j])
                    focus_idx = min(digits - 1, idx + len(clip) - 1)
                    entries[focus_idx].focus_set()
                    entries[focus_idx].icursor(tk.END)
                return "break"
            except Exception:
                pass

        e.bind("<Control-v>", on_paste)
        e.bind("<Command-v>", on_paste)

        vars_[i].trace_add("write", make_trace(i))

    wrap.get_code = lambda: "".join(v.get().strip() for v in vars_)

    def clear():
        for v in vars_: v.set("")
        entries[0].focus_set()

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


# ================= CUSTOM DIALOGS =================
def custom_messagebox(parent, title, message, type="info", allow_copy=False):
    win = tk.Toplevel(parent)
    win.title(title)
    win.configure(bg=BG)
    win.transient(parent)
    win.grab_set()

    parent.update_idletasks()
    x = parent.winfo_rootx() + (parent.winfo_width() // 2) - 200
    y = parent.winfo_rooty() + (parent.winfo_height() // 2) - 120
    win.geometry(f"400x220+{x}+{y}")

    panel = tk.Frame(win, bg=PANEL, highlightthickness=1, highlightbackground=BORDER)
    panel.place(relx=0.5, rely=0.5, anchor="center", relwidth=0.9, relheight=0.85)

    color = TEXT if type == "info" else ("#ef4444" if type == "error" else "#f59e0b")

    tk.Label(panel, text=title, bg=PANEL, fg=color, font=("Arial", 16, "bold")).pack(pady=(16, 8))
    tk.Label(panel, text=message, bg=PANEL, fg=MUTED, font=FONT_SUB, wraplength=320, justify="center").pack(
        pady=(0, 16), fill="both", expand=True)

    # כפתור ההעתקה המיוחד שביקשת
    if allow_copy:
        def copy_close():
            parent.clipboard_clear()
            parent.clipboard_append(message)
            win.destroy()

        make_button(panel, "📋 Copy & Close", command=copy_close, primary=True).pack(pady=(0, 16))
    else:
        make_button(panel, "OK", command=win.destroy, primary=True, small=True).pack(pady=(0, 16))

    win.wait_window()


def custom_askstring(parent, title, prompt):
    win = tk.Toplevel(parent)
    win.title(title)
    win.configure(bg=BG)
    win.transient(parent)
    win.grab_set()

    parent.update_idletasks()
    x = parent.winfo_rootx() + (parent.winfo_width() // 2) - 200
    y = parent.winfo_rooty() + (parent.winfo_height() // 2) - 125
    win.geometry(f"400x250+{x}+{y}")

    panel = tk.Frame(win, bg=PANEL, highlightthickness=1, highlightbackground=BORDER)
    panel.place(relx=0.5, rely=0.5, anchor="center", relwidth=0.9, relheight=0.9)

    tk.Label(panel, text=title, bg=PANEL, fg=TEXT, font=("Arial", 16, "bold")).pack(pady=(16, 8))
    tk.Label(panel, text=prompt, bg=PANEL, fg=MUTED, font=FONT_SUB).pack(pady=(0, 8))

    box, entry, var = make_watermark_entry(panel, prompt)
    box.pack(pady=10, padx=20, fill="x")

    result = None

    def on_submit():
        nonlocal result
        result = var.get()
        win.destroy()

    def on_cancel():
        win.destroy()

    btn_frame = tk.Frame(panel, bg=PANEL)
    btn_frame.pack(pady=10)
    make_button(btn_frame, "OK", command=on_submit, primary=True, small=True).pack(side="left", padx=5)
    make_button(btn_frame, "Cancel", command=on_cancel, small=True).pack(side="left", padx=5)

    entry.bind("<Return>", lambda e: on_submit())
    entry.focus_set()

    win.wait_window()
    return result


def custom_askyesno(parent, title, prompt):
    win = tk.Toplevel(parent)
    win.title(title)
    win.configure(bg=BG)
    win.transient(parent)
    win.grab_set()

    parent.update_idletasks()
    x = parent.winfo_rootx() + (parent.winfo_width() // 2) - 200
    y = parent.winfo_rooty() + (parent.winfo_height() // 2) - 140
    win.geometry(f"400x280+{x}+{y}")

    panel = tk.Frame(win, bg=PANEL, highlightthickness=1, highlightbackground=BORDER)
    panel.place(relx=0.5, rely=0.5, anchor="center", relwidth=0.9, relheight=0.9)

    tk.Label(panel, text=title, bg=PANEL, fg=TEXT, font=("Arial", 16, "bold")).pack(pady=(16, 8))
    tk.Label(panel, text=prompt, bg=PANEL, fg=MUTED, font=FONT_SUB, wraplength=320, justify="center").pack(pady=(0, 16),
                                                                                                           fill="both",
                                                                                                           expand=True)

    result = False

    def on_yes():
        nonlocal result
        result = True
        win.destroy()

    def on_no():
        win.destroy()

    btn_frame = tk.Frame(panel, bg=PANEL)
    btn_frame.pack(pady=(0, 16))
    make_button(btn_frame, "Yes", command=on_yes, primary=True, small=True).pack(side="left", padx=5)
    make_button(btn_frame, "No", command=on_no, small=True).pack(side="left", padx=5)

    win.wait_window()
    return result


# ================= APP CLASS =================
class App:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("Password Vault")
        self.root.geometry("820x640")
        self.root.configure(bg=BG)

        self.net = NetworkClient()

        self.session_user_id = None
        self.session_password = None
        self.session_token = None
        self.user_email = None
        self.user_role = None
        self.vault_key = None
        self.public_key_pem = None
        self.private_key_pem = None
        self.reset_email = None

        self.frame = tk.Frame(root, bg=BG)
        self.frame.pack(fill="both", expand=True)

        self.panel = tk.Frame(self.frame, bg=PANEL, highlightthickness=1, highlightbackground="#1f2026")
        self.panel.place(relx=0.5, rely=0.5, anchor="center", width=620, height=560)

        self.show_login()

    def async_request(self, payload, on_success):
        def task():
            try:
                res = self.net.request(payload)
                self.root.after(0, lambda r=res: on_success(r))
            except Exception as e:
                err_msg = str(e)
                self.root.after(0, lambda msg=err_msg: custom_messagebox(self.root, "Network error", msg, "error"))

        threading.Thread(target=task, daemon=True).start()

    def clear_panel(self):
        for w in self.panel.winfo_children():
            w.destroy()

    def _require_authed(self):
        if not self.session_token:
            custom_messagebox(self.root, "Error", "Not authenticated.", "error")
            self.show_login()
            return False
        if not self.vault_key:
            custom_messagebox(self.root, "Error", "Vault is locked.", "error")
            self.show_login()
            return False
        return True

    def _ensure_rsa_keys(self, server_pub_str, server_enc_priv_hex):
        if server_pub_str and server_enc_priv_hex:
            try:
                self.public_key_pem = server_pub_str.encode("utf-8")
                enc_priv = bytes.fromhex(server_enc_priv_hex)
                priv_pem_str = decrypt_entry_password(self.vault_key, enc_priv)
                self.private_key_pem = priv_pem_str.encode("utf-8")
                return
            except Exception:
                pass

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
                custom_messagebox(self.root, "Warning", "Failed to upload sharing keys.", "warning")
        except Exception:
            custom_messagebox(self.root, "Warning", "Failed to upload sharing keys.", "warning")

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

        make_button(self.panel, "Create Account", command=self.signup_create, primary=True).pack(pady=(18, 10), padx=30,
                                                                                                 fill="x")
        make_button(self.panel, "Back", command=self.show_login, small=True).pack()

        name_entry.focus_set()

    def signup_create(self):
        full_name = self.fullname_var.get().strip()
        email = self.email_var.get().strip()
        pw = self.pw_var.get()

        if not full_name or not email or not pw:
            custom_messagebox(self.root, "Error", "Fill all fields.", "error")
            return

        def handle_res(res):
            if not res.get("ok"):
                custom_messagebox(self.root, "Error", res.get("error", "Signup failed"), "error")
            else:
                custom_messagebox(self.root, "Success", "Account created. Please login.", "info")
                self.show_login()

        self.async_request({"action": "signup", "full_name": full_name, "email": email, "password": pw}, handle_res)

    # ================= LOGIN + OTP =================
    def login_start(self):
        email = self.email_var.get().strip()
        pw = self.pw_var.get()

        if not email or not pw:
            custom_messagebox(self.root, "Error", "Enter email and password.", "error")
            return

        def handle_res(res):
            if not res.get("ok"):
                custom_messagebox(self.root, "Error", res.get("error", "Login failed"), "error")
            else:
                self.session_user_id = res.get("user_id")
                self.session_password = pw
                custom_messagebox(self.root, "OTP sent",
                                  "We sent a 6-digit OTP code to your email.\nPlease enter it to continue.", "info")
                self.show_otp()

        self.async_request({"action": "login_start", "email": email, "password": pw}, handle_res)

    def show_otp(self):
        self.clear_panel()

        tk.Label(self.panel, text="OTP Verification", bg=PANEL, fg=TEXT, font=FONT_TITLE).pack(pady=(18, 6))
        tk.Label(self.panel, text="Enter the 6-digit code from your email", bg=PANEL, fg=MUTED, font=FONT_SUB).pack(
            pady=(0, 16))

        self.otp_boxes = make_otp_boxes(self.panel, digits=6)
        self.otp_boxes.pack(pady=10)
        self.otp_boxes.focus_first()

        make_button(self.panel, "Verify", command=self.verify_otp, primary=True).pack(pady=(18, 10), padx=30, fill="x")
        make_button(self.panel, "Back", command=self.show_login, small=True).pack()

    def verify_otp(self):
        otp = self.otp_boxes.get_code().strip()
        if not otp:
            custom_messagebox(self.root, "Error", "Enter OTP.", "error")
            return

        def handle_res(res):
            if not res.get("ok"):
                custom_messagebox(self.root, "Error", res.get("error", "OTP failed"), "error")
                self.otp_boxes.clear_code()
                return

            self.session_token = res.get("session_token")
            self.user_email = res.get("email")
            self.user_role = res.get("role")

            try:
                salt = bytes.fromhex(res["vault_salt"])
                enc_vk = bytes.fromhex(res["encrypted_vault_key"])
                derived = derive_fernet_from_password(self.session_password, salt)
                self.vault_key = decrypt_with_derived(derived, enc_vk).decode()
            except Exception as e:
                custom_messagebox(self.root, "Error", f"Failed to unlock vault: {e}", "error")
                return

            server_pub = res.get("public_key_pem") or ""
            server_enc_priv = res.get("encrypted_private_key") or ""
            self._ensure_rsa_keys(server_pub, server_enc_priv)

            self.show_dashboard()

        self.async_request({"action": "login_verify", "user_id": self.session_user_id, "otp": otp}, handle_res)

    # ================= FORGOT PASSWORD =================
    def show_reset_start(self):
        self.clear_panel()

        tk.Label(self.panel, text="Forgot Password", bg=PANEL, fg=TEXT, font=FONT_TITLE).pack(pady=(18, 6))
        tk.Label(self.panel, text="We will send you a reset code by email.", bg=PANEL, fg=MUTED, font=FONT_SUB).pack(
            pady=(0, 16))

        email_box, email_entry, self.reset_email_var = make_watermark_entry(self.panel, "Email")
        email_box.pack(pady=10, padx=30, fill="x")

        make_button(self.panel, "Send reset code", command=self.reset_start, primary=True).pack(pady=(18, 10), padx=30,
                                                                                                fill="x")
        make_button(self.panel, "Back", command=self.show_login, small=True).pack()

        email_entry.focus_set()

    def reset_start(self):
        email = (self.reset_email_var.get() or "").strip()
        if not email:
            custom_messagebox(self.root, "Error", "Enter email.", "error")
            return

        def handle_res(res):
            if not res.get("ok"):
                custom_messagebox(self.root, "Error", res.get("error", "Reset start failed"), "error")
                return

            custom_messagebox(self.root, "Reset code sent",
                              "If the account exists, a reset code was sent to your email.\nEnter it on the next screen.",
                              "info")
            self.reset_email = email
            self.show_reset_finish()

        self.async_request({"action": "reset_start", "email": email}, handle_res)

    def show_reset_finish(self):
        self.clear_panel()

        tk.Label(self.panel, text="Set New Password", bg=PANEL, fg=TEXT, font=FONT_TITLE).pack(pady=(18, 6))
        tk.Label(self.panel, text="Note: Reset wipes old vault (E2EE cannot be recovered)", bg=PANEL, fg=MUTED,
                 font=FONT_SUB).pack(pady=(0, 16))

        code_box, code_entry, self.reset_code_var = make_watermark_entry(self.panel, "Reset code (6 digits)")
        code_box.pack(pady=8, padx=30, fill="x")

        pw1_box, pw1_entry, self.reset_pw1_var = make_watermark_entry(self.panel, "New password", is_password=True,
                                                                      show_toggle=True)
        pw1_box.pack(pady=8, padx=30, fill="x")

        pw2_box, pw2_entry, self.reset_pw2_var = make_watermark_entry(self.panel, "Confirm new password",
                                                                      is_password=True, show_toggle=True)
        pw2_box.pack(pady=8, padx=30, fill="x")

        make_button(self.panel, "Reset (wipe old vault)", command=self.reset_finish, primary=True).pack(pady=(18, 10),
                                                                                                        padx=30,
                                                                                                        fill="x")
        make_button(self.panel, "Back", command=self.show_login, small=True).pack()

        code_entry.focus_set()

    def reset_finish(self):
        code = (self.reset_code_var.get() or "").strip()
        pw1 = self.reset_pw1_var.get()
        pw2 = self.reset_pw2_var.get()

        if not code or not pw1 or not pw2:
            custom_messagebox(self.root, "Error", "Fill all fields.", "error")
            return
        if pw1 != pw2:
            custom_messagebox(self.root, "Error", "Passwords do not match.", "error")
            return

        try:
            salt = os.urandom(16)
            derived = derive_fernet_from_password(pw1, salt)
            new_vk = generate_vault_key()
            enc_vk = encrypt_with_derived(derived, new_vk.encode()).hex()
            pw_hash = hash_master_password(pw1)
        except Exception as e:
            custom_messagebox(self.root, "Error", f"Crypto error: {e}", "error")
            return

        def handle_res(res):
            if not res.get("ok"):
                custom_messagebox(self.root, "Error", res.get("error", "Reset failed"), "error")
                return

            custom_messagebox(self.root, "Success", "Password reset. Old vault was wiped (E2EE).", "info")
            self.show_login()

        self.async_request({
            "action": "reset_finish", "email": self.reset_email, "code": code,
            "new_password_hash": pw_hash, "new_vault_salt": salt.hex(), "new_encrypted_vault_key": enc_vk
        }, handle_res)

    # ================= DASHBOARD =================
    def show_dashboard(self):
        self.clear_panel()

        btn_settings = tk.Button(self.panel, text="⚙️ Settings", command=self.show_settings, bg=PANEL, fg=MUTED,
                                 activebackground=BTN_HOVER, activeforeground=TEXT, relief="flat", bd=0, cursor="hand2",
                                 font=("Arial", 11, "bold"))
        btn_settings.place(x=15, y=15)

        tk.Label(self.panel, text="Vault", bg=PANEL, fg=TEXT, font=FONT_TITLE).pack(pady=(28, 6))
        subtitle = f"Signed in as {self.user_email}"
        if self.user_role:
            subtitle += f"  •  role: {self.user_role}"
        tk.Label(self.panel, text=subtitle, bg=PANEL, fg=MUTED, font=FONT_SUB).pack(pady=(0, 24))

        make_button(self.panel, "New Entry", command=self.new_entry, primary=True).pack(pady=8, padx=30, fill="x")
        make_button(self.panel, "My saved entries", command=self.show_entries).pack(pady=8, padx=30, fill="x")

        # השיתוף של סיסמאות ספציפיות
        make_button(self.panel, "Shared with me", command=self.show_shared_entries).pack(pady=8, padx=30, fill="x")

        if self.user_role == "admin":
            tk.Label(self.panel, text="— Admin Actions —", bg=PANEL, fg="#f59e0b", font=("Arial", 10, "bold")).pack(
                pady=(10, 0))
            make_button(self.panel, "Admin Panel (Manage Users)", command=self.show_admin_panel).pack(pady=8, padx=30,
                                                                                                      fill="x")

        make_button(self.panel, "Logout", command=self.logout, small=True).pack(pady=(20, 0))

    # ================= SETTINGS MENU =================
    def show_settings(self):
        if not self._require_authed():
            return

        self.clear_panel()

        tk.Label(self.panel, text="Settings", bg=PANEL, fg=TEXT, font=FONT_TITLE).pack(pady=(18, 6))
        tk.Label(self.panel, text="Manage your vault preferences", bg=PANEL, fg=MUTED, font=FONT_SUB).pack(pady=(0, 24))

        make_button(self.panel, "Export Vault (encrypted backup)", command=self.export_vault).pack(pady=8, padx=30,
                                                                                                   fill="x")
        make_button(self.panel, "Import Vault (encrypted backup)", command=self.import_vault).pack(pady=8, padx=30,
                                                                                                   fill="x")

        tk.Label(self.panel, text="— Security —", bg=PANEL, fg=MUTED, font=("Arial", 10, "bold")).pack(pady=(15, 5))
        make_button(self.panel, "Change Master Password", command=self.show_change_password).pack(pady=8, padx=30,
                                                                                                  fill="x")

        make_button(self.panel, "← Back to Dashboard", command=self.show_dashboard, small=True).pack(pady=(25, 0))

    # ================= CHANGE MASTER PASSWORD =================
    def show_change_password(self):
        self.clear_panel()

        tk.Label(self.panel, text="Change Password", bg=PANEL, fg=TEXT, font=FONT_TITLE).pack(pady=(18, 6))
        tk.Label(self.panel, text="Your existing passwords will remain perfectly safe.", bg=PANEL, fg=MUTED,
                 font=FONT_SUB).pack(pady=(0, 16))

        cur_box, cur_entry, self.cp_cur_var = make_watermark_entry(self.panel, "Current Password", is_password=True,
                                                                   show_toggle=True)
        cur_box.pack(pady=8, padx=30, fill="x")

        new_box, new_entry, self.cp_new_var = make_watermark_entry(self.panel, "New Password", is_password=True,
                                                                   show_toggle=True)
        new_box.pack(pady=8, padx=30, fill="x")

        conf_box, conf_entry, self.cp_conf_var = make_watermark_entry(self.panel, "Confirm New Password",
                                                                      is_password=True, show_toggle=True)
        conf_box.pack(pady=8, padx=30, fill="x")

        make_button(self.panel, "Update Password", command=self.execute_change_password, primary=True).pack(
            pady=(18, 10), padx=30, fill="x")
        make_button(self.panel, "Cancel", command=self.show_settings, small=True).pack()
        cur_entry.focus_set()

    def execute_change_password(self):
        cur_pw = self.cp_cur_var.get()
        new_pw = self.cp_new_var.get()
        conf_pw = self.cp_conf_var.get()

        if not cur_pw or not new_pw or not conf_pw:
            custom_messagebox(self.root, "Error", "Fill all fields.", "error")
            return

        if cur_pw != self.session_password:
            custom_messagebox(self.root, "Error", "Current password is incorrect.", "error")
            return

        if new_pw != conf_pw:
            custom_messagebox(self.root, "Error", "New passwords do not match.", "error")
            return

        try:
            salt = os.urandom(16)
            derived = derive_fernet_from_password(new_pw, salt)
            enc_vk = encrypt_with_derived(derived, self.vault_key.encode("utf-8")).hex()
            pw_hash = hash_master_password(new_pw)
        except Exception as e:
            custom_messagebox(self.root, "Error", f"Crypto error: {e}", "error")
            return

        def handle_res(res):
            if not res.get("ok"):
                custom_messagebox(self.root, "Error", res.get("error", "Failed to update password."), "error")
                return

            self.session_password = new_pw
            custom_messagebox(self.root, "Success", "Password updated successfully!\nYour vault is safe.", "info")
            self.show_settings()

        self.async_request({
            "action": "change_password",
            "session_token": self.session_token,
            "new_password_hash": pw_hash,
            "new_vault_salt": salt.hex(),
            "new_encrypted_vault_key": enc_vk
        }, handle_res)

    # ================= ADMIN PANEL =================
    def show_admin_panel(self):
        if not self._require_authed() or self.user_role != "admin":
            return

        self.clear_panel()
        top = tk.Frame(self.panel, bg=PANEL)
        top.pack(fill="x", pady=(10, 8), padx=16)
        make_button(top, "← Back", command=self.show_dashboard, small=True).pack(side="left")
        tk.Label(top, text="Admin Panel - Users", bg=PANEL, fg="#f59e0b", font=("Arial", 16, "bold")).pack(side="right")

        area = ScrollArea(self.panel, height=360)
        area.pack(fill="both", expand=True, padx=16, pady=(4, 10))

        def handle_res(res):
            if not res.get("ok"):
                return custom_messagebox(self.root, "Error", res.get("error", "Failed to load users"), "error")
            users = res.get("users", [])
            if not users:
                tk.Label(area.inner, text="No users found.", bg=PANEL, fg=MUTED, font=FONT_SUB).pack(pady=20)
            else:
                for u in users:
                    self._admin_user_row(area.inner, u)

        self.async_request({"action": "admin_get_users", "session_token": self.session_token}, handle_res)

    def _admin_user_row(self, parent, u: dict):
        row = tk.Frame(parent, bg="#111216", highlightthickness=1, highlightbackground=BORDER)
        row.pack(fill="x", pady=6, padx=2)

        left = tk.Frame(row, bg="#111216")
        left.pack(side="left", fill="both", expand=True, padx=10, pady=8)

        tk.Label(left, text=f"{u['full_name']} ({u['email']})", bg="#111216", fg=TEXT, font=("Arial", 13, "bold"),
                 anchor="w").pack(fill="x")

        role_color = "#f59e0b" if u['role'] == "admin" else MUTED
        tk.Label(left, text=f"Role: {u['role']}  |  Joined: {u.get('created_at', '')[:10]}", bg="#111216",
                 fg=role_color, font=("Arial", 11), anchor="w").pack(fill="x", pady=(2, 0))

        right = tk.Frame(row, bg="#111216")
        right.pack(side="right", padx=10, pady=8)

        if u['id'] != self.session_user_id:
            make_button(right, "Change Role", command=lambda: self.admin_change_role(u['id'], u['role']),
                        small=True).pack(pady=2, fill="x")
            make_button(right, "Delete User", command=lambda: self.admin_delete_user(u['id'], u['email']),
                        small=True).pack(pady=2, fill="x")
        else:
            tk.Label(right, text="You", bg="#111216", fg="#3b82f6", font=("Arial", 12, "bold")).pack(pady=10)

    def admin_change_role(self, user_id, current_role):
        new_role = "admin" if current_role == "user" else "user"
        if not custom_askyesno(self.root, "Confirm",
                               f"Are you sure you want to change this user's role to {new_role.upper()}?"):
            return

        def handle(res):
            if not res.get("ok"):
                custom_messagebox(self.root, "Error", res.get("error"), "error")
            else:
                self.show_admin_panel()

        self.async_request({"action": "admin_set_role", "session_token": self.session_token, "target_id": user_id,
                            "new_role": new_role}, handle)

    def admin_delete_user(self, user_id, email):
        if not custom_askyesno(self.root, "DANGER: Delete User",
                               f"Are you sure you want to permanently delete the user {email}?\n\nThis will destroy their account and ALL their passwords!"):
            return

        def handle(res):
            if not res.get("ok"):
                custom_messagebox(self.root, "Error", res.get("error"), "error")
            else:
                self.show_admin_panel()

        self.async_request({"action": "admin_delete_user", "session_token": self.session_token, "target_id": user_id},
                           handle)

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

        def handle_res(res):
            if not res.get("ok"):
                custom_messagebox(self.root, "Error", res.get("error", "Failed to load entries"), "error")
                return

            entries = res.get("entries", [])

            if not entries:
                tk.Label(area.inner, text="No entries yet. Add one from Dashboard.", bg=PANEL, fg=MUTED,
                         font=FONT_SUB).pack(pady=20)
            else:
                for ent in entries:
                    self._entry_row(area.inner, ent)

            make_button(self.panel, "New Entry", command=self.new_entry, primary=True).pack(pady=(8, 6), padx=16,
                                                                                            fill="x")
            make_button(self.panel, "Logout", command=self.logout, small=True).pack()

        self.async_request({"action": "entries_list", "session_token": self.session_token}, handle_res)

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
        # הנה השורה שהייתה חסרה! החזרתי את תצוגת המשתמש/אימייל
        tk.Label(left, text=username, bg="#111216", fg=MUTED, font=("Arial", 11), anchor="w").pack(fill="x",
                                                                                                   pady=(2, 0))

        right = tk.Frame(row, bg="#111216")
        right.pack(side="right", padx=10, pady=8)

        make_button(right, "Show",
                    command=lambda: custom_messagebox(self.root, "Password", pw_plain, "info", allow_copy=True),
                    small=True).pack(side="left", padx=2)
        make_button(right, "Share", command=lambda: self.share_specific_entry(ent, pw_plain), small=True).pack(
            side="left", padx=2)
        # החזרתי את לחצן העריכה
        make_button(right, "Edit", command=lambda: self.edit_entry(entry_id, title, username, pw_plain),
                    small=True).pack(side="left", padx=2)
        make_button(right, "Delete", command=lambda: self.delete_entry(entry_id), small=True).pack(side="left", padx=2)

    # ================= CRUD =================
    def new_entry(self):
        if not self._require_authed():
            return

        title = custom_askstring(self.root, "Title", "Title:")
        if title is None: return

        username = custom_askstring(self.root, "Username", "Email / Username:")
        if username is None: return

        pw = custom_askstring(self.root, "Password", "Password (leave empty to generate):")
        if pw is None: return

        if not pw: pw = generate_password()

        try:
            enc_hex = encrypt_entry_password(self.vault_key, pw).hex()
        except Exception as e:
            custom_messagebox(self.root, "Error", f"Encryption failed: {e}", "error")
            return

        def handle_res(res):
            if not res.get("ok"):
                custom_messagebox(self.root, "Error", res.get("error", "Failed to save"), "error")
                return
            custom_messagebox(self.root, "Success", "Entry saved.", "info")

        self.async_request({
            "action": "entry_create", "session_token": self.session_token,
            "title": title, "username": username, "encrypted_password": enc_hex
        }, handle_res)

    def edit_entry(self, entry_id: int, title: str, username: str, pw_plain: str):
        if not self._require_authed():
            return

        win = tk.Toplevel(self.root)
        win.title("Edit Entry")
        win.configure(bg=BG)

        win.transient(self.root)
        win.grab_set()

        self.root.update_idletasks()
        x = self.root.winfo_rootx() + (self.root.winfo_width() // 2) - 220
        y = self.root.winfo_rooty() + (self.root.winfo_height() // 2) - 190
        win.geometry(f"440x380+{x}+{y}")

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
                custom_messagebox(win, "Error", "Fill all fields.", "error")
                return

            try:
                enc_hex = encrypt_entry_password(self.vault_key, new_pw).hex()
            except Exception as e:
                custom_messagebox(win, "Error", f"Encryption failed: {e}", "error")
                return

            def handle_res(res):
                if not res.get("ok"):
                    custom_messagebox(win, "Error", res.get("error", "Update failed"), "error")
                    return
                win.destroy()
                self.show_entries()

            self.async_request({
                "action": "entry_update", "session_token": self.session_token,
                "id": entry_id, "title": new_title, "username": new_user, "encrypted_password": enc_hex
            }, handle_res)

        make_button(panel, "Save", command=save, primary=True).pack(pady=(16, 8), padx=20, fill="x")
        make_button(panel, "Cancel", command=win.destroy, small=True).pack()
        title_e.focus_set()

    def delete_entry(self, entry_id: int):
        if not self._require_authed():
            return

        if not custom_askyesno(self.root, "Confirm", "Are you sure you want to delete this entry?"):
            return

        def handle_res(res):
            if not res.get("ok"):
                custom_messagebox(self.root, "Error", res.get("error", "Delete failed"), "error")
                return
            self.show_entries()

        self.async_request({"action": "entry_delete", "session_token": self.session_token, "id": entry_id}, handle_res)

    # ================= BACKUP =================
    def export_vault(self):
        if not self._require_authed():
            return

        def handle_res(res):
            if not res.get("ok"):
                custom_messagebox(self.root, "Error", res.get("error", "Failed to fetch entries"), "error")
                return

            entries = res.get("entries", [])
            data = {"v": 1, "exported_at": __import__("datetime").datetime.now().isoformat(), "entries": entries}
            plaintext = json.dumps(data, ensure_ascii=False).encode("utf-8")

            enc_hex = encrypt_entry_password(self.vault_key, plaintext.decode("utf-8")).hex()

            path = filedialog.asksaveasfilename(title="Export Vault", defaultextension=".vault",
                                                filetypes=[("Vault Backup", "*.vault")])
            if not path: return

            with open(path, "w", encoding="utf-8") as f:
                f.write(enc_hex)

            custom_messagebox(self.root, "Success", "Exported encrypted backup successfully.", "info")

        self.async_request({"action": "entries_list", "session_token": self.session_token}, handle_res)

    def import_vault(self):
        if not self._require_authed():
            return

        path = filedialog.askopenfilename(title="Import Vault", filetypes=[("Vault Backup", "*.vault")])
        if not path:
            return

        def task():
            try:
                with open(path, "r", encoding="utf-8") as f:
                    enc_hex = f.read().strip()

                if len(enc_hex) < 40:
                    raise ValueError("Backup file too short / not a valid .vault")

                blob_bytes = bytes.fromhex(enc_hex)
                plaintext = decrypt_entry_password(self.vault_key, blob_bytes)
                data = json.loads(plaintext)

                entries = data.get("entries", [])
                if not isinstance(entries, list):
                    raise ValueError("Backup format invalid (missing entries list)")

                imported = 0
                failed = 0

                for ent in entries:
                    try:
                        title, username, enc_pw = ent["title"], ent["username"], ent["encrypted_password"]
                    except Exception:
                        failed += 1
                        continue

                    r = self.net.request({
                        "action": "entry_create", "session_token": self.session_token,
                        "title": title, "username": username, "encrypted_password": enc_pw
                    })
                    if r.get("ok"):
                        imported += 1
                    else:
                        failed += 1

                self.root.after(0, lambda: custom_messagebox(self.root, "Import Complete",
                                                             f"Imported: {imported}\nFailed: {failed}", "info"))

            except Exception as e:
                err_msg = str(e)
                self.root.after(0, lambda msg=err_msg: custom_messagebox(self.root, "Import error", msg, "error"))

        threading.Thread(target=task, daemon=True).start()

    # ================= SHARING SPECIFIC ENTRY =================
    def share_specific_entry(self, entry: dict, pw_plain: str):
        if not self._require_authed():
            return

        to_email = custom_askstring(self.root, "Share Entry", "Share with (user email):")
        if not to_email: return
        to_email = to_email.strip().lower()

        def handle_public_key(res):
            if not res.get("ok"):
                custom_messagebox(self.root, "Error", res.get("error", "User not found or has no keys"), "error")
                return

            receiver_pub_pem = res["public_key_pem"].encode("utf-8")

            try:
                enc_rsa = rsa_encrypt(receiver_pub_pem, pw_plain.encode("utf-8")).hex()
            except Exception as e:
                custom_messagebox(self.root, "Error", f"RSA encrypt failed: {e}", "error")
                return

            def handle_share(r2):
                if not r2.get("ok"):
                    custom_messagebox(self.root, "Error", r2.get("error", "Share failed"), "error")
                    return
                custom_messagebox(self.root, "Success", f"Shared successfully with {to_email}.", "info")

            self.async_request({
                "action": "share_entry_create", "session_token": self.session_token,
                "to_email": to_email, "title": entry['title'], "username": entry['username'],
                "encrypted_password_rsa": enc_rsa
            }, handle_share)

        self.async_request({"action": "keys_get_public", "session_token": self.session_token, "email": to_email},
                           handle_public_key)

    def show_shared_entries(self):
        if not self._require_authed():
            return

        self.clear_panel()
        tk.Label(self.panel, text="Shared With Me", bg=PANEL, fg=TEXT, font=FONT_TITLE).pack(pady=(18, 6))

        top = tk.Frame(self.panel, bg=PANEL)
        top.pack(fill="x", padx=16, pady=(0, 6))
        make_button(top, "← Back", command=self.show_dashboard, small=True).pack(side="left")

        area = ScrollArea(self.panel, height=300)
        area.pack(fill="both", expand=True, padx=16, pady=(6, 10))

        def handle_res(res):
            if not res.get("ok"):
                custom_messagebox(self.root, "Error", res.get("error", "Failed to load shared entries"), "error")
                self.show_dashboard()
                return

            shared = res.get("shared", [])
            if not shared:
                tk.Label(area.inner, text="No one shared a password with you yet.", bg=PANEL, fg=MUTED,
                         font=FONT_SUB).pack(pady=20)
                return

            for item in shared:
                self._shared_entry_row(area.inner, item)

        self.async_request({"action": "shared_entries_list", "session_token": self.session_token}, handle_res)

    def _shared_entry_row(self, parent, item: dict):
        title = item["title"]
        sender_email = item.get("sender_email", "unknown")
        enc_rsa_hex = item["encrypted_password_rsa"]

        try:
            pw_plain = rsa_decrypt(self.private_key_pem, bytes.fromhex(enc_rsa_hex)).decode("utf-8")
        except Exception:
            pw_plain = "<decrypt error>"

        row = tk.Frame(parent, bg="#111216", highlightthickness=1, highlightbackground=BORDER)
        row.pack(fill="x", pady=6, padx=2)

        left = tk.Frame(row, bg="#111216")
        left.pack(side="left", fill="both", expand=True, padx=10, pady=8)

        tk.Label(left, text=title, bg="#111216", fg=TEXT, font=("Arial", 13, "bold"), anchor="w").pack(fill="x")
        tk.Label(left, text=f"From: {sender_email}", bg="#111216", fg=MUTED, font=("Arial", 11), anchor="w").pack(
            fill="x", pady=(2, 0))

        right = tk.Frame(row, bg="#111216")
        right.pack(side="right", padx=10, pady=8)

        make_button(
            right, "Show",
            command=lambda: custom_messagebox(self.root, "Shared Password", pw_plain, "info", allow_copy=True),
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

        self.session_user_id = self.session_password = self.session_token = self.user_email = self.user_role = self.vault_key = self.public_key_pem = self.private_key_pem = self.reset_email = None
        self.show_login()


if __name__ == "__main__":
    root = tk.Tk()
    App(root)
    root.mainloop()