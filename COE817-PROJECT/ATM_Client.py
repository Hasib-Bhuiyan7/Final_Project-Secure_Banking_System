import socket
import json
import base64
import os
import time
import tkinter as tk
from tkinter import messagebox, scrolledtext

from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.fernet import Fernet

PSK = b"817_Bank_SharedSecret"

# --- CRYPTO FUNCTIONS ---
def derive_master_secret(psk, client_nonce, server_nonce):
    hkdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=client_nonce + server_nonce, info=b"COE817-BankingProject")
    return hkdf.derive(psk)

def derive_enc_and_mac_keys(master_secret):
    hkdf = HKDF(algorithm=hashes.SHA256(), length=64, salt=None, info=b"COE817-EncAndMac")
    key_material = hkdf.derive(master_secret)
    return key_material[:32], key_material[32:]

def encrypt_and_mac(enc_key, mac_key, plaintext: bytes) -> dict:
    f = Fernet(base64.urlsafe_b64encode(enc_key[:32]))
    ciphertext = f.encrypt(plaintext)
    h = hmac.HMAC(mac_key, hashes.SHA256())
    h.update(ciphertext)
    return {"ciphertext": base64.b64encode(ciphertext).decode(), "hmac": base64.b64encode(h.finalize()).decode()}

def decrypt_and_verify(enc_key, mac_key, data: dict) -> bytes:
    ciphertext = base64.b64decode(data["ciphertext"])
    h = hmac.HMAC(mac_key, hashes.SHA256())
    h.update(ciphertext)
    h.verify(base64.b64decode(data["hmac"]))
    return Fernet(base64.urlsafe_b64encode(enc_key[:32])).decrypt(ciphertext)


# --- GUI CLASS ---
class ATMClientApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Secure ATM Client")
        self.root.geometry("400x520")

        self.s = None
        self.enc_key = None
        self.mac_key = None

        self.setup_ui()
        self.connect_to_server()

    def setup_ui(self):
        # --- Authentication Frame (Login/Register) ---
        self.auth_frame = tk.Frame(self.root, pady=20)

        tk.Label(self.auth_frame, text="Secure Banking Login", font=("Helvetica", 16, "bold")).pack(pady=10)

        tk.Label(self.auth_frame, text="Username:").pack()
        self.entry_user = tk.Entry(self.auth_frame, width=30)
        self.entry_user.pack(pady=5)

        tk.Label(self.auth_frame, text="Password:").pack()
        self.entry_pass = tk.Entry(self.auth_frame, width=30, show="*")
        self.entry_pass.pack(pady=5)

        btn_frame = tk.Frame(self.auth_frame)
        btn_frame.pack(pady=10)
        tk.Button(btn_frame, text="Login", command=self.do_login, width=10, bg="lightblue").pack(side=tk.LEFT, padx=5)
        tk.Button(btn_frame, text="Register", command=self.do_register, width=10).pack(side=tk.LEFT, padx=5)

        # --- Dashboard Frame (Transactions) ---
        self.dash_frame = tk.Frame(self.root, pady=20)

        self.lbl_welcome = tk.Label(self.dash_frame, text="Welcome!", font=("Helvetica", 14, "bold"))
        self.lbl_welcome.pack(pady=10)

        tk.Label(self.dash_frame, text="Amount ($):").pack()
        self.entry_amount = tk.Entry(self.dash_frame, width=20)
        self.entry_amount.pack(pady=5)

        tk.Button(self.dash_frame, text="Deposit", command=self.do_deposit, width=20).pack(pady=5)
        tk.Button(self.dash_frame, text="Withdraw", command=self.do_withdraw, width=20).pack(pady=5)
        tk.Button(self.dash_frame, text="Check Balance", command=self.do_balance, width=20, bg="lightgreen").pack(pady=5)
        tk.Button(self.dash_frame, text="Logout", command=self.do_logout, width=20, fg="red").pack(pady=15)

        # --- Console Output (Shared) ---
        console_header = tk.Frame(self.root)
        console_header.pack(fill="x", padx=20)
        tk.Label(console_header, text="Terminal Output:").pack(side=tk.LEFT)
        tk.Button(console_header, text="Clear", command=self.clear_log, font=("Arial", 8)).pack(side=tk.RIGHT)

        self.console = scrolledtext.ScrolledText(self.root, height=8, width=45, state='disabled', bg="#f0f0f0")
        self.console.pack(padx=20, pady=5)

        self.auth_frame.pack(fill="both", expand=True)

    def log(self, message):
        self.console.config(state='normal')
        self.console.insert(tk.END, message + "\n")
        self.console.see(tk.END)
        self.console.config(state='disabled')

    def clear_log(self):
        self.console.config(state='normal')
        self.console.delete(1.0, tk.END)
        self.console.config(state='disabled')

    def connect_to_server(self):
        try:
            self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.s.connect(("127.0.0.1", 50000))
            self.log("🔌 Connected to bank server.")

            client_nonce = os.urandom(16)
            self.s.sendall(json.dumps({"type": "client_nonce", "nonce": base64.b64encode(client_nonce).decode()}).encode())

            data_json = json.loads(self.s.recv(1024).decode())
            if data_json.get("type") == "server_nonce":
                server_nonce = base64.b64decode(data_json["nonce"])
                ms = derive_master_secret(PSK, client_nonce, server_nonce)
                self.enc_key, self.mac_key = derive_enc_and_mac_keys(ms)
                self.log("🔐 Keys successfully derived.")
            else:
                self.log("❌ Invalid server response during handshake.")
        except Exception as e:
            self.log(f"❌ Connection failed: {e}")
            messagebox.showerror("Connection Error", "Could not connect to the Bank Server. Is it running?")

    def send_secure_request(self, req_dict):
        try:
            req_enc = encrypt_and_mac(self.enc_key, self.mac_key, json.dumps(req_dict).encode())
            req_enc_json = json.dumps(req_enc).encode()
            self.s.sendall(len(req_enc_json).to_bytes(4, 'big') + req_enc_json)

            raw_len = self.s.recv(4)
            if not raw_len: return None

            msg_len = int.from_bytes(raw_len, 'big')
            data_enc = b''
            while len(data_enc) < msg_len:
                data_enc += self.s.recv(msg_len - len(data_enc))

            resp_plain = decrypt_and_verify(self.enc_key, self.mac_key, json.loads(data_enc.decode()))
            return json.loads(resp_plain.decode())
        except Exception as e:
            self.log(f"❌ Network Error: {e}")
            return {"status": "error", "message": str(e)}

    # --- Button Commands ---
    def do_register(self):
        u, p = self.entry_user.get(), self.entry_pass.get()
        if not u or not p: return messagebox.showwarning("Input Error", "Enter username and password.")
        # Added timestamp for replay protection
        resp = self.send_secure_request({"cmd": "register", "username": u, "password": p, "timestamp": time.time()})
        if resp:
            if resp.get("status") == "ok":
                self.log("✅ Registration successful!\n👉 You can now log in.")
            else:
                self.log(f"❌ Registration failed: {resp.get('message')}")

    def do_login(self):
        u, p = self.entry_user.get(), self.entry_pass.get()
        if not u or not p: return messagebox.showwarning("Input Error", "Enter username and password.")
        # Added timestamp for replay protection
        resp = self.send_secure_request({"cmd": "login", "username": u, "password": p, "timestamp": time.time()})
        if resp:
            if resp.get("status") == "ok":
                self.lbl_welcome.config(text=f"Welcome, {u}!")
                self.auth_frame.pack_forget()
                self.dash_frame.pack(fill="both", expand=True)
                self.entry_pass.delete(0, tk.END)
                self.log(f"🏦 Welcome to the bank, {u}!\n🔒 You are securely logged in.")
            else:
                self.log(f"❌ Login failed: {resp.get('message')}")

    def do_deposit(self):
        amount = self.entry_amount.get()
        if not amount: return
        # Added timestamp for replay protection
        resp = self.send_secure_request({"cmd": "deposit", "amount": amount, "timestamp": time.time()})
        if resp:
            if resp.get("status") == "ok":
                msg = resp.get("message").replace("Deposited ", "✅ Successfully deposited $").replace(", new balance = ", ".\n💵 Your new balance is $")
                self.log(msg)
            else:
                self.log(f"❌ Error: {resp.get('message')}")
        self.entry_amount.delete(0, tk.END)

    def do_withdraw(self):
        amount = self.entry_amount.get()
        if not amount: return
        # Added timestamp for replay protection
        resp = self.send_secure_request({"cmd": "withdraw", "amount": amount, "timestamp": time.time()})
        if resp:
            if resp.get("status") == "ok":
                msg = resp.get("message").replace("Withdrew ", "✅ Successfully withdrew $").replace(", new balance = ", ".\n💵 Your new balance is $")
                self.log(msg)
            else:
                self.log(f"❌ Error: {resp.get('message')}")
        self.entry_amount.delete(0, tk.END)

    def do_balance(self):
        # Added timestamp for replay protection
        resp = self.send_secure_request({"cmd": "balance", "timestamp": time.time()})
        if resp:
            if resp.get("status") == "ok":
                msg = resp.get("message").replace("Balance = ", "💰 Your current balance is $")
                self.log(msg)
            else:
                self.log(f"❌ Error: {resp.get('message')}")

    def do_logout(self):
        self.dash_frame.pack_forget()
        self.auth_frame.pack(fill="both", expand=True)
        self.log("👋 You have been securely logged out.")
        # Reset socket and key state
        if self.s: self.s.close()
        self.connect_to_server()

if __name__ == "__main__":
    root = tk.Tk()
    app = ATMClientApp(root)
    root.mainloop()