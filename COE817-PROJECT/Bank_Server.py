import socket
import threading
import json
import base64
import os
import time
import pickle
import tkinter as tk
from tkinter import scrolledtext

from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.fernet import Fernet

ACCOUNTS_FILE = "accounts.dat"
AUDIT_LOG_FILE = "audit.log"
PSK = b"817_Bank_SharedSecret"
AUDIT_ENC_KEY = b"Audit_Decrypt_817_Show_log_32bit"

accounts = {}
accounts_lock = threading.Lock()

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

def append_to_audit_log(line_str):
    f = Fernet(base64.urlsafe_b64encode(AUDIT_ENC_KEY[:32]))
    encrypted_line = f.encrypt(line_str.encode())
    with open(AUDIT_LOG_FILE, "ab") as f_out:
        f_out.write(encrypted_line + b"\n")

# --- DATA MANAGEMENT ---
def load_accounts(app):
    global accounts
    try:
        with open(ACCOUNTS_FILE, "rb") as f:
            accounts = pickle.load(f)
        app.log(f"[System] Loaded {len(accounts)} accounts.")
    except FileNotFoundError:
        app.log("[System] No accounts file found, starting fresh.")

def save_accounts():
    with open(ACCOUNTS_FILE, "wb") as f:
        pickle.dump(accounts, f)

# --- GUI CLASS ---
class BankServerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Bank Server Admin Dashboard")
        self.root.geometry("550x450")

        tk.Label(self.root, text="Live Server Activity Log", font=("Helvetica", 14, "bold")).pack(pady=10)

        self.console = scrolledtext.ScrolledText(self.root, height=20, width=65, bg="#1e1e1e", fg="#00ff00", font=("Consolas", 10))
        self.console.pack(padx=20, pady=5)

        load_accounts(self)

        self.server_thread = threading.Thread(target=self.start_server, daemon=True)
        self.server_thread.start()

    def log(self, message):
        self.root.after(0, self._log_to_gui, message)

    def _log_to_gui(self, message):
        self.console.config(state='normal')
        self.console.insert(tk.END, message + "\n")
        self.console.see(tk.END)
        self.console.config(state='disabled')

    def start_server(self):
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind(("0.0.0.0", 50000))
        server.listen(5)
        self.log("[System] Server Listening on port 50000...")

        while True:
            conn, addr = server.accept()
            self.log(f"[Network] New connection from {addr}")
            t = threading.Thread(target=self.handle_client, args=(conn, addr), daemon=True)
            t.start()

    def handle_client(self, conn, addr):
        try:
            # --- Handshake Phase ---
            data_json = json.loads(conn.recv(1024).decode())
            if data_json.get("type") != "client_nonce": return conn.close()

            client_nonce = base64.b64decode(data_json["nonce"])
            server_nonce = os.urandom(16)
            conn.sendall(json.dumps({"type": "server_nonce", "nonce": base64.b64encode(server_nonce).decode()}).encode())

            ms = derive_master_secret(PSK, client_nonce, server_nonce)
            enc_key, mac_key = derive_enc_and_mac_keys(ms)

            # Added last_timestamp to track replay attacks
            session_state = {"authenticated": False, "username": None, "last_timestamp": 0.0}

            # --- Transaction Loop ---
            while True:
                raw_len = conn.recv(4)
                if not raw_len: break

                msg_len = int.from_bytes(raw_len, 'big')
                data_enc = b''
                while len(data_enc) < msg_len:
                    data_enc += conn.recv(msg_len - len(data_enc))

                req = json.loads(decrypt_and_verify(enc_key, mac_key, json.loads(data_enc.decode())).decode())
                cmd = req.get("cmd")
                req_ts = req.get("timestamp", 0.0)
                response = {}

                # Replay Protection Check
                if req_ts <= session_state["last_timestamp"]:
                    self.log(f"[ALERT] Blocked Replay Attack from {addr}!")
                    response = {"status": "error", "message": "Replay attack detected. Request rejected."}
                    resp_enc = encrypt_and_mac(enc_key, mac_key, json.dumps(response).encode())
                    resp_enc_json = json.dumps(resp_enc).encode()
                    conn.sendall(len(resp_enc_json).to_bytes(4, 'big') + resp_enc_json)
                    continue
                else:
                    session_state["last_timestamp"] = req_ts

                # --- Logic Routing ---
                if cmd == "register":
                    u, p = req["username"], req["password"]
                    with accounts_lock:
                        if u in accounts:
                            response = {"status": "error", "message": "User exists."}
                        else:
                            accounts[u] = {"password": p, "balance": 0.0}
                            save_accounts()
                            response = {"status": "ok", "message": "Registered successfully."}
                            self.log(f"[Action] Registered new user: {u}")
                    append_to_audit_log(f"{u}\tREGISTER\t{time.ctime()}")

                elif cmd == "login":
                    u, p = req["username"], req["password"]
                    with accounts_lock:
                        if u not in accounts or accounts[u]["password"] != p:
                            response = {"status": "error", "message": "Invalid credentials."}
                        else:
                            response = {"status": "ok", "message": "Login successful."}
                            session_state.update({"authenticated": True, "username": u})
                            self.log(f"[Action] User logged in: {u}")
                    append_to_audit_log(f"{u}\tLOGIN\t{time.ctime()}")

                elif cmd in ("deposit", "withdraw", "balance") and session_state["authenticated"]:
                    u = session_state["username"]
                    with accounts_lock:
                        if cmd == "deposit":
                            try:
                                amt = float(req["amount"])
                                if amt <= 0:
                                    response = {"status": "error", "message": "Amount must be greater than zero."}
                                else:
                                    accounts[u]["balance"] += amt
                                    response = {"status": "ok", "message": f"Deposited {amt}, new balance = {accounts[u]['balance']}"}
                                    self.log(f"[Transaction] {u} deposited {amt}")
                                    append_to_audit_log(f"{u}\tDEPOSIT {amt}\t{time.ctime()}")
                            except ValueError:
                                response = {"status": "error", "message": "Invalid amount format."}

                        elif cmd == "withdraw":
                            try:
                                amt = float(req["amount"])
                                if amt <= 0:
                                    response = {"status": "error", "message": "Amount must be greater than zero."}
                                elif accounts[u]["balance"] < amt:
                                    response = {"status": "error", "message": "Insufficient funds."}
                                else:
                                    accounts[u]["balance"] -= amt
                                    response = {"status": "ok", "message": f"Withdrew {amt}, new balance = {accounts[u]['balance']}"}
                                    self.log(f"[Transaction] {u} withdrew {amt}")
                                    append_to_audit_log(f"{u}\tWITHDRAW {amt}\t{time.ctime()}")
                            except ValueError:
                                response = {"status": "error", "message": "Invalid amount format."}

                        elif cmd == "balance":
                            response = {"status": "ok", "message": f"Balance = {accounts[u]['balance']}"}
                            self.log(f"[Transaction] {u} checked balance")
                            append_to_audit_log(f"{u}\tBALANCE\t{time.ctime()}")

                        save_accounts()
                else:
                    response = {"status": "error", "message": "Unauthorized or unknown command."}

                # Send encrypted response
                resp_enc = encrypt_and_mac(enc_key, mac_key, json.dumps(response).encode())
                resp_enc_json = json.dumps(resp_enc).encode()
                conn.sendall(len(resp_enc_json).to_bytes(4, 'big') + resp_enc_json)

        except Exception as e:
            self.log(f"[Network] Client disconnected or error: {e}")
        finally:
            conn.close()

if __name__ == "__main__":
    root = tk.Tk()
    app = BankServerApp(root)
    root.mainloop()