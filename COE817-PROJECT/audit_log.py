import base64
from cryptography.fernet import Fernet

AUDIT_LOG_FILE = "audit.log"


def main():
    # This must match the key used in your server code:
    # audit_enc_key = b"ServerAuditEncryptionKeyMustBe32bytes!"
    audit_enc_key = b"Audit_Decrypt_817_Show_log_32bit"

    # Fernet wants a 32-byte base64-encoded key
    # If your audit_enc_key is exactly 32 raw bytes, do:
    f = Fernet(base64.urlsafe_b64encode(audit_enc_key[:32]))

    with open(AUDIT_LOG_FILE, "rb") as f_in:
        for line in f_in:
            line = line.strip()
            if not line:
                continue
            # Decrypt
            try:
                decrypted = f.decrypt(line)
                # It's in the format: username\taction\tTimeString
                print(decrypted.decode())
            except Exception as e:
                print("[Error] Could not decrypt line:", e)


if __name__ == "__main__":
    main()
