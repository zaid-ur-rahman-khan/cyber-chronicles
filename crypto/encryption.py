# crypto/encryption.py

import os
import base64
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


# Generate a secure 32-byte AES key (for AES-256)
def generate_aes_key():
    return base64.b64encode(os.urandom(32)).decode()


# Encrypt the message
def encrypt_message(plaintext, base64_key):
    key = base64.b64decode(base64_key)
    aesgcm = AESGCM(key)

    nonce = os.urandom(12)  # 96-bit recommended nonce for AES-GCM
    plaintext_bytes = plaintext.encode()

    ciphertext = aesgcm.encrypt(nonce, plaintext_bytes, None)

    return {
        "ciphertext": base64.b64encode(ciphertext).decode(),
        "nonce": base64.b64encode(nonce).decode()
    }


# Decrypt the message
def decrypt_message(encrypted_data, base64_key):
    key = base64.b64decode(base64_key)
    aesgcm = AESGCM(key)

    nonce = base64.b64decode(encrypted_data["nonce"])
    ciphertext = base64.b64decode(encrypted_data["ciphertext"])

    try:
        plaintext_bytes = aesgcm.decrypt(nonce, ciphertext, None)
        return plaintext_bytes.decode()
    except Exception as e:
        return f"[Decryption failed: {e}]"
if __name__ == "__main__":
    key = generate_aes_key()
    print("AES Key:", key)

    encrypted = encrypt_message("This is secret", key)
    print("Encrypted:", encrypted)

    decrypted = decrypt_message(encrypted, key)
    print("Decrypted:", decrypted)
